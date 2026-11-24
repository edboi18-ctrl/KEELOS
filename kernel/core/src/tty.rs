//! Canonical-mode line discipline for the console (P1-T14).
//!
//! Behaves like Linux N_TTY with its default settings (`tty_std_termios`:
//! ICRNL, ICANON, ECHO, ECHOE, ECHOK, ECHOCTL, ISIG; `INIT_C_CC`): input
//! is collected into a line, which becomes readable when Enter or VEOF
//! (Ctrl+D) ends it; VERASE (DEL, also BS) removes the last character and
//! VKILL (Ctrl+U) the whole line; control characters echo as `^X`. VINTR
//! (Ctrl+C) discards the line and echoes `^C`: there are no signals yet.
//! A line is at most 4095 bytes plus its newline (Linux N_TTY_BUF_SIZE is
//! 4096); further characters are dropped.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

const VINTR: u8 = 0x03;
const VEOF: u8 = 0x04;
const VKILL: u8 = 0x15;
const VERASE: u8 = 0x7f;
const BACKSPACE: u8 = 0x08;
const LINE_MAX: usize = 4095;
/// Most completed input held for readers (lines beyond it are dropped).
const READY_MAX: usize = 16 * 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Item {
    Byte(u8),
    /// VEOF on an empty line: the next read returns 0.
    EndOfFile,
    /// End of a line ended by VEOF: a read stops here without a newline.
    Break,
}

#[derive(Debug, Default)]
pub struct LineDiscipline {
    line: Vec<u8>,
    ready: VecDeque<Item>,
    /// Lines (and ends of file) made ready so far: n_tty wakes its readers
    /// at each (`n_tty_receive_handle_newline`), which epoll counts.
    completed: u64,
}

impl LineDiscipline {
    pub const fn new() -> Self {
        LineDiscipline {
            line: Vec::new(),
            ready: VecDeque::new(),
            completed: 0,
        }
    }

    /// Takes one input character; appends what to echo to `echo`.
    pub fn input(&mut self, c: u8, echo: &mut Vec<u8>) {
        let c = if c == b'\r' { b'\n' } else { c }; // ICRNL
        match c {
            b'\n' => {
                echo.push(b'\n');
                self.finish(Some(b'\n'));
            }
            VEOF => {
                if self.line.is_empty() {
                    self.push_ready(Item::EndOfFile);
                } else {
                    self.finish(None);
                }
            }
            VERASE | BACKSPACE => {
                if let Some(removed) = self.line.pop() {
                    erase(removed, echo);
                }
            }
            VKILL => {
                while let Some(removed) = self.line.pop() {
                    erase(removed, echo);
                }
            }
            VINTR => {
                self.line.clear();
                echo.extend_from_slice(b"^C\n");
            }
            _ if self.line.len() >= LINE_MAX => {}
            _ => {
                self.line.push(c);
                echo_char(c, echo);
            }
        }
    }

    fn push_ready(&mut self, item: Item) {
        if self.ready.len() < READY_MAX {
            self.ready.push_back(item);
            self.completed += 1;
        }
    }

    /// How many lines (and ends of file) have been made ready.
    pub fn completed(&self) -> u64 {
        self.completed
    }

    fn finish(&mut self, terminator: Option<u8>) {
        if self.ready.len() + self.line.len() + 1 > READY_MAX {
            self.line.clear();
            return;
        }
        for &b in &self.line {
            self.ready.push_back(Item::Byte(b));
        }
        self.line.clear();
        self.ready.push_back(match terminator {
            Some(t) => Item::Byte(t),
            None => Item::Break,
        });
        self.completed += 1;
    }

    /// Whether a read would return without waiting.
    pub fn readable(&self) -> bool {
        !self.ready.is_empty()
    }

    /// Canonical read: at most one line, up to `buf.len()` bytes. Returns
    /// `None` if nothing is ready (the caller waits), `Some(0)` at end of
    /// file.
    pub fn read(&mut self, buf: &mut [u8]) -> Option<usize> {
        match self.ready.front()? {
            Item::EndOfFile => {
                self.ready.pop_front();
                return Some(0);
            }
            Item::Break => {
                self.ready.pop_front();
                return Some(0);
            }
            Item::Byte(_) => {}
        }
        let mut n = 0;
        while n < buf.len() {
            match self.ready.front() {
                Some(&Item::Byte(b)) => {
                    self.ready.pop_front();
                    buf[n] = b;
                    n += 1;
                    if b == b'\n' {
                        break;
                    }
                }
                Some(Item::Break) => {
                    self.ready.pop_front();
                    break;
                }
                _ => break,
            }
        }
        Some(n)
    }
}

/// ECHOCTL: control characters other than tab and newline echo as `^X`.
fn echo_char(c: u8, echo: &mut Vec<u8>) {
    if c < 0x20 && c != b'\t' {
        echo.extend_from_slice(&[b'^', c + 0x40]);
    } else {
        echo.push(c);
    }
}

/// ECHOE: erase a character visually (two cells for a `^X`).
fn erase(c: u8, echo: &mut Vec<u8>) {
    let cells = if c < 0x20 && c != b'\t' { 2 } else { 1 };
    for _ in 0..cells {
        echo.extend_from_slice(b"\x08 \x08");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(t: &mut LineDiscipline, s: &[u8]) -> Vec<u8> {
        let mut echo = Vec::new();
        for &c in s {
            t.input(c, &mut echo);
        }
        echo
    }

    fn read_all(t: &mut LineDiscipline, size: usize) -> Option<Vec<u8>> {
        let mut buf = alloc::vec![0; size];
        let n = t.read(&mut buf)?;
        buf.truncate(n);
        Some(buf)
    }

    #[test]
    fn lines_become_readable_at_enter() {
        let mut t = LineDiscipline::new();
        assert_eq!(feed(&mut t, b"keel"), b"keel");
        assert!(!t.readable());
        assert_eq!(read_all(&mut t, 64), None, "no line yet: the reader waits");
        assert_eq!(feed(&mut t, b"\r"), b"\n");
        assert_eq!(read_all(&mut t, 64).unwrap(), b"keel\n");
        assert_eq!(read_all(&mut t, 64), None);
    }

    #[test]
    fn reads_stop_at_line_ends_and_buffer_size() {
        let mut t = LineDiscipline::new();
        feed(&mut t, b"one\ntwo\n");
        assert_eq!(read_all(&mut t, 2).unwrap(), b"on");
        assert_eq!(read_all(&mut t, 64).unwrap(), b"e\n");
        assert_eq!(read_all(&mut t, 64).unwrap(), b"two\n");
    }

    #[test]
    fn erase_kill_and_interrupt() {
        let mut t = LineDiscipline::new();
        assert_eq!(feed(&mut t, b"kex\x7fl"), b"kex\x08 \x08l");
        feed(&mut t, b"\x08el\n");
        assert_eq!(read_all(&mut t, 64).unwrap(), b"keel\n");
        feed(&mut t, b"junk\x15ok\n");
        assert_eq!(read_all(&mut t, 64).unwrap(), b"ok\n");
        assert_eq!(feed(&mut t, b"lost\x03"), b"lost^C\n");
        assert_eq!(read_all(&mut t, 64), None);
        assert_eq!(
            feed(&mut t, b"\x7f"),
            b"",
            "erasing an empty line echoes nothing"
        );
    }

    #[test]
    fn end_of_file() {
        let mut t = LineDiscipline::new();
        feed(&mut t, b"\x04");
        assert_eq!(
            read_all(&mut t, 64).unwrap(),
            b"",
            "Ctrl+D on an empty line: EOF"
        );
        feed(&mut t, b"partial\x04");
        assert_eq!(
            read_all(&mut t, 64).unwrap(),
            b"partial",
            "Ctrl+D ends the line without NL"
        );
        assert_eq!(read_all(&mut t, 64), None);
    }

    #[test]
    fn control_characters_echo_as_caret() {
        let mut t = LineDiscipline::new();
        assert_eq!(feed(&mut t, b"\x1b\t"), b"^[\t");
        assert_eq!(feed(&mut t, b"\x7f"), b"\x08 \x08", "tab erases one cell");
        assert_eq!(
            feed(&mut t, b"\x7f"),
            b"\x08 \x08\x08 \x08",
            "^[ erases two"
        );
    }

    #[test]
    fn line_length_is_capped() {
        let mut t = LineDiscipline::new();
        let long = alloc::vec![b'x'; LINE_MAX + 10];
        feed(&mut t, &long);
        feed(&mut t, b"\n");
        assert_eq!(read_all(&mut t, 8192).unwrap().len(), LINE_MAX + 1);
    }
}
