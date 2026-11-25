//! keel-shell: Keel's own command shell (P3-T13, ADR 0032).
//!
//! A small POSIX-style shell in safe Rust on keel-rt, with no allocator:
//! every table has a fixed size. It runs the same under Linux and on Keel.
//!
//! - **Input:** one line at a time from standard input, a script file
//!   (`keel-shell FILE`) or `-c STRING`. Interactive when it reads its
//!   standard input and both fds 0 and 2 are terminals (POSIX XCU `sh`,
//!   "-i"; bash's rule): then it prints a prompt and does job control.
//! - **Words** (POSIX XCU 2.2, 2.6.2): `'...'`, `"..."` and `\`;
//!   `$NAME`, `${NAME}`, `$?`, `$$`, `$!` and `$0`. An unquoted
//!   expansion that comes to nothing is no word. There is no field
//!   splitting, globbing, command substitution or arithmetic.
//! - **Lists** (XCU 2.9): pipelines with `|`, joined by `&&`, `||`, `;`
//!   and `&`; `#` comments. Redirections (XCU 2.7): `<`, `>`, `>>`, `<&`
//!   and `>&` (a number or `-`), with an optional fd number before them.
//!   `NAME=value` alone sets a variable; before a command it is put in
//!   that command's environment.
//! - **Commands:** builtins that change the shell run in it: `cd`, `exit`,
//!   `export`, `unset`, `jobs`, `fg`, `bg`, `wait` and `kill`. The small
//!   utilities `echo`, `cat`, `ls`, `pwd`, `sleep`, `true`, `false`, `:`,
//!   `env` and `help` run in a child, as a program would. Anything else
//!   is looked up in `PATH` and executed (XCU 2.9.1.4); 127 if not found,
//!   126 if found but not executable (XCU 2.8.2).
//! - **Job control**, as the glibc manual's "Implementing a Job Control
//!   Shell" (sections 29.5.2 to 29.5.4) lays it out: the shell waits to
//!   be in the foreground, takes its own group and the terminal, and
//!   ignores SIGQUIT, SIGTSTP, SIGTTIN and SIGTTOU (SIGINT is caught, so
//!   ^C at the prompt starts a new line). It leaves SIGCHLD at its
//!   default: ignoring it, as the manual's sample does, would make Linux
//!   reap children before `wait4` sees them. Each job gets a group, made
//!   by both the shell and the child (setpgid), and the terminal when in
//!   the foreground (tcsetpgrp, also by both). A child resets those
//!   signals to SIG_DFL before it runs. The shell waits with WUNTRACED,
//!   takes the terminal back and restores its terminal modes, saving the
//!   job's if it stopped.
//! - **Without job control** (not interactive), every process stays in
//!   the shell's group, and an asynchronous list ignores SIGINT and
//!   SIGQUIT with standard input from /dev/null (XCU 2.9.3.1, 2.12).
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, Arg, Out};

// errno values (include/uapi/asm-generic/errno-base.h), negated as the
// system calls return them.
const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EINTR: i64 = -4;
const EIO: i64 = -5;
const E2BIG: i64 = -7;
const ENOEXEC: i64 = -8;
const EBADF: i64 = -9;
const ECHILD: i64 = -10;
const EAGAIN: i64 = -11;
const ENOMEM: i64 = -12;
const EACCES: i64 = -13;
const EEXIST: i64 = -17;
const ENOTDIR: i64 = -20;
const EISDIR: i64 = -21;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENOTTY: i64 = -25;
const ENOSPC: i64 = -28;
const EPIPE: i64 = -32;
const ENAMETOOLONG: i64 = -36;
const ENOTEMPTY: i64 = -39;
const ELOOP: i64 = -40;

// ioctls (include/uapi/asm-generic/ioctls.h).
const TCGETS: u64 = 0x5401;
const TCSETSW: u64 = 0x5403;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;

// wait4 options (include/uapi/linux/wait.h).
const WNOHANG: u32 = 1;
const WUNTRACED: u32 = 2;
const WCONTINUED: u32 = 8;

// open flags (include/uapi/asm-generic/fcntl.h).
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_DIRECTORY: u64 = 0o200000;
const O_CLOEXEC: u64 = 0o2000000;
const F_DUPFD_CLOEXEC: u32 = 1030;

// Signals (arch/x86/include/uapi/asm/signal.h).
const SIGINT: i32 = 2;
const SIGQUIT: i32 = 3;
const SIGPIPE: i32 = 13;
const SIGTERM: i32 = 15;
const SIGCONT: i32 = 18;
const SIGTSTP: i32 = 20;
const SIGTTIN: i32 = 21;
const SIGTTOU: i32 = 22;
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

/// Signal names, by number (the header above), and descriptions, as
/// musl's `strsignal` gives them (`src/string/strsignal.c`, v1.2.5).
const SIGNALS: [(&[u8], &[u8]); 32] = [
    (b"", b"Unknown signal"),
    (b"HUP", b"Hangup"),
    (b"INT", b"Interrupt"),
    (b"QUIT", b"Quit"),
    (b"ILL", b"Illegal instruction"),
    (b"TRAP", b"Trace/breakpoint trap"),
    (b"ABRT", b"Aborted"),
    (b"BUS", b"Bus error"),
    (b"FPE", b"Arithmetic exception"),
    (b"KILL", b"Killed"),
    (b"USR1", b"User defined signal 1"),
    (b"SEGV", b"Segmentation fault"),
    (b"USR2", b"User defined signal 2"),
    (b"PIPE", b"Broken pipe"),
    (b"ALRM", b"Alarm clock"),
    (b"TERM", b"Terminated"),
    (b"STKFLT", b"Stack fault"),
    (b"CHLD", b"Child process status"),
    (b"CONT", b"Continued"),
    (b"STOP", b"Stopped (signal)"),
    (b"TSTP", b"Stopped"),
    (b"TTIN", b"Stopped (tty input)"),
    (b"TTOU", b"Stopped (tty output)"),
    (b"URG", b"Urgent I/O condition"),
    (b"XCPU", b"CPU time limit exceeded"),
    (b"XFSZ", b"File size limit exceeded"),
    (b"VTALRM", b"Virtual timer expired"),
    (b"PROF", b"Profiling timer expired"),
    (b"WINCH", b"Window changed"),
    (b"IO", b"I/O possible"),
    (b"PWR", b"Power failure"),
    (b"SYS", b"Bad system call"),
];

/// Error messages as musl's `strerror` gives them
/// (`src/errno/__strerror.h`, v1.2.5).
fn strerror(e: i64) -> &'static [u8] {
    match e {
        EPERM => b"Operation not permitted",
        ENOENT => b"No such file or directory",
        ESRCH => b"No such process",
        EINTR => b"Interrupted system call",
        EIO => b"I/O error",
        E2BIG => b"Argument list too long",
        ENOEXEC => b"Exec format error",
        EBADF => b"Bad file descriptor",
        ECHILD => b"No child process",
        EAGAIN => b"Resource temporarily unavailable",
        ENOMEM => b"Out of memory",
        EACCES => b"Permission denied",
        EEXIST => b"File exists",
        ENOTDIR => b"Not a directory",
        EISDIR => b"Is a directory",
        EINVAL => b"Invalid argument",
        EMFILE => b"No file descriptors available",
        ENOTTY => b"Not a tty",
        ENOSPC => b"No space left on device",
        EPIPE => b"Broken pipe",
        ENAMETOOLONG => b"Filename too long",
        ENOTEMPTY => b"Directory not empty",
        ELOOP => b"Symbolic link loop",
        _ => b"Unknown error",
    }
}

const LINE: usize = 4096;
const TOKENS: usize = 512;
const ARENA: usize = 16384;
/// Arguments per command: execve's limit less the NULL.
const ARGS: usize = sys::EXECVE_MAX - 1;
const REDIRECTS: usize = 8;
const COMMANDS: usize = 16;
const VAR_BYTES: usize = 8192;
const VAR_COUNT: usize = 128;
const JOBS: usize = 16;
const JOB_TEXT: usize = 80;
const DEFAULT_PATH: &[u8] = b"/bin:/sbin:/usr/bin";

// --- output ---------------------------------------------------------------

/// Writes all of `bytes` to `fd`, retrying after a signal.
fn write_all(fd: i32, mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        let n = sys::write(fd, bytes);
        if n == EINTR {
            continue;
        }
        if n <= 0 {
            return false;
        }
        bytes = &bytes[n as usize..];
    }
    true
}

/// A small buffered writer.
struct Writer {
    fd: i32,
    buf: [u8; 512],
    len: usize,
}

impl Writer {
    const fn new(fd: i32) -> Self {
        Self {
            fd,
            buf: [0; 512],
            len: 0,
        }
    }

    fn put(&mut self, bytes: &[u8]) -> &mut Self {
        if self.len + bytes.len() > self.buf.len() {
            self.flush();
        }
        if bytes.len() > self.buf.len() {
            write_all(self.fd, bytes);
        } else {
            self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
        }
        self
    }

    fn num(&mut self, value: i64) -> &mut Self {
        let mut digits = [0u8; 20];
        let text = decimal(value, &mut digits);
        self.put(text)
    }

    fn flush(&mut self) -> bool {
        let ok = write_all(self.fd, &self.buf[..self.len]);
        self.len = 0;
        ok
    }
}

/// `value` in decimal, in `out`.
fn decimal(value: i64, out: &mut [u8; 20]) -> &[u8] {
    let mut at = out.len();
    let mut rest = value.unsigned_abs();
    loop {
        at -= 1;
        out[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    if value < 0 {
        at -= 1;
        out[at] = b'-';
    }
    &out[at..]
}

/// Writes `keel-shell: ` and `parts` as one line to standard error: the
/// shell's own messages.
fn complain(parts: &[&[u8]]) {
    let mut w = Writer::new(2);
    w.put(b"keel-shell: ");
    for p in parts {
        w.put(p);
    }
    w.put(b"\n");
    w.flush();
}

/// Writes `parts` as one line to standard error: a utility's messages,
/// which name the utility as a program's would.
fn warn(parts: &[&[u8]]) {
    let mut w = Writer::new(2);
    for p in parts {
        w.put(p);
    }
    w.put(b"\n");
    w.flush();
}

/// A non-negative decimal number, if `text` is one that fits.
fn number(text: &[u8]) -> Option<i64> {
    if text.is_empty() {
        return None;
    }
    let mut v: i64 = 0;
    for &c in text {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add(i64::from(c - b'0'))?;
    }
    Some(v)
}

fn valid_name(name: &[u8]) -> bool {
    match name.split_first() {
        Some((&first, rest)) => {
            (first.is_ascii_alphabetic() || first == b'_')
                && rest.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_')
        }
        None => false,
    }
}

/// The variable name and value of an assignment word `NAME=value`.
fn assignment(word: &[u8]) -> Option<(&[u8], &[u8])> {
    let eq = word.iter().position(|&c| c == b'=')?;
    valid_name(&word[..eq]).then(|| (&word[..eq], &word[eq + 1..]))
}

// --- system-call helpers ----------------------------------------------------

/// Sets `signal`'s action to SIG_DFL or SIG_IGN (no handler, so nothing
/// runs asynchronously).
fn disposition(signal: i32, action: u64) {
    let mut act = [0u8; 32];
    act[..8].copy_from_slice(&action.to_le_bytes());
    sys::rt_sigaction(signal, Arg::Buf(&act), Out::Null, 8);
}

fn tcgetpgrp(fd: i32) -> i64 {
    let mut b = [0u8; 64];
    match sys::ioctl(fd, TIOCGPGRP, &mut b) {
        0 => i64::from(i32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        e => e,
    }
}

fn tcsetpgrp(fd: i32, pgrp: i32) -> i64 {
    let mut b = [0u8; 64];
    b[..4].copy_from_slice(&pgrp.to_le_bytes());
    sys::ioctl(fd, TIOCSPGRP, &mut b)
}

/// The terminal's modes (`struct termios`, 36 bytes, in a 64-byte buffer).
fn tcgetattr(fd: i32) -> Option<[u8; 64]> {
    let mut b = [0u8; 64];
    (sys::ioctl(fd, TCGETS, &mut b) == 0).then_some(b)
}

/// tcsetattr(TCSADRAIN) is TCSETSW.
fn tcsetattr(fd: i32, modes: &[u8; 64]) {
    let mut b = *modes;
    sys::ioctl(fd, TCSETSW, &mut b);
}

fn is_tty(fd: i32) -> bool {
    tcgetattr(fd).is_some()
}

// --- variables ---------------------------------------------------------------

#[derive(Clone, Copy)]
struct Var {
    /// `NAME=value` and a NUL at `start` in the buffer.
    start: usize,
    name: usize,
    len: usize,
    exported: bool,
}

const NO_VAR: Var = Var {
    start: 0,
    name: 0,
    len: 0,
    exported: false,
};

struct Vars {
    buf: [u8; VAR_BYTES],
    used: usize,
    list: [Var; VAR_COUNT],
    count: usize,
}

impl Vars {
    const fn new() -> Self {
        Self {
            buf: [0; VAR_BYTES],
            used: 0,
            list: [NO_VAR; VAR_COUNT],
            count: 0,
        }
    }

    fn find(&self, name: &[u8]) -> Option<usize> {
        (0..self.count).find(|&i| {
            let v = self.list[i];
            &self.buf[v.start..v.start + v.name] == name
        })
    }

    fn get(&self, name: &[u8]) -> Option<&[u8]> {
        let v = self.list[self.find(name)?];
        Some(&self.buf[v.start + v.name + 1..v.start + v.len])
    }

    fn remove(&mut self, i: usize) {
        let v = self.list[i];
        let size = v.len + 1;
        self.buf.copy_within(v.start + size..self.used, v.start);
        self.used -= size;
        self.list.copy_within(i + 1..self.count, i);
        self.count -= 1;
        for other in &mut self.list[..self.count] {
            if other.start > v.start {
                other.start -= size;
            }
        }
    }

    /// Sets `name` to `value`; `export` None keeps its export flag. False
    /// if the table is full.
    fn set(&mut self, name: &[u8], value: &[u8], export: Option<bool>) -> bool {
        let mut exported = false;
        if let Some(i) = self.find(name) {
            exported = self.list[i].exported;
            self.remove(i);
        }
        let exported = export.unwrap_or(exported);
        let len = name.len() + 1 + value.len();
        if self.count == VAR_COUNT || self.used + len + 1 > VAR_BYTES {
            return false;
        }
        let s = self.used;
        self.buf[s..s + name.len()].copy_from_slice(name);
        self.buf[s + name.len()] = b'=';
        self.buf[s + name.len() + 1..s + len].copy_from_slice(value);
        self.buf[s + len] = 0;
        self.used += len + 1;
        self.list[self.count] = Var {
            start: s,
            name: name.len(),
            len,
            exported,
        };
        self.count += 1;
        true
    }

    fn unset(&mut self, name: &[u8]) {
        if let Some(i) = self.find(name) {
            self.remove(i);
        }
    }

    /// Marks an existing variable for export.
    fn export(&mut self, name: &[u8]) {
        if let Some(i) = self.find(name) {
            self.list[i].exported = true;
        }
    }

    fn entry(&self, i: usize) -> &[u8] {
        let v = self.list[i];
        &self.buf[v.start..v.start + v.len]
    }

    fn entry_c(&self, i: usize) -> &CStr {
        let v = self.list[i];
        CStr::from_bytes_until_nul(&self.buf[v.start..=v.start + v.len]).unwrap_or(c"")
    }
}

// --- tokens ------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Redir {
    In,
    Out,
    Append,
    DupIn,
    DupOut,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sep {
    Pipe,
    And,
    Or,
    Semi,
    Amp,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Word,
    /// An operator and its fd (-1: the operator's default).
    Redirect(Redir, i32),
    Sep(Sep),
}

#[derive(Clone, Copy)]
struct Tok {
    kind: Kind,
    start: usize,
    end: usize,
}

const NO_TOK: Tok = Tok {
    kind: Kind::Word,
    start: 0,
    end: 0,
};

/// Why a line could not be run: the message and the status (2 for a
/// syntax error, POSIX XCU 2.8.1).
struct Fail(&'static [u8], i32);

const SYNTAX: Fail = Fail(b"syntax error", 2);

fn special(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'|' | b'&' | b';' | b'<' | b'>')
}

/// Splits `line` into tokens (XCU 2.3: quotes keep operators and blanks
/// inside a word; `#` at the start of a word begins a comment).
fn lex(line: &[u8], toks: &mut [Tok; TOKENS]) -> Result<usize, Fail> {
    let mut n = 0;
    let mut i = 0;
    let mut push = |kind: Kind, start: usize, end: usize| -> Result<(), Fail> {
        let slot = toks.get_mut(n).ok_or(Fail(b"line too long", 1))?;
        *slot = Tok { kind, start, end };
        n += 1;
        Ok(())
    };
    loop {
        while i < line.len() && matches!(line[i], b' ' | b'\t') {
            i += 1;
        }
        if i >= line.len() || line[i] == b'\n' || line[i] == b'#' {
            break;
        }
        let start = i;
        let next = line.get(i + 1).copied();
        let sep = match line[i] {
            b'|' if next == Some(b'|') => Some((Sep::Or, 2)),
            b'|' => Some((Sep::Pipe, 1)),
            b'&' if next == Some(b'&') => Some((Sep::And, 2)),
            b'&' => Some((Sep::Amp, 1)),
            b';' => Some((Sep::Semi, 1)),
            _ => None,
        };
        if let Some((s, width)) = sep {
            i += width;
            push(Kind::Sep(s), start, i)?;
            continue;
        }
        let mut fd = -1;
        if !matches!(line[i], b'<' | b'>') {
            while i < line.len() && !special(line[i]) {
                match line[i] {
                    b'\\' => i = (i + 2).min(line.len()),
                    b'\'' => {
                        let close = line[i + 1..].iter().position(|&c| c == b'\'');
                        i += close.ok_or(Fail(b"unterminated quote", 2))? + 2;
                    }
                    b'"' => {
                        i += 1;
                        loop {
                            match line.get(i).copied() {
                                None => return Err(Fail(b"unterminated quote", 2)),
                                Some(b'"') => break,
                                Some(b'\\') => i += 2,
                                Some(_) => i += 1,
                            }
                        }
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
            // A number right before `<` or `>` is the fd it redirects.
            let io_number = number(&line[start..i]).filter(|&v| v <= 9);
            match (line.get(i).copied(), io_number) {
                (Some(b'<' | b'>'), Some(v)) => fd = v as i32,
                _ => {
                    push(Kind::Word, start, i)?;
                    continue;
                }
            }
        }
        let next = line.get(i + 1).copied();
        let (op, width) = match (line[i], next) {
            (b'<', Some(b'&')) => (Redir::DupIn, 2),
            (b'<', _) => (Redir::In, 1),
            (b'>', Some(b'>')) => (Redir::Append, 2),
            (b'>', Some(b'&')) => (Redir::DupOut, 2),
            _ => (Redir::Out, 1),
        };
        i += width;
        push(Kind::Redirect(op, fd), start, i)?;
    }
    Ok(n)
}

/// Checks the token sequence: every pipeline has a command, every
/// redirection a word, and the line does not end in `|`, `&&` or `||`.
fn check(toks: &[Tok]) -> Result<(), Fail> {
    let mut empty = true;
    for (i, t) in toks.iter().enumerate() {
        match t.kind {
            Kind::Word => empty = false,
            Kind::Redirect(..) => {
                if toks.get(i + 1).map(|t| t.kind) != Some(Kind::Word) {
                    return Err(SYNTAX);
                }
                empty = false;
            }
            Kind::Sep(_) if empty => return Err(SYNTAX),
            Kind::Sep(_) => empty = true,
        }
    }
    match toks.last().map(|t| t.kind) {
        Some(Kind::Sep(Sep::Pipe | Sep::And | Sep::Or)) => Err(SYNTAX),
        _ => Ok(()),
    }
}

// --- expanded words and commands ------------------------------------------------

#[derive(Clone, Copy)]
struct Word {
    start: usize,
    len: usize,
}

const NO_WORD: Word = Word { start: 0, len: 0 };

/// The expanded words of one pipeline, each followed by a NUL.
struct Arena {
    buf: [u8; ARENA],
    used: usize,
}

impl Arena {
    const fn new() -> Self {
        Self {
            buf: [0; ARENA],
            used: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), Fail> {
        let end = self.used + bytes.len();
        if end >= ARENA {
            return Err(Fail(b"line too long", 1));
        }
        self.buf[self.used..end].copy_from_slice(bytes);
        self.used = end;
        Ok(())
    }

    fn bytes(&self, w: Word) -> &[u8] {
        &self.buf[w.start..w.start + w.len]
    }

    fn c(&self, w: Word) -> &CStr {
        CStr::from_bytes_until_nul(&self.buf[w.start..=w.start + w.len]).unwrap_or(c"")
    }
}

#[derive(Clone, Copy)]
struct Redirect {
    op: Redir,
    fd: i32,
    target: Word,
}

const NO_REDIRECT: Redirect = Redirect {
    op: Redir::In,
    fd: -1,
    target: NO_WORD,
};

#[derive(Clone, Copy)]
struct Command {
    args: [Word; ARGS],
    argc: usize,
    redirects: [Redirect; REDIRECTS],
    nredirect: usize,
}

const NO_COMMAND: Command = Command {
    args: [NO_WORD; ARGS],
    argc: 0,
    redirects: [NO_REDIRECT; REDIRECTS],
    nredirect: 0,
};

struct Pipeline {
    cmds: [Command; COMMANDS],
    count: usize,
}

// --- jobs ------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Running,
    /// Stopped by this signal.
    Stopped(i32),
    /// Ended with this wait status.
    Done(i32),
}

#[derive(Clone, Copy)]
struct Proc {
    pid: i32,
    state: State,
}

const NO_PROC: Proc = Proc {
    pid: 0,
    state: State::Done(0),
};

#[derive(Clone, Copy)]
struct Job {
    used: bool,
    pgid: i32,
    procs: [Proc; COMMANDS],
    count: usize,
    text: [u8; JOB_TEXT],
    text_len: usize,
    /// Its stop has been reported.
    notified: bool,
    /// Run with `&` or `bg`: its end is reported before a prompt.
    background: bool,
    /// The terminal's modes when it stopped (glibc manual 29.5.4).
    modes: Option<[u8; 64]>,
    /// When it last stopped or went to the background: the highest is
    /// the current job (`%+`).
    seq: u64,
}

const NO_JOB: Job = Job {
    used: false,
    pgid: 0,
    procs: [NO_PROC; COMMANDS],
    count: 0,
    text: [0; JOB_TEXT],
    text_len: 0,
    notified: false,
    background: false,
    modes: None,
    seq: 0,
};

impl Job {
    fn procs(&self) -> &[Proc] {
        &self.procs[..self.count]
    }

    fn done(&self) -> bool {
        self.procs()
            .iter()
            .all(|p| matches!(p.state, State::Done(_)))
    }

    fn running(&self) -> bool {
        self.procs().iter().any(|p| p.state == State::Running)
    }

    /// Stopped: nothing running, something stopped (the signal).
    fn stopped(&self) -> Option<i32> {
        if self.running() {
            return None;
        }
        self.procs().iter().find_map(|p| match p.state {
            State::Stopped(sig) => Some(sig),
            _ => None,
        })
    }

    /// Its status as `$?` gives it: the last process's (XCU 2.9.2).
    fn status(&self) -> i32 {
        match self.procs().last().map(|p| p.state) {
            Some(State::Done(raw)) => shell_status(raw),
            Some(State::Stopped(sig)) => 128 + sig,
            _ => 0,
        }
    }

    fn text(&self) -> &[u8] {
        &self.text[..self.text_len]
    }
}

/// A wait status as the shell reports it (XCU 2.8.2): the exit code, or
/// 128 plus the signal that ended the process.
fn shell_status(raw: i32) -> i32 {
    if raw & 0x7f == 0 {
        (raw >> 8) & 0xff
    } else {
        128 + (raw & 0x7f)
    }
}

/// What a job's state reads as in `jobs` and the notices.
fn describe(w: &mut Writer, job: &Job) {
    if job.running() {
        w.put(b"Running");
    } else if let Some(sig) = job.stopped() {
        w.put(signal_text(sig));
    } else {
        match job.procs().last().map(|p| p.state) {
            Some(State::Done(raw)) if raw & 0x7f == 0 => {
                let code = (raw >> 8) & 0xff;
                if code == 0 {
                    w.put(b"Done");
                } else {
                    w.put(b"Exit ").num(i64::from(code));
                }
            }
            Some(State::Done(raw)) => {
                w.put(signal_text(raw & 0x7f));
            }
            _ => {
                w.put(b"Done");
            }
        }
    }
}

fn signal_text(sig: i32) -> &'static [u8] {
    SIGNALS.get(sig as usize).map_or(b"Unknown signal", |s| s.1)
}

/// A signal given as a number, a name, or a name with `SIG`.
fn parse_signal(text: &[u8]) -> Option<i32> {
    if let Some(n) = number(text) {
        return (n < 65).then_some(n as i32);
    }
    let name = text.strip_prefix(b"SIG").unwrap_or(text);
    SIGNALS
        .iter()
        .position(|s| !s.0.is_empty() && s.0 == name)
        .map(|i| i as i32)
}

// --- the shell -------------------------------------------------------------------

/// Builtins that act on the shell itself: run in the shell when they are
/// a whole pipeline, else in a child like any command.
const SPECIAL: [&[u8]; 9] = [
    b"cd", b"exit", b"export", b"unset", b"jobs", b"fg", b"bg", b"wait", b"kill",
];

/// Builtin utilities: always run in a child.
const UTILITIES: [&[u8]; 10] = [
    b"echo", b"cat", b"ls", b"pwd", b"sleep", b"true", b"false", b":", b"env", b"help",
];

struct Shell {
    vars: Vars,
    jobs: [Job; JOBS],
    seq: u64,
    status: i32,
    last_bg: Option<i32>,
    pid: i32,
    name: &'static [u8],
    interactive: bool,
    /// Job control is on: the shell has its own group and the terminal.
    jobctl: bool,
    pgid: i32,
    modes: Option<[u8; 64]>,
    /// `exit` was run: the status to exit with.
    exit: Option<i32>,
    /// "There are stopped jobs." was said for the line before this one
    /// (`warned`) or since the last line (`just_warned`): `exit` or end
    /// of file then exits.
    warned: bool,
    just_warned: bool,
}

impl Shell {
    fn new(name: &'static [u8]) -> Self {
        Self {
            vars: Vars::new(),
            jobs: [NO_JOB; JOBS],
            seq: 0,
            status: 0,
            last_bg: None,
            pid: sys::getpid() as i32,
            name,
            interactive: false,
            jobctl: false,
            pgid: sys::getpgrp() as i32,
            modes: None,
            exit: None,
            warned: false,
            just_warned: false,
        }
    }

    /// The glibc manual's `init_shell` (29.5.2), with SIGINT caught
    /// rather than ignored and SIGCHLD left alone.
    fn start_job_control(&mut self) {
        loop {
            let fg = tcgetpgrp(0);
            if fg < 0 {
                // No controlling terminal: interactive, without jobs.
                return;
            }
            let me = sys::getpgrp();
            if fg == me {
                break;
            }
            sys::kill(-(me as i32), SIGTTIN);
        }
        keel_rt::signal::catch(SIGINT);
        for s in [SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU] {
            disposition(s, SIG_IGN);
        }
        // A session leader's group is already its PID (setpgid would be
        // EPERM for it).
        if sys::getpgrp() != i64::from(self.pid) && sys::setpgid(0, 0) < 0 {
            complain(&[b"cannot make a process group; no job control"]);
            return;
        }
        self.pgid = self.pid;
        tcsetpgrp(0, self.pgid);
        self.modes = tcgetattr(0);
        self.jobctl = true;
    }

    // --- expansion -----------------------------------------------------------

    /// `$...` at `raw[i]`: appends its value and returns where it ends.
    fn parameter(&self, raw: &[u8], i: usize, out: &mut Arena) -> Result<usize, Fail> {
        let j = i + 1;
        let mut digits = [0u8; 20];
        let (value, end): (&[u8], usize) = match raw.get(j).copied() {
            Some(b'?') => (decimal(i64::from(self.status), &mut digits), j + 1),
            Some(b'$') => (decimal(i64::from(self.pid), &mut digits), j + 1),
            Some(b'!') => match self.last_bg {
                Some(pid) => (decimal(i64::from(pid), &mut digits), j + 1),
                None => (b"", j + 1),
            },
            Some(b'0') => (self.name, j + 1),
            Some(b'{') => {
                let close = raw[j..].iter().position(|&c| c == b'}');
                let Some(close) = close.map(|c| j + c) else {
                    return Err(Fail(b"bad substitution", 2));
                };
                let name = &raw[j + 1..close];
                match name {
                    b"?" => (decimal(i64::from(self.status), &mut digits), close + 1),
                    b"$" => (decimal(i64::from(self.pid), &mut digits), close + 1),
                    _ if valid_name(name) => (self.vars.get(name).unwrap_or(b""), close + 1),
                    _ => return Err(Fail(b"bad substitution", 2)),
                }
            }
            Some(c) if c.is_ascii_alphabetic() || c == b'_' => {
                let len = raw[j..]
                    .iter()
                    .position(|&c| !(c.is_ascii_alphanumeric() || c == b'_'))
                    .unwrap_or(raw.len() - j);
                (self.vars.get(&raw[j..j + len]).unwrap_or(b""), j + len)
            }
            _ => (b"$", j),
        };
        out.push(value)?;
        Ok(end)
    }

    /// Expands one word (XCU 2.2 quoting, 2.6.2 parameters, 2.6.7 quote
    /// removal). None for an unquoted word that came to nothing.
    fn expand(&self, raw: &[u8], out: &mut Arena) -> Result<Option<Word>, Fail> {
        let start = out.used;
        let mut quoted = false;
        let mut i = 0;
        while i < raw.len() {
            match raw[i] {
                b'\\' => {
                    quoted = true;
                    match raw.get(i + 1) {
                        Some(&c) => out.push(&[c])?,
                        None => out.push(b"\\")?,
                    }
                    i += 2;
                }
                b'\'' => {
                    quoted = true;
                    let close = raw[i + 1..]
                        .iter()
                        .position(|&c| c == b'\'')
                        .map_or(raw.len(), |c| i + 1 + c);
                    out.push(&raw[i + 1..close])?;
                    i = close + 1;
                }
                b'"' => {
                    quoted = true;
                    i += 1;
                    while i < raw.len() && raw[i] != b'"' {
                        match (raw[i], raw.get(i + 1)) {
                            (b'\\', Some(&c)) if matches!(c, b'$' | b'`' | b'"' | b'\\') => {
                                out.push(&[c])?;
                                i += 2;
                            }
                            (b'$', _) => i = self.parameter(raw, i, out)?,
                            (c, _) => {
                                out.push(&[c])?;
                                i += 1;
                            }
                        }
                    }
                    i += 1;
                }
                b'$' => i = self.parameter(raw, i, out)?,
                c => {
                    out.push(&[c])?;
                    i += 1;
                }
            }
        }
        let len = out.used - start;
        if len == 0 && !quoted {
            return Ok(None);
        }
        out.push(&[0])?;
        Ok(Some(Word { start, len }))
    }

    /// Expands one pipeline's tokens into commands.
    fn parse(&self, line: &[u8], toks: &[Tok], out: &mut Arena) -> Result<Pipeline, Fail> {
        let mut p = Pipeline {
            cmds: [NO_COMMAND; COMMANDS],
            count: 1,
        };
        let mut i = 0;
        while i < toks.len() {
            let t = toks[i];
            let cmd = &mut p.cmds[p.count - 1];
            match t.kind {
                Kind::Word => {
                    if let Some(w) = self.expand(&line[t.start..t.end], out)? {
                        let slot = cmd
                            .args
                            .get_mut(cmd.argc)
                            .ok_or(Fail(b"too many arguments", 1))?;
                        *slot = w;
                        cmd.argc += 1;
                    }
                }
                Kind::Redirect(op, fd) => {
                    i += 1;
                    let word = toks[i];
                    let target = self
                        .expand(&line[word.start..word.end], out)?
                        .ok_or(Fail(b"ambiguous redirect", 1))?;
                    let slot = cmd
                        .redirects
                        .get_mut(cmd.nredirect)
                        .ok_or(Fail(b"too many redirections", 1))?;
                    *slot = Redirect { op, fd, target };
                    cmd.nredirect += 1;
                }
                Kind::Sep(Sep::Pipe) => {
                    if p.count == COMMANDS {
                        return Err(Fail(b"pipeline too long", 1));
                    }
                    p.count += 1;
                }
                Kind::Sep(_) => return Err(SYNTAX),
            }
            i += 1;
        }
        Ok(p)
    }

    // --- running a line ----------------------------------------------------------

    fn run_line(&mut self, line: &[u8]) {
        let mut toks = [NO_TOK; TOKENS];
        let n = match lex(line, &mut toks).and_then(|n| check(&toks[..n]).map(|()| n)) {
            Ok(n) => n,
            Err(f) => {
                complain(&[f.0]);
                self.status = f.1;
                return;
            }
        };
        let toks = &toks[..n];
        // A warning about stopped jobs holds for the next line only.
        self.warned = core::mem::take(&mut self.just_warned);
        let mut prev = Sep::Semi;
        let mut i = 0;
        while i < toks.len() && self.exit.is_none() {
            let mut j = i;
            while j < toks.len() && !matches!(toks[j].kind, Kind::Sep(s) if s != Sep::Pipe) {
                j += 1;
            }
            let sep = match toks.get(j).map(|t| t.kind) {
                Some(Kind::Sep(s)) => s,
                _ => Sep::Semi,
            };
            let run = match prev {
                Sep::And => self.status == 0,
                Sep::Or => self.status != 0,
                _ => true,
            };
            if run {
                let text = &line[toks[i].start..toks[j - 1].end];
                self.run_pipeline(line, &toks[i..j], text, sep == Sep::Amp);
            }
            prev = sep;
            i = j + 1;
        }
    }

    fn run_pipeline(&mut self, line: &[u8], toks: &[Tok], text: &[u8], background: bool) {
        let mut arena = Arena::new();
        let p = match self.parse(line, toks, &mut arena) {
            Ok(p) => p,
            Err(f) => {
                complain(&[f.0]);
                self.status = f.1;
                return;
            }
        };
        if p.count == 1 && !background {
            let cmd = &p.cmds[0];
            let words = &cmd.args[..cmd.argc];
            let assigns = words
                .iter()
                .take_while(|w| assignment(arena.bytes(**w)).is_some())
                .count();
            if assigns == words.len() {
                // Assignments alone, with any redirections done and undone.
                self.with_redirects(cmd, &arena, |sh| {
                    for w in words {
                        if let Some((name, value)) = assignment(arena.bytes(*w))
                            && !sh.vars.set(name, value, None)
                        {
                            complain(&[b"too many variables"]);
                            return 1;
                        }
                    }
                    0
                });
                return;
            }
            let name = arena.bytes(words[assigns]);
            if assigns == 0 && SPECIAL.contains(&name) {
                self.with_redirects(cmd, &arena, |sh| sh.builtin(&arena, words));
                return;
            }
        }
        self.launch(&p, &arena, text, background);
    }

    /// Runs `body` in the shell with `cmd`'s redirections, then puts the
    /// shell's own descriptors back. Its result becomes `$?`.
    fn with_redirects(
        &mut self,
        cmd: &Command,
        arena: &Arena,
        body: impl FnOnce(&mut Self) -> i32,
    ) {
        // Each redirected fd's original, kept above 9 and close-on-exec.
        let mut saved = [(-1i32, -1i64); REDIRECTS];
        let mut failed = false;
        for (k, r) in cmd.redirects[..cmd.nredirect].iter().enumerate() {
            let fd = target_fd(r);
            saved[k] = (fd, sys::fcntl(fd, F_DUPFD_CLOEXEC, 10));
            if !apply(r, arena) {
                failed = true;
                saved = restore_upto(saved, k + 1);
                break;
            }
        }
        if failed {
            self.status = 1;
            return;
        }
        self.status = body(self);
        restore_upto(saved, cmd.nredirect);
    }

    /// Starts a pipeline as a job, in the foreground or the background.
    fn launch(&mut self, p: &Pipeline, arena: &Arena, text: &[u8], background: bool) {
        let Some(slot) = self.new_job() else {
            complain(&[b"too many jobs"]);
            self.status = 1;
            return;
        };
        let foreground = !background;
        let mut pgid = 0;
        let mut prev_read = -1;
        let mut started = 0;
        for k in 0..p.count {
            let last = k + 1 == p.count;
            let mut pipe = [-1i32; 2];
            if !last && sys::pipe2(&mut pipe, Some(O_CLOEXEC)) < 0 {
                complain(&[b"pipe failed"]);
                break;
            }
            let pid = sys::fork();
            if pid == 0 {
                self.child(
                    &p.cmds[k], arena, pgid, foreground, background, prev_read, pipe,
                );
            }
            if pid < 0 {
                complain(&[b"fork: ", strerror(pid)]);
                for fd in pipe {
                    if fd >= 0 {
                        sys::close(fd);
                    }
                }
                break;
            }
            let pid = pid as i32;
            if self.jobctl {
                if pgid == 0 {
                    pgid = pid;
                }
                // Both the shell and the child (glibc manual 29.5.3).
                sys::setpgid(pid, pgid);
                if foreground && k == 0 {
                    tcsetpgrp(0, pgid);
                }
            } else if pgid == 0 {
                pgid = pid;
            }
            let job = &mut self.jobs[slot];
            job.procs[k] = Proc {
                pid,
                state: State::Running,
            };
            job.count = k + 1;
            started += 1;
            if prev_read >= 0 {
                sys::close(prev_read);
            }
            if !last {
                sys::close(pipe[1]);
                prev_read = pipe[0];
            }
        }
        if prev_read >= 0 {
            sys::close(prev_read);
        }
        let job = &mut self.jobs[slot];
        job.pgid = pgid;
        let len = text.len().min(JOB_TEXT);
        job.text[..len].copy_from_slice(&text[..len]);
        job.text_len = len;
        if started == 0 {
            *job = NO_JOB;
            if self.jobctl {
                tcsetpgrp(0, self.pgid);
            }
            self.status = 1;
            return;
        }
        if background {
            self.seq += 1;
            let job = &mut self.jobs[slot];
            job.seq = self.seq;
            job.background = true;
            let last = job.procs[job.count - 1].pid;
            self.last_bg = Some(last);
            if self.interactive {
                // XCU 2.9.3.1: "[%d] %d\n" on standard error.
                let mut w = Writer::new(2);
                w.put(b"[")
                    .num(slot as i64 + 1)
                    .put(b"] ")
                    .num(i64::from(last))
                    .put(b"\n");
                w.flush();
            }
            self.status = 0;
        } else {
            self.foreground(slot);
        }
    }

    /// The child side of a launch: never returns.
    #[allow(clippy::too_many_arguments)]
    fn child(
        &mut self,
        cmd: &Command,
        arena: &Arena,
        pgid: i32,
        foreground: bool,
        background: bool,
        stdin: i32,
        pipe: [i32; 2],
    ) -> ! {
        if self.jobctl {
            let pgid = if pgid == 0 {
                sys::getpid() as i32
            } else {
                pgid
            };
            sys::setpgid(0, pgid);
            if foreground {
                tcsetpgrp(0, pgid);
            }
        }
        for s in [SIGINT, SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU] {
            disposition(s, SIG_DFL);
        }
        if !self.jobctl && background {
            disposition(SIGINT, SIG_IGN);
            disposition(SIGQUIT, SIG_IGN);
            if stdin < 0 {
                let null = sys::open(c"/dev/null", O_RDONLY, 0);
                if null >= 0 {
                    sys::dup2(null as i32, 0);
                    sys::close(null as i32);
                }
            }
        }
        if stdin >= 0 {
            sys::dup2(stdin, 0);
            sys::close(stdin);
        }
        if pipe[1] >= 0 {
            sys::dup2(pipe[1], 1);
            sys::close(pipe[1]);
            sys::close(pipe[0]);
        }
        // The shell's state is this process's own copy from here on.
        self.interactive = false;
        self.jobctl = false;
        for r in &cmd.redirects[..cmd.nredirect] {
            if !apply(r, arena) {
                keel_rt::exit(1);
            }
        }
        let mut words = &cmd.args[..cmd.argc];
        while let Some((first, rest)) = words.split_first() {
            let Some((name, value)) = assignment(arena.bytes(*first)) else {
                break;
            };
            if !self.vars.set(name, value, Some(true)) {
                complain(&[b"too many variables"]);
                keel_rt::exit(1);
            }
            words = rest;
        }
        let Some(first) = words.first() else {
            keel_rt::exit(0)
        };
        let name = arena.bytes(*first);
        let status = if SPECIAL.contains(&name) {
            self.builtin(arena, words)
        } else if UTILITIES.contains(&name) {
            self.utility(arena, words)
        } else {
            self.exec(arena, words)
        };
        keel_rt::exit(status)
    }

    /// execve with a PATH search (XCU 2.9.1.4), as musl's `execvp`: an
    /// entry that is missing or not a directory goes on to the next;
    /// EACCES is remembered. Returns the status if nothing ran.
    fn exec(&self, arena: &Arena, words: &[Word]) -> i32 {
        let mut argv: [&CStr; sys::EXECVE_MAX] = [c""; sys::EXECVE_MAX];
        for (slot, w) in argv.iter_mut().zip(words) {
            *slot = arena.c(*w);
        }
        let argv = &argv[..words.len()];
        let mut envp: [&CStr; sys::EXECVE_MAX] = [c""; sys::EXECVE_MAX];
        let mut envc = 0;
        for i in 0..self.vars.count {
            if self.vars.list[i].exported && envc < envp.len() - 1 {
                envp[envc] = self.vars.entry_c(i);
                envc += 1;
            }
        }
        let envp = &envp[..envc];
        let name = arena.bytes(words[0]);
        if name.contains(&b'/') {
            let e = sys::execve(arena.c(words[0]), Some(argv), envp);
            complain(&[name, b": ", strerror(e)]);
            return if e == ENOENT { 127 } else { 126 };
        }
        let path = self.vars.get(b"PATH").unwrap_or(DEFAULT_PATH);
        let mut denied = false;
        for dir in path.split(|&c| c == b':') {
            let dir: &[u8] = if dir.is_empty() { b"." } else { dir };
            let mut full = [0u8; 1024];
            let len = dir.len() + 1 + name.len();
            if len >= full.len() {
                continue;
            }
            full[..dir.len()].copy_from_slice(dir);
            full[dir.len()] = b'/';
            full[dir.len() + 1..len].copy_from_slice(name);
            let Ok(c) = CStr::from_bytes_until_nul(&full[..=len]) else {
                continue;
            };
            match sys::execve(c, Some(argv), envp) {
                ENOENT | ENOTDIR => {}
                EACCES => denied = true,
                e => {
                    complain(&[name, b": ", strerror(e)]);
                    return 126;
                }
            }
        }
        if denied {
            complain(&[name, b": ", strerror(EACCES)]);
            126
        } else {
            complain(&[name, b": not found"]);
            127
        }
    }

    // --- jobs ------------------------------------------------------------------------

    /// A free job slot; without job control, finished jobs nobody waited
    /// for are dropped first if the table is full.
    fn new_job(&mut self) -> Option<usize> {
        let free = |jobs: &[Job; JOBS]| jobs.iter().position(|j| !j.used);
        let slot = free(&self.jobs).or_else(|| {
            for j in &mut self.jobs {
                if j.done() {
                    *j = NO_JOB;
                }
            }
            free(&self.jobs)
        })?;
        self.jobs[slot] = NO_JOB;
        self.jobs[slot].used = true;
        Some(slot)
    }

    /// Records a wait status for `pid`.
    fn record(&mut self, pid: i32, raw: i32) {
        for job in self.jobs.iter_mut().filter(|j| j.used) {
            let count = job.count;
            if let Some(p) = job.procs[..count].iter_mut().find(|p| p.pid == pid) {
                p.state = if raw & 0xff == 0x7f {
                    job.notified = false;
                    State::Stopped((raw >> 8) & 0xff)
                } else if raw == 0xffff {
                    State::Running
                } else {
                    State::Done(raw)
                };
                return;
            }
        }
    }

    /// Collects every status ready now.
    fn reap(&mut self) {
        loop {
            let mut raw = 0;
            let pid = sys::wait4(-1, &mut raw, WNOHANG | WUNTRACED | WCONTINUED);
            if pid <= 0 {
                return;
            }
            self.record(pid as i32, raw);
        }
    }

    /// Blocks for the next status; false if there is no child.
    fn reap_one(&mut self) -> Result<(), i64> {
        let mut raw = 0;
        let pid = sys::wait4(-1, &mut raw, WUNTRACED);
        if pid < 0 {
            return Err(pid);
        }
        self.record(pid as i32, raw);
        Ok(())
    }

    /// Waits for a job in the foreground to end or stop (glibc manual
    /// 29.5.4 `put_job_in_foreground`), then takes the terminal back.
    fn foreground(&mut self, slot: usize) {
        while !self.jobs[slot].done() && self.jobs[slot].stopped().is_none() {
            match self.reap_one() {
                Ok(()) | Err(EINTR) => {}
                Err(_) => break,
            }
        }
        if self.jobctl {
            tcsetpgrp(0, self.pgid);
            if self.jobs[slot].stopped().is_some() {
                self.jobs[slot].modes = tcgetattr(0);
            }
            if let Some(modes) = &self.modes {
                tcsetattr(0, modes);
            }
        }
        let job = self.jobs[slot];
        self.status = job.status();
        if job.stopped().is_some() {
            self.seq += 1;
            self.jobs[slot].seq = self.seq;
            self.jobs[slot].notified = true;
            self.jobs[slot].background = true;
            let mut w = Writer::new(2);
            w.put(b"\n");
            self.notice(&mut w, slot);
            w.flush();
            return;
        }
        if job.done()
            && let Some(State::Done(raw)) = job.procs().last().map(|p| p.state)
        {
            let sig = raw & 0x7f;
            if self.interactive && sig != 0 {
                let mut w = Writer::new(2);
                if sig != SIGINT && sig != SIGPIPE {
                    w.put(signal_text(sig));
                }
                w.put(b"\n");
                w.flush();
            }
        }
        self.jobs[slot] = NO_JOB;
    }

    /// The current job (`%+`): the one stopped or put in the background
    /// most recently.
    fn current(&self) -> Option<usize> {
        (0..JOBS)
            .filter(|&i| self.jobs[i].used)
            .max_by_key(|&i| self.jobs[i].seq)
    }

    /// `[n]+ State\ttext` for one job.
    fn notice(&self, w: &mut Writer, slot: usize) {
        let job = &self.jobs[slot];
        let mark: &[u8] = if self.current() == Some(slot) {
            b"+ "
        } else {
            b"  "
        };
        w.put(b"[").num(slot as i64 + 1).put(b"]").put(mark);
        describe(w, job);
        w.put(b"\t").put(job.text()).put(b"\n");
    }

    /// Before a prompt: reports background jobs that ended (and forgets
    /// them) and jobs that stopped.
    fn notify(&mut self) {
        self.reap();
        let mut w = Writer::new(2);
        for slot in 0..JOBS {
            let job = self.jobs[slot];
            if !job.used {
                continue;
            }
            if job.done() {
                if job.background {
                    self.notice(&mut w, slot);
                }
                self.jobs[slot] = NO_JOB;
            } else if job.stopped().is_some() && !job.notified {
                self.notice(&mut w, slot);
                self.jobs[slot].notified = true;
            }
        }
        w.flush();
    }

    /// A job named by `%n`, `%%`, `%+`, or nothing (the current one).
    fn job_spec(&self, spec: Option<&[u8]>) -> Option<usize> {
        match spec {
            None | Some(b"%" | b"%%" | b"%+") => self.current(),
            Some(s) => {
                let n = number(s.strip_prefix(b"%")?)?;
                let slot = usize::try_from(n).ok()?.checked_sub(1)?;
                self.jobs.get(slot).filter(|j| j.used).map(|_| slot)
            }
        }
    }

    /// The job with a process `pid`.
    fn job_of(&self, pid: i32) -> Option<usize> {
        (0..JOBS).find(|&i| self.jobs[i].used && self.jobs[i].procs().iter().any(|p| p.pid == pid))
    }

    /// Sends `sig` to a job: its group with job control, else each
    /// process.
    fn signal_job(&self, slot: usize, sig: i32) -> i64 {
        let job = &self.jobs[slot];
        if self.jobctl {
            return sys::kill(-job.pgid, sig);
        }
        let mut result = ESRCH;
        for p in job
            .procs()
            .iter()
            .filter(|p| !matches!(p.state, State::Done(_)))
        {
            result = sys::kill(p.pid, sig);
        }
        result
    }

    /// Continues a stopped job (SIGCONT), marking it running.
    fn resume(&mut self, slot: usize) -> bool {
        for p in self.jobs[slot].procs.iter_mut() {
            if matches!(p.state, State::Stopped(_)) {
                p.state = State::Running;
            }
        }
        let ok = self.signal_job(slot, SIGCONT) == 0;
        if !ok {
            complain(&[b"cannot continue the job"]);
        }
        ok
    }

    // --- builtins --------------------------------------------------------------

    fn builtin(&mut self, arena: &Arena, words: &[Word]) -> i32 {
        let mut args = [&b""[..]; ARGS];
        for (slot, w) in args.iter_mut().zip(words) {
            *slot = arena.bytes(*w);
        }
        let args = &args[..words.len()];
        match args[0] {
            b"cd" => self.cd(args),
            b"exit" => {
                let stopped = self.jobs.iter().any(|j| j.used && j.stopped().is_some());
                if self.interactive && stopped && !self.warned {
                    complain(&[b"There are stopped jobs."]);
                    self.just_warned = true;
                    return 1;
                }
                let code = match args.get(1) {
                    Some(a) => match number(a) {
                        Some(n) => (n & 0xff) as i32,
                        None => {
                            complain(&[b"exit: ", a, b": numeric argument required"]);
                            2
                        }
                    },
                    None => self.status,
                };
                self.exit = Some(code);
                code
            }
            b"export" => {
                if args.len() == 1 {
                    let mut w = Writer::new(1);
                    for i in 0..self.vars.count {
                        if self.vars.list[i].exported {
                            w.put(b"export ").put(self.vars.entry(i)).put(b"\n");
                        }
                    }
                    w.flush();
                    return 0;
                }
                let mut status = 0;
                for a in &args[1..] {
                    if let Some((name, value)) = assignment(a) {
                        if !self.vars.set(name, value, Some(true)) {
                            complain(&[b"too many variables"]);
                            status = 1;
                        }
                    } else if valid_name(a) {
                        self.vars.export(a);
                    } else {
                        complain(&[b"export: ", a, b": bad variable name"]);
                        status = 1;
                    }
                }
                status
            }
            b"unset" => {
                for a in &args[1..] {
                    self.vars.unset(a);
                }
                0
            }
            b"jobs" => {
                self.reap();
                let mut w = Writer::new(1);
                for slot in 0..JOBS {
                    if self.jobs[slot].used {
                        self.notice(&mut w, slot);
                        if self.jobs[slot].stopped().is_some() {
                            self.jobs[slot].notified = true;
                        }
                    }
                }
                w.flush();
                // Ended jobs are reported once.
                for j in &mut self.jobs {
                    if j.used && j.done() && j.background {
                        *j = NO_JOB;
                    }
                }
                0
            }
            b"fg" | b"bg" => {
                let fg = args[0] == b"fg";
                if !self.jobctl {
                    complain(&[args[0], b": no job control"]);
                    return 1;
                }
                let Some(slot) = self.job_spec(args.get(1).copied()) else {
                    complain(&[args[0], b": no such job"]);
                    return 1;
                };
                if fg {
                    let mut w = Writer::new(1);
                    w.put(self.jobs[slot].text()).put(b"\n");
                    w.flush();
                    tcsetpgrp(0, self.jobs[slot].pgid);
                    if let Some(modes) = self.jobs[slot].modes {
                        tcsetattr(0, &modes);
                    }
                    self.jobs[slot].background = false;
                    if !self.resume(slot) {
                        tcsetpgrp(0, self.pgid);
                        return 1;
                    }
                    self.foreground(slot);
                    self.status
                } else {
                    if !self.resume(slot) {
                        return 1;
                    }
                    self.seq += 1;
                    let job = &mut self.jobs[slot];
                    job.seq = self.seq;
                    job.background = true;
                    self.last_bg = Some(job.procs[job.count - 1].pid);
                    let mut w = Writer::new(1);
                    w.put(b"[")
                        .num(slot as i64 + 1)
                        .put(b"]+ ")
                        .put(self.jobs[slot].text())
                        .put(b" &\n");
                    w.flush();
                    0
                }
            }
            b"wait" => self.wait(args),
            b"kill" => self.kill(args),
            _ => 127,
        }
    }

    fn cd(&mut self, args: &[&[u8]]) -> i32 {
        let target: &[u8] = match args.get(1) {
            Some(t) => t,
            None => self.vars.get(b"HOME").unwrap_or(b"/"),
        };
        let mut path = [0u8; 1024];
        if target.len() >= path.len() {
            complain(&[b"cd: ", strerror(ENAMETOOLONG)]);
            return 1;
        }
        path[..target.len()].copy_from_slice(target);
        let Ok(c) = CStr::from_bytes_until_nul(&path[..=target.len()]) else {
            return 1;
        };
        let e = sys::chdir(c);
        if e < 0 {
            complain(&[b"cd: ", target, b": ", strerror(e)]);
            return 1;
        }
        let mut cwd = [0u8; 1024];
        if sys::getcwd(&mut cwd) > 0 {
            let len = cwd.iter().position(|&c| c == 0).unwrap_or(0);
            self.vars.set(b"PWD", &cwd[..len], None);
        }
        0
    }

    /// `wait [pid | %n ...]` (XCU `wait`): without operands, every
    /// background job; else each named one, the last one's status.
    fn wait(&mut self, args: &[&[u8]]) -> i32 {
        if args.len() == 1 {
            while self.jobs.iter().any(|j| j.used && j.running()) {
                match self.reap_one() {
                    Ok(()) => {}
                    Err(EINTR) => return 128 + SIGINT,
                    Err(_) => break,
                }
            }
            for j in &mut self.jobs {
                if j.used && j.done() {
                    *j = NO_JOB;
                }
            }
            return 0;
        }
        let mut status = 0;
        for a in &args[1..] {
            let slot = if a.starts_with(b"%") {
                self.job_spec(Some(*a))
            } else {
                number(a).and_then(|pid| self.job_of(pid as i32))
            };
            let Some(slot) = slot else {
                status = 127;
                continue;
            };
            while self.jobs[slot].running() {
                match self.reap_one() {
                    Ok(()) => {}
                    Err(EINTR) => return 128 + SIGINT,
                    Err(_) => break,
                }
            }
            status = self.jobs[slot].status();
            if self.jobs[slot].done() {
                self.jobs[slot] = NO_JOB;
            }
        }
        status
    }

    /// `kill [-s SIG | -SIG] pid | %n ...` (XCU `kill`).
    fn kill(&mut self, args: &[&[u8]]) -> i32 {
        let mut sig = SIGTERM;
        let mut rest = &args[1..];
        match rest.first() {
            Some(&b"-s") => {
                let Some(s) = rest.get(1).and_then(|s| parse_signal(s)) else {
                    complain(&[b"kill: bad signal"]);
                    return 2;
                };
                sig = s;
                rest = &rest[2..];
            }
            Some(a) if a.len() > 1 && a[0] == b'-' => {
                let Some(s) = parse_signal(&a[1..]) else {
                    complain(&[b"kill: ", a, b": bad signal"]);
                    return 2;
                };
                sig = s;
                rest = &rest[1..];
            }
            _ => {}
        }
        if rest.is_empty() {
            complain(&[b"kill: usage: kill [-s SIG | -SIG] pid | %job ..."]);
            return 2;
        }
        let mut status = 0;
        for a in rest {
            let e = if a.starts_with(b"%") {
                match self.job_spec(Some(*a)) {
                    Some(slot) => self.signal_job(slot, sig),
                    None => {
                        complain(&[b"kill: ", a, b": no such job"]);
                        status = 1;
                        continue;
                    }
                }
            } else {
                let negative = a.first() == Some(&b'-');
                match number(if negative { &a[1..] } else { a }) {
                    Some(n) if n <= i64::from(i32::MAX) => {
                        let pid = n as i32;
                        sys::kill(if negative { -pid } else { pid }, sig)
                    }
                    _ => {
                        complain(&[b"kill: ", a, b": not a process"]);
                        status = 1;
                        continue;
                    }
                }
            };
            if e < 0 {
                complain(&[b"kill: ", a, b": ", strerror(e)]);
                status = 1;
            }
        }
        status
    }

    /// The builtin utilities, run in a child.
    fn utility(&self, arena: &Arena, words: &[Word]) -> i32 {
        let mut args = [&b""[..]; ARGS];
        for (slot, w) in args.iter_mut().zip(words) {
            *slot = arena.bytes(*w);
        }
        let args = &args[..words.len()];
        let mut w = Writer::new(1);
        let status = match args[0] {
            b"echo" => {
                let (newline, rest) = match args.get(1) {
                    Some(&b"-n") => (false, &args[2..]),
                    _ => (true, &args[1..]),
                };
                for (i, a) in rest.iter().enumerate() {
                    if i > 0 {
                        w.put(b" ");
                    }
                    w.put(a);
                }
                if newline {
                    w.put(b"\n");
                }
                0
            }
            b"cat" => cat(&args[1..]),
            b"ls" => ls(&mut w, &args[1..]),
            b"pwd" => {
                let mut cwd = [0u8; 1024];
                let n = sys::getcwd(&mut cwd);
                if n < 0 {
                    warn(&[b"pwd: ", strerror(n)]);
                    1
                } else {
                    let len = cwd.iter().position(|&c| c == 0).unwrap_or(0);
                    w.put(&cwd[..len]).put(b"\n");
                    0
                }
            }
            b"sleep" => sleep(args.get(1).copied()),
            b"true" | b":" => 0,
            b"false" => 1,
            b"env" => {
                for i in 0..self.vars.count {
                    if self.vars.list[i].exported {
                        w.put(self.vars.entry(i)).put(b"\n");
                    }
                }
                0
            }
            b"help" => {
                w.put(b"keel-shell builtins:\n  ");
                for (i, b) in SPECIAL.iter().chain(UTILITIES.iter()).enumerate() {
                    if i > 0 {
                        w.put(b" ");
                    }
                    w.put(b);
                }
                w.put(b"\nOther commands are looked up in PATH.\n");
                0
            }
            _ => 127,
        };
        if w.flush() { status } else { 1 }
    }
}

/// Undoes the first `count` saved redirections, last first.
fn restore_upto(saved: [(i32, i64); REDIRECTS], count: usize) -> [(i32, i64); REDIRECTS] {
    for &(fd, copy) in saved[..count].iter().rev() {
        if copy >= 0 {
            sys::dup2(copy as i32, fd);
            sys::close(copy as i32);
        } else if fd >= 0 {
            sys::close(fd);
        }
    }
    [(-1, -1); REDIRECTS]
}

fn target_fd(r: &Redirect) -> i32 {
    match (r.fd, r.op) {
        (-1, Redir::In | Redir::DupIn) => 0,
        (-1, _) => 1,
        (fd, _) => fd,
    }
}

/// Does one redirection (XCU 2.7); false, having said why, if it fails.
fn apply(r: &Redirect, arena: &Arena) -> bool {
    let fd = target_fd(r);
    let target = arena.bytes(r.target);
    let flags = match r.op {
        Redir::In => O_RDONLY,
        Redir::Out => O_WRONLY | O_CREAT | O_TRUNC,
        Redir::Append => O_WRONLY | O_CREAT | O_APPEND,
        Redir::DupIn | Redir::DupOut => {
            if target == b"-" {
                sys::close(fd);
                return true;
            }
            let from = number(target).filter(|&n| n <= i64::from(i32::MAX));
            let Some(from) = from else {
                complain(&[target, b": ambiguous redirect"]);
                return false;
            };
            let e = sys::dup2(from as i32, fd);
            if e < 0 {
                complain(&[target, b": ", strerror(e)]);
                return false;
            }
            return true;
        }
    };
    let opened = sys::open(arena.c(r.target), flags | O_CLOEXEC, 0o666);
    if opened < 0 {
        complain(&[target, b": ", strerror(opened)]);
        return false;
    }
    let opened = opened as i32;
    if opened != fd {
        // dup2 clears close-on-exec on the copy.
        let e = sys::dup2(opened, fd);
        sys::close(opened);
        if e < 0 {
            complain(&[target, b": ", strerror(e)]);
            return false;
        }
    } else {
        sys::fcntl(fd, 2, 0); // F_SETFD 0: keep it across exec
    }
    true
}

// --- utilities -------------------------------------------------------------------

/// Copies `fd` to standard output.
fn copy_out(fd: i32) -> Result<(), i64> {
    let mut buf = [0u8; 4096];
    loop {
        let n = sys::read(fd, &mut buf);
        if n == EINTR {
            continue;
        }
        if n < 0 {
            return Err(n);
        }
        if n == 0 {
            return Ok(());
        }
        if !write_all(1, &buf[..n as usize]) {
            return Err(EIO);
        }
    }
}

/// A NUL-terminated copy of `text` in `buf`.
fn c_path<'a>(text: &[u8], buf: &'a mut [u8; 1024]) -> Option<&'a CStr> {
    if text.len() >= buf.len() {
        return None;
    }
    buf[..text.len()].copy_from_slice(text);
    buf[text.len()] = 0;
    CStr::from_bytes_until_nul(&buf[..=text.len()]).ok()
}

fn cat(files: &[&[u8]]) -> i32 {
    if files.is_empty() {
        return i32::from(copy_out(0).is_err());
    }
    let mut status = 0;
    for f in files {
        let result = if *f == b"-" {
            copy_out(0)
        } else {
            let mut buf = [0u8; 1024];
            let fd = match c_path(f, &mut buf) {
                Some(c) => sys::open(c, O_RDONLY | O_CLOEXEC, 0),
                None => ENAMETOOLONG,
            };
            if fd < 0 {
                Err(fd)
            } else {
                let r = copy_out(fd as i32);
                sys::close(fd as i32);
                r
            }
        };
        if let Err(e) = result {
            warn(&[b"cat: ", f, b": ", strerror(e)]);
            status = 1;
        }
    }
    status
}

/// `ls [-a] [path ...]`: each directory's names, sorted, one per line.
fn ls(w: &mut Writer, args: &[&[u8]]) -> i32 {
    let all = args.first() == Some(&&b"-a"[..]);
    let mut paths = if all { &args[1..] } else { args };
    if paths.is_empty() {
        const DOT: &[&[u8]] = &[b"."];
        paths = DOT;
    }
    let mut status = 0;
    for (k, p) in paths.iter().enumerate() {
        let mut buf = [0u8; 1024];
        let Some(c) = c_path(p, &mut buf) else {
            warn(&[b"ls: ", p, b": ", strerror(ENAMETOOLONG)]);
            status = 2;
            continue;
        };
        let fd = sys::open(c, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
        if fd == ENOTDIR {
            w.put(p).put(b"\n");
            continue;
        }
        if fd < 0 {
            warn(&[b"ls: ", p, b": ", strerror(fd)]);
            status = 2;
            continue;
        }
        if paths.len() > 1 {
            if k > 0 {
                w.put(b"\n");
            }
            w.put(p).put(b":\n");
        }
        list_dir(w, fd as i32, all);
        sys::close(fd as i32);
    }
    status
}

/// Prints a directory's names in byte order. If they do not all fit in
/// the buffer, each bufferful is sorted on its own.
fn list_dir(w: &mut Writer, fd: i32, all: bool) {
    let mut names = [0u8; 16384];
    let mut spans = [(0u16, 0u16); 512];
    let mut count = 0;
    let mut used = 0;
    let mut dents = [0u8; 4096];
    let flush = |w: &mut Writer, names: &[u8], spans: &mut [(u16, u16)]| {
        // Insertion sort: few entries, and no allocator.
        for i in 1..spans.len() {
            let mut j = i;
            while j > 0 {
                let (a, b) = (spans[j - 1], spans[j]);
                let name = |s: (u16, u16)| &names[s.0 as usize..s.0 as usize + s.1 as usize];
                if name(a) <= name(b) {
                    break;
                }
                spans.swap(j - 1, j);
                j -= 1;
            }
        }
        for s in spans.iter() {
            w.put(&names[s.0 as usize..s.0 as usize + s.1 as usize])
                .put(b"\n");
        }
    };
    loop {
        let n = sys::getdents64(fd, &mut dents);
        if n <= 0 {
            break;
        }
        let mut at = 0;
        let n = n as usize;
        // struct linux_dirent64: u64 ino, i64 off, u16 reclen, u8 type,
        // then the NUL-terminated name (getdents64(2)).
        while at + 19 <= n {
            let reclen = usize::from(u16::from_le_bytes([dents[at + 16], dents[at + 17]]));
            if reclen < 19 || at + reclen > n {
                break;
            }
            let field = &dents[at + 19..at + reclen];
            let name = &field[..field.iter().position(|&c| c == 0).unwrap_or(field.len())];
            at += reclen;
            if !all && name.first() == Some(&b'.') {
                continue;
            }
            if count == spans.len() || used + name.len() > names.len() {
                flush(w, &names, &mut spans[..count]);
                count = 0;
                used = 0;
            }
            if name.len() > names.len() {
                continue;
            }
            names[used..used + name.len()].copy_from_slice(name);
            spans[count] = (used as u16, name.len() as u16);
            count += 1;
            used += name.len();
        }
    }
    flush(w, &names, &mut spans[..count]);
}

/// Monotonic time in milliseconds.
fn now_ms() -> i64 {
    let mut ts = [0u8; 16];
    sys::clock_gettime(1, &mut ts); // CLOCK_MONOTONIC
    let mut sec = [0u8; 8];
    let mut nsec = [0u8; 8];
    sec.copy_from_slice(&ts[..8]);
    nsec.copy_from_slice(&ts[8..]);
    i64::from_le_bytes(sec)
        .saturating_mul(1000)
        .saturating_add(i64::from_le_bytes(nsec) / 1_000_000)
}

/// `sleep SECONDS[.FRACTION]`, by poll(2) timeouts until the deadline
/// (a signal that interrupts one only shortens that wait).
fn sleep(arg: Option<&[u8]>) -> i32 {
    let Some(arg) = arg else {
        complain(&[b"sleep: missing operand"]);
        return 1;
    };
    let (whole, fraction) = match arg.iter().position(|&c| c == b'.') {
        Some(dot) => (&arg[..dot], &arg[dot + 1..]),
        None => (arg, &b""[..]),
    };
    let mut ms = match number(if whole.is_empty() { b"0" } else { whole }) {
        Some(s) => s.saturating_mul(1000),
        None => {
            warn(&[b"sleep: ", arg, b": invalid time"]);
            return 1;
        }
    };
    let mut scale = 100;
    for &c in fraction {
        if !c.is_ascii_digit() {
            warn(&[b"sleep: ", arg, b": invalid time"]);
            return 1;
        }
        ms = ms.saturating_add(i64::from(c - b'0') * scale);
        scale /= 10;
    }
    let deadline = now_ms().saturating_add(ms);
    loop {
        let left = deadline - now_ms();
        if left <= 0 {
            return 0;
        }
        sys::poll(&mut [], left.min(i64::from(i32::MAX)) as i32);
    }
}

// --- input -------------------------------------------------------------------------

/// Lines from a descriptor.
struct Reader {
    fd: i32,
    buf: [u8; LINE],
    start: usize,
    end: usize,
}

impl Reader {
    const fn new(fd: i32) -> Self {
        Self {
            fd,
            buf: [0; LINE],
            start: 0,
            end: 0,
        }
    }

    /// The next line, without its newline, in `out`; None at end of
    /// file. A line longer than the buffer comes in pieces.
    fn line(&mut self, out: &mut [u8; LINE]) -> Result<Option<usize>, i64> {
        loop {
            let pending = &self.buf[self.start..self.end];
            if let Some(k) = pending.iter().position(|&c| c == b'\n') {
                out[..k].copy_from_slice(&pending[..k]);
                self.start += k + 1;
                return Ok(Some(k));
            }
            if self.start > 0 {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            if self.end == LINE {
                out.copy_from_slice(&self.buf);
                self.end = 0;
                return Ok(Some(LINE));
            }
            let n = sys::read(self.fd, &mut self.buf[self.end..]);
            if n < 0 {
                // ^C at the prompt: the terminal discards the line.
                self.end = 0;
                return Err(n);
            }
            if n == 0 {
                // End of file (^D on a terminal): what is left is a line.
                let k = self.end;
                self.end = 0;
                if k == 0 {
                    return Ok(None);
                }
                out[..k].copy_from_slice(&self.buf[..k]);
                return Ok(Some(k));
            }
            self.end += n as usize;
        }
    }
}

fn main(startup: &Startup) -> i32 {
    let name = startup.args().next().unwrap_or(b"keel-shell");
    let mut sh = Shell::new(name);
    for entry in startup.env() {
        if let Some((name, value)) = assignment(entry) {
            sh.vars.set(name, value, Some(true));
        }
    }
    let mut args = startup.args().skip(1);
    let mut reader = match args.next() {
        Some(b"-c") => {
            let Some(text) = args.next() else {
                complain(&[b"-c: option requires an argument"]);
                return 2;
            };
            for line in text.split(|&c| c == b'\n') {
                sh.run_line(line);
                if let Some(code) = sh.exit {
                    return code;
                }
            }
            return sh.status;
        }
        Some(script) => {
            let mut buf = [0u8; 1024];
            let fd = match c_path(script, &mut buf) {
                Some(c) => sys::open(c, O_RDONLY | O_CLOEXEC, 0),
                None => ENAMETOOLONG,
            };
            if fd < 0 {
                complain(&[script, b": ", strerror(fd)]);
                return 127;
            }
            Reader::new(fd as i32)
        }
        None => {
            sh.interactive = is_tty(0) && is_tty(2);
            Reader::new(0)
        }
    };
    if sh.interactive {
        sh.start_job_control();
    }
    let mut line = [0u8; LINE];
    loop {
        if sh.interactive {
            sh.notify();
            let mut w = Writer::new(2);
            w.put(sh.vars.get(b"PS1").unwrap_or(b"keel$ "));
            w.flush();
        } else {
            sh.reap();
        }
        match reader.line(&mut line) {
            Ok(Some(n)) => sh.run_line(&line[..n]),
            Ok(None) => {
                if sh.interactive {
                    let stopped = sh.jobs.iter().any(|j| j.used && j.stopped().is_some());
                    if stopped && !sh.just_warned {
                        complain(&[b"There are stopped jobs."]);
                        sh.just_warned = true;
                        continue;
                    }
                    write_all(2, b"exit\n");
                }
                break;
            }
            Err(EINTR) => {
                write_all(2, b"\n");
                sh.status = 128 + SIGINT;
            }
            Err(_) => break,
        }
        if let Some(code) = sh.exit {
            return code;
        }
    }
    sh.status
}

keel_rt::main!(main);
