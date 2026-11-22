//! Kernel console: every message goes to COM1 and, once initialised, to
//! the framebuffer text console.
//!
//! Lock order (see docs/locking.md): `SERIAL` before `FRAMEBUFFER`. No
//! other lock is ever taken while either is held.

use core::fmt::{self, Write};

use crate::sync::IrqMutex;

use crate::boot;
use crate::drivers::framebuffer::TextConsole;
use crate::drivers::serial::{COM1_BASE, SerialPort};

// SAFETY: 0x3F8 is the standard COM1 base (or undecoded when the port is
// not fitted). This static is the only long-lived handle; the panic path
// creates a second one only after normal printing has stopped for good.
static SERIAL: IrqMutex<SerialPort> = IrqMutex::new(unsafe { SerialPort::new(COM1_BASE) });

static FRAMEBUFFER: IrqMutex<Option<TextConsole<'static>>> = IrqMutex::new(None);

/// Initialises COM1. Returns whether a UART answered the loopback test.
pub fn init_serial() -> bool {
    SERIAL.lock().init()
}

/// Whether COM1 passed its loopback test during [`init_serial`].
pub fn serial_present() -> bool {
    SERIAL.lock().is_present()
}

/// Takes the boot framebuffer and starts mirroring output to it.
/// Returns the text grid size as `(columns, rows)` on success.
pub fn init_framebuffer() -> Option<(usize, usize)> {
    let fb = boot::take_framebuffer()?;
    let console = TextConsole::new(fb.pixels, fb.layout)?;
    let size = (console.cols(), console.rows());
    *FRAMEBUFFER.lock() = Some(console);
    Some(size)
}

/// Text grid size of the framebuffer console as `(columns, rows)`, if it
/// is running.
pub fn framebuffer_size_chars() -> Option<(usize, usize)> {
    FRAMEBUFFER
        .lock()
        .as_ref()
        .map(|console| (console.cols(), console.rows()))
}

/// Cursor of the framebuffer console as `(column, row)`, if it is running.
pub fn framebuffer_cursor() -> Option<(usize, usize)> {
    FRAMEBUFFER.lock().as_ref().map(TextConsole::cursor)
}

/// Whether the framebuffer currently shows `text` starting at
/// `(col, row)`, checked by reading the pixels back.
pub fn framebuffer_shows(col: usize, row: usize, text: &str) -> bool {
    FRAMEBUFFER
        .lock()
        .as_ref()
        .is_some_and(|console| console.text_matches(col, row, text))
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    // Writing to these sinks cannot fail; formatting errors from a
    // `Display` impl are ignored on purpose.
    let _ = SERIAL.lock().write_fmt(args);
    if let Some(console) = FRAMEBUFFER.lock().as_mut() {
        let _ = console.write_fmt(args);
    }
}

/// Untrusted bytes shown as text: control characters other than tab,
/// newline and carriage return (including ESC, so no terminal escape
/// sequences, and the C1 controls U+0080 to U+009F) become U+FFFD, and so
/// does each invalid UTF-8 sequence. Uses `core::str::Utf8Chunks`, so
/// nothing is allocated.
pub struct UserText<'a>(pub &'a [u8]);

impl fmt::Display for UserText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            for c in chunk.valid().chars() {
                let shown = if c.is_control() && !matches!(c, '\t' | '\n' | '\r') {
                    char::REPLACEMENT_CHARACTER
                } else {
                    c
                };
                fmt::Write::write_char(f, shown)?;
            }
            if !chunk.invalid().is_empty() {
                fmt::Write::write_char(f, char::REPLACEMENT_CHARACTER)?;
            }
        }
        Ok(())
    }
}

/// Writes bytes a user program sent to `/dev/console`, as [`UserText`],
/// so a terminal reading the serial line sees only text.
pub fn write_user_bytes(bytes: &[u8]) {
    _print(format_args!("{}", UserText(bytes)));
}

/// Prints from the panic handler without waiting on any lock.
///
/// The panicking code may hold `SERIAL` or `FRAMEBUFFER`, so this path
/// talks to COM1 through a fresh handle and uses the framebuffer only if
/// its lock happens to be free.
pub fn emergency_print(args: fmt::Arguments) {
    // SAFETY: the kernel is single-threaded with interrupts off when it
    // panics and never resumes normal printing, so this second handle is
    // not used concurrently with `SERIAL`.
    let mut serial = unsafe { SerialPort::new(COM1_BASE) };
    serial.init();
    let _ = serial.write_fmt(args);
    if let Some(mut guard) = FRAMEBUFFER.try_lock()
        && let Some(console) = guard.as_mut()
    {
        let _ = console.write_fmt(args);
    }
}

/// Writes `text` to COM1 only, with no formatting and no framebuffer: the
/// last-resort output of a nested panic. Port I/O cannot fault.
pub fn emergency_serial(text: &str) {
    // SAFETY: as in `emergency_print`.
    let mut serial = unsafe { SerialPort::new(COM1_BASE) };
    serial.init();
    let _ = serial.write_str(text);
}

/// Prints to the kernel console without a trailing newline.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {
        $crate::console::_print(::core::format_args!($($arg)*))
    };
}

/// Prints a line to the kernel console.
#[macro_export]
macro_rules! kprintln {
    () => {
        $crate::kprint!("\n")
    };
    ($($arg:tt)*) => {
        $crate::console::_print(::core::format_args!("{}\n", ::core::format_args!($($arg)*)))
    };
}

#[cfg(test)]
mod tests {
    use super::UserText;
    use alloc::format;

    #[test]
    fn user_text_is_only_text() {
        assert_eq!(
            format!("{}", UserText(b"hello\tworld\r\n")),
            "hello\tworld\r\n"
        );
        assert_eq!(format!("{}", UserText("Grüße ✓".as_bytes())), "Grüße ✓");
        // ESC [ 2 J (clear screen), BEL, NUL, DEL.
        assert_eq!(
            format!("{}", UserText(b"\x1b[2J\x07\x00\x7f")),
            "\u{fffd}[2J\u{fffd}\u{fffd}\u{fffd}"
        );
        // C1 control U+009B (CSI) in UTF-8, and invalid bytes.
        assert_eq!(format!("{}", UserText(b"a\xc2\x9bb")), "a\u{fffd}b");
        assert_eq!(format!("{}", UserText(b"a\xffb\xc3")), "a\u{fffd}b\u{fffd}");
    }
}
