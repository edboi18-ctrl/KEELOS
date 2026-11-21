//! Kernel console: every message goes to COM1 and, once initialised, to
//! the framebuffer text console.
//!
//! Lock order (see docs/locking.md): `SERIAL` before `FRAMEBUFFER`. No
//! other lock is ever taken while either is held.

use core::fmt::{self, Write};

use spin::Mutex;

use crate::boot;
use crate::drivers::framebuffer::TextConsole;
use crate::drivers::serial::{COM1_BASE, SerialPort};

// SAFETY: 0x3F8 is the standard COM1 base (or undecoded when the port is
// not fitted). This static is the only long-lived handle; the panic path
// creates a second one only after normal printing has stopped for good.
static SERIAL: Mutex<SerialPort> = Mutex::new(unsafe { SerialPort::new(COM1_BASE) });

static FRAMEBUFFER: Mutex<Option<TextConsole<'static>>> = Mutex::new(None);

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
