//! Kernel console: every message goes to COM1 and, once initialised, to
//! the framebuffer text console.
//!
//! Lock order (see docs/locking.md): `SERIAL` before `FRAMEBUFFER`. No
//! other lock is ever taken while either is held.

use core::fmt::{self, Write};

use crate::sync::IrqMutex;

use crate::boot;
use crate::drivers::framebuffer::TextConsole;
use crate::drivers::serial::{COM1_BASE, COM2_BASE, SerialPort};

// SAFETY: 0x3F8 is the standard COM1 base (or undecoded when the port is
// not fitted). This static is the only long-lived handle; the panic path
// creates a second one only after normal printing has stopped for good.
static SERIAL: IrqMutex<SerialPort> = IrqMutex::new(unsafe { SerialPort::new(COM1_BASE) });

static FRAMEBUFFER: IrqMutex<Option<TextConsole<'static>>> = IrqMutex::new(None);

// SAFETY: 0x2F8 is the standard COM2 base, as for COM1 above. Only the
// kernel's result lines go here: user programs cannot do port I/O (IOPL 0,
// no I/O permission bitmap; SR-9), and no device node leads to it.
static RESULTS: IrqMutex<SerialPort> = IrqMutex::new(unsafe { SerialPort::new(COM2_BASE) });

/// Writes one line the test harness trusts (a `TEST` result, a summary,
/// an acceptance marker, a layout line) to COM2, which only the kernel can
/// write, and also to the normal console for people reading it. Programs
/// share COM1 and the screen with the kernel, so a hostile one could print
/// a forged result line there; `cargo xtask test` reads results from COM2
/// only (Phase 2 audit, item 3). Without a COM2 nothing is lost: the line
/// is still on the console.
pub fn _result(args: fmt::Arguments) {
    let _ = RESULTS.lock().write_fmt(args);
    _print(args);
}

/// As [`_result`], from the panic and fatal-fault paths: no locks waited
/// on, fresh port handles (see [`emergency_print`]).
pub fn emergency_result(args: fmt::Arguments) {
    // SAFETY: as in `emergency_print`, for COM2.
    let mut results = unsafe { SerialPort::new(COM2_BASE) };
    results.init();
    let _ = results.write_fmt(args);
    emergency_print(args);
}

/// As [`emergency_serial`], also on COM2: a fixed line from a nested panic.
pub fn emergency_result_serial(text: &str) {
    // SAFETY: as in `emergency_print`, for COM2.
    let mut results = unsafe { SerialPort::new(COM2_BASE) };
    results.init();
    let _ = results.write_str(text);
    emergency_serial(text);
}

/// Initialises COM1, and COM2 for result lines. Returns whether COM1
/// answered the loopback test.
pub fn init_serial() -> bool {
    RESULTS.lock().init();
    let present = SERIAL.lock().init();
    COM1_READY.store(present, core::sync::atomic::Ordering::Release);
    present
}

/// Set once COM1 is initialised and answered: the emergency paths then use
/// it as it is, since programming it again would clear its receive
/// interrupt (IER) and FIFOs, and user faults, which print through them,
/// are not the end of the system.
static COM1_READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// A lock-free COM1 handle for the emergency paths: the set-up one, or a
/// freshly initialised one before that.
fn emergency_com1() -> SerialPort {
    if COM1_READY.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: `init_serial` set COM1 up and it answered; this handle
        // only writes bytes, as the emergency paths below explain.
        unsafe { SerialPort::attached(COM1_BASE) }
    } else {
        // SAFETY: as in `emergency_print`.
        let mut serial = unsafe { SerialPort::new(COM1_BASE) };
        serial.init();
        serial
    }
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
    // The console locks disable interrupts, and a UART at 115200 baud
    // takes about 0.36 s for 4 KiB, while each newline can scroll the whole
    // framebuffer. So user text goes out in pieces of at most `PIECE` bytes,
    // ending after a newline, with the locks released (and interrupts
    // allowed) between pieces (audit 2, A3). Pieces end on UTF-8 character
    // boundaries, so the split never turns a valid character into U+FFFD.
    const PIECE: usize = 64;
    let mut rest = bytes;
    while !rest.is_empty() {
        let mut end = rest.len().min(PIECE);
        if let Some(newline) = rest[..end].iter().position(|&b| b == b'\n') {
            end = newline + 1;
        } else if end < rest.len() {
            // Back off over continuation bytes (10xxxxxx), at most three.
            let mut cut = end;
            while cut > end.saturating_sub(3) && rest[cut] & 0xC0 == 0x80 {
                cut -= 1;
            }
            if rest[cut] & 0xC0 != 0x80 {
                end = cut;
            }
        }
        _print(format_args!("{}", UserText(&rest[..end])));
        rest = &rest[end..];
    }
}

/// Terminal output (the line discipline's, already processed): as
/// [`UserText`], but backspace also passes, which line editing and the
/// echo of an erase need.
pub struct TtyText<'a>(pub &'a [u8]);

impl fmt::Display for TtyText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            for c in chunk.valid().chars() {
                let shown = if c.is_control() && !matches!(c, '\t' | '\n' | '\r' | '\u{8}') {
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

/// COM1 without the newline translation [`SerialPort`]'s `fmt::Write`
/// makes: the line discipline has done it (ONLCR).
struct RawSerial<'a>(&'a mut SerialPort);

impl Write for RawSerial<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.write_raw(s.as_bytes());
        Ok(())
    }
}

/// Writes a terminal's output to the console (COM1 and the screen), as
/// [`TtyText`], in pieces as [`write_user_bytes`] does.
pub fn write_tty_bytes(bytes: &[u8]) {
    const PIECE: usize = 64;
    let mut rest = bytes;
    while !rest.is_empty() {
        let mut end = rest.len().min(PIECE);
        if let Some(newline) = rest[..end].iter().position(|&b| b == b'\n') {
            end = newline + 1;
        } else if end < rest.len() {
            let mut cut = end;
            while cut > end.saturating_sub(3) && rest[cut] & 0xC0 == 0x80 {
                cut -= 1;
            }
            if rest[cut] & 0xC0 != 0x80 {
                end = cut;
            }
        }
        let text = TtyText(&rest[..end]);
        let _ = write!(RawSerial(&mut SERIAL.lock()), "{text}");
        if let Some(console) = FRAMEBUFFER.lock().as_mut() {
            let _ = write!(console, "{text}");
        }
        rest = &rest[end..];
    }
}

/// The vector COM1's received-data interrupt (ISA IRQ 4) arrives on.
pub const SERIAL_VECTOR: u8 = 0x24;
#[cfg(target_os = "none")]
const SERIAL_IRQ: u8 = 4;
#[cfg(target_os = "none")]
static SERIAL_INPUT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// COM1's interrupts so far, and the bytes they took (for self-tests).
static SERIAL_INTERRUPTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static SERIAL_RECEIVED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// COM1's received-data interrupts and the bytes they took.
pub fn serial_input_counts() -> (u64, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    (
        SERIAL_INTERRUPTS.load(Relaxed),
        SERIAL_RECEIVED.load(Relaxed),
    )
}

#[cfg(target_os = "none")]
fn on_serial_interrupt() {
    crate::random::add_interrupt_timing();
    // The 16550's FIFO holds 16 bytes.
    let mut buf = [0u8; 16];
    let n = SERIAL.lock().read_received(&mut buf);
    SERIAL_INTERRUPTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    SERIAL_RECEIVED.fetch_add(n as u64, core::sync::atomic::Ordering::Relaxed);
    let callback = SERIAL_INPUT.load(core::sync::atomic::Ordering::Acquire);
    if n == 0 || callback == 0 {
        return;
    }
    // SAFETY: the only non-zero value stored is a `fn(&[u8])` converted to
    // usize in `init_serial_input`, so converting back gives that function.
    let callback: fn(&[u8]) = unsafe { core::mem::transmute::<usize, fn(&[u8])>(callback) };
    callback(&buf[..n]);
}

/// Delivers what COM1 receives to `callback`, in interrupt context (it may
/// take `IrqMutex` locks and wake wait queues, but not print). Returns
/// false if there is no COM1 or its interrupt could not be routed.
#[cfg(target_os = "none")]
pub fn init_serial_input(callback: fn(&[u8])) -> bool {
    if !serial_present() {
        return false;
    }
    SERIAL_INPUT.store(callback as usize, core::sync::atomic::Ordering::Release);
    if !crate::interrupts::set_handler(SERIAL_VECTOR, on_serial_interrupt)
        || !crate::interrupts::route_isa_irq(SERIAL_IRQ, SERIAL_VECTOR)
    {
        return false;
    }
    SERIAL.lock().enable_rx_interrupt();
    true
}

/// Makes COM1 receive `bytes` through its loopback mode, for self-tests:
/// they arrive by interrupt as if typed on the serial line. COM1 is held
/// meanwhile, so no other output is looped back with them.
pub fn serial_loop_back(bytes: &[u8]) -> bool {
    SERIAL.lock().loop_back(bytes)
}

/// Prints from the panic handler without waiting on any lock.
///
/// The panicking code may hold `SERIAL` or `FRAMEBUFFER`, so this path
/// talks to COM1 through a fresh handle and uses the framebuffer only if
/// its lock happens to be free.
pub fn emergency_print(args: fmt::Arguments) {
    // The kernel is single-threaded with interrupts off when it panics and
    // never resumes normal printing, so this second handle is not used
    // concurrently with `SERIAL`. A user fault's message also comes here,
    // with interrupts off; at worst its bytes interleave with another
    // writer's on the wire.
    let mut serial = emergency_com1();
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
    let mut serial = emergency_com1();
    let _ = serial.write_str(text);
}

/// Prints to the kernel console without a trailing newline.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {
        $crate::console::_print(::core::format_args!($($arg)*))
    };
}

/// A line the test harness trusts, to COM2 and the console (see
/// `console::_result`).
#[macro_export]
macro_rules! kresult {
    ($($arg:tt)*) => {
        $crate::console::_result(::core::format_args!("{}\n", ::core::format_args!($($arg)*)))
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
