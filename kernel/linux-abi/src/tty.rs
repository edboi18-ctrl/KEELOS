//! The console terminal (P1-T14): keyboard bytes from the i8042 are
//! decoded (scancode set 1, US layout) and fed to a canonical-mode line
//! discipline; `/dev/console` reads take finished lines.
//!
//! The keyboard callback runs in interrupt context, so it only takes
//! `IrqMutex` locks and wakes wait queues. Echo is printed by a kernel
//! thread, because the console output locks are spinlocks the interrupted
//! code could be holding.

use alloc::vec::Vec;

use keel_core::keyboard::Decoder;
use keel_core::tty::LineDiscipline;
use keel_hal::drivers::ps2;
use keel_hal::kprint;
use keel_hal::sched::{self, WaitQueue};
use keel_hal::sync::IrqMutex;

struct Terminal {
    decoder: Decoder,
    line: LineDiscipline,
    echo: Vec<u8>,
}

static TERMINAL: IrqMutex<Terminal> = IrqMutex::new(Terminal {
    decoder: Decoder::new(),
    line: LineDiscipline::new(),
    echo: Vec::new(),
});
/// Readers waiting for a line.
static INPUT: WaitQueue = WaitQueue::new();
/// The echo thread waiting for output.
static ECHO: WaitQueue = WaitQueue::new();
/// Echo held for printing at most (more is dropped, input is not).
const ECHO_MAX: usize = 4096;

/// Interrupt context: one byte from the keyboard.
fn on_keyboard_byte(byte: u8) {
    {
        let mut t = TERMINAL.lock();
        let Terminal {
            decoder,
            line,
            echo,
        } = &mut *t;
        if let Some(c) = decoder.feed(byte) {
            let mut out = Vec::new();
            line.input(c, &mut out);
            let room = ECHO_MAX.saturating_sub(echo.len());
            echo.extend_from_slice(&out[..out.len().min(room)]);
        }
    }
    INPUT.wake_all();
    ECHO.wake_all();
}

fn echo_thread() {
    loop {
        ECHO.wait_until(|| !TERMINAL.lock().echo.is_empty());
        let echo = core::mem::take(&mut TERMINAL.lock().echo);
        // Kernel-generated from decoded keys: ASCII text, BS, `^X`.
        if let Ok(text) = core::str::from_utf8(&echo) {
            kprint!("{text}");
        }
    }
}

/// Sets up the keyboard and starts the echo thread.
pub fn init() -> Result<(), ps2::Ps2Error> {
    ps2::init(on_keyboard_byte)?;
    sched::spawn("console-echo", echo_thread).map_err(|_| ps2::Ps2Error::Interrupt)?;
    Ok(())
}

/// Reads one line (or what fits in `buf`), waiting until one is ready.
/// Returns 0 at end of file (Ctrl+D on an empty line).
pub fn read(buf: &mut [u8]) -> usize {
    loop {
        INPUT.wait_until(|| TERMINAL.lock().line.readable());
        if let Some(n) = TERMINAL.lock().line.read(buf) {
            return n;
        }
    }
}

/// Types `bytes` (set-1 scancodes) through the controller, for tests.
pub fn type_scancodes(bytes: &[u8]) -> Result<(), ps2::Ps2Error> {
    for &b in bytes {
        ps2::inject(b)?;
    }
    Ok(())
}
