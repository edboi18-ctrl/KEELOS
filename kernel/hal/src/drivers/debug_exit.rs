//! QEMU `isa-debug-exit` test device.
//!
//! The test harness starts QEMU with
//! `-device isa-debug-exit,iobase=0xf4,iosize=0x04`. A write of value `v`
//! to that port makes QEMU exit with status `(v << 1) | 1`
//! (QEMU source, `hw/misc/debugexit.c`, `debug_exit_write`). On real
//! hardware nothing is expected to decode port 0xf4, so the write is
//! ignored; the kernel only calls this in self-test mode.

use crate::arch::x86_64::port::outb;

const DEBUG_EXIT_PORT: u16 = 0xf4;

/// Outcome reported to the host test harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitCode {
    /// QEMU exits with status 33 (`(0x10 << 1) | 1`).
    Success = 0x10,
    /// QEMU exits with status 35 (`(0x11 << 1) | 1`).
    Failure = 0x11,
}

/// Asks QEMU to exit. Returns if the device is absent.
pub fn exit_qemu(code: ExitCode) {
    // SAFETY: port 0xf4 is the isa-debug-exit device under the test
    // harness and is undecoded otherwise; a one-byte write there cannot
    // affect memory safety.
    unsafe { outb(DEBUG_EXIT_PORT, code as u8) }
}
