//! Catching signals in Keel's own test programs: a handler that only
//! counts what arrives, and the restorer it returns through.
//!
//! The handler does nothing but an atomic add, which is async-signal-safe
//! (it touches no lock and no state a Rust object holds), so catching a
//! signal with it is sound wherever the program is interrupted.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::sys::{self, Arg, Out};

/// Linux has 64 signals (`_NSIG`); index 0 is unused.
static CAUGHT: [AtomicU32; 65] = [const { AtomicU32::new(0) }; 65];

/// SA_RESTORER (`arch/x86/include/uapi/asm/signal.h`): `sa_restorer` is
/// where the handler returns.
const SA_RESTORER: u64 = 0x0400_0000;

/// The handler: counts the signal. Called by the kernel with the System
/// V ABI (signal number in RDI) on a frame Linux aligns as after a call
/// (`get_sigframe`: `round_down(sp, 16) - 8`).
extern "C" fn count(signal: i32) {
    if let Some(slot) = CAUGHT.get(signal as usize) {
        slot.fetch_add(1, Ordering::SeqCst);
    }
}

/// The restorer the handler's `ret` lands on: rt_sigreturn(2).
///
/// Assembly reasoning (spec section 1, rule 4)
/// Entry state: the handler has returned with `ret`, popping the frame's
///   `pretcode` (this function's address, `arch/x86/kernel/signal_64.c`
///   `x64_setup_rt_frame`), so RSP is the frame's address plus 8. The
///   kernel finds the frame at RSP - 8 (`SYSCALL_DEFINE0(rt_sigreturn)`:
///   `regs->sp - sizeof(long)`), so RSP must not change before the call.
/// Instructions:
///   - `mov eax, 15`: the rt_sigreturn number (`syscall_64.tbl`: 15);
///     a 32-bit write zero-extends into RAX (SDM Vol. 1 section 3.4.1.1).
///   - `syscall`: enters the kernel, which restores every register from
///     the frame and does not return here.
///   - `ud2`: never reached; if the kernel ever did return, this traps
///     rather than running into whatever follows.
///
/// Exit state: none (control continues where the signal interrupted).
#[unsafe(naked)]
extern "C" fn restore() {
    // SAFETY: only the kernel jumps here, as described above; the code
    // uses no stack and no Rust state.
    core::arch::naked_asm!("mov eax, 15", "syscall", "ud2");
}

/// Catches `signal` with the counting handler (no SA_RESTART, no other
/// flags, an empty handler mask). Returns rt_sigaction's result.
pub fn catch(signal: i32) -> i64 {
    let mut act = [0u8; 32];
    act[..8].copy_from_slice(&(count as extern "C" fn(i32) as usize as u64).to_le_bytes());
    act[8..16].copy_from_slice(&SA_RESTORER.to_le_bytes());
    act[16..24].copy_from_slice(&(restore as extern "C" fn() as usize as u64).to_le_bytes());
    sys::rt_sigaction(signal, Arg::Buf(&act), Out::Null, 8)
}

/// How many times the handler has run for `signal`.
pub fn caught(signal: i32) -> u32 {
    CAUGHT
        .get(signal as usize)
        .map_or(0, |slot| slot.load(Ordering::SeqCst))
}
