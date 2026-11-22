//! System-call dispatch and user-fault handling (P1-T10, P1-T13).
//!
//! The hardware layer only moves registers: the Linux x86-64 convention
//! (`man 2 syscall`) puts the number in RAX and arguments in RDI, RSI,
//! RDX, R10, R8, R9, and the result (or -errno) in RAX. What each call
//! means is decided by the handler that `linux-abi` registers at boot, in
//! safe Rust. Without a handler every call fails with ENOSYS (SR-10).

use crate::arch::x86_64::idt::{TrapFrame, exception_name};
use crate::sched;
use crate::sync::IrqMutex;

/// Linux errno ENOSYS (include/uapi/asm-generic/errno.h: 38).
const ENOSYS: i64 = 38;

/// One system call as the handler sees it.
#[derive(Clone, Copy, Debug)]
pub struct SyscallArgs {
    pub number: u64,
    pub args: [u64; 6],
    /// The caller's user stack pointer (sigaltstack(2) checks it).
    pub user_rsp: u64,
}

/// The registered system-call handler: arguments in, RAX out.
pub type Handler = fn(&SyscallArgs) -> i64;

static HANDLER: IrqMutex<Option<Handler>> = IrqMutex::new(None);

/// Registers the system-call handler. Call once at boot.
pub fn set_handler(handler: Handler) {
    *HANDLER.lock() = Some(handler);
}

/// Handles a SYSCALL; the result goes into the frame's RAX.
pub(crate) fn dispatch(frame: &mut TrapFrame) {
    let call = SyscallArgs {
        number: frame.rax,
        args: [
            frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
        ],
        user_rsp: frame.rsp,
    };
    // Copy the handler out so the lock is not held during the call, which
    // may block or switch threads.
    let handler = *HANDLER.lock();
    let result = match handler {
        Some(handler) => handler(&call),
        None => -ENOSYS,
    };
    frame.rax = result as u64;
}

/// Exit status for a thread killed by an exception: 128 + the signal
/// Linux would deliver (SIGILL 4, SIGTRAP 5, SIGBUS 7, SIGFPE 8,
/// SIGSEGV 11), as a shell reports it.
fn status_for(vector: u64) -> i64 {
    128 + match vector {
        0 | 16 | 19 => 8, // #DE, #MF, #XM
        1 | 3 => 5,       // #DB, #BP
        6 => 4,           // #UD
        17 => 7,          // #AC
        _ => 11,          // #GP, #PF, #SS, #NP, ...
    }
}

/// Ends a thread whose user code raised an exception the kernel could not
/// resolve.
pub(crate) fn user_fault(frame: &mut TrapFrame) {
    let address = if frame.vector == 14 {
        crate::arch::x86_64::cpu::read_cr2()
    } else {
        0
    };
    sched::record_user_fault(sched::UserFault {
        vector: frame.vector,
        error_code: frame.error_code,
        address,
        rip: frame.rip,
        user_rflags: frame.rflags,
        handler_rflags: crate::arch::x86_64::cpu::rflags(),
    });
    crate::console::emergency_print(format_args!(
        "user fault: {} at {:#x} (error {:#x}, address {:#x}); thread ends\n",
        exception_name(frame.vector),
        frame.rip,
        frame.error_code,
        address
    ));
    sched::exit_with(status_for(frame.vector));
}
