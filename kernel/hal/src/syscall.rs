//! System-call dispatch and user-fault handling (P1-T10).
//!
//! Follows the Linux x86-64 convention (`man 2 syscall`): number in RAX,
//! arguments in RDI, RSI, RDX, R10, R8, R9, result in RAX, RCX and R11
//! clobbered. Errors are returned as -errno.
//!
//! P1-T10 provides only what is needed to test the user-mode path: exit,
//! exit_group, and one Keel test call. The Linux system calls themselves
//! arrive with P1-T13 in `keel-linux-abi`. Every other number fails with
//! ENOSYS and is logged once (SR-10: fail closed).

use alloc::collections::BTreeSet;

use crate::arch::x86_64::idt::{TrapFrame, exception_name};
use crate::sched;
use crate::sync::IrqMutex;

/// Linux x86-64 `exit` and `exit_group`
/// (arch/x86/entry/syscalls/syscall_64.tbl: 60 and 231).
pub const SYS_EXIT: u64 = 60;
pub const SYS_EXIT_GROUP: u64 = 231;
/// Keel test call, outside the Linux range: returns its first argument
/// plus one. Removed when the real system-call table lands.
pub const SYS_KEEL_TEST_ADD_ONE: u64 = 0x1000;

/// Linux errno ENOSYS (include/uapi/asm-generic/errno.h: 38).
const ENOSYS: i64 = 38;

static LOGGED: IrqMutex<BTreeSet<u64>> = IrqMutex::new(BTreeSet::new());

/// Handles a SYSCALL; the result goes into the frame's RAX.
pub(crate) fn dispatch(frame: &mut TrapFrame) {
    let number = frame.rax;
    let result: i64 = match number {
        SYS_EXIT | SYS_EXIT_GROUP => sched::exit_with(frame.rdi as i32 as i64),
        SYS_KEEL_TEST_ADD_ONE => frame.rdi.wrapping_add(1) as i64,
        _ => {
            if LOGGED.lock().insert(number) {
                crate::console::emergency_print(format_args!(
                    "syscall: unimplemented {} (args {:#x} {:#x} {:#x}) -> ENOSYS\n",
                    number, frame.rdi, frame.rsi, frame.rdx
                ));
            }
            -ENOSYS
        }
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
