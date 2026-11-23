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
    /// All of the caller's user registers as they came in (fork copies
    /// them into the child).
    pub frame: TrapFrame,
}

/// The registered system-call handler: arguments in, RAX out.
pub type Handler = fn(&SyscallArgs) -> i64;

static HANDLER: IrqMutex<Option<Handler>> = IrqMutex::new(None);

/// Registers the system-call handler. Call once at boot.
pub fn set_handler(handler: Handler) {
    *HANDLER.lock() = Some(handler);
}

/// A user exception the kernel could not resolve, as the fault hook sees
/// it: what Linux records as `trap_nr`, `error_code` and `cr2` for the
/// signal frame (`arch/x86/kernel/traps.c`, `arch/x86/mm/fault.c`).
#[derive(Clone, Copy, Debug)]
pub struct Fault {
    pub vector: u64,
    pub error_code: u64,
    /// CR2 for a page fault, else 0.
    pub address: u64,
}

/// Turns a user fault into a signal: returns true if the thread should
/// carry on (a handler will run; the return hook builds its frame), false
/// if the thread is to end as it did before signals existed.
pub type FaultHook = fn(&mut TrapFrame, Fault) -> bool;

/// Runs on every return to user mode, with interrupts disabled, before
/// the exit check: where pending signals are delivered. It may change any
/// register in the frame; `prepare_user_return` then makes the frame safe.
pub type ReturnHook = fn(&mut TrapFrame);

static FAULT_HOOK: IrqMutex<Option<FaultHook>> = IrqMutex::new(None);
static RETURN_HOOK: IrqMutex<Option<ReturnHook>> = IrqMutex::new(None);

/// Registers the fault hook. Call once at boot.
pub fn set_fault_hook(hook: FaultHook) {
    *FAULT_HOOK.lock() = Some(hook);
}

/// Registers the return hook. Call once at boot.
pub fn set_return_hook(hook: ReturnHook) {
    *RETURN_HOOK.lock() = Some(hook);
}

/// Runs the return hook, if there is one, on a frame about to return to
/// user mode.
pub(crate) fn user_return(frame: &mut TrapFrame) {
    let hook = *RETURN_HOOK.lock();
    if let Some(hook) = hook {
        hook(frame);
    }
}

/// Handles a SYSCALL; the result goes into the frame's RAX.
pub(crate) fn dispatch(frame: &mut TrapFrame) {
    let call = SyscallArgs {
        number: frame.rax,
        args: [
            frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
        ],
        user_rsp: frame.rsp,
        frame: *frame,
    };
    // Copy the handler out so the lock is not held during the call, which
    // may block or switch threads.
    let handler = *HANDLER.lock();
    // The call runs with interrupts enabled, as on Linux, so the timer
    // can preempt a long one (a 2 GiB getrandom took 70 s under emulation
    // with every other thread stalled; found by the fuzzer). This is safe
    // because every kernel lock is an IrqMutex, which disables interrupts
    // while held, so no thread is ever preempted holding a lock
    // (docs/locking.md); kernel threads already run preemptibly on the
    // same code. The register state is all in `frame` on this thread's
    // kernel stack, and the entry code's per-CPU scratch is not used
    // after the frame is built. Interrupts are disabled again before
    // returning: the exit path switches to the user-view page tables and
    // the trampoline stack and must not be interrupted.
    let preemptible = crate::interrupts::are_enabled();
    if preemptible {
        // SAFETY: interrupts are set up (`are_enabled`), and this thread
        // holds no lock here: `HANDLER`'s guard was dropped above.
        unsafe { crate::arch::x86_64::cpu::enable_interrupts() };
    }
    let result = match handler {
        Some(handler) => handler(&call),
        None => -ENOSYS,
    };
    crate::arch::x86_64::cpu::disable_interrupts();
    frame.rax = result as u64;
    // execve replaced the program, or rt_sigreturn restores the registers
    // a signal interrupted: return with those registers. For execve every
    // general register is 0, as Linux's elf_common_init clears them for a
    // new program (`arch/x86/include/asm/elf.h` at v6.12; RAX is execve's
    // return value, 0), and RFLAGS has only IF and the reserved bit 1, as
    // start_thread_common sets (`arch/x86/kernel/process_64.c`).
    // prepare_user_return then sets the user selectors, sanitizes RFLAGS,
    // RIP and RSP, and loads the user-view CR3 of the (possibly new) space.
    if let Some(new) = sched::take_pending_frame() {
        // CS and SS stay the user selectors the call came in with: the
        // return path recognizes a return to user mode by CS's privilege
        // level and only then runs prepare_user_return.
        *frame = TrapFrame {
            cs: frame.cs,
            ss: frame.ss,
            vector: frame.vector,
            saved_cr3: frame.saved_cr3,
            ..new
        };
    }
}

/// Exit status for a thread killed by an exception: 128 + the signal
/// Linux delivers for it (`arch/x86/kernel/traps.c` at v6.12; SIGILL 4,
/// SIGTRAP 5, SIGBUS 7, SIGFPE 8, SIGSEGV 11), as a shell reports it. The
/// same mapping as the signal code's (`keel-linux-abi`'s fault_signal).
fn status_for(vector: u64) -> i64 {
    128 + match vector {
        0 | 9 | 16 | 19 => 8, // #DE, coprocessor overrun, #MF, #XM
        1 | 3 => 5,           // #DB, #BP
        6 => 4,               // #UD
        11 | 12 | 17 => 7,    // #NP, #SS, #AC
        _ => 11,              // #GP, #PF, #TS, #OF, #BR, ...
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
    let hook = *FAULT_HOOK.lock();
    let fault = Fault {
        vector: frame.vector,
        error_code: frame.error_code,
        address,
    };
    if hook.is_some_and(|hook| hook(frame, fault)) {
        // A signal handler will see the fault: nothing is recorded, so the
        // thread's exit later is not taken for a fault's.
        return;
    }
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
