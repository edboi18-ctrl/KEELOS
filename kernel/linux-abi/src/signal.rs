//! Signal generation and delivery (P3-T6, ADR 0020), after Linux v6.12:
//! `kernel/signal.c` (send_signal_locked, complete_signal, get_signal,
//! force_sig_info_to_task, signal_delivered), `arch/x86/kernel/signal.c`
//! (get_sigframe, handle_signal), `arch/x86/kernel/signal_64.c`
//! (x64_setup_rt_frame, rt_sigreturn, restore_sigcontext) and
//! `arch/x86/kernel/fpu/signal.c`. The frame layout itself is pure data in
//! `keel_core::signal::frame`, tested on the host.
//!
//! Two hooks connect this to the hardware layer:
//! - the fault hook turns a CPU exception in user code into a signal, if
//!   the program has a handler for it that is not blocked; otherwise the
//!   thread ends as before (the default action of every fault signal);
//! - the return hook runs on every return to user mode and delivers what
//!   is pending and not blocked: a handler gets a signal frame on the
//!   user stack, a default action that terminates ends the process.

use alloc::sync::Arc;
use alloc::vec::Vec;

use keel_core::errno::Errno;
use keel_core::signal::frame::{self, SigContext};
use keel_core::signal::{
    self as sig, BUS_ADRALN, DefaultAction, FPE_INTDIV, ILL_ILLOPN, NSIG, SA_NODEFER, SA_ONSTACK,
    SA_RESETHAND, SA_RESTORER, SA_SIGINFO, SEGV_ACCERR, SEGV_MAPERR, SIG_DFL, SIG_IGN, SIGBUS,
    SIGFPE, SIGILL, SIGKILL, SIGSEGV, SIGTRAP, SS_AUTODISARM, SigAction, SigInfo,
};
use keel_hal::arch::x86_64::fpu;
use keel_hal::arch::x86_64::idt::TrapFrame;
use keel_hal::sched::{self, ThreadId};
use keel_hal::sync::IrqMutex;
use keel_hal::syscall::Fault;
use keel_hal::vm::{copy_from_user, copy_to_user};

use crate::process::{self, Process, Trap};

/// Registers the hooks. Call once at boot.
pub fn init() {
    keel_hal::syscall::set_fault_hook(on_fault);
    keel_hal::syscall::set_return_hook(on_return);
}

/// RFLAGS bits (SDM Vol. 1, section 3.4.3).
const CF: u64 = 1 << 0;
const PF: u64 = 1 << 2;
const AF: u64 = 1 << 4;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const TF: u64 = 1 << 8;
const DF: u64 = 1 << 10;
const OF: u64 = 1 << 11;
const RF: u64 = 1 << 16;
const AC: u64 = 1 << 18;
/// What rt_sigreturn takes from the saved flags (`FIX_EFLAGS`,
/// `arch/x86/kernel/signal_64.c`); every other bit stays as it is.
const FIX_EFLAGS: u64 = AC | OF | DF | TF | SF | ZF | AF | PF | CF | RF;

/// `FPE_FLT*` codes (`include/uapi/asm-generic/siginfo.h`).
const FPE_FLTDIV: i32 = 3;
const FPE_FLTOVF: i32 = 4;
const FPE_FLTUND: i32 = 5;
const FPE_FLTRES: i32 = 6;
const FPE_FLTINV: i32 = 7;
/// `TRAP_BRKPT` and `TRAP_TRACE`.
const TRAP_BRKPT: i32 = 1;
const TRAP_TRACE: i32 = 2;
/// The page-fault error code's P (protection) and U (user) bits (SDM
/// Vol. 3A, section 4.7).
const PF_USER: u64 = 1 << 2;

fn is_handler(action: &SigAction) -> bool {
    action.handler != SIG_DFL && action.handler != SIG_IGN
}

/// `sig_handler_ignored`: SIG_IGN, or SIG_DFL for a signal whose default
/// is to be ignored.
fn ignored(signal: i32, action: &SigAction) -> bool {
    action.handler == SIG_IGN
        || (action.handler == SIG_DFL
            && matches!(
                sig::default_action(signal),
                DefaultAction::Ignore | DefaultAction::Continue | DefaultAction::Stop
            ))
}

/// Sends `info` to the process `target` as a whole (kill(2)). SIGKILL
/// ends every thread at once. Otherwise the signal is discarded if the
/// process ignores it and no thread blocks it (Linux discards an ignored
/// signal at generation unless it is blocked: `sig_ignored`), else it goes
/// on the process's pending set and the first thread that does not block
/// it is interrupted, so it takes it on its way back to user mode
/// (`complete_signal`, `wants_signal`).
pub fn send_to_process(target: &Arc<IrqMutex<Process>>, info: SigInfo) {
    let signal = info.signo;
    if signal == SIGKILL {
        process::kill_all_threads(target, SIGKILL);
        return;
    }
    let wake = {
        let mut p = target.lock();
        let Some(action) = p.signals.action(signal) else {
            return;
        };
        let bit = sig::sigmask(signal);
        let taker = p
            .threads
            .iter()
            .find(|(_, t)| t.signals.blocked() & bit == 0)
            .map(|(&id, _)| id);
        if ignored(signal, &action) && taker.is_some() {
            return;
        }
        p.pending.post(info);
        taker
    };
    if let Some(thread) = wake {
        sched::interrupt(ThreadId(thread));
    }
}

/// Sends `info` to one thread (tkill(2), tgkill(2)). SIGKILL still ends
/// the whole process, as on Linux.
pub fn send_to_thread(target: &Arc<IrqMutex<Process>>, thread: ThreadId, info: SigInfo) {
    let signal = info.signo;
    if signal == SIGKILL {
        process::kill_all_threads(target, SIGKILL);
        return;
    }
    let wake = {
        let mut p = target.lock();
        let Some(action) = p.signals.action(signal) else {
            return;
        };
        let Some(t) = p.threads.get_mut(&thread.0) else {
            return;
        };
        let blocked = t.signals.blocked() & sig::sigmask(signal) != 0;
        if ignored(signal, &action) && !blocked {
            return;
        }
        t.signals.pending.post(info);
        !blocked
    };
    if wake {
        sched::interrupt(thread);
    }
}

/// `force_sig_info_to_task` for the running thread: a signal the thread
/// must take now (a fault, or a frame that could not be written). If it
/// is blocked or ignored, its action goes back to SIG_DFL and it is
/// unblocked, so it ends the process. It is queued even if already
/// pending.
fn force(p: &Arc<IrqMutex<Process>>, info: SigInfo) {
    let me = sched::current().0;
    let mut process = p.lock();
    let signal = info.signo;
    let Some(action) = process.signals.action(signal) else {
        return;
    };
    let Some(t) = process.threads.get(&me) else {
        return;
    };
    let blocked = t.signals.blocked() & sig::sigmask(signal) != 0;
    if blocked || action.handler == SIG_IGN {
        process.signals.set_action(
            signal,
            SigAction {
                handler: SIG_DFL,
                ..action
            },
        );
    }
    if let Some(t) = process.threads.get_mut(&me) {
        if blocked {
            let mask = t.signals.blocked() & !sig::sigmask(signal);
            t.signals.set_blocked(mask);
        }
        t.signals.pending.take(signal);
        t.signals.pending.post(info);
    }
}

/// The signal Linux raises for an exception in user code
/// (`arch/x86/kernel/traps.c`, `arch/x86/mm/fault.c`, at v6.12), and the
/// `trap_nr`, `error_code`, `cr2` it records. None for a spurious SIMD
/// exception (`math_error` returns to the program without a signal).
fn fault_signal(
    frame: &TrapFrame,
    fault: Fault,
    space: Option<&keel_hal::vm::AddressSpace>,
) -> Option<(SigInfo, Trap)> {
    let rip = frame.rip;
    let trap = |err| Trap {
        trapno: fault.vector,
        err,
        cr2: 0,
    };
    let (info, trap) = match fault.vector {
        // exc_divide_error: do_error_trap(SIGFPE, FPE_INTDIV, the RIP).
        0 => (SigInfo::fault(SIGFPE, FPE_INTDIV, rip), trap(0)),
        // exc_debug_user: send_sigtrap with the RIP; TRAP_TRACE for a
        // single step (Keel reads no DR6; user code has no hardware
        // breakpoints, so a #DB is a single step or ICEBP).
        1 => {
            let code = if frame.rflags & TF != 0 {
                TRAP_TRACE
            } else {
                TRAP_BRKPT
            };
            (SigInfo::fault(SIGTRAP, code, rip), trap(0))
        }
        // do_int3_user: do_trap(SIGTRAP) with no code: force_sig, SI_KERNEL.
        3 => (SigInfo::kernel(SIGTRAP), trap(0)),
        // exc_overflow, exc_bounds: SIGSEGV, force_sig.
        4 | 5 => (SigInfo::kernel(SIGSEGV), trap(0)),
        // exc_invalid_op: SIGILL, ILL_ILLOPN, the RIP.
        6 => (SigInfo::fault(SIGILL, ILL_ILLOPN, rip), trap(0)),
        // exc_coproc_segment_overrun: SIGFPE, force_sig.
        9 => (SigInfo::kernel(SIGFPE), trap(0)),
        // exc_invalid_tss: SIGSEGV; segment not present and stack
        // segment: SIGBUS; all force_sig with the error code recorded.
        10 => (SigInfo::kernel(SIGSEGV), trap(fault.error_code)),
        11 | 12 => (SigInfo::kernel(SIGBUS), trap(fault.error_code)),
        // exc_general_protection: gp_user_force_sig_segv, force_sig.
        13 => (SigInfo::kernel(SIGSEGV), trap(fault.error_code)),
        // A page fault: SEGV_MAPERR where nothing is mapped (bad_area),
        // SEGV_ACCERR where the mapping forbids the access (access_error);
        // set_signal_archinfo records the error code with the user bit.
        14 => {
            let mapped = space.is_some_and(|s| s.is_mapped(fault.address));
            let code = if mapped { SEGV_ACCERR } else { SEGV_MAPERR };
            (
                SigInfo::fault(SIGSEGV, code, fault.address),
                Trap {
                    trapno: 14,
                    err: fault.error_code | PF_USER,
                    cr2: fault.address,
                },
            )
        }
        // math_error: the code from the unmasked exception flags
        // (fpu__exception_code), the RIP; error code 0.
        16 | 19 => {
            let code = fpu_exception_code(fault.vector)?;
            (SigInfo::fault(SIGFPE, code, rip), trap(0))
        }
        // exc_alignment_check: SIGBUS, BUS_ADRALN, no address.
        17 => (
            SigInfo::fault(SIGBUS, BUS_ADRALN, 0),
            trap(fault.error_code),
        ),
        _ => (SigInfo::kernel(SIGSEGV), trap(fault.error_code)),
    };
    Some((info, trap))
}

/// `fpu__exception_code` (`arch/x86/kernel/fpu/core.c`): for #MF the x87
/// status word's flags not masked in the control word, for #XM MXCSR's
/// flags not masked by its mask bits (7 above each flag). None if no flag
/// is left (a spurious exception).
fn fpu_exception_code(vector: u64) -> Option<i32> {
    let area = sched::save_user_fpu()?;
    let word = |at: usize| u32::from(u16::from_le_bytes([area[at], area[at + 1]]));
    let err = if vector == 16 {
        // FXSAVE layout: FCW at byte 0, FSW at byte 2 (SDM Vol. 1,
        // Table 10-2).
        word(2) & !word(0)
    } else {
        let mxcsr = u32::from_le_bytes([area[24], area[25], area[26], area[27]]);
        !(mxcsr >> 7) & mxcsr
    };
    if err & 0x001 != 0 {
        Some(FPE_FLTINV)
    } else if err & 0x004 != 0 {
        Some(FPE_FLTDIV)
    } else if err & 0x008 != 0 {
        Some(FPE_FLTOVF)
    } else if err & 0x012 != 0 {
        Some(FPE_FLTUND)
    } else if err & 0x020 != 0 {
        Some(FPE_FLTRES)
    } else {
        None
    }
}

/// The fault hook: a fault in user code becomes its signal if the program
/// catches it and does not block it; the return hook then builds the
/// handler's frame. Otherwise (default action, ignored, or blocked: all
/// end the process, as force_sig_info_to_task makes them) the hardware
/// layer ends the thread as before, with the same signal as its status.
fn on_fault(frame: &mut TrapFrame, fault: Fault) -> bool {
    let Some(p) = process::current() else {
        return false;
    };
    let space = p.lock().space.clone();
    let Some((info, trap)) = fault_signal(frame, fault, space.as_deref()) else {
        // Spurious SIMD exception: back to the program, as Linux.
        return true;
    };
    let me = sched::current().0;
    {
        let mut process = p.lock();
        let Some(action) = process.signals.action(info.signo) else {
            return false;
        };
        let Some(t) = process.threads.get_mut(&me) else {
            return false;
        };
        if !is_handler(&action) || t.signals.blocked() & sig::sigmask(info.signo) != 0 {
            return false;
        }
        t.trap = trap;
    }
    force(&p, info);
    true
}

/// What delivery needs about one dequeued signal.
struct Dequeued {
    signal: i32,
    info: SigInfo,
    action: SigAction,
    /// The mask at delivery, which the handler's mask is added to.
    blocked: u64,
    /// The mask the frame saves, for sigreturn to restore: `blocked`, or
    /// the mask ppoll or pselect6 replaced (`sigmask_to_save`).
    to_save: u64,
    signals: sig::ThreadSignals,
    trap: Trap,
}

/// `dequeue_signal`: the next unblocked pending signal, the thread's own
/// first, then the process's. SA_RESETHAND resets the action as the
/// signal is taken (`get_signal`: SA_ONESHOT).
fn dequeue(p: &Arc<IrqMutex<Process>>) -> Option<Dequeued> {
    let me = sched::current().0;
    let mut process = p.lock();
    let process = &mut *process;
    let t = process.threads.get_mut(&me)?;
    let blocked = t.signals.blocked();
    let own = t.signals.pending.set() & !blocked;
    let shared = process.pending.set() & !blocked;
    let signal = sig::next_signal(own).or_else(|| sig::next_signal(shared))?;
    let info = t
        .signals
        .pending
        .take(signal)
        .or_else(|| process.pending.take(signal))?;
    let action = process.signals.action(signal)?;
    if is_handler(&action) && action.flags & SA_RESETHAND != 0 {
        process.signals.set_action(
            signal,
            SigAction {
                handler: SIG_DFL,
                ..action
            },
        );
    }
    let t = process.threads.get(&me)?;
    Some(Dequeued {
        signal,
        info,
        action,
        blocked,
        to_save: t.signals.mask_to_save(),
        signals: t.signals.clone(),
        trap: t.trap,
    })
}

/// The return hook: delivers every pending, unblocked signal, as Linux's
/// exit_to_user_mode_loop calls get_signal until none is left (so several
/// handlers' frames can nest at once).
fn on_return(frame: &mut TrapFrame) {
    sched::clear_interrupt();
    let Some(p) = process::current() else {
        return;
    };
    // Each pass takes one pending signal; a failed frame adds at most one
    // SIGSEGV, and a second failure kills, so this ends.
    for _ in 0..2 * NSIG {
        let Some(d) = dequeue(&p) else {
            // No handler ran (or the last one's frame holds it): put back
            // a mask ppoll or pselect6 replaced (`restore_saved_sigmask`).
            let me = sched::current().0;
            if let Some(t) = p.lock().threads.get_mut(&me) {
                t.signals.restore_saved();
            }
            return;
        };
        match d.action.handler {
            SIG_IGN => continue,
            SIG_DFL => match sig::default_action(d.signal) {
                DefaultAction::Terminate => {
                    process::kill_all_threads(&p, d.signal);
                    return;
                }
                // Job control is not implemented: a stop signal is
                // ignored (ADR 0020).
                DefaultAction::Ignore | DefaultAction::Stop | DefaultAction::Continue => continue,
            },
            _ => {
                if setup_frame(&p, frame, &d).is_err() {
                    // signal_setup_done -> force_sigsegv: a SIGSEGV that
                    // cannot be delivered either ends the process.
                    if d.signal == SIGSEGV {
                        let mut process = p.lock();
                        if let Some(action) = process.signals.action(SIGSEGV) {
                            process.signals.set_action(
                                SIGSEGV,
                                SigAction {
                                    handler: SIG_DFL,
                                    ..action
                                },
                            );
                        }
                    }
                    force(&p, SigInfo::kernel(SIGSEGV));
                }
            }
        }
    }
}

/// The FPU save area size in a frame: Keel's area, plus the 4-byte
/// FP_XSTATE_MAGIC2 with XSAVE (`xstate_sigframe_size`).
fn math_size() -> usize {
    let xsave = fpu::xsave_mask() != 0;
    fpu::area_size()
        + if xsave {
            frame::FP_XSTATE_MAGIC2_SIZE
        } else {
            0
        }
}

/// x64_setup_rt_frame and handle_signal: writes the FPU area and the
/// frame below the user stack (or on the alternate stack), then points
/// the registers at the handler: RDI = signal, RSI = &info, RDX = &uc,
/// RAX = 0, RSP = the frame (its first word, the restorer, is the return
/// address), RIP = the handler; DF, RF and TF cleared; the FPU in its
/// initial state. Then the mask grows by sa_mask and, unless SA_NODEFER,
/// the signal itself, and an SS_AUTODISARM stack is disarmed
/// (signal_delivered). EFAULT without SA_RESTORER, as Linux ("x86-64
/// should always use SA_RESTORER"), or if user memory cannot be written.
fn setup_frame(
    p: &Arc<IrqMutex<Process>>,
    regs: &mut TrapFrame,
    d: &Dequeued,
) -> Result<(), Errno> {
    if d.action.flags & SA_RESTORER == 0 {
        return Err(Errno::EFAULT);
    }
    let xfeatures = fpu::xsave_mask();
    let sp = regs.rsp;
    let alt = d.signals.altstack();
    let placement = frame::place(
        sp,
        d.action.flags & SA_ONSTACK != 0,
        alt,
        d.signals.sas_ss_flags(sp),
        d.signals.on_altstack(sp),
        |a| d.signals.within_altstack(a),
        math_size() as u64,
    )
    .ok_or(Errno::EFAULT)?;
    let mut area: Vec<u8> = sched::save_user_fpu().ok_or(Errno::EFAULT)?;
    area.resize(math_size(), 0);
    frame::finish_fpu_area(&mut area, xfeatures);
    copy_to_user(placement.fpstate, &area).map_err(|_| Errno::EFAULT)?;
    let context = SigContext {
        r8: regs.r8,
        r9: regs.r9,
        r10: regs.r10,
        r11: regs.r11,
        r12: regs.r12,
        r13: regs.r13,
        r14: regs.r14,
        r15: regs.r15,
        rdi: regs.rdi,
        rsi: regs.rsi,
        rbp: regs.rbp,
        rbx: regs.rbx,
        rdx: regs.rdx,
        rax: regs.rax,
        rcx: regs.rcx,
        rsp: regs.rsp,
        rip: regs.rip,
        eflags: regs.rflags,
        cs: regs.cs as u16,
        gs: 0,
        fs: 0,
        ss: regs.ss as u16,
        err: d.trap.err,
        trapno: d.trap.trapno,
        oldmask: d.to_save,
        cr2: d.trap.cr2,
        fpstate: placement.fpstate,
    };
    let uc_flags = frame::UC_SIGCONTEXT_SS
        | frame::UC_STRICT_RESTORE_SS
        | if xfeatures != 0 {
            frame::UC_FP_XSTATE
        } else {
            0
        };
    let siginfo = d.action.flags & SA_SIGINFO != 0;
    let bytes = frame::build(
        d.action.restorer,
        uc_flags,
        alt,
        &context,
        d.to_save,
        siginfo.then_some(d.info),
    );
    // Without SA_SIGINFO Linux leaves the info part as it was.
    let length = if siginfo { frame::SIZE } else { frame::INFO };
    copy_to_user(placement.frame, &bytes[..length]).map_err(|_| Errno::EFAULT)?;

    regs.rdi = d.signal as u64;
    regs.rax = 0;
    regs.rsi = placement.frame + frame::INFO as u64;
    regs.rdx = placement.frame + frame::UC as u64;
    regs.rip = d.action.handler;
    regs.rsp = placement.frame;
    regs.rflags &= !(DF | RF | TF);
    sched::reset_user_fpu();

    let me = sched::current().0;
    let mut process = p.lock();
    if let Some(t) = process.threads.get_mut(&me) {
        let mut mask = d.blocked | d.action.mask;
        if d.action.flags & SA_NODEFER == 0 {
            mask |= sig::sigmask(d.signal);
        }
        t.signals.set_blocked(mask);
        t.signals.forget_saved();
        if t.signals.altstack().flags & SS_AUTODISARM != 0 {
            t.signals.disarm_altstack();
        }
    }
    Ok(())
}

/// rt_sigreturn(2): the handler returned through the restorer, which
/// made this call with RSP just above the frame's `pretcode` (the return
/// popped it). Restores the mask, the alternate stack (errors ignored, as
/// Linux's restore_altstack), the FPU state and every general register,
/// RIP, RSP and the FIX_EFLAGS bits of RFLAGS; returns the saved RAX. A
/// frame that cannot be read, or whose FPU state the CPU would refuse,
/// ends in SIGSEGV (signal_fault).
///
/// CS and SS are not taken from the frame: Keel has one user code and one
/// user data selector, and the return path always uses them.
pub fn rt_sigreturn(p: &Arc<IrqMutex<Process>>, regs: &TrapFrame) -> i64 {
    match restore(p, regs) {
        Ok(rax) => rax as i64,
        Err(()) => {
            force(p, SigInfo::kernel(SIGSEGV));
            0
        }
    }
}

fn restore(p: &Arc<IrqMutex<Process>>, regs: &TrapFrame) -> Result<u64, ()> {
    let start = regs.rsp.checked_sub(8).ok_or(())?;
    let mut bytes = [0u8; frame::INFO];
    copy_from_user(&mut bytes, start).map_err(|_| ())?;
    let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]));
    let mask = word(frame::UC_SIGMASK);
    let mut sc = [0u8; frame::SIGCONTEXT_SIZE];
    sc.copy_from_slice(&bytes[frame::MCONTEXT..frame::MCONTEXT + frame::SIGCONTEXT_SIZE]);
    let context = SigContext::from_bytes(&sc);
    let mut stack = [0u8; sig::STACK_T_SIZE];
    stack.copy_from_slice(&bytes[frame::UC_STACK..frame::UC_STACK + sig::STACK_T_SIZE]);
    let stack = sig::AltStack::from_bytes(&stack);

    let me = sched::current().0;
    {
        let mut process = p.lock();
        if let Some(t) = process.threads.get_mut(&me) {
            t.signals.set_blocked(mask);
            let _ = t.signals.sigaltstack(Some(stack), regs.rsp);
        }
    }

    // fpu__restore_sig: no area means the initial state.
    if context.fpstate == 0 {
        sched::reset_user_fpu();
    } else {
        let xsave = fpu::xsave_mask() != 0;
        let size = fpu::area_size();
        let mut user = alloc::vec![0u8; math_size()];
        // A legacy-only frame may stop after 512 bytes: read what can be
        // read, at least the legacy part.
        if copy_from_user(&mut user, context.fpstate).is_err() {
            user.truncate(512);
            copy_from_user(&mut user, context.fpstate).map_err(|_| ())?;
        }
        let area = frame::fpu_area_for_restore(&user, size, xsave);
        if !sched::load_user_fpu(&area) {
            sched::reset_user_fpu();
            return Err(());
        }
    }

    let new = TrapFrame {
        r8: context.r8,
        r9: context.r9,
        r10: context.r10,
        r11: context.r11,
        r12: context.r12,
        r13: context.r13,
        r14: context.r14,
        r15: context.r15,
        rdi: context.rdi,
        rsi: context.rsi,
        rbp: context.rbp,
        rbx: context.rbx,
        rdx: context.rdx,
        rax: context.rax,
        rcx: context.rcx,
        rsp: context.rsp,
        rip: context.rip,
        rflags: (regs.rflags & !FIX_EFLAGS) | (context.eflags & FIX_EFLAGS),
        ..TrapFrame::default()
    };
    sched::set_pending_frame(new);
    Ok(context.rax)
}

/// Whether the calling thread has a signal pending that it does not
/// block (`signal_pending` after `recalc_sigpending`): a wait that has
/// just unblocked one with a temporary mask ends at once.
pub fn pending_unblocked(p: &Arc<IrqMutex<Process>>) -> bool {
    let me = sched::current().0;
    let process = p.lock();
    process.threads.get(&me).is_some_and(|t| {
        let blocked = t.signals.blocked();
        (t.signals.pending.set() | process.pending.set()) & !blocked != 0
    })
}

/// `set_user_sigmask`: with a mask (8 bytes at `mask`; `size` must be
/// 8, else EINVAL; unreadable EFAULT), blocks it until the call returns
/// to user mode: a handler's frame then saves the replaced mask (and
/// sigreturn restores it), and otherwise `on_return` restores it. Without
/// one (address 0), nothing changes.
pub fn temporary_mask(p: &Arc<IrqMutex<Process>>, mask: u64, size: u64) -> Result<(), Errno> {
    if mask == 0 {
        return Ok(());
    }
    if size != sig::SIGSET_SIZE {
        return Err(Errno::EINVAL);
    }
    let mut b = [0u8; 8];
    copy_from_user(&mut b, mask).map_err(|_| Errno::EFAULT)?;
    let mask = u64::from_le_bytes(b);
    process::with_current_thread(p, |t| t.signals.set_temporary(mask)).ok_or(Errno::ESRCH)
}
