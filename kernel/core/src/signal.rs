//! Signal state of a Linux process: the disposition of each signal
//! (per process, [`SignalState`]), and each thread's blocked mask,
//! alternate signal stack and pending signals ([`ThreadSignals`]), as
//! `rt_sigaction(2)`, `rt_sigprocmask(2)` and `sigaltstack(2)` read and set
//! them; with what delivery needs that is pure data (P3-T6, ADR 0020):
//! pending sets, `siginfo_t`, default actions and the signal frame layout
//! ([`frame`]). `keel-linux-abi` delivers.
//!
//! Every rule below is from Linux v6.12, `kernel/signal.c`
//! (`do_sigaction`, `sys_rt_sigaction`, `sys_rt_sigprocmask`,
//! `sigprocmask`, `do_sigaltstack`) and `include/linux/sched/signal.h`
//! (`on_sig_stack`, `sas_ss_flags`); constants from
//! `arch/x86/include/uapi/asm/signal.h`,
//! `include/uapi/asm-generic/signal-defs.h`,
//! `include/uapi/linux/signal.h` and `include/linux/signal_types.h`.

use crate::errno::Errno;

/// Number of signals (`_NSIG`, `arch/x86/include/asm/signal.h`).
pub const NSIG: usize = 64;
/// `sizeof(sigset_t)` on x86-64: one 64-bit word.
pub const SIGSET_SIZE: u64 = 8;

pub const SIGKILL: i32 = 9;
pub const SIGSTOP: i32 = 19;

/// `rt_sigprocmask` `how` values.
pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

pub const SA_NOCLDSTOP: u64 = 0x0000_0001;
pub const SA_NOCLDWAIT: u64 = 0x0000_0002;
pub const SA_SIGINFO: u64 = 0x0000_0004;
pub const SA_EXPOSE_TAGBITS: u64 = 0x0000_0800;
pub const SA_RESTORER: u64 = 0x0400_0000;
pub const SA_ONSTACK: u64 = 0x0800_0000;
pub const SA_RESTART: u64 = 0x1000_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;
/// Flags the kernel keeps (`UAPI_SA_FLAGS`, with x86's `SA_RESTORER`);
/// Linux clears every other bit, so programs can detect unsupported
/// flags (such as `SA_UNSUPPORTED`, 0x400) by reading the action back.
pub const UAPI_SA_FLAGS: u64 = SA_NOCLDSTOP
    | SA_NOCLDWAIT
    | SA_SIGINFO
    | SA_ONSTACK
    | SA_RESTART
    | SA_NODEFER
    | SA_RESETHAND
    | SA_EXPOSE_TAGBITS
    | SA_RESTORER;

pub const SS_ONSTACK: u32 = 1;
pub const SS_DISABLE: u32 = 2;
pub const SS_AUTODISARM: u32 = 1 << 31;
/// `SS_FLAG_BITS`: flags allowed beside the mode.
pub const SS_FLAG_BITS: u32 = SS_AUTODISARM;
/// Smallest alternate stack (`MINSIGSTKSZ`, x86 uapi).
pub const MINSIGSTKSZ: u64 = 2048;

/// `SIG_DFL` and `SIG_IGN` handler values.
pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

/// `sigmask(sig)`: bit `sig - 1`.
const fn bit(sig: i32) -> u64 {
    1 << (sig - 1)
}

/// SIGKILL and SIGSTOP can be neither blocked nor caught.
const UNBLOCKABLE: u64 = bit(SIGKILL) | bit(SIGSTOP);

/// The kernel's `struct sigaction` on x86-64 (`include/linux/signal_types.h`):
/// handler, flags, restorer, mask; 32 bytes, as `rt_sigaction` copies it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

pub const SIGACTION_SIZE: usize = 32;

impl SigAction {
    pub fn from_bytes(b: &[u8; SIGACTION_SIZE]) -> Self {
        let word = |i: usize| {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i * 8..i * 8 + 8]);
            u64::from_le_bytes(w)
        };
        Self {
            handler: word(0),
            flags: word(1),
            restorer: word(2),
            mask: word(3),
        }
    }

    pub fn to_bytes(self) -> [u8; SIGACTION_SIZE] {
        let mut b = [0u8; SIGACTION_SIZE];
        for (i, w) in [self.handler, self.flags, self.restorer, self.mask]
            .into_iter()
            .enumerate()
        {
            b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        b
    }
}

/// `stack_t` on x86-64: `ss_sp` (8), `ss_flags` (int, then 4 bytes of
/// padding), `ss_size` (8); 24 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AltStack {
    pub sp: u64,
    pub flags: u32,
    pub size: u64,
}

pub const STACK_T_SIZE: usize = 24;

impl AltStack {
    pub fn from_bytes(b: &[u8; STACK_T_SIZE]) -> Self {
        let mut sp = [0u8; 8];
        let mut flags = [0u8; 4];
        let mut size = [0u8; 8];
        sp.copy_from_slice(&b[0..8]);
        flags.copy_from_slice(&b[8..12]);
        size.copy_from_slice(&b[16..24]);
        Self {
            sp: u64::from_le_bytes(sp),
            flags: u32::from_le_bytes(flags),
            size: u64::from_le_bytes(size),
        }
    }

    /// The padding is zero (Linux clears the whole `stack_t` first).
    pub fn to_bytes(self) -> [u8; STACK_T_SIZE] {
        let mut b = [0u8; STACK_T_SIZE];
        b[0..8].copy_from_slice(&self.sp.to_le_bytes());
        b[8..12].copy_from_slice(&self.flags.to_le_bytes());
        b[16..24].copy_from_slice(&self.size.to_le_bytes());
        b
    }
}

/// A process's signal dispositions (`struct sighand_struct`), shared by
/// its threads.
#[derive(Clone, Debug)]
pub struct SignalState {
    actions: [SigAction; NSIG],
}

impl Default for SignalState {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalState {
    /// A new process: every action `SIG_DFL`.
    pub const fn new() -> Self {
        Self {
            actions: [SigAction {
                handler: SIG_DFL,
                flags: 0,
                restorer: 0,
                mask: 0,
            }; NSIG],
        }
    }

    /// `do_sigaction`: returns the previous action, after setting `new`
    /// if given. EINVAL for a signal outside 1..=64, and for setting the
    /// action of SIGKILL or SIGSTOP (reading it is allowed). Unknown flag
    /// bits are cleared, in the stored and the returned action alike, and
    /// SIGKILL and SIGSTOP are removed from the handler's mask.
    pub fn sigaction(&mut self, sig: i32, new: Option<SigAction>) -> Result<SigAction, Errno> {
        if !(1..=NSIG as i32).contains(&sig) || (new.is_some() && (bit(sig) & UNBLOCKABLE) != 0) {
            return Err(Errno::EINVAL);
        }
        let slot = &mut self.actions[(sig - 1) as usize];
        let mut old = *slot;
        old.flags &= UAPI_SA_FLAGS;
        if let Some(mut action) = new {
            action.flags &= UAPI_SA_FLAGS;
            action.mask &= !UNBLOCKABLE;
            *slot = action;
        }
        Ok(old)
    }

    /// execve (Linux v6.12 `fs/exec.c`, begin_new_exec): every caught
    /// signal goes back to `SIG_DFL` and ignored ones stay ignored, with
    /// flags, restorer and mask cleared (`flush_signal_handlers(me, 0)`,
    /// `kernel/signal.c`). execve(2): "The dispositions of any signals that
    /// are being caught are reset to the default."
    pub fn reset_for_exec(&mut self) {
        for action in &mut self.actions {
            if action.handler != SIG_IGN {
                action.handler = SIG_DFL;
            }
            action.flags = 0;
            action.restorer = 0;
            action.mask = 0;
        }
    }

    pub fn action(&self, sig: i32) -> Option<SigAction> {
        (1..=NSIG as i32)
            .contains(&sig)
            .then(|| self.actions[(sig - 1) as usize])
    }

    /// Sets the action for `sig` with no checks (the kernel's own changes:
    /// `SA_RESETHAND`, and a forced fault signal going back to `SIG_DFL`).
    pub fn set_action(&mut self, sig: i32, action: SigAction) {
        if (1..=NSIG as i32).contains(&sig) {
            self.actions[(sig - 1) as usize] = action;
        }
    }
}

/// One thread's signal state: its blocked mask, its alternate stack
/// (`sas_ss_sp`, `sas_ss_size`, `sas_ss_flags`) and the signals pending
/// for it alone (`task_struct.pending`). The process's shared pending set
/// is a separate [`Pending`].
#[derive(Clone, Debug)]
pub struct ThreadSignals {
    blocked: u64,
    /// The mask ppoll, pselect6 (and later epoll_pwait) replaced for their
    /// wait (`saved_sigmask` with TIF_RESTORE_SIGMASK, `set_user_sigmask`):
    /// put back when the call returns, unless a signal interrupted it, in
    /// which case a handler's frame saves it (and sigreturn restores it)
    /// or, with no handler run, the way back to user mode restores it.
    saved: Option<u64>,
    altstack: AltStack,
    pub pending: Pending,
}

impl Default for ThreadSignals {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadSignals {
    /// Nothing blocked or pending, no alternate stack (`sas_ss_reset`:
    /// flags `SS_DISABLE`).
    pub const fn new() -> Self {
        Self {
            blocked: 0,
            saved: None,
            altstack: AltStack {
                sp: 0,
                flags: SS_DISABLE,
                size: 0,
            },
            pending: Pending::new(),
        }
    }

    /// A thread created by clone or fork: the creator's mask and alternate
    /// stack, nothing pending. clone(2): the child's pending set is empty;
    /// "the alternate signal stack is cleared" only with CLONE_VM without
    /// CLONE_VFORK (`kernel/fork.c`, copy_process: `sas_ss_reset` when
    /// `(clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM`).
    pub fn for_child(&self, shares_memory: bool) -> Self {
        let mut child = Self::new();
        child.blocked = self.blocked;
        if !shares_memory {
            child.altstack = self.altstack;
        }
        child
    }

    /// execve keeps the mask and the pending signals and drops the
    /// alternate stack (`sas_ss_sp = sas_ss_size = 0`, begin_new_exec).
    pub fn reset_for_exec(&mut self) {
        self.altstack = AltStack {
            sp: 0,
            flags: SS_DISABLE,
            size: 0,
        };
    }

    /// `rt_sigprocmask` after its size check: returns the mask as it was
    /// before the call. With no new set, `how` is not checked (as Linux).
    pub fn sigprocmask(&mut self, how: i32, set: Option<u64>) -> Result<u64, Errno> {
        let old = self.blocked;
        if let Some(set) = set {
            let set = set & !UNBLOCKABLE;
            self.blocked = match how {
                SIG_BLOCK => old | set,
                SIG_UNBLOCK => old & !set,
                SIG_SETMASK => set,
                _ => return Err(Errno::EINVAL),
            };
        }
        Ok(old)
    }

    pub fn blocked(&self) -> u64 {
        self.blocked
    }

    /// `set_user_sigmask`: blocks `mask` for the length of a call, keeping
    /// the mask it replaces (once: a nested call keeps the first).
    pub fn set_temporary(&mut self, mask: u64) {
        if self.saved.is_none() {
            self.saved = Some(self.blocked);
        }
        self.set_blocked(mask);
    }

    /// `restore_saved_sigmask`: the mask from before `set_temporary`.
    pub fn restore_saved(&mut self) {
        if let Some(mask) = self.saved.take() {
            self.blocked = mask;
        }
    }

    /// `sigmask_to_save`: what a signal frame records as the mask to go
    /// back to, the saved one if a call replaced it.
    pub fn mask_to_save(&self) -> u64 {
        self.saved.unwrap_or(self.blocked)
    }

    /// `clear_restore_sigmask`: a frame now holds the saved mask.
    pub fn forget_saved(&mut self) {
        self.saved = None;
    }

    /// `set_current_blocked`: SIGKILL and SIGSTOP are never blocked.
    pub fn set_blocked(&mut self, mask: u64) {
        self.blocked = mask & !UNBLOCKABLE;
    }

    /// The alternate stack as stored (`unsafe_save_altstack` writes these
    /// three fields, the flags as stored, into a signal frame).
    pub fn altstack(&self) -> AltStack {
        self.altstack
    }

    /// `sas_ss_reset` (after a delivery with `SS_AUTODISARM`).
    pub fn disarm_altstack(&mut self) {
        self.altstack = AltStack {
            sp: 0,
            flags: SS_DISABLE,
            size: 0,
        };
    }

    /// `sas_ss_flags`: `SS_DISABLE` without a stack, else `SS_ONSTACK`
    /// when `sp` is on it.
    pub fn sas_ss_flags(&self, sp: u64) -> u32 {
        if self.altstack.size == 0 {
            SS_DISABLE
        } else if self.on_altstack(sp) {
            SS_ONSTACK
        } else {
            0
        }
    }

    /// `__on_sig_stack`, without the `SS_AUTODISARM` exception: whether
    /// `sp` lies in `(ss_sp, ss_sp + ss_size]`.
    pub fn within_altstack(&self, sp: u64) -> bool {
        sp > self.altstack.sp && sp - self.altstack.sp <= self.altstack.size
    }

    /// `on_sig_stack`: the stack grows down, so `sp` is on the alternate
    /// stack when it lies in `(ss_sp, ss_sp + ss_size]`. Never with
    /// `SS_AUTODISARM`.
    pub fn on_altstack(&self, sp: u64) -> bool {
        if self.altstack.flags & SS_AUTODISARM != 0 {
            return false;
        }
        self.within_altstack(sp)
    }

    /// `do_sigaltstack` with the caller's user stack pointer `sp`: returns
    /// the old stack (as `oss` reports it), after setting `new` if given.
    /// EPERM while running on the alternate stack, EINVAL for an unknown
    /// mode, ENOMEM below `MINSIGSTKSZ`.
    pub fn sigaltstack(&mut self, new: Option<AltStack>, sp: u64) -> Result<AltStack, Errno> {
        let current = self.altstack;
        let mode = if current.size == 0 {
            SS_DISABLE
        } else if self.on_altstack(sp) {
            SS_ONSTACK
        } else {
            0
        };
        let old = AltStack {
            sp: current.sp,
            size: current.size,
            flags: mode | (current.flags & SS_FLAG_BITS),
        };
        if let Some(new) = new {
            if self.on_altstack(sp) {
                return Err(Errno::EPERM);
            }
            let ss_mode = new.flags & !SS_FLAG_BITS;
            if ss_mode != SS_DISABLE && ss_mode != SS_ONSTACK && ss_mode != 0 {
                return Err(Errno::EINVAL);
            }
            // No change requested: success before the size check (Linux
            // returns early here).
            if current == new {
                return Ok(old);
            }
            let stack = if ss_mode == SS_DISABLE {
                AltStack {
                    sp: 0,
                    size: 0,
                    flags: new.flags,
                }
            } else {
                // x86's sigaltstack_size_valid adds a check only for
                // dynamically enabled FPU state (AMX), which Keel does not
                // grant.
                if new.size < MINSIGSTKSZ {
                    return Err(Errno::ENOMEM);
                }
                new
            };
            self.altstack = stack;
        }
        Ok(old)
    }
}

/// Signal numbers delivery treats specially (`arch/x86/include/uapi/asm/signal.h`).
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGTSTP: i32 = 20;
pub const SIGTTIN: i32 = 21;
pub const SIGTTOU: i32 = 22;
pub const SIGURG: i32 = 23;
pub const SIGXCPU: i32 = 24;
pub const SIGXFSZ: i32 = 25;
pub const SIGWINCH: i32 = 28;
pub const SIGSYS: i32 = 31;

/// `si_code` values (`include/uapi/asm-generic/siginfo.h`).
pub const SI_USER: i32 = 0;
pub const SI_KERNEL: i32 = 0x80;
pub const SI_TKILL: i32 = -6;
pub const ILL_ILLOPN: i32 = 2;
pub const FPE_INTDIV: i32 = 1;
pub const SEGV_MAPERR: i32 = 1;
pub const SEGV_ACCERR: i32 = 2;
pub const BUS_ADRALN: i32 = 1;

/// `sigmask(sig)` for callers outside this module.
pub const fn sigmask(sig: i32) -> u64 {
    bit(sig)
}

/// What a signal does with `SIG_DFL` (signal(7), "Standard signals", and
/// `kernel/signal.c`'s `SIG_KERNEL_*_MASK`). Real-time signals terminate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultAction {
    /// "Term" and "Core". Keel writes no core files, so both end the
    /// process with the signal as its wait status and no core-dump bit,
    /// as Linux does when no core is written (RLIMIT_CORE 0).
    Terminate,
    /// "Ign" (SIGCHLD, SIGURG, SIGWINCH).
    Ignore,
    /// "Stop" (SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU).
    Stop,
    /// "Cont" (SIGCONT): resumes a stopped process, else nothing.
    Continue,
}

pub fn default_action(sig: i32) -> DefaultAction {
    match sig {
        SIGCHLD | SIGURG | SIGWINCH => DefaultAction::Ignore,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => DefaultAction::Stop,
        SIGCONT => DefaultAction::Continue,
        _ => DefaultAction::Terminate,
    }
}

/// Signals raised by the CPU for the instruction just run; dequeued before
/// any other (`SYNCHRONOUS_MASK`, `kernel/signal.c`).
pub const SYNCHRONOUS: u64 =
    bit(SIGSEGV) | bit(SIGBUS) | bit(SIGILL) | bit(SIGTRAP) | bit(SIGFPE) | bit(SIGSYS);

/// `next_signal`: the signal to deliver next among `set`, synchronous
/// ones first, then the lowest number.
pub fn next_signal(set: u64) -> Option<i32> {
    if set == 0 {
        return None;
    }
    let pick = if set & SYNCHRONOUS != 0 {
        set & SYNCHRONOUS
    } else {
        set
    };
    Some(pick.trailing_zeros() as i32 + 1)
}

/// `siginfo_t` as delivery fills it: 128 bytes (`SI_MAX_SIZE`), a 16-byte
/// preamble on 64-bit (`si_signo`, `si_errno`, `si_code`, then padding to
/// the union's 8-byte alignment), then the union, of which Keel fills the
/// first 16 bytes (`include/uapi/asm-generic/siginfo.h`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigInfo {
    pub signo: i32,
    pub errno: i32,
    pub code: i32,
    /// The union's first 16 bytes: `si_pid` and `si_uid` (two 32-bit
    /// fields) for kill and tkill, `si_addr` (64 bits) for a fault.
    pub fields: [u8; 16],
}

pub const SIGINFO_SIZE: usize = 128;

impl SigInfo {
    /// kill(2) and friends: `_kill` with the sender's PID and UID.
    pub fn from_process(signo: i32, code: i32, pid: u32, uid: u32) -> Self {
        let mut fields = [0; 16];
        fields[0..4].copy_from_slice(&pid.to_le_bytes());
        fields[4..8].copy_from_slice(&uid.to_le_bytes());
        Self {
            signo,
            errno: 0,
            code,
            fields,
        }
    }

    /// A CPU fault: `_sigfault` with `si_addr` (`force_sig_fault`).
    pub fn fault(signo: i32, code: i32, address: u64) -> Self {
        let mut fields = [0; 16];
        fields[0..8].copy_from_slice(&address.to_le_bytes());
        Self {
            signo,
            errno: 0,
            code,
            fields,
        }
    }

    /// `force_sig`: `SI_KERNEL` with every field 0.
    pub fn kernel(signo: i32) -> Self {
        Self {
            signo,
            errno: 0,
            code: SI_KERNEL,
            fields: [0; 16],
        }
    }

    pub fn to_bytes(self) -> [u8; SIGINFO_SIZE] {
        let mut b = [0u8; SIGINFO_SIZE];
        b[0..4].copy_from_slice(&self.signo.to_le_bytes());
        b[4..8].copy_from_slice(&self.errno.to_le_bytes());
        b[8..12].copy_from_slice(&self.code.to_le_bytes());
        b[16..32].copy_from_slice(&self.fields);
        b
    }
}

/// A set of pending signals (`struct sigpending`), with the `siginfo_t`
/// of each. A standard signal already pending is not queued again
/// (`legacy_queue`, `kernel/signal.c`). Real-time signals (32 and above)
/// are coalesced the same way for now, where Linux would queue every one
/// up to RLIMIT_SIGPENDING: ADR 0020.
#[derive(Clone, Debug)]
pub struct Pending {
    set: u64,
    info: [SigInfo; NSIG],
}

impl Default for Pending {
    fn default() -> Self {
        Self::new()
    }
}

impl Pending {
    pub const fn new() -> Self {
        Self {
            set: 0,
            info: [SigInfo {
                signo: 0,
                errno: 0,
                code: 0,
                fields: [0; 16],
            }; NSIG],
        }
    }

    pub fn set(&self) -> u64 {
        self.set
    }

    /// Adds `info`; returns false if its signal was already pending (or is
    /// not a signal).
    pub fn post(&mut self, info: SigInfo) -> bool {
        if !(1..=NSIG as i32).contains(&info.signo) || self.set & bit(info.signo) != 0 {
            return false;
        }
        self.set |= bit(info.signo);
        self.info[(info.signo - 1) as usize] = info;
        true
    }

    /// Removes `sig`, returning its information if it was pending.
    pub fn take(&mut self, sig: i32) -> Option<SigInfo> {
        if !(1..=NSIG as i32).contains(&sig) || self.set & bit(sig) == 0 {
            return None;
        }
        self.set &= !bit(sig);
        Some(self.info[(sig - 1) as usize])
    }

    /// Drops every signal in `mask` (a signal set to be ignored is
    /// discarded when pending, as `do_sigaction` does with
    /// `flush_sigqueue_mask`).
    pub fn discard(&mut self, mask: u64) {
        self.set &= !mask;
    }
}

/// The x86-64 signal frame (`struct rt_sigframe`,
/// `arch/x86/include/asm/sigframe.h`) and the user context in it
/// (`struct ucontext`, `arch/x86/include/uapi/asm/ucontext.h`;
/// `struct sigcontext`, `arch/x86/include/uapi/asm/sigcontext.h`), at
/// Linux v6.12. Offsets are bytes from the frame's start, where the
/// handler's RSP points.
pub mod frame {
    use super::{AltStack, SIGINFO_SIZE, SigInfo};

    /// `pretcode`: the restorer, as the handler's return address.
    pub const PRETCODE: usize = 0;
    /// `uc`: `struct ucontext`.
    pub const UC: usize = 8;
    /// In `ucontext`: `uc_flags` 0, `uc_link` 8, `uc_stack` 16 (a 24-byte
    /// `stack_t`), `uc_mcontext` 40 (the 256-byte `sigcontext`),
    /// `uc_sigmask` 296; 304 bytes.
    pub const UC_FLAGS: usize = UC;
    pub const UC_LINK: usize = UC + 8;
    pub const UC_STACK: usize = UC + 16;
    pub const MCONTEXT: usize = UC + 40;
    pub const UC_SIGMASK: usize = UC + 296;
    /// `info`: the `siginfo_t`, after the 304-byte ucontext.
    pub const INFO: usize = UC + 304;
    /// `sizeof(struct rt_sigframe)`.
    pub const SIZE: usize = INFO + SIGINFO_SIZE;
    pub const SIGCONTEXT_SIZE: usize = 256;

    /// `uc_flags` bits (`arch/x86/include/uapi/asm/ucontext.h`):
    /// `UC_FP_XSTATE` when the FPU area is in XSAVE format,
    /// `UC_SIGCONTEXT_SS` (the frame's SS is meaningful) and
    /// `UC_STRICT_RESTORE_SS` (sigreturn restores it as saved), as
    /// `frame_uc_flags` sets for a 64-bit task.
    pub const UC_FP_XSTATE: u64 = 1;
    pub const UC_SIGCONTEXT_SS: u64 = 2;
    pub const UC_STRICT_RESTORE_SS: u64 = 4;

    /// The FPU area's software-reserved words (`struct _fpx_sw_bytes`, at
    /// bytes 464 to 511 of the FXSAVE area, which the CPU ignores) and the
    /// magic after the XSAVE area (`arch/x86/include/uapi/asm/sigcontext.h`).
    pub const FPX_SW_BYTES: usize = 464;
    pub const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
    pub const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
    pub const FP_XSTATE_MAGIC2_SIZE: usize = 4;
    /// `sizeof(struct fxregs_state) + sizeof(struct xstate_header)`.
    pub const MIN_XSTATE_SIZE: usize = 512 + 64;
    /// x87 and SSE (`XFEATURE_MASK_FPSSE`).
    pub const XFEATURE_MASK_FPSSE: u64 = 3;

    /// The red zone below a 64-bit program's stack pointer, which a
    /// signal frame must not overwrite (System V AMD64 ABI, section 3.2.2;
    /// `get_sigframe`: `sp -= 128`).
    pub const RED_ZONE: u64 = 128;

    /// `struct sigcontext` (64-bit). The order is the header's.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct SigContext {
        pub r8: u64,
        pub r9: u64,
        pub r10: u64,
        pub r11: u64,
        pub r12: u64,
        pub r13: u64,
        pub r14: u64,
        pub r15: u64,
        pub rdi: u64,
        pub rsi: u64,
        pub rbp: u64,
        pub rbx: u64,
        pub rdx: u64,
        pub rax: u64,
        pub rcx: u64,
        pub rsp: u64,
        pub rip: u64,
        pub eflags: u64,
        pub cs: u16,
        pub gs: u16,
        pub fs: u16,
        pub ss: u16,
        pub err: u64,
        pub trapno: u64,
        pub oldmask: u64,
        pub cr2: u64,
        pub fpstate: u64,
    }

    impl SigContext {
        pub fn to_bytes(&self) -> [u8; SIGCONTEXT_SIZE] {
            let mut b = [0u8; SIGCONTEXT_SIZE];
            let words = [
                self.r8,
                self.r9,
                self.r10,
                self.r11,
                self.r12,
                self.r13,
                self.r14,
                self.r15,
                self.rdi,
                self.rsi,
                self.rbp,
                self.rbx,
                self.rdx,
                self.rax,
                self.rcx,
                self.rsp,
                self.rip,
                self.eflags,
            ];
            for (i, w) in words.iter().enumerate() {
                b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
            }
            for (i, h) in [self.cs, self.gs, self.fs, self.ss].iter().enumerate() {
                b[144 + i * 2..146 + i * 2].copy_from_slice(&h.to_le_bytes());
            }
            for (i, w) in [self.err, self.trapno, self.oldmask, self.cr2, self.fpstate]
                .iter()
                .enumerate()
            {
                b[152 + i * 8..160 + i * 8].copy_from_slice(&w.to_le_bytes());
            }
            // reserved1[8] (bytes 192 to 255) stays zero.
            b
        }

        pub fn from_bytes(b: &[u8; SIGCONTEXT_SIZE]) -> Self {
            let w = |at: usize| {
                let mut x = [0u8; 8];
                x.copy_from_slice(&b[at..at + 8]);
                u64::from_le_bytes(x)
            };
            let h = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
            Self {
                r8: w(0),
                r9: w(8),
                r10: w(16),
                r11: w(24),
                r12: w(32),
                r13: w(40),
                r14: w(48),
                r15: w(56),
                rdi: w(64),
                rsi: w(72),
                rbp: w(80),
                rbx: w(88),
                rdx: w(96),
                rax: w(104),
                rcx: w(112),
                rsp: w(120),
                rip: w(128),
                eflags: w(136),
                cs: h(144),
                gs: h(146),
                fs: h(148),
                ss: h(150),
                err: w(152),
                trapno: w(160),
                oldmask: w(168),
                cr2: w(176),
                fpstate: w(184),
            }
        }
    }

    /// Where a frame goes (`get_sigframe` and `fpu__alloc_mathframe`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Placement {
        /// The frame's start: the handler's RSP. 16n - 8, as at a function
        /// entry after `call` (`round_down(sp, 16) - 8`).
        pub frame: u64,
        /// The FPU area: 64-byte aligned, above the frame.
        pub fpstate: u64,
    }

    /// Places a frame below `sp` (the interrupted RSP): 128 bytes of red
    /// zone are skipped; with `SA_ONSTACK` and the thread not already on
    /// its alternate stack (`sas_ss_flags(sp) == 0`) the frame goes at the
    /// top of that stack instead; then the FPU area of `math_size` bytes,
    /// rounded down to 64; then the frame. None when the frame would leave
    /// the alternate stack it is on or entering, or wrap the address space
    /// (Linux returns a bogus address there and the delivery fails with
    /// SIGSEGV).
    ///
    /// `ss_flags` is `sas_ss_flags(sp)` and `within` tells whether an
    /// address lies on the alternate stack (`__on_sig_stack`).
    pub fn place(
        sp: u64,
        onstack: bool,
        altstack: AltStack,
        ss_flags: u32,
        nested: bool,
        within: impl Fn(u64) -> bool,
        math_size: u64,
    ) -> Option<Placement> {
        let mut top = sp.checked_sub(RED_ZONE)?;
        let mut entering = false;
        if onstack && ss_flags == 0 {
            top = altstack.sp.checked_add(altstack.size)?;
            entering = true;
        }
        let fpstate = top.checked_sub(math_size)? & !63;
        let frame = (fpstate.checked_sub(SIZE as u64)? & !15).checked_sub(8)?;
        if (nested || entering) && !within(frame) {
            return None;
        }
        Some(Placement { frame, fpstate })
    }

    /// The frame's bytes, from `pretcode` to the end of `info`.
    pub fn build(
        restorer: u64,
        uc_flags: u64,
        stack: AltStack,
        context: &SigContext,
        mask: u64,
        info: Option<SigInfo>,
    ) -> [u8; SIZE] {
        let mut b = [0u8; SIZE];
        b[PRETCODE..PRETCODE + 8].copy_from_slice(&restorer.to_le_bytes());
        b[UC_FLAGS..UC_FLAGS + 8].copy_from_slice(&uc_flags.to_le_bytes());
        // uc_link is 0.
        b[UC_STACK..UC_STACK + 24].copy_from_slice(&stack.to_bytes());
        b[MCONTEXT..MCONTEXT + SIGCONTEXT_SIZE].copy_from_slice(&context.to_bytes());
        b[UC_SIGMASK..UC_SIGMASK + 8].copy_from_slice(&mask.to_le_bytes());
        if let Some(info) = info {
            b[INFO..INFO + SIGINFO_SIZE].copy_from_slice(&info.to_bytes());
        }
        b
    }

    /// The software words and magic Linux adds to the saved FPU area
    /// (`save_sw_bytes`, `save_xstate_epilog`): `area` is the save area
    /// with room for 4 more bytes when `xfeatures` is nonzero (XSAVE).
    /// Also sets the x87 and SSE bits in XSTATE_BV, as Linux does for
    /// programs that edit the legacy area alone.
    pub fn finish_fpu_area(area: &mut [u8], xfeatures: u64) {
        if xfeatures == 0 {
            // FXSAVE only: Linux writes the software words too, but a
            // reader checks magic1 only for an XSAVE frame (uc_flags says
            // which); zeroes say "no extended state".
            return;
        }
        let user_size = area.len() - FP_XSTATE_MAGIC2_SIZE;
        let at = FPX_SW_BYTES;
        area[at..at + 4].copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
        area[at + 4..at + 8]
            .copy_from_slice(&((user_size + FP_XSTATE_MAGIC2_SIZE) as u32).to_le_bytes());
        area[at + 8..at + 16].copy_from_slice(&xfeatures.to_le_bytes());
        area[at + 16..at + 20].copy_from_slice(&(user_size as u32).to_le_bytes());
        area[at + 20..at + 48].fill(0);
        area[user_size..].copy_from_slice(&FP_XSTATE_MAGIC2.to_le_bytes());
        let bv = u64::from_le_bytes(area[512..520].try_into().unwrap_or([0; 8]));
        area[512..520].copy_from_slice(&(bv | XFEATURE_MASK_FPSSE).to_le_bytes());
    }

    /// The FPU area rt_sigreturn loads, from `user` (what the program left
    /// at `fpstate`: `size` bytes, plus the magic word when XSAVE is in
    /// use), following `check_xstate_in_sigframe` and `__fpu_restore_sig`:
    /// without both magics, or with sizes that do not match Keel's area
    /// exactly, only the legacy 512 bytes are taken and every extended
    /// component is put in its initial state (XSTATE_BV = x87 | SSE).
    /// Components the program left out of `xfeatures` are put in their
    /// initial state too. Validity against the CPU (MXCSR, the header) is
    /// checked by the caller before the area is loaded.
    pub fn fpu_area_for_restore(user: &[u8], size: usize, xsave: bool) -> alloc::vec::Vec<u8> {
        let mut area = alloc::vec![0u8; size];
        let legacy = user.len().min(512).min(size);
        area[..legacy].copy_from_slice(&user[..legacy]);
        if !xsave || user.len() < MIN_XSTATE_SIZE {
            return area;
        }
        let word32 = |at: usize| u32::from_le_bytes(user[at..at + 4].try_into().unwrap_or([0; 4]));
        let at = FPX_SW_BYTES;
        let magic1 = word32(at);
        let extended_size = word32(at + 4) as usize;
        let xfeatures = u64::from_le_bytes(user[at + 8..at + 16].try_into().unwrap_or([0; 8]));
        let xstate_size = word32(at + 16) as usize;
        let full = magic1 == FP_XSTATE_MAGIC1
            && xstate_size == size
            && xstate_size <= extended_size
            && user.len() >= size + FP_XSTATE_MAGIC2_SIZE
            && word32(size) == FP_XSTATE_MAGIC2;
        if full {
            area.copy_from_slice(&user[..size]);
            let bv = u64::from_le_bytes(area[512..520].try_into().unwrap_or([0; 8]));
            area[512..520].copy_from_slice(&(bv & (xfeatures | XFEATURE_MASK_FPSSE)).to_le_bytes());
        } else {
            area[512..520].copy_from_slice(&XFEATURE_MASK_FPSSE.to_le_bytes());
        }
        area
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigaction_round_trip_and_flag_masking() {
        let mut s = SignalState::new();
        let action = SigAction {
            handler: 0x40_1000,
            flags: SA_SIGINFO | SA_ONSTACK | SA_RESTORER | 0x400, // + SA_UNSUPPORTED
            restorer: 0x40_2000,
            mask: u64::MAX,
        };
        assert_eq!(s.sigaction(SIGSEGV, Some(action)), Ok(SigAction::default()));
        let back = s.sigaction(SIGSEGV, None).unwrap();
        assert_eq!(back.flags, SA_SIGINFO | SA_ONSTACK | SA_RESTORER);
        assert_eq!(back.mask, !UNBLOCKABLE);
        assert_eq!(back.handler, 0x40_1000);
        assert_eq!(SigAction::from_bytes(&back.to_bytes()), back);
    }

    #[test]
    fn sigaction_rejects_bad_signals() {
        let mut s = SignalState::new();
        let ignore = SigAction {
            handler: SIG_IGN,
            ..SigAction::default()
        };
        for sig in [0, -1, 65, i32::MIN] {
            assert_eq!(s.sigaction(sig, None), Err(Errno::EINVAL));
        }
        assert_eq!(s.sigaction(SIGKILL, Some(ignore)), Err(Errno::EINVAL));
        assert_eq!(s.sigaction(SIGSTOP, Some(ignore)), Err(Errno::EINVAL));
        assert_eq!(s.sigaction(SIGKILL, None), Ok(SigAction::default()));
        assert_eq!(s.sigaction(64, Some(ignore)), Ok(SigAction::default()));
        assert_eq!(s.sigaction(SIGPIPE, Some(ignore)), Ok(SigAction::default()));
        assert_eq!(s.action(SIGPIPE).unwrap().handler, SIG_IGN);
    }

    #[test]
    fn sigprocmask_rules() {
        let mut s = ThreadSignals::new();
        assert_eq!(s.sigprocmask(SIG_BLOCK, Some(u64::MAX)), Ok(0));
        assert_eq!(s.blocked(), !UNBLOCKABLE, "SIGKILL/SIGSTOP never blocked");
        assert_eq!(
            s.sigprocmask(SIG_UNBLOCK, Some(bit(SIGPIPE))),
            Ok(!UNBLOCKABLE)
        );
        assert_eq!(s.blocked() & bit(SIGPIPE), 0);
        assert_eq!(
            s.sigprocmask(SIG_SETMASK, Some(bit(SIGSEGV))).map(|_| ()),
            Ok(())
        );
        assert_eq!(s.blocked(), bit(SIGSEGV));
        assert_eq!(s.sigprocmask(7, Some(0)), Err(Errno::EINVAL));
        assert_eq!(s.blocked(), bit(SIGSEGV), "a failed call changes nothing");
        assert_eq!(
            s.sigprocmask(7, None),
            Ok(bit(SIGSEGV)),
            "how unchecked without a set"
        );
    }

    #[test]
    fn sigaltstack_rules() {
        let mut s = ThreadSignals::new();
        let initial = s.sigaltstack(None, 0x7000).unwrap();
        assert_eq!(
            (initial.sp, initial.size, initial.flags),
            (0, 0, SS_DISABLE)
        );
        // Unchanged request: success even though the size is 0.
        assert!(s.sigaltstack(Some(initial), 0x7000).is_ok());
        let small = AltStack {
            sp: 0x1000,
            flags: 0,
            size: MINSIGSTKSZ - 1,
        };
        assert_eq!(s.sigaltstack(Some(small), 0x7000), Err(Errno::ENOMEM));
        let bad = AltStack { flags: 4, ..small };
        assert_eq!(s.sigaltstack(Some(bad), 0x7000), Err(Errno::EINVAL));
        let good = AltStack {
            sp: 0x1_0000,
            flags: 0,
            size: 0x4000,
        };
        assert!(s.sigaltstack(Some(good), 0x7000).is_ok());
        let now = s.sigaltstack(None, 0x7000).unwrap();
        assert_eq!(now, good);
        // On the alternate stack: reported, and changes refused.
        let on = s.sigaltstack(None, 0x1_4000).unwrap();
        assert_eq!(on.flags, SS_ONSTACK);
        assert_eq!(
            s.sigaltstack(None, 0x1_0000).unwrap().flags,
            0,
            "bottom is exclusive"
        );
        assert_eq!(s.sigaltstack(Some(small), 0x1_2000), Err(Errno::EPERM));
        // Disable: size and pointer cleared.
        let disable = AltStack {
            sp: 0x5555,
            flags: SS_DISABLE,
            size: 99,
        };
        assert!(s.sigaltstack(Some(disable), 0x7000).is_ok());
        let off = s.sigaltstack(None, 0x7000).unwrap();
        assert_eq!((off.sp, off.size, off.flags), (0, 0, SS_DISABLE));
        let bytes = good.to_bytes();
        assert_eq!(&bytes[12..16], &[0; 4]);
        assert_eq!(AltStack::from_bytes(&bytes), good);
    }

    #[test]
    fn autodisarm_is_never_on_stack() {
        let mut s = ThreadSignals::new();
        let stack = AltStack {
            sp: 0x1_0000,
            flags: SS_AUTODISARM,
            size: 0x4000,
        };
        assert!(s.sigaltstack(Some(stack), 0x7000).is_ok());
        let seen = s.sigaltstack(None, 0x1_2000).unwrap();
        assert_eq!(seen.flags, SS_AUTODISARM);
        assert!(
            s.sigaltstack(
                Some(AltStack {
                    size: 0x8000,
                    ..stack
                }),
                0x1_2000
            )
            .is_ok()
        );
    }

    #[test]
    fn exec_resets_caught_signals_and_the_alternate_stack_but_keeps_the_mask() {
        let mut state = SignalState::new();
        let caught = SigAction {
            handler: 0x40_1000,
            flags: 0x0400_0000, // SA_RESTORER
            restorer: 0x40_2000,
            mask: 0b110,
        };
        state.sigaction(10, Some(caught)).unwrap();
        state
            .sigaction(
                13,
                Some(SigAction {
                    handler: SIG_IGN,
                    flags: 0x0400_0000,
                    restorer: 0x40_2000,
                    mask: 1,
                }),
            )
            .unwrap();
        let mut thread = ThreadSignals::new();
        thread.sigprocmask(SIG_SETMASK, Some(1 << 9)).unwrap();
        thread
            .sigaltstack(
                Some(AltStack {
                    sp: 0x7000_0000,
                    flags: 0,
                    size: 0x4000,
                }),
                0x7fff_0000,
            )
            .unwrap();
        state.reset_for_exec();
        thread.reset_for_exec();
        let blank = |handler| SigAction {
            handler,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        assert_eq!(state.action(10), Some(blank(SIG_DFL)));
        assert_eq!(
            state.action(13),
            Some(blank(SIG_IGN)),
            "ignored stays ignored"
        );
        assert_eq!(thread.blocked(), 1 << 9, "the mask survives");
        let old = thread.sigaltstack(None, 0x7fff_0000).unwrap();
        assert_eq!(old.flags, SS_DISABLE);
    }
    #[test]
    fn frame_offsets_match_linux() {
        use frame::*;
        // arch/x86/include/asm/sigframe.h: pretcode, then uc (304 bytes),
        // then info (128); uapi ucontext.h and sigcontext.h for the rest.
        assert_eq!(
            (UC, MCONTEXT, UC_SIGMASK, INFO, SIZE),
            (8, 48, 304, 312, 440)
        );
        let context = SigContext {
            rip: 0x1111,
            eflags: 0x2222,
            cs: 0x33,
            ss: 0x2b,
            err: 4,
            trapno: 14,
            oldmask: 0x55,
            cr2: 0x6666,
            fpstate: 0x7777,
            r8: 1,
            rcx: 2,
            ..SigContext::default()
        };
        let b = context.to_bytes();
        let word = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        assert_eq!(
            (word(0), word(112), word(128), word(136)),
            (1, 2, 0x1111, 0x2222)
        );
        assert_eq!((b[144], b[150]), (0x33, 0x2b));
        assert_eq!(
            (word(152), word(160), word(168), word(176), word(184)),
            (4, 14, 0x55, 0x6666, 0x7777)
        );
        assert_eq!(SigContext::from_bytes(&b), context);
        let info = SigInfo::fault(SIGSEGV, SEGV_MAPERR, 0xdead_0000).to_bytes();
        assert_eq!(&info[0..4], &11i32.to_le_bytes());
        assert_eq!(&info[8..12], &1i32.to_le_bytes());
        assert_eq!(&info[16..24], &0xdead_0000u64.to_le_bytes());
        let sent = SigInfo::from_process(SIGUSR1, SI_TKILL, 7, 0).to_bytes();
        assert_eq!(
            (&sent[8..12], &sent[16..20]),
            (&(-6i32).to_le_bytes()[..], &7u32.to_le_bytes()[..])
        );
    }

    #[test]
    fn frames_are_placed_as_get_sigframe_places_them() {
        let none = ThreadSignals::new();
        let math = 576 + 4;
        let p = frame::place(
            0x8000,
            false,
            none.altstack(),
            none.sas_ss_flags(0x8000),
            false,
            |_| false,
            math,
        )
        .unwrap();
        // 0x8000 - 128 = 0x7f80; - 580 rounded down to 64 = 0x7d00;
        // - 440 rounded down to 16, - 8 = 0x7b38.
        assert_eq!((p.fpstate, p.frame), (0x7d00, 0x7b38));
        assert_eq!(p.frame % 16, 8, "as after a call");
        let mut t = ThreadSignals::new();
        t.sigaltstack(
            Some(AltStack {
                sp: 0x10_0000,
                flags: 0,
                size: 0x2000,
            }),
            0x8000,
        )
        .unwrap();
        let p = frame::place(
            0x8000,
            true,
            t.altstack(),
            t.sas_ss_flags(0x8000),
            false,
            |a| t.within_altstack(a),
            math,
        )
        .unwrap();
        assert_eq!(
            p.fpstate,
            0x10_2000 - 640,
            "at the top of the alternate stack"
        );
        assert!(t.within_altstack(p.frame));
        // Without SA_ONSTACK the normal stack is used.
        let p = frame::place(
            0x8000,
            false,
            t.altstack(),
            t.sas_ss_flags(0x8000),
            false,
            |a| t.within_altstack(a),
            math,
        )
        .unwrap();
        assert_eq!(p.frame, 0x7b38);
        // Already on the alternate stack: nested, below the current SP.
        let sp = 0x10_1800;
        let p = frame::place(
            sp,
            true,
            t.altstack(),
            t.sas_ss_flags(sp),
            t.on_altstack(sp),
            |a| t.within_altstack(a),
            math,
        )
        .unwrap();
        assert!(p.frame < sp - 128);
        // Nested too deep: the frame would leave the stack.
        let sp = 0x10_0400;
        assert_eq!(
            frame::place(
                sp,
                true,
                t.altstack(),
                t.sas_ss_flags(sp),
                t.on_altstack(sp),
                |a| t.within_altstack(a),
                math
            ),
            None
        );
        // A stack pointer near 0 does not wrap.
        assert_eq!(
            frame::place(
                0x100,
                false,
                none.altstack(),
                SS_DISABLE,
                false,
                |_| false,
                math
            ),
            None
        );
    }

    #[test]
    fn delivery_order_and_queueing() {
        assert_eq!(next_signal(0), None);
        assert_eq!(
            next_signal(sigmask(SIGTERM) | sigmask(SIGUSR1)),
            Some(SIGUSR1)
        );
        assert_eq!(
            next_signal(sigmask(SIGHUP) | sigmask(SIGSEGV)),
            Some(SIGSEGV),
            "synchronous signals first"
        );
        let mut p = Pending::new();
        assert!(p.post(SigInfo::from_process(SIGUSR1, SI_USER, 3, 0)));
        assert!(
            !p.post(SigInfo::from_process(SIGUSR1, SI_USER, 4, 0)),
            "not queued twice"
        );
        assert_eq!(p.take(SIGUSR1).unwrap().fields[0], 3, "the first sender's");
        assert_eq!(p.take(SIGUSR1), None);
        assert!(!p.post(SigInfo::kernel(0)) && !p.post(SigInfo::kernel(65)));
        assert_eq!(default_action(SIGCHLD), DefaultAction::Ignore);
        assert_eq!(default_action(SIGSEGV), DefaultAction::Terminate);
        assert_eq!(default_action(SIGTSTP), DefaultAction::Stop);
        assert_eq!(default_action(40), DefaultAction::Terminate);
    }

    #[test]
    fn fpu_areas_round_trip_and_fall_back_to_legacy() {
        use frame::*;
        let size = 832;
        let mut area = alloc::vec![0xabu8; size + 4];
        area[512..520].copy_from_slice(&0u64.to_le_bytes());
        area[520..576].fill(0);
        finish_fpu_area(&mut area, 0b111);
        assert_eq!(&area[464..468], &FP_XSTATE_MAGIC1.to_le_bytes());
        assert_eq!(&area[size..], &FP_XSTATE_MAGIC2.to_le_bytes());
        assert_eq!(area[512], 3, "x87 and SSE marked present");
        let back = fpu_area_for_restore(&area, size, true);
        assert_eq!(
            &back[..],
            &area[..size],
            "a frame Keel wrote is taken whole"
        );
        // A program that copied only the legacy part (no second magic).
        let mut legacy = area.clone();
        legacy[size..].fill(0);
        let back = fpu_area_for_restore(&legacy, size, true);
        assert_eq!(&back[..512], &area[..512]);
        assert_eq!(
            back[512..520],
            3u64.to_le_bytes(),
            "extended state to its initial values"
        );
        assert!(back[520..].iter().all(|&b| b == 0));
        // xfeatures without AVX: AVX goes to its initial state.
        let mut no_avx = area.clone();
        no_avx[464 + 8..464 + 16].copy_from_slice(&3u64.to_le_bytes());
        no_avx[512] = 0b111;
        assert_eq!(fpu_area_for_restore(&no_avx, size, true)[512], 3);
        // FXSAVE only: just the 512 bytes.
        assert_eq!(
            fpu_area_for_restore(&area, 512, false),
            area[..512].to_vec()
        );
    }

    #[test]
    fn a_child_thread_keeps_the_mask_and_maybe_the_altstack() {
        let mut t = ThreadSignals::new();
        t.sigprocmask(SIG_SETMASK, Some(sigmask(SIGUSR1))).unwrap();
        t.sigaltstack(
            Some(AltStack {
                sp: 0x10_0000,
                flags: 0,
                size: 0x2000,
            }),
            0x8000,
        )
        .unwrap();
        t.pending.post(SigInfo::kernel(SIGUSR2));
        let thread = t.for_child(true);
        let process = t.for_child(false);
        assert_eq!(
            (thread.blocked(), process.blocked()),
            (sigmask(SIGUSR1), sigmask(SIGUSR1))
        );
        assert_eq!(
            thread.altstack().size,
            0,
            "CLONE_VM without CLONE_VFORK clears it"
        );
        assert_eq!(process.altstack().size, 0x2000);
        assert_eq!((thread.pending.set(), process.pending.set()), (0, 0));
    }
}
