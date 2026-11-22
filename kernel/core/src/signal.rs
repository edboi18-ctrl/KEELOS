//! Signal state of a Linux process (Phase 1 subset): the disposition of
//! each signal, the blocked mask and the alternate signal stack, as
//! `rt_sigaction(2)`, `rt_sigprocmask(2)` and `sigaltstack(2)` read and set
//! them.
//!
//! Phase 1 records this state with Linux's validation rules so programs
//! that set it at startup (Rust's standard library, musl) run; nothing is
//! delivered yet. Generation, masking at delivery, signal frames and
//! `rt_sigreturn` are P3-T6. Until then a CPU fault still ends the thread
//! with the status Linux would give for the default action.
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

/// A process's signal state. With one thread per process (until clone(2),
/// P3) the per-thread parts (blocked mask, alternate stack) live here too;
/// they move to the thread when threads arrive. Dispositions are
/// per-process on Linux as well.
#[derive(Clone, Debug)]
pub struct SignalState {
    actions: [SigAction; NSIG],
    blocked: u64,
    /// The thread's `sas_ss_sp`, `sas_ss_size`, `sas_ss_flags`.
    altstack: AltStack,
}

impl Default for SignalState {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalState {
    /// A new process: every action `SIG_DFL`, nothing blocked, no
    /// alternate stack (`sas_ss_reset`: flags `SS_DISABLE`).
    pub const fn new() -> Self {
        Self {
            actions: [SigAction {
                handler: SIG_DFL,
                flags: 0,
                restorer: 0,
                mask: 0,
            }; NSIG],
            blocked: 0,
            altstack: AltStack {
                sp: 0,
                flags: SS_DISABLE,
                size: 0,
            },
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

    pub fn action(&self, sig: i32) -> Option<SigAction> {
        (1..=NSIG as i32)
            .contains(&sig)
            .then(|| self.actions[(sig - 1) as usize])
    }

    /// `on_sig_stack`: the stack grows down, so `sp` is on the alternate
    /// stack when it lies in `(ss_sp, ss_sp + ss_size]`. Never with
    /// `SS_AUTODISARM`.
    fn on_altstack(&self, sp: u64) -> bool {
        if self.altstack.flags & SS_AUTODISARM != 0 {
            return false;
        }
        sp > self.altstack.sp && sp - self.altstack.sp <= self.altstack.size
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

#[cfg(test)]
mod tests {
    use super::*;

    const SIGSEGV: i32 = 11;
    const SIGPIPE: i32 = 13;

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
        let mut s = SignalState::new();
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
        let mut s = SignalState::new();
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
        let mut s = SignalState::new();
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
}
