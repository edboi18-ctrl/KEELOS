//! Compartments (P3-S1, SR-2 to SR-4; ADR 0014): the unit of confinement.
//! Every process belongs to exactly one. A compartment fixes the
//! process's filesystem root, numbers its processes in a PID space of
//! its own, and counts what its processes use against its limits
//! (P3-S4, SR-8).
//!
//! This module holds the object and its accounting, so it is tested on
//! the host. `keel-linux-abi` creates compartments and puts processes in
//! them.
//!
//! PIDs follow Linux PID namespaces, pid_namespaces(7): "The first process
//! created in a new namespace ... has the PID 1", and a process sees only
//! PIDs of its own namespace. A process limit refuses a new process with
//! EAGAIN, as fork(2) does at RLIMIT_NPROC ("EAGAIN ... the RLIMIT_NPROC
//! soft resource limit ... was reached").

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::errno::Errno;
use crate::vfs::Ino;

/// PIDs stay below this, as on Linux with `pid_max` at its largest:
/// proc_sys_kernel(5), /proc/sys/kernel/pid_max, "one greater than the
/// maximum PID", which "can be set to any value up to 2^22
/// (PID_MAX_LIMIT)". So a PID always fits `pid_t`.
pub const PID_MAX: u32 = 1 << 22;

/// What a compartment may use. Later limits (tmpfs bytes and nodes) join
/// this as their accounting lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Processes alive at once.
    pub processes: u32,
    /// 4 KiB frames of user memory: pages its processes have touched and
    /// their user page tables (see [`Budget`]).
    pub memory_frames: usize,
    /// Bytes of tmpfs file data its files hold (see [`Quota`]).
    pub tmpfs_bytes: usize,
    /// tmpfs nodes it has created.
    pub tmpfs_nodes: usize,
    /// Descriptors each of its processes may hold (EMFILE beyond, as at
    /// RLIMIT_NOFILE; ADR 0042). The kernel's own table size, 1024, caps
    /// it.
    pub handles: usize,
    /// Its system-call and ioctl allowlists (ADR 0041).
    pub profile: &'static crate::profile::Profile,
}

impl Limits {
    /// No limit beyond the kernel's own (the system compartment).
    pub const UNLIMITED: Limits = Limits {
        processes: u32::MAX,
        memory_frames: usize::MAX,
        tmpfs_bytes: usize::MAX,
        tmpfs_nodes: usize::MAX,
        handles: usize::MAX,
        profile: &crate::profile::FULL,
    };

    /// Whether every limit is at or below `ceiling`'s (a factory's, ADR
    /// 0040).
    pub fn fits_within(&self, ceiling: &Limits) -> bool {
        self.processes <= ceiling.processes
            && self.memory_frames <= ceiling.memory_frames
            && self.tmpfs_bytes <= ceiling.tmpfs_bytes
            && self.tmpfs_nodes <= ceiling.tmpfs_nodes
            && self.handles <= ceiling.handles
            && self.profile.within(ceiling.profile)
    }
}

/// A count with a ceiling, shared by everything charged to it. Charging
/// succeeds only if it keeps the count at or below the limit, and is
/// checked and done in one atomic step, so concurrent charges cannot pass
/// the limit together.
#[derive(Debug)]
pub struct Budget {
    used: AtomicUsize,
    limit: usize,
}

impl Budget {
    pub fn new(limit: usize) -> Budget {
        Budget {
            used: AtomicUsize::new(0),
            limit,
        }
    }

    /// Adds `n` if that keeps the count within the limit.
    #[must_use]
    pub fn try_charge(&self, n: usize) -> bool {
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(n).filter(|&total| total <= self.limit)
            })
            .is_ok()
    }

    /// Gives back `n` charged earlier. Never goes below zero: a mismatch is
    /// a kernel bug, and saturating keeps it from turning into a huge
    /// allowance.
    pub fn uncharge(&self, n: usize) {
        let _ = self
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used.saturating_sub(n))
            });
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

/// A compartment's share of the tmpfs (P3-S4): the file data its files
/// hold and the nodes it has created. `vfs::Fs` charges it: a file's bytes
/// go to the file's owner, the compartment that created it, or, for a
/// file the kernel created, the first compartment that grows it.
#[derive(Debug)]
pub struct Quota {
    pub bytes: Budget,
    pub nodes: Budget,
}

/// A compartment.
#[derive(Debug)]
pub struct Compartment {
    id: u32,
    root: Ino,
    limits: Limits,
    /// Processes alive now; never above `limits.processes`.
    processes: AtomicU32,
    /// The next PID to hand out. PIDs are not reused yet, so a compartment
    /// can start at most `PID_MAX - 1` processes in its lifetime (PIDs
    /// 1 to `PID_MAX - 1`).
    next_pid: AtomicU32,
    /// User memory of all its processes, in frames.
    memory: Arc<Budget>,
    /// None when both tmpfs limits are unlimited (the system compartment):
    /// its files are bounded only by the filesystem's own caps.
    tmpfs: Option<Arc<Quota>>,
    /// The wait status of its PID 1 once that has ended, else -1 (ADR
    /// 0040: what `compartment_wait` reports to the launcher).
    lead_status: AtomicI64,
    /// Calls and operations its profile has refused (ADR 0041).
    denied: AtomicU64,
    /// The rate limit on its denial records in the audit log (ADR 0045).
    audit_limit: crate::audit::Limiter,
}

impl Compartment {
    /// A compartment whose processes see `root` as `/`.
    pub fn new(id: u32, root: Ino, limits: Limits) -> Compartment {
        Compartment {
            id,
            root,
            limits,
            processes: AtomicU32::new(0),
            next_pid: AtomicU32::new(1),
            memory: Arc::new(Budget::new(limits.memory_frames)),
            tmpfs: (limits.tmpfs_bytes != usize::MAX || limits.tmpfs_nodes != usize::MAX).then(
                || {
                    Arc::new(Quota {
                        bytes: Budget::new(limits.tmpfs_bytes),
                        nodes: Budget::new(limits.tmpfs_nodes),
                    })
                },
            ),
            lead_status: AtomicI64::new(-1),
            denied: AtomicU64::new(0),
            audit_limit: crate::audit::Limiter::new(),
        }
    }

    /// The rate limit on its denial records in the audit log (ADR 0045).
    pub fn audit_limiter(&self) -> &crate::audit::Limiter {
        &self.audit_limit
    }

    /// Counts a refusal by its profile, and returns how many there have
    /// been before this one.
    pub fn note_denied(&self) -> u64 {
        self.denied.fetch_add(1, Ordering::Relaxed)
    }

    /// How many calls and operations its profile has refused.
    pub fn denied(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }

    /// Records the wait status of its PID 1, which has ended.
    pub fn set_lead_status(&self, status: i32) {
        self.lead_status.store(i64::from(status), Ordering::Release);
    }

    /// The wait status of its PID 1, if that has ended.
    pub fn lead_status(&self) -> Option<i32> {
        let s = self.lead_status.load(Ordering::Acquire);
        (s >= 0).then_some(s as i32)
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    /// The directory its processes see as `/`; lookups never leave it.
    pub fn root(&self) -> Ino {
        self.root
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Its allowlists (ADR 0041), fixed when it was made.
    pub fn profile(&self) -> &'static crate::profile::Profile {
        self.limits.profile
    }

    /// The user-memory budget its processes' address spaces charge.
    pub fn memory(&self) -> &Arc<Budget> {
        &self.memory
    }

    /// Its tmpfs quota, if it has limits there.
    pub fn tmpfs(&self) -> Option<&Arc<Quota>> {
        self.tmpfs.as_ref()
    }

    /// Processes alive in it now.
    pub fn processes(&self) -> u32 {
        self.processes.load(Ordering::Relaxed)
    }

    /// Admits one more process: counts it against the process limit and
    /// gives it the next PID. EAGAIN at the limit or when the PID space is
    /// used up. The count drops when the returned [`Member`] is dropped.
    pub fn admit(self: &Arc<Self>) -> Result<Member, Errno> {
        // Count first, so two concurrent admissions cannot both pass the
        // limit: the update only succeeds from a value below it.
        self.processes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.limits.processes).then_some(n + 1)
            })
            .map_err(|_| Errno::EAGAIN)?;
        let pid = self
            .next_pid
            .try_update(Ordering::AcqRel, Ordering::Acquire, |p| {
                (p < PID_MAX).then_some(p + 1)
            });
        match pid {
            Ok(pid) => Ok(Member {
                compartment: self.clone(),
                pid,
            }),
            Err(_) => {
                self.processes.fetch_sub(1, Ordering::AcqRel);
                Err(Errno::EAGAIN)
            }
        }
    }
}

/// A process's place in its compartment: the compartment and the PID it
/// has there. Dropping it gives the process slot back.
#[derive(Debug)]
pub struct Member {
    compartment: Arc<Compartment>,
    pid: u32,
}

impl Member {
    pub fn compartment(&self) -> &Arc<Compartment> {
        &self.compartment
    }

    /// The PID inside the compartment (what getpid(2) returns).
    pub fn pid(&self) -> u32 {
        self.pid
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        self.compartment.processes.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::ROOT;

    fn compartment(processes: u32) -> Arc<Compartment> {
        Arc::new(Compartment::new(
            1,
            ROOT,
            Limits {
                processes,
                ..Limits::UNLIMITED
            },
        ))
    }

    #[test]
    fn limits_fit_beneath_a_ceiling_field_by_field() {
        let ceiling = Limits {
            processes: 64,
            memory_frames: 1000,
            tmpfs_bytes: 4096,
            tmpfs_nodes: 10,
            handles: 64,
            profile: &crate::profile::DEFAULT,
        };
        assert!(ceiling.fits_within(&ceiling));
        assert!(ceiling.fits_within(&Limits::UNLIMITED));
        assert!(!Limits::UNLIMITED.fits_within(&ceiling));
        for over in [
            Limits {
                processes: 65,
                ..ceiling
            },
            Limits {
                memory_frames: 1001,
                ..ceiling
            },
            Limits {
                tmpfs_bytes: 4097,
                ..ceiling
            },
            Limits {
                tmpfs_nodes: 11,
                ..ceiling
            },
            Limits {
                handles: 65,
                ..ceiling
            },
            // A profile beyond the ceiling's (ADR 0041).
            Limits {
                profile: &crate::profile::FULL,
                ..ceiling
            },
        ] {
            assert!(!over.fits_within(&ceiling), "{over:?}");
        }
        let c = compartment(2);
        assert_eq!(c.lead_status(), None);
        c.set_lead_status(3 << 8);
        assert_eq!(c.lead_status(), Some(3 << 8));
    }

    #[test]
    fn pids_start_at_one_in_each_compartment() {
        let a = compartment(10);
        let b = compartment(10);
        let a1 = a.admit().unwrap();
        let a2 = a.admit().unwrap();
        let b1 = b.admit().unwrap();
        assert_eq!((a1.pid(), a2.pid(), b1.pid()), (1, 2, 1));
    }

    #[test]
    fn the_process_limit_refuses_with_eagain_and_frees_on_drop() {
        let c = compartment(2);
        let first = c.admit().unwrap();
        let second = c.admit().unwrap();
        assert_eq!(c.admit().unwrap_err(), Errno::EAGAIN);
        assert_eq!(c.processes(), 2);
        drop(first);
        assert_eq!(c.processes(), 1);
        let third = c.admit().unwrap();
        // PIDs are not reused.
        assert_eq!(third.pid(), 3);
        drop((second, third));
        assert_eq!(c.processes(), 0);
    }

    #[test]
    fn an_exhausted_pid_space_refuses_without_leaking_a_slot() {
        let c = compartment(10);
        c.next_pid.store(PID_MAX - 1, Ordering::Relaxed);
        assert_eq!(c.admit().unwrap().pid(), PID_MAX - 1);
        assert_eq!(c.admit().unwrap_err(), Errno::EAGAIN);
        assert_eq!(c.processes(), 0, "the refused admission gave its slot back");
    }

    #[test]
    fn a_budget_charges_up_to_its_limit_exactly() {
        let b = Budget::new(10);
        assert!(b.try_charge(4));
        assert!(b.try_charge(6));
        assert!(!b.try_charge(1), "11 > 10");
        assert_eq!(b.used(), 10, "a refused charge adds nothing");
        b.uncharge(3);
        assert!(b.try_charge(3));
        let huge = Budget::new(usize::MAX);
        assert!(huge.try_charge(usize::MAX));
        assert!(!huge.try_charge(1), "overflow is refused, not wrapped");
        b.uncharge(100);
        assert_eq!(b.used(), 0, "uncharging never goes below zero");
    }

    #[test]
    fn concurrent_charges_never_pass_the_limit() {
        let b = Budget::new(1000);
        let granted: usize = std::thread::scope(|s| {
            let workers: Vec<_> = (0..16)
                .map(|_| s.spawn(|| (0..200).filter(|_| b.try_charge(1)).count()))
                .collect();
            workers.into_iter().map(|w| w.join().unwrap()).sum()
        });
        assert_eq!((granted, b.used()), (1000, 1000));
    }

    #[test]
    fn concurrent_admissions_never_pass_the_limit() {
        let c = compartment(8);
        let admitted: Vec<_> = std::thread::scope(|s| {
            let workers: Vec<_> = (0..32).map(|_| s.spawn(|| c.admit().ok())).collect();
            workers
                .into_iter()
                .filter_map(|w| w.join().unwrap())
                .collect()
        });
        assert_eq!(admitted.len(), 8);
        assert_eq!(c.processes(), 8);
    }
}
