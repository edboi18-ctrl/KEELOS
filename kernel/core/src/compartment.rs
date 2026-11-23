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
use core::sync::atomic::{AtomicU32, Ordering};

use crate::errno::Errno;
use crate::vfs::Ino;

/// PIDs stay below this, as on Linux with `pid_max` at its largest:
/// proc_sys_kernel(5), /proc/sys/kernel/pid_max, "one greater than the
/// maximum PID", which "can be set to any value up to 2^22
/// (PID_MAX_LIMIT)". So a PID always fits `pid_t`.
pub const PID_MAX: u32 = 1 << 22;

/// What a compartment may use. Later limits (memory, tmpfs bytes and
/// nodes, handles) join this as their accounting lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Processes alive at once.
    pub processes: u32,
}

impl Limits {
    /// No limit beyond the kernel's own (the system compartment).
    pub const UNLIMITED: Limits = Limits {
        processes: u32::MAX,
    };
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
        }
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
        Arc::new(Compartment::new(1, ROOT, Limits { processes }))
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
