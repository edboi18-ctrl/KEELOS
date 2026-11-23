//! POSIX record locks (fcntl F_SETLK, F_SETLKW, F_GETLK; P3-T8, ADR 0023),
//! after Linux v6.12 `fs/locks.c`. Pure data, tested on the host; the
//! kernel keeps one table and decides who an owner is (a process, as
//! Linux's `current->files`).
//!
//! A lock covers `start..=end` of one file (`end` is `OFFSET_MAX` for "to
//! the end and beyond"), shared (read) or exclusive (write). Locks of one
//! owner never conflict with each other; a new lock replaces the owner's
//! own locks where they overlap, splitting them, and merges with the
//! owner's adjacent or overlapping locks of the same type
//! (`posix_lock_inode`). Another owner's lock conflicts if the ranges
//! overlap and either is exclusive (`posix_locks_conflict`).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::errno::Errno;

/// The largest offset (`OFFSET_MAX`, `include/linux/fs.h`: `LLONG_MAX`).
pub const OFFSET_MAX: i64 = i64::MAX;

/// One lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lock {
    pub owner: u64,
    pub start: i64,
    /// Inclusive.
    pub end: i64,
    pub exclusive: bool,
    /// For F_GETLK's `l_pid`: the owner's PID, and the compartment it is
    /// numbered in.
    pub pid: u32,
    pub compartment: u32,
}

impl Lock {
    fn overlaps(&self, start: i64, end: i64) -> bool {
        self.start <= end && start <= self.end
    }
}

/// Who takes a lock: the owner, and the PID and compartment F_GETLK
/// reports for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub id: u64,
    pub pid: u32,
    pub compartment: u32,
}

/// What F_SETLK asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Shared,
    Exclusive,
    Unlock,
}

/// Every file's locks, by file (an inode number).
#[derive(Debug, Default)]
pub struct Locks {
    files: BTreeMap<u64, Vec<Lock>>,
}

impl Locks {
    pub const fn new() -> Self {
        Locks {
            files: BTreeMap::new(),
        }
    }

    /// The first lock (lowest start) of another owner that conflicts with
    /// `owner` taking `start..=end` (exclusively or not): what F_GETLK
    /// reports, and why F_SETLK fails.
    pub fn conflict(
        &self,
        file: u64,
        owner: u64,
        start: i64,
        end: i64,
        exclusive: bool,
    ) -> Option<Lock> {
        self.files
            .get(&file)?
            .iter()
            .filter(|l| l.owner != owner && l.overlaps(start, end) && (exclusive || l.exclusive))
            .min_by_key(|l| l.start)
            .copied()
    }

    /// F_SETLK: takes, changes or drops `owner`'s lock on `start..=end`.
    /// EAGAIN if another owner's lock conflicts (nothing changes then). An
    /// unlock always succeeds.
    pub fn set(
        &mut self,
        file: u64,
        who: Owner,
        start: i64,
        end: i64,
        request: Request,
    ) -> Result<(), Errno> {
        let Owner {
            id: owner,
            pid,
            compartment,
        } = who;
        let exclusive = match request {
            Request::Exclusive => Some(true),
            Request::Shared => Some(false),
            Request::Unlock => None,
        };
        if let Some(exclusive) = exclusive
            && self.conflict(file, owner, start, end, exclusive).is_some()
        {
            return Err(Errno::EAGAIN);
        }
        let locks = self.files.entry(file).or_default();
        // Cut the owner's locks out of the range, keeping what lies on
        // either side.
        let mut kept = Vec::with_capacity(locks.len() + 1);
        for l in locks.drain(..) {
            if l.owner != owner || !l.overlaps(start, end) {
                kept.push(l);
                continue;
            }
            if l.start < start {
                kept.push(Lock {
                    end: start - 1,
                    ..l
                });
            }
            if l.end > end {
                kept.push(Lock {
                    start: end + 1,
                    ..l
                });
            }
        }
        if let Some(exclusive) = exclusive {
            // Merge with the owner's locks of the same type that touch it.
            let (mut s, mut e) = (start, end);
            kept.retain(|l| {
                let touches = l.owner == owner
                    && l.exclusive == exclusive
                    && l.start <= e.saturating_add(1)
                    && s <= l.end.saturating_add(1);
                if touches {
                    s = s.min(l.start);
                    e = e.max(l.end);
                }
                !touches
            });
            kept.push(Lock {
                owner,
                start: s,
                end: e,
                exclusive,
                pid,
                compartment,
            });
        }
        kept.sort_by_key(|l| (l.start, l.owner));
        if kept.is_empty() {
            self.files.remove(&file);
        } else {
            *locks = kept;
        }
        Ok(())
    }

    /// Drops every lock `owner` holds on `file` (a close of any of its
    /// descriptors for the file: `locks_remove_posix`). Returns whether it
    /// held any, so the caller knows to wake waiters.
    pub fn release(&mut self, file: u64, owner: u64) -> bool {
        let Some(locks) = self.files.get_mut(&file) else {
            return false;
        };
        let before = locks.len();
        locks.retain(|l| l.owner != owner);
        let released = locks.len() != before;
        if locks.is_empty() {
            self.files.remove(&file);
        }
        released
    }

    /// Drops every lock `owner` holds (it has exited).
    pub fn release_owner(&mut self, owner: u64) -> bool {
        let mut released = false;
        self.files.retain(|_, locks| {
            let before = locks.len();
            locks.retain(|l| l.owner != owner);
            released |= locks.len() != before;
            !locks.is_empty()
        });
        released
    }

    /// The locks on `file`, in order (tests).
    pub fn of(&self, file: u64) -> Vec<Lock> {
        self.files.get(&file).cloned().unwrap_or_default()
    }

    /// Number of files with locks (tests).
    pub fn files(&self) -> usize {
        self.files.len()
    }
}

/// `flock64_to_posix_lock`: the range a `struct flock` names, from the
/// position `l_whence` picks (`base`: 0, the file position or the file
/// size), as `start..=end`. EINVAL for a start below 0 or a negative
/// length reaching below 0; EOVERFLOW past OFFSET_MAX. A length of 0
/// means to OFFSET_MAX; a negative one covers the bytes before the start.
pub fn range(base: i64, l_start: i64, l_len: i64) -> Result<(i64, i64), Errno> {
    if l_start > OFFSET_MAX - base {
        return Err(Errno::EOVERFLOW);
    }
    let start = base + l_start;
    if start < 0 {
        return Err(Errno::EINVAL);
    }
    if l_len > 0 {
        if l_len - 1 > OFFSET_MAX - start {
            return Err(Errno::EOVERFLOW);
        }
        Ok((start, start + (l_len - 1)))
    } else if l_len < 0 {
        if start + l_len < 0 {
            return Err(Errno::EINVAL);
        }
        Ok((start + l_len, start - 1))
    } else {
        Ok((start, OFFSET_MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(l: &mut Locks, owner: u64, start: i64, end: i64, r: Request) -> Result<(), Errno> {
        let who = Owner {
            id: owner,
            pid: owner as u32,
            compartment: 0,
        };
        l.set(1, who, start, end, r)
    }

    fn spans(l: &Locks) -> Vec<(u64, i64, i64, bool)> {
        l.of(1)
            .iter()
            .map(|k| (k.owner, k.start, k.end, k.exclusive))
            .collect()
    }

    #[test]
    fn conflicts_are_between_owners_and_need_an_exclusive_lock() {
        let mut l = Locks::new();
        set(&mut l, 1, 0, 9, Request::Shared).unwrap();
        set(&mut l, 2, 5, 14, Request::Shared).unwrap();
        assert_eq!(set(&mut l, 3, 9, 9, Request::Exclusive), Err(Errno::EAGAIN));
        assert_eq!(set(&mut l, 3, 15, 20, Request::Exclusive), Ok(()));
        assert_eq!(
            l.conflict(1, 4, 0, OFFSET_MAX, true).map(|k| k.owner),
            Some(1),
            "lowest start"
        );
        assert_eq!(l.conflict(1, 4, 0, 4, false), None, "shared with shared");
        // The owner's own locks never conflict: it upgrades in place.
        set(&mut l, 1, 0, 3, Request::Exclusive).unwrap();
        assert_eq!(
            spans(&l),
            [
                (1, 0, 3, true),
                (1, 4, 9, false),
                (2, 5, 14, false),
                (3, 15, 20, true)
            ]
        );
        assert_eq!(
            set(&mut l, 2, 4, 4, Request::Exclusive),
            Err(Errno::EAGAIN),
            "1 shares 4"
        );
    }

    #[test]
    fn unlocking_splits_and_locking_merges() {
        let mut l = Locks::new();
        set(&mut l, 1, 0, 99, Request::Exclusive).unwrap();
        set(&mut l, 1, 40, 59, Request::Unlock).unwrap();
        assert_eq!(spans(&l), [(1, 0, 39, true), (1, 60, 99, true)]);
        set(&mut l, 1, 40, 59, Request::Exclusive).unwrap();
        assert_eq!(
            spans(&l),
            [(1, 0, 99, true)],
            "adjacent same-type locks merge"
        );
        set(&mut l, 1, 100, 109, Request::Shared).unwrap();
        assert_eq!(
            spans(&l),
            [(1, 0, 99, true), (1, 100, 109, false)],
            "types do not merge"
        );
        set(&mut l, 1, 0, OFFSET_MAX, Request::Unlock).unwrap();
        assert_eq!(l.files(), 0, "an empty file is forgotten");
    }

    #[test]
    fn release_drops_an_owners_locks() {
        let mut l = Locks::new();
        set(&mut l, 1, 0, 9, Request::Exclusive).unwrap();
        let who = Owner {
            id: 1,
            pid: 1,
            compartment: 0,
        };
        l.set(2, who, 0, 9, Request::Exclusive).unwrap();
        set(&mut l, 2, 10, 19, Request::Exclusive).unwrap();
        assert!(l.release(1, 1));
        assert!(!l.release(1, 1));
        assert_eq!(spans(&l), [(2, 10, 19, true)]);
        assert!(l.release_owner(1));
        assert_eq!(l.files(), 1);
    }

    #[test]
    fn ranges_follow_flock64_to_posix_lock() {
        assert_eq!(range(0, 10, 5), Ok((10, 14)));
        assert_eq!(range(100, -10, 0), Ok((90, OFFSET_MAX)));
        assert_eq!(range(0, 10, -4), Ok((6, 9)));
        assert_eq!(range(0, 3, -4), Err(Errno::EINVAL));
        assert_eq!(range(0, -1, 1), Err(Errno::EINVAL));
        assert_eq!(range(10, OFFSET_MAX, 1), Err(Errno::EOVERFLOW));
        assert_eq!(range(0, OFFSET_MAX, 2), Err(Errno::EOVERFLOW));
        assert_eq!(range(0, OFFSET_MAX, 1), Ok((OFFSET_MAX, OFFSET_MAX)));
    }
}
