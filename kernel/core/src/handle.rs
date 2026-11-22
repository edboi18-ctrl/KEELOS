//! Per-process handle table with rights (P1-S1, SR-1).
//!
//! Every kernel object a process can reach is a handle in this table, and
//! every handle carries a rights mask. A Linux file descriptor is the
//! handle's index. Each operation states the right it needs and
//! [`HandleTable::get`] checks it; duplicating can only remove rights.
//! There is no plain file-descriptor table anywhere to migrate from.

use alloc::vec::Vec;

use crate::errno::Errno;

/// A set of rights (SR-1's list).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    pub const MAP_EXEC: Rights = Rights(1 << 2);
    pub const SEEK: Rights = Rights(1 << 3);
    pub const STAT: Rights = Rights(1 << 4);
    pub const ENUMERATE: Rights = Rights(1 << 5);
    pub const CREATE: Rights = Rights(1 << 6);
    pub const DELETE: Rights = Rights(1 << 7);
    pub const CONNECT: Rights = Rights(1 << 8);
    pub const ACCEPT: Rights = Rights(1 << 9);
    pub const DUPLICATE: Rights = Rights(1 << 10);
    pub const TRANSFER: Rights = Rights(1 << 11);
    pub const SIGNAL: Rights = Rights(1 << 12);
    pub const WAIT: Rights = Rights(1 << 13);

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    /// Whether every right in `required` is present.
    pub const fn contains(self, required: Rights) -> bool {
        self.0 & required.0 == required.0
    }
}

impl core::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, other: Rights) -> Rights {
        self.union(other)
    }
}

/// One handle: an object and what this process may do with it.
#[derive(Clone, Debug)]
pub struct Handle<T> {
    pub object: T,
    pub rights: Rights,
    /// Close on exec (O_CLOEXEC / FD_CLOEXEC). A property of the handle,
    /// not of the object.
    pub close_on_exec: bool,
}

/// The table. Indices are Linux file descriptors.
#[derive(Debug)]
pub struct HandleTable<T> {
    slots: Vec<Option<Handle<T>>>,
    limit: usize,
}

impl<T: Clone> HandleTable<T> {
    /// An empty table holding at most `limit` handles (EMFILE beyond; the
    /// RLIMIT_NOFILE analogue, per compartment from Phase 3, SR-8).
    pub fn new(limit: usize) -> Self {
        HandleTable {
            slots: Vec::new(),
            limit,
        }
    }

    /// Adds a handle at the lowest free index, as POSIX requires for
    /// open(2), and returns the index.
    pub fn insert(&mut self, handle: Handle<T>) -> Result<i32, Errno> {
        let index = match self.slots.iter().position(Option::is_none) {
            Some(free) => free,
            None if self.slots.len() < self.limit => {
                self.slots.push(None);
                self.slots.len() - 1
            }
            None => return Err(Errno::EMFILE),
        };
        self.slots[index] = Some(handle);
        i32::try_from(index).map_err(|_| Errno::EMFILE)
    }

    fn slot(&self, fd: i32) -> Option<&Handle<T>> {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.slots.get(i))
            .and_then(Option::as_ref)
    }

    /// The object behind `fd`, if the handle has every right in
    /// `required`. A missing handle and a missing right both give EBADF,
    /// which is what Linux returns for, e.g., write(2) on a read-only
    /// descriptor.
    pub fn get(&self, fd: i32, required: Rights) -> Result<&T, Errno> {
        match self.slot(fd) {
            Some(h) if h.rights.contains(required) => Ok(&h.object),
            _ => Err(Errno::EBADF),
        }
    }

    /// The rights of `fd`.
    pub fn rights(&self, fd: i32) -> Result<Rights, Errno> {
        self.slot(fd).map(|h| h.rights).ok_or(Errno::EBADF)
    }

    /// Copies `fd` to the lowest free index, keeping only the rights in
    /// `mask`: rights can be removed, never added. Needs DUPLICATE.
    pub fn duplicate(&mut self, fd: i32, mask: Rights) -> Result<i32, Errno> {
        let handle = self.slot(fd).ok_or(Errno::EBADF)?;
        if !handle.rights.contains(Rights::DUPLICATE) {
            return Err(Errno::EBADF);
        }
        let copy = Handle {
            object: handle.object.clone(),
            rights: handle.rights.intersect(mask),
            close_on_exec: false,
        };
        self.insert(copy)
    }

    /// Removes `fd` and returns its handle.
    pub fn close(&mut self, fd: i32) -> Result<Handle<T>, Errno> {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.slots.get_mut(i))
            .and_then(Option::take)
            .ok_or(Errno::EBADF)
    }

    /// Number of open handles.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(object: u32, rights: Rights) -> Handle<u32> {
        Handle {
            object,
            rights,
            close_on_exec: false,
        }
    }

    #[test]
    fn rights_are_checked() {
        let mut t = HandleTable::new(16);
        let fd = t.insert(h(7, Rights::READ | Rights::STAT)).unwrap();
        assert_eq!(fd, 0);
        assert_eq!(t.get(fd, Rights::READ), Ok(&7));
        assert_eq!(t.get(fd, Rights::READ | Rights::STAT), Ok(&7));
        assert_eq!(t.get(fd, Rights::NONE), Ok(&7));
        assert_eq!(t.get(fd, Rights::WRITE), Err(Errno::EBADF));
        assert_eq!(t.get(fd, Rights::READ | Rights::WRITE), Err(Errno::EBADF));
        for bad in [-1, 1, 1000, i32::MIN, i32::MAX] {
            assert_eq!(t.get(bad, Rights::NONE), Err(Errno::EBADF));
        }
    }

    #[test]
    fn lowest_free_index_and_limit() {
        let mut t = HandleTable::new(3);
        assert_eq!(t.insert(h(0, Rights::READ)), Ok(0));
        assert_eq!(t.insert(h(1, Rights::READ)), Ok(1));
        assert_eq!(t.insert(h(2, Rights::READ)), Ok(2));
        assert_eq!(t.insert(h(3, Rights::READ)), Err(Errno::EMFILE));
        assert_eq!(t.close(1).map(|h| h.object), Ok(1));
        assert_eq!(t.close(1).map(|h| h.object), Err(Errno::EBADF));
        assert_eq!(t.insert(h(4, Rights::READ)), Ok(1));
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn duplicate_only_removes_rights() {
        let mut t = HandleTable::new(8);
        let all = Rights::READ | Rights::WRITE | Rights::DUPLICATE;
        let fd = t.insert(h(9, all)).unwrap();
        let read_only = t.duplicate(fd, Rights::READ | Rights::DUPLICATE).unwrap();
        assert_eq!(t.rights(read_only), Ok(Rights::READ | Rights::DUPLICATE));
        // Asking for more than the source has gives only what it has.
        let again = t.duplicate(read_only, all | Rights::MAP_EXEC).unwrap();
        assert_eq!(t.rights(again), Ok(Rights::READ | Rights::DUPLICATE));
        // Without DUPLICATE, no copies.
        let plain = t.insert(h(5, Rights::READ)).unwrap();
        assert_eq!(t.duplicate(plain, all), Err(Errno::EBADF));
        assert_eq!(t.duplicate(77, all), Err(Errno::EBADF));
    }
}
