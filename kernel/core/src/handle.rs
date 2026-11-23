//! Per-process handle table with rights (P1-S1, SR-1).
//!
//! Every kernel object a process can reach is a handle in this table, and
//! every handle carries a rights mask. A Linux file descriptor is the
//! handle's index. Each operation states the right it needs and
//! [`HandleTable::get`] checks it; duplicating can only remove rights.
//! There is no plain file-descriptor table anywhere to migrate from.

use alloc::vec::Vec;

use crate::errno::Errno;

/// `index` if `index < size`, else 0, without a branch: Linux's generic
/// `array_index_mask_nospec` (`include/linux/nospec.h`), with `black_box`
/// in the role of `OPTIMIZER_HIDE_VAR` so the compiler cannot use what it
/// knows about `index` to drop the mask. (This crate has no assembly; the
/// kernel's own uses go through `keel_hal::arch::x86_64::cpu::index_nospec`,
/// the `cmp`/`sbb` form.) Valid for `index` and `size` below 2^63.
pub fn index_nospec(index: usize, size: usize) -> usize {
    let index = core::hint::black_box(index);
    let mask = !((index | size.wrapping_sub(1).wrapping_sub(index)) as isize >> (isize::BITS - 1));
    index & mask as usize
}

/// Why [`HandleTable::check`] refused a lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No open handle at that index.
    NoHandle,
    /// The handle exists but lacks some of the rights asked for.
    MissingRights { has: Rights, needs: Rights },
}

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

/// The table. Indices are Linux file descriptors. Cloning it copies every
/// handle with its rights and close-on-exec flag (fork); the objects are
/// cloned too, so for shared objects (an `Arc`) both tables refer to the
/// same ones, as fork(2)'s duplicated descriptors refer to the same open
/// file descriptions.
#[derive(Clone, Debug)]
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

    /// Removes every handle marked close-on-exec and returns them (execve;
    /// Linux's do_close_on_exec). The caller drops them, outside any lock
    /// it holds.
    pub fn take_close_on_exec(&mut self) -> alloc::vec::Vec<Handle<T>> {
        let mut closed = alloc::vec::Vec::new();
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|h| h.close_on_exec)
                && let Some(handle) = slot.take()
            {
                closed.push(handle);
            }
        }
        closed
    }

    /// Whether `fd` is closed by execve (FD_CLOEXEC). EBADF if no handle.
    pub fn close_on_exec(&self, fd: i32) -> Result<bool, Errno> {
        self.slot(fd).map(|h| h.close_on_exec).ok_or(Errno::EBADF)
    }

    /// Sets whether `fd` is closed by execve. EBADF if no handle.
    pub fn set_close_on_exec(&mut self, fd: i32, close: bool) -> Result<(), Errno> {
        let index = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        if index >= self.slots.len() {
            return Err(Errno::EBADF);
        }
        let index = index_nospec(index, self.slots.len());
        let handle = self.slots[index].as_mut().ok_or(Errno::EBADF)?;
        handle.close_on_exec = close;
        Ok(())
    }

    fn slot(&self, fd: i32) -> Option<&Handle<T>> {
        let index = usize::try_from(fd).ok()?;
        if index >= self.slots.len() {
            return None;
        }
        // Spectre v1: the descriptor is user-controlled, so clamp it
        // without a branch before using it as an index (SR-15).
        let index = index_nospec(index, self.slots.len());
        self.slots[index].as_ref()
    }

    /// The object behind `fd`, if the handle has every right in
    /// `required`. A missing handle and a missing right both give EBADF,
    /// which is what Linux returns for, e.g., write(2) on a read-only
    /// descriptor.
    pub fn get(&self, fd: i32, required: Rights) -> Result<&T, Errno> {
        self.check(fd, required).map_err(|_| Errno::EBADF)
    }

    /// As [`HandleTable::get`], saying why a lookup was refused, so the
    /// kernel can tell a rights refusal from a bad descriptor (security
    /// acceptance P1 item 4).
    pub fn check(&self, fd: i32, required: Rights) -> Result<&T, Refusal> {
        match self.slot(fd) {
            Some(h) if h.rights.contains(required) => Ok(&h.object),
            Some(h) => Err(Refusal::MissingRights {
                has: h.rights,
                needs: required,
            }),
            None => Err(Refusal::NoHandle),
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
    fn index_masking() {
        assert_eq!(index_nospec(0, 4), 0);
        assert_eq!(index_nospec(3, 4), 3);
        assert_eq!(index_nospec(4, 4), 0);
        assert_eq!(index_nospec(1 << 40, 4), 0);
        assert_eq!(index_nospec(5, 0), 0);
        assert_eq!(index_nospec(1023, 1024), 1023);
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
        assert_eq!(
            t.check(fd, Rights::WRITE),
            Err(Refusal::MissingRights {
                has: Rights::READ | Rights::STAT,
                needs: Rights::WRITE
            })
        );
        assert_eq!(t.check(5, Rights::NONE), Err(Refusal::NoHandle));
        assert_eq!(t.check(-1, Rights::READ), Err(Refusal::NoHandle));
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

    #[test]
    fn close_on_exec_is_per_handle_and_needs_one() {
        let mut table: HandleTable<u8> = HandleTable::new(4);
        let fd = table
            .insert(Handle {
                object: 1,
                rights: Rights::READ,
                close_on_exec: false,
            })
            .unwrap();
        assert_eq!(table.close_on_exec(fd), Ok(false));
        table.set_close_on_exec(fd, true).unwrap();
        assert_eq!(table.close_on_exec(fd), Ok(true));
        assert_eq!(table.close_on_exec(fd + 1), Err(Errno::EBADF));
        assert_eq!(table.set_close_on_exec(-1, true), Err(Errno::EBADF));
        assert_eq!(table.set_close_on_exec(100, true), Err(Errno::EBADF));
    }

    #[test]
    fn exec_closes_only_close_on_exec_handles() {
        let mut table: HandleTable<u8> = HandleTable::new(4);
        let handle = |object, close_on_exec| Handle {
            object,
            rights: Rights::READ,
            close_on_exec,
        };
        let kept = table.insert(handle(1, false)).unwrap();
        let gone = table.insert(handle(2, true)).unwrap();
        let closed = table.take_close_on_exec();
        assert_eq!(closed.iter().map(|h| h.object).collect::<Vec<_>>(), [2]);
        assert_eq!(table.get(kept, Rights::READ), Ok(&1));
        assert_eq!(table.get(gone, Rights::NONE), Err(Errno::EBADF));
        // The freed number is used again.
        assert_eq!(table.insert(handle(3, false)), Ok(gone));
    }

    #[test]
    fn a_cloned_table_shares_its_objects_and_keeps_rights_and_flags() {
        use alloc::sync::Arc;
        let mut table: HandleTable<Arc<u8>> = HandleTable::new(4);
        let object = Arc::new(7u8);
        let fd = table
            .insert(Handle {
                object: object.clone(),
                rights: Rights::READ,
                close_on_exec: true,
            })
            .unwrap();
        let copy = table.clone();
        let shared = copy.get(fd, Rights::READ).unwrap();
        assert!(
            Arc::ptr_eq(shared, &object),
            "the same object, as fork's descriptors"
        );
        assert_eq!(copy.close_on_exec(fd), Ok(true));
        assert_eq!(
            copy.get(fd, Rights::WRITE),
            Err(Errno::EBADF),
            "rights are copied, not widened"
        );
    }
}
