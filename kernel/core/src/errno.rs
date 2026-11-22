//! Linux error numbers, as returned (negated) by system calls.
//!
//! Values from Linux `include/uapi/asm-generic/errno-base.h` and
//! `errno.h` at v6.12, which x86-64 uses unchanged.

/// An error a system call returns to user space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Errno {
    EPERM = 1,
    ENOENT = 2,
    EIO = 5,
    E2BIG = 7,
    ENOEXEC = 8,
    EBADF = 9,
    EAGAIN = 11,
    ENOMEM = 12,
    EACCES = 13,
    EFAULT = 14,
    EEXIST = 17,
    ENODEV = 19,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    EMFILE = 24,
    ENOTTY = 25,
    EFBIG = 27,
    ENOSPC = 28,
    ESPIPE = 29,
    ENAMETOOLONG = 36,
    ENOSYS = 38,
    ENOTEMPTY = 39,
    ELOOP = 40,
}

impl Errno {
    /// The value a system call puts in RAX: `-errno`.
    pub fn to_return(self) -> i64 {
        -(self as i64)
    }
}
