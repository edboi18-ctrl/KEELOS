//! P3-T8 second part: the descriptor-level calls, checked against Linux.
//! Runs under Linux (`host.fdprobe`) and on Keel (`exec.descriptors`) and
//! must pass on both, on any filesystem /tmp is on.
//!
//! Semantics from dup(2), fcntl(2) (F_DUPFD, F_DUPFD_CLOEXEC, F_GETFL,
//! F_SETFL, F_GETLK, F_SETLK, F_SETLKW: "record locks are not inherited
//! by a child created via fork", and are released when the process
//! closes any descriptor of the file or exits), pwrite(2) ("BUGS": with
//! O_APPEND, pwrite appends), pwritev2(2) (RWF_APPEND, RWF_NOAPPEND,
//! offset -1), readv(2), statfs(2), getxattr(2). Two answers differ by
//! filesystem, so both are accepted: getxattr of a missing attribute is
//! ENODATA where the filesystem supports extended attributes (ext4,
//! tmpfs) and EOPNOTSUPP where it does not (Keel's tmpfs, ADR 0023); and
//! statfs's f_type is not checked.
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_WRONLY};

const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EINVAL: i64 = -22;
const ENOENT: i64 = -2;
const ERANGE: i64 = -34;
const ENODATA: i64 = -61;
const EOPNOTSUPP: i64 = -95;

const O_APPEND: u64 = 0o2000;
const O_NONBLOCK: u64 = 0o4000;
const O_LARGEFILE: u64 = 0o100000;
const O_CLOEXEC: u64 = 0o2000000;

const F_DUPFD: u32 = 0;
const F_GETFD: u32 = 1;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;
const F_GETLK: u32 = 5;
const F_SETLK: u32 = 6;
const F_SETLKW: u32 = 7;
const F_DUPFD_CLOEXEC: u32 = 1030;
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;

const RWF_APPEND: u32 = 0x10;
const RWF_NOAPPEND: u32 = 0x20;

/// A `struct flock`: type, whence 0, start, length.
fn flock(kind: i16, start: i64, len: i64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..2].copy_from_slice(&kind.to_le_bytes());
    b[8..16].copy_from_slice(&start.to_le_bytes());
    b[16..24].copy_from_slice(&len.to_le_bytes());
    b
}

fn lock(fd: i32, cmd: u32, kind: i16, start: i64, len: i64) -> i64 {
    let mut b = flock(kind, start, len);
    sys::fcntl_lock(fd, cmd, &mut b)
}

/// F_GETLK: (l_type, l_start, l_len, l_pid) written back.
fn getlk(fd: i32, kind: i16, start: i64, len: i64) -> Result<(i16, i64, i64, i32), i64> {
    let mut b = flock(kind, start, len);
    let r = sys::fcntl_lock(fd, F_GETLK, &mut b);
    if r != 0 {
        return Err(r);
    }
    let w = |at: usize| i64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]));
    Ok((
        i16::from_le_bytes([b[0], b[1]]),
        w(8),
        w(16),
        i32::from_le_bytes(b[24..28].try_into().unwrap_or([0; 4])),
    ))
}

fn read_at(fd: i32, offset: u64, len: usize) -> [u8; 16] {
    let mut b = [0u8; 16];
    sys::pread(fd, &mut b[..len], offset);
    b
}

/// Runs `f` in a forked child and returns its exit status.
fn in_child(f: impl FnOnce() -> i32) -> i32 {
    let pid = sys::fork();
    if pid == 0 {
        keel_rt::exit(f());
    }
    let mut status = 0;
    sys::wait4(pid as i32, &mut status, 0);
    (status >> 8) & 0xff
}

fn main(_startup: &Startup) -> i32 {
    let mut name = *b"/tmp/keel-fdprobe-0000000000\0";
    let mut pid = sys::getpid() as u64;
    for at in (18..28).rev() {
        name[at] = b'0' + (pid % 10) as u8;
        pid /= 10;
    }
    let Ok(path) = CStr::from_bytes_with_nul(&name) else {
        return 90;
    };
    let fd = sys::openat(AT_FDCWD, path, O_RDWR | O_CREAT | O_EXCL, 0o600);
    if fd < 0 {
        return 91;
    }
    let status = checks(path, fd as i32);
    let _ = sys::unlinkat(AT_FDCWD, path, 0);
    status
}

fn checks(path: &CStr, fd: i32) -> i32 {
    // 1. dup shares the file position; dup2 places; dup3's refusals.
    if sys::write(fd, b"0123456789") != 10 {
        return 1;
    }
    let d = sys::dup(fd) as i32;
    if d < 0 || sys::lseek(d, 2, 0) != 2 || sys::lseek(fd, 0, 1) != 2 {
        return 2;
    }
    if sys::dup2(fd, 40) != 40 || sys::dup2(fd, fd) != fd as i64 || sys::dup2(77, 41) != EBADF {
        return 3;
    }
    if sys::dup2(fd, 0x7fff_ffff) != EBADF || sys::dup2(55, 55) != EBADF {
        return 4;
    }
    if sys::dup3(fd, fd, 0) != EINVAL || sys::dup3(fd, 42, 1) != EINVAL {
        return 5;
    }
    if sys::dup3(fd, 42, O_CLOEXEC) != 42
        || sys::fcntl(42, F_GETFD, 0) != 1
        || sys::fcntl(40, F_GETFD, 0) != 0
    {
        return 6;
    }

    // 2. F_DUPFD and F_DUPFD_CLOEXEC from a floor.
    let a = sys::fcntl(fd, F_DUPFD, 20);
    let b = sys::fcntl(fd, F_DUPFD_CLOEXEC, 20);
    if a != 20 || b != 21 || sys::fcntl(21, F_GETFD, 0) != 1 {
        return 7;
    }
    if sys::fcntl(fd, F_DUPFD, 0x7fff_ffff) != EINVAL {
        return 8;
    }

    // 3. F_GETFL and F_SETFL.
    let ap = sys::openat(AT_FDCWD, path, O_RDWR | O_APPEND, 0) as i32;
    let fl = sys::fcntl(ap, F_GETFL, 0);
    if fl < 0
        || fl as u64 & 3 != O_RDWR
        || fl as u64 & O_APPEND == 0
        || fl as u64 & O_LARGEFILE == 0
    {
        return 9;
    }
    // F_SETFL changes O_NONBLOCK and O_APPEND, never the access mode.
    if sys::fcntl(ap, F_SETFL, O_NONBLOCK | O_WRONLY) != 0 {
        return 10;
    }
    let fl = sys::fcntl(ap, F_GETFL, 0) as u64;
    if fl & O_NONBLOCK == 0 || fl & O_APPEND != 0 || fl & 3 != O_RDWR {
        return 10;
    }
    if sys::fcntl(ap, F_SETFL, O_APPEND) != 0 {
        return 11;
    }

    // 4. Positional writes leave the position; O_APPEND appends even at an
    //    offset unless RWF_NOAPPEND; offset -1 means the position.
    if sys::pwrite(fd, b"AB", 0) != 2
        || sys::lseek(fd, 0, 1) != 2
        || &read_at(fd, 0, 4)[..4] != b"AB23"
    {
        return 12;
    }
    if sys::pwrite(ap, b"z", 0) != 1
        || &read_at(ap, 10, 1)[..1] != b"z"
        || &read_at(ap, 0, 1)[..1] != b"A"
    {
        return 13; // appended: 11 bytes now
    }
    if sys::pwritev2(ap, b"Y", 1, RWF_NOAPPEND) != 1 || &read_at(ap, 1, 1)[..1] != b"Y" {
        return 14;
    }
    if sys::pwritev2(fd, b"q", 3, RWF_APPEND) != 1 || &read_at(fd, 11, 1)[..1] != b"q" {
        return 15; // RWF_APPEND appends: 12 bytes
    }
    if sys::pwritev2(fd, b"P", -1, 0) != 1
        || sys::lseek(fd, 0, 1) != 3
        || &read_at(fd, 2, 1)[..1] != b"P"
    {
        return 16; // at the position (2), which moves
    }
    if sys::pwritev2(fd, b"x", 0, RWF_APPEND | RWF_NOAPPEND) != EINVAL
        || sys::pwritev2(fd, b"x", 0, 0x8000) != EOPNOTSUPP
    {
        return 17;
    }
    if sys::pwrite(fd, b"x", -1) != EINVAL {
        return 18;
    }

    // 5. readv fills buffers in order from the position; preadv from an
    //    offset.
    let (mut x, mut y) = ([0u8; 3], [0u8; 2]);
    sys::lseek(fd, 4, 0);
    if sys::readv2(fd, &mut x, &mut y, None) != 5
        || &x != b"456"
        || &y != b"78"
        || sys::lseek(fd, 0, 1) != 9
    {
        return 19;
    }
    if sys::readv2(fd, &mut x, &mut y, Some(0)) != 5 || &x != b"AYP" || &y != b"34" {
        return 20;
    }

    // 6. Record locks. The owner's own locks never conflict.
    if lock(fd, F_SETLK, F_WRLCK, 0, 10) != 0
        || getlk(fd, F_WRLCK, 0, 0).map(|g| g.0) != Ok(F_UNLCK)
    {
        return 21;
    }
    if lock(fd, F_SETLK, 9, 0, 1) != EINVAL || getlk(fd, F_UNLCK, 0, 1).err() != Some(EINVAL) {
        return 22;
    }
    let ro = sys::openat(AT_FDCWD, path, O_RDONLY, 0) as i32;
    if lock(ro, F_SETLK, F_WRLCK, 50, 1) != EBADF {
        return 23; // a write lock needs a descriptor open for writing
    }
    let me = sys::getpid() as i32;
    // A child is another owner: it sees the parent's lock and cannot take
    // a conflicting one, but can lock elsewhere.
    let child = in_child(|| {
        match getlk(fd, F_RDLCK, 5, 1) {
            Ok((t, 0, 10, pid)) if t == F_WRLCK && pid == me => {}
            _ => return 1,
        }
        if lock(fd, F_SETLK, F_RDLCK, 5, 1) != EAGAIN {
            return 2;
        }
        if lock(fd, F_SETLK, F_WRLCK, 10, 5) != 0 {
            return 3;
        }
        0
    });
    if child != 0 {
        return 24 + child;
    }
    // Closing any descriptor of the file drops the parent's locks.
    if sys::close(d) != 0 {
        return 28;
    }
    let child = in_child(|| {
        if lock(fd, F_SETLK, F_WRLCK, 0, 10) == 0 {
            0
        } else {
            1
        }
    });
    if child != 0 {
        return 29;
    }
    // F_SETLKW waits for a lock held by a child, and its exit releases it.
    let ready = sys::openat(AT_FDCWD, path, O_RDWR, 0) as i32;
    let pid = sys::fork();
    if pid == 0 {
        let ok = lock(fd, F_SETLK, F_WRLCK, 100, 10) == 0;
        sys::pwrite(ready, if ok { b"L" } else { b"F" }, 200);
        for _ in 0..20_000_000u32 {
            core::hint::spin_loop();
        }
        keel_rt::exit(0);
    }
    let mut seen = [0u8; 1];
    for _ in 0..100_000_000u32 {
        if sys::pread(ready, &mut seen, 200) == 1 && seen[0] != 0 {
            break;
        }
    }
    if seen[0] != b'L' {
        return 30;
    }
    if lock(fd, F_SETLKW, F_WRLCK, 105, 1) != 0 {
        return 31;
    }
    let mut status = 0;
    sys::wait4(pid as i32, &mut status, 0);
    if lock(fd, F_SETLK, F_UNLCK, 0, 0) != 0 {
        return 32;
    }

    // 7. statfs and fstatfs.
    let mut sf = [0u8; 120];
    if sys::fstatfs(fd, &mut sf) != 0 || sys::statfs(c"/tmp", &mut sf) != 0 {
        return 33;
    }
    let w = |at: usize| u64::from_le_bytes(sf[at..at + 8].try_into().unwrap_or([0; 8]));
    if w(8) == 0 || w(64) != 255 || sys::statfs(c"/tmp/keel-nothing-here", &mut sf) != ENOENT {
        return 34; // f_bsize, f_namelen
    }

    // 8. Extended attributes: none here, by either answer; the name and
    //    path checks are Linux's.
    let mut v = [0u8; 16];
    let got = sys::getxattr(path, c"user.DOSATTRIB", &mut v);
    if got != ENODATA && got != EOPNOTSUPP {
        return 35;
    }
    let got = sys::fgetxattr(fd, c"user.WINEREPARSE", &mut v);
    if got != ENODATA && got != EOPNOTSUPP {
        return 36;
    }
    if sys::getxattr(path, c"", &mut v) != ERANGE
        || sys::getxattr(c"/tmp/keel-nothing-here", c"user.x", &mut v) != ENOENT
    {
        return 37;
    }
    if sys::fgetxattr(77, c"user.x", &mut v) != EBADF {
        return 38;
    }
    // An empty list, or (on a host with a security module) its labels.
    let listed = sys::listxattr(path, &mut v);
    if listed < 0 && listed != EOPNOTSUPP {
        return 39;
    }
    if sys::setxattr(path, c"user.x", b"1", 8) != EINVAL {
        return 40; // flags other than XATTR_CREATE and XATTR_REPLACE
    }

    for n in [ap, ro, ready, 20, 21, 40, 42] {
        sys::close(n);
    }
    sys::close(fd);
    sys::write(1, b"fdprobe: 40 checks passed\n");
    0
}

keel_rt::main!(main);
