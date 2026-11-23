//! P3-T8: the filesystem calls, checked against Linux. Runs under Linux
//! (`host.fsprobe`) and on Keel (`exec.filesystem`) and must pass on both,
//! whatever filesystem /tmp is on Linux and as root or not: it checks
//! only what Linux guarantees for any filesystem and any owner of the
//! files it makes (directory sizes, block counts and permission checks
//! that root skips are not checked; directory listings are compared as
//! sets).
//!
//! Semantics from the man pages and Linux v6.12 (`fs/namei.c`,
//! `fs/stat.c`, `fs/utimes.c`, `fs/readdir.c`): mkdir(2), rmdir(2),
//! unlink(2), rename(2), link(2), symlink(2), readlink(2), stat(2),
//! lseek(2), getdents64(2), getcwd(2), chdir(2), chmod(2), umask(2),
//! utimensat(2), access(2), open(2) (O_NOFOLLOW, ELOOP).
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_CREAT, O_EXCL, O_RDONLY, O_RDWR};

const ENOENT: i64 = -2;
const ENXIO: i64 = -6;
const EACCES: i64 = -13;
const EEXIST: i64 = -17;
const ENOTDIR: i64 = -20;
const EISDIR: i64 = -21;
const EINVAL: i64 = -22;
const ERANGE: i64 = -34;
const ENOTEMPTY: i64 = -39;
const ELOOP: i64 = -40;
const EPERM: i64 = -1;

const O_NOFOLLOW: u64 = 0o400000;
const O_DIRECTORY: u64 = 0o200000;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const AT_REMOVEDIR: u32 = 0x200;
const AT_EMPTY_PATH: u32 = 0x1000;
const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;
const UTIME_OMIT: i64 = (1 << 30) - 2;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

/// The fields of a `struct stat` the checks read (x86-64 layout).
#[derive(Clone, Copy, PartialEq, Eq)]
struct St {
    ino: u64,
    nlink: u64,
    mode: u32,
    size: u64,
    atime: (i64, i64),
    mtime: (i64, i64),
}

fn parse(b: &[u8; 144]) -> St {
    let w = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]));
    St {
        ino: w(8),
        nlink: w(16),
        mode: u32::from_le_bytes(b[24..28].try_into().unwrap_or([0; 4])),
        size: w(48),
        atime: (w(72) as i64, w(80) as i64),
        mtime: (w(88) as i64, w(96) as i64),
    }
}

fn stat(path: &CStr) -> Result<St, i64> {
    let mut b = [0u8; 144];
    match sys::stat(path, &mut b) {
        0 => Ok(parse(&b)),
        e => Err(e),
    }
}

fn lstat(path: &CStr) -> Result<St, i64> {
    let mut b = [0u8; 144];
    match sys::lstat(path, &mut b) {
        0 => Ok(parse(&b)),
        e => Err(e),
    }
}

fn fstat(fd: i32) -> Result<St, i64> {
    let mut b = [0u8; 144];
    match sys::fstat(fd, &mut b) {
        0 => Ok(parse(&b)),
        e => Err(e),
    }
}

fn create(path: &CStr, data: &[u8]) -> i32 {
    let fd = sys::openat(AT_FDCWD, path, O_RDWR | O_CREAT | O_EXCL, 0o666);
    if fd >= 0 && !data.is_empty() {
        sys::write(fd as i32, data);
    }
    fd as i32
}

/// The names getdents64 lists for the directory open on `fd`, with their
/// d_type, sorted (filesystems list in different orders).
fn listing(fd: i32, out: &mut [([u8; 16], u8); 16]) -> Result<usize, i64> {
    let mut n = 0;
    let mut buf = [0u8; 512];
    loop {
        let got = sys::getdents64(fd, &mut buf);
        if got < 0 {
            return Err(got);
        }
        if got == 0 {
            break;
        }
        let mut at = 0usize;
        while at < got as usize {
            let reclen = u16::from_le_bytes([buf[at + 16], buf[at + 17]]) as usize;
            let kind = buf[at + 18];
            let name = &buf[at + 19..at + reclen];
            let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
            if n < out.len() && len <= 16 {
                out[n].0 = [0; 16];
                out[n].0[..len].copy_from_slice(&name[..len]);
                out[n].1 = kind;
                n += 1;
            }
            at += reclen;
        }
    }
    out[..n].sort_unstable();
    Ok(n)
}

fn entry(name: &[u8], kind: u8) -> ([u8; 16], u8) {
    let mut e = [0u8; 16];
    e[..name.len()].copy_from_slice(name);
    (e, kind)
}

fn main(_startup: &Startup) -> i32 {
    // A directory of our own in /tmp, named after our PID; we work in it.
    let mut name = *b"/tmp/keel-fsprobe-0000000000\0";
    let mut pid = sys::getpid() as u64;
    for at in (18..28).rev() {
        name[at] = b'0' + (pid % 10) as u8;
        pid /= 10;
    }
    let Ok(base) = CStr::from_bytes_with_nul(&name) else {
        return 90;
    };
    if sys::mkdir(base, 0o755) != 0 {
        return 91;
    }
    let top = sys::openat(AT_FDCWD, c"/tmp", O_RDONLY | O_DIRECTORY, 0) as i32;
    if top < 0 || sys::chdir(base) != 0 {
        return 92;
    }
    let status = checks(base);
    // Clean up whatever is left, deepest first, from inside our
    // directory (the checks end there), then the directory itself.
    let _ = sys::chdir(base);
    for path in [c"moved/sub", c"moved", c"d/sub", c"d", c"e", c"x"] {
        let _ = sys::unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
    }
    sys::fchdir(top);
    if sys::rmdir(base) != 0 && status == 0 {
        return 93; // something was left in it
    }
    status
}

fn checks(base: &CStr) -> i32 {
    // 1. mkdir: a new directory, EEXIST again, a trailing slash allowed,
    //    a missing parent ENOENT.
    if sys::mkdir(c"d", 0o755) != 0 || sys::mkdir(c"d", 0o755) != EEXIST {
        return 1;
    }
    if sys::mkdir(c"d/sub/", 0o700) != 0 || sys::mkdir(c"nope/x", 0o755) != ENOENT {
        return 2;
    }
    let Ok(d) = stat(c"d") else { return 3 };
    if d.mode & S_IFMT != S_IFDIR || d.nlink != 3 {
        return 3; // 2 + one subdirectory
    }

    // 2. umask applies at creation.
    let old = sys::umask(0o022);
    let f = create(c"f", b"hello world");
    let _ = sys::umask(0o077);
    let g = create(c"g", b"");
    let _ = sys::umask(old as u32);
    if f < 0 || g < 0 {
        return 4;
    }
    let (Ok(fs), Ok(gs)) = (stat(c"f"), stat(c"g")) else {
        return 5;
    };
    if fs.mode != S_IFREG | 0o644 || gs.mode != S_IFREG | 0o600 || fs.size != 11 {
        return 5;
    }

    // 3. Symbolic links: lstat sees the link, stat its target; readlink
    //    gives the target, truncated to the buffer, EINVAL for others.
    if sys::symlink(c"f", c"link") != 0 || sys::symlink(c"f", c"link") != EEXIST {
        return 6;
    }
    let (Ok(ls), Ok(ts)) = (lstat(c"link"), stat(c"link")) else {
        return 7;
    };
    if ls.mode & S_IFMT != S_IFLNK || ls.size != 1 || ts.ino != fs.ino {
        return 7;
    }
    let mut buf = [0u8; 16];
    if sys::readlink(c"link", &mut buf) != 1 || buf[0] != b'f' {
        return 8;
    }
    if sys::symlink(c"d/sub", c"long") != 0
        || sys::readlink(c"long", &mut buf[..3]) != 3
        || &buf[..3] != b"d/s"
    {
        return 9;
    }
    if sys::readlink(c"f", &mut buf) != EINVAL || sys::readlink(c"link", &mut buf[..0]) != EINVAL {
        return 10;
    }
    // Through a link in the middle of a path; O_NOFOLLOW refuses one at
    // the end; a loop is ELOOP; a dangling link is ENOENT to stat.
    if stat(c"long/../sub").map(|s| s.mode & S_IFMT) != Ok(S_IFDIR) {
        return 11;
    }
    if sys::openat(AT_FDCWD, c"link", O_RDONLY | O_NOFOLLOW, 0) != ELOOP {
        return 12;
    }
    if sys::symlink(c"loop2", c"loop1") != 0 || sys::symlink(c"loop1", c"loop2") != 0 {
        return 13;
    }
    if sys::openat(AT_FDCWD, c"loop1", O_RDONLY, 0) != ELOOP {
        return 13;
    }
    if sys::symlink(c"nowhere", c"dangling") != 0
        || stat(c"dangling").err() != Some(ENOENT)
        || lstat(c"dangling").is_err()
    {
        return 14;
    }

    // 4. Hard links share the node; directories cannot be linked.
    if sys::link(c"f", c"f2") != 0
        || stat(c"f").map(|s| s.nlink) != Ok(2)
        || stat(c"f2").map(|s| s.ino) != Ok(fs.ino)
    {
        return 15;
    }
    if sys::link(c"d", c"d2") != EPERM || sys::link(c"f", c"g") != EEXIST {
        return 16;
    }

    // 5. unlink: one name gone, the other stays; a directory EISDIR; an
    //    open file outlives its last name.
    if sys::unlinkat(AT_FDCWD, c"f2", 0) != 0 || stat(c"f").map(|s| s.nlink) != Ok(1) {
        return 17;
    }
    if sys::unlinkat(AT_FDCWD, c"d", 0) != EISDIR || sys::unlinkat(AT_FDCWD, c"none", 0) != ENOENT {
        return 18;
    }
    if sys::unlinkat(AT_FDCWD, c"f", 0) != 0 || stat(c"f").is_ok() {
        return 19;
    }
    let mut back = [0u8; 11];
    if sys::pread(f, &mut back, 0) != 11
        || &back != b"hello world"
        || fstat(f).map(|s| s.nlink) != Ok(0)
    {
        return 20;
    }
    if stat(c"link").err() != Some(ENOENT) {
        return 21; // the link now dangles
    }

    // 6. rmdir: not empty, not a directory, "." and "..".
    if sys::rmdir(c"d") != ENOTEMPTY || sys::rmdir(c"g") != ENOTDIR {
        return 22;
    }
    if sys::rmdir(c"d/sub/.") != EINVAL || sys::rmdir(c"d/sub/..") != ENOTEMPTY {
        return 23;
    }

    // 7. rename.
    if sys::rename(c"g", c"h") != 0 || stat(c"g").is_ok() || stat(c"h").map(|s| s.ino) != Ok(gs.ino)
    {
        return 24;
    }
    let k = create(c"k", b"k");
    let Ok(kino) = stat(c"k").map(|s| s.ino) else {
        return 25;
    };
    if k < 0 || sys::rename(c"k", c"h") != 0 || stat(c"h").map(|s| s.ino) != Ok(kino) {
        return 25; // replaced
    }
    if sys::rename(c"h", c"d") != EISDIR || sys::rename(c"d", c"h") != ENOTDIR {
        return 26;
    }
    if sys::rename(c"d", c"d/sub/x") != EINVAL {
        return 27;
    }
    if sys::mkdir(c"e", 0o755) != 0 || sys::rename(c"e", c"d") != ENOTEMPTY {
        return 28;
    }
    if sys::rename2(c"h", c"long", RENAME_NOREPLACE) != EEXIST {
        return 29;
    }
    let Ok(dino) = stat(c"d").map(|s| s.ino) else {
        return 30;
    };
    if sys::rename2(c"d", c"e", RENAME_EXCHANGE) != 0 || stat(c"e").map(|s| s.ino) != Ok(dino) {
        return 30;
    }
    if stat(c"e/sub").map(|s| s.mode & S_IFMT) != Ok(S_IFDIR) || sys::rename(c"e", c"moved") != 0 {
        return 31;
    }

    // 8. getdents64 lists ".", "..", and each name with its type.
    let dir = sys::openat(AT_FDCWD, c"moved", O_RDONLY | O_DIRECTORY, 0) as i32;
    let mut names = [([0u8; 16], 0u8); 16];
    let Ok(n) = listing(dir, &mut names) else {
        return 32;
    };
    let mut want = [entry(b".", 4), entry(b"..", 4), entry(b"sub", 4)];
    want.sort_unstable();
    if names[..n] != want {
        return 32;
    }
    if sys::symlink(c"x", c"moved/l") != 0 || create(c"moved/r", b"") < 0 {
        return 33;
    }
    sys::lseek(dir, 0, 0); // rewinddir
    let Ok(n) = listing(dir, &mut names) else {
        return 34;
    };
    let mut want = [
        entry(b".", 4),
        entry(b"..", 4),
        entry(b"l", 10),
        entry(b"r", 8),
        entry(b"sub", 4),
    ];
    want.sort_unstable();
    if names[..n] != want {
        return 34;
    }
    if sys::getdents64(f, &mut [0u8; 64]) != ENOTDIR {
        return 35;
    }

    // 9. lseek.
    let size = 11;
    if sys::lseek(f, 4, 0) != 4 || sys::lseek(f, 2, 1) != 6 || sys::lseek(f, -1, 2) != size - 1 {
        return 36;
    }
    if sys::lseek(f, -20, 1) != EINVAL || sys::lseek(f, 0, 7) != EINVAL {
        return 37;
    }
    if sys::lseek(f, size, 3) != ENXIO || sys::lseek(f, 0, 4) != size || sys::lseek(f, 3, 3) != 3 {
        return 38; // SEEK_DATA past the end, SEEK_HOLE at the end
    }

    // 10. chdir, getcwd, fchdir.
    let here = sys::openat(AT_FDCWD, c".", O_RDONLY | O_DIRECTORY, 0) as i32;
    if sys::chdir(c"moved/sub") != 0 {
        return 39;
    }
    let mut cwd = [0u8; 256];
    let len = sys::getcwd(&mut cwd);
    let base_bytes = base.to_bytes();
    let expect_len = base_bytes.len() + b"/moved/sub".len() + 1;
    if len != expect_len as i64
        || &cwd[..base_bytes.len()] != base_bytes
        || &cwd[base_bytes.len()..len as usize - 1] != b"/moved/sub"
    {
        return 40;
    }
    if sys::getcwd(&mut cwd[..5]) != ERANGE {
        return 41;
    }
    if sys::fchdir(here) != 0 || stat(c"moved").is_err() {
        return 42;
    }
    // A removed working directory: getcwd ENOENT.
    if sys::mkdir(c"x", 0o755) != 0 || sys::chdir(c"x") != 0 || sys::rmdir(c"../x") != 0 {
        return 43;
    }
    if sys::getcwd(&mut cwd) != ENOENT {
        return 44;
    }
    if sys::fchdir(here) != 0 {
        return 45;
    }

    // 11. chmod, fchmod.
    if sys::chmod(c"h", 0o640) != 0 || stat(c"h").map(|s| s.mode) != Ok(S_IFREG | 0o640) {
        return 46;
    }
    if sys::fchmod(k, 0o604) != 0 || fstat(k).map(|s| s.mode) != Ok(S_IFREG | 0o604) {
        return 47;
    }

    // 12. utimensat: exact times, UTIME_OMIT, and a descriptor with a NULL
    //     path.
    let times = [[1000, 5], [2000, 7]];
    if sys::utimensat(AT_FDCWD, Some(c"h"), Some(&times), 0) != 0 {
        return 48;
    }
    let Ok(t) = stat(c"h") else { return 49 };
    if t.atime != (1000, 5) || t.mtime != (2000, 7) {
        return 49;
    }
    if sys::utimensat(k, None, Some(&[[3000, 0], [0, UTIME_OMIT]]), 0) != 0 {
        return 50;
    }
    let Ok(t) = fstat(k) else { return 51 };
    if t.atime != (3000, 0) || t.mtime != (2000, 7) {
        return 51;
    }
    if sys::utimensat(AT_FDCWD, Some(c"h"), Some(&[[0, 1_000_000_000], [0, 0]]), 0) != EINVAL {
        return 52;
    }
    // A link's own times with AT_SYMLINK_NOFOLLOW, its target's without.
    if sys::utimensat(
        AT_FDCWD,
        Some(c"long"),
        Some(&[[10, 0], [20, 0]]),
        AT_SYMLINK_NOFOLLOW,
    ) != 0
    {
        return 53;
    }
    if lstat(c"long").map(|s| s.mtime) != Ok((20, 0))
        || stat(c"long").map(|s| s.mtime) == Ok((20, 0))
    {
        return 53;
    }

    // 13. access: as the owner (or root), existence, and execute only
    //     with an execute bit; bad modes EINVAL.
    if sys::access(c"h", 0) != 0
        || sys::access(c"none", 0) != ENOENT
        || sys::access(c"h", 8) != EINVAL
    {
        return 54;
    }
    if sys::access(c"h", 1) != EACCES || sys::access(c"moved", 1) != 0 {
        return 55;
    }

    // 14. newfstatat with AT_EMPTY_PATH is fstat; unknown flags EINVAL.
    let mut b = [0u8; 144];
    if sys::fstatat(k, c"", &mut b, AT_EMPTY_PATH) != 0 || parse(&b).ino != kino {
        return 56;
    }
    if sys::fstatat(AT_FDCWD, c"h", &mut b, 0x8000_0000) != EINVAL
        || sys::fstatat(k, c"", &mut b, 0) != ENOENT
    {
        return 57;
    }

    // Tidy up (main removes the directories).
    for path in [
        c"h",
        c"link",
        c"long",
        c"loop1",
        c"loop2",
        c"dangling",
        c"moved/l",
        c"moved/r",
    ] {
        if sys::unlinkat(AT_FDCWD, path, 0) != 0 {
            return 58;
        }
    }
    sys::close(f);
    sys::close(g);
    sys::close(k);
    sys::close(dir);
    sys::close(here);
    sys::write(1, b"fsprobe: 58 checks passed\n");
    0
}

keel_rt::main!(main);
