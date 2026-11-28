//! The escape suite (spec section 3, "Security testing"; P3-S8, ADR
//! 0047): programs that run inside a deliberately minimal compartment
//! and try to get out. Each attempt must fail in the documented way.
//!
//! The kernel's `sec.escape` test sets the scene and runs them:
//! - **The compartment** (`/comp/esc` in the system's tree) holds only
//!   the programs and nothing else: no `/dev`, `/etc` or `/test`. Its
//!   limits are small (8 processes, 8192 frames, 1 MiB and 64 nodes of
//!   tmpfs, 32 descriptors) and its profile is `full`, the widest, so
//!   every attempt reaches the check that must stop it rather than being
//!   refused by the allowlist first.
//! - **Outside it** are `/sec-outside/secret` (the text `outside\n`) and
//!   a second compartment, `/comp/escn`, running `escneighbour`, with
//!   sleeping children, a socket file and abstract socket names.
//! - **Standard input** of each program is the outside secret, open
//!   read-only; standard output is a file the kernel reads afterwards;
//!   standard error is the console.
//! - **Afterwards** the kernel checks that the secret is unchanged,
//!   that nothing new appeared outside the compartment, and that the
//!   neighbour found nothing arrived from it.
//!
//! Each program exits 0, or the number of the first check that failed,
//! having written `<program>: check N: got R` to standard output. Keel
//! only: on Linux most of these attempts would succeed.
#![no_std]

use core::ffi::CStr;

use keel_rt::sys::{self, AT_FDCWD, O_CREAT, O_RDONLY, O_WRONLY};

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ESRCH: i64 = -3;
pub const EBADF: i64 = -9;
pub const ECHILD: i64 = -10;
pub const EAGAIN: i64 = -11;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EEXIST: i64 = -17;
pub const EINVAL: i64 = -22;
pub const EMFILE: i64 = -24;
pub const ENOSPC: i64 = -28;
pub const ENOSYS: i64 = -38;
pub const ECONNREFUSED: i64 = -111;

pub const AF_UNIX: i32 = 1;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_NONBLOCK: u32 = 0o4000;
pub const O_DIRECTORY: u64 = 0o200000;
pub const WNOHANG: u32 = 1;
pub const SIGKILL: i32 = 9;
pub const SIGTERM: i32 = 15;

/// The secret's contents, as the kernel writes it.
pub const SECRET: &[u8] = b"outside\n";

/// Reports a failed check on standard output and gives its number, for
/// the program's exit status.
pub fn fail(program: &[u8], check: i32, got: i64) -> i32 {
    let sign: &[u8] = if got < 0 { b"-" } else { b"" };
    sys::writev(
        1,
        &[
            program,
            b": check ",
            digits(check as u64).as_bytes(),
            b": got ",
            sign,
        ],
    );
    sys::write_number(b"", got.unsigned_abs(), b"\n");
    check
}

/// Up to 20 decimal digits, without allocating.
pub struct Digits {
    buf: [u8; 20],
    at: usize,
}

impl Digits {
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[self.at..]
    }
}

pub fn digits(mut value: u64) -> Digits {
    let mut d = Digits {
        buf: [0; 20],
        at: 20,
    };
    loop {
        d.at -= 1;
        d.buf[d.at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    d
}

/// `parts` joined into a NUL-terminated path in `buf`.
pub fn path<'b>(buf: &'b mut [u8; 256], parts: &[&[u8]]) -> &'b CStr {
    let mut at = 0;
    for part in parts {
        let n = part.len().min(255 - at);
        buf[at..at + n].copy_from_slice(&part[..n]);
        at += n;
    }
    buf[at] = 0;
    CStr::from_bytes_until_nul(&buf[..=at]).unwrap_or(c"")
}

/// A `struct sockaddr_un` for the bytes `parts` (a leading NUL makes it
/// abstract, else a NUL is added) and its length.
pub fn sun(buf: &mut [u8; 110], parts: &[&[u8]]) -> usize {
    buf[..2].copy_from_slice(&(AF_UNIX as u16).to_le_bytes());
    let mut n = 2;
    for part in parts {
        buf[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    if buf[2] != 0 {
        buf[n] = 0;
        n += 1;
    }
    n
}

pub fn number(text: &[u8]) -> Option<i64> {
    let mut n: i64 = 0;
    for &c in text {
        n = n
            .checked_mul(10)?
            .checked_add(i64::from(c.checked_sub(b'0').filter(|d| *d < 10)?))?;
    }
    (!text.is_empty()).then_some(n)
}

/// openat(AT_FDCWD, path, O_RDONLY): the result, with the descriptor
/// closed again if one was made.
pub fn open_result(path: &CStr) -> i64 {
    open_at_result(AT_FDCWD, path, O_RDONLY)
}

/// openat(dir, path, flags): as [`open_result`].
pub fn open_at_result(dir: i32, path: &CStr, flags: u64) -> i64 {
    let fd = sys::openat(dir, path, flags, 0o644);
    if fd >= 0 {
        sys::close(fd as i32);
        0
    } else {
        fd
    }
}

pub fn exists(path: &CStr) -> bool {
    open_result(path) == 0
}

pub fn sleep_ms(ms: u64) {
    let mut req = [0u8; 16];
    req[..8].copy_from_slice(&(ms / 1000).to_le_bytes());
    req[8..].copy_from_slice(&((ms % 1000) * 1_000_000).to_le_bytes());
    sys::nanosleep(&req, None);
}

/// Waits up to `seconds` for `path` to exist.
pub fn wait_for(path: &CStr, seconds: u64) -> bool {
    for _ in 0..seconds * 100 {
        if exists(path) {
            return true;
        }
        sleep_ms(10);
    }
    false
}

pub fn touch(path: &CStr) -> bool {
    let fd = sys::openat(AT_FDCWD, path, O_WRONLY | O_CREAT, 0o644);
    if fd >= 0 {
        sys::close(fd as i32);
    }
    fd >= 0
}

/// A socket of type `ty` bound to `addr` (listening if a stream).
pub fn bound(ty: u32, addr: &[u8]) -> i32 {
    let fd = sys::socket(AF_UNIX, ty | SOCK_NONBLOCK, 0) as i32;
    if fd < 0 || sys::bind(fd, addr) != 0 {
        return -1;
    }
    if ty == SOCK_STREAM && sys::listen(fd, 4) != 0 {
        return -1;
    }
    fd
}

/// connect(2) from a new stream socket to `addr`: its result.
pub fn connect_to(addr: &[u8]) -> i64 {
    let fd = sys::socket(AF_UNIX, SOCK_STREAM, 0) as i32;
    if fd < 0 {
        return fd as i64;
    }
    let r = sys::connect(fd, addr);
    sys::close(fd);
    r
}

/// sendto(2) of one byte from a new datagram socket to `addr`.
pub fn send_to(addr: &[u8]) -> i64 {
    let fd = sys::socket(AF_UNIX, SOCK_DGRAM, 0) as i32;
    if fd < 0 {
        return fd as i64;
    }
    let r = sys::sendto(fd, b"x", 0, Some(addr));
    sys::close(fd);
    r
}

/// The inode number in a `struct stat` (its first 8 bytes are st_dev,
/// the next 8 st_ino).
pub fn ino(stat: &[u8; 144]) -> u64 {
    u64::from_le_bytes(stat[8..16].try_into().unwrap_or([0; 8]))
}

/// st_mode of a `struct stat` (offset 24).
pub fn mode(stat: &[u8; 144]) -> u32 {
    u32::from_le_bytes(stat[24..28].try_into().unwrap_or([0; 4]))
}

/// The inode of `path` (following links), or the error.
pub fn ino_of(path: &CStr) -> Result<u64, i64> {
    let mut b = [0u8; 144];
    match sys::stat(path, &mut b) {
        0 => Ok(ino(&b)),
        e => Err(e),
    }
}

/// The names in the directory `path`, each passed to `each`; the number
/// of entries other than `.` and `..`, or the error.
pub fn list(path: &CStr, mut each: impl FnMut(&[u8])) -> Result<usize, i64> {
    let fd = sys::openat(AT_FDCWD, path, O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        return Err(fd);
    }
    let fd = fd as i32;
    let mut buf = [0u8; 1024];
    let mut count = 0;
    let result = loop {
        let n = sys::getdents64(fd, &mut buf);
        if n < 0 {
            break Err(n);
        }
        if n == 0 {
            break Ok(count);
        }
        let mut at = 0;
        while at < n as usize {
            let reclen = u16::from_le_bytes([buf[at + 16], buf[at + 17]]) as usize;
            let name = &buf[at + 19..at + reclen];
            let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
            let name = &name[..end];
            if name != b"." && name != b".." {
                count += 1;
                each(name);
            }
            at += reclen;
        }
    };
    sys::close(fd);
    result
}

/// Forks a child that runs `body` and exits with its result; waits for
/// it and gives its wait status, or the fork's error.
pub fn in_child(body: impl FnOnce() -> i32) -> Result<i32, i64> {
    let pid = sys::fork();
    if pid < 0 {
        return Err(pid);
    }
    if pid == 0 {
        keel_rt::exit(body());
    }
    let mut status = 0;
    let r = sys::wait4(pid as i32, &mut status, 0);
    if r != pid {
        return Err(r);
    }
    Ok(status)
}

/// An [`in_child`] result as one number for [`fail`]: the wait status,
/// or the error.
pub fn outcome(r: Result<i32, i64>) -> i64 {
    r.map_or_else(|e| e, i64::from)
}
