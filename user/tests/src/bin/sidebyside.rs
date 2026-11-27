//! P3-S1, security acceptance P3 item 2: two compartments running side
//! by side cannot see each other's processes, files or sockets. The
//! kernel runs `sidebyside NAME OTHER CHILDREN TOP` in compartments A and
//! B at the same time, then again with the counts swapped, so each
//! direction is checked while the other compartment holds what is looked
//! for:
//!
//! 1. It forks CHILDREN sleeping children (PIDs 2..=CHILDREN+1), binds a
//!    stream listener at `/sock` and at the abstract `\0sbs-NAME`, a
//!    datagram socket at the abstract `\0sbs-dgram-NAME`, and a listener
//!    at the abstract `\0sbs-shared`, which both compartments bind (one
//!    namespace would make the second EADDRINUSE). Then it writes
//!    `/ready-NAME` and waits for the kernel's `/go`.
//! 2. With both running: `/proc` lists exactly its own PIDs; kill(2) of
//!    every PID from CHILDREN+2 to TOP (the other's, when it has more) is
//!    ESRCH; the other's files cannot be named by any route; connecting
//!    or sending to the other's abstract names is ECONNREFUSED, and to
//!    its socket path ENOENT, while its own names work.
//! 3. It writes `/checked-NAME` and waits for `/stop`, so the other's
//!    checks all ran while this one was alive. Then nothing from the
//!    other has arrived: no connection pending, no datagram, every child
//!    still alive until it kills them (each then reaped with SIGKILL).
//!
//! Exit 0, or the number of the check that failed. Keel only.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_CREAT, O_RDONLY, O_WRONLY};

const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EAGAIN: i64 = -11;
const ECONNREFUSED: i64 = -111;
const AF_UNIX: i32 = 1;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_NONBLOCK: u32 = 0o4000;
const O_DIRECTORY: u64 = 0o200000;
const WNOHANG: u32 = 1;
const SIGKILL: i32 = 9;
/// The most children a run forks.
const MAX_CHILDREN: usize = 4;

/// `parts` joined into a NUL-terminated path in `buf`.
fn path<'b>(buf: &'b mut [u8; 128], parts: &[&[u8]]) -> &'b CStr {
    let mut at = 0;
    for part in parts {
        buf[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    buf[at] = 0;
    CStr::from_bytes_until_nul(&buf[..=at]).unwrap_or(c"")
}

/// A `struct sockaddr_un` for the bytes `parts` (a leading NUL makes it
/// abstract, else a NUL is added) and its length.
fn sun(buf: &mut [u8; 110], parts: &[&[u8]]) -> usize {
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

fn number(text: &[u8]) -> Option<i64> {
    let mut n: i64 = 0;
    for &c in text {
        n = n
            .checked_mul(10)?
            .checked_add(i64::from(c.checked_sub(b'0').filter(|d| *d < 10)?))?;
    }
    (!text.is_empty()).then_some(n)
}

fn exists(path: &CStr) -> bool {
    let fd = sys::openat(AT_FDCWD, path, O_RDONLY, 0);
    if fd >= 0 {
        sys::close(fd as i32);
    }
    fd >= 0
}

fn sleep_ms(ms: u64) {
    let mut req = [0u8; 16];
    req[8..].copy_from_slice(&(ms * 1_000_000).to_le_bytes());
    sys::nanosleep(&req, None);
}

/// Waits up to 60 s for `path` to exist. Gives up at once when `/stop`
/// is there instead: the kernel has ended the run early.
fn wait_for(path: &CStr) -> bool {
    for _ in 0..6000 {
        if exists(path) {
            return true;
        }
        if exists(c"/stop") {
            return false;
        }
        sleep_ms(10);
    }
    false
}

fn touch(path: &CStr) -> bool {
    let fd = sys::openat(AT_FDCWD, path, O_WRONLY | O_CREAT, 0o644);
    if fd >= 0 {
        sys::close(fd as i32);
    }
    fd >= 0
}

/// A socket of type `ty` bound to `addr` (listening if a stream).
fn bound(ty: u32, addr: &[u8]) -> i32 {
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
fn connect_to(addr: &[u8]) -> i64 {
    let fd = sys::socket(AF_UNIX, SOCK_STREAM, 0) as i32;
    if fd < 0 {
        return fd as i64;
    }
    let r = sys::connect(fd, addr);
    sys::close(fd);
    r
}

/// sendto(2) of one byte from a new datagram socket to `addr`.
fn send_to(addr: &[u8]) -> i64 {
    let fd = sys::socket(AF_UNIX, SOCK_DGRAM, 0) as i32;
    if fd < 0 {
        return fd as i64;
    }
    let r = sys::sendto(fd, b"x", 0, Some(addr));
    sys::close(fd);
    r
}

/// The PIDs `/proc` lists, as a bit set (bit n for PID n, n < 64), or
/// None if it cannot be read or lists any other number.
fn proc_pids() -> Option<u64> {
    let fd = sys::openat(AT_FDCWD, c"/proc", O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        return None;
    }
    let fd = fd as i32;
    let mut set = 0u64;
    let mut buf = [0u8; 1024];
    let mut ok = true;
    loop {
        let n = sys::getdents64(fd, &mut buf);
        if n <= 0 {
            ok &= n == 0;
            break;
        }
        let mut at = 0;
        while at < n as usize {
            let reclen = u16::from_le_bytes([buf[at + 16], buf[at + 17]]) as usize;
            let name = &buf[at + 19..at + reclen];
            let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
            if let Some(pid) = number(&name[..end]) {
                if pid < 64 {
                    set |= 1 << pid;
                } else {
                    ok = false;
                }
            }
            at += reclen;
        }
    }
    sys::close(fd);
    ok.then_some(set)
}

fn main(startup: &Startup) -> i32 {
    let mut args = startup.args().skip(1);
    let (Some(mine), Some(other), Some(children), Some(top)) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        return 90;
    };
    let (Some(children), Some(top)) = (number(children), number(top)) else {
        return 91;
    };
    let children = children as usize;
    if children > MAX_CHILDREN || top >= 64 || sys::getpid() != 1 {
        return 92;
    }
    let mut b = [0u8; 128];
    let mut a = [0u8; 110];

    // 1. What the other compartment will look for.
    let mut kids = [0i32; MAX_CHILDREN];
    for kid in kids.iter_mut().take(children) {
        let pid = sys::fork();
        if pid == 0 {
            loop {
                sleep_ms(1000);
            }
        }
        if pid < 0 {
            return 1;
        }
        *kid = pid as i32;
    }
    let n = sun(&mut a, &[b"/sock"]);
    let path_listener = bound(SOCK_STREAM, &a[..n]);
    let n = sun(&mut a, &[b"\0sbs-", mine]);
    let listener = bound(SOCK_STREAM, &a[..n]);
    let n = sun(&mut a, &[b"\0sbs-dgram-", mine]);
    let dgram = bound(SOCK_DGRAM, &a[..n]);
    let n = sun(&mut a, &[b"\0sbs-shared"]);
    let shared = bound(SOCK_STREAM, &a[..n]);
    if path_listener < 0 || listener < 0 || dgram < 0 {
        return 2;
    }
    if shared < 0 {
        return 3;
    }
    if !touch(path(&mut b, &[b"/ready-", mine])) {
        return 4;
    }
    if !wait_for(c"/go") {
        return 5;
    }

    // 2. Processes: /proc is exactly PIDs 1..=children+1, and no PID
    //    beyond them, up to the other's highest, can be signalled.
    let own = (1u64 << (children + 2)) - 2;
    if proc_pids() != Some(own) {
        return 10;
    }
    for pid in children as i64 + 2..=top {
        if sys::kill(pid as i32, 0) != ESRCH || sys::kill(pid as i32, SIGKILL) != ESRCH {
            return 11;
        }
    }
    // Files: the other's ready marker by every route out of the root.
    let routes: [&[&[u8]]; 4] = [
        &[b"/ready-", other],
        &[b"/comp/", other, b"/ready-", other],
        &[b"/../", other, b"/ready-", other],
        &[b"../", other, b"/ready-", other],
    ];
    for (i, route) in routes.iter().enumerate() {
        if sys::openat(AT_FDCWD, path(&mut b, route), O_RDONLY, 0) != ENOENT {
            return 20 + i as i32;
        }
    }
    // Sockets: the other's names are not there; its own are.
    let n = sun(&mut a, &[b"\0sbs-", other]);
    if connect_to(&a[..n]) != ECONNREFUSED {
        return 30;
    }
    let n = sun(&mut a, &[b"\0sbs-dgram-", other]);
    if send_to(&a[..n]) != ECONNREFUSED {
        return 31;
    }
    let n = sun(&mut a, &[b"/../", other, b"/sock"]);
    if connect_to(&a[..n]) != ENOENT {
        return 32;
    }
    let n = sun(&mut a, &[b"\0sbs-", mine]);
    if connect_to(&a[..n]) != 0 {
        return 33;
    }
    // That connection is the one to take back, below.
    let mut pending = 1;

    // 3. The other has run all its checks.
    if !touch(path(&mut b, &[b"/checked-", mine])) || !wait_for(c"/stop") {
        return 40;
    }
    while pending > 0 {
        let c = sys::accept4(listener, None, 0);
        if c < 0 {
            return 41;
        }
        sys::close(c as i32);
        pending -= 1;
    }
    if sys::accept4(listener, None, 0) != EAGAIN || sys::accept4(path_listener, None, 0) != EAGAIN {
        return 42;
    }
    let mut byte = [0u8; 1];
    if sys::recvfrom(dgram, &mut byte, 0, None) != EAGAIN {
        return 43;
    }
    let mut status = 0;
    if sys::wait4(-1, &mut status, WNOHANG) != 0 && children > 0 {
        return 44;
    }
    for &kid in kids.iter().take(children) {
        if sys::kill(kid, SIGKILL) != 0 {
            return 45;
        }
        let mut status = 0;
        if sys::wait4(kid, &mut status, 0) != i64::from(kid) || status & 0x7f != SIGKILL {
            return 46;
        }
    }
    0
}

keel_rt::main!(main);
