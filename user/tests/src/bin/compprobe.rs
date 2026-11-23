//! P3-S1: a process sees only its compartment's files. Run by the kernel
//! in compartment A (root /comp/A) as `compprobe A B PID`, and in B the
//! other way round: it checks its PID, that nothing outside its root can
//! be named (the system's /test, the other compartment's marker by every
//! route), and that its own root works as `/`. Leaves a marker file so
//! the other compartment's run can look for it. Keel only.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_CREAT, O_RDONLY, O_WRONLY};

/// -ENOENT.
const ENOENT: i64 = -2;

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

fn opens(dirfd: i32, path: &CStr) -> bool {
    let fd = sys::openat(dirfd, path, O_RDONLY, 0);
    if fd >= 0 {
        sys::close(fd as i32);
    }
    fd >= 0
}

fn absent(path: &CStr) -> bool {
    sys::openat(AT_FDCWD, path, O_RDONLY, 0) == ENOENT
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

fn main(startup: &Startup) -> i32 {
    let mut args = startup.args().skip(1);
    let (Some(mine), Some(other), Some(pid)) = (args.next(), args.next(), args.next()) else {
        return 20;
    };
    let mut b = [0u8; 128];
    // Its PID is counted in its own compartment.
    if Some(sys::getpid()) != number(pid) {
        return 1;
    }
    // The system's /test exists, but not from in here.
    if !absent(c"/test/compprobe") || !absent(c"/../test/compprobe") {
        return 2;
    }
    // Its own marker, at its root.
    let fd = sys::openat(
        AT_FDCWD,
        path(&mut b, &[b"/marker-", mine]),
        O_WRONLY | O_CREAT,
        0o644,
    );
    if fd < 0 {
        return 3;
    }
    sys::close(fd as i32);
    // The root is `/`: `..` stops there, and the working directory is it.
    if !opens(AT_FDCWD, path(&mut b, &[b"/../marker-", mine]))
        || !opens(AT_FDCWD, path(&mut b, &[b"marker-", mine]))
    {
        return 4;
    }
    // The other compartment's marker, by every route out of the root.
    let routes: [&[&[u8]]; 4] = [
        &[b"/marker-", other],
        &[b"/comp/", other, b"/marker-", other],
        &[b"/../", other, b"/marker-", other],
        &[b"../", other, b"/marker-", other],
    ];
    for (i, route) in routes.iter().enumerate() {
        if !absent(path(&mut b, route)) {
            return 5 + i as i32;
        }
    }
    0
}

keel_rt::main!(main);
