//! Escape suite: the other compartment (ADR 0047). Run as
//! `escneighbour CHILDREN` in `/comp/escn` while the escape programs run
//! in `/comp/esc`. It holds what they try to reach:
//!
//! 1. It forks CHILDREN children that sleep (PIDs 2 and up in its own
//!    numbering), writes `/mine`, binds a stream listener at `/sock` and
//!    at the abstract `\0esc-n`, and a datagram socket at the abstract
//!    `\0esc-nd`. Then it writes `/ready` and waits for the kernel's
//!    `/stop` (up to 15 minutes).
//! 2. Then nothing from the other compartment has arrived: no connection
//!    is pending on either listener, no datagram is queued, `/mine` is
//!    unchanged, and every child is still alive (none was signalled).
//!    It kills and reaps them, each ended by SIGKILL.
//!
//! Exit 0, or the number of the check that failed.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys;
use keel_sectests::{
    EAGAIN, SIGKILL, SOCK_DGRAM, SOCK_STREAM, WNOHANG, bound, fail, number, sun, touch, wait_for,
};

const ME: &[u8] = b"escneighbour";
const MAX_CHILDREN: usize = 8;

fn main(startup: &Startup) -> i32 {
    let Some(children) = startup.args().nth(1).and_then(number) else {
        return 90;
    };
    let children = children as usize;
    if children > MAX_CHILDREN || sys::getpid() != 1 {
        return 91;
    }
    let mut kids = [0i32; MAX_CHILDREN];
    for kid in kids.iter_mut().take(children) {
        let pid = sys::fork();
        if pid == 0 {
            loop {
                keel_sectests::sleep_ms(1000);
            }
        }
        if pid < 0 {
            return fail(ME, 1, pid);
        }
        *kid = pid as i32;
    }
    let fd = sys::openat(
        sys::AT_FDCWD,
        c"/mine",
        sys::O_WRONLY | sys::O_CREAT | sys::O_EXCL,
        0o644,
    );
    if fd < 0 || sys::write(fd as i32, b"neighbour\n") != 10 {
        return fail(ME, 2, fd);
    }
    sys::close(fd as i32);
    let mut a = [0u8; 110];
    let n = sun(&mut a, &[b"/sock"]);
    let path_listener = bound(SOCK_STREAM, &a[..n]);
    let n = sun(&mut a, &[b"\0esc-n"]);
    let listener = bound(SOCK_STREAM, &a[..n]);
    let n = sun(&mut a, &[b"\0esc-nd"]);
    let dgram = bound(SOCK_DGRAM, &a[..n]);
    if path_listener < 0 || listener < 0 || dgram < 0 {
        return fail(ME, 3, -1);
    }
    if !touch(c"/ready") {
        return fail(ME, 4, -1);
    }
    if !wait_for(c"/stop", 900) {
        return fail(ME, 5, -1);
    }

    for (i, fd) in [listener, path_listener].into_iter().enumerate() {
        let r = sys::accept4(fd, None, 0);
        if r != EAGAIN {
            return fail(ME, 10 + i as i32, r);
        }
    }
    let mut byte = [0u8; 1];
    let r = sys::recvfrom(dgram, &mut byte, 0, None);
    if r != EAGAIN {
        return fail(ME, 12, r);
    }
    let mut buf = [0u8; 64];
    let mine = sys::openat(sys::AT_FDCWD, c"/mine", sys::O_RDONLY, 0);
    let n = if mine >= 0 {
        sys::read(mine as i32, &mut buf)
    } else {
        mine
    };
    if n != 10 || &buf[..10] != b"neighbour\n" {
        return fail(ME, 13, n);
    }
    let mut status = 0;
    let r = sys::wait4(-1, &mut status, WNOHANG);
    if children > 0 && r != 0 {
        return fail(ME, 14, r);
    }
    for &kid in kids.iter().take(children) {
        let r = sys::kill(kid, SIGKILL);
        if r != 0 {
            return fail(ME, 15, r);
        }
        let mut status = 0;
        let r = sys::wait4(kid, &mut status, 0);
        if r != i64::from(kid) || status & 0x7f != SIGKILL {
            return fail(ME, 16, i64::from(status));
        }
    }
    0
}

keel_rt::main!(main);
