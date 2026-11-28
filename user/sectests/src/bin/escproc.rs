//! Escape suite: other compartments' processes and sockets, and handles
//! it was never given (ADR 0047). Run as `escproc TOP` while
//! `escneighbour` runs in another compartment with PIDs up to TOP in its
//! own numbering, holding a socket file `/sock` and the abstract names
//! `\0esc-n` (stream) and `\0esc-nd` (datagram).
//!
//! - 1-19: signalling, waiting on and inspecting every PID from 1 to TOP
//!   but its own (a PID names a process only in its own compartment, ADR
//!   0014, and it is alone in its own): ESRCH or ECHILD for each, and
//!   ESRCH for kill(-1). Its parent is outside, so getppid is 0.
//! - 20-39: the neighbour's files and sockets: its path by every route
//!   ENOENT, its abstract names ECONNREFUSED; the same abstract names
//!   are free in this compartment's own namespace.
//! - 40-59: guessing handle numbers: every descriptor but 0, 1 and 2 is
//!   EBADF, and so is every native call (ADR 0040) on every number,
//!   since it holds no factory, compartment or audit handle.
//!
//! The neighbour checks afterwards that none of it reached it. Exit 0,
//! or the number of the check that failed.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD};
use keel_sectests::{
    EBADF, ECHILD, ECONNREFUSED, ENOENT, ENOSYS, EPERM, ESRCH, SIGKILL, SIGTERM, SOCK_DGRAM,
    SOCK_STREAM, bound, connect_to, fail, number, open_result, path, send_to, sun,
};

const ME: &[u8] = b"escproc";
const F_GETFD: u32 = 1;

fn main(startup: &Startup) -> i32 {
    let Some(top) = startup.args().nth(1).and_then(number) else {
        return 90;
    };
    if !(2..4096).contains(&top) {
        return 91;
    }
    let top = top as i32;
    // PIDs go on counting in a compartment, so this program, run after
    // others, is not PID 1. Every other number up to TOP names nothing
    // here, whatever it names in the neighbour.
    let me = sys::getpid() as i32;
    if me < 1 || me >= top {
        return fail(ME, 1, i64::from(me));
    }

    // 1-19: PIDs.
    for pid in (1..=top).filter(|&pid| pid != me) {
        let mut status = 0;
        let results = [
            sys::kill(pid, 0),
            sys::kill(pid, SIGTERM),
            sys::kill(pid, SIGKILL),
            sys::kill(-pid, 0),
            sys::kill(-pid, SIGKILL),
            sys::tgkill(pid, pid, 0),
            sys::tgkill(pid, pid, SIGKILL),
            sys::getpgid(pid),
            sys::getsid(pid),
            sys::setpgid(pid, 0),
        ];
        for (i, r) in results.into_iter().enumerate() {
            if r != ESRCH {
                return fail(ME, 2 + i as i32, i64::from(pid) << 16 | -r);
            }
        }
        let r = sys::wait4(pid, &mut status, 0);
        if r != ECHILD {
            return fail(ME, 12, i64::from(pid) << 16 | -r);
        }
    }
    // Every process of the compartment but PID 1 and the caller: none.
    let r = sys::kill(-1, SIGTERM);
    if r != ESRCH {
        return fail(ME, 13, r);
    }
    let mut status = 0;
    let r = sys::wait4(-1, &mut status, 0);
    if r != ECHILD {
        return fail(ME, 14, r);
    }
    // Joining another process group by number: none exists here (EPERM,
    // as setpgid(2): "no process with a matching process group ID in the
    // same session").
    let r = sys::setpgid(0, top + 1);
    if r != EPERM {
        return fail(ME, 15, r);
    }
    // Its parent is outside the compartment: 0, as for a process whose
    // parent is in another PID namespace.
    let r = sys::getppid();
    if r != 0 {
        return fail(ME, 16, r);
    }
    // Its own child, by contrast, is there to signal and reap.
    let child = sys::fork();
    if child == 0 {
        loop {
            keel_sectests::sleep_ms(1000);
        }
    }
    let child = child as i32;
    if child <= me || sys::kill(child, 0) != 0 || sys::kill(child, SIGKILL) != 0 {
        return fail(ME, 17, i64::from(child));
    }
    if sys::wait4(child, &mut status, 0) != i64::from(child) || status & 0x7f != SIGKILL {
        return fail(ME, 18, i64::from(status));
    }

    // 20-39: the neighbour's files and sockets.
    let mut b = [0u8; 256];
    let files: [&[&[u8]]; 6] = [
        &[b"/mine"],
        &[b"/../escn/mine"],
        &[b"../escn/mine"],
        &[b"/../../comp/escn/mine"],
        &[b"/comp/escn/mine"],
        &[b"/proc/2/../../../escn/mine"],
    ];
    for (i, route) in files.iter().enumerate() {
        let r = open_result(path(&mut b, route));
        if r != ENOENT {
            return fail(ME, 20 + i as i32, r);
        }
    }
    let mut a = [0u8; 110];
    let paths: [&[u8]; 5] = [
        b"/sock",
        b"/../escn/sock",
        b"../escn/sock",
        b"/../../comp/escn/sock",
        b"/comp/escn/sock",
    ];
    for (i, p) in paths.iter().enumerate() {
        let n = sun(&mut a, &[p]);
        let r = connect_to(&a[..n]);
        if r != ENOENT {
            return fail(ME, 26 + i as i32, r);
        }
    }
    let n = sun(&mut a, &[b"\0esc-n"]);
    let r = connect_to(&a[..n]);
    if r != ECONNREFUSED {
        return fail(ME, 31, r);
    }
    let n = sun(&mut a, &[b"\0esc-nd"]);
    let r = send_to(&a[..n]);
    if r != ECONNREFUSED {
        return fail(ME, 32, r);
    }
    // The same names here are this compartment's own: free to bind, and
    // then they answer.
    let n = sun(&mut a, &[b"\0esc-n"]);
    let mine = bound(SOCK_STREAM, &a[..n]);
    if mine < 0 || connect_to(&a[..n]) != 0 {
        return fail(ME, 33, i64::from(mine));
    }
    let n = sun(&mut a, &[b"\0esc-nd"]);
    let mine_d = bound(SOCK_DGRAM, &a[..n]);
    if mine_d < 0 || send_to(&a[..n]) != 1 {
        return fail(ME, 34, i64::from(mine_d));
    }
    // A socket file of its own at `/sock`, then: connect reaches it, not
    // the neighbour's.
    let n = sun(&mut a, &[b"/sock"]);
    let own_path = bound(SOCK_STREAM, &a[..n]);
    if own_path < 0 || connect_to(&a[..n]) != 0 {
        return fail(ME, 35, i64::from(own_path));
    }
    for fd in [mine, mine_d, own_path] {
        sys::close(fd);
    }
    let _ = sys::unlinkat(AT_FDCWD, c"/sock", 0);

    // 40-59: handle numbers. Only 0, 1 and 2 were given.
    for fd in (3..1100).chain([-1, -100, 1 << 20, i32::MAX, i32::MIN]) {
        let r = sys::fcntl(fd, F_GETFD, 0);
        if r != EBADF {
            return fail(ME, 40, i64::from(fd) << 16 | -r);
        }
    }
    // Every native call that takes a handle, on every number up to 1100
    // and on 0, 1 and 2 (files, not factories or compartments). restrict
    // (native 0) only narrows a handle the caller has, so it is left out.
    for fd in (0..1100u64).chain([u32::MAX as u64, 1 << 31]) {
        let calls = [
            sys::native_raw(1, fd, 0, 0),              // factory_derive
            sys::native_raw(2, fd, 0, 0),              // compartment_create
            sys::native_raw(3, fd, 1, 0),              // compartment_grant_device
            sys::native_raw(4, fd, 0, 0),              // compartment_spawn
            sys::native_raw(5, fd, SIGKILL as u64, 0), // compartment_kill
            sys::native_raw(6, fd, 0, 0),              // compartment_wait
            sys::native_raw(7, fd, 0, 0),              // audit_open
            sys::native_raw(8, fd, 0, 0),              // layer
        ];
        for (i, r) in calls.into_iter().enumerate() {
            if r != EBADF {
                return fail(ME, 41 + i as i32, (fd as i64) << 16 | -r);
            }
        }
    }
    // A native call that does not exist.
    let r = sys::native_raw(9, 0, 0, 0);
    if r != ENOSYS {
        return fail(ME, 49, r);
    }
    0
}

keel_rt::main!(main);
