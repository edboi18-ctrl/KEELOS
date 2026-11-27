//! P3-S3 (ADR 0041): a compartment's allowlist profile. The kernel runs
//! `profileprobe default` in a compartment with the default profile and
//! `profileprobe full` in one with the full profile. In both:
//!
//! - every never-implemented call is ENOSYS;
//! - `clone` with any namespace flag is EINVAL;
//! - sockets other than AF_UNIX are EAFNOSUPPORT;
//! - the 32-bit entry paths (`int 0x80`, `sysenter`) end the process with
//!   a signal instead of entering the kernel.
//!
//! Then what the profiles differ in: a call outside the default profile
//! (getppid, memfd_create) is ENOSYS there; an fcntl command (F_GETFD), a
//! prctl option (PR_GET_NAME) and a clone flag combination (fork's)
//! outside it are EINVAL; ioctl requests outside it (TCGETS on the
//! console, FIONREAD on a pipe) are ENOTTY. Under the full profile each
//! works. What both allow works in both (F_GETFL, PR_SET_NAME,
//! TIOCGWINSZ).
//!
//! Exit 0, or the number of the check that failed. Keel only.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys;

const ENOSYS: i64 = -38;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const EAFNOSUPPORT: i64 = -97;
const SIGILL: i32 = 4;
const SIGSEGV: i32 = 11;
const F_GETFD: u32 = 1;
const F_GETFL: u32 = 3;
const PR_SET_NAME: u64 = 15;
const PR_GET_NAME: u64 = 16;
const TCGETS: u64 = 0x5401;
const TIOCGWINSZ: u64 = 0x5413;
const FIONREAD: u64 = 0x541B;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;

/// How a forked child that runs `f` ended: its exit code, or the signal
/// (negated) that ended it.
fn in_child(f: fn()) -> i32 {
    let pid = sys::fork();
    if pid == 0 {
        f();
        keel_rt::exit(0);
    }
    if pid < 0 {
        return i32::MIN;
    }
    let mut status = 0;
    if sys::wait4(pid as i32, &mut status, 0) != pid {
        return i32::MIN;
    }
    if status & 0x7f != 0 {
        -(status & 0x7f)
    } else {
        (status >> 8) & 0xff
    }
}

/// What both profiles refuse.
fn always_refused() -> i32 {
    for &n in sys::NEVER_IMPLEMENTED {
        if sys::never_implemented(n) != ENOSYS {
            return 1;
        }
    }
    for bit in 0..31 {
        let flag = 1u64 << bit;
        if flag & sys::CLONE_NEW != 0 && sys::clone_namespace(flag) != EINVAL {
            return 2;
        }
    }
    // AF_INET, AF_INET6, AF_NETLINK, AF_PACKET.
    for family in [2, 10, 16, 17] {
        for ty in [SOCK_STREAM, SOCK_DGRAM, 3] {
            if sys::socket(family, ty, 0) != EAFNOSUPPORT {
                return 3;
            }
        }
    }
    if in_child(sys::int80) != -SIGSEGV {
        return 4;
    }
    let s = in_child(sys::sysenter);
    if s != -SIGSEGV && s != -SIGILL {
        return 5;
    }
    0
}

/// What the default profile refuses and the full one allows: Ok(true)
/// when each is refused, Ok(false) when each works, Err(check) when they
/// disagree or something else happened.
fn differing() -> Result<bool, i32> {
    let mut refused = [false; 7];
    // A call: getppid, memfd_create.
    let r = sys::getppid();
    refused[0] = match r {
        ENOSYS => true,
        r if r >= 0 => false,
        _ => return Err(10),
    };
    let r = sys::memfd_create(c"probe", 0);
    refused[1] = match r {
        ENOSYS => true,
        fd if fd >= 0 => {
            sys::close(fd as i32);
            false
        }
        _ => return Err(11),
    };
    // fcntl's F_GETFD.
    refused[2] = match sys::fcntl(1, F_GETFD, 0) {
        EINVAL => true,
        r if r >= 0 => false,
        _ => return Err(12),
    };
    // prctl's PR_GET_NAME.
    let mut name = [0u8; 16];
    refused[3] = match sys::prctl_name(PR_GET_NAME, &mut name) {
        EINVAL => true,
        0 => false,
        _ => return Err(13),
    };
    // clone with fork's flags (SIGCHLD alone).
    refused[4] = match in_child_clone() {
        Some(true) => true,
        Some(false) => false,
        None => return Err(14),
    };
    // TCGETS on the console; FIONREAD on a pipe.
    let mut buf = [0u8; 64];
    refused[5] = match sys::ioctl(1, TCGETS, &mut buf) {
        ENOTTY => true,
        0 => false,
        _ => return Err(15),
    };
    let mut fds = [0i32; 2];
    if sys::pipe2(&mut fds, None) != 0 {
        return Err(16);
    }
    refused[6] = match sys::ioctl(fds[0], FIONREAD, &mut buf) {
        ENOTTY => true,
        0 => false,
        _ => return Err(17),
    };
    sys::close(fds[0]);
    sys::close(fds[1]);
    if refused.iter().all(|r| *r) {
        Ok(true)
    } else if refused.iter().all(|r| !*r) {
        Ok(false)
    } else {
        // The first that disagrees with the first.
        Err(20 + refused.iter().position(|r| *r != refused[0]).unwrap_or(0) as i32)
    }
}

/// clone(SIGCHLD), fork by another name: Some(true) if refused with
/// EINVAL, Some(false) if a child ran and exited 0.
fn in_child_clone() -> Option<bool> {
    let pid = sys::clone_fork();
    if pid == 0 {
        keel_rt::exit(0);
    }
    if pid == EINVAL {
        return Some(true);
    }
    if pid < 0 {
        return None;
    }
    let mut status = 0;
    (sys::wait4(pid as i32, &mut status, 0) == pid && status == 0).then_some(false)
}

/// What both allow.
fn both_allow() -> i32 {
    if sys::fcntl(1, F_GETFL, 0) < 0 {
        return 30;
    }
    let mut name = *b"profileprobe\0\0\0\0";
    if sys::prctl_name(PR_SET_NAME, &mut name) != 0 {
        return 31;
    }
    let mut buf = [0u8; 64];
    if sys::ioctl(1, TIOCGWINSZ, &mut buf) != 0 {
        return 32;
    }
    0
}

fn main(startup: &Startup) -> i32 {
    let expect_refused = match startup.args().nth(1) {
        Some(b"default") => true,
        Some(b"full") => false,
        _ => return 90,
    };
    let r = always_refused();
    if r != 0 {
        return r;
    }
    match differing() {
        Ok(refused) if refused == expect_refused => {}
        Ok(_) => return 40,
        Err(check) => return check,
    }
    both_allow()
}

keel_rt::main!(main);
