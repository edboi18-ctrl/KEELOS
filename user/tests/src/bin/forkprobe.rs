//! P3-T3: fork and wait4, checked against Linux. Runs under Linux
//! (`host.forkprobe`) and on Keel (`exec.fork_wait`) and must pass on
//! both. With the argument `bomb` (Keel only, in a compartment with a
//! process limit) it forks until refused, checks that exited but unreaped
//! children (zombies) still hold their slots and that reaping one frees
//! one, and exits with the number of children it got: security acceptance
//! P3 item 3.
//!
//! Semantics from fork(2) (the child has a copy of the parent's memory;
//! "The child inherits copies of the parent's set of open file
//! descriptors ... refer to the same open file description"), wait(2)
//! (WNOHANG; ECHILD; EINVAL for bad options) and the wait status encoding
//! (WEXITSTATUS in bits 8-15, WTERMSIG in bits 0-6).
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_RDONLY, PROT_READ, PROT_WRITE, Region};

const ECHILD: i64 = -10;
const EINVAL: i64 = -22;
const EAGAIN: i64 = -11;
const WNOHANG: u32 = 1;

/// Sleeps for about `ms` milliseconds.
fn nap(ms: i32) {
    let mut ignored = [[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]];
    sys::poll(&mut ignored, ms);
}

fn bomb() -> i32 {
    let mut children = 0;
    loop {
        match sys::fork() {
            0 => {
                nap(200);
                keel_rt::exit(0);
            }
            EAGAIN => break,
            pid if pid < 0 => return 200,
            _ => children += 1,
        }
        if children > 100 {
            return 201; // no limit
        }
    }
    // The children have exited by now, but are not reaped: as zombies
    // they still hold their slots, so another fork is still refused.
    nap(400);
    if sys::fork() != EAGAIN {
        return 203;
    }
    // Reaping one frees one slot.
    let mut status = 0;
    if sys::wait4(-1, &mut status, 0) <= 0 || status != 0 {
        return 204;
    }
    let again = sys::fork();
    if again == 0 {
        keel_rt::exit(0);
    }
    if again <= 0 || sys::wait4(again as i32, &mut status, 0) != again {
        return 205;
    }
    for _ in 1..children {
        if sys::wait4(-1, &mut status, 0) <= 0 || status != 0 {
            return 202;
        }
    }
    children
}

fn main(startup: &Startup) -> i32 {
    if startup.args().nth(1) == Some(&b"bomb"[..]) {
        return bomb();
    }
    let me = sys::getpid();
    let Ok(memory) = Region::map(4096, PROT_READ | PROT_WRITE) else {
        return 1;
    };
    if memory.write_u64(0, 1).is_none() {
        return 2;
    }
    // Refusals with no children yet.
    let mut status = 0;
    if sys::wait4(-1, &mut status, 0) != ECHILD || sys::wait4(99_999, &mut status, 0) != ECHILD {
        return 3;
    }
    if sys::wait4(-1, &mut status, 0x100) != EINVAL {
        return 4;
    }
    // A file opened before fork shares its offset with the child.
    let Some(argv0) = startup.args().next() else {
        return 5;
    };
    let mut path = [0u8; 512];
    if argv0.len() >= path.len() {
        return 6;
    }
    path[..argv0.len()].copy_from_slice(argv0);
    let Ok(path) = core::ffi::CStr::from_bytes_until_nul(&path) else {
        return 7;
    };
    let fd = sys::openat(AT_FDCWD, path, O_RDONLY, 0);
    if fd < 0 {
        return 8;
    }
    let fd = fd as i32;

    // 1. The child: fork returned 0, its parent is this process, its
    //    memory is a copy (its write does not reach the parent), it reads
    //    the first 4 bytes of the shared file, and exits 7 after a nap.
    let child = sys::fork();
    if child == 0 {
        if sys::getppid() != me || sys::getpid() == me {
            keel_rt::exit(90);
        }
        if memory.read_u64(0) != Some(1) || memory.write_u64(0, 2).is_none() {
            keel_rt::exit(91);
        }
        let mut magic = [0u8; 4];
        if sys::read(fd, &mut magic) != 4 || &magic != b"\x7fELF" {
            keel_rt::exit(92);
        }
        nap(100);
        keel_rt::exit(7);
    }
    if child <= 0 {
        return 10;
    }
    // Still running: WNOHANG finds nothing yet.
    if sys::wait4(child as i32, &mut status, WNOHANG) != 0 {
        return 11;
    }
    if sys::wait4(child as i32, &mut status, 0) != child || status != 7 << 8 {
        return 12;
    }
    if memory.read_u64(0) != Some(1) {
        return 13; // the child's write reached the parent
    }
    // The child moved the shared offset past the first 4 bytes.
    let mut next = [0u8; 4];
    if sys::pread(fd, &mut next, 4) != 4 {
        return 14;
    }
    let mut got = [0u8; 4];
    if sys::read(fd, &mut got) != 4 || got != next {
        return 15;
    }
    // Reaped: no second wait.
    if sys::wait4(child as i32, &mut status, 0) != ECHILD {
        return 16;
    }

    // 2. A child that dies of a fault reports the signal (SIGSEGV, 11).
    let crasher = sys::fork();
    if crasher == 0 {
        let Ok(none) = Region::map(4096, 0) else {
            keel_rt::exit(93);
        };
        let _ = none.read_u64(0); // faults: PROT_NONE
        keel_rt::exit(94);
    }
    if sys::wait4(crasher as i32, &mut status, 0) != crasher || status & 0x7f != 11 {
        return 20;
    }

    // 3. Twenty children, each exiting at once with its number; waited
    //    for afterwards, so each is a zombie first.
    let mut pids = [0i64; 20];
    for (i, pid) in pids.iter_mut().enumerate() {
        *pid = sys::fork();
        if *pid == 0 {
            keel_rt::exit(i as i32 + 1);
        }
        if *pid < 0 {
            return 30;
        }
    }
    nap(100);
    let mut sum = 0;
    for _ in 0..pids.len() {
        let pid = sys::wait4(-1, &mut status, 0);
        if pid <= 0 || !pids.contains(&pid) || status & 0x7f != 0 {
            return 31;
        }
        sum += status >> 8;
    }
    if sum != (1..=20).sum::<i32>() || sys::wait4(-1, &mut status, 0) != ECHILD {
        return 32;
    }
    0
}

keel_rt::main!(main);
