//! P3-T4 and P3-T5: the parts of clone, gettid, kill and futex a single
//! thread can check, against Linux. Runs under Linux (`host.threadprobe`)
//! and on Keel (`exec.thread_calls`) and must pass on both. Threads
//! themselves are tested with musl's pthreads (`exec.threads`).
//!
//! clone: CLONE_THREAD without CLONE_SIGHAND, and CLONE_SIGHAND without
//! CLONE_VM, are EINVAL (copy_process). kill: signal 0 checks existence;
//! a missing PID is ESRCH; SIGKILL ends a child, whose wait status is the
//! signal. futex: a mismatched value is EAGAIN (EWOULDBLOCK), a misaligned
//! address EINVAL, a timeout ETIMEDOUT, a wake with no waiters 0, an
//! unknown command ENOSYS, a CMP_REQUEUE whose word differs EAGAIN.
#![no_std]
#![no_main]

use core::sync::atomic::AtomicU32;

use keel_rt::Startup;
use keel_rt::sys;

const ESRCH: i64 = -3;
const EAGAIN: i64 = -11;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;
const ETIMEDOUT: i64 = -110;
const SIGKILL: i32 = 9;
const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_PRIVATE_FLAG: u32 = 128;

fn main(_: &Startup) -> i32 {
    // A process's first thread has TID = PID.
    if sys::gettid() != sys::getpid() {
        return 1;
    }
    if sys::clone_refused(0x1_0000 | 0x100) != EINVAL || sys::clone_refused(0x800) != EINVAL {
        return 2;
    }
    if sys::kill(sys::getpid() as i32, 0) != 0 || sys::kill(99_999, 0) != ESRCH {
        return 3;
    }
    // SIGKILL ends a child that would otherwise wait for ever.
    let child = sys::fork();
    if child == 0 {
        loop {
            let mut ignored = [[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]];
            sys::poll(&mut ignored, 1000);
        }
    }
    if child < 0 || sys::kill(child as i32, SIGKILL) != 0 {
        return 4;
    }
    let mut status = 0;
    if sys::wait4(child as i32, &mut status, 0) != child || status & 0x7f != SIGKILL {
        return 5;
    }
    let word = AtomicU32::new(7);
    let private = FUTEX_PRIVATE_FLAG;
    if sys::futex(&word, FUTEX_WAIT | private, 8, None) != EAGAIN {
        return 6;
    }
    if sys::futex_misaligned(&[0; 8], FUTEX_WAKE) != EINVAL {
        return 7;
    }
    if sys::futex(&word, FUTEX_WAIT | private, 7, Some(&[0, 20_000_000])) != ETIMEDOUT {
        return 8;
    }
    if sys::futex(&word, FUTEX_WAIT | private, 7, Some(&[0, 1_000_000_000])) != EINVAL {
        return 9; // nanoseconds out of range
    }
    if sys::futex(&word, FUTEX_WAKE | private, 10, None) != 0 {
        return 10;
    }
    if sys::futex(&word, 99, 0, None) != ENOSYS {
        return 11;
    }
    let other = AtomicU32::new(0);
    if sys::futex_cmp_requeue(&word, &other, 1, 1, 8) != EAGAIN
        || sys::futex_cmp_requeue(&word, &other, 1, 1, 7) != 0
    {
        return 12;
    }
    0
}

keel_rt::main!(main);
