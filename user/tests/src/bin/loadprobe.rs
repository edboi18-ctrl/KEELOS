//! P3-S4, security acceptance P3 item 3 (ADR 0042): a fork bomb and a
//! memory hog in one compartment leave another responsive. Keel only.
//!
//! - `loadprobe bomb`, in compartment A: forks until the process limit
//!   refuses (EAGAIN), every child spinning in user mode for good; then
//!   touches 64 MiB of fresh memory page by page until the memory limit
//!   ends it with a fault. Exit 7 if it ever finishes; 8 if no fork was
//!   refused.
//! - `loadprobe respond MS`, in compartment B, at the same time: 50
//!   sleeps of 5 ms, and 10 forks each waited for. Prints the worst
//!   lateness of a sleep and the slowest fork and wait, in microseconds,
//!   and exits 0 if both are at most MS milliseconds (1 and 2 otherwise).
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, MAP_NORESERVE, PROT_READ, PROT_WRITE, Region};

const EAGAIN: i64 = -11;
const CLOCK_MONOTONIC: u64 = 1;
const PAGE: u64 = 4096;

fn now_us() -> u64 {
    let mut ts = [0u8; 16];
    sys::clock_gettime(CLOCK_MONOTONIC, &mut ts);
    let s = u64::from_le_bytes(ts[..8].try_into().unwrap_or([0; 8]));
    let ns = u64::from_le_bytes(ts[8..].try_into().unwrap_or([0; 8]));
    s * 1_000_000 + ns / 1000
}

fn sleep_ms(ms: u64) {
    let mut req = [0u8; 16];
    req[8..].copy_from_slice(&(ms * 1_000_000).to_le_bytes());
    sys::nanosleep(&req, None);
}

fn number(text: &[u8]) -> Option<u64> {
    let mut n: u64 = 0;
    for &c in text {
        n = n
            .checked_mul(10)?
            .checked_add(u64::from(c.checked_sub(b'0').filter(|d| *d < 10)?))?;
    }
    (!text.is_empty()).then_some(n)
}

fn bomb() -> i32 {
    let refused = loop {
        let pid = sys::fork();
        if pid == 0 {
            // A CPU hog: never blocks, never makes a call.
            loop {
                core::hint::spin_loop();
            }
        }
        if pid < 0 {
            break pid;
        }
    };
    if refused != EAGAIN {
        return 8;
    }
    // The memory hog: each page touched is a frame charged.
    let Ok(region) = Region::map_with(64 << 20, PROT_READ | PROT_WRITE, MAP_NORESERVE) else {
        return 9;
    };
    let mut at = 0;
    while at < region.length() {
        region.write_u64(at, at);
        at += PAGE;
    }
    7
}

fn respond(limit_ms: u64) -> i32 {
    let mut late = 0;
    for _ in 0..50 {
        let start = now_us();
        sleep_ms(5);
        late = late.max((now_us() - start).saturating_sub(5000));
    }
    let mut fork_wait = 0;
    for _ in 0..10 {
        let start = now_us();
        let pid = sys::fork();
        if pid == 0 {
            keel_rt::exit(0);
        }
        let mut status = 0;
        if pid < 0 || sys::wait4(pid as i32, &mut status, 0) != pid || status != 0 {
            return 3;
        }
        fork_wait = fork_wait.max(now_us() - start);
    }
    sys::write_number(b"respond: sleep lateness at most ", late, b" us");
    sys::write_number(b"; fork and wait at most ", fork_wait, b" us\n");
    if late > limit_ms * 1000 {
        1
    } else if fork_wait > limit_ms * 1000 {
        2
    } else {
        0
    }
}

fn main(startup: &Startup) -> i32 {
    let mut args = startup.args().skip(1);
    match (args.next(), args.next().and_then(number)) {
        (Some(b"bomb"), None) => bomb(),
        (Some(b"respond"), Some(ms)) => respond(ms),
        _ => 90,
    }
}

keel_rt::main!(main);
