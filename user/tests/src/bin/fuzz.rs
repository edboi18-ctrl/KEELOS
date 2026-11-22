//! The in-guest system-call fuzzer (Phase 1 security acceptance item 6):
//! `fuzz <seed> <calls>` makes that many random system calls
//! (`keel_rt::fuzz`) and exits 0. Keel only: it refuses to run without
//! `/etc/keel-release`, so it never fires random calls at a Linux host.
//! Not in the host test list for the same reason.
#![no_std]
#![no_main]

use keel_rt::Startup;

fn number(text: Option<&[u8]>) -> Option<u64> {
    let text = text?;
    if text.is_empty() {
        return None;
    }
    text.iter().try_fold(0u64, |n, &c| {
        c.is_ascii_digit()
            .then(|| n.checked_mul(10)?.checked_add(u64::from(c - b'0')))
            .flatten()
    })
}

fn main(startup: &Startup) -> i32 {
    let seed = number(startup.args().nth(1));
    let calls = number(startup.args().nth(2));
    let (Some(seed), Some(calls)) = (seed, calls) else {
        keel_rt::sys::write(2, b"usage: fuzz <seed> <calls>\n");
        return 2;
    };
    match keel_rt::fuzz::run(seed, calls, startup.initial_sp) {
        Some(_) => 0,
        None => {
            keel_rt::sys::write(2, b"fuzz: not on Keel (no /etc/keel-release); refusing\n");
            3
        }
    }
}

keel_rt::main!(main);
