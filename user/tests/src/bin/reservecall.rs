//! F-0011 regression (audit 2, A1): opens /dev/null in a loop until the
//! kernel refuses with ENOMEM. The Keel self-test makes only the kernel's
//! frame reserve free while this runs, so every call that could make the
//! kernel allocate must be refused rather than take those frames. Gives
//! up after 10 seconds. Keel only.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_RDONLY};

/// -ENOMEM.
const ENOMEM: i64 = -12;
/// CLOCK_MONOTONIC.
const MONOTONIC: u64 = 1;

fn seconds() -> u64 {
    let mut ts = [0u8; 16];
    sys::clock_gettime(MONOTONIC, &mut ts);
    u64::from_le_bytes(ts[..8].try_into().unwrap_or([0; 8]))
}

fn main(_: &Startup) -> i32 {
    let start = seconds();
    while seconds() < start + 10 {
        let fd = sys::openat(AT_FDCWD, c"/dev/null", O_RDONLY, 0);
        if fd == ENOMEM {
            return 0;
        }
        if fd >= 0 {
            sys::close(fd as i32);
        }
    }
    1
}

keel_rt::main!(main);
