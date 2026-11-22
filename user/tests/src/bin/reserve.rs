//! Phase 1 acceptance item 4: reserve 64 GiB with
//! mmap(PROT_NONE, MAP_NORESERVE). Must succeed, on Linux and on Keel, and
//! cost no physical memory (the Keel self-test measures that from the
//! address space this program leaves behind).
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, Region};

/// 64 GiB.
const SIZE: u64 = 64 << 30;

fn main(_: &Startup) -> i32 {
    match Region::map_with(SIZE, 0, sys::MAP_NORESERVE) {
        Ok(region) => {
            // Touching it must fault, so do not; just report and keep it.
            let _ = region.address();
            sys::write(1, b"reserve: 64 GiB PROT_NONE reservation succeeded\n");
            0
        }
        Err(_) => {
            sys::write(2, b"reserve: mmap of 64 GiB failed\n");
            1
        }
    }
}

keel_rt::main!(main);
