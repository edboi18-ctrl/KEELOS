//! P3-S4: touches every page of an anonymous mapping of the number of MiB
//! in its first argument (default 64), then exits 0. In a compartment with
//! a smaller memory limit the kernel cannot back a page past the limit,
//! and the program is ended by the fault before it gets there. The mapping
//! is at a fixed address, `BASE`, so the kernel's test can tell from the
//! fault address how many pages were touched first.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{PROT_READ, PROT_WRITE, Region};

/// Where the pages are touched: 1 TiB, far from the image, stack and mmap
/// area. The kernel's test (`compartment.memory_limit`) uses the same value.
const BASE: u64 = 1 << 40;

fn main(startup: &Startup) -> i32 {
    let mut mib: u64 = 0;
    for &c in startup.args().nth(1).unwrap_or(b"64") {
        if !c.is_ascii_digit() {
            return 2;
        }
        mib = mib.saturating_mul(10).saturating_add(u64::from(c - b'0'));
    }
    let Ok(region) = Region::map_at(BASE, mib << 20, PROT_READ | PROT_WRITE) else {
        return 3;
    };
    let mut offset = 0;
    while offset < region.length() {
        if region.write_u64(offset, offset).is_none() {
            return 4;
        }
        offset += 4096;
    }
    0
}

keel_rt::main!(main);
