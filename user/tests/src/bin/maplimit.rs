//! F-0011 regression (audit 2, A1 and A2): map single pages until mmap
//! fails. It must fail with ENOMEM at the map-count cap, and the kernel
//! must keep running.
//!
//! - `hint` (default): PROT_NONE pages at spaced hint addresses, the
//!   audit's proof of concept, which panicked the kernel before the cap.
//! - `null`: mmap(NULL, ...) with alternating rights, so no two mappings
//!   merge and every call is a new mapping placed below the last one. The
//!   Keel self-test runs a timing thread meanwhile (A2).
//!
//! Also runs under Linux, whose `vm.max_map_count` gives the same ENOMEM.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys;

/// -ENOMEM.
const ENOMEM: i64 = -12;
/// Fewer than this many mappings before ENOMEM means the cap is wrong
/// (Keel's is 65530, less the few this program starts with).
const AT_LEAST: u64 = 65_000;
/// A safety stop, far above any sane cap.
const AT_MOST: u64 = 4_000_000;

fn main(startup: &Startup) -> i32 {
    let null = startup.args().nth(1) == Some(b"null".as_slice());
    let mut count: u64 = 0;
    let mut hint: u64 = 0x1000_0000_0000;
    loop {
        let result = if null {
            let prot = if count.is_multiple_of(2) {
                sys::PROT_READ
            } else {
                0
            };
            sys::mmap_keep(0, 4096, prot)
        } else {
            sys::mmap_keep(hint, 4096, 0)
        };
        if result < 0 {
            sys::write_number(b"maplimit: ", count, b" mappings, then an error\n");
            return if result == ENOMEM && count >= AT_LEAST {
                0
            } else {
                1
            };
        }
        count += 1;
        hint += 8192;
        if count >= AT_MOST {
            sys::write(1, b"maplimit: no limit reached\n");
            return 2;
        }
    }
}

keel_rt::main!(main);
