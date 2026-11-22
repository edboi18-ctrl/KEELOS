//! One long system call: getrandom into a 128 MiB mapping. The Keel
//! self-test `sched.syscall_preemptible` checks that a kernel thread keeps
//! running meanwhile (F-0008). Also runs under Linux.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, Region};

const SIZE: u64 = 128 << 20;

fn main(_: &Startup) -> i32 {
    let Ok(region) = Region::map(SIZE, sys::PROT_READ | sys::PROT_WRITE) else {
        sys::write(2, b"longcall: mmap failed\n");
        return 1;
    };
    let filled = region.getrandom(SIZE);
    let _ = region.unmap();
    if filled == SIZE as i64 {
        0
    } else {
        sys::write(2, b"longcall: getrandom came up short\n");
        2
    }
}

keel_rt::main!(main);
