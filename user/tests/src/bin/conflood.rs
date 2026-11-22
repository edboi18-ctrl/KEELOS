//! Audit 2, A3 regression: two 4 KiB writes to the console. The Keel
//! self-test slows the UART to a real one's speed meanwhile and checks
//! that a kernel thread keeps running, so console output never keeps
//! interrupts off for long. Also runs under Linux.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys;

fn main(_: &Startup) -> i32 {
    let mut line = [b'.'; 4096];
    line[4095] = b'\n';
    for _ in 0..2 {
        if sys::write(1, &line) != 4096 {
            return 1;
        }
    }
    0
}

keel_rt::main!(main);
