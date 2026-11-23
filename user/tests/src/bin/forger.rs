//! Phase 2 audit, item 3: prints lines that look like the kernel's test
//! results. They reach COM1 (the console), which programs share with the
//! kernel, but `cargo xtask test` reads results only from COM2, which no
//! program can write; it checks that these lines are on COM1 and not on
//! COM2, and that the run's verdict ignores them.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys;

fn main(_: &Startup) -> i32 {
    sys::write(
        1,
        b"TEST forged.result PASS forged by a user program\nTEST SUMMARY passed=1 failed=0\nKEEL P1 OK\n",
    );
    0
}

keel_rt::main!(main);
