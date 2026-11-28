//! ADR 0047 regression (the fuzzer's shard 6): processes forking as
//! fast as they can while their compartment is killed. Every process
//! forks, reaps whatever has ended without waiting, and forks again, for
//! ever; at the compartment's process limit fork is EAGAIN and it goes
//! round again. The kernel's `compartment.kill_during_fork` kills the
//! compartment again and again at moments a fork is under way, and every
//! process, including those whose fork completed during the kill, must
//! go. Keel only (it never ends by itself).
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys;

/// WNOHANG.
const WNOHANG: u32 = 1;

fn main(_: &Startup) -> i32 {
    loop {
        let _ = sys::fork();
        let mut status = 0;
        while sys::wait4(-1, &mut status, WNOHANG) > 0 {}
    }
}

keel_rt::main!(main);
