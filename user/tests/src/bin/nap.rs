//! Stays alive for the number of milliseconds in its first argument, with
//! poll(2) on one entry whose fd is -1 (ignored, poll(2): "If this field is
//! negative, then the corresponding events field is ignored"), then exits
//! 0. Lets the kernel's tests hold a
//! process slot (P3-S4).
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys;

fn main(startup: &Startup) -> i32 {
    let mut ms: i32 = 0;
    for &c in startup.args().nth(1).unwrap_or(b"0") {
        if !c.is_ascii_digit() {
            return 2;
        }
        ms = ms.saturating_mul(10).saturating_add(i32::from(c - b'0'));
    }
    // struct pollfd { int fd = -1; short events = 0; short revents; }
    let mut ignored = [[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]];
    if sys::poll(&mut ignored, ms) == 0 {
        0
    } else {
        1
    }
}

keel_rt::main!(main);
