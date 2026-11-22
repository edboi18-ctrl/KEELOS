//! Reads standard input the way a shell does (P1-T14): one line, then end
//! of file. Runs on Linux (stdin piped from xtask) and on Keel (keystrokes
//! typed through the i8042 by the self-test). Expects exactly "keel\n" and
//! then EOF; exits 0, or the number of the failed step.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys;

fn main(_: &Startup) -> i32 {
    let mut buf = [0u8; 64];
    let n = sys::read(0, &mut buf);
    if n != 5 || &buf[..5] != b"keel\n" {
        sys::write(2, b"readline: did not get \"keel\\n\"\n");
        return 1;
    }
    if sys::read(0, &mut buf) != 0 {
        sys::write(2, b"readline: expected end of file\n");
        return 2;
    }
    sys::write(1, b"readline: got a line and end of file\n");
    0
}

keel_rt::main!(main);
