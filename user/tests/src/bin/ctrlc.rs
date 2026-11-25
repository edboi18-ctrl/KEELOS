//! P3-T12: Ctrl-C on the serial console raises SIGINT. Keel only
//! (`console.interrupt`): it needs the console as its terminal.
//!
//! The program makes its own session, takes /dev/console (fd 0) as its
//! controlling terminal (TIOCSCTTY: opening the console never makes it
//! one, as on Linux), catches SIGINT and blocks reading the console. The
//! self-test types ^C on COM1: the read ends with EINTR and the handler
//! has run once. Exits 0, or the number of the failed step.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys;

const EINTR: i64 = -4;
const SIGINT: i32 = 2;
const TIOCSCTTY: u64 = 0x540E;
const TIOCGPGRP: u64 = 0x540F;

fn main(_: &Startup) -> i32 {
    let me = sys::setsid();
    if me <= 0 {
        return 1;
    }
    if sys::ioctl_value(0, TIOCSCTTY, 0) != 0 {
        return 2;
    }
    let mut b = [0u8; 64];
    if sys::ioctl(0, TIOCGPGRP, &mut b) != 0
        || i64::from(i32::from_le_bytes([b[0], b[1], b[2], b[3]])) != me
    {
        return 3;
    }
    if keel_rt::signal::catch(SIGINT) != 0 {
        return 4;
    }
    let mut buf = [0u8; 16];
    if sys::read(0, &mut buf) != EINTR || keel_rt::signal::caught(SIGINT) != 1 {
        return 5;
    }
    sys::write(1, b"ctrlc: SIGINT from the console\n");
    0
}

keel_rt::main!(main);
