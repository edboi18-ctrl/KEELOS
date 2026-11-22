//! Phase 1 security acceptance item 4: opening a file read-only and then
//! writing through that handle fails. Runs under Linux (EBADF) and Keel,
//! where the self-test also checks that the kernel's rights check, not a
//! bad descriptor, refused exactly the two calls marked below.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys;

const EBADF: i64 = -9;

fn main(_: &Startup) -> i32 {
    let ro = sys::openat(sys::AT_FDCWD, c"/dev/null", sys::O_RDONLY, 0) as i32;
    let wo = sys::openat(sys::AT_FDCWD, c"/dev/null", sys::O_WRONLY, 0) as i32;
    if ro < 0 || wo < 0 {
        sys::write(2, b"rights: open failed\n");
        return 1;
    }
    let mut buf = [0u8; 4];
    // Refused by the rights check (1 of 2): write needs WRITE.
    let write_ro = sys::write(ro, b"x");
    // Refused by the rights check (2 of 2): read needs READ.
    let read_wo = sys::read(wo, &mut buf);
    // A bad descriptor: refused, but not by the rights check.
    let closed = sys::write(900, b"x");
    // Allowed: the handles still work for what they grant.
    let read_ro = sys::read(ro, &mut buf);
    let write_wo = sys::write(wo, b"x");
    if write_ro == EBADF && read_wo == EBADF && closed == EBADF && read_ro == 0 && write_wo == 1 {
        sys::write(
            1,
            b"rights: read-only and write-only handles refuse the other operation\n",
        );
        0
    } else {
        sys::write(2, b"rights: unexpected result\n");
        2
    }
}

keel_rt::main!(main);
