//! Audit 2, A6 regression: a directory handle confines lookups made
//! through it. `..` stops at the directory the handle names, as with
//! Linux's openat2(RESOLVE_IN_ROOT), so a handle to /test cannot reach
//! /etc. Keel only: plain Linux openat lets `..` climb (ADR 0012).
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_CREAT, O_EXCL, O_RDONLY, O_WRONLY};

/// O_DIRECTORY (Linux x86-64).
const O_DIRECTORY: u64 = 0o200000;
/// -ENOENT.
const ENOENT: i64 = -2;

fn main(_: &Startup) -> i32 {
    let dir = sys::openat(AT_FDCWD, c"/test", O_RDONLY | O_DIRECTORY, 0);
    if dir < 0 {
        return 10;
    }
    let dir = dir as i32;
    // /etc/keel-release exists, but `..` from /test stays at /test.
    if sys::openat(dir, c"../etc/keel-release", O_RDONLY, 0) != ENOENT {
        return 1;
    }
    // Clamped, `../startup` is /test/startup.
    let startup = sys::openat(dir, c"../startup", O_RDONLY, 0);
    if startup < 0 {
        return 2;
    }
    sys::close(startup as i32);
    // Creating through the handle lands beneath it.
    let made = sys::openat(dir, c"made-here", O_WRONLY | O_CREAT | O_EXCL, 0o644);
    if made < 0 {
        return 3;
    }
    sys::close(made as i32);
    let check = sys::openat(AT_FDCWD, c"/test/made-here", O_RDONLY, 0);
    if check < 0 {
        return 4;
    }
    sys::close(check as i32);
    0
}

keel_rt::main!(main);
