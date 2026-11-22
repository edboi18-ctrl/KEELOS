//! F-0011 regression (audit 2, A1): create empty files until openat
//! fails. It must fail with ENOSPC at the tmpfs node cap, and the kernel
//! must keep running. Keel only: under Linux it would fill a real disk.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_CREAT, O_EXCL, O_WRONLY};

/// -ENOSPC.
const ENOSPC: i64 = -28;
/// A safety stop, far above the cap the self-test sets.
const AT_MOST: u32 = 1_000_000;

fn main(_: &Startup) -> i32 {
    // "/flood-" + up to 10 digits + NUL.
    let mut path = *b"/flood-0000000000\0";
    for n in 0..AT_MOST {
        let mut rest = n;
        for digit in path[7..17].iter_mut().rev() {
            *digit = b'0' + (rest % 10) as u8;
            rest /= 10;
        }
        let Ok(name) = core::ffi::CStr::from_bytes_with_nul(&path) else {
            return 3;
        };
        let fd = sys::openat(AT_FDCWD, name, O_WRONLY | O_CREAT | O_EXCL, 0o644);
        if fd < 0 {
            sys::write_number(b"fileflood: ", u64::from(n), b" files, then an error\n");
            return if fd == ENOSPC && n > 0 { 0 } else { 1 };
        }
        sys::close(fd as i32);
    }
    sys::write(1, b"fileflood: no limit reached\n");
    2
}

keel_rt::main!(main);
