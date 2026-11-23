//! P3-S4: a compartment's tmpfs quota. Run as `tmpquota BYTES NODES` in a
//! compartment with those tmpfs limits, whose root holds an empty file
//! `/given` that the kernel made (so it has no owner). Checks, in order:
//! growing `/given` stops with ENOSPC at exactly BYTES (the kernel's file
//! is charged to this compartment), creating files stops with ENOSPC at
//! exactly NODES, and truncating gives the bytes back. Keel only.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_CREAT, O_WRONLY};

/// -ENOSPC.
const ENOSPC: i64 = -28;
/// O_TRUNC (Linux x86-64).
const O_TRUNC: u64 = 0o1000;
const CHUNK: usize = 4096;

fn number(text: &[u8]) -> Option<u64> {
    let mut n: u64 = 0;
    for &c in text {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
    }
    (!text.is_empty()).then_some(n)
}

fn main(startup: &Startup) -> i32 {
    let mut args = startup.args().skip(1);
    let (Some(bytes), Some(nodes)) = (args.next().and_then(number), args.next().and_then(number))
    else {
        return 20;
    };
    let data = [0x5au8; CHUNK];

    // Bytes: grow the kernel's file chunk by chunk. Stop one chunk past
    // the limit if nothing refuses, so a missing check fails quickly.
    let fd = sys::openat(AT_FDCWD, c"/given", O_WRONLY, 0);
    if fd < 0 {
        return 1;
    }
    let fd = fd as i32;
    let mut total: u64 = 0;
    let refusal = loop {
        let n = sys::write(fd, &data);
        if n < 0 {
            break n;
        }
        total += n as u64;
        if total > bytes {
            return 2;
        }
    };
    if refusal != ENOSPC || total != bytes {
        return 3;
    }
    sys::close(fd);

    // Nodes: create files until refused, at most one past the limit.
    let mut name = *b"/f0000000\0";
    let mut created: u64 = 0;
    let refusal = loop {
        let mut n = created;
        for digit in name[2..9].iter_mut().rev() {
            *digit = b'0' + (n % 10) as u8;
            n /= 10;
        }
        let path = CStr::from_bytes_until_nul(&name).unwrap_or(c"");
        let fd = sys::openat(AT_FDCWD, path, O_WRONLY | O_CREAT, 0o644);
        if fd < 0 {
            break fd;
        }
        sys::close(fd as i32);
        created += 1;
        if created > nodes {
            return 4;
        }
    };
    if refusal != ENOSPC || created != nodes {
        return 5;
    }

    // Truncating gives the bytes back: a chunk fits again.
    let fd = sys::openat(AT_FDCWD, c"/given", O_WRONLY | O_TRUNC, 0);
    if fd < 0 {
        return 6;
    }
    if sys::write(fd as i32, &data) != CHUNK as i64 {
        return 7;
    }
    sys::close(fd as i32);
    0
}

keel_rt::main!(main);
