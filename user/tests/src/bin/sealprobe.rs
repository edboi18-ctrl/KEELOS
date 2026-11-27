//! P3-S7 (ADR 0044): memfd sealing, as Linux does it. Runs under Linux
//! (the conformance reference) and on Keel, and must print the same.
//!
//! The rules come from Linux v6.12 `mm/memfd.c` and `mm/shmem.c`, and
//! each was checked on a Linux 6.18 host before Keel implemented it:
//! - a memfd made without MFD_ALLOW_SEALING has F_SEAL_SEAL, so nothing
//!   can be added (EPERM); with it, none;
//! - F_ADD_SEALS needs a descriptor open for writing (EPERM), takes only
//!   defined bits (EINVAL), and stops once F_SEAL_SEAL is set (EPERM, even
//!   for no bits); seals add up; only tmpfs files have them (EINVAL for a
//!   pipe or a directory);
//! - F_SEAL_SHRINK refuses a truncation down and F_SEAL_GROW one up
//!   (EPERM), a truncation to the same size being fine;
//! - under F_SEAL_GROW a write is cut at the last page boundary at or
//!   below the size, and is EPERM if that is not past its start; an
//!   O_APPEND write is EPERM.
//!
//! Prints one line per check and "sealprobe: N checks passed"; exits with
//! the failing check's number.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_CREAT, O_RDONLY, O_RDWR};

const EPERM: i64 = -1;
const EINVAL: i64 = -22;
const F_SETFL: u32 = 4;
const O_APPEND: u64 = 0o2000;
const O_DIRECTORY: u64 = 0o200000;
const F_ADD_SEALS: u32 = 1033;
const F_GET_SEALS: u32 = 1034;
const SEAL: u64 = 1;
const SHRINK: u64 = 2;
const GROW: u64 = 4;
const MFD_ALLOW_SEALING: u64 = 2;

struct Checks(u32);

impl Checks {
    fn expect(&mut self, what: &[u8], got: i64, want: i64) -> Result<(), i32> {
        self.0 += 1;
        if got == want {
            sys::writev(1, &[b"ok ", what, b"\n"]);
            Ok(())
        } else {
            sys::write_number(b"FAIL ", u64::from(self.0), b"");
            sys::writev(1, &[b" ", what, b"\n"]);
            sys::write_number(b"  got ", got as u64, b"\n");
            Err(self.0 as i32)
        }
    }
}

fn add(fd: i32, seals: u64) -> i64 {
    sys::fcntl(fd, F_ADD_SEALS, seals)
}

fn get(fd: i32) -> i64 {
    sys::fcntl(fd, F_GET_SEALS, 0)
}

fn run(c: &mut Checks) -> Result<(), i32> {
    // Without MFD_ALLOW_SEALING: sealed against sealing.
    let plain = sys::memfd_create(c"plain", 0) as i32;
    c.expect(
        b"a memfd without MFD_ALLOW_SEALING has F_SEAL_SEAL",
        get(plain),
        SEAL as i64,
    )?;
    c.expect(b"so a seal cannot be added", add(plain, SHRINK), EPERM)?;
    c.expect(b"nor no seal", add(plain, 0), EPERM)?;

    // With it: none, and the rules of adding.
    let m = sys::memfd_create(c"sealed", MFD_ALLOW_SEALING) as i32;
    c.expect(b"with MFD_ALLOW_SEALING, no seals", get(m), 0)?;
    c.expect(b"adding no seal", add(m, 0), 0)?;
    c.expect(b"an undefined bit is EINVAL", add(m, 0x40), EINVAL)?;
    c.expect(b"the seals unchanged", get(m), 0)?;
    c.expect(b"room for 8192 bytes", sys::ftruncate(m, 8192), 0)?;
    c.expect(b"F_SEAL_SHRINK", add(m, SHRINK), 0)?;
    c.expect(b"truncating down is EPERM", sys::ftruncate(m, 4096), EPERM)?;
    c.expect(b"to the same size is fine", sys::ftruncate(m, 8192), 0)?;
    c.expect(b"growing is fine", sys::ftruncate(m, 12288), 0)?;
    c.expect(b"F_SEAL_GROW and F_SEAL_SEAL", add(m, GROW | SEAL), 0)?;
    c.expect(b"the seals add up", get(m), (SHRINK | GROW | SEAL) as i64)?;
    c.expect(b"growing is EPERM", sys::ftruncate(m, 12289), EPERM)?;
    c.expect(b"no more seals", add(m, 0), EPERM)?;

    // Writes under F_SEAL_GROW, on a 6000-byte file.
    let g = sys::memfd_create(c"grow", MFD_ALLOW_SEALING) as i32;
    let data = [0x5au8; 8000];
    sys::ftruncate(g, 6000);
    c.expect(b"F_SEAL_GROW on 6000 bytes", add(g, GROW), 0)?;
    c.expect(
        b"a write inside the file",
        sys::pwrite(g, &data[..2000], 3000),
        2000,
    )?;
    c.expect(
        b"a write across the end stops at the page boundary",
        sys::pwrite(g, &data[..4000], 3000),
        1096,
    )?;
    c.expect(b"from 0, it stops at 4096", sys::pwrite(g, &data, 0), 4096)?;
    c.expect(
        b"one with no boundary past its start is EPERM",
        sys::pwrite(g, &data[..2000], 5000),
        EPERM,
    )?;
    c.expect(
        b"at the end, EPERM",
        sys::pwrite(g, &data[..10], 6000),
        EPERM,
    )?;
    c.expect(
        b"writing nothing past the end",
        sys::pwrite(g, &[], 9000),
        0,
    )?;
    c.expect(b"O_APPEND", sys::fcntl(g, F_SETFL, O_RDWR | O_APPEND), 0)?;
    c.expect(
        b"an appending write is EPERM",
        sys::write(g, &data[..1]),
        EPERM,
    )?;
    let mut st = [0u8; 144];
    sys::fstat(g, &mut st);
    let size = i64::from_le_bytes(st[48..56].try_into().unwrap_or([0; 8]));
    c.expect(b"the size still 6000", size, 6000)?;

    // Only tmpfs files, and only through a writable descriptor.
    let mut fds = [0i32; 2];
    sys::pipe2(&mut fds, None);
    c.expect(b"a pipe has no seals", get(fds[0]), EINVAL)?;
    c.expect(
        b"nor can its write end take one",
        add(fds[1], SHRINK),
        EINVAL,
    )?;
    let dir = sys::openat(AT_FDCWD, c"/", O_RDONLY | O_DIRECTORY, 0) as i32;
    c.expect(b"nor a directory", get(dir), EINVAL)?;
    let mut name = *b"/tmp/keel-sealprobe-0000000000\0";
    let mut pid = sys::getpid() as u64;
    for d in name[20..30].iter_mut().rev() {
        *d = b'0' + (pid % 10) as u8;
        pid /= 10;
    }
    let path = core::ffi::CStr::from_bytes_until_nul(&name).unwrap_or(c"");
    let made = sys::openat(AT_FDCWD, path, O_RDWR | O_CREAT, 0o600);
    let ro = sys::openat(AT_FDCWD, path, O_RDONLY, 0) as i32;
    if made < 0 || ro < 0 {
        return Err(99);
    }
    c.expect(
        b"a read-only descriptor cannot add a seal",
        add(ro, SHRINK),
        EPERM,
    )?;
    sys::unlink(path);
    Ok(())
}

fn main(_: &Startup) -> i32 {
    let mut c = Checks(0);
    match run(&mut c) {
        Ok(()) => {
            sys::write_number(b"sealprobe: ", u64::from(c.0), b" checks passed\n");
            0
        }
        Err(n) => n,
    }
}

keel_rt::main!(main);
