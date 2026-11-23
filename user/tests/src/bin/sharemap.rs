//! Shared file mappings (MAP_SHARED, ADR 0021) and ftruncate, checked
//! against Linux. Runs under Linux (`host.sharemap`) and on Keel
//! (`exec.shared_mappings`) and must pass on both. It is how wineserver
//! shares memory with its clients: a file in /tmp, sized with ftruncate,
//! mapped MAP_SHARED by more than one process.
//!
//! Semantics from mmap(2): MAP_SHARED "Updates to the mapping are visible
//! to other processes mapping the same region, and (in the case of
//! file-backed mappings) are carried through to the underlying file";
//! EACCES "MAP_SHARED was requested and PROT_WRITE is set, but fd is not
//! open in read/write (O_RDWR) mode"; mprotect(2) EACCES for "a file
//! opened read-only" mapped MAP_SHARED and made writable; fork(2): the
//! child inherits memory mappings, and a shared one stays shared.
//! ftruncate(2): EINVAL for a negative length or "fd does not reference a
//! regular file or a POSIX shared memory object" or is "not open for
//! writing"; when a file grows, "the extended part reads as null bytes".
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{
    self, AT_FDCWD, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, PROT_READ, PROT_WRITE, Region,
};

const EACCES: i64 = -13;
const EINVAL: i64 = -22;
const PAGE: u64 = 4096;

fn byte(region: &Region, offset: u64) -> Option<u8> {
    let mut b = [0u8; 1];
    region.read(offset, &mut b)?;
    Some(b[0])
}

fn holds(region: &Region, offset: u64, expected: &[u8]) -> bool {
    let mut buf = [0u8; 64];
    let buf = &mut buf[..expected.len()];
    region.read(offset, buf).is_some() && buf == expected
}

/// pread(2) of `expected.len()` bytes at `offset` gives exactly them.
fn file_holds(fd: i32, offset: u64, expected: &[u8]) -> bool {
    let mut buf = [0u8; 64];
    let buf = &mut buf[..expected.len()];
    sys::pread(fd, buf, offset) == expected.len() as i64 && buf == expected
}

/// Writes `data` at `offset` with write(2), through a fresh descriptor (so
/// the offset is the file's start plus a read to move it).
fn write_at(path: &core::ffi::CStr, offset: u64, data: &[u8]) -> bool {
    let fd = sys::openat(AT_FDCWD, path, O_RDWR, 0);
    if fd < 0 {
        return false;
    }
    let fd = fd as i32;
    let mut skip = [0u8; 512];
    let mut left = offset;
    while left > 0 {
        let n = left.min(skip.len() as u64) as usize;
        if sys::read(fd, &mut skip[..n]) != n as i64 {
            return false;
        }
        left -= n as u64;
    }
    let ok = sys::write(fd, data) == data.len() as i64;
    sys::close(fd);
    ok
}

fn main(_startup: &Startup) -> i32 {
    // A name of our own in /tmp: the PID's digits.
    let mut name = *b"/tmp/keel-sharemap-0000000000\0";
    let mut pid = sys::getpid() as u64;
    for at in (19..29).rev() {
        name[at] = b'0' + (pid % 10) as u8;
        pid /= 10;
    }
    let Ok(path) = core::ffi::CStr::from_bytes_with_nul(&name) else {
        return 90;
    };
    let fd = sys::openat(AT_FDCWD, path, O_RDWR | O_CREAT | O_EXCL, 0o600);
    if fd < 0 {
        return 91;
    }
    let fd = fd as i32;
    let status = checks(path, fd);
    sys::close(fd);
    if sys::unlink(path) != 0 && status == 0 {
        return 92;
    }
    status
}

fn checks(path: &core::ffi::CStr, fd: i32) -> i32 {
    // 1. ftruncate sizes the file (three pages and 100 bytes); its
    //    refusals are Linux's.
    let size = 3 * PAGE + 100;
    if sys::ftruncate(fd, size as i64) != 0 {
        return 1;
    }
    if sys::ftruncate(fd, -1) != EINVAL {
        return 2;
    }
    let read_only = sys::openat(AT_FDCWD, path, O_RDONLY, 0);
    if read_only < 0 {
        return 3;
    }
    let read_only = read_only as i32;
    if sys::ftruncate(read_only, 0) != EINVAL {
        return 4;
    }

    // 2. Stores through a shared mapping reach the file (read(2) sees
    //    them), and write(2) reaches the mapping.
    let Ok(shared) = Region::map_file_shared(4 * PAGE, PROT_READ | PROT_WRITE, fd, 0) else {
        return 5;
    };
    if shared.write(0, b"KEEL").is_none() || shared.write(2 * PAGE + 8, b"page2").is_none() {
        return 6;
    }
    if !file_holds(fd, 0, b"KEEL") || !file_holds(fd, 2 * PAGE + 8, b"page2") {
        return 7;
    }
    // Page 1 is read through the mapping first, so it is mapped when the
    // write comes: the write must reach the page already mapped, not
    // only a page read afresh from the file.
    if byte(&shared, PAGE + 16) != Some(0)
        || !write_at(path, PAGE + 16, b"written")
        || !holds(&shared, PAGE + 16, b"written")
    {
        return 8;
    }

    // 3. Two mappings of the same page in one process alias.
    let Ok(second) = Region::map_file_shared(PAGE, PROT_READ | PROT_WRITE, fd, PAGE) else {
        return 9;
    };
    if second.write(40, b"alias").is_none() || !holds(&shared, PAGE + 40, b"alias") {
        return 10;
    }

    // 4. A private mapping first read after those stores sees them; its
    //    own stores stay private.
    let Ok(private) = Region::map_file_private(PAGE, PROT_READ | PROT_WRITE, fd, 0) else {
        return 11;
    };
    if !holds(&private, 0, b"KEEL") {
        return 12;
    }
    if private.write(0, b"MINE").is_none()
        || !holds(&shared, 0, b"KEEL")
        || !file_holds(fd, 0, b"KEEL")
    {
        return 13;
    }

    // 5. fork: the child's stores through the inherited shared mapping
    //    are seen by the parent, and the child sees the parent's.
    if shared.write(200, b"parent").is_none() {
        return 14;
    }
    let child = sys::fork();
    if child == 0 {
        let ok = holds(&shared, 200, b"parent") && shared.write(100, b"child").is_some();
        keel_rt::exit(if ok { 0 } else { 1 });
    }
    if child < 0 {
        return 15;
    }
    let mut status = 0;
    if sys::wait4(child as i32, &mut status, 0) != child || status != 0 {
        return 16;
    }
    if !holds(&shared, 100, b"child") || !file_holds(fd, 100, b"child") {
        return 17;
    }

    // 6. A read-only descriptor: shared and writable is EACCES, at mmap
    //    and at mprotect; shared read-only and private writable are fine.
    if Region::map_file_shared(PAGE, PROT_READ | PROT_WRITE, read_only, 0).err() != Some(EACCES) {
        return 18;
    }
    let Ok(viewer) = Region::map_file_shared(PAGE, PROT_READ, read_only, 0) else {
        return 19;
    };
    if !holds(&viewer, 0, b"KEEL") {
        return 20;
    }
    if viewer.protect(PROT_READ | PROT_WRITE) != EACCES {
        return 21;
    }
    if Region::map_file_private(PAGE, PROT_READ | PROT_WRITE, read_only, 0).is_err() {
        return 22;
    }
    // A shared mapping that was made read-only can be made writable again
    // (its descriptor allows it), and its stores still reach the file.
    if second.protect(PROT_READ) != 0 || second.protect(PROT_READ | PROT_WRITE) != 0 {
        return 23;
    }
    if second.write(48, b"again").is_none() || !file_holds(fd, PAGE + 48, b"again") {
        return 24;
    }

    // 7. Shrinking cuts the page that holds the new end: grown back, the
    //    bytes past the old cut read as zero, in the file and through the
    //    mapping of that page.
    if shared.write(PAGE + 300, b"gone").is_none() {
        return 25;
    }
    if sys::ftruncate(fd, (PAGE + 200) as i64) != 0 || sys::ftruncate(fd, size as i64) != 0 {
        return 26;
    }
    if !file_holds(fd, PAGE + 300, &[0; 4]) || byte(&shared, PAGE + 300) != Some(0) {
        return 27;
    }
    if !holds(&shared, PAGE + 16, b"written") {
        return 28; // below the cut: kept
    }

    sys::close(read_only);

    // 8. A mapping keeps its file alive (mmap(2): "closing the file
    //    descriptor does not unmap the region"): with its descriptor
    //    closed and its name gone, pages first touched afterwards still
    //    hold the file's bytes, private and shared alike.
    let name = *b"/tmp/keel-sharemap-kept\0";
    let Ok(kept) = core::ffi::CStr::from_bytes_until_nul(&name) else {
        return 29;
    };
    let fd2 = sys::openat(AT_FDCWD, kept, O_RDWR | O_CREAT | O_EXCL, 0o600);
    if fd2 < 0
        || sys::ftruncate(fd2 as i32, (2 * PAGE) as i64) != 0
        || !write_at(kept, PAGE + 5, b"kept")
    {
        return 29;
    }
    let private = Region::map_file_private(2 * PAGE, PROT_READ, fd2 as i32, 0);
    let shared2 = Region::map_file_shared(2 * PAGE, PROT_READ, fd2 as i32, 0);
    sys::close(fd2 as i32);
    if sys::unlink(kept) != 0 {
        return 30;
    }
    let (Ok(private), Ok(shared2)) = (private, shared2) else {
        return 30;
    };
    if !holds(&private, PAGE + 5, b"kept") || !holds(&shared2, PAGE + 5, b"kept") {
        return 31;
    }
    sys::write(1, b"sharemap: 31 checks passed\n");
    0
}

keel_rt::main!(main);
