//! P3-T7: private file mappings, checked against Linux. Runs under Linux
//! (`host.filemap`) and on Keel (`exec.file_mappings`) and must pass on
//! both. It maps its own executable (`argv[0]`), which exists on both, and
//! compares every mapped byte with what read(2) returns.
//!
//! Semantics from mmap(2): a file mapping of a handle not open for reading
//! is EACCES; MAP_PRIVATE writes stay private ("Updates to the mapping
//! are not visible to other processes mapping the same file, and are not
//! carried through to the underlying file"); the part of the last page
//! past the end of the file is zero ("the remaining bytes in the partial
//! page at the end of the mapping are zeroed").
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_RDONLY, O_WRONLY, PROT_EXEC, PROT_READ, PROT_WRITE, Region};

/// -EACCES, -EBADF, -ENODEV, -EINVAL.
const EACCES: i64 = -13;
const EBADF: i64 = -9;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const PAGE: u64 = 4096;
/// O_DIRECTORY (Linux x86-64).
const O_DIRECTORY: u64 = 0o200000;

/// Whether `region` holds exactly `expected` from `offset` in it.
fn holds(region: &Region, offset: u64, expected: &[u8]) -> bool {
    let mut chunk = [0u8; 256];
    let mut done = 0;
    while done < expected.len() {
        let n = (expected.len() - done).min(chunk.len());
        if region.read(offset + done as u64, &mut chunk[..n]).is_none() {
            return false;
        }
        if chunk[..n] != expected[done..done + n] {
            return false;
        }
        done += n;
    }
    true
}

fn main(startup: &Startup) -> i32 {
    let Some(me) = startup.args().next() else {
        return 20;
    };
    let mut name = [0u8; 512];
    if me.len() >= name.len() {
        return 21;
    }
    name[..me.len()].copy_from_slice(me);
    let Ok(path) = core::ffi::CStr::from_bytes_until_nul(&name) else {
        return 22;
    };
    // The reference: the whole file, read with read(2).
    let Ok(whole) = sys::map_file(path) else {
        return 23;
    };
    let file = whole.bytes();
    let size = file.len() as u64;
    if size < 3 * PAGE {
        return 24;
    }
    let fd = sys::openat(AT_FDCWD, path, O_RDONLY, 0);
    if fd < 0 {
        return 25;
    }
    let fd = fd as i32;

    // 1. From offset 0: the first two pages are the file's.
    let Ok(start) = Region::map_file_private(2 * PAGE, PROT_READ, fd, 0) else {
        return 1;
    };
    if !holds(&start, 0, &file[..2 * PAGE as usize]) || !holds(&start, 0, b"\x7fELF") {
        return 2;
    }
    // 2. From a page offset: page 1 of the mapping is file page 2.
    let Ok(later) = Region::map_file_private(2 * PAGE, PROT_READ, fd, PAGE) else {
        return 3;
    };
    if !holds(&later, PAGE, &file[2 * PAGE as usize..3 * PAGE as usize]) {
        return 4;
    }
    // 3. The last, partial page: the file's bytes, then zeros.
    let last = (size - 1) / PAGE * PAGE;
    let Ok(tail) = Region::map_file_private(PAGE, PROT_READ, fd, last) else {
        return 5;
    };
    let in_file = (size - last) as usize;
    if !holds(&tail, 0, &file[last as usize..]) {
        return 6;
    }
    if in_file < PAGE as usize
        && !holds(
            &tail,
            in_file as u64,
            &[0u8; 64][..(PAGE as usize - in_file).min(64)],
        )
    {
        return 7;
    }
    // 4. Private and writable from a read-only descriptor; the write stays
    //    in this mapping, and neither the file nor another mapping sees it.
    let Ok(private) = Region::map_file_private(PAGE, PROT_READ | PROT_WRITE, fd, 0) else {
        return 8;
    };
    if private.write(0, b"PRIVATE!").is_none() || !holds(&private, 0, b"PRIVATE!") {
        return 9;
    }
    let Ok(again) = Region::map_file_private(PAGE, PROT_READ, fd, 0) else {
        return 10;
    };
    let Ok(reread) = sys::map_file(path) else {
        return 11;
    };
    if !holds(&again, 0, b"\x7fELF") || &reread.bytes()[..4] != b"\x7fELF" {
        return 12;
    }
    // 5. Splitting keeps the offsets: on a fresh mapping (nothing read
    //    yet), changing the protection of the first page splits it, and
    //    its second page, read only afterwards, is still file page 2.
    let Ok(split) = Region::map_file_private(2 * PAGE, PROT_READ, fd, PAGE) else {
        return 13;
    };
    if split.protect_range(0, PAGE, PROT_READ | PROT_EXEC) < 0 {
        return 13; // a readable regular file may be mapped executable
    }
    if !holds(&split, PAGE, &file[2 * PAGE as usize..3 * PAGE as usize]) {
        return 14;
    }
    // 6. Refusals: misaligned offset; a handle not open for reading
    //    (EACCES); a descriptor that is not open; a directory (ENODEV).
    if Region::map_file_private(PAGE, PROT_READ, fd, 1).err() != Some(EINVAL) {
        return 15;
    }
    let write_only = sys::openat(AT_FDCWD, c"/dev/null", O_WRONLY, 0);
    if write_only < 0 {
        return 16;
    }
    if Region::map_file_private(PAGE, PROT_READ, write_only as i32, 0).err() != Some(EACCES) {
        return 17;
    }
    sys::close(write_only as i32);
    if Region::map_file_private(PAGE, PROT_READ, 1000, 0).err() != Some(EBADF) {
        return 18;
    }
    let dir = sys::openat(AT_FDCWD, c"/", O_RDONLY | O_DIRECTORY, 0);
    if dir < 0 {
        return 19;
    }
    if Region::map_file_private(PAGE, PROT_READ, dir as i32, 0).err() != Some(ENODEV) {
        return 30;
    }
    // 8. pread64 reads at an offset and leaves the position alone; a
    //    negative offset is EINVAL. open(2) opens like openat.
    let opened = sys::open(path, O_RDONLY, 0);
    if opened < 0 {
        return 33;
    }
    let opened = opened as i32;
    let mut some = [0u8; 8];
    if sys::pread(opened, &mut some, 1) != 8 || some[..] != file[1..9] {
        return 34;
    }
    let mut first = [0u8; 4];
    if sys::read(opened, &mut first) != 4 || &first != b"\x7fELF" {
        return 35; // the pread did not move the position
    }
    if sys::pread(opened, &mut some, size + 100) != 0 {
        return 36; // at or past the end: 0
    }
    if sys::pread(opened, &mut some, u64::MAX) != EINVAL {
        return 37;
    }
    sys::close(opened);
    // 9. fcntl's descriptor flags: O_CLOEXEC shows as FD_CLOEXEC, F_SETFD
    //    changes it; a descriptor that is not open is EBADF, a command no
    //    kernel has is EINVAL.
    const F_GETFD: u32 = 1;
    const F_SETFD: u32 = 2;
    let cloexec = sys::open(path, O_RDONLY | sys::O_CLOEXEC, 0);
    if cloexec < 0 || sys::fcntl(cloexec as i32, F_GETFD, 0) != 1 {
        return 38;
    }
    if sys::fcntl(cloexec as i32, F_SETFD, 0) != 0 || sys::fcntl(cloexec as i32, F_GETFD, 0) != 0 {
        return 39;
    }
    if sys::fcntl(1000, F_GETFD, 0) != EBADF || sys::fcntl(cloexec as i32, 99_999, 0) != EINVAL {
        return 40;
    }
    sys::close(cloexec as i32);
    // 7. /dev/zero maps as zeroed memory.
    let zero = sys::openat(AT_FDCWD, c"/dev/zero", O_RDONLY, 0);
    let Ok(zeros) = Region::map_file_private(PAGE, PROT_READ | PROT_WRITE, zero as i32, 0) else {
        return 31;
    };
    if !holds(&zeros, 0, &[0u8; 256]) {
        return 32;
    }
    0
}

keel_rt::main!(main);
