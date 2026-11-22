//! Conformance test for the first system calls (P1-T13) and the
//! hostile-pointer sweep (Phase 1 security acceptance item 2). Runs on
//! Linux and on Keel; every check gives the same result on both, except
//! the few marked Keel-only, where Keel is deliberately stricter than
//! Linux (W+X mappings, unknown flags: SR-10, SR-12).
//!
//! Exits 0 when every check passes, otherwise with the number of the
//! first failure (and a line on stderr).
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, Hostile, Region};

const EFAULT: i64 = -14;
const EBADF: i64 = -9;
const ENOENT: i64 = -2;
const EINVAL: i64 = -22;
const EEXIST: i64 = -17;
const EPERM: i64 = -1;
const EACCES: i64 = -13;
const ENOTTY: i64 = -25;
const ENOSYS: i64 = -38;
const ENOMEM: i64 = -12;
const CLOCK_MONOTONIC: u64 = 1;
const TIOCGWINSZ: u64 = 0x5413;
const TCGETS: u64 = 0x5401;
const S_IFMT: u32 = 0o170000;
const S_IFCHR: u32 = 0o020000;
const S_IFREG: u32 = 0o100000;

/// Addresses no program can own: null, the null page, the first kernel
/// address, the last page, a non-canonical address, the top of the user
/// half itself, and the very last byte of the address space.
const HOSTILE: [u64; 7] = [
    0,
    0x1000,
    0xffff_8000_0000_0000,
    0xffff_ffff_ffff_f000,
    0x8000_0000_0000_0000,
    0x0000_7fff_ffff_f000,
    u64::MAX,
];

struct Checks {
    number: i32,
    failed: Option<i32>,
}

impl Checks {
    fn check(&mut self, name: &str, ok: bool) {
        self.number += 1;
        if !ok && self.failed.is_none() {
            self.failed = Some(self.number);
            sys::write(2, b"syscalls: check failed: ");
            sys::write(2, name.as_bytes());
            sys::write(2, b"\n");
        }
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(word)
}

fn hostile() -> impl Iterator<Item = Hostile> {
    HOSTILE.iter().filter_map(|&a| Hostile::new(a))
}

/// The hostile addresses without 0, for arguments where NULL means "none"
/// (signal calls) rather than a bad pointer.
fn hostile_nonnull() -> impl Iterator<Item = Hostile> {
    hostile().filter(|h| h.address() != 0)
}

fn main(startup: &Startup) -> i32 {
    // The file the Keel-only checks create; argv[1] overrides it, so a
    // second run in the same boot can use a fresh name.
    let mut name_buf = [0u8; 64];
    let default_name: &[u8] = b"/syscalls-test-file";
    let name = startup.args().nth(1).unwrap_or(default_name);
    let len = name.len().min(name_buf.len() - 1);
    name_buf[..len].copy_from_slice(&name[..len]);
    let test_file =
        core::ffi::CStr::from_bytes_until_nul(&name_buf).unwrap_or(c"/syscalls-test-file");

    let mut c = Checks {
        number: 0,
        failed: None,
    };
    let keel = sys::openat(sys::AT_FDCWD, c"/etc/keel-release", sys::O_RDONLY, 0) >= 0;

    // write, writev.
    let hello = b"syscalls: write works\n";
    c.check(
        "write returns its length",
        sys::write(1, hello) == hello.len() as i64,
    );
    c.check(
        "writev returns the total",
        sys::writev(1, &[b"syscalls: ", b"writev ", b"works\n"]) == 23,
    );
    c.check(
        "write to a closed fd is EBADF",
        sys::write(99, b"x") == EBADF,
    );
    c.check("write to fd -1 is EBADF", sys::write(-1, b"x") == EBADF);

    // openat, read, close on devices.
    let null = sys::openat(sys::AT_FDCWD, c"/dev/null", sys::O_RDONLY, 0) as i32;
    c.check("open /dev/null", null >= 3);
    let mut buf = [0xAAu8; 64];
    c.check(
        "read /dev/null is end of file",
        sys::read(null, &mut buf) == 0,
    );
    c.check(
        "write to a read-only fd is EBADF",
        sys::write(null, b"x") == EBADF,
    );
    let zero = sys::openat(sys::AT_FDCWD, c"/dev/zero", sys::O_RDWR, 0) as i32;
    c.check(
        "read /dev/zero gives zeros",
        zero >= 3 && sys::read(zero, &mut buf) == 64 && buf == [0; 64],
    );
    c.check(
        "missing file is ENOENT",
        sys::openat(sys::AT_FDCWD, c"/no/such/file", sys::O_RDONLY, 0) == ENOENT,
    );

    // fstat.
    let mut st = [0u8; 144];
    c.check("fstat /dev/null", sys::fstat(null, &mut st) == 0);
    c.check(
        "/dev/null is char device 1:3",
        u32_at(&st, 24) & S_IFMT == S_IFCHR && u64_at(&st, 40) == 0x103,
    );
    c.check("close", sys::close(null) == 0);
    c.check("close twice is EBADF", sys::close(null) == EBADF);

    // Hostile-pointer sweep: every pointer argument, every bad address.
    for h in hostile() {
        c.check(
            "write from a bad pointer is EFAULT",
            sys::write_from(1, h, 8) == EFAULT,
        );
        c.check(
            "read into a bad pointer is EFAULT",
            sys::read_into(zero, h, 8) == EFAULT,
        );
        c.check(
            "writev with a bad iovec array is EFAULT",
            sys::writev_from(1, h, 1) == EFAULT,
        );
        c.check(
            "writev with a bad base is EFAULT",
            sys::writev_hostile_base(1, h, 8) == EFAULT,
        );
        c.check(
            "openat with a bad path is EFAULT",
            sys::openat_from(h, sys::O_RDONLY) == EFAULT,
        );
        c.check(
            "fstat into a bad pointer is EFAULT",
            sys::fstat_into(zero, h) == EFAULT,
        );
        c.check(
            "clock_gettime into a bad pointer is EFAULT",
            sys::clock_gettime_into(CLOCK_MONOTONIC, h) == EFAULT,
        );
        c.check(
            "getrandom into a bad pointer is EFAULT",
            sys::getrandom_into(h, 8) == EFAULT,
        );
        c.check(
            "arch_prctl(ARCH_GET_FS) into a bad pointer is EFAULT",
            sys::arch_prctl_get_into(sys::ARCH_GET_FS, h) == EFAULT,
        );
    }
    c.check(
        "arch_prctl(ARCH_SET_FS) to a kernel address is EPERM",
        Hostile::new(0xffff_8000_0000_0000).is_some_and(|h| sys::arch_prctl_set_fs(h) == EPERM),
    );

    // mmap, mprotect, munmap.
    match Region::map(64 * 1024, sys::PROT_READ | sys::PROT_WRITE) {
        Ok(region) => {
            c.check(
                "kernel writes into an anonymous mapping",
                region.read_from(zero, 0, 64 * 1024) == 64 * 1024,
            );
            c.check("and reads from it", region.write_to(1, 0, 0) == 0);
            c.check("mprotect read-only", region.protect(sys::PROT_READ) == 0);
            c.check(
                "a read-only mapping refuses kernel writes (EFAULT)",
                region.read_from(zero, 0, 16) == EFAULT,
            );
            // F-0002: memory made PROT_NONE after it was touched must not
            // stay readable. Written to fd 1, which really reads the bytes
            // (Linux's /dev/null and /dev/zero discard writes unread).
            c.check("mprotect PROT_NONE", region.protect(0) == 0);
            c.check(
                "a PROT_NONE mapping refuses kernel reads (EFAULT)",
                region.write_to(1, 0, 16) == EFAULT,
            );
            c.check(
                "mprotect back to read/write",
                region.protect(sys::PROT_READ | sys::PROT_WRITE) == 0,
            );
            c.check(
                "the mapping is usable again",
                region.read_from(zero, 0, 16) == 16,
            );
            let (unmapped, gone) = region.unmap();
            c.check("munmap", unmapped == 0);
            c.check(
                "an unmapped range is EFAULT",
                gone.read_into(zero, 16) == EFAULT,
            );
        }
        Err(_) => c.check("mmap anonymous read/write", false),
    }
    c.check(
        "mmap of length 0 is EINVAL",
        sys::mmap_raw(0, sys::PROT_READ, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1) == EINVAL,
    );
    if keel {
        c.check(
            "Keel only: writable+executable mmap is EACCES (SR-12)",
            sys::mmap_raw(
                4096,
                sys::PROT_READ | sys::PROT_WRITE | sys::PROT_EXEC,
                sys::MAP_PRIVATE | sys::MAP_ANONYMOUS,
                -1,
            ) == EACCES,
        );
        c.check(
            "Keel only: unknown mmap flag (MAP_32BIT) is EINVAL (SR-10)",
            sys::mmap_raw(
                4096,
                sys::PROT_READ,
                0x40 | sys::MAP_PRIVATE | sys::MAP_ANONYMOUS,
                -1,
            ) == EINVAL,
        );
        c.check(
            "Keel only: unknown open flag is EINVAL (SR-10)",
            sys::openat(sys::AT_FDCWD, c"/dev/null", 0o10, 0) == EINVAL,
        );
        // PROT_SEM (0x8) means nothing on x86 and is not accepted.
        if let Ok(region) = Region::map(4096, sys::PROT_READ) {
            c.check(
                "Keel only: unknown mprotect bit is EINVAL (SR-10)",
                region.protect(sys::PROT_READ | 0x8) == EINVAL,
            );
            let _ = region.unmap();
        }
    }
    // Unknown arch_prctl codes fail on both (Linux checks the code first).
    c.check(
        "unknown arch_prctl code is EINVAL",
        Hostile::new(0).is_some_and(|h| sys::arch_prctl_get_into(0x9999, h) == EINVAL),
    );

    // brk.
    let start = sys::brk(0);
    let grown = sys::brk(start + 64 * 1024);
    c.check("brk grows", grown == start + 64 * 1024);
    c.check(
        "the new heap is usable",
        sys::read_into_heap(zero, start, start + 64 * 1024) == 64 * 1024,
    );
    c.check("brk shrinks", sys::brk(start) == start);
    c.check(
        "brk into the kernel half is refused",
        sys::brk(0xffff_8000_0000_0000) == start,
    );

    // arch_prctl FS round trip.
    let marker = 0x0123_4567_89AB_CDEFu64;
    c.check(
        "FS base round trip",
        sys::fs_base_round_trip(&marker) == (0, marker),
    );

    // set_tid_address, clock_gettime, getrandom.
    let mut tid_slot = 0u32;
    c.check(
        "set_tid_address returns the TID",
        sys::set_tid_address(&mut tid_slot) > 0,
    );
    let mut t1 = [0u8; 16];
    let mut t2 = [0u8; 16];
    let ok = sys::clock_gettime(CLOCK_MONOTONIC, &mut t1) == 0
        && sys::clock_gettime(CLOCK_MONOTONIC, &mut t2) == 0;
    let nanos = |t: &[u8; 16]| u64_at(t, 0) * 1_000_000_000 + u64_at(t, 8);
    c.check(
        "CLOCK_MONOTONIC does not go backwards",
        ok && nanos(&t2) >= nanos(&t1) && u64_at(&t1, 8) < 1_000_000_000,
    );
    c.check(
        "unknown clock is EINVAL",
        sys::clock_gettime(1000, &mut t1) == EINVAL,
    );
    let mut r1 = [0u8; 32];
    let mut r2 = [0u8; 32];
    c.check(
        "getrandom fills, twice differently",
        sys::getrandom(&mut r1, 0) == 32 && sys::getrandom(&mut r2, 0) == 32 && r1 != r2,
    );
    c.check(
        "getrandom unknown flag is EINVAL",
        sys::getrandom(&mut r1, 0x8) == EINVAL,
    );
    c.check(
        "getrandom RANDOM|INSECURE is EINVAL",
        sys::getrandom(&mut r1, 0x2 | 0x4) == EINVAL,
    );

    // ioctl.
    let mut io = [0u8; 64];
    let zero_tty = sys::ioctl(zero, TCGETS, &mut io);
    c.check("TCGETS on /dev/zero is ENOTTY", zero_tty == ENOTTY);
    if keel {
        // On Linux the harness captures stdout in a pipe, so these differ.
        c.check(
            "Keel only: stdout is a terminal with a size",
            sys::ioctl(1, TIOCGWINSZ, &mut io) == 0 && u16::from_le_bytes([io[0], io[1]]) > 0,
        );
        c.check(
            "Keel only: unknown terminal ioctl is ENOTTY",
            sys::ioctl(1, 0x5499, &mut io) == ENOTTY,
        );
        // Files: create, write, stat, exclusive create, read back.
        let f = sys::openat(
            sys::AT_FDCWD,
            test_file,
            sys::O_CREAT | sys::O_EXCL | sys::O_RDWR,
            0o644,
        ) as i32;
        c.check("Keel only: O_CREAT|O_EXCL creates", f >= 3);
        c.check(
            "Keel only: write to the new file",
            sys::write(f, b"abc") == 3,
        );
        let mut fst = [0u8; 144];
        c.check(
            "Keel only: fstat sees a 3-byte regular file",
            sys::fstat(f, &mut fst) == 0
                && u32_at(&fst, 24) & S_IFMT == S_IFREG
                && u64_at(&fst, 48) == 3,
        );
        c.check(
            "Keel only: O_EXCL on an existing file is EEXIST",
            sys::openat(
                sys::AT_FDCWD,
                test_file,
                sys::O_CREAT | sys::O_EXCL | sys::O_RDWR,
                0o644,
            ) == EEXIST,
        );
        let g = sys::openat(sys::AT_FDCWD, test_file, sys::O_RDONLY, 0) as i32;
        let mut back = [0u8; 8];
        c.check(
            "Keel only: read back what was written",
            g >= 3 && sys::read(g, &mut back) == 3 && &back[..3] == b"abc",
        );
    }

    poll_checks(&mut c, keel);
    signal_checks(&mut c);

    // Unknown system calls fail closed.
    c.check(
        "unassigned syscall 500 is ENOSYS",
        sys::unassigned_syscall(500) == ENOSYS,
    );
    // Keel's temporary Phase 1 test call is gone (and was never Linux's).
    c.check(
        "former test call 0x1000 is ENOSYS",
        sys::unassigned_syscall(0x1000) == ENOSYS,
    );

    match c.failed {
        None => {
            sys::write(1, b"syscalls: all checks passed\n");
            0
        }
        Some(n) => n,
    }
}

const POLLIN: u16 = 0x1;
const POLLOUT: u16 = 0x4;
const POLLNVAL: u16 = 0x20;

fn pollfd(fd: i32, events: u16) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&fd.to_le_bytes());
    b[4..6].copy_from_slice(&events.to_le_bytes());
    // revents starts as garbage: poll must overwrite it.
    b[6..8].copy_from_slice(&0xffffu16.to_le_bytes());
    b
}

fn revents(b: &[u8; 8]) -> u16 {
    u16::from_le_bytes([b[6], b[7]])
}

/// poll(2), against Linux v6.12 fs/select.c.
fn poll_checks(c: &mut Checks, keel: bool) {
    // Standard output with no events (Rust std's startup probe): nothing
    // reported. A negative fd is skipped; a closed one is POLLNVAL.
    let mut fds = [pollfd(1, 0), pollfd(-1, POLLIN), pollfd(900, 0)];
    let n = sys::poll(&mut fds, 0);
    c.check(
        "poll: open fd with no events, negative fd, closed fd",
        n == 1 && revents(&fds[0]) == 0 && revents(&fds[1]) == 0 && revents(&fds[2]) == POLLNVAL,
    );
    let null = sys::openat(sys::AT_FDCWD, c"/dev/null", sys::O_RDWR, 0) as i32;
    let mut fds = [pollfd(null, POLLIN | POLLOUT)];
    c.check(
        "poll: /dev/null read/write is readable and writable",
        sys::poll(&mut fds, 0) == 1 && revents(&fds[0]) == POLLIN | POLLOUT,
    );
    sys::close(null);
    if keel {
        // SR-1: readiness only for what the handle may do (Linux reports
        // POLLOUT here too).
        let ro = sys::openat(sys::AT_FDCWD, c"/dev/null", sys::O_RDONLY, 0) as i32;
        let mut fds = [pollfd(ro, POLLIN | POLLOUT)];
        c.check(
            "Keel only: poll on a read-only handle reports no POLLOUT (SR-1)",
            sys::poll(&mut fds, 0) == 1 && revents(&fds[0]) == POLLIN,
        );
        sys::close(ro);
        c.check(
            "Keel only: poll of more fds than the handle limit is EINVAL",
            Hostile::new(0).is_some_and(|h| sys::poll_from(h, 1025) == EINVAL),
        );
    }
    // Nothing ready: the timeout passes (20 ms), and 0 is returned.
    let mut t1 = [0u8; 16];
    let mut t2 = [0u8; 16];
    let mut fds = [pollfd(-1, POLLIN)];
    let ok = sys::clock_gettime(CLOCK_MONOTONIC, &mut t1) == 0
        && sys::poll(&mut fds, 20) == 0
        && sys::clock_gettime(CLOCK_MONOTONIC, &mut t2) == 0;
    let nanos = |t: &[u8; 16]| u64_at(t, 0) * 1_000_000_000 + u64_at(t, 8);
    c.check(
        "poll: times out after at least the timeout",
        ok && nanos(&t2) - nanos(&t1) >= 20_000_000,
    );
    c.check(
        "poll: unreadable array is EFAULT",
        hostile().all(|h| sys::poll_from(h, 1) == EFAULT),
    );
    // A read-only array can be read but revents cannot be written back.
    if let Ok(region) = Region::map(4096, sys::PROT_READ) {
        c.check("poll: read-only array is EFAULT", region.poll(1) == EFAULT);
        let _ = region.unmap();
    }
}

const SIGKILL: i32 = 9;
const SIGUSR1: i32 = 10;
const SIGUSR2: i32 = 12;
const SIGSTOP: i32 = 19;
const SIG_IGN: u64 = 1;
const SA_RESTORER: u64 = 0x0400_0000;
const SA_UNSUPPORTED: u64 = 0x400;
const SS_DISABLE: u32 = 2;
const UNBLOCKABLE: u64 = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));

fn sigaction_bytes(handler: u64, flags: u64, mask: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..8].copy_from_slice(&handler.to_le_bytes());
    b[8..16].copy_from_slice(&flags.to_le_bytes());
    b[24..32].copy_from_slice(&mask.to_le_bytes());
    b
}

fn stack_bytes(sp: u64, flags: u32, size: u64) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[0..8].copy_from_slice(&sp.to_le_bytes());
    b[8..12].copy_from_slice(&flags.to_le_bytes());
    b[16..24].copy_from_slice(&size.to_le_bytes());
    b
}

/// rt_sigaction, rt_sigprocmask, sigaltstack, against Linux v6.12
/// kernel/signal.c. Only the recorded state is checked: Keel delivers no
/// signals before P3-T6. Every change is undone.
fn signal_checks(c: &mut Checks) {
    use sys::{Arg, Out};
    let mut old = [0u8; 32];
    let ignore = sigaction_bytes(SIG_IGN, SA_RESTORER | SA_UNSUPPORTED, u64::MAX);
    c.check(
        "rt_sigaction: sigsetsize other than 8 is EINVAL",
        sys::rt_sigaction(SIGUSR1, Arg::Null, Out::Buf(&mut old), 4) == EINVAL,
    );
    c.check(
        "rt_sigaction: signals 0 and 65 are EINVAL",
        sys::rt_sigaction(0, Arg::Null, Out::Buf(&mut old), 8) == EINVAL
            && sys::rt_sigaction(65, Arg::Null, Out::Buf(&mut old), 8) == EINVAL,
    );
    c.check(
        "rt_sigaction: SIGKILL/SIGSTOP can be read but not set",
        sys::rt_sigaction(SIGKILL, Arg::Null, Out::Buf(&mut old), 8) == 0
            && sys::rt_sigaction(SIGKILL, Arg::Buf(&ignore), Out::Null, 8) == EINVAL
            && sys::rt_sigaction(SIGSTOP, Arg::Buf(&ignore), Out::Null, 8) == EINVAL,
    );
    let mut original = [0u8; 32];
    let mut back = [0u8; 32];
    let set = sys::rt_sigaction(SIGUSR1, Arg::Buf(&ignore), Out::Buf(&mut original), 8);
    let read = sys::rt_sigaction(SIGUSR1, Arg::Null, Out::Buf(&mut back), 8);
    c.check(
        "rt_sigaction: set and read back, unknown flags and SIGKILL/SIGSTOP mask bits cleared",
        set == 0
            && read == 0
            && u64_at(&back, 0) == SIG_IGN
            && u64_at(&back, 8) == SA_RESTORER
            && u64_at(&back, 24) == !UNBLOCKABLE,
    );
    c.check(
        "rt_sigaction: unreadable act is EFAULT",
        hostile_nonnull()
            .all(|h| sys::rt_sigaction(SIGUSR2, Arg::Hostile(h), Out::Null, 8) == EFAULT),
    );
    // The new action is set before the old one is written out.
    let marker = sigaction_bytes(0x1234_5000, SA_RESTORER, 0);
    let mut seen = [0u8; 32];
    let mut first = [0u8; 32];
    let saved = sys::rt_sigaction(SIGUSR2, Arg::Null, Out::Buf(&mut first), 8) == 0;
    c.check(
        "rt_sigaction: unwritable oldact is EFAULT after the change",
        saved
            && hostile_nonnull().all(|h| {
                sys::rt_sigaction(SIGUSR2, Arg::Buf(&marker), Out::Hostile(h), 8) == EFAULT
            })
            && sys::rt_sigaction(SIGUSR2, Arg::Null, Out::Buf(&mut seen), 8) == 0
            && u64_at(&seen, 0) == 0x1234_5000,
    );
    sys::rt_sigaction(SIGUSR2, Arg::Buf(&first), Out::Null, 8);
    sys::rt_sigaction(SIGUSR1, Arg::Buf(&original), Out::Null, 8);

    // rt_sigprocmask.
    let mut mask = 0u64;
    let all = u64::MAX;
    c.check(
        "rt_sigprocmask: sigsetsize other than 8 is EINVAL",
        sys::rt_sigprocmask(0, Arg::Null, Out::Buf(&mut mask), 16) == EINVAL,
    );
    let mut before = 0u64;
    let mut blocked = 0u64;
    let ok = sys::rt_sigprocmask(0, Arg::Buf(&all), Out::Buf(&mut before), 8) == 0
        && sys::rt_sigprocmask(0, Arg::Null, Out::Buf(&mut blocked), 8) == 0;
    c.check(
        "rt_sigprocmask: SIG_BLOCK of everything leaves SIGKILL/SIGSTOP unblocked",
        ok && blocked == !UNBLOCKABLE,
    );
    let usr1 = 1u64 << (SIGUSR1 - 1);
    let ok = sys::rt_sigprocmask(1, Arg::Buf(&usr1), Out::Null, 8) == 0
        && sys::rt_sigprocmask(0, Arg::Null, Out::Buf(&mut blocked), 8) == 0;
    c.check(
        "rt_sigprocmask: SIG_UNBLOCK",
        ok && blocked == !UNBLOCKABLE & !usr1,
    );
    c.check(
        "rt_sigprocmask: bad how is EINVAL with a set, ignored without",
        sys::rt_sigprocmask(7, Arg::Buf(&all), Out::Null, 8) == EINVAL
            && sys::rt_sigprocmask(7, Arg::Null, Out::Null, 8) == 0,
    );
    c.check(
        "rt_sigprocmask: unreadable set is EFAULT",
        hostile_nonnull().all(|h| sys::rt_sigprocmask(0, Arg::Hostile(h), Out::Null, 8) == EFAULT),
    );
    let ok = sys::rt_sigprocmask(2, Arg::Buf(&before), Out::Null, 8) == 0
        && sys::rt_sigprocmask(0, Arg::Null, Out::Buf(&mut blocked), 8) == 0;
    c.check(
        "rt_sigprocmask: SIG_SETMASK restores",
        ok && blocked == before,
    );

    // sigaltstack.
    let mut st = [0u8; 24];
    c.check(
        "sigaltstack: none at start (SS_DISABLE, size 0)",
        sys::sigaltstack(Arg::Null, Out::Buf(&mut st)) == 0
            && u32_at(&st, 8) == SS_DISABLE
            && u64_at(&st, 16) == 0,
    );
    if let Ok(region) = Region::map(16384, sys::PROT_READ | sys::PROT_WRITE) {
        let base = region.address();
        c.check(
            "sigaltstack: below MINSIGSTKSZ (2048) is ENOMEM",
            sys::sigaltstack(Arg::Buf(&stack_bytes(base, 0, 2047)), Out::Null) == ENOMEM,
        );
        c.check(
            "sigaltstack: unknown mode is EINVAL",
            sys::sigaltstack(Arg::Buf(&stack_bytes(base, 4, 16384)), Out::Null) == EINVAL,
        );
        let ok = sys::sigaltstack(Arg::Buf(&stack_bytes(base, 0, 16384)), Out::Null) == 0
            && sys::sigaltstack(Arg::Null, Out::Buf(&mut st)) == 0;
        c.check(
            "sigaltstack: set and read back",
            ok && st == stack_bytes(base, 0, 16384),
        );
        let ok = sys::sigaltstack(Arg::Buf(&stack_bytes(base, SS_DISABLE, 99)), Out::Null) == 0
            && sys::sigaltstack(Arg::Null, Out::Buf(&mut st)) == 0;
        c.check(
            "sigaltstack: SS_DISABLE clears pointer and size",
            ok && st == stack_bytes(0, SS_DISABLE, 0),
        );
        let _ = region.unmap();
    }
    c.check(
        "sigaltstack: unreadable ss is EFAULT",
        hostile_nonnull().all(|h| sys::sigaltstack(Arg::Hostile(h), Out::Null) == EFAULT),
    );
    c.check(
        "sigaltstack: unwritable old_ss is EFAULT",
        hostile_nonnull().all(|h| sys::sigaltstack(Arg::Null, Out::Hostile(h)) == EFAULT),
    );
}

keel_rt::main!(main);
