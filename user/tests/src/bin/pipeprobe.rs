//! P3-T10 part 1: pipes, eventfds, memfd_create and the waits over them
//! (poll, ppoll, select, pselect6), checked against Linux. Runs under
//! Linux (`host.pipeprobe`) and on Keel (`exec.pipes`) and must pass on
//! both.
//!
//! Semantics from pipe(7) and pipe(2) ("PIPE_BUF", "pipe capacity",
//! EPIPE and SIGPIPE), eventfd(2), memfd_create(2), poll(2), select(2)
//! and Linux v6.12's `fs/pipe.c`, `fs/eventfd.c`, `mm/memfd.c` and
//! `fs/select.c`. Only what both kernels guarantee is checked: a signal
//! that interrupts a wait here either ends the process (SIGUSR1's default
//! action) or runs a handler (then Linux too returns EINTR), because Keel
//! does not restart interrupted calls yet (ADR 0020) and Linux would
//! restart one whose signal is ignored.
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, Arg, FdSets, Hostile, O_CLOEXEC, O_RDWR, O_WRONLY, Out};

const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const ESPIPE: i64 = -29;
const EPIPE: i64 = -32;
const EFAULT: i64 = -14;
const EINTR: i64 = -4;
const O_NONBLOCK: u64 = 0o4000;
const O_LARGEFILE: u64 = 0o100000;
const F_GETFD: u32 = 1;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;
const FIONREAD: u64 = 0x541B;
const POLLIN: u16 = 0x1;
const POLLOUT: u16 = 0x4;
const POLLERR: u16 = 0x8;
const POLLHUP: u16 = 0x10;
const POLLRDNORM: u16 = 0x40;
const POLLWRNORM: u16 = 0x100;
const EFD_SEMAPHORE: u64 = 1;
const MFD_CLOEXEC: u64 = 1;
const MFD_NOEXEC_SEAL: u64 = 8;
const MFD_EXEC: u64 = 0x10;
const SIGUSR1: i32 = 10;
const SIGPIPE: i32 = 13;
const SIG_BLOCK: i32 = 0;
const SIG_SETMASK: i32 = 2;
const S_IFMT: u32 = 0o170000;
const S_IFIFO: u32 = 0o010000;
const S_IFREG: u32 = 0o100000;
const PIPE_CAPACITY: usize = 65536;

fn mode(b: &[u8; 144]) -> u32 {
    u32::from_le_bytes(b[24..28].try_into().unwrap_or([0; 4]))
}

fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]))
}

fn pollfd(fd: i32, events: u16) -> [u8; 8] {
    let mut e = [0u8; 8];
    e[..4].copy_from_slice(&fd.to_le_bytes());
    e[4..6].copy_from_slice(&events.to_le_bytes());
    e
}

fn revents(e: &[u8; 8]) -> u16 {
    u16::from_le_bytes([e[6], e[7]])
}

/// What `fd` is ready for now (poll with no wait).
fn ready(fd: i32, events: u16) -> u16 {
    let mut fds = [pollfd(fd, events)];
    if sys::poll(&mut fds, 0) < 0 {
        return 0xffff;
    }
    revents(&fds[0])
}

fn timespec(sec: i64, nsec: i64) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[..8].copy_from_slice(&sec.to_le_bytes());
    t[8..].copy_from_slice(&nsec.to_le_bytes());
    t
}

fn set_bit(set: &mut [u8; 128], fd: i32) {
    set[fd as usize / 8] |= 1 << (fd % 8);
}

fn has_bit(set: &[u8; 128], fd: i32) -> bool {
    set[fd as usize / 8] & (1 << (fd % 8)) != 0
}

/// Sleeps about `ms` milliseconds (poll with no descriptors).
fn nap(ms: i32) {
    sys::poll(&mut [], ms);
}

/// Sets `signal`'s action to `handler` (SIG_DFL 0 or SIG_IGN 1).
fn disposition(signal: i32, handler: u64) -> bool {
    let mut act = [0u8; 32];
    act[..8].copy_from_slice(&handler.to_le_bytes());
    sys::rt_sigaction(signal, Arg::Buf(&act), Out::Null, 8) == 0
}

/// Forks a child that runs `body` and exits with what it returns; the
/// child's wait status, or None.
fn in_child(body: impl FnOnce() -> i32) -> Option<i32> {
    let pid = sys::fork();
    if pid == 0 {
        keel_rt::exit(body());
    }
    let mut status = 0;
    (pid > 0 && sys::wait4(pid as i32, &mut status, 0) == pid).then_some(status)
}

/// Whether child `pid` has not exited yet (wait4 with WNOHANG).
fn still_running(pid: i64) -> Option<bool> {
    const WNOHANG: u32 = 1;
    let mut status = 0;
    match sys::wait4(pid as i32, &mut status, WNOHANG) {
        0 => Some(true),
        n if n == pid => Some(false),
        _ => None,
    }
}

fn pair(flags: Option<u64>) -> Option<(i32, i32)> {
    let mut fds = [-1i32; 2];
    (sys::pipe2(&mut fds, flags) == 0).then_some((fds[0], fds[1]))
}

fn pipes() -> i32 {
    // 1. pipe2: two descriptors, the read end first; O_CLOEXEC on both;
    //    the access modes O_RDONLY and O_WRONLY (F_GETFL); other flags
    //    EINVAL; an unwritable array EFAULT.
    let Some((r, w)) = pair(Some(O_CLOEXEC)) else {
        return 1;
    };
    if sys::fcntl(r, F_GETFD, 0) != 1 || sys::fcntl(w, F_GETFD, 0) != 1 {
        return 2;
    }
    if sys::fcntl(r, F_GETFL, 0) != 0 || sys::fcntl(w, F_GETFL, 0) != O_WRONLY as i64 {
        return 3;
    }
    let mut bad = [0i32; 2];
    if sys::pipe2(&mut bad, Some(O_RDWR)) != EINVAL {
        return 4;
    }
    if sys::pipe2_into(Hostile::new(0x10).unwrap_or_else(|| unreachable!())) != EFAULT {
        return 5;
    }

    // 2. Bytes in order; a short read takes what is asked; FIONREAD
    //    counts what is left.
    let mut buf = [0u8; 16];
    if sys::write(w, b"hello") != 5 || sys::read(r, &mut buf[..3]) != 3 || &buf[..3] != b"hel" {
        return 6;
    }
    let mut arg = [0u8; 64];
    if sys::ioctl(r, FIONREAD, &mut arg) != 0 || arg[..4] != 2i32.to_le_bytes() {
        return 7;
    }
    if sys::read(r, &mut buf) != 2 || &buf[..2] != b"lo" {
        return 8;
    }

    // 3. A FIFO, mode 0600, one inode for both ends; no seeking, no
    //    positional reads, no mapping; each end only one way.
    let (mut sr, mut sw) = ([0u8; 144], [0u8; 144]);
    if sys::fstat(r, &mut sr) != 0 || sys::fstat(w, &mut sw) != 0 {
        return 9;
    }
    if mode(&sr) != S_IFIFO | 0o600 || word(&sr, 8) != word(&sw, 8) || word(&sr, 48) != 0 {
        return 10;
    }
    if sys::lseek(r, 0, 0) != ESPIPE || sys::pread(r, &mut buf, 0) != ESPIPE {
        return 11;
    }
    if sys::mmap_raw(4096, 1, 1, r) != ENODEV {
        return 12;
    }
    if sys::write(r, b"x") != EBADF || sys::read(w, &mut buf) != EBADF {
        return 13;
    }
    let mut sf = [0u8; 120];
    if sys::fstatfs(r, &mut sf) != 0 || word(&sf, 0) != 0x5049_5045 {
        return 14;
    }

    // 4. O_NONBLOCK through F_SETFL: an empty pipe EAGAIN; poll says the
    //    read end is not ready and the write end is.
    if sys::fcntl(r, F_SETFL, O_NONBLOCK) != 0
        || sys::fcntl(w, F_SETFL, O_NONBLOCK) != 0
        || sys::fcntl(r, F_GETFL, 0) != O_NONBLOCK as i64
    {
        return 15;
    }
    if sys::read(r, &mut buf) != EAGAIN {
        return 16;
    }
    if ready(r, POLLIN) != 0 || ready(w, POLLOUT) != POLLOUT {
        return 17;
    }

    // 5. Capacity: a non-blocking write of more than the pipe holds
    //    writes 64 KiB; then even one byte is EAGAIN and the write end is
    //    not ready. A page read makes room for a page (written whole).
    let big = [7u8; PIPE_CAPACITY + 4464];
    if sys::write(w, &big) != PIPE_CAPACITY as i64 {
        return 18;
    }
    if sys::write(w, b"x") != EAGAIN || ready(w, POLLOUT) != 0 {
        return 19;
    }
    let mut page = [0u8; 4096];
    if sys::read(r, &mut page) != 4096 || sys::write(w, &page) != 4096 {
        return 20;
    }
    if ready(r, POLLIN | POLLRDNORM) != POLLIN | POLLRDNORM {
        return 21;
    }
    // A write of at most PIPE_BUF goes in whole or not at all: with 100
    // bytes read, 200 bytes EAGAIN. (What a longer write would take
    // differs: Linux counts page buffers, Keel bytes; ADR 0025.)
    if sys::read(r, &mut page[..100]) != 100 || sys::write(w, &[1u8; 200]) != EAGAIN {
        return 92;
    }
    let mut drain = [0u8; 8192];
    let mut total = 0;
    loop {
        let n = sys::read(r, &mut drain);
        if n <= 0 {
            break;
        }
        total += n;
    }
    if total != PIPE_CAPACITY as i64 - 100 {
        return 22;
    }

    // 6. writev is one write; readv takes what is there without waiting
    //    to fill every buffer.
    if sys::writev(w, &[b"ab", b"cd"]) != 4
        || sys::read(r, &mut buf[..4]) != 4
        || &buf[..4] != b"abcd"
    {
        return 23;
    }
    sys::write(w, b"xyz");
    let (mut a, mut b) = ([0u8; 2], [0u8; 2]);
    if sys::readv2(r, &mut a, &mut b, None) != 3 || &a != b"xy" || b[0] != b'z' {
        return 24;
    }

    // A read whose copy faults is EFAULT and leaves the bytes in the pipe.
    sys::write(w, b"kept");
    if sys::read_into(r, Hostile::new(0x10).unwrap_or_else(|| unreachable!()), 4) != EFAULT
        || sys::read(r, &mut buf[..4]) != 4
        || &buf[..4] != b"kept"
    {
        return 94;
    }

    // 7. The last writer gone: end of file, and POLLHUP without POLLIN.
    sys::close(w);
    if sys::read(r, &mut buf) != 0 || ready(r, POLLIN) != POLLHUP {
        return 25;
    }
    sys::close(r);

    // 8. The last reader gone: with SIGPIPE ignored, EPIPE, and the write
    //    end reports POLLERR (and is still writable by poll's account).
    let Some((r, w)) = pair(None) else {
        return 26;
    };
    sys::close(r);
    if !disposition(SIGPIPE, 1) || sys::write(w, b"x") != EPIPE {
        return 27;
    }
    if ready(w, POLLOUT) != POLLOUT | POLLERR {
        return 28;
    }
    // With SIGPIPE's default action, the writer dies of it.
    if !disposition(SIGPIPE, 0) {
        return 29;
    }
    let status = in_child(|| {
        sys::write(w, b"x");
        0
    });
    if status.map(|s| s & 0x7f) != Some(SIGPIPE) {
        return 30;
    }
    sys::close(w);

    // 9. A blocking read waits for a writer: a child writes after a
    //    pause; the read returns its byte while the child still runs (the
    //    write woke it, not the child's exit), then end of file once it
    //    and our own write end are gone.
    let Some((r, w)) = pair(None) else {
        return 31;
    };
    let child = sys::fork();
    if child == 0 {
        sys::close(r);
        nap(30);
        sys::write(w, b"!");
        nap(300);
        keel_rt::exit(0);
    }
    sys::close(w);
    if sys::read(r, &mut buf) != 1 || buf[0] != b'!' || still_running(child) != Some(true) {
        return 32;
    }
    let mut st = 0;
    if child < 0 || sys::wait4(child as i32, &mut st, 0) != child || sys::read(r, &mut buf) != 0 {
        return 33;
    }
    sys::close(r);

    // 10. poll with no timeout wakes when a child writes.
    let Some((r, w)) = pair(None) else {
        return 34;
    };
    let child = sys::fork();
    if child == 0 {
        nap(30);
        sys::write(w, b"!");
        nap(300);
        keel_rt::exit(0);
    }
    let mut fds = [pollfd(r, POLLIN)];
    if sys::poll(&mut fds, -1) != 1
        || revents(&fds[0]) != POLLIN
        || still_running(child) != Some(true)
    {
        return 35;
    }
    if sys::wait4(child as i32, &mut st, 0) != child {
        return 36;
    }
    sys::close(r);
    sys::close(w);
    0
}

fn selects() -> i32 {
    let Some((r, w)) = pair(None) else {
        return 40;
    };
    // 1. select counts each set's bits: the read end readable, the write
    //    end writable; bits for descriptors not ready are cleared.
    sys::write(w, b"x");
    let (mut rs, mut ws) = ([0u8; 128], [0u8; 128]);
    set_bit(&mut rs, r);
    set_bit(&mut rs, w);
    set_bit(&mut ws, w);
    let n = r.max(w) + 1;
    let got = sys::select(
        n,
        FdSets {
            read: Some(&mut rs),
            write: Some(&mut ws),
            except: None,
        },
        None,
    );
    if got != 2 || !has_bit(&rs, r) || has_bit(&rs, w) || !has_bit(&ws, w) {
        return 41;
    }
    let mut one = [0u8; 1];
    sys::read(r, &mut one);

    // 2. A timeout that passes: 0, the sets cleared, the time left (none)
    //    written back. Microseconds must not be negative.
    let mut rs = [0u8; 128];
    set_bit(&mut rs, r);
    let mut tv = timespec(0, 20_000);
    let none = FdSets {
        read: Some(&mut rs),
        write: None,
        except: None,
    };
    if sys::select(n, none, Some(&mut tv)) != 0 || has_bit(&rs, r) || tv != timespec(0, 0) {
        return 42;
    }
    let mut bad = timespec(0, -1);
    let empty = || FdSets {
        read: None,
        write: None,
        except: None,
    };
    if sys::select(0, empty(), Some(&mut bad)) != EINVAL || sys::select(-1, empty(), None) != EINVAL
    {
        return 43;
    }

    // 3. A descriptor that is not open, in any set, EBADF. (Bits past the
    //    descriptor table's size, 64 here, would be ignored.)
    let mut xs = [0u8; 128];
    set_bit(&mut xs, 50);
    let sets = FdSets {
        read: None,
        write: None,
        except: Some(&mut xs),
    };
    if sys::select(51, sets, None) != EBADF {
        return 44;
    }
    let mut xs = [0u8; 128];
    set_bit(&mut xs, 100);
    let mut tv = timespec(0, 0);
    let sets = FdSets {
        read: None,
        write: None,
        except: Some(&mut xs),
    };
    if sys::select(101, sets, Some(&mut tv)) != 0 {
        return 95;
    }
    // A descriptor ready in two sets counts twice (an eventfd with a
    // count is readable and writable).
    let efd = sys::eventfd2(1, None) as i32;
    let (mut rs, mut ws) = ([0u8; 128], [0u8; 128]);
    set_bit(&mut rs, efd);
    set_bit(&mut ws, efd);
    let sets = FdSets {
        read: Some(&mut rs),
        write: Some(&mut ws),
        except: None,
    };
    if efd < 0 || sys::select(efd + 1, sets, None) != 2 {
        return 96;
    }
    sys::close(efd);

    // 4. pselect6 with a timespec: the same, its time written back.
    let mut rs = [0u8; 128];
    set_bit(&mut rs, r);
    let mut ts = timespec(0, 20_000_000);
    let sets = FdSets {
        read: Some(&mut rs),
        write: None,
        except: None,
    };
    if sys::pselect6(n, sets, Some(&mut ts), None, 0) != 0 || ts != timespec(0, 0) {
        return 45;
    }

    // 5. ppoll: a timespec timeout, written back; a tv_nsec of a whole
    //    second EINVAL; a mask of the wrong size EINVAL.
    let mut fds = [pollfd(r, POLLIN)];
    let mut ts = timespec(0, 20_000_000);
    if sys::ppoll(&mut fds, Some(&mut ts), None, 0) != 0 || ts != timespec(0, 0) {
        return 46;
    }
    let mut ts = timespec(0, 1_000_000_000);
    if sys::ppoll(&mut fds, Some(&mut ts), None, 0) != EINVAL {
        return 47;
    }
    let mask = 0u64;
    let mut ts = timespec(0, 0);
    if sys::ppoll(&mut fds, Some(&mut ts), Some(&mask), 4) != EINVAL {
        return 48;
    }
    sys::close(r);
    sys::close(w);

    // 6. The temporary mask: with SIGUSR1 blocked, a ppoll whose mask
    //    lets it in times out with nothing pending, and SIGUSR1 is blocked
    //    again after; with SIGUSR1 pending, that mask lets it in, which
    //    ends the process (its default action) - for ppoll and pselect6.
    let usr1 = 1u64 << (SIGUSR1 - 1);
    let mut old = 0u64;
    if sys::rt_sigprocmask(SIG_BLOCK, Arg::Buf(&usr1), Out::Buf(&mut old), 8) != 0 {
        return 49;
    }
    let mut ts = timespec(0, 1_000_000);
    let open = 0u64;
    if sys::ppoll(&mut [], Some(&mut ts), Some(&open), 8) != 0 {
        return 50;
    }
    let mut now = 0u64;
    if sys::rt_sigprocmask(SIG_BLOCK, Arg::Null, Out::Buf(&mut now), 8) != 0 || now & usr1 == 0 {
        return 51;
    }
    let pid = || sys::getpid() as i32;
    let status = in_child(|| {
        sys::kill(pid(), SIGUSR1);
        let mut ts = timespec(5, 0);
        let empty = 0u64;
        sys::ppoll(&mut [], Some(&mut ts), Some(&empty), 8);
        1
    });
    if status.map(|s| s & 0x7f) != Some(SIGUSR1) {
        return 52;
    }
    let status = in_child(|| {
        sys::kill(pid(), SIGUSR1);
        let mut ts = timespec(5, 0);
        let empty = 0u64;
        let sets = FdSets {
            read: None,
            write: None,
            except: None,
        };
        sys::pselect6(0, sets, Some(&mut ts), Some(&empty), 8);
        1
    });
    if status.map(|s| s & 0x7f) != Some(SIGUSR1) {
        return 53;
    }
    // Still pending but blocked by the call's mask: no interruption.
    let status = in_child(|| {
        sys::kill(pid(), SIGUSR1);
        let mut ts = timespec(0, 0);
        if sys::ppoll(&mut [], Some(&mut ts), Some(&usr1), 8) != 0 {
            return 2;
        }
        0
    });
    if status != Some(0) {
        return 54;
    }
    // A handler that runs during the call: the call is EINTR (a handler
    // ran, so Linux does not restart it), and the handler's sigreturn
    // puts back the mask from before the call (the frame saved that one,
    // not the call's), so SIGUSR1 is blocked again - ppoll and pselect6.
    if keel_rt::signal::catch(SIGUSR1) != 0 {
        return 97;
    }
    for (round, wait) in [(1u32, 0), (2, 1)] {
        sys::kill(pid(), SIGUSR1);
        let mut ts = timespec(5, 0);
        let interrupted = if wait == 0 {
            sys::ppoll(&mut [], Some(&mut ts), Some(&open), 8)
        } else {
            let sets = FdSets {
                read: None,
                write: None,
                except: None,
            };
            sys::pselect6(0, sets, Some(&mut ts), Some(&open), 8)
        };
        let mut now = 0u64;
        let blocked = sys::rt_sigprocmask(SIG_BLOCK, Arg::Null, Out::Buf(&mut now), 8) == 0
            && now & usr1 != 0;
        if interrupted != EINTR || keel_rt::signal::caught(SIGUSR1) != round || !blocked {
            return 98 + wait;
        }
    }
    if !disposition(SIGUSR1, 0) {
        return 100;
    }
    if sys::rt_sigprocmask(SIG_SETMASK, Arg::Buf(&old), Out::Null, 8) != 0 {
        return 55;
    }
    0
}

fn eventfds() -> i32 {
    // 1. The counter: read whole (8 bytes; fewer EINVAL), then EAGAIN at
    //    0; writes add (exactly 8 bytes, never u64::MAX).
    let fd = sys::eventfd2(3, Some(O_NONBLOCK)) as i32;
    if fd < 0 {
        return 60;
    }
    let mut v = [0u8; 8];
    if sys::read(fd, &mut v[..4]) != EINVAL || sys::read(fd, &mut v) != 8 || v != 3u64.to_le_bytes()
    {
        return 61;
    }
    if sys::read(fd, &mut v) != EAGAIN {
        return 62;
    }
    if sys::write(fd, &[1u8; 7]) != EINVAL || sys::write(fd, &u64::MAX.to_le_bytes()) != EINVAL {
        return 63;
    }
    if sys::write(fd, &5u64.to_le_bytes()) != 8 || ready(fd, POLLIN | POLLOUT) != POLLIN | POLLOUT {
        return 64;
    }
    // 2. At u64::MAX - 1 it is no longer writable; one more would reach
    //    u64::MAX: EAGAIN.
    if sys::write(fd, &(u64::MAX - 1 - 5).to_le_bytes()) != 8
        || ready(fd, POLLIN | POLLOUT) != POLLIN
        || sys::write(fd, &1u64.to_le_bytes()) != EAGAIN
    {
        return 65;
    }
    // 3. An anonymous inode, mode 0600 with no file type; lseek stays at
    //    0; no positional reads.
    let mut st = [0u8; 144];
    if sys::fstat(fd, &mut st) != 0 || mode(&st) & S_IFMT != 0 || mode(&st) & 0o777 != 0o600 {
        return 66;
    }
    let mut sf = [0u8; 120];
    if sys::lseek(fd, 100, 0) != 0
        || sys::pread(fd, &mut v, 0) != ESPIPE
        || sys::fstatfs(fd, &mut sf) != 0
        || word(&sf, 0) != 0x0904_1934
    {
        return 67;
    }
    sys::close(fd);

    // 4. EFD_SEMAPHORE: each read takes 1. Unknown flags EINVAL. eventfd
    //    is eventfd2 without flags.
    let fd = sys::eventfd2(2, Some(EFD_SEMAPHORE | O_NONBLOCK)) as i32;
    let mut reads = [0i64; 3];
    for n in reads.iter_mut() {
        *n = sys::read(fd, &mut v);
    }
    if fd < 0 || reads != [8, 8, EAGAIN] || v != 1u64.to_le_bytes() {
        return 68;
    }
    sys::close(fd);
    if sys::eventfd2(0, Some(4)) != EINVAL {
        return 69;
    }

    // 5. A blocking read waits for a writer (a child, after a pause).
    let fd = sys::eventfd2(0, None) as i32;
    if fd < 0 {
        return 70;
    }
    let child = sys::fork();
    if child == 0 {
        nap(30);
        sys::write(fd, &9u64.to_le_bytes());
        nap(300);
        keel_rt::exit(0);
    }
    let mut status = 0;
    if sys::read(fd, &mut v) != 8 || v != 9u64.to_le_bytes() || still_running(child) != Some(true) {
        return 71;
    }
    if sys::wait4(child as i32, &mut status, 0) != child || status != 0 {
        return 72;
    }
    sys::close(fd);
    0
}

fn memfds() -> i32 {
    // 1. A regular file in no directory: mode 0777, no links, open for
    //    reading and writing (with O_LARGEFILE), close-on-exec if asked.
    let fd = sys::memfd_create(c"probe", MFD_CLOEXEC) as i32;
    if fd < 0 {
        return 80;
    }
    if sys::fcntl(fd, F_GETFD, 0) != 1
        || sys::fcntl(fd, F_GETFL, 0) != (O_RDWR | O_LARGEFILE) as i64
    {
        return 81;
    }
    let mut st = [0u8; 144];
    if sys::fstat(fd, &mut st) != 0
        || mode(&st) != S_IFREG | 0o777
        || word(&st, 16) != 0
        || word(&st, 48) != 0
    {
        return 82;
    }
    // 2. It reads, writes, seeks and grows as a file.
    let mut buf = [0u8; 8];
    if sys::write(fd, b"data") != 4 || sys::pread(fd, &mut buf[..4], 0) != 4 || &buf[..4] != b"data"
    {
        return 83;
    }
    if sys::ftruncate(fd, 8192) != 0 || sys::fstat(fd, &mut st) != 0 || word(&st, 48) != 8192 {
        return 84;
    }
    sys::close(fd);
    // 3. Unknown flags, MFD_EXEC with MFD_NOEXEC_SEAL, and a name of 250
    //    bytes EINVAL; 249 bytes is the limit.
    if sys::memfd_create(c"x", 0x100) != EINVAL
        || sys::memfd_create(c"x", MFD_EXEC | MFD_NOEXEC_SEAL) != EINVAL
    {
        return 85;
    }
    let mut name = [b'n'; 251];
    name[250] = 0;
    let long = core::ffi::CStr::from_bytes_until_nul(&name).unwrap_or(c"");
    if sys::memfd_create(long, 0) != EINVAL {
        return 86;
    }
    name[249] = 0;
    let limit = core::ffi::CStr::from_bytes_until_nul(&name).unwrap_or(c"");
    let fd = sys::memfd_create(limit, 0);
    if fd < 0 {
        return 87;
    }
    sys::close(fd as i32);
    0
}

fn main(_: &Startup) -> i32 {
    for part in [pipes, selects, eventfds, memfds] {
        let failed = part();
        if failed != 0 {
            return failed;
        }
    }
    // POLLWRNORM is reported with POLLOUT (pipe_poll) when asked for.
    let Some((r, w)) = pair(None) else {
        return 90;
    };
    if ready(w, POLLOUT | POLLWRNORM) != POLLOUT | POLLWRNORM {
        return 91;
    }
    sys::close(r);
    sys::close(w);
    sys::write(1, b"pipeprobe: 83 checks passed\n");
    0
}

keel_rt::main!(main);
