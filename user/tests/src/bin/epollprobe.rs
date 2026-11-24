//! P3-T10 part 2: epoll, checked against Linux. Runs under Linux
//! (`host.epollprobe`) and on Keel (`exec.epoll`) and must pass on both.
//!
//! Semantics from epoll(7), epoll_create(2), epoll_ctl(2),
//! epoll_wait(2) and Linux v6.12's `fs/eventpoll.c`: level-triggered
//! items stay ready, edge-triggered ones need a new wake (each write to a
//! pipe is one, a read is one for writers only if the pipe was full),
//! EPOLLONESHOT disables until EPOLL_CTL_MOD, EPOLLERR and EPOLLHUP are
//! always reported, items go when their file is released (not when one
//! of its descriptors closes), and a full wait rotates its level-triggered
//! items.
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, Arg, Hostile, O_CLOEXEC, O_RDONLY, Out};

const EPERM: i64 = -1;
const EINTR: i64 = -4;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EEXIST: i64 = -17;
const ENOENT: i64 = -2;
const EINVAL: i64 = -22;
const O_NONBLOCK: u64 = 0o4000;
const F_GETFD: u32 = 1;
const F_GETFL: u32 = 3;
const ADD: i32 = 1;
const DEL: i32 = 2;
const MOD: i32 = 3;
const IN: u32 = 0x1;
const OUT: u32 = 0x4;
const HUP: u32 = 0x10;
const EXCLUSIVE: u32 = 1 << 28;
const ONESHOT: u32 = 1 << 30;
const ET: u32 = 1 << 31;
const SIGUSR1: i32 = 10;
const SIG_BLOCK: i32 = 0;
const SIG_SETMASK: i32 = 2;
const MAX_EVENTS: i64 = 178_956_970;

fn ev(events: u32, data: u64) -> [u8; 12] {
    let mut e = [0u8; 12];
    e[..4].copy_from_slice(&events.to_le_bytes());
    e[4..].copy_from_slice(&data.to_le_bytes());
    e
}

fn parse(e: &[u8; 12]) -> (u32, u64) {
    (
        u32::from_le_bytes([e[0], e[1], e[2], e[3]]),
        u64::from_le_bytes(e[4..].try_into().unwrap_or([0; 8])),
    )
}

fn add(epfd: i32, fd: i32, events: u32, data: u64) -> i64 {
    sys::epoll_ctl(epfd, ADD, fd, Some(&ev(events, data)))
}

/// One wait with no timeout: the single event, or None if none (or an
/// error).
fn one(epfd: i32) -> Option<(u32, u64)> {
    let mut out = [[0u8; 12]; 1];
    (sys::epoll_wait(epfd, &mut out, 0) == 1).then(|| parse(&out[0]))
}

fn pair(flags: u64) -> Option<(i32, i32)> {
    let mut fds = [-1i32; 2];
    (sys::pipe2(&mut fds, Some(flags)) == 0).then_some((fds[0], fds[1]))
}

fn epoll() -> i32 {
    sys::epoll_create1(Some(O_CLOEXEC), 0) as i32
}

fn timespec(sec: i64, nsec: i64) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[..8].copy_from_slice(&sec.to_le_bytes());
    t[8..].copy_from_slice(&nsec.to_le_bytes());
    t
}

fn nap(ms: i32) {
    sys::poll(&mut [], ms);
}

fn still_running(pid: i64) -> bool {
    let mut status = 0;
    sys::wait4(pid as i32, &mut status, 1) == 0
}

fn creation() -> i32 {
    // 1. epoll_create1: close-on-exec if asked; O_RDWR; unknown flags
    //    EINVAL. epoll_create: a size of 0 EINVAL, 1 is fine.
    let e = epoll();
    if e < 0 || sys::fcntl(e, F_GETFD, 0) != 1 || sys::fcntl(e, F_GETFL, 0) != 2 {
        return 1;
    }
    if sys::epoll_create1(Some(1), 0) != EINVAL || sys::epoll_create1(None, 0) != EINVAL {
        return 2;
    }
    let old = sys::epoll_create1(None, 1);
    if old < 0 || sys::fcntl(old as i32, F_GETFD, 0) != 0 {
        return 3;
    }
    sys::close(old as i32);
    // 2. An anonymous inode, mode 0600; lseek stays at 0; no read or
    //    write (EINVAL).
    let mut st = [0u8; 144];
    let mode = |b: &[u8; 144]| u32::from_le_bytes(b[24..28].try_into().unwrap_or([0; 4]));
    let mut sf = [0u8; 120];
    if sys::fstat(e, &mut st) != 0
        || mode(&st) != 0o600
        || sys::fstatfs(e, &mut sf) != 0
        || sf[..8] != 0x0904_1934u64.to_le_bytes()
    {
        return 4;
    }
    let mut b = [0u8; 8];
    if sys::lseek(e, 9, 0) != 0 || sys::read(e, &mut b) != EINVAL || sys::write(e, &b) != EINVAL {
        return 5;
    }
    sys::close(e);
    0
}

fn control() -> i32 {
    let e = epoll();
    let Some((r, w)) = pair(O_NONBLOCK) else {
        return 10;
    };
    // 1. Targets without a poll method: EPERM (a memfd is a regular
    //    file; /dev/null; a directory).
    let mfd = sys::memfd_create(c"probe", 0) as i32;
    let null = sys::openat(AT_FDCWD, c"/dev/null", O_RDONLY, 0) as i32;
    let dir = sys::openat(AT_FDCWD, c"/", O_RDONLY, 0) as i32;
    for (i, fd) in [mfd, null, dir].into_iter().enumerate() {
        if fd < 0 || add(e, fd, IN, 0) != EPERM {
            return 11 + i as i32;
        }
    }
    // The target is checked before the op: an unknown op on a memfd is
    // EPERM, on a pipe EINVAL.
    if sys::epoll_ctl(e, 9, mfd, Some(&ev(IN, 0))) != EPERM
        || sys::epoll_ctl(e, 9, r, Some(&ev(IN, 0))) != EINVAL
    {
        return 14;
    }
    // 2. Itself EINVAL; a non-epoll epfd EINVAL; closed descriptors EBADF.
    if add(e, e, IN, 0) != EINVAL || add(w, r, IN, 0) != EINVAL {
        return 15;
    }
    if add(e, 900, IN, 0) != EBADF || add(900, r, IN, 0) != EBADF {
        return 16;
    }
    // 3. The event is read (EFAULT) except for EPOLL_CTL_DEL.
    let bad = Hostile::new(0x10).unwrap_or_else(|| unreachable!());
    if sys::epoll_ctl_from(e, ADD, r, bad) != EFAULT {
        return 17;
    }
    // 4. ADD twice EEXIST; DEL and MOD of what is not there ENOENT; DEL
    //    takes no event.
    if add(e, r, IN, 1) != 0 || add(e, r, IN, 1) != EEXIST {
        return 18;
    }
    if sys::epoll_ctl(e, MOD, w, Some(&ev(OUT, 0))) != ENOENT
        || sys::epoll_ctl(e, DEL, w, None) != ENOENT
    {
        return 19;
    }
    if sys::epoll_ctl(e, DEL, r, None) != 0 || sys::epoll_ctl(e, DEL, r, None) != ENOENT {
        return 20;
    }
    // 5. EPOLLEXCLUSIVE: not with MOD, nor with bits outside its set
    //    (EPOLLONESHOT); once added, MOD of the item EINVAL.
    if add(e, r, IN | EXCLUSIVE | ONESHOT, 0) != EINVAL {
        return 21;
    }
    if add(e, r, IN | EXCLUSIVE, 0) != 0
        || sys::epoll_ctl(e, MOD, r, Some(&ev(IN | EXCLUSIVE, 0))) != EINVAL
        || sys::epoll_ctl(e, MOD, r, Some(&ev(IN, 0))) != EINVAL
    {
        return 22;
    }
    // 6. epoll_wait's checks: maxevents 0 or past EP_MAX_EVENTS EINVAL;
    //    not an epoll instance EINVAL; closed EBADF; a kernel address
    //    EFAULT. A NULL array is a user address: with nothing ready, 0.
    let mut out = [[0u8; 12]; 1];
    if sys::epoll_wait(e, &mut [], 0) != EINVAL
        || sys::epoll_wait_into(e, bad, (MAX_EVENTS + 1) as i32, 0) != EINVAL
    {
        return 23;
    }
    if sys::epoll_wait(r, &mut out, 0) != EINVAL || sys::epoll_wait(900, &mut out, 0) != EBADF {
        return 24;
    }
    let kernel = Hostile::new(0xFFFF_8000_0000_0000).unwrap_or_else(|| unreachable!());
    let null_out = Hostile::new(0).unwrap_or_else(|| unreachable!());
    if sys::epoll_wait_into(e, kernel, 1, 0) != EFAULT
        || sys::epoll_wait_into(e, null_out, 1, 0) != 0
    {
        return 25;
    }
    // ...and with something ready, writing to it faults.
    sys::write(w, b"x");
    if sys::epoll_wait_into(e, null_out, 1, 0) != EFAULT {
        return 26;
    }
    // The item that faulted is still ready: the next wait reports it.
    if sys::epoll_wait(e, &mut out, 0) != 1 {
        return 27;
    }
    // MOD with EPOLLEXCLUSIVE is EINVAL for any item.
    if add(e, w, OUT, 0) != 0 || sys::epoll_ctl(e, MOD, w, Some(&ev(OUT | EXCLUSIVE, 0))) != EINVAL
    {
        return 28;
    }
    for fd in [e, r, w, mfd, null, dir] {
        sys::close(fd);
    }
    0
}

fn triggering() -> i32 {
    let e = epoll();
    let Some((r, w)) = pair(O_NONBLOCK) else {
        return 30;
    };
    // 1. Level-triggered: not ready, nothing; ready, reported each time
    //    (the event's data as given); only the asked-for events.
    if add(e, r, IN, 42) != 0 || one(e).is_some() {
        return 31;
    }
    sys::write(w, b"ab");
    if one(e) != Some((IN, 42)) || one(e) != Some((IN, 42)) {
        return 32;
    }
    let mut b = [0u8; 8];
    sys::read(r, &mut b);
    if one(e).is_some() {
        return 33;
    }
    // The write end, asked for IN and OUT, reports OUT only.
    if add(e, w, IN | OUT, 7) != 0 || one(e) != Some((OUT, 7)) {
        return 34;
    }
    sys::epoll_ctl(e, DEL, w, None);
    // 2. EPOLLHUP is reported unasked once the last writer is gone.
    sys::close(w);
    if one(e) != Some((HUP, 42)) {
        return 35;
    }
    sys::close(r);

    // 3. Edge-triggered: ready at ADD is one edge; then each write is a
    //    new one, even into a pipe that was not empty; a read is not.
    let Some((r, w)) = pair(O_NONBLOCK) else {
        return 36;
    };
    sys::write(w, b"a");
    if add(e, r, IN | ET, 1) != 0 || one(e) != Some((IN, 1)) || one(e).is_some() {
        return 37;
    }
    sys::write(w, b"b");
    if one(e) != Some((IN, 1)) || one(e).is_some() {
        return 38;
    }
    sys::read(r, &mut b[..1]);
    if one(e).is_some() {
        return 39;
    }
    // Empty it, so it fills with whole pages (Linux counts page buffers,
    // Keel bytes: they agree on when a pipe of whole pages is full).
    sys::read(r, &mut b[..1]);
    // A writer's edge: a read of a full pipe wakes writers; a read of one
    // that is not full does not.
    if add(e, w, OUT | ET, 2) != 0 || one(e) != Some((OUT, 2)) || one(e).is_some() {
        return 40;
    }
    let page = [5u8; 4096];
    while sys::write(w, &page) > 0 {}
    // r's edges from those writes (r is edge-triggered too).
    let mut out = [[0u8; 12]; 4];
    sys::epoll_wait(e, &mut out, 0);
    let mut big = [0u8; 4096];
    sys::read(r, &mut big);
    if one(e) != Some((OUT, 2)) {
        return 41;
    }
    sys::read(r, &mut big);
    if one(e).is_some() {
        return 42;
    }
    sys::close(r);
    sys::close(w);

    // 4. EPOLLONESHOT: reported once, then disabled until EPOLL_CTL_MOD.
    let Some((r, w)) = pair(O_NONBLOCK) else {
        return 43;
    };
    sys::write(w, b"x");
    if add(e, r, IN | ONESHOT, 3) != 0 || one(e) != Some((IN, 3)) || one(e).is_some() {
        return 44;
    }
    sys::write(w, b"y");
    if one(e).is_some() {
        return 45;
    }
    if sys::epoll_ctl(e, MOD, r, Some(&ev(IN, 4))) != 0 || one(e) != Some((IN, 4)) {
        return 46;
    }
    sys::epoll_ctl(e, DEL, r, None);

    // 5. Two ready level-triggered items and room for one: they take
    //    turns.
    let fd2 = sys::eventfd2(1, Some(O_NONBLOCK)) as i32;
    if add(e, r, IN, 10) != 0 || add(e, fd2, IN, 20) != 0 {
        return 47;
    }
    let (a, c) = (one(e), one(e));
    if a.is_none() || c.is_none() || a == c || one(e) != a {
        return 48;
    }
    // Room for both: both, in one call.
    if sys::epoll_wait(e, &mut out, 0) != 2 {
        return 49;
    }
    // 6. A wake counts only if its events match: an eventfd's read wakes
    //    with EPOLLOUT, so an edge-triggered reader sees no edge from it;
    //    a write wakes with EPOLLIN.
    let e2 = epoll();
    let sem = sys::eventfd2(3, Some(1 | O_NONBLOCK)) as i32;
    if add(e2, sem, IN | ET, 30) != 0 || one(e2) != Some((IN, 30)) {
        return 50;
    }
    let mut v = [0u8; 8];
    sys::read(sem, &mut v);
    if one(e2).is_some() {
        return 51;
    }
    sys::write(sem, &1u64.to_le_bytes());
    if one(e2) != Some((IN, 30)) {
        return 52;
    }
    sys::close(sem);
    sys::close(e2);
    sys::close(e);
    sys::close(r);
    sys::close(w);
    sys::close(fd2);
    0
}

fn lifetime() -> i32 {
    // 1. An item belongs to the open file, not the descriptor: closing
    //    the descriptor it was added by leaves it while a duplicate
    //    keeps the file open; closing the last one removes it.
    let e = epoll();
    let Some((r, w)) = pair(O_NONBLOCK) else {
        return 60;
    };
    let dup = sys::dup(r) as i32;
    sys::write(w, b"x");
    if add(e, r, IN, 5) != 0 || add(e, dup, IN, 6) != 0 {
        return 61;
    }
    let mut out = [[0u8; 12]; 4];
    if sys::epoll_wait(e, &mut out, 0) != 2 {
        return 62;
    }
    sys::close(r);
    if sys::epoll_wait(e, &mut out, 0) != 2 {
        return 63;
    }
    // The closed number cannot be named any more (EBADF).
    if sys::epoll_ctl(e, DEL, r, None) != EBADF {
        return 64;
    }
    sys::close(dup);
    if sys::epoll_wait(e, &mut out, 0) != 0 {
        return 65;
    }
    // 2. poll(2) on the epoll descriptor: readable while an item is ready.
    let fd = sys::eventfd2(0, Some(O_NONBLOCK)) as i32;
    add(e, fd, IN, 0);
    let mut p = [[0u8; 8]];
    p[0][..4].copy_from_slice(&e.to_le_bytes());
    p[0][4..6].copy_from_slice(&1u16.to_le_bytes());
    if sys::poll(&mut p, 0) != 0 {
        return 66;
    }
    sys::write(fd, &1u64.to_le_bytes());
    if sys::poll(&mut p, 0) != 1 || u16::from_le_bytes([p[0][6], p[0][7]]) != 1 {
        return 67;
    }
    sys::close(fd);
    sys::close(w);
    sys::close(e);
    0
}

fn waiting() -> i32 {
    let e = epoll();
    let Some((r, w)) = pair(0) else {
        return 70;
    };
    add(e, r, IN, 9);
    // 1. Timeouts: 20 ms with nothing ready, 0; epoll_pwait2 the same with
    //    a timespec; a tv_nsec of a second EINVAL; a mask of the wrong
    //    size EINVAL.
    let mut out = [[0u8; 12]; 2];
    if sys::epoll_wait(e, &mut out, 20) != 0 {
        return 71;
    }
    if sys::epoll_pwait2(e, &mut out, Some(&timespec(0, 20_000_000)), None, 0) != 0
        || sys::epoll_pwait2(e, &mut out, Some(&timespec(0, 1_000_000_000)), None, 0) != EINVAL
    {
        return 72;
    }
    let open = 0u64;
    if sys::epoll_pwait(e, &mut out, 0, Some(&open), 4) != EINVAL {
        return 73;
    }
    // 2. A wait without limit wakes when a child writes (while the child
    //    still runs: the write woke it).
    let child = sys::fork();
    if child == 0 {
        nap(30);
        sys::write(w, b"!");
        nap(300);
        keel_rt::exit(0);
    }
    if sys::epoll_wait(e, &mut out, -1) != 1 || parse(&out[0]) != (IN, 9) || !still_running(child) {
        return 74;
    }
    let mut status = 0;
    sys::wait4(child as i32, &mut status, 0);
    let mut b = [0u8; 1];
    sys::read(r, &mut b);
    // 3. Signals: with SIGUSR1 blocked and pending, epoll_pwait's mask
    //    lets it in: the handler runs, the call is EINTR, and the mask is
    //    back after. With a zero timeout the call returns 0 instead (Linux
    //    looks at the timeout before the signal), and as it was not
    //    interrupted the mask is back before any delivery: the handler
    //    does not run and SIGUSR1 stays pending, for the next call.
    let usr1 = 1u64 << (SIGUSR1 - 1);
    let mut old = 0u64;
    if keel_rt::signal::catch(SIGUSR1) != 0
        || sys::rt_sigprocmask(SIG_BLOCK, Arg::Buf(&usr1), Out::Buf(&mut old), 8) != 0
    {
        return 75;
    }
    let blocked = || {
        let mut now = 0u64;
        sys::rt_sigprocmask(SIG_BLOCK, Arg::Null, Out::Buf(&mut now), 8) == 0 && now & usr1 != 0
    };
    sys::kill(sys::getpid() as i32, SIGUSR1);
    if sys::epoll_pwait(e, &mut out, 5000, Some(&open), 8) != EINTR
        || keel_rt::signal::caught(SIGUSR1) != 1
        || !blocked()
    {
        return 76;
    }
    sys::kill(sys::getpid() as i32, SIGUSR1);
    if sys::epoll_pwait(e, &mut out, 0, Some(&open), 8) != 0
        || keel_rt::signal::caught(SIGUSR1) != 1
        || !blocked()
    {
        return 77;
    }
    if sys::epoll_pwait2(e, &mut out, Some(&timespec(5, 0)), Some(&open), 8) != EINTR
        || keel_rt::signal::caught(SIGUSR1) != 2
        || !blocked()
    {
        return 78;
    }
    sys::rt_sigprocmask(SIG_SETMASK, Arg::Buf(&old), Out::Null, 8);
    sys::close(e);
    sys::close(r);
    sys::close(w);
    0
}

fn main(_: &Startup) -> i32 {
    for part in [creation, control, triggering, lifetime, waiting] {
        let failed = part();
        if failed != 0 {
            return failed;
        }
    }
    sys::write(1, b"epollprobe: 64 checks passed\n");
    0
}

keel_rt::main!(main);
