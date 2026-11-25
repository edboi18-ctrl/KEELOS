//! P3-T12 part 2: process groups, sessions and the controlling terminal,
//! checked against Linux. Runs under Linux (`host.jobprobe`) and on Keel
//! (`exec.job_control`) and must pass on both.
//!
//! Semantics from setpgid(2), setsid(2), getsid(2), kill(2), wait4(2),
//! credentials(7), termios(3) (job control), ioctl_tty(2) and Linux
//! v6.12's `kernel/sys.c`, `kernel/exit.c` and `drivers/tty/tty_jobctrl.c`.
//! Each part runs in a child that makes its own session first, so nothing
//! depends on the session the probe starts in. A stopping signal (SIGTSTP,
//! SIGTTIN, SIGTTOU) is only ever sent to a process that catches or
//! ignores it: Keel does not stop processes yet (ADR 0030).
//!
//! Run as `jobprobe sleeper FD`, it writes a byte to FD and waits to be
//! killed (the program setpgid's EACCES is checked against).
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, Arg, O_RDWR, Out};

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EINTR: i64 = -4;
const EIO: i64 = -5;
const ENXIO: i64 = -6;
const ECHILD: i64 = -10;
const EACCES: i64 = -13;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;

const O_NOCTTY: u64 = 0o400;
const O_WRONLY: u64 = 1;

const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TIOCSCTTY: u64 = 0x540E;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;
const TIOCSWINSZ: u64 = 0x5414;
const TIOCNOTTY: u64 = 0x5422;
const TIOCGSID: u64 = 0x5429;
const TIOCGPTN: u64 = 0x8004_5430;
const TIOCSPTLCK: u64 = 0x4004_5431;
const TIOCSIG: u64 = 0x4004_5436;

const TOSTOP: u32 = 0x100;

const SIGHUP: i32 = 1;
const SIGINT: i32 = 2;
const SIGQUIT: i32 = 3;
const SIGTERM: i32 = 15;
const SIGCONT: i32 = 18;
const SIGTSTP: i32 = 20;
const SIGTTIN: i32 = 21;
const SIGTTOU: i32 = 22;
const SIGWINCH: i32 = 28;

const NOBODY: i32 = 0x7fff_fff0;
const POLLIN: u16 = 1;

fn nap(ms: i32) {
    sys::poll(&mut [], ms);
}

fn readable(fd: i32, ms: i32) -> bool {
    let mut e = [0u8; 8];
    e[..4].copy_from_slice(&fd.to_le_bytes());
    e[4..6].copy_from_slice(&POLLIN.to_le_bytes());
    let mut fds = [e];
    sys::poll(&mut fds, ms);
    u16::from_le_bytes([fds[0][6], fds[0][7]]) & POLLIN != 0
}

/// Sets `signal`'s action to `handler` (SIG_DFL 0 or SIG_IGN 1).
fn disposition(signal: i32, handler: u64) {
    let mut act = [0u8; 32];
    act[..8].copy_from_slice(&handler.to_le_bytes());
    sys::rt_sigaction(signal, Arg::Buf(&act), Out::Null, 8);
}

fn int_ioctl(fd: i32, request: u64) -> Result<i32, i64> {
    let mut b = [0u8; 64];
    match sys::ioctl(fd, request, &mut b) {
        0 => Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        e => Err(e),
    }
}

fn set_int(fd: i32, request: u64, v: i32) -> i64 {
    let mut b = [0u8; 64];
    b[..4].copy_from_slice(&v.to_le_bytes());
    sys::ioctl(fd, request, &mut b)
}

fn pipe() -> (i32, i32) {
    let mut fds = [-1i32; 2];
    sys::pipe2(&mut fds, None);
    (fds[0], fds[1])
}

/// Waits for one byte on `fd` (up to 5 s).
fn await_byte(fd: i32) -> Option<u8> {
    if !readable(fd, 5000) {
        return None;
    }
    let mut b = [0u8; 1];
    (sys::read(fd, &mut b) == 1).then_some(b[0])
}

fn pid() -> i32 {
    sys::getpid() as i32
}

/// Forks a child that runs `body` and exits with what it returns.
fn spawn(body: impl FnOnce() -> i32) -> i32 {
    let child = sys::fork();
    if child == 0 {
        keel_rt::exit(body());
    }
    child as i32
}

/// The wait status of child `pid` (blocking).
fn reap(pid: i32) -> Option<i32> {
    let mut status = 0;
    (sys::wait4(pid, &mut status, 0) == i64::from(pid)).then_some(status)
}

/// Exit code of a normally exited status, or 1000 + the signal.
fn outcome(status: Option<i32>) -> i32 {
    match status {
        Some(s) if s & 0x7f == 0 => (s >> 8) & 0xff,
        Some(s) => 1000 + (s & 0x7f),
        None => 2000,
    }
}

/// A child that waits on `gate` (its read end) until killed or released,
/// then exits 0.
fn waiter(gate: i32) -> i32 {
    spawn(move || {
        let mut b = [0u8; 1];
        sys::read(gate, &mut b);
        0
    })
}

/// "/dev/pts/N" with its NUL.
fn pts_path(n: i32, out: &mut [u8; 32]) -> &CStr {
    let prefix = b"/dev/pts/";
    out[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0u8; 10];
    let mut len = 0;
    let mut v = n as u32;
    loop {
        digits[len] = b'0' + (v % 10) as u8;
        len += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..len {
        out[prefix.len() + i] = digits[len - 1 - i];
    }
    out[prefix.len() + len] = 0;
    CStr::from_bytes_until_nul(&out[..]).unwrap_or(c"/dev/pts/")
}

/// A pty: the master, the slave (opened with O_NOCTTY) and its number.
fn openpty() -> Option<(i32, i32, i32)> {
    let m = sys::open(c"/dev/ptmx", O_RDWR | O_NOCTTY, 0);
    if m < 0 {
        return None;
    }
    let m = m as i32;
    let n = int_ioctl(m, TIOCGPTN).ok()?;
    set_int(m, TIOCSPTLCK, 0);
    let mut path = [0u8; 32];
    let s = sys::open(pts_path(n, &mut path), O_RDWR | O_NOCTTY, 0);
    (s >= 0).then_some((m, s as i32, n))
}

/// Runs `part` in a child that has just made its own session; the part's
/// status (0, or the failed check's number). `argv0` is this program.
fn in_session(part: fn(&[u8]) -> i32, argv0: &[u8]) -> i32 {
    let child = spawn(move || {
        let me = pid();
        // 1. setsid makes the caller the leader of a new session and group,
        //    both its PID.
        if sys::setsid() != i64::from(me) {
            return 1;
        }
        part(argv0)
    });
    outcome(reap(child))
}

fn ids(argv0: &[u8]) -> i32 {
    let me = pid();
    // 2. getsid, getpgrp and getpgid agree.
    if sys::getsid(0) != i64::from(me)
        || sys::getpgrp() != i64::from(me)
        || sys::getpgid(0) != i64::from(me)
        || sys::getpgid(me) != i64::from(me)
    {
        return 2;
    }
    // 3. A leader cannot make a new session or leave its group.
    if sys::setsid() != EPERM || sys::setpgid(0, 0) != EPERM {
        return 3;
    }
    // 4. No such process: ESRCH; a negative group: EINVAL.
    if sys::getpgid(NOBODY) != ESRCH
        || sys::getsid(NOBODY) != ESRCH
        || sys::setpgid(NOBODY, 0) != ESRCH
        || sys::setpgid(0, -1) != EINVAL
    {
        return 4;
    }
    // 5. A child is in its parent's group and session; the parent moves
    //    it into a group of its own and back; an absent group is EPERM.
    let (gate, open) = pipe();
    let g = waiter(gate);
    if sys::getpgid(g) != i64::from(me) || sys::getsid(g) != i64::from(me) {
        return 5;
    }
    if sys::setpgid(g, g) != 0 || sys::getpgid(g) != i64::from(g) {
        return 6;
    }
    if sys::setpgid(g, me) != 0 || sys::getpgid(g) != i64::from(me) {
        return 7;
    }
    if sys::setpgid(g, NOBODY) != EPERM {
        return 8;
    }
    // 6. Only the caller and its children: the parent is ESRCH.
    let parent = sys::getppid() as i32;
    if sys::setpgid(parent, parent) != ESRCH {
        return 9;
    }
    // 7. A child that made its own session: EPERM.
    let (ready_r, ready_w) = pipe();
    let (gate2, open2) = pipe();
    let leader = spawn(move || {
        sys::setsid();
        sys::write(ready_w, b"s");
        let mut b = [0u8; 1];
        sys::read(gate2, &mut b);
        0
    });
    if await_byte(ready_r).is_none() || sys::setpgid(leader, leader) != EPERM {
        return 10;
    }
    sys::write(open2, b"x");
    reap(leader);
    // 7a. A group leader that is no session leader cannot make a session
    //    (a group with its PID exists).
    let grouped = spawn(|| {
        if sys::setpgid(0, 0) != 0 || sys::setsid() != EPERM {
            return 1;
        }
        0
    });
    if outcome(reap(grouped)) != 0 {
        return 10;
    }
    // 7b. A child left in the old session when its parent makes a new one
    //    is in another session, though no leader: EPERM.
    let middle = spawn(|| {
        let (gate, open) = pipe();
        let grandchild = waiter(gate);
        let result = if sys::setsid() <= 0 || sys::setpgid(grandchild, grandchild) != EPERM {
            1
        } else {
            0
        };
        sys::write(open, b"x");
        reap(grandchild);
        result
    });
    if outcome(reap(middle)) != 0 {
        return 10;
    }
    // 8. A child that has called execve: EACCES.
    let (ready_r, ready_w) = pipe();
    let execed = spawn(move || {
        let mut fd = *b"00\0";
        fd[0] = b'0' + ready_w as u8 / 10;
        fd[1] = b'0' + ready_w as u8 % 10;
        let fd = CStr::from_bytes_until_nul(&fd).unwrap_or(c"0");
        let mut exe = [0u8; 256];
        let len = argv0.len().min(255);
        exe[..len].copy_from_slice(&argv0[..len]);
        let path = CStr::from_bytes_until_nul(&exe).unwrap_or(c"/test/jobprobe");
        sys::execve(path, Some(&[path, c"sleeper", fd]), &[]);
        99
    });
    if await_byte(ready_r).is_none() || sys::setpgid(execed, execed) != EACCES {
        return 11;
    }
    sys::kill(execed, SIGTERM);
    reap(execed);
    // 9. kill with 0 and -group: signal 0 checks there are members.
    sys::setpgid(g, g);
    if sys::kill(-g, 0) != 0 || sys::kill(-NOBODY, 0) != ESRCH || sys::kill(0, 0) != 0 {
        return 12;
    }
    sys::write(open, b"x");
    reap(g);
    // 10. A whole group killed at once.
    let (gate, open) = pipe();
    let a = waiter(gate);
    let b = waiter(gate);
    sys::setpgid(a, a);
    sys::setpgid(b, a);
    if sys::kill(-a, SIGTERM) != 0 {
        return 13;
    }
    if outcome(reap(a)) != 1000 + SIGTERM || outcome(reap(b)) != 1000 + SIGTERM {
        return 14;
    }
    if sys::kill(-a, 0) != ESRCH {
        return 15;
    }
    sys::close(gate);
    sys::close(open);
    // 11. wait4 by group: 0 is the caller's group, -G group G.
    let (gate, open) = pipe();
    let a = spawn(move || {
        let mut b = [0u8; 1];
        sys::read(gate, &mut b);
        7
    });
    sys::setpgid(a, a);
    let b = spawn(move || {
        let mut b = [0u8; 1];
        sys::read(gate, &mut b);
        8
    });
    sys::write(open, b"xx");
    let mut st = 0;
    if sys::wait4(-a, &mut st, 0) != i64::from(a) || (st >> 8) & 0xff != 7 {
        return 16;
    }
    if sys::wait4(0, &mut st, 0) != i64::from(b) || (st >> 8) & 0xff != 8 {
        return 17;
    }
    if sys::wait4(-a, &mut st, 0) != ECHILD || sys::wait4(0, &mut st, 0) != ECHILD {
        return 18;
    }
    // A child that has exited in another group is not the caller's group's.
    let a = spawn(|| 7);
    sys::setpgid(a, a);
    nap(100);
    if sys::wait4(0, &mut st, 1) != ECHILD || sys::wait4(-a, &mut st, 0) != i64::from(a) {
        return 18;
    }
    // 12. kill(-1, 0): some process can be signalled.
    if sys::kill(-1, 0) != 0 {
        return 19;
    }
    0
}

fn ctty(_: &[u8]) -> i32 {
    let me = pid();
    let Some((m, s, n)) = openpty() else {
        return 20;
    };
    // 13. Opened with O_NOCTTY: not the controlling terminal. A master
    //    reports the slave's group (none: 0) but no session.
    if int_ioctl(s, TIOCGPGRP) != Err(ENOTTY) || int_ioctl(s, TIOCGSID) != Err(ENOTTY) {
        return 21;
    }
    if int_ioctl(m, TIOCGPGRP) != Ok(0) || int_ioctl(m, TIOCGSID) != Err(ENOTTY) {
        return 22;
    }
    if sys::open(c"/dev/tty", O_RDWR, 0) != ENXIO {
        return 23;
    }
    // 14. TIOCSCTTY: the caller's session and group become the terminal's,
    //    seen from the slave and the master; again, nothing changes.
    if sys::ioctl_value(s, TIOCSCTTY, 0) != 0 || sys::ioctl_value(s, TIOCSCTTY, 0) != 0 {
        return 24;
    }
    if int_ioctl(s, TIOCGPGRP) != Ok(me)
        || int_ioctl(s, TIOCGSID) != Ok(me)
        || int_ioctl(m, TIOCGPGRP) != Ok(me)
        || int_ioctl(m, TIOCGSID) != Ok(me)
    {
        return 25;
    }
    // 15. /dev/tty is it: 5:0, and writes reach the master.
    let tty = sys::open(c"/dev/tty", O_RDWR, 0);
    if tty < 0 {
        return 26;
    }
    let mut st = [0u8; 144];
    sys::fstat(tty as i32, &mut st);
    let rdev = u64::from_le_bytes(st[40..48].try_into().unwrap_or([0; 8]));
    if rdev != 0x500 || sys::write(tty as i32, b"q") != 1 {
        return 27;
    }
    let mut buf = [0u8; 16];
    if !readable(m, 2000) || sys::read(m, &mut buf) != 1 || buf[0] != b'q' {
        return 28;
    }
    sys::close(tty as i32);
    // 16. A child has it too, but is no leader: TIOCSCTTY is EPERM.
    let child = spawn(move || {
        if int_ioctl(s, TIOCGPGRP) != Ok(me) || sys::ioctl_value(s, TIOCSCTTY, 0) != EPERM {
            return 1;
        }
        let tty = sys::open(c"/dev/tty", O_RDWR, 0);
        if tty < 0 {
            return 2;
        }
        0
    });
    if outcome(reap(child)) != 0 {
        return 29;
    }
    // 17. A leader with a controlling terminal cannot take another.
    let Some((m2, s2, _)) = openpty() else {
        return 30;
    };
    if sys::ioctl_value(s2, TIOCSCTTY, 0) != EPERM || set_int(s2, TIOCSPGRP, me) != ENOTTY {
        return 31;
    }
    sys::close(m2);
    sys::close(s2);
    // 18. TIOCSPGRP: a group of the session becomes the foreground.
    let (gate, open) = pipe();
    let g = waiter(gate);
    sys::setpgid(g, g);
    if set_int(s, TIOCSPGRP, g) != 0 || int_ioctl(s, TIOCGPGRP) != Ok(g) {
        return 32;
    }
    // 19. Now in the background, with SIGTTOU at its default and the
    //    caller's group orphaned (its parent is in another session),
    //    setting the group is ENOTTY (the check's EIO). With SIGTTOU
    //    ignored the request is checked: EINVAL, ESRCH, EPERM for a
    //    process of another session; then it takes the foreground back.
    if set_int(s, TIOCSPGRP, me) != ENOTTY {
        return 33;
    }
    disposition(SIGTTOU, 1);
    let parent = sys::getppid() as i32;
    if set_int(s, TIOCSPGRP, -1) != EINVAL
        || set_int(s, TIOCSPGRP, NOBODY) != ESRCH
        || set_int(s, TIOCSPGRP, parent) != EPERM
    {
        return 34;
    }
    if set_int(s, TIOCSPGRP, me) != 0 || int_ioctl(s, TIOCGPGRP) != Ok(me) {
        return 35;
    }
    disposition(SIGTTOU, 0);
    sys::write(open, b"x");
    reap(g);
    sys::close(gate);
    sys::close(open);
    // 20. ISIG: ^C, ^\ and TIOCSIG reach the foreground group (each
    //    member) and not the caller in the background.
    for (input, signal, check) in [
        (&b"\x03"[..], SIGINT, 36),
        (b"\x1c", SIGQUIT, 37),
        (b"", SIGINT, 38),
    ] {
        let (gate, open) = pipe();
        let a = waiter(gate);
        let b = waiter(gate);
        sys::setpgid(a, a);
        sys::setpgid(b, a);
        set_int(s, TIOCSPGRP, a);
        if input.is_empty() {
            sys::ioctl_value(m, TIOCSIG, signal as u64);
        } else {
            sys::write(m, input);
        }
        if outcome(reap(a)) != 1000 + signal || outcome(reap(b)) != 1000 + signal {
            return check;
        }
        disposition(SIGTTOU, 1);
        set_int(s, TIOCSPGRP, me);
        disposition(SIGTTOU, 0);
        sys::close(gate);
        sys::close(open);
        // Discard the echo.
        while readable(m, 100) && sys::read(m, &mut buf) > 0 {}
    }
    // 21. ^Z and a window-size change reach a foreground member that
    //    catches SIGTSTP and SIGWINCH; the same size again sends nothing.
    let (gate, open) = pipe();
    let (ready_r, ready_w) = pipe();
    let (report_r, report_w) = pipe();
    let catcher = spawn(move || {
        keel_rt::signal::catch(SIGTSTP);
        keel_rt::signal::catch(SIGWINCH);
        sys::write(ready_w, b"r");
        let mut b = [0u8; 1];
        while sys::read(gate, &mut b) == EINTR {}
        let counts = [
            keel_rt::signal::caught(SIGTSTP) as u8,
            keel_rt::signal::caught(SIGWINCH) as u8,
        ];
        sys::write(report_w, &counts);
        0
    });
    sys::setpgid(catcher, catcher);
    if await_byte(ready_r).is_none() {
        return 39;
    }
    set_int(s, TIOCSPGRP, catcher);
    sys::write(m, b"\x1a");
    nap(100);
    let mut ws = [0u8; 64];
    ws[..8].copy_from_slice(&[30, 0, 100, 0, 0, 0, 0, 0]);
    sys::ioctl(s, TIOCSWINSZ, &mut ws);
    nap(50);
    sys::ioctl(s, TIOCSWINSZ, &mut ws);
    nap(100);
    sys::write(open, b"x");
    let mut counts = [0u8; 2];
    if !readable(report_r, 5000) || sys::read(report_r, &mut counts) != 2 || counts != [1, 1] {
        return 40;
    }
    reap(catcher);
    disposition(SIGTTOU, 1);
    set_int(s, TIOCSPGRP, me);
    disposition(SIGTTOU, 0);
    while readable(m, 100) && sys::read(m, &mut buf) > 0 {}
    // 22. A background reader: SIGTTIN to its group (caught: EINTR);
    //    ignored, EIO. A background writer: allowed without TOSTOP; with
    //    TOSTOP, SIGTTOU (caught: EINTR), or allowed if ignored. Setting
    //    the terminal from the background: SIGTTOU.
    let bg = spawn(move || {
        sys::setpgid(0, 0);
        keel_rt::signal::catch(SIGTTIN);
        keel_rt::signal::catch(SIGTTOU);
        let mut b = [0u8; 8];
        if sys::read(s, &mut b) != EINTR || keel_rt::signal::caught(SIGTTIN) != 1 {
            return 1;
        }
        disposition(SIGTTIN, 1);
        if sys::read(s, &mut b) != EIO {
            return 2;
        }
        if sys::write(s, b"w") != 1 {
            return 3;
        }
        let mut t = [0u8; 64];
        sys::ioctl(s, TCGETS, &mut t);
        let lflag = u32::from_le_bytes([t[12], t[13], t[14], t[15]]) | TOSTOP;
        t[12..16].copy_from_slice(&lflag.to_le_bytes());
        if sys::ioctl(s, TCSETS, &mut t) != EINTR || keel_rt::signal::caught(SIGTTOU) != 1 {
            return 4;
        }
        0
    });
    sys::setpgid(bg, bg);
    if outcome(reap(bg)) != 0 {
        return 41;
    }
    let mut t = [0u8; 64];
    sys::ioctl(s, TCGETS, &mut t);
    let lflag = u32::from_le_bytes([t[12], t[13], t[14], t[15]]) | TOSTOP;
    t[12..16].copy_from_slice(&lflag.to_le_bytes());
    sys::ioctl(s, TCSETS, &mut t);
    let bg = spawn(move || {
        sys::setpgid(0, 0);
        keel_rt::signal::catch(SIGTTOU);
        if sys::write(s, b"w") != EINTR || keel_rt::signal::caught(SIGTTOU) != 1 {
            return 1;
        }
        disposition(SIGTTOU, 1);
        if sys::write(s, b"w") != 1 {
            return 2;
        }
        0
    });
    sys::setpgid(bg, bg);
    if outcome(reap(bg)) != 0 {
        return 42;
    }
    while readable(m, 100) && sys::read(m, &mut buf) > 0 {}
    // 23. The caller in the background of its own terminal: its group is
    //    orphaned, so a read is EIO, with no signal.
    let (gate, open) = pipe();
    let g = waiter(gate);
    sys::setpgid(g, g);
    set_int(s, TIOCSPGRP, g);
    if sys::read(s, &mut buf) != EIO {
        return 43;
    }
    disposition(SIGTTOU, 1);
    set_int(s, TIOCSPGRP, me);
    disposition(SIGTTOU, 0);
    sys::write(open, b"x");
    reap(g);
    // 24. TIOCNOTTY by a child that is no leader: only it loses the
    //    terminal.
    let child = spawn(move || {
        if sys::ioctl_value(s, TIOCNOTTY, 0) != 0 || int_ioctl(s, TIOCGPGRP) != Err(ENOTTY) {
            return 1;
        }
        if sys::open(c"/dev/tty", O_RDWR, 0) != ENXIO {
            return 2;
        }
        // With no terminal, it still is no leader: EPERM, even for a
        // terminal with no session.
        let Some((m3, s3, _)) = openpty() else {
            return 3;
        };
        if sys::ioctl_value(s, TIOCSCTTY, 0) != EPERM || sys::ioctl_value(s3, TIOCSCTTY, 0) != EPERM
        {
            return 3;
        }
        sys::close(m3);
        sys::close(s3);
        0
    });
    if outcome(reap(child)) != 0 || int_ioctl(s, TIOCGPGRP) != Ok(me) {
        return 44;
    }
    // 25. TIOCNOTTY by the leader: its foreground group gets SIGHUP and
    //    SIGCONT, the terminal has no session, and the session's other
    //    processes lose it too.
    let (gate, open) = pipe();
    let (ready_r, ready_w) = pipe();
    let (report_r, report_w) = pipe();
    let member = spawn(move || {
        keel_rt::signal::catch(SIGHUP);
        keel_rt::signal::catch(SIGCONT);
        sys::write(ready_w, b"r");
        let mut b = [0u8; 1];
        while sys::read(gate, &mut b) == EINTR {}
        let gone = sys::open(c"/dev/tty", O_RDWR, 0) == ENXIO;
        let report = [
            keel_rt::signal::caught(SIGHUP) as u8,
            keel_rt::signal::caught(SIGCONT) as u8,
            u8::from(gone),
        ];
        sys::write(report_w, &report);
        0
    });
    sys::setpgid(member, member);
    if await_byte(ready_r).is_none() {
        return 45;
    }
    set_int(s, TIOCSPGRP, member);
    disposition(SIGTTOU, 0);
    if sys::ioctl_value(s, TIOCNOTTY, 0) != 0 {
        return 46;
    }
    nap(100);
    sys::write(open, b"x");
    let mut report = [0u8; 3];
    if !readable(report_r, 5000) || sys::read(report_r, &mut report) != 3 || report != [1, 1, 1] {
        return 47;
    }
    reap(member);
    if int_ioctl(m, TIOCGSID) != Err(ENOTTY) || int_ioctl(s, TIOCGPGRP) != Err(ENOTTY) {
        return 48;
    }
    // 26. Opening the slave without O_NOCTTY makes it the leader's
    //    controlling terminal again, if opened for reading.
    let mut path = [0u8; 32];
    let p = pts_path(n, &mut path);
    let w = sys::open(p, O_WRONLY, 0);
    if w < 0 || int_ioctl(m, TIOCGSID) != Err(ENOTTY) {
        return 49;
    }
    sys::close(w as i32);
    let again = sys::open(p, O_RDWR, 0);
    if again < 0 || int_ioctl(m, TIOCGSID) != Ok(me) || int_ioctl(s, TIOCGPGRP) != Ok(me) {
        return 50;
    }
    sys::close(again as i32);
    // 27. The master closing hangs the slave up: the leader gets SIGHUP and
    //    SIGCONT, and has no controlling terminal after.
    keel_rt::signal::catch(SIGHUP);
    keel_rt::signal::catch(SIGCONT);
    sys::close(m);
    nap(100);
    if keel_rt::signal::caught(SIGHUP) != 1 || keel_rt::signal::caught(SIGCONT) != 1 {
        return 51;
    }
    if sys::open(c"/dev/tty", O_RDWR, 0) != ENXIO {
        return 52;
    }
    sys::close(s);
    0
}

fn leader_exit(_: &[u8]) -> i32 {
    // 28. A session leader's exit: its terminal's foreground group gets
    //    SIGHUP, and loses the terminal.
    let Some((m, s, _)) = openpty() else {
        return 60;
    };
    let (report_r, report_w) = pipe();
    let (ready_r, ready_w) = pipe();
    let leader = spawn(move || {
        sys::setsid();
        if sys::ioctl_value(s, TIOCSCTTY, 0) != 0 {
            return 1;
        }
        let (gate, open) = pipe();
        let (up_r, up_w) = pipe();
        let member = spawn(move || {
            // Its copy of the gate's write end would keep the gate open.
            sys::close(open);
            keel_rt::signal::catch(SIGHUP);
            sys::setpgid(0, 0);
            sys::write(up_w, b"u");
            let mut b = [0u8; 1];
            // Released when the leader has exited: the gate's other end
            // closes with it.
            while sys::read(gate, &mut b) == EINTR {}
            nap(100);
            let report = [
                keel_rt::signal::caught(SIGHUP) as u8,
                u8::from(int_ioctl(s, TIOCGPGRP) == Err(ENOTTY)),
            ];
            sys::write(report_w, &report);
            0
        });
        sys::close(gate);
        if await_byte(up_r).is_none() {
            return 2;
        }
        sys::setpgid(member, member);
        if set_int(s, TIOCSPGRP, member) != 0 {
            return 3;
        }
        sys::write(ready_w, b"r");
        let _ = open;
        0
    });
    sys::close(report_w);
    if await_byte(ready_r).is_none() || outcome(reap(leader)) != 0 {
        return 61;
    }
    let mut report = [0u8; 2];
    if !readable(report_r, 5000) || sys::read(report_r, &mut report) != 2 || report != [1, 1] {
        return 62;
    }
    sys::close(m);
    sys::close(s);
    0
}

fn main(startup: &Startup) -> i32 {
    let mut args = startup.args();
    let argv0 = args.next().unwrap_or(b"/test/jobprobe");
    if args.next() == Some(b"sleeper") {
        let fd = args.next().map_or(-1, |d| {
            d.iter()
                .fold(0i32, |n, &c| n * 10 + i32::from(c.wrapping_sub(b'0')))
        });
        sys::write(fd, b"e");
        loop {
            nap(10_000);
        }
    }
    for part in [ids, ctty, leader_exit] {
        let failed = in_session(part, argv0);
        if failed != 0 {
            return failed;
        }
    }
    sys::write(1, b"jobprobe: 62 checks passed\n");
    0
}

keel_rt::main!(main);
