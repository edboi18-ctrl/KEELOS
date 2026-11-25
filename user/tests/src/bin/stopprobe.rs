//! Job control's stop and continue, SIGCHLD and the restart of interrupted
//! calls, checked against Linux. Runs under Linux (`host.stopprobe`) and
//! on Keel (`exec.stop_continue`) and must pass on both.
//!
//! Semantics from signal(7) (stop and continue, SIGCHLD), wait(2)
//! (WUNTRACED, WCONTINUED), sigaction(2) (SA_RESTART, SA_NOCLDSTOP,
//! SA_NOCLDWAIT, SIG_IGN for SIGCHLD), credentials(7) (orphaned groups)
//! and Linux v6.12's `kernel/signal.c` (`prepare_signal`, `get_signal`,
//! `do_signal_stop`, `do_notify_parent_cldstop`, `do_notify_parent`),
//! `kernel/exit.c` (`kill_orphaned_pgrp`, `wait_task_stopped`,
//! `wait_task_continued`) and `arch/x86/kernel/signal.c` (restart).
//!
//! It runs in a child that makes its own session, so the groups it makes
//! have a known relation: a child in its own group has its parent in
//! another group of the same session (not orphaned), while the session
//! leader's own group is orphaned (its parent is outside the session).
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, Arg, Out};

const EINTR: i64 = -4;
const ECHILD: i64 = -10;

const WNOHANG: u32 = 1;
const WUNTRACED: u32 = 2;
const WCONTINUED: u32 = 8;

const SIGHUP: i32 = 1;
const SIGKILL: i32 = 9;
const SIGUSR1: i32 = 10;
const SIGCHLD: i32 = 17;
const SIGCONT: i32 = 18;
const SIGSTOP: i32 = 19;
const SIGTSTP: i32 = 20;
const SIGTTIN: i32 = 21;
const SIGTTOU: i32 = 22;

const SA_NOCLDSTOP: u64 = 1;
const SA_NOCLDWAIT: u64 = 2;
const SA_RESTART: u64 = 0x1000_0000;
const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;

const POLLIN: u16 = 1;

fn nap(ms: i32) {
    sys::poll(&mut [], ms);
}

/// Whether `fd` becomes readable within about `ms`. A poll a caught
/// signal (SIGCHLD here) cuts short is EINTR, not an answer: it is
/// tried again.
fn readable(fd: i32, ms: i32) -> bool {
    let mut e = [0u8; 8];
    e[..4].copy_from_slice(&fd.to_le_bytes());
    e[4..6].copy_from_slice(&POLLIN.to_le_bytes());
    for _ in 0..100 {
        let mut fds = [e];
        if sys::poll(&mut fds, ms) != EINTR {
            return u16::from_le_bytes([fds[0][6], fds[0][7]]) & POLLIN != 0;
        }
    }
    false
}

fn pipe() -> (i32, i32) {
    let mut fds = [-1i32; 2];
    sys::pipe2(&mut fds, None);
    (fds[0], fds[1])
}

fn disposition(signal: i32, handler: u64, flags: u64) {
    let mut act = [0u8; 32];
    act[..8].copy_from_slice(&handler.to_le_bytes());
    act[8..16].copy_from_slice(&flags.to_le_bytes());
    sys::rt_sigaction(signal, Arg::Buf(&act), Out::Null, 8);
}

fn mask(how: i32, signal: i32) {
    let set = 1u64 << (signal - 1);
    sys::rt_sigprocmask(how, Arg::Buf(&set), Out::Null, 8);
}

fn spawn(body: impl FnOnce() -> i32) -> i32 {
    let child = sys::fork();
    if child == 0 {
        keel_rt::exit(body());
    }
    child as i32
}

/// wait4 on `pid` with `options`: (its result, the status).
fn wait(pid: i32, options: u32) -> (i64, i32) {
    let mut status = 0;
    let r = sys::wait4(pid, &mut status, options);
    (r, status)
}

/// Waits (up to 5 s, polling) for `pid` to report with `options`.
fn wait_for(pid: i32, options: u32) -> (i64, i32) {
    for _ in 0..500 {
        let (r, status) = wait(pid, options | WNOHANG);
        if r != 0 {
            return (r, status);
        }
        nap(10);
    }
    (0, 0)
}

const fn stopped(signal: i32) -> i32 {
    (signal << 8) | 0x7f
}

/// A child in a group of its own (so not orphaned) that reads `gate` and
/// exits with what the read returned, 100 for EINTR.
fn reader(gate: i32) -> i32 {
    let c = spawn(move || {
        // Not the parent's SIGCHLD handler: SIGCHLD is ignored here.
        disposition(SIGCHLD, 0, 0);
        let mut b = [0u8; 1];
        match sys::read(gate, &mut b) {
            1 => 0,
            EINTR => 100,
            _ => 101,
        }
    });
    sys::setpgid(c, c);
    c
}

fn stop_and_continue() -> i32 {
    keel_rt::signal::catch(SIGCHLD);
    // 1. SIGSTOP stops a child: wait4 with WUNTRACED reports it once
    //    (status SIGSTOP << 8 | 0x7f), and the parent gets SIGCHLD.
    let (gate, open) = pipe();
    let c = reader(gate);
    nap(50);
    let before = keel_rt::signal::caught(SIGCHLD);
    sys::kill(c, SIGSTOP);
    if wait_for(c, WUNTRACED) != (i64::from(c), stopped(SIGSTOP)) {
        return 2;
    }
    if wait(c, WUNTRACED | WNOHANG).0 != 0 {
        return 3;
    }
    nap(50);
    if keel_rt::signal::caught(SIGCHLD) != before + 1 {
        return 4;
    }
    // 2. A stopped child is not continued by other signals; SIGCONT
    //    continues it, wait4 with WCONTINUED reports that once (0xffff),
    //    the parent gets SIGCHLD again, and WUNTRACED no longer sees the
    //    stop.
    sys::kill(c, SIGCHLD);
    nap(50);
    sys::kill(c, SIGCONT);
    if wait_for(c, WCONTINUED) != (i64::from(c), 0xffff) {
        return 5;
    }
    if wait(c, WCONTINUED | WUNTRACED | WNOHANG).0 != 0 {
        return 6;
    }
    nap(50);
    if keel_rt::signal::caught(SIGCHLD) != before + 2 {
        return 7;
    }
    // 3. The read it was blocked in goes on: no handler ran, so it is
    //    restarted (ERESTARTSYS), and returns the byte.
    sys::write(open, b"x");
    if wait(c, 0) != (i64::from(c), 0) {
        return 8;
    }
    sys::close(gate);
    sys::close(open);
    // 4. SIGTSTP, SIGTTIN and SIGTTOU stop by default too; SIGKILL ends a
    //    stopped process.
    for (signal, check) in [(SIGTSTP, 9), (SIGTTIN, 10), (SIGTTOU, 11)] {
        let (gate, open) = pipe();
        let c = reader(gate);
        nap(20);
        sys::kill(c, signal);
        if wait_for(c, WUNTRACED) != (i64::from(c), stopped(signal)) {
            return check;
        }
        sys::kill(c, SIGKILL);
        if wait(c, 0) != (i64::from(c), SIGKILL) {
            return check;
        }
        sys::close(gate);
        sys::close(open);
    }
    // 5. Without WUNTRACED a stop is not reported: WNOHANG returns 0.
    let (gate, open) = pipe();
    let c = reader(gate);
    nap(20);
    sys::kill(c, SIGSTOP);
    nap(100);
    if wait(c, WNOHANG).0 != 0 {
        return 12;
    }
    sys::kill(c, SIGKILL);
    wait(c, 0);
    sys::close(gate);
    sys::close(open);
    // 6. SA_NOCLDSTOP: no SIGCHLD for a stop or a continue.
    keel_rt::signal::catch_with(SIGCHLD, SA_NOCLDSTOP);
    let (gate, open) = pipe();
    let c = reader(gate);
    nap(20);
    let before = keel_rt::signal::caught(SIGCHLD);
    sys::kill(c, SIGSTOP);
    wait_for(c, WUNTRACED);
    sys::kill(c, SIGCONT);
    wait_for(c, WCONTINUED);
    nap(50);
    if keel_rt::signal::caught(SIGCHLD) != before {
        return 13;
    }
    // ... but its exit still sends SIGCHLD.
    sys::write(open, b"x");
    wait(c, 0);
    nap(50);
    if keel_rt::signal::caught(SIGCHLD) != before + 1 {
        return 14;
    }
    sys::close(gate);
    sys::close(open);
    keel_rt::signal::catch(SIGCHLD);
    // 15. A stopped process does not run: a child writing a byte every
    //     10 ms writes nothing while stopped, and goes on when continued.
    let (tick_r, tick_w) = pipe();
    let ticker = spawn(move || {
        disposition(SIGCHLD, 0, 0);
        loop {
            sys::write(tick_w, b"t");
            nap(10);
        }
    });
    sys::setpgid(ticker, ticker);
    if !readable(tick_r, 5000) {
        return 45;
    }
    sys::kill(ticker, SIGSTOP);
    wait_for(ticker, WUNTRACED);
    let mut buf = [0u8; 256];
    while readable(tick_r, 50) {
        sys::read(tick_r, &mut buf);
    }
    if readable(tick_r, 300) {
        return 45;
    }
    sys::kill(ticker, SIGCONT);
    if !readable(tick_r, 2000) {
        return 46;
    }
    sys::kill(ticker, SIGKILL);
    wait(ticker, 0);
    0
}

fn pending_rules() -> i32 {
    // 7. SIGCONT discards a pending stop signal: a child that blocks
    //    SIGTSTP gets one, then SIGCONT; unblocking, it does not stop.
    let (ready_r, ready_w) = pipe();
    let (gate, open) = pipe();
    let c = spawn(move || {
        mask(SIG_BLOCK, SIGTSTP);
        sys::write(ready_w, b"r");
        let mut b = [0u8; 1];
        sys::read(gate, &mut b);
        mask(SIG_UNBLOCK, SIGTSTP);
        0
    });
    sys::setpgid(c, c);
    if !readable(ready_r, 5000) {
        return 20;
    }
    sys::kill(c, SIGTSTP);
    sys::kill(c, SIGCONT);
    sys::write(open, b"x");
    if wait_for(c, WUNTRACED) != (i64::from(c), 0) {
        return 21;
    }
    sys::close(ready_r);
    sys::close(gate);
    sys::close(open);
    // 8. A SIGCONT handler runs once the process goes on; a signal sent
    //    while it is stopped is taken after.
    let (gate, open) = pipe();
    let (report_r, report_w) = pipe();
    let (ready_r, ready_w) = pipe();
    let c = spawn(move || {
        keel_rt::signal::catch(SIGCONT);
        keel_rt::signal::catch(SIGUSR1);
        sys::write(ready_w, b"r");
        let mut b = [0u8; 1];
        while sys::read(gate, &mut b) == EINTR {}
        let counts = [
            keel_rt::signal::caught(SIGCONT) as u8,
            keel_rt::signal::caught(SIGUSR1) as u8,
        ];
        sys::write(report_w, &counts);
        0
    });
    sys::setpgid(c, c);
    if !readable(ready_r, 5000) {
        return 22;
    }
    sys::kill(c, SIGSTOP);
    wait_for(c, WUNTRACED);
    sys::kill(c, SIGUSR1);
    nap(50);
    sys::kill(c, SIGCONT);
    wait_for(c, WCONTINUED);
    nap(50);
    sys::write(open, b"x");
    let mut counts = [0u8; 2];
    if !readable(report_r, 5000) || sys::read(report_r, &mut counts) != 2 || counts != [1, 1] {
        return 23;
    }
    wait(c, 0);
    // 9. In an orphaned group (this session leader's own) SIGTSTP is
    //    discarded; SIGSTOP still stops.
    let (gate, open) = pipe();
    let c = spawn(move || {
        let mut b = [0u8; 1];
        sys::read(gate, &mut b);
        0
    });
    nap(20);
    sys::kill(c, SIGTSTP);
    nap(100);
    if wait(c, WUNTRACED | WNOHANG).0 != 0 {
        return 24;
    }
    sys::kill(c, SIGSTOP);
    if wait_for(c, WUNTRACED) != (i64::from(c), stopped(SIGSTOP)) {
        return 25;
    }
    sys::kill(c, SIGCONT);
    sys::write(open, b"x");
    if wait(c, 0) != (i64::from(c), 0) {
        return 26;
    }
    0
}

fn restart_and_reaping() -> i32 {
    // 10. A handler with SA_RESTART: the interrupted read is restarted;
    //     without, it is EINTR.
    for (flags, want, check) in [(SA_RESTART, 0, 30), (0, 100, 31)] {
        let (gate, open) = pipe();
        let (ready_r, ready_w) = pipe();
        let c = spawn(move || {
            keel_rt::signal::catch_with(SIGUSR1, flags);
            sys::write(ready_w, b"r");
            let mut b = [0u8; 1];
            match sys::read(gate, &mut b) {
                1 => 0,
                EINTR => 100,
                _ => 101,
            }
        });
        if !readable(ready_r, 5000) {
            return check;
        }
        nap(20);
        sys::kill(c, SIGUSR1);
        nap(50);
        sys::write(open, b"x");
        if wait(c, 0) != (i64::from(c), want << 8) {
            return check;
        }
        sys::close(gate);
        sys::close(open);
        sys::close(ready_r);
    }
    // 11. SIGCHLD ignored: children are not kept as zombies; wait4 waits
    //     for them and then is ECHILD.
    disposition(SIGCHLD, 1, 0);
    let a = spawn(|| 3);
    let _ = a;
    if wait(-1, 0).0 != ECHILD {
        return 32;
    }
    // 12. SA_NOCLDWAIT with a handler: the handler runs, no zombie.
    keel_rt::signal::catch_with(SIGCHLD, SA_NOCLDWAIT);
    let before = keel_rt::signal::caught(SIGCHLD);
    spawn(|| 4);
    if wait(-1, 0).0 != ECHILD {
        return 33;
    }
    nap(50);
    if keel_rt::signal::caught(SIGCHLD) != before + 1 {
        return 34;
    }
    disposition(SIGCHLD, 0, 0);
    // 13. A stopped job its group's exit leaves orphaned gets SIGHUP and
    //     SIGCONT: a middle process in its own group starts a child that
    //     stops itself, then exits; the child, continued, takes SIGHUP.
    let (report_r, report_w) = pipe();
    let middle = spawn(move || {
        sys::setpgid(0, 0);
        let (up_r, up_w) = pipe();
        let worker = spawn(move || {
            keel_rt::signal::catch(SIGHUP);
            sys::write(up_w, b"u");
            sys::kill(sys::getpid() as i32, SIGSTOP);
            // Continued: SIGHUP's handler has run.
            let report = [keel_rt::signal::caught(SIGHUP) as u8];
            sys::write(report_w, &report);
            0
        });
        if !readable(up_r, 5000) {
            return 1;
        }
        if wait_for(worker, WUNTRACED) != (i64::from(worker), stopped(SIGSTOP)) {
            return 2;
        }
        0
    });
    sys::close(report_w);
    if wait(middle, 0) != (i64::from(middle), 0) {
        return 35;
    }
    let mut report = [0u8; 1];
    if !readable(report_r, 5000) || sys::read(report_r, &mut report) != 1 || report != [1] {
        return 36;
    }
    0
}

fn background_reader() -> i32 {
    const O_NOCTTY: u64 = 0o400;
    const TIOCGPTN: u64 = 0x8004_5430;
    const TIOCSPTLCK: u64 = 0x4004_5431;
    const TIOCSCTTY: u64 = 0x540E;
    const TIOCSPGRP: u64 = 0x5410;
    // 14. A background job reading its terminal with SIGTTIN at its
    //     default stops (SIGTTIN); made the foreground and continued, its
    //     read is restarted and gets the line.
    let m = sys::open(c"/dev/ptmx", sys::O_RDWR | O_NOCTTY, 0);
    if m < 0 {
        return 40;
    }
    let m = m as i32;
    let mut b = [0u8; 64];
    sys::ioctl(m, TIOCGPTN, &mut b);
    let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let mut lock = [0u8; 64];
    sys::ioctl(m, TIOCSPTLCK, &mut lock);
    // "/dev/pts/N": N's digits, most significant first.
    let mut path = *b"/dev/pts/\0\0\0\0\0\0\0\0\0\0\0";
    let mut digits = [0u8; 10];
    let (mut len, mut v) = (0, n);
    loop {
        digits[len] = b'0' + (v % 10) as u8;
        len += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..len {
        path[9 + i] = digits[len - 1 - i];
    }
    let p = core::ffi::CStr::from_bytes_until_nul(&path).unwrap_or(c"/dev/pts/0");
    let s = sys::open(p, sys::O_RDWR | O_NOCTTY, 0);
    if s < 0 || sys::ioctl_value(s as i32, TIOCSCTTY, 0) != 0 {
        return 41;
    }
    let s = s as i32;
    let bg = spawn(move || {
        sys::setpgid(0, 0);
        let mut buf = [0u8; 16];
        if sys::read(s, &mut buf) == 2 && &buf[..2] == b"x\n" {
            0
        } else {
            1
        }
    });
    sys::setpgid(bg, bg);
    if wait_for(bg, WUNTRACED) != (i64::from(bg), stopped(SIGTTIN)) {
        return 42;
    }
    let mut fg = [0u8; 64];
    fg[..4].copy_from_slice(&bg.to_le_bytes());
    if sys::ioctl(s, TIOCSPGRP, &mut fg) != 0 {
        return 43;
    }
    sys::kill(bg, SIGCONT);
    sys::write(m, b"x\n");
    if wait(bg, 0) != (i64::from(bg), 0) {
        return 44;
    }
    // Closing the master hangs up this session leader's terminal, which
    // sends it SIGHUP.
    disposition(SIGHUP, 1, 0);
    sys::close(s);
    sys::close(m);
    0
}

fn main(_: &Startup) -> i32 {
    for part in [
        stop_and_continue,
        pending_rules,
        restart_and_reaping,
        background_reader,
    ] {
        let child = spawn(move || {
            // 1. A session of its own (see above).
            if sys::setsid() <= 0 {
                return 1;
            }
            part()
        });
        let (r, status) = wait(child, 0);
        if r != i64::from(child) || status != 0 {
            return if status & 0x7f == 0 {
                (status >> 8) & 0xff
            } else {
                200 + (status & 0x7f)
            };
        }
    }
    sys::write(1, b"stopprobe: 46 checks passed\n");
    0
}

keel_rt::main!(main);
