//! nanosleep(2), clock_nanosleep(2), restart_syscall(2) and
//! rt_sigsuspend(2), checked
//! against Linux (P3-T13 part 2, ADR 0033). Runs under Linux
//! (`host.sleepprobe`) and on Keel (`exec.sleep`) and must pass on both.
//!
//! Semantics from nanosleep(2), clock_nanosleep(2), restart_syscall(2)
//! and Linux v6.12's `kernel/time/hrtimer.c` and
//! `kernel/time/posix-timers.c`. Times are measured with CLOCK_MONOTONIC
//! and checked with wide margins, so a slow machine does not fail them.
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, Arg, Hostile, Out};

const EINTR: i64 = -4;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EOPNOTSUPP: i64 = -95;

const SIGUSR1: i32 = 10;
const SIGUSR2: i32 = 12;
const SIG_BLOCK: i32 = 0;
const SIG_SETMASK: i32 = 2;
const SIGCONT: i32 = 18;
const SIGSTOP: i32 = 19;
const WUNTRACED: u32 = 2;
const TIMER_ABSTIME: u32 = 1;

const MS: i64 = 1_000_000;

fn ts(nanos: i64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&(nanos / 1_000_000_000).to_le_bytes());
    b[8..].copy_from_slice(&(nanos % 1_000_000_000).to_le_bytes());
    b
}

fn raw_ts(sec: i64, nsec: i64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&sec.to_le_bytes());
    b[8..].copy_from_slice(&nsec.to_le_bytes());
    b
}

fn nanos_of(b: &[u8; 16]) -> i64 {
    let sec = i64::from_le_bytes(b[..8].try_into().unwrap_or_default());
    let nsec = i64::from_le_bytes(b[8..].try_into().unwrap_or_default());
    sec * 1_000_000_000 + nsec
}

fn now() -> i64 {
    let mut b = [0u8; 16];
    sys::clock_gettime(1, &mut b);
    nanos_of(&b)
}

fn nap(ms: i32) {
    sys::poll(&mut [], ms);
}

/// Forks a child that runs `body` and exits with what it returns.
fn spawn(body: impl FnOnce() -> i32) -> i32 {
    let child = sys::fork();
    if child == 0 {
        keel_rt::exit(body());
    }
    child as i32
}

fn exit_code(pid: i32) -> i32 {
    let mut status = 0;
    loop {
        let r = sys::wait4(pid, &mut status, 0);
        if r == i64::from(pid) {
            break;
        }
        if r != EINTR {
            return 200;
        }
    }
    if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        100 + (status & 0x7f)
    }
}

fn main(_: &Startup) -> i32 {
    // 1. A relative sleep lasts at least its request and returns 0.
    let t0 = now();
    if sys::nanosleep(&ts(50 * MS), None) != 0 || now() - t0 < 50 * MS {
        return 1;
    }
    // 2. The request is checked: EFAULT, then a negative tv_sec or a
    //    tv_nsec outside 0..1e9 EINVAL (`timespec64_valid`).
    let Some(bad) = Hostile::new(8) else {
        return 2;
    };
    if sys::nanosleep_from(bad) != EFAULT
        || sys::nanosleep(&raw_ts(0, 1_000_000_000), None) != EINVAL
        || sys::nanosleep(&raw_ts(0, -1), None) != EINVAL
        || sys::nanosleep(&raw_ts(-1, 0), None) != EINVAL
    {
        return 2;
    }
    // 3. A zero request returns at once.
    if sys::nanosleep(&ts(0), None) != 0 {
        return 3;
    }
    // 4. clock_nanosleep's clocks: MONOTONIC_RAW and the COARSE clocks
    //    cannot sleep (EOPNOTSUPP, before the request is read); a number
    //    past the table is EINVAL.
    if sys::clock_nanosleep(4, 0, &ts(0), None) != EOPNOTSUPP
        || sys::clock_nanosleep(5, 0, &ts(0), None) != EOPNOTSUPP
        || sys::clock_nanosleep(6, 0, &raw_ts(0, -1), None) != EOPNOTSUPP
        || sys::clock_nanosleep(12, 0, &ts(0), None) != EINVAL
        || sys::clock_nanosleep(1, 0, &raw_ts(-1, 0), None) != EINVAL
    {
        return 4;
    }
    // 5. Relative sleeps on CLOCK_REALTIME, CLOCK_MONOTONIC and
    //    CLOCK_BOOTTIME.
    for clock in [0, 1, 7] {
        let t0 = now();
        if sys::clock_nanosleep(clock, 0, &ts(20 * MS), None) != 0 || now() - t0 < 20 * MS {
            return 5;
        }
    }
    // 6. TIMER_ABSTIME: until a CLOCK_MONOTONIC time; one already past
    //    returns at once. Flags other than TIMER_ABSTIME are ignored.
    let t0 = now();
    if sys::clock_nanosleep(1, TIMER_ABSTIME, &ts(t0 + 50 * MS), None) != 0
        || now() - t0 < 50 * MS
        || sys::clock_nanosleep(1, TIMER_ABSTIME, &ts(t0), None) != 0
        || sys::clock_nanosleep(1, 0x100, &ts(MS), None) != 0
    {
        return 6;
    }
    // 7. restart_syscall with nothing to resume is EINTR
    //    (`do_no_restart_syscall`), also after a sleep that completed.
    if sys::restart_syscall() != EINTR {
        return 7;
    }
    // 8. A signal with a handler cuts a relative sleep short: EINTR, and
    //    the time left in `rem`.
    let me = sys::getpid() as i32;
    keel_rt::signal::catch(SIGUSR1);
    let sender = spawn(move || {
        nap(100);
        sys::kill(me, SIGUSR1);
        0
    });
    let mut rem = [0u8; 16];
    let t0 = now();
    let r = sys::nanosleep(&ts(5000 * MS), Some(&mut rem));
    let slept = now() - t0;
    let left = nanos_of(&rem);
    if r != EINTR
        || keel_rt::signal::caught(SIGUSR1) != 1
        || left <= 0
        || left > 5000 * MS - slept + 50 * MS
        || exit_code(sender) != 0
    {
        return 8;
    }
    // 9. An absolute sleep cut short by a handler is EINTR and leaves
    //    `rem` alone.
    let sender = spawn(move || {
        nap(100);
        sys::kill(me, SIGUSR1);
        0
    });
    let mut rem = raw_ts(77, 77);
    let r = sys::clock_nanosleep(1, TIMER_ABSTIME, &ts(now() + 5000 * MS), Some(&mut rem));
    if r != EINTR || rem != raw_ts(77, 77) || exit_code(sender) != 0 {
        return 9;
    }
    // 10. Stopped and continued with no handler, a relative sleep goes on
    //     to its first deadline (restart_syscall with the time left): it
    //     returns 0, not EINTR, and not a whole request later. The child
    //     sleeps 300 ms; it is stopped at about 100 ms and continued at
    //     about 400 ms, after its deadline, so it returns soon after.
    for absolute in [false, true] {
        let sleeper = spawn(move || {
            let t0 = now();
            let r = if absolute {
                sys::clock_nanosleep(1, TIMER_ABSTIME, &ts(t0 + 300 * MS), None)
            } else {
                sys::nanosleep(&ts(300 * MS), None)
            };
            let slept = now() - t0;
            match r {
                0 if slept < 300 * MS => 3,
                0 if slept >= 650 * MS => 2,
                0 => 0,
                EINTR => 1,
                _ => 4,
            }
        });
        nap(100);
        sys::kill(sleeper, SIGSTOP);
        let mut status = 0;
        if sys::wait4(sleeper, &mut status, WUNTRACED) != i64::from(sleeper)
            || status & 0xff != 0x7f
        {
            return 10;
        }
        nap(300);
        sys::kill(sleeper, SIGCONT);
        if exit_code(sleeper) != 0 {
            return 11;
        }
    }
    // 12. A signal with no handler that does not stop (SIGCONT, ignored
    //     by default) does not end a sleep either.
    let sleeper = spawn(|| {
        let t0 = now();
        let r = sys::nanosleep(&ts(300 * MS), None);
        i32::from(!(r == 0 && now() - t0 >= 300 * MS))
    });
    nap(100);
    sys::kill(sleeper, SIGCONT);
    if exit_code(sleeper) != 0 {
        return 12;
    }
    // 13. rt_sigsuspend: a size other than 8 EINVAL, an unreadable mask
    //     EFAULT (`sys_rt_sigsuspend`).
    let none = 0u64;
    let Some(bad) = Hostile::new(8) else {
        return 13;
    };
    if sys::rt_sigsuspend(Arg::Buf(&none), 7) != EINVAL
        || sys::rt_sigsuspend(Arg::Hostile(bad), 8) != EFAULT
    {
        return 13;
    }
    // 14. The temporary mask is the one in force: SIGUSR1, which it
    //     blocks, sent at 50 ms, does not end the wait (though the caller's
    //     own mask lets it through); SIGUSR2, at 200 ms, does, with EINTR
    //     after its handler.
    keel_rt::signal::catch(SIGUSR2);
    let usr1 = keel_rt::signal::caught(SIGUSR1);
    let sender = spawn(move || {
        nap(50);
        sys::kill(me, SIGUSR1);
        nap(150);
        sys::kill(me, SIGUSR2);
        0
    });
    let only_usr1 = 1u64 << (SIGUSR1 - 1);
    let t0 = now();
    let r = sys::rt_sigsuspend(Arg::Buf(&only_usr1), 8);
    let waited = now() - t0;
    if r != EINTR || keel_rt::signal::caught(SIGUSR2) != 1 || waited < 150 * MS {
        return 14;
    }
    // 15. Afterwards the caller's mask is back (nothing blocked), so the
    //     held SIGUSR1 has been delivered on the way out (when SIGUSR2's
    //     handler returned and its frame put that mask back).
    let mut now_blocked = u64::MAX;
    sys::rt_sigprocmask(SIG_BLOCK, Arg::Null, Out::Buf(&mut now_blocked), 8);
    if now_blocked != 0 || keel_rt::signal::caught(SIGUSR1) != usr1 + 1 || exit_code(sender) != 0 {
        return 15;
    }
    // 16. A signal already pending that the new mask does not block ends
    //     the wait at once: SIGUSR1, blocked and sent, then let through
    //     only by the temporary mask. After its handler the caller's mask
    //     (SIGUSR1 blocked) is back.
    let usr1 = keel_rt::signal::caught(SIGUSR1);
    sys::rt_sigprocmask(SIG_BLOCK, Arg::Buf(&only_usr1), Out::Null, 8);
    sys::kill(me, SIGUSR1);
    let t0 = now();
    let r = sys::rt_sigsuspend(Arg::Buf(&none), 8);
    let mut after = 0u64;
    sys::rt_sigprocmask(SIG_SETMASK, Arg::Buf(&none), Out::Buf(&mut after), 8);
    if r != EINTR
        || keel_rt::signal::caught(SIGUSR1) != usr1 + 1
        || now() - t0 > 1000 * MS
        || after != only_usr1
    {
        return 16;
    }
    // 17. Stopped and continued with no handler run, sigsuspend waits
    //     again (ERESTARTNOHAND restarts it): the child returns only when
    //     SIGUSR1 comes, its handler having run.
    let waiter = spawn(|| {
        // The counts are a copy of the parent's.
        let before = keel_rt::signal::caught(SIGUSR1);
        let r = sys::rt_sigsuspend(Arg::Buf(&0u64), 8);
        if r == EINTR && keel_rt::signal::caught(SIGUSR1) == before + 1 {
            0
        } else {
            1
        }
    });
    nap(100);
    sys::kill(waiter, SIGSTOP);
    let mut status = 0;
    if sys::wait4(waiter, &mut status, WUNTRACED) != i64::from(waiter) {
        return 17;
    }
    sys::kill(waiter, SIGCONT);
    nap(100);
    sys::kill(waiter, SIGUSR1);
    if exit_code(waiter) != 0 {
        return 17;
    }
    // Leave SIGUSR1 and SIGUSR2 as they were.
    let act = [0u8; 32];
    sys::rt_sigaction(SIGUSR1, Arg::Buf(&act), Out::Null, 8);
    sys::rt_sigaction(SIGUSR2, Arg::Buf(&act), Out::Null, 8);
    sys::write(1, b"sleepprobe: 17 checks passed\n");
    0
}

keel_rt::main!(main);
