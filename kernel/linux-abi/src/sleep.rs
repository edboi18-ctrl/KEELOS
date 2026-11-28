//! nanosleep(2), clock_nanosleep(2) and restart_syscall(2) (P3-T13 part
//! 2, ADR 0033), as Linux v6.12's `kernel/time/hrtimer.c`
//! (`hrtimer_nanosleep`, `do_nanosleep`, `nanosleep_copyout`),
//! `kernel/time/posix-timers.c` (`clock_nanosleep`, the clocks' `nsleep`)
//! and `kernel/signal.c` (`restart_syscall`, `do_no_restart_syscall`).
//!
//! - **The clocks:** nanosleep sleeps on CLOCK_MONOTONIC. clock_nanosleep
//!   sleeps on CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME and
//!   CLOCK_TAI. The clocks Linux cannot sleep on (MONOTONIC_RAW and the
//!   COARSE ones: no `nsleep`) are EOPNOTSUPP before the request is read.
//!   The alarm clocks are EOPNOTSUPP after it, as `alarm_timer_nsleep`
//!   is without a real-time clock device, which Keel does not drive.
//!   Other numbers are EINVAL: past the table, and the CPU-time clocks,
//!   which Keel does not keep (Linux sleeps on a process's). Keel
//!   has one time base, so REALTIME and TAI are the monotonic clock
//!   counted from the epoch (docs/syscalls.md, clock_gettime).
//! - **The order of the checks:** the clock, then EFAULT for the request,
//!   then EINVAL for a negative tv_sec or a tv_nsec outside 0..1e9
//!   (`timespec64_valid`). Other flags than TIMER_ABSTIME are ignored.
//! - **Interrupted by a signal:**
//!   - **a relative sleep** writes the time left to `rem`, if given (0 if
//!     none is left, which is then success), and returns
//!     ERESTART_RESTARTBLOCK. The thread's restart record keeps the
//!     deadline and `rem`. Without a handler the return to user mode turns
//!     the call into restart_syscall, which sleeps until that same
//!     deadline (the time left, not the whole request again); with a
//!     handler it is EINTR;
//!   - **an absolute sleep** writes nothing and returns ERESTARTNOHAND:
//!     restarted with the same deadline, or EINTR after a handler.
//! - **restart_syscall** runs the thread's restart record; with none (no
//!   interrupted sleep since the last sleep call began) it is EINTR.

use alloc::sync::Arc;

use keel_core::errno::Errno;
use keel_hal::sched;
use keel_hal::sync::IrqMutex;
use keel_hal::time;
use keel_hal::vm::{copy_from_user, copy_to_user};

use crate::abi::timespec_bytes;
use crate::process::Process;

type ProcessRef = Arc<IrqMutex<Process>>;
type SysResult = Result<u64, Errno>;

const NSEC_PER_SEC: u64 = 1_000_000_000;

/// `include/uapi/linux/time.h`.
const CLOCK_REALTIME: i64 = 0;
const CLOCK_MONOTONIC: i64 = 1;
const CLOCK_MONOTONIC_RAW: i64 = 4;
const CLOCK_REALTIME_COARSE: i64 = 5;
const CLOCK_MONOTONIC_COARSE: i64 = 6;
const CLOCK_BOOTTIME: i64 = 7;
const CLOCK_REALTIME_ALARM: i64 = 8;
const CLOCK_BOOTTIME_ALARM: i64 = 9;
const CLOCK_TAI: i64 = 11;
const TIMER_ABSTIME: u64 = 1;

/// What restart_syscall resumes (`current->restart_block`): an interrupted
/// relative sleep's deadline, in monotonic nanoseconds, and where its time
/// left goes (0 for nowhere).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Restart {
    pub deadline: u64,
    pub rem: u64,
}

/// Sets the calling thread's restart record.
fn set_restart(p: &ProcessRef, restart: Option<Restart>) {
    if let Some(t) = p.lock().threads.get_mut(&sched::current().0) {
        t.restart = restart;
    }
}

/// A `struct __kernel_timespec` from user memory, checked as
/// `get_timespec64` then `timespec64_valid`: nanoseconds.
fn read_timespec(at: u64) -> Result<u64, Errno> {
    let mut b = [0u8; 16];
    copy_from_user(&mut b, at).map_err(|_| Errno::EFAULT)?;
    let sec = i64::from_le_bytes(b[..8].try_into().unwrap_or_default());
    let nsec = i64::from_le_bytes(b[8..].try_into().unwrap_or_default());
    if sec < 0 || !(0..NSEC_PER_SEC as i64).contains(&nsec) {
        return Err(Errno::EINVAL);
    }
    Ok((sec as u64)
        .saturating_mul(NSEC_PER_SEC)
        .saturating_add(nsec as u64))
}

/// Sleeps until `deadline` (monotonic nanoseconds) or a signal the thread
/// does not block. Ok if the deadline came; on a signal, for a relative
/// sleep (`relative` Some(rem)) the time left is written to `rem` and the
/// call is ERESTART_RESTARTBLOCK with the restart record set, and for an
/// absolute one it is ERESTARTNOHAND (`hrtimer_nanosleep`).
fn sleep_until(p: &ProcessRef, deadline: u64, relative: Option<u64>) -> SysResult {
    loop {
        let now = time::monotonic_nanos();
        if now >= deadline {
            return Ok(0);
        }
        if crate::signal::should_stop(p) {
            let Some(rem) = relative else {
                return Err(Errno::ERESTARTNOHAND);
            };
            // `do_nanosleep`: no time left is success.
            let left = deadline - now;
            if rem != 0 {
                copy_to_user(rem, &timespec_bytes(left)).map_err(|_| Errno::EFAULT)?;
            }
            set_restart(p, Some(Restart { deadline, rem }));
            return Err(Errno::ERESTART_RESTARTBLOCK);
        }
        crate::ready::wait(|| crate::signal::pending_unblocked(p), Some(deadline));
    }
}

/// nanosleep(2): a relative sleep on CLOCK_MONOTONIC.
pub fn nanosleep(p: &ProcessRef, req: u64, rem: u64) -> SysResult {
    let span = read_timespec(req)?;
    set_restart(p, None);
    let deadline = time::monotonic_nanos().saturating_add(span);
    sleep_until(p, deadline, Some(rem))
}

/// clock_nanosleep(2), with the checks in Linux's order.
pub fn clock_nanosleep(p: &ProcessRef, clock: i64, flags: u64, req: u64, rem: u64) -> SysResult {
    match clock {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME | CLOCK_TAI => {}
        CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM => {
            read_timespec(req)?;
            return Err(Errno::EOPNOTSUPP);
        }
        CLOCK_MONOTONIC_RAW | CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE => {
            return Err(Errno::EOPNOTSUPP);
        }
        _ => return Err(Errno::EINVAL),
    }
    let t = read_timespec(req)?;
    set_restart(p, None);
    if flags & TIMER_ABSTIME != 0 {
        // Every Keel clock counts the monotonic time (from boot, or from
        // the epoch as if the machine booted then): the same deadline.
        sleep_until(p, t, None)
    } else {
        sleep_until(p, time::monotonic_nanos().saturating_add(t), Some(rem))
    }
}

/// restart_syscall(2): resumes the thread's interrupted sleep, or EINTR
/// (`do_no_restart_syscall`) if there is none. The record stays, as
/// Linux's restart block does, so a second call after the deadline
/// returns at once.
pub fn restart_syscall(p: &ProcessRef) -> SysResult {
    let restart = p
        .lock()
        .threads
        .get(&sched::current().0)
        .and_then(|t| t.restart);
    match restart {
        Some(r) => sleep_until(p, r.deadline, Some(r.rem)),
        None => Err(Errno::EINTR),
    }
}
