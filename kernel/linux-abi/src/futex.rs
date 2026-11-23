//! futex(2): FUTEX_WAIT, FUTEX_WAKE, FUTEX_REQUEUE and FUTEX_CMP_REQUEUE
//! (P3-T5, first part): what musl's pthreads need for mutexes, condition
//! variables (a broadcast or signal requeues waiters onto the mutex) and
//! pthread_join (which waits on the thread ID word that
//! CLONE_CHILD_CLEARTID clears).
//!
//! As Linux's do_futex and futex_wait/futex_wake (`kernel/futex/` at
//! v6.12): the address must be 4-byte aligned (EINVAL); FUTEX_WAIT blocks
//! only if the word still holds `val` when checked under the futex lock
//! (else EAGAIN, Linux's EWOULDBLOCK), which no FUTEX_WAKE can slip
//! between; a relative timeout ends it with ETIMEDOUT; FUTEX_WAKE wakes up
//! to `val` waiters and returns how many. FUTEX_REQUEUE wakes up to `val`
//! waiters of `uaddr` and moves up to `val2` (the timeout argument as a
//! number) of the rest to `uaddr2`; FUTEX_CMP_REQUEUE first requires
//! `*uaddr == val3` (else EAGAIN); both return the number woken plus moved,
//! and a negative count is EINVAL (`kernel/futex/requeue.c`).
//! FUTEX_PRIVATE_FLAG is accepted; FUTEX_CLOCK_REALTIME with these
//! commands, and every other command, is ENOSYS.
//!
//! Waiters are keyed by (address space, address). Keel has no shared
//! memory between address spaces yet (MAP_SHARED), so a shared futex is
//! the same as a private one; keys by backing object arrive with shared
//! mappings.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};

use keel_core::errno::Errno;
use keel_hal::sched::{self, ThreadId, WaitQueue};
use keel_hal::sync::IrqMutex;
use keel_hal::time;
use keel_hal::vm::copy_from_user;

const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_REQUEUE: u32 = 3;
const FUTEX_CMP_REQUEUE: u32 = 4;
const FUTEX_PRIVATE_FLAG: u32 = 128;
const FUTEX_CLOCK_REALTIME: u32 = 256;

/// Threads waiting, by (address space id, address), in arrival order.
static WAITERS: IrqMutex<BTreeMap<(u64, u64), VecDeque<u64>>> = IrqMutex::new(BTreeMap::new());
/// Where each waiting thread waits now (requeueing moves it).
static WAITING: IrqMutex<BTreeMap<u64, (u64, u64)>> = IrqMutex::new(BTreeMap::new());
/// Waiters that FUTEX_WAKE has woken and that have not yet noticed.
static WOKEN: IrqMutex<BTreeSet<u64>> = IrqMutex::new(BTreeSet::new());
/// Where woken waiters block.
static QUEUE: WaitQueue = WaitQueue::new();

/// Wakes up to `count` threads waiting on `address` in address space
/// `space`; returns how many.
pub fn wake(space: u64, address: u64, count: u32) -> u64 {
    requeue(space, address, count, None, 0)
}

/// Wakes up to `wake` waiters of `from`, then moves up to `move_count` of
/// the rest to `to` (if given). Returns how many were woken or moved.
fn requeue(space: u64, from: u64, wake: u32, to: Option<u64>, move_count: u32) -> u64 {
    let mut woken = 0u64;
    let mut moved = 0u64;
    {
        let mut waiters = WAITERS.lock();
        let mut waiting = WAITING.lock();
        if let Some(mut queue) = waiters.remove(&(space, from)) {
            let mut flags = WOKEN.lock();
            while woken < u64::from(wake) {
                let Some(thread) = queue.pop_front() else {
                    break;
                };
                waiting.remove(&thread);
                flags.insert(thread);
                woken += 1;
            }
            drop(flags);
            if let Some(to) = to.filter(|&to| to != from) {
                while moved < u64::from(move_count) {
                    let Some(thread) = queue.pop_front() else {
                        break;
                    };
                    waiting.insert(thread, (space, to));
                    waiters.entry((space, to)).or_default().push_back(thread);
                    moved += 1;
                }
            }
            if !queue.is_empty() {
                waiters.insert((space, from), queue);
            }
        }
    }
    if woken > 0 {
        QUEUE.wake_all();
    }
    woken + moved
}

/// Removes `thread` from wherever it waits and from the woken set;
/// returns whether it had been woken.
fn leave(thread: u64) -> bool {
    let mut waiters = WAITERS.lock();
    if let Some(key) = WAITING.lock().remove(&thread)
        && let Some(queue) = waiters.get_mut(&key)
    {
        queue.retain(|&t| t != thread);
        if queue.is_empty() {
            waiters.remove(&key);
        }
    }
    WOKEN.lock().remove(&thread)
}

/// A relative `struct timespec` as nanoseconds: EINVAL unless the seconds
/// are not negative and the nanoseconds are below 10^9 (as Linux's
/// timespec64_valid).
fn relative_ns(timeout: u64) -> Result<Option<u64>, Errno> {
    if timeout == 0 {
        return Ok(None);
    }
    let mut raw = [0u8; 16];
    copy_from_user(&mut raw, timeout).map_err(|_| Errno::EFAULT)?;
    let seconds = i64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8]));
    let nanos = i64::from_le_bytes(raw[8..].try_into().unwrap_or([0; 8]));
    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
        return Err(Errno::EINVAL);
    }
    Ok(Some(
        (seconds as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nanos as u64),
    ))
}

/// futex(2) for the calling thread in address space `space`; `timeout`
/// is the fourth argument (a timespec pointer, or `val2` for the requeue
/// commands).
pub fn futex(
    space: u64,
    address: u64,
    op: u32,
    val: u32,
    timeout: u64,
    address2: u64,
    val3: u32,
) -> Result<u64, Errno> {
    let cmd = op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    if op & FUTEX_CLOCK_REALTIME != 0
        || !matches!(
            cmd,
            FUTEX_WAIT | FUTEX_WAKE | FUTEX_REQUEUE | FUTEX_CMP_REQUEUE
        )
    {
        return Err(Errno::ENOSYS);
    }
    if !address.is_multiple_of(4) {
        return Err(Errno::EINVAL);
    }
    match cmd {
        FUTEX_WAKE => return Ok(wake(space, address, val)),
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
            let move_count = timeout as u32;
            if (val as i32) < 0 || (move_count as i32) < 0 {
                return Err(Errno::EINVAL);
            }
            if !address2.is_multiple_of(4) {
                return Err(Errno::EINVAL);
            }
            if cmd == FUTEX_CMP_REQUEUE {
                // Compared under the waiters lock, as a waiter's check.
                let _waiters = WAITERS.lock();
                let mut word = [0u8; 4];
                copy_from_user(&mut word, address).map_err(|_| Errno::EFAULT)?;
                if u32::from_le_bytes(word) != val3 {
                    return Err(Errno::EAGAIN);
                }
            }
            return Ok(requeue(space, address, val, Some(address2), move_count));
        }
        _ => {}
    }
    let deadline = relative_ns(timeout)?.map(|ns| time::monotonic_nanos().saturating_add(ns));
    let me = sched::current().0;
    let key = (space, address);
    {
        // The check and the enqueue happen under the waiters lock, which
        // every wake and requeue also takes: none can come between them.
        let mut waiters = WAITERS.lock();
        let mut word = [0u8; 4];
        copy_from_user(&mut word, address).map_err(|_| Errno::EFAULT)?;
        if u32::from_le_bytes(word) != val {
            return Err(Errno::EAGAIN);
        }
        waiters.entry(key).or_default().push_back(me);
        WAITING.lock().insert(me, key);
    }
    let woken = || WOKEN.lock().contains(&me);
    match deadline {
        None => {
            QUEUE.wait_until(woken);
        }
        Some(deadline) => {
            // No timed wait queue yet: check every millisecond.
            while !woken()
                && time::monotonic_nanos() < deadline
                && sched::exit_requested().is_none()
                && !sched::interrupted()
            {
                sched::sleep_ms(1);
            }
        }
    }
    if leave(me) {
        Ok(0)
    } else if sched::exit_requested().is_some() || sched::interrupted() {
        // futex(2): "EINTR: A FUTEX_WAIT ... operation was interrupted by
        // a signal". SA_RESTART is not honoured yet (ADR 0020).
        Err(Errno::EINTR)
    } else {
        Err(Errno::ETIMEDOUT)
    }
}

/// A thread that ends while waiting leaves no entry behind.
pub fn forget(thread: ThreadId) {
    leave(thread.0);
}
