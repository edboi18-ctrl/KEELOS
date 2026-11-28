//! epoll (P3-T10 part 2, ADR 0026): epoll_create, epoll_create1,
//! epoll_ctl, epoll_wait, epoll_pwait and epoll_pwait2, as Linux v6.12's
//! `fs/eventpoll.c`, over the readiness queue of ADR 0025.
//!
//! The interest set and the ready list are `keel_core::epoll` (host
//! tested). Here they meet the objects: each item holds its target weakly
//! (Linux removes an item when its file is released, not when one of its
//! descriptors is closed), the handle's rights at the time of the call
//! (readiness is reported only for what they allow, as poll), and is
//! keyed by the target and the descriptor number, as Linux's (file, fd).

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};

use keel_core::epoll::{
    self as ep, EPOLLEXCLUSIVE, EPOLLEXCLUSIVE_OK_BITS, EVENT_SIZE, Interest, MAX_EVENTS, Set,
    Wakes,
};
use keel_core::errno::Errno;
use keel_core::handle::{Handle, Rights};
use keel_hal::sched::Waited;
use keel_hal::sync::IrqMutex;
use keel_hal::vm::{copy_from_user, copy_to_user};

use crate::abi::O_CLOEXEC;
use crate::process::{Object, OpenFile, Process};
use crate::ready::{EventFile, PipeEnd};

type ProcessRef = Arc<IrqMutex<Process>>;
type SysResult = Result<u64, Errno>;

const EPOLL_CTL_ADD: i32 = 1;
const EPOLL_CTL_DEL: i32 = 2;
const EPOLL_CTL_MOD: i32 = 3;

/// An item's key: its target's identity and the descriptor number.
type Key = (usize, i32);

/// An item's target, held weakly.
enum Target {
    File(Weak<IrqMutex<OpenFile>>),
    Pipe(Weak<PipeEnd>),
    EventFd(Weak<EventFile>),
    Socket(Weak<crate::socket::Socket>),
}

impl Target {
    fn upgrade(&self) -> Option<Object> {
        match self {
            Target::File(w) => w.upgrade().map(Object::File),
            Target::Pipe(w) => w.upgrade().map(Object::Pipe),
            Target::EventFd(w) => w.upgrade().map(Object::EventFd),
            Target::Socket(w) => w.upgrade().map(Object::Socket),
        }
    }
}

struct Watched {
    target: Target,
    /// The rights of the handle it was added (or last modified) through.
    rights: Rights,
}

#[derive(Default)]
struct Inner {
    set: Set<Key>,
    targets: BTreeMap<Key, Watched>,
}

/// An epoll instance, as an open file description.
pub struct EpollFile {
    /// F_GETFL and F_SETFL: O_RDWR, and O_NONBLOCK if set (it changes
    /// nothing here, as on Linux: epoll_wait's timeout decides).
    pub status: IrqMutex<u64>,
    inner: IrqMutex<Inner>,
}

/// Whether epoll can watch `object` (`file_can_poll`): pipes, eventfds and
/// the console have a poll method; regular files, directories, /dev/null,
/// /dev/zero and /dev/urandom do not (EPERM). An epoll instance can be
/// polled, but watching one from another (nesting) is not supported
/// (EINVAL; ADR 0026).
fn can_poll(object: &Object) -> Result<(), Errno> {
    match object {
        Object::Pipe(_) | Object::EventFd(_) | Object::Epoll(_) | Object::Socket(_) => Ok(()),
        Object::File(file) if file.lock().tty.is_some() => Ok(()),
        Object::File(_) => Err(Errno::EPERM),
        // A factory or compartment handle has nothing to wait for (ADR
        // 0040), as a regular file has nothing.
        Object::Factory(_) | Object::Compartment(_) | Object::Audit(_) => Err(Errno::EPERM),
    }
}

fn identity(object: &Object) -> usize {
    match object {
        Object::File(a) => Arc::as_ptr(a) as *const () as usize,
        Object::Pipe(a) => Arc::as_ptr(a) as *const () as usize,
        Object::EventFd(a) => Arc::as_ptr(a) as *const () as usize,
        Object::Epoll(a) => Arc::as_ptr(a) as *const () as usize,
        Object::Socket(a) => Arc::as_ptr(a) as *const () as usize,
        Object::Factory(a) => Arc::as_ptr(a) as *const () as usize,
        Object::Compartment(a) => Arc::as_ptr(a) as *const () as usize,
        Object::Audit(a) => Arc::as_ptr(a) as *const () as usize,
    }
}

fn downgrade(object: &Object) -> Option<Target> {
    Some(match object {
        Object::File(a) => Target::File(Arc::downgrade(a)),
        Object::Pipe(a) => Target::Pipe(Arc::downgrade(a)),
        Object::EventFd(a) => Target::EventFd(Arc::downgrade(a)),
        Object::Socket(a) => Target::Socket(Arc::downgrade(a)),
        Object::Epoll(_) | Object::Factory(_) | Object::Compartment(_) | Object::Audit(_) => {
            return None;
        }
    })
}

/// The wakes of the queue an item on `object` hears: a pipe's read end
/// waits on the readers' queue and its write end on the writers'
/// (`pipe_poll`'s `poll_wait` by access mode); an eventfd has one queue;
/// the console its read queue.
fn wakes_of(object: &Object) -> Wakes {
    match object {
        // A FIFO opened O_RDWR waits on both (`pipe_poll` by f_mode).
        Object::Pipe(end) => {
            let pipe = end.pipe.lock();
            match (end.read, end.write) {
                (true, true) => pipe.rd_wakes.merged(&pipe.wr_wakes),
                (false, true) => pipe.wr_wakes,
                _ => pipe.rd_wakes,
            }
        }
        Object::EventFd(file) => file.counter.lock().wakes,
        // A terminal's read and write queues (`n_tty_poll`).
        Object::File(file) => {
            let tty = file.lock().tty.clone();
            tty.map_or(Wakes::new(), |t| t.wakes())
        }
        Object::Epoll(_) | Object::Factory(_) | Object::Compartment(_) | Object::Audit(_) => {
            Wakes::new()
        }
        Object::Socket(s) => s.wakes(),
    }
}

impl Inner {
    /// Drops items whose target has gone (`eventpoll_release` at the last
    /// close of the file), then lets each item see its target's wakes.
    fn refresh(&mut self) {
        let dead: alloc::vec::Vec<Key> = self
            .targets
            .iter()
            .filter(|(_, w)| w.target.upgrade().is_none())
            .map(|(&k, _)| k)
            .collect();
        for key in dead {
            self.targets.remove(&key);
            let _ = self.set.remove(key);
        }
        for (&key, watched) in &self.targets {
            if let Some(object) = watched.target.upgrade() {
                self.set.note(key, wakes_of(&object));
            }
        }
    }

    /// What `key`'s target is ready for (`ep_item_poll`), None if gone.
    fn poll(targets: &BTreeMap<Key, Watched>, key: Key) -> Option<u32> {
        let watched = targets.get(&key)?;
        let object = watched.target.upgrade()?;
        Some(u32::from(crate::ready::object_ready(
            &object,
            watched.rights,
        )))
    }
}

/// poll(2) on an epoll descriptor (`ep_eventpoll_poll`): readable while a
/// listed item is ready.
pub fn poll_mask(file: &EpollFile) -> u16 {
    use keel_core::poll::{POLLIN, POLLRDNORM};
    let mut inner = file.inner.lock();
    inner.refresh();
    let Inner { set, targets } = &mut *inner;
    if set.any_ready(|k| Inner::poll(targets, k)) {
        POLLIN | POLLRDNORM
    } else {
        0
    }
}

/// epoll_create1(2) (`do_epoll_create`): flags other than EPOLL_CLOEXEC
/// EINVAL. The handle has READ, WRITE, STAT and DUPLICATE (read and write
/// are EINVAL, as an epoll file has neither).
pub fn epoll_create1(p: &ProcessRef, flags: u64) -> SysResult {
    if flags & !O_CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    let file = EpollFile {
        status: IrqMutex::new(crate::abi::O_RDWR),
        inner: IrqMutex::new(Inner::default()),
    };
    let fd = p.lock().handles.insert(Handle {
        object: Object::Epoll(Arc::new(file)),
        rights: Rights::READ | Rights::WRITE | Rights::STAT | Rights::DUPLICATE,
        close_on_exec: flags & O_CLOEXEC != 0,
    })?;
    Ok(fd as u64)
}

/// epoll_create(2): a size of 0 or less EINVAL; otherwise epoll_create1
/// with no flags (the size is a hint Linux ignores).
pub fn epoll_create(p: &ProcessRef, size: i32) -> SysResult {
    if size <= 0 {
        return Err(Errno::EINVAL);
    }
    epoll_create1(p, 0)
}

/// epoll_ctl(2) (`do_epoll_ctl`), in Linux's order:
/// - the event is read first unless `op` is EPOLL_CTL_DEL (EFAULT);
/// - `epfd`, then `fd`, must be open (EBADF);
/// - the target must have a poll method (EPERM, [`can_poll`]);
/// - `epfd` must be an epoll instance and not the target itself (EINVAL);
/// - EPOLLEXCLUSIVE: EINVAL with EPOLL_CTL_MOD, and with ADD for an epoll
///   target or events beyond EPOLLEXCLUSIVE_OK_BITS;
/// - then ADD (EEXIST if there), DEL and MOD (ENOENT if not there; MOD of
///   an EPOLLEXCLUSIVE item EINVAL); any other op EINVAL.
///
/// An epoll target (nesting) is EINVAL at ADD, where Linux allows it.
pub fn epoll_ctl(p: &ProcessRef, epfd: i32, op: i32, fd: i32, event: u64) -> SysResult {
    let interest = if op != EPOLL_CTL_DEL {
        let mut b = [0u8; EVENT_SIZE];
        copy_from_user(&mut b, event).map_err(|_| Errno::EFAULT)?;
        let (events, data) = ep::parse_event(&b);
        Interest { events, data }
    } else {
        Interest { events: 0, data: 0 }
    };
    let (epoll, target, rights) = {
        let process = p.lock();
        let epoll = process.handles.get(epfd, Rights::NONE)?.clone();
        let target = process.handles.get(fd, Rights::NONE)?.clone();
        (epoll, target, process.handles.rights(fd)?)
    };
    can_poll(&target)?;
    let Object::Epoll(file) = &epoll else {
        return Err(Errno::EINVAL);
    };
    if identity(&epoll) == identity(&target) {
        return Err(Errno::EINVAL);
    }
    let has_event = op != EPOLL_CTL_DEL;
    if has_event && interest.events & EPOLLEXCLUSIVE != 0 {
        if op == EPOLL_CTL_MOD {
            return Err(Errno::EINVAL);
        }
        if op == EPOLL_CTL_ADD
            && (matches!(target, Object::Epoll(_))
                || interest.events & !EPOLLEXCLUSIVE_OK_BITS != 0)
        {
            return Err(Errno::EINVAL);
        }
    }
    let key = (identity(&target), fd);
    let ready = u32::from(crate::ready::object_ready(&target, rights));
    let wakes = wakes_of(&target);
    let result = {
        let mut inner = file.inner.lock();
        // A key whose target has gone may name a new object now at the
        // same address: drop dead items first.
        inner.refresh();
        match op {
            EPOLL_CTL_ADD => {
                let watched = downgrade(&target).ok_or(Errno::EINVAL)?;
                inner.set.add(key, interest, ready, wakes)?;
                inner.targets.insert(
                    key,
                    Watched {
                        target: watched,
                        rights,
                    },
                );
                Ok(0)
            }
            EPOLL_CTL_DEL => {
                inner.set.remove(key)?;
                inner.targets.remove(&key);
                Ok(0)
            }
            EPOLL_CTL_MOD => {
                inner.set.modify(key, interest, ready, wakes)?;
                if let Some(w) = inner.targets.get_mut(&key) {
                    w.rights = rights;
                }
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    };
    // An item that is ready now may end another thread's wait.
    crate::ready::changed();
    result
}

/// How long a wait may last: no limit, none at all (a zero timeout:
/// `timed_out` from the start), or until a deadline.
#[derive(Clone, Copy)]
pub enum Timeout {
    Forever,
    Zero,
    Until(u64),
}

/// `do_epoll_wait` and `ep_poll`:
/// - `maxevents` at or below 0, or above EP_MAX_EVENTS, EINVAL; an array
///   outside the user half EFAULT; `epfd` not open EBADF; not an epoll
///   instance EINVAL;
/// - ready items are sent ([`Set::send`]); if some were, the call
///   returns their count;
/// - with a zero timeout, or once the deadline has passed, 0; a pending
///   signal the thread does not block, EINTR (checked after the timeout,
///   so a zero-timeout call is never interrupted);
/// - otherwise it waits for a change, a signal or the deadline.
fn wait_on(p: &ProcessRef, epfd: i32, events: u64, maxevents: i32, timeout: Timeout) -> SysResult {
    if maxevents <= 0 || maxevents > MAX_EVENTS {
        return Err(Errno::EINVAL);
    }
    let max = maxevents as usize;
    if !access_ok(events, max * EVENT_SIZE) {
        return Err(Errno::EFAULT);
    }
    let object = p.lock().handles.get(epfd, Rights::NONE)?.clone();
    let Object::Epoll(file) = object else {
        return Err(Errno::EINVAL);
    };
    let deadline = match timeout {
        Timeout::Until(d) => Some(d),
        _ => None,
    };
    let mut timed_out = matches!(timeout, Timeout::Zero);
    loop {
        let sent = {
            let mut inner = file.inner.lock();
            inner.refresh();
            let Inner { set, targets } = &mut *inner;
            let mut at = events;
            // Copied out under the set's lock, as Linux does under
            // `ep->mtx`: a fault here takes only the address space's
            // locks, which epoll never holds.
            set.send(
                max,
                |k| Inner::poll(targets, k),
                |e, data| {
                    let ok = copy_to_user(at, &ep::event_bytes(e, data)).is_ok();
                    at += EVENT_SIZE as u64;
                    ok
                },
            )?
        };
        if sent > 0 {
            return Ok(sent as u64);
        }
        if timed_out || deadline.is_some_and(|d| keel_hal::time::monotonic_nanos() >= d) {
            return Ok(0);
        }
        if crate::signal::should_stop(p) {
            return Err(Errno::EINTR);
        }
        let waited = crate::ready::wait(
            || {
                let mut inner = file.inner.lock();
                inner.refresh();
                inner.set.has_ready() || crate::signal::pending_unblocked(p)
            },
            deadline,
        );
        // After the deadline Linux looks once more, then returns 0.
        if waited == Waited::TimedOut {
            timed_out = true;
        }
    }
}

/// `access_ok` (`arch/x86/include/asm/uaccess_64.h`): up to a page, the
/// start must be a user address (NULL is one); a longer range must end
/// within the user half. Whether it is mapped is found out only when the
/// events are written (EFAULT then).
fn access_ok(address: u64, size: usize) -> bool {
    const PAGE_SIZE: usize = 4096;
    if size <= PAGE_SIZE {
        address < keel_core::vm::USER_END
    } else {
        address
            .checked_add(size as u64)
            .is_some_and(|end| end <= keel_core::vm::USER_END)
    }
}

/// epoll_wait(2): a timeout in milliseconds, negative for none
/// (`ep_timeout_to_timespec`).
pub fn epoll_wait(p: &ProcessRef, epfd: i32, events: u64, maxevents: i32, ms: i32) -> SysResult {
    wait_on(p, epfd, events, maxevents, ms_timeout(ms))
}

fn ms_timeout(ms: i32) -> Timeout {
    match ms {
        ..0 => Timeout::Forever,
        0 => Timeout::Zero,
        _ => crate::ready::deadline_ms(i64::from(ms)).map_or(Timeout::Forever, Timeout::Until),
    }
}

/// epoll_pwait(2) (`do_epoll_pwait`): the mask is set first (a size other
/// than 8 EINVAL), then the wait; the mask is put back at once unless the
/// call was interrupted (`restore_saved_sigmask_unless`), as ppoll's.
pub fn epoll_pwait(
    p: &ProcessRef,
    epfd: i32,
    events: u64,
    maxevents: i32,
    ms: i32,
    mask: u64,
    size: u64,
) -> SysResult {
    crate::signal::temporary_mask(p, mask, size)?;
    let result = wait_on(p, epfd, events, maxevents, ms_timeout(ms));
    crate::signal::end_temporary_mask(p, result == Err(Errno::EINTR));
    result
}

/// epoll_pwait2(2): a timespec timeout (NULL waits without limit;
/// unreadable EFAULT; a negative tv_sec or tv_nsec outside 0..10^9
/// EINVAL), read before the mask is set. Unlike ppoll, the time left is
/// not written back.
pub fn epoll_pwait2(
    p: &ProcessRef,
    epfd: i32,
    events: u64,
    maxevents: i32,
    tsp: u64,
    mask: u64,
    size: u64,
) -> SysResult {
    let timeout = if tsp == 0 {
        Timeout::Forever
    } else {
        let mut b = [0u8; 16];
        copy_from_user(&mut b, tsp).map_err(|_| Errno::EFAULT)?;
        let sec = i64::from_le_bytes(b[..8].try_into().unwrap_or_default());
        let nsec = i64::from_le_bytes(b[8..].try_into().unwrap_or_default());
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return Err(Errno::EINVAL);
        }
        let span = (sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nsec as u64);
        if span == 0 {
            Timeout::Zero
        } else {
            Timeout::Until(keel_hal::time::monotonic_nanos().saturating_add(span))
        }
    };
    crate::signal::temporary_mask(p, mask, size)?;
    let result = wait_on(p, epfd, events, maxevents, timeout);
    crate::signal::end_temporary_mask(p, result == Err(Errno::EINTR));
    result
}
