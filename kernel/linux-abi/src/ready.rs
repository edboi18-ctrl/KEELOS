//! Readiness and the descriptors that are not files (P3-T10, ADR 0025):
//! pipes, eventfds and `memfd_create`, and the one readiness mechanism
//! that poll, select, epoll and blocking reads and writes share.
//!
//! The mechanism: everything whose readiness can change (a pipe written,
//! read or closed; an eventfd changed; a console line typed) calls
//! [`changed`], which wakes every thread waiting in [`wait`]. A waiter
//! rechecks what it waits for and waits again if it is still not ready,
//! with its deadline. One queue for all is simple and cannot miss a wake;
//! the price is that every change wakes every waiter, which is cheap with
//! one CPU and few waiters (ADR 0025).
//!
//! The rules are Linux v6.12's (`fs/pipe.c`, `fs/eventfd.c`, `mm/memfd.c`);
//! the data parts are in `keel_core::pipe`, tested on the host.

use alloc::sync::Arc;
use alloc::vec::Vec;

use keel_core::errno::Errno;
use keel_core::handle::{Handle, Rights};
use keel_core::pipe::{EventCounter, Io, Pipe};
use keel_core::signal::{SI_USER, SIGPIPE, SigInfo};
use keel_core::vfs::{Ino, Stat, Timespec};
use keel_hal::sched::{self, WaitQueue, Waited};
use keel_hal::sync::IrqMutex;
use keel_hal::vm::{copy_from_user, copy_to_user};

use crate::abi::{O_CLOEXEC, O_NONBLOCK, O_RDONLY, O_WRONLY};
use crate::process::{Object, Process};

type ProcessRef = Arc<IrqMutex<Process>>;
type SysResult = Result<u64, Errno>;

/// Woken whenever any readiness may have changed.
static READY: WaitQueue = WaitQueue::new();

/// Something's readiness may have changed: wake every waiter to look.
pub fn changed() {
    READY.wake_all();
}

/// Waits until `ready()` is true, the deadline (monotonic nanoseconds)
/// passes, or a signal arrives.
pub fn wait(ready: impl FnMut() -> bool, deadline: Option<u64>) -> Waited {
    READY.wait_until_deadline(ready, deadline)
}

/// One end of a pipe, as an open file description: the pipe, which end,
/// and the status flags (O_NONBLOCK and the access mode) its descriptors
/// share. Dropping the last descriptor of an end closes it.
pub struct PipeEnd {
    pub pipe: Arc<IrqMutex<Pipe>>,
    pub write: bool,
    pub status: IrqMutex<u64>,
    /// A number for stat's st_ino, the pipe's (both ends share it).
    pub ino: u64,
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        self.pipe.lock().close_end(self.write);
        changed();
    }
}

/// An eventfd, as an open file description.
pub struct EventFile {
    pub counter: IrqMutex<EventCounter>,
    pub status: IrqMutex<u64>,
}

/// Numbers for stat's st_ino of pipes, each its own (pipefs is its own
/// filesystem on Linux, so they cannot collide with tmpfs's).
fn new_ino() -> u64 {
    static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
    (0xFFFE << 48) | NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// pipe2(2) (`do_pipe2`, `__do_pipe_flags`): flags other than O_CLOEXEC
/// and O_NONBLOCK EINVAL (O_DIRECT, packet mode, is not supported: ADR
/// 0025); the two descriptors are written to `fds` (read end first), and
/// if that fails both are closed again and the call is EFAULT.
pub fn pipe2(p: &ProcessRef, fds: u64, flags: u64) -> SysResult {
    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    let pipe = Arc::new(IrqMutex::new(Pipe::new()));
    let ino = new_ino();
    let status = flags & O_NONBLOCK;
    let end = |write: bool| {
        Object::Pipe(Arc::new(PipeEnd {
            pipe: pipe.clone(),
            write,
            status: IrqMutex::new(status | if write { O_WRONLY } else { O_RDONLY }),
            ino,
        }))
    };
    let base = Rights::STAT | Rights::DUPLICATE;
    let cloexec = flags & O_CLOEXEC != 0;
    let (r, w) = {
        let mut process = p.lock();
        let r = process.handles.insert(Handle {
            object: end(false),
            rights: base | Rights::READ,
            close_on_exec: cloexec,
        })?;
        let w = match process.handles.insert(Handle {
            object: end(true),
            rights: base | Rights::WRITE,
            close_on_exec: cloexec,
        }) {
            Ok(w) => w,
            Err(e) => {
                let _ = process.handles.close(r);
                return Err(e);
            }
        };
        (r, w)
    };
    let mut pair = [0u8; 8];
    pair[..4].copy_from_slice(&r.to_le_bytes());
    pair[4..].copy_from_slice(&w.to_le_bytes());
    if copy_to_user(fds, &pair).is_err() {
        let (a, b) = {
            let mut process = p.lock();
            (process.handles.close(r), process.handles.close(w))
        };
        drop((a, b));
        return Err(Errno::EFAULT);
    }
    Ok(0)
}

/// eventfd2(2) (`do_eventfd`): flags other than EFD_SEMAPHORE (1),
/// EFD_CLOEXEC and EFD_NONBLOCK EINVAL; the counter starts at `initval`
/// (an unsigned int). Read and write: see [`read`] and [`write`].
pub fn eventfd2(p: &ProcessRef, initval: u32, flags: u64) -> SysResult {
    const EFD_SEMAPHORE: u64 = 1;
    if flags & !(EFD_SEMAPHORE | O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    let file = EventFile {
        counter: IrqMutex::new(EventCounter {
            count: u64::from(initval),
            semaphore: flags & EFD_SEMAPHORE != 0,
            wakes: keel_core::epoll::Wakes::default(),
        }),
        status: IrqMutex::new(crate::abi::O_RDWR | (flags & O_NONBLOCK)),
    };
    let fd = p.lock().handles.insert(Handle {
        object: Object::EventFd(Arc::new(file)),
        rights: Rights::READ | Rights::WRITE | Rights::STAT | Rights::DUPLICATE,
        close_on_exec: flags & O_CLOEXEC != 0,
    })?;
    Ok(fd as u64)
}

/// memfd_create(2) (`mm/memfd.c`): an anonymous tmpfs file, open for
/// reading and writing, in no directory: it lives while a descriptor or a
/// mapping holds it, and grows, shrinks and maps as any tmpfs file,
/// charged to the caller's compartment.
/// - flags other than MFD_CLOEXEC (1) and MFD_EXEC (0x10) EINVAL: sealing
///   (MFD_ALLOW_SEALING 2, MFD_NOEXEC_SEAL 8) and huge pages (MFD_HUGETLB
///   4) are not supported (ADR 0025); MFD_EXEC with MFD_NOEXEC_SEAL is
///   EINVAL on Linux too;
/// - a name longer than 249 bytes (NAME_MAX less "memfd:") EINVAL; an
///   unreadable one EFAULT.
pub fn memfd_create(p: &ProcessRef, name: u64, flags: u64) -> SysResult {
    const MFD_CLOEXEC: u64 = 1;
    const MFD_EXEC: u64 = 0x10;
    const MFD_NAME_MAX_LEN: usize = 255 - 6;
    if flags & !(MFD_CLOEXEC | MFD_EXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    // strnlen_user(uname, MFD_NAME_MAX_LEN + 1): EINVAL past the limit.
    crate::syscall::user_string_max(name, MFD_NAME_MAX_LEN + 1).map_err(|e| {
        if e == Errno::ENAMETOOLONG {
            Errno::EINVAL
        } else {
            e
        }
    })?;
    let node = crate::fs::with(|fs| fs.create_detached(Vec::new(), 0o777))?;
    let open = crate::process::OpenFile {
        node,
        kind: keel_core::vfs::Kind::File,
        offset: 0,
        append: false,
        status: crate::abi::O_RDWR | crate::abi::O_LARGEFILE,
        comm: None,
    };
    let fd = p.lock().handles.insert(Handle {
        object: Object::File(Arc::new(IrqMutex::new(open))),
        rights: crate::process::file_rights(true, true, keel_core::vfs::Kind::File),
        close_on_exec: flags & MFD_CLOEXEC != 0,
    })?;
    Ok(fd as u64)
}

/// The deadline `ms` milliseconds from now (None for a negative, "no
/// limit").
pub fn deadline_ms(ms: i64) -> Option<u64> {
    u64::try_from(ms)
        .ok()
        .map(|ms| keel_hal::time::monotonic_nanos().saturating_add(ms.saturating_mul(1_000_000)))
}

/// Copies user memory from the segments `segs` (base, length), starting
/// `skip` bytes in, into `out`; false on a fault.
pub(crate) fn copy_in(segs: &[(u64, u64)], mut skip: u64, out: &mut [u8]) -> bool {
    let mut at = 0usize;
    for &(base, len) in segs {
        if at == out.len() {
            break;
        }
        if skip >= len {
            skip -= len;
            continue;
        }
        let n = ((len - skip) as usize).min(out.len() - at);
        if copy_from_user(&mut out[at..at + n], base + skip).is_err() {
            return false;
        }
        at += n;
        skip = 0;
    }
    true
}

/// Copies `data` out to the segments; the bytes copied before a fault.
pub(crate) fn copy_out(segs: &[(u64, u64)], data: &[u8]) -> usize {
    let mut at = 0usize;
    for &(base, len) in segs {
        if at == data.len() {
            break;
        }
        let n = (len as usize).min(data.len() - at);
        if copy_to_user(base, &data[at..at + n]).is_err() {
            // Byte by byte up to the fault, as `copy_to_iter` stops there.
            for (i, byte) in data[at..at + n].iter().enumerate() {
                if copy_to_user(base + i as u64, core::slice::from_ref(byte)).is_err() {
                    return at + i;
                }
            }
        }
        at += n;
    }
    at
}

pub(crate) fn total(segs: &[(u64, u64)]) -> u64 {
    segs.iter()
        .fold(0u64, |t, &(_, len)| t.saturating_add(len))
        .min(crate::abi::MAX_RW_COUNT)
}

/// read(2) and readv(2) of a pipe or eventfd into the user segments
/// `segs`, as one read; None for any other object.
/// - a pipe (`pipe_read`): what is there, up to the total; at end of file
///   0; empty with a writer left, EAGAIN with O_NONBLOCK, else waits
///   (EINTR on a signal). Bytes that fault on the way out stay in the
///   pipe; a fault before any byte is EFAULT;
/// - an eventfd (`eventfd_read`): a total below 8 EINVAL; the counter (or
///   1 with EFD_SEMAPHORE) as 8 bytes; at 0, EAGAIN or waits.
pub fn read(object: &Object, segs: &[(u64, u64)]) -> Option<SysResult> {
    Some(match object {
        Object::Pipe(end) => read_pipe(end, segs),
        Object::EventFd(file) => read_eventfd(file, segs),
        Object::Socket(s) => crate::socket::read(s, segs),
        _ => return None,
    })
}

fn read_pipe(end: &PipeEnd, segs: &[(u64, u64)]) -> SysResult {
    let count = total(segs);
    if count == 0 {
        return Ok(0);
    }
    let mut chunk = alloc::vec![0u8; (count as usize).min(keel_core::pipe::PIPE_CAPACITY)];
    let nonblock = *end.status.lock() & O_NONBLOCK != 0;
    loop {
        let io = end.pipe.lock().read(&mut chunk);
        match io {
            Io::Done(0) => return Ok(0),
            Io::Done(n) => {
                let copied = copy_out(segs, &chunk[..n]);
                if copied < n {
                    end.pipe.lock().unread(&chunk[copied..n]);
                }
                changed();
                return if copied == 0 {
                    Err(Errno::EFAULT)
                } else {
                    Ok(copied as u64)
                };
            }
            Io::WouldBlock if nonblock => return Err(Errno::EAGAIN),
            Io::WouldBlock | Io::Broken => {
                let pipe = end.pipe.clone();
                if wait(
                    || {
                        let p = pipe.lock();
                        !p.is_empty() || p.writers == 0
                    },
                    None,
                ) != Waited::Ready
                {
                    return Err(Errno::EINTR);
                }
            }
        }
    }
}

fn read_eventfd(file: &EventFile, segs: &[(u64, u64)]) -> SysResult {
    if total(segs) < 8 {
        return Err(Errno::EINVAL);
    }
    let nonblock = *file.status.lock() & O_NONBLOCK != 0;
    loop {
        let got = file.counter.lock().read();
        if let Some(n) = got {
            if copy_out(segs, &n.to_le_bytes()) < 8 {
                // eventfd_read takes the count first, then copies: a
                // fault loses it, as on Linux.
                changed();
                return Err(Errno::EFAULT);
            }
            changed();
            return Ok(8);
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        if wait(|| file.counter.lock().count > 0, None) != Waited::Ready {
            return Err(Errno::EINTR);
        }
    }
}

/// write(2) and writev(2) to a pipe or eventfd from the user segments
/// `segs`, as one write; None for any other object.
/// - a pipe (`pipe_write`): with no reader left, SIGPIPE to the writer
///   (SI_USER, `send_sig`) and EPIPE; a write of at most PIPE_BUF goes in
///   whole; a longer one in parts as room appears. Without room: with
///   O_NONBLOCK, EAGAIN if nothing was written, else the count so far;
///   blocking, waits (a signal ends it: EINTR, or the count so far);
/// - an eventfd (`eventfd_write`): a total other than 8 EINVAL; u64::MAX
///   EINVAL; a sum reaching u64::MAX waits or EAGAIN.
pub fn write(p: &ProcessRef, object: &Object, segs: &[(u64, u64)]) -> Option<SysResult> {
    Some(match object {
        Object::Pipe(end) => write_pipe(p, end, segs),
        Object::EventFd(file) => write_eventfd(file, segs),
        Object::Socket(s) => crate::socket::write(p, s, segs),
        _ => return None,
    })
}

fn write_pipe(p: &ProcessRef, end: &PipeEnd, segs: &[(u64, u64)]) -> SysResult {
    use keel_core::pipe::{PIPE_BUF, PIPE_CAPACITY};
    let count = total(segs);
    let nonblock = *end.status.lock() & O_NONBLOCK != 0;
    let partial = |done: u64, error: Errno| if done > 0 { Ok(done) } else { Err(error) };
    let mut chunk = alloc::vec![0u8; (count as usize).min(PIPE_CAPACITY)];
    let mut done = 0u64;
    // A write of at most PIPE_BUF goes in whole, so it is one piece; a
    // longer one is copied a pipe's worth at a time, and what does not fit
    // is copied again next time round.
    let atomic = count <= PIPE_BUF as u64;
    loop {
        let n = ((count - done) as usize).min(PIPE_CAPACITY);
        if !copy_in(segs, done, &mut chunk[..n]) {
            return partial(done, Errno::EFAULT);
        }
        let io = end.pipe.lock().write(&chunk[..n], atomic);
        match io {
            Io::Done(m) => {
                if m > 0 {
                    changed();
                }
                done += m as u64;
                if done == count {
                    return Ok(done);
                }
            }
            Io::Broken => {
                let pid = p.lock().pid();
                crate::signal::send_to_thread(
                    p,
                    sched::current(),
                    SigInfo::from_process(SIGPIPE, SI_USER, pid, 0),
                );
                return partial(done, Errno::EPIPE);
            }
            Io::WouldBlock if nonblock => return partial(done, Errno::EAGAIN),
            Io::WouldBlock => {
                let want = if atomic { n } else { 1 };
                let pipe = end.pipe.clone();
                let waited = wait(
                    || {
                        let q = pipe.lock();
                        q.readers == 0 || PIPE_CAPACITY - q.len() >= want
                    },
                    None,
                );
                if waited != Waited::Ready {
                    return partial(done, Errno::EINTR);
                }
            }
        }
    }
}

fn write_eventfd(file: &EventFile, segs: &[(u64, u64)]) -> SysResult {
    if total(segs) != 8 {
        return Err(Errno::EINVAL);
    }
    let mut raw = [0u8; 8];
    if !copy_in(segs, 0, &mut raw) {
        return Err(Errno::EFAULT);
    }
    let n = u64::from_le_bytes(raw);
    if n == u64::MAX {
        return Err(Errno::EINVAL);
    }
    let nonblock = *file.status.lock() & O_NONBLOCK != 0;
    loop {
        if file.counter.lock().write(n) {
            changed();
            return Ok(8);
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        if wait(|| u64::MAX - file.counter.lock().count > n, None) != Waited::Ready {
            return Err(Errno::EINTR);
        }
    }
}

/// The poll mask of a pipe end, eventfd or epoll instance, or None for a
/// file.
pub fn poll_mask(object: &Object) -> Option<u16> {
    Some(match object {
        Object::Pipe(end) => end.pipe.lock().poll(!end.write),
        Object::EventFd(file) => file.counter.lock().poll(),
        Object::Epoll(ep) => crate::epoll::poll_mask(ep),
        Object::Socket(s) => s.poll(),
        Object::File(_) => return None,
    })
}

/// The device pipes report: pipefs is its own superblock on Linux, an
/// anonymous device (major 0); 0:3 is arbitrary, as procfs's 0:2.
pub const PIPEFS_DEV: (u32, u32) = (0, 3);
/// The device sockets report: sockfs's, 0:5.
pub const SOCKFS_DEV: (u32, u32) = (0, 5);
/// The device eventfds report: the anon-inode filesystem's, 0:4.
pub const ANON_INODE_DEV: (u32, u32) = (0, 4);
/// The inode every eventfd shares: Linux gives all of them the one
/// `anon_inode_inode` (`fs/anon_inodes.c`), so they report one st_ino.
const ANON_INODE_INO: u64 = 0xFFFF << 48;

/// stat of a pipe or eventfd, as the bytes of `struct stat`, or None for
/// any other object.
/// - a pipe is a FIFO, mode 0600, as pipefs makes them (`get_pipe_inode`:
///   S_IFIFO | S_IRUSR | S_IWUSR), with one inode per pipe;
/// - an eventfd is the anonymous inode, mode 0600 with no file type
///   (`alloc_anon_inode`: S_IRUSR | S_IWUSR), the same for all.
///
/// Both report size 0 and one link. Their times read as now, where Linux
/// keeps the pipe's creation (and its last read and write) and the boot
/// time for the anonymous inode (ADR 0025).
pub fn stat_bytes(object: &Object) -> Option<[u8; 144]> {
    const S_IFIFO: u32 = 0o010000;
    let (ino, mode, dev) = match object {
        Object::Pipe(end) => (end.ino, S_IFIFO | 0o600, PIPEFS_DEV),
        // An epoll instance is the same anonymous inode.
        Object::EventFd(_) | Object::Epoll(_) => (ANON_INODE_INO, 0o600, ANON_INODE_DEV),
        // A socket's own inode on sockfs, S_IFSOCK | 0777 (`sock_alloc`).
        Object::Socket(s) => (s.ino, keel_core::vfs::S_IFSOCK | 0o777, SOCKFS_DEV),
        Object::File(_) => return None,
    };
    let now = crate::fs::with(|fs| Ok(fs.time_now())).unwrap_or(Timespec::default());
    let stat = Stat {
        ino: ino as Ino,
        mode,
        size: 0,
        nlink: 1,
        rdev: (0, 0),
        atime: now,
        mtime: now,
        ctime: now,
    };
    Some(crate::abi::stat_bytes_on(&stat, dev))
}

/// The filesystem magic fstatfs reports for a pipe (PIPEFS_MAGIC) or an
/// eventfd (ANON_INODE_FS_MAGIC), `include/uapi/linux/magic.h`.
pub fn statfs_magic(object: &Object) -> Option<u64> {
    match object {
        Object::Pipe(_) => Some(0x5049_5045),
        Object::EventFd(_) | Object::Epoll(_) => Some(0x0904_1934),
        // SOCKFS_MAGIC.
        Object::Socket(_) => Some(0x534F_434B),
        Object::File(_) => None,
    }
}

/// The status flags of a pipe end or eventfd (F_GETFL, F_SETFL).
pub fn status(object: &Object) -> Option<&IrqMutex<u64>> {
    match object {
        Object::Pipe(end) => Some(&end.status),
        Object::EventFd(file) => Some(&file.status),
        Object::Epoll(ep) => Some(&ep.status),
        Object::Socket(s) => Some(&s.status),
        Object::File(_) => None,
    }
}

/// FIONREAD on a pipe (`pipe_ioctl`): the bytes waiting.
pub fn bytes_waiting(object: &Object) -> Option<usize> {
    match object {
        Object::Pipe(end) => Some(end.pipe.lock().len()),
        _ => None,
    }
}

/// What `fd` is ready for (`vfs_poll`), limited to what the handle's
/// rights allow (SR-1): readable only through a handle with READ,
/// writable only through one with WRITE (POLLERR and POLLHUP always).
/// Linux reports both whatever the access mode; Keel does not reveal
/// readiness for an operation the handle cannot perform
/// (docs/syscalls.md). None if `fd` is not open.
pub fn fd_ready(p: &ProcessRef, fd: i32) -> Option<u16> {
    let (object, rights) = {
        let process = p.lock();
        let object = process.handles.get(fd, Rights::NONE).ok()?.clone();
        (object, process.handles.rights(fd).ok()?)
    };
    Some(object_ready(&object, rights))
}

/// What `object` is ready for, through a handle with `rights` (as
/// [`fd_ready`]).
pub fn object_ready(object: &Object, rights: Rights) -> u16 {
    use keel_core::poll::*;
    let ready = match object {
        Object::File(file) => {
            // Copy the kind out: the file lock is not held while the
            // terminal's is taken.
            let kind = file.lock().kind;
            match kind {
                // n_tty_poll: writable while output has room (console
                // output never waits); readable once a line or end of
                // file is ready.
                keel_core::vfs::Kind::Device(keel_core::vfs::Device::Console) => {
                    let input = if crate::tty::readable() {
                        POLLIN | POLLRDNORM
                    } else {
                        0
                    };
                    input | POLLOUT | POLLWRNORM
                }
                // Regular files, directories, /dev/null, /dev/zero and
                // /dev/urandom have no poll method: DEFAULT_POLLMASK.
                _ => DEFAULT_POLLMASK,
            }
        }
        other => poll_mask(other).unwrap_or(0),
    };
    // POLLRDBAND and POLLRDHUP are about reading, POLLWRBAND writing.
    const POLLRDBAND: u16 = 0x80;
    const POLLWRBAND: u16 = 0x200;
    const POLLRDHUP: u16 = 0x2000;
    let mut allowed = POLLERR | POLLHUP;
    if rights.contains(Rights::READ) {
        allowed |= POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND | POLLRDHUP;
    }
    if rights.contains(Rights::WRITE) {
        allowed |= POLLOUT | POLLWRNORM | POLLWRBAND;
    }
    ready & allowed
}

/// The wait poll, select and their variants share (`do_poll`,
/// `do_select`): `scan` looks at every descriptor and returns how many
/// are ready (or an error); if none is, and a signal is pending that the
/// thread does not block, the call is interrupted (EINTR, even with a
/// zero timeout, as Linux's ERESTARTNOHAND); at the deadline it returns
/// 0; otherwise it waits for a readiness change and scans again.
fn wait_scan(
    p: &ProcessRef,
    deadline: Option<u64>,
    mut scan: impl FnMut() -> Result<u64, Errno>,
) -> Result<u64, Errno> {
    loop {
        let count = scan()?;
        if count > 0 {
            return Ok(count);
        }
        if crate::signal::pending_unblocked(p) || sched::interrupted() {
            return Err(Errno::EINTR);
        }
        if deadline.is_some_and(|d| keel_hal::time::monotonic_nanos() >= d) {
            return Ok(0);
        }
        // Wait for a change that makes something ready, a signal or the
        // deadline, then scan again for the result. The condition is the
        // scan itself, checked under the queue's lock, so a change that
        // lands between the scan above and the sleep is not missed.
        wait(
            || scan().map_or(true, |c| c > 0) || crate::signal::pending_unblocked(p),
            deadline,
        );
    }
}

/// `do_sys_poll` over the user array at `fds`: more entries than the
/// handle limit EINVAL (Linux: RLIMIT_NOFILE); EFAULT if the array cannot
/// be read, or its `revents` written back; otherwise the number of
/// entries with events (`revents` written back for all, 0 where none).
fn do_poll(p: &ProcessRef, fds: u64, nfds: u32, deadline: Option<u64>) -> SysResult {
    use keel_core::poll::{POLLFD_SIZE, PollFd, REVENTS_OFFSET, revents};
    if nfds as usize > crate::process::HANDLE_LIMIT {
        return Err(Errno::EINVAL);
    }
    let mut raw = alloc::vec![0u8; nfds as usize * POLLFD_SIZE];
    copy_from_user(&mut raw, fds).map_err(|_| Errno::EFAULT)?;
    let entries: Vec<PollFd> = raw
        .as_chunks::<POLLFD_SIZE>()
        .0
        .iter()
        .map(PollFd::from_bytes)
        .collect();
    let mut results = alloc::vec![0u16; entries.len()];
    let count = wait_scan(p, deadline, || {
        let mut count = 0;
        for (entry, result) in entries.iter().zip(results.iter_mut()) {
            // A negative fd is skipped without a lookup; any other number
            // either names an open handle or gets POLLNVAL.
            let ready = (entry.fd >= 0).then(|| fd_ready(p, entry.fd)).flatten();
            *result = revents(entry.fd, entry.events, ready);
            if *result != 0 {
                count += 1;
            }
        }
        Ok(count)
    })?;
    for (i, result) in results.iter().enumerate() {
        let at = fds + (i * POLLFD_SIZE + REVENTS_OFFSET) as u64;
        copy_to_user(at, &result.to_le_bytes()).map_err(|_| Errno::EFAULT)?;
    }
    Ok(count)
}

/// poll(2): a negative timeout waits without limit.
pub fn poll(p: &ProcessRef, fds: u64, nfds: u32, timeout_ms: i32) -> SysResult {
    do_poll(p, fds, nfds, deadline_ms(i64::from(timeout_ms)))
}

/// A `struct timespec` timeout (`poll_select_set_timeout`): EFAULT if
/// unreadable; a negative tv_sec or a tv_nsec outside 0..1e9 EINVAL. The
/// deadline, and whether it was zero (then never written back).
fn timespec_deadline(tsp: u64) -> Result<Option<(u64, bool)>, Errno> {
    if tsp == 0 {
        return Ok(None);
    }
    let mut b = [0u8; 16];
    copy_from_user(&mut b, tsp).map_err(|_| Errno::EFAULT)?;
    let sec = i64::from_le_bytes(b[..8].try_into().unwrap_or_default());
    let nsec = i64::from_le_bytes(b[8..].try_into().unwrap_or_default());
    timeout_from(sec, nsec)
}

fn timeout_from(sec: i64, nsec: i64) -> Result<Option<(u64, bool)>, Errno> {
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(Errno::EINVAL);
    }
    let span = (sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(nsec as u64);
    Ok(Some((
        keel_hal::time::monotonic_nanos().saturating_add(span),
        span == 0,
    )))
}

/// How a timed call writes back (`poll_select_finish`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum TimeForm {
    Timeval,
    Timespec,
}

/// `poll_select_finish`: puts back a mask the call replaced unless a
/// signal interrupted it (`restore_saved_sigmask_unless`), and writes the
/// time left (0 if none) to `at`, unless the timeout was zero. A failed
/// write is ignored, as on Linux ("an application puts its timeval in
/// read-only memory").
fn finish(
    p: &ProcessRef,
    at: u64,
    timeout: Option<(u64, bool)>,
    form: TimeForm,
    result: SysResult,
) -> SysResult {
    crate::signal::end_temporary_mask(p, result == Err(Errno::EINTR));
    if let Some((deadline, false)) = timeout {
        let left = deadline.saturating_sub(keel_hal::time::monotonic_nanos());
        let sec = left / 1_000_000_000;
        let sub = left % 1_000_000_000;
        let second = if form == TimeForm::Timeval {
            sub / 1000
        } else {
            sub
        };
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&sec.to_le_bytes());
        b[8..].copy_from_slice(&second.to_le_bytes());
        let _ = copy_to_user(at, &b);
    }
    result
}

/// ppoll(2): a timespec timeout (NULL waits without limit), and a signal
/// mask to block for the call (`set_user_sigmask`: a size other than 8
/// EINVAL). The time left is written back.
pub fn ppoll(p: &ProcessRef, fds: u64, nfds: u32, tsp: u64, mask: u64, size: u64) -> SysResult {
    let timeout = timespec_deadline(tsp)?;
    crate::signal::temporary_mask(p, mask, size)?;
    let result = do_poll(p, fds, nfds, timeout.map(|t| t.0));
    finish(p, tsp, timeout, TimeForm::Timespec, result)
}

/// `fd_set` bytes for `n` descriptors: whole longs (`FDS_BYTES`).
fn fds_bytes(n: usize) -> usize {
    n.div_ceil(64) * 8
}

/// The size Linux's descriptor table would have (`fdt->max_fds`), which
/// select clamps `n` to: 64 (NR_OPEN_DEFAULT) until a descriptor at or
/// above it is open, then as `alloc_fdtable` grows it for the highest one,
/// `h`: (h / 128 + 1) rounded up to a power of two, times 128 (1024 bytes
/// of 8-byte pointers), at most the handle limit. Linux's table never
/// shrinks, so Linux keeps the size of the highest descriptor ever open;
/// Keel takes the highest open now (ADR 0025).
fn max_fds(p: &ProcessRef) -> usize {
    const NR_OPEN_DEFAULT: usize = 64;
    let process = p.lock();
    let highest = (0..crate::process::HANDLE_LIMIT)
        .rev()
        .find(|&fd| process.handles.rights(fd as i32).is_ok());
    match highest {
        Some(h) if h >= NR_OPEN_DEFAULT => {
            ((h / 128 + 1).next_power_of_two() * 128).min(crate::process::HANDLE_LIMIT)
        }
        _ => NR_OPEN_DEFAULT,
    }
}

/// `core_sys_select`: n negative EINVAL, clamped to the descriptor
/// table's size ([`max_fds`]; bits past it are ignored); the three sets read
/// (absent ones empty; EFAULT if unreadable); a descriptor set in any of
/// them that is not open EBADF (`max_select_fd`). The result sets are
/// written back, only if the call was not interrupted (EFAULT if they
/// cannot be). The count counts each set's bits separately:
/// - readable: POLLIN_SET (RDNORM, RDBAND, IN, HUP, ERR, NVAL);
/// - writable: POLLOUT_SET (WRBAND, WRNORM, OUT, ERR, NVAL);
/// - exceptional: POLLEX_SET (PRI, NVAL).
fn do_select(p: &ProcessRef, n: i32, sets: [u64; 3], deadline: Option<u64>) -> SysResult {
    use keel_core::poll::*;
    const POLLRDBAND: u16 = 0x0080;
    const POLLWRBAND: u16 = 0x0200;
    const IN_SET: u16 = POLLRDNORM | POLLRDBAND | POLLIN | POLLHUP | POLLERR | POLLNVAL;
    const OUT_SET: u16 = POLLWRBAND | POLLWRNORM | POLLOUT | POLLERR | POLLNVAL;
    const EX_SET: u16 = POLLPRI | POLLNVAL;
    const MASKS: [u16; 3] = [IN_SET, OUT_SET, EX_SET];
    if n < 0 {
        return Err(Errno::EINVAL);
    }
    let n = (n as usize).min(max_fds(p));
    let size = fds_bytes(n);
    let mut wanted = [
        alloc::vec![0u8; size],
        alloc::vec![0u8; size],
        alloc::vec![0u8; size],
    ];
    for (set, &at) in wanted.iter_mut().zip(&sets) {
        if at != 0 {
            copy_from_user(set, at).map_err(|_| Errno::EFAULT)?;
        }
    }
    let bit = |set: &[u8], fd: usize| fd < n && set[fd / 8] & (1 << (fd % 8)) != 0;
    // max_select_fd: every descriptor asked about must be open.
    for fd in 0..n {
        if wanted.iter().any(|s| bit(s, fd)) && p.lock().handles.rights(fd as i32).is_err() {
            return Err(Errno::EBADF);
        }
    }
    let mut results = [
        alloc::vec![0u8; size],
        alloc::vec![0u8; size],
        alloc::vec![0u8; size],
    ];
    let count = wait_scan(p, deadline, || {
        let mut count = 0;
        for r in results.iter_mut() {
            r.fill(0);
        }
        for fd in 0..n {
            if !wanted.iter().any(|s| bit(s, fd)) {
                continue;
            }
            // Closed since the check: POLLNVAL, which every set reports
            // (Linux's do_select gives EPOLLNVAL for a vanished file too).
            let mask = fd_ready(p, fd as i32).unwrap_or(POLLNVAL);
            for i in 0..3 {
                if bit(&wanted[i], fd) && mask & MASKS[i] != 0 {
                    results[i][fd / 8] |= 1 << (fd % 8);
                    count += 1;
                }
            }
        }
        Ok(count)
    })?;
    for (set, &at) in results.iter().zip(&sets) {
        if at != 0 {
            copy_to_user(at, set).map_err(|_| Errno::EFAULT)?;
        }
    }
    Ok(count)
}

/// select(2): a `struct timeval` timeout (NULL waits without limit;
/// unreadable EFAULT). Microseconds of a second or more carry into the
/// seconds; a negative time EINVAL (`kern_select`). The time left is
/// written back.
pub fn select(p: &ProcessRef, n: i32, sets: [u64; 3], tvp: u64) -> SysResult {
    let timeout = if tvp == 0 {
        None
    } else {
        let mut b = [0u8; 16];
        copy_from_user(&mut b, tvp).map_err(|_| Errno::EFAULT)?;
        let sec = i64::from_le_bytes(b[..8].try_into().unwrap_or_default());
        let usec = i64::from_le_bytes(b[8..].try_into().unwrap_or_default());
        // Rust's / and % truncate toward zero, as C's.
        timeout_from(
            sec.saturating_add(usec / 1_000_000),
            (usec % 1_000_000) * 1000,
        )?
    };
    let result = do_select(p, n, sets, timeout.map(|t| t.0));
    finish(p, tvp, timeout, TimeForm::Timeval, result)
}

/// pselect6(2): a timespec timeout, and a mask from the "argpack" at
/// `sig` (a pointer and a size; EFAULT if unreadable; a NULL `sig` or
/// pointer is no mask).
pub fn pselect6(p: &ProcessRef, n: i32, sets: [u64; 3], tsp: u64, sig: u64) -> SysResult {
    let (mask, size) = if sig == 0 {
        (0, 0)
    } else {
        let mut b = [0u8; 16];
        copy_from_user(&mut b, sig).map_err(|_| Errno::EFAULT)?;
        (
            u64::from_le_bytes(b[..8].try_into().unwrap_or_default()),
            u64::from_le_bytes(b[8..].try_into().unwrap_or_default()),
        )
    };
    let timeout = timespec_deadline(tsp)?;
    crate::signal::temporary_mask(p, mask, size)?;
    let result = do_select(p, n, sets, timeout.map(|t| t.0));
    finish(p, tsp, timeout, TimeForm::Timespec, result)
}
