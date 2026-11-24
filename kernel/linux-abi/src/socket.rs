//! Unix domain sockets (P3-T11, ADR 0027 and ADR 0028): socket,
//! socketpair, bind, listen, connect, accept and accept4, getsockname,
//! getpeername, shutdown, setsockopt and getsockopt, and the data calls
//! (read, write, sendto, recvfrom, sendmsg, recvmsg), for stream and
//! datagram sockets, with descriptors (SCM_RIGHTS) and credentials
//! (SCM_CREDENTIALS) passed alongside, as Linux v6.12's `net/socket.c`,
//! `net/core/scm.c` and `net/unix/af_unix.c`.
//!
//! The receive queue holds message parts, as Linux's sk_buffs
//! (`keel_core::unix::Queue`): the bytes, the descriptors sent with them,
//! the sender's credentials and (for a datagram) the sender's name.
//!
//! A socket is an object of its own (`Object::Socket`). A connected pair
//! points at each other weakly; each side keeps the bytes it has received
//! (Linux's `sk_receive_queue`). connect makes the accepting side at once
//! (Linux's "embryo" socket), connected to the client, and queues it on
//! the listener; accept hands it out. A socket bound to a path has a
//! socket node in the filesystem, pinned while bound; one bound to an
//! abstract name is in a table of its compartment's (as Linux's are per
//! network namespace). Dropping the last reference to a socket releases
//! it as `unix_release_sock` does.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use keel_core::epoll::Wakes;
use keel_core::errno::Errno;
use keel_core::handle::{Handle, Rights};
use keel_core::signal::{SI_USER, SIGPIPE, SigInfo};
use keel_core::unix::{
    self as un, AF_UNIX, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_OOB, MSG_PEEK, MSG_WAITALL, Name,
    RCV_SHUTDOWN, SEND_SHUTDOWN, SHUTDOWN_MASK, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_MAX, SOCK_NONBLOCK,
    SOCK_RAW, SOCK_SEQPACKET, SOCK_STREAM, SOCK_TYPE_MASK, Target,
};
use keel_core::vfs::{Ino, Kind, Last};
use keel_hal::sched::{self, Waited};
use keel_hal::sync::IrqMutex;
use keel_hal::vm::{copy_from_user, copy_to_user};

use crate::abi::{AT_FDCWD, O_CLOEXEC, O_NONBLOCK, O_RDWR};
use crate::fs;
use crate::process::{Object, Process};
use crate::ready::{changed, wait};

type ProcessRef = Arc<IrqMutex<Process>>;
type SysResult = Result<u64, Errno>;

/// `AF_MAX` (`include/linux/socket.h`): families at or past it are
/// EAFNOSUPPORT before anything else.
const AF_MAX: i32 = 46;
/// SOCK_MIN_SNDBUF and SOCK_MIN_RCVBUF on x86-64 (`include/net/sock.h`,
/// `TCP_SKB_MIN_TRUESIZE`; checked on the Linux test host: 4608, 2304).
const MIN_SNDBUF: u32 = 4608;
const MIN_RCVBUF: u32 = 2304;
/// The wakes `sock_def_readable` (data arrived) and `unix_write_space`
/// (room appeared) announce.
const KEY_READABLE: u32 = 0x1 | 0x2 | 0x40 | 0x80;
const KEY_WRITABLE: u32 = 0x4 | 0x100 | 0x200;

/// A descriptor in flight (SCM_RIGHTS): the object and the rights of the
/// handle it was sent from, which the receiver's new handle gets (no more
/// than the sender had). The ticket counts it against its compartment's
/// in-flight limit while it is queued; a copy made by MSG_PEEK has none.
pub struct Passed {
    object: Object,
    rights: Rights,
    _ticket: Option<InFlight>,
}

impl Clone for Passed {
    fn clone(&self) -> Self {
        Passed {
            object: self.object.clone(),
            rights: self.rights,
            _ticket: None,
        }
    }
}

/// The most descriptors a compartment may have in flight at once. Linux
/// limits each user to RLIMIT_NOFILE (`too_many_unix_fds`, ETOOMANYREFS)
/// but exempts root, which all Keel processes are; Keel holds every
/// compartment to it, so in-flight descriptors (which a socket passed to
/// itself keeps alive: there is no garbage collector, ADR 0028) stay
/// bounded.
const INFLIGHT_LIMIT: usize = crate::process::HANDLE_LIMIT;

/// In-flight counts by compartment.
static INFLIGHT: IrqMutex<BTreeMap<u32, usize>> = IrqMutex::new(BTreeMap::new());

/// One descriptor counted as in flight; uncounted when dropped.
pub struct InFlight(u32);

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Some(n) = INFLIGHT.lock().get_mut(&self.0) {
            *n = n.saturating_sub(1);
        }
    }
}

/// A datagram's charge to its sender's send buffer (its `sk_wmem_alloc`),
/// released when the datagram is read or dropped, which wakes the sender
/// (`sock_wfree`, `unix_write_space`).
pub struct Charge {
    sender: Weak<Socket>,
    bytes: usize,
}

impl Drop for Charge {
    fn drop(&mut self) {
        if let Some(s) = self.sender.upgrade() {
            s.wmem
                .fetch_sub(self.bytes, core::sync::atomic::Ordering::Relaxed);
            s.wake(KEY_WRITABLE);
            changed();
        }
    }
}

type Part = un::Segment<Passed, Option<Charge>>;
type Queue = un::Queue<Passed, Option<Charge>>;

/// `max_dgram_qlen`: a datagram socket's queue is full past this many
/// (`unix_recvq_full`; the sysctl's default, 10).
const MAX_DGRAM_QLEN: usize = 10;

/// Who a socket's peer credentials name (`sk_peer_pid`, `sk_peer_cred`):
/// a process, by its compartment and PID there. Keel's processes are all
/// uid and gid 0.
#[derive(Clone, Copy, Debug)]
struct Cred {
    compartment: u32,
    pid: u32,
}

/// `sk_state`: TCP_CLOSE, TCP_LISTEN or TCP_ESTABLISHED.
enum Conn {
    Unconnected,
    Listening {
        backlog: u32,
        queue: VecDeque<Arc<Socket>>,
    },
    Connected {
        peer: Weak<Socket>,
        /// The peer's name when connected, in case it has gone since
        /// (Linux holds a reference to it).
        peer_name: Option<Name>,
    },
}

struct State {
    conn: Conn,
    name: Option<Name>,
    /// The socket node it is bound to, pinned while bound.
    node: Option<Ino>,
    recv: Queue,
    shutdown: u8,
    /// `sk_err`, reported once.
    err: Option<Errno>,
    /// Connected by connect but not yet accepted (released "embrion").
    embryo: bool,
    wakes: Wakes,
    passcred: bool,
    /// SO_REUSEADDR, SO_KEEPALIVE, SO_BROADCAST, SO_DONTROUTE,
    /// SO_OOBINLINE: kept and reported, with no effect on Unix sockets.
    flags: BTreeMap<i32, bool>,
    rcvtimeo: Option<u64>,
    sndtimeo: Option<u64>,
    sndbuf: u32,
    rcvbuf: u32,
    peercred: Option<Cred>,
}

/// A Unix domain socket, as an open file description.
pub struct Socket {
    /// F_GETFL: O_RDWR, and O_NONBLOCK if set (`sock_alloc_file`).
    pub status: IrqMutex<u64>,
    /// stat's st_ino: each socket has its own inode on sockfs.
    pub ino: u64,
    kind: u32,
    /// The compartment it was made in: its abstract names are there.
    compartment: u32,
    /// A datagram socket's bytes sent and not yet read.
    wmem: core::sync::atomic::AtomicUsize,
    state: IrqMutex<State>,
}

/// Bound names: abstract ones per compartment, path ones by the socket
/// node (`unix_find_socket_byinode`).
#[derive(Default)]
struct Names {
    /// By compartment, type and name: Linux's abstract names are per
    /// type (`unix_abstract_hash` mixes the type into the bucket).
    abstract_names: BTreeMap<(u32, u32, Vec<u8>), Weak<Socket>>,
    paths: BTreeMap<Ino, Weak<Socket>>,
}

static NAMES: IrqMutex<Names> = IrqMutex::new(Names {
    abstract_names: BTreeMap::new(),
    paths: BTreeMap::new(),
});

fn new_ino() -> u64 {
    static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
    (0xFFFD << 48) | NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

impl Socket {
    fn new(kind: u32, compartment: u32, nonblock: bool) -> Arc<Socket> {
        Arc::new(Socket {
            status: IrqMutex::new(O_RDWR | if nonblock { O_NONBLOCK } else { 0 }),
            ino: new_ino(),
            kind,
            compartment,
            wmem: core::sync::atomic::AtomicUsize::new(0),
            state: IrqMutex::new(State {
                conn: Conn::Unconnected,
                name: None,
                node: None,
                recv: Queue::default(),
                shutdown: 0,
                err: None,
                embryo: false,
                wakes: Wakes::new(),
                passcred: false,
                flags: BTreeMap::new(),
                rcvtimeo: None,
                sndtimeo: None,
                sndbuf: un::BUF_DEFAULT,
                rcvbuf: un::BUF_DEFAULT,
                peercred: None,
            }),
        })
    }

    fn nonblocking(&self) -> bool {
        *self.status.lock() & O_NONBLOCK != 0
    }

    fn peer_weak(&self) -> Option<Weak<Socket>> {
        match &self.state.lock().conn {
            Conn::Connected { peer, .. } => Some(peer.clone()),
            _ => None,
        }
    }

    fn peer(&self) -> Option<Arc<Socket>> {
        match &self.state.lock().conn {
            Conn::Connected { peer, .. } => peer.upgrade(),
            _ => None,
        }
    }

    /// The wakes of its wait queue (`sk_wq`), for epoll.
    pub fn wakes(&self) -> Wakes {
        self.state.lock().wakes
    }

    fn wake(&self, key: u32) {
        self.state.lock().wakes.wake(key);
    }

    /// `unix_poll` (stream) and `unix_dgram_poll`:
    /// - EPOLLERR with an error pending;
    /// - EPOLLHUP when shut down both ways, or (a stream socket) not
    ///   connected (TCP_CLOSE);
    /// - readable with data, a connection to accept, or the reading side
    ///   shut down (EPOLLRDHUP too);
    /// - writable unless listening, while what it has sent and is not yet
    ///   read is at most a quarter of its send buffer (`unix_writable`);
    ///   a datagram socket also not while its peer's queue is full and
    ///   that peer is not connected back to it.
    pub fn poll(&self) -> u16 {
        use keel_core::poll::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
        const POLLWRBAND: u16 = 0x200;
        const POLLRDHUP: u16 = 0x2000;
        let (mut mask, listening, closed, sndbuf) = {
            let s = self.state.lock();
            let mut mask = 0;
            if s.err.is_some() {
                mask |= POLLERR;
            }
            if s.shutdown == SHUTDOWN_MASK {
                mask |= POLLHUP;
            }
            if s.shutdown & RCV_SHUTDOWN != 0 {
                mask |= POLLRDHUP | POLLIN | POLLRDNORM;
            }
            let pending = match &s.conn {
                Conn::Listening { queue, .. } => !queue.is_empty(),
                _ => !s.recv.is_empty(),
            };
            if pending {
                mask |= POLLIN | POLLRDNORM;
            }
            (
                mask,
                matches!(s.conn, Conn::Listening { .. }),
                matches!(s.conn, Conn::Unconnected),
                s.sndbuf,
            )
        };
        if closed && self.kind == SOCK_STREAM {
            mask |= POLLHUP;
        }
        let mut writable = !listening && self.in_flight() * 4 <= sndbuf as usize;
        if writable
            && self.kind == SOCK_DGRAM
            && let Some(peer) = self.peer()
        {
            let ps = peer.state.lock();
            let back = matches!(&ps.conn, Conn::Connected { peer, .. } if core::ptr::eq(peer.as_ptr(), self));
            if !back && ps.recv.count() > MAX_DGRAM_QLEN {
                writable = false;
            }
        }
        if writable {
            mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
        }
        mask
    }

    /// The bytes it has sent that are not yet read (its `sk_wmem_alloc`,
    /// counted in bytes): a stream socket's are its peer's queue; a
    /// datagram socket's, its charges.
    fn in_flight(&self) -> usize {
        if self.kind == SOCK_DGRAM {
            return self.wmem.load(core::sync::atomic::Ordering::Relaxed);
        }
        self.peer().map_or(0, |p| p.state.lock().recv.len())
    }

    /// SIOCINQ (FIONREAD): the bytes waiting, for a datagram socket the
    /// first datagram's; EINVAL for a listening socket (`unix_inq_len`).
    pub fn inq(&self) -> Result<usize, Errno> {
        let s = self.state.lock();
        if matches!(s.conn, Conn::Listening { .. }) {
            return Err(Errno::EINVAL);
        }
        Ok(if self.kind == SOCK_DGRAM {
            s.recv.first_len()
        } else {
            s.recv.len()
        })
    }

    /// SIOCOUTQ: what it has sent that is not yet read.
    pub fn outq(&self) -> usize {
        self.in_flight()
    }
}

/// `unix_release_sock`, when the last reference goes: its names go; the
/// peer of a connected socket is shut down both ways, with ECONNRESET if
/// this side had unread data or was never accepted; the connections a
/// listener had not accepted are released too (their clients see
/// ECONNRESET).
impl Drop for Socket {
    fn drop(&mut self) {
        let me: *const Socket = self;
        let (name, node, conn, unread, embryo) = {
            let mut s = self.state.lock();
            s.shutdown = SHUTDOWN_MASK;
            (
                s.name.take(),
                s.node.take(),
                core::mem::replace(&mut s.conn, Conn::Unconnected),
                !s.recv.is_empty(),
                s.embryo,
            )
        };
        {
            let mut names = NAMES.lock();
            if let Some(Name::Abstract(a)) = &name {
                let key = (self.compartment, self.kind, a.clone());
                if names
                    .abstract_names
                    .get(&key)
                    .is_some_and(|w| w.as_ptr() == me)
                {
                    names.abstract_names.remove(&key);
                }
            }
            if let Some(ino) = node
                && names.paths.get(&ino).is_some_and(|w| w.as_ptr() == me)
            {
                names.paths.remove(&ino);
            }
        }
        if let Some(ino) = node {
            let _ = fs::with(|fs| {
                fs.unpin(ino);
                Ok(())
            });
        }
        match conn {
            // A datagram socket's peer is not told (`unix_release_sock`
            // shuts down only stream peers); its next send there is
            // ECONNREFUSED.
            Conn::Connected { .. } if self.kind == SOCK_DGRAM => {}
            Conn::Connected { peer, .. } => {
                if let Some(peer) = peer.upgrade() {
                    let mut ps = peer.state.lock();
                    ps.shutdown = SHUTDOWN_MASK;
                    if unread || embryo {
                        ps.err = Some(Errno::ECONNRESET);
                    }
                    ps.wakes.wake(0);
                }
            }
            // Dropping the queue releases each embryo in turn.
            Conn::Listening { queue, .. } => drop(queue),
            Conn::Unconnected => {}
        }
        changed();
    }
}

/// The socket behind `fd`: EBADF if not open, ENOTSOCK if not a socket
/// (`sockfd_lookup_light`). Socket calls need no right beyond the handle
/// (the data calls check READ and WRITE as read and write do).
fn socket_of(p: &ProcessRef, fd: i32) -> Result<Arc<Socket>, Errno> {
    match p.lock().handles.get(fd, Rights::NONE)? {
        Object::Socket(s) => Ok(s.clone()),
        _ => Err(Errno::ENOTSOCK),
    }
}

fn compartment_of(p: &ProcessRef) -> u32 {
    p.lock().member.compartment().id()
}

fn cred_of(p: &ProcessRef) -> Cred {
    let process = p.lock();
    Cred {
        compartment: process.member.compartment().id(),
        pid: process.pid(),
    }
}

fn install(p: &ProcessRef, socket: Arc<Socket>, cloexec: bool) -> Result<i32, Errno> {
    p.lock().handles.insert(Handle {
        object: Object::Socket(socket),
        rights: Rights::READ | Rights::WRITE | Rights::STAT | Rights::DUPLICATE,
        close_on_exec: cloexec,
    })
}

/// The type and flags of socket(2) and socketpair(2), and the socket's
/// kind (`__sys_socket_create`, `__sock_create`, `unix_create`):
/// - flags other than SOCK_CLOEXEC and SOCK_NONBLOCK EINVAL;
/// - a family below 0 or at AF_MAX or past EAFNOSUPPORT; a type at
///   SOCK_MAX or past EINVAL; any family but AF_UNIX EAFNOSUPPORT (Keel
///   has no other: ADR 0027);
/// - a protocol other than 0 and PF_UNIX EPROTONOSUPPORT;
/// - SOCK_STREAM and SOCK_DGRAM; SOCK_RAW is SOCK_DGRAM (`unix_create`);
///   SOCK_SEQPACKET is not supported (ESOCKTNOSUPPORT, ADR 0028), nor is
///   any other type.
fn socket_kind(family: i32, ty: u32, protocol: i32) -> Result<(u32, bool, bool), Errno> {
    let flags = ty & !SOCK_TYPE_MASK;
    if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    let kind = ty & SOCK_TYPE_MASK;
    if !(0..AF_MAX).contains(&family) {
        return Err(Errno::EAFNOSUPPORT);
    }
    if kind >= SOCK_MAX {
        return Err(Errno::EINVAL);
    }
    if family != i32::from(AF_UNIX) {
        return Err(Errno::EAFNOSUPPORT);
    }
    if protocol != 0 && protocol != i32::from(AF_UNIX) {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let kind = match kind {
        SOCK_STREAM => SOCK_STREAM,
        SOCK_DGRAM | SOCK_RAW => SOCK_DGRAM,
        SOCK_SEQPACKET => return Err(Errno::ESOCKTNOSUPPORT),
        _ => return Err(Errno::ESOCKTNOSUPPORT),
    };
    Ok((kind, flags & SOCK_CLOEXEC != 0, flags & SOCK_NONBLOCK != 0))
}

/// socket(2).
pub fn socket(p: &ProcessRef, family: i32, ty: u32, protocol: i32) -> SysResult {
    let (kind, cloexec, nonblock) = socket_kind(family, ty, protocol)?;
    let s = Socket::new(kind, compartment_of(p), nonblock);
    Ok(install(p, s, cloexec)? as u64)
}

/// socketpair(2) (`__sys_socketpair`, `unix_socketpair`): two sockets
/// connected to each other, each with the other's credentials (the
/// caller's); the descriptors written to `sv` (EFAULT closes both again).
pub fn socketpair(p: &ProcessRef, family: i32, ty: u32, protocol: i32, sv: u64) -> SysResult {
    let (kind, cloexec, nonblock) = socket_kind(family, ty, protocol)?;
    let compartment = compartment_of(p);
    let (a, b) = (
        Socket::new(kind, compartment, nonblock),
        Socket::new(kind, compartment, nonblock),
    );
    let cred = cred_of(p);
    for (me, other) in [(&a, &b), (&b, &a)] {
        let mut s = me.state.lock();
        s.conn = Conn::Connected {
            peer: Arc::downgrade(other),
            peer_name: None,
        };
        s.peercred = Some(cred);
    }
    let fa = install(p, a, cloexec)?;
    let fb = match install(p, b, cloexec) {
        Ok(fb) => fb,
        Err(e) => {
            let gone = p.lock().handles.close(fa);
            drop(gone);
            return Err(e);
        }
    };
    let mut pair = [0u8; 8];
    pair[..4].copy_from_slice(&fa.to_le_bytes());
    pair[4..].copy_from_slice(&fb.to_le_bytes());
    if copy_to_user(sv, &pair).is_err() {
        let gone = {
            let mut process = p.lock();
            (process.handles.close(fa), process.handles.close(fb))
        };
        drop(gone);
        return Err(Errno::EFAULT);
    }
    Ok(0)
}

/// `move_addr_to_kernel`.
fn addr_in(addr: u64, len: i32) -> Result<Vec<u8>, Errno> {
    let len = un::check_addr_len(len)?;
    let mut b = alloc::vec![0u8; len];
    copy_from_user(&mut b, addr).map_err(|_| Errno::EFAULT)?;
    Ok(b)
}

/// `move_addr_to_user`: the length at `len_at` (EFAULT if unreadable;
/// below 0 EINVAL) caps the bytes copied; the full length is written
/// back.
fn addr_out(sockaddr: &[u8], addr: u64, len_at: u64) -> Result<(), Errno> {
    let mut b = [0u8; 4];
    copy_from_user(&mut b, len_at).map_err(|_| Errno::EFAULT)?;
    let n = un::addr_copy_len(i32::from_le_bytes(b), sockaddr.len())?;
    if n > 0 {
        copy_to_user(addr, &sockaddr[..n]).map_err(|_| Errno::EFAULT)?;
    }
    copy_to_user(len_at, &(sockaddr.len() as i32).to_le_bytes()).map_err(|_| Errno::EFAULT)
}

/// `unix_autobind`: an unused abstract name of five hex digits, from a
/// random start (ENOSPC if all 2^20 are taken).
fn autobind(s: &Arc<Socket>) -> Result<(), Errno> {
    if s.state.lock().name.is_some() {
        return Ok(());
    }
    let mut seed = [0u8; 4];
    keel_hal::random::fill(&mut seed);
    let start = u32::from_le_bytes(seed);
    let mut names = NAMES.lock();
    for i in 1..=0x10_0000u32 {
        let name = Name::autobind(start.wrapping_add(i));
        let Name::Abstract(bytes) = &name else {
            continue;
        };
        let key = (s.compartment, s.kind, bytes.clone());
        if names
            .abstract_names
            .get(&key)
            .is_some_and(|w| w.strong_count() > 0)
        {
            continue;
        }
        names.abstract_names.insert(key, Arc::downgrade(s));
        drop(names);
        s.state.lock().name = Some(name);
        return Ok(());
    }
    Err(Errno::ENOSPC)
}

/// bind(2) (`__sys_bind`, `unix_bind`): the descriptor first (EBADF,
/// ENOTSOCK), then the address (EINVAL, EFAULT, [`un::parse`]):
/// - family alone: autobind (nothing if already named);
/// - a path (`unix_bind_bsd`): the socket node is made first, mode 0777
///   less the umask (EEXIST is EADDRINUSE; lookup errors as mknod's);
///   then a socket already named is EINVAL and the new node is removed;
/// - an abstract name (`unix_bind_abstract`): EINVAL if already named,
///   EADDRINUSE if the name is taken in the compartment.
pub fn bind(p: &ProcessRef, fd: i32, addr: u64, len: i32) -> SysResult {
    let s = socket_of(p, fd)?;
    let raw = addr_in(addr, len)?;
    match un::parse(&raw, true)? {
        Target::Autobind => autobind(&s)?,
        Target::Name(Name::Path(path)) => bind_path(p, &s, path)?,
        Target::Name(name @ Name::Abstract(_)) => {
            let Name::Abstract(bytes) = &name else {
                unreachable!()
            };
            if s.state.lock().name.is_some() {
                return Err(Errno::EINVAL);
            }
            let key = (s.compartment, s.kind, bytes.clone());
            let mut names = NAMES.lock();
            if names
                .abstract_names
                .get(&key)
                .is_some_and(|w| w.strong_count() > 0)
            {
                return Err(Errno::EADDRINUSE);
            }
            names.abstract_names.insert(key, Arc::downgrade(&s));
            drop(names);
            s.state.lock().name = Some(name);
        }
    }
    Ok(0)
}

fn bind_path(p: &ProcessRef, s: &Arc<Socket>, path: Vec<u8>) -> Result<(), Errno> {
    let parent = crate::fscalls::parent_of(p, AT_FDCWD, &path)?;
    // `filename_create`: a last component that is not a name EEXIST; a
    // trailing slash on a name to be made ENOENT.
    let Last::Name(last) = parent.last else {
        return Err(Errno::EADDRINUSE);
    };
    if parent.trailing_slash {
        return Err(Errno::ENOENT);
    }
    let umask = p.lock().umask;
    let quota = crate::syscall::quota_of(p);
    let dir = parent.dir;
    let node = fs::with(|fs| fs.create_socket_as(dir, last, 0o777 & !umask, quota.as_ref()))
        .map_err(|e| {
            if e == Errno::EEXIST {
                Errno::EADDRINUSE
            } else {
                e
            }
        })?;
    if s.state.lock().name.is_some() {
        let _ = fs::with(|fs| fs.unlink(dir, last));
        return Err(Errno::EINVAL);
    }
    let _ = fs::with(|fs| {
        fs.pin(node);
        Ok(())
    });
    NAMES.lock().paths.insert(node, Arc::downgrade(s));
    let mut st = s.state.lock();
    st.name = Some(Name::Path(path));
    st.node = Some(node);
    Ok(())
}

/// listen(2) (`__sys_listen`, `unix_listen`): the backlog capped at
/// SOMAXCONN (as unsigned, so a negative one too); not a stream socket
/// EOPNOTSUPP; unnamed EINVAL; connected EINVAL. Listening takes the
/// caller's credentials as the socket's (`update_peercred`).
pub fn listen(p: &ProcessRef, fd: i32, backlog: i32) -> SysResult {
    let s = socket_of(p, fd)?;
    let backlog = (backlog as u32).min(un::SOMAXCONN);
    if s.kind != SOCK_STREAM {
        return Err(Errno::EOPNOTSUPP);
    }
    let cred = cred_of(p);
    {
        let mut st = s.state.lock();
        if st.name.is_none() {
            return Err(Errno::EINVAL);
        }
        match &mut st.conn {
            Conn::Unconnected => {
                st.conn = Conn::Listening {
                    backlog,
                    queue: VecDeque::new(),
                }
            }
            Conn::Listening { backlog: b, .. } => *b = backlog,
            Conn::Connected { .. } => return Err(Errno::EINVAL),
        }
        st.peercred = Some(cred);
    }
    // A larger backlog may let a waiting connect in.
    changed();
    Ok(0)
}

/// `unix_find_other`: the socket a name names. A path is looked up
/// (following links; its errors as lookup's); a node that is not a socket,
/// or that no socket is bound to (any more), ECONNREFUSED; a socket of
/// another type EPROTOTYPE. An abstract name not bound in the caller's
/// compartment for this type ECONNREFUSED (abstract names are per type,
/// so never EPROTOTYPE).
fn find(p: &ProcessRef, name: &Name, kind: u32) -> Result<Arc<Socket>, Errno> {
    let found = match name {
        Name::Path(path) => {
            let node = crate::fscalls::node_at(p, AT_FDCWD, path, true, false)?;
            if fs::with(|fs| fs.kind(node))? != Kind::Socket {
                return Err(Errno::ECONNREFUSED);
            }
            NAMES.lock().paths.get(&node).and_then(Weak::upgrade)
        }
        Name::Abstract(bytes) => {
            let key = (compartment_of(p), kind, bytes.clone());
            NAMES
                .lock()
                .abstract_names
                .get(&key)
                .and_then(Weak::upgrade)
        }
    };
    let other = found.ok_or(Errno::ECONNREFUSED)?;
    if other.kind != kind {
        return Err(Errno::EPROTOTYPE);
    }
    Ok(other)
}

/// A wait for `ready`, up to a socket timeout (SO_RCVTIMEO or SO_SNDTIMEO;
/// None waits without limit): Ok when ready, EAGAIN at the timeout
/// (`sock_intr_errno` of a used-up timeout), EINTR on a signal.
fn wait_for(ready: impl FnMut() -> bool, timeout: Option<u64>) -> Result<(), Errno> {
    let deadline = timeout.map(|t| keel_hal::time::monotonic_nanos().saturating_add(t));
    match wait(ready, deadline) {
        Waited::Ready => Ok(()),
        Waited::TimedOut => Err(Errno::EAGAIN),
        Waited::Interrupted => Err(Errno::EINTR),
    }
}

/// connect(2) on a stream socket (`unix_stream_connect`), in Linux's
/// order:
/// 1. the address (EINVAL as [`un::parse`], not autobind);
/// 2. with SO_PASSCRED and no name, an autobind name;
/// 3. the listener ([`find`]): not listening, or shut down for reading,
///    ECONNREFUSED; its backlog full (more waiting than the backlog),
///    EAGAIN if non-blocking, else a wait (up to SO_SNDTIMEO);
/// 4. this socket already connected EISCONN, listening EINVAL;
/// 5. the connection: a new socket, connected to this one, named as the
///    listener, with the caller's credentials, queued on the listener;
///    this one gets the listener's credentials. It is connected at once:
///    it can send before the connection is accepted.
pub fn connect(p: &ProcessRef, fd: i32, addr: u64, len: i32) -> SysResult {
    let s = socket_of(p, fd)?;
    let raw = addr_in(addr, len)?;
    if s.kind == SOCK_DGRAM {
        return connect_dgram(p, &s, &raw);
    }
    let Target::Name(name) = un::parse(&raw, false)? else {
        return Err(Errno::EINVAL);
    };
    if s.state.lock().passcred {
        autobind(&s)?;
    }
    let nonblock = s.nonblocking();
    let sndtimeo = s.state.lock().sndtimeo;
    let other = loop {
        let other = find(p, &name, s.kind)?;
        let full = {
            let os = other.state.lock();
            match &os.conn {
                Conn::Listening { backlog, queue } if os.shutdown & RCV_SHUTDOWN == 0 => {
                    queue.len() > *backlog as usize
                }
                _ => return Err(Errno::ECONNREFUSED),
            }
        };
        if !full {
            break other;
        }
        if nonblock || sndtimeo == Some(0) {
            return Err(Errno::EAGAIN);
        }
        let target = Arc::downgrade(&other);
        drop(other);
        wait_for(
            || {
                target.upgrade().is_none_or(|o| match &o.state.lock().conn {
                    Conn::Listening { backlog, queue } => queue.len() <= *backlog as usize,
                    _ => true,
                })
            },
            sndtimeo,
        )?;
    };
    match s.state.lock().conn {
        Conn::Connected { .. } => return Err(Errno::EISCONN),
        Conn::Listening { .. } => return Err(Errno::EINVAL),
        Conn::Unconnected => {}
    }
    let embryo = Socket::new(s.kind, s.compartment, false);
    let (listener_name, listener_cred) = {
        let os = other.state.lock();
        (os.name.clone(), os.peercred)
    };
    let my_name = s.state.lock().name.clone();
    {
        let mut es = embryo.state.lock();
        es.conn = Conn::Connected {
            peer: Arc::downgrade(&s),
            peer_name: my_name,
        };
        es.name = listener_name.clone();
        es.peercred = Some(cred_of(p));
        es.embryo = true;
    }
    {
        let mut st = s.state.lock();
        st.conn = Conn::Connected {
            peer: Arc::downgrade(&embryo),
            peer_name: listener_name,
        };
        st.peercred = listener_cred;
    }
    {
        let mut os = other.state.lock();
        if let Conn::Listening { queue, .. } = &mut os.conn {
            queue.push_back(embryo);
        }
        os.wakes.wake(KEY_READABLE);
    }
    changed();
    Ok(0)
}

/// connect(2) on a datagram socket (`unix_dgram_connect`):
/// - shorter than the family EINVAL; AF_UNSPEC disconnects;
/// - otherwise the address (EINVAL), an autobind name with SO_PASSCRED,
///   the target ([`find`]), which must not be connected to another socket
///   (EPERM, `unix_may_send`);
/// - connecting elsewhere, or disconnecting, drops what this socket had
///   received (`unix_dgram_disconnected`), and if anything was dropped and
///   the old peer was connected back to it, the old peer gets ECONNRESET.
fn connect_dgram(p: &ProcessRef, s: &Arc<Socket>, raw: &[u8]) -> SysResult {
    const AF_UNSPEC: u16 = 0;
    if raw.len() < 2 {
        return Err(Errno::EINVAL);
    }
    let other = if u16::from_le_bytes([raw[0], raw[1]]) == AF_UNSPEC {
        None
    } else {
        let Target::Name(name) = un::parse(raw, false)? else {
            return Err(Errno::EINVAL);
        };
        if s.state.lock().passcred {
            autobind(s)?;
        }
        let other = find(p, &name, s.kind)?;
        if !may_send(s, &other) {
            return Err(Errno::EPERM);
        }
        Some(other)
    };
    let old = {
        let mut st = s.state.lock();
        let old = match &st.conn {
            Conn::Connected { peer, .. } => Some(peer.clone()),
            _ => None,
        };
        st.conn = match &other {
            Some(o) => Conn::Connected {
                peer: Arc::downgrade(o),
                peer_name: o.state.lock().name.clone(),
            },
            None => Conn::Unconnected,
        };
        old
    };
    if let Some(old) = old
        && other
            .as_ref()
            .is_none_or(|o| !core::ptr::eq(old.as_ptr(), Arc::as_ptr(o)))
    {
        let dropped = core::mem::take(&mut s.state.lock().recv);
        if !dropped.is_empty()
            && let Some(old) = old.upgrade()
            && points_at(&old, s)
        {
            old.state.lock().err = Some(Errno::ECONNRESET);
            old.wake(0);
        }
        drop(dropped);
    }
    changed();
    Ok(0)
}

/// Whether `a` is connected to `b`.
fn points_at(a: &Arc<Socket>, b: &Arc<Socket>) -> bool {
    matches!(&a.state.lock().conn, Conn::Connected { peer, .. } if core::ptr::eq(peer.as_ptr(), Arc::as_ptr(b)))
}

/// `unix_may_send`: `other` takes datagrams from `s` if it is connected to
/// no one, or to `s`.
fn may_send(s: &Arc<Socket>, other: &Arc<Socket>) -> bool {
    match &other.state.lock().conn {
        Conn::Connected { peer, .. } => core::ptr::eq(peer.as_ptr(), Arc::as_ptr(s)),
        _ => true,
    }
}

/// accept(2) and accept4(2) (`__sys_accept4_file`, `do_accept`,
/// `unix_accept`), in Linux's order:
/// - flags other than SOCK_CLOEXEC and SOCK_NONBLOCK EINVAL (after
///   EBADF, before ENOTSOCK);
/// - not a stream socket EOPNOTSUPP; not listening EINVAL;
/// - no connection waiting: EAGAIN if the listener is non-blocking, else
///   a wait (up to SO_RCVTIMEO; EINTR on a signal);
/// - the new socket inherits SO_PASSCRED; its peer's address is written
///   if asked (a fault then closes it again: EFAULT).
pub fn accept4(p: &ProcessRef, fd: i32, addr: u64, len_at: u64, flags: u32) -> SysResult {
    p.lock().handles.get(fd, Rights::NONE)?;
    if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    let s = socket_of(p, fd)?;
    if s.kind != SOCK_STREAM {
        return Err(Errno::EOPNOTSUPP);
    }
    let taken = loop {
        let (taken, rcvtimeo) = {
            let mut st = s.state.lock();
            let Conn::Listening { queue, .. } = &mut st.conn else {
                return Err(Errno::EINVAL);
            };
            (queue.pop_front(), st.rcvtimeo)
        };
        if let Some(t) = taken {
            break t;
        }
        if s.nonblocking() || rcvtimeo == Some(0) {
            return Err(Errno::EAGAIN);
        }
        let me = s.clone();
        wait_for(
            || match &me.state.lock().conn {
                Conn::Listening { queue, .. } => !queue.is_empty(),
                _ => true,
            },
            rcvtimeo,
        )?;
    };
    // Room in the backlog may let a waiting connect in.
    changed();
    let passcred = s.state.lock().passcred;
    let peer_addr = {
        let mut ts = taken.state.lock();
        ts.embryo = false;
        ts.passcred = passcred;
        peer_sockaddr(&ts)
    };
    if flags & SOCK_NONBLOCK != 0 {
        *taken.status.lock() |= O_NONBLOCK;
    }
    if addr != 0 {
        // The connection is taken: a fault closes it (do_accept's fput).
        addr_out(&peer_addr, addr, len_at)?;
    }
    Ok(install(p, taken, flags & SOCK_CLOEXEC != 0)? as u64)
}

/// The peer's address as getpeername gives it: its name now, or the one
/// it had when connected, or unnamed.
fn peer_sockaddr(st: &State) -> Vec<u8> {
    match &st.conn {
        Conn::Connected { peer, peer_name } => {
            let now = peer.upgrade().and_then(|p| p.state.lock().name.clone());
            now.or_else(|| peer_name.clone())
                .map_or_else(un::unnamed_sockaddr, |n| n.sockaddr())
        }
        _ => un::unnamed_sockaddr(),
    }
}

/// getsockname(2) and getpeername(2) (`unix_getname`): getpeername of a
/// socket with no peer ENOTCONN.
pub fn getname(p: &ProcessRef, fd: i32, addr: u64, len_at: u64, peer: bool) -> SysResult {
    let s = socket_of(p, fd)?;
    let sockaddr = {
        let st = s.state.lock();
        if peer {
            if !matches!(st.conn, Conn::Connected { .. }) {
                return Err(Errno::ENOTCONN);
            }
            peer_sockaddr(&st)
        } else {
            st.name
                .as_ref()
                .map_or_else(un::unnamed_sockaddr, Name::sockaddr)
        }
    };
    addr_out(&sockaddr, addr, len_at)?;
    Ok(0)
}

/// shutdown(2) (`unix_shutdown`): `how` outside SHUT_RD..SHUT_RDWR
/// EINVAL; the socket's shutdown gains how + 1; a stream peer gains the
/// mirror (reading shut here is writing shut there; a datagram peer
/// nothing). An unconnected socket is fine (0).
pub fn shutdown(p: &ProcessRef, fd: i32, how: i32) -> SysResult {
    let s = socket_of(p, fd)?;
    if !(un::SHUT_RD..=un::SHUT_RDWR).contains(&how) {
        return Err(Errno::EINVAL);
    }
    let mode = (how + 1) as u8;
    {
        let mut st = s.state.lock();
        st.shutdown |= mode;
        st.wakes.wake(0);
    }
    if let Some(peer) = s.peer().filter(|_| s.kind == SOCK_STREAM) {
        let mut mirror = 0;
        if mode & RCV_SHUTDOWN != 0 {
            mirror |= SEND_SHUTDOWN;
        }
        if mode & SEND_SHUTDOWN != 0 {
            mirror |= RCV_SHUTDOWN;
        }
        let mut ps = peer.state.lock();
        ps.shutdown |= mirror;
        ps.wakes.wake(0);
    }
    changed();
    Ok(0)
}

/// What a sendmsg's control data carries, checked (`__scm_send`).
#[derive(Default)]
pub struct Ancillary {
    fds: Vec<Passed>,
    creds: Option<un::Creds>,
}

/// `scm_send`: the control data parsed ([`un::parse_control`]: EINVAL);
/// each descriptor must be open with DUPLICATE (EBADF: passing one is
/// duplicating it, and a handle without DUPLICATE may not be, SR-1);
/// SCM_CREDENTIALS must name a process of the sender's compartment
/// (ESRCH, `find_get_pid`), with any uid and gid (Keel's processes are
/// root, which may claim them: `scm_check_creds`).
fn ancillary(p: &ProcessRef, control: &[u8]) -> Result<Ancillary, Errno> {
    let parsed = un::parse_control(control)?;
    let mut out = Ancillary::default();
    {
        let process = p.lock();
        for fd in parsed.fds {
            if fd < 0 {
                return Err(Errno::EBADF);
            }
            let object = process.handles.get(fd, Rights::DUPLICATE)?.clone();
            let rights = process.handles.rights(fd)?;
            out.fds.push(Passed {
                object,
                rights,
                _ticket: None,
            });
        }
    }
    if let Some((pid, uid, gid)) = parsed.creds {
        let compartment = p.lock().member.compartment().clone();
        let pid = u32::try_from(pid).map_err(|_| Errno::ESRCH)?;
        crate::process::find_in(&compartment, pid).ok_or(Errno::ESRCH)?;
        out.creds = Some(un::Creds {
            compartment: compartment.id(),
            pid,
            uid,
            gid,
        });
    }
    Ok(out)
}

/// `unix_attach_fds`: ETOOMANYREFS if the compartment already has more
/// than its limit in flight (`too_many_unix_fds`, held to all, ADR 0028);
/// else each descriptor is counted until it is received or dropped.
fn attach(compartment: u32, fds: Vec<Passed>) -> Result<Option<Vec<Passed>>, Errno> {
    if fds.is_empty() {
        return Ok(None);
    }
    let mut counts = INFLIGHT.lock();
    let n = counts.entry(compartment).or_insert(0);
    if *n > INFLIGHT_LIMIT {
        return Err(Errno::ETOOMANYREFS);
    }
    *n += fds.len();
    drop(counts);
    Ok(Some(
        fds.into_iter()
            .map(|f| Passed {
                _ticket: Some(InFlight(compartment)),
                ..f
            })
            .collect(),
    ))
}

/// `maybe_add_creds`: a part with no credentials gets the sender's if the
/// sender or the receiver has SO_PASSCRED, or the receiver is not yet
/// accepted (`!other->sk_socket`).
fn creds_for(
    p: &ProcessRef,
    given: Option<un::Creds>,
    sender_passcred: bool,
    receiver: &State,
) -> Option<un::Creds> {
    if given.is_some() {
        return given;
    }
    if sender_passcred || receiver.passcred || receiver.embryo {
        let c = cred_of(p);
        return Some(un::Creds {
            compartment: c.compartment,
            pid: c.pid,
            uid: 0,
            gid: 0,
        });
    }
    None
}

fn sigpipe(p: &ProcessRef) {
    let pid = p.lock().pid();
    crate::signal::send_to_thread(
        p,
        sched::current(),
        SigInfo::from_process(SIGPIPE, SI_USER, pid, 0),
    );
}

/// sendmsg's work for either type (`flags` with MSG_DONTWAIT added for a
/// non-blocking descriptor); `to` is an address given (its bytes).
pub fn send(
    p: &ProcessRef,
    s: &Arc<Socket>,
    segs: &[(u64, u64)],
    flags: u32,
    to: Option<&[u8]>,
    anc: Ancillary,
) -> SysResult {
    let flags = if s.nonblocking() {
        flags | MSG_DONTWAIT
    } else {
        flags
    };
    if flags & MSG_OOB != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if s.kind == SOCK_DGRAM {
        send_dgram(p, s, segs, flags, to, anc)
    } else {
        send_stream(p, s, segs, flags, to.is_some(), anc)
    }
}

/// `unix_stream_sendmsg`, in Linux's order:
/// - an address: EISCONN if connected, else EOPNOTSUPP;
/// - no peer ENOTCONN;
/// - sending shut down: EPIPE, and SIGPIPE unless MSG_NOSIGNAL;
/// - then the bytes go to the peer as room appears: its unread bytes from
///   this side may reach the send buffer (SO_SNDBUF). Without room:
///   EAGAIN if non-blocking and nothing was sent, else a wait (up to
///   SO_SNDTIMEO); the peer gone or shut for reading: EPIPE (with SIGPIPE
///   if nothing was sent), or the count so far.
/// - descriptors go with the first part (and with nothing, as a send of
///   no bytes sends no part, they are dropped); credentials with every
///   part ([`creds_for`]).
fn send_stream(
    p: &ProcessRef,
    s: &Arc<Socket>,
    segs: &[(u64, u64)],
    flags: u32,
    has_addr: bool,
    anc: Ancillary,
) -> SysResult {
    let (peer, shut, sndbuf, sndtimeo, passcred) = {
        let st = s.state.lock();
        if has_addr {
            return Err(if matches!(st.conn, Conn::Connected { .. }) {
                Errno::EISCONN
            } else {
                Errno::EOPNOTSUPP
            });
        }
        let peer = match &st.conn {
            Conn::Connected { peer, .. } => peer.clone(),
            _ => return Err(Errno::ENOTCONN),
        };
        (
            peer,
            st.shutdown & SEND_SHUTDOWN != 0,
            st.sndbuf as usize,
            st.sndtimeo,
            st.passcred,
        )
    };
    let pipe = |sent: u64| -> SysResult {
        if sent == 0 && flags & MSG_NOSIGNAL == 0 {
            sigpipe(p);
        }
        if sent > 0 {
            Ok(sent)
        } else {
            Err(Errno::EPIPE)
        }
    };
    if shut {
        return pipe(0);
    }
    let total = crate::ready::total(segs);
    let mut fds = Some(anc.fds);
    let mut sent = 0u64;
    let mut chunk = alloc::vec![0u8; (total as usize).min(sndbuf).max(1)];
    while sent < total {
        let Some(other) = peer.upgrade() else {
            return pipe(sent);
        };
        let room = {
            let os = other.state.lock();
            if os.shutdown & RCV_SHUTDOWN != 0 {
                drop(os);
                return pipe(sent);
            }
            sndbuf.saturating_sub(os.recv.len())
        };
        if room == 0 {
            if flags & MSG_DONTWAIT != 0 || sndtimeo == Some(0) {
                return if sent > 0 {
                    Ok(sent)
                } else {
                    Err(Errno::EAGAIN)
                };
            }
            let target = Arc::downgrade(&other);
            drop(other);
            let waited = wait_for(
                || {
                    target.upgrade().is_none_or(|o| {
                        let os = o.state.lock();
                        os.shutdown & RCV_SHUTDOWN != 0 || os.recv.len() < sndbuf
                    })
                },
                sndtimeo,
            );
            if let Err(e) = waited {
                return if sent > 0 { Ok(sent) } else { Err(e) };
            }
            continue;
        }
        let n = ((total - sent) as usize).min(room);
        if !crate::ready::copy_in(segs, sent, &mut chunk[..n]) {
            return if sent > 0 {
                Ok(sent)
            } else {
                Err(Errno::EFAULT)
            };
        }
        let passed = match attach(s.compartment, fds.take().unwrap_or_default()) {
            Ok(f) => f,
            Err(e) => return if sent > 0 { Ok(sent) } else { Err(e) },
        };
        {
            let mut os = other.state.lock();
            let creds = creds_for(p, anc.creds, passcred, &os);
            os.recv.push(un::Segment {
                data: chunk[..n].to_vec(),
                consumed: 0,
                fds: passed,
                creds,
                from: None,
                token: None,
            });
            os.wakes.wake(KEY_READABLE);
        }
        changed();
        sent += n as u64;
    }
    Ok(sent)
}

/// `unix_dgram_sendmsg`, in Linux's order:
/// - an address (EINVAL as connect's), else the connected peer (none:
///   ENOTCONN);
/// - with SO_PASSCRED and no name, an autobind name;
/// - longer than the send buffer less 32 bytes EMSGSIZE;
/// - room in this socket's send buffer (its datagrams not yet read below
///   SO_SNDBUF; this socket shut for sending EPIPE): without it EAGAIN if
///   non-blocking, else a wait (up to SO_SNDTIMEO);
/// - the bytes (EFAULT);
/// - the target ([`find`] for an address; a connected peer that has gone
///   disconnects this socket, dropping what it had received, and is
///   ECONNREFUSED); one connected to another socket EPERM; one shut for
///   reading EPIPE (no SIGPIPE);
/// - its queue full (more than `max_dgram_qlen`), unless it is this
///   socket or connected back to it: EAGAIN if non-blocking, else a wait;
/// - the datagram is queued whole, with this socket's name, its
///   descriptors and credentials; the call returns its length.
fn send_dgram(
    p: &ProcessRef,
    s: &Arc<Socket>,
    segs: &[(u64, u64)],
    flags: u32,
    to: Option<&[u8]>,
    anc: Ancillary,
) -> SysResult {
    let name = match to {
        Some(raw) => match un::parse(raw, false)? {
            Target::Name(n) => Some(n),
            Target::Autobind => return Err(Errno::EINVAL),
        },
        None => {
            if s.peer_weak().is_none() {
                return Err(Errno::ENOTCONN);
            }
            None
        }
    };
    if s.state.lock().passcred {
        autobind(s)?;
    }
    let len = crate::ready::total(segs) as usize;
    let (sndbuf, sndtimeo, passcred) = {
        let st = s.state.lock();
        (st.sndbuf as usize, st.sndtimeo, st.passcred)
    };
    if len > sndbuf.saturating_sub(32) {
        return Err(Errno::EMSGSIZE);
    }
    let nonblock = flags & MSG_DONTWAIT != 0 || sndtimeo == Some(0);
    // `sock_alloc_send_pskb`.
    loop {
        if s.state.lock().shutdown & SEND_SHUTDOWN != 0 {
            return Err(Errno::EPIPE);
        }
        if s.in_flight() < sndbuf {
            break;
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        let me = s.clone();
        wait_for(
            || me.in_flight() < sndbuf || me.state.lock().shutdown & SEND_SHUTDOWN != 0,
            sndtimeo,
        )?;
    }
    let mut data = alloc::vec![0u8; len];
    if !crate::ready::copy_in(segs, 0, &mut data) {
        return Err(Errno::EFAULT);
    }
    let other = loop {
        let other = match &name {
            Some(n) => find(p, n, s.kind)?,
            None => match s.peer_weak().and_then(|w| w.upgrade()) {
                Some(o) => o,
                None => {
                    // The peer has gone: disconnect (`unix_dgram_disconnected`).
                    let dropped = {
                        let mut st = s.state.lock();
                        st.conn = Conn::Unconnected;
                        core::mem::take(&mut st.recv)
                    };
                    drop(dropped);
                    return Err(Errno::ECONNREFUSED);
                }
            },
        };
        if !may_send(s, &other) {
            return Err(Errno::EPERM);
        }
        let (shut, full) = {
            let os = other.state.lock();
            (
                os.shutdown & RCV_SHUTDOWN != 0,
                os.recv.count() > MAX_DGRAM_QLEN,
            )
        };
        if shut {
            return Err(Errno::EPIPE);
        }
        if !full || Arc::ptr_eq(&other, s) || points_at(&other, s) {
            break other;
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        let target = Arc::downgrade(&other);
        drop(other);
        wait_for(
            || {
                target
                    .upgrade()
                    .is_none_or(|o| o.state.lock().recv.count() <= MAX_DGRAM_QLEN)
            },
            sndtimeo,
        )?;
    };
    let passed = attach(s.compartment, anc.fds)?;
    let from = s.state.lock().name.clone();
    s.wmem.fetch_add(len, core::sync::atomic::Ordering::Relaxed);
    let charge = Charge {
        sender: Arc::downgrade(s),
        bytes: len,
    };
    {
        let mut os = other.state.lock();
        let creds = creds_for(p, anc.creds, passcred, &os);
        os.recv.push(un::Segment {
            data,
            consumed: 0,
            fds: passed,
            creds,
            from,
            token: Some(charge),
        });
        os.wakes.wake(KEY_READABLE);
    }
    changed();
    Ok(len as u64)
}

/// What a receive got besides its bytes.
#[derive(Default)]
pub struct Received {
    pub n: u64,
    /// The sender's address (empty: none to report, length 0).
    pub from: Vec<u8>,
    pub fds: Vec<Passed>,
    /// The `struct ucred` SO_PASSCRED reports, if the reader has it.
    pub creds: Option<[u8; 12]>,
    /// MSG_TRUNC: a datagram was longer than the buffer.
    pub truncated: bool,
}

/// The `struct ucred` for a part's credentials (`__scm_recv_common`): its
/// pid if of the reader's compartment (the socket's; else 0), its uid and gid; a part
/// with none, pid 0 and the overflow uid and gid (65534, as
/// `from_kuid_munged` of INVALID_UID); nothing read, all 0 (the zeroed
/// cookie).
fn ucred_of(read: Option<Option<un::Creds>>, me: u32) -> [u8; 12] {
    const OVERFLOW: u32 = 65534;
    match read {
        Some(Some(c)) => un::ucred_bytes(if c.compartment == me { c.pid } else { 0 }, c.uid, c.gid),
        Some(None) => un::ucred_bytes(0, OVERFLOW, OVERFLOW),
        None => un::ucred_bytes(0, 0, 0),
    }
}

/// recvmsg's work for either type.
pub fn recv(s: &Arc<Socket>, segs: &[(u64, u64)], flags: u32) -> Result<Received, Errno> {
    let flags = if s.nonblocking() {
        flags | MSG_DONTWAIT
    } else {
        flags
    };
    if s.kind == SOCK_DGRAM {
        return recv_dgram(s, segs, flags);
    }
    if !matches!(s.state.lock().conn, Conn::Connected { .. }) {
        return Err(Errno::EINVAL);
    }
    if flags & MSG_OOB != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    recv_stream(s, segs, flags)
}

/// `unix_stream_read_generic` into the user segments `segs`:
/// - what is waiting, up to the total (all of it with MSG_WAITALL, else
///   at least one byte); MSG_PEEK leaves it (and copies any descriptors);
/// - it stops after a part with descriptors, and (with SO_PASSCRED)
///   before a part whose credentials differ from the first one's
///   ([`un::Queue::stream_plan`]);
/// - nothing waiting: a pending error (ECONNRESET, reported once), then
///   reading shut down (0), then EAGAIN if non-blocking, else a wait (up
///   to SO_RCVTIMEO; EINTR on a signal);
/// - bytes that fault on the way out stay; a fault before any EFAULT.
fn recv_stream(s: &Arc<Socket>, segs: &[(u64, u64)], flags: u32) -> Result<Received, Errno> {
    let size = crate::ready::total(segs);
    let peek = flags & MSG_PEEK != 0;
    let target = if flags & MSG_WAITALL != 0 {
        size.max(1)
    } else {
        1
    };
    let passcred = s.state.lock().passcred;
    let mut rs = un::ReadState::default();
    let mut out = Received::default();
    let mut copied = 0u64;
    let mut buf = alloc::vec![0u8; (size as usize).min(65536)];
    let mut from = None;
    let mut fds: Option<Vec<Passed>> = None;
    loop {
        let (plan, rcvtimeo, peeked) = {
            let mut st = s.state.lock();
            if st.recv.is_empty() {
                if copied >= target {
                    break;
                }
                if let Some(e) = st.err.take() {
                    if copied > 0 {
                        break;
                    }
                    return Err(e);
                }
                if st.shutdown & RCV_SHUTDOWN != 0 {
                    break;
                }
                (None, st.rcvtimeo, None)
            } else {
                let want = ((size - copied) as usize).min(buf.len());
                let plan = st.recv.stream_plan(&mut buf[..want], passcred, &mut rs);
                let peeked = if peek { st.recv.peek_fds(plan.n) } else { None };
                (Some(plan), st.rcvtimeo, peeked)
            }
        };
        let Some(plan) = plan else {
            if flags & MSG_DONTWAIT != 0 || rcvtimeo == Some(0) {
                if copied > 0 {
                    break;
                }
                return Err(Errno::EAGAIN);
            }
            let me = s.clone();
            if let Err(e) = wait_for(
                || {
                    let st = me.state.lock();
                    !st.recv.is_empty() || st.err.is_some() || st.shutdown & RCV_SHUTDOWN != 0
                },
                rcvtimeo,
            ) {
                if copied > 0 {
                    break;
                }
                return Err(e);
            }
            continue;
        };
        let n = plan.n;
        let out_segs = skip_segments(segs, copied);
        let done = crate::ready::copy_out(&out_segs, &buf[..n]);
        if from.is_none() && n > 0 {
            from = Some(sender_name(&s.state.lock()));
        }
        if !peek && done > 0 {
            let got = s.state.lock().recv.consume(done);
            if got.is_some() {
                fds = got;
            }
            // `unix_write_space`: the writer may have room now.
            if let Some(peer) = s.peer() {
                peer.wake(KEY_WRITABLE);
            }
            changed();
        }
        if peek && fds.is_none() {
            fds = peeked;
        }
        copied += done as u64;
        if done < n {
            if copied == 0 {
                return Err(Errno::EFAULT);
            }
            break;
        }
        if plan.stop || peek || copied >= size || copied >= target && s.state.lock().recv.is_empty()
        {
            break;
        }
    }
    out.n = copied;
    out.from = from.unwrap_or_default();
    out.fds = fds.unwrap_or_default();
    if passcred {
        out.creds = Some(ucred_of(rs.creds, s.compartment));
    }
    Ok(out)
}

/// `__unix_dgram_recvmsg`: one datagram (MSG_PEEK leaves it, copying its
/// descriptors):
/// - none waiting: a pending error first, then reading shut down (0),
///   then EAGAIN if non-blocking, else a wait (up to SO_RCVTIMEO);
/// - a buffer shorter than the datagram takes what fits, and MSG_TRUNC
///   is set; with MSG_TRUNC in the flags the call returns the datagram's
///   whole length;
/// - a fault copying it out loses it (it was taken): EFAULT;
/// - the sender's name if it had one; descriptors; credentials with
///   SO_PASSCRED.
fn recv_dgram(s: &Arc<Socket>, segs: &[(u64, u64)], flags: u32) -> Result<Received, Errno> {
    if flags & MSG_OOB != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let peek = flags & MSG_PEEK != 0;
    let size = crate::ready::total(segs) as usize;
    let passcred = s.state.lock().passcred;
    let (data, fds, creds, from_name, part) = loop {
        let (got, rcvtimeo) = {
            let mut st = s.state.lock();
            if peek {
                let got = st.recv.front().map(|f| {
                    (
                        f.data[f.consumed..].to_vec(),
                        f.fds.clone(),
                        f.creds,
                        f.from.clone(),
                        None::<Part>,
                    )
                });
                (got, st.rcvtimeo)
            } else if let Some(mut part) = st.recv.pop() {
                let data = core::mem::take(&mut part.data);
                let fds = part.fds.take();
                (
                    Some((data, fds, part.creds, part.from.clone(), Some(part))),
                    st.rcvtimeo,
                )
            } else {
                (None, st.rcvtimeo)
            }
        };
        if let Some(g) = got {
            break g;
        }
        {
            let mut st = s.state.lock();
            if let Some(e) = st.err.take() {
                return Err(e);
            }
            if st.shutdown & RCV_SHUTDOWN != 0 {
                return Ok(Received::default());
            }
        }
        if flags & MSG_DONTWAIT != 0 || rcvtimeo == Some(0) {
            return Err(Errno::EAGAIN);
        }
        let me = s.clone();
        wait_for(
            || {
                let st = me.state.lock();
                !st.recv.is_empty() || st.err.is_some() || st.shutdown & RCV_SHUTDOWN != 0
            },
            rcvtimeo,
        )?;
    };
    // The datagram has left the queue: its charge goes, waking its sender.
    drop(part);
    let n = size.min(data.len());
    if crate::ready::copy_out(segs, &data[..n]) < n {
        return Err(Errno::EFAULT);
    }
    Ok(Received {
        n: if flags & un::MSG_TRUNC != 0 {
            data.len() as u64
        } else {
            n as u64
        },
        from: from_name.map_or_else(Vec::new, |n| n.sockaddr()),
        fds: fds.unwrap_or_default(),
        creds: passcred.then(|| ucred_of(Some(creds), s.compartment)),
        truncated: data.len() > size,
    })
}

/// The sender's address as recvfrom reports it (`unix_copy_addr`): the
/// peer's name, or nothing (a length of 0) if it has none.
fn sender_name(st: &State) -> Vec<u8> {
    match &st.conn {
        Conn::Connected { peer, peer_name } => peer
            .upgrade()
            .and_then(|p| p.state.lock().name.clone())
            .or_else(|| peer_name.clone())
            .map_or_else(Vec::new, |n| n.sockaddr()),
        _ => Vec::new(),
    }
}

/// `segs` with the first `skip` bytes dropped.
fn skip_segments(segs: &[(u64, u64)], mut skip: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for &(base, len) in segs {
        if skip >= len {
            skip -= len;
            continue;
        }
        out.push((base + skip, len - skip));
        skip = 0;
    }
    out
}

/// read(2) and readv(2) on a socket (`sock_read_iter`): nothing asked is
/// 0 at once; otherwise recv with no flags (descriptors that come with the
/// bytes are closed, as `scm_destroy`).
pub fn read(s: &Arc<Socket>, segs: &[(u64, u64)]) -> SysResult {
    if crate::ready::total(segs) == 0 {
        return Ok(0);
    }
    recv(s, segs, 0).map(|r| r.n)
}

/// write(2) and writev(2) on a socket (`sock_write_iter`): send with no
/// flags.
pub fn write(p: &ProcessRef, s: &Arc<Socket>, segs: &[(u64, u64)]) -> SysResult {
    send(p, s, segs, 0, None, Ancillary::default())
}

/// sendto(2) (`__sys_sendto`): the descriptor (EBADF, ENOTSOCK), then
/// the address if any (EINVAL, EFAULT; a length of 0 is none), then the
/// send.
pub fn sendto(
    p: &ProcessRef,
    fd: i32,
    buf: u64,
    len: u64,
    flags: u32,
    addr: u64,
    alen: i32,
) -> SysResult {
    let s = socket_of(p, fd)?;
    let to = if addr != 0 {
        let raw = addr_in(addr, alen)?;
        (alen != 0).then_some(raw)
    } else {
        None
    };
    send(
        p,
        &s,
        &[(buf, len)],
        flags,
        to.as_deref(),
        Ancillary::default(),
    )
}

/// recvfrom(2) (`__sys_recvfrom`): the sender's address is written if
/// asked; with nothing to report its length is 0 (`msg_namelen` stays 0).
pub fn recvfrom(
    p: &ProcessRef,
    fd: i32,
    buf: u64,
    len: u64,
    flags: u32,
    addr: u64,
    len_at: u64,
) -> SysResult {
    let s = socket_of(p, fd)?;
    let r = recv(&s, &[(buf, len)], flags)?;
    if addr != 0 {
        addr_out(&r.from, addr, len_at)?;
    }
    Ok(r.n)
}

/// `struct user_msghdr` on x86-64: msg_name 0, msg_namelen 8 (int),
/// msg_iov 16, msg_iovlen 24, msg_control 32, msg_controllen 40,
/// msg_flags 48 (int); 56 bytes.
struct MsgHdr {
    name: u64,
    namelen: i32,
    iov: Vec<(u64, u64)>,
    control: u64,
    controllen: u64,
}

/// `copy_msghdr_from_user`, `__copy_msghdr`: unreadable EFAULT; a
/// negative name length EINVAL (a NULL name has none); more than
/// UIO_MAXIOV vectors EMSGSIZE; then the vectors (`import_iovec`).
fn msghdr(at: u64) -> Result<MsgHdr, Errno> {
    let mut b = [0u8; 56];
    copy_from_user(&mut b, at).map_err(|_| Errno::EFAULT)?;
    let word = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or_default());
    let name = word(0);
    let mut namelen = i32::from_le_bytes(b[8..12].try_into().unwrap_or_default());
    if name == 0 {
        namelen = 0;
    }
    if namelen < 0 {
        return Err(Errno::EINVAL);
    }
    let namelen = namelen.min(un::SOCKADDR_STORAGE_SIZE as i32);
    if word(24) > 1024 {
        return Err(Errno::EMSGSIZE);
    }
    let iov = crate::fscalls::iovecs(word(16), word(24))?;
    Ok(MsgHdr {
        name,
        namelen,
        iov,
        control: word(32),
        controllen: word(40),
    })
}

/// sendmsg(2) (`____sys_sendmsg`): the name (EINVAL, EFAULT); a control
/// length past INT_MAX ENOBUFS; the control data copied in (EFAULT) and
/// checked ([`ancillary`]); then the send.
pub fn sendmsg(p: &ProcessRef, fd: i32, msg: u64, flags: u32) -> SysResult {
    let s = socket_of(p, fd)?;
    let m = msghdr(msg)?;
    let to = if m.namelen > 0 {
        Some(addr_in(m.name, m.namelen)?)
    } else {
        None
    };
    if m.controllen > i32::MAX as u64 {
        return Err(Errno::ENOBUFS);
    }
    let anc = if m.controllen > 0 {
        let mut control = alloc::vec![0u8; m.controllen as usize];
        copy_from_user(&mut control, m.control).map_err(|_| Errno::EFAULT)?;
        ancillary(p, &control)?
    } else {
        Ancillary::default()
    };
    send(p, &s, &m.iov, flags, to.as_deref(), anc)
}

/// recvmsg(2) (`____sys_recvmsg`, `scm_recv_unix`): after the read:
/// - the name (if asked) and its length;
/// - the control data: SCM_CREDENTIALS first (with SO_PASSCRED), then
///   SCM_RIGHTS, each as `put_cmsg` and `scm_detach_fds` fit them; with
///   no control buffer, MSG_CTRUNC if either was due. Each descriptor
///   received is a new handle with the sender's rights, close-on-exec
///   with MSG_CMSG_CLOEXEC; those that do not fit (or find no free
///   number: EMFILE) are closed, and MSG_CTRUNC set;
/// - msg_controllen (the bytes used) and msg_flags (MSG_CMSG_CLOEXEC
///   kept, MSG_TRUNC, MSG_CTRUNC).
pub fn recvmsg(p: &ProcessRef, fd: i32, msg: u64, flags: u32) -> SysResult {
    const MSG_CTRUNC: u32 = 0x8;
    let s = socket_of(p, fd)?;
    let m = msghdr(msg)?;
    let r = recv(&s, &m.iov, flags)?;
    if m.name != 0 {
        let k = (m.namelen as usize).min(r.from.len());
        copy_to_user(m.name, &r.from[..k]).map_err(|_| Errno::EFAULT)?;
        copy_to_user(msg + 8, &(r.from.len() as i32).to_le_bytes()).map_err(|_| Errno::EFAULT)?;
    } else {
        copy_to_user(msg + 8, &0i32.to_le_bytes()).map_err(|_| Errno::EFAULT)?;
    }
    let room = if m.control == 0 {
        0
    } else {
        m.controllen as usize
    };
    let mut out = un::ControlOut::new(room);
    let has_control = m.control != 0;
    if let Some(c) = r.creds {
        if has_control {
            out.put(un::SCM_CREDENTIALS, &c);
        } else {
            out.truncated = true;
        }
    }
    let count = r.fds.len();
    let mut installed = Vec::new();
    if count > 0 {
        if has_control {
            let fit = out.fd_room(count);
            let cloexec = flags & un::MSG_CMSG_CLOEXEC != 0;
            for passed in r.fds.into_iter().take(fit) {
                let inserted = p.lock().handles.insert(Handle {
                    object: passed.object,
                    rights: passed.rights,
                    close_on_exec: cloexec,
                });
                match inserted {
                    Ok(n) => installed.push(n),
                    Err(_) => break,
                }
            }
            out.put_fds(&installed, count);
        } else {
            out.truncated = true;
        }
    }
    if !out.bytes.is_empty() && copy_to_user(m.control, &out.bytes).is_err() {
        // `put_cmsg`'s EFAULT: nothing delivered; the new handles go.
        let gone: Vec<_> = {
            let mut process = p.lock();
            installed
                .iter()
                .map(|&n| process.handles.close(n))
                .collect()
        };
        drop(gone);
        out.bytes.clear();
        out.truncated = true;
    }
    let mut out_flags = flags & un::MSG_CMSG_CLOEXEC;
    if out.truncated {
        out_flags |= MSG_CTRUNC;
    }
    if r.truncated {
        out_flags |= un::MSG_TRUNC;
    }
    copy_to_user(msg + 48, &out_flags.to_le_bytes()).map_err(|_| Errno::EFAULT)?;
    copy_to_user(msg + 40, &(out.bytes.len() as u64).to_le_bytes()).map_err(|_| Errno::EFAULT)?;
    Ok(r.n)
}

const SOL_SOCKET: i32 = 1;
const SO_DEBUG: i32 = 1;
const SO_REUSEADDR: i32 = 2;
const SO_TYPE: i32 = 3;
const SO_ERROR: i32 = 4;
const SO_DONTROUTE: i32 = 5;
const SO_BROADCAST: i32 = 6;
const SO_SNDBUF: i32 = 7;
const SO_RCVBUF: i32 = 8;
const SO_KEEPALIVE: i32 = 9;
const SO_OOBINLINE: i32 = 10;
const SO_PASSCRED: i32 = 16;
const SO_PEERCRED: i32 = 17;
const SO_RCVTIMEO_OLD: i32 = 20;
const SO_SNDTIMEO_OLD: i32 = 21;
const SO_ACCEPTCONN: i32 = 30;
const SO_PROTOCOL: i32 = 38;
const SO_DOMAIN: i32 = 39;

/// setsockopt(2) (`do_sock_setsockopt`, `sk_setsockopt`):
/// - a negative length EINVAL; levels other than SOL_SOCKET EOPNOTSUPP
///   (a Unix socket has no protocol options);
/// - a length below an int EINVAL; unreadable EFAULT;
/// - SO_PASSCRED; SO_SNDBUF and SO_RCVBUF (capped, doubled, a minimum);
///   SO_RCVTIMEO and SO_SNDTIMEO (a timeval: EDOM for microseconds out of
///   range; negative means no waiting, zero no limit); the flags SO_DEBUG,
///   SO_REUSEADDR, SO_DONTROUTE, SO_BROADCAST, SO_KEEPALIVE and
///   SO_OOBINLINE (kept);
/// - SO_TYPE, SO_PROTOCOL, SO_DOMAIN and SO_ERROR ENOPROTOOPT, and so is
///   any other option (ADR 0027 lists them).
pub fn setsockopt(p: &ProcessRef, fd: i32, level: i32, name: i32, val: u64, len: i32) -> SysResult {
    let s = socket_of(p, fd)?;
    if len < 0 {
        return Err(Errno::EINVAL);
    }
    if level != SOL_SOCKET {
        return Err(Errno::EOPNOTSUPP);
    }
    if len < 4 {
        return Err(Errno::EINVAL);
    }
    let mut b = [0u8; 4];
    copy_from_user(&mut b, val).map_err(|_| Errno::EFAULT)?;
    let v = i32::from_le_bytes(b);
    let mut st = s.state.lock();
    match name {
        SO_PASSCRED => st.passcred = v != 0,
        SO_SNDBUF => st.sndbuf = un::buffer_size(v, MIN_SNDBUF),
        SO_RCVBUF => st.rcvbuf = un::buffer_size(v, MIN_RCVBUF),
        SO_DEBUG | SO_REUSEADDR | SO_DONTROUTE | SO_BROADCAST | SO_KEEPALIVE | SO_OOBINLINE => {
            st.flags.insert(name, v != 0);
        }
        SO_RCVTIMEO_OLD | SO_SNDTIMEO_OLD => {
            // `sock_copy_user_timeval`: an old timeval needs its 16 bytes.
            if (len as usize) < 16 {
                return Err(Errno::EINVAL);
            }
            drop(st);
            let mut t = [0u8; 16];
            copy_from_user(&mut t, val).map_err(|_| Errno::EFAULT)?;
            let sec = i64::from_le_bytes(t[..8].try_into().unwrap_or_default());
            let usec = i64::from_le_bytes(t[8..].try_into().unwrap_or_default());
            let timeout = un::timeout(sec, usec)?;
            let mut st = s.state.lock();
            if name == SO_RCVTIMEO_OLD {
                st.rcvtimeo = timeout;
            } else {
                st.sndtimeo = timeout;
            }
            return Ok(0);
        }
        _ => return Err(Errno::ENOPROTOOPT),
    }
    drop(st);
    changed();
    Ok(0)
}

/// getsockopt(2) (`do_sock_getsockopt`, `sk_getsockopt`): levels other
/// than SOL_SOCKET EOPNOTSUPP (checked first); then the length at
/// `len_at` (EFAULT; negative EINVAL) caps what is copied, and the length
/// used is written back; unknown options ENOPROTOOPT. SO_PEERCRED is a `struct ucred` (the PID 0 for a process
/// of another compartment; no peer: pid 0, uid and gid -1, as
/// `cred_to_ucred` of none); SO_ERROR takes the pending error.
pub fn getsockopt(
    p: &ProcessRef,
    fd: i32,
    level: i32,
    name: i32,
    val: u64,
    len_at: u64,
) -> SysResult {
    let s = socket_of(p, fd)?;
    if level != SOL_SOCKET {
        return Err(Errno::EOPNOTSUPP);
    }
    let mut lb = [0u8; 4];
    copy_from_user(&mut lb, len_at).map_err(|_| Errno::EFAULT)?;
    let len = i32::from_le_bytes(lb);
    if len < 0 {
        return Err(Errno::EINVAL);
    }
    let me = compartment_of(p);
    let bytes: Vec<u8> = {
        let mut st = s.state.lock();
        let int = |v: i32| v.to_le_bytes().to_vec();
        match name {
            SO_TYPE => int(s.kind as i32),
            SO_PROTOCOL => int(0),
            SO_DOMAIN => int(i32::from(AF_UNIX)),
            SO_ERROR => int(st.err.take().map_or(0, |e| e as i32)),
            SO_ACCEPTCONN => int(i32::from(matches!(st.conn, Conn::Listening { .. }))),
            SO_PASSCRED => int(i32::from(st.passcred)),
            SO_SNDBUF => int(st.sndbuf as i32),
            SO_RCVBUF => int(st.rcvbuf as i32),
            SO_DEBUG | SO_REUSEADDR | SO_DONTROUTE | SO_BROADCAST | SO_KEEPALIVE | SO_OOBINLINE => {
                int(i32::from(st.flags.get(&name).copied().unwrap_or(false)))
            }
            SO_RCVTIMEO_OLD => un::timeval_bytes(st.rcvtimeo).to_vec(),
            SO_SNDTIMEO_OLD => un::timeval_bytes(st.sndtimeo).to_vec(),
            SO_PEERCRED => match st.peercred {
                Some(c) => {
                    un::ucred_bytes(if c.compartment == me { c.pid } else { 0 }, 0, 0).to_vec()
                }
                None => un::ucred_bytes(0, u32::MAX, u32::MAX).to_vec(),
            },
            _ => return Err(Errno::ENOPROTOOPT),
        }
    };
    let n = (len as usize).min(bytes.len());
    copy_to_user(val, &bytes[..n]).map_err(|_| Errno::EFAULT)?;
    copy_to_user(len_at, &(n as i32).to_le_bytes()).map_err(|_| Errno::EFAULT)?;
    Ok(0)
}

/// So O_CLOEXEC's and SOCK_CLOEXEC's equality is checked where both are
/// used (`BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC)`).
const _: () = assert!(SOCK_CLOEXEC as u64 == O_CLOEXEC && SOCK_NONBLOCK as u64 == O_NONBLOCK);
