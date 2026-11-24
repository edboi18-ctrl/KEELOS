//! Unix domain stream sockets (P3-T11 part 1, ADR 0027): socket,
//! socketpair, bind, listen, connect, accept and accept4, getsockname,
//! getpeername, shutdown, setsockopt and getsockopt, and the data calls
//! (read, write, sendto, recvfrom, sendmsg, recvmsg without ancillary
//! data), as Linux v6.12's `net/socket.c` and `net/unix/af_unix.c`.
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
    SOCK_RAW, SOCK_SEQPACKET, SOCK_STREAM, SOCK_TYPE_MASK, StreamQueue, Target,
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
    recv: StreamQueue,
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
    state: IrqMutex<State>,
}

/// Bound names: abstract ones per compartment, path ones by the socket
/// node (`unix_find_socket_byinode`).
#[derive(Default)]
struct Names {
    abstract_names: BTreeMap<(u32, Vec<u8>), Weak<Socket>>,
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
            state: IrqMutex::new(State {
                conn: Conn::Unconnected,
                name: None,
                node: None,
                recv: StreamQueue::default(),
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

    /// `unix_poll` for a stream socket:
    /// - EPOLLERR with an error pending;
    /// - EPOLLHUP when shut down both ways, or not connected (TCP_CLOSE);
    /// - readable with data, a connection to accept, or the reading side
    ///   shut down (EPOLLRDHUP too);
    /// - writable unless listening, while what it has sent and its peer
    ///   has not read is at most a quarter of its send buffer
    ///   (`unix_writable`).
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
        if closed {
            mask |= POLLHUP;
        }
        if !listening && self.in_flight() * 4 <= sndbuf as usize {
            mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
        }
        mask
    }

    /// The bytes it has sent that its peer has not read (its
    /// `sk_wmem_alloc`, counted in bytes).
    fn in_flight(&self) -> usize {
        self.peer().map_or(0, |p| p.state.lock().recv.len())
    }

    /// SIOCINQ (FIONREAD): the bytes waiting; EINVAL for a listening
    /// socket (`unix_inq_len`).
    pub fn inq(&self) -> Result<usize, Errno> {
        let s = self.state.lock();
        if matches!(s.conn, Conn::Listening { .. }) {
            return Err(Errno::EINVAL);
        }
        Ok(s.recv.len())
    }

    /// SIOCOUTQ: what it has sent that its peer has not read.
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
                let key = (self.compartment, a.clone());
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
/// - SOCK_STREAM; SOCK_DGRAM, SOCK_RAW (which is SOCK_DGRAM) and
///   SOCK_SEQPACKET are ESOCKTNOSUPPORT for now (part 1); any other type
///   ESOCKTNOSUPPORT.
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
    match kind {
        SOCK_STREAM => {}
        SOCK_DGRAM | SOCK_RAW | SOCK_SEQPACKET => return Err(Errno::ESOCKTNOSUPPORT),
        _ => return Err(Errno::ESOCKTNOSUPPORT),
    }
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
        let key = (s.compartment, bytes.clone());
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
            let key = (s.compartment, bytes.clone());
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
/// compartment ECONNREFUSED.
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
            let key = (compartment_of(p), bytes.clone());
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
/// mirror (reading shut here is writing shut there). An unconnected
/// socket is fine (0).
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
    if let Some(peer) = s.peer() {
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

/// `unix_stream_sendmsg` from the user segments `segs` (`flags` with
/// MSG_DONTWAIT added for a non-blocking descriptor), in Linux's order:
/// - MSG_OOB EOPNOTSUPP (Keel has no out-of-band data: ADR 0027);
/// - an address: EISCONN if connected, else EOPNOTSUPP;
/// - no peer ENOTCONN;
/// - sending shut down: EPIPE, and SIGPIPE unless MSG_NOSIGNAL;
/// - then the bytes go to the peer as room appears: its unread bytes from
///   this side may reach the send buffer (SO_SNDBUF). Without room:
///   EAGAIN if non-blocking and nothing was sent, else a wait (up to
///   SO_SNDTIMEO; a signal or the timeout ends it with what was sent, or
///   EINTR or EAGAIN); the peer gone or shut for reading: EPIPE (with
///   SIGPIPE if nothing was sent), or the count so far.
pub fn send(
    p: &ProcessRef,
    s: &Arc<Socket>,
    segs: &[(u64, u64)],
    flags: u32,
    has_addr: bool,
) -> SysResult {
    let flags = if s.nonblocking() {
        flags | MSG_DONTWAIT
    } else {
        flags
    };
    if flags & MSG_OOB != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let (peer, shut, sndbuf, sndtimeo) = {
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
        )
    };
    let pipe = |sent: u64| -> SysResult {
        if sent == 0 && flags & MSG_NOSIGNAL == 0 {
            let pid = p.lock().pid();
            crate::signal::send_to_thread(
                p,
                sched::current(),
                SigInfo::from_process(SIGPIPE, SI_USER, pid, 0),
            );
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
        {
            let mut os = other.state.lock();
            os.recv.push(&chunk[..n]);
            os.wakes.wake(KEY_READABLE);
        }
        changed();
        sent += n as u64;
    }
    Ok(sent)
}

/// `unix_stream_read_generic` into the user segments `segs`:
/// - not connected EINVAL; MSG_OOB EOPNOTSUPP;
/// - what is waiting, up to the total (all of it with MSG_WAITALL, else
///   at least one byte); MSG_PEEK leaves it;
/// - nothing waiting: a pending error (ECONNRESET, reported once), then
///   reading shut down (0), then EAGAIN if non-blocking, else a wait (up
///   to SO_RCVTIMEO; EINTR on a signal);
/// - bytes that fault on the way out stay; a fault before any EFAULT.
///
/// Returns the count and the peer's address (for recvfrom's address: the
/// sender's, `unix_copy_addr`), if anything was read.
pub fn recv(
    s: &Arc<Socket>,
    segs: &[(u64, u64)],
    flags: u32,
) -> Result<(u64, Option<Vec<u8>>), Errno> {
    let flags = if s.nonblocking() {
        flags | MSG_DONTWAIT
    } else {
        flags
    };
    if !matches!(s.state.lock().conn, Conn::Connected { .. }) {
        return Err(Errno::EINVAL);
    }
    if flags & MSG_OOB != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let size = crate::ready::total(segs);
    let peek = flags & MSG_PEEK != 0;
    let target = if flags & MSG_WAITALL != 0 {
        size.max(1)
    } else {
        1
    };
    let mut copied = 0u64;
    let mut buf = alloc::vec![0u8; (size as usize).min(65536)];
    let mut from = None;
    loop {
        let (got, rcvtimeo) = {
            let mut st = s.state.lock();
            if st.recv.is_empty() {
                if copied >= target {
                    break;
                }
                if let Some(e) = st.err.take() {
                    return if copied > 0 {
                        Ok((copied, from))
                    } else {
                        Err(e)
                    };
                }
                if st.shutdown & RCV_SHUTDOWN != 0 {
                    break;
                }
                (None, st.rcvtimeo)
            } else {
                let want = ((size - copied) as usize).min(buf.len());
                let n = st.recv.take(&mut buf[..want], peek);
                (Some(n), st.rcvtimeo)
            }
        };
        let Some(n) = got else {
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
        // Copy out at the right place in the segments.
        let out = skip_segments(segs, copied);
        let done = crate::ready::copy_out(&out, &buf[..n]);
        if done < n && !peek {
            s.state.lock().recv.unread(&buf[done..n]);
        }
        if from.is_none() {
            from = Some(sender_name(&s.state.lock()));
        }
        copied += done as u64;
        if done < n {
            if copied == 0 {
                return Err(Errno::EFAULT);
            }
            break;
        }
        if !peek {
            // `unix_write_space`: the writer may have room now.
            if let Some(peer) = s.peer() {
                peer.wake(KEY_WRITABLE);
            }
            changed();
        }
        if peek || copied >= size || copied >= target && s.state.lock().recv.is_empty() {
            break;
        }
    }
    Ok((copied, from))
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
/// 0 at once; otherwise recv with no flags.
pub fn read(s: &Arc<Socket>, segs: &[(u64, u64)]) -> SysResult {
    if crate::ready::total(segs) == 0 {
        return Ok(0);
    }
    recv(s, segs, 0).map(|(n, _)| n)
}

/// write(2) and writev(2) on a socket (`sock_write_iter`): send with no
/// flags.
pub fn write(p: &ProcessRef, s: &Arc<Socket>, segs: &[(u64, u64)]) -> SysResult {
    send(p, s, segs, 0, false)
}

/// sendto(2) (`__sys_sendto`): the descriptor (EBADF, ENOTSOCK), then
/// the address if any (EINVAL, EFAULT), then the send.
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
    let has_addr = if addr != 0 {
        addr_in(addr, alen)?;
        alen != 0
    } else {
        false
    };
    send(p, &s, &[(buf, len)], flags, has_addr)
}

/// recvfrom(2) (`__sys_recvfrom`): the sender's address is written if
/// asked and something was read; with nothing to report its length is 0
/// (`msg_namelen` stays 0).
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
    let (n, from) = recv(&s, &[(buf, len)], flags)?;
    if addr != 0 {
        addr_out(from.as_deref().unwrap_or(&[]), addr, len_at)?;
    }
    Ok(n)
}

/// `struct user_msghdr` on x86-64: msg_name 0, msg_namelen 8 (int),
/// msg_iov 16, msg_iovlen 24, msg_control 32, msg_controllen 40,
/// msg_flags 48 (int); 56 bytes.
struct MsgHdr {
    name: u64,
    namelen: i32,
    iov: Vec<(u64, u64)>,
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
        controllen: word(40),
    })
}

/// sendmsg(2) (`____sys_sendmsg`): a control length past INT_MAX
/// ENOBUFS. Ancillary data is part 2: any is EINVAL for now (ADR 0027).
pub fn sendmsg(p: &ProcessRef, fd: i32, msg: u64, flags: u32) -> SysResult {
    let s = socket_of(p, fd)?;
    let m = msghdr(msg)?;
    if m.namelen > 0 {
        addr_in(m.name, m.namelen)?;
    }
    if m.controllen > i32::MAX as u64 {
        return Err(Errno::ENOBUFS);
    }
    if m.controllen != 0 {
        return Err(Errno::EINVAL);
    }
    send(p, &s, &m.iov, flags, m.namelen > 0)
}

/// recvmsg(2) (`____sys_recvmsg`): after the read, the name length (and
/// the name if asked), msg_flags (MSG_CMSG_CLOEXEC kept from the flags)
/// and a control length of 0 are written back.
pub fn recvmsg(p: &ProcessRef, fd: i32, msg: u64, flags: u32) -> SysResult {
    let s = socket_of(p, fd)?;
    let m = msghdr(msg)?;
    let (n, from) = recv(&s, &m.iov, flags)?;
    if m.name != 0 {
        let from = from.unwrap_or_default();
        let room = m.namelen as usize;
        let k = room.min(from.len());
        copy_to_user(m.name, &from[..k]).map_err(|_| Errno::EFAULT)?;
        copy_to_user(msg + 8, &(from.len() as i32).to_le_bytes()).map_err(|_| Errno::EFAULT)?;
    } else {
        copy_to_user(msg + 8, &0i32.to_le_bytes()).map_err(|_| Errno::EFAULT)?;
    }
    let out_flags = flags & un::MSG_CMSG_CLOEXEC;
    copy_to_user(msg + 48, &out_flags.to_le_bytes()).map_err(|_| Errno::EFAULT)?;
    copy_to_user(msg + 40, &0u64.to_le_bytes()).map_err(|_| Errno::EFAULT)?;
    Ok(n)
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
