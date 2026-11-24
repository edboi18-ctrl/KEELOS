//! Unix domain sockets as data (P3-T11, ADR 0027), tested on the host:
//! addresses, the stream receive queue, and the option values.
//! `keel-linux-abi` adds the objects, names, waits and system calls. Rules
//! from Linux v6.12 `net/unix/af_unix.c`, `net/socket.c` and
//! `net/core/sock.c`; constants from `include/linux/socket.h`,
//! `include/linux/net.h` and `include/uapi/asm-generic/socket.h`.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::errno::Errno;

pub const AF_UNIX: u16 = 1;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
pub const SOCK_SEQPACKET: u32 = 5;
/// `sock_create`: a type at or past SOCK_MAX is EINVAL.
pub const SOCK_MAX: u32 = 11;
pub const SOCK_TYPE_MASK: u32 = 0xf;
pub const SOCK_NONBLOCK: u32 = 0o4000;
pub const SOCK_CLOEXEC: u32 = 0o2000000;

pub const MSG_OOB: u32 = 0x1;
pub const MSG_PEEK: u32 = 0x2;
pub const MSG_TRUNC: u32 = 0x20;
pub const MSG_DONTWAIT: u32 = 0x40;
pub const MSG_WAITALL: u32 = 0x100;
pub const MSG_NOSIGNAL: u32 = 0x4000;
pub const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;

pub const SHUT_RD: i32 = 0;
pub const SHUT_RDWR: i32 = 2;
/// `sk_shutdown` bits (`include/net/sock.h`): SHUT_RD + 1 and SHUT_WR + 1.
pub const RCV_SHUTDOWN: u8 = 1;
pub const SEND_SHUTDOWN: u8 = 2;
pub const SHUTDOWN_MASK: u8 = 3;

/// `offsetof(struct sockaddr_un, sun_path)`.
pub const SUN_PATH_OFFSET: usize = 2;
/// `sizeof(struct sockaddr_un)`: 2 + 108.
pub const SOCKADDR_UN_SIZE: usize = 110;
/// `sizeof(struct sockaddr_storage)`: the most `move_addr_to_kernel`
/// takes.
pub const SOCKADDR_STORAGE_SIZE: usize = 128;

/// `sysctl_wmem_default` and `sysctl_rmem_default` (SK_WMEM_MAX: 256
/// sk_buff overheads of 832 bytes on x86-64 is 212992), also the maxima
/// SO_SNDBUF and SO_RCVBUF are capped at before doubling.
pub const BUF_DEFAULT: u32 = 212_992;
/// `sysctl_somaxconn`: listen's backlog is capped here.
pub const SOMAXCONN: u32 = 4096;

/// A socket's name, as getsockname reports it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Name {
    /// A filesystem name: the path as bound (not resolved).
    Path(Vec<u8>),
    /// An abstract name: the bytes of sun_path, its leading NUL included,
    /// as long as the address given (`unix_create_addr`).
    Abstract(Vec<u8>),
}

impl Name {
    /// The `struct sockaddr_un` bytes and their length (`unix_getname`):
    /// a path with its NUL (`unix_mkname_bsd`: strlen + offset + 1); an
    /// abstract name as given.
    pub fn sockaddr(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SOCKADDR_UN_SIZE);
        out.extend_from_slice(&AF_UNIX.to_le_bytes());
        match self {
            Name::Path(p) => {
                out.extend_from_slice(p);
                out.push(0);
            }
            Name::Abstract(a) => out.extend_from_slice(a),
        }
        out
    }

    /// The name autobind gives (`unix_autobind`): NUL and five lower-case
    /// hex digits of `n` (taken mod 2^20).
    pub fn autobind(n: u32) -> Name {
        let n = n & 0xF_FFFF;
        let mut a = Vec::with_capacity(6);
        a.push(0);
        for shift in [16, 12, 8, 4, 0] {
            let digit = ((n >> shift) & 0xF) as u8;
            a.push(if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            });
        }
        Name::Abstract(a)
    }
}

/// The address of an unnamed socket: the family alone
/// (`unix_getname`: `offsetof(struct sockaddr_un, sun_path)`).
pub fn unnamed_sockaddr() -> Vec<u8> {
    AF_UNIX.to_le_bytes().to_vec()
}

/// What a bind or connect address asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// bind with only the family: an autobind name (`unix_bind`).
    Autobind,
    Name(Name),
}

/// `unix_validate_addr` and the name it gives (`unix_mkname_bsd` for a
/// path; the bytes as given for an abstract name). `addr` is what
/// `move_addr_to_kernel` copied (its length is the caller's `addr_len`):
/// - for bind, a length of exactly 2 with AF_UNIX is autobind;
/// - otherwise a length at or below 2, or above 110, is EINVAL, and so is
///   a family other than AF_UNIX;
/// - a first byte other than NUL is a path, cut at its first NUL;
/// - a first NUL is an abstract name.
pub fn parse(addr: &[u8], for_bind: bool) -> Result<Target, Errno> {
    let family = |a: &[u8]| a.len() >= 2 && u16::from_le_bytes([a[0], a[1]]) == AF_UNIX;
    if for_bind && addr.len() == SUN_PATH_OFFSET && family(addr) {
        return Ok(Target::Autobind);
    }
    if addr.len() <= SUN_PATH_OFFSET || addr.len() > SOCKADDR_UN_SIZE || !family(addr) {
        return Err(Errno::EINVAL);
    }
    let path = &addr[SUN_PATH_OFFSET..];
    if path[0] != 0 {
        let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
        Ok(Target::Name(Name::Path(path[..end].to_vec())))
    } else {
        Ok(Target::Name(Name::Abstract(path.to_vec())))
    }
}

/// `move_addr_to_kernel`: a length below 0 or above sockaddr_storage
/// EINVAL.
pub fn check_addr_len(len: i32) -> Result<usize, Errno> {
    usize::try_from(len)
        .ok()
        .filter(|&l| l <= SOCKADDR_STORAGE_SIZE)
        .ok_or(Errno::EINVAL)
}

/// `move_addr_to_user`: with room for `room` bytes (below 0 EINVAL), how
/// many of the address's `len` to copy; the length written back is
/// always the full one ("fromlen shall refer to the value before
/// truncation").
pub fn addr_copy_len(room: i32, len: usize) -> Result<usize, Errno> {
    if room < 0 {
        return Err(Errno::EINVAL);
    }
    Ok((room as usize).min(len))
}

/// The credentials a message carries (`UNIXCB(skb)`'s pid, uid, gid): the
/// sender's process, by compartment and PID there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Creds {
    pub compartment: u32,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// One received message part (Linux's `sk_buff` on `sk_receive_queue`):
/// its bytes (and how many are read), the descriptors sent with it (`F`),
/// the sender's credentials if any were attached, the sender's name (for
/// datagrams), and a token `X` dropped when the part goes (the sender's
/// send-buffer charge).
#[derive(Debug)]
pub struct Segment<F, X> {
    pub data: Vec<u8>,
    pub consumed: usize,
    pub fds: Option<Vec<F>>,
    pub creds: Option<Creds>,
    pub from: Option<Name>,
    pub token: X,
}

impl<F, X> Segment<F, X> {
    fn remaining(&self) -> usize {
        self.data.len() - self.consumed
    }
}

/// What a stream read may take (`unix_stream_read_generic`), worked out
/// before anything is consumed, so a fault on the way out loses nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Bytes copied into the caller's buffer.
    pub n: usize,
    /// The read must end here: it reached a part with descriptors (`if
    /// (scm.fp) break`), a part with other credentials, or the middle of
    /// a part.
    pub stop: bool,
}

/// The state a stream read keeps across its waits: the credentials of
/// the first part it read, when the reader has SO_PASSCRED (later parts
/// must carry the same, `unix_skb_scm_eq`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadState {
    pub creds: Option<Option<Creds>>,
}

/// A socket's receive queue.
#[derive(Debug)]
pub struct Queue<F, X> {
    parts: VecDeque<Segment<F, X>>,
}

impl<F, X> Default for Queue<F, X> {
    fn default() -> Self {
        Queue {
            parts: VecDeque::new(),
        }
    }
}

impl<F, X> Queue<F, X> {
    /// Unread bytes in all parts (SIOCINQ for a stream socket).
    pub fn len(&self) -> usize {
        self.parts.iter().map(Segment::remaining).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Parts waiting (a datagram socket's queue length, for
    /// `max_dgram_qlen`).
    pub fn count(&self) -> usize {
        self.parts.len()
    }

    /// The first part's unread length (SIOCINQ for a datagram socket).
    pub fn first_len(&self) -> usize {
        self.parts.front().map_or(0, Segment::remaining)
    }

    pub fn push(&mut self, part: Segment<F, X>) {
        self.parts.push_back(part);
    }

    /// Drops every part (`skb_queue_purge`); their descriptors close.
    pub fn purge(&mut self) {
        self.parts.clear();
    }

    /// A stream read's next step, as `unix_stream_read_generic` walks
    /// the queue: bytes from the parts in order into `out`, stopping
    /// after a part with descriptors, in the middle of a part, or (when
    /// `passcred`) before a part whose credentials differ from the first
    /// part read's. Nothing is taken: [`Queue::consume`] does that.
    pub fn stream_plan(&self, out: &mut [u8], passcred: bool, st: &mut ReadState) -> Plan {
        let mut n = 0;
        for part in &self.parts {
            if passcred {
                match st.creds {
                    Some(c) if c != part.creds => return Plan { n, stop: true },
                    Some(_) => {}
                    None => st.creds = Some(part.creds),
                }
            }
            let take = part.remaining().min(out.len() - n);
            out[n..n + take].copy_from_slice(&part.data[part.consumed..part.consumed + take]);
            n += take;
            if part.fds.is_some() || take < part.remaining() {
                return Plan { n, stop: true };
            }
            if n == out.len() {
                break;
            }
        }
        Plan { n, stop: false }
    }

    /// Takes `n` bytes off the front of a stream queue; the descriptors
    /// of any part they reach are detached and returned
    /// (`unix_detach_fds`).
    pub fn consume(&mut self, mut n: usize) -> Option<Vec<F>> {
        let mut fds = None;
        while n > 0 {
            let Some(part) = self.parts.front_mut() else {
                break;
            };
            let take = part.remaining().min(n);
            part.consumed += take;
            n -= take;
            if let Some(f) = part.fds.take() {
                fds = Some(f);
            }
            if part.remaining() == 0 {
                self.parts.pop_front();
            }
        }
        fds
    }

    /// The first part, taken off unless `peek` (`__skb_try_recv_datagram`).
    pub fn pop(&mut self) -> Option<Segment<F, X>> {
        self.parts.pop_front()
    }

    pub fn front(&self) -> Option<&Segment<F, X>> {
        self.parts.front()
    }
}

impl<F: Clone, X> Queue<F, X> {
    /// MSG_PEEK of a stream: the descriptors of the part the first `n`
    /// bytes end in, if it has any, as copies (`unix_peek_fds`).
    pub fn peek_fds(&self, n: usize) -> Option<Vec<F>> {
        let mut left = n;
        for part in &self.parts {
            if left == 0 {
                break;
            }
            let take = part.remaining().min(left);
            left -= take;
            if let Some(f) = &part.fds {
                return Some(f.clone());
            }
        }
        None
    }
}

/// `struct cmsghdr` on x86-64: cmsg_len (size_t), cmsg_level (int),
/// cmsg_type (int); 16 bytes, and CMSG_ALIGN rounds to 8.
pub const CMSG_HDR: usize = 16;
pub const SOL_SOCKET: i32 = 1;
pub const SCM_RIGHTS: i32 = 1;
pub const SCM_CREDENTIALS: i32 = 2;
/// The most descriptors one message may carry (`SCM_MAX_FD`).
pub const SCM_MAX_FD: usize = 253;

pub fn cmsg_align(n: usize) -> usize {
    (n + 7) & !7
}

/// CMSG_LEN and CMSG_SPACE.
pub fn cmsg_len(data: usize) -> usize {
    CMSG_HDR + data
}

pub fn cmsg_space(data: usize) -> usize {
    CMSG_HDR + cmsg_align(data)
}

/// What a sendmsg's control data asks for (`__scm_send`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Control {
    /// Descriptor numbers, from every SCM_RIGHTS in order.
    pub fds: Vec<i32>,
    /// SCM_CREDENTIALS: pid, uid, gid (the last one given).
    pub creds: Option<(i32, u32, u32)>,
}

/// `__scm_send`'s walk over the control data (`for_each_cmsghdr`, with
/// `CMSG_OK` and `__cmsg_nxthdr`): a header whose length is below the
/// header's or past the data left EINVAL; other levels skipped; at
/// SOL_SOCKET, SCM_RIGHTS (none if empty; more than SCM_MAX_FD in all
/// EINVAL) and SCM_CREDENTIALS (exactly CMSG_LEN(12), else EINVAL; uid
/// or gid -1 EINVAL); any other type EINVAL. A next header that would
/// not fit ends the walk.
pub fn parse_control(c: &[u8]) -> Result<Control, Errno> {
    let mut out = Control::default();
    let mut at = 0usize;
    while c.len() >= at + CMSG_HDR {
        let word = |o: usize| u64::from_le_bytes(c[o..o + 8].try_into().unwrap_or_default());
        let int = |o: usize| i32::from_le_bytes(c[o..o + 4].try_into().unwrap_or_default());
        let len = word(at);
        if len < CMSG_HDR as u64 || len > (c.len() - at) as u64 {
            return Err(Errno::EINVAL);
        }
        let len = len as usize;
        let (level, ty) = (int(at + 8), int(at + 12));
        if level == SOL_SOCKET {
            match ty {
                SCM_RIGHTS => {
                    let num = (len - CMSG_HDR) / 4;
                    if num > SCM_MAX_FD || out.fds.len() + num > SCM_MAX_FD {
                        return Err(Errno::EINVAL);
                    }
                    for i in 0..num {
                        out.fds.push(int(at + CMSG_HDR + 4 * i));
                    }
                }
                SCM_CREDENTIALS => {
                    if len != cmsg_len(12) {
                        return Err(Errno::EINVAL);
                    }
                    let d = at + CMSG_HDR;
                    let (pid, uid, gid) = (int(d), int(d + 4) as u32, int(d + 8) as u32);
                    if uid == u32::MAX || gid == u32::MAX {
                        return Err(Errno::EINVAL);
                    }
                    out.creds = Some((pid, uid, gid));
                }
                _ => return Err(Errno::EINVAL),
            }
        }
        at += cmsg_align(len);
    }
    Ok(out)
}

/// recvmsg's control buffer as `put_cmsg` and `scm_detach_fds` fill it.
#[derive(Debug)]
pub struct ControlOut {
    pub bytes: Vec<u8>,
    room: usize,
    /// MSG_CTRUNC: something did not fit.
    pub truncated: bool,
}

impl ControlOut {
    /// A buffer of `room` bytes (0 for none given).
    pub fn new(room: usize) -> Self {
        ControlOut {
            bytes: Vec::new(),
            room,
            truncated: false,
        }
    }

    fn header(&mut self, len: usize, ty: i32) {
        self.bytes.extend_from_slice(&(len as u64).to_le_bytes());
        self.bytes.extend_from_slice(&SOL_SOCKET.to_le_bytes());
        self.bytes.extend_from_slice(&ty.to_le_bytes());
    }

    fn left(&self) -> usize {
        self.room - self.bytes.len()
    }

    /// `put_cmsg`: no room for a header, MSG_CTRUNC and nothing; less room
    /// than the whole, as much as fits (its length the room) and
    /// MSG_CTRUNC; then the buffer advances by CMSG_SPACE, at most to its
    /// end.
    pub fn put(&mut self, ty: i32, data: &[u8]) {
        let left = self.left();
        if left < CMSG_HDR {
            self.truncated = true;
            return;
        }
        let mut cmlen = cmsg_len(data.len());
        if left < cmlen {
            self.truncated = true;
            cmlen = left;
        }
        self.header(cmlen, ty);
        self.bytes.extend_from_slice(&data[..cmlen - CMSG_HDR]);
        let space = cmsg_space(data.len()).min(left);
        self.bytes.resize(self.bytes.len() + space - cmlen, 0);
    }

    /// How many of `count` descriptors fit (`scm_max_fds`).
    pub fn fd_room(&self, count: usize) -> usize {
        let left = self.left();
        if left <= CMSG_HDR {
            0
        } else {
            ((left - CMSG_HDR) / 4).min(count)
        }
    }

    /// `scm_detach_fds` once `fds` (the numbers installed) are known, of
    /// `count` sent: the header if any went in; MSG_CTRUNC if some did not
    /// (or none could).
    pub fn put_fds(&mut self, fds: &[i32], count: usize) {
        let left = self.left();
        if !fds.is_empty() {
            let cmlen = cmsg_len(fds.len() * 4);
            self.header(cmlen, SCM_RIGHTS);
            for fd in fds {
                self.bytes.extend_from_slice(&fd.to_le_bytes());
            }
            let space = cmsg_space(fds.len() * 4).min(left);
            self.bytes.resize(self.bytes.len() + space - cmlen, 0);
        }
        if fds.len() < count {
            self.truncated = true;
        }
    }
}

/// SO_SNDBUF and SO_RCVBUF (`sk_setsockopt`): the value capped at the
/// maximum, then doubled ("the kernel doubles this value (to allow space
/// for bookkeeping overhead)", socket(7)), and at least the minimum.
pub fn buffer_size(val: i32, min: u32) -> u32 {
    let capped = (val as u32).min(BUF_DEFAULT).min(i32::MAX as u32 / 2);
    (capped * 2).max(min)
}

/// `struct ucred` (`include/linux/socket.h`): pid, uid, gid, each 4 bytes.
pub fn ucred_bytes(pid: u32, uid: u32, gid: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[..4].copy_from_slice(&pid.to_le_bytes());
    b[4..8].copy_from_slice(&uid.to_le_bytes());
    b[8..].copy_from_slice(&gid.to_le_bytes());
    b
}

/// A socket timeout (SO_RCVTIMEO, SO_SNDTIMEO) from a `struct timeval`
/// (`sock_set_timeout`): microseconds outside 0..10^6 EDOM; a negative
/// time is "no waiting" (Linux stores 0, which makes the call
/// non-blocking); zero is "wait without limit". In nanoseconds: None
/// for no limit.
pub fn timeout(sec: i64, usec: i64) -> Result<Option<u64>, Errno> {
    if !(0..1_000_000).contains(&usec) {
        return Err(Errno::EDOM);
    }
    if sec < 0 {
        return Ok(Some(0));
    }
    if sec == 0 && usec == 0 {
        return Ok(None);
    }
    Ok(Some(
        (sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(usec as u64 * 1000),
    ))
}

/// The `struct timeval` getsockopt reports for a timeout.
pub fn timeval_bytes(timeout: Option<u64>) -> [u8; 16] {
    let ns = timeout.unwrap_or(0);
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&((ns / 1_000_000_000) as i64).to_le_bytes());
    b[8..].copy_from_slice(&(((ns % 1_000_000_000) / 1000) as i64).to_le_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(path: &[u8]) -> Vec<u8> {
        let mut a = AF_UNIX.to_le_bytes().to_vec();
        a.extend_from_slice(path);
        a
    }

    #[test]
    fn addresses_parse_as_linux() {
        assert_eq!(parse(&addr(b""), true), Ok(Target::Autobind));
        assert_eq!(parse(&addr(b""), false), Err(Errno::EINVAL));
        assert_eq!(
            parse(&addr(b"sock\0junk"), true),
            Ok(Target::Name(Name::Path(b"sock".to_vec())))
        );
        assert_eq!(
            parse(&addr(b"\0abs\0x"), false),
            Ok(Target::Name(Name::Abstract(b"\0abs\0x".to_vec())))
        );
        let mut wrong = addr(b"x");
        wrong[0] = 2;
        assert_eq!(parse(&wrong, true), Err(Errno::EINVAL));
        assert_eq!(
            parse(&addr(&[b'a'; 109]), true),
            Err(Errno::EINVAL),
            "past 110"
        );
        assert!(parse(&addr(&[b'a'; 108]), true).is_ok());
        assert_eq!(check_addr_len(-1), Err(Errno::EINVAL));
        assert_eq!(check_addr_len(129), Err(Errno::EINVAL));
        assert_eq!(addr_copy_len(3, 8), Ok(3));
        assert_eq!(addr_copy_len(-1, 8), Err(Errno::EINVAL));
    }

    #[test]
    fn names_report_as_linux() {
        assert_eq!(Name::Path(b"s".to_vec()).sockaddr(), addr(b"s\0"));
        assert_eq!(Name::Abstract(b"\0ab".to_vec()).sockaddr(), addr(b"\0ab"));
        assert_eq!(
            Name::autobind(0x1_2abc),
            Name::Abstract(b"\x0012abc".to_vec())
        );
        assert_eq!(
            Name::autobind(0x10_0000 + 5),
            Name::Abstract(b"\x0000005".to_vec())
        );
        assert_eq!(Name::autobind(7).sockaddr().len(), 8);
        assert_eq!(unnamed_sockaddr().len(), 2);
    }

    fn part(data: &[u8], fds: Option<Vec<u8>>, pid: Option<u32>) -> Segment<u8, ()> {
        Segment {
            data: data.to_vec(),
            consumed: 0,
            fds,
            creds: pid.map(|pid| Creds {
                compartment: 1,
                pid,
                uid: 0,
                gid: 0,
            }),
            from: None,
            token: (),
        }
    }

    #[test]
    fn stream_reads_stop_where_linux_stops() {
        let mut q: Queue<u8, ()> = Queue::default();
        q.push(part(b"ab", None, None));
        q.push(part(b"cd", Some(alloc::vec![7]), None));
        q.push(part(b"ef", None, None));
        let mut out = [0u8; 8];
        let mut st = ReadState::default();
        // Across the first part, and stopping after the one with
        // descriptors.
        assert_eq!(
            q.stream_plan(&mut out, false, &mut st),
            Plan { n: 4, stop: true }
        );
        assert_eq!(&out[..4], b"abcd");
        assert_eq!(q.peek_fds(4), Some(alloc::vec![7]));
        assert_eq!(q.peek_fds(2), None, "the descriptors' part not reached");
        // Consuming only the first part leaves its descriptors.
        assert_eq!(q.consume(2), None);
        assert_eq!(q.consume(1), Some(alloc::vec![7]), "touched: detached");
        assert_eq!(q.len(), 3);
        let mut st = ReadState::default();
        assert_eq!(
            q.stream_plan(&mut out, false, &mut st),
            Plan { n: 3, stop: false }
        );
        assert_eq!(&out[..3], b"def");
    }

    #[test]
    fn credentials_divide_a_stream_for_a_passcred_reader() {
        let mut q: Queue<u8, ()> = Queue::default();
        q.push(part(b"a", None, Some(5)));
        q.push(part(b"b", None, Some(5)));
        q.push(part(b"c", None, Some(6)));
        let mut out = [0u8; 8];
        let mut st = ReadState::default();
        assert_eq!(q.stream_plan(&mut out, true, &mut st).n, 2);
        let mut st = ReadState::default();
        assert_eq!(
            q.stream_plan(&mut out, false, &mut st).n,
            3,
            "without SO_PASSCRED"
        );
        // Partial reads stop in the middle of a part.
        let mut st = ReadState::default();
        assert_eq!(
            q.stream_plan(&mut out[..1], true, &mut st),
            Plan { n: 1, stop: false }
        );
        assert_eq!(q.count(), 3);
        assert_eq!(q.first_len(), 1);
    }

    #[test]
    fn control_data_parses_as_linux() {
        let cmsg = |len: u64, level: i32, ty: i32, data: &[u8]| {
            let mut v = len.to_le_bytes().to_vec();
            v.extend_from_slice(&level.to_le_bytes());
            v.extend_from_slice(&ty.to_le_bytes());
            v.extend_from_slice(data);
            while !v.len().is_multiple_of(8) {
                v.push(0);
            }
            v
        };
        let mut fds = Vec::new();
        for fd in [3i32, 4] {
            fds.extend_from_slice(&fd.to_le_bytes());
        }
        let mut c = cmsg(24, SOL_SOCKET, SCM_RIGHTS, &fds);
        c.extend(cmsg(20, 99, 1, b"junk"));
        let mut cred = Vec::new();
        for v in [7i32, 0, 0] {
            cred.extend_from_slice(&v.to_le_bytes());
        }
        c.extend(cmsg(28, SOL_SOCKET, SCM_CREDENTIALS, &cred));
        assert_eq!(
            parse_control(&c),
            Ok(Control {
                fds: alloc::vec![3, 4],
                creds: Some((7, 0, 0)),
            })
        );
        assert_eq!(
            parse_control(&cmsg(8, SOL_SOCKET, SCM_RIGHTS, &[])),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            parse_control(&cmsg(64, SOL_SOCKET, SCM_RIGHTS, &fds)),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            parse_control(&cmsg(24, SOL_SOCKET, 9, &fds)),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            parse_control(&cmsg(24, SOL_SOCKET, SCM_CREDENTIALS, &cred)),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            parse_control(&[0u8; 8]),
            Ok(Control::default()),
            "no room for a header"
        );
        let many = alloc::vec![0u8; 4 * 254];
        assert_eq!(
            parse_control(&cmsg(16 + 4 * 254, SOL_SOCKET, SCM_RIGHTS, &many)),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn control_out_truncates_as_linux() {
        let mut out = ControlOut::new(cmsg_space(12) + CMSG_HDR);
        out.put(SCM_CREDENTIALS, &[1u8; 12]);
        assert_eq!(out.bytes.len(), 32);
        assert_eq!(out.fd_room(3), 0, "exactly a header left: no room");
        let mut out = ControlOut::new(cmsg_space(8));
        assert_eq!(out.fd_room(3), 2);
        out.put_fds(&[5, 6], 3);
        assert!(out.truncated);
        assert_eq!(out.bytes.len(), 24);
        assert_eq!(out.bytes[..8], 24u64.to_le_bytes());
        let mut none = ControlOut::new(8);
        none.put(SCM_CREDENTIALS, &[0u8; 12]);
        assert!(none.truncated && none.bytes.is_empty());
        let mut short = ControlOut::new(20);
        short.put(SCM_CREDENTIALS, &[0u8; 12]);
        assert!(short.truncated);
        assert_eq!(short.bytes.len(), 20);
        assert_eq!(short.bytes[..8], 20u64.to_le_bytes());
    }

    #[test]
    fn options_as_linux() {
        assert_eq!(buffer_size(65536, 4608), 131_072);
        assert_eq!(buffer_size(1, 4608), 4608);
        assert_eq!(buffer_size(1 << 30, 4608), 2 * BUF_DEFAULT);
        assert_eq!(timeout(0, 0), Ok(None));
        assert_eq!(timeout(-1, 0), Ok(Some(0)));
        assert_eq!(timeout(1, 5), Ok(Some(1_000_005_000)));
        assert_eq!(timeout(0, 1_000_000), Err(Errno::EDOM));
        assert_eq!(
            timeval_bytes(Some(2_500_000_000))[8..],
            500_000i64.to_le_bytes()
        );
        assert_eq!(ucred_bytes(7, 0, 0)[..4], 7u32.to_le_bytes());
    }
}
