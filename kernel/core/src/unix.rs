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

/// The bytes a stream socket has received and not yet read
/// (`sk_receive_queue`), as one byte queue.
#[derive(Debug, Default)]
pub struct StreamQueue {
    data: VecDeque<u8>,
}

impl StreamQueue {
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.data.extend(bytes);
    }

    /// Up to `out.len()` bytes into `out`, taken off the queue unless
    /// `peek`; how many.
    pub fn take(&mut self, out: &mut [u8], peek: bool) -> usize {
        let n = out.len().min(self.data.len());
        for (slot, byte) in out.iter_mut().zip(self.data.iter()) {
            *slot = *byte;
        }
        if !peek {
            self.data.drain(..n);
        }
        n
    }

    /// Puts bytes back at the front (a read whose copy out faulted).
    pub fn unread(&mut self, bytes: &[u8]) {
        for &b in bytes.iter().rev() {
            self.data.push_front(b);
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

    #[test]
    fn the_stream_queue_reads_peeks_and_puts_back() {
        let mut q = StreamQueue::default();
        q.push(b"hello");
        let mut b = [0u8; 3];
        assert_eq!(q.take(&mut b, true), 3);
        assert_eq!(q.len(), 5, "a peek takes nothing");
        assert_eq!(q.take(&mut b, false), 3);
        assert_eq!(&b, b"hel");
        q.unread(b"el");
        let mut rest = [0u8; 8];
        assert_eq!(q.take(&mut rest, false), 4);
        assert_eq!(&rest[..4], b"ello");
        assert!(q.is_empty());
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
