//! P3-T11 part 1: Unix domain stream sockets, checked against Linux. Runs
//! under Linux (`host.sockprobe`) and on Keel (`exec.sockets`) and must
//! pass on both.
//!
//! Semantics from unix(7), socket(2), socketpair(2), bind(2), listen(2),
//! connect(2), accept(2), getsockname(2), shutdown(2), socket(7) (the
//! options) and Linux v6.12's `net/socket.c`, `net/unix/af_unix.c` and
//! `net/core/sock.c`. Only what both kernels guarantee is checked: buffer
//! capacities differ (Linux counts sk_buff overheads), so a full socket is
//! reached by writing until EAGAIN, never by a byte count.
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, Arg, Hostile, O_CLOEXEC, O_RDONLY, Out};

const EPIPE: i64 = -32;
const EAGAIN: i64 = -11;
const EBADF: i64 = -9;
const EINVAL: i64 = -22;
const ENOENT: i64 = -2;
const ENXIO: i64 = -6;
const EFAULT: i64 = -14;
const ESPIPE: i64 = -29;
const EDOM: i64 = -33;
const ENOTSOCK: i64 = -88;
const EPROTOTYPE: i64 = -91;
const ENOPROTOOPT: i64 = -92;
const EPROTONOSUPPORT: i64 = -93;
const ESOCKTNOSUPPORT: i64 = -94;
const EOPNOTSUPP: i64 = -95;
const EAFNOSUPPORT: i64 = -97;
const EADDRINUSE: i64 = -98;
const ECONNRESET: i64 = -104;
const EISCONN: i64 = -106;
const ENOTCONN: i64 = -107;
const ECONNREFUSED: i64 = -111;

const AF_UNIX: i32 = 1;
const STREAM: u32 = 1;
const SOCK_NONBLOCK: u32 = 0o4000;
const SOCK_CLOEXEC: u32 = 0o2000000;
const O_NONBLOCK: u64 = 0o4000;
const F_GETFD: u32 = 1;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;
const SOL_SOCKET: i32 = 1;
const SO_REUSEADDR: i32 = 2;
const SO_TYPE: i32 = 3;
const SO_ERROR: i32 = 4;
const SO_SNDBUF: i32 = 7;
const SO_RCVBUF: i32 = 8;
const SO_PASSCRED: i32 = 16;
const SO_PEERCRED: i32 = 17;
const SO_RCVTIMEO: i32 = 20;
const SO_ACCEPTCONN: i32 = 30;
const SO_PROTOCOL: i32 = 38;
const SO_DOMAIN: i32 = 39;
const MSG_PEEK: u32 = 2;
const MSG_DONTWAIT: u32 = 0x40;
const MSG_WAITALL: u32 = 0x100;
const MSG_NOSIGNAL: u32 = 0x4000;
const SHUT_WR: i32 = 1;
const SHUT_RDWR: i32 = 2;
const FIONREAD: u64 = 0x541B;
const SIOCOUTQ: u64 = 0x5411;
const POLLIN: u16 = 0x1;
const POLLOUT: u16 = 0x4;
const POLLHUP: u16 = 0x10;
const POLLRDHUP: u16 = 0x2000;
const SIGPIPE: i32 = 13;
const S_IFMT: u32 = 0o170000;
const S_IFSOCK: u32 = 0o140000;

/// A `struct sockaddr_un` for `path` (which may begin with a NUL: an
/// abstract name), and its length: the family, then the bytes, plus a
/// NUL for a path.
fn sun(path: &[u8], buf: &mut [u8; 110]) -> usize {
    buf[..2].copy_from_slice(&(AF_UNIX as u16).to_le_bytes());
    buf[2..2 + path.len()].copy_from_slice(path);
    let mut n = 2 + path.len();
    if path.first() != Some(&0) {
        buf[n] = 0;
        n += 1;
    }
    n
}

fn ready(fd: i32, events: u16) -> u16 {
    let mut e = [0u8; 8];
    e[..4].copy_from_slice(&fd.to_le_bytes());
    e[4..6].copy_from_slice(&events.to_le_bytes());
    let mut fds = [e];
    if sys::poll(&mut fds, 0) < 0 {
        return 0xffff;
    }
    u16::from_le_bytes([fds[0][6], fds[0][7]])
}

fn get_int(fd: i32, name: i32) -> Option<i32> {
    let mut v = [0u8; 4];
    let mut len = 4;
    (sys::getsockopt(fd, SOL_SOCKET, name, &mut v, &mut len) == 0 && len == 4)
        .then(|| i32::from_le_bytes(v))
}

fn set_int(fd: i32, name: i32, v: i32) -> i64 {
    sys::setsockopt(fd, SOL_SOCKET, name, &v.to_le_bytes())
}

fn ioctl_int(fd: i32, request: u64) -> Option<i32> {
    let mut b = [0u8; 64];
    (sys::ioctl(fd, request, &mut b) == 0).then(|| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn pair(flags: u32) -> Option<(i32, i32)> {
    let mut sv = [-1i32; 2];
    (sys::socketpair(AF_UNIX, STREAM | flags, 0, &mut sv) == 0).then_some((sv[0], sv[1]))
}

/// The peer credentials: (pid, uid, gid).
fn peercred(fd: i32) -> Option<(i32, i32, i32)> {
    let mut v = [0u8; 12];
    let mut len = 12;
    (sys::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &mut v, &mut len) == 0 && len == 12).then(|| {
        let w = |i: usize| i32::from_le_bytes(v[i..i + 4].try_into().unwrap_or([0; 4]));
        (w(0), w(4), w(8))
    })
}

/// The address getsockname (or getpeername) reports, and its length.
fn name_of(fd: i32, peer: bool) -> Result<([u8; 110], i32), i64> {
    let mut b = [0u8; 110];
    let mut len = 110;
    let r = sys::getname(fd, &mut b, &mut len, peer);
    if r != 0 { Err(r) } else { Ok((b, len)) }
}

fn disposition(signal: i32, handler: u64) -> bool {
    let mut act = [0u8; 32];
    act[..8].copy_from_slice(&handler.to_le_bytes());
    sys::rt_sigaction(signal, Arg::Buf(&act), Out::Null, 8) == 0
}

fn nap(ms: i32) {
    sys::poll(&mut [], ms);
}

fn still_running(pid: i64) -> bool {
    let mut status = 0;
    sys::wait4(pid as i32, &mut status, 1) == 0
}

fn creation() -> i32 {
    // 1. socket: flags, close-on-exec and O_NONBLOCK; bad flags EINVAL; a
    //    family past AF_MAX EAFNOSUPPORT; a type past SOCK_MAX EINVAL; a
    //    protocol other than 0 EPROTONOSUPPORT; SOCK_RDM ESOCKTNOSUPPORT.
    let s = sys::socket(AF_UNIX, STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0) as i32;
    if s < 0 || sys::fcntl(s, F_GETFD, 0) != 1 || sys::fcntl(s, F_GETFL, 0) != 0o4002 {
        return 1;
    }
    if sys::socket(AF_UNIX, STREAM | 0x100, 0) != EINVAL
        || sys::socket(9999, STREAM, 0) != EAFNOSUPPORT
        || sys::socket(AF_UNIX, 11, 0) != EINVAL
    {
        return 2;
    }
    if sys::socket(AF_UNIX, STREAM, 7) != EPROTONOSUPPORT
        || sys::socket(AF_UNIX, 4, 0) != ESOCKTNOSUPPORT
    {
        return 3;
    }
    // 2. Its inode: S_IFSOCK | 0777, on sockfs; no seeking.
    let mut st = [0u8; 144];
    let mode = u32::from_le_bytes(st[24..28].try_into().unwrap_or([0; 4]));
    let _ = mode;
    let mut sf = [0u8; 120];
    if sys::fstat(s, &mut st) != 0
        || u32::from_le_bytes(st[24..28].try_into().unwrap_or([0; 4])) != S_IFSOCK | 0o777
        || sys::fstatfs(s, &mut sf) != 0
        || sf[..8] != 0x534F_434Bu64.to_le_bytes()
    {
        return 4;
    }
    if sys::lseek(s, 0, 0) != ESPIPE {
        return 5;
    }
    // 3. Socket calls on what is not a socket ENOTSOCK; on nothing EBADF.
    let mut fds = [0i32; 2];
    sys::pipe2(&mut fds, None);
    let mut a = [0u8; 110];
    let n = sun(b"x", &mut a);
    if sys::bind(fds[0], &a[..n]) != ENOTSOCK || sys::listen(900, 1) != EBADF {
        return 6;
    }
    sys::close(fds[0]);
    sys::close(fds[1]);
    // 4. Options: type, domain, protocol; not listening; the default
    //    buffers; SO_SNDBUF doubled; read-only options ENOPROTOOPT; another
    //    level EOPNOTSUPP; a short value EINVAL; a negative length EINVAL;
    //    a flag kept; unknown ENOPROTOOPT.
    if get_int(s, SO_TYPE) != Some(1)
        || get_int(s, SO_DOMAIN) != Some(1)
        || get_int(s, SO_PROTOCOL) != Some(0)
        || get_int(s, SO_ACCEPTCONN) != Some(0)
        || get_int(s, SO_ERROR) != Some(0)
    {
        return 7;
    }
    if get_int(s, SO_SNDBUF) != Some(212_992) || get_int(s, SO_RCVBUF) != Some(212_992) {
        return 8;
    }
    if set_int(s, SO_SNDBUF, 65536) != 0 || get_int(s, SO_SNDBUF) != Some(131_072) {
        return 9;
    }
    if set_int(s, SO_TYPE, 1) != ENOPROTOOPT
        || sys::setsockopt(s, 0, 1, &1i32.to_le_bytes()) != EOPNOTSUPP
        || sys::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &[1, 0]) != EINVAL
    {
        return 10;
    }
    let mut v = [0u8; 4];
    let mut len = -1;
    if sys::getsockopt(s, SOL_SOCKET, SO_TYPE, &mut v, &mut len) != EINVAL {
        return 11;
    }
    if set_int(s, SO_REUSEADDR, 1) != 0
        || get_int(s, SO_REUSEADDR) != Some(1)
        || set_int(s, 999, 1) != ENOPROTOOPT
    {
        return 12;
    }
    // A short buffer takes what fits and reports what it took.
    let mut two = [0u8; 2];
    let mut len = 2;
    if sys::getsockopt(s, SOL_SOCKET, SO_TYPE, &mut two, &mut len) != 0 || len != 2 || two != [1, 0]
    {
        return 13;
    }
    // SO_RCVTIMEO: a timeval; microseconds of a second EDOM.
    let mut tv = [0u8; 16];
    tv[..8].copy_from_slice(&2i64.to_le_bytes());
    let mut got = [0u8; 16];
    let mut len = 16;
    if sys::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv) != 0
        || sys::getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &mut got, &mut len) != 0
        || got != tv
    {
        return 14;
    }
    tv[8..].copy_from_slice(&1_000_000i64.to_le_bytes());
    if sys::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv) != EDOM {
        return 15;
    }
    // With no peer, SO_PEERCRED is pid 0, uid and gid -1.
    if peercred(s) != Some((0, -1, -1)) {
        return 16;
    }
    // 5. Unconnected: poll says hung up and writable; read EINVAL; write
    //    ENOTCONN; getpeername ENOTCONN; getsockname the family alone;
    //    shutdown is fine; listen on an unnamed socket EINVAL; accept on a
    //    socket not listening EINVAL.
    if ready(s, POLLIN | POLLOUT) != POLLOUT | POLLHUP {
        return 17;
    }
    let mut b = [0u8; 4];
    if sys::read(s, &mut b) != EINVAL || sys::write(s, b"x") != ENOTCONN {
        return 18;
    }
    if name_of(s, true).err() != Some(ENOTCONN) || name_of(s, false).map(|r| r.1) != Ok(2) {
        return 19;
    }
    if sys::shutdown(s, SHUT_WR) != 0 || sys::shutdown(s, 3) != EINVAL {
        return 20;
    }
    let t = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if sys::listen(t, 1) != EINVAL || sys::accept4(t, None, 0) != EINVAL {
        return 21;
    }
    if sys::accept4(t, None, 0x1) != EINVAL {
        return 22;
    }
    sys::close(t);
    sys::close(s);
    0
}

fn pairs() -> i32 {
    // 1. socketpair: connected both ways; unknown flags EINVAL; EFAULT.
    let Some((a, b)) = pair(0) else {
        return 30;
    };
    let bad = Hostile::new(0x10).unwrap_or_else(|| unreachable!());
    if sys::socketpair_into(AF_UNIX, STREAM, bad) != EFAULT {
        return 31;
    }
    let mut sv = [0i32; 2];
    if sys::socketpair(AF_UNIX, STREAM | 0x100, 0, &mut sv) != EINVAL {
        return 32;
    }
    let mut buf = [0u8; 64];
    if sys::write(a, b"ping") != 4 || sys::read(b, &mut buf) != 4 || &buf[..4] != b"ping" {
        return 33;
    }
    if sys::write(b, b"pong") != 4 || sys::read(a, &mut buf) != 4 || &buf[..4] != b"pong" {
        return 34;
    }
    // Unnamed peers; each side's credentials are ours.
    let me = sys::getpid() as i32;
    if name_of(a, true).map(|r| r.1) != Ok(2) || peercred(a) != Some((me, 0, 0)) {
        return 35;
    }
    // 2. Bytes in order as one stream: two writes read as one; FIONREAD
    //    counts them; MSG_PEEK leaves them; MSG_DONTWAIT on empty
    //    EAGAIN; a zero-length read is 0 at once.
    sys::write(a, b"abc");
    sys::write(a, b"def");
    // (SIOCOUTQ counts Linux's buffer memory, not bytes: not compared.)
    if ioctl_int(b, FIONREAD) != Some(6) || ioctl_int(a, SIOCOUTQ).is_none_or(|n| n <= 0) {
        return 36;
    }
    if sys::recvfrom(b, &mut buf[..2], MSG_PEEK, None) != 2 || &buf[..2] != b"ab" {
        return 37;
    }
    if sys::read(b, &mut buf) != 6 || &buf[..6] != b"abcdef" {
        return 38;
    }
    if sys::recvfrom(b, &mut buf, MSG_DONTWAIT, None) != EAGAIN || sys::read(b, &mut buf[..0]) != 0
    {
        return 39;
    }
    // sendmsg's vectors and recvmsg's: one stream; names and flags back.
    if sys::sendmsg(a, &[b"12", b"345"], 0) != 5 {
        return 40;
    }
    let (mut x, mut y) = ([0u8; 2], [0u8; 8]);
    let mut nm = [0u8; 16];
    let (n, namelen, flags) = sys::recvmsg2(b, &mut x, &mut y, Some(&mut nm), 0);
    if n != 5 || &x != b"12" || &y[..3] != b"345" || namelen != 0 || flags != 0 {
        return 41;
    }
    // 3. MSG_WAITALL waits for all of it: a child writes the rest later.
    let child = sys::fork();
    if child == 0 {
        sys::write(a, b"wa");
        nap(30);
        sys::write(a, b"it");
        nap(300);
        keel_rt::exit(0);
    }
    if sys::recvfrom(b, &mut buf[..4], MSG_WAITALL, None) != 4 || &buf[..4] != b"wait" {
        return 42;
    }
    // A blocking read woken by the child's write while it still runs.
    let child2 = sys::fork();
    if child2 == 0 {
        nap(30);
        sys::write(a, b"!");
        nap(300);
        keel_rt::exit(0);
    }
    if sys::read(b, &mut buf) != 1 || !still_running(child2) {
        return 43;
    }
    let mut st = 0;
    sys::wait4(child as i32, &mut st, 0);
    sys::wait4(child2 as i32, &mut st, 0);
    // 4. Full: a non-blocking writer writes until EAGAIN, part of a large
    //    write first; then it is not writable; the reader gets every byte
    //    and the writer is writable again.
    sys::fcntl(a, F_SETFL, O_NONBLOCK);
    let big = [9u8; 16384];
    let mut total = 0i64;
    let mut partial = false;
    loop {
        let n = sys::write(a, &big);
        if n == EAGAIN {
            break;
        }
        if n <= 0 || total > 64 << 20 {
            return 44;
        }
        partial |= n < big.len() as i64;
        total += n;
    }
    if total == 0 || ready(a, POLLOUT) != 0 {
        return 45;
    }
    let _ = partial;
    let mut got = 0i64;
    let mut sink = [0u8; 16384];
    while got < total {
        let n = sys::recvfrom(b, &mut sink, MSG_DONTWAIT, None);
        if n <= 0 {
            return 46;
        }
        got += n;
    }
    if got != total || ready(a, POLLOUT) != POLLOUT {
        return 47;
    }
    // 5. shutdown(SHUT_WR): the peer reads end of file and sees RDHUP; the
    //    writer EPIPE, with SIGPIPE ignored here; with MSG_NOSIGNAL none.
    if !disposition(SIGPIPE, 1) {
        return 48;
    }
    sys::shutdown(a, SHUT_WR);
    if sys::read(b, &mut buf) != 0
        || ready(b, POLLIN | POLLRDHUP) & (POLLIN | POLLRDHUP) != POLLIN | POLLRDHUP
    {
        return 49;
    }
    if sys::write(a, b"x") != EPIPE || sys::sendto(a, b"x", MSG_NOSIGNAL, None) != EPIPE {
        return 50;
    }
    // The other way still works until it is shut too; then both hang up.
    if sys::write(b, b"y") != 1 || sys::read(a, &mut buf) != 1 {
        return 51;
    }
    sys::shutdown(b, SHUT_RDWR);
    if ready(a, POLLIN) & POLLHUP == 0 {
        return 52;
    }
    sys::close(a);
    sys::close(b);
    // 6. The peer closed: end of file and EPIPE; with SIGPIPE's default
    //    action the writer dies of it.
    let Some((a, b)) = pair(0) else {
        return 53;
    };
    sys::close(a);
    if sys::read(b, &mut buf) != 0 || sys::write(b, b"x") != EPIPE {
        return 54;
    }
    disposition(SIGPIPE, 0);
    // MSG_NOSIGNAL: EPIPE alone, even with SIGPIPE's default action.
    let child = sys::fork();
    if child == 0 {
        keel_rt::exit(i32::from(sys::sendto(b, b"x", MSG_NOSIGNAL, None) != EPIPE));
    }
    let mut status = 0;
    if sys::wait4(child as i32, &mut status, 0) != child || status != 0 {
        return 58;
    }
    let child = sys::fork();
    if child == 0 {
        sys::write(b, b"x");
        keel_rt::exit(0);
    }
    let mut status = 0;
    if sys::wait4(child as i32, &mut status, 0) != child || status & 0x7f != SIGPIPE {
        return 55;
    }
    sys::close(b);
    // 7. Closing with unread data resets the peer: ECONNRESET once, then
    //    end of file.
    let Some((a, b)) = pair(0) else {
        return 56;
    };
    sys::write(b, b"unread");
    sys::close(a);
    if sys::read(b, &mut buf) != ECONNRESET || sys::read(b, &mut buf) != 0 {
        return 57;
    }
    sys::close(b);
    0
}

/// A unique path under /tmp for this run.
fn tmp_path<'a>(buf: &'a mut [u8; 64], tag: &[u8]) -> &'a [u8] {
    let prefix = b"/tmp/sockprobe-";
    buf[..prefix.len()].copy_from_slice(prefix);
    let mut at = prefix.len();
    let mut pid = sys::getpid() as u64;
    let mut digits = [0u8; 20];
    let mut d = 20;
    loop {
        d -= 1;
        digits[d] = b'0' + (pid % 10) as u8;
        pid /= 10;
        if pid == 0 {
            break;
        }
    }
    buf[at..at + 20 - d].copy_from_slice(&digits[d..]);
    at += 20 - d;
    buf[at..at + tag.len()].copy_from_slice(tag);
    at += tag.len();
    &buf[..at]
}

fn cstr<'a>(path: &[u8], buf: &'a mut [u8; 80]) -> &'a CStr {
    buf[..path.len()].copy_from_slice(path);
    buf[path.len()] = 0;
    CStr::from_bytes_until_nul(&buf[..]).unwrap_or(c"")
}

fn named() -> i32 {
    let mut pb = [0u8; 64];
    let path = tmp_path(&mut pb, b"-l");
    let mut addr = [0u8; 110];
    let alen = sun(path, &mut addr);
    let mut cb = [0u8; 80];
    let cpath = cstr(path, &mut cb);
    sys::unlink(cpath);
    // 1. bind makes a socket node, mode 0777 less the umask (022); it
    //    cannot be opened (ENXIO); getsockname gives the path and its NUL.
    let l = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if sys::bind(l, &addr[..alen]) != 0 {
        return 60;
    }
    let mut st = [0u8; 144];
    let mode = |b: &[u8; 144]| u32::from_le_bytes(b[24..28].try_into().unwrap_or([0; 4]));
    if sys::stat(cpath, &mut st) != 0 || mode(&st) != S_IFSOCK | 0o755 {
        return 61;
    }
    if sys::openat(AT_FDCWD, cpath, O_RDONLY, 0) != ENXIO {
        return 62;
    }
    match name_of(l, false) {
        Ok((b, len)) if len as usize == alen && b[..alen] == addr[..alen] => {}
        _ => return 63,
    }
    // 2. The name taken: EADDRINUSE; a named socket bound again: EINVAL,
    //    and the new name is not left behind.
    let other = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if sys::bind(other, &addr[..alen]) != EADDRINUSE {
        return 64;
    }
    let mut pb2 = [0u8; 64];
    let path2 = tmp_path(&mut pb2, b"-x");
    let mut addr2 = [0u8; 110];
    let alen2 = sun(path2, &mut addr2);
    let mut cb2 = [0u8; 80];
    let cpath2 = cstr(path2, &mut cb2);
    sys::unlink(cpath2);
    if sys::bind(l, &addr2[..alen2]) != EINVAL || sys::stat(cpath2, &mut st) != ENOENT {
        return 65;
    }
    // Addresses: too short (the family alone, for connect) or a wrong
    // family EINVAL.
    let mut wrong = addr;
    wrong[0] = 2;
    if sys::connect(other, &addr[..2]) != EINVAL || sys::bind(other, &wrong[..alen]) != EINVAL {
        return 66;
    }
    // 3. connect before listen: ECONNREFUSED. Then listen; nothing to
    //    accept yet (non-blocking: EAGAIN); SO_ACCEPTCONN.
    if sys::connect(other, &addr[..alen]) != ECONNREFUSED {
        return 67;
    }
    if sys::listen(l, 5) != 0 || get_int(l, SO_ACCEPTCONN) != Some(1) {
        return 68;
    }
    sys::fcntl(l, F_SETFL, O_NONBLOCK);
    if sys::accept4(l, None, 0) != EAGAIN || ready(l, POLLIN) != 0 {
        return 69;
    }
    // accept4's flags are checked first: EINVAL even on a listener.
    if sys::accept4(l, None, 0x1) != EINVAL {
        return 87;
    }
    // 4. connect succeeds at once, and the client may write before the
    //    connection is accepted; the listener is then readable.
    let c = other;
    if sys::connect(c, &addr[..alen]) != 0 || sys::write(c, b"early") != 5 {
        return 70;
    }
    if ready(l, POLLIN) != POLLIN {
        return 71;
    }
    // A second connect EISCONN; listening on a connected socket EINVAL.
    if sys::connect(c, &addr[..alen]) != EISCONN || sys::listen(c, 1) != EINVAL {
        return 72;
    }
    // 5. accept4 with SOCK_CLOEXEC: the peer's address is unnamed (the
    //    family alone); the new socket is named as the listener; the
    //    client's peer is the listener's name; data both ways.
    let mut peer = [0u8; 110];
    let mut plen = 110;
    let s = sys::accept4(l, Some((&mut peer, &mut plen)), SOCK_CLOEXEC) as i32;
    if s < 0 || plen != 2 || sys::fcntl(s, F_GETFD, 0) != 1 {
        return 73;
    }
    let same = |r: Result<([u8; 110], i32), i64>| matches!(r, Ok((b, len)) if len as usize == alen && b[..alen] == addr[..alen]);
    if !same(name_of(s, false)) || !same(name_of(c, true)) || name_of(s, true).map(|r| r.1) != Ok(2)
    {
        return 74;
    }
    let mut buf = [0u8; 16];
    if sys::read(s, &mut buf) != 5 || &buf[..5] != b"early" {
        return 75;
    }
    if sys::write(s, b"hi") != 2 || sys::read(c, &mut buf) != 2 {
        return 76;
    }
    // Credentials: ours, both ways.
    let me = sys::getpid() as i32;
    if peercred(s) != Some((me, 0, 0)) || peercred(c) != Some((me, 0, 0)) {
        return 77;
    }
    // recvfrom on the client reports the sender: the listener's name.
    sys::write(s, b"z");
    let mut from = [0u8; 110];
    let mut flen = 110;
    if sys::recvfrom(c, &mut buf, 0, Some((&mut from, &mut flen))) != 1
        || flen as usize != alen
        || from[..alen] != addr[..alen]
    {
        return 78;
    }
    // ...and on the accepted side, from an unnamed client: no name (0).
    sys::write(c, b"y");
    let mut flen = 110;
    if sys::recvfrom(s, &mut buf, 0, Some((&mut from, &mut flen))) != 1 || flen != 0 {
        return 86;
    }
    sys::close(s);
    sys::close(c);
    // 6. Errors connecting: a path that does not exist ENOENT; a file that
    //    is not a socket ECONNREFUSED.
    let mut nb = [0u8; 64];
    let none = tmp_path(&mut nb, b"-none");
    let mut na = [0u8; 110];
    let nlen = sun(none, &mut na);
    let c = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if sys::connect(c, &na[..nlen]) != ENOENT {
        return 79;
    }
    let mut fb = [0u8; 80];
    let mut fpb = [0u8; 64];
    let fpath = tmp_path(&mut fpb, b"-file");
    let cf = cstr(fpath, &mut fb);
    let fd = sys::openat(AT_FDCWD, cf, 0o100 | 1, 0o644) as i32;
    sys::close(fd);
    let mut fa = [0u8; 110];
    let flen2 = sun(fpath, &mut fa);
    if sys::connect(c, &fa[..flen2]) != ECONNREFUSED {
        return 80;
    }
    sys::unlink(cf);
    // 7. The backlog: listen(1) lets two connections wait, then a
    //    non-blocking connect is EAGAIN.
    sys::listen(l, 1);
    let c1 = sys::socket(AF_UNIX, STREAM, 0) as i32;
    let c2 = sys::socket(AF_UNIX, STREAM, 0) as i32;
    let c3 = sys::socket(AF_UNIX, STREAM | SOCK_NONBLOCK, 0) as i32;
    if sys::connect(c1, &addr[..alen]) != 0 || sys::connect(c2, &addr[..alen]) != 0 {
        return 81;
    }
    if sys::connect(c3, &addr[..alen]) != EAGAIN {
        return 82;
    }
    // 8. Closing the listener resets the connections it had not accepted:
    //    their clients read ECONNRESET. The node stays, naming nothing:
    //    a connect to it ECONNREFUSED.
    sys::close(l);
    if sys::read(c1, &mut buf) != ECONNRESET || sys::read(c1, &mut buf) != 0 {
        return 83;
    }
    if sys::stat(cpath, &mut st) != 0 || mode(&st) & S_IFMT != S_IFSOCK {
        return 84;
    }
    if sys::connect(c, &addr[..alen]) != ECONNREFUSED {
        return 85;
    }
    for fd in [c, c1, c2, c3] {
        sys::close(fd);
    }
    sys::unlink(cpath);
    0
}

fn abstract_names() -> i32 {
    // 1. An abstract name: getsockname gives it as bound (its leading NUL,
    //    no added NUL); a second bind of it EADDRINUSE; no node is made.
    let mut nb = [0u8; 64];
    let p = tmp_path(&mut nb, b"-abs");
    let mut name = [0u8; 64];
    name[0] = 0;
    name[1..p.len() + 1].copy_from_slice(p);
    let name = &name[..p.len() + 1];
    let mut addr = [0u8; 110];
    let alen = sun(name, &mut addr);
    let l = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if sys::bind(l, &addr[..alen]) != 0 || sys::listen(l, 4) != 0 {
        return 90;
    }
    match name_of(l, false) {
        Ok((b, len)) if len as usize == alen && b[..alen] == addr[..alen] => {}
        _ => return 91,
    }
    let x = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if sys::bind(x, &addr[..alen]) != EADDRINUSE {
        return 92;
    }
    // 2. Autobind: bind with the family alone gives an abstract name of a
    //    NUL and five hex digits (8 bytes in all); bound again, nothing
    //    changes.
    if sys::bind(x, &addr[..2]) != 0 {
        return 93;
    }
    let Ok((auto, alen_auto)) = name_of(x, false) else {
        return 94;
    };
    let hex = |b: &u8| b.is_ascii_digit() || (b'a'..=b'f').contains(b);
    if alen_auto != 8 || auto[2] != 0 || !auto[3..8].iter().all(hex) {
        return 94;
    }
    if sys::bind(x, &addr[..2]) != 0 || name_of(x, false).map(|r| r.0) != Ok(auto) {
        return 95;
    }
    // 3. SO_PASSCRED before connect autobinds the client: the accepted
    //    side's peer is that name, and recvfrom reports it.
    let c = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if set_int(c, SO_PASSCRED, 1) != 0 || sys::connect(c, &addr[..alen]) != 0 {
        return 96;
    }
    let Ok((cname, clen)) = name_of(c, false) else {
        return 97;
    };
    if clen != 8 || cname[2] != 0 {
        return 97;
    }
    let s = sys::accept4(l, None, 0) as i32;
    match name_of(s, true) {
        Ok((b, 8)) if b[..8] == cname[..8] => {}
        _ => return 98,
    }
    sys::write(c, b"q");
    let mut from = [0u8; 110];
    let mut flen = 110;
    let mut buf = [0u8; 4];
    if sys::recvfrom(s, &mut buf, 0, Some((&mut from, &mut flen))) != 1
        || flen != 8
        || from[..8] != cname[..8]
    {
        return 99;
    }
    // The accepted socket inherits SO_PASSCRED from the listener (off).
    if get_int(s, SO_PASSCRED) != Some(0) {
        return 100;
    }
    // 4. A stream socket connecting to a name another type holds would be
    //    EPROTOTYPE; a name nobody holds ECONNREFUSED.
    let mut none = [0u8; 110];
    let nlen = sun(b"\0sockprobe-nobody-here", &mut none);
    let d = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if sys::connect(d, &none[..nlen]) != ECONNREFUSED {
        return 101;
    }
    let _ = EPROTOTYPE;
    for fd in [l, x, c, s, d] {
        sys::close(fd);
    }
    // 5. Once the listener is closed, its name is free again.
    let again = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if sys::bind(again, &addr[..alen]) != 0 {
        return 102;
    }
    sys::close(again);
    0
}

fn accept_waits() -> i32 {
    // A blocking accept woken by a child's connect, while the child still
    // runs; accept's address length 0 copies nothing but reports the
    // length.
    let mut addr = [0u8; 110];
    let mut nb = [0u8; 64];
    let p = tmp_path(&mut nb, b"-w");
    let mut name = [0u8; 64];
    name[1..p.len() + 1].copy_from_slice(p);
    let alen = sun(&name[..p.len() + 1], &mut addr);
    let l = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if sys::bind(l, &addr[..alen]) != 0 || sys::listen(l, 1) != 0 {
        return 110;
    }
    let child = sys::fork();
    if child == 0 {
        nap(30);
        let c = sys::socket(AF_UNIX, STREAM, 0) as i32;
        sys::connect(c, &addr[..alen]);
        nap(300);
        keel_rt::exit(0);
    }
    let mut peer = [0u8; 4];
    let mut plen = 0;
    let s = sys::accept4(l, Some((&mut peer, &mut plen)), 0);
    if s < 0 || plen != 2 || !still_running(child) {
        return 111;
    }
    let mut status = 0;
    sys::wait4(child as i32, &mut status, 0);
    sys::close(s as i32);
    sys::close(l);
    0
}

fn epolled() -> i32 {
    // epoll over sockets: a listener is readable when a connection waits;
    // an edge-triggered reader sees an edge per write (each queues data
    // and wakes readers, `sock_def_readable`), none without one; the
    // peer's close is an edge with EPOLLHUP.
    const ET: u32 = 1 << 31;
    let ev = |events: u32, data: u64| {
        let mut e = [0u8; 12];
        e[..4].copy_from_slice(&events.to_le_bytes());
        e[4..].copy_from_slice(&data.to_le_bytes());
        e
    };
    let one = |e: i32| {
        let mut out = [[0u8; 12]; 1];
        (sys::epoll_wait(e, &mut out, 0) == 1).then(|| {
            (
                u32::from_le_bytes([out[0][0], out[0][1], out[0][2], out[0][3]]),
                u64::from_le_bytes(out[0][4..].try_into().unwrap_or([0; 8])),
            )
        })
    };
    let e = sys::epoll_create1(Some(0o2000000), 0) as i32;
    let mut addr = [0u8; 110];
    let alen = sun(b"\0sockprobe-epoll", &mut addr);
    let l = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if sys::bind(l, &addr[..alen]) != 0 || sys::listen(l, 2) != 0 {
        return 120;
    }
    if sys::epoll_ctl(e, 1, l, Some(&ev(1, 1))) != 0 || one(e).is_some() {
        return 121;
    }
    let c = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if sys::connect(c, &addr[..alen]) != 0 || one(e) != Some((1, 1)) {
        return 122;
    }
    let s = sys::accept4(l, None, 0) as i32;
    if one(e).is_some() || sys::epoll_ctl(e, 2, l, None) != 0 {
        return 123;
    }
    if sys::epoll_ctl(e, 1, s, Some(&ev(1 | ET, 2))) != 0 || one(e).is_some() {
        return 124;
    }
    sys::write(c, b"a");
    if one(e) != Some((1, 2)) || one(e).is_some() {
        return 125;
    }
    sys::write(c, b"b");
    if one(e) != Some((1, 2)) {
        return 126;
    }
    // An edge-triggered writer: full, no edge; its peer's reads make
    // room and wake it (`unix_write_space`).
    let mut drain = [0u8; 4096];
    sys::read(s, &mut drain);
    sys::fcntl(c, F_SETFL, O_NONBLOCK);
    let e2 = sys::epoll_create1(Some(0o2000000), 0) as i32;
    if sys::epoll_ctl(e2, 1, c, Some(&ev(4 | ET, 3))) != 0 || one(e2) != Some((4, 3)) {
        return 128;
    }
    let chunk = [1u8; 8192];
    while sys::write(c, &chunk) > 0 {}
    if one(e2).is_some() {
        return 129;
    }
    sys::fcntl(s, F_SETFL, O_NONBLOCK);
    while sys::read(s, &mut drain) > 0 {}
    if one(e2) != Some((4, 3)) {
        return 130;
    }
    sys::close(e2);
    // Drain s's edges from those writes, then the close is one more.
    while one(e).is_some() {}
    sys::close(c);
    match one(e) {
        Some((events, 2)) if events & POLLHUP as u32 != 0 => {}
        _ => return 127,
    }
    for fd in [e, l, s] {
        sys::close(fd);
    }
    0
}

fn main(_: &Startup) -> i32 {
    for part in [
        creation,
        pairs,
        named,
        abstract_names,
        accept_waits,
        epolled,
    ] {
        let failed = part();
        if failed != 0 {
            return failed;
        }
    }
    let _ = O_CLOEXEC;
    sys::write(1, b"sockprobe: 102 checks passed\n");
    0
}

keel_rt::main!(main);
