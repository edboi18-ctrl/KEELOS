//! P3-T11 part 2: descriptors (SCM_RIGHTS) and credentials
//! (SCM_CREDENTIALS) over Unix sockets, and datagram sockets, checked
//! against Linux. Runs under Linux (`host.scmprobe`) and on Keel
//! (`exec.socket_messages`) and must pass on both.
//!
//! Semantics from unix(7) ("Ancillary messages"), cmsg(3), recvmsg(2),
//! socket(7) (SO_PASSCRED) and Linux v6.12's `net/core/scm.c` and
//! `net/unix/af_unix.c`. Only what both kernels guarantee is checked: no
//! exact uid or gid (the Linux host's need not be root's), no queue
//! lengths or buffer sizes the host configures.
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, Arg, O_RDONLY, Out};

const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EINVAL: i64 = -22;
const EPIPE: i64 = -32;
const EMSGSIZE: i64 = -90;
const EPROTOTYPE: i64 = -91;
const EPERM: i64 = -1;
const ENOTCONN: i64 = -107;
const ECONNREFUSED: i64 = -111;

const AF_UNIX: i32 = 1;
const STREAM: u32 = 1;
const DGRAM: u32 = 2;
const RAW: u32 = 3;
const SOCK_NONBLOCK: u32 = 0o4000;
const O_NONBLOCK: u64 = 0o4000;
const F_GETFD: u32 = 1;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
const SO_TYPE: i32 = 3;
const SO_SNDBUF: i32 = 7;
const SO_PASSCRED: i32 = 16;
const SO_PEERCRED: i32 = 17;
const MSG_PEEK: u32 = 2;
const MSG_CTRUNC: i32 = 8;
const MSG_TRUNC: u32 = 0x20;
const MSG_DONTWAIT: u32 = 0x40;
const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;
const SHUT_RD: i32 = 0;
const FIONREAD: u64 = 0x541B;
const POLLIN: u16 = 1;
const POLLOUT: u16 = 4;
const POLLHUP: u16 = 0x10;
const SIGPIPE: i32 = 13;

/// CMSG_LEN and CMSG_SPACE on x86-64 (a 16-byte header, 8-byte
/// alignment).
const fn cmsg_len(n: usize) -> usize {
    16 + n
}
const fn cmsg_space(n: usize) -> usize {
    16 + ((n + 7) & !7)
}

/// One control message: header and data, padded to its space.
fn cmsg(out: &mut [u8], at: usize, level: i32, ty: i32, data: &[u8]) -> usize {
    let len = cmsg_len(data.len());
    out[at..at + 8].copy_from_slice(&(len as u64).to_le_bytes());
    out[at + 8..at + 12].copy_from_slice(&level.to_le_bytes());
    out[at + 12..at + 16].copy_from_slice(&ty.to_le_bytes());
    out[at + 16..at + 16 + data.len()].copy_from_slice(data);
    at + cmsg_space(data.len())
}

fn fds_bytes(fds: &[i32], out: &mut [u8; 64]) -> usize {
    for (i, fd) in fds.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&fd.to_le_bytes());
    }
    4 * fds.len()
}

/// Sends `data` with `fds` as SCM_RIGHTS.
fn send_fds(sock: i32, data: &[u8], fds: &[i32]) -> i64 {
    let mut d = [0u8; 64];
    let n = fds_bytes(fds, &mut d);
    let mut c = [0u8; 128];
    let len = cmsg(&mut c, 0, SOL_SOCKET, SCM_RIGHTS, &d[..n]);
    sys::sendmsg_full(sock, None, &[data], Some(&c[..len]), 0)
}

fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]))
}

fn int(b: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(b[at..at + 4].try_into().unwrap_or([0; 4]))
}

/// The descriptors in the first control message, if it is SCM_RIGHTS.
fn rights(c: &[u8], controllen: u64) -> ([i32; 8], usize) {
    let mut fds = [-1i32; 8];
    if controllen < 16 || int(c, 8) != SOL_SOCKET || int(c, 12) != SCM_RIGHTS {
        return (fds, 0);
    }
    let n = ((word(c, 0) as usize).saturating_sub(16) / 4).min(8);
    for (i, slot) in fds.iter_mut().enumerate().take(n) {
        *slot = int(c, 16 + 4 * i);
    }
    (fds, n)
}

fn pair(ty: u32) -> Option<(i32, i32)> {
    let mut sv = [-1i32; 2];
    (sys::socketpair(AF_UNIX, ty, 0, &mut sv) == 0).then_some((sv[0], sv[1]))
}

fn pipe() -> (i32, i32) {
    let mut fds = [-1i32; 2];
    sys::pipe2(&mut fds, None);
    (fds[0], fds[1])
}

fn set_int(fd: i32, name: i32, v: i32) -> i64 {
    sys::setsockopt(fd, SOL_SOCKET, name, &v.to_le_bytes())
}

fn get_int(fd: i32, name: i32) -> Option<i32> {
    let mut v = [0u8; 4];
    let mut len = 4;
    (sys::getsockopt(fd, SOL_SOCKET, name, &mut v, &mut len) == 0).then(|| i32::from_le_bytes(v))
}

fn ready(fd: i32, events: u16) -> u16 {
    let mut e = [0u8; 8];
    e[..4].copy_from_slice(&fd.to_le_bytes());
    e[4..6].copy_from_slice(&events.to_le_bytes());
    let mut fds = [e];
    sys::poll(&mut fds, 0);
    u16::from_le_bytes([fds[0][6], fds[0][7]])
}

fn rights_part() -> i32 {
    let Some((a, b)) = pair(STREAM) else {
        return 1;
    };
    let (r, w) = pipe();
    // 1. A pipe's read end, sent with one byte: received as a new
    //    descriptor (SCM_RIGHTS, CMSG_LEN(4), the buffer used to
    //    CMSG_SPACE(4)), not close-on-exec; it reads what the write end
    //    writes.
    if send_fds(a, b"x", &[r]) != 1 {
        return 2;
    }
    let mut buf = [0u8; 8];
    let mut c = [0u8; 64];
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    let (fds, n) = rights(&c, got.controllen);
    if got.result != 1 || n != 1 || word(&c, 0) != cmsg_len(4) as u64 || got.controllen != 24 {
        return 3;
    }
    let nr = fds[0];
    if nr == r || sys::fcntl(nr, F_GETFD, 0) != 0 || got.flags != 0 {
        return 4;
    }
    sys::write(w, b"via");
    if sys::read(nr, &mut buf) != 3 || &buf[..3] != b"via" {
        return 5;
    }
    // 2. The same open file: O_NONBLOCK set through one shows through the
    //    other. MSG_CMSG_CLOEXEC makes the new descriptor close-on-exec.
    sys::fcntl(r, F_SETFL, O_NONBLOCK);
    if sys::fcntl(nr, F_GETFL, 0) & O_NONBLOCK as i64 == 0 {
        return 6;
    }
    send_fds(a, b"y", &[w]);
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), MSG_CMSG_CLOEXEC);
    let (fds, n) = rights(&c, got.controllen);
    if n != 1 || sys::fcntl(fds[0], F_GETFD, 0) != 1 {
        return 7;
    }
    sys::close(fds[0]);
    sys::close(nr);
    // 3. Errors: a closed descriptor EBADF, and nothing is sent; an
    //    unknown type EINVAL; a length below the header's, or past the
    //    data, EINVAL; another level is skipped; more than 253 EINVAL.
    if send_fds(a, b"z", &[900]) != EBADF || send_fds(a, b"z", &[-1]) != EBADF {
        return 8;
    }
    let mut ctl = [0u8; 64];
    let len = cmsg(&mut ctl, 0, SOL_SOCKET, 9, &[0; 4]);
    if sys::sendmsg_full(a, None, &[b"z"], Some(&ctl[..len]), 0) != EINVAL {
        return 9;
    }
    ctl[..8].copy_from_slice(&8u64.to_le_bytes());
    if sys::sendmsg_full(a, None, &[b"z"], Some(&ctl[..len]), 0) != EINVAL {
        return 10;
    }
    ctl[..8].copy_from_slice(&100u64.to_le_bytes());
    if sys::sendmsg_full(a, None, &[b"z"], Some(&ctl[..len]), 0) != EINVAL {
        return 11;
    }
    let len = cmsg(&mut ctl, 0, 99, 1, &[0; 4]);
    if sys::sendmsg_full(a, None, &[b"z"], Some(&ctl[..len]), 0) != 1 {
        return 12;
    }
    let mut many = [0u8; 16 + 4 * 254];
    let total = many.len() as u64;
    many[..8].copy_from_slice(&total.to_le_bytes());
    many[8..12].copy_from_slice(&SOL_SOCKET.to_le_bytes());
    many[12..16].copy_from_slice(&SCM_RIGHTS.to_le_bytes());
    if sys::sendmsg_full(a, None, &[b"z"], Some(&many), 0) != EINVAL {
        return 13;
    }
    // Only the one skipped-level byte arrived.
    let mut q = [0u8; 64];
    if sys::ioctl(b, FIONREAD, &mut q) != 0 || int(&q, 0) != 1 {
        return 14;
    }
    sys::read(b, &mut buf);
    // 4. Room for one of three: one is installed, MSG_CTRUNC, the buffer
    //    used to its end; the others are closed.
    let (r2, w2) = pipe();
    send_fds(a, b"t", &[r2, r2, r2]);
    let mut small = [0u8; cmsg_len(4)];
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut small), 0);
    let (fds, n) = rights(&small, got.controllen);
    if got.result != 1
        || n != 1
        || got.flags & MSG_CTRUNC == 0
        || got.controllen != cmsg_len(4) as u64
    {
        return 15;
    }
    sys::close(fds[0]);
    // No control buffer: MSG_CTRUNC, and the descriptor is closed.
    send_fds(a, b"u", &[r2]);
    let got = sys::recvmsg_full(b, &mut buf, None, None, 0);
    if got.result != 1 || got.flags & MSG_CTRUNC == 0 || got.controllen != 0 {
        return 16;
    }
    // 5. A read stops after the part with descriptors; one that starts
    //    before it takes it along.
    send_fds(a, b"ab", &[r2]);
    sys::write(a, b"cd");
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    let (fds, n) = rights(&c, got.controllen);
    if got.result != 2 || n != 1 || sys::read(b, &mut buf) != 2 || &buf[..2] != b"cd" {
        return 17;
    }
    sys::close(fds[0]);
    sys::write(a, b"ef");
    send_fds(a, b"gh", &[r2]);
    sys::write(a, b"ij");
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    let (fds, n) = rights(&c, got.controllen);
    if got.result != 4 || &buf[..4] != b"efgh" || n != 1 {
        return 18;
    }
    sys::close(fds[0]);
    sys::read(b, &mut buf);
    // 6. MSG_PEEK copies the descriptors; the read after gets them again.
    send_fds(a, b"p", &[w2]);
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), MSG_PEEK);
    let (pf, pn) = rights(&c, got.controllen);
    let got2 = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    let (rf, rn) = rights(&c, got2.controllen);
    if got.result != 1 || pn != 1 || got2.result != 1 || rn != 1 || pf[0] == rf[0] {
        return 19;
    }
    sys::close(pf[0]);
    sys::close(rf[0]);
    // 7. Descriptors with no bytes on a stream socket are not sent (a send
    //    of nothing sends no part): 0, and nothing arrives.
    if send_fds(a, b"", &[r2]) != 0 {
        return 20;
    }
    if sys::recvfrom(b, &mut buf, MSG_DONTWAIT, None) != EAGAIN {
        return 21;
    }
    // 8. In flight, a descriptor outlives its sender's close; a socket can
    //    be passed and used; a read-only file stays read-only.
    send_fds(a, b"k", &[w2]);
    sys::close(w2);
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    let (fds, _) = rights(&c, got.controllen);
    if sys::write(fds[0], b"kept") != 4 || sys::read(r2, &mut buf) != 4 {
        return 22;
    }
    sys::close(fds[0]);
    let Some((x, y)) = pair(STREAM) else {
        return 23;
    };
    send_fds(a, b"s", &[x]);
    sys::close(x);
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    let (fds, _) = rights(&c, got.controllen);
    if sys::write(fds[0], b"sock") != 4 || sys::read(y, &mut buf) != 4 || &buf[..4] != b"sock" {
        return 24;
    }
    sys::close(fds[0]);
    sys::close(y);
    let f = sys::openat(AT_FDCWD, c"/proc/self/exe", O_RDONLY, 0) as i32;
    send_fds(a, b"f", &[f]);
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    let (fds, _) = rights(&c, got.controllen);
    if f < 0 || sys::write(fds[0], b"no") != EBADF || sys::read(fds[0], &mut buf[..4]) != 4 {
        return 25;
    }
    sys::close(fds[0]);
    sys::close(f);
    // 9. A child passes its descriptor to its parent.
    let child = sys::fork();
    if child == 0 {
        let (cr, cw) = pipe();
        sys::write(cw, b"from child");
        send_fds(a, b"c", &[cr]);
        keel_rt::exit(0);
    }
    let mut status = 0;
    sys::wait4(child as i32, &mut status, 0);
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    let (fds, n) = rights(&c, got.controllen);
    if status != 0 || n != 1 || sys::read(fds[0], &mut buf) != 8 || &buf[..8] != b"from chi" {
        return 26;
    }
    for fd in [fds[0], a, b, r, w, r2] {
        sys::close(fd);
    }
    0
}

/// The SCM_CREDENTIALS in a control buffer: (pid, uid, gid).
fn creds_in(c: &[u8], controllen: u64) -> Option<(i32, i32, i32)> {
    (controllen >= cmsg_len(12) as u64
        && int(c, 8) == SOL_SOCKET
        && int(c, 12) == SCM_CREDENTIALS
        && word(c, 0) == cmsg_len(12) as u64)
        .then(|| (int(c, 16), int(c, 20), int(c, 24)))
}

fn peercred(fd: i32) -> (i32, i32, i32) {
    let mut v = [0u8; 12];
    let mut len = 12;
    sys::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &mut v, &mut len);
    (int(&v, 0), int(&v, 4), int(&v, 8))
}

fn credentials() -> i32 {
    let Some((a, b)) = pair(STREAM) else {
        return 30;
    };
    let me = sys::getpid() as i32;
    let (_, uid, gid) = peercred(b);
    // 1. Without SO_PASSCRED no credentials come.
    sys::write(a, b"1");
    let mut buf = [0u8; 8];
    let mut c = [0u8; 64];
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    if got.result != 1 || got.controllen != 0 {
        return 31;
    }
    // 2. With it, the sender's: our pid, and the uid and gid SO_PEERCRED
    //    reports; first in the buffer.
    if set_int(b, SO_PASSCRED, 1) != 0 {
        return 32;
    }
    sys::write(a, b"2");
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    if creds_in(&c, got.controllen) != Some((me, uid, gid))
        || got.controllen != cmsg_space(12) as u64
    {
        return 33;
    }
    // Credentials then descriptors.
    let (r, w) = pipe();
    send_fds(a, b"3", &[r]);
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    let (fds, n) = rights(&c[cmsg_space(12)..], got.controllen - cmsg_space(12) as u64);
    if creds_in(&c, got.controllen).is_none() || n != 1 {
        return 34;
    }
    sys::close(fds[0]);
    // 3. A child's bytes carry its pid, and a read does not run on into
    //    parts with other credentials.
    let child = sys::fork();
    if child == 0 {
        sys::write(a, b"c");
        keel_rt::exit(0);
    }
    let mut status = 0;
    sys::wait4(child as i32, &mut status, 0);
    sys::write(a, b"p");
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    if got.result != 1
        || buf[0] != b'c'
        || creds_in(&c, got.controllen).map(|v| v.0) != Some(child as i32)
    {
        return 35;
    }
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    if got.result != 1 || creds_in(&c, got.controllen).map(|v| v.0) != Some(me) {
        return 36;
    }
    // 4. SCM_CREDENTIALS sent: our own pid goes through; a pid that does
    //    not exist ESRCH; uid -1 EINVAL; the wrong length EINVAL.
    let cred = |pid: i32, uid: i32, gid: i32, out: &mut [u8; 64]| {
        let mut d = [0u8; 12];
        d[..4].copy_from_slice(&pid.to_le_bytes());
        d[4..8].copy_from_slice(&uid.to_le_bytes());
        d[8..].copy_from_slice(&gid.to_le_bytes());
        cmsg(out, 0, SOL_SOCKET, SCM_CREDENTIALS, &d)
    };
    let mut ctl = [0u8; 64];
    let len = cred(me, uid, gid, &mut ctl);
    if sys::sendmsg_full(a, None, &[b"4"], Some(&ctl[..len]), 0) != 1 {
        return 37;
    }
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut c), 0);
    if creds_in(&c, got.controllen) != Some((me, uid, gid)) {
        return 38;
    }
    // (Root, which Keel's processes are, gets ESRCH; Linux refuses another
    // user another process's pid first, with EPERM.)
    let len = cred(999_999_999, uid, gid, &mut ctl);
    let res = sys::sendmsg_full(a, None, &[b"5"], Some(&ctl[..len]), 0);
    if res != ESRCH && res != EPERM {
        return 39;
    }
    let len = cred(me, -1, gid, &mut ctl);
    if sys::sendmsg_full(a, None, &[b"5"], Some(&ctl[..len]), 0) != EINVAL {
        return 40;
    }
    ctl[..8].copy_from_slice(&(cmsg_len(8) as u64).to_le_bytes());
    if sys::sendmsg_full(a, None, &[b"5"], Some(&ctl[..cmsg_space(12)]), 0) != EINVAL {
        return 41;
    }
    // Longer than CMSG_LEN(12) is EINVAL too.
    let mut long = [0u8; 64];
    let len = cred(me, uid, gid, &mut long);
    long[..8].copy_from_slice(&(cmsg_len(16) as u64).to_le_bytes());
    if sys::sendmsg_full(a, None, &[b"5"], Some(&long[..len.max(cmsg_space(16))]), 0) != EINVAL {
        return 43;
    }
    // 5. A buffer with room for the header only: truncated to it,
    //    MSG_CTRUNC.
    sys::write(a, b"6");
    let mut hdr = [0u8; 16];
    let got = sys::recvmsg_full(b, &mut buf, None, Some(&mut hdr), 0);
    if got.result != 1 || got.flags & MSG_CTRUNC == 0 || got.controllen != 16 || word(&hdr, 0) != 16
    {
        return 42;
    }
    for fd in [a, b, r, w] {
        sys::close(fd);
    }
    0
}

fn sun(name: &[u8], out: &mut [u8; 110]) -> usize {
    out[..2].copy_from_slice(&(AF_UNIX as u16).to_le_bytes());
    out[2..2 + name.len()].copy_from_slice(name);
    2 + name.len()
}

fn datagrams() -> i32 {
    // 1. A datagram pair keeps message boundaries; SO_TYPE is SOCK_DGRAM
    //    (also for SOCK_RAW); a short buffer truncates, with MSG_TRUNC in
    //    msg_flags, and the rest is gone; MSG_TRUNC in the flags returns
    //    the whole length; an empty datagram is a message of 0 bytes.
    let Some((a, b)) = pair(DGRAM) else {
        return 50;
    };
    let raw = sys::socket(AF_UNIX, RAW, 0) as i32;
    if get_int(a, SO_TYPE) != Some(2) || get_int(raw, SO_TYPE) != Some(2) {
        return 51;
    }
    sys::close(raw);
    sys::write(a, b"one");
    sys::write(a, b"two");
    let mut buf = [0u8; 16];
    if sys::read(b, &mut buf) != 3 || sys::read(b, &mut buf) != 3 || &buf[..3] != b"two" {
        return 52;
    }
    sys::write(a, b"longer");
    let mut short = [0u8; 2];
    let got = sys::recvmsg_full(b, &mut short, None, None, 0);
    if got.result != 2 || got.flags & MSG_TRUNC as i32 == 0 {
        return 53;
    }
    if sys::recvfrom(b, &mut buf, MSG_DONTWAIT, None) != EAGAIN {
        return 54;
    }
    sys::write(a, b"whole");
    if sys::recvfrom(b, &mut short, MSG_TRUNC, None) != 5 {
        return 55;
    }
    sys::write(a, b"");
    if sys::recvfrom(b, &mut buf, MSG_DONTWAIT, None) != 0 {
        return 56;
    }
    // MSG_PEEK leaves the datagram for the next read.
    sys::write(a, b"peek");
    if sys::recvfrom(b, &mut buf, MSG_PEEK, None) != 4 || sys::read(b, &mut buf) != 4 {
        return 78;
    }
    if sys::recvfrom(b, &mut buf, MSG_DONTWAIT, None) != EAGAIN {
        return 79;
    }
    // FIONREAD is the next datagram's length; poll is readable, and an
    //    unconnected datagram socket is writable and not hung up.
    sys::write(a, b"abc");
    sys::write(a, b"de");
    let mut q = [0u8; 64];
    if sys::ioctl(b, FIONREAD, &mut q) != 0 || int(&q, 0) != 3 || ready(b, POLLIN) != POLLIN {
        return 57;
    }
    sys::read(b, &mut buf);
    sys::read(b, &mut buf);
    let u = sys::socket(AF_UNIX, DGRAM, 0) as i32;
    if ready(u, POLLIN | POLLOUT) != POLLOUT {
        return 58;
    }
    // 2. Named sockets: sendto an abstract name; recvfrom reports the
    //    sender's name, or nothing for an unnamed sender; no one there
    //    ECONNREFUSED; a stream socket's name EPROTOTYPE; no address and
    //    no peer ENOTCONN.
    let mut an = [0u8; 110];
    let alen = sun(b"\0scmprobe-dgram-a", &mut an);
    let mut bn = [0u8; 110];
    let blen = sun(b"\0scmprobe-dgram-b", &mut bn);
    let x = sys::socket(AF_UNIX, DGRAM, 0) as i32;
    let y = sys::socket(AF_UNIX, DGRAM, 0) as i32;
    if sys::bind(x, &an[..alen]) != 0 || sys::bind(y, &bn[..blen]) != 0 {
        return 59;
    }
    if sys::sendto(y, b"hi", 0, Some(&an[..alen])) != 2 {
        return 60;
    }
    let mut from = [0u8; 110];
    let mut flen = 110;
    if sys::recvfrom(x, &mut buf, 0, Some((&mut from, &mut flen))) != 2
        || flen as usize != blen
        || from[..blen] != bn[..blen]
    {
        return 61;
    }
    sys::sendto(u, b"anon", 0, Some(&an[..alen]));
    let mut flen = 110;
    if sys::recvfrom(x, &mut buf, 0, Some((&mut from, &mut flen))) != 4 || flen != 0 {
        return 62;
    }
    let mut none = [0u8; 110];
    let nlen = sun(b"\0scmprobe-nobody", &mut none);
    if sys::sendto(u, b"?", 0, Some(&none[..nlen])) != ECONNREFUSED
        || sys::write(u, b"?") != ENOTCONN
    {
        return 63;
    }
    // A stream socket's path name: EPROTOTYPE. Abstract names are per
    // type: a stream socket's is not seen (ECONNREFUSED), and a datagram
    // socket may hold the same one.
    let mut sn = [0u8; 110];
    let slen = sun(b"\0scmprobe-stream", &mut sn);
    let st = sys::socket(AF_UNIX, STREAM, 0) as i32;
    sys::bind(st, &sn[..slen]);
    sys::listen(st, 1);
    if sys::sendto(u, b"?", 0, Some(&sn[..slen])) != ECONNREFUSED {
        return 64;
    }
    let same = sys::socket(AF_UNIX, DGRAM, 0) as i32;
    if sys::bind(same, &sn[..slen]) != 0 {
        return 75;
    }
    sys::close(same);
    sys::close(st);
    let mut path = *b"/tmp/scmprobe-stream-path\0";
    let pid = sys::getpid() as u8;
    path[20] = b'a' + pid % 26;
    let cpath = core::ffi::CStr::from_bytes_until_nul(&path).unwrap_or(c"");
    sys::unlink(cpath);
    let mut pn = [0u8; 110];
    let plen = sun(&path[..path.len() - 1], &mut pn) + 1;
    let ps = sys::socket(AF_UNIX, STREAM, 0) as i32;
    if sys::bind(ps, &pn[..plen]) != 0 || sys::listen(ps, 1) != 0 {
        return 76;
    }
    if sys::sendto(u, b"?", 0, Some(&pn[..plen])) != EPROTOTYPE {
        return 77;
    }
    sys::close(ps);
    sys::unlink(cpath);
    // 3. connect sets the peer; then send needs no address. A socket
    //    connected to another takes nothing from a third: EPERM.
    if sys::connect(y, &an[..alen]) != 0 || sys::write(y, b"conn") != 4 {
        return 65;
    }
    sys::read(x, &mut buf);
    if sys::connect(x, &bn[..blen]) != 0 || sys::sendto(u, b"?", 0, Some(&an[..alen])) != EPERM {
        return 66;
    }
    // A datagram carries descriptors too.
    let (r, w) = pipe();
    send_fds(y, b"fd", &[w]);
    let mut c = [0u8; 64];
    let got = sys::recvmsg_full(x, &mut buf, None, Some(&mut c), 0);
    let (fds, n) = rights(&c, got.controllen);
    if got.result != 2 || n != 1 || sys::write(fds[0], b"!") != 1 || sys::read(r, &mut buf) != 1 {
        return 67;
    }
    sys::close(fds[0]);
    // 4. AF_UNSPEC disconnects: no peer (ENOTCONN).
    let mut unspec = [0u8; 16];
    if sys::connect(x, &unspec[..16]) != 0
        || sys::getname(x, &mut unspec, &mut 16, true) != ENOTCONN
    {
        return 68;
    }
    // 5. The peer gone: ECONNREFUSED, and the socket is unconnected after.
    sys::close(x);
    if sys::write(y, b"gone") != ECONNREFUSED || sys::write(y, b"gone") != ENOTCONN {
        return 69;
    }
    // 6. Too long for the send buffer: EMSGSIZE.
    let big = [0u8; 8192];
    set_int(y, SO_SNDBUF, 1);
    if sys::sendto(y, &big, 0, Some(&bn[..blen])) != EMSGSIZE {
        return 70;
    }
    // 7. A receiver's queue fills: a non-blocking sender gets EAGAIN.
    let mut full = false;
    for _ in 0..10_000 {
        let n = sys::sendto(u, b"q", MSG_DONTWAIT, Some(&bn[..blen]));
        if n == EAGAIN {
            full = true;
            break;
        }
        if n != 1 {
            return 71;
        }
    }
    if !full {
        return 72;
    }
    // 8. Shut for reading: a sender's EPIPE (no SIGPIPE: the default action
    //    would end this process); reading the empty socket is 0.
    let Some((d, e)) = pair(DGRAM) else {
        return 73;
    };
    let act = [0u8; 32];
    sys::rt_sigaction(SIGPIPE, Arg::Buf(&act), Out::Null, 8);
    sys::shutdown(e, SHUT_RD);
    if sys::write(d, b"x") != EPIPE || sys::read(e, &mut buf) != 0 {
        return 74;
    }
    let _ = (ENOENT, POLLHUP, SOCK_NONBLOCK);
    for fd in [a, b, u, y, d, e, r, w] {
        sys::close(fd);
    }
    0
}

fn main(_: &Startup) -> i32 {
    for part in [rights_part, credentials, datagrams] {
        let failed = part();
        if failed != 0 {
            return failed;
        }
    }
    sys::write(1, b"scmprobe: 70 checks passed\n");
    0
}

keel_rt::main!(main);
