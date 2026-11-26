//! FIFOs and mknod(2), checked against Linux (ADR 0035). Runs under Linux
//! (`host.fifoprobe`) and on Keel (`exec.fifos`) and must pass on both.
//!
//! Semantics from mknod(2), fifo(7), pipe(7), open(2) and Linux v6.12's
//! `fs/namei.c` (`may_mknod`, `do_mknodat`, `filename_create`) and
//! `fs/pipe.c` (`fifo_open`, `wait_for_partner`, `pipe_poll`). It works
//! in a directory of its own under /tmp, and sets its umask first.
//! Device nodes are not checked: Linux lets root make them (CAP_MKNOD),
//! Keel does not.
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_RDONLY, O_RDWR, O_WRONLY};

const EINTR: i64 = -4;
const ENOENT: i64 = -2;
const ENXIO: i64 = -6;
const EAGAIN: i64 = -11;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const EPERM: i64 = -1;
const ESPIPE: i64 = -29;

const O_NONBLOCK: u64 = 0o4000;
const S_IFMT: u32 = 0o170000;
const S_IFIFO: u32 = 0o010000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFSOCK: u32 = 0o140000;
const POLLIN: u16 = 1;
const POLLHUP: u16 = 0x10;
const EPOLLIN: u32 = 1;
const EPOLLET: u32 = 1 << 31;
const SIGUSR1: i32 = 10;
const MS: i64 = 1_000_000;

fn now() -> i64 {
    let mut b = [0u8; 16];
    sys::clock_gettime(1, &mut b);
    let sec = i64::from_le_bytes(b[..8].try_into().unwrap_or_default());
    let nsec = i64::from_le_bytes(b[8..].try_into().unwrap_or_default());
    sec * 1_000_000_000 + nsec
}

fn nap(ms: i32) {
    sys::poll(&mut [], ms);
}

/// A path in the probe's directory, NUL-terminated.
struct Path {
    buf: [u8; 128],
    len: usize,
}

impl Path {
    fn new(dir: &[u8], name: &[u8]) -> Self {
        let mut p = Path {
            buf: [0; 128],
            len: 0,
        };
        p.put(dir);
        if !name.is_empty() {
            p.put(b"/");
            p.put(name);
        }
        p
    }

    fn put(&mut self, b: &[u8]) {
        let n = b.len().min(self.buf.len() - 1 - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
    }

    fn c(&self) -> &CStr {
        CStr::from_bytes_until_nul(&self.buf[..=self.len]).unwrap_or(c"")
    }
}

fn mode_of(path: &CStr) -> Option<(u32, u64, u64)> {
    let mut st = [0u8; 144];
    if sys::stat(path, &mut st) != 0 {
        return None;
    }
    let mode = u32::from_le_bytes(st[24..28].try_into().unwrap_or_default());
    let ino = u64::from_le_bytes(st[8..16].try_into().unwrap_or_default());
    let size = u64::from_le_bytes(st[48..56].try_into().unwrap_or_default());
    Some((mode, ino, size))
}

fn fd_ino(fd: i32) -> Option<(u32, u64)> {
    let mut st = [0u8; 144];
    if sys::fstat(fd, &mut st) != 0 {
        return None;
    }
    let mode = u32::from_le_bytes(st[24..28].try_into().unwrap_or_default());
    let ino = u64::from_le_bytes(st[8..16].try_into().unwrap_or_default());
    Some((mode, ino))
}

fn revents(fd: i32) -> u16 {
    let mut e = [0u8; 8];
    e[..4].copy_from_slice(&fd.to_le_bytes());
    e[4..6].copy_from_slice(&(POLLIN | POLLHUP).to_le_bytes());
    let mut fds = [e];
    sys::poll(&mut fds, 0);
    u16::from_le_bytes([fds[0][6], fds[0][7]])
}

fn open(path: &CStr, flags: u64) -> i64 {
    sys::open(path, flags, 0)
}

fn spawn(body: impl FnOnce() -> i32) -> i32 {
    let child = sys::fork();
    if child == 0 {
        keel_rt::exit(body());
    }
    child as i32
}

fn exit_code(pid: i32) -> i32 {
    let mut status = 0;
    if sys::wait4(pid, &mut status, 0) != i64::from(pid) {
        return 2000;
    }
    if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        1000 + (status & 0x7f)
    }
}

fn checks(dir: &[u8]) -> i32 {
    let fifo = Path::new(dir, b"f");
    let f = fifo.c();
    // 1. mknod with S_IFIFO makes a FIFO: its mode is the request less the
    //    umask (022 here), size 0.
    if sys::mknod(f, S_IFIFO | 0o666, 0) != 0 {
        return 1;
    }
    let Some((mode, ino, size)) = mode_of(f) else {
        return 1;
    };
    if mode != S_IFIFO | 0o644 || size != 0 {
        return 1;
    }
    // 2. The refusals, in `do_mknodat`'s order: a directory's type EPERM
    //    and an unknown type EINVAL (before the name is looked at); a
    //    name that exists EEXIST; with a trailing slash, EEXIST if it
    //    exists, ENOENT if not.
    let missing_slash = Path::new(dir, b"none/");
    let f_slash = Path::new(dir, b"f/");
    if sys::mknod(f, S_IFDIR | 0o755, 0) != EPERM
        || sys::mknod(f, 0o150000 | 0o644, 0) != EINVAL
        || sys::mknod(f, S_IFIFO | 0o644, 0) != EEXIST
        || sys::mknod(f_slash.c(), S_IFIFO | 0o644, 0) != EEXIST
        || sys::mknod(missing_slash.c(), S_IFIFO | 0o644, 0) != ENOENT
    {
        return 2;
    }
    // 3. Type 0 and S_IFREG make a regular file; S_IFSOCK a socket node,
    //    which open(2) cannot open (ENXIO); mknodat takes a directory.
    let regular = Path::new(dir, b"r");
    let zero = Path::new(dir, b"z");
    let sock = Path::new(dir, b"s");
    let dfd = sys::open(Path::new(dir, b"").c(), O_RDONLY, 0);
    if sys::mknod(regular.c(), S_IFREG | 0o600, 0) != 0
        || mode_of(regular.c()).map(|m| m.0) != Some(S_IFREG | 0o600)
        || sys::mknodat(dfd as i32, c"z", 0o640, 0) != 0
        || mode_of(zero.c()).map(|m| m.0) != Some(S_IFREG | 0o640)
        || sys::mknodat(AT_FDCWD, sock.c(), S_IFSOCK | 0o777, 0) != 0
        || mode_of(sock.c()).map(|m| m.0 & S_IFMT) != Some(S_IFSOCK)
        || open(sock.c(), O_RDWR) != ENXIO
    {
        return 3;
    }
    sys::close(dfd as i32);
    // 4. A nonblocking reader opens at once with no writer: read is end of
    //    file, and POLLHUP is not reported before any writer has come
    //    (`f_pipe`). A nonblocking writer then opens: data goes through.
    //    The writer gone, the reader sees POLLHUP and end of file.
    let r = open(f, O_RDONLY | O_NONBLOCK) as i32;
    let mut b = [0u8; 8];
    if r < 0 || sys::read(r, &mut b) != 0 || revents(r) & POLLHUP != 0 {
        return 4;
    }
    let w = open(f, O_WRONLY | O_NONBLOCK) as i32;
    if w < 0 || sys::write(w, b"ab") != 2 || revents(r) & POLLIN == 0 {
        return 5;
    }
    if sys::read(r, &mut b) != 2 || &b[..2] != b"ab" {
        return 5;
    }
    // stat of the open FIFO is its node; lseek is ESPIPE.
    if fd_ino(r) != Some((S_IFIFO | 0o644, ino)) || sys::lseek(r, 0, 0) != ESPIPE {
        return 6;
    }
    sys::close(w);
    if revents(r) & POLLHUP == 0 || sys::read(r, &mut b) != 0 {
        return 7;
    }
    sys::close(r);
    // 5. A nonblocking writer with no reader: ENXIO.
    if open(f, O_WRONLY | O_NONBLOCK) != ENXIO {
        return 8;
    }
    // 6. A blocking reader waits for a writer to open; a blocking writer
    //    for a reader.
    for reader_first in [true, false] {
        let child = spawn(move || {
            nap(100);
            let fd = if reader_first {
                open(f, O_WRONLY)
            } else {
                open(f, O_RDONLY)
            };
            if fd < 0 {
                return 1;
            }
            if reader_first {
                sys::write(fd as i32, b"x");
            } else {
                let mut b = [0u8; 1];
                if sys::read(fd as i32, &mut b) != 1 || b[0] != b'y' {
                    return 2;
                }
            }
            0
        });
        let t0 = now();
        let fd = if reader_first {
            open(f, O_RDONLY)
        } else {
            open(f, O_WRONLY)
        };
        if fd < 0 || now() - t0 < 90 * MS {
            return 9;
        }
        if reader_first {
            let mut b = [0u8; 1];
            if sys::read(fd as i32, &mut b) != 1 || b[0] != b'x' {
                return 10;
            }
        } else if sys::write(fd as i32, b"y") != 1 {
            return 10;
        }
        if exit_code(child) != 0 {
            return 10;
        }
        sys::close(fd as i32);
    }
    // 7. O_RDWR never waits: it is a reader and a writer itself.
    let rw = open(f, O_RDWR) as i32;
    if rw < 0 || sys::write(rw, b"zz") != 2 || sys::read(rw, &mut b) != 2 {
        return 11;
    }
    // 8. The data goes with the last open: written, closed, and reopened,
    //    the FIFO is empty.
    sys::write(rw, b"qq");
    sys::close(rw);
    let rw = open(f, O_RDWR | O_NONBLOCK) as i32;
    if rw < 0 || sys::read(rw, &mut b) != EAGAIN {
        return 12;
    }
    // 9. An O_RDWR end is in epoll for reading too: edge-triggered, a
    //    write through another descriptor makes it ready (its readers'
    //    queue is woken).
    let ep = sys::epoll_create1(None, 1) as i32;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&(EPOLLIN | EPOLLET).to_le_bytes());
    if ep < 0 || sys::epoll_ctl(ep, 1, rw, Some(&ev)) != 0 {
        return 13;
    }
    let mut out = [[0u8; 12]; 2];
    let before = sys::epoll_wait(ep, &mut out, 0);
    let w = open(f, O_WRONLY | O_NONBLOCK) as i32;
    sys::write(w, b"e");
    let after = sys::epoll_wait(ep, &mut out, 0);
    if before != 0
        || after != 1
        || u32::from_le_bytes(out[0][..4].try_into().unwrap_or_default()) & EPOLLIN == 0
    {
        return 13;
    }
    sys::close(w);
    sys::close(ep);
    sys::close(rw);
    // 10. A blocking open a signal interrupts is EINTR (ERESTARTSYS, its
    //     handler without SA_RESTART), and takes its reader back. The pipe
    //     is kept alive meanwhile by a nonblocking reader, R0, and then a
    //     nonblocking writer, W. Once R0 is closed no reader is left, so
    //     W's write is EPIPE (SIGPIPE ignored); a reader the interrupted
    //     open left behind would let it through.
    const SIGPIPE: i32 = 13;
    const EPIPE: i64 = -32;
    let mut ignore = [0u8; 32];
    ignore[..8].copy_from_slice(&1u64.to_le_bytes());
    sys::rt_sigaction(SIGPIPE, sys::Arg::Buf(&ignore), sys::Out::Null, 8);
    keel_rt::signal::catch(SIGUSR1);
    let me = sys::getpid() as i32;
    let r0 = open(f, O_RDONLY | O_NONBLOCK) as i32;
    let sender = spawn(move || {
        nap(100);
        sys::kill(me, SIGUSR1);
        0
    });
    if r0 < 0 || open(f, O_RDONLY) != EINTR || exit_code(sender) != 0 {
        return 14;
    }
    let w = open(f, O_WRONLY | O_NONBLOCK) as i32;
    sys::close(r0);
    if w < 0 || sys::write(w, b"p") != EPIPE {
        return 15;
    }
    sys::close(w);
    // 11. Unlinked while open, the FIFO still works.
    let rw = open(f, O_RDWR) as i32;
    if rw < 0 || sys::unlink(f) != 0 || sys::write(rw, b"u") != 1 || sys::read(rw, &mut b) != 1 {
        return 16;
    }
    sys::close(rw);
    0
}

fn main(_: &Startup) -> i32 {
    sys::umask(0o022);
    let mut dir = Path::new(b"/tmp/keel-fifoprobe-", b"");
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    let mut pid = sys::getpid() as u64;
    loop {
        at -= 1;
        digits[at] = b'0' + (pid % 10) as u8;
        pid /= 10;
        if pid == 0 {
            break;
        }
    }
    dir.put(&digits[at..]);
    let name = &dir.buf[..dir.len];
    if sys::mkdir(dir.c(), 0o700) != 0 {
        return 100;
    }
    let result = checks(name);
    for leaf in [&b"f"[..], b"r", b"z", b"s"] {
        sys::unlink(Path::new(name, leaf).c());
    }
    sys::rmdir(dir.c());
    if result == 0 {
        sys::write(1, b"fifoprobe: 16 checks passed\n");
    }
    result
}

keel_rt::main!(main);
