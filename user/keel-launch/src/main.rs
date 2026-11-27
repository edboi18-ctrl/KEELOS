//! keel-launch: reads a compartment manifest and runs its application in
//! a compartment of its own (P3-S2, ADR 0040).
//!
//! Three ways to run it:
//! - **`keel-launch MANIFEST`**, the client: asks the launch service to
//!   run MANIFEST. It connects to [`SOCKET`], sends the manifest's
//!   absolute path with its own fds 0 to 2 (SCM_RIGHTS), and exits with
//!   the status the service sends back. It needs no factory, and has
//!   none: this is what a user at the shell runs.
//! - **`keel-launch --serve`**, the service: keel-init starts it with a
//!   restricted factory on fd 3 and the listening socket, already bound
//!   at [`SOCKET`], on fd 4. For each connection a worker (a forked child)
//!   reads the request and launches the manifest with the client's fds 0
//!   to 2 as the application's, and writes its errors to the client's
//!   fd 2.
//! - **`keel-launch --direct MANIFEST`**, with a factory on fd 3: launches
//!   it with this program's own fds 0 to 2 (`keel-init --launch`).
//!
//! A launch parses the manifest (`keel-manifest`), and only if all of it
//! is good: opens `[root] base` as a directory, the compartment's `/`;
//! creates the compartment with the manifest's limits; grants its
//! devices; spawns `exec` as its PID 1 with `exec` as argv[0], then
//! `args`, and the environment `env`; and waits until the compartment is
//! empty. The status is PID 1's exit code, or 128 plus the signal that
//! ended it (as a shell reports it); 2 for a bad manifest or a refused
//! step, which is named.
//!
//! Safe Rust on keel-rt, like keel-init.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_manifest::Manifest;
use keel_rt::Startup;
use keel_rt::sys::{self, Arg, Limits, Out};

const FACTORY: i32 = 3;
/// The service's listening socket, from keel-init.
const LISTENER: i32 = 4;
/// Where the service listens: in the system tree only, so only the
/// system compartment (keel-init, the shell and what they run) can ask.
pub const SOCKET: &CStr = c"/run/keel-launch.sock";
const O_DIRECTORY: u64 = 0o200000;
const AF_UNIX: i32 = 1;
const SOCK_STREAM: u32 = 1;
const SOCK_CLOEXEC: u32 = 0o2000000;
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const SHUT_WR: i32 = 1;
const SIGCHLD: i32 = 17;
const EINTR: i64 = -4;
/// The longest manifest path a request may carry.
const MAX_PATH: usize = 4096;

/// Writes `keel-launch: ` and `parts` to `fd`.
fn say_to(fd: i32, parts: &[&[u8]]) {
    let mut line = [0u8; 512];
    let mut len = 0;
    for p in [&b"keel-launch: "[..]].iter().chain(parts) {
        let n = p.len().min(line.len() - len);
        line[len..len + n].copy_from_slice(&p[..n]);
        len += n;
    }
    sys::write(fd, &line[..len]);
}

fn decimal(value: i64, out: &mut [u8; 20]) -> &[u8] {
    let mut at = out.len();
    let mut rest = value.unsigned_abs();
    loop {
        at -= 1;
        out[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    if value < 0 {
        at -= 1;
        out[at] = b'-';
    }
    &out[at..]
}

/// Fails a step: names it and the error on `err`; status 2.
fn refused(err: i32, step: &[u8], errno: i64) -> i32 {
    let mut d = [0u8; 20];
    say_to(err, &[step, b": error ", decimal(errno, &mut d), b"\n"]);
    2
}

/// NUL-terminated copies of strings, for the calls.
struct CStrings {
    buf: [u8; 8192],
    used: usize,
    ends: [usize; 72],
    count: usize,
}

impl CStrings {
    fn new() -> Self {
        CStrings {
            buf: [0; 8192],
            used: 0,
            ends: [0; 72],
            count: 0,
        }
    }

    fn push(&mut self, s: &[u8]) -> Option<()> {
        let end = self.used + s.len();
        if end >= self.buf.len() || self.count == self.ends.len() || s.contains(&0) {
            return None;
        }
        self.buf[self.used..end].copy_from_slice(s);
        self.buf[end] = 0;
        self.used = end + 1;
        self.ends[self.count] = self.used;
        self.count += 1;
        Some(())
    }

    fn get(&self, i: usize) -> &CStr {
        let start = if i == 0 { 0 } else { self.ends[i - 1] };
        CStr::from_bytes_until_nul(&self.buf[start..self.ends[i]]).unwrap_or(c"")
    }
}

/// Reads and parses the manifest at `path`; errors go to `err`.
fn load(path: &[u8], err: i32) -> Result<Manifest, i32> {
    let mut name = [0u8; MAX_PATH + 1];
    if path.len() > MAX_PATH || path.contains(&0) {
        say_to(err, &[b"manifest path too long\n"]);
        return Err(2);
    }
    name[..path.len()].copy_from_slice(path);
    let cpath = CStr::from_bytes_until_nul(&name[..=path.len()]).unwrap_or(c"");
    let fd = sys::open(cpath, sys::O_RDONLY, 0);
    if fd < 0 {
        return Err(refused(err, b"reading the manifest", fd));
    }
    let mut buf = [0u8; keel_manifest::MAX_MANIFEST + 1];
    let mut len = 0;
    loop {
        if len == buf.len() {
            break;
        }
        let n = sys::read(fd as i32, &mut buf[len..]);
        if n < 0 {
            sys::close(fd as i32);
            return Err(refused(err, b"reading the manifest", n));
        }
        if n == 0 {
            break;
        }
        len += n as usize;
    }
    sys::close(fd as i32);
    keel_manifest::parse(&buf[..len]).map_err(|e| {
        let mut d = [0u8; 20];
        say_to(
            err,
            &[
                path,
                b":",
                decimal(e.line as i64, &mut d),
                b": ",
                e.what.as_bytes(),
                b"\n",
            ],
        );
        2
    })
}

/// Runs `m` in a new compartment with `stdio` as its PID 1's fds 0 to 2;
/// errors go to `err`. Its status, as a shell reports it.
fn launch(m: &Manifest, stdio: [i32; 3], err: i32) -> i32 {
    let mut strings = CStrings::new();
    // 0: root, 1: exec (also argv[0]), then the arguments, then the
    // environment.
    let pushed = strings.push(m.root()).is_some()
        && strings.push(m.exec()).is_some()
        && m.args().all(|a| strings.push(a).is_some());
    let nargs = strings.count - 1;
    if !pushed || !m.env().all(|e| strings.push(e).is_some()) {
        say_to(err, &[b"too many or too long arguments and environment\n"]);
        return 2;
    }
    let root = sys::open(strings.get(0), sys::O_RDONLY | O_DIRECTORY, 0);
    if root < 0 {
        return refused(err, b"opening the root", root);
    }
    let l = m.limits;
    let limits = Limits {
        processes: l.processes,
        memory_bytes: l.memory_mb << 20,
        tmpfs_bytes: l.tmpfs_mb << 20,
        tmpfs_nodes: l.tmpfs_nodes,
    };
    let c = sys::compartment_create(FACTORY, root as i32, &limits.bytes());
    sys::close(root as i32);
    if c < 0 {
        return refused(err, b"creating the compartment", c);
    }
    let c = c as i32;
    for device in m.devices() {
        let r = sys::compartment_grant_device(c, device.code());
        if r < 0 {
            return refused(err, b"granting a device", r);
        }
    }
    let mut argv = [c""; 64];
    for (i, slot) in argv.iter_mut().enumerate().take(nargs) {
        *slot = strings.get(1 + i);
    }
    let mut envp = [c""; 64];
    let nenv = strings.count - 1 - nargs;
    for (i, slot) in envp.iter_mut().enumerate().take(nenv) {
        *slot = strings.get(1 + nargs + i);
    }
    let pid = sys::compartment_spawn(c, strings.get(1), &argv[..nargs], &envp[..nenv], stdio);
    if pid < 0 {
        return refused(err, b"starting the program", pid);
    }
    let status = match sys::compartment_wait(c, 0) {
        Ok(usage) if usage.status >= 0 => {
            let raw = usage.status;
            if raw & 0x7f == 0 {
                (raw >> 8) & 0xff
            } else {
                128 + (raw & 0x7f)
            }
        }
        Ok(_) => 2,
        Err(e) => refused(err, b"waiting", e),
    };
    sys::close(c);
    status
}

/// A `sockaddr_un` for [`SOCKET`] and its length.
fn address() -> ([u8; 110], usize) {
    let mut a = [0u8; 110];
    a[..2].copy_from_slice(&(AF_UNIX as u16).to_le_bytes());
    let path = SOCKET.to_bytes_with_nul();
    a[2..2 + path.len()].copy_from_slice(path);
    (a, 2 + path.len())
}

/// The client: asks the service to launch `manifest`.
fn client(manifest: &[u8]) -> i32 {
    // The service reads the path in its own tree: make it absolute.
    let mut path = [0u8; MAX_PATH];
    let mut len = 0;
    if manifest.first() != Some(&b'/') {
        let n = sys::getcwd(&mut path);
        if n <= 0 {
            say_to(2, &[b"no working directory\n"]);
            return 2;
        }
        len = path.iter().position(|&b| b == 0).unwrap_or(0);
        if len > 1 {
            path[len] = b'/';
            len += 1;
        }
    }
    if len + manifest.len() > path.len() {
        say_to(2, &[b"manifest path too long\n"]);
        return 2;
    }
    path[len..len + manifest.len()].copy_from_slice(manifest);
    len += manifest.len();
    let s = sys::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if s < 0 {
        return refused(2, b"socket", s);
    }
    let s = s as i32;
    let (addr, alen) = address();
    let r = sys::connect(s, &addr[..alen]);
    if r < 0 {
        return refused(2, b"the launch service is not running (connect)", r);
    }
    // SCM_RIGHTS with fds 0, 1 and 2: cmsg_len CMSG_LEN(12) = 28, the
    // buffer CMSG_SPACE(12) = 32 (cmsg(3), x86-64).
    let mut control = [0u8; 32];
    control[0..8].copy_from_slice(&28u64.to_le_bytes());
    control[8..12].copy_from_slice(&SOL_SOCKET.to_le_bytes());
    control[12..16].copy_from_slice(&SCM_RIGHTS.to_le_bytes());
    for fd in 0..3i32 {
        let at = 16 + fd as usize * 4;
        control[at..at + 4].copy_from_slice(&fd.to_le_bytes());
    }
    let sent = sys::sendmsg_full(s, None, &[&path[..len]], Some(&control), 0);
    if sent != len as i64 {
        return refused(2, b"sending the request", sent);
    }
    sys::shutdown(s, SHUT_WR);
    let mut status = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = sys::read(s, &mut status[got..]);
        if n == EINTR {
            continue;
        }
        if n <= 0 {
            say_to(2, &[b"the launch service gave no status\n"]);
            return 2;
        }
        got += n as usize;
    }
    i32::from_le_bytes(status)
}

/// A worker: one request on connection `c`.
fn worker(c: i32) -> i32 {
    let mut path = [0u8; MAX_PATH + 1];
    let mut control = [0u8; 64];
    let first = sys::recvmsg_full(c, &mut path[..MAX_PATH], None, Some(&mut control), 0);
    // The three descriptors, and nothing else.
    let fds_ok = first.result >= 0
        && first.controllen == 32
        && u64::from_le_bytes(control[0..8].try_into().unwrap_or([0; 8])) == 28
        && i32::from_le_bytes(control[8..12].try_into().unwrap_or([0; 4])) == SOL_SOCKET
        && i32::from_le_bytes(control[12..16].try_into().unwrap_or([0; 4])) == SCM_RIGHTS;
    if !fds_ok {
        return 1;
    }
    let fd =
        |i: usize| i32::from_le_bytes(control[16 + i * 4..20 + i * 4].try_into().unwrap_or([0; 4]));
    let stdio = [fd(0), fd(1), fd(2)];
    let mut len = first.result as usize;
    while len < MAX_PATH {
        let n = sys::read(c, &mut path[len..MAX_PATH]);
        if n <= 0 {
            break;
        }
        len += n as usize;
    }
    let status = if path[..len].first() != Some(&b'/') {
        say_to(stdio[2], &[b"the manifest path must be absolute\n"]);
        2
    } else {
        match load(&path[..len], stdio[2]) {
            Ok(m) => launch(&m, stdio, stdio[2]),
            Err(status) => status,
        }
    };
    sys::write(c, &status.to_le_bytes());
    0
}

/// The service: one worker per connection, reaped by the kernel (SIGCHLD
/// ignored: no zombies).
fn serve() -> i32 {
    // struct sigaction: handler SIG_IGN (1), flags, restorer, mask.
    let mut ignore = [0u8; 32];
    ignore[0] = 1;
    sys::rt_sigaction(SIGCHLD, Arg::Buf(&ignore), Out::Null, 8);
    say_to(2, &[b"serving on ", SOCKET.to_bytes(), b"\n"]);
    loop {
        let c = sys::accept4(LISTENER, None, SOCK_CLOEXEC);
        if c == EINTR {
            continue;
        }
        if c < 0 {
            return refused(2, b"accept", c);
        }
        let pid = sys::fork();
        if pid == 0 {
            sys::close(LISTENER);
            keel_rt::exit(worker(c as i32));
        }
        sys::close(c as i32);
    }
}

fn main(startup: &Startup) -> i32 {
    let mut args = startup.args().skip(1);
    match (args.next(), args.next(), args.next()) {
        (Some(b"--serve"), None, None) => serve(),
        (Some(b"--direct"), Some(path), None) => match load(path, 2) {
            Ok(m) => launch(&m, [0, 1, 2], 2),
            Err(status) => status,
        },
        (Some(path), None, None) if !path.starts_with(b"--") => client(path),
        _ => {
            say_to(
                2,
                &[b"usage: keel-launch MANIFEST | --serve | --direct MANIFEST\n"],
            );
            2
        }
    }
}

keel_rt::main!(main);
