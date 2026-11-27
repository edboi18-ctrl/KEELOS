//! keel-launch: reads a compartment manifest and runs its application in
//! a compartment of its own (P3-S2, ADR 0040).
//!
//! `keel-launch MANIFEST`, with a factory on fd 3 (keel-init gives it
//! one, restricted so it cannot be copied on). It parses the manifest
//! (`keel-manifest`), and only if all of it is good:
//! 1. opens `[root] base` as a directory, the compartment's `/`;
//! 2. creates the compartment with the manifest's limits;
//! 3. grants its devices;
//! 4. spawns `exec` as its PID 1 with `exec` as argv[0], then `args`, the
//!    environment `env`, and this program's fds 0 to 2;
//! 5. waits until the compartment is empty.
//!
//! It exits with PID 1's exit code, or 128 plus the signal that ended it
//! (as a shell reports it); with 2 for a bad manifest or a refused step,
//! naming it on standard error.
//!
//! Safe Rust on keel-rt, like keel-init.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_manifest::Manifest;
use keel_rt::Startup;
use keel_rt::sys::{self, Limits};

const FACTORY: i32 = 3;
const O_DIRECTORY: u64 = 0o200000;

fn say(parts: &[&[u8]]) {
    let mut line = [0u8; 512];
    let mut len = 0;
    for p in [&b"keel-launch: "[..]].iter().chain(parts) {
        let n = p.len().min(line.len() - len);
        line[len..len + n].copy_from_slice(&p[..n]);
        len += n;
    }
    sys::write(2, &line[..len]);
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

/// Fails a step: names it and the error, exits 2.
fn refused(step: &[u8], errno: i64) -> i32 {
    let mut d = [0u8; 20];
    say(&[step, b": error ", decimal(errno, &mut d), b"\n"]);
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

/// The manifest file's bytes.
fn read_manifest(path: &CStr, buf: &mut [u8]) -> Result<usize, i64> {
    let fd = sys::open(path, sys::O_RDONLY, 0);
    if fd < 0 {
        return Err(fd);
    }
    let mut len = 0;
    loop {
        if len == buf.len() {
            sys::close(fd as i32);
            return Err(-27); // EFBIG: over MAX_MANIFEST
        }
        let n = sys::read(fd as i32, &mut buf[len..]);
        if n < 0 {
            sys::close(fd as i32);
            return Err(n);
        }
        if n == 0 {
            break;
        }
        len += n as usize;
    }
    sys::close(fd as i32);
    Ok(len)
}

fn launch(m: &Manifest) -> i32 {
    let mut strings = CStrings::new();
    // 0: root, 1: exec (also argv[0]), then the arguments, then the
    // environment.
    let pushed = strings.push(m.root()).is_some()
        && strings.push(m.exec()).is_some()
        && m.args().all(|a| strings.push(a).is_some());
    let nargs = strings.count - 1;
    if !pushed || !m.env().all(|e| strings.push(e).is_some()) {
        say(&[b"too many or too long arguments and environment\n"]);
        return 2;
    }
    let root = sys::open(strings.get(0), sys::O_RDONLY | O_DIRECTORY, 0);
    if root < 0 {
        return refused(b"opening the root", root);
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
        return refused(b"creating the compartment", c);
    }
    let c = c as i32;
    for device in m.devices() {
        let r = sys::compartment_grant_device(c, device.code());
        if r < 0 {
            return refused(b"granting a device", r);
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
    let pid = sys::compartment_spawn(c, strings.get(1), &argv[..nargs], &envp[..nenv], [0, 1, 2]);
    if pid < 0 {
        return refused(b"starting the program", pid);
    }
    match sys::compartment_wait(c, 0) {
        Ok(usage) if usage.status >= 0 => {
            let raw = usage.status;
            if raw & 0x7f == 0 {
                (raw >> 8) & 0xff
            } else {
                128 + (raw & 0x7f)
            }
        }
        Ok(_) => 2,
        Err(e) => refused(b"waiting", e),
    }
}

fn main(startup: &Startup) -> i32 {
    let mut args = startup.args().skip(1);
    let (Some(path), None) = (args.next(), args.next()) else {
        say(&[b"usage: keel-launch MANIFEST\n"]);
        return 2;
    };
    let mut name = [0u8; 512];
    if path.len() >= name.len() || path.contains(&0) {
        say(&[b"manifest path too long\n"]);
        return 2;
    }
    name[..path.len()].copy_from_slice(path);
    let cpath = CStr::from_bytes_until_nul(&name[..=path.len()]).unwrap_or(c"");
    let mut buf = [0u8; keel_manifest::MAX_MANIFEST];
    let len = match read_manifest(cpath, &mut buf) {
        Ok(n) => n,
        Err(e) => return refused(b"reading the manifest", e),
    };
    match keel_manifest::parse(&buf[..len]) {
        Ok(m) => launch(&m),
        Err(e) => {
            let mut d = [0u8; 20];
            say(&[
                path,
                b":",
                decimal(e.line as i64, &mut d),
                b": ",
                e.what.as_bytes(),
                b"\n",
            ]);
            2
        }
    }
}

keel_rt::main!(main);
