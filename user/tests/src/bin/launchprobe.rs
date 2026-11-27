//! The native launch interface (P3-S2, ADR 0040), on Keel only: Linux has
//! no such calls. The kernel's self-test (`exec.launch`) runs it with a
//! factory on fd 3, as keel-init gets one.
//!
//! The compartments it makes are rooted in a directory of its own under
//! /tmp, holding `/prog` (this program, linked) and `/dev`. Run as `/prog
//! child MODE` inside one, it checks what a confined process sees and
//! exits with a code the parent checks.
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, Limits};

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EEXIST: i64 = -17;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;
const O_DIRECTORY: u64 = 0o200000;
const SIGKILL: i32 = 9;
const FACTORY: i32 = 3;

// Rights (ADR 0040, keel_core::handle::Rights).
const CREATE: u64 = 1 << 6;
const DUPLICATE: u64 = 1 << 10;
const STAT: u64 = 1 << 4;

struct Buf<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> Buf<N> {
    const fn new() -> Self {
        Self {
            data: [0; N],
            len: 0,
        }
    }

    fn put(&mut self, b: &[u8]) -> &mut Self {
        let n = b.len().min(N - 1 - self.len);
        self.data[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        self
    }

    fn num(&mut self, mut v: u64) -> &mut Self {
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        loop {
            at -= 1;
            digits[at] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&digits[at..])
    }

    fn c(&mut self) -> &CStr {
        self.data[self.len] = 0;
        CStr::from_bytes_until_nul(&self.data[..=self.len]).unwrap_or(c"")
    }
}

/// Child mode: what a process in a compartment sees.
fn child(mode: &[u8]) -> i32 {
    match mode {
        // It is PID 1, has fds 1 and 2 only (0 was given as -1), no
        // factory, sees only its own tree, and cannot use the native
        // calls without a handle.
        b"look" => {
            let mut st = [0u8; 144];
            if sys::getpid() != 1 {
                return 51;
            }
            if sys::fstat(0, &mut st) != EBADF || sys::fstat(1, &mut st) != 0 {
                return 52;
            }
            if sys::fstat(FACTORY, &mut st) != EBADF {
                return 53;
            }
            let limits = Limits::UNLIMITED.bytes();
            if sys::compartment_create(FACTORY, 1, &limits) != EBADF
                || sys::factory_derive(1, &limits) != EBADF
            {
                return 54;
            }
            if sys::open(c"/test/launchprobe", sys::O_RDONLY, 0) != ENOENT
                || sys::open(c"/../../test", sys::O_RDONLY, 0) != ENOENT
            {
                return 55;
            }
            if sys::open(c"/dev/null", sys::O_RDWR, 0) < 0 {
                return 56;
            }
            sys::write(1, b"child: confined\n");
            42
        }
        // Started by keel-launch from a manifest (`launch.manifest`): PID
        // 1, keel-launch's stdio, no factory, /dev/null granted and
        // /dev/zero not, the manifest's environment, nothing outside.
        b"manifest" => {
            let mut st = [0u8; 144];
            if sys::getpid() != 1
                || sys::fstat(1, &mut st) != 0
                || sys::fstat(FACTORY, &mut st) != EBADF
            {
                return 61;
            }
            if sys::open(c"/dev/null", sys::O_RDWR, 0) < 0
                || sys::open(c"/dev/zero", sys::O_RDONLY, 0) != ENOENT
                || sys::open(c"/test/launchprobe", sys::O_RDONLY, 0) != ENOENT
            {
                return 62;
            }
            if !ENV_SEEN.load(core::sync::atomic::Ordering::Relaxed) {
                return 63;
            }
            sys::write(1, b"manifest: hello\n");
            43
        }
        // Run as keel-init's shell while the launch service runs
        // (`launch.service`): it has no factory on fd 3 or anywhere else
        // that it could use.
        b"nofactory" => {
            let mut st = [0u8; 144];
            let limits = Limits::UNLIMITED.bytes();
            if sys::fstat(FACTORY, &mut st) != EBADF {
                return 71;
            }
            for fd in 0..64 {
                if sys::compartment_create(fd, 0, &limits) != EBADF {
                    return 72;
                }
            }
            44
        }
        // Run as keel-init's shell with the launch service: runs the
        // client, `keel-launch /launch-test/good.toml`, with its standard
        // output on a pipe. The program in the compartment writes there,
        // through the client's descriptor the service was given (45).
        b"viaservice" => {
            let mut out = [-1i32; 2];
            if sys::pipe2(&mut out, None) != 0 {
                return 81;
            }
            let pid = sys::fork();
            if pid == 0 {
                sys::dup2(out[1], 1);
                sys::close(out[0]);
                sys::close(out[1]);
                sys::execve(
                    c"/sbin/keel-launch",
                    Some(&[c"keel-launch", c"/launch-test/good.toml"]),
                    &[],
                );
                keel_rt::exit(82);
            }
            sys::close(out[1]);
            let mut line = [0u8; 64];
            let mut got = 0;
            loop {
                let n = sys::read(out[0], &mut line[got..]);
                if n <= 0 {
                    break;
                }
                got += n as usize;
            }
            let mut status = 0;
            if sys::wait4(pid as i32, &mut status, 0) != pid || (status >> 8) & 0xff != 43 {
                return 83;
            }
            if line[..got] != *b"manifest: hello\n" {
                return 84;
            }
            45
        }
        // Waits to be killed.
        b"sleep" => loop {
            let ts = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            sys::nanosleep(&ts, None);
        },
        // Forks against a limit of one process: EAGAIN.
        b"fork" => {
            if sys::fork() == EAGAIN {
                7
            } else {
                8
            }
        }
        _ => 99,
    }
}

fn path(dir: &Buf<128>, tail: &[u8]) -> Buf<128> {
    let mut p = Buf::new();
    p.put(&dir.data[..dir.len]).put(tail);
    p
}

/// A compartment root under `dir`: `/prog` (this program) and, if `dev`,
/// an empty `/dev`. Returns a directory descriptor for it.
fn make_root(dir: &Buf<128>, me: &CStr, dev: bool) -> i64 {
    if sys::mkdir(path(dir, b"").c(), 0o755) != 0
        || sys::link(me, path(dir, b"/prog").c()) != 0
        || (dev && sys::mkdir(path(dir, b"/dev").c(), 0o755) != 0)
    {
        return -1;
    }
    sys::open(path(dir, b"").c(), sys::O_RDONLY | O_DIRECTORY, 0)
}

fn checks(base: &Buf<128>, me: &CStr) -> i32 {
    let limits = Limits {
        processes: 16,
        memory_bytes: 64 << 20,
        tmpfs_bytes: 1 << 20,
        tmpfs_nodes: 64,
    };
    // 1. No such call past the last; a handle that is no factory EBADF.
    if sys::native_raw(7, 0, 0, 0) != ENOSYS
        || sys::compartment_create(0, 0, &limits.bytes()) != EBADF
    {
        return 1;
    }
    // 2. restrict: rights only go; unknown bits EINVAL; a handle without
    //    DUPLICATE cannot be copied again.
    let only_create = sys::native_restrict(FACTORY, CREATE);
    if only_create < 0
        || sys::native_restrict(FACTORY, 1 << 20) != EINVAL
        || sys::native_restrict(only_create as i32, CREATE | DUPLICATE) != EBADF
    {
        return 2;
    }
    // 3. factory_derive: a ceiling beneath the factory's; above the
    //    derived one EPERM; reserved bytes or no processes EINVAL.
    let derived = sys::factory_derive(only_create as i32, &limits.bytes());
    if derived < 0 {
        return 3;
    }
    let derived = derived as i32;
    let more = Limits {
        processes: 17,
        ..limits
    };
    let mut reserved = limits.bytes();
    reserved[36] = 1;
    let none = Limits {
        processes: 0,
        ..limits
    };
    if sys::factory_derive(derived, &more.bytes()) != EPERM
        || sys::factory_derive(derived, &reserved) != EINVAL
        || sys::factory_derive(derived, &none.bytes()) != EINVAL
    {
        return 3;
    }
    // 4. compartment_create: above the ceiling EPERM; a file as root
    //    ENOTDIR; a root without ENUMERATE EBADF.
    let root_dir = path(base, b"/a");
    let root = make_root(&root_dir, me, true);
    if root < 0 {
        return 4;
    }
    let root = root as i32;
    let file = sys::open(path(&root_dir, b"/prog").c(), sys::O_RDONLY, 0) as i32;
    let blind = sys::native_restrict(root, STAT) as i32;
    if sys::compartment_create(derived, root, &more.bytes()) != EPERM
        || sys::compartment_create(derived, file, &limits.bytes()) != ENOTDIR
        || sys::compartment_create(derived, blind, &limits.bytes()) != EBADF
    {
        return 4;
    }
    let c = sys::compartment_create(derived, root, &limits.bytes());
    if c < 0 {
        return 4;
    }
    let c = c as i32;
    // 5. grant_device: /dev/null appears; granted again, nothing changes;
    //    a file where a device would go EEXIST; unknown EINVAL.
    let mut st = [0u8; 144];
    let zero = sys::open(
        path(&root_dir, b"/dev/zero").c(),
        sys::O_WRONLY | sys::O_CREAT,
        0o644,
    );
    if zero < 0 {
        return 5;
    }
    sys::close(zero as i32);
    if sys::compartment_grant_device(c, 1) != 0
        || sys::stat(path(&root_dir, b"/dev/null").c(), &mut st) != 0
        || sys::compartment_grant_device(c, 1) != 0
        || sys::compartment_grant_device(c, 2) != EEXIST
        || sys::compartment_grant_device(c, 9) != EINVAL
    {
        return 5;
    }
    // 6. spawn: a missing program ENOENT; a factory as stdio EPERM; then
    //    /prog child look, its output on a pipe.
    let mut out = [-1i32; 2];
    if sys::pipe2(&mut out, None) != 0 {
        return 6;
    }
    let argv = [c"/prog", c"child", c"look"];
    if sys::compartment_spawn(c, c"/nothing", &argv, &[], [-1, out[1], 2]) != ENOENT
        || sys::compartment_spawn(c, c"/prog", &argv, &[], [-1, FACTORY, 2]) != EPERM
    {
        return 6;
    }
    let pid = sys::compartment_spawn(c, c"/prog", &argv, &[], [-1, out[1], 2]);
    sys::close(out[1]);
    if pid != 1 {
        return 6;
    }
    // 7. wait: once it has ended, no process, its status 42.
    let Ok(usage) = sys::compartment_wait(c, 0) else {
        return 7;
    };
    let mut line = [0u8; 64];
    let n = sys::read(out[0], &mut line);
    sys::close(out[0]);
    if usage.processes != 0
        || usage.status != 42 << 8
        || line[..n.max(0) as usize] != *b"child: confined\n"
    {
        return 7;
    }
    // 8. kill: a sleeping PID 1 killed with SIGKILL; WNOHANG while it runs
    //    shows it; a handle with STAT only can look but not spawn or wait.
    let root2_dir = path(base, b"/b");
    let root2 = make_root(&root2_dir, me, false);
    let c2 = sys::compartment_create(derived, root2 as i32, &limits.bytes());
    if root2 < 0 || c2 < 0 {
        return 8;
    }
    let c2 = c2 as i32;
    if sys::compartment_grant_device(c2, 1) != ENOENT {
        return 8;
    }
    if sys::compartment_spawn(
        c2,
        c"/prog",
        &[c"/prog", c"child", c"sleep"],
        &[],
        [-1, -1, 2],
    ) != 1
    {
        return 8;
    }
    let look = sys::native_restrict(c2, STAT) as i32;
    match sys::compartment_wait(look, 1) {
        Ok(u) if u.processes == 1 && u.status == -1 && u.memory_bytes > 0 => {}
        _ => return 8,
    }
    if sys::compartment_wait(look, 0) != Err(EBADF)
        || sys::compartment_spawn(look, c"/prog", &argv, &[], [-1, -1, 2]) != EBADF
        || sys::compartment_kill(look, SIGKILL) != EBADF
    {
        return 8;
    }
    if sys::compartment_kill(c2, SIGKILL) != 0 {
        return 8;
    }
    match sys::compartment_wait(c2, 0) {
        Ok(u) if u.processes == 0 && u.status == SIGKILL => {}
        _ => return 8,
    }
    // 9. Limits hold: with one process, its fork is EAGAIN.
    let root3_dir = path(base, b"/c");
    let root3 = make_root(&root3_dir, me, false);
    let one = Limits {
        processes: 1,
        ..limits
    };
    let c3 = sys::compartment_create(derived, root3 as i32, &one.bytes());
    if root3 < 0 || c3 < 0 {
        return 9;
    }
    if sys::compartment_spawn(
        c3 as i32,
        c"/prog",
        &[c"/prog", c"child", c"fork"],
        &[],
        [-1, -1, 2],
    ) != 1
    {
        return 9;
    }
    match sys::compartment_wait(c3 as i32, 0) {
        Ok(u) if u.status == 7 << 8 => {}
        _ => return 9,
    }
    // 10. Not a file: read EBADF or EINVAL, lseek ESPIPE, fstat an
    //     anonymous inode.
    let mut b = [0u8; 4];
    if sys::read(c, &mut b) >= 0
        || sys::lseek(c, 0, 0) != -29
        || sys::fstat(FACTORY, &mut st) != 0
        || u32::from_le_bytes([st[24], st[25], st[26], st[27]]) != 0o600
    {
        return 10;
    }
    0
}

/// Whether GREETING=hello was in the environment (the manifest mode).
static ENV_SEEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn main(startup: &Startup) -> i32 {
    ENV_SEEN.store(
        startup.env().any(|e| e == b"GREETING=hello"),
        core::sync::atomic::Ordering::Relaxed,
    );
    let mut args = startup.args();
    let _ = args.next();
    if args.next() == Some(b"child") {
        return child(args.next().unwrap_or(b""));
    }
    let mut base = Buf::<128>::new();
    base.put(b"/tmp/keel-launchprobe-")
        .num(sys::getpid() as u64);
    if sys::mkdir(base.c(), 0o700) != 0 {
        return 100;
    }
    let result = checks(&base, c"/test/launchprobe");
    for (dir, dev) in [(&b"/a"[..], true), (b"/b", false), (b"/c", false)] {
        let d = path(&base, dir);
        sys::unlink(path(&d, b"/prog").c());
        if dev {
            sys::unlink(path(&d, b"/dev/null").c());
            sys::unlink(path(&d, b"/dev/zero").c());
            sys::rmdir(path(&d, b"/dev").c());
        }
        sys::rmdir(path(&d, b"").c());
    }
    sys::rmdir(base.c());
    if result == 0 {
        sys::write(1, b"launchprobe: 10 checks passed\n");
    }
    result
}

keel_rt::main!(main);
