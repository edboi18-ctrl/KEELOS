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
const EMFILE: i64 = -24;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EEXIST: i64 = -17;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const EBUSY: i64 = -16;
const EROFS: i64 = -30;
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

    fn bytes(&self) -> &[u8] {
        &self.data[..self.len]
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
        // With `manifest-full`, from a manifest asking for the full
        // profile (ADR 0041): getppid, outside the default profile, works
        // only then.
        // A layered root (ADR 0046): `/` is a private tree over the base
        // and prefix images. `layered` is a first launch (exit 46),
        // `layered-again` a later one of the same private tree (47).
        b"layered" | b"layered-again" => layered(mode == b"layered-again"),
        b"manifest" | b"manifest-full" => {
            let full = mode == b"manifest-full";
            if (sys::getppid() == ENOSYS) == full {
                return 64;
            }
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
            // The full manifest also sets `handles = 16` (ADR 0042): dup
            // reaches descriptor 15 and no further (EMFILE).
            if full {
                let mut highest = 0;
                let last = loop {
                    let fd = sys::dup(1);
                    if fd < 0 {
                        break fd;
                    }
                    highest = fd;
                };
                if highest != 15 || last != EMFILE {
                    return 65;
                }
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
        // Its children run calls the Wine trace has no need for.
        profile: sys::PROFILE_FULL,
        memory_bytes: 64 << 20,
        tmpfs_bytes: 1 << 20,
        tmpfs_nodes: 64,
        handles: 0,
    };
    // 1. No such call past the last; a handle that is no factory EBADF.
    if sys::native_raw(9, 0, 0, 0) != ENOSYS
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
    // ADR 0041: an unknown profile EINVAL; beneath a ceiling with the
    // default profile, a full one EPERM.
    let unknown = Limits {
        profile: 2,
        ..limits
    };
    let narrow = Limits {
        profile: sys::PROFILE_DEFAULT,
        ..limits
    };
    if sys::factory_derive(derived, &more.bytes()) != EPERM
        || sys::factory_derive(derived, &reserved) != EINVAL
        || sys::factory_derive(derived, &none.bytes()) != EINVAL
        || sys::factory_derive(derived, &unknown.bytes()) != EINVAL
    {
        return 3;
    }
    let narrow_factory = sys::factory_derive(derived, &narrow.bytes());
    if narrow_factory < 0
        || sys::factory_derive(narrow_factory as i32, &limits.bytes()) != EPERM
        || sys::compartment_create(narrow_factory as i32, -1, &limits.bytes()) != EPERM
    {
        return 3;
    }
    sys::close(narrow_factory as i32);
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
    // 11. restrict on a file (ADR 0044's one check Linux has no simple
    //     test for: Keel cannot reopen /proc/self/fd/N read-only): without
    //     WRITE, F_ADD_SEALS on a sealable memfd is EPERM; the original
    //     descriptor, with WRITE, adds the seal.
    const READ: u64 = 1;
    const F_ADD_SEALS: u32 = 1033;
    const F_SEAL_SHRINK: u64 = 2;
    let memfd = sys::memfd_create(c"sealable", 2);
    let read_only = sys::native_restrict(memfd as i32, READ | STAT | DUPLICATE);
    if memfd < 0
        || read_only < 0
        || sys::fcntl(read_only as i32, F_ADD_SEALS, F_SEAL_SHRINK) != EPERM
        || sys::fcntl(memfd as i32, F_ADD_SEALS, F_SEAL_SHRINK) != 0
    {
        return 11;
    }
    sys::close(read_only as i32);
    sys::close(memfd as i32);
    // 12. The audit log (ADR 0045): only the root factory opens it, not
    //     a restricted copy or a derived factory; read gives whole lines,
    //     EINVAL for a buffer too small; spawn will not give it to a
    //     compartment (EPERM); it holds this program's own
    //     creations, grants and refusals above a ceiling (checks 3 to 9).
    if sys::audit_open(only_create as i32) != EBADF || sys::audit_open(derived) != EBADF {
        return 12;
    }
    let log = sys::audit_open(FACTORY);
    if log < 0 {
        return 12;
    }
    let log = log as i32;
    let mut tiny = [0u8; 8];
    if sys::read(log, &mut tiny) != EINVAL
        || sys::write(log, b"x") != EBADF
        || sys::compartment_spawn(c, c"/prog", &argv, &[], [-1, log, 2]) != EPERM
    {
        return 12;
    }
    let mut me = Buf::<32>::new();
    me.put(b" by=c0:").num(sys::getpid() as u64);
    let mut deny = Buf::<64>::new();
    deny.put(b"deny c=0 pid=").num(sys::getpid() as u64);
    let (mut created, mut granted, mut refused) = (false, false, false);
    let mut chunk = [0u8; 4096];
    loop {
        let n = sys::read(log, &mut chunk);
        if n < 0 {
            return 12;
        }
        if n == 0 {
            break;
        }
        for line in chunk[..n as usize].split(|&b| b == b'\n') {
            let has = |needle: &[u8]| line.windows(needle.len()).any(|w| w == needle);
            if has(b" create c=") && line.ends_with(me.bytes()) {
                created = true;
            }
            if has(b" grant c=") && has(b"device=null") && line.ends_with(me.bytes()) {
                granted = true;
            }
            if has(deny.bytes()) && has(b" compartment_create(") && has(b"errno=1") {
                refused = true;
            }
        }
    }
    if !(created && granted && refused) {
        return 12;
    }
    sys::close(log);
    // 13. layer (ADR 0046), and what a frozen image refuses. The image
    //     is made once, at a fixed path, and kept: nothing removes an
    //     image (the warm run makes it, so the measured run leaks
    //     nothing). Nothing here links /test/launchprobe into it, which
    //     would freeze that file too.
    let r = layer_checks(base);
    if r != 0 {
        return r;
    }
    0
}

/// Check 13 (see above): 0, or 13.
fn layer_checks(base: &Buf<128>) -> i32 {
    const O_WRONLY_TRUNC: u64 = 1 | 0o1000;
    const IMAGE: &CStr = c"/tmp/keel-launchprobe-image";
    if sys::mkdir(IMAGE, 0o755) == 0 {
        let f = sys::open(
            c"/tmp/keel-launchprobe-image/f",
            sys::O_WRONLY | sys::O_CREAT,
            0o644,
        );
        if f < 0
            || sys::write(f as i32, b"f") != 1
            || sys::mkdir(c"/tmp/keel-launchprobe-image/inner", 0o755) != 0
        {
            return 13;
        }
        sys::close(f as i32);
    }
    let dir = |p: &CStr| sys::open(p, sys::O_RDONLY | O_DIRECTORY, 0) as i32;
    let mut busy_dir = path(base, b"/busy");
    let mut private_dir = path(base, b"/priv");
    if sys::mkdir(path(base, b"/busy").c(), 0o755) != 0
        || sys::mkdir(path(base, b"/priv").c(), 0o755) != 0
    {
        return 13;
    }
    let held = sys::open(
        path(&busy_dir, b"/f").c(),
        sys::O_RDWR | sys::O_CREAT,
        0o644,
    );
    let (image, private, busy) = (dir(IMAGE), dir(path(base, b"/priv").c()), dir(busy_dir.c()));
    let file = sys::open(c"/tmp/keel-launchprobe-image/f", sys::O_RDONLY, 0) as i32;
    let no_create = sys::native_restrict(FACTORY, STAT) as i32;
    let refusals_ok = held >= 0
        && image >= 0
        && private >= 0
        && sys::native_layer(no_create, private, image) == EBADF
        && sys::native_layer(FACTORY, file, image) == ENOTDIR
        && sys::native_layer(FACTORY, private, private) == EINVAL
        // An open file in it: EBUSY, and it stays as it was.
        && sys::native_layer(FACTORY, private, busy) == EBUSY
        && sys::write(held as i32, b"still mine") == 10
        // A private tree inside the image it would be laid from: EINVAL.
        && sys::mkdir(path(&busy_dir, b"/sub").c(), 0o755) == 0
        && {
            let sub = dir(path(&busy_dir, b"/sub").c());
            let r = sys::native_layer(FACTORY, sub, busy);
            sys::close(sub);
            r == EINVAL
        };
    sys::rmdir(path(&busy_dir, b"/sub").c());
    sys::close(held as i32);
    sys::close(file);
    sys::close(no_create);
    sys::unlink(path(&busy_dir, b"/f").c());
    sys::close(busy);
    sys::rmdir(busy_dir.c());
    if !refusals_ok || sys::native_layer(FACTORY, private, image) != 0 {
        return 13;
    }
    // The private tree has the image's file, and writes its own copy; the
    // image cannot be written, nor laid over (it is frozen), nor have a
    // private tree inside it.
    let inner = dir(c"/tmp/keel-launchprobe-image/inner");
    // What it holds before this program truncates its own copy.
    let shared = holds(path(&private_dir, b"/f").c(), b"f");
    let copy = sys::open(path(&private_dir, b"/f").c(), O_WRONLY_TRUNC, 0);
    let ok = shared
        && copy >= 0
        && sys::write(copy as i32, b"copy") == 4
        && holds(path(&private_dir, b"/f").c(), b"copy")
        && holds(c"/tmp/keel-launchprobe-image/f", b"f")
        && sys::open(c"/tmp/keel-launchprobe-image/f", sys::O_WRONLY, 0) == EROFS
        && sys::open(
            c"/tmp/keel-launchprobe-image/g",
            sys::O_WRONLY | sys::O_CREAT,
            0o644,
        ) == EROFS
        && sys::native_layer(FACTORY, image, private) == EROFS
        && sys::native_layer(FACTORY, inner, image) == EROFS;
    sys::close(copy as i32);
    sys::close(inner);
    sys::close(image);
    sys::close(private);
    sys::unlink(path(&private_dir, b"/f").c());
    sys::rmdir(path(&private_dir, b"/inner").c());
    sys::rmdir(private_dir.c());
    if ok { 0 } else { 13 }
}

/// What the file at `path` holds (up to 32 bytes), or None.
fn contents(path: &CStr) -> Option<([u8; 32], usize)> {
    let fd = sys::open(path, sys::O_RDONLY, 0);
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 32];
    let n = sys::read(fd as i32, &mut buf);
    sys::close(fd as i32);
    (n >= 0).then_some((buf, n as usize))
}

fn holds(path: &CStr, want: &[u8]) -> bool {
    contents(path).is_some_and(|(b, n)| &b[..n] == want)
}

/// The `layered` child modes (ADR 0046).
fn layered(again: bool) -> i32 {
    const O_TRUNC: u64 = 0o1000;
    if again {
        // The private tree kept what the first launch did.
        return if holds(c"/etc/keep", b"mine")
            && holds(c"/etc/new", b"")
            && contents(c"/lib/x").is_none()
            && holds(c"/etc/extra2", b"extra")
        {
            47
        } else {
            71
        };
    }
    // The prefix overrides the base; the base shows through elsewhere.
    if !holds(c"/etc/greeting", b"prefix")
        || !holds(c"/etc/keep", b"keep")
        || !holds(c"/etc/extra", b"extra")
        || !holds(c"/lib/x", b"x")
    {
        return 72;
    }
    // Writing a base file: the compartment's own copy.
    let fd = sys::open(c"/etc/keep", sys::O_WRONLY | O_TRUNC, 0);
    if fd < 0 || sys::write(fd as i32, b"mine") != 4 {
        return 73;
    }
    sys::close(fd as i32);
    if !holds(c"/etc/keep", b"mine") {
        return 74;
    }
    // New names, removed names, renamed names, changed modes.
    let made = sys::open(c"/etc/new", sys::O_WRONLY | sys::O_CREAT, 0o644);
    if made < 0
        || sys::unlink(c"/lib/x") != 0
        || sys::rename(c"/etc/extra", c"/etc/extra2") != 0
        || sys::chmod(c"/etc/greeting", 0o600) != 0
    {
        return 75;
    }
    sys::close(made as i32);
    let mut st = [0u8; 144];
    if sys::stat(c"/etc/greeting", &mut st) != 0
        || u32::from_le_bytes([st[24], st[25], st[26], st[27]]) & 0o7777 != 0o600
        || contents(c"/lib/x").is_some()
    {
        return 76;
    }
    46
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
        sys::write(1, b"launchprobe: 13 checks passed\n");
    }
    result
}

keel_rt::main!(main);
