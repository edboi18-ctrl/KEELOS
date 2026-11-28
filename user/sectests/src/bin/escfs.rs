//! Escape suite, the filesystem (ADR 0047). Tries to name the outside
//! secret, `/sec-outside/secret` in the system's tree, by every route,
//! and to bring an outside file or device into the compartment's tree:
//!
//! - 1-19: `..` traversal, from the root, a directory handle and the
//!   working directory;
//! - 20-39: absolute and relative symbolic links pointing out, and
//!   creating through one;
//! - 40-49: a symbolic link swapped, by a second process, while the
//!   first looks up through it;
//! - 50-69: hard links to outside files, renames out, and the
//!   descriptors it was given (standard input is the secret, read-only;
//!   standard error is the console);
//! - 70-99: `/proc`;
//! - 100-119: device nodes that should not exist;
//! - 120-129: a decoy `/sec-outside/secret` of its own: every route above
//!   now finds that, never the real one.
//!
//! Run as `escfs` from `/escfs` in a compartment whose tree holds only
//! the suite's programs. See the crate's documentation.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_WRONLY};
use keel_sectests::{
    EBADF, ENOENT, EPERM, O_DIRECTORY, SECRET, SIGKILL, exists, fail, in_child, ino_of, list,
    open_at_result, open_result,
};

const ELOOP: i64 = -40;
const AT_SYMLINK_FOLLOW: u32 = 0x400;
const AT_EMPTY_PATH: u32 = 0x1000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFIFO: u32 = 0o010000;

const ME: &[u8] = b"escfs";

/// Every way of naming the secret from inside: none may reach it.
const ROUTES: [&CStr; 13] = [
    c"/sec-outside/secret",
    c"/../sec-outside/secret",
    c"/../../../../../../sec-outside/secret",
    c"../sec-outside/secret",
    c"../../../../sec-outside/secret",
    c"/./.././../sec-outside/./secret",
    c"//..//..//sec-outside//secret",
    c"/d/../../sec-outside/secret",
    c"/d/../../../d/../../sec-outside/secret",
    c"/abs",
    c"/abs-dir/secret",
    c"/d/rel",
    c"/d/rel-dir/sec-outside/secret",
];

/// What the system's tree has and this compartment must not see.
const SYSTEM: [&CStr; 10] = [
    c"/comp",
    c"/comp/esc/escfs",
    c"/comp/escn",
    c"/sec",
    c"/sec/escfs",
    c"/test",
    c"/etc/keel-release",
    c"/sbin/keel-init",
    c"/bin/keel-shell",
    c"/sec-outside",
];

/// `/proc` entries Linux has and Keel does not, each of which would show
/// or reach something outside on Linux.
const PROC_ABSENT: [&CStr; 20] = [
    c"/proc/self/root",
    c"/proc/1/root",
    c"/proc/self/cwd",
    c"/proc/self/fd",
    c"/proc/self/fd/0",
    c"/proc/self/mem",
    c"/proc/self/maps",
    c"/proc/self/environ",
    c"/proc/self/mountinfo",
    c"/proc/self/task/1/root",
    c"/proc/mounts",
    c"/proc/kcore",
    c"/proc/kallsyms",
    c"/proc/sysrq-trigger",
    c"/proc/sys/kernel/core_pattern",
    c"/proc/net/unix",
    c"/proc/2",
    c"/proc/2/exe",
    c"/proc/1/task/2",
    c"/proc/thread-self/root",
];

/// Device nodes nothing granted, so none may be there.
const DEVICES: [&CStr; 16] = [
    c"/dev/null",
    c"/dev/zero",
    c"/dev/urandom",
    c"/dev/console",
    c"/dev/tty",
    c"/dev/ptmx",
    c"/dev/pts/0",
    c"/dev/mem",
    c"/dev/kmem",
    c"/dev/port",
    c"/dev/sda",
    c"/dev/vda",
    c"/dev/fb0",
    c"/dev/input/event0",
    c"/dev/kvm",
    c"/dev/cpu/0/msr",
];

/// The whole contents of `path`, up to 64 bytes, or the error.
fn read_all<'b>(path: &CStr, buf: &'b mut [u8; 64]) -> Result<&'b [u8], i64> {
    let fd = sys::openat(AT_FDCWD, path, O_RDONLY, 0);
    if fd < 0 {
        return Err(fd);
    }
    let n = sys::read(fd as i32, buf);
    sys::close(fd as i32);
    if n < 0 {
        return Err(n);
    }
    Ok(&buf[..n as usize])
}

fn write_file(path: &CStr, data: &[u8]) -> bool {
    let fd = sys::openat(AT_FDCWD, path, O_WRONLY | O_CREAT | O_EXCL, 0o644);
    if fd < 0 {
        return false;
    }
    let ok = sys::write(fd as i32, data) == data.len() as i64;
    sys::close(fd as i32);
    ok
}

fn main(_: &Startup) -> i32 {
    let root = match ino_of(c"/") {
        Ok(i) => i,
        Err(e) => return fail(ME, 1, e),
    };
    if sys::mkdir(c"/d", 0o755) != 0 || !write_file(c"/d/inner", b"in\n") {
        return fail(ME, 2, -1);
    }
    let d = ino_of(c"/d").unwrap_or(0);

    // 1-19: `..` traversal.
    for (i, route) in ROUTES[..9].iter().enumerate() {
        let r = open_result(route);
        if r != ENOENT {
            return fail(ME, 3 + i as i32, r);
        }
    }
    for (i, name) in SYSTEM.iter().enumerate() {
        let r = open_result(name);
        if r != ENOENT {
            return fail(ME, 12, (i as i64) << 8 | -r);
        }
    }
    // `/..` is `/`.
    if ino_of(c"/..") != Ok(root) || ino_of(c"/../../..") != Ok(root) {
        return fail(ME, 13, -1);
    }
    // Through a directory handle: `..` stops at the handle's directory
    // (ADR 0012), so this is /d/sec-outside/secret.
    let dir = sys::openat(AT_FDCWD, c"/d", O_RDONLY | O_DIRECTORY, 0);
    if dir < 0 {
        return fail(ME, 14, dir);
    }
    let dir = dir as i32;
    let r = open_at_result(dir, c"../../../sec-outside/secret", O_RDONLY);
    if r != ENOENT {
        return fail(ME, 15, r);
    }
    if open_at_result(dir, c"inner", O_RDONLY) != 0 {
        return fail(ME, 16, -1);
    }
    // The working directory: climbing stops at the root.
    for _ in 0..8 {
        sys::chdir(c"..");
    }
    if ino_of(c".") != Ok(root) || open_result(c"sec-outside/secret") != ENOENT {
        return fail(ME, 17, -1);
    }
    if sys::fchdir(dir) != 0 || sys::chdir(c"../../..") != 0 || ino_of(c".") != Ok(root) {
        return fail(ME, 18, -1);
    }
    // The root lists only what is in the compartment.
    let mut outside = false;
    let listed = list(c"/", |name| {
        outside |= [
            &b"sec-outside"[..],
            b"comp",
            b"test",
            b"sec",
            b"etc",
            b"sbin",
        ]
        .contains(&name);
    });
    if listed.is_err() || outside {
        return fail(ME, 19, listed.map_or_else(|e| e, |_| -1));
    }

    // 20-39: symbolic links pointing out.
    let links: [(&CStr, &CStr); 6] = [
        (c"/../sec-outside/secret", c"/abs"),
        (c"/../../sec-outside", c"/abs-dir"),
        (c"../../../../sec-outside/secret", c"/d/rel"),
        (c"../../../..", c"/d/rel-dir"),
        (c"/loop", c"/loop"),
        (c"/../../sec-outside/made", c"/out"),
    ];
    for (i, (target, name)) in links.iter().enumerate() {
        let r = sys::symlink(target, name);
        if r != 0 {
            return fail(ME, 20 + i as i32, r);
        }
    }
    for (i, route) in ROUTES[9..].iter().enumerate() {
        let r = open_result(route);
        if r != ENOENT {
            return fail(ME, 26 + i as i32, r);
        }
    }
    // A link to `../../../..` from /d is the root.
    if ino_of(c"/d/rel-dir") != Ok(root) {
        return fail(ME, 31, -1);
    }
    let r = open_result(c"/loop");
    if r != ELOOP {
        return fail(ME, 32, r);
    }
    // Creating through a dangling link pointing out: the target's
    // directory is the compartment's `/sec-outside`, which does not exist.
    let r = open_at_result(AT_FDCWD, c"/out", O_WRONLY | O_CREAT);
    if r != ENOENT {
        return fail(ME, 33, r);
    }
    let r = sys::mkdir(c"/abs-dir/new", 0o755);
    if r != ENOENT {
        return fail(ME, 34, r);
    }

    // 40-49: a link swapped by another process during lookups. The child
    // keeps replacing `/sw` (rename over it, atomically) with a link to
    // `/d`, to the root by `..`, and to the outside directory by `..`; the
    // parent looks up through it. Each lookup must land in /d or at the
    // root, and the secret is never found.
    if sys::symlink(c"/d", c"/sw") != 0 {
        return fail(ME, 40, -1);
    }
    let swapper = sys::fork();
    if swapper < 0 {
        return fail(ME, 41, swapper);
    }
    if swapper == 0 {
        let targets = [c"/d", c"../../../../..", c"/../../sec-outside", c"d/../.."];
        let mut i = 0usize;
        loop {
            let _ = sys::unlinkat(AT_FDCWD, c"/sw-new", 0);
            if sys::symlink(targets[i % targets.len()], c"/sw-new") == 0 {
                sys::rename(c"/sw-new", c"/sw");
            }
            i = i.wrapping_add(1);
        }
    }
    let (mut in_d, mut at_root) = (0u32, 0u32);
    let mut bad = 0i64;
    // At least 4000 rounds, and on until both kinds of target were seen
    // (the swapper may first run only after a time slice or two).
    for round in 0..400_000 {
        if round >= 4000 && in_d > 0 && at_root > 0 {
            break;
        }
        match ino_of(c"/sw") {
            Ok(i) if i == d => in_d += 1,
            Ok(i) if i == root => at_root += 1,
            Ok(_) => bad = -1,
            // `/sec-outside` by `..` is the compartment's own, absent.
            Err(ENOENT) => {}
            Err(e) => bad = e,
        }
        for route in [
            c"/sw/secret",
            c"/sw/sec-outside/secret",
            c"/sw/../sec-outside/secret",
        ] {
            let r = open_result(route);
            if r != ENOENT {
                bad = r;
            }
        }
        if bad != 0 {
            break;
        }
    }
    sys::kill(swapper as i32, SIGKILL);
    let mut status = 0;
    sys::wait4(swapper as i32, &mut status, 0);
    if bad != 0 {
        return fail(ME, 42, bad);
    }
    // Both kinds of target were seen, so the lookups did race the swaps.
    if in_d == 0 || at_root == 0 {
        return fail(ME, 43, i64::from(in_d) << 16 | i64::from(at_root));
    }

    // 50-69: hard links and renames out, and the descriptors given.
    let r = sys::link(c"/../sec-outside/secret", c"/h1");
    if r != ENOENT {
        return fail(ME, 50, r);
    }
    let r = sys::linkat(AT_FDCWD, c"/abs", AT_FDCWD, c"/h2", AT_SYMLINK_FOLLOW);
    if r != ENOENT {
        return fail(ME, 51, r);
    }
    let r = sys::rename(c"/../sec-outside/secret", c"/h3");
    if r != ENOENT {
        return fail(ME, 52, r);
    }
    let r = sys::rename(c"/d/inner", c"/../../sec-outside/stolen");
    if r != ENOENT {
        return fail(ME, 53, r);
    }
    // Standard input is the secret, open read-only: it reads, but it
    // cannot be written, and cannot be given a name here (which would let
    // it be opened again for writing). Linux refuses the same linkat
    // (ENOENT) to a caller that did not open the file itself and lacks
    // CAP_DAC_READ_SEARCH (`fs/namei.c`, LOOKUP_LINKAT_EMPTY).
    let mut b = [0u8; 64];
    let n = sys::pread(0, &mut b, 0);
    if n != SECRET.len() as i64 || &b[..SECRET.len()] != SECRET {
        return fail(ME, 54, n);
    }
    let r = sys::write(0, b"x");
    if r != EBADF {
        return fail(ME, 55, r);
    }
    let r = sys::ftruncate(0, 0);
    if r >= 0 {
        return fail(ME, 56, r);
    }
    let r = sys::linkat(0, c"", AT_FDCWD, c"/stdin", AT_EMPTY_PATH);
    if r != ENOENT {
        return fail(ME, 57, r);
    }
    // Standard error, the console: no device node from it either.
    let r = sys::linkat(2, c"", AT_FDCWD, c"/console", AT_EMPTY_PATH);
    if r != ENOENT {
        return fail(ME, 58, r);
    }
    if exists(c"/stdin") || exists(c"/console") || exists(c"/h1") || exists(c"/h2") {
        return fail(ME, 59, -1);
    }
    // A link to its own file, by name or through its own descriptor's
    // path, works as usual.
    if sys::link(c"/d/inner", c"/d/inner2") != 0 {
        return fail(ME, 60, -1);
    }

    // 70-99: /proc.
    for (i, name) in PROC_ABSENT.iter().enumerate() {
        let r = open_result(name);
        if r != ENOENT {
            return fail(ME, 70 + i as i32, r);
        }
    }
    // Climbing out of /proc names nothing: /proc is not a directory of
    // the compartment's tree but names the kernel answers, and a path
    // that leaves it is not looked up again in the tree. ENOENT, where
    // Linux would give the root (ADR 0047, "Not yet covered").
    for path in [
        c"/proc/..",
        c"/proc/self/../../..",
        c"/proc/../sec-outside/secret",
    ] {
        let r = open_result(path);
        if r != ENOENT {
            return fail(ME, 90, r);
        }
    }
    // Its own program, by the name it has here.
    let mut link = [0u8; 64];
    let n = sys::readlink(c"/proc/self/exe", &mut link);
    if n < 0 || &link[..n as usize] != b"/escfs" {
        return fail(ME, 91, n);
    }
    if ino_of(c"/proc/self/exe") != ino_of(c"/escfs") {
        return fail(ME, 92, -1);
    }
    // /proc lists only this process.
    let mut pids = 0;
    let mut others = false;
    let listed = list(c"/proc", |name| {
        if name.iter().all(u8::is_ascii_digit) {
            pids += 1;
            others |= name != b"1";
        }
    });
    if listed.is_err() || pids != 1 || others {
        return fail(ME, 93, pids);
    }
    // Nothing can be made in /proc.
    let r = open_at_result(AT_FDCWD, c"/proc/new", O_WRONLY | O_CREAT);
    if r >= 0 {
        return fail(ME, 94, r);
    }
    let r = sys::symlink(c"/", c"/proc/self/root");
    if r >= 0 {
        return fail(ME, 95, r);
    }

    // 100-119: devices.
    for (i, name) in DEVICES.iter().enumerate() {
        let r = open_result(name);
        if r != ENOENT {
            return fail(ME, 100 + i as i32, r);
        }
    }
    if sys::mkdir(c"/dev", 0o755) != 0 {
        return fail(ME, 116, -1);
    }
    // Character and block devices need CAP_MKNOD (ADR 0035): EPERM, for
    // /dev/mem (1:1), /dev/null (1:3), the console (5:1) and a disk (8:0).
    let nodes: [(&CStr, u32, u64); 4] = [
        (c"/dev/mem", S_IFCHR, 0x101),
        (c"/dev/null", S_IFCHR, 0x103),
        (c"/dev/console", S_IFCHR, 0x501),
        (c"/dev/sda", S_IFBLK, 0x800),
    ];
    for (name, kind, dev) in nodes {
        let r = sys::mknodat(AT_FDCWD, name, kind | 0o666, dev);
        if r != EPERM {
            return fail(ME, 117, r);
        }
    }
    // A FIFO is not a device: that works.
    if sys::mknodat(AT_FDCWD, c"/dev/fifo", S_IFIFO | 0o600, 0) != 0 {
        return fail(ME, 118, -1);
    }
    // A link to the system's console by `..`.
    if sys::symlink(c"/../../dev/console", c"/dev/con") != 0 || open_result(c"/dev/con") != ENOENT {
        return fail(ME, 119, -1);
    }

    // 120-129: a decoy of its own at `/sec-outside/secret`. Every route
    // now reaches it, and only it.
    if sys::mkdir(c"/sec-outside", 0o755) != 0 || !write_file(c"/sec-outside/secret", b"decoy\n") {
        return fail(ME, 120, -1);
    }
    for (i, route) in ROUTES.iter().enumerate() {
        let mut buf = [0u8; 64];
        match read_all(route, &mut buf) {
            Ok(b"decoy\n") => {}
            Ok(_) => return fail(ME, 121, i as i64),
            Err(e) => return fail(ME, 122, (i as i64) << 8 | -e),
        }
    }
    let r = open_result(c"/proc/../sec-outside/secret");
    if r != ENOENT {
        return fail(ME, 126, r);
    }
    // The dangling link now makes its file in the decoy directory.
    let r = open_at_result(AT_FDCWD, c"/out", O_WRONLY | O_CREAT);
    if r != 0 || !exists(c"/sec-outside/made") {
        return fail(ME, 123, r);
    }
    // And a child of this process sees the same.
    let child = in_child(|| {
        let mut buf = [0u8; 64];
        match read_all(c"/../../sec-outside/secret", &mut buf) {
            Ok(b"decoy\n") => 0,
            _ => 1,
        }
    });
    if child != Ok(0) {
        return fail(ME, 124, keel_sectests::outcome(child));
    }
    let r = open_at_result(AT_FDCWD, c"/sec-outside/secret", O_RDWR);
    if r != 0 {
        return fail(ME, 125, r);
    }
    0
}

keel_rt::main!(main);
