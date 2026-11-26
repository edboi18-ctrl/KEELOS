//! vfork(2), clone(2)'s CLONE_VFORK and the ID calls, checked against
//! Linux (ADR 0034). Runs under Linux (`host.spawnprobe`) and on Keel
//! (`exec.spawn`) and must pass on both.
//!
//! Semantics from vfork(2), clone(2), getuid(2), getresuid(2) and Linux
//! v6.12's `kernel/fork.c` (`SYSCALL_DEFINE0(vfork)`: CLONE_VFORK |
//! CLONE_VM; `wait_for_vfork_done`; `mm_release` letting the parent go
//! on at execve or exit) and `kernel/sys.c`. The vfork children run only
//! keel-rt's assembly (`sys::vfork_then_exit`, `sys::vfork_exec`).
//!
//! Run as `spawnprobe nap`, it sleeps 300 ms and exits 0 (the program a
//! vfork child executes). Run as `spawnprobe root`, as Keel's self-test
//! does, it also checks that every ID is 0.
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use core::ffi::CStr;
use core::sync::atomic::{AtomicU32, Ordering};

use keel_rt::Startup;
use keel_rt::sys::{self, Hostile};

const EFAULT: i64 = -14;
const SIGCHLD: u64 = 17;
const CLONE_VM: u64 = 0x100;
const CLONE_VFORK: u64 = 0x4000;
const WNOHANG: u32 = 1;
const MS: i64 = 1_000_000;

fn ts(nanos: i64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&(nanos / 1_000_000_000).to_le_bytes());
    b[8..].copy_from_slice(&(nanos % 1_000_000_000).to_le_bytes());
    b
}

fn now() -> i64 {
    let mut b = [0u8; 16];
    sys::clock_gettime(1, &mut b);
    let sec = i64::from_le_bytes(b[..8].try_into().unwrap_or_default());
    let nsec = i64::from_le_bytes(b[8..].try_into().unwrap_or_default());
    sec * 1_000_000_000 + nsec
}

/// The exit code of `pid` (blocking), or 1000 plus the signal.
fn exit_code(pid: i64) -> i32 {
    let mut status = 0;
    if sys::wait4(pid as i32, &mut status, 0) != pid {
        return 2000;
    }
    if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        1000 + (status & 0x7f)
    }
}

/// A NUL-terminated copy of `text`.
fn c_string<'a>(text: &[u8], buf: &'a mut [u8; 512]) -> &'a CStr {
    let n = text.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&text[..n]);
    buf[n] = 0;
    CStr::from_bytes_until_nul(&buf[..=n]).unwrap_or(c"")
}

fn main(startup: &Startup) -> i32 {
    let mut args = startup.args();
    let argv0 = args.next().unwrap_or(b"/test/spawnprobe");
    let mode = args.next();
    if mode == Some(b"nap") {
        sys::poll(&mut [], 300);
        return 0;
    }
    // 1. vfork: the parent waits until the child exits, and the child's
    //    write is in the parent's memory (CLONE_VM).
    let nap = ts(100 * MS);
    let flag = AtomicU32::new(0);
    let t0 = now();
    let child = sys::vfork_then_exit(None, &nap, &flag, 7);
    let waited = now() - t0;
    if child <= 0 || waited < 100 * MS || flag.load(Ordering::SeqCst) != 1 || exit_code(child) != 7
    {
        return 1;
    }
    // 2. CLONE_VFORK alone: the parent waits as well, but the child has a
    //    copy of the memory, so its write is its own.
    let flag = AtomicU32::new(0);
    let t0 = now();
    let child = sys::vfork_then_exit(Some(CLONE_VFORK | SIGCHLD), &nap, &flag, 7);
    let waited = now() - t0;
    if child <= 0 || waited < 100 * MS || flag.load(Ordering::SeqCst) != 0 || exit_code(child) != 7
    {
        return 2;
    }
    // 3. CLONE_VM | CLONE_VFORK, as musl's posix_spawn passes them: vfork.
    let flag = AtomicU32::new(0);
    let t0 = now();
    let child = sys::vfork_then_exit(Some(CLONE_VM | CLONE_VFORK | SIGCHLD), &nap, &flag, 9);
    let waited = now() - t0;
    if child <= 0 || waited < 100 * MS || flag.load(Ordering::SeqCst) != 1 || exit_code(child) != 9
    {
        return 3;
    }
    // 4. A child that executes a program lets the parent go on at once
    //    (`mm_release` at execve), while it runs on: the parent is back
    //    long before the program's 300 ms are over, and the child has not
    //    exited yet.
    let mut path = [0u8; 512];
    let path = c_string(argv0, &mut path);
    let t0 = now();
    let child = sys::vfork_exec(path, &[path, c"nap"], &[]);
    let back = now() - t0;
    let mut status = 0;
    let early = sys::wait4(child as i32, &mut status, WNOHANG);
    if child <= 0 || back >= 250 * MS || early != 0 {
        return 4;
    }
    if exit_code(child) != 0 || now() - t0 < 300 * MS {
        return 5;
    }
    // 5. An execve that fails in the child: the child exits (127 here),
    //    which lets the parent go on.
    let child = sys::vfork_exec(c"/nonexistent/program", &[c"x"], &[]);
    if child <= 0 || exit_code(child) != 127 {
        return 6;
    }
    // 6. The IDs agree with each other (getuid(2), getresuid(2)): real
    //    and effective the same here, and getresuid and getresgid giving
    //    them in order; EFAULT for an unwritable pointer.
    let uid = sys::get_id(102);
    let gid = sys::get_id(104);
    if uid < 0 || gid < 0 || sys::get_id(107) != uid || sys::get_id(108) != gid {
        return 7;
    }
    let mut ids = [u32::MAX; 3];
    let mut gids = [u32::MAX; 3];
    if sys::getres_ids(false, &mut ids) != 0
        || ids.iter().any(|&i| i64::from(i) != uid)
        || sys::getres_ids(true, &mut gids) != 0
        || gids.iter().any(|&g| i64::from(g) != gid)
    {
        return 8;
    }
    let (Some(a), Some(b), Some(c)) = (Hostile::new(8), Hostile::new(8), Hostile::new(8)) else {
        return 9;
    };
    if sys::getresuid_from([a, b, c]) != EFAULT {
        return 9;
    }
    // 7. On Keel every process is root in its compartment (ADR 0030).
    if mode == Some(b"root") && (uid != 0 || gid != 0) {
        return 10;
    }
    sys::write(1, b"spawnprobe: 10 checks passed\n");
    0
}

keel_rt::main!(main);
