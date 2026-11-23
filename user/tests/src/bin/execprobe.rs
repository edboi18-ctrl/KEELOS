//! P3-T3: execve(2), checked against Linux. Runs under Linux
//! (`host.execprobe`) and on Keel (`exec.execve`) and must pass on both.
//! It runs itself three times, with the stage in its environment:
//!
//! 1. first: refusals (ENOENT, EACCES, EFAULT); then it opens itself twice
//!    (once with O_CLOEXEC), catches SIGUSR1, ignores SIGPIPE, blocks
//!    SIGUSR2, sets its FS and GS bases, and execs itself with a NULL
//!    argv;
//! 2. empty: argv is exactly [""] (Linux inserts it since 5.18); execs
//!    itself again with real arguments;
//! 3. second: the arguments and environment arrived; the plain handle is
//!    still open and the O_CLOEXEC one closed; SIGUSR1 is back to SIG_DFL
//!    with no flags or mask, SIGPIPE still ignored, SIGUSR2 still blocked;
//!    the FS and GS bases are 0. Exit 0.
//!
//! What execve keeps and resets is execve(2) and Linux's begin_new_exec
//! (`fs/exec.c`); the register and segment reset is elf_common_init.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, Arg, Hostile, O_CLOEXEC, O_RDONLY, Out};

const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const SIGUSR1: i32 = 10;
const SIGUSR2: i32 = 12;
const SIGPIPE: i32 = 13;
const SIG_IGN: u64 = 1;
const SA_RESTORER: u64 = 0x0400_0000;
const SIG_BLOCK: i32 = 0;
const F_GETFD: u32 = 1;

/// `prefix` and `value` as a NUL-terminated string in `buf`.
fn join<'b>(buf: &'b mut [u8; 600], prefix: &[u8], value: &[u8]) -> Option<&'b CStr> {
    let len = prefix.len() + value.len();
    if len >= buf.len() {
        return None;
    }
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len()..len].copy_from_slice(value);
    buf[len] = 0;
    CStr::from_bytes_until_nul(&buf[..=len]).ok()
}

/// `n` in decimal.
fn decimal(n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut at = buf.len();
    let mut n = n;
    loop {
        at -= 1;
        buf[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return &buf[at..];
        }
    }
}

fn number(text: &[u8]) -> Option<i32> {
    let mut n: i32 = 0;
    for &c in text {
        n = n
            .checked_mul(10)?
            .checked_add(i32::from(c.checked_sub(b'0').filter(|d| *d < 10)?))?;
    }
    (!text.is_empty()).then_some(n)
}

/// The value of `name=` in the environment.
fn var(startup: &Startup, name: &[u8]) -> Option<&'static [u8]> {
    startup
        .env()
        .find(|e| e.starts_with(name) && e.get(name.len()) == Some(&b'='))
        .map(|e| &e[name.len() + 1..])
}

fn action(sig: i32) -> Option<[u8; 32]> {
    let mut old = [0u8; 32];
    (sys::rt_sigaction(sig, Arg::Null, Out::Buf(&mut old), 8) == 0).then_some(old)
}

fn word(bytes: &[u8; 32], index: usize) -> u64 {
    u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap_or([0; 8]))
}

fn first(startup: &Startup) -> i32 {
    let Some(me) = startup.args().next() else {
        return 20;
    };
    let mut path_buf = [0u8; 600];
    let Some(me) = join(&mut path_buf, me, b"") else {
        return 21;
    };
    // Refusals leave this program running.
    if sys::execve(c"/no/such/program", Some(&[c"x"]), &[]) != ENOENT {
        return 1;
    }
    if sys::execve(c"/", Some(&[c"x"]), &[]) != EACCES {
        return 2;
    }
    let Some(null) = Hostile::new(0) else {
        return 22;
    };
    if sys::execve_from(null) != EFAULT {
        return 3;
    }
    // State for the new program to find kept or reset.
    let keep = sys::openat(AT_FDCWD, me, O_RDONLY, 0);
    let drop = sys::openat(AT_FDCWD, me, O_RDONLY | O_CLOEXEC, 0);
    if keep < 0 || drop < 0 {
        return 4;
    }
    // Any address will do as the handler: no signal is ever delivered.
    let handler = first as fn(&Startup) -> i32 as usize as u64;
    let mut caught = [0u8; 32];
    caught[..8].copy_from_slice(&handler.to_le_bytes());
    caught[8..16].copy_from_slice(&SA_RESTORER.to_le_bytes());
    caught[16..24].copy_from_slice(&handler.to_le_bytes());
    caught[24..32].copy_from_slice(&0b11u64.to_le_bytes());
    let mut ignored = [0u8; 32];
    ignored[..8].copy_from_slice(&SIG_IGN.to_le_bytes());
    if sys::rt_sigaction(SIGUSR1, Arg::Buf(&caught), Out::Null, 8) != 0
        || sys::rt_sigaction(SIGPIPE, Arg::Buf(&ignored), Out::Null, 8) != 0
    {
        return 5;
    }
    let block = 1u64 << (SIGUSR2 - 1);
    if sys::rt_sigprocmask(SIG_BLOCK, Arg::Buf(&block), Out::Null, 8) != 0 {
        return 6;
    }
    // Nothing in this runtime reads through FS or GS, so any base will do.
    let Some(fs) = Hostile::new(0x1000) else {
        return 24;
    };
    if sys::arch_prctl_set_fs(fs) != 0 || sys::set_gs_base(0x2000) != 0 {
        return 7;
    }
    if sys::fs_base() != Ok(0x1000) || sys::gs_base() != Ok(0x2000) {
        return 9;
    }
    let (mut a, mut b, mut c, mut d1, mut d2) =
        ([0u8; 600], [0u8; 600], [0u8; 600], [0u8; 20], [0u8; 20]);
    let self_var = join(&mut a, b"KEEL_EXEC_SELF=", me.to_bytes());
    let keep_var = join(&mut b, b"KEEL_EXEC_KEEP=", decimal(keep as u64, &mut d1));
    let drop_var = join(&mut c, b"KEEL_EXEC_DROP=", decimal(drop as u64, &mut d2));
    let (Some(self_var), Some(keep_var), Some(drop_var)) = (self_var, keep_var, drop_var) else {
        return 23;
    };
    sys::execve(
        me,
        None,
        &[c"KEEL_EXEC_STAGE=empty", self_var, keep_var, drop_var],
    );
    8 // execve returned
}

fn empty(startup: &Startup) -> i32 {
    // A NULL argv arrives as [""].
    let mut args = startup.args();
    if startup.argc() != 1 || args.next() != Some(&b""[..]) {
        return 11;
    }
    let (Some(me), Some(keep), Some(drop)) = (
        var(startup, b"KEEL_EXEC_SELF"),
        var(startup, b"KEEL_EXEC_KEEP"),
        var(startup, b"KEEL_EXEC_DROP"),
    ) else {
        return 12;
    };
    let (mut p, mut b, mut c) = ([0u8; 600], [0u8; 600], [0u8; 600]);
    let (Some(me), Some(keep_var), Some(drop_var)) = (
        join(&mut p, me, b""),
        join(&mut b, b"KEEL_EXEC_KEEP=", keep),
        join(&mut c, b"KEEL_EXEC_DROP=", drop),
    ) else {
        return 13;
    };
    sys::execve(
        me,
        Some(&[c"execprobe-second", c"two"]),
        &[c"KEEL_EXEC_STAGE=second", keep_var, drop_var],
    );
    14
}

fn second(startup: &Startup) -> i32 {
    let mut args = startup.args();
    if startup.argc() != 2
        || args.next() != Some(&b"execprobe-second"[..])
        || args.next() != Some(&b"two"[..])
        || startup.env().count() != 3
    {
        return 30;
    }
    let (Some(keep), Some(drop)) = (
        var(startup, b"KEEL_EXEC_KEEP").and_then(number),
        var(startup, b"KEEL_EXEC_DROP").and_then(number),
    ) else {
        return 31;
    };
    // The plain handle survives; the O_CLOEXEC one was closed.
    if sys::fcntl(keep, F_GETFD, 0) != 0 || sys::fcntl(drop, F_GETFD, 0) != EBADF {
        return 32;
    }
    // A caught signal goes back to SIG_DFL with no flags, restorer or
    // mask; an ignored one stays ignored.
    let (Some(usr1), Some(pipe)) = (action(SIGUSR1), action(SIGPIPE)) else {
        return 33;
    };
    if word(&usr1, 0) != 0 || word(&usr1, 1) != 0 || word(&usr1, 3) != 0 {
        return 34;
    }
    if word(&pipe, 0) != SIG_IGN {
        return 35;
    }
    // The blocked mask is kept.
    let mut blocked = 0u64;
    if sys::rt_sigprocmask(SIG_BLOCK, Arg::Null, Out::Buf(&mut blocked), 8) != 0
        || blocked & (1 << (SIGUSR2 - 1)) == 0
    {
        return 36;
    }
    // The FS and GS bases are reset.
    if sys::fs_base() != Ok(0) || sys::gs_base() != Ok(0) {
        return 37;
    }
    0
}

fn main(startup: &Startup) -> i32 {
    match var(startup, b"KEEL_EXEC_STAGE") {
        None => first(startup),
        Some(b"empty") => empty(startup),
        Some(b"second") => second(startup),
        Some(_) => 40,
    }
}

keel_rt::main!(main);
