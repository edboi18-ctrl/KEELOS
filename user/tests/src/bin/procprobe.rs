//! P3-T9: the procfs subset, checked against Linux. Runs under Linux
//! (`host.procprobe`) and on Keel (`exec.procfs`) and must pass on both.
//! It reads what the Wine traces read: `/proc` itself, `/proc/self` and
//! `/proc/<pid>`, the `exe` links, thread names in `comm` (and prctl
//! PR_SET_NAME / PR_GET_NAME), `/proc/cpuinfo` and `/proc/net/dev`.
//!
//! Only what Linux guarantees is checked: values that depend on the
//! machine (the CPU's flags, the network interfaces) are checked for
//! form, not content; nothing depends on running as root.
//!
//! Semantics from proc(5), proc_pid_exe(5), proc_pid_comm(5),
//! proc_cpuinfo(5), proc_pid_net(5) (`/proc/net/dev`) and prctl(2)
//! (PR_SET_NAME: "the name can be up to 16 bytes long, including the
//! terminating null byte").
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_RDONLY, O_WRONLY};

const ENOENT: i64 = -2;
const EINVAL: i64 = -22;
const ELOOP: i64 = -40;
const O_NOFOLLOW: u64 = 0o400000;
const PR_SET_NAME: u64 = 15;
const PR_GET_NAME: u64 = 16;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;

fn mode(b: &[u8; 144]) -> u32 {
    u32::from_le_bytes(b[24..28].try_into().unwrap_or([0; 4]))
}

fn ino(b: &[u8; 144]) -> u64 {
    u64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8]))
}

/// A path built from pieces, NUL-terminated, in `buf`.
fn path<'a>(buf: &'a mut [u8; 128], pieces: &[&[u8]]) -> &'a CStr {
    let mut at = 0;
    for p in pieces {
        buf[at..at + p.len()].copy_from_slice(p);
        at += p.len();
    }
    buf[at] = 0;
    CStr::from_bytes_until_nul(&buf[..]).unwrap_or(c"")
}

fn decimal(mut n: u64, out: &mut [u8; 20]) -> &[u8] {
    let mut at = out.len();
    loop {
        at -= 1;
        out[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &out[at..]
}

/// The whole of a small file.
fn slurp(p: &CStr, out: &mut [u8]) -> Result<usize, i64> {
    let fd = sys::openat(AT_FDCWD, p, O_RDONLY, 0);
    if fd < 0 {
        return Err(fd);
    }
    let mut n = 0;
    loop {
        let got = sys::read(fd as i32, &mut out[n..]);
        if got <= 0 {
            break;
        }
        n += got as usize;
        if n == out.len() {
            break;
        }
    }
    sys::close(fd as i32);
    Ok(n)
}

fn comm_now(out: &mut [u8; 32]) -> usize {
    slurp(c"/proc/self/comm", out).unwrap_or(0)
}

fn main(startup: &Startup) -> i32 {
    let Some(me) = startup.args().next() else {
        return 90;
    };
    let mut digits = [0u8; 20];
    let pid = sys::getpid() as u64;
    let pid_s = decimal(pid, &mut digits);
    let mut st = [0u8; 144];

    // 1. /proc is a directory (0555, as procfs); readlink of it EINVAL.
    if sys::stat(c"/proc", &mut st) != 0 || mode(&st) & S_IFMT != S_IFDIR {
        return 1;
    }
    let mut link = [0u8; 256];
    if sys::readlink(c"/proc", &mut link) != EINVAL {
        return 2;
    }

    // 2. /proc/self is a link to our PID; stat follows it to a directory.
    let n = sys::readlink(c"/proc/self", &mut link);
    if n != pid_s.len() as i64 || &link[..n as usize] != pid_s {
        return 3;
    }
    if sys::lstat(c"/proc/self", &mut st) != 0 || mode(&st) & S_IFMT != S_IFLNK {
        return 4;
    }
    if sys::stat(c"/proc/self", &mut st) != 0 || mode(&st) & S_IFMT != S_IFDIR {
        return 5;
    }
    let mut pb = [0u8; 128];
    if sys::stat(path(&mut pb, &[b"/proc/", pid_s]), &mut st) != 0 || mode(&st) & S_IFMT != S_IFDIR
    {
        return 6;
    }

    // 3. exe: a link to the program, under self and under the PID; stat
    //    follows it to the program itself; O_NOFOLLOW refuses it.
    if me.first() == Some(&b'/') {
        for p in [
            c"/proc/self/exe",
            path(&mut pb, &[b"/proc/", pid_s, b"/exe"]),
        ] {
            let n = sys::readlink(p, &mut link);
            if n != me.len() as i64 || &link[..n as usize] != me {
                return 7;
            }
        }
        let mut prog = [0u8; 144];
        let mut mb = [0u8; 128];
        if sys::stat(path(&mut mb, &[me]), &mut prog) != 0
            || sys::stat(c"/proc/self/exe", &mut st) != 0
        {
            return 8;
        }
        if ino(&st) != ino(&prog) || mode(&st) & S_IFMT != S_IFREG {
            return 8;
        }
    }
    if sys::openat(AT_FDCWD, c"/proc/self/exe", O_RDONLY | O_NOFOLLOW, 0) != ELOOP {
        return 9;
    }
    if sys::access(c"/proc/self/exe", 1) != 0 {
        return 10;
    }

    // 4. Names: the program's base name to begin with; a write to
    //    task/<tid>/comm renames the thread; PR_GET_NAME agrees; PR_SET_NAME
    //    keeps 15 bytes.
    let base = me.rsplit(|&b| b == b'/').next().unwrap_or(me);
    let base = &base[..base.len().min(15)];
    let mut c = [0u8; 32];
    let n = comm_now(&mut c);
    if n != base.len() + 1 || &c[..base.len()] != base || c[base.len()] != b'\n' {
        return 11;
    }
    let mut tb = [0u8; 20];
    let tid = decimal(sys::gettid() as u64, &mut tb);
    let task_comm = path(&mut pb, &[b"/proc/self/task/", tid, b"/comm"]);
    let fd = sys::openat(AT_FDCWD, task_comm, O_WRONLY, 0);
    if fd < 0 || sys::write(fd as i32, b"probe-thread") != 12 {
        return 12;
    }
    sys::close(fd as i32);
    let n = comm_now(&mut c);
    if &c[..n] != b"probe-thread\n" {
        return 13;
    }
    let mut name = [0u8; 16];
    if sys::prctl_name(PR_GET_NAME, &mut name) != 0 || &name[..13] != b"probe-thread\0" {
        return 14;
    }
    let mut long = *b"a-very-long-thread-name\0";
    let mut set = [0u8; 16];
    set.copy_from_slice(&long[..16]);
    if sys::prctl_name(PR_SET_NAME, &mut set) != 0 {
        return 15;
    }
    long[15] = 0;
    let n = comm_now(&mut c);
    if n != 16 || c[..15] != long[..15] || c[15] != b'\n' {
        return 16;
    }

    // 5. A forked child sees itself as self, its parent under its PID, and
    //    starts with its parent's name.
    let child = sys::fork();
    if child == 0 {
        let mut cd = [0u8; 20];
        let mine = decimal(sys::getpid() as u64, &mut cd);
        let mut l = [0u8; 32];
        let n = sys::readlink(c"/proc/self", &mut l);
        let mut s = [0u8; 144];
        let mut b = [0u8; 128];
        let ok = n == mine.len() as i64
            && &l[..n as usize] == mine
            && sys::stat(path(&mut b, &[b"/proc/", pid_s]), &mut s) == 0;
        let mut cc = [0u8; 32];
        let named = comm_now(&mut cc) == 16 && cc[..15] == long[..15];
        keel_rt::exit(if !ok {
            1
        } else if !named {
            2
        } else {
            0
        });
    }
    let mut status = 0;
    if child < 0 || sys::wait4(child as i32, &mut status, 0) != child || status != 0 {
        return 17;
    }

    // 6. A PID that does not exist, and a name procfs does not have.
    if sys::stat(c"/proc/999999999", &mut st) != ENOENT
        || sys::stat(c"/proc/self/nonesuch", &mut st) != ENOENT
    {
        return 18;
    }

    // 7. /proc/cpuinfo: Linux's x86 layout, a processor 0 first.
    let mut info = [0u8; 4096];
    let Ok(n) = slurp(c"/proc/cpuinfo", &mut info) else {
        return 19;
    };
    let text = &info[..n];
    let has = |needle: &[u8]| text.windows(needle.len()).any(|w| w == needle);
    if !text.starts_with(b"processor\t: 0\nvendor_id\t: ")
        || !has(b"\nmodel name\t: ")
        || !has(b"\nflags\t\t:")
    {
        return 20;
    }
    if !has(b"\ncpu family\t: ") || !has(b"\naddress sizes\t: ") {
        return 21;
    }
    // Read, then step back, as Wine does.
    let fd = sys::openat(AT_FDCWD, c"/proc/cpuinfo", O_RDONLY, 0) as i32;
    let mut part = [0u8; 64];
    if sys::read(fd, &mut part) != 64 || sys::lseek(fd, -54, 1) != 10 {
        return 22;
    }
    sys::close(fd);

    // 8. /proc/net/dev: the two header lines first.
    let mut dev = [0u8; 2048];
    let Ok(n) = slurp(c"/proc/net/dev", &mut dev) else {
        return 23;
    };
    if !dev[..n].starts_with(b"Inter-|   Receive")
        || !dev[..n].windows(21).any(|w| w == b" face |bytes    packe")
    {
        return 24;
    }

    // 9. statfs: procfs's magic.
    let mut sf = [0u8; 120];
    if sys::statfs(c"/proc", &mut sf) != 0
        || u64::from_le_bytes(sf[0..8].try_into().unwrap_or([0; 8])) != 0x9fa0
    {
        return 25;
    }

    sys::write(1, b"procprobe: 25 checks passed\n");
    0
}

keel_rt::main!(main);
