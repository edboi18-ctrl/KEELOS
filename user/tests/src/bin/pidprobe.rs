//! /proc's process directories, checked against Linux (ADR 0037). Runs
//! under Linux (`host.pidprobe`) and on Keel (`exec.procdirs`) and must
//! pass on both.
//!
//! Semantics from Linux v6.12's `fs/proc/root.c` (`proc_root_readdir`),
//! `fs/proc/base.c` (`proc_pid_readdir`, `proc_pident_readdir`,
//! `proc_task_readdir`, `get_mm_cmdline`), `fs/proc/generic.c`
//! (`proc_readdir_de`), `fs/proc/array.c` (`do_task_stat`) and proc(5).
//! Run with PIDPROBE_HOLD in its environment, it writes one byte to
//! descriptor 1 and reads descriptor 0 until end of file: the process
//! the checks look at.
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD};

const ENOENT: i64 = -2;
const ENOTDIR: i64 = -20;
const EISDIR: i64 = -21;
const EINVAL: i64 = -22;
const O_DIRECTORY: u64 = 0o200000;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const WUNTRACED: u32 = 2;
const SIGCONT: i32 = 18;
const SIGSTOP: i32 = 19;
const PR_SET_NAME: u64 = 15;
/// `proc_pid_readdir`: PIDs from TGID_OFFSET (FIRST_PROCESS_ENTRY 256 +
/// 2), and PID_MAX_LIMIT (4 Mi on 64-bit) + TGID_OFFSET at the end.
const TGID_OFFSET: i64 = 258;
const END: i64 = 4 * 1024 * 1024 + TGID_OFFSET;

/// Bytes put together in a fixed buffer.
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

fn lit(path: &[u8]) -> Buf<128> {
    let mut p = Buf::new();
    p.put(path);
    p
}

fn proc_path(pid: i64, tail: &[u8]) -> Buf<128> {
    let mut p = Buf::new();
    p.put(b"/proc/").num(pid as u64).put(tail);
    p
}

/// A decimal number, or None.
fn parse(b: &[u8]) -> Option<i64> {
    let (neg, digits) = match b.strip_prefix(b"-") {
        Some(d) => (true, d),
        None => (false, b),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut v: i64 = 0;
    for &d in digits {
        v = v.checked_mul(10)?.checked_add(i64::from(d - b'0'))?;
    }
    Some(if neg { -v } else { v })
}

/// A whole file's contents, or the open's error.
fn read_file(path: &mut Buf<128>, out: &mut Buf<4096>) -> Result<(), i64> {
    read_at(AT_FDCWD, path.c(), out)
}

/// The contents of `path` relative to `dir`, or the open's error.
fn read_at(dir: i32, path: &CStr, out: &mut Buf<4096>) -> Result<(), i64> {
    let fd = sys::openat(dir, path, sys::O_RDONLY, 0);
    if fd < 0 {
        return Err(fd);
    }
    let mut chunk = [0u8; 512];
    loop {
        let n = sys::read(fd as i32, &mut chunk);
        if n <= 0 {
            break;
        }
        out.put(&chunk[..n as usize]);
    }
    sys::close(fd as i32);
    Ok(())
}

/// Calls `f` with each entry (name, d_off, d_type) of directory `fd`,
/// reading from its current position to the end.
fn each(fd: i32, f: &mut dyn FnMut(&[u8], i64, u8)) -> Result<(), i64> {
    let mut buf = [0u8; 8192];
    loop {
        let n = sys::getdents64(fd, &mut buf);
        if n < 0 {
            return Err(n);
        }
        if n == 0 {
            return Ok(());
        }
        let mut at = 0;
        while at < n as usize {
            let off = i64::from_le_bytes(buf[at + 8..at + 16].try_into().unwrap_or([0; 8]));
            let reclen = u16::from_le_bytes([buf[at + 16], buf[at + 17]]) as usize;
            let kind = buf[at + 18];
            let name = &buf[at + 19..at + reclen];
            let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
            f(&name[..end], off, kind);
            at += reclen;
        }
    }
}

/// The first entry from position `pos` of directory `fd`.
fn first_at(fd: i32, pos: i64) -> Option<([u8; 16], usize)> {
    if sys::lseek(fd, pos, 0) != pos {
        return None;
    }
    let mut buf = [0u8; 64];
    if sys::getdents64(fd, &mut buf) <= 0 {
        return None;
    }
    let reclen = u16::from_le_bytes([buf[16], buf[17]]) as usize;
    let name = &buf[19..reclen];
    let end = name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(name.len())
        .min(16);
    let mut out = [0u8; 16];
    out[..end].copy_from_slice(&name[..end]);
    Some((out, end))
}

fn open_dir(path: &mut Buf<128>) -> i64 {
    sys::open(path.c(), sys::O_RDONLY | O_DIRECTORY, 0)
}

/// The fields of a stat line: the PID, the name between the first `(`
/// and the last `)`, and the rest split at spaces (field 3 on), with
/// how many there were in all. None if it is not one line in that form.
struct StatLine<'a> {
    pid: i64,
    comm: &'a [u8],
    rest: [&'a [u8]; 50],
    fields: usize,
}

impl StatLine<'_> {
    /// Field `n`, numbered as proc(5) numbers them (3 is the state).
    fn field(&self, n: usize) -> &[u8] {
        self.rest.get(n - 3).copied().unwrap_or(b"")
    }

    fn num(&self, n: usize) -> Option<i64> {
        parse(self.field(n))
    }
}

fn stat_line(text: &[u8]) -> Option<StatLine<'_>> {
    let body = text.strip_suffix(b"\n")?;
    if body.contains(&b'\n') {
        return None;
    }
    let open = body.iter().position(|&c| c == b'(')?;
    let close = body.iter().rposition(|&c| c == b')')?;
    let pid = parse(body.get(..open.checked_sub(1)?)?)?;
    let mut line = StatLine {
        pid,
        comm: &body[open + 1..close],
        rest: [b""; 50],
        fields: 2,
    };
    for (i, part) in body.get(close + 2..)?.split(|&c| c == b' ').enumerate() {
        *line.rest.get_mut(i)? = part;
        line.fields += 1;
    }
    Some(line)
}

/// Process `pid`'s stat state letter, read until it is `want` (for up to
/// about a second: another CPU may not have got it there yet).
fn state_becomes(pid: i64, want: u8) -> bool {
    for _ in 0..1000 {
        let mut text = Buf::<4096>::new();
        if read_file(&mut proc_path(pid, b"/stat"), &mut text).is_ok()
            && stat_line(text.bytes()).is_some_and(|l| l.field(3) == [want])
        {
            return true;
        }
        let mut ts = [0u8; 16];
        ts[8..16].copy_from_slice(&1_000_000u64.to_le_bytes());
        sys::nanosleep(&ts, None);
    }
    false
}

/// A held child: started from `me` with `argv`, stopped in a read of
/// its descriptor 0 until `release` closes the write end.
struct Held {
    pid: i64,
    release: i32,
}

fn hold(me: &mut Buf<512>, argv: &[&CStr]) -> Option<Held> {
    let mut input = [-1i32; 2];
    let mut ready = [-1i32; 2];
    if sys::pipe2(&mut input, None) != 0 || sys::pipe2(&mut ready, None) != 0 {
        return None;
    }
    let child = sys::fork();
    if child == 0 {
        sys::dup2(input[0], 0);
        sys::dup2(ready[1], 1);
        for fd in [input[0], input[1], ready[0], ready[1]] {
            sys::close(fd);
        }
        sys::execve(me.c(), Some(argv), &[c"PIDPROBE_HOLD=1"]);
        keel_rt::exit(99);
    }
    sys::close(input[0]);
    sys::close(ready[1]);
    let mut b = [0u8; 1];
    let got = sys::read(ready[0], &mut b);
    sys::close(ready[0]);
    if child < 0 || got != 1 {
        return None;
    }
    Some(Held {
        pid: child,
        release: input[1],
    })
}

/// 1-3: /proc as a directory.
fn root_listing(me: i64, child: i64) -> i32 {
    let fd = open_dir(&mut lit(b"/proc"));
    if fd < 0 {
        return 1;
    }
    let fd = fd as i32;
    let mut st = [0u8; 144];
    let mode = if sys::fstat(fd, &mut st) == 0 {
        u32::from_le_bytes([st[24], st[25], st[26], st[27]])
    } else {
        0
    };
    // 1. ".", "..", the fixed entries (cpuinfo and net among them) up to
    //    position 256, "self" and "thread-self" links, then each PID's
    //    directory in order, each entry's d_off the next one's position
    //    (a PID's is PID + 258) and the last's the end.
    let mut index = 0usize;
    let mut ok = mode == 0o040555;
    let mut prev_off = 0i64;
    let mut stage = 0; // 0 fixed, 1 after self, 2 after thread-self
    let (mut cpuinfo, mut net, mut found_me, mut found_child) = (false, false, false, false);
    let mut last_pid = 0i64;
    let r = each(fd, &mut |name, off, kind| {
        match (index, stage) {
            (0, _) => ok &= name == b"." && kind == DT_DIR && off == 1,
            (1, _) => ok &= name == b".." && kind == DT_DIR && off == 2,
            (_, 0) if name == b"self" => {
                ok &= prev_off == 256 && off == 257 && kind == DT_LNK;
                stage = 1;
            }
            (_, 0) => {
                cpuinfo |= name == b"cpuinfo";
                net |= name == b"net";
                // The next entry's position: the next index, or 256 after
                // the last fixed entry.
                ok &= (off == index as i64 + 1 || off == 256) && parse(name).is_none();
            }
            (_, 1) => {
                ok &= name == b"thread-self" && kind == DT_LNK;
                stage = 2;
            }
            _ => match parse(name) {
                Some(pid) if kind == DT_DIR && pid > last_pid && prev_off == pid + TGID_OFFSET => {
                    found_me |= pid == me;
                    found_child |= pid == child;
                    last_pid = pid;
                }
                _ => ok = false,
            },
        }
        prev_off = off;
        index += 1;
    });
    if r.is_err() || !ok || stage != 2 || prev_off != END || !cpuinfo || !net {
        return 1;
    }
    if !found_me || !found_child {
        return 1;
    }
    // 2. Positions can be gone back to: the entry at 257 is
    //    "thread-self", at PID + 258 that PID, at 0 ".".
    let mut name = Buf::<16>::new();
    name.num(child as u64);
    if first_at(fd, 257).map(|(n, l)| n[..l] == *b"thread-self") != Some(true)
        || first_at(fd, child + TGID_OFFSET).map(|(n, l)| n[..l] == *name.bytes()) != Some(true)
        || first_at(fd, 0).map(|(n, l)| n[..l] == *b".") != Some(true)
    {
        return 2;
    }
    // 3. A buffer too small for the next record is EINVAL; one record's
    //    worth gets that one.
    sys::lseek(fd, 0, 0);
    let mut tiny = [0u8; 23];
    let mut one = [0u8; 24];
    if sys::getdents64(fd, &mut tiny) != EINVAL || sys::getdents64(fd, &mut one) != 24 {
        return 3;
    }
    sys::close(fd);
    0
}

/// 4-5: a process's directory and its task directory.
fn pid_listing(child: i64) -> i32 {
    // 4. ".", "..", then task, comm, cmdline, stat and exe in Linux's
    //    order (`tgid_base_stuff`), with their types; openat relative to
    //    the directory reaches its stat.
    let fd = open_dir(&mut proc_path(child, b""));
    if fd < 0 {
        return 4;
    }
    let want: [(&[u8], u8); 5] = [
        (b"task", DT_DIR),
        (b"comm", DT_REG),
        (b"cmdline", DT_REG),
        (b"stat", DT_REG),
        (b"exe", DT_LNK),
    ];
    let mut next = 0;
    let mut index = 0;
    let mut ok = true;
    let r = each(fd as i32, &mut |name, _, kind| {
        match index {
            0 => ok &= name == b".",
            1 => ok &= name == b"..",
            _ => {
                if let Some(&(n, k)) = want.get(next) {
                    if n == name {
                        ok &= k == kind;
                        next += 1;
                    } else if want.iter().any(|&(w, _)| w == name) {
                        ok = false;
                    }
                }
            }
        }
        index += 1;
    });
    // Its files can be opened relative to it.
    let mut text = Buf::<4096>::new();
    let relative = read_at(fd as i32, c"stat", &mut text).is_ok()
        && stat_line(text.bytes()).is_some_and(|l| l.pid == child);
    sys::close(fd as i32);
    if r.is_err() || !ok || next != want.len() || !relative {
        return 4;
    }
    // 5. Its task directory: ".", "..", and its one thread.
    let fd = open_dir(&mut proc_path(child, b"/task"));
    if fd < 0 {
        return 5;
    }
    let mut names = 0;
    let mut ok = true;
    let mut tid = Buf::<16>::new();
    tid.num(child as u64);
    let r = each(fd as i32, &mut |name, off, kind| {
        let want: &[u8] = match names {
            0 => b".",
            1 => b"..",
            _ => tid.bytes(),
        };
        ok &= name == want && kind == DT_DIR && off == names + 1;
        names += 1;
    });
    sys::close(fd as i32);
    if r.is_err() || !ok || names != 3 {
        return 5;
    }
    0
}

/// 6. Opens: a file as a directory ENOTDIR, a directory for writing
///    EISDIR, a missing PID ENOENT; the files' and directories' modes.
fn opens() -> i32 {
    if sys::open(c"/proc/self/stat", sys::O_RDONLY | O_DIRECTORY, 0) != ENOTDIR
        || sys::open(c"/proc", sys::O_WRONLY, 0) != EISDIR
        || sys::open(c"/proc/self", sys::O_RDWR, 0) != EISDIR
        || sys::open(c"/proc/2147483647/stat", sys::O_RDONLY, 0) != ENOENT
    {
        return 6;
    }
    let mut st = [0u8; 144];
    for (path, want) in [
        (c"/proc/self/stat", 0o100444u32),
        (c"/proc/self/cmdline", 0o100444),
        (c"/proc/self/task", 0o040555),
    ] {
        if sys::stat(path, &mut st) != 0
            || u32::from_le_bytes([st[24], st[25], st[26], st[27]]) != want
        {
            return 6;
        }
    }
    0
}

/// 7-8: /proc/self/stat.
fn self_stat() -> i32 {
    // 7. 52 fields: the PID, the name, running, the parent, group and
    //    session as the calls give them, priority 20 and nice 0, one
    //    thread, an address space, RLIMIT_RSS unlimited. (Resident pages are not checked: Linux's counters
    //    are per CPU and caught up lazily, so a small program can read
    //    0.)
    let mut text = Buf::<4096>::new();
    if read_file(&mut lit(b"/proc/self/stat"), &mut text).is_err() {
        return 7;
    }
    let Some(l) = stat_line(text.bytes()) else {
        return 7;
    };
    if l.fields != 52
        || l.pid != sys::getpid()
        || l.comm != b"pidprobe"
        || l.field(3) != b"R"
        || l.num(4) != Some(sys::getppid())
        || l.num(5) != Some(sys::getpgid(0))
        || l.num(6) != Some(sys::getsid(0))
        || l.num(18) != Some(20)
        || l.num(19) != Some(0)
        || l.num(20) != Some(1)
        || l.num(23).is_none_or(|v| v <= 0)
        || l.field(25) != b"18446744073709551615"
    {
        report(b"self stat", text.bytes());
        return 7;
    }
    // 8. In a new session there is no terminal (tty_nr 0, tpgid -1) and
    //    the process leads both; a name with ") (" in it is shown whole;
    //    a forked process's exit signal is SIGCHLD.
    let child = sys::fork();
    if child == 0 {
        sys::setsid();
        let mut name = [0u8; 16];
        name[..5].copy_from_slice(b"a) (b");
        sys::prctl_name(PR_SET_NAME, &mut name);
        let mut text = Buf::<4096>::new();
        let mut path = Buf::<128>::new();
        path.put(b"/proc/self/stat");
        let pid = sys::getpid();
        let good = read_file(&mut path, &mut text).is_ok()
            && stat_line(text.bytes()).is_some_and(|l| {
                l.comm == b"a) (b"
                    && l.num(5) == Some(pid)
                    && l.num(6) == Some(pid)
                    && l.num(7) == Some(0)
                    && l.num(8) == Some(-1)
                    && l.num(38) == Some(17)
            });
        if !good {
            report(b"session stat", text.bytes());
        }
        keel_rt::exit(if good { 0 } else { 1 });
    }
    let mut status = 0;
    if sys::wait4(child as i32, &mut status, 0) != child || status != 0 {
        return 8;
    }
    0
}

fn report(what: &[u8], got: &[u8]) {
    sys::writev(2, &[b"pidprobe: ", what, b"\n", got, b"\n"]);
}

/// 9-11: another process's stat and cmdline, as it runs, stops, and
/// becomes a zombie.
fn child_files(me: &mut Buf<512>, held: &Held, own_cmdline: &[u8]) -> i32 {
    // 9. Its argv as exec gave it, each string with its NUL (an empty one
    //    too); its stat: its PID, the program's name, sleeping in its
    //    read, this process its parent, in this one's group and session.
    let mut want = Buf::<4096>::new();
    want.put(me.bytes()).put(b"\0a b\0\0c\0");
    let mut got = Buf::<4096>::new();
    if read_file(&mut proc_path(held.pid, b"/cmdline"), &mut got).is_err()
        || got.bytes() != want.bytes()
    {
        report(b"cmdline", got.bytes());
        return 9;
    }
    if !state_becomes(held.pid, b'S') {
        return 9;
    }
    let mut text = Buf::<4096>::new();
    if read_file(&mut proc_path(held.pid, b"/stat"), &mut text).is_err() {
        return 9;
    }
    let good = stat_line(text.bytes()).is_some_and(|l| {
        l.fields == 52
            && l.pid == held.pid
            && l.comm == b"pidprobe"
            && l.num(4) == Some(sys::getpid())
            && l.num(5) == Some(sys::getpgid(0))
            && l.num(6) == Some(sys::getsid(0))
    });
    if !good {
        report(b"child stat", text.bytes());
        return 9;
    }
    // 10. Stopped, it is T; continued, S again. A forked child's cmdline
    //     is its parent's.
    let mut status = 0;
    if sys::kill(held.pid as i32, SIGSTOP) != 0
        || sys::wait4(held.pid as i32, &mut status, WUNTRACED) != held.pid
        || !state_becomes(held.pid, b'T')
        || sys::kill(held.pid as i32, SIGCONT) != 0
        || !state_becomes(held.pid, b'S')
    {
        return 10;
    }
    let mut ready = [-1i32; 2];
    if sys::pipe2(&mut ready, None) != 0 {
        return 10;
    }
    let forked = sys::fork();
    if forked == 0 {
        sys::close(ready[1]);
        let mut b = [0u8; 1];
        sys::read(ready[0], &mut b);
        keel_rt::exit(0);
    }
    sys::close(ready[0]);
    let mut got = Buf::<4096>::new();
    let same = read_file(&mut proc_path(forked, b"/cmdline"), &mut got).is_ok()
        && got.bytes() == own_cmdline;
    sys::close(ready[1]);
    sys::wait4(forked as i32, &mut status, 0);
    if !same {
        report(b"forked cmdline", got.bytes());
        return 10;
    }
    // 11. Exited and not yet reaped, it is Z, and its cmdline is empty;
    //     reaped, it is gone from /proc.
    sys::close(held.release);
    if !state_becomes(held.pid, b'Z') {
        return 11;
    }
    let mut got = Buf::<4096>::new();
    if read_file(&mut proc_path(held.pid, b"/cmdline"), &mut got).is_err() || got.len != 0 {
        return 11;
    }
    if sys::wait4(held.pid as i32, &mut status, 0) != held.pid || status != 0 {
        return 11;
    }
    if sys::open(proc_path(held.pid, b"/stat").c(), sys::O_RDONLY, 0) != ENOENT {
        return 11;
    }
    let fd = open_dir(&mut lit(b"/proc"));
    let mut listed = false;
    let mut name = Buf::<16>::new();
    name.num(held.pid as u64);
    let r = each(fd as i32, &mut |n, _, _| listed |= n == name.bytes());
    sys::close(fd as i32);
    if fd < 0 || r.is_err() || listed {
        return 11;
    }
    0
}

fn main(startup: &Startup) -> i32 {
    if startup.env().any(|e| e.starts_with(b"PIDPROBE_HOLD=")) {
        sys::write(1, b"r");
        let mut b = [0u8; 16];
        while sys::read(0, &mut b) > 0 {}
        return 0;
    }
    // This program's absolute path, to run it again.
    let arg0 = startup.args().next().unwrap_or(b"");
    let mut me = Buf::<512>::new();
    if arg0.first() != Some(&b'/') {
        let mut cwd = [0u8; 256];
        if sys::getcwd(&mut cwd) > 0 {
            let len = cwd.iter().position(|&c| c == 0).unwrap_or(0);
            me.put(&cwd[..len]).put(b"/");
        }
    }
    me.put(arg0.strip_prefix(b"./").unwrap_or(arg0));
    let mut own = Buf::<4096>::new();
    for a in startup.args() {
        own.put(a).put(b"\0");
    }
    let mut path = Buf::<512>::new();
    path.put(me.bytes());
    let mut arg = Buf::<512>::new();
    arg.put(me.bytes());
    let Some(held) = hold(&mut path, &[arg.c(), c"a b", c"", c"c"]) else {
        return 100;
    };
    let mut result = root_listing(sys::getpid(), held.pid);
    if result == 0 {
        result = pid_listing(held.pid);
    }
    if result == 0 {
        result = opens();
    }
    if result == 0 {
        result = self_stat();
    }
    if result == 0 {
        result = child_files(&mut me, &held, own.bytes());
    } else {
        sys::close(held.release);
        let mut status = 0;
        sys::wait4(held.pid as i32, &mut status, 0);
    }
    if result == 0 {
        sys::write(1, b"pidprobe: 11 checks passed\n");
    }
    result
}

keel_rt::main!(main);
