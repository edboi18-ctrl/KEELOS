//! The procfs subset (P3-T9, ADR 0024): `/proc` as the Wine traces use
//! it, mounted over every process's `/proc` (whatever its tree holds
//! there), and seen per compartment: `/proc/<pid>` exists only for the
//! caller's compartment's PIDs, as in a Linux PID namespace (ADR 0014).
//!
//! Absolute paths reach it: `/proc...` after `.`, `..` and repeated
//! slashes are taken out lexically. So do paths relative to a procfs
//! directory's descriptor (ADR 0037), as the directory's path and the
//! relative one, whose `..` stops at that directory as with any directory
//! handle (ADR 0012). A working directory in `/proc` is not supported.
//! Its nodes and the file formats are `keel_core::procfs`'s.
//!
//! A compartment's processes are its running ones and its zombies (ADR
//! 0037), as a PID namespace's: a zombie stays until its parent reaps
//! it.

use alloc::sync::Arc;
use alloc::vec::Vec;

use keel_core::errno::Errno;
use keel_core::procfs::{self, Kind, Node, Resolved, View};
use keel_core::vfs::{Ino, S_IFDIR, S_IFLNK, S_IFREG, Stat};
use keel_hal::sched;
use keel_hal::sync::IrqMutex;

use crate::fs;
use crate::process::{self, Process};

type ProcessRef = Arc<IrqMutex<Process>>;

/// What a path names, once procfs has looked at it.
pub enum Hit {
    /// A procfs node.
    Node(Node),
    /// A real file: an `exe` link followed.
    Real(Ino),
}

/// The components of `path` after `/proc`, if `path` is absolute and lies
/// in `/proc` once `.`, `..` and empty components are taken out; and
/// whether it ended in `/`.
fn split(path: &[u8]) -> Option<(Vec<&[u8]>, bool)> {
    if path.first() != Some(&b'/') {
        return None;
    }
    let mut parts: Vec<&[u8]> = Vec::new();
    for c in path.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    if parts.first() != Some(&&b"proc"[..]) {
        return None;
    }
    let slash = path.len() > 1 && path.last() == Some(&b'/');
    Some((parts[1..].to_vec(), slash))
}

/// The caller as procfs sees it.
struct Caller<'a> {
    p: &'a ProcessRef,
}

impl View for Caller<'_> {
    fn me(&self) -> (u32, u32) {
        let process = self.p.lock();
        let tid = process
            .threads
            .get(&sched::current().0)
            .map_or(process.pid(), |t| t.tid);
        (process.pid(), tid)
    }

    fn has_pid(&self, pid: u32) -> bool {
        target(self.p, pid).is_some()
    }

    fn has_task(&self, pid: u32, tid: u32) -> bool {
        target(self.p, pid).is_some_and(|t| t.lock().threads.values().any(|th| th.tid == tid))
    }

    /// A zombie has no program (`proc_exe_link`: no mm, ENOENT).
    fn exe(&self, pid: u32) -> Option<Vec<u8>> {
        target(self.p, pid).and_then(|t| {
            let t = t.lock();
            t.space.is_some().then(|| t.exe.clone())
        })
    }

    fn pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = visible(self.p).iter().map(|t| t.lock().pid()).collect();
        pids.sort_unstable();
        pids.dedup();
        pids
    }

    fn tasks(&self, pid: u32) -> Vec<u32> {
        target(self.p, pid).map_or_else(Vec::new, |t| {
            let t = t.lock();
            let mut tids: Vec<u32> = t.threads.values().map(|th| th.tid).collect();
            // The first thread (TID = PID) first, then by creation (TIDs
            // count up): `first_tid`, `next_thread`.
            tids.sort_unstable_by_key(|&tid| (tid != pid, tid));
            tids
        })
    }
}

/// The caller's compartment's processes: the running ones and the
/// zombies.
fn visible(p: &ProcessRef) -> Vec<ProcessRef> {
    let compartment = p.lock().member.compartment().clone();
    let mut all = process::members(&compartment, |_| true);
    all.extend(process::zombies(&compartment, |_| true));
    all
}

/// Process `pid` of the caller's compartment, running or a zombie.
fn target(p: &ProcessRef, pid: u32) -> Option<ProcessRef> {
    let (compartment, mine) = {
        let process = p.lock();
        (process.member.compartment().clone(), process.pid())
    };
    if pid == mine {
        return Some(p.clone());
    }
    process::find_in(&compartment, pid)
        .or_else(|| process::zombies(&compartment, |z| z.pid() == pid).pop())
}

/// Looks `path` up in procfs: None if it is not a `/proc` path; else the
/// node or the real file it names, ENOENT if nothing, ENOTDIR for a
/// trailing slash after something that is not a directory.
pub fn lookup(p: &ProcessRef, path: &[u8], follow: bool) -> Option<Result<Hit, Errno>> {
    let (rest, slash) = split(path)?;
    Some(resolve(p, &rest, follow || slash, slash))
}

fn resolve(p: &ProcessRef, rest: &[&[u8]], follow: bool, slash: bool) -> Result<Hit, Errno> {
    match procfs::resolve(rest, follow, &Caller { p }) {
        Resolved::Node(node) => {
            if slash && node.kind() != Kind::Directory {
                return Err(Errno::ENOTDIR);
            }
            Ok(Hit::Node(node))
        }
        Resolved::Elsewhere(real) => {
            let (root, cwd) = {
                let process = p.lock();
                (process.root, process.cwd)
            };
            fs::with(|fs| fs.resolve(root, cwd, &real, true)).map(Hit::Real)
        }
        Resolved::Missing => Err(Errno::ENOENT),
    }
}

/// A stable inode number for `node`, in a range tmpfs never reaches
/// (its numbers count up from 0).
fn ino(node: Node) -> Ino {
    let (tag, a, b): (u64, u32, u32) = match node {
        Node::Root => (1, 0, 0),
        Node::SelfLink => (2, 0, 0),
        Node::ThreadSelf => (3, 0, 0),
        Node::CpuInfo => (4, 0, 0),
        Node::Net => (5, 0, 0),
        Node::NetDev => (6, 0, 0),
        Node::Pid(p) => (7, p, 0),
        Node::Exe(p) => (8, p, 0),
        Node::Comm(p) => (9, p, 0),
        Node::Tasks(p) => (10, p, 0),
        Node::Task(p, t) => (11, p, t),
        Node::TaskComm(p, t) => (12, p, t),
        Node::Cmdline(p) => (13, p, 0),
        Node::Stat(p) => (14, p, 0),
    };
    (0xFFFF << 48) | (tag << 44) | (u64::from(a & 0x3f_ffff) << 22) | u64::from(b & 0x3f_ffff)
}

/// stat of a procfs node: its type and procfs's mode, size 0 (procfs
/// files report no size: their contents are made when read), 2 links for
/// a directory and 1 otherwise, every time now.
pub fn stat(node: Node) -> Stat {
    let kind = match node.kind() {
        Kind::Directory => S_IFDIR,
        Kind::Symlink => S_IFLNK,
        Kind::File => S_IFREG,
    };
    let now = fs::with(|fs| Ok(fs.time_now())).unwrap_or_default();
    Stat {
        ino: ino(node),
        mode: kind | node.permissions(),
        size: 0,
        nlink: if node.kind() == Kind::Directory { 2 } else { 1 },
        rdev: (0, 0),
        atime: now,
        mtime: now,
        ctime: now,
    }
}

/// readlink of a procfs node: EINVAL if it is not a link.
pub fn readlink(p: &ProcessRef, node: Node) -> Result<Vec<u8>, Errno> {
    if node.kind() != Kind::Symlink {
        return Err(Errno::EINVAL);
    }
    procfs::link_target(node, &Caller { p }).ok_or(Errno::ENOENT)
}

/// The name of thread `tid` of process `pid`, with its newline
/// (`comm_show`), and where a write to it goes.
fn comm(p: &ProcessRef, pid: u32, tid: u32) -> Result<(Vec<u8>, process::CommTarget), Errno> {
    let t = target(p, pid).ok_or(Errno::ENOENT)?;
    let process = t.lock();
    let (&thread, info) = process
        .threads
        .iter()
        .find(|(_, th)| th.tid == tid)
        .ok_or(Errno::ENOENT)?;
    let mut text = info.comm.clone();
    text.push(b'\n');
    drop(process);
    Ok((
        text,
        process::CommTarget {
            process: Arc::downgrade(&t),
            thread,
            own: Arc::ptr_eq(&t, p),
        },
    ))
}

/// What a regular procfs file holds when opened, and for `comm` where
/// writes go.
pub fn contents(
    p: &ProcessRef,
    node: Node,
) -> Result<(Vec<u8>, Option<process::CommTarget>), Errno> {
    match node {
        Node::CpuInfo => {
            let khz = keel_hal::time::tsc_hz() / 1000;
            let text = procfs::cpuinfo(&keel_hal::arch::x86_64::cpu::cpuid, khz, 1);
            Ok((text.into_bytes(), None))
        }
        Node::NetDev => Ok((procfs::NET_DEV.as_bytes().to_vec(), None)),
        Node::Comm(pid) => comm(p, pid, pid).map(|(t, c)| (t, Some(c))),
        Node::Cmdline(pid) => {
            let t = target(p, pid).ok_or(Errno::ENOENT)?;
            let t = t.lock();
            // `get_mm_cmdline`: nothing without an address space.
            let text = if t.space.is_some() {
                t.cmdline.clone()
            } else {
                Vec::new()
            };
            Ok((text, None))
        }
        Node::Stat(pid) => {
            let t = target(p, pid).ok_or(Errno::ENOENT)?;
            Ok((procfs::stat_line(&stat_info(p, &t)), None))
        }
        Node::TaskComm(pid, tid) => comm(p, pid, tid).map(|(t, c)| (t, Some(c))),
        _ => Err(Errno::EISDIR),
    }
}

/// A write to a `comm` file (`comm_write`): the first 15 bytes (or fewer)
/// of `data`, up to any NUL, become the thread's name; the whole count is
/// returned. EINVAL for a thread of another process; ESRCH if it is gone.
pub fn write_comm(target: &process::CommTarget, data: &[u8]) -> Result<usize, Errno> {
    if !target.own {
        return Err(Errno::EINVAL);
    }
    let t = target.process.upgrade().ok_or(Errno::ESRCH)?;
    let mut process = t.lock();
    let info = process
        .threads
        .get_mut(&target.thread)
        .ok_or(Errno::ESRCH)?;
    let take = &data[..data.len().min(15)];
    let end = take.iter().position(|&b| b == 0).unwrap_or(take.len());
    info.comm = take[..end].to_vec();
    Ok(data.len())
}

/// open(2) of a `/proc` path, or None if `path` is not one:
/// - a regular file opens as a snapshot of its contents as of now (Linux
///   makes them as they are read: `seq_file`), positioned and seekable;
///   only `comm` may be opened for writing (EACCES for the others, whose
///   mode is 0444);
/// - O_CREAT on a missing name EACCES (procfs makes no files); O_CREAT
///   with O_EXCL on an existing one EEXIST;
/// - O_NOFOLLOW on a link ELOOP; a followed `exe` link opens the program
///   in the real tree;
/// - as `do_open`: O_DIRECTORY on something not a directory ENOTDIR;
///   then a directory opened with O_CREAT, or for writing, EISDIR
///   (`may_open`); else it opens to be listed (ADR 0037), not to be a
///   working directory.
pub fn open(p: &ProcessRef, path: &[u8], flags: u64) -> Option<Result<Hit, Errno>> {
    use crate::abi::{O_ACCMODE, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_RDONLY};
    let follow = flags & O_NOFOLLOW == 0 && !(flags & O_CREAT != 0 && flags & O_EXCL != 0);
    let hit = match lookup(p, path, follow)? {
        Err(Errno::ENOENT) if flags & O_CREAT != 0 => return Some(Err(Errno::EACCES)),
        other => other,
    };
    Some(hit.and_then(|hit| {
        if flags & O_CREAT != 0 && flags & O_EXCL != 0 {
            return Err(Errno::EEXIST);
        }
        if let Hit::Node(node) = &hit {
            if flags & O_DIRECTORY != 0 && node.kind() == Kind::File {
                return Err(Errno::ENOTDIR);
            }
            match node.kind() {
                Kind::Symlink => return Err(Errno::ELOOP),
                Kind::Directory => {
                    if flags & O_CREAT != 0 || flags & O_ACCMODE != O_RDONLY {
                        return Err(Errno::EISDIR);
                    }
                }
                Kind::File => {
                    let writes = flags & O_ACCMODE != O_RDONLY;
                    if writes && !matches!(node, Node::Comm(_) | Node::TaskComm(..)) {
                        return Err(Errno::EACCES);
                    }
                }
            }
        }
        Ok(hit)
    }))
}

/// What `/proc/<pid>/stat` shows of `t` (`do_task_stat`), read by `p`:
/// - **state:** Z for a zombie, T if stopped, R for the reader itself,
///   else S. Keel's scheduler does not say whether another thread is
///   runnable: one waiting for the CPU reads as S, where Linux gives R;
/// - **the name** is the first thread's;
/// - **the parent:** its PID, 0 for a process the kernel started or
///   whose parent has gone (getppid's rule);
/// - **the terminal:** its device number and foreground group, or 0 and
///   -1 without one;
/// - **the start** in clock ticks since boot; the address space's size
///   and resident pages; the initial stack pointer and the break's
///   start;
/// - **signals:** the first thread's pending and blocked sets, and the
///   dispositions ignored and caught;
/// - **wchan** 1 for a single-threaded process not running;
/// - **the exit signal** SIGCHLD for a forked process, 0 for one the
///   kernel started (as Linux's `kernel_init`);
/// - **the exit code** a zombie's wait status.
pub fn stat_info(p: &ProcessRef, t: &ProcessRef) -> procfs::StatInfo {
    use keel_core::signal::{NSIG, SIG_DFL, SIG_IGN};
    let reader = Arc::ptr_eq(p, t);
    let parent = t
        .lock()
        .parent
        .as_ref()
        .and_then(alloc::sync::Weak::upgrade);
    let ppid = parent.as_ref().map_or(0, |q| q.lock().pid());
    let process = t.lock();
    let pid = process.pid();
    let first = process
        .threads
        .values()
        .find(|th| th.tid == pid)
        .or_else(|| process.threads.values().next());
    let zombie = process.space.is_none();
    let state = if zombie {
        b'Z'
    } else if process.stopped {
        b'T'
    } else if reader {
        b'R'
    } else {
        b'S'
    };
    let (tty_nr, tpgid) = crate::tty::stat_fields(process.ctty.as_ref());
    let (mut ignored, mut caught) = (0u64, 0u64);
    for sig in 1..=NSIG as i32 {
        match process.signals.action(sig).map(|a| a.handler) {
            Some(SIG_IGN) => ignored |= 1 << (sig - 1),
            Some(SIG_DFL) | None => {}
            Some(_) => caught |= 1 << (sig - 1),
        }
    }
    let (vsize, rss) = process
        .space
        .as_ref()
        .map_or((0, 0), |s| (s.mapped_bytes(), s.resident_bytes() / 4096));
    let threads = process.threads.len() as u32;
    procfs::StatInfo {
        pid,
        comm: first.map_or_else(|| process.exit_comm.clone(), |th| th.comm.clone()),
        state,
        ppid,
        pgid: process.pgid,
        sid: process.sid,
        tty_nr,
        tpgid,
        num_threads: threads,
        // USER_HZ 100: one tick is 10 ms.
        start_time: process.started / 10_000_000,
        vsize,
        rss,
        start_stack: process.start_stack,
        start_brk: process.brk_start,
        pending: first.map_or(0, |th| th.signals.pending.set()),
        blocked: first.map_or(0, |th| th.signals.blocked()),
        ignored,
        caught,
        wchan: u64::from(state != b'R' && threads < 2),
        exit_signal: if process.parent.is_some() { 17 } else { 0 },
        exit_code: process.exit_status.unwrap_or(0),
    }
}

/// The getdents64 records of procfs directory `dir` from position `from`
/// (`linux_dirent64`, as `fscalls::getdents64` writes them): what fits in
/// `count` bytes (EINVAL if not even the first), and the position to go
/// on from. ENOENT once a process directory's process is gone
/// (`proc_pident_readdir`, `proc_task_readdir`).
pub fn getdents(
    p: &ProcessRef,
    dir: Node,
    from: u64,
    count: usize,
) -> Result<(Vec<u8>, u64), Errno> {
    let view = Caller { p };
    let gone = match dir {
        Node::Pid(pid) | Node::Tasks(pid) => !view.has_pid(pid),
        Node::Task(pid, tid) => !view.has_task(pid, tid),
        _ => false,
    };
    if gone {
        return Err(Errno::ENOENT);
    }
    let (entries, end) = procfs::list(dir, &view);
    let root = p.lock().root;
    let mut out = Vec::new();
    let mut at = from;
    let start = entries
        .iter()
        .position(|e| e.pos >= from)
        .unwrap_or(entries.len());
    for (i, e) in entries.iter().enumerate().skip(start) {
        let next = entries.get(i + 1).map_or(end, |n| n.pos);
        let (ino, kind) = match e.node {
            Some(node) => (stat(node).ino, node.kind()),
            None => (root, Kind::Directory),
        };
        let d_type = match kind {
            Kind::Directory => 4,
            Kind::File => 8,
            Kind::Symlink => 10,
        };
        let reclen = (19 + e.name.len() + 1).next_multiple_of(8);
        if out.len() + reclen > count {
            if out.is_empty() {
                return Err(Errno::EINVAL);
            }
            return Ok((out, at));
        }
        let s = out.len();
        out.resize(s + reclen, 0);
        out[s..s + 8].copy_from_slice(&(ino + 1).to_le_bytes());
        out[s + 8..s + 16].copy_from_slice(&next.to_le_bytes());
        out[s + 16..s + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
        out[s + 18] = d_type;
        out[s + 19..s + 19 + e.name.len()].copy_from_slice(&e.name);
        at = next;
    }
    Ok((out, at))
}

/// The absolute path a lookup of `path` relative to procfs directory
/// `dir` names: the directory's path, then `path`'s components, `..`
/// stopping at `dir` (a directory handle is its lookups' root, ADR 0012).
pub fn relative(dir: Node, path: &[u8]) -> Option<Vec<u8>> {
    let base = procfs::path_of(dir)?.into_bytes();
    let depth = base.split(|&b| b == b'/').filter(|c| !c.is_empty()).count();
    let mut parts: Vec<&[u8]> = base
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .collect();
    for c in path.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                if parts.len() > depth {
                    parts.pop();
                }
            }
            c => parts.push(c),
        }
    }
    let mut out = Vec::new();
    for c in parts {
        out.push(b'/');
        out.extend_from_slice(c);
    }
    if path.last() == Some(&b'/') {
        out.push(b'/');
    }
    Some(out)
}

/// statfs(2) for procfs (`simple_statfs` with PROC_SUPER_MAGIC 0x9fa0):
/// 4096-byte blocks, no counts, NAME_MAX 255; the flags of /proc as
/// systemd mounts it (nosuid, nodev, noexec, relatime) and ST_VALID.
pub fn statfs_bytes() -> [u8; 120] {
    const PROC_SUPER_MAGIC: u64 = 0x9fa0;
    const ST_VALID_NOSUID_NODEV_NOEXEC_RELATIME: u64 = 0x20 | 0x2 | 0x4 | 0x8 | 0x400;
    let mut b = [0u8; 120];
    b[0..8].copy_from_slice(&PROC_SUPER_MAGIC.to_le_bytes());
    b[8..16].copy_from_slice(&4096u64.to_le_bytes());
    b[64..72].copy_from_slice(&255u64.to_le_bytes());
    b[72..80].copy_from_slice(&4096u64.to_le_bytes());
    b[80..88].copy_from_slice(&ST_VALID_NOSUID_NODEV_NOEXEC_RELATIME.to_le_bytes());
    b
}

/// prctl(2) (`kernel/sys.c`): PR_SET_NAME (15) sets the calling thread's
/// name from at most 15 bytes at `arg2`, up to a NUL
/// (`strncpy_from_user(comm, arg2, 15)`; EFAULT if unreadable);
/// PR_GET_NAME (16) writes the name as 16 bytes, padded with NULs. Every
/// other option is EINVAL, the default branch (PR_SET_PTRACER among them:
/// only the Yama security module knows it).
pub fn prctl(p: &ProcessRef, option: u64, arg2: u64) -> Result<u64, Errno> {
    const PR_SET_NAME: u64 = 15;
    const PR_GET_NAME: u64 = 16;
    let me = sched::current().0;
    match option & 0xffff_ffff {
        PR_SET_NAME => {
            let mut name = Vec::new();
            for i in 0..15 {
                let mut b = [0u8; 1];
                keel_hal::vm::copy_from_user(&mut b, arg2 + i).map_err(|_| Errno::EFAULT)?;
                if b[0] == 0 {
                    break;
                }
                name.push(b[0]);
            }
            if let Some(t) = p.lock().threads.get_mut(&me) {
                t.comm = name;
            }
            Ok(0)
        }
        PR_GET_NAME => {
            let mut out = [0u8; 16];
            if let Some(t) = p.lock().threads.get(&me) {
                let n = t.comm.len().min(15);
                out[..n].copy_from_slice(&t.comm[..n]);
            }
            keel_hal::vm::copy_to_user(arg2, &out).map_err(|_| Errno::EFAULT)?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}
