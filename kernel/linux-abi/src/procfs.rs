//! The procfs subset (P3-T9, ADR 0024): `/proc` as the Wine traces use
//! it, mounted over every process's `/proc` (whatever its tree holds
//! there), and seen per compartment: `/proc/<pid>` exists only for the
//! caller's compartment's PIDs, as in a Linux PID namespace (ADR 0014).
//!
//! Only absolute paths reach it: `/proc...` after `.`, `..` and repeated
//! slashes are taken out lexically. A path relative to a directory inside
//! `/proc`, or a working directory there, is not supported (no descriptor
//! or working directory can name a procfs directory). Its nodes and the
//! file formats are `keel_core::procfs`'s.

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

    fn exe(&self, pid: u32) -> Option<Vec<u8>> {
        target(self.p, pid).map(|t| t.lock().exe.clone())
    }
}

/// Process `pid` of the caller's compartment.
fn target(p: &ProcessRef, pid: u32) -> Option<ProcessRef> {
    let (compartment, mine) = {
        let process = p.lock();
        (process.member.compartment().clone(), process.pid())
    };
    if pid == mine {
        return Some(p.clone());
    }
    process::find_in(&compartment, pid)
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
/// - a directory cannot be opened yet (EACCES), so none can be listed or
///   used as a working directory (ADR 0024).
pub fn open(p: &ProcessRef, path: &[u8], flags: u64) -> Option<Result<Hit, Errno>> {
    use crate::abi::{O_ACCMODE, O_CREAT, O_EXCL, O_NOFOLLOW, O_RDONLY};
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
            match node.kind() {
                Kind::Symlink => return Err(Errno::ELOOP),
                Kind::Directory => return Err(Errno::EACCES),
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
