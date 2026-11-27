//! Filesystem system calls (P3-T8, ADR 0022): status, the namespace
//! (directories, links, symbolic links, rename), metadata (permissions,
//! times, the umask), the working directory, `lseek` and `getdents64`.
//! The rules are Linux v6.12's (`fs/namei.c`, `fs/stat.c`, `fs/open.c`,
//! `fs/utimes.c`, `fs/readdir.c`, `fs/d_path.c`, `fs/read_write.c`,
//! `fs/libfs.c`, `mm/shmem.c`); each function names the parts it follows.
//!
//! Paths start where openat's do (ADR 0012): AT_FDCWD or an absolute path
//! at the process's working directory and root; a path relative to a
//! directory handle at that directory, which is then also the root, so
//! `..` stops there (as openat2's RESOLVE_IN_ROOT). A lookup through a
//! handle needs ENUMERATE on it, and a change to the names in it (create,
//! remove, rename, link) CREATE too.
//!
//! No user memory is read or written while the filesystem lock is held: a
//! copy can fault, and the fault path may read a mapped file under that
//! lock.

use alloc::sync::Arc;
use alloc::vec::Vec;

use keel_core::errno::Errno;
use keel_core::handle::Rights;
use keel_core::vfs::{self, Ino, Kind, Last, Parent, Timespec};
use keel_hal::sync::IrqMutex;
use keel_hal::vm::{copy_from_user, copy_to_user};

use crate::abi::{AT_FDCWD, stat_bytes};
use crate::fs;
use crate::process::Object;
use crate::process::Process;
use crate::syscall::{fault, file, file_or, object, quota_of, user_path};

type SysResult = Result<u64, Errno>;
type ProcessRef = Arc<IrqMutex<Process>>;

/// `*at` flags (`include/uapi/linux/fcntl.h`).
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const AT_REMOVEDIR: u32 = 0x200;
pub const AT_EACCESS: u32 = 0x200;
pub const AT_SYMLINK_FOLLOW: u32 = 0x400;
pub const AT_NO_AUTOMOUNT: u32 = 0x800;
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// lseek whence (`include/uapi/linux/fs.h`).
const SEEK_SET: u32 = 0;
const SEEK_CUR: u32 = 1;
const SEEK_END: u32 = 2;
const SEEK_DATA: u32 = 3;
const SEEK_HOLE: u32 = 4;

/// access(2) modes (`include/uapi/linux/fcntl.h` and unistd.h).
const X_OK: u32 = 1;

/// utimensat special nanoseconds (`include/linux/stat.h`).
const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

/// The largest file offset, `MAX_LFS_FILESIZE` on 64-bit
/// (`include/linux/fs.h`: `LLONG_MAX`).
const MAX_LFS_FILESIZE: u64 = i64::MAX as u64;

/// The directory open on `fd`, checked as Linux checks it: a handle that
/// is not a directory is ENOTDIR (its type is checked first, as
/// `iterate_dir` and `fchdir` do), and only then must it have ENUMERATE
/// (EBADF without, as every missing right).
fn directory(p: &ProcessRef, fd: i32) -> Result<Arc<IrqMutex<crate::process::OpenFile>>, Errno> {
    if file_or(p, fd, Rights::NONE, Errno::ENOTDIR)?.lock().kind != Kind::Directory {
        return Err(Errno::ENOTDIR);
    }
    file(p, fd, Rights::ENUMERATE)
}

/// The absolute `/proc` path a lookup of relative `path` from `dirfd`
/// names, if `dirfd` is a procfs directory (ADR 0037); `..` stops at that
/// directory, as at any directory handle (ADR 0012).
pub(crate) fn in_proc_dir(p: &ProcessRef, dirfd: i32, path: &[u8]) -> Option<Vec<u8>> {
    if dirfd == AT_FDCWD || path.is_empty() || path.first() == Some(&b'/') {
        return None;
    }
    let dir = file_or(p, dirfd, Rights::NONE, Errno::ENOTDIR)
        .ok()?
        .lock()
        .proc?;
    crate::procfs::relative(dir, path)
}

/// Where a lookup of `path` relative to `dirfd` starts: `(root, base)`.
/// Other calls than open, stat, readlink and access relative to a procfs
/// directory are EACCES: procfs makes, removes and renames nothing.
/// `modify` asks for CREATE on a directory handle as well as ENUMERATE.
fn start(p: &ProcessRef, dirfd: i32, path: &[u8], modify: bool) -> Result<(Ino, Ino), Errno> {
    let (root, cwd) = {
        let process = p.lock();
        (process.root, process.cwd)
    };
    if dirfd == AT_FDCWD || path.first() == Some(&b'/') {
        return Ok((root, cwd));
    }
    let needs = if modify {
        Rights::ENUMERATE | Rights::CREATE
    } else {
        Rights::ENUMERATE
    };
    // A pipe or eventfd is not a directory, whatever its rights.
    file_or(p, dirfd, Rights::NONE, Errno::ENOTDIR)?;
    let dir = file(p, dirfd, needs)?;
    let dir = dir.lock();
    if dir.kind != Kind::Directory {
        return Err(Errno::ENOTDIR);
    }
    if dir.proc.is_some() {
        return Err(Errno::EACCES);
    }
    Ok((dir.node, dir.node))
}

/// The node `path` names relative to `dirfd`; an empty path with
/// AT_EMPTY_PATH is the handle itself (which then needs STAT), without it
/// ENOENT.
pub(crate) fn node_at(
    p: &ProcessRef,
    dirfd: i32,
    path: &[u8],
    follow: bool,
    empty: bool,
) -> Result<Ino, Errno> {
    if path.is_empty() {
        if !empty {
            return Err(Errno::ENOENT);
        }
        if dirfd == AT_FDCWD {
            return Ok(p.lock().cwd);
        }
        return Ok(file(p, dirfd, Rights::STAT)?.lock().node);
    }
    let (root, base) = start(p, dirfd, path, false)?;
    fs::with(|fs| fs.resolve(root, base, path, follow))
}

/// A path argument that may be empty (with AT_EMPTY_PATH): user_path
/// refuses nothing itself, but a lookup of "" is ENOENT.
fn path_arg(address: u64) -> Result<Vec<u8>, Errno> {
    user_path(address)
}

fn put_stat(node: Ino, buf: u64) -> SysResult {
    let stat = fs::with(|fs| fs.stat(node))?;
    copy_to_user(buf, &stat_bytes(&stat)).map_err(fault)?;
    Ok(0)
}

/// stat(2): newfstatat(AT_FDCWD, path, buf, 0).
pub fn stat(p: &ProcessRef, path: u64, buf: u64) -> SysResult {
    newfstatat(p, AT_FDCWD, path, buf, 0)
}

/// lstat(2): newfstatat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW).
pub fn lstat(p: &ProcessRef, path: u64, buf: u64) -> SysResult {
    newfstatat(p, AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW)
}

/// newfstatat(2) (`vfs_fstatat`, `vfs_statx`): flags other than
/// AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT and AT_EMPTY_PATH are EINVAL.
pub fn newfstatat(p: &ProcessRef, dirfd: i32, path: u64, buf: u64, flags: u32) -> SysResult {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    let path = path_arg(path)?;
    let path = in_proc_dir(p, dirfd, &path).unwrap_or(path);
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    if let Some(hit) = crate::procfs::lookup(p, &path, follow) {
        return match hit? {
            crate::procfs::Hit::Node(node) => {
                let b =
                    crate::abi::stat_bytes_on(&crate::procfs::stat(node), crate::abi::PROCFS_DEV);
                copy_to_user(buf, &b).map_err(fault)?;
                Ok(0)
            }
            crate::procfs::Hit::Real(ino) => put_stat(ino, buf),
        };
    }
    if path.is_empty() && flags & AT_EMPTY_PATH != 0 && dirfd != AT_FDCWD {
        let target = object(p, dirfd, Rights::STAT)?;
        if let Object::File(f) = &target
            && let Some(node) = f.lock().proc
        {
            let b = crate::abi::stat_bytes_on(&crate::procfs::stat(node), crate::abi::PROCFS_DEV);
            copy_to_user(buf, &b).map_err(fault)?;
            return Ok(0);
        }
        if let Some(b) = crate::ready::stat_bytes(&target) {
            copy_to_user(buf, &b).map_err(fault)?;
            return Ok(0);
        }
    }
    let node = node_at(p, dirfd, &path, follow, flags & AT_EMPTY_PATH != 0)?;
    put_stat(node, buf)
}

/// lseek(2) (`ksys_lseek`, `generic_file_llseek_size`, `shmem_file_llseek`,
/// `dcache_dir_lseek`):
/// - an unknown whence EINVAL;
/// - the console ESPIPE (a terminal cannot seek, `no_llseek`);
/// - /dev/null, /dev/zero and /dev/urandom stay at 0 and return 0
///   (`null_lseek`, `zero_lseek`, `noop_llseek`);
/// - a file: SEEK_SET, SEEK_CUR and SEEK_END, a result below 0 or above
///   MAX_LFS_FILESIZE EINVAL. SEEK_DATA and SEEK_HOLE with an offset
///   outside the file are ENXIO; inside it every byte is data (tmpfs
///   reports unwritten pages as holes; Keel keeps no holes), so SEEK_DATA
///   returns the offset and SEEK_HOLE the size;
/// - a directory: SEEK_SET and SEEK_CUR set the entry index getdents64
///   resumes from; SEEK_END and the others are EINVAL;
/// - a pipe ESPIPE; an eventfd 0, whatever is asked (ADR 0025).
pub fn lseek(p: &ProcessRef, fd: i32, offset: i64, whence: u32) -> SysResult {
    if whence > SEEK_HOLE {
        return Err(Errno::EINVAL);
    }
    match object(p, fd, Rights::NONE)? {
        // `stream_open` takes FMODE_LSEEK away: vfs_llseek ESPIPE.
        Object::Pipe(_) => return Err(Errno::ESPIPE),
        // eventfd's and eventpoll's `noop_llseek`: the position, always 0.
        Object::EventFd(_) | Object::Epoll(_) => return Ok(0),
        // `socket_file_ops` has no llseek: ESPIPE.
        Object::Socket(_) => return Err(Errno::ESPIPE),
        // Not files (ADR 0040).
        Object::Factory(_) | Object::Compartment(_) | Object::Audit(_) => {
            return Err(Errno::ESPIPE);
        }
        Object::File(_) => {}
    }
    let open = file(p, fd, Rights::SEEK)?;
    let mut f = open.lock();
    let size = match f.kind {
        // A terminal is opened non-seekable (`tty_open`); an open FIFO is
        // a pipe end, never a file description, but would be too.
        Kind::Device(d) if d.is_tty() => return Err(Errno::ESPIPE),
        Kind::Fifo => return Err(Errno::ESPIPE),
        Kind::Device(_) => {
            f.offset = 0;
            return Ok(0);
        }
        Kind::Directory => {
            let base = match whence {
                SEEK_SET => 0,
                SEEK_CUR => f.offset as i64,
                _ => return Err(Errno::EINVAL),
            };
            let at = base
                .checked_add(offset)
                .filter(|&a| a >= 0)
                .ok_or(Errno::EINVAL)?;
            f.offset = at as u64;
            return Ok(at as u64);
        }
        Kind::File | Kind::Symlink | Kind::Socket => {
            let node = f.node;
            fs::with(|fs| fs.stat(node))?.size
        }
    };
    let new = match whence {
        SEEK_SET => offset,
        SEEK_CUR => (f.offset as i64).checked_add(offset).ok_or(Errno::EINVAL)?,
        SEEK_END => (size as i64).checked_add(offset).ok_or(Errno::EINVAL)?,
        _ => {
            if offset < 0 || offset as u64 >= size {
                return Err(Errno::ENXIO);
            }
            if whence == SEEK_DATA {
                offset
            } else {
                size as i64
            }
        }
    };
    if new < 0 || new as u64 > MAX_LFS_FILESIZE {
        return Err(Errno::EINVAL);
    }
    f.offset = new as u64;
    Ok(new as u64)
}

/// `d_type` values (`include/linux/fs_types.h`: DT_FIFO 1, DT_CHR 2,
/// DT_DIR 4, DT_REG 8, DT_LNK 10, DT_SOCK 12).
fn d_type(kind: Kind) -> u8 {
    match kind {
        Kind::Fifo => 1,
        Kind::Device(_) => 2,
        Kind::Directory => 4,
        Kind::File => 8,
        Kind::Symlink => 10,
        Kind::Socket => 12,
    }
}

/// getdents64(2) (`fs/readdir.c`, `dcache_readdir`): `struct
/// linux_dirent64` records (d_ino u64, d_off i64, d_reclen u16, d_type
/// u8, the name with its NUL, padded to 8 bytes) from the handle's entry
/// index: "." at 0, ".." at 1, then the names in byte order. Returns the
/// bytes written, 0 at the end; EINVAL if not even the next record fits;
/// ENOTDIR for a non-directory; ENOENT for a removed directory
/// (`iterate_dir`, IS_DEADDIR). d_ino is the inode number + 1, as stat
/// reports it; d_off is the index of the next entry.
pub fn getdents64(p: &ProcessRef, fd: i32, buf: u64, count: u32) -> SysResult {
    let open = directory(p, fd)?;
    let (node, index, proc) = {
        let f = open.lock();
        (f.node, f.offset, f.proc)
    };
    let count = count as usize;
    if let Some(dir) = proc {
        let (out, next) = crate::procfs::getdents(p, dir, index, count)?;
        copy_to_user(buf, &out).map_err(fault)?;
        open.lock().offset = next;
        return Ok(out.len() as u64);
    }
    let (out, next) = fs::with(|fs| {
        if fs.stat(node)?.nlink == 0 {
            return Err(Errno::ENOENT);
        }
        let parent = fs.dir_parent(node)?;
        let names = fs.entries(node)?;
        let mut out = Vec::new();
        let mut at = index;
        loop {
            let (name, ino, kind): (&[u8], Ino, Kind) = match at {
                0 => (b".", node, Kind::Directory),
                1 => (b"..", parent, Kind::Directory),
                n => match names.get((n - 2) as usize) {
                    Some((name, ino)) => (name.as_slice(), *ino, fs.kind(*ino)?),
                    None => break,
                },
            };
            let reclen = (19 + name.len() + 1).next_multiple_of(8);
            if out.len() + reclen > count {
                if out.is_empty() {
                    return Err(Errno::EINVAL);
                }
                break;
            }
            let start = out.len();
            out.resize(start + reclen, 0);
            out[start..start + 8].copy_from_slice(&(ino + 1).to_le_bytes());
            out[start + 8..start + 16].copy_from_slice(&((at + 1) as i64).to_le_bytes());
            out[start + 16..start + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
            out[start + 18] = d_type(kind);
            out[start + 19..start + 19 + name.len()].copy_from_slice(name);
            at += 1;
        }
        fs.touch_atime(node);
        Ok((out, at))
    })?;
    copy_to_user(buf, &out).map_err(fault)?;
    open.lock().offset = next;
    Ok(out.len() as u64)
}

/// getcwd(2) (`fs/d_path.c`): the working directory's path from the
/// process root, with its NUL; ERANGE if it does not fit in `size`;
/// ENOENT if the directory has been removed (or moved out of the root).
/// Returns the length with the NUL.
pub fn getcwd(p: &ProcessRef, buf: u64, size: u64) -> SysResult {
    let (root, cwd) = {
        let process = p.lock();
        (process.root, process.cwd)
    };
    let mut path = fs::with(|fs| fs.path_of(root, cwd))?;
    path.push(0);
    if path.len() as u64 > size {
        return Err(Errno::ERANGE);
    }
    copy_to_user(buf, &path).map_err(fault)?;
    Ok(path.len() as u64)
}

/// chdir(2): to a directory (ENOTDIR otherwise) the path names.
pub fn chdir(p: &ProcessRef, path: u64) -> SysResult {
    let path = user_path(path)?;
    let node = node_at(p, AT_FDCWD, &path, true, false)?;
    set_cwd(p, node)
}

/// fchdir(2): to the directory open on `fd` (ENOTDIR otherwise), which
/// needs ENUMERATE. A directory handle from outside the process root makes
/// a working directory from which relative paths name nothing (the lookup
/// start check, ADR 0022).
pub fn fchdir(p: &ProcessRef, fd: i32) -> SysResult {
    let open = directory(p, fd)?;
    let (node, proc) = {
        let f = open.lock();
        (f.node, f.proc)
    };
    // A working directory in /proc is not supported (ADR 0024).
    if proc.is_some() {
        return Err(Errno::EACCES);
    }
    set_cwd(p, node)
}

fn set_cwd(p: &ProcessRef, node: Ino) -> SysResult {
    if fs::with(|fs| fs.kind(node))? != Kind::Directory {
        return Err(Errno::ENOTDIR);
    }
    p.lock().cwd = node;
    Ok(0)
}

/// The parent and last component of `path`, for a call that changes the
/// names in a directory.
pub(crate) fn parent_of<'p>(
    p: &ProcessRef,
    dirfd: i32,
    path: &'p [u8],
) -> Result<Parent<'p>, Errno> {
    let (root, base) = start(p, dirfd, path, true)?;
    fs::with(|fs| fs.parent(root, base, path))
}

/// mkdir(2) and mkdirat(2) (`do_mkdirat`, `filename_create` with
/// LOOKUP_DIRECTORY): "/", "." or ".." as the last component, or an
/// existing name, EEXIST; a trailing slash is allowed. The mode keeps the
/// permission and sticky bits and loses those in the umask (`mode &
/// (S_IRWXUGO|S_ISVTX)`, then `~umask`). Charged one node to the caller's
/// compartment.
pub fn mkdirat(p: &ProcessRef, dirfd: i32, path: u64, mode: u32) -> SysResult {
    let path = user_path(path)?;
    let parent = parent_of(p, dirfd, &path)?;
    let Last::Name(name) = parent.last else {
        return Err(Errno::EEXIST);
    };
    let umask = p.lock().umask;
    let quota = quota_of(p);
    fs::with(|fs| fs.create_dir_as(parent.dir, name, mode & 0o1777 & !umask, quota.as_ref()))?;
    Ok(0)
}

/// mknodat(2) and mknod(2) (`do_mknodat`, ADR 0035), in Linux's order:
/// - `may_mknod`: a directory's type EPERM, an unknown type EINVAL;
/// - `filename_create`: the parent's lookup errors; a last component that
///   is not a name, or a name that exists, EEXIST; with a trailing slash,
///   EEXIST if it exists, else ENOENT;
/// - then a regular file (type 0 or S_IFREG), a FIFO or a socket node,
///   with the umask applied and charged to the compartment's quota. A
///   character or block device is EPERM: it needs CAP_MKNOD
///   (`vfs_mknod`), which Keel's compartments do not have; their /dev is
///   the kernel's.
pub fn mknodat(p: &ProcessRef, dirfd: i32, path: u64, mode: u32, _dev: u32) -> SysResult {
    const S_IFMT: u32 = 0o170000;
    const S_IFBLK: u32 = 0o060000;
    let kind = mode & S_IFMT;
    match kind {
        0 | vfs::S_IFREG | vfs::S_IFIFO | vfs::S_IFSOCK | vfs::S_IFCHR | S_IFBLK => {}
        vfs::S_IFDIR => return Err(Errno::EPERM),
        _ => return Err(Errno::EINVAL),
    }
    let path = user_path(path)?;
    let parent = parent_of(p, dirfd, &path)?;
    let Last::Name(name) = parent.last else {
        return Err(Errno::EEXIST);
    };
    let umask = p.lock().umask;
    let quota = quota_of(p);
    let permissions = mode & 0o7777 & !umask;
    fs::with(|fs| {
        if fs.child(parent.dir, name).is_ok() {
            return Err(Errno::EEXIST);
        }
        if parent.trailing_slash {
            return Err(Errno::ENOENT);
        }
        match kind {
            vfs::S_IFIFO => fs.create_fifo_as(parent.dir, name, permissions, quota.as_ref()),
            vfs::S_IFSOCK => fs.create_socket_as(parent.dir, name, permissions, quota.as_ref()),
            vfs::S_IFCHR | S_IFBLK => Err(Errno::EPERM),
            _ => fs.create_file_as(parent.dir, name, permissions, quota.as_ref()),
        }
    })?;
    Ok(0)
}

/// rmdir(2) (`do_rmdir`): ".." ENOTEMPTY, "." EINVAL, "/" EBUSY; then
/// `vfs_rmdir` (ENOTDIR, ENOTEMPTY).
pub fn rmdir(p: &ProcessRef, dirfd: i32, path: &[u8]) -> SysResult {
    let parent = parent_of(p, dirfd, path)?;
    let name = match parent.last {
        Last::Name(name) => name,
        Last::DotDot => return Err(Errno::ENOTEMPTY),
        Last::Dot => return Err(Errno::EINVAL),
        Last::Root => return Err(Errno::EBUSY),
    };
    fs::with(|fs| fs.rmdir(parent.dir, name))?;
    Ok(0)
}

/// unlink(2) (`do_unlinkat`): a last component that is not a name EISDIR;
/// a directory EISDIR; with a trailing slash, ENOENT if missing, EISDIR
/// for a directory, else ENOTDIR (the `slashes` exit).
pub fn unlink(p: &ProcessRef, dirfd: i32, path: &[u8]) -> SysResult {
    let parent = parent_of(p, dirfd, path)?;
    let Last::Name(name) = parent.last else {
        return Err(Errno::EISDIR);
    };
    fs::with(|fs| {
        if parent.trailing_slash {
            return Err(match fs.child(parent.dir, name).and_then(|i| fs.kind(i)) {
                Err(e) => e,
                Ok(Kind::Directory) => Errno::EISDIR,
                Ok(_) => Errno::ENOTDIR,
            });
        }
        fs.unlink(parent.dir, name)
    })?;
    Ok(0)
}

/// unlinkat(2): AT_REMOVEDIR makes it rmdir; other flags EINVAL.
pub fn unlinkat(p: &ProcessRef, dirfd: i32, path: u64, flags: u32) -> SysResult {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Errno::EINVAL);
    }
    let path = user_path(path)?;
    if flags & AT_REMOVEDIR != 0 {
        rmdir(p, dirfd, &path)
    } else {
        unlink(p, dirfd, &path)
    }
}

/// renameat2(2) (`do_renameat2`), and rename(2)/renameat(2) with flags 0:
/// bad flags EINVAL (checked first); a source that is not a name EBUSY, a
/// target that is not one EEXIST with RENAME_NOREPLACE, else EBUSY; a
/// trailing slash on either side with a non-directory source ENOTDIR;
/// then `Fs::rename`. Both paths need CREATE on a directory handle.
pub fn renameat2(
    p: &ProcessRef,
    olddirfd: i32,
    oldpath: u64,
    newdirfd: i32,
    newpath: u64,
    flags: u32,
) -> SysResult {
    use vfs::{RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};
    if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0
        || (flags & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0 && flags & RENAME_EXCHANGE != 0)
    {
        return Err(Errno::EINVAL);
    }
    let old = user_path(oldpath)?;
    let new = user_path(newpath)?;
    let from = parent_of(p, olddirfd, &old)?;
    let to = parent_of(p, newdirfd, &new)?;
    let Last::Name(old_name) = from.last else {
        return Err(Errno::EBUSY);
    };
    let Last::Name(new_name) = to.last else {
        return Err(if flags & RENAME_NOREPLACE != 0 {
            Errno::EEXIST
        } else {
            Errno::EBUSY
        });
    };
    fs::with(|fs| {
        let source = fs.child(from.dir, old_name)?;
        if (from.trailing_slash || to.trailing_slash) && fs.kind(source)? != Kind::Directory {
            return Err(Errno::ENOTDIR);
        }
        fs.rename(from.dir, old_name, to.dir, new_name, flags)
    })?;
    Ok(0)
}

/// The new name for link, symlink: `filename_create` without
/// LOOKUP_DIRECTORY: not a name EEXIST; an existing name EEXIST; a
/// trailing slash ENOENT.
fn new_name<'p>(fs: &vfs::Fs, parent: &Parent<'p>) -> Result<&'p [u8], Errno> {
    let Last::Name(name) = parent.last else {
        return Err(Errno::EEXIST);
    };
    if fs.child(parent.dir, name).is_ok() {
        return Err(Errno::EEXIST);
    }
    if parent.trailing_slash {
        return Err(Errno::ENOENT);
    }
    Ok(name)
}

/// linkat(2), and link(2) with flags 0 (`do_linkat`): flags other than
/// AT_SYMLINK_FOLLOW and AT_EMPTY_PATH EINVAL; the source is not followed
/// if it is a symbolic link unless AT_SYMLINK_FOLLOW (link(2): "does not
/// dereference oldpath if it is a symbolic link"); then `Fs::link`.
pub fn linkat(
    p: &ProcessRef,
    olddirfd: i32,
    oldpath: u64,
    newdirfd: i32,
    newpath: u64,
    flags: u32,
) -> SysResult {
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    let old = path_arg(oldpath)?;
    let new = user_path(newpath)?;
    let source = node_at(
        p,
        olddirfd,
        &old,
        flags & AT_SYMLINK_FOLLOW != 0,
        flags & AT_EMPTY_PATH != 0,
    )?;
    let parent = parent_of(p, newdirfd, &new)?;
    fs::with(|fs| {
        let name = new_name(fs, &parent)?;
        fs.link(source, parent.dir, name)
    })?;
    Ok(0)
}

/// symlinkat(2), and symlink(2) (`do_symlinkat`): the target is any
/// string (not looked up); then `Fs::create_symlink_as`, charged one node.
pub fn symlinkat(p: &ProcessRef, target: u64, newdirfd: i32, linkpath: u64) -> SysResult {
    let target = user_path(target)?;
    let link = user_path(linkpath)?;
    let parent = parent_of(p, newdirfd, &link)?;
    let quota = quota_of(p);
    fs::with(|fs| {
        let name = new_name(fs, &parent)?;
        fs.create_symlink_as(parent.dir, name, &target, quota.as_ref())
    })?;
    Ok(0)
}

/// readlinkat(2), and readlink(2) (`do_readlinkat`): a size not above 0
/// EINVAL; the last component is not followed; not a symbolic link
/// EINVAL; at most `size` bytes of the target, without a NUL. Returns the
/// bytes copied.
pub fn readlinkat(p: &ProcessRef, dirfd: i32, path: u64, buf: u64, size: i32) -> SysResult {
    if size <= 0 {
        return Err(Errno::EINVAL);
    }
    let path = user_path(path)?;
    let path = in_proc_dir(p, dirfd, &path).unwrap_or(path);
    let target = match crate::procfs::lookup(p, &path, false) {
        Some(hit) => match hit? {
            crate::procfs::Hit::Node(node) => crate::procfs::readlink(p, node)?,
            crate::procfs::Hit::Real(_) => return Err(Errno::EINVAL),
        },
        None => {
            let node = node_at(p, dirfd, &path, false, false)?;
            fs::with(|fs| fs.readlink(node))?
        }
    };
    let n = target.len().min(size as usize);
    copy_to_user(buf, &target[..n]).map_err(fault)?;
    Ok(n as u64)
}

/// fchmodat(2), and chmod(2): the permission bits (`mode & S_IALLUGO`,
/// 07777) of what the path names, following links. Stored only (SR-6).
pub fn fchmodat(p: &ProcessRef, dirfd: i32, path: u64, mode: u32) -> SysResult {
    let path = user_path(path)?;
    let node = node_at(p, dirfd, &path, true, false)?;
    fs::with(|fs| fs.set_permissions(node, mode & 0o7777))?;
    Ok(0)
}

/// fchmod(2): as chmod, of the file open on `fd`, which needs STAT.
pub fn fchmod(p: &ProcessRef, fd: i32, mode: u32) -> SysResult {
    let node = file(p, fd, Rights::STAT)?.lock().node;
    fs::with(|fs| fs.set_permissions(node, mode & 0o7777))?;
    Ok(0)
}

/// umask(2): sets the mask to `mask & 0777` and returns the old one.
pub fn umask(p: &ProcessRef, mask: u32) -> SysResult {
    let mut process = p.lock();
    let old = process.umask;
    process.umask = mask & 0o777;
    Ok(u64::from(old))
}

/// The process's umask, for openat's O_CREAT.
pub fn umask_of(p: &ProcessRef) -> u32 {
    p.lock().umask
}

/// utimensat(2) (`fs/utimes.c`):
/// - `times` NULL: both times now;
/// - both UTIME_OMIT: nothing happens, and the path is not even looked up;
/// - a nanosecond field outside 0..=999999999 that is neither UTIME_NOW
///   nor UTIME_OMIT EINVAL;
/// - a NULL path with a descriptor: that file (flags must be 0, else
///   EINVAL); with AT_FDCWD it is looked up as a path, so EFAULT;
/// - flags other than AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH EINVAL.
///
/// The change time becomes now in every case that changes something.
pub fn utimensat(p: &ProcessRef, dirfd: i32, path: u64, times: u64, flags: u32) -> SysResult {
    let mut new: [Option<Timespec>; 2] = [None, None];
    let mut now = [true, true];
    if times != 0 {
        let mut raw = [0u8; 32];
        copy_from_user(&mut raw, times).map_err(fault)?;
        let field = |at: usize| i64::from_le_bytes(raw[at..at + 8].try_into().unwrap_or([0; 8]));
        let (a_nsec, m_nsec) = (field(8), field(24));
        if a_nsec == UTIME_OMIT && m_nsec == UTIME_OMIT {
            return Ok(0);
        }
        for (i, (sec, nsec)) in [(field(0), a_nsec), (field(16), m_nsec)]
            .into_iter()
            .enumerate()
        {
            match nsec {
                UTIME_NOW => {}
                UTIME_OMIT => now[i] = false,
                0..=999_999_999 => {
                    now[i] = false;
                    new[i] = Some(Timespec {
                        sec,
                        nsec: nsec as u32,
                    });
                }
                _ => return Err(Errno::EINVAL),
            }
        }
    }
    let node = if path == 0 && dirfd != AT_FDCWD {
        if flags != 0 {
            return Err(Errno::EINVAL);
        }
        file(p, dirfd, Rights::STAT)?.lock().node
    } else {
        if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(Errno::EINVAL);
        }
        let path = path_arg(path)?;
        node_at(
            p,
            dirfd,
            &path,
            flags & AT_SYMLINK_NOFOLLOW == 0,
            flags & AT_EMPTY_PATH != 0,
        )?
    };
    fs::with(|fs| {
        let t = fs.time_now();
        let pick = |i: usize| if now[i] { Some(t) } else { new[i] };
        fs.set_times(node, pick(0), pick(1))
    })?;
    Ok(0)
}

/// faccessat2(2), and access(2) and faccessat(2) with flags 0
/// (`do_faccessat`): a mode with bits outside R_OK|W_OK|X_OK EINVAL;
/// flags other than AT_EACCESS, AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH
/// EINVAL. Keel's processes run as root (uid 0) and check no modes
/// (SR-6), so as for root in `generic_permission`: reading and writing are
/// always allowed, executing only a directory or a file with an execute
/// bit (EACCES otherwise).
pub fn faccessat2(p: &ProcessRef, dirfd: i32, path: u64, mode: u32, flags: u32) -> SysResult {
    if mode & !7 != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    let path = path_arg(path)?;
    let path = in_proc_dir(p, dirfd, &path).unwrap_or(path);
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let stat = match crate::procfs::lookup(p, &path, follow) {
        Some(hit) => match hit? {
            crate::procfs::Hit::Node(node) => crate::procfs::stat(node),
            crate::procfs::Hit::Real(ino) => fs::with(|fs| fs.stat(ino))?,
        },
        None => {
            let node = node_at(p, dirfd, &path, follow, flags & AT_EMPTY_PATH != 0)?;
            fs::with(|fs| fs.stat(node))?
        }
    };
    if mode & X_OK != 0 && stat.mode & vfs::S_IFMT != vfs::S_IFDIR && stat.mode & 0o111 == 0 {
        return Err(Errno::EACCES);
    }
    Ok(0)
}

// ---------------------------------------------------------------------
// Descriptor-level calls (P3-T8 second part, ADR 0023).

/// Every POSIX record lock, and the queue F_SETLKW waits on.
static LOCKS: IrqMutex<keel_core::lock::Locks> = IrqMutex::new(keel_core::lock::Locks::new());
static LOCK_WAIT: keel_hal::sched::WaitQueue = keel_hal::sched::WaitQueue::new();

/// Drops `owner`'s record locks on `file`, or on every file if None, and
/// wakes F_SETLKW waiters if any went: a close of any descriptor of the
/// file (`locks_remove_posix`), and a process's exit.
pub fn release_locks(owner: u64, file: Option<Ino>) {
    let released = {
        let mut locks = LOCKS.lock();
        match file {
            Some(file) => locks.release(file, owner),
            None => locks.release_owner(owner),
        }
    };
    if released {
        LOCK_WAIT.wake_all();
    }
}

/// What closing a handle does beyond dropping it: if it was a file, the
/// process's locks on that file go (`filp_flush` -> `locks_remove_posix`,
/// whatever other descriptors of it stay open).
pub fn closed(p: &ProcessRef, handle: keel_core::handle::Handle<crate::process::Object>) {
    if let Object::File(file) = &handle.object {
        let node = file.lock().node;
        let owner = p.lock().lock_owner;
        release_locks(owner, Some(node));
    }
    drop(handle);
}

/// dup(2): the lowest free descriptor, sharing the open file description
/// (needs DUPLICATE; EBADF without). Close-on-exec is clear.
pub fn dup(p: &ProcessRef, fd: i32) -> SysResult {
    p.lock()
        .handles
        .duplicate_from(fd, 0, false)
        .map(|n| n as u64)
}

/// dup2(2) and dup3(2) (`ksys_dup3`): dup3's flags other than O_CLOEXEC
/// EINVAL, and the same descriptor twice EINVAL (checked first); dup2 of a
/// descriptor to itself returns it if it is open (EBADF if not). A
/// descriptor at or past the handle limit EBADF. Whatever `newfd` held is
/// closed, its locks released.
pub fn dup3(p: &ProcessRef, fd: i32, newfd: i32, flags: u64, is_dup2: bool) -> SysResult {
    if is_dup2 && fd == newfd {
        p.lock().handles.rights(fd)?;
        return Ok(fd as u64);
    }
    if flags & !crate::abi::O_CLOEXEC != 0 || fd == newfd {
        return Err(Errno::EINVAL);
    }
    let old = p
        .lock()
        .handles
        .duplicate_to(fd, newfd, flags & crate::abi::O_CLOEXEC != 0)?;
    if let Some(old) = old {
        closed(p, old);
    }
    Ok(newfd as u64)
}

/// fcntl commands (`include/uapi/asm-generic/fcntl.h`,
/// `include/uapi/linux/fcntl.h`).
pub const F_DUPFD: u32 = 0;
pub const F_GETFL: u32 = 3;
pub const F_SETFL: u32 = 4;
pub const F_GETLK: u32 = 5;
pub const F_SETLK: u32 = 6;
pub const F_SETLKW: u32 = 7;
pub const F_DUPFD_CLOEXEC: u32 = 1024 + 6;
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;
/// F_SETFL's changeable flags (`SETFL_MASK`, `fs/fcntl.c`): O_APPEND,
/// O_NONBLOCK (O_NDELAY is the same bit on x86), O_DIRECT, O_NOATIME.
const O_DIRECT: u64 = 0o40000;
const O_NOATIME: u64 = 0o1000000;
const SETFL_MASK: u64 = crate::abi::O_APPEND | crate::abi::O_NONBLOCK | O_DIRECT | O_NOATIME;

/// F_ADD_SEALS and F_GET_SEALS, for memfd sealing (P3-S7, ADR 0044):
/// F_LINUX_SPECIFIC_BASE (1024) plus 9 and 10, in
/// `include/uapi/linux/fcntl.h`.
const F_ADD_SEALS: u32 = 1033;
const F_GET_SEALS: u32 = 1034;

/// `memfd_fcntl` (`mm/memfd.c`): the seals of the file `fd` names, or
/// `seals` added to them. Adding needs a descriptor open for writing
/// (EPERM, `memfd_add_seals`' first check); then the rules are the
/// filesystem's (`Fs::add_seals`). Anything but a tmpfs file, which on
/// Keel is anything but a regular file, is EINVAL: pipes, sockets,
/// directories, devices and procfs files.
fn seals(p: &ProcessRef, fd: i32, cmd: u32, seals: u32) -> SysResult {
    let writable = p.lock().handles.check(fd, Rights::WRITE).is_ok();
    let node = match object(p, fd, Rights::NONE)? {
        Object::File(open) => {
            let f = open.lock();
            (f.proc.is_none() && f.tty.is_none()).then_some(f.node)
        }
        _ => None,
    };
    if cmd == F_ADD_SEALS && !writable {
        return Err(Errno::EPERM);
    }
    let node = node.ok_or(Errno::EINVAL)?;
    if cmd == F_ADD_SEALS {
        crate::fs::with(|fs| fs.add_seals(node, seals)).map(|()| 0)
    } else {
        crate::fs::with(|fs| fs.seals(node)).map(u64::from)
    }
}

/// fcntl(2) beyond F_GETFD and F_SETFD:
/// - F_DUPFD, F_DUPFD_CLOEXEC (`f_dupfd`): the lowest free descriptor at
///   or above `arg` (as an int); at or past the limit EINVAL;
/// - F_GETFL: the status flags; F_SETFL: sets O_APPEND, O_NONBLOCK,
///   O_DIRECT and O_NOATIME from `arg` and ignores the rest (`setfl`;
///   tmpfs allows O_DIRECT, `shmem_file_open`'s FMODE_CAN_ODIRECT, and
///   root may set O_NOATIME);
/// - F_GETLK, F_SETLK, F_SETLKW: POSIX record locks (`fs/locks.c`);
/// - F_ADD_SEALS, F_GET_SEALS: a memfd's seals (ADR 0044).
pub fn fcntl_more(p: &ProcessRef, fd: i32, cmd: u32, arg: u64) -> SysResult {
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let from = arg as u32 as i32;
            let from = usize::try_from(from).map_err(|_| Errno::EINVAL)?;
            p.lock()
                .handles
                .duplicate_from(fd, from, cmd == F_DUPFD_CLOEXEC)
                .map(|n| n as u64)
        }
        F_GETFL => match object(p, fd, Rights::NONE)? {
            Object::File(open) => Ok(open.lock().status),
            other => Ok(crate::ready::status(&other).map_or(0, |s| *s.lock())),
        },
        F_SETFL => {
            let target = object(p, fd, Rights::NONE)?;
            if let Some(status) = crate::ready::status(&target) {
                let mut f = status.lock();
                let arg = arg as u32 as u64;
                *f = (arg & SETFL_MASK) | (*f & !SETFL_MASK);
                drop(f);
                // Waiters on it re-read O_NONBLOCK only when they wake.
                crate::ready::changed();
                return Ok(0);
            }
            let open = file(p, fd, Rights::NONE)?;
            let mut f = open.lock();
            let arg = arg as u32 as u64;
            f.status = (arg & SETFL_MASK) | (f.status & !SETFL_MASK);
            f.append = f.status & crate::abi::O_APPEND != 0;
            Ok(0)
        }
        F_GETLK | F_SETLK | F_SETLKW => record_lock(p, fd, cmd, arg),
        F_ADD_SEALS | F_GET_SEALS => seals(p, fd, cmd, arg as u32),
        _ => {
            // Still checks the descriptor first, as Linux's fdget does.
            p.lock().handles.rights(fd)?;
            Err(Errno::EINVAL)
        }
    }
}

/// `struct flock` on x86-64 (`include/uapi/asm-generic/fcntl.h`): l_type
/// i16 at 0, l_whence i16 at 2, l_start i64 at 8, l_len i64 at 16, l_pid
/// i32 at 24; 32 bytes.
const FLOCK_SIZE: usize = 32;

/// F_GETLK, F_SETLK and F_SETLKW (`fcntl_getlk`, `fcntl_setlk`,
/// `flock64_to_posix_lock`, `check_fmode_for_setlk`):
/// - the range from l_whence (SEEK_SET, SEEK_CUR, SEEK_END, else EINVAL),
///   l_start and l_len (`keel_core::lock::range`);
/// - F_SETLK: F_RDLCK needs the descriptor open for reading and F_WRLCK
///   for writing (EBADF), another owner's conflicting lock EAGAIN; F_UNLCK
///   always succeeds; F_SETLKW waits instead, and a signal ends the wait
///   with EINTR (no deadlock detection: ADR 0023);
/// - F_GETLK: F_RDLCK or F_WRLCK (else EINVAL); the first conflicting
///   lock is written back (l_whence SEEK_SET, l_len 0 for "to the end",
///   l_pid its owner's PID, 0 if in another compartment), or only l_type
///   becomes F_UNLCK if none.
fn record_lock(p: &ProcessRef, fd: i32, cmd: u32, arg: u64) -> SysResult {
    use keel_core::lock::{Request, range};
    let open = file(p, fd, Rights::NONE)?;
    let rights = p.lock().handles.rights(fd)?;
    let mut raw = [0u8; FLOCK_SIZE];
    copy_from_user(&mut raw, arg).map_err(fault)?;
    let l_type = i16::from_le_bytes([raw[0], raw[1]]);
    let l_whence = i16::from_le_bytes([raw[2], raw[3]]);
    let field = |at: usize| i64::from_le_bytes(raw[at..at + 8].try_into().unwrap_or([0; 8]));
    let (l_start, l_len) = (field(8), field(16));
    let (node, position) = {
        let f = open.lock();
        (f.node, f.offset as i64)
    };
    let base = match l_whence as u32 {
        SEEK_SET => 0,
        SEEK_CUR => position,
        SEEK_END => fs::with(|fs| fs.stat(node))?.size as i64,
        _ => return Err(Errno::EINVAL),
    };
    let (start, end) = range(base, l_start, l_len)?;
    let (owner, pid, compartment) = {
        let process = p.lock();
        (
            process.lock_owner,
            process.pid(),
            process.member.compartment().id(),
        )
    };
    if cmd == F_GETLK {
        let exclusive = match l_type {
            F_RDLCK => false,
            F_WRLCK => true,
            _ => return Err(Errno::EINVAL),
        };
        let found = LOCKS.lock().conflict(node, owner, start, end, exclusive);
        match found {
            None => raw[0..2].copy_from_slice(&F_UNLCK.to_le_bytes()),
            Some(l) => {
                let t = if l.exclusive { F_WRLCK } else { F_RDLCK };
                raw[0..2].copy_from_slice(&t.to_le_bytes());
                raw[2..4].copy_from_slice(&0i16.to_le_bytes());
                raw[8..16].copy_from_slice(&l.start.to_le_bytes());
                let len = if l.end == keel_core::lock::OFFSET_MAX {
                    0
                } else {
                    l.end - l.start + 1
                };
                raw[16..24].copy_from_slice(&len.to_le_bytes());
                let shown = if l.compartment == compartment {
                    l.pid
                } else {
                    0
                };
                raw[24..28].copy_from_slice(&shown.to_le_bytes());
            }
        }
        copy_to_user(arg, &raw).map_err(fault)?;
        return Ok(0);
    }
    let request = match l_type {
        F_RDLCK => Request::Shared,
        F_WRLCK => Request::Exclusive,
        F_UNLCK => Request::Unlock,
        _ => return Err(Errno::EINVAL),
    };
    match request {
        Request::Shared if !rights.contains(Rights::READ) => return Err(Errno::EBADF),
        Request::Exclusive if !rights.contains(Rights::WRITE) => return Err(Errno::EBADF),
        _ => {}
    }
    let who = keel_core::lock::Owner {
        id: owner,
        pid,
        compartment,
    };
    let attempt = || LOCKS.lock().set(node, who, start, end, request);
    let result = if cmd == F_SETLKW {
        let mut outcome = Err(Errno::EAGAIN);
        let done = LOCK_WAIT.wait_until(|| {
            outcome = attempt();
            outcome != Err(Errno::EAGAIN)
        });
        if !done {
            // locks_lock_inode_wait: ERESTARTSYS.
            return Err(Errno::ERESTARTSYS);
        }
        outcome
    } else {
        attempt()
    };
    result?;
    if request == Request::Unlock {
        LOCK_WAIT.wake_all();
    }
    Ok(0)
}

/// An `iovec` array (`import_iovec`): more than UIO_MAXIOV (1024) entries
/// EINVAL; a total length past `ssize_t` EINVAL.
pub(crate) fn iovecs(iov: u64, count: u64) -> Result<Vec<(u64, u64)>, Errno> {
    const UIO_MAXIOV: u64 = 1024;
    if count > UIO_MAXIOV {
        return Err(Errno::EINVAL);
    }
    let mut raw = alloc::vec![0u8; count as usize * 16];
    copy_from_user(&mut raw, iov).map_err(fault)?;
    let vectors: Vec<(u64, u64)> = raw
        .as_chunks::<16>()
        .0
        .iter()
        .map(|v| {
            let word = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap_or_default());
            (word(&v[..8]), word(&v[8..]))
        })
        .collect();
    let mut total = 0u64;
    for &(_, len) in &vectors {
        total = total
            .checked_add(len)
            .filter(|&t| t <= i64::MAX as u64)
            .ok_or(Errno::EINVAL)?;
    }
    Ok(vectors)
}

/// `RWF_*` (`include/uapi/linux/fs.h`).
const RWF_HIPRI: u32 = 0x01;
const RWF_DSYNC: u32 = 0x02;
const RWF_SYNC: u32 = 0x04;
const RWF_NOWAIT: u32 = 0x08;
const RWF_APPEND: u32 = 0x10;
const RWF_NOAPPEND: u32 = 0x20;
const RWF_ATOMIC: u32 = 0x40;

/// `kiocb_set_rw_flags`: unknown flags EOPNOTSUPP; RWF_APPEND with
/// RWF_NOAPPEND EINVAL; RWF_ATOMIC EOPNOTSUPP (tmpfs has no atomic
/// writes, nor reads have any). HIPRI, DSYNC, SYNC and NOWAIT change
/// nothing here: tmpfs has no device to sync and Keel never blocks on a
/// file. Returns the append override: Some(true) for RWF_APPEND,
/// Some(false) for RWF_NOAPPEND.
fn rw_flags(flags: u32) -> Result<Option<bool>, Errno> {
    let known =
        RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND | RWF_NOAPPEND | RWF_ATOMIC;
    if flags & !known != 0 || flags & RWF_ATOMIC != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if flags & RWF_APPEND != 0 && flags & RWF_NOAPPEND != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(if flags & RWF_APPEND != 0 {
        Some(true)
    } else if flags & RWF_NOAPPEND != 0 {
        Some(false)
    } else {
        None
    })
}

/// readv(2), preadv(2), preadv2(2): `at` None reads from the file
/// position (readv, and preadv2 with offset -1); a negative offset
/// otherwise EINVAL; a positional read of the console ESPIPE. Stops at
/// the first short read, as `do_iter_readv_writev`.
pub fn readv(
    p: &ProcessRef,
    fd: i32,
    iov: u64,
    count: u64,
    at: Option<i64>,
    flags: u32,
) -> SysResult {
    let target = object(p, fd, Rights::READ)?;
    rw_flags(flags)?;
    if !matches!(target, Object::File(_)) {
        // A pipe or eventfd reads the vectors as one read; it has no
        // position (ESPIPE for preadv, whatever the offset).
        if at.is_some() {
            return Err(Errno::ESPIPE);
        }
        let vectors = iovecs(iov, count)?;
        return crate::ready::read(&target, &vectors).unwrap_or(Err(Errno::EINVAL));
    }
    let open = file(p, fd, Rights::READ)?;
    let at = match at {
        Some(a) if a < 0 => return Err(Errno::EINVAL),
        Some(a) => Some(a as u64),
        None => None,
    };
    let tty = open.lock().tty.clone();
    if let Some(tty) = tty {
        // A terminal: no position, and the vectors are one read.
        if at.is_some() {
            return Err(Errno::ESPIPE);
        }
        let nonblock = open.lock().status & crate::abi::O_NONBLOCK != 0;
        return crate::tty::read(&tty, nonblock, &iovecs(iov, count)?);
    }
    let mut done = 0u64;
    for (base, len) in iovecs(iov, count)? {
        match crate::syscall::read_into(p, fd, base, len, at.map(|a| a + done)) {
            Ok(n) => {
                done += n;
                if n < len {
                    break;
                }
            }
            Err(error) if done == 0 => return Err(error),
            Err(_) => break,
        }
    }
    Ok(done)
}

/// writev(2)'s positional forms, pwritev(2) and pwritev2(2), and
/// pwrite64(2) (one vector): `at` None writes at the file position
/// (pwritev2 with offset -1); a negative offset otherwise EINVAL; the
/// console ESPIPE. A file open with O_APPEND appends even at an offset,
/// as Linux does ("BUGS" in pwrite(2)), unless RWF_NOAPPEND; RWF_APPEND
/// appends either way. A positional write leaves the file position.
pub fn pwritev(
    p: &ProcessRef,
    fd: i32,
    iov: &[(u64, u64)],
    at: Option<i64>,
    flags: u32,
) -> SysResult {
    let target = object(p, fd, Rights::WRITE)?;
    let append = rw_flags(flags)?;
    if !matches!(target, Object::File(_)) {
        if at.is_some() {
            return Err(Errno::ESPIPE);
        }
        return crate::ready::write(p, &target, iov).unwrap_or(Err(Errno::EINVAL));
    }
    let open = file(p, fd, Rights::WRITE)?;
    let at = match at {
        Some(a) if a < 0 => return Err(Errno::EINVAL),
        Some(a) => Some(a as u64),
        None => None,
    };
    let tty = open.lock().tty.clone();
    if let Some(tty) = tty {
        if at.is_some() {
            return Err(Errno::ESPIPE);
        }
        let nonblock = open.lock().status & crate::abi::O_NONBLOCK != 0;
        return crate::tty::write(&tty, nonblock, iov);
    }
    let quota = quota_of(p);
    let mut done = 0u64;
    for &(base, len) in iov {
        match crate::syscall::write_at(
            &open,
            base,
            len,
            quota.as_ref(),
            at.map(|a| a + done),
            append,
        ) {
            Ok(n) => {
                done += n;
                if n < len {
                    break;
                }
            }
            Err(error) if done == 0 => return Err(error),
            Err(_) => break,
        }
    }
    Ok(done)
}

/// pwritev(2) and pwritev2(2) from a user iovec array.
pub fn pwritev_user(
    p: &ProcessRef,
    fd: i32,
    iov: u64,
    count: u64,
    at: Option<i64>,
    flags: u32,
) -> SysResult {
    object(p, fd, Rights::WRITE)?;
    let vectors = iovecs(iov, count)?;
    pwritev(p, fd, &vectors, at, flags)
}

/// `struct statfs` on x86-64 (`include/uapi/asm-generic/statfs.h`, the
/// 64-bit layout): f_type, f_bsize, f_blocks, f_bfree, f_bavail, f_files,
/// f_ffree (8 bytes each), f_fsid (two ints), f_namelen, f_frsize, f_flags,
/// f_spare[4]; 120 bytes. For tmpfs (`shmem_statfs`): TMPFS_MAGIC
/// 0x01021994, 4096-byte blocks, the byte and node limits as totals (the
/// caller's compartment quota where it is smaller), NAME_MAX 255, and
/// ST_VALID among the flags. f_fsid is 0, as tmpfs reports it.
fn statfs_bytes(p: &ProcessRef) -> Result<[u8; 120], Errno> {
    const TMPFS_MAGIC: u64 = 0x0102_1994;
    const ST_VALID: u64 = 0x0020;
    let ((used_bytes, used_nodes), (byte_limit, node_limit)) =
        fs::with(|fs| Ok((fs.usage(), fs.limits())))?;
    let mut total_bytes = byte_limit as u64;
    let mut free_bytes = (byte_limit - used_bytes.min(byte_limit)) as u64;
    let mut total_nodes = node_limit as u64;
    let mut free_nodes = (node_limit - used_nodes.min(node_limit)) as u64;
    if let Some(q) = quota_of(p) {
        if (q.bytes.limit() as u64) < total_bytes {
            total_bytes = q.bytes.limit() as u64;
            free_bytes =
                free_bytes.min((q.bytes.limit() - q.bytes.used().min(q.bytes.limit())) as u64);
        }
        if (q.nodes.limit() as u64) < total_nodes {
            total_nodes = q.nodes.limit() as u64;
            free_nodes =
                free_nodes.min((q.nodes.limit() - q.nodes.used().min(q.nodes.limit())) as u64);
        }
    }
    let mut b = [0u8; 120];
    let words = [
        TMPFS_MAGIC,
        4096,
        total_bytes / 4096,
        free_bytes / 4096,
        free_bytes / 4096,
        total_nodes,
        free_nodes,
    ];
    for (i, w) in words.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    // f_fsid at 56 stays 0.
    b[64..72].copy_from_slice(&(vfs::NAME_MAX as u64).to_le_bytes());
    b[72..80].copy_from_slice(&4096u64.to_le_bytes());
    b[80..88].copy_from_slice(&ST_VALID.to_le_bytes());
    Ok(b)
}

/// statfs(2): the filesystem holding the path (there is one).
pub fn statfs(p: &ProcessRef, path: u64, buf: u64) -> SysResult {
    let path = user_path(path)?;
    let b = match crate::procfs::lookup(p, &path, true) {
        Some(hit) => match hit? {
            crate::procfs::Hit::Node(_) => crate::procfs::statfs_bytes(),
            crate::procfs::Hit::Real(_) => statfs_bytes(p)?,
        },
        None => {
            node_at(p, AT_FDCWD, &path, true, false)?;
            statfs_bytes(p)?
        }
    };
    copy_to_user(buf, &b).map_err(fault)?;
    Ok(0)
}

/// fstatfs(2): of the filesystem holding the descriptor's file.
pub fn fstatfs(p: &ProcessRef, fd: i32, buf: u64) -> SysResult {
    let target = object(p, fd, Rights::NONE)?;
    if let Object::File(f) = &target
        && f.lock().proc.is_some()
    {
        copy_to_user(buf, &crate::procfs::statfs_bytes()).map_err(fault)?;
        return Ok(0);
    }
    let mut b = statfs_bytes(p)?;
    if let Some(magic) = crate::ready::statfs_magic(&target) {
        // pipefs and the anon-inode filesystem are pseudo filesystems:
        // `simple_statfs` reports only their magic, PAGE_SIZE blocks and
        // NAME_MAX; `statfs_by_dentry` makes f_frsize f_bsize, and
        // `calculate_f_flags` adds ST_VALID.
        b = [0; 120];
        b[0..8].copy_from_slice(&magic.to_le_bytes());
        b[8..16].copy_from_slice(&4096u64.to_le_bytes());
        b[64..72].copy_from_slice(&(vfs::NAME_MAX as u64).to_le_bytes());
        b[72..80].copy_from_slice(&4096u64.to_le_bytes());
        b[80..88].copy_from_slice(&0x20u64.to_le_bytes());
    }
    copy_to_user(buf, &b).map_err(fault)?;
    Ok(0)
}

/// The xattr calls (getxattr(2) and the rest): Keel's tmpfs keeps no
/// extended attributes and answers as a filesystem without xattr support
/// does, EOPNOTSUPP, after the checks Linux makes first, in its order
/// (`fs/xattr.c`):
/// - get and list: the path or descriptor (ENOENT, EBADF), then for get
///   the name;
/// - set: its flags (other than XATTR_CREATE and XATTR_REPLACE: EINVAL),
///   the name, the size (past XATTR_SIZE_MAX 65536: E2BIG), then the path
///   or descriptor (`setxattr_copy`);
/// - remove: the name, then the path or descriptor.
///
/// An empty name, or one longer than XATTR_NAME_MAX (255), is ERANGE.
/// Wine treats EOPNOTSUPP as it treats ENODATA: no attribute (ADR 0023).
pub fn xattr(p: &ProcessRef, target: XattrTarget, call: XattrCall) -> SysResult {
    const XATTR_CREATE: u64 = 1;
    const XATTR_REPLACE: u64 = 2;
    const XATTR_SIZE_MAX: u64 = 65536;
    let check_name = |name: u64| -> Result<(), Errno> {
        let name = crate::syscall::user_string_max(name, 256).map_err(|e| {
            if e == Errno::ENAMETOOLONG {
                Errno::ERANGE
            } else {
                e
            }
        })?;
        if name.is_empty() {
            return Err(Errno::ERANGE);
        }
        Ok(())
    };
    let check_target = || -> Result<(), Errno> {
        match target {
            XattrTarget::Path(path, follow) => {
                let path = user_path(path)?;
                node_at(p, AT_FDCWD, &path, follow, false).map(|_| ())
            }
            XattrTarget::Fd(fd) => file(p, fd, Rights::NONE).map(|_| ()),
        }
    };
    match call {
        XattrCall::Get(name) => {
            check_target()?;
            check_name(name)?;
        }
        XattrCall::List => check_target()?,
        XattrCall::Set { name, size, flags } => {
            if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
                return Err(Errno::EINVAL);
            }
            check_name(name)?;
            if size > XATTR_SIZE_MAX {
                return Err(Errno::E2BIG);
            }
            check_target()?;
        }
        XattrCall::Remove(name) => {
            check_name(name)?;
            check_target()?;
        }
    }
    Err(Errno::EOPNOTSUPP)
}

/// What an xattr call names.
#[derive(Clone, Copy)]
pub enum XattrTarget {
    /// A path, followed (`getxattr`) or not (`lgetxattr`).
    Path(u64, bool),
    Fd(i32),
}

/// Which xattr call, with the arguments its checks read.
#[derive(Clone, Copy)]
pub enum XattrCall {
    Get(u64),
    List,
    Set { name: u64, size: u64, flags: u64 },
    Remove(u64),
}
