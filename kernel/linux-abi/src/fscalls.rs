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
use crate::process::Process;
use crate::syscall::{fault, file, quota_of, user_path};

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
    if file(p, fd, Rights::NONE)?.lock().kind != Kind::Directory {
        return Err(Errno::ENOTDIR);
    }
    file(p, fd, Rights::ENUMERATE)
}

/// Where a lookup of `path` relative to `dirfd` starts: `(root, base)`.
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
    let dir = file(p, dirfd, needs)?;
    let dir = dir.lock();
    if dir.kind != Kind::Directory {
        return Err(Errno::ENOTDIR);
    }
    Ok((dir.node, dir.node))
}

/// The node `path` names relative to `dirfd`; an empty path with
/// AT_EMPTY_PATH is the handle itself (which then needs STAT), without it
/// ENOENT.
fn node_at(
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
    let node = node_at(
        p,
        dirfd,
        &path,
        flags & AT_SYMLINK_NOFOLLOW == 0,
        flags & AT_EMPTY_PATH != 0,
    )?;
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
///   resumes from; SEEK_END and the others are EINVAL.
pub fn lseek(p: &ProcessRef, fd: i32, offset: i64, whence: u32) -> SysResult {
    if whence > SEEK_HOLE {
        return Err(Errno::EINVAL);
    }
    let open = file(p, fd, Rights::SEEK)?;
    let mut f = open.lock();
    let size = match f.kind {
        Kind::Device(vfs::Device::Console) => return Err(Errno::ESPIPE),
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
        Kind::File | Kind::Symlink => {
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

/// `d_type` values (`include/linux/fs_types.h`: DT_CHR 2, DT_DIR 4,
/// DT_REG 8, DT_LNK 10).
fn d_type(kind: Kind) -> u8 {
    match kind {
        Kind::Device(_) => 2,
        Kind::Directory => 4,
        Kind::File => 8,
        Kind::Symlink => 10,
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
    let (node, index) = {
        let f = open.lock();
        (f.node, f.offset)
    };
    let count = count as usize;
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
    let node = open.lock().node;
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
fn parent_of<'p>(p: &ProcessRef, dirfd: i32, path: &'p [u8]) -> Result<Parent<'p>, Errno> {
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
    let node = node_at(p, dirfd, &path, false, false)?;
    let target = fs::with(|fs| fs.readlink(node))?;
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
    let node = node_at(
        p,
        dirfd,
        &path,
        flags & AT_SYMLINK_NOFOLLOW == 0,
        flags & AT_EMPTY_PATH != 0,
    )?;
    let stat = fs::with(|fs| fs.stat(node))?;
    if mode & X_OK != 0 && stat.mode & vfs::S_IFMT != vfs::S_IFDIR && stat.mode & 0o111 == 0 {
        return Err(Errno::EACCES);
    }
    Ok(0)
}
