//! In-memory filesystem and path lookup (P1-T12).
//!
//! One tmpfs holds the whole tree in Phase 1: the initramfs is unpacked
//! into it at boot and `/dev` is added beside it. Nodes live in a table
//! indexed by inode number; the kernel guards the whole [`Fs`] with one
//! lock.
//!
//! Lookup always starts from an explicit root directory, and `..` at that
//! root stays there. From Phase 3 a compartment's root is just another
//! directory, so no path can name anything above it (SR-4). Symbolic
//! links do not exist yet; when they arrive they must keep this property.
//!
//! Device nodes are limited to the kinds in [`Device`]: there is no way to
//! create `/dev/mem`, `/dev/kmem` or `/dev/port` (SR-9).
//!
//! Mode bits are stored and reported for compatibility only; no check
//! here or elsewhere grants or denies anything by user ID or mode (SR-6).
//! Access is controlled by handle rights (SR-1) and, later, compartment
//! grants.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::cpio;
use crate::errno::Errno;

/// Longest path accepted, including the terminating NUL, and longest
/// name (Linux `include/uapi/linux/limits.h`: PATH_MAX 4096, NAME_MAX 255).
pub const PATH_MAX: usize = 4096;
pub const NAME_MAX: usize = 255;

/// File type bits for `st_mode` (Linux `include/uapi/linux/stat.h`).
pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;

/// An inode number: an index into the node table.
pub type Ino = u32;

/// The root directory of the tree.
pub const ROOT: Ino = 0;

/// The character devices Keel provides. Numbers from Linux
/// `Documentation/admin-guide/devices.txt` (char major 1: 3 null, 5 zero,
/// 9 urandom; major 5 minor 1: console).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Device {
    Console,
    Null,
    Zero,
    Urandom,
}

impl Device {
    /// `(major, minor)`.
    pub fn number(self) -> (u32, u32) {
        match self {
            Device::Console => (5, 1),
            Device::Null => (1, 3),
            Device::Zero => (1, 5),
            Device::Urandom => (1, 9),
        }
    }
}

#[derive(Clone, Debug)]
enum Contents {
    /// File data. `Arc` so a reader (the ELF loader) can take a snapshot
    /// without holding the filesystem lock; writes copy on demand.
    File(Arc<Vec<u8>>),
    Directory(BTreeMap<Vec<u8>, Ino>),
    Device(Device),
}

#[derive(Clone, Debug)]
struct Node {
    contents: Contents,
    /// Permission bits only (`& 0o7777`).
    permissions: u32,
    /// The directory holding this node; the root is its own parent. Every
    /// node has exactly one (there are no hard links), so this also
    /// answers "is this beneath that root?" for files and devices.
    parent: Ino,
}

/// What a node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Device(Device),
}

/// File status, the parts `stat(2)` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub ino: Ino,
    /// File type and permission bits.
    pub mode: u32,
    pub size: u64,
    pub nlink: u32,
    /// Device number for character devices, as `(major, minor)`.
    pub rdev: (u32, u32),
}

/// Most nodes one filesystem may hold. Each node is kernel memory (the
/// node, its name of at most `NAME_MAX` bytes, its directory entry), so
/// without a cap `openat(O_CREAT)` in a loop exhausts the kernel heap
/// (F-0011). 65536 nodes with the longest names is a few tens of MiB.
/// Per compartment from Phase 3 (SR-8).
pub const NODE_LIMIT: usize = 65536;

/// The filesystem.
pub struct Fs {
    nodes: Vec<Option<Node>>,
    /// Bytes of file data held, and the cap (SR-8 groundwork; per
    /// compartment from Phase 3).
    bytes_used: usize,
    byte_limit: usize,
    /// Cap on `nodes` (`NODE_LIMIT`; lower in tests).
    node_limit: usize,
    /// Asked before a file buffer is allocated: may this many bytes be
    /// allocated now? The kernel answers from its frame reserve
    /// (`linux-abi::fs`), so one write cannot take the reserve that the
    /// admission check protects (third Phase 1 audit, C3). Default: yes.
    may_allocate: fn(usize) -> bool,
}

fn always(_: usize) -> bool {
    true
}

/// Makes `file` uniquely owned and at least `len` bytes long, failing
/// instead of aborting if memory runs out: copying a file that a reader
/// still holds (`Fs::contents`) and growing it are both allocations a
/// program controls the size of (F-0011).
///
/// Every allocation is first put to `may_allocate` with its full size (a
/// grown buffer is allocated whole before the old one is freed). Growth
/// doubles the capacity when that is allowed, so appending stays cheap;
/// otherwise it takes exactly what is needed; otherwise ENOMEM (C3).
fn grow_file(
    file: &mut Arc<Vec<u8>>,
    len: usize,
    may_allocate: fn(usize) -> bool,
) -> Result<&mut Vec<u8>, Errno> {
    if Arc::get_mut(file).is_none() {
        let size = file.len().max(len);
        if !may_allocate(size) {
            return Err(Errno::ENOMEM);
        }
        let mut copy = Vec::new();
        copy.try_reserve_exact(size).map_err(|_| Errno::ENOMEM)?;
        copy.extend_from_slice(file);
        *file = Arc::new(copy);
    }
    let data = Arc::get_mut(file).ok_or(Errno::ENOMEM)?;
    if len > data.capacity() {
        let doubled = data.capacity().saturating_mul(2).max(len);
        let target = if may_allocate(doubled) {
            doubled
        } else if may_allocate(len) {
            len
        } else {
            return Err(Errno::ENOMEM);
        };
        data.try_reserve_exact(target - data.len())
            .map_err(|_| Errno::ENOMEM)?;
    }
    if data.len() < len {
        data.resize(len, 0);
    }
    Ok(data)
}

/// Splits a path into components, checking the length limits.
fn components(path: &[u8]) -> Result<impl Iterator<Item = &[u8]>, Errno> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    if path.len() >= PATH_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    if path.contains(&0) {
        return Err(Errno::EINVAL);
    }
    let parts = path.split(|&b| b == b'/').filter(|c| !c.is_empty());
    if parts.clone().any(|c| c.len() > NAME_MAX) {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(path.split(|&b| b == b'/').filter(|c| !c.is_empty()))
}

impl Fs {
    /// An empty tree with a root directory and a cap on file data.
    pub fn new(byte_limit: usize) -> Fs {
        Fs {
            nodes: alloc::vec![Some(Node {
                contents: Contents::Directory(BTreeMap::new()),
                permissions: 0o755,
                parent: ROOT,
            })],
            bytes_used: 0,
            byte_limit,
            node_limit: NODE_LIMIT,
            may_allocate: always,
        }
    }

    /// Sets the check made before a file buffer is allocated (C3).
    pub fn set_allocation_check(&mut self, check: fn(usize) -> bool) {
        self.may_allocate = check;
    }

    /// Sets the cap on the number of nodes (tests use a small one) and
    /// returns the previous cap.
    pub fn set_node_limit(&mut self, limit: usize) -> usize {
        core::mem::replace(&mut self.node_limit, limit)
    }

    /// Bytes of file data held, and the number of nodes ever created.
    pub fn usage(&self) -> (usize, usize) {
        (self.bytes_used, self.nodes.len())
    }

    fn node(&self, ino: Ino) -> Result<&Node, Errno> {
        self.nodes
            .get(ino as usize)
            .and_then(Option::as_ref)
            .ok_or(Errno::ENOENT)
    }

    fn node_mut(&mut self, ino: Ino) -> Result<&mut Node, Errno> {
        self.nodes
            .get_mut(ino as usize)
            .and_then(Option::as_mut)
            .ok_or(Errno::ENOENT)
    }

    /// What `ino` is.
    pub fn kind(&self, ino: Ino) -> Result<Kind, Errno> {
        Ok(match self.node(ino)?.contents {
            Contents::File(_) => Kind::File,
            Contents::Directory(_) => Kind::Directory,
            Contents::Device(device) => Kind::Device(device),
        })
    }

    /// One step of lookup: `name` in directory `dir`, with `.` and `..`
    /// handled and `..` clamped at `root`.
    fn step(&self, root: Ino, dir: Ino, name: &[u8]) -> Result<Ino, Errno> {
        let node = self.node(dir)?;
        let Contents::Directory(entries) = &node.contents else {
            return Err(Errno::ENOTDIR);
        };
        match name {
            b"." => Ok(dir),
            b".." if dir == root => Ok(root),
            b".." => Ok(node.parent),
            _ => entries.get(name).copied().ok_or(Errno::ENOENT),
        }
    }

    /// Resolves `path`. An absolute path starts at `root`, a relative one
    /// at `cwd`; no path leaves `root`. `cwd` must lie beneath `root`
    /// (the caller's invariant; [`Fs::is_beneath`] checks it).
    pub fn lookup(&self, root: Ino, cwd: Ino, path: &[u8]) -> Result<Ino, Errno> {
        let mut at = if path.first() == Some(&b'/') {
            root
        } else {
            cwd
        };
        for name in components(path)? {
            at = self.step(root, at, name)?;
        }
        // "name/" must name a directory.
        if path.last() == Some(&b'/') && self.kind(at)? != Kind::Directory {
            return Err(Errno::ENOTDIR);
        }
        Ok(at)
    }

    /// Resolves all but the last component of `path`, returning the parent
    /// directory and the final name (for create).
    pub fn lookup_parent<'p>(
        &self,
        root: Ino,
        cwd: Ino,
        path: &'p [u8],
    ) -> Result<(Ino, &'p [u8]), Errno> {
        let names: Vec<&[u8]> = components(path)?.collect();
        let Some((&last, init)) = names.split_last() else {
            return Err(Errno::EEXIST); // "/" itself
        };
        if last == b"." || last == b".." {
            return Err(Errno::EEXIST);
        }
        let mut at = if path.first() == Some(&b'/') {
            root
        } else {
            cwd
        };
        for name in init {
            at = self.step(root, at, name)?;
        }
        if self.kind(at)? != Kind::Directory {
            return Err(Errno::ENOTDIR);
        }
        Ok((at, last))
    }

    /// Whether `ino` is `root` or lies beneath it.
    pub fn is_beneath(&self, root: Ino, mut ino: Ino) -> bool {
        loop {
            if ino == root {
                return true;
            }
            match self.node(ino) {
                Ok(node) if node.parent != ino => ino = node.parent,
                _ => return false,
            }
        }
    }

    fn add(&mut self, dir: Ino, name: &[u8], node: Node) -> Result<Ino, Errno> {
        if name.is_empty() || name.len() > NAME_MAX || name.contains(&b'/') || name.contains(&0) {
            return Err(Errno::EINVAL);
        }
        if name == b"." || name == b".." {
            return Err(Errno::EEXIST);
        }
        if self.nodes.len() >= self.node_limit {
            return Err(Errno::ENOSPC);
        }
        let ino = Ino::try_from(self.nodes.len()).map_err(|_| Errno::ENOSPC)?;
        let Contents::Directory(entries) = &mut self.node_mut(dir)?.contents else {
            return Err(Errno::ENOTDIR);
        };
        if entries.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        entries.insert(name.to_vec(), ino);
        self.nodes.push(Some(Node {
            parent: dir,
            ..node
        }));
        Ok(ino)
    }

    /// Creates an empty file.
    pub fn create_file(&mut self, dir: Ino, name: &[u8], permissions: u32) -> Result<Ino, Errno> {
        self.add(
            dir,
            name,
            Node {
                contents: Contents::File(Arc::new(Vec::new())),
                permissions: permissions & 0o7777,
                parent: dir,
            },
        )
    }

    /// Creates a directory.
    pub fn create_dir(&mut self, dir: Ino, name: &[u8], permissions: u32) -> Result<Ino, Errno> {
        self.add(
            dir,
            name,
            Node {
                contents: Contents::Directory(BTreeMap::new()),
                permissions: permissions & 0o7777,
                parent: dir,
            },
        )
    }

    /// Creates a device node.
    pub fn create_device(&mut self, dir: Ino, name: &[u8], device: Device) -> Result<Ino, Errno> {
        self.add(
            dir,
            name,
            Node {
                contents: Contents::Device(device),
                permissions: 0o666,
                parent: dir,
            },
        )
    }

    /// A snapshot of a file's contents, for readers that must not hold the
    /// filesystem lock (the ELF loader).
    pub fn contents(&self, ino: Ino) -> Result<Arc<Vec<u8>>, Errno> {
        match &self.node(ino)?.contents {
            Contents::File(data) => Ok(data.clone()),
            Contents::Directory(_) => Err(Errno::EISDIR),
            Contents::Device(_) => Err(Errno::EINVAL),
        }
    }

    /// Reads from a regular file at `offset`; returns the bytes read
    /// (0 at or past the end).
    pub fn read(&self, ino: Ino, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let data = match &self.node(ino)?.contents {
            Contents::File(data) => data,
            Contents::Directory(_) => return Err(Errno::EISDIR),
            Contents::Device(_) => return Err(Errno::EINVAL),
        };
        let Ok(start) = usize::try_from(offset) else {
            return Ok(0);
        };
        let available = data.get(start..).unwrap_or(&[]);
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }

    /// Writes to a regular file at `offset`, extending it (with zeros
    /// before `offset` if needed). Fails with ENOSPC past the byte limit
    /// and EFBIG if the end does not fit.
    pub fn write(&mut self, ino: Ino, offset: u64, data: &[u8]) -> Result<usize, Errno> {
        let start = usize::try_from(offset).map_err(|_| Errno::EFBIG)?;
        let end = start.checked_add(data.len()).ok_or(Errno::EFBIG)?;
        let (bytes_used, byte_limit) = (self.bytes_used, self.byte_limit);
        let may_allocate = self.may_allocate;
        let Contents::File(file) = &mut self.node_mut(ino)?.contents else {
            return Err(match self.kind(ino)? {
                Kind::Directory => Errno::EISDIR,
                _ => Errno::EINVAL,
            });
        };
        let growth = end.saturating_sub(file.len());
        if bytes_used
            .checked_add(growth)
            .is_none_or(|total| total > byte_limit)
        {
            return Err(Errno::ENOSPC);
        }
        let file = grow_file(file, end, may_allocate)?;
        file[start..end].copy_from_slice(data);
        self.bytes_used += growth;
        Ok(data.len())
    }

    /// Sets a file's length (truncate), zero-filling any growth.
    pub fn set_len(&mut self, ino: Ino, len: u64) -> Result<(), Errno> {
        let len = usize::try_from(len).map_err(|_| Errno::EFBIG)?;
        let (bytes_used, byte_limit) = (self.bytes_used, self.byte_limit);
        let may_allocate = self.may_allocate;
        let Contents::File(file) = &mut self.node_mut(ino)?.contents else {
            return Err(Errno::EINVAL);
        };
        let old = file.len();
        if len > old && bytes_used + (len - old) > byte_limit {
            return Err(Errno::ENOSPC);
        }
        grow_file(file, len, may_allocate)?.truncate(len);
        self.bytes_used = bytes_used - old + len;
        Ok(())
    }

    /// File status.
    pub fn stat(&self, ino: Ino) -> Result<Stat, Errno> {
        let node = self.node(ino)?;
        let (kind, size, nlink, rdev) = match &node.contents {
            Contents::File(data) => (S_IFREG, data.len() as u64, 1, (0, 0)),
            Contents::Directory(entries) => {
                let subdirs = entries
                    .values()
                    .filter(|&&i| matches!(self.kind(i), Ok(Kind::Directory)))
                    .count() as u32;
                (S_IFDIR, 0, 2 + subdirs, (0, 0))
            }
            Contents::Device(device) => (S_IFCHR, 0, 1, device.number()),
        };
        Ok(Stat {
            ino,
            mode: kind | node.permissions,
            size,
            nlink,
            rdev,
        })
    }

    /// Names in a directory, in byte order (without `.` and `..`).
    pub fn entries(&self, dir: Ino) -> Result<Vec<(Vec<u8>, Ino)>, Errno> {
        match &self.node(dir)?.contents {
            Contents::Directory(entries) => {
                Ok(entries.iter().map(|(n, &i)| (n.clone(), i)).collect())
            }
            _ => Err(Errno::ENOTDIR),
        }
    }

    /// Bytes of file data held.
    pub fn bytes_used(&self) -> usize {
        self.bytes_used
    }

    /// Unpacks a cpio archive beneath `root`. Every name must be a plain
    /// relative path (no `.` or `..` components); directories are created
    /// as needed. Members that are neither files nor directories (symbolic
    /// links, devices) are skipped and counted: Phase 1 has no symlinks,
    /// and device nodes come only from [`Fs::create_device`] (SR-9).
    /// Returns the number skipped.
    pub fn unpack(&mut self, root: Ino, entries: &[cpio::Entry<'_>]) -> Result<usize, Errno> {
        let mut skipped = 0;
        for entry in entries {
            let names: Vec<&[u8]> = components(entry.name)?.collect();
            if names.iter().any(|&n| n == b"." || n == b"..") {
                return Err(Errno::EINVAL);
            }
            let Some((&last, parents)) = names.split_last() else {
                continue; // "." or "/": the root itself
            };
            if entry.kind == cpio::Kind::Other {
                skipped += 1;
                continue;
            }
            let mut dir = root;
            for &name in parents {
                dir = match self.step(root, dir, name) {
                    Ok(next) => next,
                    Err(Errno::ENOENT) => self.create_dir(dir, name, 0o755)?,
                    Err(error) => return Err(error),
                };
            }
            match (entry.kind, self.step(root, dir, last)) {
                (cpio::Kind::Directory, Ok(existing))
                    if self.kind(existing)? == Kind::Directory => {}
                (cpio::Kind::Directory, Err(Errno::ENOENT)) => {
                    self.create_dir(dir, last, entry.permissions)?;
                }
                (cpio::Kind::File, Err(Errno::ENOENT)) => {
                    let ino = self.create_file(dir, last, entry.permissions)?;
                    self.write(ino, 0, entry.data)?;
                }
                (_, Ok(_)) => return Err(Errno::EEXIST),
                (_, Err(error)) => return Err(error),
            }
        }
        Ok(skipped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Fs {
        let mut fs = Fs::new(1 << 20);
        let etc = fs.create_dir(ROOT, b"etc", 0o755).unwrap();
        let f = fs.create_file(etc, b"hostname", 0o644).unwrap();
        fs.write(f, 0, b"keel\n").unwrap();
        let dev = fs.create_dir(ROOT, b"dev", 0o755).unwrap();
        fs.create_device(dev, b"null", Device::Null).unwrap();
        fs
    }

    #[test]
    fn lookup_walks_paths() {
        let fs = sample();
        let etc = fs.lookup(ROOT, ROOT, b"/etc").unwrap();
        let f = fs.lookup(ROOT, ROOT, b"/etc/hostname").unwrap();
        assert_eq!(fs.lookup(ROOT, ROOT, b"etc//hostname"), Ok(f));
        assert_eq!(fs.lookup(ROOT, etc, b"hostname"), Ok(f));
        assert_eq!(fs.lookup(ROOT, etc, b"./hostname"), Ok(f));
        assert_eq!(fs.lookup(ROOT, etc, b"../etc/hostname"), Ok(f));
        assert_eq!(fs.lookup(ROOT, etc, b"/"), Ok(ROOT));
        assert_eq!(fs.lookup(ROOT, ROOT, b"/etc/"), Ok(etc));
        assert_eq!(
            fs.lookup(ROOT, ROOT, b"/etc/hostname/"),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(
            fs.lookup(ROOT, ROOT, b"/etc/hostname/x"),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(fs.lookup(ROOT, ROOT, b"/etc/missing"), Err(Errno::ENOENT));
        assert_eq!(fs.lookup(ROOT, ROOT, b""), Err(Errno::ENOENT));
        assert_eq!(fs.lookup(ROOT, ROOT, b"/a\0b"), Err(Errno::EINVAL));
    }

    #[test]
    fn dot_dot_never_leaves_the_root() {
        let fs = sample();
        let etc = fs.lookup(ROOT, ROOT, b"/etc").unwrap();
        assert_eq!(fs.lookup(ROOT, ROOT, b"/../../.."), Ok(ROOT));
        assert_eq!(fs.lookup(ROOT, ROOT, b"../etc"), Ok(etc));
        // With /etc as the root, nothing outside it can be named.
        assert_eq!(fs.lookup(etc, etc, b"/"), Ok(etc));
        assert_eq!(fs.lookup(etc, etc, b".."), Ok(etc));
        assert_eq!(fs.lookup(etc, etc, b"../../dev/null"), Err(Errno::ENOENT));
        assert_eq!(fs.lookup(etc, etc, b"/dev/null"), Err(Errno::ENOENT));
        assert_eq!(
            fs.lookup(etc, etc, b"/../hostname"),
            fs.lookup(ROOT, ROOT, b"/etc/hostname")
        );
        assert!(fs.is_beneath(ROOT, etc));
        assert!(fs.is_beneath(etc, etc));
        let dev = fs.lookup(ROOT, ROOT, b"/dev").unwrap();
        assert!(!fs.is_beneath(etc, dev));
        // Files and devices too, not only directories.
        let null = fs.lookup(ROOT, ROOT, b"/dev/null").unwrap();
        let hostname = fs.lookup(ROOT, ROOT, b"/etc/hostname").unwrap();
        assert!(fs.is_beneath(ROOT, null) && fs.is_beneath(etc, hostname));
        assert!(!fs.is_beneath(etc, null));
    }

    #[test]
    fn length_limits() {
        let fs = sample();
        let long_name = alloc::vec![b'a'; NAME_MAX + 1];
        assert_eq!(fs.lookup(ROOT, ROOT, &long_name), Err(Errno::ENAMETOOLONG));
        let ok_name = alloc::vec![b'a'; NAME_MAX];
        assert_eq!(fs.lookup(ROOT, ROOT, &ok_name), Err(Errno::ENOENT));
        let long_path = alloc::vec![b'/'; PATH_MAX];
        assert_eq!(fs.lookup(ROOT, ROOT, &long_path), Err(Errno::ENAMETOOLONG));
        let ok_path = alloc::vec![b'/'; PATH_MAX - 1];
        assert_eq!(fs.lookup(ROOT, ROOT, &ok_path), Ok(ROOT));
    }

    #[test]
    fn files_read_write_and_stat() {
        let mut fs = sample();
        let f = fs.lookup(ROOT, ROOT, b"/etc/hostname").unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(fs.read(f, 0, &mut buf), Ok(5));
        assert_eq!(&buf[..5], b"keel\n");
        assert_eq!(fs.read(f, 3, &mut buf), Ok(2));
        assert_eq!(fs.read(f, 5, &mut buf), Ok(0));
        assert_eq!(fs.read(f, u64::MAX, &mut buf), Ok(0));
        assert_eq!(fs.write(f, 8, b"!"), Ok(1));
        assert_eq!(fs.read(f, 0, &mut buf), Ok(9));
        assert_eq!(&buf[..9], b"keel\n\0\0\0!");
        assert_eq!(fs.bytes_used(), 9);
        assert_eq!(fs.write(f, u64::MAX, b"x"), Err(Errno::EFBIG));
        fs.set_len(f, 2).unwrap();
        assert_eq!(fs.bytes_used(), 2);
        let s = fs.stat(f).unwrap();
        assert_eq!((s.mode, s.size, s.nlink), (S_IFREG | 0o644, 2, 1));
        let etc = fs.lookup(ROOT, ROOT, b"/etc").unwrap();
        assert_eq!(fs.stat(etc).unwrap().mode, S_IFDIR | 0o755);
        assert_eq!(fs.stat(ROOT).unwrap().nlink, 4, "2 + etc + dev");
        let null = fs.lookup(ROOT, ROOT, b"/dev/null").unwrap();
        let s = fs.stat(null).unwrap();
        assert_eq!((s.mode & S_IFMT, s.rdev), (S_IFCHR, (1, 3)));
        assert_eq!(fs.read(etc, 0, &mut buf), Err(Errno::EISDIR));
        assert_eq!(fs.write(etc, 0, b"x"), Err(Errno::EISDIR));
        assert_eq!(fs.read(null, 0, &mut buf), Err(Errno::EINVAL));
    }

    #[test]
    fn snapshots_are_not_changed_by_later_writes() {
        let mut fs = sample();
        let f = fs.lookup(ROOT, ROOT, b"/etc/hostname").unwrap();
        let before = fs.contents(f).unwrap();
        fs.write(f, 0, b"KEEL").unwrap();
        assert_eq!(&before[..], b"keel\n");
        assert_eq!(&fs.contents(f).unwrap()[..], b"KEEL\n");
    }

    /// A check that allows buffers of at most 64 bytes.
    fn at_most_64(bytes: usize) -> bool {
        bytes <= 64
    }

    #[test]
    fn growth_asks_first_and_falls_back_from_doubling() {
        let mut fs = Fs::new(1 << 20);
        fs.set_allocation_check(at_most_64);
        let ino = fs.create_file(ROOT, b"f", 0o644).unwrap();
        assert_eq!(fs.write(ino, 0, &[1; 40]), Ok(40));
        // 50 bytes: doubling would ask for 80; it falls back to exactly 50.
        assert_eq!(fs.write(ino, 40, &[2; 10]), Ok(10));
        // 65 bytes: more than the check allows at all.
        assert_eq!(fs.write(ino, 50, &[3; 15]), Err(Errno::ENOMEM));
        assert_eq!(
            fs.stat(ino).unwrap().size,
            50,
            "a refused write changes nothing"
        );
        // Copying a file a reader holds asks too.
        let _snapshot = fs.contents(ino).unwrap();
        fs.set_allocation_check(|bytes| bytes < 50);
        assert_eq!(fs.write(ino, 0, b"x"), Err(Errno::ENOMEM));
    }

    #[test]
    fn node_limit_is_enforced() {
        let mut fs = Fs::new(1 << 20);
        fs.set_node_limit(3); // the root and two more
        assert!(fs.create_file(ROOT, b"a", 0o644).is_ok());
        assert!(fs.create_dir(ROOT, b"d", 0o755).is_ok());
        assert_eq!(fs.create_file(ROOT, b"b", 0o644), Err(Errno::ENOSPC));
        assert_eq!(fs.create_dir(ROOT, b"e", 0o755), Err(Errno::ENOSPC));
        assert_eq!(fs.usage().1, 3);
    }

    #[test]
    fn writing_a_file_a_reader_holds_copies_it() {
        let mut fs = Fs::new(1 << 20);
        let ino = fs.create_file(ROOT, b"f", 0o644).unwrap();
        fs.write(ino, 0, b"abc").unwrap();
        let snapshot = fs.contents(ino).unwrap();
        fs.write(ino, 1, b"XYZ").unwrap();
        assert_eq!(
            snapshot.as_slice(),
            b"abc",
            "the reader's copy is unchanged"
        );
        assert_eq!(fs.contents(ino).unwrap().as_slice(), b"aXYZ");
        fs.set_len(ino, 2).unwrap();
        assert_eq!(fs.contents(ino).unwrap().as_slice(), b"aX");
    }

    #[test]
    fn byte_limit_is_enforced() {
        let mut fs = Fs::new(10);
        let f = fs.create_file(ROOT, b"f", 0o644).unwrap();
        assert_eq!(fs.write(f, 0, b"0123456789"), Ok(10));
        assert_eq!(fs.write(f, 10, b"x"), Err(Errno::ENOSPC));
        assert_eq!(fs.write(f, 0, b"abc"), Ok(3), "overwriting does not grow");
        assert_eq!(fs.set_len(f, 11), Err(Errno::ENOSPC));
        let g = fs.create_file(ROOT, b"g", 0o644).unwrap();
        assert_eq!(fs.write(g, 0, b"x"), Err(Errno::ENOSPC));
        fs.set_len(f, 0).unwrap();
        assert_eq!(fs.write(g, 0, b"x"), Ok(1));
    }

    #[test]
    fn create_checks_names() {
        let mut fs = sample();
        let etc = fs.lookup(ROOT, ROOT, b"/etc").unwrap();
        assert_eq!(fs.create_file(etc, b"hostname", 0o644), Err(Errno::EEXIST));
        assert_eq!(fs.create_file(etc, b"a/b", 0o644), Err(Errno::EINVAL));
        assert_eq!(fs.create_file(etc, b"", 0o644), Err(Errno::EINVAL));
        assert_eq!(fs.create_file(etc, b"..", 0o644), Err(Errno::EEXIST));
        let f = fs.lookup(ROOT, ROOT, b"/etc/hostname").unwrap();
        assert_eq!(fs.create_file(f, b"x", 0o644), Err(Errno::ENOTDIR));
        assert_eq!(
            fs.lookup_parent(ROOT, ROOT, b"/etc/new"),
            Ok((etc, &b"new"[..]))
        );
        assert_eq!(fs.lookup_parent(ROOT, ROOT, b"/"), Err(Errno::EEXIST));
        assert_eq!(
            fs.lookup_parent(ROOT, ROOT, b"/etc/hostname/x"),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(fs.lookup_parent(ROOT, ROOT, b"/nope/x"), Err(Errno::ENOENT));
    }

    fn entry<'a>(name: &'a [u8], kind: cpio::Kind, data: &'a [u8]) -> cpio::Entry<'a> {
        cpio::Entry {
            name,
            kind,
            permissions: 0o644,
            data,
        }
    }

    #[test]
    fn unpacks_archives() {
        let mut fs = Fs::new(1 << 20);
        let skipped = fs
            .unpack(
                ROOT,
                &[
                    entry(b"etc", cpio::Kind::Directory, &[]),
                    entry(b"etc/keel-release", cpio::Kind::File, b"Keel\n"),
                    entry(b"test/startup", cpio::Kind::File, b"\x7fELF"),
                    entry(b"bin/sh", cpio::Kind::Other, b"busybox"),
                ],
            )
            .unwrap();
        assert_eq!(skipped, 1);
        let f = fs.lookup(ROOT, ROOT, b"/test/startup").unwrap();
        assert_eq!(&fs.contents(f).unwrap()[..], b"\x7fELF");
        assert_eq!(fs.lookup(ROOT, ROOT, b"/bin/sh"), Err(Errno::ENOENT));
        let mut fs = Fs::new(1 << 20);
        assert_eq!(
            fs.unpack(ROOT, &[entry(b"a/../../x", cpio::Kind::File, b"")]),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            fs.unpack(
                ROOT,
                &[
                    entry(b"x", cpio::Kind::File, b""),
                    entry(b"x", cpio::Kind::File, b"")
                ]
            ),
            Err(Errno::EEXIST)
        );
        let mut fs = Fs::new(3);
        assert_eq!(
            fs.unpack(ROOT, &[entry(b"big", cpio::Kind::File, b"four")]),
            Err(Errno::ENOSPC)
        );
    }

    /// Random paths against a small tree never panic and never resolve to
    /// anything outside the chosen root.
    #[test]
    fn random_paths_stay_beneath_the_root() {
        let fs = sample();
        let etc = fs.lookup(ROOT, ROOT, b"/etc").unwrap();
        let alphabet: &[&[u8]] = &[
            b"/",
            b".",
            b"..",
            b"etc",
            b"dev",
            b"null",
            b"hostname",
            b"x",
        ];
        let mut state = 0x853C_49E6_748F_EA9Bu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let mut path = Vec::new();
            for _ in 0..(next() % 10) {
                path.extend_from_slice(alphabet[(next() % alphabet.len() as u64) as usize]);
                if next() % 2 == 0 {
                    path.push(b'/');
                }
            }
            for root in [ROOT, etc] {
                if let Ok(ino) = fs.lookup(root, root, &path) {
                    assert!(
                        fs.is_beneath(root, ino),
                        "{:?}",
                        core::str::from_utf8(&path)
                    );
                }
            }
        }
    }
}
