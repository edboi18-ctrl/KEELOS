//! In-memory filesystem and path lookup (P1-T12; P3-T8, ADR 0022).
//!
//! One tmpfs holds the whole tree: the initramfs is unpacked into it at
//! boot and `/dev` is added beside it. Nodes live in a map keyed by inode
//! number; numbers are 64-bit and never reused, so a stale number (a
//! process's working directory after its removal, a page cache key) can
//! only ever name nothing, never a different file. The kernel guards the
//! whole [`Fs`] with one lock.
//!
//! Lookup always starts from an explicit root directory, and `..` at that
//! root stays there. A compartment's root is just another directory, so
//! no path can name anything above it (SR-4). Symbolic links keep that: an
//! absolute target starts again at the same root, and `..` in a target is
//! clamped the same way (ADR 0022).
//!
//! A node lives while a name refers to it (its links) or something holds
//! it (its pins: open file descriptions and address spaces that map it),
//! as Linux frees an inode when its link count and its references are both
//! zero (unlink(2): "If the name was the last link to a file but any
//! processes still have the file open, the file will remain in existence
//! until the last file descriptor referring to it is closed").
//!
//! Device nodes are limited to the kinds in [`Device`]: there is no way to
//! create `/dev/mem`, `/dev/kmem` or `/dev/port` (SR-9).
//!
//! Mode bits and timestamps are stored and reported for compatibility
//! only; no check here or elsewhere grants or denies anything by user ID
//! or mode (SR-6). Access is controlled by handle rights (SR-1) and
//! compartment roots.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::compartment::Quota;
use crate::cpio;
use crate::errno::Errno;

/// Longest path accepted, including the terminating NUL, and longest
/// name (Linux `include/uapi/linux/limits.h`: PATH_MAX 4096, NAME_MAX 255).
pub const PATH_MAX: usize = 4096;
pub const NAME_MAX: usize = 255;

/// Most symbolic links one lookup follows (`MAXSYMLINKS`,
/// `include/linux/namei.h`): past it, ELOOP.
pub const MAXSYMLINKS: usize = 40;

/// File type bits for `st_mode` (Linux `include/uapi/linux/stat.h`).
pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFSOCK: u32 = 0o140000;

/// tmpfs's size for each directory entry, and for an empty directory two
/// of them (`BOGO_DIRENT_SIZE` 20, `mm/shmem.c`), which `stat` reports as a
/// directory's size.
const BOGO_DIRENT_SIZE: u64 = 20;

/// An inode number. Never reused (see the module comment).
pub type Ino = u64;

/// The root directory of the tree.
pub const ROOT: Ino = 0;

/// A point in time: seconds and nanoseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: u32,
}

/// The character devices Keel provides. Numbers from Linux
/// `Documentation/admin-guide/devices.txt` (char major 1: 3 null, 5 zero,
/// 9 urandom; major 5: 1 console, 2 ptmx; majors 136-143: the Unix98 pty
/// slaves, `/dev/pts/N`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Device {
    Console,
    Null,
    Zero,
    Urandom,
    /// `/dev/ptmx`: opening it makes a new pty pair (P3-T12).
    Ptmx,
    /// `/dev/pts/N`: a pty slave.
    Pts(u32),
}

impl Device {
    /// `(major, minor)`.
    pub fn number(self) -> (u32, u32) {
        match self {
            Device::Console => (5, 1),
            Device::Null => (1, 3),
            Device::Zero => (1, 5),
            Device::Urandom => (1, 9),
            Device::Ptmx => (5, 2),
            // UNIX98_PTY_SLAVE_MAJOR 136, 256 minors a major.
            Device::Pts(n) => (136 + n / 256, n % 256),
        }
    }

    /// Whether it is a terminal (opened as one, not seekable: tty_open
    /// calls `nonseekable_open`).
    pub fn is_tty(self) -> bool {
        matches!(self, Device::Console | Device::Ptmx | Device::Pts(_))
    }
}

#[derive(Clone, Debug)]
enum Contents {
    /// File data. `Arc` so a reader (the ELF loader) can take a snapshot
    /// without holding the filesystem lock; writes copy on demand.
    File(Arc<Vec<u8>>),
    Directory(BTreeMap<Vec<u8>, Ino>),
    Device(Device),
    /// A symbolic link's target, as given (never empty).
    Symlink(Vec<u8>),
    /// A Unix domain socket's name (bind(2), ADR 0027): which socket, if
    /// any, it names is the socket layer's record, not the node's.
    Socket,
}

#[derive(Clone, Debug)]
struct Node {
    contents: Contents,
    /// Permission bits only (`& 0o7777`).
    permissions: u32,
    /// For a directory, the directory holding it (the root is its own
    /// parent). Directories have one name each (no hard links to them),
    /// so this answers "is this beneath that root?". For other nodes, the
    /// directory they were first created in (informational).
    parent: Ino,
    /// The compartment quota this node's data and names are charged to
    /// (P3-S4): the creator's, or for a node the kernel made (none), the
    /// first compartment to grow it.
    owner: Option<Arc<Quota>>,
    /// Bytes of a file charged to `owner`: the last `charged` bytes of the
    /// file (so shrinking gives them back first). At most its length.
    charged: usize,
    /// Directory entries naming it (hard links). 0 once removed: it then
    /// lives only while pinned, and a directory accepts no new entries.
    links: u32,
    /// Open file descriptions and address spaces holding it.
    pins: u32,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
}

/// What a node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Device(Device),
    Symlink,
    /// A Unix socket's name in the filesystem (ADR 0027).
    Socket,
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
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
}

/// The last component of a path, as Linux's `filename_parentat` sorts it
/// (`LAST_NORM`, `LAST_DOT`, `LAST_DOTDOT`, `LAST_ROOT`): each call that
/// creates or removes a name refuses the last three with its own error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Last<'p> {
    Name(&'p [u8]),
    Dot,
    DotDot,
    Root,
}

/// A path's parent directory and last component, and whether the path
/// ended in `/` (which makes the last component name a directory).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parent<'p> {
    pub dir: Ino,
    pub last: Last<'p>,
    pub trailing_slash: bool,
}

/// rename flags (`include/uapi/linux/fs.h`).
pub const RENAME_NOREPLACE: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;
pub const RENAME_WHITEOUT: u32 = 4;

/// Most directory entries one filesystem may hold (a node per entry, a
/// hard link counting as one more, as tmpfs's `nr_inodes` counts both:
/// `shmem_reserve_inode` in `shmem_link`). Each is kernel memory, so
/// without a cap `openat(O_CREAT)` in a loop exhausts the kernel heap
/// (F-0011). 65536 with the longest names is a few tens of MiB. Per
/// compartment from Phase 3 (SR-8).
pub const NODE_LIMIT: usize = 65536;

/// The filesystem.
pub struct Fs {
    nodes: BTreeMap<Ino, Node>,
    /// The next inode number to hand out.
    next_ino: Ino,
    /// Directory entries and nodes that have none (pinned after removal),
    /// counted against `node_limit`.
    slots: usize,
    /// Bytes of file data held, and the cap (SR-8 groundwork; per
    /// compartment from Phase 3).
    bytes_used: usize,
    byte_limit: usize,
    /// Cap on `slots` (`NODE_LIMIT`; lower in tests).
    node_limit: usize,
    /// Asked before a file buffer is allocated: may this many bytes be
    /// allocated now? The kernel answers from its frame reserve
    /// (`linux-abi::fs`), so one write cannot take the reserve that the
    /// admission check protects (third Phase 1 audit, C3). Default: yes.
    may_allocate: fn(usize) -> bool,
    /// The time now, for timestamps (the kernel's realtime clock). Default:
    /// the epoch.
    clock: fn() -> Timespec,
    /// Told the number of each node as it is freed (the kernel drops its
    /// shared pages). Default: nothing.
    on_free: fn(Ino),
}

fn always(_: usize) -> bool {
    true
}

fn epoch() -> Timespec {
    Timespec::default()
}

fn nothing(_: Ino) {}

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

/// Checks a path's length limits and characters.
fn check_path(path: &[u8]) -> Result<(), Errno> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    if path.len() >= PATH_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    if path.contains(&0) {
        return Err(Errno::EINVAL);
    }
    if path.split(|&b| b == b'/').any(|c| c.len() > NAME_MAX) {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(())
}

/// Splits a path into components, checking the length limits.
fn components(path: &[u8]) -> Result<impl Iterator<Item = &[u8]>, Errno> {
    check_path(path)?;
    Ok(path.split(|&b| b == b'/').filter(|c| !c.is_empty()))
}

/// Whether `path` ends in `/` after its last component (a path of only
/// slashes is the root and has none).
pub fn has_trailing_slash(path: &[u8]) -> bool {
    path.last() == Some(&b'/') && path.iter().any(|&b| b != b'/')
}

impl Node {
    fn new(contents: Contents, permissions: u32, owner: Option<Arc<Quota>>, now: Timespec) -> Node {
        Node {
            contents,
            permissions: permissions & 0o7777,
            parent: ROOT,
            owner,
            charged: 0,
            links: 0,
            pins: 0,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }
}

impl Fs {
    /// An empty tree with a root directory and a cap on file data.
    pub fn new(byte_limit: usize) -> Fs {
        let mut root = Node::new(
            Contents::Directory(BTreeMap::new()),
            0o755,
            None,
            Timespec::default(),
        );
        root.links = 1;
        let mut nodes = BTreeMap::new();
        nodes.insert(ROOT, root);
        Fs {
            nodes,
            next_ino: ROOT + 1,
            slots: 1,
            bytes_used: 0,
            byte_limit,
            node_limit: NODE_LIMIT,
            may_allocate: always,
            clock: epoch,
            on_free: nothing,
        }
    }

    /// Sets the check made before a file buffer is allocated (C3).
    pub fn set_allocation_check(&mut self, check: fn(usize) -> bool) {
        self.may_allocate = check;
    }

    /// Sets the clock timestamps come from.
    pub fn set_clock(&mut self, clock: fn() -> Timespec) {
        self.clock = clock;
    }

    /// Sets what is told the number of each freed node.
    pub fn set_free_hook(&mut self, hook: fn(Ino)) {
        self.on_free = hook;
    }

    /// Sets the cap on the number of entries (tests use a small one) and
    /// returns the previous cap.
    pub fn set_node_limit(&mut self, limit: usize) -> usize {
        core::mem::replace(&mut self.node_limit, limit)
    }

    /// Bytes of file data held, and the entries counted against the cap.
    pub fn usage(&self) -> (usize, usize) {
        (self.bytes_used, self.slots)
    }

    /// The cap on file data and the cap on entries (statfs).
    pub fn limits(&self) -> (usize, usize) {
        (self.byte_limit, self.node_limit)
    }

    /// Nodes alive (tests).
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn now(&self) -> Timespec {
        (self.clock)()
    }

    fn node(&self, ino: Ino) -> Result<&Node, Errno> {
        self.nodes.get(&ino).ok_or(Errno::ENOENT)
    }

    fn node_mut(&mut self, ino: Ino) -> Result<&mut Node, Errno> {
        self.nodes.get_mut(&ino).ok_or(Errno::ENOENT)
    }

    /// What `ino` is.
    pub fn kind(&self, ino: Ino) -> Result<Kind, Errno> {
        Ok(match self.node(ino)?.contents {
            Contents::File(_) => Kind::File,
            Contents::Directory(_) => Kind::Directory,
            Contents::Device(device) => Kind::Device(device),
            Contents::Symlink(_) => Kind::Symlink,
            Contents::Socket => Kind::Socket,
        })
    }

    /// One step of lookup: `name` in directory `dir`, with `.` and `..`
    /// handled and `..` clamped at `root`. Symbolic links are not followed
    /// here.
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

    /// Where a lookup of `path` starts: `root` for an absolute path, else
    /// `cwd`, which must still lie beneath `root`. A directory moved out
    /// from under a confined process's working directory (by the system
    /// compartment, which sees both places) would otherwise let `..` climb
    /// above its root; such a working directory names nothing (ENOENT),
    /// like a removed one (ADR 0022).
    fn start(&self, root: Ino, cwd: Ino, path: &[u8]) -> Result<Ino, Errno> {
        if path.first() == Some(&b'/') {
            Ok(root)
        } else if self.is_beneath(root, cwd) {
            Ok(cwd)
        } else {
            Err(Errno::ENOENT)
        }
    }

    /// Walks `names` from `dir`, following symbolic links: every link met
    /// before the last name, and the last too if `follow_last`. A link's
    /// target is walked from `root` if absolute, else from the directory
    /// holding the link; more than `MAXSYMLINKS` links is ELOOP. `budget`
    /// counts the links followed so far across nested targets.
    fn walk(
        &self,
        root: Ino,
        mut dir: Ino,
        names: &[&[u8]],
        follow_last: bool,
        budget: &mut usize,
    ) -> Result<Ino, Errno> {
        for (i, &name) in names.iter().enumerate() {
            let next = self.step(root, dir, name)?;
            let last = i + 1 == names.len();
            match &self.node(next)?.contents {
                Contents::Symlink(target) if !last || follow_last => {
                    *budget += 1;
                    if *budget > MAXSYMLINKS {
                        return Err(Errno::ELOOP);
                    }
                    let from = if target.first() == Some(&b'/') {
                        root
                    } else {
                        dir
                    };
                    let inner: Vec<&[u8]> = components(target)?.collect();
                    dir = self.walk(root, from, &inner, true, budget)?;
                }
                _ => dir = next,
            }
        }
        Ok(dir)
    }

    /// Resolves `path`, following every symbolic link. An absolute path
    /// starts at `root`, a relative one at `cwd`; no path leaves `root`.
    pub fn lookup(&self, root: Ino, cwd: Ino, path: &[u8]) -> Result<Ino, Errno> {
        self.resolve(root, cwd, path, true)
    }

    /// Resolves `path`; a symbolic link as its last component is followed
    /// only if `follow_last` (lstat(2), O_NOFOLLOW, AT_SYMLINK_NOFOLLOW
    /// pass false). A trailing `/` always follows it and requires a
    /// directory (ENOTDIR).
    pub fn resolve(
        &self,
        root: Ino,
        cwd: Ino,
        path: &[u8],
        follow_last: bool,
    ) -> Result<Ino, Errno> {
        let names: Vec<&[u8]> = components(path)?.collect();
        let start = self.start(root, cwd, path)?;
        let slash = has_trailing_slash(path);
        let mut budget = 0;
        let at = self.walk(root, start, &names, follow_last || slash, &mut budget)?;
        if slash && self.kind(at)? != Kind::Directory {
            return Err(Errno::ENOTDIR);
        }
        Ok(at)
    }

    /// Resolves all but the last component of `path` (following links),
    /// for calls that create, remove or rename the last one.
    pub fn parent<'p>(&self, root: Ino, cwd: Ino, path: &'p [u8]) -> Result<Parent<'p>, Errno> {
        let names: Vec<&[u8]> = components(path)?.collect();
        let start = self.start(root, cwd, path)?;
        let trailing_slash = has_trailing_slash(path);
        let Some((&last, init)) = names.split_last() else {
            return Ok(Parent {
                dir: start,
                last: Last::Root,
                trailing_slash: false,
            });
        };
        let mut budget = 0;
        let dir = self.walk(root, start, init, true, &mut budget)?;
        if self.kind(dir)? != Kind::Directory {
            return Err(Errno::ENOTDIR);
        }
        let last = match last {
            b"." => Last::Dot,
            b".." => Last::DotDot,
            name => Last::Name(name),
        };
        Ok(Parent {
            dir,
            last,
            trailing_slash,
        })
    }

    /// Resolves all but the last component of `path`, returning the parent
    /// directory and the final name (for create). "/", "." and ".." as
    /// the last component are EEXIST.
    pub fn lookup_parent<'p>(
        &self,
        root: Ino,
        cwd: Ino,
        path: &'p [u8],
    ) -> Result<(Ino, &'p [u8]), Errno> {
        match self.parent(root, cwd, path)? {
            Parent {
                dir,
                last: Last::Name(name),
                ..
            } => Ok((dir, name)),
            _ => Err(Errno::EEXIST),
        }
    }

    /// Whether `ino` is `root` or lies beneath it (through directories'
    /// parents).
    pub fn is_beneath(&self, root: Ino, mut ino: Ino) -> bool {
        loop {
            if ino == root {
                return true;
            }
            match self.node(ino) {
                Ok(node) if node.parent != ino && node.links > 0 => ino = node.parent,
                _ => return false,
            }
        }
    }

    /// The path of directory `dir` from `root` (getcwd(2)): ENOENT if it
    /// has been removed or is not beneath `root`.
    pub fn path_of(&self, root: Ino, dir: Ino) -> Result<Vec<u8>, Errno> {
        if !self.is_beneath(root, dir) {
            return Err(Errno::ENOENT);
        }
        let mut names: Vec<&[u8]> = Vec::new();
        let mut at = dir;
        while at != root {
            let parent = self.node(at)?.parent;
            let Contents::Directory(entries) = &self.node(parent)?.contents else {
                return Err(Errno::ENOENT);
            };
            let name = entries
                .iter()
                .find(|&(_, &i)| i == at)
                .map(|(n, _)| n.as_slice())
                .ok_or(Errno::ENOENT)?;
            names.push(name);
            at = parent;
        }
        let mut path = Vec::new();
        for name in names.iter().rev() {
            path.push(b'/');
            path.extend_from_slice(name);
        }
        if path.is_empty() {
            path.push(b'/');
        }
        Ok(path)
    }

    fn check_name(name: &[u8]) -> Result<(), Errno> {
        if name.is_empty() || name.len() > NAME_MAX || name.contains(&b'/') || name.contains(&0) {
            return Err(Errno::EINVAL);
        }
        if name == b"." || name == b".." {
            return Err(Errno::EEXIST);
        }
        Ok(())
    }

    /// Takes one entry slot: from the filesystem's cap and, if given, one
    /// node from `quota`. ENOSPC if either is full.
    fn take_slot(&mut self, quota: Option<&Arc<Quota>>) -> Result<(), Errno> {
        if self.slots >= self.node_limit {
            return Err(Errno::ENOSPC);
        }
        if let Some(quota) = quota
            && !quota.nodes.try_charge(1)
        {
            return Err(Errno::ENOSPC);
        }
        self.slots += 1;
        Ok(())
    }

    fn give_slot(&mut self, quota: Option<&Arc<Quota>>) {
        self.slots = self.slots.saturating_sub(1);
        if let Some(quota) = quota {
            quota.nodes.uncharge(1);
        }
    }

    /// Checks that `dir` can take a new entry `name`: a live directory
    /// without one. A removed directory takes none (ENOENT, as Linux's
    /// `IS_DEADDIR`).
    fn can_add(&self, dir: Ino, name: &[u8]) -> Result<(), Errno> {
        Self::check_name(name)?;
        let node = self.node(dir)?;
        let Contents::Directory(entries) = &node.contents else {
            return Err(Errno::ENOTDIR);
        };
        if node.links == 0 {
            return Err(Errno::ENOENT);
        }
        if entries.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        Ok(())
    }

    /// Enters `ino` as `name` in `dir` (already checked by `can_add`), and
    /// stamps the directory.
    fn enter(&mut self, dir: Ino, name: &[u8], ino: Ino) {
        let now = self.now();
        if let Ok(d) = self.node_mut(dir) {
            if let Contents::Directory(entries) = &mut d.contents {
                entries.insert(name.to_vec(), ino);
            }
            d.mtime = now;
            d.ctime = now;
        }
    }

    fn add(&mut self, dir: Ino, name: &[u8], mut node: Node) -> Result<Ino, Errno> {
        self.can_add(dir, name)?;
        // Charged last, after every other reason to refuse.
        let owner = node.owner.clone();
        self.take_slot(owner.as_ref())?;
        let ino = self.next_ino;
        self.next_ino += 1;
        node.parent = dir;
        node.links = 1;
        self.nodes.insert(ino, node);
        self.enter(dir, name, ino);
        Ok(ino)
    }

    /// Creates an empty file (for the kernel: charged to no quota).
    pub fn create_file(&mut self, dir: Ino, name: &[u8], permissions: u32) -> Result<Ino, Errno> {
        self.create_file_as(dir, name, permissions, None)
    }

    /// Creates an empty file owned by `quota` (its creator's compartment),
    /// which is charged one node: ENOSPC if it has none left (open(2):
    /// "the device containing path has no room for the new file").
    pub fn create_file_as(
        &mut self,
        dir: Ino,
        name: &[u8],
        permissions: u32,
        quota: Option<&Arc<Quota>>,
    ) -> Result<Ino, Errno> {
        let node = Node::new(
            Contents::File(Arc::new(Vec::new())),
            permissions,
            quota.cloned(),
            self.now(),
        );
        self.add(dir, name, node)
    }

    /// Creates a directory (for the kernel: charged to no quota).
    pub fn create_dir(&mut self, dir: Ino, name: &[u8], permissions: u32) -> Result<Ino, Errno> {
        self.create_dir_as(dir, name, permissions, None)
    }

    /// Creates a directory owned by `quota`, charged one node.
    pub fn create_dir_as(
        &mut self,
        dir: Ino,
        name: &[u8],
        permissions: u32,
        quota: Option<&Arc<Quota>>,
    ) -> Result<Ino, Errno> {
        let node = Node::new(
            Contents::Directory(BTreeMap::new()),
            permissions,
            quota.cloned(),
            self.now(),
        );
        self.add(dir, name, node)
    }

    /// Creates a socket node (`unix_bind_bsd`'s `vfs_mknod` with
    /// S_IFSOCK), owned by `quota`: EEXIST if the name is taken.
    pub fn create_socket_as(
        &mut self,
        dir: Ino,
        name: &[u8],
        permissions: u32,
        quota: Option<&Arc<Quota>>,
    ) -> Result<Ino, Errno> {
        let node = Node::new(Contents::Socket, permissions, quota.cloned(), self.now());
        self.add(dir, name, node)
    }

    /// Creates a device node.
    pub fn create_device(&mut self, dir: Ino, name: &[u8], device: Device) -> Result<Ino, Errno> {
        self.create_device_mode(dir, name, device, 0o666)
    }

    /// Creates a device node with `permissions`.
    pub fn create_device_mode(
        &mut self,
        dir: Ino,
        name: &[u8],
        device: Device,
        permissions: u32,
    ) -> Result<Ino, Errno> {
        let node = Node::new(Contents::Device(device), permissions, None, self.now());
        self.add(dir, name, node)
    }

    /// Creates a symbolic link to `target` (symlink(2)), owned by
    /// `quota`. As tmpfs (`shmem_symlink`): a target that with its NUL
    /// exceeds a page is ENAMETOOLONG; an empty one is ENOENT (`do_symlinkat`
    /// rejects an empty name). Mode 0777, as every Linux symlink.
    pub fn create_symlink_as(
        &mut self,
        dir: Ino,
        name: &[u8],
        target: &[u8],
        quota: Option<&Arc<Quota>>,
    ) -> Result<Ino, Errno> {
        if target.is_empty() {
            return Err(Errno::ENOENT);
        }
        if target.len() + 1 > PATH_MAX || target.contains(&0) {
            return Err(Errno::ENAMETOOLONG);
        }
        let node = Node::new(
            Contents::Symlink(target.to_vec()),
            0o777,
            quota.cloned(),
            self.now(),
        );
        self.add(dir, name, node)
    }

    /// A file no directory names, holding `data`, already pinned once (by
    /// the open file description the caller makes for it): a procfs
    /// file's contents as of its open (ADR 0024). It goes when unpinned.
    /// Its bytes count against the filesystem's cap (ENOSPC) but no
    /// compartment's quota: a process holds at most its handle limit of
    /// them, and each is a few kilobytes.
    pub fn create_detached(&mut self, data: Vec<u8>, permissions: u32) -> Result<Ino, Errno> {
        if self
            .bytes_used
            .checked_add(data.len())
            .is_none_or(|t| t > self.byte_limit)
        {
            return Err(Errno::ENOSPC);
        }
        self.bytes_used += data.len();
        let mut node = Node::new(
            Contents::File(Arc::new(data)),
            permissions,
            None,
            self.now(),
        );
        node.pins = 1;
        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.insert(ino, node);
        Ok(ino)
    }

    /// A symbolic link's target (readlink(2)): EINVAL if `ino` is not one.
    pub fn readlink(&self, ino: Ino) -> Result<Vec<u8>, Errno> {
        match &self.node(ino)?.contents {
            Contents::Symlink(target) => Ok(target.clone()),
            _ => Err(Errno::EINVAL),
        }
    }

    /// Adds `name` in `dir` for existing node `ino` (link(2)). A directory
    /// cannot be linked (EPERM, as `vfs_link`). The new name costs one
    /// slot, charged to the node's owner, as tmpfs reserves an inode for
    /// each hard link.
    pub fn link(&mut self, ino: Ino, dir: Ino, name: &[u8]) -> Result<(), Errno> {
        let node = self.node(ino)?;
        if matches!(node.contents, Contents::Directory(_)) {
            return Err(Errno::EPERM);
        }
        // A file whose last name is gone cannot get a new one (ENOENT,
        // `vfs_link`: "i_nlink == 0 && !(inode->i_state & I_LINKABLE)").
        if node.links == 0 {
            return Err(Errno::ENOENT);
        }
        let owner = node.owner.clone();
        self.can_add(dir, name)?;
        self.take_slot(owner.as_ref())?;
        let now = self.now();
        let node = self.node_mut(ino)?;
        node.links += 1;
        node.ctime = now;
        self.enter(dir, name, ino);
        Ok(())
    }

    /// The node `name` names in `dir`.
    pub fn child(&self, dir: Ino, name: &[u8]) -> Result<Ino, Errno> {
        match &self.node(dir)?.contents {
            Contents::Directory(entries) => entries.get(name).copied().ok_or(Errno::ENOENT),
            _ => Err(Errno::ENOTDIR),
        }
    }

    /// Takes `name` out of `dir` and drops the link it held: the node goes
    /// once nothing else names or holds it. Stamps the directory and the
    /// node.
    fn detach(&mut self, dir: Ino, name: &[u8]) -> Result<Ino, Errno> {
        let now = self.now();
        let ino = {
            let d = self.node_mut(dir)?;
            let Contents::Directory(entries) = &mut d.contents else {
                return Err(Errno::ENOTDIR);
            };
            let ino = entries.remove(name).ok_or(Errno::ENOENT)?;
            d.mtime = now;
            d.ctime = now;
            ino
        };
        let owner = self.node(ino)?.owner.clone();
        self.give_slot(owner.as_ref());
        let node = self.node_mut(ino)?;
        node.links = node.links.saturating_sub(1);
        // A removed directory has no links left at all ("." included).
        if matches!(node.contents, Contents::Directory(_)) {
            node.links = 0;
        }
        node.ctime = now;
        self.maybe_free(ino);
        Ok(ino)
    }

    /// unlink(2) of `name` in `dir`: not a directory (EISDIR, as
    /// `may_delete`).
    pub fn unlink(&mut self, dir: Ino, name: &[u8]) -> Result<(), Errno> {
        let ino = self.child(dir, name)?;
        if self.kind(ino)? == Kind::Directory {
            return Err(Errno::EISDIR);
        }
        self.detach(dir, name).map(|_| ())
    }

    /// rmdir(2) of `name` in `dir`: a directory (ENOTDIR), empty
    /// (ENOTEMPTY, `simple_rmdir`), and not the filesystem's root (EBUSY).
    pub fn rmdir(&mut self, dir: Ino, name: &[u8]) -> Result<(), Errno> {
        let ino = self.child(dir, name)?;
        match &self.node(ino)?.contents {
            Contents::Directory(entries) if !entries.is_empty() => return Err(Errno::ENOTEMPTY),
            Contents::Directory(_) => {}
            _ => return Err(Errno::ENOTDIR),
        }
        if ino == ROOT {
            return Err(Errno::EBUSY);
        }
        self.detach(dir, name).map(|_| ())
    }

    /// Whether `ino` is `dir` or one of its ancestors' descendants: true
    /// if `dir` lies at or beneath directory `ino`.
    fn contains_dir(&self, ino: Ino, dir: Ino) -> bool {
        self.is_beneath(ino, dir)
    }

    /// rename(2) and renameat2(2), for `old_name` in `old_dir` to
    /// `new_name` in `new_dir`, as `do_renameat2`, `vfs_rename` and
    /// `shmem_rename2`:
    /// - flags other than RENAME_NOREPLACE and RENAME_EXCHANGE: EINVAL
    ///   (RENAME_WHITEOUT, for overlay filesystems, is not supported);
    ///   both together EINVAL;
    /// - no source ENOENT; RENAME_NOREPLACE onto an existing name EEXIST;
    ///   RENAME_EXCHANGE without a target ENOENT;
    /// - the same node under both names: nothing happens;
    /// - a directory into itself or beneath itself: EINVAL;
    /// - replacing: a directory by a non-directory EISDIR, the reverse
    ///   ENOTDIR, a non-empty directory ENOTEMPTY;
    /// - the replaced node loses that name, as by unlink or rmdir.
    pub fn rename(
        &mut self,
        old_dir: Ino,
        old_name: &[u8],
        new_dir: Ino,
        new_name: &[u8],
        flags: u32,
    ) -> Result<(), Errno> {
        if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) != 0
            || (flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0)
        {
            return Err(Errno::EINVAL);
        }
        let source = self.child(old_dir, old_name)?;
        let target = match self.child(new_dir, new_name) {
            Ok(t) => Some(t),
            Err(Errno::ENOENT) => None,
            Err(e) => return Err(e),
        };
        if flags & RENAME_NOREPLACE != 0 && target.is_some() {
            return Err(Errno::EEXIST);
        }
        if flags & RENAME_EXCHANGE != 0 && target.is_none() {
            return Err(Errno::ENOENT);
        }
        Self::check_name(new_name)?;
        let source_dir = self.kind(source)? == Kind::Directory;
        if target == Some(source) {
            return Ok(());
        }
        // Moving a directory beneath itself (lock_rename's trap).
        if source_dir && self.contains_dir(source, new_dir) {
            return Err(Errno::EINVAL);
        }
        if self.node(new_dir)?.links == 0 {
            return Err(Errno::ENOENT);
        }
        let now = self.now();
        if flags & RENAME_EXCHANGE != 0 {
            let target = target.ok_or(Errno::ENOENT)?;
            if self.kind(target)? == Kind::Directory && self.contains_dir(target, old_dir) {
                return Err(Errno::EINVAL);
            }
            self.set_entry(old_dir, old_name, target)?;
            self.set_entry(new_dir, new_name, source)?;
            for (ino, dir) in [(source, new_dir), (target, old_dir)] {
                let node = self.node_mut(ino)?;
                if matches!(node.contents, Contents::Directory(_)) {
                    node.parent = dir;
                }
                node.ctime = now;
            }
            self.stamp_dirs(old_dir, new_dir, now);
            return Ok(());
        }
        if let Some(target) = target {
            match (source_dir, &self.node(target)?.contents) {
                (true, Contents::Directory(entries)) if !entries.is_empty() => {
                    return Err(Errno::ENOTEMPTY);
                }
                (true, Contents::Directory(_)) => {}
                (true, _) => return Err(Errno::ENOTDIR),
                (false, Contents::Directory(_)) => return Err(Errno::EISDIR),
                (false, _) => {}
            }
            self.detach(new_dir, new_name)?;
        }
        // Move the entry: the source keeps its link and its slot.
        {
            let d = self.node_mut(old_dir)?;
            if let Contents::Directory(entries) = &mut d.contents {
                entries.remove(old_name);
            }
        }
        self.set_entry(new_dir, new_name, source)?;
        let node = self.node_mut(source)?;
        if matches!(node.contents, Contents::Directory(_)) {
            node.parent = new_dir;
        }
        node.ctime = now;
        self.stamp_dirs(old_dir, new_dir, now);
        Ok(())
    }

    fn set_entry(&mut self, dir: Ino, name: &[u8], ino: Ino) -> Result<(), Errno> {
        let Contents::Directory(entries) = &mut self.node_mut(dir)?.contents else {
            return Err(Errno::ENOTDIR);
        };
        entries.insert(name.to_vec(), ino);
        Ok(())
    }

    fn stamp_dirs(&mut self, a: Ino, b: Ino, now: Timespec) {
        for dir in [a, b] {
            if let Ok(d) = self.node_mut(dir) {
                d.mtime = now;
                d.ctime = now;
            }
        }
    }

    /// Holds `ino` alive (an open file description, an address space that
    /// maps it) even after its last name goes.
    pub fn pin(&mut self, ino: Ino) {
        if let Ok(node) = self.node_mut(ino) {
            node.pins += 1;
        }
    }

    /// Releases a hold taken with [`Fs::pin`]; frees the node if nothing
    /// names or holds it any more.
    pub fn unpin(&mut self, ino: Ino) {
        if let Ok(node) = self.node_mut(ino) {
            node.pins = node.pins.saturating_sub(1);
        }
        self.maybe_free(ino);
    }

    /// Frees `ino` if it has no links and no pins: its bytes go back to
    /// the filesystem and its owner, and `on_free` is told.
    fn maybe_free(&mut self, ino: Ino) {
        let Some(node) = self.nodes.get(&ino) else {
            return;
        };
        if ino == ROOT || node.links > 0 || node.pins > 0 {
            return;
        }
        let Some(node) = self.nodes.remove(&ino) else {
            return;
        };
        if let Contents::File(data) = &node.contents {
            self.bytes_used = self.bytes_used.saturating_sub(data.len());
            if let Some(owner) = &node.owner {
                owner.bytes.uncharge(node.charged);
            }
        }
        (self.on_free)(ino);
    }

    /// chmod(2): sets the permission bits (stored only, SR-6); stamps the
    /// change time.
    pub fn set_permissions(&mut self, ino: Ino, permissions: u32) -> Result<(), Errno> {
        let now = self.now();
        let node = self.node_mut(ino)?;
        node.permissions = permissions & 0o7777;
        node.ctime = now;
        Ok(())
    }

    /// utimensat(2): sets the access and modification times given (None
    /// leaves one as it is, UTIME_OMIT); the change time becomes now
    /// (`setattr_copy` with ATTR_CTIME).
    pub fn set_times(
        &mut self,
        ino: Ino,
        atime: Option<Timespec>,
        mtime: Option<Timespec>,
    ) -> Result<(), Errno> {
        let now = self.now();
        let node = self.node_mut(ino)?;
        if let Some(t) = atime {
            node.atime = t;
        }
        if let Some(t) = mtime {
            node.mtime = t;
        }
        node.ctime = now;
        Ok(())
    }

    /// The time now, from the filesystem's clock (UTIME_NOW).
    pub fn time_now(&self) -> Timespec {
        self.now()
    }

    /// Marks `ino` accessed, as Linux's default `relatime` does
    /// (`relatime_need_update`, `fs/inode.c`): only if the access time is
    /// not after the modification or change time, or is a day old.
    pub fn touch_atime(&mut self, ino: Ino) {
        let now = self.now();
        if let Ok(node) = self.node_mut(ino)
            && (node.atime <= node.mtime
                || node.atime <= node.ctime
                || now.sec - node.atime.sec >= 24 * 60 * 60)
        {
            node.atime = now;
        }
    }

    /// A snapshot of a file's contents, for readers that must not hold the
    /// filesystem lock (the ELF loader).
    pub fn contents(&self, ino: Ino) -> Result<Arc<Vec<u8>>, Errno> {
        match &self.node(ino)?.contents {
            Contents::File(data) => Ok(data.clone()),
            Contents::Directory(_) => Err(Errno::EISDIR),
            _ => Err(Errno::EINVAL),
        }
    }

    /// Reads from a regular file at `offset`; returns the bytes read
    /// (0 at or past the end).
    pub fn read(&self, ino: Ino, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let data = match &self.node(ino)?.contents {
            Contents::File(data) => data,
            Contents::Directory(_) => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
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
    /// and EFBIG if the end does not fit. For the kernel: no quota.
    pub fn write(&mut self, ino: Ino, offset: u64, data: &[u8]) -> Result<usize, Errno> {
        self.write_as(ino, offset, data, None)
    }

    /// [`Fs::write`] by a process whose compartment has `quota`. Growth is
    /// charged to the file's owner, or, if the kernel made the file, to
    /// `quota`, which then owns it (so a compartment cannot grow a file
    /// the kernel put in its tree at nobody's expense). ENOSPC past the
    /// owner's byte limit: to the compartment its quota is the size of the
    /// device, and write(2) gives "ENOSPC The device containing the file
    /// referred to by fd has no room for the data". A write of something
    /// stamps the modification and change times (`file_update_time`).
    pub fn write_as(
        &mut self,
        ino: Ino,
        offset: u64,
        data: &[u8],
        quota: Option<&Arc<Quota>>,
    ) -> Result<usize, Errno> {
        let start = usize::try_from(offset).map_err(|_| Errno::EFBIG)?;
        let end = start.checked_add(data.len()).ok_or(Errno::EFBIG)?;
        self.resize(ino, end, quota, |file| {
            file[start..end].copy_from_slice(data);
        })?;
        if !data.is_empty() {
            self.stamp_modified(ino);
        }
        Ok(data.len())
    }

    fn stamp_modified(&mut self, ino: Ino) {
        let now = self.now();
        if let Ok(node) = self.node_mut(ino) {
            node.mtime = now;
            node.ctime = now;
        }
    }

    /// Makes the file at `ino` at least `len` bytes long (`grow_only`) or
    /// exactly `len` bytes, charging growth to the filesystem's cap and to
    /// the payer's quota, then lets `finish` change the data. Shrinking
    /// gives charged bytes back.
    fn resize(
        &mut self,
        ino: Ino,
        len: usize,
        quota: Option<&Arc<Quota>>,
        finish: impl FnOnce(&mut Vec<u8>),
    ) -> Result<(), Errno> {
        self.resize_to(ino, len, true, quota, finish)
    }

    fn resize_to(
        &mut self,
        ino: Ino,
        len: usize,
        grow_only: bool,
        quota: Option<&Arc<Quota>>,
        finish: impl FnOnce(&mut Vec<u8>),
    ) -> Result<(), Errno> {
        let (bytes_used, byte_limit) = (self.bytes_used, self.byte_limit);
        let may_allocate = self.may_allocate;
        let is_file = matches!(self.node(ino)?.contents, Contents::File(_));
        if !is_file {
            return Err(match self.kind(ino)? {
                Kind::Directory => Errno::EISDIR,
                _ => Errno::EINVAL,
            });
        }
        let node = self.node_mut(ino)?;
        let Contents::File(file) = &mut node.contents else {
            return Err(Errno::EINVAL);
        };
        let old = file.len();
        let new = if grow_only { old.max(len) } else { len };
        let growth = new.saturating_sub(old);
        if bytes_used
            .checked_add(growth)
            .is_none_or(|total| total > byte_limit)
        {
            return Err(Errno::ENOSPC);
        }
        // Who pays: the owner, or a kernel-made file's first grower.
        if growth > 0 && node.owner.is_none() {
            node.owner = quota.cloned();
        }
        let payer = node.owner.clone();
        if growth > 0
            && let Some(payer) = &payer
            && !payer.bytes.try_charge(growth)
        {
            return Err(Errno::ENOSPC);
        }
        let grown = match grow_file(file, new, may_allocate) {
            Ok(data) => data,
            Err(error) => {
                if let Some(payer) = &payer {
                    payer.bytes.uncharge(growth);
                }
                return Err(error);
            }
        };
        grown.truncate(new);
        finish(grown);
        if growth > 0 && payer.is_some() {
            node.charged += growth;
        }
        // Shrinking removes the last bytes, which are the charged ones.
        let shrink = old.saturating_sub(new);
        let given_back = node.charged.min(shrink);
        node.charged -= given_back;
        if let Some(payer) = &payer {
            payer.bytes.uncharge(given_back);
        }
        self.bytes_used = bytes_used - old + new;
        Ok(())
    }

    /// Sets a file's length (truncate), zero-filling any growth. For the
    /// kernel: no quota.
    pub fn set_len(&mut self, ino: Ino, len: u64) -> Result<(), Errno> {
        self.set_len_as(ino, len, None)
    }

    /// [`Fs::set_len`] by a process whose compartment has `quota`, charged
    /// as [`Fs::write_as`]. Shrinking gives the owner its bytes back. The
    /// modification and change times are stamped whether or not the size
    /// changes (`do_truncate` passes ATTR_MTIME | ATTR_CTIME).
    pub fn set_len_as(
        &mut self,
        ino: Ino,
        len: u64,
        quota: Option<&Arc<Quota>>,
    ) -> Result<(), Errno> {
        let len = usize::try_from(len).map_err(|_| Errno::EFBIG)?;
        self.resize_to(ino, len, false, quota, |_| {})?;
        self.stamp_modified(ino);
        Ok(())
    }

    /// File status. A directory's link count is 2 plus its subdirectories
    /// (0 once removed) and its size tmpfs's 20 bytes per entry plus two;
    /// a symbolic link's size is its target's length (`shmem_symlink`).
    pub fn stat(&self, ino: Ino) -> Result<Stat, Errno> {
        let node = self.node(ino)?;
        let (kind, size, nlink, rdev) = match &node.contents {
            Contents::File(data) => (S_IFREG, data.len() as u64, node.links, (0, 0)),
            Contents::Directory(entries) => {
                let subdirs = entries
                    .values()
                    .filter(|&&i| matches!(self.kind(i), Ok(Kind::Directory)))
                    .count() as u32;
                let nlink = if node.links == 0 { 0 } else { 2 + subdirs };
                let size = (2 + entries.len() as u64) * BOGO_DIRENT_SIZE;
                (S_IFDIR, size, nlink, (0, 0))
            }
            Contents::Device(device) => (S_IFCHR, 0, node.links, device.number()),
            Contents::Symlink(target) => (S_IFLNK, target.len() as u64, node.links, (0, 0)),
            Contents::Socket => (S_IFSOCK, 0, node.links, (0, 0)),
        };
        Ok(Stat {
            ino,
            mode: kind | node.permissions,
            size,
            nlink,
            rdev,
            atime: node.atime,
            mtime: node.mtime,
            ctime: node.ctime,
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

    /// The parent of directory `dir` (its `..`).
    pub fn dir_parent(&self, dir: Ino) -> Result<Ino, Errno> {
        Ok(self.node(dir)?.parent)
    }

    /// Bytes of file data held.
    pub fn bytes_used(&self) -> usize {
        self.bytes_used
    }

    /// Unpacks a cpio archive beneath `root`. Every name must be a plain
    /// relative path (no `.` or `..` components); directories are created
    /// as needed. Members that are neither files nor directories (symbolic
    /// links, devices) are skipped and counted: the archive makes none
    /// Keel needs, and device nodes come only from [`Fs::create_device`]
    /// (SR-9). Returns the number skipped.
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

    fn quota(bytes: usize, nodes: usize) -> Arc<Quota> {
        use crate::compartment::Budget;
        Arc::new(Quota {
            bytes: Budget::new(bytes),
            nodes: Budget::new(nodes),
        })
    }

    #[test]
    fn a_quota_caps_its_files_bytes_and_gives_back_on_truncate() {
        let mut fs = Fs::new(1 << 20);
        let q = quota(10, 8);
        let f = fs.create_file_as(ROOT, b"f", 0o644, Some(&q)).unwrap();
        assert_eq!(fs.write_as(f, 0, &[1; 10], Some(&q)), Ok(10));
        assert_eq!(fs.write_as(f, 10, b"x", Some(&q)), Err(Errno::ENOSPC));
        assert_eq!(
            fs.write_as(f, 0, b"abc", Some(&q)),
            Ok(3),
            "overwriting is free"
        );
        assert_eq!(fs.set_len_as(f, 11, Some(&q)), Err(Errno::ENOSPC));
        assert_eq!(q.bytes.used(), 10);
        fs.set_len_as(f, 4, Some(&q)).unwrap();
        assert_eq!(q.bytes.used(), 4, "truncating gives the bytes back");
        assert_eq!(fs.write_as(f, 4, &[2; 6], Some(&q)), Ok(6));
        // A refused write changed nothing.
        assert_eq!(fs.stat(f).unwrap().size, 10);
        assert_eq!(fs.bytes_used(), 10);
    }

    #[test]
    fn a_quota_caps_the_nodes_it_creates_and_a_refusal_costs_nothing() {
        let mut fs = Fs::new(1 << 20);
        let q = quota(1 << 20, 2);
        let d = fs.create_dir_as(ROOT, b"d", 0o755, Some(&q)).unwrap();
        assert_eq!(
            fs.create_file_as(d, b"d", 0o644, Some(&q)).map(|_| ()),
            Ok(())
        );
        assert_eq!(q.nodes.used(), 2);
        assert_eq!(
            fs.create_file_as(d, b"e", 0o644, Some(&q)),
            Err(Errno::ENOSPC)
        );
        assert_eq!(
            fs.create_file_as(ROOT, b"d", 0o644, Some(&q)),
            Err(Errno::EEXIST)
        );
        assert_eq!(q.nodes.used(), 2, "refused creations charge nothing");
        // The kernel is not held to it.
        assert!(fs.create_file(d, b"kernel", 0o644).is_ok());
    }

    #[test]
    fn a_kernel_made_file_is_charged_to_the_first_compartment_that_grows_it() {
        let mut fs = Fs::new(1 << 20);
        let f = fs.create_file(ROOT, b"given", 0o644).unwrap();
        fs.write(f, 0, &[0; 100]).unwrap();
        let a = quota(30, 8);
        let b = quota(30, 8);
        // Overwriting the kernel's bytes costs nothing; growing does.
        assert_eq!(fs.write_as(f, 0, &[1; 100], Some(&a)), Ok(100));
        assert_eq!(a.bytes.used(), 0);
        assert_eq!(fs.write_as(f, 100, &[1; 30], Some(&a)), Ok(30));
        assert_eq!(fs.write_as(f, 130, b"x", Some(&a)), Err(Errno::ENOSPC));
        // A owns it now: growth by anyone is charged to A, not to B.
        assert_eq!(fs.write_as(f, 130, b"x", Some(&b)), Err(Errno::ENOSPC));
        assert_eq!(b.bytes.used(), 0);
        // Truncating below the kernel's 100 bytes gives back only A's 30.
        fs.set_len(f, 50).unwrap();
        assert_eq!(a.bytes.used(), 0);
        assert_eq!(fs.bytes_used(), 50);
    }
    #[test]
    fn symlinks_are_followed_and_stay_in_the_root() {
        let mut fs = sample();
        let etc = fs.lookup(ROOT, ROOT, b"/etc").unwrap();
        let host = fs.lookup(ROOT, ROOT, b"/etc/hostname").unwrap();
        fs.create_symlink_as(ROOT, b"rel", b"etc/hostname", None)
            .unwrap();
        fs.create_symlink_as(etc, b"abs", b"/etc/hostname", None)
            .unwrap();
        fs.create_symlink_as(etc, b"up", b"../..", None).unwrap();
        let link = fs.resolve(ROOT, ROOT, b"/rel", false).unwrap();
        assert_eq!(fs.lookup(ROOT, ROOT, b"/rel"), Ok(host));
        assert_eq!(fs.kind(link), Ok(Kind::Symlink));
        assert_eq!(fs.readlink(link), Ok(b"etc/hostname".to_vec()));
        assert_eq!(fs.readlink(host), Err(Errno::EINVAL));
        assert_eq!(fs.stat(link).unwrap().size, 12);
        assert_eq!(fs.stat(link).unwrap().mode, S_IFLNK | 0o777);
        // With /etc as the root, an absolute target starts at /etc and ".."
        // stops there: nothing outside can be reached.
        assert_eq!(fs.lookup(etc, etc, b"abs"), Err(Errno::ENOENT));
        assert_eq!(fs.lookup(etc, etc, b"up"), Ok(etc));
        assert_eq!(fs.lookup(ROOT, ROOT, b"/etc/abs"), Ok(host));
        // A link in the middle of a path is followed; a trailing slash
        // follows a last one and wants a directory.
        fs.create_symlink_as(ROOT, b"e", b"etc", None).unwrap();
        assert_eq!(fs.resolve(ROOT, ROOT, b"/e/hostname", false), Ok(host));
        assert_eq!(fs.resolve(ROOT, ROOT, b"/e/", false), Ok(etc));
        assert_eq!(fs.resolve(ROOT, ROOT, b"/rel/", false), Err(Errno::ENOTDIR));
        // 40 links are followed, the 41st is ELOOP; a loop is ELOOP.
        let mut prev = b"etc".to_vec();
        for i in 0..41u32 {
            let name = alloc::format!("l{i}").into_bytes();
            fs.create_symlink_as(ROOT, &name, &prev, None).unwrap();
            prev = name;
        }
        assert_eq!(fs.lookup(ROOT, ROOT, b"/l39"), Ok(etc));
        assert_eq!(fs.lookup(ROOT, ROOT, b"/l40"), Err(Errno::ELOOP));
        fs.create_symlink_as(ROOT, b"loop", b"loop", None).unwrap();
        assert_eq!(fs.lookup(ROOT, ROOT, b"/loop"), Err(Errno::ELOOP));
        assert_eq!(
            fs.create_symlink_as(ROOT, b"empty", b"", None),
            Err(Errno::ENOENT)
        );
        let long = alloc::vec![b'a'; PATH_MAX];
        assert_eq!(
            fs.create_symlink_as(ROOT, b"long", &long, None),
            Err(Errno::ENAMETOOLONG)
        );
    }

    #[test]
    fn hard_links_and_unlink_keep_a_held_file() {
        static FREED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        fn freed(ino: Ino) {
            FREED.store(ino + 1, core::sync::atomic::Ordering::Relaxed);
        }
        let mut fs = sample();
        fs.set_free_hook(freed);
        let etc = fs.lookup(ROOT, ROOT, b"/etc").unwrap();
        let f = fs.lookup(ROOT, ROOT, b"/etc/hostname").unwrap();
        fs.link(f, ROOT, b"second").unwrap();
        assert_eq!(fs.stat(f).unwrap().nlink, 2);
        assert_eq!(fs.link(etc, ROOT, b"dirlink"), Err(Errno::EPERM));
        assert_eq!(fs.link(f, ROOT, b"second"), Err(Errno::EEXIST));
        fs.unlink(etc, b"hostname").unwrap();
        assert_eq!(fs.stat(f).unwrap().nlink, 1);
        assert_eq!(fs.lookup(ROOT, ROOT, b"/second"), Ok(f));
        // Held, then its last name goes: still readable until released.
        fs.pin(f);
        fs.unlink(ROOT, b"second").unwrap();
        assert_eq!(fs.stat(f).unwrap().nlink, 0);
        let mut buf = [0u8; 5];
        assert_eq!(fs.read(f, 0, &mut buf), Ok(5));
        assert_eq!(fs.link(f, ROOT, b"back"), Err(Errno::ENOENT));
        assert_eq!(FREED.load(core::sync::atomic::Ordering::Relaxed), 0);
        let used = fs.bytes_used();
        fs.unpin(f);
        assert_eq!(fs.stat(f), Err(Errno::ENOENT));
        assert_eq!(fs.bytes_used(), used - 5, "its bytes come back");
        assert_eq!(FREED.load(core::sync::atomic::Ordering::Relaxed), f + 1);
        assert_eq!(fs.unlink(ROOT, b"etc"), Err(Errno::EISDIR));
        assert_eq!(fs.unlink(ROOT, b"missing"), Err(Errno::ENOENT));
    }

    #[test]
    fn rmdir_and_removed_directories() {
        let mut fs = sample();
        let etc = fs.lookup(ROOT, ROOT, b"/etc").unwrap();
        assert_eq!(fs.rmdir(ROOT, b"etc"), Err(Errno::ENOTEMPTY));
        fs.unlink(etc, b"hostname").unwrap();
        fs.pin(etc); // an open descriptor of it
        fs.rmdir(ROOT, b"etc").unwrap();
        assert_eq!(fs.stat(etc).unwrap().nlink, 0);
        assert_eq!(fs.create_file(etc, b"new", 0o644), Err(Errno::ENOENT));
        assert_eq!(fs.path_of(ROOT, etc), Err(Errno::ENOENT));
        assert_eq!(
            fs.lookup(ROOT, etc, b"x"),
            Err(Errno::ENOENT),
            "a removed cwd names nothing"
        );
        fs.unpin(etc);
        assert_eq!(fs.stat(etc), Err(Errno::ENOENT));
        let dev = fs.lookup(ROOT, ROOT, b"/dev").unwrap();
        assert_eq!(fs.rmdir(dev, b"null"), Err(Errno::ENOTDIR));
    }

    #[test]
    fn rename_follows_linux() {
        let mut fs = sample();
        let etc = fs.lookup(ROOT, ROOT, b"/etc").unwrap();
        let f = fs.lookup(ROOT, ROOT, b"/etc/hostname").unwrap();
        let a = fs.create_dir(ROOT, b"a", 0o755).unwrap();
        let b = fs.create_dir(a, b"b", 0o755).unwrap();
        let g = fs.create_file(ROOT, b"g", 0o644).unwrap();
        // A file over a file replaces it (the old one goes).
        fs.rename(etc, b"hostname", ROOT, b"g", 0).unwrap();
        assert_eq!(fs.lookup(ROOT, ROOT, b"/g"), Ok(f));
        assert_eq!(fs.stat(g), Err(Errno::ENOENT));
        assert_eq!(fs.lookup(ROOT, ROOT, b"/etc/hostname"), Err(Errno::ENOENT));
        // Errors.
        assert_eq!(fs.rename(ROOT, b"g", ROOT, b"a", 0), Err(Errno::EISDIR));
        assert_eq!(fs.rename(ROOT, b"a", ROOT, b"g", 0), Err(Errno::ENOTDIR));
        assert_eq!(
            fs.rename(ROOT, b"etc", ROOT, b"a", 0),
            Err(Errno::ENOTEMPTY)
        );
        assert_eq!(fs.rename(ROOT, b"a", b, b"inner", 0), Err(Errno::EINVAL));
        assert_eq!(fs.rename(ROOT, b"a", a, b"self", 0), Err(Errno::EINVAL));
        assert_eq!(
            fs.rename(ROOT, b"g", ROOT, b"etc", RENAME_NOREPLACE),
            Err(Errno::EEXIST)
        );
        assert_eq!(
            fs.rename(ROOT, b"g", ROOT, b"none", RENAME_EXCHANGE),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            fs.rename(ROOT, b"g", ROOT, b"h", RENAME_WHITEOUT),
            Err(Errno::EINVAL)
        );
        assert_eq!(fs.rename(ROOT, b"none", ROOT, b"h", 0), Err(Errno::ENOENT));
        // The same node by two names: nothing happens.
        fs.link(f, ROOT, b"g2").unwrap();
        fs.rename(ROOT, b"g", ROOT, b"g2", 0).unwrap();
        assert_eq!(fs.stat(f).unwrap().nlink, 2);
        // A directory moves with its contents; its ".." follows.
        fs.rename(ROOT, b"a", etc, b"moved", 0).unwrap();
        assert_eq!(fs.lookup(ROOT, ROOT, b"/etc/moved/b"), Ok(b));
        assert_eq!(fs.lookup(ROOT, b, b"../.."), Ok(etc));
        assert_eq!(fs.path_of(ROOT, b), Ok(b"/etc/moved/b".to_vec()));
        // Exchange swaps two names.
        fs.rename(ROOT, b"g", etc, b"moved", RENAME_EXCHANGE)
            .unwrap();
        assert_eq!(fs.lookup(ROOT, ROOT, b"/g"), Ok(a));
        assert_eq!(fs.lookup(ROOT, ROOT, b"/etc/moved"), Ok(f));
        assert_eq!(fs.lookup(ROOT, b, b"../.."), Ok(ROOT));
    }

    #[test]
    fn a_working_directory_moved_out_of_its_root_names_nothing() {
        let mut fs = sample();
        let jail = fs.create_dir(ROOT, b"jail", 0o755).unwrap();
        let inside = fs.create_dir(jail, b"inside", 0o755).unwrap();
        assert_eq!(fs.lookup(jail, inside, b".."), Ok(jail));
        // The system compartment moves it out: relative lookups from it
        // would otherwise climb to the real root.
        fs.rename(jail, b"inside", ROOT, b"out", 0).unwrap();
        assert_eq!(fs.lookup(jail, inside, b"../etc"), Err(Errno::ENOENT));
        assert_eq!(fs.lookup(jail, inside, b"."), Err(Errno::ENOENT));
        assert_eq!(
            fs.lookup(jail, inside, b"/"),
            Ok(jail),
            "absolute paths still work"
        );
    }

    #[test]
    fn timestamps_and_sizes() {
        static NOW: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(100);
        fn clock() -> Timespec {
            Timespec {
                sec: NOW.load(core::sync::atomic::Ordering::Relaxed),
                nsec: 0,
            }
        }
        let at = |t: i64| NOW.store(t, core::sync::atomic::Ordering::Relaxed);
        let mut fs = Fs::new(1 << 20);
        fs.set_clock(clock);
        at(100);
        let d = fs.create_dir(ROOT, b"d", 0o755).unwrap();
        let s = fs.stat(d).unwrap();
        assert_eq!((s.atime.sec, s.mtime.sec, s.ctime.sec), (100, 100, 100));
        assert_eq!(s.size, 40, "two bogus entries");
        at(200);
        let f = fs.create_file(d, b"f", 0o644).unwrap();
        assert_eq!(
            fs.stat(d).unwrap().mtime.sec,
            200,
            "a new entry stamps the directory"
        );
        assert_eq!(fs.stat(d).unwrap().size, 60);
        at(300);
        fs.write(f, 0, b"x").unwrap();
        let s = fs.stat(f).unwrap();
        assert_eq!((s.atime.sec, s.mtime.sec, s.ctime.sec), (200, 300, 300));
        at(400);
        fs.write(f, 0, b"").unwrap();
        assert_eq!(
            fs.stat(f).unwrap().mtime.sec,
            300,
            "an empty write changes nothing"
        );
        fs.set_len(f, 1).unwrap();
        assert_eq!(
            fs.stat(f).unwrap().mtime.sec,
            400,
            "truncate stamps even at the same size"
        );
        at(500);
        fs.set_permissions(f, 0o600).unwrap();
        let s = fs.stat(f).unwrap();
        assert_eq!(
            (s.mode, s.mtime.sec, s.ctime.sec),
            (S_IFREG | 0o600, 400, 500)
        );
        let t = Timespec { sec: 7, nsec: 9 };
        fs.set_times(f, Some(t), None).unwrap();
        let s = fs.stat(f).unwrap();
        assert_eq!((s.atime, s.mtime.sec, s.ctime.sec), (t, 400, 500));
        // relatime: an access time before the change time is renewed.
        at(600);
        fs.touch_atime(f);
        assert_eq!(fs.stat(f).unwrap().atime.sec, 600);
        at(700);
        fs.touch_atime(f);
        assert_eq!(
            fs.stat(f).unwrap().atime.sec,
            600,
            "newer than mtime and ctime: kept"
        );
        at(600 + 24 * 60 * 60);
        fs.touch_atime(f);
        assert_eq!(
            fs.stat(f).unwrap().atime.sec,
            600 + 24 * 60 * 60,
            "a day old: renewed"
        );
    }

    #[test]
    fn links_cost_a_slot_and_a_quota_node() {
        let mut fs = Fs::new(1 << 20);
        let q = quota(1 << 10, 2);
        let f = fs.create_file_as(ROOT, b"f", 0o644, Some(&q)).unwrap();
        fs.link(f, ROOT, b"g").unwrap();
        assert_eq!(q.nodes.used(), 2);
        assert_eq!(fs.link(f, ROOT, b"h"), Err(Errno::ENOSPC));
        fs.unlink(ROOT, b"g").unwrap();
        assert_eq!(q.nodes.used(), 1);
        fs.set_node_limit(fs.usage().1);
        assert_eq!(
            fs.link(f, ROOT, b"h"),
            Err(Errno::ENOSPC),
            "the filesystem's cap too"
        );
    }

    #[test]
    fn parent_sorts_the_last_component_and_getcwd_paths() {
        let fs = sample();
        let etc = fs.lookup(ROOT, ROOT, b"/etc").unwrap();
        let p = fs.parent(ROOT, ROOT, b"/etc/new/").unwrap();
        assert_eq!(
            p,
            Parent {
                dir: etc,
                last: Last::Name(b"new"),
                trailing_slash: true
            }
        );
        assert_eq!(fs.parent(ROOT, ROOT, b"/").unwrap().last, Last::Root);
        assert_eq!(fs.parent(ROOT, ROOT, b"/etc/.").unwrap().last, Last::Dot);
        assert_eq!(fs.parent(ROOT, etc, b"..").unwrap().last, Last::DotDot);
        assert_eq!(
            fs.parent(ROOT, ROOT, b"/etc/hostname/x"),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(fs.path_of(ROOT, etc), Ok(b"/etc".to_vec()));
        assert_eq!(fs.path_of(ROOT, ROOT), Ok(b"/".to_vec()));
        assert_eq!(fs.path_of(etc, etc), Ok(b"/".to_vec()));
        let dev = fs.lookup(ROOT, ROOT, b"/dev").unwrap();
        assert_eq!(
            fs.path_of(etc, dev),
            Err(Errno::ENOENT),
            "not beneath the root"
        );
    }

    #[test]
    fn a_detached_file_lives_while_pinned() {
        let mut fs = Fs::new(16);
        let f = fs.create_detached(b"processor".to_vec(), 0o444).unwrap();
        let mut buf = [0u8; 9];
        assert_eq!((fs.read(f, 0, &mut buf), &buf), (Ok(9), b"processor"));
        assert_eq!(fs.bytes_used(), 9);
        assert_eq!(
            fs.create_detached(alloc::vec![0; 8], 0o444),
            Err(Errno::ENOSPC)
        );
        fs.unpin(f);
        assert_eq!(fs.stat(f), Err(Errno::ENOENT));
        assert_eq!(fs.bytes_used(), 0);
    }
}
