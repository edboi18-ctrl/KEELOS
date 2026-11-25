//! The root filesystem (P1-T12): the initramfs unpacked into a tmpfs, plus
//! `/dev`. Built once at boot; guarded by one lock.

use alloc::sync::Arc;
use alloc::vec::Vec;

use keel_core::cpio;
use keel_core::errno::Errno;
use keel_core::vfs::{Device, Fs, Ino, ROOT};
use keel_hal::sync::IrqMutex;
use keel_hal::{boot, console, random};

/// Cap on file data in the tmpfs. Phase 1 has one tree and 8 GB of RAM on
/// the target; per-compartment caps replace this in Phase 3 (SR-8).
pub const TMPFS_LIMIT: usize = 256 << 20;

static FS: IrqMutex<Option<Fs>> = IrqMutex::new(None);

/// Bytes of file data in the tmpfs and its node count (reports).
pub fn usage() -> (usize, usize) {
    FS.lock().as_ref().map_or((0, 0), Fs::usage)
}

/// Whether the kernel may allocate a `bytes`-byte file buffer now: only if
/// that leaves the frames user page faults may not take (the reserve,
/// `memory::user_reserve`) untouched. One page more covers the heap's own
/// bookkeeping. The admission check runs once per system call; this runs
/// before every buffer, so one large write cannot take the reserve either
/// (third Phase 1 audit, C3; ADR 0011).
fn may_allocate(bytes: usize) -> bool {
    let pages = bytes.div_ceil(4096) + 1;
    keel_hal::memory::free_frames() > keel_hal::memory::user_reserve().saturating_add(pages)
}

/// What `init` found.
#[derive(Clone, Copy, Debug)]
pub struct Report {
    pub archive_bytes: usize,
    pub members: usize,
    /// Members that were neither files nor directories (not supported).
    pub skipped: usize,
}

/// Why the root filesystem could not be built.
#[derive(Clone, Copy, Debug)]
pub enum InitError {
    /// No boot module named `initramfs.cpio`.
    NoInitramfs,
    /// The archive is malformed.
    Archive(cpio::CpioError),
    /// Unpacking failed (bad names, too large).
    Unpack(Errno),
}

impl core::fmt::Display for InitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InitError::NoInitramfs => write!(f, "no initramfs.cpio boot module"),
            InitError::Archive(error) => write!(f, "malformed initramfs ({error:?})"),
            InitError::Unpack(errno) => write!(f, "unpacking failed ({errno:?})"),
        }
    }
}

/// The device nodes in `/dev`. Only these exist; `/dev/mem`, `/dev/kmem`
/// and `/dev/port` cannot be created (SR-9).
const DEVICES: [(&[u8], Device); 6] = [
    (b"console", Device::Console),
    (b"null", Device::Null),
    (b"zero", Device::Zero),
    (b"urandom", Device::Urandom),
    (b"ptmx", Device::Ptmx),
    (b"tty", Device::Tty),
];

/// Builds the tree from the initramfs boot module and adds `/dev`.
pub fn init() -> Result<Report, InitError> {
    let module = boot::modules()
        .find(|m| m.path.ends_with("/initramfs.cpio"))
        .ok_or(InitError::NoInitramfs)?;
    let entries = cpio::parse(module.data).map_err(InitError::Archive)?;
    let mut fs = Fs::new(TMPFS_LIMIT);
    fs.set_allocation_check(may_allocate);
    fs.set_clock(now);
    // A freed file's shared pages go with it (ADR 0021, 0022).
    fs.set_free_hook(keel_hal::vm::shared_forget);
    let skipped = fs.unpack(ROOT, &entries).map_err(InitError::Unpack)?;
    let dev = match fs.lookup(ROOT, ROOT, b"/dev") {
        Ok(dev) => dev,
        Err(_) => fs
            .create_dir(ROOT, b"dev", 0o755)
            .map_err(InitError::Unpack)?,
    };
    for (name, device) in DEVICES {
        // A node of the same name from the archive is refused (EEXIST).
        fs.create_device(dev, name, device)
            .map_err(InitError::Unpack)?;
    }
    // /dev/pts, where the pty slaves appear (devpts, mounted there on
    // Linux: its root is mode 0755).
    fs.create_dir(dev, b"pts", 0o755)
        .map_err(InitError::Unpack)?;
    // /tmp, as on Linux (the Filesystem Hierarchy Standard 3.0, section
    // 3.18: "/tmp : Temporary files"); Wine keeps its server directory
    // under it. Mode 1777 (world-writable and sticky), as Linux
    // distributions create it.
    if fs.lookup(ROOT, ROOT, b"/tmp").is_err() {
        fs.create_dir(ROOT, b"tmp", 0o1777)
            .map_err(InitError::Unpack)?;
    }
    *FS.lock() = Some(fs);
    Ok(Report {
        archive_bytes: module.data.len(),
        members: entries.len(),
        skipped,
    })
}

/// Timestamps: the realtime clock, which counts from the epoch as if the
/// machine booted at 1970-01-01 until Keel reads a real-time clock (as
/// clock_gettime's CLOCK_REALTIME).
fn now() -> keel_core::vfs::Timespec {
    let nanos = keel_hal::time::monotonic_nanos();
    keel_core::vfs::Timespec {
        sec: (nanos / 1_000_000_000) as i64,
        nsec: (nanos % 1_000_000_000) as u32,
    }
}

/// The VM's object hook (ADR 0022): an address space that starts mapping
/// a file pins it, and one that stops releases it, so a mapped file
/// outlives its last name and descriptor, as Linux's `vm_file` reference
/// keeps it.
pub fn object_mapped(object: u64, mapped: bool) {
    let _ = with(|fs| {
        if mapped {
            fs.pin(object);
        } else {
            fs.unpin(object);
        }
        Ok(())
    });
}

/// Runs `f` on the filesystem. Fails with ENOENT before `init`.
pub fn with<R>(f: impl FnOnce(&mut Fs) -> Result<R, Errno>) -> Result<R, Errno> {
    match FS.lock().as_mut() {
        Some(fs) => f(fs),
        None => Err(Errno::ENOENT),
    }
}

/// The contents of the regular file at `path`, as a snapshot that later
/// writes do not change.
pub fn read_file(path: &[u8]) -> Result<Arc<Vec<u8>>, Errno> {
    with(|fs| {
        let ino = fs.lookup(ROOT, ROOT, path)?;
        fs.contents(ino)
    })
}

/// Reads from a device that is not a terminal (terminals are read through
/// their open file's `tty`: EIO here).
pub fn device_read(device: Device, buf: &mut [u8]) -> Result<usize, Errno> {
    Ok(match device {
        Device::Null => 0,
        Device::Console | Device::Ptmx | Device::Pts(_) | Device::Tty => {
            return Err(Errno::EIO);
        }
        Device::Zero => {
            buf.fill(0);
            buf.len()
        }
        Device::Urandom => {
            // The kernel generator (hal::random: BLAKE2s pool, ChaCha20).
            random::fill(buf);
            buf.len()
        }
    })
}

/// Writes to a device; returns the bytes consumed.
pub fn device_write(device: Device, data: &[u8]) -> usize {
    if device.is_tty() {
        // Terminals are written through their open file's `tty`; this is
        // the kernel's own path to the screen.
        console::write_user_bytes(data);
    }
    // null, zero and urandom discard writes, as on Linux.
    data.len()
}

/// The inode at `path` from the root, for tests and the loader.
pub fn lookup(path: &[u8]) -> Result<Ino, Errno> {
    with(|fs| fs.lookup(ROOT, ROOT, path))
}
