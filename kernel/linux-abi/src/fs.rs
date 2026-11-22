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
const DEVICES: [(&[u8], Device); 4] = [
    (b"console", Device::Console),
    (b"null", Device::Null),
    (b"zero", Device::Zero),
    (b"urandom", Device::Urandom),
];

/// Builds the tree from the initramfs boot module and adds `/dev`.
pub fn init() -> Result<Report, InitError> {
    let module = boot::modules()
        .find(|m| m.path.ends_with("/initramfs.cpio"))
        .ok_or(InitError::NoInitramfs)?;
    let entries = cpio::parse(module.data).map_err(InitError::Archive)?;
    let mut fs = Fs::new(TMPFS_LIMIT);
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
    *FS.lock() = Some(fs);
    Ok(Report {
        archive_bytes: module.data.len(),
        members: entries.len(),
        skipped,
    })
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

/// Reads from a device. `/dev/console` waits for a line from the
/// keyboard (see `tty`); call it with no lock held.
pub fn device_read(device: Device, buf: &mut [u8]) -> usize {
    match device {
        Device::Null => 0,
        Device::Console => crate::tty::read(buf),
        Device::Zero => {
            buf.fill(0);
            buf.len()
        }
        Device::Urandom => {
            // Interim source (see hal::random); P1-S5 provides the real
            // generator.
            random::fill(buf);
            buf.len()
        }
    }
}

/// Writes to a device; returns the bytes consumed.
pub fn device_write(device: Device, data: &[u8]) -> usize {
    if device == Device::Console {
        console::write_user_bytes(data);
    }
    // null, zero and urandom discard writes, as on Linux.
    data.len()
}

/// The inode at `path` from the root, for tests and the loader.
pub fn lookup(path: &[u8]) -> Result<Ino, Errno> {
    with(|fs| fs.lookup(ROOT, ROOT, path))
}
