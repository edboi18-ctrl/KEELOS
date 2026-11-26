//! Compartments in the running kernel (P3-S1; ADR 0014): the system
//! compartment the kernel's own programs run in, and creation of confined
//! ones. The object and its accounting are `keel_core::compartment`.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use keel_core::compartment::{Compartment, Limits};
use keel_core::errno::Errno;
use keel_core::vfs::{Kind, ROOT};
use keel_hal::sync::IrqMutex;

/// The system compartment: root `/`, no limits beyond the kernel's own.
/// Programs the kernel starts at boot run here. Created on first use.
static SYSTEM: IrqMutex<Option<Arc<Compartment>>> = IrqMutex::new(None);

/// Compartment IDs; the system compartment is 0.
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

pub fn system() -> Arc<Compartment> {
    SYSTEM
        .lock()
        .get_or_insert_with(|| Arc::new(Compartment::new(0, ROOT, Limits::UNLIMITED)))
        .clone()
}

/// A new compartment whose processes see the directory at `root` (a path
/// from the filesystem root) as `/`. ENOTDIR if it is not a directory;
/// EAGAIN once compartment IDs are used up.
pub fn create(root: &[u8], limits: Limits) -> Result<Arc<Compartment>, Errno> {
    create_at(crate::fs::lookup(root)?, limits)
}

/// As [`create`], with the root a directory node (the native interface
/// passes a directory handle's, ADR 0040).
pub fn create_at(root: keel_core::vfs::Ino, limits: Limits) -> Result<Arc<Compartment>, Errno> {
    if crate::fs::with(|fs| fs.kind(root))? != Kind::Directory {
        return Err(Errno::ENOTDIR);
    }
    let id = NEXT_ID
        .try_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
        .map_err(|_| Errno::EAGAIN)?;
    Ok(Arc::new(Compartment::new(id, root, limits)))
}
