//! Physical memory: the boot CPU's frame allocator over the bootloader's
//! memory map (P1-T3), and access to frame contents through the
//! higher-half direct map.
//!
//! The bookkeeping logic lives in `keel_core::frame` (safe Rust). This
//! module adds the parts that need raw memory: carving the bookkeeping out
//! of free RAM, and zeroing frames before they are handed out (SR-18).
//!
//! Frame contents are only reachable through functions here that take a
//! `Frame` the allocator currently has allocated, so a stray physical
//! address cannot be used to read or write arbitrary memory.

use core::sync::atomic::{AtomicU64, Ordering};

use keel_core::frame::{FRAME_SIZE, Frame, FrameAllocator, FrameError, bookkeeping_len};
use spin::Mutex;

use crate::boot::{self, RegionKind};

/// Physical memory above this is ignored. 1 TiB is far beyond the target
/// machine (32 GB maximum) and keeps the bookkeeping bounded if firmware
/// reports a nonsensical region (SR-20: hardware input is untrusted).
const MAX_PHYSICAL: u64 = 1 << 40;

static FRAMES: Mutex<Option<FrameAllocator<'static>>> = Mutex::new(None);
static HHDM: AtomicU64 = AtomicU64::new(0);

/// What `init` found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryStats {
    /// Frames from 0 up to the end of the highest usable region.
    pub frames_managed: usize,
    /// Frames free after setup.
    pub frames_free: usize,
    /// Physical range holding the allocator's own bookkeeping.
    pub bookkeeping: core::ops::Range<u64>,
}

/// Why `init` failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryInitError {
    /// Called a second time.
    AlreadyInitialised,
    /// The bootloader did not report the direct-map offset.
    NoHhdm,
    /// No usable region was large enough for the bookkeeping.
    NoRoomForBookkeeping,
}

/// Builds the frame allocator from the bootloader's memory map. Only
/// `Usable` regions are handed out; bootloader-reclaimable memory (which
/// holds the current page tables, stack and boot information) is kept.
pub fn init() -> Result<MemoryStats, MemoryInitError> {
    let mut frames = FRAMES.lock();
    if frames.is_some() {
        return Err(MemoryInitError::AlreadyInitialised);
    }
    let hhdm = boot::hhdm_offset().ok_or(MemoryInitError::NoHhdm)?;

    let usable = || {
        boot::memory_map()
            .filter(|region| region.kind == RegionKind::Usable && region.base < MAX_PHYSICAL)
    };
    let top = usable()
        .map(|region| region.base.saturating_add(region.length).min(MAX_PHYSICAL))
        .max()
        .unwrap_or(0);
    let frame_count = (top / FRAME_SIZE) as usize;
    let (words, counts) = bookkeeping_len(frame_count);
    // Bitmap words first (8-byte aligned at a page boundary), then the
    // 2-byte counts, which start at a multiple of 8 and so are aligned.
    let bytes = (words * 8 + counts * 2) as u64;
    let bytes = bytes.div_ceil(FRAME_SIZE) * FRAME_SIZE;

    // The protocol guarantees usable regions are 4 KiB aligned and never
    // overlap other entries ("Memory Map Feature"). Skip the region
    // containing physical address 0 so that frame 0 stays unused.
    let base = usable()
        .find(|region| region.base >= FRAME_SIZE && region.length >= bytes)
        .map(|region| region.base)
        .ok_or(MemoryInitError::NoRoomForBookkeeping)?;

    // SAFETY: `[base, base + bytes)` lies in one `Usable` region, which the
    // protocol defines as free RAM holding nothing the kernel or bootloader
    // still uses, and which base revision 3 and later map in the HHDM as
    // read-write ("Memory Layout at Entry"). The lock above ensures this
    // runs once, so the two slices are the only references to this memory;
    // they do not overlap (the counts start after `words * 8` bytes); the
    // memory stays valid forever because the range is reserved in the
    // allocator below and never handed out. Both element types accept any
    // bit pattern and the start addresses are suitably aligned.
    let (used, refs) = unsafe {
        let start = (hhdm + base) as *mut u8;
        let used = core::slice::from_raw_parts_mut(start.cast::<u64>(), words);
        let refs = core::slice::from_raw_parts_mut(start.add(words * 8).cast::<u16>(), counts);
        (used, refs)
    };
    let mut allocator = FrameAllocator::new(frame_count, used, refs)
        .ok_or(MemoryInitError::NoRoomForBookkeeping)?;
    for region in usable() {
        allocator.add_free_region(region.base, region.length);
    }
    allocator.reserve_region(base, bytes);

    let stats = MemoryStats {
        frames_managed: allocator.frame_count(),
        frames_free: allocator.free_frames(),
        bookkeeping: base..base + bytes,
    };
    HHDM.store(hhdm, Ordering::Release);
    *frames = Some(allocator);
    Ok(stats)
}

/// Pointer to a frame's first byte through the direct map.
pub(crate) fn frame_pointer(frame: Frame) -> *mut u8 {
    (HHDM.load(Ordering::Acquire) + frame.address()) as *mut u8
}

/// Allocates a frame and fills it with zeros before returning it, so no
/// earlier contents can ever reach whoever maps it next (SR-18).
pub fn allocate_zeroed() -> Option<Frame> {
    let frame = FRAMES.lock().as_mut()?.allocate()?;
    // SAFETY: the frame was just allocated, so nobody else owns it; it is
    // in a `Usable` region, which the HHDM maps read-write; the write
    // covers exactly the frame's 4096 bytes.
    unsafe { frame_pointer(frame).write_bytes(0, FRAME_SIZE as usize) };
    Some(frame)
}

/// Adds a reference to an allocated frame.
pub fn retain(frame: Frame) -> Result<(), FrameError> {
    FRAMES
        .lock()
        .as_mut()
        .ok_or(FrameError::NotAllocated)?
        .retain(frame)
}

/// Drops a reference; the frame is freed when the last one goes.
pub fn release(frame: Frame) -> Result<bool, FrameError> {
    FRAMES
        .lock()
        .as_mut()
        .ok_or(FrameError::NotAllocated)?
        .release(frame)
}

/// Number of free frames, or 0 before `init`.
pub fn free_frames() -> usize {
    FRAMES.lock().as_ref().map_or(0, |a| a.free_frames())
}

/// Runs `f` on the contents of an allocated frame. Fails for a frame the
/// allocator does not currently have allocated.
pub fn with_frame_bytes<R>(
    frame: Frame,
    f: impl FnOnce(&mut [u8; 4096]) -> R,
) -> Result<R, FrameError> {
    let guard = FRAMES.lock();
    let allocator = guard.as_ref().ok_or(FrameError::NotAllocated)?;
    if allocator.references(frame) == 0 {
        return Err(FrameError::NotAllocated);
    }
    // SAFETY: the frame is allocated (checked above, under the lock, so it
    // cannot be freed meanwhile) and HHDM-mapped read-write. Frames are
    // never mapped as Rust objects elsewhere, so this unique reference does
    // not alias a live Rust reference. `[u8; 4096]` has alignment 1.
    let bytes = unsafe { &mut *frame_pointer(frame).cast::<[u8; 4096]>() };
    Ok(f(bytes))
}
