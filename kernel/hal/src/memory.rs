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

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::sync::IrqMutex;
use keel_core::frame::{FRAME_SIZE, Frame, FrameAllocator, FrameError, bookkeeping_len};

use crate::boot::{self, RegionKind};

/// Physical memory above this is ignored. 1 TiB is far beyond the target
/// machine (32 GB maximum) and keeps the bookkeeping bounded if firmware
/// reports a nonsensical region (SR-20: hardware input is untrusted).
const MAX_PHYSICAL: u64 = 1 << 40;

static FRAMES: IrqMutex<Option<FrameAllocator<'static>>> = IrqMutex::new(None);
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
    /// Usable memory-map entries left out because they were misaligned or
    /// overlapped another entry (audit finding 8).
    pub regions_skipped: usize,
}

/// Why `init` failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryInitError {
    /// Called a second time.
    AlreadyInitialised,
    /// The bootloader did not report the direct-map offset.
    NoHhdm,
    /// The direct-map offset is not page-aligned or not in the higher
    /// half (audit finding 8).
    BadHhdm(u64),
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
    if !keel_core::frame::hhdm_is_sound(hhdm) {
        return Err(MemoryInitError::BadHhdm(hhdm));
    }

    // Only usable entries that are page-aligned and overlap nothing else
    // (`sound_usable_regions`): the bookkeeping slices below are built at
    // `hhdm + base`, so a malformed entry must never reach them.
    let map = || {
        boot::memory_map().map(|region| keel_core::frame::MapEntry {
            base: region.base,
            length: region.length,
            usable: region.kind == RegionKind::Usable,
        })
    };
    let usable =
        || keel_core::frame::sound_usable_regions(map).filter(|region| region.base < MAX_PHYSICAL);
    let skipped =
        map().filter(|e| e.usable).count() - keel_core::frame::sound_usable_regions(map).count();
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

    // Skip the region containing physical address 0 so that frame 0 stays
    // unused.
    let base = usable()
        .find(|region| region.base >= FRAME_SIZE && region.length >= bytes)
        .map(|region| region.base)
        .ok_or(MemoryInitError::NoRoomForBookkeeping)?;

    // SAFETY: `hhdm` is page-aligned and in the higher half and `base` is
    // page-aligned (both checked above), so the start is aligned for u64.
    // `[base, base + bytes)` lies in one `Usable` region, which the
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
        regions_skipped: skipped,
    };
    HHDM.store(hhdm, Ordering::Release);
    USER_RESERVE.store(
        (stats.frames_managed / 16).clamp(USER_RESERVE_MIN, USER_RESERVE_MAX),
        Ordering::Relaxed,
    );
    *frames = Some(allocator);
    Ok(stats)
}

/// Pointer to a frame's first byte through the direct map.
pub(crate) fn frame_pointer(frame: Frame) -> *mut u8 {
    (HHDM.load(Ordering::Acquire) + frame.address()) as *mut u8
}

/// A physical frame owned by code outside `keel-hal` (ADR 0009, audit
/// finding 1). Only the allocator creates one, it is neither `Copy` nor
/// `Clone`, and dropping it frees the frame, so safe code can reach and
/// free only frames it was given, and only once. Its contents are reached
/// through `&self`/`&mut self`, so the borrow checker rules out aliasing
/// without holding the allocator's lock.
///
/// Inside `keel-hal`, frames are plain `keel_core::frame::Frame` values
/// (an address, which grants nothing by itself): page tables and address
/// spaces keep many references to one frame and manage the counts
/// themselves. The raw operations on them are `pub(crate)`.
///
/// What safe code outside this crate can do (this compiles):
///
/// ```no_run
/// use keel_hal::memory::OwnedFrame;
/// if let Some(mut frame) = OwnedFrame::allocate() {
///     frame.bytes_mut()[0] = 1;
///     drop(frame); // frees it
/// }
/// ```
///
/// What it cannot do (stable rustdoc does not check the error codes; each
/// was confirmed by hand: E0603 private item, E0382 use after move):
/// free or read a frame from an address, ...
///
/// ```compile_fail,E0603
/// let forged = keel_core::frame::Frame::containing(0x10_0000);
/// let _ = keel_hal::memory::release(forged); // private function
/// ```
///
/// ... copy a handle so it can be used after it is freed, ...
///
/// ```compile_fail,E0382
/// use keel_hal::memory::OwnedFrame;
/// let frame = OwnedFrame::allocate().unwrap();
/// drop(frame);
/// let _ = frame.bytes(); // use after move
/// ```
///
/// ... or build one itself.
///
/// ```compile_fail,E0603
/// let _ = keel_hal::memory::OwnedFrame(keel_core::frame::Frame::containing(0));
/// ```
#[derive(Debug)]
pub struct OwnedFrame(Frame);

impl OwnedFrame {
    /// A zero-filled frame (SR-18), or `None` if memory is exhausted.
    pub fn allocate() -> Option<OwnedFrame> {
        allocate_zeroed().map(OwnedFrame)
    }

    /// As [`OwnedFrame::allocate`], subject to the kernel's reserve (see
    /// [`user_reserve`]).
    pub fn allocate_user() -> Option<OwnedFrame> {
        allocate_zeroed_user().map(OwnedFrame)
    }

    /// Physical address of the first byte (information only).
    pub fn address(&self) -> u64 {
        self.0.address()
    }

    pub fn bytes(&self) -> &[u8; 4096] {
        // SAFETY: this value owns the frame: it holds the only reference
        // count, `keel-hal` never maps a frame it handed out as an
        // `OwnedFrame` (the inner `Frame` is private and never given back),
        // and the frame stays allocated until `drop`. The HHDM maps it
        // read-write; `[u8; 4096]` has alignment 1. The borrow of `self`
        // bounds the reference's lifetime and excludes `bytes_mut`.
        unsafe { &*frame_pointer(self.0).cast::<[u8; 4096]>() }
    }

    pub fn bytes_mut(&mut self) -> &mut [u8; 4096] {
        // SAFETY: as in `bytes`; `&mut self` makes this the only reference.
        unsafe { &mut *frame_pointer(self.0).cast::<[u8; 4096]>() }
    }
}

impl Drop for OwnedFrame {
    fn drop(&mut self) {
        let freed = release(self.0);
        debug_assert_eq!(freed, Ok(true), "an owned frame has exactly one reference");
    }
}

/// Self-test helper: a frame that has been freed is refused by the raw
/// operations (it cannot be freed again and has no references). Returns
/// whether that held. Safe code cannot attempt either itself.
pub fn stale_frame_refused() -> bool {
    let Some(frame) = allocate_zeroed() else {
        return false;
    };
    let freed = release(frame) == Ok(true);
    freed && release(frame).is_err() && references(frame) == 0 && retain(frame).is_err()
}

/// Allocates a frame and fills it with zeros before returning it, so no
/// earlier contents can ever reach whoever maps it next (SR-18).
pub(crate) fn allocate_zeroed() -> Option<Frame> {
    let frame = FRAMES.lock().as_mut()?.allocate()?;
    // SAFETY: the frame was just allocated, so nobody else owns it; it is
    // in a `Usable` region, which the HHDM maps read-write; the write
    // covers exactly the frame's 4096 bytes.
    unsafe { frame_pointer(frame).write_bytes(0, FRAME_SIZE as usize) };
    Some(frame)
}

/// Frames user page faults may never take: 1/16 of memory, between 16 MiB
/// and 256 MiB. A program that touches all the memory it can map (the
/// fuzzer found one) then gets its fault refused while the kernel still
/// has frames for page tables, its heap and thread stacks. Interim floor
/// until per-compartment memory limits (SR-8, P3-S4).
static USER_RESERVE: AtomicUsize = AtomicUsize::new(USER_RESERVE_MIN);
const USER_RESERVE_MIN: usize = 4096;
const USER_RESERVE_MAX: usize = 65536;
static USER_RESERVE_HIT: AtomicBool = AtomicBool::new(false);

/// The kernel's reserve, in frames (see [`allocate_zeroed_user`]).
pub fn user_reserve() -> usize {
    USER_RESERVE.load(Ordering::Relaxed)
}

/// Sets the reserve and returns the old one (tests raise it to check the
/// refusal, then put it back).
pub fn set_user_reserve(frames: usize) -> usize {
    USER_RESERVE.swap(frames, Ordering::Relaxed)
}

/// As [`allocate_zeroed`], for a page of user memory: fails once only the
/// kernel's reserve is left. The first refusal is logged.
pub(crate) fn allocate_zeroed_user() -> Option<Frame> {
    let reserve = user_reserve();
    let frame = {
        let mut frames = FRAMES.lock();
        let allocator = frames.as_mut()?;
        if allocator.free_frames() <= reserve {
            None
        } else {
            allocator.allocate()
        }
    };
    let Some(frame) = frame else {
        if !USER_RESERVE_HIT.swap(true, Ordering::Relaxed) {
            crate::kprintln!(
                "memory: user page refused: only the kernel reserve ({reserve} frames) is free; further refusals are not logged"
            );
        }
        return None;
    };
    // SAFETY: as in `allocate_zeroed`: the frame was just allocated and
    // is mapped read-write by the HHDM; exactly its 4096 bytes are written.
    unsafe { frame_pointer(frame).write_bytes(0, FRAME_SIZE as usize) };
    Some(frame)
}

/// Adds a reference to an allocated frame.
pub(crate) fn retain(frame: Frame) -> Result<(), FrameError> {
    FRAMES
        .lock()
        .as_mut()
        .ok_or(FrameError::NotAllocated)?
        .retain(frame)
}

/// Drops a reference; the frame is freed when the last one goes.
pub(crate) fn release(frame: Frame) -> Result<bool, FrameError> {
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

/// Reference count of a frame (0 if not allocated).
pub(crate) fn references(frame: Frame) -> u16 {
    FRAMES.lock().as_ref().map_or(0, |a| a.references(frame))
}

/// Copies `bytes` (at most one frame) to the start of allocated frame
/// `to`; the rest of the frame is left as it is.
// Only the page-fault path (private file mappings) calls this, and it
// exists only for the kernel target, so a host build sees no caller.
#[cfg_attr(not(target_os = "none"), expect(dead_code))]
pub(crate) fn fill_frame(to: Frame, bytes: &[u8]) -> Result<(), FrameError> {
    if bytes.len() > FRAME_SIZE as usize {
        return Err(FrameError::NotAllocated);
    }
    let guard = FRAMES.lock();
    let allocator = guard.as_ref().ok_or(FrameError::NotAllocated)?;
    if allocator.references(to) == 0 {
        return Err(FrameError::NotAllocated);
    }
    // SAFETY: `to` is allocated (checked under the lock) and mapped
    // read-write in the direct map, 4096 bytes long; `bytes` is at most
    // that long (checked above) and, being a shared borrow of memory the
    // caller owns, cannot overlap a frame only the allocator hands out.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), frame_pointer(to), bytes.len());
    }
    Ok(())
}

/// Copies the contents of allocated frame `from` into allocated frame `to`.
// Only the page-fault path (copy-on-write) calls this, and it exists only
// for the kernel target, so a host build sees no caller.
#[cfg_attr(not(target_os = "none"), expect(dead_code))]
pub(crate) fn copy_frame(from: Frame, to: Frame) -> Result<(), FrameError> {
    let guard = FRAMES.lock();
    let allocator = guard.as_ref().ok_or(FrameError::NotAllocated)?;
    if allocator.references(from) == 0 || allocator.references(to) == 0 || from == to {
        return Err(FrameError::NotAllocated);
    }
    // SAFETY: both frames are allocated (checked under the lock), distinct,
    // and mapped read-write in the direct map; each is exactly 4096 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(frame_pointer(from), frame_pointer(to), FRAME_SIZE as usize);
    }
    Ok(())
}
