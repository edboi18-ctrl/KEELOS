//! Physical frame allocator (P1-T3).
//!
//! A bitmap with one bit per 4 KiB frame (1 = in use) plus a reference
//! count per frame. The counts let copy-on-write (P1-T9) share a frame
//! between address spaces and free it when the last user drops it.
//!
//! The allocator only does bookkeeping. It never touches the memory it
//! manages; zeroing a frame before it is mapped anywhere (SR-18) is done by
//! the caller through `keel-hal`.

/// Size of a physical frame.
pub const FRAME_SIZE: u64 = 4096;

/// A 4 KiB-aligned physical address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Frame(u64);

impl Frame {
    /// The frame starting at `address`, which must be 4 KiB aligned.
    pub fn containing(address: u64) -> Frame {
        Frame(address & !(FRAME_SIZE - 1))
    }

    /// Physical address of the first byte.
    pub fn address(self) -> u64 {
        self.0
    }

    fn index(self) -> usize {
        (self.0 / FRAME_SIZE) as usize
    }
}

/// Lowest address of the higher half: the HHDM offset must be at or above
/// it (Limine protocol, "Memory Layout at Entry"; x86-64 canonical
/// addresses with 48-bit virtual addresses, SDM Vol. 1 section 3.3.7.1).
pub const HIGHER_HALF: u64 = 0xffff_8000_0000_0000;

/// Whether a direct-map offset from the bootloader can be used: in the
/// higher half and page-aligned (audit finding 8). The protocol promises
/// both; the kernel checks rather than trusts it (SR-19).
pub fn hhdm_is_sound(offset: u64) -> bool {
    offset >= HIGHER_HALF && offset.is_multiple_of(FRAME_SIZE)
}

/// One memory-map entry, as far as the allocator cares: where it is and
/// whether it is free RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapEntry {
    pub base: u64,
    pub length: u64,
    pub usable: bool,
}

/// The usable entries of `map` that the allocator may take: non-empty,
/// base and length multiples of 4 KiB, not wrapping past the top of the
/// address space, and overlapping no other entry of any kind. The Limine
/// protocol promises all of this for usable entries ("Memory Map
/// Feature"); an entry that breaks it is skipped rather than trusted
/// (audit finding 8). `map` is called once per entry checked, so the
/// check needs no allocation (memory maps have tens to a few hundred
/// entries).
pub fn sound_usable_regions<I>(map: impl Fn() -> I) -> impl Iterator<Item = MapEntry>
where
    I: Iterator<Item = MapEntry>,
{
    let candidates = map().enumerate();
    candidates
        .filter(move |&(index, entry)| {
            let Some(end) = entry.base.checked_add(entry.length) else {
                return false;
            };
            entry.usable
                && entry.length != 0
                && entry.base.is_multiple_of(FRAME_SIZE)
                && entry.length.is_multiple_of(FRAME_SIZE)
                && map().enumerate().all(|(other_index, other)| {
                    other_index == index
                        || other.length == 0
                        || other.base >= end
                        || other.base.saturating_add(other.length) <= entry.base
                })
        })
        .map(|(_, entry)| entry)
}

/// Errors from reference-count operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The frame is outside the managed range or not allocated.
    NotAllocated,
    /// The reference count would overflow.
    TooManyReferences,
}

/// Reference-count value marking a permanently reserved frame.
const RESERVED: u16 = u16::MAX;

/// Bytes of bookkeeping needed to manage frames `0..frame_count`:
/// `(bitmap words, reference counts)`.
pub fn bookkeeping_len(frame_count: usize) -> (usize, usize) {
    (frame_count.div_ceil(64), frame_count)
}

/// The allocator. Frame 0 is never handed out, so a zero physical address
/// can always mean "none".
pub struct FrameAllocator<'a> {
    used: &'a mut [u64],
    refs: &'a mut [u16],
    frame_count: usize,
    free: usize,
    /// Word index to start the next search at.
    next: usize,
    /// Most references a frame may have: `MAX_REFERENCES`, lower in tests.
    reference_limit: u16,
}

/// Most references a frame may have: RESERVED is not a real count, so the
/// last usable value is one below it.
pub const MAX_REFERENCES: u16 = RESERVED - 1;

impl<'a> FrameAllocator<'a> {
    /// Creates an allocator for frames `0..frame_count` with every frame
    /// marked in use. Returns `None` if the bookkeeping slices are too
    /// short.
    pub fn new(frame_count: usize, used: &'a mut [u64], refs: &'a mut [u16]) -> Option<Self> {
        let (words, counts) = bookkeeping_len(frame_count);
        if used.len() < words || refs.len() < counts {
            return None;
        }
        used.fill(u64::MAX);
        refs.fill(0);
        Some(Self {
            used,
            refs,
            frame_count,
            free: 0,
            next: 0,
            reference_limit: MAX_REFERENCES,
        })
    }

    /// Number of frames under management.
    pub fn frame_count(&self) -> usize {
        self.frame_count
    }

    /// Number of free frames.
    pub fn free_frames(&self) -> usize {
        self.free
    }

    fn is_used(&self, index: usize) -> bool {
        self.used[index / 64] & (1 << (index % 64)) != 0
    }

    fn set_used(&mut self, index: usize, used: bool) {
        let bit = 1u64 << (index % 64);
        if used {
            self.used[index / 64] |= bit;
        } else {
            self.used[index / 64] &= !bit;
        }
    }

    /// Marks the frames fully inside `[base, base + length)` free. Partial
    /// frames at either end, frame 0, frames beyond `frame_count`, and
    /// frames already free are skipped. Returns how many became free.
    pub fn add_free_region(&mut self, base: u64, length: u64) -> usize {
        let first = base.div_ceil(FRAME_SIZE).max(1);
        let end = base.saturating_add(length) / FRAME_SIZE;
        let end = end.min(self.frame_count as u64);
        let mut added = 0;
        for index in first..end {
            let index = index as usize;
            if self.is_used(index) && self.refs[index] == 0 {
                self.set_used(index, false);
                added += 1;
            }
        }
        self.free += added;
        added
    }

    /// Marks the frames overlapping `[base, base + length)` as in use and
    /// permanently reserved: later calls to `add_free_region`, `retain`
    /// and `release` leave them alone. Used for the allocator's own
    /// bookkeeping. Returns how many were free before.
    pub fn reserve_region(&mut self, base: u64, length: u64) -> usize {
        let first = base / FRAME_SIZE;
        let end = base.saturating_add(length).div_ceil(FRAME_SIZE);
        let end = end.min(self.frame_count as u64);
        let mut taken = 0;
        for index in first..end {
            let index = index as usize;
            if !self.is_used(index) {
                self.set_used(index, true);
                taken += 1;
            }
            self.refs[index] = RESERVED;
        }
        self.free -= taken;
        taken
    }

    /// Allocates one frame with reference count 1. The contents are
    /// whatever the frame last held: the caller must zero it (SR-18).
    pub fn allocate(&mut self) -> Option<Frame> {
        if self.free == 0 {
            return None;
        }
        let words = self.frame_count.div_ceil(64);
        for offset in 0..words {
            let word_index = (self.next + offset) % words;
            let word = self.used[word_index];
            if word == u64::MAX {
                continue;
            }
            let bit = (!word).trailing_zeros() as usize;
            let index = word_index * 64 + bit;
            if index >= self.frame_count {
                // Bits past the last frame stay set, so this only happens
                // if the bookkeeping is corrupt.
                continue;
            }
            self.set_used(index, true);
            self.refs[index] = 1;
            self.free -= 1;
            self.next = word_index;
            return Some(Frame(index as u64 * FRAME_SIZE));
        }
        None
    }

    fn allocated_index(&self, frame: Frame) -> Result<usize, FrameError> {
        let index = frame.index();
        if index >= self.frame_count
            || !self.is_used(index)
            || self.refs[index] == 0
            || self.refs[index] == RESERVED
        {
            return Err(FrameError::NotAllocated);
        }
        Ok(index)
    }

    /// Lowers the most references a frame may have (tests reach the limit
    /// with a handful of processes instead of 65534), at most to
    /// `MAX_REFERENCES`; returns the previous limit.
    pub fn set_reference_limit(&mut self, limit: u16) -> u16 {
        core::mem::replace(&mut self.reference_limit, limit.clamp(1, MAX_REFERENCES))
    }

    /// Adds a reference to an allocated frame (copy-on-write sharing).
    pub fn retain(&mut self, frame: Frame) -> Result<(), FrameError> {
        let index = self.allocated_index(frame)?;
        if self.refs[index] >= self.reference_limit {
            return Err(FrameError::TooManyReferences);
        }
        self.refs[index] += 1;
        Ok(())
    }

    /// Drops a reference. Returns `Ok(true)` if that was the last one and
    /// the frame is free again.
    pub fn release(&mut self, frame: Frame) -> Result<bool, FrameError> {
        let index = self.allocated_index(frame)?;
        self.refs[index] -= 1;
        if self.refs[index] > 0 {
            return Ok(false);
        }
        self.set_used(index, false);
        self.free += 1;
        Ok(true)
    }

    /// Current reference count of a frame (0 if free or reserved).
    pub fn references(&self, frame: Frame) -> u16 {
        match self.refs.get(frame.index()).copied() {
            Some(RESERVED) | None => 0,
            Some(count) => count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usable(base: u64, length: u64) -> MapEntry {
        MapEntry {
            base,
            length,
            usable: true,
        }
    }

    fn reserved(base: u64, length: u64) -> MapEntry {
        MapEntry {
            base,
            length,
            usable: false,
        }
    }

    fn sound(map: &[MapEntry]) -> Vec<(u64, u64)> {
        sound_usable_regions(|| map.iter().copied())
            .map(|e| (e.base, e.length))
            .collect()
    }

    #[test]
    fn hhdm_must_be_higher_half_and_page_aligned() {
        assert!(hhdm_is_sound(HIGHER_HALF));
        assert!(hhdm_is_sound(0xffff_9000_0000_0000));
        assert!(!hhdm_is_sound(0x0000_7fff_ffff_f000), "lower half");
        assert!(!hhdm_is_sound(0), "zero");
        assert!(!hhdm_is_sound(HIGHER_HALF + 8), "misaligned");
    }

    #[test]
    fn a_well_formed_map_is_kept_whole() {
        let map = [
            reserved(0, 0x1000),
            usable(0x1000, 0x9_f000),
            reserved(0xa_0000, 0x6_0000),
            usable(0x10_0000, 0x7ff0_0000),
        ];
        assert_eq!(sound(&map), [(0x1000, 0x9_f000), (0x10_0000, 0x7ff0_0000)]);
    }

    #[test]
    fn misaligned_empty_and_wrapping_regions_are_skipped() {
        let map = [
            usable(0x1008, 0x1000),
            usable(0x2000, 0x1800),
            usable(0x4000, 0),
            usable(0xffff_ffff_ffff_f000, 0x2000),
            usable(0x10_0000, 0x1000),
        ];
        assert_eq!(sound(&map), [(0x10_0000, 0x1000)]);
    }

    #[test]
    fn overlapping_regions_are_skipped_whatever_the_other_kind() {
        // Two usable entries overlapping each other: neither is trusted.
        let map = [usable(0x1000, 0x3000), usable(0x3000, 0x2000)];
        assert_eq!(sound(&map), []);
        // A usable entry overlapping a reserved one is skipped; one that
        // only touches it is kept.
        let map = [
            reserved(0x1000, 0x2000),
            usable(0x2000, 0x2000),
            usable(0x3000_0000, 0x1000),
            reserved(0x3000_1000, 0x1000),
        ];
        assert_eq!(sound(&map), [(0x3000_0000, 0x1000)]);
        // Empty reserved entries overlap nothing.
        let map = [usable(0x1000, 0x2000), reserved(0x2000, 0)];
        assert_eq!(sound(&map), [(0x1000, 0x2000)]);
    }

    fn allocator(frames: usize) -> (Vec<u64>, Vec<u16>) {
        let (words, counts) = bookkeeping_len(frames);
        (vec![0; words], vec![0; counts])
    }

    #[test]
    fn starts_empty_and_frees_only_whole_frames() {
        let (mut used, mut refs) = allocator(100);
        let mut a = FrameAllocator::new(100, &mut used, &mut refs).unwrap();
        assert_eq!(a.free_frames(), 0);
        assert!(a.allocate().is_none());
        // 0x1800..0x5800 contains whole frames 2, 3, 4.
        assert_eq!(a.add_free_region(0x1800, 0x4000), 3);
        // Frame 0 is never handed out; frames past the end are ignored.
        assert_eq!(a.add_free_region(0, 0x2000), 1);
        assert_eq!(a.add_free_region(98 * 4096, 10 * 4096), 2);
        // Adding the same region twice changes nothing.
        assert_eq!(a.add_free_region(0x2000, 0x3000), 0);
        assert_eq!(a.free_frames(), 6);
    }

    #[test]
    fn allocates_distinct_frames_until_exhausted() {
        let (mut used, mut refs) = allocator(200);
        let mut a = FrameAllocator::new(200, &mut used, &mut refs).unwrap();
        a.add_free_region(0, 200 * 4096);
        let mut seen = std::collections::BTreeSet::new();
        while let Some(frame) = a.allocate() {
            assert_ne!(frame.address(), 0);
            assert_eq!(frame.address() % FRAME_SIZE, 0);
            assert!(seen.insert(frame));
            assert_eq!(a.references(frame), 1);
        }
        assert_eq!(seen.len(), 199);
        assert_eq!(a.free_frames(), 0);
    }

    #[test]
    fn reference_counts_free_on_last_release() {
        let (mut used, mut refs) = allocator(64);
        let mut a = FrameAllocator::new(64, &mut used, &mut refs).unwrap();
        a.add_free_region(0, 64 * 4096);
        let before = a.free_frames();
        let frame = a.allocate().unwrap();
        a.retain(frame).unwrap();
        assert_eq!(a.release(frame), Ok(false));
        assert_eq!(a.free_frames(), before - 1);
        assert_eq!(a.release(frame), Ok(true));
        assert_eq!(a.free_frames(), before);
        // Double free and use of a never-allocated frame are refused.
        assert_eq!(a.release(frame), Err(FrameError::NotAllocated));
        assert_eq!(
            a.retain(Frame::containing(1 << 40)),
            Err(FrameError::NotAllocated)
        );
    }

    #[test]
    fn a_lowered_reference_limit_applies_and_can_be_restored() {
        let (mut used, mut refs) = allocator(8);
        let mut a = FrameAllocator::new(8, &mut used, &mut refs).unwrap();
        a.add_free_region(0, 8 * 4096);
        let frame = a.allocate().unwrap();
        assert_eq!(a.set_reference_limit(3), MAX_REFERENCES);
        assert_eq!(a.retain(frame), Ok(()));
        assert_eq!(a.retain(frame), Ok(()));
        assert_eq!(
            a.retain(frame),
            Err(FrameError::TooManyReferences),
            "3 references"
        );
        // Never above the real limit, never 0.
        assert_eq!(a.set_reference_limit(u16::MAX), 3);
        assert_eq!(a.set_reference_limit(0), MAX_REFERENCES);
        assert_eq!(a.set_reference_limit(MAX_REFERENCES), 1);
        assert_eq!(a.retain(frame), Ok(()));
    }

    #[test]
    fn reference_count_overflow_is_an_error() {
        let (mut used, mut refs) = allocator(8);
        let mut a = FrameAllocator::new(8, &mut used, &mut refs).unwrap();
        a.add_free_region(0, 8 * 4096);
        let frame = a.allocate().unwrap();
        for _ in 1..RESERVED - 1 {
            a.retain(frame).unwrap();
        }
        assert_eq!(a.references(frame), RESERVED - 1);
        assert_eq!(a.retain(frame), Err(FrameError::TooManyReferences));
    }

    #[test]
    fn reserved_frames_are_never_allocated_or_released() {
        let (mut used, mut refs) = allocator(16);
        let mut a = FrameAllocator::new(16, &mut used, &mut refs).unwrap();
        a.add_free_region(0, 16 * 4096);
        assert_eq!(a.reserve_region(0x3000, 0x2001), 3); // frames 3, 4, 5
        let mut got = Vec::new();
        while let Some(f) = a.allocate() {
            got.push(f.address() / 4096);
        }
        assert!(!got.iter().any(|f| (3..=5).contains(f)));
        assert_eq!(
            a.release(Frame::containing(0x3000)),
            Err(FrameError::NotAllocated)
        );
        assert_eq!(
            a.retain(Frame::containing(0x4000)),
            Err(FrameError::NotAllocated)
        );
        // A later free-region pass cannot release reserved frames either.
        assert_eq!(a.add_free_region(0x3000, 0x3000), 0);
        assert_eq!(a.references(Frame::containing(0x5000)), 0);
    }

    #[test]
    fn short_bookkeeping_is_rejected() {
        let mut used = vec![0u64; 1];
        let mut refs = vec![0u16; 65];
        assert!(FrameAllocator::new(65, &mut used, &mut refs).is_none());
    }
}
