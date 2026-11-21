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
}

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

    /// Adds a reference to an allocated frame (copy-on-write sharing).
    pub fn retain(&mut self, frame: Frame) -> Result<(), FrameError> {
        let index = self.allocated_index(frame)?;
        // RESERVED is not a real count, so the last usable value is one
        // below it.
        if self.refs[index] >= RESERVED - 1 {
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
