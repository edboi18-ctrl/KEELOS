//! Kernel heap (P1-T5): the global allocator behind `alloc::{Box, Vec, ...}`.
//!
//! Small requests (up to 2 KiB, alignment up to the block size) come from
//! eight power-of-two size classes, 16 B to 2 KiB, each with a free list
//! threaded through its free blocks. A class takes one 4 KiB page at a
//! time from the page source and splits it; blocks of size `s` sit at
//! multiples of `s` inside a page-aligned page, so every block is aligned
//! to its own size.
//!
//! Larger requests get whole pages straight from the page source and give
//! them back on free. The kernel's page source maps fresh zeroed frames in
//! a dedicated non-executable region and leaves an unmapped page between
//! large allocations, so running off the end of one faults (SR-17 spirit).
//!
//! Rules (docs/locking.md): the heap lock is an `IrqMutex`, so allocating
//! from an interrupt handler is safe (no interrupt arrives while it is
//! held); never hold the heap lock while taking the page-table or frame
//! lock in the other order.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};

use crate::sync::IrqMutex;

const PAGE: usize = 4096;
const MIN_CLASS_SHIFT: u32 = 4; // 16 bytes: room for the free-list link
const MAX_CLASS_SHIFT: u32 = 11; // 2048 bytes
const CLASSES: usize = (MAX_CLASS_SHIFT - MIN_CLASS_SHIFT + 1) as usize;

/// Where the heap gets memory from.
pub trait PageSource {
    /// Maps `pages` consecutive page-aligned pages of zeroed, read-write
    /// memory and returns the first. The memory stays valid until passed
    /// to `unmap`.
    fn map(&mut self, pages: usize) -> Option<NonNull<u8>>;
    /// Returns pages obtained from `map` with the same count.
    fn unmap(&mut self, first: NonNull<u8>, pages: usize);
}

/// A free block; the link is stored in the block's first 8 bytes.
struct FreeBlock {
    next: *mut FreeBlock,
}

/// Heap state. Not thread-safe by itself; [`LockedHeap`] wraps it.
pub struct Heap<P: PageSource> {
    free: [*mut FreeBlock; CLASSES],
    source: P,
}

impl<P: PageSource> Heap<P> {
    /// An empty heap that will draw pages from `source`.
    pub const fn new(source: P) -> Self {
        Self {
            free: [ptr::null_mut(); CLASSES],
            source,
        }
    }

    /// The size class for `layout`, or `None` for a large request.
    fn class(layout: Layout) -> Option<usize> {
        let need = layout.size().max(layout.align()).max(1 << MIN_CLASS_SHIFT);
        let shift = need.next_power_of_two().trailing_zeros();
        (shift <= MAX_CLASS_SHIFT).then(|| (shift - MIN_CLASS_SHIFT) as usize)
    }

    fn pages_for(size: usize) -> Option<usize> {
        size.checked_add(PAGE - 1).map(|n| n / PAGE)
    }

    /// Allocates memory for `layout`, or returns null.
    pub fn allocate(&mut self, layout: Layout) -> *mut u8 {
        match Self::class(layout) {
            Some(class) => {
                if self.free[class].is_null() && !self.refill(class) {
                    return ptr::null_mut();
                }
                let block = self.free[class];
                // SAFETY: `block` is non-null and heads this class's free
                // list, so it points to a free block of this class inside a
                // page the source mapped; its first 8 bytes hold the link
                // written when it was freed or carved.
                self.free[class] = unsafe { (*block).next };
                block.cast()
            }
            None if layout.align() <= PAGE => match Self::pages_for(layout.size()) {
                Some(pages) => self
                    .source
                    .map(pages)
                    .map_or(ptr::null_mut(), NonNull::as_ptr),
                None => ptr::null_mut(),
            },
            // Alignment beyond a page is not supported.
            None => ptr::null_mut(),
        }
    }

    /// Carves one fresh page into blocks of `class`.
    fn refill(&mut self, class: usize) -> bool {
        let Some(page) = self.source.map(1) else {
            return false;
        };
        let size = 1usize << (class as u32 + MIN_CLASS_SHIFT);
        let base = page.as_ptr();
        for offset in (0..PAGE).step_by(size).rev() {
            // SAFETY: `offset < PAGE`, so the block lies inside the page
            // just mapped for this heap alone; `size >= 16` and the page is
            // 4096-aligned, so the block is aligned for `FreeBlock`.
            unsafe {
                let block = base.add(offset).cast::<FreeBlock>();
                block.write(FreeBlock {
                    next: self.free[class],
                });
                self.free[class] = block;
            }
        }
        true
    }

    /// Frees memory returned by `allocate` with the same layout.
    ///
    /// # Safety
    ///
    /// `ptr` must come from `allocate` on this heap with this `layout` and
    /// must not be used afterwards.
    pub unsafe fn deallocate(&mut self, ptr: *mut u8, layout: Layout) {
        match Self::class(layout) {
            Some(class) => {
                let block = ptr.cast::<FreeBlock>();
                // SAFETY: by the contract, `ptr` is a block of this class
                // that the caller no longer uses; it is at least 16 bytes
                // and aligned to its size.
                unsafe {
                    block.write(FreeBlock {
                        next: self.free[class],
                    })
                };
                self.free[class] = block;
            }
            None => {
                if let (Some(first), Some(pages)) =
                    (NonNull::new(ptr), Self::pages_for(layout.size()))
                {
                    self.source.unmap(first, pages);
                }
            }
        }
    }
}

/// [`Heap`] behind a spinlock, usable as `#[global_allocator]`.
pub struct LockedHeap<P: PageSource>(IrqMutex<Heap<P>>);

// SAFETY: all access to the raw free-list pointers goes through the
// mutex, and the memory they point to belongs to the heap alone.
unsafe impl<P: PageSource + Send> Sync for LockedHeap<P> {}
// SAFETY: as above; the pointers are not tied to any thread.
unsafe impl<P: PageSource + Send> Send for Heap<P> {}

impl<P: PageSource> LockedHeap<P> {
    /// An empty heap.
    pub const fn new(source: P) -> Self {
        Self(IrqMutex::new(Heap::new(source)))
    }
}

// SAFETY: `allocate` returns null or memory valid for `layout` that no
// other allocation overlaps (blocks come off one free list at a time and
// pages are fresh); `deallocate` only accepts what `allocate` returned
// (GlobalAlloc's own contract on callers).
unsafe impl<P: PageSource + Send> GlobalAlloc for LockedHeap<P> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.lock().allocate(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded from GlobalAlloc's contract on the caller.
        unsafe { self.0.lock().deallocate(ptr, layout) }
    }
}

/// The kernel's page source: [`crate::va::VaRanges`] over the kernel-heap region,
/// one unmapped guard page after every mapping.
#[cfg(target_os = "none")]
pub struct KernelPages {
    ranges: crate::va::VaRanges,
    /// Pages mapped for the heap right now (frames it holds).
    mapped: u64,
}

#[cfg(target_os = "none")]
impl PageSource for KernelPages {
    fn map(&mut self, pages: usize) -> Option<NonNull<u8>> {
        use crate::arch::x86_64::paging::map_heap_pages;
        let choice = self.ranges.choose(pages as u64)?;
        map_heap_pages(choice.start, pages as u64).ok()?;
        self.ranges.commit(choice);
        self.mapped += pages as u64;
        NonNull::new(choice.start as *mut u8)
    }

    fn unmap(&mut self, first: NonNull<u8>, pages: usize) {
        let start = first.as_ptr() as u64;
        crate::arch::x86_64::paging::unmap_heap_pages(start, pages as u64);
        self.ranges.release(start, pages as u64);
        self.mapped -= pages as u64;
    }
}

#[cfg(target_os = "none")]
#[global_allocator]
static KERNEL_HEAP: LockedHeap<KernelPages> = LockedHeap::new(KernelPages {
    ranges: crate::va::VaRanges::new(
        // Placed at a random offset by `paging::init` before first use.
        0xffff_c000_0000_0000,
        crate::arch::x86_64::paging::KERNEL_HEAP_SIZE,
    ),
    mapped: 0,
});

/// Moves the heap's address range to `[base, base + size)`. Only before the
/// first allocation (returns false afterwards): `paging::init` places the
/// region at a random offset (audit 2, A5).
#[cfg(target_os = "none")]
pub(crate) fn rebase(base: u64, size: u64) -> bool {
    let mut heap = KERNEL_HEAP.0.lock();
    if heap.source.mapped != 0 {
        return false;
    }
    heap.source.ranges = crate::va::VaRanges::new(base, size);
    true
}

/// Pages the heap holds mapped (and so frames it uses), small-class pages
/// included (those are kept once taken).
#[cfg(target_os = "none")]
pub fn mapped_pages() -> u64 {
    KERNEL_HEAP.0.lock().source.mapped
}

/// Bytes of heap address space used so far (its high-water mark) and
/// pages of it that can no longer be reused (F-0009's regression test).
#[cfg(target_os = "none")]
pub fn address_space_usage() -> (u64, u64) {
    let heap = KERNEL_HEAP.0.lock();
    (
        heap.source.ranges.used_bytes(),
        heap.source.ranges.lost_pages(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{alloc_zeroed, dealloc};
    use std::collections::HashMap;

    /// Pages from the host allocator, with bookkeeping to catch misuse.
    #[derive(Default)]
    struct HostPages {
        live: HashMap<usize, usize>,
        mapped: usize,
    }

    impl PageSource for HostPages {
        fn map(&mut self, pages: usize) -> Option<NonNull<u8>> {
            let layout = Layout::from_size_align(pages * PAGE, PAGE).ok()?;
            // SAFETY: non-zero size, valid layout.
            let ptr = NonNull::new(unsafe { alloc_zeroed(layout) })?;
            self.live.insert(ptr.as_ptr() as usize, pages);
            self.mapped += pages;
            Some(ptr)
        }
        fn unmap(&mut self, first: NonNull<u8>, pages: usize) {
            let recorded = self.live.remove(&(first.as_ptr() as usize));
            assert_eq!(recorded, Some(pages), "unmap of something never mapped");
            self.mapped -= pages;
            // SAFETY: allocated in `map` with exactly this layout.
            unsafe {
                dealloc(
                    first.as_ptr(),
                    Layout::from_size_align(pages * PAGE, PAGE).unwrap(),
                )
            };
        }
    }

    fn layout(size: usize, align: usize) -> Layout {
        Layout::from_size_align(size, align).unwrap()
    }

    #[test]
    fn size_classes() {
        type H = Heap<HostPages>;
        assert_eq!(H::class(layout(1, 1)), Some(0));
        assert_eq!(H::class(layout(16, 8)), Some(0));
        assert_eq!(H::class(layout(17, 8)), Some(1));
        assert_eq!(H::class(layout(8, 64)), Some(2));
        assert_eq!(H::class(layout(2048, 8)), Some(7));
        assert_eq!(H::class(layout(2049, 8)), None);
        assert_eq!(H::class(layout(8, 4096)), None);
    }

    #[test]
    fn small_blocks_are_aligned_distinct_and_reused() {
        let mut heap = Heap::new(HostPages::default());
        let l = layout(24, 8);
        let mut seen = Vec::new();
        for _ in 0..1000 {
            let p = heap.allocate(l);
            assert!(!p.is_null());
            assert_eq!(p as usize % 32, 0);
            seen.push(p as usize);
        }
        let mut sorted = seen.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), seen.len(), "blocks must not overlap");
        assert_eq!(heap.source.mapped, 1000usize.div_ceil(PAGE / 32));
        let first = seen[0] as *mut u8;
        // SAFETY: allocated above with this layout and not used again.
        unsafe { heap.deallocate(first, l) };
        assert_eq!(heap.allocate(l), first);
    }

    #[test]
    fn alignment_is_honoured_for_every_class() {
        let mut heap = Heap::new(HostPages::default());
        for shift in 0..=12 {
            let align = 1usize << shift;
            let p = heap.allocate(layout(1, align));
            assert!(!p.is_null());
            assert_eq!(p as usize % align, 0, "align {align}");
        }
        assert!(heap.allocate(layout(1, 8192)).is_null());
    }

    #[test]
    fn large_allocations_round_to_pages_and_are_returned() {
        let mut heap = Heap::new(HostPages::default());
        let l = layout(5000, 8);
        let p = heap.allocate(l);
        assert!(!p.is_null());
        assert_eq!(p as usize % PAGE, 0);
        assert_eq!(heap.source.mapped, 2);
        // SAFETY: allocated above with this layout.
        unsafe { heap.deallocate(p, l) };
        assert_eq!(heap.source.mapped, 0);
        assert!(heap.allocate(layout(isize::MAX as usize - 10, 8)).is_null());
    }
}
