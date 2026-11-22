//! Reusable kernel virtual address space (F-0009): the heap's large
//! allocations and the kernel stacks each take ranges from one of these,
//! and give them back when freed.

const PAGE: usize = 4096;

/// Most free ranges [`VaRanges`] tracks. It cannot grow (it is used under
/// the heap lock, so it may not allocate); a range freed when it is full
/// and that touches no other free range is not reused (counted in
/// `lost_pages`).
pub const FREE_RANGES: usize = 1024;

/// Virtual address space for large allocations (F-0009): a bump pointer
/// plus freed ranges for reuse. Every allocation of `n` pages occupies
/// `n + 1` pages of address space; the last stays unmapped as its guard.
/// A freed allocation goes back as a free range of `n` usable pages
/// followed by its guard. Adjacent free ranges merge (the guard between
/// them becomes usable), and a free range that ends at the bump pointer
/// is returned to it. Reuse is best fit, so the address space in use
/// follows the peak of live allocations, not their total.
///
/// Before this, address space was never reused: every 4 KiB buffer a
/// read(2) allocated used 8 KiB of the 64 GiB region for good, so about
/// 8.4 million calls exhausted it and the kernel's allocations failed.
pub struct VaRanges {
    base: u64,
    end: u64,
    next: u64,
    free: [(u64, u64); FREE_RANGES],
    len: usize,
    lost_pages: u64,
}

impl VaRanges {
    pub const fn new(base: u64, size: u64) -> Self {
        Self {
            base,
            end: base + size,
            next: base,
            free: [(0, 0); FREE_RANGES],
            len: 0,
            lost_pages: 0,
        }
    }

    /// Picks the start of `pages` usable pages (a guard page after them is
    /// never handed out). Nothing changes until [`VaRanges::commit`].
    pub fn choose(&self, pages: u64) -> Option<Choice> {
        let mut best: Option<(usize, u64)> = None;
        for (i, &(_, free)) in self.free[..self.len].iter().enumerate() {
            if free >= pages && best.is_none_or(|(_, b)| free < b) {
                best = Some((i, free));
            }
        }
        if let Some((slot, _)) = best {
            return Some(Choice {
                start: self.free[slot].0,
                pages,
                slot: Some(slot),
            });
        }
        let after = pages
            .checked_add(1)?
            .checked_mul(PAGE as u64)?
            .checked_add(self.next)?;
        (after <= self.end).then_some(Choice {
            start: self.next,
            pages,
            slot: None,
        })
    }

    /// Takes the space [`VaRanges::choose`] picked, once it is mapped.
    pub fn commit(&mut self, choice: Choice) {
        let page = PAGE as u64;
        match choice.slot {
            None => self.next = choice.start + (choice.pages + 1) * page,
            Some(slot) => {
                let (start, free) = self.free[slot];
                if free > choice.pages {
                    // The page after the new allocation stays unmapped as
                    // its guard; the rest stays free. With one page over,
                    // the rest is a free range of 0 usable pages (only a
                    // guard), which still merges with its neighbours.
                    self.free[slot] = (start + (choice.pages + 1) * page, free - choice.pages - 1);
                } else {
                    // An exact fit: the range's own guard is the new
                    // allocation's guard.
                    self.remove(slot);
                }
            }
        }
    }

    fn remove(&mut self, slot: usize) {
        self.len -= 1;
        self.free[slot] = self.free[self.len];
    }

    /// Returns `pages` usable pages at `start` (their guard follows).
    pub fn release(&mut self, start: u64, pages: u64) {
        let page = PAGE as u64;
        let (mut start, mut pages) = (start, pages);
        // Merge with a free range just before (its guard is our start - 1)
        // or just after (it starts after our guard).
        let mut i = 0;
        while i < self.len {
            let (s, p) = self.free[i];
            if s + (p + 1) * page == start {
                start = s;
                pages += p + 1;
                self.remove(i);
                // The bigger range may now touch one already passed.
                i = 0;
                continue;
            }
            if start + (pages + 1) * page == s {
                pages += p + 1;
                self.remove(i);
                i = 0;
                continue;
            }
            i += 1;
        }
        if start + (pages + 1) * page == self.next {
            // The top of the used space: give it back to the bump pointer.
            self.next = start;
            return;
        }
        if self.len < FREE_RANGES {
            self.free[self.len] = (start, pages);
            self.len += 1;
        } else {
            self.lost_pages += pages + 1;
        }
    }

    /// Highest address handed out so far, from the base.
    pub fn used_bytes(&self) -> u64 {
        self.next - self.base
    }

    pub fn lost_pages(&self) -> u64 {
        self.lost_pages
    }
}

/// Space chosen by [`VaRanges::choose`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Choice {
    pub start: u64,
    pub pages: u64,
    slot: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: u64 = PAGE as u64;

    #[test]
    fn va_ranges_reuse_freed_space() {
        let mut va = VaRanges::new(0x1000_0000, 1 << 30);
        let take = |va: &mut VaRanges, pages| {
            let c = va.choose(pages).unwrap();
            va.commit(c);
            c.start
        };
        // Allocate and free one page a million times: no growth.
        for _ in 0..1_000_000 {
            let a = take(&mut va, 1);
            va.release(a, 1);
        }
        assert_eq!(
            va.used_bytes(),
            0,
            "freed top-most space returns to the bump pointer"
        );
        // Interleaved: free the first of two, then reuse it.
        let a = take(&mut va, 2);
        let b = take(&mut va, 1);
        assert_eq!(b, a + 3 * P, "two pages, a guard, then the next");
        va.release(a, 2);
        assert_eq!(take(&mut va, 1), a, "best fit reuses the freed range");
        // The guard after the reused page is not handed out.
        let c = va.choose(1).unwrap();
        assert_ne!(c.start, a + P);
        va.release(a, 1);
        va.release(b, 1);
        assert_eq!(va.used_bytes(), 0, "everything merged back");
        assert_eq!(va.lost_pages(), 0);
    }

    #[test]
    fn va_ranges_merge_and_respect_the_end() {
        let mut va = VaRanges::new(0, 10 * P);
        let mut take = |pages| {
            let c = va.choose(pages)?;
            va.commit(c);
            Some(c.start)
        };
        let x = take(1).unwrap(); // pages 0, guard 1
        let y = take(1).unwrap(); // pages 2, guard 3
        let z = take(1).unwrap(); // pages 4, guard 5
        assert_eq!((x, y, z), (0, 2 * P, 4 * P));
        assert_eq!(take(4), None, "4 pages + guard do not fit in pages 6-9");
        assert_eq!(take(3), Some(6 * P));
        drop(take);
        va.release(x, 1);
        va.release(y, 1);
        // x and y merged: 3 usable pages (0-2) before y's guard at 3.
        let c = va.choose(3).unwrap();
        assert_eq!(c.start, 0);
        va.commit(c);
        assert_eq!(va.lost_pages(), 0);
    }
}
