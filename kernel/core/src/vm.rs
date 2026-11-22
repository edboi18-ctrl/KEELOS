//! User address-space layout (P1-T9): the list of virtual memory areas
//! (VMAs) of one process, and the decision of what a page fault means.
//! Safe Rust, host tested. Page tables are changed by `keel-hal`, guided
//! by the results returned here.
//!
//! Semantics follow `mmap(2)`, `munmap(2)` and `mprotect(2)` (Linux
//! man-pages): mappings are page-granular; MAP_FIXED replaces whatever was
//! there; MAP_FIXED_NOREPLACE fails with EEXIST instead; unmapping or
//! changing protection of part of a mapping splits it. Unlike Linux, a
//! mapping that is both writable and executable is refused (SR-12); the
//! per-compartment exception the spec allows comes with compartments.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Page size.
pub const PAGE: u64 = 4096;
/// Lowest user address. The first 64 KiB stay unmapped so that null and
/// near-null pointer dereferences always fault (Linux's default
/// `vm.mmap_min_addr` is also 64 KiB).
pub const USER_START: u64 = 0x1_0000;
/// One past the highest user address: the top of the lower canonical half
/// minus one page. The excluded last page keeps every user range clear of
/// the non-canonical boundary (SDM Vol. 1 section 3.3.7.1).
pub const USER_END: u64 = 0x0000_7FFF_FFFF_F000;

/// Access rights of a mapping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Prot {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Prot {
    pub const NONE: Prot = Prot {
        read: false,
        write: false,
        exec: false,
    };
    pub const READ_WRITE: Prot = Prot {
        read: true,
        write: true,
        exec: false,
    };
}

/// One virtual memory area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: Prot,
}

/// Errors, named after the errno each maps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmError {
    /// EINVAL: misaligned, zero length, or outside the user range.
    Invalid,
    /// ENOMEM: no gap large enough, or the range is not fully mapped.
    NoMemory,
    /// EEXIST: MAP_FIXED_NOREPLACE over an existing mapping.
    Exists,
    /// EACCES: writable and executable together (SR-12).
    WriteExec,
}

/// How a new mapping is placed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// Anywhere; `hint` is tried first if it is free.
    Anywhere { hint: u64 },
    /// Exactly here, replacing existing mappings (MAP_FIXED).
    Fixed(u64),
    /// Exactly here, failing if anything is mapped (MAP_FIXED_NOREPLACE).
    FixedNoReplace(u64),
}

/// Page ranges whose page-table entries must be removed or downgraded.
pub type Changed = Vec<(u64, u64)>;

/// The VMAs of one address space, keyed by start address. VMAs never
/// overlap and never have zero length.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layout {
    vmas: BTreeMap<u64, Vma>,
    /// Where the top-down search for mmap(NULL, ...) starts (the mmap
    /// base); randomized per process (SR-16). 0 means USER_END.
    mmap_top: u64,
}

fn check_range(start: u64, length: u64) -> Result<u64, VmError> {
    if length == 0 || !start.is_multiple_of(PAGE) {
        return Err(VmError::Invalid);
    }
    let length = length
        .checked_next_multiple_of(PAGE)
        .ok_or(VmError::Invalid)?;
    let end = start.checked_add(length).ok_or(VmError::Invalid)?;
    if start < USER_START || end > USER_END {
        return Err(VmError::Invalid);
    }
    Ok(end)
}

impl Layout {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the mmap base: mappings without an address are placed below
    /// it, top-down. Must be page-aligned and in the user range.
    pub fn set_mmap_top(&mut self, top: u64) -> Result<(), VmError> {
        if !top.is_multiple_of(PAGE) || !(USER_START..=USER_END).contains(&top) {
            return Err(VmError::Invalid);
        }
        self.mmap_top = top;
        Ok(())
    }

    /// The VMA containing `address`.
    pub fn find(&self, address: u64) -> Option<Vma> {
        self.vmas
            .range(..=address)
            .next_back()
            .map(|(_, v)| *v)
            .filter(|v| address < v.end)
    }

    /// All VMAs in address order.
    pub fn vmas(&self) -> impl Iterator<Item = &Vma> {
        self.vmas.values()
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.vmas
            .range(..end)
            .next_back()
            .is_some_and(|(_, v)| v.end > start)
    }

    /// Highest free gap of `length` bytes below `below`.
    fn find_gap(&self, length: u64, below: u64) -> Option<u64> {
        let mut top = below;
        for vma in self.vmas.range(..below).rev().map(|(_, v)| v) {
            if vma.end <= top && top - vma.end >= length {
                return Some(top - length);
            }
            top = top.min(vma.start);
        }
        (top >= USER_START + length).then(|| top - length)
    }

    /// Adds a mapping. Returns its start and the ranges previously mapped
    /// there (for MAP_FIXED), whose pages the caller must unmap.
    pub fn map(
        &mut self,
        placement: Placement,
        length: u64,
        prot: Prot,
    ) -> Result<(u64, Changed), VmError> {
        if prot.write && prot.exec {
            return Err(VmError::WriteExec);
        }
        if length == 0 {
            return Err(VmError::Invalid);
        }
        let length = length
            .checked_next_multiple_of(PAGE)
            .ok_or(VmError::Invalid)?;
        let (start, replaced) = match placement {
            Placement::Fixed(start) => {
                let end = check_range(start, length)?;
                (start, self.unmap(start, end - start)?)
            }
            Placement::FixedNoReplace(start) => {
                let end = check_range(start, length)?;
                if self.overlaps(start, end) {
                    return Err(VmError::Exists);
                }
                (start, Vec::new())
            }
            Placement::Anywhere { hint } => {
                let hint_free = hint.is_multiple_of(PAGE)
                    && check_range(hint, length).is_ok()
                    && !self.overlaps(hint, hint + length);
                let top = if self.mmap_top == 0 {
                    USER_END
                } else {
                    self.mmap_top
                };
                let start = if hint_free {
                    hint
                } else {
                    // Below the mmap base first; anywhere if that is full.
                    self.find_gap(length, top)
                        .or_else(|| self.find_gap(length, USER_END))
                        .ok_or(VmError::NoMemory)?
                };
                (start, Vec::new())
            }
        };
        self.vmas.insert(
            start,
            Vma {
                start,
                end: start + length,
                prot,
            },
        );
        Ok((start, replaced))
    }

    /// Splits VMAs so that `at` is a boundary.
    fn split_at(&mut self, at: u64) {
        if let Some(vma) = self.find(at)
            && vma.start < at
        {
            self.vmas.insert(vma.start, Vma { end: at, ..vma });
            self.vmas.insert(at, Vma { start: at, ..vma });
        }
    }

    /// Removes `[start, start + length)`. Unmapped holes are fine (as in
    /// munmap). Returns the ranges that were mapped.
    pub fn unmap(&mut self, start: u64, length: u64) -> Result<Changed, VmError> {
        let end = check_range(start, length)?;
        self.split_at(start);
        self.split_at(end);
        let starts: Vec<u64> = self.vmas.range(start..end).map(|(&s, _)| s).collect();
        Ok(starts
            .into_iter()
            .filter_map(|s| self.vmas.remove(&s))
            .map(|v| (v.start, v.end))
            .collect())
    }

    /// Changes the protection of `[start, start + length)`, which must be
    /// fully mapped (ENOMEM otherwise, as in mprotect). Returns the ranges
    /// whose page-table entries must be updated.
    pub fn protect(&mut self, start: u64, length: u64, prot: Prot) -> Result<Changed, VmError> {
        if prot.write && prot.exec {
            return Err(VmError::WriteExec);
        }
        let end = check_range(start, length)?;
        // Fully mapped?
        let mut cursor = start;
        while cursor < end {
            match self.find(cursor) {
                Some(v) => cursor = v.end,
                None => return Err(VmError::NoMemory),
            }
        }
        self.split_at(start);
        self.split_at(end);
        let mut changed = Vec::new();
        for (_, vma) in self.vmas.range_mut(start..end) {
            vma.prot = prot;
            changed.push((vma.start, vma.end));
        }
        Ok(changed)
    }
}

/// What a page fault in user space means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultAction {
    /// No page yet: map a fresh zeroed page with these rights.
    DemandZero(Prot),
    /// A write to a page shared copy-on-write: give the writer its own
    /// copy (or reuse the page if it is the only user).
    CopyOnWrite(Prot),
    /// The access is not allowed: SIGSEGV for user code, EFAULT for the
    /// kernel's user-copy routines.
    Violation,
}

/// Decides how to handle a fault at `address`. `present` is the
/// page-fault error code's P bit (SDM Vol. 3 Figure 7-11): 0 means no
/// translation, 1 a protection violation.
pub fn classify_fault(
    layout: &Layout,
    address: u64,
    write: bool,
    exec: bool,
    present: bool,
) -> FaultAction {
    let Some(vma) = layout.find(address) else {
        return FaultAction::Violation;
    };
    let allowed = if exec {
        vma.prot.exec
    } else if write {
        vma.prot.write
    } else {
        vma.prot.read || vma.prot.write || vma.prot.exec
    };
    match (allowed, present) {
        (false, _) => FaultAction::Violation,
        (true, false) => FaultAction::DemandZero(vma.prot),
        // Present and allowed by the VMA but the page table said no: only
        // a write to a page left read-only for copy-on-write fits.
        (true, true) if write => FaultAction::CopyOnWrite(vma.prot),
        (true, true) => FaultAction::Violation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RW: Prot = Prot::READ_WRITE;
    const RO: Prot = Prot {
        read: true,
        write: false,
        exec: false,
    };

    #[test]
    fn mmap_base_is_respected() {
        let mut l = Layout::new();
        let rw = Prot::READ_WRITE;
        l.set_mmap_top(0x5000_0000).unwrap();
        let (a, _) = l.map(Placement::Anywhere { hint: 0 }, PAGE, rw).unwrap();
        assert_eq!(a, 0x5000_0000 - PAGE);
        let (b, _) = l.map(Placement::Anywhere { hint: 0 }, PAGE, rw).unwrap();
        assert_eq!(b, 0x5000_0000 - 2 * PAGE);
        // Too big to fit below the base: placed above it instead.
        let (c, _) = l
            .map(Placement::Anywhere { hint: 0 }, 0x6000_0000, rw)
            .unwrap();
        assert!(c >= 0x5000_0000);
        assert_eq!(l.set_mmap_top(0x5000_0001), Err(VmError::Invalid));
        assert_eq!(l.set_mmap_top(USER_END + PAGE), Err(VmError::Invalid));
    }

    #[test]
    fn anywhere_mappings_go_top_down_without_overlap() {
        let mut l = Layout::new();
        let (a, _) = l
            .map(Placement::Anywhere { hint: 0 }, 3 * PAGE, RW)
            .unwrap();
        let (b, _) = l.map(Placement::Anywhere { hint: 0 }, PAGE, RW).unwrap();
        assert_eq!(a, USER_END - 3 * PAGE);
        assert_eq!(b, a - PAGE);
        let (c, _) = l
            .map(Placement::Anywhere { hint: 0x40_0000 }, PAGE, RW)
            .unwrap();
        assert_eq!(c, 0x40_0000);
        assert_eq!(l.vmas().count(), 3);
    }

    #[test]
    fn huge_reservation_is_just_bookkeeping() {
        let mut l = Layout::new();
        let (start, _) = l
            .map(Placement::Anywhere { hint: 0 }, 64 << 30, Prot::NONE)
            .unwrap();
        assert_eq!(l.find(start + (32 << 30)).unwrap().prot, Prot::NONE);
    }

    #[test]
    fn fixed_replaces_and_noreplace_refuses() {
        let mut l = Layout::new();
        l.map(Placement::Fixed(0x10_0000), 4 * PAGE, RW).unwrap();
        assert_eq!(
            l.map(Placement::FixedNoReplace(0x10_1000), PAGE, RO),
            Err(VmError::Exists)
        );
        let (_, replaced) = l.map(Placement::Fixed(0x10_1000), PAGE, RO).unwrap();
        assert_eq!(replaced, alloc::vec![(0x10_1000, 0x10_2000)]);
        let prots: Vec<_> = l.vmas().map(|v| (v.start, v.end, v.prot)).collect();
        assert_eq!(
            prots,
            alloc::vec![
                (0x10_0000, 0x10_1000, RW),
                (0x10_1000, 0x10_2000, RO),
                (0x10_2000, 0x10_4000, RW)
            ]
        );
    }

    #[test]
    fn unmap_and_protect_split_mappings() {
        let mut l = Layout::new();
        l.map(Placement::Fixed(0x20_0000), 8 * PAGE, RW).unwrap();
        assert_eq!(
            l.unmap(0x20_2000, 2 * PAGE),
            Ok(alloc::vec![(0x20_2000, 0x20_4000)])
        );
        assert_eq!(l.find(0x20_2000), None);
        assert_eq!(l.find(0x20_1000).unwrap().end, 0x20_2000);
        assert_eq!(l.find(0x20_4000).unwrap().start, 0x20_4000);
        assert_eq!(
            l.protect(0x20_5000, PAGE, RO),
            Ok(alloc::vec![(0x20_5000, 0x20_6000)])
        );
        assert_eq!(l.vmas().count(), 4);
        // mprotect over a hole fails and changes nothing.
        let before = l.clone();
        assert_eq!(l.protect(0x20_1000, 3 * PAGE, RO), Err(VmError::NoMemory));
        assert_eq!(l, before);
        // munmap over holes is fine.
        assert_eq!(l.unmap(0x20_0000, 8 * PAGE).unwrap().len(), 4);
        assert_eq!(l.vmas().count(), 0);
    }

    #[test]
    fn invalid_requests() {
        let mut l = Layout::new();
        let wx = Prot {
            read: true,
            write: true,
            exec: true,
        };
        assert_eq!(
            l.map(Placement::Anywhere { hint: 0 }, PAGE, wx),
            Err(VmError::WriteExec)
        );
        assert_eq!(l.map(Placement::Fixed(0), PAGE, RW), Err(VmError::Invalid)); // below USER_START
        assert_eq!(
            l.map(Placement::Fixed(0x10_0001), PAGE, RW),
            Err(VmError::Invalid)
        );
        assert_eq!(
            l.map(Placement::Fixed(USER_END - PAGE), 2 * PAGE, RW),
            Err(VmError::Invalid)
        );
        assert_eq!(
            l.map(Placement::Anywhere { hint: 0 }, 0, RW),
            Err(VmError::Invalid)
        );
        assert_eq!(
            l.map(Placement::Anywhere { hint: 0 }, u64::MAX, RW),
            Err(VmError::Invalid)
        );
        assert_eq!(l.unmap(u64::MAX - PAGE + 1, PAGE), Err(VmError::Invalid));
        l.map(Placement::Fixed(0x10_0000), PAGE, RW).unwrap();
        assert_eq!(l.protect(0x10_0000, PAGE, wx), Err(VmError::WriteExec));
    }

    #[test]
    fn fault_classification() {
        let mut l = Layout::new();
        l.map(Placement::Fixed(0x10_0000), PAGE, RW).unwrap();
        l.map(Placement::Fixed(0x20_0000), PAGE, RO).unwrap();
        l.map(Placement::Fixed(0x30_0000), PAGE, Prot::NONE)
            .unwrap();
        use FaultAction::*;
        assert_eq!(
            classify_fault(&l, 0x10_0123, false, false, false),
            DemandZero(RW)
        );
        assert_eq!(
            classify_fault(&l, 0x10_0123, true, false, true),
            CopyOnWrite(RW)
        );
        assert_eq!(classify_fault(&l, 0x20_0000, true, false, false), Violation);
        assert_eq!(classify_fault(&l, 0x20_0000, false, true, false), Violation);
        assert_eq!(
            classify_fault(&l, 0x30_0000, false, false, false),
            Violation
        );
        assert_eq!(
            classify_fault(&l, 0x40_0000, false, false, false),
            Violation
        );
        assert_eq!(classify_fault(&l, 0x20_0000, false, false, true), Violation);
    }
}
