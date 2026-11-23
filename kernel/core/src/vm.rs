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

/// Most VMAs one address space may have. Each is kernel memory a program
/// can make the kernel allocate, so without a cap a loop of `mmap` calls
/// exhausts the kernel heap (F-0011). Linux's default, v6.12
/// `include/linux/mm.h`: `DEFAULT_MAX_MAP_COUNT` = `USHRT_MAX` - 5;
/// `Documentation/admin-guide/sysctl/vm.rst`: "The default value is
/// 65530." Beyond it, mmap, munmap and mprotect fail with ENOMEM, as on
/// Linux.
pub const MAX_MAP_COUNT: usize = 65530;

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
    /// For a file mapping (P3-T7): which file, and where in it `start`
    /// is. Private: pages are read from the file when first touched; until
    /// then the file's later changes show through, which mmap(2) allows
    /// for MAP_PRIVATE ("It is unspecified whether changes made to the
    /// file after the mmap() call are visible in the mapped region").
    /// Shared (ADR 0021): every mapping of the file maps the same frames.
    pub backing: Option<Backing>,
}

/// What a file mapping maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backing {
    /// The file, as the owner of the layout names it (an inode number).
    pub object: u64,
    /// File offset of the VMA's first page.
    pub offset: u64,
    /// Whether the mapping may be made executable: the handle it came from
    /// had MAP_EXEC (SR-1). mprotect cannot add PROT_EXEC otherwise.
    pub may_exec: bool,
    /// MAP_SHARED: stores reach the file and every other mapping of it
    /// (mmap(2): "Updates to the mapping are visible to other processes
    /// mapping the same region, and ... are carried through to the
    /// underlying file").
    pub shared: bool,
    /// Whether a shared mapping may be made writable: its handle was open
    /// for writing. Linux clears VM_MAYWRITE for a shared mapping of a
    /// file not open for writing (`do_mmap`, `mm/mmap.c`), so mmap with
    /// PROT_WRITE and a later mprotect adding it are EACCES. Private
    /// mappings may always be written (their copies are private).
    pub may_write: bool,
}

impl Vma {
    /// The file offset of the page at `address`, for a file mapping.
    pub fn file_offset(&self, address: u64) -> Option<u64> {
        let backing = self.backing?;
        let page = address & !(PAGE - 1);
        backing.offset.checked_add(page.checked_sub(self.start)?)
    }

    /// Whether `next`, which starts where this ends, continues it: same
    /// rights and either both anonymous or the same file, contiguously.
    fn continues_with(&self, next: &Vma) -> bool {
        if next.start != self.end || next.prot != self.prot {
            return false;
        }
        match (self.backing, next.backing) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.object == b.object
                    && a.may_exec == b.may_exec
                    && a.shared == b.shared
                    && a.may_write == b.may_write
                    && a.offset.checked_add(self.end - self.start) == Some(b.offset)
            }
            _ => false,
        }
    }
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
    /// EACCES: PROT_EXEC on a file mapping whose handle lacked MAP_EXEC.
    NotExecutable,
    /// EACCES: PROT_WRITE on a shared file mapping whose handle was not
    /// open for writing.
    NotWritable,
    /// EINVAL: a file offset that overflows with the mapping's length.
    BadOffset,
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
/// overlap and never have zero length; adjacent VMAs with the same rights
/// are merged, so the count reflects real boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    vmas: BTreeMap<u64, Vma>,
    /// Where the top-down search for mmap(NULL, ...) starts (the mmap
    /// base); randomized per process (SR-16). 0 means USER_END.
    mmap_top: u64,
    /// Where the last top-down placement ended: the next search starts
    /// here, so filling the space downward does not walk every VMA each
    /// time (audit 2, A2). 0 means "from the top". Only a starting point:
    /// if nothing fits below it, the whole range is searched.
    search_from: u64,
    /// Cap on the number of VMAs (`MAX_MAP_COUNT`; lower in tests).
    map_limit: usize,
    /// How many VMAs map each file (by `Backing::object`), so the owner
    /// of the layout knows which files it maps: a mapping keeps its file
    /// alive after the file's last name is gone (mmap(2): "closing the
    /// file descriptor does not unmap the region"; unlink(2): the file
    /// stays while "any process still has the file open"), as Linux's
    /// `vm_file` reference does. ADR 0022.
    objects: BTreeMap<u64, u32>,
    /// Files this layout started mapping (true) or stopped mapping
    /// (false) since the last [`Layout::take_object_changes`].
    object_changes: Vec<(u64, bool)>,
}

impl Default for Layout {
    fn default() -> Self {
        Layout {
            vmas: BTreeMap::new(),
            mmap_top: 0,
            search_from: 0,
            map_limit: MAX_MAP_COUNT,
            objects: BTreeMap::new(),
            object_changes: Vec::new(),
        }
    }
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

    /// Sets the cap on the number of VMAs (tests use a small one).
    pub fn set_map_limit(&mut self, limit: usize) {
        self.map_limit = limit;
    }

    /// Number of VMAs.
    pub fn count(&self) -> usize {
        self.vmas.len()
    }

    /// Files this layout maps (each once).
    pub fn objects(&self) -> impl Iterator<Item = u64> + '_ {
        self.objects.keys().copied()
    }

    /// Files it began (true) or ceased (false) to map since the last call,
    /// in order. One operation can report a file both ways (MAP_FIXED
    /// over a mapping of the same file removes before it adds), so the
    /// owner should net each operation's changes per file.
    pub fn take_object_changes(&mut self) -> Vec<(u64, bool)> {
        core::mem::take(&mut self.object_changes)
    }

    fn count_object(&mut self, vma: &Vma, up: bool) {
        let Some(b) = vma.backing else {
            return;
        };
        if up {
            let n = self.objects.entry(b.object).or_insert(0);
            *n += 1;
            if *n == 1 {
                self.object_changes.push((b.object, true));
            }
        } else if let Some(n) = self.objects.get_mut(&b.object) {
            *n -= 1;
            if *n == 0 {
                self.objects.remove(&b.object);
                self.object_changes.push((b.object, false));
            }
        }
    }

    /// Every VMA enters the table here, so `objects` stays exact.
    fn insert_vma(&mut self, vma: Vma) {
        // A new reference before the old one goes, so replacing a VMA by
        // one of the same file never reports the file unmapped.
        self.count_object(&vma, true);
        if let Some(old) = self.vmas.insert(vma.start, vma) {
            self.count_object(&old, false);
        }
    }

    /// Every VMA leaves the table here.
    fn remove_vma(&mut self, start: u64) -> Option<Vma> {
        let old = self.vmas.remove(&start)?;
        self.count_object(&old, false);
        Some(old)
    }

    /// How many existing VMAs `[start, end)` would cut in two: one for each
    /// end that falls strictly inside a VMA. Each cut adds a VMA.
    fn cuts(&self, start: u64, end: u64) -> usize {
        let inside = |at: u64| self.find(at).is_some_and(|v| v.start < at);
        usize::from(inside(start)) + usize::from(inside(end))
    }

    /// Fails with ENOMEM unless `extra` more VMAs fit under the cap. Checked
    /// before any change, so a refused call leaves the layout as it was.
    fn ensure_room(&self, extra: usize) -> Result<(), VmError> {
        if self.vmas.len().saturating_add(extra) > self.map_limit {
            Err(VmError::NoMemory)
        } else {
            Ok(())
        }
    }

    /// Merges runs of adjacent VMAs with equal rights, from the VMA at or
    /// before `from` up to the one starting at `to`. Allocates nothing.
    fn coalesce(&mut self, from: u64, to: u64) {
        let Some(mut key) = self
            .vmas
            .range(..from)
            .next_back()
            .or_else(|| self.vmas.range(from..).next())
            .map(|(&start, _)| start)
        else {
            return;
        };
        loop {
            let current = self.vmas[&key];
            let Some(next) = self.vmas.range(current.end..).next().map(|(_, v)| *v) else {
                return;
            };
            if next.start > to {
                return;
            }
            if current.continues_with(&next) {
                self.remove_vma(next.start);
                self.insert_vma(Vma {
                    end: next.end,
                    ..current
                });
            } else {
                key = next.start;
            }
        }
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

    /// Adds an anonymous mapping. Returns its start and the ranges
    /// previously mapped there (for MAP_FIXED), whose pages the caller must
    /// unmap.
    pub fn map(
        &mut self,
        placement: Placement,
        length: u64,
        prot: Prot,
    ) -> Result<(u64, Changed), VmError> {
        self.map_backed(placement, length, prot, None)
    }

    /// Adds a mapping, of `backing` if given (a private file mapping).
    pub fn map_backed(
        &mut self,
        placement: Placement,
        length: u64,
        prot: Prot,
        backing: Option<Backing>,
    ) -> Result<(u64, Changed), VmError> {
        if prot.write && prot.exec {
            return Err(VmError::WriteExec);
        }
        if let Some(b) = backing {
            if prot.exec && !b.may_exec {
                return Err(VmError::NotExecutable);
            }
            if prot.write && b.shared && !b.may_write {
                return Err(VmError::NotWritable);
            }
            // Every page's file offset must fit (checked once here).
            b.offset.checked_add(length).ok_or(VmError::BadOffset)?;
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
                // The new VMA, plus any VMA the replacement cuts in two.
                self.ensure_room(1 + self.cuts(start, end))?;
                (start, self.unmap(start, end - start)?)
            }
            Placement::FixedNoReplace(start) => {
                let end = check_range(start, length)?;
                if self.overlaps(start, end) {
                    return Err(VmError::Exists);
                }
                self.ensure_room(1)?;
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
                self.ensure_room(1)?;
                let start = if hint_free {
                    hint
                } else {
                    // Below the last placement first (A2), then below the
                    // mmap base, then anywhere.
                    let from = match self.search_from {
                        0 => top,
                        cached => cached.min(top),
                    };
                    let start = self
                        .find_gap(length, from)
                        .or_else(|| self.find_gap(length, top))
                        .or_else(|| self.find_gap(length, USER_END))
                        .ok_or(VmError::NoMemory)?;
                    self.search_from = start;
                    start
                };
                (start, Vec::new())
            }
        };
        self.insert_vma(Vma {
            start,
            end: start + length,
            prot,
            backing,
        });
        self.coalesce(start, start + length);
        Ok((start, replaced))
    }

    /// Splits VMAs so that `at` is a boundary.
    fn split_at(&mut self, at: u64) {
        if let Some(vma) = self.find(at)
            && vma.start < at
        {
            self.insert_vma(Vma { end: at, ..vma });
            // The upper part maps the file from further in.
            let backing = vma.backing.map(|b| Backing {
                offset: b.offset + (at - vma.start),
                ..b
            });
            self.insert_vma(Vma {
                start: at,
                backing,
                ..vma
            });
        }
    }

    /// Removes `[start, start + length)`. Unmapped holes are fine (as in
    /// munmap). Returns the ranges that were mapped.
    pub fn unmap(&mut self, start: u64, length: u64) -> Result<Changed, VmError> {
        let end = check_range(start, length)?;
        // Cutting a hole out of the middle of one VMA leaves two.
        let middle = self
            .find(start)
            .is_some_and(|v| v.start < start && end < v.end);
        self.ensure_room(usize::from(middle))?;
        // Freed space above the cached search start is used again.
        if self.search_from != 0 && end > self.search_from {
            self.search_from = end;
        }
        self.split_at(start);
        self.split_at(end);
        let starts: Vec<u64> = self.vmas.range(start..end).map(|(&s, _)| s).collect();
        Ok(starts
            .into_iter()
            .filter_map(|s| self.remove_vma(s))
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
        // Fully mapped, and executable only where the file allows it?
        let mut cursor = start;
        while cursor < end {
            match self.find(cursor) {
                Some(v) if prot.exec && v.backing.is_some_and(|b| !b.may_exec) => {
                    return Err(VmError::NotExecutable);
                }
                Some(v) if prot.write && v.backing.is_some_and(|b| b.shared && !b.may_write) => {
                    return Err(VmError::NotWritable);
                }
                Some(v) => cursor = v.end,
                None => return Err(VmError::NoMemory),
            }
        }
        self.ensure_room(self.cuts(start, end))?;
        self.split_at(start);
        self.split_at(end);
        let mut changed = Vec::new();
        for (_, vma) in self.vmas.range_mut(start..end) {
            vma.prot = prot;
            changed.push((vma.start, vma.end));
        }
        self.coalesce(start, end);
        Ok(changed)
    }
}

/// What a page fault in user space means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultAction {
    /// No page yet: map a fresh zeroed page with these rights.
    DemandZero(Prot),
    /// No page yet in a private file mapping: map a fresh page holding the
    /// file's bytes from `offset` (zero past the end of the file).
    FromFile {
        prot: Prot,
        object: u64,
        offset: u64,
    },
    /// A write to a page shared copy-on-write: give the writer its own
    /// copy (or reuse the page if it is the only user).
    CopyOnWrite(Prot),
    /// A page of a shared file mapping: map the file's own frame for
    /// `offset` (never a copy), or, if it is mapped already and this is an
    /// allowed write, make it writable.
    Shared {
        prot: Prot,
        object: u64,
        offset: u64,
    },
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
    if let (true, Some(b), Some(offset)) = (allowed, vma.backing, vma.file_offset(address))
        && b.shared
    {
        return FaultAction::Shared {
            prot: vma.prot,
            object: b.object,
            offset,
        };
    }
    match (allowed, present) {
        (false, _) => FaultAction::Violation,
        (true, false) => match (vma.backing, vma.file_offset(address)) {
            (Some(b), Some(offset)) => FaultAction::FromFile {
                prot: vma.prot,
                object: b.object,
                offset,
            },
            _ => FaultAction::DemandZero(vma.prot),
        },
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
        // `a` and `b` are adjacent with equal rights: one VMA.
        assert_eq!(l.vmas().count(), 2);
        assert_eq!(
            l.find(b),
            Some(Vma {
                start: b,
                end: a + 3 * PAGE,
                prot: RW,
                backing: None,
            })
        );
    }

    #[test]
    fn the_map_count_is_capped_and_a_refusal_changes_nothing() {
        let mut l = Layout::new();
        l.set_map_limit(4);
        // Alternate rights so adjacent mappings do not merge.
        for i in 0..4 {
            let prot = if i % 2 == 0 { RW } else { RO };
            l.map(Placement::Anywhere { hint: 0 }, PAGE, prot).unwrap();
        }
        assert_eq!(l.count(), 4);
        let before = l.clone();
        assert_eq!(
            l.map(Placement::Anywhere { hint: 0 }, PAGE, RW),
            Err(VmError::NoMemory)
        );
        assert_eq!(
            l.map(Placement::FixedNoReplace(0x40_0000), PAGE, RW),
            Err(VmError::NoMemory)
        );
        assert_eq!(l, before, "a refused call leaves the layout unchanged");
    }

    #[test]
    fn splits_count_against_the_cap() {
        let mut l = Layout::new();
        l.set_map_limit(1);
        let (start, _) = l.map(Placement::Fixed(0x40_0000), 4 * PAGE, RW).unwrap();
        let before = l.clone();
        // A hole in the middle, or new rights for the middle, would make
        // more than one VMA.
        assert_eq!(l.unmap(start + PAGE, PAGE), Err(VmError::NoMemory));
        assert_eq!(l.protect(start + PAGE, PAGE, RO), Err(VmError::NoMemory));
        assert_eq!(
            l.map(Placement::Fixed(start + PAGE), PAGE, RO),
            Err(VmError::NoMemory)
        );
        assert_eq!(l, before);
        // Trimming an end does not add a VMA, and all of it can go.
        assert!(l.unmap(start, PAGE).is_ok());
        assert!(l.protect(start + PAGE, 3 * PAGE, RO).is_ok());
        assert!(l.unmap(start, 4 * PAGE).is_ok());
        assert_eq!(l.count(), 0);
    }

    #[test]
    fn adjacent_mappings_with_equal_rights_merge() {
        let mut l = Layout::new();
        l.map(Placement::Fixed(0x40_0000), PAGE, RW).unwrap();
        l.map(Placement::Fixed(0x40_2000), PAGE, RW).unwrap();
        assert_eq!(l.count(), 2);
        // Filling the gap joins all three.
        l.map(Placement::Fixed(0x40_1000), PAGE, RW).unwrap();
        assert_eq!(l.count(), 1);
        // mprotect of the middle splits; restoring the rights merges again.
        l.protect(0x40_1000, PAGE, RO).unwrap();
        assert_eq!(l.count(), 3);
        l.protect(0x40_1000, PAGE, RW).unwrap();
        assert_eq!(l.count(), 1);
        assert_eq!(
            l.find(0x40_0000),
            Some(Vma {
                start: 0x40_0000,
                end: 0x40_3000,
                prot: RW,
                backing: None,
            })
        );
    }

    #[test]
    fn mmap_null_continues_below_the_last_placement() {
        let mut l = Layout::new();
        let mut last = USER_END;
        for i in 0..100 {
            let prot = if i % 2 == 0 { RW } else { RO };
            let (at, _) = l.map(Placement::Anywhere { hint: 0 }, PAGE, prot).unwrap();
            assert_eq!(at, last - PAGE, "packed downward");
            last = at;
        }
        assert_eq!(l.search_from, last);
        // Space freed above the cached start is found again.
        l.unmap(USER_END - PAGE, PAGE).unwrap();
        let (again, _) = l.map(Placement::Anywhere { hint: 0 }, PAGE, RO).unwrap();
        assert!(again < USER_END && again >= last - PAGE);
        // When nothing fits below the cache, the whole range is searched.
        let mut full = Layout::new();
        full.map(
            Placement::Fixed(USER_START),
            USER_END - USER_START - PAGE,
            RW,
        )
        .unwrap();
        full.search_from = USER_START;
        let (top, _) = full.map(Placement::Anywhere { hint: 0 }, PAGE, RO).unwrap();
        assert_eq!(top, USER_END - PAGE);
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

    fn file(object: u64, offset: u64, may_exec: bool) -> Option<Backing> {
        Some(Backing {
            object,
            offset,
            may_exec,
            shared: false,
            may_write: true,
        })
    }

    fn shared(object: u64, offset: u64, may_write: bool) -> Option<Backing> {
        Some(Backing {
            object,
            offset,
            may_exec: false,
            shared: true,
            may_write,
        })
    }

    #[test]
    fn layouts_know_which_files_they_map() {
        let mut l = Layout::new();
        l.map_backed(Placement::Fixed(0x10_0000), 0x4000, RO, file(7, 0, false))
            .unwrap();
        assert_eq!(l.take_object_changes(), alloc::vec![(7, true)]);
        // Splitting (two VMAs of file 7) and merging change nothing.
        l.protect(0x10_1000, 0x1000, RW).unwrap();
        l.protect(0x10_1000, 0x1000, RO).unwrap();
        assert_eq!(l.take_object_changes(), alloc::vec![]);
        // Part of it unmapped: still mapped.
        l.unmap(0x10_0000, 0x1000).unwrap();
        assert_eq!(l.take_object_changes(), alloc::vec![]);
        // Another file over the rest, with MAP_FIXED: 8 in, 7 out.
        l.map_backed(Placement::Fixed(0x10_0000), 0x4000, RO, shared(8, 0, true))
            .unwrap();
        // MAP_FIXED removes first: the owner must net a batch's changes,
        // or a file mapped again over itself would look unmapped between.
        assert_eq!(l.take_object_changes(), alloc::vec![(7, false), (8, true)]);
        assert_eq!(l.objects().collect::<Vec<_>>(), alloc::vec![8]);
        l.map_backed(Placement::Fixed(0x10_0000), 0x4000, RO, shared(8, 0, true))
            .unwrap();
        assert_eq!(l.take_object_changes(), alloc::vec![(8, false), (8, true)]);
        // Over part of it, the rest still maps the file: nothing changes.
        l.map_backed(Placement::Fixed(0x10_0000), 0x1000, RO, shared(8, 0, true))
            .unwrap();
        assert_eq!(l.take_object_changes(), alloc::vec![]);
        // A copy (fork) maps the same files.
        let copy = l.clone();
        assert_eq!(copy.objects().collect::<Vec<_>>(), alloc::vec![8]);
        // Anonymous memory counts for nothing; unmapping all of 8 ends it.
        l.map_backed(Placement::Fixed(0x20_0000), 0x1000, RW, None)
            .unwrap();
        l.unmap(0x10_0000, 0x4000).unwrap();
        assert_eq!(l.take_object_changes(), alloc::vec![(8, false)]);
        assert_eq!(l.objects().count(), 0);
    }

    #[test]
    fn shared_mappings_fault_to_the_file_and_keep_may_write() {
        let mut l = Layout::new();
        // Read-only handle: PROT_WRITE refused at mmap and at mprotect,
        // as Linux without VM_MAYWRITE.
        assert_eq!(
            l.map_backed(Placement::Fixed(0x10_0000), 0x2000, RW, shared(7, 0, false)),
            Err(VmError::NotWritable)
        );
        l.map_backed(Placement::Fixed(0x10_0000), 0x2000, RO, shared(7, 0, false))
            .unwrap();
        assert_eq!(l.protect(0x10_0000, 0x1000, RW), Err(VmError::NotWritable));
        // A private mapping of a read-only handle may still be written.
        l.map_backed(Placement::Fixed(0x20_0000), 0x1000, RO, file(7, 0, false))
            .unwrap();
        assert!(l.protect(0x20_0000, 0x1000, RW).is_ok());
        // Writable handle: faults map the file's page, present or not,
        // never copy-on-write.
        l.map_backed(
            Placement::Fixed(0x30_0000),
            0x2000,
            RW,
            shared(8, 0x5000, true),
        )
        .unwrap();
        let expect = FaultAction::Shared {
            prot: RW,
            object: 8,
            offset: 0x6000,
        };
        assert_eq!(classify_fault(&l, 0x30_1234, true, false, false), expect);
        assert_eq!(classify_fault(&l, 0x30_1234, true, false, true), expect);
        // Still refused where the VMA forbids it.
        assert_eq!(
            classify_fault(&l, 0x10_0000, true, false, true),
            FaultAction::Violation
        );
        // Shared and private mappings of one file never merge.
        l.map_backed(Placement::Fixed(0x40_0000), 0x1000, RO, shared(9, 0, true))
            .unwrap();
        l.map_backed(
            Placement::Fixed(0x40_1000),
            0x1000,
            RO,
            file(9, 0x1000, false),
        )
        .unwrap();
        assert_eq!(l.find(0x40_1000).unwrap().start, 0x40_1000);
    }

    #[test]
    fn file_mappings_keep_their_offsets_through_splits_and_merges() {
        let mut l = Layout::new();
        let base = 0x40_0000;
        l.map_backed(Placement::Fixed(base), 4 * PAGE, RO, file(7, 0x2000, false))
            .unwrap();
        // A page fault reads the right part of the file.
        let fault = |l: &Layout, at| classify_fault(l, at, false, false, false);
        assert_eq!(
            fault(&l, base + 2 * PAGE + 5),
            FaultAction::FromFile {
                prot: RO,
                object: 7,
                offset: 0x4000
            }
        );
        // Cutting the middle out leaves the top part mapping further in.
        l.unmap(base + PAGE, PAGE).unwrap();
        assert_eq!(
            l.find(base + 2 * PAGE).unwrap().backing,
            file(7, 0x4000, false)
        );
        assert_eq!(l.find(base).unwrap().backing, file(7, 0x2000, false));
        // Mapping the hole back contiguously merges into one VMA again.
        l.map_backed(
            Placement::Fixed(base + PAGE),
            PAGE,
            RO,
            file(7, 0x3000, false),
        )
        .unwrap();
        assert_eq!(l.count(), 1);
        // Not contiguous in the file, another file, or anonymous: separate.
        l.map_backed(
            Placement::Fixed(base + 4 * PAGE),
            PAGE,
            RO,
            file(7, 0x9000, false),
        )
        .unwrap();
        l.map_backed(
            Placement::Fixed(base + 5 * PAGE),
            PAGE,
            RO,
            file(8, 0x8000, false),
        )
        .unwrap();
        l.map(Placement::Fixed(base + 6 * PAGE), PAGE, RO).unwrap();
        assert_eq!(l.count(), 4);
        // Anonymous pages fault as zero pages.
        assert_eq!(fault(&l, base + 6 * PAGE), FaultAction::DemandZero(RO));
    }

    #[test]
    fn a_file_mapping_is_executable_only_if_its_handle_allowed_it() {
        let rx = Prot {
            read: true,
            write: false,
            exec: true,
        };
        let mut l = Layout::new();
        let base = 0x40_0000;
        assert_eq!(
            l.map_backed(Placement::Fixed(base), PAGE, rx, file(1, 0, false)),
            Err(VmError::NotExecutable)
        );
        l.map_backed(Placement::Fixed(base), 2 * PAGE, RO, file(1, 0, false))
            .unwrap();
        assert_eq!(l.protect(base, PAGE, rx), Err(VmError::NotExecutable));
        assert_eq!(l.find(base).unwrap().prot, RO, "a refusal changes nothing");
        l.map_backed(
            Placement::Fixed(base + 2 * PAGE),
            PAGE,
            RO,
            file(2, 0, true),
        )
        .unwrap();
        assert!(l.protect(base + 2 * PAGE, PAGE, rx).is_ok());
        // An offset that would overflow is refused.
        assert_eq!(
            l.map_backed(
                Placement::Fixed(base),
                PAGE,
                RO,
                file(1, u64::MAX - 10, true)
            ),
            Err(VmError::BadOffset)
        );
    }
}
