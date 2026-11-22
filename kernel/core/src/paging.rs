//! 4-level x86-64 page tables (P1-T4): building, walking and checking
//! them, in safe Rust. Raw access to table memory is behind the
//! [`TableAccess`] trait, which `keel-hal` implements over the direct map
//! and the unit tests implement over ordinary heap memory.
//!
//! Entry formats: Intel SDM Vol. 3 (325384-093), Tables 5-15 to 5-20.
//!   bit 0 P, 1 R/W, 2 U/S, 3 PWT, 4 PCD, 7 PS (in PDPTEs and PDEs; PAT in
//!   PTEs), 12 PAT (in 2 MiB PDEs), 51:12 physical address, 63 XD.
//! Effective rights (SDM section 5.6): a page is writable only if R/W is 1
//! at every level, user-accessible only if U/S is 1 at every level, and
//! executable only if XD is 0 at every level.
//! Memory type (SDM Table 14-11): the PAT, PCD and PWT bits select a PAT
//! entry. Limine programs PAT entry 0 as write-back and entry 5 as
//! write-combining (PROTOCOL.md, "Caching", x86-64); entry 5 is selected by
//! PAT = 1, PCD = 0, PWT = 1. Entry 3 is uncacheable (UC), selected by
//! PAT = 0, PCD = 1, PWT = 1; it is used for device registers.

use crate::frame::Frame;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const PWT: u64 = 1 << 3;
const PCD: u64 = 1 << 4;
const HUGE: u64 = 1 << 7; // PS in PDPTEs and PDEs
const PAT_4K: u64 = 1 << 7;
const PAT_2M: u64 = 1 << 12;
const NO_EXECUTE: u64 = 1 << 63;
/// Physical-address bits 51:12.
const ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Size of a mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageSize {
    /// 4 KiB, mapped by a page-table entry.
    Small,
    /// 2 MiB, mapped by a page-directory entry with PS = 1.
    Large,
}

impl PageSize {
    /// Size in bytes.
    pub const fn bytes(self) -> u64 {
        match self {
            PageSize::Small => 4096,
            PageSize::Large => 2 * 1024 * 1024,
        }
    }

    /// Depth of the leaf entry: 3 for a PTE, 2 for a PDE.
    const fn leaf_level(self) -> usize {
        match self {
            PageSize::Small => 3,
            PageSize::Large => 2,
        }
    }
}

/// Access rights and memory type of a mapping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub writable: bool,
    pub executable: bool,
    pub user: bool,
    /// Write-combining memory type (for the framebuffer).
    pub write_combining: bool,
    /// Uncacheable memory type (for device registers). Write-back when
    /// neither this nor `write_combining` is set.
    pub uncached: bool,
}

impl Flags {
    /// Read-only, not executable, kernel only.
    pub const READ_ONLY: Flags = Flags {
        writable: false,
        executable: false,
        user: false,
        write_combining: false,
        uncached: false,
    };
    /// Read and execute, kernel only (kernel text).
    pub const TEXT: Flags = Flags {
        executable: true,
        ..Flags::READ_ONLY
    };
    /// Read and write, not executable, kernel only.
    pub const DATA: Flags = Flags {
        writable: true,
        ..Flags::READ_ONLY
    };
}

/// Errors from [`map`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// The virtual or physical address is not aligned to the page size, or
    /// the virtual address is not canonical.
    Misaligned,
    /// Writable and executable at once (SR-12).
    WritableAndExecutable,
    /// Something is already mapped there (a page, or a large page covering
    /// the address, or a page table where a large page should go).
    AlreadyMapped,
    /// No memory for a page table.
    OutOfMemory,
}

/// Raw access to page-table memory.
pub trait TableAccess {
    /// Allocates a zero-filled frame for a page table.
    fn allocate_table(&mut self) -> Option<Frame>;
    /// The 512 entries of the table in `frame`. Only called for frames
    /// that `allocate_table` returned, or the root passed to [`map`].
    fn table(&mut self, frame: Frame) -> &mut [u64; 512];
}

/// Index into the table at `level` (0 = PML4) for `virt`.
fn index(virt: u64, level: usize) -> usize {
    ((virt >> (39 - 9 * level)) & 0x1FF) as usize
}

/// Whether `virt` is canonical under 4-level paging: bits 63:47 all equal
/// (SDM Vol. 1 section 3.3.7.1).
pub fn is_canonical(virt: u64) -> bool {
    let top = virt >> 47;
    top == 0 || top == 0x1_FFFF
}

/// Encodes a leaf entry. Pure; exposed for tests.
pub fn leaf_entry(phys: u64, size: PageSize, flags: Flags) -> u64 {
    let mut entry = phys & ADDRESS_MASK | PRESENT;
    if flags.writable {
        entry |= WRITABLE;
    }
    if flags.user {
        entry |= USER;
    }
    if !flags.executable {
        entry |= NO_EXECUTE;
    }
    if size == PageSize::Large {
        entry |= HUGE;
    }
    if flags.write_combining {
        entry |= PWT
            | match size {
                PageSize::Small => PAT_4K,
                PageSize::Large => PAT_2M,
            };
    } else if flags.uncached {
        entry |= PCD | PWT;
    }
    entry
}

/// Intermediate entries grant everything; the leaf decides the rights.
/// U/S is set only on paths to user pages.
fn table_entry(table: Frame, user: bool) -> u64 {
    table.address() | PRESENT | WRITABLE | if user { USER } else { 0 }
}

/// Maps one page of `size` at `virt` to `phys`.
pub fn map<A: TableAccess>(
    access: &mut A,
    root: Frame,
    virt: u64,
    phys: u64,
    size: PageSize,
    flags: Flags,
) -> Result<(), MapError> {
    if !virt.is_multiple_of(size.bytes())
        || !phys.is_multiple_of(size.bytes())
        || !is_canonical(virt)
    {
        return Err(MapError::Misaligned);
    }
    if flags.writable && flags.executable {
        return Err(MapError::WritableAndExecutable);
    }
    if flags.write_combining && flags.uncached {
        return Err(MapError::Misaligned);
    }
    let mut table = root;
    for level in 0..size.leaf_level() {
        let i = index(virt, level);
        let entry = access.table(table)[i];
        if entry & PRESENT == 0 {
            let next = access.allocate_table().ok_or(MapError::OutOfMemory)?;
            access.table(table)[i] = table_entry(next, flags.user);
            table = next;
        } else if level > 0 && entry & HUGE != 0 {
            return Err(MapError::AlreadyMapped);
        } else {
            if flags.user && entry & USER == 0 {
                access.table(table)[i] = entry | USER;
            }
            table = Frame::containing(entry & ADDRESS_MASK);
        }
    }
    let i = index(virt, size.leaf_level());
    let slot = &mut access.table(table)[i];
    if *slot & PRESENT != 0 {
        return Err(MapError::AlreadyMapped);
    }
    *slot = leaf_entry(phys, size, flags);
    Ok(())
}

/// Removes the 4 KiB mapping at `virt` and returns the physical address it
/// pointed to. Intermediate tables are kept. The caller must invalidate
/// the TLB entry for `virt` afterwards. Returns `None` if nothing (or a
/// 2 MiB page) is mapped there.
pub fn unmap_small<A: TableAccess>(access: &mut A, root: Frame, virt: u64) -> Option<u64> {
    if !is_canonical(virt) || !virt.is_multiple_of(PageSize::Small.bytes()) {
        return None;
    }
    let mut table = root;
    for level in 0..3 {
        let entry = access.table(table)[index(virt, level)];
        if entry & PRESENT == 0 || (level > 0 && entry & HUGE != 0) {
            return None;
        }
        table = Frame::containing(entry & ADDRESS_MASK);
    }
    let slot = &mut access.table(table)[index(virt, 3)];
    if *slot & PRESENT == 0 {
        return None;
    }
    let phys = *slot & ADDRESS_MASK;
    *slot = 0;
    Some(phys)
}

/// Replaces the 4 KiB leaf at `virt` with a mapping of `phys` and
/// returns the physical address it pointed to before. The intermediate
/// tables must already exist (the page must have been mapped). The caller
/// must invalidate the TLB entry for `virt` afterwards.
pub fn replace_small<A: TableAccess>(
    access: &mut A,
    root: Frame,
    virt: u64,
    phys: u64,
    flags: Flags,
) -> Result<u64, MapError> {
    if !virt.is_multiple_of(PageSize::Small.bytes())
        || !phys.is_multiple_of(PageSize::Small.bytes())
        || !is_canonical(virt)
    {
        return Err(MapError::Misaligned);
    }
    if flags.writable && flags.executable {
        return Err(MapError::WritableAndExecutable);
    }
    let mut table = root;
    for level in 0..3 {
        let entry = access.table(table)[index(virt, level)];
        if entry & PRESENT == 0 || (level > 0 && entry & HUGE != 0) {
            return Err(MapError::AlreadyMapped);
        }
        table = Frame::containing(entry & ADDRESS_MASK);
    }
    let slot = &mut access.table(table)[index(virt, 3)];
    if *slot & PRESENT == 0 {
        return Err(MapError::AlreadyMapped);
    }
    let old = *slot & ADDRESS_MASK;
    *slot = leaf_entry(phys, PageSize::Small, flags);
    Ok(old)
}

/// Makes sure the top-level entries `indices` exist, allocating empty
/// next-level tables where needed. The kernel does this for the whole
/// upper half at boot, so that every address space can share those
/// entries and later kernel mappings appear in all of them.
pub fn ensure_top_level<A: TableAccess>(
    access: &mut A,
    root: Frame,
    indices: core::ops::Range<usize>,
) -> Result<(), MapError> {
    for i in indices {
        if access.table(root)[i] & PRESENT == 0 {
            let table = access.allocate_table().ok_or(MapError::OutOfMemory)?;
            access.table(root)[i] = table_entry(table, false);
        }
    }
    Ok(())
}

/// Removes everything below top-level entry 256 (the user half) and
/// returns the page-table frames that held it plus every leaf's physical
/// address, so the caller can release them. The caller must not have
/// `root` active, or must flush the TLB.
pub fn clear_user_half<A: TableAccess>(
    access: &mut A,
    root: Frame,
) -> (alloc::vec::Vec<Frame>, alloc::vec::Vec<u64>) {
    let mut tables = alloc::vec::Vec::new();
    let mut leaves = alloc::vec::Vec::new();
    fn visit<A: TableAccess>(
        access: &mut A,
        table: Frame,
        level: usize,
        tables: &mut alloc::vec::Vec<Frame>,
        leaves: &mut alloc::vec::Vec<u64>,
    ) {
        for i in 0..512 {
            let entry = access.table(table)[i];
            if entry & PRESENT == 0 {
                continue;
            }
            let is_leaf = level == 3 || (level >= 1 && entry & HUGE != 0);
            if is_leaf {
                leaves.push(entry & ADDRESS_MASK);
            } else {
                let next = Frame::containing(entry & ADDRESS_MASK);
                visit(access, next, level + 1, tables, leaves);
                tables.push(next);
            }
        }
    }
    for i in 0..256 {
        let entry = access.table(root)[i];
        if entry & PRESENT == 0 {
            continue;
        }
        let next = Frame::containing(entry & ADDRESS_MASK);
        visit(access, next, 1, &mut tables, &mut leaves);
        tables.push(next);
        access.table(root)[i] = 0;
    }
    (tables, leaves)
}

/// A resolved mapping with its effective rights.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    /// Physical address `virt` maps to.
    pub phys: u64,
    pub size: PageSize,
    /// Effective rights, combined across all levels.
    pub flags: Flags,
}

fn effective(rights: &mut Flags, entry: u64) {
    rights.writable &= entry & WRITABLE != 0;
    rights.user &= entry & USER != 0;
    rights.executable &= entry & NO_EXECUTE == 0;
}

/// Looks up `virt`. Returns `None` if it is not mapped.
pub fn translate<A: TableAccess>(access: &mut A, root: Frame, virt: u64) -> Option<Translation> {
    if !is_canonical(virt) {
        return None;
    }
    let mut rights = Flags {
        writable: true,
        executable: true,
        user: true,
        write_combining: false,
        uncached: false,
    };
    let mut table = root;
    for level in 0..4 {
        let entry = access.table(table)[index(virt, level)];
        if entry & PRESENT == 0 {
            return None;
        }
        effective(&mut rights, entry);
        let leaf_size = match level {
            2 if entry & HUGE != 0 => Some(PageSize::Large),
            3 => Some(PageSize::Small),
            _ => None,
        };
        if let Some(size) = leaf_size {
            let pat = match size {
                PageSize::Small => PAT_4K,
                PageSize::Large => PAT_2M,
            };
            rights.write_combining = entry & PWT != 0 && entry & pat != 0;
            rights.uncached = entry & PWT != 0 && entry & PCD != 0 && entry & pat == 0;
            let offset = virt % size.bytes();
            return Some(Translation {
                phys: (entry & ADDRESS_MASK & !(size.bytes() - 1)) + offset,
                size,
                flags: rights,
            });
        }
        if level == 1 && entry & HUGE != 0 {
            // 1 GiB pages are never created by Keel.
            return None;
        }
        table = Frame::containing(entry & ADDRESS_MASK);
    }
    None
}

/// Summary of a full walk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WalkSummary {
    pub small_pages: u64,
    pub large_pages: u64,
    /// Leaves whose effective rights are both writable and executable.
    pub writable_and_executable: u64,
    /// Present 1 GiB leaves (Keel never creates them).
    pub giant_pages: u64,
    /// Not-present entries, at any level, that are not entirely zero. Keel
    /// keeps this at 0: a not-present entry with a frame address in it can
    /// be used to read that frame speculatively on CPUs affected by L1TF
    /// (Linux `Documentation/admin-guide/hw-vuln/l1tf.rst`).
    pub nonpresent_nonzero: u64,
}

/// Visits every present leaf and counts what it finds. `visit` receives
/// the virtual address, the translation, and must not touch the tables.
pub fn walk<A: TableAccess>(
    access: &mut A,
    root: Frame,
    mut visit: impl FnMut(u64, Translation),
) -> WalkSummary {
    let mut summary = WalkSummary::default();
    let all = Flags {
        writable: true,
        executable: true,
        user: true,
        write_combining: false,
        uncached: false,
    };
    walk_level(access, root, 0, 0, all, &mut summary, &mut visit);
    summary
}

fn walk_level<A: TableAccess>(
    access: &mut A,
    table: Frame,
    level: usize,
    base: u64,
    rights: Flags,
    summary: &mut WalkSummary,
    visit: &mut impl FnMut(u64, Translation),
) {
    for i in 0..512usize {
        let entry = access.table(table)[i];
        if entry & PRESENT == 0 {
            if entry != 0 {
                summary.nonpresent_nonzero += 1;
            }
            continue;
        }
        let mut virt = base | (i as u64) << (39 - 9 * level);
        if level == 0 && i >= 256 {
            virt |= 0xFFFF_0000_0000_0000; // sign-extend bit 47
        }
        let mut here = rights;
        effective(&mut here, entry);
        let leaf_size = match level {
            1 if entry & HUGE != 0 => {
                summary.giant_pages += 1;
                continue;
            }
            2 if entry & HUGE != 0 => Some(PageSize::Large),
            3 => Some(PageSize::Small),
            _ => None,
        };
        match leaf_size {
            Some(size) => {
                if here.writable && here.executable {
                    summary.writable_and_executable += 1;
                }
                match size {
                    PageSize::Small => summary.small_pages += 1,
                    PageSize::Large => summary.large_pages += 1,
                }
                let pat = if size == PageSize::Small {
                    PAT_4K
                } else {
                    PAT_2M
                };
                here.write_combining = entry & PWT != 0 && entry & pat != 0;
                here.uncached = entry & PWT != 0 && entry & PCD != 0 && entry & pat == 0;
                visit(
                    virt,
                    Translation {
                        phys: entry & ADDRESS_MASK & !(size.bytes() - 1),
                        size,
                        flags: here,
                    },
                );
            }
            None => {
                let next = Frame::containing(entry & ADDRESS_MASK);
                walk_level(access, next, level + 1, virt, here, summary, visit);
            }
        }
    }
}

/// Maps `[virt, virt + length)` to `[phys, ...)` using 2 MiB pages where
/// both addresses allow it and 4 KiB pages elsewhere. Pages that are
/// already mapped are skipped, not replaced: used for the direct map, whose
/// source regions may overlap (Limine PROTOCOL.md, "Memory Map Feature").
/// Returns the number of bytes newly mapped.
pub fn map_range_skipping_present<A: TableAccess>(
    access: &mut A,
    root: Frame,
    virt: u64,
    phys: u64,
    length: u64,
    flags: Flags,
    allow_large: bool,
) -> Result<u64, MapError> {
    let small = PageSize::Small.bytes();
    let large = PageSize::Large.bytes();
    if !virt.is_multiple_of(small) || !phys.is_multiple_of(small) || !length.is_multiple_of(small) {
        return Err(MapError::Misaligned);
    }
    let mut mapped = 0;
    let mut offset = 0;
    while offset < length {
        let (v, p) = (virt + offset, phys + offset);
        let try_large = allow_large && v % large == 0 && p % large == 0 && length - offset >= large;
        if try_large {
            match map(access, root, v, p, PageSize::Large, flags) {
                Ok(()) => {
                    mapped += large;
                    offset += large;
                    continue;
                }
                // Something smaller is already mapped in this 2 MiB: fill
                // the gaps with 4 KiB pages below.
                Err(MapError::AlreadyMapped) => {}
                Err(other) => return Err(other),
            }
        }
        match map(access, root, v, p, PageSize::Small, flags) {
            Ok(()) => mapped += small,
            Err(MapError::AlreadyMapped) => {}
            Err(other) => return Err(other),
        }
        offset += small;
    }
    Ok(mapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Page tables in heap memory, addressed by fake physical frames.
    struct HeapTables {
        tables: HashMap<u64, Box<[u64; 512]>>,
        next: u64,
        limit: usize,
    }

    impl HeapTables {
        fn new() -> (Self, Frame) {
            let mut t = HeapTables {
                tables: HashMap::new(),
                next: 0x10_0000,
                limit: usize::MAX,
            };
            let root = t.allocate_table().unwrap();
            (t, root)
        }
    }

    impl TableAccess for HeapTables {
        fn allocate_table(&mut self) -> Option<Frame> {
            if self.tables.len() >= self.limit {
                return None;
            }
            let frame = Frame::containing(self.next);
            self.next += 4096;
            self.tables.insert(frame.address(), Box::new([0; 512]));
            Some(frame)
        }
        fn table(&mut self, frame: Frame) -> &mut [u64; 512] {
            self.tables.get_mut(&frame.address()).expect("known table")
        }
    }

    const KERNEL: u64 = 0xffff_ffff_8000_0000;

    #[test]
    fn unmapping_leaves_no_stale_bits() {
        let (mut t, root) = HeapTables::new();
        let rw = Flags {
            writable: true,
            ..Flags::READ_ONLY
        };
        map(&mut t, root, KERNEL, 0x20_0000, PageSize::Small, rw).unwrap();
        assert_eq!(unmap_small(&mut t, root, KERNEL), Some(0x20_0000));
        assert_eq!(walk(&mut t, root, |_, _| {}).nonpresent_nonzero, 0);
        // A hand-made not-present entry with an address is counted.
        let table = Frame::containing(t.table(root)[index(KERNEL, 0)] & ADDRESS_MASK);
        t.table(table)[3] = 0x1234_5000;
        assert_eq!(walk(&mut t, root, |_, _| {}).nonpresent_nonzero, 1);
    }

    #[test]
    fn leaf_entries_have_the_documented_bits() {
        let text = leaf_entry(0x1234_5000, PageSize::Small, Flags::TEXT);
        assert_eq!(text, 0x1234_5000 | 1); // present, read-only, executable
        let data = leaf_entry(0x1234_5000, PageSize::Small, Flags::DATA);
        assert_eq!(data, 0x8000_0000_1234_5003); // XD | RW | P
        let wc = Flags {
            write_combining: true,
            ..Flags::DATA
        };
        assert_eq!(
            leaf_entry(0x20_0000, PageSize::Large, wc),
            0x8000_0000_0020_108B
        );
        assert_eq!(
            leaf_entry(0x1000, PageSize::Small, wc),
            0x8000_0000_0000_108B
        );
    }

    #[test]
    fn uncached_entries_select_pat_entry_3() {
        let mmio = Flags {
            uncached: true,
            ..Flags::DATA
        };
        assert_eq!(
            leaf_entry(0xFEE0_0000, PageSize::Small, mmio),
            0x8000_0000_FEE0_001B
        );
        let (mut t, root) = HeapTables::new();
        map(&mut t, root, KERNEL, 0xFEE0_0000, PageSize::Small, mmio).unwrap();
        assert_eq!(translate(&mut t, root, KERNEL).unwrap().flags, mmio);
        let both = Flags {
            write_combining: true,
            ..mmio
        };
        assert!(map(&mut t, root, KERNEL + 0x1000, 0, PageSize::Small, both).is_err());
    }

    #[test]
    fn maps_and_translates_with_effective_rights() {
        let (mut t, root) = HeapTables::new();
        map(
            &mut t,
            root,
            KERNEL,
            0x20_0000,
            PageSize::Small,
            Flags::TEXT,
        )
        .unwrap();
        map(
            &mut t,
            root,
            KERNEL + 0x1000,
            0x20_1000,
            PageSize::Small,
            Flags::DATA,
        )
        .unwrap();
        let text = translate(&mut t, root, KERNEL + 0x123).unwrap();
        assert_eq!(text.phys, 0x20_0123);
        assert_eq!(text.flags, Flags::TEXT);
        let data = translate(&mut t, root, KERNEL + 0x1FFF).unwrap();
        assert_eq!(data.phys, 0x20_1FFF);
        assert_eq!(data.flags, Flags::DATA);
        assert_eq!(translate(&mut t, root, KERNEL + 0x2000), None);
        assert_eq!(translate(&mut t, root, 0x0000_8000_0000_0000), None); // non-canonical
    }

    #[test]
    fn refuses_writable_executable_misaligned_and_double_mappings() {
        let (mut t, root) = HeapTables::new();
        let wx = Flags {
            writable: true,
            executable: true,
            ..Flags::READ_ONLY
        };
        assert_eq!(
            map(&mut t, root, KERNEL, 0, PageSize::Small, wx),
            Err(MapError::WritableAndExecutable)
        );
        assert_eq!(
            map(&mut t, root, KERNEL + 1, 0, PageSize::Small, Flags::DATA),
            Err(MapError::Misaligned)
        );
        assert_eq!(
            map(
                &mut t,
                root,
                KERNEL + 0x1000,
                0,
                PageSize::Large,
                Flags::DATA
            ),
            Err(MapError::Misaligned)
        );
        map(&mut t, root, KERNEL, 0, PageSize::Large, Flags::DATA).unwrap();
        assert_eq!(
            map(
                &mut t,
                root,
                KERNEL + 0x1000,
                0x1000,
                PageSize::Small,
                Flags::DATA
            ),
            Err(MapError::AlreadyMapped)
        );
        assert_eq!(
            map(&mut t, root, KERNEL, 0, PageSize::Large, Flags::DATA),
            Err(MapError::AlreadyMapped)
        );
    }

    #[test]
    fn out_of_memory_is_reported() {
        let (mut t, root) = HeapTables::new();
        t.limit = 2;
        assert_eq!(
            map(&mut t, root, KERNEL, 0, PageSize::Small, Flags::DATA),
            Err(MapError::OutOfMemory)
        );
    }

    #[test]
    fn walk_counts_pages_and_flags_writable_executable_leaves() {
        let (mut t, root) = HeapTables::new();
        map(
            &mut t,
            root,
            KERNEL,
            0x20_0000,
            PageSize::Small,
            Flags::TEXT,
        )
        .unwrap();
        map(
            &mut t,
            root,
            0xffff_8000_0020_0000,
            0x20_0000,
            PageSize::Large,
            Flags::DATA,
        )
        .unwrap();
        let mut seen = Vec::new();
        let summary = walk(&mut t, root, |virt, tr| seen.push((virt, tr.phys)));
        assert_eq!(summary.small_pages, 1);
        assert_eq!(summary.large_pages, 1);
        assert_eq!(summary.writable_and_executable, 0);
        assert!(seen.contains(&(KERNEL, 0x20_0000)));
        assert!(seen.contains(&(0xffff_8000_0020_0000, 0x20_0000)));

        // Forge a writable+executable leaf behind the API's back: the walk
        // must report it (this is the page-table self-test's job).
        let leaf = leaf_entry(0x30_0000, PageSize::Small, Flags::DATA) & !NO_EXECUTE;
        map(
            &mut t,
            root,
            KERNEL + 0x1000,
            0x30_0000,
            PageSize::Small,
            Flags::DATA,
        )
        .unwrap();
        let tr = translate(&mut t, root, KERNEL).unwrap();
        assert_eq!(tr.size, PageSize::Small);
        // Find the PTE and overwrite it.
        let pml4e = t.table(root)[index(KERNEL, 0)];
        let pdpt = Frame::containing(pml4e & ADDRESS_MASK);
        let pdpte = t.table(pdpt)[index(KERNEL, 1)];
        let pd = Frame::containing(pdpte & ADDRESS_MASK);
        let pde = t.table(pd)[index(KERNEL, 2)];
        let pt = Frame::containing(pde & ADDRESS_MASK);
        t.table(pt)[index(KERNEL + 0x1000, 3)] = leaf;
        assert_eq!(walk(&mut t, root, |_, _| {}).writable_and_executable, 1);
    }

    #[test]
    fn range_mapping_uses_large_pages_and_skips_existing_ones() {
        let (mut t, root) = HeapTables::new();
        let hhdm = 0xffff_8000_0000_0000u64;
        // 4 KiB head, one 2 MiB page, 4 KiB tail.
        let start = 0x1F_F000u64;
        let length = 0x1000 + 0x20_0000 + 0x2000;
        let mapped = map_range_skipping_present(
            &mut t,
            root,
            hhdm + start,
            start,
            length,
            Flags::DATA,
            true,
        )
        .unwrap();
        assert_eq!(mapped, length);
        let summary = walk(&mut t, root, |_, _| {});
        assert_eq!((summary.small_pages, summary.large_pages), (3, 1));
        // An overlapping region maps only the new part.
        let again = map_range_skipping_present(
            &mut t,
            root,
            hhdm + start,
            start,
            length + 0x1000,
            Flags::DATA,
            true,
        )
        .unwrap();
        assert_eq!(again, 0x1000);
        // A 2 MiB-aligned region that already contains a small page falls
        // back to small pages around it.
        let (mut t, root) = HeapTables::new();
        map(
            &mut t,
            root,
            hhdm + 0x40_1000,
            0x40_1000,
            PageSize::Small,
            Flags::DATA,
        )
        .unwrap();
        let mapped = map_range_skipping_present(
            &mut t,
            root,
            hhdm + 0x40_0000,
            0x40_0000,
            0x20_0000,
            Flags::DATA,
            true,
        )
        .unwrap();
        assert_eq!(mapped, 0x20_0000 - 0x1000);
        assert_eq!(walk(&mut t, root, |_, _| {}).small_pages, 512);
    }

    #[test]
    fn user_paths_get_the_user_bit_and_kernel_paths_do_not() {
        let (mut t, root) = HeapTables::new();
        map(&mut t, root, KERNEL, 0, PageSize::Small, Flags::DATA).unwrap();
        assert!(!translate(&mut t, root, KERNEL).unwrap().flags.user);
        let user = Flags {
            user: true,
            ..Flags::DATA
        };
        map(&mut t, root, 0x40_0000, 0x1000, PageSize::Small, user).unwrap();
        assert!(translate(&mut t, root, 0x40_0000).unwrap().flags.user);
        assert!(!translate(&mut t, root, KERNEL).unwrap().flags.user);
    }

    #[test]
    fn unmapping_removes_only_small_pages() {
        let (mut t, root) = HeapTables::new();
        map(&mut t, root, KERNEL, 0x5000, PageSize::Small, Flags::DATA).unwrap();
        map(
            &mut t,
            root,
            KERNEL + 0x20_0000,
            0x20_0000,
            PageSize::Large,
            Flags::DATA,
        )
        .unwrap();
        assert_eq!(unmap_small(&mut t, root, KERNEL), Some(0x5000));
        assert_eq!(translate(&mut t, root, KERNEL), None);
        assert_eq!(unmap_small(&mut t, root, KERNEL), None);
        assert_eq!(unmap_small(&mut t, root, KERNEL + 0x20_0000), None);
        assert!(translate(&mut t, root, KERNEL + 0x20_0000).is_some());
        // The slot can be reused.
        map(&mut t, root, KERNEL, 0x6000, PageSize::Small, Flags::DATA).unwrap();
    }

    #[test]
    fn replacing_and_clearing_the_user_half() {
        let (mut t, root) = HeapTables::new();
        let user = Flags {
            user: true,
            ..Flags::READ_ONLY
        };
        map(&mut t, root, 0x40_0000, 0x5000, PageSize::Small, user).unwrap();
        map(&mut t, root, KERNEL, 0x6000, PageSize::Small, Flags::DATA).unwrap();
        let rw = Flags {
            writable: true,
            ..user
        };
        assert_eq!(
            replace_small(&mut t, root, 0x40_0000, 0x7000, rw),
            Ok(0x5000)
        );
        assert_eq!(translate(&mut t, root, 0x40_0000).unwrap().phys, 0x7000);
        assert!(translate(&mut t, root, 0x40_0000).unwrap().flags.writable);
        assert!(replace_small(&mut t, root, 0x40_1000, 0x7000, rw).is_err());
        let (tables, leaves) = clear_user_half(&mut t, root);
        assert_eq!(leaves, alloc::vec![0x7000]);
        assert_eq!(tables.len(), 3); // PDPT, PD, PT
        assert_eq!(translate(&mut t, root, 0x40_0000), None);
        assert!(translate(&mut t, root, KERNEL).is_some());
        ensure_top_level(&mut t, root, 256..512).unwrap();
        assert!((256..512).all(|i| t.table(root)[i] & PRESENT != 0));
    }

    #[test]
    fn canonical_addresses() {
        assert!(is_canonical(0));
        assert!(is_canonical(0x0000_7FFF_FFFF_FFFF));
        assert!(!is_canonical(0x0000_8000_0000_0000));
        assert!(!is_canonical(0xFFFF_7FFF_FFFF_FFFF));
        assert!(is_canonical(0xFFFF_8000_0000_0000));
    }
}
