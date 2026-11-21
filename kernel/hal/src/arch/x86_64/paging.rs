//! The kernel's own page tables (P1-T4; SR-12, SR-13, SR-17).
//!
//! `init` builds a fresh PML4 that maps:
//!  - the kernel image with per-segment rights: text read+execute, rodata
//!    read-only, data and bss read+write and not executable (W^X, SR-12),
//!    leaving the IST guard pages unmapped (SR-17);
//!  - the higher-half direct map (HHDM) over the same memory-map regions
//!    Limine maps for base revision 4 and later (PROTOCOL.md, "Memory
//!    Layout at Entry"), read+write and never executable; the framebuffer
//!    write-combining, everything else write-back ("Caching");
//!  - nothing in the lower half.
//!
//! Hardening beyond Limine's layout: the kernel image's own physical pages
//! are left out of the direct map, so kernel text and rodata cannot be
//! written through a second, writable alias.
//!
//! It then switches CR3 and turns on the CPU protections the processor
//! reports: EFER.NXE, CR0.WP, CR4.SMEP, CR4.SMAP and CR4.UMIP (SR-13).
//!
//! The table logic lives in `keel_core::paging` (safe Rust, host tested);
//! this module supplies table memory and the register writes.

use core::sync::atomic::{AtomicU64, Ordering};

use keel_core::frame::Frame;
use keel_core::paging::{self, Flags, PageSize, TableAccess, Translation, WalkSummary};

use super::cpu::{self, Features};
use super::gdt;
use crate::boot::{self, RegionKind};
use crate::memory;

const PAGE: u64 = 4096;

unsafe extern "C" {
    // Defined in kernel/keel-kernel/linker.ld. Only their addresses are
    // used; the "objects" are never read.
    static __kernel_start: u8;
    static __rodata_start: u8;
    static __data_start: u8;
    static __kernel_end: u8;
}

/// Page tables built from frames of the frame allocator, reached through
/// the direct map.
pub(crate) struct DirectMapTables;

impl TableAccess for DirectMapTables {
    fn allocate_table(&mut self) -> Option<Frame> {
        // Zeroed, so every entry starts not-present.
        memory::allocate_zeroed()
    }

    fn table(&mut self, frame: Frame) -> &mut [u64; 512] {
        // SAFETY: `keel_core::paging` only passes frames that came from
        // `allocate_table` above (or the root, which did too); they belong
        // to the page tables alone, are mapped read-write in the direct map
        // (usable RAM), and are 4096-byte aligned, which satisfies the
        // alignment of `[u64; 512]`. The `&mut self` receiver means at most
        // one such reference exists at a time.
        unsafe { &mut *memory::frame_pointer(frame).cast::<[u64; 512]>() }
    }
}

/// Physical address of the active PML4, or 0 before `init`.
static ROOT: AtomicU64 = AtomicU64::new(0);

/// Serialises every change to, and walk of, the kernel's page tables after
/// `init`. Lock order: see docs/locking.md.
static TABLES: crate::sync::IrqMutex<()> = crate::sync::IrqMutex::new(());

/// What `init` set up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagingReport {
    pub features: Features,
    pub summary: WalkSummary,
}

/// Why `init` failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagingError {
    AlreadyInitialised,
    /// The CPU lacks the execute-disable bit, without which W^X cannot be
    /// enforced (SR-12). Every x86-64 CPU Keel targets has it.
    NoExecuteDisable,
    NoBootInformation,
    Map(paging::MapError),
}

impl From<paging::MapError> for PagingError {
    fn from(error: paging::MapError) -> Self {
        PagingError::Map(error)
    }
}

fn kernel_layout() -> [u64; 4] {
    [
        &raw const __kernel_start as u64,
        &raw const __rodata_start as u64,
        &raw const __data_start as u64,
        &raw const __kernel_end as u64,
    ]
}

/// Builds the kernel's page tables, switches to them, and enables the
/// CPU protections. Call once, after `memory::init`, with interrupts off.
pub fn init() -> Result<PagingReport, PagingError> {
    if ROOT.load(Ordering::Acquire) != 0 {
        return Err(PagingError::AlreadyInitialised);
    }
    let features = cpu::features();
    if !features.nx {
        return Err(PagingError::NoExecuteDisable);
    }
    let hhdm = boot::hhdm_offset().ok_or(PagingError::NoBootInformation)?;
    let kernel = boot::kernel_address().ok_or(PagingError::NoBootInformation)?;

    let mut tables = DirectMapTables;
    let root = tables
        .allocate_table()
        .ok_or(paging::MapError::OutOfMemory)?;

    // Kernel image, one 4 KiB page at a time, with per-segment rights. The
    // image is physically contiguous (PROTOCOL.md, "Memory Layout at
    // Entry"), so physical = virtual - virtual_base + physical_base.
    let [start, rodata, data, end] = kernel_layout();
    let guards = gdt::ist_guard_pages();
    let to_phys = |virt: u64| virt - kernel.virtual_base + kernel.physical_base;
    let mut virt = start;
    while virt < end {
        let flags = if virt < rodata {
            Flags::TEXT
        } else if virt < data {
            Flags::READ_ONLY
        } else {
            Flags::DATA
        };
        if !guards.contains(&virt) {
            paging::map(
                &mut tables,
                root,
                virt,
                to_phys(virt),
                PageSize::Small,
                flags,
            )?;
        }
        virt += PAGE;
    }
    let image_phys = to_phys(start)..to_phys(end);

    // Direct map. Framebuffer regions go first so that write-combining
    // wins where a firmware region overlaps them.
    let wc = Flags {
        write_combining: true,
        ..Flags::DATA
    };
    let regions = || {
        boot::memory_map().filter(|r| {
            matches!(
                r.kind,
                RegionKind::Usable
                    | RegionKind::BootloaderReclaimable
                    | RegionKind::ExecutableAndModules
                    | RegionKind::Framebuffer
                    | RegionKind::ReservedMapped
                    | RegionKind::AcpiReclaimable
                    | RegionKind::AcpiNvs
            )
        })
    };
    let framebuffers = regions().filter(|r| r.kind == RegionKind::Framebuffer);
    let others = regions().filter(|r| r.kind != RegionKind::Framebuffer);
    for (region, flags, allow_large) in framebuffers
        .map(|r| (r, wc, false))
        .chain(others.map(|r| (r, Flags::DATA, true)))
    {
        // Limine rounds unaligned regions outward to whole pages when it
        // builds the direct map ("Memory Layout at Entry"); so does Keel.
        let base = region.base & !(PAGE - 1);
        let top = region
            .base
            .saturating_add(region.length)
            .next_multiple_of(PAGE);
        // Leave the kernel image out (see the module documentation).
        for (from, to) in [
            (base, top.min(image_phys.start).max(base)),
            (base.max(image_phys.end).min(top), top),
        ] {
            if from < to {
                paging::map_range_skipping_present(
                    &mut tables,
                    root,
                    hhdm + from,
                    from,
                    to - from,
                    flags,
                    allow_large,
                )?;
            }
        }
    }

    // Create every upper-half top-level entry now. User address spaces
    // copy these 256 entries, so any kernel mapping made later (heap,
    // stacks, devices) lands in shared lower-level tables and is visible
    // in every address space.
    paging::ensure_top_level(&mut tables, root, 256..512)?;

    let summary = paging::walk(&mut tables, root, |_, _| {});

    // SAFETY: (1) EFER.NXE is supported (checked above) and must be on
    // before CR3 points at tables that use the XD bit, which is reserved
    // while NXE is 0. (2) The new tables map the code running now (kernel
    // text), its stack (Limine's stack is in bootloader-reclaimable memory,
    // which the direct map covers), the GDT, IDT, TSS and IST stacks
    // (kernel data/bss), the framebuffer and all boot information. (3) CR0
    // keeps PE and PG; WP only adds checks. (4) Only CR4 bits the CPU
    // reports are set, and nothing is mapped in the lower half, so SMEP and
    // SMAP cannot break any access the kernel makes. Interrupts are off
    // (caller contract), so nothing runs between the steps.
    unsafe {
        let efer = cpu::rdmsr(cpu::IA32_EFER);
        cpu::wrmsr(cpu::IA32_EFER, efer | cpu::EFER_NXE);
        cpu::write_cr0(cpu::read_cr0() | cpu::CR0_WP);
        cpu::write_cr3(root.address());
        let mut cr4 = cpu::read_cr4();
        if features.smep {
            cr4 |= cpu::CR4_SMEP;
        }
        if features.smap {
            cr4 |= cpu::CR4_SMAP;
        }
        if features.umip {
            cr4 |= cpu::CR4_UMIP;
        }
        cpu::write_cr4(cr4);
    }
    ROOT.store(root.address(), Ordering::Release);
    crate::vm::set_smap_enabled(features.smap);
    Ok(PagingReport { features, summary })
}

/// The kernel's top-level table.
pub fn kernel_root() -> Option<Frame> {
    let root = ROOT.load(Ordering::Acquire);
    (root != 0).then(|| Frame::containing(root))
}

/// Looks up `virt` in the kernel's page tables.
pub fn translate(virt: u64) -> Option<Translation> {
    let root = ROOT.load(Ordering::Acquire);
    if root == 0 {
        return None;
    }
    let _guard = TABLES.lock();
    paging::translate(&mut DirectMapTables, Frame::containing(root), virt)
}

/// Walks the kernel's page tables (the page-table self-test).
pub fn walk() -> Option<WalkSummary> {
    let root = ROOT.load(Ordering::Acquire);
    if root == 0 {
        return None;
    }
    let _guard = TABLES.lock();
    Some(paging::walk(
        &mut DirectMapTables,
        Frame::containing(root),
        |_, _| {},
    ))
}

/// Start of the kernel-heap virtual region. It lies outside both the
/// direct map (which starts at Limine's HHDM offset and spans physical
/// memory, at most 1 TiB here) and the kernel image (top 2 GiB).
pub const KERNEL_HEAP_BASE: u64 = 0xffff_c000_0000_0000;
/// Size of the kernel-heap virtual region (64 GiB).
pub const KERNEL_HEAP_SIZE: u64 = 64 << 30;

/// Start of the region where device registers are mapped.
pub const MMIO_BASE: u64 = 0xffff_d000_0000_0000;
const MMIO_SIZE: u64 = 1 << 30;
static MMIO_NEXT: AtomicU64 = AtomicU64::new(MMIO_BASE);

/// Why `map_mmio` refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioError {
    /// Paging is not set up yet.
    NotReady,
    /// The range is empty, overflows, or exhausts the MMIO region.
    BadRange,
    /// The range overlaps RAM, the kernel, or boot data. Firmware tables
    /// are untrusted (SR-20); a device address pointing into RAM would
    /// create an uncached alias of memory the kernel uses.
    OverlapsMemory,
    Map(paging::MapError),
}

/// Maps the physical device registers `[phys, phys + length)` uncached,
/// read+write and not executable, and returns the virtual address that
/// corresponds to `phys`.
pub fn map_mmio(phys: u64, length: u64) -> Result<u64, MmioError> {
    let root = ROOT.load(Ordering::Acquire);
    if root == 0 {
        return Err(MmioError::NotReady);
    }
    let end = phys
        .checked_add(length)
        .filter(|_| length > 0)
        .ok_or(MmioError::BadRange)?;
    let first = phys & !(PAGE - 1);
    let last = end.next_multiple_of(PAGE);
    let overlaps = boot::memory_map().any(|r| {
        let is_memory = matches!(
            r.kind,
            RegionKind::Usable
                | RegionKind::BootloaderReclaimable
                | RegionKind::ExecutableAndModules
                | RegionKind::AcpiReclaimable
                | RegionKind::AcpiNvs
                | RegionKind::Framebuffer
        );
        is_memory && r.base < last && first < r.base.saturating_add(r.length)
    });
    if overlaps {
        return Err(MmioError::OverlapsMemory);
    }
    let pages = (last - first) / PAGE;
    let size = pages * PAGE;
    // One unmapped page between mappings.
    let virt = MMIO_NEXT.fetch_add(size + PAGE, Ordering::AcqRel);
    if virt + size > MMIO_BASE + MMIO_SIZE {
        return Err(MmioError::BadRange);
    }
    let flags = Flags {
        uncached: true,
        ..Flags::DATA
    };
    let _guard = TABLES.lock();
    for i in 0..pages {
        paging::map(
            &mut DirectMapTables,
            Frame::containing(root),
            virt + i * PAGE,
            first + i * PAGE,
            PageSize::Small,
            flags,
        )
        .map_err(MmioError::Map)?;
    }
    Ok(virt + (phys - first))
}

/// Maps fresh zeroed frames, read+write and not executable, at the 4 KiB
/// pages `[virt, virt + pages * 4096)` inside the kernel-heap region.
/// On failure nothing stays mapped.
pub fn map_heap_pages(virt: u64, pages: u64) -> Result<(), paging::MapError> {
    map_fresh_pages(
        virt,
        pages,
        KERNEL_HEAP_BASE..KERNEL_HEAP_BASE + KERNEL_HEAP_SIZE,
    )
}

/// Maps `pages` fresh zeroed frames RW+NX at `virt`, which must lie with
/// its whole length inside `region`. On failure nothing stays mapped.
fn map_fresh_pages(
    virt: u64,
    pages: u64,
    region: core::ops::Range<u64>,
) -> Result<(), paging::MapError> {
    let in_region = virt >= region.start
        && pages
            .checked_mul(PAGE)
            .and_then(|len| virt.checked_add(len))
            .is_some_and(|end| end <= region.end);
    let root = ROOT.load(Ordering::Acquire);
    // Before `init` there are no kernel tables to map into.
    if !in_region || root == 0 {
        return Err(paging::MapError::Misaligned);
    }
    let root = Frame::containing(root);
    let _guard = TABLES.lock();
    for i in 0..pages {
        let page = virt + i * PAGE;
        let result = memory::allocate_zeroed()
            .ok_or(paging::MapError::OutOfMemory)
            .and_then(|frame| {
                paging::map(
                    &mut DirectMapTables,
                    root,
                    page,
                    frame.address(),
                    PageSize::Small,
                    Flags::DATA,
                )
                .inspect_err(|_| {
                    let _ = memory::release(frame);
                })
            });
        if let Err(error) = result {
            for j in 0..i {
                unmap_locked(root, virt + j * PAGE);
            }
            return Err(error);
        }
    }
    Ok(())
}

/// Start of the kernel-stack region.
pub const KERNEL_STACKS_BASE: u64 = 0xffff_e000_0000_0000;
const KERNEL_STACKS_SIZE: u64 = 64 << 30;
static NEXT_STACK: AtomicU64 = AtomicU64::new(KERNEL_STACKS_BASE);

/// A kernel stack: mapped pages with an unmapped guard page directly
/// below them (SR-17). Overflowing it faults on the guard page; the fault
/// cannot be delivered on the exhausted stack, so it becomes a double
/// fault, which runs on its own IST stack and reports cleanly.
#[derive(Debug)]
pub struct KernelStack {
    /// Lowest mapped address.
    pub base: u64,
    /// One past the highest mapped address; 16-byte aligned.
    pub top: u64,
}

impl KernelStack {
    /// The unmapped guard page below the stack.
    pub fn guard_page(&self) -> u64 {
        self.base - PAGE
    }
}

/// Allocates a kernel stack of `pages` pages. Virtual space is not reused
/// yet (64 GiB is far more than Phase 1 needs); frames are.
pub fn map_kernel_stack(pages: u64) -> Option<KernelStack> {
    let slot = pages.checked_add(1)?.checked_mul(PAGE)?;
    let guard = NEXT_STACK.fetch_add(slot, Ordering::AcqRel);
    let base = guard + PAGE;
    map_fresh_pages(
        base,
        pages,
        KERNEL_STACKS_BASE..KERNEL_STACKS_BASE + KERNEL_STACKS_SIZE,
    )
    .ok()?;
    Some(KernelStack {
        base,
        top: base + pages * PAGE,
    })
}

/// Unmaps a kernel stack and frees its frames. The caller must not be
/// running on it.
pub fn unmap_kernel_stack(stack: KernelStack) {
    let root = ROOT.load(Ordering::Acquire);
    if root == 0 {
        return;
    }
    let root = Frame::containing(root);
    let _guard = TABLES.lock();
    let mut page = stack.base;
    while page < stack.top {
        unmap_locked(root, page);
        page += PAGE;
    }
}

/// Whether `address` is in the guard page of some kernel stack.
pub fn is_kernel_stack_guard(address: u64) -> bool {
    (KERNEL_STACKS_BASE..NEXT_STACK.load(Ordering::Acquire)).contains(&address)
        && translate(address).is_none()
}

/// Unmaps heap pages mapped by `map_heap_pages` and frees their frames.
pub fn unmap_heap_pages(virt: u64, pages: u64) {
    let root = ROOT.load(Ordering::Acquire);
    if root == 0 {
        return;
    }
    let root = Frame::containing(root);
    let _guard = TABLES.lock();
    for i in 0..pages {
        let page = virt + i * PAGE;
        if (KERNEL_HEAP_BASE..KERNEL_HEAP_BASE + KERNEL_HEAP_SIZE).contains(&page) {
            unmap_locked(root, page);
        }
    }
}

fn unmap_locked(root: Frame, page: u64) {
    if let Some(phys) = paging::unmap_small(&mut DirectMapTables, root, page) {
        cpu::invalidate_page(page);
        let _ = memory::release(Frame::containing(phys));
    }
}

/// The kernel image's virtual layout: start, rodata, data, end.
pub fn kernel_segments() -> [u64; 4] {
    kernel_layout()
}
