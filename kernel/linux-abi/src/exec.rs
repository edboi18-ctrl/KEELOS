//! Program loading (P1-T11): builds a new address space from a static ELF
//! executable and its initial stack. No `unsafe`: it uses only the
//! checked interfaces of `keel_hal::vm` and the parsers in `keel_core`.

use alloc::sync::Arc;
use alloc::vec::Vec;

use keel_core::elf::{self, ElfError, Kind};
use keel_core::exec::{self as stack, ExecError};
use keel_core::vm::{PAGE, Placement, Prot, USER_END};
use keel_hal::random::{self, Quality};
use keel_hal::vm::{AddressSpace, AsError, copy_to_user, with_address_space};

/// Lowest load address of a position-independent (`ET_DYN`) image; the
/// actual one adds a random number of pages (`MMAP_RANDOM_PAGES`). Linux's ELF_ET_DYN_BASE on x86-64 is
/// `DEFAULT_MAP_WINDOW / 3 * 2` (`arch/x86/include/asm/elf.h`) with
/// `DEFAULT_MAP_WINDOW = (1 << 47) - 4096` (`page_64_types.h`), which is
/// 0x5555_5555_4AAA; this is that value rounded down to a page.
pub const DYN_BASE: u64 = 0x5555_5555_4000;
/// Highest possible top of the initial stack: below the last user page,
/// which stays unmapped. The actual top is lower by a random number of
/// pages (SR-16).
pub const STACK_TOP: u64 = USER_END - PAGE;

/// Address-space randomization (P1-S5, SR-16), with Linux's ranges:
/// - stack top: up to STACK_RND_MASK = 0x3fffff pages lower (22 bits,
///   16 GiB; `arch/x86/include/asm/elf.h`, `randomize_stack_top` in
///   `mm/util.c`);
/// - mmap base and position-independent load bias: 28 bits of pages
///   (1 TiB; `ARCH_MMAP_RND_BITS_MIN` 28 for 64-bit in `arch/x86/Kconfig`,
///   `arch_rnd` in `arch/x86/mm/mmap.c`, `load_bias += arch_mmap_rnd()` in
///   `fs/binfmt_elf.c`);
/// - program break: a random page within 1 GiB above the image
///   (`arch_randomize_brk`, `arch/x86/kernel/process.c`).
///
/// The mmap base sits below the lowest possible stack, with Linux's
/// minimum gap of 128 MiB (`mmap_base`, `arch/x86/mm/mmap.c`).
pub const STACK_RANDOM_PAGES: u64 = 1 << 22;
pub const MMAP_RANDOM_PAGES: u64 = 1 << 28;
pub const BRK_RANDOM_BYTES: u64 = 1 << 30;
const MMAP_GAP: u64 = 128 << 20;
/// Size of the stack reservation (demand-paged; nothing is allocated until
/// touched), as Linux's default 8 MiB RLIMIT_STACK.
pub const STACK_SIZE: u64 = 8 << 20;
/// Largest argv + envp + auxv block (E2BIG beyond it).
pub const ARG_LIMIT: usize = 256 << 10;

/// Why a program could not be loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    Elf(ElfError),
    Stack(ExecError),
    Memory(AsError),
    /// Copying into the new address space failed.
    Copy,
}

impl From<ElfError> for LoadError {
    fn from(error: ElfError) -> Self {
        LoadError::Elf(error)
    }
}

impl From<ExecError> for LoadError {
    fn from(error: ExecError) -> Self {
        LoadError::Stack(error)
    }
}

impl From<AsError> for LoadError {
    fn from(error: AsError) -> Self {
        LoadError::Memory(error)
    }
}

/// A loaded program, ready to start at `entry` with RSP = `rsp`.
pub struct Loaded {
    pub space: Arc<AddressSpace>,
    pub entry: u64,
    pub rsp: u64,
    /// Quality of the AT_RANDOM bytes.
    pub random: Quality,
    /// First page after the image: where the program break starts (brk).
    pub brk_start: u64,
    /// The randomized stack top and mmap base chosen for this program.
    pub stack_top: u64,
    pub mmap_top: u64,
}

/// Loads `file` into a new address space. On error nothing is left
/// behind: the half-built address space is dropped with all its frames.
pub fn load(file: &[u8], path: &[u8], argv: &[&[u8]], envp: &[&[u8]]) -> Result<Loaded, LoadError> {
    let image = elf::parse(file)?;
    let bias = match image.kind {
        Kind::Fixed => {
            image.check_bias(0)?;
            0
        }
        // Checked subtraction: an image above the base is refused (C1).
        Kind::Relocatable => {
            image.bias_for_base(DYN_BASE + random::below(MMAP_RANDOM_PAGES) * PAGE)?
        }
    };

    let space = AddressSpace::new()?;
    for segment in &image.segments {
        let start = segment.page_start() + bias;
        let length = segment.page_end() - segment.page_start();
        space.map(Placement::Fixed(start), length, Prot::READ_WRITE)?;
        // Bounds were checked by the parser: offset + size <= file length.
        let from = segment.file_offset as usize;
        let bytes = &file[from..from + segment.file_size as usize];
        // The rest of each page (before vaddr, and from file_size to
        // mem_size: .bss) stays zero, because frames are zeroed when they
        // are allocated (SR-18).
        with_address_space(&space, || copy_to_user(segment.vaddr + bias, bytes))
            .map_err(|_| LoadError::Copy)?;
        space.protect(start, length, segment.prot)?;
    }

    let stack_top = STACK_TOP - random::below(STACK_RANDOM_PAGES) * PAGE;
    space.map(
        Placement::Fixed(stack_top - STACK_SIZE),
        STACK_SIZE,
        Prot::READ_WRITE,
    )?;
    let lowest_stack = STACK_TOP - STACK_RANDOM_PAGES * PAGE - STACK_SIZE;
    let mmap_top = lowest_stack - MMAP_GAP - random::below(MMAP_RANDOM_PAGES) * PAGE;
    space.set_mmap_top(mmap_top)?;
    let mut random_bytes = [0u8; 16];
    let quality = random::fill(&mut random_bytes);
    let mut auxv: Vec<(u64, u64)> = Vec::new();
    if let Some(phdr) = image.phdr_vaddr {
        auxv.push((stack::AT_PHDR, phdr + bias));
    }
    auxv.extend([
        (stack::AT_PHENT, elf::PHDR_SIZE as u64),
        (stack::AT_PHNUM, u64::from(image.phnum)),
        (stack::AT_PAGESZ, PAGE),
        // No interpreter: AT_BASE is 0, as Linux reports for static
        // executables.
        (stack::AT_BASE, 0),
        (stack::AT_FLAGS, 0),
        (stack::AT_ENTRY, image.entry + bias),
        (stack::AT_SECURE, 0),
    ]);
    let initial =
        stack::initial_stack(stack_top, ARG_LIMIT, path, argv, envp, &random_bytes, &auxv)?;
    with_address_space(&space, || copy_to_user(initial.rsp, &initial.bytes))
        .map_err(|_| LoadError::Copy)?;

    Ok(Loaded {
        space,
        entry: image.entry + bias,
        rsp: initial.rsp,
        random: quality,
        brk_start: image.span().1 + bias + random::below(BRK_RANDOM_BYTES / PAGE) * PAGE,
        stack_top,
        mmap_top,
    })
}
