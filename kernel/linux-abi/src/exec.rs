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

/// Load address of the lowest page of a position-independent (`ET_DYN`)
/// image until ASLR (P1-S5). Linux's ELF_ET_DYN_BASE on x86-64 is
/// `DEFAULT_MAP_WINDOW / 3 * 2` (`arch/x86/include/asm/elf.h`) with
/// `DEFAULT_MAP_WINDOW = (1 << 47) - 4096` (`page_64_types.h`), which is
/// 0x5555_5555_4AAA; this is that value rounded down to a page.
pub const DYN_BASE: u64 = 0x5555_5555_4000;
/// Top of the initial stack: the highest 16-byte boundary below the last
/// user page, which stays unmapped.
pub const STACK_TOP: u64 = USER_END - PAGE;
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
}

/// Loads `file` into a new address space. On error nothing is left
/// behind: the half-built address space is dropped with all its frames.
pub fn load(file: &[u8], path: &[u8], argv: &[&[u8]], envp: &[&[u8]]) -> Result<Loaded, LoadError> {
    let image = elf::parse(file)?;
    let bias = match image.kind {
        Kind::Fixed => 0,
        Kind::Relocatable => DYN_BASE - image.span().0,
    };
    image.check_bias(bias)?;

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

    space.map(
        Placement::Fixed(STACK_TOP - STACK_SIZE),
        STACK_SIZE,
        Prot::READ_WRITE,
    )?;
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
        stack::initial_stack(STACK_TOP, ARG_LIMIT, path, argv, envp, &random_bytes, &auxv)?;
    with_address_space(&space, || copy_to_user(initial.rsp, &initial.bytes))
        .map_err(|_| LoadError::Copy)?;

    Ok(Loaded {
        space,
        entry: image.entry + bias,
        rsp: initial.rsp,
        random: quality,
        brk_start: image.span().1 + bias,
    })
}
