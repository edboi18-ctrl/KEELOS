//! Program loading (P1-T11, P3-T2): builds a new address space from an ELF
//! executable, its interpreter (`PT_INTERP`, the dynamic linker) if it
//! names one, and the initial stack. No `unsafe`: it uses only the checked
//! interfaces of `keel_hal::vm` and the parsers in `keel_core`.
//!
//! An interpreter is loaded as Linux's `load_elf_interp` does
//! (`fs/binfmt_elf.c` at v6.12): it is a separate position-independent
//! image, placed by the mmap allocator (below the randomized mmap base),
//! and the program starts at the interpreter's entry point. AT_BASE is the
//! interpreter's load address and AT_ENTRY the program's entry, so the
//! dynamic linker can find and run the program.

use alloc::sync::Arc;
use alloc::vec::Vec;

use keel_core::elf::{self, ElfError, Image, Kind};
use keel_core::errno::Errno;
use keel_core::exec::{self as stack, ExecError};
use keel_core::vfs::{Ino, ROOT};
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
    /// The interpreter could not be read (not found, not a regular file).
    Interpreter(Errno),
    /// The interpreter is not a usable ELF image (ELIBBAD, as Linux).
    BadInterpreter(ElfError),
}

impl LoadError {
    /// The errno execve(2) reports, as Linux's load_elf_binary
    /// (`fs/binfmt_elf.c` at v6.12): ENOEXEC for a program that is not a
    /// usable ELF executable, ELIBBAD for such an interpreter ("Accessing
    /// a corrupted shared library"), the lookup's error for a missing one,
    /// E2BIG for arguments that do not fit, ENOMEM otherwise.
    pub fn errno(self) -> Errno {
        match self {
            LoadError::Elf(_) => Errno::ENOEXEC,
            LoadError::BadInterpreter(_) => Errno::ELIBBAD,
            LoadError::Interpreter(errno) => errno,
            LoadError::Stack(ExecError::TooLarge) => Errno::E2BIG,
            LoadError::Stack(_) => Errno::EINVAL,
            LoadError::Memory(_) | LoadError::Copy => Errno::ENOMEM,
        }
    }
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
    /// Where the interpreter was loaded (AT_BASE), if there is one.
    pub interpreter_base: Option<u64>,
    /// The program's path as given to the loader (`/proc/<pid>/exe` and
    /// the first thread's name come from it; ADR 0024).
    pub path: Vec<u8>,
}

/// `AT_CLKTCK`: Linux reports CLOCKS_PER_SEC, which is USER_HZ, 100
/// (`include/asm-generic/param.h`).
const CLOCKS_PER_SEC: u64 = 100;

/// Copies `image`'s segments from `file` into `space`, moved by `bias`,
/// each with its own protection.
fn map_image(
    space: &Arc<AddressSpace>,
    image: &Image,
    file: &[u8],
    bias: u64,
) -> Result<(), LoadError> {
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
        with_address_space(space, || copy_to_user(segment.vaddr + bias, bytes))
            .map_err(|_| LoadError::Copy)?;
        space.protect(start, length, segment.prot)?;
    }
    Ok(())
}

/// Reads the interpreter at `path`, resolved from `root` (the process's
/// root: a compartment's program finds its dynamic linker in its own
/// tree). Only a regular file: anything else is EACCES, as execve(2) for
/// "the file or a script interpreter is not a regular file".
fn read_interpreter(root: Ino, path: &[u8]) -> Result<Arc<Vec<u8>>, LoadError> {
    crate::fs::with(|fs| {
        let ino = fs.lookup(root, root, path)?;
        if fs.kind(ino)? != keel_core::vfs::Kind::File {
            return Err(Errno::EACCES);
        }
        fs.contents(ino)
    })
    .map_err(LoadError::Interpreter)
}

/// Loads `file` into a new address space, finding any interpreter from the
/// filesystem root. On error nothing is left behind: the half-built
/// address space is dropped with all its frames.
pub fn load(file: &[u8], path: &[u8], argv: &[&[u8]], envp: &[&[u8]]) -> Result<Loaded, LoadError> {
    load_in(ROOT, file, path, argv, envp)
}

/// [`load`], with the interpreter looked up beneath `root`.
pub fn load_in(
    root: Ino,
    file: &[u8],
    path: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> Result<Loaded, LoadError> {
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
    map_image(&space, &image, file, bias)?;

    let stack_top = STACK_TOP - random::below(STACK_RANDOM_PAGES) * PAGE;
    space.map(
        Placement::Fixed(stack_top - STACK_SIZE),
        STACK_SIZE,
        Prot::READ_WRITE,
    )?;
    let lowest_stack = STACK_TOP - STACK_RANDOM_PAGES * PAGE - STACK_SIZE;
    let mmap_top = lowest_stack - MMAP_GAP - random::below(MMAP_RANDOM_PAGES) * PAGE;
    space.set_mmap_top(mmap_top)?;

    // The interpreter: a position-independent image with no interpreter of
    // its own (stricter than Linux, which also takes ET_EXEC and ignores a
    // PT_INTERP in it). Its whole span is reserved first, PROT_NONE, where
    // the mmap allocator puts it; the segments then replace their parts,
    // and the gaps between them stay reserved and inaccessible.
    let interpreter = match image.interpreter(file) {
        None => None,
        Some(interp_path) => {
            let interp_file = read_interpreter(root, interp_path)?;
            let interp = elf::parse(&interp_file).map_err(LoadError::BadInterpreter)?;
            if interp.interpreter.is_some() {
                return Err(LoadError::BadInterpreter(ElfError::Interpreter));
            }
            if interp.kind != Kind::Relocatable {
                return Err(LoadError::BadInterpreter(ElfError::BadInterpreter));
            }
            let (first, last) = interp.span();
            let base = space.map(Placement::Anywhere { hint: 0 }, last - first, Prot::NONE)?;
            let interp_bias = interp
                .bias_for_base(base)
                .map_err(LoadError::BadInterpreter)?;
            map_image(&space, &interp, &interp_file, interp_bias)?;
            Some((interp.entry + interp_bias, interp_bias))
        }
    };
    let entry = match interpreter {
        Some((interp_entry, _)) => interp_entry,
        None => image.entry + bias,
    };

    let mut random_bytes = [0u8; 16];
    let quality = random::fill(&mut random_bytes);
    // The entries Linux's create_elf_tables writes (`fs/binfmt_elf.c`),
    // in its order, except AT_SYSINFO_EHDR (no vDSO), AT_MINSIGSTKSZ,
    // AT_HWCAP2, AT_PLATFORM and the rseq entries, none of which musl
    // reads. AT_HWCAP is ELF_HWCAP, CPUID leaf 1 EDX
    // (`arch/x86/include/asm/elf.h`). User and group IDs are 0: Keel has
    // no users (SR-6), so AT_SECURE is 0 too.
    let hwcap = u64::from(keel_hal::arch::x86_64::cpu::cpuid(1, 0).3);
    let mut auxv: Vec<(u64, u64)> = Vec::new();
    auxv.extend([
        (stack::AT_HWCAP, hwcap),
        (stack::AT_PAGESZ, PAGE),
        (stack::AT_CLKTCK, CLOCKS_PER_SEC),
    ]);
    if let Some(phdr) = image.phdr_vaddr {
        auxv.push((stack::AT_PHDR, phdr + bias));
    }
    auxv.extend([
        (stack::AT_PHENT, elf::PHDR_SIZE as u64),
        (stack::AT_PHNUM, u64::from(image.phnum)),
        // The interpreter's load address; 0 without one, as Linux reports
        // for static executables.
        (stack::AT_BASE, interpreter.map_or(0, |(_, base)| base)),
        (stack::AT_FLAGS, 0),
        (stack::AT_ENTRY, image.entry + bias),
        (stack::AT_UID, 0),
        (stack::AT_EUID, 0),
        (stack::AT_GID, 0),
        (stack::AT_EGID, 0),
        (stack::AT_SECURE, 0),
    ]);
    let initial =
        stack::initial_stack(stack_top, ARG_LIMIT, path, argv, envp, &random_bytes, &auxv)?;
    with_address_space(&space, || copy_to_user(initial.rsp, &initial.bytes))
        .map_err(|_| LoadError::Copy)?;

    Ok(Loaded {
        space,
        entry,
        interpreter_base: interpreter.map(|(_, base)| base),
        path: path.to_vec(),
        rsp: initial.rsp,
        random: quality,
        brk_start: image.span().1 + bias + random::below(BRK_RANDOM_BYTES / PAGE) * PAGE,
        stack_top,
        mmap_top,
    })
}
