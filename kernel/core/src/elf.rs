//! ELF64 executable parser for the program loader (P1-T11).
//!
//! The input is an untrusted file, so every offset and size is checked
//! against the file length with checked arithmetic, and anything Keel does
//! not support is refused as a whole (SR-10: fail closed).
//!
//! Layouts and constants: System V gABI, "ELF Header" and "Program Header"
//! chapters; Linux `include/uapi/linux/elf.h` and `elf-em.h` at v6.12
//! (`Elf64_Ehdr`, `Elf64_Phdr`, `PT_*`, `PF_*`, `ET_*`, `EM_X86_64` = 62).
//!
//! Accepted: little-endian ELF64 for x86-64, `ET_EXEC`, or `ET_DYN` with no
//! `PT_INTERP` (static PIE; the caller picks the load bias). Refused:
//! `PT_INTERP` (dynamic linking arrives in Phase 3, P3-T2), any segment
//! that is both writable and executable, and an executable stack request
//! (`PT_GNU_STACK` with `PF_X`), both by SR-12.

use alloc::vec::Vec;

use crate::vm::{PAGE, Prot, USER_END, USER_START};

/// `e_ident` magic, class, data encoding and version (gABI "ELF
/// Identification"; Linux `elf.h`: ELFCLASS64 = 2, ELFDATA2LSB = 1,
/// EV_CURRENT = 1).
const MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;

/// Sizes of `Elf64_Ehdr` and `Elf64_Phdr`.
pub const EHDR_SIZE: usize = 64;
pub const PHDR_SIZE: usize = 56;

/// Largest program-header table accepted: one page, as Linux
/// (`load_elf_phdrs` in `fs/binfmt_elf.c` refuses `size > ELF_MIN_ALIGN`).
const MAX_PHDR_TABLE: usize = 4096;

pub const PT_LOAD: u32 = 1;
pub const PT_INTERP: u32 = 3;
pub const PT_PHDR: u32 = 6;
/// `PT_LOOS + 0x474e551` (Linux `elf.h`).
pub const PT_GNU_STACK: u32 = 0x6474_e551;

pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

/// Why a file was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// Shorter than the ELF header, or a table runs past the end.
    Truncated,
    /// Not an ELF file.
    BadMagic,
    /// Not little-endian ELF64 version 1 for x86-64.
    WrongFormat,
    /// Not `ET_EXEC` or `ET_DYN`.
    WrongType,
    /// Header or program-header sizes are not the ELF64 ones, or the table
    /// is empty or larger than one page.
    BadHeaderTable,
    /// Needs an interpreter (dynamic linking); not supported yet.
    Interpreter,
    /// A segment's file bytes lie outside the file, or exceed its memory
    /// size.
    BadSegment,
    /// `p_vaddr` and `p_offset` differ modulo the page size, so the file
    /// cannot be mapped page by page.
    Misaligned,
    /// A segment is writable and executable (SR-12).
    WritableAndExecutable,
    /// The file asks for an executable stack (SR-12).
    ExecutableStack,
    /// Loadable segments are out of order or share a page.
    Overlap,
    /// A segment lies outside the user half, or its end overflows.
    OutOfRange,
    /// No loadable segment with a non-zero memory size.
    NoSegments,
    /// The entry point is not inside an executable segment.
    BadEntry,
}

/// What kind of executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Fixed addresses (`ET_EXEC`); load bias 0.
    Fixed,
    /// Position-independent (`ET_DYN`); the loader chooses the bias.
    Relocatable,
}

/// One `PT_LOAD` segment, with addresses before the load bias.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub vaddr: u64,
    pub mem_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub prot: Prot,
}

impl Segment {
    /// First page of the segment.
    pub fn page_start(&self) -> u64 {
        self.vaddr & !(PAGE - 1)
    }

    /// End of the segment's last page (exclusive). Checked at parse time
    /// not to overflow.
    pub fn page_end(&self) -> u64 {
        (self.vaddr + self.mem_size).next_multiple_of(PAGE)
    }
}

/// A parsed executable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub kind: Kind,
    /// Entry point, before the load bias.
    pub entry: u64,
    /// Loadable segments in ascending address order, none sharing a page.
    pub segments: Vec<Segment>,
    /// Address of the program-header table in the loaded image, before the
    /// load bias, if a loadable segment contains it (for `AT_PHDR`).
    pub phdr_vaddr: Option<u64>,
    /// Number of program headers (`AT_PHNUM`).
    pub phnum: u16,
}

impl Image {
    /// First page and end of the last page of the loaded image, before the
    /// load bias.
    pub fn span(&self) -> (u64, u64) {
        let first = self.segments.first().map_or(0, Segment::page_start);
        let last = self.segments.last().map_or(0, Segment::page_end);
        (first, last)
    }

    /// The bias that moves a relocatable image's first page to `base`,
    /// checked like any bias. An image whose first page lies above `base`
    /// needs a negative bias, which is refused rather than computed with an
    /// unchecked subtraction (that panicked the kernel: third Phase 1 audit,
    /// C1).
    pub fn bias_for_base(&self, base: u64) -> Result<u64, ElfError> {
        let bias = base
            .checked_sub(self.span().0)
            .ok_or(ElfError::OutOfRange)?;
        self.check_bias(bias)?;
        Ok(bias)
    }

    /// Checks that the image, moved by `bias`, lies inside the user half.
    pub fn check_bias(&self, bias: u64) -> Result<(), ElfError> {
        let (first, last) = self.span();
        let start = first.checked_add(bias).ok_or(ElfError::OutOfRange)?;
        let end = last.checked_add(bias).ok_or(ElfError::OutOfRange)?;
        if start < USER_START || end > USER_END {
            return Err(ElfError::OutOfRange);
        }
        Ok(())
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, ElfError> {
    let end = at.checked_add(2).ok_or(ElfError::Truncated)?;
    let field = bytes.get(at..end).ok_or(ElfError::Truncated)?;
    Ok(u16::from_le_bytes([field[0], field[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, ElfError> {
    let end = at.checked_add(4).ok_or(ElfError::Truncated)?;
    let field = bytes.get(at..end).ok_or(ElfError::Truncated)?;
    Ok(u32::from_le_bytes(
        field.try_into().map_err(|_| ElfError::Truncated)?,
    ))
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64, ElfError> {
    let end = at.checked_add(8).ok_or(ElfError::Truncated)?;
    let field = bytes.get(at..end).ok_or(ElfError::Truncated)?;
    Ok(u64::from_le_bytes(
        field.try_into().map_err(|_| ElfError::Truncated)?,
    ))
}

/// Parses and validates an executable.
pub fn parse(bytes: &[u8]) -> Result<Image, ElfError> {
    if bytes.len() < EHDR_SIZE {
        return Err(ElfError::Truncated);
    }
    if bytes[..4] != MAGIC {
        return Err(ElfError::BadMagic);
    }
    // e_ident[EI_CLASS], [EI_DATA], [EI_VERSION] at 4, 5, 6.
    if bytes[4] != ELFCLASS64 || bytes[5] != ELFDATA2LSB || bytes[6] != EV_CURRENT {
        return Err(ElfError::WrongFormat);
    }
    // Elf64_Ehdr: e_type 16, e_machine 18, e_version 20, e_entry 24,
    // e_phoff 32, e_ehsize 52, e_phentsize 54, e_phnum 56.
    let kind = match u16_at(bytes, 16)? {
        ET_EXEC => Kind::Fixed,
        ET_DYN => Kind::Relocatable,
        _ => return Err(ElfError::WrongType),
    };
    if u16_at(bytes, 18)? != EM_X86_64 || u32_at(bytes, 20)? != u32::from(EV_CURRENT) {
        return Err(ElfError::WrongFormat);
    }
    let entry = u64_at(bytes, 24)?;
    let phoff = u64_at(bytes, 32)?;
    let ehsize = u16_at(bytes, 52)?;
    let phentsize = u16_at(bytes, 54)?;
    let phnum = u16_at(bytes, 56)?;
    if usize::from(ehsize) != EHDR_SIZE || usize::from(phentsize) != PHDR_SIZE {
        return Err(ElfError::BadHeaderTable);
    }
    let table_size = usize::from(phnum) * PHDR_SIZE;
    if table_size == 0 || table_size > MAX_PHDR_TABLE {
        return Err(ElfError::BadHeaderTable);
    }
    let table_start = usize::try_from(phoff).map_err(|_| ElfError::Truncated)?;
    let table_end = table_start
        .checked_add(table_size)
        .ok_or(ElfError::Truncated)?;
    let table = bytes
        .get(table_start..table_end)
        .ok_or(ElfError::Truncated)?;

    let mut segments: Vec<Segment> = Vec::new();
    let mut phdr_segment: Option<u64> = None;
    for header in table.as_chunks::<PHDR_SIZE>().0 {
        // Elf64_Phdr: p_type 0, p_flags 4, p_offset 8, p_vaddr 16,
        // p_filesz 32, p_memsz 40.
        let p_type = u32_at(header, 0)?;
        let flags = u32_at(header, 4)?;
        match p_type {
            PT_INTERP => return Err(ElfError::Interpreter),
            PT_GNU_STACK if flags & PF_X != 0 => return Err(ElfError::ExecutableStack),
            PT_PHDR => phdr_segment = Some(u64_at(header, 16)?),
            PT_LOAD => {
                let segment = Segment {
                    vaddr: u64_at(header, 16)?,
                    mem_size: u64_at(header, 40)?,
                    file_offset: u64_at(header, 8)?,
                    file_size: u64_at(header, 32)?,
                    prot: Prot {
                        read: flags & PF_R != 0,
                        write: flags & PF_W != 0,
                        exec: flags & PF_X != 0,
                    },
                };
                if segment.mem_size == 0 {
                    continue;
                }
                check_segment(&segment, bytes.len())?;
                if let Some(previous) = segments.last()
                    && segment.page_start() < previous.page_end()
                {
                    return Err(ElfError::Overlap);
                }
                segments.push(segment);
            }
            _ => {}
        }
    }
    if segments.is_empty() {
        return Err(ElfError::NoSegments);
    }

    let image_entry_ok = segments
        .iter()
        .any(|s| s.prot.exec && entry >= s.vaddr && entry - s.vaddr < s.mem_size);
    if !image_entry_ok {
        return Err(ElfError::BadEntry);
    }

    // AT_PHDR: the table's address in memory. PT_PHDR names it directly;
    // otherwise find the loadable segment whose file bytes contain it.
    let table_size = table_size as u64;
    let contains = |s: &Segment, vaddr: u64| {
        vaddr >= s.vaddr
            && vaddr - s.vaddr <= s.file_size
            && s.file_size - (vaddr - s.vaddr) >= table_size
    };
    let phdr_vaddr = match phdr_segment {
        Some(vaddr) => segments.iter().any(|s| contains(s, vaddr)).then_some(vaddr),
        None => segments.iter().find_map(|s| {
            let within = phoff.checked_sub(s.file_offset)?;
            let vaddr = s.vaddr.checked_add(within)?;
            contains(s, vaddr).then_some(vaddr)
        }),
    };

    let image = Image {
        kind,
        entry,
        segments,
        phdr_vaddr,
        phnum,
    };
    if kind == Kind::Fixed {
        image.check_bias(0)?;
    }
    Ok(image)
}

fn check_segment(segment: &Segment, file_len: usize) -> Result<(), ElfError> {
    if segment.prot.write && segment.prot.exec {
        return Err(ElfError::WritableAndExecutable);
    }
    if segment.file_size > segment.mem_size {
        return Err(ElfError::BadSegment);
    }
    let file_end = segment
        .file_offset
        .checked_add(segment.file_size)
        .ok_or(ElfError::BadSegment)?;
    if file_end > file_len as u64 {
        return Err(ElfError::BadSegment);
    }
    if segment.vaddr % PAGE != segment.file_offset % PAGE {
        return Err(ElfError::Misaligned);
    }
    // The end, rounded up to a page, must not overflow and must stay in
    // the lower half even before any bias; `check_bias` does the rest.
    let end = segment
        .vaddr
        .checked_add(segment.mem_size)
        .ok_or(ElfError::OutOfRange)?;
    if end.next_multiple_of(PAGE) > USER_END {
        return Err(ElfError::OutOfRange);
    }
    Ok(())
}

/// Builders for test files, shared with the in-kernel self-tests.
pub mod build {
    use alloc::vec::Vec;

    use super::{EHDR_SIZE, PHDR_SIZE};

    /// One program header for [`file`].
    #[derive(Clone, Copy, Debug)]
    pub struct Phdr {
        pub p_type: u32,
        pub flags: u32,
        pub offset: u64,
        pub vaddr: u64,
        pub file_size: u64,
        pub mem_size: u64,
    }

    /// An ELF64 x86-64 file of type `e_type` with `phdrs` right after the
    /// header, padded with zeros to `len` bytes.
    pub fn file(e_type: u16, entry: u64, phdrs: &[Phdr], len: usize) -> Vec<u8> {
        let mut out = alloc::vec![0u8; len.max(EHDR_SIZE + phdrs.len() * PHDR_SIZE)];
        out[..4].copy_from_slice(&super::MAGIC);
        out[4] = super::ELFCLASS64;
        out[5] = super::ELFDATA2LSB;
        out[6] = super::EV_CURRENT;
        out[16..18].copy_from_slice(&e_type.to_le_bytes());
        out[18..20].copy_from_slice(&super::EM_X86_64.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[24..32].copy_from_slice(&entry.to_le_bytes());
        out[32..40].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes());
        out[52..54].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
        out[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        out[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
        for (i, p) in phdrs.iter().enumerate() {
            let at = EHDR_SIZE + i * PHDR_SIZE;
            out[at..at + 4].copy_from_slice(&p.p_type.to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&p.flags.to_le_bytes());
            out[at + 8..at + 16].copy_from_slice(&p.offset.to_le_bytes());
            out[at + 16..at + 24].copy_from_slice(&p.vaddr.to_le_bytes());
            out[at + 24..at + 32].copy_from_slice(&p.vaddr.to_le_bytes());
            out[at + 32..at + 40].copy_from_slice(&p.file_size.to_le_bytes());
            out[at + 40..at + 48].copy_from_slice(&p.mem_size.to_le_bytes());
            out[at + 48..at + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::build::{Phdr, file};
    use super::*;

    const BASE: u64 = 0x40_0000;

    fn text(offset: u64, vaddr: u64, size: u64) -> Phdr {
        Phdr {
            p_type: PT_LOAD,
            flags: PF_R | PF_X,
            offset,
            vaddr,
            file_size: size,
            mem_size: size,
        }
    }

    fn data(offset: u64, vaddr: u64, file_size: u64, mem_size: u64) -> Phdr {
        Phdr {
            p_type: PT_LOAD,
            flags: PF_R | PF_W,
            offset,
            vaddr,
            file_size,
            mem_size,
        }
    }

    fn good() -> Vec<u8> {
        file(
            ET_EXEC,
            BASE + 0x100,
            &[
                text(0, BASE, 0x800),
                data(0x800, BASE + 0x1800, 0x100, 0x3000),
            ],
            0x1000,
        )
    }

    #[test]
    fn parses_a_static_executable() {
        let image = parse(&good()).unwrap();
        assert_eq!(image.kind, Kind::Fixed);
        assert_eq!(image.entry, BASE + 0x100);
        assert_eq!(image.phnum, 2);
        assert_eq!(image.segments.len(), 2);
        assert!(image.segments[0].prot.exec && !image.segments[0].prot.write);
        assert!(image.segments[1].prot.write && !image.segments[1].prot.exec);
        // The table at file offset 64 lies in the first segment.
        assert_eq!(image.phdr_vaddr, Some(BASE + 64));
        assert_eq!(image.span(), (BASE, BASE + 0x5000));
    }

    #[test]
    fn pt_phdr_must_lie_in_a_loaded_segment() {
        let phdr = |vaddr| Phdr {
            p_type: PT_PHDR,
            flags: PF_R,
            offset: 64,
            vaddr,
            file_size: 3 * PHDR_SIZE as u64,
            mem_size: 3 * PHDR_SIZE as u64,
        };
        let inside = file(
            ET_EXEC,
            BASE + 0x100,
            &[
                phdr(BASE + 64),
                text(0, BASE, 0x800),
                data(0x800, BASE + 0x1800, 0, 8),
            ],
            0x1000,
        );
        assert_eq!(parse(&inside).unwrap().phdr_vaddr, Some(BASE + 64));
        let outside = file(
            ET_EXEC,
            BASE + 0x100,
            &[
                phdr(0x90_0000),
                text(0, BASE, 0x800),
                data(0x800, BASE + 0x1800, 0, 8),
            ],
            0x1000,
        );
        assert_eq!(parse(&outside).unwrap().phdr_vaddr, None);
    }

    #[test]
    fn relocatable_images_take_a_bias() {
        let bytes = file(ET_DYN, 0x100, &[text(0, 0, 0x800)], 0x1000);
        let image = parse(&bytes).unwrap();
        assert_eq!(image.kind, Kind::Relocatable);
        // Unbiased, it would sit on page 0, below USER_START.
        assert_eq!(image.check_bias(0), Err(ElfError::OutOfRange));
        assert_eq!(image.check_bias(0x5555_0000_0000), Ok(()));
        assert_eq!(image.check_bias(USER_END), Err(ElfError::OutOfRange));
        assert_eq!(image.check_bias(u64::MAX), Err(ElfError::OutOfRange));
        assert_eq!(image.bias_for_base(0x5555_0000_0000), Ok(0x5555_0000_0000));
    }

    /// Audit 3, C1: an ET_DYN image whose first segment lies above the load
    /// base would need a negative bias. It is refused, not computed.
    #[test]
    fn relocatable_image_above_the_base_is_refused() {
        let high = 0x7000_0000_0000;
        let bytes = file(ET_DYN, high + 0x100, &[text(0, high, 0x800)], 0x1000);
        let image = parse(&bytes).unwrap();
        assert_eq!(image.kind, Kind::Relocatable);
        assert_eq!(
            image.bias_for_base(0x5555_5555_4000),
            Err(ElfError::OutOfRange)
        );
        // Loaded at its own address, the bias is zero.
        assert_eq!(image.bias_for_base(high), Ok(0));
    }

    #[test]
    fn refuses_bad_identification() {
        let mut bytes = good();
        bytes[0] = 0;
        assert_eq!(parse(&bytes), Err(ElfError::BadMagic));
        for (at, value) in [(4, 1), (5, 2), (6, 0)] {
            let mut bytes = good();
            bytes[at] = value;
            assert_eq!(parse(&bytes), Err(ElfError::WrongFormat), "byte {at}");
        }
        let mut bytes = good();
        bytes[18] = 3; // EM_386
        assert_eq!(parse(&bytes), Err(ElfError::WrongFormat));
        let mut bytes = good();
        bytes[16] = 1; // ET_REL
        assert_eq!(parse(&bytes), Err(ElfError::WrongType));
        assert_eq!(parse(&good()[..63]), Err(ElfError::Truncated));
    }

    #[test]
    fn refuses_bad_header_tables() {
        let mut bytes = good();
        bytes[54] = 32; // e_phentsize
        assert_eq!(parse(&bytes), Err(ElfError::BadHeaderTable));
        let mut bytes = good();
        bytes[56..58].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ElfError::BadHeaderTable));
        let mut bytes = good();
        bytes[56..58].copy_from_slice(&74u16.to_le_bytes()); // > 4096 bytes
        assert_eq!(parse(&bytes), Err(ElfError::BadHeaderTable));
        let mut bytes = good();
        bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes()); // e_phoff
        assert_eq!(parse(&bytes), Err(ElfError::Truncated));
        let mut bytes = good();
        bytes[32..40].copy_from_slice(&0xfa0u64.to_le_bytes()); // 0xfa0 + 112 > 0x1000
        assert_eq!(parse(&bytes), Err(ElfError::Truncated));
    }

    #[test]
    fn refuses_interpreters_and_executable_stacks() {
        let interp = Phdr {
            p_type: PT_INTERP,
            flags: PF_R,
            offset: 0x200,
            vaddr: BASE + 0x200,
            file_size: 16,
            mem_size: 16,
        };
        let bytes = file(ET_EXEC, BASE, &[interp, text(0, BASE, 0x800)], 0x1000);
        assert_eq!(parse(&bytes), Err(ElfError::Interpreter));
        let mut stack = interp;
        stack.p_type = PT_GNU_STACK;
        stack.flags = PF_R | PF_W;
        let bytes = file(ET_EXEC, BASE, &[stack, text(0, BASE, 0x800)], 0x1000);
        assert!(parse(&bytes).is_ok(), "a non-executable stack is fine");
        stack.flags = PF_R | PF_W | PF_X;
        let bytes = file(ET_EXEC, BASE, &[stack, text(0, BASE, 0x800)], 0x1000);
        assert_eq!(parse(&bytes), Err(ElfError::ExecutableStack));
    }

    #[test]
    fn refuses_bad_segments() {
        let case = |phdrs: &[Phdr]| parse(&file(ET_EXEC, BASE, phdrs, 0x1000));
        let mut wx = text(0, BASE, 0x800);
        wx.flags = PF_R | PF_W | PF_X;
        assert_eq!(case(&[wx]), Err(ElfError::WritableAndExecutable));
        assert_eq!(
            case(&[text(0, BASE, 0x800), data(0x800, BASE + 0x1800, 0x10, 8)]),
            Err(ElfError::BadSegment),
            "file size larger than memory size"
        );
        assert_eq!(
            case(&[text(0, BASE, 0x1001)]),
            Err(ElfError::BadSegment),
            "past the end of the file"
        );
        assert_eq!(
            case(&[text(u64::MAX, BASE, 2)]),
            Err(ElfError::BadSegment),
            "offset overflow"
        );
        assert_eq!(case(&[text(0, BASE + 8, 0x800)]), Err(ElfError::Misaligned));
        assert_eq!(
            case(&[text(0, BASE, 0x800), data(0x800, BASE + 0x800, 0x10, 0x10)]),
            Err(ElfError::Overlap),
            "two segments in one page"
        );
        assert_eq!(
            case(&[data(0x800, BASE + 0x1800, 0x10, 0x10), text(0, BASE, 0x800)]),
            Err(ElfError::Overlap),
            "out of order"
        );
        let mut high = text(0, USER_END - 0x1000, 0x800);
        assert_eq!(
            parse(&file(ET_EXEC, high.vaddr, &[high], 0x1000)).map(|_| ()),
            Ok(())
        );
        high.mem_size = 0x2000;
        assert_eq!(
            parse(&file(ET_EXEC, high.vaddr, &[high], 0x1000)),
            Err(ElfError::OutOfRange)
        );
        let mut wrap = text(0, u64::MAX - 0xfff, 0x800);
        wrap.mem_size = 0x2000;
        assert_eq!(
            parse(&file(ET_EXEC, wrap.vaddr, &[wrap], 0x1000)),
            Err(ElfError::OutOfRange)
        );
        assert_eq!(
            parse(&file(ET_EXEC, 0x100, &[text(0, 0, 0x800)], 0x1000)),
            Err(ElfError::OutOfRange),
            "fixed image on page 0"
        );
    }

    #[test]
    fn refuses_bad_entry_points() {
        let case = |entry| {
            parse(&file(
                ET_EXEC,
                entry,
                &[text(0, BASE, 0x800), data(0x800, BASE + 0x1800, 0x10, 0x10)],
                0x1000,
            ))
        };
        assert!(case(BASE).is_ok());
        assert!(case(BASE + 0x7ff).is_ok());
        assert_eq!(case(BASE + 0x800), Err(ElfError::BadEntry));
        assert_eq!(case(BASE + 0x1800), Err(ElfError::BadEntry), "data");
        assert_eq!(case(0), Err(ElfError::BadEntry));
        let none = file(ET_EXEC, BASE, &[data(0x800, BASE + 0x1800, 0, 0)], 0x1000);
        assert_eq!(parse(&none), Err(ElfError::NoSegments));
    }

    /// Arbitrary bytes, and real headers with random fields, produce an
    /// image or an error, never a panic; every accepted image satisfies
    /// the invariants the loader relies on.
    #[test]
    fn random_inputs_never_panic() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let template = good();
        let mut accepted = 0;
        for round in 0..50_000 {
            let bytes: Vec<u8> = if round % 2 == 0 {
                let len = (next() % 400) as usize;
                (0..len).map(|_| next() as u8).collect()
            } else {
                let mut bytes = template.clone();
                for _ in 0..(next() % 6 + 1) {
                    let at = (next() as usize) % 176; // header and both phdrs
                    bytes[at] = next() as u8;
                }
                bytes
            };
            if let Ok(image) = parse(&bytes) {
                accepted += 1;
                for s in &image.segments {
                    assert!(!(s.prot.write && s.prot.exec));
                    assert!(s.file_size <= s.mem_size);
                    assert!(s.file_offset + s.file_size <= bytes.len() as u64);
                    assert!(s.page_end() <= USER_END);
                }
                for pair in image.segments.windows(2) {
                    assert!(pair[0].page_end() <= pair[1].page_start());
                }
                // Choosing a load address never panics (audit 3, C1).
                for base in [0, 0x5555_5555_4000, USER_END, u64::MAX] {
                    let _ = image.bias_for_base(base);
                }
            }
        }
        assert!(accepted > 0, "the mutation loop should reach valid images");
    }
}
