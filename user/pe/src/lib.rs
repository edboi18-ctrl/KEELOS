//! A PE32+ (64-bit Windows executable) parser for `peldr`, Phase 2.
//!
//! Every offset and size in the file is checked before it is used: against
//! the file length for file offsets, and against `SizeOfImage` for RVAs.
//! All arithmetic is checked. Nothing is allocated, and tables are walked
//! lazily with fixed caps: at most `MAX_IMPORTS` imports in all, each name
//! found with one lookup of its section and one scan of at most
//! `MAX_NAME` bytes, so the work a file can cause is bounded (a crafted
//! 44 KB file used to take minutes: Phase 2 audit, D1). Safe Rust only
//! (ADR 0013).
//!
//! Layouts are from Microsoft's "PE Format" (MicrosoftDocs/win32,
//! `desktop-src/Debug/pe-format.md`, read 2026-11-22):
//! - the signature offset at 0x3C, then "PE\0\0";
//! - the COFF file header (20 bytes; at most 96 sections, the Windows
//!   loader's limit);
//! - the PE32+ optional header (magic 0x20B): AddressOfEntryPoint 16,
//!   ImageBase 24 (8 bytes, a multiple of 64 KiB), SectionAlignment 32,
//!   FileAlignment 36, SizeOfImage 56, SizeOfHeaders 60,
//!   NumberOfRvaAndSizes 108, data directories from 112 (import = 1,
//!   base relocation = 5);
//! - section headers (40 bytes);
//! - import directory entries (20 bytes, ending with an all-null entry),
//!   PE32+ lookup entries (64-bit; bit 63 = by ordinal, else a 31-bit
//!   hint/name RVA), hint/name entries (2-byte hint, then a NUL-terminated
//!   name);
//! - base relocation blocks (page RVA, block size, then 16-bit entries:
//!   4-bit type, 12-bit offset; each block on a 32-bit boundary). Only
//!   `IMAGE_REL_BASED_ABSOLUTE` (0, padding) and `IMAGE_REL_BASED_DIR64`
//!   (10) occur in x86-64 images; any other type is an error.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

/// IMAGE_FILE_MACHINE_AMD64.
pub const MACHINE_AMD64: u16 = 0x8664;
/// Optional-header magic of a PE32+ image.
pub const PE32_PLUS: u16 = 0x20B;
/// IMAGE_FILE_EXECUTABLE_IMAGE.
const FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
/// IMAGE_FILE_DLL.
const FILE_DLL: u16 = 0x2000;
/// The Windows loader's limit on sections.
pub const MAX_SECTIONS: usize = 96;
/// Page size: section alignment must be a multiple of it, so each section
/// can be mapped with its own protection.
pub const PAGE: u32 = 4096;

const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

const DIR_IMPORT: usize = 1;
const DIR_BASERELOC: usize = 5;

const COFF_SIZE: usize = 20;
const OPTIONAL_DIRS_AT: usize = 112;
const SECTION_SIZE: usize = 40;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;

/// Longest DLL or function name accepted (bytes, without the NUL).
pub const MAX_NAME: usize = 255;
/// Most DLLs one image may import from.
pub const MAX_DLLS: usize = 256;
/// Most functions imported from one DLL.
pub const MAX_IMPORTS_PER_DLL: usize = 4096;
/// Most imports in all. Without it the per-DLL caps multiply to a
/// million, and descriptors may share one table, so a tiny file could
/// make the walk last minutes (Phase 2 audit, D1).
pub const MAX_IMPORTS: usize = 16384;

/// Why a file was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeError {
    /// The file ends before a structure it must contain.
    Truncated,
    /// No "MZ" at the start.
    NoMzSignature,
    /// No "PE\0\0" at the offset in 0x3C.
    NoPeSignature,
    /// Not an x86-64 image.
    WrongMachine,
    /// An object file or a DLL, not an executable image.
    NotExecutable,
    /// Not PE32+.
    NotPe32Plus,
    /// Optional-header sizes, alignments or counts are invalid.
    BadOptionalHeader,
    /// Zero sections, or more than the loader's limit.
    BadSectionCount,
    /// A section is misaligned, overlaps another or the headers, lies
    /// outside the image or the file, or is writable and executable.
    BadSection,
    /// The entry point is not in an executable section.
    BadEntryPoint,
    /// A data directory lies outside the image.
    BadDirectory,
    /// A table or string lies outside the file's data for the image.
    BadReference,
    /// A name is missing its NUL within `MAX_NAME` bytes.
    BadName,
    /// More DLLs or imports than the caps.
    TooManyImports,
    /// A relocation block is malformed or points outside the image.
    BadRelocation,
    /// A relocation type other than ABSOLUTE or DIR64.
    UnsupportedRelocation(u8),
}

fn u16_at(data: &[u8], at: usize) -> Result<u16, PeError> {
    let end = at.checked_add(2).ok_or(PeError::Truncated)?;
    let bytes = data.get(at..end).ok_or(PeError::Truncated)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, PeError> {
    let end = at.checked_add(4).ok_or(PeError::Truncated)?;
    let bytes = data.get(at..end).ok_or(PeError::Truncated)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(data: &[u8], at: usize) -> Result<u64, PeError> {
    Ok(u64::from(u32_at(data, at)?) | (u64::from(u32_at(data, at + 4)?) << 32))
}

fn round_up(value: u32, align: u32) -> Option<u32> {
    value.checked_next_multiple_of(align)
}

/// One section of the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section<'a> {
    /// The name field, NUL-padded (not necessarily UTF-8).
    pub name: [u8; 8],
    /// Where it goes, relative to the image base (page-aligned).
    pub rva: u32,
    /// Bytes it occupies in memory, rounded up to the section alignment.
    pub memory_size: u32,
    /// Its initialized data from the file; the rest of `memory_size` is
    /// zero.
    pub data: &'a [u8],
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// A parsed image. Constructed only by [`parse`], so every field and
/// every section has been checked.
#[derive(Clone, Copy, Debug)]
pub struct Image<'a> {
    file: &'a [u8],
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: u32,
    /// Bytes of headers to map at the image base (`SizeOfHeaders`).
    pub size_of_headers: u32,
    pub section_alignment: u32,
    table_at: usize,
    section_count: usize,
    dirs: [(u32, u32); 16],
    dir_count: usize,
}

/// Checks the headers and the section table of `file`.
pub fn parse(file: &[u8]) -> Result<Image<'_>, PeError> {
    if file.get(..2) != Some(b"MZ".as_slice()) {
        return Err(PeError::NoMzSignature);
    }
    let pe = u32_at(file, 0x3C)? as usize;
    let sig_end = pe.checked_add(4).ok_or(PeError::Truncated)?;
    if file.get(pe..sig_end).ok_or(PeError::Truncated)? != b"PE\0\0" {
        return Err(PeError::NoPeSignature);
    }
    let coff = sig_end;
    if u16_at(file, coff)? != MACHINE_AMD64 {
        return Err(PeError::WrongMachine);
    }
    let section_count = usize::from(u16_at(file, coff + 2)?);
    let optional_size = usize::from(u16_at(file, coff + 16)?);
    let characteristics = u16_at(file, coff + 18)?;
    if characteristics & FILE_EXECUTABLE_IMAGE == 0 || characteristics & FILE_DLL != 0 {
        return Err(PeError::NotExecutable);
    }
    let opt = coff + COFF_SIZE;
    let opt_end = opt.checked_add(optional_size).ok_or(PeError::Truncated)?;
    let optional = file.get(opt..opt_end).ok_or(PeError::Truncated)?;
    if optional.len() < 2 || u16_at(optional, 0)? != PE32_PLUS {
        return Err(PeError::NotPe32Plus);
    }
    if optional.len() < OPTIONAL_DIRS_AT {
        return Err(PeError::BadOptionalHeader);
    }
    let entry_rva = u32_at(optional, 16)?;
    let image_base = u64_at(optional, 24)?;
    let section_alignment = u32_at(optional, 32)?;
    let file_alignment = u32_at(optional, 36)?;
    let size_of_image = u32_at(optional, 56)?;
    let size_of_headers = u32_at(optional, 60)?;
    let dir_count = u32_at(optional, 108)? as usize;

    let aligned = |a: u32, lo: u32, hi: u32| a.is_power_of_two() && (lo..=hi).contains(&a);
    let dirs_end = dir_count
        .checked_mul(8)
        .and_then(|n| n.checked_add(OPTIONAL_DIRS_AT));
    if !image_base.is_multiple_of(0x1_0000)
        || !aligned(section_alignment, PAGE, 1 << 20)
        || !aligned(file_alignment, 512, 0x1_0000)
        || file_alignment > section_alignment
        || size_of_image == 0
        || !size_of_image.is_multiple_of(section_alignment)
        || size_of_headers == 0
        || size_of_headers > size_of_image
        || size_of_headers as usize > file.len()
        || dir_count > 16
        || dirs_end.is_none_or(|end| end > optional.len())
    {
        return Err(PeError::BadOptionalHeader);
    }
    // The image must fit in the lower half of the address space.
    if image_base
        .checked_add(u64::from(size_of_image))
        .is_none_or(|end| end > 0x0000_7FFF_FFFF_0000)
    {
        return Err(PeError::BadOptionalHeader);
    }
    let mut dirs = [(0u32, 0u32); 16];
    for (i, dir) in dirs.iter_mut().enumerate().take(dir_count) {
        let rva = u32_at(optional, OPTIONAL_DIRS_AT + i * 8)?;
        let size = u32_at(optional, OPTIONAL_DIRS_AT + i * 8 + 4)?;
        *dir = (rva, size);
    }

    if section_count == 0 || section_count > MAX_SECTIONS {
        return Err(PeError::BadSectionCount);
    }
    let table_end = section_count
        .checked_mul(SECTION_SIZE)
        .and_then(|n| n.checked_add(opt_end))
        .ok_or(PeError::Truncated)?;
    if table_end > file.len() {
        return Err(PeError::Truncated);
    }

    let image = Image {
        file,
        image_base,
        entry_rva,
        size_of_image,
        size_of_headers,
        section_alignment,
        table_at: opt_end,
        section_count,
        dirs,
        dir_count,
    };

    // Sections: in RVA order, aligned, after the headers, inside the
    // image, not overlapping, data inside the file, never W+X.
    let headers_end =
        round_up(size_of_headers, section_alignment).ok_or(PeError::BadOptionalHeader)?;
    let mut next_free = headers_end;
    let mut entry_ok = false;
    for i in 0..section_count {
        let s = image.section(i)?;
        let end = s
            .rva
            .checked_add(s.memory_size)
            .ok_or(PeError::BadSection)?;
        if s.rva < next_free || end > size_of_image || (s.write && s.execute) {
            return Err(PeError::BadSection);
        }
        if s.execute && (s.rva..end).contains(&entry_rva) {
            entry_ok = true;
        }
        next_free = end;
    }
    if !entry_ok {
        return Err(PeError::BadEntryPoint);
    }
    for index in [DIR_IMPORT, DIR_BASERELOC] {
        let (rva, size) = image.directory(index);
        if size != 0
            && rva
                .checked_add(size)
                .is_none_or(|end| rva < headers_end || end > size_of_image)
        {
            return Err(PeError::BadDirectory);
        }
    }
    Ok(image)
}

impl<'a> Image<'a> {
    /// Number of sections.
    pub fn section_count(&self) -> usize {
        self.section_count
    }

    /// Section `index`, checked as `parse` checked it; an index at or past
    /// `section_count` is an error.
    pub fn section(&self, index: usize) -> Result<Section<'a>, PeError> {
        if index >= self.section_count {
            return Err(PeError::BadSection);
        }
        let at = self.table_at + index * SECTION_SIZE;
        let header = self
            .file
            .get(at..at + SECTION_SIZE)
            .ok_or(PeError::Truncated)?;
        let mut name = [0u8; 8];
        name.copy_from_slice(&header[..8]);
        let virtual_size = u32_at(header, 8)?;
        let rva = u32_at(header, 12)?;
        let raw_size = u32_at(header, 16)?;
        let raw_at = u32_at(header, 20)?;
        let flags = u32_at(header, 36)?;
        if !rva.is_multiple_of(self.section_alignment) {
            return Err(PeError::BadSection);
        }
        // In memory: the larger of the two sizes, rounded up to whole
        // alignment units (a section with VirtualSize 0 uses its raw size).
        let span = virtual_size.max(raw_size);
        let memory_size = round_up(span, self.section_alignment)
            .filter(|&n| n != 0)
            .ok_or(PeError::BadSection)?;
        // Initialized data: at most VirtualSize bytes when that is set.
        let data_len = if virtual_size == 0 {
            raw_size
        } else {
            raw_size.min(virtual_size)
        } as usize;
        let data = if data_len == 0 {
            &[][..]
        } else {
            let start = raw_at as usize;
            let end = start.checked_add(data_len).ok_or(PeError::BadSection)?;
            self.file.get(start..end).ok_or(PeError::BadSection)?
        };
        Ok(Section {
            name,
            rva,
            memory_size,
            data,
            read: flags & SCN_MEM_READ != 0,
            write: flags & SCN_MEM_WRITE != 0,
            execute: flags & SCN_MEM_EXECUTE != 0,
        })
    }

    /// The headers as they are mapped at the image base.
    pub fn headers(&self) -> &'a [u8] {
        &self.file[..self.size_of_headers as usize]
    }

    /// Data directory `index` as (RVA, size); (0, 0) if absent.
    pub fn directory(&self, index: usize) -> (u32, u32) {
        if index < self.dir_count {
            self.dirs[index]
        } else {
            (0, 0)
        }
    }

    /// `len` bytes of initialized data at `rva`, from the headers or one
    /// section. Fails if the range is not entirely file-backed data of a
    /// single section (data that would be zero-fill is not readable here).
    pub fn bytes_at(&self, rva: u32, len: usize) -> Result<&'a [u8], PeError> {
        let end = (rva as usize)
            .checked_add(len)
            .ok_or(PeError::BadReference)?;
        if end <= self.size_of_headers as usize {
            return Ok(&self.file[rva as usize..end]);
        }
        let data = self.data_from(rva)?;
        data.get(..len).ok_or(PeError::BadReference)
    }

    /// The section whose address range contains `rva`, found by binary
    /// search: `parse` checked that sections are in ascending, disjoint
    /// RVA order.
    fn section_containing(&self, rva: u32) -> Result<Section<'a>, PeError> {
        let (mut lo, mut hi) = (0, self.section_count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let s = self.section(mid)?;
            if rva < s.rva {
                hi = mid;
            } else if rva >= s.rva + s.memory_size {
                lo = mid + 1;
            } else {
                return Ok(s);
            }
        }
        Err(PeError::BadReference)
    }

    /// The file-backed bytes from `rva` to the end of the headers or of the
    /// section that holds it: one lookup, however much is then read.
    fn data_from(&self, rva: u32) -> Result<&'a [u8], PeError> {
        let at = rva as usize;
        if at < self.size_of_headers as usize {
            return Ok(&self.file[at..self.size_of_headers as usize]);
        }
        let s = self.section_containing(rva)?;
        // Only the file-backed part: zero-fill beyond it is not readable.
        s.data
            .get(at - s.rva as usize..)
            .filter(|rest| !rest.is_empty())
            .ok_or(PeError::BadReference)
    }

    /// A NUL-terminated name at `rva`, without the NUL; at most `MAX_NAME`
    /// bytes, all in one section (or the headers). The section is found
    /// once and its bytes scanned once (D1: this used to look the section
    /// up again for every byte).
    fn name_at(&self, rva: u32) -> Result<&'a [u8], PeError> {
        let data = self.data_from(rva)?;
        let window = &data[..data.len().min(MAX_NAME + 1)];
        let len = window
            .iter()
            .position(|&b| b == 0)
            .ok_or(PeError::BadName)?;
        Ok(&data[..len])
    }

    /// The imports, DLL by DLL, function by function.
    pub fn imports(&self) -> Imports<'a> {
        Imports {
            image: *self,
            dll: 0,
            entry: 0,
            total: 0,
            done: self.directory(DIR_IMPORT).1 == 0,
        }
    }

    /// The base relocations that must be applied if the image is not
    /// loaded at `image_base`: the RVAs of 64-bit fields.
    pub fn relocations(&self) -> Relocations<'a> {
        let (rva, size) = self.directory(DIR_BASERELOC);
        Relocations {
            image: *self,
            block_at: rva,
            end: rva.saturating_add(size),
            entry: None,
        }
    }
}

/// What an import names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportName<'a> {
    Name(&'a [u8]),
    Ordinal(u16),
}

/// One imported function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Import<'a> {
    /// The DLL's name as written in the file (e.g. b"kernel32.dll").
    pub dll: &'a [u8],
    pub name: ImportName<'a>,
    /// RVA of the 8-byte Import Address Table slot to fill in.
    pub slot_rva: u32,
}

/// Iterator over imports; yields an error once and then stops.
pub struct Imports<'a> {
    image: Image<'a>,
    dll: usize,
    entry: usize,
    /// Imports yielded so far, against `MAX_IMPORTS`.
    total: usize,
    done: bool,
}

impl<'a> Imports<'a> {
    fn step(&mut self) -> Result<Option<Import<'a>>, PeError> {
        let image = self.image;
        let (dir_rva, dir_size) = image.directory(DIR_IMPORT);
        loop {
            if self.dll >= MAX_DLLS {
                return Err(PeError::TooManyImports);
            }
            let at = (self.dll * IMPORT_DESCRIPTOR_SIZE) as u32;
            if at as usize + IMPORT_DESCRIPTOR_SIZE > dir_size as usize {
                // No null terminator inside the directory.
                return Err(PeError::BadReference);
            }
            let desc = image.bytes_at(dir_rva + at, IMPORT_DESCRIPTOR_SIZE)?;
            if desc.iter().all(|&b| b == 0) {
                return Ok(None);
            }
            let lookup = u32_at(desc, 0)?;
            let name_rva = u32_at(desc, 12)?;
            let iat = u32_at(desc, 16)?;
            // Without a lookup table, the IAT holds the lookup entries.
            let lookup = if lookup == 0 { iat } else { lookup };
            if self.entry >= MAX_IMPORTS_PER_DLL || self.total >= MAX_IMPORTS {
                return Err(PeError::TooManyImports);
            }
            let offset = (self.entry * 8) as u32;
            let entry_rva = lookup.checked_add(offset).ok_or(PeError::BadReference)?;
            let slot_rva = iat.checked_add(offset).ok_or(PeError::BadReference)?;
            let value = u64_at(image.bytes_at(entry_rva, 8)?, 0)?;
            if value == 0 {
                self.dll += 1;
                self.entry = 0;
                continue;
            }
            // The slot itself must be inside the image's writable data.
            image.bytes_at(slot_rva, 8)?;
            let dll = image.name_at(name_rva)?;
            let name = if value & (1 << 63) != 0 {
                if value & 0x7FFF_FFFF_FFFF_0000 != 0 {
                    return Err(PeError::BadReference);
                }
                ImportName::Ordinal(value as u16)
            } else {
                if value > 0x7FFF_FFFF {
                    return Err(PeError::BadReference);
                }
                // Hint (2 bytes), then the name.
                let hint_name = (value as u32).checked_add(2).ok_or(PeError::BadReference)?;
                ImportName::Name(image.name_at(hint_name)?)
            };
            self.entry += 1;
            self.total += 1;
            return Ok(Some(Import {
                dll,
                name,
                slot_rva,
            }));
        }
    }
}

impl<'a> Iterator for Imports<'a> {
    type Item = Result<Import<'a>, PeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.step() {
            Ok(Some(import)) => Some(Ok(import)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

/// Iterator over base relocations (RVAs of 64-bit fields to adjust);
/// yields an error once and then stops.
pub struct Relocations<'a> {
    image: Image<'a>,
    block_at: u32,
    end: u32,
    /// Current block: (page RVA, next entry RVA, end of entries).
    entry: Option<(u32, u32, u32)>,
}

impl Relocations<'_> {
    fn step(&mut self) -> Result<Option<u32>, PeError> {
        loop {
            if let Some((page, at, end)) = self.entry {
                if at >= end {
                    self.entry = None;
                    continue;
                }
                let word = u16_at(self.image.bytes_at(at, 2)?, 0)?;
                self.entry = Some((page, at + 2, end));
                match (word >> 12) as u8 {
                    0 => continue, // IMAGE_REL_BASED_ABSOLUTE: padding
                    10 => {
                        let rva = page
                            .checked_add(u32::from(word & 0x0FFF))
                            .ok_or(PeError::BadRelocation)?;
                        if rva
                            .checked_add(8)
                            .is_none_or(|e| e > self.image.size_of_image)
                        {
                            return Err(PeError::BadRelocation);
                        }
                        return Ok(Some(rva));
                    }
                    other => return Err(PeError::UnsupportedRelocation(other)),
                }
            }
            if self.block_at >= self.end {
                return Ok(None);
            }
            if !self.block_at.is_multiple_of(4) {
                return Err(PeError::BadRelocation);
            }
            let header = self.image.bytes_at(self.block_at, 8)?;
            let page = u32_at(header, 0)?;
            let size = u32_at(header, 4)?;
            let block_end = self
                .block_at
                .checked_add(size)
                .ok_or(PeError::BadRelocation)?;
            if size < 8
                || !size.is_multiple_of(2)
                || block_end > self.end
                || !page.is_multiple_of(PAGE)
                || page >= self.image.size_of_image
            {
                return Err(PeError::BadRelocation);
            }
            self.entry = Some((page, self.block_at + 8, block_end));
            // The next block starts on a 32-bit boundary.
            self.block_at = round_up(block_end, 4).ok_or(PeError::BadRelocation)?;
        }
    }
}

impl Iterator for Relocations<'_> {
    type Item = Result<u32, PeError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.step() {
            Ok(Some(rva)) => Some(Ok(rva)),
            Ok(None) => None,
            Err(error) => {
                // Stop after reporting.
                self.block_at = self.end;
                self.entry = None;
                Some(Err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests;
