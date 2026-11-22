//! `peldr [--relocate] FILE.exe`: loads a 64-bit Windows console program
//! that imports
//! only the four kernel32 functions in `foreign.rs`, and runs it in this
//! process (Phase 2, spec section 9). Safe Rust except `foreign.rs`
//! (ADR 0013); the file is parsed by the safe `pe` crate.
//!
//! Steps, as the spec lists them:
//! 1. parse and validate the headers (`pe::parse`);
//! 2. reserve `SizeOfImage` at `ImageBase` (anywhere if that is taken) and
//!    copy in the headers and each section's data;
//! 3. if not at `ImageBase`, apply the DIR64 base relocations;
//! 4. fill each Import Address Table slot with a stub's address; an
//!    unresolved import prints `DLL!name` and exits with status 1;
//! 5. give each section its own protection;
//! 6. build a fake TEB and point GS at it;
//! 7. call the entry point with the Windows x64 convention.
#![no_std]
#![no_main]

mod foreign;

use core::ffi::CStr;
use core::fmt::Write;

use keel_rt::Startup;
use keel_rt::sys::{self, PROT_EXEC, PROT_READ, PROT_WRITE, Region};

/// Formats to standard error without allocating.
struct Stderr;

impl Write for Stderr {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        sys::write(2, s.as_bytes());
        Ok(())
    }
}

/// What went wrong, for the one line printed before exiting with 1.
enum Error<'a> {
    Usage,
    Open(i64),
    Parse(pe::PeError),
    Map(i64),
    Copy,
    Unresolved(&'a [u8], &'a [u8]),
    UnresolvedOrdinal(&'a [u8], u16),
    Protect(i64),
    Teb(i64),
}

fn report(error: &Error<'_>) {
    let mut out = Stderr;
    let _ = match error {
        Error::Usage => writeln!(out, "usage: peldr [--relocate] FILE.exe"),
        Error::Open(e) => writeln!(out, "peldr: cannot read the file (error {e})"),
        Error::Parse(e) => writeln!(out, "peldr: not a loadable PE32+ executable: {e:?}"),
        Error::Map(e) => writeln!(out, "peldr: cannot reserve the image (error {e})"),
        Error::Copy => writeln!(out, "peldr: image data does not fit its reservation"),
        Error::Unresolved(dll, name) => {
            let _ = write!(out, "peldr: unresolved import ");
            sys::writev(2, &[dll, b"!", name, b"\n"]);
            Ok(())
        }
        Error::UnresolvedOrdinal(dll, ordinal) => {
            let _ = write!(out, "peldr: unresolved import ");
            sys::write(2, dll);
            writeln!(out, "!#{ordinal}")
        }
        Error::Protect(e) => writeln!(out, "peldr: mprotect failed (error {e})"),
        Error::Teb(e) => writeln!(out, "peldr: cannot set up the TEB (error {e})"),
    };
}

fn prot(section: &pe::Section) -> u64 {
    let mut prot = 0;
    if section.read {
        prot |= PROT_READ;
    }
    if section.write {
        prot |= PROT_WRITE;
    }
    if section.execute {
        prot |= PROT_EXEC;
    }
    prot
}

/// Steps 2 to 5. Returns the region holding the image.
/// `relocate`: do not even try the preferred base, so the relocation path
/// runs (a test knob, `--relocate`).
fn load<'a>(image: &pe::Image<'a>, relocate: bool) -> Result<Region, Error<'a>> {
    let size = u64::from(image.size_of_image);
    let rw = PROT_READ | PROT_WRITE;
    let preferred = if relocate {
        Err(-17)
    } else {
        Region::map_at(image.image_base, size, rw)
    };
    let region = match preferred {
        Ok(region) => region,
        Err(_) => Region::map(size, rw).map_err(Error::Map)?,
    };
    region.write(0, image.headers()).ok_or(Error::Copy)?;
    for i in 0..image.section_count() {
        let section = image.section(i).map_err(Error::Parse)?;
        region
            .write(u64::from(section.rva), section.data)
            .ok_or(Error::Copy)?;
    }

    // Step 3: only needed away from the preferred base. A field is moved by
    // the difference between where the image is and where it was linked.
    let delta = region.address().wrapping_sub(image.image_base);
    if delta != 0 {
        for reloc in image.relocations() {
            let at = u64::from(reloc.map_err(Error::Parse)?);
            let value = region.read_u64(at).ok_or(Error::Copy)?;
            region
                .write_u64(at, value.wrapping_add(delta))
                .ok_or(Error::Copy)?;
        }
    }

    // Step 4.
    for import in image.imports() {
        let import = import.map_err(Error::Parse)?;
        let address = match import.name {
            pe::ImportName::Name(name) => {
                foreign::resolve(import.dll, name).ok_or(Error::Unresolved(import.dll, name))?
            }
            pe::ImportName::Ordinal(ordinal) => {
                return Err(Error::UnresolvedOrdinal(import.dll, ordinal));
            }
        };
        region
            .write_u64(u64::from(import.slot_rva), address)
            .ok_or(Error::Copy)?;
    }

    // Step 5: headers read-only, each section its own rights. The parser
    // refused writable+executable sections, and the kernel would too.
    let headers = u64::from(image.size_of_headers).next_multiple_of(4096);
    let r = region.protect_range(0, headers, PROT_READ);
    if r < 0 {
        return Err(Error::Protect(r));
    }
    for i in 0..image.section_count() {
        let section = image.section(i).map_err(Error::Parse)?;
        let r = region.protect_range(
            u64::from(section.rva),
            u64::from(section.memory_size),
            prot(&section),
        );
        if r < 0 {
            return Err(Error::Protect(r));
        }
    }
    Ok(region)
}

/// Step 6: a minimal TEB. Windows x64 code reaches its thread data through
/// GS. Offsets: NT_TIB (Wine 10.0 `include/winnt.h`, seven pointers) puts
/// StackBase at 0x08, StackLimit at 0x10 and Self at 0x30; the TEB
/// (Microsoft, winternl.h `TEB`: `PVOID Reserved1[12]` then
/// `ProcessEnvironmentBlock`) puts the PEB pointer at 0x60. The PEB is a
/// zeroed page.
fn make_teb(stack_top: u64) -> Result<Region, Error<'static>> {
    let rw = PROT_READ | PROT_WRITE;
    let teb = Region::map(0x2000, rw).map_err(Error::Teb)?;
    let peb = Region::map(0x1000, rw).map_err(Error::Teb)?;
    let stack_base = stack_top.next_multiple_of(4096);
    let fields = [
        (0x08, stack_base),
        (0x10, stack_base.saturating_sub(1 << 20)),
        (0x30, teb.address()),
        (0x60, peb.address()),
    ];
    for (offset, value) in fields {
        teb.write_u64(offset, value).ok_or(Error::Copy)?;
    }
    let r = sys::set_gs_base(teb.address());
    if r < 0 {
        return Err(Error::Teb(r));
    }
    Ok(teb)
}

/// Copies the program path into a NUL-terminated buffer.
fn c_path<'b>(path: &[u8], buffer: &'b mut [u8; 4096]) -> Result<&'b CStr, Error<'static>> {
    if path.len() >= buffer.len() {
        return Err(Error::Open(-36)); // ENAMETOOLONG
    }
    buffer[..path.len()].copy_from_slice(path);
    CStr::from_bytes_until_nul(buffer).map_err(|_| Error::Usage)
}

fn main(startup: &Startup) -> i32 {
    let mut buffer = [0u8; 4096];
    let mut args = startup.args().skip(1).peekable();
    let relocate = args.next_if(|a| *a == b"--relocate").is_some();
    let file = match args.next().ok_or(Error::Usage).and_then(|path| {
        let cpath = c_path(path, &mut buffer)?;
        sys::map_file(cpath).map_err(Error::Open)
    }) {
        Ok(file) => file,
        Err(error) => {
            report(&error);
            return 1;
        }
    };
    // The file is read only while loading: everything the program needs is
    // copied into its own reservation.
    let loaded = pe::parse(file.bytes())
        .map_err(Error::Parse)
        .and_then(|image| Ok((load(&image, relocate)?, image.entry_rva)))
        .and_then(|(region, entry_rva)| {
            let teb = make_teb(startup.initial_sp)?;
            Ok((region, teb, entry_rva))
        });
    match loaded {
        Ok((region, _teb, entry_rva)) => {
            let entry = region.address() + u64::from(entry_rva);
            foreign::call_entry(entry) as i32
        }
        Err(error) => {
            report(&error);
            1
        }
    }
}

keel_rt::main!(main);
