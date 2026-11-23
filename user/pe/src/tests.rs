use super::*;
use std::vec::Vec;

/// The Phase 2 fixture (`winetest/hello-console`).
const HELLO: &[u8] = include_bytes!("../../../winetest/hello-console/hello.exe");

#[test]
fn the_fixture_parses_as_its_build_says() {
    let image = parse(HELLO).unwrap();
    assert_eq!(image.image_base, 0x1_4000_0000);
    assert_eq!(image.entry_rva, 0x1000);
    assert_eq!(image.size_of_image, 0x5000);
    assert_eq!(image.section_count(), 4);
    let text = image.section(0).unwrap();
    assert_eq!(&text.name[..5], b".text");
    assert!(text.execute && text.read && !text.write);
    let mut names: Vec<&[u8]> = image
        .imports()
        .map(|i| {
            let i = i.unwrap();
            assert_eq!(i.dll, b"kernel32.dll");
            match i.name {
                ImportName::Name(n) => n,
                ImportName::Ordinal(_) => panic!("by ordinal"),
            }
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        [b"ExitProcess".as_slice(), b"GetStdHandle", b"WriteFile"]
    );
    // The table of two pointers in .rdata needs two DIR64 relocations.
    let rdata = image.section(1).unwrap();
    assert_eq!(&rdata.name[..6], b".rdata");
    let relocs: Vec<u32> = image.relocations().map(Result::unwrap).collect();
    assert_eq!(relocs.len(), 2);
    assert!(
        relocs
            .iter()
            .all(|&r| (rdata.rva..rdata.rva + rdata.memory_size).contains(&r))
    );
}

/// (name, rva, virtual size, data, characteristics)
type SectionSpec = ([u8; 8], u32, u32, Vec<u8>, u32);

/// Writes a PE32+ file: headers in the first 0x400 bytes, then each
/// section's data at a 0x200-aligned file offset.
struct Builder {
    image_base: u64,
    entry: u32,
    size_of_image: u32,
    sections: Vec<SectionSpec>,
    dirs: [(u32, u32); 16],
    machine: u16,
    magic: u16,
}

const R: u32 = SCN_MEM_READ;
const W: u32 = SCN_MEM_WRITE;
const X: u32 = SCN_MEM_EXECUTE;

fn name(text: &str) -> [u8; 8] {
    let mut n = [0u8; 8];
    n[..text.len()].copy_from_slice(text.as_bytes());
    n
}

impl Builder {
    fn new() -> Builder {
        Builder {
            image_base: 0x1_4000_0000,
            entry: 0x1000,
            size_of_image: 0x4000,
            sections: std::vec![
                (name(".text"), 0x1000, 0x10, std::vec![0xC3; 0x10], R | X),
                (name(".data"), 0x2000, 0x1000, std::vec![0; 0x200], R | W),
            ],
            dirs: [(0, 0); 16],
            machine: MACHINE_AMD64,
            magic: PE32_PLUS,
        }
    }

    fn build(&self) -> Vec<u8> {
        let mut f = std::vec![0u8; 0x400];
        f[0..2].copy_from_slice(b"MZ");
        f[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        f[0x40..0x44].copy_from_slice(b"PE\0\0");
        let coff = 0x44;
        f[coff..coff + 2].copy_from_slice(&self.machine.to_le_bytes());
        f[coff + 2..coff + 4].copy_from_slice(&(self.sections.len() as u16).to_le_bytes());
        let opt_size: u16 = 112 + 16 * 8;
        f[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());
        f[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());
        let opt = coff + 20;
        let put32 =
            |f: &mut Vec<u8>, at: usize, v: u32| f[at..at + 4].copy_from_slice(&v.to_le_bytes());
        f[opt..opt + 2].copy_from_slice(&self.magic.to_le_bytes());
        put32(&mut f, opt + 16, self.entry);
        f[opt + 24..opt + 32].copy_from_slice(&self.image_base.to_le_bytes());
        put32(&mut f, opt + 32, 0x1000);
        put32(&mut f, opt + 36, 0x200);
        put32(&mut f, opt + 56, self.size_of_image);
        put32(&mut f, opt + 60, 0x400);
        put32(&mut f, opt + 108, 16);
        for (i, (rva, size)) in self.dirs.iter().enumerate() {
            put32(&mut f, opt + 112 + i * 8, *rva);
            put32(&mut f, opt + 116 + i * 8, *size);
        }
        let table = opt + usize::from(opt_size);
        let mut raw_at = 0x400u32;
        let mut data = Vec::new();
        for (i, (n, rva, vsize, bytes, flags)) in self.sections.iter().enumerate() {
            let h = table + i * 40;
            f[h..h + 8].copy_from_slice(n);
            put32(&mut f, h + 8, *vsize);
            put32(&mut f, h + 12, *rva);
            let raw = (bytes.len() as u32).next_multiple_of(0x200);
            put32(&mut f, h + 16, raw);
            put32(&mut f, h + 20, if raw == 0 { 0 } else { raw_at });
            put32(&mut f, h + 36, *flags);
            let mut padded = bytes.clone();
            padded.resize(raw as usize, 0);
            data.extend_from_slice(&padded);
            raw_at += raw;
        }
        f.extend_from_slice(&data);
        f
    }
}

/// `.data` laid out with an import table for kernel32.dll (two functions
/// by name, one by ordinal) and a relocation block with two DIR64 entries
/// and one ABSOLUTE pad.
fn with_imports_and_relocs() -> Builder {
    let mut b = Builder::new();
    let base = 0x2000u32;
    let mut d = std::vec![0u8; 0x200];
    let put32 =
        |d: &mut Vec<u8>, at: usize, v: u32| d[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let put64 =
        |d: &mut Vec<u8>, at: usize, v: u64| d[at..at + 8].copy_from_slice(&v.to_le_bytes());
    // Import directory at +0x00: one descriptor and a null one (40 bytes).
    put32(&mut d, 0x00, base + 0x40); // lookup table
    put32(&mut d, 0x0C, base + 0x80); // DLL name
    put32(&mut d, 0x10, base + 0x60); // IAT
    // Lookup table at +0x40: name, name, ordinal 7, end.
    put64(&mut d, 0x40, u64::from(base + 0x90));
    put64(&mut d, 0x48, u64::from(base + 0xA0));
    put64(&mut d, 0x50, (1 << 63) | 7);
    // IAT at +0x60 (same entries before loading).
    put64(&mut d, 0x60, u64::from(base + 0x90));
    put64(&mut d, 0x68, u64::from(base + 0xA0));
    put64(&mut d, 0x70, (1 << 63) | 7);
    d[0x80..0x8D].copy_from_slice(b"kernel32.dll\0");
    d[0x92..0x9E].copy_from_slice(b"WriteFile\0\0\0");
    d[0xA2..0xAE].copy_from_slice(b"ExitProcess\0");
    // Relocation block at +0x100: page 0x2000, size 8 + 3 * 2 = 14, padded
    // to 16 in the directory.
    put32(&mut d, 0x100, 0x2000);
    put32(&mut d, 0x104, 14);
    d[0x108..0x10A].copy_from_slice(&((10u16 << 12) | 0x180).to_le_bytes());
    d[0x10A..0x10C].copy_from_slice(&((10u16 << 12) | 0x188).to_le_bytes());
    d[0x10C..0x10E].copy_from_slice(&0u16.to_le_bytes());
    b.sections[1].3 = d;
    b.dirs[DIR_IMPORT] = (base, 40);
    b.dirs[DIR_BASERELOC] = (base + 0x100, 16);
    b
}

#[test]
fn imports_and_relocations_are_read() {
    let file = with_imports_and_relocs().build();
    let image = parse(&file).unwrap();
    let imports: Vec<Import> = image.imports().map(Result::unwrap).collect();
    assert_eq!(
        imports,
        [
            Import {
                dll: b"kernel32.dll",
                name: ImportName::Name(b"WriteFile"),
                slot_rva: 0x2060
            },
            Import {
                dll: b"kernel32.dll",
                name: ImportName::Name(b"ExitProcess"),
                slot_rva: 0x2068
            },
            Import {
                dll: b"kernel32.dll",
                name: ImportName::Ordinal(7),
                slot_rva: 0x2070
            },
        ]
    );
    let relocs: Vec<u32> = image.relocations().map(Result::unwrap).collect();
    assert_eq!(relocs, [0x2180, 0x2188]);
}

fn refuses(file: &[u8], expected: PeError) {
    assert_eq!(parse(file).map(|_| ()), Err(expected));
}

#[test]
fn header_errors() {
    let good = Builder::new().build();
    assert!(parse(&good).is_ok());
    refuses(&[], PeError::NoMzSignature);
    refuses(b"MZ", PeError::Truncated);
    let mut f = good.clone();
    f[0x40] = b'X';
    refuses(&f, PeError::NoPeSignature);
    let mut f = good.clone();
    f[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    refuses(&f, PeError::Truncated);
    let mut b = Builder::new();
    b.machine = 0x14C; // i386
    refuses(&b.build(), PeError::WrongMachine);
    let mut b = Builder::new();
    b.magic = 0x10B; // PE32
    refuses(&b.build(), PeError::NotPe32Plus);
    let mut f = good.clone();
    f[0x44 + 18] |= 0x20; // IMAGE_FILE_DLL (0x2000), high byte
    f[0x44 + 19] |= 0x20;
    refuses(&f, PeError::NotExecutable);
    let mut b = Builder::new();
    b.image_base = 0x1_4000_1000; // not a multiple of 64 KiB
    refuses(&b.build(), PeError::BadOptionalHeader);
    let mut b = Builder::new();
    b.image_base = 0x7FFF_FFFF_0000;
    refuses(&b.build(), PeError::BadOptionalHeader);
    let mut b = Builder::new();
    b.size_of_image = 0x3800; // not a multiple of the alignment
    refuses(&b.build(), PeError::BadOptionalHeader);
}

#[test]
fn section_errors() {
    let mut b = Builder::new();
    b.sections.clear();
    refuses(&b.build(), PeError::BadSectionCount);
    let mut b = Builder::new();
    b.sections[1].1 = 0x1000; // overlaps .text
    refuses(&b.build(), PeError::BadSection);
    let mut b = Builder::new();
    b.sections[0].1 = 0x0000; // over the headers
    b.entry = 0;
    refuses(&b.build(), PeError::BadSection);
    let mut b = Builder::new();
    b.sections[1].2 = 0x3000; // runs past SizeOfImage
    refuses(&b.build(), PeError::BadSection);
    let mut b = Builder::new();
    b.sections[1].4 = R | W | X;
    refuses(&b.build(), PeError::BadSection);
    let mut b = Builder::new();
    b.entry = 0x2000; // in .data, not executable
    refuses(&b.build(), PeError::BadEntryPoint);
    // Raw data pointer past the end of the file.
    let mut f = Builder::new().build();
    let table = 0x44 + 20 + 240;
    f[table + 40 + 20..table + 40 + 24].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
    refuses(&f, PeError::BadSection);
    let mut b = Builder::new();
    b.dirs[DIR_IMPORT] = (0x3000, 0x2000);
    refuses(&b.build(), PeError::BadDirectory);
}

fn first_error<T>(items: impl Iterator<Item = Result<T, PeError>>) -> Option<PeError> {
    items.filter_map(Result::err).next()
}

#[test]
fn import_errors() {
    // DLL name without a NUL inside the section.
    let mut b = with_imports_and_relocs();
    b.sections[1].3[0x80..0x200].fill(b'a');
    let f = b.build();
    let image = parse(&f).unwrap();
    assert_eq!(first_error(image.imports()), Some(PeError::BadName));
    // Hint/name RVA outside the image.
    let mut b = with_imports_and_relocs();
    b.sections[1].3[0x40..0x48].copy_from_slice(&0x7FFF_0000u64.to_le_bytes());
    let f = b.build();
    let image = parse(&f).unwrap();
    assert_eq!(first_error(image.imports()), Some(PeError::BadReference));
    // No null descriptor before the end of the directory.
    let mut b = with_imports_and_relocs();
    b.dirs[DIR_IMPORT].1 = 20;
    let f = b.build();
    let image = parse(&f).unwrap();
    assert_eq!(first_error(image.imports()), Some(PeError::BadReference));
    // Ordinal entry with stray high bits.
    let mut b = with_imports_and_relocs();
    b.sections[1].3[0x50..0x58].copy_from_slice(&((1u64 << 63) | (1 << 40) | 7).to_le_bytes());
    let f = b.build();
    let image = parse(&f).unwrap();
    assert_eq!(first_error(image.imports()), Some(PeError::BadReference));
}

#[test]
fn relocation_errors() {
    let reloc_case = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut b = with_imports_and_relocs();
        edit(&mut b.sections[1].3);
        let f = b.build();
        let image = parse(&f).unwrap();
        first_error(image.relocations())
    };
    // HIGHLOW (3) is a 32-bit relocation: not expected in x86-64 images.
    assert_eq!(
        reloc_case(&|d| d[0x108..0x10A].copy_from_slice(&((3u16 << 12) | 4).to_le_bytes())),
        Some(PeError::UnsupportedRelocation(3))
    );
    // Block size below the header.
    assert_eq!(
        reloc_case(&|d| d[0x104..0x108].copy_from_slice(&4u32.to_le_bytes())),
        Some(PeError::BadRelocation)
    );
    // Block larger than the directory.
    assert_eq!(
        reloc_case(&|d| d[0x104..0x108].copy_from_slice(&0x1000u32.to_le_bytes())),
        Some(PeError::BadRelocation)
    );
    // Page outside the image.
    assert_eq!(
        reloc_case(&|d| d[0x100..0x104].copy_from_slice(&0x9000u32.to_le_bytes())),
        Some(PeError::BadRelocation)
    );
    // A DIR64 field running past the end of the image.
    assert_eq!(
        reloc_case(&|d| {
            d[0x100..0x104].copy_from_slice(&0x3000u32.to_le_bytes());
            d[0x108..0x10A].copy_from_slice(&((10u16 << 12) | 0xFFC).to_le_bytes());
        }),
        Some(PeError::BadRelocation)
    );
}

/// The Phase 2 audit's D1 file: 96 sections and 255 import descriptors
/// sharing one 4095-entry lookup table and one 255-byte name (44,544
/// bytes). Built exactly as the audit's program builds it.
fn shared_import_tables() -> Vec<u8> {
    fn p16(v: &mut [u8], at: usize, x: u16) {
        v[at..at + 2].copy_from_slice(&x.to_le_bytes());
    }
    fn p32(v: &mut [u8], at: usize, x: u32) {
        v[at..at + 4].copy_from_slice(&x.to_le_bytes());
    }
    fn p64(v: &mut [u8], at: usize, x: u64) {
        v[at..at + 8].copy_from_slice(&x.to_le_bytes());
    }
    const NSEC: usize = 96;
    const DLLS: usize = 255;
    const FUNCS: usize = 4095;
    let hdr = 0x1400usize;
    let data_len = (DLLS + 1) * 20 + (FUNCS + 1) * 8 + 2 + 256 + 256;
    let raw_len = data_len.next_multiple_of(512);
    let mut f = std::vec![0u8; hdr + 512 + raw_len];
    f[0] = b'M';
    f[1] = b'Z';
    p32(&mut f, 0x3c, 0x40);
    f[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    p16(&mut f, coff, 0x8664);
    p16(&mut f, coff + 2, NSEC as u16);
    p16(&mut f, coff + 16, 240);
    p16(&mut f, coff + 18, 0x0002);
    let opt = coff + 20;
    p16(&mut f, opt, 0x20b);
    p32(&mut f, opt + 16, 0x2000);
    p64(&mut f, opt + 24, 0x1_4000_0000);
    p32(&mut f, opt + 32, 0x1000);
    p32(&mut f, opt + 36, 512);
    let last_rva = 0x2000 + (NSEC as u32 - 1) * 0x10000;
    let size_of_image = (last_rva + raw_len as u32).next_multiple_of(0x1000);
    p32(&mut f, opt + 56, size_of_image);
    p32(&mut f, opt + 60, hdr as u32);
    p32(&mut f, opt + 108, 16);
    p32(&mut f, opt + 112 + 8, last_rva);
    p32(&mut f, opt + 112 + 12, ((DLLS + 1) * 20) as u32);
    let table = opt + 240;
    for i in 0..NSEC {
        let s = table + i * 40;
        let rva = 0x2000 + i as u32 * 0x10000;
        if i == NSEC - 1 {
            p32(&mut f, s + 8, raw_len as u32);
            p32(&mut f, s + 12, rva);
            p32(&mut f, s + 16, raw_len as u32);
            p32(&mut f, s + 20, (hdr + 512) as u32);
            p32(&mut f, s + 36, 0xC000_0000);
        } else {
            p32(&mut f, s + 8, 0x1000);
            p32(&mut f, s + 12, rva);
            p32(&mut f, s + 16, if i == 0 { 512 } else { 0 });
            p32(&mut f, s + 20, hdr as u32);
            p32(
                &mut f,
                s + 36,
                if i == 0 { 0x6000_0000 } else { 0x4000_0000 },
            );
        }
    }
    let base = hdr + 512;
    let lookup_off = (DLLS + 1) * 20;
    let hint_off = lookup_off + (FUNCS + 1) * 8;
    let dll_off = hint_off + 2 + 256;
    for d in 0..DLLS {
        let at = base + d * 20;
        p32(&mut f, at, last_rva + lookup_off as u32);
        p32(&mut f, at + 12, last_rva + dll_off as u32);
        p32(&mut f, at + 16, last_rva + lookup_off as u32);
    }
    for e in 0..FUNCS {
        p64(
            &mut f,
            base + lookup_off + e * 8,
            u64::from(last_rva + hint_off as u32),
        );
    }
    for b in 0..255 {
        f[base + hint_off + 2 + b] = b'a';
        f[base + dll_off + b] = b'k';
    }
    f
}

/// Phase 2 audit, D1: walking that file used to take minutes (a section
/// lookup per byte of every name, a million imports). Now the walk stops
/// at MAX_IMPORTS with TooManyImports, quickly.
#[test]
fn shared_import_tables_are_walked_quickly() {
    let file = shared_import_tables();
    assert_eq!(file.len(), 44_544);
    let image = parse(&file).unwrap();
    let start = std::time::Instant::now();
    let mut count = 0;
    let mut last = None;
    for import in image.imports() {
        match import {
            Ok(_) => count += 1,
            Err(error) => last = Some(error),
        }
    }
    let elapsed = start.elapsed();
    assert_eq!(count, MAX_IMPORTS);
    assert_eq!(last, Some(PeError::TooManyImports));
    // Generous for an unoptimized test build on a busy machine.
    assert!(elapsed.as_secs_f64() < 1.0, "walk took {elapsed:?}");
    std::println!("D1 file: {count} imports in {elapsed:?}");
}

/// The first error parsing `data` or walking its imports and relocations
/// gives, as text ("BadSection", "UnsupportedRelocation(3)").
fn first_error_anywhere(data: &[u8]) -> Option<std::string::String> {
    let image = match parse(data) {
        Ok(image) => image,
        Err(error) => return Some(std::format!("{error:?}")),
    };
    first_error(image.imports())
        .or_else(|| first_error(image.relocations()))
        .map(|error| std::format!("{error:?}"))
}

fn corpus_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/pe-corpus")
}

/// The malformed-file corpus (Phase 2 security note): each file's name
/// starts with the error it must produce, up to the first `-`
/// ("BadSection-wx.exe"); parentheses become `_` ("UnsupportedRelocation_3_").
#[test]
fn corpus_files_give_their_errors() {
    let mut checked = 0;
    for entry in std::fs::read_dir(corpus_dir()).unwrap() {
        let path = entry.unwrap().path();
        let file_name = path.file_name().unwrap().to_string_lossy().into_owned();
        let expected = std::string::String::from(file_name.split('-').next().unwrap());
        let data = std::fs::read(&path).unwrap();
        let got = first_error_anywhere(&data).map(|e| e.replace(['(', ')'], "_"));
        assert_eq!(got.as_deref(), Some(expected.as_str()), "{file_name}");
        checked += 1;
    }
    assert!(checked >= 20, "corpus has {checked} files");
}

/// Writes the corpus from the builder. Run once by hand:
/// `cargo test -p pe write_corpus -- --ignored`.
#[test]
#[ignore]
fn write_corpus() {
    let dir = corpus_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let good = Builder::new().build();
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    cases.push(("NoMzSignature-empty", Vec::new()));
    cases.push(("Truncated-mz-only", b"MZ".to_vec()));
    let mut f = good.clone();
    f[0x40] = b'X';
    cases.push(("NoPeSignature-bad-signature", f));
    let mut f = good.clone();
    f[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push(("Truncated-lfanew-past-end", f));
    let mut b = Builder::new();
    b.machine = 0x14C;
    cases.push(("WrongMachine-i386", b.build()));
    let mut b = Builder::new();
    b.magic = 0x10B;
    cases.push(("NotPe32Plus-pe32", b.build()));
    let mut f = good.clone();
    f[0x44 + 19] |= 0x20;
    cases.push(("NotExecutable-dll", f));
    let mut b = Builder::new();
    b.image_base = 0x1_4000_1000;
    cases.push(("BadOptionalHeader-base-unaligned", b.build()));
    let mut b = Builder::new();
    b.image_base = 0x7FFF_FFFF_0000;
    cases.push(("BadOptionalHeader-image-past-user-half", b.build()));
    let mut f = good.clone();
    f[0x44 + 20 + 108..0x44 + 20 + 112].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    cases.push(("BadOptionalHeader-huge-directory-count", f));
    let mut b = Builder::new();
    b.sections.clear();
    cases.push(("BadSectionCount-none", b.build()));
    let mut f = good.clone();
    f[0x44 + 2..0x44 + 4].copy_from_slice(&97u16.to_le_bytes());
    cases.push(("BadSectionCount-97", f));
    let mut b = Builder::new();
    b.sections[1].1 = 0x1000;
    cases.push(("BadSection-overlap", b.build()));
    let mut b = Builder::new();
    b.sections[1].2 = 0x3000;
    cases.push(("BadSection-past-image", b.build()));
    let mut b = Builder::new();
    b.sections[1].4 = R | W | X;
    cases.push(("BadSection-wx", b.build()));
    let mut f = good.clone();
    let table = 0x44 + 20 + 240;
    f[table + 40 + 20..table + 40 + 24].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
    cases.push(("BadSection-raw-past-file", f));
    let mut b = Builder::new();
    b.entry = 0x2000;
    cases.push(("BadEntryPoint-in-data", b.build()));
    let mut b = Builder::new();
    b.dirs[DIR_IMPORT] = (0x3000, 0x2000);
    cases.push(("BadDirectory-import-past-image", b.build()));
    let mut b = with_imports_and_relocs();
    b.sections[1].3[0x80..0x200].fill(b'a');
    cases.push(("BadName-dll-name-unterminated", b.build()));
    let mut b = with_imports_and_relocs();
    b.dirs[DIR_IMPORT].1 = 20;
    cases.push(("BadReference-no-null-descriptor", b.build()));
    let mut b = with_imports_and_relocs();
    b.sections[1].3[0x40..0x48].copy_from_slice(&0x7FFF_0000u64.to_le_bytes());
    cases.push(("BadReference-hint-name-outside", b.build()));
    let mut b = with_imports_and_relocs();
    b.sections[1].3[0x108..0x10A].copy_from_slice(&((3u16 << 12) | 4).to_le_bytes());
    cases.push(("UnsupportedRelocation_3_-highlow", b.build()));
    let mut b = with_imports_and_relocs();
    b.sections[1].3[0x104..0x108].copy_from_slice(&4u32.to_le_bytes());
    cases.push(("BadRelocation-block-too-small", b.build()));
    let mut b = with_imports_and_relocs();
    b.sections[1].3[0x100..0x104].copy_from_slice(&0x9000u32.to_le_bytes());
    cases.push(("BadRelocation-page-outside", b.build()));
    cases.push(("TooManyImports-shared-tables", shared_import_tables()));
    for (stem, data) in cases {
        std::fs::write(dir.join(std::format!("{stem}.exe")), data).unwrap();
    }
}
