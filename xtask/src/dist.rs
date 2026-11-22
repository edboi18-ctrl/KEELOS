//! `cargo xtask dist`: release artifacts (P0-T8, decision D14).
//!
//! Produces, in `target/dist/`:
//!   - `keel-<version>-esp.zip`      the boot tree, to extract onto a FAT32 stick
//!   - `keel-<version>.img`          the same tree in a raw GPT disk image
//!   - `keel-<version>-notices.zip`  license texts of everything shipped
//!   - `SHA256SUMS`                  checksums of the three files above
//!
//! Everything is written by this program into ordinary files. It never
//! opens a physical disk and needs no host disk tools. The output depends
//! only on the input bytes and the version string (SR-30): no timestamps,
//! and all identifiers are derived from a hash of the contents.

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::build::{self, BootMode, BootTree};
use crate::util::{self, Result};
use crate::{limine, qemu};

const SECTOR: usize = 512;
const MIB: usize = 1024 * 1024;

// ---- CRC-32 ---------------------------------------------------------------

/// CRC-32 as used by both ZIP and GPT: polynomial 0x04C11DB7 in its
/// reflected form 0xEDB88320, initial value and final XOR 0xFFFFFFFF
/// (ZIP APPNOTE.TXT section 4.4.7; UEFI specification, "GPT Header").
/// Check value: `crc32(b"123456789") == 0xCBF43926`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ---- ZIP ------------------------------------------------------------------

/// MS-DOS date for 1980-01-01 (day 1, month 1, year 1980 - 1980 = 0), the
/// earliest date the format can express (APPNOTE.TXT section 4.4.6).
const DOS_DATE_1980: u16 = (1 << 5) | 1;

/// Writes an uncompressed ("stored") ZIP archive.
///
/// Layout per PKWARE APPNOTE.TXT 6.3: a local file header and the data for
/// each member (section 4.3.7), then the central directory (4.3.12), then
/// the end-of-central-directory record (4.3.16). ZIP64 is not produced;
/// inputs that would need it are rejected.
pub fn zip_stored(files: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let too_big = || "archive too large for a ZIP file without ZIP64";
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let offset = u32::try_from(out.len()).map_err(|_| too_big())?;
        let size = u32::try_from(data.len()).map_err(|_| too_big())?;
        let name_len = u16::try_from(name.len()).map_err(|_| "ZIP member name too long")?;
        let crc = crc32(data);

        // Fields shared by the local header and the central directory.
        let mut common = Vec::new();
        common.extend_from_slice(&10u16.to_le_bytes()); // version needed: 1.0
        common.extend_from_slice(&0u16.to_le_bytes()); // general purpose flags
        common.extend_from_slice(&0u16.to_le_bytes()); // method 0: stored
        common.extend_from_slice(&0u16.to_le_bytes()); // time 00:00:00
        common.extend_from_slice(&DOS_DATE_1980.to_le_bytes());
        common.extend_from_slice(&crc.to_le_bytes());
        common.extend_from_slice(&size.to_le_bytes()); // compressed size
        common.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        common.extend_from_slice(&name_len.to_le_bytes());
        common.extend_from_slice(&0u16.to_le_bytes()); // extra field length

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&common);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&10u16.to_le_bytes()); // version made by: 1.0, MS-DOS
        central.extend_from_slice(&common);
        central.extend_from_slice(&0u16.to_le_bytes()); // comment length
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let central_offset = u32::try_from(out.len()).map_err(|_| too_big())?;
    let central_size = u32::try_from(central.len()).map_err(|_| too_big())?;
    let count = u16::try_from(files.len()).map_err(|_| "too many ZIP members")?;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with central directory
    out.extend_from_slice(&count.to_le_bytes()); // entries on this disk
    out.extend_from_slice(&count.to_le_bytes()); // entries in total
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    Ok(out)
}

// ---- GPT ------------------------------------------------------------------

/// EFI System Partition type GUID, C12A7328-F81F-11D2-BA4B-00A0C93EC93B,
/// in its on-disk encoding: the first three groups are little-endian, the
/// rest is stored as written (UEFI specification, "GPT Partition Entry"
/// and Appendix A, "GUID and Time Formats").
const ESP_TYPE_GUID: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

const GPT_ENTRY_COUNT: usize = 128;
const GPT_ENTRY_SIZE: usize = 128;
/// Sectors taken by the partition entry array: 128 * 128 / 512.
const GPT_ENTRY_SECTORS: usize = GPT_ENTRY_COUNT * GPT_ENTRY_SIZE / SECTOR;
/// First LBA of the system partition: 1 MiB, the conventional alignment.
const ESP_FIRST_LBA: usize = MIB / SECTOR;

/// Derives a stable identifier from the image contents, formatted as a
/// version-4, variant-1 UUID (RFC 4122 section 4.4) so tools accept it.
fn derived_guid(label: &str, content_hash: &str) -> [u8; 16] {
    let digest = util::sha256_hex(format!("{label}:{content_hash}").as_bytes());
    let mut guid = [0u8; 16];
    for (i, byte) in guid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[i * 2..i * 2 + 2], 16).expect("hex digest");
    }
    // In the on-disk layout the version nibble is the high nibble of byte
    // 7 (the top of the little-endian third group); the variant bits are
    // the top of byte 8.
    guid[7] = (guid[7] & 0x0F) | 0x40;
    guid[8] = (guid[8] & 0x3F) | 0x80;
    guid
}

fn gpt_header(
    my_lba: u64,
    alternate_lba: u64,
    entries_lba: u64,
    last_usable_lba: u64,
    disk_guid: &[u8; 16],
    entries_crc: u32,
) -> [u8; SECTOR] {
    // UEFI specification, "GPT Header" (table of the same name).
    let mut header = [0u8; SECTOR];
    header[0..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision 1.0
    header[12..16].copy_from_slice(&92u32.to_le_bytes()); // header size
    // 16..20: header CRC32, filled in below; 20..24 reserved (zero).
    header[24..32].copy_from_slice(&my_lba.to_le_bytes());
    header[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
    let first_usable_lba = (2 + GPT_ENTRY_SECTORS) as u64;
    header[40..48].copy_from_slice(&first_usable_lba.to_le_bytes());
    header[48..56].copy_from_slice(&last_usable_lba.to_le_bytes());
    header[56..72].copy_from_slice(disk_guid);
    header[72..80].copy_from_slice(&entries_lba.to_le_bytes());
    header[80..84].copy_from_slice(&(GPT_ENTRY_COUNT as u32).to_le_bytes());
    header[84..88].copy_from_slice(&(GPT_ENTRY_SIZE as u32).to_le_bytes());
    header[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    let crc = crc32(&header[..92]); // computed with the CRC field zero
    header[16..20].copy_from_slice(&crc.to_le_bytes());
    header
}

/// Builds a raw disk image: protective MBR, GPT, and one FAT32 EFI System
/// Partition holding `tree`.
pub fn disk_image(tree: &BootTree) -> Result<Vec<u8>> {
    // Size the partition: at least 64 MiB so that FAT32 is valid (FAT32
    // needs at least 65525 clusters; Microsoft "FAT32 File System
    // Specification", "FAT Type Determination"), and at least twice the
    // payload so directories and cluster rounding always fit.
    let payload: usize = tree.files.iter().map(|(_, data)| data.len()).sum();
    let esp_bytes = (payload * 2).max(64 * MIB).next_multiple_of(MIB);
    let esp_sectors = esp_bytes / SECTOR;
    // Leading 1 MiB for the MBR and primary GPT, trailing 1 MiB for the
    // backup GPT (which needs only 33 sectors).
    let total_sectors = ESP_FIRST_LBA + esp_sectors + MIB / SECTOR;
    if total_sectors > u32::MAX as usize {
        return Err("disk image would exceed 2 TiB".into());
    }
    let mut image = vec![0u8; total_sectors * SECTOR];
    let last_lba = (total_sectors - 1) as u64;

    let content_hash = {
        let mut all = Vec::new();
        for (path, data) in &tree.files {
            all.extend_from_slice(path.as_bytes());
            all.extend_from_slice(util::sha256_hex(data).as_bytes());
        }
        util::sha256_hex(&all)
    };

    // FAT32 file system inside the partition.
    let esp_range = ESP_FIRST_LBA * SECTOR..(ESP_FIRST_LBA + esp_sectors) * SECTOR;
    {
        let volume_id = u32::from_str_radix(&content_hash[..8], 16).expect("hex digest");
        let partition = &mut image[esp_range.clone()];
        fatfs::format_volume(
            Cursor::new(&mut *partition),
            fatfs::FormatVolumeOptions::new()
                .fat_type(fatfs::FatType::Fat32)
                .volume_id(volume_id)
                .volume_label(*b"KEEL       "),
        )?;
        let fs = fatfs::FileSystem::new(Cursor::new(&mut *partition), fatfs::FsOptions::new())?;
        if fs.fat_type() != fatfs::FatType::Fat32 {
            return Err("system partition was not formatted as FAT32".into());
        }
        {
            let root = fs.root_dir();
            for (path, data) in &tree.files {
                let mut dir = root.clone();
                let mut parts = path.split('/').peekable();
                while let Some(part) = parts.next() {
                    if parts.peek().is_some() {
                        dir = dir.create_dir(part)?;
                    } else {
                        let mut file = dir.create_file(part)?;
                        file.truncate()?;
                        file.write_all(data)?;
                        file.flush()?;
                    }
                }
            }
        }
        fs.unmount()?;
    }

    // Protective MBR (UEFI specification, "Protective MBR"): one partition
    // of type 0xEE covering the disk after LBA 0.
    let mbr_entry = &mut image[446..462];
    mbr_entry[0] = 0x00; // not bootable
    mbr_entry[1..4].copy_from_slice(&[0x00, 0x02, 0x00]); // CHS of LBA 1
    mbr_entry[4] = 0xEE; // GPT protective
    mbr_entry[5..8].copy_from_slice(&[0xFF, 0xFF, 0xFF]); // CHS end: maximum
    mbr_entry[8..12].copy_from_slice(&1u32.to_le_bytes()); // starting LBA
    mbr_entry[12..16].copy_from_slice(&(last_lba as u32).to_le_bytes()); // size in LBA
    image[510] = 0x55;
    image[511] = 0xAA;

    // Partition entry array (UEFI specification, "GPT Partition Entry").
    let mut entries = vec![0u8; GPT_ENTRY_COUNT * GPT_ENTRY_SIZE];
    {
        let entry = &mut entries[..GPT_ENTRY_SIZE];
        entry[0..16].copy_from_slice(&ESP_TYPE_GUID);
        entry[16..32].copy_from_slice(&derived_guid("keel-esp", &content_hash));
        entry[32..40].copy_from_slice(&(ESP_FIRST_LBA as u64).to_le_bytes());
        let esp_last_lba = (ESP_FIRST_LBA + esp_sectors - 1) as u64;
        entry[40..48].copy_from_slice(&esp_last_lba.to_le_bytes());
        // 48..56: attributes, zero. 56..128: name, UTF-16LE, NUL padded.
        for (i, unit) in "EFI System".encode_utf16().enumerate() {
            entry[56 + i * 2..58 + i * 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    let entries_crc = crc32(&entries);
    let disk_guid = derived_guid("keel-disk", &content_hash);
    let backup_entries_lba = last_lba - GPT_ENTRY_SECTORS as u64;
    let last_usable_lba = backup_entries_lba - 1;

    let primary = gpt_header(1, last_lba, 2, last_usable_lba, &disk_guid, entries_crc);
    image[SECTOR..2 * SECTOR].copy_from_slice(&primary);
    image[2 * SECTOR..(2 + GPT_ENTRY_SECTORS) * SECTOR].copy_from_slice(&entries);

    let backup = gpt_header(
        last_lba,
        1,
        backup_entries_lba,
        last_usable_lba,
        &disk_guid,
        entries_crc,
    );
    let backup_entries_start = backup_entries_lba as usize * SECTOR;
    image[backup_entries_start..backup_entries_start + entries.len()].copy_from_slice(&entries);
    let backup_header_start = last_lba as usize * SECTOR;
    image[backup_header_start..].copy_from_slice(&backup);

    Ok(image)
}

// ---- The command ----------------------------------------------------------

/// Fails unless the git working tree has no uncommitted changes, so that a
/// release corresponds exactly to a commit.
fn require_clean_tree(root: &Path) -> Result<()> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["status", "--porcelain"])
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    if !output.status.success() {
        return Err("`git status` failed; is this a git checkout?".into());
    }
    if !output.stdout.is_empty() {
        return Err(format!(
            "the working tree has uncommitted changes:\n{}\
             commit them, or pass --allow-dirty for a local trial build",
            String::from_utf8_lossy(&output.stdout)
        )
        .into());
    }
    Ok(())
}

/// License texts for everything that ends up in the image: the project's
/// own licenses, Limine's, and those of the crates linked into the kernel.
fn notices(root: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut files = vec![
        (
            "keel/LICENSE-MIT".to_string(),
            util::read(&root.join("LICENSE-MIT"))?,
        ),
        (
            "keel/LICENSE-APACHE".to_string(),
            util::read(&root.join("LICENSE-APACHE"))?,
        ),
        (
            format!("limine-{}/LICENSE", limine::VERSION),
            util::read(&limine::ensure()?.license)?,
        ),
    ];
    // Crates linked into the kernel image (docs/DEPENDENCIES.md, "Kernel").
    for krate in ["spin", "font8x8"] {
        let dir = root.join("vendor").join(krate);
        let mut found = false;
        let mut names: Vec<_> = std::fs::read_dir(&dir)?
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| name.to_ascii_uppercase().starts_with("LICENSE"))
            .collect();
        names.sort();
        for name in names {
            files.push((format!("{krate}/{name}"), util::read(&dir.join(&name))?));
            found = true;
        }
        if !found {
            return Err(format!("no license text found for kernel crate {krate}").into());
        }
    }
    Ok(files)
}

/// Accepts versions like `0.1.0` or `0.1.0-rc.1`; they become file names.
pub fn validate_version(version: &str) -> Result<()> {
    let ok = !version.is_empty()
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && version.starts_with(|c: char| c.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(format!("invalid version {version:?}: use digits, letters, '.' and '-'").into())
    }
}

/// `cargo xtask dist [--version V] [--allow-dirty]`.
pub fn dist(version: Option<String>, allow_dirty: bool) -> Result<PathBuf> {
    let root = util::workspace_root();
    if !allow_dirty {
        require_clean_tree(&root)?;
    }
    let version = version.unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    validate_version(&version)?;

    let tree = build::build_tree(BootMode::Normal)?;
    let out = root.join("target").join("dist");
    if out.exists() {
        std::fs::remove_dir_all(&out)?;
    }

    let esp_members: Vec<(&str, &[u8])> = tree
        .files
        .iter()
        .map(|(path, data)| (*path, data.as_slice()))
        .collect();
    let notices = notices(&root)?;
    let notice_members: Vec<(&str, &[u8])> = notices
        .iter()
        .map(|(path, data)| (path.as_str(), data.as_slice()))
        .collect();

    let artifacts = [
        (format!("keel-{version}-esp.zip"), zip_stored(&esp_members)?),
        (format!("keel-{version}.img"), disk_image(&tree)?),
        (
            format!("keel-{version}-notices.zip"),
            zip_stored(&notice_members)?,
        ),
    ];
    let mut sums = String::new();
    for (name, data) in &artifacts {
        util::write(&out.join(name), data)?;
        // The format `sha256sum --check` reads: digest, two spaces, name.
        sums.push_str(&format!("{}  {name}\n", util::sha256_hex(data)));
    }
    util::write(&out.join("SHA256SUMS"), sums.as_bytes())?;

    println!("xtask: release artifacts in {}:", out.display());
    print!("{sums}");
    Ok(out)
}

/// `cargo xtask boot-check <image>`: boots a raw disk image headless and
/// passes once the kernel reports the end of a normal boot. This proves a
/// release image is bootable by real UEFI firmware code (OVMF).
pub fn boot_check(image: &Path, options: &qemu::RunOptions) -> Result<()> {
    qemu::boot_image_until(image, options, "Keel: nothing more to run yet")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn zip_has_the_documented_records() {
        let zip = zip_stored(&[("a/b.txt", b"hello")]).unwrap();
        // Local header: signature, then name at offset 30, then data.
        assert_eq!(&zip[0..4], b"PK\x03\x04");
        assert_eq!(&zip[14..18], crc32(b"hello").to_le_bytes());
        assert_eq!(&zip[18..22], 5u32.to_le_bytes());
        assert_eq!(&zip[26..28], 7u16.to_le_bytes());
        assert_eq!(&zip[30..37], b"a/b.txt");
        assert_eq!(&zip[37..42], b"hello");
        // Central directory starts right after; its name is at offset 46.
        assert_eq!(&zip[42..46], b"PK\x01\x02");
        assert_eq!(&zip[42 + 42..42 + 46], 0u32.to_le_bytes()); // local header offset
        assert_eq!(&zip[42 + 46..42 + 53], b"a/b.txt");
        // End record: 22 bytes, pointing at the central directory.
        let end = &zip[zip.len() - 22..];
        assert_eq!(&end[0..4], b"PK\x05\x06");
        assert_eq!(&end[10..12], 1u16.to_le_bytes());
        assert_eq!(&end[12..16], 53u32.to_le_bytes()); // central directory size
        assert_eq!(&end[16..20], 42u32.to_le_bytes()); // and its offset
    }

    fn sample_tree() -> BootTree {
        BootTree {
            files: vec![
                (build::EFI_PATH, vec![0xEF; 3000]),
                (build::CONFIG_PATH, b"timeout: 0\n".to_vec()),
                (build::KERNEL_PATH, vec![0x7F; 70_000]),
            ],
        }
    }

    #[test]
    fn disk_image_has_valid_gpt_structures() {
        let image = disk_image(&sample_tree()).unwrap();
        assert_eq!(image.len(), 66 * MIB);
        assert_eq!(&image[510..512], [0x55, 0xAA]);
        assert_eq!(image[450], 0xEE);

        let header = &image[SECTOR..2 * SECTOR];
        assert_eq!(&header[0..8], b"EFI PART");
        let mut zeroed = header[..92].to_vec();
        zeroed[16..20].fill(0);
        assert_eq!(header[16..20], crc32(&zeroed).to_le_bytes());
        let entries = &image[2 * SECTOR..34 * SECTOR];
        assert_eq!(header[88..92], crc32(entries).to_le_bytes());
        assert_eq!(&entries[0..16], &ESP_TYPE_GUID);
        assert_eq!(entries[32..40], 2048u64.to_le_bytes());

        // Backup header is the last sector and points back at the primary.
        let backup = &image[image.len() - SECTOR..];
        assert_eq!(&backup[0..8], b"EFI PART");
        assert_eq!(backup[32..40], 1u64.to_le_bytes());
        let last_lba = (image.len() / SECTOR - 1) as u64;
        assert_eq!(header[32..40], last_lba.to_le_bytes());
        assert_eq!(backup[24..32], last_lba.to_le_bytes());
    }

    #[test]
    fn disk_image_files_read_back_from_fat32() {
        let tree = sample_tree();
        let mut image = disk_image(&tree).unwrap();
        let partition = &mut image[MIB..65 * MIB];
        let fs = fatfs::FileSystem::new(Cursor::new(partition), fatfs::FsOptions::new()).unwrap();
        assert_eq!(fs.fat_type(), fatfs::FatType::Fat32);
        for (path, data) in &tree.files {
            let mut file = fs.root_dir().open_file(path).unwrap();
            let mut read_back = Vec::new();
            std::io::Read::read_to_end(&mut file, &mut read_back).unwrap();
            assert_eq!(&read_back, data, "{path}");
        }
    }

    #[test]
    fn artifacts_are_deterministic() {
        assert_eq!(
            disk_image(&sample_tree()).unwrap(),
            disk_image(&sample_tree()).unwrap()
        );
        let guid = derived_guid("keel-disk", "abc");
        assert_eq!(guid[7] >> 4, 4);
        assert_eq!(guid[8] >> 6, 0b10);
    }

    #[test]
    fn version_strings_are_restricted() {
        assert!(validate_version("0.1.0").is_ok());
        assert!(validate_version("0.1.0-rc.1").is_ok());
        assert!(validate_version("").is_err());
        assert!(validate_version("v0.1.0").is_err());
        assert!(validate_version("0.1/../x").is_err());
    }
}
