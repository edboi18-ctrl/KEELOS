//! Reader for cpio "newc" archives, the initramfs format (decision D5;
//! first part of P1-T12).
//!
//! Format: cpio(5), "New ASCII Format", and Linux
//! `Documentation/driver-api/early-userspace/buffer-format.rst`. Each
//! member is a 110-byte header (magic `070701` and thirteen 8-digit
//! hexadecimal fields), the NUL-terminated name padded so that header plus
//! name is a multiple of 4, then the data padded to a multiple of 4. The
//! archive ends with a member named `TRAILER!!!`. `xtask/src/cpio.rs` is
//! the matching writer.
//!
//! The archive is pinned by hash in `limine.conf` (SR-27), but it is
//! still parsed as untrusted bytes: every field is checked, and an archive
//! that is malformed anywhere, or lacks the trailer, is refused as a whole.

use alloc::vec::Vec;

const MAGIC: &[u8; 6] = b"070701";
const HEADER_LEN: usize = 110;
const TRAILER: &[u8] = b"TRAILER!!!";

/// File type bits of `c_mode` (inode(7)).
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpioError {
    /// A header, name or data runs past the end, or the trailer is missing.
    Truncated,
    /// Wrong magic or a field that is not 8 hexadecimal digits.
    BadHeader,
    /// Empty name, name without its NUL, or a NUL inside it.
    BadName,
}

/// What a member is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    /// Symbolic links, devices and the rest; listed, but not supported yet.
    Other,
}

/// One member of an archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    /// Path inside the archive, without leading `/` or `./`.
    pub name: &'a [u8],
    pub kind: Kind,
    /// Permission bits (`c_mode & 0o7777`).
    pub permissions: u32,
    pub data: &'a [u8],
}

fn hex_field(header: &[u8], index: usize) -> Result<u32, CpioError> {
    let start = 6 + index * 8;
    let digits = header.get(start..start + 8).ok_or(CpioError::Truncated)?;
    let mut value = 0u32;
    for &digit in digits {
        let nibble = match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => return Err(CpioError::BadHeader),
        };
        value = value << 4 | u32::from(nibble);
    }
    Ok(value)
}

/// Parses a whole archive. Members come back in archive order; the
/// trailer is not included.
pub fn parse(bytes: &[u8]) -> Result<Vec<Entry<'_>>, CpioError> {
    let mut entries = Vec::new();
    let mut at = 0usize;
    loop {
        let header_end = at.checked_add(HEADER_LEN).ok_or(CpioError::Truncated)?;
        let header = bytes.get(at..header_end).ok_or(CpioError::Truncated)?;
        if &header[..6] != MAGIC {
            return Err(CpioError::BadHeader);
        }
        // Fields: ino, mode, uid, gid, nlink, mtime, filesize, devmajor,
        // devminor, rdevmajor, rdevminor, namesize, check.
        let mode = hex_field(header, 1)?;
        let file_size = hex_field(header, 6)? as usize;
        let name_size = hex_field(header, 11)? as usize;
        for index in [0, 2, 3, 4, 5, 7, 8, 9, 10, 12] {
            hex_field(header, index)?;
        }
        if name_size < 2 {
            return Err(CpioError::BadName);
        }
        let name_end = header_end
            .checked_add(name_size)
            .ok_or(CpioError::Truncated)?;
        let name_with_nul = bytes
            .get(header_end..name_end)
            .ok_or(CpioError::Truncated)?;
        let (name, nul) = name_with_nul.split_at(name_size - 1);
        if nul != [0] || name.contains(&0) {
            return Err(CpioError::BadName);
        }
        let data_start = name_end.next_multiple_of(4);
        let data_end = data_start
            .checked_add(file_size)
            .ok_or(CpioError::Truncated)?;
        let data = bytes
            .get(data_start..data_end)
            .ok_or(CpioError::Truncated)?;
        if name == TRAILER {
            return Ok(entries);
        }
        let name = name
            .strip_prefix(b"./")
            .or_else(|| name.strip_prefix(b"/"))
            .unwrap_or(name);
        if name.is_empty() {
            return Err(CpioError::BadName);
        }
        let kind = match mode & S_IFMT {
            S_IFREG => Kind::File,
            S_IFDIR => Kind::Directory,
            _ => Kind::Other,
        };
        entries.push(Entry {
            name,
            kind,
            permissions: mode & 0o7777,
            data,
        });
        at = data_end.next_multiple_of(4);
    }
}

/// The regular file at `path` (no leading `/`), if present.
pub fn find<'a>(entries: &[Entry<'a>], path: &[u8]) -> Option<&'a [u8]> {
    entries
        .iter()
        .find(|e| e.kind == Kind::File && e.name == path)
        .map(|e| e.data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    /// Same layout as `xtask/src/cpio.rs::write_member`.
    fn member(out: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
        let fields = [
            1,
            mode,
            0,
            0,
            1,
            0,
            data.len() as u32,
            0,
            0,
            0,
            0,
            name.len() as u32 + 1,
            0,
        ];
        out.extend_from_slice(MAGIC);
        for field in fields {
            out.extend_from_slice(format!("{field:08x}").as_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(data);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    fn sample() -> Vec<u8> {
        let mut out = Vec::new();
        member(&mut out, "etc", S_IFDIR | 0o755, &[]);
        member(&mut out, "etc/hostname", S_IFREG | 0o644, b"keel\n");
        member(&mut out, "./test/startup", S_IFREG | 0o755, &[1, 2, 3]);
        member(&mut out, "TRAILER!!!", 0, &[]);
        out
    }

    #[test]
    fn reads_members_in_order() {
        let bytes = sample();
        let entries = parse(&bytes).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].kind, Kind::Directory);
        assert_eq!(entries[0].permissions, 0o755);
        assert_eq!(find(&entries, b"etc/hostname"), Some(&b"keel\n"[..]));
        assert_eq!(find(&entries, b"test/startup"), Some(&[1u8, 2, 3][..]));
        assert_eq!(find(&entries, b"etc"), None, "directories are not files");
        assert_eq!(find(&entries, b"missing"), None);
    }

    #[test]
    fn refuses_malformed_archives() {
        let good = sample();
        assert_eq!(parse(&good[..good.len() - 4]), Err(CpioError::Truncated));
        assert_eq!(parse(&[]), Err(CpioError::Truncated));
        let mut bad = good.clone();
        bad[5] = b'2'; // 070702 (with checksums) is not produced or read
        assert_eq!(parse(&bad), Err(CpioError::BadHeader));
        let mut bad = good.clone();
        bad[6 + 8 + 3] = b'g'; // non-hex digit in c_mode
        assert_eq!(parse(&bad), Err(CpioError::BadHeader));
        let mut bad = good.clone();
        bad[HEADER_LEN + 3] = 0xff; // name "etc" no longer NUL-terminated
        assert_eq!(parse(&bad), Err(CpioError::BadName));
        let mut out = Vec::new();
        member(&mut out, "a\0b", S_IFREG, b"x");
        member(&mut out, "TRAILER!!!", 0, &[]);
        assert_eq!(parse(&out), Err(CpioError::BadName));
        let mut out = Vec::new();
        member(&mut out, "big", S_IFREG, &[0; 8]);
        out[6 + 6 * 8..6 + 7 * 8].copy_from_slice(b"ffffffff");
        assert_eq!(parse(&out), Err(CpioError::Truncated));
    }

    #[test]
    fn random_inputs_never_panic() {
        let mut state = 0xD1B5_4A32_D192_ED03u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let template = sample();
        for round in 0..20_000 {
            let mut bytes = template.clone();
            if round % 3 == 0 {
                bytes.truncate((next() as usize) % (template.len() + 1));
            }
            for _ in 0..(next() % 4) {
                let at = (next() as usize) % bytes.len().max(1);
                if let Some(byte) = bytes.get_mut(at) {
                    *byte = next() as u8;
                }
            }
            if let Ok(entries) = parse(&bytes) {
                for e in entries {
                    assert!(!e.name.is_empty() && !e.name.contains(&0));
                }
            }
        }
    }
}
