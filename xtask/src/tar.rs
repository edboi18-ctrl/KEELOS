//! Reader for the tar archives fixtures ship (`fixtures/busybox/testsuite.tar`),
//! to put their contents in the initramfs.
//!
//! Format reference: POSIX.1-2024 XCU `pax`, "ustar Interchange Format"
//! (512-byte headers: name at 0 (100 bytes), mode at 100, size at 124
//! (octal), chksum at 148, typeflag at 156, magic at 257, prefix at 345
//! (155 bytes); data in 512-byte blocks; two zero blocks at the end).
//! The checksum is the sum of the header's bytes with the chksum field
//! taken as spaces. The magic check takes "ustar" with either ending, so
//! GNU tar's output (the fixture's) reads the same.
//!
//! Only what the fixtures need is accepted: regular files (typeflag '0'
//! or NUL) and directories ('5'), with relative names that stay inside
//! the archive. Anything else (links, devices, GNU long names, pax
//! headers, `..` or an absolute name, a bad checksum) is an error, so an
//! archive that does not match what was reviewed is refused.

use crate::util::Result;

/// One member: its path (no trailing slash), its permission bits, and its
/// contents (None for a directory).
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub mode: u32,
    pub data: Option<Vec<u8>>,
}

fn octal(field: &[u8]) -> Result<u64> {
    let text = field
        .iter()
        .take_while(|&&b| b != 0)
        .copied()
        .collect::<Vec<u8>>();
    let text = std::str::from_utf8(&text)?.trim();
    if text.is_empty() {
        return Ok(0);
    }
    Ok(u64::from_str_radix(text, 8).map_err(|e| format!("bad octal field {text:?}: {e}"))?)
}

fn text(field: &[u8]) -> Result<String> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    Ok(String::from_utf8(field[..end].to_vec())?)
}

/// Reads every member of `archive`.
pub fn read(archive: &[u8]) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut at = 0;
    loop {
        let header = archive
            .get(at..at + 512)
            .ok_or("tar: archive ends without its end-of-archive blocks")?;
        if header.iter().all(|&b| b == 0) {
            return Ok(entries);
        }
        let recorded = octal(&header[148..156])?;
        let sum: u64 = header
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(b)
                }
            })
            .sum();
        if sum != recorded {
            return Err(format!("tar: header at {at}: checksum {recorded}, computed {sum}").into());
        }
        let mut path = text(&header[..100])?;
        if &header[257..262] == b"ustar" {
            let prefix = text(&header[345..500])?;
            if !prefix.is_empty() {
                path = format!("{prefix}/{path}");
            }
        }
        let path = path.trim_end_matches('/').to_string();
        if path.is_empty()
            || path.starts_with('/')
            || path.split('/').any(|part| part == ".." || part.is_empty())
        {
            return Err(format!("tar: member name {path:?} is not a plain relative path").into());
        }
        let mode = u32::try_from(octal(&header[100..108])? & 0o7777)?;
        let size = usize::try_from(octal(&header[124..136])?)?;
        let start = at + 512;
        let data = match header[156] {
            b'0' | 0 => Some(
                archive
                    .get(start..start + size)
                    .ok_or_else(|| format!("tar: {path}: data past the end"))?
                    .to_vec(),
            ),
            b'5' if size == 0 => None,
            other => {
                return Err(format!(
                    "tar: {path}: member type {:?} is not a regular file or directory",
                    other as char
                )
                .into());
            }
        };
        entries.push(Entry { path, mode, data });
        at = start + size.div_ceil(512) * 512;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, mode: u32, size: usize, kind: u8) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
        h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        h[156] = kind;
        h[257..263].copy_from_slice(b"ustar\0");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }

    fn archive(members: &[(&str, u32, u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, mode, kind, data) in members {
            out.extend(header(name, *mode, data.len(), *kind));
            out.extend(*data);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.extend([0u8; 1024]);
        out
    }

    #[test]
    fn reads_files_and_directories_with_their_modes() {
        let tar = archive(&[
            ("d/", 0o755, b'5', b""),
            ("d/run", 0o755, b'0', b"#!/bin/sh\n"),
        ]);
        assert_eq!(
            read(&tar).unwrap(),
            vec![
                Entry {
                    path: "d".into(),
                    mode: 0o755,
                    data: None
                },
                Entry {
                    path: "d/run".into(),
                    mode: 0o755,
                    data: Some(b"#!/bin/sh\n".to_vec())
                },
            ]
        );
    }

    #[test]
    fn refuses_what_was_not_reviewed() {
        // A symbolic link, an escaping name, an absolute name.
        for (name, kind) in [("l", b'2'), ("../x", b'0'), ("/etc/x", b'0')] {
            assert!(
                read(&archive(&[(name, 0o644, kind, b"")])).is_err(),
                "{name}"
            );
        }
        // A damaged header.
        let mut tar = archive(&[("f", 0o644, b'0', b"x")]);
        tar[0] = b'g';
        assert!(read(&tar).is_err());
        // No end-of-archive blocks.
        let tar = archive(&[("f", 0o644, b'0', b"x")]);
        assert!(read(&tar[..1024]).is_err());
    }
}
