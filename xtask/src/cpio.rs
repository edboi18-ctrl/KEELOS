//! Writer for cpio "newc" archives, the initramfs format (decision D5).
//!
//! Format reference: cpio(5), "New ASCII Format" (also documented in the
//! Linux kernel's `Documentation/driver-api/early-userspace/buffer-format.rst`):
//! each member is a 110-byte ASCII header (the magic `070701` followed by
//! thirteen 8-digit hexadecimal fields), the NUL-terminated name padded so
//! that header plus name is a multiple of 4 bytes, then the data padded to
//! a multiple of 4 bytes. The archive ends with a member named
//! `TRAILER!!!`.
//!
//! The output depends only on the member names and contents (SR-30):
//! members are sorted, timestamps and owner IDs are zero, and inode
//! numbers are assigned in order.

use std::collections::BTreeMap;
use std::path::Path;

use crate::util::Result;

const S_IFDIR: u32 = 0o040000; // directory (inode(7))
const S_IFREG: u32 = 0o100000; // regular file

/// An archive under construction: path -> file contents, or `None` for a
/// directory. `BTreeMap` keeps members in a deterministic order in which
/// every directory precedes its contents.
#[derive(Default)]
pub struct Archive {
    members: BTreeMap<String, Option<Vec<u8>>>,
    /// Permission bits given explicitly (`add_file_mode`), instead of the
    /// rule in `to_bytes`.
    modes: BTreeMap<String, u32>,
}

impl Archive {
    /// Adds every file and directory below `dir` (which may be absent).
    pub fn add_tree(&mut self, dir: &Path) -> Result<()> {
        if dir.is_dir() {
            self.add_dir_entries(dir, "")?;
        }
        Ok(())
    }

    /// Adds one file, and its parent directories, at `path`.
    pub fn add_file(&mut self, path: &str, data: Vec<u8>) {
        for (slash, _) in path.match_indices('/') {
            self.members
                .entry(path[..slash].to_string())
                .or_insert(None);
        }
        self.members.insert(path.to_string(), Some(data));
    }

    /// Adds one file with these permission bits, as a tar member has them.
    pub fn add_file_mode(&mut self, path: &str, data: Vec<u8>, mode: u32) {
        self.add_file(path, data);
        self.modes.insert(path.to_string(), mode & 0o777);
    }

    /// Adds a directory (and its parents).
    pub fn add_dir(&mut self, path: &str) {
        for (slash, _) in path.match_indices('/') {
            self.members
                .entry(path[..slash].to_string())
                .or_insert(None);
        }
        self.members.entry(path.to_string()).or_insert(None);
    }

    fn add_dir_entries(&mut self, dir: &Path, prefix: &str) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|n| format!("initramfs file name is not UTF-8: {n:?}"))?;
            let path = format!("{prefix}{name}");
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                self.members.insert(path.clone(), None);
                self.add_dir_entries(&entry.path(), &format!("{path}/"))?;
            } else if file_type.is_file() {
                self.members
                    .insert(path, Some(std::fs::read(entry.path())?));
            } else {
                return Err(format!(
                    "{}: only regular files and directories are supported in initramfs/",
                    entry.path().display()
                )
                .into());
            }
        }
        Ok(())
    }

    /// Serialises the archive.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for (inode, (name, contents)) in (1u32..).zip(&self.members) {
            let (mode, nlink, data): (u32, u32, &[u8]) = match contents {
                None => (S_IFDIR | 0o755, 2, &[]),
                Some(data) if self.modes.contains_key(name) => {
                    (S_IFREG | self.modes[name], 1, data)
                }
                // Programs and libraries (ELF, by their magic) are 0755, as
                // installed on Linux, so access(X_OK) and stat report them
                // executable; everything else 0644.
                Some(data) if data.starts_with(b"\x7fELF") => (S_IFREG | 0o755, 1, data),
                Some(data) => (S_IFREG | 0o644, 1, data),
            };
            write_member(&mut out, name, inode, mode, nlink, data)?;
        }
        write_member(&mut out, "TRAILER!!!", 0, 0, 1, &[])?;
        Ok(out)
    }
}

fn pad_to_4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn write_member(
    out: &mut Vec<u8>,
    name: &str,
    inode: u32,
    mode: u32,
    nlink: u32,
    data: &[u8],
) -> Result<()> {
    // The size fields are 32-bit; reject anything that would not fit.
    let file_size =
        u32::try_from(data.len()).map_err(|_| format!("{name}: larger than 4 GiB - 1"))?;
    let name_size = u32::try_from(name.len() + 1).map_err(|_| "member name too long")?;
    let fields: [u32; 13] = [
        inode, mode, 0, // uid
        0, // gid
        nlink, 0, // mtime
        file_size, 0, // devmajor
        0, // devminor
        0, // rdevmajor
        0, // rdevminor
        name_size, 0, // check (unused by the 070701 format)
    ];
    out.extend_from_slice(b"070701");
    for field in fields {
        out.extend_from_slice(format!("{field:08x}").as_bytes());
    }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    pad_to_4(out);
    out.extend_from_slice(data);
    pad_to_4(out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel's reader (`keel_core::cpio`) accepts what this writer
    /// produces, with the same names, kinds and contents.
    #[test]
    fn kernel_reader_reads_the_archive() {
        let mut archive = Archive::default();
        archive.add_file("test/startup", vec![1, 2, 3, 4, 5]);
        archive.add_file("etc/a/b", b"nested".to_vec());
        let bytes = archive.to_bytes().unwrap();
        let entries = keel_core::cpio::parse(&bytes).unwrap();
        let names: Vec<&[u8]> = entries.iter().map(|e| e.name).collect();
        assert_eq!(
            names,
            [&b"etc"[..], b"etc/a", b"etc/a/b", b"test", b"test/startup"]
        );
        assert_eq!(
            keel_core::cpio::find(&entries, b"test/startup"),
            Some(&[1u8, 2, 3, 4, 5][..])
        );
        assert_eq!(entries[0].kind, keel_core::cpio::Kind::Directory);
        assert_eq!(entries[2].permissions, 0o644);
    }

    #[test]
    fn single_file_archive_has_the_documented_layout() {
        let mut archive = Archive::default();
        archive.members.insert("etc".into(), None);
        archive
            .members
            .insert("etc/hello".into(), Some(b"hi!\n\n".to_vec()));
        let bytes = archive.to_bytes().unwrap();

        // Directory member: header (110) + "etc\0" (4) = 114, padded to 116.
        assert_eq!(
            &bytes[..110],
            b"070701\
              00000001000041ed0000000000000000\
              0000000200000000000000000000000000000000\
              00000000000000000000000400000000"
                .as_slice()
        );
        assert_eq!(&bytes[110..116], b"etc\0\0\0");

        // File member starts at 116: mode 0100644 = 0x81a4, size 5, name 10.
        let file = &bytes[116..];
        assert_eq!(&file[..6], b"070701");
        assert_eq!(&file[6..14], b"00000002");
        assert_eq!(&file[14..22], b"000081a4");
        assert_eq!(&file[54..62], b"00000005"); // filesize is the 7th field
        assert_eq!(&file[94..102], b"0000000a"); // namesize is the 12th field
        assert_eq!(&file[110..120], b"etc/hello\0");
        // 110 + 10 = 120 is already a multiple of 4; data follows directly.
        assert_eq!(&file[120..125], b"hi!\n\n");
        assert_eq!(&file[125..128], [0, 0, 0]);

        let trailer = &file[128..];
        assert_eq!(&trailer[110..121], b"TRAILER!!!\0");
        assert_eq!(bytes.len() % 4, 0);
    }

    #[test]
    fn output_is_deterministic_and_sorted() {
        let mut a = Archive::default();
        a.members.insert("b".into(), Some(vec![1]));
        a.members.insert("a".into(), Some(vec![2]));
        let mut b = Archive::default();
        b.members.insert("a".into(), Some(vec![2]));
        b.members.insert("b".into(), Some(vec![1]));
        let bytes = a.to_bytes().unwrap();
        assert_eq!(bytes, b.to_bytes().unwrap());
        assert_eq!(&bytes[110..112], b"a\0");
    }
}
