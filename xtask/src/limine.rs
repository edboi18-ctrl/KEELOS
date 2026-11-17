//! Fetches the pinned Limine release and verifies it (P0-T2, SR-29).
//!
//! Trust chain: the archive below is the upstream binary release asset.
//! Its detached GPG signature (`limine-binary.tar.gz.sig`) was verified
//! once, when the pin was made, against the Limine release key
//! 05D29860D0A0668AAEFB9D691F3C021BECA23821 (see docs/DEPENDENCIES.md).
//! From then on the build trusts only the SHA-256 values in this file, so
//! a changed or substituted download fails the build.
//!
//! The download and extraction use `curl` and `tar`. Both ship with
//! Windows 10 (1803 and later) and with every Linux CI image, so this
//! needs no Unix tools on the Windows host (ADR 0001).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::util::{self, Result};

pub const VERSION: &str = "12.9.6";
const ARCHIVE_URL: &str =
    "https://github.com/limine-bootloader/limine/releases/download/v12.9.6/limine-binary.tar.gz";
const ARCHIVE_SHA256: &str = "b38aabb042b0c0f9f562b7741be3c1204838d7bbacfa78bb411c674bd5b984ee";

/// Files taken from the archive, with the SHA-256 each must have.
const BOOTX64_EFI: (&str, &str) = (
    "BOOTX64.EFI",
    "e486ae7abd7d5b88f98f43cfd6e8f9057ff975ecd667dfb33f1581de36e00982",
);
const LICENSE: (&str, &str) = (
    "LICENSE",
    "5372ada69c825812b93b9e3f222253be3919bed3489372e797c9a85cd4e37fbc",
);

/// Paths of the verified Limine files in the local cache.
pub struct Limine {
    /// The x86-64 UEFI loader, installed as `EFI/BOOT/BOOTX64.EFI`.
    pub bootx64_efi: PathBuf,
    /// Limine's license text, shipped with releases.
    pub license: PathBuf,
}

fn verified(path: &Path, expected_sha256: &str) -> bool {
    std::fs::read(path).is_ok_and(|data| util::sha256_hex(&data) == expected_sha256)
}

/// Returns the verified Limine files, downloading the pinned release into
/// `target/keel-cache/` if they are not already there.
pub fn ensure() -> Result<Limine> {
    let cache = util::workspace_root()
        .join("target")
        .join("keel-cache")
        .join(format!("limine-{VERSION}"));
    let unpacked = cache.join("limine-binary");
    let limine = Limine {
        bootx64_efi: unpacked.join(BOOTX64_EFI.0),
        license: unpacked.join(LICENSE.0),
    };
    if verified(&limine.bootx64_efi, BOOTX64_EFI.1) && verified(&limine.license, LICENSE.1) {
        return Ok(limine);
    }

    std::fs::create_dir_all(&cache)?;
    let archive = cache.join("limine-binary.tar.gz");
    if !verified(&archive, ARCHIVE_SHA256) {
        println!("xtask: downloading Limine {VERSION}");
        util::run(
            Command::new("curl")
                .args(["--fail", "--location", "--silent", "--show-error"])
                .args(["--proto", "=https", "--tlsv1.2"])
                .arg("--output")
                .arg(&archive)
                .arg(ARCHIVE_URL),
        )
        .map_err(|e| {
            format!("{e}\nhint: `curl` must be on PATH (it ships with Windows 10 1803+)")
        })?;
        let actual = util::sha256_hex(&util::read(&archive)?);
        if actual != ARCHIVE_SHA256 {
            // Do not leave an unverified file where a later run could
            // mistake it for a good one.
            let _ = std::fs::remove_file(&archive);
            return Err(format!(
                "Limine archive checksum mismatch\n  expected {ARCHIVE_SHA256}\n  actual   {actual}"
            )
            .into());
        }
    }

    // Extract only the two files we use. The archive was verified above,
    // so its member paths are the known upstream ones.
    util::run(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&cache)
            .arg(format!("limine-binary/{}", BOOTX64_EFI.0))
            .arg(format!("limine-binary/{}", LICENSE.0)),
    )
    .map_err(|e| format!("{e}\nhint: `tar` must be on PATH (it ships with Windows 10 1803+)"))?;

    for (path, (name, sha256)) in [
        (&limine.bootx64_efi, BOOTX64_EFI),
        (&limine.license, LICENSE),
    ] {
        if !verified(path, sha256) {
            return Err(format!("Limine file {name} does not match its pinned SHA-256").into());
        }
    }
    Ok(limine)
}
