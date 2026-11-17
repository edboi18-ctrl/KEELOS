//! Fetches the pinned Limine release and verifies it (P0-T2, SR-29).
//!
//! Trust chain: the archive below is the upstream binary release asset.
//! Its detached GPG signature (`limine-binary.tar.gz.sig`) was verified
//! once, when the pin was made, against the Limine release key
//! 05D29860D0A0668AAEFB9D691F3C021BECA23821 (see docs/DEPENDENCIES.md).
//! From then on the build trusts only the SHA-256 values in this file, so
//! a changed or substituted download fails the build.
//!
//! Downloading and extraction are in `fetch.rs` (ADR 0001).

use std::path::PathBuf;

use crate::fetch;
use crate::util::Result;

pub const VERSION: &str = "12.9.6";
const ARCHIVE_URL: &str =
    "https://github.com/limine-bootloader/limine/releases/download/v12.9.6/limine-binary.tar.gz";
const ARCHIVE_SHA256: &str = "b38aabb042b0c0f9f562b7741be3c1204838d7bbacfa78bb411c674bd5b984ee";

/// Files taken from the archive, with the SHA-256 each must have.
const BOOTX64_EFI: (&str, &str) = (
    "limine-binary/BOOTX64.EFI",
    "e486ae7abd7d5b88f98f43cfd6e8f9057ff975ecd667dfb33f1581de36e00982",
);
const LICENSE: (&str, &str) = (
    "limine-binary/LICENSE",
    "5372ada69c825812b93b9e3f222253be3919bed3489372e797c9a85cd4e37fbc",
);

/// Paths of the verified Limine files in the local cache.
pub struct Limine {
    /// The x86-64 UEFI loader, installed as `EFI/BOOT/BOOTX64.EFI`.
    pub bootx64_efi: PathBuf,
    /// Limine's license text, shipped with releases.
    pub license: PathBuf,
}

/// Returns the verified Limine files, downloading the pinned release into
/// `target/keel-cache/` if they are not already there.
pub fn ensure() -> Result<Limine> {
    let cache = fetch::cache_dir(&format!("limine-{VERSION}"));
    let limine = Limine {
        bootx64_efi: cache.join(BOOTX64_EFI.0),
        license: cache.join(LICENSE.0),
    };
    let all_verified = || {
        fetch::verified(&limine.bootx64_efi, BOOTX64_EFI.1)
            && fetch::verified(&limine.license, LICENSE.1)
    };
    if all_verified() {
        return Ok(limine);
    }
    let archive = cache.join("limine-binary.tar.gz");
    fetch::download(ARCHIVE_URL, ARCHIVE_SHA256, &archive)?;
    // The archive was verified above, so its member paths are the known
    // upstream ones. Only the two files we use are extracted.
    fetch::extract(&archive, &cache, &[BOOTX64_EFI.0, LICENSE.0])?;
    if !all_verified() {
        return Err("extracted Limine files do not match their pinned SHA-256".into());
    }
    Ok(limine)
}
