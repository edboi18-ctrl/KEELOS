//! Downloading pinned build inputs (SR-29).
//!
//! A download is accepted only if its SHA-256 equals the value pinned in
//! this repository. Integrity therefore does not rest on TLS, on the
//! server, or on `curl`; they only have to deliver the bytes. The tools
//! used are `curl` and `tar`, which ship with Windows 10 1803+ (ADR 0001).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::util::{self, Result};

/// Whether `path` exists and has the given SHA-256.
pub fn verified(path: &Path, expected_sha256: &str) -> bool {
    std::fs::read(path).is_ok_and(|data| util::sha256_hex(&data) == expected_sha256)
}

/// Directory for verified downloads: `target/keel-cache/<name>`.
pub fn cache_dir(name: &str) -> PathBuf {
    util::workspace_root()
        .join("target")
        .join("keel-cache")
        .join(name)
}

/// Makes sure `dest` holds the file at `url` with the pinned SHA-256,
/// downloading it if needed. A download with the wrong hash is deleted.
pub fn download(url: &str, expected_sha256: &str, dest: &Path) -> Result<()> {
    if verified(dest, expected_sha256) {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    println!("xtask: downloading {url}");
    util::run(
        Command::new("curl")
            .args(["--fail", "--location", "--silent", "--show-error"])
            .args(["--proto", "=https", "--tlsv1.2"])
            .arg("--output")
            .arg(dest)
            .arg(url),
    )
    .map_err(|e| format!("{e}\nhint: `curl` must be on PATH (it ships with Windows 10 1803+)"))?;
    let actual = util::sha256_hex(&util::read(dest)?);
    if actual != expected_sha256 {
        // Do not leave an unverified file where a later run could mistake
        // it for a good one.
        let _ = std::fs::remove_file(dest);
        return Err(format!(
            "checksum mismatch for {url}\n  expected {expected_sha256}\n  actual   {actual}"
        )
        .into());
    }
    Ok(())
}

/// Extracts the named members of a verified `.tar.gz` into `dest_dir`.
pub fn extract(archive: &Path, dest_dir: &Path, members: &[&str]) -> Result<()> {
    util::run(
        Command::new("tar")
            .arg("-xzf")
            .arg(archive)
            .arg("-C")
            .arg(dest_dir)
            .args(members),
    )
    .map_err(|e| {
        format!("{e}\nhint: `tar` must be on PATH (it ships with Windows 10 1803+)").into()
    })
}
