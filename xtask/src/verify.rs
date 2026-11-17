//! `cargo xtask verify <file>`: checks a downloaded release artifact
//! before it goes anywhere near real hardware (SR-35).
//!
//! Two independent checks, both required:
//!  1. the file's SHA-256 matches its line in the `SHA256SUMS` file that
//!     sits next to it;
//!  2. GitHub holds a build-provenance attestation for the file, signed by
//!     this repository's release workflow on a GitHub-hosted runner
//!     (`gh attestation verify`).
//!
//! The checksum alone proves nothing about origin, since `SHA256SUMS`
//! comes from the same download. The attestation is the trust anchor.

use std::path::Path;
use std::process::Command;

use crate::util::{self, Result};

/// The repository whose release workflow must have built the artifact.
/// A constant on purpose: the trust anchor must not come from local,
/// editable configuration such as a git remote.
pub const REPOSITORY: &str = "edboi18-ctrl/KEELOS";
const RELEASE_WORKFLOW: &str = "edboi18-ctrl/KEELOS/.github/workflows/release.yml";

/// Finds the digest recorded for `file_name` in `SHA256SUMS` text
/// (`sha256sum` format: 64 hex digits, two spaces, name).
pub fn expected_digest<'a>(sums: &'a str, file_name: &str) -> Option<&'a str> {
    sums.lines().find_map(|line| {
        let (digest, name) = line.split_once("  ")?;
        let valid = digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit());
        (valid && name == file_name).then_some(digest)
    })
}

pub fn verify(file: &Path) -> Result<()> {
    let file_name = file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("the artifact path has no UTF-8 file name")?;
    let data = util::read(file)?;

    let sums_path = file.with_file_name("SHA256SUMS");
    let sums = String::from_utf8(util::read(&sums_path).map_err(|e| {
        format!("{e}\nhint: download SHA256SUMS from the same release into the same folder")
    })?)?;
    let expected = expected_digest(&sums, file_name)
        .ok_or_else(|| format!("{file_name} is not listed in {}", sums_path.display()))?;
    let actual = util::sha256_hex(&data);
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(format!(
            "CHECKSUM MISMATCH for {file_name}\n  expected {expected}\n  actual   {actual}\n\
             Do not use this file."
        )
        .into());
    }
    println!("xtask: checksum ok   {actual}  {file_name}");

    let status = Command::new("gh")
        .args(["attestation", "verify"])
        .arg(file)
        .args(["--repo", REPOSITORY])
        .args(["--signer-workflow", RELEASE_WORKFLOW])
        .arg("--deny-self-hosted-runners")
        .status()
        .map_err(|e| {
            format!(
                "could not run the GitHub CLI (`gh`): {e}\n\
                 The attestation was NOT verified. Install gh from https://cli.github.com \
                 and run this command again."
            )
        })?;
    if !status.success() {
        return Err(format!(
            "ATTESTATION NOT VERIFIED for {file_name} (gh exited with {status}).\n\
             Do not use this file."
        )
        .into());
    }
    println!("xtask: attestation ok: built by {RELEASE_WORKFLOW}");
    println!("xtask: {file_name} is verified.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn finds_exact_names_only() {
        let sums = format!("{DIGEST}  keel-0.1.0.img\n{DIGEST}  keel-0.1.0-esp.zip\n");
        assert_eq!(expected_digest(&sums, "keel-0.1.0.img"), Some(DIGEST));
        assert_eq!(expected_digest(&sums, "keel-0.1.0"), None);
        assert_eq!(expected_digest(&sums, "other.img"), None);
    }

    #[test]
    fn rejects_malformed_lines() {
        assert_eq!(expected_digest("abc  keel.img\n", "keel.img"), None);
        let single_space = format!("{DIGEST} keel.img\n");
        assert_eq!(expected_digest(&single_space, "keel.img"), None);
        let not_hex = format!("{}  keel.img\n", "z".repeat(64));
        assert_eq!(expected_digest(&not_hex, "keel.img"), None);
    }
}
