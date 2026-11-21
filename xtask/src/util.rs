//! Small helpers shared by the xtask commands.

use std::error::Error;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use blake2::Blake2b512;
use sha2::{Digest, Sha256};

/// Error type for xtask commands: a message for the developer.
pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// Absolute path of the workspace root (the parent of `xtask/`).
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the workspace root")
        .to_path_buf()
}

/// The `cargo` that is running this xtask, or plain `cargo`.
pub fn cargo() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// Lower-case hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Lower-case hex BLAKE2b-512 of `data`: the digest Limine checks for a
/// `#hash` path suffix (Limine `common/crypt/blake2b.h`:
/// `BLAKE2B_OUT_BYTES 64`; CONFIG.md, "Paths").
pub fn blake2b_hex(data: &[u8]) -> String {
    hex(&Blake2b512::digest(data))
}

/// Runs a command to completion and fails unless it exits successfully.
pub fn run(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .map_err(|e| format!("could not start {:?}: {e}", command.get_program()))?;
    if !status.success() {
        return Err(format!("{:?} failed with {status}", command.get_program()).into());
    }
    Ok(())
}

/// Reads a whole file, naming the path in any error.
pub fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()).into())
}

/// Writes a whole file (creating parent directories), naming the path in
/// any error.
pub fn write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, data).map_err(|e| format!("cannot write {}: {e}", path.display()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 test vector from FIPS 180-4 / NIST CAVP ("abc").
    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// BLAKE2b-512 test vector from RFC 7693, Appendix A ("abc").
    #[test]
    fn blake2b_known_answer() {
        assert_eq!(
            blake2b_hex(b"abc"),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }
}
