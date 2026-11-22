//! `cargo xtask build`: kernel, initramfs, and the bootable `target/esp`
//! tree (P0-T1, P0-T2, P0-S1).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::util::{self, Result};
use crate::{cpio, limine};

const KERNEL_TARGET: &str = "x86_64-unknown-none";

/// What the kernel should do after booting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootMode {
    /// Normal boot.
    Normal,
    /// Run the self-tests of a phase (or one named scenario of it), then
    /// exit QEMU.
    Test(u32, Option<&'static str>),
}

/// The files of a finished build, in the order they sit on the boot volume.
pub struct BootTree {
    /// `(path on the volume, contents)`, using `/` separators.
    pub files: Vec<(&'static str, Vec<u8>)>,
}

/// Paths on the boot volume. This is the layout from spec section 4.
pub const EFI_PATH: &str = "EFI/BOOT/BOOTX64.EFI";
pub const CONFIG_PATH: &str = "boot/limine.conf";
pub const KERNEL_PATH: &str = "boot/keel-kernel";
pub const INITRAMFS_PATH: &str = "boot/initramfs.cpio";

/// Rust flags for code built for the Keel target (with `--target`,
/// RUSTFLAGS do not apply to host build scripts):
///  - frame pointers for backtraces (spec section 15; SR-17);
///  - path remapping so no host or home-directory path ends up in the
///    image (SR-30, SR-37).
fn target_flags(root: &Path) -> Vec<String> {
    let mut flags = vec![
        "-Cforce-frame-pointers=yes".to_string(),
        format!("--remap-path-prefix={}=/keel", root.display()),
    ];
    if let Some(cargo_home) = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::home_dir().map(|home| home.join(".cargo")))
    {
        flags.push(format!(
            "--remap-path-prefix={}=/cargo",
            cargo_home.display()
        ));
    }
    if let Some(rustup_home) = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::home_dir().map(|home| home.join(".rustup")))
    {
        flags.push(format!(
            "--remap-path-prefix={}=/rustup",
            rustup_home.display()
        ));
    }

    flags
}

/// Compiles the kernel and returns the path of the ELF file.
fn build_kernel(root: &Path) -> Result<PathBuf> {
    // 0x1f separates CARGO_ENCODED_RUSTFLAGS entries (Cargo book,
    // "Environment variables").
    util::run(
        Command::new(util::cargo())
            .current_dir(root)
            .args(["build", "--release", "--locked", "--package", "keel-kernel"])
            .args(["--target", KERNEL_TARGET])
            .env("CARGO_ENCODED_RUSTFLAGS", target_flags(root).join("\x1f")),
    )?;
    Ok(root
        .join("target")
        .join(KERNEL_TARGET)
        .join("release")
        .join("keel-kernel"))
}

/// A program from `user/tests`, placed in the initramfs of test builds
/// only. The kernel self-tests run it with the same arguments.
pub struct TestProgram {
    /// Path inside the initramfs.
    pub path: &'static str,
    /// Binary name in `user/tests`.
    pub binary: &'static str,
    /// Arguments after argv[0], and the environment, for a passing run.
    pub args: &'static [&'static str],
    pub env: &'static [(&'static str, &'static str)],
    /// Standard input for the Linux run (Keel's self-test types it).
    pub stdin: &'static [u8],
}

pub const TEST_PROGRAMS: &[TestProgram] = &[
    TestProgram {
        path: "test/startup",
        binary: "startup",
        args: &["alpha"],
        env: &[("KEEL_TEST", "1")],
        stdin: b"",
    },
    TestProgram {
        path: "test/syscalls",
        binary: "syscalls",
        args: &[],
        env: &[],
        stdin: b"",
    },
    TestProgram {
        path: "test/reserve",
        binary: "reserve",
        args: &[],
        env: &[],
        stdin: b"",
    },
    TestProgram {
        path: "test/readline",
        binary: "readline",
        args: &[],
        env: &[],
        stdin: b"keel\n",
    },
];

/// A prebuilt test binary checked into the repository (built elsewhere by
/// a pinned recipe), placed in the initramfs of test builds only.
pub struct TestFixture {
    /// Path inside the initramfs.
    pub path: &'static str,
    /// The binary and its recorded SHA-256 (`sha256sum` format), relative to
    /// the workspace root.
    pub file: &'static str,
    pub hash_file: &'static str,
    /// What it must print on standard output.
    pub stdout: &'static str,
}

/// Phase 1 acceptance item 1: musl "hello world", built from
/// fixtures/musl-hello by its Dockerfile.
pub const TEST_FIXTURES: &[TestFixture] = &[TestFixture {
    path: "test/musl-hello",
    file: "fixtures/musl-hello/hello",
    hash_file: "fixtures/musl-hello/hello.sha256",
    stdout: "Hello from musl on Keel\n",
}];

/// Reads a fixture and checks it against its recorded SHA-256 (SR-29: every
/// input is verified); a mismatch stops the build.
pub fn load_fixture(root: &Path, fixture: &TestFixture) -> Result<Vec<u8>> {
    let data = util::read(&root.join(fixture.file))?;
    let recorded = String::from_utf8(util::read(&root.join(fixture.hash_file))?)?;
    let expected = recorded.split_whitespace().next().unwrap_or("");
    let actual = util::sha256_hex(&data);
    if actual != expected {
        return Err(format!(
            "{}: SHA-256 {actual} does not match {} ({expected})",
            fixture.file, fixture.hash_file
        )
        .into());
    }
    Ok(data)
}

/// Compiles the user test programs (static, non-PIE ELF executables for
/// the Linux x86-64 ABI) and returns the path of each, in `TEST_PROGRAMS`
/// order.
///
/// They use their own target directory: their flags differ from the
/// kernel's, and sharing one would rebuild both every time.
pub fn build_user_tests(root: &Path) -> Result<Vec<PathBuf>> {
    let target_dir = root.join("target").join("user");
    let mut flags = target_flags(root);
    // Fixed-address executables (ET_EXEC): no load bias until ASLR
    // (P1-S5). Debug info is stripped; symbols stay for backtraces.
    flags.push("-Crelocation-model=static".to_string());
    flags.push("-Cstrip=debuginfo".to_string());
    util::run(
        Command::new(util::cargo())
            .current_dir(root)
            .args([
                "build",
                "--release",
                "--locked",
                "--package",
                "keel-user-tests",
            ])
            .args(["--target", KERNEL_TARGET])
            .arg("--target-dir")
            .arg(&target_dir)
            .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\x1f")),
    )?;
    let out = target_dir.join(KERNEL_TARGET).join("release");
    Ok(TEST_PROGRAMS.iter().map(|p| out.join(p.binary)).collect())
}

/// Renders `limine.conf` with BLAKE2B hashes pinned on every loaded file
/// (SR-27; Limine CONFIG.md, "Paths": `path#<blake2b hash>`).
pub fn limine_conf(kernel: &[u8], initramfs: &[u8], mode: BootMode) -> String {
    let mut conf = String::new();
    conf.push_str("# Generated by `cargo xtask build`. Do not edit: the hashes below pin\n");
    conf.push_str("# the exact kernel and initramfs this file was built with (SR-27).\n");
    conf.push_str("timeout: 0\n");
    conf.push_str("hash_mismatch_panic: yes\n");
    conf.push_str("editor_enabled: no\n");
    conf.push('\n');
    conf.push_str("/Keel OS\n");
    conf.push_str("    protocol: limine\n");
    // KASLR (SR-16, P1-S5): the kernel is a relocatable (PIE) executable,
    // so Limine loads it at a random address at or above
    // 0xffffffff80000000, and also randomises the HHDM base (Limine
    // CONFIG.md, "kaslr", "randomise_hhdm_base": on by default with KASLR).
    conf.push_str("    kaslr: yes\n");
    conf.push_str(&format!(
        "    path: boot():/{KERNEL_PATH}#{}\n",
        util::blake2b_hex(kernel)
    ));
    conf.push_str(&format!(
        "    module_path: boot():/{INITRAMFS_PATH}#{}\n",
        util::blake2b_hex(initramfs)
    ));
    match mode {
        BootMode::Normal => {}
        BootMode::Test(phase, None) => conf.push_str(&format!("    cmdline: test={phase}\n")),
        BootMode::Test(phase, Some(scenario)) => {
            conf.push_str(&format!("    cmdline: test={phase} scenario={scenario}\n"))
        }
    }
    conf
}

/// Builds everything and returns the boot tree in memory.
pub fn build_tree(mode: BootMode) -> Result<BootTree> {
    let root = util::workspace_root();
    let limine = limine::ensure()?;
    let kernel = util::read(&build_kernel(&root)?)?;

    let mut archive = cpio::Archive::default();
    archive.add_tree(&root.join("initramfs"))?;
    if let BootMode::Test(..) = mode {
        for (program, binary) in TEST_PROGRAMS.iter().zip(build_user_tests(&root)?) {
            archive.add_file(program.path, util::read(&binary)?);
        }
        for fixture in TEST_FIXTURES {
            archive.add_file(fixture.path, load_fixture(&root, fixture)?);
        }
    }
    let initramfs = archive.to_bytes()?;

    let conf = limine_conf(&kernel, &initramfs, mode);
    Ok(BootTree {
        files: vec![
            (EFI_PATH, util::read(&limine.bootx64_efi)?),
            (CONFIG_PATH, conf.into_bytes()),
            (KERNEL_PATH, kernel),
            (INITRAMFS_PATH, initramfs),
        ],
    })
}

/// Builds everything and writes the tree to `target/esp`, replacing what
/// was there. Returns the directory.
pub fn build(mode: BootMode) -> Result<PathBuf> {
    let tree = build_tree(mode)?;
    let esp = util::workspace_root().join("target").join("esp");
    if esp.exists() {
        std::fs::remove_dir_all(&esp)?;
    }
    for (path, data) in &tree.files {
        util::write(&esp.join(path), data)?;
    }
    println!("xtask: boot tree written to {}", esp.display());
    Ok(esp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_are_checked_against_their_hash() {
        let root = util::workspace_root();
        // The committed fixture matches its recorded hash.
        assert!(load_fixture(&root, &TEST_FIXTURES[0]).is_ok());
        // A file that does not match is refused.
        let dir = root.join("target").join("fixture-test");
        util::write(&dir.join("bin"), b"not the binary").unwrap();
        // ...under the real fixture's recorded hash.
        let recorded = util::read(&root.join(TEST_FIXTURES[0].hash_file)).unwrap();
        util::write(&dir.join("bin.sha256"), &recorded).unwrap();
        let tampered = TestFixture {
            path: "test/x",
            file: "target/fixture-test/bin",
            hash_file: "target/fixture-test/bin.sha256",
            stdout: "",
        };
        assert!(load_fixture(&root, &tampered).is_err());
    }

    #[test]
    fn conf_pins_both_files_and_only_tests_on_request() {
        let conf = limine_conf(b"kernel", b"initramfs", BootMode::Normal);
        let kernel_hash = util::blake2b_hex(b"kernel");
        let initramfs_hash = util::blake2b_hex(b"initramfs");
        assert_eq!(kernel_hash.len(), 128);
        assert!(conf.contains(&format!("path: boot():/boot/keel-kernel#{kernel_hash}\n")));
        assert!(conf.contains(&format!(
            "module_path: boot():/boot/initramfs.cpio#{initramfs_hash}\n"
        )));
        assert!(conf.contains("hash_mismatch_panic: yes\n"));
        assert!(!conf.contains("cmdline"));

        let conf = limine_conf(b"kernel", b"initramfs", BootMode::Test(0, None));
        assert!(conf.contains("    cmdline: test=0\n"));
        let conf = limine_conf(b"k", b"i", BootMode::Test(1, Some("double_fault")));
        assert!(conf.contains("    cmdline: test=1 scenario=double_fault\n"));
    }
}
