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
    /// Run the system-call fuzzer for `minutes` from `seed` (with the
    /// phase 1 test programs in the initramfs), then exit QEMU.
    Fuzz { minutes: u64, seed: u64 },
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
    /// Whether it also runs natively on the Linux host. Only the fuzzer
    /// does not: random system calls must never reach a real kernel.
    pub host: bool,
}

pub const TEST_PROGRAMS: &[TestProgram] = &[
    TestProgram {
        path: "test/fuzz",
        binary: "fuzz",
        args: &[],
        env: &[],
        stdin: b"",
        host: false,
    },
    TestProgram {
        path: "test/startup",
        binary: "startup",
        args: &["alpha"],
        env: &[("KEEL_TEST", "1")],
        stdin: b"",
        host: true,
    },
    TestProgram {
        path: "test/syscalls",
        binary: "syscalls",
        args: &[],
        env: &[],
        stdin: b"",
        host: true,
    },
    TestProgram {
        path: "test/reserve",
        binary: "reserve",
        args: &[],
        env: &[],
        stdin: b"",
        host: true,
    },
    TestProgram {
        path: "test/maplimit",
        binary: "maplimit",
        args: &["hint"],
        env: &[],
        stdin: b"",
        host: true,
    },
    TestProgram {
        path: "test/fileflood",
        binary: "fileflood",
        args: &[],
        env: &[],
        stdin: b"",
        host: false,
    },
    TestProgram {
        path: "test/reservecall",
        binary: "reservecall",
        args: &[],
        env: &[],
        stdin: b"",
        host: false,
    },
    // The toy PE loader (Phase 2). Not run on its own on the host: the PE
    // fixtures are run through it there (`qemu::test_user_programs_on_host`).
    TestProgram {
        path: "test/peldr",
        binary: "peldr",
        args: &[],
        env: &[],
        stdin: b"",
        host: false,
    },
    TestProgram {
        path: "test/dirconfine",
        binary: "dirconfine",
        args: &[],
        env: &[],
        stdin: b"",
        host: false,
    },
    TestProgram {
        path: "test/compprobe",
        binary: "compprobe",
        args: &[],
        env: &[],
        stdin: b"",
        host: false,
    },
    TestProgram {
        path: "test/nap",
        binary: "nap",
        args: &["10"],
        env: &[],
        stdin: b"",
        host: true,
    },
    TestProgram {
        path: "test/forger",
        binary: "forger",
        args: &[],
        env: &[],
        stdin: b"",
        host: true,
    },
    TestProgram {
        path: "test/conflood",
        binary: "conflood",
        args: &[],
        env: &[],
        stdin: b"",
        host: true,
    },
    TestProgram {
        path: "test/longcall",
        binary: "longcall",
        args: &[],
        env: &[],
        stdin: b"",
        host: true,
    },
    TestProgram {
        path: "test/rights",
        binary: "rights",
        args: &[],
        env: &[],
        stdin: b"",
        host: true,
    },
    TestProgram {
        path: "test/readline",
        binary: "readline",
        args: &[],
        env: &[],
        stdin: b"keel\n",
        host: true,
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

/// Phase 2: Windows executables, run through `peldr` (not natively), with
/// what they print. In the initramfs of test builds at `path`.
pub const PE_FIXTURES: &[TestFixture] = &[TestFixture {
    path: "winetest/hello.exe",
    file: "winetest/hello-console/hello.exe",
    hash_file: "winetest/hello-console/hello.sha256",
    stdout: "Hello from a Windows executable on Keel\r\n",
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
                "--package",
                "keel-peldr",
            ])
            .args(["--target", KERNEL_TARGET])
            .arg("--target-dir")
            .arg(&target_dir)
            .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\x1f")),
    )?;
    let out = target_dir.join(KERNEL_TARGET).join("release");
    Ok(TEST_PROGRAMS.iter().map(|p| out.join(p.binary)).collect())
}

/// Target of the programs in `user/std-tests`, which use Rust's standard
/// library: static musl executables, as Phase 1 acceptance item 2 asks.
pub const STD_TARGET: &str = "x86_64-unknown-linux-musl";

/// A program from `user/std-tests`, placed in the initramfs of test builds
/// only, with the standard output it must print, the same on Linux and on
/// Keel.
pub struct StdProgram {
    /// Path inside the initramfs.
    pub path: &'static str,
    /// Binary name in `user/std-tests`.
    pub binary: &'static str,
    /// Its whole standard output.
    pub stdout: &'static str,
}

/// Phase 1 acceptance item 2: allocate 64 MB on the heap, touch every
/// page, print a checksum. The checksum is of fixed data, so it is known
/// in advance.
pub const STD_PROGRAMS: &[StdProgram] = &[StdProgram {
    path: "test/heap64",
    binary: "heap64",
    stdout: "heap64: 67108864 bytes in 16384 pages, checksum 0x7f282b735ac8d3f2\n",
}];

/// Compiles the `user/std-tests` programs and returns the path of each, in
/// `STD_PROGRAMS` order. They stay static PIE (the musl target's default),
/// so Keel loads them at a random bias.
///
/// They link with `rust-lld` and the target's bundled musl start files
/// (rustc `-Clink-self-contained`, on by default for this target), so no
/// C toolchain is needed and the build works on Windows too.
pub fn build_std_tests(root: &Path) -> Result<Vec<PathBuf>> {
    let target_dir = root.join("target").join("std");
    let mut flags = target_flags(root);
    flags.push("-Clinker=rust-lld".to_string());
    flags.push("-Clinker-flavor=ld.lld".to_string());
    flags.push("-Cstrip=debuginfo".to_string());
    util::run(
        Command::new(util::cargo())
            .current_dir(root)
            .args([
                "build",
                "--release",
                "--locked",
                "--package",
                "keel-std-tests",
            ])
            .args(["--target", STD_TARGET])
            .arg("--target-dir")
            .arg(&target_dir)
            .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\x1f")),
    )?;
    let out = target_dir.join(STD_TARGET).join("release");
    Ok(STD_PROGRAMS.iter().map(|p| out.join(p.binary)).collect())
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
        BootMode::Fuzz { minutes, seed } => {
            conf.push_str(&format!("    cmdline: test=1 fuzz={minutes} seed={seed}\n"))
        }
        BootMode::Test(phase, Some(scenario)) => {
            conf.push_str(&format!("    cmdline: test={phase} scenario={scenario}\n"))
        }
    }
    conf
}

/// Marker that precedes the enrolled config checksum in Limine's EFI
/// executable: 128 hex digits follow it, all `0` when none is enrolled
/// (Limine v12.9.6 `common/lib/config.c`, `CONFIG_B2SUM_SIGNATURE` and
/// `CONFIG_B2SUM_EMPTY`; the `limine enroll-config` command in
/// `host/limine.c` writes the same 128 bytes).
const CONFIG_B2SUM_SIGNATURE: &[u8] = b"++CONFIG_B2SUM_SIGNATURE++";

/// Enrols the BLAKE2B of `conf` into `efi`, as `limine enroll-config`
/// does, without needing that host tool (ADR 0010, audit finding 2).
/// Limine then refuses any other config: on a mismatch it panics before
/// reading it, and the config editor is disabled. Refuses an executable
/// with no marker, or more than one, or no hex-digit slot after it, so a
/// different Limine build cannot be patched in the wrong place.
pub fn enroll_config(efi: &mut [u8], conf: &[u8]) -> Result<()> {
    let marks: Vec<usize> = efi
        .windows(CONFIG_B2SUM_SIGNATURE.len())
        .enumerate()
        .filter(|(_, window)| *window == CONFIG_B2SUM_SIGNATURE)
        .map(|(at, _)| at)
        .collect();
    let [at] = marks[..] else {
        return Err(format!(
            "BOOTX64.EFI: expected one config checksum marker, found {}",
            marks.len()
        )
        .into());
    };
    let start = at + CONFIG_B2SUM_SIGNATURE.len();
    let slot = efi
        .get_mut(start..start + 128)
        .filter(|slot| slot.iter().all(u8::is_ascii_hexdigit))
        .ok_or("BOOTX64.EFI: no 128-digit checksum slot after the marker")?;
    slot.copy_from_slice(util::blake2b_hex(conf).as_bytes());
    Ok(())
}

/// Builds everything and returns the boot tree in memory.
pub fn build_tree(mode: BootMode) -> Result<BootTree> {
    let root = util::workspace_root();
    let limine = limine::ensure()?;
    let kernel = util::read(&build_kernel(&root)?)?;

    let mut archive = cpio::Archive::default();
    archive.add_tree(&root.join("initramfs"))?;
    if let BootMode::Test(..) | BootMode::Fuzz { .. } = mode {
        for (program, binary) in TEST_PROGRAMS.iter().zip(build_user_tests(&root)?) {
            archive.add_file(program.path, util::read(&binary)?);
        }
        for fixture in TEST_FIXTURES.iter().chain(PE_FIXTURES) {
            archive.add_file(fixture.path, load_fixture(&root, fixture)?);
        }
        for (program, binary) in STD_PROGRAMS.iter().zip(build_std_tests(&root)?) {
            archive.add_file(program.path, util::read(&binary)?);
        }
    }
    let initramfs = archive.to_bytes()?;

    let conf = limine_conf(&kernel, &initramfs, mode);
    // The pinned SHA-256 covers the file as downloaded; the shipped copy
    // differs only in the enrolled checksum (docs/DEPENDENCIES.md).
    let mut efi = util::read(&limine.bootx64_efi)?;
    enroll_config(&mut efi, conf.as_bytes())?;
    Ok(BootTree {
        files: vec![
            (EFI_PATH, efi),
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
    fn efi_with(slot: &[u8]) -> Vec<u8> {
        let mut efi = b"MZ...code...".to_vec();
        efi.extend_from_slice(CONFIG_B2SUM_SIGNATURE);
        efi.extend_from_slice(slot);
        efi.extend_from_slice(b"...more");
        efi
    }

    #[test]
    fn enroll_config_writes_the_hash_after_the_marker() {
        let mut efi = efi_with(&[b'0'; 128]);
        let before = efi.clone();
        enroll_config(&mut efi, b"timeout: 0\n").unwrap();
        let start = 12 + CONFIG_B2SUM_SIGNATURE.len();
        assert_eq!(
            &efi[start..start + 128],
            util::blake2b_hex(b"timeout: 0\n").as_bytes()
        );
        assert_eq!(efi[..start], before[..start]);
        assert_eq!(efi[start + 128..], before[start + 128..]);
        // Enrolling again (a test that edits the config) replaces it.
        enroll_config(&mut efi, b"other").unwrap();
        assert_eq!(
            &efi[start..start + 128],
            util::blake2b_hex(b"other").as_bytes()
        );
    }

    #[test]
    fn enroll_config_refuses_unexpected_executables() {
        let mut none = b"no marker here".to_vec();
        assert!(enroll_config(&mut none, b"c").is_err());
        let mut two = efi_with(&[b'0'; 128]);
        two.extend(efi_with(&[b'0'; 128]));
        assert!(enroll_config(&mut two, b"c").is_err());
        let mut short = efi_with(&[b'0'; 100]);
        short.truncate(12 + CONFIG_B2SUM_SIGNATURE.len() + 100);
        assert!(enroll_config(&mut short, b"c").is_err());
        let mut not_hex = efi_with(&[b'z'; 128]);
        assert!(enroll_config(&mut not_hex, b"c").is_err());
    }

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
