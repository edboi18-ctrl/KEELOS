//! `cargo xtask`: the single build, run, and test entry point for Keel.
//!
//! It is plain Rust so that every command behaves the same in PowerShell
//! on Windows and in a shell on Linux (spec section 1, rule 5).

mod audit;
mod build;
mod cpio;
mod dist;
mod fetch;
mod fuzzpe;
mod limine;
mod qemu;
mod syscalls;
mod tar;
mod util;
mod verify;

use std::process::ExitCode;
use std::time::Duration;

use util::Result;

const USAGE: &str = "\
Usage: cargo xtask <command> [options]

Commands:
  build                     Build the kernel and initramfs; populate target/esp
  run   [--gdb] [--kvm] [--accel NAME]
                            Build, then boot in QEMU with serial on stdio
  test  [--phase N [--scenario NAME]] [--kvm] [--accel NAME] [--timeout SECONDS]
                            Build, boot headless, run the in-guest tests
                            (--scenario: only that boot of the phase, or
                            `main` for the phase's main boot alone)
  fuzz  [--minutes N] [--seed S] [--kvm] [--accel NAME]
                            Boot the in-guest system-call fuzzer for N
                            minutes (default 60); fails on a kernel panic
                            or a hung fuzz process
  stress [--minutes N] [--seed S] [--kvm] [--accel NAME]
                            Boot the fork, thread and signal stress test
                            for N minutes (default 60); fails on a kernel
                            panic, a failed check or a leaked frame
  fuzz-pe [--minutes N] [--seed S]
                            Fuzz the PE parser on the host for N minutes
                            (default 30); fails on a parser panic
  dist  [--version V] [--allow-dirty]
                            Build release artifacts into target/dist
  boot-check <image> [--kvm] [--accel NAME]
                            Boot a raw disk image headless; pass when the
                            kernel finishes a normal boot
  verify <file>             Check a downloaded release artifact: SHA256SUMS
                            entry and GitHub build-provenance attestation
  syscalls <trace> [--counts FILE] [--out FILE] [--source TEXT]
                            Write the system-call inventory (default
                            docs/syscall-inventory.md) from an strace -f trace
  audit [--offline]         Format, lint, unsafe count, licenses, workflow
                            policy, dependency advisories

Environment:
  KEEL_QEMU                 Path of qemu-system-x86_64, if not on PATH
  KEEL_OVMF_CODE            Path of the UEFI firmware code image
";

/// Default limit for one phase's test run. Generous because the Windows
/// development host may run QEMU without hardware acceleration.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);

fn main() -> ExitCode {
    match dispatch(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Removes `flag` from `args` and reports whether it was present.
fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    let before = args.len();
    args.retain(|arg| arg != flag);
    args.len() != before
}

/// Removes `name VALUE` from `args` and returns the value.
fn take_value(args: &mut Vec<String>, name: &str) -> Result<Option<String>> {
    let Some(index) = args.iter().position(|arg| arg == name) else {
        return Ok(None);
    };
    if index + 1 >= args.len() {
        return Err(format!("{name} needs a value").into());
    }
    let value = args.remove(index + 1);
    args.remove(index);
    Ok(Some(value))
}

fn run_options(args: &mut Vec<String>) -> Result<qemu::RunOptions> {
    let mut accel = take_value(args, "--accel")?;
    if take_flag(args, "--kvm") {
        accel = Some("kvm".to_string());
    }
    Ok(qemu::RunOptions {
        accel,
        gdb: take_flag(args, "--gdb"),
    })
}

fn no_extra_args(args: &[String]) -> Result<()> {
    match args.first() {
        Some(extra) => Err(format!("unexpected argument {extra:?}\n\n{USAGE}").into()),
        None => Ok(()),
    }
}

fn dispatch(mut args: Vec<String>) -> Result<()> {
    if args.is_empty() {
        return Err(USAGE.into());
    }
    let command = args.remove(0);
    match command.as_str() {
        "build" => {
            no_extra_args(&args)?;
            build::build(build::BootMode::Normal)?;
            Ok(())
        }
        "run" => {
            let options = run_options(&mut args)?;
            no_extra_args(&args)?;
            qemu::run(&options)
        }
        "test" => {
            let options = run_options(&mut args)?;
            let phase = take_value(&mut args, "--phase")?
                .map(|v| v.parse::<u32>().map_err(|_| "--phase needs a number"))
                .transpose()?;
            let scenario = take_value(&mut args, "--scenario")?;
            if scenario.is_some() && phase.is_none() {
                return Err("--scenario needs --phase".into());
            }
            let timeout = take_value(&mut args, "--timeout")?
                .map(|v| v.parse::<u64>().map_err(|_| "--timeout needs seconds"))
                .transpose()?
                .map_or(DEFAULT_TIMEOUT, Duration::from_secs);
            no_extra_args(&args)?;
            if options.gdb {
                return Err("--gdb is only for `cargo xtask run`".into());
            }
            qemu::test(phase, scenario.as_deref(), &options, timeout)
        }
        "fuzz" => {
            let options = run_options(&mut args)?;
            let minutes = take_value(&mut args, "--minutes")?
                .map(|v| v.parse::<u64>().map_err(|_| "--minutes needs a number"))
                .transpose()?
                .unwrap_or(60);
            // Without --seed, one from the clock; it is printed, so the
            // session can be repeated.
            let seed = match take_value(&mut args, "--seed")? {
                Some(v) => v.parse::<u64>().map_err(|_| "--seed needs a number")?,
                None => std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() as u64),
            };
            no_extra_args(&args)?;
            if options.gdb {
                return Err("--gdb is only for `cargo xtask run`".into());
            }
            qemu::fuzz(minutes, seed, &options)
        }
        "stress" => {
            let options = run_options(&mut args)?;
            let minutes = take_value(&mut args, "--minutes")?
                .map(|v| v.parse::<u64>().map_err(|_| "--minutes needs a number"))
                .transpose()?
                .unwrap_or(60);
            // Without --seed, one from the clock; it is printed, so the
            // session can be repeated.
            let seed = match take_value(&mut args, "--seed")? {
                Some(v) => v.parse::<u64>().map_err(|_| "--seed needs a number")?,
                None => std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() as u64),
            };
            no_extra_args(&args)?;
            if options.gdb {
                return Err("--gdb is only for `cargo xtask run`".into());
            }
            qemu::stress(minutes, seed, &options)
        }
        "fuzz-pe" => {
            let minutes = take_value(&mut args, "--minutes")?
                .map(|v| v.parse::<u64>().map_err(|_| "--minutes needs a number"))
                .transpose()?
                .unwrap_or(30);
            let seed = match take_value(&mut args, "--seed")? {
                Some(v) => v.parse::<u64>().map_err(|_| "--seed needs a number")?,
                None => std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() as u64),
            };
            no_extra_args(&args)?;
            fuzzpe::fuzz_pe(minutes, seed)
        }
        "dist" => {
            let version = take_value(&mut args, "--version")?;
            let allow_dirty = take_flag(&mut args, "--allow-dirty");
            no_extra_args(&args)?;
            dist::dist(version, allow_dirty)?;
            Ok(())
        }
        "boot-check" => {
            let options = run_options(&mut args)?;
            if args.len() != 1 {
                return Err("boot-check needs exactly one image path".into());
            }
            dist::boot_check(std::path::Path::new(&args[0]), &options)
        }
        "verify" => {
            if args.len() != 1 {
                return Err("verify needs exactly one file path".into());
            }
            verify::verify(std::path::Path::new(&args[0]))
        }
        "syscalls" => {
            let counts = take_value(&mut args, "--counts")?;
            let out = take_value(&mut args, "--out")?
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| util::workspace_root().join("docs/syscall-inventory.md"));
            let source = take_value(&mut args, "--source")?
                .unwrap_or_else(|| "an strace -f trace".to_string());
            if args.len() != 1 {
                return Err("syscalls needs exactly one trace path".into());
            }
            syscalls::syscalls(
                std::path::Path::new(&args[0]),
                counts.as_deref().map(std::path::Path::new),
                &out,
                &source,
            )
        }
        "audit" => {
            let offline = take_flag(&mut args, "--offline");
            no_extra_args(&args)?;
            audit::audit(offline)
        }
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command {other:?}\n\n{USAGE}").into()),
    }
}
