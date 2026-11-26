//! Phase 3 acceptance item 1: the conformance tests' output under Linux is
//! the reference, and Keel's must match it (spec section 10, "Conformance
//! tests"; ADR 0039).
//!
//! - **The programs:** every `user/tests` program that runs under Linux,
//!   every test fixture with a fixed output (the musl programs), and the
//!   Rust std programs. [`programs`] lists them, with their arguments,
//!   environment and standard input.
//! - **The reference:** `cargo xtask linux-test` runs each under Linux
//!   and writes its exit status and standard output to
//!   `user/tests/reference/<name>.out`. `--check` compares instead.
//! - **On Keel:** the `conformance` boot of phase 3 runs each in a
//!   compartment of its own and reports its exit status and standard
//!   output on the results channel (COM2), which programs cannot write.
//!   [`compare`] matches them against the reference.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::build;
use crate::util::{self, Result};

/// The phase 3 boot that runs the conformance programs.
pub const SCENARIO: &str = "conformance";

/// Where the list of programs is in the initramfs, for the kernel.
pub const LIST_PATH: &str = "test/conformance.list";

/// One conformance program.
pub struct Program {
    /// Its name in the reference and the results.
    pub name: String,
    /// Its path in the initramfs (and in the compartment: `/` + this).
    pub path: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub stdin: Vec<u8>,
    kind: Kind,
}

enum Kind {
    /// `user/tests`, by its index in `build::TEST_PROGRAMS`.
    Test(usize),
    /// A fixture, by its index in `build::TEST_FIXTURES`.
    Fixture(usize),
    /// `user/std-tests`, by its index in `build::STD_PROGRAMS`.
    Std(usize),
}

/// Every conformance program, in a fixed order.
pub fn programs() -> Vec<Program> {
    let mut out = Vec::new();
    for (i, p) in build::TEST_PROGRAMS.iter().enumerate() {
        if !p.host {
            continue;
        }
        out.push(Program {
            name: p.binary.to_string(),
            path: p.path.to_string(),
            args: p.args.iter().map(|a| a.to_string()).collect(),
            env: p
                .env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            stdin: p.stdin.to_vec(),
            kind: Kind::Test(i),
        });
    }
    for (i, f) in build::TEST_FIXTURES.iter().enumerate() {
        if f.stdout.is_none() {
            continue;
        }
        out.push(Program {
            name: f.path.rsplit('/').next().unwrap_or(f.path).to_string(),
            path: f.path.to_string(),
            args: Vec::new(),
            env: Vec::new(),
            stdin: Vec::new(),
            kind: Kind::Fixture(i),
        });
    }
    for (i, s) in build::STD_PROGRAMS.iter().enumerate() {
        out.push(Program {
            name: s.binary.to_string(),
            path: s.path.to_string(),
            args: Vec::new(),
            env: Vec::new(),
            stdin: Vec::new(),
            kind: Kind::Std(i),
        });
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The list the kernel reads: one program a line, its fields separated by
/// tabs: name, path, the arguments, the environment (`KEY=VALUE`) and
/// standard input. Arguments and environment entries are each hex,
/// separated by commas; standard input is hex.
pub fn list_text(programs: &[Program]) -> Vec<u8> {
    let mut text = String::new();
    for p in programs {
        let args: Vec<String> = p.args.iter().map(|a| hex(a.as_bytes())).collect();
        let env: Vec<String> = p
            .env
            .iter()
            .map(|(k, v)| hex(format!("{k}={v}").as_bytes()))
            .collect();
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            p.name,
            p.path,
            args.join(","),
            env.join(","),
            hex(&p.stdin)
        ));
    }
    text.into_bytes()
}

/// What a program did: its end (`exit N`, or `signal N`) and its
/// standard output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub end: String,
    pub stdout: Vec<u8>,
}

impl Outcome {
    /// The reference file: the end on the first line, then the output.
    fn encode(&self) -> Vec<u8> {
        let mut out = format!("{}\n", self.end).into_bytes();
        out.extend_from_slice(&self.stdout);
        out
    }

    fn decode(bytes: &[u8]) -> Option<Outcome> {
        let nl = bytes.iter().position(|&b| b == b'\n')?;
        Some(Outcome {
            end: String::from_utf8(bytes[..nl].to_vec()).ok()?,
            stdout: bytes[nl + 1..].to_vec(),
        })
    }
}

fn reference_dir(root: &Path) -> PathBuf {
    root.join("user").join("tests").join("reference")
}

fn reference_path(root: &Path, name: &str) -> PathBuf {
    reference_dir(root).join(format!("{name}.out"))
}

/// A fixture copied where the host can run it, mode 0755.
fn fixture_on_host(root: &Path, fixture: &build::TestFixture) -> Result<PathBuf> {
    let data = build::load_fixture(root, fixture)?;
    let path = root.join("target").join("fixtures").join(fixture.path);
    util::write(&path, &data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(path)
}

/// Runs every conformance program under Linux, as `cargo xtask test` runs
/// them: nothing from the environment but the program's own, standard
/// input a pipe with its bytes, standard output a pipe.
pub fn run_on_host(root: &Path) -> Result<Vec<(String, Outcome)>> {
    let tests = build::build_user_tests(root)?;
    let stds = build::build_std_tests(root)?;
    let mut out = Vec::new();
    for p in programs() {
        let mut command = match p.kind {
            Kind::Test(i) => {
                let mut c = Command::new(&tests[i]);
                c.args(&p.args);
                c
            }
            Kind::Std(i) => Command::new(&stds[i]),
            Kind::Fixture(i) => {
                let fixture = &build::TEST_FIXTURES[i];
                let path = fixture_on_host(root, fixture)?;
                match fixture.host_via {
                    Some(via) => {
                        let interpreter = build::TEST_FIXTURES
                            .iter()
                            .find(|f| f.path == via)
                            .ok_or_else(|| format!("{}: no fixture {via}", fixture.path))?;
                        for library in build::TEST_FIXTURES
                            .iter()
                            .filter(|f| f.stdout.is_none() && f.path.starts_with("lib/"))
                        {
                            fixture_on_host(root, library)?;
                        }
                        let mut c = Command::new(fixture_on_host(root, interpreter)?);
                        c.arg(&path);
                        c
                    }
                    None => Command::new(&path),
                }
            }
        };
        command.env_clear().envs(p.env.iter().map(|(k, v)| (k, v)));
        if let Kind::Fixture(_) = p.kind {
            command.env(
                "LD_LIBRARY_PATH",
                root.join("target").join("fixtures").join("lib"),
            );
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            std::io::Write::write_all(&mut stdin, &p.stdin)?;
        }
        let output = child.wait_with_output()?;
        let end = match output.status.code() {
            Some(code) => format!("exit {code}"),
            None => {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    format!("signal {}", output.status.signal().unwrap_or(0))
                }
                #[cfg(not(unix))]
                {
                    "signal ?".to_string()
                }
            }
        };
        out.push((
            p.name.clone(),
            Outcome {
                end,
                stdout: output.stdout,
            },
        ));
    }
    Ok(out)
}

/// `cargo xtask linux-test [--check]`: records the reference output under
/// Linux, or (`--check`) compares this Linux's output with it.
pub fn linux_test(check: bool) -> Result<()> {
    if !(cfg!(target_os = "linux") && cfg!(target_arch = "x86_64")) {
        return Err("linux-test needs x86-64 Linux (CI runs it; on Windows, use WSL)".into());
    }
    let root = util::workspace_root();
    let results = run_on_host(&root)?;
    let mut differ = Vec::new();
    for (name, outcome) in &results {
        let path = reference_path(&root, name);
        if check {
            let recorded = std::fs::read(&path).ok().and_then(|b| Outcome::decode(&b));
            if recorded.as_ref() != Some(outcome) {
                differ.push(name.clone());
                println!("  linux-test: {name} differs from {}", path.display());
            }
        } else {
            util::write(&path, &outcome.encode())?;
        }
    }
    // Every reference file belongs to a program.
    for entry in std::fs::read_dir(reference_dir(&root))? {
        let file = entry?.file_name().to_string_lossy().into_owned();
        let name = file.strip_suffix(".out").unwrap_or(&file).to_string();
        if !results.iter().any(|(n, _)| *n == name) {
            if check {
                differ.push(name.clone());
                println!("  linux-test: {file} names no conformance program");
            } else {
                std::fs::remove_file(reference_dir(&root).join(&file))?;
            }
        }
    }
    if !differ.is_empty() {
        return Err(format!(
            "linux-test: {} reference(s) differ from this Linux's output: {}",
            differ.len(),
            differ.join(", ")
        )
        .into());
    }
    println!(
        "xtask: linux-test: {} programs {}",
        results.len(),
        if check {
            "match the reference"
        } else {
            "recorded in user/tests/reference"
        }
    );
    Ok(())
}

/// The outcomes the kernel reported on the results channel: `CONF <name>
/// out <hex>` lines, in order, then `CONF <name> end <end>`.
pub fn parse_results(results: &[String]) -> BTreeMap<String, Outcome> {
    let mut out: BTreeMap<String, Outcome> = BTreeMap::new();
    for line in results {
        let Some(rest) = line.trim_end().strip_prefix("CONF ") else {
            continue;
        };
        let mut parts = rest.splitn(3, ' ');
        let (Some(name), Some(what), value) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let entry = out.entry(name.to_string()).or_insert(Outcome {
            end: String::new(),
            stdout: Vec::new(),
        });
        match what {
            "out" => entry
                .stdout
                .extend(unhex(value.unwrap_or("")).unwrap_or_default()),
            "end" => entry.end = value.unwrap_or("").to_string(),
            _ => {}
        }
    }
    out
}

/// Compares Keel's outcomes with the reference: every program must have
/// reported, ended as it did under Linux and printed the same bytes.
/// Returns the TEST lines to print, and whether all matched.
pub fn compare(results: &[String]) -> Result<(Vec<String>, bool)> {
    let root = util::workspace_root();
    let keel = parse_results(results);
    let mut lines = Vec::new();
    let mut all = true;
    for p in programs() {
        let path = reference_path(&root, &p.name);
        let reference = std::fs::read(&path)
            .ok()
            .and_then(|b| Outcome::decode(&b))
            .ok_or_else(|| {
                format!(
                    "no reference for {} ({}): run `cargo xtask linux-test`",
                    p.name,
                    path.display()
                )
            })?;
        let (line, ok) = judge(&p.name, &reference, keel.get(&p.name));
        all &= ok;
        lines.push(line);
    }
    Ok((lines, all))
}

/// One program's verdict: it passes only if Keel reported it, it ended
/// as under Linux, and it printed exactly the same bytes.
fn judge(name: &str, reference: &Outcome, got: Option<&Outcome>) -> (String, bool) {
    let name = format!("conformance.{name}");
    match got {
        Some(got) if got.end == reference.end && got.stdout == reference.stdout => (
            format!("TEST {name} PASS matches Linux ({})", reference.end),
            true,
        ),
        Some(got) => (
            format!(
                "TEST {name} FAIL Linux: {} {:?}; Keel: {} {:?}",
                reference.end,
                String::from_utf8_lossy(&reference.stdout),
                got.end,
                String::from_utf8_lossy(&got.stdout)
            ),
            false,
        ),
        None => (format!("TEST {name} FAIL not reported by Keel"), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_round_trip_and_parse() {
        let o = Outcome {
            end: "exit 0".into(),
            stdout: b"a\nb\x00c".to_vec(),
        };
        assert_eq!(Outcome::decode(&o.encode()), Some(o.clone()));
        let results = [
            "CONF p out 610a62".to_string(),
            "CONF p out 0063".to_string(),
            "TEST other PASS".to_string(),
            "CONF p end exit 0".to_string(),
        ];
        assert_eq!(parse_results(&results).get("p"), Some(&o));
        assert_eq!(unhex("0g"), None);
        assert_eq!(unhex("abc"), None);
    }

    #[test]
    fn only_the_same_end_and_bytes_pass() {
        let reference = Outcome {
            end: "exit 0".into(),
            stdout: b"x: 3 checks passed\n".to_vec(),
        };
        let mut got = reference.clone();
        assert!(judge("x", &reference, Some(&got)).1);
        got.stdout.pop();
        assert!(!judge("x", &reference, Some(&got)).1);
        let mut got = reference.clone();
        got.end = "exit 1".into();
        assert!(!judge("x", &reference, Some(&got)).1);
        assert!(!judge("x", &reference, None).1);
    }

    #[test]
    fn the_list_has_every_program_once() {
        let programs = programs();
        let mut names: Vec<&str> = programs.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
        assert!(names.contains(&"readline") && names.contains(&"musl-signals"));
        assert!(!names.contains(&"fuzz"));
        let text = String::from_utf8(list_text(&programs)).unwrap();
        let readline = text.lines().find(|l| l.starts_with("readline\t")).unwrap();
        // stdin "keel\n".
        assert!(readline.ends_with("\t6b65656c0a"));
    }
}
