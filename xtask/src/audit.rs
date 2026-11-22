//! `cargo xtask audit` (P0-S2; SR-29, SR-32, SR-33; spec section 3,
//! "`unsafe` budget").
//!
//! Runs every check and reports all failures, rather than stopping at the
//! first one:
//!   format      `cargo fmt --check`
//!   lint        `cargo clippy -D warnings` for the host crates and the kernel
//!   unsafe      count of `unsafe` in our own code; none outside `kernel/hal`
//!               and the user runtime `user/keel-rt` (ADR 0006)
//!   licenses    every locked crate is vendored and under an allowed license
//!   workflows   actions pinned by commit SHA, least-privilege tokens
//!   advisories  RustSec advisory database, through a pinned `cargo-deny`

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::fetch;
use crate::util::{self, Result};

// ---- unsafe census ----------------------------------------------------------

/// Occurrences of the `unsafe` keyword in one file or crate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnsafeCount {
    /// `unsafe { ... }` blocks.
    pub blocks: usize,
    /// Source lines spanned by those blocks.
    pub block_lines: usize,
    /// `unsafe fn`, `unsafe impl`, `unsafe trait`, `unsafe extern`.
    pub declarations: usize,
    /// `#[unsafe(...)]` attributes.
    pub attributes: usize,
}

impl UnsafeCount {
    fn total(&self) -> usize {
        self.blocks + self.declarations + self.attributes
    }

    fn add(&mut self, other: UnsafeCount) {
        self.blocks += other.blocks;
        self.block_lines += other.block_lines;
        self.declarations += other.declarations;
        self.attributes += other.attributes;
    }
}

/// Replaces comments and string/char literal contents with spaces, keeping
/// newlines, so that a later keyword search sees only code.
///
/// This is a small lexer for the parts of Rust's lexical grammar that can
/// hide the word `unsafe`: line and (nested) block comments, string
/// literals with escapes, raw strings, and character literals as opposed
/// to lifetimes (The Rust Reference, "Comments" and "Tokens").
pub fn blank_comments_and_literals(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                out.push(' ');
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0usize;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(chars[i]));
                    i += 1;
                }
            }
        } else if c == 'r'
            && matches!(next, Some('"') | Some('#'))
            && !chars
                .get(i.wrapping_sub(1))
                .is_some_and(|p| p.is_alphanumeric() || *p == '_')
        {
            // Possible raw string: r"..." or r#"..."# with any number of #.
            let mut j = i + 1;
            let mut hashes = 0;
            while chars.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if chars.get(j) != Some(&'"') {
                out.push(c); // an identifier such as `r#type`, not a string
                i += 1;
                continue;
            }
            j += 1;
            loop {
                match chars.get(j) {
                    None => break,
                    Some('"') if (1..=hashes).all(|k| chars.get(j + k) == Some(&'#')) => {
                        j += 1 + hashes;
                        break;
                    }
                    Some(_) => j += 1,
                }
            }
            for &ch in &chars[i..j.min(chars.len())] {
                out.push(blank(ch));
            }
            i = j;
        } else if c == '"' {
            out.push(' ');
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    out.push(' ');
                    i += 1;
                }
                out.push(blank(chars[i]));
                i += 1;
            }
            out.push(' ');
            i += 1;
        } else if c == '\'' {
            // A char literal is 'x' or '\...'; anything else is a lifetime.
            let is_char = next == Some('\\') || chars.get(i + 2) == Some(&'\'');
            if is_char {
                out.push(' ');
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    if chars[i] == '\\' {
                        out.push(' ');
                        i += 1;
                    }
                    out.push(' ');
                    i += 1;
                }
                out.push(' ');
                i += 1;
            } else {
                out.push(c);
                i += 1;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Counts uses of `unsafe` in Rust source text.
pub fn count_unsafe(source: &str) -> UnsafeCount {
    let code: Vec<char> = blank_comments_and_literals(source).chars().collect();
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let keyword: Vec<char> = "unsafe".chars().collect();
    let mut count = UnsafeCount::default();
    let mut i = 0;
    while i + keyword.len() <= code.len() {
        let at_keyword = code[i..i + keyword.len()] == keyword[..]
            && (i == 0 || !is_ident(code[i - 1]))
            && code.get(i + keyword.len()).is_none_or(|c| !is_ident(*c));
        if !at_keyword {
            i += 1;
            continue;
        }
        let mut j = i + keyword.len();
        while code.get(j).is_some_and(|c| c.is_whitespace()) {
            j += 1;
        }
        match code.get(j) {
            Some('{') => {
                count.blocks += 1;
                let mut depth = 0usize;
                let mut lines = 1;
                for &c in &code[j..] {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        '\n' => lines += 1,
                        _ => {}
                    }
                }
                count.block_lines += lines;
            }
            Some('(') => count.attributes += 1,
            _ => count.declarations += 1,
        }
        i += keyword.len();
    }
    count
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if entry.file_type()?.is_dir() {
            // Our own code only: skip build output, vendored crates, git.
            if name != "target" && name != "vendor" && name != ".git" {
                rust_files(&path, out)?;
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// The one place in the kernel outside `kernel/hal` where the keyword may
/// appear: the `#[unsafe(no_mangle)]` on the kernel entry point, which
/// must carry the exact symbol name the linker script's `ENTRY` refers to.
const ENTRY_POINT_FILE: &str = "kernel/keel-kernel/src/main.rs";

/// The user-space runtime: process entry and raw system calls for Keel's
/// own user programs (ADR 0006). It runs in ring 3, so its `unsafe` can
/// harm only the program using it, never the kernel.
const USER_RUNTIME_DIR: &str = "user/keel-rt/";

fn check_unsafe(root: &Path) -> Result<()> {
    let mut files = Vec::new();
    rust_files(root, &mut files)?;
    files.sort();

    let mut per_crate: BTreeMap<String, UnsafeCount> = BTreeMap::new();
    let mut violations = Vec::new();
    for file in &files {
        let relative = file
            .strip_prefix(root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        let count = count_unsafe(&String::from_utf8(util::read(file)?)?);
        if count.total() == 0 {
            continue;
        }
        let krate = relative
            .split("/src/")
            .next()
            .unwrap_or(&relative)
            .to_string();
        per_crate.entry(krate).or_default().add(count);

        let allowed = relative.starts_with("kernel/hal/")
            || relative.starts_with(USER_RUNTIME_DIR)
            || (relative == ENTRY_POINT_FILE
                && count
                    == UnsafeCount {
                        attributes: 1,
                        ..UnsafeCount::default()
                    });
        if !allowed {
            violations.push(format!("{relative}: {count:?}"));
        }
    }

    let mut total = UnsafeCount::default();
    println!("  crate                      blocks  block-lines  declarations  attributes");
    for (krate, count) in &per_crate {
        println!(
            "  {krate:<26} {:>6}  {:>11}  {:>12}  {:>10}",
            count.blocks, count.block_lines, count.declarations, count.attributes
        );
        total.add(*count);
    }
    println!(
        "  {:<26} {:>6}  {:>11}  {:>12}  {:>10}",
        "TOTAL", total.blocks, total.block_lines, total.declarations, total.attributes
    );
    if violations.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "`unsafe` outside kernel/hal and user/keel-rt (spec section 7, ADR 0006):\n  {}",
            violations.join("\n  ")
        )
        .into())
    }
}

// ---- licenses ---------------------------------------------------------------

/// SPDX identifiers accepted for third-party crates. All are permissive
/// and compatible with shipping under MIT OR Apache-2.0. Anything else
/// (in particular any copyleft license) is a licensing question for the
/// owner, not something to add here quietly.
const ALLOWED_LICENSES: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "0BSD",
    "Unlicense",
    "Unicode-3.0",
];

/// Whether an SPDX license expression can be satisfied using only allowed
/// licenses. Handles `OR`, `AND`, parentheses around the whole expression,
/// and the legacy `A/B` spelling of `A OR B`. `WITH` exceptions and nested
/// groups are rejected so that they get a human decision.
pub fn license_allowed(expression: &str) -> bool {
    let normalised = expression.replace('/', " OR ");
    let trimmed = normalised.trim().trim_matches(|c| c == '(' || c == ')');
    if trimmed.contains(['(', ')']) || trimmed.contains(" WITH ") {
        return false;
    }
    trimmed.split(" OR ").any(|alternative| {
        alternative
            .split(" AND ")
            .all(|id| ALLOWED_LICENSES.contains(&id.trim()))
    })
}

/// `(name, version)` of every package in `Cargo.lock` that comes from a
/// registry (workspace members have no `source` line).
pub fn locked_packages(lock: &str) -> Vec<(String, String)> {
    let value = |line: &str, key: &str| {
        line.strip_prefix(key)
            .map(|rest| rest.trim().trim_matches('"').to_string())
    };
    let mut packages = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let mut name = None;
        let mut version = None;
        let mut has_source = false;
        for line in block.lines() {
            name = name.or(value(line, "name = "));
            version = version.or(value(line, "version = "));
            has_source |= line.starts_with("source = ");
        }
        if let (Some(name), Some(version), true) = (name, version, has_source) {
            packages.push((name, version));
        }
    }
    packages
}

fn manifest_license(manifest: &str) -> Option<String> {
    manifest
        .lines()
        .find_map(|line| line.strip_prefix("license = "))
        .map(|value| value.trim().trim_matches('"').to_string())
}

fn check_licenses(root: &Path) -> Result<()> {
    let lock = String::from_utf8(util::read(&root.join("Cargo.lock"))?)?;
    let mut problems = Vec::new();
    let packages = locked_packages(&lock);
    for (name, version) in &packages {
        // `cargo vendor` uses `<name>` or, with several versions, `<name>-<version>`.
        let candidates = [
            root.join("vendor").join(name),
            root.join("vendor").join(format!("{name}-{version}")),
        ];
        let manifest = candidates
            .iter()
            .map(|dir| dir.join("Cargo.toml"))
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .find(|text| text.contains(&format!("version = \"{version}\"")));
        let Some(manifest) = manifest else {
            problems.push(format!("{name} {version}: not vendored"));
            continue;
        };
        match manifest_license(&manifest) {
            Some(license) if license_allowed(&license) => {}
            Some(license) => problems.push(format!("{name} {version}: license {license:?}")),
            None => problems.push(format!("{name} {version}: no license field")),
        }
    }
    println!("  {} locked crates checked against vendor/", packages.len());
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "crate license or vendoring problems:\n  {}",
            problems.join("\n  ")
        )
        .into())
    }
}

// ---- workflows --------------------------------------------------------------

/// The only workflow allowed to request a write permission (SR-33).
const RELEASE_WORKFLOW_FILE: &str = "release.yml";

/// Checks one workflow file against SR-32 and SR-33. Returns the problems
/// found. Line-based on purpose: the rules are about what must never
/// appear, and a line check cannot be fooled by YAML structure.
pub fn workflow_problems(file_name: &str, text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut in_top_permissions = false;
    let mut saw_top_permissions = false;
    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        let at = |message: &str| format!("{file_name}:{}: {message}", number + 1);
        if line.trim_start().starts_with('#') {
            continue; // a comment line; it is not top-level content either
        }
        let code = line.split(" #").next().unwrap_or(line);
        let trimmed = code.trim_start().trim_start_matches("- ").trim();

        if let Some(action) = trimmed.strip_prefix("uses:") {
            let action = action.trim();
            let pinned = action.rsplit_once('@').is_some_and(|(_, reference)| {
                reference.len() == 40
                    && reference
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            });
            if !action.starts_with("./") {
                if !pinned {
                    problems.push(at("action is not pinned to a full commit SHA (SR-32)"));
                } else if !line.contains(" # v") {
                    problems.push(at(
                        "pinned action lacks a `# vX.Y.Z` version comment (SR-32)",
                    ));
                }
            }
        }
        if code.contains("pull_request_target") {
            problems.push(at("pull_request_target is forbidden (SR-33)"));
        }
        if code.contains("self-hosted") {
            problems.push(at("self-hosted runners are forbidden (SR-33)"));
        }
        if code.contains("secrets.") {
            problems.push(at("workflows must not use secrets (SR-34)"));
        }
        if trimmed.ends_with(": write") && file_name != RELEASE_WORKFLOW_FILE {
            problems.push(at("write permission outside the release workflow (SR-33)"));
        }

        // The top-level `permissions:` block must grant read access only.
        let top_level = !line.starts_with(' ') && !line.is_empty();
        if top_level {
            in_top_permissions = false;
            if let Some(inline) = code.strip_prefix("permissions:") {
                saw_top_permissions = true;
                in_top_permissions = true;
                let inline = inline.trim();
                if !(inline.is_empty() || inline == "{}") {
                    problems.push(at(
                        "top-level permissions must be a block of `read` entries",
                    ));
                }
            }
        } else if in_top_permissions && !trimmed.is_empty() && !trimmed.ends_with(": read") {
            problems.push(at("top-level token permission is not read-only (SR-33)"));
        }
    }
    if !saw_top_permissions {
        problems.push(format!(
            "{file_name}: no top-level `permissions:` block (SR-33)"
        ));
    }
    problems
}

fn check_workflows(root: &Path) -> Result<()> {
    let dir = root.join(".github").join("workflows");
    let mut problems = Vec::new();
    let mut checked = 0;
    if dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .collect();
        entries.sort();
        for path in entries {
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let text = String::from_utf8(util::read(&path)?)?;
            problems.extend(workflow_problems(&name, &text));
            checked += 1;
        }
    }
    println!("  {checked} workflow files checked");
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!("workflow policy violations:\n  {}", problems.join("\n  ")).into())
    }
}

// ---- advisories -------------------------------------------------------------

const CARGO_DENY_VERSION: &str = "0.21.0";

/// Pinned `cargo-deny` release binaries: (target triple, archive SHA-256,
/// executable name). Hashes match the `.sha256` files upstream publishes
/// beside each asset (checked 2026-11-17; see docs/DEPENDENCIES.md).
const CARGO_DENY_BUILDS: &[(&str, &str, &str)] = &[
    (
        "x86_64-unknown-linux-musl",
        "a2170b854ff697e79e39c4c538981c9c1bdd803addbae6719a4cb66b4585a903",
        "cargo-deny",
    ),
    (
        "x86_64-pc-windows-msvc",
        "8c445ef95217269d3cee234b18e2f543f8f1653f4a9801d9439df24bfcef4824",
        "cargo-deny.exe",
    ),
];

fn cargo_deny() -> Result<PathBuf> {
    let triple = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-musl"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-msvc"
    } else {
        return Err("no pinned cargo-deny build for this host platform".into());
    };
    let (_, sha256, exe) = CARGO_DENY_BUILDS
        .iter()
        .find(|(t, _, _)| *t == triple)
        .expect("triple is one of the pinned builds");
    let stem = format!("cargo-deny-{CARGO_DENY_VERSION}-{triple}");
    let cache = fetch::cache_dir(&format!("cargo-deny-{CARGO_DENY_VERSION}"));
    let archive = cache.join(format!("{stem}.tar.gz"));
    let url = format!(
        "https://github.com/EmbarkStudios/cargo-deny/releases/download/{CARGO_DENY_VERSION}/{stem}.tar.gz"
    );
    // Verified on every run, and the binary is re-extracted from the
    // verified archive each time, so a modified cached executable is never
    // run.
    fetch::download(&url, sha256, &archive)?;
    let member = format!("{stem}/{exe}");
    fetch::extract(&archive, &cache, &[&member])?;
    Ok(cache.join(stem).join(exe))
}

fn check_advisories(root: &Path) -> Result<()> {
    let deny = cargo_deny()?;
    util::run(
        Command::new(deny)
            .current_dir(root)
            .args(["check", "advisories"]),
    )
}

// ---- driver -----------------------------------------------------------------

fn cargo_step(root: &Path, args: &[&str]) -> Result<()> {
    util::run(Command::new(util::cargo()).current_dir(root).args(args))
}

/// `cargo xtask audit [--offline]`. `--offline` skips only the advisory
/// check, which needs the network, and says so; CI never passes it.
pub fn audit(offline: bool) -> Result<()> {
    let root = util::workspace_root();
    type Check<'a> = (&'a str, Box<dyn Fn() -> Result<()> + 'a>);
    let checks: Vec<Check> = vec![
        (
            "format",
            Box::new(|| cargo_step(&root, &["fmt", "--all", "--check"])),
        ),
        (
            "lint (host crates)",
            Box::new(|| {
                cargo_step(
                    &root,
                    &[
                        "clippy",
                        "--locked",
                        "--workspace",
                        "--exclude",
                        "keel-kernel",
                        "--exclude",
                        "keel-rt",
                        "--exclude",
                        "keel-user-tests",
                        "--all-targets",
                        "--",
                        "-D",
                        "warnings",
                    ],
                )
            }),
        ),
        (
            "lint (kernel)",
            Box::new(|| {
                cargo_step(
                    &root,
                    &[
                        "clippy",
                        "--locked",
                        "--release",
                        "--package",
                        "keel-kernel",
                        "--target",
                        "x86_64-unknown-none",
                        "--",
                        "-D",
                        "warnings",
                    ],
                )
            }),
        ),
        (
            "lint (user programs)",
            Box::new(|| {
                cargo_step(
                    &root,
                    &[
                        "clippy",
                        "--locked",
                        "--release",
                        "--package",
                        "keel-rt",
                        "--package",
                        "keel-user-tests",
                        "--target",
                        "x86_64-unknown-none",
                        "--target-dir",
                        "target/user",
                        "--",
                        "-D",
                        "warnings",
                    ],
                )
            }),
        ),
        ("unsafe census", Box::new(|| check_unsafe(&root))),
        ("licenses", Box::new(|| check_licenses(&root))),
        ("workflows", Box::new(|| check_workflows(&root))),
    ];

    let mut failures = Vec::new();
    for (name, check) in &checks {
        println!("xtask: audit: {name}");
        if let Err(error) = check() {
            println!("xtask: audit: {name}: FAILED\n{error}");
            failures.push(*name);
        }
    }
    if offline {
        println!("xtask: audit: advisories: SKIPPED (--offline). This audit is incomplete.");
    } else {
        println!("xtask: audit: advisories");
        if let Err(error) = check_advisories(&root) {
            println!("xtask: audit: advisories: FAILED\n{error}");
            failures.push("advisories");
        }
    }

    if failures.is_empty() {
        println!("xtask: audit passed");
        Ok(())
    } else {
        Err(format!("audit failed: {}", failures.join(", ")).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_each_kind_of_unsafe() {
        let source = "
            unsafe fn f() {}
            unsafe impl Sync for X {}
            #[unsafe(no_mangle)]
            fn g() {
                unsafe {
                    f();
                }
                let x = unsafe { 1 };
            }
        ";
        assert_eq!(
            count_unsafe(source),
            UnsafeCount {
                blocks: 2,
                block_lines: 4,
                declarations: 2,
                attributes: 1,
            }
        );
    }

    #[test]
    fn ignores_comments_strings_and_longer_identifiers() {
        let source = r##"
            // unsafe { }
            /* unsafe /* nested unsafe */ unsafe */
            /// # Safety: unsafe
            let a = "unsafe { }";
            let b = r#"unsafe "quoted" unsafe"#;
            let c = '"'; let d = "unsafe";
            fn not_unsafe_code<'a>(x: &'a str) {}
            #![deny(unsafe_code)]
            let unsafe_count = 1;
        "##;
        assert_eq!(count_unsafe(source), UnsafeCount::default());
    }

    #[test]
    fn blanking_preserves_line_structure() {
        let source = "a /* x\ny */ b\n\"s\ns\" c";
        let blanked = blank_comments_and_literals(source);
        assert_eq!(blanked.lines().count(), source.lines().count());
        assert!(blanked.contains('a') && blanked.contains('b') && blanked.contains('c'));
        assert!(!blanked.contains('x') && !blanked.contains('s'));
    }

    #[test]
    fn license_expressions() {
        assert!(license_allowed("MIT"));
        assert!(license_allowed("MIT OR Apache-2.0"));
        assert!(license_allowed("MIT/Apache-2.0"));
        assert!(license_allowed("Unlicense OR MIT"));
        assert!(license_allowed("(MIT OR Apache-2.0)"));
        assert!(license_allowed("GPL-3.0-only OR MIT"));
        assert!(license_allowed("MIT AND BSD-3-Clause"));
        assert!(!license_allowed("GPL-3.0-only"));
        assert!(!license_allowed("MIT AND LGPL-2.1-or-later"));
        assert!(!license_allowed("Apache-2.0 WITH LLVM-exception"));
        assert!(!license_allowed("(MIT OR Apache-2.0) AND GPL-2.0"));
        assert!(!license_allowed(""));
    }

    #[test]
    fn lockfile_lists_only_registry_packages() {
        let lock = "version = 4\n\n[[package]]\nname = \"spin\"\nversion = \"0.12.3\"\n\
            source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
            checksum = \"abc\"\n\n[[package]]\nname = \"xtask\"\nversion = \"0.0.0\"\n\
            dependencies = [\n \"spin\",\n]\n";
        assert_eq!(
            locked_packages(lock),
            vec![("spin".to_string(), "0.12.3".to_string())]
        );
    }

    const GOOD_WORKFLOW: &str = "name: ci\non: [push]\npermissions:\n  contents: read\njobs:\n  \
        build:\n    runs-on: ubuntu-24.04\n    steps:\n      \
        - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n      \
        - run: cargo xtask test\n";

    #[test]
    fn accepts_a_pinned_read_only_workflow() {
        assert_eq!(
            workflow_problems("ci.yml", GOOD_WORKFLOW),
            Vec::<String>::new()
        );
    }

    #[test]
    fn rejects_each_policy_violation() {
        let cases = [
            (
                "@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                "@v7 # v7.0.1",
            ),
            (
                "@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                "@3d3c42e # v7.0.1",
            ),
            (" # v7.0.1", ""),
            ("on: [push]", "on: [pull_request_target]"),
            ("ubuntu-24.04", "self-hosted"),
            ("contents: read", "contents: write"),
            ("permissions:\n  contents: read\n", ""),
            ("cargo xtask test", "echo ${{ secrets.TOKEN }}"),
            (
                "    runs-on",
                "    permissions:\n      id-token: write\n    runs-on",
            ),
        ];
        for (from, to) in cases {
            assert!(GOOD_WORKFLOW.contains(from), "test setup: {from:?}");
            let bad = GOOD_WORKFLOW.replacen(from, to, 1);
            assert!(
                !workflow_problems("ci.yml", &bad).is_empty(),
                "should reject replacing {from:?} with {to:?}"
            );
        }
    }

    #[test]
    fn release_workflow_may_grant_job_level_write() {
        let release = GOOD_WORKFLOW.replacen(
            "    runs-on",
            "    permissions:\n      contents: write\n      id-token: write\n    runs-on",
            1,
        );
        assert_eq!(
            workflow_problems("release.yml", &release),
            Vec::<String>::new()
        );
        // ...but its top-level default must still be read-only.
        let top = GOOD_WORKFLOW.replacen("contents: read", "contents: write", 1);
        assert!(!workflow_problems("release.yml", &top).is_empty());
    }
}
