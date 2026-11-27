//! `cargo xtask fuzz-manifest --minutes N --seed S`: host fuzzing of the
//! compartment-manifest parser (P3-S2, ADR 0040; spec section 3, "Parser
//! fuzzing on the host"). Starts from every manifest in
//! `fuzz/manifest-corpus/` and mutates them: bytes flipped, inserted and
//! removed, tokens of the format inserted, lines duplicated and swapped.
//! Every input is parsed; every accepted one is checked against what
//! `keel_manifest` promises (the required keys there, `exec` and the
//! root absolute, the limits in range, no NUL in a string), so a parser
//! that accepts what it should not is caught as well as one that panics.
//! Runs in xtask's dev profile, so integer overflow is a panic too.
//!
//! Panics abort (workspace profile), so the input being tried is kept in
//! a static and a panic hook writes it to `target/fuzz-manifest-crash.toml`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::util::{self, Result};

static CURRENT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

const BATCH: u64 = 20_000;

/// Pieces of the format, inserted whole.
const TOKENS: &[&[u8]] = &[
    b"[",
    b"]",
    b"[[",
    b"]]",
    b"\"",
    b"=",
    b"#",
    b"\\",
    b"\\\"",
    b"\\n",
    b"\n",
    b"\r\n",
    b",",
    b" ",
    b"\t",
    b"\0",
    b"\xff",
    b"[root]",
    b"[limits]",
    b"[display]",
    b"[network]",
    b"[[grant]]",
    b"name",
    b"exec",
    b"args",
    b"env",
    b"devices",
    b"profile",
    b"base",
    b"memory_mb",
    b"processes",
    b"handles",
    b"tmpfs_mb",
    b"tmpfs_nodes",
    b"allowed",
    b"true",
    b"false",
    b"0",
    b"18446744073709551616",
    b"\"null\"",
    b"\"ptmx\"",
    b"\"/x\"",
    b"\"\"",
];

/// xorshift64 (Marsaglia 2003, section 3: shifts 13, 7, 17).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    for _ in 0..1 + rng.below(8) {
        match rng.below(7) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(v.len() + 1);
                v.insert(i, rng.next() as u8);
            }
            2 if !v.is_empty() => {
                let i = rng.below(v.len());
                let n = 1 + rng.below(16.min(v.len() - i));
                v.drain(i..i + n);
            }
            3 => {
                let t = TOKENS[rng.below(TOKENS.len())];
                let i = rng.below(v.len() + 1);
                v.splice(i..i, t.iter().copied());
            }
            4 => {
                let lines: Vec<&[u8]> = base.split(|&b| b == b'\n').collect();
                let line = lines[rng.below(lines.len())];
                let i = rng.below(v.len() + 1);
                let mut piece = line.to_vec();
                piece.push(b'\n');
                v.splice(i..i, piece);
            }
            5 => {
                // A long string or a long run of one byte.
                let i = rng.below(v.len() + 1);
                let n = rng.below(5000);
                let b = TOKENS[rng.below(TOKENS.len())]
                    .first()
                    .copied()
                    .unwrap_or(b'x');
                v.splice(i..i, std::iter::repeat_n(b, n));
            }
            _ => {
                let mut lines: Vec<Vec<u8>> =
                    v.split(|&b| b == b'\n').map(<[u8]>::to_vec).collect();
                let (a, b) = (rng.below(lines.len()), rng.below(lines.len()));
                lines.swap(a, b);
                v = lines.join(&b'\n');
            }
        }
    }
    v
}

/// What every accepted manifest must be (`keel_manifest`'s documentation).
fn check(m: &keel_manifest::Manifest) {
    let abs = |s: &[u8]| s.first() == Some(&b'/') && !s.contains(&0);
    assert!(!m.name().is_empty() && m.name().len() <= 64, "name");
    assert!(
        m.name()
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "name bytes"
    );
    assert!(abs(m.exec()) && abs(m.root()), "paths");
    assert!(m.args().all(|a| !a.contains(&0)), "args");
    assert!(m.args().count() <= keel_manifest::MAX_LIST, "args count");
    assert!(
        m.env()
            .all(|e| !e.contains(&0) && e.iter().position(|&b| b == b'=').is_some_and(|i| i > 0)),
        "env"
    );
    let devices: Vec<_> = m.devices().collect();
    assert!(devices.len() <= 5, "devices");
    for (i, d) in devices.iter().enumerate() {
        assert!(!devices[..i].contains(d), "a device twice");
    }
    let l = m.limits;
    assert!((1..=1 << 20).contains(&l.memory_mb), "memory_mb");
    assert!((1..=4096).contains(&l.processes), "processes");
    assert!((3..=1024).contains(&l.handles), "handles");
    assert!(l.tmpfs_mb <= 1 << 20 && l.tmpfs_nodes <= 1 << 24, "tmpfs");
}

pub fn fuzz_manifest(minutes: u64, seed: u64) -> Result<()> {
    let root = util::workspace_root();
    let corpus = root.join("fuzz/manifest-corpus");
    let mut names: Vec<_> = std::fs::read_dir(&corpus)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    names.sort();
    let mut templates = Vec::new();
    for path in names {
        templates.push(util::read(&path)?);
    }
    if templates.is_empty() {
        return Err("fuzz/manifest-corpus is empty".into());
    }
    let crash_file = root.join("target").join("fuzz-manifest-crash.toml");
    let crash_report = crash_file.clone();
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Ok(input) = CURRENT.lock() {
            let _ = std::fs::write(&crash_report, &*input);
        }
        eprintln!(
            "xtask: fuzz-manifest: the parser PANICKED; input written to {}",
            crash_report.display()
        );
        default_hook(info);
    }));
    println!(
        "xtask: fuzz-manifest: seed {seed}, {minutes} minutes, {} starting files",
        templates.len()
    );
    let deadline = Instant::now() + Duration::from_secs(minutes * 60);
    let mut rng = Rng(seed | 1);
    let (mut total, mut accepted) = (0u64, 0u64);
    let mut next_report = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        for _ in 0..BATCH {
            let base = &templates[rng.below(templates.len())];
            let input = mutate(&mut rng, base);
            if let Ok(mut current) = CURRENT.lock() {
                current.clone_from(&input);
            }
            if let Ok(m) = keel_manifest::parse(&input) {
                check(&m);
                accepted += 1;
            }
            total += 1;
        }
        if Instant::now() >= next_report {
            println!("xtask: fuzz-manifest: {total} inputs, {accepted} accepted");
            next_report += Duration::from_secs(60);
        }
    }
    println!(
        "  TEST manifest.fuzz PASS {total} inputs in {minutes} minutes ({accepted} accepted), no panic and every accepted manifest valid"
    );
    println!("xtask: fuzz-manifest PASSED (seed {seed})");
    Ok(())
}
