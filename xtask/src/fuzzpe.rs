//! `cargo xtask fuzz-pe --minutes N --seed S`: host fuzzing of the PE
//! parser (Phase 2 security note, P2-S1; acceptance is 30 minutes with no
//! crash). Uses the parser's own mutation engine (`pe::fuzz`) on the
//! fixture `hello.exe` and every file of the malformed corpus
//! (`fuzz/pe-corpus/`), and walks every accepted image completely. Runs in
//! xtask's dev profile, so integer overflow is a panic too.
//!
//! Panics abort here (workspace profile), so the input being tried is kept
//! in a static and a panic hook writes it to `target/fuzz-pe-crash.exe`
//! before the process ends; add it to the corpus once fixed.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::util::{self, Result};

static CURRENT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Inputs per progress report.
const BATCH: u64 = 20_000;

pub fn fuzz_pe(minutes: u64, seed: u64) -> Result<()> {
    let root = util::workspace_root();
    let mut templates = vec![util::read(&root.join("winetest/hello-console/hello.exe"))?];
    let corpus = root.join("fuzz/pe-corpus");
    let mut names: Vec<_> = std::fs::read_dir(&corpus)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    names.sort();
    for path in names {
        templates.push(util::read(&path)?);
    }
    let crash_file = root.join("target").join("fuzz-pe-crash.exe");
    let crash_report = crash_file.clone();
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Ok(input) = CURRENT.lock() {
            let _ = std::fs::write(&crash_report, &*input);
        }
        eprintln!(
            "xtask: fuzz-pe: the parser PANICKED; input written to {}",
            crash_report.display()
        );
        default_hook(info);
    }));

    println!(
        "xtask: fuzz-pe: seed {seed}, {} minutes, {} starting files",
        minutes,
        templates.len()
    );
    let deadline = Instant::now() + Duration::from_secs(minutes * 60);
    let mut rng = pe::fuzz::Rng(seed);
    let (mut total, mut accepted) = (0u64, 0u64);
    let mut next_report = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        for _ in 0..BATCH {
            let input = pe::fuzz::input(&mut rng, &templates);
            if let Ok(mut current) = CURRENT.lock() {
                current.clone_from(&input);
            }
            if pe::fuzz::exercise(&input) {
                accepted += 1;
            }
            total += 1;
        }
        if Instant::now() >= next_report {
            println!("xtask: fuzz-pe: {total} inputs, {accepted} accepted");
            next_report += Duration::from_secs(60);
        }
    }
    println!(
        "  TEST pe.fuzz PASS {total} inputs in {minutes} minutes ({accepted} accepted as images), no panic"
    );
    println!("xtask: fuzz-pe PASSED (seed {seed})");
    Ok(())
}
