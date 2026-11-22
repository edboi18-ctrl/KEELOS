//! A mutation fuzzer for the parser (P2-S1), shared by the unit test and
//! `cargo xtask fuzz-pe`. Deterministic from its seed, so a failure can be
//! replayed. Inputs are random bytes or valid files with some bytes
//! changed: flipped bits, boundary values written over header fields, and
//! truncation. Each accepted image is walked completely (sections, headers,
//! imports, relocations), so every reader runs on the result.

use std::vec::Vec;

/// SplitMix64 (Sebastiano Vigna, public domain), as in keel-rt's fuzzer.
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n.max(1) as u64) as usize
    }
}

/// Values that sit on the edges of checks.
const BOUNDARY: [u32; 10] = [
    0,
    1,
    2,
    0x200,
    0x1000,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFF,
    0xFFFF_FFF8,
    0x0001_0000,
];

/// One input derived from `templates` (or random bytes).
pub fn input(rng: &mut Rng, templates: &[Vec<u8>]) -> Vec<u8> {
    if templates.is_empty() || rng.below(8) == 0 {
        let len = rng.below(2048);
        return (0..len).map(|_| rng.next_u64() as u8).collect();
    }
    let mut data = templates[rng.below(templates.len())].clone();
    for _ in 0..=rng.below(8) {
        if data.is_empty() {
            break;
        }
        match rng.below(4) {
            // Flip a byte anywhere.
            0 => {
                let at = rng.below(data.len());
                data[at] ^= rng.next_u64() as u8 | 1;
            }
            // A boundary value over a 4-byte field in the headers.
            1 => {
                let limit = data.len().min(0x400).saturating_sub(4);
                let at = rng.below(limit / 2) * 2;
                let value = BOUNDARY[rng.below(BOUNDARY.len())];
                if at + 4 <= data.len() {
                    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
                }
            }
            // A boundary value anywhere (tables live in sections).
            2 => {
                let at = rng.below(data.len().saturating_sub(4).max(1));
                let value = BOUNDARY[rng.below(BOUNDARY.len())];
                if at + 4 <= data.len() {
                    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
                }
            }
            // Truncate.
            _ => {
                let keep = rng.below(data.len());
                data.truncate(keep);
            }
        }
    }
    data
}

/// Parses `data` and walks everything an accepted image offers. Returns
/// whether it was accepted. Must never panic.
pub fn exercise(data: &[u8]) -> bool {
    let Ok(image) = crate::parse(data) else {
        return false;
    };
    let _ = image.headers();
    for i in 0..image.section_count() {
        let section = image.section(i).expect("parse checked every section");
        assert!(!(section.write && section.execute));
        assert!(section.rva + section.memory_size <= image.size_of_image);
    }
    for import in image.imports() {
        if import.is_err() {
            break;
        }
    }
    for reloc in image.relocations() {
        match reloc {
            Ok(rva) => assert!(rva + 8 <= image.size_of_image),
            Err(_) => break,
        }
    }
    true
}

/// Runs `iterations` inputs from `seed`; returns how many were accepted.
pub fn run(seed: u64, iterations: u64, templates: &[Vec<u8>]) -> u64 {
    let mut rng = Rng(seed);
    let mut accepted = 0;
    for _ in 0..iterations {
        let data = input(&mut rng, templates);
        if exercise(&data) {
            accepted += 1;
        }
    }
    accepted
}
