//! The kernel's random-number generator (P1-S5, SR-16).
//!
//! Structure follows Linux's `drivers/char/random.c` since 5.17/5.18
//! (Jason A. Donenfeld's rewrite): an input pool hashed with BLAKE2s, and
//! a ChaCha20 generator that uses "fast key erasure" (Bernstein,
//! <https://blog.cr.yp.to/20170723-random.html>, which Linux cites): every
//! block's first 32 bytes replace the key and the second 32 are output,
//! exactly as Linux's `crng_fast_key_erasure` (v6.12), so output already
//! given out cannot be recomputed from a later state. The block is then
//! overwritten with zeros (Linux uses `memzero_explicit`; this crate has
//! no `unsafe`, so `black_box` keeps the compiler from dropping the
//! write, on a best-effort basis).
//!
//! - [`Rng::mix`] adds input (hardware RNG output, timing) to the pool;
//!   it never makes the output weaker, whatever the input is.
//! - [`Rng::reseed`] folds the pool into the key:
//!   `key = BLAKE2s(key = old key, data = pool digest)`.
//! - [`Rng::fill`] produces output.
//!
//! There is no fixed seed anywhere: an RNG that was never reseeded refuses
//! to produce output (SR-16: "never a fixed seed in release builds").

use crate::crypto::{Blake2s, chacha20_block};

pub struct Rng {
    key: [u8; 32],
    pool: Blake2s,
    /// Inputs mixed since the last reseed.
    pending: u64,
    /// Number of reseeds so far; 0 means not yet seeded.
    reseeds: u64,
    /// Block counter, part of the nonce (the key changes every block, so
    /// this is belt and braces).
    blocks: u64,
}

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}

impl Rng {
    pub fn new() -> Self {
        Rng {
            key: [0; 32],
            pool: Blake2s::new(32, &[]),
            pending: 0,
            reseeds: 0,
            blocks: 0,
        }
    }

    /// Adds `data` to the input pool.
    pub fn mix(&mut self, data: &[u8]) {
        self.pool.update(data);
        self.pending += 1;
    }

    /// Inputs mixed since the last reseed.
    pub fn pending(&self) -> u64 {
        self.pending
    }

    /// Whether the generator has been seeded at least once.
    pub fn seeded(&self) -> bool {
        self.reseeds > 0
    }

    /// Folds the pool into the key and starts a fresh pool.
    pub fn reseed(&mut self) {
        let pool = core::mem::replace(&mut self.pool, Blake2s::new(32, &[]));
        let mut digest = [0u8; 32];
        pool.finalize(&mut digest);
        let mut extract = Blake2s::new(32, &self.key);
        extract.update(&digest);
        extract.update(&self.reseeds.to_le_bytes());
        extract.finalize(&mut self.key);
        self.reseeds += 1;
        self.pending = 0;
    }

    /// Fills `out`. Returns false, leaving `out` untouched, if the
    /// generator was never seeded.
    pub fn fill(&mut self, out: &mut [u8]) -> bool {
        if !self.seeded() {
            return false;
        }
        for chunk in out.chunks_mut(32) {
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&self.blocks.to_le_bytes());
            let mut block = chacha20_block(&self.key, 0, &nonce);
            self.blocks = self.blocks.wrapping_add(1);
            // Fast key erasure: the first half becomes the next key.
            self.key.copy_from_slice(&block[..32]);
            chunk.copy_from_slice(&block[32..32 + chunk.len()]);
            block.fill(0);
            core::hint::black_box(&block);
        }
        true
    }

    /// A keystream for one large request, keyed with fresh output of this
    /// generator, so the caller can produce many bytes without holding the
    /// generator (Linux v6.12 `get_random_bytes_user`: `crng_make_state`
    /// once per call, then ChaCha20 blocks in a loop). `None` if the
    /// generator was never seeded.
    pub fn stream(&mut self) -> Option<Stream> {
        let mut key = [0u8; 32];
        self.fill(&mut key).then_some(Stream { key, block: 0 })
    }

    /// A uniformly distributed value below `bound` (> 0), by rejection.
    pub fn below(&mut self, bound: u64) -> Option<u64> {
        if bound == 0 {
            return None;
        }
        // Reject the top partial range so every value is equally likely.
        let limit = u64::MAX - u64::MAX % bound;
        loop {
            let mut bytes = [0u8; 8];
            if !self.fill(&mut bytes) {
                return None;
            }
            let value = u64::from_le_bytes(bytes);
            if value < limit {
                return Some(value % bound);
            }
        }
    }
}

/// ChaCha20 keystream for one request (see [`Rng::stream`]). Every call
/// to [`Stream::fill`] starts at a fresh block, so no keystream byte is
/// ever given out twice; the key is overwritten when the stream is
/// dropped (best effort, as in [`Rng::fill`]).
pub struct Stream {
    key: [u8; 32],
    /// Next block number: the low 32 bits are ChaCha20's block counter,
    /// the high 32 bits go in the nonce (RFC 8439 section 2.3), so the
    /// counter never wraps onto an earlier block.
    block: u64,
}

impl Stream {
    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(64) {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&((self.block >> 32) as u32).to_le_bytes());
            let mut block = chacha20_block(&self.key, self.block as u32, &nonce);
            self.block = self.block.wrapping_add(1);
            chunk.copy_from_slice(&block[..chunk.len()]);
            block.fill(0);
            core::hint::black_box(&block);
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.key.fill(0);
        core::hint::black_box(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_output_until_seeded() {
        let mut rng = Rng::new();
        let mut out = [7u8; 16];
        assert!(!rng.fill(&mut out));
        assert_eq!(out, [7; 16], "untouched");
        assert_eq!(rng.below(10), None);
        rng.mix(b"seed material");
        rng.reseed();
        assert!(rng.fill(&mut out) && out != [7; 16]);
    }

    #[test]
    fn same_inputs_same_outputs_different_inputs_differ() {
        let make = |seed: &[u8]| {
            let mut rng = Rng::new();
            rng.mix(seed);
            rng.reseed();
            let mut out = [0u8; 64];
            rng.fill(&mut out);
            out
        };
        assert_eq!(make(b"a"), make(b"a"));
        assert_ne!(make(b"a"), make(b"b"));
    }

    #[test]
    fn output_never_repeats_and_key_moves_forward() {
        let mut rng = Rng::new();
        rng.mix(b"x");
        rng.reseed();
        let key_before = rng.key;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill(&mut a);
        rng.fill(&mut b);
        assert_ne!(a, b);
        assert_ne!(rng.key, key_before, "fast key erasure replaced the key");
        // The output is not the key that follows it.
        assert_ne!(rng.key, b);
    }

    #[test]
    fn reseeding_changes_the_stream() {
        let mut one = Rng::new();
        one.mix(b"x");
        one.reseed();
        let mut two = Rng::new();
        two.mix(b"x");
        two.reseed();
        two.mix(b"more");
        two.reseed();
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        one.fill(&mut a);
        two.fill(&mut b);
        assert_ne!(a, b);
        assert_eq!(two.pending(), 0);
    }

    #[test]
    fn stream_needs_a_seed_and_never_repeats() {
        let mut rng = Rng::new();
        assert!(rng.stream().is_none());
        rng.mix(b"stream");
        rng.reseed();
        let mut one = rng.stream().unwrap();
        let mut two = rng.stream().unwrap();
        assert_ne!(one.key, two.key, "each stream has its own key");
        // Partial blocks still advance: no byte is given out twice.
        let mut a = [0u8; 10];
        let mut b = [0u8; 64];
        one.fill(&mut a);
        one.fill(&mut b);
        assert_ne!(a[..], b[..10]);
        assert_eq!(one.block, 2);
        let mut c = [0u8; 64];
        two.fill(&mut c);
        assert_ne!(b, c);
    }

    #[test]
    fn stream_is_chacha20_with_the_block_number_split_over_counter_and_nonce() {
        let key = [7u8; 32];
        let mut stream = Stream {
            key,
            block: (5 << 32) | 0xffff_ffff,
        };
        let mut out = [0u8; 128];
        stream.fill(&mut out);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(out[..64], chacha20_block(&key, u32::MAX, &nonce));
        nonce[..4].copy_from_slice(&6u32.to_le_bytes());
        assert_eq!(out[64..], chacha20_block(&key, 0, &nonce));
    }

    #[test]
    fn below_is_in_range_and_covers_it() {
        let mut rng = Rng::new();
        rng.mix(b"range");
        rng.reseed();
        let mut seen = [false; 7];
        for _ in 0..2000 {
            let v = rng.below(7).unwrap() as usize;
            seen[v] = true;
        }
        assert!(seen.iter().all(|&s| s));
        assert_eq!(rng.below(1), Some(0));
        assert_eq!(rng.below(0), None);
    }
}
