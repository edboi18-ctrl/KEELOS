//! The two primitives behind Keel's random-number generator (P1-S5):
//! the ChaCha20 block function (RFC 8439, section 2.3) and BLAKE2s
//! (RFC 7693). Checked against the RFCs' own test vectors, including the
//! RFC 7693 Appendix E self-test (a hash over 48 keyed and unkeyed hashes
//! of several lengths).
//!
//! RFC texts used: rfc8439.txt (SHA-256 25bef70f...415324c) and
//! rfc7693.txt (SHA-256 c9437548...0721e5), from rfc-editor.org,
//! read 2026-11-22.

/// "expand 32-byte k" (RFC 8439 section 2.3).
const CHACHA_CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    // RFC 8439 section 2.1.
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// One 64-byte ChaCha20 block for `key`, `counter` and `nonce`.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&CHACHA_CONSTANTS);
    for (i, word) in key.as_chunks::<4>().0.iter().enumerate() {
        state[4 + i] = u32::from_le_bytes(*word);
    }
    state[12] = counter;
    for (i, word) in nonce.as_chunks::<4>().0.iter().enumerate() {
        state[13 + i] = u32::from_le_bytes(*word);
    }
    let mut working = state;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// BLAKE2s IV: the SHA-256 IV (RFC 7693 section 2.6).
const BLAKE2S_IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// Message schedule (RFC 7693 section 2.7).
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Incremental BLAKE2s (RFC 7693; rotations 16, 12, 8, 7; 10 rounds).
#[derive(Clone)]
pub struct Blake2s {
    h: [u32; 8],
    /// Bytes compressed so far (the offset counter t).
    t: u64,
    buffer: [u8; 64],
    filled: usize,
    out_len: usize,
}

fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

impl Blake2s {
    /// A hash of `out_len` bytes (1 to 32), keyed if `key` is not empty
    /// (at most 32 bytes). Panics on other sizes (a programming error).
    pub fn new(out_len: usize, key: &[u8]) -> Self {
        assert!((1..=32).contains(&out_len) && key.len() <= 32);
        let mut h = BLAKE2S_IV;
        // Parameter block p[0] = 0x0101kknn (section 2.5).
        h[0] ^= 0x0101_0000 ^ ((key.len() as u32) << 8) ^ out_len as u32;
        let mut hasher = Blake2s {
            h,
            t: 0,
            buffer: [0; 64],
            filled: 0,
            out_len,
        };
        if !key.is_empty() {
            // The key, zero-padded to one block, is the first block.
            hasher.buffer[..key.len()].copy_from_slice(key);
            hasher.filled = 64;
        }
        hasher
    }

    fn compress(&mut self, last: bool) {
        let mut m = [0u32; 16];
        for (i, word) in self.buffer.as_chunks::<4>().0.iter().enumerate() {
            m[i] = u32::from_le_bytes(*word);
        }
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&BLAKE2S_IV);
        v[12] ^= self.t as u32;
        v[13] ^= (self.t >> 32) as u32;
        if last {
            v[14] = !v[14];
        }
        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            // A full buffer is compressed only once more data arrives: the
            // last block must be compressed with the final flag.
            if self.filled == 64 {
                self.t += 64;
                self.compress(false);
                self.filled = 0;
            }
            let take = (64 - self.filled).min(data.len());
            self.buffer[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
        }
    }

    /// Finishes; writes `out_len` bytes to the front of `out`.
    pub fn finalize(mut self, out: &mut [u8]) {
        self.t += self.filled as u64;
        self.buffer[self.filled..].fill(0);
        self.compress(true);
        let mut digest = [0u8; 32];
        for (i, word) in self.h.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out[..self.out_len].copy_from_slice(&digest[..self.out_len]);
    }

    /// One-shot 32-byte unkeyed hash.
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut h = Blake2s::new(32, &[]);
        h.update(data);
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_quarter_round_vector() {
        // RFC 8439 section 2.1.1.
        let mut s = [0u32; 16];
        s[0] = 0x1111_1111;
        s[1] = 0x0102_0304;
        s[2] = 0x9b8d_6f43;
        s[3] = 0x0123_4567;
        quarter_round(&mut s, 0, 1, 2, 3);
        assert_eq!(
            &s[..4],
            &[0xea2a_92f4, 0xcb1c_f8ce, 0x4581_472e, 0x5881_c4bb]
        );
    }

    #[test]
    fn chacha20_block_vectors() {
        // RFC 8439 section 2.3.2.
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let block = chacha20_block(&key, 1, &nonce);
        let expected_start = [0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15];
        let expected_end = [0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e];
        assert_eq!(&block[..8], &expected_start);
        assert_eq!(&block[56..], &expected_end);
        // Appendix A.1, test vector #1: all-zero key, nonce and counter.
        let zero = chacha20_block(&[0; 32], 0, &[0; 12]);
        assert_eq!(
            &zero[..8],
            &[0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90]
        );
        assert_eq!(
            &zero[56..],
            &[0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86]
        );
    }

    #[test]
    fn blake2s_abc() {
        // RFC 7693 Appendix B.
        let expected = [
            0x50, 0x8C, 0x5E, 0x8C, 0x32, 0x7C, 0x14, 0xE2, 0xE1, 0xA7, 0x2B, 0xA3, 0x4E, 0xEB,
            0x45, 0x2F, 0x37, 0x45, 0x8B, 0x20, 0x9E, 0xD6, 0x3A, 0x29, 0x4D, 0x99, 0x9B, 0x4C,
            0x86, 0x67, 0x59, 0x82,
        ];
        assert_eq!(Blake2s::hash(b"abc"), expected);
        // Split updates give the same digest.
        let mut h = Blake2s::new(32, &[]);
        h.update(b"a");
        h.update(b"bc");
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        assert_eq!(out, expected);
    }

    /// RFC 7693 Appendix E, `blake2s_selftest`.
    #[test]
    fn blake2s_rfc_selftest() {
        fn seq(out: &mut [u8], seed: u32) {
            let mut a = 0xDEAD_4BADu32.wrapping_mul(seed);
            let mut b = 1u32;
            for byte in out.iter_mut() {
                let t = a.wrapping_add(b);
                a = b;
                b = t;
                *byte = (t >> 24) as u8;
            }
        }
        let expected = [
            0x6A, 0x41, 0x1F, 0x08, 0xCE, 0x25, 0xAD, 0xCD, 0xFB, 0x02, 0xAB, 0xA6, 0x41, 0x45,
            0x1C, 0xEC, 0x53, 0xC5, 0x98, 0xB2, 0x4F, 0x4F, 0xC7, 0x87, 0xFB, 0xDC, 0x88, 0x79,
            0x7F, 0x4C, 0x1D, 0xFE,
        ];
        let mut grand = Blake2s::new(32, &[]);
        let mut input = [0u8; 1024];
        let mut key = [0u8; 32];
        for out_len in [16usize, 20, 28, 32] {
            for in_len in [0usize, 3, 64, 65, 255, 1024] {
                seq(&mut input[..in_len], in_len as u32);
                let mut md = [0u8; 32];
                let mut h = Blake2s::new(out_len, &[]);
                h.update(&input[..in_len]);
                h.finalize(&mut md);
                grand.update(&md[..out_len]);
                seq(&mut key[..out_len], out_len as u32);
                let mut h = Blake2s::new(out_len, &key[..out_len]);
                h.update(&input[..in_len]);
                h.finalize(&mut md);
                grand.update(&md[..out_len]);
            }
        }
        let mut result = [0u8; 32];
        grand.finalize(&mut result);
        assert_eq!(result, expected);
    }
}
