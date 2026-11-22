//! The initial user stack of a new program (P1-T11).
//!
//! Layout from the System V AMD64 psABI 1.0, section 3.4.1, Figure 3.9
//! ("Initial Process Stack"), from low to high addresses:
//!
//! ```text
//! rsp ->  argc
//!         argv[0] .. argv[argc - 1], 0
//!         envp[0] .. envp[n - 1], 0
//!         auxv pairs (type, value) .., AT_NULL pair
//!         padding
//!         information block: argument and environment strings, the
//!         AT_EXECFN path, the 16 AT_RANDOM bytes, an 8-byte zero marker
//! top
//! ```
//!
//! RSP is 16-byte aligned at entry (same section). Auxiliary vector types
//! are from psABI Figure 3.11 and Linux `include/uapi/linux/auxvec.h` at
//! v6.12.

use alloc::vec;
use alloc::vec::Vec;

pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_FLAGS: u64 = 8;
pub const AT_ENTRY: u64 = 9;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_RANDOM: u64 = 25;
pub const AT_EXECFN: u64 = 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecError {
    /// A string contains a NUL byte.
    BadString,
    /// The caller passed AT_NULL, AT_RANDOM or AT_EXECFN, which the builder
    /// adds itself, or a stack top that is not 16-byte aligned.
    BadArgument,
    /// Everything together is larger than the limit (E2BIG).
    TooLarge,
}

/// The bytes to copy to the top of the new stack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackImage {
    /// Address of `bytes[0]`; equal to the initial RSP.
    pub rsp: u64,
    pub bytes: Vec<u8>,
}

/// Builds the initial stack that ends at `top`.
///
/// `auxv` holds the entries that depend on the image (AT_PHDR, AT_ENTRY,
/// ...); AT_RANDOM, AT_EXECFN and the terminating AT_NULL are added here.
/// The result is at most `limit` bytes.
pub fn initial_stack(
    top: u64,
    limit: usize,
    path: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
    random: &[u8; 16],
    auxv: &[(u64, u64)],
) -> Result<StackImage, ExecError> {
    if !top.is_multiple_of(16) {
        return Err(ExecError::BadArgument);
    }
    if auxv
        .iter()
        .any(|&(kind, _)| matches!(kind, AT_NULL | AT_RANDOM | AT_EXECFN))
    {
        return Err(ExecError::BadArgument);
    }
    let strings = || argv.iter().chain(envp).chain(core::iter::once(&path));
    if strings().any(|s| s.contains(&0)) {
        return Err(ExecError::BadString);
    }

    // Information block, laid out upward from `info`: strings, then the
    // random bytes at a 16-byte boundary, then the zero marker.
    let strings_len = strings()
        .try_fold(0usize, |total, s| total.checked_add(s.len() + 1))
        .ok_or(ExecError::TooLarge)?;
    let random_offset = strings_len.next_multiple_of(16);
    let info_len = random_offset + 16 + 8;
    // The pointer area, in 8-byte words.
    let aux_entries = auxv.len() + 3;
    let words = 1 + (argv.len() + 1) + (envp.len() + 1) + 2 * aux_entries;
    let total = (words * 8)
        .checked_add(info_len)
        .and_then(|n| n.checked_add(16))
        .ok_or(ExecError::TooLarge)?;
    if total > limit {
        return Err(ExecError::TooLarge);
    }

    let info = (top - info_len as u64) & !15;
    let rsp = (info - words as u64 * 8) & !15;
    let mut bytes = vec![0u8; (top - rsp) as usize];
    let at = |address: u64| (address - rsp) as usize;

    let mut cursor = info;
    let mut place = |s: &[u8], bytes: &mut Vec<u8>| {
        let start = cursor;
        bytes[at(start)..at(start) + s.len()].copy_from_slice(s);
        cursor += s.len() as u64 + 1; // the NUL is already zero
        start
    };
    let argv_ptrs: Vec<u64> = argv.iter().map(|s| place(s, &mut bytes)).collect();
    let envp_ptrs: Vec<u64> = envp.iter().map(|s| place(s, &mut bytes)).collect();
    let execfn = place(path, &mut bytes);
    let random_ptr = info + random_offset as u64;
    bytes[at(random_ptr)..at(random_ptr) + 16].copy_from_slice(random);

    let mut word = rsp;
    let mut push = |value: u64, bytes: &mut Vec<u8>| {
        bytes[at(word)..at(word) + 8].copy_from_slice(&value.to_le_bytes());
        word += 8;
    };
    push(argv.len() as u64, &mut bytes);
    for &p in &argv_ptrs {
        push(p, &mut bytes);
    }
    push(0, &mut bytes);
    for &p in &envp_ptrs {
        push(p, &mut bytes);
    }
    push(0, &mut bytes);
    for &(kind, value) in
        auxv.iter()
            .chain(&[(AT_RANDOM, random_ptr), (AT_EXECFN, execfn), (AT_NULL, 0)])
    {
        push(kind, &mut bytes);
        push(value, &mut bytes);
    }
    debug_assert!(word <= info);
    Ok(StackImage { rsp, bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOP: u64 = 0x7fff_ffff_e000;

    /// Reads the stack back the way a C runtime's `_start` does.
    struct Reader<'a> {
        image: &'a StackImage,
    }

    impl Reader<'_> {
        fn word(&self, address: u64) -> u64 {
            let at = (address - self.image.rsp) as usize;
            u64::from_le_bytes(self.image.bytes[at..at + 8].try_into().unwrap())
        }

        fn string(&self, address: u64) -> Vec<u8> {
            let at = (address - self.image.rsp) as usize;
            let rest = &self.image.bytes[at..];
            rest[..rest.iter().position(|&b| b == 0).unwrap()].to_vec()
        }
    }

    #[test]
    fn layout_matches_the_psabi() {
        let random = [7u8; 16];
        let image = initial_stack(
            TOP,
            1 << 20,
            b"/test/startup",
            &[b"/test/startup", b"alpha"],
            &[b"KEEL_TEST=1", b"HOME=/"],
            &random,
            &[(AT_PAGESZ, 4096), (AT_ENTRY, 0x40_1000)],
        )
        .unwrap();
        assert_eq!(image.rsp % 16, 0);
        assert_eq!(image.rsp + image.bytes.len() as u64, TOP);
        let r = Reader { image: &image };
        let sp = image.rsp;
        assert_eq!(r.word(sp), 2);
        assert_eq!(r.string(r.word(sp + 8)), b"/test/startup");
        assert_eq!(r.string(r.word(sp + 16)), b"alpha");
        assert_eq!(r.word(sp + 24), 0);
        assert_eq!(r.string(r.word(sp + 32)), b"KEEL_TEST=1");
        assert_eq!(r.string(r.word(sp + 40)), b"HOME=/");
        assert_eq!(r.word(sp + 48), 0);
        let mut aux = Vec::new();
        let mut p = sp + 56;
        loop {
            let (kind, value) = (r.word(p), r.word(p + 8));
            p += 16;
            if kind == AT_NULL {
                break;
            }
            aux.push((kind, value));
        }
        assert_eq!(&aux[..2], &[(AT_PAGESZ, 4096), (AT_ENTRY, 0x40_1000)]);
        assert_eq!(aux[2].0, AT_RANDOM);
        let at = (aux[2].1 - sp) as usize;
        assert_eq!(&image.bytes[at..at + 16], &random);
        assert_eq!(aux[2].1 % 16, 0);
        assert_eq!(aux[3].0, AT_EXECFN);
        assert_eq!(r.string(aux[3].1), b"/test/startup");
        // The information block lies above the vectors, the marker at the top.
        assert!(r.word(sp + 8) >= p);
        assert_eq!(r.word(TOP - 8), 0);
    }

    #[test]
    fn empty_argv_and_envp() {
        let image = initial_stack(TOP, 4096, b"/init", &[], &[], &[0; 16], &[]).unwrap();
        let r = Reader { image: &image };
        assert_eq!(r.word(image.rsp), 0);
        assert_eq!(r.word(image.rsp + 8), 0);
        assert_eq!(r.word(image.rsp + 16), 0);
        assert_eq!(r.word(image.rsp + 24), AT_RANDOM);
    }

    #[test]
    fn refuses_bad_input() {
        let run = |argv: &[&[u8]], auxv: &[(u64, u64)], limit| {
            initial_stack(TOP, limit, b"/x", argv, &[], &[0; 16], auxv)
        };
        assert_eq!(run(&[b"a\0b"], &[], 4096), Err(ExecError::BadString));
        for kind in [AT_NULL, AT_RANDOM, AT_EXECFN] {
            assert_eq!(run(&[], &[(kind, 1)], 4096), Err(ExecError::BadArgument));
        }
        let long = vec![b'x'; 5000];
        assert_eq!(run(&[&long], &[], 4096), Err(ExecError::TooLarge));
        assert!(run(&[&long], &[], 8192).is_ok());
        assert_eq!(
            initial_stack(TOP + 8, 4096, b"/x", &[], &[], &[0; 16], &[]),
            Err(ExecError::BadArgument)
        );
    }

    #[test]
    fn alignment_holds_for_every_shape() {
        for argc in 0..6 {
            for len in 0..40 {
                let arg = vec![b'a'; len];
                let argv: Vec<&[u8]> = (0..argc).map(|_| &arg[..]).collect();
                let image = initial_stack(
                    TOP,
                    1 << 16,
                    b"/p",
                    &argv,
                    &[b"E=1"],
                    &[1; 16],
                    &[(6, 4096)],
                )
                .unwrap();
                assert_eq!(image.rsp % 16, 0);
                assert_eq!(image.rsp + image.bytes.len() as u64, TOP);
            }
        }
    }
}
