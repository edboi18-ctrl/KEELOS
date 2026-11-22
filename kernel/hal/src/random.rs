//! Random bytes for AT_RANDOM (P1-T11).
//!
//! Interim source until the entropy work of P1-S5 (SR-16): RDRAND when the
//! CPU has it, otherwise a TSC-based mix that is NOT cryptographically
//! secure and is reported as such. Every caller learns which one it got.

use core::arch::asm;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::arch::x86_64::cpu;

/// CPUID.01H:ECX.RDRAND[30] (SDM Vol. 1 section 7.3.17.1).
const CPUID_1_ECX_RDRAND: u32 = 1 << 30;
/// Retry limit while RDRAND reports no data (CF = 0); the SDM's example
/// uses 10 (Vol. 1 section 7.3.17.1).
const RDRAND_RETRIES: u32 = 10;

/// Where random bytes came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quality {
    /// The CPU's DRBG (RDRAND).
    Hardware,
    /// TSC mixing only: unpredictable to a casual observer, not to an
    /// attacker. Acceptable for tests until P1-S5.
    Weak,
}

/// Whether the CPU reports RDRAND.
pub fn has_rdrand() -> bool {
    let (_, _, ecx, _) = cpu::cpuid(1, 0);
    ecx & CPUID_1_ECX_RDRAND != 0
}

/// One RDRAND result, retried up to the limit.
fn rdrand() -> Option<u64> {
    for _ in 0..RDRAND_RETRIES {
        let value: u64;
        let ok: u8;
        // Assembly reasoning (spec section 1, rule 4)
        // Entry state: CPUID reported RDRAND (checked by the caller).
        // Instructions: `rdrand {v}` loads a 64-bit value from the DRBG and
        //   sets CF = 1 if it is valid; otherwise the register is 0 and
        //   CF = 0; OF, SF, ZF, AF, PF are cleared (SDM Vol. 2B "RDRAND",
        //   Operation and Flags Affected). `setc {ok}` copies CF.
        // Exit state: {v} = value, {ok} = 1 if valid. No memory or stack
        //   use; flags change, so `preserves_flags` is not claimed.
        // SAFETY: RDRAND is supported (caller checked CPUID) and has no
        // effect beyond its register and flag outputs.
        unsafe {
            asm!(
                "rdrand {v}",
                "setc {ok}",
                v = out(reg) value,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok == 1 {
            return Some(value);
        }
    }
    None
}

/// 0 = not yet tested, 1 = passed, 2 = failed.
static RDRAND_STATE: AtomicU8 = AtomicU8::new(0);

/// Whether RDRAND is present and passed a sanity test. Some firmware does
/// not restore RDRAND correctly after suspend (Linux
/// `arch/x86/kernel/cpu/amd.c`, `clear_rdrand_cpuid_bit`), so it is not
/// trusted on CPUID alone. The test follows Linux `x86_init_rdrand`
/// (`arch/x86/kernel/cpu/rdrand.c` at v6.12): 8 samples, all valid, with
/// at least 5 changes between consecutive samples.
pub fn rdrand_usable() -> bool {
    match RDRAND_STATE.load(Ordering::Acquire) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let mut passed = has_rdrand();
    if passed {
        let mut changed = 0;
        let mut previous = None;
        for _ in 0..8 {
            let Some(sample) = rdrand() else {
                passed = false;
                break;
            };
            if previous.is_some_and(|p| p != sample) {
                changed += 1;
            }
            previous = Some(sample);
        }
        passed &= changed >= 5;
    }
    RDRAND_STATE.store(if passed { 1 } else { 2 }, Ordering::Release);
    passed
}

/// SplitMix64 finaliser (Steele, Lea, Flood, "Fast splittable
/// pseudorandom number generators", OOPSLA 2014; constants as in Vigna's
/// reference `splitmix64.c`, prng.di.unimi.it): spreads TSC bits.
fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Fills `buf` and says how good the bytes are.
pub fn fill(buf: &mut [u8]) -> Quality {
    let hardware = rdrand_usable();
    let mut quality = if hardware {
        Quality::Hardware
    } else {
        Quality::Weak
    };
    let mut state = cpu::read_tsc();
    for chunk in buf.chunks_mut(8) {
        let word = match hardware.then(rdrand).flatten() {
            Some(word) => word,
            None => {
                quality = Quality::Weak;
                state = mix(state ^ cpu::read_tsc());
                state
            }
        };
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
    quality
}
