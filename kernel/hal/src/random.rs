//! The kernel's random numbers (P1-S5, SR-16): a `keel_core::rng::Rng`
//! (BLAKE2s pool, ChaCha20 fast-key-erasure output) behind one lock.
//!
//! Seeded at boot from RDSEED (CPUID.07H.00H:EBX.RDSEED[18]) and RDRAND
//! (after a Linux-style self-test), TSC jitter, and the timing of
//! interrupts collected since boot; reseeded with fresh hardware output
//! and interrupt timing every 60 seconds, as Linux does
//! (`CRNG_RESEED_INTERVAL = 60 * HZ`, drivers/char/random.c v6.12).
//! Never a fixed seed: an unseeded generator produces nothing, and the
//! first request seeds it.
//!
//! Every caller learns the quality: `Hardware` if a CPU random-number
//! instruction contributed, `Weak` if only timing did (then the output is
//! unpredictable only as far as timing is, which on an emulator or VM may
//! be not much). The boot log says which.

use core::arch::asm;
use core::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};

use keel_core::rng::{Rng, Stream};

use crate::arch::x86_64::cpu;
use crate::sync::IrqMutex;

/// CPUID.01H:ECX.RDRAND[30] (SDM Vol. 1 section 7.3.17.1).
const CPUID_1_ECX_RDRAND: u32 = 1 << 30;
/// Retry limit while RDRAND reports no data (CF = 0); the SDM's example
/// uses 10 (Vol. 1 section 7.3.17.1).
const RDRAND_RETRIES: u32 = 10;

/// CPUID.07H.00H:EBX.RDSEED[18] (SDM Vol. 1 section 7.3.17.2).
const CPUID_7_EBX_RDSEED: u32 = 1 << 18;

/// What seeded the generator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quality {
    /// RDSEED and/or RDRAND output, plus timing.
    Hardware,
    /// Timing only (TSC jitter, interrupt arrival times).
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

/// Whether the CPU reports RDSEED.
pub fn has_rdseed() -> bool {
    let (max_leaf, ..) = cpu::cpuid(0, 0);
    max_leaf >= 7 && cpu::cpuid(7, 0).1 & CPUID_7_EBX_RDSEED != 0
}

/// One RDSEED result, retried up to the limit.
fn rdseed() -> Option<u64> {
    for _ in 0..RDRAND_RETRIES {
        let value: u64;
        let ok: u8;
        // Assembly reasoning (spec section 1, rule 4)
        // Entry state: CPUID reported RDSEED (checked by the caller).
        // Instructions: `rdseed {v}` loads a 64-bit value from the
        //   enhanced NRBG and sets CF = 1 if it is valid, else zeroes the
        //   register and clears CF; OF, SF, ZF, AF, PF are cleared (SDM
        //   Vol. 2B "RDSEED", Operation and Flags Affected). `setc {ok}`
        //   copies CF. The SDM recommends retrying while CF = 0 (Vol. 1
        //   section 7.3.17.2); like RDRAND, a bounded number of times.
        // Exit state: {v} = value, {ok} = 1 if valid. No memory or stack
        //   use; flags change.
        // SAFETY: RDSEED is supported and only writes its outputs.
        unsafe {
            asm!(
                "rdseed {v}",
                "setc {ok}",
                v = out(reg) value,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok == 1 {
            return Some(value);
        }
        core::hint::spin_loop();
    }
    None
}

/// Interrupt arrival times since the last reseed, folded into 64 slots
/// without locks (interrupt handlers call `add_interrupt_timing`).
static TIMING: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static TIMING_NEXT: AtomicUsize = AtomicUsize::new(0);

/// Records the arrival time of an interrupt. Cheap and lock-free; called
/// from the timer and keyboard handlers.
pub fn add_interrupt_timing() {
    let tsc = cpu::read_tsc();
    let slot = TIMING_NEXT.fetch_add(1, Ordering::Relaxed);
    TIMING[slot % 64].fetch_xor(tsc.rotate_left((slot % 64) as u32), Ordering::Relaxed);
}

/// Reseed interval: 60 s, as Linux, counted in timer ticks. Linux
/// schedules its reseed by jiffies (`crng_reseed_interval`,
/// drivers/char/random.c v6.12) and reads no clock when producing output;
/// here too a request never touches a clock device. Reading the clock per
/// request cost an HPET access and two CPUIDs, which under KVM are exits
/// to the hypervisor: a 128 MiB getrandom took over 15 s in CI (F-0010).
const RESEED_INTERVAL_TICKS: u64 = 60 * crate::time::TICK_HZ;

struct State {
    rng: Rng,
    quality: Quality,
    last_reseed_tick: u64,
}

static STATE: IrqMutex<Option<State>> = IrqMutex::new(None);

/// Requests served (each takes the generator's lock once), for the F-0010
/// regression test.
static DRAWS: AtomicU64 = AtomicU64::new(0);

/// How many times the generator has been asked for output since boot.
pub fn draws() -> u64 {
    DRAWS.load(Ordering::Relaxed)
}

/// Mixes everything available into `rng`; returns whether a hardware
/// source contributed.
fn collect(rng: &mut Rng) -> bool {
    let mut hardware = false;
    if has_rdseed() {
        for _ in 0..16 {
            if let Some(v) = rdseed() {
                rng.mix(&v.to_le_bytes());
                hardware = true;
            }
        }
    }
    if rdrand_usable() {
        for _ in 0..16 {
            if let Some(v) = rdrand() {
                rng.mix(&v.to_le_bytes());
                hardware = true;
            }
        }
    }
    // TSC jitter: the low bits of the time between closely spaced reads.
    let mut previous = cpu::read_tsc();
    let mut jitter = [0u8; 256];
    for byte in jitter.iter_mut() {
        for _ in 0..8 {
            core::hint::spin_loop();
        }
        let now = cpu::read_tsc();
        *byte = now.wrapping_sub(previous) as u8;
        previous = now;
    }
    rng.mix(&jitter);
    for slot in &TIMING {
        rng.mix(&slot.swap(0, Ordering::Relaxed).to_le_bytes());
    }
    rng.mix(&cpu::read_tsc().to_le_bytes());
    hardware
}

/// Three random words for the kernel's own layout (the region bases in
/// `paging::init`), needed before the timer and `init`. Drawn from a
/// separate generator seeded exactly as the main one is (`collect`:
/// RDSEED, RDRAND after its self-test, TSC jitter), then dropped. Linux
/// draws its memory-region offsets early in the same spirit
/// (`kaslr_get_random_long`). Also says whether hardware contributed.
pub fn early_words() -> ([u64; 3], Quality) {
    let mut rng = Rng::new();
    let hardware = collect(&mut rng);
    rng.reseed();
    let mut bytes = [0u8; 24];
    let filled = rng.fill(&mut bytes);
    debug_assert!(filled, "seeded just above");
    let word = |i: usize| {
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        u64::from_le_bytes(w)
    };
    let quality = if hardware {
        Quality::Hardware
    } else {
        Quality::Weak
    };
    ([word(0), word(1), word(2)], quality)
}

/// Seeds the generator (call once at boot, after the clock is set up;
/// a `fill` before that seeds it on first use). Returns the quality.
pub fn init() -> Quality {
    let mut guard = STATE.lock();
    if let Some(state) = guard.as_ref() {
        return state.quality;
    }
    let mut rng = Rng::new();
    let hardware = collect(&mut rng);
    rng.reseed();
    let quality = if hardware {
        Quality::Hardware
    } else {
        Quality::Weak
    };
    *guard = Some(State {
        rng,
        quality,
        last_reseed_tick: crate::time::ticks(),
    });
    quality
}

/// Runs `f` on the seeded generator, reseeding first if the interval has
/// passed.
fn with_generator<R>(f: impl FnOnce(&mut State) -> R) -> R {
    if STATE.lock().is_none() {
        init();
    }
    DRAWS.fetch_add(1, Ordering::Relaxed);
    let mut guard = STATE.lock();
    let state = guard.as_mut().expect("seeded by init");
    let now = crate::time::ticks();
    if now.wrapping_sub(state.last_reseed_tick) >= RESEED_INTERVAL_TICKS {
        if collect(&mut state.rng) {
            state.quality = Quality::Hardware;
        }
        state.rng.reseed();
        state.last_reseed_tick = now;
    }
    f(state)
}

/// Fills `buf` with random bytes and says how the generator was seeded.
pub fn fill(buf: &mut [u8]) -> Quality {
    with_generator(|state| {
        let filled = state.rng.fill(buf);
        debug_assert!(filled, "the generator is seeded before use");
        state.quality
    })
}

/// A keystream for one large request (getrandom, a read of
/// `/dev/urandom`), keyed from the generator under one lock; the caller
/// then fills any amount without the lock (Linux v6.12
/// `get_random_bytes_user`).
pub fn stream() -> (Stream, Quality) {
    with_generator(|state| {
        let stream = state.rng.stream().expect("seeded by init");
        (stream, state.quality)
    })
}

/// A uniformly distributed value below `bound`, for address randomization.
pub fn below(bound: u64) -> u64 {
    with_generator(|state| state.rng.below(bound).unwrap_or(0))
}
