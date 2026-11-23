//! Timekeeping (P1-T7): the HPET as reference clock, the local APIC timer
//! calibrated against it and run periodically at 1 kHz, and a monotonic
//! nanosecond clock from the TSC (when invariant) or the HPET.
//!
//! References: IA-PC HPET Specification 1.0a, section 2.3 (register
//! offsets: capabilities 000h with COUNTER_CLK_PERIOD in bits 63:32, in
//! femtoseconds, at most 05F5E100h; configuration 010h with ENABLE_CNF in
//! bit 0; main counter 0F0h). Intel SDM Vol. 3 section 13.5.4 (APIC timer:
//! one-shot and periodic modes, divide configuration) and section 20.17.1
//! (invariant TSC).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::x86_64::{apic, cpu, paging};
use crate::interrupts;

/// Vector of the periodic timer interrupt.
pub const TIMER_VECTOR: u8 = 0x20;
/// Timer interrupts per second.
pub const TICK_HZ: u64 = 1000;
const CALIBRATION_MS: u64 = 10;
const FEMTOS_PER_NANO: u64 = 1_000_000;
const MAX_HPET_PERIOD_FS: u64 = 0x05F5_E100;

static HPET_BASE: AtomicU64 = AtomicU64::new(0);
static HPET_PERIOD_FS: AtomicU64 = AtomicU64::new(0);
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
static TSC_START: AtomicU64 = AtomicU64::new(0);
static HPET_START: AtomicU64 = AtomicU64::new(0);
static TICKS: AtomicU64 = AtomicU64::new(0);
/// Whether the monotonic clock reads the TSC: set once by `init`, from
/// CPUID (invariant TSC, a fixed property of the CPU) and a calibrated
/// frequency. Decided once because CPUID always exits to the hypervisor
/// under hardware virtualization (Intel SDM Vol. 3, 325384-093US, section
/// 28.1.2, "Instructions That Cause VM Exits Unconditionally"), which made
/// every clock read two VM exits (F-0010).
static TSC_CLOCK: AtomicBool = AtomicBool::new(false);

fn hpet_read(offset: u64) -> u64 {
    let base = HPET_BASE.load(Ordering::Acquire);
    // SAFETY: `base` maps the 1 KiB HPET register block uncached (`init`);
    // the offsets used are 64-bit registers inside it.
    unsafe { ((base + offset) as *const u64).read_volatile() }
}

fn hpet_write(offset: u64, value: u64) {
    let base = HPET_BASE.load(Ordering::Acquire);
    // SAFETY: as in `hpet_read`.
    unsafe { ((base + offset) as *mut u64).write_volatile(value) }
}

fn hpet_counter() -> u64 {
    hpet_read(0xF0)
}

/// Busy-waits for `nanos` nanoseconds by the HPET.
fn hpet_wait(nanos: u64) {
    let ticks = nanos * FEMTOS_PER_NANO / HPET_PERIOD_FS.load(Ordering::Relaxed);
    let start = hpet_counter();
    while hpet_counter().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

/// The TSC frequency calibrated at `init`, in Hz (0 before then).
pub fn tsc_hz() -> u64 {
    TSC_HZ.load(Ordering::Relaxed)
}

/// Nanoseconds since `init`, from the HPET.
pub fn hpet_nanos() -> u64 {
    let ticks = hpet_counter().wrapping_sub(HPET_START.load(Ordering::Relaxed));
    (u128::from(ticks) * u128::from(HPET_PERIOD_FS.load(Ordering::Relaxed))
        / u128::from(FEMTOS_PER_NANO)) as u64
}

/// Monotonic nanoseconds since `init`: from the TSC when it is invariant
/// (cheap, no device access), otherwise from the HPET.
pub fn monotonic_nanos() -> u64 {
    if TSC_CLOCK.load(Ordering::Relaxed) {
        let hz = TSC_HZ.load(Ordering::Relaxed);
        let cycles = cpu::read_tsc().wrapping_sub(TSC_START.load(Ordering::Relaxed));
        (u128::from(cycles) * 1_000_000_000 / u128::from(hz)) as u64
    } else {
        hpet_nanos()
    }
}

/// Busy-waits about `nanos` nanoseconds by the TSC, at the frequency
/// calibrated in `init` (0 before then: no wait). For short test delays:
/// RDTSC does not leave a virtual machine, whereas reading the HPET (the
/// monotonic clock when the TSC is not invariant) is an exit to the
/// hypervisor each time, which made a per-byte delay loop many times slower
/// than asked under KVM.
pub fn spin_ns(nanos: u64) {
    let hz = TSC_HZ.load(Ordering::Relaxed);
    let cycles = (u128::from(nanos) * u128::from(hz) / 1_000_000_000) as u64;
    let start = cpu::read_tsc();
    while cpu::read_tsc().wrapping_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

/// Timer interrupts since the timer started.
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

fn on_tick() {
    crate::random::add_interrupt_timing();
    let tick = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    crate::sched::on_tick(tick);
}

/// What `init` measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeReport {
    pub hpet_period_fs: u64,
    pub lapic_timer_hz: u64,
    pub tsc_hz: u64,
    pub invariant_tsc: bool,
}

/// Why `init` failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeError {
    Hpet(crate::acpi::TableError),
    Mmio(paging::MmioError),
    /// The HPET reports a period outside the specification's range.
    BadHpetPeriod(u64),
    /// The APIC timer did not count, or counted too fast to measure.
    Calibration,
    VectorTaken,
}

/// Starts the HPET, calibrates the APIC timer and TSC against it, and
/// starts the 1 kHz periodic timer. Interrupts must still be disabled;
/// the caller enables them afterwards.
pub fn init() -> Result<TimeReport, TimeError> {
    let hpet = crate::acpi::hpet().map_err(TimeError::Hpet)?;
    HPET_BASE.store(
        paging::map_mmio(hpet.address, 1024).map_err(TimeError::Mmio)?,
        Ordering::Release,
    );
    let period = hpet_read(0x000) >> 32;
    if period == 0 || period > MAX_HPET_PERIOD_FS {
        return Err(TimeError::BadHpetPeriod(period));
    }
    HPET_PERIOD_FS.store(period, Ordering::Relaxed);
    hpet_write(0x010, hpet_read(0x010) | 1); // ENABLE_CNF: counter runs

    // Calibrate: run the APIC timer one-shot from its maximum count,
    // masked, for CALIBRATION_MS by the HPET; read the TSC alongside.
    apic::write(apic::REG_TIMER_DIVIDE, apic::TIMER_DIVIDE_16);
    apic::write(
        apic::REG_LVT_TIMER,
        apic::LVT_MASKED | u32::from(TIMER_VECTOR),
    );
    let tsc_before = cpu::read_tsc();
    apic::write(apic::REG_TIMER_INITIAL, u32::MAX);
    hpet_wait(CALIBRATION_MS * 1_000_000);
    let remaining = apic::read(apic::REG_TIMER_CURRENT);
    let tsc_after = cpu::read_tsc();
    apic::write(apic::REG_TIMER_INITIAL, 0);
    let counted = u64::from(u32::MAX - remaining);
    if counted == 0 || remaining == 0 {
        return Err(TimeError::Calibration);
    }
    let lapic_hz = counted * 1000 / CALIBRATION_MS;
    let tsc_hz = tsc_after.wrapping_sub(tsc_before) * 1000 / CALIBRATION_MS;
    TSC_HZ.store(tsc_hz, Ordering::Relaxed);
    TSC_START.store(cpu::read_tsc(), Ordering::Relaxed);
    HPET_START.store(hpet_counter(), Ordering::Relaxed);
    let invariant_tsc = cpu::invariant_tsc();
    TSC_CLOCK.store(tsc_hz != 0 && invariant_tsc, Ordering::Relaxed);

    // Periodic 1 kHz tick.
    if !interrupts::set_handler(TIMER_VECTOR, on_tick) {
        return Err(TimeError::VectorTaken);
    }
    let per_tick = u32::try_from(lapic_hz / TICK_HZ).map_err(|_| TimeError::Calibration)?;
    if per_tick == 0 {
        return Err(TimeError::Calibration);
    }
    apic::write(
        apic::REG_LVT_TIMER,
        apic::LVT_TIMER_PERIODIC | u32::from(TIMER_VECTOR),
    );
    apic::write(apic::REG_TIMER_INITIAL, per_tick);

    Ok(TimeReport {
        hpet_period_fs: period,
        lapic_timer_hz: lapic_hz,
        tsc_hz,
        invariant_tsc,
    })
}
