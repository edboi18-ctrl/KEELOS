//! Local APIC, I/O APIC and legacy PIC (P1-T6).
//!
//! References:
//!  - Intel SDM Vol. 3 chapter 13: Table 13-1 (register offsets), Figure
//!    13-8 (LVT; timer mode bits 18:17, mask bit 16), Figure 13-10 (timer
//!    divide encoding), Figure 13-23 (SVR: vector 7:0, enable bit 8),
//!    section 13.8.5 (EOI before IRET), section 13.9 (no EOI for the
//!    spurious vector), Figure 13-5 and section 13.12 (IA32_APIC_BASE at
//!    MSR 1BH; bit 11 global enable, bit 10 x2APIC mode; in x2APIC mode
//!    register offset `o` is MSR 800H + o/16, and EOI takes a zero write).
//!  - Intel 82093AA I/O APIC datasheet (290566-001): IOREGSEL at offset
//!    00h, IOWIN at 10h (section 3.1); IOAPICVER bits 23:16 = highest
//!    redirection entry (3.2.2); redirection entry n at registers
//!    10h + 2n (low dword) and 11h + 2n (high dword), vector 7:0, polarity
//!    bit 13 (1 = active low), trigger bit 15 (1 = level), mask bit 16,
//!    destination 63:56 (3.2.4).
//!  - 8259 PIC mask (interrupt mask) registers at I/O ports 21h and A1h
//!    (Linux `arch/x86/include/asm/i8259.h`, PIC_MASTER_IMR/PIC_SLAVE_IMR).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::cpu;
use super::port::outb;

/// IA32_APIC_BASE MSR.
const IA32_APIC_BASE: u32 = 0x1B;
const APIC_BASE_X2APIC: u64 = 1 << 10;
const APIC_BASE_ENABLE: u64 = 1 << 11;

// Local APIC register offsets (Table 13-1).
pub const REG_ID: u32 = 0x20;
pub const REG_VERSION: u32 = 0x30;
pub const REG_TPR: u32 = 0x80;
pub const REG_EOI: u32 = 0xB0;
pub const REG_SVR: u32 = 0xF0;
pub const REG_LVT_TIMER: u32 = 0x320;
pub const REG_LVT_ERROR: u32 = 0x370;
pub const REG_TIMER_INITIAL: u32 = 0x380;
pub const REG_TIMER_CURRENT: u32 = 0x390;
pub const REG_TIMER_DIVIDE: u32 = 0x3E0;

pub const LVT_MASKED: u32 = 1 << 16;
pub const LVT_TIMER_PERIODIC: u32 = 0b01 << 17;
/// Divide configuration 0b0011: divide by 16 (Figure 13-10).
pub const TIMER_DIVIDE_16: u32 = 0b0011;
const SVR_ENABLE: u32 = 1 << 8;

/// The spurious-interrupt vector. Its low four bits must be 1 on old
/// processors (Figure 13-23 note 3); 0xFF satisfies that everywhere.
pub const SPURIOUS_VECTOR: u8 = 0xFF;

/// Set once `init_local` has run.
static READY: AtomicBool = AtomicBool::new(false);
static X2APIC: AtomicBool = AtomicBool::new(false);
/// Virtual address of the xAPIC registers (unused in x2APIC mode).
static MMIO: AtomicU64 = AtomicU64::new(0);

/// Reads a local APIC register.
pub fn read(offset: u32) -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        // SAFETY: in x2APIC mode MSRs 800H-8FFH are the APIC registers
        // (SDM 13.12.1); `offset` is one of the constants above.
        unsafe { cpu::rdmsr(0x800 + (offset >> 4)) as u32 }
    } else {
        let base = MMIO.load(Ordering::Relaxed);
        // SAFETY: `base` maps the 4 KiB xAPIC register page uncached
        // (set by `init_local` before READY); every offset used is a
        // 16-byte-aligned register inside it. Registers must be accessed
        // as 32-bit quantities (SDM 13.4.1), hence a volatile u32 read.
        unsafe { ((base + u64::from(offset)) as *const u32).read_volatile() }
    }
}

/// Writes a local APIC register.
pub fn write(offset: u32, value: u32) {
    if X2APIC.load(Ordering::Relaxed) {
        // SAFETY: as in `read`; the callers pass valid register values.
        unsafe { cpu::wrmsr(0x800 + (offset >> 4), u64::from(value)) }
    } else {
        let base = MMIO.load(Ordering::Relaxed);
        // SAFETY: as in `read`, for a 32-bit volatile write.
        unsafe { ((base + u64::from(offset)) as *mut u32).write_volatile(value) }
    }
}

/// Signals end of interrupt to the local APIC. Must not be called for the
/// spurious vector (SDM 13.9).
pub fn end_of_interrupt() {
    if READY.load(Ordering::Acquire) {
        write(REG_EOI, 0);
    }
}

/// This CPU's APIC ID.
pub fn id() -> u32 {
    let raw = read(REG_ID);
    if X2APIC.load(Ordering::Relaxed) {
        raw
    } else {
        raw >> 24
    }
}

/// Whether the local APIC is in x2APIC mode.
pub fn is_x2apic() -> bool {
    X2APIC.load(Ordering::Relaxed)
}

/// Why local APIC setup failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApicError {
    /// IA32_APIC_BASE says the APIC is globally disabled.
    Disabled,
    Mmio(super::paging::MmioError),
}

/// Takes over the boot CPU's local APIC: maps its registers (xAPIC) or
/// uses MSRs (x2APIC, if the firmware already switched it), software-
/// enables it with the spurious vector, accepts all priorities, and masks
/// the timer and error LVT entries until they are configured.
pub fn init_local() -> Result<(), ApicError> {
    // SAFETY: IA32_APIC_BASE exists on every CPU with an APIC, which
    // includes all x86-64 processors.
    let base = unsafe { cpu::rdmsr(IA32_APIC_BASE) };
    if base & APIC_BASE_ENABLE == 0 {
        return Err(ApicError::Disabled);
    }
    if base & APIC_BASE_X2APIC != 0 {
        X2APIC.store(true, Ordering::Relaxed);
    } else {
        // Bits 12 and up hold the page address (Figure 13-5); the top
        // bits above MAXPHYADDR are reserved and read as zero.
        let phys = base & 0x000F_FFFF_FFFF_F000;
        let virt = super::paging::map_mmio(phys, 4096).map_err(ApicError::Mmio)?;
        MMIO.store(virt, Ordering::Relaxed);
    }
    write(REG_SVR, SVR_ENABLE | u32::from(SPURIOUS_VECTOR));
    write(REG_TPR, 0);
    write(REG_LVT_TIMER, LVT_MASKED);
    write(REG_LVT_ERROR, LVT_MASKED);
    READY.store(true, Ordering::Release);
    Ok(())
}

/// Masks every input of both 8259 PICs (OCW1 = FFh), so only the APICs
/// deliver interrupts (ACPI 6.6 Table 5.20: with PCAT_COMPAT the 8259
/// vectors "must be disabled (that is, masked)").
pub fn mask_legacy_pic() {
    // SAFETY: ports 21h and A1h are the 8259 interrupt-mask registers on
    // every PC-compatible chipset, or undecoded where none exists; writing
    // a mask cannot affect memory safety.
    unsafe {
        outb(0x21, 0xFF);
        outb(0xA1, 0xFF);
    }
}

/// One I/O APIC.
#[derive(Clone, Copy, Debug)]
pub struct IoApic {
    /// Virtual address of IOREGSEL.
    base: u64,
    /// First global system interrupt this I/O APIC handles.
    pub gsi_base: u32,
    /// Number of redirection entries.
    pub entries: u32,
}

impl IoApic {
    /// Maps the I/O APIC at physical `address`, masks every entry, and
    /// returns it.
    pub fn new(address: u64, gsi_base: u32) -> Result<IoApic, super::paging::MmioError> {
        let base = super::paging::map_mmio(address, 0x20)?;
        let mut apic = IoApic {
            base,
            gsi_base,
            entries: 0,
        };
        apic.entries = (apic.read(0x01) >> 16 & 0xFF) + 1;
        for entry in 0..apic.entries {
            apic.write(0x10 + 2 * entry, LVT_MASKED);
        }
        Ok(apic)
    }

    fn read(&self, register: u32) -> u32 {
        // SAFETY: `base` maps the I/O APIC's register window uncached
        // (`new`); IOREGSEL (offset 0) selects, IOWIN (offset 10h) holds
        // the data, both 32-bit (datasheet 3.1). The select-then-access
        // pair is not interrupted because callers run with interrupts off
        // or hold the interrupt-routing lock.
        unsafe {
            (self.base as *mut u32).write_volatile(register);
            ((self.base + 0x10) as *const u32).read_volatile()
        }
    }

    fn write(&self, register: u32, value: u32) {
        // SAFETY: as in `read`.
        unsafe {
            (self.base as *mut u32).write_volatile(register);
            ((self.base + 0x10) as *mut u32).write_volatile(value);
        }
    }

    /// Whether this I/O APIC handles `gsi`.
    pub fn handles(&self, gsi: u32) -> bool {
        gsi >= self.gsi_base && gsi - self.gsi_base < self.entries
    }

    /// Routes `gsi` to `vector` on the CPU with APIC ID `destination`
    /// (physical destination mode, fixed delivery) and unmasks it.
    pub fn route(&self, gsi: u32, vector: u8, destination: u8, active_low: bool, level: bool) {
        let entry = gsi - self.gsi_base;
        let low = u32::from(vector) | u32::from(active_low) << 13 | u32::from(level) << 15;
        // Write the high half first while the entry is still masked.
        self.write(0x11 + 2 * entry, u32::from(destination) << 24);
        self.write(0x10 + 2 * entry, low);
    }
}
