//! Interrupt routing and dispatch (P1-T6).
//!
//! `init` takes over the interrupt controllers described by the MADT: it
//! masks the legacy PICs, enables the boot CPU's local APIC, and maps
//! every I/O APIC with all inputs masked. Devices then ask for their ISA
//! IRQ (or GSI) to be routed to a vector with a handler.
//!
//! Handlers run with interrupts disabled, on the interrupted stack or the
//! kernel stack. They must be short, must not allocate, and must not take
//! any lock that ordinary code holds with interrupts enabled
//! (docs/locking.md).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::sync::IrqMutex;
use keel_core::acpi::{IntiFlags, MadtEntry};

use crate::acpi::{self, TableError};
use crate::arch::x86_64::apic::{self, IoApic, SPURIOUS_VECTOR};

/// First vector available to devices; 0-31 are CPU exceptions.
pub const FIRST_DEVICE_VECTOR: u8 = 32;

/// Handler for each vector 32-255; 0 means none.
static HANDLERS: [AtomicUsize; 224] = [const { AtomicUsize::new(0) }; 224];
static SPURIOUS: AtomicU64 = AtomicU64::new(0);
static UNEXPECTED: AtomicU64 = AtomicU64::new(0);

struct Routing {
    io_apics: Vec<IoApic>,
    overrides: Vec<(u8, u32, IntiFlags)>,
    bsp_apic_id: u32,
}

static ROUTING: IrqMutex<Option<Routing>> = IrqMutex::new(None);

/// Called by the IDT stub for vectors 32-255, with interrupts disabled.
pub(crate) fn dispatch(vector: u8) {
    if vector == SPURIOUS_VECTOR {
        // No EOI for the spurious vector (SDM 13.9).
        SPURIOUS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let handler = HANDLERS[usize::from(vector - FIRST_DEVICE_VECTOR)].load(Ordering::Acquire);
    if handler == 0 {
        UNEXPECTED.fetch_add(1, Ordering::Relaxed);
    } else {
        // SAFETY: the only non-zero values ever stored are `fn()` pointers
        // converted to usize in `set_handler`, so converting back yields a
        // valid function pointer with the same signature.
        let handler: fn() = unsafe { core::mem::transmute::<usize, fn()>(handler) };
        handler();
    }
    // EOI before IRETQ (SDM 13.8.5), and before any thread switch, so the
    // timer keeps interrupting whichever thread runs next.
    apic::end_of_interrupt();
    crate::sched::preempt_if_needed();
}

/// Installs `handler` for `vector` (32-254). Returns false if the vector
/// is out of range or already taken.
pub fn set_handler(vector: u8, handler: fn()) -> bool {
    if !(FIRST_DEVICE_VECTOR..SPURIOUS_VECTOR).contains(&vector) {
        return false;
    }
    HANDLERS[usize::from(vector - FIRST_DEVICE_VECTOR)]
        .compare_exchange(0, handler as usize, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Interrupts that arrived on a vector without a handler.
pub fn unexpected_count() -> u64 {
    UNEXPECTED.load(Ordering::Relaxed)
}

/// Spurious interrupts seen.
pub fn spurious_count() -> u64 {
    SPURIOUS.load(Ordering::Relaxed)
}

/// What `init` found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterruptReport {
    pub x2apic: bool,
    pub bsp_apic_id: u32,
    pub io_apics: usize,
    pub gsis: u32,
    pub enabled_cpus: usize,
}

/// Why `init` failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptError {
    Acpi(TableError),
    LocalApic(apic::ApicError),
    IoApic(crate::arch::x86_64::paging::MmioError),
    NoIoApic,
}

/// Sets up interrupt routing from the MADT. Interrupts stay disabled.
pub fn init() -> Result<InterruptReport, InterruptError> {
    let madt = acpi::madt().map_err(InterruptError::Acpi)?;
    // Mask the PICs whatever PCAT_COMPAT says: masking absent hardware is
    // harmless, and leaving present hardware unmasked is not.
    apic::mask_legacy_pic();
    apic::init_local().map_err(InterruptError::LocalApic)?;

    let mut io_apics = Vec::new();
    let mut overrides = Vec::new();
    let mut enabled_cpus = 0;
    for entry in &madt.entries {
        match *entry {
            MadtEntry::IoApic {
                address, gsi_base, ..
            } => {
                io_apics.push(
                    IoApic::new(u64::from(address), gsi_base).map_err(InterruptError::IoApic)?,
                );
            }
            MadtEntry::InterruptOverride {
                source_irq,
                gsi,
                flags,
            } => overrides.push((source_irq, gsi, flags)),
            MadtEntry::LocalApic { enabled: true, .. }
            | MadtEntry::LocalX2Apic { enabled: true, .. } => {
                enabled_cpus += 1;
            }
            _ => {}
        }
    }
    if io_apics.is_empty() {
        return Err(InterruptError::NoIoApic);
    }
    let report = InterruptReport {
        x2apic: apic::is_x2apic(),
        bsp_apic_id: apic::id(),
        io_apics: io_apics.len(),
        gsis: io_apics.iter().map(|a| a.entries).sum(),
        enabled_cpus,
    };
    *ROUTING.lock() = Some(Routing {
        io_apics,
        overrides,
        bsp_apic_id: report.bsp_apic_id,
    });
    Ok(report)
}

/// Routes ISA `irq` (0-15) to `vector` on the boot CPU, applying any MADT
/// interrupt source override; ISA interrupts default to active-high,
/// edge-triggered (ACPI 6.6 Table 5.26, "conforms to the bus"). Returns
/// false if no I/O APIC handles the resulting GSI.
pub fn route_isa_irq(irq: u8, vector: u8) -> bool {
    let routing = ROUTING.lock();
    let Some(routing) = routing.as_ref() else {
        return false;
    };
    let (gsi, flags) = routing
        .overrides
        .iter()
        .find(|(source, ..)| *source == irq)
        .map(|&(_, gsi, flags)| (gsi, flags))
        .unwrap_or((
            u32::from(irq),
            IntiFlags {
                active_low: None,
                level_triggered: None,
            },
        ));
    let Ok(destination) = u8::try_from(routing.bsp_apic_id) else {
        // Physical destination mode in the redirection entry holds 8 bits.
        return false;
    };
    match routing.io_apics.iter().find(|a| a.handles(gsi)) {
        Some(io_apic) => {
            io_apic.route(
                gsi,
                vector,
                destination,
                flags.active_low.unwrap_or(false),
                flags.level_triggered.unwrap_or(false),
            );
            true
        }
        None => false,
    }
}

static ENABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Enables interrupts on the boot CPU, once routing and the timer are set
/// up. Every vector has an entry stub, unhandled ones are counted, and
/// handlers take no locks, so enabling is safe from any context that holds
/// no spinlock (the boot path calls this holding none).
pub fn enable() {
    assert!(
        ROUTING.lock().is_some(),
        "interrupt routing must be set up first"
    );
    ENABLED.store(true, Ordering::Release);
    // SAFETY: see the function documentation.
    unsafe { crate::arch::x86_64::cpu::enable_interrupts() }
}

/// Halts until the next interrupt. Only valid after `enable`.
pub fn wait() {
    assert!(
        ENABLED.load(Ordering::Acquire),
        "interrupts are not enabled yet"
    );
    // SAFETY: as for `enable`; `sti; hlt` cannot miss a wake-up.
    unsafe { crate::arch::x86_64::cpu::enable_and_wait() }
}

/// Re-enables interrupts after a thread switch. Only the scheduler calls
/// this, on behalf of a thread that had interrupts enabled when it gave up
/// the CPU, or that is starting for the first time.
pub(crate) fn enable_after_switch() {
    // SAFETY: called only after `enable` (the scheduler starts after it)
    // and with no spinlock held: the scheduler releases its locks before
    // switching and before calling this.
    unsafe { crate::arch::x86_64::cpu::enable_interrupts() }
}
