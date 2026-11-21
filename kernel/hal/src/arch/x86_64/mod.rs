//! x86-64 primitives.

#[cfg(target_os = "none")]
pub mod apic;
pub mod cpu;
#[cfg(target_os = "none")]
pub mod fpu;
pub mod gdt;
pub mod idt;
#[cfg(target_os = "none")]
pub mod paging;
pub mod port;
#[cfg(target_os = "none")]
pub mod selftest;
#[cfg(target_os = "none")]
pub mod switch;

#[cfg(target_os = "none")]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "none")]
static DESCRIPTOR_TABLES_LOADED: AtomicBool = AtomicBool::new(false);

/// Loads Keel's GDT, TSS and IDT on the boot CPU. Safe to call: it runs
/// the setup at most once and refuses to run with interrupts enabled.
#[cfg(target_os = "none")]
pub fn init_descriptor_tables() {
    assert!(
        !cpu::interrupts_enabled(),
        "descriptor tables must be loaded with interrupts disabled"
    );
    if DESCRIPTOR_TABLES_LOADED.swap(true, Ordering::AcqRel) {
        return;
    }
    // SAFETY: the swap above makes this the only call; interrupts are off
    // (asserted above) and the boot CPU is the only one running (D8).
    unsafe {
        gdt::init();
        idt::init();
    }
}
