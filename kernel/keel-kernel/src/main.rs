//! The Keel kernel binary: entry point, boot sequence, panic handler.
#![no_std]
#![no_main]
#![deny(unsafe_code)]

extern crate alloc;

mod exec;
mod selftest;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use keel_hal::arch::x86_64::cpu::halt_forever;
use keel_hal::arch::x86_64::{fpu, init_descriptor_tables, paging};
use keel_hal::boot::{self, RegionKind};
use keel_hal::drivers::debug_exit::{ExitCode, exit_qemu};
use keel_hal::{console, interrupts, kprintln, memory, sched, time};

/// Set once the command line asked for self-tests, so that a panic can
/// report failure to the test harness instead of hanging until timeout.
static TEST_MODE: AtomicBool = AtomicBool::new(false);

/// Kernel entry point, named by `ENTRY(kmain)` in `linker.ld`.
///
/// Limine enters here as if by a C call (PROTOCOL.md, "Machine State at
/// Entry", x86-64): `rsp` points at a stack of at least 64 KiB with a zero
/// return address already pushed, interrupts are disabled, the direction
/// flag is clear, and paging maps the kernel image and the HHDM. That is
/// exactly the System V AMD64 state a non-returning `extern "C"` function
/// expects, so no assembly stub is needed.
//
// `no_mangle` is the one `unsafe` attribute in this crate: the symbol name
// must be exactly `kmain` for the linker script's ENTRY to find it, and no
// other `kmain` exists in the link.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
extern "C" fn kmain() -> ! {
    let serial_ok = console::init_serial();
    // Own GDT, TSS and IDT before anything can fault, so that a fault is
    // reported with a register dump instead of resetting the machine.
    init_descriptor_tables();

    let revision = boot::base_revision();
    if !revision.supported {
        // The guarantees the rest of the boot relies on (machine state,
        // HHDM contents, RSDP addressing) are those of the requested
        // revision. Without them, stop rather than guess (SR-10).
        kprintln!(
            "Keel: bootloader does not support Limine base revision {} (loaded {:?}); halting",
            revision.requested,
            revision.loaded
        );
        halt_forever();
    }

    let fb_size = console::init_framebuffer();
    kprintln!("Keel {} booting", env!("CARGO_PKG_VERSION"));
    report_boot_info(serial_ok, fb_size);

    match memory::init() {
        Ok(stats) => kprintln!(
            "mem: {} frames managed, {} free ({} MiB); bookkeeping at {:#x}..{:#x}",
            stats.frames_managed,
            stats.frames_free,
            stats.frames_free * 4096 / (1024 * 1024),
            stats.bookkeeping.start,
            stats.bookkeeping.end
        ),
        // Nothing past this point can work without physical memory.
        Err(error) => panic!("frame allocator setup failed: {error:?}"),
    }

    match paging::init() {
        Ok(report) => kprintln!(
            "paging: own tables active; {} x 4 KiB + {} x 2 MiB pages; NX {}, WP on, SMEP {}, SMAP {}, UMIP {}",
            report.summary.small_pages,
            report.summary.large_pages,
            on_off(report.features.nx),
            on_off(report.features.smep),
            on_off(report.features.smap),
            on_off(report.features.umip),
        ),
        // Running on the bootloader's tables would mean no W^X and no
        // guard pages; stop instead (SR-12).
        Err(error) => panic!("page table setup failed: {error:?}"),
    }
    // System calls and user-mode entry, with page-table isolation.
    keel_hal::arch::x86_64::entry::init(paging::kernel_root().map_or(0, |r| r.address()));

    let fpu = fpu::init();
    match fpu.xcr0 {
        Some(xcr0) => kprintln!(
            "fpu: XSAVE, XCR0 {xcr0:#x}, {} bytes per thread",
            fpu.area_size
        ),
        None => kprintln!("fpu: FXSAVE, {} bytes per thread", fpu.area_size),
    }

    match interrupts::init() {
        Ok(r) => kprintln!(
            "apic: {} mode, boot CPU APIC ID {}, {} CPU(s) in MADT, {} I/O APIC(s) with {} inputs; legacy PIC masked",
            if r.x2apic { "x2APIC" } else { "xAPIC" },
            r.bsp_apic_id,
            r.enabled_cpus,
            r.io_apics,
            r.gsis
        ),
        Err(error) => panic!("interrupt controller setup failed: {error:?}"),
    }
    match time::init() {
        Ok(r) => kprintln!(
            "time: HPET period {} fs; APIC timer {} kHz, ticking at {} Hz; TSC {} MHz ({})",
            r.hpet_period_fs,
            r.lapic_timer_hz / 1000,
            time::TICK_HZ,
            r.tsc_hz / 1_000_000,
            if r.invariant_tsc {
                "invariant"
            } else {
                "not invariant: clock uses the HPET"
            }
        ),
        Err(error) => panic!("timer setup failed: {error:?}"),
    }
    if let Err(error) = sched::init() {
        panic!("scheduler setup failed: {error:?}");
    }
    interrupts::enable();

    let test_phase = selftest::requested_phase(boot::cmdline());
    if let Some(phase) = test_phase {
        TEST_MODE.store(true, Ordering::Relaxed);
        let passed = selftest::run(phase, selftest::requested_scenario(boot::cmdline()));
        exit_qemu(if passed {
            ExitCode::Success
        } else {
            ExitCode::Failure
        });
    }

    kprintln!("Keel: nothing more to run yet; halting.");
    halt_forever();
}

fn on_off(enabled: bool) -> &'static str {
    if enabled { "on" } else { "unsupported" }
}

fn report_boot_info(serial_ok: bool, fb_size: Option<(usize, usize)>) {
    let revision = boot::base_revision();
    kprintln!(
        "boot: Limine base revision {} (requested {})",
        revision.loaded.unwrap_or(revision.requested),
        revision.requested
    );
    kprintln!("boot: cmdline \"{}\"", boot::cmdline());
    kprintln!(
        "boot: serial COM1 {}",
        if serial_ok { "ok" } else { "not present" }
    );
    match fb_size {
        Some((cols, rows)) => kprintln!("boot: framebuffer console {cols}x{rows} characters"),
        None => kprintln!("boot: no usable framebuffer"),
    }
    match boot::hhdm_offset() {
        Some(offset) => kprintln!("boot: HHDM offset {offset:#018x}"),
        None => kprintln!("boot: no HHDM response"),
    }
    match boot::kernel_address() {
        Some(k) => kprintln!(
            "boot: kernel at virt {:#018x} phys {:#018x}",
            k.virtual_base,
            k.physical_base
        ),
        None => kprintln!("boot: no kernel address response"),
    }
    let mut regions = 0u64;
    let mut usable = 0u64;
    for region in boot::memory_map() {
        regions += 1;
        if region.kind == RegionKind::Usable {
            usable = usable.saturating_add(region.length);
        }
    }
    kprintln!(
        "boot: memory map {} regions, {} MiB usable",
        regions,
        usable / (1024 * 1024)
    );
    kprintln!(
        "boot: ACPI RSDP {}",
        if boot::rsdp().is_some() {
            "found"
        } else {
            "not found"
        }
    );
    for module in boot::modules() {
        kprintln!("boot: module {} ({} bytes)", module.path, module.data.len());
    }
}

/// Prints a recognisable banner with the panic location and message, then
/// stops. In self-test mode the failure is reported to QEMU first.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if TEST_MODE.load(Ordering::Relaxed) {
        // A scenario that ends in a deliberate fatal exception judges the
        // outcome here and exits QEMU itself.
        selftest::judge_expected_fault();
    }
    console::emergency_print(format_args!("\n*** KEEL KERNEL PANIC ***\n{info}\n"));
    if TEST_MODE.load(Ordering::Relaxed) {
        exit_qemu(ExitCode::Failure);
    }
    halt_forever();
}
