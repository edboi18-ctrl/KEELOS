//! The Keel kernel binary: entry point, boot sequence, panic handler.
#![no_std]
#![no_main]
#![deny(unsafe_code)]

extern crate alloc;

/// The self-tests: test builds only (SR-21, ADR 0043).
#[cfg(feature = "selftest")]
mod selftest;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use keel_hal::arch::x86_64::cpu::halt_forever;
use keel_hal::arch::x86_64::{fpu, init_descriptor_tables, paging};
use keel_hal::boot::{self, RegionKind};
use keel_hal::drivers::debug_exit::{ExitCode, exit_qemu};
use keel_hal::{console, interrupts, kprintln, kresult, memory, sched, time};

/// Set once the command line asked for self-tests, so that a panic can
/// report failure to the test harness instead of hanging until timeout.
static TEST_MODE: AtomicBool = AtomicBool::new(false);
/// Set on the first entry to the panic handler (audit finding 7).
static PANICKING: AtomicBool = AtomicBool::new(false);

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
        Ok(stats) => {
            kprintln!(
                "mem: {} frames managed, {} free ({} MiB); bookkeeping at {:#x}..{:#x}",
                stats.frames_managed,
                stats.frames_free,
                stats.frames_free * 4096 / (1024 * 1024),
                stats.bookkeeping.start,
                stats.bookkeeping.end
            );
            if stats.regions_skipped != 0 {
                kprintln!(
                    "mem: {} usable memory-map entries skipped (misaligned or overlapping)",
                    stats.regions_skipped
                );
            }
        }
        // Nothing past this point can work without physical memory.
        Err(error) => panic!("frame allocator setup failed: {error:?}"),
    }

    match paging::init() {
        Ok(report) => {
            kprintln!(
                "paging: own tables active; {} x 4 KiB + {} x 2 MiB pages; NX {}, WP on, SMEP {}, SMAP {}, UMIP {}",
                report.summary.small_pages,
                report.summary.large_pages,
                on_off(report.features.nx),
                on_off(report.features.smep),
                on_off(report.features.smap),
                on_off(report.features.umip),
            );
            kprintln!(
                "paging: heap, device and stack regions {} ({})",
                if report.regions_randomized {
                    "at random offsets"
                } else {
                    "NOT randomized: already in use"
                },
                if report.regions_quality == keel_hal::random::Quality::Hardware {
                    "hardware random source"
                } else {
                    "timing only: weak"
                }
            );
            // As with the kernel base: test boots only (audit 2, A5).
            let cmdline = boot::cmdline();
            if test_boot(cmdline) {
                let [heap, mmio, stacks] = paging::region_bases();
                kresult!("boot: regions heap {heap:#018x} mmio {mmio:#018x} stacks {stacks:#018x}");
            }
        }
        Err(error) => panic!("page table setup failed: {error:?}"),
    }
    // Leave the bootloader's stack, which has no guard page, for one of
    // the kernel's own (P1-S6, SR-17).
    keel_hal::sched::continue_on_boot_stack(kmain_on_boot_stack)
}

/// The rest of boot, on the kernel's own guarded boot stack.
extern "C" fn kmain_on_boot_stack() -> ! {
    // System calls and user-mode entry, with page-table isolation.
    keel_hal::arch::x86_64::entry::init(paging::kernel_root().map_or(0, |r| r.address()));
    report_mitigations(&keel_hal::mitigations::init());

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
    // Random numbers (P1-S5, SR-16): BLAKE2s pool, ChaCha20 output.
    match keel_hal::random::init() {
        keel_hal::random::Quality::Hardware => kprintln!(
            "random: seeded from {}{}TSC jitter; ChaCha20 generator, reseeded every 60 s",
            if keel_hal::random::has_rdseed() {
                "RDSEED, "
            } else {
                ""
            },
            if keel_hal::random::rdrand_usable() {
                "RDRAND, "
            } else {
                ""
            },
        ),
        keel_hal::random::Quality::Weak => kprintln!(
            "random: WARNING: no usable RDSEED/RDRAND; seeded from timing only (weak until interrupts add more)"
        ),
    }
    if let Err(error) = sched::init() {
        panic!("scheduler setup failed: {error:?}");
    }
    interrupts::enable();

    // The Linux system calls and process teardown (P1-T13).
    keel_linux_abi::syscall::init();
    match keel_linux_abi::fs::init() {
        Ok(r) => kprintln!(
            "fs: initramfs {} bytes, {} members unpacked into tmpfs ({} unsupported skipped); /dev has console, null, zero, urandom",
            r.archive_bytes,
            r.members - r.skipped,
            r.skipped
        ),
        // Without a root filesystem no program can start; the kernel keeps
        // running so the console shows why.
        Err(error) => kprintln!("fs: root filesystem not available: {error}"),
    }
    let tty = keel_linux_abi::tty::init();
    match tty.keyboard {
        Ok(()) => {
            kprintln!("keyboard: i8042 ready (IRQ 1, scancode set 1, US layout) on /dev/console")
        }
        // No keyboard is not fatal: output still works.
        Err(error) => kprintln!("keyboard: not available ({error:?})"),
    }
    if tty.serial {
        kprintln!("serial: COM1 input (IRQ 4) on /dev/console");
    } else {
        kprintln!("serial: no COM1 input");
    }

    #[cfg(feature = "debug-tracing")]
    keel_linux_abi::trace::configure(boot::cmdline());
    note_ignored_options(boot::cmdline());
    #[cfg(feature = "selftest")]
    run_test_boot();

    // P3-T13 (ADR 0032): a normal boot runs /sbin/keel-init, which keeps
    // a shell on the console. This thread waits for it; the scheduler runs
    // everything else meanwhile.
    run_init()
}

/// A test boot (`test=`, `fuzz=`, `stress=`): runs it and exits QEMU.
/// Returns for a normal boot.
#[cfg(feature = "selftest")]
fn run_test_boot() {
    if let Some((minutes, seed)) = selftest::requested_fuzz(boot::cmdline()) {
        TEST_MODE.store(true, Ordering::Relaxed);
        let passed = selftest::run_fuzz(minutes, seed);
        exit_qemu(if passed {
            ExitCode::Success
        } else {
            ExitCode::Failure
        });
    }
    if let Some((minutes, seed)) = selftest::requested_stress(boot::cmdline()) {
        TEST_MODE.store(true, Ordering::Relaxed);
        let passed = selftest::run_stress(minutes, seed);
        exit_qemu(if passed {
            ExitCode::Success
        } else {
            ExitCode::Failure
        });
    }
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
}

/// Whether the command line asks for a test boot. Never in a kernel
/// built without the self-tests (SR-21).
#[cfg(feature = "selftest")]
fn test_boot(cmdline: &str) -> bool {
    selftest::requested_phase(cmdline).is_some()
        || selftest::requested_fuzz(cmdline).is_some()
        || selftest::requested_stress(cmdline).is_some()
}

#[cfg(not(feature = "selftest"))]
fn test_boot(_: &str) -> bool {
    false
}

/// Command-line words this build has no use for because the code behind
/// them is not in it (SR-21): each is logged and ignored.
fn note_ignored_options(cmdline: &str) {
    const TEST_WORDS: [&str; 5] = ["test=", "fuzz=", "stress=", "scenario=", "seed="];
    const TRACE_WORDS: [&str; 2] = ["trace=", "trace.pid="];
    for word in cmdline.split_ascii_whitespace() {
        if !cfg!(feature = "selftest") && TEST_WORDS.iter().any(|w| word.starts_with(w)) {
            kprintln!("boot: {word} ignored: this kernel was built without the self-tests");
        }
        if !cfg!(feature = "debug-tracing") && TRACE_WORDS.iter().any(|w| word.starts_with(w)) {
            kprintln!("boot: {word} ignored: this kernel was built without debug-tracing");
        }
    }
}

/// Starts /sbin/keel-init and waits for it; halts when it ends.
fn run_init() -> ! {
    match start_init() {
        Ok(spawned) => {
            kprintln!("Keel: started {} (PID {})", INIT_DISPLAY, spawned.pid);
            sched::join(spawned.thread);
            match sched::exit_status(spawned.thread) {
                Some((status, None)) => {
                    kprintln!("Keel: {INIT_DISPLAY} exited with status {status}; halting.")
                }
                Some((_, Some(fault))) => {
                    kprintln!("Keel: {INIT_DISPLAY} ended by a fault ({fault:?}); halting.")
                }
                None => kprintln!("Keel: {INIT_DISPLAY} ended; halting."),
            }
        }
        Err(why) => kprintln!("Keel: cannot start {INIT_DISPLAY} ({why}); halting."),
    }
    halt_forever();
}

const INIT: &[u8] = b"/sbin/keel-init";
const INIT_DISPLAY: &str = "/sbin/keel-init";

/// Loads and starts the first user program, with the console on fds 0-2.
fn start_init() -> Result<keel_linux_abi::process::Spawned, &'static str> {
    let file = keel_linux_abi::fs::read_file(INIT).map_err(|_| "not in the initramfs")?;
    let loaded =
        keel_linux_abi::exec::load(&file, INIT, &[INIT], &[]).map_err(|_| "not a valid program")?;
    // The only factory the kernel hands out, at fd 3, close-on-exec (ADR
    // 0040).
    keel_linux_abi::process::spawn_with_fd3(
        "keel-init",
        &loaded,
        keel_linux_abi::native::root_factory(),
    )
    .map_err(|_| "no process could be made")
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
    // Where the kernel and the direct map are would undo KASLR (P1-S5),
    // so a normal boot does not print them (audit finding 8). Test boots
    // do: `cargo xtask test` compares them across boots
    // (`kaslr.layout_varies`). The command line comes from `limine.conf`,
    // which is trusted only as far as the boot chain is (audit finding 2);
    // whoever can edit it can also replace the kernel.
    let cmdline = boot::cmdline();
    if test_boot(cmdline) {
        match boot::hhdm_offset() {
            Some(offset) => kresult!("boot: HHDM offset {offset:#018x}"),
            None => kprintln!("boot: no HHDM response"),
        }
        match boot::kernel_address() {
            Some(k) => kresult!(
                "boot: kernel at virt {:#018x} phys {:#018x}",
                k.virtual_base,
                k.physical_base
            ),
            None => kprintln!("boot: no kernel address response"),
        }
    } else {
        kprintln!("boot: kernel and direct-map addresses not shown (KASLR)");
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
    if PANICKING.swap(true, Ordering::AcqRel) {
        // A fault or panic while panicking. Formatting or the framebuffer
        // may be what failed, so write one fixed line and stop.
        #[cfg(feature = "selftest")]
        if TEST_MODE.load(Ordering::Relaxed) {
            selftest::judge_nested_panic();
        }
        console::emergency_serial("\n*** KEEL KERNEL PANIC while panicking; halted ***\n");
        if TEST_MODE.load(Ordering::Relaxed) {
            exit_qemu(ExitCode::Failure);
        }
        halt_forever();
    }
    #[cfg(feature = "selftest")]
    if TEST_MODE.load(Ordering::Relaxed) {
        // A scenario that ends in a deliberate fatal exception judges the
        // outcome here and exits QEMU itself.
        selftest::judge_expected_fault();
        selftest::fault_in_panic_if_requested();
    }
    console::emergency_print(format_args!("\n*** KEEL KERNEL PANIC ***\n{info}\n"));
    if TEST_MODE.load(Ordering::Relaxed) {
        exit_qemu(ExitCode::Failure);
    }
    halt_forever();
}

/// The boot-time vulnerability report (P1-S4, SR-15): one line per item.
fn report_mitigations(report: &keel_hal::mitigations::Report) {
    use keel_core::cpuvuln::Status;
    let c = &report.cpu;
    kprintln!(
        "cpu: {} family {:#x} model {:#x} stepping {:#x}{}; IA32_ARCH_CAPABILITIES {:#x}",
        if c.intel { "Intel" } else { "non-Intel" },
        c.family,
        c.model,
        c.stepping,
        if c.hypervisor { " (virtualized)" } else { "" },
        c.arch_capabilities
    );
    for item in &report.items {
        let (kind, detail) = match item.status {
            Status::NotAffected(d) => ("Not affected", d),
            Status::Mitigated(d) => ("Mitigation", d),
            Status::Vulnerable(d) => ("VULNERABLE", d),
        };
        kprintln!("vuln: {}: {kind}: {detail}", item.name);
    }
    if !report.spec_ctrl_written || !report.mcu_opt_written {
        kprintln!(
            "vuln: WARNING: the CPU rejected a mitigation MSR write (SPEC_CTRL {}, MCU_OPT_CTRL {}); IBRS and IBPB are off",
            if report.spec_ctrl_written {
                "ok"
            } else {
                "rejected"
            },
            if report.mcu_opt_written {
                "ok"
            } else {
                "rejected"
            }
        );
    }
}
