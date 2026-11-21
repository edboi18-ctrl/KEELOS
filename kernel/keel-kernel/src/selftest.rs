//! In-kernel self-tests, run at boot when the command line contains
//! `test=<phase>` (spec section 15, "Kernel integration" layer).
//!
//! Output format, parsed by `cargo xtask test`:
//!   `TEST <name> PASS|FAIL <detail>` per test, then one
//!   `TEST SUMMARY passed=<n> failed=<m>` line.
//!
//! The test flag only adds checks; it disables no security control
//! (SR-21).

use core::sync::atomic::{AtomicU8, Ordering};

use keel_hal::arch::x86_64::gdt::{self, IstSlot};
use keel_hal::arch::x86_64::{cpu, idt, selftest as hw};
use keel_hal::boot::{self, RegionKind};
use keel_hal::drivers::debug_exit::{ExitCode, exit_qemu};
use keel_hal::{console, kprintln, memory};

/// Lowest address of the canonical higher half with 4-level paging
/// (Intel SDM Vol. 1, section 3.3.7.1, "Canonical Addressing").
const HIGHER_HALF_START: u64 = 0xffff_8000_0000_0000;

/// Lowest address a Limine executable may be loaded at
/// (PROTOCOL.md, "Memory Layout at Entry").
const KERNEL_MIN_BASE: u64 = 0xffff_ffff_8000_0000;

/// Extracts the phase from a `test=<n>` word on the command line.
pub fn requested_phase(cmdline: &str) -> Option<u32> {
    cmdline
        .split_ascii_whitespace()
        .find_map(|word| word.strip_prefix("test="))
        .and_then(|value| value.parse().ok())
}

/// Scenarios: boots that test one behaviour which ends the kernel, such as
/// a double fault. Selected with `scenario=<name>` next to `test=<n>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Scenario {
    None = 0,
    DoubleFault = 1,
    Unknown = 255,
}

/// Extracts the scenario from a `scenario=<name>` word on the command line.
pub fn requested_scenario(cmdline: &str) -> Scenario {
    match cmdline
        .split_ascii_whitespace()
        .find_map(|word| word.strip_prefix("scenario="))
    {
        None => Scenario::None,
        Some("double_fault") => Scenario::DoubleFault,
        Some(_) => Scenario::Unknown,
    }
}

/// The scenario that is running, for the panic handler.
static ACTIVE_SCENARIO: AtomicU8 = AtomicU8::new(Scenario::None as u8);

/// Called from the panic handler in test mode. If the running scenario
/// expected exactly this fatal exception, report PASS and exit QEMU;
/// otherwise return so the normal panic path reports a failure.
pub fn judge_expected_fault() {
    if ACTIVE_SCENARIO.load(Ordering::Relaxed) != Scenario::DoubleFault as u8 {
        return;
    }
    let Some(fault) = idt::last_fatal_exception() else {
        return;
    };
    let on_ist1 = idt::ist_containing(fault.frame_address) == Some(IstSlot::DoubleFault);
    if fault.vector == 8 && on_ist1 {
        console::emergency_print(format_args!(
            "TEST idt.double_fault PASS #DF delivered on the IST1 stack (frame at {:#x})\n\
             TEST SUMMARY passed=1 failed=0\n",
            fault.frame_address
        ));
        exit_qemu(ExitCode::Success);
    }
}

pub struct Runner {
    passed: u32,
    failed: u32,
}

impl Runner {
    fn check(&mut self, name: &str, ok: bool, detail: &str) {
        if ok {
            self.passed += 1;
            kprintln!("TEST {name} PASS {detail}");
        } else {
            self.failed += 1;
            kprintln!("TEST {name} FAIL {detail}");
        }
    }
}

/// Runs the self-tests for `phase` (or one scenario) and returns whether
/// all passed. A scenario may not return at all.
pub fn run(phase: u32, scenario: Scenario) -> bool {
    let mut runner = Runner {
        passed: 0,
        failed: 0,
    };
    match (phase, scenario) {
        (0, Scenario::None) => phase0(&mut runner),
        (1, Scenario::None) => phase1(&mut runner),
        (1, Scenario::DoubleFault) => {
            ACTIVE_SCENARIO.store(Scenario::DoubleFault as u8, Ordering::Relaxed);
            kprintln!("selftest: forcing a double fault");
            hw::trigger_double_fault();
        }
        _ => runner.check(
            "selftest.phase",
            false,
            "unknown phase or scenario requested",
        ),
    }
    kprintln!(
        "TEST SUMMARY passed={} failed={}",
        runner.passed,
        runner.failed
    );
    runner.failed == 0
}

fn phase0(t: &mut Runner) {
    let revision = boot::base_revision();
    t.check(
        "boot.base_revision",
        revision.supported && revision.loaded == Some(revision.requested),
        "bootloader honours the requested Limine base revision",
    );

    t.check(
        "serial.loopback",
        console::serial_present(),
        "COM1 answered the 16550 loopback test",
    );

    let hhdm = boot::hhdm_offset();
    t.check(
        "boot.hhdm",
        hhdm.is_some_and(|o| o >= HIGHER_HALF_START && o % 4096 == 0),
        "HHDM offset is page-aligned and in the higher half",
    );

    let kernel = boot::kernel_address();
    let entry = crate::kmain as *const () as u64;
    t.check(
        "boot.kernel_address",
        kernel.is_some_and(|k| k.virtual_base >= KERNEL_MIN_BASE && entry >= k.virtual_base),
        "kernel is loaded in the top 2 GiB and contains its entry point",
    );

    let mut usable_bytes = 0u64;
    let mut sorted = true;
    let mut usable_aligned = true;
    let mut previous_base = 0u64;
    for region in boot::memory_map() {
        sorted &= region.base >= previous_base;
        previous_base = region.base;
        if region.kind == RegionKind::Usable {
            usable_bytes = usable_bytes.saturating_add(region.length);
            usable_aligned &= region.base % 4096 == 0 && region.length % 4096 == 0;
        }
    }
    t.check(
        "boot.memmap",
        usable_bytes >= 64 * 1024 * 1024 && sorted && usable_aligned,
        "memory map is sorted, usable regions are page-aligned, >= 64 MiB usable",
    );

    t.check(
        "boot.rsdp",
        boot::rsdp().is_some_and(|rsdp| rsdp.starts_with(b"RSD PTR ")),
        "ACPI RSDP is mapped and carries its signature",
    );

    // cpio "newc" archives start with the ASCII magic 070701
    // (cpio(5), "New ASCII Format").
    let initramfs = boot::modules().find(|m| m.path.ends_with("initramfs.cpio"));
    t.check(
        "boot.module.initramfs",
        initramfs.is_some_and(|m| m.data.starts_with(b"070701")),
        "initramfs module is loaded and starts with the cpio newc magic",
    );

    let have_framebuffer = console::framebuffer_cursor().is_some();
    t.check(
        "fb.console",
        have_framebuffer,
        "framebuffer text console is running",
    );

    if t.failed != 0 {
        return;
    }

    // Phase 0 acceptance marker, on serial and on the framebuffer. The
    // framebuffer copy is then proven by reading its pixels back.
    const MARKER: &str = "KEEL P0 OK";
    kprintln!("{MARKER}");
    let shown = console::framebuffer_cursor()
        .and_then(|(_, row)| row.checked_sub(1))
        .is_some_and(|row| console::framebuffer_shows(0, row, MARKER));
    t.check(
        "fb.marker",
        shown,
        "framebuffer pixels show the acceptance marker",
    );
}

fn phase1(t: &mut Runner) {
    // P1-T1: our GDT and TSS are live.
    let segments = cpu::segment_state();
    t.check(
        "gdt.selectors",
        segments.cs == gdt::KERNEL_CS
            && segments.ss == gdt::KERNEL_DS
            && segments.tr == gdt::TSS_SELECTOR,
        "CS, SS and TR hold Keel's kernel selectors",
    );
    let ist_aligned = [IstSlot::DoubleFault, IstSlot::Nmi, IstSlot::MachineCheck]
        .into_iter()
        .all(|slot| gdt::ist_stack_top(slot).is_multiple_of(16));
    t.check(
        "tss.ist_stacks",
        ist_aligned,
        "IST stack tops are 16-byte aligned",
    );

    // P1-T2: a #BP round trip through the IDT returns and preserves state.
    let before = idt::breakpoint_count();
    let preserved = hw::breakpoint_preserves_registers();
    t.check(
        "idt.breakpoint",
        preserved && idt::breakpoint_count() == before + 1,
        "INT3 reaches the handler once and returns with all registers intact",
    );
    phase1_frames(t);
    t.check(
        "cpu.interrupts_off",
        !cpu::interrupts_enabled(),
        "maskable interrupts stay disabled until the APIC is set up",
    );
}

/// P1-T3 and SR-18: frames come out distinct, page-aligned, inside usable
/// memory and zero-filled, even after a previous owner dirtied them; and
/// freeing returns the allocator to its starting count.
pub fn phase1_frames(t: &mut Runner) {
    const COUNT: usize = 64;
    let baseline = memory::free_frames();
    let mut frames = [None; COUNT];
    for slot in frames.iter_mut() {
        *slot = memory::allocate_zeroed();
    }
    let all = frames.iter().all(Option::is_some);
    let frames = frames.map(|f| f.unwrap_or(keel_core::frame::Frame::containing(0)));

    let mut distinct = all;
    for (i, a) in frames.iter().enumerate() {
        distinct &= frames[i + 1..].iter().all(|b| a != b);
    }
    let in_usable = frames.iter().all(|f| {
        f.address() != 0
            && f.address() % 4096 == 0
            && boot::memory_map().any(|r| {
                r.kind == RegionKind::Usable
                    && r.base <= f.address()
                    && f.address() < r.base + r.length
            })
    });
    t.check(
        "frames.allocate",
        all && distinct && in_usable && memory::free_frames() == baseline - COUNT,
        "64 frames are distinct, aligned, in usable RAM, and counted",
    );

    let zeroed = frames
        .iter()
        .all(|&f| memory::with_frame_bytes(f, |bytes| bytes.iter().all(|&b| b == 0)) == Ok(true));
    // Dirty every frame, free it, and allocate again: the allocator hands
    // frames back out, and each must arrive zeroed (SR-18).
    for &f in &frames {
        let _ = memory::with_frame_bytes(f, |bytes| bytes.fill(0xA5));
        let _ = memory::release(f);
    }
    let mut reused_zeroed = true;
    let mut again = [None; COUNT];
    for slot in again.iter_mut() {
        let frame = memory::allocate_zeroed();
        reused_zeroed &= frame.is_some_and(|f| {
            memory::with_frame_bytes(f, |bytes| bytes.iter().all(|&b| b == 0)) == Ok(true)
        });
        *slot = frame;
    }
    let reused = again
        .iter()
        .flatten()
        .filter(|f| frames.contains(f))
        .count();
    t.check(
        "frames.zeroed",
        zeroed && reused_zeroed && reused > 0,
        "new frames read as zero, including frames a previous owner filled (SR-18)",
    );

    for frame in again.iter().flatten() {
        let _ = memory::release(*frame);
    }
    let stale = frames[0];
    t.check(
        "frames.release",
        memory::free_frames() == baseline
            && memory::release(stale).is_err()
            && memory::with_frame_bytes(stale, |_| ()).is_err(),
        "freeing restores the count; a freed frame can be neither freed again nor read",
    );
}
