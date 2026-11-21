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
use keel_hal::arch::x86_64::{cpu, idt, paging, selftest as hw};
use keel_hal::boot::{self, RegionKind};
use keel_hal::drivers::debug_exit::{ExitCode, exit_qemu};
use keel_hal::{console, interrupts, kprintln, memory, time};

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
    WriteKernelText = 2,
    ExecuteData = 3,
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
        Some("write_kernel_text") => Scenario::WriteKernelText,
        Some("execute_data") => Scenario::ExecuteData,
        Some(_) => Scenario::Unknown,
    }
}

/// The scenario that is running, for the panic handler.
static ACTIVE_SCENARIO: AtomicU8 = AtomicU8::new(Scenario::None as u8);

/// Called from the panic handler in test mode. If the running scenario
/// expected exactly this fatal exception, report PASS and exit QEMU;
/// otherwise return so the normal panic path reports a failure.
pub fn judge_expected_fault() {
    use idt::page_fault::{INSTRUCTION_FETCH, PRESENT, WRITE};
    let Some(fault) = idt::last_fatal_exception() else {
        return;
    };
    let (name, passed, detail) = match ACTIVE_SCENARIO.load(Ordering::Relaxed) {
        s if s == Scenario::DoubleFault as u8 => (
            "idt.double_fault",
            fault.vector == 8
                && idt::ist_containing(fault.frame_address) == Some(IstSlot::DoubleFault),
            "#DF delivered on the IST1 stack",
        ),
        s if s == Scenario::WriteKernelText as u8 => (
            "paging.text_read_only",
            fault.vector == 14
                && fault.error_code & (PRESENT | WRITE | INSTRUCTION_FETCH) == PRESENT | WRITE
                && fault.fault_address == hw::write_to_kernel_text as *const () as u64,
            "a kernel write to its own text raised #PF (present, write) at the target (SR-12)",
        ),
        s if s == Scenario::ExecuteData as u8 => (
            "paging.data_no_execute",
            fault.vector == 14
                && fault.error_code & (PRESENT | INSTRUCTION_FETCH) == PRESENT | INSTRUCTION_FETCH
                && paging::translate(fault.fault_address).is_some_and(|t| !t.flags.executable),
            "an instruction fetch from kernel data raised #PF (present, fetch) (SR-12)",
        ),
        _ => return,
    };
    if passed {
        console::emergency_print(format_args!(
            "TEST {name} PASS {detail}\nTEST SUMMARY passed=1 failed=0\n"
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
        (1, Scenario::WriteKernelText) => {
            ACTIVE_SCENARIO.store(Scenario::WriteKernelText as u8, Ordering::Relaxed);
            kprintln!("selftest: writing to kernel text");
            hw::write_to_kernel_text();
        }
        (1, Scenario::ExecuteData) => {
            ACTIVE_SCENARIO.store(Scenario::ExecuteData as u8, Ordering::Relaxed);
            kprintln!("selftest: executing kernel data");
            hw::execute_kernel_data();
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
    phase1_paging(t);
    phase1_heap(t);
    phase1_interrupts(t);
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

/// P1-T4, SR-12, SR-13, SR-17: the active page tables and CPU protections.
pub fn phase1_paging(t: &mut Runner) {
    let walk = paging::walk();
    t.check(
        "paging.wx_walk",
        walk.is_some_and(|w| {
            w.writable_and_executable == 0 && w.giant_pages == 0 && w.small_pages > 0
        }),
        "no page in the kernel's tables is both writable and executable (SR-12)",
    );

    let [start, rodata, data, end] = paging::kernel_segments();
    let text = paging::translate(start);
    let ro = paging::translate(rodata);
    let rw = paging::translate(data);
    let segments_ok = text
        .is_some_and(|t| t.flags.executable && !t.flags.writable && !t.flags.user)
        && ro.is_some_and(|t| !t.flags.executable && !t.flags.writable)
        && rw.is_some_and(|t| !t.flags.executable && t.flags.writable)
        && paging::translate(end - 1).is_some_and(|t| t.flags.writable && !t.flags.executable);
    t.check(
        "paging.kernel_segments",
        segments_ok,
        "text is read+execute, rodata read-only, data read+write no-execute",
    );

    let guards = gdt::ist_guard_pages();
    let guarded = guards.iter().all(|&g| paging::translate(g).is_none())
        && [IstSlot::DoubleFault, IstSlot::Nmi, IstSlot::MachineCheck]
            .into_iter()
            .all(|slot| {
                let r = gdt::ist_stack_range(slot);
                paging::translate(r.start).is_some_and(|t| t.flags.writable)
                    && paging::translate(r.end - 1).is_some_and(|t| t.flags.writable)
            });
    t.check(
        "paging.ist_guard_pages",
        guarded,
        "each IST stack is mapped and the page below it is not (SR-17)",
    );

    let alias_hidden = match (paging::translate(start), boot::hhdm_offset()) {
        (Some(text), Some(hhdm)) => paging::translate(hhdm + text.phys).is_none(),
        _ => false,
    };
    t.check(
        "paging.no_kernel_alias",
        alias_hidden,
        "the kernel image has no writable alias in the direct map",
    );

    let lower_half_empty = [0u64, 0x1000, 0x40_0000, 0x7fff_ffff_f000]
        .iter()
        .all(|&a| paging::translate(a).is_none());
    t.check(
        "paging.lower_half_empty",
        lower_half_empty,
        "nothing is mapped in the user half of the address space",
    );

    let features = cpu::features();
    let cr4 = cpu::read_cr4();
    let protections = cpu::read_cr0() & cpu::CR0_WP != 0
        && (cr4 & cpu::CR4_SMEP != 0) == features.smep
        && (cr4 & cpu::CR4_SMAP != 0) == features.smap
        && (cr4 & cpu::CR4_UMIP != 0) == features.umip
        && features.nx;
    t.check(
        "cpu.protections",
        protections,
        "NX, WP, and every reported one of SMEP, SMAP and UMIP are on (SR-13)",
    );
}

/// P1-T5: the kernel heap behind `alloc`.
pub fn phase1_heap(t: &mut Runner) {
    use alloc::boxed::Box;
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::fmt::Write;

    // Many small objects of mixed sizes, kept alive together.
    let mut numbers: Vec<u64> = Vec::new();
    for i in 0..20_000u64 {
        numbers.push(i * 3);
    }
    let mut map = BTreeMap::new();
    for i in 0..2_000u32 {
        let mut text = String::new();
        let _ = write!(text, "entry-{i}");
        map.insert(i, (Box::new(i ^ 0x5A5A), text));
    }
    let numbers_ok = numbers.iter().sum::<u64>() == 3 * (19_999 * 20_000 / 2);
    let map_ok = map.len() == 2_000
        && map.iter().all(|(k, (b, s))| {
            **b == k ^ 0x5A5A
                && s.strip_prefix("entry-").and_then(|n| n.parse::<u32>().ok()) == Some(*k)
        });
    t.check(
        "heap.collections",
        numbers_ok && map_ok,
        "Vec, Box, String and BTreeMap work with 22,000 live objects",
    );
    drop(map);

    // A large allocation gets its own pages, non-executable, with an
    // unmapped page after it, and returns its frames when freed.
    const LARGE: usize = 1 << 20;
    let before = memory::free_frames();
    let block: Vec<u8> = alloc::vec![0xAB; LARGE];
    let start = block.as_ptr() as u64;
    let after_alloc = memory::free_frames();
    let rights_ok = paging::translate(start)
        .is_some_and(|t| t.flags.writable && !t.flags.executable && !t.flags.user)
        && paging::translate(start + LARGE as u64 - 1).is_some()
        && paging::translate(start + LARGE as u64).is_none()
        && (paging::KERNEL_HEAP_BASE..paging::KERNEL_HEAP_BASE + paging::KERNEL_HEAP_SIZE)
            .contains(&start);
    let content_ok = block.iter().all(|&b| b == 0xAB);
    drop(block);
    let after_free = memory::free_frames();
    let pages = LARGE / 4096;
    t.check(
        "heap.large",
        rights_ok
            && content_ok
            && before - after_alloc >= pages
            && after_free >= before.saturating_sub(4)
            && paging::translate(start).is_none(),
        "1 MiB allocation: own RW+NX pages, guard page after, frames returned and unmapped on free",
    );
    drop(numbers);
}

/// P1-T6, P1-T7: interrupt controllers, the periodic timer and the clock.
pub fn phase1_interrupts(t: &mut Runner) {
    let madt = keel_hal::acpi::madt();
    t.check(
        "acpi.madt",
        madt.as_ref().is_ok_and(|m| {
            m.entries
                .iter()
                .any(|e| matches!(e, keel_core::acpi::MadtEntry::IoApic { .. }))
                && m.entries.iter().any(|e| {
                    matches!(
                        e,
                        keel_core::acpi::MadtEntry::LocalApic { enabled: true, .. }
                            | keel_core::acpi::MadtEntry::LocalX2Apic { enabled: true, .. }
                    )
                })
        }),
        "the MADT validates and lists an enabled CPU and an I/O APIC",
    );
    t.check(
        "cpu.interrupts_on",
        cpu::interrupts_enabled(),
        "maskable interrupts are enabled after the APIC and timer are set up",
    );

    // 100 timer interrupts must take about 100 ms by the HPET. The bounds
    // are wide because emulated time under TCG is not exact.
    let start_ticks = time::ticks();
    let start_ns = time::hpet_nanos();
    while time::ticks() < start_ticks + 100 {
        interrupts::wait();
    }
    let elapsed_ms = (time::hpet_nanos() - start_ns) / 1_000_000;
    t.check(
        "time.periodic_tick",
        (50..=250).contains(&elapsed_ms),
        "100 APIC timer interrupts took 50-250 ms by the HPET (1 kHz nominal)",
    );

    let mut previous = time::monotonic_nanos();
    let mut monotonic = true;
    for _ in 0..10_000 {
        let now = time::monotonic_nanos();
        monotonic &= now >= previous;
        previous = now;
    }
    let (clock, reference) = (time::monotonic_nanos(), time::hpet_nanos());
    let agrees = clock.abs_diff(reference) <= reference / 20 + 1_000_000;
    t.check(
        "time.monotonic",
        monotonic && agrees,
        "the monotonic clock never goes backwards and agrees with the HPET within 5%",
    );

    t.check(
        "interrupts.no_strays",
        interrupts::unexpected_count() == 0,
        "no interrupt arrived on a vector without a handler",
    );
}
