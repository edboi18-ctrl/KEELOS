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
use keel_hal::{console, interrupts, kprintln, memory, sched, time};

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
    StackOverflow = 4,
    Smap = 5,
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
        Some("stack_overflow") => Scenario::StackOverflow,
        Some("smap") => Scenario::Smap,
        Some(_) => Scenario::Unknown,
    }
}

/// User page the `smap` scenario reads directly.
const SMAP_TARGET: u64 = 0x60_0000;

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
        s if s == Scenario::StackOverflow as u8 => (
            "sched.stack_guard",
            fault.vector == 8
                && idt::ist_containing(fault.frame_address) == Some(IstSlot::DoubleFault)
                && paging::is_kernel_stack_guard(fault.fault_address),
            "a kernel thread overflowing its stack hit its guard page and was caught on IST1 (SR-17)",
        ),
        s if s == Scenario::Smap as u8 => (
            "vm.smap",
            fault.vector == 14
                && fault.error_code & (PRESENT | WRITE | INSTRUCTION_FETCH) == PRESENT
                && fault.fault_address == SMAP_TARGET,
            "a direct kernel read of a present user page faulted (SMAP, SR-13)",
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
        (1, Scenario::StackOverflow) => {
            ACTIVE_SCENARIO.store(Scenario::StackOverflow as u8, Ordering::Relaxed);
            kprintln!("selftest: overflowing a kernel thread's stack");
            let _ = sched::spawn("overflow", || {
                let _ = hw::overflow_stack(0);
            });
            loop {
                sched::sleep_ms(1000);
            }
        }
        (1, Scenario::Smap) => {
            use keel_core::vm::{Placement, Prot};
            use keel_hal::vm::{AddressSpace, copy_to_user, with_address_space};
            ACTIVE_SCENARIO.store(Scenario::Smap as u8, Ordering::Relaxed);
            kprintln!("selftest: kernel reading user memory without the copy routine");
            let space = AddressSpace::new().expect("address space");
            space
                .map(Placement::Fixed(SMAP_TARGET), 4096, Prot::READ_WRITE)
                .expect("mapping");
            with_address_space(&space, || {
                // Populate the page legitimately first, so the direct read
                // below hits a present page and only SMAP can stop it.
                let _ = copy_to_user(SMAP_TARGET, b"user data");
                let _ = hw::read_user_directly(SMAP_TARGET);
            });
            runner.check(
                "vm.smap",
                false,
                "the direct read of user memory did not fault",
            );
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
    phase1_sched(t);
    phase1_vm(t);
    phase1_prot_none(t);
    phase1_user(t);
    phase1_fs(t);
    phase1_musl(t);
    phase1_exec(t);
    phase1_mitigations(t);
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

    // P1-S6: RELRO. Every page of .data.rel.ro and .got is read-only and
    // no-execute, and the range really holds relocated pointers (a
    // reference to a static is one).
    static TARGET: u8 = 7;
    static POINTER: &u8 = &TARGET;
    let (relro_start, relro_end) = paging::relro_range();
    let relro_pages_ok = (relro_start..relro_end).step_by(4096).all(|page| {
        paging::translate(page).is_some_and(|t| !t.flags.writable && !t.flags.executable)
    });
    let pointer_at = core::ptr::addr_of!(POINTER) as u64;
    t.check(
        "paging.relro",
        relro_end > relro_start
            && relro_pages_ok
            && relro_start <= pointer_at
            && pointer_at < relro_end
            && *core::hint::black_box(POINTER) == 7,
        ".data.rel.ro and .got are read-only after relocation (P1-S6)",
    );

    // P1-S6: boot runs on its own kernel stack, with an unmapped guard
    // page below it, not on the bootloader's unguarded one.
    let rsp = cpu::stack_pointer();
    t.check(
        "paging.boot_stack_guard",
        sched::boot_stack_bounds().is_some_and(|(guard, base, top)| {
            (base..top).contains(&rsp)
                && paging::translate(guard).is_none()
                && paging::translate(base).is_some()
        }),
        "the boot thread runs on a kernel stack whose guard page is unmapped (SR-17)",
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

static COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static STOP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static WAKE: sched::WaitQueue = sched::WaitQueue::new();
static XMM_OK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn counting_worker() {
    for _ in 0..1000 {
        COUNTER.fetch_add(1, Ordering::Relaxed);
        sched::yield_now();
    }
}

fn xmm_worker(pattern: u64) {
    hw::set_xmm0(pattern);
    let mut ok = true;
    for _ in 0..200 {
        sched::yield_now();
        ok &= hw::get_xmm0() == pattern;
    }
    if ok {
        XMM_OK.fetch_add(1, Ordering::Relaxed);
    }
}

/// P1-T8: threads, preemption, sleeping, wait queues, FPU isolation.
pub fn phase1_sched(t: &mut Runner) {
    use core::sync::atomic::Ordering::Relaxed;

    let frames_before = memory::free_frames();
    // System threads (idle, console echo) are not this test's business.
    let threads_before = sched::thread_count();
    let switches_before = sched::switch_count();
    let mut ids = alloc::vec::Vec::new();
    for _ in 0..4 {
        ids.extend(sched::spawn("counter", counting_worker).ok());
    }
    for id in &ids {
        join(*id);
    }
    t.check(
        "sched.round_robin",
        ids.len() == 4
            && COUNTER.load(Relaxed) == 4000
            && sched::switch_count() >= switches_before + 4000,
        "four threads yielding to each other all ran to completion",
    );

    // A thread that never yields: the boot thread only gets the CPU back
    // to set STOP if the timer preempts it.
    let spinner = sched::spawn("spinner", || {
        while !STOP.load(Ordering::Relaxed) {
            core::hint::spin_loop();
        }
    });
    sched::sleep_ms(30);
    STOP.store(true, Relaxed);
    if let Ok(id) = spinner {
        join(id);
    }
    t.check(
        "sched.preemption",
        spinner.is_ok(),
        "a thread spinning without yielding was preempted by the timer",
    );

    let start = time::monotonic_nanos();
    sched::sleep_ms(50);
    let slept_ms = (time::monotonic_nanos() - start) / 1_000_000;
    t.check(
        "sched.sleep",
        (50..=200).contains(&slept_ms),
        "sleep_ms(50) slept between 50 and 200 ms",
    );

    let producer = sched::spawn("producer", || {
        sched::sleep_ms(10);
        READY.store(true, Ordering::Relaxed);
        WAKE.wake_all();
    });
    WAKE.wait_until(|| READY.load(Ordering::Relaxed));
    if let Ok(id) = producer {
        join(id);
    }
    t.check(
        "sched.wait_queue",
        producer.is_ok() && READY.load(Relaxed),
        "a thread blocked on a wait queue was woken by another thread",
    );

    let a = sched::spawn("xmm-a", || xmm_worker(0x1111_2222_3333_4444));
    let b = sched::spawn("xmm-b", || xmm_worker(0x5555_6666_7777_8888));
    for id in [a, b].into_iter().flatten() {
        join(id);
    }
    t.check(
        "sched.fpu_isolation",
        XMM_OK.load(Relaxed) == 2,
        "two threads kept their own XMM0 across 200 switches each",
    );

    // F-0004 regression: while the console lock is held (here: while a
    // kprintln! argument is being formatted), interrupts must be off, so
    // the holder cannot be preempted and leave a system call spinning.
    struct InterruptProbe;
    static INTERRUPTS_DURING_PRINT: AtomicU8 = AtomicU8::new(2);
    impl core::fmt::Display for InterruptProbe {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let on = cpu::interrupts_enabled();
            INTERRUPTS_DURING_PRINT.store(u8::from(on), Ordering::Relaxed);
            f.write_str("console lock probe")
        }
    }
    let enabled_before = cpu::interrupts_enabled();
    kprintln!("selftest: {InterruptProbe}");
    t.check(
        "console.lock_disables_interrupts",
        enabled_before
            && INTERRUPTS_DURING_PRINT.load(Ordering::Relaxed) == 0
            && cpu::interrupts_enabled(),
        "printing holds the console lock with interrupts off, and restores them after (F-0004)",
    );

    // The bounded wait the self-tests use: it gives up on a thread that
    // is still running, and succeeds once it has finished.
    let sleeper = sched::spawn("sleeper", || sched::sleep_ms(100));
    t.check(
        "sched.join_timeout",
        sleeper.is_ok_and(|id| !sched::join_timeout(id, 10) && sched::join_timeout(id, 2_000)),
        "a bounded join gives up on a running thread and returns once it exits",
    );

    // All those threads have exited; their stacks must be gone again.
    sched::yield_now();
    t.check(
        "sched.reclaim",
        sched::thread_count() == threads_before && memory::free_frames() + 64 >= frames_before,
        "exited threads are removed and their stack frames returned",
    );
}

/// P1-T9 and P1-S2: user address spaces, demand paging, copy-on-write,
/// and the checked user-copy routines.
pub fn phase1_vm(t: &mut Runner) {
    use keel_core::vm::{Placement, Prot, USER_END};
    use keel_hal::vm::{AddressSpace, copy_from_user, copy_to_user, with_address_space};

    let frames_at_start = memory::free_frames();
    let Ok(space) = AddressSpace::new() else {
        t.check(
            "vm.address_space",
            false,
            "could not create an address space",
        );
        return;
    };

    // Phase 1 acceptance item 4: a 64 GiB PROT_NONE reservation costs no
    // physical memory.
    let before = memory::free_frames();
    let reserve = space.map(Placement::Anywhere { hint: 0 }, 64 << 30, Prot::NONE);
    let after = memory::free_frames();
    let reserve_denied = reserve.is_ok_and(|start| {
        with_address_space(&space, || {
            copy_from_user(&mut [0u8; 8], start + (1 << 30)).is_err()
        })
    });
    t.check(
        "vm.reservation",
        reserve.is_ok() && before == after && space.resident_bytes() == 0 && reserve_denied,
        "a 64 GiB PROT_NONE reservation uses no frames and refuses access",
    );

    // Demand paging: only touched pages get frames, and they start zeroed.
    let region = space.map(Placement::Anywhere { hint: 0 }, 16 << 20, Prot::READ_WRITE);
    let demand_ok = region.is_ok_and(|start| {
        let target = start + (5 << 20) + 123;
        with_address_space(&space, || {
            let mut first = [0xFFu8; 16];
            let read_zero = copy_from_user(&mut first, target).is_ok() && first == [0; 16];
            let wrote = copy_to_user(target, b"demand paged!").is_ok();
            let mut back = [0u8; 13];
            let read_back = copy_from_user(&mut back, target).is_ok() && &back == b"demand paged!";
            read_zero && wrote && read_back
        })
    });
    t.check(
        "vm.demand_paging",
        demand_ok && space.resident_bytes() == 4096,
        "touching 16 bytes of a 16 MiB mapping backs exactly one zeroed page",
    );

    // Bad user pointers are refused without touching kernel memory.
    let kernel_address = &raw const COUNTER as u64;
    let bad_pointers = with_address_space(&space, || {
        let mut buf = [0u8; 16];
        copy_to_user(kernel_address, b"x").is_err()
            && copy_from_user(&mut buf, 0).is_err()
            && copy_from_user(&mut buf, 0x50_0000).is_err()
            && copy_from_user(&mut buf, USER_END - 8).is_err()
            && copy_from_user(&mut buf, u64::MAX - 4).is_err()
    });
    t.check(
        "vm.user_copy_bounds",
        bad_pointers,
        "kernel, null, unmapped, boundary-straddling and wrapping pointers give EFAULT (SR-19)",
    );

    // mprotect to read-only: a write through the copy routine is refused.
    let protect_ok = region.is_ok_and(|start| {
        space
            .protect(
                start,
                16 << 20,
                Prot {
                    read: true,
                    write: false,
                    exec: false,
                },
            )
            .is_ok()
            && with_address_space(&space, || copy_to_user(start + (5 << 20), b"no").is_err())
    });
    t.check(
        "vm.protect",
        protect_ok,
        "after mprotect(PROT_READ) the page can no longer be written",
    );
    let wx_refused = space
        .map(
            Placement::Anywhere { hint: 0 },
            4096,
            Prot {
                read: true,
                write: true,
                exec: true,
            },
        )
        .is_err();
    t.check(
        "vm.no_write_exec",
        wx_refused,
        "a writable and executable user mapping is refused (SR-12)",
    );

    // Copy-on-write: duplicate, then write in each copy.
    let cow_ok = (|| {
        let parent = AddressSpace::new().ok()?;
        let page = parent
            .map(Placement::Fixed(0x40_0000), 4096, Prot::READ_WRITE)
            .ok()?;
        with_address_space(&parent, || copy_to_user(page, b"parent")).ok()?;
        let child = parent.duplicate().ok()?;
        let shared = !parent.page_flags(page)?.writable && !child.page_flags(page)?.writable;
        with_address_space(&child, || copy_to_user(page, b"child!")).ok()?;
        let mut p = [0u8; 6];
        let mut c = [0u8; 6];
        with_address_space(&parent, || copy_from_user(&mut p, page)).ok()?;
        with_address_space(&child, || copy_from_user(&mut c, page)).ok()?;
        // The parent's page is exclusive again after the child copied, so
        // its next write takes it over without copying.
        with_address_space(&parent, || copy_to_user(page, b"PARENT")).ok()?;
        let parent_writable = parent.page_flags(page)?.writable;
        Some(
            shared
                && &p == b"parent"
                && &c == b"child!"
                && child.page_flags(page)?.writable
                && parent_writable,
        )
    })()
    .unwrap_or(false);
    t.check(
        "vm.copy_on_write",
        cow_ok,
        "after duplicate, a write in either copy gets a private page; the other copy is unchanged",
    );

    drop(space);
    t.check(
        "vm.teardown",
        memory::free_frames() + 8 >= frames_at_start,
        "dropping address spaces returns their pages and page tables",
    );
}

/// P1-T12: the root filesystem built at boot from the initramfs, path
/// lookup, and the device nodes.
pub fn phase1_fs(t: &mut Runner) {
    use keel_core::errno::Errno;
    use keel_core::vfs::{Device, Kind, ROOT, S_IFCHR, S_IFMT};
    use keel_linux_abi::fs;

    let release = fs::read_file(b"/etc/keel-release");
    t.check(
        "fs.initramfs",
        release.as_deref().is_ok_and(|r| r.starts_with(b"Keel")),
        "/etc/keel-release from the initramfs is readable in the tmpfs",
    );
    t.check(
        "fs.dot_dot_clamped",
        fs::lookup(b"/../../etc/./keel-release").is_ok()
            && fs::lookup(b"/../../etc/./keel-release") == fs::lookup(b"/etc/keel-release")
            && fs::lookup(b"/..") == Ok(ROOT),
        "`..` at the root stays at the root (SR-4 groundwork)",
    );
    let nodes_ok = [
        (&b"/dev/console"[..], Device::Console, (5, 1)),
        (b"/dev/null", Device::Null, (1, 3)),
        (b"/dev/zero", Device::Zero, (1, 5)),
        (b"/dev/urandom", Device::Urandom, (1, 9)),
    ]
    .iter()
    .all(|&(path, device, number)| {
        fs::with(|f| {
            let ino = f.lookup(ROOT, ROOT, path)?;
            let stat = f.stat(ino)?;
            Ok(f.kind(ino)? == Kind::Device(device)
                && stat.mode & S_IFMT == S_IFCHR
                && stat.rdev == number)
        })
        .unwrap_or(false)
    });
    t.check(
        "fs.dev_nodes",
        nodes_ok,
        "/dev/console, null, zero and urandom exist with Linux's device numbers",
    );
    t.check(
        "fs.no_forbidden_devices",
        [&b"/dev/mem"[..], b"/dev/kmem", b"/dev/port"]
            .iter()
            .all(|p| fs::lookup(p) == Err(Errno::ENOENT)),
        "no /dev/mem, /dev/kmem or /dev/port (SR-9)",
    );

    let mut zeros = [0xAAu8; 64];
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let devices_ok = fs::device_read(Device::Zero, &mut zeros) == 64
        && zeros == [0; 64]
        && fs::device_read(Device::Null, &mut a) == 0
        && fs::device_read(Device::Urandom, &mut a) == 32
        && fs::device_read(Device::Urandom, &mut b) == 32
        && a != b
        && fs::device_write(Device::Null, b"discarded") == 9
        && fs::device_write(Device::Console, b"") == 0;
    t.check(
        "fs.devices",
        devices_ok,
        "zero reads zeros, null reads end of file, urandom gives fresh bytes, writes are consumed",
    );

    let written = fs::with(|f| {
        let tmp = f.create_dir(ROOT, b"tmp-selftest", 0o755)?;
        let file = f.create_file(tmp, b"note", 0o644)?;
        f.write(file, 0, b"hello")?;
        f.write(file, 5, b", tmpfs")?;
        let mut buf = [0u8; 32];
        let n = f.read(file, 0, &mut buf)?;
        Ok(buf[..n] == *b"hello, tmpfs" && f.stat(file)?.size == 12)
    });
    t.check(
        "fs.tmpfs_write",
        written == Ok(true),
        "files can be created, written and read back",
    );
}

/// Phase 1 acceptance item 1: a C program statically linked against musl
/// (fixtures/musl-hello, built by its pinned recipe) runs as PID 1 and
/// exits 0. Its output, "Hello from musl on Keel", goes to the console;
/// `cargo xtask test` checks it on serial. Runs before any other process
/// is started, so it gets PID 1.
pub fn phase1_musl(t: &mut Runner) {
    const PATH: &[u8] = b"/test/musl-hello";
    let result = keel_linux_abi::fs::read_file(PATH).ok().and_then(|file| {
        let loaded = keel_linux_abi::exec::load(&file, PATH, &[PATH], &[]).ok()?;
        let spawned = keel_linux_abi::process::spawn("musl-hello", &loaded).ok()?;
        join(spawned.thread);
        Some((spawned.pid, sched::exit_status(spawned.thread)?))
    });
    t.check(
        "acceptance.musl_hello_pid1",
        result == Some((1, (0, None))),
        "a static musl C program runs as PID 1 and exits 0 (its line is checked on serial)",
    );
    if let Some((pid, status)) = result
        && (pid != 1 || status != (0, None))
    {
        kprintln!("  musl-hello: pid {pid}, exit {status:?}");
    }

    // Acceptance item 2: a Rust program using the standard library, built
    // for x86_64-unknown-linux-musl, allocates 64 MB on the heap, touches
    // every page and prints a checksum; cargo xtask test checks the line
    // against the one it prints under Linux.
    const HEAP: &[u8] = b"/test/heap64";
    let heap = keel_linux_abi::fs::read_file(HEAP).ok().and_then(|file| {
        let loaded = keel_linux_abi::exec::load(&file, HEAP, &[HEAP], &[]).ok()?;
        let spawned = keel_linux_abi::process::spawn("heap64", &loaded).ok()?;
        join(spawned.thread);
        sched::exit_status(spawned.thread)
    });
    t.check(
        "acceptance.rust_std_heap64",
        heap == Some((0, None)),
        "a Rust std musl program touches 64 MB of heap and exits 0 (its line is checked on serial)",
    );
    if heap != Some((0, None)) {
        kprintln!("  heap64: exit {heap:?}");
    }

    // Acceptance item 3: a null-pointer read in a user program ends that
    // program with a logged #PF at address 0 (cargo xtask test checks the
    // log line), and the kernel carries on.
    let null = run_user_program_with(keel_hal::arch::x86_64::userprog::Program::ReadAddress, 0);
    t.check(
        "acceptance.null_dereference",
        null.is_some_and(|(status, fault, _)| {
            status == 128 + 11 && fault.is_some_and(|f| f.vector == 14 && f.address == 0)
        }),
        "a user null dereference is a logged #PF at 0 that ends only that program (SIGSEGV status)",
    );

    // Acceptance item 4: a program reserves 64 GiB with
    // mmap(PROT_NONE, MAP_NORESERVE); the reservation exists and costs no
    // physical memory. The address space outlives the program because the
    // loader's handle to it is kept here.
    const RESERVE: &[u8] = b"/test/reserve";
    let frames_before = memory::free_frames();
    let reserve = keel_linux_abi::fs::read_file(RESERVE)
        .ok()
        .and_then(|file| {
            let loaded = keel_linux_abi::exec::load(&file, RESERVE, &[RESERVE], &[]).ok()?;
            let spawned = keel_linux_abi::process::spawn("reserve", &loaded).ok()?;
            join(spawned.thread);
            Some((sched::exit_status(spawned.thread)?, loaded.space))
        });
    let reserved = reserve.as_ref().is_some_and(|((status, fault), space)| {
        *status == 0
            && fault.is_none()
            && space.mapped_bytes() >= 64 << 30
            && space.resident_bytes() < 1 << 20
    });
    let used = frames_before.saturating_sub(memory::free_frames());
    t.check(
        "acceptance.reserve_64gib",
        reserved && used < 256,
        "mmap(PROT_NONE, MAP_NORESERVE) of 64 GiB succeeds and uses under 1 MiB of frames",
    );
    if let Some((_, space)) = &reserve {
        kprintln!(
            "  reserve: {} GiB mapped, {} KiB resident, {} frames used meanwhile",
            space.mapped_bytes() >> 30,
            space.resident_bytes() >> 10,
            used
        );
    }
}

/// P1-T11: the initramfs, the ELF loader and the initial process state,
/// checked from inside a real static executable (`user/tests`, built by
/// xtask into the initramfs of test builds).
pub fn phase1_exec(t: &mut Runner) {
    use keel_core::elf::{ElfError, PF_R, PF_W, PF_X, PT_LOAD};
    use keel_linux_abi::exec::{self, LoadError};

    let file = keel_linux_abi::fs::read_file(b"/test/startup");
    t.check(
        "fs.test_program",
        file.is_ok(),
        "test builds carry /test/startup in the root filesystem",
    );
    let Ok(file) = file else {
        return;
    };
    let file: &[u8] = &file;

    const PATH: &[u8] = b"/test/startup";
    let run = |argv: &[&[u8]]| {
        let loaded = exec::load(file, PATH, argv, &[b"KEEL_TEST=1"]).ok()?;
        let spawned = keel_linux_abi::process::spawn("startup", &loaded).ok()?;
        join(spawned.thread);
        Some((sched::exit_status(spawned.thread)?, loaded))
    };
    let passed = run(&[PATH, b"alpha"]);
    t.check(
        "exec.startup_state",
        passed.as_ref().is_some_and(|((status, fault), _)| *status == 0 && fault.is_none()),
        "a static ELF finds argc, argv, envp, auxv, entry registers, data, bss and stack as the psABI defines them",
    );
    if let Some((_, loaded)) = &passed {
        // A CPU with a working RDRAND must not fall back to the weak mix.
        let hardware = keel_hal::random::rdrand_usable() || keel_hal::random::has_rdseed();
        t.check(
            "exec.random_source",
            (loaded.random == keel_hal::random::Quality::Hardware) == hardware,
            if hardware {
                "AT_RANDOM comes from the generator seeded by RDSEED/RDRAND"
            } else {
                "no usable RDSEED/RDRAND: the generator is seeded from timing only"
            },
        );
        // SR-12, SR-14 for a real program: the only kernel pages are the
        // trampoline and nothing is writable and executable.
        let summary = loaded.space.user_view_walk(|_, _| {});
        t.check(
            "exec.user_view",
            summary.writable_and_executable == 0,
            "a loaded program's page tables hold no writable and executable page",
        );
    }
    t.check(
        "exec.exit_status",
        run(&[PATH, b"beta"]).is_some_and(|((status, _), _)| status == 5),
        "a failed check inside the program comes back as its exit status",
    );

    // P1-T13, P1-S1 and security acceptance item 2: the first system
    // calls, rights on handles, and the hostile-pointer sweep, checked by
    // a program that passes the same checks under Linux (`host.syscalls`).
    let syscalls = keel_linux_abi::fs::read_file(b"/test/syscalls")
        .ok()
        .and_then(|file| {
            let loaded = exec::load(&file, b"/test/syscalls", &[b"/test/syscalls"], &[]).ok()?;
            let spawned = keel_linux_abi::process::spawn("syscalls", &loaded).ok()?;
            join(spawned.thread);
            sched::exit_status(spawned.thread)
        });
    t.check(
        "syscalls.conformance",
        syscalls == Some((0, None)),
        "write, writev, read, openat, close, fstat, mmap, mprotect, munmap, brk, arch_prctl, set_tid_address, clock_gettime, getrandom, ioctl, poll, rt_sigaction, rt_sigprocmask, sigaltstack behave as on Linux, and every pointer argument refuses hostile addresses with EFAULT",
    );
    if let Some((status, fault)) = syscalls
        && (status != 0 || fault.is_some())
    {
        kprintln!(
            "  syscalls: exit status {status} (number of the first failed check), fault {fault:?}"
        );
    }
    // P1-T14: the keyboard feeds /dev/console. The program must be blocked
    // in read(2) before anything is typed; then "keel", Enter, Ctrl+D.
    let readline = keel_linux_abi::fs::read_file(b"/test/readline")
        .ok()
        .and_then(|file| {
            let loaded = exec::load(&file, b"/test/readline", &[b"/test/readline"], &[]).ok()?;
            let spawned = keel_linux_abi::process::spawn("readline", &loaded).ok()?;
            sched::sleep_ms(20);
            let was_waiting = sched::exit_status(spawned.thread).is_none();
            // Set 1: k e e l (press, release), Enter, then Ctrl down, D, Ctrl up.
            let keys = [
                0x25, 0xa5, 0x12, 0x92, 0x12, 0x92, 0x26, 0xa6, 0x1c, 0x9c, 0x1d, 0x20, 0xa0, 0x9d,
            ];
            let typed = keel_linux_abi::tty::type_scancodes(&keys).is_ok();
            join(spawned.thread);
            Some((was_waiting, typed, sched::exit_status(spawned.thread)?))
        });
    t.check(
        "console.keyboard_line",
        readline == Some((true, true, (0, None))),
        "a program blocked reading /dev/console gets the typed line, then end of file at Ctrl+D",
    );

    t.check(
        "process.teardown",
        keel_linux_abi::process::count() == 0,
        "every process is gone once its thread has exited",
    );

    // P1-S5 (SR-16): two loads of the same program get different stack
    // tops, mmap bases and program breaks, all inside Linux's ranges.
    let a = exec::load(file, PATH, &[PATH], &[]).ok();
    let b = exec::load(file, PATH, &[PATH], &[]).ok();
    let aslr = a.as_ref().zip(b.as_ref()).is_some_and(|(a, b)| {
        let in_range = |l: &exec::Loaded| {
            l.stack_top <= exec::STACK_TOP
                && exec::STACK_TOP - l.stack_top < exec::STACK_RANDOM_PAGES * 4096
                && l.stack_top.is_multiple_of(4096)
                && l.mmap_top < l.stack_top
        };
        in_range(a)
            && in_range(b)
            && a.stack_top != b.stack_top
            && a.mmap_top != b.mmap_top
            && a.brk_start != b.brk_start
    });
    t.check(
        "aslr.layout_varies",
        aslr,
        "two loads of a program get different stack tops, mmap bases and program breaks (SR-16)",
    );
    drop((a, b));

    // Malformed files are refused before anything runs.
    let mut writable_code = file.to_vec();
    let phoff = u64::from_le_bytes(file[32..40].try_into().unwrap_or_default()) as usize;
    let phnum = usize::from(u16::from_le_bytes([file[56], file[57]]));
    for i in 0..phnum {
        let at = phoff + i * keel_core::elf::PHDR_SIZE;
        let Some(header) = writable_code.get_mut(at..at + 8) else {
            break;
        };
        let p_type = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let flags = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if p_type == PT_LOAD && flags & PF_X != 0 {
            header[4..8].copy_from_slice(&(PF_R | PF_W | PF_X).to_le_bytes());
        }
    }
    let refused = |bytes: &[u8]| exec::load(bytes, PATH, &[PATH], &[]).err();
    t.check(
        "exec.refuses_malformed",
        refused(&file[..100]) == Some(LoadError::Elf(ElfError::Truncated))
            && refused(&writable_code) == Some(LoadError::Elf(ElfError::WritableAndExecutable))
            && refused(b"#!/bin/sh\n") == Some(LoadError::Elf(ElfError::Truncated)),
        "truncated files, writable code segments and non-ELF files are refused (SR-12)",
    );

    // A load that fails after its segments are mapped (arguments too large
    // for the stack) leaves nothing behind.
    let huge = alloc::vec![b'x'; exec::ARG_LIMIT];
    let before = memory::free_frames();
    let too_big = exec::load(file, PATH, &[&huge], &[]).err();
    t.check(
        "exec.failure_cleans_up",
        too_big == Some(LoadError::Stack(keel_core::exec::ExecError::TooLarge))
            && memory::free_frames() + 8 >= before,
        "a load that fails half-way returns every frame it took",
    );
}

/// F-0002 and SR-15 (L1TF): PROT_NONE takes populated pages out of the
/// page tables entirely; the data comes back when the protection is
/// raised, survives fork, and every frame is returned at the end. No
/// page table anywhere holds a not-present entry with bits set.
pub fn phase1_prot_none(t: &mut Runner) {
    use keel_core::vm::{Placement, Prot};
    use keel_hal::vm::{AddressSpace, copy_from_user, copy_to_user, with_address_space};
    const AT: u64 = 0x5000_0000;
    const LEN: u64 = 4 * 4096;

    let frames_at_start = memory::free_frames();
    let ok = (|| {
        let space = AddressSpace::new().ok()?;
        space
            .map(Placement::Fixed(AT), LEN, Prot::READ_WRITE)
            .ok()?;
        let pattern: alloc::vec::Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
        with_address_space(&space, || copy_to_user(AT, &pattern)).ok()?;
        space.protect(AT, LEN, Prot::NONE).ok()?;
        let mut probe = [0u8; 8];
        let hidden = space.page_flags(AT).is_none()
            && with_address_space(&space, || copy_from_user(&mut probe, AT).is_err())
            && space.resident_bytes() == LEN;
        let clean = space.user_view_walk(|_, _| {}).nonpresent_nonzero == 0;
        // fork while parked: both sides get the data back, independently.
        let child = space.duplicate().ok()?;
        space.protect(AT, LEN, Prot::READ_WRITE).ok()?;
        child.protect(AT, LEN, Prot::READ_WRITE).ok()?;
        let mut back = alloc::vec![0u8; LEN as usize];
        let parent_ok =
            with_address_space(&space, || copy_from_user(&mut back, AT)).is_ok() && back == pattern;
        with_address_space(&space, || copy_to_user(AT, &[0xEE; 16])).ok()?;
        let child_ok =
            with_address_space(&child, || copy_from_user(&mut back, AT)).is_ok() && back == pattern;
        Some(hidden && clean && parent_ok && child_ok)
    })();
    t.check(
        "vm.prot_none_hides_pages",
        ok == Some(true),
        "PROT_NONE pages are unreadable, keep their data, and come back after mprotect and fork (F-0002)",
    );
    // F-0003 regression: a context switch inside with_address_space must
    // not undo the switch (it used to put the kernel thread back on the
    // kernel's tables, so the user copy after the sleep found no page).
    let survives = (|| {
        let space = AddressSpace::new().ok()?;
        space
            .map(Placement::Fixed(AT), 4096, Prot::READ_WRITE)
            .ok()?;
        Some(with_address_space(&space, || {
            let written = copy_to_user(AT, b"survives").is_ok();
            sched::sleep_ms(5);
            sched::yield_now();
            let mut back = [0u8; 8];
            written && copy_from_user(&mut back, AT).is_ok() && back == *b"survives"
        }))
    })();
    t.check(
        "vm.borrowed_space_survives_switch",
        survives == Some(true),
        "a thread working in another address space keeps it across a context switch (F-0003)",
    );
    t.check(
        "vm.prot_none_frames_returned",
        memory::free_frames() + 8 >= frames_at_start,
        "parked frames are freed with their address space",
    );
    t.check(
        "l1tf.no_stale_entries",
        paging::walk().is_some_and(|w| w.nonpresent_nonzero == 0),
        "no not-present page-table entry in the kernel's tables holds any bits (L1TF)",
    );
}

/// P1-S4: the vulnerability report covers every item, the chosen plan is
/// what the entry code uses, and the exit path with VERW still returns to
/// user mode correctly. (IBRS and IBPB need a CPU that has them: QEMU's
/// emulator does not, so CI checks them under KVM.)
pub fn phase1_mitigations(t: &mut Runner) {
    use keel_hal::arch::x86_64::entry;
    let info = keel_hal::mitigations::cpu_info();
    let (plan, items) = keel_core::cpuvuln::assess(&info);
    let names = [
        "Meltdown",
        "Spectre v1",
        "Spectre v2",
        "Retbleed",
        "Spectre v2 between processes",
        "SpectreRSB",
        "BHI",
        "Speculative Store Bypass",
        "L1TF",
        "MDS",
        "TAA",
        "MMIO stale data",
        "SRBDS",
        "GDS",
        "ITS",
        "RFDS",
        "SMT",
    ];
    t.check(
        "vuln.report_complete",
        names.iter().all(|n| items.iter().any(|i| i.name == *n)),
        "the boot report has a line for every item SR-15 and Linux's hw-vuln list name",
    );
    let (verw, ibrs, kernel, _) = entry::mitigations();
    let spec_ctrl_ok =
        !plan.spec_ctrl || keel_hal::mitigations::spec_ctrl_now() == Some(plan.spec_ctrl_kernel);
    t.check(
        "vuln.plan_applied",
        verw == plan.verw_on_exit
            && ibrs == plan.ibrs_on_entry
            && kernel == plan.spec_ctrl_kernel
            && spec_ctrl_ok,
        "the entry code uses the chosen mitigations, and IA32_SPEC_CTRL holds the kernel value",
    );
    // The #GP fixup behind rdmsr_safe/wrmsr_safe: an MSR index in an
    // unassigned range (0xC000_2000; Intel and AMD define nothing there)
    // must fault and come back as an error, not as a kernel crash.
    // rdmsr_safe reads what the plain RDMSR reads, and survives an MSR
    // that does not exist. 0xC000_2000 is in a range Intel and AMD leave
    // unassigned: real CPUs and KVM raise #GP there (the fixup turns it
    // into None); QEMU's emulator (TCG) returns 0 for any unknown MSR
    // without faulting (target/i386/tcg/sysemu/misc_helper.c, "XXX:
    // exception?"), which only a virtualized CPU may show.
    use keel_hal::arch::x86_64::cpu as hw_cpu;
    let efer_ok = hw_cpu::rdmsr_safe(hw_cpu::IA32_EFER) == Some(hw_cpu::read_efer());
    let missing = hw_cpu::rdmsr_safe(0xC000_2000);
    t.check(
        "cpu.msr_safe",
        efer_ok && (missing.is_none() || (info.hypervisor && missing == Some(0))),
        if missing.is_none() {
            "rdmsr_safe matches RDMSR; a missing MSR faulted and was caught"
        } else {
            "rdmsr_safe matches RDMSR; this emulator reads missing MSRs as 0 (fault path checked under KVM)"
        },
    );
    // Force VERW on for one user program, whatever the CPU, so the exit
    // path with VERW is exercised on every test run.
    let before = entry::mitigations();
    entry::set_mitigations(true, before.1, before.2, before.3);
    let file = keel_linux_abi::fs::read_file(b"/test/startup").ok();
    let status = file.and_then(|file| {
        let path: &[u8] = b"/test/startup";
        let loaded =
            keel_linux_abi::exec::load(&file, path, &[path, b"alpha"], &[b"KEEL_TEST=1"]).ok()?;
        let spawned = keel_linux_abi::process::spawn("verw", &loaded).ok()?;
        join(spawned.thread);
        sched::exit_status(spawned.thread)
    });
    entry::set_mitigations(before.0, before.1, before.2, before.3);
    t.check(
        "vuln.verw_exit_path",
        status == Some((0, None)),
        "with VERW on, a user program enters and leaves the kernel normally",
    );

    // The legacy-IBRS entry/exit code and IBPB on switch, forced on where
    // IA32_SPEC_CTRL and IA32_PRED_CMD accept writes. On a CPU that has
    // them this is the real mitigation; QEMU's emulator accepts and
    // ignores the writes, which still runs every instruction of the entry
    // and exit paths. Where the writes are refused (a virtual CPU without
    // them) the paths cannot run at all, and the check says so.
    let value = keel_hal::mitigations::spec_ctrl_now().unwrap_or(0);
    let writable = keel_hal::mitigations::speculation_msrs_writable();
    let forced = writable.then(|| {
        entry::set_mitigations(before.0, true, value, value);
        sched::set_ibpb_on_switch(true);
        let status = keel_linux_abi::fs::read_file(b"/test/syscalls")
            .ok()
            .and_then(|file| {
                let path: &[u8] = b"/test/syscalls";
                // A file name of its own: the first run created the default.
                let argv: &[&[u8]] = &[path, b"/syscalls-test-file-ibrs"];
                let loaded = keel_linux_abi::exec::load(&file, path, argv, &[]).ok()?;
                let spawned = keel_linux_abi::process::spawn("ibrs", &loaded).ok()?;
                join(spawned.thread);
                sched::exit_status(spawned.thread)
            });
        entry::set_mitigations(before.0, before.1, before.2, before.3);
        sched::set_ibpb_on_switch(plan.ibpb_on_switch);
        status
    });
    t.check(
        "vuln.ibrs_entry_path",
        forced.is_none_or(|status| status == Some((0, None))),
        if forced.is_some() {
            "with IBRS writes on every entry and exit, and IBPB on switch, the syscall conformance program passes"
        } else {
            "skipped: this CPU refuses IA32_SPEC_CTRL/IA32_PRED_CMD writes, so the paths cannot run here"
        },
    );
}

/// Waits for a test thread, at most 15 s. A thread that hangs is named on
/// the console and the check waiting on it fails, instead of the whole
/// run timing out with no clue where.
fn join(id: sched::ThreadId) {
    if !sched::join_timeout(id, 15_000) {
        kprintln!(
            "selftest: thread {} ({}) did not finish within 15 s",
            id.0,
            sched::thread_name(id).unwrap_or("?")
        );
    }
}

/// Loads a test program into a fresh address space and runs it as a user
/// thread to completion. Returns its exit status and last user fault.
fn run_user_program(
    program: keel_hal::arch::x86_64::userprog::Program,
) -> Option<(
    i64,
    Option<sched::UserFault>,
    alloc::sync::Arc<keel_hal::vm::AddressSpace>,
)> {
    run_user_program_with(program, 0)
}

/// As `run_user_program`, with `argument` in RDI.
fn run_user_program_with(
    program: keel_hal::arch::x86_64::userprog::Program,
    argument: u64,
) -> Option<(
    i64,
    Option<sched::UserFault>,
    alloc::sync::Arc<keel_hal::vm::AddressSpace>,
)> {
    use keel_core::vm::{Placement, Prot};
    use keel_hal::vm::{AddressSpace, copy_to_user, with_address_space};
    const CODE: u64 = 0x40_0000;
    const STACK_TOP: u64 = 0x7000_0000_0000;
    const STACK_SIZE: u64 = 16 * 1024;
    let space = AddressSpace::new().ok()?;
    space
        .map(Placement::Fixed(CODE), 4096, Prot::READ_WRITE)
        .ok()?;
    with_address_space(&space, || copy_to_user(CODE, program.code())).ok()?;
    space
        .protect(
            CODE,
            4096,
            Prot {
                read: true,
                write: false,
                exec: true,
            },
        )
        .ok()?;
    space
        .map(
            Placement::Fixed(STACK_TOP - STACK_SIZE),
            STACK_SIZE,
            Prot::READ_WRITE,
        )
        .ok()?;
    let id = sched::spawn_user("user-test", space.clone(), CODE, STACK_TOP, argument).ok()?;
    join(id);
    let (status, fault) = sched::exit_status(id)?;
    Some((status, fault, space))
}

/// P1-T10, P1-S3 and P1 security acceptance: user mode, system calls,
/// privilege boundaries, and page-table isolation.
pub fn phase1_user(t: &mut Runner) {
    use idt::page_fault::{INSTRUCTION_FETCH, PRESENT, USER, WRITE};
    use keel_hal::arch::x86_64::userprog::Program;

    let add = run_user_program(Program::SyscallResult);
    t.check(
        "user.syscall",
        add.as_ref()
            .is_some_and(|(status, fault, _)| *status == 42 && fault.is_none()),
        "a user program got a system call's result in rax and exited with status 42",
    );
    let regs = run_user_program(Program::Registers);
    t.check(
        "user.syscall_registers",
        regs.as_ref().is_some_and(|(status, ..)| *status == 0),
        "rbx, rbp and r12-r15 survive a system call and the result is in rax",
    );
    let enosys = run_user_program(Program::UnknownSyscall);
    t.check(
        "user.unknown_syscall",
        enosys.as_ref().is_some_and(|(status, ..)| *status == 38),
        "an unknown system call number returns -ENOSYS (SR-10)",
    );

    let gp = |program| {
        run_user_program(program).is_some_and(|(status, fault, _)| {
            status == 128 + 11 && fault.is_some_and(|f| f.vector == 13)
        })
    };
    t.check(
        "user.no_cli",
        gp(Program::Cli),
        "CLI in user mode raises #GP and ends only that thread",
    );
    t.check(
        "user.no_port_io",
        gp(Program::PortIo),
        "port I/O from user mode raises #GP (SR-9)",
    );

    // Page-table isolation: the kernel is not merely protected but absent
    // from the user view, so the fault reports a non-present page.
    let absent = |address: u64| {
        run_user_program_with(Program::ReadAddress, address).is_some_and(|(_, fault, _)| {
            fault.is_some_and(|f| {
                f.vector == 14 && f.error_code & (PRESENT | USER) == USER && f.address == address
            })
        })
    };
    // Kernel text just past the trampoline, kernel rodata, kernel data,
    // the direct map, and the kernel heap.
    // Moves a probe past any page the trampoline maps; those pages are
    // meant to be present in the user view.
    let off_trampoline = |mut address: u64| {
        for (start, end, _) in paging::trampoline_ranges() {
            if address < end.next_multiple_of(4096) && address >= start & !0xfff {
                address = end.next_multiple_of(4096);
            }
        }
        address
    };
    let [text, rodata, data, _] = paging::kernel_segments();
    let heap_object = alloc::boxed::Box::new(0u64);
    let probes = [
        off_trampoline(text),
        off_trampoline(rodata),
        off_trampoline(data),
        boot::hhdm_offset().unwrap_or(0) + 0x1000,
        &raw const *heap_object as u64,
    ];
    t.check(
        "pti.kernel_absent",
        probes.iter().all(|&address| absent(address)),
        "user reads of kernel text, rodata, data, the direct map and the heap find no page (SR-14)",
    );

    let write_code = run_user_program(Program::WriteCode);
    t.check(
        "user.code_read_only",
        write_code.as_ref().is_some_and(|(_, fault, _)| {
            fault.is_some_and(|f| {
                f.vector == 14 && f.error_code & (PRESENT | WRITE | USER) == PRESENT | WRITE | USER
            })
        }),
        "a user program writing its own code page faults (SR-12)",
    );
    let exec_stack = run_user_program(Program::ExecStack);
    t.check(
        "user.stack_no_execute",
        exec_stack.as_ref().is_some_and(|(_, fault, _)| {
            fault.is_some_and(|f| f.vector == 14 && f.error_code & INSTRUCTION_FETCH != 0)
        }),
        "a user program executing from its stack faults (SR-12)",
    );

    let umip = cpu::features().umip;
    let sgdt = run_user_program(Program::Sgdt);
    t.check(
        "user.umip",
        sgdt.as_ref().is_some_and(|(status, fault, _)| {
            if umip {
                fault.is_some_and(|f| f.vector == 13)
            } else {
                *status == 0
            }
        }),
        "SGDT in user mode faults when the CPU has UMIP, and runs otherwise",
    );

    // A user thread that sets RFLAGS.AC must not switch SMAP off for the
    // kernel code that handles its interrupts and exceptions (SR-13).
    let ac = cpu::RFLAGS_AC;
    t.check(
        "user.ac_cleared_on_entry",
        run_user_program(Program::SetAc).is_some_and(|(_, fault, _)| {
            fault.is_some_and(|f| {
                f.vector == 6 && f.user_rflags & ac != 0 && f.handler_rflags & ac == 0
            })
        }),
        "a fault from user code with AC set is handled with AC clear",
    );

    // The user view of an address space maps nothing of the kernel but the
    // entry trampoline, and nothing in it is writable and executable.
    let user_view_ok = add.as_ref().is_some_and(|(_, _, space)| {
        let ranges = paging::trampoline_ranges();
        let mut only_trampoline = true;
        let summary = space.user_view_walk(|virt, tr| {
            if virt >= 0xffff_8000_0000_0000 {
                let in_trampoline = ranges
                    .iter()
                    .any(|&(start, end, _)| (start..end).contains(&virt));
                only_trampoline &= in_trampoline && !tr.flags.user;
            }
        });
        only_trampoline && summary.writable_and_executable == 0 && summary.nonpresent_nonzero == 0
    });
    t.check(
        "pti.user_view",
        user_view_ok,
        "a user address space maps only the entry trampoline of the kernel, and no W+X page (SR-12, SR-14)",
    );
    t.check(
        "user.kernel_survives",
        sched::thread_count() >= 2,
        "the kernel kept running after every user fault",
    );
}
