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
use keel_hal::{console, interrupts, kprintln, kresult, memory, sched, time};

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

/// `fuzz=<minutes> seed=<n>` on the command line: a fuzzing session
/// instead of the phase tests (`cargo xtask fuzz`).
pub fn requested_fuzz(cmdline: &str) -> Option<(u64, u64)> {
    let value = |key: &str| {
        cmdline
            .split_ascii_whitespace()
            .find_map(|word| word.strip_prefix(key))
            .and_then(|v| v.parse::<u64>().ok())
    };
    Some((value("fuzz=")?, value("seed=").unwrap_or(0)))
}

/// `stress=<minutes> seed=<n>` on the command line: a fork, thread and
/// signal stress session instead of the phase tests (`cargo xtask
/// stress`, Phase 3 acceptance item 4).
pub fn requested_stress(cmdline: &str) -> Option<(u64, u64)> {
    let value = |key: &str| {
        cmdline
            .split_ascii_whitespace()
            .find_map(|word| word.strip_prefix(key))
            .and_then(|v| v.parse::<u64>().ok())
    };
    Some((value("stress=")?, value("seed=").unwrap_or(0)))
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
    FaultInPanic = 6,
    /// Phase 3: BusyBox's own test suite (ADR 0034).
    BusyboxSuite = 7,
    /// Phase 3: the conformance programs, each in a compartment, their
    /// output for xtask to compare with Linux's (ADR 0039).
    Conformance = 8,
    Unknown = 255,
}

/// Extracts the scenario from a `scenario=<name>` word on the command line.
///
/// Scenarios are compiled into release kernels and chosen only by the
/// command line, which comes from `limine.conf`. That file's hash is
/// enrolled in `BOOTX64.EFI` (ADR 0010), so the command line is exactly as
/// trustworthy as the bootloader executable: someone who can replace that
/// can replace the kernel too. Until it is signed and Secure Boot is on,
/// that is anyone who can write the boot disk.
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
        Some("fault_in_panic") => Scenario::FaultInPanic,
        Some("busybox_testsuite") => Scenario::BusyboxSuite,
        Some("conformance") => Scenario::Conformance,
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
        console::emergency_result(format_args!(
            "TEST {name} PASS {detail}\nTEST SUMMARY passed=1 failed=0\n"
        ));
        exit_qemu(ExitCode::Success);
    }
}

/// The `fault_in_panic` scenario's second step: called by the panic
/// handler after its first message, it faults (a write to kernel text,
/// #PF), so the fatal path and the panic handler are entered again.
pub fn fault_in_panic_if_requested() {
    if ACTIVE_SCENARIO.load(Ordering::Relaxed) == Scenario::FaultInPanic as u8 {
        hw::write_to_kernel_text();
    }
}

/// Judges `fault_in_panic` on the nested entry to the panic handler: it
/// passes if that entry came from the deliberate #PF and was reached at
/// all (without the guards the kernel faults and prints forever). Uses
/// only fixed strings: formatting is not trusted here.
pub fn judge_nested_panic() {
    if ACTIVE_SCENARIO.load(Ordering::Relaxed) != Scenario::FaultInPanic as u8 {
        return;
    }
    if idt::last_fatal_exception().is_some_and(|f| f.vector == 14) {
        console::emergency_result_serial(
            "TEST panic.nested_fault_halts PASS a fault inside the panic handler ends in one short message and a halt\nTEST SUMMARY passed=1 failed=0\n",
        );
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
            kresult!("TEST {name} PASS {detail}");
        } else {
            self.failed += 1;
            kresult!("TEST {name} FAIL {detail}");
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
        (2, Scenario::None) => phase2(&mut runner),
        (3, Scenario::None) => phase3(&mut runner),
        (3, Scenario::BusyboxSuite) => phase3_busybox_suite(&mut runner),
        (3, Scenario::Conformance) => phase3_conformance(&mut runner),
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
        (1, Scenario::FaultInPanic) => {
            ACTIVE_SCENARIO.store(Scenario::FaultInPanic as u8, Ordering::Relaxed);
            kprintln!("selftest: panicking, then faulting inside the panic handler");
            panic!("deliberate panic for the fault_in_panic scenario");
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
    kresult!(
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
    kresult!("{MARKER}");
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
    phase1_rights(t);
    phase1_exec(t);
    phase1_mitigations(t);
    phase1_robustness(t);
    phase1_resource_limits(t);
    phase1_audit_small_items(t);
    phase1_fuzz_smoke(t);

    // Phase 1 acceptance marker, printed only when every test above
    // passed (the four acceptance items are among them). `cargo xtask
    // test` also checks the acceptance programs' own serial lines.
    if t.failed == 0 {
        kresult!("KEEL P1 OK");
    }
}

/// P1-T3 and SR-18: frames come out distinct, page-aligned, inside usable
/// memory and zero-filled, even after a previous owner dirtied them; and
/// freeing returns the allocator to its starting count.
pub fn phase1_frames(t: &mut Runner) {
    use alloc::vec::Vec;
    use keel_hal::memory::OwnedFrame;
    const COUNT: usize = 64;
    // Every vector is allocated at full size before the baseline: a heap
    // allocation in between could take a frame for the heap and throw the
    // count off by one (it did, once the heap had no spare room).
    let mut frames: Vec<OwnedFrame> = Vec::with_capacity(COUNT);
    let mut addresses: Vec<u64> = Vec::with_capacity(COUNT);
    let mut again: Vec<OwnedFrame> = Vec::with_capacity(COUNT);
    let baseline = memory::free_frames();
    frames.extend((0..COUNT).filter_map(|_| OwnedFrame::allocate()));
    let all = frames.len() == COUNT;
    addresses.extend(frames.iter().map(OwnedFrame::address));

    let mut distinct = all;
    for (i, a) in addresses.iter().enumerate() {
        distinct &= addresses[i + 1..].iter().all(|b| a != b);
    }
    let in_usable = addresses.iter().all(|&address| {
        address != 0
            && address % 4096 == 0
            && boot::memory_map().any(|r| {
                r.kind == RegionKind::Usable && r.base <= address && address < r.base + r.length
            })
    });
    t.check(
        "frames.allocate",
        all && distinct && in_usable && memory::free_frames() == baseline - COUNT,
        "64 frames are distinct, aligned, in usable RAM, and counted",
    );

    let zeroed = frames.iter().all(|f| f.bytes().iter().all(|&b| b == 0));
    // Dirty every frame, free it (by dropping it), and allocate again: the
    // allocator hands frames back out, and each must arrive zeroed (SR-18).
    for frame in frames.iter_mut() {
        frame.bytes_mut().fill(0xA5);
    }
    frames.clear();
    again.extend((0..COUNT).filter_map(|_| OwnedFrame::allocate()));
    let reused_zeroed =
        again.len() == COUNT && again.iter().all(|f| f.bytes().iter().all(|&b| b == 0));
    let reused = again
        .iter()
        .filter(|f| addresses.contains(&f.address()))
        .count();
    t.check(
        "frames.zeroed",
        zeroed && reused_zeroed && reused > 0,
        "new frames read as zero, including frames a previous owner filled (SR-18)",
    );

    again.clear();
    // A freed frame can be neither freed again nor read: outside keel-hal
    // that is the type system (an `OwnedFrame` is consumed when freed and
    // cannot be copied or made from an address; audit finding 1); inside,
    // the raw operations refuse a stale frame.
    t.check(
        "frames.release",
        memory::free_frames() == baseline && memory::stale_frame_refused(),
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
        && paging::kernel_heap_region().contains(&start);
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
    let devices_ok = fs::device_read(Device::Zero, &mut zeros) == Ok(64)
        && zeros == [0; 64]
        && fs::device_read(Device::Null, &mut a) == Ok(0)
        && fs::device_read(Device::Urandom, &mut a) == Ok(32)
        && fs::device_read(Device::Urandom, &mut b) == Ok(32)
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

/// System calls per fuzz run (`user/tests/fuzz`). A run ends when they
/// are made, or earlier if the program kills itself (by unmapping its own
/// code, say); either way a new run starts with the next seed.
const FUZZ_CALLS: u64 = 2_000;
/// A fuzz run that has not ended by then counts as a hang: Keel has no
/// way to stop a thread yet, and the fuzzer avoids every call that can
/// wait for long, so a hang is a kernel bug to investigate. Generous,
/// because a single legitimate call can move 2 GiB (MAX_RW_COUNT), which
/// takes over a minute without hardware acceleration.
const FUZZ_RUN_LIMIT_MS: u64 = 600_000;
/// The harness wakes every second while a run goes on. If it is ever kept
/// from running for longer than this, the kernel failed to preempt the
/// fuzz process (as before system calls became preemptible).
const FUZZ_MAX_WAKE_MS: u64 = 5_000;

/// What a fuzzing session did.
struct FuzzReport {
    runs: u64,
    calls: u64,
    /// Runs the kernel ended with a user fault (the fuzzer harmed itself).
    faulted: u64,
    /// Seed of a run that did not end in time.
    hung: Option<u64>,
    /// Longest the harness thread waited past its one-second wake-up.
    worst_wake_ms: u64,
}

/// Runs fuzz processes one after another, run `i` with seed `seed + i`,
/// until `deadline_ns` (monotonic) or `max_runs`. Each seed is logged
/// before its run, so the last one in the log is the one to replay.
fn fuzz_session(
    seed: u64,
    deadline_ns: u64,
    max_runs: u64,
    calls_per_run: u64,
    verbose: bool,
) -> FuzzReport {
    use alloc::format;
    const PATH: &[u8] = b"/test/fuzz";
    let mut report = FuzzReport {
        runs: 0,
        calls: 0,
        faulted: 0,
        hung: None,
        worst_wake_ms: 0,
    };
    let Ok(file) = keel_linux_abi::fs::read_file(PATH) else {
        kprintln!(
            "fuzz: {} missing",
            core::str::from_utf8(PATH).unwrap_or("?")
        );
        return report;
    };
    let calls_before = keel_linux_abi::syscall::count();
    let calls = format!("{calls_per_run}");
    let start = time::monotonic_nanos();
    let mut next_report = start + 60_000_000_000;
    while report.runs < max_runs && time::monotonic_nanos() < deadline_ns {
        let run_seed = seed.wrapping_add(report.runs);
        let seed_text = format!("{run_seed}");
        let args: [&[u8]; 3] = [PATH, seed_text.as_bytes(), calls.as_bytes()];
        if verbose {
            kprintln!(
                "fuzz: run {} seed {run_seed}, {} free frames, heap {} pages, {} address spaces, {} kernel table frames",
                report.runs,
                memory::free_frames(),
                keel_hal::heap::mapped_pages(),
                keel_hal::vm::live_address_spaces(),
                paging::kernel_table_frames()
            );
        }
        let spawned = keel_linux_abi::exec::load(&file, PATH, &args, &[])
            .ok()
            .and_then(|loaded| keel_linux_abi::process::spawn("fuzz", &loaded).ok());
        let Some(spawned) = spawned else {
            kprintln!(
                "fuzz: could not start run {} (seed {run_seed})",
                report.runs
            );
            report.hung = Some(run_seed);
            break;
        };
        let run_start = time::monotonic_nanos();
        let mut last_wake = run_start;
        let ended = loop {
            let ended = sched::join_timeout(spawned.thread, 1000);
            let now = time::monotonic_nanos();
            let late_ms = (now - last_wake).saturating_sub(1_000_000_000) / 1_000_000;
            report.worst_wake_ms = report.worst_wake_ms.max(late_ms);
            last_wake = now;
            if verbose && now >= next_report {
                next_report = now + 60_000_000_000;
                kprintln!(
                    "fuzz: {} min: {} runs done, {} system calls, {} free frames, worst wake-up delay {} ms",
                    (now - start) / 60_000_000_000,
                    report.runs,
                    keel_linux_abi::syscall::count() - calls_before,
                    memory::free_frames(),
                    report.worst_wake_ms
                );
            }
            if ended {
                break true;
            }
            if now - run_start > FUZZ_RUN_LIMIT_MS * 1_000_000 {
                break false;
            }
        };
        if !ended {
            kprintln!(
                "fuzz: run {} (seed {run_seed}) did not end within {} s",
                report.runs,
                FUZZ_RUN_LIMIT_MS / 1000
            );
            report.hung = Some(run_seed);
            break;
        }
        if let Some((_, Some(_))) = sched::exit_status(spawned.thread) {
            report.faulted += 1;
        }
        report.runs += 1;
    }
    report.calls = keel_linux_abi::syscall::count() - calls_before;
    report
}

/// The fuzzing boot (`cargo xtask fuzz`): `minutes` of runs from `seed`.
/// Security acceptance P1 item 6 is a 60-minute session that passes.
pub fn run_fuzz(minutes: u64, seed: u64) -> bool {
    let mut runner = Runner {
        passed: 0,
        failed: 0,
    };
    kprintln!("fuzz: {minutes} min from seed {seed}, {FUZZ_CALLS} calls per run");
    keel_linux_abi::syscall::set_slow_log(true);
    let frames_before = memory::free_frames();
    let tmpfs_before = keel_linux_abi::fs::usage();
    let start = time::monotonic_nanos();
    let deadline = start.saturating_add(minutes.saturating_mul(60_000_000_000));
    let report = fuzz_session(seed, deadline, u64::MAX, FUZZ_CALLS, true);
    let elapsed_s = (time::monotonic_nanos() - start) / 1_000_000_000;
    kprintln!(
        "fuzz: done: {} runs, {} system calls, {} runs ended by a fault, {} s, worst harness wake-up delay {} ms, free frames {} -> {}",
        report.runs,
        report.calls,
        report.faulted,
        elapsed_s,
        report.worst_wake_ms,
        frames_before,
        memory::free_frames()
    );
    // Frames still in use afterwards should be what the fuzzer left in
    // the tmpfs (file data and nodes live on the kernel heap).
    let tmpfs_after = keel_linux_abi::fs::usage();
    let (heap_used, heap_lost) = keel_hal::heap::address_space_usage();
    kprintln!(
        "fuzz: tmpfs grew by {} bytes of file data and {} nodes; heap address space {} KiB, {heap_lost} pages not reusable",
        tmpfs_after.0 - tmpfs_before.0,
        tmpfs_after.1 - tmpfs_before.1,
        heap_used / 1024
    );
    runner.check(
        "fuzz.syscalls",
        report.hung.is_none() && report.runs > 0 && report.worst_wake_ms <= FUZZ_MAX_WAKE_MS,
        "random system calls from user programs: no kernel panic, no hung run, and the kernel stays responsive, for the whole session",
    );
    kresult!(
        "TEST SUMMARY passed={} failed={}",
        runner.passed,
        runner.failed
    );
    runner.failed == 0
}

/// Regression tests for what the fuzzer found (F-0005 to F-0008).
pub fn phase1_robustness(t: &mut Runner) {
    use keel_core::vm::{Placement, Prot};
    use keel_hal::vm::AddressSpace;

    // F-0005: distinct unknown numbers outside the table do not each add
    // a log line (nor kernel memory).
    let before = keel_linux_abi::syscall::unimplemented_lines();
    for number in 0..1000u64 {
        let call = keel_hal::syscall::SyscallArgs {
            number: 0x1_0000_0000 + number * 7919,
            args: [0; 6],
            user_rsp: 0,
            frame: keel_hal::arch::x86_64::idt::TrapFrame::default(),
        };
        let _ = keel_linux_abi::syscall::handle(&call);
    }
    let added = keel_linux_abi::syscall::unimplemented_lines() - before;
    t.check(
        "syscall.log_bounded",
        added <= 1,
        "1000 distinct unknown numbers outside the table add at most one log line (F-0005)",
    );

    // F-0006: protecting and unmapping a 64 TiB reservation costs time in
    // proportion to the pages present (none), not to its length.
    let huge = AddressSpace::new().ok().and_then(|space| {
        let start = space
            .map(Placement::Anywhere { hint: 0 }, 1 << 46, Prot::NONE)
            .ok()?;
        let begin = time::monotonic_nanos();
        space.protect(start, 1 << 46, Prot::READ_WRITE).ok()?;
        space.protect(start, 1 << 46, Prot::NONE).ok()?;
        space.unmap(start, 1 << 46).ok()?;
        Some((time::monotonic_nanos() - begin) / 1_000_000)
    });
    t.check(
        "vm.huge_range_fast",
        huge.is_some_and(|ms| ms < 2000),
        "mprotect twice and munmap of an empty 64 TiB reservation take under 2 s (F-0006)",
    );
    if let Some(ms) = huge {
        kprintln!("  64 TiB mprotect/mprotect/munmap: {ms} ms");
    }

    // F-0009: freed large heap allocations give their address space back.
    // 100,000 page-sized buffers allocated and freed one after another (as
    // read(2) does per call) must not move the heap's high-water mark; the
    // old bump pointer used 8 KiB per buffer, 800 MB here.
    let (used_before, _) = keel_hal::heap::address_space_usage();
    for i in 0..100_000u32 {
        let buffer = alloc::vec![0u8; 4096];
        core::hint::black_box(&buffer);
        let _ = i;
    }
    let (used_after, lost) = keel_hal::heap::address_space_usage();
    t.check(
        "heap.va_reused",
        used_after <= used_before + 64 * 1024,
        "100,000 page-sized allocations, each freed, do not grow the heap's address space (F-0009)",
    );
    kprintln!(
        "  heap address space: {} KiB before, {} KiB after, {lost} pages not reusable",
        used_before / 1024,
        used_after / 1024
    );

    // F-0009 also applied to kernel stacks: 300 threads started and
    // finished one after another reuse the same stack address space (the
    // old bump pointer used 68 KiB per thread, 20 MB here).
    let stacks_before = paging::kernel_stack_space_used();
    let mut started = 0;
    for _ in 0..300 {
        if let Ok(id) = sched::spawn("stack-reuse", || {}) {
            join(id);
            started += 1;
        }
    }
    // Exited threads are reclaimed shortly after; let that happen.
    sched::sleep_ms(50);
    let stacks_after = paging::kernel_stack_space_used();
    t.check(
        "sched.stack_va_reused",
        started == 300 && stacks_after - stacks_before <= 1 << 20,
        "300 threads, one after another, reuse kernel stack address space (F-0009)",
    );
    kprintln!(
        "  kernel stack space: {} KiB before, {} KiB after 300 threads",
        stacks_before / 1024,
        stacks_after / 1024
    );

    // F-0007: user page faults never take the kernel's reserve.
    let old = memory::set_user_reserve(memory::free_frames() + 16);
    let user = memory::OwnedFrame::allocate_user();
    let kernel = memory::OwnedFrame::allocate();
    memory::set_user_reserve(old);
    let refused = user.is_none() && kernel.is_some();
    drop((user, kernel));
    t.check(
        "memory.user_reserve",
        refused,
        "a user page is refused once only the kernel reserve is free; the kernel still gets frames (F-0007)",
    );

    // F-0008: a long system call is preempted. A kernel thread counting
    // 5 ms sleeps keeps running while `user/tests/longcall` spends
    // seconds (without acceleration) in one 128 MiB getrandom.
    static TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    static STOP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    STOP.store(false, Ordering::Relaxed);
    let ticker = sched::spawn("ticker", || {
        while !STOP.load(Ordering::Relaxed) {
            sched::sleep_ms(5);
            TICKS.fetch_add(1, Ordering::Relaxed);
        }
    });
    const PATH: &[u8] = b"/test/longcall";
    let ticks_before = TICKS.load(Ordering::Relaxed);
    let draws_before = keel_hal::random::draws();
    let begin = time::monotonic_nanos();
    let status = keel_linux_abi::fs::read_file(PATH).ok().and_then(|file| {
        let loaded = keel_linux_abi::exec::load(&file, PATH, &[PATH], &[]).ok()?;
        let spawned = keel_linux_abi::process::spawn("longcall", &loaded).ok()?;
        join(spawned.thread);
        sched::exit_status(spawned.thread)
    });
    let elapsed_ms = (time::monotonic_nanos() - begin) / 1_000_000;
    let ticks = TICKS.load(Ordering::Relaxed) - ticks_before;
    let draws = keel_hal::random::draws() - draws_before;
    STOP.store(true, Ordering::Relaxed);
    if let Ok(id) = ticker {
        join(id);
    }
    // At least one tick per 50 ms of the call, on average (a 5 ms sleep
    // with 10 ms time slices); without preemption there is about one.
    t.check(
        "sched.syscall_preemptible",
        status == Some((0, None)) && ticker.is_ok() && ticks >= (elapsed_ms / 50).max(1),
        "a kernel thread keeps running while a user program is inside one long system call (F-0008)",
    );
    kprintln!("  longcall: {elapsed_ms} ms, ticker ran {ticks} times, exit {status:?}");
    // F-0010: the 128 MiB getrandom draws from the generator once, not
    // once per 256 bytes (524,288 draws, each reading a clock device,
    // which under KVM took over 15 s). Loading the program draws a few
    // more for address randomization and AT_RANDOM.
    t.check(
        "random.one_draw_per_getrandom",
        status == Some((0, None)) && draws <= 16,
        "a 128 MiB getrandom takes the generator's lock once, not per chunk (F-0010)",
    );
    kprintln!("  generator draws while longcall ran: {draws}");
}

/// Runs `/test/<name>` with `args` and waits for it.
/// Frames neither free nor the heap's nor the kernel's page tables: what
/// a leak-checking test compares before and after. The kernel's tables
/// are counted because the heap can need a new one when it maps a page
/// in a range no table covers yet, and tables are never freed: a run that
/// grows the heap there is no leak.
fn frames_outside_heap() -> i64 {
    memory::free_frames() as i64
        + keel_hal::heap::mapped_pages() as i64
        + paging::kernel_table_frames() as i64
}

fn run_test_program(path: &[u8], args: &[&[u8]]) -> Option<(i64, Option<sched::UserFault>)> {
    let file = keel_linux_abi::fs::read_file(path).ok()?;
    let loaded = keel_linux_abi::exec::load(&file, path, args, &[]).ok()?;
    let spawned = keel_linux_abi::process::spawn("test", &loaded).ok()?;
    join(spawned.thread);
    sched::exit_status(spawned.thread)
}

/// F-0011 (audit 2, A1 and A2): a user program cannot make the kernel run
/// out of memory. Mapping, creating files and calling into the kernel all
/// end in ENOMEM or ENOSPC while the kernel keeps running.
pub fn phase1_resource_limits(t: &mut Runner) {
    // The audit's proof of concept: single PROT_NONE pages at spaced hints.
    const MAPLIMIT: &[u8] = b"/test/maplimit";
    let hint = run_test_program(MAPLIMIT, &[MAPLIMIT, b"hint"]);
    t.check(
        "limits.map_count",
        hint == Some((0, None)),
        "mapping single pages in a loop ends in ENOMEM at the 65530-mapping cap; the kernel keeps running (F-0011)",
    );

    // mmap(NULL) to the cap, with a kernel thread counting 5 ms sleeps
    // meanwhile: placing each mapping must not stall the kernel (A2).
    static TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    static STOP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    STOP.store(false, Ordering::Relaxed);
    let ticker = sched::spawn("ticker", || {
        while !STOP.load(Ordering::Relaxed) {
            sched::sleep_ms(5);
            TICKS.fetch_add(1, Ordering::Relaxed);
        }
    });
    let ticks_before = TICKS.load(Ordering::Relaxed);
    let begin = time::monotonic_nanos();
    let null = run_test_program(MAPLIMIT, &[MAPLIMIT, b"null"]);
    let elapsed_ms = (time::monotonic_nanos() - begin) / 1_000_000;
    let ticks = TICKS.load(Ordering::Relaxed) - ticks_before;
    STOP.store(true, Ordering::Relaxed);
    if let Ok(id) = ticker {
        join(id);
    }
    t.check(
        "limits.map_null_preemptible",
        null == Some((0, None)) && ticks >= (elapsed_ms / 50).max(1),
        "mmap(NULL) up to the cap ends in ENOMEM, and a kernel thread keeps running throughout (A2)",
    );
    kprintln!("  maplimit null: {elapsed_ms} ms, ticker ran {ticks} times, exit {null:?}");

    // Creating files until the node cap. The cap is lowered to 200 more
    // nodes than exist, so the run is short and later tests still have room.
    let room = 200;
    let old_limit = keel_linux_abi::fs::with(|fs| {
        let nodes = fs.usage().1;
        Ok(fs.set_node_limit(nodes + room))
    });
    let flood = run_test_program(b"/test/fileflood", &[b"/test/fileflood"]);
    let nodes_after = keel_linux_abi::fs::usage().1;
    if let Ok(old) = old_limit {
        let _ = keel_linux_abi::fs::with(|fs| Ok(fs.set_node_limit(old)));
    }
    t.check(
        "limits.tmpfs_nodes",
        old_limit.is_ok() && flood == Some((0, None)),
        "creating files in a loop ends in ENOSPC at the node cap; the kernel keeps running (F-0011)",
    );
    kprintln!("  fileflood: exit {flood:?}, {nodes_after} nodes");

    // With only the kernel's reserve free, calls that would make the kernel
    // allocate are refused with ENOMEM. The program is loaded first, then
    // the reserve is raised while it loops.
    const RESERVECALL: &[u8] = b"/test/reservecall";
    let refused_before = keel_linux_abi::syscall::reserve_refusals();
    let reserve = keel_linux_abi::fs::read_file(RESERVECALL)
        .ok()
        .and_then(|file| {
            let loaded =
                keel_linux_abi::exec::load(&file, RESERVECALL, &[RESERVECALL], &[]).ok()?;
            let spawned = keel_linux_abi::process::spawn("reservecall", &loaded).ok()?;
            sched::sleep_ms(20);
            let old = memory::set_user_reserve(memory::free_frames() + 16);
            join(spawned.thread);
            memory::set_user_reserve(old);
            sched::exit_status(spawned.thread)
        });
    let refused = keel_linux_abi::syscall::reserve_refusals() - refused_before;
    t.check(
        "limits.reserve_admission",
        reserve == Some((0, None)) && refused > 0,
        "with only the kernel's reserve free, system calls are refused with ENOMEM instead of taking it (F-0011)",
    );

    // A3: console writes on a UART at least as slow as a real one (115200 baud,
    // 8N1: 11,520 bytes a second) must not keep interrupts off. A kernel
    // thread counting 5 ms sleeps keeps running while a program writes
    // 8 KiB to the console: about 0.7 s of transmission, each 4 KiB write
    // 0.36 s with interrupts off if it went out in one piece. (Kept small:
    // under nested KVM each UART port access is an exit to QEMU, about
    // 0.5 ms a byte in CI, so 32 KiB overran the 15 s join.)
    use keel_hal::drivers::serial::TEST_BYTE_DELAY_NS;
    STOP.store(false, Ordering::Relaxed);
    let ticker = sched::spawn("ticker", || {
        while !STOP.load(Ordering::Relaxed) {
            sched::sleep_ms(5);
            TICKS.fetch_add(1, Ordering::Relaxed);
        }
    });
    let ticks_before = TICKS.load(Ordering::Relaxed);
    let begin = time::monotonic_nanos();
    TEST_BYTE_DELAY_NS.store(1_000_000_000 / 11_520, Ordering::Relaxed);
    let flood = run_test_program(b"/test/conflood", &[b"/test/conflood"]);
    TEST_BYTE_DELAY_NS.store(0, Ordering::Relaxed);
    let elapsed_ms = (time::monotonic_nanos() - begin) / 1_000_000;
    let ticks = TICKS.load(Ordering::Relaxed) - ticks_before;
    STOP.store(true, Ordering::Relaxed);
    if let Ok(id) = ticker {
        join(id);
    }
    t.check(
        "console.slow_uart_preemptible",
        flood == Some((0, None)) && elapsed_ms >= 500 && ticks >= elapsed_ms / 50,
        "a program flooding a real-speed UART does not keep interrupts off: a kernel thread keeps running (A3)",
    );
    kprintln!("  conflood: {elapsed_ms} ms, ticker ran {ticks} times, exit {flood:?}");

    // A4: the branch-predictor barrier between processes is keyed on an id
    // that a new address space never shares with a freed one, even when it
    // gets the freed one's table frame. In this boot sequence it does get
    // that frame (logged below), so keying on the table address, as before,
    // fails this test; the allocator does not promise the reuse, so the
    // check does not require it.
    use keel_hal::vm::AddressSpace;
    let barrier = AddressSpace::new().ok().and_then(|a| {
        sched::note_user_space(&a);
        let same_again = sched::note_user_space(&a);
        let (a_id, a_root) = (a.id(), a.user_root());
        drop(a);
        let b = AddressSpace::new().ok()?;
        let changed = sched::note_user_space(&b);
        Some((same_again, changed, b.id() != a_id, b.user_root() == a_root))
    });
    t.check(
        "mitigations.ibpb_keyed_by_space_id",
        matches!(barrier, Some((false, true, true, _))),
        "a dropped and recreated address space gets a new id and a barrier; the same space again does not (A4)",
    );
    if let Some((_, _, _, reused)) = barrier {
        kprintln!("  new address space reused the old table frame: {reused}");
    }
}

/// Audit 2, A7: small robustness items that can be observed.
pub fn phase1_audit_small_items(t: &mut Runner) {
    // A7.2: exit statuses of finished threads are not kept for ever.
    let mut last = None;
    for _ in 0..1100 {
        if let Ok(id) = sched::spawn("short", || {}) {
            join(id);
            last = Some(id);
        }
    }
    let kept = sched::exited_count();
    t.check(
        "sched.exited_bounded",
        last.is_some_and(|id| sched::exit_status(id).is_some()) && kept <= 1024,
        "after 1100 threads exit, at most 1024 statuses are kept and the latest is still there (A7.2)",
    );
    kprintln!("  exit statuses kept: {kept}");

    // A6: a directory handle confines lookups made through it.
    let confined = run_test_program(b"/test/dirconfine", &[b"/test/dirconfine"]);
    t.check(
        "fs.dirfd_confines",
        confined == Some((0, None)),
        "`..` through a directory handle stops at that directory; creating through it lands beneath it (A6)",
    );
    if confined != Some((0, None)) {
        kprintln!("  dirconfine: exit {confined:?}");
    }

    // Audit 3, C2: tearing down a process allocates nothing, however
    // large it is. 1024 pages, one every 2 MiB (so as many page tables),
    // then the heap's allocation count across the drop.
    {
        use keel_core::vm::{Placement, Prot};
        use keel_hal::vm::{AddressSpace, copy_to_user, with_address_space};
        const BASE: u64 = 0x1000_0000_0000;
        const PAGES: u64 = 1024;
        const STRIDE: u64 = 2 << 20;
        let result = AddressSpace::new().ok().and_then(|space| {
            space
                .map(Placement::Fixed(BASE), PAGES * STRIDE, Prot::READ_WRITE)
                .ok()?;
            let touched = with_address_space(&space, || {
                (0..PAGES).all(|i| copy_to_user(BASE + i * STRIDE, &[1]).is_ok())
            });
            let alone = alloc::sync::Arc::strong_count(&space) == 1;
            let frames_before = memory::free_frames();
            let allocations_before = keel_hal::heap::allocations();
            drop(space);
            let allocated = keel_hal::heap::allocations() - allocations_before;
            let freed = memory::free_frames() - frames_before;
            Some((touched && alone, allocated, freed))
        });
        t.check(
            "vm.teardown_allocates_nothing",
            matches!(result, Some((true, 0, freed)) if freed >= 2 * PAGES as usize),
            "dropping an address space with 1024 pages and 1024 page tables makes no heap allocation (audit 3, C2)",
        );
        if let Some((_, allocated, freed)) = result {
            kprintln!("  teardown: {allocated} heap allocations, {freed} frames freed");
        }
    }

    // Audit 3, C3: growing a file never takes the kernel's reserve. With
    // only 64 frames free above the reserve, grow a file 4 KiB at a time:
    // free memory must never fall below the reserve, and growth must end
    // in ENOMEM.
    {
        use keel_core::errno::Errno;
        use keel_core::vfs::ROOT;
        let old = memory::set_user_reserve(memory::free_frames().saturating_sub(64));
        let result = keel_linux_abi::fs::with(|fs| {
            let ino = fs.create_file(ROOT, b"c3-growth", 0o644)?;
            let chunk = [0u8; 4096];
            let mut offset = 0u64;
            let mut lowest = i64::MAX;
            loop {
                match fs.write(ino, offset, &chunk) {
                    Ok(n) => offset += n as u64,
                    Err(error) => return Ok((error, offset, lowest)),
                }
                let margin = memory::free_frames() as i64 - memory::user_reserve() as i64;
                lowest = lowest.min(margin);
                if offset > 64 << 20 {
                    return Ok((Errno::EFBIG, offset, lowest));
                }
            }
        });
        memory::set_user_reserve(old);
        t.check(
            "fs.growth_keeps_reserve",
            matches!(result, Ok((Errno::ENOMEM, _, lowest)) if lowest >= 0),
            "growing a tmpfs file stops with ENOMEM before free memory reaches the kernel's reserve (audit 3, C3)",
        );
        if let Ok((error, offset, lowest)) = result {
            kprintln!(
                "  growth: {offset} bytes, then {error:?}; lowest margin over the reserve {lowest} frames"
            );
        }
    }

    // Phase 2 audit, item 3: a program prints forged result lines. They
    // land on COM1 only; xtask checks they are absent from COM2.
    let forged = run_test_program(b"/test/forger", &[b"/test/forger"]);
    t.check(
        "results.forger_ran",
        forged == Some((0, None)),
        "a program that prints forged test results ran (xtask checks they are not on the result channel)",
    );

    // A7.5: no global translations: CR4.PGE is clear.
    t.check(
        "paging.no_global_pages",
        cpu::read_cr4() & cpu::CR4_PGE == 0,
        "CR4.PGE is clear, so a CR3 write leaves no stale global translation (A7.5)",
    );
}

/// Phase 2: the toy PE loader runs a Windows executable (spec section 9).
/// Acceptance P2: `peldr /winetest/hello.exe` writes the exact line, which
/// `cargo xtask test --phase 2` finds on serial, and exits 0.
fn phase2(t: &mut Runner) {
    const PELDR: &[u8] = b"/test/peldr";
    const HELLO: &[u8] = b"/winetest/hello.exe";
    let status = run_test_program(PELDR, &[PELDR, HELLO]);
    t.check(
        "acceptance.peldr_hello",
        status == Some((0, None)),
        "peldr runs hello.exe, a Windows x64 executable, to exit status 0 (its line is checked on serial)",
    );
    if status != Some((0, None)) {
        kprintln!("  peldr: exit {status:?}");
    }
    // Loaded away from its preferred base: the DIR64 relocations of its
    // pointer table must have been applied for the same line to come out.
    let relocated = run_test_program(PELDR, &[PELDR, b"--relocate", HELLO]);
    t.check(
        "peldr.relocated",
        relocated == Some((0, None)),
        "peldr runs hello.exe away from its preferred base (base relocations applied) to exit status 0",
    );
    if relocated != Some((0, None)) {
        kprintln!("  peldr --relocate: exit {relocated:?}");
    }
    // A malformed file is refused with an error, and the kernel carries on.
    const BAD: &[u8] = b"/test/startup";
    let refused = run_test_program(PELDR, &[PELDR, BAD]);
    t.check(
        "peldr.refuses_non_pe",
        refused == Some((1, None)),
        "peldr refuses a file that is not a PE executable with exit status 1",
    );

    // Phase 2 acceptance marker, only when every test above passed.
    if t.failed == 0 {
        kresult!("KEEL P2 OK");
    }
}

/// Runs `path` in `compartment` to completion: its exit status and fault.
fn run_in(
    compartment: &alloc::sync::Arc<keel_core::compartment::Compartment>,
    path: &[u8],
    args: &[&[u8]],
) -> Option<(i64, Option<sched::UserFault>)> {
    let file = keel_linux_abi::fs::read_file(path).ok()?;
    // Its interpreter, if any, is looked up in the compartment's own tree.
    let loaded = keel_linux_abi::exec::load_in(compartment.root(), &file, path, args, &[]).ok()?;
    let spawned = keel_linux_abi::process::spawn_in(compartment, "test", &loaded).ok()?;
    join(spawned.thread);
    sched::exit_status(spawned.thread)
}

/// Phase 3 (in progress): compartments first (P3-S1 to P3-S4), before any
/// program from outside the tree runs.
fn phase3(t: &mut Runner) {
    use keel_core::compartment::Limits;
    use keel_core::errno::Errno;
    use keel_linux_abi::{compartment, fs};

    let made = fs::with(|fs| {
        let comp = fs.create_dir(keel_core::vfs::ROOT, b"comp", 0o755)?;
        for name in [&b"a"[..], b"b", b"c"] {
            fs.create_dir(comp, name, 0o755)?;
        }
        Ok(())
    });
    let limits = Limits {
        processes: 4,
        ..Limits::UNLIMITED
    };
    let (Ok(()), Ok(a), Ok(b)) = (
        made,
        compartment::create(b"/comp/a", limits),
        compartment::create(b"/comp/b", limits),
    ) else {
        t.check(
            "compartment.create",
            false,
            "creating /comp/a and /comp/b and their compartments",
        );
        return;
    };

    // Security acceptance P3 item 2, files: A, then B, then A again, so
    // each looks for the other's marker after it exists. Each run also
    // checks it cannot name the system's /test and that its PID counts
    // from 1 in its own compartment.
    const PROBE: &[u8] = b"/test/compprobe";
    let first_a = run_in(&a, PROBE, &[PROBE, b"a", b"b", b"1"]);
    let first_b = run_in(&b, PROBE, &[PROBE, b"b", b"a", b"1"]);
    let second_a = run_in(&a, PROBE, &[PROBE, b"a", b"b", b"2"]);
    // Seen from the system root, each marker is in its own compartment's
    // directory and nowhere else.
    let placed = fs::lookup(b"/comp/a/marker-a").is_ok()
        && fs::lookup(b"/comp/b/marker-b").is_ok()
        && fs::lookup(b"/marker-a").is_err()
        && fs::lookup(b"/marker-b").is_err()
        && fs::lookup(b"/comp/a/marker-b").is_err();
    let ok = [first_a, first_b, second_a] == [Some((0, None)); 3];
    t.check(
        "compartment.files_confined",
        ok && placed,
        "two compartments cannot name each other's files, or the system's, in either direction; absolute paths and .. stay in the compartment root",
    );
    if !(ok && placed) {
        kprintln!(
            "  compprobe: A {first_a:?}, B {first_b:?}, A again {second_a:?}; markers placed: {placed}"
        );
    }
    t.check(
        "compartment.pid_space",
        ok && a.processes() == 0 && b.processes() == 0,
        "each compartment numbers its processes from 1 (getpid), and its count returns to 0 when they exit",
    );

    // P3-S4: a compartment's process limit. One slot: a second process
    // is refused with EAGAIN while the first lives, and admitted after.
    const NAP: &[u8] = b"/test/nap";
    let one = compartment::create(
        b"/comp/c",
        Limits {
            processes: 1,
            ..Limits::UNLIMITED
        },
    );
    let limited = one.as_ref().ok().and_then(|c| {
        let file = fs::read_file(NAP).ok()?;
        let load = || keel_linux_abi::exec::load(&file, NAP, &[NAP, b"300"], &[]).ok();
        let first = keel_linux_abi::process::spawn_in(c, "nap", &load()?).ok()?;
        let refused = keel_linux_abi::process::spawn_in(c, "nap", &load()?).err();
        join(first.thread);
        let first_status = sched::exit_status(first.thread);
        let again = keel_linux_abi::process::spawn_in(c, "nap", &load()?).ok()?;
        join(again.thread);
        Some((
            refused,
            first_status,
            sched::exit_status(again.thread),
            c.processes(),
        ))
    });
    t.check(
        "compartment.process_limit",
        limited == Some((Some(Errno::EAGAIN), Some((0, None)), Some((0, None)), 0)),
        "at a compartment's process limit a new process is refused with EAGAIN, and admitted once one exits",
    );
    if let Some(result) =
        limited.filter(|r| *r != (Some(Errno::EAGAIN), Some((0, None)), Some((0, None)), 0))
    {
        kprintln!("  process limit: {result:?}");
    }
    phase3_memory_limit(t);
    phase3_tmpfs_quota(t);
    phase3_dynamic(t);
    phase3_file_mappings(t);
    phase3_execve(t);
    phase3_fork(t);
    phase3_shared_frame_limit(t);
    phase3_hostile_executables(t);
    phase3_exit_status_order(t);
    phase3_threads(t);
    phase3_signals(t);
    phase3_acceptance2(t);
    phase3_stress_short(t);
    phase3_shared_mappings(t);
    phase3_filesystem(t);
    phase3_descriptors(t);
    phase3_procfs(t);
    phase3_pipes(t);
    phase3_epoll(t);
    phase3_sockets(t);
    phase3_socket_messages(t);
    phase3_terminals(t);
    phase3_job_control(t);
    phase3_console_interrupt(t);
    phase3_stop_continue(t);
    phase3_sleep(t);
    phase3_spawn(t);
    phase3_fifos(t);
    phase3_scripts(t);
    phase3_procdirs(t);
    phase3_launch(t);
    phase3_shell(t);
    phase3_console_shell(t);
    phase3_console_busybox(t);
    const THREAD_PROBE: &[u8] = b"/test/threadprobe";
    let status = run_test_program(THREAD_PROBE, &[THREAD_PROBE]);
    t.check(
        "exec.thread_calls",
        status == Some((0, None)),
        "clone flag refusals, gettid, kill (0, ESRCH, SIGKILL ending a waiting child) and futex errors (EAGAIN, EINVAL, ETIMEDOUT, ENOSYS) as Linux",
    );
    if status != Some((0, None)) {
        kprintln!("  threadprobe: {status:?}");
    }
}

/// P3-T4: POSIX threads on musl (fixtures/musl-dynamic/threads): clone
/// with musl's thread flags, futex contention, condition variables, TLS,
/// pthread_join, and exit_group ending a thread blocked in a futex wait and
/// one spinning in user mode. Its line is checked on serial.
fn phase3_threads(t: &mut Runner) {
    use keel_linux_abi::process;
    const PROGRAM: &[u8] = b"/test/musl-threads";
    let outside_heap = frames_outside_heap;
    let (frames, processes) = (outside_heap(), process::count());
    let status = run_test_program(PROGRAM, &[PROGRAM]);
    // The two left-behind threads end at exit_group; give them a moment
    // to be scheduled and reaped.
    sched::sleep_ms(50);
    let (frames_after, processes_after) = (outside_heap(), process::count());
    let ok = status == Some((0, None)) && processes_after == processes && frames_after == frames;
    t.check(
        "exec.threads",
        ok,
        "POSIX threads on musl: 4 workers contend on a mutex, wait on a condition variable, keep thread-local values and are joined; exit_group ends a blocked and a spinning thread; nothing left over",
    );
    if !ok {
        kprintln!(
            "  threads: {status:?}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T6: signal delivery on musl (fixtures/musl-dynamic/signals): 24
/// checks that pass on Linux too (handlers and siginfo, masks, the
/// alternate stack, SIGSEGV and SIGILL handlers that move RIP, FPU state
/// kept and edited across a handler, default actions in forked children,
/// tgkill to a thread blocked in a futex (EINTR) and to one spinning).
/// Its line is checked on serial; nothing may be left over.
fn phase3_signals(t: &mut Runner) {
    use keel_linux_abi::process;
    const PROGRAM: &[u8] = b"/test/musl-signals";
    let outside_heap = frames_outside_heap;
    let (frames, processes) = (outside_heap(), process::count());
    let status = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames_after, processes_after) = (outside_heap(), process::count());
    let ok = status == Some((0, None)) && processes_after == processes && frames_after == frames;
    t.check(
        "exec.signals",
        ok,
        "signals on musl as on Linux: handlers with siginfo, masks, SA_RESETHAND, SIG_IGN, the alternate stack, fault handlers that edit the context (SEGV_MAPERR, SEGV_ACCERR, SIGILL), FPU state across a handler, default actions, tgkill with EINTR; nothing left over",
    );
    if !ok {
        kprintln!(
            "  signals: {status:?}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// Phase 3 acceptance item 2 (fixtures/musl-dynamic/acceptance2): a
/// dynamically linked musl program whose four threads each take SIGUSR1
/// on their own alternate stack (SA_ONSTACK, checked in the handler),
/// then send values over a Unix stream socket, bound in /tmp, to a forked
/// child that sends back their sum; the main thread takes a signal on
/// its alternate stack too. It passes on Linux too
/// (`host.musl-acceptance2`) and its line is checked on serial. Every
/// frame, process and tmpfs node must come back.
fn phase3_acceptance2(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/musl-acceptance2";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && processes_after == processes
        && frames_after == frames
        && nodes_after == nodes_before;
    t.check(
        "acceptance.musl_threads_signals_socket",
        ok,
        "Phase 3 acceptance item 2: a dynamically linked musl program with four POSIX threads, each taking a signal on its own alternate stack, and a Unix socket to a forked child that sums what they send; nothing left over",
    );
    if !ok {
        kprintln!(
            "  acceptance2: {status:?}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}; nodes {nodes_before} -> {nodes_after}"
        );
    }
}

/// The tree the conformance programs' compartments share (ADR 0039):
/// what they look for, linked from the system tree, and nothing else.
/// - `/dev`: null, zero, urandom, tty and ptmx (made by the kernel: a
///   compartment cannot make devices), and an empty `pts`;
/// - `/tmp`, mode 1777;
/// - `/test`: every file of the system's `/test`; `/bin/keel-shell`;
///   `/lib`'s files (musl's dynamic linker and the test library);
///   `/etc/keel-release`.
fn conformance_tree() -> Result<(), keel_core::errno::Errno> {
    use keel_core::vfs::{Device, Kind, ROOT};
    keel_linux_abi::fs::with(|fs| {
        let top = fs.create_dir(ROOT, b"conformance", 0o755)?;
        let dev = fs.create_dir(top, b"dev", 0o755)?;
        fs.create_dir(dev, b"pts", 0o755)?;
        for (name, device) in [
            (&b"null"[..], Device::Null),
            (b"zero", Device::Zero),
            (b"urandom", Device::Urandom),
            (b"tty", Device::Tty),
            (b"ptmx", Device::Ptmx),
        ] {
            fs.create_device(dev, name, device)?;
        }
        fs.create_dir(top, b"tmp", 0o1777)?;
        for (dir, only) in [
            (&b"test"[..], None),
            (b"bin", Some(&b"keel-shell"[..])),
            (b"lib", None),
            (b"etc", Some(&b"keel-release"[..])),
        ] {
            let mut path = alloc::vec![b'/'];
            path.extend_from_slice(dir);
            let from = fs.lookup(ROOT, ROOT, &path)?;
            let to = fs.create_dir(top, dir, 0o755)?;
            for (name, ino) in fs.entries(from)? {
                if fs.kind(ino)? == Kind::File && only.is_none_or(|o| o == name.as_slice()) {
                    fs.link(ino, to, &name)?;
                }
            }
        }
        Ok(())
    })
}

/// A hex field of the conformance list.
fn unhex(text: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.chunks(2)
        .map(|pair| {
            let digit = |c: u8| (c as char).to_digit(16);
            Some((digit(pair[0])? * 16 + digit(pair[1])?) as u8)
        })
        .collect()
}

/// Phase 3 acceptance item 1 (ADR 0039): every program in
/// `/test/conformance.list` (written by xtask), each in a compartment of
/// its own on the tree [`conformance_tree`] makes, with its arguments,
/// environment and standard input, standard output a tmpfs file. Its
/// outcome goes on the results channel, which programs cannot write:
/// `CONF <name> out <hex>` lines, then `CONF <name> end exit <status>`
/// (or `end fault <status>` if it ended by a fault). xtask compares them
/// with Linux's. This boot's own check is that every program ran and
/// ended within CONFORMANCE_LIMIT_S, and that every process and frame
/// outside the kernel heap came back.
fn phase3_conformance(t: &mut Runner) {
    use alloc::vec::Vec;
    use keel_core::compartment::Limits;
    use keel_linux_abi::{compartment, fs, process};
    const CONFORMANCE_LIMIT_S: u64 = 900;
    let list = fs::read_file(b"/test/conformance.list");
    let (Ok(list), Ok(())) = (list, conformance_tree()) else {
        t.check(
            "conformance.ran",
            false,
            "reading the list and making the tree",
        );
        return;
    };
    let outside_heap = frames_outside_heap;
    let (frames, processes) = (outside_heap(), process::count());
    let mut ran = 0;
    let mut problems = 0;
    for line in list.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let fields: Vec<&[u8]> = line.split(|&b| b == b'\t').collect();
        let [name, path, args, env, stdin] = fields[..] else {
            problems += 1;
            continue;
        };
        let name = core::str::from_utf8(name).unwrap_or("?");
        let list_of = |field: &[u8]| -> Option<Vec<Vec<u8>>> {
            field
                .split(|&b| b == b',')
                .filter(|f| !f.is_empty())
                .map(unhex)
                .collect()
        };
        let mut abs = alloc::vec![b'/'];
        abs.extend_from_slice(path);
        let (Some(args), Some(env), Some(stdin)) = (list_of(args), list_of(env), unhex(stdin))
        else {
            problems += 1;
            continue;
        };
        let mut argv: Vec<&[u8]> = alloc::vec![abs.as_slice()];
        argv.extend(args.iter().map(Vec::as_slice));
        let envp: Vec<&[u8]> = env.iter().map(Vec::as_slice).collect();
        let limits = Limits {
            processes: 512,
            ..Limits::UNLIMITED
        };
        let files = fs::with(|f| {
            Ok((
                f.create_detached(stdin, 0o600)?,
                f.create_detached(Vec::new(), 0o600)?,
            ))
        });
        let started = match (compartment::create(b"/conformance", limits), files) {
            (Ok(comp), Ok((input, output))) => fs::read_file(&abs)
                .ok()
                .and_then(|file| {
                    keel_linux_abi::exec::load_in(comp.root(), &file, &abs, &argv, &envp).ok()
                })
                .and_then(|loaded| {
                    process::spawn_in_with(&comp, "conformance", &loaded, Some((input, output)))
                        .ok()
                })
                .map(|s| (s, input, output)),
            _ => None,
        };
        let Some((spawned, input, output)) = started else {
            kprintln!("conformance: {name}: could not start");
            problems += 1;
            continue;
        };
        let start = time::monotonic_nanos();
        let ended = loop {
            if sched::join_timeout(spawned.thread, 1000) {
                break true;
            }
            if time::monotonic_nanos() - start > CONFORMANCE_LIMIT_S * 1_000_000_000 {
                break false;
            }
        };
        if !ended {
            kprintln!("conformance: {name}: did not end within {CONFORMANCE_LIMIT_S} s");
            problems += 1;
            break;
        }
        sched::sleep_ms(20);
        let out = fs::with(|f| f.contents(output)).unwrap_or_default();
        let _ = fs::with(|f| {
            f.unpin(input);
            f.unpin(output);
            Ok(())
        });
        for chunk in out.chunks(48) {
            let mut text = alloc::string::String::new();
            for b in chunk {
                let _ = core::fmt::Write::write_fmt(&mut text, format_args!("{b:02x}"));
            }
            kresult!("CONF {name} out {text}");
        }
        match sched::exit_status(spawned.thread) {
            Some((code, None)) => kresult!("CONF {name} end exit {code}"),
            Some((code, Some(_))) => kresult!("CONF {name} end fault {code}"),
            None => kresult!("CONF {name} end unknown"),
        }
        ran += 1;
    }
    sched::sleep_ms(100);
    let (frames_after, processes_after) = (outside_heap(), process::count());
    let ok = problems == 0 && ran > 0 && processes_after == processes && frames_after == frames;
    t.check(
        "conformance.ran",
        ok,
        "every conformance program ran in a compartment of its own and ended; every process and frame outside the kernel heap back (xtask compares their output with Linux's)",
    );
    if !ok {
        kprintln!(
            "  conformance: {ran} ran, {problems} problems; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// The stress program (fixtures/musl-dynamic/stress, a static musl
/// build).
const STRESS: &[u8] = b"/test/musl-stress";
/// How many more bytes the kernel heap may hold live after a stress
/// session than before it, once the kernel is warm: tables that fill once
/// and then stay (the scheduler's last 1024 exit statuses, audit 2, A7.2;
/// the capacity of its queues) can still move by a few KiB. From a cold
/// boot they grow by about 150 KiB, so the long session runs a warm-up
/// first. A leak of one small object per process or thread is far more:
/// the 192 bytes of each new thread's first register frame, kept for
/// good before ADR 0038, came to over 300 KiB in 20 seconds.
const STRESS_HEAP_SLACK: u64 = 64 * 1024;

/// How long a stress session may run past its own time before it counts
/// as hung: its last steps (killing and reaping up to 16 children) take
/// well under a second on Linux, and much longer under TCG.
const STRESS_GRACE_S: u64 = 600;

/// One run of the stress program for `seconds` from `seed`, in a
/// compartment of its own (128 processes and threads, 256 MiB), whose
/// directory is `/stress-<seed>`. Every minute (if `verbose`) it logs the
/// free frames, the kernel heap's pages and live bytes, and the
/// compartment's processes and memory. Passes if the program exits 0
/// within its time and STRESS_GRACE_S, and afterwards every process,
/// frame outside the kernel heap and compartment slot and frame is back,
/// and the kernel heap holds no more than STRESS_HEAP_SLACK more live
/// bytes than before. (The heap keeps the pages it grew into for its
/// small blocks, so the free frame count itself ends as much lower as the
/// heap's peak was higher; the live bytes show whether anything inside
/// it was kept.)
fn stress_session(seed: u64, seconds: u64, verbose: bool, check_heap: bool) -> bool {
    use alloc::format;
    use keel_core::compartment::Limits;
    use keel_linux_abi::{compartment, fs, process};
    let dir = format!("stress-{seed}");
    let made = fs::with(|f| f.create_dir(keel_core::vfs::ROOT, dir.as_bytes(), 0o755));
    let limits = Limits {
        processes: 128,
        memory_frames: 65_536,
        ..Limits::UNLIMITED
    };
    let path = format!("/{dir}");
    let (Ok(_), Ok(comp), Ok(file)) = (
        made,
        compartment::create(path.as_bytes(), limits),
        fs::read_file(STRESS),
    ) else {
        kprintln!("stress: could not set up the compartment or read the program");
        return false;
    };
    let outside_heap = frames_outside_heap;
    let (frames, processes) = (outside_heap(), process::count());
    let live = keel_hal::heap::live_bytes();
    let seed_text = format!("{seed}");
    let seconds_text = format!("{seconds}");
    let args: [&[u8]; 3] = [STRESS, seed_text.as_bytes(), seconds_text.as_bytes()];
    let spawned = keel_linux_abi::exec::load_in(comp.root(), &file, STRESS, &args, &[])
        .ok()
        .and_then(|loaded| process::spawn_in(&comp, "stress", &loaded).ok());
    let Some(spawned) = spawned else {
        kprintln!("stress: could not start the program");
        return false;
    };
    let start = time::monotonic_nanos();
    let limit = (seconds + STRESS_GRACE_S) * 1_000_000_000;
    let mut next_report = start + 60_000_000_000;
    let ended = loop {
        if sched::join_timeout(spawned.thread, 1000) {
            break true;
        }
        let now = time::monotonic_nanos();
        if verbose && now >= next_report {
            next_report = now + 60_000_000_000;
            kprintln!(
                "stress: {} min: {} free frames, heap {} pages holding {} live bytes, {} processes and threads in the compartment, {} frames charged to it",
                (now - start) / 60_000_000_000,
                memory::free_frames(),
                keel_hal::heap::mapped_pages(),
                keel_hal::heap::live_bytes(),
                comp.processes(),
                comp.memory().used()
            );
        }
        if now - start > limit {
            break false;
        }
    };
    if !ended {
        kprintln!(
            "stress: seed {seed} did not end within {} s",
            seconds + STRESS_GRACE_S
        );
        return false;
    }
    let status = sched::exit_status(spawned.thread);
    sched::sleep_ms(50);
    let (frames_after, processes_after) = (outside_heap(), process::count());
    let live_after = keel_hal::heap::live_bytes();
    let ok = status == Some((0, None))
        && frames_after == frames
        && processes_after == processes
        && comp.processes() == 0
        && comp.memory().used() == 0
        && (!check_heap || live_after <= live + STRESS_HEAP_SLACK);
    kprintln!(
        "stress: seed {seed}, {seconds} s: exit {status:?}; frames outside the heap {frames} -> {frames_after}; processes {processes} -> {processes_after}; compartment {} processes, {} frames left; kernel heap live bytes {live} -> {live_after}",
        comp.processes(),
        comp.memory().used()
    );
    ok
}

/// Phase 3 acceptance item 4, briefly: 20 seconds of the stress program
/// (fixtures/musl-dynamic/stress) in every phase 3 boot. `cargo xtask
/// stress` runs it for an hour.
fn phase3_stress_short(t: &mut Runner) {
    let ok = stress_session(20_261_126, 20, false, true);
    t.check(
        "stress.short",
        ok,
        "20 s of randomized fork, threads and signals (exits, crashes, SIGTERM and SIGKILL, stop and continue, exit_group from a thread, a grandchild, threads signalling each other on alternate stacks), every wait status as planned, in a compartment of its own; every process, frame and compartment slot back",
    );
}

/// The stress boot (`cargo xtask stress`): Phase 3 acceptance item 4 is a
/// 60-minute session that passes.
pub fn run_stress(minutes: u64, seed: u64) -> bool {
    let mut runner = Runner {
        passed: 0,
        failed: 0,
    };
    kprintln!("stress: {minutes} min from seed {seed}");
    // A warm-up of 20 seconds (from another seed), checked like any
    // session except for the heap: from a cold boot the kernel's tables
    // that fill once and then stay grow by about 150 KiB. The session
    // that counts starts from a warm kernel.
    let warm = stress_session(seed.wrapping_add(1), 20, false, false);
    let frames_before = memory::free_frames();
    let ok = warm && stress_session(seed, minutes * 60, true, true);
    kprintln!(
        "stress: free frames {frames_before} -> {} (the kernel heap may keep pages it grew into)",
        memory::free_frames()
    );
    runner.check(
        "stress.fork_threads_signals",
        ok,
        "Phase 3 acceptance item 4: randomized fork, threads and signals for the whole session with no kernel panic, every wait status as planned, and every frame outside the kernel heap, process and compartment slot back",
    );
    kresult!(
        "TEST SUMMARY passed={} failed={}",
        runner.passed,
        runner.failed
    );
    runner.failed == 0
}

/// P3-T7, shared file mappings (ADR 0021): user/tests/sharemap, which
/// passes under Linux too (`host.sharemap`): MAP_SHARED stores reach the
/// file and other mappings (in the process and across fork), write(2)
/// reaches the mappings, read-only descriptors refuse writable shared
/// mappings at mmap and mprotect, and ftruncate works as Linux's. The
/// program unlinks its file at the end; once its descriptors and
/// mappings are gone the file is freed (ADR 0022), and its shared pages
/// with it: nothing may be left in /tmp or the cache, and every frame and
/// process must come back.
fn phase3_shared_mappings(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/sharemap";
    let outside_heap = frames_outside_heap;
    let (frames, processes) = (outside_heap(), process::count());
    let status = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let cached = keel_hal::vm::shared_pages();
    let left = fs::with(|f| {
        let tmp = f.lookup(keel_core::vfs::ROOT, keel_core::vfs::ROOT, b"/tmp")?;
        f.entries(tmp)
    })
    .map(|e| e.len())
    .unwrap_or(usize::MAX);
    let (frames_after, processes_after) = (outside_heap(), process::count());
    let ok = status == Some((0, None))
        && cached == 0
        && left == 0
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.shared_mappings",
        ok,
        "MAP_SHARED file mappings as on Linux: stores reach the file, other mappings and a forked child, write(2) reaches them, read-only descriptors refuse PROT_WRITE (mmap and mprotect), ftruncate grows, shrinks and zeroes; the unlinked file and its shared pages are freed, every frame back",
    );
    if !ok {
        kprintln!(
            "  sharemap: {status:?}; cached pages {cached}; left in /tmp {left}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T8 (ADR 0022): user/tests/fsprobe, which passes under Linux too
/// (`host.fsprobe`): directories, symbolic and hard links, unlink of an
/// open file, rmdir, rename (replace, exchange, no-replace and its
/// refusals), getdents64, lseek, the working directory, chmod, umask,
/// utimensat and access. Afterwards nothing is left in /tmp, and every
/// node, frame and process is back.
fn phase3_filesystem(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/fsprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let left = fs::with(|f| {
        let tmp = f.lookup(keel_core::vfs::ROOT, keel_core::vfs::ROOT, b"/tmp")?;
        f.entries(tmp)
    })
    .map(|e| e.len())
    .unwrap_or(usize::MAX);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && left == 0
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.filesystem",
        ok,
        "the filesystem calls as on Linux: mkdir, rmdir, unlink (an open file outlives its name), rename, link, symlink and readlink (ELOOP, O_NOFOLLOW), getdents64, lseek, getcwd/chdir/fchdir, chmod, umask, utimensat, access; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  fsprobe: {status:?}; left in /tmp {left}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T8 second part (ADR 0023): user/tests/fdprobe, which passes under
/// Linux too (`host.fdprobe`): dup, dup2, dup3, F_DUPFD(_CLOEXEC),
/// F_GETFL/F_SETFL, pwrite64 and pwritev2 with O_APPEND, RWF_APPEND,
/// RWF_NOAPPEND and offset -1, readv and preadv, record locks between a
/// process and its children (F_GETLK, F_SETLK, F_SETLKW, release on close
/// and on exit), statfs, fstatfs and the xattr calls' checks. Afterwards
/// nothing is left in /tmp, and every node, frame and process is back.
fn phase3_descriptors(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/fdprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.descriptors",
        ok,
        "the descriptor calls as on Linux: dup, dup2, dup3, F_DUPFD, F_GETFL/F_SETFL, pwrite and pwritev2 (O_APPEND, RWF_APPEND, RWF_NOAPPEND), readv, record locks across fork (EAGAIN, F_GETLK, F_SETLKW, released on close and exit), statfs, xattr checks; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  fdprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T9 (ADR 0024): user/tests/procprobe, which passes under Linux too
/// (`host.procprobe`): /proc, /proc/self and /proc/<pid>, the exe links,
/// comm and prctl thread names, a forked child's view, /proc/cpuinfo,
/// /proc/net/dev and procfs's statfs. Afterwards every node, frame and
/// process is back (the open procfs files' snapshots are freed).
fn phase3_procfs(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/procprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.procfs",
        ok,
        "the traced procfs as on Linux: /proc, /proc/self and /proc/<pid>, exe links (readlink, stat, O_NOFOLLOW), thread names through comm and prctl, a forked child's view, /proc/cpuinfo, /proc/net/dev, statfs; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  procprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T10 part 1 (ADR 0025): user/tests/pipeprobe, which passes under
/// Linux too (`host.pipeprobe`): pipes (capacity, atomic writes, EOF,
/// EPIPE and SIGPIPE, blocking and non-blocking), poll, ppoll, select and
/// pselect6 with their timeouts and temporary masks, eventfds and
/// memfd_create. Afterwards every node, frame and process is back.
fn phase3_pipes(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/pipeprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.pipes",
        ok,
        "pipes, eventfds and memfd_create as on Linux, and poll, ppoll, select and pselect6 over them (timeouts written back, temporary signal masks); every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  pipeprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T10 part 2 (ADR 0026): user/tests/epollprobe, which passes under
/// Linux too (`host.epollprobe`). Afterwards every node, frame and process
/// is back.
fn phase3_epoll(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/epollprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.epoll",
        ok,
        "epoll as on Linux: creation, epoll_ctl's checks in its order, level and edge triggering, EPOLLONESHOT, EPOLLHUP unasked, rotation, items living with their file, poll on the epoll descriptor, timeouts and temporary signal masks; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  epollprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T11 part 1 (ADR 0027): user/tests/sockprobe, which passes under
/// Linux too (`host.sockprobe`), run twice. After the second run every
/// node, frame and process is back (socket nodes are unlinked by the
/// probe).
fn phase3_sockets(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/sockprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    // A first run warms up: it takes the heap to the high-water mark the
    // probe needs (the probe queues about 200 KiB in one socket), whose
    // page-table frames the heap keeps. The second run is measured, so a
    // leak would show and one-time growth does not.
    let warm = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    // A failed first run is the status reported (its check number).
    let status = if warm == Some((0, None)) {
        run_test_program(PROGRAM, &[PROGRAM])
    } else {
        warm
    };
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.sockets",
        ok,
        "Unix stream sockets as on Linux: creation and options, socketpair data, shutdown and EPIPE, resets, path and abstract names, autobind, listen, connect before accept, the backlog, accept4, peer names and credentials; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  sockprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T11 part 2 (ADR 0028): user/tests/scmprobe, which passes under
/// Linux too (`host.scmprobe`), run twice; after the second run every
/// node, frame and process is back.
fn phase3_socket_messages(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/scmprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    // A first run warms up: it takes the heap to the high-water mark the
    // probe needs (the probe fills sockets), whose
    // page-table frames the heap keeps. The second run is measured, so a
    // leak would show and one-time growth does not.
    let warm = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    // A failed first run is the status reported (its check number).
    let status = if warm == Some((0, None)) {
        run_test_program(PROGRAM, &[PROGRAM])
    } else {
        warm
    };
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.socket_messages",
        ok,
        "descriptors and credentials over Unix sockets, and datagram sockets, as on Linux: SCM_RIGHTS (rights kept, truncation, read boundaries, MSG_PEEK, in-flight lifetime), SCM_CREDENTIALS and SO_PASSCRED, datagram boundaries, MSG_TRUNC, names, EPERM, ECONNREFUSED, EMSGSIZE, a full queue; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  scmprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T12 part 1 (ADR 0029): user/tests/ttyprobe, which passes under
/// Linux too (`host.ttyprobe`), run twice; after the second run every
/// node, frame and process is back (each pty's /dev/pts node included).
fn phase3_terminals(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/ttyprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    // As phase3_socket_messages: the first run warms the heap up.
    let warm = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = if warm == Some((0, None)) {
        run_test_program(PROGRAM, &[PROGRAM])
    } else {
        warm
    };
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.terminals",
        ok,
        "ptys and the N_TTY line discipline as on Linux: /dev/ptmx and /dev/pts, locking, termios and its ioctls, canonical lines, erase, kill, ^C, ^D, VMIN and VTIME, echo, output and input processing, flow control, flushing, a closed or hung-up end; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  ttyprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T12 part 2 (ADR 0030): user/tests/jobprobe, which passes under
/// Linux too (`host.jobprobe`), run twice; after the second run every
/// node, frame and process is back.
fn phase3_job_control(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/jobprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let warm = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = if warm == Some((0, None)) {
        run_test_program(PROGRAM, &[PROGRAM])
    } else {
        warm
    };
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.job_control",
        ok,
        "process groups, sessions and the controlling terminal as on Linux: setsid, setpgid (ESRCH, EPERM, EACCES after execve), kill and wait4 by group, TIOCSCTTY, /dev/tty, TIOCSPGRP, ^C, ^\\, ^Z and SIGWINCH to the foreground group, SIGTTIN and SIGTTOU in the background, orphaned groups, TIOCNOTTY, hangup and a leader's exit; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  jobprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T12: ^C typed on COM1 sends SIGINT to the console's foreground
/// process group: user/tests/ctrlc, a session leader with the console as
/// its terminal, blocked reading it, sees EINTR and its handler run. If
/// the signal never comes, Enter on the keyboard ends the read, so the
/// check fails rather than hangs.
fn phase3_console_interrupt(t: &mut Runner) {
    let outcome = keel_linux_abi::fs::read_file(b"/test/ctrlc")
        .ok()
        .and_then(|file| {
            let loaded =
                keel_linux_abi::exec::load(&file, b"/test/ctrlc", &[b"/test/ctrlc"], &[]).ok()?;
            let spawned = keel_linux_abi::process::spawn("ctrlc", &loaded).ok()?;
            sched::sleep_ms(50);
            let typed = keel_linux_abi::tty::type_serial(b"\x03");
            let mut ended = false;
            for _ in 0..200 {
                if sched::exit_status(spawned.thread).is_some() {
                    ended = true;
                    break;
                }
                sched::sleep_ms(10);
            }
            if !ended {
                let _ = keel_linux_abi::tty::type_scancodes(&[0x1c, 0x9c]);
            }
            join(spawned.thread);
            Some((typed && ended, sched::exit_status(spawned.thread)?))
        });
    t.check(
        "console.interrupt",
        outcome == Some((true, (0, None))),
        "^C typed on COM1 sends SIGINT to the console's foreground process group: a session leader that took the console with TIOCSCTTY, blocked reading it, gets EINTR and its handler runs",
    );
    if outcome != Some((true, (0, None))) {
        kprintln!("  ctrlc: {outcome:?}");
    }
}

/// Job control's stop and continue (ADR 0031): user/tests/stopprobe,
/// which passes under Linux too (`host.stopprobe`), run twice; after the
/// second run every node, frame and process is back.
fn phase3_stop_continue(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/stopprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let warm = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = if warm == Some((0, None)) {
        run_test_program(PROGRAM, &[PROGRAM])
    } else {
        warm
    };
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.stop_continue",
        ok,
        "stop and continue as on Linux: SIGSTOP, SIGTSTP, SIGTTIN and SIGTTOU stop, SIGCONT continues (WUNTRACED and WCONTINUED once each, SIGCHLD, SA_NOCLDSTOP), the interrupted read restarted, pending stops and SIGCONT discarding each other, orphaned groups, SA_RESTART, SIGCHLD ignored and SA_NOCLDWAIT reaping, an orphaned stopped job's SIGHUP and SIGCONT; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  stopprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T13 (ADR 0032): user/tests/shellprobe, which passes under Linux
/// too (`host.shellprobe`): keel-shell runs a script on a pipe, then an
/// interactive session on a pty with job control. Run twice; after the
/// second run every node, frame and process is back.
fn phase3_shell(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/shellprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let warm = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = if warm == Some((0, None)) {
        run_test_program(PROGRAM, &[PROGRAM])
    } else {
        warm
    };
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.shell",
        ok,
        "keel-shell as on Linux: a script's quoting, parameters, lists, pipelines, redirections, PATH search, statuses (1, 127, 143), &, wait, export, cd; on a pty, ^Z and jobs, fg, ^C (130), a background reader stopped by SIGTTIN, bg and wait, ^C at the prompt; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  shellprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-T13 (ADR 0032): what a normal boot runs, on the real console.
/// `/sbin/keel-init --once` starts `/bin/keel-shell` in a session that
/// has the console as its controlling terminal. Typed on COM1 through the
/// UART's loopback: `cat`, ^Z (the job stops), `jobs` into a file, `fg`,
/// a line, ^D, `$?` into a file, `exit 3` (keel-init exits with the
/// shell's status). Each key waits for the console's
/// foreground group to change hands, so it reaches the job or the shell
/// as intended. If a step fails, ^C and `exit` end the shell so later
/// tests have the console.
fn phase3_console_shell(t: &mut Runner) {
    use keel_linux_abi::{exec, fs, process, tty};
    const INIT: &[u8] = b"/sbin/keel-init";
    // Up to 5 s for the console's (session, foreground group) to satisfy
    // `pick`.
    let until = |pick: &dyn Fn(u32, u32) -> bool| {
        for _ in 0..500 {
            if tty::console_job().is_some_and(|(s, g)| pick(s, g)) {
                return true;
            }
            sched::sleep_ms(10);
        }
        false
    };
    // At most 14 bytes go to the UART at a time (its FIFO is 16).
    let type_text = |text: &[u8]| {
        text.chunks(14).all(|c| {
            let ok = tty::type_serial(c);
            sched::sleep_ms(30);
            ok
        })
    };
    let spawned = fs::read_file(INIT)
        .ok()
        .and_then(|file| exec::load(&file, INIT, &[INIT, b"--once"], &[]).ok())
        .and_then(|loaded| process::spawn("keel-init", &loaded).ok());
    let mut failed_at = 0;
    if let Some(spawned) = &spawned {
        // The shell leads a session on the console, its group in front.
        let ready = until(&|s, g| s != 0 && s == g);
        let sid = tty::console_job().map_or(0, |(s, _)| s);
        let steps: [&dyn Fn() -> bool; 8] = [
            &|| ready,
            &|| type_text(b"cat\n") && until(&|_, g| g != sid),
            // The job has the console; a pause so it has reset SIGTSTP.
            &|| {
                sched::sleep_ms(150);
                type_text(b"\x1a") && until(&|_, g| g == sid)
            },
            &|| type_text(b"jobs >/tmp/kj\n"),
            &|| type_text(b"fg\n") && until(&|_, g| g != sid),
            &|| {
                sched::sleep_ms(150);
                type_text(b"x\n")
            },
            &|| {
                sched::sleep_ms(100);
                type_text(b"\x04") && until(&|_, g| g == sid)
            },
            &|| type_text(b"echo $? >/tmp/ks\n") && type_text(b"exit 3\n"),
        ];
        for (i, step) in steps.iter().enumerate() {
            if !step() {
                failed_at = i + 1;
                type_text(b"\x03\x04\x03exit\nexit\n");
                break;
            }
        }
        join(spawned.thread);
    }
    let status = spawned.as_ref().and_then(|s| sched::exit_status(s.thread));
    let jobs = fs::read_file(b"/tmp/kj").ok();
    let last = fs::read_file(b"/tmp/ks").ok();
    let ok = failed_at == 0
        && status == Some((3, None))
        && jobs.as_deref().map(|v| v.as_slice()) == Some(b"[1]+ Stopped\tcat\n")
        && last.as_deref().map(|v| v.as_slice()) == Some(b"0\n");
    t.check(
        "console.shell",
        ok,
        "a normal boot's /sbin/keel-init starts /bin/keel-shell with the console as its controlling terminal; typed on COM1, ^Z stops a job, jobs lists it, fg resumes it, ^D ends it with status 0, and exit 3 ends the shell and keel-init with status 3",
    );
    if !ok {
        kprintln!(
            "  console shell: spawned {}, failed at step {failed_at}, keel-init {status:?}, jobs {:?}, status {:?}",
            spawned.is_some(),
            jobs.as_deref()
                .map(|v| core::str::from_utf8(v).unwrap_or("?")),
            last.as_deref()
                .map(|v| core::str::from_utf8(v).unwrap_or("?")),
        );
    }
}

/// ADR 0033: user/tests/sleepprobe, which passes under Linux too
/// (`host.sleepprobe`): nanosleep, clock_nanosleep and restart_syscall.
/// Run twice; after the second run every node, frame and process is back.
fn phase3_sleep(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/sleepprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let warm = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = if warm == Some((0, None)) {
        run_test_program(PROGRAM, &[PROGRAM])
    } else {
        warm
    };
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.sleep",
        ok,
        "nanosleep and clock_nanosleep as on Linux: the request's checks, the clocks that can sleep, TIMER_ABSTIME, EINTR with the time left after a handler, and after a stop and SIGCONT the sleep going on to its first deadline through restart_syscall; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  sleepprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// ADR 0034: user/tests/spawnprobe, which passes under Linux too
/// (`host.spawnprobe`): vfork, CLONE_VFORK and the ID calls, here with
/// `root` (every ID 0). Run twice; after the second run every node, frame
/// and process is back.
fn phase3_spawn(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/spawnprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let warm = run_test_program(PROGRAM, &[PROGRAM, b"root"]);
    sched::sleep_ms(50);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = if warm == Some((0, None)) {
        run_test_program(PROGRAM, &[PROGRAM, b"root"])
    } else {
        warm
    };
    sched::sleep_ms(400);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.spawn",
        ok,
        "vfork and clone's CLONE_VFORK as on Linux: the parent waiting until the child execs or exits, the memory shared with CLONE_VM and copied without, a failed execve; getuid, geteuid, getgid, getegid, getresuid and getresgid (all 0); every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  spawnprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// ADR 0035: user/tests/fifoprobe, which passes under Linux too
/// (`host.fifoprobe`): mknod and FIFOs. Run twice; after the second run
/// every node, frame and process is back.
fn phase3_fifos(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/fifoprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let warm = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = if warm == Some((0, None)) {
        run_test_program(PROGRAM, &[PROGRAM])
    } else {
        warm
    };
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.fifos",
        ok,
        "FIFOs and mknod as on Linux: mknod's types, modes and refusals in its order, a FIFO's opens (nonblocking reader at once, nonblocking writer ENXIO, blocking ends waiting for each other, O_RDWR never), data through it and gone with its last open, POLLHUP after a writer, an interrupted open, epoll on an O_RDWR end, unlinked while open; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  fifoprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// ADR 0036: user/tests/scriptprobe, which passes under Linux too
/// (`host.scriptprobe`): `#!` scripts in execve. Run twice; after the
/// second run every node, frame and process is back.
fn phase3_scripts(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/scriptprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let warm = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = if warm == Some((0, None)) {
        run_test_program(PROGRAM, &[PROGRAM])
    } else {
        warm
    };
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.scripts",
        ok,
        "#! scripts in execve as on Linux: the interpreter, its argument (inner blanks kept) and the script's path before the original argv, the thread named after the script, AT_EXECFN the script, exe the interpreter, five nested levels and ELOOP at six, ENOEXEC, ENOENT and EACCES; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  scriptprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// ADR 0037: user/tests/pidprobe, which passes under Linux too
/// (`host.pidprobe`): /proc's directories listed, and /proc/<pid>/stat
/// and cmdline. Run twice; after the second run every node, frame and
/// process is back.
fn phase3_procdirs(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/pidprobe";
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let warm = run_test_program(PROGRAM, &[PROGRAM]);
    sched::sleep_ms(50);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = if warm == Some((0, None)) {
        run_test_program(PROGRAM, &[PROGRAM])
    } else {
        warm
    };
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.procdirs",
        ok,
        "/proc's process directories as on Linux: /proc listed with self, thread-self and the compartment's PIDs at PID + 258, /proc/<pid> and its task directory listed, lseek back to a position, EINVAL for a short buffer, ENOTDIR and EISDIR opens; /proc/<pid>/stat's 52 fields (R, S, T, Z, the parent, group, session and terminal, a name with \") (\") and cmdline as exec gave it, empty for a zombie; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  pidprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// P3-S2 (ADR 0040): user/tests/launchprobe, given a factory on fd 3 as
/// keel-init is, exercises the native launch interface: restrict,
/// factory_derive, compartment_create, grant_device, spawn, kill and wait,
/// their refusals, and what a process in the compartment sees. Run twice;
/// after the second run every node, frame and process is back.
fn phase3_launch(t: &mut Runner) {
    use keel_linux_abi::{fs, process};
    const PROGRAM: &[u8] = b"/test/launchprobe";
    let run = || {
        let file = fs::read_file(PROGRAM).ok()?;
        let loaded = keel_linux_abi::exec::load(&file, PROGRAM, &[PROGRAM], &[]).ok()?;
        let spawned = process::spawn_with_fd3(
            "launchprobe",
            &loaded,
            keel_linux_abi::native::root_factory(),
        )
        .ok()?;
        join(spawned.thread);
        sched::exit_status(spawned.thread)
    };
    let outside_heap = frames_outside_heap;
    let nodes = || fs::with(|f| Ok(f.node_count())).unwrap_or(0);
    let warm = run();
    sched::sleep_ms(50);
    let (frames, processes, nodes_before) = (outside_heap(), process::count(), nodes());
    let status = if warm == Some((0, None)) { run() } else { warm };
    sched::sleep_ms(50);
    let (frames_after, processes_after, nodes_after) = (outside_heap(), process::count(), nodes());
    let ok = status == Some((0, None))
        && nodes_after == nodes_before
        && processes_after == processes
        && frames_after == frames;
    t.check(
        "exec.launch",
        ok,
        "the native launch interface (ADR 0040): rights only removed by restrict, factory ceilings, compartments rooted in a directory handle with their limits, device grants, spawn with given stdio only, kill and wait with PID 1's status, each refusal; a confined PID 1 sees no factory and nothing outside its tree; every node, frame and process back",
    );
    if !ok {
        kprintln!(
            "  launchprobe: {status:?}; nodes {nodes_before} -> {nodes_after}; processes {processes} -> {processes_after}; frames outside the heap {frames} -> {frames_after}"
        );
    }
}

/// Phase 3 acceptance item 3 (P3-T13 part 2): static BusyBox `sh` runs
/// interactively on the serial console and runs `ls`, `cat`, pipelines
/// and background jobs. `/sbin/keel-init --once --shell /bin/busybox sh`
/// starts it as a normal boot starts keel-shell. Typed on COM1 through
/// the UART's loopback, each line once the last has been handled; each
/// command leaves its result in /tmp, which this test reads:
/// - the applets linked into /tmp/bb (`mkdir`, `--install -s`), PATH
///   set to them;
/// - the shell is BusyBox: `readlink /proc/$$/exe` gives /bin/busybox;
/// - `ls /etc` (keel-release) and a pipeline `echo | cat | tr`;
/// - a background `sleep 1 &`: `jobs` shows it running, `wait` gives 0;
/// - `cat` in the foreground, ^Z (stopped, in `jobs`), `fg`, a line,
///   ^D: `$?` 0;
/// - `exit 3`: keel-init exits 3.
///
/// Keys for a foreground job wait for the console's foreground group to
/// change hands. If a step fails, ^C, ^D and `exit` end the shell.
fn phase3_console_busybox(t: &mut Runner) {
    use keel_linux_abi::{exec, fs, process, tty};
    const INIT: &[u8] = b"/sbin/keel-init";
    let until = |pick: &dyn Fn(u32, u32) -> bool| {
        for _ in 0..500 {
            if tty::console_job().is_some_and(|(s, g)| pick(s, g)) {
                return true;
            }
            sched::sleep_ms(10);
        }
        false
    };
    let type_text = |text: &[u8]| {
        text.chunks(14).all(|c| {
            let ok = tty::type_serial(c);
            sched::sleep_ms(30);
            ok
        })
    };
    // A command line, then time for the shell to run it.
    let line = |text: &[u8]| {
        let ok = type_text(text);
        sched::sleep_ms(400);
        ok
    };
    // A command line that writes `file`, then up to 5 s for it to appear.
    let writes = |text: &[u8], file: &[u8]| {
        type_text(text)
            && (0..500).any(|_| {
                let there = fs::read_file(file).is_ok_and(|f| !f.is_empty());
                if !there {
                    sched::sleep_ms(10);
                }
                there
            })
    };
    let spawned = fs::read_file(INIT)
        .ok()
        .and_then(|file| {
            exec::load(
                &file,
                INIT,
                &[INIT, b"--once", b"--shell", b"/bin/busybox", b"sh"],
                &[],
            )
            .ok()
        })
        .and_then(|loaded| process::spawn("keel-init", &loaded).ok());
    let mut failed_at = 0;
    if let Some(spawned) = &spawned {
        let ready = until(&|s, g| s != 0 && s == g);
        // Line editing asks the terminal where the cursor is; a moment
        // for that before typing.
        sched::sleep_ms(300);
        let sid = tty::console_job().map_or(0, |(s, _)| s);
        let steps: [&dyn Fn() -> bool; 13] = [
            &|| ready,
            &|| line(b"/bin/busybox mkdir /tmp/bb\n"),
            &|| line(b"/bin/busybox --install -s /tmp/bb\n"),
            &|| line(b"export PATH=/tmp/bb\n"),
            // The shell is BusyBox's: its own executable.
            &|| writes(b"readlink /proc/$$/exe >/tmp/b7\n", b"/tmp/b7"),
            &|| {
                writes(b"ls /etc >/tmp/b1\n", b"/tmp/b1")
                    && writes(b"echo hi | cat | tr a-z A-Z >/tmp/b2\n", b"/tmp/b2")
            },
            &|| line(b"sleep 1 &\n") && writes(b"jobs >/tmp/b3\n", b"/tmp/b3"),
            &|| writes(b"wait; echo $? >/tmp/b4\n", b"/tmp/b4"),
            &|| type_text(b"cat\n") && until(&|_, g| g != sid),
            &|| {
                sched::sleep_ms(150);
                type_text(b"\x1a") && until(&|_, g| g == sid)
            },
            &|| {
                writes(b"jobs >/tmp/b5\n", b"/tmp/b5")
                    && type_text(b"fg\n")
                    && until(&|_, g| g != sid)
            },
            &|| {
                sched::sleep_ms(150);
                type_text(b"x\n")
                    && {
                        sched::sleep_ms(100);
                        type_text(b"\x04")
                    }
                    && until(&|_, g| g == sid)
            },
            &|| writes(b"echo $? >/tmp/b6\n", b"/tmp/b6") && type_text(b"exit 3\n"),
        ];
        for (i, step) in steps.iter().enumerate() {
            if !step() {
                failed_at = i + 1;
                type_text(b"\x03\x04\x03exit\nexit\n");
                break;
            }
        }
        join(spawned.thread);
    }
    let status = spawned.as_ref().and_then(|s| sched::exit_status(s.thread));
    let file = |path: &[u8]| fs::read_file(path).ok();
    let text = |v: &Option<alloc::sync::Arc<alloc::vec::Vec<u8>>>| -> alloc::string::String {
        v.as_deref()
            .map(|v| core::str::from_utf8(v).unwrap_or("?"))
            .unwrap_or("-")
            .into()
    };
    let results = [
        b"/tmp/b1", b"/tmp/b2", b"/tmp/b3", b"/tmp/b4", b"/tmp/b5", b"/tmp/b6", b"/tmp/b7",
    ]
    .map(|p| file(p));
    let has = |i: usize, parts: &[&str]| {
        let t = text(&results[i]);
        parts.iter().all(|p| t.contains(p))
    };
    let ok = failed_at == 0
        && status == Some((3, None))
        && text(&results[0]) == "keel-release\n"
        && text(&results[1]) == "HI\n"
        && has(2, &["[1]", "Running", "sleep 1"])
        && text(&results[3]) == "0\n"
        && has(4, &["[1]", "Stopped", "cat"])
        && text(&results[5]) == "0\n"
        && text(&results[6]) == "/bin/busybox\n";
    t.check(
        "console.busybox",
        ok,
        "Phase 3 acceptance item 3: static BusyBox sh, started by keel-init on the serial console, runs ls, cat, a pipeline (echo | cat | tr), a background job (sleep 1 &, jobs, wait), and stops, lists and resumes a foreground job (^Z, jobs, fg, ^D)",
    );
    if !ok {
        kprintln!(
            "  busybox: spawned {}, failed at step {failed_at}, keel-init {status:?}",
            spawned.is_some()
        );
        for (i, r) in results.iter().enumerate() {
            kprintln!("  /tmp/b{}: {:?}", i + 1, text(r));
        }
    }
}

/// ADR 0034: BusyBox's own test suite (`fixtures/busybox/testsuite.tar`),
/// a boot of its own. BusyBox's shell installs its applets in /bin, as
/// the Linux reference run had them, and runs `runtest` in
/// /test/bb/testsuite with its output in /tmp/bbts.log. Every test
/// `/test/bb/expected.txt` lists as passing must pass; the others are
/// reported, so the list can grow as Keel does.
fn phase3_busybox_suite(t: &mut Runner) {
    use alloc::collections::BTreeMap;
    use keel_linux_abi::{exec, fs, process};
    const BUSYBOX: &[u8] = b"/bin/busybox";
    const SCRIPT: &[u8] = b"/bin/busybox --install -s /bin && cd /test/bb/testsuite && PATH=/bin HOME=/tmp ./runtest >/tmp/bbts.log 2>&1";
    let begin = time::monotonic_nanos();
    let ran = fs::read_file(BUSYBOX)
        .ok()
        .and_then(|file| exec::load(&file, BUSYBOX, &[BUSYBOX, b"sh", b"-c", SCRIPT], &[]).ok())
        .and_then(|loaded| process::spawn("runtest", &loaded).ok())
        .map(|spawned| {
            // Under an hour, inside the boot's own timeout.
            let ended = sched::join_timeout(spawned.thread, 55 * 60 * 1000);
            (ended, sched::exit_status(spawned.thread))
        });
    let seconds = (time::monotonic_nanos() - begin) / 1_000_000_000;
    let text = |path: &[u8]| {
        fs::read_file(path)
            .ok()
            .map(|v| alloc::string::String::from_utf8_lossy(&v).into_owned())
            .unwrap_or_default()
    };
    let log = text(b"/tmp/bbts.log");
    let expected = text(b"/test/bb/expected.txt");
    // Each test's outcomes by name (a name can repeat).
    let mut outcome: BTreeMap<&str, alloc::vec::Vec<&str>> = BTreeMap::new();
    let mut counts = [0u32; 4];
    const KINDS: [&str; 4] = ["PASS", "FAIL", "SKIPPED", "UNTESTED"];
    for line in log.lines() {
        for (k, kind) in KINDS.iter().enumerate() {
            if let Some(name) = line.strip_prefix(kind).and_then(|r| r.strip_prefix(": ")) {
                counts[k] += 1;
                outcome.entry(name).or_default().push(kind);
            }
        }
    }
    let mut wanted: BTreeMap<&str, usize> = BTreeMap::new();
    for line in expected.lines() {
        if let Some(name) = line.strip_prefix("PASS: ") {
            *wanted.entry(name).or_default() += 1;
        }
    }
    let passes = |name: &str| {
        outcome
            .get(name)
            .map_or(0, |v| v.iter().filter(|k| **k == "PASS").count())
    };
    let missing: alloc::vec::Vec<&str> = wanted
        .iter()
        .filter(|(name, n)| passes(name) < **n)
        .map(|(name, _)| *name)
        .collect();
    let new: alloc::vec::Vec<&str> = outcome
        .keys()
        .filter(|name| passes(name) > wanted.get(*name).copied().unwrap_or(0))
        .copied()
        .collect();
    kprintln!(
        "busybox testsuite: {} PASS, {} FAIL, {} SKIPPED, {} UNTESTED in {seconds} s; runtest {ran:?}",
        counts[0],
        counts[1],
        counts[2],
        counts[3]
    );
    for line in log.lines().filter(|l| l.starts_with("FAIL: ")) {
        kprintln!("  {line}");
    }
    for name in &new {
        kprintln!("  passes, not yet in expected.txt: {name}");
    }
    for name in &missing {
        kprintln!("  REGRESSION: expected to pass: {name}");
    }
    t.check(
        "busybox.testsuite",
        ran.is_some_and(|(ended, _)| ended) && counts[0] > 0 && missing.is_empty(),
        "BusyBox 1.37.0's own test suite, run by its shell on Keel: every test fixtures/busybox/keel-expected.txt lists passes",
    );
}

/// The scheduler keeps the last 1024 exit statuses. A thread whose 1100
/// children exited before it still has its own status afterwards: the
/// oldest exit is dropped, not the smallest thread id (the parent's).
fn phase3_exit_status_order(t: &mut Runner) {
    fn child() {}
    fn parent() {
        let mut children = alloc::vec::Vec::new();
        for _ in 0..1100 {
            match sched::spawn("short", child) {
                Ok(id) => children.push(id),
                Err(_) => sched::exit_with(1),
            }
            if children.len() == 64 {
                children.drain(..).for_each(join);
            }
        }
        children.into_iter().for_each(join);
        sched::exit_with(42);
    }
    let status = sched::spawn("parent", parent).ok().and_then(|id| {
        join(id);
        sched::exit_status(id)
    });
    t.check(
        "sched.exit_status_order",
        status == Some((42, None)),
        "a thread's exit status survives 1100 children exiting before it (the oldest status is dropped first, not the smallest thread id)",
    );
    if status != Some((42, None)) {
        kprintln!("  parent status: {status:?}");
    }
}

/// Phase 2 audit item 5: execve makes the ELF parser and loader attack
/// surface. user/tests/badexec has 400 randomly damaged executables run
/// by forked children, in a compartment with process, memory and tmpfs
/// limits. The kernel must not panic, and every process slot and user
/// frame must come back.
fn phase3_hostile_executables(t: &mut Runner) {
    use keel_core::compartment::Limits;
    use keel_linux_abi::{compartment, fs};

    const PROGRAM: &[u8] = b"/test/badexec";
    let made = fs::with(|fs| {
        let comp = fs.lookup(keel_core::vfs::ROOT, keel_core::vfs::ROOT, b"/comp")?;
        fs.create_dir(comp, b"hostile", 0o755)
    });
    let limits = Limits {
        processes: 8,
        memory_frames: 8192,
        tmpfs_bytes: 1 << 20,
        tmpfs_nodes: 64,
    };
    let (Ok(_), Ok(c)) = (made, compartment::create(b"/comp/hostile", limits)) else {
        t.check(
            "exec.hostile_executables",
            false,
            "creating the compartment",
        );
        return;
    };
    let status = run_in(&c, PROGRAM, &[PROGRAM, b"20261123", b"400"]);
    let ok = status == Some((0, None)) && c.processes() == 0 && c.memory().used() == 0;
    t.check(
        "exec.hostile_executables",
        ok,
        "400 randomly damaged executables, each run by a forked child in a limited compartment: refused or run, never a kernel panic; every slot and frame back (the summary line is on serial)",
    );
    if !ok {
        kprintln!(
            "  badexec: {status:?}; processes left {}, memory left {}",
            c.processes(),
            c.memory().used()
        );
    }
}

/// Phase 2 audit item 4: a frame's reference count can fill up from user
/// mode. The real limit, 65534, is tested on the host
/// (`keel_core::frame`); here it is lowered to 12 so a dozen processes
/// reach it: the program's pages then have 12 sharers, so fork number 12
/// is refused with ENOMEM. The partial copy is undone, the kernel carries
/// on, every frame comes back, and the limit is restored.
fn phase3_shared_frame_limit(t: &mut Runner) {
    const PROGRAM: &[u8] = b"/test/forkprobe";
    const LIMIT: u16 = 12;
    let outside_heap = frames_outside_heap;
    let before = outside_heap();
    let previous = memory::set_reference_limit(LIMIT);
    let status = run_test_program(PROGRAM, &[PROGRAM, b"sharers"]);
    memory::set_reference_limit(previous);
    let after = outside_heap();
    // The program's text pages are shared by it and every child, so they
    // hit the limit first: LIMIT - 1 children.
    let ok = status == Some((i64::from(LIMIT) - 1, None)) && after == before;
    t.check(
        "vm.shared_frame_limit",
        ok,
        "with a frame's reference limit lowered to 12, fork from user mode gets 11 children and then ENOMEM; nothing leaks and the program keeps running",
    );
    if !ok {
        kprintln!("  sharers: {status:?}; frames outside the heap {before} -> {after}");
    }
}

/// P3-T3: fork and wait4, and a fork bomb against a compartment's process
/// limit (security acceptance P3 item 3).
fn phase3_fork(t: &mut Runner) {
    use keel_core::compartment::Limits;
    use keel_linux_abi::{compartment, fs, process};

    const PROGRAM: &[u8] = b"/test/forkprobe";
    // Frames outside the kernel heap. The heap may keep a few more pages
    // after a run: the scheduler keeps the exit statuses of the last 1024
    // threads (audit 2, A7.2), and this run ends 22, so that table grows
    // until it is full. Every other frame must come back.
    let outside_heap = frames_outside_heap;
    let (frames, processes) = (outside_heap(), process::count());
    let status = run_test_program(PROGRAM, &[PROGRAM]);
    let (frames_after, processes_after) = (outside_heap(), process::count());
    let ok = status == Some((0, None)) && frames_after == frames && processes_after == processes;
    t.check(
        "exec.fork_wait",
        ok,
        "fork gives the child a copy-on-write copy and shared open files; wait4 reaps exits (status code << 8), faults (signal 11) and twenty zombies, with WNOHANG, ECHILD and EINVAL as Linux; no frame or process is left over",
    );
    if !ok {
        kprintln!(
            "  forkprobe: {status:?}; frames outside the heap {frames} -> {frames_after}; processes {processes} -> {processes_after}"
        );
    }

    // The bomb: a compartment of 8 processes. The program forks until
    // EAGAIN and exits with the number of children it got (7), while a
    // program in another compartment runs normally.
    let made = fs::with(|fs| {
        let comp = fs.lookup(keel_core::vfs::ROOT, keel_core::vfs::ROOT, b"/comp")?;
        fs.create_dir(comp, b"bomb", 0o755)?;
        fs.create_dir(comp, b"bystander", 0o755)
    });
    let limits = Limits {
        processes: 8,
        ..Limits::UNLIMITED
    };
    let (Ok(_), Ok(bomb), Ok(bystander)) = (
        made,
        compartment::create(b"/comp/bomb", limits),
        compartment::create(b"/comp/bystander", Limits::UNLIMITED),
    ) else {
        t.check(
            "compartment.fork_bomb",
            false,
            "creating the bomb compartments",
        );
        return;
    };
    let started = fs::read_file(PROGRAM).ok().and_then(|file| {
        let loaded =
            keel_linux_abi::exec::load_in(bomb.root(), &file, PROGRAM, &[PROGRAM, b"bomb"], &[])
                .ok()?;
        keel_linux_abi::process::spawn_in(&bomb, "bomb", &loaded).ok()
    });
    const NAP: &[u8] = b"/test/nap";
    let other = run_in(&bystander, NAP, &[NAP, b"10"]);
    let bombed = started.and_then(|s| {
        join(s.thread);
        sched::exit_status(s.thread)
    });
    let ok = bombed == Some((7, None))
        && other == Some((0, None))
        && bomb.processes() == 0
        && bomb.memory().used() == 0;
    t.check(
        "compartment.fork_bomb",
        ok,
        "a fork bomb in a compartment of 8 processes gets 7 children and then EAGAIN; zombies keep their slots until reaped; all reaped, every slot and frame back; a program in another compartment runs meanwhile",
    );
    if !ok {
        kprintln!(
            "  bomb: {bombed:?}; bystander {other:?}; processes left {}, memory left {}",
            bomb.processes(),
            bomb.memory().used()
        );
    }
}

/// P3-T3: execve. user/tests/execprobe runs itself three times; it passes
/// under Linux too (`host.execprobe`).
fn phase3_execve(t: &mut Runner) {
    const PROGRAM: &[u8] = b"/test/execprobe";
    // Frames outside the kernel heap, which may keep a page for the
    // tables a run grows (as in exec.fork_wait).
    let outside_heap = frames_outside_heap;
    let before = outside_heap();
    let status = run_test_program(PROGRAM, &[PROGRAM]);
    let after = outside_heap();
    let ok = status == Some((0, None)) && after == before;
    t.check(
        "exec.execve",
        ok,
        "execve replaces the program: refusals as Linux (ENOENT, EACCES, EFAULT), an empty argv arrives as [\"\"], close-on-exec handles closed and others kept, caught signals reset, ignored ones and the blocked mask kept, the FS base cleared; no frame is lost across three programs",
    );
    if !ok {
        kprintln!("  execprobe: {status:?}, frames outside the heap {before} -> {after}");
    }
}

/// P3-T7, private file mappings: user/tests/filemap maps its own
/// executable and compares every byte with read(2). It passes under Linux
/// too (`host.filemap`).
fn phase3_file_mappings(t: &mut Runner) {
    // A program with a shared library of its own: musl's dynamic linker
    // opens /lib/libkeelgreet.so (open, read, fstat), maps it from the
    // file and runs. The line, with the count kept in the library's data
    // segment, is checked on serial.
    const GREET: &[u8] = b"/test/musl-greet";
    let greet = run_test_program(GREET, &[GREET]);
    t.check(
        "exec.shared_library",
        greet == Some((0, None)),
        "a musl program linked against its own shared library runs: the dynamic linker finds it in /lib and maps it from the file (its line is checked on serial)",
    );
    if greet != Some((0, None)) {
        kprintln!("  musl-greet: {greet:?}");
    }

    const PROGRAM: &[u8] = b"/test/filemap";
    let status = run_test_program(PROGRAM, &[PROGRAM]);
    t.check(
        "exec.file_mappings",
        status == Some((0, None)),
        "private file mappings hold the file's bytes at the right offsets (zero past the end), stay private when written, survive a split, and are refused as Linux refuses them (EACCES, EBADF, ENODEV, EINVAL)",
    );
    if status != Some((0, None)) {
        kprintln!("  filemap: {status:?}");
    }

    // A page wholly past the end of the file cannot be filled: Linux sends
    // SIGBUS (mmap(2)); here a kernel copy from it gets EFAULT, while the
    // page holding the file's last byte reads normally.
    use keel_core::vm::{Backing, Placement, Prot};
    use keel_hal::vm::{AddressSpace, copy_from_user, with_address_space};
    const AT: u64 = 0x1000_0000;
    let ino = keel_linux_abi::fs::lookup(PROGRAM).ok();
    let size = ino
        .and_then(|ino| keel_linux_abi::fs::with(|fs| fs.stat(ino)).ok())
        .map(|s| s.size);
    let space = AddressSpace::new().ok();
    let past_end = match (ino, size, space) {
        (Some(ino), Some(size), Some(space)) => {
            let last = (size - 1) / 4096 * 4096;
            let map = |at, offset| {
                let backing = Backing {
                    object: ino,
                    offset,
                    may_exec: false,
                    shared: false,
                    may_write: false,
                };
                space.map_file(
                    Placement::Fixed(at),
                    4096,
                    Prot {
                        read: true,
                        write: false,
                        exec: false,
                    },
                    backing,
                )
            };
            let (a, b) = (map(AT, last), map(AT + 0x10000, last + 4096));
            let mut byte = [0u8; 1];
            let mut magic = [0u8; 4];
            let tail = with_address_space(&space, || copy_from_user(&mut byte, AT));
            let beyond = with_address_space(&space, || copy_from_user(&mut byte, AT + 0x10000));
            let head = map(AT + 0x20000, 0).and_then(|_| {
                with_address_space(&space, || copy_from_user(&mut magic, AT + 0x20000))
                    .map_err(|_| keel_hal::vm::AsError::OutOfMemory)
            });
            a.is_ok()
                && b.is_ok()
                && tail.is_ok()
                && beyond.is_err()
                && head.is_ok()
                && &magic == b"\x7fELF"
        }
        _ => false,
    };
    t.check(
        "exec.file_mapping_past_end",
        past_end,
        "a mapped page wholly past the end of its file is not filled (a copy from it gets EFAULT; Linux sends SIGBUS), while the page holding the last byte and the first page read normally",
    );
}

/// P3-T2: dynamically linked programs. The musl program names
/// /lib/ld-musl-x86_64.so.1, musl's dynamic linker; the kernel loads both
/// and starts the dynamic linker, which runs the program.
fn phase3_dynamic(t: &mut Runner) {
    use keel_core::compartment::Limits;
    use keel_core::elf::ElfError;
    use keel_core::errno::Errno;
    use keel_linux_abi::exec::{self, LoadError};
    use keel_linux_abi::{compartment, fs};

    const PROGRAM: &[u8] = b"/test/musl-dynamic";
    const LDSO: &[u8] = b"/lib/ld-musl-x86_64.so.1";
    let file = fs::read_file(PROGRAM).ok();
    // In the system compartment: the program's line is checked on serial.
    let loaded = file
        .as_ref()
        .and_then(|f| exec::load(f, PROGRAM, &[PROGRAM], &[]).ok());
    let base = loaded.as_ref().and_then(|l| l.interpreter_base);
    let status = loaded.and_then(|l| {
        let spawned = keel_linux_abi::process::spawn("musl-dynamic", &l).ok()?;
        join(spawned.thread);
        sched::exit_status(spawned.thread)
    });
    // The interpreter lies in the mmap area, below the randomized stack,
    // away from the program (loaded near DYN_BASE).
    let placed = base.is_some_and(|b| b > exec::DYN_BASE + (1 << 40) && b % 4096 == 0);
    t.check(
        "exec.dynamic_musl",
        status == Some((0, None)) && placed,
        "a dynamically linked musl program runs: the kernel loads its PT_INTERP (musl's dynamic linker) in the mmap area and starts it, AT_BASE set (its line is checked on serial)",
    );
    if !(status == Some((0, None)) && placed) {
        kprintln!("  musl-dynamic: exit {status:?}, interpreter at {base:#x?}");
    }

    // In a compartment, the interpreter is found in the compartment's own
    // tree: without /lib there the program cannot load (ENOENT), with a
    // copy of the dynamic linker it runs.
    let made = fs::with(|fs| {
        let comp = fs.lookup(keel_core::vfs::ROOT, keel_core::vfs::ROOT, b"/comp")?;
        fs.create_dir(comp, b"bare", 0o755)?;
        let dyn_root = fs.create_dir(comp, b"dyn", 0o755)?;
        let lib = fs.create_dir(dyn_root, b"lib", 0o755)?;
        let ldso = fs.lookup(keel_core::vfs::ROOT, keel_core::vfs::ROOT, LDSO)?;
        let bytes = fs.contents(ldso)?;
        let copy = fs.create_file(lib, b"ld-musl-x86_64.so.1", 0o755)?;
        fs.write(copy, 0, &bytes)?;
        // A static executable as the "interpreter": refused.
        let fixed = fs.create_dir(comp, b"fixed", 0o755)?;
        let lib = fs.create_dir(fixed, b"lib", 0o755)?;
        let startup = fs.lookup(keel_core::vfs::ROOT, keel_core::vfs::ROOT, b"/test/startup")?;
        let bytes = fs.contents(startup)?;
        let copy = fs.create_file(lib, b"ld-musl-x86_64.so.1", 0o755)?;
        fs.write(copy, 0, &bytes)?;
        Ok(())
    });
    let at = |path: &[u8]| compartment::create(path, Limits::UNLIMITED).ok();
    let (Ok(()), Some(file), Some(bare), Some(with_ldso), Some(fixed)) = (
        made,
        file,
        at(b"/comp/bare"),
        at(b"/comp/dyn"),
        at(b"/comp/fixed"),
    ) else {
        t.check(
            "exec.interpreter_in_root",
            false,
            "setting up the interpreter compartments",
        );
        return;
    };
    let missing = exec::load_in(bare.root(), &file, PROGRAM, &[PROGRAM], &[]).err();
    let refused = exec::load_in(fixed.root(), &file, PROGRAM, &[PROGRAM], &[]).err();
    let runs = run_in(&with_ldso, PROGRAM, &[PROGRAM]);
    let ok = missing == Some(LoadError::Interpreter(Errno::ENOENT))
        && refused == Some(LoadError::BadInterpreter(ElfError::BadInterpreter))
        && runs == Some((0, None));
    t.check(
        "exec.interpreter_in_root",
        ok,
        "a compartment's program finds its interpreter in the compartment's tree: ENOENT without one, a fixed-address one refused, a copy of the dynamic linker runs it",
    );
    if !ok {
        kprintln!("  missing {missing:?}, fixed {refused:?}, with ld.so {runs:?}");
    }
}

/// P3-S4 tmpfs, the rest of Phase 2 audit item 1: each compartment's file
/// bytes and nodes are capped on their own. Two compartments with the same
/// quota each reach exactly their own limits, so neither's use is counted
/// against the other, and a file the kernel placed is charged to the
/// compartment that grows it.
fn phase3_tmpfs_quota(t: &mut Runner) {
    use keel_core::compartment::Limits;
    use keel_linux_abi::{compartment, fs};

    const PROGRAM: &[u8] = b"/test/tmpquota";
    const BYTES: usize = 64 << 10;
    const NODES: usize = 8;
    let made = fs::with(|fs| {
        let comp = fs.lookup(keel_core::vfs::ROOT, keel_core::vfs::ROOT, b"/comp")?;
        for name in [&b"qa"[..], b"qb"] {
            let dir = fs.create_dir(comp, name, 0o755)?;
            fs.create_file(dir, b"given", 0o644)?;
        }
        Ok(())
    });
    let limits = Limits {
        tmpfs_bytes: BYTES,
        tmpfs_nodes: NODES,
        ..Limits::UNLIMITED
    };
    let (Ok(()), Ok(a), Ok(b)) = (
        made,
        compartment::create(b"/comp/qa", limits),
        compartment::create(b"/comp/qb", limits),
    ) else {
        t.check(
            "compartment.tmpfs_quota",
            false,
            "creating the quota compartments",
        );
        return;
    };
    let args: [&[u8]; 3] = [PROGRAM, b"65536", b"8"];
    let in_a = run_in(&a, PROGRAM, &args);
    let in_b = run_in(&b, PROGRAM, &args);
    let used = |c: &alloc::sync::Arc<keel_core::compartment::Compartment>| {
        c.tmpfs().map(|q| (q.bytes.used(), q.nodes.used()))
    };
    // After the run: one chunk in /given, and the eight files.
    let expected = Some((4096, NODES));
    let ok = in_a == Some((0, None))
        && in_b == Some((0, None))
        && used(&a) == expected
        && used(&b) == expected;
    t.check(
        "compartment.tmpfs_quota",
        ok,
        "file bytes and nodes are capped per compartment (ENOSPC at exactly 64 KiB and 8 nodes, in each of two compartments); a kernel-made file is charged to the compartment that grows it; truncating gives bytes back",
    );
    if !ok {
        kprintln!(
            "  tmpquota: A {in_a:?} {:?}, B {in_b:?} {:?}",
            used(&a),
            used(&b)
        );
    }
}

/// P3-S4 memory, and security acceptance P3 item 3 for memory: a program
/// that touches more than its compartment's memory limit is ended by the
/// fault at the limit; every frame comes back; the kernel and another
/// compartment carry on.
fn phase3_memory_limit(t: &mut Runner) {
    use keel_core::compartment::Limits;
    use keel_core::errno::Errno;
    use keel_linux_abi::compartment;

    const HOG: &[u8] = b"/test/hog";
    const NAP: &[u8] = b"/test/nap";
    // 17 MiB. Not a multiple of 512: hog needs a new page table every 512
    // pages, so with a limit on that boundary a fault that ignored the
    // limit would still stop exactly at it (the next table is refused).
    const LIMIT: usize = 4352;
    let made = keel_linux_abi::fs::with(|fs| {
        let comp = fs.lookup(keel_core::vfs::ROOT, keel_core::vfs::ROOT, b"/comp")?;
        fs.create_dir(comp, b"hog", 0o755)?;
        fs.create_dir(comp, b"calm", 0o755)
    });
    let limited = |frames| {
        compartment::create(
            b"/comp/hog",
            Limits {
                processes: 4,
                memory_frames: frames,
                ..Limits::UNLIMITED
            },
        )
    };
    let (Ok(_), Ok(hog)) = (made, limited(LIMIT)) else {
        t.check(
            "compartment.memory_limit",
            false,
            "creating the hog compartment",
        );
        return;
    };
    let free_before = memory::free_frames();
    // 64 MiB of touches against a 17 MiB limit.
    let status = run_in(&hog, HOG, &[HOG, b"64"]);
    let used_after = hog.memory().used();
    let free_after = memory::free_frames();
    // Within the limit the same program finishes.
    let small = run_in(&hog, HOG, &[HOG, b"8"]);
    let calm = compartment::create(b"/comp/calm", Limits::UNLIMITED);
    let other = calm.ok().and_then(|c| run_in(&c, NAP, &[NAP, b"10"]));
    // hog touches pages in order from 1 TiB (its BASE): the fault address
    // says how many it touched. Every touched page and every table is
    // charged, so that is at most the limit, and the image, stack and
    // tables take only a few dozen frames, so it is close to the limit.
    const BASE: u64 = 1 << 40;
    let touched = match status {
        Some((_, Some(fault))) if fault.vector == 14 && fault.address >= BASE => {
            Some(((fault.address - BASE) / 4096) as usize)
        }
        _ => None,
    };
    let killed = matches!(touched, Some(pages) if pages <= LIMIT && pages + 64 >= LIMIT);
    let ok = killed
        && used_after == 0
        && free_after == free_before
        && small == Some((0, None))
        && other == Some((0, None));
    t.check(
        "compartment.memory_limit",
        ok,
        "touching 64 MiB in a compartment limited to 17 MiB ends the program at the limit (its fault address is within the limit, near it); all its frames come back; 8 MiB fits; another compartment runs normally",
    );
    if !ok {
        kprintln!(
            "  hog: {status:?}, {touched:?} pages touched, budget after {used_after}, free frames {free_before} -> {free_after}; 8 MiB: {small:?}; other compartment: {other:?}"
        );
    }

    // What the loader populated counts too: a limit below it refuses the
    // process at spawn, with ENOMEM, before it runs.
    let tiny = limited(2).ok().and_then(|c| {
        let file = keel_linux_abi::fs::read_file(HOG).ok()?;
        let loaded = keel_linux_abi::exec::load(&file, HOG, &[HOG], &[]).ok()?;
        let charged = loaded.space.charged_frames();
        let refused = keel_linux_abi::process::spawn_in(&c, "hog", &loaded).err();
        Some((charged, refused, c.memory().used(), c.processes()))
    });
    let refused = matches!(tiny, Some((charged, Some(Errno::ENOMEM), 0, 0)) if charged > 2);
    t.check(
        "compartment.memory_limit_at_spawn",
        refused,
        "a program whose loaded image already exceeds its compartment's memory limit is refused at spawn with ENOMEM, charging nothing",
    );
    if !refused {
        kprintln!("  tiny limit: {tiny:?}");
    }
}

/// A short fuzzing smoke test in every phase 1 boot: three runs of 200
/// calls with fixed seeds (the full session is `cargo xtask fuzz`).
pub fn phase1_fuzz_smoke(t: &mut Runner) {
    let report = fuzz_session(0x6b65_656c, u64::MAX, 3, 200, false);
    t.check(
        "fuzz.smoke",
        report.hung.is_none() && report.runs == 3 && report.worst_wake_ms <= FUZZ_MAX_WAKE_MS,
        "three runs of random system calls end without a kernel panic or a hung call",
    );
    kprintln!(
        "  fuzz smoke: {} runs, {} system calls, {} ended by a fault",
        report.runs,
        report.calls,
        report.faulted
    );
}

/// Security acceptance P1 item 4: a write through a read-only handle (and
/// a read through a write-only one) fails, and it is the rights check
/// that refuses it: the kernel's count of rights refusals rises by exactly
/// the two calls `user/tests/rights` makes on purpose, and its write to a
/// closed descriptor does not count.
pub fn phase1_rights(t: &mut Runner) {
    const PATH: &[u8] = b"/test/rights";
    let before = keel_linux_abi::syscall::rights_refusals();
    let status = keel_linux_abi::fs::read_file(PATH).ok().and_then(|file| {
        let loaded = keel_linux_abi::exec::load(&file, PATH, &[PATH], &[]).ok()?;
        let spawned = keel_linux_abi::process::spawn("rights", &loaded).ok()?;
        join(spawned.thread);
        sched::exit_status(spawned.thread)
    });
    let refused = keel_linux_abi::syscall::rights_refusals() - before;
    t.check(
        "security.rights_refuse_write",
        status == Some((0, None)) && refused == 2,
        "writing through a read-only handle fails, refused by the rights check (not a bad descriptor)",
    );
    if status != Some((0, None)) || refused != 2 {
        kprintln!("  rights: exit {status:?}, {refused} rights refusals (expected 2)");
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
    // P3-T12: COM1's input reaches /dev/console too, by its interrupt:
    // "kel", DEL (erasing the l), "el", Enter (CR), Ctrl+D, through the
    // UART's loopback mode.
    let serial = keel_linux_abi::fs::read_file(b"/test/readline")
        .ok()
        .and_then(|file| {
            let loaded = exec::load(&file, b"/test/readline", &[b"/test/readline"], &[]).ok()?;
            let spawned = keel_linux_abi::process::spawn("readline", &loaded).ok()?;
            sched::sleep_ms(20);
            let was_waiting = sched::exit_status(spawned.thread).is_none();
            let typed = keel_linux_abi::tty::type_serial(b"kel\x7fel\r\x04");
            // Up to two seconds for it to finish; if the line never came,
            // the keyboard ends it, so a failure cannot hang the run.
            let mut arrived = false;
            for _ in 0..200 {
                if sched::exit_status(spawned.thread).is_some() {
                    arrived = true;
                    break;
                }
                sched::sleep_ms(10);
            }
            if !arrived {
                let keys = [
                    0x25, 0xa5, 0x12, 0x92, 0x12, 0x92, 0x26, 0xa6, 0x1c, 0x9c, 0x1d, 0x20, 0xa0,
                    0x9d,
                ];
                let _ = keel_linux_abi::tty::type_scancodes(&keys);
            }
            join(spawned.thread);
            Some((
                was_waiting,
                typed && arrived,
                sched::exit_status(spawned.thread)?,
            ))
        });
    t.check(
        "console.serial_line",
        serial == Some((true, true, (0, None))),
        "a program blocked reading /dev/console gets a line typed on COM1 (received by interrupt, edited by the line discipline), then end of file",
    );
    if serial != Some((true, true, (0, None))) {
        let (interrupts, bytes) = keel_hal::console::serial_input_counts();
        kprintln!("  serial: {serial:?}; COM1 interrupts {interrupts}, bytes {bytes}");
    }

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
