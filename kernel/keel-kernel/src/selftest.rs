//! In-kernel self-tests, run at boot when the command line contains
//! `test=<phase>` (spec section 15, "Kernel integration" layer).
//!
//! Output format, parsed by `cargo xtask test`:
//!   `TEST <name> PASS|FAIL <detail>` per test, then one
//!   `TEST SUMMARY passed=<n> failed=<m>` line.
//!
//! The test flag only adds checks; it disables no security control
//! (SR-21).

use keel_hal::boot::{self, RegionKind};
use keel_hal::{console, kprintln};

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

struct Runner {
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

/// Runs the self-tests for `phase` and returns whether all passed.
pub fn run(phase: u32) -> bool {
    let mut runner = Runner {
        passed: 0,
        failed: 0,
    };
    match phase {
        0 => phase0(&mut runner),
        _ => runner.check("selftest.phase", false, "unknown phase requested"),
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
