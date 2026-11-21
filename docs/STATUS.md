# Status

Updated at the end of every working session so a fresh session can
resume from here.

## Phase 0 (toolchain and first boot): ACCEPTED 2026-11-21

- Acceptance P0: `cargo xtask test --phase 0` passes locally on Linux,
  on the owner's Windows PC, and in CI.
- CI acceptance P0: `ci` run 44946991701 passed on `main` at
  `1502eb9` (the merge of PR #1). Tag `v0.0.1` on that commit ran
  `release` (run 44948575379), which published the zip, the disk image,
  the notices and `SHA256SUMS` with a build-provenance attestation. On
  the owner's PC, `cargo xtask verify` reported all three artifacts
  verified (checksum and attestation from `release.yml@refs/tags/v0.0.1`
  on a GitHub-hosted runner).
- The owner carried out `docs/REPOSITORY-SETUP.md`, sections 1 to 6.

| ID | Task | Status |
| --- | --- | --- |
| P0-T1 | Workspace, `rust-toolchain.toml`, xtask skeleton | Done. Built on the owner's Windows PC after the line-ending fix (`.gitattributes`). |
| P0-T2 | Pinned Limine download with checksum; `target/esp` | Done (Limine 12.9.6) |
| P0-T3 | Limine protocol entry; higher-half linker script | Done (own bindings, ADR 0002; base revision 6) |
| P0-T4 | COM1 serial, `kprintln!`, panic handler | Done |
| P0-T5 | Framebuffer text console mirroring serial | Done |
| P0-T6 | `cargo xtask test` harness | Done |
| P0-T7 | `ci.yml` | Done: run 44011447886 on the working branch passed both jobs (audit and host tests; QEMU with KVM on a hosted runner). Not yet run on `main`. |
| P0-T8 | `xtask dist`, `release.yml`, `xtask verify` | Written; artifacts build and the disk image boots in OVMF. The attestation path can only be exercised by a real tagged release. |
| P0-T9 | Repository setup checklist | Written: `docs/REPOSITORY-SETUP.md`. Owner to carry out. |
| P0-S1 | Verified downloads; BLAKE2B hashes in `limine.conf` | Done, with a tamper test for kernel and initramfs |
| P0-S2 | `cargo xtask audit` | Done |

## Phase 1 (kernel core): in progress

Started 2026-11-21 at the owner's request. P1-T1 to P1-T3 were merged
to `main` with PR #1.

| ID | Task | Status |
| --- | --- | --- |
| P1-T1 | GDT, TSS with RSP0 and IST stacks | Done. Linux-compatible selectors; no 32-bit user code segment; no I/O bitmap (SR-9). IST stacks lack guard pages until P1-T4. |
| P1-T2 | IDT, exception handlers with register dump, double fault on its own stack | Done. Tests: `idt.breakpoint` (INT3 round trip preserves registers), scenario `double_fault` (#DF lands on IST1). |
| P1-T3 | Physical frame allocator with per-frame reference counts | Done. Logic in `kernel/core` (`#![forbid(unsafe_code)]`), host unit tests; `hal::memory` zeroes every frame on allocation (SR-18). Boots with 256 MB to 13 GB of RAM; bookkeeping is about 0.06% of RAM (8 MB at 13 GB). |
| P1-T4 | Kernel page tables with W^X; NX, WP, SMEP, SMAP, UMIP | Done. Table logic in `keel-core` (host tests); `hal::paging` builds a fresh PML4 (kernel text RX, rodata R, data RW+NX, direct map RW+NX with the framebuffer write-combining, nothing in the lower half), switches CR3 and enables every protection CPUID reports. The kernel image has no alias in the direct map. IST stacks now have unmapped guard pages (SR-17). |
| P1-T5 | Kernel heap allocator | Done. `hal::heap`: eight power-of-two size classes (16 B to 2 KiB) plus whole-page allocations in a dedicated RW+NX region, each large allocation followed by an unmapped guard page; frames go back to the allocator on free. Host tests for the allocator core; in-kernel test with 22,000 live objects and a 1 MiB allocation. Virtual addresses of freed large allocations are not reused yet (64 GiB region). |
| P1-T6 | ACPI MADT; local APIC and I/O APIC; legacy PIC masked | Done. Own ACPI parser in `keel-core` (ADR 0004), fed only byte ranges inside ACPI memory regions. Local APIC in xAPIC (MMIO) or x2APIC (MSR) mode, whichever the firmware left; I/O APICs mapped with all inputs masked; ISA IRQ routing honours MADT overrides. Device registers are mapped uncached through `paging::map_mmio`, which refuses addresses that overlap RAM (SR-20). The x2APIC path is untested: OVMF leaves xAPIC mode on. |
| P1-T7 | Timer and monotonic clock | Done. HPET as reference; APIC timer and TSC calibrated against it over 10 ms; 1 kHz periodic tick; monotonic clock from the TSC when invariant, else the HPET. Under QEMU TCG no invariant TSC is reported, so the TSC path runs only under KVM and on real hardware. No PIT fallback yet if a machine has no HPET (to check on the OptiPlex in Phase 6). |
| P1-T8 to P1-T14 | | Not started |
| P1-S2 | NX, WP, SMEP, SMAP, UMIP; one checked user-copy API | Protections done with P1-T4. The user-copy API arrives with user mode (P1-T10). |
| P1-S1, P1-S3 to P1-S7 | | Not started. Entry code and data are already grouped in page-aligned sections for P1-S3. |

Phase 1 security acceptance progress: item 1 (page-table self-test) is
covered for kernel tables by `paging.wx_walk`; the user-table half needs
user mode. Item 3's kernel half is covered by the `write_kernel_text`
scenario, plus `execute_data` for NX; the user-program half needs user
mode.

Hardening notes for later Phase 1 work:
- `.data.rel.ro` and `.got` stay writable after the bootloader relocates
  them. Making them read-only after boot (RELRO) is a small follow-up.
- The kernel still runs on Limine's boot stack, which has no guard page;
  kernel threads (P1-T8) get their own guarded stacks.

## Test results (local, QEMU 8.2.2 TCG, OVMF, Ubuntu 24.04)

- `cargo xtask test`: 9 in-kernel tests pass, `KEEL P0 OK` on serial and
  read back from the framebuffer, plus `sr27.tamper.kernel` and
  `sr27.tamper.initramfs` (Limine refuses a one-byte change).
- `cargo test`: 77 host unit tests pass (23 `keel-core`, 26 `keel-hal`, 28 `xtask`).
- `cargo xtask audit`: passes, including RustSec advisories.
- `cargo xtask dist` + `cargo xtask boot-check`: the GPT/FAT32 image
  boots under OVMF.

Known failing tests: none.

## First boot on the target machine (2026-11-21)

The owner built the image on Windows, wrote it to a USB stick, and booted
the OptiPlex 3060 (Secure Boot off). Not a phase gate, since bare metal
is Phase 6, but it confirms the boot path on real UEFI firmware. The
screen showed every boot line through `Keel: nothing more to run yet;
halting.`:

- Limine base revision 6 honoured.
- Framebuffer console 120x67 characters, so the GOP mode is 1920x1080
  (16-pixel cells).
- 39 memory-map regions, 7679 MiB usable (8 GB installed).
- ACPI RSDP found; initramfs module loaded.
- `serial COM1 ok`: a 16550 UART answered the loopback test at I/O port
  0x3F8. That shows the UART exists in the chipset or Super I/O; it does
  not show a serial connector is fitted on the back panel.

## `unsafe` budget

From `cargo xtask audit` (our code only; includes test code):

| Crate | Blocks | Block lines | Declarations | Attributes |
| --- | --- | --- | --- | --- |
| `kernel/hal` | 83 | 270 | 28 | 13 |
| `kernel/keel-kernel` | 0 | 0 | 0 | 1 |

The increase since Phase 0 (from 29 blocks) is the GDT/TSS/IDT setup,
the CPU register reads, and the self-test triggers, each with its
reasoning block; then three blocks in `hal::memory` (carving the
allocator's bookkeeping, zeroing frames, frame access for tests); then
P1-T4: control-register and MSR access, the page-table memory accessor,
the CR3/CR4 switch, and two fault-triggering self-tests; then P1-T5:
TLB invalidation and the heap's free-list and GlobalAlloc code (the
`unsafe impl GlobalAlloc` is unavoidable for a Rust allocator); then
P1-T6/T7: APIC register access (MMIO and MSR), I/O APIC and HPET
register access, the ACPI physical-memory reader, interrupt-flag
instructions, RDTSC, and the interrupt handler table. The single item outside `hal` is `#[unsafe(no_mangle)]` on the kernel
entry point, which the audit allows by exact file and count.

## Image hashes

Release v0.0.1 (commit `1502eb9`, built by CI):

```
d561819723b1fb0c21816f0d87be2bce42d27a7f64bbcb206b9e867060af756b  keel-0.0.1-esp.zip
a658ffbdad33cb31a3bdec9d3a4cabc9ea1ba0f802a3066669317ed8c13b4307  keel-0.0.1.img
54e902d64c8bb3a7faa5460464e398e8bf9bb66c706065cb95548ead8dcb3f38  keel-0.0.1-notices.zip
```

The formal reproducibility gate (two independent CI jobs comparing
hashes) is Phase 4 work (SR-30).

## Decisions made by the owner (2026-11-17)

- License: MIT OR Apache-2.0 for the kernel and native user space.
- The agent may push its working branch; pull requests only on request.
- One-time exception: the agent seeded `main` with the license and README.
- Own Limine protocol bindings instead of the `limine` crate (ADR 0002).

## Deviations from the spec and things not built yet

- ADR 0001: downloads use the system `curl` and `tar`.
- ADR 0002: own Limine bindings (deviation from D4).
- Dual license files are named `LICENSE-MIT` and `LICENSE-APACHE` rather
  than a single `LICENSE`. There is no `LICENSES/` directory: release
  notices are collected by `xtask dist` from the verified Limine archive
  and `vendor/`.
- The spec's "source bundle" release artifact is, in Phase 0, the
  `-notices.zip` of license texts. Wine sources join it in Phase 4.
- `wine-image.yml` and `security.yml` do not exist yet: there is no Wine
  build and no fuzzer or escape suite before Phases 1 to 4.
- `cargo xtask usb`, `linux-test`, and `wine-build` are not implemented;
  they belong to later phases.
- KASLR (`kaslr: yes` in `limine.conf`) is off until P1-S5. The kernel is
  already linked position-independent so it can be turned on then.
- QEMU and OVMF come from the runner's distribution packages and are not
  hash-pinned; they are test tools, not image inputs.

## Open items for the owner

1. Still open from the spec: which video output is in use, whether a USB
   mouse is available, whether a serial connector is on the back panel
   (a UART does answer at COM1); the first third-party GUI target after
   Notepad; any time budget per phase.
2. The `gh` login on the owner's PC uses the CLI's default scopes
   (`repo`, `workflow`, `gist`, `read:org`). Verifying releases of a
   public repository needs none of them; that is the owner's call.

## Notes

- Limine's source repository contains an `AGENTS.md` addressed to coding
  agents contributing to Limine. It was read as data while pinning the
  release and not acted on; Keel does not modify Limine.
