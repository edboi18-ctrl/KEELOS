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
| P1-T5 | Kernel heap allocator | Done. `hal::heap`: eight power-of-two size classes (16 B to 2 KiB) plus whole-page allocations in a dedicated RW+NX region, each large allocation followed by an unmapped guard page; frames go back to the allocator on free. Host tests for the allocator core; in-kernel test with 22,000 live objects and a 1 MiB allocation. Virtual addresses of freed large allocations are reused since F-0009 (they were not at first). |
| P1-T6 | ACPI MADT; local APIC and I/O APIC; legacy PIC masked | Done. Own ACPI parser in `keel-core` (ADR 0004), fed only byte ranges inside ACPI memory regions. Local APIC in xAPIC (MMIO) or x2APIC (MSR) mode, whichever the firmware left; I/O APICs mapped with all inputs masked; ISA IRQ routing honours MADT overrides. Device registers are mapped uncached through `paging::map_mmio`, which refuses addresses that overlap RAM (SR-20). The x2APIC path is untested: OVMF leaves xAPIC mode on. |
| P1-T7 | Timer and monotonic clock | Done. HPET as reference; APIC timer and TSC calibrated against it over 10 ms; 1 kHz periodic tick; monotonic clock from the TSC when invariant, else the HPET. Under QEMU TCG no invariant TSC is reported, so the TSC path runs only under KVM and on real hardware. No PIT fallback yet if a machine has no HPET (to check on the OptiPlex in Phase 6). |
| P1-T8 | Kernel threads, context switch, preemptive round-robin scheduler, sleep and wait queues, FPU/SSE/AVX state | Done. Each thread has a 64 KiB kernel stack with an unmapped guard page and its own XSAVE area (FXSAVE where XSAVE is missing), sized from CPUID; XCR0 enables x87, SSE, AVX, and AVX-512 when complete. 10 ms time slices from the 1 kHz tick; switches happen after the EOI. The heap, page-table, frame and scheduler locks disable interrupts while held, so no thread is preempted holding one. Tests: round robin, preemption of a non-yielding thread, sleep accuracy, wait-queue wake-up, XMM isolation across 400 switches (checked to fail when save/restore is removed), reclamation of exited threads, and a stack-overflow scenario caught on the guard page. |
| P1-T9 | Address spaces: VMAs, demand paging, copy-on-write, free PROT_NONE reservations | Done for anonymous memory. VMA bookkeeping (mmap/munmap/mprotect semantics incl. MAP_FIXED, MAP_FIXED_NOREPLACE and splitting) in `keel-core::vm` with host tests; page-table side in `hal::vm`. Writable+executable user mappings refused (SR-12). Every address space shares the kernel's upper half (all 256 entries pre-created at boot). File-backed and shared mappings come with the VFS (P1-T12, P3-T7). Tests: 64 GiB reservation costs no frames (acceptance item 4), demand paging, mprotect, copy-on-write isolation, teardown returns all frames. |
| P1-T10 | Ring 3 entry and the `syscall` path | Done, with returns by IRETQ instead of SYSRET and no SWAPGS (ADR 0005). STAR/LSTAR/FMASK set, EFER.SCE on; Linux register convention; `exit`, `exit_group` and a temporary test call (0x1000, since removed: the built-in test programs now check an ENOSYS result instead, and `user/tests/syscalls` checks that 0x1000 is ENOSYS); unknown numbers return ENOSYS and are logged once (`docs/syscalls.md`). User faults end the thread with 128 + signal. User RFLAGS sanitized on every return (IOPL 0, SR-9). Tests: syscall round trip, all callee registers preserved, ENOSYS, CLI and port I/O refused, user code read-only, user stack no-execute, UMIP, kernel survives every refused program. |
| P1-T11 | Static ELF64 loader; initial stack with argc/argv/envp and auxiliary vector | Done. Parser in `keel-core::elf` (safe, every offset checked; ET_EXEC and static-PIE ET_DYN; refuses PT_INTERP until P3-T2, W+X segments, executable-stack requests, overlapping or misaligned segments, anything outside the user half). Stack builder in `keel-core::exec` per psABI Figure 3.9 (AT_PHDR, AT_PHENT, AT_PHNUM, AT_PAGESZ, AT_BASE, AT_FLAGS, AT_ENTRY, AT_SECURE, AT_RANDOM, AT_EXECFN). Loader in `keel-kernel::exec`, no `unsafe`. AT_RANDOM from RDRAND after a Linux-style self-test, else a weak interim source that reports itself (P1-S5 replaces it). Host tests and random-input loops for both parsers. In-kernel: `user/tests/startup`, a real static Rust executable, checks its own entry state (alignment, RDX = 0, DF = 0, argv, envp, auxv, AT_PHDR, AT_RANDOM, AT_EXECFN, .data, .bss, 256 KiB of stack) under Keel, and the same binary passes under Linux (`host.startup`). Also: malformed files refused, failed loads return their frames, no W+X page in a loaded program. |
| P1-T12 | cpio unpacker into tmpfs; minimal VFS with path lookup; `/dev/console`, `/dev/null`, `/dev/zero`, `/dev/urandom` | Done. `keel-core::cpio` reader and `keel-core::vfs` tmpfs (safe Rust, host tests, random-path test that no lookup leaves its root). Lookup takes an explicit root; `..` at the root stays there (SR-4 groundwork); PATH_MAX/NAME_MAX enforced; 256 MiB cap on file data. Archive names with `.`/`..` components are refused; symlinks and device members are skipped (no symlinks yet). Device nodes only from a fixed list, so `/dev/mem`, `/dev/kmem`, `/dev/port` cannot exist (SR-9). Console output from user programs is filtered to text (no escape sequences). Console input reads as end of file until P1-T14; `/dev/urandom` uses the interim source until P1-S5. Built at every boot; the loader now reads `/test/startup` through it. |
| P1-T13 | First syscalls: write, writev, read, openat, close, fstat, mmap, munmap, mprotect, brk, arch_prctl, set_tid_address, exit, exit_group, ioctl (TTY stubs), getrandom, clock_gettime | Done; details and limits per call in `docs/syscalls.md`. New crate `kernel/linux-abi` (`#![deny(unsafe_code)]`) holds the syscalls, processes, the root filesystem and the loader; `hal::syscall` only moves registers to the registered handler. Per-thread user FS/GS bases (arch_prctl) switched with the thread; only user addresses accepted. Unknown calls log their Linux name once (name table generated from `syscall_64.tbl`) and return ENOSYS. Test: `user/tests/syscalls` passes under Linux and Keel; checked to fail when a kernel check is broken on purpose. Not yet: file-backed and shared mmap, terminal state ioctls, a real-time clock, console input. |
| P1-T14 | PS/2 keyboard driver feeding `/dev/console` input (QEMU only) | Done. `hal::drivers::ps2` sets up the i8042 (translation on, keyboard interrupt on IRQ 1, all waits bounded; no controller is reported, not fatal). `keel-core::keyboard` decodes scancode set 1 (US layout, Shift, Ctrl, Caps Lock, keypad Enter and slash; Print Screen's fake shifts and Pause ignored) and `keel-core::tty` is a canonical line discipline with Linux's default settings (ICRNL, echo, erase, kill, Ctrl+D end of file; Ctrl+C discards the line until signals exist). The interrupt handler only takes IRQ-safe locks; echo is printed by a kernel thread. `read` on the console blocks until a line is ready, with no lock held. Test: `user/tests/readline` reads a line and end of file, piped on Linux and typed through the controller (command 0xD2) on Keel. On the OptiPlex, keyboards are USB: whether firmware emulates an i8042 is checked in Phase 6, where the USB HID driver replaces this path. |
| P1-S2 | NX, WP, SMEP, SMAP, UMIP; one checked user-copy API | Done. `hal::vm::copy_to_user`/`copy_from_user` are the only code that touches user memory: they check the range against the user half with checked arithmetic, lift SMAP (STAC/CLAC) only around one `rep movsb`, resolve demand-paging faults, and turn anything else into EFAULT through a fixup. Tests: bad-pointer sweep (kernel, null, unmapped, straddling, wrapping) and a `smap` scenario proving a direct kernel read of a present user page faults. Both the SMAP and no-SMAP routines are exercised. |
| P1-S3 | Page-table isolation with a trampoline entry path | Done. Each address space has a kernel view and a user view; the user view's kernel half is one top-level entry mapping only `.text.keel_entry` (RX), `.data.keel_entry` and `.bss.keel_entry` (RW+NX). Every entry switches to the kernel view; every exit to user mode switches back from the trampoline stack. Always on until P1-S4 reads RDCL_NO; no PCIDs yet. Tests: `pti.user_view` (walks the user view: only trampoline pages, no W+X), `pti.kernel_absent` (user reads of kernel text, rodata, data, direct map and heap find no page). Finding F-0001 fixed on the way (`user.ac_cleared_on_entry`). |
| P1-S1 | Object table with a rights mask from its first version; every syscall handler names the right it requires | Done. `keel-core::handle`: rights from SR-1's list, checked on every lookup, lowest-free descriptor allocation, duplicate only removes rights, per-process limit 1024 (host tests). The process table is a `HandleTable`; there is no other descriptor table. Rights per call in `docs/syscalls.md`. |
| P1-S4 | Boot-time vulnerability report and mitigation selection; one log line per item | Done (ADR 0007). `keel-core::cpuvuln` assesses 17 items from CPUID, IA32_ARCH_CAPABILITIES and IA32_MCU_OPT_CTRL (host tests for the target with and without current microcode, newer CPUs, hypervisors, unknown models); `hal::mitigations` applies the plan: legacy IBRS on entry/exit (or enhanced IBRS once), SSBD, BHI_DIS_S when needed, IBPB between address spaces, RSB fill on every context switch, VERW before every return to user mode, SRBDS/GDS microcode controls on. Spectre v1: branch-free index masking for syscall numbers and descriptors. L1TF: no not-present entry holds bits (checked in every page-table walk). The boot log has one `vuln:` line per item; `cargo xtask test` prints them. Found and fixed on the way: F-0002. Where the mitigations run: QEMU's emulator advertises none of the speculation-control features but accepts the MSR writes, so `vuln.ibrs_entry_path` forces the IBRS entry/exit and IBPB paths on there and runs the whole syscall conformance program through them; CI's KVM guest (an Ice Lake server CPU inside GitHub's own virtual machine) hides IBRS/IBPB/SSBD entirely but raises #GP for missing MSRs, which proves the fault path (`cpu.msr_safe`). The CPU's actual speculation behaviour under these mitigations can only be confirmed on the OptiPlex (P6-S6). Not implemented: software BHB clearing and ITS mitigations (neither applies to the target). |
| P1-S5 | Kernel and user address-space randomization; entropy source | Done. (The intermittent timeout seen after these changes was F-0004, a console-lock deadlock older than P1-S5, now fixed.) Entropy: `keel-core::crypto` (ChaCha20, RFC 8439; BLAKE2s, RFC 7693; checked against the RFCs' vectors including the RFC 7693 self-test) and `keel-core::rng` (BLAKE2s pool, ChaCha20 fast key erasure, as Linux's random.c); `hal::random` seeds it at boot from RDSEED, RDRAND (after its self-test) and TSC jitter, adds timer and keyboard interrupt timing, reseeds every 60 s, never runs unseeded, and reports whether a hardware source contributed. AT_RANDOM, getrandom and /dev/urandom use it. KASLR: Limine `kaslr: yes` (the kernel is a PIE), which also randomises the HHDM base; `cargo xtask test` checks that the boots of a phase land at different addresses. User ASLR with Linux's ranges: stack top (22 bits of pages), mmap base and PIE load bias (28 bits), program break (1 GiB). Found on the way: F-0003. |
| P1-S6 | Kernel stack guard pages; zero-on-allocate for user frames; zeroed copy-out buffers; overflow checks in release | Done. Every kernel stack, now including the boot thread's (boot leaves Limine's unguarded stack for a 128 KiB kernel stack right after paging is up), has an unmapped guard page; an overflow becomes a double fault on IST1 and a clean panic (`stack_overflow` scenario). Stack probes: the pinned target (`x86_64-unknown-none`, Rust 1.100.0) sets `stack_probes: StackProbeType::Inline`, and the kernel binary contains the probe sequence. RELRO: `.data.rel.ro` and `.got` have their own segment, mapped read-only after Limine relocates them. Frames are zeroed on allocation (SR-18), structures copied to user space are built in zeroed buffers, and `overflow-checks = true` in release. Tests: `paging.boot_stack_guard`, `paging.relro`, `frames.zeroed`. |
| P1-S7 | No identity checks; no forbidden device nodes; unknown syscalls and flags fail closed | Done (verification). SR-6: a sweep of `kernel/` and `user/` finds no check on user or group IDs or set-ID bits anywhere; uid and gid are reported as 0 and never consulted, and the loader ignores mode bits. SR-9: device nodes come from a fixed list (`fs.no_forbidden_devices`); user port I/O and CLI fault (`user.no_port_io`, `user.no_cli`). SR-10: unknown system calls return ENOSYS (`user.unknown_syscall`, conformance check on number 500); unknown flags or codes are EINVAL for openat, mmap, mprotect, getrandom, clock_gettime, arch_prctl, and ENOTTY for ioctl requests, all in `user/tests/syscalls`. |

Phase 1 acceptance progress: item 1 (a static musl C "hello world" runs
as PID 1 and prints to serial) is covered by `acceptance.musl_hello_pid1`
plus the serial check in `cargo xtask test`, using `fixtures/musl-hello`
(reference build by the owner with Docker Desktop, SHA-256 aa498cc9...,
checked by xtask before use; also run natively under Linux as
`host.musl-hello`). The fixture lives in `fixtures/`, not `initramfs/`, so
it is not shipped in release images. Item 3 (a null dereference
kills only that program, with a logged fault) is `acceptance.null_dereference`
plus the serial check for the fault line. Item 4 (64 GB
`mmap(PROT_NONE, MAP_NORESERVE)` with no measurable memory use) is
`acceptance.reserve_64gib`, run by `user/tests/reserve`, which also passes
under Linux: 64 GiB mapped, 16 KiB resident, 12 frames used during the run.
Item 2 (a Rust x86_64-unknown-linux-musl program, 64 MB heap checksum,
identical output on Linux and Keel) is `acceptance.rust_std_heap64`:
`user/std-tests/heap64`, built with the real standard library for the
musl target (static PIE, linked by `rust-lld` with the target's bundled
musl start files, so no C toolchain is needed and it builds on Windows),
runs under Linux (`host.heap64`) and under Keel, and both must print
`heap64: 67108864 bytes in 16384 pages, checksum 0x7f282b735ac8d3f2`
(checked against that fixed line in both places). Its startup needed
`poll`, `rt_sigaction`, `rt_sigprocmask` and `sigaltstack`, now
implemented (state only for the signal calls; ADR 0008) and covered by
`user/tests/syscalls` on both systems. All four Phase 1 acceptance items
are now covered; the temporary test syscall is removed; the phase stays
open for the remaining checks.

Phase 1 security acceptance progress: item 2 (hostile-pointer sweep over
every implemented syscall) is covered by `user/tests/syscalls`, on Keel
and on Linux. Item 1 (page-table self-test) is
covered for kernel tables by `paging.wx_walk` and for user views by
`pti.user_view`. Item 3 is covered by the `write_kernel_text` and
`execute_data` scenarios for the kernel and by `user.code_read_only` and
`user.stack_no_execute` for user programs. Item 4 (a write through a
read-only handle fails, and the test asserts it was the rights check) is
`security.rights_refuse_write`: `user/tests/rights` (also passes under
Linux) makes one write through a read-only handle and one read through a
write-only one, and the kernel's count of rights refusals
(`keel_core::handle::Refusal::MissingRights`, counted in
`linux-abi::syscall::file`, the one place descriptors are resolved) must
rise by exactly 2, while its write to a closed descriptor does not count;
checked to fail with the rights check disabled. Item 5 (boot log lists each
vulnerability and mitigation) is `vuln.report_complete` and
`vuln.plan_applied`. Item 6 (one hour of random-syscall fuzzing):
`cargo xtask fuzz --minutes N [--seed S]` boots the in-guest fuzzer
(`keel_rt::fuzz`, `user/tests/fuzz`: seeded random system calls with
structure-aware arguments; Keel only, it refuses to run without
`/etc/keel-release` and is never run on the host). The kernel harness
starts runs back to back, logs each seed, and fails on a kernel panic, a
run that does not end within 10 minutes, or a harness wake-up more than
5 s late (kernel not preempting). Every phase 1 boot also runs a short
smoke (`fuzz.smoke`). The first sessions found F-0005 to F-0008, all
fixed with regression tests, and a check of frame use after the first
one-hour session found F-0009 (also fixed). **Passed on the final code:**
`cargo xtask fuzz --minutes 60 --seed 20261122` (no KVM): 62 runs,
124,434 system calls, 3,781 s, no panic, no hung run, worst harness
wake-up delay 702 ms. Free frames went 1,034,119 → 1,034,108. All 11
frames are accounted for: kernel page tables 282 → 290, level from run 9
onward (the high-water mark of kernel address space), and heap pages
173 → 176. No address spaces were left alive, tmpfs grew by 0 bytes, and
0 heap pages were lost.
`.github/workflows/security.yml` (nightly and manual) runs four
60-minute fuzz shards with distinct seeds under KVM and keeps each serial
log; it is on the working branch for the owner to review and merge
(SR-36).

Hardening notes for later Phase 1 work:
- User programs share the serial line with the kernel's `TEST` report lines,
  so a hostile program could print a forged result. Harmless while only our
  own programs run; before the escape suite (P3-S8) runs hostile code, test
  results must travel on a channel user code cannot write (for example a
  second serial port, or the debug-exit code).

## Test results (local, QEMU 8.2.2 TCG, OVMF, Ubuntu 24.04)

- `cargo xtask test`: 9 in-kernel tests pass, `KEEL P0 OK` on serial and
  read back from the framebuffer, plus `sr27.tamper.kernel` and
  `sr27.tamper.initramfs` (Limine refuses a one-byte change).
- `cargo test`: 84 host unit tests pass (30 `keel-core`, 26 `keel-hal`, 28 `xtask`).
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
| `kernel/hal` | 130 | 404 | 39 | 16 |
| `kernel/keel-kernel` | 0 | 0 | 0 | 1 |
| `user/keel-rt` | 18 | 86 | 5 | 1 |

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
instructions, RDTSC, and the interrupt handler table; then P1-T8: the
context switch and new-thread frame, XSAVE/FXSAVE save and restore,
XSETBV, the save-area allocation, the interrupt-disabling lock, and
three self-test helpers (XMM0 access, stack overflow); then P1-T9: the
user-copy routines (the one sanctioned place for user-memory access),
frame copying, and the SMAP self-test read; then P1-T10/P1-S3: the
SYSCALL MSR setup, the entry/exit trampoline (`global_asm!`, one
reasoning block), the user test programs, and loading CR3 for the
two page-table views; then P1-T11: RDRAND in `hal::random`. then P1-T13: the
FS/GS base MSR writes in `hal::sched`; then P1-T14: the i8042 port accesses
and the keyboard callback conversion in `hal::drivers::ps2`; then P1-S4: rdmsr_safe and
wrmsr_safe, the mitigation MSR writes, IBPB, the cmp/sbb index mask,
and the mitigation block in the trampoline data (one `link_section`).
Then P1-S5: RDSEED. Then P1-S6: the switch to the boot stack and reading RSP. `user/keel-rt` is
the user-space runtime (ADR 0006), plus `syscall6`, the internal wrappers
of the safe `sys` module, and one FS-relative read for the FS-base test: `_start`, the initial-stack reader and
the `syscall` wrapper. The single kernel item outside `hal` is `#[unsafe(no_mangle)]` on the kernel
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
