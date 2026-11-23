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
| P0-T9 | Repository setup checklist | Done: `docs/REPOSITORY-SETUP.md` written by the agent and carried out by the owner (checklist ticked, pull request #4). |
| P0-S1 | Verified downloads; BLAKE2B hashes in `limine.conf` | Done, with a tamper test for kernel and initramfs. Since audit finding 2, the config's own BLAKE2B is enrolled in the shipped `BOOTX64.EFI` (ADR 0010), with a third tamper test. The boot chain detects corruption; it is not a verified boot until the executable is signed and Secure Boot is on (owner, SR-34). |
| P0-S2 | `cargo xtask audit` | Done |

## Phase 1 (kernel core): complete (2026-11-22)

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
| P1-S5 | Kernel and user address-space randomization; entropy source | Done. (The intermittent timeout seen after these changes was F-0004, a console-lock deadlock older than P1-S5, now fixed.) Entropy: `keel-core::crypto` (ChaCha20, RFC 8439; BLAKE2s, RFC 7693; checked against the RFCs' vectors including the RFC 7693 self-test) and `keel-core::rng` (BLAKE2s pool, ChaCha20 fast key erasure, as Linux's random.c); `hal::random` seeds it at boot from RDSEED, RDRAND (after its self-test) and TSC jitter, adds timer and keyboard interrupt timing, reseeds every 60 s, never runs unseeded, and reports whether a hardware source contributed. AT_RANDOM, getrandom and /dev/urandom use it. KASLR: Limine `kaslr: yes` (the kernel is a PIE), which also randomises the HHDM base; the kernel heap, device-register and kernel-stack regions are placed at random offsets too (audit 2, A5); `cargo xtask test` checks that the boots of a phase land at different addresses (`kaslr.layout_varies`, `kaslr.regions_vary`). User ASLR with Linux's ranges: stack top (22 bits of pages), mmap base and PIE load bias (28 bits), program break (1 GiB). Found on the way: F-0003. |
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
are covered, and the temporary test syscall is removed. The phase 1 boot
prints `KEEL P1 OK` only when all of its tests pass, and `cargo xtask test`
requires that line as well as the acceptance programs' own lines.

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
one-hour session found F-0009, and CI under KVM found F-0010 (both
fixed). **Passed on the final code:**
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
- Resolved at the start of Phase 3: test results now travel on COM2, which
  only the kernel writes (see Phase 3 below). Programs still share COM1 and
  the screen with the kernel log.

## Phase 2 (toy PE loader): complete (2026-11-22)

Started 2026-11-22, after the third Phase 1 audit cleared it
(`docs/PHASE1-AUDIT-3.md`; C1 fixed first, C2 and C3 fixed at the end
of Phase 2).

Acceptance P2, all met:
- `cargo xtask test --phase 2` boots Keel, runs `peldr /winetest/hello.exe`,
  finds the exact line on serial and exit status 0 (`acceptance.peldr_hello`;
  `KEEL P2 OK` required).
- The same `.exe` runs unmodified on Windows and prints the same line:
  confirmed by the owner on 2026-11-22 (exit status 0).
- Security note: the PE parser is safe Rust with every offset checked, a
  host fuzz target and a malformed-file corpus; the 30-minute fuzz run
  passed (P2-S1). Spec section 9 lists the steps but no task IDs; these are
Keel's.

| ID | Task | Status |
| --- | --- | --- |
| P2-T1 | PE parser (`user/pe`, `#![forbid(unsafe_code)]`): headers, sections, base relocations, imports; every offset and size checked; host tests and a malformed-file corpus | Done. `no_std`, no allocation; one checked reader for every field; tables walked lazily with caps (96 sections, 256 DLLs, 4096 imports per DLL, 255-byte names). Refuses W+X sections, overlapping or misaligned sections, an entry point outside executable code, an image that does not fit the user half, and any relocation type other than ABSOLUTE and DIR64. Host tests: the real `hello.exe`, a builder for imports (by name and ordinal) and DIR64 relocations, one test per error class, 20,000 random inputs; `fuzz/pe-corpus/` holds 24 malformed files, each named after the error it must give. Removing the W+X or image-bounds check fails both the targeted test and the random-input test. |
| P2-T2 | `peldr` (`user/peldr`): maps the image, relocates, resolves imports to the four stubs, applies section protections, fake TEB through `gs`, calls the entry point | Done; runs `hello.exe` on Linux (exact line, exit 0), at its preferred base and with `--relocate` (forced elsewhere; with relocation skipped it prints nothing and exits 1). Safe Rust over `keel-rt` and `pe`; `unsafe` only in `src/foreign.rs` (the four `extern "win64"` stubs and the entry call; ADR 0013). New `keel-rt` APIs: `Region::map_at` (MAP_FIXED_NOREPLACE), bounds-checked `write`/`read_u64`/`write_u64`/`protect_range`, `map_file` (read-only after reading, then borrowed as `&[u8]`), `set_gs_base`. Fake TEB: NT_TIB StackBase 0x08, StackLimit 0x10, Self 0x30 (Wine 10.0 `winnt.h`), PEB pointer at 0x60 (Microsoft `TEB`, `Reserved1[12]`). Bad input: one line on stderr, exit 1. On Keel: P2-T4. |
| P2-T3 | `winetest/hello-console`: no-CRT Windows x64 `.exe` importing `GetStdHandle`, `WriteFile`, `ExitProcess` (`raw-dylib`), checked in as a pinned fixture with its build command | Done. Built with the pinned toolchain's `rust-lld` (lld-link mode), no Windows SDK. It writes its line through a static table of pointers, so it carries two DIR64 relocations and tests a loader's relocation code. 3072 bytes, SHA-256 `f603ceac...65e4`, reproducible (a clean rebuild gave the same hash). ADR 0013 records where `unsafe` may appear for Phase 2. The owner ran it on Windows: it printed the line and exited with status 0. |
| P2-T4 | `cargo xtask test --phase 2`: `peldr /winetest/hello.exe` under Linux and on Keel; the exact line on serial and exit status 0 | Done. Under Linux: `host.peldr.hello.exe` and `.relocated` (exact stdout, exit 0). On Keel: `acceptance.peldr_hello`, `peldr.relocated` and `peldr.refuses_non_pe`; xtask requires the exact line on serial. The serial log shows no unimplemented system call and no user fault. `KEEL P2 OK` is printed when all pass; xtask requires it once the phase is marked complete. |
| P2-S1 | Host fuzz target for the PE parser; 30 minutes with no crash | Done. `cargo xtask fuzz-pe --minutes N --seed S` (engine in `fuzz/pe-fuzz`, a host-only crate so `pe` never needs std; overflow checks on; a panic writes the input to `target/fuzz-pe-crash.exe`, checked by breaking the parser on purpose). Acceptance run: `cargo xtask fuzz-pe --minutes 30 --seed 20261122` passed, 187,340,000 inputs, 13,291,167 accepted as images, no panic. |

## Phase 3 (Linux-ABI personality and compartments): in progress

Started 2026-11-22, after the Phase 2 audit cleared it
(`docs/PHASE2-AUDIT.md`; D1 fixed first). Plan, in the spec's order:

1. Before any hostile code runs, the open assumptions the Phase 2 audit
   lists. First done: the test-result channel (below).
2. P3-T1, the trace: P4-T1's minimal Wine build in Alpine (Dockerfile
   under `wine/build/`, run by a `wine-image.yml` workflow for the owner
   to review), then `strace -f` of `wine cmd /c echo hello` on real Linux,
   which also answers the risk-table question of whether Wine builds and
   runs on musl at all before Phase 3 work depends on it.
3. The kernel tasks in order of first appearance in the trace, with the
   compartment tasks (P3-S1 to P3-S4) built before any Wine binary runs.

| ID | Task | Status |
| --- | --- | --- |
| P3-pre | Test results on a channel programs cannot write (Phase 2 audit, item 3) | Done. The kernel writes `TEST`, summary, marker and layout lines to COM2 (0x2F8; `kresult!`), and also to the console. `cargo xtask test` attaches a second `-serial` to a file and reads every verdict only from it; COM1 can only fail a run (a panic banner). Test program `forger` prints a fake PASS line, summary and `KEEL P1 OK`; xtask checks they reach COM1 and not COM2 (`results.channel_isolated`). Reading verdicts from COM1 again makes phase 1 fail (100 PASS lines against a summary of 99). Unit test for the verdict rule. |
| P4-T1 (early) | Minimal Wine build in Alpine | Done in the build recipe; the owner reviews and merges `wine-image.yml`. `wine/build/Dockerfile`: Wine 11.0 (SHA-256 pinned, signature checked), pinned Alpine 3.24.4, `--enable-archs=x86_64`, no tests, no Win16, no X11/Wayland, every optional library off, `mingw-w64-gcc` 15.2.0 as the PE cross-compiler. Builds in about 18 minutes on 4 cores; the installed tree is 135 MB as `.tar.xz`. **Wine runs on musl** (the spec's risk-table question), with one fix: an `$ORIGIN` rpath on Wine's Unix libraries, without which musl's loader cannot resolve their `ntdll.so` dependency and Wine fails with `could not load kernel32.dll, status c0000135` (musl 1.2.6 `ldso/dynlink.c`, cited in the Dockerfile). The workflow fails unless `wine cmd /c echo hello` prints `hello` and exits 0. |
| P3-T1 | System-call inventory from a real trace | Done for the first trace. `docs/syscall-inventory.md`, generated by `cargo xtask syscalls` (6 host tests, two mutation-checked) from `strace -f` of `wine cmd /c echo hello` in CI (`wine-image` run 6, pinned packages, Linux 7.0.0-1014-aws on a GitHub-hosted runner): 87 distinct system calls, 21 of which Keel handles at least in part. The first local trace, under Linux 6.18, had the same calls except `readv`. Findings that shape Phase 3: about 4,600 private file-backed `MAP_FIXED` mappings (PE images mapped section by section) and 15 `MAP_SHARED` file mappings, both refused by Keel today; heavy `rt_sigprocmask` (62,000) and `read`/`write` on the wineserver pipes; `epoll_pwait`, `sendmsg`/`recvmsg` with `SCM_RIGHTS`; processes started with `fork` (25) and threads with `clone` (`CLONE_VM\|CLONE_THREAD\|CLONE_SETTLS\|...`); `getxattr` for `user.DOSATTRIB`; `AF_INET`/`AF_NETLINK` sockets probed (spec: `EAFNOSUPPORT`); `userfaultfd` probed and failing, `membarrier` failing 12 times out of 19; no `clock_gettime` (musl reads the clock through the vDSO, which Keel does not provide, so it will call it). Even a warm prefix runs `wineboot --init` for each new session (Wine `dlls/ntdll/unix/env.c`), which starts `winemenubuilder` and execs `update-mime-database`; Keel can switch that off with `WINEDLLOVERRIDES=winemenubuilder.exe=d`. |
| P3-T2 | Dynamic ELF support | Done for programs that need only libc (ADR 0015). The kernel loads `PT_INTERP` (musl's dynamic linker) in the mmap area and starts it, with a complete auxv (`AT_BASE`, `AT_HWCAP`, `AT_CLKTCK`, `AT_UID`..`AT_EGID`, `AT_SECURE`, `AT_EXECFN`, ...). A compartment's program finds its interpreter in its own tree. The `PT_INTERP` rules follow Linux, and are stricter where Linux ignores input. `fixtures/musl-dynamic` (reproducible build, hash-pinned) prints its line on Keel and under Linux. `exec.dynamic_musl` and `exec.interpreter_in_root` fail when `AT_BASE` is wrong or the interpreter is looked up outside the compartment. Other shared libraries wait for file-backed `mmap` (P3-T7). |
| P3-T7 (first part) | VM: private file mappings | Done (ADR 0016). `mmap` of a regular file with `MAP_PRIVATE`: pages are read from the file on first touch into private, compartment-charged frames, and zero past the end of the file. Offsets survive splits and merges. Errors are mmap(2)'s (`EACCES`, `EPERM`, `ENODEV`, `EBADF`, `EINVAL`), and `mprotect` cannot add `PROT_EXEC` without `MAP_EXEC`. `user/tests/filemap` passes under Linux and on Keel. `exec.file_mapping_past_end`: a page wholly past the end is not filled. Each rule fails its test when broken. End to end: `exec.shared_library` runs a musl program linked against its own shared library. musl's dynamic linker finds `/lib/libkeelgreet.so`, maps it from the file, and the program prints a count kept in the library's data segment. That brought `open`, `pread64` and `fcntl` (`F_GETFD`, `F_SETFD`), each checked against Linux in `filemap`. Still to do: `MAP_SHARED`, `mremap`. |
| P3-T3 (first part) | Processes: `execve` | Done for ELF programs (ADR 0017). Everything that can fail runs first, and leaves the process unchanged. Then, as Linux's begin_new_exec: new image, close-on-exec handles closed, caught signals reset, the blocked mask kept, FS/GS/FPU and registers reset, IBPB on the switch. Errors as Linux (`ENOENT`, `EACCES`, `ENOEXEC`, `ELIBBAD`, `E2BIG`, `EFAULT`); an empty argv becomes `[""]`. `user/tests/execprobe` passes under Linux and on Keel across three programs with no frame lost. Each rule fails the test when removed. Hostile executables (Phase 2 audit item 5): `exec.hostile_executables` has 400 randomly damaged executables run by forked children in a compartment with process, memory and tmpfs limits. With the CI seed: 295 refused, 85 ran, 20 faulted, none stuck, no kernel panic, every slot and frame back. Two longer runs (3,000 each, other seeds) found a scheduler bug, now fixed: once 1,024 children had exited, the parent's own exit status was dropped (eviction by smallest thread ID instead of age). `sched.exit_status_order` covers it. Programs that loop are now killed after 3 s (`kill`, ADR 0019). Two 3,000-file runs killed 10 and 4 of them; no panic, everything back. `#!` scripts still to do. |
| P3-T3 (second part) | Processes: `fork`, `wait4`, `getppid` | Done (ADR 0018). `fork` gives a copy-on-write child in the same compartment (process and memory limits apply), sharing open files, with the caller's registers, segment bases and FPU state. `wait4` follows Linux's kernel_wait4. Zombies keep their slot until reaped, so exits cannot pile up. `forkprobe` passes under Linux and on Keel: copy-on-write, shared offsets, `WNOHANG`, status encoding, a crash as signal 11, twenty zombies, `ECHILD`/`EINVAL`. No frame is lost outside the kernel heap. `compartment.fork_bomb`: 7 children in a compartment of 8, `EAGAIN` beyond, zombies still counted, another compartment unaffected (security acceptance P3 item 3, processes). This covers Phase 2 audit item 4 for fork from user mode. The reference-count limit is reached from user mode too: `vm.shared_frame_limit` lowers it to 12 (the real 65,534 is host-tested), and the 12th fork gets `ENOMEM`, with nothing leaked and the program still running. When `duplicate` ignores the refusal, 3,500 frames leak and the test fails. Next: `clone` (P3-T4), process groups. |
| P3-T4 | Threads: clone, per-thread state, exit_group | Done for musl's and the Wine trace's thread flags (ADR 0019). Threads have their own TID and `clear_child_tid` and take compartment slots. Thread exit clears the TID word and wakes a waiter. A fault ends the whole process. `exit_group` and `kill(SIGKILL)` end every thread through a scheduler exit request, which also wakes a blocked thread and catches a spinning one at the next tick. `fixtures/musl-dynamic/threads` (musl pthreads: mutex contention, condition variables, TLS, join, a raw `CLONE_CHILD_CLEARTID` wake, `exit_group` ending a blocked and a spinning thread) passes under Linux and on Keel. `threadprobe` checks the refusals against Linux. Not yet: `vfork`, `CLONE_VFORK`. |
| P3-T5 (first part) | Futexes | WAIT, WAKE, REQUEUE, CMP_REQUEUE keyed by (address space, address), with Linux's errors (ADR 0019). Shared keys come with `MAP_SHARED`; timed waits poll every millisecond for now. |
| P3-S1 (first part) | Compartment kernel object; per-compartment root and PID space | Done for files and PIDs (ADR 0014). `keel_core::compartment`: every process belongs to one compartment, which fixes its root (so absolute paths and `AT_FDCWD` cannot reach outside it: Phase 2 audit item 2) and numbers its processes from 1 (`getpid`, now implemented). Boot and test programs run in the system compartment (root `/`). `compartment.files_confined`: two compartments cannot name each other's files, or the system's, in either direction. With the system root given to every process again, all three probe runs fail. Socket names, IPC names, the procfs view and signals become per compartment as each arrives (ADR 0014, "Not yet covered"). |
| P3-S4 (in part) | Per-compartment limits and accounting | Processes and memory done (ADR 0014). Processes: `EAGAIN` at the limit, as fork(2) at `RLIMIT_NPROC`. Memory: every user page and user page table an address space holds is charged to its compartment's budget. A fault past the limit ends the program, and all frames come back. `compartment.memory_limit`: 64 MiB of touches against 17 MiB stop within the limit, the budget and the free frame count return to where they were, and another compartment runs normally (security acceptance P3 item 3, for memory). Each rule fails its test when removed. tmpfs: each compartment's file bytes and created nodes are capped by its own quota. Bytes are charged to a file's owner; a file the kernel placed is charged to the first compartment that grows it. `ENOSPC` at the limit. `compartment.tmpfs_quota`: two compartments each reach exactly their own 64 KiB and 8 nodes, and truncation gives bytes back. This closes Phase 2 audit item 1. Each rule fails its test when removed. Left for P3-S4: none of the audit's items. Handles are bounded per process (1024) and processes per compartment. |

## Test results (local, QEMU 8.2.2 TCG, OVMF, Ubuntu 24.04)

- `cargo xtask test`: 9 in-kernel tests pass, `KEEL P0 OK` on serial and
  read back from the framebuffer, plus `sr27.tamper.kernel`,
  `sr27.tamper.initramfs` and `sr27.tamper.config` (Limine refuses a
  one-byte change to each; the config's hash is enrolled in
  `BOOTX64.EFI`).
- `cargo xtask test --phase 1`: 98 in-kernel tests pass and `KEEL P1 OK`
  is on serial; the six fault scenarios (`double_fault`,
  `write_kernel_text`, `execute_data`, `stack_overflow`, `smap`,
  `fault_in_panic`) pass; the
  boots land at different kernel addresses (KASLR); and the user test
  programs, `musl-hello` and `heap64` pass under Linux too. Checked to
  fail when the marker is not printed.
- `cargo xtask test --phase 3` (phase in progress): 19 in-kernel tests
  pass (`compartment.files_confined`, `compartment.pid_space`,
  `compartment.process_limit`, `compartment.memory_limit`,
  `compartment.memory_limit_at_spawn`, `compartment.tmpfs_quota`,
  `exec.dynamic_musl`, `exec.interpreter_in_root`, `exec.shared_library`,
  `exec.file_mappings`, `exec.file_mapping_past_end`, `exec.execve`,
  `exec.fork_wait`, `compartment.fork_bomb`, `vm.shared_frame_limit`,
  `exec.hostile_executables`, `sched.exit_status_order`, `exec.threads`,
  `exec.thread_calls`),
  and both
  dynamically linked musl programs' lines are on serial.
- `cargo xtask test --phase 2`: 3 in-kernel tests pass and `KEEL P2 OK`
  is on serial with the exact line `hello.exe` writes; under Linux,
  `peldr` runs it at its preferred base and relocated.
- `cargo xtask fuzz --minutes 60 --seed 20261122`: passes (see security
  acceptance item 6 above).
- `cargo xtask fuzz-pe --minutes 30 --seed 20261122`: passes (P2-S1).
- `cargo test`: 215 host tests pass (124 `keel-core`, 29 `keel-hal`,
  5 `keel-linux-abi`, 8 `pe`, 1 `pe-fuzz`, 44 `xtask`, and 4 `keel-hal`
  doctests).
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

## Second boot on the target machine (2026-11-22, release v0.1.0)

The owner verified `keel-0.1.0-esp.zip` with `cargo xtask verify`
(checksum, and an attestation from `release.yml` at `refs/tags/v0.1.0`),
unzipped it onto a FAT32 USB stick, and booted the OptiPlex 3060 (Secure
Boot off). Every line through `Keel: nothing more to run yet; halting.`
appeared. Read from a photo of the screen:

- Limine accepted the enrolled `limine.conf` (ADR 0010) and the hashed
  kernel and initramfs. The kernel base and HHDM offset are hidden
  (audit finding 8).
- Memory: 39 regions, 7676 MiB usable; 1,964,018 frames free (7671 MiB).
- Paging: NX, WP, SMEP and SMAP on; UMIP unsupported (CPUID does not
  report it on this CPU).
- CPU: Intel family 6, model 0x9E, stepping 0xA. `IA32_ARCH_CAPABILITIES`
  is 0, and 6 CPUs are listed in the MADT (Keel uses one).
- Time: HPET period 41,666,667 fs (24 MHz), APIC timer 1502 kHz, and TSC
  3005 MHz, **invariant**. This is the first real-hardware run of the TSC
  clock path (QEMU TCG has no invariant TSC).
- Random: seeded from RDSEED, RDRAND and TSC jitter.
- Keyboard: the i8042 controller answered its self-test. Whether the
  firmware delivers USB keystrokes through it was not tested.
- Mitigations in use: page-table isolation, legacy IBRS on every kernel
  entry, IBPB between address spaces, RSB filling, SSBD, and L1TF-safe
  page tables.
- **Reported VULNERABLE: MDS, TAA, MMIO stale data, SRBDS and GDS.** In
  every case the reason given is missing microcode support (no MD_CLEAR,
  FB_CLEAR, SRBDS or GDS controls), not a missing Keel mitigation: Keel
  already issues VERW. The firmware's microcode on this machine is older
  than those fixes. The remedies are a newer firmware (BIOS) from the
  vendor, or Keel loading microcode early (P6-S8), which the GDS line
  names.
- Known issue: the banner says `Keel 0.0.0 booting`. The kernel prints
  its crate version (`CARGO_PKG_VERSION`), and `cargo xtask dist
  --version` only names the files, so a release kernel does not know its
  own version.

## `unsafe` budget

From `cargo xtask audit` (our code only; includes test code):

| Crate | Blocks | Block lines | Declarations | Attributes |
| --- | --- | --- | --- | --- |
| `kernel/hal` | 134 | 407 | 39 | 16 |
| `kernel/keel-kernel` | 0 | 0 | 0 | 1 |
| `user/keel-rt` | 19 | 87 | 5 | 1 |

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

Audit finding 1 (ADR 0009) removed the closure-based frame accessor and
added two blocks for `OwnedFrame::bytes` and `bytes_mut`, whose safety
rests on ownership instead of a lock.

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
- `wine-image.yml` does not exist yet: there is no Wine build before
  Phase 4. `security.yml` (nightly system-call fuzzing) is on the working
  branch for the owner to review and merge; the escape suite comes in
  Phase 3.
- `cargo xtask usb`, `linux-test`, and `wine-build` are not implemented;
  they belong to later phases.
- KASLR is on (P1-S5). A normal boot does not print the kernel base or
  the HHDM offset; test boots do, so `cargo xtask test` can check that
  they vary (audit finding 8). Fatal exception dumps still print kernel
  addresses.
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
