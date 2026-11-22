# Sources

References actually used while writing the code, with where they are
relied on. Add to this file whenever a non-obvious hardware or ABI fact
enters the code (spec section 1, rule 3).

## Boot

| Source | Used for |
| --- | --- |
| Limine boot protocol, `PROTOCOL.md`, https://codeberg.org/Limine/limine-protocol (read 2026-11-17; base revision 6) | `kernel/hal/src/boot/limine.rs` (request IDs, structure layouts, markers, base revision tag); `kernel/keel-kernel/src/main.rs` (machine state at entry); `linker.ld` (load address) |
| Limine 12.9.6 `CONFIG.md` and `USAGE.md` (source tag `v12.9.6`, commit `89a9512c623a4779cc73e3869383876d54264b28`) | `xtask/src/build.rs` (`limine.conf` syntax, `#hash` path suffix, config file location); Secure Boot behaviour noted for Phase 6 |
| Limine 12.9.6 source: `common/crypt/blake2b.h` (`BLAKE2B_OUT_BYTES 64`), `common/lib/uri.c` (hash mismatch panic), `common/lib/elf.c` (relocation of `ET_DYN` kernels) | Hash length in `xtask/src/util.rs`; tamper test in `xtask/src/qemu.rs`; position-independent kernel in `linker.ld` |
| System V ABI, generic part, "Program Header" | Segment types and flags in `linker.ld` |
| ACPI specification, "Root System Description Pointer (RSDP) Structure" | `boot::rsdp` (20-byte ACPI 1.0 structure, `"RSD PTR "` signature) |

## CPU

Intel's website refuses connections from the agent's environment, so the
manuals were fetched from the kib.kiev.ua x86 documentation mirror on
2026-11-21. The files carry Intel's and AMD's own titles, order numbers
and dates; their SHA-256 values are recorded so they can be checked
against copies downloaded from the vendors:

- Intel SDM Vol. 3 (3A-3D), order number 325384-093US, September 2026,
  file `325384-093.pdf`, SHA-256
  `77919be320f35da2782771ef2cb65a868cf68e62c8f8279f2ca61199cb70d1f8`.
- Intel SDM Vol. 1, order number 253665-093US, file `253665-093.pdf`.
- AMD64 APM Vol. 2 (System Programming), 24593 rev. 3.46, October 2026,
  file `24593_APM_v2-r3.46.pdf`.

| Source | Used for |
| --- | --- |
| Intel SDM Vol. 3, section 3.4.5 and Figure 3-8 (segment descriptors); Table 3-2 (system descriptor types); Figure 10-4 (64-bit TSS descriptor); section 10.7 and Figure 10-11 (64-bit TSS) | `kernel/hal/src/arch/x86_64/gdt.rs` |
| Intel SDM Vol. 3, section 6.8.8 (SYSCALL/SYSRET selector derivation from IA32_STAR) | GDT order in `gdt.rs` |
| Intel SDM Vol. 1, section 20.5.2 (no I/O permission bitmap when the map base is at or beyond the TSS limit) | `io_map_base` in `gdt.rs` (SR-9) |
| Intel SDM Vol. 3, Table 7-1 (vectors and error codes); section 7.14.1 and Figure 7-8 (64-bit gates); sections 7.14.2-7.14.5 and Figure 7-9 (stack frame, IRET, IST); Table 7-5 (double-fault conditions) | `kernel/hal/src/arch/x86_64/idt.rs`; double-fault self-test in `selftest.rs` |
| AMD64 APM Vol. 2 rev. 3.46, Table 8-1 and sections 15.28, 15.35 (#SX and #VC push error codes) | Error-code vector list in `idt.rs` |
| Linux `arch/x86/include/asm/segment.h` at tag v6.18 (GDT entry numbers on x86-64), read for the selector values only | Selector values in `gdt.rs` |
| Intel SDM Vol. 3, Tables 5-15 to 5-20 (4-level paging entries); section 5.6 (combined access rights); section 5.1.4 (CPUID enumeration of NX, SMEP, SMAP, PCID, PGE); Table 14-11 (PAT entry selection); section 2.5 (CR0.WP, CR4.SMEP/SMAP/UMIP bit positions); Table 2-1 (IA32_EFER.NXE bit 11); Figure 7-11 (page-fault error code) | `kernel/core/src/paging.rs`, `kernel/hal/src/arch/x86_64/paging.rs`, `cpu.rs`, `idt.rs` |
| Intel SDM Vol. 2 (325383-093, file SHA-256 `d137a7887787bbb06c1a8b8bafd51958d8d2e16b4dff987a03226c845cca1516`): MOV to/from control registers, RDMSR, WRMSR | Reasoning blocks in `cpu.rs`. This revision no longer contains the CPUID leaf tables. |
| Linux `arch/x86/include/asm/cpufeatures.h` at v6.18 (X86_FEATURE_UMIP is leaf 7 ECX bit 2) | UMIP detection in `cpu.rs` |
| AMD64 APM Vol. 2, Table A-1 (EFER at MSR C000_0080h); section 5 (SMEP/SMAP CPUID bits, which agree with Intel's) | `cpu.rs` |
| Limine PROTOCOL.md, "Caching" (PAT0 = WB, PAT5 = WC; framebuffer mapped WC) and "Memory Layout at Entry" (which regions the HHDM covers; outward rounding to 4 KiB) | `hal::paging::init` |
| ACPI Specification 6.6, chapter 5 (https://uefi.org/specs/ACPI/6.6/05_ACPI_Software_Programming_Model.html, read 2026-11-21): Table 5.1 (Generic Address Structure), Table 5.3 (RSDP), section 5.2.6 (table header), Table 5.8 (XSDT), Tables 5.19-5.28 and section 5.2.12.12 (MADT and its entries, MPS INTI flags, PCAT_COMPAT) | `kernel/core/src/acpi.rs`, `kernel/hal/src/interrupts.rs` |
| IA-PC HPET Specification 1.0a (file `hpet-spec-1-0a.pdf`, kib.kiev.ua mirror): section 2.3 register map and bit definitions; HPET description table | `kernel/hal/src/time.rs`, `kernel/core/src/acpi.rs` |
| Intel 82093AA I/O APIC datasheet, order number 290566-001 (kib.kiev.ua mirror): sections 3.1, 3.2.2, 3.2.4 | `kernel/hal/src/arch/x86_64/apic.rs` |
| Intel SDM Vol. 3 chapter 13: Table 13-1, Figures 13-5, 13-8, 13-10, 13-23, sections 13.5.4, 13.8.5, 13.9, 13.12; section 20.17.1 (invariant TSC) | `apic.rs`, `time.rs`, `cpu.rs` |
| Linux `arch/x86/include/asm/i8259.h` at v6.18 (PIC mask ports 21h and A1h) | `apic::mask_legacy_pic` |
| Intel SDM Vol. 1, section 13.2 (CPUID.01H:ECX.XSAVE[26]; CPUID.0DH.00H EDX:EAX supported components, EBX area size), section 13.4 (64-byte alignment, header at offset 512), section 13.8.1 (XRSTOR loads MXCSR when RFBM[1] or RFBM[2] is set), Table 10-2 (FXSAVE layout: FCW byte 0, MXCSR byte 24), reset values FCW 037FH and MXCSR 1F80H; Vol. 3 section 2.5 and Figure 2-8 (CR0.MP/EM/TS, CR4.OSFXSR/OSXMMEXCPT/OSXSAVE, XCR0 bits) | `kernel/hal/src/arch/x86_64/fpu.rs` |
| System V AMD64 ABI, section 3.2.1 (callee-saved rbx, rbp, r12-r15; stack 16-byte aligned at a call) | `kernel/hal/src/arch/x86_64/switch.rs` |
| Linux man-pages `mmap(2)`, `munmap(2)`, `mprotect(2)` (MAP_FIXED, MAP_FIXED_NOREPLACE/EEXIST, ENOMEM for mprotect over holes, page granularity) | `kernel/core/src/vm.rs` |
| Intel SDM Vol. 2B "STAC" (#UD when CPUID.07H.00H:EBX.SMAP[20] = 0) and "REP" (an interrupted string instruction resumes with RSI/RDI/RCX describing the remaining work); Vol. 3 section 5.6 (SMAP) | `kernel/hal/src/vm.rs` user-copy routines |
| Rust platform-support page for `x86_64-unknown-none` (soft-float, no red zone) | Why the exception stub saves only general registers (`idt.rs`) |
| Intel SDM Vol. 2A, "IN - Input from Port"; Vol. 2B, "OUT - Output to Port" | `kernel/hal/src/arch/x86_64/port.rs` |
| Intel SDM Vol. 2A, "CLI - Clear Interrupt Flag", "HLT - Halt" | `kernel/hal/src/arch/x86_64/cpu.rs` |
| Intel SDM Vol. 1, section 3.3.7.1, "Canonical Addressing" | Higher-half bound in `kernel/keel-kernel/src/selftest.rs` |
| Intel SDM Vol. 2B "SYSCALL" (RIP from IA32_LSTAR, RCX/R11 saved, RFLAGS masked by IA32_FMASK at C0000084H, RSP not saved) and "SYSRET" (#GP(0) at CPL 0 for non-canonical RCX; RFLAGS from R11, including IOPL); AMD64 APM Vol. 2 section 6.1.1 and Table A-1 (STAR C000_0081h, LSTAR C000_0082h, SFMASK C000_0084h), EFER.SCE bit 0 | `kernel/hal/src/arch/x86_64/entry.rs`; ADR 0005 |
| Intel SDM Vol. 3 section 7.12.1.3 (interrupt delivery clears TF, VM, RF, NT and, for interrupt gates, IF; not AC); Vol. 2B "POPF" flag-update table (all flags writable at CPL 0, AC writable at CPL 3); Vol. 3 section 5.6 (SMAP applies while AC = 0) | `push 2; popfq` at handler entry in `entry.rs`; finding F-0001 |
| System V AMD64 psABI 1.0 (March 12, 2025; gitlab.com/x86-psABIs/x86-64-ABI, `abi.pdf` SHA-256 `19f346cc723dbeb6ad80494614291f4e85aba3caca48dcfd537d33f82af6d6ac`, read 2026-11-22): section 3.4.1 and Figure 3.9 (initial process stack; RSP 16-byte aligned at entry; RDX atexit pointer), Tables 3.4-3.6 (initial x87 control word, MXCSR, RFLAGS), section 3.4.3 and Figure 3.11 (auxiliary vector types), section 3.2.2 (stack alignment at calls; 128-byte red zone) | `kernel/core/src/exec.rs`, `kernel/keel-kernel/src/exec.rs`, `user/keel-rt` |
| Linux `include/uapi/linux/elf.h`, `elf-em.h`, `include/uapi/linux/auxvec.h` at v6.12 (`Elf64_Ehdr`, `Elf64_Phdr`, PT_*, PF_*, ET_*, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, EM_X86_64 = 62, AT_* values), read 2026-11-22 | `kernel/core/src/elf.rs`, `kernel/core/src/exec.rs` |
| Linux `fs/binfmt_elf.c` at v6.12, `load_elf_phdrs` (program-header table refused above one page), read for that limit only | `MAX_PHDR_TABLE` in `kernel/core/src/elf.rs` |
| Linux `arch/x86/include/asm/elf.h` (ELF_ET_DYN_BASE = DEFAULT_MAP_WINDOW / 3 * 2) and `page_64_types.h` (DEFAULT_MAP_WINDOW = 2^47 - 4096) at v6.12 | `DYN_BASE` in `kernel/keel-kernel/src/exec.rs` |
| Intel SDM Vol. 1 section 7.3.17.1 (CPUID.01H:ECX.RDRAND[30]; bounded retry while CF = 0, example limit 10); Vol. 2B "RDRAND" (CF = 1 on valid data, flags affected) | `kernel/hal/src/random.rs` |
| Linux `arch/x86/kernel/cpu/rdrand.c` (`x86_init_rdrand`: 8 samples, at least 5 changes) and `amd.c` (`clear_rdrand_cpuid_bit`: firmware that breaks RDRAND after resume) at v6.12 | RDRAND self-test in `kernel/hal/src/random.rs` |
| Steele, Lea, Flood, "Fast splittable pseudorandom number generators", OOPSLA 2014; Vigna, `splitmix64.c` (prng.di.unimi.it), constants 0xbf58476d1ce4e5b9 and 0x94d049bb133111eb, read 2026-11-22 | Weak interim mixing in `kernel/hal/src/random.rs` |
| Linux `include/uapi/asm-generic/errno-base.h` and `errno.h` at v6.12 (errno values), `include/uapi/linux/limits.h` (PATH_MAX 4096, NAME_MAX 255), `include/uapi/linux/stat.h` (S_IFMT, S_IFREG, S_IFDIR, S_IFCHR), read 2026-11-22 | `kernel/core/src/errno.rs`, `kernel/core/src/vfs.rs` |
| Linux `Documentation/admin-guide/devices.txt` at v6.12 (char 1:3 null, 1:5 zero, 1:9 urandom, 5:1 console; 1:1 mem, 1:2 kmem, 1:4 port are the forbidden ones) | `Device::number` in `kernel/core/src/vfs.rs`; `kernel/keel-kernel/src/fs.rs` |
| Rust `core::str::Utf8Chunks` (stable since 1.79) and `char::is_control` (Unicode general category Cc: U+0000-U+001F, U+007F-U+009F) | `UserText` in `kernel/hal/src/console.rs` |
| Linux uapi headers at v6.12: `asm-generic/fcntl.h` (O_*, AT_FDCWD), `asm-generic/mman-common.h`, `asm-generic/mman.h`, `linux/mman.h`, `arch/x86/include/uapi/asm/mman.h` (PROT_*, MAP_*), `arch/x86/include/uapi/asm/prctl.h` (ARCH_*), `arch/x86/include/uapi/asm/stat.h` (x86-64 struct stat), `asm-generic/ioctls.h`, `asm-generic/termbits.h`, `termbits-common.h` (TCGETS, TIOCGWINSZ, struct termios, flag values), `linux/time.h` (CLOCK_*), `linux/random.h` (GRND_*), `linux/uio.h` (UIO_MAXIOV); kernel-internal `include/linux/kdev_t.h` (`new_encode_dev`), `include/linux/fs.h` (MAX_RW_COUNT), `include/linux/termios_internal.h` (INIT_C_CC), `drivers/tty/tty_io.c` (`tty_std_termios`), `drivers/char/random.c` (getrandom flag checks), `fs/stat.c` (`cp_new_stat` encodes st_dev/st_rdev with `new_encode_dev`); read 2026-11-22 for constants and layouts only | `kernel/linux-abi/src/abi.rs`, `syscall.rs` |
| Linux `arch/x86/entry/syscalls/syscall_64.tbl` at v6.12, `common` and `64` rows (numbers and names) | Generated `kernel/linux-abi/src/names.rs` |
| Intel SDM Vol. 3 section 4.5.3 (WRMSR to IA32_FS_BASE/IA32_GS_BASE requires a canonical value); AMD APM Vol. 2 Table A-1 (FS.Base C000_0100h, GS.Base C000_0101h); Intel SDM Vol. 1 section 3.4.2.1 (FS and GS bases still apply in 64-bit mode) | `hal::sched::set_user_base`, `cpu.rs`, `keel-rt::sys::fs_base_round_trip` |
| `man 2 syscall` (x86-64: fourth argument in R10) | `keel-rt::syscall6` |
| Linux `drivers/input/serio/i8042-io.h` (ports 0x60/0x64, keyboard IRQ 1) and `include/linux/i8042.h` (status, command and configuration bits; 0xD2 keyboard loop) at v6.12 | `kernel/hal/src/drivers/ps2.rs` |
| QEMU v9.2.0 `hw/input/pckbd.c` (0xD2 queues a byte as keyboard data) and `hw/input/ps2.c` (set-1 release = make code \| 0x80; 0xE0 prefix; Pause and Print Screen sequences), read 2026-11-22 | `ps2::inject`; `kernel/core/src/keyboard.rs` |
| keycodemapdb `data/keymaps.csv` (QEMU project; column "AT set1 keycode"; SHA-256 527727ef96d7103a8d7725a6ed9738812660b5a3f4aec086dd7b587b1ba9fcca, read 2026-11-22) | Set-1 table in `kernel/core/src/keyboard.rs` |
| Linux `include/linux/termios_internal.h` (INIT_C_CC: VINTR ^C, VERASE DEL, VKILL ^U, VEOF ^D) and `drivers/tty/tty_io.c` (`tty_std_termios`: ICRNL, ICANON, ECHO, ECHOE, ECHOK, ECHOCTL) at v6.12; N_TTY_BUF_SIZE 4096 | `kernel/core/src/tty.rs` |
| Linux v6.12 `Documentation/admin-guide/hw-vuln/` (spectre, mds, tsx_async_abort, l1tf, processor_mmio_stale_data, special-register-buffer-data-sampling, gather_data_sampling, reg-file-data-sampling, cross-thread-rsb) and `Documentation/arch/x86/mds.rst` (VERW placement); v6.18 hw-vuln index (adds rsb, indirect-target-selection, vmscape, old_microcode); read 2026-11-22 | ADR 0007, `kernel/core/src/cpuvuln.rs` |
| Linux v6.18 `arch/x86/kernel/cpu/common.c` (`cpu_vuln_blacklist` rows for SKYLAKE_L/SKYLAKE/KABYLAKE_L/KABYLAKE, BHI rule) and `arch/x86/include/asm/msr-index.h`, `cpufeatures.h`, `kernel/cpu/scattered.c` (BHI_CTRL = CPUID.(7,2):EDX[4]); v6.12 `intel-family.h` (INTEL_KABYLAKE = 6/0x9E), `bugs.c` (SPECTRE_V2_IBRS for retbleed Intel parts, RSB fill on context switch, BHI selection), `arch/x86/entry/calling.h` (IBRS_ENTER/IBRS_EXIT), `nospec-branch.h` (__FILL_RETURN_BUFFER, CLEAR_CPU_BUFFERS), `arch/x86/entry/entry.S` (`mds_verw_sel` = __KERNEL_DS), `include/linux/nospec.h` and `arch/x86/include/asm/barrier.h` (array_index_mask_nospec), `arch/x86/lib/cpu.c` (family/model decoding) | `kernel/core/src/cpuvuln.rs`, `handle.rs`, `kernel/hal/src/mitigations.rs`, `arch/x86_64/entry.rs`, `switch.rs`, `cpu.rs`, `sched.rs`, `kernel/linux-abi/src/syscall.rs` |
| Intel SDM Vol. 2C "VERR/VERW" (selector operand; only ZF changes), Vol. 2B "RDMSR"/"WRMSR" (#GP for unimplemented MSRs), "CMP", "SBB"; Vol. 3 IA32_TIME_STAMP_COUNTER at 10H | `entry.rs`, `cpu.rs` |
| QEMU v8.2.2 `target/i386/tcg/sysemu/misc_helper.c` (TCG `helper_rdmsr` returns 0 for unknown MSRs without #GP) and the TCG warnings for spec-ctrl, md-clear, arch-capabilities, ssbd, stibp ("TCG doesn't support requested feature") | Why `cpu.msr_safe` accepts 0 under emulation; ADR 0007 |
| RFC 8439 (ChaCha20; rfc-editor.org rfc8439.txt, SHA-256 25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c): sections 2.1-2.3, test vectors 2.1.1, 2.3.2, A.1 #1; RFC 7693 (BLAKE2; rfc7693.txt, SHA-256 c943754888364fe29bbd0bb3c71c6658ef392371497eaa4a9d9dde015b0721e5): sections 2.1, 2.5-2.7, 3.1-3.3, Appendix B, Appendix E self-test; read 2026-11-22 | `kernel/core/src/crypto.rs` |
| Linux v6.12 `drivers/char/random.c` (BLAKE2s input pool, `crng_fast_key_erasure`, CRNG_RESEED_INTERVAL = 60 s), and Bernstein, "Fast-key-erasure random-number generators", https://blog.cr.yp.to/20170723-random.html (cited there) | `kernel/core/src/rng.rs`, `kernel/hal/src/random.rs` |
| Intel SDM Vol. 1 section 7.3.17.2 (RDSEED, CPUID.07H.00H:EBX.RDSEED[18], retry while CF = 0) and Vol. 2B "RDSEED" | `kernel/hal/src/random.rs` |
| Linux v6.12 `arch/x86/include/asm/elf.h` (STACK_RND_MASK 0x3fffff), `mm/util.c` (`randomize_stack_top`), `arch/x86/mm/mmap.c` (`arch_rnd`, `mmap_base`, 128 MiB minimum gap), `arch/x86/Kconfig` (ARCH_MMAP_RND_BITS_MIN 28 for 64-bit), `arch/x86/kernel/process.c` (`arch_randomize_brk`: 1 GiB), `fs/binfmt_elf.c` (`load_bias += arch_mmap_rnd()`) | ASLR ranges in `kernel/linux-abi/src/exec.rs`, `kernel/core/src/vm.rs` |
| Limine v12.9.6 `CONFIG.md` (`kaslr`, `randomise_hhdm_base`) and the Limine protocol `PROTOCOL.md` (relocatable executables may be slid; kernel at or above 0xffffffff80000000), read 2026-11-22 | `xtask/src/build.rs` (`kaslr: yes`), `xtask/src/qemu.rs` (`kaslr.layout_varies`) |
| rust-lang/rust 1.100.0 `compiler/rustc_target/src/spec/targets/x86_64_unknown_none.rs` (`stack_probes: StackProbeType::Inline`, static PIE), read 2026-11-22 | SR-17 stack probes; STATUS P1-S6 |
| cpio(5), "New ASCII Format"; Linux `Documentation/driver-api/early-userspace/buffer-format.rst` | `kernel/core/src/cpio.rs` (reader), `xtask/src/cpio.rs` (writer) |
| Linux v6.12 (raw.githubusercontent.com/torvalds/linux/v6.12, read 2026-11-22): `syscall_64.tbl` (poll 7, rt_sigaction 13, rt_sigprocmask 14, sigaltstack 131); `kernel/signal.c` (`sys_rt_sigaction`, `do_sigaction`, `sys_rt_sigprocmask`, `sigprocmask`, `sys_sigaltstack`, `do_sigaltstack`); `include/linux/sched/signal.h` (`__on_sig_stack`, `on_sig_stack`, `sas_ss_flags`, `sas_ss_reset`); `include/linux/signal_types.h` (kernel `struct sigaction`, UAPI_SA_FLAGS); `include/uapi/asm-generic/signal-defs.h` (SA_* and SIG_BLOCK/UNBLOCK/SETMASK); `include/uapi/linux/signal.h` (SS_*); `arch/x86/include/uapi/asm/signal.h` (signal numbers, `stack_t`, MINSIGSTKSZ 2048, SA_RESTORER); `arch/x86/include/asm/signal.h` (_NSIG 64); `arch/x86/kernel/signal.c` (`sigaltstack_size_valid`); `fs/select.c` (`sys_poll`, `do_sys_poll`, `do_pollfd`); `include/uapi/asm-generic/poll.h` (POLL* bits); `include/linux/poll.h` (DEFAULT_POLLMASK, `vfs_poll`); `drivers/tty/n_tty.c` (`n_tty_poll`); `drivers/char/random.c` (`urandom_fops` has no poll method) | `kernel/core/src/signal.rs`, `kernel/core/src/poll.rs`, the poll and signal calls in `kernel/linux-abi/src/syscall.rs`, `docs/syscalls.md` |
| Rust 1.100.0 standard library source (rust-src component of the pinned toolchain): `library/std/src/sys/pal/unix/mod.rs` (`init`, `sanitize_standard_fds`: poll on fds 0-2, abort on any error but EINTR/EINVAL/EAGAIN/ENOMEM; `reset_sigpipe`: SIGPIPE set to SIG_IGN, asserted) and `stack_overflow.rs` (`init`: sigaction on SIGSEGV/SIGBUS, `make_handler`: mmap, mprotect, sigaltstack; no main-thread guard on musl) | Which calls Phase 1 acceptance item 2 needs; ADR 0008 |
| Linux `arch/x86/entry/syscalls/syscall_64.tbl`, `include/uapi/asm-generic/errno.h`, `arch/x86/include/uapi/asm/signal.h` at v6.12 (exit 60, exit_group 231, ENOSYS 38, SIGILL 4, SIGTRAP 5, SIGBUS 7, SIGFPE 8, SIGSEGV 11), read 2026-11-22 | `kernel/hal/src/syscall.rs`, `docs/syscalls.md` |

## Devices

| Source | Used for |
| --- | --- |
| PC16550D UART datasheet (register summary); OSDev wiki, "Serial Ports" | `kernel/hal/src/drivers/serial.rs` |
| QEMU behaviour observed with QEMU 8.2.2: vvfat `rw` refuses `snapshot=on`; AHCI refuses read-only media | ADR 0003 |
| QEMU source, `hw/misc/debugexit.c` (exit status is `(value << 1) \| 1`) | `kernel/hal/src/drivers/debug_exit.rs`, `xtask/src/qemu.rs` |
| `font8x8` crate documentation (bit order of `BASIC_LEGACY`) | `kernel/hal/src/drivers/framebuffer.rs` |

## Formats and algorithms

| Source | Used for |
| --- | --- |
| cpio(5), "New ASCII Format" | `xtask/src/cpio.rs`; initramfs magic check in the self-test |
| FIPS 180-4 (SHA-256 "abc" vector); RFC 7693 Appendix A (BLAKE2b-512 "abc" vector) | Known-answer tests in `xtask/src/util.rs` |
| ECMA-48, section 5.4 (control sequences) | `strip_ansi` in `xtask/src/qemu.rs` |

## Build host

| Source | Used for |
| --- | --- |
| Microsoft, "Tar and Curl Come to Windows!", https://devblogs.microsoft.com/commandline/tar-and-curl-come-to-windows/ ; curl project, https://curl.se/windows/microsoft.html | ADR 0001 |
| Cargo book, "Environment variables" (`CARGO_ENCODED_RUSTFLAGS`), "Source replacement" | `xtask/src/build.rs`, `.cargo/config.toml` |
| crates.io version list for `limine` (0.6.x requires nightly) | ADR 0002 |

## Release artifacts and CI

| Source | Used for |
| --- | --- |
| UEFI specification, chapter "GUID Partition Table (GPT) Disk Layout" (Protective MBR, GPT Header, GPT Partition Entry) and Appendix A (GUID byte order) | `disk_image` and `gpt_header` in `xtask/src/dist.rs` |
| Microsoft, "FAT32 File System Specification" (FAT type determination: FAT32 needs at least 65525 clusters) | Minimum partition size in `xtask/src/dist.rs` |
| PKWARE `APPNOTE.TXT` 6.3 (sections 4.3.7, 4.3.12, 4.3.16, 4.4.6, 4.4.7) | `zip_stored` and `crc32` in `xtask/src/dist.rs` |
| RFC 4122 section 4.4 (version and variant bits) | `derived_guid` in `xtask/src/dist.rs` |
| `gh attestation verify --help` (GitHub CLI): `--repo`, `--signer-workflow`, `--deny-self-hosted-runners` | `xtask/src/verify.rs` |
| `actions/attest-build-provenance` v4.2.2 `action.yml` (`subject-checksums` input) | `.github/workflows/release.yml` |
| GitHub changelog 2024-04-02, hardware acceleration on hosted Linux runners (KVM udev rule) | `.github/workflows/*.yml` |
| The Rust Reference, "Comments" and "Tokens" | Lexer for the `unsafe` census in `xtask/src/audit.rs` |
| Limine 12.9.6 `.github/workflows/release.yml` and `README.md` (binary release assets and their GPG signatures) | Limine pin procedure in `docs/DEPENDENCIES.md` |
| Linux `drivers/char/random.c` at v6.12: `get_random_bytes_user` (one `crng_make_state` per call, then ChaCha20 blocks without the lock) and `crng_reseed` / `crng_reseed_interval` (reseeding scheduled by jiffies; no clock read on the output path), read 2026-11-22 | `Stream` in `kernel/core/src/rng.rs`, `stream` and the tick-based reseed in `kernel/hal/src/random.rs`, `getrandom` in `kernel/linux-abi/src/syscall.rs` (F-0010) |
| QEMU 8.2.2 `target/i386/cpu.c`: CPUID 0x80000007 EDX `unmigratable_flags = CPUID_APM_INVTSC`, `DEFINE_PROP_BOOL("migratable", X86CPU, migratable, true)` (so `-cpu host` hides invariant TSC by default), read 2026-11-22 | Diagnosis of F-0010 (CI's KVM guest uses the HPET clock) |
| Intel SDM Vol. 3 (325384-093US), section 28.1.2, "Instructions That Cause VM Exits Unconditionally" (CPUID, GETSEC, INVD, XSETBV) | `TSC_CLOCK` in `kernel/hal/src/time.rs` (F-0010) |
