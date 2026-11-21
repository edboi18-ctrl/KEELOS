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
| Rust platform-support page for `x86_64-unknown-none` (soft-float, no red zone) | Why the exception stub saves only general registers (`idt.rs`) |
| Intel SDM Vol. 2A, "IN - Input from Port"; Vol. 2B, "OUT - Output to Port" | `kernel/hal/src/arch/x86_64/port.rs` |
| Intel SDM Vol. 2A, "CLI - Clear Interrupt Flag", "HLT - Halt" | `kernel/hal/src/arch/x86_64/cpu.rs` |
| Intel SDM Vol. 1, section 3.3.7.1, "Canonical Addressing" | Higher-half bound in `kernel/keel-kernel/src/selftest.rs` |

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
