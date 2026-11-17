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

| Source | Used for |
| --- | --- |
| Intel SDM Vol. 2A, "IN - Input from Port"; Vol. 2B, "OUT - Output to Port" | `kernel/hal/src/arch/x86_64/port.rs` |
| Intel SDM Vol. 2A, "CLI - Clear Interrupt Flag", "HLT - Halt" | `kernel/hal/src/arch/x86_64/cpu.rs` |
| Intel SDM Vol. 1, section 3.3.7.1, "Canonical Addressing" | Higher-half bound in `kernel/keel-kernel/src/selftest.rs` |

## Devices

| Source | Used for |
| --- | --- |
| PC16550D UART datasheet (register summary); OSDev wiki, "Serial Ports" | `kernel/hal/src/drivers/serial.rs` |
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
