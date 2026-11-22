# ADR 0004: Keel parses the ACPI tables it needs itself

Status: accepted (Phase 1). Deviates from the P1-T6 task note "Use the
`acpi` crate for table parsing only".

## Context

Checked on crates.io on 2026-11-21: `acpi` 6.1.1 (the latest stable
release) has `#![feature(allocator_api)]` in `src/lib.rs`, so it builds
only on nightly Rust. It is about 9,500 lines including an AML
interpreter, and brings in `bit_field`, `bitflags`, `byteorder`, `log`,
`pci_types` and `spinning_top`. The 7.0 line is still a pre-release.

Keel builds on pinned stable Rust (ADR 0002 made the same call for the
`limine` crate, with the owner's approval). SR-20 requires that firmware
tables be parsed in safe Rust with bounds checks, and section 3 asks for
a fuzz target for every parser of untrusted bytes.

## Options

1. `acpi` 6.1.1 on a nightly toolchain.
2. An older stable-compatible `acpi` release.
3. A small parser for the tables Keel reads.

## Decision

Option 3. `kernel/core/src/acpi.rs` parses the RSDP, XSDT/RSDT, MADT and
HPET tables in `#![forbid(unsafe_code)]` code: every length is checked
against the bytes available, every checksum is verified, reserved field
values are rejected, and a malformed table is refused as a whole.
`kernel/hal/src/acpi.rs` hands it only byte ranges that lie inside the
ACPI regions of the memory map. Layouts are cited from the ACPI 6.6
specification and the IA-PC HPET specification 1.0a.

## Consequences

- No new third-party code in the kernel; stays on stable Rust.
- About 450 lines including tests, with a random-input loop on every
  `cargo test`. A cargo-fuzz target joins the other parser fuzz targets
  with the security work.
- Keel cannot evaluate AML. Nothing before Phase 6 needs it; if power
  management or device discovery later does, this is revisited.
