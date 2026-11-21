# ADR 0002: Keel carries its own Limine protocol bindings

Status: accepted (Phase 0). Deviates from spec decision D4, approved by
the owner on 2026-11-17.

## Context

Decision D4 says to use the `limine` crate. Checked against crates.io on
2026-11-17:

- `limine` 0.6.2 to 0.6.5 (the current line) contain
  `#![feature(ptr_metadata)]` in `src/lib.rs` and therefore build only on
  nightly Rust.
- `limine` 0.5.0 builds on stable but predates the newer protocol base
  revisions and is from a different maintainer.

The spec prefers a pinned stable toolchain and allows nightly only when a
required feature needs it.

## Options

1. `limine` 0.6.5 on a dated nightly toolchain.
2. `limine` 0.5.0 on stable.
3. Write the request and response structures in `kernel/hal`.

## Decision

Option 3. `kernel/hal/src/boot/limine.rs` declares the eight requests Keel
uses, each checked against PROTOCOL.md with the section named in a
comment, plus layout unit tests. `kernel/hal/src/boot/mod.rs` wraps them
in a safe API with bounded, checked reads.

## Consequences

- The kernel stays on stable Rust (1.100.0).
- One fewer third-party crate in the kernel's trusted base; the code that
  dereferences bootloader pointers is ours to review.
- The kernel requests base revision 6, the current one, and refuses to
  continue if the bootloader does not honour it.
- New protocol features have to be added by hand from PROTOCOL.md.

## Sources

- Limine boot protocol: https://codeberg.org/Limine/limine-protocol
  (PROTOCOL.md, read 2026-11-17)
- `limine` crate versions: https://crates.io/crates/limine/versions
