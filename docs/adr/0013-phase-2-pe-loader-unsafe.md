# ADR 0013: Where `unsafe` may appear for the Phase 2 PE loader

Status: accepted (Phase 2). Extends ADR 0006. The `peldr` part ends when
`peldr` is retired (P4-T8).

## Context

Phase 2 adds two kinds of code that ADR 0006 does not cover:

- **Windows test programs** (`winetest/`), starting with `hello-console`.
  They are Windows executables. The only way a Windows program reaches
  the OS is by calling DLL functions through FFI, which is `unsafe` in
  Rust. They are not part of Keel: they are inputs Keel runs, like the C
  musl fixture, and they are checked in as pinned binaries.
- **`peldr`** (`user/peldr`), the toy PE loader. It parses a file anyone
  can craft, then maps the image, patches it, and calls into it. Copying
  into memory it mapped is the kind of thing `keel-rt` already offers
  safely (`Region`). Two things cannot be made safe:
  - Calling the image's entry point runs foreign machine code in the
    process. No Rust API can make that sound.
  - The stubs (`WriteFile` and the rest) receive raw pointers from that
    code, such as where to store the byte count, and must write through
    them.

## Decision

1. **`winetest/` may use `unsafe`** for calls into Windows DLLs and their
   arguments, each with a `// SAFETY:` comment. The census counts it
   separately. Nothing in `winetest/` is built into Keel.
2. **The PE parser is its own crate, `user/pe`, under
   `#![forbid(unsafe_code)]`.** It is the part that reads hostile input.
   It checks every offset and size against the file and the image, and
   has host tests, a malformed-file corpus and a fuzz target (Phase 2
   security note).
3. **`peldr` may use `unsafe` in one file, `user/peldr/src/foreign.rs`,
   and nowhere else.** That file holds the entry-point call, the stubs'
   pointer writes, and the Windows calling-convention glue. Everything
   else in `peldr` is safe Rust over `keel-rt` and `pe`. The census allows
   exactly that path.

Why this is acceptable: `peldr` runs in ring 3. Whatever the loaded image
does, it can harm only the process it runs in. The kernel's isolation
does not depend on it, which is the reasoning behind ADR 0006. And `peldr`
is disposable by design (spec section 9): it is retired once Wine runs
the same `.exe` (P4-T8).

## Consequences

- The audit's census lists `winetest/hello-console` and `user/peldr` with
  their counts. Any `unsafe` elsewhere in `peldr`, or in `user/pe`, fails
  the audit.
- When `peldr` is retired, this ADR's second exception goes with it.
