# ADR 0006: One user-space runtime crate may use `unsafe`

Status: accepted (Phase 1, P1-T11). Extends spec section 1, rule 7
("confine `unsafe` Rust to the designated low-level crates"), which
section 7 states for the kernel only (`kernel/hal`).

## Context

Keel's own user programs (`user/`: test programs now, `keel-init`,
`keel-shell` and others later) are `no_std` Rust programs that talk to the
kernel through the Linux x86-64 system-call ABI, so they also run on
Linux. Any such program needs a little `unsafe` code and assembly: the
ELF entry point `_start`, reading argc/argv/envp/auxv from the initial
stack, and the `syscall` instruction. The audit rejected `unsafe`
anywhere outside `kernel/hal`.

User code runs in ring 3. Its `unsafe` cannot weaken the kernel: every
pointer it hands to the kernel goes through the checked user-copy
routines, and the kernel's isolation does not depend on user programs
being correct.

## Options

1. Allow `unsafe` in every user program.
2. One runtime crate, `user/keel-rt`, holds all user-space `unsafe` and
   assembly behind a safe API; programs themselves stay free of it.
3. Write user programs in C against musl.

## Decision

Option 2. `user/keel-rt` provides `_start`, a safe view of the initial
stack (`Startup`: arguments, environment, auxiliary vector, program
headers, AT_RANDOM, AT_EXECFN), `write`, `exit`, a raw `syscall3`, and a
panic handler. Every `unsafe` block in it has a `// SAFETY:` comment and
every assembly block a reasoning comment, as in `kernel/hal`.

The audit allows `unsafe` under `user/keel-rt/` and nowhere else outside
`kernel/hal`, and lists the crate in the census. Programs register their
entry point with `keel_rt::main!(main)`; that macro writes the one
`#[unsafe(export_name)]` attribute, and its source lives in `keel-rt`.

## Consequences

- Programs in `user/tests` contain no `unsafe` and use only atomics and
  safe slices for their own data.
- The same binaries run on Linux. `cargo xtask test` runs them natively
  on an x86-64 Linux host (CI) before running them on Keel, so a test that
  passes on Keel is also checked against the real Linux ABI.
- musl-based C programs are still needed for the Phase 1 acceptance
  ("musl hello world"); they come with P1-T13 and do not change this
  decision.
