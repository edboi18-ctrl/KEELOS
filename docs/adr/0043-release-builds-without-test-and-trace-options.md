# ADR 0043: release builds without test and trace options

Status: accepted (Phase 3, P3-S9).

## Context

**SR-21** (spec section 3): "Release images have no kernel command-line
option, device node, or environment variable that disables a security
control. Tracing options exist only in builds made with a
`debug-tracing` feature."

Spec section 15 asks for these debugging flags on the kernel command
line:
- `trace=syscalls` (every call with its arguments and result,
  filterable by PID);
- `trace=faults`;
- `trace=signals`;
- `trace=sched`.

None of them existed yet.

What a kernel accepted, before this change:

| Where | What | Weakens a control? |
| --- | --- | --- |
| Command line | `test=N`, `scenario=NAME`, `fuzz=M`, `stress=M`, `seed=N`: run the self-tests, the fuzzer or the stress test, then exit QEMU | Yes. A test boot prints the kernel's load address, the direct-map offset and the region bases, which undoes KASLR (SR-16); some scenarios fault the kernel on purpose; tests lower limits for themselves |
| Command line | anything else | No: ignored |
| Environment | none: the kernel reads no environment variables (programs' environments are theirs) | No |
| Device nodes | `/dev/null`, `zero`, `urandom`, `tty`, `ptmx`, `console`, `pts/*` | No: none controls the kernel (SR-9 already rules out `/dev/mem`, `/dev/kmem`, `/dev/port`) |

The command line of a release image comes from `limine.conf`, whose
hash is enrolled in the bootloader (SR-27), so it cannot be changed
without the boot failing. Even so, SR-21 asks that such options do not
exist in a release image at all, rather than being unreachable.

## Decision

### Two Cargo features of `keel-kernel`

| Feature | Holds | In |
| --- | --- | --- |
| `selftest` | the self-tests (`selftest.rs`), the options that start them, and the KASLR addresses that test boots print. It brings `debug-tracing`, which the self-tests check | test, fuzz and stress builds |
| `debug-tracing` | `trace=` and `trace.pid=`, and the tracing code in `keel-linux-abi` (`trace.rs`) and `keel-hal` (the scheduler's) | test builds, and `cargo xtask run --trace` |

- **xtask chooses** them per boot mode (`BootMode::kernel_features`). A
  normal build, which is also what `cargo xtask dist` ships, has
  neither.
- **The audit lints both:** `cargo xtask audit` runs clippy on the
  kernel without features and again with both, so test-only code is
  still linted.

### In a kernel built without them

- The code is not compiled in, so neither are the options. A word on
  the command line that would have been one is logged and ignored:
  `boot: test=3 ignored: this kernel was built without the self-tests`.
  This makes a mistaken release configuration visible on the console.
- The KASLR addresses are never printed: the condition that guarded
  them is now false by construction.

### The trace options (only with `debug-tracing`)

- **Flags:** `trace=WHAT[,WHAT...]`, where WHAT is one of:
  - `syscalls`: every system call, with its compartment, PID, TID,
    name, number, six arguments and result;
  - `faults`: every user fault, with its vector and RIP and the signal
    it becomes;
  - `signals`: every signal sent to a process, with its code;
  - `sched`: threads made and ended, with their exit status.
- **Filter:** `trace.pid=N` limits `syscalls`, `faults` and `signals`
  to processes whose PID in their compartment is N.
- **Bad input:** an unknown WHAT, or a PID that is not a positive
  number, is logged and ignored.
- **Output:** each traced event is one kernel-log line starting
  `trace:`. The parser is in `keel_core::trace` (host-tested).
- **Unimplemented calls:** these are logged once per number in every
  build, as spec section 15 asks, and so are profile refusals
  (ADR 0041). Neither is tracing.
- **For developers:** `cargo xtask run --trace "trace=syscalls
  trace.pid=1"` builds a tracing kernel and boots it. `--trace` takes
  only `trace=` and `trace.pid=` words.

## Evidence

- **`sr21.release_kernel`** (run with phase 3):
  - **Strings checked:** the release kernel's binary holds none of
    three strings that only gated code holds:
    - `TEST SUMMARY passed=` (the self-tests);
    - `trace: on (` (tracing);
    - `trace: sched: thread` (the scheduler's tracing).
  - **The strings are real markers:** a test kernel holds each, so a
    string that stopped naming gated code would fail the check rather
    than pass it.
- **`sr21.release_ignores_options`:** the release kernel is booted with
  `test=3 scenario=conformance fuzz=1 stress=1 seed=5
  trace=syscalls,sched trace.pid=1` on its command line. It:
  - logs each word as ignored;
  - runs no test (no `TEST` line);
  - traces nothing (no `trace:` line);
  - prints no kernel, direct-map or region address;
  - boots to keel-init's shell.
- **`trace.syscalls`** (phase 3, in-kernel):
  - with `trace=syscalls` for PID 1, `nap` run as PID 1 of a new
    compartment is traced;
  - with the filter on PID 99, nothing is.
- **Running only these:** `cargo xtask test --phase 3 --scenario
  release` runs the two `sr21` checks alone.
- **Host tests:**
  - `keel_core::trace`: the parser, including unknown words and a bad
    PID;
  - xtask: both SR-21 verdicts. One requires every marker in the test
    kernel and none in the release kernel. The other requires every
    word reported, the shell reached, and no test, trace or address
    line.

- **Mutations,** each caught:

  | Mutation | Caught by |
  | --- | --- |
  | the release kernel built with `selftest` | `sr21.release_kernel`: it contains `TEST SUMMARY passed=` |
  | the release kernel built with `debug-tracing` | `sr21.release_kernel`: it contains `trace: on (` |
  | the ignored-option notices removed | `sr21.release_ignores_options`: no line says `test=3` was ignored |
  | a release kernel treating every boot as a test boot | `sr21.release_ignores_options`: it printed the HHDM offset |
  | `trace.pid` ignored | `trace.syscalls`: 14 lines traced with the filter on PID 99 |
  | `exit` and `exit_group` not traced | `trace.syscalls`: 1 line for PID 1 |

  The first one at first failed to compile, which is how the self-tests'
  use of tracing came to light; `selftest` now brings `debug-tracing`.

## Consequences

- A test build is a different binary from a release build. Tests run
  the kernel with `selftest` and `debug-tracing`, while the release
  image is built and boot-checked separately (`dist`, `boot-check`),
  and the two SR-21 checks above boot and inspect the release kernel
  itself.
- Cargo keeps both feature sets' builds, so switching between them
  relinks rather than rebuilding everything.
- Phase 4's Wine bring-up will use `trace=syscalls` through
  `cargo xtask run --trace`.
