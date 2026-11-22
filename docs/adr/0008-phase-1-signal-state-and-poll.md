# ADR 0008: Signal state without delivery, and rights-limited poll, in Phase 1

Status: accepted (Phase 1, acceptance item 2). Signal handling is
replaced by P3-T6; poll's waiting by P3-T10.

## Context

Phase 1 acceptance item 2 runs a program built with Rust's real standard
library for `x86_64-unknown-linux-musl`. Its startup (Rust 1.100.0,
`library/std/src/sys/pal/unix/mod.rs` and `stack_overflow.rs`) calls:

- `poll` on fds 0-2 with no events, to find closed standard streams. Any
  error other than EINTR, EINVAL, EAGAIN or ENOMEM aborts the program, so
  ENOSYS is fatal. (It did abort under Keel before this change: poll,
  then musl's `abort` path, then a crash.)
- `rt_sigaction(SIGPIPE, SIG_IGN)`, asserted to succeed.
- `rt_sigaction` to read and then set SIGSEGV and SIGBUS handlers, with an
  alternate stack from `mmap`, `mprotect` and `sigaltstack`, so stack
  overflows print a message.
- `rt_sigprocmask`, through musl's `sigaction` wrapper.

The spec puts signals in Phase 3 (P3-T6: generation, delivery, frames,
`rt_sigreturn`) and poll/epoll over a readiness mechanism in P3-T10.
Pulling them forward would break the phase gate.

## Decision

1. **Record signal state, deliver nothing.** `rt_sigaction`,
   `rt_sigprocmask` and `sigaltstack` store dispositions, the blocked mask
   and the alternate stack in `keel_core::signal::SignalState`, with every
   validation rule and error order of Linux v6.12 (`kernel/signal.c`), so
   what a program reads back is what Linux would return. Nothing is ever
   delivered: a CPU fault still ends the thread with status 128 + signal,
   as before, even when a handler is set. That is also what an unhandled
   fault does on Linux, and Rust's handler would only print a message and
   abort for a stack overflow. P3-T6 adds delivery to this state.
2. **poll checks readiness now; waiting re-checks every 10 ms.** Keel's
   files are either always ready or are the console. A poll that must
   wait sleeps 10 ms between checks until something is ready or its
   timeout passes. That is correct but adds up to 10 ms of latency; P3-T10
   replaces it with wake-ups.
3. **poll reports only readiness the handle may act on (SR-1).** POLLIN
   needs READ, POLLOUT needs WRITE; POLLERR, POLLHUP and POLLNVAL are always
   reported. Linux reports readiness whatever the access mode. Keel's
   handle rights can be narrower than the access mode (a transferred handle
   can lose rights), and a handle should not reveal the state of an
   operation it cannot perform. A program asking only about what it can do
   sees no difference. The conformance test checks this as a Keel-only case.
4. **The std test program links with `rust-lld`.** The musl target's
   default linker is `cc`, which a Windows host lacks. `-Clinker=rust-lld
   -Clinker-flavor=ld.lld` with the target's self-contained start files and
   `libc.a` (rustc's `-Clink-self-contained`, on by default for this
   target) builds the same program on Linux and Windows with nothing but
   the pinned toolchain.

## Consequences

- Programs that install handlers and rely on them running (Wine) do not
  work until P3-T6. Phase 1 has no such program.
- Per-thread state (mask, alternate stack) lives in the process until
  clone(2) arrives, which is correct while every process has one thread.
- The one Linux difference (decision 3) is recorded in
  `docs/syscalls.md`; Phase 3's differential tests must allow for it.
