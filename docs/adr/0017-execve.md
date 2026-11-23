# ADR 0017: execve

Status: accepted (Phase 3, first part of P3-T3).

## Context

`execve` is the first system call in the Wine trace. Wine starts its
preloader, `wineserver` and every Windows program with it. It is also
where the loader becomes attack surface (Phase 2 audit, item 5): a
program now chooses which file is loaded.

## Decision

1. **Everything that can fail happens first, and leaves the process as
   it was:**
   - reading the path and the argument and environment strings;
   - looking up the file from the process's root and working directory,
     so a compartment can run only what is in its tree;
   - loading it and its interpreter into a new address space
     (`exec::load_in`, ADR 0015);
   - charging that space to the compartment's memory budget (ADR 0014).
2. **Then the point of no return,** as Linux's `begin_new_exec`
   (`fs/exec.c` at v6.12):
   - the process gets the new space and program break;
   - close-on-exec handles are closed (`do_close_on_exec`);
   - caught signals are reset to `SIG_DFL` with their flags, restorer and
     mask cleared, while ignored ones stay ignored
     (`flush_signal_handlers(me, 0)`);
   - the alternate signal stack is dropped; the blocked mask is kept.
3. **The thread switches in place** (`sched::exec_current`):
   - its address space is replaced, with an IBPB when the CPU needs one,
     as on any switch to a different space (ADR 0007);
   - its FS and GS bases are zeroed (`elf_common_init`);
   - its FPU/SSE/AVX state is reset (`fpu_flush_thread`).

   The system-call return then builds a fresh frame: every general
   register 0, RFLAGS = IF (`start_thread_common`), the new RIP and RSP,
   and the user CS and SS the call came in with. The return path
   recognizes a user return by CS, so a zeroed CS would skip
   `prepare_user_return`; the first test run hung on exactly that. The
   old space is dropped only after the switch.
4. **A failure after the point of no return** ends the thread as if by
   `SIGSEGV`, as Linux's `bprm_execve` (`force_fatal_sig`). Only an
   allocation failure in `exec_current` can cause one.
5. **Errors as Linux:**
   - a missing file or path component: the lookup's error (`ENOENT`,
     `ENOTDIR`);
   - not a regular file: `EACCES`;
   - not a usable ELF executable: `ENOEXEC`; an unusable interpreter:
     `ELIBBAD`;
   - a string longer than `MAX_ARG_STRLEN` (32 pages, NUL included), or
     arguments and environment that do not fit the initial stack:
     `E2BIG`. The size is checked while reading, so a huge array is
     refused before it is read in full;
   - a bad pointer: `EFAULT`.
   - An empty `argv` becomes `[""]`, as Linux does since 5.18.
   - Mode bits grant nothing (SR-6), so no execute bit is checked.
6. **Not yet:**
   - `execveat`;
   - `#!` scripts. Linux would run the interpreter named on the first
     line; here such a file is `ENOEXEC`;
   - one thread per process, so the other-threads part of
     `begin_new_exec` has nothing to do yet;
   - the system-call fuzzer never calls `execve`, since a random success
     would end its run. Hostile executables get their own test (audit
     item 5).

## Evidence

- `user/tests/execprobe` passes under Linux (`host.execprobe`) and on
  Keel (`exec.execve`). It runs itself three times:
  - first, it checks the refusals (`ENOENT`, `EACCES`, `EFAULT`), sets
    up handles, signal state and FS/GS bases, and execs with a NULL argv;
  - second, it checks that argv is `[""]` and execs with real arguments;
  - third, it checks what was kept and what was reset.
  - The kernel checks that no frame is lost across the three programs.
- Mutations, each failing the test:
  - close-on-exec ignored (exit 32);
  - signals not reset (34);
  - FS/GS kept (37);
  - the old address space leaked (28 frames missing).
- Host tests:
  - `SignalState::reset_for_exec`: caught signals reset, ignored kept,
    mask kept, alternate stack dropped;
  - `HandleTable::take_close_on_exec`.
