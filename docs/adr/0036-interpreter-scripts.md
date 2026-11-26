# ADR 0036: `#!` interpreter scripts in execve

Status: accepted (Phase 3, after P3-T13).

## Context

execve on Keel ran only ELF programs (ADR 0017). A file starting with
`#!` was ENOEXEC, so only shells could run scripts, because they fall
back to running the file themselves (POSIX XCU 2.9.1.4). Other programs
that run a script call execve on it directly: `env`, `xargs`,
`find -exec`, and BusyBox's `pidof this` test (ADR 0034), which runs
a script and expects the process to carry the script's name.

The rules are Linux v6.12's:
- `fs/binfmt_script.c`, `load_script`: the line's parsing, and argv
  rewritten;
- `fs/exec.c`: `exec_binprm` (at most five interpreter rounds: ELOOP
  after that), `prepare_binprm` (the first BINPRM_BUF_SIZE bytes),
  `begin_new_exec` (the thread named `kbasename(bprm->filename)`);
- `include/linux/binfmts.h`: BINPRM_BUF_SIZE 256;
- execve(2), "Interpreter scripts".

## Decision

1. **The line** (`keel_core::script::interpreter`), as `load_script`
   reads it:
   - **Not a script:** the file does not start with `#!`. It goes on to
     the ELF loader as before.
   - **The buffer:** the first 256 bytes, up to the first newline. With
     no newline in them, the line is cut at 255 bytes. The interpreter's
     name must then end inside the buffer (a blank, a tab or a NUL after
     it), or the exec is ENOEXEC: a cut-off name is never run.
   - **The parts:** blanks and tabs after `#!` and at the end are
     skipped. The name runs to the first blank, tab or NUL. The argument
     is everything after the blanks that follow, up to a NUL, with its
     inner blanks kept: one argument, not split.
   - **No name:** the line is only blanks (ENOEXEC).
2. **The exec:** argv becomes the interpreter's name, the argument if
   there is one, the path execve was given, and the original argv from
   its second element on. The interpreter is looked up from the process
   root and working directory, as the script was, and can itself be a
   script.
   - **Depth:** five levels of scripts run; at a sixth, execve is ELOOP,
     with the process unchanged.
   - **Limits:** the strings added are counted against the same stack
     budget as the arguments (E2BIG).
   - **Failures** are the interpreter's lookup errors: ENOENT if it is
     missing, EACCES if it is a directory or not a regular file.
3. **What the new program sees:**
   - **The thread name** (/proc/self/comm) is the last part of the path
     execve was given: the script's, not the interpreter's.
   - **AT_EXECFN** is the path execve was given.
   - **/proc/self/exe** is the interpreter the chain ended at.
   - **No execute-bit check** on the script or the interpreter (SR-6,
     as for ELF programs).

## Not yet covered

- BINPRM_FLAGS_PATH_INACCESSIBLE: execveat with a close-on-exec
  descriptor and an empty path, where the script's path would be
  `/dev/fd/N`. Keel has no execveat.
- binfmt_misc, which Linux lets an administrator configure, and which
  Keel does not have.

## Evidence

- **`exec.scripts` (phase 3) and `host.scriptprobe`.**
  `user/tests/scriptprobe` makes 10 checks. They pass under Linux (as
  root, and as an unprivileged user with umask 077) and on Keel. Keel
  runs it twice and measures the second run: every node, frame and
  process is back. The interpreter is the probe itself, run in a mode
  that prints its argv, thread name, AT_EXECFN and /proc/self/exe.
  - **argv:** `#!interp argument`; no argument, with blanks and tabs
    around the name; an argument with inner blanks kept and trailing
    ones dropped.
  - **Chains:** five levels, each putting its own path in; a sixth
    ELOOP.
  - **Refusals:** an empty line (ENOEXEC), a name cut off at 256 bytes
    (ENOEXEC), a missing interpreter (ENOENT), a directory (EACCES).
  - **Names:** the thread name and AT_EXECFN from the script's path,
    exe the interpreter's.
- **`keel_core::script` unit tests:** the parsing, including a line cut
  at 255 bytes and an argument cut by it.
- **Mutations** on Keel, 10, all caught (the scriptprobe check that
  failed in brackets):
  - **argv:** scripts not recognised (1); the original argv[0] kept (1);
    the script's path left out (1); the argument dropped (1);
  - **depth:** no limit (6); a limit of four levels (5);
  - **names:** the thread named after the interpreter (1); AT_EXECFN
    the interpreter's path (1);
  - **the line:** a cut-off name run (8); trailing blanks kept (3).

## Consequences

- Any program can run a script with execve, as on Linux: `env`,
  `xargs`, `find -exec`, BusyBox's applets.
- The interpreter's lookup is the script's: from the process root, so
  a `#!` line cannot name a file outside the compartment.
