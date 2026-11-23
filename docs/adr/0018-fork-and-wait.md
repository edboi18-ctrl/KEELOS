# ADR 0018: fork and wait4

Status: accepted (Phase 3, second part of P3-T3).

## Context

Wine starts its processes with `fork` and `execve` (25 forks in the
trace) and reaps them with `wait4`. The Phase 2 audit (item 4) noted that
copy-on-write sharing (`AddressSpace::duplicate`) had only been exercised
by kernel self-tests. Security acceptance P3 item 3 asks that a fork bomb
in one compartment leave another responsive.

## Decision

1. **fork** creates a process in the caller's compartment:
   - counted against its process limit (`EAGAIN`);
   - with a copy-on-write duplicate of the address space, charged to the
     compartment's memory budget (`ENOMEM`);
   - with a clone of the handle table, whose handles refer to the same
     open files and so share offsets. fork(2): "refer to the same open
     file description";
   - with copies of the signal state, program break, root and working
     directory;
   - not inheriting `clear_child_tid`.

   The child's thread starts from a copy of the caller's saved registers
   (`SyscallArgs::frame`) with RAX = 0, and the caller's FS/GS bases and
   FPU state (`sched::spawn_user_copy`). The registers go through
   `prepare_user_return` like any return to user mode. The parent gets
   the child's PID.
2. **The child is recorded before it can run.** The process table stays
   locked, with interrupts off, until the child's thread is created and
   the parent holds its record. A child cannot exit before its parent
   knows it.
3. **Zombies.**
   - When a process exits, the exit hook (which now receives the status
     and fault) frees its handles, address space and its own children's
     records.
   - It stores the wait status in its parent's record. The status is
     encoded as Linux's `kernel/exit.c`: `(code & 0xff) << 8` for an
     exit, the signal number for a death by fault.
   - The record keeps the process object, and with it the compartment
     slot, until `wait4` reaps it. As on Linux, where a zombie still
     counts against `RLIMIT_NPROC`, exiting children cannot pile up
     without limit.
   - A process whose parent has gone is dropped at once. There is no
     reparenting to an init process yet.
4. **wait4** follows `kernel_wait4`:
   - unknown options are `EINVAL`, and `INT_MIN` is `ESRCH`;
   - `-1` and `0` wait for any child, since there are no process groups
     yet; another negative pgid finds none (`ECHILD`);
   - no matching child is `ECHILD`;
   - `WNOHANG` with none exited returns 0; otherwise it blocks until a
     matching child exits;
   - the status is written if asked for, and `rusage` as zeros;
   - `WUNTRACED` and `WCONTINUED` change nothing until stopped processes
     exist (P3-T6).

   **getppid** returns the parent's PID in the compartment, or 0 without
   one, as Linux's `task_tgid_vnr` gives for a parent outside the
   caller's namespace.
5. **The system-call fuzzer never calls clone, fork or vfork.** Each
   child would go on fuzzing and forking, in the system compartment,
   which has no process limit. That changes when the fuzzer runs inside
   a limited compartment (P3-S8).

## Evidence

- `user/tests/forkprobe` passes under Linux (`host.forkprobe`) and on
  Keel (`exec.fork_wait`). It checks:
  - the child's view: return value 0, `getppid`, `getpid`;
  - copy-on-write: the child's write is not seen by the parent;
  - a shared file offset;
  - `WNOHANG` while the child runs, a blocking wait, and status `7 << 8`;
  - a reaped child cannot be waited for twice;
  - a child killed by a fault reports signal 11;
  - twenty children exiting before they are waited for are all reaped
    with their statuses;
  - `ECHILD` and `EINVAL`.
  - The kernel checks that no process is left over and no frame is lost
    outside the kernel heap. The heap keeps a few pages for the
    scheduler's bounded table of recent exit statuses. Measured run by
    run: 0 frames lost outside the heap, the heap growing 1 to 3 pages
    per run as that table fills.
- `compartment.fork_bomb`: in a compartment of 8 processes, the bomb
  gets 7 children, then `EAGAIN`.
  - Once its children have exited unreaped, it still gets `EAGAIN`;
    after reaping one, a fork succeeds.
  - Meanwhile a program in another compartment runs to completion.
  - Afterwards every slot and frame is back.
- Mutation: a wait status without the `<< 8` fails `forkprobe` (exit 12).
- Host test: `HandleTable` clones share the objects.

## Not yet

- `vfork` and `clone` (P3-T4).
- Process groups and sessions, and reparenting to an init process.
- Delivering `SIGCHLD` (P3-T6).
