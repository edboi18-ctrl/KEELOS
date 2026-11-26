# ADR 0019: Threads, futexes and ending threads

Status: accepted (Phase 3: P3-T4, the first part of P3-T5, and `kill`
with SIGKILL until P3-T6).

## Context

Wine and musl's pthreads create threads with `clone` (the trace's flag
set), synchronize with `futex`, and end processes with `exit_group`.
Ending a process with several threads needs a way to stop threads that
are running user code or are blocked in the kernel. The same mechanism
lets `kill(SIGKILL)` end a looping child (`badexec`).

## Decision

1. **Ending a thread: an exit request** (`sched::request_exit`).
   - The thread ends the next time it would return to user mode. That is
     the next timer interrupt if it is running user code, or when its
     system call returns.
   - A blocked or sleeping thread is made ready. `WaitQueue::wait_until`
     returns early for it, so its system call ends too.
   - The first request wins.
2. **Threads.** A process now has a table of threads. Each thread has a
   TID and a `clear_child_tid`:
   - The first thread's TID is the PID.
   - A thread made by `clone` takes a compartment slot. Its TID is the
     compartment's next PID, and Linux likewise counts threads against
     `RLIMIT_NPROC`.
   - `gettid` and `set_tid_address` are per thread.
3. **clone** (x86-64 order: flags, stack, parent_tid, child_tid, tls;
   `kernel/fork.c`, no `CLONE_BACKWARDS`). As `copy_process`,
   `CLONE_THREAD` without `CLONE_SIGHAND`, or `CLONE_SIGHAND` without
   `CLONE_VM`, is `EINVAL`.
   - **Without `CLONE_VM`** it is `fork`, on the given stack if one is
     given.
   - **With it**, a thread. The flags must include `CLONE_VM`,
     `CLONE_FS`, `CLONE_FILES`, `CLONE_SIGHAND` and `CLONE_THREAD`, and
     may add `CLONE_SYSVSEM`, `CLONE_SETTLS`, `CLONE_PARENT_SETTID`,
     `CLONE_CHILD_CLEARTID`, `CLONE_CHILD_SETTID` and `CLONE_DETACHED`
     (which Linux ignores). That is the Wine trace's set and musl's.
   - Anything else is `EINVAL` for now: `CLONE_VFORK`, `CLONE_VM` without
     `CLONE_THREAD`, namespaces. (ADR 0034 adds `CLONE_VFORK`, alone and
     with `CLONE_VM`.)
   - The new thread starts with the caller's registers, with RAX = 0 and
     RSP = the given stack. It has the caller's FS/GS bases, with FS =
     tls under `CLONE_SETTLS` (`EPERM` outside the user half), and the
     caller's FPU state.
4. **Thread exit**, as Linux's `mm_release`. If other threads still share
   the memory:
   - the TID word (`clear_child_tid`) gets 0 and one futex waiter on it
     is woken;
   - the thread's slot is freed.
   - A fault in any thread ends the whole process with the fault's
     signal, as on Linux.
   - When the last thread exits, the process exits (ADR 0018). Its wait
     status is the `exit_group` code, the last thread's exit code, or the
     signal.
5. **exit_group** records the code and asks every other thread to end.
   It, and any call that ends the caller, must not keep a reference to
   the process on the ending thread's stack, because that thread never
   unwinds. A first version did, and every process leaked with its
   compartment slot. `execve`'s failure past the point of no return
   therefore asks for the exit instead of exiting.
6. **futex**, as `kernel/futex/` in v6.12:
   - **Commands.** `FUTEX_WAIT`, `FUTEX_WAKE`, `FUTEX_REQUEUE` and
     `FUTEX_CMP_REQUEUE`, with `FUTEX_PRIVATE_FLAG`. Anything else, or
     `FUTEX_CLOCK_REALTIME`, is `ENOSYS`.
   - **Errors.** A misaligned address is `EINVAL`. A mismatched value is
     `EAGAIN`, checked under the same lock that wakes take, so no wake is
     lost. A relative timeout gives `ETIMEDOUT`; an invalid timespec
     gives `EINVAL`.
   - **Requeue** wakes up to `val` waiters and moves up to `val2` of the
     rest; `CMP` first requires `*uaddr == val3`. musl's condition
     variables use it, and without it the threads test hung on
     `ENOSYS`.
   - **Keys** are (address space, address). There is no shared memory
     between address spaces yet, so shared futexes come with
     `MAP_SHARED`.
   - **Timed waits** poll once a millisecond until a timed wait queue
     exists.
7. **kill**, until signal delivery (P3-T6):
   - signal 0 checks existence; `SIGKILL` ends every thread, and the
     wait status is 9;
   - other signals are `EINVAL` for now; Linux would deliver them;
   - a PID names a process only in the caller's compartment (`ESRCH`
     otherwise);
   - process groups (PID 0 or negative) are `ESRCH`.
8. **The fuzzer** never calls `kill` (it could end itself) or `futex` (a
   wait whose value happens to match would block for ever).

## Evidence

- `fixtures/musl-dynamic/threads`, a C program with musl pthreads, passes
  under Linux and on Keel (`exec.threads`). It checks:
  - four workers contend on a mutex, 40,000 increments;
  - a condition variable broadcast, which requeues;
  - thread-local values (`CLONE_SETTLS`);
  - TIDs that differ from the PID;
  - `pthread_join`;
  - a raw clone with `CLONE_CHILD_CLEARTID` whose exit clears the word
    and wakes a futex waiter. musl's own join does not need the kernel's
    wake, so this checks it directly;
  - `exit_group` ending a thread blocked in a futex wait and one spinning
    in user mode.
  - Nothing is left over.
  - Mutations: no wake at thread exit makes the raw-clone check time out
    (exit 5); an `exit_group` that leaves threads leaves 2 behind.
- `user/tests/threadprobe` passes under Linux and on Keel
  (`exec.thread_calls`): clone flag refusals; `gettid`; `kill` with
  signal 0, `ESRCH`, and `SIGKILL` ending a waiting child (status 9);
  futex `EAGAIN`, `EINVAL`, `ETIMEDOUT`, `EINVAL` for a bad timespec,
  wake with no waiters, `ENOSYS`, and `CMP_REQUEUE`'s `EAGAIN`.
- `badexec` now kills children still running after 3 s. Two 3,000-file
  runs killed 10 and 4 looping programs; no panic, everything back.

## Not yet

- Signal delivery (P3-T6). With it come the other signals, `SIGCHLD`,
  and interrupting a blocked call with `EINTR` and `SA_RESTART`.
- `vfork` and `CLONE_VFORK`, which musl's `posix_spawn` uses (done in
  ADR 0034).
- Shared futex keys, futex `BITSET` and PI commands, and
  `membarrier`. musl handles `membarrier`'s `ENOSYS`.
