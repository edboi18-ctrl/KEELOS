# ADR 0038: the fork, thread and signal stress test, unreaped processes, and a heap leak

Status: accepted (Phase 3, acceptance item 4).

## Context

Phase 3 acceptance item 4 asks for "one hour of a randomized
fork/thread/signal stress test with no kernel panic and no leaked frames
(frame allocator count returns to baseline)".

The first 20-second run on Keel failed. kill(2) of a child that had
exited but was not yet reaped was ESRCH, where Linux accepts it. On
Linux v6.12:
- `kernel/signal.c`, `kill_pid_info_type`: finds the task still attached
  to the PID;
- `kernel/exit.c`, `__exit_signal`: clears the task's `sighand` only
  from `release_task`, when the zombie is reaped;
- so until then the signal is accepted. It goes nowhere: a group that is
  exiting ignores it.

`kill_something_info` (kill -1) walks `for_each_process`, and zombies
stay on that list until reaped.

The first one-hour run passed its checks, but the free frame count
fell by about 260 frames a minute: 15,554 frames (61 MiB) over the
hour, all of them in the kernel heap. The session's check counted only
frames outside the heap, so it could not see this. A count of live heap
bytes and a histogram by size found one 192-byte allocation left per
thread made by fork or clone: `sched::spawn_user_copy` boxes the new
thread's first register frame (`TrapFrame`, 24 registers), and
`user_thread_start` entered user mode with `enter_user_frame(*frame)`.
That moves the frame out of the box, but the box is freed only when its
scope ends, and `enter_user_frame` never returns. Every other call that
does not return was checked: none holds anything that needs freeing.

A mutation run then found a second window. `on_thread_exit` takes the
last thread's process out of the process table before it records the
wait status in the parent's child list, so in between the process was
neither running nor a zombie. Linux has no such window. A third, shorter
one showed in the second one-hour run, four minutes in: the exiting
thread left the process table before it left its process's thread
list, so for a moment the process was in the table under no thread,
and still had a thread listed, so it did not count as ended either.

## Decision

1. **The stress program**, `fixtures/musl-dynamic/stress`: a static
   musl build, so it runs in a compartment with an empty tree. It is
   reproducible from the pinned recipe. `stress SEED SECONDS` runs until
   its time is up, choosing each step from SEED's xorshift64 sequence
   (Marsaglia 2003, section 3: shifts 13, 7, 17). The steps:
   - **Fork a child** that does one of:
     - starts 0 to 3 threads that make calls and signal the main thread,
       then exits with a chosen code;
     - crashes (SIGSEGV);
     - waits in pause() for SIGTERM or SIGKILL;
     - forks and reaps a grandchild, then exits;
     - ends the process with _exit from one of its threads
       (exit_group).
   - **Signal a child:** SIGTERM or SIGKILL; SIGSTOP, then wait4 with
     WUNTRACED, then SIGCONT; or SIGUSR1, which everything catches.
   - **Reap** children with WNOHANG.
   - **Thread pairs:** two threads in the parent, each with an alternate
     stack, signal each other (SA_ONSTACK).
   - **Sleep** for a millisecond.

   Every wait status is checked against what the child was told to do
   and what was sent to it. At the end every child is reaped, and wait4
   must then be ECHILD.
2. **On Keel**, the kernel runs it in a compartment of its own: 128
   processes and threads, 256 MiB.
   - **It passes when:**
     - the program exits 0 within its time plus 10 minutes;
     - every frame outside the kernel heap and every process is back;
     - the compartment has no process and no frame left;
     - the kernel heap holds at most 64 KiB more live bytes than before,
       measured from a warm kernel. The long session first runs a
       20-second warm-up from another seed, checked like any session
       except for this. From a cold boot the tables that fill once and
       then stay (the scheduler's last 1024 exit statuses, queue
       capacities) grow by about 150 KiB. A one-hour run measured from
       a cold boot showed that: live bytes 3,085,218 before, then 3.35 MB
       at minute 1 and 3.48 MB at minute 59, flat. The leak came to over
       300 KiB in 20 seconds. The heap keeps the pages it grew into
       for small blocks, so the free frame count itself ends lower by
       the heap's peak growth. The live bytes show whether anything
       inside the heap was kept.
   - **Where it runs:**
     - `stress.short`: 20 seconds in every phase 3 boot, so CI runs it;
     - `cargo xtask stress --minutes N --seed S`: the long session. It
       logs the free frames and the compartment's processes and memory
       every minute, and the full log goes to `target/test-logs/stress.log`.
3. **The register frame** is copied out of its box, and the box freed,
   before the new thread enters user mode. `keel_hal::heap::live_bytes`
   counts the bytes allocated and not yet freed, and the stress session
   logs it every minute.
4. **Unreaped processes:** `process::zombies` now covers every child
   that has ended and is not yet reaped. That includes one whose last
   thread has gone but whose status its parent has not recorded yet.
   - **kill** of a single PID accepts a signal for one, which goes
     nowhere. Only a PID that does not exist is ESRCH.
   - **tgkill and tkill** do the same when the TID is the zombie's PID
     (and the TGID, if given, too).
   - **kill(-1)** counts them, so it succeeds when every other process
     has ended but is not yet reaped.
   - **Group kill** already counted zombies (ADR 0030) and now covers
     the window too. So do setpgid's checks and /proc (ADR 0037).
   - **A thread's exit** takes it out of its process first and out of
     the process table after. So a process is at every moment either in
     the table or, with no threads left, among the unreaped.

## Evidence

- **Under Linux** (`host.musl-stress`, 5 s, seed 1), and by hand:
  - as root, seeds 2 to 6 for 8 s each and seed 77 for 120 s (208,758
    children);
  - as an unprivileged user with umask 077, seeds 8, 9 and 102 to 106.

  Every run passed.
- **On Keel**, `stress.short` (seed 20261126, 20 s under TCG): 639
  children forked and reaped, 161 stops, 357 signals, 246 thread pairs.
  Frames outside the heap 1,032,647 before and after; no process or
  compartment slot left.
- **The acceptance run**, `cargo xtask stress --minutes 60 --seed
  20261126` under QEMU TCG, passed:
  - **Warm-up** (20 s, seed 20261127): passed; live heap bytes
    3,085,218 to 3,218,778.
  - **The hour:**
    - 89,360 children forked and reaped, 19,816 stops, 46,572 signals
      sent, 29,926 thread pairs; no panic, every wait status as
      planned;
    - frames outside the kernel heap 1,032,644 before and after;
    - no process or compartment slot or frame left;
    - live heap bytes 3,218,777 to 3,235,513, with 3.43 MB at minute 1,
      3.52 MB at minute 30 and 3.39 MB at minute 59: no growth;
    - free frames 1,031,505 to 1,031,493. The 12 frames are heap pages
      kept from its peak for small blocks; nothing in them is live.
  - **Two earlier hour-long runs** found the heap leak (15,554 frames
    gone) and the third window (ESRCH at minute 4). A third, measured
    from a cold boot without the warm-up, passed every check but the
    heap one: live bytes 3,085,218 to 3,234,434, flat after minute 1.
- **`exec.procdirs`** (ADR 0037) now also checks kill and tgkill of a
  zombie (0, also with SIGCONT), and ESRCH for both once it is reaped,
  under Linux and on Keel.
- **Mutations** on Keel against the phase 3 main boot:
  - **Caught by `stress.short`:**
    - the register frame's box kept again (the live bytes: 4,166,785 to
      4,487,977 in 20 s);
    - kill of a zombie ESRCH again (check 15);
    - an exited process's address space leaked (the frame count);
    - stops not reported to wait4 WUNTRACED (the program waits for
      ever; the boot times out).
  - **kill of a zombie ESRCH** is also caught by `exec.procdirs`
    (check 11).
  - **Equivalent:** exit_group's code ignored for the exit status. Every
    other thread is asked to exit with that same code, so whichever
    exits last carries it anyway.
  - **Survived: the window fix reverted.** The window is a few steps of
    the last thread's exit: the vfork release, the terminal, record
    locks and orphaned groups (the address space's frames go later,
    when the scheduler drops its reference). That is too short to hit
    on purpose. One stress run under another mutant hit it, which is
    how it was found. A check that kills a child while it frees 64 MiB
    did not reach it either, and was not kept. The fix is there because
    Linux has no such window.
