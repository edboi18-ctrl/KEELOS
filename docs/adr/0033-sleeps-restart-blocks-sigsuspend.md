# ADR 0033: Sleeps, restart blocks and sigsuspend

Status: accepted (Phase 3, P3-T13 part 2).

## Context

Running BusyBox's `sh` on the console (ADR 0032, Phase 3 acceptance
item 3) found two calls Keel lacked:
- **nanosleep.** BusyBox's `sleep` calls it, and it was ENOSYS. BusyBox
  treats that as done, so `sleep 1 &` ended at once.
- **rt_sigsuspend.** ash's `wait` and its wait for a foreground job call
  `waitpid` with WNOHANG, then block every signal and wait in
  `sigsuspend` for their SIGCHLD handler (`shell/ash.c`, `waitproc`).
  With ENOSYS that loop never ended: the handler could not run with
  everything blocked.

A sleep also needs Linux's restart block. A sleep cut short by a stop
and SIGCONT, with no handler run, carries on for the time that was left.
It is not restarted from the start, and it is not EINTR. ADR 0031 left
restart blocks out.

The rules are Linux v6.12's:
- `kernel/time/hrtimer.c`: `hrtimer_nanosleep`, `do_nanosleep`,
  `nanosleep_copyout`, `SYSCALL_DEFINE2(nanosleep)`;
- `kernel/time/posix-timers.c`: `SYSCALL_DEFINE4(clock_nanosleep)`,
  `posix_clocks[]` and which clocks have `nsleep`;
- `kernel/time/alarmtimer.c`: `alarm_timer_nsleep`;
- `include/linux/time64.h`: `timespec64_valid`;
- `kernel/signal.c`: `sigsuspend`, `SYSCALL_DEFINE2(rt_sigsuspend)`,
  `SYSCALL_DEFINE0(restart_syscall)`, `do_no_restart_syscall`;
- `arch/x86/kernel/signal.c`: `handle_signal` and
  `arch_do_signal_or_restart` for `-ERESTART_RESTARTBLOCK`.

## Decision

1. **ERESTART_RESTARTBLOCK (516)**, a third restart code beside ADR
   0031's ERESTARTSYS and ERESTARTNOHAND:
   - with no handler run, the return to user mode puts
     `__NR_restart_syscall` (219) in RAX and steps RIP back over the
     SYSCALL;
   - with a handler, the call is EINTR.

   Each thread has a restart record (`ThreadInfo::restart`, Linux's
   `restart_block`). Today it only ever holds a relative sleep's deadline
   and its `rem`.
2. **restart_syscall** runs the thread's restart record. With none it is
   EINTR, as `do_no_restart_syscall`. A sleep call empties the record when
   it starts, as Linux resets `restart_block.fn`.
3. **nanosleep** sleeps relative to CLOCK_MONOTONIC. The checks come in
   Linux's order: EFAULT for the request, then EINVAL for a negative
   tv_sec or a tv_nsec outside 0..1e9. When a signal the thread does not
   block is pending:
   - with no time left, it succeeds;
   - otherwise it writes the time left to `rem`, if given (EFAULT if it
     cannot), sets the restart record to its deadline and returns
     ERESTART_RESTARTBLOCK.

   After a stop and SIGCONT, it sleeps on to the same deadline.
4. **clock_nanosleep:**
   - **Clocks that can sleep:** REALTIME, MONOTONIC, BOOTTIME and TAI.
   - **EOPNOTSUPP before the request is read:** MONOTONIC_RAW and the
     COARSE clocks (no `nsleep`).
   - **EOPNOTSUPP after it:** the alarm clocks, as `alarm_timer_nsleep`
     without a real-time clock device, which Keel does not drive.
   - **EINVAL:** other numbers, the CPU-time clocks among them.
   - **Relative,** it is nanosleep on that clock.
   - **With TIMER_ABSTIME** (other flags ignored), it sleeps until that
     time. It never writes `rem`, and a signal gives ERESTARTNOHAND, so
     a restart keeps the same deadline.

   Keel has one time base: REALTIME and TAI are the monotonic clock
   counted from the epoch, as clock_gettime gives them.
5. **rt_sigsuspend:**
   - **Checks:** a size other than 8 is EINVAL, an unreadable mask
     EFAULT.
   - **The wait:** the mask replaces the thread's blocked one, through
     the temporary mask ppoll and pselect6 use (ADR 0025), with SIGKILL
     and SIGSTOP kept unblocked. The call waits until a signal that mask
     lets through is pending, then returns ERESTARTNOHAND.
   - **With a handler,** it runs under the temporary mask, its frame
     restores the old one, and the call is EINTR.
   - **With no handler** (a stop), the old mask is put back and the call
     is restarted, so it waits again.

## Not yet covered

- **Other calls Linux resumes through a restart block:** poll and ppoll
  with a timeout, select, and futex waits with a timeout. They are still
  EINTR without a handler (ADR 0031). They can use the record now.
- **Timer slack.** Linux may sleep up to `timer_slack_ns` (50 µs) longer.
  Keel wakes at the first scheduler pass after the deadline.
- **CPU-time clocks:** Linux can sleep on a process's CPU time (clock 2);
  Keel keeps no CPU time.
- **A real-time clock:** CLOCK_REALTIME still starts at the epoch at
  boot (docs/syscalls.md).

## Evidence

- **`exec.sleep` (phase 3) and `host.sleepprobe`.** `user/tests/sleepprobe`
  makes 17 checks, which pass under Linux (as root, and as an
  unprivileged user with umask 077, eight runs) and on Keel. Keel runs it
  twice and measures the second run: every node, frame and process is
  back. The checks:
  - **nanosleep:** a sleep lasting at least its request; EFAULT, then
    EINVAL for each bad tv_sec and tv_nsec; a zero sleep.
  - **clock_nanosleep's clocks:** EOPNOTSUPP for MONOTONIC_RAW and the
    COARSE clocks, even with a bad request; EINVAL past the table and for
    a bad request; relative sleeps on REALTIME, MONOTONIC and BOOTTIME.
  - **TIMER_ABSTIME:** a deadline kept; one in the past returning at
    once; unknown flags ignored.
  - **restart_syscall** with nothing to resume: EINTR.
  - **A handler:** a relative sleep EINTR with the time left in `rem`;
    an absolute one EINTR with `rem` untouched.
  - **A stop and SIGCONT, no handler:** a 300 ms sleep stopped at 100 ms
    and continued at 400 ms returns 0, soon after. Not EINTR (no restart)
    and not at 700 ms (restarted from the start). Checked for relative
    and absolute sleeps.
  - **SIGCONT alone** not ending a sleep.
  - **rt_sigsuspend:** EINVAL and EFAULT; a signal the temporary mask
    blocks not ending the wait, one it lets through ending it with EINTR
    after its handler; the old mask back after, and the held signal
    delivered then; a signal already pending ending the wait at once,
    and the caller's mask back; stopped and continued, waiting again
    until a signal with a handler comes.
- **`console.busybox` (phase 3), acceptance item 3:** see ADR 0032.
  BusyBox's `sleep 1 &` and `wait`, and its foreground jobs, use these
  calls.
- **Mutations** on Keel, 12, all caught (the sleepprobe check that
  failed in brackets):
  - **Restart blocks:** ERESTART_RESTARTBLOCK made EINTR without a
    handler (11), or restarting the original call instead of
    restart_syscall (11: it ends a whole request late); restart_syscall
    with no record succeeding (7).
  - **The sleeps:** the time left not written (8); an absolute sleep
    writing `rem` (9); the COARSE clocks sleeping (4); tv_nsec unchecked
    (2); a sleep not cut short by a signal (8).
  - **rt_sigsuspend:** the temporary mask not set (14); the size
    unchecked (13); EINTR instead of ERESTARTNOHAND, so a stop ends the
    wait (17, a check added).

## Consequences

- Programs that sleep with nanosleep or clock_nanosleep (BusyBox's
  `sleep`, and libc sleep functions built on them) work, and keep their
  deadline across job control.
- Programs that wait in `sigsuspend`, as ash does for its jobs, work.
- The other timed calls can be moved onto the restart record without new
  mechanism.
