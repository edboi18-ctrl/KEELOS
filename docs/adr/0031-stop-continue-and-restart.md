# ADR 0031: Stop and continue, SIGCHLD, and restarting interrupted calls

Status: accepted (Phase 3, job control after P3-T12).

## Context

ADR 0030 gave Keel process groups, sessions and a controlling terminal,
but a stop signal's default action still did nothing:
- ^Z did not stop a job;
- a background reader with SIGTTIN at its default got EINTR instead of
  stopping;
- wait4's WUNTRACED and WCONTINUED reported nothing;
- a parent heard nothing of its children: no SIGCHLD.

ADR 0020 had also left out restarting interrupted calls, which makes
stopping usable. When a process stopped in a blocking read is continued,
Linux restarts the read, so `cat` does not see an error after ^Z and
`fg`. Calls whose handler has SA_RESTART are restarted too, and musl's
`signal()` sets that flag.

The rules are Linux v6.12's:
- `kernel/signal.c`: `prepare_signal`, `sig_ignored`, `get_signal`,
  `do_signal_stop`, `do_notify_parent_cldstop`, `do_notify_parent`;
- `kernel/exit.c`: `kill_orphaned_pgrp`, `wait_task_stopped`,
  `wait_task_continued`, `wait_consider_task`, `do_wait`;
- `arch/x86/kernel/signal.c`: `handle_signal`,
  `arch_do_signal_or_restart`;
- each interrupted call's restart code: `fs/pipe.c`, `fs/eventfd.c`,
  `fs/select.c`, `fs/locks.c`, `kernel/futex/waitwake.c`,
  `include/net/sock.h` (`sock_intr_errno`), `drivers/tty/n_tty.c`,
  `tty_jobctrl.c`, `tty_ioctl.c`.

## Decision

1. **Sending** (`prepare_signal`):
   - **A stop signal** (SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU) takes back a
     pending SIGCONT. At its default action it is no longer ignored, so it
     is queued.
   - **SIGCONT** takes back pending stop signals, then continues a stopped
     process, even one that ignores or blocks SIGCONT. After that:
     - its threads go on;
     - its stop is no longer reported to WUNTRACED, and its continuing is
       reported once to WCONTINUED;
     - the parent gets SIGCHLD (CLD_CONTINUED, status SIGCONT) unless it
       ignores SIGCHLD or set SA_NOCLDSTOP.

     The SIGCONT itself is then dropped at its default, or queued for a
     handler.
2. **Stopping** (`get_signal`, `do_signal_stop`): a stop signal taken at
   its default action stops the whole process. SIGTSTP, SIGTTIN and
   SIGTTOU are discarded instead in an orphaned group, as Linux does;
   SIGSTOP always stops. The stop:
   - marks the process stopped (reported once to WUNTRACED, status
     `sig << 8 | 0x7f`);
   - sends the parent SIGCHLD (CLD_STOPPED, the signal), unless it ignores
     SIGCHLD or set SA_NOCLDSTOP, and wakes its wait4;
   - interrupts the process's other threads.

   Each thread then parks on its way back to user mode, in the return
   hook, where signals are delivered. It stays there until SIGCONT
   continues the process or SIGKILL ends it. Signals sent meanwhile stay
   pending and are taken after.
3. **wait4** (`wait_consider_task`): the first matching child with
   something to report, in creation order:
   - its exit, which reaps it;
   - with WUNTRACED, a stop not yet reported;
   - with WCONTINUED, a continuing not yet reported (0xffff).

   A blocking wait4 that a signal interrupts is ERESTARTSYS (`do_wait`).
4. **SIGCHLD at exit** (`do_notify_parent`): the parent gets SIGCHLD
   (CLD_EXITED with the exit code, or CLD_KILLED with the signal; `si_pid`
   the child) unless it ignores SIGCHLD. A parent that ignores SIGCHLD,
   or set SA_NOCLDWAIT, keeps no zombie (autoreap). Its wait4 then waits
   until no child is left, and is ECHILD.
5. **Orphaned stopped jobs** (`kill_orphaned_pgrp`): when an exit leaves
   a group orphaned that has a stopped member, the group gets SIGHUP and
   SIGCONT from the kernel. Such a group is either the exiting process's
   own (if its parent was in another group of its session) or a live
   child's.
6. **Restarting** (`handle_signal`, `arch_do_signal_or_restart`).
   - **The codes:** calls that Linux restarts now return its
     kernel-internal codes, ERESTARTSYS (512) or ERESTARTNOHAND (514),
     where they used to return EINTR.
   - **Turning them into a result:** the return to user mode does it, once
     per return:
     - with no handler run, the call is restarted;
     - with a handler that has SA_RESTART, an ERESTARTSYS call is
       restarted;
     - otherwise the result is EINTR.
   - **How a restart is done:** RAX gets the call's number back and RIP
     steps back over the two-byte SYSCALL. The number is kept in the frame
     as Linux keeps `orig_ax`, in the entry stub's error-code slot, unused
     on that path. rt_sigreturn and execve clear it, so they are never
     restarted.
   - **The first handler decides,** before its frame saves the registers,
     so a handler's sigreturn comes back into the restarted call.

   Which code each call returns, as Linux:
   - **ERESTARTSYS:** pipe and eventfd reads and writes; wait4; F_SETLKW;
     futex waits without a timeout; socket waits without SO_RCVTIMEO or
     SO_SNDTIMEO; terminal reads and writes; TCSETSW and TCSETSF; and the
     background check (`__tty_check_change`). A background reader with
     SIGTTIN at its default therefore stops and, continued in the
     foreground, reads.
   - **ERESTARTNOHAND:** select, pselect6, ppoll, and poll without a
     timeout. The first three write back the time left, so a restart
     waits only for what remains, as on Linux.
   - **EINTR:** epoll_wait, TCSBRK, TCSBRKP and TIOCSETD's wait, as Linux
     returns. Also EINTR for now: the calls Linux restarts with a restart
     block (poll with a timeout, futex waits with one).

## Not yet covered

- **Restart blocks** (`restart_syscall`, ERESTART_RESTARTBLOCK): poll
  with a timeout and timed futex waits are EINTR even with no handler,
  where Linux continues them for the time left. There are no sleep calls
  yet.
- **Stopping a process during an uninterruptible kernel wait:** Keel's
  only such waits are short; a thread parks when it next returns to user
  mode.
- **`waitid`**, WNOWAIT and `rusage`; SIGCHLD's `si_utime` and
  `si_stime` are 0. A clone exit signal other than SIGCHLD.
- **`rt_sigpending`**, so a pending SIGCONT that a stop took back cannot
  be observed (that rule has no test).
- **ptrace stops.**

## Evidence

- **`exec.stop_continue` (phase 3) and `host.stopprobe`:**
  `user/tests/stopprobe` makes 46 checks, which pass under Linux (as root
  and as an unprivileged user with umask 077, nine runs in a row) and on
  Keel. Each part runs in a child that makes its own session, so the
  groups it makes are orphaned or not by design. Keel runs it twice and
  measures the second run: every node, frame and process is back. The
  checks:
  - **Stop and continue:** SIGSTOP's stop reported once to WUNTRACED, and
    the parent's SIGCHLD; another signal not continuing it; SIGCONT's
    continuing reported once to WCONTINUED, its SIGCHLD, and the stop no
    longer reported.
  - **The restart:** the blocked read restarted and returning the byte;
    a handler with SA_RESTART restarting the read, and without it EINTR.
  - **Each stop signal:** SIGTSTP, SIGTTIN and SIGTTOU stopping; SIGKILL
    ending a stopped process; no report without WUNTRACED.
  - **SIGCHLD's flags:** SA_NOCLDSTOP (no SIGCHLD for a stop or a
    continuing, but one at exit); SIGCHLD ignored and SA_NOCLDWAIT reaping
    (ECHILD), the latter with its handler run.
  - **The pending rules:** SIGCONT taking back a blocked pending SIGTSTP;
    a SIGCONT handler and a signal sent while stopped both taken after;
    SIGTSTP discarded in an orphaned group, SIGSTOP not.
  - **Not running while stopped:** a process writing every 10 ms writes
    nothing while stopped, and goes on when continued.
  - **Orphaned stopped jobs:** a job left orphaned and stopped getting
    SIGHUP and SIGCONT.
  - **The terminal:** a background reader with SIGTTIN at its default
    stopping, then, made the foreground and continued, reading the line.
- **The earlier probes still pass:** `exec.signals` and the musl
  programs, pipeprobe, epollprobe, sockprobe, scmprobe, ttyprobe and
  jobprobe. Their handlers have no SA_RESTART, so they still see EINTR.
- **Mutations** on Keel, 22, all caught (the probe check that failed in
  brackets):
  - **Stopping:** a stop signal at its default doing nothing (2); a stop
    not parking the process (36); SIGTSTP not discarded in an orphaned
    group (24), or SIGSTOP discarded there (25).
  - **Continuing:** SIGCONT leaving pending stops (21), not continuing
    (5), or not reported to WCONTINUED (5).
  - **SIGCHLD:** none for a stop (4); SA_NOCLDSTOP ignored (13); none at
    exit (14); no autoreap with SIGCHLD ignored (32), or with SA_NOCLDWAIT
    (33).
  - **wait4:** WUNTRACED ignored (2); a stop reported twice (3); a stop
    reported without WUNTRACED (12); WCONTINUED ignored (5).
  - **Restarting:** no restart without a handler (7); SA_RESTART ignored
    (30); a pipe read EINTR instead of ERESTARTSYS (7); the background
    check EINTR (44).
  - **Orphaned groups at exit:** no SIGHUP and SIGCONT for a stopped job
    (36); sent to a group with nothing stopped (jobprobe 62).

## Consequences

- ^Z stops a job and `fg` (SIGCONT, TIOCSPGRP) resumes it where it was. A
  shell's background jobs stop when they touch the terminal, as on Linux.
- A parent can follow its children with SIGCHLD, and ignore them without
  collecting zombies.
- Every blocking call names its restart code, so the restart rules apply
  to calls added later.
