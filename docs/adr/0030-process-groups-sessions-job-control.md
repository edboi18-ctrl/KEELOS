# ADR 0030: Process groups, sessions and the controlling terminal

Status: accepted (Phase 3, P3-T12 part 2).

## Context

P3-T3 asked for "process groups and sessions (minimal)" and P3-T12 for
"Ctrl-C to SIGINT". ADR 0029 built the line discipline, whose ISIG
characters raise signals, but there was nothing to send them to: no
groups, no sessions, no controlling terminal. kill(2) and wait4(2)
refused group arguments.

A shell needs all of these. It puts each job in a group, makes one
group the terminal's foreground, and expects ^C to reach that group and
not itself. It relies on background jobs being stopped (SIGTTIN,
SIGTTOU) when they touch the terminal, and on SIGHUP when the terminal
goes away.

The rules are Linux v6.12's:
- `kernel/sys.c`: setpgid, getpgid, getpgrp, setsid, getsid;
- `kernel/exit.c`: `will_become_orphaned_pgrp`, `eligible_pid`, and
  `disassociate_ctty` at exit;
- `kernel/signal.c`: `kill_something_info`, `__kill_pgrp_info`,
  `SEND_SIG_PRIV`;
- `drivers/tty/tty_jobctrl.c`: `__tty_check_change`, `tiocsctty`,
  `tiocgpgrp`, `tiocspgrp`, `tiocgsid`, `no_tty`,
  `tty_signal_session_leader`, `disassociate_ctty`;
- `drivers/tty/tty_io.c`: `tty_open`'s `noctty` and
  `tty_open_current_tty`, `__tty_hangup`;
- `drivers/tty/n_tty.c`: `job_control`, and the TOSTOP check in
  `n_tty_write`.

## Decision

1. **Groups and sessions** (`linux-abi::jobs`). Each process has a group
   and a session, PIDs of its compartment. Since a compartment never
   reuses a PID (ADR 0014), a number names one group or session for good.
   - **Inheritance:** fork inherits the group, the session and the
     controlling terminal, and a child is never a session leader.
   - **Processes the kernel starts** are in session 0 and group 0, not
     leaders, as Linux's init begins; so they can call setsid.
   - **setpgid**, in Linux's order:
     - `pid` 0 is the caller, `pgid` 0 is `pid`, a negative group is
       EINVAL;
     - the target must be the caller or a child of it (ESRCH), a process
       and not another thread (EINVAL);
     - a child in another session is EPERM, a child that has called
       execve is EACCES (PF_FORKNOEXEC), a session leader is EPERM;
     - joining another group needs a member of it in the caller's session
       (EPERM).
   - **setsid:** EPERM for a leader, or if a group numbered as the caller
     exists. Otherwise the caller leads a new session and group with no
     controlling terminal.
   - **getpgid and getsid** take a PID or a thread's TID, and give ESRCH
     for none; getpgrp is getpgid(0).
2. **Signals to a group** (`kill_something_info`): kill with PID 0 is the
   caller's group, -1 every process of the compartment but its PID 1 and
   the caller, and a lower value the group -PID. An empty group is ESRCH,
   and signal 0 only checks.
3. **wait4 by group** (`eligible_pid`): 0 is the caller's group and -G is
   group G, as the child's group is when wait4 looks. It works for zombies
   too, through the parent's records.
4. **The controlling terminal** is the console or a pty's slave (a master
   never is one). It is held weakly, so a pty whose ends are both closed
   is no one's, as `tty_release` clears the sessions at the final close.
   Each terminal records its session and foreground group by
   (compartment, number).
   - **TIOCSCTTY** (on a master: its slave):
     - nothing to do if the terminal is already the caller's session's;
     - EPERM unless the caller leads its session and has no terminal;
     - a terminal of another session is taken only with argument 1 (root,
       as every Keel process is) and only within the caller's
       compartment, else EPERM. A compartment cannot take the console
       from another.
   - **Opening a terminal** without O_NOCTTY, for reading, makes it the
     controlling terminal of a leader that has none, if the terminal has
     no session (`tty_open_proc_set_tty`). Opening /dev/console or a
     master never does, as on Linux, and neither does TIOCGPTPEER with
     O_NOCTTY.
   - **`/dev/tty`** (5:0) opens the caller's controlling terminal (ENXIO
     without one).
   - **TIOCGPGRP and TIOCGSID:** ENOTTY unless this is the caller's
     terminal or a master. A group or session of another compartment
     reads as 0 (`pid_vnr`). TIOCGSID with no session is ENOTTY.
   - **TIOCSPGRP**, in Linux's order:
     - the background check first (its EIO becomes ENOTTY);
     - EFAULT, then a negative group EINVAL;
     - not the caller's terminal or not its session: ENOTTY;
     - a number that names nothing: ESRCH;
     - a group of another session: EPERM.
   - **TIOCNOTTY:** the caller gives up its terminal (ENOTTY if this is
     not it). A leader's foreground group gets SIGHUP and SIGCONT, the
     terminal leaves the session, and every process of the session loses
     it.
5. **Signals from the terminal** go to its foreground group as the kernel
   (`kill_pgrp(..., 1)`: `si_code` SI_KERNEL):
   - ISIG's ^C (SIGINT), ^\ (SIGQUIT) and ^Z (SIGTSTP);
   - TIOCSIG on a master;
   - SIGWINCH when TIOCSWINSZ changes the size.

   The console's input arrives in interrupt context, so its signals are
   queued and sent by the echo thread.
6. **The background checks** (`__tty_check_change`) apply to a process
   whose controlling terminal is this one, when its group is not the
   foreground:
   - **When:** reading it (SIGTTIN); writing it with TOSTOP (SIGTTOU);
     and setting it with TCSETS and its forms, TCFLSH, TCXONC, TCSBRK,
     TCSBRKP, TIOCSETD or TIOCSPGRP (SIGTTOU).
   - **Signal blocked or ignored:** SIGTTIN is EIO, and SIGTTOU lets the
     call through.
   - **Orphaned group** (no member has a parent in another group of its
     session): EIO.
   - **Otherwise:** the signal goes to the caller's whole group and the
     call is EINTR.
7. **Hangup and exit:**
   - **A pty's master closing** hangs its slave up
     (`tty_signal_session_leader`, ADR 0029's hangup):
     - the session's processes lose the terminal;
     - its leader gets SIGHUP and SIGCONT, and keeps the foreground group
       (`tty_old_pgrp`);
     - the terminal has no session after.
   - **A session leader's exit** (`disassociate_ctty(1)`):
     - its terminal's foreground group gets SIGHUP;
     - the console's input is discarded, and the console's leader is
       signalled as for a hangup;
     - the terminal leaves the session, and its processes lose it;
     - a leader whose terminal was hung up earlier sends that old
       foreground group SIGHUP and SIGCONT.

     The console's open files are not hung up: they are all
     `/dev/console`, which `__tty_hangup` passes over
     (`redirected_tty_write`).

## Not yet covered

- **Stopping and continuing.** A stop signal's default action does
  nothing yet. A background reader whose SIGTTIN is at its default gets
  EINTR where Linux would stop it and restart the read. ^Z without a
  handler does nothing. WUNTRACED and WCONTINUED report nothing, and
  orphaned groups with stopped members get no SIGHUP and SIGCONT
  (`kill_orphaned_pgrp`). SIGCHLD to the parent, and its SIG_IGN
  auto-reaping, belong with these. They are the next task.
- **Zombies** are not in their group: Linux keeps a zombie findable
  (getpgid, kill, setpgid's group check) until it is reaped, Keel only
  through its parent's wait records.
- **kill with a thread's TID** is ESRCH; Linux signals its process.
- **TIOCVHANGUP**, `vhangup(2)`, TIOCCONS.

## Evidence

- **`exec.job_control` (phase 3) and `host.jobprobe`:**
  `user/tests/jobprobe` makes 62 checks, which pass under Linux (as root
  and as an unprivileged user with umask 077) and on Keel. Each part runs
  in a child that makes its own session. Keel runs it twice and measures
  the second run: every node, frame and process is back. The checks:
  - **IDs:** setsid and the IDs it gives; a leader's EPERMs; ESRCH and
    EINVAL; moving a child between groups.
  - **setpgid's refusals:** a group with no members, the parent, a child
    in its own session, a child after execve (EACCES; the probe runs
    itself as the child).
  - **kill and wait4:** kill with 0 and -G (signal 0); killing a whole
    group; wait4 by group and ECHILD; kill(-1, 0).
  - **The controlling terminal:** O_NOCTTY; TIOCGPGRP and TIOCGSID on
    both ends; TIOCSCTTY and repeating it; /dev/tty (5:0, ENXIO without
    one); a child's inherited terminal and its EPERM; a second terminal
    refused.
  - **TIOCSPGRP:** ENOTTY from an orphaned background group, then
    EINVAL, ESRCH and EPERM with SIGTTOU ignored.
  - **Signals from the terminal:** ^C, ^\ and TIOCSIG reaching each
    member of the foreground group and not the background caller; ^Z and
    SIGWINCH caught, an unchanged size sending none.
  - **Background access:** a read (SIGTTIN caught: EINTR; ignored: EIO);
    a write without and with TOSTOP (SIGTTOU caught; ignored allowed);
    TCSETS from the background; an orphaned group's EIO.
  - **Giving up and taking back:** TIOCNOTTY by a non-leader and by a
    leader (SIGHUP and SIGCONT to the foreground, the session cleared);
    taking the terminal back by opening it for reading but not write-only.
  - **Endings:** the master closing (the leader's SIGHUP and SIGCONT); a
    leader's exit (its foreground group's SIGHUP, and the terminal gone).
- **`console.interrupt` (phase 3):** `user/tests/ctrlc` takes the console
  with TIOCSCTTY and blocks reading it. ^C typed on COM1 through the
  UART's loopback ends the read with EINTR and runs its SIGINT handler.
  This is the spec's "Ctrl-C to SIGINT" on the serial console, end to
  end.
- **Mutations** on Keel, 33 (the jobprobe check that failed in
  brackets; "hung" is the probe never finishing):
  - **Groups and sessions:** setsid's group check skipped (10, a check
    added); setpgid allowing a child after execve (11), a child in another
    session (10, a check added), a process that is not a child (9), an
    absent group (8), a leader (3); kill of an empty group succeeding
    (12); groups never orphaned (33) or always (41); wait4(0) waiting for
    any child (18, a check added); fork not passing the terminal on (29).
  - **The background checks:** off (33); an ignored SIGTTIN allowed
    (hung); TOSTOP ignored (42); TCSETS unchecked (41).
  - **Signals from the terminal:** ISIG's dropped (hung); the console's
    dropped (`console.interrupt`); TIOCSIG's dropped (hung); SIGWINCH sent
    for an unchanged size (40).
  - **The controlling terminal:** TIOCSCTTY by a non-leader (a check
    added: the leader's SIGHUP when that terminal closed); taken on a
    write-only open (49) or never on open (50); TIOCSPGRP without its
    session check (34) or with the check's EIO (33); TIOCGPGRP unchecked
    (21); /dev/tty never found (26).
  - **Hangup and exit:** a hung-up leader unsignalled (51) or keeping
    the terminal (52); TIOCNOTTY leaving the session's terminal (47); a
    leader's exit without its foreground group's SIGHUP (62) or leaving
    the session's terminal (62).
  - **Equivalent:** setsid without its leader check (a leader's group is
    always its PID, so the group check refuses it).

## Consequences

- A shell can run jobs in groups, give the terminal to one, and have ^C
  reach it.
- With stop and continue still missing, an interactive shell's
  background job that reads the terminal is told EINTR (or EIO) instead
  of being stopped; the next task closes that gap.
