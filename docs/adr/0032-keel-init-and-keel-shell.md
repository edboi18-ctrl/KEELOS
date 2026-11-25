# ADR 0032: keel-init and keel-shell

Status: accepted (Phase 3, P3-T13 parts 1 and 2).

## Context

P3-T13 asks for "`keel-init` and `keel-shell` as real programs", with
BusyBox as an optional second shell (part 2). Until now a normal boot
ended with "Keel: nothing more to run yet; halting.": the kernel had
terminals (ADR 0029), groups, sessions and a controlling terminal
(ADR 0030), and stopping and continuing (ADR 0031), but no program used
them.

Both programs are Keel's own, so they follow the user-program rules
(ADR 0006): safe Rust on `user/keel-rt`, no allocator, and the Linux
system-call ABI only, so they run unchanged under Linux. That lets the
shell be tested against Linux, as the other probes are.

The shell's job control is the sequence the glibc manual lays out in
"Implementing a Job Control Shell" (sections 29.5.2 to 29.5.4, read
from sourceware.org's copy of the manual for glibc 2.44). Its language
is a subset of POSIX.1-2024 XCU chapter 2 (pubs.opengroup.org). Its
messages are musl's: `strsignal` (`src/string/strsignal.c`) and
`strerror` (`src/errno/__strerror.h`), v1.2.5.

## Decision

1. **A normal boot** starts `/sbin/keel-init` as its first process,
   with the console on fds 0 to 2. The boot thread waits for it; if it
   ever ends, the kernel says so and halts.
2. **keel-init** (`user/keel-init`):
   - forks a child that calls setsid, takes the console with TIOCSCTTY
     and executes `/bin/keel-shell` with `PATH=/bin:/sbin:/usr/bin`,
     `HOME=/` and `SHELL=/bin/keel-shell`;
   - reaps every child (wait4 with -1), and when the shell ends starts
     another, after a second if the last lasted less, so a shell that
     cannot start does not make it spin;
   - prints `keel-init: starting /bin/keel-shell` each time, the line
     `cargo xtask boot-check` now waits for;
   - with `--once`, runs one shell and exits with its status, for the
     self-tests;
   - with `--shell PATH [ARG ...]`, last on its command line, runs PATH
     with those arguments (argv[0] is PATH) instead of keel-shell: the
     "optional second shell" P3-T13 asks for, as `--shell /bin/busybox
     sh` (part 2).
3. **keel-shell** (`user/keel-shell`):
   - **Input:** standard input, a script file or `-c STRING`. It is
     interactive when it reads standard input and fds 0 and 2 are both
     terminals (bash's rule), and only then does it prompt (`PS1`,
     default `keel$ `) and do job control.
   - **Words:** quoting with `'`, `"` and `\`; `$NAME`, `${NAME}`, `$?`,
     `$$`, `$!` and `$0`. An unquoted expansion that comes to nothing is
     no word. There is no field splitting, pathname expansion, command
     substitution or arithmetic.
   - **Lists:** pipelines joined by `&&`, `||`, `;` and `&`, and `#`
     comments. `a && b &` puts only `b` in the background.
   - **Redirections:** `<`, `>`, `>>`, `<&` and `>&` (with a number or
     `-`), with an optional fd number in front.
   - **Variables:** `NAME=value` alone sets one; in front of a command
     it goes into that command's environment only.
   - **Builtins that change the shell** run in it, with their
     redirections done and then undone: `cd`, `exit`, `export`, `unset`,
     `jobs`, `fg`, `bg`, `wait` and `kill`. In a pipeline they run in a
     child, as in other shells.
   - **Utilities** always run in a child, as a program would: `echo`,
     `cat`, `ls`, `pwd`, `sleep`, `true`, `false`, `:`, `env` and
     `help`. Their messages name the utility, not the shell.
   - **Any other command** is found in `PATH` as musl's `execvp` does
     (a missing entry or one that is not a directory goes on to the
     next; EACCES is remembered). Not found is 127, found but not run is
     126 (XCU 2.8.2), and a process ended by a signal is 128 plus the
     signal.
   - **Job control**, as the glibc manual:
     - **At start:** the shell waits to be in the foreground, sending
       its group SIGTTIN until it is. Then it takes its own group
       (unless it already leads one, as a session leader does) and the
       terminal, and saves the terminal's modes.
     - **Signals:** it ignores SIGQUIT, SIGTSTP, SIGTTIN and SIGTTOU,
       and catches SIGINT, so ^C at the prompt gives a new prompt with
       `$?` 130.
     - **SIGCHLD is left at its default.** The manual's sample ignores
       it, but on Linux that makes the kernel reap children before
       wait4 sees them (ADR 0031).
     - **Launching a job:** each job gets a process group, set by both
       the shell and the child. A foreground job also gets the
       terminal, again from both sides, so no ordering of the two can
       leave a job's process outside its group or its keys going to
       the shell. The child resets the five signals to SIG_DFL only
       after that: done before, its own TIOCSPGRP from the background
       would stop it with SIGTTOU.
     - **Waiting for a foreground job:** the shell waits with
       WUNTRACED until the job ends or stops. Then it takes the
       terminal back and restores its own modes, after saving the job's
       if it stopped.
     - **Stopped jobs:** a stop is reported as `[n]+ Stopped\tcommand`,
       with musl's `strsignal` text: "Stopped (tty input)" for SIGTTIN.
     - **Before each prompt**, the ends of background jobs are reported
       (WNOHANG, also WCONTINUED).
     - **Builtins:** `fg` and `bg` take `%n`, `%%` or `%+`, or nothing
       (the job stopped or put in the background last). `fg` gives the
       job the terminal and its saved modes, then sends SIGCONT. `kill`
       of `%n` sends to the job's group.
     - **Leaving:** `exit` or end of file with stopped jobs warns once
       ("There are stopped jobs."), as bash does, and the next one
       exits.
   - **Without job control** (not interactive), every process stays in
     the shell's group. An asynchronous list ignores SIGINT and SIGQUIT
     and reads `/dev/null` unless it redirects its input (XCU 2.9.3.1,
     2.12). Ended jobs are kept for `wait` until the table needs room.
4. **A group of zombies still exists.** Linux detaches a task from its
   group only when it is reaped (`release_task`, `__exit_signal`,
   `__unhash_process` in `kernel/exit.c`). setpgid
   (`kernel/sys.c:1133`), TIOCSPGRP (`tiocspgrp`'s `pid_task`) and kill
   of a group (`__kill_pgrp_info`) all find a zombie member. Keel kept a
   zombie only in its parent's wait records, so a pipeline's second
   process could not join the group of a first that had already exited.
   `process::zombies` now finds a compartment's unreaped children, and
   those three calls count them. setpgid also takes an unreaped child as
   its target, as `find_task_by_vpid` still finds one, and moves it to
   the group: before, that was ESRCH, so a child that exited before its
   parent's setpgid stayed in the parent's group (an occasional jobprobe
   failure, check 18). getpgid and getsid of a zombie are still ESRCH
   (ADR 0030, "Not yet covered").
5. **Leak checks count the kernel's page tables.** The self-tests that
   compare frames before and after a run counted free frames and the
   heap's pages. The heap can need a new page-table frame when it maps
   a page in a range no table covers yet, and kernel tables are never
   freed. With the shell's programs in the initramfs, that happened
   during pipeprobe's measured run (one frame "lost", `exec.pipes`), so
   `frames_outside_heap` now adds `paging::kernel_table_frames()`. A
   leaked frame of any other kind still shows.

## Not yet covered

- In keel-shell: field splitting, globbing, command substitution,
  arithmetic, here-documents, functions, `if`, `while`, `case`,
  subshells, `trap`, `set`, `#!` scripts by `ENOEXEC`, and line
  editing. BusyBox `sh` (P3-T13 part 2) is the full shell.
- keel-init has no configuration, no runlevels and no shutdown: Keel has
  no `reboot(2)` yet.
- The console's ^C and ^Z come only from COM1 and the PS/2 keyboard
  (ADR 0029); there is no virtual-terminal switching.

## Evidence

- **`exec.shell` (phase 3) and `host.shellprobe`.** `user/tests/shellprobe`
  passes under Linux (as root, and as an unprivileged user with umask
  077) and on Keel. Keel runs it twice and measures the second run:
  every node, frame and process is back. It has two parts.
  - **A script on a pipe.** Its whole output and its exit status (7)
    are compared. It covers:
    - quoting and parameters, `;`, `&&` and `||`, a three-stage
      pipeline;
    - `<`, `>`, `>>`, `2>`, `2>&1` and `1>&2`;
    - `ls` sorted;
    - `$?` of a missing file (1), a missing command (127) and a killed
      background job (143);
    - PATH search and `-c`;
    - `&`, `$!` and `wait`;
    - `export` reaching a child and an unexported variable not reaching
      it, `unset`, `cd` and `pwd`.
  - **An interactive session on a pty.** The shell is a session leader
    with the slave as its controlling terminal, as keel-init starts it.
    Each key is typed only after the terminal's foreground group
    (TIOCGPGRP on the master) has changed hands. The steps:
    - `cat`, ^Z ("[1]+ Stopped"), `jobs`, `fg`, a line read, ^D,
      `$?` 0;
    - `cat`, ^C, `$?` 130;
    - `cat &`, stopped by SIGTTIN ("Stopped (tty input)"), `fg %1`,
      a line read;
    - `sleep 1`, ^Z, `bg`, `wait`;
    - ^C at the prompt, `$?` 130;
    - `exit 5`.
- **`console.shell` (phase 3).** The kernel starts
  `/sbin/keel-init --once`, as a normal boot starts keel-init, and types
  on COM1 through the UART's loopback. It waits on the console's
  foreground group between keys. The sequence is `cat`, ^Z,
  `jobs >/tmp/kj`, `fg`, a line, ^D, `echo $? >/tmp/ks` and `exit 3`.
  `/tmp/kj` must hold `[1]+ Stopped\tcat`, `/tmp/ks` must hold `0`, and
  keel-init must exit 3.
- **`exec.job_control` and `host.jobprobe`**, now 67 checks (part 29).
  A group whose only member has exited and is not yet reaped can still
  be signalled with kill(-G, 0), made the foreground with TIOCSPGRP, and
  joined with setpgid. An exited, unreaped child can be moved to a group
  and reaped by wait4 of that group. Once its members are reaped, the
  number names nothing (ESRCH). This passes under Linux.
- **Boot:** `cargo xtask boot-check` passes when the image reaches
  `keel-init: starting /bin/keel-shell`.
- **Mutations of keel-shell**, 22, run with shellprobe under Linux (the
  failed check in brackets). All are caught except one equivalent:
  - **Job control:**
    - a child keeping the shell's ignored signals (12);
    - no terminal for the job from either side (11);
    - no WUNTRACED (12);
    - the terminal not taken back (12);
    - `fg` without SIGCONT (15);
    - SIGTTOU not ignored by the shell (12);
    - SIGINT not caught at the prompt (51), or its `$?` not 130 (52);
    - "Stopped" for every stop signal (31);
    - no `+` on the current job (12).
  - **Language and statuses:**
    - a signal's status without 128 (4);
    - `&&` run as `;` (4), `||` never running (4);
    - an empty expansion kept as a word (4);
    - `>>` truncating (4), `<` not reading (4), `>&` doing nothing (4,
      a check added: `cat` of a missing file through `2>&1 |`);
    - no PATH search (4);
    - `$?` giving the PID (4);
    - `export` not exporting (4);
    - `kill` sending signal 0 (4).
  - **Equivalent:** the child not taking the terminal. The shell does it
    as well, and both are there only so that neither order of the two
    can race.
- **Mutations of the kernel and keel-init**, 7, on Keel (phase 3), all
  caught:
  - **Zombie groups:** zombies not counted by kill (jobprobe 63), by
    TIOCSPGRP (64) or by setpgid (65); an unreaped child not found as
    setpgid's target (67).
  - **keel-init:** no TIOCSCTTY (`console.shell`), no setsid (`console.shell` step 1), and
    the shell's status not passed on (`console.shell`: keel-init
    exits 0).

## Part 2: BusyBox

- **The binary:** `fixtures/busybox` builds BusyBox 1.37.0 from its
  pinned source, with Alpine 3.24's configuration made static, in the
  pinned Alpine image. The owner built it twice with Docker Desktop and
  got the same bytes (`fixtures/busybox/README.md`).
  - It is static PIE, with no interpreter: the configuration has PIE
    off, but with this toolchain BusyBox's `-static` link (without
    `-no-pie`) gave a static PIE. Keel loads those at a random bias, as
    it does `heap64`.
  - It sits at `/bin/busybox` in test builds, the path it was configured
    with (`CONFIG_BUSYBOX_EXEC_PATH`), which `busybox --install` links
    its applets to.
  - It is not run on the host and not in release images.
- **The kernel calls it needed:** nanosleep, clock_nanosleep,
  restart_syscall and rt_sigsuspend (ADR 0033). Everything else BusyBox
  `sh` and the applets below use was already there.
- **Not yet done:** BusyBox's own test suite (`testsuite.tar`, committed
  with the binary) as a conformance suite for Keel.

Evidence: **`console.busybox` (phase 3), Phase 3 acceptance item 3.**
The kernel starts `/sbin/keel-init --once --shell /bin/busybox sh`, as a
normal boot starts keel-init, and types on COM1 through the UART's
loopback. Each command writes its result to a file in /tmp, and the test
waits for that file before typing the next line. Keys for a foreground
job wait for the console's foreground group to change hands. The test
checks:
- `/bin/busybox mkdir /tmp/bb`, `--install -s /tmp/bb`, then PATH set to
  the links;
- `readlink /proc/$$/exe` gives `/bin/busybox`: the shell on the console
  is BusyBox's;
- `ls /etc` gives `keel-release`;
- the pipeline `echo hi | cat | tr a-z A-Z` gives `HI`;
- `sleep 1 &`: `jobs` shows it running, and `wait` gives 0;
- `cat` in the foreground, ^Z: `jobs` shows it stopped; `fg`, a line and
  ^D end it with `$?` 0;
- `exit 3`: keel-init exits 3.

Mutations: keel-init ignoring `--shell`, caught by `console.busybox`
only once the `readlink` check was added (keel-shell, run in BusyBox's
place, passes every other step); the kernel's, in ADR 0033.

## Consequences

- A normal boot ends at a shell on the console. With a serial cable or
  a PS/2 keyboard, a user can run commands and stop, resume and
  background jobs.
- The shell is the job-control client the next steps use, and later
  Wine's processes are started from it. BusyBox `sh` runs on the console
  the same way (acceptance item 3).
