# ADR 0037: /proc's process directories, stat and cmdline

Status: accepted (Phase 3, after P3-T13).

## Context

Keel's procfs (ADR 0024) holds what the Wine traces read, and it could
not open a procfs directory, so nothing could list `/proc`. BusyBox's
test suite (ADR 0034) found two `pidof` tests failing because of it.
`pidof`, `ps`, `top` and `killall` find processes the same way
(BusyBox's `procps_scan`, `libbb/procps.c`). They read `/proc` for the
numeric names, then each process's `stat` (parsed after the last `)`),
its `cmdline` and its `exe` link.

This goes beyond the Wine trace. The owner approved it, scoped to the
caller's compartment. Nothing here is on the spec's never-implemented
list: `/proc/<pid>/mem` is, and stays absent.

The rules are Linux v6.12's:
- `fs/proc/root.c`: `proc_root_readdir`, the fixed entries up to
  FIRST_PROCESS_ENTRY (256, `include/linux/proc_fs.h`);
- `fs/proc/generic.c`: `proc_readdir_de`, with `proc_match` ordering
  names by length, then by byte;
- `fs/proc/base.c`:
  - `proc_pid_readdir`: `self` and `thread-self`, then PID n at
    n + TGID_OFFSET (258), and the end at PID_MAX_LIMIT + 258 (4 Mi on
    64-bit, `include/linux/threads.h`);
  - `proc_pident_readdir` with `tgid_base_stuff`'s order;
  - `proc_task_readdir`;
  - `get_mm_cmdline`;
- `fs/proc/array.c`: `do_task_stat`;
- `fs/namei.c`: `do_open` (ENOTDIR before EISDIR);
- proc(5) and proc_pid_stat(5).

## Decision

1. **Listing:** a procfs directory opens read-only, for getdents64. It
   cannot be a working directory: fchdir is EACCES, as before.
   - **Refusals** (`do_open`): O_DIRECTORY on a file ENOTDIR, then a
     directory for writing or with O_CREAT EISDIR.
   - **`/proc`:** `.`, `..`, `net` and `cpuinfo` (Linux's order), then
     from position 256 `self` and `thread-self`, then the compartment's
     PIDs in order, each at PID + 258. Each entry's d_off is the next
     one's position; the last one's is PID_MAX_LIMIT + 258.
   - **`/proc/<pid>`:** `.`, `..`, `task`, `comm`, `cmdline`, `stat`
     and `exe`, in `tgid_base_stuff`'s order.
   - **`task`:** the threads, the first one first.
   - **`task/<tid>`:** `comm` and `exe`.
   - **`net`:** `dev`.
   - **Positions** are what lseek takes back to. Outside `/proc` they
     are indices. A buffer too small for the next record is EINVAL.
   - **A process directory** whose process has gone lists as ENOENT.
   - **Relative lookups:** openat, newfstatat, readlinkat and faccessat
     relative to a procfs directory look up its path and the relative
     one. `..` stops at the directory, as at any directory handle (ADR
     0012). Other calls relative to one are EACCES.
   - **fstat and fstatfs** of it report the procfs node.
2. **The compartment's processes** are its running ones and its zombies,
   as in a PID namespace. A zombie is listed and has a `stat` until its
   parent reaps it. Its `cmdline` is empty and its `exe` is ENOENT, as
   Linux's are without an address space.
3. **`/proc/<pid>/cmdline`:** the argv exec gave the program, each
   string with its NUL. fork copies it.
   - **A deviation:** Linux reads the process's memory, so a program
     that rewrites its argv shows the change. Keel keeps what exec gave.
4. **`/proc/<pid>/stat`:** one line of `do_task_stat`'s 52 fields, the
   name between `(` and `)` as stored.
   - **State:** Z for a zombie, T if stopped, R for the reader itself,
     S for the others. Keel's scheduler does not say whether another
     thread is waiting for the CPU, so such a thread reads S where
     Linux gives R.
   - **The relations:** the parent's PID, 0 if there is none (as
     getppid); the group and session; the controlling terminal's device
     number (`new_encode_dev`) and foreground group, or 0 and -1 without
     a terminal; the number of threads.
   - **Fixed values:** priority 20 and nice 0 (Keel has no priorities);
     RLIMIT_RSS RLIM_INFINITY; the exit signal SIGCHLD for a forked
     process, 0 for one the kernel started (as Linux's `kernel_init`).
   - **Memory:** the start time in clock ticks since boot; the address
     space's size and resident pages; the initial stack pointer and
     the break's start.
   - **Signals:** the first thread's pending and blocked sets, and the
     dispositions ignored and caught (signals 1 to 31, as Linux).
   - **wchan:** 1 for a single-threaded process not running.
   - **Exit:** a zombie's wait status as the exit code.
   - **Zero:** the fields Keel does not keep: flags, fault counts, CPU
     times, the code, data, argument and environment bounds, the CPU,
     and the real-time priority and policy.

## Not yet covered

- `/proc/<pid>/status`, `statm`, `fd/`, `maps` and the rest, and `stat`
  and `cmdline` in a task directory.
- A procfs working directory.
- A process directory descriptor follows its PID, not its process: if
  the process is reaped and its PID reused, the descriptor shows the
  new process. Linux holds the process (`struct pid`) instead.

## Evidence

- **`exec.procdirs` (phase 3) and `host.pidprobe`.**
  `user/tests/pidprobe` makes 11 checks. They pass under Linux (as root,
  as an unprivileged user with umask 077, and from a relative path) and
  on Keel. Keel runs it twice and measures the second run: every node,
  frame and process is back. The checks:
  - **`/proc`:**
    - its mode;
    - the order and d_off of every entry;
    - this process and a child among the PIDs;
    - lseek back to 0, to 257 and to a PID's position;
    - EINVAL for a short buffer, and one record for a buffer of its
      size.
  - **A child's directory:**
    - its five entries in order, with their types;
    - openat of `stat` relative to it;
    - its task directory.
  - **Opens:**
    - ENOTDIR, EISDIR (twice) and ENOENT;
    - the modes of `stat`, `cmdline` and `task`.
  - **This process's stat:**
    - 52 fields, R, priority 20, nice 0 and one thread;
    - the parent, group and session as the calls give them;
    - a nonzero vsize and RLIM_INFINITY;
    - in a new session no terminal (0 and -1), a name with `) (` in
      it, and SIGCHLD as the exit signal.
  - **A child's files:**
    - its cmdline (an empty argument included);
    - S, then T when stopped, then S when continued;
    - a forked child's cmdline its parent's;
    - Z and an empty cmdline as a zombie, then gone once reaped, from
      both a lookup and the listing.
- **`keel_core::procfs` unit tests:** every listing with its positions,
  and a stat line field by field.
- **`busybox.testsuite`:** `pidof (exit with success)` and `pidof this`
  now pass and are in `keel-expected.txt` (896 tests).
- **Mutations** on Keel, 19, all caught (the pidprobe check that
  failed in brackets):
  - **Listing:**
    - PIDs at their index, not PID + 258 (1);
    - the end one past the last entry (1);
    - `cmdline` and `stat` swapped (4);
    - lseek's position ignored (the listing never ends:
      `exec.procdirs` times out);
    - a short buffer reading as the end (3);
    - no threads in `task` (5);
    - relative opens ignored (4).
  - **Opens:** O_DIRECTORY ignored (6); a directory opened for writing
    (6).
  - **Zombies:** hidden (11); their cmdline kept (11); shown as S (11).
  - **stat:**
    - a stopped process S (10);
    - the parent 0 (9);
    - the exit signal 0 (8);
    - tpgid 0 without a terminal (8);
    - priority and nice swapped (7).
  - **cmdline:** not set by exec (9); not copied by fork (10).

## Consequences

- `ps`, `pidof`, `top` and `killall` work within a compartment, and see
  nothing outside it.
- A procfs directory descriptor is an `OpenFile` whose `proc` names the
  directory. Its `node` is a detached placeholder, so code that handles
  directories must check `proc` first: getdents64, fstat, fstatfs,
  fchdir and the relative lookups do.
