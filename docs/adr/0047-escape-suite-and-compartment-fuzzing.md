# ADR 0047: the escape suite and in-compartment fuzzing

Status: accepted (Phase 3, P3-S8). Builds on ADR 0014 (compartments),
ADR 0041 (profiles), ADR 0042 (limits) and the Phase 1 fuzzer.

## Context

- **Spec section 3, "Security testing":**
  - "Escape suite (`user/sectests`). Programs that run inside a
    deliberately minimal compartment and try to get out. Each must fail
    in the documented way." The minimum set:
    - `..` traversal; absolute and relative symbolic links pointing out;
      a symbolic link swapped during lookup; hard links to outside files;
      `/proc` tricks; device nodes that should not exist;
    - signalling, waiting on or inspecting PIDs outside the compartment;
      another compartment's filesystem and abstract Unix sockets;
      guessing handle numbers;
    - every never-implemented call; forbidden `clone` and `prctl` flags;
      writable-and-executable mappings;
    - exceeding each resource limit; reading freshly mapped memory for
      non-zero bytes.
  - "Syscall fuzzing. A fuzzer running inside a compartment issues
    random and structure-aware syscalls. Gate: zero kernel panics and zero
    escapes."
- **Security acceptance P3:** item 1, "the full escape suite passes";
  item 4, "eight hours in total of in-compartment syscall fuzzing, run as
  parallel CI shards with distinct seeds".
- **Until now:**
  - The fuzzer ran in the system compartment, so it could not fork (its
    children would have had no limit) and an escape could not be told
    from ordinary use.
  - Parts of the set were tested one by one (`compartment.files_confined`,
    `compartment.side_by_side`, `compartment.profiles`, the limit tests),
    each in its own compartment set up for it.

## Decision

### The suite: `user/sectests`

- **A crate of its own,** `keel-sectests`: four escape programs and a
  neighbour, sharing a small library of helpers. Like `user/tests` they
  are static, non-PIE, built with keel-rt, and have no `unsafe` (keel-rt
  gained safe `linkat`, `prctl_option` and `arch_prctl_option` wrappers
  that pass 0 for every pointer).
- **Keel only:** on Linux most attempts would succeed. They sit in the
  initramfs at `/sec/<name>` of test builds.
- **Each attempt fails in one documented way,** the exact errno, checked.
  A program exits with the number of the first check that failed, and
  writes `<program>: check N: got R` to its standard output, which the
  kernel prints on failure.

### The scene: `sec.escape` (phase 3)

The kernel sets it up and runs the programs one after another:

| What | Where |
| --- | --- |
| The escape compartment | `/comp/esc`, holding nothing but copies of the programs: no `/dev`, `/etc`, `/proc` entries of its own, or `/test` |
| Its limits | 8 processes, 8192 frames, 1 MiB and 64 nodes of tmpfs, 32 descriptors |
| Its profile | `full` |
| Standard input | `/sec-outside/secret` (`outside\n`), in the system's tree, open read-only |
| Standard output | a file the kernel reads afterwards |
| Standard error | the console |
| The neighbour | `/comp/escn`, running `escneighbour 4`: 4 sleeping children, a file `/mine`, a stream listener at `/sock` and at the abstract `\0esc-n`, a datagram socket at `\0esc-nd` |

- **Why the `full` profile:** it is the widest. Under `default`, many
  attempts would be refused by the allowlist first (ENOSYS), and the
  check that must stop them would go untested. `compartment.profiles`
  already shows the default profile refusing what it lacks.
- **Afterwards** (`sec.escape_outside`):
  - the secret's contents are unchanged;
  - the system's root, `/comp` and `/sec-outside` have the same names as
    before;
  - the neighbour's tree has only its own names;
  - the neighbour exits 0, having found no pending connection, no
    datagram, `/mine` unchanged and every child still alive;
  - the escape compartment is empty and its memory back to 0.
- **`cargo xtask test --phase 3 --scenario escape`** boots the suite
  alone, for the nightly workflow and for work on it. The main phase 3
  boot runs it too, so a full run does not boot it again.

### The programs and what each attempt gets

**`escfs`** (`sec.escape_fs`), the filesystem:

| Attempt | Result |
| --- | --- |
| The secret by `..` from the root, through `/d/..`, repeated and mixed with `.` and `//` | ENOENT |
| The system's `/comp`, `/sec`, `/test`, `/etc/keel-release`, `/sbin/keel-init`, its own path in the system's tree | ENOENT |
| `/..`, `/../../..` | the root |
| `..` through a directory handle | stops at the handle's directory (ADR 0012) |
| `chdir("..")` eight times | the root |
| The root's listing | only the compartment's own names |
| Absolute and relative links pointing out, to the secret and to its directory | ENOENT |
| A relative link to `../../../..` from `/d` | the root |
| A link to itself | ELOOP |
| O_CREAT through a dangling link pointing out, mkdir through one | ENOENT (its directory, the compartment's own `/sec-outside`, does not exist) |
| A link swapped by a second process (rename over it, alternately to `/d`, the root by `..`, the outside directory by `..`) while the first looks up through it, at least 4000 rounds until both targets are seen | every lookup lands in `/d` or the root; the secret is never found |
| `link` and `linkat(AT_SYMLINK_FOLLOW)` to the secret, `rename` of it, `rename` out | ENOENT |
| Its standard input, the secret | reads; write EBADF; ftruncate refused |
| `linkat(0, "", ..., AT_EMPTY_PATH)`, the secret; `linkat(2, ...)`, the console | ENOENT (F-0012) |
| 20 `/proc` entries Linux has and Keel does not, each of which shows or reaches something outside on Linux: `self/root`, `1/root`, `self/cwd`, `self/fd`, `self/mem`, `self/maps`, `self/environ`, `self/mountinfo`, `mounts`, `kcore`, `kallsyms`, `sysrq-trigger`, `sys/kernel/core_pattern`, `net/unix`, the neighbour's PID 2, `thread-self/root` and others | ENOENT |
| `/proc/..`, `/proc/self/../../..`, `/proc/../sec-outside/secret` | ENOENT (see "Not yet covered") |
| `/proc/self/exe` | `/escfs`, its own file |
| `/proc`'s listing | one PID, its own |
| Creating in `/proc` | refused |
| 16 device nodes nothing granted: null, zero, urandom, console, tty, ptmx, `pts/0`, mem, kmem, port, sda, vda, fb0, `input/event0`, kvm, `cpu/0/msr` | ENOENT |
| mknod of `/dev/mem` (1:1), `/dev/null` (1:3), the console (5:1), a disk (8:0) | EPERM (ADR 0035) |
| mknod of a FIFO | works: not a device |
| A link to the system's console by `..` | ENOENT |
| A decoy `/sec-outside/secret` of its own | every route above now reads the decoy, never the secret; the dangling link creates its file in the decoy directory; a child sees the same |

**`escproc`** (`sec.escape_processes`), processes, sockets and handles,
run as `escproc 16`:

| Attempt | Result |
| --- | --- |
| For every PID from 1 to 16 but its own: kill with 0, SIGTERM and SIGKILL; kill of the group; tgkill; getpgid; getsid; setpgid | ESRCH |
| wait4 on each | ECHILD |
| kill(-1, SIGTERM) | ESRCH: no other process here |
| wait4(-1) | ECHILD |
| setpgid into a group that does not exist here | EPERM |
| getppid | 0: its parent is outside |
| Its own child | signalled and reaped |
| The neighbour's `/mine` by six routes | ENOENT |
| Its `/sock` by five routes | ENOENT |
| Its abstract stream and datagram names | ECONNREFUSED |
| The same abstract names in its own compartment | free: bound, then they answer; and a `/sock` of its own answers |
| fcntl(F_GETFD) on every descriptor from 3 to 1099, and -1, -100, 2^20, i32::MAX, i32::MIN | EBADF |
| Every native call that takes a handle (`factory_derive`, `compartment_create`, `compartment_grant_device`, `compartment_spawn`, `compartment_kill`, `compartment_wait`, `audit_open`, `layer`), on every number from 0 to 1099, 2^31 and u32::MAX | EBADF: it holds no factory, compartment or audit handle (0, 1 and 2 are files) |
| Native call 9 | ENOSYS |

The neighbour's check afterwards shows that none of the kills, connects
or datagrams reached it.

**`esccalls`** (`sec.escape_calls`):

| Attempt | Result |
| --- | --- |
| All 43 never-implemented calls | ENOSYS |
| Each of the 7 namespace clone flags, and all together | EINVAL |
| CLONE_THREAD without CLONE_SIGHAND, CLONE_SIGHAND without CLONE_VM | EINVAL |
| 18 prctl options Keel does not have (PR_SET_PDEATHSIG, PR_SET_DUMPABLE, PR_SET_KEEPCAPS, PR_SET_SECCOMP, PR_CAPBSET_DROP, PR_SET_TSC, PR_SET_SECUREBITS, PR_SET_TIMERSLACK, PR_SET_MM, PR_SET_CHILD_SUBREAPER, PR_SET_NO_NEW_PRIVS, PR_SET_THP_DISABLE, PR_SET_FP_MODE, PR_CAP_AMBIENT, PR_SET_SPECULATION_CTRL, PR_SET_IO_FLUSHER, PR_SET_SYSCALL_USER_DISPATCH, PR_SET_PTRACER) | EINVAL |
| 12 arch_prctl codes other than FS and GS (CPUID, XCOMP, VDSO, tagged addresses, shadow stacks, 0) | EINVAL |
| `int 0x80` and `sysenter` in children | each child ends by SIGSEGV (or SIGILL for `sysenter` on AMD) |
| mmap RWX and WX, private anonymous | EACCES |
| The same, shared anonymous | EINVAL: shared anonymous memory is not implemented (ADR 0021) |
| mprotect to RWX or WX, whole or part, of a RW mapping; to RWX of an RX one | EACCES |
| A memfd mapped RWX, private and shared; a RW mapping of it, private and shared, mprotected to RWX | EACCES |
| 1 MiB fresh; 1 MiB in place of one it filled; 4 MiB after a child filled 4 MiB and exited | all zero |
| A memfd filled, cut to 0, grown to 8 KiB | reads zero |
| A memfd cut to 100 bytes, its first page mapped | bytes 100 to 4095 are zero |

The program numbers, flag values and options are from Linux v6.12
(`syscall_64.tbl`, `include/uapi/linux/sched.h`,
`include/uapi/linux/prctl.h`, `arch/x86/include/uapi/asm/prctl.h`).

**`esclimits`** (`sec.escape_limits`), run with the compartment's limits
as arguments:

| Limit | Past it |
| --- | --- |
| 8 processes | fork EAGAIN after 7 children, and clone EAGAIN; once reaped, fork works |
| 32 descriptors | dup EMFILE with 31 the highest; dup2 to 32 EBADF; F_DUPFD from 32 EINVAL; a freed number is reused and the table is full again |
| 1 MiB of tmpfs | write ENOSPC within a page of the quota; a memfd cannot grow (ENOSPC); deleting gives the bytes back |
| 64 tmpfs nodes | create ENOSPC, mkdir ENOSPC; removing gives them back |
| 8192 frames | a child touching twice as many pages is ended by a fault; the parent goes on and gets 1 MiB |

### Two fixes the suite found

- **F-0012** (`docs/SECURITY-FINDINGS.md`):
  `linkat(fd, "", ..., AT_EMPTY_PATH)` gave a descriptor's file a name in
  the caller's tree. A compartment could then open a file it had been
  given read-only again for writing, or give itself a console device
  node. Linux refuses this (ENOENT) to a caller that did not open the
  file itself and lacks CAP_DAC_READ_SEARCH (`fs/namei.c`, `path_init`
  with LOOKUP_LINKAT_EMPTY). Keel keeps no record of who opened a file,
  so it refuses all of them.
- **O_CREAT through a dangling symbolic link** created nothing (EEXIST,
  the link's own name). Linux follows the link and creates its target
  (`open_last_lookups`). Measured on Linux 6.18: through a chain of
  links; a relative target from the link's directory; ENOENT if the
  target's directory does not exist; EISDIR for a target ending in `/`.
  Keel now does the same (`Fs::create_parent`), and every target is
  looked up within the root. Safe before, but this is the path that most
  needs testing, so it is now tested as Linux behaves.

### A fix the fuzzer found: F-0013

The first nightly run of the fuzzer in a compartment found that a
process forked while its compartment was being killed could survive the
kill (`docs/SECURITY-FINDINGS.md`, F-0013). Now:
- **fork and clone:** under the process table's lock, they check whether
  the caller has been killed. If so, they kill the new child or thread
  before the lock is released.
- **`process::kill_every`:** it sends SIGKILL, then lists the
  compartment's processes again, until it finds none it has not
  signalled. The native `compartment_kill`, kill(-1, SIGKILL) and the
  kernel's tests use it.

`compartment.kill_during_fork` (phase 3, and the escape scenario) kills a
compartment of continually forking processes 40 times.

### The fuzzer in a compartment

- **Its compartment:** `/fuzz-root`, holding:
  - the fuzzer at `/fuzz`;
  - `/etc/keel-release`, which it looks for before it starts;
  - `/dev` with null, zero and urandom.

  `/fuzz-outside/secret` is outside it.
- **Its limits:** 16 processes, 65,536 frames (256 MiB), 8 MiB and 512
  nodes of tmpfs, 1,024 descriptors; profile `full`.
- **Used by both sessions:** `cargo xtask fuzz` and every phase 1 boot's
  smoke test (`fuzz.smoke`).
- **fork is now made.** The process limit bounds the children. A child
  reseeds from its parent's generator and its PID, so it does not repeat
  its parent's calls. clone and vfork stay out: a child sharing the
  fuzzer's memory would run on its stack. kill, futex, rt_sigreturn,
  tkill and tgkill stay out as before.
- **After each run:**
  1. When the first process ends, the rest of the compartment is killed.
  2. It must empty within the run limit (600 s) and give back all its
     frames.
  3. The secret, the system root's names and `/fuzz-outside`'s names
     must be as before.

  Anything else stops the session as an escape (`fuzz.syscalls` and
  `fuzz.smoke` fail).
- **A run that waits:** a forking fuzzer can wait for good without any
  kernel fault. A parent can wait4 for a child sleeping for days, or read
  a pipe that both of them hold open. So a run that makes no system call
  for 2 s is killed and counted as "killed while waiting". It must then
  end within the run limit, or it is a hang, the kernel's fault.

### CI

- **`security.yml`:**
  - eight 60-minute fuzzing shards a night, with distinct seeds (`run_id
    × 16 + shard`): eight hours in total, P3's gate;
  - an `escape-suite` job running the scenario.
- **`ci.yml`:** the main phase 3 boot runs the suite on every push.

## Evidence

- **`cargo xtask test --phase 3 --scenario escape`** (QEMU TCG): all five
  `sec.*` checks pass. The boot, with the host programs before it, takes
  under a minute.
- **The first boot of the suite** found what the programs had assumed
  wrongly, each corrected:
  - PIDs go on counting within a compartment, so `escproc`, run third,
    is not PID 1;
  - shared anonymous mappings are EINVAL;
  - `/proc/..` is ENOENT (see "Not yet covered").

  It also found the two fixes above: the dangling link gave EEXIST, and
  `linkat` would have let check 57 succeed.
- **Host test** (`keel_core::vfs`):
  `create_parent_follows_dangling_links_within_the_root`, covering:
  - a chain of links, and a relative target from the link's directory;
  - a link pointing out of a root names a place inside it, and the same
    link from the whole tree names the real `/etc`;
  - EISDIR and ELOOP.
- **Measured on Linux 6.18,** as root and as nobody: the open(2) rules
  above (`docs/SOURCES.md`).
- **Fuzzing** (QEMU TCG, 5 minutes, seed 77), in the compartment:
  - 54 runs and 115,239 calls, no fault in the kernel;
  - 23 runs killed while waiting, every one of which then ended;
  - after every run the compartment was empty and nothing outside had
    changed.

  Before the idle kill, the same seeds gave a run (seed 79) that waited
  600 s.
- **First nightly run** (security.yml on this branch, KVM, 2026-11-28):
  - the escape suite passed;
  - seven of the eight 60-minute shards passed;
  - shard 6 found F-0013 after 1,390 runs and 2.7 million calls, with
    617 runs killed while waiting.
- **Mutations,** each run through the escape scenario (the fuzzer's
  through `cargo xtask fuzz`), each caught:

  | Mutation | Caught by |
  | --- | --- |
  | `linkat` with AT_EMPTY_PATH allowed again | `sec.escape_fs`: check 57, the read-only secret linked (0) |
  | O_CREAT not following a dangling link | `sec.escape_fs`: check 33 (EEXIST) |
  | a dangling link's target looked up from the whole tree, not the root | `sec.escape_fs`: check 33 (0), and `sec.escape_outside`: `/sec-outside/made` appeared in the system's tree |
  | a PID looked up in every compartment | `sec.escape_processes`: check 2, kill(1, 0) found a process; `sec.escape_fs` killed at its 30 s limit, its kill of its own child having reached another's; `sec.escape_outside`: the neighbour was killed (137) |
  | mprotect allowing writable and executable | `sec.escape_calls`: check 46 |
  | the compartment's descriptor limit not applied | `sec.escape_limits`: check 10 |
  | the fuzzer spawned in the system compartment, as before | `fuzz.syscalls`: the first run waited, and the kill, which reaches only the fuzzer's compartment, could not end it |

  | fork not checking whether its caller was killed (`fork_with`) | `compartment.kill_during_fork`: round 0, 16 processes left |
  | that, and a single pass in `kill_every` (the code before F-0013) | `compartment.kill_during_fork`: round 0 |
  | the child killed after the table is unlocked (the first version of the fix) | `compartment.kill_during_fork`, in about half its boots: a grandchild forked before the child was marked |
  | a single pass in `kill_every`, fork's check kept | not caught (4 boots, 160 kills). The window, a fork completing between the list and its parent's signal, is too narrow for the test; the second pass rests on the reasoning above, as Linux's lock does |

  With the PID mutation the suite first ran into the boot's timeout. Each
  program is now limited to 30 s, and killed past it, so it fails with
  its output.

## Not yet covered

- **`/proc/..`:** Keel's `/proc` is not a directory of the compartment's
  tree but names the kernel answers, resolved lexically. A path that
  climbs back out of it (`/proc/../x`) is not looked up again in the
  tree, so it is ENOENT where Linux gives `/x`. It fails closed; it is a
  conformance gap to fix in the procfs lookup.
- **W^X is per mapping.** Both are allowed, on Linux as well:
  - one file mapped writable in one mapping and executable in another;
  - a file written while it is mapped executable.

  SR-12 is about mappings. A manifest can withhold MAP_EXEC from a file
  handle (ADR 0012).
- **The default profile:** the suite runs under `full`. Running it under
  `default` as well would show mostly the allowlist's ENOSYS.
- **Threads against the process limit** and the CPU share are not pushed
  here; `compartment.under_load` covers the share.
- **Wine:** the hostile Windows programs that run the suite from PE code
  are P4-S4.
- **Security acceptance P3 item 5,** an independent review of the
  compartment code, needs a reviewer.
