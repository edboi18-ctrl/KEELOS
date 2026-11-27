# ADR 0041: allowlist profiles

Status: accepted (Phase 3, P3-S3).

## Context

- **SR-7:** each compartment has a system-call allowlist and, per device
  type, an ioctl allowlist. The default profile is the set Wine was
  observed to need. Anything else returns an error and is logged.
- **SR-10:** fail closed. An unknown call, ioctl, flag bit or socket
  option is an error, never "allow and log".
- **Spec section 7:**
  - `prctl`, `fcntl`, `ioctl`, `madvise` and `clone` are multiplexers,
    so their individual operations and flags are allowlisted, not just
    the call.
  - A fixed list of calls is never implemented in Phases 0 to 6.
- **Spec principle 2:** no system call is added to an allowlist without
  a traced need.

Until now every process could make every call Keel implements. SR-10
already held per call: each refuses flags and operations it does not
implement.

## Decision

### Profiles

A profile (`keel_core::profile`, host-tested, no `unsafe`) holds:
- a set of system-call numbers below 512;
- for each multiplexer, the operation values allowed (or any value the
  call accepts);
- the ioctl requests allowed, per class of object:
  - a terminal (the console, a pty side, `/dev/tty`);
  - a regular file;
  - a directory;
  - a pipe or FIFO end;
  - a socket;
  - anything else.

Two profiles exist:

| Profile | Number | Holds | Used by |
| --- | --- | --- | --- |
| `default` | 0 | The calls of the Wine trace (`docs/syscall-inventory.md`); of the multiplexers, only the operations the trace shows | A manifest that names no profile |
| `full` | 1 | Every call except the never-implemented ones; any operation the call implements | The system compartment, compartments the kernel makes for its tests, and a manifest that asks for it |

**`default`** is the trace's 87 calls with two changes:
- **Removed:** `userfaultfd`, which is never implemented. Wine probes it,
  gets an error on Linux too, and goes on without it.
- **Added:** `clock_gettime`. The trace cannot show it, because musl
  reads the clock through the vDSO on Linux. Keel has no vDSO, so musl
  makes the call (the inventory's own note).

Every profile also has `exit`, `exit_group`, `rt_sigreturn` and
`restart_syscall`. These are mechanism, not surface. The last is what
the kernel itself has a program call to resume a sleep (ADR 0033).

Its operations:
- **`clone`:** the whole flags argument must be one of the two traced
  combinations:
  - musl's `pthread_create`: `CLONE_VM | CLONE_FS | CLONE_FILES |
    CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
    CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_DETACHED`;
  - musl's `posix_spawn`: `CLONE_VM | CLONE_VFORK | SIGCHLD`.
- **`fcntl`:** `F_SETFD`, `F_GETFL`, `F_SETFL`, `F_SETLK`.
- **`prctl`:** `PR_SET_NAME` and `PR_SET_PTRACER`. The second is
  allowed only because it was traced: Keel answers it EINVAL, since it
  has no ptrace to permit.
- **`madvise`:** no advice (it was not traced, so the call is not in
  the set either).
- **ioctl requests:**
  - `TIOCGWINSZ` on a terminal;
  - `FS_IOC_GETFLAGS` and `VFAT_IOCTL_READDIR_BOTH` on files and
    directories (Keel's tmpfs answers both ENOTTY).
  - The traced `SIOCGIF*` requests were made on `AF_INET` sockets,
    which Keel does not have.

The values are checked against the Linux v6.12 uapi headers and against
the host's headers by compiling them:
- `include/uapi/linux/sched.h` for the clone flags;
- `include/uapi/linux/msdos_fs.h` for `VFAT_IOCTL_READDIR_BOTH`,
  0x82307201: `_IOR('r', 1, struct __fat_dirent[2])`, two 280-byte
  entries;
- `include/uapi/linux/fs.h` for `FS_IOC_GETFLAGS`, 0x80086601;
- `include/uapi/asm-generic/ioctls.h`;
- `include/uapi/linux/prctl.h`.

P4-S3 later reduces `default` to the operations Wine is observed to use
across more programs, each with its threat note.

### Where a profile lives

- **In the limits.** A compartment's profile is part of its `Limits`, so
  it is fixed when the compartment is made, and nothing inside can
  change it.
- **In the native interface.** In ADR 0040's 40-byte limits structure,
  bytes 4 to 7 (reserved until now) hold the profile's number, 0 being
  the default. An unknown number is EINVAL.
- **Ceilings.** A factory's ceiling has a profile too. A compartment, or
  a derived factory, may have only a profile within its factory's: no
  call and no operation that the ceiling lacks (EPERM, like any limit
  above the ceiling).
- **Who gets what:**
  - The root factory's ceiling is `full`.
  - keel-init gives keel-launch a `full` ceiling, so a manifest can name
    either profile.
  - A manifest's `profile` key is `"default"` (also when it is left
    out) or `"full"`; anything else fails to parse.

### Where calls are checked

- **Every Linux call.** Before dispatch, a call whose number is below
  512, made by a process, is checked against its compartment's profile.
  The native calls are not: a compartment is never given the handles
  they need (ADR 0040), and any other number is ENOSYS already.
- **The never-implemented calls** fail the check before the profile is
  consulted, and no profile may contain one (host test).
- **Multiplexers:**
  - `clone`'s flags (all 64 bits), and `fcntl`'s command, `prctl`'s
    option and `madvise`'s advice (each the low 32 bits, an `int` as
    Linux reads them), are checked with the call.
  - A `clone` with any namespace flag (`CLONE_NEW*`) is refused under
    every profile.
- **ioctl:** the request is checked in `ioctl` once the descriptor's
  object, and so its class, is known.

### The errors

Each is what Linux itself answers for something it does not have:
- **A call:** ENOSYS, as `sys_ni_syscall`.
- **An operation of `fcntl`, `prctl` or `madvise`:** EINVAL, which
  fcntl(2) ("op is not recognized by this kernel"), prctl(2) ("op is not
  recognized, or not supported") and madvise(2) ("advice is not valid")
  give.
- **A `clone` flag combination:** EINVAL, which clone(2) gives for the
  combinations it refuses (CLONE_SIGHAND without CLONE_VM, for one).
  Linux's own `clone` does not refuse unknown bits; Keel's profile does.
- **An ioctl request:** ENOTTY, "the specified operation does not apply
  to the kind of object" (ioctl(2)).

So a program sees an older or smaller kernel, not a new kind of failure.

### Logging

- Every refusal is counted in its compartment (`Compartment::denied`).
- The first 8 of each compartment are logged on the kernel log: the
  compartment, the profile, the PID, the call, the operation and the
  error.
- After those, a compartment's refusals are counted but no longer
  logged, so a program cannot flood the log.
- P3-S6 moves this to the audit log (SR-11).

### The 32-bit entry paths

The spec never implements them. Keel had none: every IDT gate has
DPL 0, so `int 0x80` from user mode is #GP, and there is no 32-bit code
segment. `sysenter` was left to whatever the firmware put in
IA32_SYSENTER_CS. The kernel now clears that MSR at boot, so
`sysenter` is #GP(0) on Intel (SDM Vol. 2B, "SYSENTER"); on AMD it is
#UD in long mode.

## Not yet covered

- **`ioctl` classes for devices:** `/dev/null`, `/dev/zero` and the
  rest are "other", which `default` gives no requests. A device that
  needs requests gets its own class when it arrives (the framebuffer
  and input devices, Phase 5).
- **`socket` families and options** are not part of the profile:
  non-AF_UNIX families are refused by the call (EAFNOSUPPORT, spec
  section 10), and unknown socket options by `setsockopt` (SR-10).
- **`futex` operations** are not filtered per profile. The call
  implements only WAIT, WAKE, REQUEUE and CMP_REQUEUE and refuses the
  rest.

## Evidence

- **Host tests** (`keel_core::profile`, 10):
  - no profile holds a never-implemented call, and each is refused;
  - the never list has no duplicates, and keel-rt's copy (which
    profileprobe calls) is the same list;
  - a namespace flag is refused under every profile, alone or added to
    musl's thread flags;
  - every profile has the mechanism calls;
  - `default` is exactly the trace: its calls are the trace's and the
    mechanism ones, and the names are checked against
    `docs/syscall-inventory.md` itself (87 rows; userfaultfd out,
    clock_gettime in);
  - the default and full operations, the int-sized fcntl command, and
    the ceilings;
  - `compartment::Limits` refuses a profile above the ceiling's.
- **Manifest tests:** `profile = "full"` parses, the default is
  `default`, and anything else is "unknown profile".
- **`compartment.profiles` (phase 3):** `user/tests/profileprobe` runs
  in a compartment with each profile.
  - **In both:** all 43 never-implemented calls are ENOSYS; the 7
    namespace flags in `clone` are EINVAL; AF_INET, AF_INET6,
    AF_NETLINK and AF_PACKET sockets of three types are EAFNOSUPPORT.
    A child running `int 0x80` ends with SIGSEGV, and one running
    `sysenter` with SIGSEGV or SIGILL.
  - **Under `default`:** getppid and memfd_create are ENOSYS; fcntl
    F_GETFD, prctl PR_GET_NAME and clone with fork's flags are EINVAL;
    TCGETS on the console and FIONREAD on a pipe are ENOTTY.
  - **Under `full`:** each of those works.
  - **In both:** F_GETFL, PR_SET_NAME and TIOCGWINSZ work.
  - **Counts:** each compartment counts its refusals: 50 under `full`
    (43 calls, 7 flags), and exactly 7 more under `default`. The log
    shows the first 8 of each, then that the rest are only counted.
- **`exec.launch`:** an unknown profile number is EINVAL; beneath a
  ceiling with the default profile, a full one is EPERM, for a factory
  and for a compartment.
- **`launch.manifest`:** the manifest that names no profile runs its
  program with `default` (getppid ENOSYS), and one with
  `profile = "full"` with `full` (getppid works). Both exit 43.
- **Mutations, 8, each caught:**

  | Mutation | Caught by |
  | --- | --- |
  | no profile check at dispatch | `launch.manifest`: the default program exits 64 |
  | no ioctl check | `compartment.profiles`: exit 25, TCGETS let through; 2 fewer counted |
  | the terminal class dropped (the console counted as "other") | `compartment.profiles`: exit 32, TIOCGWINSZ refused |
  | `clone`'s flags not checked | `compartment.profiles`: exit 24, fork's flags let through |
  | `fcntl`'s command not checked | `compartment.profiles`: exit 22, F_GETFD let through |
  | every profile number read as `full` | `exec.launch` (ceiling check) and `launch.manifest` (exit 64) |
  | the profile left out of the ceiling check | `exec.launch` |
  | keel-launch ignoring the manifest's profile | `launch.manifest`: the full manifest's program exits 64 |

- **Not observable in a boot, so held by host tests only:**
  - the never-implemented check ahead of the profile (no profile
    contains one, and none is implemented);
  - the namespace-flag check (Keel's `clone` refuses those flags as
    well);
  - clearing IA32_SYSENTER_CS: QEMU starts it at 0, so `sysenter`
    faults with or without the write.

## Consequences

- A compartment made from a manifest that names no profile now runs
  with Wine's calls only. A program that needs more says
  `profile = "full"` in its manifest.
- The system compartment and the kernel's test compartments behave as
  before.
- A denied call costs one profile check per call: a bit test, and for
  the multiplexers a short list.
