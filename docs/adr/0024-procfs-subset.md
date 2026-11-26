# ADR 0024: The procfs subset

Status: accepted (Phase 3, P3-T9).

## Context

The spec's P3-T9 asks for "procfs subset as traced", and guesses
`/proc/self/exe`, `/proc/self/maps`, `/proc/self/fd/`, `/proc/cpuinfo` and
`/proc/meminfo`, marked **[verify]**. The Wine traces (both runs,
`docs/syscall-inventory.md`) settle it. Wine uses:

| Path | Calls | How |
| --- | --- | --- |
| `/proc` | `stat` 30, `readlink` 34 | its mode; not a link (EINVAL) |
| `/proc/self` | `readlink` 34 | the PID |
| `/proc/<pid>`, `/proc/<pid>/exe`, `/proc/self/exe` | `readlink` 34, 34, 32 | the program's path, to find Wine's install directory |
| `/proc/<pid>/task/<tid>/comm` | `open` O_WRONLY 66 | thread names |
| `/proc/cpuinfo` | `open`, `read`, `lseek` 3 | CPU details |
| `/proc/net/dev` | `open`, `read`, `lseek` 5 | network interfaces |

Wine also calls `prctl(PR_SET_NAME)` 22 times, the same thread name by
another door. `maps`, `fd/` and `meminfo` do not appear. Wine also reads
sysfs (`/sys/devices/system/cpu/...`), which P3-T9 does not cover.

## Decision

1. **Where procfs lives.** It sits over every process's `/proc`,
   whatever its tree holds there.
   - **Which paths reach it:** absolute paths whose first component,
     after `.`, `..` and repeated slashes are taken out lexically, is
     `proc`.
   - **Per compartment:** `/proc/<pid>` exists only for a PID of the
     caller's compartment, as in a PID namespace (ADR 0014).
   - **Parsing** (`keel_core::procfs`, host-tested) reads numbers as
     `name_to_int` does: digits only, no leading zero.
2. **The nodes and their modes.** These are procfs's: directories 0555,
   links 0777, `comm` 0644, the rest 0444. They are reported on their
   own device (0:2), with sizes of 0, as procfs reports them.
   - **Directories:** `/proc`, `/proc/<pid>`, `/proc/<pid>/task`,
     `/proc/<pid>/task/<tid>`, `/proc/net`. On Linux `/proc/net` is a
     link to `self/net`.
   - **Links:**
     - `/proc/self` reads as the PID;
     - `/proc/thread-self` as `<pid>/task/<tid>`;
     - `exe` as the program's path. `stat` and `open` follow it to the
       program in the real tree, and O_NOFOLLOW refuses it (ELOOP).
   - **Files:** `comm` (under the PID and under each task),
     `/proc/cpuinfo`, `/proc/net/dev`.
3. **The program's path** is recorded at spawn and at `execve`: the path
   from the root. A relative path is completed from the working
   directory. Symbolic links in it are not resolved, where Linux reports
   the file's own path.
4. **Thread names** (`comm`, at most 15 bytes):
   - **Where they start:**
     - a program starts named after its path's last component
       (`__set_task_comm(kbasename(bprm->filename))`), and `execve`
       renames;
     - a new thread or forked child starts with its creator's name.
   - **Reading** `comm` gives the name and a newline (`comm_show`).
   - **Writing** takes up to 15 bytes, stopping at a NUL, and reports the
     whole count (`comm_write`). It is EINVAL for a thread of another
     process; that is checked when the file is opened, where Linux
     checks the writer at each write.
   - **`prctl`:** PR_SET_NAME reads up to 15 bytes and PR_GET_NAME writes
     16, NUL-padded (`kernel/sys.c`). Every other option is EINVAL, the
     default branch. That includes PR_SET_PTRACER (11 calls in the
     traces), which only the Yama security module knows.
5. **`/proc/cpuinfo`** follows `show_cpuinfo` (`arch/x86/kernel/cpu/
   proc.c`), from CPUID and the TSC calibration:
   - **The identification lines:**
     - vendor, family, model and stepping (`x86_family`, `x86_model`,
       `x86_stepping`);
     - the model name with its spaces trimmed (`get_model_name`);
     - `cpu MHz`, and `bogomips` as twice it.
   - **The rest:**
     - the core lines for Keel's one CPU;
     - `fpu`, `cpuid level`, `wp`, `clflush size`, `cache_alignment`,
       `address sizes` and `power management` (`powerflags.c`).
   - **`flags`** is in Linux's order, with Linux's names. The table is
     generated from `cpufeatures.h` by the rule of `mkcapflags.sh` (the
     quoted name, lower case; none or "" hides the flag), for the words
     that are one CPUID register each.
6. **`/proc/net/dev`** is the two header lines of `dev_seq_show`. Keel has
   no network interfaces yet.
7. **How a file is opened.**
   - **Snapshots.** A procfs file opens as a snapshot of its contents as
     of the open, in a tmpfs node no directory names, pinned by the open
     file (ADR 0022). So read, lseek and fstat work as on any file, and
     the snapshot goes at the last close. Linux makes the contents as
     they are read.
   - **Writing:** only `comm` may be opened for writing. The others are
     EACCES: their mode is 0444, and Keel refuses writes there to root
     too.
   - **Creating:** O_CREAT of a new name is EACCES; O_CREAT with O_EXCL
     on an existing node is EEXIST.
   - **`exe`:** opened through the link, the program is read only
     (ETXTBSY for writing, as Linux's `deny_write_access`).
   - **`statfs`** on `/proc` reports PROC_SUPER_MAGIC (`simple_statfs`)
     and the flags of `/proc` as systemd mounts it.
8. **Execute bits.** The initramfs now marks ELF files 0755, as installed
   programs are on Linux, so `access(X_OK)` through `/proc/self/exe`
   answers as Linux does. Other files stay 0644.

## Not yet covered

- **A procfs working directory.** Listing procfs directories and
  lookups relative to their descriptors came with ADR 0037.
- **The other procfs files:** `/proc/self/fd/`, `maps`, `status`,
  `meminfo` and the rest. None is in the traces. `stat` and `cmdline`
  came with ADR 0037.
- **`/proc/cpuinfo` omits** what Linux derives rather than reads:
  - `microcode` (an MSR);
  - `cache size`;
  - the flags Linux synthesizes (constant_tsc, nopl, ...);
  - the `bugs` list Linux derives from its mitigations.
- **sysfs** (`/sys/devices/system/cpu`), which Wine reads for the CPU
  topology. Wine falls back without it.
- **`fstat` of an open procfs file** reports its snapshot's size, where
  Linux reports 0.

## Evidence

- **Host tests** (`keel_core::procfs`):
  - path resolution: `self`, `thread-self`, `exe` followed and not,
    `task`, `net/dev`;
  - nothing for another compartment's PID, another process's thread, a
    leading zero or a sign;
  - link targets and modes;
  - `cpuinfo` from a fake CPUID: family, extended model, stepping,
    trimmed brand, MHz, flags in order, bogomips, clflush, address
    sizes, power management.
- **Host test** (`keel_core::vfs`): a detached file lives while pinned
  and gives its bytes back.
- **`exec.procfs` (phase 3) and `host.procprobe`:** `user/tests/procprobe`
  makes 25 checks, which pass under Linux and on Keel:
  - `/proc` is a directory and not a link;
  - `/proc/self` gives the PID, and lstat/stat see a link and a
    directory;
  - `exe` under self and the PID reads as the program's absolute path;
    `stat` reaches the program itself; O_NOFOLLOW is ELOOP; X_OK passes;
  - the starting name is the program's base name;
  - a write to `task/<tid>/comm` renames the thread, and PR_GET_NAME
    agrees; PR_SET_NAME keeps 15 bytes;
  - a forked child sees itself as self, its parent's PID, and its
    parent's name;
  - an absent PID and an absent name are ENOENT;
  - `/proc/cpuinfo` has Linux's layout and can be read and stepped back;
  - `/proc/net/dev` begins with the header lines;
  - `statfs` gives procfs's magic.

  Afterwards every node, frame and process is back.
- **Mutations.**
  - **Host,** each caught:
    - a leading zero accepted;
    - another compartment's PID shown;
    - another process's thread shown;
    - the extended model ignored;
    - the brand not trimmed.
  - **On Keel,** each caught by `procprobe` at the check named:
    - comm writes ignored (13);
    - PR_SET_NAME taking 16 bytes (16);
    - a forked child not given its parent's name (17);
    - the program's path not recorded (7);
    - an empty `/proc/net/dev` (24).

## Consequences

- Wine finds its install directory, names its threads, reads the CPU
  description and finds no network interfaces, as on a Linux host with
  none.
- Every absolute path lookup first checks whether it is a `/proc` path:
  one pass over the path.
