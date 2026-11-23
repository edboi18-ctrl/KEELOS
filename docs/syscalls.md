# System calls

Every system call, ioctl and device node gets a row here: what authority
it exercises and which right is checked (spec section 1, rule 5).
Numbers follow the Linux x86-64 ABI: number in `rax`, arguments in
`rdi, rsi, rdx, r10, r8, r9`, result in `rax`, `rcx` and `r11`
clobbered. Unknown numbers return `-ENOSYS` (38); the first call of each
number below 512 is logged to serial with its Linux name and arguments,
and only the first number at or above 512 (the log is a fixed bitmap, so
no program can make it grow: F-0005). System calls run with interrupts
enabled and can be preempted (F-0008).

Which calls Wine actually makes, how often and with which flags, is
measured in `syscall-inventory.md` (P3-T1); Phase 3 adds calls here in
the order they first appear there.

Implementation: `kernel/linux-abi/src/syscall.rs`. Every file descriptor
is a handle with a rights mask (P1-S1, SR-1); the "Right" column is what
the handler asks the handle table for. A missing handle and a missing
right both give EBADF, as Linux does for writing to a read-only
descriptor.

Common rules for all calls:

- User memory is read and written only through `hal::vm::copy_from_user`
  and `copy_to_user`, which refuse anything outside the user half and turn
  a fault into EFAULT (SR-13). Structures are built in zeroed buffers
  (SR-18).
- Every length is capped: reads and writes at MAX_RW_COUNT
  (0x7fff_f000), iovec counts at UIO_MAXIOV (1024), paths at PATH_MAX
  (4096), with checked arithmetic throughout (SR-19).
- A partial transfer that then faults returns the bytes done, or EFAULT
  if nothing was done, as on Linux.
- `int` arguments use their low 32 bits, as on Linux.
- When only the kernel's frame reserve is free (`memory::user_reserve`),
  every call except `close`, `munmap`, `brk` and `exit`/`exit_group`
  (and `getpid`, which allocates nothing) returns ENOMEM before doing
  anything, so no program can make the kernel allocate its last frames
  (F-0011, ADR 0011). Page tables for user
  mappings come out of the same user-limited pool as user pages.

Tested by `user/tests/src/bin/syscalls.rs`, which runs under Linux
(`host.syscalls`) and under Keel (`syscalls.conformance`) and must pass
on both; it also performs the hostile-pointer sweep (security acceptance
item 2): every pointer argument of every call below, with null, the null
page, kernel addresses, a non-canonical address, the top of the user
half and the last byte of the address space, returns EFAULT. Where Linux
reads a null pointer as "no argument" (the input and output of the three
signal calls), null is a valid argument and the sweep uses the other
addresses.

| Number | Name | Status | Right | Authority and checks |
| --- | --- | --- | --- | --- |
| 0 | `read` | Complete for files and the four devices | READ | Regular files advance the shared offset. `/dev/console` waits for a line and returns at most one. Directories: EISDIR. |
| 1 | `write` | Complete for files and devices | WRITE | O_APPEND writes at the end. File growth is capped by the tmpfs limit and by the file owner's compartment quota (ENOSPC; ADR 0014). Console output is filtered to text. |
| 2 | `open` | As `openat` | as `openat` | `openat(AT_FDCWD, path, flags \| O_LARGEFILE, mode)`, as Linux's sys_open on 64-bit (`fs/open.c`). musl uses it on x86-64. |
| 3 | `close` | Complete | none (the handle is the caller's own) | |
| 5 | `fstat` | Complete | STAT | x86-64 `struct stat`; uid/gid 0 and reported only (SR-6); times 0 until there is a real-time clock. |
| 7 | `poll` | Complete for files and the four devices; waiting re-checks every 10 ms | none to look up the handle; readiness reported only for rights it has (READ for POLLIN, WRITE for POLLOUT) | Linux's rules (`fs/select.c`): more than 1024 entries (the handle limit, Linux's RLIMIT_NOFILE) EINVAL; a negative fd is skipped; a closed one gets POLLNVAL; POLLERR and POLLHUP always reported; `revents` written back for every entry (EFAULT if it cannot be). Files, directories, `/dev/null`, `/dev/zero`, `/dev/urandom` are always ready (DEFAULT_POLLMASK); the console is writable and readable once a line or end of file is ready. Differs from Linux on purpose: readiness is not reported for an operation the handle cannot perform (SR-1; ADR 0008). Until a readiness mechanism exists (P3-T10), a poll that must wait sleeps 10 ms between checks; a negative timeout waits without limit. No signal can interrupt it before P3-T6. |
| 9 | `mmap` | Partial: anonymous and private file mappings; MAP_SHARED not yet | READ on the handle for file mappings, and MAP_EXEC for PROT_EXEC | Writable+executable is EACCES (SR-12). Unknown flags EINVAL (SR-10). MAP_SHARED: EINVAL until P3-T7's second part. File mappings (ADR 0016): regular files only (a directory or other device ENODEV, as Linux); /dev/zero maps as anonymous memory; a handle not open for reading EACCES, PROT_EXEC without MAP_EXEC EPERM (mmap(2)); offset page-aligned (EINVAL). Pages are read from the file when first touched, into private frames charged to the compartment; the part of the last page past the end of the file is zero; a page wholly past the end cannot be filled (Linux: SIGBUS; here the access ends the thread until signals arrive). Changes to the file show through untouched pages, which mmap(2) leaves unspecified for MAP_PRIVATE. MAP_FIXED replaces only the caller's own mappings; MAP_FIXED_NOREPLACE supported. Reservations cost no memory. At most 65530 mappings per process; beyond that ENOMEM (F-0011). Adjacent mappings with the same rights are merged, file mappings only when contiguous in the same file. |
| 10 | `mprotect` | Complete for anonymous memory and private file mappings | none (own address space) | W+X refused (SR-12); unknown bits EINVAL. PROT_EXEC on a file mapping whose handle lacked MAP_EXEC: EACCES (mprotect(2)). ENOMEM if splitting a mapping would exceed the 65530-mapping cap, as on Linux. A split file mapping keeps each part's file offset. |
| 11 | `munmap` | Complete | none (own address space) | ENOMEM if cutting a hole would exceed the 65530-mapping cap, as on Linux. |
| 12 | `brk` | Complete | none (own address space) | Grows only into free space (never over another mapping) and never into the kernel half; a refused request returns the old break, as Linux. Not randomized until P1-S5. |
| 13 | `rt_sigaction` | Partial: records dispositions; no delivery until P3-T6 | none (own process) | Linux's rules (`kernel/signal.c`): `sigsetsize` other than 8, a signal outside 1..64, and setting SIGKILL or SIGSTOP are EINVAL; flag bits outside UAPI_SA_FLAGS are cleared (as Linux, so SA_UNSUPPORTED reads back clear); SIGKILL and SIGSTOP are removed from the handler mask; the old action is written after the new one is set (EFAULT then, with the change kept). Faults still end the thread with 128 + signal whatever handler is set (ADR 0008). |
| 14 | `rt_sigprocmask` | Partial: records the blocked mask; nothing is delivered yet | none (own thread) | `sigsetsize` other than 8 EINVAL; SIGKILL and SIGSTOP are never blocked; an unknown `how` is EINVAL only when a set is given, as Linux. |
| 16 | `ioctl` | Partial: TCGETS, TIOCGWINSZ on `/dev/console` | STAT | Other descriptors and requests: ENOTTY (SR-10). TCGETS reports Linux's `tty_std_termios`. Setting terminal state arrives with the TTY layer. |
| 17 | `pread64` | Complete for files and the four devices | READ | Reads at the given offset; the file position is not changed (pread(2)). A negative offset is EINVAL; the console is ESPIPE, as Linux, where tty_open calls nonseekable_open. Same caps and partial-transfer rules as `read`. |
| 20 | `writev` | Complete | WRITE | Count above 1024, or a total above the `ssize_t` maximum: EINVAL. |
| 39 | `getpid` | Complete | none (own process) | The PID inside the caller's compartment; each compartment numbers its processes from 1, as a Linux PID namespace (P3-S1, ADR 0014). Exempt from the reserve check: getpid(2) is "always successful". |
| 56 | `clone` | Partial: threads (musl's and the Wine trace's flags) and fork-like clones | none | ADR 0019. CLONE_THREAD needs CLONE_SIGHAND, CLONE_SIGHAND needs CLONE_VM (EINVAL). Without CLONE_VM: fork, on the given stack. With it: a thread (VM, FS, FILES, SIGHAND, THREAD; optional SYSVSEM, SETTLS, PARENT_SETTID, CHILD_CLEARTID, CHILD_SETTID, DETACHED) taking a compartment slot (EAGAIN), TID = the compartment's next PID; caller's registers (RAX 0, RSP = stack), FS = tls with SETTLS (EPERM outside the user half). Other flags EINVAL for now (CLONE_VFORK, namespaces). |
| 57 | `fork` | Complete | none | ADR 0018. A new process in the caller's compartment: EAGAIN at its process limit, ENOMEM if the copy-on-write address space does not fit its memory budget. Handles cloned (same open files and offsets), signal state, break, root and cwd copied; the child resumes with the caller's registers, FS/GS bases and FPU state, RAX 0, and gets the next PID of the compartment. |
| 59 | `execve` | Complete for ELF programs (static, PIE, dynamic); no `#!` scripts yet | none on handles; the file is looked up from the process root and working directory (its compartment's tree) | ADR 0017. Fails with the process unchanged: lookup errors; not a regular file EACCES; not usable ELF ENOEXEC; bad interpreter ELIBBAD; a string over MAX_ARG_STRLEN (128 KiB with its NUL) or arguments over the stack limit E2BIG, checked while reading; EFAULT; the new image must fit the compartment's memory budget (ENOMEM). An empty argv becomes [""]. Then: new address space and break; close-on-exec handles closed; caught signals reset (ignored kept), alternate stack dropped, blocked mask kept; FS/GS bases and FPU state reset, registers zeroed. No execute-bit check (SR-6). |
| 60 | `exit` | Complete | none | Ends the calling thread; the process ends with its last thread. Status is the low 8 bits, as Linux. |
| 61 | `wait4` | Partial: no process groups, no stopped children, rusage zero | none (own children) | ADR 0018. As kernel_wait4: unknown options EINVAL, INT_MIN ESRCH; -1 and 0 any child, other negative pgids ECHILD; no matching child ECHILD; WNOHANG with none exited 0; else blocks. Status `(code & 0xff) << 8` or the signal number. A zombie keeps its compartment slot until reaped. |
| 72 | `fcntl` | Partial: F_GETFD, F_SETFD | none (own handle table) | F_GETFD returns FD_CLOEXEC if set; F_SETFD sets it from the low 32 bits of the argument & FD_CLOEXEC; as Linux's do_fcntl. A missing descriptor is EBADF; any other command EINVAL, as Linux does for one it does not know. F_GETFL/F_SETFL and record locks come as the trace needs them. |
| 62 | `kill` | Partial: signal 0 and SIGKILL | none; the PID must be in the caller's compartment (ESRCH) | ADR 0019. Signal 0 checks existence; SIGKILL ends every thread of the process (wait status 9). Other signals EINVAL until delivery (P3-T6); PID 0 and negative (process groups) ESRCH. |
| 110 | `getppid` | Complete | none | The parent's PID in the compartment; 0 if it has none or has gone. |
| 131 | `sigaltstack` | Partial: records the alternate stack; used from P3-T6 | none (own thread) | Linux's rules: an unknown mode EINVAL; a stack below MINSIGSTKSZ (2048) ENOMEM; a change while the caller's stack pointer is on the alternate stack EPERM (never with SS_AUTODISARM); SS_DISABLE clears pointer and size; an unchanged request succeeds before the size check. The old stack reports SS_DISABLE, SS_ONSTACK or 0, as Linux's `sas_ss_flags`. |
| 158 | `arch_prctl` | ARCH_SET_FS/GS, ARCH_GET_FS/GS | none (own thread) | Bases must be user addresses (EPERM otherwise), so the MSR write cannot fault and no segment can point into the kernel. The kernel never uses FS or GS (ADR 0005). Other codes EINVAL. |
| 186 | `gettid` | Complete | none | The calling thread's TID (the PID for a process's first thread). |
| 202 | `futex` | Partial: WAIT, WAKE, REQUEUE, CMP_REQUEUE (private and shared alike) | none (own memory) | ADR 0019. Misaligned EINVAL; mismatch EAGAIN, checked under the wake lock; relative timeout ETIMEDOUT, bad timespec EINVAL; requeue counts negative EINVAL, CMP mismatch EAGAIN; other commands and FUTEX_CLOCK_REALTIME ENOSYS. Keys are (address space, address). |
| 218 | `set_tid_address` | Complete | none | Sets the calling thread's clear_child_tid and returns its TID. At thread exit, if other threads share the memory, 0 is written there and one futex waiter woken (Linux's mm_release). |
| 228 | `clock_gettime` | MONOTONIC, MONOTONIC_RAW, MONOTONIC_COARSE, BOOTTIME, REALTIME, REALTIME_COARSE | none | No real-time clock yet: the REALTIME clocks count from boot as if boot were 1970-01-01. CPU-time and other clocks EINVAL. |
| 231 | `exit_group` | Partial: same as `exit` until processes have several threads | none | |
| 257 | `openat` | Files, directories and devices in the tmpfs | ENUMERATE on `dirfd` when it is not AT_FDCWD; also CREATE with O_CREAT | Lookups never leave the process root, which is its compartment's root (SR-4, ADR 0014): absolute paths and AT_FDCWD start there and `..` stops there. A relative path through a directory handle is confined to that directory: `..` stops there, as with Linux's `openat2` RESOLVE_IN_ROOT, unlike plain Linux `openat` (ADR 0012). Directory handles get CREATE by default. Flags outside the supported set (O_DSYNC, O_SYNC, O_DIRECT, O_NOATIME, O_PATH, O_TMPFILE and unknown bits) are EINVAL (SR-10; Linux ignores unknown bits). O_CREAT applies umask 022; ENOSPC once the tmpfs holds 65536 nodes (F-0011) or the caller's compartment has used its node quota (ADR 0014); O_TRUNC gives the owner its bytes back. No permission checks by mode or user ID (SR-6). Rights granted: READ/WRITE by access mode, plus STAT, SEEK, DUPLICATE; ENUMERATE for directories; MAP_EXEC with READ on regular files (Linux compatibility; compartment manifests can withhold it from Phase 3). |
| 318 | `getrandom` | Complete | none | Unknown flags, and GRND_RANDOM with GRND_INSECURE, are EINVAL, as Linux. Bytes come from the kernel generator (`hal::random`: BLAKE2s pool, ChaCha20 with fast key erasure, seeded from RDSEED/RDRAND and timing, reseeded every 60 s). GRND_NONBLOCK never matters: the generator is seeded before the first process starts. |

Numbers checked against Linux v6.12 `arch/x86/entry/syscalls/syscall_64.tbl`,
flags and structures against the uapi headers listed in
`kernel/linux-abi/src/abi.rs`.

## Standard handles

Every process starts with `/dev/console` on fd 0 (READ, STAT, SEEK,
DUPLICATE) and on fds 1 and 2 (WRITE, STAT, SEEK, DUPLICATE). Each handle
gets only the direction it is for.

## Device nodes

| Path | Device | Authority and checks | Tests |
| --- | --- | --- | --- |
| `/dev/console` | 5:1 | Writes go to the kernel console, filtered to text (no control characters or escape sequences). Reads wait for a line from the keyboard (canonical mode, echo; Ctrl+D is end of file). Every process shares the one console until compartments (Phase 3) give each its own. | `fs.dev_nodes`, `fs.devices`, `console.keyboard_line` |
| `/dev/null` | 1:3 | Reads return end of file; writes are discarded. No authority. | `fs.dev_nodes`, `fs.devices` |
| `/dev/zero` | 1:5 | Reads return zeros; writes are discarded. No authority. | `fs.dev_nodes`, `fs.devices` |
| `/dev/urandom` | 1:9 | Reads return bytes from the kernel generator (as getrandom); writes are discarded (they are not mixed in, so no process can influence the pool). No authority. | `fs.dev_nodes`, `fs.devices` |

`/dev/mem`, `/dev/kmem` and `/dev/port` do not exist and cannot be
created: device nodes come only from a fixed list in the kernel (SR-9;
test `fs.no_forbidden_devices`).

## Faults

A fault in user mode (any exception vector below 32 except NMI and
machine check) ends the thread with status 128 + the matching Linux
signal number (SIGSEGV 11 for #PF, #GP and the rest, SIGILL 4 for #UD,
SIGFPE 8 for #DE/#MF/#XM, SIGTRAP 5 for #DB/#BP, SIGBUS 7 for #AC;
numbers from Linux `arch/x86/include/uapi/asm/signal.h`). Signals
proper arrive in Phase 2.
