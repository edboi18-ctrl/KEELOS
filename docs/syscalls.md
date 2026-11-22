# System calls

Every system call, ioctl and device node gets a row here: what authority
it exercises and which right is checked (spec section 1, rule 5).
Numbers follow the Linux x86-64 ABI: number in `rax`, arguments in
`rdi, rsi, rdx, r10, r8, r9`, result in `rax`, `rcx` and `r11`
clobbered. Unknown numbers return `-ENOSYS` (38); the first call of each
is logged to serial with its Linux name and arguments.

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

Tested by `user/tests/src/bin/syscalls.rs`, which runs under Linux
(`host.syscalls`) and under Keel (`syscalls.conformance`) and must pass
on both; it also performs the hostile-pointer sweep (security acceptance
item 2): every pointer argument of every call below, with null, the null
page, kernel addresses, a non-canonical address, the top of the user
half and the last byte of the address space, returns EFAULT.

| Number | Name | Status | Right | Authority and checks |
| --- | --- | --- | --- | --- |
| 0 | `read` | Complete for files and the four devices | READ | Regular files advance the shared offset. `/dev/console` waits for a line and returns at most one. Directories: EISDIR. |
| 1 | `write` | Complete for files and devices | WRITE | O_APPEND writes at the end. File growth is capped by the tmpfs limit (ENOSPC). Console output is filtered to text. |
| 3 | `close` | Complete | none (the handle is the caller's own) | |
| 5 | `fstat` | Complete | STAT | x86-64 `struct stat`; uid/gid 0 and reported only (SR-6); times 0 until there is a real-time clock. |
| 9 | `mmap` | Partial: anonymous private mappings | READ (and MAP_EXEC for PROT_EXEC) on the handle, for file mappings | Writable+executable is EACCES (SR-12). Unknown flags EINVAL (SR-10). MAP_SHARED: EINVAL until fork. File mappings: ENODEV until P3-T7, after the handle check. MAP_FIXED replaces only the caller's own mappings; MAP_FIXED_NOREPLACE supported. Reservations cost no memory (demand paging). |
| 10 | `mprotect` | Complete for anonymous memory | none (own address space) | W+X refused (SR-12); unknown bits EINVAL. |
| 11 | `munmap` | Complete | none (own address space) | |
| 12 | `brk` | Complete | none (own address space) | Grows only into free space (never over another mapping) and never into the kernel half; a refused request returns the old break, as Linux. Not randomized until P1-S5. |
| 16 | `ioctl` | Partial: TCGETS, TIOCGWINSZ on `/dev/console` | STAT | Other descriptors and requests: ENOTTY (SR-10). TCGETS reports Linux's `tty_std_termios`. Setting terminal state arrives with the TTY layer. |
| 20 | `writev` | Complete | WRITE | Count above 1024, or a total above the `ssize_t` maximum: EINVAL. |
| 60 | `exit` | Partial: ends the calling thread | none | Status is the low 8 bits, as Linux. |
| 158 | `arch_prctl` | ARCH_SET_FS/GS, ARCH_GET_FS/GS | none (own thread) | Bases must be user addresses (EPERM otherwise), so the MSR write cannot fault and no segment can point into the kernel. The kernel never uses FS or GS (ADR 0005). Other codes EINVAL. |
| 218 | `set_tid_address` | Partial: stores the address, returns the TID | none | The clear-on-exit write needs futexes and threads (Phase 2 onward). |
| 228 | `clock_gettime` | MONOTONIC, MONOTONIC_RAW, MONOTONIC_COARSE, BOOTTIME, REALTIME, REALTIME_COARSE | none | No real-time clock yet: the REALTIME clocks count from boot as if boot were 1970-01-01. CPU-time and other clocks EINVAL. |
| 231 | `exit_group` | Partial: same as `exit` until processes have several threads | none | |
| 257 | `openat` | Files, directories and devices in the tmpfs | ENUMERATE on `dirfd` when it is not AT_FDCWD | Lookups never leave the process root (SR-4 groundwork). Flags outside the supported set (O_DSYNC, O_SYNC, O_DIRECT, O_NOATIME, O_PATH, O_TMPFILE and unknown bits) are EINVAL (SR-10; Linux ignores unknown bits). O_CREAT applies umask 022. No permission checks by mode or user ID (SR-6). Rights granted: READ/WRITE by access mode, plus STAT, SEEK, DUPLICATE; ENUMERATE for directories; MAP_EXEC with READ on regular files (Linux compatibility; compartment manifests can withhold it from Phase 3). |
| 318 | `getrandom` | Complete | none | Unknown flags, and GRND_RANDOM with GRND_INSECURE, are EINVAL, as Linux. Bytes come from the interim source until P1-S5 (RDRAND after a self-test, else a weak mix). |
| 0x1000 | `keel_test_add_one` | Temporary, Phase 1 self-tests only: returns `rdi + 1` | none | Touches no memory. Removed before Phase 1 acceptance. |

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
| `/dev/urandom` | 1:9 | Reads return random bytes (interim source until P1-S5); writes are discarded. No authority. | `fs.dev_nodes`, `fs.devices` |

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
