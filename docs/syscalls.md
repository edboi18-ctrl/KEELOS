# System calls

Every system call, ioctl and device node gets a row here: what authority
it exercises and which right is checked (spec section 1, rule 5).
Numbers follow the Linux x86-64 ABI: number in `rax`, arguments in
`rdi, rsi, rdx, r10, r8, r9`, result in `rax`, `rcx` and `r11`
clobbered. Unknown numbers return `-ENOSYS` (38), and the first
occurrence of each number is logged to serial.

| Number | Name | Status | Authority and checks | Tests |
| --- | --- | --- | --- | --- |
| 60 | `exit` | Partial: ends the calling thread; its status is `rdi` as a 32-bit integer | None beyond being the caller | `user.syscall`, `user.syscall_registers` |
| 231 | `exit_group` | Partial: same as `exit` until processes have several threads | None beyond being the caller | `exec.startup_state`, `exec.exit_status` (`keel-rt` exits through it) |
| 0x1000 | `keel_test_add_one` | Temporary, Phase 1 self-tests only: returns `rdi + 1` (wrapping) | None; touches no memory. Removed before Phase 1 acceptance | `user.syscall` |

## Device nodes

| Path | Device | Authority and checks | Tests |
| --- | --- | --- | --- |
| `/dev/console` | 5:1 | Writes go to the kernel console, filtered to text (no control characters or escape sequences). Reads return end of file until the keyboard driver (P1-T14). Rights checks arrive with handles (P1-S1). | `fs.dev_nodes`, `fs.devices` |
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

Numbers checked against Linux v6.12 `arch/x86/entry/syscalls/syscall_64.tbl`
and `include/uapi/asm-generic/errno.h`.
