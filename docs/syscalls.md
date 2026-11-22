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
| 231 | `exit_group` | Partial: same as `exit` until processes have several threads | None beyond being the caller | None yet (same code path as `exit`) |
| 0x1000 | `keel_test_add_one` | Temporary, Phase 1 self-tests only: returns `rdi + 1` (wrapping) | None; touches no memory. Removed before Phase 1 acceptance | `user.syscall` |

## Faults

A fault in user mode (any exception vector below 32 except NMI and
machine check) ends the thread with status 128 + the matching Linux
signal number (SIGSEGV 11 for #PF, #GP and the rest, SIGILL 4 for #UD,
SIGFPE 8 for #DE/#MF/#XM, SIGTRAP 5 for #DB/#BP, SIGBUS 7 for #AC;
numbers from Linux `arch/x86/include/uapi/asm/signal.h`). Signals
proper arrive in Phase 2.

Numbers checked against Linux v6.12 `arch/x86/entry/syscalls/syscall_64.tbl`
and `include/uapi/asm-generic/errno.h`.
