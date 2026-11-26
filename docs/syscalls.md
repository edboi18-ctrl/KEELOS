# System calls

Every system call, ioctl and device node gets a row here: what authority
it exercises and which right is checked (spec section 1, rule 5).
Numbers follow the Linux x86-64 ABI: number in `rax`, arguments in
`rdi, rsi, rdx, r10, r8, r9`, result in `rax`, `rcx` and `r11`
clobbered. Unknown numbers return `-ENOSYS` (38); the first call of each
number below 512 is logged to serial with its Linux name and arguments,
and only the first number at or above 512 (the log is a fixed bitmap, so
no program can make it grow: F-0005). System calls run with interrupts
enabled and can be preempted (F-0008). A blocking call a signal
interrupts is restarted, or is EINTR, by Linux's rules (ADR 0031: its
ERESTARTSYS or ERESTARTNOHAND, SA_RESTART, and no handler run).

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
| 0 | `read` | Complete for files, the four devices, pipes and eventfds | READ | Regular files advance the shared offset. Terminals (`/dev/console`, `/dev/ptmx`, `/dev/pts/N`): ADR 0029 (a line in canonical mode, else VMIN and VTIME; EIO from a master whose slave closed; 0 from a hung-up slave). Directories: EISDIR. Pipes and eventfds: ADR 0025 (EAGAIN with O_NONBLOCK, else a wait). A wait is cut short by a signal with EINTR. |
| 1 | `write` | Complete for files, devices, pipes and eventfds | WRITE | O_APPEND writes at the end. File growth is capped by the tmpfs limit and by the file owner's compartment quota (ENOSPC; ADR 0014). Console output is filtered to text. Pipes: at most PIPE_BUF bytes atomically, EPIPE and SIGPIPE with no reader; eventfds: 8 bytes added to the counter (ADR 0025). |
| 2 | `open` | As `openat` | as `openat` | `openat(AT_FDCWD, path, flags \| O_LARGEFILE, mode)`, as Linux's sys_open on 64-bit (`fs/open.c`). musl uses it on x86-64. |
| 3 | `close` | Complete | none (the handle is the caller's own) | |
| 4 | `stat` | Complete | none (a path from the process root; no mode checks, SR-6) | ADR 0022. newfstatat(AT_FDCWD, path, buf, 0): follows symbolic links. Times are tmpfs's (access, modification, change); a directory's size is 20 bytes per entry plus two, a link's its target's length; st_blocks whole pages for files. |
| 5 | `fstat` | Complete | STAT | x86-64 `struct stat`; uid/gid 0 and reported only (SR-6); access, modification and change times from the realtime clock, as tmpfs keeps them (ADR 0022); a file unlinked while open reports nlink 0. |
| 6 | `lstat` | Complete | as `stat` | ADR 0022. As stat without following a last symbolic link. |
| 7 | `poll` | Complete for files, the four devices, pipes and eventfds | none to look up the handle; readiness reported only for rights it has (READ for POLLIN, WRITE for POLLOUT) | ADR 0025. Linux's rules (`fs/select.c`): more than 1024 entries (the handle limit, Linux's RLIMIT_NOFILE) EINVAL; a negative fd is skipped; a closed one gets POLLNVAL; POLLERR and POLLHUP always reported; `revents` written back for every entry (EFAULT if it cannot be). Files, directories, `/dev/null`, `/dev/zero`, `/dev/urandom` are always ready (DEFAULT_POLLMASK); the console is writable and readable once a line or end of file is ready; pipes and eventfds as `pipe_poll` and `eventfd_poll`. Differs from Linux on purpose: readiness is not reported for an operation the handle cannot perform (SR-1; ADR 0008). A wait ends at a readiness change, the timeout (negative: none) or a signal the thread does not block (EINTR, even with a zero timeout; not restarted, ADR 0020). |
| 8 | `lseek` | Complete for files, directories and the four devices | SEEK | ADR 0022. As `generic_file_llseek_size`: SEEK_SET, SEEK_CUR, SEEK_END; below 0 or above MAX_LFS_FILESIZE EINVAL; an unknown whence EINVAL. SEEK_DATA and SEEK_HOLE outside the file ENXIO, inside it every byte is data (no holes). Directories: SEEK_SET and SEEK_CUR set getdents64's entry index (SEEK_END EINVAL). The console ESPIPE; /dev/null, /dev/zero, /dev/urandom stay at 0. |
| 9 | `mmap` | Partial: anonymous, private and shared file mappings; no shared anonymous memory | READ on the handle for file mappings, MAP_EXEC for PROT_EXEC, and WRITE for a writable shared one | Writable+executable is EACCES (SR-12). Unknown flags EINVAL (SR-10). MAP_SHARED and MAP_SHARED_VALIDATE (ADR 0021): every shared mapping of a file page maps one frame, kept coherent with read(2) and write(2); a shared mapping with PROT_WRITE from a handle not open for writing EACCES, and it can never be made writable (mprotect EACCES, as Linux without VM_MAYWRITE); fork keeps it shared. MAP_SHARED with MAP_ANONYMOUS, or of /dev/zero, EINVAL for now. File mappings (ADR 0016): regular files only (a directory or other device ENODEV, as Linux); /dev/zero maps as anonymous memory; a handle not open for reading EACCES, PROT_EXEC without MAP_EXEC EPERM (mmap(2)); offset page-aligned (EINVAL). Pages are read from the file when first touched, into private frames charged to the compartment; the part of the last page past the end of the file is zero; a page wholly past the end cannot be filled (Linux: SIGBUS; here the access is a SIGSEGV fault, ADR 0020). Changes to the file show through untouched pages, which mmap(2) leaves unspecified for MAP_PRIVATE. MAP_FIXED replaces only the caller's own mappings; MAP_FIXED_NOREPLACE supported. Reservations cost no memory. At most 65530 mappings per process; beyond that ENOMEM (F-0011). Adjacent mappings with the same rights are merged, file mappings only when contiguous in the same file. |
| 10 | `mprotect` | Complete for anonymous memory and private file mappings | none (own address space) | W+X refused (SR-12); unknown bits EINVAL. PROT_EXEC on a file mapping whose handle lacked MAP_EXEC: EACCES (mprotect(2)). ENOMEM if splitting a mapping would exceed the 65530-mapping cap, as on Linux. A split file mapping keeps each part's file offset. |
| 11 | `munmap` | Complete | none (own address space) | ENOMEM if cutting a hole would exceed the 65530-mapping cap, as on Linux. |
| 12 | `brk` | Complete | none (own address space) | Grows only into free space (never over another mapping) and never into the kernel half; a refused request returns the old break, as Linux. Not randomized until P1-S5. |
| 13 | `rt_sigaction` | Complete | none (own process) | Linux's rules (`kernel/signal.c`): `sigsetsize` other than 8, a signal outside 1..64, and setting SIGKILL or SIGSTOP are EINVAL; flag bits outside UAPI_SA_FLAGS are cleared (as Linux, so SA_UNSUPPORTED reads back clear); SIGKILL and SIGSTOP are removed from the handler mask; the old action is written after the new one is set (EFAULT then, with the change kept). Setting SIG_IGN (or SIG_DFL for a signal ignored by default) discards it where pending, as do_sigaction. Delivery: ADR 0020. A handler without SA_RESTORER cannot be delivered (Linux: "x86-64 should always use SA_RESTORER"; the delivery becomes SIGSEGV). SA_RESTART, SA_NOCLDSTOP and SA_NOCLDWAIT, and SIGCHLD set to SIG_IGN: ADR 0031. |
| 14 | `rt_sigprocmask` | Complete | none (own thread) | `sigsetsize` other than 8 EINVAL; SIGKILL and SIGSTOP are never blocked; an unknown `how` is EINVAL only with a new set (as Linux). The mask is per thread (ADR 0020); a pending signal it unblocks is delivered as the call returns. |
| 15 | `rt_sigreturn` | Complete | none (own thread) | ADR 0020. Reads the frame at RSP - 8 (the restorer was called by the handler's `ret`): restores the mask, the alternate stack (errors ignored, as Linux), the FPU state (XSAVE or FXSAVE format; a legacy-only area restores x87/SSE and resets the rest; one the CPU would refuse is SIGSEGV) and every general register, RIP, RSP and the FIX_EFLAGS bits; returns the saved RAX. CS and SS are not taken from the frame: there is one user code and one user data selector. An unreadable frame: SIGSEGV. |
| 16 | `ioctl` | Partial: terminal requests; FIONREAD and SIOCOUTQ on pipes and sockets | STAT | Terminals: ADR 0029 (TCGETS, TCSETS, TCSETSW, TCSETSF and their termios2 and termio forms; TIOCGWINSZ, TIOCSWINSZ; TCFLSH, TCXONC, FIONREAD, TIOCOUTQ, TCSBRK, TCSBRKP; TIOCEXCL, TIOCNXCL, TIOCGEXCL; TIOCGETD, TIOCSETD (N_TTY only); TIOCGDEV; TIOCGSOFTCAR, TIOCSSOFTCAR; TIOCGLCKTRMIOS, TIOCSLCKTRMIOS; on a pty master TIOCGPTN, TIOCSPTLCK, TIOCGPTLCK, TIOCGPTPEER, TIOCSIG, TIOCGPKT). A hung-up terminal: EIO (TIOCSPGRP ENOTTY). Job control: TIOCSCTTY, TIOCNOTTY, TIOCGPGRP, TIOCSPGRP (a group whose members have all exited but are not reaped still exists, ADR 0032), TIOCGSID, and the background checks (SIGTTIN, SIGTTOU) of ADR 0030. Other descriptors and requests: ENOTTY (SR-10). |
| 17 | `pread64` | Complete for files and the four devices | READ | Reads at the given offset; the file position is not changed (pread(2)). A negative offset is EINVAL; a terminal is ESPIPE, as Linux, where tty_open calls nonseekable_open. Same caps and partial-transfer rules as `read`. |
| 18 | `pwrite64` | Complete for files and the three seekable devices | WRITE | ADR 0023. As pwritev with one buffer: a negative offset EINVAL, a terminal ESPIPE; the file position stays; with O_APPEND the data goes at the end, as Linux (pwrite(2) BUGS). |
| 19 | `readv` | Complete | READ | ADR 0023. More than 1024 vectors or a total past ssize_t EINVAL; buffers filled in order, stopping at a short read. A pipe or eventfd reads the vectors as one read (ADR 0025). |
| 20 | `writev` | Complete | WRITE | Count above 1024, or a total above the `ssize_t` maximum: EINVAL. A pipe or eventfd takes the vectors as one write (atomic up to PIPE_BUF; ADR 0025). |
| 21 | `access` | Complete | none | ADR 0022. faccessat2(AT_FDCWD, path, mode, 0). Bits outside R_OK, W_OK, X_OK EINVAL. Processes are root and modes are not checked (SR-6): as root in `generic_permission`, read and write always allowed, execute only for a directory or a file with an execute bit (EACCES). |
| 22 | `pipe` | Complete | none (makes two handles: READ, STAT, DUPLICATE and WRITE, STAT, DUPLICATE) | ADR 0025. pipe2 with no flags. |
| 23 | `select` | Complete | as `poll` | ADR 0025. n below 0 EINVAL, clamped to the size Linux's descriptor table would have; a descriptor set but not open EBADF; each set counted separately (POLLIN_SET, POLLOUT_SET, POLLEX_SET); sets written back unless interrupted. A timeval (microseconds carry into seconds; negative EINVAL); the time left written back. |
| 32 | `dup` | Complete | DUPLICATE (EBADF without) | ADR 0023. The lowest free descriptor, sharing the open file description and its rights; close-on-exec clear. |
| 33 | `dup2` | Complete | DUPLICATE | ADR 0023. To exactly newfd, which is closed first (with its record locks); the same descriptor returns it if open; newfd at or past the handle limit EBADF. |
| 35 | `nanosleep` | Complete | none (own thread) | ADR 0033. As `hrtimer_nanosleep` on CLOCK_MONOTONIC: the request EFAULT, then EINVAL for a negative tv_sec or a tv_nsec outside 0..1e9. Cut short by a signal: the time left to `rem` (if given; none left is success) and ERESTART_RESTARTBLOCK, so with no handler (a stop and SIGCONT) it goes on to its first deadline through restart_syscall, and after a handler it is EINTR. |
| 39 | `getpid` | Complete | none (own process) | The PID inside the caller's compartment; each compartment numbers its processes from 1, as a Linux PID namespace (P3-S1, ADR 0014). Exempt from the reserve check: getpid(2) is "always successful". |
| 41 | `socket` | Partial: AF_UNIX SOCK_STREAM and SOCK_DGRAM | none (makes a handle: READ, WRITE, STAT, DUPLICATE) | ADR 0027, 0028. Linux's order: bad flags EINVAL; family outside 0..AF_MAX EAFNOSUPPORT; type at SOCK_MAX or past EINVAL; other families EAFNOSUPPORT; protocol other than 0 or 1 EPROTONOSUPPORT; SOCK_RAW is SOCK_DGRAM; SOCK_SEQPACKET and others ESOCKTNOSUPPORT. fstat S_IFSOCK 0777 on sockfs; lseek ESPIPE. |
| 42 | `connect` | Complete for stream and datagram sockets | none | ADR 0027 (stream: connected at once, the accepting side queued on the listener; EISCONN, ECONNREFUSED, EPROTOTYPE, backlog EAGAIN), ADR 0028 (datagram: sets or, with AF_UNSPEC, clears the peer; EPERM for a target connected elsewhere; a change drops what was received). |
| 43 | `accept` | Complete | none | ADR 0027. accept4 with no flags. |
| 44 | `sendto` | Complete for Unix sockets | WRITE as write | ADR 0027 (stream), ADR 0028 (datagram: an address or the peer; EMSGSIZE past the send buffer less 32; EPERM; ECONNREFUSED for a gone peer, which disconnects; EPIPE without SIGPIPE; a full queue EAGAIN or a wait). |
| 45 | `recvfrom` | Complete for Unix sockets | READ as read | ADR 0027 (stream), ADR 0028 (datagram: one datagram, truncated to the buffer; MSG_TRUNC returns its length). The sender's name if it has one, else length 0. Descriptors that arrive are closed. |
| 46 | `sendmsg` | Complete for Unix sockets | WRITE; DUPLICATE on each descriptor passed | ADR 0028. msghdr EFAULT, EINVAL, EMSGSIZE (vectors); control past INT_MAX ENOBUFS; control copied (EFAULT) and walked as `__scm_send`: SCM_RIGHTS (EBADF; more than 253 EINVAL), SCM_CREDENTIALS (EINVAL, ESRCH), other types EINVAL, other levels skipped. Then as sendto. In-flight descriptors limited per compartment (ETOOMANYREFS past 1024). |
| 47 | `recvmsg` | Complete for Unix sockets | READ | ADR 0028. As recvfrom into the vectors; SCM_CREDENTIALS (with SO_PASSCRED) then SCM_RIGHTS, as `put_cmsg`/`scm_detach_fds` fit them; received descriptors get the sender's rights (MSG_CMSG_CLOEXEC honoured); MSG_CTRUNC, MSG_TRUNC; msg_namelen, msg_controllen, msg_flags written back. |
| 48 | `shutdown` | Complete | none | ADR 0027. how outside 0..2 EINVAL; the peer gains the mirror; an unconnected socket is fine. |
| 49 | `bind` | Complete for Unix sockets | none | ADR 0027. Family alone: autobind. A path: a socket node (0777 less umask; EEXIST is EADDRINUSE), then EINVAL if already named (node removed). An abstract name, per compartment: EINVAL if named, EADDRINUSE if taken. |
| 50 | `listen` | Complete | none | ADR 0027. Backlog capped at 4096 (unsigned); not stream EOPNOTSUPP; unnamed or connected EINVAL. |
| 51 | `getsockname` | Complete | none | ADR 0027. As bound (a path with its NUL), or the family alone; the length caps the copy and the full length is written back (negative EINVAL). |
| 52 | `getpeername` | Complete | none | ADR 0027. The peer's name, or the family alone; no peer ENOTCONN. |
| 53 | `socketpair` | Partial: AF_UNIX SOCK_STREAM and SOCK_DGRAM | as `socket` | ADR 0027, 0028. Two connected sockets, each with the caller's credentials; EFAULT closes both. |
| 54 | `setsockopt` | Partial | none | ADR 0027. SOL_SOCKET only (others EOPNOTSUPP); a value under 4 bytes EINVAL; SO_PASSCRED, SO_SNDBUF/SO_RCVBUF (capped, doubled, minimum), SO_RCVTIMEO/SO_SNDTIMEO (EDOM), and six kept flags; SO_TYPE/SO_PROTOCOL/SO_DOMAIN/SO_ERROR and the rest ENOPROTOOPT. |
| 55 | `getsockopt` | Partial | none | ADR 0027. The level first (EOPNOTSUPP), then the length (EFAULT, negative EINVAL); those options plus SO_TYPE, SO_DOMAIN, SO_PROTOCOL, SO_ACCEPTCONN, SO_ERROR (taken), SO_PEERCRED (pid in the caller's compartment, else 0; none: 0, -1, -1). |
| 56 | `clone` | Partial: threads (musl's and the Wine trace's flags) and fork-like clones | none | ADR 0019. CLONE_THREAD needs CLONE_SIGHAND, CLONE_SIGHAND needs CLONE_VM (EINVAL). Without CLONE_VM: fork, on the given stack. With it: a thread (VM, FS, FILES, SIGHAND, THREAD; optional SYSVSEM, SETTLS, PARENT_SETTID, CHILD_CLEARTID, CHILD_SETTID, DETACHED) taking a compartment slot (EAGAIN), TID = the compartment's next PID; caller's registers (RAX 0, RSP = stack), FS = tls with SETTLS (EPERM outside the user half). CLONE_VM | CLONE_VFORK (posix_spawn's) is vfork, and CLONE_VFORK alone a fork whose caller waits likewise (ADR 0034). Other flags EINVAL for now (CLONE_VM without CLONE_THREAD otherwise, namespaces). |
| 57 | `fork` | Complete | none | ADR 0018. A new process in the caller's compartment: EAGAIN at its process limit, ENOMEM if the copy-on-write address space does not fit its memory budget. Handles cloned (same open files and offsets), signal state, break, root and cwd copied; the child resumes with the caller's registers, FS/GS bases and FPU state, RAX 0, and gets the next PID of the compartment. |
| 58 | `vfork` | Complete | none | ADR 0034. As `kernel_clone` with CLONE_VFORK \| CLONE_VM: a new process as fork makes (EAGAIN at the process limit), using the parent's own address space (charged once) and the caller's stack. The calling thread waits, killable only (TASK_KILLABLE), until the child's execve has put its new image in place or the child exits (`mm_release`); signals sent meanwhile are taken after. |
| 59 | `execve` | Complete for ELF programs (static, PIE, dynamic) and `#!` scripts | none on handles; the file is looked up from the process root and working directory (its compartment's tree) | ADRs 0017, 0036. `#!` scripts as `load_script`: the first 256 bytes; a cut-off interpreter name ENOEXEC, no name ENOEXEC; argv the interpreter, its one argument, the given path, then argv[1..]; the interpreter looked up the same way and may be a script, five levels, ELOOP at a sixth; thread name and AT_EXECFN from the given path, /proc/self/exe the interpreter. Fails with the process unchanged: lookup errors; not a regular file EACCES; not usable ELF ENOEXEC; bad interpreter ELIBBAD; a string over MAX_ARG_STRLEN (128 KiB with its NUL) or arguments over the stack limit E2BIG, checked while reading; EFAULT; the new image must fit the compartment's memory budget (ENOMEM). An empty argv becomes [""]. Then: new address space and break; close-on-exec handles closed; caught signals reset (ignored kept), alternate stack dropped, blocked mask kept; FS/GS bases and FPU state reset, registers zeroed. No execute-bit check (SR-6). |
| 60 | `exit` | Complete | none | Ends the calling thread; the process ends with its last thread. Status is the low 8 bits, as Linux. |
| 61 | `wait4` | Partial: rusage zero | none (own children) | ADR 0018, ADR 0030, ADR 0031 (WUNTRACED and WCONTINUED report a child's stop and continuing once each; interrupted: ERESTARTSYS). As kernel_wait4: unknown options EINVAL, INT_MIN ESRCH; -1 any child, 0 a child in the caller's process group, another negative value one in that group (the child's group when wait4 looks); no matching child ECHILD; WNOHANG with none exited 0; else blocks. Status `(code & 0xff) << 8` or the signal number. A zombie keeps its compartment slot until reaped. A blocking wait is cut short by a signal with EINTR. |
| 72 | `fcntl` | Partial: F_GETFD, F_SETFD, F_DUPFD, F_DUPFD_CLOEXEC, F_GETFL, F_SETFL, F_GETLK, F_SETLK, F_SETLKW | none for the descriptor flags; READ or WRITE for a read or write lock | ADR 0023. F_GETFL: the access mode and kept open flags with O_LARGEFILE; F_SETFL changes only O_APPEND, O_NONBLOCK, O_DIRECT, O_NOATIME. F_DUPFD(_CLOEXEC): lowest free at or above arg, at or past the limit EINVAL. Record locks per process (`fs/locks.c`): conflicts EAGAIN, F_SETLKW waits (EINTR on a signal; no deadlock detection), F_GETLK reports the conflicting lock and its owner's PID (0 across compartments); released when the process closes any descriptor of the file, and at exit. Other commands (OFD locks, leases, seals) EINVAL. |
| 77 | `ftruncate` | Complete for tmpfs files | WRITE (EINVAL without it, as Linux) | ADR 0021. As do_sys_ftruncate and do_ftruncate (`fs/open.c`): a negative length EINVAL, no handle EBADF, not a regular file or not open for writing EINVAL. Growth reads as zeros and is charged to the compartment's tmpfs quota (ENOSPC); shrinking gives bytes back. Shared mappings follow: pages past the end leave the shared page cache, the cut part of the last page becomes zero. |
| 62 | `kill` | Partial: a thread's TID is ESRCH (Linux signals its process) | none; targets only in the caller's compartment (ESRCH) | ADR 0019, ADR 0020, ADR 0030. Signal 0 checks existence; SIGKILL ends every thread of the process (wait status 9); other signals go to the process (SI_USER, `si_pid` the caller) and are taken by a thread that does not block them; a signal outside 0..64 EINVAL. PID 0 is the caller's process group, -1 every process of the compartment but its PID 1 and the caller, a lower value the group -PID; an empty group ESRCH (INT_MIN ESRCH), while a group of zombies not yet reaped is found and the signal goes nowhere, as `__kill_pgrp_info` (ADR 0032). A child that has ended but is not yet reaped keeps its PID: a signal to it is accepted and goes nowhere (ADR 0038); kill(-1) counts such processes too. |
| 79 | `getcwd` | Complete | none | ADR 0022. The working directory's path from the process root, with its NUL; ERANGE if it does not fit; ENOENT if removed or no longer beneath the root. Returns the length with the NUL. |
| 80 | `chdir` | Complete | none (a path from the process root) | ADR 0022. To a directory (ENOTDIR otherwise). |
| 81 | `fchdir` | Complete | ENUMERATE (after the type check: ENOTDIR first) | ADR 0022. A directory from outside the root makes a working directory from which relative paths name nothing. |
| 82 | `rename` | Complete | as `renameat2` | renameat2(AT_FDCWD, old, AT_FDCWD, new, 0). |
| 83 | `mkdir` | Complete | as `mkdirat` | mkdirat(AT_FDCWD, path, mode). |
| 84 | `rmdir` | Complete | as `unlinkat` | unlinkat(AT_FDCWD, path, AT_REMOVEDIR): "." EINVAL, ".." ENOTEMPTY, "/" EBUSY, not empty ENOTEMPTY, not a directory ENOTDIR. |
| 86 | `link` | Complete | as `linkat` | linkat(AT_FDCWD, old, AT_FDCWD, new, 0): the source is not followed. |
| 87 | `unlink` | Complete | as `unlinkat` | unlinkat(AT_FDCWD, path, 0). A file open or mapped stays until the last description and mapping go (ADR 0022). |
| 88 | `symlink` | Complete | as `symlinkat` | symlinkat(target, AT_FDCWD, path). |
| 89 | `readlink` | Complete | as `readlinkat` | readlinkat(AT_FDCWD, path, buf, size). |
| 90 | `chmod` | Complete | none | fchmodat(AT_FDCWD, path, mode). Stored and reported only (SR-6). |
| 91 | `fchmod` | Complete | STAT | ADR 0022. mode & 07777, stored only; stamps the change time. |
| 95 | `umask` | Complete | none (own process) | ADR 0022. Sets mask & 0777, returns the old one; 022 for a process the kernel starts; kept across fork and execve; applied by open(O_CREAT) and mkdir. |
| 102 | `getuid` | Complete: always 0 | none | ADR 0034. Every Keel process is root in its compartment (ADR 0030). |
| 104 | `getgid` | Complete: always 0 | none | ADR 0034. As getuid. |
| 107 | `geteuid` | Complete: always 0 | none | ADR 0034. As getuid. |
| 108 | `getegid` | Complete: always 0 | none | ADR 0034. As getuid. |
| 109 | `setpgid` | Complete | none (the caller or its children) | ADR 0030. As `kernel/sys.c`: `pid` 0 the caller, `pgid` 0 `pid`, a negative group EINVAL; not the caller or a child of it ESRCH; another thread EINVAL; a child in another session EPERM, one that has called execve EACCES; a session leader EPERM; joining a group needs a member of it in the caller's session (EPERM); an exited member its parent has not reaped counts, and an exited, unreaped child can still be moved, as on Linux (ADR 0032). |
| 110 | `getppid` | Complete | none | The parent's PID in the compartment; 0 if it has none or has gone. |
| 111 | `getpgrp` | Complete | none | ADR 0030. getpgid(0). A process the kernel starts is in group 0. |
| 112 | `setsid` | Complete | none | ADR 0030. EPERM for a session leader or if a group numbered as the caller exists; otherwise a new session and group, both the caller's PID, with no controlling terminal. |
| 118 | `getresuid` | Complete: always 0 | none | ADR 0034. Writes the real, effective and saved IDs (0) in that order; the first that cannot be written is EFAULT (`put_user`). |
| 120 | `getresgid` | Complete: always 0 | none | ADR 0034. As getresuid. |
| 121 | `getpgid` | Complete | none; the PID must be in the caller's compartment (ESRCH) | ADR 0030. The process group of a process or of a thread's process; 0 is the caller. |
| 124 | `getsid` | Complete | none; as `getpgid` | ADR 0030. The session, as `getpgid` finds the process. A process the kernel starts is in session 0. |
| 130 | `rt_sigsuspend` | Complete | none (own thread) | ADR 0033. As `sigsuspend`: a size other than 8 EINVAL, an unreadable mask EFAULT; the mask replaces the blocked one (SIGKILL and SIGSTOP stay unblocked) until a signal it lets through is pending, then ERESTARTNOHAND. A handler runs with the temporary mask and its frame restores the old one (EINTR); with no handler the old mask is put back and the call waits again. |
| 131 | `sigaltstack` | Complete | none (own thread) | Linux's rules: an unknown mode EINVAL; a stack below MINSIGSTKSZ (2048) ENOMEM; a change while the caller's stack pointer is on the alternate stack EPERM (never with SS_AUTODISARM); SS_DISABLE clears pointer and size; an unchanged request succeeds before the size check. The old stack reports SS_DISABLE, SS_ONSTACK or 0, as Linux's `sas_ss_flags`. Per thread; a new thread sharing memory starts without one, as clone(2); handlers with SA_ONSTACK run on it (ADR 0020). |
| 133 | `mknod` | Partial: no device nodes (EPERM) | as `mkdirat`: none from the root; ENUMERATE and CREATE on a directory handle | ADR 0035. As `do_mknodat`: a directory's type EPERM and an unknown type EINVAL first; then the parent's lookup, EEXIST for a name that exists (with a trailing slash EEXIST, or ENOENT if missing); a regular file (type 0, S_IFREG), a FIFO or a socket node, mode less the umask, charged to the quota. Character and block devices EPERM (Keel's compartments have no CAP_MKNOD). |
| 137 | `statfs` | Complete | none (a path from the root) | ADR 0023. tmpfs's answer (`shmem_statfs`): TMPFS_MAGIC, 4096-byte blocks, totals and free counts from the filesystem's caps or the compartment's quota where smaller, NAME_MAX 255, ST_VALID. |
| 138 | `fstatfs` | Complete | none on the handle | ADR 0023. As statfs. |
| 157 | `prctl` | Partial: PR_SET_NAME, PR_GET_NAME | none (own thread) | ADR 0024. PR_SET_NAME takes up to 15 bytes, to a NUL; PR_GET_NAME writes 16, NUL-padded; the name is the thread's `comm`. Other options EINVAL (the default branch; PR_SET_PTRACER is Yama's). |
| 158 | `arch_prctl` | ARCH_SET_FS/GS, ARCH_GET_FS/GS | none (own thread) | Bases must be user addresses (EPERM otherwise), so the MSR write cannot fault and no segment can point into the kernel. The kernel never uses FS or GS (ADR 0005). Other codes EINVAL. |
| 186 | `gettid` | Complete | none | The calling thread's TID (the PID for a process's first thread). |
| 188-199 | `setxattr`, `lsetxattr`, `fsetxattr`, `getxattr`, `lgetxattr`, `fgetxattr`, `listxattr`, `llistxattr`, `flistxattr`, `removexattr`, `lremovexattr`, `fremovexattr` | Checks only: tmpfs keeps no extended attributes | none | ADR 0023. EOPNOTSUPP, as a filesystem without xattr support, after Linux's checks in its order (`fs/xattr.c`): get and list check the path or descriptor first, then get the name; set its flags (EINVAL), the name, the size (E2BIG past 64 KiB), then the path; remove the name, then the path. An empty name or one past 255 bytes ERANGE. |
| 200 | `tkill` | Complete | none; the TID must be in the caller's compartment (ESRCH) | ADR 0020. As tgkill without the process check. A TID that is an unreaped zombie's PID is accepted, as for kill (ADR 0038). |
| 202 | `futex` | Partial: WAIT, WAKE, REQUEUE, CMP_REQUEUE (private and shared alike) | none (own memory) | ADR 0019. Misaligned EINVAL; mismatch EAGAIN, checked under the wake lock; relative timeout ETIMEDOUT, bad timespec EINVAL; requeue counts negative EINVAL, CMP mismatch EAGAIN; other commands and FUTEX_CLOCK_REALTIME ENOSYS. Keys are (address space, address). A signal for the thread cuts a wait short with EINTR (no SA_RESTART yet; ADR 0020). |
| 213 | `epoll_create` | Complete | none (makes a handle: READ, WRITE, STAT, DUPLICATE) | ADR 0026. A size of 0 or less EINVAL; otherwise epoll_create1(0). |
| 217 | `getdents64` | Complete | ENUMERATE (after the type check: ENOTDIR first) | ADR 0022. `struct linux_dirent64` records: ".", "..", then the names in byte order, d_type as Linux (DT_DIR, DT_REG, DT_LNK, DT_CHR), d_ino as stat's st_ino, d_off the next index. EINVAL if not even one record fits; ENOENT for a removed directory. Resumes by index, so a directory changed between calls can skip or repeat a name. A procfs directory lists as procfs does (ADR 0037; see procfs below). |
| 218 | `set_tid_address` | Complete | none | Sets the calling thread's clear_child_tid and returns its TID. At thread exit, if other threads share the memory, 0 is written there and one futex waiter woken (Linux's mm_release). |
| 219 | `restart_syscall` | Complete for the sleeps | none (own thread) | ADR 0033. Resumes the thread's interrupted relative sleep (its deadline and `rem`); with none, EINTR (`do_no_restart_syscall`). The return to user mode substitutes it for a call that returned ERESTART_RESTARTBLOCK when no handler runs. |
| 228 | `clock_gettime` | MONOTONIC, MONOTONIC_RAW, MONOTONIC_COARSE, BOOTTIME, REALTIME, REALTIME_COARSE | none | No real-time clock yet: the REALTIME clocks count from boot as if boot were 1970-01-01. CPU-time and other clocks EINVAL. |
| 230 | `clock_nanosleep` | REALTIME, MONOTONIC, BOOTTIME, TAI | none (own thread) | ADR 0033. MONOTONIC_RAW and the COARSE clocks EOPNOTSUPP (no `nsleep`), before the request is read; the alarm clocks EOPNOTSUPP after it (no real-time clock device); the CPU-time clocks and unknown numbers EINVAL (Linux sleeps on a process's CPU time). Then as nanosleep. TIMER_ABSTIME (other flags ignored): until that time on the clock, `rem` never written, and a signal gives ERESTARTNOHAND, so the same deadline is kept after a stop. The realtime and TAI clocks are the monotonic one, as in clock_gettime. |
| 231 | `exit_group` | Partial: same as `exit` until processes have several threads | none | |
| 232 | `epoll_wait` | Complete | none on the epoll handle; readiness reported only for the rights of the handle an item was added through | ADR 0026. maxevents at or below 0 or above 178956970 EINVAL; the array checked as `access_ok` (EFAULT past the user half; NULL fine until an event is written); not epoll EINVAL. Ready items sent (level-triggered ones requeued at the end, edge-triggered ones until their next matching wake, EPOLLONESHOT disabled); then 0 at a zero or passed timeout; then EINTR for an unblocked pending signal (never restarted, as Linux); else a wait. |
| 233 | `epoll_ctl` | Complete except nesting | none | ADR 0026. Linux's order: the event read unless DEL (EFAULT); EBADF; EPERM for a target with no poll method (regular files, directories, `/dev/null`, `/dev/zero`, `/dev/urandom`); EINVAL for a non-epoll epfd or itself; the EPOLLEXCLUSIVE rules; EEXIST, ENOENT; unknown op EINVAL. ADD and MOD add EPOLLERR and EPOLLHUP. Items live as long as their open file. Adding an epoll instance is EINVAL (Linux nests). |
| 234 | `tgkill` | Complete | none; the TID must be in the caller's compartment (ESRCH) | ADR 0020. A TID or TGID not above 0, or a signal outside 0..64, EINVAL; the thread must belong to process TGID (ESRCH). The signal goes to that thread alone (SI_TKILL); SIGKILL still ends the whole process. A TID that is an unreaped zombie's PID is accepted, as for kill (ADR 0038). |
| 257 | `openat` | Files, directories, devices and FIFOs in the tmpfs | ENUMERATE on `dirfd` when it is not AT_FDCWD; also CREATE with O_CREAT | Lookups never leave the process root, which is its compartment's root (SR-4, ADR 0014): absolute paths and AT_FDCWD start there and `..` stops there. A relative path through a directory handle is confined to that directory: `..` stops there, as with Linux's `openat2` RESOLVE_IN_ROOT, unlike plain Linux `openat` (ADR 0012). Directory handles get CREATE by default. Flags outside the supported set (O_DSYNC, O_SYNC, O_DIRECT, O_NOATIME, O_PATH, O_TMPFILE and unknown bits) are EINVAL (SR-10; Linux ignores unknown bits). O_CREAT applies umask 022; ENOSPC once the tmpfs holds 65536 nodes (F-0011) or the caller's compartment has used its node quota (ADR 0014); O_TRUNC gives the owner its bytes back. No permission checks by mode or user ID (SR-6). Rights granted: READ/WRITE by access mode, plus STAT, SEEK, DUPLICATE; ENUMERATE for directories; MAP_EXEC with READ on regular files (Linux compatibility; compartment manifests can withhold it from Phase 3). A FIFO opens as a pipe end on its node's pipe, as `fifo_open` (ADR 0035): O_RDONLY waits for a writer and O_WRONLY for a reader unless O_NONBLOCK (then a writer with no reader is ENXIO); O_RDWR never waits; an interrupted wait is ERESTARTSYS. |
| 258 | `mkdirat` | Complete | none from the root; ENUMERATE and CREATE on a directory handle | ADR 0022. "/", ".", ".." or an existing name EEXIST; trailing slash allowed; mode & 01777 & ~umask; one node charged to the compartment quota (ENOSPC). |
| 259 | `mknodat` | As mknod | As mknod | ADR 0035. mknod relative to a directory descriptor. |
| 262 | `newfstatat` | Complete | none from the root; ENUMERATE on a directory handle; STAT for AT_EMPTY_PATH on a descriptor | ADR 0022. Flags AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT, AT_EMPTY_PATH; others EINVAL; an empty path without AT_EMPTY_PATH ENOENT. |
| 263 | `unlinkat` | Complete | none from the root; ENUMERATE and CREATE on a directory handle | ADR 0022. Flags other than AT_REMOVEDIR EINVAL. unlink: not a plain name EISDIR, a directory EISDIR, a trailing slash ENOENT/EISDIR/ENOTDIR as `do_unlinkat`. Each name gives back its quota node; the node goes when nothing names or holds it. |
| 264 | `renameat` | Complete | as `renameat2` | renameat2(..., 0). |
| 265 | `linkat` | Complete | ENUMERATE on a source handle; ENUMERATE and CREATE on a target directory handle | ADR 0022. Flags AT_SYMLINK_FOLLOW and AT_EMPTY_PATH, others EINVAL. A directory EPERM; an existing name EEXIST; a file with no names left ENOENT; each name one quota node (ENOSPC), as tmpfs. |
| 266 | `symlinkat` | Complete | none from the root; ENUMERATE and CREATE on a directory handle | ADR 0022. The target is stored as given: empty ENOENT, 4096 bytes or more ENAMETOOLONG; an existing name EEXIST; a trailing slash ENOENT; mode 0777; one quota node. Followed in lookups, 40 per lookup (ELOOP), an absolute target from the lookup's root. |
| 267 | `readlinkat` | Complete | none from the root; ENUMERATE on a directory handle | ADR 0022. size not above 0 EINVAL; not a link EINVAL; at most size bytes, no NUL. |
| 268 | `fchmodat` | Complete | none from the root; ENUMERATE on a directory handle | ADR 0022. Follows links; mode & 07777, stored only. |
| 269 | `faccessat` | Complete | as `faccessat2` | faccessat2(dirfd, path, mode, 0). |
| 270 | `pselect6` | Complete | as `poll` | ADR 0025. select with a timespec (negative or tv_nsec out of range EINVAL) and a mask from the argpack (pointer and size; size other than 8 EINVAL), blocked for the call and put back at once unless the call was interrupted (then saved in a handler's frame, or restored on the way out). |
| 271 | `ppoll` | Complete | as `poll` | ADR 0025. poll with a timespec (written back) and a temporary mask, as pselect6. |
| 280 | `utimensat` | Complete | none from the root; ENUMERATE on a directory handle; STAT on a descriptor with a NULL path | ADR 0022. As `fs/utimes.c`: NULL times both now; both UTIME_OMIT does nothing (and looks up nothing); a bad nanosecond EINVAL; a NULL path with a descriptor that file (flags 0, else EINVAL); flags AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH. The change time becomes now. |
| 281 | `epoll_pwait` | Complete | as `epoll_wait` | ADR 0026. epoll_wait with a temporary mask (size other than 8 EINVAL), put back at once unless the call was interrupted. |
| 284 | `eventfd` | Complete | none (makes a handle: READ, WRITE, STAT, DUPLICATE) | ADR 0025. eventfd2 with no flags. |
| 290 | `eventfd2` | Complete | as `eventfd` | ADR 0025. EFD_SEMAPHORE, EFD_CLOEXEC, EFD_NONBLOCK (others EINVAL). Reads take the counter (or 1) as 8 bytes, fewer EINVAL; writes add 8 bytes, never u64::MAX; the sum stays below u64::MAX (else a wait or EAGAIN). fstat: the anonymous inode, mode 0600; lseek 0; pread ESPIPE. |
| 291 | `epoll_create1` | Complete | as `epoll_create` | ADR 0026. EPOLL_CLOEXEC only (else EINVAL). An anonymous inode, mode 0600; lseek 0; read and write EINVAL; poll reports POLLIN while an item is ready. |
| 288 | `accept4` | Complete | none | ADR 0027. EBADF, then flags other than SOCK_CLOEXEC/SOCK_NONBLOCK EINVAL, then ENOTSOCK; not stream EOPNOTSUPP; not listening EINVAL; EAGAIN or a wait (SO_RCVTIMEO); inherits SO_PASSCRED; a fault writing the address closes the new socket (EFAULT). |
| 292 | `dup3` | Complete | DUPLICATE | ADR 0023. Flags other than O_CLOEXEC, or oldfd == newfd, EINVAL (checked first); otherwise as dup2, with O_CLOEXEC setting close-on-exec. |
| 293 | `pipe2` | Partial: no O_DIRECT, no O_NOTIFICATION_PIPE | as `pipe` | ADR 0025. O_CLOEXEC and O_NONBLOCK (others EINVAL); EFAULT closes both again. 64 KiB capacity; PIPE_BUF 4096 atomic; end of file with no writer; EPIPE and SIGPIPE with no reader; FIONREAD; fstat a FIFO 0600; lseek and pread ESPIPE; mmap ENODEV. |
| 295 | `preadv` | Complete | READ | ADR 0023. readv at an offset: negative EINVAL, a terminal ESPIPE; the position stays. |
| 296 | `pwritev` | Complete | WRITE | ADR 0023. As pwrite64 with vectors. |
| 316 | `renameat2` | Complete | none from the root; ENUMERATE and CREATE on directory handles | ADR 0022. RENAME_NOREPLACE, RENAME_EXCHANGE (RENAME_WHITEOUT and combinations EINVAL); not a plain name EBUSY (EEXIST with NOREPLACE); a trailing slash with a non-directory source ENOTDIR; into itself EINVAL; replacing: dir by non-dir EISDIR, the reverse ENOTDIR, non-empty ENOTEMPTY; the same node: nothing. |
| 318 | `getrandom` | Complete | none | Unknown flags, and GRND_RANDOM with GRND_INSECURE, are EINVAL, as Linux. Bytes come from the kernel generator (`hal::random`: BLAKE2s pool, ChaCha20 with fast key erasure, seeded from RDSEED/RDRAND and timing, reseeded every 60 s). GRND_NONBLOCK never matters: the generator is seeded before the first process starts. |
| 319 | `memfd_create` | Partial: no sealing, no huge pages | none (makes a handle as a file opened O_RDWR) | ADR 0025. A tmpfs file in no directory, mode 0777, no links, O_RDWR with O_LARGEFILE, pinned by its descriptors and mappings, charged to the caller's compartment. MFD_CLOEXEC and MFD_EXEC; anything else EINVAL; a name past 249 bytes EINVAL. |
| 327 | `preadv2` | Complete | READ | ADR 0023. preadv, offset -1 meaning the file position; RWF flags as pwritev2 (RWF_APPEND and RWF_NOAPPEND change nothing for a read). |
| 328 | `pwritev2` | Complete | WRITE | ADR 0023. pwritev, offset -1 meaning the position. RWF flags (`kiocb_set_rw_flags`): unknown EOPNOTSUPP, RWF_APPEND with RWF_NOAPPEND EINVAL, RWF_ATOMIC EOPNOTSUPP; RWF_APPEND appends, RWF_NOAPPEND writes at the offset despite O_APPEND; HIPRI, DSYNC, SYNC, NOWAIT change nothing (no device; files never block). |
| 439 | `faccessat2` | Complete | none from the root; ENUMERATE on a directory handle | ADR 0022. Flags AT_EACCESS, AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH; others EINVAL. See `access`. |
| 441 | `epoll_pwait2` | Complete | as `epoll_wait` | ADR 0026. A timespec timeout (NULL none; invalid EINVAL; not written back), read before the mask; then as epoll_pwait. |

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
| `/dev/console` | 5:1 | A terminal (ADR 0029): input from the keyboard and COM1, by interrupt, through the N_TTY line discipline (a serial console's settings, changeable with TCSETS). Output goes to COM1 and the screen, filtered to text (no control characters but tab, newline, CR and backspace, so no escape sequences). Every process shares the one console until compartments give each its own. | `fs.dev_nodes`, `fs.devices`, `console.keyboard_line`, `console.serial_line` |
| `/dev/tty` | 5:0 | The opener's controlling terminal (ENXIO without one; ADR 0030). | `exec.job_control` |
| `/dev/ptmx` | 5:2 | Opening it makes a pty pair and its slave node (ADR 0029); at most 64 at once (ENOSPC). | `exec.terminals` |
| `/dev/pts/N` | 136+N/256 : N%256 | A pty slave, mode 0600, there while its master is open, in the `/dev/pts` of the tree of the process that opened `/dev/ptmx` (each compartment its own, ADR 0039); locked until TIOCSPTLCK unlocks it (EIO). | `exec.terminals` |
| `/dev/null` | 1:3 | Reads return end of file; writes are discarded. No authority. | `fs.dev_nodes`, `fs.devices` |
| `/dev/zero` | 1:5 | Reads return zeros; writes are discarded. No authority. | `fs.dev_nodes`, `fs.devices` |
| `/dev/urandom` | 1:9 | Reads return bytes from the kernel generator (as getrandom); writes are discarded (they are not mixed in, so no process can influence the pool). No authority. | `fs.dev_nodes`, `fs.devices` |

`/dev/mem`, `/dev/kmem` and `/dev/port` do not exist and cannot be
created: device nodes come only from a fixed list in the kernel (SR-9;
test `fs.no_forbidden_devices`).

## Faults

A fault in user mode (any exception vector below 32 except NMI and
machine check) raises the signal Linux raises for it (ADR 0020;
`arch/x86/kernel/traps.c` and `arch/x86/mm/fault.c` at v6.12): SIGSEGV
for #PF (SEGV_MAPERR or SEGV_ACCERR, `si_addr` the address), #GP, #TS,
#OF and #BR; SIGBUS for #NP, #SS and #AC; SIGILL for #UD (ILL_ILLOPN);
SIGFPE for #DE (FPE_INTDIV) and #MF/#XM (the code from the unmasked
flags); SIGTRAP for #DB and #BP. A handler that is installed and not
blocked runs with the fault in its frame (`trapno`, `err`, `cr2`);
otherwise the process ends with that signal (wait status the signal;
thread exit status 128 + the signal).

## procfs

ADRs 0024 and 0037. Paths under `/proc` (absolute, after lexical
`.`/`..`, or relative to a procfs directory's descriptor) are procfs's,
over whatever the process tree holds there, and show only the caller's
compartment's processes, running and zombies:

| Path | Kind | Contents |
| --- | --- | --- |
| `/proc` | directory 0555 | |
| `/proc/self`, `/proc/thread-self` | links | the PID; `<pid>/task/<tid>` |
| `/proc/<pid>`, `/proc/<pid>/task`, `/proc/<pid>/task/<tid>` | directories 0555 | |
| `/proc/<pid>/exe` (also under a task) | link | the program's path; followed by stat and open |
| `/proc/<pid>/comm`, `/proc/<pid>/task/<tid>/comm` | file 0644 | the thread's name and a newline; a write renames a thread of the caller's process |
| `/proc/<pid>/cmdline` | file 0444 | the argv exec gave, each string with its NUL; empty for a zombie |
| `/proc/<pid>/stat` | file 0444 | `do_task_stat`'s 52 fields; what Keel does not keep is 0 (ADR 0037) |
| `/proc/cpuinfo` | file 0444 | Linux's x86 format from CPUID (without microcode, cache size, synthesized flags and bugs) |
| `/proc/net`, `/proc/net/dev` | directory; file 0444 | the header lines (no interfaces yet) |

Files open as snapshots taken at the open. Directories open read-only
to be listed (O_DIRECTORY on a file ENOTDIR; writing or O_CREAT EISDIR),
in Linux's order and positions: `/proc`'s PIDs at PID + 258 after
`self` and `thread-self` at 256 and 257. They cannot be a working
directory (fchdir EACCES). statfs reports PROC_SUPER_MAGIC.

