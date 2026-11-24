# ADR 0025: Pipes, eventfd, memfd and one readiness mechanism

Status: accepted (Phase 3, P3-T10 part 1; epoll is part 2).

## Context

The spec's P3-T10 asks for "pipes, `eventfd`, `memfd`, `poll`/`epoll`
over a common readiness-notification mechanism". The Wine traces
(`docs/syscall-inventory.md`) show what Wine uses:

| Call | Calls | How |
| --- | --- | --- |
| `pipe2` | 166 | always with O_CLOEXEC |
| `pipe` | 17 | |
| `poll` | 1 | one descriptor, a 1 ms timeout |
| `select` | 69 | `select(0, NULL, NULL, NULL, &tv)` as a sleep |
| `epoll_pwait` | 21615 | 128 events, a 16 ms timeout, no mask (part 2) |
| `epoll_ctl` | 155 | ADD with EPOLLIN, one MOD, one ADD with EPOLLOUT (part 2) |

`eventfd` and `memfd_create` do not appear in the traces; the spec asks
for them, and Wine's server and graphics drivers use them on other paths.
Until now `poll` re-checked every 10 ms, and a signal did not end its
wait.

## Decision

1. **One readiness queue.** Everything whose readiness can change calls
   `ready::changed()`, which wakes every thread waiting in `ready::wait`:
   - a pipe read, written, or closed at either end;
   - an eventfd read or written;
   - a console line typed (`tty`, from the keyboard interrupt);
   - F_SETFL on a pipe or eventfd (O_NONBLOCK changes what a waiter does).

   A waiter's condition is checked under the queue's lock before it
   sleeps, so a change between its check and its sleep is not missed. On
   a wake it checks again and sleeps again if still not ready, up to its
   deadline. One queue for everything cannot miss a wake; its cost is
   that each change wakes every waiter, which is cheap with one CPU and
   few waiters. Per-object queues can replace it without changing callers.
   - **The timed wait** is new in the hardware layer:
     `WaitQueue::wait_until_deadline` sleeps until a wake, a signal or
     the deadline (`Waited::Ready`, `Interrupted` or `TimedOut`), and
     leaves the queue whichever ends it. `wake_all` now wakes sleeping
     threads as well as blocked ones.
2. **Pipes** (`fs/pipe.c`; the data part in `keel_core::pipe`):
   - **pipe2** takes O_CLOEXEC and O_NONBLOCK; any other flag is EINVAL.
     That includes O_DIRECT (packet mode) and O_NOTIFICATION_PIPE, which
     Linux accepts: not supported. The read end has READ, STAT and
     DUPLICATE rights; the write end WRITE, STAT and DUPLICATE. An
     unwritable array closes both again and is EFAULT. `pipe` is pipe2
     with no flags.
   - **Capacity** is 65536 bytes (16 pages, `PIPE_DEF_BUFFERS`). A write
     of at most PIPE_BUF (4096) bytes goes in whole or waits; a longer one
     goes in parts as room appears.
   - **Reading** returns what is there, up to the count; with no writer
     left, 0 (end of file). Empty with a writer left: EAGAIN with
     O_NONBLOCK, else it waits. A read whose copy out faults is EFAULT
     and leaves the bytes in the pipe.
   - **Writing** with no reader left sends SIGPIPE to the writing thread
     (SI_USER, as `send_sig`) and is EPIPE. Without room: EAGAIN with
     O_NONBLOCK if nothing was written, else the count so far. A zero
     write is 0, reader or not.
   - **readv and writev** are one read or one write, as Linux's iov_iter
     calls: a writev of at most PIPE_BUF is atomic.
   - **poll:** the read end is readable (POLLIN, POLLRDNORM) with data
     and hung up (POLLHUP) with no writer; the write end is writable
     (POLLOUT, POLLWRNORM) when not full and in error (POLLERR) with no
     reader (`pipe_poll`).
   - **Other calls:** fstat is a FIFO, mode 0600 (`get_pipe_inode`),
     size 0, one inode for both ends, on its own device (0:3); fstatfs
     is PIPEFS_MAGIC. lseek, pread and preadv are ESPIPE (`stream_open`);
     mmap is ENODEV; FIONREAD gives the bytes waiting; other ioctls are
     ENOTTY. F_GETFL is O_RDONLY or O_WRONLY with O_NONBLOCK; F_SETFL
     changes O_NONBLOCK. A pipe used as a directory (openat's dirfd,
     getdents64, fchdir) is ENOTDIR; fstatat with AT_EMPTY_PATH stats it.
3. **eventfd** (`fs/eventfd.c`):
   - **eventfd2** takes EFD_SEMAPHORE, EFD_CLOEXEC and EFD_NONBLOCK;
     other flags are EINVAL. `eventfd` is eventfd2 with no flags.
   - **Read:** fewer than 8 bytes EINVAL; the counter (or 1 with
     EFD_SEMAPHORE) as 8 bytes, taken off it; at 0, EAGAIN or wait.
   - **Write:** other than 8 bytes EINVAL; u64::MAX EINVAL; a sum that
     would reach u64::MAX waits or is EAGAIN.
   - **poll:** POLLIN above 0, POLLOUT below u64::MAX - 1, POLLERR at
     u64::MAX (`eventfd_poll`).
   - **Other calls:** fstat is the anonymous inode, mode 0600 with no file
     type, one inode for all eventfds (as Linux's `anon_inode_inode`);
     fstatfs ANON_INODE_FS_MAGIC; lseek is 0 (`noop_llseek`); pread is
     ESPIPE (no FMODE_PREAD).
4. **memfd_create** (`mm/memfd.c`) makes a tmpfs file in no directory
   (`Fs::create_detached`, ADR 0024): mode 0777, no links, open O_RDWR
   with O_LARGEFILE. It lives while a descriptor or a mapping pins it, and
   reads, writes, grows, shrinks and maps as any tmpfs file, charged to
   the caller's compartment.
   - **Flags:** MFD_CLOEXEC and MFD_EXEC. Sealing (MFD_ALLOW_SEALING,
     MFD_NOEXEC_SEAL) and huge pages (MFD_HUGETLB) are EINVAL: not
     supported. MFD_EXEC with MFD_NOEXEC_SEAL is EINVAL on Linux too.
   - **The name** may be at most 249 bytes (NAME_MAX less "memfd:"),
     else EINVAL; an unreadable one EFAULT.
5. **poll, ppoll, select and pselect6** (`fs/select.c`) share one wait:
   - **The scan.** Every descriptor is scanned. If one is ready, the call
     returns. Otherwise, a signal pending that the thread does not block
     ends the call with EINTR, even with a zero timeout (Linux's
     ERESTARTNOHAND). At the deadline the call returns 0. Otherwise it
     waits for a readiness change and scans again.
   - **Readiness by rights.** What is reported is still limited by the
     handle's rights (SR-1, ADR 0008): POLLIN only with READ, POLLOUT
     only with WRITE.
   - **ppoll and pselect6** take a timespec: tv_sec below 0 or tv_nsec
     outside 0..10^9 is EINVAL. **select** takes a timeval, whose
     microseconds of a second or more carry into the seconds; a negative
     time is EINVAL (`kern_select`).
   - **The time left** is written back, to 0 if none, unless the timeout
     was zero. A failed write is ignored (`poll_select_finish`).
   - **select:**
     - n below 0 is EINVAL. n is clamped to the size Linux's descriptor
       table would have (64, or as `alloc_fdtable` grows it for the
       highest open descriptor), so bits past it are ignored.
     - A descriptor set in any set that is not open is EBADF
       (`max_select_fd`).
     - Each set's bits count separately: readable by POLLIN_SET, writable
       by POLLOUT_SET, exceptional by POLLEX_SET.
     - The sets are written back unless the call was interrupted.
6. **Temporary signal masks** (ppoll, pselect6; `set_user_sigmask`): a
   mask (its size must be 8, else EINVAL) is blocked for the call, and
   the mask it replaced is kept in the thread's signal state:
   - if a handler runs on the way out, its frame saves the kept mask
     (`sigmask_to_save`), so sigreturn restores it;
   - otherwise the way back to user mode restores it
     (`restore_saved_sigmask`).

   pselect6 reads its mask and size from the "argpack" its sixth argument
   points at.
7. **Descriptors that are not files.** `Object` gains `Pipe` and
   `EventFd`. The calls that need a file answer for them as Linux does:
   - ENOTDIR where a directory is wanted, checked before the handle's
     rights;
   - ESPIPE for seeking and positional I/O;
   - ENODEV for mmap;
   - EINVAL for the rest (ftruncate, the record locks, fsync and the like).
   Closing one releases no record locks (it has none).
8. **Zero-length user copies** succeed for any address in the user half,
   mapped or not, as Linux's `access_ok(ptr, 0)` checks only that the
   address is a user one. So `poll(NULL, 0, ms)`, which C programs use as
   a sleep, is not EFAULT.

## Not yet covered

- **epoll:** part 2 of P3-T10.
- **Restarting interrupted calls.** As ADR 0020, an interrupted wait
  returns EINTR. Linux restarts poll, select and the blocking pipe and
  eventfd reads and writes when no handler runs (for an ignored signal,
  or a stop and continue), and pipe reads and writes for a handler with
  SA_RESTART.
- **Pipe capacity by buffers.** Linux counts 16 page buffers, so a pipe
  filled by small writes can be full with fewer bytes, and space freed
  inside a buffer is not reused until it empties. Keel counts bytes: a
  long write into a pipe with room left in a partly read buffer takes
  that room, where Linux would wait or be EAGAIN. F_SETPIPE_SZ and
  F_GETPIPE_SZ are not supported (EINVAL).
- **Named pipes** (mkfifo, mknod) and pipe O_DIRECT (packet mode).
- **Pipe and eventfd times.** stat reports the current time for all
  three; Linux keeps the pipe's creation and last read and write times,
  and the boot time for the anonymous inode. Pipes are owned by uid 0.
- **memfd:** sealing (F_ADD_SEALS, F_GET_SEALS, MFD_ALLOW_SEALING,
  MFD_NOEXEC_SEAL), huge pages, and the `memfd:` name in `/proc/self/fd`
  (which Keel does not have).
- **select's table size** follows the highest descriptor open now; Linux's
  table never shrinks, so Linux keeps the size for the highest ever open.
- **Record locks on pipes** are EINVAL; Linux allows them (on the pipe's
  inode).

## Evidence

- **Host tests** (`keel_core::pipe`):
  - reads, writes, end of file, broken pipes and poll masks;
  - bytes put back after a faulting copy;
  - small writes atomic, long ones and their tails filling;
  - the eventfd counter: read, the semaphore, the u64::MAX - 1 limit,
    poll.
- **`exec.pipes` (phase 3) and `host.pipeprobe`:** `user/tests/pipeprobe`
  makes 83 checks, which pass under Linux and on Keel. Afterwards every
  node, frame and process is back.
  - **Pipes:**
    - pipe2's flags, close-on-exec, access modes, EINVAL and EFAULT;
    - order and FIONREAD;
    - stat, fstatfs, ESPIPE, ENODEV, and each end's direction;
    - non-blocking EAGAIN and poll;
    - the 64 KiB capacity, a page read making room for a page, and an
      atomic 200-byte write refused;
    - a faulting read keeping its bytes;
    - writev as one write, readv not waiting to fill;
    - end of file with POLLHUP;
    - EPIPE with SIGPIPE ignored (and POLLERR), death by SIGPIPE
      otherwise;
    - a blocking read and a poll woken by a child's write while the child
      still runs.
  - **The waits:**
    - select's per-set counts, timeout write-back, EINVAL, EBADF, and the
      table-size clamp;
    - pselect6 and ppoll with timeouts written back, and their EINVALs;
    - a temporary mask restored after a timeout;
    - a pending signal let in by the mask ending the process (ppoll and
      pselect6);
    - one the mask keeps blocked not interrupting;
    - a handler that runs during the call: EINTR, and the mask from
      before the call back after sigreturn (ppoll and pselect6).
  - **eventfd:** read and write sizes, EAGAIN, u64::MAX, the limit at
    u64::MAX - 1, poll, stat, lseek, pread, fstatfs, EFD_SEMAPHORE,
    unknown flags, and a blocking read woken by a child.
  - **memfd:** close-on-exec, F_GETFL, mode, links, size; read, write and
    ftruncate; unknown flags, MFD_EXEC with MFD_NOEXEC_SEAL, and the
    name limit.
- **The handler** is keel-rt's new `signal::catch`: an atomic counter, and
  a restorer that makes rt_sigreturn as glibc's `__restore_rt` does.
- **Mutations** on Keel, 28, each caught by `pipeprobe` (the check that
  failed in brackets):
  - **Pipes:**
    - SIGPIPE not sent (30); small writes not atomic (92);
    - no end of file (25); no POLLHUP (25); no POLLERR (28);
    - faulting reads losing their bytes (94);
    - EPIPE as EAGAIN (27); pipe2's O_CLOEXEC ignored (2);
    - not a FIFO (10); FIONREAD missing (7); mmap EINVAL (12);
    - no wake on a pipe write (32).
  - **eventfd:**
    - short reads accepted (61); EFD_SEMAPHORE ignored (68);
    - u64::MAX accepted (63); lseek ESPIPE (67);
    - no wake on an eventfd write (the probe never finishes).
  - **memfd:** the name unlimited (86); the flags unchecked (85).
  - **The waits:**
    - select counting once per descriptor (41); no EBADF (44);
      clamped to the handle limit (95);
    - the time left not written back (42);
    - no check for a pending signal (the probe never finishes).
  - **Masks:**
    - the temporary mask ignored (52);
    - the frame saving the call's mask (98);
    - the mask not restored (51).
  - **Zero-length copies faulting:** the probe never finishes.

## Consequences

- poll and select wake at once on a change instead of within 10 ms, and a
  signal ends their wait.
- Wine's server pipes and its select-as-sleep run as on Linux.
- epoll (part 2) can use the same queue and the same per-object poll
  masks.
