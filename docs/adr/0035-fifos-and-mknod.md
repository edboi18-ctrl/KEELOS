# ADR 0035: FIFOs and mknod

Status: accepted (Phase 3, after P3-T13).

## Context

BusyBox's test suite (ADR 0034) found three tests Keel failed for want
of named pipes: `mkfifo` is mknod(2) with S_IFIFO, and mknod was ENOSYS.
Shells, build tools and daemons use FIFOs; Wine's `wineserver` talks
over sockets, but a Linux personality without FIFOs is incomplete.

The rules are Linux v6.12's:
- `fs/namei.c`: `may_mknod`, `do_mknodat`, `filename_create`,
  `vfs_mknod` (CAP_MKNOD for devices);
- `fs/pipe.c`: `fifo_open`, `wait_for_partner`, `wake_up_partner`,
  `pipe_poll` (by the file's mode; POLLHUP held back by `f_pipe`),
  `put_pipe_info`.

## Decision

1. **mknod (133) and mknodat (259)**, in `do_mknodat`'s order:
   - **`may_mknod`:** a directory's type EPERM, an unknown type EINVAL,
     before the path is looked at;
   - **`filename_create`:** the parent's lookup errors; a name that
     exists EEXIST; with a trailing slash, EEXIST if the name exists,
     ENOENT if not;
   - **the node:** a regular file (type 0 or S_IFREG), a FIFO, or a
     socket node, which no socket is bound to. The mode is the request
     less the umask, and the node is charged to the compartment's quota.
   - **Devices:** a character or block device is EPERM, after EEXIST. It
     needs CAP_MKNOD (`vfs_mknod`), which Keel's compartments do not
     have: their /dev is the kernel's. This is a deviation from Linux
     run as root.
2. **A FIFO is a tmpfs node** (`Kind::Fifo`). stat reports S_IFIFO and
   size 0, and getdents DT_FIFO. Opening one makes a pipe end on the
   node's pipe (`fifo_open`):
   - **The pipe:** one per node while any open file description has it
     (`inode->i_pipe`), made with no reader and no writer. Its data goes
     with the last description (`put_pipe_info`), as Linux's. The open
     end keeps the node, so a FIFO unlinked while open goes on working.
   - **O_RDONLY:** a reader. With no writer, O_NONBLOCK opens at once,
     and POLLHUP is not reported until a writer has opened (Linux's
     `f_pipe` against `w_counter`). Otherwise it waits for a writer's
     open.
   - **O_WRONLY:** a writer. With no reader, O_NONBLOCK is ENXIO, and
     otherwise it waits for a reader's open.
   - **O_RDWR:** both, and never waits.
   - **Interruption:** a wait a signal interrupts is ERESTARTSYS (ADR
     0031), with this open's count taken back.
   - **Each open** wakes those waiting on the other side.
3. **An open FIFO is a pipe end** (ADR 0025's), with these differences:
   - **Both directions:** an end opened O_RDWR reads and writes.
     `pipe_poll` gives the reader's events and the writer's. epoll
     listens to both queues, through the two queues' wake counts added
     together (`Wakes::merged`).
   - **stat and statfs** report the node on tmpfs, not pipefs.
   - **Not seekable:** lseek is ESPIPE, as for any pipe.

## Not yet covered

- Device nodes (CAP_MKNOD), as above.
- F_SETPIPE_SZ and F_GETPIPE_SZ, and O_DIRECT packet pipes (ADR 0025).

## Evidence

- **`exec.fifos` (phase 3) and `host.fifoprobe`.** `user/tests/fifoprobe`
  makes 16 checks, which pass under Linux (as root and as an
  unprivileged user with umask 077, six runs) and on Keel. Keel runs it
  twice and measures the second run: every node, frame and process is
  back. The checks:
  - **mknod:** a FIFO's mode after the umask; EPERM, EINVAL, EEXIST and
    both trailing-slash results in order; regular files from S_IFREG
    and type 0, mknodat with a directory descriptor; a socket node that
    open(2) cannot open (ENXIO).
  - **Opens:**
    - a nonblocking reader opening at once and reading end of file;
    - no POLLHUP before a writer, POLLHUP and end of file after it went;
    - a nonblocking writer's ENXIO with no reader;
    - blocking readers and writers waiting for each other;
    - O_RDWR not waiting;
    - an interrupted open (EINTR) taking its reader back: with the pipe
      held open by another reader and then a writer, closing that reader
      leaves none, so the writer's write is EPIPE.
  - **Data:** through the FIFO, and gone once every open was closed.
  - **The end:** fstat giving the node; lseek ESPIPE; edge-triggered
    epoll on an O_RDWR end becoming ready when another descriptor
    writes; an unlinked FIFO still working.
- **`busybox.testsuite`:** the three diff tests with FIFOs now pass and
  are in `keel-expected.txt` (894 tests then).
- **Mutations** on Keel, 12, all caught (the fifoprobe check that failed
  in brackets):
  - **Opens:** a blocking reader not waiting (9), or a writer (9); a
    nonblocking writer without ENXIO (waits for ever: `exec.fifos`
    times out); POLLHUP not held back (4); a new pipe for each open (5);
    an interrupted open keeping its reader (15). This one at first
    survived: with nothing else holding the pipe it went with the open,
    so the check was rewritten to keep the pipe alive.
  - **The end:** fstat reporting pipefs (6); epoll on an O_RDWR end
    hearing only its writers' queue (13).
  - **mknod:** a directory's type allowed (2); an existing name not
    checked before the trailing slash (2); the umask ignored (1); a
    socket node made a regular file (3).

## Consequences

- Programs that make and use named pipes work, with Linux's open
  rules, including the ones that block.
- Pipe ends can now be both directions at once. Any later object built
  on `PipeEnd` must look at `read` and `write`, not one flag.
