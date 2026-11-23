# ADR 0023: Descriptor calls, record locks and extended attributes

Status: accepted (Phase 3, P3-T8 second part). Extends ADR 0022.

## Context

These are the descriptor-level calls in the Wine traces
(`docs/syscall-inventory.md` and the prefix creation trace with it):

| Call | Prefix creation | `wine cmd /c echo hello` |
| --- | --- | --- |
| `fcntl` | 16,356 | 1,497 |
| `dup` | 673 | 401 |
| `dup2` | 38 | 22 |
| `fstatfs` | 6,091 | 242 |
| `getxattr` | 3,018 | 276 |
| `fgetxattr` | 5,072 | 8 |
| `readv` | — | 36 |
| `pwritev2` | 3 | 3 |

- **`fcntl`** commands seen are F_SETFD, F_GETFL, F_SETFL and F_SETLK.
  wineserver takes a write lock on its lock file to make sure it runs
  once per prefix.
- **The xattrs** Wine reads are `user.DOSATTRIB` and `user.WINEREPARSE`.
  On the trace's overlay filesystem every read was ENODATA, and the trace
  has no `setxattr`.
- **`pwritev2`** is `RWF_NOAPPEND` writes of one byte, which grow
  wineserver's mapping files.

## Decision

1. **Duplicating descriptors** (`fs/file.c`).
   - `dup` takes the lowest free descriptor.
   - `dup2` and `dup3` copy to an exact one, replacing it; the replaced
     descriptor is closed, with its locks.
     - dup3's flags other than O_CLOEXEC are EINVAL, and so is the same
       descriptor twice (checked first).
     - dup2 of a descriptor to itself returns it if open.
     - A target at or past the handle limit is EBADF.
   - F_DUPFD and F_DUPFD_CLOEXEC take the lowest free descriptor at or
     above `arg`; at or past the limit, EINVAL.
   - All need the DUPLICATE right (EBADF without, as any missing right),
     and the copy keeps the handle's rights.
2. **Status flags.** An open file description keeps Linux's `f_flags`:
   - the access mode and the open flags that stay with it;
   - O_LARGEFILE, which open sets on 64-bit;
   - not O_CLOEXEC, O_CREAT, O_EXCL, O_NOCTTY or O_TRUNC.

   F_GETFL reports them. F_SETFL changes O_APPEND, O_NONBLOCK, O_DIRECT
   and O_NOATIME and ignores every other bit (`setfl`). tmpfs accepts
   O_DIRECT (`shmem_file_open`), and root may set O_NOATIME.
3. **POSIX record locks** (F_GETLK, F_SETLK, F_SETLKW, as `fs/locks.c`)
   live in one table in `keel_core::lock`, tested on the host.
   - **The owner** is the process, as Linux's `current->files`: threads
     share its locks, and a forked child has none of its parent's.
   - **Ranges** come from l_whence, l_start and l_len
     (`flock64_to_posix_lock`):
     - a length of 0 runs to OFFSET_MAX;
     - a negative length covers the bytes before the start;
     - a start below 0 is EINVAL, and past OFFSET_MAX EOVERFLOW.
   - **Conflicts.** A lock conflicts with another owner's overlapping lock
     when either is exclusive. A new lock replaces the owner's own locks
     where they overlap, splitting them, and merges with the owner's
     touching locks of the same type (`posix_lock_inode`).
   - **F_SETLK and F_SETLKW:**
     - F_RDLCK needs the descriptor open for reading and F_WRLCK for
       writing (EBADF otherwise, `check_fmode_for_setlk`);
     - a conflict is EAGAIN;
     - F_SETLKW waits on a queue that every unlock, close and exit wakes,
       and a signal ends the wait with EINTR.
   - **F_GETLK** reports the first conflicting lock, with l_whence
     SEEK_SET, l_len 0 for "to the end", and l_pid the owner's PID (0 if
     the owner is in another compartment, as Linux shows a PID from
     another namespace). With no conflict, only l_type changes, to
     F_UNLCK. F_UNLCK as the request is EINVAL.
   - **Release.** A process's locks on a file go when it closes any
     descriptor of that file (`locks_remove_posix`): through close,
     dup2's replacement and execve's close-on-exec. All of them go when it
     exits.
4. **Vector and positional I/O** (`fs/read_write.c`).
   - **The calls:** `readv`, `preadv` and `preadv2`; `pwrite64`, `pwritev`
     and `pwritev2`. Their offset rules:
     - an offset of -1 in the `*v2` forms means the file position;
     - another negative offset is EINVAL;
     - a positional call on the console is ESPIPE;
     - a positional write leaves the file position.
   - **Vectors:** more than UIO_MAXIOV (1024) is EINVAL, as is a total
     past `ssize_t`. A short transfer ends the call.
   - **O_APPEND.** A positional write to a file with O_APPEND appends, as
     Linux does (pwrite(2), "BUGS"), unless RWF_NOAPPEND; RWF_APPEND
     appends either way.
   - **RWF flags** (`kiocb_set_rw_flags`): unknown ones are EOPNOTSUPP;
     RWF_APPEND with RWF_NOAPPEND is EINVAL; RWF_ATOMIC is EOPNOTSUPP,
     since tmpfs has no atomic writes. RWF_HIPRI, RWF_DSYNC, RWF_SYNC and
     RWF_NOWAIT change nothing: tmpfs has no device to sync, and Keel
     never blocks on a file.
5. **`statfs` and `fstatfs`** report tmpfs as `shmem_statfs` does:
   - TMPFS_MAGIC, 4096-byte blocks, NAME_MAX 255, ST_VALID;
   - total and free blocks and nodes from the filesystem's byte and entry
     caps, or from the caller's compartment quota where it is smaller, so
     a compartment sees the device it has.
6. **Extended attributes.** Keel's tmpfs stores none.
   - **Answer:** every xattr call is EOPNOTSUPP, the answer of a
     filesystem without xattr support. This comes after the checks Linux
     makes first, in its order (`fs/xattr.c`):
     - get and list check the path or descriptor first, then get checks
       the name;
     - set checks its flags (EINVAL), the name, then the size (past 64
       KiB E2BIG), then the path;
     - remove checks the name, then the path;
     - an empty name, or one over XATTR_NAME_MAX (255), is ERANGE.
   - **Why EOPNOTSUPP.** Linux's own tmpfs stores `user.*` attributes and
     answers ENODATA for a missing one. Wine treats EOPNOTSUPP like
     ENODATA ("no attribute"). Answering ENODATA while a set fails would
     describe a filesystem that cannot exist.

## Not yet covered

- **OFD locks** (F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW) are EINVAL. They
  are not in the traces.
- **Deadlock detection.** F_SETLKW does not detect deadlock (EDEADLK); two
  processes waiting on each other wait until a signal.
- **Stored xattrs** (`user.*`), should a program need to set one.
- **The rest of fcntl:** leases, F_NOTIFY, seals and pipe sizes.

## Evidence

- **Host tests:**
  - `keel_core::lock`:
    - conflicts only between owners, and only with an exclusive lock;
    - upgrading in place;
    - split on unlock and merge on lock;
    - release by file and by owner;
    - the `flock64_to_posix_lock` ranges, including negative lengths and
      EOVERFLOW.
  - `keel_core::handle`: F_DUPFD's floor, dup2's replacement, the limits,
    the DUPLICATE right.
- **`exec.descriptors` (phase 3) and `host.fdprobe`:**
  `user/tests/fdprobe` makes 40 checks, which pass under Linux (ext4)
  and on Keel:
  - dup's shared position; dup2 and dup3 with their refusals and
    O_CLOEXEC; F_DUPFD(_CLOEXEC).
  - F_GETFL with O_LARGEFILE; F_SETFL leaving the access mode.
  - pwrite leaving the position; O_APPEND appending at an offset;
    RWF_NOAPPEND, RWF_APPEND and offset -1; the RWF refusals.
  - readv and preadv.
  - Record locks between a parent and forked children:
    - F_GETLK showing the parent's lock and PID;
    - EAGAIN;
    - a lock elsewhere allowed;
    - release when another descriptor of the file is closed;
    - F_SETLKW waiting for a child's lock until the child exits.
  - statfs and fstatfs.
  - The xattr checks, accepting ENODATA (Linux) or EOPNOTSUPP (Keel) for
    a missing attribute.

  Afterwards every node, frame and process is back.
- **Mutations.**
  - **Host,** each caught:
    - own locks conflicting;
    - no split on unlock;
    - no merge;
    - shared locks blocking shared ones;
    - F_DUPFD ignoring its floor;
    - negative lengths mapped wrongly.
  - **On Keel,** each caught by `fdprobe` at the check named:
    - close keeping the process's locks (29);
    - exit keeping them (times out: F_SETLKW waits for ever);
    - pwrite moving the file position (16);
    - pwrite ignoring O_APPEND (13);
    - RWF_NOAPPEND ignored (14);
    - F_SETFL changing the access mode (10);
    - dup3 of a descriptor to itself allowed (5).

## Consequences

- wineserver's single-instance lock works. Its descriptor juggling (dup,
  dup2, F_SETFL O_NONBLOCK) behaves as on Linux.
- Every close of a file takes the lock table's lock once.
