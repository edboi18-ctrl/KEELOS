# ADR 0022: tmpfs namespace, node lifetime and metadata

Status: accepted (Phase 3, P3-T8 first part: the namespace and metadata
calls; descriptor-level calls follow). Extends ADR 0012 (path authority),
ADR 0014 (compartments) and ADR 0021 (shared file mappings).

## Context

P3-T8 asks for "tmpfs complete enough for a Wine prefix": directories,
symbolic links, hard links, rename, timestamps, and permissions as stored
metadata. The Wine traces (`docs/syscall-inventory.md`, and wineboot's
prefix creation traced with it) make these calls:

| Call | Prefix creation | `wine cmd /c echo hello` |
| --- | --- | --- |
| `readlink` | 34,233 | 5,418 |
| `stat` | 19,929 | 2,093 |
| `lstat` | 1,540 | 162 |
| `getdents64` | 35,306 | 1,980 |
| `lseek` | 840 | 188 |
| `fchdir` | 503 | 75 |
| `mkdir` | 148 | 2 |
| `utimensat` | 90 | 0 |
| `fchmod` | 90 | 0 |
| `umask` | 38 | 22 |
| `unlink` | 15 | 9 |
| `rename` | 6 | 3 |
| `chdir` | 6 | 4 |
| `access` | 5 | 4 |
| `symlink` | 2 (`dosdevices/c:` and `z:`) | 0 |
| `chmod` | 1 | 1 |
| `getcwd` | 1 | 1 |

- **`readlink`:** most calls are musl's `realpath` walking each
  component of a path; for a name that is not a link the answer is
  EINVAL.
- **wineserver's shared memory** relies on a file that is unlinked while
  open, then sized and mapped (ADR 0021).

Until now tmpfs had none of this:
- inode numbers were indexes into a table;
- nodes were never freed;
- there were no links;
- times were 0.

## Decision

1. **Inode numbers are 64-bit and never reused.** Nodes live in a map
   keyed by number, so memory follows the live nodes, and a stale
   number can only name nothing. Stale numbers include a removed working
   directory and a key in the shared page cache.
2. **A node lives while it is named or held.**
   - **Named:** directory entries (`links`).
   - **Held:** pins, which come from two places:
     - Every open file description pins its node. The pin is taken under
       the lookup's lock, so the node cannot go in between, and dropped
       when the description is.
     - Every address space that maps the file pins it. The core VM's
       layout counts the mappings of each file and reports when a layout
       starts or stops mapping one. The hardware layer nets each
       operation's reports, since `MAP_FIXED` over a mapping of the same
       file removes and adds it in one operation, and passes them to the
       filesystem. `fork` pins the child's files, and dropping an address
       space unpins its files.
   - **Freed** when both counts are zero. The file's bytes go back to the
       filesystem and its owner's quota, and its shared pages are dropped
       (`shared_forget`).

   This is Linux's model: unlink(2) says the file "will remain in
   existence until the last file descriptor referring to it is closed",
   and a mapping's `vm_file` keeps it too (mmap(2): "closing the file
   descriptor does not unmap the region").
3. **Symbolic links** are followed in lookup:
   - every link before the last component;
   - the last one too, unless the call says not to (`lstat`,
     `O_NOFOLLOW`, `AT_SYMLINK_NOFOLLOW`);
   - a trailing `/` always follows and needs a directory;
   - more than 40 links in one lookup is ELOOP (`MAXSYMLINKS`).

   Confinement is unchanged (SR-4). An absolute target starts again at
   the lookup's root, which is the compartment's root or a directory
   handle's, and `..` in a target stops there too. A target is stored as
   given: up to 4,095 bytes, empty refused (ENOENT), mode 0777 as on
   Linux.
4. **Hard links** (`link`, `linkat`):
   - a directory cannot be linked (EPERM);
   - a file whose last name is gone cannot get a new one (ENOENT);
   - each extra name costs one entry of the filesystem's cap and one
     node of the owner's quota, as tmpfs reserves an inode for each hard
     link (`shmem_link`), so links cannot grow kernel memory without
     limit.
5. **Removal and rename** follow `fs/namei.c` and `mm/shmem.c`:
   - **unlink:** a directory EISDIR; a trailing slash on a non-directory
     ENOTDIR.
   - **rmdir:** a non-empty directory ENOTEMPTY; a non-directory
     ENOTDIR; "." EINVAL, ".." ENOTEMPTY, "/" EBUSY. A removed directory
     takes no new entries (ENOENT, as `IS_DEADDIR`), and `getdents64` on
     it is ENOENT.
   - **rename** (`rename`, `renameat`, `renameat2`):
     - RENAME_NOREPLACE and RENAME_EXCHANGE are supported. RENAME_WHITEOUT
       is EINVAL, since it is for overlay filesystems.
     - A directory into itself or beneath itself is EINVAL.
     - Replacing a directory by a non-directory is EISDIR, the reverse
       ENOTDIR; replacing a non-empty directory is ENOTEMPTY.
     - Two names of the same node: nothing happens.
     - A source or target that is not a plain name is EBUSY, or EEXIST
       with RENAME_NOREPLACE.
6. **Confinement across rename (the open question in ADR 0014).** The
   system compartment can move a directory out from under a confined
   process's working directory. From there, `..` would climb above the
   process's root. So a relative lookup first checks that the working
   directory still lies beneath the root; if not, the lookup names
   nothing (ENOENT), like a removed directory. `getcwd` reports ENOENT
   the same way. `fchdir` to a handle from outside the root gives the
   same result.
7. **Metadata.**
   - **Times.** Nodes keep access, modification and change times, from
     the realtime clock (which counts from boot until Keel reads a
     real-time clock). The rules are tmpfs's:
     - creating a node stamps all three, and its directory's
       modification and change times;
     - a write of at least one byte stamps modification and change;
     - truncate stamps them whatever the size (`do_truncate`);
     - chmod, link, unlink and rename stamp change, and rename and
       removal stamp both directories;
     - reads and `getdents64` update the access time by Linux's default
       `relatime` rule (`relatime_need_update`).
   - **`utimensat`** follows `fs/utimes.c`: UTIME_NOW and UTIME_OMIT; a
     bad nanosecond field EINVAL; both fields UTIME_OMIT do nothing and
     do not even look up the path; a NULL path means the descriptor.
   - **Permissions** are stored (`chmod`, `fchmod`, `fchmodat`, mode &
     07777) and reported, never checked (SR-6). `umask` is per process
     (022 for a process the kernel starts), kept across fork and execve.
     `mkdir` keeps the permission and sticky bits, without the umask's;
     `open` with O_CREAT uses the umask.
   - **Sizes.** A directory's size is tmpfs's 20 bytes per entry plus two
     (`BOGO_DIRENT_SIZE`); a symlink's is its target's length. `st_blocks`
     counts whole pages for files, as tmpfs allocates them.
8. **The calls added:**
   - **Status and access:** `stat`, `lstat`, `newfstatat` (AT_EMPTY_PATH,
     AT_SYMLINK_NOFOLLOW), `access`, `faccessat`, `faccessat2`.
     - For `access`, processes are root and check no modes, so as root in
       `generic_permission`: reading and writing are allowed, and
       executing only a directory or a file with an execute bit.
   - **Names:** `mkdir`, `mkdirat`, `rmdir`, `unlink`, `unlinkat`
     (AT_REMOVEDIR), `rename`, `renameat`, `renameat2`, `link`, `linkat`
     (AT_SYMLINK_FOLLOW), `symlink`, `symlinkat`, `readlink`,
     `readlinkat`.
   - **Metadata:** `chmod`, `fchmod`, `fchmodat`, `umask`, `utimensat`.
   - **Working directory:** `getcwd` (ERANGE, ENOENT), `chdir`, `fchdir`.
   - **Descriptors:**
     - `lseek`: SEEK_SET, SEEK_CUR and SEEK_END. SEEK_DATA and SEEK_HOLE
       give ENXIO outside the file; inside it every byte is data. The
       console is ESPIPE, and the other devices stay at 0.
     - `getdents64`: ".", "..", then the names in byte order; d_type as
       Linux; resumable by index; `lseek` to 0 rewinds.
   - **The rights rule for `*at` calls**, as openat's (ADR 0012): through
     a directory handle, a lookup needs ENUMERATE; a change to the names
     in it (create, remove, rename, link) needs CREATE too; `getdents64`
     and `fchdir` check the type first (ENOTDIR) and then ENUMERATE.
   - **Not followed for `open`:** O_NOFOLLOW, and O_CREAT with O_EXCL, do
     not follow a last symbolic link (ELOOP and EEXIST); O_CREAT with a
     trailing slash is EISDIR.

## Not yet covered

- **`O_CREAT` through a dangling symbolic link** is EEXIST; Linux would
  create the target.
- **Holes:** tmpfs reports unwritten pages as holes to SEEK_DATA and
  SEEK_HOLE; Keel keeps none.
- **Entry order:** `getdents64` resumes by index, so a directory changed
  between calls can skip or repeat a name. Linux's tmpfs keeps stable
  offsets.
- **Ownership:** uid and gid are always 0, and `chown` does not exist.
- **The cpio initramfs** still skips symbolic links: the archive has
  none Keel needs.
- **Descriptor-level calls** follow in the second part: `dup` and its
  forms, `fcntl` F_GETFL, F_SETFL, F_DUPFD and locks, `readv` and the
  `pwrite` family, `statfs` and `fstatfs`, and the xattr calls.

## Evidence

- **Host tests** (`keel_core::vfs`, 23):
  - Symbolic links:
    - followed;
    - kept in the root (an absolute target and `..` from a link inside a
      confined root reach nothing outside);
    - 40 followed and the 41st ELOOP; a loop ELOOP;
    - the empty and over-long targets.
  - Hard links:
    - the link count;
    - EPERM for a directory;
    - a pinned file readable after its last name goes, its bytes and
      number given back when unpinned, the free hook told;
    - a dead file not linkable.
  - rmdir, removed directories and rename: every error above; exchange;
    a moved directory's `..`.
  - A working directory moved out of its root names nothing.
  - Timestamps under an injected clock, including relatime, and
    directory sizes.
  - Links charged to the quota and the cap.
  - `parent`'s last-component kinds, and `getcwd` paths.
- **Host tests** (`keel_core::vm`): layouts know which files they map
  through splits, partial unmaps, `MAP_FIXED` replacement (by another
  file and by the same one) and clones.
- **`exec.filesystem` (phase 3) and `host.fsprobe`:**
  `user/tests/fsprobe` makes 58 checks, which pass under Linux (on ext4
  here) and on Keel. They exercise every call above and their errors.
  Afterwards `/tmp` is empty, and every node, frame and process is back.
- **`exec.shared_mappings`:** `sharemap` now makes 31 checks; the program
  unlinks its file, and the file and its shared pages are freed. Its
  last check maps a file privately and shared, closes the descriptor and
  unlinks the file, then touches the pages for the first time: the
  mapping alone keeps the file.
- **Mutations:**
  - **Against the host tests**, each caught:
    - an absolute target walked from the filesystem's root instead of
      the lookup's;
    - one more symlink allowed;
    - a node freed while pinned;
    - rmdir of a non-empty directory;
    - a directory renamed into itself;
    - no working-directory check;
    - directories linkable;
    - writes without timestamps;
    - links costing no slot;
    - removed directories taking entries.
  - **Against the phase 3 tests**, each caught at the check named:
    - open that does not pin its node: `sharemap` dies with SIGSEGV on a
      page of its unlinked file;
    - mappings that do not pin their file: the same, at its check 31;
    - O_NOFOLLOW ignored: `fsprobe` check 12;
    - the umask ignored at O_CREAT: check 5;
    - a symbolic link listed as a regular file: check 34;
    - getcwd without ERANGE: check 41;
    - UTIME_OMIT taken as UTIME_NOW: check 51.

## Consequences

- **Wine:** a prefix's tree (`dosdevices` links, `drive_c`, the registry
  files written and renamed into place) can now be built in tmpfs.
- **Cost:** every relative lookup walks from the working directory up to
  the root once, for the confinement check.
