# ADR 0044: memfd sealing

Status: accepted (Phase 3, P3-S7). Extends ADR 0025 (memfd).

## Context

- **SR-26:** the Phase 5 compositor seals a client's shared buffer
  against shrinking before it maps it. Otherwise the client could
  truncate the buffer under the compositor and make its reads fault.
- **P3-S7** asks for F_SEAL_SHRINK, F_SEAL_GROW and F_SEAL_SEAL.
- **Before this,** Keel's `memfd_create` refused MFD_ALLOW_SEALING, and
  `fcntl` had no seal commands (ADR 0025, "Not yet covered").

The rules are Linux v6.12's:
- `mm/memfd.c`: `memfd_add_seals`, `memfd_get_seals`, `memfd_fcntl` and
  `memfd_create`;
- `mm/shmem.c`: `shmem_get_inode` starts every inode with F_SEAL_SEAL;
  `shmem_setattr` checks truncation; `shmem_write_begin` checks writes;
- `include/uapi/linux/fcntl.h` and `include/uapi/linux/memfd.h`.

Each rule below was also run on a Linux 6.18 host before Keel
implemented it, including how a write across the end is cut.

## Decision

1. **Seals belong to the node**, as `shmem_inode_info.seals` does.
   - **Every file starts with F_SEAL_SEAL** (0x1), as every tmpfs inode
     does, so no seal can be added to it.
   - **`memfd_create(name, MFD_ALLOW_SEALING)`** (flag 2) makes a memfd
     with no seals. Nothing else does.
2. **`fcntl(fd, F_ADD_SEALS, seals)`** (1033, F_LINUX_SPECIFIC_BASE +
   9), in `memfd_add_seals`' order, with `seals` taken as the low 32
   bits:
   - a descriptor not open for writing: EPERM;
   - bits Linux does not define (beyond 0x3f): EINVAL;
   - anything but a regular file (on Linux, anything but tmpfs or
     hugetlbfs): EINVAL. That is pipes, sockets, directories, devices,
     terminals and procfs files;
   - F_SEAL_SEAL already set: EPERM, even when adding no seals;
   - otherwise the seals are added. They are never removed.
3. **`fcntl(fd, F_GET_SEALS)`** (1034): the seals, from any descriptor
   of a regular file; EINVAL otherwise.
4. **What the seals refuse,** each with EPERM:
   - **F_SEAL_SHRINK** (0x2): a truncation to a smaller size;
   - **F_SEAL_GROW** (0x4): a truncation to a larger size, and a write
     past the end. A truncation to the same size is always fine.
   - **How a write past the end is cut.** Linux writes a file a page at
     a time (`generic_perform_write`), and `shmem_write_begin` refuses
     each page-sized piece that would end past the size. So a write that
     crosses the end stops at the last page boundary at or below the
     size, and is EPERM if that boundary is not past the write's start.
     On a 6000-byte file:
     - `pwrite(3000, 4000 bytes)` writes 1096;
     - `pwrite(0, 8000 bytes)` writes 4096;
     - `pwrite(5000, 2000 bytes)` is EPERM;
     - an O_APPEND write is EPERM.
   - **A write of nothing** changes nothing, sealed or not: no size
     change, 0 returned. Keel's filesystem used to extend the file
     to a zero-length write's offset; that is fixed too.
5. **Not implemented, and refused:** F_SEAL_WRITE (0x8),
   F_SEAL_FUTURE_WRITE (0x10) and F_SEAL_EXEC (0x20) are EINVAL from
   F_ADD_SEALS. Linux accepts them, but accepting a seal and not
   enforcing it would break SR-10, so Keel refuses. MFD_NOEXEC_SEAL,
   which sets F_SEAL_EXEC, is EINVAL from `memfd_create`, as before.
6. **The default profile** (ADR 0041) has neither command: the Wine
   trace shows no sealing. The full profile has both, and the Phase 5
   compositor's profile will.

## Evidence

- **`user/tests/sealprobe`**, 30 checks, runs under Linux and on Keel.
  - **Linux:** its output is the conformance reference
    (`user/tests/reference/sealprobe.out`).
  - **Keel:** `exec.seals` (phase 3) runs it with the leak check, and
    the conformance boot runs it in a compartment and compares the
    output with Linux's.
  - **What it checks:** the defaults with and without
    MFD_ALLOW_SEALING; adding no seal; an undefined bit; seals adding
    up; F_SEAL_SEAL; truncation under each seal; the four cut or
    refused writes above; a zero-length write past the end; O_APPEND;
    the size kept; a pipe's two ends; a directory; a read-only
    descriptor.
- **Host tests** (`keel_core::vfs`): the seal rules, Keel's refusal of
  the three unimplemented seals, truncation under each seal, and the
  write cuts measured on Linux.
- **`exec.launch`** (launchprobe check 11, Keel only): a read-only
  descriptor of a sealable memfd cannot add a seal (EPERM), and the
  writable one can. sealprobe cannot check this on a sealable file: it
  would need to reopen `/proc/self/fd/N` read-only, which Keel does not
  have. Its read-only check is on a regular file, which is EPERM for
  F_SEAL_SEAL as well. launchprobe makes the read-only descriptor with
  the native `restrict` call instead.
- **Mutations,** each caught:

  | Mutation | Caught by |
  | --- | --- |
  | F_SEAL_GROW not checked on writes | `exec.seals`: check 19, 4000 bytes written |
  | the write cut at the size, not the page boundary | `exec.seals`: check 19, 3000 written |
  | F_SEAL_SHRINK not checked on truncation | `exec.seals`: check 10 |
  | F_SEAL_GROW not checked on truncation | `exec.seals`: check 15 |
  | F_SEAL_SEAL not checked | `exec.seals`: check 2 |
  | MFD_ALLOW_SEALING ignored | `exec.seals`: check 4, seals 1 |
  | the writable-descriptor check removed | `exec.launch`: launchprobe check 11 |

  The last one first survived: sealprobe's read-only check could not
  tell the two refusals apart. launchprobe's check 11 was added for it.

## Not yet covered

- **F_SEAL_WRITE, F_SEAL_FUTURE_WRITE and F_SEAL_EXEC.** They need
  shared writable mappings refused or tracked; when the compositor
  needs them, they come with that.
- **`fallocate`,** which Linux also checks against F_SEAL_GROW, is not
  implemented.
