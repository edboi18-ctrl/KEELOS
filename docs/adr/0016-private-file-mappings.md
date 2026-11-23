# ADR 0016: Private file mappings

Status: accepted (Phase 3, first part of P3-T7).

## Context

The Wine trace (`docs/syscall-inventory.md`) maps files about 4,700
times: 4,611 private writable `MAP_FIXED` mappings, plus read-only and
executable ones. These are PE images mapped section by section, and the
dynamic linker's libraries. Keel refused every file mapping with
`ENODEV`.

## Decision

1. **A VMA can be backed by a file.** It records the inode, the file
   offset of its first page, and whether the handle allowed `MAP_EXEC`.
   - **Splitting** moves the offset forward for the upper part.
   - **Merging** joins only mappings of the same file whose offsets are
     contiguous.
   - **Offset overflow.** An offset that would overflow with the length
     is refused when the mapping is made, so no page's offset can
     overflow later.
2. **Pages are read when first touched, not copied when mapped.**
   - A fault in a file-backed VMA allocates a private frame, charged to
     the compartment like any other (ADR 0014), and fills it from the
     file. The part past the end of the file stays zero.
   - **Nothing is pinned.** The mapping keeps no snapshot of the file. A
     snapshot would let a program hold old versions of a file in kernel
     memory that no limit counts.
   - **The cost** is that a change to the file shows through pages not
     yet touched. mmap(2) allows this for `MAP_PRIVATE`: "It is
     unspecified whether changes made to the file after the mmap() call
     are visible in the mapped region."
3. **A page wholly past the end of the file is not filled.** Linux sends
   `SIGBUS` there (mmap(2)). Until signals arrive (P3-T6), a user access
   ends the thread and a kernel copy gets `EFAULT`.
4. **Errors follow mmap(2) and mprotect(2).**
   - No handle: `EBADF`.
   - Not open for reading: `EACCES`.
   - `PROT_EXEC` without `MAP_EXEC`: `EPERM`, as for a noexec mount. A
     later `mprotect` adding `PROT_EXEC` without it: `EACCES`.
   - Not a regular file: `ENODEV`. `/dev/zero` is the exception: it maps
     as anonymous memory, as on Linux.
   - A misaligned offset: `EINVAL`.
5. **Lock order: address space, then filesystem.** The fault path holds
   the address-space lock and calls the `FileReader` that `linux-abi`
   installs, which takes the filesystem lock. The reverse order never
   happens: no `fs::with` closure touches user memory. That was checked
   by a scan of every closure, and must stay true. The reader allocates
   nothing.
6. **`MAP_SHARED` is still refused** (`EINVAL`). Shared file mappings
   need the page shared with the file and with every mapping, and come in
   P3-T7's second part.

## Evidence

- Host tests (`keel_core::vm`):
  - offsets through faults, splits, holes and re-merges;
  - no merge across files, gaps or anonymous memory;
  - exec allowed only with `MAP_EXEC`, at map and at protect time;
  - an overflowing offset is refused.
- `user/tests/filemap` passes under Linux (`host.filemap`) and on Keel
  (`exec.file_mappings`). It maps its own executable and compares every
  byte with `read(2)`:
  - at offset 0 and at a page offset;
  - the last page, zero past the end;
  - private writes stay private;
  - a split keeps offsets;
  - each refusal above. Linux confirmed `ENODEV` for a directory and
    `EACCES` for a write-only handle.
  - Mutations, each failing the Keel test:
    - splits that keep the old offset fail at the split check;
    - faults that ignore the page's place in the file fail at the first
      comparison.
- `exec.file_mapping_past_end`: a page wholly past the end gives `EFAULT`
  to a kernel copy, while the last partial page and the first page read
  normally. Zero-filling instead of refusing fails it.

## Consequences

- When `unlink` arrives (P3-T8), a mapped file must stay alive until its
  last mapping goes, as on Linux. Today nothing can be deleted, and a
  mapping names its inode by number.
- A dynamic linker can now map shared libraries. `exec.shared_library`
  runs `fixtures/musl-dynamic/greet`: musl's dynamic linker opens
  `/lib/libkeelgreet.so` with `open`, reads its headers with `read`,
  maps it from the file with `mmap` and `mprotect`, and the program
  prints the library's string and a count from its data segment. That
  needed `open`, `pread64` and `fcntl`'s `F_SETFD` too, and it logs no
  unimplemented call.
