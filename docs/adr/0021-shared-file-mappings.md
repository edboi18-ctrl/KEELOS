# ADR 0021: Shared file mappings and ftruncate

Status: accepted (Phase 3, P3-T7 second part, without `mremap` and
shared anonymous memory). Extends ADR 0016 (private file mappings).

## Context

Wine's server shares memory with its clients through files. The trace
(`docs/syscall-inventory.md`) shows 15 `MAP_SHARED` file mappings, by
wineserver and by the clients it sends descriptors to. The pattern is:

1. wineserver opens a new file with `O_CREAT | O_EXCL`, unlinks it and
   sizes it with `ftruncate` (24 calls);
2. it maps the file shared;
3. it sends the descriptor over a Unix socket (`SCM_RIGHTS`);
4. each client maps it shared, often `MAP_FIXED` (the user shared data
   page at 0x7ffe0000).

Both sides must see each other's stores. tmpfs keeps a file's data as a
copy-on-write byte vector (`vfs::Fs`, ADR 0012), which nothing can map
directly. The trace never calls `mremap`, and maps no shared anonymous
memory.

## Decision

1. **A shared page cache** in the hardware layer (`vm::SHARED_PAGES`),
   keyed by (file, page offset).
   - **Filling it.** The first fault of a shared mapping on a page makes
     the page's frame from the file's bytes (zero past the end of the
     file). Every later shared mapping of that page, in any process,
     maps the same frame.
   - **Never copied.** Shared pages are not copy-on-write:
     - `fork` gives the child the same frame with the same rights and
       leaves the parent's writable;
     - `mprotect` makes them writable whoever else maps them;
     - a write fault on a present shared page only raises its rights.
   - **References.** The cache holds one reference to each frame, and
     each mapping another.
   - **Accounting.** Each mapping charges its address space one frame
     per present page, as for any page, so a compartment's memory limit
     still bounds what it maps. The cached frames themselves are the
     file's data, bounded by its size and so by the tmpfs limits and its
     owner's quota. They are not charged a second time.
2. **Coherence with read(2) and write(2).** The cached frames hold the
   file's newest bytes:
   - `read` and `pread` copy cached pages over what tmpfs returns;
   - `write` updates the cached pages it covers as well as tmpfs;
   - a private mapping's page, filled when first touched, takes the
     cached bytes too.

   Not covered: `execve` and the ELF loader still read tmpfs's bytes,
   so they do not see stores made only through a shared mapping.
3. **Truncation.** `ftruncate`, and `O_TRUNC` at open, drop cached pages
   wholly past the new end. In the page that holds the new end, the
   bytes past it become zero, so a file grown again reads zeros there,
   in the file and through its mappings, as on Linux. A mapping that
   already has a dropped page keeps its frame until it unmaps it, where
   Linux unmaps it (a later access is SIGBUS). The page is no longer the
   file's, so no other process sees stores to it.
4. **Rights**, as Linux's `do_mmap` (`mm/mmap.c`):
   - Any file mapping needs a handle open for reading (EACCES).
   - A shared mapping with `PROT_WRITE` needs one open for writing
     (EACCES).
   - A shared mapping of a read-only handle can never be made writable:
     Linux clears `VM_MAYWRITE`, and Keel records `may_write` in the
     mapping's `Backing`, so `mprotect` adding `PROT_WRITE` is EACCES.
   - Private mappings of read-only handles stay writable, since their
     copies are private.
   - Shared and private mappings of one file never merge.
5. **The flags.**
   - `MAP_SHARED` and `MAP_SHARED_VALIDATE` are the same here: unknown
     flags are refused for both (SR-10).
   - `MAP_SHARED | MAP_ANONYMOUS` and shared `/dev/zero` are EINVAL for
     now.
6. **`ftruncate`** as `do_sys_ftruncate` and `do_ftruncate`
   (`fs/open.c`): a negative length EINVAL, no handle EBADF, and EINVAL
   for something that is not a regular file or a handle not open for
   writing. Growth is charged to the compartment's tmpfs quota (ENOSPC),
   as a write is.
7. **`/tmp`** is created at boot. hier(7) lists it as the directory for
   temporary files, following FHS 3.0. Its mode is 1777 (world-writable,
   sticky), as `stat /tmp` shows on the Linux host the tests run on;
   Keel stores the mode but checks no permissions yet. Wine keeps its
   server directory there.

## Not yet covered

- **`mremap`** (not in the trace).
- **Shared anonymous memory** (`MAP_SHARED | MAP_ANONYMOUS`). Its pages
  belong to no file. Freeing them needs a count of the mappings that
  share them, across splits and `fork`.
- **Unmapping truncated pages from other mappings.** This needs a
  reverse map from frames to the mappings that hold them.
- **`msync`.** tmpfs has no backing store, so Linux's `msync` does
  nothing for it either.
- **Dropping a deleted file's pages.** When `unlink` arrives (P3-T8),
  deleting the last name of a file must drop its cached pages
  (`shared_forget`). Until then the pages stay as long as the file does.

## Evidence

- **Host tests** (`keel_core::vm`):
  - a read-only handle's shared mapping refuses `PROT_WRITE` at map and
    at protect;
  - a private one does not;
  - faults in a shared mapping, present or not, are `Shared` with the
    right file offset, never copy-on-write;
  - shared and private mappings of one file stay apart.
- **`exec.shared_mappings` (phase 3) and `host.sharemap`:**
  `user/tests/sharemap` makes 28 checks, which pass under Linux and on
  Keel:
  - `ftruncate` sizing a file in `/tmp`, and its EINVAL cases;
  - stores through a shared mapping seen by `pread`, and `write`s seen
    through the mapping;
  - two mappings of one page aliasing;
  - a private mapping first read after a shared store seeing it, and
    keeping its own store private;
  - a forked child and its parent seeing each other's stores through
    the inherited mapping, and the file seeing the child's;
  - EACCES for `PROT_WRITE` from a read-only descriptor, at `mmap` and
    at `mprotect`;
  - a shared mapping made read-only and then writable again;
  - shrinking and regrowing zeroing the cut part of a page, in the file
    and through the mapping.

  The kernel then drops the cached pages of the file the program left in
  `/tmp`, and every frame and process must be back.
- **Mutations**, each of which makes it fail (the check that fails in
  brackets):
  - `read` that ignores the shared pages (7);
  - `write` that does not reach already-mapped pages (8; before check 8
    first touched the page through the mapping, this mutant passed);
  - a private page first touched without the shared stores (12);
  - shared faults treated as private ones (7);
  - `mprotect` ignoring `may_write` (21);
  - `ftruncate` on a read-only descriptor (4);
  - truncation that leaves the cut part of a page (27).
  - One mutant passes and is equivalent: `fork` write-protecting shared
    pages. The first write in either process faults, and since the
    mapping is shared the fault only raises the page's rights, never
    copies it.

## Consequences

- wineserver's shared memory can work once Unix sockets carry
  descriptors (P3-T11) and `unlink` exists (P3-T8).
- Every `read` and `write` of a regular file now also looks up the
  shared page cache: one lock and a range lookup.
