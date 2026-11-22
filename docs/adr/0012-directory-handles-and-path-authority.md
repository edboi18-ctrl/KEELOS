# ADR 0012: Directory handles confine lookups; where path authority comes from

Status: accepted (second Phase 1 audit, `docs/PHASE1-AUDIT-2.md`, A6).
Revisited when compartments arrive (Phase 3).

## Context

SR-1 says every kernel object is reached through a handle with rights.
For paths in Phase 1:

- `openat(dirfd, "../x")` walked up from the directory a handle names, and
  stopped only at the process root, which is the filesystem root for
  every process. A handle to `/a/b` therefore reached all of `/`.
- `O_CREAT` needed only `ENUMERATE` on the directory handle. `CREATE`
  existed in the rights list but was never checked.
- `AT_FDCWD` and absolute paths use no handle at all.

None of this crosses a boundary yet, since there are no compartments.
It is the state compartments must not inherit.

## Decision

1. **A directory handle is a root.** A relative path through a directory
   handle is resolved with that directory as both start and root, so `..`
   stops there. That is the behaviour of Linux's
   `openat2(..., RESOLVE_IN_ROOT)` (`openat2(2)`). Plain Linux `openat`
   lets `..` climb, so this is a deliberate difference, recorded in
   `docs/syscalls.md`. A program that relies on `..` escaping a
   descriptor's directory sees ENOENT, or a different file, instead.
2. **Creating needs `CREATE`.** `openat(dirfd, ..., O_CREAT)` requires
   `ENUMERATE | CREATE` on the handle. Directory handles get `CREATE` by
   default. Linux lets a program create through any directory descriptor
   it can write to, and here mode bits grant nothing (SR-6). The same is
   done for `MAP_EXEC` on files. From Phase 3, a compartment manifest can
   withhold it.
3. **`AT_FDCWD` and absolute paths use the process's root and working
   directory.** These are the process's ambient path authority. No lookup
   leaves the process root (`vfs::Fs::lookup`). Today every root is `/`.
   In Phase 3, each compartment's root becomes the directory its manifest
   names. The root then works as the compartment's one implicit directory
   handle, and the rule above applies to it unchanged.

## Evidence

- `fs.dirfd_confines` runs `user/tests/dirconfine` with a handle to
  `/test`. `../etc/keel-release` gives ENOENT even though the file
  exists, `../startup` opens `/test/startup`, and `O_CREAT` through the
  handle creates `/test/made-here`. With the old root (the process root)
  restored, the program exits 1 and the test fails.
- The `CREATE` check itself is exercised only on the allowed side. No
  program can yet hold a directory handle without `CREATE`: rights are
  removed only when a handle is duplicated, and those calls arrive with
  compartments. A refusal test belongs with them.

## Consequences

- Directory-relative code that climbs out of its descriptor with `..`
  behaves differently from Linux. Wine's use of `openat` should be
  checked against this in Phase 4.
- Compartments in Phase 3 need no new lookup rule: they set the process
  root.
