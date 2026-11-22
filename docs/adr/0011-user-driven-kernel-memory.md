# ADR 0011: Bounding the kernel memory user programs can cause

Status: accepted (F-0011; second Phase 1 audit, `docs/PHASE1-AUDIT-2.md`,
A1 and A2). Per-compartment limits replace the global ones in Phase 3
(SR-8, P3-S4).

## Context

The kernel's own allocations cannot fail gracefully. `hal::heap` returns
null when no frame is left, every caller uses the infallible `alloc` API,
and Rust turns the null into a panic. The audit showed that a user
program could reach that panic by calling `mmap` 5.5 million times:
each call added a VMA, and nothing capped them. Creating files did the
same through tmpfs nodes. User page faults were already kept out of the
kernel's reserve (F-0007), but not the memory the kernel allocates on a
program's behalf, nor the page tables for its mappings.

Making every kernel allocation fallible is not practical with the stable
`alloc` collections (`BTreeMap` has no fallible insert). What has to hold
is narrower: nothing a program does may bring the kernel's own
allocations to the point of failing.

## Decision

Four layers, each enough for its own kind of allocation:

1. **Caps on what a program can create.**
   - At most 65530 VMAs per address space, Linux's default
     `vm.max_map_count` (`include/linux/mm.h` v6.12; `vm.rst`). Calls that
     would exceed it fail with ENOMEM, as on Linux. The check runs before
     any change and counts the VMAs a call would split.
   - Adjacent VMAs with the same rights are merged, as Linux does, so
     ordinary programs stay far below the cap.
   - At most 65536 tmpfs nodes (ENOSPC). Names are at most `NAME_MAX`, so
     tmpfs metadata stays at a few tens of MiB.
   - Already in place: handles (1024 per process), file data (256 MiB),
     path, iovec and transfer lengths.
2. **Admission against the reserve.** When free frames are down to the
   reserve that user page faults may not take (`memory::user_reserve`,
   1/16 of RAM between 16 and 256 MiB), every system call except
   `close`, `munmap`, `brk` and `exit` returns ENOMEM before running. The
   exempt calls free memory or cannot fail. So the reserve is left for
   the kernel's own work.
3. **User page tables from the user pool.** Tables created for user
   mappings come from `allocate_zeroed_user`, like the pages they map.
   Otherwise a program touching one page per 2 MiB region makes the
   kernel spend one table frame per page from its own pool.
4. **Fallible where a program sets the size.** Growing or copying a
   tmpfs file uses `try_reserve`, so a large write returns ENOMEM rather
   than aborting.

A2, the slow placement of `mmap(NULL)`: the search starts below the last
mapping it placed (Linux's old `free_area_cache` idea), and falls back to
a full search only if nothing fits there. With the cap, even that full
search is bounded.

An allocation failure in the kernel proper (scheduler, interrupt paths)
still panics. That is acceptable only because the reserve keeps those
allocations from failing, and nothing above lets a program take it.

## Evidence

- Host tests in `keel-core` (`vm.rs`, `vfs.rs`): the cap, splits counted
  against it, an unchanged layout after a refusal, merging, the search
  cache and its fallback, the node cap, and copy-on-write of a file a
  reader holds.
- Self-tests (`phase1_resource_limits`):
  - `limits.map_count`: the audit's proof of concept now ends in ENOMEM
    after 65526 mappings.
  - `limits.map_null_preemptible`: `mmap(NULL)` up to the cap, with a
    kernel thread on schedule throughout (1.2 s under TCG).
  - `limits.tmpfs_nodes`: creating files ends in ENOSPC.
  - `limits.reserve_admission`: with only the reserve free, `openat` is
    refused with ENOMEM.
- Each test failed with its protection removed (cap, admission, node
  cap, search cache).
- `host.maplimit`: the same program also ends in ENOMEM under Linux.

## Consequences

- A program that legitimately needs more than 65530 mappings fails as it
  would on a default Linux system.
- Under memory exhaustion, programs see ENOMEM from calls Linux rarely
  fails that way (for example `read`). That is the price of never letting
  the kernel's own allocations fail.
- With more than one process (Phase 3), the caps become per compartment
  and the reserve check stays global.
