# ADR 0009: Owned frame handles outside `keel-hal`

Status: accepted (audit finding 1, `docs/PHASE1-AUDIT.md`).

## Context

`keel_core::frame::Frame` is a page-aligned physical address. It is
`Copy`, and `Frame::containing(address)` is public. Until this change,
`keel_hal::memory` exported `release`, `retain`, `with_frame_bytes`,
`copy_frame` and `references`, all taking any `Frame`. So safe code in
any crate (`keel-kernel`, `keel-linux-abi`, both free of `unsafe`) could
build a `Frame` for any address, then write to it or free it while its
real owner, such as a page table, kernel stack or heap page, still used
it. That is memory corruption reachable without `unsafe`, which defeats
the reason for keeping `unsafe` in `keel-hal` (ADR 0006).
`with_frame_bytes` also ran the caller's closure under the allocator
lock, so a closure that allocated would deadlock.

Raw frames are needed inside `keel-hal`. Page tables refer to frames by
physical address, and copy-on-write keeps several references to one
frame and manages the counts explicitly (`vm.rs`). Outside `keel-hal`,
the only users were the self-tests.

## Decision

1. **Raw operations are `pub(crate)`.** `allocate_zeroed`,
   `allocate_zeroed_user`, `retain`, `release`, `references` and
   `copy_frame` are visible only inside `keel-hal`. `with_frame_bytes` is
   removed. `Frame` stays a plain address in `keel-core`: holding one
   grants nothing, because nothing outside `keel-hal` accepts it.
2. **`keel_hal::memory::OwnedFrame` for everyone else.** Only
   `OwnedFrame::allocate` and `allocate_user` create one (the field is
   private). It is neither `Copy` nor `Clone`, and dropping it frees the
   frame. Its contents are reached through `bytes(&self)` and
   `bytes_mut(&mut self)`, so the borrow checker excludes aliasing and no
   lock is held while the caller works. The inner `Frame` is never handed
   back, so `keel-hal` never maps an owned frame anywhere else, which is
   what makes those two accessors sound.
3. **No public `retain`.** The audit suggested `retain` returning a
   second owned handle. Nothing outside `keel-hal` needs shared frames
   today; shared file pages (P3-T7) will get a reference-counted type
   when they exist, rather than a general API now.
4. **Other public helpers that touch raw memory** were checked:
   `map_mmio` and `IoApic::new` refuse RAM (SR-20).
   `selftest::read_user_directly` now refuses any address outside the
   user half, since its old safety argument relied on its only caller.

## Evidence

- Doctests on `OwnedFrame` in `kernel/hal/src/memory.rs`. One normal use
  compiles. Three `compile_fail` cases fail to compile: freeing a frame
  made from an address (E0603, private function), using a handle after
  it is freed (E0382) and building an `OwnedFrame` directly (E0603).
  Stable rustdoc does not check error codes, so each code was confirmed
  by compiling the snippet as a normal doctest.
- `frames.allocate`, `frames.zeroed` and `frames.release` in
  `selftest.rs` use the new API. `memory::stale_frame_refused` checks,
  inside `keel-hal`, that a freed frame cannot be freed, retained or
  counted again.

## Consequences

- A safe crate that needs a page of memory gets an `OwnedFrame`. It
  cannot map it into an address space through the public API; that stays
  inside `keel-hal` (`vm`, `paging`).
- Adding a new public `keel-hal` function that takes a `Frame` or a
  physical address would reopen this. Reviews of `keel-hal` changes
  should look for that.
