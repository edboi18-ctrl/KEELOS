# Phase 1 security audit, third pass

Audit date: 2026-11-22. Commit audited: `5f23a97` (`main` after pull
requests #4 and #6).

**Verdict: clear to start Phase 2.** Every finding of the second audit is
fixed and has a regression test that passed here. No new finding blocks.
Three low-severity items are listed below; C1 must be fixed before any
system call lets a program choose a file to execute.

## Status on the working branch

| # | Status |
| --- | --- |
| C1 | Fixed before Phase 2 work began. `elf::Image::bias_for_base` computes the bias with `checked_sub` and then checks it; `exec::load` uses it. Host test `relocatable_image_above_the_base_is_refused` (the audit's 0x7000_0000_0000 case) and the parser's random-input test now also choose load addresses; with the plain subtraction back, both panic. |
| C2 | Fixed. `paging::clear_user_half` hands each leaf and table to a callback as the walk reaches it (tables after everything below them); `AddressSpace::drop` frees them there. Test `vm.teardown_allocates_nothing`: 1024 pages, one every 2 MiB, torn down with 0 heap allocations and 2053 frames freed; collecting into a `Vec` again makes 11 allocations and the test fails. |
| C3 | Fixed (ADR 0011 updated). Every tmpfs buffer is checked against the reserve at its full size before it is allocated: doubling if that leaves the reserve intact, else exactly what is needed, else ENOMEM. Test `fs.growth_keeps_reserve` (64 frames above the reserve): growth stops at 128 KiB with ENOMEM, never below the reserve; with the check always allowing, it went 32,833 frames below and the test fails. Host test for the fallback from doubling. |

## What was run (QEMU 8.2.2, TCG, no KVM, Ubuntu 24.04)

- `cargo test --locked --offline`: passed.
- `cargo xtask audit --offline`: passed (advisory check skipped).
- `cargo xtask test`: passed, 128 PASS lines, phases 0 and 1 with every
  scenario and tamper test.
- `cargo xtask fuzz --minutes 12 --seed 7741093`: passed. 35 runs, 70,245
  system calls, no panic, no hung run, worst harness wake-up delay
  185 ms, free frames 1,034,059 to 1,034,048.
- CI run 45062334767 on `main` at `5f23a97` succeeded.

Not run: anything under KVM or on real hardware, `cargo xtask dist`, the
nightly `security.yml` (it has not yet run on `main`).

## Second-audit findings, re-checked

| # | Result |
| --- | --- |
| A1 | Fixed (F-0011, ADR 0011). 65530-mapping cap with merging, 65536-node cap, admission check against the reserve, user page tables from the user pool, fallible tmpfs growth. `limits.map_count`, `limits.tmpfs_nodes` and `limits.reserve_admission` passed. The cap counts splits from `munmap`, `mprotect` and `MAP_FIXED` before changing anything; I found no way round it by reading. |
| A2 | Fixed. The search starts below the last placement; the fallback scan is bounded by the cap. `limits.map_null_preemptible` passed. |
| A3 | Fixed. Device writes no longer hold the file lock; user text goes out in pieces of at most 64 bytes with the locks released between. `console.slow_uart_preemptible` passed. |
| A4 | Fixed. The barrier keys on an address-space id that is never reused. |
| A5 | Fixed. Heap, device and stack regions start at random 2 MiB-aligned offsets; `kaslr.regions_vary` saw 7 distinct layouts in 7 boots. |
| A6 | Fixed (ADR 0012). A directory handle is the root of lookups made through it; `O_CREAT` needs `CREATE`. `fs.dirfd_confines` passed. `AT_FDCWD` and absolute paths remain ambient authority until compartments, as the ADR says. |
| A7 | All five fixed: double fault excluded from user faults, `EXITED` bounded at 1024, the leaked reference released, the allocation rule rewritten to match the code, `CR4.PGE` cleared explicitly. |
| A8 | `docs/REPOSITORY-SETUP.md` is now fully ticked and GitHub reports `main` as protected. I still cannot read the ruleset details or the tag ruleset. |

One claim I had not checked before: `paging.rs` says the direct map
cannot overlap the heap, device and stack windows. Limine 12.9.6
(`common/protos/limine.c`) randomises the direct-map base within "a
quarter of the higher half", so it stays below `0xffff_a000_0000_0000`
and the windows start at `0xffff_c000_0000_0000`. The claim holds.

## Files read in this pass that the second pass skipped

`core/paging.rs`, `elf.rs`, `exec.rs`, `cpio.rs`, `signal.rs`, `poll.rs`,
`tty.rs`, `rng.rs`; `hal/va.rs`, `hal/acpi.rs`, `arch/x86_64/fpu.rs`
(non-test code in each). Nothing blocking in any of them. Notes:

- Page-table code never sets the global bit, refuses writable and
  executable together, and refuses to map over a present entry.
- The ELF parser checks every offset and rejects overlapping or
  descending segments.
- FPU state is per thread, starts from a zeroed area with a clear
  `XSTATE_BV`, and is saved and restored on every switch.
- The address-range allocator keeps a guard page after every range and
  merges correctly on release.
- The generator rekeys after every 32 bytes (fast key erasure) and
  refuses to produce output before it is seeded.

Still not read: `core/acpi.rs`, `cpuvuln.rs`, `crypto.rs` (covered by
RFC test vectors in the host tests), `keyboard.rs`; `hal/mitigations.rs`,
`time.rs` beyond one function, `interrupts.rs` in full, `apic.rs`,
`drivers/ps2.rs`; `keel-kernel/src/selftest.rs`; everything under
`user/`; `xtask/src/qemu.rs` and `build.rs` changes. A clean result here
says nothing about those files.

## New findings (none blocking)

### C1. A crafted position-independent executable panics the loader

**Where**: `kernel/linux-abi/src/exec.rs`, `load`:

```
Kind::Relocatable => DYN_BASE + random::below(MMAP_RANDOM_PAGES) * PAGE - image.span().0,
```

**Problem**: the subtraction is unchecked and release builds have
`overflow-checks = true`. `DYN_BASE` plus the largest random offset is
below `0x5656_0000_0000`. An `ET_DYN` file whose first loadable segment
has a higher address (for example `0x7000_0000_0000`, which the parser
accepts) makes the subtraction underflow, and the kernel panics.
`check_bias` runs on the next line, too late.

**Reach**: none from user code today. Only the kernel calls `load`, on
files from the hash-pinned initramfs. It becomes a user-triggered kernel
panic the moment `execve`, or anything else that loads a file a program
supplies, exists. Established by reading; not run.

**Change**: compute the bias with `checked_sub` and return an
`ElfError`, or reject in the parser an `ET_DYN` image whose span starts
above `DYN_BASE`. Add the case to the parser's random-input test and a
host test.

**Done when**: the crafted file is refused with an error, covered by a
test, before the first system call that can load a program.

### C2. Process exit allocates kernel memory in proportion to the process

**Where**: `core::paging::clear_user_half`, called from
`hal::vm::AddressSpace::drop`.

**Problem**: teardown first collects every leaf address and every table
frame into two `Vec`s, then frees them. That is 8 bytes per resident
page, and a growing `Vec` briefly holds its old and new buffers. A
process that has taken all user memory exits while only the reserve is
free, so this comes out of the reserve. By my arithmetic it fits on the
target: about 16 MB for 8 GB, and under 200 MB at the 32 GB maximum
against a 256 MiB reserve. The margin shrinks as RAM grows, and a
failure here is a kernel panic on the exit path.

**Change**: free each leaf and table as the walk reaches it, with no
list. Not urgent; do it before per-compartment limits change the
reserve arithmetic in Phase 3.

### C3. One tmpfs write can take a large part of the reserve

**Where**: `core::vfs::grow_file` and the admission check in
`linux-abi::syscall::dispatch`.

**Problem**: admission is checked once, before the call. A write that
passes with free memory just above the reserve can then grow a file's
buffer by doubling, up to the 256 MiB cap, and that one allocation may
leave free memory well below the reserve. It fails cleanly if there is
not enough, and later calls are refused, so I see no way to reach zero
with it. It does mean the reserve is not the hard floor ADR 0011
describes.

**Change**: grow file buffers by a bounded step instead of doubling, or
re-check the reserve inside `grow_file` before large growth. Record the
limit in ADR 0011.

## Carried over, not findings

- **Boot chain.** The config hash is enrolled, but the bootloader is
  unsigned and Secure Boot is off. Until the owner signs it and turns
  Secure Boot on, the chain detects corruption and does not stop someone
  who can write the boot media (ADR 0010).
- **Self-tests in release kernels.** Still selected by the command line.
- **Test results share the serial line with user output**
  (`docs/STATUS.md`, hardening notes). Fine until hostile code runs.
- **Hardware.** Speculation mitigations, the x2APIC path and the
  invariant-TSC path have only run where the emulator or CI's virtual
  machine allows. Real confirmation is Phase 6.
