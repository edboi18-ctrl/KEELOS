# Phase 1 security audit, second pass

Audit date: 2026-11-22. Commit audited: `51e484c` (`main` after pull
requests #2 and #3).

**Verdict: not clear to start Phase 2.** Finding A1 lets any user program
panic the kernel, confirmed by running it. `docs/SECURITY-FINDINGS.md`
already treats unprivileged denial of service as a finding that blocks
the phase (F-0005 to F-0010), and lists none open. A1 belongs there. A2
and A3 are the same kind and should go with it. A4 to A8 do not block.

This file is a work list in the same form as `docs/PHASE1-AUDIT.md`.

## Status on the working branch

| # | Status |
| --- | --- |
| A1 | Fixed (F-0011, ADR 0011): 65530-mapping cap with merging, 65536-node tmpfs cap, fallible file growth, user page tables from the user pool (a third path found while fixing), and an admission check that refuses calls with ENOMEM once only the kernel's reserve is free. Regression tests `limits.map_count` (the proof of concept below, now ENOMEM after 65526 mappings), `limits.tmpfs_nodes` and `limits.reserve_admission`, each failing with its protection removed. |
| A2 | Fixed (same change): `mmap(NULL)` searches below its last placement first. `limits.map_null_preemptible` maps to the cap with a kernel thread on schedule; without the search cache it does not finish in 15 s. |
| A3 | Fixed. A device write no longer holds the file's lock, and user console text goes out in pieces of at most 64 bytes (ending after a newline, on UTF-8 character boundaries) with the console locks released between them, which also bounds framebuffer scrolling with interrupts off. Test `console.slow_uart_preemptible` slows the emulated UART to 115200 baud (a test knob in the serial driver) while a program writes 8 KiB (32 KiB at first, which overran the 15 s join under CI's nested KVM, where each UART port access is an exit to QEMU). |
| A4 | Fixed. Each `AddressSpace` has an id that is never reused, and the scheduler issues the barrier when the id changes (`sched::note_user_space`), not when the table address does. Test `mitigations.ibpb_keyed_by_space_id`: the same space twice gets no barrier; a dropped and recreated one gets a new id and a barrier. In the test boot the new space does get the freed table frame, and with the old keying on the table address the test fails. |
| A5 | Fixed. The kernel heap, device-register and kernel-stack regions start at random 2 MiB-aligned offsets in the lower 8 TiB of their 16 TiB windows (2^22 places each), chosen at the start of `paging::init` from a one-off generator seeded as the main one is (RDSEED, RDRAND, TSC jitter), before any of them is used. As Linux's `kernel_randomize_memory` does for its regions (`arch/x86/mm/kaslr.c` v6.12). Test boots print the bases; new check `kaslr.regions_vary` requires them on every boot and different between boots (7 distinct in 7 boots; with fixed offsets, 1, and the check fails). Normal boots print only whether it happened and the entropy quality. |
| A6 | Fixed (ADR 0012). A relative path through a directory handle uses that directory as its root, so `..` stops there (Linux's `openat2` RESOLVE_IN_ROOT behaviour). `O_CREAT` through a handle needs `CREATE`, which directory handles get by default and Phase 3 manifests can withhold. `AT_FDCWD` and absolute paths use the process root and working directory, which become the compartment's root in Phase 3. Test `fs.dirfd_confines`; with the old root it fails. The refusal side of `CREATE` cannot be exercised until handles can lose rights (duplication arrives with compartments). |
| A7 | All five fixed. (1) Vector 8 joins 2 and 18 as never a user fault, so a double fault stays fatal; no user program can produce one, so this is not testable directly. (2) `sched::EXITED` keeps the 1024 most recent statuses; `sched.exited_bounded` runs 1100 threads (1443 kept without the bound, and the test fails). (3) `duplicate` releases the reference when the map fails. (4) The rule now matches the code: interrupt handlers may allocate, since the heap lock is an `IrqMutex` and the reserve keeps such allocations from failing (`docs/locking.md`, `heap.rs`; the stale "handlers take no lock" note is corrected too). (5) `paging::init` clears CR4.PGE if set before switching tables, which flushes global entries (SDM Vol. 3 section 5.10.4.1, "MOV to CR4"); `paging.no_global_pages` checks it is clear. |
| A8 | Owner. The agent did not change `docs/STATUS.md` or `docs/REPOSITORY-SETUP.md` on this point: which settings are applied is for the owner to confirm. The tag ruleset does exist: pushing tag `v0.1.0` printed "Bypassed rule violations ... Cannot create ref due to creations being restricted" for the owner, the admin bypass working as `docs/REPOSITORY-SETUP.md` section 4 describes. |



About 22,000 lines were added since the first audit. This pass did not
read all of them.

- Read in full: `hal/arch/x86_64/entry.rs`, `switch.rs`, `paging.rs`;
  `hal/vm.rs`, `syscall.rs`, `sched.rs`, `memory.rs`, `heap.rs`,
  `sync.rs`, `console.rs`; all of `kernel/linux-abi` except `names.rs`
  and most of `abi.rs`; `core/vm.rs` (logic, not tests), `core/handle.rs`;
  the workflow check in `xtask/src/audit.rs`; `verify.rs` changes;
  `security.yml`; `CODEOWNERS`; ADRs 0005 and 0010.
- Read in part: `hal/arch/x86_64/idt.rs`, `gdt.rs`, `cpu.rs`,
  `userprog.rs`; `hal/random.rs`, `interrupts.rs`; `core/vfs.rs`;
  `xtask/src/build.rs`.
- Not read: `core/paging.rs`, `elf.rs`, `exec.rs`, `cpio.rs`, `acpi.rs`,
  `cpuvuln.rs`, `crypto.rs`, `rng.rs`, `signal.rs`, `tty.rs`,
  `keyboard.rs`, `poll.rs`; `hal/arch/x86_64/apic.rs`, `fpu.rs`;
  `hal/acpi.rs`, `mitigations.rs`, `time.rs`, `va.rs`,
  `drivers/ps2.rs`; `keel-kernel/src/selftest.rs` and `main.rs` beyond
  spot checks; everything under `user/`; `xtask/src/qemu.rs` changes.
  A clean result here says nothing about those files.
- Run in this audit (QEMU 8.2.2, TCG, no KVM, Ubuntu 24.04):
  `cargo test --locked --offline` passed; `cargo xtask audit --offline`
  passed (advisory check skipped); `cargo xtask test` passed, phases 0
  and 1 with all scenarios and tamper tests.
- CI: run 45053783867 on `main` at `51e484c` succeeded.
- Not run: `cargo xtask fuzz`, `cargo xtask dist`, anything under KVM or
  on real hardware.

## Summary

| # | Severity | Finding | How established |
| --- | --- | --- | --- |
| A1 | High, blocks | A user program can exhaust kernel memory and panic the kernel | Run: kernel panic reproduced |
| A2 | Medium | `mmap` without a usable hint scans every mapping with interrupts off | Code, plus one observation |
| A3 | Low to medium | Console writes hold interrupts off for the whole write | Code only |
| A4 | Low | IBPB is skipped when a new address space reuses a freed table address | Code only |
| A5 | Low | Kernel heap, stacks and device mappings are at fixed addresses | Code only |
| A6 | Low, before Phase 3 | A directory handle does not confine lookups; creating needs no right | Code only |
| A7 | Low | Five small robustness items | Code only |
| A8 | Note | Three documents disagree on whether the repository settings are applied | Docs, plus GitHub's branch list |

---

## A1. A user program can exhaust kernel memory and panic the kernel

**Reproduced.** A test program that maps single `PROT_NONE` pages in a
loop, each at a fresh hint address, ended the kernel on a 512 MB guest
after about 5.5 million calls:

```
poc: another 262144 mappings        (21 times)

*** KEEL KERNEL PANIC ***
panicked at .../library/alloc/src/alloc.rs:699:9:
memory allocation of 368 bytes failed
```

The patch that produced this is at the end of this file. It was run in a
scratch copy; nothing in the repository was changed.

**Cause**

1. Kernel allocations cannot fail gracefully. `hal::heap` returns null
   when no frame is left, and every caller uses the infallible `alloc`
   API (`BTreeMap::insert`, `Vec::push`, `vec![]`, `Arc::new`). There is
   no `try_reserve` anywhere in `kernel/`. A null return becomes Rust's
   allocation-error panic.
2. User programs can make the kernel allocate without limit:
   - `core::vm::Layout` has no cap on the number of mappings. Each
     `mmap` adds a `BTreeMap` entry, and adjacent mappings are never
     merged. This is what the proof of concept used.
   - `core::vfs::Fs` caps file bytes (`byte_limit`) but not the number of
     nodes. `openat(O_CREAT)` in a loop adds a node, a name and a
     directory entry each time. Not run, read only (`Fs::add`).
3. The user reserve (`memory::allocate_zeroed_user`) protects the kernel
   from user page faults only. It does nothing about memory the kernel
   allocates on a program's behalf.

The fuzzer did not find this because it takes millions of calls.

**Change**

- Cap mappings per address space and return `ENOMEM` beyond the cap, as
  Linux does with `vm.max_map_count` ("The default value is 65530",
  Linux v6.12 `Documentation/admin-guide/sysctl/vm.rst`).
  Merging adjacent mappings with equal protection would reduce the count
  for normal programs.
- Cap tmpfs nodes (`ENOSPC`), and count name and directory-entry bytes
  against a limit.
- Make user-driven allocations fallible and return `ENOMEM`: the paths in
  `linux-abi::syscall` (`vec![0u8; ...]` for `read`, `write`, `writev`,
  `poll`), `Layout::map`/`split_at`, `Fs::add`/`write`/`set_len`, the
  handle table, and `AddressSpace::protect`'s `parked` map. Caps alone
  are not enough once there is more than one process.
- Decide what an allocation failure inside the kernel proper should do
  (scheduler, interrupt path). A panic may be acceptable there, but it
  must not be reachable from user input.
- Record this in `docs/SECURITY-FINDINGS.md` with the next F-number.

**Done when**

- The proof of concept ends with `mmap` returning `ENOMEM`, the kernel
  still running, as a regression test in `cargo xtask test`.
- An equivalent test for `openat(O_CREAT)` in a loop.

---

## A2. `mmap` without a usable hint scans every mapping with interrupts off

**Where**: `core/src/vm.rs`, `Layout::find_gap`; called from
`hal::vm::AddressSpace::map` while it holds `inner`, an `IrqMutex`.

**Problem**: `find_gap` walks the mappings from the top down until it
finds a hole. Mappings made by `mmap(NULL, ...)` are packed downward from
the mmap base, so the first hole is below all of them and every call
visits every mapping. Cost per call grows with the number of mappings,
and interrupts are off for the whole walk, so the timer and scheduler
stop for that long.

**Observation**: the first proof-of-concept run used `mmap(NULL, ...)`.
It did not reach 262,144 mappings before the test run ended. The second
run, with hint addresses, made 5.5 million in a few minutes. I did not
measure the interrupts-off time directly.

**Change**: the cap from A1 bounds this. Beyond that, keep the lowest
address handed out and try just below it first, or track gaps in the
tree, so the common case does not scan.

**Done when**: a test maps up to the cap with `mmap(NULL, ...)` while
`sched.syscall_preemptible`-style timing shows the ticker thread still
running on schedule.

---

## A3. Console writes hold interrupts off for the whole write

**Where**: `linux-abi::syscall::write_to` holds the file's `IrqMutex`
across `fs::device_write`; `hal::console::_print` holds `SERIAL` (also an
`IrqMutex`) for the whole string.

**Problem**: one `write` to `/dev/console` sends up to 4096 bytes, up to
three times that after control bytes are replaced with U+FFFD, with
interrupts disabled throughout. At 115200 baud, 8N1, a UART sends 11,520
bytes a second, so 4096 bytes is about 0.36 s. A program that writes in a
loop would keep interrupts off almost all the time on a machine with a
real UART: one timer tick gets through per write. This is arithmetic from
the code. Under QEMU the serial port is instant, so it was not observed.

**Change**: do not hold the file lock across the device write (the
console has no file position). Send to the UART in small pieces and
release the lock between them, or queue the bytes and let a kernel thread
drain the queue.

**Done when**: a test with an artificially slow serial sink shows the
ticker thread keeping time while a program floods the console.

---

## A4. IBPB is skipped when a new address space reuses a freed table address

**Where**: `hal/src/sched.rs`, `schedule`:
`LAST_USER_CR3.swap(user_cr3) != user_cr3`.

**Problem**: the barrier is issued when the user-view table address
changes. When a process exits, its table frame is freed and the next
process can get the same frame. The addresses then compare equal and no
IBPB is issued between two different processes.

**Change**: compare an identifier that is never reused (a counter stored
in `AddressSpace`), or reset `LAST_USER_CR3` in `AddressSpace::drop`.

**Done when**: a host or in-kernel test creates, drops and recreates an
address space and sees the barrier requested.

---

## A5. Kernel heap, stacks and device mappings are at fixed addresses

**Where**: `hal/src/arch/x86_64/paging.rs`: `KERNEL_HEAP_BASE`
`0xffff_c000_0000_0000`, `MMIO_BASE` `0xffff_d000_0000_0000`,
`KERNEL_STACKS_BASE` `0xffff_e000_0000_0000`.

**Problem**: KASLR moves the kernel image and the direct map (Limine does
both). These three regions do not move, and stack addresses are handed
out first-fit, so the first kernel stacks are at known addresses on every
boot. SR-16 is met for the image only.

**Change**: add a random page-aligned offset to each base at boot, from
`hal::random`, keeping the regions apart. Extend `kaslr.layout_varies` to
compare them across boots.

---

## A6. A directory handle does not confine lookups; creating needs no right

**Where**: `linux-abi::syscall::openat`; `core::vfs::Fs::step`.

**Problem**

- With a directory handle as `dirfd`, a path containing `..` walks up to
  the directory's parent. It is stopped only at the process root, which
  is the filesystem root for every process today. A handle to `/a/b`
  therefore reaches all of `/`.
- `O_CREAT` creates a file with only `ENUMERATE` on the directory handle.
  `Rights::CREATE` exists and is never checked.
- With `AT_FDCWD` or an absolute path there is no handle at all: the
  working directory and root are ambient authority.

None of this crosses a boundary today, because there are no compartments
yet. It is the starting state compartments must not inherit.

**Change**: before Phase 3, clamp `..` at the directory the handle names
(pass it as the lookup's root), require `CREATE` for `O_CREAT` and record
it in `docs/syscalls.md`, and decide how `AT_FDCWD` and absolute paths
get their authority.

---

## A7. Small robustness items

1. `idt::exception_dispatch` treats any exception below 32 from user mode
   as a user fault, except NMI and machine check. A double fault with a
   user-mode frame would call `sched::exit_with` while running on the
   IST1 stack. I know of no way for user code to cause one. Add `8` to
   the excluded vectors so it stays fatal.
2. `sched::EXITED` keeps one entry per exited thread for ever. Remove the
   entry when the status is collected, or bound the map.
3. `hal::vm::AddressSpace::duplicate` retains a frame and then maps it.
   If the map fails, the function returns without releasing that
   reference, so the frame is never freed.
4. `docs/locking.md` and `heap.rs` say never to allocate in an interrupt
   handler. `linux-abi::tty::on_keyboard_byte` builds a `Vec` there, and
   `sched::schedule` (reached from the timer interrupt) builds one too.
   It is safe as written, because the heap lock disables interrupts.
   Change the rule or the code so they agree.
5. `cpu::write_cr3` relies on a comment that Limine leaves `CR4.PGE`
   clear. Clear the bit explicitly in `paging::init`, or assert it, so
   stale global translations from the bootloader can never survive.

---

## A8. Three documents disagree on the repository settings

- `docs/STATUS.md` says the owner carried out
  `docs/REPOSITORY-SETUP.md`, sections 1 to 6.
- `docs/REPOSITORY-SETUP.md` has every box unticked except the license
  line.
- `docs/PHASE1-AUDIT.md` says the owner part of finding 4 is open.

GitHub's branch list reports `main` as protected. I could not read the
ruleset details or the tag ruleset. The first audit's finding 3 depends
on the tag ruleset. Owner: confirm, tick the boxes, and correct whichever
documents are wrong.

---

## First-audit findings, re-checked

| # | Result |
| --- | --- |
| 1 | Fixed. `release`, `retain`, `references` are `pub(crate)`; outside `keel-hal` only `OwnedFrame` exists, not `Copy` or `Clone`, freed on drop. |
| 2 | Agent part done. The config hash is enrolled; `sr27.tamper.config` passed here. Signing and Secure Boot remain with the owner, and the docs now say so. |
| 3 | Fixed. `--source-ref refs/tags/v<version>` is derived from the file name, with tests for rejected names. |
| 4 | `CODEOWNERS` covers `/xtask/`. Settings: see A8. |
| 5 | Fixed. Allow-lists for triggers, runners, permissions and actions. It is still a hand-written reader of a YAML subset, so GitHub's parser and this one could in principle disagree; unusual YAML is refused rather than interpreted. |
| 6 | Fixed. `preserves_flags` removed from the GDT block. |
| 7 | Fixed. Guard pages below IST stacks; the `fault_in_panic` scenario passed here. |
| 8 | Fixed. HHDM and region checks in `memory::init`; addresses printed only on test boots. |

## Checked and found correct in this pass

- **Entry and exit.** Frame offsets in `entry.rs` match `TrapFrame`.
  Every return to user mode passes through `prepare_user_return`: user
  selectors forced, RFLAGS masked to `0x240DD5 | 0x202` (IOPL 0), RIP and
  RSP at or above `USER_END` replaced with 0. Returns use IRETQ only, so
  the SYSRET non-canonical-RCX fault does not apply. Every handler starts
  with `push 2; popfq`, clearing AC. No SWAPGS exists. An NMI or machine
  check arriving in the first instructions of the system-call entry runs
  on an IST stack and switches to the kernel tables itself.
- **User memory.** Only `copy_to_user` and `copy_from_user` touch it.
  The range check uses checked addition against `USER_START..USER_END`.
  A kernel-mode page fault is resolved only when RIP is exactly the
  `rep movsb` in the copy routines; anything else is fatal. Writes to
  read-only user pages fault (CR0.WP) and return `EFAULT`.
- **System calls.** No double fetch found: each handler copies user data
  once into a kernel buffer. Counts are capped before allocation
  (`MAX_RW_COUNT`, `UIO_MAXIOV`, `HANDLE_LIMIT`, `PATH_MAX`). No lock is
  held across a user copy. Unknown numbers, flags and requests fail
  closed. Structures copied out are built in zeroed buffers.
- **Page tables.** User view maps only the trampoline in the kernel half.
  Keel's tables never set the global bit. Writable and executable
  together is refused for user mappings. `PROT_NONE` pages are unmapped
  and parked, not left present.
- **Context switch.** FPU state is saved and restored eagerly on every
  switch. The RSB is filled on every switch.
- **Supply chain.** All 19 vendored crates are still byte-identical to
  crates.io and match `Cargo.lock`. No crate was added. The three
  workflows pass the policy check; `security.yml` has a read-only token
  and pinned actions.

## Proof of concept for A1

Applied to a scratch copy of `51e484c` and run with
`cargo xtask test --phase 1 --timeout 1500`. It replaces the `reserve`
test program, stops that program running on the Linux host, lowers guest
memory to 512 MB so the run is short, and lengthens the self-test's wait.
Do not merge it as it is: turn the loop into a regression test that
expects `ENOMEM`.

```diff
diff --git a/kernel/keel-kernel/src/selftest.rs b/kernel/keel-kernel/src/selftest.rs
index 30af904..c5d4688 100644
--- a/kernel/keel-kernel/src/selftest.rs
+++ b/kernel/keel-kernel/src/selftest.rs
@@ -1887,7 +1887,7 @@ pub fn phase1_mitigations(t: &mut Runner) {
 /// the console and the check waiting on it fails, instead of the whole
 /// run timing out with no clue where.
 fn join(id: sched::ThreadId) {
-    if !sched::join_timeout(id, 15_000) {
+    if !sched::join_timeout(id, 1_500_000) {
         kprintln!(
             "selftest: thread {} ({}) did not finish within 15 s",
             id.0,
diff --git a/user/keel-rt/src/sys.rs b/user/keel-rt/src/sys.rs
index 12ea7b2..801fb11 100644
--- a/user/keel-rt/src/sys.rs
+++ b/user/keel-rt/src/sys.rs
@@ -423,3 +423,8 @@ pub fn unassigned_syscall(number: u64) -> i64 {
     }
     call3(number, 0, 0, 0)
 }
+
+/// AUDIT PROOF OF CONCEPT helper: mmap with an address hint.
+pub fn mmap_hint(address: u64, length: u64) -> i64 {
+    call6(nr::MMAP, [address, length, 0, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0])
+}
diff --git a/user/tests/src/bin/reserve.rs b/user/tests/src/bin/reserve.rs
index c6b9f5b..bdd8bba 100644
--- a/user/tests/src/bin/reserve.rs
+++ b/user/tests/src/bin/reserve.rs
@@ -1,27 +1,25 @@
-//! Phase 1 acceptance item 4: reserve 64 GiB with
-//! mmap(PROT_NONE, MAP_NORESERVE). Must succeed, on Linux and on Keel, and
-//! cost no physical memory (the Keel self-test measures that from the
-//! address space this program leaves behind).
+//! AUDIT PROOF OF CONCEPT (not part of the repository): map single
+//! PROT_NONE pages until mmap fails or the kernel stops.
 #![no_std]
 #![no_main]
 
 use keel_rt::Startup;
-use keel_rt::sys::{self, Region};
-
-/// 64 GiB.
-const SIZE: u64 = 64 << 30;
+use keel_rt::sys;
 
 fn main(_: &Startup) -> i32 {
-    match Region::map_with(SIZE, 0, sys::MAP_NORESERVE) {
-        Ok(region) => {
-            // Touching it must fault, so do not; just report and keep it.
-            let _ = region.address();
-            sys::write(1, b"reserve: 64 GiB PROT_NONE reservation succeeded\n");
-            0
+    sys::write(1, b"poc: mapping single PROT_NONE pages\n");
+    let mut count: u64 = 0;
+    let mut at: u64 = 0x1000_0000_0000;
+    loop {
+        let r = sys::mmap_hint(at, 4096);
+        if r < 0 {
+            sys::write(1, b"poc: mmap returned an error; the kernel survived\n");
+            return 0;
         }
-        Err(_) => {
-            sys::write(2, b"reserve: mmap of 64 GiB failed\n");
-            1
+        at += 8192;
+        count += 1;
+        if count % 262_144 == 0 {
+            sys::write(1, b"poc: another 262144 mappings\n");
         }
     }
 }
diff --git a/xtask/src/build.rs b/xtask/src/build.rs
index 6864171..add3e5e 100644
--- a/xtask/src/build.rs
+++ b/xtask/src/build.rs
@@ -132,7 +132,7 @@ pub const TEST_PROGRAMS: &[TestProgram] = &[
         args: &[],
         env: &[],
         stdin: b"",
-        host: true,
+        host: false,
     },
     TestProgram {
         path: "test/longcall",
diff --git a/xtask/src/qemu.rs b/xtask/src/qemu.rs
index c76fb8f..e9857d4 100644
--- a/xtask/src/qemu.rs
+++ b/xtask/src/qemu.rs
@@ -168,7 +168,7 @@ fn base_command(disk: BootDisk, options: &RunOptions) -> Result<Command> {
 
     let mut command = Command::new(qemu);
     command.current_dir(&root);
-    command.args(["-machine", "q35", "-m", "4G", "-smp", "1"]);
+    command.args(["-machine", "q35", "-m", "512M", "-smp", "1"]);
     match &options.accel {
         // `-cpu host` needs an accelerator; `max` is the TCG equivalent.
         Some(accel) => command.args(["-accel", accel, "-cpu", "host"]),
```
