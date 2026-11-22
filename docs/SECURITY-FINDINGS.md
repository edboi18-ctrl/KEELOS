# Security findings

Any way out of a compartment, kernel memory disclosure, or unchecked user
pointer is recorded here and blocks the current phase until it is fixed
and covered by a regression test (spec section 1, security rule 6).

## Open

None.

## Closed

F-0005 to F-0009 were found on 2026-11-22 by the system-call fuzzer
(`cargo xtask fuzz`, security acceptance P1 item 6), each a denial of
service reachable from an unprivileged user program. F-0010, of the same
kind, was found the same day by CI.

### F-0010: getrandom read a clock device for every 256 bytes

Found 2026-11-22 by CI, not by the fuzzer: `sched.syscall_preemptible`
failed on 5 of 6 pushes to the working branch under KVM (GitHub-hosted
runner, Intel model 0xAD), always the same way: `longcall` (one 128 MiB
getrandom) did not finish within 15 s, while the ticker thread kept
running normally (about 2,490 ticks), so preemption (F-0008) was not
the problem. Under QEMU TCG locally the same call took 4.3 s. These CI
failures went unnoticed for several pushes because CI was not checked
after each one.

Cause. `getrandom` drew from the generator once per 256-byte chunk
(524,288 draws for 128 MiB), and every draw read the monotonic clock to
decide whether 60 s had passed since the last reseed. Each clock read
ran CPUID twice (to ask whether the TSC is invariant), and CPUID always
causes a VM exit (Intel SDM Vol. 3, section 28.1.2). QEMU's `-cpu host`
also hides invariant TSC by default (QEMU 8.2.2 `target/i386/cpu.c`:
`unmigratable_flags = CPUID_APM_INVTSC`, `migratable` defaults to true),
so the clock fell back to the HPET, an emulated device whose every read
is a further exit to QEMU. On a nested-virtualization runner that is
about 1.5 million expensive exits for one system call. A Windows program
asking for random bytes in a loop would have been just as slow on any
virtual machine.

Fix, following Linux v6.12 `drivers/char/random.c`:
- `hal::random` checks the reseed interval in timer ticks
  (`time::ticks()`, an in-memory counter), as Linux uses jiffies; no
  random-number request touches a clock device.
- `getrandom` takes one `keel_core::rng::Stream` per call (keyed with
  fresh generator output under the lock once, as `get_random_bytes_user`
  does with `crng_make_state`) and fills every chunk from it without the
  lock.
- `time::monotonic_nanos` decides once at boot whether to use the TSC
  instead of running CPUID on every read.

Regression test: `random.one_draw_per_getrandom` counts generator draws
while `longcall` runs: 5 with the fix (loading the program draws a few
for address randomization), 524,293 with the per-chunk draw restored,
which makes the test fail. Host tests cover `Stream` (needs a seed, no
keystream byte given out twice, block number split over counter and
nonce). Under TCG `longcall` went from 4.3 s to 3.5 s; the KVM result is
whatever the next CI run shows.

### F-0009: kernel address space for heap pages and stacks was never reused

- Found: free frames after the first one-hour fuzz session were 120 below
  their starting count. Per-run counters showed every address space freed
  and the heap's pages flat; the missing frames were new kernel page
  tables.
- Problem: the kernel heap's page source and the kernel-stack allocator
  were bump pointers that never reused address space (a known Phase 1
  shortcut, listed under P1-T5). read(2) and write(2) allocate a 4 KiB
  buffer per call, which used 8 KiB (with its guard page) of the 64 GiB
  heap region for good: about 8.4 million calls, seconds of work on real
  hardware, would exhaust it, after which every kernel allocation fails
  (a kernel panic). Every thread likewise used 68 KiB of the stack region
  for good (about a million threads). On the way, each new 2 MiB of
  address space left a page-table frame behind.
- Fix: `hal::va::VaRanges`: a bump pointer plus a fixed-size list of
  freed ranges (1024; it may not allocate, as it runs under the heap
  lock), best-fit reuse, merging of neighbours, and return of a top-most
  range to the bump pointer. Every allocation keeps an unmapped guard page
  after it; kernel stacks also keep one below (the region's first page is
  never mapped). The heap and the kernel stacks each use one. Kernel page
  tables are now bounded by the peak of live allocations.
- Regression tests: `heap.va_reused` (100,000 page-sized allocations,
  each freed: heap address space unchanged; 800,000 KiB with reuse
  disabled), `sched.stack_va_reused` (300 threads: stack space unchanged;
  20 MB with reuse disabled), host tests `va_ranges_reuse_freed_space` (a
  million allocate/free cycles) and `va_ranges_merge_and_respect_the_end`.

### F-0008: system calls ran with interrupts disabled

- Problem: `exception_dispatch` is entered with interrupts off and called
  the system-call handler directly, so every call ran to completion with
  no timer tick. One 2 GiB `getrandom` (the MAX_RW_COUNT cap, as on
  Linux) took 70 s under QEMU's emulator with every other thread stopped,
  and any long call stalled the whole machine. Present since P1-T10.
- Fix: `hal::syscall::dispatch` enables interrupts for the handler and
  disables them before the exit path, as Linux does. Safe because every
  kernel lock is an `IrqMutex` (interrupts off while held), so nothing is
  preempted holding a lock (docs/locking.md).
- Regression test: `sched.syscall_preemptible`: a kernel thread counting
  5 ms sleeps keeps running while `user/tests/longcall` is inside one
  128 MiB getrandom (724 ticks in 4 s; 2 ticks with the fix removed).

### F-0007: one program could take every free frame

- Problem: demand-zero and copy-on-write faults allocated from the same
  pool as the kernel, with no floor. A program writing into a huge
  mapping drove free frames to 0, leaving the kernel without memory for
  page tables, its heap or stacks.
- Fix: user page allocations (`memory::allocate_zeroed_user`) fail once
  only the kernel reserve is free (1/16 of memory, 16 MiB to 256 MiB); the
  access then gets EFAULT or ends the program with SIGSEGV status. The
  first refusal is logged. Interim floor until per-compartment memory
  limits (SR-8, P3-S4).
- Regression test: `memory.user_reserve` (raises the reserve above the
  free count: a user frame is refused, a kernel frame is not); fails with
  the check removed. Fuzz sessions now end with free frames back at their
  starting count.

### F-0006: munmap and mprotect took time in proportion to the range

- Problem: `AddressSpace::unmap_pages` and `protect` visited every page
  of the affected range. A reservation can be terabytes, so one munmap or
  mprotect over it kept the kernel busy for hours (the first fuzz session
  stopped in `unmap_pages`).
- Fix: `keel_core::paging::next_present_small` finds the next present
  page, skipping the whole span of an absent table entry; both loops visit
  only present pages and the parked PROT_NONE frames in the range.
- Regression tests: `vm.huge_range_fast` (mprotect twice and munmap an
  empty 64 TiB reservation: 0 ms; the old loop needs 2^34 steps) and the
  host test `next_present_small_skips_empty_spans`.

### F-0005: the unknown-syscall log grew without limit

- Problem: the first call of each unimplemented number was logged and
  the number kept in a `BTreeSet`. With 64-bit numbers a program could add
  an entry, and a serial line, per call: unbounded kernel memory and a
  flooded serial line.
- Fix: a fixed 512-bit bitmap for numbers in the table; numbers outside
  it are logged once in all.
- Regression test: `syscall.log_bounded` (1000 distinct out-of-range
  numbers add at most one line); fails with the old behaviour restored.

### F-0004: a user write to the console could freeze the kernel

- Found: 2026-11-22, the intermittent phase-1 test timeout (2 in about
  60 full runs). Located with the QEMU register snapshot added for it:
  RIP in `console::_print`, spinning on the framebuffer console's lock,
  RFLAGS 0x2 (interrupts off), not halted.
- Problem: the console locks (SERIAL, FRAMEBUFFER) were plain spinlocks.
  A kernel thread printing with interrupts on (the echo thread, or the
  boot thread) could be preempted while holding one; a system call,
  which runs with interrupts off, then writing to /dev/console spun on it
  forever, and with interrupts off the timer could never switch back to
  the holder. Any program writing to the console while the kernel was
  printing could freeze the whole machine: a denial of service reachable
  from user mode. Present since the console became writable from user
  mode (P1-T13); timing made it rare.
- Fix: both console locks, and the interrupt-routing lock, are
  `IrqMutex`es, which keep interrupts off while held, so a holder is
  never preempted. `sync.rs` states the rule: any lock that code with
  interrupts off may take must be an `IrqMutex`.
- Regression test: `console.lock_disables_interrupts` (records the
  interrupt flag from inside a print); checked to fail with the old
  console code.

### F-0003: a context switch undid `with_address_space`

- Found: 2026-11-22, from an intermittent failure of the `smap` scenario
  after KASLR changed boot timing (P1-S5). In code since P1-T9.
- Problem: `vm::with_address_space` loaded another address space's CR3
  directly. If the thread was preempted inside it, the scheduler restored
  the thread's own recorded space (the kernel's tables, for a kernel
  thread), so the rest of the work ran without the borrowed mappings: the
  ELF loader could fail with a spurious EFAULT, and the SMAP scenario saw
  a not-present page. It also always returned to the kernel's tables, even
  for a caller running in a process. Impact: reliability; no access to
  the wrong address space was possible (the fallback tables map no user
  memory).
- Fix: `sched::swap_space` makes the borrowed space the thread's recorded
  space for the duration and restores the previous one afterwards.
- Regression test: `vm.borrowed_space_survives_switch` (sleeps and yields
  inside the borrowed space, then reads it back); checked to fail with the
  old code.

### F-0002: mprotect(PROT_NONE) left populated pages readable

- Found: 2026-11-22, while checking the page tables for L1TF (P1-S4), in
  code committed with P1-T9 (not in any release).
- Problem: `AddressSpace::protect` rewrote present pages with the new
  rights, and a page with no rights at all still became a present,
  user-readable page. Memory made PROT_NONE after it was touched (guard
  pages, freed allocator pages, Wine's reserved ranges) stayed readable
  by the process and by the kernel's user copies. Confirmed with a test:
  write(2) from such a page returned its bytes instead of EFAULT.
- Fix: PROT_NONE removes the page-table entry entirely (it becomes zero)
  and keeps the frame in a per-address-space table; raising the
  protection maps it back; munmap, MAP_FIXED, fork and teardown handle the
  parked frames. Because the entry is zero rather than "not present with
  an address", this also satisfies the L1TF rule in SR-15.
- Regression tests: `user/tests/syscalls` checks "a PROT_NONE mapping
  refuses kernel reads (EFAULT)", passing under Linux and checked to fail
  on Keel before the fix; in-kernel `vm.prot_none_hides_pages`,
  `vm.prot_none_frames_returned`, `l1tf.no_stale_entries`.

### F-0001: kernel handlers ran with RFLAGS.AC from user mode (SMAP bypass)

- Found: 2026-11-22, during review of the P1-T10 entry code, before the
  code was committed or released.
- Problem: interrupt and exception delivery clears TF, VM, RF, NT and,
  for interrupt gates, IF, but not AC (Intel SDM Vol. 3 section
  7.12.1.3), and user code can set AC with POPF. A user thread that set
  AC and then took a timer interrupt or fault ran the kernel handler
  with AC = 1, which disables SMAP for explicit supervisor accesses (SDM
  Vol. 3 section 5.6). SYSCALL was not affected: IA32_FMASK clears AC.
- Fix: every handler starts with `push 2; popfq` (AC, DF, TF, IOPL, NT
  cleared) in `kernel/hal/src/arch/x86_64/entry.rs`.
- Regression test: `user.ac_cleared_on_entry` (user program sets AC,
  then faults; the handler's RFLAGS must have AC = 0). Checked to fail
  with the fix removed.
