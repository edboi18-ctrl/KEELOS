# Security findings

Any way out of a compartment, kernel memory disclosure, or unchecked user
pointer is recorded here and blocks the current phase until it is fixed
and covered by a regression test (spec section 1, security rule 6).

## Open

None.

## Closed

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
