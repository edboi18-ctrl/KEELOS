# Security findings

Any way out of a compartment, kernel memory disclosure, or unchecked user
pointer is recorded here and blocks the current phase until it is fixed
and covered by a regression test (spec section 1, security rule 6).

## Open

None.

## Closed

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
