# ADR 0005: Kernel entry without SWAPGS, and returns to user mode by IRETQ only

Status: accepted (Phase 1, P1-T10 and P1-S3). Deviates from the P1-T10
task note "per-CPU kernel stack via `swapgs`" and from the "`sysret`"
half of "`syscall`/`sysret` path".

## Context

P1-S3 (SR-14) requires page-table isolation from the first version of
the entry code: while user code runs, the active tables map only an
entry trampoline. The trampoline must therefore find the kernel's CR3
and the thread's kernel stack with nothing but its own pages mapped.

Two well-documented hazards shape the design:

- **SWAPGS.** Every entry has to decide whether to execute SWAPGS from
  the interrupted CS, and NMI and machine-check entries can arrive in
  the few instructions where GS is in the wrong state. Getting this
  wrong gives the kernel a user-controlled GS base. Speculative SWAPGS
  is also its own vulnerability (CVE-2019-1125). Keel's kernel does not
  use GS for anything else.
- **SYSRET.** SYSRET raises #GP(0) when RCX is not canonical, and it
  does so at CPL 0 on the user's stack pointer (Intel SDM Vol. 2B
  "SYSRET", Operation: `IF (RCX is not canonical) THEN #GP(0)`, after
  the `IF (CPL ≠ 0)` check). This is the cause of CVE-2012-0217. SYSRET
  also loads RFLAGS from R11 (`RFLAGS := (R11 & 3C7FD7H) | 2`), which
  includes IOPL, so R11 must be sanitized on every path.

## Options

1. SWAPGS-based per-CPU area and SYSRET fast path, as Linux does, with
   its paranoid-entry handling for NMI/#MC/#DB.
2. A per-CPU area reached RIP-relatively inside the trampoline (no
   SWAPGS), and a single return path through IRETQ for interrupts,
   exceptions and syscalls alike.

## Decision

Option 2.

- `hal::arch::x86_64::entry::ENTRY_CPU` (in `.data.keel_entry`) holds the
  kernel CR3, the current user CR3, the current thread's kernel stack
  top and a scratch slot for the user RSP. Entry code addresses it as
  `[rip + ENTRY_CPU]`; it is mapped in both views. GS is never used, so
  there is no SWAPGS anywhere and no state to get wrong on an NMI.
- TSS.RSP0 points at a 4 KiB trampoline stack in `.bss.keel_entry`.
  Entries from user mode copy the 9-word hardware frame to the thread's
  kernel stack after switching CR3; exits copy it back. IST vectors (NMI,
  #DF, #MC) stay on their IST stacks, which are mapped in both views.
- Every entry compares CR3 with the kernel view and switches if needed;
  every exit restores the CR3 saved in the frame. An NMI that interrupts
  the entry or exit code itself therefore runs with kernel tables and
  returns to whatever view was active.
- System calls return with IRETQ. The frame's RIP and RSP are replaced
  with 0 if they are outside the user half (the thread then faults in
  user mode, not in the kernel), CS and SS are forced to the user
  selectors, and RFLAGS is reduced to the user-controllable bits
  (`& 0x240DD5 | 0x202`: IOPL, NT, RF, VM, VIF and VIP cleared, IF set;
  SR-9).
- Every handler starts with `push 2; popfq`, which clears AC, DF, TF,
  IOPL and NT. Interrupt delivery does not clear AC (SDM Vol. 3 section
  7.12.1.3), so without this a user thread with AC set would run kernel
  handlers with SMAP lifted. See `docs/SECURITY-FINDINGS.md`.

## Consequences

- One exit path to review and test instead of two. IRETQ is slower
  than SYSRET by some tens of cycles per syscall; measure in Phase 7
  before considering a SYSRET path, which would need the canonical
  check and R11 sanitizing above.
- RIP-relative per-CPU data works for one CPU. Before a second CPU is
  started, each CPU needs its own copy: either a per-CPU alias page at a
  fixed virtual address in each CPU's top-level tables, or a switch to
  SWAPGS with paranoid entry handling. That decision gets its own ADR.
- Page-table isolation is always on and does not use PCIDs yet. P1-S4
  will select it from `IA32_ARCH_CAPABILITIES.RDCL_NO`, and PCID use
  (SR-14 note) is tracked for Phase 7 performance work.
