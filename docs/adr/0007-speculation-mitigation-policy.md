# ADR 0007: Speculation mitigation policy

Status: accepted (Phase 1, P1-S4; SR-14, SR-15). To be re-checked on the
real CPU in P6-S6.

## Context

SR-15 lists mitigations "from the spec author's knowledge" and requires
each to be checked against Intel's guidance and Linux's hardware
vulnerability documentation. Checked against Linux v6.12 and v6.18
(`Documentation/admin-guide/hw-vuln/`, `Documentation/arch/x86/mds.rst`,
`arch/x86/kernel/cpu/bugs.c` and `common.c`, `arch/x86/entry/calling.h`,
`arch/x86/include/asm/nospec-branch.h`, `msr-index.h`, `cpufeatures.h`;
all read 2026-11-22). Intel's own pages could not be fetched from this
environment; Linux's documentation cites them and is the reference used.

The target, an i5-8500 (family 6, model 0x9E, stepping 0xA), is in Linux's
INTEL_KABYLAKE row: MMIO stale data, RETBLEED, GDS, SRBDS (and VMSCAPE,
which concerns hypervisors). It has no enhanced IBRS and no
Hyper-Threading. ITS applies to that model only above stepping 0xC.

## Decision

- **Fail closed.** Affected unless the CPU reports the `*_NO` bit or
  Linux's rows say the model is not affected. Keel carries Linux's rows
  only for the four Skylake-family models; any other model is "assumed
  affected" for the model-listed bugs, and the boot log says so.
- **Page-table isolation stays on** even when RDCL_NO is set (SR-14 allows
  skipping it; Keel does not, until a measured reason exists).
- **Spectre v2 / Retbleed: legacy IBRS** on CPUs without enhanced IBRS:
  IA32_SPEC_CTRL is written with IBRS on every kernel entry, before any
  RET, and with the user value on every return to user mode, after the
  last RET. This is what Linux chooses by default for retbleed-affected
  Intel CPUs (`spectre_v2_select_mitigation`: SPECTRE_V2_IBRS). With
  enhanced IBRS, IBRS is set once. Retpolines are not used: the pinned
  stable toolchain does not build them, and on Skylake-family parts Linux
  uses IBRS anyway.
- **IBPB** whenever a different user address space is switched in (SR-15
  asks for it between compartments; doing it between any two processes is
  stricter and needs no compartment bookkeeping yet).
- **RSB filled** on every context switch, unconditionally, as Linux does.
- **SSBD always on** where available (SR-15: on for compartments; every
  user process will be in one).
- **VERW before every return to user mode** when MDS, TAA or MMIO stale
  data apply, issued even without MD_CLEAR (Linux's "VMWERV" behaviour),
  and reported as vulnerable in that case.
- **L1TF:** no not-present page-table entry ever holds bits; checked by the
  page-table walk in the self-tests (this also fixed F-0002).
- **Spectre v1:** user-controlled indices (system-call number, file
  descriptor) are clamped without a branch before use (Linux's
  `array_index_nospec`). There is no SWAPGS (ADR 0005).
- **SRBDS, GDS:** microcode mitigations; Keel clears their "disabled" bits
  in IA32_MCU_OPT_CTRL if firmware left them set. Without the microcode
  the item is reported vulnerable; P6-S8 loads current microcode.
- **SMT:** Keel uses one CPU until SMP (P6-S7).
- Every MSR access that depends on CPU support goes through
  `rdmsr_safe`/`wrmsr_safe`: a rejected write is reported and the
  dependent mitigation is switched off rather than crashing the kernel.

## Consequences

- Legacy IBRS costs two WRMSRs per kernel entry and exit; acceptable now,
  to be measured in Phase 7.
- Not implemented, and reported as vulnerable where they apply: the
  software branch-history clearing sequence for BHI (applies only with
  enhanced IBRS or under a hypervisor without BHI_DIS_S; not on the
  target), and ITS mitigations (not on the target's stepping).
- QEMU's emulator (TCG) offers none of the speculation-control features,
  so the IBRS, IBPB and MSR-fault paths run only under KVM (CI) and on
  real hardware. The VERW exit path and the RSB fill run on every test.
