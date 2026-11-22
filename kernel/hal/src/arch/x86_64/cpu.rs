//! CPU control primitives.

use core::arch::asm;
#[cfg(target_os = "none")]
use core::arch::global_asm;

/// Stops this CPU for good: interrupts off, then halt, in a loop.
///
/// Used when the kernel has nothing left to run or has panicked.
pub fn halt_forever() -> ! {
    loop {
        // Assembly reasoning (spec section 1, rule 4)
        //
        // Entry state: any. No operands; no register or stack slot is read.
        // Instructions:
        //   `cli` clears RFLAGS.IF so maskable interrupts cannot wake the
        //     CPU into a handler. At CPL 0 it is always permitted.
        //   `hlt` stops instruction execution until an interrupt, NMI, SMI
        //     or reset arrives. Only NMI/SMI can resume it with IF clear;
        //     if one does, execution continues after `hlt` and the
        //     surrounding `loop` halts again.
        // Exit state: IF is clear (so `preserves_flags` is NOT claimed);
        //   no general register, memory, or stack is touched (`nomem`,
        //   `nostack`).
        // Reference: Intel SDM Vol. 2A, "CLI - Clear Interrupt Flag" and
        //   "HLT - Halt".
        //
        // SAFETY: both instructions are privileged but memory-safe; the
        // kernel runs at CPL 0. Disabling interrupts here is the intent.
        unsafe {
            asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

/// Reads CR2, which holds the faulting linear address after a page fault
/// (SDM Vol. 3A section 7.15, "Interrupt 14—Page-Fault Exception (#PF)").
pub fn read_cr2() -> u64 {
    let value: u64;
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: CPL 0 (MOV from a control register is privileged).
    // Instruction: `mov {value}, cr2` copies CR2 into a general register.
    // Exit state: only the output register changes; no memory, stack or
    //   flags are touched (SDM Vol. 2B "MOV—Move to/from Control
    //   Registers": the flags are undefined for this instruction, so
    //   `preserves_flags` is NOT claimed).
    // SAFETY: reading CR2 has no side effects; the kernel runs at CPL 0.
    unsafe {
        asm!("mov {}, cr2", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Selectors currently loaded in CS, SS and the task register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentState {
    pub cs: u16,
    pub ss: u16,
    pub tr: u16,
}

/// Reads the CS, SS and TR selectors.
pub fn segment_state() -> SegmentState {
    let (cs, ss, tr): (u16, u16, u16);
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: any CPL 0 state.
    // Instructions: `mov r16, cs` and `mov r16, ss` copy the visible
    //   selector parts (SDM Vol. 2B "MOV", segment register source); `str
    //   r16` stores the task register selector (SDM Vol. 2B "STR").
    // Exit state: only the three outputs change. None of these
    //   instructions affects RFLAGS or memory.
    // SAFETY: reads of segment selectors have no side effects.
    unsafe {
        asm!(
            "mov {cs:x}, cs",
            "mov {ss:x}, ss",
            "str {tr:x}",
            cs = out(reg) cs,
            ss = out(reg) ss,
            tr = out(reg) tr,
            options(nomem, nostack, preserves_flags),
        );
    }
    SegmentState { cs, ss, tr }
}

/// RFLAGS.IF, the interrupt-enable flag (SDM Vol. 1 section 3.4.3.3).
const RFLAGS_IF: u64 = 1 << 9;

/// RFLAGS.AC, the alignment-check / SMAP-override flag (SDM Vol. 1
/// section 3.4.3.3; Vol. 3 section 5.6).
pub const RFLAGS_AC: u64 = 1 << 18;

/// Whether maskable interrupts are currently enabled.
pub fn interrupts_enabled() -> bool {
    rflags() & RFLAGS_IF != 0
}

/// The current RFLAGS.
pub fn rflags() -> u64 {
    let rflags: u64;
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: any.
    // Instructions: `pushfq` pushes RFLAGS; `pop {r}` moves it into a
    //   register. Net stack change zero; RFLAGS itself is not modified.
    // Exit state: `{r}` holds RFLAGS. Stack memory below RSP was used, so
    //   `nostack` is not claimed. No other memory is touched.
    // Reference: SDM Vol. 2B "PUSHF/PUSHFD/PUSHFQ".
    // SAFETY: reading RFLAGS has no side effects.
    unsafe {
        asm!("pushfq", "pop {r}", r = out(reg) rflags, options(nomem, preserves_flags));
    }
    rflags
}

/// Executes CPUID for `leaf` and `subleaf`; returns (EAX, EBX, ECX, EDX).
pub fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    // The compiler intrinsic handles RBX, which inline asm may not name.
    let r = core::arch::x86_64::__cpuid_count(leaf, subleaf);
    (r.eax, r.ebx, r.ecx, r.edx)
}

/// Protection features the CPU reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Features {
    /// Execute-disable bit: CPUID.80000001H:EDX.NX[20] (SDM Vol. 3 section 5.1.4).
    pub nx: bool,
    /// CPUID.07H.00H:EBX.SMEP[7] (SDM Vol. 3 section 5.1.4).
    pub smep: bool,
    /// CPUID.07H.00H:EBX.SMAP[20] (SDM Vol. 3 section 5.1.4).
    pub smap: bool,
    /// CPUID.07H.00H:ECX.UMIP[2]. Bit position from Linux
    /// `arch/x86/include/asm/cpufeatures.h` (X86_FEATURE_UMIP = word 16,
    /// the leaf 7 ECX word, bit 2); SDM 325383-093 no longer carries the
    /// CPUID bit tables.
    pub umip: bool,
}

/// Reads the protection features from CPUID.
pub fn features() -> Features {
    let (max_basic, ..) = cpuid(0, 0);
    let (max_extended, ..) = cpuid(0x8000_0000, 0);
    let (_, ebx7, ecx7, _) = if max_basic >= 7 {
        cpuid(7, 0)
    } else {
        (0, 0, 0, 0)
    };
    let (.., edx_ext) = if max_extended >= 0x8000_0001 {
        cpuid(0x8000_0001, 0)
    } else {
        (0, 0, 0, 0)
    };
    Features {
        nx: edx_ext & (1 << 20) != 0,
        smep: ebx7 & (1 << 7) != 0,
        smap: ebx7 & (1 << 20) != 0,
        umip: ecx7 & (1 << 2) != 0,
    }
}

/// CR0.WP (bit 16): supervisor writes honour read-only pages (SDM Vol. 3
/// section 2.5).
pub const CR0_WP: u64 = 1 << 16;
/// CR4.UMIP (bit 11): SGDT, SIDT, SLDT, SMSW and STR fault at CPL > 0.
pub const CR4_UMIP: u64 = 1 << 11;
/// CR4.SMEP (bit 20): the kernel cannot execute user pages.
pub const CR4_SMEP: u64 = 1 << 20;
/// CR4.SMAP (bit 21): the kernel cannot access user pages unless
/// RFLAGS.AC is set.
pub const CR4_SMAP: u64 = 1 << 21;
/// FS.Base and GS.Base MSRs (AMD APM Vol. 2, Table A-1: C000_0100h,
/// C000_0101h; SDM Vol. 3 section 4.5.3: WRMSR to either raises #GP if the
/// value is not canonical).
pub const IA32_FS_BASE: u32 = 0xC000_0100;
pub const IA32_GS_BASE: u32 = 0xC000_0101;
/// IA32_EFER MSR address (AMD APM Vol. 2, Table A-1: C000_0080h).
pub const IA32_EFER: u32 = 0xC000_0080;
/// IA32_EFER.NXE (bit 11, SDM Vol. 3 Table 2-1 "IA32_EFER MSR
/// Information"): enables the execute-disable bit in page tables.
pub const EFER_NXE: u64 = 1 << 11;

macro_rules! read_cr {
    ($name:ident, $reg:literal) => {
        /// Reads a control register.
        pub fn $name() -> u64 {
            let value: u64;
            // Assembly reasoning (spec section 1, rule 4)
            // Entry state: CPL 0.
            // Instruction: MOV from a control register into a general
            //   register (SDM Vol. 2B "MOV—Move to/from Control Registers").
            // Exit state: only the output register changes. The flags are
            //   undefined after this instruction, so `preserves_flags` is
            //   not claimed. No memory or stack access.
            // SAFETY: reading a control register has no side effects.
            unsafe {
                core::arch::asm!(concat!("mov {}, ", $reg), out(reg) value, options(nomem, nostack));
            }
            value
        }
    };
}

read_cr!(read_cr0, "cr0");
read_cr!(read_cr3, "cr3");
read_cr!(read_cr4, "cr4");

/// Writes CR0.
///
/// # Safety
///
/// The new value must keep the CPU in 64-bit paged mode (PE, PG set) and
/// must not disable protections the kernel relies on.
pub unsafe fn write_cr0(value: u64) {
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: CPL 0; `{}` holds the new value.
    // Instruction: `mov cr0, {}` (SDM Vol. 2B "MOV—Move to/from Control
    //   Registers"). It is serializing. Changing WP changes how later
    //   memory accesses are checked, so `nomem` is not claimed.
    // Exit state: CR0 holds the value; flags undefined; stack unused.
    // SAFETY: the caller guarantees the value is valid for this kernel.
    unsafe { core::arch::asm!("mov cr0, {}", in(reg) value, options(nostack)) }
}

/// Writes CR4.
///
/// # Safety
///
/// Only bits the CPU reports as supported may be set, and the change must
/// be compatible with the active page tables (for example SMAP must not be
/// enabled while the kernel still needs to touch user pages).
pub unsafe fn write_cr4(value: u64) {
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: CPL 0; `{}` holds the new value.
    // Instruction: `mov cr4, {}`, serializing; setting a reserved or
    //   unsupported bit raises #GP (SDM Vol. 2B, same entry). The change
    //   affects later memory accesses, so `nomem` is not claimed.
    // Exit state: CR4 holds the value; flags undefined; stack unused.
    // SAFETY: the caller guarantees only supported, compatible bits.
    unsafe { core::arch::asm!("mov cr4, {}", in(reg) value, options(nostack)) }
}

/// Loads CR3 with the physical address of a PML4.
///
/// # Safety
///
/// `pml4` must be the physical address of a valid 4-level page table that
/// maps the currently executing code, the current stack, and every other
/// address the kernel will touch, with suitable permissions.
pub unsafe fn write_cr3(pml4: u64) {
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: CPL 0; `{}` holds the PML4 physical address with the
    //   low 12 bits (PWT, PCD and reserved bits; CR4.PCIDE is 0) clear.
    // Instruction: `mov cr3, {}` switches the address space and flushes
    //   all non-global TLB entries (SDM Vol. 3 section 5.10.4.1). CR4.PGE
    //   is clear at entry under Limine base revision 5 and later, so no
    //   global translations from the bootloader survive.
    // Exit state: every later access is translated by the new tables. The
    //   stack pointer's address must be mapped there (caller contract).
    // SAFETY: the caller guarantees the new tables map everything in use.
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) pml4, options(nostack)) }
}

/// Reads a model-specific register.
///
/// # Safety
///
/// `msr` must be an MSR the CPU implements; reading an unimplemented one
/// raises #GP.
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: CPL 0; ECX holds the MSR address.
    // Instruction: `rdmsr` loads EDX:EAX with the MSR (SDM Vol. 2B "RDMSR").
    // Exit state: EAX and EDX hold the low and high halves (the upper
    //   halves of RAX and RDX are cleared). Flags are not affected; no
    //   memory or stack access.
    // SAFETY: the caller guarantees the MSR exists.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high,
            options(nomem, nostack, preserves_flags));
    }
    u64::from(high) << 32 | u64::from(low)
}

/// Writes a model-specific register.
///
/// # Safety
///
/// `msr` must exist, and `value` must be valid for it and compatible with
/// the kernel's state.
pub unsafe fn wrmsr(msr: u32, value: u64) {
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: CPL 0; ECX = MSR address, EDX:EAX = value.
    // Instruction: `wrmsr` (SDM Vol. 2B "WRMSR"). Some MSRs change memory
    //   behaviour (EFER.NXE, PAT), so `nomem` is not claimed.
    // Exit state: the MSR holds the value; flags not affected; no stack use.
    // SAFETY: the caller guarantees a valid MSR and value.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") value as u32,
            in("edx") (value >> 32) as u32, options(nostack, preserves_flags));
    }
}

/// Removes the TLB entry for the page containing `virt` on this CPU.
pub fn invalidate_page(virt: u64) {
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: CPL 0; `{}` holds a linear address.
    // Instruction: `invlpg [{}]` invalidates TLB entries and paging-
    //   structure caches for the page containing the address (SDM Vol. 2A
    //   "INVLPG"). It does not access the memory at that address. Flags are
    //   not affected; the stack is not used.
    // Exit state: the next access to that page walks the page tables.
    // SAFETY: invalidating a TLB entry can only make translations more
    // up to date; it has no other effect.
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags));
    }
}

/// Enables maskable interrupts.
///
/// # Safety
///
/// Every interrupt that can arrive must have a working handler, and no
/// spinlock that an interrupt handler takes may be held.
pub unsafe fn enable_interrupts() {
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: CPL 0.
    // Instruction: `sti` sets RFLAGS.IF (SDM Vol. 2B "STI"). Interrupts are
    //   recognised after the next instruction. RFLAGS changes, so
    //   `preserves_flags` is not claimed; interrupt handlers may run
    //   afterwards and touch memory, so `nomem` is not claimed either.
    // SAFETY: the caller guarantees handlers exist and no handler lock is held.
    unsafe { core::arch::asm!("sti", options(nostack)) }
}

/// Disables maskable interrupts and returns whether they were enabled.
pub fn disable_interrupts() -> bool {
    let was = interrupts_enabled();
    // Assembly reasoning (spec section 1, rule 4)
    // Instruction: `cli` clears RFLAGS.IF (SDM Vol. 2A "CLI"). Only makes
    //   the kernel run without interruption; memory is unaffected but the
    //   compiler must not move memory accesses across it, so `nomem` is not
    //   claimed.
    // SAFETY: disabling interrupts at CPL 0 cannot violate memory safety.
    unsafe { core::arch::asm!("cli", options(nostack)) }
    was
}

/// Enables interrupts and halts until one arrives, as one step.
///
/// # Safety
///
/// As for `enable_interrupts`.
pub unsafe fn enable_and_wait() {
    // Assembly reasoning (spec section 1, rule 4)
    // `sti` delays interrupt recognition until after the next instruction
    // (SDM Vol. 2B "STI"), so an interrupt cannot slip in between `sti` and
    // `hlt` and leave the CPU halted with nothing to wake it. `hlt` then
    // waits for an interrupt (SDM Vol. 2A "HLT"); after the handler's IRETQ,
    // execution continues after `hlt` with IF = 1.
    // SAFETY: as for `enable_interrupts`.
    unsafe { core::arch::asm!("sti", "hlt", options(nostack)) }
}

/// Reads the time-stamp counter.
pub fn read_tsc() -> u64 {
    let (low, high): (u32, u32);
    // Assembly reasoning (spec section 1, rule 4)
    // Instruction: `rdtsc` loads EDX:EAX with the TSC (SDM Vol. 2B
    //   "RDTSC"); allowed at CPL 0 regardless of CR4.TSD. No memory, stack
    //   or flags are touched.
    // SAFETY: reading the TSC has no side effects.
    unsafe {
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags));
    }
    u64::from(high) << 32 | u64::from(low)
}

/// Whether the TSC runs at a constant rate in all P-, C- and T-states:
/// CPUID.80000007H:EDX[8] (SDM Vol. 3 section 20.17.1, "Invariant TSC").
pub fn invariant_tsc() -> bool {
    let (max_extended, ..) = cpuid(0x8000_0000, 0);
    max_extended >= 0x8000_0007 && cpuid(0x8000_0007, 0).3 & (1 << 8) != 0
}

// Assembly reasoning (spec section 1, rule 4)
//
// keel_rdmsr_safe(msr = edi, out = rsi) -> eax (0 = read, 1 = #GP) and
// keel_wrmsr_safe(msr = edi, value = rsi) -> eax (0 = written, 1 = #GP):
// MSR access that survives an MSR the CPU (or emulator) does not have.
//   RDMSR reads MSR[ECX] into EDX:EAX; WRMSR writes EDX:EAX to MSR[ECX];
//   both raise #GP(0) for a reserved or unimplemented MSR or a reserved
//   bit (SDM Vol. 2B "RDMSR", "WRMSR"). In 64-bit mode the upper halves of
//   RAX and RDX are cleared by RDMSR, and ignored by WRMSR.
//   The #GP handler (`idt::dispatch_kernel`) recognizes a fault at exactly
//   `keel_rdmsr_safe_insn` or `keel_wrmsr_safe_insn` and resumes at the
//   matching `_fault` label, which returns 1. This is the same idea as
//   Linux's exception-table entries for rdmsr_safe/wrmsr_safe.
//   Clobbers RAX, RCX, RDX (caller-saved in the SysV ABI). No stack use
//   besides the return address.
#[cfg(target_os = "none")]
global_asm!(
    r#"
    .pushsection .text.keel_msr_safe, "ax", @progbits
    .global keel_rdmsr_safe, keel_rdmsr_safe_insn, keel_rdmsr_safe_fault
    keel_rdmsr_safe:
        mov ecx, edi
    keel_rdmsr_safe_insn:
        rdmsr
        shl rdx, 32
        or rax, rdx
        mov qword ptr [rsi], rax
        xor eax, eax
        ret
    keel_rdmsr_safe_fault:
        mov eax, 1
        ret

    .global keel_wrmsr_safe, keel_wrmsr_safe_insn, keel_wrmsr_safe_fault
    keel_wrmsr_safe:
        mov ecx, edi
        mov eax, esi
        mov rdx, rsi
        shr rdx, 32
    keel_wrmsr_safe_insn:
        wrmsr
        xor eax, eax
        ret
    keel_wrmsr_safe_fault:
        mov eax, 1
        ret
    .popsection
    "#
);

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn keel_rdmsr_safe(msr: u32, out: *mut u64) -> u32;
    fn keel_wrmsr_safe(msr: u32, value: u64) -> u32;
    static keel_rdmsr_safe_insn: u8;
    static keel_rdmsr_safe_fault: u8;
    static keel_wrmsr_safe_insn: u8;
    static keel_wrmsr_safe_fault: u8;
}

#[cfg(target_os = "none")]
/// Reads an MSR that may not exist; `None` if the read raised #GP.
pub fn rdmsr_safe(msr: u32) -> Option<u64> {
    let mut value = 0u64;
    // SAFETY: the routine writes only `value` and turns a #GP into a
    // return value; reading an MSR has no memory side effects.
    let failed = unsafe { keel_rdmsr_safe(msr, &raw mut value) };
    (failed == 0).then_some(value)
}

#[cfg(target_os = "none")]
/// Writes an MSR that may not exist; false if the write raised #GP.
///
/// # Safety
/// As [`wrmsr`]: the value must be safe for the machine (callers here only
/// write speculation-control MSRs).
pub unsafe fn wrmsr_safe(msr: u32, value: u64) -> bool {
    // SAFETY: the caller's contract; a #GP is turned into `false`.
    unsafe { keel_wrmsr_safe(msr, value) == 0 }
}

#[cfg(target_os = "none")]
/// Where to resume after a #GP at `rip`, if `rip` is one of the safe MSR
/// instructions.
pub(crate) fn msr_fixup(rip: u64) -> Option<u64> {
    if rip == &raw const keel_rdmsr_safe_insn as u64 {
        Some(&raw const keel_rdmsr_safe_fault as u64)
    } else if rip == &raw const keel_wrmsr_safe_insn as u64 {
        Some(&raw const keel_wrmsr_safe_fault as u64)
    } else {
        None
    }
}

/// `index` if `index < size`, else 0, computed without a branch so that a
/// mispredicted bounds check cannot use an out-of-range index
/// speculatively (Spectre v1, SR-15). This is Linux's x86
/// `array_index_mask_nospec` (`arch/x86/include/asm/barrier.h`): `cmp`
/// then `sbb` turns the carry flag into an all-ones or all-zero mask.
pub fn index_nospec(index: u64, size: u64) -> u64 {
    let mask: u64;
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: {i} = index, {s} = size.
    // Instructions: `cmp {i}, {s}` computes index - size and sets CF if
    //   index < size (unsigned borrow); `sbb {m}, {m}` computes m - m - CF
    //   = -CF: all ones when index < size, zero otherwise (SDM Vol. 2A
    //   "CMP", Vol. 2B "SBB"). The old value of {m} cancels out.
    // Exit state: {m} = mask; flags changed (not preserved). No memory.
    // SAFETY: arithmetic on registers only.
    unsafe {
        asm!(
            "cmp {i}, {s}",
            "sbb {m}, {m}",
            i = in(reg) index,
            s = in(reg) size,
            m = out(reg) mask,
            options(pure, nomem, nostack),
        );
    }
    index & mask
}

/// IA32_EFER, read with the plain RDMSR (EFER exists on every x86-64 CPU).
pub fn read_efer() -> u64 {
    // SAFETY: IA32_EFER is architectural in long mode; reading it has no
    // side effects.
    unsafe { rdmsr(IA32_EFER) }
}

/// The current stack pointer (for tests that check which stack is in use).
pub fn stack_pointer() -> u64 {
    let rsp: u64;
    // Assembly reasoning (spec section 1, rule 4)
    // Instruction: `mov {r}, rsp` copies RSP; nothing else changes.
    // SAFETY: reading a register has no side effects.
    unsafe {
        asm!("mov {r}, rsp", r = out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    rsp
}
