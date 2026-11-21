//! CPU control primitives.

use core::arch::asm;

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

/// Whether maskable interrupts are currently enabled.
pub fn interrupts_enabled() -> bool {
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
    rflags & RFLAGS_IF != 0
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
