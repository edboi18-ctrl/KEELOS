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
