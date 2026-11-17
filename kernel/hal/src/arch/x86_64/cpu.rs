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
