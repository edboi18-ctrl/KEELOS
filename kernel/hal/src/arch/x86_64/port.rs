//! x86 I/O-port access.
//!
//! These two functions are the only place in the kernel that executes the
//! `IN` and `OUT` instructions. User space never gets port access (SR-9).

use core::arch::asm;

/// Writes one byte to an I/O port.
///
/// # Safety
///
/// Port I/O talks directly to hardware. The caller must own the device at
/// `port` and must know that writing `value` there cannot violate memory
/// safety (for example by reprogramming a DMA-capable device).
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    // Assembly reasoning (spec section 1, rule 4)
    //
    // Entry state: the compiler has loaded `port` into DX and `value` into
    //   AL, as the operand bindings below request. The stack is not touched.
    // Instruction: `out dx, al` (opcode EE) writes the byte in AL to the
    //   I/O port whose number is in DX. In 64-bit mode at CPL 0 the
    //   instruction is always permitted (CPL <= IOPL holds for any IOPL).
    // Exit state: no register is modified and no RFLAGS bit is affected,
    //   which is why `preserves_flags` is sound; no memory is read or
    //   written (`nomem`); the stack pointer is not used (`nostack`).
    // Reference: Intel SDM Vol. 2B, "OUT - Output to Port" (operation and
    //   "Flags Affected: None").
    //
    // SAFETY: the instruction itself touches no memory and no register
    // beyond its operands; the hardware side effect is the caller's
    // obligation as stated in this function's safety contract.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Reads one byte from an I/O port.
///
/// # Safety
///
/// Reading a port can have side effects on the device (for example it can
/// pop a byte from a FIFO). The caller must own the device at `port`.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // Assembly reasoning (spec section 1, rule 4)
    //
    // Entry state: the compiler has loaded `port` into DX. AL is declared
    //   as an output, so its previous contents are dead.
    // Instruction: `in al, dx` (opcode EC) reads one byte from the I/O
    //   port whose number is in DX into AL. Permitted at CPL 0 as above.
    // Exit state: AL holds the byte read; the upper bits of RAX are
    //   unspecified to us, and only AL is read back as a `u8`. No other
    //   register and no RFLAGS bit changes (`preserves_flags`); no memory
    //   is accessed (`nomem`); the stack is not used (`nostack`).
    // Reference: Intel SDM Vol. 2A, "IN - Input from Port" (operation and
    //   "Flags Affected: None").
    //
    // SAFETY: as for `outb`; the device side effect is the caller's
    // obligation.
    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}
