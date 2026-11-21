//! Hardware-level self-test triggers, run only when the kernel command
//! line asks for them (spec section 15, kernel integration tests). They
//! add checks; they disable no security control (SR-21).

use core::arch::asm;

/// Executes INT3 with known values in 13 general registers and reports
/// whether the #BP round trip preserved all of them.
pub fn breakpoint_preserves_registers() -> bool {
    const PATTERN: [u64; 13] = [
        0x1111_0000_0000_0001,
        0x2222_0000_0000_0002,
        0x3333_0000_0000_0003,
        0x4444_0000_0000_0004,
        0x5555_0000_0000_0005,
        0x6666_0000_0000_0006,
        0x7777_0000_0000_0007,
        0x8888_0000_0000_0008,
        0x9999_0000_0000_0009,
        0xaaaa_0000_0000_000a,
        0xbbbb_0000_0000_000b,
        0xcccc_0000_0000_000c,
        0xdddd_0000_0000_000d,
    ];
    let mut regs = PATTERN;
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: interrupts off; the IDT gate for vector 3 is installed.
    //   The compiler has loaded the pattern into rax, rcx, rdx, rsi, rdi
    //   and r8-r15 (rbx and rbp are reserved by the compiler and cannot be
    //   operands; the stub's handling of them is identical to the others).
    // Instruction: `int3` raises #BP, a trap. The processor pushes a frame
    //   on the current stack (CPL 0, gate IST 0), the stub saves and
    //   restores every register around the Rust handler, and IRETQ returns
    //   to the next instruction.
    // Exit state: every bound register should hold its input value; each
    //   is declared `inout` so the compiler reads back what is really
    //   there. The exception frame was pushed below RSP, which the asm may
    //   do because `nostack` is not claimed. RFLAGS is restored by IRETQ,
    //   so `preserves_flags` holds.
    // Reference: SDM Vol. 2A "INT n/INTO/INT3/INT1"; section 7.15,
    //   "Interrupt 3—Breakpoint Exception (#BP)".
    // SAFETY: the #BP handler returns normally and restores all registers.
    unsafe {
        asm!(
            "int3",
            inout("rax") regs[0],
            inout("rcx") regs[1],
            inout("rdx") regs[2],
            inout("rsi") regs[3],
            inout("rdi") regs[4],
            inout("r8") regs[5],
            inout("r9") regs[6],
            inout("r10") regs[7],
            inout("r11") regs[8],
            inout("r12") regs[9],
            inout("r13") regs[10],
            inout("r14") regs[11],
            inout("r15") regs[12],
            options(preserves_flags),
        );
    }
    regs == PATTERN
}

/// A canonical lower-half address. Under Limine base revision 1 and later
/// the lower half is not mapped at entry (PROTOCOL.md, "Memory Layout at
/// Entry": the identity map exists for base revision 0 only), and Keel maps
/// nothing there yet.
const UNMAPPED_STACK: u64 = 0x0000_1000_0000_0000;

/// Forces a double fault and never returns.
///
/// It moves RSP to an unmapped address and pushes. The push raises #PF.
/// Delivering #PF at CPL 0 through a gate without IST uses the same
/// unmapped stack, so the delivery itself raises a second #PF, and a page
/// fault during delivery of a page fault is a double fault (SDM Table 7-5).
/// The #DF gate uses IST1, so its handler runs on a good stack. This is the
/// test that "double fault runs on its own stack" (P1-T2).
pub fn trigger_double_fault() -> ! {
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: interrupts off; GDT, TSS (with IST1 set) and IDT loaded.
    // 1. `mov rsp, {stack}` points the stack at unmapped memory. Nothing
    //    after this uses the old stack, hence `noreturn`.
    // 2. `push rax` writes to [stack - 8]: #PF.
    // 3. The processor tries to push the #PF frame at the same unmapped
    //    stack: #PF during #PF delivery, so #DF; the #DF gate switches to
    //    IST1 and the handler runs there.
    // 4. `ud2` is never reached; it is a backstop in case no fault occurs,
    //    and raises #UD, which also ends in the fatal-exception path.
    // Exit state: none; control never returns.
    // SAFETY: this deliberately ends the kernel; it is only called from the
    // `double_fault` self-test scenario.
    unsafe {
        asm!(
            "mov rsp, {stack}",
            "push rax",
            "ud2",
            stack = in(reg) UNMAPPED_STACK,
            options(noreturn),
        );
    }
}
