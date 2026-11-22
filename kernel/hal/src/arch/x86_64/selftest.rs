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

/// Writes one byte to the kernel's own text, which must raise #PF with the
/// present and write bits set: text is mapped read-only and CR0.WP makes
/// the kernel obey that (SR-12, SR-13; spec section 8, security
/// acceptance P1 item 3). Never returns.
pub fn write_to_kernel_text() -> ! {
    let target = write_to_kernel_text as *const () as u64;
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: kernel page tables active; `{target}` holds the address
    //   of this function's first instruction, in the read-only text
    //   segment.
    // 1. `mov byte ptr [{target}], 0x90` attempts a one-byte store there.
    //    The PTE has R/W = 0 and CR0.WP = 1, so the CPU raises #PF with
    //    error code P = 1, W = 1 and CR2 = target (SDM Vol. 3 section 5.6,
    //    Figure 7-11). The store does not happen.
    // 2. `ud2` is a backstop: if the store succeeded, #UD ends the test in
    //    the fatal path with the wrong vector, so the test fails.
    // Exit state: none; control never returns (`noreturn`).
    // SAFETY: the store is expected to fault and is only issued from the
    // `write_kernel_text` self-test scenario, which ends the kernel.
    unsafe {
        asm!("mov byte ptr [{target}], 0x90", "ud2", target = in(reg) target, options(noreturn));
    }
}

/// One `ret` instruction (opcode C3) placed in writable, non-executable
/// kernel data.
#[used]
static mut DATA_RET: [u8; 16] = [0xC3; 16];

/// Calls into kernel data, which must raise #PF with the instruction-fetch
/// bit set: data pages carry XD = 1 (SR-12). Never returns.
pub fn execute_kernel_data() -> ! {
    let target = &raw const DATA_RET as u64;
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: kernel page tables active, EFER.NXE = 1; `{target}`
    //   holds the address of DATA_RET in the data segment (XD = 1).
    // 1. `call {target}` pushes a return address and jumps there. The
    //    instruction fetch from an XD page raises #PF with P = 1 and I/D = 1,
    //    CR2 = target (SDM Vol. 3 section 5.6, Figure 7-11).
    // 2. If the fetch were allowed, the `ret` there would return here and
    //    `ud2` would end the test with the wrong vector, failing it.
    // Exit state: none (`noreturn`).
    // SAFETY: the call is expected to fault and is only issued from the
    // `execute_data` self-test scenario, which ends the kernel.
    unsafe {
        asm!("call {target}", "ud2", target = in(reg) target, options(noreturn));
    }
}

/// Puts `value` in the low 64 bits of XMM0.
pub fn set_xmm0(value: u64) {
    // Assembly reasoning (spec section 1, rule 4)
    // `movq xmm0, {}` copies a general register into XMM0 (SDM Vol. 2B
    // "MOVQ"). CR4.OSFXSR is set by fpu::init, so SSE instructions are
    // allowed. The kernel is built without SSE, so no compiler-generated
    // code relies on XMM0; this is how the FPU-isolation test plants a
    // per-thread value. No memory, stack or flags are touched.
    // SAFETY: changes only XMM0, which kernel code never uses.
    unsafe { asm!("movq xmm0, {}", in(reg) value, options(nomem, nostack, preserves_flags)) }
}

/// Reads the low 64 bits of XMM0.
pub fn get_xmm0() -> u64 {
    let value: u64;
    // Assembly reasoning (spec section 1, rule 4)
    // `movq {}, xmm0` copies XMM0's low quadword out (SDM Vol. 2B "MOVQ").
    // SAFETY: reading XMM0 has no side effects.
    unsafe { asm!("movq {}, xmm0", out(reg) value, options(nomem, nostack, preserves_flags)) }
    value
}

/// Recurses with 512-byte frames until the stack runs into its guard page
/// (the `stack_overflow` scenario). Never returns.
#[inline(never)]
pub fn overflow_stack(depth: u64) -> u64 {
    let frame = core::hint::black_box([depth; 64]);
    if core::hint::black_box(true) {
        overflow_stack(depth + 1).wrapping_add(frame[63])
    } else {
        frame[0]
    }
}

/// Reads a user address directly, outside the user-copy routines. With
/// CR4.SMAP = 1 and RFLAGS.AC = 0 this must raise #PF even though the
/// page is present (SDM Vol. 3 section 5.6, supervisor-mode access
/// prevention). Used by the `smap` scenario; on a CPU without SMAP the
/// read succeeds and the scenario reports failure. Refuses (returns
/// `None`, reading nothing) any address outside the user half, so safe
/// code cannot use it to read kernel memory (audit finding 1).
pub fn read_user_directly(address: u64) -> Option<u8> {
    if !crate::vm::user_range_ok(address, 1) {
        return None;
    }
    // SAFETY: `address` is in the user half, where the kernel keeps no
    // Rust objects: only user pages, which are frames, not Rust values.
    // With SMAP on the read faults (the expected outcome); with SMAP off
    // it reads one byte of a user page, or faults if none is mapped there,
    // which the page-fault handler deals with like any kernel fault.
    Some(unsafe { (address as *const u8).read_volatile() })
}
