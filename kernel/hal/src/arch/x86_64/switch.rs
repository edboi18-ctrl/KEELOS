//! Kernel context switch (P1-T8).

use core::arch::global_asm;

// Assembly reasoning (spec section 1, rule 4)
//
// keel_context_switch(save: *mut u64 /* rdi */, load: u64 /* rsi */)
//   Called from Rust as an `extern "C"` function with interrupts disabled.
//   Entry state: [rsp] = return address into the scheduler. The System V
//     AMD64 ABI (section 3.2.1) makes rbx, rbp and r12-r15 callee-saved;
//     everything else is caller-saved, so the compiler already assumes it
//     is clobbered across this call. RFLAGS.DF is 0 (ABI).
//   1. Push the six callee-saved registers on the current stack.
//   2. `mov [rdi], rsp` records the outgoing thread's stack pointer.
//   3. `mov rsp, rsi` adopts the incoming thread's stack, which holds the
//      same six registers and a return address, either from its own
//      earlier call to this function or as prepared by `prepare_stack`.
//   3a. Fill the return stack buffer (SpectreRSB, SR-15; P1-S4): 16
//      rounds of two CALLs whose return addresses are never used (each
//      falls through to the next call; a speculative return into one of
//      them lands on INT3), then RSP += 16 per round to drop the pushed
//      return addresses, and an LFENCE against a mispredicted final JNZ.
//      After 32 calls the RSB holds only harmless entries, so a RET that
//      underflows or was trained by the previous thread cannot steer the
//      new one. This is Linux's 64-bit __FILL_RETURN_BUFFER
//      (arch/x86/include/asm/nospec-branch.h, RSB_CLEAR_LOOPS 32), which
//      Linux runs on every context switch (bugs.c, X86_FEATURE_RSB_CTXSW).
//      Uses EAX (caller-saved) and 16 bytes below the new stack pointer,
//      which the incoming thread does not use.
//   4. Pop the six registers in reverse order and `ret` into that thread.
//   Exit state: the incoming thread continues as if its call to
//     keel_context_switch had just returned, with its callee-saved
//     registers intact. FPU/SSE state is handled separately by the
//     scheduler (fpu.rs). Interrupts are still disabled.
//
// keel_thread_trampoline
//   Entry state: reached by the `ret` above on a new thread's first run,
//     with r12 = entry function and r13 = argument (from prepare_stack),
//     and RSP 16-byte aligned (prepare_stack places the return address so
//     that RSP is a multiple of 16 after it is popped).
//   `mov rdi, r12; mov rsi, r13` pass them as the first two arguments;
//   `call` pushes 8 bytes, so the callee starts with RSP = 8 mod 16, as
//     the ABI requires. `thread_start` never returns; `ud2` guards that.
global_asm!(
    r#"
    .pushsection .text, "ax", @progbits
    .global keel_context_switch
    keel_context_switch:
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15
        mov [rdi], rsp
        mov rsp, rsi
        mov eax, 16
    1:
        call 2f
        int3
    2:
        call 3f
        int3
    3:
        add rsp, 16
        dec eax
        jnz 1b
        lfence
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret

    keel_thread_trampoline:
        mov rdi, r12
        mov rsi, r13
        call {start}
        ud2
    .popsection
    "#,
    start = sym crate::sched::thread_start,
);

unsafe extern "C" {
    fn keel_context_switch(save: *mut u64, load: u64);
    static keel_thread_trampoline: u8;
}

/// Switches stacks: saves the current one into `*save` and resumes the
/// thread whose saved stack pointer is `load`.
///
/// # Safety
///
/// Interrupts must be disabled. `save` must stay valid until this thread
/// is resumed. `load` must be a stack pointer saved by this function or
/// returned by `prepare_stack`, for a stack that is still mapped.
pub unsafe fn switch(save: *mut u64, load: u64) {
    // SAFETY: forwarded from the caller.
    unsafe { keel_context_switch(save, load) }
}

/// Writes the initial frame for a new thread at the top of its stack and
/// returns the stack pointer to pass to `switch`. The first switch to it
/// runs `crate::sched::thread_start(entry, argument)`.
///
/// # Safety
///
/// `top` must be the 16-byte-aligned top of a mapped stack of at least
/// 64 bytes that nothing else uses.
pub unsafe fn prepare_stack(top: u64, entry: u64, argument: u64) -> u64 {
    // Layout from low to high: r15, r14, r13, r12, rbx, rbp, return.
    // After the six pops and `ret`, RSP = top, which is 16-byte aligned.
    let trampoline = &raw const keel_thread_trampoline as u64;
    let frame: [u64; 7] = [0, 0, argument, entry, 0, 0, trampoline];
    let sp = top - 7 * 8;
    // SAFETY: the caller guarantees `[top - 56, top)` is mapped, unused and
    // writable; `sp` is 8-byte aligned.
    unsafe { (sp as *mut [u64; 7]).write(frame) };
    sp
}
