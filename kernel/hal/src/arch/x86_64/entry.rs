//! Kernel entry and exit with page-table isolation (P1-T10, P1-S3; SR-14).
//!
//! While user code runs, CR3 holds the address space's *user view*, which
//! maps the user half and, of the kernel, only the entry trampoline: this
//! file's code, the per-CPU entry data, the GDT, IDT and TSS, the IST
//! stacks and the trampoline stack (all in `.text.keel_entry`,
//! `.data.keel_entry` and `.bss.keel_entry`). Every way into the kernel
//! switches to the *kernel view* before touching anything else; every
//! return to user mode switches back as its last step before IRETQ.
//!
//! Design choices (ADR 0005):
//! - Per-CPU entry data is reached RIP-relatively. Keel runs on one CPU
//!   until Phase 6 (decision D8), so there is exactly one copy, and the
//!   kernel never uses the GS register. The user's GS base (Wine keeps the
//!   Windows TEB there) therefore stays loaded throughout, and there is no
//!   SWAPGS anywhere: no SWAPGS ordering bugs and no Spectre-v1 SWAPGS
//!   variant. SMP will need a per-CPU scheme (revisit in P6-T8).
//! - System calls return through IRETQ, never SYSRET. SYSRET raises #GP in
//!   ring 0 if RCX is non-canonical and loads IOPL from R11 (SDM Vol. 2B
//!   "SYSRET"); IRETQ from a sanitized frame has neither problem. The cost
//!   is speed, which a later performance task can recover.
//!
//! Frame layout (low to high, 24 words = 192 bytes; see `TrapFrame`):
//!   pad, r15 ... rbx (14 registers), saved CR3, rax, vector, error code,
//!   rip, cs, rflags, rsp, ss.

use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use super::cpu;
use super::gdt::{KERNEL_CS, USER_CS, USER_DS, USER_STAR_BASE};
use super::idt::TrapFrame;

/// Per-CPU data read by the entry code. Field offsets are used in the
/// assembly below and checked by the assertions after the struct.
#[repr(C)]
pub struct EntryCpu {
    /// CR3 of the current thread's kernel view (offset 0).
    kernel_cr3: AtomicU64,
    /// CR3 of the current thread's user view, or 0 (offset 8).
    user_cr3: AtomicU64,
    /// Top of the current thread's kernel stack (offset 16).
    kernel_stack_top: AtomicU64,
    /// User RSP while a system call builds its frame (offset 24).
    user_rsp: AtomicU64,
}

const _: () = assert!(core::mem::offset_of!(EntryCpu, kernel_cr3) == 0);
const _: () = assert!(core::mem::offset_of!(EntryCpu, user_cr3) == 8);
const _: () = assert!(core::mem::offset_of!(EntryCpu, kernel_stack_top) == 16);
const _: () = assert!(core::mem::offset_of!(EntryCpu, user_rsp) == 24);
const _: () = assert!(core::mem::size_of::<TrapFrame>() == 24 * 8);

#[unsafe(link_section = ".data.keel_entry")]
static ENTRY_CPU: EntryCpu = EntryCpu {
    kernel_cr3: AtomicU64::new(0),
    user_cr3: AtomicU64::new(0),
    kernel_stack_top: AtomicU64::new(0),
    user_rsp: AtomicU64::new(0),
};

/// Speculation mitigations applied by the entry code (P1-S4, SR-15),
/// chosen at boot by `keel_core::cpuvuln`. In the trampoline data, so the
/// exit path can still read it after switching to the user view.
#[repr(C)]
pub struct EntryMitigations {
    /// Non-zero: VERW before every return to user mode (offset 0).
    verw: AtomicU8,
    /// Non-zero: legacy IBRS, write IA32_SPEC_CTRL on entry and exit (1).
    ibrs: AtomicU8,
    /// Selector VERW checks: the kernel data segment, as Linux's
    /// `mds_verw_sel` holds `__KERNEL_DS` (offset 2).
    verw_selector: u16,
    /// IA32_SPEC_CTRL while in the kernel and in user mode (low 32 bits;
    /// every bit Keel uses is below bit 11) (offsets 4 and 8).
    spec_ctrl_kernel: AtomicU32,
    spec_ctrl_user: AtomicU32,
}

const _: () = assert!(core::mem::offset_of!(EntryMitigations, verw) == 0);
const _: () = assert!(core::mem::offset_of!(EntryMitigations, ibrs) == 1);
const _: () = assert!(core::mem::offset_of!(EntryMitigations, verw_selector) == 2);
const _: () = assert!(core::mem::offset_of!(EntryMitigations, spec_ctrl_kernel) == 4);
const _: () = assert!(core::mem::offset_of!(EntryMitigations, spec_ctrl_user) == 8);

#[unsafe(link_section = ".data.keel_entry")]
static MITIGATIONS: EntryMitigations = EntryMitigations {
    verw: AtomicU8::new(0),
    ibrs: AtomicU8::new(0),
    verw_selector: super::gdt::KERNEL_DS,
    spec_ctrl_kernel: AtomicU32::new(0),
    spec_ctrl_user: AtomicU32::new(0),
};

/// Switches the entry-path mitigations on or off. Call with interrupts
/// disabled or before user mode starts. `ibrs` must only be set when
/// IA32_SPEC_CTRL exists (the entry code writes it unconditionally then).
pub fn set_mitigations(verw: bool, ibrs: bool, spec_ctrl_kernel: u64, spec_ctrl_user: u64) {
    MITIGATIONS
        .spec_ctrl_kernel
        .store(spec_ctrl_kernel as u32, Ordering::Relaxed);
    MITIGATIONS
        .spec_ctrl_user
        .store(spec_ctrl_user as u32, Ordering::Relaxed);
    MITIGATIONS.verw.store(u8::from(verw), Ordering::Relaxed);
    MITIGATIONS.ibrs.store(u8::from(ibrs), Ordering::Release);
}

/// What `set_mitigations` stored: `(verw, ibrs, kernel, user)`.
pub fn mitigations() -> (bool, bool, u64, u64) {
    (
        MITIGATIONS.verw.load(Ordering::Relaxed) != 0,
        MITIGATIONS.ibrs.load(Ordering::Acquire) != 0,
        u64::from(MITIGATIONS.spec_ctrl_kernel.load(Ordering::Relaxed)),
        u64::from(MITIGATIONS.spec_ctrl_user.load(Ordering::Relaxed)),
    )
}

const TRAMPOLINE_STACK_SIZE: usize = 4096;

/// The stack the CPU switches to (TSS.RSP0) on an interrupt from user
/// mode. It is mapped in the user view; the entry code immediately moves
/// the frame to the thread's kernel stack. The exit path uses it for the
/// final IRETQ frame.
#[repr(C, align(4096))]
struct TrampolineStack(UnsafeCell<[u8; TRAMPOLINE_STACK_SIZE]>);
// SAFETY: only the CPU and the entry assembly use this memory, with
// interrupts disabled; Rust never forms references into it.
unsafe impl Sync for TrampolineStack {}

#[unsafe(link_section = ".bss.keel_entry")]
static TRAMPOLINE_STACK: TrampolineStack =
    TrampolineStack(UnsafeCell::new([0; TRAMPOLINE_STACK_SIZE]));

/// Top of the trampoline stack (16-byte aligned).
pub fn trampoline_stack_top() -> u64 {
    TRAMPOLINE_STACK.0.get() as u64 + TRAMPOLINE_STACK_SIZE as u64
}

/// The "vector" the system-call path stores in the frame.
pub const SYSCALL_VECTOR: u64 = 0x100;

// Assembly reasoning (spec section 1, rule 4)
//
// keel_exception_common: reached from a per-vector stub (idt.rs).
//   Entry state: interrupts off (interrupt gates). Stack holds, from RSP:
//   vector, error code, RIP, CS, RFLAGS, RSP, SS. The stack is the
//   interrupted kernel stack (kernel-mode, non-IST), an IST stack (vectors
//   2, 8, 18), or the trampoline stack (user-mode, non-IST; TSS.RSP0).
//   All three are mapped in both views. CR3 is the kernel view, or the
//   user view if user code (or the entry/exit code itself, for an NMI or
//   machine check) was interrupted.
//   1. push rax; mov rax, cr3; push rax. Offsets now: [rsp]=old CR3,
//      [8]=rax, [16]=vector, [24]=error, [32]=RIP, [40]=CS.
//   2. If CR3 differs from the kernel view in ENTRY_CPU, load the kernel
//      view. The old value stays in the frame for the exit path.
//   3. From user mode (CS RPL 3) on the trampoline stack, i.e. not an IST
//      vector: copy the 9 words to the top of the thread's kernel stack
//      and switch RSP there. `push qword ptr [rsp + N]` computes the
//      address before decrementing RSP (SDM Vol. 2B "PUSH"), and `pop
//      qword ptr [rax + N]` uses RAX as base, so each push/pop pair moves
//      one word without another scratch register. The kernel stack top is
//      16-byte aligned, so after 9 words RSP is 8 mod 16, exactly as after
//      a hardware frame on an aligned stack.
//   4. keel_save_rest: push rbx, rcx, rdx, rsi, rdi, rbp, r8-r15 and one
//      pad word: 24 words in total, so RSP is 16-byte aligned. Then
//      `push 2; popfq` gives the handler a known RFLAGS: at CPL 0 POPF
//      writes every flag (SDM Vol. 2B "POPF", table of flag updates), so
//      AC = 0, DF = 0, IF = 0, TF = 0, IOPL = 0, NT = 0, bit 1 = 1.
//      Interrupt and exception delivery clears only TF, VM, RF and NT
//      (and IF for interrupt gates; SDM Vol. 3 section 7.12.1.3), not AC,
//      and user code may set AC at CPL 3. Without this a user thread
//      could set AC and have every kernel handler run with SMAP lifted
//      (SDM Vol. 3 section 5.6: SMAP applies only while AC = 0). POPF is
//      used rather than CLAC because CLAC raises #UD without SMAP.
//      IF was already 0 (all gates are interrupt gates).
//      Legacy IBRS (P1-S4, when MITIGATIONS.ibrs is set): write the
//      kernel IA32_SPEC_CTRL value (MSR 48h; WRMSR takes ECX = MSR,
//      EDX:EAX = value, SDM Vol. 2B "WRMSR"). RAX, RCX and RDX are already
//      saved in the frame, and no RET has executed since entry, so
//      indirect predictions trained in user mode cannot steer the kernel
//      before IBRS is set (Linux does the same in IBRS_ENTER,
//      arch/x86/entry/calling.h). Then call the Rust dispatcher with
//      RDI = frame.
//   keel_restore (RSP = frame): if returning to user mode with legacy
//      IBRS, write the user IA32_SPEC_CTRL value first (CS is at frame
//      offset 160). This is after the dispatcher's last RET, as Linux's
//      IBRS_EXIT requires; RAX, RCX and RDX are restored below. Then drop
//      pad, pop the 14 registers.
//   5a. Return to kernel mode: reload the saved CR3 if it is not the
//      kernel view (an NMI that interrupted entry or exit code), restore
//      rax, drop 4 words, IRETQ.
//   5b. Return to user mode: copy the 9 words to the top of the trampoline
//      stack, switch RSP there, load the saved CR3 (the user view, which
//      the dispatcher has set), restore rax, drop 4 words. If
//      MITIGATIONS.verw is set, VERW on the kernel data selector: on CPUs
//      with the MD_CLEAR microcode this overwrites the buffers MDS, TAA
//      and MMIO stale data leak from (Linux Documentation/arch/x86/
//      mds.rst; CLEAR_CPU_BUFFERS in nospec-branch.h); otherwise it only
//      sets ZF (SDM Vol. 2C "VERR/VERW"). Last, as Linux places it: after
//      every register is restored. RFLAGS comes from the frame, so the
//      flag changes do not matter. Then IRETQ. After the CR3 load only
//      trampoline pages are touched (the selector is in MITIGATIONS, in
//      `.data.keel_entry`).
//
// keel_syscall_entry: the SYSCALL target (IA32_LSTAR).
//   Entry state: CPL 0 with user RSP, user CR3 (user view), interrupts off
//   (IA32_FMASK clears IF, TF, DF, AC, NT and IOPL), RCX = user RIP,
//   R11 = user RFLAGS (SDM Vol. 2B "SYSCALL").
//   1. Save the user RSP in ENTRY_CPU; use RSP as the scratch register to
//      load the kernel-view CR3; load the thread's kernel stack.
//   2. Push a frame identical to a hardware interrupt frame (SS = user
//      data, the user RSP, R11 as RFLAGS, CS = user code, RCX as RIP),
//      error code 0, vector 0x100, rax, and the user-view CR3 to return
//      with; then continue at keel_save_rest. Same 24-word frame, same
//      alignment (kernel stack top is 16-byte aligned).
//   An NMI between the first instruction and the CR3 load arrives on its
//   IST stack and takes the "CR3 is not the kernel view" path in step 2
//   of the common code, so it never runs kernel code on user tables.
//
// keel_enter_user(frame = rdi): RSP := frame; jump to keel_restore. Used
//   for a thread's first entry to user mode with a frame built in Rust.
global_asm!(
    r#"
    .pushsection .text.keel_entry, "ax", @progbits

    .global keel_exception_common
    keel_exception_common:
        push rax
        mov rax, cr3
        push rax
        cmp rax, qword ptr [rip + {cpu}]
        je 2f
        mov rax, qword ptr [rip + {cpu}]
        mov cr3, rax
    2:
        test byte ptr [rsp + 40], 3
        jz keel_save_rest
        cmp qword ptr [rsp + 16], 2
        je keel_save_rest
        cmp qword ptr [rsp + 16], 8
        je keel_save_rest
        cmp qword ptr [rsp + 16], 18
        je keel_save_rest
        mov rax, qword ptr [rip + {cpu} + 16]
        sub rax, 72
        push qword ptr [rsp + 64]
        pop qword ptr [rax + 64]
        push qword ptr [rsp + 56]
        pop qword ptr [rax + 56]
        push qword ptr [rsp + 48]
        pop qword ptr [rax + 48]
        push qword ptr [rsp + 40]
        pop qword ptr [rax + 40]
        push qword ptr [rsp + 32]
        pop qword ptr [rax + 32]
        push qword ptr [rsp + 24]
        pop qword ptr [rax + 24]
        push qword ptr [rsp + 16]
        pop qword ptr [rax + 16]
        push qword ptr [rsp + 8]
        pop qword ptr [rax + 8]
        push qword ptr [rsp]
        pop qword ptr [rax]
        mov rsp, rax

    keel_save_rest:
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push rbp
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
        push 0
        push 2
        popfq
        cmp byte ptr [rip + {mit} + 1], 0
        je 5f
        mov ecx, 0x48
        mov eax, dword ptr [rip + {mit} + 4]
        xor edx, edx
        wrmsr
    5:
        mov rdi, rsp
        call {dispatch}

    .global keel_restore
    keel_restore:
        test byte ptr [rsp + 160], 3
        jz 6f
        cmp byte ptr [rip + {mit} + 1], 0
        je 6f
        mov ecx, 0x48
        mov eax, dword ptr [rip + {mit} + 8]
        xor edx, edx
        wrmsr
    6:
        add rsp, 8
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rbp
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        test byte ptr [rsp + 40], 3
        jnz 4f
        mov rax, qword ptr [rsp]
        cmp rax, qword ptr [rip + {cpu}]
        je 3f
        mov cr3, rax
    3:
        mov rax, qword ptr [rsp + 8]
        add rsp, 32
        iretq
    4:
        lea rax, [rip + {tramp} + {tramp_size}]
        sub rax, 72
        push qword ptr [rsp + 64]
        pop qword ptr [rax + 64]
        push qword ptr [rsp + 56]
        pop qword ptr [rax + 56]
        push qword ptr [rsp + 48]
        pop qword ptr [rax + 48]
        push qword ptr [rsp + 40]
        pop qword ptr [rax + 40]
        push qword ptr [rsp + 32]
        pop qword ptr [rax + 32]
        push qword ptr [rsp + 24]
        pop qword ptr [rax + 24]
        push qword ptr [rsp + 16]
        pop qword ptr [rax + 16]
        push qword ptr [rsp + 8]
        pop qword ptr [rax + 8]
        push qword ptr [rsp]
        pop qword ptr [rax]
        mov rsp, rax
        mov rax, qword ptr [rsp]
        mov cr3, rax
        mov rax, qword ptr [rsp + 8]
        add rsp, 32
        cmp byte ptr [rip + {mit}], 0
        je 7f
        verw word ptr [rip + {mit} + 2]
    7:
        iretq

    .global keel_syscall_entry
    keel_syscall_entry:
        mov qword ptr [rip + {cpu} + 24], rsp
        mov rsp, qword ptr [rip + {cpu}]
        mov cr3, rsp
        mov rsp, qword ptr [rip + {cpu} + 16]
        push {user_ds}
        push qword ptr [rip + {cpu} + 24]
        push r11
        push {user_cs}
        push rcx
        push 0
        push {syscall_vector}
        push rax
        push qword ptr [rip + {cpu} + 8]
        jmp keel_save_rest

    .global keel_enter_user
    keel_enter_user:
        mov rsp, rdi
        jmp keel_restore

    .popsection
    "#,
    cpu = sym ENTRY_CPU,
    mit = sym MITIGATIONS,
    tramp = sym TRAMPOLINE_STACK,
    tramp_size = const TRAMPOLINE_STACK_SIZE,
    dispatch = sym super::idt::exception_dispatch,
    user_ds = const USER_DS,
    user_cs = const USER_CS,
    syscall_vector = const SYSCALL_VECTOR,
);

unsafe extern "C" {
    fn keel_syscall_entry();
    fn keel_enter_user(frame: *const TrapFrame) -> !;
}

/// IA32_STAR, IA32_LSTAR, IA32_FMASK at C000_0081h, C000_0082h,
/// C000_0084h (AMD APM Vol. 2 section 6.1.1 and Table A-1; Intel SDM
/// Vol. 2B "SYSCALL"; Vol. 3 section 6.8.8).
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;
/// EFER.SCE (bit 0): enables SYSCALL/SYSRET.
const EFER_SCE: u64 = 1 << 0;
/// Flags cleared on SYSCALL: TF (8), IF (9), DF (10), IOPL (12-13),
/// NT (14), AC (18).
const SYSCALL_FLAG_MASK: u64 = 1 << 8 | 1 << 9 | 1 << 10 | 3 << 12 | 1 << 14 | 1 << 18;

/// RFLAGS bits user code may control: CF, PF, AF, ZF, SF, TF, DF, OF, AC,
/// ID. IOPL, NT, RF, VM, VIF and VIP are forced to 0 and IF to 1 on every
/// return to user mode (SR-9: IOPL must stay 0).
const USER_RFLAGS_MASK: u64 = 0x24_0DD5;
const RFLAGS_FIXED: u64 = 0x202;

/// Sets up the SYSCALL MSRs and points TSS.RSP0 at the trampoline stack.
/// Call once at boot, after paging.
pub fn init(kernel_cr3: u64) {
    ENTRY_CPU.kernel_cr3.store(kernel_cr3, Ordering::Release);
    // SAFETY: the trampoline stack is static and mapped in every view.
    unsafe { super::gdt::set_kernel_stack(trampoline_stack_top()) };
    let star = u64::from(USER_STAR_BASE) << 48 | u64::from(KERNEL_CS) << 32;
    // SAFETY: these MSRs exist on every x86-64 CPU (SYSCALL is
    // architectural in long mode, CPUID.80000001H:EDX[11]); the values
    // follow SDM 6.8.8 and the GDT layout in gdt.rs; LSTAR points at
    // canonical kernel code in the trampoline.
    unsafe {
        cpu::wrmsr(IA32_STAR, star);
        cpu::wrmsr(IA32_LSTAR, keel_syscall_entry as *const () as u64);
        cpu::wrmsr(IA32_FMASK, SYSCALL_FLAG_MASK);
        let efer = cpu::rdmsr(cpu::IA32_EFER);
        cpu::wrmsr(cpu::IA32_EFER, efer | EFER_SCE);
    }
}

/// Records the thread that is about to run: its kernel-view CR3, user-view
/// CR3 (0 for kernel threads) and kernel stack top. Interrupts must be
/// disabled (the scheduler holds its lock).
pub fn set_current(kernel_cr3: u64, user_cr3: u64, kernel_stack_top: u64) {
    ENTRY_CPU.kernel_cr3.store(kernel_cr3, Ordering::Relaxed);
    ENTRY_CPU.user_cr3.store(user_cr3, Ordering::Relaxed);
    ENTRY_CPU
        .kernel_stack_top
        .store(kernel_stack_top, Ordering::Relaxed);
}

/// Makes a frame safe to return to user mode with: user selectors,
/// sanitized RFLAGS, canonical user RIP and RSP, and the current thread's
/// user-view CR3. Returns false if the thread has no user view.
pub fn prepare_user_return(frame: &mut TrapFrame) -> bool {
    let user_cr3 = ENTRY_CPU.user_cr3.load(Ordering::Relaxed);
    if user_cr3 == 0 {
        return false;
    }
    frame.cs = u64::from(USER_CS);
    frame.ss = u64::from(USER_DS);
    frame.rflags = frame.rflags & USER_RFLAGS_MASK | RFLAGS_FIXED;
    frame.saved_cr3 = user_cr3;
    // A non-canonical RIP would fault in IRETQ at CPL 0; keep both inside
    // the user half. User code that sets them elsewhere then simply faults
    // in user mode.
    let user_end = keel_core::vm::USER_END;
    if frame.rip >= user_end {
        frame.rip = 0;
    }
    if frame.rsp >= user_end {
        frame.rsp = 0;
    }
    true
}

/// Enters user mode for the first time with the given entry point and
/// stack, and `argument` in RDI. Never returns; later entries to the kernel come back through
/// the entry code on this thread's kernel stack.
pub fn enter_user(rip: u64, rsp: u64, argument: u64) -> ! {
    let mut frame = TrapFrame {
        rip,
        rsp,
        rdi: argument,
        rflags: RFLAGS_FIXED,
        ..TrapFrame::default()
    };
    let _ = cpu::disable_interrupts();
    if !prepare_user_return(&mut frame) {
        panic!("enter_user on a thread without an address space");
    }
    // The frame stays where it is, in this function's stack frame: the
    // user-return path copies it to the trampoline stack before IRETQ, and
    // later entries from user mode build their frames at the top of the
    // kernel stack, so its location does not matter. (Writing it at the
    // top of the kernel stack instead would overwrite the live frames of
    // this very call chain.)
    // SAFETY: `frame` is a valid, 16-byte-aligned (TrapFrame is 192 bytes
    // of u64; the call below only needs 8-byte alignment for the pops)
    // frame on the current stack; keel_enter_user switches RSP to it and
    // leaves through the user-return path, abandoning everything else on
    // this stack. Interrupts are disabled until IRETQ.
    unsafe { keel_enter_user(&raw const frame) }
}
