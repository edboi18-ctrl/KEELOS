//! Interrupt descriptor table and exception entry (P1-T2).
//!
//! References:
//!  - Intel SDM Vol. 3 (325384-093): Table 7-1 "Protected-Mode Exceptions
//!    and Interrupts" (vectors and which push an error code); section
//!    7.14.1 and Figure 7-8 "64-Bit IDT Gate Descriptors"; section 7.14.2
//!    "64-Bit Mode Stack Frame" (16-byte alignment, SS:RSP always pushed);
//!    section 7.14.3 "IRET in IA-32e Mode"; section 7.14.5 "Interrupt Stack
//!    Table"; Figure 7-9 (frame layout); Table 7-5 "Conditions for
//!    Generating a Double Fault".
//!  - AMD64 APM Vol. 2 (24593 rev. 3.46): Table 8-1; vectors 29 (#VC) and
//!    30 (#SX) push an error code (sections 15.35 and 15.28). They only
//!    occur in AMD secure-virtualisation setups, but a stub that guessed
//!    wrong would misread the whole frame, so they are handled as
//!    error-code vectors.
//!
//! Every vector has a gate. Vectors 0-31 are exceptions; vectors 32-255
//! are interrupts, dispatched to `crate::interrupts` (P1-T6).

#[cfg(target_os = "none")]
use core::arch::{asm, global_asm};
#[cfg(target_os = "none")]
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "none")]
use super::gdt::DescriptorTablePointer;
use super::gdt::{self, IstSlot, KERNEL_CS};

/// Register state saved by the exception entry stub, in memory order.
///
/// Built by the entry code in entry.rs: a pad word, the general
/// registers (r15 lowest), the CR3 at entry, rax, then the vector and
/// error code pushed by the per-vector stub, then the five words the
/// processor pushed (Figure 7-9).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrapFrame {
    /// Alignment padding (keeps the frame a multiple of 16 bytes).
    pub pad: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    /// CR3 at entry; restored on exit (entry.rs).
    pub saved_cr3: u64,
    pub rax: u64,
    /// Vector number pushed by the stub (0x100 for a system call).
    pub vector: u64,
    /// Error code from the processor, or 0 pushed by the stub.
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const _: () = assert!(core::mem::size_of::<TrapFrame>() == 24 * 8);
// entry.rs reads CS at [rsp + 40] counting from saved_cr3, and the vector
// at [rsp + 16].
const _: () = assert!(
    core::mem::offset_of!(TrapFrame, cs) - core::mem::offset_of!(TrapFrame, saved_cr3) == 40
);
const _: () = assert!(
    core::mem::offset_of!(TrapFrame, vector) - core::mem::offset_of!(TrapFrame, saved_cr3) == 16
);

// Assembly reasoning (spec section 1, rule 4) for the entry stubs.
//
// Per-vector stubs (`keel_vector_N`).
//   Entry state: the processor has switched to the handler stack (the IST
//   stack named in the gate, RSP0 from the TSS when coming from ring 3, or
//   the interrupted kernel stack otherwise), aligned RSP to 16 bytes, and
//   pushed SS, RSP, RFLAGS, CS, RIP and, for vectors 8, 10-14, 17, 21, 29
//   and 30, an error code (SDM 7.14.2, Table 7-1). Interrupts are off
//   because every gate is an interrupt gate (type 0xE clears IF).
//   Vectors without an error code first `push 0` so that every frame has
//   the same shape. Then `push N` records the vector and the stub jumps to
//   the common code. Both pushes are 8 bytes (64-bit mode PUSH imm8 is
//   sign-extended to 64 bits, SDM Vol. 2B "PUSH").
//
// Common stub (`keel_exception_common`).
//   Entry state: [rsp+0] = vector, [rsp+8] = error code, [rsp+16] = RIP,
//   [rsp+24] = CS, [rsp+32] = RFLAGS, [rsp+40] = RSP, [rsp+48] = SS.
//   1. If the saved CS has RPL 3 the exception came from user mode, and
//      `swapgs` exchanges the user GS base with the kernel's
//      (IA32_KERNEL_GS_BASE). No user mode exists yet, so the branch is
//      not taken; it is here so that the entry path is shaped for user mode
//      and for page-table isolation from the start (SR-14). P1-T10/P1-S3
//      add the CR3 switch at this point and must also make NMI, #MC and #DB
//      entry robust against arriving between a SYSCALL and its SWAPGS.
//   2. Push the 15 general registers, rax first. RSP now points at a
//      complete TrapFrame. Frame size: 5 processor words + 2 stub words +
//      15 registers = 22 words = 176 bytes, a multiple of 16, and the
//      processor aligned RSP to 16 before its pushes, so RSP is 16-byte
//      aligned here, as the System V ABI requires at a `call`.
//   3. `cld`: the ABI requires DF = 0 on function entry, and the
//      interrupted code may have set it.
//   4. `mov rdi, rsp; call exception_dispatch`: the first argument (RDI)
//      is the TrapFrame pointer. The handler may modify the frame.
//      Callee-saved registers are preserved by the call; the caller-saved
//      ones were saved in the frame. The kernel target uses no SSE/x87
//      registers ("soft-float", Rust platform-support page for
//      x86_64-unknown-none), so no vector state needs saving, and it has
//      no red zone, so the interrupted function's stack below RSP was not
//      in use.
//   5. Pop the registers in reverse order, possibly with values the
//      handler changed; `add rsp, 16` drops the vector and error code.
//   6. If returning to user mode, `swapgs` restores the user GS base.
//   7. `iretq` (IRET with REX.W) pops RIP, CS, RFLAGS, RSP and SS
//      (SDM 7.14.3).
//   Exit state: every general register and the interrupted RSP, RFLAGS
//   and segment state are as in the (possibly edited) frame.
//
// The stubs use ELF section directives, so they are built only for the
// kernel target; host unit tests compile the pure functions alone.
#[cfg(target_os = "none")]
global_asm!(
    r#"
    .pushsection .text.keel_entry, "ax", @progbits

    .macro KEEL_VECTOR_NO_ERROR_CODE vector
    keel_vector_\vector:
        push 0
        push \vector
        jmp keel_exception_common
    .endm

    .macro KEEL_VECTOR_ERROR_CODE vector
    keel_vector_\vector:
        push \vector
        jmp keel_exception_common
    .endm

    .irp vector, 0,1,2,3,4,5,6,7,9,15,16,18,19,20,22,23,24,25,26,27,28,31
        KEEL_VECTOR_NO_ERROR_CODE \vector
    .endr
    .irp vector, 8,10,11,12,13,14,17,21,29,30
        KEEL_VECTOR_ERROR_CODE \vector
    .endr
    // Vectors 32-255 are interrupts (external or INT n); none pushes an
    // error code (SDM Table 7-1, "User Defined (Non-reserved) Interrupts").
    .irp vector, 32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255
        KEEL_VECTOR_NO_ERROR_CODE \vector
    .endr


    .popsection

    .pushsection .data.keel_entry, "aw", @progbits
    .balign 8
    keel_exception_stubs:
    .irp vector, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255
        .quad keel_vector_\vector
    .endr
    .popsection
    "#,
);

#[cfg(target_os = "none")]
unsafe extern "C" {
    /// Entry addresses of the 256 stubs, in vector order. The bootloader
    /// relocates the `.quad` values with the kernel image.
    static keel_exception_stubs: [u64; 256];
}

/// An IDT gate (Figure 7-8) as two 8-byte words.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
fn gate(handler: u64, ist: u8, dpl: u8) -> [u64; 2] {
    const TYPE_INTERRUPT_GATE: u64 = 0xE << 40;
    const PRESENT: u64 = 1 << 47;
    let low = (handler & 0xFFFF)
        | u64::from(KERNEL_CS) << 16
        | u64::from(ist & 0x7) << 32
        | TYPE_INTERRUPT_GATE
        | u64::from(dpl & 0x3) << 45
        | PRESENT
        | (handler >> 16 & 0xFFFF) << 48;
    [low, handler >> 32]
}

/// The IST slot used by each exception, if any.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
fn ist_for(vector: usize) -> u8 {
    match vector {
        2 => IstSlot::Nmi as u8,
        8 => IstSlot::DoubleFault as u8,
        18 => IstSlot::MachineCheck as u8,
        _ => 0,
    }
}

#[cfg(target_os = "none")]
#[repr(C, align(16))]
struct Idt(UnsafeCell<[[u64; 2]; 256]>);
// SAFETY: written only by `init` (once, single CPU, interrupts off);
// afterwards read only by the processor.
#[cfg(target_os = "none")]
unsafe impl Sync for Idt {}

#[cfg(target_os = "none")]
#[unsafe(link_section = ".data.keel_entry")]
static IDT: Idt = Idt(UnsafeCell::new([[0; 2]; 256]));

/// Loads the IDT with gates for all 256 vectors.
#[cfg(target_os = "none")]
///
/// # Safety
///
/// Call once, after `gdt::init`, with interrupts disabled.
pub unsafe fn init() {
    // SAFETY: the stub table is defined in the global_asm above, holds 32
    // relocated addresses and is never written after relocation.
    let stubs: &[u64; 256] = unsafe { &keel_exception_stubs };
    // SAFETY: by the contract, nothing else accesses the IDT now.
    let idt = unsafe { &mut *IDT.0.get() };
    for (vector, &stub) in stubs.iter().enumerate() {
        idt[vector] = gate(stub, ist_for(vector), 0);
    }

    let pointer = DescriptorTablePointer {
        limit: (core::mem::size_of::<[[u64; 2]; 256]>() - 1) as u16,
        base: IDT.0.get() as u64,
    };
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: interrupts off; `{ptr}` holds the address of a 10-byte
    //   LIDT operand (16-bit limit 4095, 64-bit base of the static IDT).
    // Instruction: `lidt [{ptr}]` loads IDTR. From now on exceptions are
    //   delivered through our gates.
    // Exit state: no register or flag changes (`preserves_flags`); the
    //   operand is only read and the stack is not used (`nostack`;
    //   `readonly` because memory is read, not written).
    // Reference: SDM Vol. 2A "LGDT/LIDT".
    //
    // SAFETY: the IDT is static, 16-byte aligned, and every present gate
    // points at a stub in this module that expects exactly the frame the
    // processor pushes for that vector.
    unsafe {
        asm!("lidt [{ptr}]", ptr = in(reg) &raw const pointer, options(readonly, nostack, preserves_flags));
    }
}

/// Exception names from Table 7-1, for diagnostics.
pub fn exception_name(vector: u64) -> &'static str {
    match vector {
        0 => "#DE divide error",
        1 => "#DB debug",
        2 => "NMI",
        3 => "#BP breakpoint",
        4 => "#OF overflow",
        5 => "#BR bound range exceeded",
        6 => "#UD invalid opcode",
        7 => "#NM device not available",
        8 => "#DF double fault",
        10 => "#TS invalid TSS",
        11 => "#NP segment not present",
        12 => "#SS stack-segment fault",
        13 => "#GP general protection",
        14 => "#PF page fault",
        16 => "#MF x87 floating-point error",
        17 => "#AC alignment check",
        18 => "#MC machine check",
        19 => "#XM SIMD floating-point",
        20 => "#VE virtualization exception",
        21 => "#CP control protection",
        28 => "#HV hypervisor injection",
        29 => "#VC VMM communication",
        30 => "#SX security exception",
        _ => "reserved vector",
    }
}

static BREAKPOINTS: AtomicU64 = AtomicU64::new(0);

/// Number of #BP exceptions handled so far.
pub fn breakpoint_count() -> u64 {
    BREAKPOINTS.load(Ordering::Relaxed)
}

/// Details of the last fatal exception, kept for the panic handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatalException {
    /// Vector number.
    pub vector: u64,
    /// Error code pushed by the processor (0 for vectors without one).
    pub error_code: u64,
    /// CR2 for a page fault: the linear address that faulted.
    pub fault_address: u64,
    /// Address of the saved TrapFrame, which tells which stack the handler
    /// ran on.
    pub frame_address: u64,
}

static FATAL_VECTOR: AtomicU64 = AtomicU64::new(u64::MAX);
static FATAL_FRAME: AtomicU64 = AtomicU64::new(0);
static FATAL_ERROR_CODE: AtomicU64 = AtomicU64::new(0);
static FATAL_CR2: AtomicU64 = AtomicU64::new(0);
/// Set on the first entry to `fatal`. A fault while the dump is being
/// printed (or later, in the panic handler) re-enters `fatal`; without
/// this it would print again, fault again, and never halt (audit
/// finding 7).
#[cfg(target_os = "none")]
static FATAL_ENTERED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The fatal exception that caused the current panic, if any.
pub fn last_fatal_exception() -> Option<FatalException> {
    let vector = FATAL_VECTOR.load(Ordering::Acquire);
    (vector != u64::MAX).then(|| FatalException {
        vector,
        error_code: FATAL_ERROR_CODE.load(Ordering::Relaxed),
        fault_address: FATAL_CR2.load(Ordering::Relaxed),
        frame_address: FATAL_FRAME.load(Ordering::Relaxed),
    })
}

/// Called by the common entry code (entry.rs) with interrupts disabled.
#[cfg(target_os = "none")]
pub(crate) extern "C" fn exception_dispatch(frame: *mut TrapFrame) {
    // SAFETY: the stub passes the address of the TrapFrame it just built on
    // the current stack. It is valid, aligned, and exclusively ours until
    // this function returns.
    let frame = unsafe { &mut *frame };
    let vector = frame.vector;
    let from_user = frame.cs & 3 == 3;
    if vector == super::entry::SYSCALL_VECTOR {
        crate::syscall::dispatch(frame);
    } else if vector == 14 && crate::vm::handle_page_fault(frame, super::cpu::read_cr2()) {
        // Resolved (demand paging, copy-on-write, or a user-copy fixup).
    } else if from_user && vector < 32 && !matches!(vector, 2 | 8 | 18) {
        // A user program faulted. Until signals exist (Phase 3) that ends
        // the thread; the kernel carries on. NMI (2), double fault (8) and
        // machine check (18) are never a user program's fault, whatever the
        // saved CS says, and run on IST stacks; they stay fatal (audit 2,
        // A7.1).
        crate::syscall::user_fault(frame);
    } else {
        dispatch_kernel(frame);
    }
    if frame.cs & 3 == 3 && !super::entry::prepare_user_return(frame) {
        panic!("returning to user mode without a user address space");
    }
}

#[cfg(target_os = "none")]
fn dispatch_kernel(frame: &mut TrapFrame) {
    let vector = frame.vector;
    match vector {
        32..=255 => crate::interrupts::dispatch(vector as u8),
        3 => {
            // #BP is a trap: the saved RIP already points after INT3, so
            // returning resumes execution (SDM section 7.15, Interrupt 3).
            BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
        }
        // #GP from rdmsr_safe/wrmsr_safe: resume at their error return.
        13 => match super::cpu::msr_fixup(frame.rip) {
            Some(resume) => frame.rip = resume,
            None => fatal(frame),
        },
        _ => fatal(frame),
    }
}

#[cfg(target_os = "none")]
fn fatal(frame: &TrapFrame) -> ! {
    if FATAL_ENTERED.swap(true, Ordering::AcqRel) {
        // Nested: keep the first fault's record and print nothing that
        // could fault again; the panic handler's own guard halts.
        panic!("fault inside the fatal path");
    }
    // CR2 matters for #PF and for a #DF caused by a page fault (such as a
    // stack running into its guard page).
    let cr2 = if matches!(frame.vector, 8 | 14) {
        super::cpu::read_cr2()
    } else {
        0
    };
    FATAL_FRAME.store(frame as *const TrapFrame as u64, Ordering::Relaxed);
    FATAL_ERROR_CODE.store(frame.error_code, Ordering::Relaxed);
    FATAL_CR2.store(cr2, Ordering::Relaxed);
    FATAL_VECTOR.store(frame.vector, Ordering::Release);
    crate::console::emergency_print(format_args!("{}", Dump { frame, cr2 }));
    panic!(
        "unhandled exception {} at {:#018x}",
        exception_name(frame.vector),
        frame.rip
    );
}

/// Register dump printed before the panic banner.
#[cfg(target_os = "none")]
struct Dump<'a> {
    frame: &'a TrapFrame,
    cr2: u64,
}

#[cfg(target_os = "none")]
impl core::fmt::Display for Dump<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let t = self.frame;
        writeln!(
            f,
            "\nEXCEPTION {} (vector {}) error code {:#x}",
            exception_name(t.vector),
            t.vector,
            t.error_code
        )?;
        writeln!(
            f,
            "  rip {:#018x}  cs {:#06x}  rflags {:#010x}",
            t.rip, t.cs, t.rflags
        )?;
        writeln!(
            f,
            "  rsp {:#018x}  ss {:#06x}  cr2 {:#018x}",
            t.rsp, t.ss, self.cr2
        )?;
        writeln!(
            f,
            "  rax {:#018x}  rbx {:#018x}  rcx {:#018x}",
            t.rax, t.rbx, t.rcx
        )?;
        writeln!(
            f,
            "  rdx {:#018x}  rsi {:#018x}  rdi {:#018x}",
            t.rdx, t.rsi, t.rdi
        )?;
        writeln!(
            f,
            "  rbp {:#018x}  r8  {:#018x}  r9  {:#018x}",
            t.rbp, t.r8, t.r9
        )?;
        writeln!(
            f,
            "  r10 {:#018x}  r11 {:#018x}  r12 {:#018x}",
            t.r10, t.r11, t.r12
        )?;
        writeln!(
            f,
            "  r13 {:#018x}  r14 {:#018x}  r15 {:#018x}",
            t.r13, t.r14, t.r15
        )?;
        writeln!(f, "  frame at {:#018x}", t as *const TrapFrame as u64)
    }
}

/// Which IST stack, if any, contains `address`.
pub fn ist_containing(address: u64) -> Option<IstSlot> {
    [IstSlot::DoubleFault, IstSlot::Nmi, IstSlot::MachineCheck]
        .into_iter()
        .find(|&slot| gdt::ist_stack_range(slot).contains(&address))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_fields_follow_figure_7_8() {
        let [low, high] = gate(0xffff_ffff_8012_3456, 1, 0);
        assert_eq!(low & 0xFFFF, 0x3456); // offset 15:0
        assert_eq!(low >> 16 & 0xFFFF, 0x10); // selector
        assert_eq!(low >> 32 & 0x7, 1); // IST
        assert_eq!(low >> 35 & 0x1F, 0); // bits 7:3 of dword 1 are zero
        assert_eq!(low >> 40 & 0xF, 0xE); // 64-bit interrupt gate
        assert_eq!(low >> 44 & 1, 0); // bit 12 is zero
        assert_eq!(low >> 45 & 3, 0); // DPL
        assert_eq!(low >> 47 & 1, 1); // present
        assert_eq!(low >> 48, 0x8012); // offset 31:16
        assert_eq!(high, 0xffff_ffff); // offset 63:32, reserved half zero
    }

    #[test]
    fn critical_vectors_use_their_own_stacks() {
        assert_eq!(ist_for(8), 1);
        assert_eq!(ist_for(2), 2);
        assert_eq!(ist_for(18), 3);
        assert_eq!(ist_for(14), 0);
    }
}

/// Page-fault error code bits (SDM Vol. 3 section 7.15, Figure 7-11
/// "Page-Fault Error Code").
pub mod page_fault {
    /// 1: protection violation; 0: page not present.
    pub const PRESENT: u64 = 1 << 0;
    /// 1: the access was a write.
    pub const WRITE: u64 = 1 << 1;
    /// 1: the access came from user mode.
    pub const USER: u64 = 1 << 2;
    /// 1: a reserved bit was set in a paging-structure entry.
    pub const RESERVED: u64 = 1 << 3;
    /// 1: the access was an instruction fetch.
    pub const INSTRUCTION_FETCH: u64 = 1 << 4;
}
