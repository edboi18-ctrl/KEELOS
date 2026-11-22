//! Global descriptor table and task-state segment (P1-T1).
//!
//! References (Intel SDM Vol. 3, order number 325384-093, September 2026):
//!  - section 3.4.5 and Figure 3-8, "Segment Descriptor" (bit layout);
//!  - Table 3-2, "System-Segment and Gate-Descriptor Types" (type 9 =
//!    64-bit TSS, available);
//!  - Figure 10-4, "Format of TSS and LDT Descriptors in 64-bit Mode"
//!    (a TSS descriptor is 16 bytes and takes two GDT slots);
//!  - section 10.7 and Figure 10-11, "64-Bit TSS Format";
//!  - section 6.8.8, "Fast System Calls in 64-Bit Mode" (how SYSCALL and
//!    SYSRET derive selectors from IA32_STAR, which fixes the order of the
//!    kernel and user entries below).
//!
//! Layout. The selector values are the ones Linux uses on x86-64
//! (`arch/x86/include/asm/segment.h`, read for reference only). Programs
//! see these numbers in signal frames (`uc_mcontext.cs`), so matching them
//! keeps Keel's output identical to the Linux reference runs (spec
//! section 10, conformance tests).
//!
//! | Index | Selector | Descriptor |
//! | --- | --- | --- |
//! | 0 | 0x00 | null (required) |
//! | 1 | 0x08 | null (Linux: 32-bit kernel code; Keel has none) |
//! | 2 | 0x10 | kernel code, 64-bit, DPL 0 |
//! | 3 | 0x18 | kernel data, DPL 0 |
//! | 4 | 0x23 | null: no 32-bit user code segment exists (spec section 3: 32-bit entry paths are never implemented). A far transfer to this selector raises #GP. |
//! | 5 | 0x2b | user data, DPL 3 |
//! | 6 | 0x33 | user code, 64-bit, DPL 3 |
//! | 7 | 0x38 | null |
//! | 8-9 | 0x40 | 64-bit TSS (16-byte descriptor) |
//!
//! SYSCALL loads CS = STAR[47:32] = 0x10 and SS = 0x10 + 8 = 0x18.
//! SYSRET to 64-bit code loads SS = STAR[63:48] + 8 and
//! CS = STAR[63:48] + 16; with STAR[63:48] = 0x23 that gives 0x2b and
//! 0x33 (the processor forces RPL 3).
//!
//! Page-table isolation (SR-14): the GDT and TSS live in the
//! `.data.keel_entry` section so that a later task can map exactly the
//! entry trampoline's data into user page tables.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem::size_of;

/// Kernel code segment selector.
pub const KERNEL_CS: u16 = 0x10;
/// Kernel data / stack segment selector.
pub const KERNEL_DS: u16 = 0x18;
/// Base for IA32_STAR[63:48]; see the module documentation.
pub const USER_STAR_BASE: u16 = 0x23;
/// User data / stack segment selector (RPL 3).
pub const USER_DS: u16 = 0x2b;
/// User 64-bit code segment selector (RPL 3).
pub const USER_CS: u16 = 0x33;
/// Task-state segment selector.
pub const TSS_SELECTOR: u16 = 0x40;

/// Interrupt-stack-table slots used by the IDT (1-based, as in the gate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IstSlot {
    /// Double fault: runs on a known-good stack even if the kernel stack
    /// overflowed (SDM section 7.14.5).
    DoubleFault = 1,
    /// Non-maskable interrupt: can arrive at any instruction.
    Nmi = 2,
    /// Machine check: can arrive at any instruction.
    MachineCheck = 3,
}

const IST_STACK_SIZE: usize = 16 * 1024;
const PAGE: usize = 4096;

/// One interrupt stack preceded by a guard page (SR-17). Stacks grow
/// down, so an overflow runs into the guard page, which the kernel page
/// tables leave unmapped (`paging::init`): the overflow faults instead of
/// silently overwriting the neighbouring stack. Page alignment puts the
/// guard on its own page; the stack top is then 16-byte aligned, as SDM
/// section 7.14.4 expects of TSS stack pointers.
#[repr(C, align(4096))]
struct GuardedStack {
    guard: [u8; PAGE],
    stack: [u8; IST_STACK_SIZE],
}

/// IST stacks with their guard pages.
#[unsafe(link_section = ".bss.keel_entry")]
static IST_STACKS: IstStacks = IstStacks(UnsafeCell::new(
    [const {
        GuardedStack {
            guard: [0; PAGE],
            stack: [0; IST_STACK_SIZE],
        }
    }; 3],
));

struct IstStacks(UnsafeCell<[GuardedStack; 3]>);
// SAFETY: the stacks are only ever written by the processor while it runs
// an interrupt handler on them; Rust code never forms references to their
// contents, only computes addresses.
unsafe impl Sync for IstStacks {}

const GUARDED_STACK_SIZE: u64 = core::mem::size_of::<GuardedStack>() as u64;

/// The 64-bit TSS, Figure 10-11. The 64-bit fields sit at 4-byte offsets
/// (RSP0 at offset 4), so the structure is packed to 4-byte alignment.
#[repr(C, packed(4))]
struct TaskStateSegment {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    io_map_base: u16,
}

const TSS_SIZE: usize = size_of::<TaskStateSegment>();
const _: () = assert!(TSS_SIZE == 104, "Figure 10-11: the 64-bit TSS is 104 bytes");

/// GDT entries as raw 8-byte words (Figure 3-8).
const GDT_ENTRIES: usize = 10;

struct Tables {
    gdt: [u64; GDT_ENTRIES],
    tss: TaskStateSegment,
}

#[repr(C, align(16))]
struct TablesCell(UnsafeCell<Tables>);
// SAFETY: written only by `init`, which runs once, on one CPU, with
// interrupts disabled, before anything reads the tables; afterwards only
// the processor and `set_kernel_stack` touch them, the latter only with
// interrupts disabled on the single boot CPU (decision D8).
unsafe impl Sync for TablesCell {}

#[unsafe(link_section = ".data.keel_entry")]
static TABLES: TablesCell = TablesCell(UnsafeCell::new(Tables {
    gdt: [0; GDT_ENTRIES],
    tss: TaskStateSegment {
        reserved0: 0,
        rsp: [0; 3],
        reserved1: 0,
        ist: [0; 7],
        reserved2: 0,
        reserved3: 0,
        // "If the I/O bit map base address is greater than or equal to the
        // TSS segment limit, there is no I/O permission map, and all I/O
        // instructions generate exceptions when the CPL is greater than
        // the current IOPL" (SDM Vol. 1, 253665-093, section 20.5.2).
        // The limit is 103, so a base of 104 means no map. Together with
        // IOPL = 0 this gives SR-9: no I/O-port access from user space.
        // P1-T10 note: SYSRET loads RFLAGS from R11, so the syscall exit
        // path must never return a user-chosen IOPL.
        io_map_base: TSS_SIZE as u16,
    },
}));

// Descriptor bit fields (Figure 3-8). Bit numbers are within the 64-bit
// descriptor: the "4" row of the figure is bits 63:32.
const ACCESSED: u64 = 1 << 40; // type bit 0; set so the CPU never writes it
const WRITABLE: u64 = 1 << 41; // data: writable; code: readable
const EXECUTABLE: u64 = 1 << 43; // type bit 3: code segment
const CODE_OR_DATA: u64 = 1 << 44; // S = 1
const DPL3: u64 = 3 << 45;
const PRESENT: u64 = 1 << 47;
const LONG_MODE: u64 = 1 << 53; // L = 1: 64-bit code (D must be 0)
const LIMIT_4G: u64 = 0xF << 48 | 0xFFFF | 1 << 55; // limit 0xFFFFF, G = 1

const fn code_segment(user: bool) -> u64 {
    let dpl = if user { DPL3 } else { 0 };
    LIMIT_4G | ACCESSED | WRITABLE | EXECUTABLE | CODE_OR_DATA | dpl | PRESENT | LONG_MODE
}

const fn data_segment(user: bool) -> u64 {
    let dpl = if user { DPL3 } else { 0 };
    LIMIT_4G | ACCESSED | WRITABLE | CODE_OR_DATA | dpl | PRESENT
}

/// The two 8-byte halves of a 64-bit TSS descriptor (Figure 10-4).
const fn tss_descriptor(base: u64, limit: u64) -> [u64; 2] {
    const TYPE_TSS_AVAILABLE: u64 = 0x9 << 40;
    let low = (limit & 0xFFFF)
        | (base & 0xFF_FFFF) << 16
        | TYPE_TSS_AVAILABLE
        | PRESENT
        | (limit >> 16 & 0xF) << 48
        | (base >> 24 & 0xFF) << 56;
    [low, base >> 32]
}

/// Builds the GDT words. Pure, so it is unit-tested on the host.
fn build_gdt(tss_base: u64) -> [u64; GDT_ENTRIES] {
    let mut gdt = [0u64; GDT_ENTRIES];
    gdt[usize::from(KERNEL_CS >> 3)] = code_segment(false);
    gdt[usize::from(KERNEL_DS >> 3)] = data_segment(false);
    gdt[usize::from(USER_DS >> 3)] = data_segment(true);
    gdt[usize::from(USER_CS >> 3)] = code_segment(true);
    let [low, high] = tss_descriptor(tss_base, TSS_SIZE as u64 - 1);
    gdt[usize::from(TSS_SELECTOR >> 3)] = low;
    gdt[usize::from(TSS_SELECTOR >> 3) + 1] = high;
    gdt
}

/// Operand of LGDT and LIDT: 16-bit limit, 64-bit base (SDM section 3.5.1).
#[repr(C, packed)]
pub(crate) struct DescriptorTablePointer {
    pub(crate) limit: u16,
    pub(crate) base: u64,
}

/// Address one past the end of IST stack `slot`.
pub fn ist_stack_top(slot: IstSlot) -> u64 {
    let base = IST_STACKS.0.get() as u64;
    // Slot n (1-based) ends where block n ends.
    base + (slot as u64) * GUARDED_STACK_SIZE
}

/// The address range `[low, high)` of IST stack `slot`.
pub fn ist_stack_range(slot: IstSlot) -> core::ops::Range<u64> {
    let top = ist_stack_top(slot);
    top - IST_STACK_SIZE as u64..top
}

/// The guard page directly below each IST stack. These pages must stay
/// unmapped.
pub fn ist_guard_pages() -> [u64; 3] {
    [IstSlot::DoubleFault, IstSlot::Nmi, IstSlot::MachineCheck]
        .map(|slot| ist_stack_range(slot).start - PAGE as u64)
}

/// Loads Keel's GDT and TSS on the boot CPU and reloads every segment
/// register.
///
/// # Safety
///
/// Call exactly once, early in boot, with interrupts disabled, before the
/// IDT is loaded.
pub unsafe fn init() {
    let tables = TABLES.0.get();
    // SAFETY: the function contract makes this the only access to TABLES:
    // single CPU, interrupts off, nothing else has run yet.
    unsafe {
        let tss = &raw mut (*tables).tss;
        let ist = &raw mut (*tss).ist;
        for slot in [IstSlot::DoubleFault, IstSlot::Nmi, IstSlot::MachineCheck] {
            // IST1..IST7 are ist[0..6]; the gate holds the 1-based number.
            ist.cast::<u64>()
                .add(slot as usize - 1)
                .write_unaligned(ist_stack_top(slot));
        }
        (*tables).gdt = build_gdt(tss as u64);
    }

    let pointer = DescriptorTablePointer {
        limit: (GDT_ENTRIES * 8 - 1) as u16,
        // SAFETY: only an address is taken; no reference is formed.
        base: unsafe { &raw const (*tables).gdt } as u64,
    };

    // Assembly reasoning (spec section 1, rule 4)
    //
    // Entry state: interrupts disabled (function contract). Limine's GDT
    //   is loaded, CS = 0x28 and the data selectors are 0x30 (PROTOCOL.md,
    //   "Machine State at Entry"). `{ptr}` holds the address of a valid
    //   10-byte LGDT operand on our stack. `{cs}` and `{ds}` hold the
    //   selectors 0x10 and 0x18; `{tss}` holds 0x40.
    // 1. `lgdt [{ptr}]` loads GDTR with our table's base and limit. The
    //    segment registers keep their cached descriptors until reloaded,
    //    so execution continues unaffected (SDM section 3.4.3).
    // 2. CS cannot be loaded with MOV. A far return pops RIP and then CS
    //    (SDM Vol. 2, RET, "far return" with REX.W: 8-byte pops):
    //      push {cs}            ; becomes the new CS
    //      lea  rax, [rip + 2f] ; address of label 2
    //      push rax             ; becomes the new RIP
    //      retfq                ; pops RIP then CS; RSP is back where it
    //                           ; was before the two pushes
    //    so execution resumes at label 2 with CS = 0x10 from our GDT.
    // 3. SS, DS and ES are loaded with the kernel data selector. FS and GS
    //    are loaded with the null selector, which is permitted in 64-bit
    //    mode; their bases are set through MSRs later (P1-T10).
    // 4. `ltr` loads TR with the TSS selector; the processor marks the
    //    descriptor busy (type 11). The TSS is used from now on for RSP0
    //    and the IST pointers.
    // Exit state: all segment registers refer to our GDT; RSP is
    //   unchanged; RAX is clobbered (declared). The status flags are NOT
    //   preserved: `xor eax, eax` clears OF and CF, sets SF, ZF and PF from
    //   the result and leaves AF undefined (SDM Vol. 2D "XOR", Flags
    //   Affected), so `preserves_flags` is not claimed (the Rust Reference,
    //   "Inline assembly", asm.rules.preserved-registers: the status flags
    //   must be restored on exit if it is). LGDT, MOV Sreg, LTR and a far
    //   return from CPL 0 to CPL 0 do not modify RFLAGS.
    // References: Intel SDM Vol. 2A "LGDT/LIDT", Vol. 2B "RET" and "LTR",
    //   Vol. 2B "MOV" (segment register loads), Vol. 3A section 3.4.3.
    //
    // SAFETY: the GDT built above contains valid kernel code and data
    // descriptors at the selectors loaded, and a valid available-TSS
    // descriptor at 0x40 pointing to a static TSS. The table is static and
    // never moves. The far return targets a label inside this asm block.
    unsafe {
        asm!(
            "lgdt [{ptr}]",
            "push {cs}",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov ss, {ds:x}",
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "xor eax, eax",
            "mov fs, ax",
            "mov gs, ax",
            "ltr {tss:x}",
            ptr = in(reg) &raw const pointer,
            cs = in(reg) u64::from(KERNEL_CS),
            ds = in(reg) u64::from(KERNEL_DS),
            tss = in(reg) u64::from(TSS_SELECTOR),
            out("rax") _,
        );
    }
}

/// Sets RSP0, the stack the processor switches to when an interrupt or
/// exception arrives while ring 3 runs.
///
/// # Safety
///
/// `top` must be the 16-byte-aligned top of a mapped kernel stack that
/// stays valid until replaced. Call with interrupts disabled.
pub unsafe fn set_kernel_stack(top: u64) {
    // SAFETY: see TablesCell; the write is a single unaligned store into
    // the static TSS, and the caller guarantees interrupts are off.
    unsafe {
        let tss = &raw mut (*TABLES.0.get()).tss;
        (&raw mut (*tss).rsp).cast::<u64>().write_unaligned(top);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_descriptors_have_the_documented_bits() {
        // Well-known encodings: flat 64-bit kernel code segment 0x00af9b...
        // (P=1, DPL=0, S=1, type 0xB, G=1, L=1, limit 0xFFFFF).
        assert_eq!(code_segment(false), 0x00af_9b00_0000_ffff);
        assert_eq!(data_segment(false), 0x008f_9300_0000_ffff);
        assert_eq!(code_segment(true), 0x00af_fb00_0000_ffff);
        assert_eq!(data_segment(true), 0x008f_f300_0000_ffff);
        // L and D/B must not both be set in a 64-bit code segment.
        assert_eq!(code_segment(false) & (1 << 54), 0);
    }

    #[test]
    fn tss_descriptor_splits_the_base_and_limit() {
        let [low, high] = tss_descriptor(0xffff_ffff_8012_3456, 103);
        assert_eq!(low & 0xFFFF, 103); // limit 15:0
        assert_eq!(low >> 16 & 0xFF_FFFF, 0x12_3456); // base 23:0
        assert_eq!(low >> 40 & 0xF, 0x9); // available 64-bit TSS
        assert_eq!(low >> 47 & 1, 1); // present
        assert_eq!(low >> 56, 0x80); // base 31:24
        assert_eq!(high, 0xffff_ffff); // base 63:32, upper half reserved
    }

    #[test]
    fn gdt_matches_the_syscall_selector_arithmetic() {
        let gdt = build_gdt(0x1000);
        // SYSCALL: SS = STAR[47:32] + 8 must be the kernel data segment.
        assert_eq!(KERNEL_CS + 8, KERNEL_DS);
        // SYSRET (64-bit): SS = base + 8, CS = base + 16.
        assert_eq!((USER_STAR_BASE + 8) | 3, USER_DS);
        assert_eq!((USER_STAR_BASE + 16) | 3, USER_CS);
        // The 32-bit user code slot is empty: no compatibility mode.
        assert_eq!(gdt[usize::from(USER_STAR_BASE >> 3)], 0);
        assert_eq!(gdt[0], 0);
        assert_eq!(gdt[usize::from(USER_CS >> 3)] >> 45 & 3, 3);
        assert_eq!(gdt[usize::from(KERNEL_CS >> 3)] >> 45 & 3, 0);
    }

    #[test]
    fn guard_pages_sit_directly_below_page_aligned_stacks() {
        assert_eq!(GUARDED_STACK_SIZE, (PAGE + IST_STACK_SIZE) as u64);
        for (slot, guard) in [IstSlot::DoubleFault, IstSlot::Nmi, IstSlot::MachineCheck]
            .into_iter()
            .zip(ist_guard_pages())
        {
            let range = ist_stack_range(slot);
            assert_eq!(guard % PAGE as u64, 0);
            assert_eq!(guard + PAGE as u64, range.start);
            assert_eq!(range.end % 16, 0);
        }
    }

    #[test]
    fn tss_layout_matches_figure_10_11() {
        use core::mem::offset_of;
        assert_eq!(offset_of!(TaskStateSegment, rsp), 4);
        assert_eq!(offset_of!(TaskStateSegment, ist), 36);
        assert_eq!(offset_of!(TaskStateSegment, io_map_base), 102);
    }
}
