//! Floating-point, SSE and AVX state (P1-T8).
//!
//! The kernel itself is built soft-float and never touches these
//! registers; user programs do, so every thread carries a save area that
//! the scheduler saves and restores on each switch.
//!
//! References (Intel SDM Vol. 1, 253665-093): section 13.2 (XSAVE
//! enumeration: CPUID.01H:ECX.XSAVE[26]; CPUID.0DH.00H EDX:EAX = supported
//! user components, EBX = area size for the components enabled in XCR0);
//! section 13.4 (64-byte alignment; header at offset 512); Table 10-2
//! (FXSAVE layout: FCW at byte 0, MXCSR at byte 24); the reset values
//! FCW = 037FH and MXCSR = 1F80H; section 13.8.1 (XRSTOR loads MXCSR when
//! RFBM[1] or RFBM[2] is set). SDM Vol. 3 section 2.5 (CR0.MP bit 1, CR0.EM
//! bit 2, CR0.TS bit 3; CR4.OSFXSR bit 9, OSXMMEXCPT bit 10, OSXSAVE bit
//! 18) and Figure 2-8 (XCR0: bit 0 x87, 1 SSE, 2 AVX, 5-7 AVX-512).

use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use super::cpu;

/// Legacy-only area size used with FXSAVE (SDM Vol. 1 Table 10-2).
const FXSAVE_SIZE: u64 = 512;
/// XCR0 components Keel enables when the CPU supports them: x87, SSE,
/// AVX and the three AVX-512 components. MPX (3, 4) is deprecated and AMX
/// (17, 18) needs a separate permission scheme; both stay off.
const WANTED_XCR0: u64 = 0b1110_0111;

/// 0: FXSAVE; otherwise the XCR0 mask used with XSAVE.
static XSAVE_MASK: AtomicU64 = AtomicU64::new(0);
static AREA_SIZE: AtomicU64 = AtomicU64::new(FXSAVE_SIZE);
/// The MXCSR bits this CPU accepts (`MXCSR_MASK`, FXSAVE bytes 28-31; 0
/// there means 0xFFBF: SDM Vol. 1 section 11.6.6). Read once at `init`.
static MXCSR_MASK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0xFFBF);

/// Configuration chosen by `init`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpuReport {
    /// XCR0 value, or `None` when only FXSAVE is available.
    pub xcr0: Option<u64>,
    /// Bytes per thread save area.
    pub area_size: u64,
}

/// Enables SSE and, if available, XSAVE with the wanted components.
pub fn init() -> FpuReport {
    let (_, _, ecx1, _) = cpu::cpuid(1, 0);
    let xsave = ecx1 & (1 << 26) != 0;
    record_mxcsr_mask();
    // SAFETY: CR0.MP = 1 and EM = 0 are the documented settings for SSE
    // (SDM Vol. 3 section 14.1.3); TS = 0 so FPU instructions do not trap.
    // OSFXSR and OSXMMEXCPT are architectural on every x86-64 CPU;
    // OSXSAVE is set only when CPUID reports XSAVE.
    unsafe {
        let cr0 = (cpu::read_cr0() | 1 << 1) & !(1 << 2 | 1 << 3);
        cpu::write_cr0(cr0);
        let mut cr4 = cpu::read_cr4() | 1 << 9 | 1 << 10;
        if xsave {
            cr4 |= 1 << 18;
        }
        cpu::write_cr4(cr4);
    }
    if !xsave {
        return FpuReport {
            xcr0: None,
            area_size: FXSAVE_SIZE,
        };
    }
    let (supported_low, _, _, supported_high) = cpu::cpuid(0xD, 0);
    let supported = u64::from(supported_high) << 32 | u64::from(supported_low);
    let mut mask = supported & WANTED_XCR0;
    // AVX-512 components are only usable together (SDM Vol. 1 13.3).
    if mask & 0b1110_0000 != 0b1110_0000 {
        mask &= !0b1110_0000;
    }
    // SAFETY: XCR0 = 0 (index in ECX) exists when OSXSAVE is set; `mask`
    // contains only bits CPUID reports as supported, always bits 0 and 1,
    // AVX only with SSE, and AVX-512 only as a complete group, which are
    // the XSETBV validity rules (SDM Vol. 2B "XSETBV").
    unsafe { xsetbv(0, mask) };
    let (_, size, _, _) = cpu::cpuid(0xD, 0);
    XSAVE_MASK.store(mask, Ordering::Relaxed);
    AREA_SIZE.store(u64::from(size), Ordering::Relaxed);
    FpuReport {
        xcr0: Some(mask),
        area_size: u64::from(size),
    }
}

/// Reads MXCSR_MASK with one FXSAVE into a scratch area.
fn record_mxcsr_mask() {
    #[repr(C, align(16))]
    struct Area([u8; 512]);
    let mut area = Area([0; 512]);
    // Assembly reasoning (spec section 1, rule 4)
    // Instruction: `fxsave64 [area]` stores the 512-byte legacy area,
    //   which needs a 16-byte aligned destination (SDM Vol. 2A "FXSAVE");
    //   `Area` is aligned 16 and 512 bytes long. MXCSR_MASK is at bytes
    //   28-31 (Table 10-2). Registers and flags are unchanged.
    // SAFETY: the area is a local, aligned and large enough.
    unsafe {
        core::arch::asm!("fxsave64 [{}]", in(reg) area.0.as_mut_ptr(), options(nostack, preserves_flags));
    }
    let mask = u32::from_le_bytes([area.0[28], area.0[29], area.0[30], area.0[31]]);
    MXCSR_MASK.store(if mask == 0 { 0xFFBF } else { mask }, Ordering::Relaxed);
}

/// Size of a thread's save area (what a signal frame carries).
pub fn area_size() -> usize {
    AREA_SIZE.load(Ordering::Relaxed) as usize
}

/// The XCR0 mask in use, or 0 when only FXSAVE is.
pub fn xsave_mask() -> u64 {
    XSAVE_MASK.load(Ordering::Relaxed)
}

/// Whether `bytes`, a save area from user memory (rt_sigreturn), can be
/// loaded without a fault: the right size; MXCSR within MXCSR_MASK (FXRSTOR
/// and XRSTOR raise #GP otherwise: SDM Vol. 2A "FXRSTOR"); and with XSAVE
/// a standard-form header (SDM Vol. 1 section 13.8.1, Vol. 2C "XRSTOR"):
/// XSTATE_BV only components enabled in XCR0, XCOMP_BV 0, and the rest of
/// the 64-byte header zero.
pub fn valid_user_area(bytes: &[u8]) -> bool {
    if bytes.len() != area_size() {
        return false;
    }
    let mxcsr = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    if mxcsr & !MXCSR_MASK.load(Ordering::Relaxed) != 0 {
        return false;
    }
    let mask = xsave_mask();
    if mask == 0 {
        return true;
    }
    let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0xff; 8]));
    word(512) & !mask == 0 && word(520) == 0 && bytes[528..576].iter().all(|&b| b == 0)
}

/// Writes an extended control register.
///
/// # Safety
///
/// CR4.OSXSAVE must be set and `value` must be valid for the register.
unsafe fn xsetbv(register: u32, value: u64) {
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: CPL 0, CR4.OSXSAVE = 1; ECX = register, EDX:EAX = value.
    // Instruction: `xsetbv` (SDM Vol. 2B "XSETBV"). Flags unaffected; no
    //   memory or stack access.
    // SAFETY: guaranteed by the caller.
    unsafe {
        core::arch::asm!("xsetbv", in("ecx") register, in("eax") value as u32,
            in("edx") (value >> 32) as u32, options(nomem, nostack, preserves_flags));
    }
}

/// One thread's saved FPU/SSE/AVX registers, 64-byte aligned.
pub struct FpuState {
    area: NonNull<u8>,
    size: usize,
}

// SAFETY: the area is owned exclusively by this value.
unsafe impl Send for FpuState {}

impl FpuState {
    /// A save area holding the initial register state: x87 control word
    /// 037FH, MXCSR 1F80H, everything else zero (and, for XSAVE, an all-
    /// zero header, meaning every component is in its initial state).
    pub fn new() -> Option<FpuState> {
        let size = AREA_SIZE.load(Ordering::Relaxed) as usize;
        let layout = Layout::from_size_align(size, 64).ok()?;
        // SAFETY: `size` is at least 512, so the layout is not zero-sized.
        let area = NonNull::new(unsafe { alloc_zeroed(layout) })?;
        // SAFETY: the area is at least 512 bytes; bytes 0-1 hold FCW and
        // 24-27 hold MXCSR (SDM Vol. 1 Table 10-2). Both offsets are
        // naturally aligned for their types within a 64-byte-aligned area.
        unsafe {
            area.as_ptr().cast::<u16>().write(0x037F);
            area.as_ptr().add(24).cast::<u32>().write(0x1F80);
        }
        Some(FpuState { area, size })
    }

    /// Saves the current CPU state into this area.
    pub fn save(&mut self) {
        let mask = XSAVE_MASK.load(Ordering::Relaxed);
        let area = self.area.as_ptr();
        // Assembly reasoning (spec section 1, rule 4)
        // Entry state: CR4.OSFXSR (and OSXSAVE when `mask` != 0) set by
        //   `init`; `area` is 64-byte aligned and `AREA_SIZE` bytes long,
        //   the size CPUID reports for the enabled components.
        // Instructions: `xsave64 [area]` with EDX:EAX = mask stores the
        //   enabled components and the header (SDM Vol. 2C "XSAVE");
        //   `fxsave64 [area]` stores the 512-byte legacy area (SDM Vol. 2A
        //   "FXSAVE"). Neither changes registers or flags.
        // SAFETY: the area is valid, exclusively ours, and large and
        // aligned enough for the chosen instruction.
        unsafe {
            if mask != 0 {
                core::arch::asm!("xsave64 [{}]", in(reg) area, in("eax") mask as u32,
                    in("edx") (mask >> 32) as u32, options(nostack, preserves_flags));
            } else {
                core::arch::asm!("fxsave64 [{}]", in(reg) area, options(nostack, preserves_flags));
            }
        }
    }

    /// Loads this area into the CPU.
    pub fn restore(&self) {
        let mask = XSAVE_MASK.load(Ordering::Relaxed);
        let area = self.area.as_ptr();
        // Assembly reasoning (spec section 1, rule 4)
        // Instructions: `xrstor64 [area]` (SDM Vol. 2C "XRSTOR") or
        //   `fxrstor64 [area]` (Vol. 2A "FXRSTOR") load the state saved by
        //   `save` or prepared by `new`. A malformed header or a reserved
        //   MXCSR bit would raise #GP; `new` writes valid values and only
        //   `save` writes afterwards. Only FPU/SSE/AVX state changes, but
        //   that state includes the x87 status word and MXCSR's exception
        //   flags, which `preserves_flags` promises to leave unchanged (the
        //   Rust Reference, "Inline assembly",
        //   asm.rules.preserved-registers), so the option is not claimed.
        //   RFLAGS itself is not touched.
        // SAFETY: as for `save`; the contents are always valid as argued.
        unsafe {
            if mask != 0 {
                core::arch::asm!("xrstor64 [{}]", in(reg) area, in("eax") mask as u32,
                    in("edx") (mask >> 32) as u32, options(nostack, readonly));
            } else {
                core::arch::asm!("fxrstor64 [{}]", in(reg) area, options(nostack, readonly));
            }
        }
    }
}

impl FpuState {
    /// The saved registers, as `save` stored them.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the area is `size` bytes, allocated in `new` and owned
        // exclusively by this value; any bytes are valid `u8`s.
        unsafe { core::slice::from_raw_parts(self.area.as_ptr(), self.size) }
    }

    /// Replaces the saved registers with `bytes`, which must pass
    /// `valid_user_area` (so a later `restore` cannot fault). Returns
    /// whether it did.
    pub fn load_bytes(&mut self, bytes: &[u8]) -> bool {
        if !valid_user_area(bytes) || bytes.len() != self.size {
            return false;
        }
        // SAFETY: as `bytes`, mutably: the borrow of `self` is exclusive.
        unsafe { core::slice::from_raw_parts_mut(self.area.as_ptr(), self.size) }
            .copy_from_slice(bytes);
        true
    }
}

impl Drop for FpuState {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with exactly this layout.
        unsafe {
            dealloc(
                self.area.as_ptr(),
                Layout::from_size_align_unchecked(self.size, 64),
            )
        }
    }
}
