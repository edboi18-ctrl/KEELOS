//! Reads what the CPU reports about speculation vulnerabilities, chooses
//! mitigations (`keel_core::cpuvuln`) and switches them on (P1-S4,
//! SR-15). Call once at boot, after the entry code is set up and before
//! interrupts are enabled or any user code runs.

use alloc::vec::Vec;

use keel_core::cpuvuln::{self, CpuInfo, Item, Plan, edx7};

use crate::arch::x86_64::{cpu, entry};
use crate::sched;

const IA32_SPEC_CTRL: u32 = 0x48;
const IA32_ARCH_CAPABILITIES: u32 = 0x10A;
const IA32_MCU_OPT_CTRL: u32 = 0x123;

/// What was found and done.
pub struct Report {
    pub cpu: CpuInfo,
    pub plan: Plan,
    pub items: Vec<Item>,
    /// Whether the IA32_SPEC_CTRL and IA32_MCU_OPT_CTRL writes the plan
    /// asked for succeeded (a CPU that advertises but rejects them is
    /// reported, and the entry code then leaves SPEC_CTRL alone).
    pub spec_ctrl_written: bool,
    pub mcu_opt_written: bool,
}

/// Reads CPUID and the vulnerability MSRs.
pub fn cpu_info() -> CpuInfo {
    let (max_leaf, vendor_b, vendor_c, vendor_d) = cpu::cpuid(0, 0);
    // "GenuineIntel" in EBX, EDX, ECX (SDM Vol. 2A "CPUID", leaf 0).
    let intel = vendor_b == u32::from_le_bytes(*b"Genu")
        && vendor_d == u32::from_le_bytes(*b"ineI")
        && vendor_c == u32::from_le_bytes(*b"ntel");
    let (signature, _, ecx1, _) = cpu::cpuid(1, 0);
    let (family, model, stepping) = cpuvuln::decode_signature(signature);
    let (_, ebx7, _, edx7_value) = if max_leaf >= 7 {
        cpu::cpuid(7, 0)
    } else {
        (0, 0, 0, 0)
    };
    // CPUID.(7,0):EAX is the highest subleaf; BHI_CTRL is subleaf 2 EDX[4]
    // (Linux arch/x86/kernel/cpu/scattered.c).
    let max_subleaf = if max_leaf >= 7 { cpu::cpuid(7, 0).0 } else { 0 };
    let bhi_ctrl = max_subleaf >= 2 && cpu::cpuid(7, 2).3 & (1 << 4) != 0;
    let arch_capabilities = if edx7_value & edx7::ARCH_CAPABILITIES != 0 {
        cpu::rdmsr_safe(IA32_ARCH_CAPABILITIES).unwrap_or(0)
    } else {
        0
    };
    let has_mcu_opt =
        edx7_value & edx7::SRBDS_CTRL != 0 || arch_capabilities & cpuvuln::arch_cap::GDS_CTRL != 0;
    CpuInfo {
        intel,
        family,
        model,
        stepping,
        hypervisor: ecx1 & (1 << 31) != 0,
        rtm: ebx7 & (1 << 11) != 0,
        edx7: edx7_value,
        bhi_ctrl,
        arch_capabilities,
        mcu_opt_ctrl: if has_mcu_opt {
            cpu::rdmsr_safe(IA32_MCU_OPT_CTRL)
        } else {
            None
        },
    }
}

/// Assesses the CPU and applies the plan.
pub fn init() -> Report {
    let info = cpu_info();
    let (mut plan, items) = cpuvuln::assess(&info);
    let mut spec_ctrl_written = true;
    if plan.spec_ctrl {
        // SAFETY: IA32_SPEC_CTRL only changes how the CPU speculates; the
        // value uses architectural bits the CPU reported (IBRS, SSBD,
        // BHI_DIS_S). A rejected write is caught (#GP -> false).
        spec_ctrl_written = unsafe { cpu::wrmsr_safe(IA32_SPEC_CTRL, plan.spec_ctrl_kernel) };
        if !spec_ctrl_written {
            plan.ibrs_on_entry = false;
            plan.ibpb_on_switch = false;
        }
    }
    let mut mcu_opt_written = true;
    if let Some(value) = plan.mcu_opt_ctrl {
        // SAFETY: clears the "mitigation disabled" bits of IA32_MCU_OPT_CTRL
        // (RNGDS_MITG_DIS, GDS_MITG_DIS; Linux msr-index.h), which turns
        // microcode mitigations on; caught if rejected.
        mcu_opt_written = unsafe { cpu::wrmsr_safe(IA32_MCU_OPT_CTRL, value) };
    }
    entry::set_mitigations(
        plan.verw_on_exit,
        plan.ibrs_on_entry,
        plan.spec_ctrl_kernel,
        if plan.ibrs_on_entry {
            plan.spec_ctrl_user
        } else {
            plan.spec_ctrl_kernel
        },
    );
    sched::set_ibpb_on_switch(plan.ibpb_on_switch);
    Report {
        cpu: info,
        plan,
        items,
        spec_ctrl_written,
        mcu_opt_written,
    }
}

/// IA32_SPEC_CTRL as the CPU holds it now, for tests.
pub fn spec_ctrl_now() -> Option<u64> {
    cpu::rdmsr_safe(IA32_SPEC_CTRL)
}

/// Whether IA32_SPEC_CTRL and IA32_PRED_CMD accept writes here, for tests
/// that force the IBRS and IBPB paths on. Rewrites SPEC_CTRL with the
/// value it already holds and issues one IBPB, so nothing changes.
pub fn speculation_msrs_writable() -> bool {
    let Some(current) = spec_ctrl_now() else {
        return false;
    };
    // SAFETY: writing IA32_SPEC_CTRL's own current value back, and an IBPB
    // (IA32_PRED_CMD 49h, bit 0), change no state other code relies on;
    // a refused write is caught.
    unsafe { cpu::wrmsr_safe(IA32_SPEC_CTRL, current) && cpu::wrmsr_safe(0x49, 1) }
}
