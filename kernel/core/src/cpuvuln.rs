//! CPU vulnerability assessment and mitigation selection (P1-S4, SR-14,
//! SR-15). Pure logic: the inputs are CPUID and MSR values read by
//! `keel-hal`, the outputs a report (one line per item) and a plan that
//! `keel-hal` applies.
//!
//! Policy: fail closed. A CPU is treated as affected unless it reports the
//! matching `*_NO` bit, or Linux's tables say its model is not affected.
//! Keel carries Linux's per-model rows only for the Skylake-family models
//! its target belongs to; any other model is reported as "assumed
//! affected" for the model-listed bugs.
//!
//! Sources (read 2026-11-22): Linux v6.18 `arch/x86/kernel/cpu/common.c`
//! (`cpu_vuln_blacklist`: INTEL_SKYLAKE_L, INTEL_SKYLAKE, INTEL_KABYLAKE_L,
//! INTEL_KABYLAKE rows, and the BHI rule), `arch/x86/include/asm/
//! msr-index.h` (ARCH_CAP_*, SPEC_CTRL_*, MCU_OPT_CTRL bits),
//! `cpufeatures.h` and `kernel/cpu/scattered.c` (CPUID bit positions),
//! `intel-family.h` (model numbers); v6.12 `kernel/cpu/bugs.c` (legacy
//! IBRS chosen for retbleed-affected Intel CPUs; RSB filled on every
//! context switch) and `Documentation/admin-guide/hw-vuln/*.rst`.

use alloc::vec::Vec;

/// IA32_ARCH_CAPABILITIES bits.
pub mod arch_cap {
    pub const RDCL_NO: u64 = 1 << 0;
    pub const IBRS_ALL: u64 = 1 << 1;
    pub const SSB_NO: u64 = 1 << 4;
    pub const MDS_NO: u64 = 1 << 5;
    pub const TAA_NO: u64 = 1 << 8;
    pub const SBDR_SSDP_NO: u64 = 1 << 13;
    pub const FBSDP_NO: u64 = 1 << 14;
    pub const PSDP_NO: u64 = 1 << 15;
    pub const FB_CLEAR: u64 = 1 << 17;
    pub const BHI_NO: u64 = 1 << 20;
    pub const GDS_CTRL: u64 = 1 << 25;
    pub const GDS_NO: u64 = 1 << 26;
    pub const RFDS_NO: u64 = 1 << 27;
    pub const ITS_NO: u64 = 1 << 62;
}

/// CPUID.(EAX=7,ECX=0):EDX bits (Linux cpufeatures.h word 18).
pub mod edx7 {
    pub const SRBDS_CTRL: u32 = 1 << 9;
    pub const MD_CLEAR: u32 = 1 << 10;
    pub const SPEC_CTRL: u32 = 1 << 26;
    pub const ARCH_CAPABILITIES: u32 = 1 << 29;
    pub const SSBD: u32 = 1 << 31;
}

/// IA32_SPEC_CTRL bits.
pub mod spec_ctrl {
    pub const IBRS: u64 = 1 << 0;
    pub const SSBD: u64 = 1 << 2;
    pub const BHI_DIS_S: u64 = 1 << 10;
}

/// IA32_MCU_OPT_CTRL bits.
pub mod mcu_opt {
    pub const RNGDS_MITG_DIS: u64 = 1 << 0;
    pub const GDS_MITG_DIS: u64 = 1 << 4;
    pub const GDS_MITG_LOCKED: u64 = 1 << 5;
}

/// Family, model and stepping from the CPUID.1:EAX signature, as Linux
/// computes them (`arch/x86/lib/cpu.c`: the extended family is added only
/// for base family 0xF; the extended model is prepended for family 6 and
/// above).
pub fn decode_signature(signature: u32) -> (u32, u32, u32) {
    let mut family = (signature >> 8) & 0xf;
    if family == 0xf {
        family += (signature >> 20) & 0xff;
    }
    let mut model = (signature >> 4) & 0xf;
    if family >= 6 {
        model += ((signature >> 16) & 0xf) << 4;
    }
    (family, model, signature & 0xf)
}

/// What the CPU reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuInfo {
    pub intel: bool,
    /// Display family and model (CPUID.1 with the extended fields added).
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    /// CPUID.1:ECX[31]: running under a hypervisor.
    pub hypervisor: bool,
    /// CPUID.(7,0):EBX[11]: RTM (TSX).
    pub rtm: bool,
    /// CPUID.(7,0):EDX.
    pub edx7: u32,
    /// CPUID.(7,2):EDX[4]: BHI_DIS_S is available.
    pub bhi_ctrl: bool,
    /// IA32_ARCH_CAPABILITIES, or 0 if the MSR does not exist.
    pub arch_capabilities: u64,
    /// IA32_MCU_OPT_CTRL, if it exists and could be read.
    pub mcu_opt_ctrl: Option<u64>,
}

/// How one item stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    NotAffected(&'static str),
    Mitigated(&'static str),
    Vulnerable(&'static str),
}

/// One line of the boot report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    pub name: &'static str,
    pub status: Status,
}

/// What to switch on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Page-table isolation (always on in Phase 1; SR-14 allows skipping
    /// it only when RDCL_NO is set, and Keel keeps it regardless).
    pub pti: bool,
    /// Whether IA32_SPEC_CTRL exists.
    pub spec_ctrl: bool,
    /// IA32_SPEC_CTRL while kernel code runs and while user code runs.
    pub spec_ctrl_kernel: u64,
    pub spec_ctrl_user: u64,
    /// Legacy IBRS: write `spec_ctrl_kernel` on every kernel entry and
    /// `spec_ctrl_user` on every return to user mode.
    pub ibrs_on_entry: bool,
    /// IBPB when switching to a different user address space.
    pub ibpb_on_switch: bool,
    /// Overwrite the return stack buffer on every context switch.
    pub rsb_fill: bool,
    /// VERW before every return to user mode (MDS, TAA, MMIO stale data).
    pub verw_on_exit: bool,
    /// Value to write to IA32_MCU_OPT_CTRL, if it must change.
    pub mcu_opt_ctrl: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Bugs {
    mmio: bool,
    retbleed: bool,
    gds: bool,
    srbds: bool,
    its: bool,
}

/// Linux v6.18 `cpu_vuln_blacklist` rows for the Skylake-family desktop
/// and mobile models (family 6): SKYLAKE_L 0x4E, SKYLAKE 0x5E: MMIO,
/// RETBLEED, GDS, SRBDS; KABYLAKE_L 0x8E, KABYLAKE 0x9E: the same, plus
/// ITS for steppings above 0xC. (VMSCAPE, also listed, concerns
/// hypervisors; Keel is not one.) `None` for any other model.
fn model_row(cpu: &CpuInfo) -> Option<Bugs> {
    if !cpu.intel || cpu.family != 6 {
        return None;
    }
    let base = Bugs {
        mmio: true,
        retbleed: true,
        gds: true,
        srbds: true,
        its: false,
    };
    match cpu.model {
        0x4E | 0x5E => Some(base),
        0x8E | 0x9E => Some(Bugs {
            its: cpu.stepping > 0xC,
            ..base
        }),
        _ => None,
    }
}

/// Assesses the CPU and chooses mitigations.
pub fn assess(cpu: &CpuInfo) -> (Plan, Vec<Item>) {
    use Status::*;
    let caps = cpu.arch_capabilities;
    let has = |bit: u64| caps & bit != 0;
    let row = model_row(cpu);
    let known = row.is_some();
    let listed = |pick: fn(&Bugs) -> bool| row.as_ref().is_none_or(pick);
    let feature = |bit: u32| cpu.edx7 & bit != 0;
    let mut items = Vec::new();
    let mut plan = Plan {
        pti: true,
        spec_ctrl: feature(edx7::SPEC_CTRL) || feature(edx7::SSBD),
        rsb_fill: true,
        ..Plan::default()
    };
    let mut push = |name, status| items.push(Item { name, status });

    // Meltdown (SR-14).
    push(
        "Meltdown",
        if has(arch_cap::RDCL_NO) {
            NotAffected("RDCL_NO; page-table isolation kept on anyway")
        } else {
            Mitigated("page-table isolation")
        },
    );

    // Spectre v1: no CPU fix exists; the kernel masks user-controlled
    // indices (system-call table, handle table) without branches.
    push(
        "Spectre v1",
        Mitigated("index masking of user-controlled indices; no SWAPGS"),
    );

    // Spectre v2 (and Retbleed on Skylake-family parts).
    let ibrs = feature(edx7::SPEC_CTRL);
    let eibrs = has(arch_cap::IBRS_ALL);
    if eibrs {
        plan.spec_ctrl_kernel |= spec_ctrl::IBRS;
        plan.spec_ctrl_user |= spec_ctrl::IBRS;
        push("Spectre v2", Mitigated("enhanced IBRS"));
    } else if ibrs {
        plan.spec_ctrl_kernel |= spec_ctrl::IBRS;
        plan.ibrs_on_entry = true;
        push(
            "Spectre v2",
            Mitigated("IBRS written on every kernel entry"),
        );
    } else {
        push(
            "Spectre v2",
            Vulnerable("no IBRS (microcode needed); retpolines are not available"),
        );
    }
    push(
        "Retbleed",
        if !listed(|b| b.retbleed) && known {
            NotAffected("model not listed")
        } else if eibrs {
            Mitigated("enhanced IBRS")
        } else if ibrs {
            Mitigated("IBRS on kernel entry")
        } else {
            Vulnerable("no IBRS")
        },
    );
    plan.ibpb_on_switch = ibrs;
    push(
        "Spectre v2 between processes",
        if ibrs {
            Mitigated("IBPB when switching address spaces")
        } else {
            Vulnerable("no IBPB (microcode needed)")
        },
    );
    push(
        "SpectreRSB",
        Mitigated("return stack filled on every context switch"),
    );

    // Branch history injection: Linux counts it only with eIBRS or under
    // a hypervisor (which may hide eIBRS).
    let bhi = !has(arch_cap::BHI_NO) && cpu.intel && (eibrs || cpu.hypervisor);
    push(
        "BHI",
        if !bhi {
            NotAffected(if has(arch_cap::BHI_NO) {
                "BHI_NO"
            } else if !cpu.intel {
                "not Intel"
            } else {
                "no enhanced IBRS, not virtualized"
            })
        } else if cpu.bhi_ctrl {
            plan.spec_ctrl_kernel |= spec_ctrl::BHI_DIS_S;
            plan.spec_ctrl_user |= spec_ctrl::BHI_DIS_S;
            Mitigated("BHI_DIS_S")
        } else {
            Vulnerable("no BHI_DIS_S; software history clearing not implemented")
        },
    );

    // Speculative store bypass: SSBD on for all user code (every process
    // will be in a compartment, SR-15).
    let ssbd = feature(edx7::SSBD);
    push(
        "Speculative Store Bypass",
        if has(arch_cap::SSB_NO) {
            NotAffected("SSB_NO")
        } else if ssbd {
            plan.spec_ctrl_kernel |= spec_ctrl::SSBD;
            plan.spec_ctrl_user |= spec_ctrl::SSBD;
            Mitigated("SSBD always on")
        } else {
            Vulnerable("no SSBD (microcode needed)")
        },
    );

    // L1TF: Keel never leaves a not-present entry holding bits (checked by
    // the page-table self-test), which is all bare-metal Linux relies on
    // too (PTE inversion).
    push(
        "L1TF",
        if !cpu.intel || has(arch_cap::RDCL_NO) {
            NotAffected("RDCL_NO or not Intel")
        } else {
            Mitigated("no stale not-present page-table entries")
        },
    );

    // MDS, TAA, MMIO stale data: VERW before every return to user mode.
    let md_clear = feature(edx7::MD_CLEAR);
    let mds = cpu.intel && !has(arch_cap::MDS_NO);
    let taa = cpu.intel && cpu.rtm && !has(arch_cap::TAA_NO);
    let mmio = cpu.intel
        && listed(|b| b.mmio)
        && !(has(arch_cap::FBSDP_NO) && has(arch_cap::PSDP_NO) && has(arch_cap::SBDR_SSDP_NO));
    plan.verw_on_exit = mds || taa || mmio;
    let verw = if md_clear || has(arch_cap::FB_CLEAR) {
        Mitigated("VERW before every return to user mode")
    } else {
        Vulnerable("VERW issued, but the CPU does not report MD_CLEAR (microcode needed)")
    };
    push(
        "MDS",
        if mds {
            verw
        } else {
            NotAffected("MDS_NO or not Intel")
        },
    );
    push(
        "TAA",
        if taa {
            verw
        } else {
            NotAffected("no TSX, TAA_NO, or not Intel")
        },
    );
    push(
        "MMIO stale data",
        if !mmio {
            NotAffected("not listed or *_NO bits")
        } else if md_clear || has(arch_cap::FB_CLEAR) {
            Mitigated("VERW before every return to user mode; no user MMIO")
        } else {
            Vulnerable("no FB_CLEAR/MD_CLEAR (microcode needed); no user MMIO")
        },
    );

    // SRBDS and GDS: microcode mitigations; make sure they are not off.
    let mut mcu = cpu.mcu_opt_ctrl;
    let srbds = cpu.intel && listed(|b| b.srbds);
    push(
        "SRBDS",
        if !srbds {
            NotAffected("model not listed")
        } else if !feature(edx7::SRBDS_CTRL) {
            Vulnerable("no SRBDS microcode: RDRAND output visible to other cores")
        } else if let Some(value) = mcu.as_mut() {
            *value &= !mcu_opt::RNGDS_MITG_DIS;
            Mitigated("microcode (RDRAND/RDSEED serialized)")
        } else {
            Vulnerable("SRBDS control unreadable")
        },
    );
    let gds = cpu.intel && !has(arch_cap::GDS_NO) && listed(|b| b.gds);
    push(
        "GDS",
        if !gds {
            NotAffected("GDS_NO or model not listed")
        } else if !has(arch_cap::GDS_CTRL) {
            Vulnerable("no GDS microcode (early microcode update: P6-S8)")
        } else if let Some(value) = mcu.as_mut() {
            if *value & mcu_opt::GDS_MITG_LOCKED != 0 && *value & mcu_opt::GDS_MITG_DIS != 0 {
                Vulnerable("GDS mitigation disabled and locked by firmware")
            } else {
                *value &= !mcu_opt::GDS_MITG_DIS;
                Mitigated("microcode")
            }
        } else {
            Vulnerable("GDS control unreadable")
        },
    );
    if mcu != cpu.mcu_opt_ctrl {
        plan.mcu_opt_ctrl = mcu;
    }

    let its = cpu.intel && !has(arch_cap::ITS_NO) && listed(|b| b.its);
    push(
        "ITS",
        if its {
            Vulnerable(if known {
                "no indirect-target-selection mitigation implemented"
            } else {
                "model not in Keel's table: assumed affected; no mitigation implemented"
            })
        } else {
            NotAffected("ITS_NO or model not listed")
        },
    );
    // RFDS affects Atom cores only (Linux's rows); Keel's table covers
    // core models, so other models are assumed affected.
    push(
        "RFDS",
        if !cpu.intel || has(arch_cap::RFDS_NO) || known {
            NotAffected("RFDS_NO, not an Atom core, or not Intel")
        } else {
            Vulnerable("model not in Keel's table: assumed affected; no mitigation implemented")
        },
    );
    push(
        "SMT",
        NotAffected("one CPU in use; no sibling runs other code"),
    );

    if !cpu.intel {
        // Everything above was decided from CPUID alone.
        push(
            "Vendor",
            Vulnerable("not Intel: assessed from feature bits only"),
        );
    }
    (plan, items)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The target: i5-8500, signature 906EA (family 6, model 0x9E,
    /// stepping 0xA), bare metal. Inputs for an up-to-date microcode:
    /// IBRS/IBPB, STIBP, SSBD, MD_CLEAR, SRBDS_CTRL, ARCH_CAPABILITIES with
    /// GDS_CTRL; no TSX.
    fn optiplex(updated_microcode: bool) -> CpuInfo {
        CpuInfo {
            intel: true,
            family: 6,
            model: 0x9E,
            stepping: 0xA,
            hypervisor: false,
            rtm: false,
            edx7: if updated_microcode {
                edx7::SRBDS_CTRL
                    | edx7::MD_CLEAR
                    | edx7::SPEC_CTRL
                    | edx7::ARCH_CAPABILITIES
                    | edx7::SSBD
            } else {
                0
            },
            bhi_ctrl: false,
            arch_capabilities: if updated_microcode {
                arch_cap::GDS_CTRL
            } else {
                0
            },
            mcu_opt_ctrl: updated_microcode.then_some(mcu_opt::GDS_MITG_DIS),
        }
    }

    fn status(items: &[Item], name: &str) -> Status {
        items.iter().find(|i| i.name == name).unwrap().status
    }

    #[test]
    fn signatures_decode_like_linux() {
        assert_eq!(decode_signature(0x906EA), (6, 0x9E, 0xA), "i5-8500");
        assert_eq!(
            decode_signature(0x00A20F12),
            (0x19, 0x21, 2),
            "AMD family 19h"
        );
    }

    #[test]
    fn target_with_current_microcode() {
        let (plan, items) = assess(&optiplex(true));
        assert!(plan.pti && plan.rsb_fill && plan.verw_on_exit && plan.ibpb_on_switch);
        assert!(
            plan.ibrs_on_entry,
            "legacy IBRS, as Linux picks for retbleed parts"
        );
        assert_eq!(plan.spec_ctrl_kernel, spec_ctrl::IBRS | spec_ctrl::SSBD);
        assert_eq!(plan.spec_ctrl_user, spec_ctrl::SSBD);
        // GDS mitigation was off: the plan turns it on.
        assert_eq!(plan.mcu_opt_ctrl, Some(0));
        assert!(matches!(status(&items, "Meltdown"), Status::Mitigated(_)));
        assert!(matches!(status(&items, "MDS"), Status::Mitigated(_)));
        assert!(matches!(status(&items, "GDS"), Status::Mitigated(_)));
        assert!(matches!(status(&items, "SRBDS"), Status::Mitigated(_)));
        assert!(
            matches!(status(&items, "ITS"), Status::NotAffected(_)),
            "stepping 0xA"
        );
        assert!(matches!(status(&items, "BHI"), Status::NotAffected(_)));
        assert!(matches!(status(&items, "TAA"), Status::NotAffected(_)));
        assert!(
            !items
                .iter()
                .any(|i| matches!(i.status, Status::Vulnerable(_))),
            "{items:?}"
        );
    }

    #[test]
    fn target_without_microcode_is_reported_vulnerable() {
        let (plan, items) = assess(&optiplex(false));
        assert!(!plan.spec_ctrl && !plan.ibrs_on_entry && plan.spec_ctrl_kernel == 0);
        assert!(plan.verw_on_exit, "VERW is issued anyway");
        for name in [
            "Spectre v2",
            "MDS",
            "GDS",
            "SRBDS",
            "Speculative Store Bypass",
        ] {
            assert!(
                matches!(status(&items, name), Status::Vulnerable(_)),
                "{name}"
            );
        }
    }

    #[test]
    fn newer_cpu_bits_switch_mitigations_off() {
        let cpu = CpuInfo {
            intel: true,
            family: 6,
            model: 0xB7, // not in Keel's table
            stepping: 1,
            edx7: edx7::SPEC_CTRL | edx7::SSBD | edx7::ARCH_CAPABILITIES | edx7::MD_CLEAR,
            arch_capabilities: arch_cap::RDCL_NO
                | arch_cap::IBRS_ALL
                | arch_cap::MDS_NO
                | arch_cap::TAA_NO
                | arch_cap::SSB_NO
                | arch_cap::BHI_NO
                | arch_cap::GDS_NO
                | arch_cap::ITS_NO
                | arch_cap::RFDS_NO
                | arch_cap::FBSDP_NO
                | arch_cap::PSDP_NO
                | arch_cap::SBDR_SSDP_NO,
            ..CpuInfo::default()
        };
        let (plan, items) = assess(&cpu);
        assert!(plan.pti, "kept on even with RDCL_NO");
        assert!(!plan.ibrs_on_entry && !plan.verw_on_exit);
        assert_eq!(plan.spec_ctrl_kernel, spec_ctrl::IBRS);
        assert_eq!(plan.spec_ctrl_user, spec_ctrl::IBRS);
        assert!(matches!(
            status(&items, "Spectre v2"),
            Status::Mitigated("enhanced IBRS")
        ));
        assert!(matches!(status(&items, "MDS"), Status::NotAffected(_)));
    }

    #[test]
    fn under_a_hypervisor_bhi_counts() {
        let mut cpu = optiplex(true);
        cpu.hypervisor = true;
        let (plan, items) = assess(&cpu);
        assert!(matches!(status(&items, "BHI"), Status::Vulnerable(_)));
        cpu.bhi_ctrl = true;
        let (plan2, items) = assess(&cpu);
        assert!(matches!(status(&items, "BHI"), Status::Mitigated(_)));
        assert_eq!(
            plan2.spec_ctrl_kernel,
            plan.spec_ctrl_kernel | spec_ctrl::BHI_DIS_S
        );
    }

    #[test]
    fn unknown_models_are_assumed_affected() {
        let mut cpu = optiplex(true);
        cpu.model = 0x55;
        let (_, items) = assess(&cpu);
        assert!(matches!(status(&items, "ITS"), Status::Vulnerable(_)));
        assert!(matches!(status(&items, "RFDS"), Status::Vulnerable(_)));
        let mut locked = optiplex(true);
        locked.mcu_opt_ctrl = Some(mcu_opt::GDS_MITG_DIS | mcu_opt::GDS_MITG_LOCKED);
        assert!(matches!(
            status(&assess(&locked).1, "GDS"),
            Status::Vulnerable(_)
        ));
    }
}
