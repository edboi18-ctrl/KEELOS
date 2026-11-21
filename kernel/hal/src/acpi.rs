//! Reading ACPI tables from physical memory (P1-T6).
//!
//! Parsing is done by `keel_core::acpi` in safe Rust. This module only
//! turns physical addresses from the firmware into byte slices, and only
//! when the whole range lies inside a memory-map region that holds ACPI
//! data and is mapped in the direct map: under Limine base revision 4 and
//! later every ACPI table is guaranteed to sit in an ACPI-reclaimable,
//! ACPI-NVS or reserved-mapped region (PROTOCOL.md, "Memory Map Feature").
//! A pointer anywhere else is refused (SR-20).

use alloc::vec::Vec;

use keel_core::acpi::{self, AcpiError, Hpet, Madt, Rsdp};

use crate::boot::{self, RegionKind};

/// Why a table could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError {
    /// The firmware or bootloader provides no ACPI.
    NoAcpi,
    /// The table is not listed in the XSDT/RSDT.
    NotFound,
    /// An address points outside the ACPI memory regions.
    OutsideAcpiMemory,
    Invalid(AcpiError),
}

impl From<AcpiError> for TableError {
    fn from(error: AcpiError) -> Self {
        TableError::Invalid(error)
    }
}

/// `length` bytes at physical `phys`, if the range lies entirely inside
/// one ACPI region of the memory map.
fn physical_bytes(phys: u64, length: usize) -> Result<&'static [u8], TableError> {
    let hhdm = boot::hhdm_offset().ok_or(TableError::NoAcpi)?;
    let end = phys
        .checked_add(length as u64)
        .ok_or(TableError::OutsideAcpiMemory)?;
    let inside = boot::memory_map().any(|r| {
        matches!(
            r.kind,
            RegionKind::AcpiReclaimable | RegionKind::AcpiNvs | RegionKind::ReservedMapped
        ) && r.base <= phys
            && end <= r.base.saturating_add(r.length)
    });
    if !inside {
        return Err(TableError::OutsideAcpiMemory);
    }
    // SAFETY: the range lies inside one region of a kind the direct map
    // covers read+write (hal::paging maps ACPI-reclaimable, ACPI-NVS and
    // reserved-mapped regions, rounded outward to pages). Firmware tables
    // are not modified while Keel runs (it never reclaims ACPI memory), so
    // a shared `'static` slice is sound. `u8` has alignment 1.
    Ok(unsafe { core::slice::from_raw_parts((hhdm + phys) as *const u8, length) })
}

/// The RSDP.
pub fn rsdp() -> Result<Rsdp, TableError> {
    let phys = boot::rsdp_physical().ok_or(TableError::NoAcpi)?;
    let v1 = physical_bytes(phys, acpi::RSDP_V1_LEN)?;
    // Revision 2 and later have 36 bytes; read them only if claimed.
    let bytes = if v1[15] >= 2 {
        physical_bytes(phys, acpi::RSDP_V2_LEN)?
    } else {
        v1
    };
    Ok(acpi::parse_rsdp(bytes)?)
}

/// The whole table at `phys`, after checking its signature and checksum.
fn table_at(phys: u64, signature: &[u8; 4]) -> Result<&'static [u8], TableError> {
    let header = physical_bytes(phys, acpi::HEADER_LEN)?;
    let (_, length) = acpi::peek_header(header)?;
    let bytes = physical_bytes(phys, length)?;
    Ok(acpi::validate_table(bytes, signature)?)
}

/// Physical addresses of every table listed in the XSDT (or the RSDT on
/// ACPI 1.0 firmware).
fn root_entries() -> Result<Vec<u64>, TableError> {
    let rsdp = rsdp()?;
    match rsdp.xsdt {
        Some(xsdt) => Ok(acpi::root_entries(table_at(xsdt, b"XSDT")?, true)?),
        None => Ok(acpi::root_entries(
            table_at(u64::from(rsdp.rsdt), b"RSDT")?,
            false,
        )?),
    }
}

/// Finds and validates the table with `signature`.
pub fn find_table(signature: &[u8; 4]) -> Result<&'static [u8], TableError> {
    for phys in root_entries()? {
        let Ok(header) = physical_bytes(phys, acpi::HEADER_LEN) else {
            continue;
        };
        if &header[..4] == signature {
            return table_at(phys, signature);
        }
    }
    Err(TableError::NotFound)
}

/// The MADT.
pub fn madt() -> Result<Madt, TableError> {
    Ok(acpi::parse_madt(find_table(b"APIC")?)?)
}

/// The HPET table.
pub fn hpet() -> Result<Hpet, TableError> {
    Ok(acpi::parse_hpet(find_table(b"HPET")?)?)
}
