//! Parsers for the ACPI tables Keel reads (P1-T6): RSDP, XSDT/RSDT, MADT
//! and HPET. Safe Rust, bounds-checked, checksum-verified; firmware bytes
//! are untrusted input (SR-20) and any malformed table is rejected rather
//! than partly used (SR-10).
//!
//! Layouts are from the ACPI Specification 6.6, chapter 5:
//!  - Table 5.3 "RSDP Structure";
//!  - section 5.2.6 "System Description Table Header" (36 bytes);
//!  - Table 5.8 "Extended System Description Table Fields (XSDT)": 64-bit
//!    entries from offset 36; the RSDT has 32-bit entries;
//!  - Table 5.19 "MADT Format", Table 5.21 "Interrupt Controller Structure
//!    Types", Tables 5.22-5.26 and 5.28, and section 5.2.12.12 (x2APIC);
//!  - Table 5.1 "Generic Address Structure".
//!
//! The HPET table layout is from the IA-PC HPET Specification 1.0a,
//! "HPET Description Table" (event timer block ID at offset 36, base
//! address as a Generic Address Structure at offset 40).

use alloc::vec::Vec;

/// Why a table was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiError {
    /// Shorter than its fixed fields, or a length field points past the
    /// bytes provided.
    Truncated,
    /// The bytes do not add up to zero.
    BadChecksum,
    /// Wrong signature for the table being parsed.
    BadSignature,
    /// A field holds a value the specification does not allow.
    Malformed,
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, AcpiError> {
    let b = bytes.get(offset..offset + 2).ok_or(AcpiError::Truncated)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, AcpiError> {
    let b = bytes.get(offset..offset + 4).ok_or(AcpiError::Truncated)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, AcpiError> {
    let b = bytes.get(offset..offset + 8).ok_or(AcpiError::Truncated)?;
    let mut word = [0u8; 8];
    word.copy_from_slice(b);
    Ok(u64::from_le_bytes(word))
}

fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, &b| sum.wrapping_add(b)) == 0
}

/// The parts of the RSDP Keel uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rsdp {
    pub revision: u8,
    /// Physical address of the RSDT (ACPI 1.0).
    pub rsdt: u32,
    /// Physical address of the XSDT (revision 2 and later).
    pub xsdt: Option<u64>,
}

/// Length of the ACPI 1.0 part of the RSDP.
pub const RSDP_V1_LEN: usize = 20;
/// Length of the revision 2 RSDP.
pub const RSDP_V2_LEN: usize = 36;

/// Parses an RSDP. `bytes` must hold at least 20 bytes, and 36 for a
/// revision 2 structure.
pub fn parse_rsdp(bytes: &[u8]) -> Result<Rsdp, AcpiError> {
    let v1 = bytes.get(..RSDP_V1_LEN).ok_or(AcpiError::Truncated)?;
    if &v1[..8] != b"RSD PTR " {
        return Err(AcpiError::BadSignature);
    }
    // "This includes only the first 20 bytes of this table, bytes 0 to 19,
    // including the checksum field. These bytes must sum to zero."
    if !checksum_ok(v1) {
        return Err(AcpiError::BadChecksum);
    }
    let revision = v1[15];
    let rsdt = u32_at(v1, 16)?;
    if revision < 2 {
        return Ok(Rsdp {
            revision,
            rsdt,
            xsdt: None,
        });
    }
    let length = u32_at(bytes, 20)? as usize;
    if length < RSDP_V2_LEN {
        return Err(AcpiError::Malformed);
    }
    let whole = bytes.get(..length).ok_or(AcpiError::Truncated)?;
    if !checksum_ok(whole) {
        return Err(AcpiError::BadChecksum);
    }
    let xsdt = u64_at(whole, 24)?;
    Ok(Rsdp {
        revision,
        rsdt,
        xsdt: (xsdt != 0).then_some(xsdt),
    })
}

/// Length of the common table header.
pub const HEADER_LEN: usize = 36;

/// Reads a table's signature and total length from its header, without
/// validating the rest (used to find out how many bytes to read).
pub fn peek_header(bytes: &[u8]) -> Result<([u8; 4], usize), AcpiError> {
    let header = bytes.get(..HEADER_LEN).ok_or(AcpiError::Truncated)?;
    let mut signature = [0u8; 4];
    signature.copy_from_slice(&header[..4]);
    let length = u32_at(header, 4)? as usize;
    if length < HEADER_LEN {
        return Err(AcpiError::Malformed);
    }
    Ok((signature, length))
}

/// Validates a whole table: the length field must fit in `bytes` and the
/// checksum over that length must be zero. Returns the table's bytes,
/// trimmed to its length.
pub fn validate_table<'a>(bytes: &'a [u8], signature: &[u8; 4]) -> Result<&'a [u8], AcpiError> {
    let (found, length) = peek_header(bytes)?;
    if &found != signature {
        return Err(AcpiError::BadSignature);
    }
    let table = bytes.get(..length).ok_or(AcpiError::Truncated)?;
    if !checksum_ok(table) {
        return Err(AcpiError::BadChecksum);
    }
    Ok(table)
}

/// Physical addresses listed in a validated XSDT (`wide = true`, 8-byte
/// entries) or RSDT (4-byte entries). Trailing bytes that do not form a
/// whole entry make the table malformed.
pub fn root_entries(table: &[u8], wide: bool) -> Result<Vec<u64>, AcpiError> {
    let body = table.get(HEADER_LEN..).ok_or(AcpiError::Truncated)?;
    let size = if wide { 8 } else { 4 };
    if !body.len().is_multiple_of(size) {
        return Err(AcpiError::Malformed);
    }
    body.chunks_exact(size)
        .map(|entry| {
            if wide {
                u64_at(entry, 0)
            } else {
                u32_at(entry, 0).map(u64::from)
            }
        })
        .collect()
}

/// Polarity and trigger mode from an MPS INTI flags field (Table 5.26).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntiFlags {
    /// `None`: conforms to the bus. `Some(true)`: active low.
    pub active_low: Option<bool>,
    /// `None`: conforms to the bus. `Some(true)`: level-triggered.
    pub level_triggered: Option<bool>,
}

fn inti_flags(raw: u16) -> Result<IntiFlags, AcpiError> {
    let decode = |bits: u16| match bits {
        0b00 => Ok(None),
        0b01 => Ok(Some(false)),
        0b11 => Ok(Some(true)),
        _ => Err(AcpiError::Malformed), // 10 is reserved
    };
    Ok(IntiFlags {
        active_low: decode(raw & 0b11)?,
        level_triggered: decode(raw >> 2 & 0b11)?,
    })
}

/// One MADT entry Keel understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MadtEntry {
    /// Type 0, Table 5.22.
    LocalApic {
        uid: u8,
        apic_id: u8,
        enabled: bool,
        online_capable: bool,
    },
    /// Type 1, Table 5.24.
    IoApic { id: u8, address: u32, gsi_base: u32 },
    /// Type 2, Table 5.25.
    InterruptOverride {
        source_irq: u8,
        gsi: u32,
        flags: IntiFlags,
    },
    /// Type 4, Table 5.28.
    LocalApicNmi { uid: u8, flags: IntiFlags, lint: u8 },
    /// Type 5: a 64-bit local APIC address replacing the header's.
    LocalApicAddress { address: u64 },
    /// Type 9, section 5.2.12.12.
    LocalX2Apic {
        x2apic_id: u32,
        enabled: bool,
        uid: u32,
    },
    /// Any other type; skipped using its length.
    Other { kind: u8 },
}

/// The parts of the MADT Keel uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Madt {
    /// Local APIC physical address, after any type 5 override.
    pub local_apic_address: u64,
    /// MADT flags bit 0: dual 8259 PICs are present and must be masked.
    pub pcat_compat: bool,
    pub entries: Vec<MadtEntry>,
}

/// Parses a validated MADT (signature "APIC").
pub fn parse_madt(table: &[u8]) -> Result<Madt, AcpiError> {
    let table = validate_table(table, b"APIC")?;
    let mut local_apic_address = u64::from(u32_at(table, 36)?);
    let pcat_compat = u32_at(table, 40)? & 1 != 0;
    let mut entries = Vec::new();
    let mut offset = 44;
    while offset < table.len() {
        let kind = *table.get(offset).ok_or(AcpiError::Truncated)?;
        let length = usize::from(*table.get(offset + 1).ok_or(AcpiError::Truncated)?);
        // Every entry starts with type and length; a length under 2 would
        // never advance and is malformed.
        if length < 2 {
            return Err(AcpiError::Malformed);
        }
        let entry = table
            .get(offset..offset + length)
            .ok_or(AcpiError::Truncated)?;
        let need = |n: usize| {
            if length >= n {
                Ok(())
            } else {
                Err(AcpiError::Malformed)
            }
        };
        let parsed = match kind {
            0 => {
                need(8)?;
                let flags = u32_at(entry, 4)?;
                MadtEntry::LocalApic {
                    uid: entry[2],
                    apic_id: entry[3],
                    enabled: flags & 1 != 0,
                    online_capable: flags & 2 != 0,
                }
            }
            1 => {
                need(12)?;
                MadtEntry::IoApic {
                    id: entry[2],
                    address: u32_at(entry, 4)?,
                    gsi_base: u32_at(entry, 8)?,
                }
            }
            2 => {
                need(10)?;
                MadtEntry::InterruptOverride {
                    source_irq: entry[3],
                    gsi: u32_at(entry, 4)?,
                    flags: inti_flags(u16_at(entry, 8)?)?,
                }
            }
            4 => {
                need(6)?;
                MadtEntry::LocalApicNmi {
                    uid: entry[2],
                    flags: inti_flags(u16_at(entry, 3)?)?,
                    lint: entry[5],
                }
            }
            5 => {
                need(12)?;
                let address = u64_at(entry, 4)?;
                local_apic_address = address;
                MadtEntry::LocalApicAddress { address }
            }
            9 => {
                need(16)?;
                MadtEntry::LocalX2Apic {
                    x2apic_id: u32_at(entry, 4)?,
                    enabled: u32_at(entry, 8)? & 1 != 0,
                    uid: u32_at(entry, 12)?,
                }
            }
            other => MadtEntry::Other { kind: other },
        };
        entries.push(parsed);
        offset += length;
    }
    Ok(Madt {
        local_apic_address,
        pcat_compat,
        entries,
    })
}

/// The parts of the HPET table Keel uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hpet {
    /// Physical address of the event timer block (1 KiB of registers).
    pub address: u64,
}

/// Parses a validated HPET table. Only a timer block in system memory
/// (Generic Address Structure address space 0) is accepted.
pub fn parse_hpet(table: &[u8]) -> Result<Hpet, AcpiError> {
    let table = validate_table(table, b"HPET")?;
    let address_space = *table.get(40).ok_or(AcpiError::Truncated)?;
    if address_space != 0 {
        return Err(AcpiError::Malformed);
    }
    let address = u64_at(table, 44)?;
    if address == 0 || !address.is_multiple_of(1024) {
        return Err(AcpiError::Malformed);
    }
    Ok(Hpet { address })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a table with a correct header and checksum around `body`.
    fn table(signature: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(signature);
        t.extend_from_slice(&((HEADER_LEN + body.len()) as u32).to_le_bytes());
        t.push(1); // revision
        t.push(0); // checksum, fixed below
        t.extend_from_slice(b"KEELOS");
        t.extend_from_slice(b"TESTTABL");
        t.extend_from_slice(&[0; 12]);
        assert_eq!(t.len(), HEADER_LEN);
        t.extend_from_slice(body);
        fix_checksum(&mut t, 9);
        t
    }

    fn fix_checksum(bytes: &mut [u8], at: usize) {
        bytes[at] = 0;
        let sum = bytes.iter().fold(0u8, |s, &b| s.wrapping_add(b));
        bytes[at] = sum.wrapping_neg();
    }

    fn rsdp_v2(xsdt: u64) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(b"RSD PTR ");
        r.push(0);
        r.extend_from_slice(b"KEELOS");
        r.push(2);
        r.extend_from_slice(&0x1000u32.to_le_bytes());
        r.extend_from_slice(&36u32.to_le_bytes());
        r.extend_from_slice(&xsdt.to_le_bytes());
        r.extend_from_slice(&[0; 4]);
        fix_checksum(&mut r[..20], 8);
        fix_checksum(&mut r, 32);
        r
    }

    #[test]
    fn rsdp_versions_and_checksums() {
        let r = rsdp_v2(0x7fe1_4000);
        assert_eq!(
            parse_rsdp(&r),
            Ok(Rsdp {
                revision: 2,
                rsdt: 0x1000,
                xsdt: Some(0x7fe1_4000)
            })
        );
        let mut bad = r.clone();
        bad[30] ^= 1; // breaks only the extended checksum
        assert_eq!(parse_rsdp(&bad), Err(AcpiError::BadChecksum));
        let mut v1 = r[..20].to_vec();
        v1[15] = 0;
        fix_checksum(&mut v1, 8);
        assert_eq!(parse_rsdp(&v1).unwrap().xsdt, None);
        assert_eq!(parse_rsdp(&r[..20]), Err(AcpiError::Truncated)); // rev 2 needs 36
        assert_eq!(
            parse_rsdp(b"RSD PTX 0123456789ab"),
            Err(AcpiError::BadSignature)
        );
    }

    #[test]
    fn root_tables() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x1111_2222_3333u64.to_le_bytes());
        body.extend_from_slice(&0x4444u64.to_le_bytes());
        let xsdt = table(b"XSDT", &body);
        let t = validate_table(&xsdt, b"XSDT").unwrap();
        assert_eq!(
            root_entries(t, true),
            Ok(alloc::vec![0x1111_2222_3333, 0x4444])
        );
        assert_eq!(root_entries(t, false).unwrap().len(), 4);
        let odd = table(b"XSDT", &[1, 2, 3]);
        assert_eq!(root_entries(&odd, true), Err(AcpiError::Malformed));
        let mut corrupt = xsdt.clone();
        corrupt[40] ^= 0xFF;
        assert_eq!(
            validate_table(&corrupt, b"XSDT"),
            Err(AcpiError::BadChecksum)
        );
        assert_eq!(validate_table(&xsdt, b"APIC"), Err(AcpiError::BadSignature));
        let mut long = xsdt.clone();
        long[4] = 200; // length beyond the buffer
        assert_eq!(validate_table(&long, b"XSDT"), Err(AcpiError::Truncated));
    }

    fn madt_body(entries: &[&[u8]]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0xFEE0_0000u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // PCAT_COMPAT
        for e in entries {
            b.extend_from_slice(e);
        }
        b
    }

    #[test]
    fn madt_entries() {
        let lapic = [0u8, 8, 0, 0, 1, 0, 0, 0];
        let ioapic = [1u8, 12, 0, 0, 0x00, 0x00, 0xC0, 0xFE, 0, 0, 0, 0];
        // IRQ 0 -> GSI 2, flags 0 (conforms to bus).
        let iso = [2u8, 10, 0, 0, 2, 0, 0, 0, 0, 0];
        // IRQ 9 -> GSI 9, active low (11), level (11): 0b1111.
        let iso_sci = [2u8, 10, 0, 9, 9, 0, 0, 0, 0x0F, 0];
        let nmi = [4u8, 6, 0xFF, 0x05, 0x00, 1];
        let unknown = [0x7Fu8, 4, 0, 0];
        let madt = table(
            b"APIC",
            &madt_body(&[&lapic, &ioapic, &iso, &iso_sci, &nmi, &unknown]),
        );
        let m = parse_madt(&madt).unwrap();
        assert_eq!(m.local_apic_address, 0xFEE0_0000);
        assert!(m.pcat_compat);
        assert_eq!(
            m.entries,
            alloc::vec![
                MadtEntry::LocalApic {
                    uid: 0,
                    apic_id: 0,
                    enabled: true,
                    online_capable: false
                },
                MadtEntry::IoApic {
                    id: 0,
                    address: 0xFEC0_0000,
                    gsi_base: 0
                },
                MadtEntry::InterruptOverride {
                    source_irq: 0,
                    gsi: 2,
                    flags: IntiFlags {
                        active_low: None,
                        level_triggered: None
                    }
                },
                MadtEntry::InterruptOverride {
                    source_irq: 9,
                    gsi: 9,
                    flags: IntiFlags {
                        active_low: Some(true),
                        level_triggered: Some(true)
                    }
                },
                MadtEntry::LocalApicNmi {
                    uid: 0xFF,
                    flags: IntiFlags {
                        active_low: Some(false),
                        level_triggered: Some(false)
                    },
                    lint: 1
                },
                MadtEntry::Other { kind: 0x7F },
            ]
        );
    }

    #[test]
    fn madt_rejects_malformed_entries() {
        // Zero length would loop forever.
        let zero = table(b"APIC", &madt_body(&[&[0u8, 0, 0, 0]]));
        assert_eq!(parse_madt(&zero), Err(AcpiError::Malformed));
        // Entry runs past the end of the table.
        let past = table(b"APIC", &madt_body(&[&[1u8, 12, 0, 0]]));
        assert_eq!(parse_madt(&past), Err(AcpiError::Truncated));
        // An I/O APIC entry too short for its fields.
        let short = table(b"APIC", &madt_body(&[&[1u8, 6, 0, 0, 0, 0]]));
        assert_eq!(parse_madt(&short), Err(AcpiError::Malformed));
        // Reserved polarity value 10.
        let reserved = table(
            b"APIC",
            &madt_body(&[&[2u8, 10, 0, 1, 1, 0, 0, 0, 0x02, 0]]),
        );
        assert_eq!(parse_madt(&reserved), Err(AcpiError::Malformed));
    }

    #[test]
    fn madt_address_override() {
        let over = [5u8, 12, 0, 0, 0, 0, 0xE0, 0xFE, 1, 0, 0, 0];
        let m = parse_madt(&table(b"APIC", &madt_body(&[&over]))).unwrap();
        assert_eq!(m.local_apic_address, 0x1_FEE0_0000);
    }

    #[test]
    fn hpet_table() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x8086_A201u32.to_le_bytes()); // block ID
        body.extend_from_slice(&[0, 0, 0, 0]); // GAS: memory, width, offset, size
        body.extend_from_slice(&0xFED0_0000u64.to_le_bytes());
        body.extend_from_slice(&[0, 0x80, 0, 0]); // number, minimum tick, attributes
        let hpet = table(b"HPET", &body);
        assert_eq!(
            parse_hpet(&hpet),
            Ok(Hpet {
                address: 0xFED0_0000
            })
        );
        let mut io_space = hpet.clone();
        io_space[40] = 1;
        fix_checksum(&mut io_space, 9);
        assert_eq!(parse_hpet(&io_space), Err(AcpiError::Malformed));
    }

    /// A small fuzz loop: arbitrary bytes must produce an error or a
    /// result, never a panic. The real fuzz target (cargo-fuzz) comes
    /// with the security work; this runs on every `cargo test`.
    #[test]
    fn random_bytes_never_panic() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..20_000 {
            let len = (next() % 160) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if round % 2 == 0 && len >= HEADER_LEN {
                // Make some inputs look like real tables so the entry
                // parser is reached.
                bytes[..4].copy_from_slice(b"APIC");
                bytes[4..8].copy_from_slice(&(len as u32).to_le_bytes());
                fix_checksum(&mut bytes, 9);
            }
            let _ = parse_rsdp(&bytes);
            let _ = parse_madt(&bytes);
            let _ = parse_hpet(&bytes);
            if let Ok(t) = validate_table(&bytes, b"APIC") {
                let _ = root_entries(t, round % 3 == 0);
            }
        }
    }
}
