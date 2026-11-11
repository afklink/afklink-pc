//! The raw SMBIOS table as `GetSystemFirmwareTable('RSMB')` returns it, read for the two structures
//! the fingerprint needs: type 1 (System Information: the system UUID, the maker and the product)
//! and type 0 (BIOS Information: the vendor and the version, for the virtual machine table).
//!
//! The buffer is Windows' `RawSMBIOSData`:
//!
//! | offset | size | field                                                    |
//! |--------|------|----------------------------------------------------------|
//! | 0      | 1    | `Used20CallingMethod`                                    |
//! | 1      | 1    | `SMBIOSMajorVersion`                                     |
//! | 2      | 1    | `SMBIOSMinorVersion`                                     |
//! | 3      | 1    | `DmiRevision`                                            |
//! | 4      | 4    | `Length` (little-endian): the bytes of table data after  |
//! | 8      | …    | `SMBIOSTableData`: the structures, one after another     |
//!
//! Each structure (DSP0134 §6.1): `type` u8, `length` u8 (the formatted part, header included),
//! `handle` u16, the formatted fields, then its strings — each NUL-terminated, the set ended by one
//! more NUL (two NULs when there are none). A string field holds the string's 1-based number in that
//! set; 0 means none. Type 127 ends the table.
//!
//! Nothing here is ever logged: the reasons it returns name what is wrong, never a value.

/// SMBIOS structure types read here.
const TYPE_BIOS: u8 = 0;
const TYPE_SYSTEM: u8 = 1;
const TYPE_END: u8 = 127;

/// Type 0 (BIOS Information): the string numbers of the vendor and the version.
const BIOS_VENDOR: usize = 0x04;
const BIOS_VERSION: usize = 0x05;

/// Type 1 (System Information): the string numbers of the maker and the product, and the 16 bytes
/// of the UUID (SMBIOS 2.1 and later; a 2.0 structure ends at 0x08 and has none).
const SYSTEM_MANUFACTURER: usize = 0x04;
const SYSTEM_PRODUCT: usize = 0x05;
const SYSTEM_UUID: usize = 0x08;
const UUID_LEN: usize = 16;

/// `RawSMBIOSData`'s header before the table.
const RAW_HEADER: usize = 8;

/// What the fingerprint takes from the table. No `Debug`: every field is a value about this PC.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Smbios {
    /// The type 1 structure's UUID as stored, or why there is none.
    pub(crate) uuid: Result<[u8; UUID_LEN], &'static str>,
    pub(crate) system_manufacturer: Option<String>,
    pub(crate) system_product: Option<String>,
    pub(crate) bios_vendor: Option<String>,
    pub(crate) bios_version: Option<String>,
}

impl Smbios {
    /// Nothing found: what a table with neither structure reads as.
    pub(crate) const fn empty() -> Self {
        Self {
            uuid: Err(NO_SYSTEM_STRUCTURE),
            system_manufacturer: None,
            system_product: None,
            bios_vendor: None,
            bios_version: None,
        }
    }
}

/// A table with no type 1 structure: no UUID, and no maker or product.
pub(crate) const NO_SYSTEM_STRUCTURE: &str =
    "the table has no System Information (type 1) structure";
/// A type 1 structure that ends before the UUID (SMBIOS 2.0).
pub(crate) const NO_UUID_FIELD: &str =
    "the System Information structure ends before its UUID (SMBIOS older than 2.1)";

/// Read `raw` (`RawSMBIOSData`). An error says why the table could not be walked at all; a table
/// that walks but lacks a structure or a field comes back with that part missing.
pub(crate) fn parse(raw: &[u8]) -> Result<Smbios, &'static str> {
    if raw.len() < RAW_HEADER {
        return Err("the firmware table is shorter than its own header");
    }
    let length = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let table = raw
        .get(RAW_HEADER..RAW_HEADER.saturating_add(length))
        .ok_or("the table says it is longer than what Windows returned")?;
    let mut found = Smbios::empty();
    let (mut saw_bios, mut saw_system) = (false, false);
    let mut at = 0usize;
    while at + 4 <= table.len() {
        let kind = table[at];
        let len = usize::from(table[at + 1]);
        if len < 4 {
            return Err("a structure is shorter than its own header");
        }
        let formatted = table
            .get(at..at + len)
            .ok_or("a structure runs past the end of the table")?;
        let strings_at = at + len;
        let end = strings_end(table, strings_at).ok_or("a structure's strings never end")?;
        let strings = &table[strings_at..end];
        match kind {
            TYPE_BIOS if !saw_bios => {
                saw_bios = true;
                found.bios_vendor = string(formatted, strings, BIOS_VENDOR);
                found.bios_version = string(formatted, strings, BIOS_VERSION);
            }
            TYPE_SYSTEM if !saw_system => {
                saw_system = true;
                found.system_manufacturer = string(formatted, strings, SYSTEM_MANUFACTURER);
                found.system_product = string(formatted, strings, SYSTEM_PRODUCT);
                found.uuid = formatted
                    .get(SYSTEM_UUID..SYSTEM_UUID + UUID_LEN)
                    .and_then(|b| <[u8; UUID_LEN]>::try_from(b).ok())
                    .ok_or(NO_UUID_FIELD);
            }
            TYPE_END => break,
            _ => {}
        }
        // Past the strings' closing NUL.
        at = end + 1;
        if saw_bios && saw_system {
            break;
        }
    }
    Ok(found)
}

/// Where a structure's strings end: the index of the second of the two NULs that close them.
fn strings_end(table: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < table.len() {
        if table[i] == 0 && table[i + 1] == 0 {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

/// The string a field at `offset` of `formatted` names in `strings`, trimmed; `None` for no field,
/// string number 0, a number past the set, or one that is blank.
fn string(formatted: &[u8], strings: &[u8], offset: usize) -> Option<String> {
    let n = usize::from(*formatted.get(offset)?);
    if n == 0 {
        return None;
    }
    let raw = strings.split(|&b| b == 0).nth(n - 1)?;
    let text = String::from_utf8_lossy(raw).trim().to_string();
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One structure: its type, the formatted fields after the 4-byte header, and its strings.
    pub(crate) fn structure(kind: u8, fields: &[u8], strings: &[&str]) -> Vec<u8> {
        let mut s = vec![
            kind,
            u8::try_from(4 + fields.len()).expect("short"),
            0x00,
            0x01,
        ];
        s.extend_from_slice(fields);
        for text in strings {
            s.extend_from_slice(text.as_bytes());
            s.push(0);
        }
        if strings.is_empty() {
            s.push(0);
        }
        s.push(0);
        s
    }

    /// `RawSMBIOSData` around `structures` (version 3.4), the end-of-table structure last.
    pub(crate) fn raw(structures: &[Vec<u8>]) -> Vec<u8> {
        let mut table: Vec<u8> = structures.concat();
        table.extend(structure(TYPE_END, &[], &[]));
        around(table)
    }

    /// `RawSMBIOSData` around `table` as it is.
    fn around(table: Vec<u8>) -> Vec<u8> {
        let mut raw = vec![0, 3, 4, 0];
        raw.extend_from_slice(&u32::try_from(table.len()).expect("short").to_le_bytes());
        raw.extend(table);
        raw
    }

    /// A type 1 structure (SMBIOS 2.4 layout, 0x1B bytes) with `uuid`, maker and product.
    pub(crate) fn system(uuid: [u8; 16], manufacturer: &str, product: &str) -> Vec<u8> {
        let mut fields = vec![1, 2, 0, 0];
        fields.extend_from_slice(&uuid);
        fields.extend_from_slice(&[0x06, 0, 0]);
        structure(TYPE_SYSTEM, &fields, &[manufacturer, product])
    }

    /// A type 0 structure with the vendor and the version.
    pub(crate) fn bios(vendor: &str, version: &str) -> Vec<u8> {
        structure(
            TYPE_BIOS,
            &[1, 2, 0x00, 0xF0, 3, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0],
            &[vendor, version, "01/01/2024"],
        )
    }

    pub(crate) const UUID: [u8; 16] = [
        0x4c, 0x4c, 0x45, 0x44, 0x00, 0x4a, 0x31, 0x10, 0x80, 0x37, 0xb6, 0xc0, 0x4f, 0x4e, 0x46,
        0x32,
    ];

    #[test]
    fn reads_the_system_and_bios_structures() {
        let t = parse(&raw(&[
            bios("American Megatrends Inc.", "1.20"),
            structure(2, &[1, 2], &["Board Co", "B550"]),
            system(UUID, "  Micro-Star International Co., Ltd.  ", "MS-7C91"),
        ]))
        .expect("walks");
        assert!(t.uuid == Ok(UUID));
        assert_eq!(
            t.system_manufacturer.as_deref(),
            Some("Micro-Star International Co., Ltd."),
            "trimmed"
        );
        assert_eq!(t.system_product.as_deref(), Some("MS-7C91"));
        assert_eq!(t.bios_vendor.as_deref(), Some("American Megatrends Inc."));
        assert_eq!(t.bios_version.as_deref(), Some("1.20"));
    }

    #[test]
    fn a_missing_structure_or_field_is_a_missing_part_not_a_failure() {
        let t = parse(&raw(&[bios("Dell Inc.", "2.1.0")])).expect("walks");
        assert!(t.uuid == Err(NO_SYSTEM_STRUCTURE));
        assert_eq!(t.system_manufacturer, None);
        // SMBIOS 2.0: the structure stops at 0x08, before the UUID.
        let t = parse(&raw(&[structure(
            TYPE_SYSTEM,
            &[1, 2, 0, 0],
            &["Maker", "Box"],
        )]))
        .expect("walks");
        assert!(t.uuid == Err(NO_UUID_FIELD));
        assert_eq!(t.system_product.as_deref(), Some("Box"));
        // String number 0 (none), one past the set, and a blank one.
        let mut fields = vec![0, 5, 0, 0];
        fields.extend_from_slice(&UUID);
        let t = parse(&raw(&[
            structure(TYPE_SYSTEM, &fields, &[" "]),
            bios(" ", "  "),
        ]))
        .expect("walks");
        assert!(t.uuid == Ok(UUID));
        assert_eq!(t.system_manufacturer, None);
        assert_eq!(t.system_product, None);
        assert_eq!(t.bios_vendor, None);
        assert_eq!(t.bios_version, None);
    }

    #[test]
    fn a_structure_with_no_strings_ends_with_two_nuls() {
        let mut fields = vec![0, 0, 0, 0];
        fields.extend_from_slice(&UUID);
        let t = parse(&raw(&[
            structure(TYPE_SYSTEM, &fields, &[]),
            bios("SeaBIOS", "rel-1.16.3"),
        ]))
        .expect("walks");
        assert!(t.uuid == Ok(UUID));
        assert_eq!(
            t.bios_vendor.as_deref(),
            Some("SeaBIOS"),
            "the next one read"
        );
    }

    #[test]
    fn only_the_first_structure_of_a_type_counts_and_type_127_ends_the_table() {
        let other = [0xAA; 16];
        // Behind the end-of-table structure, inside the table's length: never read.
        let t = parse(&around(
            [
                bios("Late BIOS", "9"),
                structure(TYPE_END, &[], &[]),
                system(other, "Late", "Two"),
            ]
            .concat(),
        ))
        .expect("walks");
        assert_eq!(t.bios_vendor.as_deref(), Some("Late BIOS"));
        assert!(t.uuid == Err(NO_SYSTEM_STRUCTURE));
        assert_eq!(t.system_manufacturer, None);
        let t = parse(&raw(&[
            system(UUID, "First", "One"),
            system(other, "Second", "Two"),
        ]))
        .expect("walks");
        assert!(t.uuid == Ok(UUID));
        assert_eq!(t.system_product.as_deref(), Some("One"));
    }

    #[test]
    fn a_broken_table_says_why_without_a_value() {
        assert!(parse(&[0, 3, 4]).is_err(), "shorter than the header");
        let mut long = raw(&[system(UUID, "M", "P")]);
        long[4] = 0xFF;
        long[5] = 0xFF;
        assert_eq!(
            parse(&long).err(),
            Some("the table says it is longer than what Windows returned")
        );
        let mut tiny = raw(&[]);
        // The end structure's length byte: 2, under its own header.
        tiny[RAW_HEADER + 1] = 2;
        assert_eq!(
            parse(&tiny).err(),
            Some("a structure is shorter than its own header")
        );
        // Strings that never close.
        let mut open = vec![0, 3, 4, 0, 0, 0, 0, 0];
        let body = [TYPE_SYSTEM, 4, 0, 1, b'x', b'y'];
        open[4] = u8::try_from(body.len()).expect("short");
        open.extend_from_slice(&body);
        assert_eq!(parse(&open).err(), Some("a structure's strings never end"));
        // An empty table: nothing found, nothing broken.
        let empty = parse(&[0, 3, 4, 0, 0, 0, 0, 0]).expect("walks");
        assert!(empty.uuid == Err(NO_SYSTEM_STRUCTURE));
    }
}
