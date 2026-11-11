//! The PC's hardware fingerprint for `agent_hello.hw` (the invite-only beta): what tells a new PC from one seen
//! before, where `device_id` cannot (deleting `identity.json` makes a new one).
//!
//! ## What it is made of
//!
//! Three parts, each read on its own and each allowed to be missing ([`Sources`]; the system's in
//! `system.rs`):
//!
//! | part           | source                                                       | normalized to                    |
//! |----------------|--------------------------------------------------------------|----------------------------------|
//! | `machine_guid` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`           | trimmed, braces off, lowercase   |
//! | `smbios_uuid`  | the SMBIOS System Information (type 1) UUID, `GetSystemFirmwareTable('RSMB')` | the 16 bytes as stored, 32 lowercase hex digits |
//! | `disk_serial`  | the serial of the disk the Windows volume is on, `IOCTL_STORAGE_QUERY_PROPERTY` | trimmed, case kept     |
//!
//! A GUID is case-insensitive, so it is lowercased; the UUID is hex we write ourselves from bytes, so
//! it has one spelling; a disk's serial is the drive's own text, read the same way every time, so
//! only the padding drives put around it is taken off. A value that identifies nothing is a missing
//! part, not a weak one: an all-zero GUID; a UUID of all zeros ("not present") or all ones ("not
//! set"), as SMBIOS defines them, or the firmware placeholder many boards ship with; a blank or
//! all-zero serial.
//!
//! ## The encoding, and the hash
//!
//! ```text
//! "afklink-hw-v1" 0x00
//! for each part, in the order machine_guid, smbios_uuid, disk_serial:
//!     len(name) as u8, name (ASCII)
//!     0x00                                        the part is missing
//!     0x01, len(value) as u32 big-endian, value   the part, UTF-8
//! ```
//!
//! [`canonical`] writes it, [`hash_of`] takes its SHA-256 as base64url without padding: the
//! contract's 43 characters. The version tag keeps this hash apart from any other SHA-256 of the same
//! strings and lets a later encoding (`-v2`) never collide with this one; the names, the presence byte
//! and the lengths keep every part apart from the others, so no two different sets of parts (one
//! missing, one moved into another) encode alike. `parts` says how many went in; with none the
//! hello has no `hw` at all.
//!
//! ## Virtual machines
//!
//! [`VM_RULES`]: the SMBIOS system maker and product, the BIOS vendor and version, each against the
//! strings hypervisors write there. Any match sets `vm`, and the server sends the PC to an admin's
//! review, never a refusal, so a rule errs towards no false alarm on real hardware.
//!
//! ## Logs
//!
//! Never a value and never the hash, neither raw nor normalized (the tests hold it to that):
//!
//!   debug `hw: <part> not read: <why>`  each missing part, why in words and error codes only
//!   debug `hw: parts=<n> vm=<bool>`     the result, with `vm_by` (the family of the rule that
//!                                       matched, from [`VM_RULES`]) and how long it took
//!   warn  `hw: … does not fit the contract` (not expected: the hello then goes without it)

use std::time::Instant;

use afklink_protocol::AgentHw;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

mod smbios;
#[cfg(windows)]
mod system;
mod vm;

#[cfg(windows)]
pub use system::SystemSources;
pub use vm::{VmField, VmMatch, VmRule, VM_RULES};

/// The encoding's version tag: the first bytes hashed.
pub const DOMAIN: &str = "afklink-hw-v1";

/// A `MachineGuid` longer than this is not one (a GUID is 36 characters, 38 with braces).
const GUID_MAX: usize = 64;

/// A disk serial longer than this is not one (ATA's is 20 characters, NVMe's 20, SCSI's VPD page
/// rarely past 40): a descriptor that says so is read wrong.
const SERIAL_MAX: usize = 128;

/// The three parts, in the encoding's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    MachineGuid,
    SmbiosUuid,
    DiskSerial,
}

impl Part {
    /// Every part, in the encoding's order.
    pub const ALL: [Self; 3] = [Self::MachineGuid, Self::SmbiosUuid, Self::DiskSerial];

    /// The part's name: in the encoding and in the log.
    pub const fn name(self) -> &'static str {
        match self {
            Self::MachineGuid => "machine_guid",
            Self::SmbiosUuid => "smbios_uuid",
            Self::DiskSerial => "disk_serial",
        }
    }
}

/// Where the three parts come from. Each read stands alone: one failing leaves the others. An error
/// says why in words and error codes, never with a value.
pub trait Sources {
    /// `MachineGuid` as the registry holds it.
    fn machine_guid(&self) -> Result<String, String>;
    /// The raw SMBIOS table, as `GetSystemFirmwareTable('RSMB')` returns it (`RawSMBIOSData`).
    fn smbios(&self) -> Result<Vec<u8>, String>;
    /// The serial number of the disk the Windows volume is on, as the drive reports it.
    fn system_disk_serial(&self) -> Result<String, String>;
}

/// What was read: the three parts, normalized, or why each is missing; and the VM rule that matched.
/// No `Debug`: the parts are values about this PC.
pub struct Reading {
    pub parts: [Result<String, String>; 3],
    /// The family of the first [`VM_RULES`] row that matched the SMBIOS strings; `None` for none, or
    /// for a table that could not be read.
    pub vm_by: Option<&'static str>,
}

impl Reading {
    /// How many parts were read.
    pub fn count(&self) -> u8 {
        let n = self.parts.iter().filter(|p| p.is_ok()).count();
        u8::try_from(n).unwrap_or(u8::MAX)
    }
}

/// Read and normalize every part from `sources`. Logs nothing: [`compose`] does.
pub fn read(sources: &dyn Sources) -> Reading {
    let guid = sources
        .machine_guid()
        .and_then(|raw| normalize_guid(&raw).map_err(str::to_string));
    let (uuid, vm_by) = match sources.smbios() {
        Ok(raw) => match smbios::parse(&raw) {
            Ok(table) => (
                table
                    .uuid
                    .map_err(str::to_string)
                    .and_then(|bytes| uuid_part(&bytes).map_err(str::to_string)),
                vm::signal(&table),
            ),
            Err(why) => (
                Err(format!("the SMBIOS table could not be read: {why}")),
                None,
            ),
        },
        Err(why) => (Err(why), None),
    };
    let disk = sources
        .system_disk_serial()
        .and_then(|raw| normalize_serial(&raw).map_err(str::to_string));
    Reading {
        parts: [guid, uuid, disk],
        vm_by,
    }
}

/// The fingerprint `agent_hello` carries, from `sources`: `None` when no part could be read (or,
/// never expected, when the result does not fit the contract). Logs each missing part and the result,
/// never a value. Blocking: the system's sources touch the registry, the firmware and a disk.
pub fn compose(sources: &dyn Sources) -> Option<AgentHw> {
    let started = Instant::now();
    let reading = read(sources);
    for (part, value) in Part::ALL.iter().zip(&reading.parts) {
        if let Err(why) = value {
            tracing::debug!(part = part.name(), "hw: {} not read: {why}", part.name());
        }
    }
    let parts = reading.count();
    let vm = reading.vm_by.is_some();
    tracing::debug!(
        vm_by = reading.vm_by.unwrap_or("-"),
        took_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "hw: parts={parts} vm={vm}"
    );
    if parts == 0 {
        tracing::debug!("hw: no part of this PC could be read: every hello goes without hw");
        return None;
    }
    let values = reading
        .parts
        .each_ref()
        .map(|p| p.as_ref().ok().map(String::as_str));
    let hw = AgentHw {
        hash: hash_of(values),
        vm,
        parts,
    };
    match hw.check() {
        Ok(()) => Some(hw),
        Err(e) => {
            tracing::warn!(
                parts,
                vm,
                "hw: the fingerprint does not fit the contract ({e}): every hello goes without it"
            );
            None
        }
    }
}

/// The bytes hashed (see the module's docs): the version tag, then each part by name, present or not.
pub fn canonical(parts: [Option<&str>; 3]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(DOMAIN.as_bytes());
    out.push(0);
    for (part, value) in Part::ALL.iter().zip(parts) {
        let name = part.name().as_bytes();
        out.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(name);
        match value {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&u32::try_from(v.len()).unwrap_or(u32::MAX).to_be_bytes());
                out.extend_from_slice(v.as_bytes());
            }
        }
    }
    out
}

/// SHA-256 of [`canonical`], base64url without padding: 43 characters.
pub fn hash_of(parts: [Option<&str>; 3]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(parts)))
}

/// `MachineGuid`: trimmed, the braces some tools write taken off, lowercase.
///
/// Not held to a GUID's shape: Windows writes one, but the value is only text in the registry, and
/// what tools and images leave there is not always shaped like one (one real PC has 32 characters
/// with four dashes). Whatever it is, it is what this installation reads every time,
/// and a part all the same. Blank, all zeros, not printable ASCII or implausibly long: missing.
fn normalize_guid(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim_matches(|c: char| c.is_whitespace() || c == '\0');
    let bare = trimmed
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(trimmed)
        .trim();
    if bare.is_empty() {
        return Err("the registry value is blank");
    }
    if bare.len() > GUID_MAX {
        return Err("the registry value is implausibly long");
    }
    if !bare.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err("the registry value is not printable text");
    }
    if bare.bytes().all(|b| b == b'0' || b == b'-') {
        return Err("the registry value is the all-zero GUID");
    }
    Ok(bare.to_ascii_lowercase())
}

/// The firmware placeholder many boards ship with in place of a real UUID (shown by tools as
/// `03000200-0400-0500-0006-000700080009`), in both byte orders it is found in.
const PLACEHOLDER_UUIDS: [[u8; 16]; 2] = [
    [0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9],
    [3, 0, 2, 0, 4, 0, 5, 0, 0, 6, 0, 7, 0, 8, 0, 9],
];

/// The type 1 UUID as 32 lowercase hex digits of its bytes as stored (no field swapping: one
/// spelling whatever the SMBIOS version). All zeros, all ones or the placeholder: missing.
fn uuid_part(bytes: &[u8; 16]) -> Result<String, &'static str> {
    if bytes.iter().all(|&b| b == 0) {
        return Err("the system UUID is all zeros (not present)");
    }
    if bytes.iter().all(|&b| b == 0xFF) {
        return Err("the system UUID is all ones (not set)");
    }
    if PLACEHOLDER_UUIDS.contains(bytes) {
        return Err("the system UUID is the firmware placeholder many boards share");
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// A disk's serial: the spaces and NULs drives pad it with taken off, the case kept. Blank, all
/// zeros, not printable ASCII or implausibly long: missing.
fn normalize_serial(raw: &str) -> Result<String, &'static str> {
    let serial = raw.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\0');
    if serial.is_empty() {
        return Err("the disk reports a blank serial number");
    }
    if serial.len() > SERIAL_MAX {
        return Err("the disk's serial number is implausibly long");
    }
    if !serial.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
        return Err("the disk's serial number is not printable text");
    }
    if serial
        .bytes()
        .all(|b| matches!(b, b'0' | b' ' | b'-' | b'_' | b'.'))
    {
        return Err("the disk's serial number is all zeros");
    }
    Ok(serial.to_string())
}

/// The system's fingerprint, read once per process ([`compose`] over [`SystemSources`]) and kept:
/// every later call answers from memory. Blocking on the first call. `None` off Windows.
pub fn system() -> Option<AgentHw> {
    static ONCE: std::sync::OnceLock<Option<AgentHw>> = std::sync::OnceLock::new();
    ONCE.get_or_init(read_system).clone()
}

#[cfg(windows)]
fn read_system() -> Option<AgentHw> {
    compose(&SystemSources)
}

#[cfg(not(windows))]
fn read_system() -> Option<AgentHw> {
    tracing::debug!("hw: not on Windows: no part of the PC is read");
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    pub(crate) struct Fake {
        guid: Result<String, String>,
        smbios: Result<Vec<u8>, String>,
        disk: Result<String, String>,
    }

    impl Sources for Fake {
        fn machine_guid(&self) -> Result<String, String> {
            self.guid.clone()
        }
        fn smbios(&self) -> Result<Vec<u8>, String> {
            self.smbios.clone()
        }
        fn system_disk_serial(&self) -> Result<String, String> {
            self.disk.clone()
        }
    }

    const GUID: &str = "7c3e2b1a-9d4f-4a6b-8c2d-1e0f3a5b7c9d";
    const SERIAL: &str = "S4EVNX0R123456K";

    fn table(manufacturer: &str, product: &str) -> Vec<u8> {
        smbios::tests::raw(&[
            smbios::tests::bios("American Megatrends International, LLC.", "F12"),
            smbios::tests::system(smbios::tests::UUID, manufacturer, product),
        ])
    }

    fn pc() -> Fake {
        Fake {
            guid: Ok(format!("{{{}}}\0", GUID.to_uppercase())),
            smbios: Ok(table("Gigabyte Technology Co., Ltd.", "B550 AORUS ELITE")),
            disk: Ok(format!("  {SERIAL}  \0")),
        }
    }

    /// Log lines written while `f` runs, at every level.
    fn logged<T>(f: impl FnOnce() -> T) -> (T, String) {
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8_lossy(
            &buf.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_owned();
        (out, text)
    }

    /// Every value a log must not hold: raw, normalized, and the hash.
    fn assert_no_values(log: &str, hash: Option<&str>) {
        let uuid_hex: String = smbios::tests::UUID
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        for secret in [GUID, &GUID.to_uppercase(), SERIAL, &uuid_hex]
            .into_iter()
            .chain(hash)
        {
            assert!(!log.contains(secret), "a value in the log: {log}");
        }
        for maker in ["Gigabyte", "AORUS", "American Megatrends"] {
            assert!(!log.contains(maker), "an SMBIOS string in the log: {log}");
        }
    }

    #[test]
    fn three_parts_normalized_and_hashed() {
        let reading = read(&pc());
        assert_eq!(reading.count(), 3);
        assert_eq!(
            reading.parts[0].as_deref(),
            Ok(GUID),
            "braces off, lowercase"
        );
        assert_eq!(
            reading.parts[1].as_deref(),
            Ok("4c4c4544004a31108037b6c04f4e4632"),
            "the UUID's bytes as stored"
        );
        assert_eq!(reading.parts[2].as_deref(), Ok(SERIAL), "padding off");
        assert_eq!(reading.vm_by, None);
        let (hw, log) = logged(|| compose(&pc()));
        let hw = hw.expect("a fingerprint");
        assert_eq!(hw.parts, 3);
        assert!(!hw.vm);
        assert_eq!(hw.check(), Ok(()));
        assert_eq!(
            hw.hash,
            hash_of([
                Some(GUID),
                Some("4c4c4544004a31108037b6c04f4e4632"),
                Some(SERIAL)
            ])
        );
        assert!(log.contains("hw: parts=3 vm=false"), "{log}");
        assert_no_values(&log, Some(&hw.hash));
    }

    /// The encoding byte for byte, and its hash pinned: computed apart from this code (PowerShell,
    /// .NET's SHA256 over the same bytes), so a change to either is a decision, not an accident — the
    /// server would see every PC as new hardware.
    #[test]
    fn the_encoding_and_its_hash_are_pinned() {
        let bytes = canonical([Some("ab"), None, Some("X")]);
        let mut want = b"afklink-hw-v1\0".to_vec();
        want.extend_from_slice(b"\x0cmachine_guid\x01\x00\x00\x00\x02ab");
        want.extend_from_slice(b"\x0bsmbios_uuid\x00");
        want.extend_from_slice(b"\x0bdisk_serial\x01\x00\x00\x00\x01X");
        assert_eq!(bytes, want);
        assert_eq!(
            hash_of([Some("ab"), None, Some("X")]),
            "lQq2waOwALM7bkbfuG7gimA4juF1jGgqdpdZxYxuVRU"
        );
        assert_eq!(
            hash_of([
                Some(GUID),
                Some("4c4c4544004a31108037b6c04f4e4632"),
                Some(SERIAL)
            ]),
            "Hj1zYqJnivmzWO8MaGoMJwVmmdx6sdZt_N66v8B_e6k"
        );
        assert_eq!(hash_of([None, None, None]).len(), 43);
    }

    #[test]
    fn the_hash_is_stable_and_every_part_counts() {
        let all = [Some("a"), Some("b"), Some("c")];
        assert_eq!(hash_of(all), hash_of(all), "the same parts, the same hash");
        let mut seen = std::collections::BTreeSet::new();
        for parts in [
            all,
            [Some("a"), Some("b"), None],
            [Some("a"), None, Some("c")],
            [None, Some("b"), Some("c")],
            [Some("a"), None, None],
            // Moved, not changed: another part's value.
            [None, Some("a"), None],
            [None, None, Some("a")],
            // One part's value split across two.
            [Some("ab"), None, None],
            [Some("a"), Some("b"), None],
            [Some("b"), Some("a"), Some("c")],
            [Some(""), None, None],
            [None, None, None],
        ] {
            seen.insert(hash_of(parts));
        }
        // `[Some("a"), Some("b"), None]` is listed twice.
        assert_eq!(seen.len(), 11, "no two different sets of parts hash alike");
        // Normalized, so the spellings of one PC read alike.
        let upper = Fake {
            guid: Ok(GUID.to_uppercase()),
            ..pc()
        };
        assert_eq!(compose(&upper), compose(&pc()));
    }

    #[test]
    fn a_missing_part_is_counted_out_and_logged_without_a_value() {
        let no_disk = Fake {
            disk: Err("IOCTL_STORAGE_QUERY_PROPERTY on disk 0 failed: error 1".into()),
            ..pc()
        };
        let (hw, log) = logged(|| compose(&no_disk));
        let hw = hw.expect("two parts are a fingerprint");
        assert_eq!(hw.parts, 2);
        assert_eq!(
            hw.hash,
            hash_of([Some(GUID), Some("4c4c4544004a31108037b6c04f4e4632"), None])
        );
        assert!(
            log.contains("hw: disk_serial not read: IOCTL_STORAGE_QUERY_PROPERTY"),
            "{log}"
        );
        assert!(log.contains("hw: parts=2 vm=false"), "{log}");
        assert_no_values(&log, Some(&hw.hash));

        // Each one missing alone.
        for (i, broken) in [
            Fake {
                guid: Err("RegGetValueW failed: error 2".into()),
                ..pc()
            },
            Fake {
                smbios: Err("GetSystemFirmwareTable failed: error 1".into()),
                ..pc()
            },
            Fake {
                disk: Ok("   ".into()),
                ..pc()
            },
        ]
        .into_iter()
        .enumerate()
        {
            let reading = read(&broken);
            assert_eq!(reading.count(), 2, "part {i}");
            assert!(reading.parts[i].is_err(), "part {i}");
        }
    }

    #[test]
    fn nothing_read_is_no_fingerprint() {
        let nothing = Fake {
            guid: Err("RegGetValueW failed: error 2".into()),
            smbios: Ok(smbios::tests::raw(&[])),
            disk: Err("the system volume names no disk".into()),
        };
        let (hw, log) = logged(|| compose(&nothing));
        assert_eq!(hw, None);
        assert!(log.contains("hw: parts=0 vm=false"), "{log}");
        assert!(
            log.contains("smbios_uuid not read: the table has no System Information"),
            "{log}"
        );
    }

    #[test]
    fn a_vm_says_so_and_still_has_its_fingerprint() {
        let vm = Fake {
            smbios: Ok(table("VMware, Inc.", "VMware20,1")),
            ..pc()
        };
        let (hw, log) = logged(|| compose(&vm));
        let hw = hw.expect("a fingerprint");
        assert!(hw.vm);
        assert_eq!(hw.parts, 3);
        assert!(log.contains("hw: parts=3 vm=true"), "{log}");
        assert!(
            log.contains("vm_by=\"vmware\"") || log.contains("vm_by=vmware"),
            "{log}"
        );
        assert!(!log.contains("VMware20,1"), "the product never: {log}");
        // The SMBIOS table unreadable: no VM signal, not a guess.
        let broken = Fake {
            smbios: Ok(vec![1, 2, 3]),
            ..pc()
        };
        let hw = compose(&broken).expect("two parts");
        assert!(!hw.vm);
        assert_eq!(hw.parts, 2);
    }

    #[test]
    fn guids_that_identify_nothing_are_missing() {
        assert_eq!(
            normalize_guid(&format!(" {{{GUID}}} ")),
            Ok(GUID.to_string())
        );
        assert_eq!(normalize_guid(&GUID.to_uppercase()), Ok(GUID.to_string()));
        assert_eq!(normalize_guid(&format!("{GUID}\0")), Ok(GUID.to_string()));
        // Not a GUID's shape, and still this installation's value.
        for odd in [
            "7c3e2b1a9d4f4a6b8c2d1e0f3a5b7c9d",
            "7c3e2b1-9d4f-4a6b-8c2d-1e0f3a5",
            "Custom-Machine-Id",
        ] {
            assert_eq!(normalize_guid(odd), Ok(odd.to_ascii_lowercase()), "{odd:?}");
        }
        let long = "a".repeat(GUID_MAX + 1);
        for bad in [
            "",
            "   ",
            "{}",
            "\0",
            "00000000-0000-0000-0000-000000000000",
            "{00000000-0000-0000-0000-000000000000}",
            "7c3e 2b1a",
            "Машина",
            long.as_str(),
        ] {
            assert!(normalize_guid(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn uuids_that_identify_nothing_are_missing() {
        assert!(uuid_part(&[0; 16]).is_err());
        assert!(uuid_part(&[0xFF; 16]).is_err());
        for placeholder in PLACEHOLDER_UUIDS {
            assert!(uuid_part(&placeholder).is_err());
        }
        assert_eq!(
            uuid_part(&[0xAB; 16]).as_deref(),
            Ok("abababababababababababababababab")
        );
    }

    #[test]
    fn serials_that_identify_nothing_are_missing() {
        assert_eq!(
            normalize_serial(" WD-WX12A3456789 \0\0"),
            Ok("WD-WX12A3456789".into())
        );
        assert_eq!(
            normalize_serial("0025_3881_91B3_5A12."),
            Ok("0025_3881_91B3_5A12.".into()),
            "an NVMe drive's EUI-64 spelling is its serial as Windows gives it"
        );
        assert_eq!(normalize_serial("abc"), Ok("abc".into()), "case kept");
        let long = "A".repeat(SERIAL_MAX + 1);
        for bad in [
            "",
            "   ",
            "\0\0",
            "0000000000",
            "0000_0000_0000.",
            "AB\u{1}CD",
            "Серия",
            long.as_str(),
        ] {
            assert!(normalize_serial(bad).is_err(), "{bad:?}");
        }
    }
}
