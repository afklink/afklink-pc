//! The three parts as Windows has them ([`SystemSources`]). Each read stands alone, each failure is
//! a reason in words and Windows error codes — never a value: the caller logs it.
//!
//! | part           | call                                                                         |
//! |----------------|------------------------------------------------------------------------------|
//! | `machine_guid` | `RegGetValueW(HKLM, SOFTWARE\Microsoft\Cryptography, MachineGuid)`, the 64-bit view |
//! | SMBIOS         | `GetSystemFirmwareTable('RSMB', 0)`: sized, then read                         |
//! | `disk_serial`  | the Windows directory's drive → `\\.\C:` → `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` → `\\.\PhysicalDriveN` → `IOCTL_STORAGE_QUERY_PROPERTY` (`StorageDeviceProperty`) |
//!
//! Both devices are opened with no access right at all: neither query reads data, so an ordinary
//! user's process may make them — no elevation, no prompt. None of this needs WMI: `Win32_DiskDrive`
//! and `Win32_ComputerSystemProduct` read these same sources, behind COM and a service that can take
//! seconds to answer.

use std::ffi::c_void;
use std::mem::{offset_of, size_of};

use windows::core::{w, HSTRING};
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_SUCCESS, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING,
};
use windows::Win32::System::Ioctl::{
    PropertyStandardQuery, StorageDeviceProperty, DISK_EXTENT, IOCTL_STORAGE_QUERY_PROPERTY,
    STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY, VOLUME_DISK_EXTENTS,
};
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
};
use windows::Win32::System::SystemInformation::{
    GetSystemFirmwareTable, GetSystemWindowsDirectoryW, RSMB,
};
use windows::Win32::System::IO::DeviceIoControl;

use crate::Sources;

/// SMBIOS tables are a few kilobytes; one past this is read wrong.
const SMBIOS_MAX: u32 = 1 << 20;

/// Extents a system volume may span (a spanned or striped dynamic volume, Storage Spaces): more is
/// not a volume Windows boots from.
const EXTENTS_MAX: usize = 32;

/// A device descriptor is a few hundred bytes; the first read takes this much, a larger one is read
/// again at its own size, up to [`DESCRIPTOR_MAX`].
const DESCRIPTOR_FIRST: usize = 1024;
const DESCRIPTOR_MAX: usize = 64 * 1024;

/// The system's sources.
pub struct SystemSources;

impl Sources for SystemSources {
    fn machine_guid(&self) -> Result<String, String> {
        // A GUID is 36 characters; the buffer has room for any spelling of one and its NUL.
        let mut buf = [0u16; 128];
        let mut bytes = u32::try_from(size_of::<[u16; 128]>()).unwrap_or(0);
        // SAFETY: `buf` outlives the call and `bytes` holds its size in bytes, as RegGetValueW
        // requires; it writes at most that many and says how many in `bytes`.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                w!("SOFTWARE\\Microsoft\\Cryptography"),
                w!("MachineGuid"),
                // The 64-bit view whatever this process is: a 32-bit build would otherwise read
                // WOW6432Node, which has no MachineGuid.
                RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                None,
                Some(buf.as_mut_ptr().cast::<c_void>()),
                Some(&raw mut bytes),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("RegGetValueW failed: error {}", status.0));
        }
        let chars = (bytes as usize / 2).min(buf.len());
        Ok(String::from_utf16_lossy(&buf[..chars]))
    }

    fn smbios(&self) -> Result<Vec<u8>, String> {
        // SAFETY: no buffer: the call only returns the size the table needs.
        let need = unsafe { GetSystemFirmwareTable(RSMB, 0, None) };
        if need == 0 {
            return Err(format!(
                "GetSystemFirmwareTable(RSMB) gave no size: error {}",
                last_error()
            ));
        }
        if need > SMBIOS_MAX {
            return Err(format!(
                "GetSystemFirmwareTable(RSMB) asks for {need} bytes: implausibly large"
            ));
        }
        let mut buf = vec![0u8; need as usize];
        // SAFETY: the slice is the buffer and its length, which the call writes within.
        let got = unsafe { GetSystemFirmwareTable(RSMB, 0, Some(buf.as_mut_slice())) };
        if got == 0 {
            return Err(format!(
                "GetSystemFirmwareTable(RSMB) read nothing: error {}",
                last_error()
            ));
        }
        if got > need {
            return Err("the SMBIOS table grew between its size and its read".into());
        }
        buf.truncate(got as usize);
        Ok(buf)
    }

    fn system_disk_serial(&self) -> Result<String, String> {
        let drive = system_drive()?;
        let disk = {
            let volume = Device::open(&format!("\\\\.\\{drive}"), "the system volume")?;
            volume_disk(&volume)?
        };
        let device = Device::open(&format!("\\\\.\\PhysicalDrive{disk}"), "the system disk")?;
        let descriptor = device_descriptor(&device, disk)?;
        serial_of_descriptor(&descriptor).map_err(|why| format!("{why} (disk {disk})"))
    }
}

/// `GetLastError` as a number, for a reason.
fn last_error() -> u32 {
    // SAFETY: reads this thread's last-error value; no memory is touched.
    unsafe { GetLastError() }.0
}

/// The drive the Windows directory is on: `C:` — the system volume.
fn system_drive() -> Result<String, String> {
    let mut buf = [0u16; 260];
    // SAFETY: the slice is the buffer and its length; the call writes within it and returns the
    // characters written (or the size needed, larger than the buffer, when it does not fit).
    let n = unsafe { GetSystemWindowsDirectoryW(Some(&mut buf[..])) } as usize;
    if n == 0 || n >= buf.len() {
        return Err(format!(
            "GetSystemWindowsDirectoryW failed: error {}",
            last_error()
        ));
    }
    let dir = String::from_utf16_lossy(&buf[..n]);
    drive_of(&dir).ok_or_else(|| "the Windows directory is not on a drive letter".to_string())
}

/// `C:` of `C:\Windows`; `None` for a path that does not start with a drive letter.
fn drive_of(dir: &str) -> Option<String> {
    let mut chars = dir.chars();
    let letter = chars.next()?;
    (letter.is_ascii_alphabetic() && chars.next() == Some(':'))
        .then(|| format!("{}:", letter.to_ascii_uppercase()))
}

/// A device handle, closed when dropped.
struct Device {
    handle: HANDLE,
    what: &'static str,
}

impl Device {
    /// Open `path` with no access right: queries only.
    fn open(path: &str, what: &'static str) -> Result<Self, String> {
        // SAFETY: the path is a NUL-terminated wide string that outlives the call; no security
        // attributes and no template are passed.
        let handle = unsafe {
            CreateFileW(
                &HSTRING::from(path),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        }
        .map_err(|e| format!("opening {what} failed: {:#010x}", e.code().0))?;
        Ok(Self { handle, what })
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateFileW and is closed once, here.
        if let Err(e) = unsafe { CloseHandle(self.handle) } {
            tracing::debug!(
                device = self.what,
                code = format_args!("{:#010x}", e.code().0),
                "hw: closing a device handle failed (the handle is left to the process's exit)"
            );
        }
    }
}

/// `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`: the number of the disk the volume is on.
fn volume_disk(volume: &Device) -> Result<u32, String> {
    // u64s for the structure's 8-byte alignment.
    let size = size_of::<VOLUME_DISK_EXTENTS>() + (EXTENTS_MAX - 1) * size_of::<DISK_EXTENT>();
    let mut buf = vec![0u64; size.div_ceil(8)];
    let mut returned = 0u32;
    // SAFETY: no input; the output buffer and its byte size are passed together, and the call
    // writes within them and says how much in `returned`. Synchronous: no OVERLAPPED.
    unsafe {
        DeviceIoControl(
            volume.handle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            None,
            0,
            Some(buf.as_mut_ptr().cast::<c_void>()),
            u32::try_from(size).unwrap_or(u32::MAX),
            Some(&raw mut returned),
            None,
        )
    }
    .map_err(|e| {
        format!(
            "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS failed: {:#010x}",
            e.code().0
        )
    })?;
    let bytes: Vec<u8> = buf.iter().flat_map(|w| w.to_ne_bytes()).collect();
    let returned = (returned as usize).min(bytes.len());
    disk_of_extents(&bytes[..returned]).map_err(str::to_string)
}

/// The disk of a `VOLUME_DISK_EXTENTS` the call returned: the lowest disk number among its extents,
/// so a volume on several disks always names the same one.
fn disk_of_extents(bytes: &[u8]) -> Result<u32, &'static str> {
    let count = read_u32(bytes, offset_of!(VOLUME_DISK_EXTENTS, NumberOfDiskExtents))
        .ok_or("the volume's extents came back too short")? as usize;
    if count == 0 {
        return Err("the system volume names no disk");
    }
    if count > EXTENTS_MAX {
        return Err("the system volume spans more disks than any boot volume does");
    }
    let first = offset_of!(VOLUME_DISK_EXTENTS, Extents);
    (0..count)
        .map(|i| {
            read_u32(
                bytes,
                first + i * size_of::<DISK_EXTENT>() + offset_of!(DISK_EXTENT, DiskNumber),
            )
        })
        .collect::<Option<Vec<u32>>>()
        .ok_or("the volume's extents came back shorter than their count")?
        .into_iter()
        .min()
        .ok_or("the system volume names no disk")
}

/// `IOCTL_STORAGE_QUERY_PROPERTY` (`StorageDeviceProperty`): the disk's device descriptor, read at
/// its own size when the first buffer was too small.
fn device_descriptor(device: &Device, disk: u32) -> Result<Vec<u8>, String> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    let mut size = DESCRIPTOR_FIRST;
    loop {
        let mut buf = vec![0u8; size];
        let mut returned = 0u32;
        // SAFETY: the query and the buffer are passed with their byte sizes; the call writes within
        // the buffer and says how much in `returned`. Synchronous: no OVERLAPPED.
        unsafe {
            DeviceIoControl(
                device.handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                Some(std::ptr::from_ref(&query).cast::<c_void>()),
                u32::try_from(size_of::<STORAGE_PROPERTY_QUERY>()).unwrap_or(0),
                Some(buf.as_mut_ptr().cast::<c_void>()),
                u32::try_from(size).unwrap_or(u32::MAX),
                Some(&raw mut returned),
                None,
            )
        }
        .map_err(|e| {
            format!(
                "IOCTL_STORAGE_QUERY_PROPERTY on disk {disk} failed: {:#010x}",
                e.code().0
            )
        })?;
        buf.truncate((returned as usize).min(size));
        let whole = read_u32(&buf, offset_of!(STORAGE_DEVICE_DESCRIPTOR, Size))
            .ok_or_else(|| format!("disk {disk}'s device descriptor came back too short"))?
            as usize;
        if whole <= size || size >= DESCRIPTOR_MAX {
            return Ok(buf);
        }
        size = whole.min(DESCRIPTOR_MAX);
    }
}

/// The serial number in a `STORAGE_DEVICE_DESCRIPTOR`: the NUL-terminated text at
/// `SerialNumberOffset`, as the drive gives it (normalized by the caller).
fn serial_of_descriptor(bytes: &[u8]) -> Result<String, &'static str> {
    let at = read_u32(
        bytes,
        offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset),
    )
    .ok_or("the device descriptor came back too short")?;
    // 0: no serial; ~0: the same, from some drivers.
    if at == 0 || at == u32::MAX {
        return Err("the disk reports no serial number");
    }
    let rest = bytes
        .get(at as usize..)
        .filter(|r| !r.is_empty())
        .ok_or("the serial number's offset is outside the descriptor")?;
    let raw = rest.split(|&b| b == 0).next().unwrap_or_default();
    std::str::from_utf8(raw)
        .map(str::to_string)
        .map_err(|_| "the disk's serial number is not text")
}

/// The little-endian u32 at `at`, when the bytes reach that far.
fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_drive_is_the_letter_of_the_windows_directory() {
        assert_eq!(drive_of("C:\\WINDOWS").as_deref(), Some("C:"));
        assert_eq!(drive_of("d:\\Windows").as_deref(), Some("D:"));
        assert_eq!(drive_of("\\\\?\\Volume{x}\\Windows"), None);
        assert_eq!(drive_of(""), None);
        assert_eq!(drive_of("C"), None);
    }

    /// `VOLUME_DISK_EXTENTS` laid out as Windows lays it out (the `windows` crate's own offsets).
    fn extents(disks: &[u32], count: u32) -> Vec<u8> {
        let first = offset_of!(VOLUME_DISK_EXTENTS, Extents);
        let mut bytes = vec![0u8; first + disks.len().max(1) * size_of::<DISK_EXTENT>()];
        bytes[..4].copy_from_slice(&count.to_le_bytes());
        for (i, disk) in disks.iter().enumerate() {
            let at = first + i * size_of::<DISK_EXTENT>() + offset_of!(DISK_EXTENT, DiskNumber);
            bytes[at..at + 4].copy_from_slice(&disk.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn the_volume_names_its_lowest_disk() {
        assert_eq!(disk_of_extents(&extents(&[0], 1)), Ok(0));
        assert_eq!(
            disk_of_extents(&extents(&[3, 1, 2], 3)),
            Ok(1),
            "one answer for a spanned volume"
        );
        assert!(disk_of_extents(&extents(&[], 0)).is_err());
        assert!(
            disk_of_extents(&extents(&[1], 2)).is_err(),
            "shorter than its count"
        );
        assert!(disk_of_extents(&[1, 0]).is_err(), "too short for the count");
        let many = u32::try_from(EXTENTS_MAX + 1).expect("small");
        assert!(disk_of_extents(&extents(&[0], many)).is_err());
    }

    /// A `STORAGE_DEVICE_DESCRIPTOR` with `serial` at its offset (the `windows` crate's layout).
    fn descriptor(serial: Option<&[u8]>) -> Vec<u8> {
        let fixed = size_of::<STORAGE_DEVICE_DESCRIPTOR>();
        let mut bytes = vec![0u8; fixed];
        let at = offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset);
        if let Some(s) = serial {
            bytes[at..at + 4].copy_from_slice(&u32::try_from(fixed).expect("small").to_le_bytes());
            bytes.extend_from_slice(s);
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn the_serial_is_the_text_at_its_offset() {
        assert_eq!(
            serial_of_descriptor(&descriptor(Some(b"  WD-WX12A3456789"))).as_deref(),
            Ok("  WD-WX12A3456789"),
            "as the drive gives it; normalized by the caller"
        );
        assert!(
            serial_of_descriptor(&descriptor(None)).is_err(),
            "offset 0: no serial"
        );
        let mut far = descriptor(None);
        let at = offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset);
        far[at..at + 4].copy_from_slice(&9999u32.to_le_bytes());
        assert!(
            serial_of_descriptor(&far).is_err(),
            "outside the descriptor"
        );
        far[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(serial_of_descriptor(&far).is_err(), "~0: no serial");
        assert!(serial_of_descriptor(&[0; 8]).is_err(), "too short");
        assert!(
            serial_of_descriptor(&descriptor(Some(&[0xFF, 0xFE]))).is_err(),
            "not text"
        );
    }

    /// The real sources on this PC, by hand: what was read, counted, never shown.
    /// `cargo test -p afklink-hw -- --ignored --nocapture`.
    #[test]
    #[ignore = "reads this PC's registry, firmware table and system disk"]
    fn reads_this_pc() {
        let reading = crate::read(&SystemSources);
        for (part, value) in crate::Part::ALL.iter().zip(&reading.parts) {
            match value {
                Ok(v) => println!("{}: read, {} characters", part.name(), v.len()),
                Err(why) => println!("{}: not read: {why}", part.name()),
            }
        }
        println!("vm_by: {}", reading.vm_by.unwrap_or("-"));
        assert!(reading.count() > 0, "nothing at all could be read");
    }
}
