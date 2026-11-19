//! The Windows looks for [`super::Probe`]: thin calls, the decisions in [`super::classify`].
//! Desktop and session metadata and process names only — never a read of local input.

use windows::core::PWSTR;
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation};
use windows::Win32::Foundation::{HANDLE, STATUS_INFO_LENGTH_MISMATCH};
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSFreeMemory, WTSQuerySessionInformationW, WTSSessionInfoEx, WTSINFOEXW,
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSIONSTATE_LOCK, WTS_SESSIONSTATE_UNLOCK,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, DESKTOP_CONTROL_FLAGS,
    DESKTOP_READOBJECTS, UOI_NAME,
};
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;

use super::{Facts, Look, Probe};

/// The process list is read into a buffer of this size first; it grows as the list needs and
/// stays grown for the next look.
const PROCESS_LIST_START: usize = 512 * 1024;

/// The process list is never read into more than this.
const PROCESS_LIST_MAX: usize = 64 << 20;

/// The watcher's looks, in this process's Windows session.
pub(super) struct WinProbe {
    session: u32,
    /// The process list's buffer, 8-byte aligned, kept between looks.
    list: Vec<u64>,
}

impl WinProbe {
    /// Our session; `Err` (why) where there is no person's desktop to watch: session 0, or a
    /// session id Windows will not give.
    pub(super) fn new() -> Result<Self, String> {
        let mut session = 0;
        // SAFETY: the current process id and a live u32 output.
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) }
            .map_err(|e| format!("this process's Windows session is not known ({e})"))?;
        if session == 0 {
            return Err(
                "this process runs in Windows' session 0 (a service or a remote shell), which has \
                 no person's desktop"
                    .into(),
            );
        }
        tracing::debug!(
            session,
            "secure desktop watch: this process's Windows session"
        );
        Ok(Self {
            session,
            list: Vec::new(),
        })
    }
}

impl Probe for WinProbe {
    fn desktop(&mut self) -> Look {
        let mut failures = Vec::new();
        let (default, why) = input_desktop(&mut failures);
        Look {
            default,
            why,
            failures,
        }
    }

    fn facts(&mut self) -> Facts {
        let mut failures = Vec::new();
        let consent = match session_has_consent(&mut self.list, self.session) {
            Ok(found) => Some(found),
            Err(e) => {
                failures.push(("NtQuerySystemInformation", e));
                None
            }
        };
        let locked = match session_locked(self.session) {
            Ok(locked) => locked,
            Err(e) => {
                failures.push(("WTSQuerySessionInformationW", e));
                None
            }
        };
        Facts {
            session: self.session,
            consent,
            locked,
            failures,
        }
    }
}

/// Whether the input desktop is the ordinary one (it opens and is named `Default`), and how it
/// showed: the same metadata look as the injector's (`afklink_input`).
fn input_desktop(failures: &mut Vec<(&'static str, String)>) -> (bool, String) {
    // SAFETY: desktop metadata only; never switches desktops or takes input rights.
    let desktop =
        match unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) } {
            Ok(d) => d,
            Err(e) => {
                return (
                    false,
                    format!("input desktop not openable ({:#010x})", e.code().0),
                )
            }
        };
    let mut name = [0u16; 256];
    // SAFETY: `name` is a live array of the size given in bytes.
    let query = unsafe {
        GetUserObjectInformationW(
            HANDLE(desktop.0),
            UOI_NAME,
            Some(name.as_mut_ptr().cast()),
            size_of::<[u16; 256]>() as u32,
            None,
        )
    };
    // SAFETY: the handle opened above, closed once.
    if let Err(e) = unsafe { CloseDesktop(desktop) } {
        failures.push(("CloseDesktop", e.to_string()));
    }
    if let Err(e) = query {
        failures.push(("GetUserObjectInformationW", e.to_string()));
        return (false, "input desktop's name unavailable".into());
    }
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let name = String::from_utf16_lossy(&name[..len]);
    (
        name.eq_ignore_ascii_case("Default"),
        format!("input desktop {name}"),
    )
}

/// Whether `consent.exe` runs in `session`: one
/// `NtQuerySystemInformation(SystemProcessInformation)` — the kernel's copy of every process's
/// image name and session, with no process opened, no access check, no service and no RPC, so it
/// sees the SYSTEM-owned `consent.exe` from an ordinary user's agent. `list` is the buffer, grown
/// on `STATUS_INFO_LENGTH_MISMATCH` and kept.
fn session_has_consent(list: &mut Vec<u64>, session: u32) -> Result<bool, String> {
    if list.is_empty() {
        list.resize(PROCESS_LIST_START / 8, 0);
    }
    for _ in 0..4 {
        let bytes = list.len() * 8;
        let mut needed = 0u32;
        // SAFETY: the buffer is writable for `bytes` and 8-byte aligned.
        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                list.as_mut_ptr().cast(),
                u32::try_from(bytes).unwrap_or(u32::MAX),
                &mut needed,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            let want = (needed as usize).max(bytes * 2) + 64 * 1024;
            if want > PROCESS_LIST_MAX {
                return Err(format!("the process list needs {want} bytes"));
            }
            tracing::debug!(
                from = bytes,
                to = want,
                "secure desktop watch: the process list's buffer grows"
            );
            *list = vec![0u64; want.div_ceil(8)];
            continue;
        }
        if status.0 < 0 {
            return Err(format!("NTSTATUS {:#010x}", status.0 as u32));
        }
        // SAFETY: the u64 buffer seen as the bytes the call wrote.
        let raw = unsafe { std::slice::from_raw_parts(list.as_ptr().cast::<u8>(), bytes) };
        let filled = (needed as usize).min(raw.len());
        return consent_in_session(&raw[..filled], session);
    }
    Err("the process list kept growing".into())
}

/// Walk a `SystemProcessInformation` list: does `consent.exe` run in `session`. Every entry and
/// name is bounds-checked against the list; a name outside it is skipped, and a list that ends
/// inside an entry or whose next offset does not move past the entry is refused.
fn consent_in_session(list: &[u8], session: u32) -> Result<bool, String> {
    let entry_size = size_of::<SYSTEM_PROCESS_INFORMATION>();
    let base = list.as_ptr() as usize;
    let mut at = 0usize;
    loop {
        let Some(end) = at.checked_add(entry_size).filter(|&e| e <= list.len()) else {
            return Err("the process list ends inside an entry".into());
        };
        // SAFETY: `at..end` lies in the list (checked); read unaligned, a copy.
        let p = unsafe {
            list[at..end]
                .as_ptr()
                .cast::<SYSTEM_PROCESS_INFORMATION>()
                .read_unaligned()
        };
        if p.SessionId == session && p.ImageName.Length > 0 && !p.ImageName.Buffer.is_null() {
            // The name points into the list the call filled.
            let from = (p.ImageName.Buffer.0 as usize).wrapping_sub(base);
            let len = usize::from(p.ImageName.Length);
            if from.checked_add(len).is_some_and(|to| to <= list.len()) {
                let units: Vec<u16> = list[from..from + len]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_le_bytes(*b))
                    .collect();
                if String::from_utf16_lossy(&units).eq_ignore_ascii_case("consent.exe") {
                    return Ok(true);
                }
            }
        }
        match p.NextEntryOffset as usize {
            0 => return Ok(false),
            next if next < entry_size => {
                return Err(format!("an entry's next offset ({next}) points inside it"));
            }
            next => at = at.saturating_add(next),
        }
    }
}

/// Whether `session` is locked (`WTSSessionInfoEx`'s `SessionFlags`): `None` when Windows says it
/// does not know.
fn session_locked(session: u32) -> Result<Option<bool>, String> {
    let mut buffer = PWSTR::null();
    let mut bytes = 0u32;
    // SAFETY: live outputs; the buffer is Windows' and freed below.
    unsafe {
        WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            session,
            WTSSessionInfoEx,
            &mut buffer,
            &mut bytes,
        )
    }
    .map_err(|e| e.to_string())?;
    if buffer.is_null() {
        return Err("no buffer".into());
    }
    let result = if (bytes as usize) < size_of::<WTSINFOEXW>() {
        Err(format!("{bytes} bytes, too short"))
    } else {
        // SAFETY: Windows returned at least a WTSINFOEXW at `buffer`, suitably aligned.
        let info = unsafe { &*buffer.0.cast::<WTSINFOEXW>() };
        if info.Level == 1 {
            // SAFETY: level 1 is the union's only member.
            let flags = unsafe { info.Data.WTSInfoExLevel1.SessionFlags } as u32;
            Ok(match flags {
                WTS_SESSIONSTATE_LOCK => Some(true),
                WTS_SESSIONSTATE_UNLOCK => Some(false),
                _ => None,
            })
        } else {
            Err(format!("level {}", info.Level))
        }
    };
    // SAFETY: the buffer WTSQuerySessionInformationW allocated, freed once.
    unsafe { WTSFreeMemory(buffer.0.cast()) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: usize = size_of::<SYSTEM_PROCESS_INFORMATION>();

    /// A synthetic process list: entries at their offsets, names after them, as the kernel lays
    /// it out (the names inside the same buffer).
    struct List {
        bytes: Vec<u8>,
        names_at: usize,
    }

    impl List {
        fn new(entries: usize, len: usize) -> Self {
            Self {
                bytes: vec![0; len],
                names_at: entries * ENTRY,
            }
        }

        /// A name written into the list's name area: where it is and its length in bytes.
        fn name(&mut self, name: &str) -> (usize, u16) {
            let at = self.names_at;
            let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            self.bytes[at..at + units.len()].copy_from_slice(&units);
            self.names_at += units.len() + 2;
            (at, u16::try_from(units.len()).expect("a short name"))
        }

        /// An entry at `at` with `session`, a name at `name` (an offset into this list, or a raw
        /// pointer elsewhere) and `next`.
        fn entry(&mut self, at: usize, session: u32, name: Option<(*mut u16, u16)>, next: u32) {
            let mut p = SYSTEM_PROCESS_INFORMATION {
                NextEntryOffset: next,
                SessionId: session,
                ..Default::default()
            };
            if let Some((ptr, len)) = name {
                p.ImageName.Buffer = PWSTR(ptr);
                p.ImageName.Length = len;
                p.ImageName.MaximumLength = len;
            }
            assert!(at + ENTRY <= self.bytes.len());
            // SAFETY: `at..at + ENTRY` lies in the buffer (asserted); written unaligned.
            unsafe {
                self.bytes
                    .as_mut_ptr()
                    .add(at)
                    .cast::<SYSTEM_PROCESS_INFORMATION>()
                    .write_unaligned(p);
            }
        }

        /// A pointer to `offset` in the list, for a name.
        fn at(&mut self, offset: usize) -> *mut u16 {
            // SAFETY: an offset inside the buffer (the callers' names are).
            unsafe { self.bytes.as_mut_ptr().add(offset).cast() }
        }
    }

    /// Two chained entries: `consent.exe` in session 2, `explorer.exe` in session 1. Found in its
    /// own session only, whatever the case of its name.
    #[test]
    fn consent_is_found_in_its_own_session_only() {
        let mut l = List::new(2, 2 * ENTRY + 128);
        let (consent, consent_len) = l.name("CONSENT.EXE");
        let (explorer, explorer_len) = l.name("explorer.exe");
        let (c, e) = (l.at(consent), l.at(explorer));
        l.entry(0, 2, Some((c, consent_len)), ENTRY as u32);
        l.entry(ENTRY, 1, Some((e, explorer_len)), 0);
        assert_eq!(consent_in_session(&l.bytes, 2), Ok(true));
        assert_eq!(consent_in_session(&l.bytes, 1), Ok(false));
        assert_eq!(consent_in_session(&l.bytes, 3), Ok(false));
    }

    /// A name pointing outside the list is not read: the entry counts as no match.
    #[test]
    fn a_name_outside_the_list_is_skipped() {
        let mut elsewhere: Vec<u16> = "consent.exe".encode_utf16().collect();
        let len = u16::try_from(elsewhere.len() * 2).expect("short");
        let mut l = List::new(1, ENTRY + 64);
        l.entry(0, 1, Some((elsewhere.as_mut_ptr(), len)), 0);
        assert_eq!(consent_in_session(&l.bytes, 1), Ok(false));
        // A name that starts inside the list and runs past its end: skipped too.
        let mut l = List::new(1, ENTRY + 8);
        let inside = l.at(ENTRY);
        l.entry(0, 1, Some((inside, 64)), 0);
        assert_eq!(consent_in_session(&l.bytes, 1), Ok(false));
    }

    /// A list that ends inside its last entry, and next offsets that point past the end or do not
    /// move past the entry: refused, never a panic or an endless walk.
    #[test]
    fn a_malformed_list_is_refused() {
        let mut l = List::new(1, ENTRY + 10);
        l.entry(0, 1, None, ENTRY as u32);
        assert!(
            consent_in_session(&l.bytes, 1).is_err(),
            "truncated last entry"
        );

        for next in [10_000_000, u32::MAX, 1, ENTRY as u32 - 1] {
            let mut l = List::new(1, ENTRY);
            l.entry(0, 1, None, next);
            assert!(consent_in_session(&l.bytes, 1).is_err(), "next {next}");
        }
        assert!(consent_in_session(&[], 1).is_err(), "an empty list");
        assert!(
            consent_in_session(&[0; 8], 1).is_err(),
            "shorter than an entry"
        );
    }
}
