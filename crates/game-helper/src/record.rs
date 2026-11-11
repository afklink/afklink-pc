//! What the helper may do: the record the elevated setup writes beside the helper's exe, and the
//! rules both sides use to build and read it (paths, the owner's SID, the run level a launch exe
//! needs).

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The record's format. A record of another format is not read: the setup that wrote it belongs
/// to another build, and the app asks the owner to confirm the setup again.
pub const RECORD_FORMAT: u32 = 1;

/// Longest window class Win32 has (`GetClassNameW` buffers are 256 characters).
const MAX_CLASS_CHARS: usize = 256;

/// The level the helper's task runs at, and with it the game: Task Scheduler's `HighestAvailable`
/// or `LeastPrivilege`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunLevel {
    /// The launch exe asks for administrator (`requireAdministrator`, `highestAvailable`, or the
    /// compatibility layer `RUNASADMIN`): started without, Windows would show its elevation prompt
    /// on the secure desktop, which nobody can answer from afar.
    Highest,
    /// Everything else: the game runs as the owner's ordinary programs do.
    Lua,
}

impl RunLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Highest => "highest",
            Self::Lua => "lua",
        }
    }
}

/// `record.json`: written only by the elevated setup, after Windows' confirmation, into
/// `Program Files\AFKLink\GameHelper\<SID>` — administrators write there, users only read. The
/// helper reads nothing else to decide what to launch and which window is the game.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub format: u32,
    /// SHA-256 (lowercase hex) of the helper exe the setup installed with this record: the app
    /// compares it with the helper it carries, so an update of the app is not a silent downgrade
    /// or upgrade of the helper.
    pub helper_sha256: String,
    /// The owner: the task runs in this account's session only.
    pub sid: String,
    /// What the helper starts — the game's own exe or its loader (`ScrydeGame.exe`), with no
    /// arguments, in its folder.
    pub launch_exe: String,
    /// The exe that owns the game's window (`ScrydeGame.bin`): with the class, what makes a window
    /// the game.
    pub window_exe: String,
    pub window_class: String,
    pub run_level: RunLevel,
    /// Why that level: the manifest's request and the compatibility layers, for the logs.
    pub run_level_why: String,
    /// When the setup wrote it, Unix ms.
    pub written_ms: u64,
    /// The priority the setup registered the task at ([`crate::TASK_PRIORITY`]). `None`: an older
    /// setup, which left Task Scheduler's default 7 — below normal; the app asks for the setup
    /// again over it, as over another build's helper. A field with a default: an older app
    /// skips it, and this one reads an older record without it.
    #[serde(default)]
    pub task_priority: Option<u8>,
}

impl Record {
    /// Parse and check a record read from disk.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let record: Record =
            serde_json::from_slice(bytes).map_err(|e| format!("record.json unreadable: {e}"))?;
        if record.format != RECORD_FORMAT {
            return Err(format!(
                "record.json has format {}, this build reads {RECORD_FORMAT}",
                record.format
            ));
        }
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !valid_sid(&self.sid) {
            return Err("the record's owner SID is invalid".into());
        }
        check_launch_exe(&self.launch_exe)?;
        check_path(&self.window_exe, "the game window's exe")?;
        check_class(&self.window_class)?;
        if self.helper_sha256.len() != 64
            || !self.helper_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("the record's helper hash is not SHA-256 hex".into());
        }
        Ok(())
    }

    /// The record as written to disk. An error is the caller's to log: no file is written then —
    /// never an empty one.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("the record not serialized: {e}"))
    }

    /// `path` is one of the game's two exes: what the helper counts as the game running (a loader
    /// that is still alive is the game starting, not the game missing).
    pub fn is_game_exe(&self, path: &str) -> bool {
        same_path(path, &self.launch_exe) || same_path(path, &self.window_exe)
    }

    /// `path` is the launch exe and not also the window exe: a loader, which may be patching before
    /// the game starts. A game that is its own launch exe has none.
    pub fn is_loader(&self, path: &str) -> bool {
        same_path(path, &self.launch_exe) && !same_path(path, &self.window_exe)
    }

    pub fn class_matches(&self, class: &str) -> bool {
        class.trim().eq_ignore_ascii_case(self.window_class.trim())
    }
}

/// An absolute path with no NUL: what a record or the setup's arguments may carry.
pub fn check_path(path: &str, what: &str) -> Result<(), String> {
    if path.is_empty() || path.contains('\0') || path.trim() != path {
        return Err(format!("{what}: not a usable path"));
    }
    if !Path::new(path).is_absolute() {
        return Err(format!("{what}: not an absolute path"));
    }
    Ok(())
}

/// The launch exe: an absolute path to an `.exe` — never a script, a shortcut or a command line.
pub fn check_launch_exe(path: &str) -> Result<(), String> {
    check_path(path, "the launch exe")?;
    if !path.to_ascii_lowercase().ends_with(".exe") {
        return Err("the launch exe is not an .exe".into());
    }
    Ok(())
}

pub fn check_class(class: &str) -> Result<(), String> {
    if class.trim().is_empty()
        || class.chars().count() > MAX_CLASS_CHARS
        || class.chars().any(char::is_control)
    {
        return Err("the window class is not usable".into());
    }
    Ok(())
}

/// A string SID (`S-1-5-21-…`) — the one thing that names the install directory and the task, so
/// nothing in it can step out of either.
pub fn valid_sid(sid: &str) -> bool {
    sid.len() < 185
        && sid.strip_prefix("S-1-").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .split('-')
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// Windows paths: case-insensitive, either slash a separator.
pub fn same_path(a: &str, b: &str) -> bool {
    normalized(a) == normalized(b)
}

fn normalized(path: &str) -> String {
    path.trim().replace('/', "\\").to_lowercase()
}

/// The file name at the end of a Windows path.
pub fn file_name(path: &str) -> &str {
    let path = path.trim();
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// The exe to launch when the owner chose none: the window's exe if it is an `.exe`; else an `.exe`
/// of the same name beside it (`ScrydeGame.bin` → `ScrydeGame.exe`, the loader that starts it,
/// for Scryde); else none — the owner has to pick one.
pub fn default_launch_exe(window_exe: &str, is_file: impl Fn(&Path) -> bool) -> Option<String> {
    let window_exe = window_exe.trim();
    if window_exe.is_empty() {
        return None;
    }
    if window_exe.to_ascii_lowercase().ends_with(".exe") {
        return Some(window_exe.to_string());
    }
    let sibling = Path::new(window_exe).with_extension("exe");
    is_file(&sibling).then(|| sibling.to_string_lossy().into_owned())
}

/* ── The level a launch exe needs ─────────────────────────────────────────────────────────── */

/// A manifest's `requestedExecutionLevel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionLevel {
    AsInvoker,
    HighestAvailable,
    RequireAdministrator,
}

impl ExecutionLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AsInvoker => "asInvoker",
            Self::HighestAvailable => "highestAvailable",
            Self::RequireAdministrator => "requireAdministrator",
        }
    }
}

/// The text of an embedded manifest (`RT_MANIFEST` #1): UTF-8, or UTF-16 with its byte order mark.
pub fn manifest_text(bytes: &[u8]) -> String {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => {
            let units: Vec<u16> = rest
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            String::from_utf16_lossy(&units)
        }
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// The level a manifest asks for: `None` when it asks for none (Windows runs it as invoked).
/// Comments are skipped — Visual Studio's template lists every level inside one.
pub fn manifest_execution_level(manifest: &str) -> Result<Option<ExecutionLevel>, String> {
    let text = strip_comments(manifest);
    let lower = text.to_ascii_lowercase();
    let Some(at) = lower.find("requestedexecutionlevel") else {
        return Ok(None);
    };
    let tag_end = lower[at..].find('>').map_or(lower.len(), |end| at + end);
    let tag = &text[at..tag_end];
    let lower_tag = &lower[at..tag_end];
    let mut from = 0;
    while let Some(found) = lower_tag[from..].find("level") {
        let start = from + found;
        from = start + "level".len();
        // `level` as an attribute of its own, not the tail of the element's name.
        if !lower_tag[..start].ends_with(|c: char| c.is_ascii_whitespace()) {
            continue;
        }
        let rest = tag[from..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(quote) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            return Err("the manifest's execution level is not quoted".into());
        };
        let value = &rest[1..];
        let Some(end) = value.find(quote) else {
            return Err("the manifest's execution level is not closed".into());
        };
        let value = value[..end].trim();
        return match value.to_ascii_lowercase().as_str() {
            "asinvoker" => Ok(Some(ExecutionLevel::AsInvoker)),
            "highestavailable" => Ok(Some(ExecutionLevel::HighestAvailable)),
            "requireadministrator" => Ok(Some(ExecutionLevel::RequireAdministrator)),
            _ => Err(format!("the manifest asks for an unknown level {value:?}")),
        };
    }
    Err("the manifest's requestedExecutionLevel has no level".into())
}

fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("<!--") {
        out.push_str(&rest[..open]);
        match rest[open..].find("-->") {
            Some(close) => rest = &rest[open + close + 3..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// A compatibility-layers value (`AppCompatFlags\Layers`, «Запускать от имени администратора» in
/// the exe's properties) asks for administrator.
pub fn layers_require_admin(value: &str) -> bool {
    value
        .split_whitespace()
        .any(|layer| layer.eq_ignore_ascii_case("RUNASADMIN"))
}

/// The task's level for a launch exe, with why: administrator asked for, by the manifest or a
/// layer, is HIGHEST; anything else is LUA, so an ordinary game never runs as administrator.
pub fn run_level_for(
    manifest: Result<Option<ExecutionLevel>, &str>,
    layers: &[(String, String)],
) -> (RunLevel, String) {
    let manifest_says = match manifest {
        Ok(Some(level)) => format!("manifest {}", level.as_str()),
        Ok(None) => "no execution level in a manifest".to_string(),
        Err(e) => format!("manifest not read ({e})"),
    };
    let admin_layer = layers
        .iter()
        .find(|(_, value)| layers_require_admin(value))
        .map(|(place, value)| format!("compatibility layer {value:?} in {place}"));
    let level = match (manifest, &admin_layer) {
        (Ok(Some(ExecutionLevel::RequireAdministrator | ExecutionLevel::HighestAvailable)), _)
        | (_, Some(_)) => RunLevel::Highest,
        _ => RunLevel::Lua,
    };
    let why = match admin_layer {
        Some(layer) => format!("{manifest_says}; {layer}"),
        None => format!("{manifest_says}; no RUNASADMIN layer"),
    };
    (level, why)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
pub(crate) mod tests {
    use super::*;

    /// Scryde's Lineage 2, for the tests here and the supervisor's.
    pub(crate) fn record() -> Record {
        Record {
            format: RECORD_FORMAT,
            helper_sha256: "ab".repeat(32),
            sid: "S-1-5-21-123-456-789-1001".into(),
            launch_exe: r"D:\Games\Scryde\Scryde\ScrydeGame.exe".into(),
            window_exe: r"D:\Games\Scryde\Scryde\ScrydeGame.bin".into(),
            window_class: "ScrydeGameUnrealWWindowsViewportWindow".into(),
            run_level: RunLevel::Highest,
            run_level_why: "manifest requireAdministrator; no RUNASADMIN layer".into(),
            written_ms: 1_790_000_000_000,
            task_priority: Some(crate::TASK_PRIORITY),
        }
    }

    #[test]
    fn a_record_round_trips_and_is_checked() {
        let r = record();
        assert_eq!(Record::parse(r.to_json().unwrap().as_bytes()).unwrap(), r);
        // An older setup's record has no task priority: read all the same, as `None`.
        let mut old: serde_json::Value = serde_json::from_str(&r.to_json().unwrap()).unwrap();
        old.as_object_mut().unwrap().remove("task_priority");
        assert_eq!(
            Record::parse(old.to_string().as_bytes()).unwrap(),
            Record {
                task_priority: None,
                ..record()
            }
        );
        for broken in [
            Record {
                format: 2,
                ..record()
            },
            Record {
                launch_exe: r"ScrydeGame.exe".into(),
                ..record()
            },
            Record {
                launch_exe: r"D:\Games\run.bat".into(),
                ..record()
            },
            Record {
                window_exe: "".into(),
                ..record()
            },
            Record {
                window_class: " ".into(),
                ..record()
            },
            Record {
                sid: "S-1-5-21/../x".into(),
                ..record()
            },
            Record {
                helper_sha256: "nothex".into(),
                ..record()
            },
        ] {
            assert!(
                Record::parse(serde_json::to_vec(&broken).unwrap().as_slice()).is_err(),
                "{broken:?}"
            );
        }
        assert!(Record::parse(b"{\"format\":1}").is_err());
        assert!(Record::parse(b"not json").is_err());
    }

    #[test]
    fn the_loader_and_the_window_exe_are_both_the_game() {
        let r = record();
        assert!(r.is_game_exe(r"d:/games/scryde/scryde/scrydegame.EXE"));
        assert!(r.is_game_exe(r"D:\Games\Scryde\Scryde\ScrydeGame.bin"));
        assert!(!r.is_game_exe(r"C:\Other\ScrydeGame.bin"));
        assert!(r.is_loader(r"d:/games/scryde/scryde/scrydegame.EXE"));
        assert!(!r.is_loader(r"D:\Games\Scryde\Scryde\ScrydeGame.bin"));
        // A game that is its own launch exe has no loader.
        let own = Record {
            launch_exe: r"C:\Games\Plain\game.exe".into(),
            window_exe: r"C:\Games\Plain\game.exe".into(),
            ..record()
        };
        assert!(own.is_game_exe(r"C:\Games\Plain\game.exe"));
        assert!(!own.is_loader(r"C:\Games\Plain\game.exe"));
        assert!(r.class_matches("scrydegameunrealwwindowsviewportwindow"));
        assert!(!r.class_matches("NSplashWnd"));
    }

    #[test]
    fn a_sid_cannot_step_out_of_its_task_or_directory() {
        assert!(valid_sid("S-1-5-21-123-456-789-1001"));
        for invalid in [
            "",
            "S-1-",
            "S-1-5/../../",
            "S-1-5-21-",
            "S-1-5-21\" extra",
            "S-1-5-21;command",
            "s-1-5-21",
        ] {
            assert!(!valid_sid(invalid), "{invalid}");
        }
    }

    #[test]
    fn the_default_launch_exe_is_the_window_exe_or_its_loader() {
        let none = |_: &Path| false;
        let loader = |p: &Path| p == Path::new(r"D:\Games\Scryde\Scryde\ScrydeGame.exe");
        assert_eq!(
            default_launch_exe(r"C:\Games\Plain\game.EXE", none).as_deref(),
            Some(r"C:\Games\Plain\game.EXE")
        );
        assert_eq!(
            default_launch_exe(r"D:\Games\Scryde\Scryde\ScrydeGame.bin", loader).as_deref(),
            Some(r"D:\Games\Scryde\Scryde\ScrydeGame.exe")
        );
        assert_eq!(
            default_launch_exe(r"D:\Games\Scryde\Scryde\ScrydeGame.bin", none),
            None
        );
        assert_eq!(default_launch_exe("", loader), None);
    }

    #[test]
    fn the_manifest_decides_the_level() {
        let manifest = |level: &str| {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges>
      <requestedExecutionLevel uiAccess="false" level = '{level}' />
    </requestedPrivileges></security>
  </trustInfo>
</assembly>"#
            )
        };
        assert_eq!(
            manifest_execution_level(&manifest("requireAdministrator")),
            Ok(Some(ExecutionLevel::RequireAdministrator))
        );
        assert_eq!(
            manifest_execution_level(&manifest("highestAvailable")),
            Ok(Some(ExecutionLevel::HighestAvailable))
        );
        assert_eq!(
            manifest_execution_level(&manifest("asInvoker")),
            Ok(Some(ExecutionLevel::AsInvoker))
        );
        assert!(manifest_execution_level(&manifest("root")).is_err());
        // Visual Studio's template: every level inside a comment, the real one after it.
        let template = r#"<assembly><!-- UAC Manifest Options
            <requestedExecutionLevel  level="requireAdministrator" uiAccess="false" />
            <requestedExecutionLevel  level="highestAvailable" uiAccess="false" />
          --><ms_asmv3:requestedExecutionLevel level="asInvoker" uiAccess="false"/></assembly>"#;
        assert_eq!(
            manifest_execution_level(template),
            Ok(Some(ExecutionLevel::AsInvoker))
        );
        // Common Controls only: no level asked.
        assert_eq!(
            manifest_execution_level(
                "<assembly><dependency><dependentAssembly/></dependency></assembly>"
            ),
            Ok(None)
        );
        // UTF-16 with its byte order mark, as some linkers write it.
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(
                manifest("requireAdministrator")
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes),
            )
            .collect();
        assert_eq!(
            manifest_execution_level(&manifest_text(&utf16)),
            Ok(Some(ExecutionLevel::RequireAdministrator))
        );
    }

    #[test]
    fn the_level_is_highest_only_when_administrator_is_asked_for() {
        let none: Vec<(String, String)> = Vec::new();
        assert_eq!(
            run_level_for(Ok(Some(ExecutionLevel::RequireAdministrator)), &none).0,
            RunLevel::Highest
        );
        assert_eq!(
            run_level_for(Ok(Some(ExecutionLevel::HighestAvailable)), &none).0,
            RunLevel::Highest
        );
        assert_eq!(
            run_level_for(Ok(Some(ExecutionLevel::AsInvoker)), &none).0,
            RunLevel::Lua
        );
        assert_eq!(run_level_for(Ok(None), &none).0, RunLevel::Lua);
        assert_eq!(run_level_for(Err("no resources"), &none).0, RunLevel::Lua);
        let layer = vec![("HKCU".to_string(), "~ RUNASADMIN WIN8RTM".to_string())];
        let (level, why) = run_level_for(Ok(None), &layer);
        assert_eq!(level, RunLevel::Highest);
        assert!(why.contains("RUNASADMIN") && why.contains("HKCU"), "{why}");
        let other = vec![("HKLM".to_string(), "~ HIGHDPIAWARE".to_string())];
        assert_eq!(run_level_for(Ok(None), &other).0, RunLevel::Lua);
    }
}
