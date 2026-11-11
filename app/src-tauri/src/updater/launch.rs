//! How this process was started: an ordinary launch, the new version after an update, the old one
//! after a rollback, or the watchdog — read from the command line before anything else runs.
//!
//! The flags (every one written only by this app, never by the owner):
//!
//! - `--after-update <pid>`: the watchdog started this new version; `<pid>` is the version it
//!   replaced, which must be gone before Tauri's single-instance lock is taken.
//! - `--rolled-back-from <version>`: the watchdog put the previous version back after `<version>`
//!   failed.
//! - `--hidden`: the main window starts hidden, as the replaced process had it (an update at night
//!   does not leave a window on the desktop).
//! - `--autostart`: Windows started it at sign-in — the `Run` entry carries it (`crate::autostart`).
//!   It changes nothing in how the app starts; it is what `agent_started.autostart` says.
//! - `--relaunched-from <pid>`: the previous process relaunched the app after its orchestrator
//!   stopped (`crate::supervise`); `<pid>` is that process, which must be gone before Tauri's
//!   single-instance lock is taken. Otherwise an ordinary launch. With `--after-update` (which the
//!   app never writes with it) both waits are made, each bounded, and the pair is a problem said.
//! - `--paused`: the relaunching process was paused («Прервать все сеансы») and could not write it
//!   to config.json: this start is paused too (it can only shut connections out, never let any in).
//! - `--update-watchdog --expect <version> --from <version> --exe <path> (--parent <pid> | --adopt
//!   <pid>) [--timeout <seconds>] [--hidden]`: run as the watchdog (`watchdog`), never as the app.
//!
//! An ordinary launch never fails on its arguments: a flag it cannot read is reported (the log does
//! not exist yet, so [`Parsed::log`] says it once it does) and the app starts as usual — remote
//! access matters more than a malformed flag. The watchdog is the opposite: with `--update-watchdog`
//! present, anything missing or malformed is an error and the process exits without starting the app.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use semver::Version;

pub(crate) const AFTER_UPDATE: &str = "--after-update";
pub(crate) const ROLLED_BACK_FROM: &str = "--rolled-back-from";
pub(crate) const HIDDEN: &str = "--hidden";
pub(crate) const AUTOSTART: &str = "--autostart";
pub(crate) const RELAUNCHED_FROM: &str = "--relaunched-from";
pub(crate) const PAUSED: &str = "--paused";
pub(crate) const WATCHDOG: &str = "--update-watchdog";
pub(crate) const EXPECT: &str = "--expect";
pub(crate) const FROM: &str = "--from";
pub(crate) const EXE: &str = "--exe";
pub(crate) const PARENT: &str = "--parent";
pub(crate) const ADOPT: &str = "--adopt";
pub(crate) const TIMEOUT: &str = "--timeout";

/// The watchdog's wait for the new version's health, when `--timeout` is not given.
pub(crate) const DEFAULT_HEALTH_TIMEOUT: Duration = Duration::from_secs(180);

/// The shortest and longest `--timeout` accepted: under half a minute a slow start or one reconnect
/// backoff would be a rollback; past half an hour the PC has been without a confirmed agent too long.
const TIMEOUT_RANGE: (u64, u64) = (30, 1800);

/// What the command line says this process is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Launch {
    Normal {
        hidden: bool,
    },
    /// The new version, started by the watchdog; `old_pid` is the version it replaced.
    AfterUpdate {
        old_pid: u32,
        hidden: bool,
    },
    /// The previous version, put back by the watchdog after `from` failed.
    RolledBack {
        from: Version,
        hidden: bool,
    },
    Watchdog(WatchdogArgs),
}

impl Launch {
    pub(crate) fn hidden(&self) -> bool {
        match self {
            Self::Normal { hidden }
            | Self::AfterUpdate { hidden, .. }
            | Self::RolledBack { hidden, .. } => *hidden,
            Self::Watchdog(args) => args.hidden,
        }
    }

    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Normal { .. } => "normal",
            Self::AfterUpdate { .. } => "after-update",
            Self::RolledBack { .. } => "rolled-back",
            Self::Watchdog(_) => "watchdog",
        }
    }
}

/// Whom the watchdog supervises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WatchTarget {
    /// Wait for `parent` (the old version, which started the watchdog) to exit, then start the new
    /// exe and supervise it.
    Launch { parent: u32 },
    /// Supervise `pid`, a new version already running (started without a watchdog, e.g. by sign-in
    /// after a reboot in the middle of an update).
    Adopt { pid: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WatchdogArgs {
    /// The version the new exe must be.
    pub(crate) expect: Version,
    /// The version the watchdog itself is — the backup it runs from — and the one a rollback restores.
    pub(crate) from: Version,
    /// The exe that was replaced, and is restored on rollback.
    pub(crate) exe: PathBuf,
    pub(crate) target: WatchTarget,
    pub(crate) timeout: Duration,
    pub(crate) hidden: bool,
}

/// The command line read: what to do, plus what was not understood (for the log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Parsed {
    pub(crate) launch: Launch,
    /// `--autostart`: Windows started this process at sign-in.
    pub(crate) autostart: bool,
    /// `--relaunched-from <pid>`: the process that relaunched this one (`crate::supervise`).
    pub(crate) relaunched_from: Option<u32>,
    /// `--paused`: start with connections paused (`crate::supervise`).
    pub(crate) paused: bool,
    /// Arguments that are none of ours: ignored.
    pub(crate) ignored: Vec<String>,
    /// Our flags that could not be read, and what was done instead.
    pub(crate) problems: Vec<String>,
}

impl Parsed {
    /// Say what the command line was, once the log exists.
    pub(crate) fn log(&self) {
        tracing::debug!(
            launch = self.launch.kind(),
            hidden = self.launch.hidden(),
            autostart = self.autostart,
            relaunched_from = ?self.relaunched_from,
            paused = self.paused,
            ignored = ?self.ignored,
            "command line read"
        );
        for problem in &self.problems {
            tracing::warn!("command line: {problem}; starting as usual");
        }
    }
}

/// Read `args` (the first one is the exe itself). `Err` only with `--update-watchdog`: then the
/// process must not become the app.
pub(crate) fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Parsed, String> {
    let args: Vec<String> = args
        .into_iter()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if args.iter().any(|a| a == WATCHDOG) {
        return parse_watchdog(&args).map(|w| Parsed {
            launch: Launch::Watchdog(w),
            autostart: false,
            relaunched_from: None,
            paused: false,
            ignored: Vec::new(),
            problems: Vec::new(),
        });
    }

    let mut hidden = false;
    let mut autostart = false;
    let mut paused = false;
    let mut after_update: Option<u32> = None;
    let mut relaunched_from: Option<u32> = None;
    let mut rolled_back: Option<Version> = None;
    let mut ignored = Vec::new();
    let mut problems = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            HIDDEN => hidden = true,
            AUTOSTART => autostart = true,
            PAUSED => paused = true,
            AFTER_UPDATE => match it.next().map(|v| (v, parse_pid(v))) {
                Some((_, Ok(pid))) => after_update = Some(pid),
                Some((v, Err(e))) => problems.push(format!("{AFTER_UPDATE} {v:?}: {e}")),
                None => problems.push(format!("{AFTER_UPDATE} without a process id")),
            },
            RELAUNCHED_FROM => match it.next().map(|v| (v, parse_pid(v))) {
                Some((_, Ok(pid))) => relaunched_from = Some(pid),
                Some((v, Err(e))) => problems.push(format!("{RELAUNCHED_FROM} {v:?}: {e}")),
                None => problems.push(format!("{RELAUNCHED_FROM} without a process id")),
            },
            ROLLED_BACK_FROM => match it.next().map(|v| (v, parse_version(v))) {
                Some((_, Ok(v))) => rolled_back = Some(v),
                Some((v, Err(e))) => problems.push(format!("{ROLLED_BACK_FROM} {v:?}: {e}")),
                None => problems.push(format!("{ROLLED_BACK_FROM} without a version")),
            },
            other => ignored.push(other.to_string()),
        }
    }
    let launch = match (after_update, rolled_back) {
        (Some(old_pid), None) => Launch::AfterUpdate { old_pid, hidden },
        (None, Some(from)) => Launch::RolledBack { from, hidden },
        (Some(old_pid), Some(from)) => {
            problems.push(format!(
                "both {AFTER_UPDATE} {old_pid} and {ROLLED_BACK_FROM} {from}: taken as a rollback"
            ));
            Launch::RolledBack { from, hidden }
        }
        (None, None) => Launch::Normal { hidden },
    };
    // Only a relaunch passes `--paused` (`crate::supervise`), always with `--relaunched-from`:
    // alone it is nobody's, and ignored.
    if paused && relaunched_from.is_none() {
        paused = false;
        problems.push(format!(
            "{PAUSED} without {RELAUNCHED_FROM} (only a relaunch passes it): ignored, the pause \
             as config.json has it"
        ));
    }
    if let (Launch::AfterUpdate { old_pid, .. }, Some(pid)) = (&launch, relaunched_from) {
        problems.push(format!(
            "both {AFTER_UPDATE} {old_pid} and {RELAUNCHED_FROM} {pid} (never written together): \
             both waited for"
        ));
    }
    Ok(Parsed {
        launch,
        autostart,
        relaunched_from,
        paused,
        ignored,
        problems,
    })
}

fn parse_watchdog(args: &[String]) -> Result<WatchdogArgs, String> {
    let mut expect = None;
    let mut from = None;
    let mut exe = None;
    let mut target = None;
    let mut timeout = DEFAULT_HEALTH_TIMEOUT;
    let mut hidden = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} without a value"))
        };
        match arg.as_str() {
            WATCHDOG => {}
            HIDDEN => hidden = true,
            EXPECT => {
                expect = Some(parse_version(&value(EXPECT)?).map_err(|e| format!("{EXPECT}: {e}"))?)
            }
            FROM => from = Some(parse_version(&value(FROM)?).map_err(|e| format!("{FROM}: {e}"))?),
            EXE => {
                let path = PathBuf::from(value(EXE)?);
                if !path.is_absolute() {
                    return Err(format!("{EXE} {}: not an absolute path", path.display()));
                }
                exe = Some(path);
            }
            PARENT | ADOPT => {
                let name = arg.clone();
                let pid = parse_pid(&value(&name)?).map_err(|e| format!("{name}: {e}"))?;
                if target.is_some() {
                    return Err(format!("{PARENT} and {ADOPT} are exclusive"));
                }
                target = Some(if name == PARENT {
                    WatchTarget::Launch { parent: pid }
                } else {
                    WatchTarget::Adopt { pid }
                });
            }
            TIMEOUT => {
                let raw = value(TIMEOUT)?;
                let secs: u64 = raw
                    .parse()
                    .map_err(|_| format!("{TIMEOUT} {raw:?}: not a number of seconds"))?;
                if !(TIMEOUT_RANGE.0..=TIMEOUT_RANGE.1).contains(&secs) {
                    return Err(format!(
                        "{TIMEOUT} {secs}: outside {}..={} seconds",
                        TIMEOUT_RANGE.0, TIMEOUT_RANGE.1
                    ));
                }
                timeout = Duration::from_secs(secs);
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    let expect = expect.ok_or_else(|| format!("{EXPECT} is missing"))?;
    let from = from.ok_or_else(|| format!("{FROM} is missing"))?;
    if expect == from {
        return Err(format!(
            "{EXPECT} and {FROM} are the same version, {expect}"
        ));
    }
    Ok(WatchdogArgs {
        expect,
        from,
        exe: exe.ok_or_else(|| format!("{EXE} is missing"))?,
        target: target.ok_or_else(|| format!("{PARENT} or {ADOPT} is missing"))?,
        timeout,
        hidden,
    })
}

fn parse_pid(value: &str) -> Result<u32, String> {
    match value.trim().parse::<u32>() {
        Ok(0) => Err("process id 0".to_string()),
        Ok(pid) => Ok(pid),
        Err(_) => Err("not a process id".to_string()),
    }
}

fn parse_version(value: &str) -> Result<Version, String> {
    Version::parse(value.trim().trim_start_matches('v')).map_err(|e| format!("not a version: {e}"))
}

/// The watchdog's command line, as the app starts it. `hidden` is passed on to the app it starts.
pub(crate) fn watchdog_args(args: &WatchdogArgs) -> Vec<OsString> {
    let mut out: Vec<OsString> = vec![
        WATCHDOG.into(),
        EXPECT.into(),
        args.expect.to_string().into(),
        FROM.into(),
        args.from.to_string().into(),
        EXE.into(),
        args.exe.clone().into_os_string(),
    ];
    match args.target {
        WatchTarget::Launch { parent } => {
            out.push(PARENT.into());
            out.push(parent.to_string().into());
        }
        WatchTarget::Adopt { pid } => {
            out.push(ADOPT.into());
            out.push(pid.to_string().into());
        }
    }
    out.push(TIMEOUT.into());
    out.push(args.timeout.as_secs().to_string().into());
    if args.hidden {
        out.push(HIDDEN.into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<OsString> {
        std::iter::once("C:\\AFKLink.exe")
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect()
    }

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn an_ordinary_start_has_no_flags_and_ignores_foreign_ones() {
        let p = parse(argv(&[])).unwrap();
        assert_eq!(p.launch, Launch::Normal { hidden: false });
        assert!(p.problems.is_empty() && p.ignored.is_empty());

        let p = parse(argv(&["--minimized", "C:\\x"])).unwrap();
        assert_eq!(p.launch, Launch::Normal { hidden: false });
        assert_eq!(p.ignored, ["--minimized", "C:\\x"]);
        assert!(!p.autostart);
    }

    /// The sign-in entry's flag: an ordinary start in every other way, said for `agent_started`.
    #[test]
    fn autostart_is_read_and_changes_nothing_else() {
        let p = parse(argv(&["--autostart"])).unwrap();
        assert!(p.autostart);
        assert_eq!(p.launch, Launch::Normal { hidden: false });
        assert!(p.problems.is_empty() && p.ignored.is_empty());
    }

    /// The relaunch's flag (`crate::supervise`): the previous process to wait for, an ordinary start
    /// otherwise; malformed, it is a problem said and the app starts as usual.
    #[test]
    fn relaunched_from_is_read_and_changes_nothing_else() {
        let p = parse(argv(&["--relaunched-from", "4242", "--hidden"])).unwrap();
        assert_eq!(p.relaunched_from, Some(4242));
        assert_eq!(p.launch, Launch::Normal { hidden: true });
        assert!(p.problems.is_empty() && p.ignored.is_empty());
        assert_eq!(parse(argv(&[])).unwrap().relaunched_from, None);
        for bad in [&["--relaunched-from"][..], &["--relaunched-from", "0"]] {
            let p = parse(argv(bad)).unwrap();
            assert_eq!(p.relaunched_from, None, "{bad:?}");
            assert_eq!(p.problems.len(), 1, "{bad:?}");
            assert_eq!(p.launch, Launch::Normal { hidden: false });
        }
        assert!(!p.paused);
        let p = parse(argv(&["--relaunched-from", "4242", "--paused"])).unwrap();
        assert!(p.paused, "--paused read");
        assert!(p.problems.is_empty() && p.ignored.is_empty());
        // Item 3: alone — or with a malformed `--relaunched-from` — it is ignored, and said.
        for alone in [&["--paused"][..], &["--paused", "--relaunched-from", "0"]] {
            let p = parse(argv(alone)).unwrap();
            assert!(!p.paused, "{alone:?}");
            assert!(
                p.problems.iter().any(|m| m.contains("--paused without")),
                "{alone:?}: {:?}",
                p.problems
            );
        }
    }

    /// With `--after-update` (never written together): both read, the update's launch kept, and
    /// the pair said as a problem.
    #[test]
    fn relaunched_from_with_after_update_is_read_and_said() {
        let p = parse(argv(&["--after-update", "100", "--relaunched-from", "200"])).unwrap();
        assert_eq!(
            p.launch,
            Launch::AfterUpdate {
                old_pid: 100,
                hidden: false
            }
        );
        assert_eq!(p.relaunched_from, Some(200));
        assert_eq!(p.problems.len(), 1, "{:?}", p.problems);
    }

    #[test]
    fn after_update_and_rolled_back_are_read_with_hidden() {
        let p = parse(argv(&["--after-update", "4242", "--hidden"])).unwrap();
        assert_eq!(
            p.launch,
            Launch::AfterUpdate {
                old_pid: 4242,
                hidden: true
            }
        );
        let p = parse(argv(&["--rolled-back-from", "v0.1.1"])).unwrap();
        assert_eq!(
            p.launch,
            Launch::RolledBack {
                from: v("0.1.1"),
                hidden: false
            }
        );
    }

    #[test]
    fn a_malformed_flag_never_stops_the_app() {
        for args in [
            vec!["--after-update"],
            vec!["--after-update", "abc"],
            vec!["--after-update", "0"],
            vec!["--rolled-back-from", "next"],
        ] {
            let p = parse(argv(&args)).unwrap();
            assert_eq!(p.launch, Launch::Normal { hidden: false }, "{args:?}");
            assert_eq!(p.problems.len(), 1, "{args:?}");
        }
        // Both: the rollback wins, and it is reported.
        let p = parse(argv(&[
            "--after-update",
            "7",
            "--rolled-back-from",
            "0.2.0",
        ]))
        .unwrap();
        assert!(matches!(p.launch, Launch::RolledBack { .. }));
        assert_eq!(p.problems.len(), 1);
    }

    #[test]
    fn the_watchdog_command_line_round_trips() {
        for target in [
            WatchTarget::Launch { parent: 1234 },
            WatchTarget::Adopt { pid: 99 },
        ] {
            let args = WatchdogArgs {
                expect: v("0.1.1"),
                from: v("0.1.0"),
                exe: PathBuf::from(r"C:\Users\Иван Петров\Downloads\AFKLink 0.1.0.exe"),
                target,
                timeout: Duration::from_secs(240),
                hidden: true,
            };
            let mut line = vec![OsString::from(r"C:\backup.exe")];
            line.extend(watchdog_args(&args));
            assert_eq!(parse(line).unwrap().launch, Launch::Watchdog(args));
        }
    }

    #[test]
    fn the_watchdog_refuses_anything_incomplete_or_odd() {
        let good = [
            "--update-watchdog",
            "--expect",
            "0.1.1",
            "--from",
            "0.1.0",
            "--exe",
            r"C:\AFKLink.exe",
            "--parent",
            "5",
        ];
        let p = parse(argv(&good)).unwrap();
        let Launch::Watchdog(w) = p.launch else {
            unreachable!("a watchdog command line");
        };
        assert_eq!(w.timeout, DEFAULT_HEALTH_TIMEOUT);
        assert!(!w.hidden);

        let without = |flag: &str| -> Vec<&str> {
            let at = good.iter().position(|a| *a == flag).unwrap();
            good.iter()
                .enumerate()
                .filter(|(i, _)| *i != at && *i != at + 1)
                .map(|(_, a)| *a)
                .collect()
        };
        for flag in ["--expect", "--from", "--exe", "--parent"] {
            assert!(parse(argv(&without(flag))).is_err(), "without {flag}");
        }
        fn with<'a>(good: &[&'a str], extra: &[&'a str]) -> Vec<&'a str> {
            good.iter().chain(extra).copied().collect()
        }
        for extra in [
            &["--adopt", "6"][..],
            &["--timeout", "5"],
            &["--timeout", "99999"],
            &["--timeout", "soon"],
            &["--whatever"],
        ] {
            assert!(parse(argv(&with(&good, extra))).is_err(), "{extra:?}");
        }
        assert!(parse(argv(&with(&good, &["--timeout", "600"]))).is_ok());
        // Relative exe, same versions.
        let mut relative = good.to_vec();
        relative[6] = "AFKLink.exe";
        assert!(parse(argv(&relative)).is_err());
        let mut same = good.to_vec();
        same[4] = "0.1.1";
        assert!(parse(argv(&same)).is_err());
    }
}
