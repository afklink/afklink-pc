//! The elevated setup: this exe started again through Windows' elevation prompt with
//! [`SETUP_ARG`] as its first argument (`system::elevate`), never by anything else. It runs before
//! the app's log, config, Tauri or network (`super::early`): first it limits where Windows looks
//! for DLLs it loads by name to System32 (its static imports are limited the same way by the
//! linker, `build.rs`); then it takes everything — the action, the owner's SID, the launch exe, the
//! game window's exe and class, the language of the task's description — from its arguments and
//! checks them itself, reads the launch exe's manifest for the run level, writes only into the
//! install directory (`Program Files\AFKLink\GameHelper\<SID>`) and the task, starts the task, logs
//! every step to `setup.log` there (never to the helper's `helper.log`, which a running helper may
//! be rotating), and exits with a code per kind of failure ([`Exit`]).
//!
//! A failed install removes what it put there in the same process: one prompt, never a second one
//! to clean up.

use std::ffi::OsString;

use afklink_game_helper::{check_class, check_launch_exe, check_path, valid_sid};
use afklink_i18n::Locale;

/// The first argument that makes this exe the setup; anywhere else it is an ordinary start.
pub(crate) const SETUP_ARG: &str = "--game-helper-setup";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Install {
    pub(crate) sid: String,
    pub(crate) launch_exe: String,
    pub(crate) window_exe: String,
    pub(crate) window_class: String,
    /// The language of the task's description in Task Scheduler (`task.gameHelper.native`): the
    /// window's when the owner asked for the setup. Last on the command
    /// line, `ru` or `en` exactly.
    pub(crate) locale: Locale,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Install (or re-install over) the helper for this game and launch exe, and start it.
    Install(Install),
    /// Stop and remove the task and the files; the log stays.
    Remove { sid: String },
}

impl Action {
    pub(crate) fn sid(&self) -> &str {
        match self {
            Self::Install(install) => &install.sid,
            Self::Remove { sid } => sid,
        }
    }

    /// The setup's command line after the exe, one argument each.
    pub(crate) fn args(&self) -> Vec<String> {
        match self {
            Self::Install(i) => vec![
                SETUP_ARG.into(),
                "install".into(),
                i.sid.clone(),
                i.launch_exe.clone(),
                i.window_exe.clone(),
                i.window_class.clone(),
                i.locale.tag().into(),
            ],
            Self::Remove { sid } => vec![SETUP_ARG.into(), "remove".into(), sid.clone()],
        }
    }

    /// For the logs.
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Install(i) => format!(
                "install: launch {}, game window {} with class {}, owner {}, the task described in \
                 {}",
                i.launch_exe,
                i.window_exe,
                i.window_class,
                i.sid,
                i.locale.tag()
            ),
            Self::Remove { sid } => format!("remove, owner {sid}"),
        }
    }
}

/// `Some` when this process is the setup — [`SETUP_ARG`] as the first argument; `None`
/// otherwise, whatever the other arguments hold.
pub(crate) fn parse(args: &[OsString]) -> Option<Result<Action, String>> {
    if args.first()? != SETUP_ARG {
        return None;
    }
    Some(parse_action(&args[1..]))
}

fn parse_action(rest: &[OsString]) -> Result<Action, String> {
    let text = rest
        .iter()
        .map(|a| a.to_str().ok_or("an argument is not Unicode"))
        .collect::<Result<Vec<_>, _>>()?;
    match text.as_slice() {
        ["install", sid, launch, window, class, lang] => {
            if !valid_sid(sid) {
                return Err("invalid owner SID".into());
            }
            check_launch_exe(launch)?;
            check_path(window, "the game window's exe")?;
            check_class(class)?;
            Ok(Action::Install(Install {
                sid: (*sid).to_string(),
                launch_exe: (*launch).to_string(),
                window_exe: (*window).to_string(),
                window_class: (*class).to_string(),
                locale: description_locale(lang)?,
            }))
        }
        ["remove", sid] => {
            if !valid_sid(sid) {
                return Err("invalid owner SID".into());
            }
            Ok(Action::Remove {
                sid: (*sid).to_string(),
            })
        }
        _ => Err("unknown setup action, or the wrong number of arguments".into()),
    }
}

/// The description's language as [`Action::args`] writes it: `ru` or `en`, nothing else — not
/// `Locale::from_tag`, which takes anything (as English).
fn description_locale(tag: &str) -> Result<Locale, String> {
    [Locale::Ru, Locale::En]
        .into_iter()
        .find(|l| l.tag() == tag)
        .ok_or_else(|| "unknown language for the task's description".to_string())
}

/// The setup's exit code, by what went wrong; the app tells the owner «Файл не найден» for
/// [`Exit::NotFound`] and «Не удалось применить» for the rest, and logs the code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Exit {
    Done = 0,
    /// The arguments did not pass the checks.
    Arguments = 2,
    /// The launch exe or the game window's exe does not exist.
    NotFound = 3,
    /// Writing the exe, the record or the owner's directory failed.
    Files = 4,
    /// The launch exe could not be read as a program (its manifest).
    Program = 5,
    /// Task Scheduler refused (connect, remove the old task, register).
    Scheduler = 6,
    /// The task was registered but did not start.
    Start = 7,
    /// Removing the task or the files failed.
    Remove = 8,
    /// The install directory could not be found or made: no log either.
    Directory = 9,
    /// Windows did not limit the DLL search to System32 (`SetDefaultDllDirectories`): nothing is
    /// done elevated with a search path that includes the exe's own folder.
    DllSearch = 10,
}

impl Exit {
    pub(crate) fn code(self) -> i32 {
        self as i32
    }

    pub(crate) fn from_code(code: u32) -> Option<Self> {
        [
            Self::Done,
            Self::Arguments,
            Self::NotFound,
            Self::Files,
            Self::Program,
            Self::Scheduler,
            Self::Start,
            Self::Remove,
            Self::Directory,
            Self::DllSearch,
        ]
        .into_iter()
        .find(|e| e.code() as u32 == code)
    }

    pub(crate) fn meaning(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Arguments => "the arguments did not pass the checks",
            Self::NotFound => "the launch exe or the game's exe does not exist",
            Self::Files => "a file in the install directory could not be written",
            Self::Program => "the launch exe could not be read as a program",
            Self::Scheduler => "Task Scheduler refused",
            Self::Start => "the task was registered but did not start",
            Self::Remove => "the task or the files could not be removed",
            Self::Directory => "the install directory could not be found or made",
            Self::DllSearch => "the DLL search could not be limited to System32",
        }
    }
}

#[cfg(windows)]
pub(crate) use steps::run;

#[cfg(windows)]
mod steps {
    use std::path::Path;
    use std::time::{Duration, Instant, SystemTime};

    use afklink_game_helper::{
        manifest_execution_level, run_level_for, unix_ms, HelperLog, Level, Log, Record, RunLevel,
        EXE_NAME, RECORD_FILE, RECORD_FORMAT, STATE_FILE, TASK_PRIORITY, USER_DIR,
    };
    use afklink_i18n::NativeText;

    use super::{Action, Exit, Install};
    use crate::game_helper::system::{self, Scheduler};
    use crate::game_helper::{HELPER, HELPER_SHA256};

    /// How long a file the stopped helper still holds may take to let go.
    const UNLOCK_WAIT: Duration = Duration::from_secs(10);

    /// The setup's log: `setup.log` in the install directory, or nowhere when there is none yet
    /// (a removal of nothing). Its own file: a helper still running from the previous install
    /// keeps appending to (and rotating) `helper.log` until the task is stopped below.
    struct SetupLog(Option<HelperLog>);

    impl Log for SetupLog {
        fn line(&mut self, level: Level, message: &str) {
            if let Some(log) = self.0.as_mut() {
                log.line(level, message);
            }
        }
    }

    /// Called with the DLL search already limited to System32 (`super::super::early`).
    pub(crate) fn run(action: Action) -> Exit {
        let Ok(dir) = system::install_dir(action.sid()) else {
            return Exit::Directory;
        };
        let mut log = SetupLog(None);
        let exit = match &action {
            Action::Install(install) => {
                if std::fs::create_dir_all(&dir).is_err() {
                    return Exit::Directory;
                }
                log = SetupLog(Some(HelperLog::setup(&dir)));
                started(&mut log, &action);
                install_in(&dir, install, &mut log)
            }
            Action::Remove { sid } => {
                if dir.is_dir() {
                    log = SetupLog(Some(HelperLog::setup(&dir)));
                }
                started(&mut log, &action);
                remove_in(&dir, sid, &mut log)
            }
        };
        log.line(
            if exit == Exit::Done {
                Level::Info
            } else {
                Level::Error
            },
            &format!("exits with code {} ({})", exit.code(), exit.meaning()),
        );
        exit
    }

    fn started(log: &mut SetupLog, action: &Action) {
        log.line(
            Level::Info,
            &format!(
                "started elevated, DLLs from System32 only: {}; pid {}, app {} {}",
                action.describe(),
                std::process::id(),
                env!("CARGO_PKG_VERSION"),
                std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|e| format!("(exe path not read: {e})"))
            ),
        );
    }

    fn install_in(dir: &Path, install: &Install, log: &mut SetupLog) -> Exit {
        for (what, path) in [
            ("the launch exe", &install.launch_exe),
            ("the game window's exe", &install.window_exe),
        ] {
            if !Path::new(path).is_file() {
                log.line(Level::Error, &format!("{what} {path} does not exist"));
                return Exit::NotFound;
            }
        }
        let launch = Path::new(&install.launch_exe);
        let manifest = match system::read_manifest(launch) {
            Ok(manifest) => manifest,
            Err(e) => {
                log.line(
                    Level::Error,
                    &format!(
                        "{} is not a program Windows can read: {e}",
                        install.launch_exe
                    ),
                );
                return Exit::Program;
            }
        };
        let level = match &manifest {
            Some(text) => manifest_execution_level(text),
            None => Ok(None),
        };
        let (layers, notes) = system::compat_layers(&install.sid, &install.launch_exe);
        for note in notes {
            log.line(Level::Debug, &format!("compatibility layers: {note}"));
        }
        let (run_level, why) =
            run_level_for(level.as_ref().copied().map_err(String::as_str), &layers);
        log.line(
            Level::Info,
            &format!(
                "run level {} for {}: {why}{}",
                run_level.as_str(),
                install.launch_exe,
                if manifest.is_none() {
                    " (no manifest)"
                } else {
                    ""
                }
            ),
        );
        let scheduler = match Scheduler::connect() {
            Ok(s) => s,
            Err(e) => {
                log.line(Level::Error, &format!("Task Scheduler not reached: {e}"));
                return Exit::Scheduler;
            }
        };
        match system::remove_task(&scheduler, &install.sid) {
            Ok(true) => log.line(Level::Info, "the previous task stopped and removed"),
            Ok(false) => log.line(Level::Debug, "no previous task"),
            Err(e) => {
                log.line(Level::Error, &format!("the previous task not removed: {e}"));
                return Exit::Scheduler;
            }
        }
        if let Err(e) = clear_files(dir, log) {
            log.line(
                Level::Error,
                &format!("the previous files not removed: {e}"),
            );
            return Exit::Files;
        }
        let result = put(dir, install, run_level, &why, &scheduler, log);
        if let Err(exit) = result {
            log.line(
                Level::Warn,
                &format!(
                    "install failed ({}): removing what it put there",
                    exit.meaning()
                ),
            );
            match system::remove_task(&scheduler, &install.sid) {
                Ok(existed) => log.line(
                    Level::Info,
                    &format!(
                        "cleanup: task {}",
                        if existed { "removed" } else { "was not there" }
                    ),
                ),
                Err(e) => log.line(Level::Error, &format!("cleanup: task not removed: {e}")),
            }
            if let Err(e) = clear_files(dir, log) {
                log.line(Level::Error, &format!("cleanup: files not removed: {e}"));
            }
            return exit;
        }
        log.line(
            Level::Info,
            &format!(
                "installed and started: task {:?}, run level {}, helper {}",
                system::task_name(&install.sid).to_string(),
                run_level.as_str(),
                HELPER_SHA256
            ),
        );
        Exit::Done
    }

    fn put(
        dir: &Path,
        install: &Install,
        run_level: RunLevel,
        why: &str,
        scheduler: &Scheduler,
        log: &mut SetupLog,
    ) -> Result<(), Exit> {
        let exe = dir.join(EXE_NAME);
        std::fs::write(&exe, HELPER).map_err(|e| {
            log.line(Level::Error, &format!("{} not written: {e}", exe.display()));
            Exit::Files
        })?;
        log.line(
            Level::Info,
            &format!("{} written ({} bytes)", exe.display(), HELPER.len()),
        );
        let record = Record {
            format: RECORD_FORMAT,
            helper_sha256: HELPER_SHA256.to_string(),
            sid: install.sid.clone(),
            launch_exe: install.launch_exe.clone(),
            window_exe: install.window_exe.clone(),
            window_class: install.window_class.clone(),
            run_level,
            run_level_why: why.to_string(),
            written_ms: unix_ms(SystemTime::now()),
            // What `register_task` below sets: the app reads it back to tell this setup's task
            // from an older one, left below normal.
            task_priority: Some(TASK_PRIORITY),
        };
        record.validate().map_err(|e| {
            log.line(Level::Error, &format!("the record would not be valid: {e}"));
            Exit::Files
        })?;
        // Not serialized: no file at all, never an empty one.
        let json = record.to_json().map_err(|e| {
            log.line(Level::Error, &format!("{RECORD_FILE} not written: {e}"));
            Exit::Files
        })?;
        let tmp = dir.join(format!("{RECORD_FILE}.tmp"));
        std::fs::write(&tmp, json)
            .and_then(|()| std::fs::rename(&tmp, dir.join(RECORD_FILE)))
            .map_err(|e| {
                log.line(Level::Error, &format!("{RECORD_FILE} not written: {e}"));
                Exit::Files
            })?;
        log.line(Level::Info, &format!("{RECORD_FILE} written"));
        if run_level == RunLevel::Lua {
            // A helper without rights cannot write into Program Files: its own subdirectory, the
            // owner's to write — and never written by anything elevated.
            system::create_user_dir(&dir.join(USER_DIR), &install.sid).map_err(|e| {
                log.line(Level::Error, &format!("{USER_DIR}\\ not made: {e}"));
                Exit::Files
            })?;
            log.line(
                Level::Info,
                &format!("{USER_DIR}\\ made: the helper runs without rights and writes there"),
            );
        }
        // What anyone checking what starts at logon reads in Task Scheduler: one sentence in the
        // window's language when the owner asked for this setup.
        let description = NativeText::TaskGameHelper.t(install.locale);
        system::register_task(scheduler, &install.sid, dir, run_level, description).map_err(
            |e| {
                log.line(Level::Error, &format!("the task not registered: {e}"));
                Exit::Scheduler
            },
        )?;
        log.line(
            Level::Info,
            &format!(
                "the task registered: at the owner's logon, in their session, at priority \
                 {TASK_PRIORITY} (a normal-priority process, as from Explorer); described in {} \
                 ({}): {description}",
                install.locale.tag(),
                NativeText::TaskGameHelper.key()
            ),
        );
        system::run_task(scheduler, &install.sid).map_err(|e| {
            log.line(Level::Error, &format!("the task did not start: {e}"));
            Exit::Start
        })?;
        Ok(())
    }

    fn remove_in(dir: &Path, sid: &str, log: &mut SetupLog) -> Exit {
        let scheduler = match Scheduler::connect() {
            Ok(s) => s,
            Err(e) => {
                log.line(Level::Error, &format!("Task Scheduler not reached: {e}"));
                return Exit::Scheduler;
            }
        };
        match system::remove_task(&scheduler, sid) {
            Ok(existed) => log.line(
                Level::Info,
                &format!(
                    "task {}",
                    if existed {
                        "stopped and removed"
                    } else {
                        "was not there"
                    }
                ),
            ),
            Err(e) => {
                log.line(Level::Error, &format!("the task not removed: {e}"));
                return Exit::Remove;
            }
        }
        if dir.is_dir() {
            if let Err(e) = clear_files(dir, log) {
                log.line(Level::Error, &format!("files not removed: {e}"));
                return Exit::Remove;
            }
        }
        log.line(
            Level::Info,
            "removed: the task and the files; this log stays for diagnostics",
        );
        Exit::Done
    }

    /// Everything but the log: the exe (waiting for a just-stopped helper to let go of it), the
    /// record, the state, `user\`. Each removal is logged.
    fn clear_files(dir: &Path, log: &mut SetupLog) -> Result<(), String> {
        for name in [
            EXE_NAME.to_string(),
            RECORD_FILE.to_string(),
            format!("{RECORD_FILE}.tmp"),
            STATE_FILE.to_string(),
            format!("{STATE_FILE}.tmp"),
        ] {
            let path = dir.join(&name);
            let until = Instant::now() + UNLOCK_WAIT;
            loop {
                match std::fs::remove_file(&path) {
                    Ok(()) => {
                        log.line(Level::Debug, &format!("{name} removed"));
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                    Err(_) if Instant::now() < until => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => return Err(format!("{name}: {e}")),
                }
            }
        }
        // Its contents are the owner's to write: removed without following any link in it.
        match std::fs::remove_dir_all(dir.join(USER_DIR)) {
            Ok(()) => log.line(Level::Debug, &format!("{USER_DIR}\\ removed")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{USER_DIR}\\: {e}")),
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    const SID: &str = "S-1-5-21-123-456-789-1001";
    const LAUNCH: &str = r"D:\Games\Scryde\Scryde\ScrydeGame.exe";
    const WINDOW: &str = r"D:\Games\Scryde\Scryde\ScrydeGame.bin";
    const CLASS: &str = "ScrydeGameUnrealWWindowsViewportWindow";

    #[test]
    fn the_setup_is_only_the_first_argument() {
        assert_eq!(parse(&os(&[])), None);
        assert_eq!(parse(&os(&["--hidden"])), None);
        // Anywhere but first: an ordinary start, not a setup that failed.
        assert_eq!(parse(&os(&["--hidden", SETUP_ARG, "remove", SID])), None);
        assert_eq!(parse(&os(&["x", SETUP_ARG])), None);
        assert_eq!(
            parse(&os(&[SETUP_ARG, "remove", SID])),
            Some(Ok(Action::Remove { sid: SID.into() }))
        );
        let install = Action::Install(Install {
            sid: SID.into(),
            launch_exe: LAUNCH.into(),
            window_exe: WINDOW.into(),
            window_class: CLASS.into(),
            locale: Locale::Ru,
        });
        assert_eq!(
            parse(&os(&[
                SETUP_ARG, "install", SID, LAUNCH, WINDOW, CLASS, "ru"
            ])),
            Some(Ok(install.clone()))
        );
        // What the app passes is what the setup reads, in either language.
        let args: Vec<OsString> = install.args().into_iter().map(OsString::from).collect();
        assert_eq!(parse(&args), Some(Ok(install)));
        let english = Action::Install(Install {
            sid: SID.into(),
            launch_exe: LAUNCH.into(),
            window_exe: WINDOW.into(),
            window_class: CLASS.into(),
            locale: Locale::En,
        });
        let args: Vec<OsString> = english.args().into_iter().map(OsString::from).collect();
        assert_eq!(args.last(), Some(&OsString::from("en")));
        assert_eq!(parse(&args), Some(Ok(english)));
    }

    #[test]
    fn the_setup_checks_every_argument_itself() {
        for args in [
            vec![SETUP_ARG],
            vec![SETUP_ARG, "launch-anything", SID],
            vec![SETUP_ARG, "remove", "../escape"],
            vec![SETUP_ARG, "remove", SID, "extra"],
            vec![SETUP_ARG, "install", SID, LAUNCH, WINDOW],
            // Without the description's language (an older build wrote none), or another one.
            vec![SETUP_ARG, "install", SID, LAUNCH, WINDOW, CLASS],
            vec![SETUP_ARG, "install", SID, LAUNCH, WINDOW, CLASS, "de"],
            vec![SETUP_ARG, "install", SID, LAUNCH, WINDOW, CLASS, "ru-RU"],
            vec![SETUP_ARG, "install", SID, LAUNCH, WINDOW, CLASS, "RU"],
            vec![SETUP_ARG, "install", SID, LAUNCH, WINDOW, CLASS, "ru", "x"],
            vec![
                SETUP_ARG,
                "install",
                "S-1-5-21;x",
                LAUNCH,
                WINDOW,
                CLASS,
                "ru",
            ],
            vec![
                SETUP_ARG,
                "install",
                SID,
                "ScrydeGame.exe",
                WINDOW,
                CLASS,
                "ru",
            ],
            vec![
                SETUP_ARG,
                "install",
                SID,
                r"D:\Games\run.cmd",
                WINDOW,
                CLASS,
                "ru",
            ],
            vec![
                SETUP_ARG,
                "install",
                SID,
                r"D:\Games\game.exe --x",
                WINDOW,
                CLASS,
                "ru",
            ],
            vec![
                SETUP_ARG,
                "install",
                SID,
                LAUNCH,
                "ScrydeGame.bin",
                CLASS,
                "ru",
            ],
            vec![SETUP_ARG, "install", SID, LAUNCH, WINDOW, " ", "ru"],
            vec![
                SETUP_ARG,
                "install",
                SID,
                LAUNCH,
                WINDOW,
                "Class\nwith a break",
                "ru",
            ],
        ] {
            assert!(
                matches!(parse(&os(&args)), Some(Err(_))),
                "{args:?} should be refused"
            );
        }
    }

    #[test]
    fn exit_codes_read_back() {
        for exit in [
            Exit::Done,
            Exit::Arguments,
            Exit::NotFound,
            Exit::Files,
            Exit::Program,
            Exit::Scheduler,
            Exit::Start,
            Exit::Remove,
            Exit::Directory,
            Exit::DllSearch,
        ] {
            assert_eq!(Exit::from_code(exit.code() as u32), Some(exit));
        }
        assert_eq!(Exit::from_code(1), None);
        assert_eq!(Exit::from_code(1223), None);
    }
}
