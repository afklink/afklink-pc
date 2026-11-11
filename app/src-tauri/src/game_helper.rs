//! Settings → «Только игра» → «Запускать игру автоматически»: the app's half of the game helper
//! (`afklink_game_helper`).
//!
//! - **The owner's choice**: config.json `game_helper` (the switch) and `game_launch_exe` (the exe
//!   to launch, when the default beside the game's exe will not do).
//! - **The launcher learned** ([`Learner`], on the watch thread, with this app's own rights): the
//!   game's own launcher, read from the parent of the game's process, kept as
//!   `game_launch_learned`. The launch exe is the owner's choice, else the one learned, else the
//!   guess by name ([`Wanted`]). The helper itself never learns anything: it launches only what its
//!   record names, and a learned file is only offered, never applied without the setup.
//! - **The setup** (`setup`): this exe again, started elevated through Windows' prompt with
//!   `--game-helper-setup` as its first argument. It alone installs, re-installs and removes the
//!   helper (its exe, the record of what it may launch, its task) and starts the task: one prompt
//!   per change. Turning the helper back on over an installation that still matches needs none.
//! - **The signal** ([`Watch`]): set only while «Только игра» and the helper are on, the installed
//!   record matches the bound game and launch exe, and a session that game-only applies to has
//!   connected. Every change is logged with its reason. It fails closed: with the app gone the
//!   helper idles. Another build's helper (after the app updated itself) keeps working, because
//!   what it may do is the record's, which this app reads and checks, not the helper exe's;
//!   Settings asks for this build's helper instead ([`Ask::Update`]).
//! - **What the window shows** ([`HelperDto`]): the installation as read from disk and Task
//!   Scheduler (at start and whenever Settings opens, not while a change runs) and the helper's
//!   `state.json`, including the failed-launch mark («Игра не запускается», [`failed_launch`]).
//! - **Keeping the helper alive** ([`GameHelper::revive`]): a helper that stopped is started again,
//!   at most once a minute and less often while it keeps stopping.
//! - **What the viewer is told** ([`launching`]): while the helper launches the game, every live
//!   session's heartbeat says `game.launching` (`AgentControl::set_game_launching`), so the viewer
//!   shows «Игра запускается» rather than «Игра не запущена», within about a second of the change.
//! - **The helper's and the setup's logs** (`helper.log`, `setup.log`), mirrored line by line under
//!   [`HELPER_TARGET`], a system target (`log_route::SYSTEM_TARGETS`): the system log has them, and
//!   a live session's file has what the helper decided during it.

use std::ffi::OsString;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use tauri::{Manager, State};

use afklink_core::game::GameBinding;
use afklink_core::game_access::HelperSessions;
use afklink_core::{lock, AgentControl, Config};
use afklink_game_helper::{
    check_launch_exe, default_launch_exe, file_name, parse_line, same_path, utc_stamp, HelperState,
    Level, Record, StateFile, LOG_FILE, LOG_OLD_FILE, RECORD_FILE, SETUP_LOG_FILE,
    SETUP_LOG_OLD_FILE, STATE_FILE, STATE_REFRESH, TASK_PRIORITY, USER_DIR,
};
use afklink_i18n::{Locale, NativeText};

use crate::game_only::{self, GameOnlyDto};

mod setup;
#[cfg(windows)]
mod system;

/// The helper's exe, built and hashed by `build.rs`: what the setup installs.
#[cfg(windows)]
pub(crate) const HELPER: &[u8] = include_bytes!(env!("AFKLINK_GAME_HELPER_EXE"));
/// Its SHA-256, lowercase hex: the record names it. An installation of another build's helper keeps
/// working (its record decides what it may do) and Settings offers this one in its place.
#[cfg(windows)]
pub(crate) const HELPER_SHA256: &str = env!("AFKLINK_GAME_HELPER_SHA256");
#[cfg(not(windows))]
const HELPER_SHA256: &str = "";

/// The target the helper's own lines are mirrored under.
const HELPER_TARGET: &str = "afklink_app_lib::game_helper::helper";

/// How often the signal is decided again: the helper's own poll.
const WATCH_EVERY: Duration = afklink_game_helper::POLL;
/// Once off, the signal stays off at least this long — three of the helper's polls — so the helper
/// sees every session change, and a new session starts it afresh (its give-up and pauses forgotten).
const SIGNAL_OFF_MIN: Duration = Duration::from_millis(1500);
/// How often the record is read again from disk (removed by hand, replaced by a setup).
const RECORD_EVERY: Duration = Duration::from_secs(5);
/// How often `state.json` is read again.
const STATE_EVERY: Duration = Duration::from_secs(2);
/// … and while the signal is on — the helper may launch the game: on every look, so its
/// `launch_pending` reaches the viewer's heartbeat within about a second ([`launching`]). Two small
/// files twice a second, during a session only.
const STATE_EVERY_ALLOWED: Duration = WATCH_EVERY;
/// How often the helper's log is looked at for new lines.
const MIRROR_EVERY: Duration = Duration::from_secs(1);
/// At the app's start, the helper's lines from this long before it are mirrored too: the helper
/// starts at logon, about when the app does.
const MIRROR_BACK: Duration = Duration::from_secs(120);
/// At most this much of the helper's log is mirrored per look.
const MIRROR_MAX_BYTES: u64 = 256 * 1024;
/// The setup is given this long — the owner's answer to the prompt included — before the app stops
/// waiting for it.
const SETUP_WAIT: Duration = Duration::from_secs(180);
/// `state.json` older than this is a helper that is not running.
const STATE_STALE: Duration = Duration::from_secs(3 * STATE_REFRESH.as_secs());
/// A stopped helper's task is started again at most this often ([`GameHelper::revive`]) — and less
/// often, doubling up to [`REVIVE_MAX`], while it keeps stopping again. The first look is this long
/// after the app's start, which starts the task itself when it can ([`GameHelper::keep_running`]).
const REVIVE_EVERY: Duration = Duration::from_secs(60);
const REVIVE_MAX: Duration = Duration::from_secs(16 * 60);

/// Game platforms' clients. Steam, GOG Galaxy and Ubisoft Connect keep their games' folders under
/// their own, so the folder rule alone would learn them as the launcher; started with no arguments
/// they open themselves, not the game. Lowercase file names.
const PLATFORM_CLIENTS: &[&str] = &[
    "steam.exe",
    "galaxyclient.exe",
    "upc.exe",
    "ubisoftconnect.exe",
    "epicgameslauncher.exe",
    "battle.net.exe",
    "eadesktop.exe",
    "origin.exe",
    "riotclientservices.exe",
];

/// Why the installation is not the one the owner's settings need: each takes the signal off. Another
/// build's helper is not one of them ([`outdated`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mismatch {
    /// No record (or none this app can read), or no task.
    NotInstalled,
    /// Installed for another game window (another game chosen since).
    Game,
    /// Installed with another launch exe.
    Launch,
    /// The helper itself asks for the setup again (Windows refused its launch, 740).
    NeedsSetup,
}

impl Mismatch {
    fn why(self) -> &'static str {
        match self {
            Self::NotInstalled => "the helper is not installed",
            Self::Game => "it is installed for another game window",
            Self::Launch => "it is installed with another launch exe",
            Self::NeedsSetup => "the helper asks for the setup again",
        }
    }
}

/// The helper's row in Settings.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelperDto {
    /// The owner's switch.
    enabled: bool,
    /// The exe the helper launches for the bound game — the owner's choice, else the default; `None`
    /// when there is no game or no default: the owner picks one.
    launch_exe: Option<String>,
    launch_name: Option<String>,
    /// The record and the task are both there (for whatever game).
    installed: bool,
    /// What makes the installation not the one needed now; `None`: it is.
    mismatch: Option<Mismatch>,
    /// The installed helper is another build's than the one this app carries, or its task was
    /// registered at an older priority ([`outdated_why`]): it works on (when nothing else differs),
    /// and Settings asks for this build's («Нужно обновление» → «Обновить», [`Ask::Update`]: the
    /// installed launch exe kept) before anything else it offers.
    outdated: bool,
    /// The launcher learned from the game's parent process, when the helper works on with another
    /// launch exe installed: Settings offers it («Заменить», [`Ask::ApplyFound`]) — while the
    /// helper is another build's, only once «Обновить» has installed this one.
    found_launch: Option<String>,
    /// The helper's own state, from a fresh `state.json`; `None`: none, or too old.
    state: Option<HelperState>,
    /// «Игра не запускается»: the fresh `state.json`'s failed-launch mark ([`failed_launch`]).
    failed_launch: bool,
}

/// The task as last read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TaskSeen {
    Absent,
    Present { running: bool },
}

/// What is installed, as last read.
#[derive(Clone, Debug, Default, PartialEq)]
struct Installed {
    record: Option<Record>,
    /// The record is there and could not be read.
    record_error: Option<String>,
    /// `None`: not read, or not readable — not held against the installation.
    task: Option<TaskSeen>,
}

impl Installed {
    /// Something of it is there — a record or a task: what turning the helper off removes.
    fn present(&self) -> bool {
        self.record.is_some() || matches!(self.task, Some(TaskSeen::Present { .. }))
    }

    /// The record is there and the task too (or the task could not be read).
    fn complete(&self) -> bool {
        self.record.is_some() && self.task != Some(TaskSeen::Absent)
    }

    fn describe(&self) -> String {
        let record = match (&self.record, &self.record_error) {
            (Some(r), _) => format!(
                "record: launch {}, game window {} class {}, run level {}, helper {}",
                r.launch_exe,
                r.window_exe,
                r.window_class,
                r.run_level.as_str(),
                r.helper_sha256
            ),
            (None, Some(e)) => format!("record unreadable ({e})"),
            (None, None) => "no record".to_string(),
        };
        let task = match self.task {
            Some(TaskSeen::Absent) => "no task",
            Some(TaskSeen::Present { running: true }) => "task running",
            Some(TaskSeen::Present { running: false }) => "task not running",
            None => "task not read",
        };
        format!("{record}; {task}")
    }
}

/// Where the launch exe comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LaunchFrom {
    /// The owner chose it in Settings (`game_launch_exe`).
    Chosen,
    /// Learned from the game's parent process (`game_launch_learned`).
    Learned,
    /// The guess by name beside the game's exe (`default_launch_exe`).
    Guessed,
}

impl LaunchFrom {
    fn as_str(self) -> &'static str {
        match self {
            Self::Chosen => "chosen by the owner",
            Self::Learned => "learned from the game's parent process",
            Self::Guessed => "guessed beside the game's exe",
        }
    }
}

/// The launch exe the settings want for the bound game — the owner's choice, else the one learned,
/// else the guess by name — and whether the helper is on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Wanted {
    exe: Option<String>,
    from: Option<LaunchFrom>,
    helper_on: bool,
}

impl Wanted {
    fn of(config: &Config) -> Self {
        let helper_on = config.game_helper;
        let (exe, from) = match (
            &config.game,
            &config.game_launch_exe,
            &config.game_launch_learned,
        ) {
            (None, _, _) => (None, None),
            (Some(_), Some(chosen), _) => (Some(chosen.clone()), Some(LaunchFrom::Chosen)),
            (Some(_), None, Some(learned)) => (Some(learned.clone()), Some(LaunchFrom::Learned)),
            (Some(game), None, None) => match default_launch_exe(&game.exe_path, Path::is_file) {
                Some(guess) => (Some(guess), Some(LaunchFrom::Guessed)),
                None => (None, None),
            },
        };
        Self {
            exe,
            from,
            helper_on,
        }
    }

    /// An installation with another launch exe still counts as the one needed: the exe wanted was
    /// only learned (the owner chose none) and the helper is on. Learning never takes a working
    /// helper off; Settings offers the learned exe instead ([`found_launch`]). With the helper off,
    /// turning it on installs the learned one.
    fn keeps_installed(&self) -> bool {
        self.from == Some(LaunchFrom::Learned) && self.helper_on
    }

    fn describe(&self) -> String {
        match (&self.exe, self.from) {
            (Some(exe), Some(from)) => format!("{exe} ({})", from.as_str()),
            _ => "-".to_string(),
        }
    }
}

/// The launch exe for the bound game: the owner's, else the one learned, else the default beside it.
fn launch_for(config: &Config) -> Option<String> {
    Wanted::of(config).exe
}

/// What keeps the installation from being the one needed: no record (this app reads and checks it)
/// or no task, another game, another launch exe (unless only a learned one differs while the
/// helper is on: [`Wanted::keeps_installed`]), or the helper asking for the setup again. Which
/// build's helper is installed is not one of them ([`outdated`]): the record, not the helper exe,
/// says what the helper may launch and which window it may bring to the front.
fn mismatch(
    installed: &Installed,
    game: Option<&GameBinding>,
    wanted: &Wanted,
    state: Option<HelperState>,
) -> Option<Mismatch> {
    let Some(record) = &installed.record else {
        return Some(Mismatch::NotInstalled);
    };
    if installed.task == Some(TaskSeen::Absent) {
        return Some(Mismatch::NotInstalled);
    }
    match game {
        Some(game)
            if same_path(&record.window_exe, &game.exe_path)
                && record.class_matches(&game.window_class) => {}
        _ => return Some(Mismatch::Game),
    }
    match wanted.exe.as_deref() {
        Some(launch) if same_path(&record.launch_exe, launch) => {}
        Some(_) if wanted.keeps_installed() => {}
        _ => return Some(Mismatch::Launch),
    }
    (state == Some(HelperState::NeedsSetup)).then_some(Mismatch::NeedsSetup)
}

/// The learned launcher Settings offers in place of the installed launch exe: the helper works on
/// with the installed one until the owner applies it. Only where [`mismatch`] found none.
fn found_launch(installed: &Installed, wanted: &Wanted) -> Option<String> {
    let record = installed.record.as_ref()?;
    let exe = wanted.exe.as_deref()?;
    (wanted.keeps_installed() && !same_path(&record.launch_exe, exe)).then(|| exe.to_string())
}

/// The installation as last read, against the settings: one copy of it, judged by [`mismatch`],
/// [`found_launch`] and [`outdated`] with no lock held ([`GameHelper::fit_with`]).
struct Fit {
    installed: Installed,
    wanted: Wanted,
    mismatch: Option<Mismatch>,
    /// [`found_launch`], only where nothing else differs.
    found: Option<String>,
    /// [`outdated`]: another build's helper is installed, or its task at an older priority.
    other_build: bool,
}

impl Fit {
    fn of(installed: Installed, config: &Config, state: Option<HelperState>) -> Self {
        let wanted = Wanted::of(config);
        let mismatch = mismatch(&installed, config.game.as_ref(), &wanted, state);
        let found = match mismatch {
            None => found_launch(&installed, &wanted),
            Some(_) => None,
        };
        let other_build = outdated(&installed, HELPER_SHA256);
        Self {
            installed,
            wanted,
            mismatch,
            found,
            other_build,
        }
    }
}

/// What the owner asked for when the helper is turned on or set up again ([`GameHelper::turn_on`]).
/// Every setup installs this build's helper; each ask its own launch exe ([`plan`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ask {
    /// The switch on, «Разрешить», a file chosen («Выбрать», «Изменить»): the setup only when the
    /// installation does not match ([`mismatch`]), with the launch exe the settings want.
    Switch,
    /// «Обновить» by «Нужно обновление»: this build's helper in place of another build's, with the
    /// launch exe its record names. A learned launcher is not applied with it: Settings offers it
    /// after («Найден другой файл запуска»): the update before the file.
    Update,
    /// «Заменить» by «Найден другой файл запуска»: the launcher learned from the game's parent in
    /// place of the launch exe the record names.
    ApplyFound,
}

impl Ask {
    fn as_str(self) -> &'static str {
        match self {
            Self::Switch => "the switch on («Разрешить», or a launch exe chosen)",
            Self::Update => "«Обновить»: this build's helper, the installed launch exe kept",
            Self::ApplyFound => {
                "«Заменить»: the learned launcher in place of the installed launch exe"
            }
        }
    }
}

/// What turning the helper on does ([`plan`]).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Plan {
    /// No setup: the installation is what was asked for already — why.
    Ready(&'static str),
    /// The setup, installing `launch` as the launch exe — why.
    Setup { launch: String, why: String },
}

/// Which setup `ask` needs over the installation as read (`fit`), and the launch exe it installs.
/// An installation that does not match ([`mismatch`]: none, or no record this app can read, another
/// game, another file chosen, Windows' 740) is set up as the settings want — `wanted`, the launch
/// exe [`Wanted`] gives — whatever was asked: Settings shows «Нужно разрешение» + «Разрешить» there,
/// and a button pressed just before is that. Otherwise only a button runs the setup: «Обновить»
/// while another build's helper is installed, with the launch exe its record names; «Заменить» while
/// a learned launcher differs from it ([`found_launch`]), with that launcher.
fn plan(ask: Ask, fit: &Fit, wanted: &str) -> Plan {
    if let Some(m) = fit.mismatch {
        return Plan::Setup {
            launch: wanted.to_string(),
            why: format!("{}: the helper as the settings want it", m.why()),
        };
    }
    match ask {
        Ask::Switch => Plan::Ready("the installation already matches"),
        Ask::Update => match (&fit.installed.record, fit.other_build) {
            (Some(record), true) => Plan::Setup {
                launch: record.launch_exe.clone(),
                why: format!(
                    "the owner asked for this build's helper (installed: {}); the launch exe its \
                     record names is kept{}",
                    outdated_why(&fit.installed, HELPER_SHA256)
                        .unwrap_or_else(|| record.helper_sha256.clone()),
                    match &fit.found {
                        Some(found) => format!(
                            ", the learned one ({found}) is not applied with it — Settings offers \
                             it after the update"
                        ),
                        None => String::new(),
                    }
                ),
            },
            _ => Plan::Ready("this build's helper is installed already: nothing to update"),
        },
        Ask::ApplyFound => match &fit.found {
            Some(found) => Plan::Setup {
                launch: found.clone(),
                why: format!(
                    "the owner applied the launcher learned from the game's parent process in \
                     place of {}",
                    fit.installed
                        .record
                        .as_ref()
                        .map_or("- (no record)", |r| r.launch_exe.as_str())
                ),
            },
            None => Plan::Ready(
                "no learned launcher differs from the installed launch exe: nothing to apply \
                 (applied already, a file chosen since, or the helper off)",
            ),
        },
    }
}

/// A process in Windows' list (`platform::processes`): its id, its parent's, its exe's file name.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Listed {
    pid: u32,
    parent: u32,
    name: String,
}

/// What the limited query right reads of a process (`platform::process`) — Windows grants it for
/// processes running with rights too (measured).
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessSeen {
    path: String,
    /// When it started, in 100 ns units since 1601.
    started: u64,
    session: u32,
    alive: bool,
}

/// Whether the game's parent process is its launcher — the exe to learn — or why not. It has to be
/// alive and older than the game (an id is reused: a «parent» started after the game is another
/// process), an `.exe`, not the game's own exe, not AFKLink's (the helper's launches come from
/// Program Files) nor a game platform's client ([`PLATFORM_CLIENTS`]), and in the window exe's
/// folder or one above it — but not a drive's root: Explorer, consoles and other programs' folders
/// are none of those.
fn launcher_of(
    window_exe: &str,
    game: &ProcessSeen,
    parent: &Result<ProcessSeen, String>,
) -> Result<String, String> {
    let parent = parent
        .as_ref()
        .map_err(|e| format!("its parent not read ({e}): exited, or not readable"))?;
    let path = parent.path.as_str();
    if !parent.alive {
        return Err(format!("its parent ({path}) has exited"));
    }
    if parent.started >= game.started {
        return Err(format!(
            "its parent's id belongs to a process started after the game ({path}): the parent \
             has exited"
        ));
    }
    if !path.to_ascii_lowercase().ends_with(".exe") {
        return Err(format!("its parent is not an .exe ({path})"));
    }
    if same_path(path, window_exe) {
        return Err("its parent is the game's own exe".to_string());
    }
    let name = file_name(path).to_ascii_lowercase();
    if name.starts_with("afklink") {
        return Err(format!("its parent is AFKLink's own ({path})"));
    }
    if PLATFORM_CLIENTS.contains(&name.as_str()) {
        return Err(format!(
            "its parent is a game platform's client ({path}): it starts games by their id, not by \
             itself"
        ));
    }
    if !folder_holds(path, window_exe) {
        return Err(format!(
            "its parent is outside the game's folder and those above it ({path})"
        ));
    }
    Ok(path.to_string())
}

/// `outer`'s folder is `inner`'s folder or one above it — and not a drive's root.
fn folder_holds(outer: &str, inner: &str) -> bool {
    let folder = |path: &str| -> Vec<String> {
        let mut parts: Vec<String> = path
            .trim()
            .replace('/', "\\")
            .to_lowercase()
            .split('\\')
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect();
        parts.pop();
        parts
    };
    let (outer, inner) = (folder(outer), folder(inner));
    outer.len() >= 2 && outer.len() <= inner.len() && inner[..outer.len()] == outer[..]
}

/// The installation is not this build's, though its record may match the settings: [`outdated_why`].
fn outdated(installed: &Installed, helper_sha256: &str) -> bool {
    outdated_why(installed, helper_sha256).is_some()
}

/// Why the installed record asks for this build's setup, if it does: it names another build's helper
/// than the one this app carries (`helper_sha256`) — after the app updated itself — or its task was
/// registered at another priority than [`TASK_PRIORITY`] (an older setup left Task Scheduler's
/// default, 7: below normal). Either way the helper works on as it is (the signal does not count
/// this), and Settings asks for the update until the owner installs this build's:
/// «Нужно обновление» → «Обновить», through Windows' prompt ([`Ask::Update`]) — the setup puts
/// this build's helper in place and registers its task again, at [`TASK_PRIORITY`].
fn outdated_why(installed: &Installed, helper_sha256: &str) -> Option<String> {
    let record = installed.record.as_ref()?;
    let mut why = Vec::new();
    if !record.helper_sha256.eq_ignore_ascii_case(helper_sha256) {
        why.push(format!(
            "another build's helper ({}; this app carries {helper_sha256})",
            record.helper_sha256
        ));
    }
    match record.task_priority {
        Some(p) if p == TASK_PRIORITY => {}
        Some(p) => why.push(format!(
            "its task registered at priority {p} (this build registers {TASK_PRIORITY}, normal)"
        )),
        None => why.push(format!(
            "its task registered by an older setup that set no priority, at Task Scheduler's \
             default priority 7 (below normal; this build registers {TASK_PRIORITY}, normal)"
        )),
    }
    (!why.is_empty()).then(|| why.join("; "))
}

/// Whether the helper may act now; the reason when not. `seen`: the live sessions in one look
/// (`AgentControl::helper_sessions`) — the helper acts only for a **connected** one game-only
/// applies to: with «Только для гостей» on, the owner's own get the whole desktop and never let it
/// act, and a session still connecting (an attempt that may never connect) does not either.
fn decide(
    seen: &HelperSessions,
    game_only: bool,
    enabled: bool,
    mismatch: Option<Mismatch>,
) -> Result<(), String> {
    if !enabled {
        return Err("the helper is off in Settings".into());
    }
    if !game_only {
        return Err("«Только игра» is off".into());
    }
    if let Some(m) = mismatch {
        return Err(format!("the installation does not match: {}", m.why()));
    }
    if seen.game_only.is_empty() {
        let live = seen.live;
        return Err(if live == 0 {
            "no live session".into()
        } else if !seen.game_only_connecting.is_empty() {
            format!(
                "no connected session in game-only yet: {} still connecting ({:?}), {} of {live} \
                 live connected — the helper acts once the viewer receives, and an attempt that \
                 never connects never touches the game",
                seen.game_only_connecting.len(),
                seen.game_only_connecting,
                seen.connected
            )
        } else {
            format!(
                "no live session in game-only: {live} live, all the owner's own with «Только для \
                 гостей» on (the whole desktop never launches the game)"
            )
        });
    }
    Ok(())
}

/// The newest of the states read, if fresh.
fn fresh_state(states: Vec<StateFile>, now: SystemTime) -> Option<StateFile> {
    let newest = states.into_iter().max_by_key(|s| s.updated_ms)?;
    let age = afklink_game_helper::unix_ms(now).saturating_sub(newest.updated_ms);
    (age <= STATE_STALE.as_millis() as u64).then_some(newest)
}

/// «Игра не запускается» in Settings: the helper gave up launching the game and it has not run
/// since — the fresh `state.json`'s failed-launch mark, which the helper keeps across sessions and
/// its own restarts until the game runs a minute with its window. An older helper's file has no
/// mark: then its `gave_up`, which lasts the session only. A stale file is no helper: nothing.
fn failed_launch(state: Option<&StateFile>) -> bool {
    state.is_some_and(|s| s.failed_launch_since_ms.is_some() || s.state == HelperState::GaveUp)
}

/// Whether a stopped helper's task should be started again ([`GameHelper::revive`]): the owner's
/// switch on, a record installed and the task not known gone — and no fresh `state.json`. Whether
/// the installation matches the settings does not count: a helper that does not match acts on
/// nothing, and the window asks for the setup («Нужно разрешение»), which starts the task itself.
fn revive_wanted(enabled: bool, installed: &Installed, fresh: bool) -> bool {
    enabled && !fresh && installed.record.is_some() && installed.task != Some(TaskSeen::Absent)
}

/// How long after the last look the next one is, `tries` restarts in a row having found the helper
/// stopped again: [`REVIVE_EVERY`], doubling to [`REVIVE_MAX`].
fn revive_delay(tries: u32) -> Duration {
    REVIVE_EVERY
        .saturating_mul(1 << tries.min(8))
        .min(REVIVE_MAX)
}

/// Whether the sessions' heartbeats say the helper is launching the game: only while the signal lets
/// the helper act, and its fresh `state.json` ([`fresh_state`]; a stale one is none) says a launch
/// of its own waits for the game's window, or that it is about to launch the game again (its
/// window gone while its process runs, or being closed as hung): `launch_pending`. An older
/// helper's file has no such field and reads as not launching. `state.json` is read on every look
/// while the signal is on, so a change reaches the viewer within about a second.
fn launching(signal_on: bool, state: Option<&StateFile>) -> bool {
    signal_on && state.is_some_and(|s| s.launch_pending)
}

/// Why [`launching`] says what it says: for the line that logs a change.
fn launching_why(signal_on: bool, signal_why: &str, state: Option<&StateFile>) -> String {
    match state {
        _ if !signal_on => format!("the helper's signal is off: {signal_why}"),
        None => format!(
            "no fresh state.json from the helper (none read, or none written in the last {} s)",
            STATE_STALE.as_secs()
        ),
        Some(s) => format!(
            "the helper's state.json says {} ({}: {})",
            if s.launch_pending {
                "a launch of its own waits for the game's window"
            } else {
                "no launch of its own waits for the game's window"
            },
            s.state.as_str(),
            s.reason
        ),
    }
}

/// What a failed change tells the window: «Файл не найден» or «Не удалось применить».
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    NotFound,
    Failed,
}

impl Failure {
    fn code(self) -> String {
        match self {
            Self::NotFound => "not_found",
            Self::Failed => "failed",
        }
        .to_string()
    }
}

/// How a setup went, from the owner's side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Done,
    /// The owner did not confirm: not an error, the switch just goes back.
    Cancelled,
    Failed(Failure),
}

/// The setup's exit code (or the prompt's answer) as an outcome.
fn outcome_of(exit: Option<setup::Exit>) -> Outcome {
    match exit {
        Some(setup::Exit::Done) => Outcome::Done,
        Some(setup::Exit::NotFound) => Outcome::Failed(Failure::NotFound),
        _ => Outcome::Failed(Failure::Failed),
    }
}

/// Quote one argument the way `CommandLineToArgvW` reads it back: spaces, quotes, Unicode and
/// trailing backslashes intact.
#[cfg_attr(not(windows), allow(dead_code))]
fn quote_arg(value: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for ch in value.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        if ch == '"' {
            out.push_str(&"\\".repeat(slashes * 2 + 1));
        } else {
            out.push_str(&"\\".repeat(slashes));
        }
        slashes = 0;
        out.push(ch);
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

/// Recognize the setup before anything else the app does — the updater's arguments, the log,
/// config, Tauri: as the setup this process ends here.
pub(crate) fn early() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some(parsed) = setup::parse(&args) else {
        return;
    };
    // The setup runs elevated from the folder the owner keeps the portable exe in: before any of
    // its work, DLLs it loads by name come from System32 only. If Windows refuses, nothing is done.
    // The error's text goes nowhere but this exit code (the app logs its meaning): writing it to
    // `setup.log` would first mean finding Program Files — work done with the search unlimited.
    #[cfg(windows)]
    if system::limit_dll_search().is_err() {
        std::process::exit(setup::Exit::DllSearch.code());
    }
    let exit = match parsed {
        Err(_) => setup::Exit::Arguments,
        #[cfg(windows)]
        Ok(action) => setup::run(action),
        #[cfg(not(windows))]
        Ok(_) => setup::Exit::Directory,
    };
    std::process::exit(exit.code());
}

/* ── Windows, behind a few functions ──────────────────────────────────────────────────────── */

#[cfg(windows)]
mod platform {
    use super::system::{self, Elevated, Scheduler, TaskPresence};
    use super::TaskSeen;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    pub(super) use system::Signal;

    pub(super) fn sid() -> Result<String, String> {
        system::current_sid()
    }

    pub(super) fn dir(sid: &str) -> Result<PathBuf, String> {
        system::install_dir(sid)
    }

    pub(super) fn task(sid: &str) -> Result<TaskSeen, String> {
        let scheduler = Scheduler::connect()?;
        Ok(match system::task_presence(&scheduler, sid)? {
            TaskPresence::Absent => TaskSeen::Absent,
            TaskPresence::Present { running } => TaskSeen::Present { running },
        })
    }

    pub(super) fn run_task(sid: &str) -> Result<(), String> {
        let scheduler = Scheduler::connect()?;
        system::run_task(&scheduler, sid)
    }

    /// `Ok(None)`: the owner did not confirm; `Ok(Some(code))`: the setup's exit code, or `None`
    /// inside when it did not finish in time.
    pub(super) fn elevate(
        args: &[String],
        owner: Option<usize>,
        wait: Duration,
    ) -> Result<Option<Option<u32>>, String> {
        Ok(match system::elevate(args, owner, wait)? {
            Elevated::Cancelled => None,
            Elevated::Exited(code) => Some(Some(code)),
            Elevated::TimedOut => Some(None),
        })
    }

    pub(super) fn pick(
        owner: Option<usize>,
        start: Option<&Path>,
        title: &str,
        filter: &str,
    ) -> Result<Option<String>, String> {
        system::pick_exe(
            owner,
            start.map(Path::to_path_buf),
            title.to_string(),
            filter.to_string(),
        )
    }

    pub(super) fn processes() -> Result<Vec<super::Listed>, String> {
        system::processes()
    }

    pub(super) fn process(pid: u32) -> Result<super::ProcessSeen, String> {
        system::process(pid)
    }

    pub(super) fn this_session() -> Result<u32, String> {
        system::this_session()
    }
}

#[cfg(not(windows))]
mod platform {
    use super::TaskSeen;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const ONLY: &str = "the game helper needs Windows";

    pub(super) struct Signal;
    impl Signal {
        pub(super) fn create() -> Result<(Self, bool), String> {
            Err(ONLY.into())
        }
        pub(super) fn set(&self, _: bool) -> Result<(), String> {
            Err(ONLY.into())
        }
    }

    pub(super) fn sid() -> Result<String, String> {
        Err(ONLY.into())
    }
    pub(super) fn dir(_: &str) -> Result<PathBuf, String> {
        Err(ONLY.into())
    }
    pub(super) fn task(_: &str) -> Result<TaskSeen, String> {
        Err(ONLY.into())
    }
    pub(super) fn run_task(_: &str) -> Result<(), String> {
        Err(ONLY.into())
    }
    pub(super) fn elevate(
        _: &[String],
        _: Option<usize>,
        _: Duration,
    ) -> Result<Option<Option<u32>>, String> {
        Err(ONLY.into())
    }
    pub(super) fn pick(
        _: Option<usize>,
        _: Option<&Path>,
        _: &str,
        _: &str,
    ) -> Result<Option<String>, String> {
        Err(ONLY.into())
    }
    pub(super) fn processes() -> Result<Vec<super::Listed>, String> {
        Err(ONLY.into())
    }
    pub(super) fn process(_: u32) -> Result<super::ProcessSeen, String> {
        Err(ONLY.into())
    }
    pub(super) fn this_session() -> Result<u32, String> {
        Err(ONLY.into())
    }
}

/// What a change, and keeping the helper alive, ask of Windows — the helper's task in Task
/// Scheduler, the setup through Windows' elevation prompt — behind a trait: [`Native`] in the app;
/// in the tests, stand-ins, so [`GameHelper`]'s own methods run with no prompt, no task and no
/// process.
trait Platform: Send + Sync {
    /// As `platform::task`.
    fn task(&self, sid: &str) -> Result<TaskSeen, String>;
    /// As `platform::run_task`.
    fn run_task(&self, sid: &str) -> Result<(), String>;
    /// As `platform::elevate`.
    fn elevate(
        &self,
        args: &[String],
        owner: Option<usize>,
        wait: Duration,
    ) -> Result<Option<Option<u32>>, String>;
}

/// Windows' own calls (`platform`).
struct Native;

impl Platform for Native {
    fn task(&self, sid: &str) -> Result<TaskSeen, String> {
        platform::task(sid)
    }

    fn run_task(&self, sid: &str) -> Result<(), String> {
        platform::run_task(sid)
    }

    fn elevate(
        &self,
        args: &[String],
        owner: Option<usize>,
        wait: Duration,
    ) -> Result<Option<Option<u32>>, String> {
        platform::elevate(args, owner, wait)
    }
}

/* ── The helper, as the app keeps it ──────────────────────────────────────────────────────── */

/// The signal as last decided. It is on only while «Только игра» and the helper are on, the
/// installed record is the one for the bound game and the launch exe, and a session game-only
/// applies to has connected: with «Только для гостей» on, a guest's, so the owner's whole desktop
/// never launches the game nor brings it back. A session only requested, still connecting, never
/// counts (otherwise attempts that never connected would let the helper launch the game). The
/// sessions are read in one look (`AgentControl::helper_sessions`).
///
/// Another build's helper does not turn it off: the owner is away from the PC, and a helper that
/// stopped until they press a button would fail them. Settings asks for this build's helper
/// («Нужно обновление» → «Обновить», through Windows' prompt: [`Ask::Update`]) with the launch exe
/// its record names; a learned launcher is offered after it: the update first, the file then.
struct Watch {
    on: bool,
    reason: String,
    off_since: Option<Instant>,
    sessions: Vec<String>,
}

/// What [`GameHelper::revive`] remembers.
struct Revive {
    /// The last look at the task of a helper found stopped (or the app's start).
    last: Instant,
    /// Restarts in a row that found the helper stopped again; a fresh `state.json` starts over.
    tries: u32,
    /// Why the task was not started, as last logged: each reason once per change.
    noted: Option<String>,
}

/// What the watch thread remembers to learn the game's launcher ([`GameHelper::learn`]): when a
/// process of the game's window exe starts in this Windows session, its parent (alive, older than
/// it, an `.exe` in the game's folder or one above it, not a game platform's client) is the game's
/// own launcher. Learning a file never takes a working helper off: with the helper on and no file
/// chosen, an installation with another launch exe still matches, and Settings offers the learned
/// one («Найден другой файл запуска» → «Заменить», through the setup: [`Ask::ApplyFound`]); while
/// another build's helper is installed, only after its update.
#[derive(Default)]
struct Learner {
    /// The window exe watched for.
    game: Option<String>,
    /// Processes named like it already looked at, by id (dropped once gone from Windows' list).
    seen: Vec<u32>,
    /// This app's Windows session, read once.
    session: Option<Result<u32, String>>,
    /// Why the process list was last not read, as logged.
    failed: Option<String>,
}

/// The locks, and the one order they are taken in. `change` first, or not at all: taken blocking
/// only by a command's thread that holds nothing (`set_enabled`, `update`, `choose_launch`),
/// otherwise only tried (`refresh_unless_changing`; `revive`, under `revive` — the watch thread's
/// own, taken with nothing held). Under them every other lock — these, and the agent's config and
/// state — is taken alone and let go before the next: a value read under a short `let`, never a
/// guard kept alive by a temporary across a call that takes a lock (otherwise one thread waits on
/// itself for `installed`, holding the config, and the window stops answering). The log's own
/// locks come last, under any of these; logging takes none of them.
struct Shared {
    control: AgentControl,
    /// Task Scheduler and the elevated setup ([`Native`] in the app).
    platform: Arc<dyn Platform>,
    sid: Result<String, String>,
    dir: Result<PathBuf, String>,
    installed: Mutex<Installed>,
    state: Mutex<Option<StateFile>>,
    /// The newest `state.json` read, fresh or not: when it was written (Unix ms), for the lines on a
    /// stopped helper.
    state_seen_ms: Mutex<Option<u64>>,
    /// Why a `state.json` could not be read, as last logged.
    state_error: Mutex<Option<String>>,
    /// Keeping the helper alive ([`GameHelper::revive`]).
    revive: Mutex<Revive>,
    watch: Mutex<Watch>,
    /// Why the installation is outdated while it works on ([`outdated_why`]): logged once per
    /// change.
    version_note: Mutex<Option<String>>,
    /// The learned launcher Settings offers while the helper works on with another: logged once
    /// per change.
    found_note: Mutex<Option<String>>,
    signal: Option<platform::Signal>,
    /// The helper's two logs (the install directory's and `user\`) and the setup's, followed for
    /// new lines.
    mirror: Mutex<Vec<Tail>>,
    /// One change at a time: a setup, a choice of file. Settings opening does not read the
    /// installation while one runs (`refresh_unless_changing`).
    change: Mutex<()>,
}

/// Managed by Tauri; cheap to clone.
#[derive(Clone)]
pub(crate) struct GameHelper(Arc<Shared>);

impl GameHelper {
    /// The signal (not set), and the thread that keeps it, reads the installation and mirrors the
    /// helper's log.
    ///
    /// Takes the built app: a [`tauri::App`] exists only once `Builder::build` has initialised the
    /// plugins — the single-instance one among them, which ends a second launch there — so only the
    /// one instance makes the signal. Made before that, a second launch would reset the running
    /// instance's signal under a live «Только игра» session. `AgentControl` must be
    /// managed already (it is, on the builder). Main thread (`setup`): nothing here waits on another
    /// thread or the event loop.
    pub(crate) fn start(app: &tauri::App) -> Self {
        let control = app.state::<AgentControl>().inner().clone();
        let sid = platform::sid();
        let dir = sid.clone().and_then(|sid| platform::dir(&sid));
        if let Err(e) = &dir {
            tracing::warn!(
                "game helper: its install directory is not known ({e}); it cannot be set up"
            );
        }
        let signal = match platform::Signal::create() {
            Ok((signal, existed)) => {
                if existed {
                    tracing::warn!(
                        "game helper: its signal's name already existed — another process made it \
                         first; it is reset now, but that process could set it (and so make the \
                         helper launch or focus the approved game, nothing else)"
                    );
                } else {
                    tracing::debug!("game helper: signal made, not set");
                }
                Some(signal)
            }
            Err(e) => {
                tracing::error!(
                    "game helper: the signal was not made ({e}); the helper never acts in this run"
                );
                None
            }
        };
        let helper = Self::new(control, sid, dir, signal, Arc::new(Native));
        let watcher = helper.clone();
        if let Err(e) = std::thread::Builder::new()
            .name("afklink-game-helper".into())
            .spawn(move || watcher.watch())
        {
            tracing::error!(
                "game helper: its thread did not start ({e}); the signal stays off in this run"
            );
        }
        helper
    }

    /// The helper as the app keeps it, nothing started: no thread, nothing read. `platform`:
    /// Windows' own calls ([`Native`]), or the tests' stand-ins.
    fn new(
        control: AgentControl,
        sid: Result<String, String>,
        dir: Result<PathBuf, String>,
        signal: Option<platform::Signal>,
        platform: Arc<dyn Platform>,
    ) -> Self {
        // The helper starts at logon, about when the app does: its lines from a little before
        // this start are mirrored too, older ones are only in its file.
        let cutoff = utc_stamp(
            SystemTime::now()
                .checked_sub(MIRROR_BACK)
                .unwrap_or(SystemTime::UNIX_EPOCH),
        );
        let mirror = match &dir {
            Ok(dir) => vec![
                Tail::new(dir, SETUP_LOG_FILE, SETUP_LOG_OLD_FILE, cutoff.clone()),
                Tail::new(dir, LOG_FILE, LOG_OLD_FILE, cutoff.clone()),
                Tail::new(&dir.join(USER_DIR), LOG_FILE, LOG_OLD_FILE, cutoff),
            ],
            Err(_) => Vec::new(),
        };
        Self(Arc::new(Shared {
            control,
            platform,
            sid,
            dir,
            installed: Mutex::new(Installed::default()),
            state: Mutex::new(None),
            state_seen_ms: Mutex::new(None),
            state_error: Mutex::new(None),
            revive: Mutex::new(Revive {
                last: Instant::now(),
                tries: 0,
                noted: None,
            }),
            watch: Mutex::new(Watch {
                on: false,
                reason: "not decided yet".into(),
                off_since: None,
                sessions: Vec::new(),
            }),
            version_note: Mutex::new(None),
            found_note: Mutex::new(None),
            signal,
            mirror: Mutex::new(mirror),
            change: Mutex::new(()),
        }))
    }

    fn watch(self) {
        self.mirror();
        self.refresh("the app started");
        let (fit, (enabled, game_only)) = self.fit_with(|c| (c.game_helper, c.game_only));
        tracing::info!(
            enabled,
            game_only,
            launch = %fit.wanted.describe(),
            mismatch = fit.mismatch.map_or("none", Mismatch::why),
            other_build = fit.other_build,
            "game helper at the app's start"
        );
        if enabled && fit.mismatch.is_none() {
            self.keep_running("the app started");
        }
        let started = Instant::now();
        let (mut record_at, mut state_at, mut mirror_at) = (started, started, started);
        let mut learner = Learner::default();
        loop {
            let now = Instant::now();
            if now.duration_since(record_at) >= RECORD_EVERY {
                record_at = now;
                self.reread_record();
            }
            let state_every = if lock(&self.0.watch).on {
                STATE_EVERY_ALLOWED
            } else {
                STATE_EVERY
            };
            if now.duration_since(state_at) >= state_every {
                state_at = now;
                self.reread_state();
                self.revive(now);
            }
            if now.duration_since(mirror_at) >= MIRROR_EVERY {
                mirror_at = now;
                self.mirror();
            }
            // Every look (half a second): Scryde's loader lives about 3.5 s after the game starts.
            self.learn(&mut learner);
            self.evaluate("");
            std::thread::sleep(WATCH_EVERY);
        }
    }

    /// The game's launcher, from its window exe's parent process: each new process of the window
    /// exe in this Windows session is looked at once ([`launcher_of`]), and a launcher found is
    /// kept in config.json (`game_launch_learned`). Only while a game is chosen; every rejected
    /// parent is a debug line with why.
    fn learn(&self, learner: &mut Learner) {
        let window_exe = lock(&self.0.control.config)
            .game
            .as_ref()
            .map(|g| g.exe_path.clone());
        let Some(window_exe) = window_exe else {
            if learner.game.take().is_some() {
                learner.seen.clear();
                tracing::debug!("game helper: no game chosen; no launcher to learn");
            }
            return;
        };
        if learner.game.as_deref() != Some(window_exe.as_str()) {
            tracing::debug!(
                game = %window_exe,
                "game helper: watching the game's processes to learn its launcher"
            );
            learner.game = Some(window_exe.clone());
            learner.seen.clear();
        }
        let session = match learner.session.get_or_insert_with(platform::this_session) {
            Ok(session) => *session,
            Err(e) => {
                if learner.failed.as_deref() != Some(e.as_str()) {
                    tracing::warn!(
                        "game helper: this app's Windows session not read ({e}); the game's \
                         launcher is not learned in this run"
                    );
                    learner.failed = Some(e.clone());
                }
                return;
            }
        };
        let listed = match platform::processes() {
            Ok(listed) => {
                if learner.failed.take().is_some() {
                    tracing::debug!("game helper: the process list is read again");
                }
                listed
            }
            Err(e) => {
                if learner.failed.as_deref() != Some(e.as_str()) {
                    tracing::warn!(
                        "game helper: the process list not read ({e}); no launcher is learned \
                         meanwhile"
                    );
                }
                learner.failed = Some(e);
                return;
            }
        };
        let name = file_name(&window_exe).to_lowercase();
        learner
            .seen
            .retain(|pid| listed.iter().any(|entry| entry.pid == *pid));
        for entry in &listed {
            if entry.name.to_lowercase() != name || learner.seen.contains(&entry.pid) {
                continue;
            }
            learner.seen.push(entry.pid);
            let game = match platform::process(entry.pid) {
                Ok(game) => game,
                Err(e) => {
                    tracing::debug!(
                        pid = entry.pid,
                        "game helper: a process named like the game's not read ({e}); its parent \
                         is not looked at"
                    );
                    continue;
                }
            };
            if game.session != session || !same_path(&game.path, &window_exe) {
                tracing::debug!(
                    pid = entry.pid,
                    path = %game.path,
                    session = game.session,
                    "game helper: a process named like the game's is not it (another folder or \
                     Windows session); its parent is not looked at"
                );
                continue;
            }
            let parent = platform::process(entry.parent);
            match launcher_of(&window_exe, &game, &parent) {
                Ok(launcher) => self.learned(&window_exe, &launcher, entry.pid, entry.parent),
                Err(why) => tracing::debug!(
                    game_pid = entry.pid,
                    parent_pid = entry.parent,
                    "game helper: the game's launcher not learned from its parent: {why}"
                ),
            }
        }
    }

    /// Keep a launcher just found for `window_exe` — if that is still the game.
    fn learned(&self, window_exe: &str, launcher: &str, game_pid: u32, parent_pid: u32) {
        let mut config = lock(&self.0.control.config);
        if !config
            .game
            .as_ref()
            .is_some_and(|g| g.exe_matches(window_exe))
        {
            tracing::debug!(
                launcher,
                "game helper: the game changed meanwhile; the launcher found for the last one is \
                 not kept"
            );
            return;
        }
        if config
            .game_launch_learned
            .as_deref()
            .is_some_and(|l| same_path(l, launcher))
        {
            tracing::debug!(
                launcher,
                game_pid,
                parent_pid,
                "game helper: the game started by its launcher again, as learned"
            );
            return;
        }
        let was = config.game_launch_learned.replace(launcher.to_string());
        tracing::info!(
            learned = %launcher,
            was = %was.as_deref().unwrap_or("-"),
            chosen = %config.game_launch_exe.as_deref().unwrap_or("- (none)"),
            helper_on = config.game_helper,
            game_pid,
            parent_pid,
            "game helper: the game's launcher learned from its parent process{}",
            if config.game_launch_exe.is_some() {
                "; the owner's choice still goes first"
            } else {
                ""
            }
        );
        if let Err(e) = config.save() {
            tracing::warn!(
                "game helper: the learned launcher not saved to config.json: {e:#}; in force until \
                 exit"
            );
        }
    }

    /// The helper's new lines into this app's log.
    fn mirror(&self) {
        for tail in lock(&self.0.mirror).iter_mut() {
            tail.poll();
        }
    }

    fn read_record(&self) -> Installed {
        let mut installed = Installed {
            task: lock(&self.0.installed).task,
            ..Installed::default()
        };
        let Ok(dir) = &self.0.dir else {
            return installed;
        };
        match std::fs::read(dir.join(RECORD_FILE)) {
            Ok(bytes) => match Record::parse(&bytes) {
                Ok(record) => installed.record = Some(record),
                Err(e) => installed.record_error = Some(e),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => installed.record_error = Some(format!("{RECORD_FILE} not read: {e}")),
        }
        installed
    }

    /// Settings opened: read the installation again — unless a change (a setup, a choice of file)
    /// is running, which may have the installation half done; then what is known is shown as it
    /// is, and the change's own reads follow when it ends. Held for the read, so a change does not
    /// start in the middle of it either.
    pub(crate) fn refresh_unless_changing(&self, why: &str) {
        let _one = match self.0.change.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                tracing::debug!(
                    "game helper: installation not read again ({why}): a change is running; the \
                     window gets the state as last read"
                );
                return;
            }
            // A change panicked: nothing is half held by a mutex of `()`, read on.
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };
        self.refresh(why);
    }

    /// Read the record and the task again, and log what is there. Outside a change, from Settings,
    /// only through [`Self::refresh_unless_changing`].
    fn refresh(&self, why: &str) {
        let mut installed = self.read_record();
        installed.task = match &self.0.sid {
            Ok(sid) => match self.0.platform.task(sid) {
                Ok(task) => Some(task),
                Err(e) => {
                    tracing::warn!("game helper: its task not read ({why}): {e}");
                    None
                }
            },
            Err(_) => None,
        };
        self.reread_state();
        let state = lock(&self.0.state).clone();
        tracing::info!(
            dir = %self.0.dir.as_ref().map_or_else(|e| format!("unknown ({e})"), |d| d.display().to_string()),
            helper = HELPER_SHA256,
            state = %state.as_ref().map_or("-".to_string(), |s| format!("{} ({})", s.state.as_str(), s.reason)),
            "game helper installation read ({why}): {}",
            installed.describe()
        );
        *lock(&self.0.installed) = installed;
        self.evaluate(why);
    }

    fn reread_record(&self) {
        let fresh = self.read_record();
        let mut installed = lock(&self.0.installed);
        if fresh.record != installed.record || fresh.record_error != installed.record_error {
            tracing::info!(
                "game helper: the installed record changed on disk: {}",
                fresh.describe()
            );
            installed.record = fresh.record;
            installed.record_error = fresh.record_error;
        }
    }

    fn reread_state(&self) {
        let Ok(dir) = &self.0.dir else {
            return;
        };
        let mut states = Vec::new();
        let mut errors = Vec::new();
        for path in [dir.join(STATE_FILE), dir.join(USER_DIR).join(STATE_FILE)] {
            match std::fs::read(&path).map_err(|e| (e.kind(), e.to_string())) {
                Ok(bytes) => match StateFile::parse(&bytes) {
                    Ok(state) => states.push(state),
                    Err(e) => errors.push(format!("{}: {e}", path.display())),
                },
                // Not written yet, or removed by a setup: nothing to show.
                Err((std::io::ErrorKind::NotFound, _)) => {}
                Err((_, e)) => errors.push(format!("{}: {e}", path.display())),
            }
        }
        let errors = (!errors.is_empty()).then(|| errors.join("; "));
        {
            let mut last = lock(&self.0.state_error);
            if *last != errors {
                if let Some(e) = &errors {
                    tracing::debug!("game helper: its state.json not read: {e}");
                }
                *last = errors;
            }
        }
        *lock(&self.0.state_seen_ms) = states.iter().map(|s| s.updated_ms).max();
        let fresh = fresh_state(states, SystemTime::now());
        let mut state = lock(&self.0.state);
        let before = state
            .as_ref()
            .map(|s| (s.state, s.launch_pending, s.failed_launch_since_ms));
        let after = fresh
            .as_ref()
            .map(|s| (s.state, s.launch_pending, s.failed_launch_since_ms));
        if before != after {
            let mark = |s: Option<(HelperState, bool, Option<u64>)>| match s {
                None => "- (no fresh state.json)".to_string(),
                Some((_, _, None)) => "not set".to_string(),
                Some((_, _, Some(ms))) => format!("set since {ms} ms"),
            };
            tracing::debug!(
                from = before.map_or("-", |(s, ..)| s.as_str()),
                to = after.map_or("- (no fresh state.json)", |(s, ..)| s.as_str()),
                launch_pending = after.is_some_and(|(_, pending, _)| pending),
                was_launch_pending = before.is_some_and(|(_, pending, _)| pending),
                failed_launch = %mark(after),
                was_failed_launch = %mark(before),
                shows_failed_launch = failed_launch(fresh.as_ref()),
                reason = %fresh.as_ref().map_or("", |s| s.reason.as_str()),
                "game helper: its state"
            );
        }
        *state = fresh;
    }

    /// The helper is on and installed, but its `state.json` is stale and its task not running: it
    /// stopped — crashed, or ended — and the window would go on as if it worked. Its task is started
    /// again, as the owner may without a prompt ([`revive_wanted`]): at most once a minute, the
    /// pause doubling while it keeps stopping ([`revive_delay`]); never while a change runs (a setup
    /// removes and starts the task itself). Each try is logged with why and how it went; a task
    /// that runs with a stale file (the helper hangs, or cannot write) is said once, not restarted.
    fn revive(&self, now: Instant) {
        // Each read under a lock of its own, let go at once — before `revive` is taken.
        let fresh = lock(&self.0.state).is_some();
        let enabled = lock(&self.0.control.config).game_helper;
        let installed = lock(&self.0.installed).clone();
        let wanted = revive_wanted(enabled, &installed, fresh);
        let mut revive = lock(&self.0.revive);
        if fresh {
            if revive.tries > 0 {
                tracing::info!(
                    restarts = revive.tries,
                    "game helper: its state.json is fresh again after its task was started again"
                );
            }
            revive.tries = 0;
            revive.noted = None;
            return;
        }
        if !wanted || now.duration_since(revive.last) < revive_delay(revive.tries) {
            return;
        }
        let Ok(sid) = &self.0.sid else {
            return;
        };
        // A setup removes the task and starts it again itself: not in its middle.
        let _one = match self.0.change.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                tracing::trace!(
                    "game helper: its state.json is stale, but a change is running: its task is \
                     looked at after it"
                );
                return;
            }
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };
        revive.last = now;
        let seen_ms = *lock(&self.0.state_seen_ms);
        let seen = match seen_ms {
            Some(ms) => format!(
                "its newest state.json was written {} s ago",
                afklink_game_helper::unix_ms(SystemTime::now()).saturating_sub(ms) / 1000
            ),
            None => "no state.json of it is there".to_string(),
        };
        let task = self.0.platform.task(sid);
        if let Ok(task) = &task {
            lock(&self.0.installed).task = Some(*task);
        }
        let (note, why) = match task {
            Ok(TaskSeen::Present { running: false }) => {
                revive.tries += 1;
                let why = format!(
                    "the helper is on and installed, {seen} (stale after {} s) and its task is not \
                     running: it stopped (crashed, or ended)",
                    STATE_STALE.as_secs()
                );
                match self.0.platform.run_task(sid) {
                    Ok(()) => tracing::warn!(
                        restart = revive.tries,
                        next_look_in_s = revive_delay(revive.tries).as_secs(),
                        "game helper: its task started again — {why}"
                    ),
                    Err(e) => tracing::warn!(
                        restart = revive.tries,
                        next_look_in_s = revive_delay(revive.tries).as_secs(),
                        "game helper: its task did not start again ({e}) — {why}"
                    ),
                }
                revive.noted = None;
                return;
            }
            Ok(TaskSeen::Present { running: true }) => (
                "running".to_string(),
                format!(
                    "{seen} (stale after {} s) while its task runs: the helper hangs, or cannot \
                     write its state; not restarted",
                    STATE_STALE.as_secs()
                ),
            ),
            Ok(TaskSeen::Absent) => (
                "absent".to_string(),
                format!(
                    "{seen} and its task is gone: nothing to start (Settings asks for the setup)"
                ),
            ),
            Err(e) => (
                format!("unread: {e}"),
                format!("{seen} and its task not read ({e}): not started"),
            ),
        };
        if revive.noted.as_deref() != Some(note.as_str()) {
            tracing::warn!("game helper: the helper is on and installed, but {why}");
            revive.noted = Some(note);
        }
    }

    /// The installation as last read, against the settings now ([`Fit`]), and `read` of the same
    /// config. Each lock alone — the helper's state, the installation, then the config — and each
    /// let go before the next is taken: nothing here waits for a lock while holding another of the
    /// helper's. `read` runs under the config's lock and takes none. (A guard of the installation,
    /// kept alive by a temporary to the end of a statement, across a call that takes it again,
    /// leaves one thread waiting on itself, the config held: «Установить» hangs the window.)
    fn fit_with<T>(&self, read: impl FnOnce(&Config) -> T) -> (Fit, T) {
        let state = lock(&self.0.state).as_ref().map(|s| s.state);
        let installed = lock(&self.0.installed).clone();
        let config = lock(&self.0.control.config);
        (Fit::of(installed, &config, state), read(&config))
    }

    /// [`Self::fit_with`], nothing else read.
    fn fit(&self) -> Fit {
        self.fit_with(|_| ()).0
    }

    /// The learned launcher offered in place of the installed launch exe: one line when that
    /// starts, and one when it ends.
    fn note_found(&self, fit: &Fit) {
        let found = fit.found.clone();
        let installed = fit.installed.record.as_ref().map(|r| r.launch_exe.as_str());
        let mut last = lock(&self.0.found_note);
        if *last == found {
            return;
        }
        match (&found, last.as_ref()) {
            (Some(learned), _) => tracing::info!(
                learned = %learned,
                installed = %installed.unwrap_or("- (no record)"),
                other_build = fit.other_build,
                "game helper: the launcher learned from the game's parent is not the installed \
                 launch exe; the helper works on with the installed one, and Settings offers the \
                 learned one{}",
                if fit.other_build {
                    " once this build's helper is installed («Нужно обновление» goes first)"
                } else {
                    ""
                }
            ),
            (None, Some(was)) => tracing::info!(
                was = %was,
                installed = %installed.unwrap_or("- (no record)"),
                "game helper: the learned launcher is offered no more (applied, a file chosen, the \
                 helper off, or another game)"
            ),
            (None, None) => {}
        }
        *last = found;
    }

    /// An outdated installation that works on — its record matches (`mismatch` is `None`), but it is
    /// another build's helper or its task's priority is not this build's ([`outdated_why`]): one line
    /// with why when that starts, and one when it ends.
    fn note_version(&self, fit: &Fit) {
        let mismatch = fit.mismatch;
        let installed = fit
            .installed
            .record
            .as_ref()
            .map(|r| r.helper_sha256.as_str());
        let other = if mismatch.is_none() {
            outdated_why(&fit.installed, HELPER_SHA256)
        } else {
            None
        };
        let mut last = lock(&self.0.version_note);
        if *last == other {
            return;
        }
        match (&other, last.as_ref()) {
            (Some(why), _) => tracing::info!(
                installed = %installed.unwrap_or("- (no record)"),
                carried = HELPER_SHA256,
                task_priority = TASK_PRIORITY,
                "game helper: the installation is outdated — {why} — and its record matches the \
                 game and the launch exe: it works on (the signal does not count this); Settings \
                 asks for the update («Нужно обновление» → «Обновить», Windows' prompt)"
            ),
            (None, Some(was)) => tracing::info!(
                was = %was,
                installed = %installed.unwrap_or("- (no record)"),
                carried = HELPER_SHA256,
                mismatch = mismatch.map_or("none", Mismatch::why),
                "game helper: the installation is outdated no more (updated), or it no longer \
                 works on"
            ),
            (None, None) => {}
        }
        *last = other;
    }

    /// Decide the signal now and set it; log a change with its reason (`why`: what asked). Then what
    /// the sessions' heartbeats say of the helper's launch ([`launching`]).
    pub(crate) fn evaluate(&self, why: &str) {
        let now = Instant::now();
        // One look at the sessions — the count of live ones and the lists from the same snapshot,
        // so the reason never says «0 live» beside a session in game-only. Only connected
        // sessions game-only applies to: with «Только для гостей» on, the owner's own get the
        // whole desktop, and the game is neither launched nor brought back for them; and nothing
        // is done for a session still connecting (`afklink_core::game_access`). A new one of these
        // starts the helper afresh.
        let seen = self.0.control.helper_sessions();
        let sessions = seen.game_only.clone();
        // Read before the watch is taken, each under a lock of its own: no lock is held inside
        // another here, and under the watch's nothing else of the helper's is taken.
        let helper_state = lock(&self.0.state).clone();
        let (fit, (game_only, enabled)) = self.fit_with(|c| (c.game_only, c.game_helper));
        let decision = decide(&seen, game_only, enabled, fit.mismatch);
        self.note_version(&fit);
        self.note_found(&fit);
        let mut watch = lock(&self.0.watch);
        let new_session = sessions.iter().any(|id| !watch.sessions.contains(id));
        let (on, reason) = match decision {
            Err(reason) => (false, reason),
            Ok(()) if watch.on && new_session => (
                false,
                "a new session: off for a moment so the helper starts it afresh".to_string(),
            ),
            Ok(())
                if watch
                    .off_since
                    .is_some_and(|at| now.duration_since(at) < SIGNAL_OFF_MIN) =>
            {
                (
                    false,
                    "held off for a moment so the helper sees the change".to_string(),
                )
            }
            Ok(()) => (
                true,
                format!(
                    "{} connected session(s) in game-only, of {} live",
                    sessions.len(),
                    seen.live
                ),
            ),
        };
        let asked = if why.is_empty() {
            String::new()
        } else {
            format!(" [{why}]")
        };
        if on != watch.on {
            let applied = match &self.0.signal {
                Some(signal) => signal.set(on),
                None => Err("no signal in this run".to_string()),
            };
            match applied {
                Ok(()) => tracing::info!(
                    sessions = ?sessions,
                    connecting = ?seen.game_only_connecting,
                    live = seen.live,
                    connected = seen.connected,
                    "game helper signal {}: {reason}{asked}",
                    if on { "on" } else { "off" }
                ),
                Err(e) => tracing::error!(
                    sessions = ?sessions,
                    connecting = ?seen.game_only_connecting,
                    live = seen.live,
                    connected = seen.connected,
                    "game helper signal not set {}: {e} ({reason}){asked}",
                    if on { "on" } else { "off" }
                ),
            }
            watch.on = on;
            if !on {
                watch.off_since = Some(now);
            }
        } else if reason != watch.reason {
            tracing::debug!(
                sessions = ?sessions,
                connecting = ?seen.game_only_connecting,
                live = seen.live,
                connected = seen.connected,
                "game helper signal stays {}: {reason}{asked}",
                if on { "on" } else { "off" }
            );
        }
        // Under the watch, as the signal: two callers cannot tell the sessions in the wrong order.
        let launch = launching(on, helper_state.as_ref());
        if launch != self.0.control.game_launching() {
            let told = launching_why(on, &reason, helper_state.as_ref());
            self.0
                .control
                .set_game_launching(launch, &format!("{told}{asked}"));
        }
        watch.reason = reason;
        watch.sessions = sessions;
    }

    /// Start the task if it is installed and not running: the owner may run it, no prompt.
    fn keep_running(&self, why: &str) {
        let Ok(sid) = &self.0.sid else {
            return;
        };
        let task = lock(&self.0.installed).task;
        match task {
            Some(TaskSeen::Present { running: false }) => match self.0.platform.run_task(sid) {
                Ok(()) => tracing::info!("game helper: its task started ({why})"),
                Err(e) => tracing::warn!("game helper: its task did not start ({why}): {e}"),
            },
            Some(TaskSeen::Present { running: true }) => {
                tracing::debug!("game helper: its task is running ({why})");
            }
            Some(TaskSeen::Absent) | None => {
                tracing::debug!("game helper: no task to start ({why})");
            }
        }
    }

    pub(crate) fn dto(&self) -> HelperDto {
        let (fit, enabled) = self.fit_with(|c| c.game_helper);
        let (state, failed_launch) = {
            let state = lock(&self.0.state);
            (
                state.as_ref().map(|s| s.state),
                failed_launch(state.as_ref()),
            )
        };
        let launch = fit.wanted.exe;
        HelperDto {
            enabled,
            launch_name: launch.as_deref().map(|l| file_name(l).to_string()),
            launch_exe: launch,
            installed: fit.installed.complete(),
            mismatch: fit.mismatch,
            outdated: fit.other_build,
            found_launch: fit.found,
            state,
            failed_launch,
        }
    }

    fn save(&self, what: &str, change: impl FnOnce(&mut Config)) {
        let mut config = lock(&self.0.control.config);
        change(&mut config);
        if let Err(e) = config.save() {
            tracing::warn!(
                "game helper: {what} not saved to config.json: {e:#}; in force until exit"
            );
        }
    }

    fn run_setup(&self, action: &setup::Action, owner: Option<usize>) -> Outcome {
        tracing::info!(
            "game helper: asking Windows to run the setup elevated: {}",
            action.describe()
        );
        let outcome = match self.0.platform.elevate(&action.args(), owner, SETUP_WAIT) {
            Ok(None) => {
                tracing::info!(
                    "game helper: the owner did not confirm Windows' prompt (ERROR_CANCELLED, \
                     1223): nothing changed"
                );
                Outcome::Cancelled
            }
            Ok(Some(None)) => {
                tracing::warn!(
                    "game helper: the setup did not finish in {} s; left to finish on its own",
                    SETUP_WAIT.as_secs()
                );
                Outcome::Failed(Failure::Failed)
            }
            Ok(Some(Some(code))) => {
                let exit = setup::Exit::from_code(code);
                let outcome = outcome_of(exit);
                match outcome {
                    Outcome::Done => tracing::info!("game helper: the setup is done (exit 0)"),
                    // not-a-key-name: the setup's exit code
                    _ => tracing::warn!(
                        code,
                        "game helper: the setup failed: {} (its steps are in setup.log, mirrored \
                         below)",
                        exit.map_or("an unknown exit code", setup::Exit::meaning)
                    ),
                }
                outcome
            }
            Err(e) => {
                tracing::warn!("game helper: the setup did not run: {e}");
                Outcome::Failed(Failure::Failed)
            }
        };
        // Its steps now, beside these lines, not at the next look.
        self.mirror();
        outcome
    }

    /// The switch: on, after the setup when the installation does not match; off at once, then
    /// the removal. `Ok` also when the owner did not confirm.
    fn set_enabled(&self, enabled: bool, owner: Option<usize>) -> Result<(), Failure> {
        let _one = lock(&self.0.change);
        tracing::info!(enabled, "game helper switched in Settings");
        if enabled {
            self.turn_on(owner, Ask::Switch).map(|_| ())
        } else {
            self.turn_off(owner);
            Ok(())
        }
    }

    /// «Обновить» by «Нужно обновление» ([`Ask::Update`]: this build's helper, the launch exe its
    /// record names kept) and «Заменить» by «Найден другой файл запуска» ([`Ask::ApplyFound`]: the
    /// learned launcher, this build's helper with it as with any setup) — through the setup (and
    /// Windows' prompt), [`plan`]. Over an installation that does not match, either is «Разрешить»:
    /// the helper as the settings want it. Also turns the helper on, as any setup does — Settings
    /// offers either only while the helper is on. `Ok` also when the owner did not confirm: the
    /// installed helper then works on as it was.
    fn update(&self, owner: Option<usize>, ask: Ask) -> Result<(), Failure> {
        let _one = lock(&self.0.change);
        let (fit, enabled) = self.fit_with(|c| c.game_helper);
        let record = fit.installed.record.as_ref();
        tracing::info!(
            enabled,
            installed = %record.map_or("- (no record)", |r| r.helper_sha256.as_str()),
            installed_launch = %record.map_or("-", |r| r.launch_exe.as_str()),
            carried = HELPER_SHA256,
            other_build = fit.other_build,
            mismatch = fit.mismatch.map_or("none", Mismatch::why),
            launch = %fit.wanted.describe(),
            found = %fit.found.as_deref().unwrap_or("-"),
            "game helper: the owner pressed {}",
            ask.as_str()
        );
        self.turn_on(owner, ask).map(|_| ())
    }

    /// `Ok(true)`: on; `Ok(false)`: the owner did not confirm. `ask`: what the owner pressed — the
    /// switch runs the setup only when the installation does not match, «Обновить» also when only
    /// the helper's build differs, «Заменить» also when only a learned launch exe does ([`plan`]).
    fn turn_on(&self, owner: Option<usize>, ask: Ask) -> Result<bool, Failure> {
        let (game, launch, lang) = {
            let config = lock(&self.0.control.config);
            (
                config.game.clone(),
                launch_for(&config),
                config.lang.clone(),
            )
        };
        let Some(game) = game else {
            tracing::warn!("game helper: not turned on: no game is chosen");
            return Err(Failure::Failed);
        };
        let Some(launch) = launch else {
            tracing::warn!(
                game = %game.exe_path,
                "game helper: not turned on: no launch exe beside the game's, none chosen"
            );
            return Err(Failure::NotFound);
        };
        let sid = self.0.sid.clone().map_err(|e| {
            tracing::warn!("game helper: not turned on: the owner's SID is not known ({e})");
            Failure::Failed
        })?;
        self.refresh("before turning the helper on");
        // One copy of the installation, judged with no lock held (`fit_with`): a guard of
        // `installed` kept alive by a temporary to the end of the statement would outlive a call
        // that takes it again — the thread waiting on itself, holding the config; the window hung.
        let fit = self.fit();
        let planned = plan(ask, &fit, &launch);
        tracing::debug!(
            ask = ask.as_str(),
            needed = fit.mismatch.map_or("none", Mismatch::why),
            other_build = fit.other_build,
            installed_launch = %fit
                .installed
                .record
                .as_ref()
                .map_or("- (no record)", |r| r.launch_exe.as_str()),
            wanted = %fit.wanted.describe(),
            found = %fit.found.as_deref().unwrap_or("-"),
            plan = ?planned,
            "game helper: turning on: the installation against the settings and what was asked"
        );
        let (launch, reason) = match planned {
            Plan::Setup { launch, why } => (launch, why),
            Plan::Ready(why) => {
                self.save("the helper's switch", |c| c.game_helper = true);
                tracing::info!(
                    ask = ask.as_str(),
                    other_build = fit.other_build,
                    found = %fit.found.as_deref().unwrap_or("-"),
                    "game helper on without a Windows prompt: {why}{}",
                    match (fit.other_build, &fit.found) {
                        (true, _) => {
                            " (another build's helper: it works on, Settings asks for this build's)"
                        }
                        (false, Some(_)) => {
                            " (a learned launcher differs from the installed launch exe: Settings \
                             offers it)"
                        }
                        (false, None) => "",
                    }
                );
                self.keep_running("turned on");
                self.evaluate("turned on");
                return Ok(true);
            }
        };
        tracing::info!(
            ask = ask.as_str(),
            launch = %launch,
            "game helper: the setup is needed: {reason}"
        );
        // The task's description in Task Scheduler, in the window's language now: the setting
        // when it names one, Windows' own for «auto» — as the window resolves it.
        let locale = Locale::resolve(Some(lang.as_str()));
        tracing::debug!(
            setting = %lang,
            locale = locale.tag(),
            "game helper: the task will be described in the window's language"
        );
        let action = setup::Action::Install(setup::Install {
            sid,
            launch_exe: launch.clone(),
            window_exe: game.exe_path.clone(),
            window_class: game.window_class.clone(),
            locale,
        });
        match self.run_setup(&action, owner) {
            Outcome::Done => {
                self.save("the helper's switch", |c| c.game_helper = true);
                self.refresh("after the setup");
                self.check_after_setup(ask, &launch);
                Ok(true)
            }
            Outcome::Cancelled => {
                self.evaluate("the owner did not confirm");
                Ok(false)
            }
            Outcome::Failed(failure) => {
                self.refresh("after a failed setup");
                Err(failure)
            }
        }
    }

    /// After a setup that went through: whether the installation read again is what was asked —
    /// this build's helper with `launch`. Each difference is a warning; a learned launcher still
    /// offered after «Обновить», which keeps the installed launch exe, is a debug line.
    fn check_after_setup(&self, ask: Ask, launch: &str) {
        let after = self.fit();
        let record_launch = after
            .installed
            .record
            .as_ref()
            .map(|r| r.launch_exe.as_str());
        if let Some(left) = after.mismatch {
            tracing::warn!(
                ask = ask.as_str(),
                "game helper: after the setup the installation still differs: {}",
                left.why()
            );
        } else if !record_launch.is_some_and(|l| same_path(l, launch)) {
            tracing::warn!(
                ask = ask.as_str(),
                installed = %launch,
                record = %record_launch.unwrap_or("- (no record)"),
                "game helper: after the setup the record names another launch exe than the one \
                 installed"
            );
        } else if after.other_build {
            tracing::warn!(
                ask = ask.as_str(),
                carried = HELPER_SHA256,
                "game helper: after the setup the installation is still outdated: {}",
                outdated_why(&after.installed, HELPER_SHA256).unwrap_or_default()
            );
        } else if let Some(found) = &after.found {
            if ask == Ask::Update {
                tracing::debug!(
                    found = %found,
                    launch = %launch,
                    "game helper: updated to this build's helper with the installed launch exe, as \
                     asked; the learned launcher is offered now («Найден другой файл запуска»)"
                );
            } else {
                tracing::warn!(
                    ask = ask.as_str(),
                    found = %found,
                    "game helper: after the setup the record still names another launch exe than \
                     the learned one"
                );
            }
        } else {
            tracing::debug!(
                ask = ask.as_str(),
                launch = %launch,
                "game helper: after the setup the installation is the one asked for, this build's \
                 helper"
            );
        }
    }

    fn turn_off(&self, owner: Option<usize>) {
        self.save("the helper's switch", |c| c.game_helper = false);
        // The signal first: the helper does nothing from its next look.
        self.evaluate("turned off");
        self.refresh("turning the helper off");
        if !lock(&self.0.installed).present() {
            tracing::info!("game helper off; nothing installed to remove");
            return;
        }
        let Ok(sid) = self.0.sid.clone() else {
            return;
        };
        match self.run_setup(&setup::Action::Remove { sid }, owner) {
            Outcome::Done => tracing::info!("game helper off and removed"),
            Outcome::Cancelled => tracing::info!(
                "game helper off; it stays installed (the owner did not confirm the removal), \
                 and turning it on again needs no prompt while it matches"
            ),
            Outcome::Failed(_) => tracing::warn!(
                "game helper off; its removal failed, it stays installed and does nothing"
            ),
        }
        self.refresh("after turning the helper off");
    }

    /// Windows' Open dialog in the game's folder; a chosen exe becomes the launch exe and the setup
    /// runs (also to turn the helper on, when it is off). The owner not confirming keeps the
    /// previous exe when the helper was on.
    fn choose_launch(&self, owner: Option<usize>, locale: Locale) -> Result<(), Failure> {
        let _one = lock(&self.0.change);
        let (game, was_on, previous) = {
            let config = lock(&self.0.control.config);
            (
                config.game.clone(),
                config.game_helper,
                config.game_launch_exe.clone(),
            )
        };
        let Some(game) = game else {
            tracing::warn!("game helper: no game, so no launch exe to choose");
            return Err(Failure::Failed);
        };
        let start = Path::new(&game.exe_path).parent();
        tracing::info!(
            start = %start.map_or("-".to_string(), |p| p.display().to_string()),
            "game helper: the owner is choosing the launch exe"
        );
        let picked = match platform::pick(
            owner,
            start,
            NativeText::DialogGameLaunchTitle.t(locale),
            NativeText::DialogGameLaunchFilter.t(locale),
        ) {
            Ok(Some(path)) => path,
            Ok(None) => {
                tracing::info!("game helper: the file dialog closed without a choice");
                return Ok(());
            }
            Err(e) => {
                tracing::warn!("game helper: the file dialog failed: {e}");
                return Err(Failure::Failed);
            }
        };
        if let Err(e) = check_launch_exe(&picked) {
            tracing::warn!(picked = %picked, "game helper: the chosen file is refused: {e}");
            return Err(Failure::Failed);
        }
        if !Path::new(&picked).is_file() {
            tracing::warn!(picked = %picked, "game helper: the chosen file is not there");
            return Err(Failure::NotFound);
        }
        tracing::info!(
            picked = %picked,
            previous = %previous.as_deref().unwrap_or("- (default)"),
            helper_on = was_on,
            "game helper: launch exe chosen"
        );
        self.save("the launch exe", |c| {
            c.game_launch_exe = Some(picked.clone())
        });
        let result = self.turn_on(owner, Ask::Switch);
        if was_on && !matches!(result, Ok(true)) {
            tracing::info!(
                previous = %previous.as_deref().unwrap_or("- (default)"),
                "game helper: the setup for the new launch exe did not happen; the previous one is \
                 kept"
            );
            self.save("the launch exe", |c| c.game_launch_exe = previous);
            self.evaluate("the launch exe kept");
        }
        result.map(|_| ())
    }
}

/* ── The helper's log in the app's ────────────────────────────────────────────────────────── */

/// New lines of one log (`helper.log` or `setup.log`), followed across its rotation.
struct Tail {
    path: PathBuf,
    old: PathBuf,
    /// Where the next read starts; `None` before the first look.
    offset: Option<u64>,
    /// On the first look, lines older than this are skipped (stamps sort as text).
    cutoff: String,
    failed: Option<String>,
}

impl Tail {
    /// `file` in `dir`, and `old`, its rotated copy there.
    fn new(dir: &Path, file: &str, old: &str, cutoff: String) -> Self {
        Self {
            path: dir.join(file),
            old: dir.join(old),
            offset: None,
            cutoff,
            failed: None,
        }
    }

    fn poll(&mut self) {
        match self.read() {
            Ok(lines) => {
                if self.failed.take().is_some() {
                    tracing::debug!(path = %self.path.display(), "game helper: its log is read again");
                }
                for line in lines {
                    emit(&line);
                }
            }
            Err(e) => {
                let e = e.to_string();
                if self.failed.as_deref() != Some(e.as_str()) {
                    tracing::debug!(path = %self.path.display(), "game helper: its log not read: {e}");
                }
                self.failed = Some(e);
            }
        }
    }

    fn read(&mut self) -> std::io::Result<Vec<String>> {
        let len = match std::fs::metadata(&self.path) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // None yet: when it comes, all of it is new.
                if self.offset.is_none() {
                    self.offset = Some(0);
                    self.cutoff.clear();
                }
                return Ok(Vec::new());
            }
            Err(e) => return Err(e),
        };
        let first = self.offset.is_none();
        let mut offset = self.offset.unwrap_or(0);
        let mut bytes = Vec::new();
        if len < offset {
            // Rotated: the rest of the old file first.
            if let Ok(old) = std::fs::metadata(&self.old) {
                if old.len() > offset {
                    bytes.extend(read_range(&self.old, offset, old.len())?);
                }
            }
            offset = 0;
        }
        let to = len.min(offset + MIRROR_MAX_BYTES);
        let chunk = read_range(&self.path, offset, to)?;
        let whole = chunk
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |at| at + 1);
        bytes.extend_from_slice(&chunk[..whole]);
        self.offset = Some(offset + whole as u64);
        let text = String::from_utf8_lossy(&bytes);
        let cutoff = std::mem::take(&mut self.cutoff);
        Ok(text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter(|l| {
                !first
                    || cutoff.is_empty()
                    || l.get(..cutoff.len()).is_some_and(|s| s >= cutoff.as_str())
            })
            .map(str::to_string)
            .collect())
    }
}

fn read_range(path: &Path, from: u64, to: u64) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(from))?;
    let mut bytes = Vec::with_capacity(to.saturating_sub(from) as usize);
    file.take(to.saturating_sub(from)).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// One line of the helper's log into the app's, at its level, with the helper's own UTC stamp.
fn emit(line: &str) {
    match parse_line(line) {
        Some((stamp, Level::Error, rest)) => {
            tracing::error!(target: HELPER_TARGET, "{stamp} {rest}")
        }
        Some((stamp, Level::Warn, rest)) => tracing::warn!(target: HELPER_TARGET, "{stamp} {rest}"),
        Some((stamp, Level::Info, rest)) => tracing::info!(target: HELPER_TARGET, "{stamp} {rest}"),
        Some((stamp, Level::Debug, rest)) => {
            tracing::debug!(target: HELPER_TARGET, "{stamp} {rest}")
        }
        None => tracing::info!(target: HELPER_TARGET, "{line}"),
    }
}

/* ── Commands ─────────────────────────────────────────────────────────────────────────────── */

/// Only this app's own main window changes the helper: no remote command reaches here.
fn local_window(window: &tauri::WebviewWindow) -> Result<(), String> {
    if window.label() == "main" {
        Ok(())
    } else {
        tracing::warn!(
            window = window.label(),
            "game helper: a change asked from another window, refused"
        );
        Err(Failure::Failed.code())
    }
}

/// The window Windows' prompt and dialog belong to.
fn owner_of(window: &tauri::WebviewWindow) -> Option<usize> {
    #[cfg(windows)]
    {
        match window.hwnd() {
            Ok(hwnd) => Some(hwnd.0 as usize),
            Err(e) => {
                tracing::debug!("game helper: the main window's handle unknown: {e}");
                None
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        None
    }
}

/// The switch. Errors: `not_found`, `failed`; the owner not confirming is not one.
#[tauri::command]
pub(crate) async fn set_game_helper(
    window: tauri::WebviewWindow,
    control: State<'_, AgentControl>,
    helper: State<'_, GameHelper>,
    enabled: bool,
) -> Result<GameOnlyDto, String> {
    local_window(&window)?;
    let owner = owner_of(&window);
    let (control, helper) = ((*control).clone(), (*helper).clone());
    tauri::async_runtime::spawn_blocking(move || {
        let before = afklink_core::lock(&control.config).game_helper;
        let result = helper.set_enabled(enabled, owner);
        // `pc_setting_changed` (`afklink_core::agent_events`): only when the switch really moved
        // (the owner may not confirm the setup, and nothing changes then).
        let after = afklink_core::lock(&control.config).game_helper;
        if after != before {
            afklink_core::agent_events::setting_changed(
                afklink_protocol::metrics::PcSettingKey::GameHelper,
                afklink_protocol::metrics::PcSettingValue::Flag(after),
            );
        }
        result
            .map(|()| game_only::dto(&control, &helper))
            .map_err(Failure::code)
    })
    .await
    .map_err(|e| {
        tracing::warn!("game helper: the switch did not finish: {e}");
        Failure::Failed.code()
    })?
}

/// «Обновить» by «Нужно обновление»: this build's helper in place of another build's, with the
/// launch exe its record names — a learned launcher is not applied with it ([`Ask::Update`]) —
/// through the setup. Errors as [`set_game_helper`].
#[tauri::command]
pub(crate) async fn update_game_helper(
    window: tauri::WebviewWindow,
    control: State<'_, AgentControl>,
    helper: State<'_, GameHelper>,
) -> Result<GameOnlyDto, String> {
    reinstall(window, (*control).clone(), (*helper).clone(), Ask::Update).await
}

/// «Заменить» by «Найден другой файл запуска»: the launcher learned from the game's parent in place
/// of the installed launch exe ([`Ask::ApplyFound`]) — this build's helper with it, as with any
/// setup. Errors as [`set_game_helper`].
#[tauri::command]
pub(crate) async fn apply_found_launch(
    window: tauri::WebviewWindow,
    control: State<'_, AgentControl>,
    helper: State<'_, GameHelper>,
) -> Result<GameOnlyDto, String> {
    reinstall(
        window,
        (*control).clone(),
        (*helper).clone(),
        Ask::ApplyFound,
    )
    .await
}

/// [`update_game_helper`] and [`apply_found_launch`]: [`GameHelper::update`] off the async runtime.
async fn reinstall(
    window: tauri::WebviewWindow,
    control: AgentControl,
    helper: GameHelper,
    ask: Ask,
) -> Result<GameOnlyDto, String> {
    local_window(&window)?;
    let owner = owner_of(&window);
    tauri::async_runtime::spawn_blocking(move || {
        helper
            .update(owner, ask)
            .map(|()| game_only::dto(&control, &helper))
            .map_err(Failure::code)
    })
    .await
    .map_err(|e| {
        tracing::warn!("game helper: {} did not finish: {e}", ask.as_str());
        Failure::Failed.code()
    })?
}

/// «Выбрать» (by «Нужен файл запуска») / «Изменить»: the launch exe, then the setup — which turns
/// the helper on when it is off. Errors as [`set_game_helper`].
#[tauri::command]
pub(crate) async fn choose_game_launch(
    window: tauri::WebviewWindow,
    control: State<'_, AgentControl>,
    helper: State<'_, GameHelper>,
    locale: State<'_, Locale>,
) -> Result<GameOnlyDto, String> {
    local_window(&window)?;
    let owner = owner_of(&window);
    let locale = *locale;
    let (control, helper) = ((*control).clone(), (*helper).clone());
    tauri::async_runtime::spawn_blocking(move || {
        let before = afklink_core::lock(&control.config).game_helper;
        let result = helper.choose_launch(owner, locale);
        // The setup turns the helper on when it was off: the switch moved, by the owner's choice.
        let after = afklink_core::lock(&control.config).game_helper;
        if after != before {
            afklink_core::agent_events::setting_changed(
                afklink_protocol::metrics::PcSettingKey::GameHelper,
                afklink_protocol::metrics::PcSettingValue::Flag(after),
            );
        }
        result
            .map(|()| game_only::dto(&control, &helper))
            .map_err(Failure::code)
    })
    .await
    .map_err(|e| {
        tracing::warn!("game helper: the choice of file did not finish: {e}");
        Failure::Failed.code()
    })?
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use afklink_game_helper::{RunLevel, RECORD_FORMAT, STATE_FORMAT};

    use super::*;

    const SHA: &str = "abababababababababababababababababababababababababababababababab";

    fn record() -> Record {
        Record {
            format: RECORD_FORMAT,
            helper_sha256: SHA.into(),
            sid: "S-1-5-21-1-2-3-1001".into(),
            launch_exe: r"D:\Games\Scryde\Scryde\ScrydeGame.exe".into(),
            window_exe: r"D:\Games\Scryde\Scryde\ScrydeGame.bin".into(),
            window_class: "ScrydeGameUnrealWWindowsViewportWindow".into(),
            run_level: RunLevel::Highest,
            run_level_why: "manifest requireAdministrator".into(),
            written_ms: 1,
            task_priority: Some(TASK_PRIORITY),
        }
    }

    fn game() -> GameBinding {
        GameBinding::new(
            r"d:\games\scryde\scryde\ScrydeGame.bin",
            "ScrydeGameUnrealWWindowsViewportWindow",
        )
    }

    fn installed() -> Installed {
        Installed {
            record: Some(record()),
            record_error: None,
            task: Some(TaskSeen::Present { running: true }),
        }
    }

    const LAUNCH: Option<&str> = Some(r"D:\Games\Scryde\Scryde\ScrydeGame.exe");

    fn wanted(exe: Option<&str>, from: LaunchFrom, helper_on: bool) -> Wanted {
        Wanted {
            exe: exe.map(str::to_string),
            from: exe.map(|_| from),
            helper_on,
        }
    }

    /// The launch exe as guessed by name, the helper on.
    fn guessed(exe: Option<&str>) -> Wanted {
        wanted(exe, LaunchFrom::Guessed, true)
    }

    /// A second launch of the exe while one runs: everything `run` does before the
    /// single-instance plugin hands it over runs in that second process too, and `GameHelper::start`
    /// there would reset the running instance's signal — its helper would stop reviving and
    /// focusing the game under a live «Только игра» session. So the helper is started once only,
    /// in `setup` (which Tauri runs after `build` has initialised the plugins and the lock has
    /// ended a second launch), first thing there — before the window is fitted and the tray
    /// built — and never managed on the builder. `start` taking `&tauri::App` keeps it out of
    /// `run`; this keeps the order. The kernel's half: `system::tests` (a set signal stays set
    /// unless one is made over it).
    #[test]
    fn the_signal_is_made_only_past_the_single_instance_lock() {
        // Code only: comments may name these calls freely.
        let lib = include_str!("lib.rs")
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let at = |needle: &str| {
            let found: Vec<usize> = lib.match_indices(needle).map(|(at, _)| at).collect();
            assert_eq!(found.len(), 1, "`{needle}` once in lib.rs: {found:?}");
            found[0]
        };
        let probe = at("instance_probe::check_or_exit(");
        let lock = at(".plugin(tauri_plugin_single_instance::init(");
        let setup = at(".setup(move |app|");
        let start = at("GameHelper::start(");
        let fit = at("window_fit::fit_main_window(");
        let tray = setup
            + lib[setup..]
                .find("MenuItem::with_id(")
                .expect("the tray's menu built in setup");
        assert!(
            probe < lock && lock < setup,
            "probe {probe}, lock {lock}, setup {setup}"
        );
        assert!(
            setup < start && start < fit && start < tray,
            "the helper started first in setup: setup {setup}, start {start}, fit {fit}, tray {tray}"
        );
        assert!(
            !lib.contains(".manage(game_helper)"),
            "never managed on the builder, before the lock"
        );
    }

    #[test]
    fn the_installation_matches_only_the_game_and_the_launch_exe() {
        let g = game();
        assert_eq!(
            mismatch(&installed(), Some(&g), &guessed(LAUNCH), None),
            None
        );
        assert_eq!(
            mismatch(
                &installed(),
                Some(&g),
                &guessed(LAUNCH),
                Some(HelperState::Running)
            ),
            None
        );
        assert_eq!(
            mismatch(&Installed::default(), Some(&g), &guessed(LAUNCH), None),
            Some(Mismatch::NotInstalled)
        );
        // A record this app cannot read (another format, broken) is no installation.
        let unreadable = Installed {
            record: None,
            record_error: Some("record.json has format 2, this build reads 1".into()),
            ..installed()
        };
        assert_eq!(
            mismatch(&unreadable, Some(&g), &guessed(LAUNCH), None),
            Some(Mismatch::NotInstalled)
        );
        let no_task = Installed {
            task: Some(TaskSeen::Absent),
            ..installed()
        };
        assert_eq!(
            mismatch(&no_task, Some(&g), &guessed(LAUNCH), None),
            Some(Mismatch::NotInstalled)
        );
        // A task that could not be read is not held against it.
        let unread = Installed {
            task: None,
            ..installed()
        };
        assert_eq!(mismatch(&unread, Some(&g), &guessed(LAUNCH), None), None);
        let other = GameBinding::new(r"C:\Other\game.exe", "Window");
        assert_eq!(
            mismatch(&installed(), Some(&other), &guessed(LAUNCH), None),
            Some(Mismatch::Game)
        );
        let other_class = GameBinding::new(&g.exe_path, "NSplashWnd");
        assert_eq!(
            mismatch(&installed(), Some(&other_class), &guessed(LAUNCH), None),
            Some(Mismatch::Game)
        );
        assert_eq!(
            mismatch(&installed(), None, &guessed(LAUNCH), None),
            Some(Mismatch::Game)
        );
        assert_eq!(
            mismatch(
                &installed(),
                Some(&g),
                &guessed(Some(r"D:\Other.exe")),
                None
            ),
            Some(Mismatch::Launch)
        );
        assert_eq!(
            mismatch(&installed(), Some(&g), &guessed(None), None),
            Some(Mismatch::Launch)
        );
        assert_eq!(
            mismatch(
                &installed(),
                Some(&g),
                &guessed(LAUNCH),
                Some(HelperState::NeedsSetup)
            ),
            Some(Mismatch::NeedsSetup)
        );
    }

    /// A launcher learned while the helper is on does not take the signal off: the installation
    /// with another launch exe still matches, and the learned one is offered. With the helper off,
    /// or a file the owner chose, another launch exe is a mismatch as ever.
    #[test]
    fn a_learned_launcher_is_offered_without_taking_a_working_helper_off() {
        let g = game();
        let learned = Some(r"D:\Games\Scryde\Launcher.exe");
        let on = wanted(learned, LaunchFrom::Learned, true);
        assert_eq!(mismatch(&installed(), Some(&g), &on, None), None);
        assert_eq!(decide(&connected(1, 1), true, true, None), Ok(()));
        assert_eq!(
            found_launch(&installed(), &on).as_deref(),
            Some(r"D:\Games\Scryde\Launcher.exe")
        );
        // Learned the same as installed: nothing to offer.
        let same = wanted(LAUNCH, LaunchFrom::Learned, true);
        assert_eq!(mismatch(&installed(), Some(&g), &same, None), None);
        assert_eq!(found_launch(&installed(), &same), None);
        // The helper off: turning it on installs the learned one.
        let off = wanted(learned, LaunchFrom::Learned, false);
        assert_eq!(
            mismatch(&installed(), Some(&g), &off, None),
            Some(Mismatch::Launch)
        );
        assert_eq!(found_launch(&installed(), &off), None);
        // The owner's choice is held to as before.
        let chosen = wanted(learned, LaunchFrom::Chosen, true);
        assert_eq!(
            mismatch(&installed(), Some(&g), &chosen, None),
            Some(Mismatch::Launch)
        );
        assert_eq!(found_launch(&installed(), &chosen), None);
        // Nothing installed: nothing to keep, nothing to offer.
        assert_eq!(
            mismatch(&Installed::default(), Some(&g), &on, None),
            Some(Mismatch::NotInstalled)
        );
        assert_eq!(found_launch(&Installed::default(), &on), None);
        // Another game is another game, learned or not.
        let other = GameBinding::new(r"C:\Other\game.exe", "Window");
        assert_eq!(
            mismatch(&installed(), Some(&other), &on, None),
            Some(Mismatch::Game)
        );
    }

    /// Each button installs its own launch exe: «Обновить» the one the record
    /// names, a learned launcher not applied with it; «Заменить» the learned one; the switch none
    /// over a matching installation. Over one that does not match, each is «Разрешить»: what the
    /// settings want.
    #[test]
    fn each_button_installs_its_own_launch_exe() {
        let learned = r"D:\Games\Scryde\Launcher.exe";
        let fit = |installed: Installed, mismatch, found: Option<&str>, other_build| Fit {
            installed,
            wanted: wanted(Some(learned), LaunchFrom::Learned, true),
            mismatch,
            found: found.map(str::to_string),
            other_build,
        };
        let launch = |p: Plan| match p {
            Plan::Setup { launch, .. } => Some(launch),
            Plan::Ready(_) => None,
        };
        // What each of [the switch, «Обновить», «Заменить»] installs; `None`: no setup.
        let run = |f: &Fit| {
            [Ask::Switch, Ask::Update, Ask::ApplyFound].map(|ask| launch(plan(ask, f, learned)))
        };
        let kept = LAUNCH.map(str::to_string);
        let found = Some(learned.to_string());
        // Another build's helper and a launcher found: the update keeps the installed file.
        assert_eq!(
            run(&fit(installed(), None, Some(learned), true)),
            [None, kept.clone(), found.clone()]
        );
        // This build's: nothing to update; the found file is applied.
        assert_eq!(
            run(&fit(installed(), None, Some(learned), false)),
            [None, None, found.clone()]
        );
        // Another build's, nothing found: nothing to apply.
        assert_eq!(run(&fit(installed(), None, None, true)), [None, kept, None]);
        // Nothing differs: no setup, whatever is pressed.
        assert_eq!(
            run(&fit(installed(), None, None, false)),
            [None, None, None]
        );
        // Not matching — another game or file, 740, no record (or none readable): the helper as
        // the settings want it, whatever was pressed.
        let wanted_by_all = [found.clone(), found.clone(), found.clone()];
        for m in [
            Mismatch::NotInstalled,
            Mismatch::Game,
            Mismatch::Launch,
            Mismatch::NeedsSetup,
        ] {
            assert_eq!(
                run(&fit(installed(), Some(m), None, true)),
                wanted_by_all,
                "{m:?}"
            );
        }
        let nothing = fit(
            Installed::default(),
            Some(Mismatch::NotInstalled),
            None,
            false,
        );
        assert_eq!(run(&nothing), wanted_by_all);
    }

    fn seen(path: &str, started: u64) -> ProcessSeen {
        ProcessSeen {
            path: path.into(),
            started,
            session: 1,
            alive: true,
        }
    }

    /// The game's parent is its launcher only when it is alive, older than the game, an `.exe` in
    /// the game's folder or one above it — not Explorer, a platform's client, AFKLink, a drive's
    /// root, or a process that took a dead parent's id.
    #[test]
    fn the_games_parent_is_learned_only_as_its_own_launcher() {
        let bin = r"D:\Games\Scryde\Scryde\ScrydeGame.bin";
        let game = seen(bin, 2_000);
        let parent = |path: &str| Ok(seen(path, 1_000));
        // The same folder: Scryde's loader.
        assert_eq!(
            launcher_of(
                bin,
                &game,
                &parent(r"d:\games\scryde\scryde\ScrydeGame.exe")
            ),
            Ok(r"d:\games\scryde\scryde\ScrydeGame.exe".to_string())
        );
        // A folder above: a launcher at the game's root, the binary deeper.
        let shipping = r"D:\Games\X\X\Binaries\Win64\X-Win64-Shipping.exe";
        assert_eq!(
            launcher_of(
                shipping,
                &seen(shipping, 2_000),
                &parent(r"D:\Games\X\Launcher.exe")
            ),
            Ok(r"D:\Games\X\Launcher.exe".to_string())
        );
        let refused = |path: &str, game: &ProcessSeen, parent: &Result<ProcessSeen, String>| {
            launcher_of(path, game, parent).unwrap_err()
        };
        // Explorer, a console, another program's folder.
        for other in [
            r"C:\Windows\explorer.exe",
            r"C:\Windows\System32\cmd.exe",
            r"D:\Tools\run.exe",
            r"D:\Games\Other\Launcher.exe",
        ] {
            assert!(
                refused(bin, &game, &parent(other)).contains("outside the game's folder"),
                "{other}"
            );
        }
        // Steam's folder holds its games: refused by name.
        let steam_game = r"C:\Program Files (x86)\Steam\steamapps\common\G\g.exe";
        assert!(refused(
            steam_game,
            &seen(steam_game, 2_000),
            &parent(r"C:\Program Files (x86)\Steam\steam.exe")
        )
        .contains("game platform's client"));
        // AFKLink's own — the helper launches from Program Files, but not even beside the game.
        assert!(refused(bin, &game, &parent(r"D:\Games\Scryde\AFKLink.exe")).contains("AFKLink"));
        assert!(refused(
            bin,
            &game,
            &parent(r"C:\Program Files\AFKLink\GameHelper\S-1-5-21-1\afklink-game-helper.exe")
        )
        .contains("AFKLink"));
        // A drive's root is above every game on it: not a launcher's place.
        assert!(refused(bin, &game, &parent(r"D:\launcher.exe")).contains("outside"));
        // The game's own exe (a game restarting itself), and something not an .exe.
        let own = r"D:\Games\Plain\game.exe";
        assert!(refused(own, &seen(own, 2_000), &parent(own)).contains("the game's own exe"));
        assert!(refused(bin, &game, &parent(r"D:\Games\Scryde\run.com")).contains("not an .exe"));
        // The parent's id reused: the process there now started after the game.
        assert!(refused(
            bin,
            &game,
            &Ok(seen(r"D:\Games\Scryde\Scryde\ScrydeGame.exe", 3_000))
        )
        .contains("started after the game"));
        // The parent has exited — still open somewhere, or gone altogether.
        let dead = ProcessSeen {
            alive: false,
            ..seen(r"D:\Games\Scryde\Scryde\ScrydeGame.exe", 1_000)
        };
        assert!(refused(bin, &game, &Ok(dead)).contains("has exited"));
        assert!(refused(
            bin,
            &game,
            &Err("pid 7 not opened: invalid parameter".into())
        )
        .contains("not read"));
    }

    /// The launch exe: the owner's choice, else the one learned, else the guess beside the game.
    #[test]
    fn the_launch_exe_is_the_owners_choice_then_the_learned_one_then_the_guess() {
        let dir = std::env::temp_dir().join(format!("afklink-launch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("Game.bin");
        std::fs::write(&bin, b"fixture, never run").unwrap();
        std::fs::write(dir.join("Game.exe"), b"fixture, never run").unwrap();
        let mut config = Config::load_or_create_at(dir.join("config.json")).unwrap();
        config.game = Some(GameBinding::new(&bin.to_string_lossy(), "Window"));
        assert_eq!(Wanted::of(&config).from, Some(LaunchFrom::Guessed));
        config.game_launch_learned = Some(r"D:\Learned\Launcher.exe".into());
        let w = Wanted::of(&config);
        assert_eq!(
            (w.exe.as_deref(), w.from),
            (Some(r"D:\Learned\Launcher.exe"), Some(LaunchFrom::Learned))
        );
        config.game_launch_exe = Some(r"D:\Chosen\Run.exe".into());
        let w = Wanted::of(&config);
        assert_eq!(
            (w.exe.as_deref(), w.from),
            (Some(r"D:\Chosen\Run.exe"), Some(LaunchFrom::Chosen))
        );
        assert_eq!(launch_for(&config).as_deref(), Some(r"D:\Chosen\Run.exe"));
        // No game: nothing, whatever is stored.
        config.game = None;
        assert_eq!(Wanted::of(&config).exe, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// After the app updated itself the installed helper is another build's: it is offered for an
    /// update, and — its record matching — it still gets the signal during a session.
    #[test]
    fn another_builds_helper_is_offered_an_update_and_works_on() {
        let g = game();
        let other_build = &"cd".repeat(32);
        assert!(!outdated(&installed(), SHA));
        assert!(!outdated(&installed(), &SHA.to_uppercase()));
        assert!(outdated(&installed(), other_build));
        assert!(!outdated(&Installed::default(), other_build));
        let matching = mismatch(&installed(), Some(&g), &guessed(LAUNCH), None);
        assert_eq!(matching, None);
        assert_eq!(decide(&connected(1, 1), true, true, matching), Ok(()));
        // Anything else that differs still takes the signal off, whatever the build.
        let other = GameBinding::new(r"C:\Other\game.exe", "Window");
        let differs = mismatch(&installed(), Some(&other), &guessed(LAUNCH), None);
        assert!(decide(&connected(1, 1), true, true, differs).is_err());
    }

    /// An older setup registered the task at Task Scheduler's default priority 7 (below
    /// normal): its record has no priority, and the installation is outdated — Settings asks for
    /// the update («Нужно обновление» → «Обновить», Windows' prompt) while the helper works on, as
    /// for another build's. So is a record naming another priority. Each says why.
    #[test]
    fn a_task_registered_below_normal_is_offered_the_update_and_works_on() {
        let old = Installed {
            record: Some(Record {
                task_priority: None,
                ..record()
            }),
            ..installed()
        };
        assert!(outdated(&old, SHA));
        let why = outdated_why(&old, SHA).unwrap();
        assert!(
            why.contains("an older setup") && why.contains("priority 7"),
            "{why}"
        );
        assert!(!why.contains("another build's"), "the same build: {why}");
        let other = Installed {
            record: Some(Record {
                task_priority: Some(7),
                ..record()
            }),
            ..installed()
        };
        assert!(outdated_why(&other, SHA).is_some_and(|w| w.contains("priority 7")));
        // Both at once: both said.
        let both = outdated_why(&old, &"cd".repeat(32)).unwrap();
        assert!(
            both.contains("another build's") && both.contains("an older setup"),
            "{both}"
        );
        // This build's, at this build's priority: up to date.
        assert_eq!(outdated_why(&installed(), SHA), None);
        // It works on: the signal does not count it.
        let matching = mismatch(&old, Some(&game()), &guessed(LAUNCH), None);
        assert_eq!(matching, None);
        assert_eq!(decide(&connected(1, 1), true, true, matching), Ok(()));
        // «Обновить» runs the setup, with the launch exe its record names.
        let fit = Fit {
            installed: old,
            wanted: guessed(LAUNCH),
            mismatch: None,
            found: None,
            other_build: true,
        };
        assert!(matches!(
            plan(Ask::Update, &fit, LAUNCH.unwrap()),
            Plan::Setup { launch, .. } if Some(launch.as_str()) == LAUNCH
        ));
    }

    /// `n` connected sessions in game-only, of `live`.
    fn connected(n: usize, live: usize) -> HelperSessions {
        HelperSessions {
            live,
            connected: live,
            game_only: (0..n).map(|i| format!("s{i}")).collect(),
            game_only_connecting: Vec::new(),
        }
    }

    #[test]
    fn the_signal_needs_a_session_the_mode_the_switch_and_a_matching_installation() {
        assert_eq!(decide(&connected(1, 1), true, true, None), Ok(()));
        assert_eq!(decide(&connected(2, 2), true, true, None), Ok(()));
        let no = |r: Result<(), String>| r.unwrap_err();
        let one = connected(1, 1);
        assert!(no(decide(&connected(0, 0), true, true, None)).contains("no live session"));
        assert!(no(decide(&one, false, true, None)).contains("«Только игра» is off"));
        assert!(no(decide(&one, true, false, None)).contains("off in Settings"));
        assert!(no(decide(&one, true, true, Some(Mismatch::Game))).contains("another game"));
        assert!(no(decide(&one, true, true, Some(Mismatch::Launch))).contains("launch exe"));
        assert!(
            no(decide(&one, true, true, Some(Mismatch::NotInstalled))).contains("not installed")
        );
        assert!(
            no(decide(&one, true, true, Some(Mismatch::NeedsSetup))).contains("asks for the setup")
        );
    }

    /// «Только для гостей»: the helper acts only for sessions game-only applies to. The owner's own
    /// session, with the whole desktop, never lets it launch or bring back the game; a guest's
    /// beside it does.
    #[test]
    fn the_signal_waits_for_a_session_in_game_only() {
        let no = |r: Result<(), String>| r.unwrap_err();
        // Only the owner is connected, with the whole desktop.
        let owner_only = no(decide(&connected(0, 1), true, true, None));
        assert!(
            owner_only.contains("no live session in game-only"),
            "{owner_only}"
        );
        assert!(owner_only.contains("«Только для гостей»"), "{owner_only}");
        // A guest's session beside the owner's: the helper acts.
        assert_eq!(decide(&connected(1, 2), true, true, None), Ok(()));
    }

    /// A session in game-only acts on the game only once it has
    /// connected — requested and still connecting (or never connecting), it does not; the reason
    /// says so, with the counts from the same look.
    #[test]
    fn the_signal_waits_for_the_session_to_connect() {
        let connecting = HelperSessions {
            live: 2,
            connected: 1,
            game_only: Vec::new(),
            game_only_connecting: vec!["guest".to_string()],
        };
        let why = decide(&connecting, true, true, None).unwrap_err();
        assert!(
            why.contains("no connected session in game-only yet")
                && why.contains("1 still connecting")
                && why.contains("1 of 2 live connected"),
            "{why}"
        );
        let connected_now = HelperSessions {
            connected: 2,
            game_only: vec!["guest".to_string()],
            game_only_connecting: Vec::new(),
            ..connecting
        };
        assert_eq!(decide(&connected_now, true, true, None), Ok(()));
    }

    #[test]
    fn only_a_fresh_state_is_shown() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let at = |secs_ago: u64, state: HelperState| StateFile {
            format: STATE_FORMAT,
            state,
            reason: String::new(),
            since_ms: 0,
            updated_ms: afklink_game_helper::unix_ms(now) - secs_ago * 1000,
            pid: 1,
            elevated: true,
            launches: 0,
            failed_starts: 0,
            focus_set_foreground: 0,
            focus_uia: 0,
            focus_refused: 0,
            launch_pending: false,
            failed_launch_since_ms: None,
        };
        assert_eq!(
            fresh_state(
                vec![at(50, HelperState::Idle), at(5, HelperState::GaveUp)],
                now
            )
            .map(|s| s.state),
            Some(HelperState::GaveUp)
        );
        assert_eq!(fresh_state(vec![at(600, HelperState::Running)], now), None);
        assert_eq!(fresh_state(Vec::new(), now), None);
    }

    /// «Игра не запускается» goes by the helper's failed-launch mark, which outlives the session
    /// (the helper idle between sessions still has it) — and by `gave_up` for an older helper's
    /// file without the mark; a stale file shows nothing.
    #[test]
    fn the_failed_launch_line_goes_by_the_mark_and_by_an_older_helpers_give_up() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let file = |secs_ago: u64, state: HelperState, mark: Option<u64>| StateFile {
            format: STATE_FORMAT,
            state,
            reason: String::new(),
            since_ms: 0,
            updated_ms: afklink_game_helper::unix_ms(now) - secs_ago * 1000,
            pid: 1,
            elevated: true,
            launches: 0,
            failed_starts: 0,
            focus_set_foreground: 0,
            focus_uia: 0,
            focus_refused: 0,
            launch_pending: false,
            failed_launch_since_ms: mark,
        };
        let shows = |f: StateFile| failed_launch(fresh_state(vec![f], now).as_ref());
        // Between sessions: idle, the mark kept.
        assert!(shows(file(5, HelperState::Idle, Some(1))));
        assert!(shows(file(5, HelperState::GaveUp, Some(1))));
        // Taken off: the game ran.
        assert!(!shows(file(5, HelperState::Running, None)));
        assert!(!shows(file(5, HelperState::Idle, None)));
        // An older helper: no mark, its give-up for the session.
        let mut old = serde_json::to_value(file(5, HelperState::GaveUp, None)).unwrap();
        old.as_object_mut()
            .unwrap()
            .remove("failed_launch_since_ms");
        assert!(shows(StateFile::parse(old.to_string().as_bytes()).unwrap()));
        // A stale file is no helper.
        assert!(!shows(file(600, HelperState::GaveUp, Some(1))));
        assert!(!failed_launch(None));
    }

    /// A stopped helper's task is started again only while the helper is on, a record installed,
    /// the task not known gone and no fresh `state.json`; at most once a minute, less often while it
    /// keeps stopping.
    #[test]
    fn a_stopped_helper_is_started_again_only_when_on_installed_and_stale() {
        let stopped = Installed {
            task: Some(TaskSeen::Present { running: false }),
            ..installed()
        };
        assert!(revive_wanted(true, &stopped, false));
        // Its task not read yet: looked at all the same.
        let unread = Installed {
            task: None,
            ..installed()
        };
        assert!(revive_wanted(true, &unread, false));
        assert!(!revive_wanted(true, &stopped, true), "a fresh state.json");
        assert!(!revive_wanted(false, &stopped, false), "the switch off");
        let no_task = Installed {
            task: Some(TaskSeen::Absent),
            ..installed()
        };
        assert!(!revive_wanted(true, &no_task, false));
        assert!(!revive_wanted(true, &Installed::default(), false));
        let unreadable = Installed {
            record: None,
            record_error: Some("record.json unreadable".into()),
            ..stopped
        };
        assert!(!revive_wanted(true, &unreadable, false));
        assert_eq!(revive_delay(0), Duration::from_secs(60));
        assert_eq!(revive_delay(1), Duration::from_secs(120));
        assert_eq!(revive_delay(3), Duration::from_secs(480));
        assert_eq!(revive_delay(4), REVIVE_MAX);
        assert_eq!(revive_delay(40), REVIVE_MAX);
    }

    /// The viewer hears «Игра запускается» only while the signal is on and a fresh `state.json`
    /// says a launch of the helper's waits for the window; a stale file, or an older helper's
    /// without the field, says nothing of the kind.
    #[test]
    fn the_sessions_are_told_of_a_launch_only_from_a_fresh_state_while_the_signal_is_on() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let file = |secs_ago: u64, launch_pending: bool| StateFile {
            format: STATE_FORMAT,
            state: HelperState::Launching,
            reason: "launched; its process not seen yet".into(),
            since_ms: 0,
            updated_ms: afklink_game_helper::unix_ms(now) - secs_ago * 1000,
            pid: 1,
            elevated: true,
            launches: 1,
            failed_starts: 0,
            focus_set_foreground: 0,
            focus_uia: 0,
            focus_refused: 0,
            launch_pending,
            failed_launch_since_ms: None,
        };
        let pending = fresh_state(vec![file(1, true)], now);
        assert!(launching(true, pending.as_ref()));
        assert!(launching_why(true, "1 live session(s)", pending.as_ref())
            .contains("a launch of its own waits for the game's window (launching: launched"));
        // The signal off: the helper does nothing, whatever its file still says.
        assert!(!launching(false, pending.as_ref()));
        assert!(launching_why(false, "no live session", pending.as_ref())
            .contains("signal is off: no live session"));
        // Not pending, stale, none.
        let done = fresh_state(vec![file(1, false)], now);
        assert!(!launching(true, done.as_ref()));
        assert!(launching_why(true, "", done.as_ref()).contains("no launch of its own"));
        let stale = fresh_state(vec![file(600, true)], now);
        assert!(!launching(true, stale.as_ref()));
        assert!(launching_why(true, "", stale.as_ref()).contains("no fresh state.json"));
        // An older helper's file: no `launch_pending` at all.
        let mut old = serde_json::to_value(file(1, true)).unwrap();
        old.as_object_mut().unwrap().remove("launch_pending");
        let old = StateFile::parse(old.to_string().as_bytes()).unwrap();
        assert!(!launching(true, Some(&old)));
    }

    #[test]
    fn a_setup_outcome_tells_cancel_missing_file_and_failure_apart() {
        assert_eq!(outcome_of(Some(setup::Exit::Done)), Outcome::Done);
        assert_eq!(
            outcome_of(Some(setup::Exit::NotFound)),
            Outcome::Failed(Failure::NotFound)
        );
        assert_eq!(
            outcome_of(Some(setup::Exit::Scheduler)),
            Outcome::Failed(Failure::Failed)
        );
        assert_eq!(outcome_of(None), Outcome::Failed(Failure::Failed));
        assert_eq!(Failure::NotFound.code(), "not_found");
        assert_eq!(Failure::Failed.code(), "failed");
    }

    #[test]
    fn windows_arguments_keep_spaces_unicode_quotes_and_trailing_slashes() {
        assert_eq!(
            quote_arg(r"C:\Users\Иван Петров\game.exe"),
            "\"C:\\Users\\Иван Петров\\game.exe\""
        );
        assert_eq!(quote_arg("a\"b\\"), "\"a\\\"b\\\\\"");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg(r"C:\dir\"), "\"C:\\dir\\\\\"");
    }

    #[test]
    fn the_launch_exe_is_the_owners_choice_else_the_default() {
        let dir = std::env::temp_dir().join(format!("afklink-launch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("Game.bin");
        let exe = dir.join("Game.exe");
        std::fs::write(&bin, b"fixture, never run").unwrap();
        let mut config = Config::load_or_create_at(dir.join("config.json")).unwrap();
        config.game = Some(GameBinding::new(&bin.to_string_lossy(), "Window"));
        assert_eq!(launch_for(&config), None, "no .exe beside the .bin");
        std::fs::write(&exe, b"fixture, never run").unwrap();
        assert_eq!(
            launch_for(&config),
            Some(exe.to_string_lossy().into_owned())
        );
        config.game_launch_exe = Some(r"D:\Chosen\Launcher.exe".into());
        assert_eq!(
            launch_for(&config).as_deref(),
            Some(r"D:\Chosen\Launcher.exe")
        );
        config.game = None;
        assert_eq!(launch_for(&config), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The mirror: on its first look only recent lines, then each new line once, across a rotation.
    #[test]
    fn the_mirror_reads_each_new_line_once_across_a_rotation() {
        let dir = std::env::temp_dir().join(format!("afklink-mirror-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join(LOG_FILE);
        std::fs::write(
            &log,
            "2020-01-01T00:00:00.000Z INFO helper: old\n2026-10-02T10:00:00.000Z INFO helper: recent\n",
        )
        .unwrap();
        let mut tail = Tail::new(
            &dir,
            LOG_FILE,
            LOG_OLD_FILE,
            "2026-01-01T00:00:00.000Z".into(),
        );
        assert_eq!(
            tail.read().unwrap(),
            vec!["2026-10-02T10:00:00.000Z INFO helper: recent".to_string()]
        );
        assert!(tail.read().unwrap().is_empty());
        // A half-written line waits for its end.
        let mut text = std::fs::read_to_string(&log).unwrap();
        text.push_str(
            "2026-10-02T10:00:01.000Z INFO helper: next\n2026-10-02T10:00:02.000Z INFO hel",
        );
        std::fs::write(&log, &text).unwrap();
        assert_eq!(tail.read().unwrap().len(), 1);
        // Rotated: the old file's rest, then the new file.
        text.push_str("per: rest\n");
        std::fs::write(dir.join(LOG_OLD_FILE), &text).unwrap();
        std::fs::write(&log, "2026-10-02T10:00:03.000Z INFO setup: new\n").unwrap();
        assert_eq!(
            tail.read().unwrap(),
            vec![
                "2026-10-02T10:00:02.000Z INFO helper: rest".to_string(),
                "2026-10-02T10:00:03.000Z INFO setup: new".to_string()
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// [`GameHelper`]'s own methods against stand-ins for Task Scheduler and the setup: none of them
    /// may wait for a lock its own thread or another holds (`turn_on` waiting on itself for
    /// `installed`, holding the config, hangs the window on «Установить»).
    #[cfg(windows)]
    mod locks {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::mpsc::{self, RecvTimeoutError};

        use afklink_core::{Agent, Backends, Identity};
        use afklink_game_helper::{RunLevel, RECORD_FORMAT};

        use super::super::*;

        const SID: &str = "S-1-5-21-1-2-3-1001";
        const CLASS: &str = "GameWindowClass";
        /// The game's window exe, an `.exe`: its own launch exe when none is chosen or learned.
        const GAME: &str = r"D:\Games\Test\Game.exe";
        const LEARNED: &str = r"D:\Games\Test\Launcher.exe";
        /// Ample for calls of a few milliseconds each: past it, a thread waits for a lock for good.
        const LIMIT: Duration = Duration::from_secs(10);

        /// Task Scheduler and the elevated setup, stood in for: the task as last set, each setup's
        /// arguments kept, and a setup that does to what the app reads what the real one does — an
        /// install writes this build's record and starts the task, a removal takes both away.
        struct Fake {
            dir: PathBuf,
            task: Mutex<TaskSeen>,
            setups: Mutex<Vec<Vec<String>>>,
            runs: AtomicU32,
        }

        impl Fake {
            fn setups(&self) -> Vec<Vec<String>> {
                lock(&self.setups).clone()
            }
        }

        impl Platform for Fake {
            fn task(&self, _: &str) -> Result<TaskSeen, String> {
                Ok(*lock(&self.task))
            }

            fn run_task(&self, _: &str) -> Result<(), String> {
                self.runs.fetch_add(1, Ordering::SeqCst);
                *lock(&self.task) = TaskSeen::Present { running: true };
                Ok(())
            }

            fn elevate(
                &self,
                args: &[String],
                _: Option<usize>,
                _: Duration,
            ) -> Result<Option<Option<u32>>, String> {
                lock(&self.setups).push(args.to_vec());
                let parsed: Vec<OsString> = args.iter().map(OsString::from).collect();
                let path = self.dir.join(RECORD_FILE);
                let exit = match setup::parse(&parsed) {
                    Some(Ok(setup::Action::Install(install))) => {
                        let record = Record {
                            format: RECORD_FORMAT,
                            helper_sha256: HELPER_SHA256.into(),
                            sid: install.sid,
                            launch_exe: install.launch_exe,
                            window_exe: install.window_exe,
                            window_class: install.window_class,
                            run_level: RunLevel::Lua,
                            run_level_why: "a stand-in setup".into(),
                            written_ms: 2,
                            task_priority: Some(TASK_PRIORITY),
                        };
                        std::fs::write(&path, record.to_json()?).map_err(|e| e.to_string())?;
                        *lock(&self.task) = TaskSeen::Present { running: true };
                        setup::Exit::Done
                    }
                    Some(Ok(setup::Action::Remove { .. })) => {
                        match std::fs::remove_file(&path) {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => return Err(e.to_string()),
                        }
                        *lock(&self.task) = TaskSeen::Absent;
                        setup::Exit::Done
                    }
                    _ => setup::Exit::Arguments,
                };
                Ok(Some(Some(u32::try_from(exit.code()).unwrap())))
            }
        }

        struct Rig {
            helper: GameHelper,
            control: AgentControl,
            fake: Arc<Fake>,
            base: PathBuf,
        }

        impl Drop for Rig {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.base);
            }
        }

        /// A helper over a scratch install directory — `record` there, or none; the task as
        /// `task` — and a config with [`GAME`] bound, as `set` leaves it. Nothing started: no
        /// watch thread, no signal.
        fn rig(record: Option<Record>, task: TaskSeen, set: impl FnOnce(&mut Config)) -> Rig {
            let base =
                std::env::temp_dir().join(format!("afklink-helper-locks-{}", uuid::Uuid::new_v4()));
            let dir = base.join("install");
            std::fs::create_dir_all(&dir).unwrap();
            if let Some(record) = record {
                std::fs::write(dir.join(RECORD_FILE), record.to_json().unwrap()).unwrap();
            }
            let mut config = Config::load_or_create_at(base.join("config.json")).unwrap();
            config.game = Some(GameBinding::new(GAME, CLASS));
            set(&mut config);
            let identity = Identity::load_or_create_at(base.join("identity.json")).unwrap();
            let backends = Backends {
                make_capturer: Box::new(|| {
                    Err(std::io::Error::other("no capture in a test").into())
                }),
                make_game_capturer: Box::new(|_| {
                    Err(std::io::Error::other("no capture in a test").into())
                }),
                make_encoder: Box::new(
                    || Err(std::io::Error::other("no encoder in a test").into()),
                ),
                injector: Arc::new(afklink_input::SendInputInjector::default()),
            };
            let (_agent, control) = Agent::new(config, Arc::new(identity), backends);
            let fake = Arc::new(Fake {
                dir: dir.clone(),
                task: Mutex::new(task),
                setups: Mutex::default(),
                runs: AtomicU32::new(0),
            });
            let helper =
                GameHelper::new(control.clone(), Ok(SID.into()), Ok(dir), None, fake.clone());
            // The installation read, as the watch thread reads it at the app's start.
            let reader = helper.clone();
            within("the first read", LIMIT, move || {
                reader.refresh("a test's start")
            });
            Rig {
                helper,
                control,
                fake,
                base,
            }
        }

        /// A record for [`GAME`] with `launch`, of the helper build `sha`.
        fn record_of(sha: &str, launch: &str) -> Record {
            Record {
                format: RECORD_FORMAT,
                helper_sha256: sha.into(),
                sid: SID.into(),
                launch_exe: launch.into(),
                window_exe: GAME.into(),
                window_class: CLASS.into(),
                run_level: RunLevel::Lua,
                run_level_why: "a test's".into(),
                written_ms: 1,
                task_priority: Some(TASK_PRIORITY),
            }
        }

        fn another_build() -> String {
            "cd".repeat(32)
        }

        /// `f` on a thread of its own, waited for at most `limit`: a lock that never comes fails the
        /// test instead of hanging the run (the thread stays blocked until the test binary exits).
        fn within<T: Send + 'static>(
            what: &str,
            limit: Duration,
            f: impl FnOnce() -> T + Send + 'static,
        ) -> T {
            let (tx, rx) = mpsc::channel();
            std::thread::Builder::new()
                .name(format!("game helper test: {what}"))
                .spawn(move || {
                    let _ = tx.send(f());
                })
                .unwrap();
            let got = rx.recv_timeout(limit);
            assert!(
                !matches!(got, Err(RecvTimeoutError::Timeout)),
                "{what} did not finish in {} s: it waits for a lock its own thread, or another, \
                 holds",
                limit.as_secs()
            );
            got.expect("the call panicked on its thread")
        }

        fn dto(rig: &Rig) -> HelperDto {
            let helper = rig.helper.clone();
            within("dto", LIMIT, move || helper.dto())
        }

        /// The switch on over an installation that matches — this build's, the same launch exe:
        /// no prompt, its stopped task started, and the call returns. «Обновить» and «Заменить»
        /// there (nothing to update, nothing to apply) are the same.
        #[test]
        fn turning_on_over_a_matching_installation_returns_without_a_prompt() {
            let rig = rig(
                Some(record_of(HELPER_SHA256, GAME)),
                TaskSeen::Present { running: false },
                |c| c.game_helper = false,
            );
            let helper = rig.helper.clone();
            assert_eq!(
                within("set_enabled(true)", LIMIT, move || helper
                    .set_enabled(true, None)),
                Ok(())
            );
            assert!(
                rig.fake.setups().is_empty(),
                "no prompt over a matching installation"
            );
            assert_eq!(
                rig.fake.runs.load(Ordering::SeqCst),
                1,
                "its stopped task started"
            );
            assert!(lock(&rig.control.config).game_helper);
            let shown = dto(&rig);
            assert!(
                shown.enabled && shown.installed && !shown.outdated,
                "{shown:?}"
            );
            assert_eq!((shown.mismatch, shown.found_launch), (None, None));
            for ask in [Ask::Update, Ask::ApplyFound] {
                let helper = rig.helper.clone();
                assert_eq!(
                    within("update", LIMIT, move || helper.update(None, ask)),
                    Ok(()),
                    "{ask:?}"
                );
            }
            assert!(
                rig.fake.setups().is_empty(),
                "nothing to update, nothing to apply"
            );
        }

        /// «Нужно обновление» → «Обновить»: another build's helper, its record matching, is
        /// replaced by this build's through the setup — by `update`, and by `turn_on` asked to.
        #[test]
        fn another_builds_helper_is_replaced_through_the_setup() {
            for by_update in [true, false] {
                // The task's description goes in the window's language: the setting's.
                let lang = if by_update { "ru" } else { "en" };
                let rig = rig(
                    Some(record_of(&another_build(), GAME)),
                    TaskSeen::Present { running: true },
                    |c| {
                        c.game_helper = true;
                        c.lang = lang.into();
                    },
                );
                let shown = dto(&rig);
                assert!(shown.outdated && shown.mismatch.is_none(), "{shown:?}");
                let helper = rig.helper.clone();
                let done = within("update", LIMIT, move || {
                    if by_update {
                        helper.update(None, Ask::Update)
                    } else {
                        helper.turn_on(None, Ask::Update).map(|_| ())
                    }
                });
                assert_eq!(done, Ok(()), "by update: {by_update}");
                let setups = rig.fake.setups();
                assert_eq!(setups.len(), 1, "{setups:?}");
                assert_eq!(setups[0][..2], [setup::SETUP_ARG, "install"]);
                assert_eq!(setups[0][3], GAME);
                assert_eq!(setups[0].last().map(String::as_str), Some(lang));
                let shown = dto(&rig);
                assert!(shown.installed && !shown.outdated, "{shown:?}");
                assert_eq!(shown.mismatch, None);
            }
        }

        /// «Найден другой файл запуска» → «Заменить»: the launcher learned is installed through the
        /// setup in place of the launch exe the record names — this build's helper with it, when
        /// another build's was there.
        #[test]
        fn a_learned_launcher_is_applied_through_the_setup() {
            for sha in [HELPER_SHA256.to_string(), another_build()] {
                let rig = rig(
                    Some(record_of(&sha, GAME)),
                    TaskSeen::Present { running: true },
                    |c| {
                        c.game_helper = true;
                        c.game_launch_learned = Some(LEARNED.into());
                    },
                );
                let shown = dto(&rig);
                assert_eq!(shown.found_launch.as_deref(), Some(LEARNED));
                assert_eq!(
                    (shown.mismatch, shown.outdated),
                    (None, sha != HELPER_SHA256)
                );
                let helper = rig.helper.clone();
                assert_eq!(
                    within("«Заменить»", LIMIT, move || helper
                        .update(None, Ask::ApplyFound)),
                    Ok(())
                );
                let setups = rig.fake.setups();
                assert_eq!(setups.len(), 1, "{setups:?}");
                assert_eq!(setups[0][1], "install");
                assert_eq!(setups[0][3], LEARNED, "the learned launcher installed");
                let shown = dto(&rig);
                assert!(!shown.outdated, "this build's helper with it: {shown:?}");
                assert_eq!((shown.mismatch, shown.found_launch), (None, None));
            }
        }

        /// «Обновить» installs this build's helper with the launch exe the record
        /// names, the learned launcher not applied with it; Settings offers that one after, and
        /// «Заменить» then installs it. Nothing the owner chose or the app learned is changed.
        #[test]
        fn the_update_keeps_the_installed_launch_exe_and_the_found_one_is_offered_after() {
            let rig = rig(
                Some(record_of(&another_build(), GAME)),
                TaskSeen::Present { running: true },
                |c| {
                    c.game_helper = true;
                    c.game_launch_learned = Some(LEARNED.into());
                },
            );
            let shown = dto(&rig);
            assert!(shown.outdated && shown.mismatch.is_none(), "{shown:?}");
            assert_eq!(shown.found_launch.as_deref(), Some(LEARNED));
            let helper = rig.helper.clone();
            assert_eq!(
                within("«Обновить»", LIMIT, move || helper
                    .update(None, Ask::Update)),
                Ok(())
            );
            let setups = rig.fake.setups();
            assert_eq!(setups.len(), 1, "{setups:?}");
            assert_eq!(setups[0][1], "install");
            assert_eq!(
                setups[0][3], GAME,
                "the installed launch exe kept, not the learned one"
            );
            let shown = dto(&rig);
            assert!(!shown.outdated && shown.enabled, "{shown:?}");
            assert_eq!(shown.mismatch, None);
            assert_eq!(
                shown.found_launch.as_deref(),
                Some(LEARNED),
                "the learned launcher offered after the update"
            );
            {
                let config = lock(&rig.control.config);
                assert_eq!(config.game_launch_exe, None);
                assert_eq!(config.game_launch_learned.as_deref(), Some(LEARNED));
            }
            // «Обновить» again: this build's is there, nothing to update.
            let helper = rig.helper.clone();
            assert_eq!(
                within("«Обновить» again", LIMIT, move || helper
                    .update(None, Ask::Update)),
                Ok(())
            );
            assert_eq!(rig.fake.setups().len(), 1);
            // Then «Заменить».
            let helper = rig.helper.clone();
            assert_eq!(
                within("«Заменить»", LIMIT, move || helper
                    .update(None, Ask::ApplyFound)),
                Ok(())
            );
            let setups = rig.fake.setups();
            assert_eq!(setups.len(), 2, "{setups:?}");
            assert_eq!(setups[1][3], LEARNED);
            let shown = dto(&rig);
            assert_eq!((shown.mismatch, shown.found_launch), (None, None));
        }

        /// «Обновить» or «Заменить» pressed as the record went (removed, or one this app cannot
        /// read): there is no installed launch exe to keep — each is «Разрешить», the helper as the
        /// settings want it (here the learned launcher).
        #[test]
        fn with_no_record_to_read_either_button_sets_the_helper_up_as_the_settings_want() {
            for ask in [Ask::Update, Ask::ApplyFound] {
                for unreadable in [false, true] {
                    let rig = rig(None, TaskSeen::Present { running: true }, |c| {
                        c.game_helper = true;
                        c.game_launch_learned = Some(LEARNED.into());
                    });
                    if unreadable {
                        std::fs::write(rig.base.join("install").join(RECORD_FILE), b"{ half")
                            .unwrap();
                    }
                    let helper = rig.helper.clone();
                    assert_eq!(
                        within("update", LIMIT, move || helper.update(None, ask)),
                        Ok(()),
                        "{ask:?}, unreadable: {unreadable}"
                    );
                    let setups = rig.fake.setups();
                    assert_eq!(
                        setups.len(),
                        1,
                        "{ask:?}, unreadable: {unreadable}: {setups:?}"
                    );
                    assert_eq!(setups[0][3], LEARNED, "{ask:?}, unreadable: {unreadable}");
                    let shown = dto(&rig);
                    assert!(shown.installed && !shown.outdated, "{shown:?}");
                    assert_eq!((shown.mismatch, shown.found_launch), (None, None));
                }
            }
        }

        /// The watch thread, Settings and changes, all at once, over and over: none waits for
        /// another for good — the locks are taken in one order (`Shared`).
        #[test]
        fn the_watch_settings_and_changes_at_once_never_wait_on_each_other() {
            const ROUNDS: u64 = 40;
            let rig = rig(
                Some(record_of(&another_build(), GAME)),
                TaskSeen::Present { running: false },
                |c| {
                    c.game_helper = true;
                    c.game_only = true;
                },
            );
            let (watch, settings, change) =
                (rig.helper.clone(), rig.helper.clone(), rig.helper.clone());
            let control = rig.control.clone();
            within(
                "the watch, Settings and changes at once",
                3 * LIMIT,
                move || {
                    let start = Instant::now();
                    let threads = [
                        std::thread::spawn(move || {
                            for round in 0..ROUNDS {
                                watch.reread_record();
                                watch.reread_state();
                                // Far enough on that each look may start the task again.
                                watch.revive(start + Duration::from_secs(3600 * (round + 1)));
                                watch.mirror();
                                let launcher = if round % 2 == 0 {
                                    LEARNED
                                } else {
                                    r"D:\Games\Test\Other.exe"
                                };
                                watch.learned(GAME, launcher, 1, 2);
                                watch.evaluate("");
                            }
                        }),
                        std::thread::spawn(move || {
                            for round in 0..ROUNDS {
                                settings.refresh_unless_changing("a test's Settings");
                                let _ = game_only::dto(&control, &settings);
                                let _ = control.set_game_only(round % 2 == 0);
                                settings.evaluate("a test's game-only switch");
                            }
                        }),
                        std::thread::spawn(move || {
                            for round in 0..ROUNDS {
                                let _ = match round % 4 {
                                    0 => change.update(None, Ask::Update),
                                    1 => change.update(None, Ask::ApplyFound),
                                    2 => change.set_enabled(false, None),
                                    _ => change.set_enabled(true, None),
                                };
                            }
                        }),
                    ];
                    for thread in threads {
                        thread.join().unwrap();
                    }
                },
            );
            let setups = rig.fake.setups();
            assert!(
                setups.iter().any(|a| a[1] == "install") && setups.iter().any(|a| a[1] == "remove"),
                "the changes went through the setup both ways: {setups:?}"
            );
        }
    }
}
