//! Settings → «only the game window» (`afklink_core::game`): the switch, the bound game, and the
//! picker's list of windows.
//!
//! The only way the mode or the game changes: these commands, from this app's own window on this PC.
//! Nothing the backend or a viewer sends reaches them. A change is in force at once — a live session
//! switches its capture within a tenth of a second (`afklink_core::pipeline::Supervisor`) — and is
//! saved to config.json.
//!
//! «Только для гостей» (`set_game_only_for_guests`) narrows the mode to guests' sessions: whose
//! session is whose is the role the server gave each viewer's binding, decided per session in
//! `afklink_core::game_access` — never anything the viewer says.
//!
//! No command forgets the game: a «Сбросить» would have no use of its own — another game is chosen
//! over the bound one, the whole screen again is the mode's switch — and all it could add is the
//! mode on without a game, black for the viewer. The game stays bound while the mode is
//! off. (`AgentControl::set_game_binding` still takes `None`: the core's API, not this window's.)

use serde::Serialize;
use tauri::State;

use afklink_core::game::GameBinding;
use afklink_core::AgentControl;

use crate::fakerinput_setup::{DriverRead, DriverState};
use crate::game_helper::{GameHelper, HelperDto};
use crate::log_route::SYSTEM_TARGET;

/// The bound game, as the window shows it.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct GameDto {
    exe_path: String,
    /// The exe's file name: what the window shows for the game.
    exe_name: String,
    window_class: String,
}

/// The section's state.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct GameOnlyDto {
    /// The mode is on: every session it applies to shows the game's window only (black while it
    /// cannot be shown), never the desktop.
    enabled: bool,
    /// «Только для гостей» (`Config::game_only_for_guests`): the mode applies to guests' sessions
    /// only, the owner's get the whole desktop (`afklink_core::game_access`).
    for_guests: bool,
    /// The bound game; `None` with the mode on is black frames only.
    game: Option<GameDto>,
    /// «Запускать игру автоматически» (`game_helper`).
    helper: HelperDto,
}

/// A window the picker offers.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct GameWindowDto {
    exe_path: String,
    exe_name: String,
    window_class: String,
    /// For the picker only: the title is not what the game is bound on (it changes in game).
    title: String,
    /// Its program runs as administrator and this agent does not, and the driver is missing (not
    /// installed, or not working): controls will not reach it — «Нужен драйвер» beside it, until
    /// the driver is installed.
    needs_driver: bool,
}

/// Where in the window a change came from, for the log: the main view's «Только игра» row
/// (`home`) or Settings (`settings`, also when the window does not say).
fn origin(from: Option<&str>) -> &'static str {
    match from {
        Some("home") => "the main view",
        _ => "Settings",
    }
}

pub(crate) fn dto(control: &AgentControl, helper: &GameHelper) -> GameOnlyDto {
    let (enabled, game) = control.game_only();
    GameOnlyDto {
        enabled,
        for_guests: control.game_only_for_guests(),
        game: game.map(|g| GameDto {
            exe_name: g.shown_name().to_string(),
            exe_path: g.exe_path,
            window_class: g.window_class,
        }),
        helper: helper.dto(),
    }
}

/// The section's state, read when Settings opens — with the game helper's installation read again
/// from disk and Task Scheduler (logged), off the window's thread; while a helper change is running,
/// as last read (`GameHelper::refresh_unless_changing`).
#[tauri::command]
pub async fn get_game_only(
    control: State<'_, AgentControl>,
    helper: State<'_, GameHelper>,
) -> Result<GameOnlyDto, String> {
    let (control, helper) = ((*control).clone(), (*helper).clone());
    tauri::async_runtime::spawn_blocking(move || {
        helper.refresh_unless_changing("Settings opened");
        dto(&control, &helper)
    })
    .await
    .map_err(|e| {
        tracing::warn!(target: SYSTEM_TARGET, "game-only state not read: {e}");
        e.to_string()
    })
}

/// The switch — in Settings, or on the main view's row (`from`: `home`). Answers with the state in
/// force — also when the save failed (the change is in force for this run, and the error is in the
/// log).
#[tauri::command]
pub fn set_game_only(
    control: State<'_, AgentControl>,
    helper: State<'_, GameHelper>,
    enabled: bool,
    from: Option<String>,
) -> GameOnlyDto {
    let origin = origin(from.as_deref());
    tracing::info!(target: SYSTEM_TARGET, enabled, origin, "game-only switched");
    if let Err(e) = control.set_game_only(enabled) {
        tracing::warn!(target: SYSTEM_TARGET, enabled, "game-only switch not saved: {e:#}");
    }
    helper.evaluate("game-only switched");
    dto(&control, &helper)
}

/// «Только для гостей» (Settings only: the main view has no switch for it). In force at once — every
/// live session is decided again by its viewer's role (`afklink_core::game_access`) — and saved;
/// answers as [`set_game_only`]. The helper's signal is decided again with it: it acts only while a
/// session game-only applies to is live.
#[tauri::command]
pub fn set_game_only_for_guests(
    control: State<'_, AgentControl>,
    helper: State<'_, GameHelper>,
    enabled: bool,
) -> GameOnlyDto {
    let (game_only, _) = control.game_only();
    tracing::info!(
        target: SYSTEM_TARGET,
        enabled,
        game_only,
        "«Только для гостей» switched{}",
        if game_only {
            ""
        } else {
            " (game-only is off: in force once it is on)"
        }
    );
    if let Err(e) = control.set_game_only_for_guests(enabled) {
        tracing::warn!(
            target: SYSTEM_TARGET,
            enabled,
            "«Только для гостей» switch not saved: {e:#}"
        );
    }
    helper.evaluate("«Только для гостей» switched");
    dto(&control, &helper)
}

/// The visible windows the owner can bind, with the app each belongs to.
#[tauri::command]
pub fn list_game_windows() -> Result<Vec<GameWindowDto>, String> {
    list().inspect_err(|e| {
        tracing::warn!(target: SYSTEM_TARGET, "game picker: windows not listed: {e}");
    })
}

/// The driver is missing, for the picker's «Нужен драйвер»: read not installed or not working, where
/// the embedded installer runs. Not read yet, or the read failed: not known, so no label.
#[cfg_attr(not(windows), allow(dead_code))]
fn driver_missing(install_supported: bool, read: DriverRead) -> bool {
    install_supported
        && matches!(
            read,
            DriverRead::Read(DriverState::NotInstalled | DriverState::Broken)
        )
}

/// The windows, each with «Нужен драйвер» when the driver is missing and its program runs as
/// administrator while this agent does not — read the way the foreground window's elevation is
/// (`afklink_input::window_blocks_sendinput`: its process opened for limited information and its
/// token for a query, nothing more), and only while the driver is missing.
#[cfg(windows)]
fn list() -> Result<Vec<GameWindowDto>, String> {
    let windows = afklink_capture::game::list_windows()?;
    let read = crate::fakerinput_setup::last_read();
    let missing = driver_missing(crate::fakerinput_setup::install_supported(), read);
    let (mut labelled, mut unreadable) = (0u32, 0u32);
    let out = windows
        .into_iter()
        .map(|w| {
            let needs_driver = missing
                && match afklink_input::window_blocks_sendinput(w.hwnd) {
                    Ok(true) => {
                        labelled += 1;
                        tracing::debug!(
                            target: SYSTEM_TARGET,
                            exe = %w.exe_name,
                            pid = w.pid,
                            "game picker: «Нужен драйвер» beside a window that runs as \
                             administrator (this agent does not, and the driver is missing)"
                        );
                        true
                    }
                    Ok(false) => false,
                    Err(e) => {
                        unreadable += 1;
                        tracing::debug!(
                            target: SYSTEM_TARGET,
                            exe = %w.exe_name,
                            pid = w.pid,
                            "game picker: whether the window runs as administrator could not be \
                             read ({e}); no label"
                        );
                        false
                    }
                };
            GameWindowDto {
                exe_path: w.exe_path,
                exe_name: w.exe_name,
                window_class: w.class,
                title: w.title,
                needs_driver,
            }
        })
        .collect::<Vec<_>>();
    tracing::debug!(
        target: SYSTEM_TARGET,
        driver = ?read,
        driver_missing = missing,
        listed = out.len(),
        labelled,
        unreadable,
        "game picker: «Нужен драйвер» decided{}",
        if missing {
            ""
        } else {
            " (the driver is not known to be missing: no labels, no process looked at)"
        }
    );
    Ok(out)
}

#[cfg(not(windows))]
fn list() -> Result<Vec<GameWindowDto>, String> {
    Err("windows can only be listed on Windows".into())
}

/// Bind the chosen window's game: its exe path and its class. Refused when either is empty.
///
/// `enable`: also turn the mode on — the main view's «Выбрать игру», whose choice puts «Только игра»
/// in force at once; Settings' «Выбрать» leaves the switch as it is.
#[tauri::command]
pub fn set_game_window(
    control: State<'_, AgentControl>,
    helper: State<'_, GameHelper>,
    exe_path: String,
    window_class: String,
    enable: Option<bool>,
    from: Option<String>,
) -> Result<GameOnlyDto, String> {
    let origin = origin(from.as_deref());
    let binding = GameBinding::new(&exe_path, &window_class);
    if let Some(why) = binding.unusable() {
        tracing::debug!(
            target: SYSTEM_TARGET,
            exe = %exe_path,
            class = %window_class,
            origin,
            "game picker: choice refused ({why})"
        );
        return Err(why.to_string());
    }
    let enable = enable == Some(true);
    tracing::info!(
        target: SYSTEM_TARGET,
        game = %binding.shown_name(),
        exe = %binding.exe_path,
        class = %binding.window_class,
        origin,
        enable,
        "a game was chosen{}",
        if enable {
            "; game-only goes on with it"
        } else {
            ""
        }
    );
    if let Err(e) = control.set_game_binding(Some(binding)) {
        tracing::warn!(target: SYSTEM_TARGET, "chosen game not saved: {e:#}");
    }
    if enable {
        if let Err(e) = control.set_game_only(true) {
            tracing::warn!(target: SYSTEM_TARGET, "game-only switch not saved: {e:#}");
        }
    }
    // Another game is not what the helper was installed for: its signal goes off now.
    helper.evaluate("a game was chosen");
    Ok(dto(&control, &helper))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// «Нужен драйвер» only where the driver is read missing — not installed, or not working — and
    /// the installer runs; not before the first read, nor after a failed one.
    #[test]
    fn the_picker_label_waits_for_a_missing_driver() {
        use DriverRead::{Failed, NotYet, Read};
        assert!(driver_missing(true, Read(DriverState::NotInstalled)));
        assert!(driver_missing(true, Read(DriverState::Broken)));
        assert!(!driver_missing(true, Read(DriverState::Installed)));
        assert!(!driver_missing(true, Read(DriverState::InstalledExternal)));
        assert!(!driver_missing(true, NotYet));
        assert!(!driver_missing(true, Failed));
        assert!(!driver_missing(false, Read(DriverState::NotInstalled)));
    }
}
