//! The tray icon follows the taskbar: a white glyph on a dark taskbar, a near-black one on a light
//! taskbar, drawn for the size Windows puts in the notification area at the primary monitor's scale
//! (16 px at 100 %, 20 at 125 %, 24 at 150 %, 32 from 175 % up) — each size is its own drawing
//! (`assets/brand/svg/tray-*.svg`, exported by `assets/brand/export.mjs`), so Windows never has to
//! resample a glyph this small.
//!
//! The taskbar's theme is `SystemUsesLightTheme` under `HKCU\…\Themes\Personalize`, not
//! `AppsUseLightTheme`: in Windows' custom colour mode the two differ, and the tray sits on the
//! taskbar. Tauri gives no notification for that value, so the choice is re-made on a 10 s timer
//! and at once when a window reports a theme or scale change (the usual moment the user flips the
//! mode). Every re-check runs on one watcher thread; `set_icon` is called only when the choice
//! changes.
//!
//! While someone is in control of the PC the tray shows the live set instead (`live-on-*`: the
//! glyph lit in the accent — see `assets/brand/README.md`), and the same thread keeps the tooltip,
//! the menu's first line («Вера управляет · 12 мин») and «Приостановить доступ» / «Возобновить» in
//! step with what the state watcher reports ([`Nudge::status`], worded by `tray_status`). One thread
//! owns every change to the tray: the calls block until Windows' UI thread has run them, which is
//! not something to do on the async runtime the orchestrator shares, and one owner keeps the
//! updates in order.

use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Mutex;
use std::time::Duration;

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::{AppHandle, Wry};

use crate::tray_status::TrayStatus;

/// The one tray icon this app creates.
pub const TRAY_ID: &str = "afklink-tray";

/// How often the watcher re-reads the taskbar theme when nothing nudges it.
const RECHECK: Duration = Duration::from_secs(10);

/// The notification-area drawings that exist, in pixels.
pub const SIZES: [u32; 4] = [16, 20, 24, 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskbarTheme {
    Dark,
    Light,
}

impl TaskbarTheme {
    /// `SystemUsesLightTheme`: non-zero is light. Absent (never set, or a Windows 10 older than
    /// 1903, whose taskbar is always dark) is dark.
    pub fn from_registry(value: Option<u32>) -> Self {
        match value {
            Some(v) if v != 0 => TaskbarTheme::Light,
            _ => TaskbarTheme::Dark,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            TaskbarTheme::Dark => "dark",
            TaskbarTheme::Light => "light",
        }
    }
}

/// Which drawing the tray shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrayIconChoice {
    pub theme: TaskbarTheme,
    pub size: u32,
    /// Someone is in control of the PC: the live set.
    pub live: bool,
}

impl std::fmt::Display for TrayIconChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = if self.live { "live" } else { "idle" };
        write!(
            f,
            "{state}, {} taskbar, {} px",
            self.theme.as_str(),
            self.size
        )
    }
}

/// The drawing for the notification area at `scale`: Windows draws tray icons at 16 px × scale,
/// so the smallest drawing at least that big (Windows then only ever scales down, by less than a
/// pixel's worth at the common scales). Past 32 px (above 200 %) the 32 px drawing is scaled up.
/// A scale that is not a positive number — a monitor that reported nothing sensible — counts as
/// 100 %.
pub fn size_for_scale(scale: f64) -> u32 {
    let scale = if scale.is_finite() && scale > 0.0 {
        scale
    } else {
        1.0
    };
    let want = 16.0 * scale;
    SIZES
        .into_iter()
        .find(|&size| f64::from(size) + 0.5 >= want)
        .unwrap_or(32)
}

pub fn choose(theme: TaskbarTheme, scale: f64, live: bool) -> TrayIconChoice {
    TrayIconChoice {
        theme,
        size: size_for_scale(scale),
        live,
    }
}

/// The PNG for a choice: `on-dark` is the white glyph, `on-light` the near-black one, and the
/// `live-` sets the same drawings while someone is in control. A size without a drawing gets the
/// 32 px one.
pub fn png(choice: TrayIconChoice) -> &'static [u8] {
    match (choice.live, choice.theme, choice.size) {
        (false, TaskbarTheme::Dark, 16) => include_bytes!("../icons/tray/on-dark-16.png"),
        (false, TaskbarTheme::Dark, 20) => include_bytes!("../icons/tray/on-dark-20.png"),
        (false, TaskbarTheme::Dark, 24) => include_bytes!("../icons/tray/on-dark-24.png"),
        (false, TaskbarTheme::Dark, _) => include_bytes!("../icons/tray/on-dark-32.png"),
        (false, TaskbarTheme::Light, 16) => include_bytes!("../icons/tray/on-light-16.png"),
        (false, TaskbarTheme::Light, 20) => include_bytes!("../icons/tray/on-light-20.png"),
        (false, TaskbarTheme::Light, 24) => include_bytes!("../icons/tray/on-light-24.png"),
        (false, TaskbarTheme::Light, _) => include_bytes!("../icons/tray/on-light-32.png"),
        (true, TaskbarTheme::Dark, 16) => include_bytes!("../icons/tray/live-on-dark-16.png"),
        (true, TaskbarTheme::Dark, 20) => include_bytes!("../icons/tray/live-on-dark-20.png"),
        (true, TaskbarTheme::Dark, 24) => include_bytes!("../icons/tray/live-on-dark-24.png"),
        (true, TaskbarTheme::Dark, _) => include_bytes!("../icons/tray/live-on-dark-32.png"),
        (true, TaskbarTheme::Light, 16) => include_bytes!("../icons/tray/live-on-light-16.png"),
        (true, TaskbarTheme::Light, 20) => include_bytes!("../icons/tray/live-on-light-20.png"),
        (true, TaskbarTheme::Light, 24) => include_bytes!("../icons/tray/live-on-light-24.png"),
        (true, TaskbarTheme::Light, _) => include_bytes!("../icons/tray/live-on-light-32.png"),
    }
}

/// The decoded icon for a choice.
pub fn image(choice: TrayIconChoice) -> tauri::Result<Image<'static>> {
    Image::from_bytes(png(choice))
}

/// `SystemUsesLightTheme`, or `None` where the value (or its key) does not exist.
#[cfg(windows)]
fn read_system_uses_light_theme() -> std::io::Result<Option<u32>> {
    use std::io::ErrorKind;
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    const PERSONALIZE: &str = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    let key = match RegKey::predef(HKEY_CURRENT_USER).open_subkey(PERSONALIZE) {
        Ok(key) => key,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    match key.get_value::<u32, _>("SystemUsesLightTheme") {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// No taskbar theme to follow off Windows: the dark-taskbar glyph.
#[cfg(not(windows))]
fn read_system_uses_light_theme() -> std::io::Result<Option<u32>> {
    Ok(None)
}

/// The primary monitor's scale factor: the notification area lives on the primary taskbar.
fn read_scale(app: &AppHandle) -> Result<f64, String> {
    match app.primary_monitor() {
        Ok(Some(monitor)) => Ok(monitor.scale_factor()),
        Ok(None) => Err("no primary monitor reported".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// The choice to build the tray with, from what the system reports now — idle: nobody can be
/// connected before the orchestrator has started. A value that cannot be read falls back to the
/// default (dark taskbar, 100 %), which is logged.
pub fn initial_choice(app: &AppHandle) -> TrayIconChoice {
    let registry = read_system_uses_light_theme();
    let theme = match &registry {
        Ok(value) => TaskbarTheme::from_registry(*value),
        Err(e) => {
            tracing::warn!(
                "taskbar theme not read: {e}; the tray starts with the dark-taskbar icon"
            );
            TaskbarTheme::Dark
        }
    };
    let scale = match read_scale(app) {
        Ok(scale) => scale,
        Err(e) => {
            tracing::warn!("display scale not read: {e}; the tray starts with the 100 % icon");
            1.0
        }
    };
    let choice = choose(theme, scale, false);
    tracing::debug!(
        system_uses_light_theme = ?registry.as_ref().ok().copied().flatten(),
        scale,
        icon = %choice,
        "tray icon chosen"
    );
    choice
}

/// What the watcher thread is asked to do.
enum Msg {
    /// Re-read the taskbar theme and scale now; the reason goes to the log.
    Recheck(&'static str),
    /// Show who is in control: tooltip, the menu's first line, the live or idle icon.
    Status(TrayStatus),
}

/// The handle windows use to ask for an immediate re-check, and the state watcher to report who is
/// in control (managed Tauri state).
pub struct Nudge(Mutex<Option<Sender<Msg>>>);

impl Nudge {
    /// Ask the watcher to re-check now; `reason` goes to the log.
    pub fn send(&self, reason: &'static str) {
        match self.post(Msg::Recheck(reason)) {
            Ok(()) => tracing::debug!(reason, "tray icon re-check requested"),
            Err(why) => tracing::debug!(reason, "tray icon re-check not requested: {why}"),
        }
    }

    /// Have the tray show `status`. The caller sends it only when it changed, and logs why.
    pub fn status(&self, status: TrayStatus) {
        let live = status.live;
        if let Err(why) = self.post(Msg::Status(status)) {
            // Someone may be controlling this PC with the tray still saying nobody is: a warning.
            tracing::warn!(live, "tray status not shown: {why}");
        }
    }

    fn post(&self, msg: Msg) -> Result<(), &'static str> {
        let sender = afklink_core::lock(&self.0);
        match sender.as_ref() {
            Some(tx) => tx.send(msg).map_err(|_| "watcher gone"),
            None => Err("no watcher"),
        }
    }
}

/// The parts of the tray menu the watcher rewrites.
pub struct TrayMenu {
    pub menu: Menu<Wry>,
    /// The first line, «Вера управляет · 12 мин».
    pub status: MenuItem<Wry>,
    /// «Приостановить доступ», in the menu while the PC is not paused.
    pub kill: MenuItem<Wry>,
    /// «Возобновить», in its place while the PC is paused; not in the menu otherwise.
    pub resume: MenuItem<Wry>,
}

/// Start the watcher thread, which keeps the tray icon in step with the taskbar from `initial`
/// on, and applies the status reports. `status` is what the tray was built with, and `menu` the
/// items it rewrites (built with «Приостановить доступ» in place). The returned handle is what
/// windows nudge and the state watcher reports to; it holds nothing if the thread did not start
/// (logged), and the tray then keeps its first icon, tooltip and menu.
pub fn spawn_watcher(
    app: AppHandle,
    initial: TrayIconChoice,
    status: TrayStatus,
    menu: TrayMenu,
) -> Nudge {
    let (tx, rx) = mpsc::channel::<Msg>();
    let mut watcher = Watcher {
        app,
        current: initial,
        live: initial.live,
        paused: status.paused,
        status,
        menu,
        theme_failing: false,
        scale_failing: false,
        tray_missing: false,
        action_failing: false,
    };
    let spawned = std::thread::Builder::new()
        .name("tray-theme".into())
        .spawn(move || {
            tracing::debug!(every_s = RECHECK.as_secs(), current = %watcher.current, "tray theme watcher started");
            loop {
                match rx.recv_timeout(RECHECK) {
                    Ok(Msg::Recheck(reason)) => watcher.check(reason),
                    Ok(Msg::Status(status)) => watcher.apply_status(status),
                    Err(RecvTimeoutError::Timeout) => {
                        watcher.check("timer");
                        // A swap that failed is retried here: while paused the status text does
                        // not change, so no new report would come to retry it.
                        watcher.sync_action("retry");
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        tracing::debug!("tray theme watcher stopped: the app dropped its handle");
                        return;
                    }
                }
            }
        });
    match spawned {
        Ok(_) => Nudge(Mutex::new(Some(tx))),
        Err(e) => {
            tracing::warn!(
                "tray theme watcher not started: {e}; the tray icon will not follow theme changes \
                 and the tray will not show who is connected"
            );
            Nudge(Mutex::new(None))
        }
    }
}

struct Watcher {
    app: AppHandle,
    /// The drawing on the tray now.
    current: TrayIconChoice,
    /// Whether the live set is wanted: the last status report's. `current.live` catches up on the
    /// next successful swap, so a failed one is retried on the timer.
    live: bool,
    /// Whether «Возобновить» is wanted in place of «Приостановить доступ»: the last report's.
    /// `status.paused` is what the menu shows, and catches up on a successful swap.
    paused: bool,
    /// The tooltip, menu line and kill/resume item on the tray now (the icon half is `current`).
    status: TrayStatus,
    menu: TrayMenu,
    /// A failure is logged when it starts and when it ends, not on every 10 s tick.
    theme_failing: bool,
    scale_failing: bool,
    tray_missing: bool,
    action_failing: bool,
}

impl Watcher {
    fn theme(&mut self) -> TaskbarTheme {
        match read_system_uses_light_theme() {
            Ok(value) => {
                if std::mem::take(&mut self.theme_failing) {
                    tracing::debug!(system_uses_light_theme = ?value, "taskbar theme readable again");
                }
                TaskbarTheme::from_registry(value)
            }
            Err(e) => {
                if !std::mem::replace(&mut self.theme_failing, true) {
                    tracing::warn!(
                        "taskbar theme not read: {e}; the tray keeps the {} icon",
                        self.current
                    );
                }
                self.current.theme
            }
        }
    }

    /// The scale, or `None` to keep the current size.
    fn scale(&mut self) -> Option<f64> {
        match read_scale(&self.app) {
            Ok(scale) => {
                if std::mem::take(&mut self.scale_failing) {
                    tracing::debug!(scale, "display scale readable again");
                }
                Some(scale)
            }
            Err(e) => {
                if !std::mem::replace(&mut self.scale_failing, true) {
                    tracing::warn!(
                        "display scale not read: {e}; the tray keeps the {} icon",
                        self.current
                    );
                }
                None
            }
        }
    }

    /// Put a status report on the tray: the tooltip and the menu line where they changed, then the
    /// icon set. Each part that fails is logged and left as it was; the next report (at the latest
    /// when the minute on it turns) tries the text again, and the timer the icon.
    fn apply_status(&mut self, next: TrayStatus) {
        if next.tooltip != self.status.tooltip {
            match self.app.tray_by_id(TRAY_ID) {
                Some(tray) => match tray.set_tooltip(Some(next.tooltip.as_str())) {
                    Ok(()) => {
                        tracing::trace!(live = next.live, "tray tooltip updated");
                        self.status.tooltip.clone_from(&next.tooltip);
                    }
                    Err(e) => tracing::warn!(live = next.live, "tray tooltip not updated: {e}"),
                },
                None => {
                    if !std::mem::replace(&mut self.tray_missing, true) {
                        tracing::warn!(live = next.live, "no tray icon to update the tooltip of");
                    }
                }
            }
        }
        if next.menu_text != self.status.menu_text {
            match self.menu.status.set_text(next.menu_text.as_str()) {
                Ok(()) => {
                    tracing::trace!(live = next.live, "tray menu status line updated");
                    self.status.menu_text.clone_from(&next.menu_text);
                }
                Err(e) => {
                    tracing::warn!(live = next.live, "tray menu status line not updated: {e}")
                }
            }
        }
        self.status.live = next.live;
        if next.paused != self.paused {
            self.paused = next.paused;
            self.sync_action(if next.paused { "paused" } else { "resumed" });
        }
        if next.live != self.live {
            tracing::debug!(
                from = self.live,
                to = next.live,
                "tray icon set follows the connection: {}",
                if next.live { "live" } else { "idle" }
            );
            self.live = next.live;
            self.check(if next.live {
                "someone connected"
            } else {
                "nobody connected"
            });
        }
    }

    /// Put «Возобновить» in place of «Приостановить доступ» while the PC is paused, and back after.
    /// Nothing to do when the menu already shows what is wanted; a failure is logged once and
    /// retried on the timer.
    fn sync_action(&mut self, reason: &'static str) {
        if self.status.paused == self.paused {
            return;
        }
        let (out, into, shows) = if self.paused {
            (&self.menu.kill, &self.menu.resume, "resume")
        } else {
            (&self.menu.resume, &self.menu.kill, "kill")
        };
        match swap_item(&self.menu.menu, out, into) {
            Ok(position) => {
                tracing::debug!(
                    reason,
                    shows,
                    position,
                    "tray menu: kill/resume item swapped"
                );
                self.status.paused = self.paused;
                if std::mem::take(&mut self.action_failing) {
                    tracing::debug!(
                        shows,
                        "tray menu: the kill/resume swap went through on retry"
                    );
                }
            }
            Err(e) => {
                if !std::mem::replace(&mut self.action_failing, true) {
                    tracing::warn!(
                        reason,
                        wants = shows,
                        "tray menu: kill/resume item not swapped: {e}; retried every {} s",
                        RECHECK.as_secs()
                    );
                }
            }
        }
    }

    fn check(&mut self, reason: &'static str) {
        let theme = self.theme();
        let next = match self.scale() {
            Some(scale) => choose(theme, scale, self.live),
            None => TrayIconChoice {
                theme,
                size: self.current.size,
                live: self.live,
            },
        };
        if next == self.current {
            tracing::trace!(reason, icon = %next, "tray icon unchanged");
            return;
        }
        let Some(tray) = self.app.tray_by_id(TRAY_ID) else {
            if !std::mem::replace(&mut self.tray_missing, true) {
                tracing::warn!(reason, want = %next, "no tray icon to update");
            }
            return;
        };
        self.tray_missing = false;
        let icon = match image(next) {
            Ok(icon) => icon,
            Err(e) => {
                tracing::warn!(reason, want = %next, "tray icon not decoded: {e}; keeping {}", self.current);
                return;
            }
        };
        match tray.set_icon(Some(icon)) {
            Ok(()) => {
                tracing::debug!(reason, from = %self.current, to = %next, "tray icon swapped");
                self.current = next;
            }
            // `current` stays, so the next tick tries again.
            Err(e) => tracing::warn!(reason, want = %next, "tray icon not swapped: {e}"),
        }
    }
}

/// Replace `out` with `into` at the same place in `menu`; the position it went to. A menu that
/// already has `into` and not `out` is left as it is: a remove that went through with an insert
/// that did not is retried as the insert alone.
fn swap_item(menu: &Menu<Wry>, out: &MenuItem<Wry>, into: &MenuItem<Wry>) -> Result<usize, String> {
    let items = menu.items().map_err(|e| format!("menu not read: {e}"))?;
    let at = |item: &MenuItem<Wry>| items.iter().position(|i| i.id() == item.id());
    let (out_id, into_id) = (&out.id().0, &into.id().0);
    let position = match (at(out), at(into)) {
        (None, Some(position)) => return Ok(position),
        (Some(_), Some(_)) => return Err(format!("both {out_id} and {into_id} are in the menu")),
        (Some(position), None) => {
            menu.remove(out)
                .map_err(|e| format!("{out_id} not removed: {e}"))?;
            position
        }
        // The remove went through last time and the insert did not: where `out` stood, the
        // item before «Выход».
        (None, None) => items.len().saturating_sub(1),
    };
    menu.insert(into, position)
        .map_err(|e| format!("{into_id} not inserted at {position}: {e}"))?;
    Ok(position)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_value_maps_to_taskbar_theme() {
        assert_eq!(TaskbarTheme::from_registry(None), TaskbarTheme::Dark);
        assert_eq!(TaskbarTheme::from_registry(Some(0)), TaskbarTheme::Dark);
        assert_eq!(TaskbarTheme::from_registry(Some(1)), TaskbarTheme::Light);
        assert_eq!(TaskbarTheme::from_registry(Some(2)), TaskbarTheme::Light);
    }

    #[test]
    fn scale_picks_the_drawing_windows_would_draw() {
        for (scale, size) in [
            (1.0, 16),
            (1.25, 20),
            (1.5, 24),
            (1.75, 32),
            (2.0, 32),
            (2.5, 32),
            (1.1, 20),
            (0.8, 16),
        ] {
            assert_eq!(size_for_scale(scale), size, "scale {scale}");
        }
    }

    #[test]
    fn nonsense_scale_counts_as_100_percent() {
        for scale in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(size_for_scale(scale), 16, "scale {scale}");
        }
    }

    #[test]
    fn choice_combines_theme_scale_and_connection() {
        assert_eq!(
            choose(TaskbarTheme::Light, 1.5, true),
            TrayIconChoice {
                theme: TaskbarTheme::Light,
                size: 24,
                live: true,
            }
        );
    }

    /// Whether a pixel is the accent lime (#bff23a), give or take the rasteriser's rounding.
    fn is_lime(px: &[u8; 4]) -> bool {
        px[3] == 255
            && px[0].abs_diff(0xbf) <= 8
            && px[1].abs_diff(0xf2) <= 8
            && px[2].abs_diff(0x3a) <= 8
    }

    /// Every drawing the tray can pick decodes at its own size, and the glyph is white on a dark
    /// taskbar and near-black on a light one — the two sets swapped would vanish into the taskbar.
    #[test]
    fn every_drawing_decodes_at_its_size_in_the_right_ink() {
        for theme in [TaskbarTheme::Dark, TaskbarTheme::Light] {
            for size in SIZES {
                let choice = TrayIconChoice {
                    theme,
                    size,
                    live: false,
                };
                let icon = image(choice).expect("tray PNG decodes");
                assert_eq!((icon.width(), icon.height()), (size, size), "{choice}");
                let ink = icon
                    .rgba()
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .max_by_key(|px| px[3])
                    .expect("at least one pixel");
                assert_eq!(ink[3], 255, "{choice}: the glyph has fully opaque pixels");
                let brightness = u32::from(ink[0]) + u32::from(ink[1]) + u32::from(ink[2]);
                match theme {
                    TaskbarTheme::Dark => assert!(brightness > 3 * 240, "{choice}: white glyph"),
                    TaskbarTheme::Light => assert!(brightness < 3 * 40, "{choice}: dark glyph"),
                }
                assert!(
                    !icon.rgba().as_chunks::<4>().0.iter().any(is_lime),
                    "{choice}: the idle set has no lime"
                );
            }
        }
    }

    /// The live set decodes at its sizes and is lit: lime glyph pixels — on the charcoal plate on a
    /// light taskbar, where lime alone does not read, and without one on a dark taskbar.
    #[test]
    fn every_live_drawing_is_lit_and_plated_only_on_a_light_taskbar() {
        for theme in [TaskbarTheme::Dark, TaskbarTheme::Light] {
            for size in SIZES {
                let choice = TrayIconChoice {
                    theme,
                    size,
                    live: true,
                };
                let icon = image(choice).expect("live tray PNG decodes");
                assert_eq!((icon.width(), icon.height()), (size, size), "{choice}");
                let px = icon.rgba().as_chunks::<4>().0;
                let lime = px.iter().filter(|p| is_lime(p)).count();
                assert!(
                    lime >= (size * size / 10) as usize,
                    "{choice}: {lime} lime pixels"
                );
                // The middle of the bottom-right quarter is empty in the glyph: the plate's
                // charcoal on a light taskbar, transparent on a dark one.
                let at = |x: u32, y: u32| px[(y * size + x) as usize];
                let corner = at(size * 7 / 8, size * 7 / 8);
                match theme {
                    TaskbarTheme::Light => assert!(
                        corner[3] == 255 && u32::from(corner[0]) < 0x20,
                        "{choice}: charcoal plate, got {corner:?}"
                    ),
                    TaskbarTheme::Dark => {
                        assert_eq!(corner[3], 0, "{choice}: no plate, got {corner:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_size_without_a_drawing_gets_the_32_px_one() {
        for live in [false, true] {
            let odd = TrayIconChoice {
                theme: TaskbarTheme::Dark,
                size: 40,
                live,
            };
            let icon = image(odd).expect("tray PNG decodes");
            assert_eq!(icon.width(), 32);
        }
    }
}
