//! The connection journal (`afklink_core::journal`) as the window shows it: the «Журнал» screen
//! and the main view's «Журнал» row.
//!
//! The window gets the entries with everything that needs Rust already decided: the device by the
//! viewer's Telegram platform, how a session ended (a label, or none for an ordinary end), how long
//! it lasted in the window's language (the tray's own words, `tray_status::duration_text`), and
//! whether its log is still kept for «Отправить логи». Names of devices and labels are the window's.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tauri::State;

use afklink_core::journal::{Journal, Kind, View};
use afklink_i18n::Locale;

use crate::log_retention::SESSION_MAX_AGE_DAYS;

const DAY_MS: i64 = 86_400_000;

/// One entry, as the window draws it.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct JournalEntryDto {
    /// The session's id, or the event's own.
    pub(crate) id: String,
    /// `"session"`, `"granted"`, `"invited"` (a guest the owner let in by his invite), `"revoked"`
    /// or `"paused"`.
    pub(crate) kind: &'static str,
    pub(crate) telegram_user_id: i64,
    /// First name, else `@username`, else `#id`, as of the entry.
    pub(crate) name: String,
    /// Unix ms: when the session's video came up, or when the event happened.
    pub(crate) at_ms: i64,
    /// A session going on now.
    pub(crate) live: bool,
    /// Sessions: how long, «1 ч 05 мин» — until now while it runs — in the window's language.
    pub(crate) duration: Option<String>,
    /// Sessions: `"iphone"`, `"android"`, `"mac"`, `"desktop"`, `"browser"`; `None` when the platform
    /// is unknown or never came.
    pub(crate) device: Option<&'static str>,
    /// Sessions: `"pc"`, `"owner"`, `"revoked"`, `"lost"`, `"failed"` or `"app_closed"`; `None` for
    /// an ordinary end, a reason this build does not know, and a session going on.
    pub(crate) ending: Option<&'static str>,
    pub(crate) game_only: bool,
    pub(crate) weak: bool,
    /// Sessions: its log is still kept (younger than `SESSION_MAX_AGE_DAYS`), so «Отправить логи»
    /// can carry it first.
    pub(crate) logs: bool,
}

/// The «Журнал» screen.
#[derive(Serialize, Debug)]
pub(crate) struct JournalDto {
    /// Newest first: the sessions going on now, then the rest by when they happened.
    entries: Vec<JournalEntryDto>,
}

/// `view` for the window, durations in `locale`, ages against `now_ms`.
pub(crate) fn entry_dto(view: &View, locale: Locale, now_ms: i64) -> JournalEntryDto {
    let e = &view.entry;
    let session = e.kind == Kind::Session;
    let duration = session.then(|| {
        let end = if view.live {
            now_ms
        } else {
            e.end.unwrap_or(e.at)
        };
        let ms = u64::try_from(end.saturating_sub(e.at)).unwrap_or(0);
        crate::tray_status::duration_text(locale, Duration::from_millis(ms))
    });
    JournalEntryDto {
        id: e.id.clone(),
        kind: e.kind.as_str(),
        telegram_user_id: e.user,
        name: e.name.clone(),
        at_ms: e.at,
        live: view.live,
        duration,
        device: view.device.map(afklink_core::journal::Device::as_str),
        ending: view.ending.and_then(afklink_core::journal::Ending::label),
        game_only: e.game_only,
        weak: e.weak,
        logs: session && now_ms.saturating_sub(e.at) < SESSION_MAX_AGE_DAYS * DAY_MS,
    }
}

/// The «Журнал» screen's entries, read when it opens and every few seconds while it is open.
/// `lang` is the window's language, as for `get_status`.
#[tauri::command]
pub(crate) fn get_journal(
    journal: State<'_, Arc<Journal>>,
    locale: State<'_, Locale>,
    lang: Option<String>,
) -> JournalDto {
    let locale = crate::window_locale(lang.as_deref(), *locale);
    let now = afklink_core::journal::now_ms();
    let entries: Vec<JournalEntryDto> = journal
        .entries()
        .iter()
        .map(|v| entry_dto(v, locale, now))
        .collect();
    tracing::trace!(
        entries = entries.len(),
        "journal: the window read the entries"
    );
    JournalDto { entries }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afklink_core::journal::{Person, SessionStart};

    const T0: i64 = 1_790_000_000_000;

    /// A duration with its non-breaking spaces read as spaces.
    fn plain(text: Option<&str>) -> Option<String> {
        text.map(|t| t.replace('\u{a0}', " "))
    }

    #[test]
    fn a_session_reads_as_the_window_draws_it() {
        let j = Journal::open(None, T0);
        j.session_started(
            &SessionStart {
                session_id: "s1",
                user: 7,
                name: "Вера",
                username: Some("vera"),
                game_only: true,
            },
            T0,
        );
        assert!(j.session_platform("s1", "tdesktop", T0));
        let live = entry_dto(&j.last().expect("live"), Locale::Ru, T0 + 12 * 60_000);
        assert!(live.live);
        assert_eq!(plain(live.duration.as_deref()).as_deref(), Some("12 мин"));
        assert_eq!(live.device, Some("desktop"));
        assert_eq!(live.ending, None);

        j.session_ended("s1", "ice_timeout", T0 + 72 * 60_000);
        let done = entry_dto(&j.last().expect("done"), Locale::Ru, T0 + 100 * 60_000);
        assert!(!done.live);
        assert_eq!(
            plain(done.duration.as_deref()).as_deref(),
            Some("1 ч 12 мин")
        );
        assert_eq!(done.ending, Some("lost"));
        assert!(done.game_only);
        assert!(done.logs, "a session of today keeps its log");
        let week_later = entry_dto(
            &j.last().expect("done"),
            Locale::En,
            T0 + SESSION_MAX_AGE_DAYS * DAY_MS + 1,
        );
        assert!(!week_later.logs, "past the session logs' week");
        assert_eq!(
            plain(week_later.duration.as_deref()).as_deref(),
            Some("1 hr 12 min")
        );
    }

    #[test]
    fn an_event_has_no_duration_and_no_logs() {
        let j = Journal::open(None, T0);
        j.event(
            Kind::Granted,
            Person {
                user: 7,
                name: "Вера",
                username: None,
            },
            T0,
        );
        let e = entry_dto(&j.last().expect("event"), Locale::Ru, T0);
        assert_eq!(e.kind, "granted");
        assert_eq!(e.duration, None);
        assert_eq!(e.device, None);
        assert!(!e.logs);
    }

    /// A guest the owner let in by his invite reaches the window as its own kind, which it words
    /// «Доступ по приглашению» (`app.journalInvited`) in place of «Доступ выдан».
    #[test]
    fn access_by_invite_reaches_the_window_as_its_own_kind() {
        let j = Journal::open(None, T0);
        j.event(
            Kind::Invited,
            Person {
                user: 42,
                name: "Друг",
                username: Some("friend"),
            },
            T0,
        );
        let e = entry_dto(&j.last().expect("event"), Locale::Ru, T0);
        assert_eq!(e.kind, "invited");
        assert_eq!(e.name, "Друг");
        assert_eq!(e.duration, None);
        assert_eq!(e.ending, None);
        assert!(!e.live);
        assert!(!e.logs);
    }
}
