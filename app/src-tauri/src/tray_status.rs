//! Who is in control of this PC right now, as the tray says it — and the window's timer with it.
//!
//! One answer, [`Presence`], read from the orchestrator's state, and every surface worded from it:
//! the tray menu's first item «Вера управляет · 12 мин» (clicking it opens the window), the tooltip
//! «AFKLink — Вера управляет · 12 мин», the tray icon's live set, «Возобновить» in place of
//! «Приостановить доступ» while paused, and the window's muted «12 мин» under «Вера управляет»
//! (`StatusDto::live_for`). The window gets the duration as finished text from here, so the format
//! and its strings exist once.
//!
//! In control means the video is up (`SessionInfo::connected`: ICE and DTLS up, media flowing) —
//! the same moment the «Вера управляет ПК» toast fires; a session still connecting does not
//! count. After «Приостановить доступ» the PC is paused, and that outranks everything, as in the
//! window.
//!
//! The duration counts from `SessionInfo::connected_at` and is shown in whole minutes, floored: a
//! text that changes once a minute, so the tray is touched once a minute and never on the 500 ms
//! poll that computes it.
//!
//! Nobody in control is «Готов к подключению» only while the server can reach this PC; without the
//! link it is «Нет связи» ([`Presence::Offline`]). Whether the link is down long enough to say so is
//! [`LinkWatch`]'s answer, one for the tray and the window ([`SharedLink`]): a drop shorter than
//! [`OFFLINE_SHOWN_AFTER`] — the handshake at launch, a reconnect — is never shown, so a normal
//! launch never changes the text. A session outranks the link (its video does not go through the
//! server), and the pause outranks everything.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afklink_core::{PersonName, SessionInfo};
use afklink_i18n::{Locale, NativeText};

/// A viewer's name is cut to this many characters (then «…») on every tray surface: a Telegram
/// first name can run to 64, and a menu item as wide as the screen helps nobody.
pub const MAX_NAME_CHARS: usize = 32;

/// `NOTIFYICONDATAW::szTip` holds 128 UTF-16 units including the terminating NUL. `tray-icon`
/// copies up to 128 units and would overwrite the NUL, so the tooltip is fitted here.
pub const TOOLTIP_MAX_UTF16: usize = 127;

/// Between the status and the duration, in the menu line and the tooltip.
const SEPARATOR: &str = " · ";

/// Between the product and the status in the tooltip.
const TOOLTIP_DASH: &str = " — ";

/// Who is in control, from one read of the orchestrator's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    /// After the kill switch: every session ended, new ones refused until Resume.
    Paused,
    /// Nobody's video is up, and the server can reach this PC (or the link has been down for less
    /// than [`OFFLINE_SHOWN_AFTER`]): «Готов к подключению».
    Idle,
    /// Nobody's video is up, and the server cannot reach this PC: the link has been down for
    /// [`OFFLINE_SHOWN_AFTER`], or the backend refuses this agent. «Нет связи», where `Idle` would
    /// be ([`Presence::with_link`]).
    Offline,
    /// The viewers whose video is up, sorted by name so the text does not reorder between polls,
    /// and how long the longest of them has been connected.
    Live {
        viewers: Vec<PersonName>,
        longest: Duration,
    },
}

impl Presence {
    /// Stable spelling for log fields.
    pub fn kind(&self) -> &'static str {
        match self {
            Presence::Paused => "paused",
            Presence::Idle => "idle",
            Presence::Offline => "offline",
            Presence::Live { .. } => "live",
        }
    }

    /// The same presence with the link to the server said: «Нет связи» in place of
    /// «Готов к подключению» when the link is down long enough ([`Link::offline`]), and nowhere
    /// else — the pause and a live session outrank it (a session's video does not go through the
    /// server).
    pub fn with_link(self, link: &Link) -> Presence {
        match self {
            Presence::Idle if link.offline => Presence::Offline,
            other => other,
        }
    }

    /// Why this is what the tray says, given the `link` it was read with — for the log.
    pub fn why(&self, link: &Link) -> &'static str {
        match self {
            Presence::Paused => {
                "paused after «Приостановить доступ»: outranks any session and the link"
            }
            Presence::Live { .. } if link.offline => {
                "someone's video is up; the link to the server is down, but the session does not \
                 need it"
            }
            Presence::Live { .. } => "someone's video is up",
            Presence::Offline if link.refused => {
                "nobody in control, and the backend refuses this agent"
            }
            Presence::Offline => "nobody in control, and the link to the server is down",
            Presence::Idle if link.connected => "nobody in control; the server can reach this PC",
            Presence::Idle => {
                "nobody in control; the link to the server is down for less than the threshold \
                 (the launch or a reconnect): not said yet"
            }
        }
    }

    /// Whole minutes of the longest live connection, for the log; 0 when nobody is connected.
    pub fn minutes(&self) -> u64 {
        match self {
            Presence::Live { longest, .. } => longest.as_secs() / 60,
            _ => 0,
        }
    }

    /// The same state with the same people in control — so a changed text is only the minute
    /// turning.
    pub fn same_people(&self, other: &Presence) -> bool {
        match (self, other) {
            (Presence::Live { viewers: a, .. }, Presence::Live { viewers: b, .. }) => a == b,
            (a, b) => a.kind() == b.kind(),
        }
    }

    /// Which field each live viewer's name came from, for the log — never the names themselves.
    pub fn name_sources(&self) -> Vec<&'static str> {
        match self {
            Presence::Live { viewers, .. } => viewers.iter().map(|n| n.source.as_str()).collect(),
            _ => Vec::new(),
        }
    }
}

/// Read who is in control from the state: `paused` and the session list as `AgentState` holds
/// them, at `now`.
pub fn presence(paused: bool, sessions: &[SessionInfo], now: Instant) -> Presence {
    if paused {
        return Presence::Paused;
    }
    let mut live: Vec<(PersonName, Duration)> = sessions
        .iter()
        .filter(|s| s.connected)
        .map(|s| {
            // `connected_at` is set together with `connected`; a session without it (an older
            // state, a test) counts from now rather than not at all.
            let elapsed = s
                .connected_at
                .map_or(Duration::ZERO, |at| now.saturating_duration_since(at));
            (display_name(s.name()), elapsed)
        })
        .collect();
    if live.is_empty() {
        return Presence::Idle;
    }
    live.sort_by(|a, b| a.0.text.cmp(&b.0.text));
    let longest = live
        .iter()
        .map(|(_, elapsed)| *elapsed)
        .max()
        .unwrap_or_default();
    Presence::Live {
        viewers: live.into_iter().map(|(name, _)| name).collect(),
        longest,
    }
}

/// A name made safe for a tray line: control characters (a tab would split a menu item into an
/// accelerator column) become spaces, and the length is capped at [`MAX_NAME_CHARS`].
fn display_name(name: PersonName) -> PersonName {
    let clean: String = name
        .text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let clean = clean.trim();
    let text = if clean.chars().count() > MAX_NAME_CHARS {
        let mut cut: String = clean.chars().take(MAX_NAME_CHARS - 1).collect();
        cut.truncate(cut.trim_end().len());
        cut.push('…');
        cut
    } else {
        clean.to_string()
    };
    PersonName {
        text,
        source: name.source,
    }
}

/// How long a connection has lasted, as the tray and the window show it: «меньше минуты»,
/// «12 мин», «1 ч 05 мин» — whole minutes, floored.
pub fn duration_text(locale: Locale, elapsed: Duration) -> String {
    let minutes = elapsed.as_secs() / 60;
    if minutes == 0 {
        return NativeText::DurationUnderMinute.t(locale).to_string();
    }
    if minutes < 60 {
        return NativeText::DurationMinutes.fill(locale, &[("minutes", &minutes.to_string())]);
    }
    NativeText::DurationHours.fill(
        locale,
        &[
            ("hours", &(minutes / 60).to_string()),
            ("minutes", &format!("{:02}", minutes % 60)),
        ],
    )
}

/// «Вера управляет» / «Вера и Мама управляют» for already joined `names`.
fn who(locale: Locale, names: &str, count: usize) -> String {
    if count == 1 {
        NativeText::TrayStatusLive.fill(locale, &[("user", names)])
    } else {
        NativeText::TrayStatusLiveMany.fill(locale, &[("users", names)])
    }
}

/// The viewers' names as one list, «Вера и Мама», «Дима, Вера и Мама» / "Vera and Mom" — joined as
/// the window joins them (`Intl.ListFormat`, conjunction; `Locale::and_list`), not with a comma
/// alone («Вера, Мама управляют»).
fn joined(locale: Locale, viewers: &[PersonName]) -> String {
    let names: Vec<&str> = viewers.iter().map(|n| n.text.as_str()).collect();
    locale.and_list(&names)
}

/// The menu's first line, unescaped: «Готов к подключению», «Нет связи», «Вера управляет · 12 мин»,
/// «На паузе».
pub fn status_line(locale: Locale, presence: &Presence) -> String {
    match presence {
        Presence::Paused => NativeText::TrayStatusPaused.t(locale).to_string(),
        Presence::Idle => NativeText::TrayStatusIdle.t(locale).to_string(),
        Presence::Offline => NativeText::TrayStatusOffline.t(locale).to_string(),
        Presence::Live { viewers, longest } => format!(
            "{}{SEPARATOR}{}",
            who(locale, &joined(locale, viewers), viewers.len()),
            duration_text(locale, *longest)
        ),
    }
}

/// The tooltip: «AFKLink — » and the status line, fitted to [`TOOLTIP_MAX_UTF16`] by shortening
/// the names first and, if that is not enough, the whole text.
pub fn tooltip(locale: Locale, presence: &Presence) -> String {
    let product = NativeText::TrayTooltip.t(locale);
    let full = format!("{product}{TOOLTIP_DASH}{}", status_line(locale, presence));
    if utf16_len(&full) <= TOOLTIP_MAX_UTF16 {
        return full;
    }
    if let Presence::Live { viewers, longest } = presence {
        let names = joined(locale, viewers);
        let without_names = format!(
            "{product}{TOOLTIP_DASH}{}{SEPARATOR}{}",
            who(locale, "", viewers.len()),
            duration_text(locale, *longest)
        );
        let budget = TOOLTIP_MAX_UTF16.saturating_sub(utf16_len(&without_names));
        // Room for at least a letter and the ellipsis; otherwise the whole text is cut below.
        if budget >= 2 {
            let names = fit_utf16(&names, budget);
            return format!(
                "{product}{TOOLTIP_DASH}{}{SEPARATOR}{}",
                who(locale, &names, viewers.len()),
                duration_text(locale, *longest)
            );
        }
    }
    fit_utf16(&full, TOOLTIP_MAX_UTF16)
}

fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// `s` in at most `max` UTF-16 units: cut on a character boundary, with «…» when cut.
fn fit_utf16(s: &str, max: usize) -> String {
    if utf16_len(s) <= max {
        return s.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        // One unit is kept for the ellipsis.
        if used + c.len_utf16() > max.saturating_sub(1) {
            break;
        }
        used += c.len_utf16();
        out.push(c);
    }
    out.truncate(out.trim_end().len());
    out.push('…');
    out
}

/// A Windows menu reads `&` as the mnemonic marker (it underlines the next letter and vanishes);
/// `&&` is a literal one. muda passes the text through as is.
fn escape_menu_text(line: &str) -> String {
    line.replace('&', "&&")
}

/// What the tray shows for a [`Presence`], compared as a whole so the tray is touched only when
/// something on it changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayStatus {
    /// The first menu item's text, escaped for a Windows menu.
    pub menu_text: String,
    pub tooltip: String,
    /// The live icon set (someone is in control) rather than the idle one.
    pub live: bool,
    /// The PC is paused: «Возобновить» stands where «Приостановить доступ» does.
    pub paused: bool,
}

impl TrayStatus {
    pub fn new(locale: Locale, presence: &Presence) -> Self {
        TrayStatus {
            menu_text: escape_menu_text(&status_line(locale, presence)),
            tooltip: tooltip(locale, presence),
            live: matches!(presence, Presence::Live { .. }),
            paused: matches!(presence, Presence::Paused),
        }
    }
}

/// The window's timer: how long someone has been in control, in the window's language; `None`
/// when nobody is.
pub fn live_for(locale: Locale, presence: &Presence) -> Option<String> {
    match presence {
        Presence::Live { longest, .. } => Some(duration_text(locale, *longest)),
        _ => None,
    }
}

/// How long the link to the server has to stay down, without a break, before the tray and the
/// window say so: «Нет связи» in the tray and under the monitor, and the «Нет связи с сервером»
/// toast.
///
/// The agent is disconnected for a moment at every launch (until the handshake, about 1.3 s) and on
/// every reconnect, whose first retry comes after 1 s (`afklink_core::reconnect::BACKOFF_FIRST`)
/// plus the handshake. Saying each of those would flash «Нет связи» over «Готов к подключению» for
/// nothing. Three seconds covers the handshake and the first retry. A refusal is not delayed: it
/// will not clear by itself.
pub const OFFLINE_SHOWN_AFTER: Duration = Duration::from_secs(3);

/// One reading of the link to the server ([`LinkWatch::observe`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    /// The signaling connection is up (`AgentState::connected`).
    pub connected: bool,
    /// The backend refuses this agent (`AgentState::refused`).
    pub refused: bool,
    /// How long the link has been down without a break — since the launch, while it has not been up
    /// yet; `None` while it is up.
    pub down_for: Option<Duration>,
    /// The server cannot reach this PC, as the tray and the window say it: down for
    /// [`OFFLINE_SHOWN_AFTER`], or refused (at once) — and, once said, until the link is back, so a
    /// refusal that clears while the link is still down does not bring «Готов к подключению» back
    /// for a moment.
    pub offline: bool,
}

impl Link {
    /// Stable spelling for log fields: `up`, `settling` (down, not said yet), `down`, `refused`.
    pub fn kind(&self) -> &'static str {
        if self.connected {
            "up"
        } else if self.refused {
            "refused"
        } else if self.offline {
            "down"
        } else {
            "settling"
        }
    }

    /// Whole milliseconds down, for the log; 0 while up.
    pub fn down_ms(&self) -> u64 {
        self.down_for.map_or(0, millis)
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Dates the link's drops from the polls of `AgentState`, so that a drop is said only once it has
/// lasted [`OFFLINE_SHOWN_AFTER`], and logs every change of what is said, with why.
#[derive(Debug)]
pub struct LinkWatch {
    /// Since when the link has been down: the launch until the first handshake, then the first poll
    /// that saw it down. `None` while it is up.
    down_since: Option<Instant>,
    /// The link has been up at least once in this run.
    ever_up: bool,
    /// «Нет связи» is being said for the current outage (the last poll's [`Link::offline`]).
    said_offline: bool,
    /// The last poll's refusal, for the log's edges.
    refused: bool,
}

impl LinkWatch {
    /// A watch from `launched`: the link is down until the agent's first handshake, and that wait
    /// counts toward the threshold like any drop — so a normal launch, up in about a second, never
    /// says «Нет связи», and a launch without a server says it three seconds in.
    pub fn new(launched: Instant) -> Self {
        LinkWatch {
            down_since: Some(launched),
            ever_up: false,
            said_offline: false,
            refused: false,
        }
    }

    /// One poll: `connected` and `refused` as `AgentState` holds them, at `now`. `by` is who polled
    /// (`tray` or `window`), for the log; whichever sees a change first dates it.
    pub fn observe(&mut self, connected: bool, refused: bool, now: Instant, by: &str) -> Link {
        let threshold_ms = millis(OFFLINE_SHOWN_AFTER);
        let link = if connected {
            if let Some(since) = self.down_since.take() {
                let down_ms = millis(now.saturating_duration_since(since));
                let what = if self.said_offline {
                    "«Нет связи» → «Готов к подключению»"
                } else {
                    "within the threshold: «Нет связи» was never said"
                };
                if self.ever_up {
                    tracing::debug!(by, down_ms, threshold_ms, "link to the server back: {what}");
                } else {
                    tracing::debug!(
                        by,
                        after_launch_ms = down_ms,
                        threshold_ms,
                        "link to the server up for the first time in this run: {what}"
                    );
                }
            }
            self.ever_up = true;
            self.said_offline = false;
            Link {
                connected: true,
                refused: false,
                down_for: None,
                offline: false,
            }
        } else {
            let since = *self.down_since.get_or_insert_with(|| {
                if refused {
                    tracing::debug!(by, "link to the server dropped with a refusal");
                } else {
                    tracing::debug!(
                        by,
                        threshold_ms,
                        "link to the server dropped: «Готов к подключению» stays until it has been \
                         down for the threshold (a reconnect usually closes it first)"
                    );
                }
                now
            });
            let down_for = now.saturating_duration_since(since);
            Link {
                connected: false,
                refused,
                down_for: Some(down_for),
                offline: refused || down_for >= OFFLINE_SHOWN_AFTER || self.said_offline,
            }
        };
        if link.refused != self.refused {
            tracing::debug!(
                by,
                link = link.kind(),
                down_ms = link.down_ms(),
                "{}",
                if link.refused {
                    "the backend refuses this agent: «Нет связи» at once, not after the threshold"
                } else if link.connected {
                    "the refusal is over: connected"
                } else {
                    "the refusal is over, the link still down: «Нет связи» stays until it is back"
                }
            );
            self.refused = link.refused;
        }
        if link.offline && !self.said_offline {
            tracing::debug!(
                by,
                link = link.kind(),
                down_ms = link.down_ms(),
                threshold_ms,
                refused = link.refused,
                "the server cannot reach this PC: the tray and the window say «Нет связи» where \
                 nobody is in control"
            );
        }
        // The way back is said above, by the link coming up: nothing else withdraws it.
        self.said_offline = link.offline;
        link
    }
}

/// The one [`LinkWatch`] of a run, shared by the tray's state watcher and the window's `get_status`
/// (Tauri state), so the tray, the monitor's caption and the toast say «Нет связи» from the same
/// moment. A window shown in the middle of an outage (its poll pauses while it is hidden) says it at
/// once, rather than «Готов к подключению» for three seconds of its own.
#[derive(Debug, Clone)]
pub struct SharedLink(Arc<Mutex<LinkWatch>>);

impl SharedLink {
    pub fn new(launched: Instant) -> Self {
        SharedLink(Arc::new(Mutex::new(LinkWatch::new(launched))))
    }

    /// [`LinkWatch::observe`] under the lock. Call it without the state's lock held.
    pub fn observe(&self, connected: bool, refused: bool, now: Instant, by: &str) -> Link {
        afklink_core::lock(&self.0).observe(connected, refused, now, by)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afklink_core::NameSource;

    const NBSP: char = '\u{a0}';

    /// A `now` with days of room behind it: `Instant` minus an hour panics on a machine booted a
    /// minute ago (a fresh CI runner), since the clock counts from boot.
    fn later() -> Instant {
        Instant::now() + Duration::from_secs(3 * 86_400)
    }

    fn session(
        id: &str,
        first_name: &str,
        connected_for: Option<u64>,
        now: Instant,
    ) -> SessionInfo {
        SessionInfo {
            session_id: id.into(),
            telegram_user_id: 7,
            username: None,
            first_name: Some(first_name.into()),
            connected: connected_for.is_some(),
            connected_at: connected_for.map(|s| now - Duration::from_secs(s)),
        }
    }

    fn live(names: &[&str], secs: u64) -> Presence {
        Presence::Live {
            viewers: names
                .iter()
                .map(|n| PersonName {
                    text: (*n).into(),
                    source: NameSource::FirstName,
                })
                .collect(),
            longest: Duration::from_secs(secs),
        }
    }

    /// The owner's format: under a minute, whole minutes, hours with two-digit minutes — with
    /// non-breaking spaces, so a narrow menu never splits «12» from «мин».
    #[test]
    fn durations_read_in_whole_minutes() {
        let ru = |s: u64| duration_text(Locale::Ru, Duration::from_secs(s)).replace(NBSP, " ");
        assert_eq!(ru(0), "меньше минуты");
        assert_eq!(ru(59), "меньше минуты");
        assert_eq!(ru(60), "1 мин");
        assert_eq!(ru(12 * 60 + 59), "12 мин");
        assert_eq!(ru(59 * 60 + 59), "59 мин");
        assert_eq!(ru(3600), "1 ч 00 мин");
        assert_eq!(ru(3600 + 5 * 60), "1 ч 05 мин");
        assert_eq!(ru(26 * 3600 + 30 * 60), "26 ч 30 мин");

        let en = |s: u64| duration_text(Locale::En, Duration::from_secs(s)).replace(NBSP, " ");
        assert_eq!(en(30), "under a minute");
        assert_eq!(en(12 * 60), "12 min");
        assert_eq!(en(3600 + 5 * 60), "1 hr 05 min");

        let text = duration_text(Locale::Ru, Duration::from_secs(12 * 60));
        assert!(!text.contains(' '), "only non-breaking spaces: {text:?}");
    }

    #[test]
    fn only_viewers_whose_video_is_up_count() {
        let now = later();
        assert_eq!(presence(false, &[], now), Presence::Idle);
        // Requested, video not up yet: the toast waits, and so does the tray.
        let connecting = [session("s1", "Вера", None, now)];
        assert_eq!(presence(false, &connecting, now), Presence::Idle);

        let up = [session("s1", "Вера", Some(12 * 60 + 5), now)];
        assert_eq!(presence(false, &up, now), live(&["Вера"], 12 * 60 + 5));
    }

    #[test]
    fn the_pause_outranks_everything() {
        let now = later();
        let up = [session("s1", "Вера", Some(60), now)];
        assert_eq!(presence(true, &up, now), Presence::Paused);
        assert_eq!(presence(true, &[], now), Presence::Paused);
    }

    #[test]
    fn several_viewers_are_sorted_and_the_longest_connection_counts() {
        let now = later();
        let up = [
            session("s2", "Мама", Some(90), now),
            session("s1", "Вера", Some(30 * 60), now),
        ];
        assert_eq!(presence(false, &up, now), live(&["Вера", "Мама"], 30 * 60));
    }

    #[test]
    fn the_menu_line_and_the_tooltip_say_the_same() {
        let line = |p: &Presence| status_line(Locale::Ru, p).replace(NBSP, " ");
        assert_eq!(line(&Presence::Idle), "Готов к подключению");
        assert_eq!(line(&Presence::Offline), "Нет связи");
        assert_eq!(line(&Presence::Paused), "На паузе");
        assert_eq!(line(&live(&["Вера"], 12 * 60)), "Вера управляет · 12 мин");
        // Two or more names as the window joins them, not with a comma alone.
        assert_eq!(
            line(&live(&["Вера", "Мама"], 30)),
            "Вера и Мама управляют · меньше минуты"
        );
        assert_eq!(
            line(&live(&["Дима", "Вера", "Мама"], 30)),
            "Дима, Вера и Мама управляют · меньше минуты"
        );
        assert_eq!(
            status_line(Locale::En, &live(&["Vera"], 65 * 60)).replace(NBSP, " "),
            "Vera is in control · 1 hr 05 min"
        );
        assert_eq!(
            status_line(Locale::En, &live(&["Vera", "Mom"], 60)).replace(NBSP, " "),
            "Vera and Mom are in control · 1 min"
        );
        assert_eq!(
            status_line(Locale::En, &live(&["Dima", "Vera", "Mom"], 60)).replace(NBSP, " "),
            "Dima, Vera, and Mom are in control · 1 min"
        );
        assert_eq!(
            tooltip(Locale::Ru, &live(&["Вера", "Мама"], 12 * 60)).replace(NBSP, " "),
            "AFKLink — Вера и Мама управляют · 12 мин"
        );

        let tip = |p: &Presence| tooltip(Locale::Ru, p).replace(NBSP, " ");
        assert_eq!(tip(&Presence::Idle), "AFKLink — Готов к подключению");
        assert_eq!(tip(&Presence::Offline), "AFKLink — Нет связи");
        assert_eq!(tip(&Presence::Paused), "AFKLink — На паузе");
        assert_eq!(status_line(Locale::En, &Presence::Idle), "Ready to connect");
        assert_eq!(tooltip(Locale::En, &Presence::Offline), "AFKLink — Offline");
        assert_eq!(
            tip(&live(&["Вера"], 12 * 60)),
            "AFKLink — Вера управляет · 12 мин"
        );
    }

    #[test]
    fn a_long_name_is_cut_and_control_characters_are_blanked() {
        let now = later();
        let long = "Александр".repeat(8);
        let up = [session("s1", &long, Some(60), now)];
        let Presence::Live { viewers, .. } = presence(false, &up, now) else {
            panic!("live expected");
        };
        assert_eq!(viewers[0].text.chars().count(), MAX_NAME_CHARS);
        assert!(viewers[0].text.ends_with('…'));

        let up = [session("s1", "Вера\tМ", Some(60), now)];
        let Presence::Live { viewers, .. } = presence(false, &up, now) else {
            panic!("live expected");
        };
        assert_eq!(viewers[0].text, "Вера М");
    }

    /// Windows keeps 127 characters of a tooltip; `tray-icon` would copy 128 and lose the NUL. The
    /// names give way first, so the status and the duration always survive.
    #[test]
    fn the_tooltip_fits_windows_and_keeps_the_duration() {
        let names: Vec<String> = (0..6).map(|i| format!("{i}{}", "Ж".repeat(31))).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let p = live(&refs, 12 * 60);
        let tip = tooltip(Locale::Ru, &p);
        assert!(
            utf16_len(&tip) <= TOOLTIP_MAX_UTF16,
            "{} units",
            utf16_len(&tip)
        );
        assert!(tip.starts_with("AFKLink — 0"), "{tip}");
        assert!(
            tip.replace(NBSP, " ").ends_with("управляют · 12 мин"),
            "{tip}"
        );
        assert!(tip.contains('…'), "{tip}");

        // Characters outside the BMP count double and are never split.
        let emoji = "😀".repeat(40);
        let p = live(&[emoji.as_str(), emoji.as_str(), emoji.as_str()], 60);
        let tip = tooltip(Locale::En, &p);
        assert!(utf16_len(&tip) <= TOOLTIP_MAX_UTF16);
        assert!(
            tip.ends_with(&format!("are in control · 1{NBSP}min")),
            "{tip}"
        );
    }

    #[test]
    fn an_ampersand_in_a_name_survives_the_menu() {
        let status = TrayStatus::new(Locale::Ru, &live(&["Tom & Jerry"], 60));
        assert!(status.menu_text.starts_with("Tom && Jerry управляет"));
        assert!(
            status.tooltip.contains("Tom & Jerry управляет"),
            "not in the tooltip"
        );
        assert!(status.live && !status.paused);
        let paused = TrayStatus::new(Locale::Ru, &Presence::Paused);
        assert!(
            !paused.live && paused.paused,
            "paused: idle icon, «Возобновить»"
        );
        let idle = TrayStatus::new(Locale::Ru, &Presence::Idle);
        assert!(!idle.live && !idle.paused);
        let offline = TrayStatus::new(Locale::Ru, &Presence::Offline);
        assert!(
            !offline.live && !offline.paused,
            "offline: idle icon, «Приостановить доступ»"
        );
    }

    #[test]
    fn the_window_gets_the_same_duration_text() {
        let p = live(&["Вера"], 12 * 60);
        assert_eq!(
            live_for(Locale::Ru, &p),
            Some(duration_text(Locale::Ru, Duration::from_secs(12 * 60)))
        );
        assert_eq!(live_for(Locale::Ru, &Presence::Idle), None);
        assert_eq!(live_for(Locale::Ru, &Presence::Offline), None);
        assert_eq!(live_for(Locale::Ru, &Presence::Paused), None);
    }

    #[test]
    fn log_fields_carry_no_names() {
        let p = live(&["Вера"], 12 * 60 + 30);
        assert_eq!(p.kind(), "live");
        assert_eq!(p.minutes(), 12);
        assert_eq!(p.name_sources(), vec!["first_name"]);
        assert_eq!(Presence::Idle.minutes(), 0);
    }

    #[test]
    fn the_same_people_a_minute_later_are_the_same_people() {
        assert!(live(&["Вера"], 60).same_people(&live(&["Вера"], 120)));
        assert!(!live(&["Вера"], 60).same_people(&live(&["Вера", "Мама"], 60)));
        assert!(!live(&["Вера"], 60).same_people(&Presence::Idle));
        assert!(Presence::Idle.same_people(&Presence::Idle));
        assert!(!Presence::Idle.same_people(&Presence::Paused));
        assert!(!Presence::Idle.same_people(&Presence::Offline));
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Polls a watch launched at `t0` every 500 ms (the tray's pace) from `from` to `to` ms after
    /// the launch with the given link, and returns what each poll said.
    fn polls(
        watch: &mut LinkWatch,
        t0: Instant,
        from: u64,
        to: u64,
        connected: bool,
        refused: bool,
    ) -> Vec<Link> {
        (from..=to)
            .step_by(500)
            .map(|at| watch.observe(connected, refused, t0 + ms(at), "tray"))
            .collect()
    }

    /// The owner's promise: at a normal launch — the handshake done in about a second — the text
    /// never changes; it is «Готов к подключению» from the first poll on.
    #[test]
    fn a_normal_launch_never_says_offline() {
        let t0 = later();
        let mut watch = LinkWatch::new(t0);
        let settling = polls(&mut watch, t0, 0, 1000, false, false);
        assert!(settling
            .iter()
            .all(|l| !l.offline && l.kind() == "settling"));
        assert_eq!(
            settling[2].down_for,
            Some(ms(1000)),
            "counted from the launch"
        );
        let up = watch.observe(true, false, t0 + ms(1300), "tray");
        assert!(up.connected && !up.offline && up.down_for.is_none());
        assert_eq!(up.kind(), "up");
        for link in settling.iter().chain([&up]) {
            assert_eq!(Presence::Idle.with_link(link), Presence::Idle);
        }
    }

    /// No server at launch: «Нет связи» three seconds in, not before.
    #[test]
    fn a_launch_without_a_server_says_offline_after_the_threshold() {
        let t0 = later();
        let mut watch = LinkWatch::new(t0);
        assert!(polls(&mut watch, t0, 0, 2500, false, false)
            .iter()
            .all(|l| !l.offline));
        let down = watch.observe(false, false, t0 + ms(3000), "tray");
        assert!(down.offline);
        assert_eq!(down.kind(), "down");
        assert_eq!(Presence::Idle.with_link(&down), Presence::Offline);
        // And back the moment the link is.
        let up = watch.observe(true, false, t0 + ms(9000), "tray");
        assert_eq!(Presence::Idle.with_link(&up), Presence::Idle);
    }

    /// A reconnect — the first retry after 1 s plus the handshake — is never shown; a drop that
    /// lasts is, counted from the first poll that saw it, not from the launch.
    #[test]
    fn a_short_drop_is_not_shown_and_a_long_one_is() {
        let t0 = later();
        let mut watch = LinkWatch::new(t0);
        watch.observe(true, false, t0 + ms(1000), "tray");
        // Up for a minute, then a reconnect of 2.5 s.
        let blip = polls(&mut watch, t0, 60_000, 62_500, false, false);
        assert!(blip.iter().all(|l| !l.offline));
        assert_eq!(
            blip[0].down_for,
            Some(Duration::ZERO),
            "counted from the drop"
        );
        assert!(!watch.observe(true, false, t0 + ms(63_000), "tray").offline);
        // Then an outage.
        let outage = polls(&mut watch, t0, 120_000, 125_000, false, false);
        assert!(!outage[5].offline, "2.5 s in");
        assert!(outage[6].offline, "3 s in");
        assert!(outage[10].offline);
    }

    /// A refusal will not clear by itself: «Нет связи» at once. When it clears with the link still
    /// down (the next attempt failed some other way), «Нет связи» stays — no «Готов к подключению»
    /// for the moment until the threshold.
    #[test]
    fn a_refusal_says_offline_at_once_and_it_stays_until_the_link_is_back() {
        let t0 = later();
        let mut watch = LinkWatch::new(t0);
        assert!(!watch.observe(false, false, t0 + ms(500), "tray").offline);
        let refused = watch.observe(false, true, t0 + ms(1000), "tray");
        assert!(refused.offline);
        assert_eq!(refused.kind(), "refused");
        let cleared = watch.observe(false, false, t0 + ms(2000), "window");
        assert!(cleared.offline, "said once, kept until the link is back");
        assert_eq!(cleared.kind(), "down");
        assert!(!watch.observe(true, false, t0 + ms(2500), "tray").offline);
        // The next drop starts from scratch.
        assert!(!watch.observe(false, false, t0 + ms(10_000), "tray").offline);
    }

    /// «Нет связи» stands only where «Готов к подключению» would: the pause and someone in control
    /// outrank it, since a live session's video does not go through the server.
    #[test]
    fn the_pause_and_a_live_session_outrank_the_link() {
        let now = later();
        let mut watch = LinkWatch::new(now - ms(60_000));
        let down = watch.observe(false, false, now, "tray");
        assert!(down.offline);
        let up = [session("s1", "Вера", Some(5 * 60), now)];
        assert_eq!(
            presence(false, &up, now).with_link(&down),
            live(&["Вера"], 5 * 60)
        );
        assert_eq!(presence(true, &up, now).with_link(&down), Presence::Paused);
        assert_eq!(presence(true, &[], now).with_link(&down), Presence::Paused);
        assert_eq!(
            presence(false, &[], now).with_link(&down),
            Presence::Offline
        );
        // A session still connecting is nobody in control here, as everywhere in the tray.
        let connecting = [session("s1", "Вера", None, now)];
        assert_eq!(
            presence(false, &connecting, now).with_link(&down),
            Presence::Offline
        );
    }

    /// The tray and the window read one watch: a drop the window saw first is dated for the tray
    /// too.
    #[test]
    fn the_tray_and_the_window_share_one_watch() {
        let t0 = later();
        let shared = SharedLink::new(t0);
        let tray = shared.clone();
        shared.observe(true, false, t0 + ms(1000), "window");
        shared.observe(false, false, t0 + ms(10_000), "window");
        let link = tray.observe(false, false, t0 + ms(13_000), "tray");
        assert_eq!(link.down_for, Some(ms(3000)));
        assert!(link.offline);
    }
}
