//! Which keys reached the PC, for the log: one line a second while key messages come, and a flight
//! recorder of the last few, written out when the guard asks — the game's window stops taking input,
//! Alt+F4 is let through (`crate::game_guard`, game-only mode).
//!
//! ## Whose keys are named
//!
//! Only the viewer's own keys (`k.src`, [`KeySource`]): a key cell of the Mini App's keys layer or a
//! key of its keys sheet — cut-down binds and system keys, on which no password can be typed. The
//! rule: our own panel and game keys may be logged; input from the phone's system keyboard or from
//! the PC's physical keyboard never is.
//! Every other key — the viewer's physical keyboard, the phone's system keyboard, a tag this build
//! does not know — is counted and never named, and a modifier of that kind held under one of ours is
//! written `mod`; `text` never comes here at all. [`loggable`] is the same rule for the guard's own
//! lines, which name the keys of a system combination whoever pressed them.
//!
//! Nothing here reads the PC's keyboard: what is "held" is what the viewer pressed through us and has
//! not released, as the guard let it through.
//!
//! ## Logs
//!
//! `debug`: one `keys` line a second while key messages come, in any mode — ours by name as the PC
//! got them, each non-modifier with the modifiers down at its press (`AltLeft+KeyB×9`), cells and the
//! sheet apart, the rest as counts — and the recorder's one line when the guard asks for it. `trace`:
//! a recorder asked for with nothing in it. Nothing per key at `debug`.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use afklink_protocol::KeySource;

/// The summary line: one per this long while key messages come.
const SUMMARY_EVERY: Duration = Duration::from_secs(1);

/// Key events of ours the recorder keeps.
pub(crate) const RECORDED: usize = 12;

/// Distinct names one [`Names`] lists; the rest are counted in its `+N more`.
const NAMES_MAX: usize = 24;

/// Every name a viewer uses for a modifier key.
const MODIFIERS: [&str; 10] = [
    "ShiftLeft",
    "ShiftRight",
    "ControlLeft",
    "ControlRight",
    "AltLeft",
    "AltRight",
    "MetaLeft",
    "MetaRight",
    "OSLeft",
    "OSRight",
];

pub(crate) fn is_modifier(code: &str) -> bool {
    MODIFIERS.contains(&code)
}

/// The keys a system combination is made of — the modifiers, Tab, Escape and F4 (Win, Alt+Tab,
/// Alt+Esc, Ctrl+Esc, Ctrl+Shift+Esc, Alt+F4): named in the guard's protection lines whoever pressed
/// them, since they say which combination was judged, not what was typed.
fn is_system_key(code: &str) -> bool {
    is_modifier(code) || matches!(code, "Tab" | "Escape" | "F4")
}

/// One of the viewer's own keys (`k.src`: a key cell or the keys sheet).
pub(crate) fn ours(src: Option<KeySource>) -> bool {
    src.is_some_and(KeySource::is_ours)
}

/// `src` for a log line: `cell`, `sheet`, `unknown` (a tag this build does not know), or `untagged`
/// (the viewer's own keyboard, or an older viewer).
pub(crate) fn source_name(src: Option<KeySource>) -> &'static str {
    src.map_or("untagged", KeySource::as_str)
}

/// A key's name for a log line: its code when it is one of ours or a key of a system combination,
/// `-` otherwise — a key from the viewer's keyboard may be a password being typed.
pub(crate) fn loggable(code: &str, src: Option<KeySource>) -> &str {
    if ours(src) || is_system_key(code) {
        code
    } else {
        "-"
    }
}

/// Names with how often each came, in the order first seen, for a log field: `F1×2 F3`, `-` for
/// none. At most [`NAMES_MAX`] distinct ones; the rest are counted as `+N more`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Names {
    names: Vec<(String, u32)>,
    more: u32,
}

impl Names {
    pub(crate) fn add(&mut self, name: &str) {
        if let Some((_, n)) = self.names.iter_mut().find(|(have, _)| have == name) {
            *n += 1;
        } else if self.names.len() < NAMES_MAX {
            self.names.push((name.to_owned(), 1));
        } else {
            self.more += 1;
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.names.is_empty() && self.more == 0
    }
}

impl fmt::Display for Names {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("-");
        }
        let mut first = true;
        for (name, n) in &self.names {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            if *n == 1 {
                f.write_str(name)?;
            } else {
                write!(f, "{name}×{n}")?;
            }
        }
        if self.more > 0 {
            if !first {
                f.write_str(" ")?;
            }
            write!(f, "+{} more", self.more)?;
        }
        Ok(())
    }
}

/// What is down through us at one moment, for the guard's transition line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldNow {
    /// Keys that are not modifiers.
    pub(crate) keys: usize,
    pub(crate) mods: usize,
    /// Mouse buttons, on either path.
    pub(crate) buttons: u32,
    /// The held keys that are ours, by name (`-` for none).
    pub(crate) ours: String,
    /// The held keys that are not: counted only.
    pub(crate) other: usize,
}

/// The second's counts.
#[derive(Debug, Default)]
struct Second {
    since: Option<Instant>,
    /// Our fresh presses that reached the PC, as it got them, by where they came from.
    cells: Names,
    sheet: Names,
    /// Fresh presses of every other key that reached the PC.
    other: u32,
    /// Fresh presses the guard did not let through (blocked, or held back), any key.
    dropped: u32,
    /// Presses of a key already down through us (a held key's repeat), any key.
    repeats: u32,
    /// Releases, any key.
    ups: u32,
    /// The most keys and modifiers down through us at once.
    max_held: usize,
    /// Our presses of a non-modifier while a modifier and another non-modifier were already down:
    /// two fingers on two chords (F4 while the Alt+B cell is still held).
    under_held_mod: u32,
}

impl Second {
    fn any(&self) -> bool {
        !self.cells.is_empty()
            || !self.sheet.is_empty()
            || self.other + self.dropped + self.repeats + self.ups > 0
    }
}

/// One key event of ours the recorder keeps.
#[derive(Debug, Clone)]
struct Recorded {
    at: Instant,
    code: String,
    down: bool,
    src: KeySource,
    /// The guard let it through to the PC.
    passed: bool,
    /// Key messages not ours between the one kept before this and this one.
    untagged_before: u32,
}

/// The flight recorder: the last [`RECORDED`] key events of ours, and how many key messages not ours
/// came among them — never which.
#[derive(Debug, Default)]
struct Recorder {
    kept: VecDeque<Recorded>,
    /// Key messages not ours since the newest kept event (or since the recorder began).
    untagged_after: u32,
    untagged_last: Option<Instant>,
}

impl Recorder {
    fn ours(&mut self, code: &str, down: bool, src: KeySource, passed: bool, now: Instant) {
        if self.kept.len() == RECORDED {
            self.kept.pop_front();
        }
        self.kept.push_back(Recorded {
            at: now,
            code: code.to_owned(),
            down,
            src,
            passed,
            untagged_before: std::mem::take(&mut self.untagged_after),
        });
    }

    fn untagged(&mut self, now: Instant) {
        self.untagged_after = self.untagged_after.saturating_add(1);
        self.untagged_last = Some(now);
    }

    /// Key messages not ours since the oldest event kept (all of them while none is kept).
    fn untagged_since_oldest(&self) -> u32 {
        self.kept.iter().skip(1).fold(self.untagged_after, |n, r| {
            n.saturating_add(r.untagged_before)
        })
    }

    fn list(&self, now: Instant) -> String {
        let mut out = String::new();
        for (i, r) in self.kept.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            let ago = now.saturating_duration_since(r.at).as_millis();
            out.push_str(&format!(
                "{} {} {}{} -{ago}ms",
                r.src.as_str(),
                r.code,
                if r.down { "down" } else { "up" },
                if r.passed { "" } else { " dropped" }
            ));
        }
        out
    }
}

/// The key log: one per guard (one per process-wide backend), told of every key message of every
/// session with the guard's word on it.
#[derive(Debug, Default)]
pub(crate) struct KeyLog {
    /// What is down through us (DOM codes), and whose — the guard's own book of held keys, with
    /// where each came from.
    down: BTreeMap<String, Option<KeySource>>,
    second: Second,
    recorder: Recorder,
}

impl KeyLog {
    /// One key message the guard judged; `passed`: it went on to the PC.
    pub(crate) fn note(
        &mut self,
        code: &str,
        down: bool,
        src: Option<KeySource>,
        passed: bool,
        now: Instant,
    ) {
        self.flush_if_due(now);
        if self.second.since.is_none() {
            self.second.since = Some(now);
            // Keys held from before this second count towards its most.
            self.second.max_held = self.down.len();
        }
        let mine = src.filter(|s| s.is_ours());
        let repeat = down && self.down.contains_key(code);
        match mine {
            // A held key's repeat says nothing the press before it did not.
            Some(src) if !repeat => self.recorder.ours(code, down, src, passed, now),
            Some(_) => {}
            None => self.recorder.untagged(now),
        }
        if !down {
            self.second.ups += 1;
            if passed {
                self.down.remove(code);
            }
            return;
        }
        if repeat {
            self.second.repeats += 1;
            return;
        }
        if !passed {
            self.second.dropped += 1;
            return;
        }
        match mine {
            Some(src) => {
                let modifier = is_modifier(code);
                if !modifier
                    && self.down.keys().any(|k| is_modifier(k))
                    && self.down.keys().any(|k| !is_modifier(k) && k != code)
                {
                    self.second.under_held_mod += 1;
                }
                let name = if modifier {
                    code.to_owned()
                } else {
                    self.chord(code)
                };
                match src {
                    KeySource::Sheet => self.second.sheet.add(&name),
                    _ => self.second.cells.add(&name),
                }
            }
            None => self.second.other += 1,
        }
        // Defence in depth (KB-6): the guard books no more than this and drops a new key past it,
        // so a full book here is a flood the guard already warned of; the line's counts have it.
        if self.down.len() >= crate::game_guard::MAX_GUARD_KEYS {
            tracing::trace!("keys: the book of keys down is full: this one is not booked");
            return;
        }
        self.down.insert(code.to_owned(), src);
        self.second.max_held = self.second.max_held.max(self.down.len());
    }

    /// `code` as the PC gets it: the modifiers down through us, then the key — `AltLeft+KeyB`. A
    /// modifier that is not ours is `mod`.
    fn chord(&self, code: &str) -> String {
        let mut name = String::new();
        for (held, src) in &self.down {
            if is_modifier(held) {
                name.push_str(if ours(*src) { held } else { "mod" });
                name.push('+');
            }
        }
        name.push_str(code);
        name
    }

    #[cfg(test)]
    pub(crate) fn down_len(&self) -> usize {
        self.down.len()
    }

    /// Everything held was released (`ra`, the game lost the front, the session's end): nothing is
    /// down through us any more.
    pub(crate) fn released(&mut self) {
        self.down.clear();
    }

    /// What is down through us now, with `buttons` mouse buttons held on either path.
    pub(crate) fn held_now(&self, buttons: u32) -> HeldNow {
        let mods = self.down.keys().filter(|k| is_modifier(k)).count();
        let mut ours_held = Vec::new();
        let mut other = 0;
        for (code, src) in &self.down {
            if ours(*src) {
                ours_held.push(code.as_str());
            } else {
                other += 1;
            }
        }
        HeldNow {
            keys: self.down.len() - mods,
            mods,
            buttons,
            ours: if ours_held.is_empty() {
                "-".to_owned()
            } else {
                ours_held.join(" ")
            },
            other,
        }
    }

    /// The flight recorder's line: the last key events of ours, oldest first, and how many key
    /// messages not ours came among them.
    pub(crate) fn dump(&self, why: &'static str, now: Instant) {
        let untagged = self.recorder.untagged_since_oldest();
        if self.recorder.kept.is_empty() && untagged == 0 {
            tracing::trace!(why, "keys: recorder empty: no key message this session");
            return;
        }
        let last_ms = self.recorder.untagged_last.map_or_else(
            || "-".to_owned(),
            |at| now.saturating_duration_since(at).as_millis().to_string(),
        );
        tracing::debug!(
            target: crate::KEY_NAMES_TARGET,
            why,
            recorded = self.recorder.kept.len(),
            keys = %self.recorder.list(now),
            untagged_since_oldest = untagged,
            untagged_last_ms = %last_ms,
            "keys: the last of ours before this, oldest first, with how long before it (the \
             viewer's own keyboard only counted)"
        );
    }

    pub(crate) fn flush_if_due(&mut self, now: Instant) {
        if self
            .second
            .since
            .is_some_and(|t| now.saturating_duration_since(t) >= SUMMARY_EVERY)
        {
            self.flush(now, "second");
        }
    }

    pub(crate) fn flush(&mut self, now: Instant, why: &'static str) {
        let s = std::mem::take(&mut self.second);
        let Some(since) = s.since else {
            return;
        };
        if !s.any() {
            return;
        }
        tracing::debug!(
            target: crate::KEY_NAMES_TARGET,
            why,
            window_ms = now.saturating_duration_since(since).as_millis() as u64,
            cells = %s.cells,
            sheet = %s.sheet,
            other = s.other,
            dropped = s.dropped,
            repeats = s.repeats,
            ups = s.ups,
            max_held = s.max_held,
            under_held_mod = s.under_held_mod,
            "keys: presses that reached the PC — ours by name, with the modifiers down at each; \
             every other key only counted"
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::*;

    const CELL: Option<KeySource> = Some(KeySource::Cell);
    const SHEET: Option<KeySource> = Some(KeySource::Sheet);
    const UNKNOWN: Option<KeySource> = Some(KeySource::Unknown);

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn logged(f: impl FnOnce()) -> String {
        let capture = Capture::default();
        let writer = capture.clone();
        let ours = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .without_time()
                .with_writer(move || writer.clone())
                .finish(),
        );
        // See `fakerinput::typing::tests::logged`: a second live dispatcher makes tracing ask every
        // one of them.
        let _second = tracing::Dispatch::new(tracing_subscriber::registry());
        tracing::dispatcher::with_default(&ours, f);
        let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        log
    }

    struct Rig {
        log: KeyLog,
        t0: Instant,
        now: Instant,
    }

    impl Rig {
        fn new() -> Self {
            let t0 = Instant::now();
            Self {
                log: KeyLog::default(),
                t0,
                now: t0,
            }
        }

        fn at(&mut self, ms: u64) {
            self.now = self.t0 + Duration::from_millis(ms);
        }

        fn key(&mut self, code: &str, down: bool, src: Option<KeySource>) {
            self.log.note(code, down, src, true, self.now);
        }

        fn tap(&mut self, code: &str, src: Option<KeySource>) {
            self.key(code, true, src);
            self.key(code, false, src);
        }
    }

    /// The `l2` preset, as a real session pressed it: the Alt+B cell (Alt, then B, released in
    /// reverse), F-keys, and F4 pressed while the Alt+B chord was still held. The line names our keys
    /// as the PC got them, the second's most held and the overlap.
    #[test]
    fn a_second_of_our_keys_is_named_as_the_pc_got_them() {
        let log = logged(|| {
            let mut r = Rig::new();
            for _ in 0..9 {
                r.key("AltLeft", true, CELL);
                r.tap("KeyB", CELL);
                r.key("AltLeft", false, CELL);
            }
            r.tap("F4", CELL);
            // F4 while Alt+B is still held: two fingers, two chords.
            r.key("AltLeft", true, CELL);
            r.key("KeyB", true, CELL);
            r.key("F4", true, CELL);
            r.key("F4", false, CELL);
            r.key("KeyB", false, CELL);
            r.key("AltLeft", false, CELL);
            r.tap("Escape", SHEET);
            r.at(1_000);
            r.log.flush_if_due(r.now);
        });
        assert!(
            log.contains(r#"cells=AltLeft×10 AltLeft+KeyB×10 F4 AltLeft+F4"#),
            "{log}"
        );
        assert!(log.contains("sheet=Escape"), "{log}");
        assert!(log.contains("max_held=3"), "{log}");
        assert!(log.contains("under_held_mod=1"), "{log}");
        assert!(log.contains("other=0"), "{log}");
        assert!(log.contains("window_ms=1000"), "{log}");
        assert_eq!(log.matches("keys: presses").count(), 1, "{log}");
    }

    /// A key from the viewer's own keyboard (or a tag this build does not know) is counted, never
    /// named — not on its own, not as a modifier under one of ours.
    #[test]
    fn keys_that_are_not_ours_are_counted_and_never_named() {
        let log = logged(|| {
            let mut r = Rig::new();
            for code in ["KeyP", "KeyA", "KeyS", "Digit7"] {
                r.tap(code, None);
            }
            r.tap("KeyQ", UNKNOWN);
            // The viewer's Shift held under our F1.
            r.key("ShiftLeft", true, None);
            r.tap("F1", CELL);
            r.key("ShiftLeft", false, None);
            r.log.flush(r.now, "test");
            r.log.dump("test", r.now);
        });
        assert!(log.contains("cells=mod+F1"), "{log}");
        assert!(log.contains("other=6"), "{log}");
        for leak in ["KeyP", "KeyA", "KeyS", "Digit7", "KeyQ", "ShiftLeft"] {
            assert!(!log.contains(leak), "{leak} named:\n{log}");
        }
        assert!(log.contains("untagged_since_oldest=1"), "{log}");
    }

    /// Repeats of a held key, presses the guard dropped and releases are counted apart; nothing is
    /// written for a second without key messages.
    #[test]
    fn repeats_drops_and_releases_are_counted_and_a_quiet_second_writes_nothing() {
        let log = logged(|| {
            let mut r = Rig::new();
            r.key("KeyW", true, CELL);
            for _ in 0..5 {
                r.key("KeyW", true, CELL);
            }
            r.key("KeyW", false, CELL);
            r.log.note("Tab", true, CELL, false, r.now);
            r.log.note("Tab", false, CELL, false, r.now);
            r.at(1_200);
            r.log.flush_if_due(r.now);
            r.at(5_000);
            r.log.flush_if_due(r.now);
            r.log.flush(r.now, "test");
        });
        assert!(log.contains("cells=KeyW "), "{log}");
        assert!(log.contains("repeats=5"), "{log}");
        assert!(log.contains("dropped=1"), "{log}");
        assert!(log.contains("ups=2"), "{log}");
        assert_eq!(log.matches("keys: presses").count(), 1, "{log}");
    }

    /// The recorder keeps the last twelve of ours, oldest first, with how long before the moment each
    /// came and whether the guard let it through, and counts the other keys among them.
    #[test]
    fn the_recorder_keeps_the_last_of_ours_and_counts_the_rest() {
        let log = logged(|| {
            let mut r = Rig::new();
            for i in 0..10 {
                r.at(i * 100);
                r.tap("F1", CELL);
            }
            r.at(1_000);
            r.tap("KeyX", None);
            r.at(1_100);
            r.key("AltLeft", true, CELL);
            r.key("KeyB", true, CELL);
            r.at(1_500);
            r.log.note("F4", true, SHEET, false, r.now);
            r.at(1_640);
            r.log.dump("the game's window is not shown", r.now);
        });
        let line = log.lines().find(|l| l.contains("keys: the last")).unwrap();
        assert!(line.contains("recorded=12"), "{line}");
        assert!(
            line.contains("cell F1 down -740ms, cell F1 up -740ms, cell AltLeft down -540ms"),
            "{line}"
        );
        assert!(line.contains("sheet F4 down dropped -140ms"), "{line}");
        assert!(line.contains("untagged_since_oldest=2"), "{line}");
        assert!(line.contains("untagged_last_ms=640"), "{line}");
        assert!(!line.contains("KeyX"), "{line}");
        assert!(
            line.contains("why=\"the game's window is not shown\""),
            "{line}"
        );
    }

    #[test]
    fn an_empty_recorder_says_so_at_trace_only() {
        let log = logged(|| KeyLog::default().dump("test", Instant::now()));
        assert!(log.contains("TRACE"), "{log}");
        assert!(!log.contains("DEBUG"), "{log}");
    }

    /// What is held, for the guard's transition line: ours by name, the rest counted, modifiers apart;
    /// a release forgets it all.
    #[test]
    fn what_is_held_is_ours_by_name_and_the_rest_counted() {
        let mut r = Rig::new();
        r.key("AltLeft", true, CELL);
        r.key("KeyB", true, CELL);
        r.key("KeyW", true, None);
        r.key("ShiftLeft", true, None);
        assert_eq!(
            r.log.held_now(1),
            HeldNow {
                keys: 2,
                mods: 2,
                buttons: 1,
                ours: "AltLeft KeyB".into(),
                other: 2,
            }
        );
        r.log.released();
        assert_eq!(
            r.log.held_now(0),
            HeldNow {
                keys: 0,
                mods: 0,
                buttons: 0,
                ours: "-".into(),
                other: 0,
            }
        );
    }

    #[test]
    fn names_count_in_the_order_first_seen_and_stop_listing_at_their_bound() {
        let mut n = Names::default();
        assert_eq!(n.to_string(), "-");
        for name in ["F1", "F3", "F1"] {
            n.add(name);
        }
        assert_eq!(n.to_string(), "F1×2 F3");
        let mut many = Names::default();
        for i in 0..NAMES_MAX + 3 {
            many.add(&format!("K{i}"));
        }
        assert!(many.to_string().ends_with("K23 +3 more"), "{many}");
    }

    #[test]
    fn only_ours_and_the_keys_of_a_system_combination_are_loggable() {
        assert_eq!(loggable("KeyR", CELL), "KeyR");
        assert_eq!(loggable("KeyR", SHEET), "KeyR");
        assert_eq!(loggable("KeyR", None), "-");
        assert_eq!(loggable("KeyR", UNKNOWN), "-");
        for system in ["MetaLeft", "AltRight", "Tab", "Escape", "F4", "ControlLeft"] {
            assert_eq!(loggable(system, None), system);
        }
        assert_eq!(source_name(None), "untagged");
        assert_eq!(source_name(UNKNOWN), "unknown");
        assert_eq!(source_name(CELL), "cell");
    }

    // ---------- Every line that names a key goes under `KEY_NAMES_TARGET` ----------

    /// What makes a log call name a key: the producers of key names this workspace has —
    /// [`loggable`], the [`Names`] lists (`tap_keys`, `cells`, `sheet`, `held.ours`, the recorder's
    /// list), the language hotkey, a combination (`combo`, `ctrl_alt_del`). A new line that logs a
    /// key through any of them, anywhere, must carry the target.
    fn names_a_key(call: &str) -> bool {
        // The hotkey as a field (`hotkey = …`, `language_hotkey = …`), not the word in a message
        // («the language hotkey instead» names no key).
        const SOURCES: [&str; 10] = [
            "loggable(",
            "tap_keys",
            "held.ours",
            "recorder.list(",
            "cells = %",
            "sheet = %",
            "hotkey =",
            "hotkey.name(",
            "ctrl_alt_del",
            "key = %code",
        ];
        if SOURCES.iter().any(|s| call.contains(s)) || call.contains("key = code,") {
            return true;
        }
        // `combo` as a word (a field or the text), not `combos` (a count).
        call.match_indices("combo").any(|(at, _)| {
            let before = call[..at].chars().next_back();
            let after = call[at + "combo".len()..].chars().next();
            !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
    }

    /// Every `trace!` … `error!` call in `text` (not in a test module), with its line number.
    fn log_calls(text: &str) -> Vec<(usize, String)> {
        let code = text
            // An inline test module only: `mod tests;` declared at the top is another file.
            .find("#[cfg(test)]\nmod tests {")
            .map_or(text, |at| &text[..at]);
        let bytes = code.as_bytes();
        let mut calls = Vec::new();
        for level in ["trace!(", "debug!(", "info!(", "warn!(", "error!("] {
            for (at, _) in code.match_indices(level) {
                if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
                    continue;
                }
                let open = at + level.len() - 1;
                let Some(close) = closing_paren(bytes, open) else {
                    continue;
                };
                let line = code[..at].matches('\n').count() + 1;
                calls.push((line, code[open..=close].to_string()));
            }
        }
        calls
    }

    /// The `)` that closes the `(` at `open`, past string literals.
    fn closing_paren(bytes: &[u8], open: usize) -> Option<usize> {
        let mut depth = 0usize;
        let mut i = open;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                }
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !matches!(
                    name.as_str(),
                    "target" | "node_modules" | "contract" | "tests"
                ) {
                    rust_files(&path, out);
                }
            } else if name.ends_with(".rs") && name != "tests.rs" && !name.ends_with("_tests.rs") {
                out.push(path);
            }
        }
    }

    /// The privacy policy says an automatic report carries no pressed keys; the report leaves out
    /// the lines under [`crate::KEY_NAMES_TARGET`]. This holds every log call in the workspace that
    /// names a key to that target: a new one without it fails here.
    #[test]
    fn every_line_that_names_a_key_is_under_its_target() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        rust_files(&root.join("crates"), &mut files);
        rust_files(&root.join("app/src-tauri/src"), &mut files);
        assert!(files.len() > 50, "the workspace's sources: {}", files.len());
        let mut marked = 0;
        let mut missing = Vec::new();
        for file in &files {
            let text = std::fs::read_to_string(file)
                .expect("a source file")
                .replace("\r\n", "\n");
            for (line, call) in log_calls(&text) {
                if !names_a_key(&call) {
                    continue;
                }
                if call.contains("KEY_NAMES_TARGET") {
                    marked += 1;
                } else {
                    missing.push(format!("{}:{line}", file.display()));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "log lines that name a key without `target: KEY_NAMES_TARGET`: {missing:#?}"
        );
        assert!(marked >= 20, "the known key lines were found: {marked}");
        assert!(names_a_key("debug!(combo = %name, \"x\")"));
        assert!(!names_a_key("debug!(combos = c.combos, \"x\")"));
    }

    /// `call` without its string literals, and the literals' contents.
    fn split_strings(call: &str) -> (String, Vec<String>) {
        let mut code = String::new();
        let mut strings = Vec::new();
        let mut chars = call.chars();
        while let Some(c) = chars.next() {
            if c != '"' {
                code.push(c);
                continue;
            }
            let mut text = String::new();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        if let Some(escaped) = chars.next() {
                            text.push(escaped);
                        }
                    }
                    '"' => break,
                    _ => text.push(c),
                }
            }
            code.push_str("\"\"");
            strings.push(text);
        }
        (code, strings)
    }

    /// The fields a log call has that may carry a key: `code`, `key`, `vk`, `keys`, `k`,
    /// `key_code` — as `name = …`, `%name`, `?name`, or the bare `name,` shorthand (a positional
    /// argument too) — a `.code` / `.key` read off something (`msg.code`; not a method call,
    /// `e.code()`), or a `{code}`, `{key}`, `{k}`, `{key_code}` interpolated into its text.
    ///
    /// Not `name`: device, window, exe and display names are logged everywhere, and a combination's
    /// name goes in a `combo` field, which `names_a_key` catches.
    fn key_fields(call: &str) -> Vec<String> {
        let (code, strings) = split_strings(call);
        let mut found = Vec::new();
        let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
        for name in ["code", "key", "vk", "keys", "k", "key_code"] {
            for (at, _) in code.match_indices(name) {
                let before = code[..at].chars().next_back();
                let after = code[at + name.len()..].chars().next();
                if before.is_some_and(ident) || after.is_some_and(ident) {
                    continue;
                }
                let prev = code[..at].trim_end().chars().next_back();
                let next = code[at + name.len()..].trim_start();
                let assigned = next.starts_with('=') && !next.starts_with("==");
                // A closure's parameters (`|(f, k)| …`) are not arguments.
                let closure_param = next
                    .strip_prefix(')')
                    .is_some_and(|rest| rest.trim_start().starts_with('|'));
                let shorthand = matches!(prev, Some('%' | '?'))
                    || (matches!(prev, Some('(' | ','))
                        && matches!(next.chars().next(), Some(',' | ')'))
                        && !closure_param);
                // `msg.code`, `k.key`: read off something, not called.
                let read_off =
                    before == Some('.') && matches!(name, "code" | "key") && !next.starts_with('(');
                if read_off {
                    found.push(format!(".{name}"));
                } else if assigned || shorthand {
                    found.push(name.to_string());
                }
            }
        }
        for text in &strings {
            for pattern in [
                "{code}",
                "{code:",
                "{key}",
                "{key:",
                "{k}",
                "{k:",
                "{key_code}",
                "{key_code:",
            ] {
                if text.contains(pattern) {
                    found.push(pattern.to_string());
                }
            }
        }
        found.dedup();
        found
    }

    /// How many log calls say why a field that looks like a key's is none (`not-a-key-name:`):
    /// pinned, so a new exemption is a deliberate change here, read in review.
    const EXEMPTIONS: usize = 55;

    /// Wider than [`every_line_that_names_a_key_is_under_its_target`]: in the crates whose lines
    /// reach a log (input, core, transport, capture, clipboard, the CLI, the app), a log call with
    /// a field that may carry a key ([`key_fields`]) is under [`crate::KEY_NAMES_TARGET`] — or says
    /// why it names none with a `not-a-key-name:` comment inside it or on the line right above it
    /// (an error code, a registry key, a count). Their number is pinned ([`EXEMPTIONS`]).
    #[test]
    fn every_field_that_may_carry_a_key_is_marked_or_explained() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        for dir in [
            "crates/input/src",
            "crates/core/src",
            "crates/transport/src",
            "crates/capture/src",
            "crates/clipboard/src",
            "crates/agent/src",
            "app/src-tauri/src",
        ] {
            rust_files(&root.join(dir), &mut files);
        }
        let mut unexplained = Vec::new();
        let mut explained = 0;
        for file in &files {
            let text = std::fs::read_to_string(file)
                .expect("a source file")
                .replace("\r\n", "\n");
            let lines: Vec<&str> = text.lines().collect();
            for (line, call) in log_calls(&text) {
                let fields = key_fields(&call);
                if fields.is_empty() || call.contains("KEY_NAMES_TARGET") {
                    continue;
                }
                // The line right above the call's first line (`line` is 1-based).
                let above = line
                    .checked_sub(2)
                    .and_then(|i| lines.get(i))
                    .copied()
                    .unwrap_or("");
                if call.contains("not-a-key-name:") || above.contains("not-a-key-name:") {
                    explained += 1;
                } else {
                    unexplained.push(format!("{}:{line} {fields:?}", file.display()));
                }
            }
        }
        assert!(
            unexplained.is_empty(),
            "log calls with a field that may carry a key, neither under `KEY_NAMES_TARGET` nor \
             explained by a `not-a-key-name:` comment: {unexplained:#?}"
        );
        assert_eq!(
            explained, EXEMPTIONS,
            "the `not-a-key-name:` exemptions changed: check the new one, then pin the number"
        );
        // The detector itself, on shapes the workspace has.
        assert_eq!(key_fields("debug!(code = %code, \"x\")"), ["code"]);
        assert_eq!(key_fields("debug!(key = code, src)"), ["key"]);
        assert_eq!(key_fields("trace!(?vk, \"x\")"), ["vk"]);
        assert_eq!(key_fields("debug!(keys, \"x\")"), ["keys"]);
        assert_eq!(
            key_fields("debug!(%k, key_code = c, \"x\")"),
            ["k", "key_code"]
        );
        assert_eq!(key_fields("warn!(\"pressed {key} now\")"), ["{key}"]);
        assert_eq!(key_fields("warn!(\"pressed {k:?}\")"), ["{k:"]);
        assert_eq!(key_fields("debug!(\"x {}\", msg.code)"), [".code"]);
        assert_eq!(key_fields("debug!(x = a.key, \"y\")"), [".key"]);
        assert!(key_fields("debug!(error = e.code(), \"code = 1 key\")").is_empty());
        assert!(key_fields("debug!(fps = ?recent.map(|(f, k)| f + k), \"x\")").is_empty());
        assert!(key_fields("debug!(keyframe = k, codec = c, held_keys = 2, kb = 1)").is_empty());
    }
}
