//! The automatic report: its limits, its triggers, its flow, and its uploads through a local server.

use std::io::Read as _;
use std::path::PathBuf;
use std::sync::Mutex;

use super::super::package::{self, TailInputs};
use super::super::upload::test_server::{identity_with, local_client, serve};
use super::*;
use base64::Engine;

/// 2026-10-26T…, Unix ms.
const NOW: u64 = 1_793_016_260_000;
const MIN: u64 = 60_000;
const HOUR: u64 = 60 * MIN;
const DAY: u64 = 24 * HOUR;
const SESSION: &str = "3fa85f64-5717-4562-b3fc-2c963f66afa6";
const RECEIPT: &str = r#"{"report_id":"5e0b1c2d-3f4a-4b5c-8d6e-7f8091a2b3c4","bytes":22}"#;

fn fired(trigger: Trigger) -> Fired {
    Fired::new(trigger, NOW, "x", None)
}

fn mark(at: u64, trigger: Trigger) -> Mark {
    Mark {
        at,
        trigger: trigger.as_str().to_string(),
    }
}

fn limiter_with(sent: &[(u64, Trigger)]) -> Limiter {
    Limiter::new(LimiterRecord {
        sent: sent.iter().map(|&(at, t)| mark(at, t)).collect(),
        ..LimiterRecord::default()
    })
}

/// A folder of its own under the temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(what: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("afklink-auto-{what}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn at(tick_ms: u64, awake_ms: u64) -> Clocks {
    Clocks { tick_ms, awake_ms }
}

/// A report for `trigger` opened at mono 0 and packed: what `next_upload` sees.
fn with_one_ready(auto: &mut Auto, trigger: Trigger, to: Option<reqwest::Url>) {
    assert_eq!(auto.fire(fired(trigger), 0, NOW, true), Fire::Opened);
    let c = auto.take_due(MERGE_WINDOW_MS).expect("due");
    auto.add_ready(c, ready_for_tests(to), MERGE_WINDOW_MS);
}

// ---------- Limits ----------

#[test]
fn at_most_three_in_any_24_hours() {
    let mut limiter = limiter_with(&[
        (NOW, Trigger::Crash),
        (NOW + 20 * MIN, Trigger::Offline),
        (NOW + 40 * MIN, Trigger::Stall),
    ]);
    assert_eq!(
        limiter.check_new(Trigger::SessionFailed, NOW + 60 * MIN, &[]),
        Verdict::Block("per_window")
    );
    assert_eq!(
        limiter.check_new(Trigger::SessionFailed, NOW + DAY - 1, &[]),
        Verdict::Block("per_window"),
        "the window is rolling: the first is still in it"
    );
    assert_eq!(
        limiter.check_new(Trigger::SessionFailed, NOW + DAY, &[]),
        Verdict::Allow,
        "the first left the window"
    );
    // Reports opened and not yet sent count as if sent.
    let mut limiter = limiter_with(&[(NOW, Trigger::Crash)]);
    let reserved = [
        (Trigger::Offline, NOW + 20 * MIN),
        (Trigger::Stall, NOW + 40 * MIN),
    ];
    assert_eq!(
        limiter.check_new(Trigger::SessionFailed, NOW + 60 * MIN, &reserved),
        Verdict::Block("per_window")
    );
    assert_eq!(
        limiter.check_send(Trigger::SessionFailed, NOW + 60 * MIN),
        SendVerdict::Go,
        "sending counts the sent only"
    );
}

#[test]
fn at_most_two_of_one_trigger() {
    let mut limiter = limiter_with(&[(NOW, Trigger::Crash), (NOW + 20 * MIN, Trigger::Crash)]);
    assert_eq!(
        limiter.check_new(Trigger::Crash, NOW + 40 * MIN, &[]),
        Verdict::Block("per_trigger")
    );
    assert_eq!(
        limiter.check_new(Trigger::Stall, NOW + 40 * MIN, &[]),
        Verdict::Allow
    );
    assert_eq!(
        limiter.check_send(Trigger::Crash, NOW + 40 * MIN),
        SendVerdict::Block("per_trigger")
    );
}

#[test]
fn fifteen_minutes_between_two() {
    let mut limiter = limiter_with(&[(NOW, Trigger::Crash)]);
    assert_eq!(
        limiter.check_new(Trigger::Stall, NOW + 15 * MIN - 1, &[]),
        Verdict::Block("min_gap")
    );
    assert_eq!(
        limiter.check_new(Trigger::Stall, NOW + 15 * MIN, &[]),
        Verdict::Allow
    );
    assert_eq!(
        limiter.check_send(Trigger::Stall, NOW + 5 * MIN),
        SendVerdict::Wait { ms: 10 * MIN }
    );
    // A report waiting to be sent is the last one too.
    let mut empty = Limiter::default();
    assert_eq!(
        empty.check_new(Trigger::Stall, NOW + MIN, &[(Trigger::Crash, NOW)]),
        Verdict::Block("min_gap")
    );
}

/// A clock set back never unlocks a limit: what is in the future counts as now.
#[test]
fn a_clock_set_back_does_not_unlock_the_limits() {
    let mut limiter = limiter_with(&[
        (NOW, Trigger::Crash),
        (NOW + 20 * MIN, Trigger::Offline),
        (NOW + 40 * MIN, Trigger::Stall),
    ]);
    let back = NOW - 30 * DAY;
    assert_eq!(
        limiter.check_new(Trigger::SessionFailed, back, &[]),
        Verdict::Block("per_window")
    );
    assert_eq!(
        limiter.check_new(Trigger::SessionFailed, back + DAY - 1, &[]),
        Verdict::Block("per_window"),
        "a full day from the clock's new now"
    );
    let mut limiter = limiter_with(&[(NOW, Trigger::Crash)]);
    assert_eq!(
        limiter.check_new(Trigger::Stall, NOW - HOUR, &[]),
        Verdict::Block("min_gap")
    );
    assert_eq!(
        limiter.check_new(Trigger::Stall, NOW - HOUR + 15 * MIN, &[]),
        Verdict::Allow,
        "the gap counts from the clock's new now"
    );
}

/// A clock set a day or more ahead lets the window pass, as a day passing does — the agent cannot
/// tell the two apart; the server's own limit (3 a day by its clock) still holds.
#[test]
fn a_clock_set_a_day_ahead_counts_as_a_day_passing() {
    let mut limiter = limiter_with(&[
        (NOW, Trigger::Crash),
        (NOW + 20 * MIN, Trigger::Offline),
        (NOW + 40 * MIN, Trigger::Stall),
    ]);
    for i in 0..ATTEMPTS_PER_WINDOW as u64 {
        limiter.record_attempt(NOW + i);
    }
    let ahead = NOW + 40 * MIN + DAY;
    assert_eq!(
        limiter.check_new(Trigger::SessionFailed, ahead, &[]),
        Verdict::Allow
    );
    assert!(limiter.attempt_allowed(ahead));
    assert!(limiter.record.sent.is_empty() && limiter.record.attempts.is_empty());
}

#[test]
fn upload_attempts_are_capped_too() {
    let mut limiter = Limiter::default();
    for i in 0..ATTEMPTS_PER_WINDOW as u64 {
        assert!(limiter.attempt_allowed(NOW + i));
        limiter.record_attempt(NOW + i);
    }
    assert!(!limiter.attempt_allowed(NOW + HOUR));
    assert!(limiter.attempt_allowed(NOW + DAY + 10));
}

/// Written, read back by the next run: the limits hold across a restart.
#[test]
fn the_limits_survive_a_restart() {
    let dir = TempDir::new("persist");
    let path = dir.0.join(FILE_NAME);
    let mut limiter = Limiter::default();
    for (i, t) in [Trigger::Crash, Trigger::Offline, Trigger::Stall]
        .into_iter()
        .enumerate()
    {
        limiter.record_sent(t, NOW + i as u64 * 20 * MIN);
    }
    limiter.skip(Trigger::Stall);
    save_record(&path, &limiter.record).expect("written");
    assert!(!dir.0.join(format!("{FILE_NAME}.tmp")).exists(), "renamed");
    let mut next_run = Limiter::new(load_record(&path).expect("read"));
    assert_eq!(next_run.record, limiter.record);
    assert_eq!(
        next_run.check_new(Trigger::SessionFailed, NOW + HOUR, &[]),
        Verdict::Block("per_window")
    );
    assert_eq!(next_run.skipped().get("stall"), Some(&1));
    // None yet: an empty record, and the reports go.
    assert_eq!(
        load_record(&dir.0.join("none.json")),
        Ok(LimiterRecord::default())
    );
}

/// Fail closed: a record that cannot be read — garbled, too large, a folder in its place — closes
/// the reports for the run: nothing is opened, nothing is sent.
#[test]
fn a_record_that_cannot_be_read_closes_the_reports() {
    let dir = TempDir::new("garbled");
    let path = dir.0.join(FILE_NAME);
    std::fs::write(&path, b"{\"sent\": [{\"at\": \"x\"").expect("write");
    assert!(load_record(&path).is_err(), "garbled");
    std::fs::write(&path, vec![b' '; 70 * 1024]).expect("write");
    assert!(load_record(&path).is_err(), "too large");
    let folder = dir.0.join("folder.json");
    std::fs::create_dir_all(&folder).expect("dir");
    assert!(load_record(&folder).is_err(), "a folder");
    // What the task does with such an error: closed, and nothing goes.
    let mut auto = Auto::new(Limiter::default());
    auto.connected(at(0, 0), NOW, true);
    with_one_ready(&mut auto, Trigger::Stall, None);
    auto.close("the limits' record: garbled");
    assert_eq!(auto.pending_len(), 0, "what waited is dropped");
    assert_eq!(
        auto.fire(fired(Trigger::Crash), HOUR, NOW + HOUR, true),
        Fire::Closed
    );
    assert!(auto.take_due(DAY).is_none());
    assert!(auto.next_upload(DAY, NOW + DAY, true).is_none());
    assert_eq!(auto.next_wake(DAY, NOW + DAY), IDLE_WAKE_MS);
    // A trigger name this build does not know still counts toward the total.
    std::fs::write(
        &path,
        format!(
            r#"{{"sent":[{{"at":{NOW},"trigger":"later"}},{{"at":{},"trigger":"later"}},{{"at":{},"trigger":"later"}}]}}"#,
            NOW + 20 * MIN,
            NOW + 40 * MIN
        ),
    )
    .expect("write");
    let mut limiter = Limiter::new(load_record(&path).expect("read"));
    assert_eq!(
        limiter.check_new(Trigger::Crash, NOW + HOUR, &[]),
        Verdict::Block("per_window")
    );
}

/// A record that cannot be written — read-only, or its folder gone — is an error the task closes
/// the reports on.
#[test]
// The read-only attribute is cleared again so the test's folder can be removed (Windows).
#[allow(clippy::permissions_set_readonly_false)]
fn a_record_that_cannot_be_written_is_an_error() {
    let dir = TempDir::new("readonly");
    let path = dir.0.join(FILE_NAME);
    save_record(&path, &LimiterRecord::default()).expect("written");
    let mut permissions = std::fs::metadata(&path).expect("meta").permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&path, permissions.clone()).expect("read-only");
    let read_only = save_record(&path, &LimiterRecord::default());
    permissions.set_readonly(false);
    std::fs::set_permissions(&path, permissions).expect("writable again");
    assert!(read_only.is_err(), "a read-only record is not replaced");
    assert!(save_record(
        &dir.0.join("gone").join(FILE_NAME),
        &LimiterRecord::default()
    )
    .is_err());
}

#[test]
fn skipped_counts_are_cleared_once_told() {
    let mut limiter = Limiter::default();
    limiter.skip(Trigger::Stall);
    limiter.skip(Trigger::Stall);
    limiter.skip(Trigger::Offline);
    let told = limiter.skipped();
    limiter.skip(Trigger::Stall);
    limiter.told(&told);
    assert_eq!(
        limiter.skipped(),
        BTreeMap::from([("stall".to_string(), 1)]),
        "only what the sent report named"
    );
}

// ---------- Triggers ----------

/// Every failure on the agent's side fires; every other reason — `agent_disconnected` (that is
/// `offline`), the normal ends, the ones only received — does not.
#[test]
fn which_session_ends_are_failures() {
    let mut every: Vec<&str> = end_reason::AGENT_SENT.to_vec();
    every.extend(end_reason::local::ALL);
    every.extend([
        end_reason::UNKNOWN_SESSION,
        end_reason::OWNER_ENDED,
        end_reason::BLOCKED,
        "",
        "something_new",
    ]);
    let failures: Vec<&str> = every
        .iter()
        .copied()
        .filter(|r| session_failed(r))
        .collect();
    assert_eq!(failures, FAILED_REASONS.to_vec());
    assert!(!session_failed(end_reason::AGENT_DISCONNECTED));
    for normal in [
        end_reason::KILL_SWITCH,
        end_reason::PAUSED_ON_PC,
        end_reason::PEER_CLOSED,
        end_reason::AGENT_ENDED,
        end_reason::UNBOUND,
        end_reason::local::SERVER_ENDED,
    ] {
        let mut auto = Auto::new(Limiter::default());
        assert_eq!(
            auto.session_ended(SESSION, normal, 0, NOW, true),
            None,
            "{normal}"
        );
        assert!(auto.take_due(DAY).is_none(), "{normal}");
    }
    for reason in FAILED_REASONS {
        let mut auto = Auto::new(Limiter::default());
        assert_eq!(
            auto.session_ended(SESSION, reason, 0, NOW, true),
            Some(Fire::Opened),
            "{reason}"
        );
        let c = auto.take_due(MERGE_WINDOW_MS).expect("due");
        assert_eq!(c.first.trigger, Trigger::SessionFailed);
        assert_eq!(c.first.detail.as_deref(), Some(reason));
        assert_eq!(c.failed_session(), Some(SESSION));
        assert!(c.first.detail.as_deref().is_some_and(is_auto_detail));
    }
}

#[test]
fn how_the_last_run_ended_decides_a_crash_report() {
    let ended = |kind| AgentLastExit {
        kind,
        at: Some(NOW - HOUR),
    };
    let panic = crash_fired(ended(AgentExitKind::Panic), NOW).expect("a panic");
    assert_eq!(
        (panic.trigger, panic.detail.as_deref(), panic.at_ms),
        (Trigger::Crash, Some("panic"), NOW - HOUR)
    );
    let crash = crash_fired(ended(AgentExitKind::Crash), NOW).expect("a crash");
    assert_eq!(crash.detail.as_deref(), Some("crash"));
    for kind in [
        AgentExitKind::AppExit,
        AgentExitKind::UpdateExit,
        AgentExitKind::OsShutdown,
        AgentExitKind::Unknown,
    ] {
        assert_eq!(crash_fired(ended(kind), NOW), None, "{kind:?}");
    }
    // No time recorded: now stands in.
    let untimed = crash_fired(
        AgentLastExit {
            kind: AgentExitKind::Crash,
            at: None,
        },
        NOW,
    )
    .expect("a crash");
    assert_eq!(untimed.at_ms, NOW);
}

/// A crash is in the past: its report is packed at once, not after the merge window — a run that
/// dies again half a minute in still gets it out.
#[test]
fn a_crash_report_is_packed_at_once() {
    let mut auto = Auto::new(Limiter::default());
    let crash = crash_fired(
        AgentLastExit {
            kind: AgentExitKind::Crash,
            at: Some(NOW - HOUR),
        },
        NOW,
    )
    .expect("a crash");
    assert_eq!(auto.fire(crash, 5_000, NOW, true), Fire::Opened);
    let c = auto.take_due(5_000).expect("due at once");
    assert!(c.has_crash());
    // Any other trigger waits for its lines.
    auto.add_ready(c, ready_for_tests(None), 5_000);
    let mut other = Auto::new(Limiter::default());
    other.fire(fired(Trigger::Stall), 5_000, NOW, true);
    assert!(other.take_due(5_000 + MERGE_WINDOW_MS - 1).is_none());
    assert!(other.take_due(5_000 + MERGE_WINDOW_MS).is_some());
}

#[test]
fn outages_are_judged_on_awake_time() {
    let mut watch = OutageWatch::default();
    // A drop before the first connection is not an outage, nor is the first connection.
    watch.disconnected(at(0, 0));
    assert_eq!(watch.connected(at(500_000, 500_000)), Outage::FirstConnect);
    assert_eq!(watch.connected(at(510_000, 510_000)), Outage::NoneSeen);
    let base = 1_000_000;
    for (down_ms, want) in [
        (59_999, Outage::Short { ms: 59_999 }),
        (60_000, Outage::Long { ms: 60_000 }),
        (3_600_000, Outage::Long { ms: 3_600_000 }),
    ] {
        watch.disconnected(at(base, base));
        // A repeated drop keeps the first.
        watch.disconnected(at(base + 1_000, base + 1_000));
        assert_eq!(
            watch.connected(at(base + down_ms, base + down_ms)),
            want,
            "{down_ms}"
        );
    }
    // Two hours down, 30 s of it awake: the sleep explains it.
    watch.disconnected(at(base, base));
    assert_eq!(
        watch.connected(at(base + 2 * HOUR, base + 30_000)),
        Outage::Slept {
            ms: 2 * HOUR,
            slept_ms: 2 * HOUR - 30_000
        }
    );
    // Slept, then down ten more minutes awake: offline, timed on the awake part.
    watch.disconnected(at(base, base));
    assert_eq!(
        watch.connected(at(base + 2 * HOUR, base + 10 * MIN)),
        Outage::Long { ms: 10 * MIN }
    );
    // A second of jitter between the clocks is no sleep.
    watch.disconnected(at(base, base));
    assert_eq!(
        watch.connected(at(base + 90_000, base + 89_000)),
        Outage::Long { ms: 89_000 }
    );
    // Events missed: the outage running is not timed.
    watch.disconnected(at(base, base));
    watch.forget();
    assert_eq!(
        watch.connected(at(base + HOUR, base + HOUR)),
        Outage::NoneSeen
    );
    // Refused by the server meanwhile: its decision, not the link's fault — and only that outage.
    watch.disconnected(at(base, base));
    watch.refused(at(base + 1_000, base + 1_000));
    assert_eq!(
        watch.connected(at(base + HOUR, base + HOUR)),
        Outage::Refused { ms: HOUR }
    );
    watch.disconnected(at(base + 2 * HOUR, base + 2 * HOUR));
    assert_eq!(
        watch.connected(at(base + 3 * HOUR, base + 3 * HOUR)),
        Outage::Long { ms: HOUR }
    );
}

#[test]
fn an_outage_of_a_minute_or_more_opens_an_offline_report() {
    let mut auto = Auto::new(Limiter::default());
    assert_eq!(
        auto.connected(at(0, 0), NOW, true),
        None,
        "the first connection"
    );
    auto.disconnected(at(1_000, 1_000));
    assert_eq!(
        auto.connected(at(60_999, 60_999), NOW, true),
        None,
        "59.999 s"
    );
    auto.disconnected(at(100_000, 100_000));
    assert_eq!(
        auto.connected(at(100_000 + 75_400, 100_000 + 75_400), NOW, true),
        Some(Fire::Opened)
    );
    let c = auto.take_due(175_400 + MERGE_WINDOW_MS).expect("due");
    assert_eq!(c.first.trigger, Trigger::Offline);
    assert_eq!(c.first.detail.as_deref(), Some("outage_s=75"));
    // Slept through (30 s awake): nothing.
    let mut auto = Auto::new(Limiter::default());
    auto.connected(at(0, 0), NOW, true);
    auto.disconnected(at(1_000, 1_000));
    assert_eq!(auto.connected(at(HOUR, 31_000), NOW, true), None);
    assert!(auto.take_due(DAY).is_none());
}

/// Agent events missed (the broadcast lagged): the outage running is not timed, so no `offline`.
#[test]
fn missed_events_time_no_outage() {
    let mut auto = Auto::new(Limiter::default());
    auto.connected(at(0, 0), NOW, true);
    auto.disconnected(at(1_000, 1_000));
    auto.lagged();
    assert_eq!(auto.connected(at(HOUR, HOUR), NOW, true), None);
    assert!(auto.take_due(DAY).is_none());
}

/// Triggers in the window merge into the first; after it, a new one is a new report (and the
/// limits judge it).
#[test]
fn triggers_in_the_window_merge() {
    let mut auto = Auto::new(Limiter::default());
    assert_eq!(auto.fire(fired(Trigger::Stall), 0, NOW, true), Fire::Opened);
    assert_eq!(
        auto.session_ended(
            SESSION,
            end_reason::ENCODER_ERROR,
            10_000,
            NOW + 10_000,
            true
        ),
        Some(Fire::Merged)
    );
    assert_eq!(
        auto.fire(fired(Trigger::Crash), 20_000, NOW + 20_000, true),
        Fire::Merged
    );
    assert!(
        auto.take_due(MERGE_WINDOW_MS - 1).is_none(),
        "the window is open"
    );
    let c = auto.take_due(MERGE_WINDOW_MS).expect("due");
    assert_eq!(c.first.trigger, Trigger::Stall);
    assert!(c.has_crash());
    assert_eq!(c.failed_session(), Some(SESSION));
    assert_eq!(c.event_ms(), NOW + 10_000, "the newest event");
    let about = c.about(&BTreeMap::new());
    assert_eq!(about["merged"].as_array().map(Vec::len), Some(2));
    assert_eq!(about["merged"][0]["trigger"], "session_failed");
    // A new trigger now: a new report, but the one waiting to be sent is 40 s old — the gap.
    auto.add_ready(c, ready_for_tests(None), MERGE_WINDOW_MS);
    assert_eq!(
        auto.fire(fired(Trigger::Offline), 40_000, NOW + 40_000, true),
        Fire::Skipped("min_gap")
    );
    assert_eq!(auto.limiter.skipped().get("offline"), Some(&1));
    assert!(auto.take_dirty());
}

// ---------- The log ----------

/// The log lets reports through only when it writes and the stored choice is not «Выключены» —
/// `RUST_LOG` keeping it on included.
#[test]
fn the_log_lets_reports_through_only_when_it_is_on() {
    assert!(log_lets_auto(true, Some(LogLevel::Debug), LogLevel::Debug));
    assert!(log_lets_auto(true, None, LogLevel::Info));
    assert!(!log_lets_auto(
        false,
        Some(LogLevel::Debug),
        LogLevel::Debug
    ));
    assert!(
        !log_lets_auto(true, Some(LogLevel::Off), LogLevel::Off),
        "chosen off"
    );
    assert!(
        !log_lets_auto(true, Some(LogLevel::Off), LogLevel::Debug),
        "chosen off while RUST_LOG keeps it on"
    );
    assert!(!log_lets_auto(true, None, LogLevel::Off));
}

/// The log off: no trigger is recorded, and what waits is dropped, never sent.
#[test]
fn with_the_log_off_nothing_is_recorded_or_sent() {
    let mut auto = Auto::new(Limiter::default());
    assert_eq!(
        auto.fire(fired(Trigger::Crash), 0, NOW, false),
        Fire::Ignored
    );
    assert_eq!(
        auto.session_ended(SESSION, end_reason::PEER_ERROR, 0, NOW, false),
        Some(Fire::Ignored)
    );
    assert!(auto.take_due(DAY).is_none());
    assert!(!auto.take_dirty());
    assert_eq!(
        auto.limiter.record,
        LimiterRecord::default(),
        "not even counted"
    );
    // Packed while it was on, then the log went off.
    with_one_ready(&mut auto, Trigger::Crash, None);
    auto.connected(at(MERGE_WINDOW_MS, MERGE_WINDOW_MS), NOW, false);
    assert!(auto.next_upload(MERGE_WINDOW_MS, NOW, false).is_none());
    assert_eq!(auto.pending_len(), 0, "dropped");
    assert!(auto.next_upload(MERGE_WINDOW_MS, NOW, true).is_none());
}

/// Off, then on again between two looks: what was opened or packed before the «off» is dropped
/// all the same; an upload already on its way finishes.
#[test]
fn turning_the_log_off_drops_what_was_opened_before() {
    let mut auto = Auto::new(Limiter::default());
    auto.connected(at(0, 0), NOW, true);
    with_one_ready(&mut auto, Trigger::Stall, None);
    assert_eq!(
        auto.fire(fired(Trigger::Crash), HOUR, NOW + HOUR, true),
        Fire::Opened
    );
    auto.observe_log(1);
    assert_eq!(auto.pending_len(), 0, "the packed one dropped");
    assert!(auto.take_due(DAY).is_none(), "the open one dropped");
    // One packed under the old generation and handed back after the flip: dropped too.
    let mut auto = Auto::new(Limiter::default());
    auto.fire(fired(Trigger::Crash), 0, NOW, true);
    let c = auto.take_due(0).expect("due");
    auto.observe_log(1);
    auto.add_ready(c, ready_for_tests(None), 0);
    assert_eq!(auto.pending_len(), 0);
    // An upload on its way when the log goes off: named to be stopped, its report dropped; if it
    // got through all the same, it still counts.
    let mut auto = Auto::new(Limiter::default());
    auto.connected(at(0, 0), NOW, true);
    with_one_ready(&mut auto, Trigger::Stall, None);
    let up = auto.next_upload(MERGE_WINDOW_MS, NOW, true).expect("goes");
    assert_eq!(auto.observe_log(1), Some(up.id), "the upload to stop");
    assert_eq!(auto.pending_len(), 0, "its report dropped");
    auto.upload_done(
        up.id,
        &upload::Outcome::Sent { receipt: None },
        MERGE_WINDOW_MS,
        NOW,
    );
    assert_eq!(auto.limiter.record.sent.len(), 1, "got through: counted");
    // Stopped (the guard's failure): nothing counted, nothing retried.
    let mut stopped = Auto::new(Limiter::default());
    stopped.connected(at(0, 0), NOW, true);
    with_one_ready(&mut stopped, Trigger::Stall, None);
    let up = stopped
        .next_upload(MERGE_WINDOW_MS, NOW, true)
        .expect("goes");
    assert_eq!(stopped.observe_log(1), Some(up.id));
    stopped.upload_done(
        up.id,
        &upload::Outcome::Failed(upload::Failure::Network("stopped".into())),
        MERGE_WINDOW_MS,
        NOW,
    );
    assert!(stopped.limiter.record.sent.is_empty());
    assert!(stopped.next_upload(DAY, NOW + DAY, true).is_none());
    // New reports under the new generation go as usual.
    assert_eq!(
        auto.fire(fired(Trigger::Crash), HOUR, NOW + HOUR, true),
        Fire::Opened
    );
    let c = auto.take_due(HOUR).expect("due");
    auto.add_ready(c, ready_for_tests(None), HOUR);
    assert_eq!(auto.pending_len(), 1);
}

// ---------- Waiting, and never spinning ----------

#[test]
fn reports_wait_for_the_connection_and_expire() {
    let mut auto = Auto::new(Limiter::default());
    with_one_ready(&mut auto, Trigger::Crash, None);
    assert!(
        auto.next_upload(MERGE_WINDOW_MS, NOW, true).is_none(),
        "not connected"
    );
    assert_eq!(auto.waiting(), Some("not_connected"));
    assert_eq!(auto.next_wake(MERGE_WINDOW_MS, NOW), BUSY_WAKE_MS);
    assert!(auto
        .next_upload(MERGE_WINDOW_MS + PENDING_TTL_MS, NOW + PENDING_TTL_MS, true)
        .is_none());
    assert_eq!(auto.pending_len(), 0, "expired");
}

/// A retry time that has passed while the report cannot go (disconnected) does not make the task
/// spin: it wakes at the busy pace.
#[test]
fn a_past_retry_time_while_disconnected_is_no_spin() {
    let mut auto = Auto::new(Limiter::default());
    auto.connected(at(0, 0), NOW, true);
    with_one_ready(&mut auto, Trigger::Stall, None);
    let up = auto.next_upload(MERGE_WINDOW_MS, NOW, true).expect("goes");
    auto.upload_done(
        up.id,
        &upload::Outcome::Failed(upload::Failure::Network("x".into())),
        MERGE_WINDOW_MS,
        NOW,
    );
    auto.disconnected(at(MERGE_WINDOW_MS, MERGE_WINDOW_MS));
    let later = MERGE_WINDOW_MS + RETRY_AFTER_FAILURE_MS + 1;
    assert!(auto.next_upload(later, NOW + later, true).is_none());
    assert_eq!(auto.waiting(), Some("not_connected"));
    assert_eq!(auto.next_wake(later, NOW + later), BUSY_WAKE_MS);
    // Connected: still waiting for the retry time — woken exactly then.
    let mut auto = Auto::new(Limiter::default());
    auto.connected(at(0, 0), NOW, true);
    with_one_ready(&mut auto, Trigger::Stall, None);
    let up = auto.next_upload(MERGE_WINDOW_MS, NOW, true).expect("goes");
    auto.upload_done(
        up.id,
        &upload::Outcome::Failed(upload::Failure::Network("x".into())),
        MERGE_WINDOW_MS,
        NOW,
    );
    assert!(auto.next_upload(MERGE_WINDOW_MS + 1, NOW, true).is_none());
    assert_eq!(
        auto.next_wake(MERGE_WINDOW_MS + 1, NOW),
        BUSY_WAKE_MS.min(RETRY_AFTER_FAILURE_MS - 1)
    );
    // A wait shorter than the busy pace: woken exactly when it ends.
    let mut auto = Auto::new(Limiter::default());
    auto.connected(at(0, 0), NOW, true);
    with_one_ready(&mut auto, Trigger::Stall, None);
    let up = auto.next_upload(MERGE_WINDOW_MS, NOW, true).expect("goes");
    auto.upload_done(
        up.id,
        &upload::Outcome::TooOften {
            retry_after_s: Some(20),
        },
        MERGE_WINDOW_MS,
        NOW,
    );
    assert!(auto.next_upload(MERGE_WINDOW_MS + 1, NOW, true).is_none());
    assert_eq!(auto.next_wake(MERGE_WINDOW_MS + 1, NOW), 19_999);
}

/// Out of upload attempts for the day, across several reports: nothing goes, the task wakes at the
/// busy pace (no spin), and a day later the report goes.
#[test]
fn out_of_attempts_across_reports_is_no_spin() {
    // Eight attempts of other reports in the last day, the oldest leaving the window in 10 min.
    let mut limiter = Limiter::default();
    for i in 0..ATTEMPTS_PER_WINDOW as u64 - 1 {
        limiter.record_attempt(NOW - DAY + 10 * MIN + i);
    }
    let mut auto = Auto::new(limiter);
    auto.connected(at(0, 0), NOW, true);
    with_one_ready(&mut auto, Trigger::Stall, None);
    let up = auto
        .next_upload(MERGE_WINDOW_MS, NOW, true)
        .expect("the last attempt of the day");
    auto.upload_done(
        up.id,
        &upload::Outcome::Failed(upload::Failure::Network("x".into())),
        MERGE_WINDOW_MS,
        NOW,
    );
    let later = MERGE_WINDOW_MS + RETRY_AFTER_FAILURE_MS;
    assert!(auto.next_upload(later, NOW + later, true).is_none());
    assert_eq!(auto.waiting(), Some("out_of_attempts"));
    assert_eq!(auto.next_wake(later, NOW + later), BUSY_WAKE_MS);
    assert!(
        auto.next_upload(later + 1, NOW + later + 1, true).is_none(),
        "still not"
    );
    // Those eight left the window: it goes (still well inside its six hours).
    assert!(auto
        .next_upload(later + 15 * MIN, NOW + 20 * MIN, true)
        .is_some());
}

/// The gap since the last report sent, in the flow: the next waits, woken when the gap ends.
#[test]
fn the_gap_holds_the_next_report_until_it_ends() {
    let mut auto = Auto::new(limiter_with(&[(NOW, Trigger::Crash)]));
    auto.connected(at(0, 0), NOW, true);
    // Opened 16 min after the last one was seen as the limit's reservation would not allow: here
    // it slipped in (made directly), and the send-time check holds it.
    let c = Collecting {
        id: 7,
        first: fired(Trigger::Stall),
        merged: Vec::new(),
        merged_dropped: 0,
        due_ms: 0,
        seen_unix_ms: NOW,
        generation: 0,
    };
    auto.add_ready(c, ready_for_tests(None), 0);
    assert!(auto.next_upload(0, NOW + 5 * MIN, true).is_none());
    assert_eq!(auto.waiting(), Some("retry_or_gap_wait"));
    assert_eq!(auto.next_wake(0, NOW + 5 * MIN), BUSY_WAKE_MS.min(10 * MIN));
    assert!(auto
        .next_upload(10 * MIN - 1, NOW + 15 * MIN - 1, true)
        .is_none());
    assert!(auto.next_upload(10 * MIN, NOW + 15 * MIN, true).is_some());
}

#[test]
fn an_oversize_report_is_never_sent() {
    let mut auto = Auto::new(Limiter::default());
    auto.fire(fired(Trigger::Crash), 0, NOW, true);
    let c = auto.take_due(MERGE_WINDOW_MS).expect("due");
    let mut ready = ready_for_tests(None);
    ready.prepared.body = Bytes::from(vec![0u8; limits::AGENT_AUTO_BODY_BYTES as usize + 1]);
    auto.add_ready(c, ready, MERGE_WINDOW_MS);
    auto.connected(at(0, 0), NOW, true);
    assert!(auto.next_upload(MERGE_WINDOW_MS, NOW, true).is_none());
    assert_eq!(auto.pending_len(), 0);
}

/// An upload's task that panics or is dropped still hands an outcome back: a network failure, so
/// uploads do not stop for the rest of the run.
#[test]
fn an_upload_that_dies_still_hands_back_an_outcome() {
    let (tx, mut rx) = mpsc::channel(4);
    OutcomeGuard::new(3, tx.clone()).send(upload::Outcome::Sent { receipt: None });
    assert_eq!(
        rx.try_recv().expect("sent"),
        (3, upload::Outcome::Sent { receipt: None })
    );
    drop(OutcomeGuard::new(4, tx.clone()));
    let (id, outcome) = rx.try_recv().expect("dropped");
    assert_eq!(id, 4);
    assert!(matches!(
        outcome,
        upload::Outcome::Failed(upload::Failure::Network(_))
    ));
    let guard = OutcomeGuard::new(5, tx);
    let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = guard;
        std::panic::resume_unwind(Box::new("the upload's task died"));
    }));
    assert!(died.is_err());
    assert_eq!(rx.try_recv().map(|(id, _)| id), Ok(5));
    // And the state takes it as such: free for the next attempt.
    let mut auto = Auto::new(Limiter::default());
    auto.connected(at(0, 0), NOW, true);
    with_one_ready(&mut auto, Trigger::Stall, None);
    let up = auto.next_upload(MERGE_WINDOW_MS, NOW, true).expect("goes");
    auto.upload_done(
        up.id,
        &upload::Outcome::Failed(upload::Failure::Network("task ended".into())),
        MERGE_WINDOW_MS,
        NOW,
    );
    assert!(auto
        .next_upload(MERGE_WINDOW_MS + RETRY_AFTER_FAILURE_MS, NOW, true)
        .is_some());
}

// ---------- Packing and uploading ----------

/// A small real package of a logs folder: the system log and the failed session's file.
fn small_package(dir: &TempDir, session: Option<&str>) -> package::Package {
    let logs = dir.0.join("logs");
    let sessions = logs.join("sessions");
    std::fs::create_dir_all(&sessions).expect("dirs");
    std::fs::write(
        logs.join("system.log"),
        // A minute before NOW (12:04:20 UTC): inside the half hour, not after packing.
        "2026-10-26T12:03:20.000001Z  INFO a: line\n",
    )
    .expect("write");
    if let Some(id) = session {
        std::fs::write(
            sessions.join(format!("2026-10-26_16-24-00_{}.log", &id[..8])),
            format!(
                "2026-10-26T12:03:20.000001Z  INFO afklink_app_lib::log_file: session log opened \
                 session={id} build=\"0.7.2\"\n\
                 2026-10-26T12:03:21.000001Z  INFO afklink_core::agent: the session's line\n"
            ),
        )
        .expect("write");
    }
    package::build_tail(TailInputs {
        logs_dir: Some(logs),
        config: package::ConfigSource {
            path: None,
            in_memory: json!({ "device_id": "d" }),
        },
        generated: vec![("build.json".into(), b"{}".to_vec())],
        about: Map::new(),
        now_unix_ms: NOW,
        event_unix_ms: NOW,
        cap: package::AUTO_CAP,
        system_raw: package::AUTO_SYSTEM_RAW,
        session: session.map(str::to_string),
        session_raw: package::AUTO_SESSION_RAW,
        previous_end: None,
        this_run_raw: package::AUTO_THIS_RUN_RAW,
    })
    .expect("packs")
}

fn build() -> BuildInfo {
    BuildInfo::from_stamp(
        "0.7.2",
        "61132f7a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e",
        "0",
        "2026-10-26T09:30:00Z",
        "release",
    )
}

fn endpoint() -> reqwest::Url {
    reqwest::Url::parse("http://127.0.0.1:9/api/diagnostics/agent").expect("url")
}

/// A report ready to send, of a package of nothing much, to `to` (or a dead address).
fn ready_for_tests(to: Option<reqwest::Url>) -> Ready {
    let dir = TempDir::new("ready");
    let mut auto = Auto::new(Limiter::default());
    auto.fire(fired(Trigger::Stall), 0, NOW, true);
    let c = auto.take_due(MERGE_WINDOW_MS).expect("due");
    ready(
        &build(),
        "a3f1c2d4-5b6e-4f7a-8c9d-0e1f2a3b4c5d",
        to.unwrap_or_else(endpoint),
        &c,
        small_package(&dir, None),
        Meta {
            session_ids: Vec::new(),
            os: None,
            now_ms: NOW,
        },
        BTreeMap::new(),
    )
    .expect("ready")
}

fn meta_of(prepared: &upload::Prepared) -> Value {
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&prepared.meta_header)
        .expect("base64url");
    serde_json::from_slice(&json).expect("json")
}

/// The metadata of an automatic report is the contract fixture's shape: the same keys, `auto` with
/// its trigger, time and detail, the failed session first.
#[test]
fn the_metadata_carries_auto_as_the_contract_has_it() {
    let dir = TempDir::new("meta");
    let mut auto = Auto::new(Limiter::default());
    auto.session_ended(SESSION, end_reason::ENCODER_ERROR, 0, NOW, true);
    let c = auto.take_due(MERGE_WINDOW_MS).expect("due");
    let package = small_package(&dir, Some(SESSION));
    assert!(package
        .files
        .iter()
        .any(|f| f.name == format!("sessions/2026-10-26_16-24-00_{}.log", &SESSION[..8])));
    let ready = ready(
        &build(),
        "a3f1c2d4-5b6e-4f7a-8c9d-0e1f2a3b4c5d",
        endpoint(),
        &c,
        package,
        Meta {
            session_ids: vec![SESSION.to_string()],
            os: Some("Windows 10 Pro 22H2 (19045)".into()),
            now_ms: NOW + 1,
        },
        BTreeMap::new(),
    )
    .expect("ready");
    let meta = meta_of(&ready.prepared);
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../contract/packages/protocol/fixtures/rest/diagnostics_agent_meta_auto.json",
        ))
        .expect("the contract submodule"),
    )
    .expect("json");
    let keys = |v: &Value| {
        let mut keys: Vec<String> = v.as_object().expect("object").keys().cloned().collect();
        keys.sort();
        keys
    };
    assert_eq!(keys(&meta), keys(&fixture));
    assert_eq!(keys(&meta["auto"]), keys(&fixture["auto"]));
    assert_eq!(keys(&meta["build"]), keys(&fixture["build"]));
    assert_eq!(meta["auto"]["trigger"], "session_failed");
    assert_eq!(meta["auto"]["detail"], "encoder_error");
    assert_eq!(meta["auto"]["at"], NOW);
    assert_eq!(meta["session_ids"][0], SESSION);
    assert!(meta.get("comment").is_none());
    let typed: AgentDiagnosticsMeta = serde_json::from_value(meta).expect("the contract's type");
    assert_eq!(typed.auto, Some(c.first.marker()));
    assert!(ready.prepared.body.len() as u64 <= limits::AGENT_AUTO_BODY_BYTES);
}

/// One upload as the task makes it (`AfterBody::Stop`), to `endpoints`, with the clock at `now`
/// and the stall limits `stall`.
fn upload_to(
    up: &Upload,
    endpoints: &[reqwest::Url],
    now: u64,
    stall: upload::Stall,
) -> upload::Outcome {
    let identity = identity_with("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=");
    let client = local_client();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut n = 0u8;
    runtime.block_on(upload::send_any(
        &client,
        &up.prepared,
        endpoints,
        &identity,
        || now,
        || {
            n = n.wrapping_add(1);
            [n; 16]
        },
        stall,
        upload::AfterBody::Stop,
    ))
}

fn upload_now(up: &Upload, now: u64) -> upload::Outcome {
    upload_to(
        up,
        std::slice::from_ref(&up.prepared.endpoint),
        now,
        upload::STALL,
    )
}

/// An auto with one report ready for `to`, connected.
fn one_ready(to: reqwest::Url) -> Auto {
    let mut auto = Auto::new(Limiter::default());
    auto.connected(at(0, 0), NOW, true);
    with_one_ready(&mut auto, Trigger::Stall, Some(to));
    auto
}

/// Sent: recorded in the limits, the server saw the signed `auto` metadata.
#[test]
fn a_report_goes_through_the_local_server() {
    let (url, seen) = serve(vec![("201 Created", String::new(), RECEIPT.into())]);
    let mut auto = one_ready(url);
    let up = auto.next_upload(MERGE_WINDOW_MS, NOW, true).expect("goes");
    assert!(
        auto.next_upload(MERGE_WINDOW_MS, NOW, true).is_none(),
        "one at a time"
    );
    assert_eq!(
        auto.next_wake(MERGE_WINDOW_MS, NOW),
        UPLOAD_WATCH_MS,
        "watched every second while on its way"
    );
    let outcome = upload_now(&up, NOW);
    assert!(
        matches!(outcome, upload::Outcome::Sent { .. }),
        "{outcome:?}"
    );
    auto.upload_done(up.id, &outcome, MERGE_WINDOW_MS, NOW);
    assert_eq!(auto.pending_len(), 0);
    assert_eq!(auto.limiter.record.sent, vec![mark(NOW, Trigger::Stall)]);
    assert!(auto.take_dirty());
    let seen = afklink_core::lock(&seen).clone();
    assert_eq!(seen.len(), 1);
    let header = seen[0].header("x-afklink-meta").expect("meta header");
    assert_eq!(header, up.prepared.meta_header);
    assert_eq!(meta_of(&up.prepared)["auto"]["trigger"], "stall");
    assert_eq!(seen[0].body, up.prepared.body.to_vec());
}

/// `429` with a short `Retry-After`: once more after it. A long one, or a second `429`: dropped.
#[test]
fn too_often_is_retried_once_after_its_wait() {
    let (url, seen) = serve(vec![
        (
            "429 Too Many Requests",
            "Retry-After: 60\r\n".into(),
            r#"{"error":"rate_limited"}"#.into(),
        ),
        (
            "429 Too Many Requests",
            "Retry-After: 60\r\n".into(),
            r#"{"error":"rate_limited"}"#.into(),
        ),
    ]);
    let mut auto = one_ready(url);
    let up = auto.next_upload(MERGE_WINDOW_MS, NOW, true).expect("goes");
    let outcome = upload_now(&up, NOW);
    assert_eq!(
        outcome,
        upload::Outcome::TooOften {
            retry_after_s: Some(60)
        }
    );
    auto.upload_done(up.id, &outcome, MERGE_WINDOW_MS, NOW);
    assert!(
        auto.next_upload(MERGE_WINDOW_MS + 59_999, NOW, true)
            .is_none(),
        "waits"
    );
    let up = auto
        .next_upload(MERGE_WINDOW_MS + 60_000, NOW + 60_000, true)
        .expect("once more");
    let outcome = upload_now(&up, NOW + 60_000);
    auto.upload_done(up.id, &outcome, MERGE_WINDOW_MS + 60_000, NOW + 60_000);
    assert_eq!(auto.pending_len(), 0, "a second 429: dropped");
    assert!(
        auto.limiter.record.sent.is_empty(),
        "nothing recorded as sent"
    );
    assert_eq!(afklink_core::lock(&seen).len(), 2);

    // A wait longer than an hour: dropped at once.
    let mut auto = one_ready(endpoint());
    let up = auto.next_upload(MERGE_WINDOW_MS, NOW, true).expect("goes");
    auto.upload_done(
        up.id,
        &upload::Outcome::TooOften {
            retry_after_s: Some(7200),
        },
        MERGE_WINDOW_MS,
        NOW,
    );
    assert_eq!(auto.pending_len(), 0);
}

/// Any other refusal — `400`, `413`, the clock refused — drops the report: one request, no retry,
/// nothing recorded as sent.
#[test]
fn a_refusal_drops_the_report_without_a_retry() {
    for (status, body) in [
        ("400 Bad Request", r#"{"error":"bad_meta"}"#),
        ("413 Payload Too Large", r#"{"error":"payload_too_large"}"#),
        ("401 Unauthorized", r#"{"error":"clock_skew"}"#),
    ] {
        let (url, seen) = serve(vec![
            (status, String::new(), body.into()),
            (status, String::new(), body.into()),
        ]);
        let mut auto = one_ready(url);
        let up = auto.next_upload(MERGE_WINDOW_MS, NOW, true).expect("goes");
        let outcome = upload_now(&up, NOW);
        assert!(
            matches!(outcome, upload::Outcome::Failed(_)),
            "{status}: {outcome:?}"
        );
        auto.upload_done(up.id, &outcome, MERGE_WINDOW_MS, NOW);
        assert_eq!(auto.pending_len(), 0, "{status}: dropped");
        assert!(auto.limiter.record.sent.is_empty(), "{status}");
        assert!(
            auto.next_upload(MERGE_WINDOW_MS + DAY, NOW + MIN, true)
                .is_none(),
            "{status}: no retry"
        );
        assert_eq!(afklink_core::lock(&seen).len(), 1, "{status}: one request");
    }
}

/// No answer before the body went: tried again at the next reconnect or after 5 min, three
/// attempts in all, then dropped.
#[test]
fn no_answer_is_retried_three_times_then_dropped() {
    let dead = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        reqwest::Url::parse(&format!("http://{addr}/api/diagnostics/agent")).expect("url")
    };
    let mut auto = one_ready(dead);
    let mut mono = MERGE_WINDOW_MS;
    let mut attempts = 0;
    while let Some(up) = auto.next_upload(mono, NOW + mono, true) {
        attempts += 1;
        let outcome = upload_now(&up, NOW + mono);
        assert!(
            matches!(
                outcome,
                upload::Outcome::Failed(upload::Failure::Network(_))
            ),
            "{outcome:?}"
        );
        auto.upload_done(up.id, &outcome, mono, NOW + mono);
        if attempts == 1 {
            // Not before 5 min — unless the link comes back.
            assert!(auto.next_upload(mono + 1_000, NOW + mono, true).is_none());
            auto.disconnected(at(mono, mono));
            auto.connected(at(mono + 2_000, mono + 2_000), NOW + mono, true);
            mono += 2_000;
        } else {
            mono += RETRY_AFTER_FAILURE_MS;
        }
        assert!(attempts <= MAX_ATTEMPTS, "never more than three");
    }
    assert_eq!(attempts, MAX_ATTEMPTS);
    assert_eq!(auto.pending_len(), 0, "dropped");
    assert!(auto.limiter.record.sent.is_empty());
    assert_eq!(auto.limiter.record.attempts.len(), MAX_ATTEMPTS as usize);
}

/// A server that reads the whole request and never answers (a route that freezes what the server
/// sends): returns how many requests it got.
fn silent_server() -> (reqwest::Url, std::sync::Arc<Mutex<usize>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = reqwest::Url::parse(&format!(
        "http://{}/api/diagnostics/agent",
        listener.local_addr().expect("addr")
    ))
    .expect("url");
    let count = std::sync::Arc::new(Mutex::new(0usize));
    let counted = std::sync::Arc::clone(&count);
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().take(4) {
            let Ok(mut stream) = stream else {
                return;
            };
            *afklink_core::lock(&counted) += 1;
            let mut chunk = [0u8; 8192];
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            while let Ok(n) = stream.read(&mut chunk) {
                if n == 0 {
                    break;
                }
            }
            // Never answered: held open until the test is done.
            held.push(stream);
        }
    });
    (url, count)
}

/// The whole report went and no answer came: counted as sent, never sent again — not retried, and
/// not the other way.
#[test]
fn a_report_that_went_without_an_answer_is_counted_and_never_resent() {
    let (silent, silent_count) = silent_server();
    let (other, other_seen) = serve(vec![("201 Created", String::new(), RECEIPT.into())]);
    let mut auto = one_ready(silent.clone());
    let up = auto.next_upload(MERGE_WINDOW_MS, NOW, true).expect("goes");
    let short = upload::Stall {
        body: Duration::from_secs(5),
        answer: Duration::from_millis(800),
    };
    let outcome = upload_to(&up, &[silent, other], NOW, short);
    assert!(
        matches!(
            outcome,
            upload::Outcome::Failed(upload::Failure::Unanswered(_))
        ),
        "{outcome:?}"
    );
    auto.upload_done(up.id, &outcome, MERGE_WINDOW_MS, NOW);
    assert_eq!(auto.pending_len(), 0, "not kept for a retry");
    assert_eq!(
        auto.limiter.record.sent,
        vec![mark(NOW, Trigger::Stall)],
        "counted"
    );
    assert_eq!(*afklink_core::lock(&silent_count), 1, "one request");
    assert!(
        afklink_core::lock(&other_seen).is_empty(),
        "not the other way"
    );
}

/// Three sent in a day, the next trigger is not even queued: counted, and named in the report
/// after the window.
#[test]
fn no_more_than_three_go_in_a_day() {
    let (url, seen) = serve(vec![
        ("201 Created", String::new(), RECEIPT.into()),
        ("201 Created", String::new(), RECEIPT.into()),
        ("201 Created", String::new(), RECEIPT.into()),
        ("201 Created", String::new(), RECEIPT.into()),
    ]);
    let mut auto = Auto::new(Limiter::default());
    auto.connected(at(0, 0), NOW, true);
    let triggers = [
        Trigger::Stall,
        Trigger::Crash,
        Trigger::Offline,
        Trigger::SessionFailed,
    ];
    let mut fired_at = Vec::new();
    for (i, trigger) in triggers.into_iter().enumerate() {
        let mono = i as u64 * 20 * MIN;
        let now = NOW + mono;
        let fire = auto.fire(Fired::new(trigger, now, "x", None), mono, now, true);
        fired_at.push(fire);
        if fire != Fire::Opened {
            continue;
        }
        let c = auto.take_due(mono + MERGE_WINDOW_MS).expect("due");
        auto.add_ready(
            c,
            ready_for_tests(Some(url.clone())),
            mono + MERGE_WINDOW_MS,
        );
        let up = auto
            .next_upload(mono + MERGE_WINDOW_MS, now + MERGE_WINDOW_MS, true)
            .expect("goes");
        let outcome = upload_now(&up, now);
        auto.upload_done(
            up.id,
            &outcome,
            mono + MERGE_WINDOW_MS,
            now + MERGE_WINDOW_MS,
        );
    }
    assert_eq!(
        fired_at,
        [
            Fire::Opened,
            Fire::Opened,
            Fire::Opened,
            Fire::Skipped("per_window")
        ]
    );
    assert_eq!(afklink_core::lock(&seen).len(), 3, "the fourth never went");
    assert_eq!(auto.limiter.record.sent.len(), 3);
    assert_eq!(auto.limiter.skipped().get("session_failed"), Some(&1));
    // Even a report that slipped in would not go: the send-time check holds the same limit.
    let c = Collecting {
        id: 99,
        first: fired(Trigger::SessionFailed),
        merged: Vec::new(),
        merged_dropped: 0,
        due_ms: 0,
        seen_unix_ms: NOW,
        generation: 0,
    };
    auto.add_ready(c, ready_for_tests(None), HOUR);
    assert!(auto.next_upload(HOUR, NOW + HOUR, true).is_none());
    assert_eq!(auto.pending_len(), 0);
    assert_eq!(auto.limiter.skipped().get("session_failed"), Some(&2));
    // A day later, the next report names what was skipped.
    let later = Collecting {
        id: 100,
        first: fired(Trigger::Stall),
        merged: Vec::new(),
        merged_dropped: 0,
        due_ms: 0,
        seen_unix_ms: NOW + DAY,
        generation: 0,
    };
    assert_eq!(
        later.about(&auto.limiter.skipped())["skipped"]["session_failed"],
        2
    );
}

/// The attempt is on disk before the upload starts. A record that reads but cannot be replaced
/// (read-only) and a crash at start: nothing leaves — not once per restart — and the reports close.
#[test]
// The read-only attribute is cleared again so the test's folder can be removed (Windows).
#[allow(clippy::permissions_set_readonly_false)]
fn an_attempt_is_recorded_before_its_upload_starts() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let crash = || {
        crash_fired(
            AgentLastExit {
                kind: AgentExitKind::Crash,
                at: Some(NOW - HOUR),
            },
            NOW,
        )
        .expect("a crash")
    };
    // Read-only: zero requests.
    let dir = TempDir::new("attempt-ro");
    let path = dir.0.join(FILE_NAME);
    save_record(&path, &LimiterRecord::default()).expect("written");
    let mut permissions = std::fs::metadata(&path).expect("meta").permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&path, permissions.clone()).expect("read-only");
    let (url, seen) = serve(vec![("201 Created", String::new(), RECEIPT.into())]);
    let mut auto = Auto::new(Limiter::new(load_record(&path).expect("it reads")));
    auto.connected(at(0, 0), NOW, true);
    assert_eq!(auto.fire(crash(), 0, NOW, true), Fire::Opened);
    let c = auto.take_due(0).expect("due at once");
    auto.add_ready(c, ready_for_tests(Some(url)), 0);
    let up = runtime.block_on(next_upload_persisted(&mut auto, Some(&path), 0, NOW, true));
    permissions.set_readonly(false);
    std::fs::set_permissions(&path, permissions).expect("writable again");
    assert!(up.is_none(), "no upload starts");
    assert_eq!(
        auto.fire(fired(Trigger::Stall), HOUR, NOW + HOUR, true),
        Fire::Closed
    );
    assert!(auto.next_upload(HOUR, NOW + HOUR, true).is_none());
    assert!(afklink_core::lock(&seen).is_empty(), "zero requests");
    // Writable: the attempt is on disk when the upload is handed out.
    let dir = TempDir::new("attempt-rw");
    let path = dir.0.join(FILE_NAME);
    let (url, seen) = serve(vec![("201 Created", String::new(), RECEIPT.into())]);
    let mut auto = Auto::new(Limiter::default());
    auto.connected(at(0, 0), NOW, true);
    auto.fire(crash(), 0, NOW, true);
    let c = auto.take_due(0).expect("due at once");
    auto.add_ready(c, ready_for_tests(Some(url)), 0);
    let up = runtime
        .block_on(next_upload_persisted(&mut auto, Some(&path), 0, NOW, true))
        .expect("goes");
    assert_eq!(load_record(&path).expect("read").attempts, vec![NOW]);
    let outcome = upload_now(&up, NOW);
    assert!(
        matches!(outcome, upload::Outcome::Sent { .. }),
        "{outcome:?}"
    );
    assert_eq!(afklink_core::lock(&seen).len(), 1);
}

/// The log turned off with an upload on its way: the task is stopped, and its guard still hands
/// back an outcome (a failure), so the state is free again.
#[test]
fn a_stopped_upload_still_hands_back_an_outcome() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (tx, mut rx) = mpsc::channel(4);
    let outcome = runtime.block_on(async move {
        let guard = OutcomeGuard::new(9, tx);
        let task = tokio::spawn(async move {
            std::future::pending::<()>().await;
            guard.send(upload::Outcome::Sent { receipt: None });
        });
        task.abort();
        let _stopped = task.await;
        rx.recv().await
    });
    let (id, outcome) = outcome.expect("an outcome");
    assert_eq!(id, 9);
    assert!(matches!(
        outcome,
        upload::Outcome::Failed(upload::Failure::Network(_))
    ));
}

/// A gateway's error (502/504, Cloudflare's 52x) after the whole body went: for the automatic
/// report, as no answer — counted, not the other way, not retried; the owner's report still tries
/// the other way.
#[test]
fn a_gateway_error_after_the_body_is_not_sent_again() {
    for status in [
        "502 Bad Gateway",
        "504 Gateway Timeout",
        "522 Connection Timed Out",
    ] {
        let (first, first_seen) = serve(vec![(status, String::new(), "{}".into())]);
        let (other, other_seen) = serve(vec![("201 Created", String::new(), RECEIPT.into())]);
        let mut auto = one_ready(first.clone());
        let up = auto.next_upload(MERGE_WINDOW_MS, NOW, true).expect("goes");
        let outcome = upload_to(&up, &[first, other.clone()], NOW, upload::STALL);
        assert!(
            matches!(
                outcome,
                upload::Outcome::Failed(upload::Failure::Unanswered(_))
            ),
            "{status}: {outcome:?}"
        );
        auto.upload_done(up.id, &outcome, MERGE_WINDOW_MS, NOW);
        assert_eq!(auto.pending_len(), 0, "{status}");
        assert_eq!(auto.limiter.record.sent.len(), 1, "{status}: counted");
        assert_eq!(afklink_core::lock(&first_seen).len(), 1, "{status}");
        assert!(
            afklink_core::lock(&other_seen).is_empty(),
            "{status}: not the other way"
        );
        // The owner's report, unchanged: on to the other way.
        let (first, _) = serve(vec![(status, String::new(), "{}".into())]);
        let (other, other_seen) = serve(vec![("201 Created", String::new(), RECEIPT.into())]);
        let identity = identity_with("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=");
        let manual = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(upload::send_any(
                &local_client(),
                &up.prepared,
                &[first, other],
                &identity,
                || NOW,
                || [7; 16],
                upload::STALL,
                upload::AfterBody::FallBack,
            ));
        assert!(
            matches!(manual, upload::Outcome::Sent { .. }),
            "{status}: {manual:?}"
        );
        assert_eq!(afklink_core::lock(&other_seen).len(), 1, "{status}");
    }
}

#[test]
fn a_stall_note_before_the_reports_start_is_dropped_quietly() {
    // Nothing started in the test process: the note goes nowhere, and nothing waits.
    if STALL_NOTES.get().is_none() {
        stall_seen("main_thread");
    }
    assert!(is_auto_detail("side=main_thread") && is_auto_detail("side=async_runtime"));
}
