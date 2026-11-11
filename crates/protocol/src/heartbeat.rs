//! What the agent sends the viewer over a DataChannel: the pipeline heartbeat (and, in
//! [`crate::cursor`], the cursor position; both are [`AgentDataMessage`] variants).
//!
//! Mirrors `heartbeatSchema` / `agentDataMessageSchema` in `packages/protocol/src/datachannel.ts`,
//! held to it by the `agent-to-viewer` fixtures in `tests/fixtures.rs`.
//!
//! ## Why it exists
//!
//! The agent captures on change, so a desktop nobody touches sends no video at all. A capture or
//! encode pipeline that has died sends no video either, and the WebRTC link stays up under both —
//! so from the viewer's side a still screen and a dead pipeline are the same frozen picture. Only
//! the agent can tell them apart, and this is it saying which, once a second.
//!
//! ## Why the `cursor` channel
//!
//! A heartbeat is a sample that the next one supersedes: a late one is worthless and a
//! retransmitted one only adds delay. That is the `cursor` channel's contract exactly (unordered,
//! never retransmitted), and the channel carries nothing agent -> viewer otherwise. A viewer that
//! predates heartbeats sets no `onmessage` on it and drops them unseen. `seq` rises by one per
//! heartbeat so the viewer can discard one the unordered channel delivered late.

use serde::{Deserialize, Serialize};

/// The pipeline as the agent observes it. See `PIPELINE_STATES` in the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineState {
    /// Capturing and encoding normally. Says nothing about whether the picture moves.
    Ok,
    /// A stage failed and is being brought back without ending the session.
    Restarting,
    /// Stuck somewhere the agent cannot restart from; the agent ends the session if it persists.
    Stalled,
    /// The agent gave up and is ending the session.
    Failed,
}

impl PipelineState {
    /// The wire spelling, for log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Restarting => "restarting",
            Self::Stalled => "stalled",
            Self::Failed => "failed",
        }
    }
}

/// Why the pipeline is not `ok`. See `PIPELINE_CAUSES` in the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineCause {
    /// The capture ended on its own: thread exited, monitor went away, handler failed.
    CaptureLost,
    /// The capture stopped delivering while it demonstrably should have, or a restart hung.
    CaptureStalled,
    /// The encoder kept returning errors, or panicked.
    EncoderError,
    /// One encode call has not returned for seconds.
    EncoderStalled,
}

impl PipelineCause {
    /// The wire spelling, for log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CaptureLost => "capture_lost",
            Self::CaptureStalled => "capture_stalled",
            Self::EncoderError => "encoder_error",
            Self::EncoderStalled => "encoder_stalled",
        }
    }
}

/// The game window in the «only the game window» mode. See `GAME_WINDOW_STATES` in the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GameWindowState {
    /// No window of the bound game (not running, or no game bound). The viewer gets black frames.
    Absent,
    /// The game's process runs but its window is not there yet (a splash, a loader) — or not any
    /// more (a game closing keeps its process a few seconds). Black.
    Starting,
    /// The window is minimized, hidden or off this desktop. Black.
    Minimized,
    /// On screen, but another window is in front and has the keyboard; the picture is the game's.
    /// The agent holds the viewer's input back (releases pass) until the game has the front again.
    Unfocused,
    /// On screen, and its picture is the video.
    Shown,
}

impl GameWindowState {
    /// The wire spelling, for log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Starting => "starting",
            Self::Minimized => "minimized",
            Self::Unfocused => "unfocused",
            Self::Shown => "shown",
        }
    }

    /// The game's window is not there: the states `launching` may go with (the contract refuses it
    /// with any other).
    pub fn window_missing(self) -> bool {
        matches!(self, Self::Absent | Self::Starting)
    }
}

/// The heartbeat's `game` object: the game window's state, the size of its picture, and whether the
/// PC's game helper is launching the game.
///
/// `w`/`h` — the window's client area in pixels, before the agent scales it to the rung; the last size
/// captured this session, absent until the first. Both or neither (the contract refuses one alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameHeartbeat {
    pub state: GameWindowState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub w: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<u32>,
    /// The PC's game helper («Запускать игру автоматически») launched the game itself in this
    /// session and waits for its window — from the launch to the window, a failed start or its
    /// giving up — or is about to launch it again (its window gone while its process runs, and
    /// while the helper closes it as hung), and the window is not there (`absent`, `starting`):
    /// the viewer says «Игра запускается» rather than «Игра не запущена». Absent (false) otherwise
    /// — a game started by hand before its window is up, one Windows refused to close, the pause
    /// before the next launch after a failed start — and from older agents; an older viewer
    /// ignores it. Set only through [`Self::with_launching`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub launching: bool,
}

impl GameHeartbeat {
    /// A state with the picture's size when it is known — both sides, never one. Not launching.
    pub fn new(state: GameWindowState, size: Option<(u32, u32)>) -> Self {
        let size = size.filter(|&(w, h)| w > 0 && h > 0);
        Self {
            state,
            w: size.map(|(w, _)| w),
            h: size.map(|(_, h)| h),
            launching: false,
        }
    }

    /// `launching` as the game helper says it, kept only while the window is not there
    /// ([`GameWindowState::window_missing`]): a window that is up, minimized or behind another needs
    /// no word about a launch.
    pub fn with_launching(self, launching: bool) -> Self {
        Self {
            launching: launching && self.state.window_missing(),
            ..self
        }
    }
}

/// One heartbeat. Field names are the wire names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Rises by one per heartbeat, from 0 at session start.
    pub seq: u64,
    pub state: PipelineState,
    /// Absent while `ok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<PipelineCause>,
    /// Milliseconds since the capturer last delivered a frame; `null` before the first one.
    ///
    /// Always present on the wire, `null` included: the contract requires the field, so a mirror
    /// that stopped sending it would fail the viewer's reading rather than go unnoticed.
    pub since_capture_ms: Option<u64>,
    /// Milliseconds since the encoder last produced a frame; `null` before the first one.
    pub since_encode_ms: Option<u64>,
    /// Healthy, and nothing has arrived for a while because nothing on screen changed.
    pub still: bool,
    /// The rung: frame height and frame rate.
    pub h: u32,
    pub fps: u32,
    /// Pipeline restarts this session.
    pub restarts: u32,
    /// The pipeline is fine and the agent is deliberately sending no video: the network path is
    /// holding a backlog of frames already sent, and nothing more is encoded until it drains
    /// (`afklink_core::quality::QualityController::draining`). A frozen picture now is the
    /// network's, not the PC's. Absent (false) otherwise, so a viewer that predates it reads the
    /// same heartbeat it always did.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub net_stall: bool,
    /// This agent moves a visible cursor by exactly the `r` fraction of the captured screen —
    /// Windows' display scaling and pointer acceleration taken out — and honours `r.x`/`r.y`
    /// (`afklink_input`'s cursor sync). Always true from this build; absent (false) from older
    /// agents, where Windows' scaling applies on top of `r` (1.5 px per count at 150 %), so the
    /// viewer knows which one it is steering.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rel_exact: bool,
    /// The game window, only in the «only the game window» mode (`afklink_core::game`); absent
    /// otherwise, so a heartbeat outside the mode reads exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub game: Option<GameHeartbeat>,
    /// The PC has no working input driver where it could have one (Windows x64): input goes by
    /// `SendInput` alone. The viewer says «Нужен драйвер на ПК» for 5 s on entering a game mode
    /// while this is set. Absent
    /// (false) while the driver works, where there can be none, and from older agents.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_driver: bool,
    /// The viewer's presses are not reaching the window in front — it runs as administrator, the
    /// agent does not and has no driver, so Windows drops them (UIPI): three in a row within two
    /// seconds, held while they keep being dropped and for ten seconds after the last one
    /// (`afklink_input`'s reach watch). The viewer says «Нужен драйвер на ПК» while it is set
    /// (occasion 1). Only with `no_driver`. Absent (false) otherwise, and from older agents.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub input_blocked: bool,
    /// This agent honours `vis` ([`crate::InputMessage::Visibility`]): it holds video back while
    /// the viewer's page is hidden. Always true from this build, in every heartbeat; absent (false)
    /// from older agents, which do not know `vis` — the viewer sends one only after it has seen
    /// this, so a released agent that would drop it as malformed never gets one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub vis_ok: bool,
    /// The agent is holding video back now because the viewer said its page is hidden: the
    /// background hold (`afklink_core::bg_hold`), after the agent's grace — not during it. The
    /// pipeline is fine and `state` stays `ok`; capture, encoding and sending are stopped on
    /// purpose while the peer, this heartbeat and input stay. `still` is true through it: the
    /// pipeline is healthy and nothing has been captured for longer than a still screen's second,
    /// which is what `still` has always said — this field says why. Only ever with
    /// [`Self::vis_ok`]. Absent (false) otherwise, and from older agents.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bg_hold: bool,
}

/// Everything the agent sends the viewer over a DataChannel. The discriminant is `t`.
///
/// The heartbeat and the cursor go on `cursor`; the clipboard's three on `input`, which must
/// deliver them (see [`crate::clipboard`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum AgentDataMessage {
    #[serde(rename = "hb")]
    Heartbeat(Heartbeat),
    /// Where the PC's cursor is. See [`crate::cursor`].
    #[serde(rename = "cp")]
    Cursor(crate::cursor::CursorPos),
    /// Clipboard sync as the agent has it for this session: the answer to every `cb_sync`, and
    /// again whenever the PC changes it.
    #[serde(rename = "cb_state")]
    ClipboardState(crate::clipboard::ClipboardState),
    /// One chunk of the PC's clipboard, after it changed to a text.
    #[serde(rename = "cb_pc")]
    ClipboardPc(crate::clipboard::ClipboardChunk),
    /// The answer to one whole `cb_set` text.
    #[serde(rename = "cb_ack")]
    ClipboardAck(crate::clipboard::ClipboardAck),
}

impl AgentDataMessage {
    /// The wire form: one JSON text message.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_beat() -> Heartbeat {
        Heartbeat {
            seq: 7,
            state: PipelineState::Ok,
            cause: None,
            since_capture_ms: Some(1500),
            since_encode_ms: None,
            still: true,
            h: 1080,
            fps: 30,
            restarts: 0,
            net_stall: false,
            rel_exact: false,
            game: None,
            no_driver: false,
            input_blocked: false,
            vis_ok: false,
            bg_hold: false,
        }
    }

    /// Each absent while false — an older agent's heartbeat reads as before — `vis_ok` alone from an
    /// agent that honours `vis`, and `bg_hold` beside it while that agent holds video back.
    #[test]
    fn vis_ok_and_bg_hold_are_on_the_wire_only_while_true() {
        let json = AgentDataMessage::Heartbeat(ok_beat()).to_json().unwrap();
        assert!(
            !json.contains("vis_ok") && !json.contains("bg_hold"),
            "{json}"
        );

        let honours = Heartbeat {
            vis_ok: true,
            ..ok_beat()
        };
        let json = AgentDataMessage::Heartbeat(honours.clone())
            .to_json()
            .unwrap();
        assert!(json.contains(r#""vis_ok":true"#), "{json}");
        assert!(!json.contains("bg_hold"), "{json}");
        let back: AgentDataMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AgentDataMessage::Heartbeat(honours));

        let held = Heartbeat {
            vis_ok: true,
            bg_hold: true,
            ..ok_beat()
        };
        let json = AgentDataMessage::Heartbeat(held.clone()).to_json().unwrap();
        assert!(
            json.contains(r#""vis_ok":true"#) && json.contains(r#""bg_hold":true"#),
            "{json}"
        );
        let back: AgentDataMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AgentDataMessage::Heartbeat(held));

        // An older agent's heartbeat: neither, read as false.
        let old: AgentDataMessage = serde_json::from_str(
            r#"{"t":"hb","seq":1,"state":"ok","since_capture_ms":5,"since_encode_ms":6,"still":false,"h":720,"fps":30,"restarts":0}"#,
        )
        .unwrap();
        let AgentDataMessage::Heartbeat(old) = old else {
            panic!("a heartbeat");
        };
        assert!(!old.vis_ok && !old.bg_hold);
    }

    /// Absent while false — an older agent's heartbeat, and this one's while the driver works,
    /// read as before — and each present and true on its own.
    #[test]
    fn the_driver_flags_are_on_the_wire_only_while_true() {
        let json = AgentDataMessage::Heartbeat(ok_beat()).to_json().unwrap();
        assert!(!json.contains("no_driver"), "{json}");
        assert!(!json.contains("input_blocked"), "{json}");

        let no_driver = Heartbeat {
            no_driver: true,
            ..ok_beat()
        };
        let json = AgentDataMessage::Heartbeat(no_driver.clone())
            .to_json()
            .unwrap();
        assert!(json.contains(r#""no_driver":true"#), "{json}");
        assert!(!json.contains("input_blocked"), "{json}");
        let back: AgentDataMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AgentDataMessage::Heartbeat(no_driver));

        let blocked = Heartbeat {
            no_driver: true,
            input_blocked: true,
            ..ok_beat()
        };
        let json = AgentDataMessage::Heartbeat(blocked.clone())
            .to_json()
            .unwrap();
        assert!(json.contains(r#""input_blocked":true"#), "{json}");
        let back: AgentDataMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AgentDataMessage::Heartbeat(blocked));

        // An older agent's heartbeat, and one that says false outright: both read as false.
        let old: AgentDataMessage = serde_json::from_str(
            r#"{"t":"hb","seq":1,"state":"ok","since_capture_ms":5,"since_encode_ms":6,"still":false,"h":720,"fps":30,"restarts":0}"#,
        )
        .unwrap();
        let AgentDataMessage::Heartbeat(old) = old else {
            panic!("a heartbeat");
        };
        assert!(!old.no_driver && !old.input_blocked);
        let said_false: AgentDataMessage = serde_json::from_str(
            r#"{"t":"hb","seq":1,"state":"ok","since_capture_ms":5,"since_encode_ms":6,"still":false,"h":720,"fps":30,"restarts":0,"no_driver":false,"input_blocked":false}"#,
        )
        .unwrap();
        let AgentDataMessage::Heartbeat(said_false) = said_false else {
            panic!("a heartbeat");
        };
        assert!(!said_false.no_driver && !said_false.input_blocked);
    }

    /// Absent outside the game mode — a heartbeat reads exactly as before — and in it the state with
    /// the picture's size, both sides or neither.
    #[test]
    fn game_is_on_the_wire_only_in_the_game_mode() {
        let json = AgentDataMessage::Heartbeat(ok_beat()).to_json().unwrap();
        assert!(!json.contains("game"), "{json}");

        let shown = Heartbeat {
            game: Some(GameHeartbeat::new(
                GameWindowState::Shown,
                Some((3576, 2268)),
            )),
            ..ok_beat()
        };
        let json = AgentDataMessage::Heartbeat(shown.clone())
            .to_json()
            .unwrap();
        assert!(
            json.contains(r#""game":{"state":"shown","w":3576,"h":2268}"#),
            "{json}"
        );
        let back: AgentDataMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AgentDataMessage::Heartbeat(shown));

        // No size yet, or a degenerate one: neither side goes out.
        for size in [None, Some((0, 720)), Some((1280, 0))] {
            let absent = Heartbeat {
                game: Some(GameHeartbeat::new(GameWindowState::Absent, size)),
                ..ok_beat()
            };
            let json = AgentDataMessage::Heartbeat(absent).to_json().unwrap();
            assert!(json.contains(r#""game":{"state":"absent"}"#), "{json}");
        }
    }

    /// `launching` only while the game's window is not there, on the wire only while true; an older
    /// agent's `game` (none) reads as not launching.
    #[test]
    fn launching_goes_out_only_with_the_window_missing_and_only_while_true() {
        for (state, kept) in [
            (GameWindowState::Absent, true),
            (GameWindowState::Starting, true),
            (GameWindowState::Minimized, false),
            (GameWindowState::Unfocused, false),
            (GameWindowState::Shown, false),
        ] {
            let game = GameHeartbeat::new(state, Some((1280, 720))).with_launching(true);
            assert_eq!(game.launching, kept, "{}", state.as_str());
            assert_eq!(state.window_missing(), kept);
            let json = serde_json::to_string(&game).unwrap();
            assert_eq!(json.contains(r#""launching":true"#), kept, "{json}");
            assert!(!json.contains("false"), "false is not on the wire: {json}");
        }
        let starting = Heartbeat {
            game: Some(GameHeartbeat::new(GameWindowState::Starting, None).with_launching(true)),
            ..ok_beat()
        };
        let json = AgentDataMessage::Heartbeat(starting.clone())
            .to_json()
            .unwrap();
        assert!(
            json.contains(r#""game":{"state":"starting","launching":true}"#),
            "{json}"
        );
        let back: AgentDataMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AgentDataMessage::Heartbeat(starting));
        // Not launching: nothing more on the wire than before.
        let quiet = GameHeartbeat::new(GameWindowState::Absent, None).with_launching(false);
        assert_eq!(
            serde_json::to_string(&quiet).unwrap(),
            r#"{"state":"absent"}"#
        );
        let old: GameHeartbeat = serde_json::from_str(r#"{"state":"starting"}"#).unwrap();
        assert!(!old.launching);
    }

    #[test]
    fn the_game_states_log_as_they_are_spelled_on_the_wire() {
        for s in [
            GameWindowState::Absent,
            GameWindowState::Starting,
            GameWindowState::Minimized,
            GameWindowState::Unfocused,
            GameWindowState::Shown,
        ] {
            assert_eq!(serde_json::to_value(s).unwrap(), s.as_str());
        }
    }

    /// Absent while false — an older agent's heartbeat reads as before — and `true` on the wire
    /// from this one.
    #[test]
    fn rel_exact_is_on_the_wire_only_while_it_is_true() {
        let json = AgentDataMessage::Heartbeat(ok_beat()).to_json().unwrap();
        assert!(!json.contains("rel_exact"), "{json}");
        let exact = Heartbeat {
            rel_exact: true,
            ..ok_beat()
        };
        let json = AgentDataMessage::Heartbeat(exact.clone())
            .to_json()
            .unwrap();
        assert!(json.contains(r#""rel_exact":true"#), "{json}");
        let back: AgentDataMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AgentDataMessage::Heartbeat(exact));
    }

    /// Absent while false, so every existing fixture and every viewer reads the same heartbeat;
    /// present and true while the agent drains a backlog.
    #[test]
    fn net_stall_is_on_the_wire_only_while_it_is_true() {
        let json = AgentDataMessage::Heartbeat(ok_beat()).to_json().unwrap();
        assert!(!json.contains("net_stall"), "{json}");
        let stalled = Heartbeat {
            net_stall: true,
            ..ok_beat()
        };
        let json = AgentDataMessage::Heartbeat(stalled.clone())
            .to_json()
            .unwrap();
        assert!(json.contains(r#""net_stall":true"#), "{json}");
        let back: AgentDataMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AgentDataMessage::Heartbeat(stalled));
    }

    /// The viewer reads these by hand (the Mini App ships no validator), so the exact spelling is
    /// the contract: `t` first-class, `cause` absent when ok, the ages present even when null.
    #[test]
    fn an_ok_heartbeat_has_no_cause_and_keeps_its_null_ages() {
        let json = AgentDataMessage::Heartbeat(ok_beat()).to_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["t"], "hb");
        assert_eq!(v["state"], "ok");
        assert!(
            v.get("cause").is_none(),
            "cause must be absent while ok: {json}"
        );
        assert!(
            v.get("since_encode_ms")
                .is_some_and(serde_json::Value::is_null),
            "a missing age is null, not absent: {json}"
        );
        assert_eq!(v["since_capture_ms"], 1500);
    }

    #[test]
    fn a_restarting_heartbeat_names_its_cause_in_the_wire_spelling() {
        let beat = Heartbeat {
            state: PipelineState::Restarting,
            cause: Some(PipelineCause::CaptureLost),
            ..ok_beat()
        };
        let json = AgentDataMessage::Heartbeat(beat.clone()).to_json().unwrap();
        assert!(json.contains(r#""state":"restarting""#), "{json}");
        assert!(json.contains(r#""cause":"capture_lost""#), "{json}");
        let back: AgentDataMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AgentDataMessage::Heartbeat(beat));
    }

    #[test]
    fn the_log_spelling_is_the_wire_spelling() {
        for s in [
            PipelineState::Ok,
            PipelineState::Restarting,
            PipelineState::Stalled,
            PipelineState::Failed,
        ] {
            assert_eq!(serde_json::to_value(s).unwrap(), s.as_str());
        }
        for c in [
            PipelineCause::CaptureLost,
            PipelineCause::CaptureStalled,
            PipelineCause::EncoderError,
            PipelineCause::EncoderStalled,
        ] {
            assert_eq!(serde_json::to_value(c).unwrap(), c.as_str());
        }
    }
}
