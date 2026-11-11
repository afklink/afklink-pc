//! Input messages carried over the two DataChannels.
//!
//! The split is the whole point. Discrete events — button and key transitions —
//! must arrive and must arrive in order, because a lost `Up` does not drop a frame,
//! it leaves a button physically held on the owner's desktop. Positional events
//! supersede each other, so losing one costs nothing while retransmitting one costs
//! latency, and sending them reliably would put head-of-line blocking in front of
//! the clicks.
//!
//! The agent parses both channels with the same enum and does not trust the label: a
//! peer that puts a `Down` on the cursor channel is buggy or hostile, and either way
//! the event still has to be handled safely rather than crash the parser.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Channel label for discrete, order-sensitive events. Reliable and ordered.
pub const CHANNEL_INPUT: &str = "input";

/// Channel label for positional updates. Unordered, never retransmitted.
pub const CHANNEL_CURSOR: &str = "cursor";

/// Which channel a message belongs on, per the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputChannel {
    /// Reliable and ordered.
    Input,
    /// Unreliable and unordered.
    Cursor,
}

impl InputChannel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Input => CHANNEL_INPUT,
            Self::Cursor => CHANNEL_CURSOR,
        }
    }
}

/// Mouse button. 0 = left, 1 = middle, 2 = right.
pub type MouseButton = u8;

/// The longest `why` a `vis` message may carry, in characters (`visibilitySchema`: `max(32)`).
pub const VIS_WHY_MAX_CHARS: usize = 32;

/// The longest `code` and `key` a `k` message may carry (`keySchema`: `max(32)` each), counted as
/// the contract's validator counts a string's length: in UTF-16 code units, so the agent refuses
/// exactly what the viewer's own schema refuses.
pub const KEY_FIELD_MAX_UNITS: usize = 32;

/// Modifier state carried alongside a key event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mods {
    #[serde(default)]
    pub ctrl: bool,
    #[serde(default)]
    pub alt: bool,
    #[serde(default)]
    pub shift: bool,
    #[serde(default)]
    pub meta: bool,
}

/// Which of the viewer's own keys sent a key message (`k.src`).
///
/// The Mini App tags the keys it draws itself: a key cell of its keys layer (`cell`) and a key of its
/// keys sheet (`sheet`). Those are cut-down binds and system keys on which no password can be typed,
/// so the agent may name them in its logs. A key without the tag (the viewer's physical keyboard,
/// the phone's system keyboard, an older viewer) is never named, only counted.
///
/// Read leniently, because a refused key message is a lost key-up and a key stuck down on the PC: a
/// value this build does not know — a newer viewer's, or one that is not a string — is
/// [`Self::Unknown`], which is not ours either. `null` is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// A key cell of the Mini App's keys layer.
    Cell,
    /// A key of the Mini App's keys sheet.
    Sheet,
    /// A value this build does not know: not ours.
    Unknown,
}

impl KeySource {
    /// The contract's spelling; anything else is [`Self::Unknown`].
    pub fn from_wire(s: &str) -> Self {
        match s {
            "cell" => Self::Cell,
            "sheet" => Self::Sheet,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cell => "cell",
            Self::Sheet => "sheet",
            Self::Unknown => "unknown",
        }
    }

    /// One of the viewer's own keys, whose identity may be logged.
    pub fn is_ours(self) -> bool {
        matches!(self, Self::Cell | Self::Sheet)
    }
}

impl Serialize for KeySource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KeySource {
    /// Any JSON value: a string by [`Self::from_wire`], everything else [`Self::Unknown`].
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(value.as_str().map_or(Self::Unknown, Self::from_wire))
    }
}

/// How to read a wheel delta. Mirrors `WheelEvent.deltaMode`.
///
/// Without this the number is uninterpretable: a Chrome desktop notch reports about
/// 100 pixels, Firefox reports 3 lines, and a two-finger phone scroll reports single
/// digits — while Windows counts notches in units of 120.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WheelMode {
    Pixel,
    Line,
    Page,
}

impl WheelMode {
    pub fn from_wire(v: Option<u8>) -> Self {
        match v {
            Some(1) => Self::Line,
            Some(2) => Self::Page,
            // Absent means pixels: older viewers predate the field.
            _ => Self::Pixel,
        }
    }
}

/// A single input event. The discriminant is the `t` field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum InputMessage {
    /// Pointer position, normalized to `[0..1]` against the captured screen.
    #[serde(rename = "m")]
    Move { x: f64, y: f64 },
    /// Relative pointer delta, as a fraction of the screen.
    ///
    /// Counted on the viewer and sent coalesced once per frame. Absolute positions
    /// cannot drive game cameras, so trackpad and MMO-look modes move only with this;
    /// the trackpad never sends a `Move` at all — its clicks land where the cursor is.
    ///
    /// `s` numbers the message (the viewer's own count of `r` sent); the agent echoes the highest
    /// one applied as `ack` in its cursor report ([`crate::CursorPos`]), so the viewer can tell
    /// which of its moves a reported position already includes. Absent from a viewer that draws
    /// no cursor marker.
    ///
    /// `x`, `y`: the viewer's pointer on the captured screen, normalized like [`Self::Move`]
    /// (`[0..1]`), sent by a viewer that points at the picture (the desktop game mode without
    /// pointer capture); both or neither. The agent decides per message from the cursor as it is:
    /// hidden (a game turning its camera): relative counts as always; visible, a target and no
    /// button held: the cursor is put on the target; otherwise: moved by exactly the intended
    /// distance (to the target, or `dx`/`dy` of the screen), Windows' scaling and acceleration taken
    /// out. Older agents ignore them. [`Self::parse`] refuses a message with one and not the other,
    /// or one outside `[0..1]`, as the contract's schema does.
    #[serde(rename = "r")]
    Rel {
        dx: f64,
        dy: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        s: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        x: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        y: Option<f64>,
    },
    /// Wheel delta. See [`WheelMode`] for why `mode` matters.
    ///
    /// `game: true` marks a wheel from the viewer's game (MMO) mode — its pinch. With the HID
    /// driver open, the agent sends that one as whole HID wheel notches, which games reading the
    /// mouse directly see; every other wheel — absent or `false`, the desktop's — stays on smooth
    /// `SendInput`, except in game-only mode and over a window running elevated (which `SendInput`
    /// cannot reach), where it too goes as whole HID notches (`crates/input`, option C). Optional
    /// both ways: an older viewer sends no `game`, an older agent ignores it.
    #[serde(rename = "w")]
    Wheel {
        #[serde(default)]
        dx: f64,
        #[serde(default)]
        dy: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        game: Option<bool>,
    },
    /// Button down.
    #[serde(rename = "d")]
    Down { b: MouseButton },
    /// Button up. Losing this one is the bug the channel split exists to prevent.
    #[serde(rename = "u")]
    Up { b: MouseButton },
    /// Key transition. `d`: 1 = down, 0 = up.
    #[serde(rename = "k")]
    Key {
        d: u8,
        /// `KeyboardEvent.code` — physical position. Empty on most mobile IMEs.
        code: String,
        /// `KeyboardEvent.key` — the produced character, when reported.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mods: Option<Mods>,
        /// Which of the viewer's own keys sent it, if one did: see [`KeySource`]. Absent — the
        /// viewer's physical keyboard, the phone's system keyboard, an older viewer — is not ours,
        /// and the agent never names such a key in a log. Optional both ways.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        src: Option<KeySource>,
    },
    /// On-screen-panel combo.
    #[serde(rename = "combo")]
    Combo { name: String },
    /// Committed text from a mobile IME.
    ///
    /// Mobile keyboards do not produce usable key events, so the viewer diffs its
    /// hidden input and sends the string here. Injected as Unicode, which needs no
    /// layout mapping but does not drive games waiting for a scancode.
    ///
    /// `game: true` marks text typed in the viewer's game (MMO) mode — a game's chat. With the HID
    /// driver open, the agent types that one as real key presses on the PC's keyboard layout,
    /// switching the layout when a character needs another, because games see only HID keys; every
    /// other text — absent or `false` — stays Unicode. Optional both ways, like the wheel's `game`.
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        game: Option<bool>,
    },
    /// Release everything currently held.
    ///
    /// Sent by the viewer when it is about to lose the ability to deliver a matching
    /// up — tab hidden, app backgrounded, channel closing. The agent applies the
    /// same thing on session end, on kill switch, and after a silence timeout,
    /// because the viewer may die without sending anything at all.
    #[serde(rename = "ra")]
    ReleaseAll,
    /// The resolution the viewer pinned, as a height in text (`"1080"`), or `"auto"`.
    ///
    /// A pin is a real pin: the agent holds that height and sheds frame rate instead when the
    /// link tightens. Safe to offer because the encoder's bitrate follows the bandwidth estimate
    /// and a pinned ladder still walks down in frame rate — so pinning 1080p on a thin link costs
    /// sharpness-per-frame and smoothness, never responsiveness. Queued frames would be the
    /// unacceptable outcome: the data channels share the transport, so input would queue behind
    /// them.
    ///
    /// Text rather than a number because the wire form is a discriminated union keyed on strings,
    /// and `"auto"` has to live in the same field.
    #[serde(rename = "q")]
    Quality { q: String },
    /// What the viewer observes about latency. The only message here that asks for nothing.
    ///
    /// Everything this agent calls latency is its own send queue — one term of a sum whose other
    /// terms it cannot see. The largest of those is the receiver's jitter buffer: the browser
    /// deliberately holding frames back to absorb arrival jitter. On a one-second budget a buffer
    /// that settles at 400 ms has spent nearly half of it, and until this message existed nothing
    /// in this project had ever measured it.
    ///
    /// `jbuf_ms` is `jitterBufferDelay / jitterBufferEmittedCount` over the sending interval, per
    /// the W3C stats spec. Over the interval rather than cumulative: a cumulative mean cannot
    /// fall, so a session that began badly would report the penalty for the rest of its life.
    ///
    /// These numbers arrive over the network from a peer, so they are evidence and not truth.
    /// Whatever reads them bounds them itself; see `afklink_core::agent`.
    #[serde(rename = "vl")]
    ViewerLatency {
        /// Mean jitter-buffer delay over the interval, milliseconds.
        jbuf_ms: f64,
        /// Frames the decoder emitted during the interval — the denominator behind `jbuf_ms`.
        frames: u32,
        /// Packet jitter as the receiver measures it, milliseconds.
        jitter_ms: f64,
    },
    /// What the viewer's decoder and video element are doing, once a second. See [`ViewerVideo`].
    ///
    /// Boxed: the report is ten times the size of any other variant, and pointer moves — sixty a
    /// second — should not each carry its footprint.
    #[serde(rename = "vv")]
    ViewerVideo(Box<ViewerVideo>),
    /// The viewer asks for a keyframe itself, because its browser did not send a PLI.
    ///
    /// JavaScript cannot send RTCP; only the browser decides when to ask, and WebKit has been seen
    /// to decode a whole frozen session with two PLIs, both at the start. The viewer can see its
    /// frames stop reaching the screen, so it asks here, and the agent forces a keyframe through the same
    /// path a PLI takes. `reason` is one of `KEYFRAME_REASONS` in the contract (`render_stall`,
    /// `decode_stall`, `foreground`), kept as text so a newer viewer's reason is logged rather
    /// than refused; optional here for the same tolerance, though the contract always sends it.
    #[serde(rename = "kf")]
    KeyframeRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Whether the viewer's page is hidden (`document.visibilityState`): the signal for the
    /// agent's background hold (`afklink_core::bg_hold`). Mirrors `visibilitySchema` in `packages/protocol/src/datachannel.ts`.
    ///
    /// A state, not a command: `hidden` is what the page is now, and the same value again changes
    /// nothing. Once the page has been hidden for the agent's grace, the agent stops capturing,
    /// encoding and sending video for the session — the peer, the heartbeat and input stay — and
    /// on `hidden: false` it sends video again, opening with a keyframe of the current screen.
    /// Sent only to an agent whose heartbeat said `vis_ok` ([`crate::Heartbeat::vis_ok`]).
    ///
    /// `why` says where in the viewer it was sent from (`visibilitychange`, `first_picture`,
    /// `input_open`, `path_up`, `reconcile`), for the logs: free text, kept as given, at most
    /// [`VIS_WHY_MAX_CHARS`] characters — [`Self::parse`] refuses a longer one, as the contract's
    /// schema does. Absent stays absent.
    #[serde(rename = "vis")]
    Visibility {
        hidden: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        why: Option<String>,
    },
    /// Clipboard sync on or off for this session: the browser's own switch, off by default. Sent
    /// when the channel opens (`on: false` too) and whenever the switch flips; the agent answers
    /// each with `cb_state`. Not input: the session's clipboard task takes it
    /// (`afklink_core::clipboard`). See [`crate::clipboard`].
    #[serde(rename = "cb_sync")]
    ClipboardSync { on: bool },
    /// One chunk of a text the viewer copied, for the PC's clipboard. Not input either: joined and
    /// written (or refused) by the session's clipboard task, which answers the whole text with one
    /// `cb_ack`. Its numbers are checked there, not by [`Self::parse`], so a bad chunk is answered
    /// `malformed` rather than lost. Never logged: a clipboard can hold a password.
    #[serde(rename = "cb_set")]
    ClipboardSet(crate::clipboard::ClipboardChunk),
}

/// The viewer's decoder and video element, as it reports them once a second.
///
/// Mirrors `viewerVideoSchema` in `packages/protocol/src/datachannel.ts`. `ViewerLatency` says
/// frames were decoded; this says whether they reached the screen — the question a frozen picture
/// asks, and one the agent's own log cannot answer.
///
/// Every field is optional and absent means "this browser does not expose it", never zero: an
/// older viewer sends none of them, a WebView without `requestVideoFrameCallback` sends no
/// `rvfc_frames`. Counters are cumulative for the session. The numbers arrive from the network, so
/// whatever reads them bounds them itself. Most are evidence for the log; a few are control inputs.
///
/// Drain mode reads `frames_received` and `current_ms`
/// (`afklink_core::quality::QualityController::note_viewer_frames`). A receiver report's round trip
/// is the sender report it answers, which waited in the queue it describes, so it reaches the agent
/// a whole round trip late; this report comes back the other way. Read against the frames and bytes
/// the agent handed to the transport, the viewer's count says how much of ours is still in flight
/// and how fast it arrives. Only when it came on time by the viewer's own clock (`current_ms`), it
/// vetoes a drain the round trip would begin and ends one whose backlog has reached the viewer: a
/// drain begun after the backlog has already cleared freezes the picture for nothing (1.6 s in one
/// recorded session). The most a viewer can do with false numbers is keep its own session out of
/// drain mode, or end a drain early. Beside it, `engine` and `jbuf_target_ms` decide how a playout
/// hold is released (the target also sizes the cushion), and `freeze_count`/`freeze_ms` engage a
/// Chromium viewer's playout cushion (`afklink_transport`'s `playout` module).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ViewerVideo {
    /// inbound-rtp, cumulative: frames assembled from packets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_received: Option<u64>,
    /// inbound-rtp, cumulative: frames the decoder emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_decoded: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_dropped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_frames_decoded: Option<u64>,
    /// The browser's own freeze detector, cumulative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freeze_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freeze_ms: Option<u64>,
    /// PLIs the browser itself sent, cumulative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pli_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// Decoded frames per second as the browser counts them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fps: Option<f64>,
    /// `decoderImplementation`, when the browser exposes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoder: Option<String>,
    /// Interval means of the jitter buffer's target and minimum delay, ms: whether this browser
    /// honours the `playout-delay` header shows here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jbuf_target_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jbuf_min_ms: Option<f64>,
    /// Frames presented per `requestVideoFrameCallback`, cumulative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rvfc_frames: Option<u64>,
    /// `getVideoPlaybackQuality()` totals. May reset when the stream is re-attached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpq_frames: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpq_dropped: Option<u64>,
    /// `video.currentTime`, ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused: Option<bool>,
    /// `HTMLMediaElement.readyState`, 0..4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_state: Option<u8>,
    /// `document.visibilityState`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    /// Telegram's platform string, or `browser`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Which counter the viewer's watchdog trusts: `rvfc`, `vpq`, `time` or `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented_by: Option<String>,
    /// The viewer's render watchdog: `ok`, `hidden`, `blocked`, `keyframe`, `reattach`, `replace`,
    /// `reconnect`, `stalled` (`RENDER_WATCH_STATES`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watchdog: Option<String>,
    /// Keyframes the viewer asked for with [`InputMessage::KeyframeRequest`], this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kf_asked: Option<u64>,
    /// Times the viewer re-attached the stream to its video element, this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reattaches: Option<u64>,
    /// `pause`, `waiting` and `stalled` events from the video element, this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ev_pause: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ev_waiting: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ev_stalled: Option<u64>,
    /// The viewer's browser engine: `webkit`, `chromium`, `gecko` or `unknown` (`VIEWER_ENGINES`).
    /// Text rather than [`ViewerEngine`] so a newer viewer's value is logged rather than refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    /// Times the viewer replaced its video element with a fresh one, this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacements: Option<u64>,
    /// Freezes this session that ended with a frame on screen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recoveries: Option<u64>,
    /// The watchdog step the last of those ended at: `keyframe`, `reattach`, `replace`, `stalled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_at: Option<String>,
    /// How long that freeze lasted, ms, from when it was declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_ms: Option<u64>,
    /// How many automatic reconnects in a row led to this session: the viewer ended the previous
    /// one and started this one by itself, because a frozen picture survived a keyframe, a
    /// re-attach and a new video element. 0 for a session the user or the first connect started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_reconnects: Option<u64>,
}

/// A viewer's browser engine, as its `vv` report names it.
///
/// Telegram on iOS and macOS, and Safari, render in WebKit; Telegram on Android and on Windows in
/// Chromium. It decides how the agent releases a playout-delay hold — fast for Chromium, carefully
/// for anyone else, because the one freeze only an iPhone showed came with the fast release — and
/// is logged with every playout switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerEngine {
    WebKit,
    Chromium,
    Gecko,
    /// The viewer could not tell, or sent a value this build does not know.
    Unknown,
}

impl ViewerEngine {
    /// The contract's spelling; anything else is [`Self::Unknown`].
    pub fn from_wire(s: &str) -> Self {
        match s {
            "webkit" => Self::WebKit,
            "chromium" => Self::Chromium,
            "gecko" => Self::Gecko,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::WebKit => "webkit",
            Self::Chromium => "chromium",
            Self::Gecko => "gecko",
            Self::Unknown => "unknown",
        }
    }
}

impl InputMessage {
    /// The channel this message belongs on.
    pub fn channel(&self) -> InputChannel {
        match self {
            Self::Move { .. } | Self::Rel { .. } | Self::Wheel { .. } => InputChannel::Cursor,
            _ => InputChannel::Input,
        }
    }

    /// True when dropping this message would leave the desktop in a wrong state.
    ///
    /// Not the same question as [`Self::channel`], and it stopped being the same question when
    /// [`Self::ViewerLatency`] arrived. Everything that must arrive rides the reliable channel,
    /// but the converse is not true: a lost latency report costs one sample of a diagnostic and
    /// nothing else. Leaving these as one function would have quietly widened the meaning of the
    /// stronger claim to fit the weaker member.
    pub fn must_arrive(&self) -> bool {
        match self {
            // A transition. Losing one leaves a button or key held down with nothing to release
            // it, which is the whole reason the channel split exists. Text joins them: a lost
            // half-word is a corrupted input, and the next message does not supersede it.
            Self::Down { .. }
            | Self::Up { .. }
            | Self::Key { .. }
            | Self::Combo { .. }
            | Self::Text { .. }
            | Self::ReleaseAll => true,
            // A setting. Losing it leaves the two sides disagreeing indefinitely, because from
            // the viewer's side it already looks applied. The page's visibility is the same kind
            // of state: a lost `hidden: false` would leave the PC holding video back from a viewer
            // that is looking at it.
            Self::Quality { .. } | Self::Visibility { .. } => true,
            // Clipboard sync: a setting, and a chunk whose loss corrupts the text.
            Self::ClipboardSync { .. } | Self::ClipboardSet(_) => true,
            // Samples. The next one is along in a moment and supersedes this one.
            Self::Move { .. }
            | Self::Rel { .. }
            | Self::Wheel { .. }
            | Self::ViewerLatency { .. }
            | Self::ViewerVideo(_) => false,
            // A request the viewer repeats, on its own backoff, for as long as the picture stays
            // frozen. Losing one costs a second of waiting, not a wrong state on the desktop.
            Self::KeyframeRequest { .. } => false,
        }
    }

    /// Parse one message, and refuse what the contract's schema refuses beyond its shape: an `r`
    /// with half a target, or a target off the screen (see [`Self::validate`]).
    pub fn parse(s: &str) -> Result<Self, serde_json::Error> {
        let message: Self = serde_json::from_str(s)?;
        message
            .validate()
            .map_err(<serde_json::Error as serde::de::Error>::custom)?;
        Ok(message)
    }

    /// The rules serde's shape cannot say: an `r`'s `x` and `y` come together or not at all, each
    /// in `[0..1]` (`relSchema` in the contract). A move with half a target would leave the agent
    /// guessing which way the viewer meant it; the whole message is refused, as the viewer's own
    /// validator refuses it. And a `vis`'s `why` is at most [`VIS_WHY_MAX_CHARS`] characters
    /// (`visibilitySchema`): a longer one is a viewer the contract does not describe. A `k`'s `d` is
    /// 0 or 1, and its `code` and `key` at most [`KEY_FIELD_MAX_UNITS`] each (`keySchema`): the
    /// agent keeps what a session holds by them, so their size is the contract's, not the sender's.
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Self::Key { d, code, key, .. } = self {
            if *d > 1 {
                return Err("k: d is 1 (down) or 0 (up)");
            }
            let too_long = |s: &str| s.encode_utf16().count() > KEY_FIELD_MAX_UNITS;
            if too_long(code) || key.as_deref().is_some_and(too_long) {
                return Err("k: code and key are at most 32 UTF-16 units each");
            }
        }
        if let Self::Visibility { why: Some(why), .. } = self {
            if why.chars().count() > VIS_WHY_MAX_CHARS {
                return Err("vis: why is at most 32 characters");
            }
        }
        if let Self::Rel { x, y, .. } = self {
            match (x, y) {
                (None, None) => {}
                (Some(x), Some(y)) => {
                    if !(0.0..=1.0).contains(x) || !(0.0..=1.0).contains(y) {
                        return Err("r: x and y are fractions of the screen, in [0, 1]");
                    }
                }
                _ => return Err("r: x and y come together or not at all"),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discrete_events_are_the_ones_that_must_arrive() {
        for m in [
            InputMessage::Down { b: 0 },
            InputMessage::Up { b: 0 },
            InputMessage::ReleaseAll,
            InputMessage::Combo {
                name: "ctrl_alt_del".into(),
            },
        ] {
            assert!(m.must_arrive(), "{m:?} must be on the reliable channel");
            assert_eq!(m.channel().label(), CHANNEL_INPUT);
        }
    }

    #[test]
    fn positional_events_are_droppable() {
        for m in [
            InputMessage::Move { x: 0.5, y: 0.5 },
            InputMessage::Rel {
                dx: 0.02,
                dy: -0.01,
                s: None,
                x: None,
                y: None,
            },
            InputMessage::Wheel {
                dx: 0.0,
                dy: 1.0,
                mode: None,
                game: None,
            },
        ] {
            assert!(!m.must_arrive());
            assert_eq!(m.channel().label(), CHANNEL_CURSOR);
        }
    }

    /// `game` is optional in both directions: a viewer that predates it is a desktop wheel, and the
    /// flag survives a round-trip only when it was sent.
    #[test]
    fn a_wheel_is_a_game_wheel_only_when_the_viewer_says_so() {
        let old = InputMessage::parse(r#"{"t":"w","dx":0,"dy":100,"mode":0}"#).unwrap();
        assert!(matches!(old, InputMessage::Wheel { game: None, .. }));
        let json = serde_json::to_string(&old).unwrap();
        assert!(
            !json.contains("game"),
            "an absent flag stays absent: {json}"
        );

        for (flag, want) in [("true", Some(true)), ("false", Some(false))] {
            let m = InputMessage::parse(&format!(
                r#"{{"t":"w","dx":0,"dy":-100,"mode":0,"game":{flag}}}"#
            ))
            .unwrap();
            let InputMessage::Wheel { game, .. } = &m else {
                panic!("{m:?} is not a wheel");
            };
            assert_eq!(*game, want);
            let json = serde_json::to_string(&m).unwrap();
            assert!(json.contains(&format!(r#""game":{flag}"#)), "{json}");
        }
    }

    /// The other direction of the same tolerance: a field this build does not know (what `game`
    /// is to an older agent) is ignored, not refused — a lost wheel would be the only symptom.
    #[test]
    fn a_wheel_with_a_field_this_build_does_not_know_still_parses() {
        let m = InputMessage::parse(r#"{"t":"w","dy":3,"mode":1,"game":true,"zoom":2}"#).unwrap();
        assert!(matches!(
            m,
            InputMessage::Wheel {
                mode: Some(1),
                game: Some(true),
                ..
            }
        ));
    }

    #[test]
    fn committed_text_is_a_reliable_message() {
        let m = InputMessage::parse(r#"{"t":"text","text":"привет"}"#).unwrap();
        assert!(matches!(m, InputMessage::Text { .. }));
        assert!(m.must_arrive());
        assert_eq!(m.channel().label(), CHANNEL_INPUT);
    }

    /// `game` on text is optional in both directions, like the wheel's: a viewer that predates it
    /// sends Unicode text, and the flag survives a round-trip only when it was sent.
    #[test]
    fn text_is_game_text_only_when_the_viewer_says_so() {
        let old = InputMessage::parse(r#"{"t":"text","text":"hi"}"#).unwrap();
        assert_eq!(
            old,
            InputMessage::Text {
                text: "hi".into(),
                game: None
            }
        );
        let json = serde_json::to_string(&old).unwrap();
        assert_eq!(
            json, r#"{"t":"text","text":"hi"}"#,
            "an absent flag stays absent"
        );

        for (flag, want) in [("true", Some(true)), ("false", Some(false))] {
            let m = InputMessage::parse(&format!(r#"{{"t":"text","text":"gg","game":{flag}}}"#))
                .unwrap();
            let InputMessage::Text { text, game } = &m else {
                panic!("{m:?} is not text");
            };
            assert_eq!(text, "gg");
            assert_eq!(*game, want);
            assert!(m.must_arrive());
            assert_eq!(m.channel().label(), CHANNEL_INPUT);
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(json, format!(r#"{{"t":"text","text":"gg","game":{flag}}}"#));
        }
    }

    /// A field this build does not know is ignored on text too, not refused: a lost chat line would
    /// be the only symptom.
    #[test]
    fn text_with_a_field_this_build_does_not_know_still_parses() {
        let m = InputMessage::parse(r#"{"t":"text","text":"ok","game":true,"ime":"ru"}"#).unwrap();
        assert_eq!(
            m,
            InputMessage::Text {
                text: "ok".into(),
                game: Some(true)
            }
        );
    }

    #[test]
    fn a_relative_delta_parses_from_the_viewers_wire_form() {
        let m = InputMessage::parse(r#"{"t":"r","dx":0.02,"dy":-0.01}"#).unwrap();
        assert!(matches!(
            m,
            InputMessage::Rel {
                s: None,
                x: None,
                y: None,
                ..
            }
        ));
        assert!(!m.must_arrive());
        assert_eq!(m.channel().label(), CHANNEL_CURSOR);
    }

    /// The number is optional both ways: an unnumbered move parses and re-serializes without one,
    /// and a numbered one keeps it — it is what the agent echoes back as the cursor report's `ack`.
    #[test]
    fn a_relative_delta_keeps_its_number_only_when_it_has_one() {
        let m = InputMessage::parse(r#"{"t":"r","dx":0.5,"dy":0.25,"s":4294967295}"#).unwrap();
        assert!(matches!(
            m,
            InputMessage::Rel {
                s: Some(u32::MAX),
                ..
            }
        ));
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains(r#""s":4294967295"#), "{json}");

        let bare = InputMessage::Rel {
            dx: 0.5,
            dy: 0.25,
            s: None,
            x: None,
            y: None,
        };
        let json = serde_json::to_string(&bare).unwrap();
        assert!(
            !json.contains(r#""s""#),
            "an absent number stays absent: {json}"
        );
        assert!(
            !json.contains(r#""x""#) && !json.contains(r#""y""#),
            "an absent target stays absent: {json}"
        );
    }

    /// The viewer's pointer rides along as `x`, `y` (fractions of the screen, like `m`), both or
    /// neither: the agent puts a visible cursor there, or moves it exactly toward it.
    #[test]
    fn a_relative_delta_carries_its_target_both_ways() {
        let m =
            InputMessage::parse(r#"{"t":"r","dx":0.0125,"dy":-0.005,"s":8,"x":0.4375,"y":0.625}"#)
                .unwrap();
        let InputMessage::Rel { s, x, y, .. } = &m else {
            panic!("{m:?} is not a relative move");
        };
        assert_eq!((*s, *x, *y), (Some(8), Some(0.4375), Some(0.625)));
        let json = serde_json::to_string(&m).unwrap();
        assert!(
            json.contains(r#""x":0.4375"#) && json.contains(r#""y":0.625"#),
            "{json}"
        );
        assert_eq!(InputMessage::parse(&json).unwrap(), m);

        // The screen's edges are on it.
        for (x, y) in [(0.0, 0.0), (1.0, 1.0), (0.0, 1.0)] {
            let m = InputMessage::parse(&format!(r#"{{"t":"r","dx":0,"dy":0,"x":{x},"y":{y}}}"#));
            assert!(m.is_ok(), "({x}, {y}): {m:?}");
        }
    }

    /// Half a target, or one off the screen, is refused whole — as the contract's schema refuses it.
    #[test]
    fn a_relative_delta_with_half_a_target_or_one_off_screen_is_refused() {
        for bad in [
            r#"{"t":"r","dx":0.01,"dy":0,"x":0.5}"#,
            r#"{"t":"r","dx":0.01,"dy":0,"y":0.5}"#,
            r#"{"t":"r","dx":0.01,"dy":0,"s":3,"x":0.5}"#,
            r#"{"t":"r","dx":0.01,"dy":0,"x":1.5,"y":0.5}"#,
            r#"{"t":"r","dx":0.01,"dy":0,"x":0.5,"y":-0.1}"#,
        ] {
            let parsed = InputMessage::parse(bad);
            assert!(parsed.is_err(), "{bad} must be refused, got {parsed:?}");
        }
        // Built in code rather than parsed, the rule is the same.
        let half = InputMessage::Rel {
            dx: 0.0,
            dy: 0.0,
            s: None,
            x: Some(0.5),
            y: None,
        };
        assert!(half.validate().is_err());
        assert!(InputMessage::Move { x: 0.5, y: 0.5 }.validate().is_ok());
    }

    #[test]
    fn a_missing_wheel_mode_means_pixels() {
        assert_eq!(WheelMode::from_wire(None), WheelMode::Pixel);
        assert_eq!(WheelMode::from_wire(Some(0)), WheelMode::Pixel);
        assert_eq!(WheelMode::from_wire(Some(1)), WheelMode::Line);
        assert_eq!(WheelMode::from_wire(Some(2)), WheelMode::Page);
    }

    #[test]
    fn a_key_up_without_optional_fields_still_parses() {
        let m = InputMessage::parse(r#"{"t":"k","d":0,"code":"KeyA"}"#).unwrap();
        assert!(matches!(
            m,
            InputMessage::Key {
                d: 0,
                src: None,
                ..
            }
        ));
    }

    /// `src` is optional both ways: absent stays absent (not ours), and the Mini App's two tags are
    /// read and written back in the contract's spelling.
    #[test]
    fn a_key_says_which_of_the_viewers_own_keys_sent_it_only_when_tagged() {
        let bare = InputMessage::parse(r#"{"t":"k","d":1,"code":"F4"}"#).unwrap();
        assert!(matches!(bare, InputMessage::Key { src: None, .. }));
        assert_eq!(
            serde_json::to_string(&bare).unwrap(),
            r#"{"t":"k","d":1,"code":"F4"}"#,
            "an absent tag stays absent"
        );

        for (wire, want) in [("cell", KeySource::Cell), ("sheet", KeySource::Sheet)] {
            let json = format!(r#"{{"t":"k","d":1,"code":"F4","src":"{wire}"}}"#);
            let m = InputMessage::parse(&json).unwrap();
            let InputMessage::Key { src, .. } = &m else {
                panic!("{m:?} is not a key");
            };
            assert_eq!(*src, Some(want));
            assert!(want.is_ours());
            assert_eq!(want.as_str(), wire);
            assert_eq!(serde_json::to_string(&m).unwrap(), json);
        }
    }

    /// A tag this build does not know — a newer viewer's, or not even a string — never refuses the
    /// key: a lost key-up strands a key on the PC. It reads as unknown, which is not ours; `null` is
    /// absent.
    #[test]
    fn a_key_with_a_tag_this_build_does_not_know_still_parses_and_is_not_ours() {
        for (raw, want) in [
            (r#""pad""#, Some(KeySource::Unknown)),
            (r#""CELL""#, Some(KeySource::Unknown)),
            (r#""""#, Some(KeySource::Unknown)),
            ("7", Some(KeySource::Unknown)),
            ("true", Some(KeySource::Unknown)),
            (r#"{"kind":"cell"}"#, Some(KeySource::Unknown)),
            (r#"["cell"]"#, Some(KeySource::Unknown)),
            ("null", None),
        ] {
            for d in [0, 1] {
                let m = InputMessage::parse(&format!(
                    r#"{{"t":"k","d":{d},"code":"KeyB","src":{raw}}}"#
                ))
                .unwrap_or_else(|e| panic!("src {raw}, d {d}: refused: {e}"));
                let InputMessage::Key { d: got, src, .. } = &m else {
                    panic!("{m:?} is not a key");
                };
                assert_eq!(*got, d);
                assert_eq!(*src, want, "src {raw}");
                assert!(
                    !src.is_some_and(KeySource::is_ours),
                    "src {raw} is not ours"
                );
            }
        }
        assert_eq!(KeySource::from_wire("sheet"), KeySource::Sheet);
        assert_eq!(KeySource::from_wire("Sheet"), KeySource::Unknown);
        // Written back, an unknown tag says so, and reads back the same.
        let m = InputMessage::parse(r#"{"t":"k","d":0,"code":"KeyB","src":"pad"}"#).unwrap();
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, r#"{"t":"k","d":0,"code":"KeyB","src":"unknown"}"#);
        assert_eq!(InputMessage::parse(&json).unwrap(), m);
    }

    #[test]
    fn an_unknown_event_is_rejected() {
        assert!(InputMessage::parse(r#"{"t":"teleport","x":1}"#).is_err());
    }

    /// The wire form has to match `packages/protocol/src/datachannel.ts`'s `viewerLatencySchema`
    /// exactly, and the two are edited independently. This is the only thing that notices when
    /// one side is renamed.
    #[test]
    fn a_viewer_latency_report_parses_from_the_viewers_wire_form() {
        let m = InputMessage::parse(r#"{"t":"vl","jbuf_ms":84.5,"frames":30,"jitter_ms":3.2}"#)
            .unwrap();
        let InputMessage::ViewerLatency {
            jbuf_ms,
            frames,
            jitter_ms,
        } = m
        else {
            panic!("parsed as the wrong variant: {m:?}");
        };
        assert!((jbuf_ms - 84.5).abs() < 1e-9);
        assert_eq!(frames, 30);
        assert!((jitter_ms - 3.2).abs() < 1e-9);
    }

    /// It rides the reliable channel because that is the control channel, but losing one costs a
    /// diagnostic sample rather than correctness. See [`InputMessage::must_arrive`].
    #[test]
    fn a_latency_report_is_on_the_reliable_channel_without_being_required() {
        let m = InputMessage::ViewerLatency {
            jbuf_ms: 84.5,
            frames: 30,
            jitter_ms: 3.2,
        };
        assert_eq!(m.channel().label(), CHANNEL_INPUT);
        assert!(!m.must_arrive());
    }

    /// The wire form of `viewerVideoSchema`, spelled out by hand: the fixture round-trip catches a
    /// dropped field, this catches the two sides agreeing on a wrong name.
    #[test]
    fn a_video_report_parses_from_the_viewers_wire_form() {
        let m = InputMessage::parse(
            r#"{"t":"vv","frames_received":6180,"frames_decoded":6172,"frames_dropped":0,
                "key_frames_decoded":2,"freeze_count":1,"freeze_ms":2150,"pli_count":2,
                "width":1620,"height":1080,"fps":59.8,"decoder":"VideoToolbox",
                "jbuf_target_ms":42.5,"jbuf_min_ms":0,"rvfc_frames":5980,"vpq_frames":6100,
                "vpq_dropped":3,"current_ms":148250,"paused":false,"ready_state":4,
                "visibility":"visible","platform":"ios","presented_by":"rvfc","watchdog":"ok",
                "kf_asked":0,"reattaches":0,"ev_pause":0,"ev_waiting":1,"ev_stalled":0,
                "engine":"webkit","replacements":1,"recoveries":2,"recovered_at":"replace",
                "recovered_ms":6200,"auto_reconnects":1}"#,
        )
        .unwrap();
        let InputMessage::ViewerVideo(v) = m else {
            panic!("parsed as the wrong variant: {m:?}");
        };
        assert_eq!(v.frames_decoded, Some(6172));
        assert_eq!(v.rvfc_frames, Some(5980));
        assert_eq!(v.ready_state, Some(4));
        assert_eq!(v.paused, Some(false));
        assert_eq!(v.decoder.as_deref(), Some("VideoToolbox"));
        assert_eq!(v.watchdog.as_deref(), Some("ok"));
        assert!(v.fps.is_some_and(|f| (f - 59.8).abs() < 1e-9));
        assert_eq!(v.engine.as_deref(), Some("webkit"));
        assert_eq!(v.replacements, Some(1));
        assert_eq!(v.recoveries, Some(2));
        assert_eq!(v.recovered_at.as_deref(), Some("replace"));
        assert_eq!(v.recovered_ms, Some(6200));
        assert_eq!(v.auto_reconnects, Some(1));
    }

    #[test]
    fn engines_are_read_in_the_contracts_spelling_and_nothing_else() {
        for e in [
            ViewerEngine::WebKit,
            ViewerEngine::Chromium,
            ViewerEngine::Gecko,
            ViewerEngine::Unknown,
        ] {
            assert_eq!(ViewerEngine::from_wire(e.as_str()), e);
        }
        assert_eq!(ViewerEngine::from_wire("WebKit"), ViewerEngine::Unknown);
        assert_eq!(ViewerEngine::from_wire("presto"), ViewerEngine::Unknown);
        assert_eq!(ViewerEngine::from_wire(""), ViewerEngine::Unknown);
    }

    /// An older viewer sends none of the fields, and a WebView sends only what it exposes. Neither
    /// may be refused: absent is "not exposed", and a newer viewer's extra field is ignored.
    #[test]
    fn a_video_report_tolerates_missing_and_unknown_fields() {
        let empty = InputMessage::parse(r#"{"t":"vv"}"#).unwrap();
        assert_eq!(empty, InputMessage::ViewerVideo(Box::default()));
        let partial =
            InputMessage::parse(r#"{"t":"vv","frames_decoded":10,"from_the_future":[1,2]}"#)
                .unwrap();
        let InputMessage::ViewerVideo(v) = partial else {
            panic!("parsed as the wrong variant: {partial:?}");
        };
        assert_eq!(v.frames_decoded, Some(10));
        assert_eq!(v.rvfc_frames, None);
        // And it serialises back without inventing the absent fields as nulls.
        let back = serde_json::to_string(&InputMessage::ViewerVideo(v)).unwrap();
        assert_eq!(back, r#"{"t":"vv","frames_decoded":10}"#);
    }

    #[test]
    fn a_keyframe_request_parses_with_or_without_its_reason() {
        let m = InputMessage::parse(r#"{"t":"kf","reason":"render_stall"}"#).unwrap();
        assert_eq!(
            m,
            InputMessage::KeyframeRequest {
                reason: Some("render_stall".into())
            }
        );
        // A reason this build has never heard of is kept, for the log.
        let newer = InputMessage::parse(r#"{"t":"kf","reason":"solar_flare"}"#).unwrap();
        assert!(
            matches!(newer, InputMessage::KeyframeRequest { reason: Some(r) } if r == "solar_flare")
        );
        let bare = InputMessage::parse(r#"{"t":"kf"}"#).unwrap();
        assert_eq!(bare, InputMessage::KeyframeRequest { reason: None });
    }

    /// The background hold's signal, as the viewer sends it: both values, `why` present and absent,
    /// and absent staying absent on the way back out. A state the two sides must agree on: on the
    /// reliable channel, and required to arrive, like `q`.
    #[test]
    fn a_visibility_message_parses_with_or_without_its_why() {
        let hidden =
            InputMessage::parse(r#"{"t":"vis","hidden":true,"why":"visibilitychange"}"#).unwrap();
        assert_eq!(
            hidden,
            InputMessage::Visibility {
                hidden: true,
                why: Some("visibilitychange".into())
            }
        );
        assert!(hidden.must_arrive());
        assert_eq!(hidden.channel().label(), CHANNEL_INPUT);

        let visible = InputMessage::parse(r#"{"t":"vis","hidden":false}"#).unwrap();
        assert_eq!(
            visible,
            InputMessage::Visibility {
                hidden: false,
                why: None
            }
        );
        assert_eq!(
            serde_json::to_string(&visible).unwrap(),
            r#"{"t":"vis","hidden":false}"#,
            "an absent why stays absent, not null"
        );
        // A place this build has never heard of is kept as given, for the log; an unknown field is
        // ignored.
        let newer =
            InputMessage::parse(r#"{"t":"vis","hidden":true,"why":"tg_deactivated","x":1}"#)
                .unwrap();
        assert!(
            matches!(newer, InputMessage::Visibility { hidden: true, why: Some(w) } if w == "tg_deactivated")
        );
    }

    /// `why` is bounded as the contract bounds it: 32 characters pass, 33 refuse the message — and
    /// characters, not bytes, so 32 Cyrillic letters pass too. A `vis` without `hidden` is no `vis`.
    #[test]
    fn a_visibility_message_with_a_why_past_its_bound_or_no_state_is_refused() {
        let at = "a".repeat(VIS_WHY_MAX_CHARS);
        let past = "a".repeat(VIS_WHY_MAX_CHARS + 1);
        let cyrillic = "я".repeat(VIS_WHY_MAX_CHARS);
        assert!(
            InputMessage::parse(&format!(r#"{{"t":"vis","hidden":true,"why":"{at}"}}"#)).is_ok()
        );
        assert!(InputMessage::parse(&format!(
            r#"{{"t":"vis","hidden":true,"why":"{cyrillic}"}}"#
        ))
        .is_ok());
        assert!(
            InputMessage::parse(&format!(r#"{{"t":"vis","hidden":true,"why":"{past}"}}"#)).is_err()
        );
        assert!(InputMessage::parse(r#"{"t":"vis","why":"reconcile"}"#).is_err());
        assert!(InputMessage::parse(r#"{"t":"vis","hidden":"yes"}"#).is_err());
    }

    /// `code` and `key` are bounded as the contract bounds them: 32 UTF-16 units pass, 33 refuse the
    /// whole message — counted as the viewer's schema counts, so 32 Cyrillic letters pass and 17
    /// emoji (34 units) do not. `d` is 0 or 1.
    #[test]
    fn a_key_message_past_its_bounds_is_refused() {
        let k = |code: &str, key: Option<&str>| {
            let key = key.map_or(String::new(), |k| format!(r#","key":"{k}""#));
            InputMessage::parse(&format!(r#"{{"t":"k","d":1,"code":"{code}"{key}}}"#))
        };
        let at = "a".repeat(KEY_FIELD_MAX_UNITS);
        let past = "a".repeat(KEY_FIELD_MAX_UNITS + 1);
        let cyrillic = "я".repeat(KEY_FIELD_MAX_UNITS);
        let emoji = "😀".repeat(KEY_FIELD_MAX_UNITS / 2 + 1);
        assert!(k(&at, None).is_ok());
        assert!(k(&at, Some(&at)).is_ok());
        assert!(
            k("", Some(&cyrillic)).is_ok(),
            "an IME's empty code, a long key"
        );
        assert!(k(&past, None).is_err(), "a code past 32");
        assert!(k("KeyA", Some(&past)).is_err(), "a key past 32");
        assert!(k("KeyA", Some(&emoji)).is_err(), "34 UTF-16 units");
        assert!(k(&emoji, None).is_err());
        assert!(InputMessage::parse(r#"{"t":"k","d":0,"code":"KeyA"}"#).is_ok());
        assert!(InputMessage::parse(r#"{"t":"k","d":2,"code":"KeyA"}"#).is_err());
    }

    /// Both ride the reliable channel, and neither is required: a lost report is one sample, a lost
    /// request is repeated by the viewer on its backoff.
    #[test]
    fn the_video_report_and_keyframe_request_are_reliable_without_being_required() {
        for m in [
            InputMessage::ViewerVideo(Box::default()),
            InputMessage::KeyframeRequest {
                reason: Some("decode_stall".into()),
            },
        ] {
            assert_eq!(m.channel().label(), CHANNEL_INPUT, "{m:?}");
            assert!(!m.must_arrive(), "{m:?}");
        }
    }
}
