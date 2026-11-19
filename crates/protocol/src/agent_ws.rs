//! The `/ws/agent` signaling channel.
//!
//! Both directions are typed. The inbound one matters most: the agent starts screen
//! capture off the back of these messages, so "whatever the server sent" has to
//! become a value with a shape before anything acts on it.

use serde::{Deserialize, Serialize};

use crate::common::{BindingInfo, IceCandidate, PairDeclineReason, SdpType, TurnCreds};
use crate::hw::AgentHw;
use crate::invites::BindingVia;
use crate::metrics::{
    AgentBuildInfo, AgentEvent, AgentLastExit, AgentSessionEndDetail, AgentSessionSummary,
};
use crate::party::{PartyAckOp, PartyAckResult, PartyDelegation};
use crate::roles::{
    BindingRole, OwnerRequestKind, OwnerRequestReason, OwnerRequestState, OwnerStateKind,
};

/// Domain prefix of the signed challenge: ASCII, 30 bytes with the trailing NUL.
///
/// Mirrors `AGENT_CHALLENGE_PREFIX` in the contract (`agent-ws.ts`), its single source;
/// `tests/agent_challenge.rs` holds this copy to `vectors/agent-challenge-signature.json`. The agent
/// signs these bytes followed by the 32 nonce bytes ([`agent_challenge_message`]), so a challenge
/// signature is never valid for anything else the device key signs (signed requests start with
/// [`crate::diagnostics::AGENT_REQUEST_SCHEME`]).
pub const AGENT_CHALLENGE_PREFIX: &[u8; 30] = b"AFKLINK-AGENT-WS-CHALLENGE-V1\0";

/// Bytes in a `challenge.nonce` once base64 decoded (`AGENT_CHALLENGE_NONCE_BYTES` in the contract).
pub const AGENT_CHALLENGE_NONCE_BYTES: usize = 32;

/// Bytes the agent signs for `agent_auth`: the prefix and the nonce.
pub const AGENT_CHALLENGE_MESSAGE_BYTES: usize =
    AGENT_CHALLENGE_PREFIX.len() + AGENT_CHALLENGE_NONCE_BYTES;

/// What the agent signs for `agent_auth`: [`AGENT_CHALLENGE_PREFIX`] followed by the decoded
/// nonce. `None` for a nonce that is not exactly [`AGENT_CHALLENGE_NONCE_BYTES`] long: the agent
/// signs nothing for it.
pub fn agent_challenge_message(nonce: &[u8]) -> Option<[u8; AGENT_CHALLENGE_MESSAGE_BYTES]> {
    if nonce.len() != AGENT_CHALLENGE_NONCE_BYTES {
        return None;
    }
    let mut message = [0u8; AGENT_CHALLENGE_MESSAGE_BYTES];
    let (prefix, rest) = message.split_at_mut(AGENT_CHALLENGE_PREFIX.len());
    prefix.copy_from_slice(AGENT_CHALLENGE_PREFIX);
    rest.copy_from_slice(nonce);
    Some(message)
}

/// [`AgentToServer::GrantToken`]'s value, as on the wire (a bare string). Its `Debug` shows only
/// whether there is one, so a message printed with `{:?}` never carries the token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GrantTokenText(pub String);

impl std::fmt::Debug for GrantTokenText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() {
            "GrantTokenText(\"\")"
        } else {
            "GrantTokenText(<hidden>)"
        })
    }
}

/// Messages the agent sends to the backend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentToServer {
    /// First frame. Announces identity and the protocol version this build speaks.
    AgentHello {
        protocol_version: u32,
        device_id: String,
        /// base64 Ed25519 public key, 32 bytes.
        pubkey: String,
        /// Contract v2: this build (`crate::metrics::AgentBuildInfo`), stored on every session the
        /// PC serves. Absent from an older agent, and when the build's own values do not fit the
        /// contract (a hello the server refuses would be refused on every attempt).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        build: Option<AgentBuildInfo>,
        /// Contract v2: this process's random id, new on every start.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        boot_id: Option<String>,
        /// Contract v2: how the previous process ended (`afklink_core::run_state`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_exit: Option<AgentLastExit>,
        /// The invite-only beta: the PC's hardware fingerprint (`crate::hw`, `afklink_core::hw`).
        /// Absent from an older agent, from one that could read no part of the PC, and when what it
        /// read does not fit the contract (`AgentHw::check`) — the server then judges the PC
        /// `unknown`, as before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hw: Option<AgentHw>,
    },
    /// Signature over the challenge nonce, proving ownership of the private key.
    AgentAuth {
        /// base64 Ed25519 signature over [`agent_challenge_message`] of the challenge's nonce.
        signature: String,
    },
    /// The owner opened the pairing panel. The code stays valid while it is open.
    RequestPairing,
    /// The owner closed the pairing panel; invalidate the code now.
    PairingCancel,
    /// The owner's answer to a `PairRequest`. Only this creates a binding.
    PairResponse {
        request_id: String,
        accept: bool,
        /// This PC's name, sent with an approval: the backend makes it the device's name before it
        /// tells the Mini App, which otherwise lists the device under the backend's placeholder.
        /// `None` with a refusal, and when the stored name is not a valid one
        /// ([`crate::validate_device_name`]); the backend then keeps the name it has.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// The role the PC gives the person it approves: the answer
        /// to «Кто это?» when the prompt said `has_owner: false`, else `guest` — with every
        /// approval from an agent that knows roles. The server applies it only on a PC with no
        /// owner when the answer arrives. `None` with a refusal: no key on the wire.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<BindingRole>,
        /// The device key the PC took from this request's `viewer_key` (device keys, spec §5), sent
        /// with an approval that recorded one: for the server's hints only, it lets in nobody.
        /// Strict base64url of 32 bytes ([`crate::viewer_keys::is_b64url`]). `None` when no key was
        /// taken, and with a refusal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key_id: Option<String>,
    },
    /// This PC's name, after every authentication and whenever the owner renames the PC: the
    /// device's name follows the PC. Always a valid device name
    /// ([`crate::validate_device_name`]); the agent sends nothing rather than one that is not.
    DeviceName {
        name: String,
    },
    /// A batch of one-time numbers for `offer_proof` (device keys, spec §2.2): [`NONCE_BATCH`]
    /// fresh `nonce_pc` from the PC's CSPRNG, each strict base64url of 16 bytes, all different
    /// ([`crate::viewer_keys::is_nonce_batch`]). Sent only on a connection whose `agent_ready` said
    /// `nonce_pool` — an older server answers `bad_message` — after `device_name`, every
    /// `NONCE_ROTATE_MS`, and on a `session_request` that asks for a refill. Dropped while offline
    /// (`afklink_core::relay`): a batch is worth nothing on another connection. `batch` rises with
    /// every batch of the process, for the logs. Never logged: the nonces.
    ///
    /// [`NONCE_BATCH`]: crate::viewer_keys::NONCE_BATCH
    SessionNonces {
        batch: u32,
        nonces: Vec<String>,
    },
    /// The PC's mode (device keys, spec §12): `observe`, or `strict` with «Доверенные устройства»
    /// on. Sent right after `agent_ready` (after `device_name`) only on a connection whose
    /// `agent_ready` said `nonce_pool` — an older server answers `bad_message` — and again at every
    /// switch. The server keeps the last one per connection (each `agent_ready` resets it to
    /// unknown, read as `observe`) and asks the owner about a guest's `new_device` by it (§7); it
    /// lets in nobody. Dropped while offline (`afklink_core::relay`): the next connection gets the
    /// mode after its own `agent_ready`.
    KeyMode {
        mode: crate::viewer_keys::KeyMode,
    },
    /// The PC's grant token (device keys, spec §7 «Токен выдачи», §12): 22 characters of
    /// base64url, or `""` while the PC has none. Sent after this connection's `key_mode` and right
    /// after every write that replaced the token lands, only on a connection whose `agent_ready`
    /// said `grant_token` — an older server answers `bad_message`; never while the key list is
    /// damaged. The server hands it to the owner, who signs it into a `grant`; it decides nothing
    /// by it. Never logged: only that it was sent.
    GrantToken {
        token: GrantTokenText,
    },
    /// The PC's answer to a [`ServerToAgent::PartyJoin`] or a [`ServerToAgent::PartyLeave`] (party
    /// spec §4.2): the first check that failed, or `ok`, sent once the key list's snapshot that holds
    /// the decision was written. `party_id` echoes the statement's (strict base64url of 16 bytes,
    /// [`crate::party::is_party_id`]). Only on a connection whose `agent_ready` said `party` — an
    /// older server answers `bad_message`.
    PartyAck {
        party_id: String,
        op: PartyAckOp,
        result: PartyAckResult,
    },
    /// Every delegation the PC holds (party spec §4.1), the whole truth as its key list's file has
    /// it, empty too: after this connection's `grant_token` and after every write that changed
    /// them (after that write's `party_ack`), only on a connection whose `agent_ready` said
    /// `party`. Never while the key list is damaged: a delegation reported and then gone reads as
    /// the PC leaving the party. The server checks it ([`crate::party::check_party_state`]).
    PartyState {
        parties: Vec<PartyDelegation>,
    },
    /// Revoke a user's access from the PC side. A guest's goes at once; the owner's is taken by the
    /// server as [`AgentToServer::OwnerRequest`] `unbind_owner` and waits for the owner.
    Unbind {
        telegram_user_id: i64,
    },
    /// An owner-level change: `make_owner` — the guest named becomes
    /// the owner; `unbind_owner` — the owner's binding goes. Never applied on the PC's word while the
    /// PC has an owner: the server asks the owner, and `owner_request_state` says how it went.
    OwnerRequest {
        kind: OwnerRequestKind,
        telegram_user_id: i64,
    },
    /// The PC withdraws its pending request.
    OwnerRequestCancel {
        request_id: String,
    },
    Sdp {
        session_id: String,
        sdp_type: SdpType,
        sdp: String,
    },
    Ice {
        session_id: String,
        candidate: IceCandidate,
    },
    SessionEnd {
        session_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// Contract v2 (`crate::metrics::SessionEndDetail`): `peer_closed` split into the viewer's
        /// goodbye and str0m's own close, and how the peer saw its path — kinds and verdicts, never
        /// an address. Absent when there is nothing to say, and from an older agent. On an end with a
        /// reason of device keys also `key_mode` ([`AgentSessionEndDetail`]).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<AgentSessionEndDetail>,
    },
    /// A cumulative report on a running session.
    ///
    /// Sent repeatedly rather than once at the end. A session that ends cleanly usually worked;
    /// the ones worth studying are those that died because this process crashed or the network
    /// went away, and an end-of-session report is exactly what those never send. Cumulative
    /// totals mean the last one that got through is still a complete summary.
    SessionStats {
        session_id: String,
        stats: AgentSessionStats,
        /// Contract v2: the session's last report, sent once on any end — the agent's own, the
        /// viewer's, the server's (`"final": true`). The server takes it for
        /// [`crate::metrics::SESSION_TOMBSTONE_MS`] after the session ended and drops this side's
        /// later reports. `false` is no key on the wire, as every report before it.
        #[serde(rename = "final", default, skip_serializing_if = "std::ops::Not::not")]
        is_final: bool,
    },
    Pong,
    /// The agent is leaving on purpose, and why: the last frame before a normal close, so the
    /// backend marks the PC offline at once instead of finding out from its heartbeat. A backend
    /// older than the message answers `error bad_message` and keeps the socket; the close that
    /// follows ends it all the same.
    AgentGoodbye {
        reason: GoodbyeReason,
    },
    /// Contract v2: something that happened on the PC outside any session (`agent_event`,
    /// [`crate::metrics::AgentEvent`]). Only after `agent_ready`; a server older than the message
    /// answers `error bad_message` and keeps the socket.
    AgentEvent(AgentEvent),
    /// A secure-desktop episode (`crate::secure_desktop`) has lasted
    /// [`crate::SECURE_DESKTOP_ONGOING_AFTER_MS`] during the live session `session_id`, and is still
    /// on: `desktop` as the heartbeat says it now, `at` the episode's start (Unix ms on the PC's
    /// clock). Once per episode; never held for another connection (the relay drops it), never
    /// queued. The server's cue for the owner's notice in the bot. Only on a connection
    /// whose `agent_ready` said `secure_desktop` — an older server answers `bad_message`.
    SecureDesktopOngoing {
        session_id: String,
        desktop: crate::SecureDesktopKind,
        at: u64,
    },
}

/// Why the agent says goodbye (`agent_goodbye.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoodbyeReason {
    /// The owner quit the app (the tray's «Выход»), or it exited normally.
    Quit,
    /// Windows is logging off, shutting down or restarting.
    Shutdown,
    /// The system is going to sleep; the agent comes back on resume.
    Sleep,
    /// The app exits to put an update in place; the new version connects within seconds.
    Update,
}

impl GoodbyeReason {
    /// Every reason, in the contract's order.
    pub const ALL: [Self; 4] = [Self::Quit, Self::Shutdown, Self::Sleep, Self::Update];

    /// The wire word.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quit => "quit",
            Self::Shutdown => "shutdown",
            Self::Sleep => "sleep",
            Self::Update => "update",
        }
    }
}

/// What the agent knows about a session: what it captured, encoded and sent.
///
/// Field names match the TypeScript schema in `packages/protocol/src/telemetry.ts` and the
/// golden fixtures assert both sides agree, so a rename here fails a test rather than silently
/// dropping a column on the server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSessionStats {
    pub duration_ms: u64,

    /// Source resolution before scaling — tells a 4K panel apart from a laptop.
    pub source_w: u32,
    pub source_h: u32,

    /// Frames the capturer delivered. Near zero means a static screen, not a failure.
    pub frames_captured: u64,
    pub frames_encoded: u64,
    /// The encoder fell behind and a newer frame superseded this one. A fault.
    pub frames_dropped_stale: u64,
    /// Deliberately not encoded, because congestion control asked for a lower rate. Not a fault,
    /// and kept apart from `frames_dropped_stale` for exactly that reason.
    pub frames_dropped_paced: u64,
    /// The encoder skipped it itself, to hold its bitrate target.
    pub frames_skipped_encoder: u64,

    /// Mean milliseconds inside `encode()`. A debug build does not stand out much here: the dev
    /// profile optimises dependencies, OpenH264 among them, and only our crates stay at opt-level 0
    /// (release: 3 with thin LTO), so a debug build is slower, not obviously so.
    pub encode_ms_avg: f64,
    /// Worst single encode: a mean hides a stall, this does not.
    pub encode_ms_max: f64,

    pub bytes_sent: u64,

    /// Lowest rung the quality ladder reached, as encoded height.
    pub lowest_height: u32,
    pub quality_changes: u64,
    /// Most recent bandwidth estimate, kbps, or null before congestion control has spoken.
    pub estimate_kbps: Option<u32>,

    pub encode_errors: u64,

    /// Milliseconds this session's video was held back because the viewer's page was hidden (the
    /// background hold, `afklink_core::bg_hold`), cumulative, a hold still under way counted up to
    /// the report; and how many holds began. This agent always sends both, 0 included; absent from
    /// older agents — never reported, not zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bg_hold_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bg_holds: Option<u64>,

    /// Contract v2: the agent's summary of the session so far ([`AgentSessionSummary`],
    /// `afklink_core::summary`), in every report. Absent from an older agent, and from a report
    /// whose summary did not pass [`AgentSessionSummary::check`] (never expected: the report then
    /// goes without it rather than not at all). Boxed: it is most of the report's size, and the
    /// message enum would otherwise be that size for every message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<Box<AgentSessionSummary>>,
}

/// Messages the backend sends to the agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerToAgent {
    /// Nonce to sign: base64 of exactly [`AGENT_CHALLENGE_NONCE_BYTES`] random bytes, signed
    /// behind [`AGENT_CHALLENGE_PREFIX`]. Valid for this connection only.
    Challenge {
        nonce: String,
    },
    /// Handshake accepted. Carries the server's version window and current bindings.
    AgentReady {
        protocol_version: u32,
        min_supported_protocol: u32,
        bindings: Vec<BindingInfo>,
        /// The server keeps a pool of the PC's one-time numbers (device keys, spec §2.2): the agent
        /// sends [`AgentToServer::SessionNonces`] on this connection, and only on one that said so.
        /// `Some(true)` from such a server (the contract's literal `true`); `None` from a server
        /// older than device keys.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce_pool: Option<bool>,
        /// The server takes [`AgentToServer::GrantToken`] (spec §7 «Токен выдачи», §12): the agent
        /// sends it on this connection, and only on one that said so. `Some(true)` from such a
        /// server; `None` from one older than the grant token (the owner then signs `""`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant_token: Option<bool>,
        /// The server takes the party messages (party spec §4.1): the agent sends
        /// [`AgentToServer::PartyAck`] and [`AgentToServer::PartyState`] on this connection, and only
        /// on one that said so. `Some(true)` from such a server; `None` from one older than parties.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        party: Option<bool>,
        /// The server takes [`AgentToServer::SecureDesktopOngoing`] and the `agent_event`
        /// `secure_desktop_ended` (`crate::secure_desktop`): the agent sends them on this connection,
        /// and only on one that said so. `Some(true)` from such a server; `None` from an older one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secure_desktop: Option<bool>,
    },
    /// The code to display. `expires_at` is a ceiling, not the expected lifetime.
    PairingCode {
        code: String,
        expires_at: i64,
        /// The bot the pairing link opens (`t.me/<bot_username>/<miniapp_short_name>`): the
        /// backend's `TG_BOT_USERNAME`. Absent from a backend older than the field or without one
        /// configured; the agent then offers no link rather than guess (`afklink_core::qr`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bot_username: Option<String>,
        /// The Mini App's short name in that link: the backend's `TG_MINIAPP_SHORT_NAME`. Absent
        /// as `bot_username` is, each on its own.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        miniapp_short_name: Option<String>,
    },
    /// Someone redeemed the code and is waiting for the owner to approve.
    PairRequest {
        request_id: String,
        telegram_user_id: i64,
        username: Option<String>,
        first_name: Option<String>,
        expires_at: i64,
        /// Whether the PC has an owner as the prompt goes up:
        /// `Some(false)` — after «Разрешить» the PC asks «Кто это?»; `Some(true)` — no question, the
        /// new person is a guest. `None` from a server older than roles: no question either.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        has_owner: Option<bool>,
        /// The asking device's key card (`key_reg`, device keys, spec §4, §5), from `POST /api/pair`.
        /// Opaque here, kept raw like `session_request.quality_profile`: the agent holds it to the
        /// limits itself ([`crate::viewer_keys::check_viewer_key_wire`]) and parses it in
        /// `afklink_core`, taking it only while its pairing panel is open; one it cannot parse costs
        /// the key (`admit_refused:key_reg_bad`), never the prompt. `None` from a client or a server
        /// older than device keys. Never logged.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        viewer_key: Option<serde_json::Value>,
    },
    /// The pending prompt is no longer valid; dismiss it.
    PairCancelled {
        request_id: String,
        reason: PairDeclineReason,
    },
    BindingAdded {
        telegram_user_id: i64,
        username: Option<String>,
        first_name: Option<String>,
        /// The binding's role; absent from a server older than roles. A re-pair repeats the role
        /// the binding has.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<BindingRole>,
        /// How the binding came about: [`BindingVia::Invite`] — the owner let a friend in from
        /// Telegram by his invite, and nobody at the PC was asked (always with `role: guest`); the
        /// PC tells the person at it at once. Absent for a binding from the PC's own «Разрешить» and
        /// from a server older than invites. A word this build does not know is
        /// [`BindingVia::Other`], read as no `via` at all: the message is never refused for it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via: Option<BindingVia>,
        /// The parties through which this person is a guest of this PC now (`party_id`s), as
        /// [`crate::BindingInfo::parties`]. Empty (or absent on the wire): none, or a server older
        /// than the field.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        parties: Vec<String>,
    },
    BindingRemoved {
        telegram_user_id: i64,
    },
    /// The PC's owner changed other than by a new binding: this account is the owner now and every
    /// other binding a guest; `None` (`null` on the wire, never absent) — the PC has no owner. The
    /// whole truth about roles, not a change to apply on top of the list.
    OwnerChanged {
        telegram_user_id: Option<i64>,
    },
    /// Where a request from the PC stands. `kind` and
    /// `telegram_user_id` always, so the PC can mark the person's row; `request_id` on every state
    /// but `refused`; `expires_at` with `pending`; `reason` with `cancelled` and `refused` only. Also
    /// sent right after `agent_ready` for a request still pending.
    ///
    /// `kind` is an [`OwnerStateKind`]: besides the PC's own two, `pc_allow` — the PC's «Разрешить»
    /// held for the owner because someone other than the owner had a session on the PC: whoever
    /// pressed it may not be the owner, so the PC's own button does not stand for the owner's
    /// consent. Its `request_id` is the pairing's, its person the newcomer, whom the PC's list does
    /// not have yet — so the state names them (`username`, `first_name`).
    OwnerRequestState {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        kind: OwnerStateKind,
        telegram_user_id: i64,
        state: OwnerRequestState,
        /// Unix ms; with `pending`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<OwnerRequestReason>,
        /// The person named, as `pair_request` names them; with `pc_allow`. Absent (or `null`)
        /// from a server older than the fields and for the PC's own two kinds, whose person is in
        /// the list. Without its `@`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        first_name: Option<String>,
    },
    /// «ПК в пати» (party spec §2.2, §4): the owner's signed statement naming the party's leader,
    /// relayed unchanged. Opaque here, like `sdp.proof`: the agent holds it to the limits itself
    /// ([`crate::party::check_party_statement_wire`]) and parses it in `afklink_core`, answering every
    /// fault with [`AgentToServer::PartyAck`], never by dropping the frame — but a join with no
    /// readable `party_id`, which no answer can name (the server relays only a join whose
    /// `party_id` is readable): that one is logged at `warn` and not answered. Never logged: it
    /// carries a signature.
    PartyJoin {
        join: serde_json::Value,
    },
    /// The PC leaves a party (party spec §4.2): the server's word, which only takes away, like
    /// `binding_removed`. Kept as a string: its form is the agent's to judge. Answered with
    /// [`AgentToServer::PartyAck`] `op: leave`.
    PartyLeave {
        party_id: String,
    },
    /// A bound viewer wants a session. Nothing should start capturing without one.
    SessionRequest {
        session_id: String,
        telegram_user_id: i64,
        username: Option<String>,
        turn: TurnCreds,
        /// The quality controller's tuning for this session (`qualityProfileSchema`), kept raw: the
        /// agent validates it itself (`afklink_core::quality_policy::QualityPolicy::from_wire`), so
        /// any *well-formed JSON* profile — a wrong shape, wrong types, values out of range, a
        /// newer server's fields — costs only the profile (the agent falls back to its compiled
        /// one), not the `session_request`, which would cost the session. Absent from a server
        /// older than the field.
        ///
        /// Not protected: JSON that serde_json cannot hold as a `Value` at all — nesting deeper
        /// than its recursion limit (128) or a number out of `f64` range (`1e400`) — fails the
        /// whole message's parse, profile or not: this enum is internally tagged, so serde buffers
        /// the whole message before it reads a field, and no lenient field type can step in. The
        /// server is ours and sends `JSON.stringify` of a zod-parsed profile, which produces
        /// neither (`any_quality_profile_leaves_the_session_request_parsing` pins both cases).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        quality_profile: Option<serde_json::Value>,
        /// The one-time number the server put in this session's `session_created` (device keys,
        /// spec §2.2): for the PC's accounting and logs — the truth is in the offer's `proof`. Kept
        /// as a string: one not of a nonce's form costs the refill decision, never the request
        /// ([`crate::viewer_keys::is_b64url`]). `None` when the pool had none, and from a server
        /// older than device keys. Never logged.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce_pc: Option<String>,
    },
    /// The viewer's SDP, relayed.
    Sdp {
        session_id: String,
        sdp_type: SdpType,
        sdp: String,
        /// The viewer's `offer_proof` (device keys, spec §3.2), relayed unchanged: opaque here, held
        /// to the limits by [`crate::viewer_keys::check_proof_wire`] and parsed in `afklink_core`,
        /// which turns any fault into a verdict, never into a dropped frame. Only an offer carries
        /// one; on an answer the contract refuses it, and the agent ignores it rather than drop the
        /// frame. The JSON nesting `serde_json` itself refuses (past 128) still fails the frame —
        /// see [`crate::viewer_keys`]. `None` from a viewer or a server older than device keys.
        /// Never logged.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proof: Option<serde_json::Value>,
    },
    Ice {
        session_id: String,
        candidate: IceCandidate,
    },
    SessionEnd {
        session_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Ping,
    Error {
        code: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
}

impl AgentToServer {
    /// The wire `type` of this message.
    ///
    /// For log lines, which must say what went over the socket without carrying it: an `sdp` is
    /// kilobytes, and `agent_auth` carries a signature. `messages_name_their_wire_type` holds this to
    /// serde's own tag, so the two cannot drift.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AgentHello { .. } => "agent_hello",
            Self::AgentAuth { .. } => "agent_auth",
            Self::RequestPairing => "request_pairing",
            Self::PairingCancel => "pairing_cancel",
            Self::PairResponse { .. } => "pair_response",
            Self::DeviceName { .. } => "device_name",
            Self::SessionNonces { .. } => "session_nonces",
            Self::KeyMode { .. } => "key_mode",
            Self::GrantToken { .. } => "grant_token",
            Self::PartyAck { .. } => "party_ack",
            Self::PartyState { .. } => "party_state",
            Self::Unbind { .. } => "unbind",
            Self::OwnerRequest { .. } => "owner_request",
            Self::OwnerRequestCancel { .. } => "owner_request_cancel",
            Self::Sdp { .. } => "sdp",
            Self::Ice { .. } => "ice",
            Self::SessionEnd { .. } => "session_end",
            Self::SessionStats { .. } => "session_stats",
            Self::Pong => "pong",
            Self::AgentGoodbye { .. } => "agent_goodbye",
            Self::AgentEvent(_) => "agent_event",
            Self::SecureDesktopOngoing { .. } => "secure_desktop_ongoing",
        }
    }

    /// The session this message is about, if it is about one. For log lines.
    pub fn session_id(&self) -> Option<&str> {
        match self {
            Self::Sdp { session_id, .. }
            | Self::Ice { session_id, .. }
            | Self::SessionEnd { session_id, .. }
            | Self::SessionStats { session_id, .. }
            | Self::SecureDesktopOngoing { session_id, .. } => Some(session_id),
            _ => None,
        }
    }

    /// A session's final report (`session_stats` with `"final": true`): what the signaling relay
    /// holds through an outage for as long as the server would still take it.
    pub fn is_final_report(&self) -> bool {
        matches!(self, Self::SessionStats { is_final: true, .. })
    }
}

impl ServerToAgent {
    /// The wire `type` of this message. See [`AgentToServer::kind`]: here it also keeps a
    /// `session_request`'s TURN credential and a `pairing_code`'s code out of the log.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Challenge { .. } => "challenge",
            Self::AgentReady { .. } => "agent_ready",
            Self::PairingCode { .. } => "pairing_code",
            Self::PairRequest { .. } => "pair_request",
            Self::PairCancelled { .. } => "pair_cancelled",
            Self::BindingAdded { .. } => "binding_added",
            Self::BindingRemoved { .. } => "binding_removed",
            Self::OwnerChanged { .. } => "owner_changed",
            Self::OwnerRequestState { .. } => "owner_request_state",
            Self::PartyJoin { .. } => "party_join",
            Self::PartyLeave { .. } => "party_leave",
            Self::SessionRequest { .. } => "session_request",
            Self::Sdp { .. } => "sdp",
            Self::Ice { .. } => "ice",
            Self::SessionEnd { .. } => "session_end",
            Self::Ping => "ping",
            Self::Error { .. } => "error",
        }
    }

    /// The session this message is about, if it is about one. For log lines.
    pub fn session_id(&self) -> Option<&str> {
        match self {
            Self::SessionRequest { session_id, .. }
            | Self::Sdp { session_id, .. }
            | Self::Ice { session_id, .. }
            | Self::SessionEnd { session_id, .. } => Some(session_id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `kind()` is what the log calls a message; serde's tag is what the wire calls it. One of
    /// every variant, so a new one that is given the wrong name, or none, fails here.
    #[test]
    fn messages_name_their_wire_type() {
        let ice = IceCandidate {
            candidate: String::new(),
            sdp_mid: None,
            sdp_mline_index: None,
            username_fragment: None,
        };
        let stats = AgentSessionStats {
            duration_ms: 0,
            source_w: 0,
            source_h: 0,
            frames_captured: 0,
            frames_encoded: 0,
            frames_dropped_stale: 0,
            frames_dropped_paced: 0,
            frames_skipped_encoder: 0,
            encode_ms_avg: 0.0,
            encode_ms_max: 0.0,
            bytes_sent: 0,
            lowest_height: 0,
            quality_changes: 0,
            estimate_kbps: None,
            encode_errors: 0,
            bg_hold_ms: Some(0),
            bg_holds: Some(0),
            summary: None,
        };
        let s = || "s".to_string();
        let outgoing = [
            AgentToServer::AgentHello {
                protocol_version: 1,
                device_id: s(),
                pubkey: s(),
                build: None,
                boot_id: None,
                last_exit: None,
                hw: None,
            },
            AgentToServer::AgentAuth { signature: s() },
            AgentToServer::RequestPairing,
            AgentToServer::PairingCancel,
            AgentToServer::PairResponse {
                request_id: s(),
                accept: true,
                name: Some(s()),
                role: Some(BindingRole::Guest),
                key_id: Some(s()),
            },
            AgentToServer::DeviceName { name: s() },
            AgentToServer::SessionNonces {
                batch: 0,
                nonces: vec![s()],
            },
            AgentToServer::KeyMode {
                mode: crate::viewer_keys::KeyMode::Strict,
            },
            AgentToServer::GrantToken {
                token: GrantTokenText(s()),
            },
            AgentToServer::PartyAck {
                party_id: s(),
                op: PartyAckOp::Leave,
                result: PartyAckResult::Ok,
            },
            AgentToServer::PartyState { parties: vec![] },
            AgentToServer::Unbind {
                telegram_user_id: 1,
            },
            AgentToServer::OwnerRequest {
                kind: OwnerRequestKind::MakeOwner,
                telegram_user_id: 1,
            },
            AgentToServer::OwnerRequestCancel { request_id: s() },
            AgentToServer::Sdp {
                session_id: s(),
                sdp_type: SdpType::Answer,
                sdp: s(),
            },
            AgentToServer::Ice {
                session_id: s(),
                candidate: ice.clone(),
            },
            AgentToServer::SessionEnd {
                session_id: s(),
                reason: None,
                detail: None,
            },
            AgentToServer::SessionStats {
                session_id: s(),
                stats,
                is_final: true,
            },
            AgentToServer::Pong,
            AgentToServer::AgentGoodbye {
                reason: GoodbyeReason::Shutdown,
            },
            AgentToServer::AgentEvent(crate::metrics::AgentEvent {
                at: 1,
                event: crate::metrics::AgentEventKind::PcSettingChanged {
                    key: crate::metrics::PcSettingKey::GameOnly,
                    value: crate::metrics::PcSettingValue::Flag(true),
                },
            }),
            AgentToServer::SecureDesktopOngoing {
                session_id: s(),
                desktop: crate::SecureDesktopKind::Uac,
                at: 1,
            },
        ];
        for m in &outgoing {
            let v = serde_json::to_value(m).expect("serialises");
            assert_eq!(v["type"], m.kind(), "{m:?}");
        }
        let incoming = [
            ServerToAgent::Challenge { nonce: s() },
            ServerToAgent::AgentReady {
                protocol_version: 1,
                min_supported_protocol: 1,
                bindings: vec![],
                nonce_pool: Some(true),
                grant_token: Some(true),
                party: Some(true),
                secure_desktop: Some(true),
            },
            ServerToAgent::PairingCode {
                code: s(),
                expires_at: 0,
                bot_username: None,
                miniapp_short_name: None,
            },
            ServerToAgent::PairRequest {
                request_id: s(),
                telegram_user_id: 1,
                username: None,
                first_name: None,
                expires_at: 0,
                has_owner: None,
                viewer_key: Some(serde_json::json!({})),
            },
            ServerToAgent::PairCancelled {
                request_id: s(),
                reason: PairDeclineReason::Declined,
            },
            ServerToAgent::BindingAdded {
                telegram_user_id: 1,
                username: None,
                first_name: None,
                role: None,
                via: Some(BindingVia::Invite),
                parties: Vec::new(),
            },
            ServerToAgent::BindingRemoved {
                telegram_user_id: 1,
            },
            ServerToAgent::OwnerChanged {
                telegram_user_id: None,
            },
            ServerToAgent::OwnerRequestState {
                request_id: None,
                kind: OwnerStateKind::UnbindOwner,
                telegram_user_id: 1,
                state: OwnerRequestState::Refused,
                expires_at: None,
                reason: Some(OwnerRequestReason::Busy),
                username: None,
                first_name: None,
            },
            ServerToAgent::PartyJoin {
                join: serde_json::json!({}),
            },
            ServerToAgent::PartyLeave { party_id: s() },
            ServerToAgent::SessionRequest {
                session_id: s(),
                telegram_user_id: 1,
                username: None,
                turn: TurnCreds {
                    urls: vec![],
                    username: s(),
                    credential: s(),
                },
                quality_profile: None,
                nonce_pc: Some(s()),
            },
            ServerToAgent::Sdp {
                session_id: s(),
                sdp_type: SdpType::Offer,
                sdp: s(),
                proof: Some(serde_json::json!({})),
            },
            ServerToAgent::Ice {
                session_id: s(),
                candidate: ice,
            },
            ServerToAgent::SessionEnd {
                session_id: s(),
                reason: None,
            },
            ServerToAgent::Ping,
            ServerToAgent::Error {
                code: s(),
                message: None,
            },
        ];
        for m in &incoming {
            let v = serde_json::to_value(m).expect("serialises");
            assert_eq!(v["type"], m.kind(), "{}", m.kind());
        }
    }

    /// `agent_goodbye` is exactly `{"type":"agent_goodbye","reason":…}`, one wire word per reason,
    /// and reads back the same; a reason outside the four is refused rather than read as another.
    #[test]
    fn a_goodbye_carries_its_reason_by_the_wire_word() {
        for (reason, word) in [
            (GoodbyeReason::Quit, "quit"),
            (GoodbyeReason::Shutdown, "shutdown"),
            (GoodbyeReason::Sleep, "sleep"),
            (GoodbyeReason::Update, "update"),
        ] {
            assert_eq!(reason.as_str(), word);
            let msg = AgentToServer::AgentGoodbye { reason };
            let text = serde_json::to_string(&msg).expect("serialises");
            assert_eq!(
                text,
                format!(r#"{{"type":"agent_goodbye","reason":"{word}"}}"#)
            );
            assert_eq!(
                serde_json::from_str::<AgentToServer>(&text).expect("parses"),
                msg
            );
            assert_eq!(msg.kind(), "agent_goodbye");
            assert_eq!(msg.session_id(), None);
        }
        assert_eq!(GoodbyeReason::ALL.len(), 4);
        assert!(serde_json::from_str::<AgentToServer>(
            r#"{"type":"agent_goodbye","reason":"crash"}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<AgentToServer>(r#"{"type":"agent_goodbye"}"#).is_err(),
            "the reason is required"
        );
    }

    /// The grant token goes out as a bare string, and a message printed with `{:?}` (a log line,
    /// a panic, a test's failure) carries none of it.
    #[test]
    fn a_grant_token_is_sent_as_text_and_never_printed() {
        let value = "AQEBAQEBAQEBAQEBAQEBAQ";
        let msg = AgentToServer::GrantToken {
            token: GrantTokenText(value.into()),
        };
        assert_eq!(
            serde_json::to_value(&msg).unwrap(),
            serde_json::json!({"type": "grant_token", "token": value})
        );
        let back: AgentToServer =
            serde_json::from_value(serde_json::json!({"type": "grant_token", "token": value}))
                .unwrap();
        assert_eq!(back, msg);
        for printed in [format!("{msg:?}"), format!("{msg:#?}"), format!("{back:?}")] {
            assert!(!printed.contains(value), "{printed}");
            assert!(printed.contains("<hidden>"), "{printed}");
        }
        let none = AgentToServer::GrantToken {
            token: GrantTokenText(String::new()),
        };
        assert_eq!(
            format!("{none:?}"),
            "GrantToken { token: GrantTokenText(\"\") }"
        );
    }

    #[test]
    fn unknown_message_type_is_rejected_rather_than_ignored() {
        let json = r#"{"type":"definitely_not_a_message"}"#;
        assert!(serde_json::from_str::<ServerToAgent>(json).is_err());
    }

    #[test]
    fn a_handshake_without_a_version_is_rejected() {
        // The version is what lets the backend keep serving an agent it has not seen
        // in months. Accepting a hello without one would silently defeat that.
        let json = r#"{"type":"agent_hello","device_id":"d","pubkey":"k"}"#;
        assert!(serde_json::from_str::<AgentToServer>(json).is_err());
    }

    #[test]
    fn sdp_type_is_closed() {
        let json = r#"{"type":"sdp","session_id":"s","sdp_type":"pranswer","sdp":""}"#;
        assert!(serde_json::from_str::<ServerToAgent>(json).is_err());
    }

    /// A backend older than the link fields sends a `pairing_code` without them: still a pairing
    /// code, with no link target — and it goes back out without inventing any.
    #[test]
    fn a_pairing_code_without_link_fields_still_parses() {
        let json = r#"{"type":"pairing_code","code":"123456","expires_at":1}"#;
        let msg: ServerToAgent = serde_json::from_str(json).expect("old shape parses");
        assert_eq!(
            msg,
            ServerToAgent::PairingCode {
                code: "123456".into(),
                expires_at: 1,
                bot_username: None,
                miniapp_short_name: None,
            }
        );
        let back = serde_json::to_value(&msg).expect("serialises");
        assert!(back.get("bot_username").is_none(), "{back}");
        assert!(back.get("miniapp_short_name").is_none(), "{back}");
    }

    #[test]
    fn decline_reason_is_closed() {
        let json = r#"{"type":"pair_cancelled","request_id":"r","reason":"because"}"#;
        assert!(serde_json::from_str::<ServerToAgent>(json).is_err());
    }

    /// The name rides only with an approval that has one: a refusal carries no `name` key at all
    /// (not `null`, which the backend's schema would refuse — and with it the whole answer).
    #[test]
    fn a_pair_response_without_a_name_has_no_name_key() {
        let refusal = AgentToServer::PairResponse {
            request_id: "r".into(),
            accept: false,
            name: None,
            role: None,
            key_id: None,
        };
        let v = serde_json::to_value(&refusal).expect("serialises");
        assert!(v.get("name").is_none(), "{v}");
        assert!(v.get("role").is_none(), "a refusal gives no role: {v}");
        assert!(v.get("key_id").is_none(), "a refusal names no key: {v}");
        // And the shape older agents send still reads.
        let old = r#"{"type":"pair_response","request_id":"r","accept":true}"#;
        assert_eq!(
            serde_json::from_str::<AgentToServer>(old).expect("parses"),
            AgentToServer::PairResponse {
                request_id: "r".into(),
                accept: true,
                name: None,
                role: None,
                key_id: None,
            }
        );
    }

    /// A server older than roles sends `pair_request` and `binding_added` without the role fields:
    /// still the same messages, read as "no roles here", and nothing is made up going back out.
    #[test]
    fn messages_from_a_server_older_than_roles_still_parse() {
        let prompt = r#"{"type":"pair_request","request_id":"r","telegram_user_id":7,
            "username":null,"first_name":"Аня","expires_at":1}"#;
        let msg: ServerToAgent = serde_json::from_str(prompt).expect("old pair_request parses");
        assert!(matches!(
            msg,
            ServerToAgent::PairRequest {
                has_owner: None,
                ..
            }
        ));
        let back = serde_json::to_value(&msg).expect("serialises");
        assert!(back.get("has_owner").is_none(), "{back}");

        let added = r#"{"type":"binding_added","telegram_user_id":7,"username":null,
            "first_name":"Аня"}"#;
        let msg: ServerToAgent = serde_json::from_str(added).expect("old binding_added parses");
        assert!(matches!(
            msg,
            ServerToAgent::BindingAdded {
                role: None,
                via: None,
                ..
            }
        ));
        let back = serde_json::to_value(&msg).expect("serialises");
        assert!(back.get("role").is_none(), "{back}");
        assert!(back.get("via").is_none(), "{back}");
    }

    /// `owner_changed` names nobody with `null`, which the contract requires present: a mirror that
    /// skipped it would send a message the server's schema refuses.
    #[test]
    fn owner_changed_to_nobody_is_an_explicit_null() {
        let none = ServerToAgent::OwnerChanged {
            telegram_user_id: None,
        };
        let v = serde_json::to_value(&none).expect("serialises");
        assert!(
            v.get("telegram_user_id").is_some_and(|x| x.is_null()),
            "{v}"
        );
        let parsed: ServerToAgent =
            serde_json::from_str(r#"{"type":"owner_changed","telegram_user_id":null}"#)
                .expect("parses");
        assert_eq!(parsed, none);
    }

    /// Contract v2's fields are additive: a hello, an end and a report without them are exactly the
    /// old frames (no key, not `null`), and the old frames still read.
    #[test]
    fn telemetry_v2_fields_are_absent_when_unset_and_old_frames_still_parse() {
        let hello = AgentToServer::AgentHello {
            protocol_version: 1,
            device_id: "d".into(),
            pubkey: "k".into(),
            build: None,
            boot_id: None,
            last_exit: None,
            hw: None,
        };
        assert_eq!(
            serde_json::to_string(&hello).expect("serialises"),
            r#"{"type":"agent_hello","protocol_version":1,"device_id":"d","pubkey":"k"}"#
        );
        let with_hw = AgentToServer::AgentHello {
            protocol_version: 1,
            device_id: "d".into(),
            pubkey: "k".into(),
            build: None,
            boot_id: None,
            last_exit: None,
            hw: Some(AgentHw {
                hash: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".into(),
                vm: false,
                parts: 2,
            }),
        };
        assert_eq!(
            serde_json::to_string(&with_hw).expect("serialises"),
            r#"{"type":"agent_hello","protocol_version":1,"device_id":"d","pubkey":"k","hw":{"hash":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","vm":false,"parts":2}}"#,
            "the beta's fingerprint, last, beside the rest"
        );
        let end = AgentToServer::SessionEnd {
            session_id: "s".into(),
            reason: Some("kill_switch".into()),
            detail: None,
        };
        assert_eq!(
            serde_json::to_string(&end).expect("serialises"),
            r#"{"type":"session_end","session_id":"s","reason":"kill_switch"}"#
        );
        let old_end: AgentToServer =
            serde_json::from_str(r#"{"type":"session_end","session_id":"s"}"#).expect("parses");
        assert!(matches!(
            old_end,
            AgentToServer::SessionEnd { detail: None, .. }
        ));
        let old_report = r#"{"type":"session_stats","session_id":"s","stats":{"duration_ms":1,
            "source_w":0,"source_h":0,"frames_captured":0,"frames_encoded":0,
            "frames_dropped_stale":0,"frames_dropped_paced":0,"frames_skipped_encoder":0,
            "encode_ms_avg":0,"encode_ms_max":0,"bytes_sent":0,"lowest_height":0,
            "quality_changes":0,"estimate_kbps":null,"encode_errors":0}}"#;
        let report: AgentToServer = serde_json::from_str(old_report).expect("parses");
        assert!(!report.is_final_report());
        let v = serde_json::to_value(&report).expect("serialises");
        assert!(
            v.get("final").is_none(),
            "an ordinary report says nothing: {v}"
        );
        assert!(v["stats"].get("summary").is_none(), "{v}");
        let AgentToServer::SessionStats {
            session_id, stats, ..
        } = report
        else {
            panic!("not a report");
        };
        let last = AgentToServer::SessionStats {
            session_id,
            stats,
            is_final: true,
        };
        assert!(last.is_final_report());
        assert_eq!(
            serde_json::to_value(&last).expect("serialises")["final"],
            true
        );
    }

    /// The request's optional fields are absent, not null, when the state has none of them.
    #[test]
    fn a_refused_owner_request_has_no_id_and_no_deadline() {
        let refused = ServerToAgent::OwnerRequestState {
            request_id: None,
            kind: OwnerStateKind::MakeOwner,
            telegram_user_id: 7,
            state: OwnerRequestState::Refused,
            expires_at: None,
            reason: Some(OwnerRequestReason::RateLimited),
            username: None,
            first_name: None,
        };
        let v = serde_json::to_value(&refused).expect("serialises");
        assert!(v.get("request_id").is_none(), "{v}");
        assert!(v.get("expires_at").is_none(), "{v}");
        assert!(v.get("username").is_none(), "{v}");
        assert!(v.get("first_name").is_none(), "{v}");
        assert_eq!(v["reason"], "rate_limited");
        // A state this build does not know is not read as another.
        let unknown = r#"{"type":"owner_request_state","kind":"make_owner","telegram_user_id":7,
            "state":"lost"}"#;
        assert!(serde_json::from_str::<ServerToAgent>(unknown).is_err());
    }

    /// `pc_allow`: the PC's «Разрешить» held for the owner. The
    /// newcomer is named, as `pair_request` names them; `null` names read as none; the PC's own two
    /// kinds still read without them, and an unknown kind is refused, not read as one of the three.
    #[test]
    fn a_pc_allow_state_names_the_newcomer() {
        let pending = r#"{"type":"owner_request_state","request_id":"r","kind":"pc_allow",
            "telegram_user_id":35791,"state":"pending","expires_at":1,"username":"vasya",
            "first_name":"Вася"}"#;
        assert_eq!(
            serde_json::from_str::<ServerToAgent>(pending).expect("parses"),
            ServerToAgent::OwnerRequestState {
                request_id: Some("r".into()),
                kind: OwnerStateKind::PcAllow,
                telegram_user_id: 35791,
                state: OwnerRequestState::Pending,
                expires_at: Some(1),
                reason: None,
                username: Some("vasya".into()),
                first_name: Some("Вася".into()),
            }
        );
        let nulls = r#"{"type":"owner_request_state","request_id":"r","kind":"pc_allow",
            "telegram_user_id":35791,"state":"cancelled","reason":"by_requester",
            "username":null,"first_name":null}"#;
        let msg: ServerToAgent = serde_json::from_str(nulls).expect("null names parse");
        assert!(matches!(
            msg,
            ServerToAgent::OwnerRequestState {
                kind: OwnerStateKind::PcAllow,
                reason: Some(OwnerRequestReason::ByRequester),
                username: None,
                first_name: None,
                ..
            }
        ));
        let old = r#"{"type":"owner_request_state","request_id":"r","kind":"make_owner",
            "telegram_user_id":7,"state":"declined"}"#;
        assert!(matches!(
            serde_json::from_str::<ServerToAgent>(old).expect("parses"),
            ServerToAgent::OwnerRequestState {
                kind: OwnerStateKind::MakeOwner,
                username: None,
                first_name: None,
                ..
            }
        ));
        let unknown = r#"{"type":"owner_request_state","request_id":"r","kind":"add_guest",
            "telegram_user_id":7,"state":"declined"}"#;
        assert!(serde_json::from_str::<ServerToAgent>(unknown).is_err());
        // What the PC asks is still its own two: `pc_allow` cannot go out in `owner_request`.
        let ask = r#"{"type":"owner_request","kind":"pc_allow","telegram_user_id":7}"#;
        assert!(serde_json::from_str::<AgentToServer>(ask).is_err());
    }

    #[test]
    fn any_quality_profile_leaves_the_session_request_parsing() {
        let turn = r#""turn":{"urls":[],"username":"u","credential":"c"}"#;
        // Absent (an older server), and omitted again when serialized.
        let old = format!(
            r#"{{"type":"session_request","session_id":"s","telegram_user_id":1,"username":null,{turn}}}"#
        );
        let msg: ServerToAgent = serde_json::from_str(&old).expect("old shape parses");
        assert!(matches!(
            msg,
            ServerToAgent::SessionRequest {
                quality_profile: None,
                ..
            }
        ));
        let back = serde_json::to_value(&msg).expect("serialises");
        assert!(back.get("quality_profile").is_none(), "{back}");
        // Any shape at all — wrong types, a string, an array, nonsense values — is carried raw: the
        // profile is the agent's to refuse, never the message's.
        for profile in [
            r#"{"id":"default","v":1,"values":{"ladder":"nope"}}"#,
            r#""a string""#,
            r"[1,2,3]",
            r#"{"id":7,"v":-1}"#,
            r"null",
        ] {
            let text = format!(
                r#"{{"type":"session_request","session_id":"s","telegram_user_id":1,"username":null,{turn},"quality_profile":{profile}}}"#
            );
            let msg: ServerToAgent =
                serde_json::from_str(&text).expect("parses whatever the profile");
            let ServerToAgent::SessionRequest {
                quality_profile, ..
            } = msg
            else {
                panic!("a session_request");
            };
            let expected: serde_json::Value = serde_json::from_str(profile).expect("json");
            // `null` reads as absent, which is what it means.
            assert_eq!(quality_profile, (!expected.is_null()).then_some(expected));
        }
        // What is not protected, and known: JSON serde_json cannot hold as a `Value` fails the
        // whole message (see the field's docs) — nesting past its recursion limit, and a number
        // out of `f64` range. The server's `JSON.stringify` of a zod-parsed profile makes neither.
        let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        for profile in [
            deep.as_str(),
            r#"{"id":"default","v":1,"values":{"x":1e400}}"#,
        ] {
            let text = format!(
                r#"{{"type":"session_request","session_id":"s","telegram_user_id":1,"username":null,{turn},"quality_profile":{profile}}}"#
            );
            assert!(
                serde_json::from_str::<ServerToAgent>(&text).is_err(),
                "known: the message fails with this profile"
            );
        }
    }

    /// Device keys (spec §12): every new field is optional — a server or an agent older than device
    /// keys reads and writes exactly what it did — and the opaque two are carried raw, whatever
    /// their shape, so a `proof` or a `viewer_key` the agent cannot use costs a verdict, never the
    /// offer or the prompt.
    #[test]
    fn device_key_fields_are_optional_and_the_opaque_ones_raw() {
        // Older shapes: parsed, nothing made up, nothing written back.
        let ready = r#"{"type":"agent_ready","protocol_version":1,"min_supported_protocol":1,"bindings":[]}"#;
        let msg: ServerToAgent = serde_json::from_str(ready).expect("old agent_ready parses");
        assert!(matches!(
            msg,
            ServerToAgent::AgentReady {
                nonce_pool: None,
                grant_token: None,
                ..
            }
        ));
        assert_eq!(
            serde_json::to_string(&msg).expect("serialises"),
            ready,
            "byte for byte"
        );
        let offer = r#"{"type":"sdp","session_id":"s","sdp_type":"offer","sdp":"v=0"}"#;
        let msg: ServerToAgent = serde_json::from_str(offer).expect("old sdp parses");
        assert!(matches!(msg, ServerToAgent::Sdp { proof: None, .. }));
        assert_eq!(serde_json::to_string(&msg).expect("serialises"), offer);

        // `proof` of any shape is carried, on an offer and (ignored by the agent) on an answer.
        for (sdp_type, proof) in [
            (
                "offer",
                r#"{"v":1,"admit":[{"kind":"future_kind","data":{"nested":[1,{"deeper":true}]}}]}"#,
            ),
            ("offer", r#"{"v":"one","sig":7}"#),
            ("offer", r"[1,2,3]"),
            ("offer", r#""a string""#),
            ("answer", r#"{"v":1}"#),
        ] {
            let text = format!(
                r#"{{"type":"sdp","session_id":"s","sdp_type":"{sdp_type}","sdp":"v=0","proof":{proof}}}"#
            );
            let msg: ServerToAgent =
                serde_json::from_str(&text).expect("parses whatever the proof");
            let ServerToAgent::Sdp { proof: got, .. } = msg else {
                panic!("an sdp");
            };
            let expected: serde_json::Value = serde_json::from_str(proof).expect("json");
            assert_eq!(got, Some(expected), "{text}");
        }
        // And `viewer_key` the same.
        for key in [r#"{"spki":"x","kind":"telegram"}"#, r"[]", r"7"] {
            let text = format!(
                r#"{{"type":"pair_request","request_id":"r","telegram_user_id":7,"username":null,"first_name":null,"expires_at":1,"viewer_key":{key}}}"#
            );
            let msg: ServerToAgent = serde_json::from_str(&text).expect("parses whatever the key");
            let ServerToAgent::PairRequest { viewer_key, .. } = msg else {
                panic!("a pair_request");
            };
            let expected: serde_json::Value = serde_json::from_str(key).expect("json");
            assert_eq!(viewer_key, Some(expected), "{text}");
        }
        // A `nonce_pc` not of a nonce's form is still a session_request: the form is the agent's.
        let turn = r#""turn":{"urls":[],"username":"u","credential":"c"}"#;
        let text = format!(
            r#"{{"type":"session_request","session_id":"s","telegram_user_id":1,"username":null,{turn},"nonce_pc":"not a nonce"}}"#
        );
        let msg: ServerToAgent = serde_json::from_str(&text).expect("parses");
        assert!(matches!(
            msg,
            ServerToAgent::SessionRequest { nonce_pc: Some(ref n), .. } if n == "not a nonce"
        ));

        // What the agent sends: `session_nonces` as the contract has it, `key_id` only when set.
        let batch = AgentToServer::SessionNonces {
            batch: 7,
            nonces: vec!["AAAAAAAAAAAAAAAAAAAAAA".into()],
        };
        assert_eq!(
            serde_json::to_string(&batch).expect("serialises"),
            r#"{"type":"session_nonces","batch":7,"nonces":["AAAAAAAAAAAAAAAAAAAAAA"]}"#
        );
        assert!(!batch.is_final_report());
        assert_eq!(batch.session_id(), None);
        let approval = AgentToServer::PairResponse {
            request_id: "r".into(),
            accept: true,
            name: None,
            role: Some(BindingRole::Guest),
            key_id: Some("k".into()),
        };
        assert_eq!(
            serde_json::to_string(&approval).expect("serialises"),
            r#"{"type":"pair_response","request_id":"r","accept":true,"role":"guest","key_id":"k"}"#
        );
    }

    /// Parties (party spec §4.1, §10): `agent_ready.party` is optional — a server older than parties
    /// says nothing and gets nothing written back — a join of any shape is carried raw, so a fault in
    /// it is answered with `party_ack`, never by losing the frame, and what the agent sends is exactly
    /// the contract's.
    #[test]
    fn party_fields_are_optional_and_the_join_raw() {
        let ready = r#"{"type":"agent_ready","protocol_version":1,"min_supported_protocol":1,"bindings":[],"nonce_pool":true,"grant_token":true}"#;
        let msg: ServerToAgent = serde_json::from_str(ready).expect("parses");
        assert!(matches!(msg, ServerToAgent::AgentReady { party: None, .. }));
        assert_eq!(serde_json::to_string(&msg).expect("serialises"), ready);
        let with = ready.replace('}', r#","party":true}"#);
        assert!(matches!(
            serde_json::from_str::<ServerToAgent>(&with).expect("parses"),
            ServerToAgent::AgentReady {
                party: Some(true),
                ..
            }
        ));

        for join in [
            r#"{"party_id":"Rk9vZEJ1ZGR5UGFydHkxMg","v":2,"future":[1,{"x":null}]}"#,
            r#"{"v":"one"}"#,
            r"[1,2,3]",
            r#""a string""#,
        ] {
            let text = format!(r#"{{"type":"party_join","join":{join}}}"#);
            let msg: ServerToAgent = serde_json::from_str(&text).expect("parses whatever the join");
            assert_eq!(msg.kind(), "party_join");
            let ServerToAgent::PartyJoin { join: got } = msg else {
                panic!("a party_join");
            };
            let expected: serde_json::Value = serde_json::from_str(join).expect("json");
            assert_eq!(got, expected, "{text}");
        }
        assert!(
            serde_json::from_str::<ServerToAgent>(r#"{"type":"party_join"}"#).is_err(),
            "the join is required"
        );
        let leave: ServerToAgent =
            serde_json::from_str(r#"{"type":"party_leave","party_id":"not an id"}"#)
                .expect("a leave's id is the agent's to judge");
        assert!(
            matches!(leave, ServerToAgent::PartyLeave { ref party_id } if party_id == "not an id")
        );

        let ack = AgentToServer::PartyAck {
            party_id: "Rk9vZEJ1ZGR5UGFydHkxMg".into(),
            op: PartyAckOp::Join,
            result: PartyAckResult::BadSig,
        };
        assert_eq!(
            serde_json::to_string(&ack).expect("serialises"),
            r#"{"type":"party_ack","party_id":"Rk9vZEJ1ZGR5UGFydHkxMg","op":"join","result":"bad_sig"}"#
        );
        assert_eq!(ack.session_id(), None);
        assert!(!ack.is_final_report());
        let state = AgentToServer::PartyState { parties: vec![] };
        assert_eq!(
            serde_json::to_string(&state).expect("serialises"),
            r#"{"type":"party_state","parties":[]}"#,
            "an empty state is a list, never absent"
        );
        // A result off the contract's list is not read as another.
        assert!(serde_json::from_str::<AgentToServer>(
            r#"{"type":"party_ack","party_id":"p","op":"join","result":"unconfirmed"}"#
        )
        .is_err());
    }

    /// The secure desktop (`crate::secure_desktop`): `agent_ready.secure_desktop` is optional — a
    /// server older than it says nothing and gets nothing written back — and the cue is exactly the
    /// contract's, about its session.
    #[test]
    fn the_secure_desktop_fields_are_optional_and_the_cue_the_contracts() {
        let ready = r#"{"type":"agent_ready","protocol_version":1,"min_supported_protocol":1,"bindings":[],"party":true}"#;
        let msg: ServerToAgent = serde_json::from_str(ready).expect("parses");
        assert!(matches!(
            msg,
            ServerToAgent::AgentReady {
                secure_desktop: None,
                ..
            }
        ));
        assert_eq!(serde_json::to_string(&msg).expect("serialises"), ready);
        let with = ready.replace('}', r#","secure_desktop":true}"#);
        assert!(matches!(
            serde_json::from_str::<ServerToAgent>(&with).expect("parses"),
            ServerToAgent::AgentReady {
                secure_desktop: Some(true),
                ..
            }
        ));

        let cue = AgentToServer::SecureDesktopOngoing {
            session_id: "3fa85f64-5717-4562-b3fc-2c963f66afa6".into(),
            desktop: crate::SecureDesktopKind::Lock,
            at: 1_789_600_400_000,
        };
        assert_eq!(
            serde_json::to_string(&cue).expect("serialises"),
            r#"{"type":"secure_desktop_ongoing","session_id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","desktop":"lock","at":1789600400000}"#
        );
        assert_eq!(cue.kind(), "secure_desktop_ongoing");
        assert_eq!(
            cue.session_id(),
            Some("3fa85f64-5717-4562-b3fc-2c963f66afa6")
        );
        assert!(!cue.is_final_report());
        // A kind off the contract's list is not read as another.
        assert!(serde_json::from_str::<AgentToServer>(
            r#"{"type":"secure_desktop_ongoing","session_id":"s","desktop":"logon","at":1}"#
        )
        .is_err());
    }
}
