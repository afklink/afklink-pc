//! The agent orchestrator: connect + authenticate to the backend, handle
//! pairing / binding events, and on `session_request` spin up the
//! capture -> encode -> WebRTC pipeline and forward remote input.
//!
//! Platform backends (capture / encode / input) are injected as
//! `Backends` so this crate stays free of Windows-only dependencies and can be
//! driven by either the headless binary or the Tauri GUI.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::sync::{broadcast, mpsc};

use afklink_transport::{
    self as transport, AgentToServer, BindingInfo, LinkShaper, PeerCloser, PeerControl, PeerEvent,
    PeerSignal, SdpType, ServerToAgent, SignalSender, SignalSent, SignalingConfig, Signer,
};

use crate::config::Config;
use crate::identity::Identity;
use crate::input_session::{InputSession, InputSilence};
use crate::reconnect::{self, Next, OnReplaced, Refusal, Wait};
use crate::relay::{Link, LinkChange, Relay};
use crate::session_log::SessionLog;
use crate::sync::lock;
use crate::traits::{Capturer, Encoder, InputInjector};
use crate::types::Frame;
use afklink_protocol::{end_reason, InputMessage};

pub mod media_feed;

/// "No pin request is pending", in the cell the event task writes and the control task reads.
///
/// `u32::MAX` rather than a sentinel inside the height range, because every other value has to
/// stay a usable height and 0 is already spoken for by [`PIN_AUTO`].
const NO_PIN_REQUEST: u32 = u32::MAX;

/// "Hand the choice back to the ladder."
///
/// Zero is safe as a sentinel because a pinned height of zero is not a resolution.
const PIN_AUTO: u32 = 0;

/// Makes a game-window capturer for a session in game mode; see [`Backends::make_game_capturer`].
pub type GameCapturerFactory =
    Box<dyn Fn(&crate::game::GameCaptureRequest) -> Result<Box<dyn Capturer>> + Send + Sync>;

/// Injected platform implementations. Factories are called per-session so a new
/// capturer/encoder is created for each connection.
pub struct Backends {
    /// The primary monitor. Never called for a session in game mode (`crate::game::SessionCapture`).
    pub make_capturer: Box<dyn Fn() -> Result<Box<dyn Capturer>> + Send + Sync>,
    /// The bound game's window only, black frames when it cannot be shown (`crate::game`): the
    /// capturer of a session in game mode, at its start and at every restart.
    pub make_game_capturer: GameCapturerFactory,
    pub make_encoder: Box<dyn Fn() -> Result<Box<dyn Encoder>> + Send + Sync>,
    pub injector: Arc<dyn InputInjector>,
}

/// A snapshot of a live/pending session, surfaced to the UI.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: String,
    pub telegram_user_id: i64,
    /// The request's username, else the binding's (`crate::person_name::session_names`).
    pub username: Option<String>,
    /// From the binding the session was admitted on: `session_request` carries none.
    pub first_name: Option<String>,
    pub connected: bool,
    /// When `connected` turned true (str0m's `Event::Connected`: ICE and DTLS up, media flowing):
    /// how long the viewer has been in control, for the tray's menu line and tooltip and the
    /// window's timer. Monotonic, so a clock change on the PC does not move it. `None` until then.
    pub connected_at: Option<Instant>,
}

impl SessionInfo {
    /// The viewer's name for toasts, the tray tooltip and the window: first name, else
    /// `@username`, else `#id` ([`crate::person_name()`]).
    pub fn name(&self) -> crate::PersonName {
        crate::person_name(
            self.telegram_user_id,
            self.first_name.as_deref(),
            self.username.as_deref(),
        )
    }
}

/// Someone redeemed this device's pairing code and is waiting for an answer.
///
/// This is what makes a six-digit code safe: the code routes a request here, and
/// only the person at this machine can turn it into a binding.
#[derive(Debug, Clone)]
pub struct PendingPair {
    pub request_id: String,
    pub telegram_user_id: i64,
    pub username: Option<String>,
    pub first_name: Option<String>,
    /// Unix ms after which the backend withdraws the request.
    pub expires_at: i64,
    /// Whether the PC had an owner as the request went up (`pair_request.has_owner`):
    /// `Some(false)` — after «Разрешить» the prompt asks «Кто это?» ([`Self::asks_role`]);
    /// `Some(true)` — no question, the person becomes a guest; `None` — a server older than roles,
    /// no question either.
    pub has_owner: Option<bool>,
    /// Where it stands with the signaling link its answer goes over: kept across a break of the
    /// link (the backend keeps it too, and re-sends it), its answer waiting until it is `Live`
    /// again (`crate::pairing`).
    pub link: crate::pairing::PairLink,
}

impl PendingPair {
    /// Whether «Разрешить» leads to «Кто это?» («Владелец» / «Гость») rather than straight to the
    /// answer: only on a PC the server says has no owner.
    pub fn asks_role(&self) -> bool {
        self.has_owner == Some(false)
    }

    /// Whether an answer can go now: the request is on a live link. While the link is down, or back
    /// but the backend has not re-sent it yet, the prompt stays with its buttons disabled
    /// (`crate::pairing`).
    pub fn answerable(&self) -> bool {
        self.link == crate::pairing::PairLink::Live
    }

    /// Label for the prompt window: [`Self::name`] as text.
    pub fn display_name(&self) -> String {
        self.name().text
    }

    /// The requester's name for the toast and the prompt window alike: «Имя (@username)» when both
    /// exist, else first name, `@username`, `#id` ([`crate::person_name::requester_name`]).
    pub fn name(&self) -> crate::PersonName {
        crate::person_name::requester_name(
            self.telegram_user_id,
            self.first_name.as_deref(),
            self.username.as_deref(),
        )
    }
}

/// Observable agent state (read by the UI).
#[derive(Debug, Clone, Default)]
pub struct AgentState {
    pub connected: bool,
    /// Set while the backend refuses this agent with a fatal code and the usual reconnecting is
    /// off: `replaced` (waiting for the owner) or another fatal code — `device_blocked` among them —
    /// (retrying slowly). Cleared by the next attempt that ends any other way. See
    /// `crate::reconnect`.
    pub refused: Option<Refusal>,
    /// The owner's pairing panel: open, closed, or paired while open (the window closes it on
    /// that). Decides whether a code that arrives is shown and whether a new connection asks for
    /// one. See `crate::pairing`.
    pub pairing_panel: crate::pairing::PairingPanel,
    /// Asking again for a code the backend refused with `rate_limited` while the panel is open
    /// (`crate::pairing::code_refused`).
    pub pairing_retry: crate::pairing::CodeRetry,
    pub pairing_code: Option<String>,
    pub pairing_expires_at: Option<i64>,
    /// Where the pairing link for the current code points (`crate::qr::resolve_target`), decided
    /// when the code arrived; `None` when the bot is unknown — then there is no link and no QR,
    /// only the code. Means nothing without `pairing_code`: [`AgentControl::deep_link`] reads the
    /// two together, and the next code replaces it.
    pub pairing_link: Option<crate::qr::LinkTarget>,
    /// Set while a confirmation prompt should be on screen.
    pub pending_pair: Option<PendingPair>,
    pub bindings: Vec<BindingInfo>,
    /// Set by the first signaling handshake of this run, never cleared: `bindings` is the backend's
    /// list from then on (the last one it sent, while offline), and empty before it only because
    /// nothing has been heard yet. The agent keeps no list on disk, so after a restart it is unknown
    /// here until the backend answers — never «nobody has access». (The desktop app keeps the last
    /// one for its window, `access_cache`, which is what it shows until then.)
    pub bindings_known: bool,
    /// The PC's request to the owner — «Сделать владельцем», «Отвязать» on the owner — in flight,
    /// and how recent ones ended (`crate::owner_request`). The roles themselves are on `bindings`.
    pub owner_requests: crate::owner_request::OwnerRequests,
    pub sessions: Vec<SessionInfo>,
    /// Set by the kill switch: every new session request is refused with `paused_on_pc` until the
    /// owner resumes ([`AgentCommand::Resume`]). Kept in config.json (`Config::paused`), so a restart
    /// of the process or an update does not end it: only the owner's «Возобновить» does.
    pub paused: bool,
    /// The agent saw a viewer's controls not reach a game for want of the input driver: presses into
    /// a window running as administrator while this agent is not and the driver is not open — three
    /// in a row within two seconds (`crate::input_reach`). The window's «Управление в играх» row then says
    /// «Управление не доходит» in red over a lime «Установить».
    ///
    /// Set the moment presses are found blocked; cleared when the driver is open for a session, when
    /// the desktop app reads it installed ([`AgentControl::driver_installed`]), or after a session
    /// whose input got through. Kept in config.json (`Config::input_not_reaching`), so it outlives a
    /// restart.
    pub input_not_reaching: bool,
    /// The viewer's presses are being dropped right now, as the heartbeats say it (`input_blocked`:
    /// held ten seconds after the last dropped press); false with no session. The desktop app's
    /// «Управление не доходит до игры…» toast follows it, once a session.
    pub input_blocked: bool,
}

/// Commands the UI/CLI sends to the running agent.
#[derive(Debug)]
pub enum AgentCommand {
    RequestPairing,
    /// The pairing panel was closed: invalidate the code now rather than leaving it
    /// live, and on screen, where a connected viewer could read it out of the stream.
    CancelPairing,
    /// The owner's answer to a pending pairing request. `role`: the answer to «Кто это?» when the
    /// prompt asked it ([`PendingPair::asks_role`]); `None` — not asked (or a front end that does
    /// not ask, the CLI's `y`), and an approval then makes the person a guest.
    RespondToPair {
        request_id: String,
        accept: bool,
        role: Option<afklink_protocol::BindingRole>,
    },
    /// «Отвязать» on a person. A guest's binding goes at once (`unbind`); the owner's waits for the
    /// owner's confirmation in Telegram (`owner_request` `unbind_owner`), as the roles in
    /// [`AgentState::bindings`] say who is who.
    Unbind(i64),
    /// «Сделать владельцем» on a guest: `owner_request` `make_owner`, which the owner confirms in
    /// Telegram (applied at once on a PC with no owner).
    MakeOwner(i64),
    /// «Отменить запрос»: withdraw the PC's pending request to the owner.
    CancelOwnerRequest,
    /// End every session and pause: new session requests are refused until [`Self::Resume`], across
    /// restarts and updates (`Config::paused`). The PC is not locked.
    KillSwitch,
    /// The owner resumed after the kill switch: session requests are accepted again.
    Resume,
    SetName(String),
    /// The owner asked to connect now: ends the wait for the owner after `replaced`, the slow
    /// retry after another fatal refusal, or an ordinary backoff (`crate::reconnect`). Nothing to do
    /// while connected.
    Retry,
    /// The process is leaving (`why`: the owner's «Выход», the exit for an update, Windows ending
    /// the session): end every live session now — its final report, then `session_end`
    /// `agent_ended` — and every request still waiting for its offer, then wait until the relay has
    /// put all of it in the connection's queue, which the goodbye writes first. `done` hears what was
    /// ended. Sent by [`AgentControl::end_sessions_for_exit_blocking`].
    ///
    /// Asked at `asked`, waited for at most `budget`: one the orchestrator gets to later than that
    /// (it was busy) is dropped, not served — the exit went ahead without it, and a process still
    /// running by then is not one to end sessions in.
    EndForExit {
        why: crate::goodbye::GoodbyeReason,
        asked: Instant,
        budget: Duration,
        done: std::sync::mpsc::SyncSender<ExitEnding>,
    },
}

impl AgentCommand {
    /// Its name, for the log and the orchestrator's step (`crate::step_watch`): never its content.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::RequestPairing => "request_pairing",
            Self::CancelPairing => "cancel_pairing",
            Self::RespondToPair { .. } => "respond_to_pair",
            Self::Unbind(_) => "unbind",
            Self::MakeOwner(_) => "make_owner",
            Self::CancelOwnerRequest => "cancel_owner_request",
            Self::KillSwitch => "kill_switch",
            Self::Resume => "resume",
            Self::SetName(_) => "set_name",
            Self::Retry => "retry",
            Self::EndForExit { .. } => "end_for_exit",
        }
    }
}

/// How long the exit waits for the live sessions to be ended before it says goodbye regardless:
/// [`AgentControl::leave_blocking`].
///
/// 300 ms. Ending a session is in-memory work — the stop flag, the final report into the outbox,
/// the peer's close signal, the input's release and the capture's stop handed to threads of their
/// own (`crate::offload`, waited for at most [`EXIT_TEARDOWN_WAIT`]) — a few milliseconds each,
/// and the relay's barrier is one channel hop; a normal exit spends well
/// under 50 ms here. The bound is for an orchestrator busy in one long await (a session's setup
/// waits up to 1.5 s for STUN): the exit does not wait for it, and those sessions end at the
/// backend's grace window as before. With the goodbye's own 500 ms (`GOODBYE_BUDGET`) an exit is
/// held 0.8 s at worst — under the second a person notices after «Выход», and far inside the five
/// seconds Windows gives `WM_QUERYENDSESSION`.
pub const EXIT_END_BUDGET: Duration = Duration::from_millis(300);

/// How long the orchestrator waits for the relay's barrier at an exit (inside [`EXIT_END_BUDGET`]).
const EXIT_BARRIER_WAIT: Duration = Duration::from_millis(150);

/// How long the orchestrator waits at an exit, after the barrier, for the sessions' teardowns on
/// their own threads (`crate::offload`: the input's release, the capture's stop) — a few
/// milliseconds each when nothing is stuck. Inside [`EXIT_END_BUDGET`] with the barrier; a stuck
/// one is said and left, and the goodbye goes ahead.
const EXIT_TEARDOWN_WAIT: Duration = Duration::from_millis(100);

/// How long the CLI, stopping after `replaced` ([`OnReplaced::Stop`]), waits for the release of
/// everything and the sessions' teardowns on their own threads before the process ends.
///
/// One second. Each is a few milliseconds when the input driver answers, and the driver's slot lock
/// may be held a moment by the game-focus watch or an injection; no deadline presses here (unlike
/// the exit's, [`EXIT_TEARDOWN_WAIT`], under Windows' end of session), so the wait is generous for
/// a slow driver. A driver still holding its lock after a second is stuck (no release can be had
/// from it either), and the CLI stops rather than hang for ever: said at warn,
/// with the jobs left.
const REPLACED_TEARDOWN_WAIT: Duration = Duration::from_secs(1);

/// What the exit keeps of its budget for the answer to reach the one who asked: the teardown wait
/// ends this long before [`EXIT_END_BUDGET`] runs out, counted from the ask.
const EXIT_REPLY_MARGIN: Duration = Duration::from_millis(20);

/// What a session's start may take beyond its setup limit (`crate::offload::START_LIMIT`) before the
/// stall watch says anything of the orchestrator's step (`crate::step_watch`): the peer's creation
/// and its STUN transaction (≤ 1.5 s), the answer's relay. START_LIMIT (10 s) and this stay well
/// under the stall watch's error (30 s), which sends an automatic report.
const START_STEP_MARGIN: Duration = Duration::from_secs(5);

/// A session's start's whole budget as the orchestrator's step ([`step_budget`] with the setup's
/// own limit): what the stall watch checks its error threshold against.
pub const START_STEP_BUDGET: Duration =
    crate::offload::START_LIMIT.saturating_add(START_STEP_MARGIN);

/// How long the orchestrator's step for `msg` may legitimately last (`crate::step_watch`): a
/// viewer's offer starts a session, bounded by `setup_limit` — that and [`START_STEP_MARGIN`]; any
/// other message, nothing beyond any step's.
fn step_budget(msg: &ServerToAgent, setup_limit: Duration) -> Duration {
    match msg {
        ServerToAgent::Sdp {
            sdp_type: SdpType::Offer,
            ..
        } => setup_limit + START_STEP_MARGIN,
        _ => Duration::ZERO,
    }
}

/// What [`AgentCommand::EndForExit`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExitEnding {
    /// Live sessions ended (final report and `session_end`).
    pub sessions: usize,
    /// Requests still waiting for their offer, ended (`session_end`).
    pub requests: usize,
    /// The relay forwarded everything before the goodbye: to connection `Some(link)`, or held
    /// (`None`: no connection up). `None` too when the barrier did not answer in time.
    pub link: Option<u64>,
    /// The relay's barrier answered within [`EXIT_BARRIER_WAIT`] (or nothing needed it).
    pub flushed: bool,
}

/// Lifecycle events, for a front end that reacts to them instead of polling [`AgentState`].
///
/// The CLI turns them into its machine-readable `BENCH` lines; the desktop app follows the sessions
/// for «Отправить логи», the first connection for its updater, and [`Self::GuestInvited`] for its
/// toast. Sent on a broadcast channel ([`AgentControl::subscribe`]): a subscriber that falls more
/// than [`EVENT_CAPACITY`] behind is told how many it missed, and with no subscriber at all they go
/// nowhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentEvent {
    /// Authenticated with the backend and serving: ready for sessions.
    SignalingConnected { bindings: usize },
    /// The signaling connection ended; the agent is reconnecting (or, when a
    /// [`AgentEvent::SignalingRefused`] follows, waiting as `crate::reconnect` says).
    SignalingDisconnected,
    /// The backend refused this agent with a fatal code, on the handshake or on a live connection.
    /// Sent for every refused attempt; [`AgentState::refused`] holds the current one.
    SignalingRefused(Refusal),
    /// A session's capture, encoder and peer are running.
    SessionStarted {
        session_id: String,
        telegram_user_id: i64,
    },
    /// A session ended, with the reason the backend is told (`afklink_protocol::end_reason`, held
    /// to `SESSION_END_REASONS`), or `end_reason::local::SERVER_ENDED` when the backend ended it and
    /// nothing is told — or, when it never got as far as [`AgentEvent::SessionStarted`], why its
    /// setup failed.
    SessionEnded { session_id: String, reason: String },
    /// The owner let a new guest in from Telegram by his invite (`binding_added.via: invite`), and
    /// nobody at the PC was asked: the person at it is told at once — the desktop app's toast
    /// «Новый гость: {user}» over «По приглашению владельца». Sent once per guest: not for a
    /// `binding_added` that repeats someone already listed. `name` as the pairing window names a
    /// requester, «Имя (@username)» ([`crate::person_name::requester_name`]): this is the first the
    /// person at the PC hears of a stranger, so the name must be as recognisable as there.
    GuestInvited {
        telegram_user_id: i64,
        name: crate::PersonName,
    },
}

/// How many [`AgentEvent`]s a slow subscriber may fall behind before it misses some.
pub const EVENT_CAPACITY: usize = 64;

/// How often the orchestrator looks at a pairing request kept across a break of the link
/// (`crate::pairing::tick`): its waits are seconds long, so half a second is precise enough, and the
/// look is a lock and a comparison.
const PAIRING_TICK: Duration = Duration::from_millis(500);

/// The pairing tick of one serving or waiting loop; a tick missed while the loop was busy is not
/// made up.
fn pairing_tick() -> tokio::time::Interval {
    let mut tick = tokio::time::interval(PAIRING_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick
}

/// What [`AgentControl::keep_pause_blocking`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PauseKept {
    /// Not paused: nothing to keep.
    NotPaused,
    /// Paused, and config.json says so now.
    Saved,
    /// Paused, but config.json could not be written (why).
    NotSaved(String),
}

/// Handle held by the UI: shared state + a command channel.
#[derive(Clone)]
pub struct AgentControl {
    pub state: Arc<Mutex<AgentState>>,
    pub commands: mpsc::UnboundedSender<AgentCommand>,
    /// The agent's config, shared with the orchestrator (the window reads the device name, server
    /// and autostart from it).
    pub config: Arc<Mutex<Config>>,
    /// Lifecycle events; see [`AgentEvent`] and [`Self::subscribe`].
    pub events: broadcast::Sender<AgentEvent>,
    /// What each session captures — the monitor, or the bound game's window only — decided per
    /// session from the owner's settings and the viewer's role (`crate::game_access`); every live
    /// session switches to a new decision at once. The settings change only through
    /// [`Self::set_game_only`], [`Self::set_game_only_for_guests`] and [`Self::set_game_binding`],
    /// which keep them equal to config.json.
    game_access: Arc<crate::game_access::GameAccess>,
    /// The game helper launched the game and waits for its window: every live session's heartbeat
    /// says so. Changed only through [`Self::set_game_launching`].
    helper_launch: Arc<crate::game::HelperLaunch>,
    /// The goodbye to the backend and the hold on reconnecting after it (`crate::goodbye`); see
    /// [`Self::goodbye_blocking`].
    goodbyes: Arc<crate::goodbye::Goodbyes>,
}

impl AgentControl {
    /// Tell the backend this agent is leaving (`agent_goodbye` with `reason`, then a normal close)
    /// and stop reconnecting until [`Self::welcome_back`] — or the owner's retry, or the hold's
    /// limit (`crate::goodbye::hold_limit`). Waits at most `budget`
    /// ([`crate::goodbye::GOODBYE_BUDGET`] for every caller so far) and never longer: said on the
    /// connection's own pump, past whatever the orchestrator is busy with. Logs the outcome.
    ///
    /// Blocks the calling thread: for the window's event loop, a Windows message thread, any thread
    /// that is not an async task's own. An async task uses [`Self::goodbye`].
    pub fn goodbye_blocking(
        &self,
        reason: crate::goodbye::GoodbyeReason,
        budget: Duration,
    ) -> crate::goodbye::GoodbyeOutcome {
        self.goodbyes.say_blocking(reason, budget)
    }

    /// [`Self::goodbye_blocking`] for an async task: the wait runs on the blocking pool.
    pub async fn goodbye(
        &self,
        reason: crate::goodbye::GoodbyeReason,
        budget: Duration,
    ) -> crate::goodbye::GoodbyeOutcome {
        let goodbyes = self.goodbyes.clone();
        match tokio::task::spawn_blocking(move || goodbyes.say_blocking(reason, budget)).await {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::error!(
                    reason = reason.as_str(),
                    "goodbye: the thread that waited for it failed ({e}); taken as not said"
                );
                crate::goodbye::GoodbyeOutcome::NoConnection
            }
        }
    }

    /// The reason a goodbye left the agent offline is over (`why`: the system resumed, Windows
    /// cancelled the shutdown): reconnect now. Whether a goodbye was holding it.
    pub fn welcome_back(&self, why: &str) -> bool {
        self.goodbyes.lift(why)
    }

    /// The pause («Прервать все сеансы», [`AgentState::paused`]) written to config.json now, on this
    /// thread, when the state has it — for a process about to go without its orchestrator (the
    /// desktop app's `supervise`): the orchestrator saves it from the blocking pool, and that save
    /// may still be pending, or may have failed, when the process relaunches. Written whatever the
    /// config in memory says, since a failed save leaves the memory saying paused and the file not.
    /// Takes the state's lock, lets it go, then the config's for the write: never both. Blocking (a
    /// file write): a thread of its own, never an async task's. Logs what it did.
    pub fn keep_pause_blocking(&self, why: &str) -> PauseKept {
        let paused = lock(&self.state).paused;
        if !paused {
            tracing::debug!(why, "the pause: not paused; nothing to keep");
            return PauseKept::NotPaused;
        }
        let mut config = lock(&self.config);
        config.paused = true;
        let kept = match config.save_even_in_place() {
            Ok(crate::config::Saved::Whole | crate::config::Saved::InPlace) => PauseKept::Saved,
            Ok(crate::config::Saved::NoFile) => {
                PauseKept::NotSaved("this config has no file".to_string())
            }
            Err(e) => PauseKept::NotSaved(format!("{e:#}")),
        };
        drop(config);
        match &kept {
            PauseKept::Saved => tracing::info!(
                why,
                "the pause written to config.json: the next start is paused too"
            ),
            PauseKept::NotSaved(e) => tracing::warn!(
                why,
                "the pause NOT written to config.json ({e}): the next start would not be paused \
                 unless told so"
            ),
            PauseKept::NotPaused => {}
        }
        kept
    }

    /// The process is leaving (`why`): end every live session properly first — its final report and
    /// `session_end agent_ended`, in the connection's queue before the goodbye — waiting at most
    /// `budget` ([`EXIT_END_BUDGET`]). Without it those sessions are left to the backend's grace
    /// window and end there as `agent_disconnected`, with no final report. Logs what it did.
    ///
    /// Blocks the calling thread, like [`Self::goodbye_blocking`]: the window's event loop, a
    /// Windows message thread, a thread of its own — never an async task's.
    pub fn end_sessions_for_exit_blocking(
        &self,
        why: crate::goodbye::GoodbyeReason,
        budget: Duration,
    ) -> Option<ExitEnding> {
        let asked = Instant::now();
        let (done, answer) = std::sync::mpsc::sync_channel(1);
        if self
            .commands
            .send(AgentCommand::EndForExit {
                why,
                asked,
                budget,
                done,
            })
            .is_err()
        {
            tracing::debug!(
                why = why.as_str(),
                "exit: the agent is not running; no session to end"
            );
            return None;
        }
        match answer.recv_timeout(budget) {
            Ok(ended) => {
                tracing::info!(
                    why = why.as_str(),
                    sessions = ended.sessions,
                    requests = ended.requests,
                    link = ?ended.link,
                    flushed = ended.flushed,
                    took_ms = asked.elapsed().as_millis() as u64,
                    "exit: live sessions ended before the goodbye"
                );
                Some(ended)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                tracing::warn!(
                    why = why.as_str(),
                    budget_ms = budget.as_millis() as u64,
                    "exit: the orchestrator did not end the sessions in time (busy); the goodbye goes \
                     ahead, the request is dropped when the orchestrator gets to it, and the backend \
                     ends what is left at its grace window"
                );
                None
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                tracing::debug!(
                    why = why.as_str(),
                    "exit: the orchestrator stopped before answering; no session to end"
                );
                None
            }
        }
    }

    /// Leave the backend for `reason`: on a way out (`quit`, `update`, `shutdown`) every live
    /// session is ended first ([`Self::end_sessions_for_exit_blocking`], at most
    /// [`EXIT_END_BUDGET`]), then the goodbye ([`Self::goodbye_blocking`], at most `budget`). A
    /// sleep only says goodbye: the process carries on after it. Blocks, as both do.
    ///
    /// Only for an exit that is certain — the app's own exit, an update's, `WM_ENDSESSION` TRUE.
    /// Where the exit may yet be called off (`WM_QUERYENDSESSION`, which another application can
    /// refuse) the goodbye alone ([`Self::goodbye_blocking`]): the sessions must outlive a
    /// cancelled shutdown.
    pub fn leave_blocking(
        &self,
        reason: crate::goodbye::GoodbyeReason,
        budget: Duration,
    ) -> crate::goodbye::GoodbyeOutcome {
        if reason == crate::goodbye::GoodbyeReason::Sleep {
            tracing::debug!(
                "leaving for sleep: the sessions are not ended (the process carries on)"
            );
        } else {
            self.end_sessions_for_exit_blocking(reason, EXIT_END_BUDGET);
        }
        self.goodbye_blocking(reason, budget)
    }

    /// The reason of the goodbye that holds the agent offline, if one does.
    pub fn goodbye_held(&self) -> Option<crate::goodbye::GoodbyeReason> {
        self.goodbyes.held().map(|h| h.reason)
    }

    /// The game helper launched the bound game itself and waits for its window (`launching`), or no
    /// longer (`crate::game::HelperLaunch`); `why` is what the desktop app read from the helper.
    /// Heartbeats say `game.launching` while the window is absent or starting. Only the desktop app
    /// calls this. True when it changed.
    pub fn set_game_launching(&self, launching: bool, why: &str) -> bool {
        self.helper_launch.set(launching, why)
    }

    /// What [`Self::set_game_launching`] last put in force.
    pub fn game_launching(&self) -> bool {
        self.helper_launch.is_launching()
    }

    /// Receive every [`AgentEvent`] from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<AgentEvent> {
        self.events.subscribe()
    }

    /// «Only the game window» as config.json has it: on or off, and the bound game.
    pub fn game_only(&self) -> (bool, Option<crate::game::GameBinding>) {
        let c = lock(&self.config);
        (c.game_only, c.game.clone())
    }

    /// Turn «only the game window» on or off: in force for live sessions at once, and saved.
    ///
    /// Only the desktop app on this PC calls this — there is no command for it from the backend or
    /// the viewer. A failed save leaves the change in force for this run and says so.
    pub fn set_game_only(&self, enabled: bool) -> Result<()> {
        let mut changed = false;
        let saved = self.change_game(|c| {
            if c.game_only == enabled {
                return None;
            }
            c.game_only = enabled;
            changed = true;
            Some(if enabled {
                "the owner turned game-only on"
            } else {
                "the owner turned game-only off"
            })
        });
        // In force whether or not the disk took it: the change happened.
        if changed {
            crate::agent_events::setting_changed(
                afklink_protocol::metrics::PcSettingKey::GameOnly,
                afklink_protocol::metrics::PcSettingValue::Flag(enabled),
            );
        }
        saved
    }

    /// «Только для гостей» as config.json has it (`Config::game_only_for_guests`).
    pub fn game_only_for_guests(&self) -> bool {
        lock(&self.config).game_only_for_guests
    }

    /// Turn «Только для гостей» on or off: game-only for guests' sessions only, or for everyone —
    /// every live session decided again at once (`crate::game_access`), and saved. Only the desktop
    /// app on this PC calls this, as [`Self::set_game_only`].
    pub fn set_game_only_for_guests(&self, enabled: bool) -> Result<()> {
        let mut changed = false;
        let saved = self.change_game(|c| {
            if c.game_only_for_guests == enabled {
                return None;
            }
            c.game_only_for_guests = enabled;
            changed = true;
            Some(if enabled {
                "the owner turned «Только для гостей» on: game-only for guests only"
            } else {
                "the owner turned «Только для гостей» off: game-only for everyone"
            })
        });
        if changed {
            crate::agent_events::setting_changed(
                afklink_protocol::metrics::PcSettingKey::GameOnlyForGuests,
                afklink_protocol::metrics::PcSettingValue::Flag(enabled),
            );
        }
        saved
    }

    /// The connected sessions game-only applies to now, by id: the game helper acts only for these —
    /// the owner's whole desktop never launches the game, and neither does a session still
    /// connecting (`crate::game_access`).
    pub fn game_only_sessions(&self) -> Vec<String> {
        self.game_access.game_only_sessions()
    }

    /// The live sessions as the game helper's signal reads them, in one look: how many, how many
    /// connected, and which connected and still-connecting ones game-only applies to
    /// (`crate::game_access::HelperSessions`).
    pub fn helper_sessions(&self) -> crate::game_access::HelperSessions {
        self.game_access.helper_sessions()
    }

    /// Bind the game `game_only` shows, or clear the binding with `None`; as [`Self::set_game_only`].
    /// Clearing it with the mode on leaves black frames only — never the desktop. Another game's
    /// window exe forgets the launch exe the owner chose for the last one (`Config::game_launch_exe`)
    /// and the one learned from its parent process (`Config::game_launch_learned`).
    pub fn set_game_binding(&self, binding: Option<crate::game::GameBinding>) -> Result<()> {
        self.change_game(|c| {
            if c.game == binding {
                return None;
            }
            let why = if binding.is_some() {
                "the owner bound a game"
            } else {
                "the owner cleared the game"
            };
            let same_exe = matches!(
                (&c.game, &binding),
                (Some(old), Some(new)) if old.exe_matches(&new.exe_path)
            );
            if !same_exe {
                if let Some(launch) = c.game_launch_exe.take() {
                    tracing::info!(
                        launch = %launch,
                        "the launch exe chosen for the last game is forgotten: another game"
                    );
                }
                if let Some(learned) = c.game_launch_learned.take() {
                    tracing::info!(
                        learned = %learned,
                        "the launch exe learned for the last game is forgotten: another game"
                    );
                }
            }
            c.game = binding;
            Some(why)
        })
    }

    /// Apply `change` to config.json's game fields, decide every live session again with the result
    /// (`crate::game_access`), then save.
    fn change_game(&self, change: impl FnOnce(&mut Config) -> Option<&'static str>) -> Result<()> {
        let mut c = lock(&self.config);
        let Some(why) = change(&mut c) else {
            tracing::debug!(
                game_only = c.game_only,
                for_guests = c.game_only_for_guests,
                game = %c.game.as_ref().map_or("-", crate::game::GameBinding::shown_name),
                "game-only setting unchanged"
            );
            return Ok(());
        };
        tracing::info!(
            game_only = c.game_only,
            for_guests = c.game_only_for_guests,
            game = %c.game.as_ref().map_or("-", crate::game::GameBinding::shown_name),
            exe = %c.game.as_ref().map_or("-", |g| g.exe_path.as_str()),
            class = %c.game.as_ref().map_or("-", |g| g.window_class.as_str()),
            "game-only setting changed: {why}"
        );
        // Before the save: what the owner asked for is in force whether or not the disk takes it.
        self.game_access
            .set_policy(crate::game_access::GamePolicy::from_config(&c), why);
        c.save().inspect_err(|e| {
            tracing::warn!(
                "game-only setting not saved to config.json: {e:#}; in force until exit"
            );
        })
    }

    /// The input driver is installed — the desktop app read it so (`why`): the window's
    /// «Управление не доходит» highlight ([`AgentState::input_not_reaching`]) has nothing left to
    /// ask for, and goes, from config.json too. Nothing to do when it is not set.
    pub fn driver_installed(&self, why: &str) {
        crate::input_reach::set_highlight(&self.state, &self.config, false, why, None);
    }

    /// Advance the PC's request to the owner to `now_ms`: the end of each wait for the server, and
    /// how long an outcome stays on its row (`crate::owner_request`). The desktop app calls it from
    /// its state watcher twice a second and before each status read; each change is logged once,
    /// when it happens.
    pub fn tick_owner_requests(&self, now_ms: i64) {
        let mut s = lock(&self.state);
        let AgentState {
            owner_requests,
            connected,
            bindings,
            ..
        } = &mut *s;
        owner_requests.tick(now_ms, *connected, bindings);
    }

    /// The pairing deep link for the current code, or `None`: no code, or no known bot (see
    /// [`AgentState::pairing_link`]). Never a link to a guessed bot. Called on every render of the
    /// window, so it decides and logs nothing: that happened once, when the code arrived.
    pub fn deep_link(&self) -> Option<String> {
        let state = lock(&self.state);
        let code = state.pairing_code.as_deref()?;
        Some(state.pairing_link.as_ref()?.link(code))
    }
}

/// Internal signals from per-session tasks to the orchestrator loop.
enum SessionSignal {
    Connected(String),
    /// The session's peer ended; end the session with `end.reason()` (`PeerEnd::reason`), so a
    /// network change that outlived the grace window (`ice_timeout`) is not recorded as the viewer
    /// hanging up (`peer_closed`). The journal also hears whether the viewer said goodbye
    /// (`PeerEnd::by_viewer`), which the wire reason does not carry.
    Closed {
        id: String,
        end: transport::PeerEnd,
    },
    /// The capture -> encode pipeline could not be brought back; end the session with `reason`,
    /// one of the agreed `SESSION_END_REASONS` (`capture_lost`, `encoder_error`). Sent by the encode
    /// thread when it gives up, and by the heartbeat task when that thread is stuck in a call.
    PipelineFailed {
        id: String,
        reason: &'static str,
    },
}

impl SessionSignal {
    /// Its name and session, for the orchestrator's step (`crate::step_watch`).
    fn kind(&self) -> (&'static str, &str) {
        match self {
            Self::Connected(id) => ("connected", id),
            Self::Closed { id, .. } => ("closed", id),
            Self::PipelineFailed { id, .. } => ("pipeline_failed", id),
        }
    }
}

struct Session {
    telegram_user_id: i64,
    username: Option<String>,
    /// The peer's queue for the viewer's trickled candidates and re-offers: handed over as they
    /// come, never waiting, none lost below its cap (`transport::peer_signal`; `signal_peer`). The
    /// peer's control queue is its tasks', not the orchestrator's: nothing here writes to it.
    signals: SignalSender,
    /// Ends the peer whatever its queues hold; see `close_peer`.
    closer: PeerCloser,
    /// Shared with the encode thread, which restarts the capture inside it. See `end_session`.
    capturer: Arc<Mutex<Box<dyn Capturer>>>,
    stop: Arc<AtomicBool>,
    input: Arc<InputSession>,
    /// Where the session's `session_stats` come from: the telemetry task's reports, and the
    /// re-announce on a new signaling connection (`Agent::announce_after_connect`).
    stats: StatsSource,
    /// The injector's word on the input's reach at the session's start: its end diffs the counts
    /// against it (`crate::input_reach`).
    reach_start: crate::traits::InputReach,
    /// The session's capture mode — game-only or not, decided for its viewer
    /// (`crate::game_access`): what the journal's entry opens with.
    capture_mode: Arc<crate::game::CaptureModeCell>,
    /// How far the peer got and over which pair (`transport::PeerPath`): the path half of the
    /// session's `session_end.detail` when the agent ends it.
    path: Arc<transport::PeerPathCell>,
}

/// The orchestrator's live sessions, by id. Whatever is still in it when it is dropped was never
/// ended: the orchestrator itself ended — a panic on its worker (the run future dropped), an error,
/// a return — and nothing else would ever end those sessions. Without this their peer tasks, encode
/// threads and input went on with nobody to stop them: the kill switch, «Отвязать» and the exit go
/// through the orchestrator's command channel, which is gone with it (the desktop app's
/// `supervise`). So each is ended at the drop ([`end_orphaned`]), whether or not the app relaunches.
///
/// How loudly depends on how the orchestrator ended: an end it said was asked for
/// ([`Self::ends_as_asked`]: the exit's request, nothing left to command it, `replaced`) is an
/// ordinary one, said at `debug`; any other — a panic, an error, a drop with nothing said — at `warn`.
#[derive(Default)]
struct LiveSessions {
    map: HashMap<String, Session>,
    /// Why the orchestrator's end is an ordinary one, once it said so.
    ordinary_end: Option<&'static str>,
}

impl LiveSessions {
    /// The orchestrator's end from here on is an ordinary one (`why`): sessions still live at the
    /// drop are ended all the same, said at `debug`.
    fn ends_as_asked(&mut self, why: &'static str) {
        if self.ordinary_end.is_none() {
            tracing::debug!(
                why,
                live = self.map.len(),
                "the orchestrator's end is an ordinary one from here"
            );
            self.ordinary_end = Some(why);
        }
    }
}

impl std::ops::Deref for LiveSessions {
    type Target = HashMap<String, Session>;
    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl std::ops::DerefMut for LiveSessions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

impl Drop for LiveSessions {
    fn drop(&mut self) {
        if self.map.is_empty() {
            return;
        }
        let panicking = std::thread::panicking();
        match self.ordinary_end {
            Some(why) if !panicking => tracing::debug!(
                sessions = self.map.len(),
                why,
                "the orchestrator ended as asked with sessions live: each is ended here (its peer \
                 closed, its input refused and released, its capture stopped)"
            ),
            ordinary => tracing::warn!(
                sessions = self.map.len(),
                panicking,
                asked = ordinary.unwrap_or("-"),
                "the orchestrator ended with sessions live: each is ended here (its peer closed, \
                 its input refused and released, its capture stopped; nothing reaches the backend \
                 — its grace window ends them there)"
            ),
        }
        for (id, session) in self.map.drain() {
            end_orphaned(&id, &session);
        }
    }
}

/// [`LiveSessions::ends_as_asked`]'s word for `run` returning `Ok`: its command channel closed.
const NOTHING_TO_COMMAND: &str = "nothing can command it any more";

/// A session's input from its opening until the session is registered ([`LiveSessions`]): should
/// the start stop in between — a panic, or its future dropped — the session is in no list that
/// would ever end it, and its input gate would stay open. Dropped armed, it refuses the input, stops
/// the session's threads and tasks (`stop`) and closes the input on a thread of its own; disarmed
/// once the session is registered. On whatever thread drops it, during unwinding too: atomics only,
/// the close detached.
struct UnregisteredInput {
    session_id: String,
    input: Arc<InputSession>,
    stop: Arc<AtomicBool>,
    armed: bool,
}

impl UnregisteredInput {
    fn arm(session_id: &str, input: &Arc<InputSession>, stop: &Arc<AtomicBool>) -> Self {
        Self {
            session_id: session_id.to_owned(),
            input: Arc::clone(input),
            stop: Arc::clone(stop),
            armed: true,
        }
    }

    /// The session is registered: its end is the list's from here.
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for UnregisteredInput {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.stop.store(true, Ordering::SeqCst);
        // False: the start's own failure path refused it first, and closes it itself.
        if !self
            .input
            .refuse("its session's start stopped before the session was registered")
        {
            tracing::debug!(
                session = %self.session_id,
                "session start ended before its registration; its input was refused already and \
                 is closed by that path"
            );
            return;
        }
        tracing::warn!(
            session = %self.session_id,
            panicking = std::thread::panicking(),
            "session start stopped between its input's opening and its registration (a panic, or \
             the orchestrator gone): input refused, threads told to stop, the input closed on a \
             thread of its own"
        );
        let input = Arc::clone(&self.input);
        drop(crate::offload::detach(
            "input-close",
            &self.session_id,
            move || input.close(),
        ));
    }
}

/// End a session the orchestrator cannot end any more ([`LiveSessions`]'s drop). On whatever thread
/// drops the orchestrator — a runtime worker, during a panic's unwinding too — so nothing here waits
/// or takes a lock of the orchestrator's: the stop flag and the input's refusal are atomics, the
/// peer's close is a watch send, and the input's gate close and release and the capture's stop —
/// each of which may wait on the driver or a capture thread — go to threads of their own
/// (`crate::offload`), detached.
fn end_orphaned(session_id: &str, session: &Session) {
    // The encode thread sees it within `pipeline::SUPERVISE_EVERY` and exits.
    session.stop.store(true, Ordering::SeqCst);
    // From here no event of it is injected.
    session.input.refuse("the orchestrator ended");
    close_peer(&session.closer, session_id);
    let input = Arc::clone(&session.input);
    let sid = session_id.to_owned();
    drop(crate::offload::detach("input-end", session_id, move || {
        // Released what it holds and closed; false: another close got there first, and ended
        // the injector session itself.
        let closed_here = input.close_gate();
        if closed_here {
            input.end_injector_session();
        }
        tracing::debug!(
            session = %sid,
            closed_here,
            "orphaned session's input ended (gate closed and released)"
        );
    }));
    let capturer = Arc::clone(&session.capturer);
    let sid = session_id.to_owned();
    drop(crate::offload::detach(
        "capture-stop",
        session_id,
        move || {
            stop_capture(&capturer, &sid);
        },
    ));
    tracing::info!(
        session = session_id,
        telegram_user_id = session.telegram_user_id,
        "session ended without the orchestrator: peer told to close, input refused, release and \
         capture stop handed to threads of their own"
    );
}

/// A session's cumulative report, readable from anywhere: the telemetry task (first after
/// `TELEMETRY_FIRST_REPORT_MS`, then every `TELEMETRY_INTERVAL_MS`), the orchestrator when it names
/// the session on a new connection, and the session's end, which sends the final one.
#[derive(Clone)]
struct StatsSource {
    counters: Arc<SessionCounters>,
    target: Arc<crate::quality::QualityTarget>,
    started: Instant,
    /// The background hold's totals (`crate::bg_hold`): held time and holds, a hold in progress
    /// counted up to the report.
    bg: Arc<crate::bg_hold::BgHold>,
    /// Whether the final report went out. Held across the check and the send, so no periodic
    /// report can follow the final into the outbox: the server drops a side's reports after its
    /// final, and one arriving after it would only be noise.
    finished: Arc<Mutex<bool>>,
    /// The session's summary (`crate::summary`): in every report, the final one included.
    summary: Arc<crate::summary::SessionSummary>,
}

/// What [`StatsSource::report`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reported {
    /// Into the outbox (the relay forwards it, or holds or drops it while signaling is down).
    Sent,
    /// Not sent: the session's final report went out already.
    AfterFinal,
    /// Not sent: the outbox is gone (the agent is stopping).
    OutboxGone,
}

impl StatsSource {
    /// A session's reports with a summary of their own, starting now (tests).
    #[cfg(test)]
    fn new(
        counters: Arc<SessionCounters>,
        target: Arc<crate::quality::QualityTarget>,
        bg: Arc<crate::bg_hold::BgHold>,
    ) -> Self {
        let summary = Arc::new(crate::summary::SessionSummary::new(
            "-",
            Instant::now(),
            None,
            None,
            crate::traits::InputReach::default(),
        ));
        Self::with_summary(counters, target, bg, summary)
    }

    /// A session's reports, its summary's start being the session's.
    fn with_summary(
        counters: Arc<SessionCounters>,
        target: Arc<crate::quality::QualityTarget>,
        bg: Arc<crate::bg_hold::BgHold>,
        summary: Arc<crate::summary::SessionSummary>,
    ) -> Self {
        Self {
            counters,
            target,
            started: summary.started(),
            bg,
            finished: Arc::new(Mutex::new(false)),
            summary,
        }
    }

    fn snapshot(&self) -> afklink_transport::AgentSessionStats {
        let now = Instant::now();
        // `(0, 0)` before the first frame: the report says "no source yet" as zeros.
        let source = self.target.source().unwrap_or((0, 0));
        let mut stats = self
            .counters
            .snapshot(now.saturating_duration_since(self.started), source);
        let (held_ms, holds) = self.bg.totals(now);
        stats.bg_hold_ms = Some(held_ms);
        stats.bg_holds = Some(holds);
        stats.summary = self.summary.checked(now, &self.counters).map(Box::new);
        stats
    }

    /// Send the session's report — the final one when `is_final` — unless the final went out
    /// already. One final per session: a second is refused like any report after it.
    fn report(
        &self,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
        session_id: &str,
        is_final: bool,
    ) -> Reported {
        let mut finished = lock(&self.finished);
        if *finished {
            return Reported::AfterFinal;
        }
        let stats = self.snapshot();
        if is_final {
            log_final_summary(session_id, &stats);
        }
        let msg = AgentToServer::SessionStats {
            session_id: session_id.to_string(),
            stats,
            is_final,
        };
        if outgoing.send(msg).is_err() {
            return Reported::OutboxGone;
        }
        if is_final {
            *finished = true;
        }
        Reported::Sent
    }
}

/// The session's summary as its final report carries it, once, at debug: what the server is told,
/// beside the log lines it was made from.
fn log_final_summary(session_id: &str, stats: &afklink_transport::AgentSessionStats) {
    let Some(s) = &stats.summary else {
        tracing::debug!(
            session = session_id,
            "session summary: none in the final report"
        );
        return;
    };
    let rungs = s.rung_s.as_ref().map_or_else(
        || "-".to_string(),
        |r| {
            r.iter()
                .map(|(h, secs)| format!("{h}:{secs}"))
                .collect::<Vec<_>>()
                .join(",")
        },
    );
    let kinds = s.episodes.as_ref().map_or_else(
        || "-".to_string(),
        |e| {
            let mut counts = std::collections::BTreeMap::<&str, u32>::new();
            for ep in e {
                *counts.entry(ep.kind.as_str()).or_insert(0) += 1;
            }
            counts
                .iter()
                .map(|(k, n)| format!("{k}:{n}"))
                .collect::<Vec<_>>()
                .join(",")
        },
    );
    let input = s.input.map_or_else(
        || "-".to_string(),
        |i| {
            format!(
                "abs:{},rel:{},buttons:{},keys:{},text:{}",
                i.abs, i.rel, i.buttons, i.keys, i.text
            )
        },
    );
    tracing::debug!(
        session = session_id,
        duration_ms = stats.duration_ms,
        rung_s = %rungs,
        freeze_s = ?s.freeze_s,
        episodes = %kinds,
        episodes_dropped = ?s.episodes_dropped,
        encode_ms_p95 = ?s.encode_ms_p95,
        input = %input,
        input_path = s.input_path.map_or("-", |p| p.as_str()),
        input_blocked_n = ?s.input_blocked_n,
        capture_mode = s.capture_mode.map_or("-", |m| m.as_str()),
        driver = s.driver.map_or("-", |d| d.as_str()),
        dropped_rate = ?s.dropped_rate,
        bytes_socket = ?s.bytes_socket,
        bytes_relay = ?s.bytes_relay,
        "session summary (final report)"
    );
}

/// The session's reports while it runs: the first after `first`, then every `every` — 5 s and 15 s
/// (`TELEMETRY_FIRST_REPORT_MS`, `TELEMETRY_INTERVAL_MS`): a session that dies in its first quarter
/// minute, as most failed ones do, still leaves a report. Stops at the session's end, whose final
/// report the orchestrator sends (`Agent::end_session`), or when the outbox is gone.
///
/// Repeatedly rather than once at the end, because the sessions worth studying are the ones that
/// never get to send a final anything — the agent crashed, the network went away, the machine
/// slept. Cumulative totals mean whichever report arrived last is still a complete summary of the
/// session up to that point.
///
/// The agent's outbox, not a connection: a report made while signaling is down is dropped by the
/// relay (the next one says it all), and the task carries on across the reconnect rather than
/// stopping for good on the first refused send.
async fn telemetry_task(
    stats: StatsSource,
    outgoing: mpsc::UnboundedSender<AgentToServer>,
    stop: Arc<AtomicBool>,
    sid: String,
    first: Duration,
    every: Duration,
) {
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + first, every);
    // A late tick is not made up: two reports back to back say nothing the second does not.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut sent = 0u64;
    tracing::debug!(
        session = %sid,
        first_ms = first.as_millis() as u64,
        every_ms = every.as_millis() as u64,
        "telemetry: reports scheduled"
    );
    loop {
        tick.tick().await;
        if stop.load(Ordering::SeqCst) {
            tracing::debug!(session = %sid, sent, "telemetry stopped: the session ended");
            break;
        }
        match stats.report(&outgoing, &sid, false) {
            Reported::Sent => {
                sent += 1;
                tracing::trace!(session = %sid, n = sent, "telemetry: report sent");
            }
            Reported::AfterFinal => {
                tracing::debug!(
                    session = %sid,
                    sent,
                    "telemetry stopped: the session's final report went out"
                );
                break;
            }
            Reported::OutboxGone => {
                tracing::debug!(
                    session = %sid,
                    sent,
                    "telemetry stopped: the signaling relay is gone (the agent is stopping)"
                );
                break;
            }
        }
    }
}

struct Pending {
    telegram_user_id: i64,
    username: Option<String>,
    /// STUN servers ("host:port") for server-reflexive gathering, from the session's ICE URLs.
    /// All of them rather than the first: see `transport::stun_servers`.
    stun_servers: Vec<String>,
    /// The quality policy the session will run on, chosen at its `session_request` (the server's
    /// profile or the fallback, `crate::quality_policy::SessionPolicy::for_session`).
    policy: crate::quality_policy::SessionPolicy,
}

/// What a session opens on before its controller exists, all from its policy: the start rung, the
/// encoder's first target there, and congestion control's opening probe target — priced against
/// the guessed 1920x1080 that the control task corrects once capture reports the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionOpening {
    start: crate::quality::Rung,
    target_kbps: u32,
    probe_kbps: u32,
}

/// [`SessionOpening`] on `policy`. Pure: `start_session` calls it on the orchestrator task.
fn session_opening(
    policy: &crate::quality_policy::QualityPolicy,
    quality: crate::quality::Quality,
) -> SessionOpening {
    let start = policy.start_rung();
    SessionOpening {
        start,
        target_kbps: start.required_kbps_with(policy, 1920, 1080, quality),
        probe_kbps: crate::quality::opening_probe_target_kbps_with(policy, 1920, 1080, quality),
    }
}

/// Whether `telegram_user_id` currently holds a binding on this device.
///
/// The single gate for "may this user open a session": checked when a
/// `SessionRequest` arrives and again when its offer does, so an unbind in
/// between still refuses. Pairing (the first binding) travels
/// `PairRequest` → owner confirm → `BindingAdded` and never passes through
/// here, so this cannot lock out the initial bind.
fn is_bound(bindings: &[BindingInfo], telegram_user_id: i64) -> bool {
    bindings
        .iter()
        .any(|b| b.telegram_user_id == telegram_user_id)
}

/// The roles as the server's list has them, for the log: who the owner is (an id, never a name),
/// how many guests, and whether the server speaks roles at all (a server older than them sends
/// none). `from`: the message the list came with.
fn log_roles(bindings: &[BindingInfo], from: &'static str) {
    use afklink_protocol::BindingRole;
    let owners: Vec<i64> = bindings
        .iter()
        .filter(|b| b.role == Some(BindingRole::Owner))
        .map(|b| b.telegram_user_id)
        .collect();
    let guests = bindings
        .iter()
        .filter(|b| b.role == Some(BindingRole::Guest))
        .count();
    let without = bindings.iter().filter(|b| b.role.is_none()).count();
    if owners.len() > 1 {
        tracing::warn!(
            from,
            owners = ?owners,
            "roles: the server lists more than one owner for this PC (it allows one); shown as listed"
        );
    }
    tracing::debug!(
        from,
        bindings = bindings.len(),
        owner = owners.first().copied().unwrap_or(0),
        guests,
        without_role = without,
        "roles: {}",
        if bindings.is_empty() {
            "nobody has access"
        } else if without == bindings.len() {
            "the server sends no roles (older than them): the list shows none"
        } else if owners.is_empty() {
            "this PC has no owner"
        } else {
            "the owner and the guests as listed"
        }
    );
}

/// The role an approval gives (`pair_response.role`): the answer to
/// «Кто это?» when the prompt asked it; `guest` when it did not — a PC with an owner, a server
/// older than roles (which drops the field), or a front end that does not ask (the CLI's `y`).
/// `asked`: whether the prompt asked (`None` — no such prompt is pending any more: answered late,
/// or withdrawn).
fn pair_role(
    request_id: &str,
    chosen: Option<afklink_protocol::BindingRole>,
    asked: Option<bool>,
) -> afklink_protocol::BindingRole {
    use afklink_protocol::BindingRole;
    let role = chosen.unwrap_or(BindingRole::Guest);
    let why = match (asked, chosen) {
        (Some(true), Some(_)) => "the answer to «Кто это?»",
        (Some(true), None) => {
            "«Кто это?» was asked and not answered here (a front end that does not ask): a guest"
        }
        (Some(false), None) => {
            "not asked (the PC has an owner, or the server knows no roles): a guest"
        }
        (Some(false), Some(BindingRole::Owner)) => {
            "owner chosen though the prompt did not ask: the server makes the person a guest on a \
             PC with an owner"
        }
        (Some(false), Some(BindingRole::Guest)) => "not asked; a guest, as chosen",
        (None, _) => "the prompt is no longer pending here; sent as it stands",
    };
    tracing::debug!(
        request_id,
        role = role.as_str(),
        asked = asked.map_or("-", |a| if a { "true" } else { "false" }),
        "pairing approval: role {} — {why}",
        role.as_str()
    );
    role
}

/// The role `telegram_user_id` has on this PC, as the server last said it; `None` for a binding
/// without one (a server older than roles) or no binding.
fn role_of(
    bindings: &[BindingInfo],
    telegram_user_id: i64,
) -> Option<afklink_protocol::BindingRole> {
    bindings
        .iter()
        .find(|b| b.telegram_user_id == telegram_user_id)
        .and_then(|b| b.role)
}

/// Write the pause as `state` has it now into config.json (`Config::paused`; `why`: what changed it),
/// one write at a time (`one_at_a_time`). On the blocking pool ([`Agent::save_pause`]): the config's
/// lock is held for the write, as for every other save, and the file is replaced whole — or, when
/// another program holds it past the replace's retries, written over in place
/// (`Config::save_even_in_place`), since a pause that is not on disk ends at the next start. Never
/// both locks at once. Every outcome is logged; a failure leaves the pause in force for this run.
fn persist_pause(
    config: &Mutex<Config>,
    state: &Mutex<AgentState>,
    one_at_a_time: &Mutex<()>,
    why: &str,
) {
    let _one = lock(one_at_a_time);
    let paused = lock(state).paused;
    let mut c = lock(config);
    if c.paused == paused {
        tracing::debug!(
            paused,
            why,
            "the pause in config.json is already so; not written again"
        );
        return;
    }
    c.paused = paused;
    let path = c
        .path()
        .map_or_else(|| "-".to_string(), |p| p.display().to_string());
    let lasting = if paused {
        "it holds across a restart and an update"
    } else {
        "the next start accepts sessions"
    };
    let lost = if paused {
        "a restart or an update would end it"
    } else {
        "the next start would be paused again until «Возобновить»"
    };
    match c.save_even_in_place() {
        Ok(crate::config::Saved::Whole) => tracing::debug!(
            paused,
            why,
            %path,
            "the pause saved to config.json: {lasting}"
        ),
        Ok(crate::config::Saved::InPlace) => tracing::debug!(
            paused,
            why,
            %path,
            "the pause saved to config.json, written over in place (see the warning): {lasting}"
        ),
        Ok(crate::config::Saved::NoFile) => tracing::warn!(
            paused,
            why,
            "the pause not saved: this config has no file; in force for this run, but {lost}"
        ),
        Err(e) => tracing::warn!(
            paused,
            why,
            %path,
            "the pause not saved to config.json: {e:#}; in force for this run, but {lost}"
        ),
    }
}

/// A pairing request approved on this PC whose binding has not been heard of yet.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ApprovedHere {
    request_id: String,
    /// Forgotten from then on: [`APPROVED_HERE_FOR`] after the press, or — while the server holds
    /// the pairing for the owner (`pc_allow`) — the owner's deadline and the server's sweep after it
    /// ([`Agent::hold_approval_for_owner`]).
    until: Instant,
}

/// How long an approval on this PC counts for an account a later binding list has: a request's own
/// lifetime (`PAIR_CONFIRM_TIMEOUT_MS`). The server makes the binding the moment it takes the
/// approval, so a list that has it comes at the first reconnect — well inside this; past it, the
/// account in a list is no longer this approval's.
const APPROVED_HERE_FOR: Duration =
    Duration::from_millis(afklink_protocol::PAIR_CONFIRM_TIMEOUT_MS);

/// How a binding list differs from an earlier one, by Telegram id: who is gone, who is new —
/// each in the order of the list it is in.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct BindingChanges {
    gone: Vec<BindingInfo>,
    added: Vec<BindingInfo>,
}

fn binding_changes(previous: &[BindingInfo], now: &[BindingInfo]) -> BindingChanges {
    let listed = |list: &[BindingInfo], id: i64| list.iter().any(|b| b.telegram_user_id == id);
    BindingChanges {
        gone: previous
            .iter()
            .filter(|b| !listed(now, b.telegram_user_id))
            .cloned()
            .collect(),
        added: now
            .iter()
            .filter(|b| !listed(previous, b.telegram_user_id))
            .cloned()
            .collect(),
    }
}

/// Why «Новый гость: {user}» does not go out for a binding by the owner's invite, or `None` when it
/// does. `listed`: the person was in the list before this `binding_added` — a repeat, not a new
/// guest, and not told twice (the journal still writes each one, as it does a re-pair's
/// «Доступ выдан»). A role other than guest breaks the contract (an invite always makes a guest;
/// warned where it comes in), and «Новый гость» would be untrue of an owner. No role at all is
/// taken as a guest's: only a server older than roles sends none, and that one knows no invites
/// either.
fn invited_guest_toast_withheld(
    role: Option<afklink_protocol::BindingRole>,
    listed: bool,
) -> Option<&'static str> {
    if listed {
        return Some("a repeat: the person was already listed, so not a new guest");
    }
    if role == Some(afklink_protocol::BindingRole::Owner) {
        return Some("the role is owner, not guest: «Новый гость» would be untrue");
    }
    None
}

/// Hand a message to the agent's outbox, and say so when it cannot go.
///
/// In the running agent `outgoing` is the outbox the signaling relay reads (`crate::relay`), which
/// lives as long as the agent: it forwards to the current connection, or holds or drops by kind
/// while there is none, and logs each of those. The pump logs every message it writes
/// (`afklink_transport::signaling`). So a refusal here means only that the relay itself has
/// stopped — the agent is stopping — and a `session_end` or an `ice` that went nowhere still says
/// so. Returns whether it was handed over.
fn send_to_backend(outgoing: &mpsc::UnboundedSender<AgentToServer>, msg: AgentToServer) -> bool {
    match outgoing.send(msg) {
        Ok(()) => true,
        Err(mpsc::error::SendError(msg)) => {
            tracing::debug!(
                session = msg.session_id().unwrap_or("-"),
                kind = msg.kind(),
                "the signaling relay is gone (the agent is stopping): message not sent"
            );
            false
        }
    }
}

/// Wait until something is queued in `queue` — never, without one.
async fn events_queued(queue: Option<&crate::agent_events::EventQueue>) {
    match queue {
        Some(q) => q.queued().await,
        None => std::future::pending().await,
    }
}

/// Tell a session's peer to close, and say whether it was still there to hear it.
///
/// Through the peer's [`PeerCloser`], not its control queue: a close sent into that bounded queue
/// is refused whenever it is full, and the peer then runs until ICE gives up on a viewer that has
/// gone — half a minute of a socket and a task for nobody. The closer cannot fill up, so there is
/// no failure left to report, only whether the peer had already ended by itself.
fn close_peer(closer: &PeerCloser, session: &str) {
    if closer.close() {
        tracing::debug!(session, "peer told to close");
    } else {
        tracing::debug!(session, "peer already gone; nothing to close");
    }
}

/// Hand one of the viewer's signals — a trickled candidate, a re-offer — to its session's peer,
/// never waiting, and say what became of it. `Err` says why the peer did not take it, for a caller
/// that has to act on that (a re-offer nobody will answer ends the session); every outcome is
/// logged here.
///
/// The peer's signal queue holds `transport::SIGNAL_QUEUE_CAP` of them untaken, so a burst — the
/// viewer's whole trickle arriving at once after `start_session`'s wait, or a resume's offer and
/// candidates — is kept whole and in order (a 16-deep queue drops ten relay candidates of a real
/// trickle of 26). Only a peer that stopped taking, or a viewer flooding it, reaches
/// the cap: the first refusal of a run is a warning with the candidate, the rest of the run trace,
/// and the next signal queued says at warn how many the run lost.
fn signal_peer(
    signals: &SignalSender,
    session: &str,
    signal: PeerSignal,
) -> Result<(), &'static str> {
    let kind = signal.kind();
    match signals.send(signal) {
        SignalSent::Queued {
            depth,
            new_high,
            after_refusals,
        } => {
            if after_refusals > 0 {
                tracing::warn!(
                    session,
                    kind,
                    refused = after_refusals,
                    dropped_total = signals.counts().dropped,
                    depth,
                    cap = signals.cap(),
                    "the peer's signal queue takes the viewer's signals again: `refused` in a row \
                     were dropped while it was full"
                );
            }
            if new_high {
                // At 8 and each doubling: a burst is a few lines, and the peer's `ICE connected`
                // and end lines have the totals.
                tracing::debug!(
                    session,
                    kind,
                    depth,
                    cap = signals.cap(),
                    "the viewer's signals are waiting for the peer to take them: the queue is the \
                     deepest it has been (said at 8 and each doubling); every one is kept, up to cap"
                );
            }
            // Per signal: a burst is dozens, so trace.
            tracing::trace!(session, kind, depth, "viewer signal queued for the peer");
            Ok(())
        }
        SignalSent::Full {
            signal,
            in_a_row,
            dropped,
        } => {
            let cap = signals.cap();
            let taken = signals.counts().taken;
            match (&signal, in_a_row) {
                // A candidate lost is a path ICE never tries — possibly the only one. The text
                // begins as it did when these went through the control queue, so a search for
                // `remote candidate dropped` finds both.
                (PeerSignal::AddRemoteIce(c), 1) => tracing::warn!(
                    session,
                    candidate = %c.candidate,
                    dropped_total = dropped,
                    taken,
                    cap,
                    "remote candidate dropped: the peer's signal queue is full (`cap` signals it \
                     has not taken); the rest of this run is at trace, and its count comes with the \
                     next signal queued"
                ),
                (PeerSignal::Renegotiate(sdp), 1) => tracing::warn!(
                    session,
                    bytes = sdp.len(),
                    dropped_total = dropped,
                    taken,
                    cap,
                    "re-offer dropped: the peer's signal queue is full (`cap` signals it has not \
                     taken)"
                ),
                (PeerSignal::AddRemoteIce(c), _) => tracing::trace!(
                    session,
                    candidate = %c.candidate,
                    in_a_row,
                    dropped_total = dropped,
                    "remote candidate dropped: the peer's signal queue is still full"
                ),
                (PeerSignal::Renegotiate(sdp), _) => tracing::trace!(
                    session,
                    bytes = sdp.len(),
                    in_a_row,
                    dropped_total = dropped,
                    "re-offer dropped: the peer's signal queue is still full"
                ),
            }
            Err("its signal queue is full")
        }
        SignalSent::Closed(_) => {
            tracing::debug!(
                session,
                kind,
                "viewer signal not delivered: the peer has ended"
            );
            Err("the peer has ended")
        }
    }
}

/// How a signaling connection ended, for `Agent::run` to decide what comes next.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Served {
    /// The connection went away: reconnect. How its pump ended, when it got to one: what the way to
    /// the server weighs (`crate::entry`).
    Disconnected(Option<transport::LinkEnd>),
    /// The backend sent an `error` frame with a fatal code on the live connection (`replaced`, and
    /// the beta's `device_blocked` when an admin blocks the PC: it closes the socket right after any
    /// fatal frame). What follows is `crate::reconnect`'s decision.
    Refused {
        code: String,
        message: Option<String>,
    },
    /// The command channel closed: nothing can command this agent any more, so it stops.
    Stopped,
    /// The signaling relay has stopped, which only a bug can do: nothing could reach the backend
    /// any more, over this connection or any other, so reconnecting would be a pretence.
    RelayGone,
}

/// How a wait between signaling attempts ended (`Agent::wait_offline`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitEnd {
    /// Its time ran out: the next attempt.
    Elapsed,
    /// The owner asked to retry: the next attempt, now.
    Retry,
    /// The command channel closed: the agent stops.
    Stopped,
}

/// The refusal an `error` frame's code amounts to, with the backend's detail; `None` when the code
/// says retrying at the usual pace can help — a transient code, or one this build does not know,
/// which a newer backend may send (`afklink_protocol::errors`). `during` names what the agent was
/// waiting for or doing when the frame came, for the log.
fn refusal_of(
    code: &str,
    message: Option<String>,
    during: &str,
) -> Option<(Refusal, Option<String>)> {
    match Refusal::from_code(code) {
        Some(refusal) => {
            // not-a-key-name: the server's error code
            tracing::debug!(
                code,
                kind = refusal.kind(),
                during,
                "error frame with a fatal code: the usual reconnecting cannot help"
            );
            Some((refusal, message))
        }
        None => {
            // not-a-key-name: the server's error code
            tracing::warn!(
                code,
                message = message.as_deref().unwrap_or("-"),
                known = afklink_protocol::error_severity(code).is_some(),
                during,
                "the backend refused this attempt with a transient or unknown code: retrying at the \
                 usual pace"
            );
            None
        }
    }
}

/// Reads the PC's hardware fingerprint for `agent_hello.hw` (the invite-only beta):
/// blocking — the registry, the firmware table, a disk's descriptor
/// — so the agent runs it once, on a blocking thread, as it starts ([`Agent::with_hw_reader`];
/// both binaries give `afklink_hw::system`).
pub type HwReader = Arc<dyn Fn() -> Option<afklink_protocol::AgentHw> + Send + Sync>;

/// How long the first connection waits for the fingerprint before its hello goes without it. The
/// reads take milliseconds; a disk that does not answer must not keep the PC offline, and the next
/// connection's hello carries what comes later.
const HW_WAIT: Duration = Duration::from_secs(2);

/// Where the fingerprint for the hellos stands.
enum HwState {
    /// `hello.hw` is what every hello says: no reader was given (the default, and the tests'), or
    /// the reading is done.
    Settled,
    /// A reader to start when the agent runs.
    ToRead(HwReader),
    /// Reading on a blocking thread since `since`.
    Reading {
        task: tokio::task::JoinHandle<Option<afklink_protocol::AgentHw>>,
        since: Instant,
    },
}

/// A wait as the log says it: «15 min», or «4 s» under a minute (the tests' slow retry).
fn every(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 60 && s.is_multiple_of(60) {
        format!("{} min", s / 60)
    } else {
        format!("{s} s")
    }
}

/// The orchestrator. Create with [`Agent::new`], then `.run().await`.
pub struct Agent {
    config: Arc<Mutex<Config>>,
    identity: Arc<Identity>,
    /// Shared with each session's encode thread, which makes fresh capturers and encoders from
    /// these factories when the ones it has fail.
    backends: Arc<Backends>,
    state: Arc<Mutex<AgentState>>,
    /// Ended at the drop if the orchestrator ends with any still in it ([`LiveSessions`]).
    sessions: LiveSessions,
    /// A test's seam: a session start panics right before its registration.
    #[cfg(test)]
    panic_before_register: bool,
    pending: HashMap<String, Pending>,
    sess_ev_tx: mpsc::UnboundedSender<SessionSignal>,
    commands_rx: Option<mpsc::UnboundedReceiver<AgentCommand>>,
    sess_ev_rx: Option<mpsc::UnboundedReceiver<SessionSignal>>,
    /// See [`AgentEvent`].
    events: broadcast::Sender<AgentEvent>,
    /// The bench link shaper every peer's socket goes through, when the CLI was given a link flag.
    /// `None` everywhere else. See `afklink_transport::shaper`.
    link_shaper: Option<Arc<LinkShaper>>,
    /// Everything for the backend goes here, for the agent's whole life, whatever connection is
    /// current: the orchestrator's handlers, and each session's telemetry and event tasks. The
    /// signaling relay forwards it; see `crate::relay`.
    outbox: mpsc::UnboundedSender<AgentToServer>,
    /// Tells the relay which connection is current.
    links: mpsc::UnboundedSender<LinkChange>,
    /// Taken and spawned by [`Agent::run`].
    relay: Option<Relay>,
    /// The id of the last connection handed to the relay.
    link_id: u64,
    /// What `replaced` does: wait for the owner (the desktop app) or stop (the CLI).
    on_replaced: OnReplaced,
    /// How long the slow retry after a fatal refusal waits: [`reconnect::SLOW_RETRY`], shorter
    /// only in tests.
    slow_retry: Duration,
    /// The refusal last logged at error, until the backend accepts the agent again: the same code
    /// again is info, not a second error. See `note_refusal`.
    refusal_logged: Option<Refusal>,
    /// When this agent was created, for the log: how long the start took to learn the binding list.
    started: Instant,
    /// Told of each session's life as it happens, for a log file per session (the desktop app).
    /// `None` for the CLI. See `crate::session_log`.
    session_log: Option<Arc<dyn SessionLog>>,
    /// What each session captures, decided per session (`crate::game_access`); see
    /// [`AgentControl::set_game_only`]. Told of every change of the roles here
    /// ([`Agent::sync_game_roles`]).
    game_access: Arc<crate::game_access::GameAccess>,
    /// The game helper's launch, for every session's heartbeat; see
    /// [`AgentControl::set_game_launching`].
    helper_launch: Arc<crate::game::HelperLaunch>,
    /// The connection journal (`crate::journal`): the desktop app's. `None` for the CLI, which
    /// keeps none.
    journal: Option<Arc<crate::journal::Journal>>,
    /// Who the journal has a «Отклонено: ПК на паузе» for in the current pause: one entry per
    /// person per pause, however often their viewer retries. Emptied when a pause starts and when
    /// it ends.
    paused_journaled: std::collections::HashSet<i64>,
    /// Whether the viewer's input reaches the window in front: each session's heartbeat polls it,
    /// and the window's «Управление не доходит» highlight follows (`crate::input_reach`).
    reach: Arc<crate::input_reach::ReachMonitor>,
    /// The signaling upgrade's `User-Agent` (`BuildInfo::user_agent`); `None` sends none.
    user_agent: Option<String>,
    /// What every `agent_hello` says beyond the device: the build, this process's boot id, how the
    /// previous process ended (`crate::run_state`) — and the PC's hardware fingerprint once it is
    /// read ([`HwState`]). Empty: the hello of older builds.
    hello: transport::HelloInfo,
    /// The fingerprint's reading for `hello.hw`: [`Agent::with_hw_reader`].
    hw: HwState,
    /// How long the first connection waits for it: [`HW_WAIT`], shorter only in tests.
    hw_wait: Duration,
    /// The PC's clipboard, for the sessions' clipboard sync (`crate::clipboard`). `None`: the PC
    /// says `unavailable` to a viewer that asks (the CLI's bench, tests).
    clipboard: Option<Arc<dyn crate::clipboard::ClipboardBackend>>,
    /// The goodbye's handle on each connection, and its hold on reconnecting (`crate::goodbye`);
    /// shared with [`AgentControl`].
    goodbyes: Arc<crate::goodbye::Goodbyes>,
    /// What happened on the PC outside sessions, waiting for a connection (`crate::agent_events`):
    /// sent on every connection once its handshake is done. `None`: no events are sent.
    event_queue: Option<Arc<crate::agent_events::EventQueue>>,
    /// The serving connection's health (when the backend was last heard from, its silence limit),
    /// for the event queue's confirmations; `None` while none is served.
    link_health: Option<transport::LinkHealth>,
    /// The orchestrator's current step and since when (`crate::step_watch`), for a watcher outside
    /// the runtime ([`Agent::step_watch`]).
    steps: Arc<crate::step_watch::StepWatch>,
    /// Which way to the server each attempt takes — the configured address or the RU entry — and
    /// what each attempt's end counts as (`crate::entry`). In memory unless the binary gives one that
    /// remembers ([`Agent::with_entry`]).
    entry: Arc<crate::entry::Entry>,
    /// The signaling connection's time limits: production's, shorter only in tests.
    signaling_limits: transport::signaling::Limits,
    /// Draws each wait of the ordinary backoff from zero up to its value (`crate::reconnect`).
    jitter: reconnect::Jitter,
    /// The accounts whose pairing request was approved on this PC and whose `binding_added` has not
    /// come yet, with the request and when: one that turns up only in a later `agent_ready` (the link
    /// broke in between) is this PC's own «Разрешить», not access given elsewhere. An entry
    /// goes with its `binding_added`, with a `pair_cancelled` of its request (the server did not take
    /// the approval), with a decline of the same account, and after [`APPROVED_HERE_FOR`].
    approved_here: HashMap<i64, ApprovedHere>,
    /// The binding list the previous run heard last (the desktop app's access cache), which the
    /// first list of this run is compared with: access given or taken away while the app was not
    /// running is journaled and announced as after a reconnect. `None`: the CLI, or nothing
    /// kept; taken by the first handshake.
    last_known_bindings: Option<Vec<BindingInfo>>,
    /// One pause write to config.json at a time ([`Agent::save_pause`]).
    pause_writes: Arc<Mutex<()>>,
    /// The last pause write handed to the blocking pool, for the tests to wait for.
    pause_save: Option<tokio::task::JoinHandle<()>>,
    /// Session teardowns running on their own threads (`crate::offload::detach`), for the exit to
    /// wait for, bounded ([`EXIT_TEARDOWN_WAIT`]). Finished ones are let go as new ones come.
    /// Shared with the sessions' event tasks, which hand the input's close off at a peer's end
    /// ([`keep_teardown`]); the lock is held only to push, prune or copy, never across a wait.
    teardowns: Teardowns,
    /// How long a session's start waits for its blocking steps together — the encoder, the
    /// capture's start, the input's opening (`crate::offload::START_LIMIT`; shorter in tests).
    setup_limit: Duration,
    /// A new session's start is refused at once when this many jobs are stuck on the input
    /// driver or past their error bound ([`START_REFUSE_STUCK`]; changed in tests).
    start_refuse_stuck: usize,
}

/// The session teardowns running on their own threads (`crate::offload::detach`).
type Teardowns = Arc<Mutex<Vec<crate::offload::JobDone>>>;

/// Keep a teardown for the exit and the kill switch to see and wait for (bounded,
/// [`EXIT_TEARDOWN_WAIT`]); finished ones are let go here. The lock is held for the push only.
fn keep_teardown(teardowns: &Teardowns, job: crate::offload::JobDone) {
    let mut kept = lock(teardowns);
    kept.retain(|t| !t.is_done());
    kept.push(job);
}

/// The jobs that wait on the input driver's slot lock (`hid`): a stuck one of these past its error
/// bound counts toward [`START_REFUSE_STUCK`]; a stuck capture or encoder job does not.
const INPUT_JOBS: [&str; 4] = ["input-open", "input-end", "input-close", "release-all"];

/// A new session's start is refused at once, with `internal_error`, when the input driver's
/// openings still stuck (`offload::running("input-open")`) and the input jobs past their error
/// bound ([`INPUT_JOBS`], `offload::abandoned_of`) together reach this.
///
/// Three. Each stuck opening is a thread blocked on the driver's slot lock, and each cost its viewer
/// the whole start limit before failing. One may be a slow driver that comes back (it is allowed
/// another try); two in a row, or one stuck past its 30 s error bound (it counts twice), mean
/// something holds the lock and does not let go — every further start would only wait its ten
/// seconds for the same failure and leave one more thread behind. Refusing at once says so in the
/// log and to the viewer; restarting the app frees the lock.
const START_REFUSE_STUCK: usize = 3;

/// How often a serving connection looks at the event queue: what is now known taken leaves it
/// (`agent_events::EventQueue::confirm`), and what the hour's budget held back may go.
const EVENTS_TICK: Duration = Duration::from_secs(5);

impl Agent {
    pub fn new(
        config: Config,
        identity: Arc<Identity>,
        backends: Backends,
    ) -> (Agent, AgentControl) {
        // The «Управление не доходит» highlight outlives a restart: the window shows it until the
        // driver is installed or a session's input gets through (`crate::input_reach`).
        if config.input_not_reaching {
            tracing::debug!(
                "the window's «Управление не доходит» highlight carries over from config.json \
                 (controls did not reach an administrator's window without the driver)"
            );
        }
        // The kill switch's pause outlives a restart and an update: in force before the first
        // connection, so no session request of this run can be accepted until the owner resumes.
        if config.paused {
            tracing::warn!(
                "connections paused on this PC (carried over from config.json: «Приостановить \
                 доступ» was pressed and not resumed): every session request is refused \
                 (paused_on_pc) until the owner presses «Возобновить»"
            );
        } else {
            tracing::debug!("connections not paused at start (config.json)");
        }
        let state = Arc::new(Mutex::new(AgentState {
            input_not_reaching: config.input_not_reaching,
            paused: config.paused,
            ..AgentState::default()
        }));
        // Logs the settings; each session's mode is decided when it starts.
        let game_access = Arc::new(crate::game_access::GameAccess::new(
            crate::game_access::GamePolicy::from_config(&config),
        ));
        let helper_launch = Arc::new(crate::game::HelperLaunch::new());
        // Until a binary gives one that remembers (`with_entry`): the same rules, for this run only.
        let entry = Arc::new(crate::entry::Entry::in_memory(&config.server_url));
        let config = Arc::new(Mutex::new(config));
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (sess_ev_tx, sess_ev_rx) = mpsc::unbounded_channel();
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        let (outbox, outbox_rx) = mpsc::unbounded_channel();
        let (links, links_rx) = mpsc::unbounded_channel();
        let goodbyes = crate::goodbye::Goodbyes::new();

        let control = AgentControl {
            state: state.clone(),
            commands: cmd_tx,
            config: config.clone(),
            events: events.clone(),
            game_access: game_access.clone(),
            helper_launch: helper_launch.clone(),
            goodbyes: goodbyes.clone(),
        };

        let reach = Arc::new(crate::input_reach::ReachMonitor::new(
            backends.injector.clone(),
            state.clone(),
            config.clone(),
        ));
        let agent = Agent {
            config,
            identity,
            backends: Arc::new(backends),
            state,
            sessions: LiveSessions::default(),
            #[cfg(test)]
            panic_before_register: false,
            pending: HashMap::new(),
            sess_ev_tx,
            commands_rx: Some(cmd_rx),
            sess_ev_rx: Some(sess_ev_rx),
            events,
            link_shaper: None,
            outbox,
            links,
            relay: Some(Relay::new(outbox_rx, links_rx)),
            link_id: 0,
            on_replaced: OnReplaced::default(),
            slow_retry: reconnect::SLOW_RETRY,
            refusal_logged: None,
            started: Instant::now(),
            session_log: None,
            game_access,
            helper_launch,
            journal: None,
            paused_journaled: std::collections::HashSet::new(),
            reach,
            user_agent: None,
            hello: transport::HelloInfo::default(),
            hw: HwState::Settled,
            hw_wait: HW_WAIT,
            clipboard: None,
            goodbyes,
            event_queue: None,
            link_health: None,
            steps: crate::step_watch::StepWatch::new(),
            entry,
            signaling_limits: transport::signaling::LIMITS,
            jitter: reconnect::Jitter::from_os(),
            approved_here: HashMap::new(),
            last_known_bindings: None,
            pause_writes: Arc::new(Mutex::new(())),
            pause_save: None,
            teardowns: Teardowns::default(),
            setup_limit: crate::offload::START_LIMIT,
            // The counts it is compared with are process-wide, and the tests run in one process,
            // some with jobs stuck on purpose: there it is off unless a test sets it.
            start_refuse_stuck: if cfg!(test) {
                usize::MAX
            } else {
                START_REFUSE_STUCK
            },
        };
        (agent, control)
    }

    /// Compare the first binding list of this run with `bindings`, the one the previous run heard
    /// last (the desktop app's access cache): who got access while the app was not running is
    /// journaled and announced, who lost it journaled — as after a reconnect.
    #[must_use]
    pub fn with_last_known_bindings(mut self, bindings: Vec<BindingInfo>) -> Self {
        tracing::debug!(
            bindings = bindings.len(),
            "access: the first list of this run is compared with the previous run's last"
        );
        self.last_known_bindings = Some(bindings);
        self
    }

    /// Another source for the backoff's waits: none (the tests that time the old waits) or a seeded
    /// one.
    #[cfg(test)]
    fn with_jitter(mut self, jitter: reconnect::Jitter) -> Self {
        self.jitter = jitter;
        self
    }

    /// Choose the way to the server through `entry` (`crate::entry`): the app's and the CLI's, which
    /// remembers the RU entry across starts and which the app's HTTP (the updater, «Отправить логи»)
    /// reads too. Built for this agent's `server_url`; one built for another is still used, and said.
    #[must_use]
    pub fn with_entry(mut self, entry: Arc<crate::entry::Entry>) -> Self {
        let server_url = lock(&self.config).server_url.clone();
        let primary = entry.url_of(crate::entry::Endpoint::Primary).to_string();
        if primary == server_url {
            tracing::debug!(
                %primary,
                alternative = entry.has_alternative(),
                preferred = entry.preferred().as_str(),
                "signaling: the way to the server is chosen by the shared entry"
            );
        } else {
            tracing::warn!(
                %primary,
                server = %server_url,
                "signaling: the shared entry was built for another server address; its addresses \
                 are used"
            );
        }
        self.entry = entry;
        self
    }

    /// Shorter signaling limits, so a test need not wait for the real ones.
    #[cfg(test)]
    fn with_signaling_limits(mut self, limits: transport::signaling::Limits) -> Self {
        self.signaling_limits = limits;
        self
    }

    /// Send the events in `queue` (`crate::agent_events`) on every connection once its handshake is
    /// done (`agent_ready`), and whatever is queued while one is up.
    #[must_use]
    pub fn with_event_queue(mut self, queue: Arc<crate::agent_events::EventQueue>) -> Self {
        tracing::debug!(
            waiting = queue.pending(),
            "agent events: sent on every connection after its handshake"
        );
        self.event_queue = Some(queue);
        self
    }

    /// Send what the event queue has for connection `link` (`why`: what prompted it, for the log).
    /// Only ever called while that connection is served — after its `agent_ready`.
    fn send_agent_events(
        &self,
        link: u64,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
        why: &'static str,
    ) {
        let Some(queue) = &self.event_queue else {
            return;
        };
        // Without a word on the connection's health (never, while it is served), the long limit:
        // the later confirmation, never the earlier.
        let limit = self.link_health.as_ref().map_or(
            transport::signaling::LEGACY_SILENCE_LIMIT,
            transport::LinkHealth::silence_limit,
        );
        let due = queue.due(link, Instant::now(), crate::agent_events::now_ms(), limit);
        if due.is_empty() {
            tracing::trace!(link, why, "agent events: nothing to send");
            return;
        }
        let n = due.len();
        let mut handed = 0usize;
        for event in due {
            if send_to_backend(outgoing, AgentToServer::AgentEvent(event)) {
                handed += 1;
            }
        }
        tracing::debug!(
            link,
            why,
            due = n,
            handed,
            "agent events handed to the connection"
        );
    }

    /// The serving connection's look at the event queue (every [`EVENTS_TICK`]): what is now known
    /// taken leaves it — the connection's own word on when the backend was last heard from and its
    /// silence limit decides — and what waits may go.
    fn tick_agent_events(&self, outgoing: &mpsc::UnboundedSender<AgentToServer>) {
        let Some(queue) = &self.event_queue else {
            return;
        };
        match &self.link_health {
            Some(health) => {
                queue.confirm(
                    self.link_id,
                    Instant::now(),
                    crate::agent_events::LinkSeen {
                        up: health.is_up(),
                        last_heard: health.last_heard(),
                        silence_limit: health.silence_limit(),
                    },
                );
            }
            None => tracing::debug!(
                link = self.link_id,
                "agent events: no word on the connection's health; nothing confirmed this tick"
            ),
        }
        if queue.pending() > 0 {
            self.send_agent_events(self.link_id, outgoing, "tick");
        }
    }

    /// Send `user_agent` with every signaling upgrade (`BuildInfo::user_agent`): the backend keeps it
    /// per device.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        tracing::debug!(%user_agent, "signaling: the upgrade's User-Agent");
        self.user_agent = Some(user_agent);
        self
    }

    /// Say `hello` in every `agent_hello` (contract v2): the build, this process's boot id and how
    /// the previous one ended — `crate::run_state::RunState::hello`. The server stores the build on
    /// each session and dates a crash by the last exit.
    #[must_use]
    pub fn with_hello(mut self, hello: transport::HelloInfo) -> Self {
        tracing::debug!(
            build = hello.build.as_ref().map_or("-", |b| b.version.as_str()),
            commit = hello
                .build
                .as_ref()
                .and_then(|b| b.commit.as_deref())
                .unwrap_or("-"),
            boot_id = hello.boot_id.as_deref().unwrap_or("-"),
            last_exit = hello.last_exit.map_or("-", |e| e.kind.as_str()),
            last_exit_at = ?hello.last_exit.and_then(|e| e.at),
            hw_parts = hello.hw.as_ref().map_or(0, |h| h.parts),
            "signaling: what agent_hello says of this build and process"
        );
        self.hello = hello;
        self
    }

    /// Read the PC's hardware fingerprint with `reader` once, on a blocking thread as the agent
    /// starts, and send it in every `agent_hello` from then on (the invite-only beta; `afklink_hw`).
    /// The first connection waits for it at most [`HW_WAIT`]; a hello that goes without it says so in
    /// the log, and the next one carries it. Without a reader every hello carries what
    /// [`Self::with_hello`] gave — no fingerprint, in production.
    #[must_use]
    pub fn with_hw_reader(mut self, reader: HwReader) -> Self {
        tracing::debug!("hw: the fingerprint is read once as the agent starts, for every hello");
        self.hw = HwState::ToRead(reader);
        self
    }

    /// Start the fingerprint's reading, if a reader was given: on a blocking thread, off the
    /// runtime's workers.
    fn start_hw_read(&mut self) {
        self.hw = match std::mem::replace(&mut self.hw, HwState::Settled) {
            HwState::ToRead(reader) => {
                tracing::debug!("hw: reading the fingerprint on a blocking thread");
                HwState::Reading {
                    task: tokio::task::spawn_blocking(move || reader()),
                    since: Instant::now(),
                }
            }
            other => other,
        };
    }

    /// Put the fingerprint into the hello once it is read: waited for until [`HW_WAIT`] after the
    /// reading began — the first connection's wait — and not at all after that.
    async fn settle_hw(&mut self) {
        let state = std::mem::replace(&mut self.hw, HwState::Settled);
        let HwState::Reading { mut task, since } = state else {
            self.hw = state;
            return;
        };
        let left = self.hw_wait.saturating_sub(since.elapsed());
        match tokio::time::timeout(left, &mut task).await {
            Ok(Ok(hw)) => {
                tracing::debug!(
                    parts = hw.as_ref().map_or(0, |h| h.parts),
                    vm = hw.as_ref().is_some_and(|h| h.vm),
                    took_ms = since.elapsed().as_millis() as u64,
                    "hw: the fingerprint is read; every hello from now on {}",
                    if hw.is_some() {
                        "carries it"
                    } else {
                        "goes without it (no part of the PC could be read)"
                    }
                );
                self.hello.hw = hw;
            }
            Ok(Err(e)) => tracing::warn!(
                "hw: the thread reading the fingerprint failed ({e}): every hello goes without it"
            ),
            Err(_) => {
                tracing::debug!(
                    waited_ms = since.elapsed().as_millis() as u64,
                    limit_ms = self.hw_wait.as_millis() as u64,
                    "hw: the fingerprint is not read yet: this hello goes without it, a later one \
                     carries it"
                );
                self.hw = HwState::Reading { task, since };
            }
        }
    }

    /// Sync the clipboard through `clipboard` for viewers that turn it on (`crate::clipboard`).
    /// Without it a viewer that asks is told the PC's clipboard is unavailable.
    #[must_use]
    pub fn with_clipboard(
        mut self,
        clipboard: Arc<dyn crate::clipboard::ClipboardBackend>,
    ) -> Self {
        tracing::debug!("clipboard sync: available to viewers that turn it on");
        self.clipboard = Some(clipboard);
        self
    }

    /// The orchestrator's current step, for a watcher outside the runtime to name one that does not
    /// end (`crate::step_watch`; the desktop app's stall watch). Taken before [`Agent::run`].
    pub fn step_watch(&self) -> Arc<crate::step_watch::StepWatch> {
        Arc::clone(&self.steps)
    }

    /// Keep the connection journal in `journal` (`crate::journal`): sessions whose video came up,
    /// access given and taken away, attempts refused while paused. Without it nothing is kept, which
    /// is the CLI's case.
    #[must_use]
    pub fn with_journal(mut self, journal: Arc<crate::journal::Journal>) -> Self {
        tracing::debug!("connection journal: sessions, access and attempts on pause are kept");
        self.journal = Some(journal);
        self
    }

    /// A session's end for the journal, with `reason`, the agent's own: what every `SessionEnded`
    /// carries.
    fn journal_end(&self, session_id: &str, reason: &str) {
        if let Some(journal) = &self.journal {
            journal.session_ended(session_id, reason, crate::journal::now_ms());
        }
    }

    /// The backend's end of a session for the journal, with its own reason — the viewer's, passed
    /// on — which the `SessionEnded` that follows only calls `server_ended`. It closes a running
    /// session's entry, or replaces the reason of one its peer's end closed a moment before
    /// ([`Self::journal_peer_end`]).
    fn journal_server_end(&self, session_id: &str, reason: &str) {
        if let Some(journal) = &self.journal {
            journal.session_ended_by_server(session_id, reason, crate::journal::now_ms());
        }
    }

    /// A session's peer ended as `peer_closed` (`end`), for the journal: its entry is closed now —
    /// as the viewer's ordinary end (`journal::VIEWER_LEFT`) when the viewer said goodbye, else as
    /// `peer_closed` («Связь потеряна») — and the backend's reason, which follows the viewer's
    /// goodbye by a tenth of a second when the viewer sent one, takes its place if it comes within
    /// `journal::SERVER_REASON_WAIT_MS`. Nothing of the session's teardown waits for it.
    fn journal_peer_end(&self, session_id: &str, end: transport::PeerEnd) {
        let Some(journal) = &self.journal else {
            return;
        };
        let reason = if end.by_viewer() {
            crate::journal::VIEWER_LEFT
        } else {
            end.reason()
        };
        tracing::debug!(
            session = session_id,
            ?end,
            by_viewer = end.by_viewer(),
            reason,
            "connection journal: the peer ended by itself; its entry closes now and is open to the \
             backend's reason"
        );
        journal.session_ended_by_peer(session_id, reason, crate::journal::now_ms());
    }

    /// An event about a person for the journal: `first_name`/`username` as known, else the last name
    /// the journal has for them, else `#id`.
    fn journal_event(
        &self,
        kind: crate::journal::Kind,
        telegram_user_id: i64,
        first_name: Option<&str>,
        username: Option<&str>,
    ) {
        let Some(journal) = &self.journal else {
            return;
        };
        let known = (first_name.is_none() && username.is_none())
            .then(|| journal.known_name(telegram_user_id))
            .flatten();
        let (name, username) = match &known {
            Some((name, username)) => (name.clone(), username.clone()),
            None => (
                crate::person_name(telegram_user_id, first_name, username).text,
                username.map(str::to_string),
            ),
        };
        tracing::debug!(
            kind = kind.as_str(),
            telegram_user_id,
            name_from = if known.is_some() {
                "the journal's last entry"
            } else {
                "the binding or the request"
            },
            "connection journal: event"
        );
        journal.event(
            kind,
            crate::journal::Person {
                user: telegram_user_id,
                name: &name,
                username: username.as_deref(),
            },
            crate::journal::now_ms(),
        );
    }

    /// A guest the owner let in by his invite (`binding_added.via: invite`): the person at the PC
    /// hears of it at once — [`AgentEvent::GuestInvited`], which the desktop app shows as the toast
    /// «Новый гость: {user}» — unless [`invited_guest_toast_withheld`] says why not. `listed`: the
    /// person was in the list before this `binding_added`. Every outcome is logged, the name never.
    fn announce_invited_guest(
        &self,
        telegram_user_id: i64,
        role: Option<afklink_protocol::BindingRole>,
        listed: bool,
        name: crate::PersonName,
    ) {
        let listeners = self.events.receiver_count();
        let why = match invited_guest_toast_withheld(role, listed) {
            Some(why) => Some(why),
            None if listeners == 0 => {
                Some("nobody listens for it (no desktop app): the journal has it")
            }
            None => None,
        };
        if let Some(why) = why {
            tracing::debug!(
                telegram_user_id,
                role = role.map_or("-", afklink_protocol::BindingRole::as_str),
                listed,
                listeners,
                "new-guest toast not shown: {why}"
            );
            return;
        }
        tracing::debug!(
            telegram_user_id,
            name_source = name.source.as_str(),
            listeners,
            "new-guest toast due: the owner let a guest in by his invite, and the person at the PC \
             is told at once"
        );
        self.emit(AgentEvent::GuestInvited {
            telegram_user_id,
            name,
        });
    }

    /// The owner answered `request_id` of `uid` on this PC: an approval is remembered
    /// ([`Agent::approved_here`]), a decline forgets an earlier approval of the same account. Old
    /// approvals go first ([`APPROVED_HERE_FOR`]). Each change said at `debug`.
    fn note_answer_here(&mut self, uid: i64, request_id: &str, accept: bool, now: Instant) {
        self.forget_old_approvals(now);
        if accept {
            self.approved_here.insert(
                uid,
                ApprovedHere {
                    request_id: request_id.to_string(),
                    until: now + APPROVED_HERE_FOR,
                },
            );
            tracing::debug!(
                telegram_user_id = uid,
                %request_id,
                keep_s = APPROVED_HERE_FOR.as_secs(),
                "pairing: approved on this PC; remembered until its binding is heard of"
            );
        } else if self.approved_here.remove(&uid).is_some() {
            tracing::debug!(
                telegram_user_id = uid,
                %request_id,
                "pairing: declined on this PC; an earlier approval of the account no longer counts"
            );
        }
    }

    /// Approvals on this PC past their time ([`ApprovedHere::until`]: [`APPROVED_HERE_FOR`], or the
    /// owner's deadline for one he is asked about) are forgotten, each said.
    fn forget_old_approvals(&mut self, now: Instant) {
        self.approved_here.retain(|uid, a| {
            let keep = now < a.until;
            if !keep {
                tracing::debug!(
                    telegram_user_id = *uid,
                    request_id = %a.request_id,
                    "pairing: an approval on this PC whose binding was never heard of is forgotten \
                     (past the request's lifetime, or the owner's deadline)"
                );
            }
            keep
        });
    }

    /// `pc_allow`: the server holds a pairing approved on this PC for the owner, who may answer
    /// minutes later — past [`APPROVED_HERE_FOR`]. So the approval is kept while he decides (if his
    /// «Разрешить» comes while this PC is away, the next list has the newcomer, and that is this
    /// PC's «Разрешить», not an invite — no «Новый гость»):
    ///
    /// - `pending`: kept until his deadline and the server's sweep after it; one this run does not
    ///   know — approved before a restart, re-sent after `agent_ready` — is taken as approved here;
    /// - `confirmed`: kept [`APPROVED_HERE_FOR`] more, for `binding_added` or the next list — unless
    ///   the binding is in the list already (its `binding_added` came first);
    /// - anything else: forgotten — no binding is coming from it.
    ///
    /// Each step said at debug.
    fn hold_approval_for_owner(
        &mut self,
        uid: i64,
        request_id: Option<&str>,
        state: afklink_protocol::OwnerRequestState,
        expires_at: Option<i64>,
        now_ms: i64,
    ) {
        use afklink_protocol::OwnerRequestState as S;
        let now = Instant::now();
        let ms = |v: i64| Duration::from_millis(u64::try_from(v).unwrap_or(0));
        let keep_for = match state {
            S::Pending => Some(
                ms(expires_at.map_or(0, |at| at.saturating_sub(now_ms)))
                    + ms(crate::owner_request::EXPIRY_GRACE_MS),
            ),
            S::Confirmed if is_bound(&lock(&self.state).bindings, uid) => {
                tracing::debug!(
                    telegram_user_id = uid,
                    "pairing: the owner allowed the approval on this PC (pc_allow), and its binding \
                     is heard of already: nothing to keep"
                );
                None
            }
            S::Confirmed => Some(APPROVED_HERE_FOR),
            _ => None,
        };
        let Some(keep_for) = keep_for else {
            if let Some(a) = self.approved_here.remove(&uid) {
                tracing::debug!(
                    telegram_user_id = uid,
                    request_id = %a.request_id,
                    state = state.as_str(),
                    "pairing: the approval on this PC is forgotten (pc_allow): {}",
                    if state == S::Confirmed {
                        "its binding is heard of"
                    } else {
                        "the owner did not allow it, so no binding is coming from it"
                    }
                );
            }
            return;
        };
        let known = self.approved_here.get(&uid).map(|a| a.request_id.clone());
        let request_id = request_id
            .map(str::to_string)
            .or_else(|| known.clone())
            .unwrap_or_default();
        tracing::debug!(
            telegram_user_id = uid,
            %request_id,
            state = state.as_str(),
            keep_s = keep_for.as_secs(),
            known = known.is_some(),
            "pairing: the approval on this PC {} (pc_allow){}",
            if state == S::Pending {
                "waits for the owner's answer"
            } else {
                "is allowed by the owner"
            },
            if known.is_some() {
                "; kept that long"
            } else {
                "; not remembered this run (approved before a restart): taken as approved here"
            }
        );
        self.approved_here.insert(
            uid,
            ApprovedHere {
                request_id,
                until: now + keep_for,
            },
        );
    }

    /// What changed in the binding list while this agent was away (`against`: what the new list was
    /// compared with), as `binding_removed` and `binding_added` would have said it: whoever is
    /// gone, «Доступ отозван» in the journal; whoever is new —
    ///
    /// - approved on this PC this run, its `binding_added` lost to the break: «Доступ выдан», as it
    ///   would have been;
    /// - anyone else: let in without this PC, which only the owner's invite does —
    ///   «Доступ по приглашению» and the toast «Новый гость» ([`Self::announce_invited_guest`]);
    /// - but an owner nobody here approved: «Доступ выдан» and a warning — an invite makes a guest,
    ///   and «Новый гость» would be untrue.
    ///
    /// Every case is logged with why; the names never.
    fn note_changes_while_away(&mut self, against: &str, changes: BindingChanges) {
        for b in &changes.gone {
            tracing::debug!(
                telegram_user_id = b.telegram_user_id,
                against,
                "a binding is gone from the list (removed while away): «Доступ отозван» in the \
                 journal"
            );
            self.journal_event(
                crate::journal::Kind::Revoked,
                b.telegram_user_id,
                b.first_name.as_deref(),
                b.username.as_deref(),
            );
        }
        let mut invited = 0usize;
        self.forget_old_approvals(Instant::now());
        for b in &changes.added {
            let uid = b.telegram_user_id;
            let role = b.role.map_or("-", afklink_protocol::BindingRole::as_str);
            if self.approved_here.remove(&uid).is_some() {
                tracing::debug!(
                    telegram_user_id = uid,
                    role,
                    against,
                    "a binding is new in the list, approved on this PC (its binding_added was lost \
                     to the break): «Доступ выдан» in the journal"
                );
                self.journal_event(
                    crate::journal::Kind::Granted,
                    uid,
                    b.first_name.as_deref(),
                    b.username.as_deref(),
                );
                continue;
            }
            if b.role == Some(afklink_protocol::BindingRole::Owner) {
                tracing::warn!(
                    telegram_user_id = uid,
                    against,
                    "an owner is new in the list, approved neither on this PC nor by an invite (an \
                     invite makes a guest): «Доступ выдан» in the journal, no new-guest toast"
                );
                self.journal_event(
                    crate::journal::Kind::Granted,
                    uid,
                    b.first_name.as_deref(),
                    b.username.as_deref(),
                );
                continue;
            }
            invited += 1;
            tracing::info!(
                telegram_user_id = uid,
                role,
                against,
                "access given while this agent was away, not on this PC: the owner's invite, the \
                 only way in without it — «Доступ по приглашению» in the journal and the new-guest \
                 toast"
            );
            self.journal_event(
                crate::journal::Kind::Invited,
                uid,
                b.first_name.as_deref(),
                b.username.as_deref(),
            );
            // As `binding_added` by invite names the guest: «Имя (@username)», cleaned.
            let name = crate::person_name::requester_name(
                uid,
                b.first_name.as_deref(),
                b.username.as_deref(),
            );
            self.announce_invited_guest(uid, b.role, false, name);
        }
        tracing::debug!(
            against,
            gone = changes.gone.len(),
            added = changes.added.len(),
            invited,
            "access: the new list compared with the earlier one"
        );
    }

    /// Tell `log` of every session's life as it happens (`crate::session_log`): the desktop app's
    /// log file per session. Without it nothing is told, which is the CLI's case.
    #[must_use]
    pub fn with_session_log(mut self, log: Arc<dyn SessionLog>) -> Self {
        tracing::debug!("session log: each session's start and end are told as they happen");
        self.session_log = Some(log);
        self
    }

    /// What `replaced` does to this agent; see [`OnReplaced`]. The desktop app keeps the default
    /// (wait for the owner's retry); the CLI stops.
    #[must_use]
    pub fn with_on_replaced(mut self, on_replaced: OnReplaced) -> Self {
        tracing::debug!(?on_replaced, "replaced by another process: policy set");
        self.on_replaced = on_replaced;
        self
    }

    /// A shorter slow retry, so a test need not wait a quarter of an hour.
    #[cfg(test)]
    fn with_slow_retry(mut self, slow_retry: Duration) -> Self {
        self.slow_retry = slow_retry;
        self
    }

    /// A shorter wait for the fingerprint, so a test of a slow reading need not wait [`HW_WAIT`].
    #[cfg(test)]
    fn with_hw_wait(mut self, wait: Duration) -> Self {
        self.hw_wait = wait;
        self
    }

    /// Put every peer's socket behind `shaper` (the CLI's bench link flags). `None` leaves the
    /// sockets alone, which is what every other caller wants.
    #[must_use]
    pub fn with_link_shaper(mut self, shaper: Option<Arc<LinkShaper>>) -> Self {
        tracing::debug!(
            shaped = shaper.is_some(),
            "peer sockets: {}",
            if shaper.is_some() {
                "behind the bench link shaper"
            } else {
                "direct"
            }
        );
        self.link_shaper = shaper;
        self
    }

    /// Tell whoever listens. Nobody listening is the desktop app's ordinary case.
    ///
    /// A session's start and end go to the session log first, synchronously (`crate::session_log`):
    /// every place a session starts or ends announces it here, so this is the one place that cannot
    /// forget to tell it.
    fn emit(&self, event: AgentEvent) {
        match &event {
            AgentEvent::SessionStarted { session_id, .. } => {
                if let Some(log) = &self.session_log {
                    log.started(session_id);
                }
            }
            AgentEvent::SessionEnded { session_id, reason } => {
                self.log_ended(session_id, reason);
                // The journal keeps the first end of a session whose video came up; an end the
                // backend sent was given to it with the backend's reason before this one.
                self.journal_end(session_id, reason);
            }
            _ => {}
        }
        if let Err(broadcast::error::SendError(event)) = self.events.send(event) {
            tracing::trace!(?event, "agent event: no subscriber");
        }
    }

    /// The session log's end for `session_id` (`crate::session_log`). Called by [`Self::emit`] for
    /// every `SessionEnded`, and directly where a request that never became a session is dropped
    /// without one.
    fn log_ended(&self, session_id: &str, reason: &str) {
        if let Some(log) = &self.session_log {
            log.ended(session_id, reason);
        }
    }

    /// Run until stopped: connect, serve until the connection ends, wait, connect again.
    ///
    /// How long each wait is — the ordinary backoff, a slow retry, or until the owner asks — depends
    /// on how the attempt ended; see `crate::reconnect`. Returns `Ok` when nothing can command the
    /// agent any more, and an error when it cannot go on: the relay is gone, or `replaced` under
    /// [`OnReplaced::Stop`] (the CLI).
    pub async fn run(mut self) -> Result<()> {
        let mut commands_rx = self.commands_rx.take().expect("commands_rx");
        let mut sess_ev_rx = self.sess_ev_rx.take().expect("sess_ev_rx");
        // One relay for the agent's whole life: sessions outlive connections. See `crate::relay`.
        let relay = self.relay.take().expect("relay");
        tokio::spawn(relay.run());
        // The hardware fingerprint for the hellos, read once, beside the first connection's setup.
        self.start_hw_read();
        let outbox = self.outbox.clone();
        let mut backoff = reconnect::BACKOFF_FIRST;
        loop {
            // A goodbye holds the agent offline (`crate::goodbye`): said while it was connected, or
            // during the wait before this attempt. No attempt until the hold is lifted or runs out.
            if let Some(hold) = self.goodbyes.held() {
                let limit = hold.remaining(Instant::now());
                tracing::debug!(
                    reason = hold.reason.as_str(),
                    limit_ms = limit.as_millis() as u64,
                    "no signaling attempt while a goodbye holds the agent"
                );
                match self
                    .wait_offline(
                        Wait::Held(limit),
                        &mut commands_rx,
                        &mut sess_ev_rx,
                        &outbox,
                    )
                    .await
                {
                    WaitEnd::Stopped => {
                        self.sessions.ends_as_asked(NOTHING_TO_COMMAND);
                        return Ok(());
                    }
                    WaitEnd::Elapsed | WaitEnd::Retry => backoff = reconnect::BACKOFF_FIRST,
                }
                // Looked at again: a newer goodbye may hold it once more.
                continue;
            }
            // Which way this attempt takes: the configured address or the RU entry (`crate::entry`).
            let attempt = self.entry.next_attempt();
            let refusal = match self
                .connect_and_serve(&attempt, &mut commands_rx, &mut sess_ev_rx)
                .await
            {
                Ok(Served::Disconnected(end)) => {
                    let verdict = match &end {
                        Some(end) => crate::entry::classify_end(end),
                        None => crate::entry::Verdict {
                            weight: crate::entry::Weight::Neutral,
                            why: "it ended before it was served (a goodbye's hold)".into(),
                        },
                    };
                    self.entry.record(attempt.endpoint, &verdict);
                    // From the start only after a connection that proved stable; says why.
                    backoff = reconnect::after_disconnect(backoff, end.as_ref().map(|e| e.lived));
                    None
                }
                Ok(Served::Refused { code, message }) => {
                    self.entry.record(
                        attempt.endpoint,
                        &crate::entry::Verdict {
                            weight: crate::entry::Weight::Healthy { proven: false },
                            why: format!(
                                "the server refused this agent on the live connection ({code}): \
                                 the path works"
                            ),
                        },
                    );
                    refusal_of(&code, message, "a live connection")
                }
                // Said by `connect_and_serve`, which saw the channel close.
                Ok(Served::Stopped) => {
                    self.sessions.ends_as_asked(NOTHING_TO_COMMAND);
                    return Ok(());
                }
                Ok(Served::RelayGone) => {
                    anyhow::bail!("the signaling relay stopped: nothing can reach the backend")
                }
                Err(e) => {
                    self.entry.record(
                        attempt.endpoint,
                        &crate::entry::classify_failure(attempt.endpoint, &e),
                    );
                    match e
                        .chain()
                        .find_map(|c| c.downcast_ref::<transport::HandshakeRefused>())
                    {
                        Some(r) => refusal_of(&r.code, r.message.clone(), r.awaiting),
                        None => {
                            tracing::warn!(
                                endpoint = attempt.endpoint.as_str(),
                                "signaling session error: {e:#}"
                            );
                            None
                        }
                    }
                }
            };
            let was_connected = {
                let mut s = lock(&self.state);
                let was = std::mem::replace(&mut s.connected, false);
                // The backend drops the pairing code with the socket, and cannot tell this agent so;
                // a pending request it keeps for its grace window, and so does this agent. Only a
                // connection that was up had any.
                if was {
                    crate::pairing::connection_lost(&mut s, crate::journal::now_ms());
                }
                was
            };
            // Only a connection that was up can go down; a failed attempt changes nothing.
            if was_connected {
                self.emit(AgentEvent::SignalingDisconnected);
            }
            // The connection ended with a goodbye (or one came during the attempt): the hold, not
            // the backoff, decides when the next attempt is — at the top of the loop.
            if let Some(hold) = self.goodbyes.held() {
                tracing::debug!(
                    reason = hold.reason.as_str(),
                    was_connected,
                    refused = refusal.is_some(),
                    "signaling ended under a goodbye's hold: no reconnect until it is lifted"
                );
                backoff = reconnect::BACKOFF_FIRST;
                continue;
            }
            let next = reconnect::next(
                refusal.as_ref().map(|(r, _)| r),
                backoff,
                self.slow_retry,
                self.on_replaced,
            );
            let blocked = refusal.as_ref().is_some_and(|(r, _)| r.is_blocked());
            self.note_refusal(refusal, next);
            if blocked {
                self.end_for_block(&outbox);
            }
            let wait = match next {
                // The backoff's wait is drawn up to its value; `backoff` keeps the value itself,
                // which the wait's end doubles.
                Next::Wait(Wait::Backoff(cap)) => Wait::Backoff(self.jitter.full(cap)),
                Next::Wait(wait) => wait,
                Next::Stop => {
                    self.stop_after_replaced(&outbox).await;
                    self.sessions
                        .ends_as_asked("replaced: it stops by its own decision");
                    anyhow::bail!(
                        "the backend handed this device's connection to another process with the \
                         same identity ({}); this agent stops rather than take it back",
                        Refusal::Replaced.code()
                    );
                }
            };
            if let Wait::Backoff(d) = wait {
                tracing::info!(
                    wait_ms = d.as_millis() as u64,
                    backoff_ms = backoff.as_millis() as u64,
                    "reconnecting in {:.1}s (drawn up to the backoff)",
                    d.as_secs_f64()
                );
            }
            match self
                .wait_offline(wait, &mut commands_rx, &mut sess_ev_rx, &outbox)
                .await
            {
                WaitEnd::Stopped => {
                    self.sessions.ends_as_asked(NOTHING_TO_COMMAND);
                    return Ok(());
                }
                WaitEnd::Elapsed => {
                    if let Wait::Slow(waited) = wait {
                        let refused = lock(&self.state).refused.clone();
                        let code = refused
                            .as_ref()
                            .map_or_else(|| "-".to_string(), |r| r.code().to_string());
                        if refused.as_ref().is_some_and(Refusal::is_blocked) {
                            // Every quarter of an hour for as long as the block holds: a decision
                            // of the retry's, not an event.
                            // not-a-key-name: the server's error code
                            tracing::debug!(
                                %code,
                                waited_s = waited.as_secs(),
                                "device_blocked: slow retry — connecting again to see whether the \
                                 block was lifted"
                            );
                        } else {
                            // not-a-key-name: the server's error code
                            tracing::info!(
                                %code,
                                waited_s = waited.as_secs(),
                                "slow retry after a fatal refusal: connecting again"
                            );
                        }
                    }
                    backoff = match wait {
                        // The backoff's own value, not the wait drawn from it.
                        Wait::Backoff(_) => reconnect::next_backoff(backoff),
                        Wait::Slow(_) | Wait::UntilOwner | Wait::Held(_) => {
                            reconnect::BACKOFF_FIRST
                        }
                    };
                }
                WaitEnd::Retry => backoff = reconnect::BACKOFF_FIRST,
            }
        }
    }

    /// Put an attempt's refusal (or its absence) into [`AgentState::refused`] and the log, and tell
    /// subscribers.
    ///
    /// Error when a refusal begins — the first time the backend gives this code since it last
    /// accepted the agent — and info when it gives the same one again (after a slow retry, a Retry,
    /// or a network failure in between; the retry's own line said it was trying). `device_blocked`
    /// is an admin's decision, not a fault: info when it begins, debug on every slow retry that
    /// meets it again (`end_for_block` then ends what is still running). An attempt that
    /// ends without a refusal (the backend was not reached, say) clears the state, since the agent
    /// is back on the usual backoff, and says so at info. `message` is the backend's detail, for the
    /// log only.
    fn note_refusal(&mut self, refusal: Option<(Refusal, Option<String>)>, next: Next) {
        let previous = lock(&self.state).refused.clone();
        let Some((refusal, message)) = refusal else {
            if let Some(was) = previous {
                tracing::info!(
                    was = was.code(),
                    "this attempt ended without a refusal (it failed some other way): back to the \
                     usual reconnecting until the backend answers"
                );
                lock(&self.state).refused = None;
            }
            return;
        };
        let message = message.as_deref().unwrap_or("-");
        let code = refusal.code();
        let live = self.sessions.len();
        if self.refusal_logged.as_ref() == Some(&refusal) {
            if refusal.is_blocked() {
                // Said at info once, when the block began; each slow retry it meets is a decision.
                // not-a-key-name: the server's error code
                tracing::debug!(
                    code,
                    message,
                    next = ?next,
                    "device_blocked: the PC is still blocked; the next slow retry in {}",
                    every(self.slow_retry)
                );
            } else {
                // not-a-key-name: the server's error code
                tracing::info!(
                    code,
                    message,
                    next = ?next,
                    "the backend still refuses this agent"
                );
            }
        } else {
            match (&refusal, next) {
                // An admin's decision, not a fault: info, once.
                // not-a-key-name: the server's error code
                (r @ Refusal::Fatal { .. }, _) if r.is_blocked() => tracing::info!(
                    code,
                    message,
                    live,
                    retry_in_s = self.slow_retry.as_secs(),
                    "device_blocked: refused by the server, slow retry every {} — an admin blocked \
                     this PC: reconnects at the usual pace stopped, the window says «ПК заблокирован» \
                     with no Retry, and a lifted block brings the PC back by itself",
                    every(self.slow_retry)
                ),
                // not-a-key-name: the server's error code
                (Refusal::Replaced, Next::Stop) => tracing::error!(
                    code,
                    message,
                    live,
                    "another process with this device's identity connected, and the backend keeps \
                     only the latest connection: this agent stops (taking the connection back would \
                     start the two taking it from each other forever)"
                ),
                // not-a-key-name: the server's error code
                (Refusal::Replaced, _) => tracing::error!(
                    code,
                    message,
                    live,
                    "another process with this device's identity connected, and the backend keeps \
                     only the latest connection: not reconnecting until the owner asks (Retry in \
                     the window, or a restart); retrying by itself would start the two taking it \
                     from each other forever"
                ),
                // not-a-key-name: the server's error code
                (Refusal::Fatal { .. }, _) => tracing::error!(
                    code,
                    message,
                    live,
                    retry_in_s = self.slow_retry.as_secs(),
                    "the backend refuses this agent with a fatal code: the usual reconnecting \
                     stops; retrying slowly, and at once when the owner asks"
                ),
            }
            self.refusal_logged = Some(refusal.clone());
        }
        lock(&self.state).refused = Some(refusal.clone());
        self.emit(AgentEvent::SignalingRefused(refusal));
    }

    /// `device_blocked`: an admin blocked this PC. The server ended its sessions first, as `blocked`,
    /// and told their viewers; what this agent still runs — a session whose end it did not hear (the
    /// block came while its signaling was down), a request waiting for its offer — ends here too, so
    /// the block holds even against a viewer that kept its peer open. Input first, as the kill switch
    /// does: the release of everything handed to a thread of its own, then each session's input
    /// refused here, on the orchestrator and without a lock, before its peer closes. Labelled
    /// `blocked` («Доступ отозван» in the journal); nothing goes to the backend, which ended them
    /// itself and will not have this agent anyway.
    ///
    /// Nothing here waits on the input driver: its slot lock may be held by a call that does not
    /// return (an unbounded `GetOverlappedResult` after `CancelIoEx`), and an orchestrator waiting
    /// on it would stop serving heartbeats, commands and the kill switch, and the PC would drop
    /// offline. The agent lives on after a block, so the release finishes whenever the driver lets
    /// go.
    fn end_for_block(&mut self, outbox: &mpsc::UnboundedSender<AgentToServer>) {
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        let requests: Vec<String> = self.pending.drain().map(|(id, _)| id).collect();
        if ids.is_empty() && requests.is_empty() {
            tracing::debug!("device_blocked: no session or request left on this agent to end");
            return;
        }
        tracing::info!(
            live = ids.len(),
            requests = requests.len(),
            teardowns_running = ?self.teardowns_running(),
            "device_blocked: ending what this agent still runs (the server ended it first); held \
             input released on a thread of its own, each session's input refused at once"
        );
        // First, before any session's end: as the kill switch, unconditionally, and not waited for.
        self.release_all_detached("device_blocked");
        for id in ids {
            self.end_session(&id, false, end_reason::BLOCKED, outbox);
        }
        for id in &requests {
            tracing::info!(
                session = %id,
                reason = end_reason::BLOCKED,
                "session request ended by device_blocked before its offer arrived"
            );
            self.emit(AgentEvent::SessionEnded {
                session_id: id.clone(),
                reason: end_reason::BLOCKED.into(),
            });
        }
    }

    /// `replaced` under [`OnReplaced::Stop`]: end what this agent is running before it stops.
    ///
    /// Input first, as the kill switch does: a key or button a viewer held must not outlive the
    /// process that pressed it. The release of everything goes to a thread of its own, then each
    /// session's input is refused here, without a lock, and its peer closed; nothing on the
    /// orchestrator waits on the input driver, whose slot lock a stuck call may hold. The process
    /// ends right after this (the CLI's `process::exit`), so the releases and the sessions' input
    /// ends — each of which releases what its session holds — are then awaited, asynchronously and
    /// at most [`REPLACED_TEARDOWN_WAIT`]: a driver that answers is let finish; a stuck one is said
    /// and left, and the CLI stops instead of hanging for ever. The sessions' ends go into the
    /// outbox like any other offline end, though no connection will carry them now; the backend
    /// ends them at its grace window.
    async fn stop_after_replaced(&mut self, outbox: &mpsc::UnboundedSender<AgentToServer>) {
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        tracing::info!(
            live = ids.len(),
            requests = self.pending.len(),
            teardowns_running = ?self.teardowns_running(),
            "stopping after replaced: releasing held input (on a thread of its own) and ending live \
             sessions"
        );
        self.release_all_detached("replaced");
        for id in ids {
            self.end_session(&id, true, end_reason::AGENT_DISCONNECTED, outbox);
        }
        self.pending.clear();
        let t0 = Instant::now();
        tracing::debug!(
            wait_ms = REPLACED_TEARDOWN_WAIT.as_millis() as u64,
            "stopping after replaced: waiting for the release and the session teardowns before the \
             process ends (the lines below say `exit:`)"
        );
        let left = self.teardowns_done(REPLACED_TEARDOWN_WAIT).await;
        tracing::debug!(
            left,
            waited_ms = t0.elapsed().as_millis() as u64,
            "stopping after replaced: teardown wait over; the agent stops"
        );
    }

    /// A pairing request kept across a break of the link: closed when its deadline passes with the
    /// link still down, or when the backend does not re-send it after the link is back
    /// (`crate::pairing::tick`, which logs it).
    fn tick_pairing(&self) {
        crate::pairing::tick(&mut lock(&self.state), crate::journal::now_ms());
    }

    /// A pairing code the backend refused (`rate_limited`), asked for again when its wait is over
    /// and the panel still waits for one (`crate::pairing::retry_due`, which logs it). On a live
    /// connection only: offline, the next connection asks anyway.
    fn retry_pairing_code(&self, outgoing: &mpsc::UnboundedSender<AgentToServer>) {
        let due = crate::pairing::retry_due(&mut lock(&self.state), crate::journal::now_ms());
        if due {
            send_to_backend(outgoing, AgentToServer::RequestPairing);
        }
    }

    /// Wait before the next attempt, serving what can be served without a backend.
    ///
    /// The wait must not swallow owner commands. The kill switch's whole point is "stop now" — with
    /// the network down and a session up, a deaf wait is the vulnerability itself, and after a
    /// refusal the wait can be a quarter of an hour or have no end. So the offline-safe subset is
    /// served: KillSwitch tears everything down locally, SetName saves the name (the next
    /// connection opens with it: its `device_name` is dropped by the relay, not held), session
    /// signals keep the UI truthful, and an unbind or a closed pairing panel is the owner's to
    /// make. What these tell the backend goes into the outbox, where the relay holds it for the
    /// next connection (`crate::relay::class`), so the backend need not guess the ends of sessions
    /// that ended offline from its own timeouts. An opened pairing panel is recorded, and its code
    /// is asked for on the next connection (`crate::pairing`), so the window is not left waiting
    /// for a code nobody asked for. Retry ends the wait. The rest needs a live backend and is
    /// ignored with a log rather than silently eaten.
    ///
    /// A goodbye's hold ([`Wait::Held`]) also ends when the hold is lifted (`crate::goodbye`), and
    /// lifts it itself when its limit passes or the owner retries.
    async fn wait_offline(
        &mut self,
        wait: Wait,
        commands_rx: &mut mpsc::UnboundedReceiver<AgentCommand>,
        sess_ev_rx: &mut mpsc::UnboundedReceiver<SessionSignal>,
        outbox: &mpsc::UnboundedSender<AgentToServer>,
    ) -> WaitEnd {
        let limit = wait.limit();
        tracing::debug!(
            wait = wait.label(),
            limit_s = limit.map(|d| d.as_secs()),
            "waiting before the next signaling attempt; the offline-safe commands are served"
        );
        let started = Instant::now();
        // Only a goodbye's hold listens for the hold's end; any other wait runs its course (and the
        // loop in `run` then finds a hold that began meanwhile).
        let held = matches!(wait, Wait::Held(_));
        let mut hold_rx = self.goodbyes.subscribe();
        if held && hold_rx.borrow_and_update().is_none() {
            tracing::debug!("the goodbye's hold was lifted before its wait began: connecting now");
            return WaitEnd::Elapsed;
        }
        // A wait with no limit never elapses: its branch below is disabled, and this sleep is
        // never polled.
        let deadline = tokio::time::sleep(limit.unwrap_or(Duration::ZERO));
        tokio::pin!(deadline);
        // A pairing request kept across the break closes at its deadline while offline too.
        let mut pairing_tick = pairing_tick();
        loop {
            tokio::select! {
                () = &mut deadline, if limit.is_some() => {
                    if held {
                        // The process did not exit, the system did not sleep, or the word that it
                        // came back never arrived: connected is better than offline for good.
                        tracing::warn!(
                            waited_s = started.elapsed().as_secs(),
                            "the goodbye's hold ran out with nothing lifting it (no resume, no \
                             cancelled shutdown heard, the process still here): connecting again"
                        );
                        self.goodbyes.lift("its limit passed");
                    }
                    return WaitEnd::Elapsed;
                }
                changed = hold_rx.changed(), if held => {
                    match changed {
                        Ok(()) if hold_rx.borrow_and_update().is_none() => {
                            tracing::debug!(
                                waited_ms = started.elapsed().as_millis() as u64,
                                "the goodbye's hold was lifted: connecting now"
                            );
                            return WaitEnd::Elapsed;
                        }
                        // A newer goodbye: the loop in `run` waits for its hold.
                        Ok(()) => {
                            tracing::debug!("the goodbye's hold changed (a newer goodbye)");
                            return WaitEnd::Elapsed;
                        }
                        // The sender lives as long as the agent; were it gone, nothing could lift
                        // the hold but its limit.
                        Err(_) => {
                            tracing::warn!("the goodbye's hold can no longer change: connecting now");
                            return WaitEnd::Elapsed;
                        }
                    }
                }
                _ = pairing_tick.tick() => {
                    let _step = self.steps.begin("pairing_tick", "-", None);
                    self.tick_pairing();
                }
                cmd = commands_rx.recv() => match cmd {
                    None => {
                        tracing::info!("command channel closed: the agent stops");
                        return WaitEnd::Stopped;
                    }
                    Some(AgentCommand::Retry) => {
                        tracing::info!(
                            wait = wait.label(),
                            waited_s = started.elapsed().as_secs(),
                            "owner asked to retry: connecting now"
                        );
                        if held {
                            self.goodbyes.lift("the owner asked to retry");
                        }
                        return WaitEnd::Retry;
                    }
                    Some(
                        cmd @ (AgentCommand::KillSwitch
                        | AgentCommand::Resume
                        | AgentCommand::SetName(_)
                        | AgentCommand::Unbind(_)
                        | AgentCommand::MakeOwner(_)
                        | AgentCommand::CancelOwnerRequest
                        | AgentCommand::RequestPairing
                        | AgentCommand::CancelPairing
                        | AgentCommand::EndForExit { .. }),
                    ) => {
                        tracing::debug!(
                            wait = wait.label(),
                            "serving {cmd:?} while signaling is offline; what it tells the \
                             backend is held for the next connection"
                        );
                        let _step = self.steps.begin("command", cmd.kind(), None);
                        self.handle_command(cmd, outbox).await;
                    }
                    Some(other) => {
                        tracing::debug!(
                            wait = wait.label(),
                            "ignoring {other:?} while signaling is offline: it needs a live \
                             backend"
                        );
                    }
                },
                sig = sess_ev_rx.recv() => {
                    if let Some(sig) = sig {
                        let (kind, session) = sig.kind();
                        let _step = self.steps.begin("session_signal", kind, Some(session));
                        self.handle_session_signal(sig, outbox);
                    }
                },
            }
        }
    }

    async fn connect_and_serve(
        &mut self,
        attempt: &crate::entry::Attempt,
        commands_rx: &mut mpsc::UnboundedReceiver<AgentCommand>,
        sess_ev_rx: &mut mpsc::UnboundedReceiver<SessionSignal>,
    ) -> Result<Served> {
        // The fingerprint into the hello, once it is read (the first attempt waits a moment for it).
        self.settle_hw().await;
        let url = attempt.url.clone();
        let device_id = lock(&self.config).device_id.clone();
        let pubkey_b64 = self.identity.public_key_b64();
        let identity = self.identity.clone();
        // The handshake hands it the challenge message (the domain prefix and the nonce).
        let signer: Signer = Arc::new(move |message: &[u8]| identity.sign(message));

        tracing::info!(
            endpoint = attempt.endpoint.as_str(),
            why = %attempt.why,
            "connecting to {url} as device {device_id}"
        );
        let sig = transport::connect_with(
            SignalingConfig {
                url,
                device_id,
                pubkey_b64,
                user_agent: self.user_agent.clone(),
                hello: self.hello.clone(),
            },
            signer,
            self.signaling_limits,
        )
        .await
        .context("signaling connect")?;

        // This connection's id, and its goodbye handle for whoever says goodbye from now on — unless
        // a goodbye came while it was being made (`crate::goodbye`): then it is told at once and
        // not served, and `run` waits for the hold to be lifted.
        let link_id = self.link_id + 1;
        self.link_id = link_id;
        if let Err(hold) = self.goodbyes.install(link_id, sig.goodbye.clone()) {
            let handle = sig.goodbye.clone();
            let reason = hold.reason;
            let said = tokio::task::spawn_blocking(move || {
                crate::goodbye::say_on(link_id, &handle, reason, crate::goodbye::GOODBYE_BUDGET)
            })
            .await;
            if let Err(e) = said {
                tracing::error!(
                    link = link_id,
                    "goodbye on a connection made during the hold: the thread that waited for it \
                     failed ({e})"
                );
            }
            // Only now: the pump must still have the connection while it says the goodbye.
            drop(sig);
            return Ok(Served::Disconnected(None));
        }
        // Authenticated: the way works this far; through the RU entry, remembered for the next start.
        self.entry.connected(attempt.endpoint);

        let (was_refused, first_list, changes) = {
            let mut s = lock(&self.state);
            s.connected = true;
            // Bindings removed or added while this agent was away (unbound in the Mini App, a guest
            // let in by the owner's invite): no `binding_removed` or `binding_added` reached it, so
            // the journal — and for a new guest the person at the PC — hears of them from the new
            // list. Compared with the list this run had, or before the first list of a run
            // with the previous run's last one (`with_last_known_bindings`); with neither there is
            // nothing to compare with.
            let compared_with = if s.bindings_known {
                Some(("a reconnect", s.bindings.clone()))
            } else {
                self.last_known_bindings
                    .take()
                    .map(|previous| ("the previous run's last list", previous))
            };
            let changes = compared_with.map(|(against, previous)| {
                (against, binding_changes(&previous, &sig.initial_bindings))
            });
            s.bindings = sig.initial_bindings.clone();
            let first_list = !std::mem::replace(&mut s.bindings_known, true);
            // What was asked of the owner while offline goes out now; a request still pending is
            // re-sent by the server right after `agent_ready` (`crate::owner_request`).
            s.owner_requests.reconnected(crate::journal::now_ms());
            (s.refused.take(), first_list, changes)
        };
        log_roles(&sig.initial_bindings, "agent_ready");
        // Sessions outlive a signaling reconnect: a role that changed while this agent was away
        // moves them now.
        self.sync_game_roles("agent_ready");
        match changes {
            Some((against, changes)) => self.note_changes_while_away(against, changes),
            None => tracing::debug!(
                bindings = sig.initial_bindings.len(),
                "access: the first list of this run, and no earlier one to compare it with"
            ),
        }
        if first_list {
            tracing::debug!(
                bindings = sig.initial_bindings.len(),
                since_start_ms = self.started.elapsed().as_millis() as u64,
                "binding list known for this run: the window leaves its placeholder"
            );
        }
        if let Some(was) = was_refused.or_else(|| self.refusal_logged.clone()) {
            if was.is_blocked() {
                tracing::info!(
                    was = was.code(),
                    "device_blocked lifted: the backend accepts this PC again (an admin lifted the \
                     block); serving as before"
                );
            } else {
                tracing::info!(
                    was = was.code(),
                    "the backend accepts this agent again after refusing it"
                );
            }
        }
        self.refusal_logged = None;
        tracing::info!(
            endpoint = attempt.endpoint.as_str(),
            peer = %sig.peer.map_or_else(|| "-".to_string(), |p| p.to_string()),
            "authenticated; {} binding(s)",
            sig.initial_bindings.len()
        );
        self.emit(AgentEvent::SignalingConnected {
            bindings: sig.initial_bindings.len(),
        });

        // Say whether the calibration sweep is armed, here, before anyone connects.
        //
        // Announcing it only once a session starts is too late to be useful: if the flag had not
        // reached the process, the person holding the phone would find out after spending their
        // time on a session that measured nothing. A mode that changes what
        // the product does has to be visible before it matters, not after.
        if calibration_armed() {
            tracing::warn!(
                points = crate::quality::CALIBRATION.len(),
                seconds = crate::quality::calibration_duration().as_secs(),
                "CALIBRATION MODE: the quality ladder is disabled and the operating point is \
                 swept on a script. Per-frame logging is on. Unset AFKLINK_CALIBRATE for normal use."
            );
        }

        let transport::Signaling {
            outgoing: link_tx,
            incoming,
            unsent,
            health,
            ..
        } = sig;
        // Kept for the end: how the pump ended is what the way to the server weighs.
        let pump_health = health.clone();
        self.link_health = Some(health);
        // Handed to the relay before anything is produced on this connection — the PC's name, the
        // re-announce below — so none of it is taken for "offline". The ordering argument is in
        // `crate::relay`. (The backend's heartbeat is answered by the connection's pump itself.)
        if self
            .links
            .send(LinkChange::Up(Link {
                id: link_id,
                tx: link_tx,
                unsent,
            }))
            .is_err()
        {
            tracing::error!(
                link = link_id,
                "the signaling relay has stopped: nothing can reach the backend; the agent stops"
            );
            self.goodbyes.retire(link_id);
            return Ok(Served::RelayGone);
        }
        tracing::debug!(link = link_id, "signaling link handed to the relay");
        let outbox = self.outbox.clone();
        self.announce_after_connect(link_id, &outbox);
        // What happened on the PC while no connection took it: after the handshake (this connection
        // is past `agent_ready`), never before (`crate::agent_events`).
        self.send_agent_events(link_id, &outbox, "connected");

        // Deliberately does NOT request a pairing code here unless the owner has the pairing
        // panel open.
        //
        // A code requested at startup would sit live on screen from the moment the agent
        // started — including inside the video stream of anyone already connected, who could
        // read it and mint themselves an independent binding that survives being revoked. A
        // code appears only when the owner opens the pairing panel, and dies when it closes.
        //
        // A panel that is open — opened while signaling was down, or left open across an outage
        // whose connection took its code — is exactly that request, so it is made now.
        let wants_code = crate::pairing::wants_code_on_connect(&lock(&self.state), link_id);
        if wants_code {
            send_to_backend(&outbox, AgentToServer::RequestPairing);
        }
        // A pairing request kept across the break waits for the backend's re-send, which follows
        // `agent_ready` on this connection (`crate::pairing`). Before `serve` reads it.
        crate::pairing::reconnected(&mut lock(&self.state), crate::journal::now_ms(), link_id);

        let served = self.serve(incoming, commands_rx, sess_ev_rx, &outbox).await;
        self.link_health = None;
        // Nothing can say goodbye on this connection any more.
        self.goodbyes.retire(link_id);
        // Events this connection did not stay up long enough to have taken go again on the next.
        if let Some(queue) = &self.event_queue {
            queue.link_down(link_id);
        }
        // Retire the link now rather than at the next refused send, so what the sessions produce
        // from here on is held for the next connection straight away.
        if self.links.send(LinkChange::Down { id: link_id }).is_err() {
            tracing::debug!(
                link = link_id,
                "the signaling relay is gone; nothing to retire the link in"
            );
        }
        Ok(match served {
            // The pump said how it ended before `incoming` ended, which is what ended `serve`.
            Served::Disconnected(_) => Served::Disconnected(pump_health.end()),
            other => other,
        })
    }

    /// Serve one connection until it ends or the agent is told to stop.
    async fn serve(
        &mut self,
        mut incoming: mpsc::UnboundedReceiver<ServerToAgent>,
        commands_rx: &mut mpsc::UnboundedReceiver<AgentCommand>,
        sess_ev_rx: &mut mpsc::UnboundedReceiver<SessionSignal>,
        outbox: &mpsc::UnboundedSender<AgentToServer>,
    ) -> Served {
        // A pairing request kept across a break waits for the backend's re-send (`crate::pairing`).
        let mut pairing_tick = pairing_tick();
        // The event queue: what is queued while this connection is up goes at once; its tick
        // delivers and sends what the budget held back (`crate::agent_events`).
        let events = self.event_queue.clone();
        let mut events_tick = tokio::time::interval(EVENTS_TICK);
        events_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            // Each branch's work is a step of the orchestrator's (`crate::step_watch`): a watcher
            // outside the runtime names one that does not end.
            tokio::select! {
                _ = pairing_tick.tick() => {
                    let _step = self.steps.begin("pairing_tick", "-", None);
                    self.tick_pairing();
                    self.retry_pairing_code(outbox);
                }
                () = events_queued(events.as_deref()) => {
                    let _step = self.steps.begin("agent_events", "queued", None);
                    self.send_agent_events(self.link_id, outbox, "queued");
                }
                _ = events_tick.tick(), if events.is_some() => {
                    let _step = self.steps.begin("agent_events", "tick", None);
                    self.tick_agent_events(outbox);
                }
                msg = incoming.recv() => {
                    // A viewer's offer starts a session (`start_session`): bounded by the setup's
                    // limit, which is its budget — the stall watch says nothing within it.
                    let _step = msg.as_ref().map(|m| {
                        let budget = step_budget(m, self.setup_limit);
                        self.steps
                            .begin_with_budget("server_message", m.kind(), m.session_id(), budget)
                    });
                    let Some(msg) = msg else {
                        match self.goodbyes.held() {
                            Some(hold) => tracing::info!(
                                live = self.sessions.len(),
                                reason = hold.reason.as_str(),
                                "the connection closed after this agent's goodbye; live sessions \
                                 carry on while the process does (their media is peer-to-peer)"
                            ),
                            None => tracing::info!(
                                live = self.sessions.len(),
                                "backend closed the connection; live sessions carry on (their \
                                 media is peer-to-peer) and are re-announced on the next one"
                            ),
                        }
                        // How the pump ended is filled in by `connect_and_serve`.
                        return Served::Disconnected(None);
                    };
                    // A fatal code ends the connection here: the backend closes the socket right
                    // after one anyway (`failAndClose`, and `replaced` in `registerAgent`), and
                    // what comes next is `crate::reconnect`'s decision, not the usual reconnect.
                    if let ServerToAgent::Error { code, message } = &msg {
                        if afklink_protocol::is_fatal(code) {
                            // not-a-key-name: the server's error code
                            tracing::debug!(
                                code = %code,
                                message = message.as_deref().unwrap_or("-"),
                                live = self.sessions.len(),
                                "fatal error frame on the live connection: this connection is over; \
                                 live sessions carry on (their media is peer-to-peer)"
                            );
                            return Served::Refused {
                                code: code.clone(),
                                message: message.clone(),
                            };
                        }
                    }
                    self.handle_server_msg(msg, outbox).await;
                }
                cmd = commands_rx.recv() => match cmd {
                    Some(cmd) => {
                        let _step = self.steps.begin("command", cmd.kind(), None);
                        self.handle_command(cmd, outbox).await;
                    }
                    // Every sender is gone, so nothing can ever command this agent again. Ignoring
                    // it would spin a core: a closed channel answers `None` at once, every turn.
                    // The same answer the offline wait in `run` gives.
                    None => {
                        tracing::info!("command channel closed: the agent stops");
                        return Served::Stopped;
                    }
                },
                sig = sess_ev_rx.recv() => {
                    if let Some(sig) = sig {
                        let (kind, session) = sig.kind();
                        let _step = self.steps.begin("session_signal", kind, Some(session));
                        self.handle_session_signal(sig, outbox);
                    }
                }
            }
        }
    }

    /// Name every live session on a new connection, and give up on requests that cannot finish.
    ///
    /// The backend keeps a session whose agent socket went away for a grace window
    /// (`AGENT_GRACE_MS` in `server/src/signaling/sessions.ts`) and re-binds it to this device's
    /// new socket on the first frame that names it — so each live session is named here, once, with
    /// its cumulative stats. This is the agent's twin of the Mini App's stats-on-reconnect; waiting
    /// for the telemetry task would take up to `TELEMETRY_INTERVAL_MS`. A session the backend no
    /// longer has is answered with `session_end` `unknown_session`, and ends here like any other
    /// backend end.
    ///
    /// A request still waiting for its offer can never get one now: the backend only re-binds a
    /// session this agent names, and a request has nothing to name it with. Ending it tells the
    /// viewer at once instead of at the backend's window.
    ///
    /// On the first connection both maps are empty and this says so at debug.
    ///
    /// First of all, the PC's name (`device_name`): the device's name follows the PC, and a rename
    /// made while offline — dropped by the relay — arrives here.
    fn announce_after_connect(
        &mut self,
        link_id: u64,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
    ) {
        if let Some(name) = self.pc_name_to_send("device_name") {
            send_to_backend(outgoing, AgentToServer::DeviceName { name });
        }
        let live = self.sessions.len();
        for (id, sess) in self.sessions.iter() {
            let reported = sess.stats.report(outgoing, id, false);
            tracing::debug!(
                session = %id,
                link = link_id,
                duration_ms = sess.stats.started.elapsed().as_millis() as u64,
                outcome = ?reported,
                "live session re-announced (its stats) so the backend re-binds it to this connection"
            );
        }
        let stale: Vec<String> = self.pending.keys().cloned().collect();
        for id in &stale {
            self.pending.remove(id);
            tracing::info!(
                session = %id,
                link = link_id,
                "session request from before the reconnect given up: its offer cannot reach this \
                 connection"
            );
            self.emit(AgentEvent::SessionEnded {
                session_id: id.clone(),
                reason: end_reason::AGENT_DISCONNECTED.into(),
            });
            send_to_backend(
                outgoing,
                AgentToServer::SessionEnd {
                    session_id: id.clone(),
                    reason: Some(end_reason::AGENT_DISCONNECTED.into()),
                    detail: None,
                },
            );
        }
        if live > 0 || !stale.is_empty() {
            tracing::info!(
                link = link_id,
                live,
                requests_given_up = stale.len(),
                "signaling connected with sessions from before: each named to the backend"
            );
        } else {
            tracing::debug!(
                link = link_id,
                "signaling connected; no session to re-announce"
            );
        }
    }

    async fn handle_server_msg(
        &mut self,
        msg: ServerToAgent,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
    ) {
        let kind = msg.kind();
        match msg {
            ServerToAgent::PairingCode {
                code,
                expires_at,
                bot_username,
                miniapp_short_name,
            } => {
                // A code for a panel that is no longer open (withdrawn before the code came) is not
                // shown; the backend revoked it already. `crate::pairing`.
                if !crate::pairing::code_wanted(&lock(&self.state), expires_at) {
                    return;
                }
                // Not logged: the code is a live credential for as long as the panel
                // is open, and an info-level log lands in files and in whatever ships
                // them off the machine.
                tracing::info!("pairing code issued (expires_at={expires_at})");
                // Where the QR code and «copy link» point, decided (and logged) once per code: the
                // backend's bot unless config.json overrides it, and no link at all when neither
                // names one. The window asks for the link twice a second.
                let target = {
                    let cfg = lock(&self.config);
                    crate::qr::resolve_target(
                        crate::qr::LinkNames {
                            bot_username: cfg.bot_username.as_deref(),
                            short_name: cfg.miniapp_short_name.as_deref(),
                        },
                        crate::qr::LinkNames {
                            bot_username: bot_username.as_deref(),
                            short_name: miniapp_short_name.as_deref(),
                        },
                    )
                };
                let mut s = lock(&self.state);
                s.pairing_code = Some(code);
                s.pairing_expires_at = Some(expires_at);
                s.pairing_link = target;
            }
            ServerToAgent::PairRequest {
                request_id,
                telegram_user_id,
                username,
                first_name,
                expires_at,
                has_owner,
            } => {
                // The request already on screen, re-sent by the backend after a reconnect: live
                // again where it was (its «Кто это?» step is the window's, by the same id); nothing
                // new to raise and no panel to close. `crate::pairing`.
                if crate::pairing::restore(
                    &mut lock(&self.state),
                    &request_id,
                    expires_at,
                    crate::journal::now_ms(),
                ) {
                    return;
                }
                let pending = PendingPair {
                    request_id,
                    telegram_user_id,
                    username,
                    first_name,
                    expires_at,
                    has_owner,
                    link: crate::pairing::PairLink::Live,
                };
                tracing::info!(
                    "pairing request from {} awaiting confirmation",
                    pending.display_name()
                );
                tracing::debug!(
                    request_id = %pending.request_id,
                    telegram_user_id,
                    has_owner = has_owner.map_or("-", |h| if h { "true" } else { "false" }),
                    asks_role = pending.asks_role(),
                    "pairing request: {}",
                    match has_owner {
                        Some(false) => "the PC has no owner: «Разрешить» leads to «Кто это?»",
                        Some(true) => "the PC has an owner: no question, the person becomes a guest",
                        None => "a server older than roles: no question",
                    }
                );
                let name = pending.display_name();
                let closed = {
                    let mut s = lock(&self.state);
                    s.pending_pair = Some(pending);
                    // The code on an open panel was spent on entry: the panel closes and the prompt
                    // is what remains (the owner's choice), and the code is revoked as for any
                    // close. `crate::pairing`.
                    crate::pairing::request_arrived(&mut s, name)
                };
                if closed {
                    send_to_backend(outgoing, AgentToServer::PairingCancel);
                }
            }
            ServerToAgent::PairCancelled { request_id, reason } => {
                tracing::info!("pairing request {request_id} withdrawn ({reason:?})");
                // An approval of it the server did not take (it had expired, say): no binding is
                // coming from it.
                let before = self.approved_here.len();
                self.approved_here.retain(|_, a| a.request_id != request_id);
                if self.approved_here.len() != before {
                    tracing::debug!(
                        %request_id,
                        "pairing: the request approved on this PC was withdrawn; its approval no \
                         longer counts"
                    );
                }
                let mut s = lock(&self.state);
                if s.pending_pair
                    .as_ref()
                    .is_some_and(|p| p.request_id == request_id)
                {
                    s.pending_pair = None;
                } else {
                    tracing::debug!(
                        %request_id,
                        shown = s.pending_pair.as_ref().map_or("-", |p| p.request_id.as_str()),
                        "pairing request withdrawn that is not the one on screen: nothing to close"
                    );
                }
            }
            ServerToAgent::BindingAdded {
                telegram_user_id,
                username,
                first_name,
                role,
                via,
            } => {
                // `via: invite`: the owner let a guest in from Telegram by his invite, and nobody
                // at the PC was asked. A word this build
                // does not know reads as no `via` at all, as the contract says.
                let invited = match &via {
                    Some(afklink_protocol::BindingVia::Invite) => true,
                    Some(afklink_protocol::BindingVia::Other(word)) => {
                        tracing::debug!(
                            telegram_user_id,
                            via = %word,
                            "binding_added: a via this build does not know, read as none: «Доступ \
                             выдан» in the journal, no new-guest toast"
                        );
                        false
                    }
                    None => false,
                };
                tracing::info!(
                    role = role.map_or("-", afklink_protocol::BindingRole::as_str),
                    via = via
                        .as_ref()
                        .map_or("-", afklink_protocol::BindingVia::as_str),
                    "binding added: {telegram_user_id}"
                );
                // Approved on this PC and heard of now: not one to look for in a later list.
                if self.approved_here.remove(&telegram_user_id).is_some() {
                    tracing::debug!(
                        telegram_user_id,
                        "pairing: the approval on this PC is heard of (binding_added); no longer \
                         looked for in a later list"
                    );
                }
                // An invite always makes a guest (the contract): nobody at the PC was asked, so
                // until the server's next word on roles this binding is a guest here — game-only
                // for guests, the guest's row, the guard on AFKLink's windows. Only until then: the
                // next `agent_ready` (whose list carries no `via`) or `owner_changed` puts in place
                // whatever role the server holds, the owner's included.
                let role = if invited && role != Some(afklink_protocol::BindingRole::Guest) {
                    tracing::warn!(
                        telegram_user_id,
                        sent = role.map_or("-", afklink_protocol::BindingRole::as_str),
                        "binding_added by invite with a role other than guest: the contract says an \
                         invite always makes a guest; taken as a guest on this PC"
                    );
                    Some(afklink_protocol::BindingRole::Guest)
                } else {
                    role
                };
                // The owner allowed it on this PC: «Доступ выдан» in the journal; he let a guest in
                // from Telegram by his invite: «Доступ по приглашению» in its place.
                self.journal_event(
                    if invited {
                        crate::journal::Kind::Invited
                    } else {
                        crate::journal::Kind::Granted
                    },
                    telegram_user_id,
                    first_name.as_deref(),
                    username.as_deref(),
                );
                let (first_pairing, listed, toast_name) = {
                    let mut s = lock(&self.state);
                    // Nobody had access before this one: the first pairing, after which the window
                    // asks once whether to start with Windows.
                    let first_pairing = s.bindings.is_empty();
                    // Already listed: a repeat, not someone new (a re-pair; for an invite, a server
                    // that sent it twice).
                    let listed = s
                        .bindings
                        .iter()
                        .any(|b| b.telegram_user_id == telegram_user_id);
                    let was = role_of(&s.bindings, telegram_user_id);
                    s.bindings
                        .retain(|b| b.telegram_user_id != telegram_user_id);
                    // One owner at most: a new owner (the first binding of a PC with none, or a
                    // guest re-paired as the owner — `owner_changed` follows that one) leaves no
                    // other. The server never lists two; this keeps the window from showing two
                    // in between.
                    if role == Some(afklink_protocol::BindingRole::Owner) {
                        for b in s.bindings.iter_mut() {
                            if b.role == Some(afklink_protocol::BindingRole::Owner) {
                                tracing::warn!(
                                    was_owner = b.telegram_user_id,
                                    new_owner = telegram_user_id,
                                    "roles: binding_added names a new owner while another was \
                                     listed; the other is a guest now"
                                );
                                b.role = Some(afklink_protocol::BindingRole::Guest);
                            }
                        }
                    }
                    if was.is_some() && was != role {
                        tracing::debug!(
                            telegram_user_id,
                            was = was.map_or("-", afklink_protocol::BindingRole::as_str),
                            now = role.map_or("-", afklink_protocol::BindingRole::as_str),
                            "roles: a re-pair changed the binding's role"
                        );
                    }
                    let binding = BindingInfo {
                        telegram_user_id,
                        username,
                        first_name,
                        role,
                    };
                    let name = binding.display_name();
                    // As the pairing window names a requester, «Имя (@username)»: the person at the
                    // PC hears of a stranger here for the first time, and a first name alone is
                    // self-chosen. Cleaned of invisible and control characters.
                    let toast_name = crate::person_name::requester_name(
                        telegram_user_id,
                        binding.first_name.as_deref(),
                        binding.username.as_deref(),
                    );
                    s.bindings.push(binding);
                    // The newcomer of a pairing held for the owner (`pc_allow`): he allowed it, and
                    // the request ends so (`confirmed` may come before this or after).
                    let held = s
                        .owner_requests
                        .newcomer_bound(telegram_user_id, crate::journal::now_ms());

                    if held && !invited {
                        // The owner allowed it in Telegram, minutes after the prompt: its code was
                        // revoked when the server held the pairing, so a panel open now is another
                        // pairing, with a code nobody spent.
                        tracing::debug!(
                            panel = s.pairing_panel.kind(),
                            had_code = s.pairing_code.is_some(),
                            "binding of a pairing held for the owner (pc_allow): the pairing panel \
                             and its code are left as they are (no code was spent now)"
                        );
                    } else if invited {
                        // No code made this binding: the owner allowed it in Telegram. The panel
                        // and a code on it are someone else's pairing, left as they are.
                        tracing::debug!(
                            panel = s.pairing_panel.kind(),
                            had_code = s.pairing_code.is_some(),
                            "binding by the owner's invite: the pairing panel and its code are left \
                             as they are (no code was spent)"
                        );
                    } else {
                        // The code that produced this binding is spent. The server deleted it the
                        // moment the owner approved — `revokePairingCodes` — so leaving it on
                        // screen shows a dead credential, and the next person to
                        // type it gets "invalid code" for a code they read correctly off this
                        // window.
                        //
                        // Worse than the confusion: a code left visible is also in the video
                        // stream of anyone already connected, which is the exact reason the panel
                        // is closed by default rather than always open.
                        //
                        // An open panel becomes `Paired`, and the window closes it on that rather
                        // than staying open with the code gone and nothing in its place
                        // (`crate::pairing`).
                        crate::pairing::binding_added(&mut s, name);
                    }
                    (first_pairing, listed, toast_name)
                };
                if invited {
                    self.announce_invited_guest(telegram_user_id, role, listed, toast_name);
                }
                // A re-pair can change a role (a guest re-paired as the owner of a PC with none).
                self.sync_game_roles("binding_added");
                // Not under the state's lock: the config's is taken on its own.
                if first_pairing {
                    let mut c = lock(&self.config);
                    if c.offer_autostart_after_first_pairing() {
                        if let Err(e) = c.save() {
                            tracing::warn!(
                                "autostart card's offer not saved to config.json: {e:#}; shown \
                                 until the app exits"
                            );
                        }
                    }
                } else {
                    tracing::trace!("not the first pairing: the autostart card is not offered");
                }
            }
            ServerToAgent::BindingRemoved { telegram_user_id } => {
                tracing::info!("binding removed: {telegram_user_id}");
                let removed = {
                    let mut s = lock(&self.state);
                    let removed = s
                        .bindings
                        .iter()
                        .find(|b| b.telegram_user_id == telegram_user_id)
                        .cloned();
                    s.bindings
                        .retain(|b| b.telegram_user_id != telegram_user_id);
                    s.owner_requests.binding_removed(telegram_user_id);
                    removed
                };
                tracing::debug!(
                    telegram_user_id,
                    role = removed
                        .as_ref()
                        .and_then(|b| b.role)
                        .map_or("-", afklink_protocol::BindingRole::as_str),
                    "roles: the binding is gone{}",
                    if removed.as_ref().and_then(|b| b.role)
                        == Some(afklink_protocol::BindingRole::Owner)
                    {
                        " — it was the owner's; owner_changed names who is now"
                    } else {
                        ""
                    }
                );
                // Unbound on this PC or in the Mini App: «Доступ отозван» in the journal, under the
                // name the binding had.
                self.journal_event(
                    crate::journal::Kind::Revoked,
                    telegram_user_id,
                    removed.as_ref().and_then(|b| b.first_name.as_deref()),
                    removed.as_ref().and_then(|b| b.username.as_deref()),
                );
                // Drop any sessions belonging to that user.
                let victims: Vec<String> = self
                    .sessions
                    .iter()
                    .filter(|(_, s)| s.telegram_user_id == telegram_user_id)
                    .map(|(id, _)| id.clone())
                    .collect();
                let ended = victims.len();
                // `unbound`, the agreed reason (the backend ends these sessions with it too). This
                // said `unbound_by_owner`, which is not in `SESSION_END_REASONS`.
                for id in victims {
                    self.end_session(&id, true, end_reason::UNBOUND, outgoing);
                }
                // And any not-yet-answered request: the offer-time check would
                // refuse it anyway, but a `pending` entry is a promise that this
                // user may connect — don't keep promises to the unbound.
                let dropped: Vec<String> = self
                    .pending
                    .iter()
                    .filter(|(_, p)| p.telegram_user_id == telegram_user_id)
                    .map(|(id, _)| id.clone())
                    .collect();
                for id in &dropped {
                    self.pending.remove(id);
                    // No `SessionEnded` for a request that never started; its log file closes.
                    self.log_ended(id, end_reason::UNBOUND);
                }
                tracing::debug!(
                    telegram_user_id,
                    sessions_ended = ended,
                    requests_dropped = dropped.len(),
                    bindings = lock(&self.state).bindings.len(),
                    "unbind applied"
                );
                // After that account's sessions ended. The owner's unbinding is followed by
                // `owner_changed`, which moves the rest.
                self.sync_game_roles("binding_removed");
            }
            ServerToAgent::OwnerChanged { telegram_user_id } => {
                self.owner_changed(telegram_user_id);
            }
            ServerToAgent::OwnerRequestState {
                request_id,
                kind,
                telegram_user_id,
                state,
                expires_at,
                reason,
                username,
                first_name,
            } => {
                let now_ms = crate::journal::now_ms();
                // `pc_allow`: a pairing approved here, held for the owner — the approval is kept
                // while he decides, and the newcomer is named for a row of their own.
                let newcomer = if kind == afklink_protocol::OwnerStateKind::PcAllow {
                    self.hold_approval_for_owner(
                        telegram_user_id,
                        request_id.as_deref(),
                        state,
                        expires_at,
                        now_ms,
                    );
                    Some(crate::owner_request::Newcomer {
                        username,
                        first_name,
                    })
                } else {
                    if username.is_some() || first_name.is_some() {
                        tracing::debug!(
                            kind = kind.as_str(),
                            telegram_user_id,
                            "owner_request_state names its person for one of the PC's own kinds: \
                             ignored, the list names them"
                        );
                    }
                    None
                };
                lock(&self.state).owner_requests.on_state(
                    request_id.as_deref(),
                    kind,
                    telegram_user_id,
                    state,
                    expires_at,
                    reason,
                    newcomer,
                    now_ms,
                );
            }
            ServerToAgent::SessionRequest {
                session_id,
                telegram_user_id,
                username,
                turn,
                quality_profile,
            } => {
                if !is_bound(&lock(&self.state).bindings, telegram_user_id) {
                    tracing::warn!(
                        "session_request {session_id} from unbound user \
                         {telegram_user_id}: ignoring"
                    );
                    send_to_backend(
                        outgoing,
                        AgentToServer::SessionEnd {
                            session_id,
                            reason: Some(end_reason::UNBOUND.into()),
                            detail: None,
                        },
                    );
                } else if lock(&self.state).paused {
                    // The kill switch paused connections: refused until the owner resumes on
                    // this PC. The viewer is told so and may try again later.
                    tracing::info!(
                        session = %session_id,
                        telegram_user_id,
                        reason = end_reason::PAUSED_ON_PC,
                        "session request refused: connections are paused on this PC (kill switch) \
                         until the owner resumes"
                    );
                    // «Отклонено: ПК на паузе» in the journal, once per person per pause: a viewer
                    // that retries every few seconds is one attempt to the owner.
                    if self.journal.is_some() {
                        if self.paused_journaled.insert(telegram_user_id) {
                            let first_name = lock(&self.state)
                                .bindings
                                .iter()
                                .find(|b| b.telegram_user_id == telegram_user_id)
                                .and_then(|b| b.first_name.clone());
                            self.journal_event(
                                crate::journal::Kind::Paused,
                                telegram_user_id,
                                first_name.as_deref(),
                                username.as_deref(),
                            );
                        } else {
                            tracing::debug!(
                                telegram_user_id,
                                "connection journal: this person's attempt on pause is already in \
                                 the journal for this pause; not again"
                            );
                        }
                    }
                    self.emit(AgentEvent::SessionEnded {
                        session_id: session_id.clone(),
                        reason: end_reason::PAUSED_ON_PC.into(),
                    });
                    send_to_backend(
                        outgoing,
                        AgentToServer::SessionEnd {
                            session_id,
                            reason: Some(end_reason::PAUSED_ON_PC.into()),
                            detail: None,
                        },
                    );
                } else {
                    // Before the request's own line, so it is the first of the session's file.
                    if let Some(log) = &self.session_log {
                        log.opened(&session_id, telegram_user_id);
                    }
                    tracing::info!("session_request {session_id} from user {telegram_user_id}");
                    // The session's quality policy, decided here once (an ICE restart's re-offer
                    // keeps it): the server's profile if it validates, the fallback otherwise.
                    // Checked in place — a few kilobytes of pure CPU, no lock, no I/O — and its
                    // `quality profile` line follows the request's, so it lands in the session
                    // file.
                    let policy = crate::quality_policy::SessionPolicy::for_session(
                        &session_id,
                        quality_profile.as_ref(),
                    );
                    // An empty list is logged, loudly, by `spawn_peer`.
                    let stun_servers = transport::stun_servers(&turn.urls);
                    // The URLs only: the TURN username and credential stay out of the log.
                    tracing::debug!(
                        session = %session_id,
                        ice_urls = ?turn.urls,
                        stun_servers = ?stun_servers,
                        pending = self.pending.len() + 1,
                        "session request accepted; waiting for the viewer's offer"
                    );
                    self.pending.insert(
                        session_id,
                        Pending {
                            telegram_user_id,
                            username,
                            stun_servers,
                            policy,
                        },
                    );
                }
            }
            ServerToAgent::Sdp {
                session_id,
                sdp_type,
                sdp,
            } => {
                if sdp_type == SdpType::Offer {
                    self.start_session(session_id, sdp, outgoing).await;
                } else {
                    tracing::debug!("ignoring non-offer sdp ({sdp_type:?})");
                }
            }
            ServerToAgent::Ice {
                session_id,
                candidate,
            } => {
                if let Some(sess) = self.sessions.get(&session_id) {
                    // The peer logs the candidate itself once it has parsed it; what can go wrong
                    // here is that it never gets there, and `signal_peer` says so. Nothing to do
                    // about a refusal but count it: the viewer will not send that one again.
                    let _ = signal_peer(
                        &sess.signals,
                        &session_id,
                        PeerSignal::AddRemoteIce(candidate),
                    );
                } else if self.pending.contains_key(&session_id) {
                    // A request with no offer yet. Cannot happen as things are: the viewer sends
                    // its offer before its first candidate, the backend relays one socket's frames
                    // in order, and this loop serves them one at a time — the candidates that come
                    // while `start_session` waits for its peer stay in the signaling inbox, which
                    // is unbounded, until the session exists. So one here means that order broke,
                    // and the candidate is lost.
                    tracing::warn!(
                        session = %session_id,
                        candidate = %candidate.candidate,
                        "remote candidate dropped: it came before the session's offer, which the \
                         viewer and the backend always send first"
                    );
                } else {
                    // Ordinary: a session whose setup failed, or one that has ended, with the
                    // viewer's trickle still on its way.
                    tracing::debug!(
                        pending = false,
                        "ICE for unknown session {session_id}: not running (it ended, or its setup \
                         failed)"
                    );
                }
            }
            ServerToAgent::SessionEnd { session_id, reason } => {
                tracing::info!("session_end {session_id} ({reason:?})");
                if reason.as_deref() == Some(end_reason::UNKNOWN_SESSION) {
                    // The answer to naming a session — the re-announce after a reconnect, or a held
                    // answer or candidate — that the backend ended while this agent was away: its
                    // grace window ran out, or the viewer ended it and the end went to the dead
                    // socket. Not echoed back (`notify_backend` is false), so this cannot loop.
                    tracing::debug!(
                        session = %session_id,
                        running = self.sessions.contains_key(&session_id),
                        "the backend no longer has this session: it ended while signaling was down"
                    );
                }
                // The journal gets the backend's own reason — the viewer's, passed on — which the
                // `SessionEnded` below only calls `server_ended`; and it may come just after the
                // peer's own end closed the entry (the viewer's goodbye lands first).
                self.journal_server_end(
                    &session_id,
                    reason.as_deref().unwrap_or(end_reason::local::SERVER_ENDED),
                );
                // Local only (`notify_backend` false): nothing goes back, the label is for the
                // agent's own event and log.
                self.end_session(
                    &session_id,
                    false,
                    end_reason::local::SERVER_ENDED,
                    outgoing,
                );
            }
            // The connection's pump answers the heartbeat itself and does not hand it on, so that a
            // busy orchestrator cannot cost the socket (`afklink_transport::signaling`).
            ServerToAgent::Ping => {
                tracing::debug!(
                    "a ping reached the orchestrator, though the pump answers pings itself: not \
                     answered twice"
                );
            }
            // Only transient and unknown codes get here: `serve` ends the connection on a fatal one.
            // The backend keeps the connection after these (`bad_json`, `bad_message`: a frame of
            // ours it could not read), so the agent does too.
            ServerToAgent::Error { code, message } => {
                // not-a-key-name: the server's error code
                tracing::warn!(
                    code = %code,
                    message = message.as_deref().unwrap_or("-"),
                    known = afklink_protocol::error_severity(&code).is_some(),
                    "backend error frame with a transient or unknown code: the connection carries on"
                );
                // The refused pairing code: the open panel would otherwise wait for it forever.
                if code == "rate_limited"
                    && message.as_deref() == Some(crate::pairing::CODE_REFUSED_MESSAGE)
                {
                    crate::pairing::code_refused(&mut lock(&self.state), crate::journal::now_ms());
                }
            }
            ServerToAgent::Challenge { .. } | ServerToAgent::AgentReady { .. } => {
                // Handshake-only messages; ignore if they arrive mid-session.
                tracing::debug!(kind, "handshake message after the handshake; ignored");
            }
        }
    }

    async fn handle_command(
        &mut self,
        cmd: AgentCommand,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
    ) {
        match cmd {
            AgentCommand::RequestPairing => {
                // Offline, the request would be dropped by the relay; the next connection asks for
                // the code instead (`connect_and_serve`). `open` logs which.
                if crate::pairing::open(&mut lock(&self.state)) {
                    send_to_backend(outgoing, AgentToServer::RequestPairing);
                }
            }
            AgentCommand::CancelPairing => {
                // Sent whatever the panel was: revoking is idempotent on the backend, and covers a
                // code issued for a request this agent does not track any more.
                crate::pairing::close(&mut lock(&self.state));
                send_to_backend(outgoing, AgentToServer::PairingCancel);
            }
            AgentCommand::RespondToPair {
                request_id,
                accept,
                role,
            } => {
                // Kept across a break of the link and not live again yet: the answer would reach
                // nobody (the relay drops it offline) or a backend that has dropped the request.
                // The prompt keeps its buttons disabled meanwhile; this is the guard behind them.
                let held = lock(&self.state)
                    .pending_pair
                    .as_ref()
                    .filter(|p| p.request_id == request_id && !p.answerable())
                    .map(|p| p.link);
                if let Some(link) = held {
                    tracing::info!(
                        %request_id,
                        accept,
                        link = link.as_str(),
                        "answer to a pairing request while its link is down: not sent; the request \
                         stays, answerable once the backend re-sends it"
                    );
                    return;
                }
                tracing::info!(
                    "pairing request {request_id} {}",
                    if accept { "approved" } else { "declined" }
                );
                // An approval carries this PC's name, so it is complete on its own: the backend
                // makes it the device's name before it tells the Mini App. (It has the name from
                // this connection's `device_name` already, unless the backend predates that.)
                let name = if accept {
                    self.pc_name_to_send("pair_response")
                } else {
                    None
                };
                let (asked, requester) = lock(&self.state)
                    .pending_pair
                    .as_ref()
                    .filter(|p| p.request_id == request_id)
                    .map_or((None, None), |p| {
                        (
                            Some(p.asks_role()),
                            Some((
                                p.telegram_user_id,
                                crate::owner_request::Newcomer {
                                    username: p.username.clone(),
                                    first_name: p.first_name.clone(),
                                },
                            )),
                        )
                    });
                let role = if accept {
                    Some(pair_role(&request_id, role, asked))
                } else {
                    None
                };
                // Approved here: if its `binding_added` is lost to a break of the link, the next
                // `agent_ready` lists it, and that is this «Разрешить», not access given elsewhere.
                // Declined: an earlier approval of the same account counts no more.
                if let Some((uid, names)) = requester {
                    self.note_answer_here(uid, &request_id, accept, Instant::now());
                    // The server may hold an approval for the owner (`pc_allow`) and name the
                    // newcomer, or not, in what it says of it: the prompt's names, for the row.
                    if accept {
                        lock(&self.state).owner_requests.note_approved(uid, names);
                    }
                }
                send_to_backend(
                    outgoing,
                    AgentToServer::PairResponse {
                        request_id: request_id.clone(),
                        accept,
                        name,
                        role,
                    },
                );
                let mut s = lock(&self.state);
                if s.pending_pair
                    .as_ref()
                    .is_some_and(|p| p.request_id == request_id)
                {
                    s.pending_pair = None;
                } else {
                    // The prompt was already gone — withdrawn or expired — when the owner answered.
                    tracing::debug!(%request_id, "answered a pairing request that is no longer pending");
                }
            }
            AgentCommand::Unbind(uid) => self.unbind(uid, outgoing),
            AgentCommand::MakeOwner(uid) => {
                let (role, owner) = {
                    let s = lock(&self.state);
                    let owner = s
                        .bindings
                        .iter()
                        .find(|b| b.role == Some(afklink_protocol::BindingRole::Owner))
                        .map(|b| b.telegram_user_id);
                    (role_of(&s.bindings, uid), owner)
                };
                tracing::info!(
                    telegram_user_id = uid,
                    role = role.map_or("-", afklink_protocol::BindingRole::as_str),
                    owner = owner.unwrap_or(0),
                    "«Сделать владельцем» pressed: asking the server ({})",
                    if owner.is_some() {
                        "the owner confirms in Telegram; the row says «Ждём подтверждения» once the \
                         server has asked him (pending)"
                    } else {
                        "the PC has no owner as last heard: the server applies it at once, nobody to \
                         confirm — the button is held until it answers, no «Ждём подтверждения»"
                    }
                );
                if role == Some(afklink_protocol::BindingRole::Owner) {
                    tracing::debug!(
                        telegram_user_id = uid,
                        "already the owner as this PC last heard: asked all the same, the server \
                         answers by its own roles"
                    );
                }
                self.ask_owner(afklink_protocol::OwnerRequestKind::MakeOwner, uid, outgoing);
            }
            AgentCommand::CancelOwnerRequest => {
                // `None`: nothing the server can be told yet; `cancel` said why.
                let id = lock(&self.state)
                    .owner_requests
                    .cancel(crate::journal::now_ms());
                if let Some(request_id) = id {
                    tracing::info!(%request_id, "owner request withdrawn on this PC");
                    send_to_backend(outgoing, AgentToServer::OwnerRequestCancel { request_id });
                }
            }
            AgentCommand::KillSwitch => self.kill_switch(outgoing),
            AgentCommand::Resume => self.resume(),
            AgentCommand::SetName(raw) => self.set_name(&raw, outgoing),
            // Served here only while connected (a wait between attempts takes it itself, in
            // `wait_offline`), where there is nothing to retry.
            AgentCommand::Retry => {
                tracing::debug!("owner asked to retry while connected: nothing to do");
            }
            AgentCommand::EndForExit {
                why,
                asked,
                budget,
                done,
            } => {
                // The process is leaving: whatever the orchestrator still holds at its end is
                // part of an ordinary exit.
                self.sessions
                    .ends_as_asked("the exit asked for the sessions' end");
                let waited = asked.elapsed();
                if waited > budget {
                    tracing::info!(
                        why = why.as_str(),
                        waited_ms = waited.as_millis() as u64,
                        budget_ms = budget.as_millis() as u64,
                        live = self.sessions.len(),
                        requests = self.pending.len(),
                        "exit: the request to end the sessions reached the orchestrator past its \
                         budget; the exit went ahead without it, so it is dropped and the sessions \
                         carry on while the process does"
                    );
                    return;
                }
                let ended = self.end_all_for_exit(why, asked, budget, outgoing).await;
                if done.try_send(ended).is_err() {
                    tracing::debug!(
                        why = why.as_str(),
                        "exit: whoever asked to end the sessions stopped waiting (its budget ran \
                         out); they are ended all the same"
                    );
                }
            }
        }
    }

    /// The process is leaving (`why`): every live session ends now — its final report, then
    /// `session_end agent_ended` with its path — and every request still waiting for its offer;
    /// then the relay's barrier puts all of it in the connection's queue, which the goodbye writes
    /// first (`crate::relay::LinkChange::Barrier`). The journal closes their entries as the exit
    /// does («Приложение закрыто»), not as an ordinary end. Served offline too: the ends are then
    /// held, and lost with the process, which is what happened before.
    ///
    /// `asked` and `budget`: when the exit asked and how long it waits for the answer; the wait for
    /// the teardowns takes only what is left of it (less [`EXIT_REPLY_MARGIN`]).
    async fn end_all_for_exit(
        &mut self,
        why: crate::goodbye::GoodbyeReason,
        asked: Instant,
        budget: Duration,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
    ) -> ExitEnding {
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        let requests: Vec<String> = self.pending.drain().map(|(id, _)| id).collect();
        if ids.is_empty() && requests.is_empty() {
            tracing::debug!(
                why = why.as_str(),
                "exit: no live session and no request to end before the goodbye"
            );
            return ExitEnding {
                flushed: true,
                ..ExitEnding::default()
            };
        }
        tracing::info!(
            why = why.as_str(),
            live = ids.len(),
            requests = requests.len(),
            reason = end_reason::AGENT_ENDED,
            "exit: ending every live session before the goodbye (final report, then session_end)"
        );
        // A key or button a viewer holds must not outlive the process that pressed it: first, as
        // the kill switch does — on its own thread, waited for below with the teardowns.
        if !ids.is_empty() {
            self.release_all_detached("exit");
        }
        // The journal's entries close as the exit closes them, first: the ends below then find
        // none open, and do not relabel them as an ordinary end.
        if let Some(journal) = &self.journal {
            journal.app_closing(crate::journal::now_ms());
        }
        for id in &ids {
            self.end_session(id, true, end_reason::AGENT_ENDED, outgoing);
        }
        for id in &requests {
            tracing::info!(
                session = %id,
                reason = end_reason::AGENT_ENDED,
                "session request ended by the exit before its offer arrived"
            );
            self.emit(AgentEvent::SessionEnded {
                session_id: id.clone(),
                reason: end_reason::AGENT_ENDED.into(),
            });
            send_to_backend(
                outgoing,
                AgentToServer::SessionEnd {
                    session_id: id.clone(),
                    reason: Some(end_reason::AGENT_ENDED.into()),
                    detail: None,
                },
            );
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let flushed = if self.links.send(LinkChange::Barrier(tx)).is_err() {
            tracing::debug!("exit: the signaling relay is gone; nothing to flush");
            None
        } else {
            match tokio::time::timeout(EXIT_BARRIER_WAIT, rx).await {
                Ok(Ok(flushed)) => Some(flushed),
                Ok(Err(_)) => {
                    tracing::debug!("exit: the relay dropped the barrier unanswered");
                    None
                }
                Err(_) => {
                    tracing::debug!(
                        wait_ms = EXIT_BARRIER_WAIT.as_millis() as u64,
                        "exit: the relay did not answer the barrier in time; the goodbye may go \
                         ahead of some ends"
                    );
                    None
                }
            }
        };
        tracing::debug!(
            sessions = ids.len(),
            requests = requests.len(),
            drained = flushed.map_or(0, |f| f.drained),
            link = ?flushed.and_then(|f| f.link),
            "exit: the ends are in the connection's queue, ahead of the goodbye"
        );
        // The releases and capture stops run on their own threads; the process should not leave
        // before them if they can still be had (it says itself how many were left). Only what is
        // left of the exit's budget, so the answer still reaches the one who asked in time.
        let budget_left = budget
            .saturating_sub(asked.elapsed())
            .saturating_sub(EXIT_REPLY_MARGIN);
        let wait = EXIT_TEARDOWN_WAIT.min(budget_left);
        tracing::debug!(
            wait_ms = wait.as_millis() as u64,
            spent_ms = asked.elapsed().as_millis() as u64,
            budget_ms = budget.as_millis() as u64,
            "exit: waiting for the session teardowns, within what is left of the budget"
        );
        self.teardowns_done(wait).await;
        ExitEnding {
            sessions: ids.len(),
            requests: requests.len(),
            link: flushed.and_then(|f| f.link),
            flushed: flushed.is_some(),
        }
    }

    /// The kill switch: end every session now, and refuse new ones until the owner resumes.
    ///
    /// It does not lock the workstation: only the connections are cut, and the PC stays usable at
    /// the desk. What keeps a viewer from simply connecting again is the pause
    /// ([`AgentState::paused`]): every `session_request` is refused with `paused_on_pc` until
    /// [`AgentCommand::Resume`]. It is kept in config.json (`Config::paused`), so neither a restart
    /// of the process nor an update ends it: a pause held only in memory would let an automatic
    /// update quietly let back in whoever the owner had shut out. The updater also installs nothing
    /// while paused (`Defer::Paused` in the desktop app). Pairing stays allowed: it takes the
    /// owner's own action at this PC, and a binding made while paused cannot open a session until
    /// the owner resumes anyway.
    ///
    /// Served offline too (`wait_offline`): the ends go into the outbox for the next connection, and
    /// the pause holds from this moment whatever the connection does.
    fn kill_switch(&mut self, outgoing: &mpsc::UnboundedSender<AgentToServer>) {
        let was_paused = std::mem::replace(&mut lock(&self.state).paused, true);
        if !was_paused && !self.paused_journaled.is_empty() {
            tracing::debug!(
                people = self.paused_journaled.len(),
                "connection journal: a new pause; attempts on it are kept afresh"
            );
            self.paused_journaled.clear();
        }
        tracing::warn!(
            live = self.sessions.len(),
            requests = self.pending.len(),
            was_paused,
            "KILL SWITCH: ending every session; new connections are refused until the owner resumes"
        );
        // Teardowns of earlier sessions still running hold what the release below needs (the
        // driver's slot lock): said, so a release that comes late has its reason in the log.
        let earlier = self.teardowns_running();
        if !earlier.is_empty() {
            tracing::warn!(
                jobs = ?earlier,
                abandoned = crate::offload::abandoned(),
                "kill switch: teardowns of earlier sessions are still running; the release and the \
                 ends below are handed off all the same and may wait behind them"
            );
        }
        // First, unconditionally — before any session teardown can fail with a button still held.
        // On its own thread: the driver's slot lock may be held by a stuck call.
        self.release_all_detached("kill switch");
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        let sessions = ids.len();
        for id in ids {
            self.end_session(&id, true, end_reason::KILL_SWITCH, outgoing);
        }
        // A request still waiting for its offer would become a session the moment the offer came.
        let requests: Vec<String> = self.pending.drain().map(|(id, _)| id).collect();
        for id in &requests {
            tracing::info!(
                session = %id,
                reason = end_reason::KILL_SWITCH,
                "session request ended by the kill switch before its offer arrived"
            );
            self.emit(AgentEvent::SessionEnded {
                session_id: id.clone(),
                reason: end_reason::KILL_SWITCH.into(),
            });
            send_to_backend(
                outgoing,
                AgentToServer::SessionEnd {
                    session_id: id.clone(),
                    reason: Some(end_reason::KILL_SWITCH.into()),
                    detail: None,
                },
            );
        }
        tracing::info!(
            sessions,
            requests = requests.len(),
            teardowns_running = ?self.teardowns_running(),
            "connections paused: every session request is refused (paused_on_pc) until the owner \
             resumes (Resume in the window or the tray, `resume` on the CLI) — a restart or an \
             update does not end it"
        );
        // After the teardown: the pause has been in force in memory since the first line, and the
        // disk write must not hold the sessions' ends up.
        self.save_pause("the kill switch");
    }

    /// Keep the pause in config.json (`Config::paused`) as the state has it now (`why`: the kill
    /// switch or the owner's resume) — off the async worker, on the blocking pool, where the config's
    /// lock is taken and the file written ([`persist_pause`]); in a test without a runtime, here.
    /// Writes go one at a time, and each writes what the state says when it runs, so a kill switch
    /// and a resume in quick succession leave the file saying what the state says, whatever order
    /// the pool runs them in.
    fn save_pause(&mut self, why: &'static str) {
        let (config, state, one_at_a_time) = (
            self.config.clone(),
            self.state.clone(),
            self.pause_writes.clone(),
        );
        let job = move || persist_pause(&config, &state, &one_at_a_time, why);
        self.pause_save = match tokio::runtime::Handle::try_current() {
            Ok(runtime) => Some(runtime.spawn_blocking(job)),
            Err(_) => {
                job();
                None
            }
        };
    }

    /// The last pause write has reached the disk (the tests').
    #[cfg(test)]
    async fn pause_saved(&mut self) {
        if let Some(write) = self.pause_save.take() {
            write.await.expect("the pause write did not panic");
        }
    }

    /// «Отвязать» on a person. A guest's binding — or any binding on a
    /// server older than roles — goes with `unbind`, at once. The owner's waits for the owner's
    /// confirmation in Telegram: `owner_request` `unbind_owner`, and the row says
    /// «Ждём подтверждения» until the server says how it went. Who is the owner is the server's
    /// last word (`bindings`); were it stale, the server answers by its own roles (an `unbind` of
    /// the owner is taken as the request too, and `unbind_owner` of a guest is refused
    /// `not_owner`).
    fn unbind(&mut self, uid: i64, outgoing: &mpsc::UnboundedSender<AgentToServer>) {
        let role = role_of(&lock(&self.state).bindings, uid);
        if role == Some(afklink_protocol::BindingRole::Owner) {
            tracing::info!(
                telegram_user_id = uid,
                "«Отвязать» on the owner: asking the server; the owner confirms in Telegram"
            );
            self.ask_owner(
                afklink_protocol::OwnerRequestKind::UnbindOwner,
                uid,
                outgoing,
            );
            return;
        }
        tracing::info!(
            telegram_user_id = uid,
            role = role.map_or("-", afklink_protocol::BindingRole::as_str),
            "owner revoked a binding{}",
            if role.is_none() {
                " (no role known: the server's list has none, or no such binding)"
            } else {
                ""
            }
        );
        send_to_backend(
            outgoing,
            AgentToServer::Unbind {
                telegram_user_id: uid,
            },
        );
    }

    /// Open a request to the owner — unless one is in flight already (at most one per PC: the row
    /// says «Уже есть запрос», and nothing goes to the server). Held while offline, like `unbind`:
    /// a person pressed it (`crate::relay`).
    fn ask_owner(
        &mut self,
        kind: afklink_protocol::OwnerRequestKind,
        uid: i64,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
    ) {
        let ask = lock(&self.state)
            .owner_requests
            .ask(kind, uid, crate::journal::now_ms());
        if ask == crate::owner_request::Ask::Send {
            send_to_backend(
                outgoing,
                AgentToServer::OwnerRequest {
                    kind,
                    telegram_user_id: uid,
                },
            );
        }
    }

    /// `owner_changed`: the account named is the owner now and every other binding a guest; `None`
    /// — the PC has no owner. The whole truth about roles, applied to every binding.
    fn owner_changed(&mut self, owner: Option<i64>) {
        use afklink_protocol::BindingRole;
        let mut s = lock(&self.state);
        let was: Vec<i64> = s
            .bindings
            .iter()
            .filter(|b| b.role == Some(BindingRole::Owner))
            .map(|b| b.telegram_user_id)
            .collect();
        let mut changed = 0usize;
        for b in s.bindings.iter_mut() {
            let role = if Some(b.telegram_user_id) == owner {
                BindingRole::Owner
            } else {
                BindingRole::Guest
            };
            if b.role != Some(role) {
                changed += 1;
                b.role = Some(role);
            }
        }
        let listed = owner.is_none_or(|o| s.bindings.iter().any(|b| b.telegram_user_id == o));
        tracing::info!(
            owner = owner.unwrap_or(0),
            was = ?was,
            changed,
            bindings = s.bindings.len(),
            "owner changed: {}",
            if owner.is_none() {
                "the PC has no owner now; everyone left is a guest"
            } else {
                "the account named is the owner, everyone else a guest"
            }
        );
        if !listed {
            tracing::warn!(
                owner = owner.unwrap_or(0),
                "owner_changed names an account this PC has no binding for; the list shows no \
                 owner until it comes (binding_added or the next agent_ready)"
            );
        }
        drop(s);
        self.sync_game_roles("owner_changed");
    }

    /// Tell the per-session game-only decisions the server's list as it stands now (`why`: the
    /// message that changed it). With «Только для гостей» on, a live session whose viewer's role
    /// changed moves to its new mode at once (`crate::game_access`). Called wherever the list
    /// changes: `agent_ready`, `binding_added`, `binding_removed`, `owner_changed`.
    fn sync_game_roles(&self, why: &str) {
        let bindings = lock(&self.state).bindings.clone();
        self.game_access.set_roles(&bindings, why);
    }

    /// The owner's Resume after the kill switch: session requests are accepted again, and the pause
    /// leaves config.json (the next start is not paused either).
    fn resume(&mut self) {
        self.paused_journaled.clear();
        if std::mem::replace(&mut lock(&self.state).paused, false) {
            tracing::info!("connections resumed by the owner: session requests are accepted again");
        } else {
            tracing::debug!("owner asked to resume while not paused: nothing to do");
        }
        // Whatever the state said: config.json must not keep a pause the owner has lifted.
        self.save_pause("the owner's resume");
    }

    /// The owner renamed this PC. Held to the device-name rule (`afklink_protocol::device_name`)
    /// the backend applies, so the name kept here is one it will store: a name it refused would
    /// leave the Mini App showing the old one. A refused name leaves the old one here too.
    ///
    /// The new name goes to the backend at once (`device_name`), and the device's name follows it
    /// in every Mini App except an account that gave the device a label of its own. Offline, the
    /// relay drops it and the next connection opens with the name
    /// ([`Self::announce_after_connect`]).
    fn set_name(&mut self, raw: &str, outgoing: &mpsc::UnboundedSender<AgentToServer>) {
        let name = match afklink_protocol::validate_device_name(raw) {
            Ok(name) => name,
            Err(why) => {
                tracing::warn!(
                    name = ?raw,
                    why = why.as_str(),
                    "device name refused ({why}); the old one stays"
                );
                return;
            }
        };
        {
            let mut c = lock(&self.config);
            if c.name == name {
                tracing::debug!(name = %name, "device name set to the one it already has");
                return;
            }
            tracing::info!(
                from = %c.name,
                to = %name,
                "device name changed; sending it to the backend, the Mini App follows"
            );
            c.name = name.clone();
            // Not fatal — the name is in use until the next start either way — but a name that
            // silently reverts on restart is a bug report nobody can explain.
            if let Err(e) = c.save() {
                tracing::warn!("device name not saved to config.json: {e:#}");
            }
        }
        send_to_backend(outgoing, AgentToServer::DeviceName { name });
    }

    /// This PC's name as it goes to the backend — `what` it rides on: `device_name` after a
    /// connect, or an approval (`pair_response.name`) — or `None` when the stored one is not a
    /// valid name. `Config` repairs it on load, so only a hand edit since can make it so; the
    /// backend then keeps the name it has, and what the name rode on goes ahead without it.
    fn pc_name_to_send(&self, what: &'static str) -> Option<String> {
        let stored = lock(&self.config).name.clone();
        match afklink_protocol::validate_device_name(&stored) {
            Ok(name) => {
                tracing::debug!(name = %name, what, "sending this PC's name to the backend");
                Some(name)
            }
            Err(why) => {
                tracing::warn!(
                    name = ?stored,
                    why = why.as_str(),
                    what,
                    "the stored device name is not a valid one ({why}): not sent, and the Mini \
                     App keeps the name the backend has"
                );
                None
            }
        }
    }

    fn handle_session_signal(
        &mut self,
        sig: SessionSignal,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
    ) {
        match sig {
            SessionSignal::Connected(id) => {
                let started = {
                    let mut s = lock(&self.state);
                    if let Some(info) = s.sessions.iter_mut().find(|x| x.session_id == id) {
                        info.connected = true;
                        // The first connect only: the timer counts from when the viewer took
                        // control, and a repeated signal must not restart it.
                        let first = info.connected_at.is_none();
                        if first {
                            info.connected_at = Some(Instant::now());
                        }
                        tracing::info!(
                            session = %id,
                            telegram_user_id = info.telegram_user_id,
                            timer_started = first,
                            "session connected: the viewer is receiving"
                        );
                        first.then(|| {
                            (
                                info.telegram_user_id,
                                info.name().text,
                                info.username.clone(),
                            )
                        })
                    } else {
                        tracing::debug!(session = %id, "connected signal for a session no longer listed");
                        None
                    }
                };
                // From now on, and not from its request, the game helper may act for it: an
                // attempt that never connects never touches the game (`crate::game_access`).
                self.game_access.connected(&id);
                // The video came up: the session's entry in the journal opens now. Attempts that
                // never got this far are not kept. «Только игра» is this session's own: with
                // «Только для гостей» on, the owner's session is not one (`crate::game_access`).
                if let (Some(journal), Some((user, name, username))) = (&self.journal, started) {
                    journal.session_started(
                        &crate::journal::SessionStart {
                            session_id: &id,
                            user,
                            name: &name,
                            username: username.as_deref(),
                            game_only: self
                                .sessions
                                .get(&id)
                                .is_some_and(|s| s.capture_mode.is_game()),
                        },
                        crate::journal::now_ms(),
                    );
                }
            }
            SessionSignal::Closed { id, end } => {
                let reason = end.reason();
                tracing::info!(
                    reason,
                    ?end,
                    by_viewer = end.by_viewer(),
                    "session {id} closed (peer)"
                );
                // `peer_closed` is the one end of the peer's own the backend may yet explain: the
                // viewer's «Отключиться» sends its reason through the backend and says goodbye peer
                // to peer at once, and the goodbye lands first. The journal closes the entry now and
                // takes that reason if it comes in time; the teardown below does not wait.
                if reason != end_reason::PEER_CLOSED {
                    tracing::trace!(
                        session = %id,
                        reason,
                        "connection journal: a peer end the backend has nothing to add to; the \
                         session's end closes the entry"
                    );
                } else if !self.sessions.contains_key(&id) {
                    tracing::trace!(
                        session = %id,
                        "connection journal: the peer's end of a session no longer running (its \
                         end closed the entry already)"
                    );
                } else {
                    self.journal_peer_end(&id, end);
                }
                self.end_session_with(&id, true, reason, peer_ended_detail(end), outgoing);
            }
            SessionSignal::PipelineFailed { id, reason } => {
                if self.sessions.contains_key(&id) {
                    tracing::warn!(
                        reason,
                        "session {id}: the capture pipeline could not be brought back; ending it"
                    );
                    self.end_session(&id, true, reason, outgoing);
                } else {
                    tracing::debug!(
                        reason,
                        "session {id}: pipeline failure reported after the session ended; ignored"
                    );
                }
            }
        }
    }

    async fn start_session(
        &mut self,
        session_id: String,
        offer_sdp: String,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
    ) {
        // A second offer for a session that is already running: the viewer restarting ICE because
        // its path failed (`webrtc.ts` `tryIceRestart`), or re-sending that offer after its
        // signaling socket lost the answer. The session — capture, encoder, data channels — carries
        // on; only the peer's ICE changes. The answer comes back from the peer as
        // `PeerEvent::Answer` and goes out from the event task, in order with any candidate the
        // restart then trickles.
        //
        // Dropping it as a duplicate would leave a phone that changed networks unable to get its
        // session back: the restart's candidates arrive for an offer that was ignored, and the
        // session ends seconds later.
        if let Some(sess) = self.sessions.get(&session_id) {
            tracing::info!(
                bytes = offer_sdp.len(),
                "offer for live session {session_id}: the viewer is renegotiating (an ICE \
                 restart); handing it to the peer"
            );
            // In the viewer's signal queue, behind the candidates it trickled before it and ahead of
            // the ones the restart trickles after: those carry the new ufrag, which str0m takes only
            // once this offer is applied.
            if let Err(why) = signal_peer(
                &sess.signals,
                &session_id,
                PeerSignal::Renegotiate(offer_sdp),
            ) {
                // The viewer is waiting for an answer that cannot come now; saying so ends its
                // wait at once rather than at its recovery deadline.
                tracing::warn!(
                    "session {session_id}: the peer cannot take the re-offer ({why}); ending the \
                     session"
                );
                self.end_session(
                    &session_id,
                    true,
                    transport::PeerEnd::RestartFailed.reason(),
                    outgoing,
                );
            }
            return;
        }

        // No request, no session. An offer on its own proves nothing — without
        // this, any party that can talk to the backend could make the agent
        // capture the screen for a user id it invented.
        let Some(request) = self.pending.get(&session_id) else {
            tracing::warn!("offer for {session_id} without a session_request: ignoring");
            send_to_backend(
                outgoing,
                AgentToServer::SessionEnd {
                    session_id,
                    reason: Some(end_reason::NO_SESSION_REQUEST.into()),
                    detail: None,
                },
            );
            return;
        };
        // The binding may have died between the request and the offer
        // (unbind, revoke). `BindingRemoved` already sweeps `pending`, so this
        // is the belt to those suspenders — kept because the cost of being
        // wrong here is a screen streaming to a stranger.
        if !is_bound(&lock(&self.state).bindings, request.telegram_user_id) {
            tracing::warn!(
                "offer for {session_id} from user {} no longer bound: ignoring",
                request.telegram_user_id
            );
            self.pending.remove(&session_id);
            self.log_ended(&session_id, end_reason::UNBOUND);
            send_to_backend(
                outgoing,
                AgentToServer::SessionEnd {
                    session_id,
                    reason: Some(end_reason::UNBOUND.into()),
                    detail: None,
                },
            );
            return;
        }
        // The same belt for the pause: the kill switch clears `pending` and refuses new requests,
        // so a request can only be here if that ever changes — and then it must not stream.
        if lock(&self.state).paused {
            tracing::info!(
                session = %session_id,
                reason = end_reason::PAUSED_ON_PC,
                "offer for a request refused: connections are paused on this PC"
            );
            self.pending.remove(&session_id);
            self.emit(AgentEvent::SessionEnded {
                session_id: session_id.clone(),
                reason: end_reason::PAUSED_ON_PC.into(),
            });
            send_to_backend(
                outgoing,
                AgentToServer::SessionEnd {
                    session_id,
                    reason: Some(end_reason::PAUSED_ON_PC.into()),
                    detail: None,
                },
            );
            return;
        }

        // `pending` holds this session: checked just above, and nothing in between removes it. (Were
        // it gone, the viewer would be account 0: no role, so game-only would apply — the safe side.)
        let (stun_servers, viewer, session_policy) = self
            .pending
            .get(&session_id)
            .map(|p| (p.stun_servers.clone(), p.telegram_user_id, p.policy.clone()))
            .unwrap_or_else(|| {
                // Unreachable, as above; and were it reached, the compiled profile is the safe side.
                tracing::warn!(
                    session = %session_id,
                    "offer: the request vanished from pending; quality policy falls back"
                );
                (
                    Vec::new(),
                    0,
                    crate::quality_policy::SessionPolicy::fallback(
                        crate::quality_policy::FallbackReason::Absent,
                    ),
                )
            });
        let setup_started = Instant::now();
        let peer =
            match transport::spawn_peer_with(&offer_sdp, stun_servers, self.link_shaper.clone())
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("failed to create peer: {e:#}");
                    self.emit(AgentEvent::SessionEnded {
                        session_id: session_id.clone(),
                        reason: end_reason::PEER_ERROR.into(),
                    });
                    // No peer, so no path to tell of.
                    send_to_backend(
                        outgoing,
                        AgentToServer::SessionEnd {
                            session_id,
                            reason: Some(end_reason::PEER_ERROR.into()),
                            detail: None,
                        },
                    );
                    return;
                }
            };

        // Relay the answer immediately.
        let answered = send_to_backend(
            outgoing,
            AgentToServer::Sdp {
                session_id: session_id.clone(),
                sdp_type: SdpType::Answer,
                sdp: peer.answer_sdp.clone(),
            },
        );
        tracing::info!(
            session = %session_id,
            offer_bytes = offer_sdp.len(),
            answer_bytes = peer.answer_sdp.len(),
            setup_ms = setup_started.elapsed().as_millis() as u64,
            answered,
            "peer created; answer relayed"
        );
        // The answer is only queued: the relay task takes it to the socket once this task yields.
        // `start_pipeline` yields at its first blocking step (each runs on a thread of its own and
        // is awaited), so the answer is on the wire while the capture comes up, never behind it.
        self.start_pipeline(
            session_id,
            peer,
            viewer,
            session_policy,
            setup_started,
            outgoing,
        )
        .await;
    }

    /// End a session whose setup failed before it was registered: the viewer told why (`reason`),
    /// its peer closed, its capture decision dropped. Nothing else of it exists yet.
    fn abort_setup(
        &mut self,
        session_id: String,
        closer: &PeerCloser,
        path: &transport::PeerPathCell,
        reason: &'static str,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
    ) {
        tracing::debug!(
            session = %session_id,
            reason,
            setup_failed = true,
            "session setup given up; the viewer is told why"
        );
        self.game_access.close(&session_id);
        close_peer(closer, &session_id);
        self.emit(AgentEvent::SessionEnded {
            session_id: session_id.clone(),
            reason: reason.into(),
        });
        let detail = end_detail(&session_id, &path.get(), None);
        send_to_backend(
            outgoing,
            AgentToServer::SessionEnd {
                session_id,
                reason: Some(reason.into()),
                detail,
            },
        );
    }

    /// The rest of a session's start, its peer made and its answer queued: the encoder, the capture,
    /// the input, the tasks, the registration. Every step that can block runs on a thread of its own
    /// and is awaited under [`Self::setup_limit`] (`crate::offload::run_bounded`): a step that does
    /// not come back in time ends the session with a reason, and the orchestrator carries on
    /// serving.
    async fn start_pipeline(
        &mut self,
        session_id: String,
        peer: transport::Peer,
        viewer: i64,
        session_policy: crate::quality_policy::SessionPolicy,
        setup_started: Instant,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
    ) {
        use crate::offload::{run_bounded, Bounded};
        // One policy for the whole session (decided at its request, in `pending`): every price and
        // probe target before the controller exists reads it, and the controller is built on it.
        let policy = session_policy.policy.clone();
        // One limit for the blocking steps together, not one each: the orchestrator serves nothing
        // else while it awaits them (every other session's signals wait in its queue), so three
        // stuck steps must not cost three limits.
        let deadline = Instant::now() + self.setup_limit;
        let left = || deadline.saturating_duration_since(Instant::now());

        // The input driver is wedged (earlier openings still stuck on its lock, or input jobs stuck
        // past their error bound): this start would wait its whole limit for the same failure and
        // leave one more thread behind. Refused at once ([`START_REFUSE_STUCK`]). Only the input's
        // jobs count: a stuck capture stop or start does not keep the next session's capture or
        // input from working, and must not lock the PC's viewers out.
        use crate::offload::{abandoned_of, running};
        let input_open_running = running("input-open");
        let input_abandoned = INPUT_JOBS
            .iter()
            .map(|what| abandoned_of(what))
            .sum::<usize>();
        if input_open_running + input_abandoned >= self.start_refuse_stuck {
            tracing::error!(
                session = %session_id,
                input_open_running,
                input_abandoned,
                refuse_at = self.start_refuse_stuck,
                input_end_running = running("input-end"),
                input_close_running = running("input-close"),
                release_all_running = running("release-all"),
                abandoned_all = crate::offload::abandoned(),
                "session start refused at once: the input driver's lock is stuck (calls on it do \
                 not return), so no session's input could open; restarting the app frees it"
            );
            self.abort_setup(
                session_id,
                &peer.closer,
                &peer.path,
                end_reason::INTERNAL_ERROR,
                outgoing,
            );
            return;
        }
        tracing::trace!(
            session = %session_id,
            input_open_running,
            input_abandoned,
            "no stuck input jobs in the way of the start"
        );

        // Build capture -> encode pipeline.
        //
        // What is captured is the owner's choice on this PC for this viewer, decided now and again
        // whenever it changes mid-session: the primary monitor, or the bound game's window only —
        // with «Только для гостей» on, the latter for guests only, by the role the server gave the
        // viewer's binding (`crate::game_access`). In game mode the monitor capturer is never made —
        // here or at any restart. See `crate::game`.
        let game_status = Arc::new(crate::game::GameStatus::new());
        let bindings = lock(&self.state).bindings.clone();
        let capture_mode = self.game_access.open(&session_id, viewer, &bindings);
        let session_capture = crate::game::SessionCapture::new(
            self.backends.clone(),
            capture_mode.clone(),
            game_status.clone(),
        );
        tracing::debug!(
            session = %session_id,
            game_only = session_capture.mode().is_game(),
            capture = %session_capture.mode().describe(),
            "capture mode at session start"
        );
        // The encoder first, on a thread of its own: its library's start is not ours to bound. Made
        // before the capture, so an encoder that cannot be had leaves no capture to stop.
        //
        // `encoder_error` on failure, the agreed spelling in `SESSION_END_REASONS`. This said
        // `encode_error`, which no viewer mapped; the Mini App still accepts both.
        let backends = self.backends.clone();
        let made = run_bounded(
            "make-encoder",
            &session_id,
            left(),
            move || (backends.make_encoder)(),
            // Late: dropped, which frees it. Nothing else was set up with it.
            drop,
        )
        .await;
        let encoder = match made {
            Bounded::Done(Ok(e)) => e,
            Bounded::Done(Err(e)) => {
                tracing::error!(session = %session_id, "encoder init failed: {e:#}");
                self.abort_setup(
                    session_id,
                    &peer.closer,
                    &peer.path,
                    end_reason::ENCODER_ERROR,
                    outgoing,
                );
                return;
            }
            failed @ (Bounded::TimedOut | Bounded::Failed(_)) => {
                tracing::error!(
                    session = %session_id,
                    limit_ms = self.setup_limit.as_millis() as u64,
                    why = %failed.why_not(),
                    "encoder init did not come back; the session is given up"
                );
                self.abort_setup(
                    session_id,
                    &peer.closer,
                    &peer.path,
                    end_reason::ENCODER_ERROR,
                    outgoing,
                );
                return;
            }
        };
        // Read once, here, because the encoder is about to be moved onto its own thread and this
        // is a property of the backend rather than of any frame. `None` from a backend with no
        // such concept, and the ladder then learns no floor.
        let qp_ceiling = encoder.max_qp().map(|q| q as f32);

        // Start at the top of the ladder and let the controller walk it down — starting low and
        // climbing makes every session begin looking worse than it needs to, and a climb costs
        // `UP_AFTER + SETTLE_AFTER_MOVE` per rung where a descent costs two seconds.
        //
        // At the very top of the policy's ladder (1080p60 on the server's tuned profile, 720p30 on
        // the compiled fallback): `cpu_bound` sheds it from encode times alone within the descent
        // dwell on a machine that cannot hold it, before any network signal exists. The session's
        // policy says which rung that is (`session_opening`, below the preference).
        //
        // `Balanced`, and nothing in this product can ask for anything else.
        //
        // `Quality` scales the whole ladder — `Best` is 1.5x what a resolution is "worth" against
        // `Balanced`'s 0.67, so it is a 2.2x difference in every rung's price and in the probe
        // ceiling derived from the top one. `QualityController::set_quality` exists to change it
        // and has no caller.
        //
        // The viewer cannot reach it: `InputMessage::Quality { q }` carries `"auto"` or a
        // pinnable height (`crates/protocol/src/input.rs`, and the miniapp's `QualitySetting` is
        // `"auto" | "1080" | "720" | "540" | "360"`), which is a *pin*, not a preference — it
        // chooses which ladder the controller walks, not how much a rung is worth. Wiring `Best`
        // up needs a new protocol value and a control to send it, which is a product decision and
        // not one to invent here.
        let quality_pref = crate::quality::Quality::default();
        let opening = session_opening(&policy, quality_pref);
        let start = opening.start;
        let target = Arc::new(crate::quality::QualityTarget::with_outstanding(
            start,
            peer.outstanding_bytes.clone(),
        ));
        let counters = Arc::new(SessionCounters::default());
        target.set_target_kbps(opening.target_kbps);
        counters.lowest_height.store(start.max_h, Ordering::Relaxed);
        // The background hold: while the viewer's page is hidden past its grace, no video. Fed by
        // the event task (the viewer's `vis`, its input, `kf`, `vv`), run out by the control task,
        // published into `target` for the supervisor, the encode loop and the heartbeat. See
        // `crate::bg_hold`.
        let bg = Arc::new(crate::bg_hold::BgHold::new(
            session_id.clone(),
            target.clone(),
        ));

        // The viewer's resolution pin, on its way from the task that receives it to the task that
        // owns the ladder.
        //
        // One controller owns the ladder, and the pin is a request it reads on its own tick. A
        // second `QualityController` in the event task applying the pin would be two controllers
        // on one actuator, on different clocks: the control task's ladder overwrites the pinned
        // rung on its next move, and a controller never fed a `Feedback` publishes
        // `encoder_target_kbps()` from `smoothed == 0` — `clamp(0.0 * 0.9, FLOOR, ceiling)`, the
        // absolute floor — on every quality change until the next 200 ms tick.
        //
        // `NO_PIN_REQUEST` means nothing new; `PIN_AUTO` hands the choice back to the ladder;
        // anything else is a height.
        let pin_request = Arc::new(AtomicU32::new(NO_PIN_REQUEST));

        // Tell congestion control how high it is allowed to look, before it looks.
        //
        // A constant in the transport crate would make the constant, not the network, the limit. It
        // is the controller's probe target (`QualityController::probe_target_kbps`), and the
        // opening value is what that target is with nothing measured (`opening_probe_target_kbps`):
        // the ladder's ceiling, priced against a guessed 1920x1080 here and corrected by the
        // control task once capture reports the real screen. str0m 0.24 queues its opening probes
        // (3x and 6x of 600, held to twice this) before the first media packet, and the exponential
        // probing behind them is held to twice this too, so a lower opening value slows every good
        // link's start (on the bench, with the floor: 2090 against 3600 kbps in the first seconds).
        // The control task lowers it when the opening is over (`quality::PROBE_OPENING`, three
        // seconds of media) — before str0m's periodic probe, twice this, can first fire five
        // seconds after its opening probes: that probe at twice the ceiling, into a link that has
        // shown nothing, floods it (23 Mbps measured).
        let initial_desired_kbps = opening.probe_kbps;
        if let Err(e) = peer
            .control_tx
            .try_send(PeerControl::SetDesiredBitrate(initial_desired_kbps))
        {
            // A fresh queue refuses nothing, so this is a peer that has already ended — and, if it
            // were not, congestion control would probe towards the transport's bootstrap ceiling
            // (2.5 Mbps: the opening probes pass, the probing after them is held to 5000) until the
            // control task's first probe target that moves a fifth from it.
            tracing::warn!(
                session = %session_id,
                desired_kbps = initial_desired_kbps,
                "bwe probe target not set at session start: {e}"
            );
        }
        tracing::debug!(
            session = %session_id,
            rung = %format!("{}p@{}", start.max_h, start.fps),
            budget_kbps = target.target_kbps().unwrap_or(0),
            desired_kbps = initial_desired_kbps,
            qp_ceiling = ?qp_ceiling,
            "session pipeline starting at the top of the ladder"
        );

        let (frame_tx, frame_rx) = std::sync::mpsc::channel::<Frame>();
        // Made and started on a thread of its own: a WGC start waits for its capture thread to come
        // up (`D3D11CreateDevice`, `CreateForMonitor`, `StartCapture`) with no bound of its own. A
        // clone of the sender, not the sender itself: the supervisor keeps the original for every
        // capturer it may have to start in this one's place (see `crate::pipeline`). The session's
        // `SessionCapture` goes along and comes back, for the supervisor.
        let (sink, start_target) = (frame_tx.clone(), target.clone());
        let late_sid = session_id.clone();
        let started = run_bounded(
            "capture-start",
            &session_id,
            left(),
            move || {
                let made = session_capture
                    .make()
                    .map_err(|e| ("capturer init", e))
                    .and_then(|mut c| match c.start(sink, start_target) {
                        Ok(()) => Ok(c),
                        Err(e) => Err(("capture start", e)),
                    });
                (session_capture, made)
            },
            // A capture that came up after the session was given up: stopped at once, here.
            move |(_, made)| {
                if let Ok(mut c) = made {
                    c.stop();
                    tracing::warn!(
                        session = %late_sid,
                        "capture came up after its session was given up; stopped"
                    );
                }
            },
        )
        .await;
        let (session_capture, capturer) = match started {
            Bounded::Done((session_capture, Ok(c))) => (session_capture, c),
            Bounded::Done((_, Err((stage, e)))) => {
                tracing::error!(session = %session_id, "{stage} failed: {e:#}");
                self.abort_setup(
                    session_id,
                    &peer.closer,
                    &peer.path,
                    end_reason::CAPTURE_ERROR,
                    outgoing,
                );
                return;
            }
            failed @ (Bounded::TimedOut | Bounded::Failed(_)) => {
                tracing::error!(
                    session = %session_id,
                    limit_ms = self.setup_limit.as_millis() as u64,
                    why = %failed.why_not(),
                    "capture start did not come back; the session is given up"
                );
                self.abort_setup(
                    session_id,
                    &peer.closer,
                    &peer.path,
                    end_reason::CAPTURE_ERROR,
                    outgoing,
                );
                return;
            }
        };
        let capturer = Arc::new(Mutex::new(capturer));

        let stop = Arc::new(AtomicBool::new(false));
        // Where this session's input may go, event by event: the desktop, or while game-only applies
        // to this session, the game's window alone (`crate::game_input`).
        let input_scope = Arc::new(crate::game_input::InputScopeSource::new(
            capture_mode.clone(),
            game_status.clone(),
        ));
        // A guest's presses, keys and text stop short of AFKLink's own windows: by the viewer's
        // role as decided for this session, kept current by every change of the roles.
        let own_windows = own_window_guard(&self.game_access, &session_id);
        // The input opens on a thread of its own: `begin_session` takes the input driver's slot lock
        // (and on the first session probes and opens the driver), and the reach read takes it too —
        // a lock a session still ending, or a stuck focus watch, may hold. Then the reach baseline,
        // after `begin_session` (the driver probed): what the session's end diffs against.
        let (injector, scope, guard, reach) = (
            self.backends.injector.clone(),
            input_scope.clone(),
            own_windows.clone(),
            self.reach.clone(),
        );
        let late_sid = session_id.clone();
        let opened = run_bounded(
            "input-open",
            &session_id,
            left(),
            move || {
                let t0 = Instant::now();
                let input = InputSession::with_scope(injector, scope).with_own_window_guard(guard);
                let open_ms = t0.elapsed().as_millis() as u64;
                let t1 = Instant::now();
                let reach_start = reach.read();
                tracing::debug!(
                    open_ms,
                    reach_ms = t1.elapsed().as_millis() as u64,
                    driver = reach_start.driver.as_str(),
                    "session input opened; reach baseline read"
                );
                (input, reach_start)
            },
            // An input that opened after its session was given up: closed, so the injector's
            // session count stays balanced.
            move |(input, _)| {
                input.refuse("it opened after its session was given up");
                input.close();
                tracing::warn!(
                    session = %late_sid,
                    "input opened after its session was given up; closed"
                );
            },
        )
        .await;
        let (input, reach_start) = match opened {
            Bounded::Done((input, reach_start)) => (Arc::new(input), reach_start),
            failed @ (Bounded::TimedOut | Bounded::Failed(_)) => {
                // No reason of its own in `SESSION_END_REASONS`: the agent's own fault, as the
                // viewer should hear it. Who holds the driver's lock, as far as the agent knows:
                // the input teardowns of earlier sessions and the releases still running (a stuck
                // one makes every later session's input time out here, until the app restarts).
                use crate::offload::running;
                tracing::error!(
                    session = %session_id,
                    limit_ms = self.setup_limit.as_millis() as u64,
                    why = %failed.why_not(),
                    input_end_running = running("input-end"),
                    input_close_running = running("input-close"),
                    release_all_running = running("release-all"),
                    input_open_running = running("input-open"),
                    abandoned = crate::offload::abandoned(),
                    "session input did not open (the input driver's lock is held); the session is \
                     given up"
                );
                self.teardown_capture(&session_id, capturer);
                self.abort_setup(
                    session_id,
                    &peer.closer,
                    &peer.path,
                    end_reason::INTERNAL_ERROR,
                    outgoing,
                );
                return;
            }
        };
        // Open from here until the session is registered below: a start that stops in between
        // closes it ([`UnregisteredInput`]).
        let unregistered = UnregisteredInput::arm(&session_id, &input, &stop);
        tokio::spawn(crate::own_windows::watch_task(
            own_windows,
            input.clone(),
            self.backends.injector.clone(),
            stop.clone(),
        ));
        // Clipboard sync for this session: off until the viewer turns it on, towards the PC only in
        // game-only mode, never echoing (`crate::clipboard`). Its task ends with the event task
        // below, which holds its only sender, or with `stop`.
        let clipboard_tx = crate::clipboard::spawn_session(
            session_id.clone(),
            self.clipboard.clone(),
            capture_mode.clone(),
            peer.control_tx.clone(),
            stop.clone(),
        );
        // The keyframe requests the encode thread honours whatever went before (the transport's, a
        // drain's end, the supervisor's, the Mini App's `kf`); and the viewer's PLIs and FIRs,
        // which it holds against the keyframe already on its way (`crate::keyframe_window`).
        let pending_kf = Arc::new(AtomicBool::new(false));
        let viewer_kf = Arc::new(crate::keyframe_window::ViewerAsks::default());
        // What the encode thread knows about the pipeline's health, read by the heartbeat below.
        let health = Arc::new(crate::pipeline::PipelineHealth::new(Instant::now()));
        // The session's summary for its reports (`crate::summary`): fed by the control task, the
        // heartbeat and the event task below, from the values their log lines print.
        let summary = Arc::new(
            crate::summary::SessionSummary::new(
                &session_id,
                Instant::now(),
                Some(peer.socket_bytes.clone()),
                Some(capture_mode.clone()),
                reach_start,
            )
            .with_quality_profile(&session_policy.label, session_policy.source),
        );

        // Encode thread (CPU-bound; std thread, not the async runtime).
        //
        // It also supervises the pipeline it runs: a capture that died or stalled and an encoder
        // that keeps failing are restarted from here, without ending the session, and given up on —
        // ending the session with a reason — only when they cannot be brought back. See
        // `crate::pipeline` for what is observed and what each observation leads to.
        {
            let sink = MediaSink {
                tx: peer.media_tx.clone(),
                queued_bytes: peer.queued_media_bytes.clone(),
                nacks: peer.nacks_received.clone(),
            };
            let stop = stop.clone();
            let target = target.clone();
            let counters = counters.clone();
            let supervisor = crate::pipeline::Supervisor::new(
                health.clone(),
                session_capture,
                capturer.clone(),
                frame_tx,
                target.clone(),
                pending_kf.clone(),
                Instant::now(),
            );
            let sess_ev_tx = self.sess_ev_tx.clone();
            let sid = session_id.clone();
            let viewer_kf = viewer_kf.clone();
            std::thread::Builder::new()
                .name(format!("encode-{session_id}"))
                .spawn(move || {
                    // Caught here as well as around each encode: a panic anywhere else in the loop
                    // must not leave the session up with nothing feeding it. The supervisor's `Drop`
                    // stops the capture during the unwind; this turns the panic into an ended
                    // session with a reason instead of a frozen picture.
                    let loop_stop = stop.clone();
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        encode_loop(
                            encoder,
                            frame_rx,
                            sink,
                            EncodeControl::ordinary(loop_stop),
                            target,
                            counters,
                            supervisor,
                            &viewer_kf,
                        )
                    }));
                    let reason = match outcome {
                        Ok(reason) => reason,
                        Err(panic) => {
                            tracing::error!(
                                "encode thread panicked: {}; ending the session",
                                panic_message(panic.as_ref())
                            );
                            Some(crate::pipeline::end_reason(
                                afklink_protocol::PipelineCause::EncoderError,
                            ))
                        }
                    };
                    match reason {
                        Some(reason) if !stop.load(Ordering::SeqCst) => {
                            if sess_ev_tx
                                .send(SessionSignal::PipelineFailed { id: sid, reason })
                                .is_err()
                            {
                                tracing::debug!(
                                    reason,
                                    "pipeline failure not delivered: the orchestrator is gone"
                                );
                            }
                        }
                        Some(reason) => tracing::debug!(
                            reason,
                            "pipeline gave up while the session was already ending"
                        ),
                        None => {}
                    }
                })
                .expect("spawn encode thread");
        }

        // Heartbeat task: once a second, and at once on every change, tell the viewer whether the
        // pipeline is alive — the one thing a frozen picture cannot say. See
        // `afklink_protocol::heartbeat`.
        tokio::spawn(heartbeat_task(
            health.clone(),
            target.clone(),
            game_status.clone(),
            self.helper_launch.clone(),
            self.reach.clone(),
            bg.clone(),
            peer.control_tx.clone(),
            stop.clone(),
            self.sess_ev_tx.clone(),
            session_id.clone(),
            summary.clone(),
        ));

        // Cursor reports: where the PC's cursor is, for the viewer's trackpad marker, with the
        // highest numbered relative move the event task below has handed to the injector — held
        // below any the cursor does not show yet, which the injector says with each sample. See
        // `crate::cursor_report`.
        let rel_ack = Arc::new(crate::cursor_report::RelAck::new());
        tokio::spawn(crate::cursor_report::cursor_report_task(
            self.backends.injector.clone(),
            peer.control_tx.clone(),
            stop.clone(),
            rel_ack.clone(),
            Some(input_scope.clone()),
            session_id.clone(),
        ));

        // Game-only mode: whether the game's window has the front, looked at while the viewer is
        // idle too — held input is released the moment another window takes it, and the heartbeat
        // says `unfocused`. Does nothing while the mode is off. See `crate::game_input`.
        tokio::spawn(crate::game_input::focus_watch_task(
            self.backends.injector.clone(),
            input_scope.clone(),
            stop.clone(),
            session_id.clone(),
        ));

        // Telemetry task: report cumulative totals while the session runs (`telemetry_task`); the
        // final report is the session's end's (`end_session`). Each with the session's summary.
        let stats = StatsSource::with_summary(
            counters.clone(),
            target.clone(),
            bg.clone(),
            summary.clone(),
        );
        {
            let outgoing = outgoing.clone();
            let stats = stats.clone();
            let stop = stop.clone();
            let sid = session_id.clone();
            // The last of the session's tasks to notice its end: when it stops, the session's log
            // file can close (`crate::session_log`).
            let session_log = self.session_log.clone();
            tokio::spawn(async move {
                telemetry_task(
                    stats,
                    outgoing,
                    stop,
                    sid.clone(),
                    Duration::from_millis(afklink_protocol::TELEMETRY_FIRST_REPORT_MS),
                    Duration::from_millis(afklink_protocol::TELEMETRY_INTERVAL_MS),
                )
                .await;
                if let Some(log) = session_log {
                    log.finished(&sid);
                }
            });
        }

        // When the viewer's `vv` reports reach the event task, as the control task reads it: what a
        // report's age is measured from (`SessionCounters::viewer_report_at_us`).
        let delivery_epoch = Instant::now();
        let media_peer = MediaPeerGauges::new(&peer);

        // Event task: forward input, keyframe requests, late local candidates, and lifecycle.
        {
            let input = input.clone();
            // Each numbered relative move the injector took, for the cursor report's `ack` (which
            // names it once the cursor shows it).
            let rel_ack = rel_ack.clone();
            let sess_ev_tx = self.sess_ev_tx.clone();
            // The input's close at the peer's end goes here, for the kill switch and the exit to
            // see and wait for.
            let teardowns = self.teardowns.clone();
            // For trickling local candidates found after the answer and answering ICE restarts;
            // see `LocalCandidate` and `Answer` below. The agent's outbox, so both reach whatever
            // connection is current — or wait in the relay for the next one — rather than the
            // connection this session happened to start on.
            let outgoing = outgoing.clone();
            let pending_kf = pending_kf.clone();
            let viewer_kf = viewer_kf.clone();
            // The background hold: the viewer's `vis`, and what else ends a hold — its input, a
            // `kf`, a `vv` saying visible — arrive here. See `crate::bg_hold`.
            let bg = bg.clone();
            // The viewer's jitter buffer and engine go to the peer's playout policy from here,
            // where its `vv` report arrives. See `afklink_transport::ViewerPlayout`.
            let playout_tx = peer.control_tx.clone();
            let sid = session_id.clone();
            // The viewer's Telegram platform goes to the journal from its reports (`crate::journal`).
            let journal = self.journal.clone();
            let mut events = peer.events;
            let counters = counters.clone();
            // The summary's `ice_restart` episodes: an answer to a re-offer with new ICE
            // credentials is a restart applied; one with the same is a repeated offer re-answered.
            let summary = summary.clone();
            let mut ufrag = crate::summary::ice_ufrag(&peer.answer_sdp).map(str::to_string);
            // The viewer's own quality choice lands here, because this is where its message
            // arrives. It is *relayed* and not acted on: the ladder lives on a fixed clock in the
            // control task below, and a second controller here is what made a pin not stick and
            // made every quality change drop the bitrate to the floor.
            let pin_request = pin_request.clone();
            // Counts the pointer moves that should have changed the captured screen: the evidence
            // a stalled capture is told from a still one by. See `crate::pipeline::PointerProbe`.
            // Not gathered when the injector moves no pointer (the bench's `--no-input`): a move
            // that never happened is no evidence of anything.
            let mut pointer = if self.backends.injector.moves_pointer() {
                Some(crate::pipeline::PointerProbe::new(health.clone()))
            } else {
                tracing::debug!(
                    session = %session_id,
                    "pointer-move stall evidence off: this injector moves no pointer"
                );
                None
            };
            tokio::spawn(async move {
                let mut silence = InputSilence::new();
                // Input is the hot path here — a moving mouse is sixty messages a second — so it
                // is counted, and the count is one debug line every ten seconds while there is any.
                let mut tally = InputTally::default();
                // The viewer's reports on its decoder and screen, and its own keyframe requests.
                // See `crate::viewer_report`.
                let mut viewer_log = crate::viewer_report::ViewerReportLog::default();
                // The journal has the viewer's platform (or there is no journal): its reports stop
                // being looked at for it. Until then each report that names one offers it, since
                // the first may come before the journal's entry opens with the video.
                let mut platform_noted = journal.is_none();
                // Whether a `vis` the parser refused has been warned about: once a session, the
                // rest go to the input tally's count.
                let mut bad_vis_warned = false;
                // Why the peer ended, which becomes the session's end reason.
                let end = loop {
                    if !input.is_active() {
                        tracing::debug!(session = %sid, "input event task stopped: session already ended");
                        break transport::PeerEnd::Closed;
                    }
                    tally.flush_if_due(Instant::now(), &sid);
                    // A viewer that is killed mid-drag sends nothing — no up, no `ra`,
                    // no close. Silence is therefore the only signal left, and after it
                    // the button is still held on the owner's desktop. The timeout is
                    // measured from any viewer data-channel message, including vv/vl telemetry,
                    // independently of local transport events. Check before receiving as well:
                    // a continuously ready queue must not starve this release.
                    if silence.release_due(Instant::now()) {
                        tracing::debug!(session = %sid, "input silence expired: releasing held input");
                        input.release_all();
                    }
                    let ev = match tokio::time::timeout(
                        silence.remaining(Instant::now()),
                        events.recv(),
                    )
                    .await
                    {
                        Ok(Some(ev)) => ev,
                        // Channel closed without the peer's own last word: it is gone all the same.
                        Ok(None) => {
                            tracing::debug!(
                                session = %sid,
                                "peer event channel closed without a Disconnected"
                            );
                            break transport::PeerEnd::Closed;
                        }
                        // The next loop checks the viewer-liveness deadline before receiving again.
                        Err(_) => continue,
                    };
                    // Count raw InputData before parsing: even an invalid viewer message proves
                    // the viewer is still alive. LinkStats/BitrateEstimate cannot extend this.
                    silence.note_peer_event(Instant::now(), &ev);
                    match ev {
                        // A message longer than the contract's `INPUT_MAX_BYTES` is not parsed.
                        // Every message a viewer sends fits it, a clipboard chunk included (its text
                        // is cut to fit: `afklink_protocol::clipboard::CLIPBOARD_CHUNK_TEXT_BYTES`).
                        // Counted in the input line, the first said at once.
                        PeerEvent::InputData(bytes)
                            if bytes.len() > afklink_protocol::INPUT_MAX_BYTES =>
                        {
                            tally.oversized(&sid, bytes.len());
                        }
                        PeerEvent::InputData(bytes) => {
                            if let Ok(s) = std::str::from_utf8(&bytes) {
                                match InputMessage::parse(s) {
                                    // Not an input event: the viewer is saying how much a pixel
                                    // is worth. Handled here rather than passed to the injector,
                                    // which has no business with it.
                                    Ok(InputMessage::Quality { q }) => {
                                        // A resolution the viewer pinned, or "auto" to hand the
                                        // choice back. Parsed here rather than passed to the
                                        // injector, which has no business with it.
                                        let pin = parse_quality_pin(&q);
                                        match pin {
                                            Some(height) => {
                                                tracing::info!(
                                                    pinned = ?height,
                                                    "viewer set quality"
                                                );
                                                pin_request.store(
                                                    height.unwrap_or(PIN_AUTO),
                                                    Ordering::Relaxed,
                                                );
                                            }
                                            // A viewer on a newer build, or a value we do not
                                            // offer. Ignoring is the safe answer: the current
                                            // setting keeps working.
                                            None => tracing::debug!("unknown quality {q:?}"),
                                        }
                                    }
                                    // The viewer's end-to-end latency. Recorded, not acted on —
                                    // see the field docs.
                                    Ok(InputMessage::ViewerLatency {
                                        jbuf_ms,
                                        frames,
                                        jitter_ms,
                                    }) => {
                                        note_viewer_latency(
                                            &counters, jbuf_ms, frames, jitter_ms, &sid,
                                        );
                                    }
                                    // What the viewer decoded and what reached its screen. Logged
                                    // and put on the pipeline line; its jitter buffer and engine go
                                    // on to the peer, whose playout release follows the buffer.
                                    Ok(InputMessage::ViewerVideo(report)) => {
                                        // A page that reports itself visible is looking: a hold
                                        // in force ends (only that way — `vv` is advisory and
                                        // never begins one).
                                        if report.visibility.as_deref() == Some("visible") {
                                            bg.on_trigger(
                                                crate::bg_hold::Trigger::ViewerVisible,
                                                Instant::now(),
                                            );
                                        }
                                        if !platform_noted {
                                            if let (Some(journal), Some(platform)) =
                                                (&journal, report.platform.as_deref())
                                            {
                                                platform_noted = journal.session_platform(
                                                    &sid,
                                                    platform,
                                                    crate::journal::now_ms(),
                                                );
                                            }
                                        }
                                        note_viewer_delivery(
                                            &counters,
                                            &report,
                                            delivery_epoch,
                                            &sid,
                                        );
                                        let playout = viewer_log.observe(
                                            Instant::now(),
                                            *report,
                                            &sid,
                                            &counters.viewer,
                                        );
                                        match playout_tx
                                            .try_send(PeerControl::ViewerPlayout(playout))
                                        {
                                            Ok(()) => {}
                                            // The next report is a second away, and a release
                                            // holds its max while it has none fresh: nothing is
                                            // lowered on a missing number.
                                            Err(mpsc::error::TrySendError::Full(_)) => {
                                                tracing::debug!(
                                                    session = %sid,
                                                    "viewer playout report not delivered: the \
                                                     peer's control queue is full (the next one \
                                                     follows in a second)"
                                                );
                                            }
                                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                                tracing::debug!(
                                                    session = %sid,
                                                    "viewer playout report not delivered: the \
                                                     peer has ended"
                                                );
                                            }
                                        }
                                    }
                                    // The viewer saw its picture stop and its browser sent no PLI.
                                    // The agent's own flag, bounded against a peer that asks on
                                    // every frame — and not held against a keyframe on its way as
                                    // a PLI is: it comes seconds apart, and on WebKit it is the
                                    // only way back (`crate::keyframe_window`, "Whose requests").
                                    Ok(InputMessage::KeyframeRequest { reason }) => {
                                        // A viewer asking for a picture wants one: a hold ends,
                                        // and its resume opens with a keyframe anyway.
                                        bg.on_trigger(
                                            crate::bg_hold::Trigger::Keyframe,
                                            Instant::now(),
                                        );
                                        if viewer_log.keyframe_request(
                                            Instant::now(),
                                            reason.as_deref(),
                                            &sid,
                                        ) {
                                            pending_kf.store(true, Ordering::SeqCst);
                                        }
                                    }
                                    // The page hidden or visible again: the background hold's own
                                    // signal. A state, not input — never handed to the injector.
                                    Ok(InputMessage::Visibility { hidden, why }) => {
                                        bg.on_vis(hidden, why.as_deref(), Instant::now());
                                    }
                                    // Clipboard sync: not input. The session's clipboard task
                                    // decides (`crate::clipboard`).
                                    Ok(InputMessage::ClipboardSync { on }) => forward_clipboard(
                                        &clipboard_tx,
                                        crate::clipboard::ViewerClipboard::Sync(on),
                                        &sid,
                                    ),
                                    Ok(InputMessage::ClipboardSet(chunk)) => forward_clipboard(
                                        &clipboard_tx,
                                        crate::clipboard::ViewerClipboard::Set(chunk),
                                        &sid,
                                    ),
                                    // A text longer than any viewer sends (it cuts at the
                                    // contract's 64) is dropped whole, not cut — see
                                    // `TEXT_MAX_CHARS`.
                                    Ok(InputMessage::Text { text, .. })
                                        if text_over_limit(&text) =>
                                    {
                                        tally.text_too_long(&sid, text.chars().count());
                                    }
                                    Ok(ie) => {
                                        // Real input ends a hold (not `ra`, which the viewer sends
                                        // as it hides). Before the injection, so the capture is
                                        // already starting while the input lands.
                                        if let Some(trigger) =
                                            crate::bg_hold::Trigger::of_input(&ie)
                                        {
                                            bg.on_trigger(trigger, Instant::now());
                                        }
                                        if let Some(pointer) = pointer.as_mut() {
                                            pointer.observe(&ie);
                                        }
                                        if matches!(ie, InputMessage::ReleaseAll) {
                                            silence.disarm();
                                            tracing::debug!(
                                                session = %sid,
                                                "viewer asked to release everything held"
                                            );
                                        }
                                        // As it arrived, before an injection that may block.
                                        tally.rhythm.note(Instant::now());
                                        match deliver_input(
                                            &input, &ie, &mut tally, &counters, &rel_ack, &sid,
                                        ) {
                                            Delivered::SessionEnded => {
                                                break transport::PeerEnd::Closed
                                            }
                                            Delivered::Injected
                                            | Delivered::HeldBack
                                            | Delivered::Failed => {}
                                        }
                                    }
                                    Err(e) => {
                                        let why = unparsed_input(s, &e);
                                        tracing::trace!(bytes = s.len(), "bad input json: {why}");
                                        // A `vis` refused leaves the two sides disagreeing on the
                                        // page's state until the viewer says it again (its
                                        // reconcile): worth a warning, once a session.
                                        if why.starts_with("vis:") && !bad_vis_warned {
                                            bad_vis_warned = true;
                                            tracing::warn!(
                                                session = %sid,
                                                bytes = s.len(),
                                                "viewer vis refused by the parser ({why}); the \
                                                 background hold keeps its state until the next one"
                                            );
                                        }
                                        tally.malformed(&sid, s.len(), &why);
                                    }
                                }
                            } else {
                                tally.malformed(&sid, bytes.len(), "not UTF-8");
                            }
                        }
                        PeerEvent::InputChannelClosed => {
                            tracing::debug!(session = %sid, "input channel closed: releasing held input");
                            input.release_all();
                        }
                        // Trace: the peer logs every viewer keyframe request (throttled) and every
                        // one of its own, and the encode thread logs what it decides and the
                        // keyframe it makes. The viewer's (its PLI or FIR) go to the encode thread
                        // with when they arrived, to be held against the keyframe already on its
                        // way; the peer's own never are: they say frames sent before are gone.
                        PeerEvent::KeyframeRequest(ask) => {
                            tracing::trace!(session = %sid, by = ask.as_str(), "keyframe requested");
                            if ask.from_viewer() {
                                viewer_kf.note(Instant::now());
                            } else {
                                pending_kf.store(true, Ordering::SeqCst);
                            }
                        }
                        PeerEvent::Connected => {
                            if sess_ev_tx
                                .send(SessionSignal::Connected(sid.clone()))
                                .is_err()
                            {
                                tracing::debug!(session = %sid, "connected, but the orchestrator is gone");
                            }
                        }
                        // An estimate is recorded and nothing else. No decision is taken here.
                        //
                        // Deciding in this handler would make the controller's clock the browser's
                        // to choose: the sampling interval would be whatever TWCC feedback happens
                        // to arrive at, and a link that stops producing estimates would freeze both
                        // the ladder and the budget — adaptation switched off by the *absence* of a
                        // signal. It runs on its own fixed tick; see the control task below.
                        PeerEvent::BitrateEstimate { kbps } => {
                            counters.estimate_kbps.store(kbps, Ordering::Relaxed);
                        }
                        // The far end's own account of what it received. Recorded here, acted on by
                        // the control task: it becomes one `ReceiverReport` on the controller's
                        // next tick, which drives the loss/round-trip brake. See
                        // `crate::quality::QualityController::take_brake_event`.
                        //
                        // A missing loss is stored as `u32::MAX`, not 0. str0m reports `None`
                        // exactly when no receiver report arrived in the interval
                        // (`streams/send_stats.rs:106-120`), and that is the brake's freshness
                        // signal; stored as 0 it would read as a clean report, and an empty
                        // interval and a lossless one would print the same.
                        PeerEvent::LinkStats {
                            rtt_ms,
                            loss,
                            plis,
                            nacks,
                            ..
                        } => {
                            note_receiver_report(&counters, rtt_ms, loss, plis, nacks);
                        }
                        // A local candidate found after the answer went out: today a srflx address
                        // whose STUN reply missed the answer's budget, without which a viewer that
                        // can only use its relay cannot reach this PC. Trickled the way the viewer
                        // trickles its own; the server relays agent `ice` to the viewer unchanged.
                        PeerEvent::LocalCandidate(candidate) => {
                            let line = candidate.candidate.clone();
                            if send_to_backend(
                                &outgoing,
                                AgentToServer::Ice {
                                    session_id: sid.clone(),
                                    candidate,
                                },
                            ) {
                                // To the relay, which forwards it, or holds it while signaling is
                                // down and says so.
                                tracing::debug!(session = %sid, candidate = %line, "local candidate trickled");
                            } else {
                                // The one candidate a relay-only viewer cannot connect without.
                                tracing::warn!(
                                    session = %sid,
                                    candidate = %line,
                                    "local candidate not trickled: the signaling relay is gone"
                                );
                            }
                        }
                        // The answer to the viewer's re-offer (an ICE restart). Sent from here, not
                        // from where the offer arrived, so that it stays ahead of any candidate the
                        // restart trickles next: both come down this one channel in order, and the
                        // relay keeps that order whether it forwards them or holds them.
                        PeerEvent::Answer(sdp) => {
                            let bytes = sdp.len();
                            let new_ufrag = crate::summary::ice_ufrag(&sdp).map(str::to_string);
                            if new_ufrag != ufrag {
                                summary.instant(
                                    Instant::now(),
                                    afklink_protocol::metrics::SessionEpisodeKind::IceRestart,
                                    None,
                                );
                                ufrag = new_ufrag;
                            } else {
                                tracing::debug!(
                                    session = %sid,
                                    "the re-offer's answer has the same ICE credentials: a repeated \
                                     offer answered again, not a restart"
                                );
                            }
                            if send_to_backend(
                                &outgoing,
                                AgentToServer::Sdp {
                                    session_id: sid.clone(),
                                    sdp_type: SdpType::Answer,
                                    sdp,
                                },
                            ) {
                                tracing::info!(
                                    session = %sid,
                                    bytes,
                                    "answer to the viewer's re-offer sent"
                                );
                            } else {
                                tracing::warn!(
                                    session = %sid,
                                    bytes,
                                    "the re-offer's answer is lost: the signaling relay is gone"
                                );
                            }
                        }
                        // ICE lost the path. The session stays up for the grace window, waiting
                        // for the viewer's ICE restart (`transport::ICE_GRACE`), but nothing held
                        // may stay held through it: a button-up cannot cross a dead path.
                        PeerEvent::LinkLost => {
                            tracing::info!(
                                session = %sid,
                                grace_s = transport::ICE_GRACE.as_secs(),
                                "ICE path lost: held input released; waiting for the viewer to \
                                 restart ICE"
                            );
                            input.release_all();
                        }
                        PeerEvent::Disconnected { reason } => {
                            tracing::debug!(
                                session = %sid,
                                ?reason,
                                by_viewer = reason.by_viewer(),
                                "peer ended"
                            );
                            break reason;
                        }
                    }
                };
                tally.flush(&sid);
                viewer_log.finish(&sid);
                // Whatever the peer was holding, it is not going to release it now. On a thread of
                // its own: the close waits on the input driver's slot lock, and the end below must
                // reach the orchestrator whatever holds it.
                input.refuse("the peer ended");
                let closing = input.clone();
                let closed = crate::offload::detach("input-close", &sid, move || closing.close());
                keep_teardown(&teardowns, closed);
                if sess_ev_tx
                    .send(SessionSignal::Closed {
                        id: sid.clone(),
                        end,
                    })
                    .is_err()
                {
                    tracing::debug!(session = %sid, ?end, "peer end not delivered: the orchestrator is gone");
                }
            });
        }

        spawn_media_control(
            media_peer,
            MediaControl {
                session_id: session_id.clone(),
                policy,
                quality_pref,
                initial_desired_kbps,
                qp_ceiling,
                delivery_epoch,
                target: target.clone(),
                counters: counters.clone(),
                stop: stop.clone(),
                pin_request,
                game_status: game_status.clone(),
                pending_kf,
                bg: bg.clone(),
                health: health.clone(),
                summary: MediaObservation(Some(summary.clone())),
                journal: self.journal.clone(),
                calibrate: calibration_armed(),
            },
        );

        // Register the session. `pending` was checked at the top of this
        // function and the orchestrator serves one message at a time, so a
        // missing entry here is unreachable — but a fallback uid of 0 would
        // lie to the UI about who is watching, so close the peer rather than
        // invent an owner.
        let Some(request) = self.pending.remove(&session_id) else {
            tracing::error!("session {session_id} lost its request mid-setup; closing the peer");
            self.game_access.close(&session_id);
            // The stop flag first: the encode thread holds a sender of its own and does not exit
            // on a closed channel, and the tasks above all watch this flag.
            stop.store(true, Ordering::SeqCst);
            input.refuse("the session lost its request mid-setup");
            let input_job =
                crate::offload::detach("input-close", &session_id, move || input.close());
            self.keep_teardown(input_job);
            close_peer(&peer.closer, &session_id);
            self.teardown_capture(&session_id, capturer.clone());
            self.emit(AgentEvent::SessionEnded {
                session_id: session_id.clone(),
                reason: end_reason::INTERNAL_ERROR.into(),
            });
            let reported = stats.report(outgoing, &session_id, true);
            tracing::debug!(session = %session_id, outcome = ?reported, "final session report");
            let detail = end_detail(&session_id, &peer.path.get(), None);
            send_to_backend(
                outgoing,
                AgentToServer::SessionEnd {
                    session_id,
                    reason: Some(end_reason::INTERNAL_ERROR.into()),
                    detail,
                },
            );
            return;
        };
        let (uid, username) = (request.telegram_user_id, request.username);
        tracing::info!(
            session = %session_id,
            telegram_user_id = uid,
            setup_ms = setup_started.elapsed().as_millis() as u64,
            live = self.sessions.len() + 1,
            "session started: capture, encoder and peer running"
        );

        {
            // The name the toasts and the window show. `session_request` has no first name, so the
            // binding this session was admitted on supplies it (`person_name::session_names`).
            let mut s = lock(&self.state);
            let names =
                crate::person_name::session_names(&s.bindings, &session_id, uid, username.clone());
            s.sessions.push(SessionInfo {
                session_id: session_id.clone(),
                telegram_user_id: uid,
                username: names.username,
                first_name: names.first_name,
                connected: false,
                connected_at: None,
            });
        }
        self.emit(AgentEvent::SessionStarted {
            session_id: session_id.clone(),
            telegram_user_id: uid,
        });

        // A test's panic between the input's opening and the registration.
        #[cfg(test)]
        if self.panic_before_register {
            panic!("a session start panics before its registration (a test)");
        }
        unregistered.disarm();
        self.sessions.insert(
            session_id,
            Session {
                telegram_user_id: uid,
                username,
                signals: peer.signals,
                closer: peer.closer,
                capturer,
                stop,
                input,
                stats,
                reach_start,
                capture_mode,
                path: peer.path,
            },
        );
    }

    /// Tear a session down.
    ///
    /// `reason` reaches the backend and is stored against the session. It matters: "the viewer
    /// hung up" and "the owner hit the kill switch" are the same event from here and very
    /// different events in a week's worth of history; reporting both as "agent" would make the
    /// second invisible.
    fn end_session(
        &mut self,
        session_id: &str,
        notify_backend: bool,
        reason: &str,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
    ) {
        self.end_session_with(session_id, notify_backend, reason, None, outgoing);
    }

    /// [`Self::end_session`], with what the agent knows of how `reason` came about
    /// (`ended_detail`, `SESSION_END_DETAILS`): `peer_closed` split into the viewer's goodbye and
    /// str0m's own close.
    ///
    /// Every end of a running session sends its final report (`"final": true`) — the agent's own,
    /// before its `session_end`, so it lands on the live session; the backend's, after the backend
    /// ended it, into its tombstone. The agent's own `session_end` carries the
    /// peer's path (`transport::PeerPath`): how far it got, the DTLS verdict, the pair's kinds.
    fn end_session_with(
        &mut self,
        session_id: &str,
        notify_backend: bool,
        reason: &str,
        ended_detail: Option<&'static str>,
        outgoing: &mpsc::UnboundedSender<AgentToServer>,
    ) {
        if let Some(sess) = self.sessions.remove(session_id) {
            // "session ended", not the wire name: `session_end` lines are the backend's word.
            tracing::info!(
                session = session_id,
                reason,
                ended_detail = ended_detail.unwrap_or("-"),
                telegram_user_id = sess.telegram_user_id,
                username = ?sess.username,
                notify_backend,
                live = self.sessions.len(),
                "session ended: tearing down peer, capture and encoder"
            );
            // Before the peer goes: a session can end while a button is down (the viewer
            // hit disconnect, the owner hit the kill switch, the backend revoked it), and
            // once the channel is closed nobody can release it.
            sess.stop.store(true, Ordering::SeqCst);
            // From this moment no event of the session is injected: refused here, on the
            // orchestrator, without a lock — its gate's close and release run on a thread of their
            // own below, and may wait on the driver; the viewer's queued events must not land
            // meanwhile (a kill switch means now).
            sess.input.refuse(reason);
            // The session's last report, whoever ended it: before the agent's own `session_end`,
            // after the backend's. Held by the relay through an outage for as long as the backend
            // would still take it (`crate::relay`).
            let reported = sess.stats.report(outgoing, session_id, true);
            tracing::debug!(
                session = session_id,
                reason,
                outcome = ?reported,
                duration_ms = sess.stats.started.elapsed().as_millis() as u64,
                "final session report"
            );
            // Not decided any more, nor counted for the game helper (`crate::game_access`).
            self.game_access.close(session_id);
            // The input's end and the capture's stop can each wait without bound — the driver's
            // slot lock, the WGC or game capture thread's join — so each goes to a thread of its
            // own and the orchestrator does not wait for either (`crate::offload`). Two threads,
            // not one: an input stuck on the driver must not keep the screen captured, nor a stuck
            // capture keep keys held.
            self.teardown_input(session_id, sess.input.clone(), sess.reach_start);
            // The encode thread sees this within `pipeline::SUPERVISE_EVERY` and exits, stopping
            // the capture on its way out; the capture is also stopped here, directly, in case that
            // thread is stuck inside an encode and will not get there.
            close_peer(&sess.closer, session_id);
            self.teardown_capture(session_id, sess.capturer.clone());
            if notify_backend {
                let detail = end_detail(session_id, &sess.path.get(), ended_detail);
                send_to_backend(
                    outgoing,
                    AgentToServer::SessionEnd {
                        session_id: session_id.to_string(),
                        reason: Some(reason.to_string()),
                        detail,
                    },
                );
            }
            self.emit(AgentEvent::SessionEnded {
                session_id: session_id.to_string(),
                reason: reason.to_string(),
            });
        } else {
            // Ordinary: the peer's own end arriving after the backend already ended it, or the
            // other way round. Said so the second of the two is not a mystery.
            let was_pending = self.pending.remove(session_id).is_some();
            tracing::debug!(
                session = session_id,
                reason,
                was_pending,
                "end for a session that is not running"
            );
            if was_pending {
                // A request the backend (or the viewer) ended before its offer: no `SessionEnded`
                // is announced for it, but its log file closes.
                self.log_ended(session_id, reason);
            }
        }
        self.pending.remove(session_id);
        {
            let mut s = lock(&self.state);
            s.sessions.retain(|x| x.session_id != session_id);
        }
    }

    /// A session's input ends on a thread of its own (`crate::offload::detach`), the orchestrator
    /// not waiting, in this order:
    ///
    /// 1. the gate closes and what the session holds is released (`InputSession::close_gate`): no
    ///    event of an ended session is injected — not after the kill switch either — and no key it
    ///    holds waits for the accounting;
    /// 2. its reach account (`crate::input_reach`), which reads the injector's reach watch and may
    ///    write config.json (the highlight): after the release, which sends no press and so counts
    ///    nothing; before the injector session ends, as the last session's end resets that watch;
    /// 3. its injector session ends (the last one closes the driver).
    ///
    /// Each takes the input driver's slot lock, which the game-focus watch and every injection hold
    /// across Win32 calls.
    ///
    /// Before any of it, here on the orchestrator and without a lock, the session's input is
    /// refused (`InputSession::refuse`): from the moment its end is decided no event of it is
    /// injected, whatever the thread below waits on.
    ///
    /// "No session left" for the account is counted when the account is made, from the sessions
    /// live then (a newer session may have started meanwhile, or the others ended), not when the
    /// end was decided.
    fn teardown_input(
        &mut self,
        session_id: &str,
        input: Arc<InputSession>,
        reach_start: crate::traits::InputReach,
    ) {
        input.refuse("the session ended");
        let reach = self.reach.clone();
        let state = self.state.clone();
        let sid = session_id.to_owned();
        let job = crate::offload::detach("input-end", session_id, move || {
            let t0 = Instant::now();
            // False: another close got there first (the peer's end, in the event task), and ends
            // the injector session itself.
            let closed_here = input.close_gate();
            let gate_ms = t0.elapsed().as_millis() as u64;
            let t1 = Instant::now();
            let sessions_left = lock(&state)
                .sessions
                .iter()
                .filter(|s| s.session_id != sid)
                .count();
            reach.session_ended(&sid, reach_start, sessions_left);
            let reach_ms = t1.elapsed().as_millis() as u64;
            let t2 = Instant::now();
            if closed_here {
                input.end_injector_session();
            }
            tracing::debug!(
                session = %sid,
                closed_here,
                sessions_left,
                gate_ms,
                reach_ms,
                end_ms = t2.elapsed().as_millis() as u64,
                "session input ended (gate closed and released, reach account, injector session \
                 ended)"
            );
        });
        self.keep_teardown(job);
    }

    /// A session's capture stops on a thread of its own ([`stop_capture`] there), the orchestrator
    /// not waiting: a WGC stop joins its capture thread and a game capture's joins its director,
    /// neither with a bound.
    fn teardown_capture(&mut self, session_id: &str, capturer: Arc<Mutex<Box<dyn Capturer>>>) {
        let sid = session_id.to_owned();
        let job = crate::offload::detach("capture-stop", session_id, move || {
            stop_capture(&capturer, &sid);
        });
        self.keep_teardown(job);
    }

    /// Keep a teardown for the exit to wait for (bounded, [`EXIT_TEARDOWN_WAIT`]); finished ones are
    /// let go here.
    fn keep_teardown(&mut self, job: crate::offload::JobDone) {
        keep_teardown(&self.teardowns, job);
    }

    /// Release every key and button the injector holds, on a thread of its own (the kill switch,
    /// the exit, `device_blocked`, `replaced`): the driver's slot lock may be held by a stuck call,
    /// and the orchestrator must not wait on it. `why` names the caller in the log.
    fn release_all_detached(&mut self, why: &'static str) {
        let injector = self.backends.injector.clone();
        let job = crate::offload::detach_for("release-all", why, move || injector.release_all());
        tracing::debug!(
            why,
            release_all_running = crate::offload::running("release-all"),
            "release of all held input handed to a thread of its own; the orchestrator does not \
             wait for it"
        );
        self.keep_teardown(job);
    }

    /// The teardowns still running, by name (`what (session)`), for a line about them.
    fn teardowns_running(&self) -> Vec<String> {
        lock(&self.teardowns)
            .iter()
            .filter(|t| !t.is_done())
            .map(crate::offload::JobDone::describe)
            .collect()
    }

    /// Wait for the session teardowns still running, at most `limit` in all (the exit: a key held by
    /// a viewer must not outlive the process if the release can still be had). Says how many were
    /// left, and returns how many.
    async fn teardowns_done(&mut self, limit: Duration) -> usize {
        let taken = std::mem::take(&mut *lock(&self.teardowns));
        let pending: Vec<_> = taken.into_iter().filter(|t| !t.is_done()).collect();
        if pending.is_empty() {
            tracing::debug!("exit: no session teardown still running");
            return 0;
        }
        let count = pending.len();
        // One timeout around them all, and none at all when there is no time: on Windows each
        // timer costs up to a tick (~15.6 ms) even when already due.
        if !limit.is_zero() {
            let all = pending.clone();
            let waited = tokio::time::timeout(limit, async move {
                for job in all {
                    job.finished().await;
                }
            })
            .await;
            tracing::trace!(all_done = waited.is_ok(), "exit: teardown wait over");
        }
        let left: Vec<String> = pending
            .iter()
            .filter(|t| !t.is_done())
            .map(crate::offload::JobDone::describe)
            .collect();
        if left.is_empty() {
            tracing::debug!(
                count,
                "exit: every session teardown finished before the goodbye"
            );
        } else {
            tracing::warn!(
                count,
                left = left.len(),
                jobs = ?left,
                limit_ms = limit.as_millis() as u64,
                abandoned = crate::offload::abandoned(),
                "exit: session teardowns still running (stuck on the driver or a capture thread); \
                 the exit goes ahead without them"
            );
        }
        left.len()
    }
}

/// The agent's `session_end.detail`: `ended_detail` when the agent knows how
/// the reason came about, and the peer's path as it last published it — how far it got, the DTLS
/// verdict, how long DTLS took after ICE, the pair's candidate kinds, the relay's transport. Kinds
/// and verdicts only, never an address. A field the contract would refuse is left out (warn), so it
/// cannot cost the whole `session_end`; nothing left, no detail.
fn end_detail(
    session_id: &str,
    path: &transport::PeerPath,
    ended_detail: Option<&'static str>,
) -> Option<afklink_protocol::SessionEndDetail> {
    let mut detail = path.detail();
    detail.ended_detail = ended_detail.map(str::to_string);
    let (detail, dropped) = detail.keep_valid();
    if !dropped.is_empty() {
        tracing::warn!(
            session = session_id,
            dropped = ?dropped,
            "session_end detail: fields the contract would refuse left out"
        );
    }
    tracing::debug!(
        session = session_id,
        ended_detail = detail.ended_detail.as_deref().unwrap_or("-"),
        stage = detail.stage.as_deref().unwrap_or("-"),
        verdict = detail.verdict.as_deref().unwrap_or("-"),
        dtls_after_ice_ms = ?detail.dtls_after_ice_ms,
        pair_local_kind = detail.pair_local_kind.as_deref().unwrap_or("-"),
        pair_remote_kind = detail.pair_remote_kind.as_deref().unwrap_or("-"),
        relay_transport = detail.relay_transport.as_deref().unwrap_or("-"),
        "session_end detail"
    );
    (!detail.is_empty()).then_some(detail)
}

/// `ended_detail` for a peer's own end (`SESSION_END_DETAILS.peer_closed`): the viewer said
/// goodbye, or str0m closed by itself. `None` for any other end — the orchestrator's close
/// ([`transport::PeerEnd::Closed`]) and the ends with a reason of their own.
fn peer_ended_detail(end: transport::PeerEnd) -> Option<&'static str> {
    use afklink_protocol::metrics::ended_detail;
    match end {
        transport::PeerEnd::ViewerClosed => Some(ended_detail::VIEWER),
        transport::PeerEnd::RtcClosed => Some(ended_detail::RTC),
        transport::PeerEnd::Closed
        | transport::PeerEnd::IceTimeout
        | transport::PeerEnd::RestartFailed
        | transport::PeerEnd::Error => None,
    }
}

/// Stop a session's capture: on the teardown's own thread ([`Agent::teardown_capture`]), never on
/// the orchestrator — the stop itself joins the capture's thread without a bound.
///
/// `try_lock`, because the encode thread holds this lock across a capture restart, and a restart
/// can wait on the WGC thread. If the lock is busy, the stop flag the caller has already set is
/// enough: the encode thread checks it after the restart and stops the capture on its way out
/// (`pipeline::Supervisor`'s `Drop`).
fn stop_capture(capturer: &Mutex<Box<dyn Capturer>>, session_id: &str) {
    let t0 = Instant::now();
    let how = match capturer.try_lock() {
        Ok(mut c) => {
            c.stop();
            "stopped"
        }
        // A panic on the encode thread while it held the capturer; the capturer itself is still
        // stoppable (see `crate::sync`), and stopping it is the point.
        Err(std::sync::TryLockError::Poisoned(p)) => {
            tracing::debug!(
                "session {session_id}: capturer lock poisoned by a panic; stopping it anyway"
            );
            p.into_inner().stop();
            "stopped (lock poisoned)"
        }
        Err(std::sync::TryLockError::WouldBlock) => {
            "left to the encode thread: the capture is mid-restart; it stops it on exit"
        }
    };
    tracing::debug!(
        session = session_id,
        took_ms = t0.elapsed().as_millis() as u64,
        "capture stop: {how}"
    );
}

/// The message a panic carried, for the log line that replaces it.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic with no message".to_string())
}

/// Tell the viewer, once a second and at once on every change, whether the pipeline is alive.
///
/// A still desktop and a dead pipeline both send no video, and the link stays up under both; this
/// is the agent saying which. It is also the one observer that can see the encode thread stuck
/// inside a call — the thread cannot report on itself from there — so a stuck call is reported
/// `stalled` from here and, past `pipeline::BUSY_FATAL_AFTER`, ends the session.
///
/// It also says whether the PC has the input driver and whether the viewer's presses reach the
/// window in front (`no_driver`, `input_blocked`: `crate::input_reach`), looked at on every
/// heartbeat — which is also what sets the window's «Управление не доходит» highlight — and, in
/// the game-only mode, whether the game helper launched the game and waits for its window
/// (`game.launching`, `crate::game::HelperLaunch`; only while the window is absent or starting).
///
/// Logging: every change of what the heartbeat says at debug, with its whole content; the heartbeat
/// itself at trace, once a second. Transitions of the pipeline are logged at info by the supervisor
/// that makes them, not here; the helper's launch by `HelperLaunch::set`.
#[allow(
    clippy::too_many_arguments,
    reason = "the session's shared pieces, each an `Arc` or a channel the heartbeat reads"
)]
async fn heartbeat_task(
    health: Arc<crate::pipeline::PipelineHealth>,
    target: Arc<crate::quality::QualityTarget>,
    game: Arc<crate::game::GameStatus>,
    launch: Arc<crate::game::HelperLaunch>,
    reach: Arc<crate::input_reach::ReachMonitor>,
    bg: Arc<crate::bg_hold::BgHold>,
    control_tx: mpsc::Sender<PeerControl>,
    stop: Arc<AtomicBool>,
    sess_ev_tx: mpsc::UnboundedSender<SessionSignal>,
    sid: String,
    summary: Arc<crate::summary::SessionSummary>,
) {
    use crate::pipeline::{cause_str, BusyVerdict};
    use afklink_protocol::{AgentDataMessage, GameHeartbeat, PipelineCause, PipelineState};

    let mut tick = tokio::time::interval(Duration::from_millis(
        afklink_protocol::HEARTBEAT_INTERVAL_MS,
    ));
    // A late tick is skipped, not made up: a burst of identical heartbeats says nothing.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut seq: u64 = 0;
    type Summary = (
        PipelineState,
        Option<PipelineCause>,
        bool,
        bool,
        Option<GameHeartbeat>,
        (bool, bool),
        bool,
    );
    let mut last: Option<Summary> = None;
    let mut stuck = false;
    let mut fatal_sent = false;
    // A fatal verdict is acted on only once the same stuck call has been seen fatal for a whole
    // heartbeat interval: see `BusyVerdict` on why a single sighting after a sleep is not enough.
    let mut fatal_seen: Option<(u64, Instant)> = None;
    let confirm_after = Duration::from_millis(afklink_protocol::HEARTBEAT_INTERVAL_MS);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = health.changed().notified() => {}
            // A game window minimized, restored, gone or resized reaches the viewer at once too.
            () = game.changed().notified() => {}
            // And the game helper's launch beginning or ending.
            () = launch.changed().notified() => {}
            // And a background hold beginning or ending: the viewer reconciles on `bg_hold`.
            () = bg.changed().notified() => {}
        }
        if stop.load(Ordering::SeqCst) {
            tracing::debug!(sent = seq, "heartbeat stopped: the session is ending");
            break;
        }
        let now = Instant::now();
        let (mut hb, verdict) = health.heartbeat(now, seq, target.max_h(), target.fps());
        // The background hold: video held back on purpose because the viewer's page is hidden
        // (`crate::bg_hold`). The pipeline's state stays `ok`.
        hb.bg_hold = bg.is_held();
        // Drain mode: the pipeline is fine and sends nothing on purpose while the network path
        // drains a backlog. Said as the network's stall, never as the PC's: the state stays what
        // the pipeline says. See `QualityController::draining`. Not during a hold, which
        // supersedes it: no frame is sent either way, and the hold is what the viewer must hear.
        hb.net_stall = target.draining() && !hb.bg_hold;
        // «Only the game window»: the window's state and picture size; absent outside the mode. With
        // the window absent or starting, whether the game helper launched it and waits for it — the
        // viewer's «Игра запускается» rather than «Игра не запущена».
        hb.game = game
            .heartbeat()
            .map(|g| g.with_launching(launch.is_launching()));
        // «Нужен драйвер на ПК» on the phone: the driver missing where it could be installed, and
        // the viewer's presses dropped by an administrator's window for want of it.
        // Off the worker (`block_in_place`): the read takes the input driver's slot lock, which the
        // focus watch and every injection hold across Win32 calls, and a stuck holder must not
        // stop this worker's timers and I/O with it. Once a second: the hand-off's cost is nothing.
        let input = crate::input_session::blocking(|| reach.poll(&sid));
        hb.no_driver = input.driver == crate::traits::DriverPresence::Missing;
        hb.input_blocked = input.blocked;
        // The same reading for the session's summary: the driver it had, the presses blocked.
        summary.note_reach(&input);
        seq += 1;

        match verdict {
            BusyVerdict::Clear => {
                if stuck {
                    tracing::info!("the encode thread's stuck call returned");
                    stuck = false;
                }
                fatal_seen = None;
            }
            BusyVerdict::Stalled { what, for_ms, .. } => {
                if !stuck {
                    tracing::warn!(
                        call = what.as_str(),
                        for_ms,
                        "the encode thread is stuck in a call that has not returned; the pipeline \
                         is reported stalled"
                    );
                    stuck = true;
                }
            }
            BusyVerdict::Fatal {
                what,
                for_ms,
                episode,
            } => {
                let first_seen = match fatal_seen {
                    Some((e, at)) if e == episode => at,
                    _ => {
                        tracing::debug!(
                            call = what.as_str(),
                            for_ms,
                            "stuck call past the fatal limit; confirming on the next heartbeat"
                        );
                        fatal_seen = Some((episode, now));
                        now
                    }
                };
                if !fatal_sent && now.saturating_duration_since(first_seen) >= confirm_after {
                    let reason = crate::pipeline::end_reason(what.cause());
                    tracing::error!(
                        call = what.as_str(),
                        for_ms,
                        reason,
                        "the encode thread has been stuck for too long and nothing can interrupt \
                         it; ending the session"
                    );
                    fatal_sent = true;
                    if sess_ev_tx
                        .send(SessionSignal::PipelineFailed {
                            id: sid.clone(),
                            reason,
                        })
                        .is_err()
                    {
                        tracing::debug!("pipeline failure not delivered: the orchestrator is gone");
                    }
                }
            }
        }

        let summary = (
            hb.state,
            hb.cause,
            hb.still,
            hb.net_stall,
            hb.game,
            (hb.no_driver, hb.input_blocked),
            hb.bg_hold,
        );
        let opt = |v: Option<u64>| v.map_or_else(|| "-".to_string(), |v| v.to_string());
        if last != Some(summary) {
            last = Some(summary);
            tracing::debug!(
                seq = hb.seq,
                state = hb.state.as_str(),
                cause = cause_str(hb.cause),
                since_capture_ms = %opt(hb.since_capture_ms),
                since_encode_ms = %opt(hb.since_encode_ms),
                still = hb.still,
                net_stall = hb.net_stall,
                rung = %format!("{}p@{}", hb.h, hb.fps),
                restarts = hb.restarts,
                game = hb.game.map_or("-", |g| g.state.as_str()),
                game_src = %hb.game.and_then(|g| g.w.zip(g.h)).map_or_else(
                    || "-".to_string(),
                    |(w, h)| format!("{w}x{h}")
                ),
                game_launching = hb.game.is_some_and(|g| g.launching),
                helper_launching = launch.is_launching(),
                no_driver = hb.no_driver,
                input_blocked = hb.input_blocked,
                driver = input.driver.as_str(),
                vis_ok = hb.vis_ok,
                bg_hold = hb.bg_hold,
                "heartbeat changed"
            );
        } else {
            tracing::trace!(
                seq = hb.seq,
                state = hb.state.as_str(),
                since_capture_ms = %opt(hb.since_capture_ms),
                since_encode_ms = %opt(hb.since_encode_ms),
                still = hb.still,
                "heartbeat"
            );
        }

        match AgentDataMessage::Heartbeat(hb).to_json() {
            Ok(json) => match control_tx.try_send(PeerControl::SendHeartbeat(json)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::debug!("heartbeat dropped: the peer's control queue is full");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    tracing::debug!(sent = seq, "heartbeat stopped: the peer is gone");
                    break;
                }
            },
            Err(e) => tracing::warn!("heartbeat could not be serialised: {e}"),
        }
    }
}

/// Whether the scripted calibration sweep is armed.
///
/// One definition, read by the three places that need it — the startup banner, the control task
/// and the encode thread — because three separate `env::var` calls is three chances for them to
/// disagree about what mode the process is in.
fn calibration_armed() -> bool {
    std::env::var("AFKLINK_CALIBRATE").is_ok_and(|v| v == "1")
}

/// Walks [`crate::quality::CALIBRATION`], holding each point long enough to measure it.
///
/// Enabled by setting `AFKLINK_CALIBRATE=1` in the environment. Off by default and inert in a
/// normal build: a mode that changes what the product does must be impossible to enter by accident.
struct CalibrationSweep {
    started: Instant,
    /// How many points have been entered, so the log can say "7 of 24".
    index: usize,
    finished: bool,
}

impl CalibrationSweep {
    /// `Some(point)` on the tick a new point begins, `None` otherwise.
    ///
    /// Driven by elapsed time rather than a tick count so a stalled runtime shortens the sweep
    /// rather than silently stretching every measurement window.
    fn step(&mut self) -> Option<crate::quality::CalibrationPoint> {
        if self.index >= crate::quality::CALIBRATION.len() {
            return None;
        }
        let due = crate::quality::CALIBRATION_DWELL * u32::try_from(self.index).unwrap_or(u32::MAX);
        if self.started.elapsed() < due {
            return None;
        }
        let point = crate::quality::CALIBRATION[self.index];
        self.index += 1;
        Some(point)
    }
}

/// The share of offered frames the brake may withhold before it is worth complaining about.
///
/// A tenth, which is well below the third at which the ladder's `throttled` arm sheds the rung —
/// the gap between them is the band where the picture is being held together by dropped frames and
/// nothing else in the system says so.
const FD_WARN_RATIO: f32 = 0.10;
/// How long it must stay there first. Longer than any keyframe takes to clear.
const FD_WARN_AFTER: Duration = Duration::from_secs(3);
/// And how often the complaint may repeat. A warning per 200 ms tick would be the fault's own
/// denial-of-service.
const FD_WARN_EVERY: Duration = Duration::from_secs(10);

/// The least time between two `brake tightened` lines. On a link dying for a minute the brake can
/// tighten on most receiver reports, which come once a second; the first one and every fifth second
/// say everything the rest would.
const BRAKE_TIGHTEN_LOG_EVERY: Duration = Duration::from_secs(5);

/// What the transport's `Peer::path_kind` value says, in the controller's words; `None` before the
/// media has taken a pair (or for a value this build does not know).
fn path_kind_of(v: u8) -> Option<crate::quality::PathKind> {
    use crate::quality::PathKind;
    match v {
        afklink_transport::webrtc::PATH_KIND_RELAY => Some(PathKind::Relay),
        afklink_transport::webrtc::PATH_KIND_REFLEXIVE => Some(PathKind::Reflexive),
        afklink_transport::webrtc::PATH_KIND_HOST => Some(PathKind::Host),
        _ => None,
    }
}

/// The `pipeline` line's `rtt_ms`, from the counters the last `LinkStats` stored: the round trip of
/// the receiver report the last stats interval carried, and `-` when it carried none.
///
/// str0m repeats the last report's round trip on an interval without a report
/// (`streams/send_stats.rs:89-90`); printed as is, that repeat reads as current (through a
/// ten-second blackout on the bench the line kept reading `rtt_ms="135"`). `loss_pct` prints `-`
/// for an empty interval; the round trip beside it says the same, and `report_age_ms` says how old
/// the last real one is. `u32::MAX` in either counter is "nothing reported".
fn rtt_field(rtt_ms: u32, loss_bp: u32) -> String {
    if rtt_ms == u32::MAX || loss_bp == u32::MAX {
        "-".to_string()
    } else {
        rtt_ms.to_string()
    }
}

/// The `pipeline` line's `report_age_ms`: milliseconds since the last fresh receiver report, as the
/// controller counts it on its own tick, or `-` before the first one.
fn report_age_field(age: Option<Duration>) -> String {
    age.map_or_else(|| "-".to_string(), |a| a.as_millis().to_string())
}

/// The send queue at which [`encode_loop`] stops making frames for a moment, in milliseconds.
///
/// ## The burst the rate controller cannot see
///
/// Measured on a sharp vertical scroll at 900p: OpenH264 in camera mode cannot find the
/// motion — its search window does not reach a jump of that size — so it codes the frames as
/// intra. Three of them, about 100 kB each, inside 200 ms. 293 kB in flight, the queue at 315 ms,
/// then the estimate collapses under our own backlog and it passes a second; the transport's hard
/// limit discards, the viewer sends a PLI, and the ladder walks 900p to 720p to 540p.
///
/// Nothing upstream could have stopped it. `crate::frame_dropper` reacts to `fill`, which is to
/// say *after the bytes exist*: it is a bit bucket, and a bucket cannot be charged for a frame
/// that has not been encoded. The budget is a rate and this is three frames. So the only place to
/// refuse is before `encoder.encode`, and the only honest thing to refuse on is the measured age
/// of the queue those bytes would join.
///
/// ## Why not a byte credit
///
/// A gate that prices admission in *bytes* against a credit of `3 x mean_frame_bytes` has a limit
/// that grows with the thing it limits, so a queue can never be too large by its own definition (a
/// "100 ms budget" of that kind measured 1311 ms). Two things are different here and both are the
/// same difference:
///
///   * the quantity is milliseconds of *measured* queue (str0m's `first_unsent()` age), not bytes
///     divided by a rate somebody supplied;
///   * the threshold is a constant taken from the product's own latency budget — twice
///     `quality::QUEUE_GUARD_MS`, the standing queue the ladder is built around — not a function
///     of the traffic.
///
/// Skipping a frame does remove its bytes: on decorrelated data bytes per frame scale as
/// `interval^0.013 ± 0.34`, indistinguishable from zero (see the header of
/// `crate::frame_dropper`), so the survivors do not get more than proportionally expensive.
///
/// ## Why 150 and not the guard itself
///
/// `QUEUE_GUARD_MS` is 75 and is where *pushback* starts: a continuous, bounded reduction of the
/// budget, which is the right response to a queue that is merely present. This is the discrete
/// one, and a discrete action needs to be past the range where the continuous one is working or
/// the two fight. Twice the guard is also four frame intervals at 30 fps and nine at 60, so no
/// single late frame reaches it.
const QUEUE_SKIP_MS: u32 = 150;

/// How many frames in a row the queue guard may withhold before it must encode anyway.
///
/// The gauge it reads is republished on the control task's 200 ms tick, so it can be stale, and a
/// control task that has stopped ticking would leave it stale forever — at which point an
/// unbounded guard is a permanent freeze with no error anywhere. Six frames is 100 ms at 60 fps and
/// 200 at 30, long enough to cover the burst this exists for (three frames, measured) and short
/// enough that a stuck gauge costs a judder rather than a session.
const MAX_QUEUE_SKIPS: u32 = 6;

/// Should this frame be withheld because the queue it would join is already too old?
///
/// A pure function of the three inputs so the decision can be tested without a pipeline. See
/// [`QUEUE_SKIP_MS`] for the burst it is for and why it is not a byte credit.
///
/// A forced keyframe is never withheld: it is how a lost picture comes back, and a queue is a
/// reason to send one sooner rather than later.
fn skip_for_queue(queue_age_ms: u32, consecutive_skips: u32, forced_keyframe: bool) -> bool {
    !forced_keyframe && queue_age_ms > QUEUE_SKIP_MS && consecutive_skips < MAX_QUEUE_SKIPS
}

/// The longest the queue guard's hard hold withholds frames in one go. See [`HardHold`].
///
/// 2.4 times the longest breaker episode measured — 0.42 s from trip to resume; the others ran
/// 0.10-0.30 s — so it never cuts a real one short, and short enough that a gauge stuck past the
/// limit costs a second of picture before the transport's breaker, and the keyframe after it, take
/// over.
const HARD_HOLD_MAX: Duration = Duration::from_secs(1);

/// The queue guard's hard hold: while the send queue is past the transport breaker's own limit
/// (`afklink_transport::QUEUE_HARD_LIMIT_MS`), withhold every frame *before* encoding it, until the
/// queue is back where the breaker resumes (`QUEUE_RESUME_MS`).
///
/// ## Why, when the breaker exists
///
/// A frame the breaker discards has been encoded: every frame after it references a picture the
/// viewer's decoder never gets, and the transport then holds delta frames and asks for a keyframe
/// (`afklink_transport::webrtc`, `RefChain`) — the largest thing this pipeline sends, onto a link
/// that has just shown it cannot take a burst. A frame that is not encoded costs nothing: the next
/// one references the last one sent. Past the limit the breaker discards everything anyway, so
/// withholding here changes nothing the viewer sees except that no keyframe is owed afterwards.
///
/// The soft guard ([`skip_for_queue`]) cannot do this: it lets one frame through every
/// [`MAX_QUEUE_SKIPS`], and past the limit that frame is exactly what the breaker discards. In one
/// recorded case the gauge read 1017 ms, the guard released a frame at its cap, the breaker
/// discarded it (1031 ms) and the next one 116 ms later, and resumed "without a keyframe" —
/// leaving the viewer's reference chain broken. With the hold both frames stay unencoded and the
/// breaker discards nothing.
///
/// A viewer's keyframe request still passes, as it passes the soft guard: if the breaker then
/// discards it, the transport asks again when the queue has drained.
#[derive(Debug, Default)]
struct HardHold {
    state: HardHoldState,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum HardHoldState {
    #[default]
    Idle,
    Holding {
        since: Instant,
        withheld: u32,
    },
    /// Held for [`HARD_HOLD_MAX`] with the gauge still past the limit; not again until it has
    /// come back under the resume level.
    GaveUp,
}

/// What [`HardHold::step`] decided about one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardHoldStep {
    /// Not holding: the soft guard and the rest decide.
    Pass,
    /// The queue just went past the limit: withhold this frame, and the ones after it.
    Engaged,
    /// Still past the resume level: withhold.
    Hold,
    /// Back under the resume level: this frame goes, and nothing was discarded.
    Released { held: Duration, withheld: u32 },
    /// [`HARD_HOLD_MAX`] and the gauge still past the limit: this frame goes, to the breaker.
    GaveUp { held: Duration, withheld: u32 },
    /// After giving up, the gauge came back under the resume level: armed again. This frame goes.
    Rearmed,
}

impl HardHold {
    fn step(&mut self, queue_age_ms: u32, now: Instant) -> HardHoldStep {
        match self.state {
            HardHoldState::Idle => {
                if queue_age_ms > afklink_transport::QUEUE_HARD_LIMIT_MS {
                    self.state = HardHoldState::Holding {
                        since: now,
                        withheld: 1,
                    };
                    HardHoldStep::Engaged
                } else {
                    HardHoldStep::Pass
                }
            }
            HardHoldState::Holding { since, withheld } => {
                let held = now.saturating_duration_since(since);
                if queue_age_ms <= afklink_transport::QUEUE_RESUME_MS {
                    self.state = HardHoldState::Idle;
                    HardHoldStep::Released { held, withheld }
                } else if held >= HARD_HOLD_MAX {
                    self.state = HardHoldState::GaveUp;
                    HardHoldStep::GaveUp { held, withheld }
                } else {
                    self.state = HardHoldState::Holding {
                        since,
                        withheld: withheld.saturating_add(1),
                    };
                    HardHoldStep::Hold
                }
            }
            HardHoldState::GaveUp => {
                if queue_age_ms <= afklink_transport::QUEUE_RESUME_MS {
                    self.state = HardHoldState::Idle;
                    HardHoldStep::Rearmed
                } else {
                    HardHoldStep::Pass
                }
            }
        }
    }
}

/// How far the measured frame rate must move before OpenH264 is told, as a percentage.
///
/// See the note at the `set_target` call in [`encode_loop`]. The encoder's own threshold is half a
/// frame, which on a change-driven capture source fires several times a second for wander that
/// changes no picture.
const FPS_DEADBAND_PCT: u64 = 15;

/// The viewer's input over a window, for one debug line instead of one per event.
///
/// Input is a hot path — a moving pointer is a message per frame on the viewer, sixty a second —
/// so events are counted, and the counts go out as one line every [`Self::EVERY`] while there is
/// any input at all, plus once when the session ends. The first failure and the first malformed
/// message of the session are said at once: they are the ones that explain the rest.
///
/// Never the content. A key message can be a password being typed.
#[derive(Default)]
struct InputTally {
    window_start: Option<Instant>,
    injected: u64,
    /// What the injected messages were, so the line shows whether the viewer steered with absolute
    /// positions or relative moves — which touch mode was really in use.
    kinds: InputKinds,
    failed: u64,
    malformed: u64,
    /// Messages longer than `INPUT_MAX_BYTES`, dropped unread.
    oversized: u64,
    /// `text` messages longer than [`TEXT_MAX_CHARS`], dropped whole.
    text_too_long: u64,
    /// Guest input held back from an AFKLink window (`crate::own_windows`).
    held_back: u64,
    first_failure_logged: bool,
    first_malformed_logged: bool,
    first_oversized_logged: bool,
    first_text_too_long_logged: bool,
    /// How the messages arrived: the most within 50 ms, the longest gap (`crate::input_rhythm`).
    rhythm: crate::input_rhythm::InputRhythm,
}

/// The longest `text` message the agent types, in characters. A viewer cuts what it types at
/// the contract's 64 UTF-16 units (`textSchema` in `datachannel.ts`; the Mini App's `TEXT_MAX_UNITS`),
/// so this is far past anything a viewer sends — and short of what `INPUT_MAX_BYTES` alone allowed
/// (4 KiB, some 4000 characters, each a pair of `SendInput` events).
///
/// A longer one is dropped whole rather than cut: a cut types the start of something the person
/// meant as a whole — half a pasted command, and a line break in it is Enter — while nothing typed
/// at all is plain to see and safe. Text larger than this has its own way, the clipboard sync.
const TEXT_MAX_CHARS: usize = 1024;

/// Whether a `text` message is too long to type ([`TEXT_MAX_CHARS`]). Counts characters only up
/// to the limit.
fn text_over_limit(text: &str) -> bool {
    text.chars().nth(TEXT_MAX_CHARS).is_some()
}

/// The guard on AFKLink's own windows for session `session_id` (`crate::own_windows`): by the
/// viewer's role as `game_access` decided it at the session's start — its very cell, which every
/// change of the roles keeps current — or, for a session it has no decision for (`open` makes one
/// first, so never in practice), as not the owner: the safe side, warned.
fn own_window_guard(
    game_access: &crate::game_access::GameAccess,
    session_id: &str,
) -> Arc<crate::own_windows::OwnWindowGuard> {
    let role = game_access.role_cell(session_id).unwrap_or_else(|| {
        tracing::warn!(
            session = %session_id,
            "own windows: no role decided for this session; taken as not the owner's"
        );
        Arc::new(crate::game_access::RoleCell::not_owner())
    });
    Arc::new(crate::own_windows::OwnWindowGuard::new(role, session_id))
}

/// What became of one viewer input event at the event task's last step ([`deliver_input`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivered {
    /// Injected, and counted.
    Injected,
    /// A guest's press, key or text that would reach an AFKLink window: not injected.
    HeldBack,
    /// The session's gate closed under it: the event task ends.
    SessionEnded,
    /// The injector refused it (counted; the first said).
    Failed,
}

/// The event task's last step for one viewer input event: held back from AFKLink's own windows
/// (the guard says each stretch; counted here as `held_back`), else injected and counted in
/// the input line, the session's counters and the relative-move ack, else counted as failed.
fn deliver_input(
    input: &InputSession,
    ie: &InputMessage,
    tally: &mut InputTally,
    counters: &SessionCounters,
    rel_ack: &crate::cursor_report::RelAck,
    sid: &str,
) -> Delivered {
    if input.held_back(ie) {
        tally.held_back();
        return Delivered::HeldBack;
    }
    match input.inject(ie) {
        Ok(true) => {
            tally.note_injected(ie);
            counters.input.count(ie);
            if let InputMessage::Rel { s: Some(s), .. } = ie {
                rel_ack.note(*s);
            }
            Delivered::Injected
        }
        Ok(false) => Delivered::SessionEnded,
        Err(e) => {
            tracing::trace!("inject failed: {e}");
            tally.failed(sid, &e);
            Delivered::Failed
        }
    }
}

/// Hand a viewer's clipboard message to the session's clipboard task (`crate::clipboard`). A full
/// queue (a viewer flooding it) or a task already gone drops it, said at debug: the chunks after a
/// lost one are answered `malformed`, and a lost `cb_sync` leaves the viewer without its answer.
fn forward_clipboard(
    tx: &mpsc::Sender<crate::clipboard::ViewerClipboard>,
    msg: crate::clipboard::ViewerClipboard,
    sid: &str,
) {
    match tx.try_send(msg) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => tracing::debug!(
            session = sid,
            "clipboard: a viewer's message dropped: the clipboard task is behind"
        ),
        Err(mpsc::error::TrySendError::Closed(_)) => tracing::debug!(
            session = sid,
            "clipboard: a viewer's message dropped: the clipboard task has ended"
        ),
    }
}

/// Why an input message did not parse, for the log — never the message itself: a key can be a
/// password being typed. For clipboard messages not even the parser's words, which can quote a
/// value: only where it stopped.
fn unparsed_input(s: &str, e: &serde_json::Error) -> String {
    let kind = serde_json::from_str::<serde_json::Value>(s)
        .ok()
        .and_then(|v| v.get("t").and_then(|t| t.as_str()).map(str::to_string))
        .unwrap_or_else(|| "?".to_string());
    if kind.starts_with("cb") {
        format!("{kind}: {:?} error at column {}", e.classify(), e.column())
    } else {
        format!("{kind}: {e}")
    }
}

/// Injected input messages by kind, for the tally line. Counts only, never content.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct InputKinds {
    /// `m`: absolute pointer positions (direct touch, a physical mouse).
    abs: u64,
    /// `r`: relative moves (trackpad, MMO look).
    rel: u64,
    /// `d` and `u`.
    buttons: u64,
    /// `w`.
    wheel: u64,
    /// `k`.
    keys: u64,
    /// `text`.
    text: u64,
    /// `combo`, `ra`, and anything else that reaches the injector.
    other: u64,
}

impl InputKinds {
    /// By the one mapping the session summary's counts use too (`crate::summary::InputClass`).
    fn count(&mut self, m: &InputMessage) {
        use crate::summary::InputClass;
        match InputClass::of(m) {
            InputClass::Abs => self.abs += 1,
            InputClass::Rel => self.rel += 1,
            InputClass::Buttons => self.buttons += 1,
            InputClass::Wheel => self.wheel += 1,
            InputClass::Keys => self.keys += 1,
            InputClass::Text => self.text += 1,
            InputClass::Other => self.other += 1,
        }
    }
}

impl InputTally {
    const EVERY: Duration = Duration::from_secs(10);

    fn touch(&mut self) {
        self.window_start.get_or_insert_with(Instant::now);
    }

    fn note_injected(&mut self, m: &InputMessage) {
        self.injected += 1;
        self.kinds.count(m);
    }

    fn failed(&mut self, sid: &str, e: &anyhow::Error) {
        self.touch();
        self.failed += 1;
        if !self.first_failure_logged {
            self.first_failure_logged = true;
            // The injector's own `SendInput` warnings say why the OS refused; this says that the
            // viewer's input is not reaching the desktop at all.
            tracing::warn!(session = sid, "input not injected: {e:#}");
        }
    }

    fn malformed(&mut self, sid: &str, bytes: usize, why: &str) {
        self.touch();
        self.malformed += 1;
        if !self.first_malformed_logged {
            self.first_malformed_logged = true;
            tracing::debug!(
                session = sid,
                bytes,
                "malformed input message dropped: {why}"
            );
        }
    }

    /// A message longer than `INPUT_MAX_BYTES`, dropped before it was parsed. The first of a
    /// session is a warning — no viewer of ours sends one — the rest are counted.
    fn oversized(&mut self, sid: &str, bytes: usize) {
        self.touch();
        self.oversized += 1;
        if !self.first_oversized_logged {
            self.first_oversized_logged = true;
            tracing::warn!(
                session = sid,
                bytes,
                max = afklink_protocol::INPUT_MAX_BYTES,
                "input message longer than any the contract allows: dropped unread (the rest of \
                 this session are counted in the input line)"
            );
        }
    }

    /// A `text` longer than [`TEXT_MAX_CHARS`], dropped whole; never its content. The first of
    /// a session is a warning, the rest are counted.
    fn text_too_long(&mut self, sid: &str, chars: usize) {
        self.touch();
        self.text_too_long += 1;
        if !self.first_text_too_long_logged {
            self.first_text_too_long_logged = true;
            tracing::warn!(
                session = sid,
                chars,
                max = TEXT_MAX_CHARS,
                "text input longer than any viewer sends: dropped whole, nothing typed (the rest of \
                 this session are counted in the input line)"
            );
        }
    }

    /// Guest input held back from an AFKLink window: counted here; the guard says each change
    /// itself (`crate::own_windows`).
    fn held_back(&mut self) {
        self.touch();
        self.held_back += 1;
    }

    /// Write the window's line if it is due. Called on every turn of the event loop, which turns
    /// at least every `afklink_protocol::INPUT_SILENCE_RELEASE_MS`.
    fn flush_if_due(&mut self, now: Instant, sid: &str) {
        if self.injected > 0 {
            self.touch();
        }
        if self
            .window_start
            .is_some_and(|t| now.saturating_duration_since(t) >= Self::EVERY)
        {
            self.flush(sid);
        }
    }

    fn flush(&mut self, sid: &str) {
        let Some(start) = self.window_start.take() else {
            return;
        };
        let (burst_50ms, gap_max_ms) = self.rhythm.take();
        if self.injected
            + self.failed
            + self.malformed
            + self.oversized
            + self.text_too_long
            + self.held_back
            > 0
        {
            let k = self.kinds;
            // not-a-key-name: counts of input events
            tracing::debug!(
                session = sid,
                window_s = start.elapsed().as_secs(),
                injected = self.injected,
                abs = k.abs,
                rel = k.rel,
                buttons = k.buttons,
                wheel = k.wheel,
                keys = k.keys,
                text = k.text,
                other = k.other,
                failed = self.failed,
                malformed = self.malformed,
                oversized = self.oversized,
                text_too_long = self.text_too_long,
                held_back = self.held_back,
                burst_50ms,
                gap_max_ms,
                "input"
            );
        }
        self.injected = 0;
        self.kinds = InputKinds::default();
        self.failed = 0;
        self.malformed = 0;
        self.oversized = 0;
        self.text_too_long = 0;
        self.held_back = 0;
    }
}

/// At most one log line per interval, counting the ones it held back.
///
/// For per-frame decisions that are usually rare and occasionally a storm — a keyframe, a change
/// of the frame rate rate control is told — so the first of a burst is always in the log, and the
/// next line says how many it stood for.
struct Throttle {
    every: Duration,
    last: Option<Instant>,
    held: u32,
}

impl Throttle {
    fn new(every: Duration) -> Self {
        Self {
            every,
            last: None,
            held: 0,
        }
    }

    /// `Some(held back since the last line)` when a line may be written now.
    fn ready(&mut self, now: Instant) -> Option<u32> {
        if self
            .last
            .is_none_or(|t| now.saturating_duration_since(t) >= self.every)
        {
            self.last = Some(now);
            Some(std::mem::take(&mut self.held))
        } else {
            self.held = self.held.saturating_add(1);
            None
        }
    }
}

fn parse_quality_pin(q: &str) -> Option<Option<u32>> {
    match q {
        "auto" => Some(None),
        other => other.parse::<u32>().ok().and_then(|h| {
            crate::quality::PINNABLE_HEIGHTS
                .contains(&h)
                .then_some(Some(h))
        }),
    }
}
fn note_viewer_latency(
    counters: &SessionCounters,
    jbuf_ms: f64,
    frames: u32,
    jitter_ms: f64,
    sid: &str,
) {
    // Clamp to the viewer schema before publishing the numbers.
    let clamp = |v: f64| {
        if v.is_finite() {
            (v * 10.0).clamp(0.0, 600_000.0) as u32
        } else {
            0
        }
    };
    let sane = |v: f64| v.is_finite() && (0.0..=60_000.0).contains(&v);
    if !sane(jbuf_ms) || !sane(jitter_ms) {
        tracing::debug!(
            session = %sid,
            jbuf_ms,
            jitter_ms,
            "viewer latency report out of range; clamped"
        );
    }
    tracing::trace!(jbuf_ms, jitter_ms, frames, "viewer latency");
    counters
        .jbuf_tenth_ms
        .store(clamp(jbuf_ms), Ordering::Relaxed);
    counters
        .jitter_tenth_ms
        .store(clamp(jitter_ms), Ordering::Relaxed);
    counters
        .jbuf_frames
        .fetch_add(u64::from(frames), Ordering::Relaxed);
}

fn note_viewer_delivery(
    counters: &SessionCounters,
    report: &afklink_protocol::ViewerVideo,
    delivery_epoch: Instant,
    sid: &str,
) {
    // Drain mode's current evidence: the viewer's count of our
    // frames, its clock, and when it reached us. A viewer that
    // counts no frames gives none.
    if let Some(received) = report.frames_received {
        counters
            .viewer_frames_received
            .store(received, Ordering::Relaxed);
        counters.viewer_clock_ms.store(
            report.current_ms.map_or(0, |ms| ms.saturating_add(1)),
            Ordering::Relaxed,
        );
        counters.viewer_report_at_us.store(
            u64::try_from(delivery_epoch.elapsed().as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        counters
            .viewer_delivery_reports
            .fetch_add(1, Ordering::Release);
    } else {
        tracing::trace!(
            session = %sid,
            "viewer report without framesReceived: no \
             delivery evidence for drain mode in it"
        );
    }
}

fn note_receiver_report(
    counters: &SessionCounters,
    rtt_ms: Option<u32>,
    loss: Option<f32>,
    plis: u64,
    nacks: u64,
) {
    counters
        .rtt_ms
        .store(rtt_ms.unwrap_or(u32::MAX), Ordering::Relaxed);
    counters.loss_bp.store(
        loss.map_or(u32::MAX, |l| (l * 10_000.0).clamp(0.0, 10_000.0) as u32),
        Ordering::Relaxed,
    );
    counters.plis.store(plis, Ordering::Relaxed);
    counters.nacks.store(nacks, Ordering::Relaxed);
    // Last, so the control task that sees the new count also sees the reports above.
    counters.link_reports.fetch_add(1, Ordering::Release);
}

struct MediaControl {
    session_id: String,
    policy: Arc<crate::quality_policy::QualityPolicy>,
    quality_pref: crate::quality::Quality,
    initial_desired_kbps: u32,
    qp_ceiling: Option<f32>,
    delivery_epoch: Instant,
    target: Arc<crate::quality::QualityTarget>,
    counters: Arc<SessionCounters>,
    stop: Arc<AtomicBool>,
    pin_request: Arc<AtomicU32>,
    game_status: Arc<crate::game::GameStatus>,
    pending_kf: Arc<AtomicBool>,
    bg: Arc<crate::bg_hold::BgHold>,
    health: Arc<crate::pipeline::PipelineHealth>,
    summary: MediaObservation,
    journal: Option<Arc<crate::journal::Journal>>,
    calibrate: bool,
}

struct MediaPeerGauges {
    control_tx: mpsc::Sender<PeerControl>,
    drain_gauge: Arc<AtomicU32>,
    queue_age: Arc<AtomicU32>,
    egress_gauge: Arc<AtomicU32>,
    egress_total: Arc<AtomicU64>,
    discard_gauge: Arc<AtomicU32>,
    path_gauge: Arc<AtomicU32>,
    kind_gauge: Arc<std::sync::atomic::AtomicU8>,
}

impl MediaPeerGauges {
    fn new(peer: &transport::Peer) -> Self {
        Self {
            control_tx: peer.control_tx.clone(),
            drain_gauge: peer.drain_kbps.clone(),
            queue_age: peer.queue_age_ms.clone(),
            egress_gauge: peer.egress_kbps.clone(),
            egress_total: peer.egress_bytes_total.clone(),
            discard_gauge: peer.discarded_frames.clone(),
            path_gauge: peer.path_changes.clone(),
            kind_gauge: peer.path_kind.clone(),
        }
    }
}

struct MediaObservation(Option<Arc<crate::summary::SessionSummary>>);

impl MediaObservation {
    fn seconds_ended(&self) {
        if let Some(observer) = &self.0 {
            observer.seconds_ended();
        }
    }

    fn instant(
        &self,
        now: Instant,
        kind: afklink_protocol::metrics::SessionEpisodeKind,
        code: Option<&str>,
    ) {
        if let Some(observer) = &self.0 {
            observer.instant(now, kind, code);
        }
    }

    fn begin(
        &self,
        now: Instant,
        kind: afklink_protocol::metrics::SessionEpisodeKind,
        code: Option<&str>,
    ) {
        if let Some(observer) = &self.0 {
            observer.begin(now, kind, code);
        }
    }

    fn end(&self, now: Instant, kind: afklink_protocol::metrics::SessionEpisodeKind) {
        if let Some(observer) = &self.0 {
            observer.end(now, kind);
        }
    }

    fn second(&self, now: Instant, sample: crate::summary::Second) {
        if let Some(observer) = &self.0 {
            observer.second(now, sample);
        }
    }
}

// The control task: one controller, one fixed clock.
//
// Everything that decides anything lives here and runs at `quality::TICK`, whatever the
// network is doing. The three loops this replaced — a ladder on the estimate's clock, a
// budget on the same clock, and a frame-rate ramp on the capture thread — each acted on a
// different view of the same link and one of them read a signal derived from another's
// output. That wiring produced a new deadlock for every fix applied to it.
//
// What is authoritative, and for what:
//
//   instantaneous estimate   the byte budget. Retargeting is free, so smoothing it is lag
//                            that buys nothing.
//   bytes in flight          admission, and a continuous pushback on that budget. The only
//                            signal a still screen cannot fake.
//   the pipeline's own       the ladder: pixels and cadence. Slow, expensive, hysteretic,
//   overshoot and delivery   and never driven by the estimate.
fn spawn_media_control(peer: MediaPeerGauges, args: MediaControl) -> tokio::task::JoinHandle<()> {
    let MediaControl {
        session_id,
        policy,
        quality_pref,
        initial_desired_kbps,
        qp_ceiling,
        delivery_epoch,
        target,
        counters,
        stop,
        pin_request,
        game_status,
        pending_kf,
        bg,
        health,
        summary,
        journal,
        calibrate,
    } = args;
    let MediaPeerGauges {
        control_tx,
        drain_gauge,
        queue_age,
        egress_gauge,
        egress_total,
        discard_gauge,
        path_gauge,
        kind_gauge,
    } = peer;
    let mut prev_path_changes = 0u32;
    let mut prev_path_kind = path_kind_of(kind_gauge.load(Ordering::Relaxed));
    // Off unless explicitly asked for. A mode that takes the controller out of the loop
    // must not be reachable by accident.
    let mut calibration = calibrate.then(|| {
        tracing::info!(
            points = crate::quality::CALIBRATION.len(),
            seconds = crate::quality::calibration_duration().as_secs(),
            "calibration sweep armed: the ladder will not move this session"
        );
        CalibrationSweep {
            started: Instant::now(),
            index: 0,
            finished: false,
        }
    });
    // On the session's policy, owned by this task from here: a copy, so nothing is shared
    // with the orchestrator and nothing is locked to read it.
    let mut quality =
        crate::quality::QualityController::with_policy(1920, 1080, quality_pref, (*policy).clone());
    // What str0m was told at session start, so the controller's first probe target is
    // compared against it rather than against nothing. See `take_probe_target` below.
    quality.probe_target_sent(initial_desired_kbps);
    let mut desired_kbps = initial_desired_kbps;
    let mut prev_bytes = 0u64;
    let mut prev_egress_bytes = 0u64;
    let mut prev_attempts = 0u64;
    let mut prev_encode_us = 0u64;
    let mut prev_key_bytes = 0u64;
    let mut prev_qp_sum = 0u64;
    let mut prev_qp_n = 0u64;
    // The pipeline line's own window, which is a whole second of the controller's ticks.
    let mut log_ticks = 0u32;
    let mut log_captured = 0u64;
    let mut log_encoded = 0u64;
    let mut log_bytes = 0u64;
    let mut log_stale = 0u64;
    let mut log_skipped = 0u64;
    let mut log_errors = 0u64;
    let mut log_discarded = 0u64;
    let mut log_dropped_rate = 0u64;
    let mut log_skipped_queue = 0u64;
    let mut log_skipped_drain = 0u64;
    let mut log_plis = 0u64;
    let mut log_nacks = 0u64;
    let mut log_kf_suppressed = 0u64;
    // The viewer's own report as of the last line: the `v_*` fields. See
    // `crate::viewer_report`.
    let mut log_viewer = crate::viewer_report::ViewerLineState::default();
    // The receiver-report counter as of the last tick, and the cumulative NACK count as of
    // the last report: what turns str0m's once-a-second event into exactly one
    // `ReceiverReport` on one tick, with the NACKs that arrived since the one before.
    let mut prev_link_reports = 0u64;
    let mut prev_report_nacks = 0u64;
    // The viewer's `vv` report count as of the last tick: a moved count is a report the
    // controller has not read (`QualityController::note_viewer_frames`).
    let mut prev_viewer_delivery = 0u64;
    // When a `brake tightened` line was last printed, and how many brake lines were held
    // back since. See the brake logging after the tick.
    let mut brake_tighten_logged_at: Option<Instant> = None;
    let mut brake_suppressed = 0u32;
    // When the brake first went over its warning threshold, and when it was last
    // complained about. See the `warn!` in the tick.
    let mut fd_high_since: Option<Instant> = None;
    let mut fd_warned_at: Option<Instant> = None;
    // Whether the last attempt to reprice the bwe ceiling was refused. See the reprice.
    let mut reprice_refused = false;
    let control_sid = session_id;
    // One sample a second for the journal's «Плохая связь» and «Только игра».
    // The background hold's grace runs out on this clock, and the controller is frozen
    // through a hold and resumed after it here. See `crate::bg_hold::HoldControl`.
    let mut hold = crate::bg_hold::HoldControl::new();
    // What the peer was last told of the viewer's page (`PeerControl::ViewerHidden`): the
    // only word besides ICE's that lets its `cursor` channel hold anything. Every session
    // starts visible on both sides.
    let mut hidden_told = crate::bg_hold::HiddenTold::default();
    // The session's summary (`crate::summary`): its episodes as the lines below are written,
    // its rung time and freeze rule on the `pipeline` line's motion seconds.
    // The encode thread's capture restarts, for the summary's `capture_restart` episodes.
    let mut prev_capture_restarts = 0u32;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(crate::quality::TICK);
        // A missed tick is skipped, not made up.
        //
        // The default is `Burst`: after a stall the interval fires back-to-back until it
        // has caught up. Every one of those ticks is handed the same constant `dt`, so the
        // ladder would accumulate dwell for time that did not pass — and it would do so
        // reading whatever the last measurement was, which during a stall is stale by
        // definition. A machine that froze for two seconds would come back to a controller
        // convinced it had watched two seconds of evidence.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The summary's seconds count each `pipeline` line's measured time, not its nominal
        // second (below).
        let mut summary_clock = crate::summary::SecondClock::new(Instant::now());
        tick.tick().await; // the first fires immediately and has no interval behind it
        loop {
            tick.tick().await;
            if stop.load(Ordering::SeqCst) {
                tracing::debug!(
                    session = %control_sid,
                    rung = %format!("{}p@{}", target.max_h(), target.fps()),
                    quality_changes = counters.quality_changes.load(Ordering::Relaxed),
                    lowest_height = counters.lowest_height.load(Ordering::Relaxed),
                    "control task stopped: the session is ending"
                );
                hold.finish(Instant::now());
                bg.finish(Instant::now());
                summary_clock.finish(&control_sid);
                summary.seconds_ended();
                break;
            }
            let dt = crate::quality::TICK;
            let secs = dt.as_secs_f32();

            // The background hold, before anything reads the controller: a grace that ran
            // out begins one here, and a hold the viewer ended since the last tick resumes
            // the controller here. While held the controller is not ticked — its evidence
            // does not decay and no dwell grows — but everything below that differences a
            // counter still runs, so the first tick after a hold sees one tick of traffic
            // and not the hold's padding in one window. See `crate::bg_hold`.
            let hold_step = hold.tick(
                &bg,
                &mut quality,
                Instant::now(),
                counters.estimate_kbps.load(Ordering::Relaxed),
                desired_kbps,
            );
            // str0m's desired bitrate: under its probing minimum while held, back after.
            // Offered every tick until the peer takes it; anything queued after it (a
            // re-anchor, a probe target) goes behind it in the same queue.
            if let Some(kbps) = hold.desired_to_send() {
                match control_tx.try_send(PeerControl::SetDesiredBitrate(kbps)) {
                    Ok(()) => {
                        hold.desired_sent(kbps);
                        desired_kbps = kbps;
                    }
                    Err(e) => hold.desired_refused(kbps, &e.to_string()),
                }
            }
            // The page hidden or visible, for the transport's `cursor` lane: offered on
            // every tick until the peer takes it.
            if let Some(hidden) = hidden_told.to_send(bg.page_hidden()) {
                let sent = control_tx.try_send(PeerControl::ViewerHidden(hidden));
                hidden_told.outcome(
                    &control_sid,
                    hidden,
                    bg.is_held(),
                    quality.receiver_silence(),
                    sent.map_err(|e| e.to_string()),
                );
            }
            let frozen = hold_step.frozen();

            // Calibration: the sweep drives the operating point, not the ladder.
            //
            // The whole reason this mode exists is identifiability. Fitted from ordinary
            // sessions, the rate surface came out with `R² = 0.17` and a *negative* pixel
            // exponent, because `corr(log(pixels), qp) = +0.78` — the controller had always
            // moved resolution and quantiser together, so nothing in the data separates
            // them. Here the bitrate is swept independently of the resolution, so the two
            // are decorrelated by construction.
            if let Some(sweep) = calibration.as_mut() {
                if let Some(point) = sweep.step() {
                    target.set(crate::quality::Rung {
                        max_h: point.max_h,
                        fps: point.fps,
                    });
                    target.set_target_kbps(point.kbps);
                    tracing::info!(
                        point = sweep.index,
                        of = crate::quality::CALIBRATION.len(),
                        rung = %format!("{}p@{}", point.max_h, point.fps),
                        kbps = point.kbps,
                        "calibration point"
                    );
                } else if sweep.index >= crate::quality::CALIBRATION.len() && !sweep.finished {
                    // Only at the end, not on every tick between points. `step()` returns
                    // `None` both while a point is still being held and after the last one;
                    // the index tells them apart, so the sweep is announced complete once,
                    // after its last point.
                    sweep.finished = true;
                    tracing::info!("calibration sweep complete");
                }
            }

            // The viewer's pin, applied by the one controller that owns the ladder.
            //
            // Taken before the tick so a pin and the tick it lands in cannot disagree, and
            // swapped rather than read so a request is consumed exactly once.
            match pin_request.swap(NO_PIN_REQUEST, Ordering::Relaxed) {
                NO_PIN_REQUEST => {}
                // Swallowed during a sweep, and swallowed *after* the swap so it cannot
                // fire late. The sweep owns the operating point for the session; a pin
                // landing in the middle of it would silently overwrite one measurement
                // point and invalidate the run without anything saying so.
                _ if calibration.is_some() => {
                    tracing::info!("quality pin ignored: a calibration sweep is running");
                }
                req => {
                    let height = (req != PIN_AUTO).then_some(req);
                    if let Some(rung) = quality.set_pinned_height(height) {
                        tracing::info!(
                            pinned = ?height,
                            rung = %format!("{}p@{}", rung.max_h, rung.fps),
                            "quality pinned"
                        );
                        target.set(rung);
                        summary.instant(
                            Instant::now(),
                            afklink_protocol::metrics::SessionEpisodeKind::RungChange,
                            Some("viewer"),
                        );
                    } else {
                        tracing::debug!(pinned = ?height, "quality pin unchanged; nothing to do");
                    }
                }
            }

            let bytes = counters.bytes_sent.load(Ordering::Relaxed);
            let attempts = counters.encode_attempts.load(Ordering::Relaxed);
            let encode_us = counters.encode_us_total.load(Ordering::Relaxed);
            let qp_sum = counters.qp_sum.load(Ordering::Relaxed);
            let qp_n = counters.qp_samples.load(Ordering::Relaxed);
            let estimate_kbps = counters.estimate_kbps.load(Ordering::Relaxed);

            // Did the encoder spend what it was given? Against the budget it was actually
            // handed, because that is the question — not against some other figure.
            //
            // This is used *only* as a precondition for climbing. As a descent trigger it
            // would be worse than useless: the encoder is handed a budget pushback has
            // already reduced, so an encoder sitting exactly on target reports
            // `1 - 0.5 x pressure`, a number that falls as the queue fills — 0.50 at the
            // moment the queue reaches its entire budget.
            let allowed_bits = target.target_kbps().unwrap_or(0) as f32 * 1000.0 * secs;
            let produced_bits = (bytes.saturating_sub(prev_bytes) as f32) * 8.0;

            // What the queue actually drains at: bytes that demonstrably left the socket,
            // or the estimate, whichever is larger. Not the budget — that is a production
            // rate, wrong in exactly the windows where the queue is growing — and not the
            // estimate alone, which on an idle screen measures our own silence.
            let drain =
                crate::quality::drain_kbps(drain_gauge.load(Ordering::Relaxed), estimate_kbps);
            // Keyframes excluded from what the ladder sees as production. An IDR of 28 to
            // 55 kB lands inside one window and reads there as several times the link's
            // capacity; over its GOP the same keyframe amortises to about 40 kbps.
            //
            // This leaves the conservation check deliberately asymmetric — socket egress
            // below includes those bytes — and the asymmetry is kept because it errs in the
            // safe direction. A keyframe is produced in one window and paced out over the
            // next two or three, so counting it in the numerator would spike the ratio
            // exactly the way a stale denominator would. Leaving it out instead makes
            // the ratio dip for a window, which can only ever suppress a descent.
            let key_bytes = counters.keyframe_bytes_total.load(Ordering::Relaxed);
            let inter_bits =
                (produced_bits - (key_bytes.saturating_sub(prev_key_bytes) as f32) * 8.0).max(0.0);
            // Bytes that left the socket in *this* window, from the monotonic counter.
            //
            // The whole point of differencing it here rather than reading the transport's
            // rate gauge: that gauge is republished once a second, this task ticks five
            // times a second, so four ticks in five would compare a fresh numerator against a
            // denominator up to a second old. During a climb — production rising to follow
            // a budget that has just gone up — that is a systematic overestimate, which the
            // ladder reads as a filling backlog, shedding the rung it has just won.
            // Measured at 1080p30 with an empty queue: 3691 over a stale 2809 gave 1.31,
            // where the same-window figure for that whole stretch was 0.89 to 1.02.
            let egress_bytes_now = egress_total.load(Ordering::Relaxed);
            let egress_bits = (egress_bytes_now.saturating_sub(prev_egress_bytes) as f32) * 8.0;
            // Read once, used twice (the log, and nothing else yet), so the two cannot
            // disagree about what the bucket said on this tick.
            let (fd_ratio, fd_fullness) = target.frame_dropper();

            // The measured queue age, read once and republished for the encode thread.
            //
            // The encode thread cannot ask str0m — it has a `QualityTarget` and nothing
            // else — and it needs this number *between frames*, which is the only place a
            // burst can be refused before its bytes exist. Published from here rather than
            // handed the transport's gauge directly so there is one reader of the
            // transport's internals and one clock for every latency decision. See
            // `skip_for_queue`.
            let queue_age_ms = queue_age.load(Ordering::Relaxed);
            target.set_queue_age_ms(queue_age_ms);
            // And the drain rate, the same way and for the same reason: the encode thread
            // prices a keyframe's time to leave with it (`crate::keyframe_window`).
            target.set_drain_kbps(drain);

            // The brake is a safety net. A safety net that is bearing the load is news.
            //
            // `afklink_core::frame_dropper` exists because OpenH264 has no VBV and its own
            // frame skip is broken, so a keyframe or a burst can still put more on the wire
            // than the budget allows. Catching those is what it is for. What it is *not*
            // for is holding the long-run rate: every frame it withholds is a frame the
            // viewer does not see, and the ladder's `throttled` arm only fires at a third
            // of frames — so between a tenth and a third the picture is being paid for in
            // judder with nothing in the log to say so.
            //
            // A tenth for three seconds is well past any keyframe transient (the periodic
            // IDR is 3000 frames apart, and one clears in well under a second), so it
            // means rate control is not holding the rate and the brake is.
            let now = Instant::now();
            // Not through a hold: no frame is offered then, and the ratio is the last one
            // from before it — a warning repeated every ten seconds for minutes of nothing.
            if fd_ratio > FD_WARN_RATIO && !frozen {
                let since = *fd_high_since.get_or_insert(now);
                if now.duration_since(since) >= FD_WARN_AFTER
                    && fd_warned_at.is_none_or(|t| now.duration_since(t) >= FD_WARN_EVERY)
                {
                    fd_warned_at = Some(now);
                    tracing::warn!(
                        drop_ratio = format!("{fd_ratio:.2}"),
                        fullness = format!("{fd_fullness:.2}"),
                        budget_kbps = target.target_kbps().unwrap_or(0),
                        produced_kbps = (inter_bits / secs / 1000.0) as u32,
                        rung = %format!("{}p@{}", target.max_h(), target.fps()),
                        "rate control is not holding the rate: the frame dropper is, by \
                         throwing frames away"
                    );
                }
            } else {
                fd_high_since = None;
            }
            // A new receiver report, if str0m delivered one since the last tick — once.
            //
            // The `LinkStats` handler bumps `link_reports` after storing the values, so a
            // changed count means the values beside it belong to a report this task has not
            // yet handed to the controller. Read on the tick the count moves and never
            // again: the brake counts reports ("two in a row", "three without one"), and
            // the same report read on five consecutive 200 ms ticks would be five reports.
            let link_reports = counters.link_reports.load(Ordering::Acquire);
            let report = if link_reports == prev_link_reports {
                None
            } else {
                prev_link_reports = link_reports;
                let nacks_total = counters.nacks.load(Ordering::Relaxed);
                let nacks = u32::try_from(nacks_total.saturating_sub(prev_report_nacks))
                    .unwrap_or(u32::MAX);
                prev_report_nacks = nacks_total;
                Some(crate::quality::ReceiverReport {
                    rtt_ms: match counters.rtt_ms.load(Ordering::Relaxed) {
                        u32::MAX => None,
                        v => Some(v),
                    },
                    loss: match counters.loss_bp.load(Ordering::Relaxed) {
                        u32::MAX => None,
                        bp => Some(bp as f32 / 10_000.0),
                    },
                    nacks,
                })
            };
            let fb = crate::quality::Feedback {
                estimate_kbps,
                drain_kbps: drain,
                produced_kbps: (inter_bits / secs / 1000.0) as u32,
                egress_kbps: (egress_bits / secs / 1000.0) as u32,
                qp_samples: u32::try_from(qp_n.saturating_sub(prev_qp_n)).unwrap_or(u32::MAX),
                queue_age_ms,
                // A true mean over this window. `None` when no frame was encoded in it,
                // which is honest: there is no quantiser for frames that do not exist, and
                // a stale one would be a measurement of the past presented as the present.
                avg_qp: (qp_n > prev_qp_n)
                    .then(|| (qp_sum - prev_qp_sum) as f32 / (qp_n - prev_qp_n) as f32),
                encode_ms: if attempts > prev_attempts {
                    (encode_us - prev_encode_us) as f32 / (attempts - prev_attempts) as f32 / 1000.0
                } else {
                    0.0
                },
                spend_ratio: if allowed_bits > 0.0 {
                    produced_bits / allowed_bits
                } else {
                    0.0
                },
                // What actually went on the wire, against what the link drains — keyframes
                // excluded. The other half of "these pixels do not fit", and unlike a queue
                // depth it names the cause rather than the symptom.
                //
                // Excluded because an IDR of 40 to 80 kB lands inside one 200 ms window and
                // reads there as several times the link's capacity, which is a statement
                // about a single frame and not about the resolution. Over its GOP the same
                // keyframe amortises to about 40 kbps.
                rung_fps_hint: target.fps() as f32,
                qp_ceiling,
                // What the brake is withholding. The ladder has to see it: a rung held by
                // throwing away a third of the frames is not being held.
                drop_ratio: fd_ratio,
                report,
            };
            prev_bytes = bytes;
            prev_egress_bytes = egress_bytes_now;
            prev_key_bytes = key_bytes;
            prev_attempts = attempts;
            prev_encode_us = encode_us;
            prev_qp_sum = qp_sum;
            prev_qp_n = qp_n;

            // The ladder is priced against the real screen as soon as capture reports it;
            // the probe target follows from that and from the evidence, inside the tick.
            if let Some((sw, sh)) = target.source() {
                quality.set_source(sw, sh);
            }

            // The media path changed under the session (another candidate pair, or ICE
            // bringing a lost path back): the round-trip baseline the brake judges against
            // describes the old path. Before the tick, so this tick's report is judged
            // against the new one.
            // Acquire: the transport stores the pair's kind before it moves the count.
            let path_changes = path_gauge.load(Ordering::Acquire);
            let path_kind = path_kind_of(kind_gauge.load(Ordering::Relaxed));
            if path_changes != prev_path_changes {
                let name = |k: Option<crate::quality::PathKind>| {
                    k.map_or("unknown", crate::quality::PathKind::as_str)
                };
                tracing::debug!(
                    session = %control_sid,
                    changes = path_changes.wrapping_sub(prev_path_changes),
                    total = path_changes,
                    from = name(prev_path_kind),
                    to = name(path_kind),
                    rtt_base_ms = ?quality.rtt_base_ms(),
                    "the transport reports the media path changed: the controller's \
                     round-trip baseline starts over, and a more direct pair is probed \
                     again"
                );
                prev_path_changes = path_changes;
                quality.note_path_move("transport", prev_path_kind, path_kind);
                // The summary's episode, named by the pair the media moved to.
                summary.instant(
                    Instant::now(),
                    afklink_protocol::metrics::SessionEpisodeKind::PathChange,
                    Some(name(path_kind)),
                );
            }
            prev_path_kind = path_kind;
            // A capture restart the encode thread made since the last tick (`capture
            // restarted`): the summary's episode, with its cause.
            let (capture_restarts, capture_cause) = health.capture_restarts();
            if capture_restarts != prev_capture_restarts {
                // Several in one tick are one episode (the last one's cause): said here,
                // so the count in the log and the episodes listed can be told apart.
                let merged = capture_restarts.wrapping_sub(prev_capture_restarts);
                if merged > 1 {
                    tracing::debug!(
                        session = %control_sid,
                        merged,
                        total = capture_restarts,
                        cause = capture_cause.map_or("-", afklink_protocol::PipelineCause::as_str),
                        "summary: several capture restarts within one control tick; one \
                         capture_restart episode stands for them (the last one's cause)"
                    );
                }
                prev_capture_restarts = capture_restarts;
                summary.instant(
                    Instant::now(),
                    afklink_protocol::metrics::SessionEpisodeKind::CaptureRestart,
                    capture_cause.map(afklink_protocol::PipelineCause::as_str),
                );
            }

            // What has gone to the transport — frames encoded less those it discarded, and
            // their bytes — and the viewer's own count of what reached it, when a report
            // came since the last tick: drain mode's current evidence. Handed over every
            // tick; a frozen controller is reset when the hold ends.
            let sent_frames = counters
                .frames_encoded
                .load(Ordering::Relaxed)
                .saturating_sub(u64::from(discard_gauge.load(Ordering::Relaxed)));
            quality.note_frames_sent(sent_frames, counters.bytes_sent.load(Ordering::Relaxed));
            let viewer_delivery = counters.viewer_delivery_reports.load(Ordering::Acquire);
            if viewer_delivery != prev_viewer_delivery {
                prev_viewer_delivery = viewer_delivery;
                let at_us = counters.viewer_report_at_us.load(Ordering::Relaxed);
                let now_us =
                    u64::try_from(delivery_epoch.elapsed().as_micros()).unwrap_or(u64::MAX);
                quality.note_viewer_frames(crate::quality::ViewerFrames {
                    received: counters.viewer_frames_received.load(Ordering::Relaxed),
                    viewer_ms: match counters.viewer_clock_ms.load(Ordering::Relaxed) {
                        0 => None,
                        ms => Some(ms - 1),
                    },
                    age: Duration::from_micros(now_us.saturating_sub(at_us)),
                });
            }

            // The ladder still *observes* during a calibration sweep — its signals are
            // smoothed across ticks and would otherwise come back cold — but it does not
            // get to move anything. The sweep owns the actuator, which is the only way the
            // resulting data is identifiable.
            //
            // Not at all through a background hold: frozen, as `hold` above says. Nothing
            // below then has anything to take from it — no drain event, no probe target, no
            // re-anchor, no brake event — and the receiver report built above is dropped.
            let moved = if frozen {
                if fb.report.is_some() {
                    tracing::trace!(
                        "receiver report not read: the controller is frozen for a \
                         background hold"
                    );
                }
                None
            } else {
                quality.tick(fb, dt)
            };

            // Drain mode, published before anything reads the target again: the encode
            // loop withholds every frame while it is set, and the heartbeat says
            // `net_stall`. Not during a calibration sweep, which owns the pipeline. See
            // `crate::quality::QualityController::draining`.
            let draining = quality.draining() && calibration.is_none();
            if target.set_draining(draining) {
                tracing::debug!(
                    session = %control_sid,
                    draining,
                    "drain flag published to the encode loop and the heartbeat"
                );
            } else if quality.draining() && calibration.is_some() {
                tracing::trace!("drain mode not applied: a calibration sweep owns the pipeline");
            }
            if let Some(event) = quality.take_drain_event() {
                let opt = |v: Option<u32>| v.map_or_else(|| "-".to_string(), |v| v.to_string());
                // The summary's `drain` episode: from the line that opens it to the line
                // that closes it, named by what started it.
                match &event {
                    crate::quality::DrainEvent::Entered { by_silence, .. } => {
                        summary.begin(
                            Instant::now(),
                            afklink_protocol::metrics::SessionEpisodeKind::Drain,
                            Some(if *by_silence { "silence" } else { "rtt" }),
                        );
                    }
                    crate::quality::DrainEvent::Left { .. } => summary.end(
                        Instant::now(),
                        afklink_protocol::metrics::SessionEpisodeKind::Drain,
                    ),
                }
                match event {
                    crate::quality::DrainEvent::Entered {
                        rtt_ms,
                        ref_ms,
                        enter_at_ms,
                        by_silence,
                        sent_kbps,
                        budget_kbps,
                    } => tracing::info!(
                        rtt_ms,
                        rtt_base_ms = opt(ref_ms),
                        enter_at_ms,
                        by_silence,
                        sent_kbps,
                        budget_kbps,
                        estimate_kbps = fb.estimate_kbps,
                        queue_age_ms = fb.queue_age_ms,
                        rung = %format!("{}p@{}", target.max_h(), target.fps()),
                        "drain mode entered: the network path is holding a backlog of \
                         frames already sent, so nothing more is encoded until it drains"
                    ),
                    crate::quality::DrainEvent::Left {
                        why,
                        rtt_ms,
                        exit_below_ms,
                        held_ms,
                        peak_rtt_ms,
                        reports,
                        resume_kbps,
                    } => {
                        // The resume is a keyframe: the viewer may have given up on frames
                        // that arrived tens of seconds late, and whatever it shows now is
                        // replaced by a picture that needs nothing before it.
                        pending_kf.store(true, Ordering::SeqCst);
                        tracing::info!(
                            why,
                            rtt_ms = opt(rtt_ms),
                            exit_below_ms,
                            held_ms,
                            peak_rtt_ms,
                            reports,
                            resume_kbps,
                            estimate_kbps = fb.estimate_kbps,
                            rung = %format!("{}p@{}", target.max_h(), target.fps()),
                            "drain mode left: resuming with a keyframe at a conservative \
                             budget"
                        );
                    }
                }
            }

            // How far congestion control may probe: the ladder's ceiling for the first three
            // seconds of media on a path (str0m's opening probes and the exponential probing
            // behind them), then twice the capacity the path has been measured carrying —
            // before there is any, twice the best estimate seen — capped at what the ladder
            // can use, re-sent when it moves by a fifth (at most once a second, but the end of
            // the opening, a rise before any evidence, and a clean rise in the first seconds
            // at once). Not the ladder's ceiling for the whole session: str0m's periodic ALR
            // probe goes to twice that whatever the estimate is — 20.6 Mbps bursts into a
            // 700 kbps 3G link — and str0m 0.24 also probes in silence, so holding the
            // ceiling until the first evidence makes the same bursts. See
            // `crate::quality::QualityController::probe_target_kbps`.
            //
            // Recorded only once it is actually on its way: updating `desired_kbps` before a
            // `try_send` would let a full control channel drop the message *permanently* while
            // the log said the change had been made. The controller counts a target as sent
            // only when told so, and offers it again on the next tick when it is not.
            if let Some(want) = quality.take_probe_target() {
                match control_tx.try_send(PeerControl::SetDesiredBitrate(want)) {
                    Ok(()) => {
                        tracing::debug!(
                            from_kbps = desired_kbps,
                            desired_kbps = want,
                            capacity_kbps = quality.capacity_kbps(),
                            opening = quality.probe_opening(),
                            evidence = quality.probe_evidence_seen(),
                            best_estimate_kbps = quality.probe_best_kbps(),
                            estimate_kbps = fb.estimate_kbps,
                            "bwe probe target sent"
                        );
                        quality.probe_target_sent(want);
                        // A ceiling from before a hold still waiting to go back is moot.
                        hold.desired_sent(want);
                        desired_kbps = want;
                        reprice_refused = false;
                    }
                    // Retried on the next tick, so said once per run of refusals.
                    Err(e) => {
                        if !reprice_refused {
                            reprice_refused = true;
                            tracing::debug!(
                                desired_kbps = want,
                                "bwe probe target refused by the peer ({e}); retrying \
                                 every tick"
                            );
                        }
                    }
                }
            }

            // The one thing this task tells congestion control about itself.
            //
            // str0m's pacer drains at `estimate * 1.1` and takes no instruction, so after
            // a pause the budget the ladder computes from its informative floor cannot
            // reach the wire — it queues inside str0m and the delay controller reads that
            // queue as overuse. `ResetBwe` hands the estimator a starting point the link
            // was measured carrying and lets it measure again from there. Two triggers:
            // motion resuming after a pause of ours, and a collapse in the middle of motion
            // that the receiver reports clean — round trip at its baseline, no real loss —
            // which is str0m cutting to `0.85 x acked` on an acked rate that was our own
            // quiet. Never against a collapse the receiver says was a queue or loss: see
            // `crate::quality::QualityController::tick`.
            //
            // Taken even during a sweep, so a stale value cannot be delivered later, and
            // sent only outside one: the sweep owns the actuators, and a probe burst in
            // the middle of a calibration point is a confounder in the data it exists to
            // produce.
            //
            // Not while the ceiling from before a background hold is still waiting to go
            // back: a re-anchor restores the ceiling it finds at the peer, and it would find
            // the hold's. The decision stays in the controller until then.
            let reanchor = if hold.reanchor_may_go() {
                quality.take_bwe_reanchor()
            } else {
                None
            };
            if let Some(kbps) = reanchor {
                let r = quality.last_reanchor();
                let opt = |v: Option<u32>| v.map_or_else(|| "-".to_string(), |v| v.to_string());
                let trigger = r.map_or("-", |r| r.trigger.as_str());
                // A hold's restart must measure the resumed video, so the peer applies it
                // right before handing str0m the next frame (`ReanchorTrigger::at_next_frame`).
                let at_next_frame = r.is_some_and(|r| r.trigger.at_next_frame());
                // A path change's: its opening probes may reach past the restart value
                // (`Reanchor::probe_cap_kbps`).
                let probe_cap = r.and_then(|r| r.probe_cap_kbps);
                let control = match (at_next_frame, probe_cap) {
                    (true, _) => PeerControl::ResetBweAtNextFrame(kbps),
                    (false, Some(probe_cap_kbps)) => PeerControl::ResetBweProbing {
                        kbps,
                        probe_cap_kbps,
                    },
                    (false, None) => PeerControl::ResetBwe(kbps),
                };
                if calibration.is_some() {
                    tracing::debug!(
                        kbps,
                        trigger,
                        "bwe re-anchor not sent: a calibration sweep owns the actuators"
                    );
                } else if let Err(e) = control_tx.try_send(control) {
                    // The controller has already started holding the collapse on the
                    // assumption that this went out; it will see the estimate not come
                    // back and release the hold within `CLEAN_COLLAPSE_HOLD`.
                    tracing::warn!(
                        kbps,
                        trigger,
                        error = %e,
                        "bwe re-anchor dropped: the peer's control channel refused it"
                    );
                } else {
                    tracing::info!(
                        trigger,
                        kbps,
                        at_next_frame,
                        probe_cap_kbps = %probe_cap
                            .map_or_else(|| "-".to_string(), |c| c.to_string()),
                        estimate_kbps = fb.estimate_kbps,
                        ratio = format!(
                            "{:.2}",
                            f64::from(kbps) / f64::from(fb.estimate_kbps.max(1))
                        ),
                        capacity_kbps = r.map_or(0, |r| r.capacity_kbps),
                        rtt_ms = opt(r.and_then(|r| r.rtt_ms)),
                        rtt_base_ms = opt(r.and_then(|r| r.rtt_base_ms)),
                        loss_pct = r.and_then(|r| r.loss_pct).map_or_else(
                            || "-".to_string(),
                            |l| format!("{l:.2}")
                        ),
                        spend_ratio = format!("{:.2}", fb.spend_ratio),
                        rung = %format!("{}p@{}", target.max_h(), target.fps()),
                        "{}",
                        match r.map(|r| r.trigger) {
                            Some(crate::quality::ReanchorTrigger::CleanCollapse) => {
                                "bwe re-anchor requested: the estimate collapsed to under \
                                 half the capacity evidence while the receiver reports \
                                 the path clean"
                            }
                            Some(crate::quality::ReanchorTrigger::DrainResume) => {
                                "bwe re-anchor requested: drain mode is over and the \
                                 estimate our silence left is under the resume budget"
                            }
                            Some(crate::quality::ReanchorTrigger::OutageResume) => {
                                "bwe re-anchor requested: the receiver is back after an \
                                 outage and reports the path clean, and the estimate the \
                                 outage left is under two thirds of the capacity evidence"
                            }
                            Some(crate::quality::ReanchorTrigger::IdleClimb) => {
                                "bwe re-anchor requested: the ladder climbs on an idle \
                                 screen on the capacity evidence, and the estimate our \
                                 silence left is under half of it"
                            }
                            Some(crate::quality::ReanchorTrigger::HoldResume) => {
                                "bwe re-anchor requested: a background hold is over; str0m \
                                 is restarted right before the resumed video's first frame, \
                                 at the capacity evidence from before the hold or its \
                                 estimate, whichever is larger, so its acknowledged rate is \
                                 the video's and not the hold's padding"
                            }
                            Some(crate::quality::ReanchorTrigger::PathChange) => {
                                "bwe re-anchor requested: the media moved to a more direct \
                                 path; str0m's opening probes run again on it from the live \
                                 estimate, up to twice the probe target (probe_cap_kbps)"
                            }
                            _ => {
                                "bwe re-anchor requested: motion resumed after an \
                                 application-limited pause, and the estimate our silence \
                                 collapsed is under half the capacity evidence"
                            }
                        }
                    );
                }
            }

            // The loss/round-trip brake, in the log whenever it moves.
            //
            // Every line carries what the receiver reported, the baseline the round trip
            // was judged against, and the budget before and after, so an episode can be
            // read off the log without re-deriving it from pipeline lines.
            //
            // Rate-limited where it can repeat. A dying link reports once a second for as
            // long as it is dying and the brake may tighten on most of those reports, so
            // `tightened` is printed at most once per `BRAKE_TIGHTEN_LOG_EVERY` and the
            // next printed line says how many were held back. `engaged` and `released` are
            // always printed: each needs a receiver report the previous one did not have,
            // so they cannot come faster than one a second, and an episode whose start or
            // end is missing from the log is an episode nobody can read.
            if let Some(event) = quality.take_brake_event() {
                use crate::quality::BrakeEvent;
                let (what, d) = match event {
                    BrakeEvent::Engaged(d) => ("engaged", d),
                    BrakeEvent::Tightened(d) => ("tightened", d),
                    BrakeEvent::Released(d) => ("released", d),
                };
                // The summary's `brake` episode: `engaged` to `released`, the engaging
                // cause its code — whether or not this line is printed (`tightened` may be
                // held back; the episode goes on).
                match event {
                    BrakeEvent::Engaged(d) => summary.begin(
                        now,
                        afklink_protocol::metrics::SessionEpisodeKind::Brake,
                        Some(d.cause.as_str()),
                    ),
                    BrakeEvent::Released(_) => {
                        summary.end(now, afklink_protocol::metrics::SessionEpisodeKind::Brake)
                    }
                    BrakeEvent::Tightened(_) => {}
                }
                let tightening = matches!(event, BrakeEvent::Tightened(_));
                let print = !tightening
                    || brake_tighten_logged_at
                        .is_none_or(|t| now.duration_since(t) >= BRAKE_TIGHTEN_LOG_EVERY);
                if print {
                    if tightening {
                        brake_tighten_logged_at = Some(now);
                    }
                    let opt = |v: Option<u32>| v.map_or_else(|| "-".to_string(), |v| v.to_string());
                    tracing::info!(
                        brake = what,
                        cause = d.cause.as_str(),
                        loss_pct = d
                            .loss_pct
                            .map_or_else(|| "-".to_string(), |l| format!("{l:.2}")),
                        rtt_ms = opt(d.rtt_ms),
                        rtt_base_ms = opt(d.rtt_base_ms),
                        budget_before_kbps = d.before_kbps,
                        budget_after_kbps = d.after_kbps,
                        estimate_kbps = fb.estimate_kbps,
                        rung = %format!("{}p@{}", target.max_h(), target.fps()),
                        suppressed = brake_suppressed,
                        "{}",
                        match event {
                            BrakeEvent::Engaged(d)
                                if d.cause == crate::quality::BrakeCause::Drain =>
                            {
                                "brake engaged: drain mode is over, so the budget resumes \
                                 at a conservative share of what the receiver last \
                                 confirmed, and releases as it reports the path clean"
                            }
                            BrakeEvent::Engaged(_) => {
                                "brake engaged: the receiver reports the link is not \
                                 carrying what we send, so the budget is cut below the \
                                 estimate"
                            }
                            BrakeEvent::Tightened(_) => {
                                "brake tightened: the next report still says the link is \
                                 not carrying it"
                            }
                            BrakeEvent::Released(d)
                                if d.cause == crate::quality::BrakeCause::Resumed =>
                            {
                                "brake released: it was set by silence alone, and the \
                                 receiver is back and reports the path clean; congestion \
                                 control is re-anchored at the capacity evidence"
                            }
                            BrakeEvent::Released(_) => {
                                "brake released: the ceiling has grown back to what the \
                                 estimate allows"
                            }
                        }
                    );
                    brake_suppressed = 0;
                } else {
                    brake_suppressed = brake_suppressed.saturating_add(1);
                }
            }

            if let Some(rung) = moved.filter(|_| calibration.is_none()) {
                tracing::info!(
                    rung = %format!("{}p@{}", rung.max_h, rung.fps),
                    estimate_kbps = fb.estimate_kbps,
                    // Every input the decision was made on, so a rung change can be
                    // explained from the log without re-deriving it from neighbouring
                    // lines. The last three diagnoses had to do exactly that, and two of
                    // them reconstructed it wrongly.
                    avg_qp = fb.avg_qp.map_or_else(
                        || "-".to_string(),
                        |qp| format!("{qp:.1}")
                    ),
                    queue_age_ms = fb.queue_age_ms,
                    encode_ms = format!("{:.1}", fb.encode_ms),
                    spend_ratio = format!("{:.2}", fb.spend_ratio),
                    // Which arm moved it: `down`, `brake`, `climb`, or `startup-thin` for
                    // the one-time jump on a link measured thin in the first seconds.
                    reason = quality.last_move_reason(),
                    "quality changed"
                );
                target.set(rung);
                counters.quality_changes.fetch_add(1, Ordering::Relaxed);
                // A running minimum: the worst the session ever got is the interesting
                // number. A last-value column would read as "fine" for a session that
                // spent ten minutes at 360p and recovered in its final seconds.
                counters
                    .lowest_height
                    .fetch_min(rung.max_h, Ordering::Relaxed);
                summary.instant(
                    now,
                    afklink_protocol::metrics::SessionEpisodeKind::RungChange,
                    Some(quality.last_move_reason()),
                );
            }
            // The pipeline line, on this clock rather than the encode thread's.
            //
            // Emitted per encoded frame, a "one second" window would really be "one second, then
            // whenever the next frame happens to arrive": it stretches (to 1.73 s, measured)
            // during the very collapse it should describe, overstating every rate on the line by
            // up to 70% against the raw counts beside them, and it stops entirely when the
            // pipeline stops — the one circumstance where the log is the only evidence there is.
            // A fixed clock has neither problem. If no frame arrives, the line still says so.
            log_ticks += 1;
            if log_ticks * dt >= Duration::from_secs(1) {
                let secs = (log_ticks * dt).as_secs_f64();
                log_ticks = 0;
                let captured = counters.frames_captured.load(Ordering::Relaxed);
                let stale = counters.frames_dropped_stale.load(Ordering::Relaxed);
                let skipped = counters.frames_skipped_encoder.load(Ordering::Relaxed);
                let errors = counters.encode_errors.load(Ordering::Relaxed);
                let encoded = counters.frames_encoded.load(Ordering::Relaxed);
                let (offered, early) = target.take_capture_counts();
                let d = |now: u64, prev: &mut u64| {
                    let out = now.saturating_sub(*prev);
                    *prev = now;
                    out
                };
                // The second, for the journal: weak when the picture stood for the network
                // or the ladder held it low (`crate::journal::weak_second`). It counts only
                // once the session's video is up, which the journal knows — and not through
                // a background hold, when there is no video to be weak or not.
                let journal = journal.as_ref().filter(|_| !frozen);
                if let Some(journal) = journal {
                    journal.session_second(
                        &control_sid,
                        crate::journal::Second {
                            weak: crate::journal::weak_second(
                                draining,
                                quality.pinned_height().is_some(),
                                target.max_h(),
                                target.fps(),
                            ),
                            game_only: game_status.is_active(),
                        },
                        crate::journal::now_ms(),
                    );
                }
                let viewer = log_viewer.take(&counters.viewer);
                let game_line = game_status.line_fields();
                let encoded_second = d(encoded, &mut log_encoded);
                let discarded_second = d(
                    u64::from(discard_gauge.load(Ordering::Relaxed)),
                    &mut log_discarded,
                );
                // The summary's second, on this line's own numbers: motion or not by what
                // was sent (encoded, less discarded), the page and the hold; a motion
                // second's time on the rung in force (`rung_s`), and the freeze rule on what
                // the viewer says it presented (`v_pres`). Its time is what the counters
                // covered — measured since the last line, at most `SECOND_COUNTED_MAX` — not
                // the nominal `secs` the rates below divide by: a starved runtime stretches
                // the five ticks.
                let now = Instant::now();
                let counted = summary_clock.step(now, &control_sid);
                summary.second(
                    now,
                    crate::summary::Second {
                        sent_frames: encoded_second.saturating_sub(discarded_second),
                        presented: viewer.presented,
                        page_hidden: bg.page_hidden(),
                        held: frozen,
                        height: target.max_h(),
                        secs: counted.as_secs_f64(),
                    },
                );
                tracing::info!(
                    offered_fps = format!("{:.1}", f64::from(offered) / secs),
                    early = early,
                    capture_fps =
                        format!("{:.1}", d(captured, &mut log_captured) as f64 / secs),
                    encode_fps = format!("{:.1}", encoded_second as f64 / secs),
                    encode_ms = format!("{:.1}", fb.encode_ms),
                    // Frames the transport threw away after the encoder had made them.
                    //
                    // Without this, `encode_fps` reads 30 through a third of a second of
                    // frozen picture, because it counts what the encoder produced and the
                    // breaker discards downstream of it — "it said 30 fps and the picture
                    // froze". The discards are on the line so it explains itself.
                    discarded = discarded_second,
                    // The quantiser, which is what the ladder steers on.
                    avg_qp = fb
                        .avg_qp
                        .map_or_else(|| "-".to_string(), |qp| format!("{qp:.1}")),
                    // libwebrtc's bit bucket, running alongside the signal the ladder
                    // actually uses so the two can be compared on a recording instead of
                    // in an argument. `fd_full` is the proportional one — bucket level
                    // over half a second of allowance, so above 1.0 means production
                    // outran the link within the last half second. `fd_ratio` is the
                    // smoothed indicator, which saturates rather than scaling because
                    // nothing here obeys it. Neither moves the ladder yet.
                    fd_full = format!("{:.2}", fd_fullness),
                    fd_ratio = format!("{:.2}", fd_ratio),
                    // Frames the bit bucket withheld to hold the bitrate. Rising while the
                    // queue is empty is the brake working, not a fault — which is why it
                    // is its own column and not folded into `dropped_stale`.
                    dropped_rate = d(
                        counters.frames_dropped_rate.load(Ordering::Relaxed),
                        &mut log_dropped_rate
                    ),
                    // Frames the latency guard withheld before the encoder, because the
                    // send queue was already past `QUEUE_SKIP_MS`. Next to `dropped_rate`
                    // and `queue_age_ms` because the three are read together: this rising
                    // while `queue_age_ms` falls is the guard doing its job, and this
                    // rising while `queue_age_ms` stays high is the guard failing to.
                    skipped_queue = d(
                        counters.frames_skipped_queue.load(Ordering::Relaxed),
                        &mut log_skipped_queue
                    ),
                    kbps = format!(
                        "{:.0}",
                        d(bytes, &mut log_bytes) as f64 * 8.0 / secs / 1000.0
                    ),
                    // What actually left the socket, from the transport's own one-second
                    // meter. On the line next to `kbps` because the two together *are* the
                    // conservation check the ladder runs: a human reading this line sees the
                    // half the ladder divides by.
                    egress_kbps = egress_gauge.load(Ordering::Relaxed),
                    budget_kbps = target.target_kbps().unwrap_or(0),
                    estimate_kbps = fb.estimate_kbps,
                    // Milliseconds, not bytes: a byte count cannot be compared against the one
                    // requirement this product actually has.
                    queue_age_ms = fb.queue_age_ms,
                    in_flight = target.outstanding_bytes(),
                    // The far end. `rtt_ms=-` means the last stats interval carried no
                    // receiver report — none yet, or none this interval — which is not the
                    // same as zero and must not print as a round trip either: str0m
                    // repeats the last one, and the bench blackout printed 135 for ten
                    // seconds of a dead link. See `rtt_field`.
                    rtt_ms = rtt_field(
                        counters.rtt_ms.load(Ordering::Relaxed),
                        counters.loss_bp.load(Ordering::Relaxed)
                    ),
                    // `-` when the last stats interval carried no receiver report — str0m's
                    // `None`; printed as 0.00 it would be indistinguishable from a clean
                    // report.
                    loss_pct = match counters.loss_bp.load(Ordering::Relaxed) {
                        u32::MAX => "-".to_string(),
                        bp => format!("{:.2}", f64::from(bp) / 100.0),
                    },
                    // How old the last fresh report is, by the controller's clock: about a
                    // second on a healthy link, two after one of Chrome's ordinary empty
                    // intervals, and growing through an outage.
                    report_age_ms = report_age_field(quality.report_age()),
                    // What the round trip is judged against, and the brake it drives: its
                    // phase (`engaged`, `holding`, `releasing`, `-`) and its ceiling on the
                    // budget. With these three the next session's brake decisions can be
                    // checked from the pipeline lines alone.
                    rtt_base_ms = quality
                        .rtt_base_ms()
                        .map_or_else(|| "-".to_string(), |v| v.to_string()),
                    brake = quality.brake_state(),
                    brake_kbps = quality
                        .brake_kbps()
                        .map_or_else(|| "-".to_string(), |v| v.to_string()),
                    // The best recent evidence of what the path carries — the loaded
                    // estimate, or a probe or burst the receiver called clean — and what
                    // the controller makes of the estimate against it: `-` (not under
                    // half), `clean` (a clean collapse held: re-anchored, the queue-reading
                    // descent arms masked), or why a collapse is not treated as clean
                    // (`rtt`, `loss`, `brake`, `no-report`, `no-baseline`, `spacing`,
                    // `no-demand`). With these two a collapse and the controller's answer
                    // to it can be read off the pipeline lines alone.
                    capacity_kbps = quality.capacity_kbps(),
                    collapse = quality.collapse_state(),
                    // The viewer's own latency. `queue_age_ms` is our send queue; `rtt_ms` is
                    // the path; `jbuf_ms` is the browser deliberately holding frames back to
                    // absorb jitter. Those three plus encode time are the end-to-end sum, and
                    // this term is plausibly the largest one.
                    //
                    // `-` means the viewer has not reported. An older viewer never will,
                    // and a still screen emits no frames to average over, so absence here
                    // is ordinary rather than a fault.
                    jbuf_ms = match counters.jbuf_tenth_ms.load(Ordering::Relaxed) {
                        0 => "-".to_string(),
                        v => format!("{:.1}", f64::from(v) / 10.0),
                    },
                    jitter_ms = match counters.jitter_tenth_ms.load(Ordering::Relaxed) {
                        0 => "-".to_string(),
                        v => format!("{:.1}", f64::from(v) / 10.0),
                    },
                    plis = d(counters.plis.load(Ordering::Relaxed), &mut log_plis),
                    nacks = d(counters.nacks.load(Ordering::Relaxed), &mut log_nacks),
                    spend_ratio = format!("{:.2}", fb.spend_ratio),
                    rung = %format!("{}p@{}", target.max_h(), target.fps()),
                    idr_bytes = counters.last_keyframe_bytes.load(Ordering::Relaxed),
                    dropped_stale = d(stale, &mut log_stale),
                    skipped_by_encoder = d(skipped, &mut log_skipped),
                    errors = d(errors, &mut log_errors),
                    source = %format!(
                        "{}x{}",
                        counters.encoded_w.load(Ordering::Relaxed),
                        counters.encoded_h.load(Ordering::Relaxed)
                    ),
                    // The viewer's own account, since the last line: frames it decoded,
                    // frames that reached its screen, frames it dropped, keyframes it
                    // decoded, freezes it counted, and its render watchdog's step. `v_dec`
                    // climbing with `v_pres` at 0 is a picture frozen on the viewer while
                    // everything upstream works (seen on iPhone WebKit). `-` means no
                    // report this second, or a viewer that does not expose it. After
                    // `source` and every older field, so no first-match lookup of an
                    // existing name can land on one of these.
                    v_dec = viewer.dec,
                    v_pres = viewer.pres,
                    v_drop = viewer.drop,
                    v_kf = viewer.kf,
                    v_frz = viewer.frz,
                    v_wd = viewer.wd,
                    // What congestion control was last told to probe towards: the ladder's
                    // ceiling in a path's opening, then twice the capacity evidence (before
                    // any, twice the best estimate seen), capped at the ceiling. Last on the
                    // line, after `source`, so no parser that looks up `kbps=` by first
                    // match can land on it.
                    desired_kbps,
                    // Drain mode: frames withheld because the path is holding a backlog
                    // of ours, and how long it has been in force (`-` outside it). After
                    // every older field, for the same first-match reason. See
                    // `crate::quality::QualityController::draining`.
                    skipped_drain = d(
                        counters.frames_skipped_drain.load(Ordering::Relaxed),
                        &mut log_skipped_drain
                    ),
                    drain_ms = quality
                        .drain_held()
                        .map_or_else(|| "-".to_string(), |h| h.as_millis().to_string()),
                    // «Only the game window»: the window's state (`absent`, `starting`,
                    // `minimized`, `shown`) and its picture's size before scaling — the
                    // client area the capture is cropped to. `-` outside the mode, and for
                    // a size not captured yet. Last, for the first-match reason above.
                    game = game_line.0,
                    game_src = %game_line.1,
                    // The background hold in progress, in milliseconds; `-` outside one.
                    // After `game_src`, for the first-match reason above: `ladder_replay`
                    // freezes its controller on a second that carries it.
                    bg_hold_ms = %bg.current(Instant::now()).map_or_else(
                        || "-".to_string(),
                        |h| h.as_millis().to_string()
                    ),
                    // The viewer's PLIs and FIRs (counted in `plis` too) not honoured since
                    // the last line, because a keyframe already on its way answers them:
                    // each an IDR not sent. Last, for the first-match reason above. See
                    // `crate::keyframe_window`.
                    kf_suppressed = d(
                        counters.keyframe_requests_suppressed.load(Ordering::Relaxed),
                        &mut log_kf_suppressed
                    ),
                    "pipeline"
                );
            }

            // The budget every tick, not only when the rung moves. Rungs change every few
            // seconds at most; the link changes continuously.
            //
            // Not during a sweep: the whole experiment is that the bitrate is dictated
            // rather than chosen, so that it varies independently of the resolution.
            if calibration.is_none() {
                target.set_target_kbps(quality.encoder_target_kbps());
            }
        }
    })
}

/// Where an encoded frame goes, and the accounting that has to travel with it.
///
/// One struct rather than two parameters because the two must never be separated: a frame put on
/// the channel without its bytes being counted is a frame the latency signal cannot see, which is
/// exactly the defect this pair replaced.
struct MediaSink {
    tx: mpsc::Sender<afklink_transport::MediaSample>,
    /// Bytes committed to [`Self::tx`] and not yet inside str0m. See `Peer::queued_media_bytes`.
    queued_bytes: Arc<AtomicU32>,
    /// The NACKs the peer has counted from the viewer, live (`Peer::nacks_received`): read as a
    /// keyframe is handed over and as the viewer's requests are judged (`crate::keyframe_window`).
    nacks: Arc<AtomicU64>,
}

struct EncodeControl {
    stop: Arc<AtomicBool>,
    /// A media-only session's feed ([`media_feed`]); `None` for the agent's own sessions.
    feed: Option<Arc<media_feed::FramePublisher>>,
}

impl EncodeControl {
    fn ordinary(stop: Arc<AtomicBool>) -> Self {
        Self { stop, feed: None }
    }

    fn admits_media(&self) -> bool {
        if let Some(feed) = &self.feed {
            return feed.permits();
        }
        true
    }

    fn receive_latest(
        &self,
        frames: &std::sync::mpsc::Receiver<Frame>,
        wait: Duration,
    ) -> Result<(Frame, u32), std::sync::mpsc::RecvTimeoutError> {
        if let Some(feed) = &self.feed {
            return feed.receive(wait);
        }
        let mut frame = frames.recv_timeout(wait)?;
        let mut offered = 1;
        while let Ok(next) = frames.try_recv() {
            frame = next;
            offered += 1;
        }
        Ok((frame, offered))
    }
}

/// Runs on a dedicated thread: pull frames, encode, push samples to the peer — and keep the
/// pipeline alive while doing it.
///
/// `sup` watches the capture and the encoder and puts either back when it fails (see
/// `crate::pipeline`); the keyframe flag it sets after a recovery is the one the transport's
/// requests, a drain's end and the Mini App's `kf` set too, and always honoured. The viewer's PLIs
/// and FIRs come through `viewer_kf`, and are held against the keyframe already on its way
/// (`crate::keyframe_window`). Returns the `session_end` reason when the pipeline had to be given
/// up on, `None` when the loop ended because the session did.
#[allow(
    clippy::too_many_arguments,
    reason = "the session's pieces the encode thread owns or shares; a struct of them would be \
              unpacked on the first line"
)]
fn encode_loop(
    encoder: Box<dyn Encoder>,
    frame_rx: std::sync::mpsc::Receiver<Frame>,
    sink: MediaSink,
    control: EncodeControl,
    target: Arc<crate::quality::QualityTarget>,
    counters: Arc<SessionCounters>,
    mut sup: crate::pipeline::Supervisor,
    viewer_kf: &crate::keyframe_window::ViewerAsks,
) -> Option<&'static str> {
    // `None` while the encoder is condemned and a new one is not yet due. See `Supervisor`.
    let mut encoder: Option<Box<dyn Encoder>> = Some(encoder);
    let pending_kf = sup.keyframe_flag();
    // The window the last keyframe opened, against which the viewer's requests are judged.
    let mut kf_window = crate::keyframe_window::KeyframeWindow::new();
    let start = Instant::now();
    let mut count: u64 = 0;
    let mut source = (0u32, 0u32);
    // Per-frame telemetry, for the calibration sweep only. See the `frame` line below.
    let calibrating = calibration_armed();
    let mut last_encoded: Option<Instant> = None;

    // libwebrtc's bit bucket, fed here because this is the one place both of its inputs are
    // visible: every frame the capturer offers arrives on `frame_rx`, and every encoded frame's
    // size comes back from `encoder.encode`. Splitting it across two threads would have needed a
    // lock on a per-frame path for a diagnostic.
    //
    // It decides two things. `drop_frame` below withholds frames to hold the rate — the brake
    // OpenH264 does not have — and its `drop_ratio` reaches the ladder as `Feedback::drop_ratio`,
    // which sheds the rung once the brake is doing more than a third of the work. `fullness` is
    // still only a number on the `pipeline` line.
    let mut dropper = crate::frame_dropper::FrameDropper::new();
    // The rate the capturer is *offering* frames at, measured over a sliding second. This is
    // `Leak`'s argument and getting it from anywhere else would break the component's central
    // invariant: `leak` is called once per offered frame and subtracts `target / rate`, so the
    // drain per wall-clock second equals the target only if `rate` is the rate of those calls.
    // libwebrtc reads the same quantity from `GetInputFrameRate()`.
    let mut offered_window = (Instant::now(), 0u32);
    let mut offered_fps = 0u32;
    // The rate handed to OpenH264's rate control: fast to rise, slow to fall, clamped to the rung.
    // See the long note at the `set_target` call below for why those three properties and not a
    // plain average.
    let mut arrival_fps = 0.0f32;
    let mut fps_known = false;
    let mut committed_fps = 0u32;
    let mut last_arrival: Option<Instant> = None;
    // Consecutive frames withheld by the queue guard. See `skip_for_queue`.
    let mut queue_skips = 0u32;
    // The guard's other half, past the transport breaker's limit. See `HardHold`.
    let mut hard_hold = HardHold::default();
    // Frames withheld in the current drain, and since when. See `QualityController::draining`.
    let mut drain_withheld = 0u32;
    let mut drain_since: Option<Instant> = None;
    // Frames dropped unencoded as a background hold began. See `crate::bg_hold`.
    let mut hold_dropped = 0u32;
    // The two per-frame decisions worth a line — the frame rate handed to rate control, and a
    // keyframe — at most once a second each, with a count of what was held back in between. See
    // `Throttle`.
    let mut fps_log = Throttle::new(Duration::from_secs(1));
    let mut keyframe_log = Throttle::new(Duration::from_secs(1));

    let fatal = loop {
        if control.stop.load(Ordering::SeqCst) || !control.admits_media() {
            break None;
        }
        // Supervise, every time round, frame or no frame: a dead capture sends nothing, so waiting
        // for a frame to notice it would be waiting forever.
        let now = Instant::now();
        sup.poll(now, &frame_rx);
        if encoder.is_none() && sup.encoder_due(now) {
            encoder = sup.recreate_encoder(now);
        }
        if let Some(reason) = sup.fatal_reason() {
            break Some(reason);
        }
        // Wait for the next frame, but not for long: see `pipeline::SUPERVISE_EVERY`. Then skip to
        // the newest available to minimize latency (drop stale frames rather than queue them).
        let (mut frame, offered_now) =
            match control.receive_latest(&frame_rx, crate::pipeline::SUPERVISE_EVERY) {
                Ok(batch) => batch,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    tracing::debug!("frame delivery closed; encode loop ending");
                    break None;
                }
            };
        counters
            .frames_captured
            .fetch_add(offered_now.into(), Ordering::Relaxed);
        if offered_now > 1 {
            counters
                .frames_dropped_stale
                .fetch_add((offered_now - 1).into(), Ordering::Relaxed);
        }
        // The background hold (`crate::bg_hold`): the viewer's page is hidden, and nothing is
        // encoded or sent. The supervisor has stopped the capture, or does on its next look; what
        // arrives in between is dropped here, unencoded.
        if target.bg_hold() {
            if hold_dropped == 0 {
                tracing::debug!(
                    "background hold: frames arriving as it begins are dropped unencoded until the \
                     supervisor has stopped the capture"
                );
            }
            hold_dropped = hold_dropped.saturating_add(offered_now);
            continue;
        }
        if hold_dropped > 0 {
            tracing::debug!(
                dropped = std::mem::take(&mut hold_dropped),
                "background hold over for the encode loop: frames dropped at its start, counted"
            );
        }
        // The frame was captured for the mode in force — or the owner has flipped «only the game
        // window» since, and a frame of the old capture (the desktop, when it was just turned on)
        // must not reach the viewer even once. The next time round, the supervisor replaces it.
        if !sup.admits_frame() || !control.admits_media() {
            continue;
        }
        sup.frame_captured(Instant::now());
        // The encoder was condemned and its replacement is not due yet: there is nothing to encode
        // this frame with. It still counted as captured, which is what the heartbeat reports.
        let Some(enc) = encoder.as_mut() else {
            tracing::trace!("frame dropped: the encoder is being replaced");
            continue;
        };

        // No rate gate here, on purpose.
        //
        // A deadline gate at 90% of the interval discards 5 to 11 of every 20 paced frames,
        // because a deadline scheduler upstream produces a correct *average* with gaps that vary
        // by a whole capture period; a token bucket refilled at the rung's frame rate is inert,
        // since the capturer admits far fewer and the bucket stays full. Neither bounds what a
        // safety net must bound: bytes in flight. That is bounded where it can be measured and
        // acted on for free — at the capturer, before the work (`QualityTarget::may_produce`). The
        // drain-to-newest loop above already stops a non-pacing producer from making this thread
        // encode stale frames.

        // The offered rate over a sliding second, then one `leak` per frame the capturer handed
        // over — including the stale ones the drain above discarded, because they were offered and
        // the wall clock does not care that we chose not to encode them.
        //
        // The rate lags by up to a second on purpose. `leak` needs the rate those calls are
        // actually arriving at, and an instantaneous inter-arrival reciprocal is not that: on a
        // change-driven capture API one 200 ms gap would read as 5 fps and drain a fifth of the
        // allowance in a single call.
        let arrived = Instant::now();
        let gap = last_arrival
            .replace(arrived)
            .map(|prev| arrived.duration_since(prev));
        offered_window.1 += offered_now;
        if offered_window.0.elapsed() >= Duration::from_secs(1) {
            let secs = offered_window.0.elapsed().as_secs_f32();
            let windowed = offered_window.1 as f32 / secs;
            offered_fps = windowed.round() as u32;
            // The window is the only thing allowed to *lower* the tracked rate. See below.
            arrival_fps = if fps_known {
                arrival_fps.min(windowed)
            } else {
                windowed
            };
            fps_known = true;
            offered_window = (Instant::now(), 0);
        }

        // Keep the encoder's budget aligned with what is actually arriving — both halves of it.
        //
        // ## Why the rung's nominal rate is the wrong number to hand over
        //
        // Rate control divides the bitrate by the frame rate to get a per-frame allowance. WGC
        // delivers frames only when the screen changes, so on a partly-moving desktop 5 to 20
        // frames a second arrive at a rung that says 30 — and the encoder then spends a fraction
        // of the budget on every frame it does get. Softer picture, for nothing:
        // `afklink-encode/examples/pipeline_bench.rs` ("bitrate actually used, 1 Mbps target, fed
        // at 12 fps") measures about 40% of the allowance spent, and
        // `examples/fps_tracking.rs` measures the repair.
        //
        // ## Why it cannot simply be the measured rate either
        //
        // The failure mode of believing a low rate is much worse than the underspend it fixes. Tell
        // the encoder 2 fps while the screen is still, then let motion resume at 30, and every
        // frame of the first second is handed `kbps/2` bits — a fifteen-fold overshoot, held until
        // the measurement catches up. Underspending costs sharpness; overshooting costs the send
        // queue, which is the one thing this product is built around.
        //
        // So the tracked rate is asymmetric, and deliberately so: it **rises on the very next
        // frame** (the instantaneous inter-arrival rate, whenever that is higher than what is
        // believed) and falls only when a full second of window says it should.
        //
        // ## And it is floored at half the rung
        //
        // The attack cannot protect the *first* frame after a quiet period, because the only
        // evidence available when that frame arrives is the long gap in front of it — which says
        // nothing about the rate behind it. So the resuming frame is always priced on a stale, low
        // number, and the lower that number the bigger the frame. Measured
        // (`afklink-encode/examples/fps_tracking.rs`, case (b): a still second at 2 fps, then 30 fps
        // of motion, worst 500 ms window against half a second of budget):
        //
        //     rung fps (untracked)     1.52x     tracked, floored at 15   1.28x
        //     tracked, no floor        2.57x     window only, no attack   4.58x
        //
        // Half the rung caps the per-frame allowance at twice nominal, so the transition costs one
        // double-sized frame instead of a second of them. It costs some of the underspend back —
        // case (a), a desktop fed at a steady 12 fps, recovers to 66% of budget where an unfloored
        // tracker reaches 77% and the rung's nominal rate manages 40% — and that is the trade:
        // when the two cannot both be had, take the one that does not overshoot.
        //
        // Before the first window completes there is no measurement, and the rung's rate is the
        // right assumption: it is what the capturer is pacing towards.
        let rung_fps = target.fps();
        let want_fps = if fps_known {
            if let Some(gap) = gap {
                // Attack. `offered_now` frames arrived across this gap, so the batch the drain
                // loop collected counts as the burst it was.
                let secs = gap.as_secs_f32().max(0.001);
                arrival_fps = arrival_fps.max(offered_now as f32 / secs);
            }
            (arrival_fps.round() as u32).clamp((rung_fps / 2).max(1), rung_fps)
        } else {
            rung_fps
        };
        // A deadband on top of the encoder's own. `OpenH264Encoder::set_target` already ignores
        // anything under half a frame, which is not enough on a change-driven source: the measured
        // rate wanders by a frame or two every window and each change is a `SetOption` crossing
        // into C. Fifteen percent is the smallest step that moves the per-frame allowance by more
        // than the rate controller's own jitter.
        if committed_fps == 0
            || u64::from(want_fps.abs_diff(committed_fps)) * 100
                >= u64::from(committed_fps) * FPS_DEADBAND_PCT
        {
            if want_fps != committed_fps {
                if let Some(held) = fps_log.ready(Instant::now()) {
                    tracing::debug!(
                        from = committed_fps,
                        to = want_fps,
                        rung_fps,
                        arrival_fps = format!("{arrival_fps:.1}"),
                        offered_fps,
                        measured = fps_known,
                        changes_held_back = held,
                        "rate control's frame rate moved past the deadband"
                    );
                }
            }
            committed_fps = want_fps;
        }
        if let Some(kbps) = target.target_kbps() {
            enc.set_target(kbps, committed_fps);
        }

        if let Some(kbps) = target.target_kbps() {
            // The allowance is this tree's own budget, which is the deviation from libwebrtc the
            // judge specified: there the argument is goog-cc's loss-based target, here it is what
            // the ladder decided to spend. `offered_fps` is the second argument only to bound
            // `drop_frame`'s run length, which nothing here calls.
            dropper.set_rates(kbps as f32, offered_fps.max(1) as f32);
        }
        for _ in 0..offered_now {
            dropper.leak(offered_fps.max(1));
        }
        target.set_frame_dropper(dropper.drop_ratio(), dropper.fullness());

        // Drain mode: the network path is holding a backlog of frames already sent, and every
        // frame encoded now would join the back of it. Nothing is encoded until the controller
        // says it has drained — not even a keyframe the viewer asks for, which waits in its flag
        // for the resume (whose own keyframe answers it). After the `leak` loop, as every other
        // withheld frame is. See `crate::quality::QualityController::draining`.
        if target.draining() {
            if drain_withheld == 0 {
                tracing::debug!(
                    rung = %format!("{}p@{}", target.max_h(), rung_fps),
                    queue_age_ms = target.queue_age_ms(),
                    "drain: withholding every frame before encoding while the network path drains"
                );
                drain_since = Some(Instant::now());
                // A keyframe in that backlog arrives that much later, if at all: its window stops
                // holding the viewer's requests (`crate::keyframe_window`).
                kf_window.note_drain(Instant::now());
            }
            drain_withheld = drain_withheld.saturating_add(1);
            counters
                .frames_skipped_drain
                .fetch_add(1, Ordering::Relaxed);
            tracing::trace!(withheld = drain_withheld, "drain: frame withheld");
            continue;
        }
        if drain_withheld > 0 {
            tracing::debug!(
                withheld = drain_withheld,
                held_ms = drain_since.map_or(0, |t| t.elapsed().as_millis() as u64),
                keyframe_pending = pending_kf.load(Ordering::SeqCst),
                "drain: over; encoding again"
            );
            drain_withheld = 0;
            drain_since = None;
        }

        // A keyframe asked for is never dropped: it is how a lost picture comes back, and
        // withholding it turns one bad second into a session that never recovers. Read before the
        // drop decision so the requests are consumed either way.
        //
        // Two kinds. The flag (`pending_kf`: the transport's broken chain, a restored path, a
        // drain's end, a restarted capture or encoder, the Mini App's `kf`) is always honoured. The
        // viewer's PLIs and FIRs are judged here, by when the latest of them arrived, against the
        // window the last keyframe opened: one sent before the viewer could have received that
        // keyframe is answered by it, and forcing another only sends the picture twice. See
        // `crate::keyframe_window`.
        //
        // Unless the path has shown since that the keyframe may not make it — loss, or a receiver
        // that went silent and reports again — when the window holds nothing more (its "When the
        // keyframe on its way cannot be trusted"). The gauges the event task keeps from str0m's
        // stats, read here: three loads a frame, and the window looks further only once a stats
        // interval. The interval count first, with acquire, as the control task reads it. And the
        // NACKs the transport counts live, read once there are requests to judge — after taking
        // them, so every NACK that arrived before them is in the count (`Peer::nacks_received`).
        kf_window.note_path(
            Instant::now(),
            crate::keyframe_window::PathNow {
                reports: counters.link_reports.load(Ordering::Acquire),
                loss_bp: counters.loss_bp.load(Ordering::Relaxed),
                nacks: counters.nacks.load(Ordering::Relaxed),
                frames_sent: count,
            },
        );
        let own_keyframe = pending_kf.swap(false, Ordering::SeqCst);
        let viewer_keyframe = match viewer_kf.take() {
            None => false,
            Some(asked) => match kf_window.judge_with(
                Instant::now(),
                asked,
                own_keyframe,
                Some(sink.nacks.load(Ordering::Acquire)),
            ) {
                crate::keyframe_window::Verdict::Honour => true,
                crate::keyframe_window::Verdict::Suppressed => {
                    counters
                        .keyframe_requests_suppressed
                        .fetch_add(u64::from(asked.count), Ordering::Relaxed);
                    false
                }
                crate::keyframe_window::Verdict::Joined => false,
            },
        };
        let forced_keyframe = own_keyframe || viewer_keyframe;
        if forced_keyframe {
            enc.request_keyframe();
        }

        // **The latency guard: the one thing that can refuse bytes before they exist.**
        //
        // Everything else in this pipeline acts on bytes that have already been made. The bit
        // bucket below is charged by `fill`, the budget is a rate the encoder may miss by a factor
        // of three on a single frame, and the ladder needs seconds. A scroll that OpenH264 codes as
        // three 100 kB intras (measured) is over before any of them has an opinion,
        // and what it leaves behind is a second of queue and a cascade of three rungs.
        //
        // So this one asks a question none of the others can: *is the queue these bytes would join
        // already past the product's latency budget?* Measured milliseconds against a constant.
        // See `QUEUE_SKIP_MS` for why that is not a byte credit, and
        // `MAX_QUEUE_SKIPS` for why it cannot starve the stream.
        //
        // Placed after the `leak` loop above on purpose. A frame withheld here was still offered by
        // the capturer, and the bit bucket's invariant is that `leak` is called once per offered
        // frame — exactly as it is for the frames the dropper itself refuses.
        let queue_age_ms = target.queue_age_ms();
        // First the hard hold: past the transport breaker's limit nothing is encoded at all, so
        // the breaker has nothing to discard and the viewer's reference chain stays whole. See
        // `HardHold`. One line per transition; the per-frame count is `skipped_queue`.
        let hard = match hard_hold.step(queue_age_ms, Instant::now()) {
            HardHoldStep::Pass => false,
            HardHoldStep::Engaged => {
                tracing::debug!(
                    queue_age_ms,
                    limit_ms = afklink_transport::QUEUE_HARD_LIMIT_MS,
                    resume_ms = afklink_transport::QUEUE_RESUME_MS,
                    max_ms = HARD_HOLD_MAX.as_millis() as u64,
                    forced_keyframe,
                    rung = %format!("{}p@{}", target.max_h(), rung_fps),
                    "queue guard: the send queue is past the transport's hard limit; withholding \
                     every frame before encoding until it drains, so the breaker has nothing to \
                     discard and no keyframe is owed"
                );
                true
            }
            HardHoldStep::Hold => true,
            HardHoldStep::Released { held, withheld } => {
                tracing::debug!(
                    queue_age_ms,
                    held_ms = held.as_millis() as u64,
                    withheld,
                    "queue guard: hard hold released — the queue drained with nothing encoded \
                     into it"
                );
                false
            }
            HardHoldStep::GaveUp { held, withheld } => {
                tracing::debug!(
                    queue_age_ms,
                    held_ms = held.as_millis() as u64,
                    withheld,
                    "queue guard: hard hold gave up with the gauge still past the limit (a stale \
                     gauge, or a queue that is not draining); frames go to the transport's breaker \
                     until the gauge is back under the resume level"
                );
                false
            }
            HardHoldStep::Rearmed => {
                tracing::debug!(
                    queue_age_ms,
                    "queue guard: the gauge is back under the resume level; the hard hold is armed \
                     again"
                );
                false
            }
        };
        // A viewer's keyframe request passes, as it passes the soft guard below.
        if hard && !forced_keyframe {
            counters
                .frames_skipped_queue
                .fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if skip_for_queue(queue_age_ms, queue_skips, forced_keyframe) {
            // One line per episode, at its start: the per-frame count is `skipped_queue` on the
            // pipeline line, and an episode is at most `MAX_QUEUE_SKIPS` frames.
            if queue_skips == 0 {
                tracing::debug!(
                    queue_age_ms,
                    limit_ms = QUEUE_SKIP_MS,
                    rung = %format!("{}p@{}", target.max_h(), rung_fps),
                    "queue guard: withholding frames until the send queue drains"
                );
            }
            queue_skips += 1;
            counters
                .frames_skipped_queue
                .fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if queue_skips > 0 {
            // Why the run ended is the half that matters: the queue drained (the guard worked), a
            // viewer's keyframe request overrode it, or the cap forced a frame through with the
            // queue still old — a stale gauge, or a queue the guard alone cannot drain.
            tracing::debug!(
                withheld = queue_skips,
                queue_age_ms,
                why = if forced_keyframe {
                    "keyframe"
                } else if queue_skips >= MAX_QUEUE_SKIPS {
                    "cap"
                } else {
                    "drained"
                },
                "queue guard released"
            );
        }
        queue_skips = 0;

        // **The encoder's brake — a safety net, not the rate controller.**
        //
        // With the camera-mode encoder the target holds (3200-4000 kbps against a 4000 kbps
        // target on screen content), so the ladder is the rate controller. The brake stays for a
        // structural reason: `skip_frames(false)` disables OpenH264's own frame skip — measurably
        // broken, 26 to 46 skips out of 46 — and OpenH264 has no VBV, so nothing inside the
        // encoder bounds what a single frame or a short burst may cost. A keyframe is 50 to 85 kB
        // whatever the budget says. Catching those is what this is for, and the control task warns
        // when it starts doing more than that (`FD_WARN_RATIO`).
        //
        // This is libwebrtc's answer too: run your own frame dropper rather than trusting the
        // codec's. It is a *duty cycle* spread over time, not a gate — `drop_frame` alternates
        // keeps and drops to hold a ratio, and its longest run is bounded (tested at three
        // frames).
        //
        // Withholding frames does lower the byte rate: on decorrelated data bytes per frame
        // scale as `interval^0.013 ± 0.34`, indistinguishable from zero, so dropping a fraction of
        // frames reduces the byte rate by that fraction. (A fit of `interval^1.248` is confounded
        // by the controller moving resolution and quantiser together.) And the decision sits
        // between capture and encode, where libwebrtc's does, on a bit bucket that knows what was
        // produced against what was allowed — not in the capturer on a queue or a credit.
        if !forced_keyframe && dropper.drop_frame() {
            counters.frames_dropped_rate.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        frame.timestamp_ms = start.elapsed().as_millis() as u64;
        if source != (frame.width, frame.height) {
            // A rung change reaching the pixels, or the display itself changing. Each one costs an
            // IDR, which the keyframe line below shows.
            tracing::debug!(
                from = %format!("{}x{}", source.0, source.1),
                to = %format!("{}x{}", frame.width, frame.height),
                rung = %format!("{}p@{}", target.max_h(), rung_fps),
                "encoding at a new size"
            );
            source = (frame.width, frame.height);
            counters.encoded_w.store(frame.width, Ordering::Relaxed);
            counters.encoded_h.store(frame.height, Ordering::Relaxed);
        }
        let encode_started = Instant::now();

        // Marked, so the heartbeat can see an encode that never returns (`pipeline::Busy`), and
        // caught, so a panic inside the encoder condemns the encoder rather than the session.
        sup.health()
            .enter(crate::pipeline::Busy::Encode, encode_started);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| enc.encode(&frame)));
        sup.health().leave();
        let spent = encode_started.elapsed();
        counters.encode_attempts.fetch_add(1, Ordering::Relaxed);
        let spent_us = spent.as_micros() as u64;
        counters
            .encode_us_total
            .fetch_add(spent_us, Ordering::Relaxed);
        SessionCounters::bump_max(&counters.encode_us_max, spent_us);
        // The summary's `encode_ms_p95`: one bucket's add (`crate::summary::EncodeHistogram`).
        counters.encode_hist.record(spent_us);
        let (result, panicked) = match result {
            Ok(result) => (result, false),
            Err(panic) => (
                Err(anyhow::anyhow!(
                    "encoder panicked: {}",
                    panic_message(panic.as_ref())
                )),
                true,
            ),
        };
        // A keyframe asked for and none made: the request is spent (the encoder's flag is cleared
        // by the encode) and no window opens, so the viewer's next request is honoured and the
        // agent's own requests come again (the transport's after `KEYFRAME_RETRY`). Rare; said.
        if forced_keyframe && !matches!(result, Ok(Some(ref ef)) if ef.is_keyframe) {
            tracing::debug!(
                outcome = match &result {
                    Ok(Some(_)) => "delta",
                    Ok(None) => "skipped",
                    Err(_) => "error",
                },
                own = own_keyframe,
                viewer = viewer_keyframe,
                "a keyframe was asked of the encoder and it made none for this frame"
            );
        }

        match result {
            Ok(Some(ef)) => {
                sup.encode_ok(Instant::now(), true);
                count += 1;
                counters.frames_encoded.fetch_add(1, Ordering::Relaxed);
                counters
                    .bytes_sent
                    .fetch_add(ef.data.len() as u64, Ordering::Relaxed);
                // Charge it to the bucket. The keyframe flag is inverted because the C++ argument
                // is `delta_frame`, and it is what decides whether the cost is spread — which is
                // the whole reason this is not the crude "exclude keyframes" the ladder does today.
                dropper.fill(ef.data.len(), !ef.is_keyframe);
                // The quantiser this frame was coded at, read here and not on the controller's
                // clock. The encoder reports the *last* frame it encoded, so polling it at 200 ms
                // while the pipeline runs at 2 fps reads one frame a dozen times and lets it decide
                // the rung on its own.
                //
                // Keyframes excluded. An IDR is quantised on its own scale — OpenH264 clips it at
                // 40 — so one would otherwise dominate a two-second window. The periodic ones are
                // rare (3000 frames), but the frame that follows a resolution change is always
                // an IDR, so the ladder's first sample after every step would otherwise be the
                // least representative frame in the session.
                let frame_qp = enc.last_frame_qp();
                // One line per encoded frame, when asked for.
                //
                // A per-second line averages away exactly what the rate surface needs to see: the
                // gap since the previous encoded frame, and this frame's own cost at this frame's
                // own quantiser. Averaged over a second those two are a single blurred point, and
                // a blurred point is what made the last fit unidentifiable.
                //
                // Off unless `AFKLINK_CALIBRATE=1`: at 30 fps this is 30 lines a second, which is
                // a diagnostic instrument and not something to leave running on a user's machine.
                if calibrating {
                    let gap_ms = last_encoded
                        .replace(Instant::now())
                        .map_or(0, |t| t.elapsed().as_millis() as u32);
                    // not-a-key-name: whether a frame is a keyframe
                    tracing::info!(
                        w = frame.width,
                        h = frame.height,
                        px = frame.width * frame.height,
                        bytes = ef.data.len(),
                        qp = frame_qp.map_or_else(|| "-".to_string(), |q| q.to_string()),
                        key = ef.is_keyframe,
                        gap_ms = gap_ms,
                        encode_us = spent_us,
                        budget_kbps = target.target_kbps().unwrap_or(0),
                        fps_cfg = target.fps(),
                        estimate_kbps = counters.estimate_kbps.load(Ordering::Relaxed),
                        in_flight = target.outstanding_bytes(),
                        rtt_ms = match counters.rtt_ms.load(Ordering::Relaxed) {
                            u32::MAX => "-".to_string(),
                            v => v.to_string(),
                        },
                        "frame"
                    );
                }
                if !ef.is_keyframe {
                    if let Some(qp) = frame_qp {
                        counters.qp_sum.fetch_add(u64::from(qp), Ordering::Relaxed);
                        counters.qp_samples.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    counters.last_keyframe_bytes.store(
                        u32::try_from(ef.data.len()).unwrap_or(u32::MAX),
                        Ordering::Relaxed,
                    );
                    counters
                        .keyframe_bytes_total
                        .fetch_add(ef.data.len() as u64, Ordering::Relaxed);
                    // Every keyframe, asked for or not, opens the window in which the viewer's
                    // requests are answered by it: priced as it is handed to the transport, behind
                    // what is already queued there (str0m's queue and the channel to it), and with
                    // the transport's live NACK count as its baseline.
                    let window = kf_window.keyframe_sent(
                        Instant::now(),
                        ef.data.len(),
                        crate::keyframe_window::LinkNow::from_gauges(
                            counters.rtt_ms.load(Ordering::Relaxed),
                            target.drain_kbps(),
                            counters.estimate_kbps.load(Ordering::Relaxed),
                            target
                                .outstanding_bytes()
                                .saturating_add(sink.queued_bytes.load(Ordering::Relaxed)),
                        )
                        .with_nacks(sink.nacks.load(Ordering::Acquire)),
                        forced_keyframe,
                    );
                    // The largest thing this pipeline emits, and a queue spike of its own: every
                    // one with why it happened. `forced` is a request (a viewer's PLI, a recovery,
                    // a breaker resync); otherwise it is a new size, a new encoder, or the GOP.
                    // `window_ms`: how long the viewer's keyframe requests are answered by it.
                    if let Some(held) = keyframe_log.ready(Instant::now()) {
                        tracing::debug!(
                            bytes = ef.data.len(),
                            forced = forced_keyframe,
                            size = %format!("{}x{}", frame.width, frame.height),
                            qp = ?frame_qp,
                            budget_kbps = target.target_kbps().unwrap_or(0),
                            queue_age_ms,
                            keyframes_held_back = held,
                            window_ms = window.len.as_millis() as u64,
                            "keyframe encoded"
                        );
                    }
                }
                if !control.admits_media() {
                    break None;
                }
                let sample = afklink_transport::MediaSample {
                    data: ef.data,
                    is_keyframe: ef.is_keyframe,
                    timestamp_ms: ef.timestamp_ms,
                    // For the transport's `keyframe handed to str0m` line, which is not rate-limited:
                    // the keyframe the viewer actually starts from, with its quantiser.
                    qp: frame_qp,
                };
                // Committed before it is sent, so the frame is inside the latency signal for the
                // whole time it is committed and unsent — including while it sits in the channel,
                // which would otherwise be invisible. The peer loop subtracts it once str0m has
                // it. `blocking_send` can park this thread here, and that wait is exactly the
                // latency this counter exists to make visible.
                let len = u32::try_from(sample.data.len()).unwrap_or(u32::MAX);
                sink.queued_bytes.fetch_add(len, Ordering::Relaxed);
                if sink.tx.blocking_send(sample).is_err() {
                    sink.queued_bytes.fetch_sub(len, Ordering::Relaxed);
                    tracing::debug!("media channel closed: the peer is gone");
                    break None;
                }
            }
            // The encoder skipped this frame to hold the bitrate target. Not an error, but it is
            // frames the viewer does not see, so it is counted rather than ignored.
            Ok(None) => {
                sup.encode_ok(Instant::now(), false);
                counters
                    .frames_skipped_encoder
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                counters.encode_errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("encode error: {e:#}");
                if sup.encode_failed(Instant::now(), panicked, &format!("{e:#}")) {
                    // Condemned: dropped here, and replaced when the supervisor says it is due.
                    encoder = None;
                }
            }
        }
    };
    kf_window.finish();
    tracing::info!(
        gave_up = fatal.unwrap_or("-"),
        restarts = sup.health().restarts(),
        "encode loop finished after {count} frames"
    );
    fatal
}

/// Session totals, shared between the encode thread that fills them and the tasks that read them.
///
/// These never reset: the telemetry report is cumulative for the whole session, so the last one
/// that reaches the server is still a complete summary even if the session then dies — which is the
/// case the reporting exists for.
///
/// Atomics rather than a mutex because the writer touches them once per frame on the hot path
/// and the reader once every fifteen seconds. A read that catches a half-written set is a report
/// off by one frame, which is not worth a lock.
#[derive(Debug, Default)]
pub struct SessionCounters {
    pub frames_captured: AtomicU64,
    pub frames_encoded: AtomicU64,
    pub frames_dropped_stale: AtomicU64,
    // No `frames_dropped_paced` counter of its own: the report's `frames_dropped_paced` is
    // `frames_dropped_rate` below — the frames the rate's bucket held back, which is what the
    // field means.
    pub frames_skipped_encoder: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub encode_errors: AtomicU64,
    /// Total microseconds spent encoding, and the count it divides by. Kept as a sum rather than
    /// a running mean so the division happens once, at report time, in f64.
    /// Calls into the encoder, successful or not — the divisor for the mean above.
    pub encode_attempts: AtomicU64,
    pub encode_us_total: AtomicU64,
    pub encode_us_max: AtomicU64,
    /// Written by the session task when the ladder moves.
    pub quality_changes: AtomicU64,
    pub lowest_height: AtomicU32,
    /// Most recent bandwidth estimate; 0 means none has arrived yet.
    pub estimate_kbps: AtomicU32,
    /// The quantiser, summed over encoded frames, and the count it divides by.
    ///
    /// The quality ladder's primary signal. Accumulated on the encode thread, one frame at a time,
    /// because the encoder reports the *last* frame it encoded — so a controller that polls this on
    /// its own 200 ms clock reads the same frame repeatedly whenever the frame rate is low, and one
    /// unlucky frame gets to decide the rung. A sum and a count let the controller take a true mean
    /// over its window however many frames landed in it.
    ///
    /// Keyframes are excluded by the writer: an IDR is quantised on a different scale (OpenH264
    /// clips it at 40 whatever the budget), so a single one would otherwise skew a two-second
    /// window. Periodic ones are rare — the GOP is 3000 frames — but every rung change still
    /// forces one, which is exactly when the ladder is reading hardest.
    pub qp_sum: AtomicU64,
    pub qp_samples: AtomicU64,
    /// Bytes of the last keyframe this session encoded, for reporting what a rung change costs.
    pub last_keyframe_bytes: AtomicU32,
    /// Every keyframe byte this session has produced.
    ///
    /// Subtracted from the produced rate before the ladder sees it. An IDR is 40 to 80 kB and lands
    /// inside a single 200 ms window, so instantaneously it reads as several times the link's
    /// capacity — and a ladder told "you are producing four times what the link drains" moves
    /// pixels. Replayed against a recorded session, one keyframe at second two was enough to drop
    /// a rung on an otherwise idle desktop.
    ///
    /// A keyframe is a one-off cost, not a sustained rate. Spread over the 3000-frame GOP it
    /// amortises to a few kbps, which is nothing; it is only the window it lands in that lies.
    pub keyframe_bytes_total: AtomicU64,
    /// The size the encoder is actually being handed, which is not the panel's size.
    pub encoded_w: AtomicU32,
    pub encoded_h: AtomicU32,
    /// What the receiver reports: the path, and what it is losing. See `PeerEvent::LinkStats`.
    ///
    /// `u32::MAX` in `rtt_ms` means "no receiver report yet", which is a different statement from
    /// "zero milliseconds" and must not be rounded into one.
    pub rtt_ms: AtomicU32,
    /// Loss fraction in hundredths of a percent, so it fits an integer without losing the range
    /// that matters (0.01% to 100%).
    ///
    /// `u32::MAX` when the last stats interval carried no receiver report (str0m's `None`). That is
    /// the loss/round-trip brake's freshness signal and must not be rounded into "no loss".
    pub loss_bp: AtomicU32,
    pub plis: AtomicU64,
    pub nacks: AtomicU64,
    /// How many `LinkStats` events have arrived — one per str0m stats interval. The control task
    /// hands the controller a `ReceiverReport` on the tick this moves, and only then.
    pub link_reports: AtomicU64,
    /// What the *viewer* reports about its own latency. See `InputMessage::ViewerLatency`.
    ///
    /// Tenths of a millisecond, because the whole latency budget is a thousand milliseconds and
    /// the terms worth distinguishing are tens — an integer in tenths holds that with room to
    /// spare and needs no float in an atomic.
    ///
    /// Zero means "the viewer has not reported yet". Unlike `rtt_ms` this does not need a distinct
    /// sentinel: a jitter buffer of exactly zero is not physically reachable, and the viewer sends
    /// nothing at all rather than sending a zero (a still screen emits no frames, so there is no
    /// denominator).
    ///
    /// This is the largest term in the end-to-end sum and the only one the agent cannot measure
    /// for itself. Recorded and logged; nothing acts on it yet, deliberately — the point of
    /// measuring first is to find out what it costs before deciding whether to trade picture
    /// stability for it.
    pub jbuf_tenth_ms: AtomicU32,
    pub jitter_tenth_ms: AtomicU32,
    /// Frames the viewer's decoder has emitted. The denominator behind `jbuf_tenth_ms`, kept so a
    /// reading taken over two frames can be told from one taken over sixty.
    pub jbuf_frames: AtomicU64,
    /// Frames withheld from the encoder by the bit bucket, to hold the bitrate the ladder set.
    ///
    /// Distinct from `frames_dropped_stale` (the encoder was behind and the frame was superseded)
    /// and from the transport's `discarded` (the send queue was past its limit). This one is the
    /// encoder's missing brake doing its job, and it has to be separable from the other two because
    /// they want opposite fixes: this rising while the queue is empty is the system working.
    ///
    /// On the wire it is the report's `frames_dropped_paced` ("deliberately not encoded, because
    /// congestion control asked for a lower rate"), the name the server's column has had all along.
    pub frames_dropped_rate: AtomicU64,
    /// Frames withheld before the encoder because the send queue was already too old.
    ///
    /// The fourth and last way a frame can fail to become pixels, and it has to be separable from
    /// the other three because it is the only one that says *latency*. `frames_dropped_stale` is
    /// the encoder falling behind capture, `frames_dropped_rate` is the bit bucket holding the
    /// bitrate, the transport's `discarded` is the send queue past its hard limit — and this one is
    /// the send queue past the product's latency budget, caught before the bytes were made rather
    /// than after. See `skip_for_queue`.
    pub frames_skipped_queue: AtomicU64,
    /// Frames withheld before the encoder because drain mode was in force: the network path was
    /// holding a backlog of frames already sent. Separate from `frames_skipped_queue` because that
    /// is our own queue and this is the path's. See `crate::quality::QualityController::draining`.
    pub frames_skipped_drain: AtomicU64,
    /// The viewer's keyframe requests (its PLIs and FIRs) the encode thread did not honour because
    /// a keyframe already on its way answers them: an IDR each that was not sent. The `pipeline`
    /// line's `kf_suppressed`. See `crate::keyframe_window`.
    pub keyframe_requests_suppressed: AtomicU64,
    /// The viewer's latest report on its decoder and screen (`InputMessage::ViewerVideo`), for the
    /// pipeline line's `v_*` fields. See `crate::viewer_report`.
    pub viewer: crate::viewer_report::ViewerGauges,
    /// The same report's count of frames received (`framesReceived`) and the viewer's own clock as
    /// it made it (`currentTime` in ms plus one; 0 when it carried none), and when it reached the
    /// event task (µs since the session's delivery epoch): drain mode's current evidence, handed to
    /// the controller by the control task (`QualityController::note_viewer_frames`). The report
    /// count moves last, with release ordering, so a reader that sees it move sees the rest.
    pub viewer_frames_received: AtomicU64,
    pub viewer_clock_ms: AtomicU64,
    pub viewer_report_at_us: AtomicU64,
    pub viewer_delivery_reports: AtomicU64,
    /// The time inside `encode()`, by bucket, for the summary's `encode_ms_p95`
    /// (`crate::summary`): one add per encode, beside `encode_us_total`.
    pub encode_hist: crate::summary::EncodeHistogram,
    /// The viewer's input by kind, for the summary's `input` (`crate::summary`): one add per
    /// injected message, beside the `input` line's tally.
    pub input: crate::summary::InputTotals,
}

impl SessionCounters {
    fn bump_max(slot: &AtomicU64, value: u64) {
        // Compare-and-swap rather than load-then-store: two threads racing on a plain store can
        // lose the larger value, and the maximum is the one field where losing a sample loses
        // the whole point of the field.
        let mut current = slot.load(Ordering::Relaxed);
        while value > current {
            match slot.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    /// Snapshot for the wire.
    pub fn snapshot(
        &self,
        duration: Duration,
        source: (u32, u32),
    ) -> afklink_transport::AgentSessionStats {
        let encoded = self.frames_encoded.load(Ordering::Relaxed);
        let us_total = self.encode_us_total.load(Ordering::Relaxed);
        let attempts = self.encode_attempts.load(Ordering::Relaxed);
        let estimate = self.estimate_kbps.load(Ordering::Relaxed);
        afklink_transport::AgentSessionStats {
            duration_ms: duration.as_millis() as u64,
            source_w: source.0,
            source_h: source.1,
            frames_captured: self.frames_captured.load(Ordering::Relaxed),
            frames_encoded: encoded,
            frames_dropped_stale: self.frames_dropped_stale.load(Ordering::Relaxed),
            // The rate's bucket (`frames_dropped_rate`): the live counter behind the old name.
            frames_dropped_paced: self.frames_dropped_rate.load(Ordering::Relaxed),
            frames_skipped_encoder: self.frames_skipped_encoder.load(Ordering::Relaxed),
            // Attempts, not successes: a declined frame still costs the colour conversion, and
            // charging that to the frames that worked inflates the figure by roughly a quarter.
            encode_ms_avg: if attempts > 0 {
                us_total as f64 / attempts as f64 / 1000.0
            } else {
                0.0
            },
            encode_ms_max: self.encode_us_max.load(Ordering::Relaxed) as f64 / 1000.0,
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            lowest_height: self.lowest_height.load(Ordering::Relaxed),
            quality_changes: self.quality_changes.load(Ordering::Relaxed),
            // Zero means "nothing reported yet", which is a different statement from "the link
            // is estimated at zero" and has to survive as null rather than as a number.
            estimate_kbps: (estimate > 0).then_some(estimate),
            encode_errors: self.encode_errors.load(Ordering::Relaxed),
            // The session's hold cell has these, not the counters: `StatsSource::snapshot` sets
            // them. Zero here for a caller without one (a session with no hold cell holds nothing).
            bg_hold_ms: Some(0),
            bg_holds: Some(0),
            // The session's summary (`crate::summary`) is set by `StatsSource::snapshot`, which has
            // it; none here.
            summary: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A text past [`TEXT_MAX_CHARS`] is dropped whole — counted by characters, not bytes — and
    /// nothing a viewer of ours sends is past either limit: its longest text (64 UTF-16 units), a
    /// `vv` report with every field at its widest, a clipboard chunk at its worst escaping.
    #[test]
    fn the_input_limits_drop_nothing_a_viewer_sends() {
        assert!(
            !text_over_limit(&"я".repeat(TEXT_MAX_CHARS)),
            "two bytes each, still in"
        );
        assert!(text_over_limit(&"x".repeat(TEXT_MAX_CHARS + 1)));
        assert!(
            !text_over_limit(&"😀".repeat(32)),
            "a viewer's longest text"
        );
        assert!(!text_over_limit(""));

        let wide = || Some("w".repeat(64));
        let report = InputMessage::ViewerVideo(Box::new(afklink_protocol::ViewerVideo {
            frames_received: Some(u64::MAX),
            frames_decoded: Some(u64::MAX),
            frames_dropped: Some(u64::MAX),
            key_frames_decoded: Some(u64::MAX),
            freeze_count: Some(u64::MAX),
            freeze_ms: Some(u64::MAX),
            pli_count: Some(u64::MAX),
            width: Some(u32::MAX),
            height: Some(u32::MAX),
            fps: Some(f64::MAX),
            decoder: wide(),
            jbuf_target_ms: Some(f64::MAX),
            jbuf_min_ms: Some(f64::MAX),
            rvfc_frames: Some(u64::MAX),
            vpq_frames: Some(u64::MAX),
            vpq_dropped: Some(u64::MAX),
            current_ms: Some(u64::MAX),
            paused: Some(false),
            ready_state: Some(4),
            visibility: wide(),
            platform: wide(),
            presented_by: wide(),
            watchdog: wide(),
            kf_asked: Some(u64::MAX),
            reattaches: Some(u64::MAX),
            ev_pause: Some(u64::MAX),
            ev_waiting: Some(u64::MAX),
            ev_stalled: Some(u64::MAX),
            engine: wide(),
            replacements: Some(u64::MAX),
            recoveries: Some(u64::MAX),
            recovered_at: wide(),
            recovered_ms: Some(u64::MAX),
            auto_reconnects: Some(u64::MAX),
        }));
        let text = InputMessage::Text {
            text: "😀".repeat(32),
            game: Some(true),
        };
        let chunk = InputMessage::ClipboardSet(afklink_protocol::clipboard::ClipboardChunk {
            id: u32::MAX,
            i: 127,
            n: 128,
            text: afklink_protocol::clipboard::chunks(1, &"\u{1}".repeat(4000))
                .expect("fits")
                .remove(0)
                .text,
        });
        for m in [report, text, chunk] {
            let wire = serde_json::to_string(&m).expect("serializes");
            assert!(
                wire.len() <= afklink_protocol::INPUT_MAX_BYTES,
                "{} bytes: {}",
                wire.len(),
                &wire[..wire.len().min(40)]
            );
        }

        // Counted in the input line, and gone with it.
        let mut tally = InputTally::default();
        tally.oversized("s", afklink_protocol::INPUT_MAX_BYTES + 1);
        tally.oversized("s", 70_000);
        tally.text_too_long("s", 4000);
        tally.held_back();
        assert_eq!(
            (tally.oversized, tally.text_too_long, tally.held_back),
            (2, 1, 1)
        );
        assert!(tally.first_oversized_logged && tally.first_text_too_long_logged);
        tally.flush("s");
        assert_eq!(
            (tally.oversized, tally.text_too_long, tally.held_back),
            (0, 0, 0)
        );
    }

    /// The `input` line tells absolute moves from relative ones — the one way to see from the
    /// agent's log which touch mode the viewer really used (a trackpad sends only `r` to move).
    #[test]
    fn the_input_tally_counts_each_kind_and_resets_with_the_line() {
        let mut tally = InputTally::default();
        for m in [
            InputMessage::Move { x: 0.5, y: 0.5 },
            InputMessage::Rel {
                dx: 0.01,
                dy: 0.0,
                s: None,
                x: None,
                y: None,
            },
            InputMessage::Rel {
                dx: 0.02,
                dy: 0.0,
                s: Some(1),
                x: Some(0.5),
                y: Some(0.25),
            },
            InputMessage::Down { b: 0 },
            InputMessage::Up { b: 0 },
            InputMessage::Wheel {
                dx: 0.0,
                dy: 3.0,
                mode: Some(1),
                game: None,
            },
            InputMessage::Text {
                text: "x".into(),
                game: None,
            },
            InputMessage::ReleaseAll,
        ] {
            tally.note_injected(&m);
        }
        assert_eq!(tally.injected, 8);
        assert_eq!(
            tally.kinds,
            InputKinds {
                abs: 1,
                rel: 2,
                buttons: 2,
                wheel: 1,
                keys: 0,
                text: 1,
                other: 1,
            }
        );
        // The event loop opens the window (`flush_if_due`); the line then empties every count.
        tally.touch();
        tally.flush("s");
        assert_eq!(tally.injected, 0);
        assert_eq!(tally.kinds, InputKinds::default());
    }

    /// The pipeline line's round trip is the current report's or nothing: str0m repeats the last
    /// report's round trip on an interval without one, which through a ten-second blackout on the
    /// bench would print `rtt_ms="135"` for a dead link.
    #[test]
    fn the_pipeline_line_does_not_print_a_repeated_round_trip_as_current() {
        // A fresh report: loss and round trip both present.
        assert_eq!(rtt_field(135, 0), "135");
        assert_eq!(rtt_field(143, 17), "143");
        // An interval without a report: str0m's `None` loss beside the repeated round trip.
        assert_eq!(rtt_field(135, u32::MAX), "-");
        // Nothing reported yet, or a report without a round trip.
        assert_eq!(rtt_field(u32::MAX, u32::MAX), "-");
        assert_eq!(rtt_field(u32::MAX, 0), "-");
        // And how old the last real one is.
        assert_eq!(report_age_field(None), "-");
        assert_eq!(
            report_age_field(Some(Duration::from_millis(10_200))),
            "10200"
        );
    }

    struct NoopInjector;
    impl InputInjector for NoopInjector {
        fn inject(&self, _event: &InputMessage) -> anyhow::Result<()> {
            Ok(())
        }
        fn release_all(&self) {}
    }

    /// An agent with no platform behind it, pointed at `server_url` when given.
    fn test_agent(server_url: Option<String>) -> (Agent, AgentControl) {
        test_agent_with(|config| {
            if let Some(url) = server_url {
                config.server_url = url;
            }
        })
    }

    /// An agent with no platform behind it, its config.json as `edit` leaves it (saved, so a reload
    /// reads the same).
    fn test_agent_with(edit: impl FnOnce(&mut Config)) -> (Agent, AgentControl) {
        // `Config::defaults` / `Identity::generate` are private to their
        // modules, so go through the public `*_at` constructors in a scratch
        // dir — no production visibility changes for the sake of tests.
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let base =
            std::env::temp_dir().join(format!("afklink-core-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&base).expect("test dir");
        let mut config = Config::load_or_create_at(base.join("config.json")).expect("test config");
        edit(&mut config);
        config.save().expect("test config saved");
        let identity =
            Identity::load_or_create_at(base.join("identity.json")).expect("test identity");
        let backends = Backends {
            make_capturer: Box::new(|| Err(anyhow::anyhow!("no capturer in test"))),
            make_game_capturer: Box::new(|_| Err(anyhow::anyhow!("no game capturer in test"))),
            make_encoder: Box::new(|| Err(anyhow::anyhow!("no encoder in test"))),
            injector: Arc::new(NoopInjector),
        };
        let (agent, control) = Agent::new(config, Arc::new(identity), backends);
        // The reconnect tests time the backoff's own waits (the jitter is `reconnect`'s tests').
        (agent.with_jitter(reconnect::Jitter::off()), control)
    }

    fn harness() -> (
        Agent,
        mpsc::UnboundedSender<AgentToServer>,
        mpsc::UnboundedReceiver<AgentToServer>,
    ) {
        let (agent, _control) = test_agent(None);
        let (tx, rx) = mpsc::unbounded_channel();
        (agent, tx, rx)
    }

    fn session_request(session_id: &str, telegram_user_id: i64) -> ServerToAgent {
        ServerToAgent::SessionRequest {
            session_id: session_id.into(),
            telegram_user_id,
            username: None,
            turn: afklink_protocol::TurnCreds {
                urls: vec![],
                username: String::new(),
                credential: String::new(),
            },
            quality_profile: None,
        }
    }

    /// The owner's answer to a pairing request, as it went out.
    async fn answer_pair(
        agent: &mut Agent,
        tx: &mpsc::UnboundedSender<AgentToServer>,
        rx: &mut mpsc::UnboundedReceiver<AgentToServer>,
        accept: bool,
    ) -> AgentToServer {
        answer_pair_as(agent, tx, rx, accept, None).await
    }

    /// The owner's answer to a pairing request with the role chosen at «Кто это?», as it went out.
    async fn answer_pair_as(
        agent: &mut Agent,
        tx: &mpsc::UnboundedSender<AgentToServer>,
        rx: &mut mpsc::UnboundedReceiver<AgentToServer>,
        accept: bool,
        role: Option<afklink_protocol::BindingRole>,
    ) -> AgentToServer {
        agent
            .handle_command(
                AgentCommand::RespondToPair {
                    request_id: "7c4b1e90-2a3d-4f51-9b8e-6d5c4a3b2f10".into(),
                    accept,
                    role,
                },
                tx,
            )
            .await;
        rx.try_recv().expect("the answer went to the backend")
    }

    fn pair_request(has_owner: Option<bool>) -> ServerToAgent {
        ServerToAgent::PairRequest {
            request_id: "7c4b1e90-2a3d-4f51-9b8e-6d5c4a3b2f10".into(),
            telegram_user_id: 7,
            username: Some("ann".into()),
            first_name: Some("Аня".into()),
            expires_at: 1,
            has_owner,
        }
    }

    fn role_binding(id: i64, role: Option<afklink_protocol::BindingRole>) -> BindingInfo {
        BindingInfo {
            telegram_user_id: id,
            username: None,
            first_name: Some(format!("n{id}")),
            role,
        }
    }

    fn roles(agent: &Agent) -> Vec<(i64, Option<afklink_protocol::BindingRole>)> {
        lock(&agent.state)
            .bindings
            .iter()
            .map(|b| (b.telegram_user_id, b.role))
            .collect()
    }

    /// «Кто это?» only on a PC with no owner; the answer rides the approval as `role`, every other
    /// approval says `guest`, and a refusal says nothing.
    #[tokio::test]
    async fn an_approval_carries_the_role_chosen_or_guest() {
        use afklink_protocol::BindingRole;
        let (mut agent, tx, mut rx) = harness();

        // A PC with no owner: the prompt asks, and the answer goes as chosen.
        for chosen in [BindingRole::Owner, BindingRole::Guest] {
            agent
                .handle_server_msg(pair_request(Some(false)), &tx)
                .await;
            let asks = lock(&agent.state)
                .pending_pair
                .as_ref()
                .map(PendingPair::asks_role);
            assert_eq!(asks, Some(true));
            let sent = answer_pair_as(&mut agent, &tx, &mut rx, true, Some(chosen)).await;
            assert!(
                matches!(sent, AgentToServer::PairResponse { role: Some(r), .. } if r == chosen),
                "{sent:?}"
            );
        }

        // A PC with an owner, and a server older than roles: no question, a guest.
        for has_owner in [Some(true), None] {
            agent.handle_server_msg(pair_request(has_owner), &tx).await;
            let asks = lock(&agent.state)
                .pending_pair
                .as_ref()
                .map(PendingPair::asks_role);
            assert_eq!(asks, Some(false), "{has_owner:?}");
            let sent = answer_pair(&mut agent, &tx, &mut rx, true).await;
            assert!(
                matches!(
                    sent,
                    AgentToServer::PairResponse {
                        role: Some(BindingRole::Guest),
                        ..
                    }
                ),
                "{has_owner:?}: {sent:?}"
            );
        }

        // A refusal gives no role, asked or not.
        agent
            .handle_server_msg(pair_request(Some(false)), &tx)
            .await;
        let sent = answer_pair_as(&mut agent, &tx, &mut rx, false, None).await;
        assert!(
            matches!(
                sent,
                AgentToServer::PairResponse {
                    accept: false,
                    role: None,
                    ..
                }
            ),
            "{sent:?}"
        );
    }

    /// The roles follow the server: `binding_added` with its role, `owner_changed` to an account
    /// (everyone else a guest) and to nobody.
    #[tokio::test]
    async fn the_roles_follow_binding_added_and_owner_changed() {
        use afklink_protocol::BindingRole;
        let (mut agent, tx, _rx) = harness();
        let added = |uid: i64, role: Option<BindingRole>| ServerToAgent::BindingAdded {
            telegram_user_id: uid,
            username: None,
            first_name: Some(format!("n{uid}")),
            role,
            via: None,
        };
        agent
            .handle_server_msg(added(1, Some(BindingRole::Owner)), &tx)
            .await;
        agent
            .handle_server_msg(added(2, Some(BindingRole::Guest)), &tx)
            .await;
        assert_eq!(
            roles(&agent),
            [(1, Some(BindingRole::Owner)), (2, Some(BindingRole::Guest))]
        );

        agent
            .handle_server_msg(
                ServerToAgent::OwnerChanged {
                    telegram_user_id: Some(2),
                },
                &tx,
            )
            .await;
        assert_eq!(
            roles(&agent),
            [(1, Some(BindingRole::Guest)), (2, Some(BindingRole::Owner))]
        );

        // The owner's binding goes, then nobody is the owner.
        agent
            .handle_server_msg(
                ServerToAgent::BindingRemoved {
                    telegram_user_id: 2,
                },
                &tx,
            )
            .await;
        agent
            .handle_server_msg(
                ServerToAgent::OwnerChanged {
                    telegram_user_id: None,
                },
                &tx,
            )
            .await;
        assert_eq!(roles(&agent), [(1, Some(BindingRole::Guest))]);

        // A re-pair as the owner of a PC with none: one owner, never two.
        agent
            .handle_server_msg(added(3, Some(BindingRole::Owner)), &tx)
            .await;
        agent
            .handle_server_msg(added(1, Some(BindingRole::Owner)), &tx)
            .await;
        let owners = roles(&agent)
            .into_iter()
            .filter(|(_, r)| *r == Some(BindingRole::Owner))
            .count();
        assert_eq!(owners, 1);
    }

    /// «Отвязать» on a guest unbinds at once; on the owner it asks the owner (`unbind_owner`); on a
    /// server older than roles it unbinds as it always did. «Сделать владельцем» asks; a second
    /// request while one is in flight is not sent; the cancel names the request the server opened.
    #[tokio::test]
    async fn unbind_and_make_owner_go_as_the_roles_say() {
        use afklink_protocol::{BindingRole, OwnerRequestKind, OwnerRequestState};
        let (mut agent, tx, mut rx) = harness();
        lock(&agent.state).bindings = vec![
            role_binding(1, Some(BindingRole::Owner)),
            role_binding(2, Some(BindingRole::Guest)),
            role_binding(3, None),
        ];

        agent.handle_command(AgentCommand::Unbind(2), &tx).await;
        assert_eq!(
            rx.try_recv().ok(),
            Some(AgentToServer::Unbind {
                telegram_user_id: 2
            })
        );
        agent.handle_command(AgentCommand::Unbind(3), &tx).await;
        assert_eq!(
            rx.try_recv().ok(),
            Some(AgentToServer::Unbind {
                telegram_user_id: 3
            })
        );

        agent.handle_command(AgentCommand::Unbind(1), &tx).await;
        assert_eq!(
            rx.try_recv().ok(),
            Some(AgentToServer::OwnerRequest {
                kind: OwnerRequestKind::UnbindOwner,
                telegram_user_id: 1
            })
        );
        assert!(lock(&agent.state).owner_requests.busy());

        // One in flight: the next is not sent, and its row says so.
        agent.handle_command(AgentCommand::MakeOwner(2), &tx).await;
        assert!(
            rx.try_recv().is_err(),
            "nothing sent while one is in flight"
        );
        assert_eq!(
            lock(&agent.state)
                .owner_requests
                .ended_for(2)
                .map(|e| e.outcome),
            Some(crate::owner_request::Outcome::Busy)
        );

        // The server opens it; the cancel names it; the server's `cancelled` ends it.
        let id = "e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b";
        agent
            .handle_server_msg(
                ServerToAgent::OwnerRequestState {
                    request_id: Some(id.into()),
                    kind: afklink_protocol::OwnerStateKind::UnbindOwner,
                    telegram_user_id: 1,
                    state: OwnerRequestState::Pending,
                    expires_at: Some(crate::journal::now_ms() + 600_000),
                    reason: None,
                    username: None,
                    first_name: None,
                },
                &tx,
            )
            .await;
        agent
            .handle_command(AgentCommand::CancelOwnerRequest, &tx)
            .await;
        assert_eq!(
            rx.try_recv().ok(),
            Some(AgentToServer::OwnerRequestCancel {
                request_id: id.into()
            })
        );
        agent
            .handle_server_msg(
                ServerToAgent::OwnerRequestState {
                    request_id: Some(id.into()),
                    kind: afklink_protocol::OwnerStateKind::UnbindOwner,
                    telegram_user_id: 1,
                    state: OwnerRequestState::Cancelled,
                    expires_at: None,
                    reason: Some(afklink_protocol::OwnerRequestReason::ByPc),
                    username: None,
                    first_name: None,
                },
                &tx,
            )
            .await;
        assert!(!lock(&agent.state).owner_requests.busy());
        assert_eq!(
            roles(&agent)[0],
            (1, Some(BindingRole::Owner)),
            "nothing changed"
        );

        // Now «Сделать владельцем» goes.
        agent.handle_command(AgentCommand::MakeOwner(2), &tx).await;
        assert_eq!(
            rx.try_recv().ok(),
            Some(AgentToServer::OwnerRequest {
                kind: OwnerRequestKind::MakeOwner,
                telegram_user_id: 2
            })
        );
    }

    /// The name the owner set on the PC goes with the approval, so the Mini App lists the new
    /// device under it rather than the backend's "My PC".
    #[tokio::test]
    async fn an_approval_carries_the_name_set_on_the_pc_and_a_refusal_none() {
        let (mut agent, tx, mut rx) = harness();
        agent
            .handle_command(AgentCommand::SetName("  Рабочий ПК ".into()), &tx)
            .await;
        assert_eq!(
            rx.try_recv().expect("the rename went to the backend"),
            AgentToServer::DeviceName {
                name: "Рабочий ПК".into()
            }
        );

        match answer_pair(&mut agent, &tx, &mut rx, true).await {
            AgentToServer::PairResponse { accept, name, .. } => {
                assert!(accept);
                assert_eq!(name.as_deref(), Some("Рабочий ПК"));
            }
            other => panic!("expected pair_response, got {}", other.kind()),
        }
        match answer_pair(&mut agent, &tx, &mut rx, false).await {
            AgentToServer::PairResponse { accept, name, .. } => {
                assert!(!accept);
                assert_eq!(name, None, "a refusal names nothing");
            }
            other => panic!("expected pair_response, got {}", other.kind()),
        }

        // A stored name outside the rule (a hand edit while running) is not sent: the backend
        // would refuse it; the pairing still goes ahead.
        lock(&agent.config).name = "Office\tPC".into();
        match answer_pair(&mut agent, &tx, &mut rx, true).await {
            AgentToServer::PairResponse { accept, name, .. } => {
                assert!(accept);
                assert_eq!(name, None);
            }
            other => panic!("expected pair_response, got {}", other.kind()),
        }
    }

    /// The journal hears of access given and taken away, and of attempts refused on pause — once per
    /// person per pause, however often the viewer retries — and the first pairing offers the
    /// autostart card, the second does not.
    #[tokio::test]
    async fn the_journal_keeps_access_and_attempts_on_pause() {
        use crate::config::AutostartOffer;
        use crate::journal::Kind;

        let (agent, tx, _rx) = harness();
        let journal = Arc::new(crate::journal::Journal::open(
            None,
            crate::journal::now_ms(),
        ));
        let mut agent = agent.with_journal(journal.clone());
        assert!(!lock(&agent.config).autostart);
        let added = |uid: i64, first: &str| ServerToAgent::BindingAdded {
            telegram_user_id: uid,
            username: Some(format!("u{uid}")),
            first_name: Some(first.to_string()),
            role: None,
            via: None,
        };

        agent.handle_server_msg(added(7, "Вера"), &tx).await;
        assert_eq!(
            lock(&agent.config).autostart_offer(),
            AutostartOffer::Pending,
            "the first pairing offers the card"
        );
        lock(&agent.config).settle_autostart_offer("test");
        agent.handle_server_msg(added(8, "Дима"), &tx).await;
        assert_eq!(
            lock(&agent.config).autostart_offer(),
            AutostartOffer::Answered,
            "a later pairing changes nothing"
        );

        agent.handle_command(AgentCommand::KillSwitch, &tx).await;
        agent.handle_server_msg(session_request("a", 7), &tx).await;
        agent.handle_server_msg(session_request("b", 7), &tx).await;
        agent.handle_command(AgentCommand::Resume, &tx).await;
        agent.handle_command(AgentCommand::KillSwitch, &tx).await;
        agent.handle_server_msg(session_request("c", 7), &tx).await;
        agent
            .handle_server_msg(
                ServerToAgent::BindingRemoved {
                    telegram_user_id: 7,
                },
                &tx,
            )
            .await;

        let entries = journal.entries();
        let count = |kind: Kind| entries.iter().filter(|v| v.entry.kind == kind).count();
        assert_eq!(count(Kind::Granted), 2);
        assert_eq!(count(Kind::Paused), 2, "once per person per pause");
        assert_eq!(count(Kind::Revoked), 1);
        assert_eq!(count(Kind::Session), 0, "no video, no session entry");
        let revoked = entries
            .iter()
            .find(|v| v.entry.kind == Kind::Revoked)
            .expect("revoked");
        assert_eq!(revoked.entry.name, "Вера", "the name the binding had");
        let paused = entries
            .iter()
            .find(|v| v.entry.kind == Kind::Paused)
            .expect("paused");
        assert_eq!(paused.entry.name, "Вера", "the binding's first name");
    }

    /// `binding_added` by the owner's invite: «Доступ по приглашению» in the
    /// journal in place of «Доступ выдан», and the new-guest toast's event, named as the pairing
    /// window names a requester — once: a repeat of someone already listed is journaled again, as a
    /// re-pair is, but is no new guest. Without `via`, or with a word this build does not know, all
    /// is as before. No code made the binding, so an open pairing panel keeps its code.
    #[tokio::test]
    async fn a_guest_by_invite_is_journaled_and_announced_once() {
        use crate::journal::Kind;
        use crate::pairing::PairingPanel;
        use afklink_protocol::{BindingRole, BindingVia};

        let (agent, tx, _rx) = harness();
        let (mut agent, journal) = with_journal(agent);
        let mut events = agent.events.subscribe();
        lock(&agent.state).bindings = vec![role_binding(1, Some(BindingRole::Owner))];
        let added = |uid: i64, role: Option<BindingRole>, via: Option<BindingVia>| {
            ServerToAgent::BindingAdded {
                telegram_user_id: uid,
                username: Some(format!("u{uid}")),
                first_name: Some("Друг".into()),
                role,
                via,
            }
        };
        // Someone else's pairing is under way at the PC.
        {
            let mut s = lock(&agent.state);
            s.pairing_panel = PairingPanel::Open;
            s.pairing_code = Some("123456".into());
        }

        agent
            .handle_server_msg(
                added(42, Some(BindingRole::Guest), Some(BindingVia::Invite)),
                &tx,
            )
            .await;
        assert_eq!(
            events.try_recv().ok(),
            Some(AgentEvent::GuestInvited {
                telegram_user_id: 42,
                name: crate::PersonName {
                    text: "Друг (@u42)".into(),
                    source: crate::NameSource::FirstNameAndUsername,
                },
            })
        );
        {
            let s = lock(&agent.state);
            assert_eq!(
                s.pairing_panel,
                PairingPanel::Open,
                "not this binding's panel"
            );
            assert_eq!(
                s.pairing_code.as_deref(),
                Some("123456"),
                "no code was spent"
            );
        }
        assert_eq!(
            roles(&agent),
            [
                (1, Some(BindingRole::Owner)),
                (42, Some(BindingRole::Guest))
            ]
        );

        // The same guest again: journaled, not announced twice.
        agent
            .handle_server_msg(
                added(42, Some(BindingRole::Guest), Some(BindingVia::Invite)),
                &tx,
            )
            .await;
        assert!(events.try_recv().is_err(), "a repeat is no new guest");

        // A word this build does not know reads as no via: «Доступ выдан», no toast — and the
        // panel's code is spent as for any pairing.
        agent
            .handle_server_msg(
                added(
                    44,
                    Some(BindingRole::Guest),
                    Some(BindingVia::Other("gift".into())),
                ),
                &tx,
            )
            .await;
        assert!(events.try_recv().is_err(), "an unknown via is no invite");
        assert_eq!(lock(&agent.state).pairing_panel.kind(), "paired");

        // No via: as before.
        agent
            .handle_server_msg(added(43, Some(BindingRole::Guest), None), &tx)
            .await;
        assert!(
            events.try_recv().is_err(),
            "the PC's own «Разрешить»: no toast"
        );

        // Against the contract, an invite naming an owner: taken as a guest on this PC —
        // nobody here was asked — so journaled by invite and announced as the new guest it is here;
        // the owner listed before stays the owner.
        agent
            .handle_server_msg(
                added(45, Some(BindingRole::Owner), Some(BindingVia::Invite)),
                &tx,
            )
            .await;
        assert!(
            matches!(
                events.try_recv(),
                Ok(AgentEvent::GuestInvited {
                    telegram_user_id: 45,
                    ..
                })
            ),
            "a guest here, and new"
        );
        assert_eq!(
            roles(&agent).last(),
            Some(&(45, Some(BindingRole::Guest))),
            "clamped to guest"
        );
        assert_eq!(roles(&agent)[0], (1, Some(BindingRole::Owner)));

        let entries = journal.entries();
        let count = |user: i64, kind: Kind| {
            entries
                .iter()
                .filter(|v| v.entry.user == user && v.entry.kind == kind)
                .count()
        };
        assert_eq!(
            count(42, Kind::Invited),
            2,
            "each binding_added is journaled"
        );
        assert_eq!(count(42, Kind::Granted), 0);
        assert_eq!(count(43, Kind::Granted), 1);
        assert_eq!(count(44, Kind::Granted), 1);
        assert_eq!(count(44, Kind::Invited), 0);
        assert_eq!(count(45, Kind::Invited), 1);
        assert_eq!(entries.len(), 5);
        let invited = entries
            .iter()
            .find(|v| v.entry.user == 42)
            .expect("journaled");
        assert_eq!(invited.entry.name, "Друг", "the binding's first name");
    }

    /// The toast names the guest «Имя (@username)», and the
    /// toast and the journal show neither bidi controls nor invisible characters; a first name of
    /// them alone falls back as a blank one does.
    #[tokio::test]
    async fn a_guest_by_invite_is_named_cleanly_and_with_the_username() {
        use afklink_protocol::{BindingRole, BindingVia};
        let (agent, tx, _rx) = harness();
        let (mut agent, journal) = with_journal(agent);
        let mut events = agent.events.subscribe();
        let added = |uid: i64, first: &str, username: &str| ServerToAgent::BindingAdded {
            telegram_user_id: uid,
            username: Some(username.into()),
            first_name: Some(first.into()),
            role: Some(BindingRole::Guest),
            via: Some(BindingVia::Invite),
        };
        let toast = |events: &mut broadcast::Receiver<AgentEvent>| match events.try_recv() {
            Ok(AgentEvent::GuestInvited { name, .. }) => name.text,
            other => panic!("expected the new-guest event, got {other:?}"),
        };

        agent
            .handle_server_msg(added(42, "\u{202E}Друг\u{200B}", "u\u{2060}42"), &tx)
            .await;
        assert_eq!(toast(&mut events), "Друг (@u42)");
        assert_eq!(journal.last().expect("journaled").entry.name, "Друг");

        agent
            .handle_server_msg(added(43, "\u{3164}\u{115F}", "friend"), &tx)
            .await;
        assert_eq!(toast(&mut events), "@friend", "a filler is no name");
        assert_eq!(journal.last().expect("journaled").entry.name, "@friend");
    }

    /// A session's guard is built on the role `game_access` decided for it — the same cell, so a
    /// change of the roles mid-session moves the guard too — and a session it never decided is not
    /// the owner's.
    #[test]
    fn the_session_guard_follows_the_role_game_access_decided() {
        use crate::own_windows::{tests::Desk, Admit};
        use afklink_protocol::BindingRole;
        let access = crate::game_access::GameAccess::new(Default::default());
        let list = [
            role_binding(1, Some(BindingRole::Owner)),
            role_binding(2, Some(BindingRole::Guest)),
        ];
        access.set_roles(&list, "agent_ready");
        access.open("s-guest", 2, &list);
        access.open("s-owner", 1, &list);
        let me = std::process::id();
        let desk = Desk::default();
        desk.place(Some(me), Some(me));
        let key = InputMessage::Key {
            d: 1,
            code: "KeyA".into(),
            key: None,
            mods: None,
            src: None,
        };
        let now = Instant::now();
        let guest = own_window_guard(&access, "s-guest");
        let owner = own_window_guard(&access, "s-owner");
        assert_eq!(
            guest.admit(&key, &desk, now),
            Admit::HoldBack { release: true }
        );
        assert_eq!(owner.admit(&key, &desk, now), Admit::Pass);
        // The guest is made the owner: the guard follows at the next event.
        access.set_roles(
            &[
                role_binding(1, Some(BindingRole::Guest)),
                role_binding(2, Some(BindingRole::Owner)),
            ],
            "owner_changed",
        );
        assert_eq!(guest.admit(&key, &desk, now), Admit::Pass);
        assert_eq!(
            owner.admit(&key, &desk, now),
            Admit::HoldBack { release: true }
        );
        // No decision for the session: the safe side.
        let unknown = own_window_guard(&access, "s-none");
        assert_eq!(
            unknown.admit(&key, &desk, now),
            Admit::HoldBack { release: true }
        );
    }

    /// The own-window guard through the event task's last step: a held-back event is counted and
    /// not injected, the stretch's start releases what the session held, and an event once nothing
    /// of ours is in the way is injected and counted as ever.
    #[test]
    fn a_held_back_event_goes_through_the_event_tasks_last_step() {
        use crate::own_windows::tests::Desk;
        use afklink_protocol::BindingRole;
        let access = crate::game_access::GameAccess::new(Default::default());
        let list = [role_binding(2, Some(BindingRole::Guest))];
        access.set_roles(&list, "agent_ready");
        access.open("s", 2, &list);
        let desk = Arc::new(Desk::default());
        let input =
            InputSession::new(desk.clone()).with_own_window_guard(own_window_guard(&access, "s"));
        let (mut tally, counters) = (InputTally::default(), SessionCounters::default());
        let rel_ack = crate::cursor_report::RelAck::new();
        let me = std::process::id();
        let key = |d: u8| InputMessage::Key {
            d,
            code: "KeyW".into(),
            key: None,
            mods: None,
            src: None,
        };

        desk.place(Some(7), Some(7));
        assert_eq!(
            deliver_input(&input, &key(1), &mut tally, &counters, &rel_ack, "s"),
            Delivered::Injected
        );
        assert_eq!((tally.injected, tally.held_back), (1, 0));

        desk.place(Some(me), Some(me));
        for e in [key(1), InputMessage::Down { b: 0 }] {
            assert_eq!(
                deliver_input(&input, &e, &mut tally, &counters, &rel_ack, "s"),
                Delivered::HeldBack,
                "{e:?}"
            );
        }
        assert_eq!((tally.injected, tally.held_back), (1, 2));
        let injected = desk.injected.lock().expect("injected").clone();
        assert_eq!(
            injected.len(),
            2,
            "the first key and its release: {injected:?}"
        );
        assert!(injected[1].contains("d: 0"), "{injected:?}");

        // A move always goes.
        assert_eq!(
            deliver_input(
                &input,
                &InputMessage::Move { x: 0.5, y: 0.5 },
                &mut tally,
                &counters,
                &rel_ack,
                "s"
            ),
            Delivered::Injected
        );
        // The session's gate closed: the task ends.
        input.close();
        desk.place(Some(7), Some(7));
        assert_eq!(
            deliver_input(&input, &key(1), &mut tally, &counters, &rel_ack, "s"),
            Delivered::SessionEnded
        );
    }

    /// Who is gone and who is new between two lists, by id — a rename or a new role is neither.
    #[test]
    fn binding_changes_are_by_id() {
        let b = |id: i64, first: &str| BindingInfo {
            telegram_user_id: id,
            username: None,
            first_name: Some(first.into()),
            role: None,
        };
        let before = [b(1, "a"), b(2, "b"), b(3, "c")];
        let after = [b(3, "c renamed"), b(1, "a"), b(4, "d"), b(5, "e")];
        let changes = binding_changes(&before, &after);
        assert_eq!(changes.gone, [b(2, "b")]);
        assert_eq!(changes.added, [b(4, "d"), b(5, "e")]);
        assert_eq!(binding_changes(&before, &before), BindingChanges::default());
        assert_eq!(binding_changes(&[], &before).added.len(), 3);
        assert_eq!(binding_changes(&before, &[]).gone.len(), 3);
    }

    /// An approval on this PC is remembered until its `binding_added` comes, so a later list
    /// that has it is not taken for access given elsewhere — and forgotten when the server withdraws
    /// the request, when the owner declines the account, and past the request's lifetime; a refusal
    /// is not remembered.
    #[tokio::test]
    async fn an_approval_here_is_remembered_until_its_binding_comes() {
        let (mut agent, tx, mut rx) = harness();
        agent.handle_server_msg(pair_request(None), &tx).await;
        let _ = answer_pair(&mut agent, &tx, &mut rx, false).await;
        assert!(
            agent.approved_here.is_empty(),
            "a refusal is nothing to look for"
        );

        // Withdrawn by the server after the approval: no binding is coming.
        agent.handle_server_msg(pair_request(None), &tx).await;
        let _ = answer_pair(&mut agent, &tx, &mut rx, true).await;
        assert!(agent.approved_here.contains_key(&7));
        agent
            .handle_server_msg(
                ServerToAgent::PairCancelled {
                    request_id: "7c4b1e90-2a3d-4f51-9b8e-6d5c4a3b2f10".into(),
                    reason: afklink_protocol::PairDeclineReason::Timeout,
                },
                &tx,
            )
            .await;
        assert!(agent.approved_here.is_empty(), "withdrawn: forgotten");

        // Declined later for the same account: the earlier approval stops counting.
        let now = Instant::now();
        agent.note_answer_here(8, "r1", true, now);
        agent.note_answer_here(8, "r2", false, now);
        assert!(!agent.approved_here.contains_key(&8));

        // Past the request's lifetime.
        agent.note_answer_here(9, "r3", true, now);
        agent.forget_old_approvals(now + APPROVED_HERE_FOR - Duration::from_millis(1));
        assert!(agent.approved_here.contains_key(&9), "still inside it");
        agent.forget_old_approvals(now + APPROVED_HERE_FOR);
        assert!(agent.approved_here.is_empty(), "past it: forgotten");

        // Heard of: forgotten too.
        agent.handle_server_msg(pair_request(None), &tx).await;
        let _ = answer_pair(&mut agent, &tx, &mut rx, true).await;
        assert!(agent.approved_here.contains_key(&7));
        agent
            .handle_server_msg(
                ServerToAgent::BindingAdded {
                    telegram_user_id: 7,
                    username: Some("ann".into()),
                    first_name: Some("Аня".into()),
                    role: Some(afklink_protocol::BindingRole::Guest),
                    via: None,
                },
                &tx,
            )
            .await;
        assert!(agent.approved_here.is_empty(), "heard of: forgotten");
    }

    /// `pc_allow`: the server holds an approval made here for the owner, who may answer minutes
    /// later. The approval is kept until his deadline and the sweep after it — a list after a break
    /// that has the newcomer is this PC's «Разрешить», not an invite — and forgotten when he does
    /// not allow it; one the server re-sends after a restart is taken as approved here. The
    /// newcomer's row is named as the prompt named them when the state names nobody, and their
    /// `binding_added` ends the request as allowed.
    #[tokio::test]
    async fn an_approval_held_for_the_owner_is_kept_while_he_decides() {
        use afklink_protocol::{BindingRole, OwnerRequestState, OwnerStateKind};
        let (mut agent, tx, mut rx) = harness();
        lock(&agent.state).bindings = vec![role_binding(1, Some(BindingRole::Owner))];
        agent.handle_server_msg(pair_request(Some(true)), &tx).await;
        let _ = answer_pair(&mut agent, &tx, &mut rx, true).await;
        let pressed = Instant::now();
        let held =
            |state: OwnerRequestState, expires_at: Option<i64>| ServerToAgent::OwnerRequestState {
                request_id: Some("7c4b1e90-2a3d-4f51-9b8e-6d5c4a3b2f10".into()),
                kind: OwnerStateKind::PcAllow,
                telegram_user_id: 7,
                state,
                expires_at,
                reason: None,
                username: None,
                first_name: None,
            };
        let deadline = crate::journal::now_ms() + 600_000;
        agent
            .handle_server_msg(held(OwnerRequestState::Pending, Some(deadline)), &tx)
            .await;
        {
            let s = lock(&agent.state);
            let (uid, names) = s.owner_requests.newcomer().expect("the newcomer's row");
            assert_eq!(uid, 7);
            assert_eq!(
                names.and_then(|n| n.first_name.as_deref()),
                Some("Аня"),
                "named as the prompt named them"
            );
            assert!(
                s.owner_requests.busy(),
                "one question from the PC at a time"
            );
        }
        // Past an ordinary approval's time, inside the owner's: kept — until his deadline and the
        // server's sweep after it, and not after.
        agent.forget_old_approvals(pressed + APPROVED_HERE_FOR + Duration::from_secs(60));
        let until = agent.approved_here.get(&7).expect("kept").until;
        let grace = u64::try_from(crate::owner_request::EXPIRY_GRACE_MS).expect("positive");
        assert!(until > pressed + Duration::from_millis(600_000 + grace - 1_000));
        assert!(until < pressed + Duration::from_millis(600_000 + grace + 1_000));

        // He declines: no binding is coming from it.
        agent
            .handle_server_msg(held(OwnerRequestState::Declined, None), &tx)
            .await;
        assert!(agent.approved_here.is_empty());
        assert!(!lock(&agent.state).owner_requests.busy());

        // Re-sent after a restart (nothing remembered): taken as approved here; then allowed — the
        // binding first, `confirmed` after it.
        agent
            .handle_server_msg(held(OwnerRequestState::Pending, Some(deadline)), &tx)
            .await;
        assert!(agent.approved_here.contains_key(&7));
        // Meanwhile someone at the PC opened the pairing panel again: a new code, which the owner's
        // «Разрешить» in Telegram does not spend.
        {
            let mut s = lock(&agent.state);
            s.pairing_panel = crate::pairing::PairingPanel::Open;
            s.pairing_code = Some("482913".into());
        }
        agent
            .handle_server_msg(
                ServerToAgent::BindingAdded {
                    telegram_user_id: 7,
                    username: Some("ann".into()),
                    first_name: Some("Аня".into()),
                    role: Some(BindingRole::Guest),
                    via: None,
                },
                &tx,
            )
            .await;
        assert!(agent.approved_here.is_empty(), "heard of: forgotten");
        {
            let s = lock(&agent.state);
            assert_eq!(s.pairing_panel, crate::pairing::PairingPanel::Open);
            assert_eq!(s.pairing_code.as_deref(), Some("482913"), "left as it is");
        }
        agent
            .handle_server_msg(held(OwnerRequestState::Confirmed, None), &tx)
            .await;
        assert!(
            agent.approved_here.is_empty(),
            "its binding is in the list: nothing to keep"
        );
        let s = lock(&agent.state);
        assert!(!s.owner_requests.busy());
        assert_eq!(
            s.owner_requests.ended_for(7).map(|e| e.outcome),
            Some(crate::owner_request::Outcome::Confirmed)
        );
    }

    /// Why «Новый гость» is withheld: a repeat, or a role the contract never sends with an invite.
    #[test]
    fn the_new_guest_toast_is_withheld_for_a_repeat_and_an_owner() {
        use afklink_protocol::BindingRole;
        assert_eq!(
            invited_guest_toast_withheld(Some(BindingRole::Guest), false),
            None
        );
        // No role: only a server older than roles, which knows no invites; taken as a guest.
        assert_eq!(invited_guest_toast_withheld(None, false), None);
        assert!(invited_guest_toast_withheld(Some(BindingRole::Guest), true).is_some());
        assert!(invited_guest_toast_withheld(Some(BindingRole::Owner), false).is_some());
    }

    /// Nobody listening (the CLI's way, before its announcer subscribes; a test agent): nothing is
    /// sent and nothing breaks — the journal still has the guest.
    #[tokio::test]
    async fn a_guest_by_invite_with_nobody_listening_is_still_journaled() {
        use afklink_protocol::{BindingRole, BindingVia};
        let (agent, tx, _rx) = harness();
        let (mut agent, journal) = with_journal(agent);
        assert_eq!(agent.events.receiver_count(), 0);
        agent
            .handle_server_msg(
                ServerToAgent::BindingAdded {
                    telegram_user_id: 42,
                    username: None,
                    first_name: Some("Друг".into()),
                    role: Some(BindingRole::Guest),
                    via: Some(BindingVia::Invite),
                },
                &tx,
            )
            .await;
        let last = journal.last().expect("journaled");
        assert_eq!(last.entry.kind, crate::journal::Kind::Invited);
        assert_eq!(roles(&agent), [(42, Some(BindingRole::Guest))]);
    }

    /// A rename is held to the rule the backend applies; a refused one leaves the old name and
    /// tells the backend nothing, and so does setting the name the PC already has.
    #[tokio::test]
    async fn a_rename_outside_the_device_name_rule_keeps_the_old_name() {
        let (mut agent, tx, mut rx) = harness();
        agent
            .handle_command(AgentCommand::SetName(" Office ".into()), &tx)
            .await;
        assert_eq!(lock(&agent.config).name, "Office");
        assert!(matches!(
            rx.try_recv(),
            Ok(AgentToServer::DeviceName { name }) if name == "Office"
        ));
        for refused in [
            "   ".to_string(),
            "x".repeat(afklink_protocol::DEVICE_NAME_MAX + 1),
            "Office\nPC".to_string(),
            "Office".to_string(),
        ] {
            agent
                .handle_command(AgentCommand::SetName(refused.clone()), &tx)
                .await;
            assert_eq!(lock(&agent.config).name, "Office", "{refused:?}");
            assert!(rx.try_recv().is_err(), "nothing sent for {refused:?}");
        }
    }

    /// Every connection opens with the PC's name, ahead of the sessions it re-announces: the
    /// device's name follows the PC, and a rename made while offline (dropped by the relay) arrives
    /// this way.
    #[tokio::test]
    async fn every_connection_opens_with_the_pc_name() {
        let (mut agent, tx, mut rx) = harness();
        lock(&agent.config).name = "HVN2MMZR".into();
        agent.announce_after_connect(1, &tx);
        assert_eq!(
            rx.try_recv().expect("the name went to the backend"),
            AgentToServer::DeviceName {
                name: "HVN2MMZR".into()
            }
        );
        assert!(rx.try_recv().is_err(), "nothing else on a first connection");

        // A stored name outside the rule (a hand edit while running) is not sent.
        lock(&agent.config).name = "Office\tPC".into();
        agent.announce_after_connect(2, &tx);
        assert!(rx.try_recv().is_err());
    }

    /// The pre-encode latency guard, as the three inputs it is a function of.
    ///
    /// The point of it being a function at all is that this test needs no capturer, no encoder and
    /// no transport, so its limits are checked rather than assumed.
    #[test]
    fn the_queue_guard_withholds_a_frame_only_while_it_can_help() {
        // Past the budget: the bytes this frame would make are bytes that arrive late by
        // construction, so not making them is the only action left that shortens the queue.
        assert!(
            skip_for_queue(160, 0, false),
            "160 ms of measured queue is past QUEUE_SKIP_MS ({QUEUE_SKIP_MS}) and the frame must \
             be withheld"
        );

        // Inside it, pushback is already working on the budget and a discrete action would only
        // fight it. See QUEUE_SKIP_MS on why this is twice quality::QUEUE_GUARD_MS.
        assert!(
            !skip_for_queue(140, 0, false),
            "140 ms is inside the guard, where the continuous lever is the right one"
        );

        // A keyframe the viewer asked for is how a lost picture comes back. Withholding it turns
        // one bad second into a session that never recovers, and a full queue is a reason to send
        // it sooner rather than a reason to hold it.
        assert!(
            !skip_for_queue(160, 0, true),
            "a forced keyframe is never withheld, whatever the queue says"
        );

        // And the guard cannot starve the stream. The gauge it reads is republished on the control
        // task's 200 ms tick; a task that has stopped ticking leaves it stale forever, and an
        // unbounded guard would then be a permanent freeze with nothing in the log to say so.
        assert!(
            !skip_for_queue(160, MAX_QUEUE_SKIPS, false),
            "after {MAX_QUEUE_SKIPS} consecutive skips the frame is encoded regardless — a stuck \
             gauge must cost a judder, not the session"
        );
        assert!(
            skip_for_queue(160, MAX_QUEUE_SKIPS - 1, false),
            "and the one before it is still withheld"
        );
    }

    /// A recorded second (Telegram iOS), the gauge the encode loop saw at 60 fps: 334, 499, 677,
    /// 845 on successive control ticks, then 1017, then 0. The soft guard withheld six frames and
    /// released one at its cap each time; the one released with the gauge at 1017 was discarded by
    /// the breaker (1031 ms) and so was the next, breaking the viewer's reference chain. The hard
    /// hold keeps every frame from then to the drain unencoded, so the breaker has nothing to
    /// discard.
    #[test]
    fn the_hard_hold_keeps_the_breaker_from_discarding_on_the_recorded_shape() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut hold = HardHold::default();
        // The first 0.8 s: under the breaker's limit, the soft guard's business.
        for (ms, gauge) in [(0, 334), (200, 499), (450, 677), (680, 845)] {
            assert_eq!(hold.step(gauge, at(ms)), HardHoldStep::Pass, "{gauge} ms");
        }
        // At 0.8 s: 1017 ms, past the limit. Everything to the drain is withheld.
        assert_eq!(hold.step(1_017, at(806)), HardHoldStep::Engaged);
        for frame in 1..12u64 {
            assert_eq!(
                hold.step(1_017, at(806 + frame * 17)),
                HardHoldStep::Hold,
                "frame {frame}"
            );
        }
        // At 1.0 s: the gauge reads 0 — released, nothing encoded into the queue.
        assert_eq!(
            hold.step(0, at(1_005)),
            HardHoldStep::Released {
                held: Duration::from_millis(199),
                withheld: 12
            }
        );
        assert_eq!(hold.step(0, at(1_022)), HardHoldStep::Pass);
        // Between the resume level and the limit it is the soft guard's again, not the hold's.
        assert_eq!(hold.step(900, at(1_039)), HardHoldStep::Pass);
    }

    /// A gauge stuck past the limit — a control task that stopped ticking — must not freeze the
    /// picture for good: after `HARD_HOLD_MAX` the frames go to the breaker, and the hold is armed
    /// again only once the gauge has come back under the resume level.
    #[test]
    fn a_stuck_gauge_costs_the_hard_hold_one_second_not_the_session() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut hold = HardHold::default();
        assert_eq!(hold.step(1_200, at(0)), HardHoldStep::Engaged);
        assert_eq!(hold.step(1_200, at(999)), HardHoldStep::Hold);
        assert!(matches!(
            hold.step(1_200, at(1_000)),
            HardHoldStep::GaveUp { withheld: 2, .. }
        ));
        for ms in [1_017, 5_000, 60_000] {
            assert_eq!(hold.step(1_200, at(ms)), HardHoldStep::Pass, "{ms}");
        }
        assert_eq!(
            hold.step(afklink_transport::QUEUE_RESUME_MS, at(60_017)),
            HardHoldStep::Rearmed
        );
        assert_eq!(hold.step(1_200, at(60_034)), HardHoldStep::Engaged);
    }

    /// The real encode loop with scriptable backends: what `start_session` wires up, minus the
    /// network. Returns the pieces a test drives it through.
    struct LoopRig {
        capture: Arc<Mutex<crate::pipeline::fakes::CaptureWorld>>,
        encode: Arc<Mutex<crate::pipeline::fakes::EncoderWorld>>,
        health: Arc<crate::pipeline::PipelineHealth>,
        media: mpsc::Receiver<afklink_transport::MediaSample>,
        /// Every sample the loop has sent the peer so far, as its keyframe flag, in order.
        samples: Vec<bool>,
        stop: Arc<AtomicBool>,
        thread: std::thread::JoinHandle<Option<&'static str>>,
    }

    fn loop_rig() -> LoopRig {
        use crate::pipeline::fakes::{fake_backends, CaptureWorld, EncoderWorld};
        let capture = Arc::new(Mutex::new(CaptureWorld::default()));
        let encode = Arc::new(Mutex::new(EncoderWorld::default()));
        let backends = fake_backends(&capture, &encode);
        loop_rig_with(capture, encode, backends, crate::game::CaptureMode::Monitor).0
    }

    /// The pieces of a loop rig a game-mode test reads besides the rig itself.
    struct LoopExtras {
        target: Arc<crate::quality::QualityTarget>,
        counters: Arc<SessionCounters>,
        game: Arc<crate::game::GameStatus>,
        /// The owner's switch, for a test that flips it mid-session.
        modes: Arc<crate::game::CaptureModeCell>,
        /// The agent's own keyframe flag and the viewer's requests, as the event task sets them.
        pending_kf: Arc<AtomicBool>,
        viewer_kf: Arc<crate::keyframe_window::ViewerAsks>,
        /// The NACKs the peer counts live (`Peer::nacks_received`), as the transport moves them.
        nacks: Arc<AtomicU64>,
    }

    fn loop_rig_with(
        capture: Arc<Mutex<crate::pipeline::fakes::CaptureWorld>>,
        encode: Arc<Mutex<crate::pipeline::fakes::EncoderWorld>>,
        backends: Arc<Backends>,
        mode: crate::game::CaptureMode,
    ) -> (LoopRig, LoopExtras) {
        let target = Arc::new(crate::quality::QualityTarget::default());
        // A budget, so the frame dropper has a rate to hold and five-byte frames never trip it.
        target.set_target_kbps(4_000);
        let (frame_tx, frame_rx) = std::sync::mpsc::channel();
        let (source, modes, game) = crate::pipeline::fakes::session_capture(backends.clone(), mode);
        let mut first = source.make().expect("capturer");
        first
            .start(frame_tx.clone(), target.clone())
            .expect("start");
        let health = Arc::new(crate::pipeline::PipelineHealth::new(Instant::now()));
        let pending_kf = Arc::new(AtomicBool::new(false));
        let viewer_kf = Arc::new(crate::keyframe_window::ViewerAsks::default());
        let sup = crate::pipeline::Supervisor::new(
            health.clone(),
            source,
            Arc::new(Mutex::new(first)),
            frame_tx,
            target.clone(),
            pending_kf.clone(),
            Instant::now(),
        );
        let encoder = (backends.make_encoder)().expect("encoder");
        let (media_tx, media) = mpsc::channel(1024);
        let nacks = Arc::new(AtomicU64::new(0));
        let sink = MediaSink {
            tx: media_tx,
            queued_bytes: Arc::new(AtomicU32::new(0)),
            nacks: nacks.clone(),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(SessionCounters::default());
        let thread = {
            let stop = stop.clone();
            let target = target.clone();
            let counters = counters.clone();
            let viewer_kf = viewer_kf.clone();
            std::thread::spawn(move || {
                encode_loop(
                    encoder,
                    frame_rx,
                    sink,
                    EncodeControl::ordinary(stop),
                    target,
                    counters,
                    sup,
                    &viewer_kf,
                )
            })
        };
        (
            LoopRig {
                capture,
                encode,
                health,
                media,
                samples: Vec::new(),
                stop,
                thread,
            },
            LoopExtras {
                target,
                counters,
                game,
                modes,
                pending_kf,
                viewer_kf,
                nacks,
            },
        )
    }

    impl LoopRig {
        /// The running fake capture delivers `n` frames, a little apart.
        fn frames(&self, n: usize) {
            for _ in 0..n {
                if let Some(sink) = lock(&self.capture).sink.clone() {
                    let _ = sink.send(crate::pipeline::fakes::test_frame());
                }
                std::thread::sleep(Duration::from_millis(15));
            }
        }

        fn wait_until(&self, what: &str, cond: impl Fn(&Self) -> bool) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !cond(self) {
                assert!(Instant::now() < deadline, "timed out waiting for: {what}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        /// Wait until the peer has been sent `n` samples in all.
        fn wait_samples(&mut self, n: usize) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                while let Ok(s) = self.media.try_recv() {
                    self.samples.push(s.is_keyframe);
                }
                if self.samples.len() >= n {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for {n} samples; have {:?}",
                    self.samples
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn state(
            &self,
        ) -> (
            afklink_protocol::PipelineState,
            Option<afklink_protocol::PipelineCause>,
        ) {
            self.health.state()
        }
    }

    /// The blind spot, end to end: the capture thread dies mid-session, then the encoder breaks,
    /// then it panics. Each time the session carries on — frames keep reaching the peer, the first
    /// one after each recovery is a keyframe — and nothing ends the session.
    #[test]
    fn the_encode_loop_brings_back_a_dead_capture_and_a_broken_encoder() {
        use afklink_protocol::{PipelineCause, PipelineState};
        let mut r = loop_rig();

        r.frames(3);
        r.wait_samples(3);
        assert!(
            r.samples[0],
            "a session opens with a keyframe: {:?}",
            r.samples
        );

        // The capture thread exits on its own. Nothing closes the channel the loop waits on.
        lock(&r.capture).dead = true;
        r.wait_until("the capture is restarted", |r| lock(&r.capture).starts == 2);
        assert_eq!(
            r.state(),
            (PipelineState::Restarting, Some(PipelineCause::CaptureLost))
        );
        r.frames(3);
        r.wait_samples(6);
        assert!(
            r.samples[3],
            "the first frame after a capture restart is a keyframe: {:?}",
            r.samples
        );
        assert_eq!(r.state(), (PipelineState::Ok, None));

        // The encoder starts failing every frame.
        lock(&r.encode).errors = crate::pipeline::ENCODE_ERRORS_BEFORE_RESTART;
        r.frames(crate::pipeline::ENCODE_ERRORS_BEFORE_RESTART as usize);
        r.wait_until("the encoder is recreated", |r| lock(&r.encode).created == 2);
        r.frames(2);
        r.wait_samples(8);
        assert!(
            r.samples[6],
            "a new encoder's first frame is a keyframe: {:?}",
            r.samples
        );

        // And one panics.
        lock(&r.encode).panics = 1;
        r.frames(1);
        r.wait_until("a panicking encoder is replaced at once", |r| {
            lock(&r.encode).created == 3
        });
        r.frames(2);
        r.wait_samples(10);
        assert!(
            r.samples[8],
            "and its replacement opens with a keyframe: {:?}",
            r.samples
        );
        assert_eq!(
            r.health.restarts(),
            3,
            "one capture restart, two encoder recreations"
        );
        assert_eq!(r.state(), (PipelineState::Ok, None));

        r.stop.store(true, Ordering::SeqCst);
        let outcome = r
            .thread
            .join()
            .expect("the encode thread does not panic out");
        assert_eq!(
            outcome, None,
            "a session that ends is not a pipeline that failed"
        );
        assert!(
            lock(&r.capture).sink.is_none(),
            "the capture stops with the encode thread"
        );
    }

    /// The background hold through the real encode loop and supervisor: held, the capture stops and
    /// nothing reaches the peer — not even a frame the stopped capture had in flight; released, a
    /// fresh capture starts and its first frame goes out as a keyframe. `ok` throughout, and no
    /// restart counted.
    #[test]
    fn the_encode_loop_sends_nothing_while_held_and_resumes_with_a_keyframe() {
        use crate::pipeline::fakes::{fake_backends, test_frame, CaptureWorld, EncoderWorld};
        use afklink_protocol::PipelineState;
        let capture = Arc::new(Mutex::new(CaptureWorld::default()));
        let encode = Arc::new(Mutex::new(EncoderWorld::default()));
        let backends = fake_backends(&capture, &encode);
        let (mut r, x) =
            loop_rig_with(capture, encode, backends, crate::game::CaptureMode::Monitor);
        r.frames(3);
        r.wait_samples(3);
        let old_sink = lock(&r.capture).sink.clone().expect("running");

        x.target.set_bg_hold(true);
        r.wait_until("the capture is stopped for the hold", |r| {
            lock(&r.capture).stops == 1
        });
        let _ = old_sink.send(test_frame());
        std::thread::sleep(Duration::from_millis(300));
        while let Ok(s) = r.media.try_recv() {
            r.samples.push(s.is_keyframe);
        }
        assert_eq!(
            r.samples.len(),
            3,
            "nothing sent while held: {:?}",
            r.samples
        );
        assert_eq!(r.state(), (PipelineState::Ok, None));

        x.target.set_bg_hold(false);
        r.wait_until("a fresh capture starts", |r| lock(&r.capture).starts == 2);
        r.frames(2);
        r.wait_samples(5);
        assert!(
            r.samples[3] && !r.samples[4],
            "the resume opens with a keyframe, and only it: {:?}",
            r.samples
        );
        assert_eq!(r.health.restarts(), 0, "a resume is not a restart");
        assert_eq!(r.state(), (PipelineState::Ok, None));

        r.stop.store(true, Ordering::SeqCst);
        assert_eq!(r.thread.join().expect("no panic"), None);
    }

    /// The viewer's keyframe requests through the real encode loop (`crate::keyframe_window`): a
    /// PLI that arrives inside the window of the keyframe just sent is answered by it — no second
    /// keyframe, and counted for the `pipeline` line — while the agent's own request inside the
    /// same window is honoured and opens a window of its own, which answers the PLI that follows; a
    /// PLI that arrives after the window gets its keyframe. A 1.5 s round trip keeps every step
    /// inside its window however slowly the machine runs the test, and the last request's arrival
    /// is stamped past it rather than waited for.
    #[test]
    fn the_encode_loop_answers_the_viewers_repeat_with_the_keyframe_in_flight() {
        use crate::pipeline::fakes::{fake_backends, CaptureWorld, EncoderWorld};
        let capture = Arc::new(Mutex::new(CaptureWorld::default()));
        let encode = Arc::new(Mutex::new(EncoderWorld::default()));
        let backends = fake_backends(&capture, &encode);
        let (mut r, x) =
            loop_rig_with(capture, encode, backends, crate::game::CaptureMode::Monitor);
        x.counters.rtt_ms.store(1_500, Ordering::Relaxed);
        let suppressed = || {
            x.counters
                .keyframe_requests_suppressed
                .load(Ordering::Relaxed)
        };
        r.frames(3);
        r.wait_samples(3);
        assert_eq!(
            r.samples,
            [true, false, false],
            "a session opens with a keyframe"
        );

        // The viewer's PLI while the opening keyframe is still within reach of it.
        x.viewer_kf.note(Instant::now());
        r.frames(2);
        r.wait_samples(5);
        assert!(
            !r.samples[3] && !r.samples[4],
            "answered by the keyframe in flight: {:?}",
            r.samples
        );
        assert_eq!(suppressed(), 1);

        // The flag (the transport's broken chain, a drain's end, the Mini App's `kf`) is never
        // held.
        x.pending_kf.store(true, Ordering::SeqCst);
        r.frames(1);
        r.wait_samples(6);
        assert!(r.samples[5], "the flag's keyframe: {:?}", r.samples);
        // Its keyframe answers the PLI that comes right after it.
        x.viewer_kf.note(Instant::now());
        r.frames(2);
        r.wait_samples(8);
        assert!(!r.samples[6] && !r.samples[7], "{:?}", r.samples);
        assert_eq!(suppressed(), 2);

        // Past the window (1.5 s, the keyframe's send time and the margin): the keyframe did not
        // make it, and the viewer gets another.
        x.viewer_kf.note(Instant::now() + Duration::from_secs(3));
        r.frames(1);
        r.wait_samples(9);
        assert!(r.samples[8], "honoured after the window: {:?}", r.samples);
        assert_eq!(suppressed(), 2);

        r.stop.store(true, Ordering::SeqCst);
        assert_eq!(r.thread.join().expect("no panic"), None);
    }

    /// The loop reads the path for the window (`crate::keyframe_window`, "When the keyframe on its
    /// way cannot be trusted"): once the transport has counted a NACK since the keyframe went out,
    /// the viewer's next request inside that keyframe's window is honoured — at once, with no stats
    /// interval — where the one before the NACK was held. The stats interval's NACKs alone do not
    /// let the window go: the live count had them first, and those from before the keyframe are
    /// not its evidence.
    #[test]
    fn the_encode_loop_lets_a_request_through_once_the_path_lost_packets() {
        use crate::pipeline::fakes::{fake_backends, CaptureWorld, EncoderWorld};
        let capture = Arc::new(Mutex::new(CaptureWorld::default()));
        let encode = Arc::new(Mutex::new(EncoderWorld::default()));
        let backends = fake_backends(&capture, &encode);
        let (mut r, x) =
            loop_rig_with(capture, encode, backends, crate::game::CaptureMode::Monitor);
        x.counters.rtt_ms.store(1_500, Ordering::Relaxed);
        // NACKs before the opening keyframe: the window's baseline, not evidence against it.
        x.nacks.store(40, Ordering::Release);
        let suppressed = || {
            x.counters
                .keyframe_requests_suppressed
                .load(Ordering::Relaxed)
        };
        r.frames(3);
        r.wait_samples(3);
        assert_eq!(r.samples, [true, false, false]);
        x.viewer_kf.note(Instant::now());
        r.frames(1);
        r.wait_samples(4);
        assert!(!r.samples[3], "held: {:?}", r.samples);
        assert_eq!(suppressed(), 1);
        // A stats interval with 12 more NACKs, as the event task stores it: nothing for a window
        // that counts them live.
        x.counters.nacks.fetch_add(12, Ordering::Relaxed);
        x.counters.link_reports.fetch_add(1, Ordering::Release);
        x.viewer_kf.note(Instant::now());
        r.frames(1);
        r.wait_samples(5);
        assert!(!r.samples[4], "still held: {:?}", r.samples);
        assert_eq!(suppressed(), 2);
        // The transport counts one: the next request is honoured.
        x.nacks.fetch_add(1, Ordering::Release);
        x.viewer_kf.note(Instant::now());
        r.frames(1);
        r.wait_samples(6);
        assert!(
            r.samples[5],
            "honoured: the window was distrusted: {:?}",
            r.samples
        );
        assert_eq!(suppressed(), 2);

        r.stop.store(true, Ordering::SeqCst);
        assert_eq!(r.thread.join().expect("no panic"), None);
    }

    async fn next_heartbeat(
        control: &mut mpsc::Receiver<PeerControl>,
        within: Duration,
    ) -> afklink_protocol::Heartbeat {
        let ctrl = tokio::time::timeout(within, control.recv())
            .await
            .expect("a heartbeat in time")
            .expect("the channel is open");
        let PeerControl::SendHeartbeat(json) = ctrl else {
            panic!("expected a heartbeat, got {ctrl:?}");
        };
        let afklink_protocol::AgentDataMessage::Heartbeat(hb) =
            serde_json::from_str(&json).expect("the heartbeat is contract JSON")
        else {
            panic!("expected a heartbeat message, got {json}");
        };
        hb
    }

    /// A heartbeat's reach monitor over an injector that knows nothing (the trait's default).
    fn no_reach() -> Arc<crate::input_reach::ReachMonitor> {
        Arc::new(crate::input_reach::ReachMonitor::new(
            Arc::new(NoopInjector),
            Arc::new(Mutex::new(AgentState::default())),
            crate::input_reach::tests::config(),
        ))
    }

    /// A session summary of its own, for the heartbeat's tests about something else.
    fn test_summary() -> Arc<crate::summary::SessionSummary> {
        Arc::new(crate::summary::SessionSummary::new(
            "s1",
            Instant::now(),
            None,
            None,
            crate::traits::InputReach::default(),
        ))
    }

    /// A background hold cell of its own that nothing ever holds: for the heartbeat's tests about
    /// something else, and a session in a test that never sees a `vis`.
    fn no_hold() -> Arc<crate::bg_hold::BgHold> {
        Arc::new(crate::bg_hold::BgHold::new(
            "s1",
            Arc::new(crate::quality::QualityTarget::default()),
        ))
    }

    /// `vis_ok` in every heartbeat from this build; `bg_hold` from the moment a hold begins — at
    /// once, not on the next tick — with the pipeline `ok` and `still`, and `net_stall` superseded by
    /// it; gone again the moment the viewer is back.
    #[tokio::test]
    async fn the_heartbeat_says_vis_ok_always_and_bg_hold_at_once_while_held() {
        use afklink_protocol::PipelineState;
        let health = Arc::new(crate::pipeline::PipelineHealth::new(Instant::now()));
        let target = Arc::new(crate::quality::QualityTarget::default());
        let bg = Arc::new(crate::bg_hold::BgHold::new("s1", target.clone()));
        let (control_tx, mut control) = mpsc::channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let (sess_tx, _sess_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(heartbeat_task(
            health.clone(),
            target.clone(),
            Arc::new(crate::game::GameStatus::new()),
            Arc::new(crate::game::HelperLaunch::new()),
            no_reach(),
            bg.clone(),
            control_tx,
            stop.clone(),
            sess_tx,
            "s1".into(),
            test_summary(),
        ));
        let first = next_heartbeat(&mut control, Duration::from_millis(500)).await;
        assert!(first.vis_ok && !first.bg_hold, "{first:?}");
        let _ = next_heartbeat(&mut control, Duration::from_millis(1_500)).await;

        // A drain in force when the hold begins: the hold is what the viewer hears.
        target.set_draining(true);
        let t0 = Instant::now();
        bg.on_vis(true, Some("visibilitychange"), t0);
        assert!(bg.poll(t0 + crate::bg_hold::BG_HOLD_GRACE, None).is_some());
        let held = next_heartbeat(&mut control, Duration::from_millis(300)).await;
        assert!(held.vis_ok && held.bg_hold, "{held:?}");
        assert_eq!(held.state, PipelineState::Ok);
        assert!(held.still);
        assert!(!held.net_stall, "the hold supersedes the drain on the wire");

        target.set_draining(false);
        let _ = next_heartbeat(&mut control, Duration::from_millis(1_500)).await;
        bg.on_vis(false, Some("visibilitychange"), Instant::now());
        let back = next_heartbeat(&mut control, Duration::from_millis(300)).await;
        assert!(back.vis_ok && !back.bg_hold, "{back:?}");

        stop.store(true, Ordering::SeqCst);
        health.changed().notify_one();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the task stops with the session")
            .expect("and does not panic");
    }

    /// Once a second, and at once on a change — so a failure reaches the viewer in milliseconds,
    /// not on the next tick — with the numbers rising and the rung attached.
    #[tokio::test]
    async fn the_heartbeat_goes_out_every_second_and_at_once_on_a_change() {
        use afklink_protocol::{PipelineCause, PipelineState};
        let health = Arc::new(crate::pipeline::PipelineHealth::new(Instant::now()));
        let target = Arc::new(crate::quality::QualityTarget::default());
        let (control_tx, mut control) = mpsc::channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let (sess_tx, _sess_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(heartbeat_task(
            health.clone(),
            target.clone(),
            Arc::new(crate::game::GameStatus::new()),
            Arc::new(crate::game::HelperLaunch::new()),
            no_reach(),
            no_hold(),
            control_tx,
            stop.clone(),
            sess_tx,
            "s1".into(),
            test_summary(),
        ));

        let first = next_heartbeat(&mut control, Duration::from_millis(500)).await;
        assert_eq!(first.seq, 0);
        assert_eq!(first.state, PipelineState::Ok);
        assert_eq!(first.game, None, "no `game` outside game mode");
        assert!(
            !first.no_driver && !first.input_blocked,
            "an injector that cannot tell says nothing of the driver"
        );
        assert!(
            first.still,
            "nothing captured yet on a healthy pipeline is a still screen"
        );
        assert_eq!((first.h, first.fps), (target.max_h(), target.fps()));

        let second = next_heartbeat(&mut control, Duration::from_millis(1_500)).await;
        assert_eq!(second.seq, 1);

        health.publish(PipelineState::Restarting, Some(PipelineCause::CaptureLost));
        let changed = next_heartbeat(&mut control, Duration::from_millis(300)).await;
        assert_eq!(changed.state, PipelineState::Restarting);
        assert_eq!(changed.cause, Some(PipelineCause::CaptureLost));
        assert!(!changed.still);

        stop.store(true, Ordering::SeqCst);
        health.changed().notify_one();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the task stops with the session")
            .expect("and does not panic");
    }

    /// An encode that never returns ends the session — but only once the same stuck call has been
    /// seen for a whole interval, never on a single sighting.
    #[tokio::test]
    async fn a_stuck_encode_ends_the_session_once_confirmed() {
        let long_ago = Instant::now()
            .checked_sub(Duration::from_secs(30))
            .expect("the machine has been up for 30 s");
        let health = Arc::new(crate::pipeline::PipelineHealth::new(long_ago));
        health.enter(crate::pipeline::Busy::Encode, long_ago);
        let target = Arc::new(crate::quality::QualityTarget::default());
        let (control_tx, mut control) = mpsc::channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let (sess_tx, mut sess_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(heartbeat_task(
            health,
            target,
            Arc::new(crate::game::GameStatus::new()),
            Arc::new(crate::game::HelperLaunch::new()),
            no_reach(),
            no_hold(),
            control_tx,
            stop.clone(),
            sess_tx,
            "s1".into(),
            test_summary(),
        ));

        let first = next_heartbeat(&mut control, Duration::from_millis(500)).await;
        assert_eq!(first.state, afklink_protocol::PipelineState::Stalled);
        assert_eq!(
            first.cause,
            Some(afklink_protocol::PipelineCause::EncoderStalled)
        );
        assert!(sess_rx.try_recv().is_err(), "not on the first sighting");

        let signal = tokio::time::timeout(Duration::from_secs(3), sess_rx.recv())
            .await
            .expect("the session is ended within a couple of heartbeats")
            .expect("a signal");
        match signal {
            SessionSignal::PipelineFailed { id, reason } => {
                assert_eq!(id, "s1");
                assert_eq!(reason, "encoder_error");
            }
            _ => panic!("expected PipelineFailed"),
        }
        stop.store(true, Ordering::SeqCst);
        task.abort();
    }

    /// In game mode the heartbeat carries the game window's state and picture size, and a change of
    /// either goes out at once rather than on the next tick.
    #[tokio::test]
    async fn the_heartbeat_carries_the_game_window_and_its_changes_at_once() {
        use afklink_protocol::{GameHeartbeat, GameWindowState};
        let health = Arc::new(crate::pipeline::PipelineHealth::new(Instant::now()));
        let target = Arc::new(crate::quality::QualityTarget::default());
        let game = Arc::new(crate::game::GameStatus::new());
        game.set_active(true);
        let (control_tx, mut control) = mpsc::channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let (sess_tx, _sess_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(heartbeat_task(
            health.clone(),
            target,
            game.clone(),
            Arc::new(crate::game::HelperLaunch::new()),
            no_reach(),
            no_hold(),
            control_tx,
            stop.clone(),
            sess_tx,
            "s1".into(),
            test_summary(),
        ));

        let first = next_heartbeat(&mut control, Duration::from_millis(500)).await;
        assert_eq!(
            first.game,
            Some(GameHeartbeat::new(GameWindowState::Absent, None))
        );
        // Wait out the tick that follows the first, so the next heartbeat is the change's own.
        let _ = next_heartbeat(&mut control, Duration::from_millis(1_500)).await;

        game.set_state(GameWindowState::Shown);
        game.set_geometry(crate::game::CaptureGeometry {
            hwnd: 0x40666,
            client: crate::game::ScreenRect {
                left: 12,
                top: 47,
                right: 3588,
                bottom: 2315,
            },
            source: (3576, 2268),
        });
        let changed = next_heartbeat(&mut control, Duration::from_millis(300)).await;
        let game_now = changed.game.expect("game in the heartbeat");
        assert_eq!(game_now.state, GameWindowState::Shown);
        // The size may follow in the next one if the two changes were read apart.
        let sized = if game_now.w.is_some() {
            game_now
        } else {
            next_heartbeat(&mut control, Duration::from_millis(300))
                .await
                .game
                .expect("game")
        };
        assert_eq!((sized.w, sized.h), (Some(3576), Some(2268)));

        stop.store(true, Ordering::SeqCst);
        health.changed().notify_one();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the task stops with the session")
            .expect("and does not panic");
    }

    /// The game helper's launch reaches the viewer at once, as `game.launching` — only while the
    /// game's window is absent or starting, and never outside the game mode.
    #[tokio::test]
    async fn the_heartbeat_says_the_helper_is_launching_the_game_only_while_its_window_is_missing()
    {
        use afklink_protocol::GameWindowState;
        let health = Arc::new(crate::pipeline::PipelineHealth::new(Instant::now()));
        let game = Arc::new(crate::game::GameStatus::new());
        let launch = Arc::new(crate::game::HelperLaunch::new());
        let (control_tx, mut control) = mpsc::channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let (sess_tx, _sess_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(heartbeat_task(
            health.clone(),
            Arc::new(crate::quality::QualityTarget::default()),
            game.clone(),
            launch.clone(),
            no_reach(),
            no_hold(),
            control_tx,
            stop.clone(),
            sess_tx,
            "s1".into(),
            test_summary(),
        ));

        // Outside the game mode the launch says nothing: there is no `game` to carry it.
        launch.set(true, "test: the helper launched the game");
        let outside = next_heartbeat(&mut control, Duration::from_millis(500)).await;
        assert_eq!(outside.game, None);
        let _ = next_heartbeat(&mut control, Duration::from_millis(1_500)).await;

        game.set_active(true);
        let absent = next_heartbeat(&mut control, Duration::from_millis(300)).await;
        let absent = absent.game.expect("game in the heartbeat");
        assert_eq!(absent.state, GameWindowState::Absent);
        assert!(absent.launching, "the helper's launch, the window absent");

        game.set_state(GameWindowState::Starting);
        let starting = next_heartbeat(&mut control, Duration::from_millis(300)).await;
        let starting = starting.game.expect("game");
        assert_eq!(starting.state, GameWindowState::Starting);
        assert!(starting.launching);

        // The launch over (a failed start, the helper gave up): at once, not on the next tick.
        let _ = next_heartbeat(&mut control, Duration::from_millis(1_500)).await;
        launch.set(false, "test: the start failed");
        let over = next_heartbeat(&mut control, Duration::from_millis(300)).await;
        assert!(!over.game.expect("game").launching);

        // The window up while the helper still says it launches: nothing about a launch.
        launch.set(true, "test: launched again");
        let again = next_heartbeat(&mut control, Duration::from_millis(300)).await;
        assert!(again.game.expect("game").launching);
        game.set_state(GameWindowState::Shown);
        let shown = next_heartbeat(&mut control, Duration::from_millis(300)).await;
        let shown = shown.game.expect("game");
        assert_eq!(shown.state, GameWindowState::Shown);
        assert!(!shown.launching);

        stop.store(true, Ordering::SeqCst);
        health.changed().notify_one();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the task stops with the session")
            .expect("and does not panic");
    }

    /// The heartbeat says what the injector says of the driver and the input's reach: `no_driver`
    /// while it is missing, `input_blocked` while presses are dropped — and with that the window's
    /// highlight goes on, in memory and in config.json, and the live flag the toast follows.
    #[tokio::test]
    async fn the_heartbeat_says_the_driver_is_missing_and_the_input_blocked() {
        use crate::traits::{DriverPresence, InputReach};
        let injector = Arc::new(crate::input_reach::tests::ReachInjector::default());
        *lock(&injector.0) = InputReach {
            driver: DriverPresence::Missing,
            ..InputReach::default()
        };
        let state = Arc::new(Mutex::new(AgentState::default()));
        let config = crate::input_reach::tests::config();
        let reach = Arc::new(crate::input_reach::ReachMonitor::new(
            injector.clone(),
            state.clone(),
            config.clone(),
        ));
        let health = Arc::new(crate::pipeline::PipelineHealth::new(Instant::now()));
        let (control_tx, mut control) = mpsc::channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let (sess_tx, _sess_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(heartbeat_task(
            health.clone(),
            Arc::new(crate::quality::QualityTarget::default()),
            Arc::new(crate::game::GameStatus::new()),
            Arc::new(crate::game::HelperLaunch::new()),
            reach,
            no_hold(),
            control_tx,
            stop.clone(),
            sess_tx,
            "s1".into(),
            test_summary(),
        ));

        let first = next_heartbeat(&mut control, Duration::from_millis(500)).await;
        assert!(first.no_driver, "no driver: the viewer's game modes say so");
        assert!(!first.input_blocked);
        assert!(!lock(&state).input_not_reaching);

        *lock(&injector.0) = InputReach {
            driver: DriverPresence::Missing,
            blocked: true,
            lost: 3,
            delivered: 0,
            episodes: 1,
        };
        let blocked = next_heartbeat(&mut control, Duration::from_millis(1_500)).await;
        assert!(blocked.no_driver && blocked.input_blocked);
        assert!(lock(&state).input_not_reaching && lock(&state).input_blocked);
        assert!(lock(&config).input_not_reaching, "kept for the next run");

        // The driver installed mid-session: both flags go, and so does the highlight.
        *lock(&injector.0) = InputReach {
            driver: DriverPresence::Open,
            lost: 3,
            episodes: 1,
            ..InputReach::default()
        };
        let open = next_heartbeat(&mut control, Duration::from_millis(1_500)).await;
        assert!(!open.no_driver && !open.input_blocked);
        assert!(!lock(&state).input_not_reaching && !lock(&state).input_blocked);
        assert!(!lock(&config).input_not_reaching);

        stop.store(true, Ordering::SeqCst);
        health.changed().notify_one();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the task stops with the session")
            .expect("and does not panic");
    }

    /// The highlight outlives a restart: an agent made from a config.json that has it shows it.
    #[test]
    fn the_input_highlight_carries_over_from_config() {
        let (agent, control) = test_agent(None);
        assert!(!lock(&control.state).input_not_reaching);
        {
            let mut c = lock(&control.config);
            c.input_not_reaching = true;
            c.save().expect("save");
        }
        let path = lock(&control.config).path().expect("a file").to_path_buf();
        drop(agent);
        // The next run: the same files.
        let identity = Arc::new(
            Identity::load_or_create_at(path.with_file_name("identity.json")).expect("identity"),
        );
        let config = Config::load_or_create_at(path).expect("reloads");
        let backends = Backends {
            make_capturer: Box::new(|| Err(anyhow::anyhow!("no capturer in test"))),
            make_game_capturer: Box::new(|_| Err(anyhow::anyhow!("no game capturer in test"))),
            make_encoder: Box::new(|| Err(anyhow::anyhow!("no encoder in test"))),
            injector: Arc::new(NoopInjector),
        };
        let (_again, control) = Agent::new(config, identity, backends);
        assert!(lock(&control.state).input_not_reaching);
        // The desktop app read the driver installed: it goes, from config.json too.
        control.driver_installed("test: installed");
        assert!(!lock(&control.state).input_not_reaching);
        assert!(!lock(&control.config).input_not_reaching);
    }

    /// The whole game-mode pipeline on fakes: the real game capturer (its thread, the finder, the
    /// black frames) with a scripted window list and window capture, through the real encode loop.
    /// Black frames flow before the game is there; the window's frames once it is shown; a resize is
    /// encoded at the new size with the ladder priced against it; a minimize goes back to black in
    /// the picture's shape; and the session never ends — nor does the monitor capturer ever run.
    #[test]
    fn the_encode_loop_follows_the_game_window_through_black_frames_and_resizes() {
        use crate::game::fakes::{
            binding, game_window, BackendWorld, ScriptedBackend, ScriptedSource, Windows,
        };
        use crate::pipeline::fakes::{fake_backends, CaptureWorld, EncoderWorld};

        let capture = Arc::new(Mutex::new(CaptureWorld::default()));
        let encode = Arc::new(Mutex::new(EncoderWorld::default()));
        let fakes = fake_backends(&capture, &encode);
        let windows: Windows = Arc::new(Mutex::new(Ok(Vec::new())));
        let world = Arc::new(Mutex::new(BackendWorld::default()));
        let monitor_made = Arc::new(AtomicU32::new(0));
        let backends = {
            let windows = windows.clone();
            let world = world.clone();
            let monitor_made = monitor_made.clone();
            Arc::new(Backends {
                make_capturer: Box::new(move || {
                    monitor_made.fetch_add(1, Ordering::SeqCst);
                    Err(anyhow::anyhow!(
                        "the monitor must not be captured in game mode"
                    ))
                }),
                make_game_capturer: Box::new(move |request| {
                    Ok(Box::new(crate::game::GameCapturer::new(
                        request,
                        Box::new(ScriptedSource::new(windows.clone())),
                        Box::new(ScriptedBackend(world.clone())),
                    )) as Box<dyn Capturer>)
                }),
                make_encoder: Box::new(move || (fakes.make_encoder)()),
                injector: Arc::new(NoopInjector),
            })
        };
        let (mut r, x) = loop_rig_with(
            capture,
            encode,
            backends,
            crate::game::CaptureMode::GameWindow {
                binding: Some(binding()),
            },
        );

        // No game yet: black frames at the default 16:9, twice a second.
        r.wait_samples(2);
        r.wait_until("black frames are encoded at 1280x720", |_| {
            (
                x.counters.encoded_w.load(Ordering::Relaxed),
                x.counters.encoded_h.load(Ordering::Relaxed),
            ) == (1280, 720)
        });
        assert_eq!(
            x.game.snapshot().state,
            afklink_protocol::GameWindowState::Absent
        );

        // The game shows up: its window is captured and its frames go out.
        *lock(&windows) = Ok(vec![game_window(0x40666, 6888)]);
        r.wait_until("the window capture starts", |_| {
            !lock(&world).started.is_empty()
        });
        for _ in 0..3 {
            assert_eq!(
                lock(&world).deliver(1702, 1080),
                crate::game::GateSend::Sent
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        r.wait_until("the window's frames are encoded", |_| {
            x.counters.encoded_w.load(Ordering::Relaxed) == 1702
        });
        assert_eq!(x.game.snapshot().source, Some((1702, 1080)));

        // Borderless → windowed: a new size, encoded as such, the session carrying on.
        for _ in 0..3 {
            lock(&world).deliver(1680, 1066);
            std::thread::sleep(Duration::from_millis(20));
        }
        r.wait_until("the new size is encoded", |_| {
            (
                x.counters.encoded_w.load(Ordering::Relaxed),
                x.counters.encoded_h.load(Ordering::Relaxed),
            ) == (1680, 1066)
        });

        assert_eq!(
            x.target.source(),
            Some((1680, 1066)),
            "the ladder is priced against the window's picture"
        );

        // Minimized: black again, in the picture's last shape (1680x1066 fits 1080 lines as is).
        *lock(&windows) = Ok(vec![crate::game::WindowInfo {
            minimized: true,
            ..game_window(0x40666, 6888)
        }]);
        r.wait_until("the window capture is stopped", |_| {
            lock(&world).stopped >= 1
        });
        assert_eq!(
            x.game.snapshot().state,
            afklink_protocol::GameWindowState::Minimized
        );
        assert_eq!(x.game.geometry(), None, "nothing for input to map into");
        r.wait_samples(r.samples.len() + 1);
        let seen = r.samples.len();
        r.wait_samples(seen + 2);
        assert_eq!(
            (
                x.counters.encoded_w.load(Ordering::Relaxed),
                x.counters.encoded_h.load(Ordering::Relaxed),
            ),
            (1680, 1066),
            "black frames keep the picture's shape"
        );

        assert_eq!(r.state(), (afklink_protocol::PipelineState::Ok, None));
        r.stop.store(true, Ordering::SeqCst);
        let outcome = r
            .thread
            .join()
            .expect("the encode thread does not panic out");
        assert_eq!(outcome, None, "the session was never given up on");
        assert_eq!(
            monitor_made.load(Ordering::SeqCst),
            0,
            "the monitor capturer was never asked for"
        );
    }

    /// The owner turns game-only on mid-session: from the moment the setting flips, no frame of the
    /// monitor's capture is encoded — not one that reaches the encode loop before the supervisor has
    /// looked at the mode, and not one left in the channel when it replaces the capture.
    #[test]
    fn no_monitor_frame_is_encoded_once_game_only_is_turned_on() {
        use crate::pipeline::fakes::{fake_backends, test_frame, CaptureWorld, EncoderWorld};
        let capture = Arc::new(Mutex::new(CaptureWorld::default()));
        let encode = Arc::new(Mutex::new(EncoderWorld::default()));
        let backends = fake_backends(&capture, &encode);
        let (mut r, x) =
            loop_rig_with(capture, encode, backends, crate::game::CaptureMode::Monitor);
        r.frames(2);
        r.wait_samples(1);
        std::thread::sleep(Duration::from_millis(100));
        let before = lock(&r.encode).encoded;
        {
            // While this is held the capture cannot be replaced (stopping it waits for it), so every
            // frame below reaches the encode loop before the supervisor could act on the mode.
            let world = lock(&r.capture);
            let monitor = world.sink.clone().expect("the monitor's capture runs");
            x.modes.set(
                crate::game::CaptureMode::GameWindow {
                    binding: Some(crate::game::fakes::binding()),
                },
                "test: on",
            );
            for _ in 0..5 {
                monitor.send(test_frame()).expect("channel open");
                std::thread::sleep(Duration::from_millis(10));
            }
            std::thread::sleep(Duration::from_millis(200));
            assert_eq!(
                lock(&r.encode).encoded,
                before,
                "a monitor frame was encoded after the setting flipped"
            );
            drop(world);
        }
        r.wait_until("the game's capture replaces the monitor's", |r| {
            lock(&r.capture).started_kinds.last() == Some(&"game")
        });
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            lock(&r.encode).encoded,
            before,
            "nor after the replacement: they went with the old capture"
        );
        r.frames(2);
        r.wait_until("the game's capture's frames are encoded", |r| {
            lock(&r.encode).encoded > before
        });
        r.stop.store(true, Ordering::SeqCst);
        assert_eq!(r.thread.join().expect("no panic"), None);
    }

    /// The owner's switch and choice of game go to config.json and into force at once — a live
    /// session's capture mode follows; nothing changes when nothing does.
    #[test]
    fn the_game_only_setting_is_saved_and_put_in_force() {
        let (_agent, control) = test_agent(None);
        assert_eq!(control.game_only(), (false, None));
        // A live session (no roles: a server older than them; game-only applies to everyone).
        let session = control.game_access.open("s", 7, &[]);
        assert!(control.game_access.connected("s"));
        assert_eq!(session.current().0, crate::game::CaptureMode::Monitor);
        let generation = session.generation();

        control.set_game_only(true).expect("saved");
        assert_eq!(
            session.current().0,
            crate::game::CaptureMode::GameWindow { binding: None },
            "on with no game: black frames only"
        );
        let game = crate::game::fakes::binding();
        control.set_game_binding(Some(game.clone())).expect("saved");
        assert_eq!(
            session.current().0,
            crate::game::CaptureMode::GameWindow {
                binding: Some(game.clone())
            }
        );
        assert_eq!(session.generation(), generation + 2);
        assert_eq!(control.game_only_sessions(), ["s"]);
        // The same again changes nothing.
        control.set_game_only(true).expect("nothing to save");
        assert_eq!(session.generation(), generation + 2);

        // On disk too.
        let path = lock(&control.config).path().expect("a file").to_path_buf();
        let saved = Config::load_or_create_at(path).expect("reloads");
        assert!(saved.game_only);
        assert_eq!(saved.game.as_ref(), Some(&game));

        control.set_game_only(false).expect("saved");
        assert_eq!(session.current().0, crate::game::CaptureMode::Monitor);
        assert!(control.game_only_sessions().is_empty());
        assert_eq!(
            control.game_only(),
            (false, Some(game)),
            "the game stays bound"
        );
        control.set_game_binding(None).expect("saved");
        assert_eq!(control.game_only(), (false, None));
    }

    /// «Только для гостей»: off by default, saved, and every live session decided again at once —
    /// by the switch, and by the roles as the server's messages change them (`owner_changed`,
    /// `binding_added`); the game helper's list of game-only sessions follows.
    #[tokio::test]
    async fn guests_only_moves_live_sessions_by_the_switch_and_the_roles() {
        use crate::game::CaptureMode;
        use afklink_protocol::BindingRole;
        let (mut agent, control) = test_agent(None);
        let (tx, _rx) = mpsc::unbounded_channel();
        let game = crate::game::fakes::binding();
        control.set_game_binding(Some(game.clone())).expect("saved");
        control.set_game_only(true).expect("saved");
        assert!(!control.game_only_for_guests(), "off by default");
        let in_game = CaptureMode::GameWindow {
            binding: Some(game),
        };

        lock(&agent.state).bindings = vec![
            role_binding(1, Some(BindingRole::Owner)),
            role_binding(2, Some(BindingRole::Guest)),
        ];
        agent.sync_game_roles("test: agent_ready");
        let bindings = lock(&agent.state).bindings.clone();
        let owner = agent.game_access.open("s-owner", 1, &bindings);
        let guest = agent.game_access.open("s-guest", 2, &bindings);
        assert!(control.game_only_sessions().is_empty(), "not connected yet");
        assert!(agent.game_access.connected("s-owner"));
        assert!(agent.game_access.connected("s-guest"));
        assert_eq!(owner.current().0, in_game, "off: the owner too");
        assert_eq!(guest.current().0, in_game);
        assert_eq!(control.game_only_sessions(), ["s-guest", "s-owner"]);

        control.set_game_only_for_guests(true).expect("saved");
        assert!(control.game_only_for_guests());
        assert_eq!(
            owner.current().0,
            CaptureMode::Monitor,
            "the owner's desktop"
        );
        assert_eq!(guest.current().0, in_game);
        assert_eq!(control.game_only_sessions(), ["s-guest"]);
        let path = lock(&control.config).path().expect("a file").to_path_buf();
        let saved = Config::load_or_create_at(path.clone()).expect("reloads");
        assert!(saved.game_only_for_guests && saved.game_only);

        // The guest is made the owner: the roles swap mid-session, and so do the modes.
        agent
            .handle_server_msg(
                ServerToAgent::OwnerChanged {
                    telegram_user_id: Some(2),
                },
                &tx,
            )
            .await;
        assert_eq!(owner.current().0, in_game, "the old owner is a guest now");
        assert_eq!(guest.current().0, CaptureMode::Monitor, "the new owner");
        assert_eq!(control.game_only_sessions(), ["s-owner"]);

        // The owner unbinds himself: the PC has no owner, everyone is a guest.
        agent
            .handle_server_msg(
                ServerToAgent::OwnerChanged {
                    telegram_user_id: None,
                },
                &tx,
            )
            .await;
        assert_eq!(guest.current().0, in_game);
        assert_eq!(control.game_only_sessions(), ["s-guest", "s-owner"]);

        // A guest re-paired as the owner of the PC with none.
        agent
            .handle_server_msg(
                ServerToAgent::BindingAdded {
                    telegram_user_id: 1,
                    username: None,
                    first_name: Some("n1".into()),
                    role: Some(BindingRole::Owner),
                    via: None,
                },
                &tx,
            )
            .await;
        assert_eq!(owner.current().0, CaptureMode::Monitor);
        assert_eq!(guest.current().0, in_game);

        // Off again: game-only for everyone, as before the switch existed.
        control.set_game_only_for_guests(false).expect("saved");
        assert_eq!(owner.current().0, in_game);
        assert_eq!(guest.current().0, in_game);
        assert!(
            !Config::load_or_create_at(path)
                .expect("reloads")
                .game_only_for_guests
        );
    }

    /// The launch exe the owner chose belongs to its game: kept when the same game's window is
    /// chosen again, forgotten with another game or none.
    #[test]
    fn the_chosen_launch_exe_goes_with_its_game() {
        let (_agent, control) = test_agent(None);
        let game = crate::game::fakes::binding();
        control.set_game_binding(Some(game.clone())).expect("saved");
        lock(&control.config).game_launch_exe = Some(r"D:\Games\Launcher.exe".into());
        // The same exe, another of its windows' classes: the same game.
        let other_class = crate::game::GameBinding::new(&game.exe_path, "AnotherClass");
        control.set_game_binding(Some(other_class)).expect("saved");
        assert!(lock(&control.config).game_launch_exe.is_some());
        let other = crate::game::GameBinding::new(r"C:\Other\game.exe", "Window");
        control.set_game_binding(Some(other)).expect("saved");
        assert_eq!(lock(&control.config).game_launch_exe, None);
        lock(&control.config).game_launch_exe = Some(r"C:\Other\run.exe".into());
        control.set_game_binding(None).expect("saved");
        assert_eq!(lock(&control.config).game_launch_exe, None);
    }

    /// The launch exe learned from the game's parent process goes with its game too: kept for the
    /// same exe, forgotten with another game or none — the owner's choice beside it or not.
    #[test]
    fn the_learned_launch_exe_goes_with_its_game() {
        let (_agent, control) = test_agent(None);
        let game = crate::game::fakes::binding();
        control.set_game_binding(Some(game.clone())).expect("saved");
        lock(&control.config).game_launch_learned = Some(r"D:\Games\Launcher.exe".into());
        let other_class = crate::game::GameBinding::new(&game.exe_path, "AnotherClass");
        control.set_game_binding(Some(other_class)).expect("saved");
        assert_eq!(
            lock(&control.config).game_launch_learned.as_deref(),
            Some(r"D:\Games\Launcher.exe")
        );
        let other = crate::game::GameBinding::new(r"C:\Other\game.exe", "Window");
        control.set_game_binding(Some(other)).expect("saved");
        assert_eq!(lock(&control.config).game_launch_learned, None);
        {
            let mut config = lock(&control.config);
            config.game_launch_learned = Some(r"C:\Other\launcher.exe".into());
            config.game_launch_exe = Some(r"C:\Other\run.exe".into());
        }
        control.set_game_binding(None).expect("saved");
        let config = lock(&control.config);
        assert_eq!(
            (&config.game_launch_learned, &config.game_launch_exe),
            (&None, &None)
        );
    }

    /// When the encoder cannot be made again, the loop gives up with the agreed reason instead of
    /// running on without one — which is how the session gets ended with a sentence the viewer can
    /// show, rather than left frozen.
    #[test]
    fn the_encode_loop_gives_up_with_a_reason_when_the_encoder_cannot_come_back() {
        let r = loop_rig();
        lock(&r.encode).fail_creates = u32::MAX;
        lock(&r.encode).panics = 1;
        r.frames(1);
        // Recreations at 0, 1 and 2 s, then it gives up.
        let outcome = r.thread.join().expect("the encode thread returns");
        assert_eq!(outcome, Some("encoder_error"));
        assert!(
            lock(&r.capture).sink.is_none(),
            "and the capture is stopped"
        );
    }

    /// The first line of a burst is always written, and the next one says how many it stood for.
    #[test]
    fn a_throttled_line_says_what_it_held_back() {
        let t0 = Instant::now();
        let mut t = Throttle::new(Duration::from_secs(1));
        assert_eq!(t.ready(t0), Some(0));
        assert_eq!(t.ready(t0 + Duration::from_millis(100)), None);
        assert_eq!(t.ready(t0 + Duration::from_millis(900)), None);
        assert_eq!(t.ready(t0 + Duration::from_millis(1_000)), Some(2));
        assert_eq!(t.ready(t0 + Duration::from_millis(2_500)), Some(0));
    }

    #[test]
    fn is_bound_matches_on_user_id_only() {
        let bindings = vec![BindingInfo {
            telegram_user_id: 42,
            username: None,
            first_name: None,
            role: None,
        }];
        assert!(is_bound(&bindings, 42));
        assert!(!is_bound(&bindings, 43));
        assert!(!is_bound(&[], 42));
    }

    /// The request's quality profile decides the session's policy, once, at the request: the
    /// server's when it validates, the fallback when it is absent or refused — and a refused profile
    /// costs only itself, not the request (a parsed request; JSON serde cannot hold at all fails
    /// the whole message, see `ServerToAgent::SessionRequest::quality_profile`).
    #[tokio::test]
    async fn a_session_request_carries_its_quality_profile_into_pending() {
        use crate::quality_policy::{FallbackReason, QualityPolicy, FALLBACK_LABEL};
        use afklink_protocol::metrics::QualityProfileSource;

        let (mut agent, tx, _rx) = harness();
        lock(&agent.state).bindings.push(BindingInfo {
            telegram_user_id: 42,
            username: None,
            first_name: None,
            role: None,
        });
        let vector: serde_json::Value =
            serde_json::from_str(
                &std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
                    "../../contract/packages/protocol/vectors/quality-profile-reference.json",
                ))
                .expect("the contract's reference vector"),
            )
            .expect("JSON");
        let mut tuned = vector.clone();
        tuned["v"] = serde_json::json!(2);
        tuned["values"]["down_after_ms"] = serde_json::json!(2_500);
        let mut broken = vector;
        broken["values"]["ladder"] = serde_json::json!([]);
        for (id, profile) in [
            ("absent", None),
            ("tuned", Some(tuned)),
            ("broken", Some(broken)),
        ] {
            let ServerToAgent::SessionRequest {
                session_id,
                telegram_user_id,
                username,
                turn,
                ..
            } = session_request(id, 42)
            else {
                unreachable!("a session_request");
            };
            agent
                .handle_server_msg(
                    ServerToAgent::SessionRequest {
                        session_id,
                        telegram_user_id,
                        username,
                        turn,
                        quality_profile: profile,
                    },
                    &tx,
                )
                .await;
        }
        let policy = |id: &str| agent.pending.get(id).expect("accepted").policy.clone();
        let absent = policy("absent");
        assert_eq!(absent.source, QualityProfileSource::Fallback);
        assert_eq!(absent.reason, Some(FallbackReason::Absent));
        assert_eq!(absent.label, FALLBACK_LABEL);
        let tuned = policy("tuned");
        assert_eq!(tuned.source, QualityProfileSource::Server);
        assert_eq!(tuned.label, "default.v2");
        assert_eq!(tuned.policy.down_after_ms, 2_500);
        let broken = policy("broken");
        assert_eq!(broken.source, QualityProfileSource::Fallback);
        assert_eq!(broken.reason, Some(FallbackReason::Invalid));
        assert_eq!(*broken.policy, QualityPolicy::fallback());
    }

    /// The contract's reference profile, as the server would send it.
    fn reference_profile() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contract/packages/protocol/vectors/quality-profile-reference.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("the reference vector"))
            .expect("JSON")
    }

    /// A profile on a request the agent refuses — a viewer with no binding, or connections paused
    /// on this PC — is not even read: no `Pending`, no `quality profile` line.
    #[tokio::test]
    async fn a_refused_request_never_reads_its_profile() {
        let (mut agent, tx, _rx) = harness();
        let with_profile = |id: &str| {
            let ServerToAgent::SessionRequest {
                session_id,
                telegram_user_id,
                username,
                turn,
                ..
            } = session_request(id, 42)
            else {
                unreachable!("a session_request");
            };
            ServerToAgent::SessionRequest {
                session_id,
                telegram_user_id,
                username,
                turn,
                quality_profile: Some(reference_profile()),
            }
        };
        let log = crate::quality_policy::log_capture::start();
        // No binding yet: unbound.
        agent.handle_server_msg(with_profile("unbound"), &tx).await;
        lock(&agent.state).bindings.push(BindingInfo {
            telegram_user_id: 42,
            username: None,
            first_name: None,
            role: None,
        });
        lock(&agent.state).paused = true;
        agent.handle_server_msg(with_profile("paused"), &tx).await;
        assert!(agent.pending.is_empty());
        let text = log.text();
        assert!(text.contains("from unbound user"), "{text}");
        assert!(text.contains("connections are paused"), "{text}");
        assert!(!text.contains("quality profile"), "{text}");
    }

    /// The server's profile is what a session opens on: a later start rung opens there, at that
    /// rung's price — what `start_session` hands the target, the summary's lowest height and the
    /// encoder — and the summary names the profile.
    #[test]
    fn a_profiles_start_rung_is_what_the_session_opens_on() {
        use crate::quality_policy::{QualityPolicy, SessionPolicy};
        let quality = crate::quality::Quality::default();
        let mut raw = reference_profile();
        raw["v"] = serde_json::json!(7);
        raw["values"]["start_rung_index"] = serde_json::json!(2);
        let server = SessionPolicy::for_session("s", Some(&raw));
        assert_eq!(server.label, "default.v7");

        // Against the profile it was made from (the reference, which opens at its top).
        let reference = session_opening(&QualityPolicy::reference(), quality);
        let opening = session_opening(&server.policy, quality);
        assert_eq!(reference.start, QualityPolicy::reference().ladder[0]);
        assert_eq!(opening.start, server.policy.ladder[2]);
        assert_ne!(opening.start, reference.start);
        assert_eq!(
            opening.target_kbps,
            opening
                .start
                .required_kbps_with(&server.policy, 1920, 1080, quality)
        );
        assert!(
            opening.target_kbps < reference.target_kbps,
            "{opening:?} against {reference:?}"
        );

        let summary = crate::summary::SessionSummary::new(
            "s",
            Instant::now(),
            None,
            None,
            crate::traits::InputReach::default(),
        )
        .with_quality_profile(&server.label, server.source);
        let out = summary.snapshot(Instant::now(), &SessionCounters::default());
        assert_eq!(out.quality_profile.as_deref(), Some("default.v7"));
        assert_eq!(
            out.quality_profile_source,
            Some(afklink_protocol::metrics::QualityProfileSource::Server)
        );
    }

    /// A `SessionRequest` from a user with no binding must not capture
    /// anything: no `pending` entry, and the backend is told to end the
    /// attempt so the viewer does not hang. A bound user is accepted, and an
    /// unbind sweeps even the not-yet-answered request.
    #[tokio::test]
    async fn session_request_requires_a_binding() {
        let (mut agent, tx, mut rx) = harness();

        agent
            .handle_server_msg(session_request("s1", 42), &tx)
            .await;
        assert!(
            agent.pending.is_empty(),
            "unbound request must not be captured"
        );
        match rx.try_recv().expect("backend must be told to end it") {
            AgentToServer::SessionEnd {
                session_id,
                reason,
                detail,
            } => {
                assert_eq!(session_id, "s1");
                assert_eq!(reason.as_deref(), Some("unbound"));
                assert_eq!(detail, None, "no peer, no path to tell of");
            }
            other => panic!("unexpected message for unbound request: {other:?}"),
        }

        lock(&agent.state).bindings.push(BindingInfo {
            telegram_user_id: 42,
            username: None,
            first_name: None,
            role: None,
        });
        agent
            .handle_server_msg(session_request("s2", 42), &tx)
            .await;
        assert!(agent.pending.contains_key("s2"));
        assert!(
            rx.try_recv().is_err(),
            "an accepted request is answered silently"
        );

        agent
            .handle_server_msg(
                ServerToAgent::BindingRemoved {
                    telegram_user_id: 42,
                },
                &tx,
            )
            .await;
        assert!(
            agent.pending.is_empty(),
            "unbind must sweep unanswered requests"
        );
    }

    /// The kill switch ends every session and every unanswered request, and pauses: a new request
    /// from a bound user is refused with `paused_on_pc` until the owner resumes, and accepted after.
    #[tokio::test]
    async fn the_kill_switch_pauses_connections_until_the_owner_resumes() {
        let (mut agent, tx, mut rx) = harness();
        let mut events = agent.events.subscribe();
        lock(&agent.state).bindings.push(BindingInfo {
            telegram_user_id: 42,
            username: None,
            first_name: None,
            role: None,
        });
        let peer = live_session(&mut agent, "s1");
        agent
            .handle_server_msg(session_request("s2", 42), &tx)
            .await;
        assert!(agent.pending.contains_key("s2"));

        agent.handle_command(AgentCommand::KillSwitch, &tx).await;
        assert!(lock(&agent.state).paused);
        assert!(agent.sessions.is_empty());
        assert!(agent.pending.is_empty(), "an unanswered request ends too");
        assert!(peer.close.is_asked());
        let mut ends = Vec::new();
        let mut finals = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            match msg {
                AgentToServer::SessionEnd {
                    session_id, reason, ..
                } => ends.push((session_id, reason)),
                AgentToServer::SessionStats {
                    session_id,
                    is_final: true,
                    ..
                } => finals.push(session_id),
                _ => {}
            }
        }
        ends.sort();
        assert_eq!(
            ends,
            [
                ("s1".to_string(), Some("kill_switch".to_string())),
                ("s2".to_string(), Some("kill_switch".to_string())),
            ]
        );
        assert_eq!(
            finals,
            ["s1"],
            "the live session's final report; the request had none to give"
        );

        // Paused: a bound user's request is refused, and nothing waits for its offer.
        agent
            .handle_server_msg(session_request("s3", 42), &tx)
            .await;
        assert!(agent.pending.is_empty());
        match rx.try_recv().expect("the backend is told") {
            AgentToServer::SessionEnd {
                session_id, reason, ..
            } => {
                assert_eq!(session_id, "s3");
                assert_eq!(reason.as_deref(), Some("paused_on_pc"));
            }
            other => panic!("unexpected message for a request while paused: {other:?}"),
        }
        let mut seen = Vec::new();
        while let Ok(ev) = events.try_recv() {
            seen.push(ev);
        }
        assert!(
            seen.contains(&AgentEvent::SessionEnded {
                session_id: "s3".into(),
                reason: end_reason::PAUSED_ON_PC.into(),
            }),
            "{seen:?}"
        );

        // Resumed: the next request waits for its offer as usual.
        agent.handle_command(AgentCommand::Resume, &tx).await;
        assert!(!lock(&agent.state).paused);
        agent
            .handle_server_msg(session_request("s4", 42), &tx)
            .await;
        assert!(agent.pending.contains_key("s4"));
        assert!(rx.try_recv().is_err(), "accepted silently");
    }

    /// The pause is kept in config.json — a restart (or the new version an update starts) is
    /// paused from its first moment and refuses a bound user's request with `paused_on_pc`; only
    /// «Возобновить» takes it out of the file.
    #[tokio::test]
    async fn the_pause_outlives_a_restart_until_the_owner_resumes() {
        let bound = || BindingInfo {
            telegram_user_id: 42,
            username: None,
            first_name: None,
            role: None,
        };
        let (mut agent, control) = test_agent(None);
        let (tx, _rx) = mpsc::unbounded_channel();
        let path = lock(&control.config).path().expect("a file").to_path_buf();
        assert!(!lock(&control.state).paused);
        agent.handle_command(AgentCommand::KillSwitch, &tx).await;
        assert!(lock(&control.state).paused, "in force at once");
        // Written on the blocking pool, after the teardown.
        assert!(agent.pause_save.is_some(), "handed to the blocking pool");
        agent.pause_saved().await;
        assert!(lock(&control.config).paused, "in the shared config");
        let on_disk = Config::load_or_create_at(path.clone()).expect("reloads");
        assert!(on_disk.paused, "and on disk");
        // A second press changes nothing on disk (and writes nothing: logged as so).
        agent.handle_command(AgentCommand::KillSwitch, &tx).await;
        agent.pause_saved().await;
        // A pause and a resume in quick succession, the writes in whatever order the pool takes
        // them: the file ends as the state.
        agent.handle_command(AgentCommand::Resume, &tx).await;
        let resumed = agent.pause_save.take();
        agent.handle_command(AgentCommand::KillSwitch, &tx).await;
        agent.pause_saved().await;
        if let Some(write) = resumed {
            write.await.expect("the resume's write");
        }
        assert!(
            Config::load_or_create_at(path.clone())
                .expect("reloads")
                .paused,
            "paused, as the state is"
        );
        drop(agent);

        // The next run — the same config.json, as after a restart or an update.
        let identity = Arc::new(
            Identity::load_or_create_at(path.with_file_name("identity.json")).expect("identity"),
        );
        let backends = Backends {
            make_capturer: Box::new(|| Err(anyhow::anyhow!("no capturer in test"))),
            make_game_capturer: Box::new(|_| Err(anyhow::anyhow!("no game capturer in test"))),
            make_encoder: Box::new(|| Err(anyhow::anyhow!("no encoder in test"))),
            injector: Arc::new(NoopInjector),
        };
        let (mut next, control) = Agent::new(on_disk, identity, backends);
        assert!(
            lock(&control.state).paused,
            "paused before the first connection"
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        lock(&next.state).bindings.push(bound());
        next.handle_server_msg(session_request("s1", 42), &tx).await;
        assert!(next.pending.is_empty(), "nothing waits for an offer");
        match rx.try_recv().expect("the backend is told") {
            AgentToServer::SessionEnd {
                session_id, reason, ..
            } => {
                assert_eq!(session_id, "s1");
                assert_eq!(reason.as_deref(), Some(end_reason::PAUSED_ON_PC));
            }
            other => panic!("unexpected message for a request after the restart: {other:?}"),
        }

        // «Возобновить»: accepted again, and the file does not pause the next start.
        next.handle_command(AgentCommand::Resume, &tx).await;
        next.pause_saved().await;
        assert!(!lock(&control.state).paused);
        assert!(!lock(&control.config).paused);
        assert!(
            !Config::load_or_create_at(path).expect("reloads").paused,
            "the next start is not paused"
        );
        next.handle_server_msg(session_request("s2", 42), &tx).await;
        assert!(next.pending.contains_key("s2"));
    }

    fn pairing_code(code: &str, bot: Option<&str>, app: Option<&str>) -> ServerToAgent {
        ServerToAgent::PairingCode {
            code: code.into(),
            expires_at: 0,
            bot_username: bot.map(str::to_string),
            miniapp_short_name: app.map(str::to_string),
        }
    }

    /// The pairing link points at the bot the backend names, a config.json override wins, and with
    /// neither there is no link at all — never one to the placeholder `YourBot`.
    #[tokio::test]
    async fn the_pairing_link_follows_the_backend_and_is_never_a_placeholder() {
        let (mut agent, control) = test_agent(None);
        let (tx, _rx) = mpsc::unbounded_channel();
        // The owner opens the pairing panel: the codes below are for it.
        agent
            .handle_command(AgentCommand::RequestPairing, &tx)
            .await;

        // An older backend, and nothing in config.json (the owner's `bot_username: null`).
        agent
            .handle_server_msg(pairing_code("568048", None, None), &tx)
            .await;
        assert_eq!(
            lock(&control.state).pairing_code.as_deref(),
            Some("568048"),
            "the code is still shown"
        );
        assert_eq!(control.deep_link(), None, "no bot known: no link");

        // A backend that names its bot.
        agent
            .handle_server_msg(
                pairing_code("123456", Some("afklink_bot"), Some("app")),
                &tx,
            )
            .await;
        assert_eq!(
            control.deep_link().as_deref(),
            Some("https://t.me/afklink_bot/app?startapp=123456")
        );

        // A developer's override in config.json wins over the backend's value.
        lock(&control.config).bot_username = Some("dev_bot".into());
        agent
            .handle_server_msg(
                pairing_code("000123", Some("afklink_bot"), Some("app")),
                &tx,
            )
            .await;
        assert_eq!(
            control.deep_link().as_deref(),
            Some("https://t.me/dev_bot/app?startapp=000123")
        );

        // The panel closes: no code, so no link either.
        agent.handle_command(AgentCommand::CancelPairing, &tx).await;
        assert_eq!(control.deep_link(), None);
    }

    /// An offer with no preceding `SessionRequest` is refused before any peer
    /// or capture exists — and, critically, nothing is registered under a
    /// fabricated owner: a `uid = 0` fallback would lie to the UI about who
    /// is watching.
    #[tokio::test]
    async fn offer_without_request_is_refused() {
        let (mut agent, tx, mut rx) = harness();

        agent
            .start_session("ghost".into(), "not-an-offer".into(), &tx)
            .await;
        assert!(agent.sessions.is_empty());
        assert!(lock(&agent.state).sessions.is_empty());
        match rx.try_recv().expect("backend must be told to end it") {
            AgentToServer::SessionEnd {
                session_id, reason, ..
            } => {
                assert_eq!(session_id, "ghost");
                assert_eq!(reason.as_deref(), Some("no_session_request"));
            }
            other => panic!("unexpected message for stray offer: {other:?}"),
        }
    }

    struct NoopCapturer;
    impl Capturer for NoopCapturer {
        fn start(
            &mut self,
            _sink: std::sync::mpsc::Sender<Frame>,
            _target: Arc<crate::quality::QualityTarget>,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        fn stop(&mut self) {}
    }

    /// What a test sees of a session's peer: its signal queue — the real one, as deep as a peer's —
    /// and its close signal.
    struct FakePeer {
        signals: transport::SignalReceiver,
        close: afklink_transport::CloseSignal,
    }

    /// A running session whose peer is the returned [`FakePeer`], as `start_session` leaves it.
    fn live_session(agent: &mut Agent, id: &str) -> FakePeer {
        let (signal_tx, signals) = transport::signal_queue();
        let (closer, close) = PeerCloser::new();
        let bindings = lock(&agent.state).bindings.clone();
        let capture_mode = agent.game_access.open(id, 42, &bindings);
        agent.sessions.insert(
            id.into(),
            Session {
                telegram_user_id: 42,
                username: None,
                signals: signal_tx,
                closer,
                capturer: Arc::new(Mutex::new(Box::new(NoopCapturer) as Box<dyn Capturer>)),
                stop: Arc::new(AtomicBool::new(false)),
                input: Arc::new(InputSession::new(agent.backends.injector.clone())),
                stats: StatsSource::new(
                    Arc::new(SessionCounters::default()),
                    Arc::new(crate::quality::QualityTarget::default()),
                    no_hold(),
                ),
                reach_start: crate::traits::InputReach::default(),
                capture_mode,
                path: Arc::new(transport::PeerPathCell::default()),
            },
        );
        lock(&agent.state).sessions.push(SessionInfo {
            session_id: id.into(),
            telegram_user_id: 42,
            username: None,
            first_name: None,
            connected: true,
            connected_at: Some(Instant::now()),
        });
        FakePeer { signals, close }
    }

    /// An injector that counts its full releases.
    #[derive(Default)]
    struct CountingInjector {
        releases: AtomicU32,
    }
    impl InputInjector for CountingInjector {
        fn inject(&self, _event: &InputMessage) -> anyhow::Result<()> {
            Ok(())
        }
        fn release_all(&self) {
            self.releases.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The orchestrator's future dropped by a panic — as the runtime drops a panicked task's —
    /// ends the sessions it never ended: the peer is told to close, the encode thread to stop, the
    /// input refused and what it holds released (on a thread of its own). Every wait bounded.
    #[test]
    fn an_orchestrator_that_panics_ends_its_live_sessions() {
        let (mut agent, _tx, _rx) = harness();
        let injector = Arc::new(CountingInjector::default());
        Arc::get_mut(&mut agent.backends)
            .expect("the backends are the agent's alone")
            .injector = Arc::clone(&injector) as Arc<dyn InputInjector>;
        let peer = live_session(&mut agent, "s1");
        let (stop, input) = {
            let session = &agent.sessions["s1"];
            (Arc::clone(&session.stop), Arc::clone(&session.input))
        };
        // A button down: the session holds something to release.
        assert!(input
            .inject(&InputMessage::Down { b: 0 })
            .expect("injected"));
        assert!(!peer.close.is_asked() && input.is_active());

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let task = rt.spawn(async move {
            let _orchestrator = agent;
            if std::hint::black_box(true) {
                panic!("the orchestrator panics (a test)");
            }
        });
        let joined = rt
            .block_on(async { tokio::time::timeout(Duration::from_secs(10), task).await })
            .expect("the task ended in time");
        assert!(joined.expect_err("it panicked").is_panic());

        assert!(peer.close.is_asked(), "the peer is told to close");
        assert!(
            stop.load(Ordering::SeqCst),
            "the encode thread is told to stop"
        );
        assert!(!input.is_active(), "the input is refused");
        let deadline = Instant::now() + Duration::from_secs(10);
        while injector.releases.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "what the session held was never released"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        rt.shutdown_timeout(Duration::from_secs(1));
    }

    /// The level of the first line of `logs` that says `what`.
    fn level_of<'a>(logs: &'a str, what: &str) -> Option<&'a str> {
        let line = logs.lines().find(|line| line.contains(what))?;
        ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"]
            .into_iter()
            .find(|level| line.contains(level))
    }

    /// An orchestrator that ends as asked (the exit's request, nothing left to command it)
    /// with sessions live ends them all the same, said at `debug`; one that ends without saying so
    /// (an error, a drop) at `warn`.
    #[test]
    fn live_sessions_at_an_ordinary_end_are_ended_without_a_warning() {
        for asked in [Some("the exit asked for the sessions' end"), None] {
            let (mut agent, _tx, _rx) = harness();
            let _peer = live_session(&mut agent, "s1");
            let stop = Arc::clone(&agent.sessions["s1"].stop);
            if let Some(why) = asked {
                agent.sessions.ends_as_asked(why);
            }
            let logs = LogCapture::start();
            drop(agent);
            let said = logs.text();
            drop(logs);
            assert!(stop.load(Ordering::SeqCst), "ended either way ({asked:?})");
            match asked {
                Some(_) => {
                    assert_eq!(
                        level_of(&said, "the orchestrator ended as asked with sessions live"),
                        Some("DEBUG"),
                        "{said}"
                    );
                    assert!(!said.contains("WARN"), "{said}");
                }
                None => assert_eq!(
                    level_of(&said, "the orchestrator ended with sessions live"),
                    Some("WARN"),
                    "{said}"
                ),
            }
        }
    }

    /// A session start that panics between its input's opening and its registration leaves
    /// no open input behind: refused, closed (the driver's session count balanced) on a thread of
    /// its own. Every wait bounded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_start_that_panics_before_its_registration_closes_its_input() {
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        agent.panic_before_register = true;
        let (tx, _rx) = mpsc::unbounded_channel();
        let started = tokio::spawn(async move {
            let _ends = start_b(&mut agent, &tx).await;
        });
        let joined = tokio::time::timeout(Duration::from_secs(10), started)
            .await
            .expect("the start ended in time");
        assert!(joined.expect_err("it panicked").is_panic());
        assert_eq!(slot.begun.load(Ordering::SeqCst), 1, "B's input opened");
        wait_on_thread("B's input to be closed", || {
            slot.ended.load(Ordering::SeqCst) == 1
        });
    }

    /// A viewer's offer starts a session, which may take its setup's limit: that and a margin
    /// is its step's budget, under the stall watch's 30 s error (an automatic report); any other
    /// message has none.
    #[test]
    fn a_session_start_is_the_one_step_with_a_budget() {
        let limit = crate::offload::START_LIMIT;
        assert_eq!(step_budget(&offer("s1", "v=0"), limit), START_STEP_BUDGET);
        assert_eq!(START_STEP_BUDGET, Duration::from_secs(15));
        assert!(START_STEP_BUDGET < Duration::from_secs(30));
        let answer = ServerToAgent::Sdp {
            session_id: "s1".into(),
            sdp_type: SdpType::Answer,
            sdp: "v=0".into(),
        };
        assert_eq!(step_budget(&answer, limit), Duration::ZERO);
        assert_eq!(
            step_budget(&session_request("s1", 42), limit),
            Duration::ZERO
        );
    }

    /// The pause written from a thread of its own, whatever the config in memory says (a save
    /// that failed left the memory paused and the file not); nothing to do when not paused.
    #[test]
    fn the_pause_is_kept_on_disk_from_a_thread_of_its_own() {
        let (_agent, control) = test_agent(None);
        let path = lock(&control.config)
            .path()
            .expect("the test config has a file")
            .to_path_buf();
        assert_eq!(control.keep_pause_blocking("a test"), PauseKept::NotPaused);
        assert!(
            !Config::load_or_create_at(path.clone())
                .expect("reloads")
                .paused
        );
        // The kill switch's state, its save lost: memory paused, the file not.
        lock(&control.state).paused = true;
        lock(&control.config).paused = true;
        assert!(
            !Config::load_or_create_at(path.clone())
                .expect("reloads")
                .paused
        );
        assert_eq!(control.keep_pause_blocking("a test"), PauseKept::Saved);
        assert!(
            Config::load_or_create_at(path).expect("reloads").paused,
            "the next start is paused"
        );
    }

    /// The stall watch's view of the orchestrator (`crate::step_watch`): a command stuck in its
    /// handling — a synchronous wait on the config's lock, as a stuck save would leave it — is
    /// named, what and kind, for as long as it lasts, and gone once it ends. Through the real
    /// signaling client and `serve`; the test waits with the thread's own sleeps, never the
    /// runtime's timers (a worker blocked in a task stops them). Every wait bounded.
    #[test]
    fn a_command_stuck_in_its_handling_is_named_by_the_step_watch() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("bind");
        let url = format!("ws://{}/ws/agent", listener.local_addr().expect("addr"));
        let (agent, control) = test_agent(Some(url));
        let steps = agent.step_watch();
        let running = rt.spawn(agent.run());
        let ws = rt.block_on(accept_agent(&listener));
        let until = |what: &str, done: &dyn Fn() -> bool| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !done() {
                assert!(Instant::now() < deadline, "timed out waiting for {what}");
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        until("the link", &|| lock(&control.state).connected);

        let held = lock(&control.config);
        control
            .commands
            .send(AgentCommand::SetName("Офис".into()))
            .expect("the orchestrator takes commands");
        until("the stuck command's step", &|| {
            steps
                .current()
                .is_some_and(|s| s.what == "command" && s.kind == "set_name")
        });
        let stuck = steps.current().expect("the step");
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            steps.current().map(|s| s.seq),
            Some(stuck.seq),
            "the same step, for as long as it is stuck"
        );
        drop(held);
        until("the step's end", &|| {
            steps.current().is_none_or(|s| s.seq != stuck.seq)
        });
        assert_eq!(
            lock(&control.config).name,
            "Офис",
            "and the command was served"
        );
        running.abort();
        drop(ws);
        rt.shutdown_timeout(Duration::from_secs(1));
    }

    fn offer(session_id: &str, sdp: &str) -> ServerToAgent {
        ServerToAgent::Sdp {
            session_id: session_id.into(),
            sdp_type: SdpType::Offer,
            sdp: sdp.into(),
        }
    }

    /// The agent's own end of a live session: its final report first (`"final": true`), then the
    /// message that follows it — returned.
    fn after_final(rx: &mut mpsc::UnboundedReceiver<AgentToServer>, id: &str) -> AgentToServer {
        match rx.try_recv().expect("the session's final report") {
            AgentToServer::SessionStats {
                session_id,
                is_final: true,
                ..
            } => assert_eq!(session_id, id),
            other => panic!("expected the final report first, got {other:?}"),
        }
        rx.try_recv().expect("then what follows it")
    }

    /// The viewer's ICE restart: a second offer for a session that is already running goes to
    /// that session's peer, and nothing else happens — no second pipeline, nothing to the backend
    /// (the answer comes back from the peer). Dropped as a duplicate, it would cost a phone that
    /// changes networks its session.
    #[tokio::test]
    async fn a_second_offer_for_a_live_session_goes_to_its_peer() {
        let (mut agent, tx, mut rx) = harness();
        let mut peer = live_session(&mut agent, "s1");

        agent
            .handle_server_msg(offer("s1", "v=0 an ice restart"), &tx)
            .await;

        match peer.signals.try_recv() {
            Ok(PeerSignal::Renegotiate(sdp)) => assert_eq!(sdp, "v=0 an ice restart"),
            other => panic!("the re-offer must reach the peer, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "the answer is the peer's to send");
        assert_eq!(agent.sessions.len(), 1, "the same session, not a new one");
        assert!(agent.sessions.contains_key("s1"));
        assert!(!peer.close.is_asked(), "and the peer carries on");
    }

    /// A re-offer the peer cannot take ends the session at once, with a reason, rather than
    /// leaving the viewer waiting on an answer until its own recovery deadline.
    #[tokio::test]
    async fn a_re_offer_the_peer_cannot_take_ends_the_session() {
        let (mut agent, tx, mut rx) = harness();
        // The signal queue gone, as a peer that has ended leaves it.
        let FakePeer { signals, close } = live_session(&mut agent, "s1");
        drop(signals);

        agent.handle_server_msg(offer("s1", "v=0"), &tx).await;

        assert!(agent.sessions.is_empty());
        assert!(lock(&agent.state).sessions.is_empty());
        match after_final(&mut rx, "s1") {
            AgentToServer::SessionEnd {
                session_id,
                reason,
                detail,
            } => {
                assert_eq!(session_id, "s1");
                assert_eq!(reason.as_deref(), Some("ice_restart_failed"));
                let detail = detail.expect("the peer's path");
                assert_eq!(detail.ended_detail, None, "not a peer_closed");
                assert_eq!(detail.stage.as_deref(), Some("new"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(close.is_asked(), "the peer is closed with the session");
    }

    /// The tray's and the window's timer counts from the viewer's connect: set by the first
    /// `Connected` signal, and a repeated one does not restart it.
    #[tokio::test]
    async fn the_connect_starts_the_viewers_timer_once() {
        let (mut agent, tx, _rx) = harness();
        let _peer = live_session(&mut agent, "s1");
        {
            let mut s = lock(&agent.state);
            s.sessions[0].connected = false;
            s.sessions[0].connected_at = None;
        }

        agent.handle_session_signal(SessionSignal::Connected("s1".into()), &tx);
        let first = {
            let s = lock(&agent.state);
            assert!(s.sessions[0].connected);
            s.sessions[0]
                .connected_at
                .expect("the connect starts the timer")
        };

        agent.handle_session_signal(SessionSignal::Connected("s1".into()), &tx);
        assert_eq!(
            lock(&agent.state).sessions[0].connected_at,
            Some(first),
            "a second signal keeps the first start"
        );
    }

    /// The game helper may act for a session only from its connect — str0m's `Connected`, the
    /// viewer receiving — not from its request (an attempt that never connected must not let it
    /// launch the game).
    #[tokio::test]
    async fn the_game_helper_counts_a_session_from_its_connect() {
        let (mut agent, tx, _rx) = harness();
        agent.game_access.set_policy(
            crate::game_access::GamePolicy {
                game_only: true,
                for_guests: false,
                binding: None,
            },
            "test: game-only on",
        );
        let bindings = lock(&agent.state).bindings.clone();
        let _cell = agent.game_access.open("s1", 42, &bindings);
        let seen = agent.game_access.helper_sessions();
        assert!(seen.game_only.is_empty(), "{seen:?}");
        assert_eq!(seen.game_only_connecting, ["s1"]);
        agent.handle_session_signal(SessionSignal::Connected("s1".into()), &tx);
        assert_eq!(agent.game_access.game_only_sessions(), ["s1"]);
    }

    /// A peer that ends reports why, and that is the session's end reason: a grace window that ran
    /// out is `ice_timeout`, not a blanket `peer_closed`.
    #[tokio::test]
    async fn a_peer_that_gave_up_on_its_path_ends_the_session_as_ice_timeout() {
        let (mut agent, tx, mut rx) = harness();
        let peer = live_session(&mut agent, "s1");

        agent.handle_session_signal(
            SessionSignal::Closed {
                id: "s1".into(),
                end: transport::PeerEnd::IceTimeout,
            },
            &tx,
        );

        assert!(agent.sessions.is_empty());
        match after_final(&mut rx, "s1") {
            AgentToServer::SessionEnd {
                session_id, reason, ..
            } => {
                assert_eq!(session_id, "s1");
                assert_eq!(reason.as_deref(), Some("ice_timeout"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(peer.close.is_asked());
    }

    /// A running session with its journal entry open, as the viewer's first connect leaves it.
    fn journaled_session(
        agent: &mut Agent,
        id: &str,
        tx: &mpsc::UnboundedSender<AgentToServer>,
    ) -> FakePeer {
        let peer = live_session(agent, id);
        {
            let mut s = lock(&agent.state);
            let info = s
                .sessions
                .iter_mut()
                .find(|x| x.session_id == id)
                .expect("listed");
            info.connected = false;
            info.connected_at = None;
        }
        agent.handle_session_signal(SessionSignal::Connected(id.into()), tx);
        peer
    }

    fn with_journal(agent: Agent) -> (Agent, Arc<crate::journal::Journal>) {
        let journal = Arc::new(crate::journal::Journal::open(
            None,
            crate::journal::now_ms(),
        ));
        (agent.with_journal(journal.clone()), journal)
    }

    /// «Отключиться» on the iPhone: the viewer's goodbye can end the peer 0.1 s before the backend
    /// relays its `viewer_closed`, and the journal must not say «Связь потеряна». The entry is an
    /// ordinary end at once and takes the viewer's reason when it comes; the session is torn down
    /// at once all the same, and the backend is told `peer_closed`.
    #[tokio::test]
    async fn the_viewers_goodbye_before_its_reason_is_an_ordinary_end_in_the_journal() {
        use crate::journal::VIEWER_LEFT;
        let (agent, tx, mut rx) = harness();
        let (mut agent, journal) = with_journal(agent);
        let peer = journaled_session(&mut agent, "s1", &tx);
        assert!(journal.last().is_some_and(|v| v.live));

        agent.handle_session_signal(
            SessionSignal::Closed {
                id: "s1".into(),
                end: transport::PeerEnd::ViewerClosed,
            },
            &tx,
        );
        assert!(agent.sessions.is_empty(), "the teardown waits for nothing");
        assert!(peer.close.is_asked());
        match after_final(&mut rx, "s1") {
            AgentToServer::SessionEnd { reason, detail, .. } => {
                assert_eq!(
                    reason.as_deref(),
                    Some("peer_closed"),
                    "the reason is unchanged"
                );
                assert_eq!(
                    detail.and_then(|d| d.ended_detail).as_deref(),
                    Some("viewer"),
                    "the detail says the viewer said goodbye"
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
        let e = journal.last().expect("entry");
        assert!(!e.live);
        assert_eq!(e.entry.reason.as_deref(), Some(VIEWER_LEFT));
        assert_eq!(
            e.ending, None,
            "no «Связь потеряна» for the viewer's own goodbye"
        );

        agent
            .handle_server_msg(
                ServerToAgent::SessionEnd {
                    session_id: "s1".into(),
                    reason: Some("viewer_closed".into()),
                },
                &tx,
            )
            .await;
        let e = journal.last().expect("entry");
        assert_eq!(e.entry.reason.as_deref(), Some("viewer_closed"));
        assert_eq!(e.ending, None);
    }

    /// A peer closed with no goodbye from the viewer is «Связь потеряна» unless the backend says in
    /// time why the viewer ended it; a link ICE gave up on stays lost whatever comes after.
    #[tokio::test]
    async fn a_peer_end_without_a_goodbye_is_lost_unless_the_backend_explains_it() {
        use crate::journal::Ending;
        let (agent, tx, _rx) = harness();
        let (mut agent, journal) = with_journal(agent);

        let _p1 = journaled_session(&mut agent, "s1", &tx);
        agent.handle_session_signal(
            SessionSignal::Closed {
                id: "s1".into(),
                end: transport::PeerEnd::RtcClosed,
            },
            &tx,
        );
        assert_eq!(journal.last().and_then(|v| v.ending), Some(Ending::Lost));
        agent
            .handle_server_msg(
                ServerToAgent::SessionEnd {
                    session_id: "s1".into(),
                    reason: Some("viewer_ended".into()),
                },
                &tx,
            )
            .await;
        let e = journal.last().expect("entry");
        assert_eq!(e.entry.reason.as_deref(), Some("viewer_ended"));
        assert_eq!(e.ending, None);

        let _p2 = journaled_session(&mut agent, "s2", &tx);
        agent.handle_session_signal(
            SessionSignal::Closed {
                id: "s2".into(),
                end: transport::PeerEnd::IceTimeout,
            },
            &tx,
        );
        agent
            .handle_server_msg(
                ServerToAgent::SessionEnd {
                    session_id: "s2".into(),
                    reason: Some("viewer_closed".into()),
                },
                &tx,
            )
            .await;
        let e = journal
            .entries()
            .into_iter()
            .find(|v| v.entry.id == "s2")
            .expect("s2");
        assert_eq!(e.entry.reason.as_deref(), Some("ice_timeout"));
        assert_eq!(e.ending, Some(Ending::Lost));
    }

    /// A viewer that really left says so, and the session ends then — the grace window is the
    /// peer's, and nothing waits for it.
    #[tokio::test]
    async fn a_viewer_end_during_the_grace_window_ends_the_session_at_once() {
        let (mut agent, tx, _rx) = harness();
        let peer = live_session(&mut agent, "s1");

        agent
            .handle_server_msg(
                ServerToAgent::SessionEnd {
                    session_id: "s1".into(),
                    reason: Some("viewer_media_stalled".into()),
                },
                &tx,
            )
            .await;

        assert!(agent.sessions.is_empty());
        assert!(
            peer.close.is_asked(),
            "the peer is closed now, whatever its ICE state"
        );
    }

    /// Ending a session closes its peer even when the queue the orchestrator writes to is full —
    /// the case where a close sent as a control message would be refused, leaving the peer running
    /// until ICE gave up. That queue is the peer's signal queue (the control queue is the
    /// session's tasks'; `a_close_is_heard_through_a_full_control_queue` in the transport fills that
    /// one): filled to its cap here.
    #[tokio::test]
    async fn ending_a_session_closes_its_peer_through_a_full_signal_queue() {
        let (mut agent, tx, mut rx) = harness();
        let peer = live_session(&mut agent, "s1");
        let signals = agent.sessions["s1"].signals.clone();
        while matches!(
            signals.send(PeerSignal::AddRemoteIce(relay_candidate(1))),
            SignalSent::Queued { .. }
        ) {}
        assert_eq!(
            usize::try_from(signals.depth()).expect("small"),
            transport::SIGNAL_QUEUE_CAP,
            "the queue is full"
        );

        agent.handle_session_signal(
            SessionSignal::PipelineFailed {
                id: "s1".into(),
                reason: "capture_lost",
            },
            &tx,
        );

        assert!(agent.sessions.is_empty());
        assert!(
            peer.close.is_asked(),
            "a full queue cannot refuse the close"
        );
        assert!(matches!(
            after_final(&mut rx, "s1"),
            AgentToServer::SessionEnd { reason: Some(r), .. } if r == "capture_lost"
        ));
    }

    /// A candidate of the viewer's as the Mini App trickles it: a TURN relay it reaches over TCP
    /// (priority 16785663), on a port of its own so the order can be read back.
    fn relay_candidate(port: u16) -> afklink_protocol::IceCandidate {
        afklink_protocol::IceCandidate {
            candidate: format!(
                "candidate:3 1 udp 16785663 203.0.113.9 {port} typ relay raddr 0.0.0.0 rport 0"
            ),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: Some("abcd".into()),
        }
    }

    fn ice(session_id: &str, port: u16) -> ServerToAgent {
        ServerToAgent::Ice {
            session_id: session_id.into(),
            candidate: relay_candidate(port),
        }
    }

    /// What a peer took off its signal queue: a candidate's port, or an offer's SDP.
    fn taken(signal: PeerSignal) -> String {
        match signal {
            PeerSignal::AddRemoteIce(c) => c
                .candidate
                .split_whitespace()
                .nth(5)
                .expect("a port")
                .to_string(),
            PeerSignal::Renegotiate(sdp) => sdp,
        }
    }

    /// A recorded case: the answer waited out its STUN budget, the viewer's 26 candidates piled up
    /// in the signaling inbox meanwhile, and the orchestrator handed them over back to back once
    /// the session existed, before the peer had taken any. A bounded control queue would take 16
    /// and drop the last ten — every TCP and TLS relay. Every one reaches the
    /// peer, in order: 40 here, with a restart's offer among them in its place, its candidates
    /// behind it.
    #[tokio::test]
    async fn a_burst_of_candidates_before_the_peer_takes_any_reaches_it_whole_and_in_order() {
        let (mut agent, tx, mut rx) = harness();
        let mut peer = live_session(&mut agent, "s1");
        for port in 1..=26 {
            agent.handle_server_msg(ice("s1", port), &tx).await;
        }
        agent
            .handle_server_msg(offer("s1", "v=0 an ice restart"), &tx)
            .await;
        for port in 27..=40 {
            agent.handle_server_msg(ice("s1", port), &tx).await;
        }
        assert_eq!(
            agent.sessions["s1"].signals.counts(),
            transport::SignalCounts {
                queued: 41,
                taken: 0,
                dropped: 0,
                max_depth: 41,
            },
            "all of them waiting at once, none lost"
        );

        let got: Vec<String> = std::iter::from_fn(|| peer.signals.try_recv().ok())
            .map(taken)
            .collect();
        let expected: Vec<String> = (1..=26)
            .map(|p: u16| p.to_string())
            .chain(["v=0 an ice restart".to_string()])
            .chain((27..=40).map(|p: u16| p.to_string()))
            .collect();
        assert_eq!(got, expected, "whole, and in the order the viewer sent");
        assert_eq!(agent.sessions["s1"].signals.counts().taken, 41);
        assert!(agent.sessions.contains_key("s1"));
        assert!(!peer.close.is_asked());
        assert!(rx.try_recv().is_err(), "nothing to the backend");
    }

    /// Past the cap — a peer that stopped taking, or a viewer flooding it — a candidate is dropped
    /// and counted: nothing waits, nothing panics, the session carries on, and the candidates kept
    /// reach the peer in order. Once the peer takes again, the queue takes candidates again.
    #[tokio::test]
    async fn candidates_past_the_signal_queues_cap_are_dropped_and_counted() {
        let (mut agent, tx, _rx) = harness();
        let mut peer = live_session(&mut agent, "s1");
        let cap = u16::try_from(transport::SIGNAL_QUEUE_CAP).expect("small");
        for port in 1..=cap + 10 {
            agent.handle_server_msg(ice("s1", port), &tx).await;
        }
        let counts = agent.sessions["s1"].signals.counts();
        assert_eq!(
            (
                counts.queued,
                counts.taken,
                counts.dropped,
                counts.max_depth
            ),
            (u32::from(cap), 0, 10, u32::from(cap)),
            "{counts:?}"
        );
        assert!(
            agent.sessions.contains_key("s1"),
            "a dropped candidate does not end the session"
        );
        assert!(!peer.close.is_asked());

        // The peer takes one: there is room again.
        assert_eq!(taken(peer.signals.try_recv().expect("queued")), "1");
        agent.handle_server_msg(ice("s1", 1000), &tx).await;
        let rest: Vec<String> = std::iter::from_fn(|| peer.signals.try_recv().ok())
            .map(taken)
            .collect();
        let expected: Vec<String> = (2..=cap).chain([1000]).map(|p| p.to_string()).collect();
        assert_eq!(
            rest, expected,
            "the kept ones in order, none of the dropped"
        );
        assert_eq!(agent.sessions["s1"].signals.counts().dropped, 10);
    }

    /// A re-offer the full signal queue refuses cannot be answered: the session ends at once, as
    /// for a peer that has ended, rather than leaving the viewer waiting out its recovery deadline.
    #[tokio::test]
    async fn a_re_offer_refused_by_a_full_signal_queue_ends_the_session() {
        let (mut agent, tx, mut rx) = harness();
        let peer = live_session(&mut agent, "s1");
        for port in 1..=u16::try_from(transport::SIGNAL_QUEUE_CAP).expect("small") {
            agent.handle_server_msg(ice("s1", port), &tx).await;
        }
        assert!(rx.try_recv().is_err(), "a full queue alone ends nothing");

        agent.handle_server_msg(offer("s1", "v=0"), &tx).await;

        assert!(agent.sessions.is_empty());
        match after_final(&mut rx, "s1") {
            AgentToServer::SessionEnd { reason, .. } => {
                assert_eq!(reason.as_deref(), Some("ice_restart_failed"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(peer.close.is_asked(), "the peer is closed with the session");
    }

    /// What the CLI's `BENCH` lines are made from: a session's end is announced once, with the
    /// reason the backend is told; a setup that fails is announced with why; a stray second end for
    /// the same session is not.
    #[tokio::test]
    async fn the_session_lifecycle_is_announced_to_subscribers() {
        let (mut agent, tx, _rx) = harness();
        let mut events = agent.events.subscribe();

        // A setup that fails before the session starts: an offer str0m cannot parse.
        lock(&agent.state).bindings.push(BindingInfo {
            telegram_user_id: 42,
            username: None,
            first_name: None,
            role: None,
        });
        agent
            .handle_server_msg(session_request("s0", 42), &tx)
            .await;
        agent
            .handle_server_msg(offer("s0", "not an offer"), &tx)
            .await;
        assert_eq!(
            events.try_recv().expect("a failed setup is announced"),
            AgentEvent::SessionEnded {
                session_id: "s0".into(),
                reason: "peer_error".into()
            }
        );

        let _peer = live_session(&mut agent, "s1");
        agent.handle_session_signal(
            SessionSignal::Closed {
                id: "s1".into(),
                end: transport::PeerEnd::IceTimeout,
            },
            &tx,
        );
        assert_eq!(
            events.try_recv().expect("an end is announced"),
            AgentEvent::SessionEnded {
                session_id: "s1".into(),
                reason: "ice_timeout".into()
            }
        );
        agent.handle_session_signal(
            SessionSignal::Closed {
                id: "s1".into(),
                end: transport::PeerEnd::Closed,
            },
            &tx,
        );
        assert!(
            events.try_recv().is_err(),
            "a second end for a session no longer running is not a second event"
        );
    }

    /// What a session log (`crate::session_log`) is told, in order.
    #[derive(Default)]
    struct RecordedSessionLog(Mutex<Vec<String>>);

    impl SessionLog for RecordedSessionLog {
        fn opened(&self, session_id: &str, telegram_user_id: i64) {
            lock(&self.0).push(format!("opened {session_id} {telegram_user_id}"));
        }
        fn started(&self, session_id: &str) {
            lock(&self.0).push(format!("started {session_id}"));
        }
        fn ended(&self, session_id: &str, reason: &str) {
            lock(&self.0).push(format!("ended {session_id} {reason}"));
        }
        fn finished(&self, session_id: &str) {
            lock(&self.0).push(format!("finished {session_id}"));
        }
    }

    /// The session log hears of each session's life as it happens: a request accepted is opened, a
    /// refused one never is, and every way a request or a session ends ends it — the ends announced
    /// as `SessionEnded` and the ones a request that never started leaves without one (the backend's
    /// end before the offer, an unbind's sweep).
    #[tokio::test]
    async fn the_session_log_hears_every_opening_and_every_end() {
        let (agent, _control) = test_agent(None);
        let log = Arc::new(RecordedSessionLog::default());
        let mut agent = agent.with_session_log(log.clone());
        let (tx, _rx) = mpsc::unbounded_channel();
        let bind = |agent: &Agent| {
            lock(&agent.state).bindings.push(BindingInfo {
                telegram_user_id: 42,
                username: None,
                first_name: None,
                role: None,
            });
        };

        // Unbound: refused, never opened.
        agent
            .handle_server_msg(session_request("refused", 42), &tx)
            .await;
        bind(&agent);
        // The backend ends a request before its offer.
        agent
            .handle_server_msg(session_request("p1", 42), &tx)
            .await;
        agent
            .handle_server_msg(
                ServerToAgent::SessionEnd {
                    session_id: "p1".into(),
                    reason: Some("viewer_closed".into()),
                },
                &tx,
            )
            .await;
        // An unbind sweeps a request.
        agent
            .handle_server_msg(session_request("p2", 42), &tx)
            .await;
        agent
            .handle_server_msg(
                ServerToAgent::BindingRemoved {
                    telegram_user_id: 42,
                },
                &tx,
            )
            .await;
        bind(&agent);
        // A running session ends.
        let _peer = live_session(&mut agent, "s1");
        agent.handle_session_signal(
            SessionSignal::Closed {
                id: "s1".into(),
                end: transport::PeerEnd::IceTimeout,
            },
            &tx,
        );
        // The kill switch ends a request.
        agent
            .handle_server_msg(session_request("p3", 42), &tx)
            .await;
        agent.handle_command(AgentCommand::KillSwitch, &tx).await;
        agent.handle_command(AgentCommand::Resume, &tx).await;
        // A setup that fails: an offer str0m cannot parse.
        agent
            .handle_server_msg(session_request("s0", 42), &tx)
            .await;
        agent
            .handle_server_msg(offer("s0", "not an offer"), &tx)
            .await;

        assert_eq!(
            *lock(&log.0),
            [
                "opened p1 42",
                "ended p1 server_ended",
                "opened p2 42",
                "ended p2 unbound",
                "ended s1 ice_timeout",
                "opened p3 42",
                "ended p3 kill_switch",
                "opened s0 42",
                "ended s0 peer_error",
            ]
        );
    }

    /// On a new connection every live session is named once, with its stats — what re-binds it on
    /// the backend — and a request still waiting for its offer is given up, with the backend and
    /// any subscriber told.
    #[tokio::test]
    async fn a_new_connection_names_every_live_session_and_gives_up_waiting_requests() {
        let (mut agent, tx, mut rx) = harness();
        let mut events = agent.events.subscribe();
        let p1 = live_session(&mut agent, "s1");
        let p2 = live_session(&mut agent, "s2");
        agent.pending.insert(
            "p1".into(),
            Pending {
                telegram_user_id: 42,
                username: None,
                stun_servers: vec![],
                policy: crate::quality_policy::SessionPolicy::fallback(
                    crate::quality_policy::FallbackReason::Absent,
                ),
            },
        );

        agent.announce_after_connect(2, &tx);

        let mut named = Vec::new();
        let mut ended = Vec::new();
        let mut pc_names = 0;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                // Every connection opens with the PC's name.
                AgentToServer::DeviceName { .. } => pc_names += 1,
                AgentToServer::SessionStats {
                    session_id,
                    is_final,
                    ..
                } => {
                    assert!(!is_final, "naming a live session is an ordinary report");
                    named.push(session_id);
                }
                AgentToServer::SessionEnd {
                    session_id, reason, ..
                } => {
                    ended.push((session_id, reason));
                }
                other => panic!("unexpected: {other:?}"),
            }
        }
        assert_eq!(pc_names, 1);
        named.sort();
        assert_eq!(named, ["s1", "s2"], "each live session named once");
        assert_eq!(
            ended,
            [("p1".to_string(), Some("agent_disconnected".to_string()))]
        );
        assert!(agent.pending.is_empty());
        assert_eq!(
            agent.sessions.len(),
            2,
            "naming a session does not touch it"
        );
        assert!(!p1.close.is_asked() && !p2.close.is_asked());
        assert_eq!(
            events
                .try_recv()
                .expect("the given-up request is announced"),
            AgentEvent::SessionEnded {
                session_id: "p1".into(),
                reason: "agent_disconnected".into()
            }
        );
    }

    /// The backend's answer to naming a session it does not have ends the session here, and is not
    /// answered with an end: an end sent back would be answered with another `unknown_session`, and
    /// so on. Only the session's final report goes — the backend keeps an ended session a minute for
    /// it (its tombstone) — and the backend's `unknown_session` to that, if it has forgotten the
    /// session, finds nothing running: nothing more.
    #[tokio::test]
    async fn an_unknown_session_answer_ends_the_session_without_a_reply() {
        let (mut agent, tx, mut rx) = harness();
        let peer = live_session(&mut agent, "s1");
        let unknown = || ServerToAgent::SessionEnd {
            session_id: "s1".into(),
            reason: Some("unknown_session".into()),
        };

        agent.handle_server_msg(unknown(), &tx).await;

        assert!(agent.sessions.is_empty());
        assert!(lock(&agent.state).sessions.is_empty());
        assert!(peer.close.is_asked());
        assert!(
            matches!(
                rx.try_recv(),
                Ok(AgentToServer::SessionStats { ref session_id, is_final: true, .. })
                    if session_id == "s1"
            ),
            "the final report, for the tombstone"
        );
        assert!(rx.try_recv().is_err(), "no session_end goes back");
        agent.handle_server_msg(unknown(), &tx).await;
        assert!(
            rx.try_recv().is_err(),
            "and the answer to the final ends it there"
        );
    }

    /// A test backend's `challenge`: 32 zero bytes, the only length the handshake signs.
    const CHALLENGE_FRAME: &str =
        r#"{"type":"challenge","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;

    /// The next text frame from the agent, as JSON.
    async fn next_frame(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) -> serde_json::Value {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("a frame from the agent in time")
                .expect("the socket is open")
                .expect("a frame");
            if let Message::Text(t) = frame {
                return serde_json::from_str(t.as_str()).expect("json from the agent");
            }
        }
    }

    /// A backend for the agent's real signaling client: accepts the next connection and completes
    /// the handshake (the signature is not checked), with user 42 bound.
    async fn accept_agent(
        listener: &tokio::net::TcpListener,
    ) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
        let (tcp, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("the agent connects in time")
            .expect("accept");
        handshake_on(tcp).await
    }

    /// [`accept_agent`] on a connection already accepted.
    async fn handshake_on(
        tcp: tokio::net::TcpStream,
    ) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
        handshake_with(
            tcp,
            r#"[{"telegram_user_id":42,"username":null,"first_name":null}]"#,
        )
        .await
    }

    /// The handshake on a connection already accepted, `agent_ready` listing `bindings` (JSON).
    async fn handshake_with(
        tcp: tokio::net::TcpStream,
        bindings: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let mut ws = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("ws accept");
        assert_eq!(next_frame(&mut ws).await["type"], "agent_hello");
        ws.send(Message::text(CHALLENGE_FRAME))
            .await
            .expect("challenge");
        assert_eq!(next_frame(&mut ws).await["type"], "agent_auth");
        ws.send(Message::text(format!(
            r#"{{"type":"agent_ready","protocol_version":{v},"min_supported_protocol":{v},"bindings":{bindings}}}"#,
            v = afklink_protocol::PROTOCOL_VERSION
        )))
        .await
        .expect("agent_ready");
        ws
    }

    /// Through the real signaling client: access given or taken away while the agent was away — the
    /// app closed (the previous run's last list), then a break of the link (this run's list) — is
    /// journaled from the new list, and a guest let in without this PC is announced as
    /// «Новый гость»; one approved here (its `binding_added` lost to the break) is «Доступ выдан»
    /// with no toast, and an owner nobody here approved is «Доступ выдан» with none either.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn access_given_while_away_is_journaled_and_announced() {
        use crate::journal::Kind;
        use afklink_protocol::BindingRole;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("ws://{}/ws/agent", listener.local_addr().expect("addr"));
        let (agent, control) = test_agent(Some(url));
        let (agent, journal) = with_journal(agent);
        let bound = |id: i64, first: &str, role: Option<BindingRole>| BindingInfo {
            telegram_user_id: id,
            username: None,
            first_name: Some(first.into()),
            role,
        };
        // The previous run's last list: the owner and 7, unbound since.
        let mut agent = agent.with_last_known_bindings(vec![
            bound(42, "Хозяин", Some(BindingRole::Owner)),
            bound(7, "Бывший", Some(BindingRole::Guest)),
        ]);
        // 46 was approved on this PC before the break (its `binding_added` never came).
        agent.note_answer_here(46, "r46", true, Instant::now());
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let running = tokio::spawn(agent.run());

        // The first handshake: the owner, and 43 — let in by the owner's invite meanwhile.
        let tcp = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("the agent connects")
            .expect("accept")
            .0;
        let first = handshake_with(
            tcp,
            r#"[{"telegram_user_id":42,"username":null,"first_name":"Хозяин","role":"owner"},
                {"telegram_user_id":43,"username":"friend","first_name":"Друг","role":"guest"}]"#,
        )
        .await;
        wait_for(&mut events, &mut seen, |e| {
            matches!(
                e,
                AgentEvent::GuestInvited {
                    telegram_user_id: 43,
                    ..
                }
            )
        })
        .await;
        match seen.last() {
            Some(AgentEvent::GuestInvited { name, .. }) => {
                assert_eq!(name.text, "Друг (@friend)", "named as a requester is");
            }
            other => panic!("{other:?}"),
        }
        // The break; the next handshake lists three more: 45 an owner from nowhere, 46 approved
        // here, and — last, so its toast comes after the others are journaled — 44 by invite.
        drop(first);
        let tcp = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("the agent reconnects")
            .expect("accept")
            .0;
        let _second = handshake_with(
            tcp,
            r#"[{"telegram_user_id":42,"username":null,"first_name":"Хозяин","role":"guest"},
                {"telegram_user_id":43,"username":"friend","first_name":"Друг","role":"guest"},
                {"telegram_user_id":45,"username":null,"first_name":"Кто","role":"owner"},
                {"telegram_user_id":46,"username":null,"first_name":"Свой","role":"guest"},
                {"telegram_user_id":44,"username":null,"first_name":"Ещё","role":"guest"}]"#,
        )
        .await;
        wait_for(&mut events, &mut seen, |e| {
            matches!(
                e,
                AgentEvent::GuestInvited {
                    telegram_user_id: 44,
                    ..
                }
            )
        })
        .await;
        // The journal, written before the toast's event: everything is there by now.
        let entries = journal.entries();
        let kinds = |user: i64| -> Vec<Kind> {
            entries
                .iter()
                .filter(|v| v.entry.user == user)
                .map(|v| v.entry.kind)
                .collect()
        };
        assert_eq!(
            kinds(7),
            [Kind::Revoked],
            "unbound while the app was closed"
        );
        assert_eq!(
            kinds(43),
            [Kind::Invited],
            "once: not again after the reconnect"
        );
        assert_eq!(kinds(44), [Kind::Invited]);
        assert_eq!(
            kinds(45),
            [Kind::Granted],
            "an owner from nowhere: no «по приглашению»"
        );
        assert_eq!(kinds(46), [Kind::Granted], "approved on this PC");
        assert!(kinds(42).is_empty(), "the owner was there all along");
        let toasts: Vec<i64> = seen
            .iter()
            .filter_map(|e| match e {
                AgentEvent::GuestInvited {
                    telegram_user_id, ..
                } => Some(*telegram_user_id),
                _ => None,
            })
            .collect();
        assert_eq!(toasts, [43, 44], "no toast for the owner nor for 46");

        drop(control);
        running.abort();
    }

    /// The next event `want` accepts, keeping every event seen on the way in `seen`.
    async fn wait_for(
        events: &mut broadcast::Receiver<AgentEvent>,
        seen: &mut Vec<AgentEvent>,
        want: impl Fn(&AgentEvent) -> bool,
    ) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let ev = events.recv().await.expect("the event stream is open");
                let done = want(&ev);
                seen.push(ev);
                if done {
                    return;
                }
            }
        })
        .await
        .expect("the event in time");
    }

    fn ended(session: &str) -> impl Fn(&AgentEvent) -> bool + '_ {
        move |ev| matches!(ev, AgentEvent::SessionEnded { session_id, .. } if session_id == session)
    }

    /// Until `cond` holds of the shared state, looked at every few milliseconds for at most five
    /// seconds; `what` names it in the failure.
    ///
    /// For what the agent's task writes to [`AgentState`] a moment after the event a test woke on:
    /// `end_session_with` announces `SessionEnded` before it takes the session off
    /// `AgentState::sessions`, in the same synchronous call on the agent's task, and the test's
    /// thread, woken by the event, can look in between. Nothing outside the tests reads the state on
    /// that event (the window, the tray and the updater poll it on their own clocks; the CLI's
    /// subscribers never read the sessions), so the test waits rather than the order changing.
    async fn wait_for_state(
        state: &Mutex<AgentState>,
        what: &str,
        cond: impl Fn(&AgentState) -> bool,
    ) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let done = cond(&lock(state));
            if done {
                return;
            }
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// The whole reconnect, through the real signaling client and the relay: the connection drops
    /// mid-session and comes back. The sessions carry on; what they produced while it was down —
    /// a late candidate, the end of a session whose peer gave up offline — reaches the new
    /// connection first, in order; a stats report made offline is dropped; the surviving session is
    /// then named so the backend re-binds it; and the backend's `unknown_session` ends it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sessions_survive_a_signaling_reconnect_and_are_named_on_the_new_connection() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (mut agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let peer1 = live_session(&mut agent, "s1");
        let peer2 = live_session(&mut agent, "s2");
        // What a session's telemetry and event tasks hold, and what its encode thread signals on.
        let outbox = agent.outbox.clone();
        let sess_ev = agent.sess_ev_tx.clone();
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let running = tokio::spawn(agent.run());

        // First connection: the PC's name, then both sessions are named, and the link carries the
        // keep-alive.
        let mut ws = accept_agent(&listener).await;
        assert_eq!(next_frame(&mut ws).await["type"], "device_name");
        let mut named = [next_frame(&mut ws).await, next_frame(&mut ws).await];
        named.sort_by_key(|f| f["session_id"].as_str().unwrap_or_default().to_string());
        assert_eq!(named[0]["type"], "session_stats");
        assert_eq!(named[0]["session_id"], "s1");
        assert_eq!(named[1]["type"], "session_stats");
        assert_eq!(named[1]["session_id"], "s2");
        ws.send(Message::text(r#"{"type":"ping"}"#))
            .await
            .expect("ping");
        assert_eq!(next_frame(&mut ws).await["type"], "pong");

        // The connection drops.
        ws.close(None).await.expect("close");
        drop(ws);
        wait_for(&mut events, &mut seen, |e| {
            *e == AgentEvent::SignalingDisconnected
        })
        .await;

        // While it is down: a late candidate from s1's event task, a report from s1's telemetry
        // task, and s2's peer giving up on its path.
        outbox
            .send(AgentToServer::Ice {
                session_id: "s1".into(),
                candidate: afklink_transport::IceCandidate {
                    candidate: "candidate:9 1 udp 1 198.51.100.7 5000 typ srflx".into(),
                    sdp_mid: None,
                    sdp_mline_index: None,
                    username_fragment: None,
                },
            })
            .expect("the outbox is open");
        outbox
            .send(AgentToServer::SessionStats {
                session_id: "s1".into(),
                stats: SessionCounters::default().snapshot(Duration::from_millis(999_999), (0, 0)),
                is_final: false,
            })
            .expect("the outbox is open");
        sess_ev
            .send(SessionSignal::Closed {
                id: "s2".into(),
                end: transport::PeerEnd::IceTimeout,
            })
            .expect("the orchestrator is running");
        wait_for(&mut events, &mut seen, ended("s2")).await;
        assert!(peer2.close.is_asked(), "s2's peer is closed offline");

        // Second connection: what was held comes first, in order — s2's final report held with its
        // end, both after the handshake (`agent_ready`); then the PC's name, and the survivor is
        // named.
        let mut ws = accept_agent(&listener).await;
        let held_ice = next_frame(&mut ws).await;
        assert_eq!(held_ice["type"], "ice");
        assert_eq!(held_ice["session_id"], "s1");
        assert_eq!(
            held_ice["candidate"]["candidate"],
            "candidate:9 1 udp 1 198.51.100.7 5000 typ srflx"
        );
        let held_final = next_frame(&mut ws).await;
        assert_eq!(held_final["type"], "session_stats");
        assert_eq!(held_final["session_id"], "s2");
        assert_eq!(held_final["final"], true, "{held_final}");
        let held_end = next_frame(&mut ws).await;
        assert_eq!(held_end["type"], "session_end");
        assert_eq!(held_end["session_id"], "s2");
        assert_eq!(held_end["reason"], "ice_timeout");
        assert_eq!(
            held_end["detail"]["stage"], "new",
            "the peer's path, as it published it: {held_end}"
        );
        assert!(
            held_end["detail"].get("ended_detail").is_none(),
            "ice_timeout is not split: {held_end}"
        );
        assert_eq!(next_frame(&mut ws).await["type"], "device_name");
        let renamed = next_frame(&mut ws).await;
        assert_eq!(renamed["type"], "session_stats");
        assert_eq!(renamed["session_id"], "s1");
        assert!(
            renamed.get("final").is_none(),
            "an ordinary report: {renamed}"
        );
        assert_ne!(
            renamed["stats"]["duration_ms"], 999_999,
            "the report made offline was dropped; this is the re-announce"
        );
        ws.send(Message::text(r#"{"type":"ping"}"#))
            .await
            .expect("ping");
        assert_eq!(
            next_frame(&mut ws).await["type"],
            "pong",
            "nothing else was sent: s2 is not named, the offline report is gone"
        );
        let live: Vec<String> = lock(&control.state)
            .sessions
            .iter()
            .map(|s| s.session_id.clone())
            .collect();
        assert_eq!(live, ["s1"], "s1 survived the reconnect");
        assert!(!peer1.close.is_asked());
        assert!(
            !seen.iter().any(ended("s1")),
            "nothing ended s1 on the way: {seen:?}"
        );

        // The backend has dropped s1 (its grace window ran out): it says so, and s1 ends here
        // without an end in reply — only its final report, for the backend's tombstone.
        ws.send(Message::text(
            r#"{"type":"session_end","session_id":"s1","reason":"unknown_session"}"#,
        ))
        .await
        .expect("session_end");
        wait_for(&mut events, &mut seen, ended("s1")).await;
        assert!(peer1.close.is_asked());
        let last = next_frame(&mut ws).await;
        assert_eq!(last["type"], "session_stats");
        assert_eq!(last["session_id"], "s1");
        assert_eq!(last["final"], true);
        ws.send(Message::text(r#"{"type":"ping"}"#))
            .await
            .expect("ping");
        assert_eq!(
            next_frame(&mut ws).await["type"],
            "pong",
            "no end in reply to the end"
        );

        drop(control);
        tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("the agent stops once nothing can command it")
            .expect("the agent task does not panic")
            .expect("and stops cleanly");
    }

    /* ── The upgrade names the build ─────────────────────────────────────────── */

    /// `with_user_agent` reaches the backend on the signaling upgrade, through the real client: the
    /// backend keeps it per device (`devices.last_agent`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::result_large_err, reason = "tungstenite's own callback type")]
    async fn the_signaling_upgrade_names_the_build() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let agent = agent.with_user_agent("AFKLink/0.4.0 (dev)".into());
        let running = tokio::spawn(agent.run());
        let (tcp, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("the agent connects in time")
            .expect("accept");
        let mut seen: Option<String> = None;
        let ws = tokio_tungstenite::accept_hdr_async(
            tcp,
            |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
                seen = request
                    .headers()
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                Ok(response)
            },
        )
        .await
        .expect("ws accept");
        assert_eq!(seen.as_deref(), Some("AFKLink/0.4.0 (dev)"));
        drop(ws);
        drop(control);
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the agent stops")
            .expect("no panic")
            .expect("clean");
    }

    /* ── The RU entry: the way to the server (`crate::entry`) ───────────────────── */

    /// The RU entry's case end to end, through the real signaling client: the configured address
    /// takes the upgrade and the hello and then delivers nothing (a provider freezing what
    /// Cloudflare sends) — the agent gives the handshake up at its silence limit and connects
    /// through the RU entry. There it authenticates and then hears not a single frame: back to the
    /// configured address, which now answers. Each switch keeps the reconnect loop's backoff.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_path_that_opens_and_delivers_nothing_moves_the_agent_to_the_other_way() {
        use futures_util::StreamExt;

        let primary = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let ru = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let primary_url = format!("ws://{}/ws/agent", primary.local_addr().expect("addr"));
        let ru_url = format!("ws://{}/ws/agent", ru.local_addr().expect("addr"));
        let entry = Arc::new(crate::entry::Entry::with_alternative(&primary_url, &ru_url));
        let (agent, control) = test_agent(Some(primary_url.clone()));
        let agent = agent.with_entry(Arc::clone(&entry)).with_signaling_limits(
            transport::signaling::Limits {
                handshake_silence: Duration::from_millis(300),
                legacy_silence: Duration::from_millis(500),
                silence: Duration::from_millis(500),
                ..transport::signaling::LIMITS
            },
        );
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let started = Instant::now();
        let running = tokio::spawn(agent.run());

        // The configured address: the upgrade and the hello go through, then nothing comes back.
        let (tcp, _) = tokio::time::timeout(Duration::from_secs(10), primary.accept())
            .await
            .expect("the agent tries the configured address first")
            .expect("accept");
        let mut frozen = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("ws accept");
        assert_eq!(next_frame(&mut frozen).await["type"], "agent_hello");

        // The RU entry: the handshake completes, the agent is connected through it.
        let mut via_ru = accept_agent(&ru).await;
        wait_for(&mut events, &mut seen, |e| {
            matches!(e, AgentEvent::SignalingConnected { .. })
        })
        .await;
        assert_eq!(entry.preferred(), crate::entry::Endpoint::Ru);
        let first_switch = started.elapsed();
        assert!(
            first_switch >= Duration::from_millis(300 + 900),
            "the silence limit, then the usual first backoff (1 s): {first_switch:?}"
        );
        drop(frozen);

        // Through the RU entry: the PC's name, then not a frame from the server — decisive.
        assert_eq!(next_frame(&mut via_ru).await["type"], "device_name");
        wait_for(&mut events, &mut seen, |e| {
            *e == AgentEvent::SignalingDisconnected
        })
        .await;
        // The configured address again, which now answers.
        let _back = accept_agent(&primary).await;
        wait_for(&mut events, &mut seen, |e| {
            matches!(e, AgentEvent::SignalingConnected { .. })
        })
        .await;
        assert_eq!(entry.preferred(), crate::entry::Endpoint::Primary);
        // The silent RU connection is over on the agent's side: its socket ends.
        let gone = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(Ok(_)) = via_ru.next().await {}
        })
        .await;
        assert!(gone.is_ok(), "the agent let go of the silent connection");

        drop(control);
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the agent stops")
            .expect("no panic")
            .expect("clean");
    }

    /// A server that closes the connection cleanly (a deploy) is not a path failure: the agent comes
    /// back the same way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_clean_close_keeps_the_agent_on_its_way() {
        let primary = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let ru = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let primary_url = format!("ws://{}/ws/agent", primary.local_addr().expect("addr"));
        let ru_url = format!("ws://{}/ws/agent", ru.local_addr().expect("addr"));
        let entry = Arc::new(crate::entry::Entry::with_alternative(&primary_url, &ru_url));
        let (agent, control) = test_agent(Some(primary_url));
        let running = tokio::spawn(agent.with_entry(Arc::clone(&entry)).run());
        for round in 0..2 {
            let mut ws = accept_agent(&primary).await;
            assert_eq!(next_frame(&mut ws).await["type"], "device_name", "{round}");
            ws.close(None).await.expect("close");
            while let Some(Ok(_)) = futures_util::StreamExt::next(&mut ws).await {}
        }
        // A third time, on the same way: two clean closes moved nothing.
        let _ws = accept_agent(&primary).await;
        assert_eq!(entry.preferred(), crate::entry::Endpoint::Primary);
        drop(control);
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the agent stops")
            .expect("no panic")
            .expect("clean");
    }

    /* ── Telemetry v2, phase C1 ─────────────────────────────────────────────── */

    /// `with_hello` reaches the backend in `agent_hello`, through the real client: the build, the
    /// boot id and how the previous process ended (`crate::run_state`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_hello_says_the_build_the_boot_and_the_last_exit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let build = crate::build_info::BuildInfo::from_stamp(
            "0.5.1",
            "1d38642aa0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
            "0",
            "",
            "dev",
        );
        let hello = transport::HelloInfo {
            build: build.wire(),
            boot_id: Some("6b1e0c2a-9f3d-4e57-8a21-c4d5e6f70812".into()),
            last_exit: Some(afklink_protocol::AgentLastExit {
                kind: afklink_protocol::AgentExitKind::AppExit,
                at: Some(1_789_599_960_000),
            }),
            hw: None,
        };
        let running = tokio::spawn(agent.with_hello(hello).run());
        let (tcp, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("the agent connects in time")
            .expect("accept");
        let mut ws = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("ws accept");
        let first = next_frame(&mut ws).await;
        assert_eq!(first["type"], "agent_hello");
        assert_eq!(
            first["build"],
            serde_json::json!({
                "version": "0.5.1",
                "commit": "1d38642aa0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
                "channel": "dev",
                "dirty": false
            })
        );
        assert_eq!(first["boot_id"], "6b1e0c2a-9f3d-4e57-8a21-c4d5e6f70812");
        assert_eq!(
            first["last_exit"],
            serde_json::json!({ "kind": "app_exit", "at": 1_789_599_960_000u64 })
        );
        assert!(
            first.get("hw").is_none(),
            "no reader, no fingerprint: {first}"
        );
        drop(ws);
        drop(control);
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the agent stops")
            .expect("no panic")
            .expect("clean");
    }

    /* ── The beta: the hardware fingerprint in the hello (`afklink_hw`) ───────── */

    fn test_hw() -> afklink_protocol::AgentHw {
        afklink_protocol::AgentHw {
            hash: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".into(),
            vm: true,
            parts: 2,
        }
    }

    /// The fingerprint `with_hw_reader` reads reaches the backend in the very first hello, whole, and
    /// in every hello after it: read once, not once per connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_hello_carries_the_fingerprint_read_once() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&reads);
        let reader: HwReader = Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Some(test_hw())
        });
        let running = tokio::spawn(agent.with_hw_reader(reader).run());
        for round in 0..2 {
            let (tcp, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
                .await
                .expect("the agent connects in time")
                .expect("accept");
            let mut ws = tokio_tungstenite::accept_async(tcp)
                .await
                .expect("ws accept");
            let first = next_frame(&mut ws).await;
            assert_eq!(first["type"], "agent_hello", "{round}");
            assert_eq!(
                first["hw"],
                serde_json::json!({
                    "hash": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                    "vm": true,
                    "parts": 2
                }),
                "{round}"
            );
            // The backend goes away after the hello: the agent comes back at the usual pace.
            drop(ws);
        }
        assert_eq!(reads.load(Ordering::SeqCst), 1, "read once per process");
        drop(control);
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the agent stops")
            .expect("no panic")
            .expect("clean");
    }

    /// A reading slower than the wait does not hold the PC offline: the first hello goes without the
    /// fingerprint, and the next one, once it is read, carries it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_slow_fingerprint_does_not_hold_the_first_hello() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let (release, released) = std::sync::mpsc::channel::<()>();
        let released = Mutex::new(released);
        let reader: HwReader = Arc::new(move || {
            // Held until the test lets it go (or ten seconds, so a failed test cannot hang).
            let _ = lock(&released).recv_timeout(Duration::from_secs(10));
            Some(test_hw())
        });
        let agent = agent
            .with_hw_reader(reader)
            .with_hw_wait(Duration::from_millis(300));
        let running = tokio::spawn(agent.run());

        let (tcp, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("the agent connects in time")
            .expect("accept");
        let mut ws = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("ws accept");
        let first = next_frame(&mut ws).await;
        assert_eq!(first["type"], "agent_hello");
        assert!(
            first.get("hw").is_none(),
            "not read yet: the hello goes without it: {first}"
        );
        release.send(()).expect("the reader waits");
        drop(ws);

        let (tcp, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("the agent comes back")
            .expect("accept");
        let mut ws = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("ws accept");
        let second = next_frame(&mut ws).await;
        assert_eq!(second["type"], "agent_hello");
        assert_eq!(second["hw"]["parts"], 2, "read now: {second}");
        drop(ws);
        drop(control);
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the agent stops")
            .expect("no panic")
            .expect("clean");
    }

    /// The first report comes after `first` — 5 s in the agent — and the next `every` after it
    /// (15 s), not at once and not only after the interval; the constants are the contract's plan.
    #[tokio::test]
    async fn the_first_report_comes_after_five_seconds_then_every_fifteen() {
        assert_eq!(afklink_protocol::TELEMETRY_FIRST_REPORT_MS, 5_000);
        assert_eq!(afklink_protocol::TELEMETRY_INTERVAL_MS, 15_000);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let stats = StatsSource::new(
            Arc::new(SessionCounters::default()),
            Arc::new(crate::quality::QualityTarget::default()),
            no_hold(),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let task = tokio::spawn(telemetry_task(
            stats.clone(),
            tx.clone(),
            stop.clone(),
            "s1".into(),
            Duration::from_millis(60),
            Duration::from_millis(600),
        ));
        let first = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the first report in time")
            .expect("a report");
        let first_after = started.elapsed();
        assert!(
            first_after >= Duration::from_millis(60) && first_after < Duration::from_millis(600),
            "the first after `first`, well before `every`: {first_after:?}"
        );
        assert!(matches!(
            first,
            AgentToServer::SessionStats { ref session_id, is_final: false, .. } if session_id == "s1"
        ));
        let second = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the second report in time")
            .expect("a report");
        let second_after = started.elapsed();
        assert!(
            second_after >= Duration::from_millis(600),
            "the second `every` after the first: {second_after:?}"
        );
        assert!(!second.is_final_report());

        // The session's end: its final report, and the task stops at its next tick.
        stop.store(true, Ordering::SeqCst);
        assert_eq!(stats.report(&tx, "s1", true), Reported::Sent);
        assert!(rx.recv().await.expect("the final").is_final_report());
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the task stops")
            .expect("no panic");
        assert!(rx.try_recv().is_err(), "nothing after the final");
    }

    /// One final per session, and no report after it — the server drops a side's reports after its
    /// final, and a report that crossed it would only be noise.
    #[test]
    fn no_report_follows_the_final() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let stats = StatsSource::new(
            Arc::new(SessionCounters::default()),
            Arc::new(crate::quality::QualityTarget::default()),
            no_hold(),
        );
        assert_eq!(stats.report(&tx, "s1", false), Reported::Sent);
        assert_eq!(stats.report(&tx, "s1", true), Reported::Sent);
        assert_eq!(stats.report(&tx, "s1", false), Reported::AfterFinal);
        assert_eq!(
            stats.report(&tx, "s1", true),
            Reported::AfterFinal,
            "a second final"
        );
        assert!(!rx.try_recv().expect("the report").is_final_report());
        assert!(rx.try_recv().expect("the final").is_final_report());
        assert!(rx.try_recv().is_err());
        drop(rx);
        let fresh = StatsSource::new(
            Arc::new(SessionCounters::default()),
            Arc::new(crate::quality::QualityTarget::default()),
            no_hold(),
        );
        assert_eq!(fresh.report(&tx, "s2", true), Reported::OutboxGone);
        assert_eq!(
            fresh.report(&tx, "s2", true),
            Reported::OutboxGone,
            "a final that went nowhere is not a final sent"
        );
    }

    /// The viewer's end and the server's: the session's final report goes — into the backend's
    /// tombstone — and no `session_end` goes back.
    #[tokio::test]
    async fn the_viewers_end_sends_the_final_report_and_no_end() {
        let (mut agent, tx, mut rx) = harness();
        let _peer = live_session(&mut agent, "s1");
        agent.sessions["s1"]
            .stats
            .counters
            .frames_encoded
            .store(77, Ordering::Relaxed);
        agent
            .handle_server_msg(
                ServerToAgent::SessionEnd {
                    session_id: "s1".into(),
                    reason: Some("viewer_closed".into()),
                },
                &tx,
            )
            .await;
        match rx.try_recv().expect("the final report") {
            AgentToServer::SessionStats {
                session_id,
                stats,
                is_final,
            } => {
                assert_eq!(session_id, "s1");
                assert!(is_final);
                assert_eq!(stats.frames_encoded, 77, "the session's totals");
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "the backend ended it: no end back");
        // The peer's own end arriving after: the session is gone, nothing more.
        agent.handle_session_signal(
            SessionSignal::Closed {
                id: "s1".into(),
                end: transport::PeerEnd::ViewerClosed,
            },
            &tx,
        );
        assert!(rx.try_recv().is_err(), "one final per session");
    }

    /// `peer_closed` split: the viewer's goodbye is `viewer`, str0m's own close `rtc`; no other end
    /// is split. With the peer's path as it published it — a stalled handshake's stage, verdict and
    /// pair kinds — and never an address.
    #[tokio::test]
    async fn the_agents_end_says_how_the_peer_ended_and_how_far_it_got() {
        use transport::PeerEnd;
        assert_eq!(peer_ended_detail(PeerEnd::ViewerClosed), Some("viewer"));
        assert_eq!(peer_ended_detail(PeerEnd::RtcClosed), Some("rtc"));
        for end in [
            PeerEnd::Closed,
            PeerEnd::IceTimeout,
            PeerEnd::RestartFailed,
            PeerEnd::Error,
        ] {
            assert_eq!(peer_ended_detail(end), None, "{end:?}");
        }

        let (mut agent, tx, mut rx) = harness();
        let _peer = live_session(&mut agent, "s1");
        agent.sessions["s1"].path.set(transport::PeerPath {
            stage: afklink_protocol::PeerStage::Dtls,
            verdict: Some("nothing_from_viewer"),
            dtls_after_ice_ms: None,
            pair_local_kind: Some("host"),
            pair_remote_kind: Some("relay"),
            relay_transport: Some("tls"),
        });
        agent.handle_session_signal(
            SessionSignal::Closed {
                id: "s1".into(),
                end: PeerEnd::RtcClosed,
            },
            &tx,
        );
        let end = after_final(&mut rx, "s1");
        let wire = serde_json::to_value(&end).expect("serialises");
        assert_eq!(
            wire,
            serde_json::json!({
                "type": "session_end",
                "session_id": "s1",
                "reason": "peer_closed",
                "detail": {
                    "ended_detail": "rtc",
                    "stage": "dtls",
                    "verdict": "nothing_from_viewer",
                    "pair_local_kind": "host",
                    "pair_remote_kind": "relay",
                    "relay_transport": "tls"
                }
            })
        );

        // The orchestrator's own end (the kill switch) carries the path too, without a split.
        let _peer = live_session(&mut agent, "s2");
        agent.sessions["s2"].path.set(transport::PeerPath {
            stage: afklink_protocol::PeerStage::Connected,
            verdict: None,
            dtls_after_ice_ms: Some(140),
            pair_local_kind: Some("host"),
            pair_remote_kind: Some("srflx"),
            relay_transport: None,
        });
        agent.handle_command(AgentCommand::KillSwitch, &tx).await;
        let end = after_final(&mut rx, "s2");
        let wire = serde_json::to_value(&end).expect("serialises");
        assert_eq!(wire["reason"], "kill_switch");
        assert_eq!(
            wire["detail"],
            serde_json::json!({
                "stage": "connected",
                "dtls_after_ice_ms": 140,
                "pair_local_kind": "host",
                "pair_remote_kind": "srflx"
            })
        );
    }

    /// `frames_dropped_paced` on the wire is the bucket's live counter: it never moved before.
    #[test]
    fn the_paced_drop_count_is_the_rate_buckets() {
        let counters = SessionCounters::default();
        counters.frames_dropped_rate.store(1_328, Ordering::Relaxed);
        counters.frames_dropped_stale.store(12, Ordering::Relaxed);
        let stats = counters.snapshot(Duration::from_secs(45), (3600, 2400));
        assert_eq!(stats.frames_dropped_paced, 1_328);
        assert_eq!(stats.frames_dropped_stale, 12, "a different count");
        let wire = serde_json::to_value(&stats).expect("serialises");
        assert_eq!(
            wire["frames_dropped_paced"], 1_328,
            "the old name on the wire"
        );
        assert!(wire.get("summary").is_none(), "phase C2's");
    }

    /* ── Telemetry v2, phase C2 ─────────────────────────────────────────────── */

    /// Every report carries the session's summary — the final one too — held to the contract.
    #[tokio::test]
    async fn every_report_carries_the_sessions_summary() {
        let (mut agent, tx, mut rx) = harness();
        let _peer = live_session(&mut agent, "s1");
        {
            let stats = &agent.sessions["s1"].stats;
            stats
                .counters
                .frames_dropped_rate
                .store(7, Ordering::Relaxed);
            stats.counters.encode_hist.record(9_000);
            stats.counters.input.count(&InputMessage::Down { b: 0 });
            // One motion second at 1080p.
            stats.summary.second(
                Instant::now(),
                crate::summary::Second {
                    sent_frames: 30,
                    presented: Some(30),
                    page_hidden: false,
                    held: false,
                    height: 1080,
                    secs: 1.0,
                },
            );
            stats.summary.instant(
                Instant::now(),
                afklink_protocol::metrics::SessionEpisodeKind::RungChange,
                Some("down"),
            );
            assert_eq!(stats.report(&tx, "s1", false), Reported::Sent);
        }
        let first = match rx.try_recv().expect("a report") {
            AgentToServer::SessionStats { stats, .. } => stats.summary.expect("a summary"),
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(first.check(), Ok(()));
        assert_eq!(first.dropped_rate, Some(7));
        assert_eq!(first.input.map(|i| i.buttons), Some(1));
        assert_eq!(first.encode_ms_p95, Some(9.0));
        assert_eq!(first.episodes.as_ref().map(Vec::len), Some(1));
        // The backend ends it: the final report has it too.
        agent
            .handle_server_msg(
                ServerToAgent::SessionEnd {
                    session_id: "s1".into(),
                    reason: Some("viewer_closed".into()),
                },
                &tx,
            )
            .await;
        match rx.try_recv().expect("the final report") {
            AgentToServer::SessionStats {
                stats,
                is_final: true,
                ..
            } => {
                let summary = stats.summary.expect("the final's summary");
                assert_eq!(summary.check(), Ok(()));
                assert_eq!(summary.rung_s.map(|r| r.len()), Some(1));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// The exit ends every live session — its final report, then `session_end agent_ended` — and
    /// every request still waiting for its offer, and answers the one who asked.
    #[tokio::test]
    async fn the_exit_ends_live_sessions_and_requests_with_agent_ended() {
        let (mut agent, tx, mut rx) = harness();
        let peer = live_session(&mut agent, "s1");
        agent.pending.insert(
            "s2".into(),
            Pending {
                telegram_user_id: 42,
                username: None,
                stun_servers: vec![],
                policy: crate::quality_policy::SessionPolicy::fallback(
                    crate::quality_policy::FallbackReason::Absent,
                ),
            },
        );
        let (done, answer) = std::sync::mpsc::sync_channel(1);
        agent
            .handle_command(
                AgentCommand::EndForExit {
                    why: crate::goodbye::GoodbyeReason::Quit,
                    asked: Instant::now(),
                    budget: EXIT_END_BUDGET,
                    done,
                },
                &tx,
            )
            .await;
        let ended = answer.try_recv().expect("answered");
        assert_eq!((ended.sessions, ended.requests), (1, 1));
        assert!(agent.sessions.is_empty() && agent.pending.is_empty());
        assert!(peer.close.is_asked());
        match after_final(&mut rx, "s1") {
            AgentToServer::SessionEnd {
                session_id, reason, ..
            } => {
                assert_eq!(session_id, "s1");
                assert_eq!(reason.as_deref(), Some(end_reason::AGENT_ENDED));
            }
            other => panic!("unexpected: {other:?}"),
        }
        match rx.try_recv().expect("the request's end") {
            AgentToServer::SessionEnd {
                session_id, reason, ..
            } => {
                assert_eq!(session_id, "s2");
                assert_eq!(reason.as_deref(), Some(end_reason::AGENT_ENDED));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(rx.try_recv().is_err());
        // Nothing left: a second exit (the app's after the shutdown's) does nothing, at once.
        let (done, answer) = std::sync::mpsc::sync_channel(1);
        agent
            .handle_command(
                AgentCommand::EndForExit {
                    why: crate::goodbye::GoodbyeReason::Quit,
                    asked: Instant::now(),
                    budget: EXIT_END_BUDGET,
                    done,
                },
                &tx,
            )
            .await;
        assert_eq!(
            answer.try_recv().expect("answered"),
            ExitEnding {
                flushed: true,
                ..ExitEnding::default()
            }
        );
        assert!(rx.try_recv().is_err());
    }

    /// A request to end the sessions that reaches the orchestrator past its budget — it was busy,
    /// and the exit went ahead without it — is dropped: the sessions carry on, nothing is sent, and
    /// the asker (long gone) hears nothing.
    #[tokio::test]
    async fn an_exit_request_past_its_budget_is_dropped() {
        let (mut agent, tx, mut rx) = harness();
        let peer = live_session(&mut agent, "s1");
        let (done, answer) = std::sync::mpsc::sync_channel(1);
        let asked = Instant::now()
            .checked_sub(EXIT_END_BUDGET + Duration::from_millis(50))
            .expect("an instant in the past");
        agent
            .handle_command(
                AgentCommand::EndForExit {
                    why: crate::goodbye::GoodbyeReason::Shutdown,
                    asked,
                    budget: EXIT_END_BUDGET,
                    done,
                },
                &tx,
            )
            .await;
        assert!(answer.try_recv().is_err(), "not answered: not served");
        assert!(agent.sessions.contains_key("s1"), "the session carries on");
        assert!(!peer.close.is_asked());
        assert!(rx.try_recv().is_err(), "nothing sent");
    }

    /// The clean exit through the real client: the session's final report and its end are on the
    /// wire ahead of the goodbye, in that order, within the exit's budgets.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_clean_exit_ends_the_live_sessions_before_the_goodbye() {
        use crate::goodbye::{GoodbyeOutcome, GoodbyeReason};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (mut agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let peer = live_session(&mut agent, "s1");
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let running = tokio::spawn(agent.run());
        let mut ws = accept_agent(&listener).await;
        assert_eq!(next_frame(&mut ws).await["type"], "device_name");
        assert_eq!(next_frame(&mut ws).await["type"], "session_stats", "named");
        wait_for(&mut events, &mut seen, connected).await;
        let backend = read_until_closed(ws);

        let ctl = control.clone();
        let asked = Instant::now();
        let outcome = tokio::task::spawn_blocking(move || {
            ctl.leave_blocking(GoodbyeReason::Quit, Duration::from_secs(3))
        })
        .await
        .expect("the leaving thread");
        let took = asked.elapsed();
        assert!(outcome.sent(), "{outcome:?}");
        assert!(matches!(outcome, GoodbyeOutcome::Said { .. }));
        assert!(
            took < EXIT_END_BUDGET + Duration::from_secs(3),
            "bounded: {took:?}"
        );
        assert!(peer.close.is_asked());
        let (texts, close) = backend.await.expect("backend task");
        let types: Vec<&str> = texts
            .iter()
            .map(|v| v["type"].as_str().unwrap_or("?"))
            .collect();
        assert_eq!(
            types,
            ["session_stats", "session_end", "agent_goodbye"],
            "the session's final and end, then the goodbye: {texts:?}"
        );
        assert_eq!(texts[0]["final"], true);
        assert!(texts[0]["stats"].get("summary").is_some(), "{}", texts[0]);
        assert_eq!(texts[1]["reason"], "agent_ended");
        assert_eq!(texts[2]["reason"], "quit");
        assert_eq!(close, Some(1000));

        drop(control);
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the agent stops")
            .expect("no panic")
            .expect("clean");
    }

    /// The agent's events go only after `agent_ready` — the handshake is the hello and the auth,
    /// nothing else — then on every connection until one stayed up long enough, with the `at` they
    /// were recorded at; one recorded while connected goes at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn agent_events_go_after_agent_ready_and_again_after_a_reconnect() {
        use afklink_protocol::metrics::{AgentEvent, AgentEventKind, PcSettingKey, PcSettingValue};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let queue = Arc::new(crate::agent_events::EventQueue::in_memory());
        let setting = |at: u64, on: bool| AgentEvent {
            at,
            event: AgentEventKind::PcSettingChanged {
                key: PcSettingKey::GameOnly,
                value: PcSettingValue::Flag(on),
            },
        };
        // Recorded before any connection.
        assert!(matches!(
            queue.record(setting(1_789_600_300_000, true)),
            crate::agent_events::Recorded::Queued { .. }
        ));
        let running = tokio::spawn(agent.with_event_queue(queue.clone()).run());
        // `handshake_on` asserts the hello and the auth are the first two frames: nothing before
        // `agent_ready`.
        let mut ws = accept_agent(&listener).await;
        assert_eq!(next_frame(&mut ws).await["type"], "device_name");
        let event = next_frame(&mut ws).await;
        assert_eq!(event["type"], "agent_event");
        assert_eq!(event["kind"], "pc_setting_changed");
        assert_eq!(event["at"], 1_789_600_300_000u64);
        assert_eq!(event["value"], true);
        // Recorded while connected: at once.
        queue.record(setting(1_789_600_301_000, false));
        let second = next_frame(&mut ws).await;
        assert_eq!(second["type"], "agent_event");
        assert_eq!(second["at"], 1_789_600_301_000u64);

        // The connection ends before it could have taken them: both again on the next, as they
        // were.
        ws.close(None).await.expect("close");
        drop(ws);
        let mut ws = accept_agent(&listener).await;
        assert_eq!(next_frame(&mut ws).await["type"], "device_name");
        let mut again = [next_frame(&mut ws).await, next_frame(&mut ws).await];
        again.sort_by_key(|f| f["at"].as_u64().unwrap_or_default());
        assert_eq!(again[0]["type"], "agent_event");
        assert_eq!(again[0]["at"], 1_789_600_300_000u64);
        assert_eq!(again[1]["at"], 1_789_600_301_000u64);
        assert_eq!(
            queue.pending(),
            2,
            "not delivered until a connection stays up"
        );

        drop(control);
        close_and_drain(ws).await;
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the agent stops")
            .expect("no panic")
            .expect("clean");
    }

    /// The owner's game-only switches are `pc_setting_changed` — once per change, not per call.
    ///
    /// Into a queue of this test's thread alone (`agent_events::record_on_this_thread`): other tests
    /// toggle the same switches on other threads at the same time, and the process's queue sees
    /// theirs too (flaky that way).
    #[test]
    fn the_game_only_switches_are_recorded_as_setting_changes() {
        use afklink_protocol::metrics::{AgentEventKind, PcSettingKey, PcSettingValue};
        let queue = Arc::new(crate::agent_events::EventQueue::in_memory());
        crate::agent_events::record_on_this_thread(Some(queue.clone()));
        let (_agent, control) = test_agent(None);
        let settings = || {
            queue
                .waiting()
                .into_iter()
                .map(|e| match e.event {
                    AgentEventKind::PcSettingChanged { key, value } => (key, value),
                    other => panic!("only setting changes are recorded here: {other:?}"),
                })
                .collect::<Vec<_>>()
        };

        let guests = control.game_only_for_guests();
        control
            .set_game_only_for_guests(!guests)
            .expect("set and saved");
        control
            .set_game_only_for_guests(!guests)
            .expect("unchanged, nothing to save");
        assert_eq!(
            settings(),
            [(
                PcSettingKey::GameOnlyForGuests,
                PcSettingValue::Flag(!guests)
            )],
            "one change, one event"
        );

        let (game_only, _) = control.game_only();
        control.set_game_only(!game_only).expect("set and saved");
        control
            .set_game_only(!game_only)
            .expect("unchanged, nothing to save");
        assert_eq!(
            settings(),
            [
                (
                    PcSettingKey::GameOnlyForGuests,
                    PcSettingValue::Flag(!guests)
                ),
                (PcSettingKey::GameOnly, PcSettingValue::Flag(!game_only)),
            ],
            "the other switch: one event too"
        );
        crate::agent_events::record_on_this_thread(None);
    }

    /* ── The goodbye (`crate::goodbye`) ─────────────────────────────────────── */

    /// What the backend reads from the agent until the connection ends: the text frames as JSON,
    /// and the agent's close code.
    fn read_until_closed(
        mut ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) -> tokio::task::JoinHandle<(Vec<serde_json::Value>, Option<u16>)> {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;
        tokio::spawn(async move {
            let mut texts = Vec::new();
            let mut close = None;
            loop {
                match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
                    Ok(Some(Ok(Message::Text(t)))) => {
                        texts.push(serde_json::from_str(t.as_str()).expect("json from the agent"))
                    }
                    // Answered by tungstenite on the next read, which the agent then ends.
                    Ok(Some(Ok(Message::Close(frame)))) => close = frame.map(|f| u16::from(f.code)),
                    Ok(Some(Ok(_))) => {}
                    _ => break,
                }
            }
            (texts, close)
        })
    }

    /// The goodbye through the real client: `agent_goodbye` with the reason and a normal close,
    /// confirmed by the backend's close; then no reconnecting — past the usual backoff — until the
    /// hold is lifted, and a second goodbye sends nothing. Lifted, the agent connects at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_goodbye_closes_the_connection_and_holds_until_welcomed_back() {
        use crate::goodbye::{GoodbyeOutcome, GoodbyeReason};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let running = tokio::spawn(agent.run());
        let mut ws = accept_agent(&listener).await;
        assert_eq!(next_frame(&mut ws).await["type"], "device_name");
        wait_for(&mut events, &mut seen, connected).await;
        let backend = read_until_closed(ws);

        let outcome = control
            .goodbye(GoodbyeReason::Sleep, Duration::from_secs(3))
            .await;
        assert!(
            matches!(
                outcome,
                GoodbyeOutcome::Said {
                    result: afklink_transport::GoodbyeResult::Confirmed { .. },
                    ..
                }
            ),
            "{outcome:?}"
        );
        assert!(outcome.sent());
        let (texts, close) = backend.await.expect("backend task");
        let types: Vec<&str> = texts
            .iter()
            .map(|v| v["type"].as_str().unwrap_or("?"))
            .collect();
        assert_eq!(types, ["agent_goodbye"], "the goodbye is the last word");
        assert_eq!(texts[0]["reason"], "sleep");
        assert_eq!(close, Some(1000), "a normal close");
        wait_for(&mut events, &mut seen, |e| {
            *e == AgentEvent::SignalingDisconnected
        })
        .await;
        assert_eq!(control.goodbye_held(), Some(GoodbyeReason::Sleep));

        // Said once: the exit that follows a goodbye finds it said.
        match control
            .goodbye(GoodbyeReason::Quit, Duration::from_secs(1))
            .await
        {
            GoodbyeOutcome::AlreadySaid { reason, .. } => assert_eq!(reason, GoodbyeReason::Sleep),
            other => panic!("expected already said, got {other:?}"),
        }

        assert_no_fast_reconnect(&listener, "held after the goodbye").await;
        assert!(control.welcome_back("the system resumed"));
        assert_eq!(control.goodbye_held(), None);
        let mut ws = accept_agent(&listener).await;
        assert_eq!(next_frame(&mut ws).await["type"], "device_name");
        wait_for(&mut events, &mut seen, connected).await;

        drop(control);
        close_and_drain(ws).await;
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the agent stops")
            .expect("no panic")
            .expect("clean");
    }

    /// A goodbye while the connection is still being made sends nothing then — there is nothing to
    /// send it on — and holds; the connection, once its handshake completes, is told goodbye at
    /// once instead of being served (no `device_name` first), and no reconnect follows. The owner's
    /// retry lifts the hold.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_goodbye_during_the_connect_is_said_on_the_connection_it_makes() {
        use crate::goodbye::{GoodbyeOutcome, GoodbyeReason};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let running = tokio::spawn(agent.run());
        // The agent's connect is in flight: its TCP connection is here, the upgrade unanswered.
        let (tcp, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("the agent connects in time")
            .expect("accept");
        assert_eq!(
            control
                .goodbye(GoodbyeReason::Shutdown, Duration::from_millis(300))
                .await,
            GoodbyeOutcome::NoConnection
        );
        let mut ws = handshake_on(tcp).await;
        let first = next_frame(&mut ws).await;
        assert_eq!(first["type"], "agent_goodbye", "not served: {first}");
        assert_eq!(first["reason"], "shutdown");
        close_and_drain(ws).await;
        assert_no_fast_reconnect(&listener, "held: a shutdown is under way").await;
        assert_eq!(control.goodbye_held(), Some(GoodbyeReason::Shutdown));

        control
            .commands
            .send(AgentCommand::Retry)
            .expect("the agent is running");
        let mut ws = accept_agent(&listener).await;
        assert_eq!(next_frame(&mut ws).await["type"], "device_name");
        assert_eq!(control.goodbye_held(), None, "the retry lifted the hold");

        drop(control);
        close_and_drain(ws).await;
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the agent stops")
            .expect("no panic")
            .expect("clean");
    }

    /// The heartbeat is answered while the orchestrator is busy: its loop stuck in a command for
    /// longer than the backend waits, the `pong`s go out all the same (the pump answers them).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pings_are_answered_while_the_orchestrator_is_busy() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        /// An injector whose `release_all` — which the kill switch calls on the orchestrator's own
        /// task — takes its time, as a driver's retries can.
        struct SlowRelease;
        impl InputInjector for SlowRelease {
            fn inject(&self, _event: &InputMessage) -> anyhow::Result<()> {
                Ok(())
            }
            fn release_all(&self) {
                std::thread::sleep(Duration::from_millis(1500));
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (mut agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        Arc::get_mut(&mut agent.backends)
            .expect("nothing shares the backends yet")
            .injector = Arc::new(SlowRelease);
        let running = tokio::spawn(agent.run());
        let mut ws = accept_agent(&listener).await;
        assert_eq!(next_frame(&mut ws).await["type"], "device_name");

        // The orchestrator goes into the slow release; the pings come meanwhile.
        control
            .commands
            .send(AgentCommand::KillSwitch)
            .expect("the agent is running");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let started = Instant::now();
        for _ in 0..3 {
            ws.send(Message::text(r#"{"type":"ping"}"#))
                .await
                .expect("ping");
            assert_eq!(next_frame(&mut ws).await["type"], "pong");
        }
        assert!(
            started.elapsed() < Duration::from_millis(1000),
            "the pongs did not wait for the orchestrator: {:?}",
            started.elapsed()
        );

        drop(control);
        close_and_drain(ws).await;
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the agent stops")
            .expect("no panic")
            .expect("clean");
    }

    /* ── Refusals: what follows a fatal code (`crate::reconnect`) ─────────────── */

    /// Longer than the ordinary backoff's first wait (1 s) with a margin: an agent that has not
    /// come back within this has not reconnected at the usual pace.
    const NO_FAST_RECONNECT: Duration = Duration::from_millis(2500);

    /// Close the backend's side and read until the agent has closed its own.
    ///
    /// Dropping a socket with unread data in it resets the connection rather than closing it, and a
    /// reset can throw away the error frame before the agent has read it — which made these tests
    /// fail under load. The real backend closes with the handshake too.
    async fn close_and_drain(mut ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) {
        use futures_util::StreamExt;
        let _ = ws.close(None).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(Ok(_)) = ws.next().await {}
        })
        .await;
    }

    /// A backend that takes the next connection and answers `agent_hello` with an error frame.
    async fn refuse_handshake(listener: &tokio::net::TcpListener, code: &str) {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let (tcp, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("the agent connects in time")
            .expect("accept");
        let mut ws = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("ws accept");
        assert_eq!(next_frame(&mut ws).await["type"], "agent_hello");
        ws.send(Message::text(format!(
            r#"{{"type":"error","code":"{code}","message":"from the test backend"}}"#
        )))
        .await
        .expect("error frame");
        close_and_drain(ws).await;
    }

    /// The backend's `replaced`, as `registerAgent` sends it on the old socket: the frame, then the
    /// close.
    async fn replace(mut ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        ws.send(Message::text(
            r#"{"type":"error","code":"replaced","message":"device reconnected elsewhere"}"#,
        ))
        .await
        .expect("replaced");
        close_and_drain(ws).await;
    }

    /// Nothing connects to `listener` for [`NO_FAST_RECONNECT`].
    async fn assert_no_fast_reconnect(listener: &tokio::net::TcpListener, why: &str) {
        assert!(
            tokio::time::timeout(NO_FAST_RECONNECT, listener.accept())
                .await
                .is_err(),
            "{why}: the agent reconnected at the usual pace"
        );
    }

    fn refused_with(code: &'static str) -> impl Fn(&AgentEvent) -> bool {
        move |ev| matches!(ev, AgentEvent::SignalingRefused(r) if r.code() == code)
    }

    fn connected(ev: &AgentEvent) -> bool {
        matches!(ev, AgentEvent::SignalingConnected { .. })
    }

    /// `replaced` in the desktop app: no reconnecting by itself — the other process would only
    /// take the connection back — while the kill switch is still served and what it tells the
    /// backend is held; the owner's Retry connects at once, and the held end goes first.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replaced_waits_for_the_owner_and_the_kill_switch_still_works() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (mut agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let peer = live_session(&mut agent, "s1");
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        assert!(
            !lock(&control.state).bindings_known,
            "nothing heard from the backend yet: the window waits rather than say nobody has access"
        );
        let running = tokio::spawn(agent.run());

        let ws = accept_agent(&listener).await;
        wait_for(&mut events, &mut seen, connected).await;
        assert!(
            lock(&control.state).bindings_known,
            "the handshake brought the list"
        );
        replace(ws).await;
        wait_for(&mut events, &mut seen, refused_with("replaced")).await;
        {
            let s = lock(&control.state);
            assert_eq!(s.refused, Some(Refusal::Replaced));
            assert!(!s.connected);
            assert!(s.bindings_known, "the last list stays known offline");
        }
        assert_no_fast_reconnect(&listener, "replaced").await;

        control
            .commands
            .send(AgentCommand::KillSwitch)
            .expect("the agent is running");
        wait_for(&mut events, &mut seen, ended("s1")).await;
        assert!(peer.close.is_asked(), "the kill switch closed the peer");
        assert!(
            lock(&control.state).paused,
            "and paused connections, offline too"
        );
        assert!(
            seen.contains(&AgentEvent::SessionEnded {
                session_id: "s1".into(),
                reason: end_reason::KILL_SWITCH.into(),
            }),
            "{seen:?}"
        );
        assert_no_fast_reconnect(&listener, "replaced, after the kill switch").await;

        control
            .commands
            .send(AgentCommand::Retry)
            .expect("the agent is running");
        let mut ws = accept_agent(&listener).await;
        // The session's final report, held with its end (within the backend's minute for it).
        let held_final = next_frame(&mut ws).await;
        assert_eq!(held_final["type"], "session_stats");
        assert_eq!(held_final["session_id"], "s1");
        assert_eq!(held_final["final"], true);
        let held = next_frame(&mut ws).await;
        assert_eq!(held["type"], "session_end");
        assert_eq!(held["session_id"], "s1");
        assert_eq!(held["reason"], "kill_switch");
        wait_for(&mut events, &mut seen, connected).await;
        assert_eq!(lock(&control.state).refused, None);

        drop(control);
        tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("the agent stops once nothing can command it")
            .expect("the agent task does not panic")
            .expect("and stops cleanly");
    }

    /// Another fatal code on the handshake: no reconnecting at the usual pace, a retry after the
    /// slow interval, and the refusal cleared once the backend accepts the agent again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fatal_handshake_code_is_retried_slowly() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let agent = agent.with_slow_retry(Duration::from_secs(4));
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let running = tokio::spawn(agent.run());

        refuse_handshake(&listener, "protocol_unsupported").await;
        wait_for(&mut events, &mut seen, refused_with("protocol_unsupported")).await;
        assert_eq!(
            lock(&control.state).refused,
            Some(Refusal::Fatal {
                code: "protocol_unsupported".into()
            })
        );
        assert_no_fast_reconnect(&listener, "protocol_unsupported").await;

        // The slow retry, a server-side fix in between.
        let _ws = accept_agent(&listener).await;
        wait_for(&mut events, &mut seen, connected).await;
        assert_eq!(lock(&control.state).refused, None);

        drop(control);
        tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("the agent stops once nothing can command it")
            .expect("the agent task does not panic")
            .expect("and stops cleanly");
    }

    /// The owner's Retry during a slow retry connects at once; a refusal that comes back the same
    /// stays in force, and the next Retry that the backend accepts clears it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_owners_retry_cuts_a_slow_retry_short() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let agent = agent.with_slow_retry(Duration::from_secs(600));
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let running = tokio::spawn(agent.run());

        refuse_handshake(&listener, "bad_signature").await;
        wait_for(&mut events, &mut seen, refused_with("bad_signature")).await;
        assert_no_fast_reconnect(&listener, "bad_signature").await;

        control
            .commands
            .send(AgentCommand::Retry)
            .expect("the agent is running");
        refuse_handshake(&listener, "bad_signature").await;
        seen.clear();
        wait_for(&mut events, &mut seen, refused_with("bad_signature")).await;
        assert!(lock(&control.state).refused.is_some(), "still refused");

        control
            .commands
            .send(AgentCommand::Retry)
            .expect("the agent is running");
        let _ws = accept_agent(&listener).await;
        wait_for(&mut events, &mut seen, connected).await;
        assert_eq!(lock(&control.state).refused, None);

        drop(control);
        tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("the agent stops once nothing can command it")
            .expect("the agent task does not panic")
            .expect("and stops cleanly");
    }

    /// A code this build does not know is transient, as the contract says: a newer backend may
    /// send one, and the agent comes back at the usual pace without calling it a refusal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unknown_code_is_retried_at_the_usual_pace() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let running = tokio::spawn(agent.run());

        refuse_handshake(&listener, "a_code_from_a_newer_backend").await;
        let started = Instant::now();
        let _ws = accept_agent(&listener).await;
        assert!(
            started.elapsed() < NO_FAST_RECONNECT,
            "back at the usual pace: {:?}",
            started.elapsed()
        );
        wait_for(&mut events, &mut seen, connected).await;
        assert!(
            !seen
                .iter()
                .any(|e| matches!(e, AgentEvent::SignalingRefused(_))),
            "{seen:?}"
        );
        assert_eq!(lock(&control.state).refused, None);

        drop(control);
        tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("the agent stops once nothing can command it")
            .expect("the agent task does not panic")
            .expect("and stops cleanly");
    }

    /// `replaced` in the CLI: the agent ends its sessions and stops with an error naming the code.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replaced_stops_the_cli() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (mut agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let peer = live_session(&mut agent, "s1");
        let agent = agent.with_on_replaced(OnReplaced::Stop);
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let running = tokio::spawn(agent.run());

        let ws = accept_agent(&listener).await;
        wait_for(&mut events, &mut seen, connected).await;
        replace(ws).await;
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("the agent stops at once")
            .expect("the agent task does not panic");
        let err = match result {
            Ok(()) => panic!("replaced must stop the CLI with an error"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("replaced"), "{err}");
        assert!(
            peer.close.is_asked(),
            "its session was ended on the way out"
        );
        while let Ok(ev) = events.try_recv() {
            seen.push(ev);
        }
        assert!(
            seen.contains(&AgentEvent::SessionEnded {
                session_id: "s1".into(),
                reason: end_reason::AGENT_DISCONNECTED.into(),
            }),
            "{seen:?}"
        );
        drop(control);
    }

    /* ── The beta: `device_blocked` (`crate::reconnect`) ─────────────────────── */

    /// A backend that takes the next connection and refuses it where the real one refuses a
    /// blocked PC: after the signature, in place of
    /// `agent_ready` — the error frame, then the close.
    async fn refuse_after_auth(listener: &tokio::net::TcpListener, code: &str) {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let (tcp, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("the agent connects in time")
            .expect("accept");
        let mut ws = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("ws accept");
        assert_eq!(next_frame(&mut ws).await["type"], "agent_hello");
        ws.send(Message::text(CHALLENGE_FRAME))
            .await
            .expect("challenge");
        assert_eq!(next_frame(&mut ws).await["type"], "agent_auth");
        ws.send(Message::text(format!(
            r#"{{"type":"error","code":"{code}","message":"from the test backend"}}"#
        )))
        .await
        .expect("error frame");
        close_and_drain(ws).await;
    }

    /// Every frame the agent sends within `quiet` of the last one, until it goes quiet.
    async fn frames_until_quiet(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        quiet: Duration,
    ) -> Vec<serde_json::Value> {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;
        let mut frames = Vec::new();
        while let Ok(Some(Ok(frame))) = tokio::time::timeout(quiet, ws.next()).await {
            if let Message::Text(t) = frame {
                frames.push(serde_json::from_str(t.as_str()).expect("json from the agent"));
            }
        }
        frames
    }

    /// `device_blocked` at the sign-in, where the server sends it: a refusal of its own kind — the
    /// window's «ПК заблокирован» with no Retry (`kind` `blocked`) — no reconnecting at the usual
    /// pace while the block holds, a slow retry all the same, and the PC back by itself the first
    /// time the slow retry finds the block lifted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_blocked_at_the_sign_in_is_retried_slowly_until_lifted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let agent = agent.with_slow_retry(Duration::from_secs(4));
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let running = tokio::spawn(agent.run());

        refuse_after_auth(&listener, "device_blocked").await;
        wait_for(&mut events, &mut seen, refused_with("device_blocked")).await;
        {
            let s = lock(&control.state);
            let refused = s.refused.as_ref().expect("refused");
            assert!(refused.is_blocked());
            assert_eq!(
                refused.kind(),
                "blocked",
                "the window's «ПК заблокирован», with no Retry"
            );
            assert!(!s.connected);
        }
        assert_no_fast_reconnect(&listener, "device_blocked").await;

        // The first slow retry: still blocked — still refused, still slow.
        refuse_after_auth(&listener, "device_blocked").await;
        seen.clear();
        wait_for(&mut events, &mut seen, refused_with("device_blocked")).await;
        assert!(lock(&control.state)
            .refused
            .as_ref()
            .is_some_and(Refusal::is_blocked));
        assert_no_fast_reconnect(&listener, "device_blocked, again").await;

        // Lifted: the next slow retry connects, and the refusal is gone.
        let _ws = accept_agent(&listener).await;
        wait_for(&mut events, &mut seen, connected).await;
        assert_eq!(lock(&control.state).refused, None);

        drop(control);
        tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("the agent stops once nothing can command it")
            .expect("the agent task does not panic")
            .expect("and stops cleanly");
    }

    /// `device_blocked` on a live connection — an admin blocks the PC while it serves: the
    /// connection is over, the refusal is the blocked kind, what the agent still runs ends
    /// (`blocked`, its input released, nothing told to the backend, which ended it first), no
    /// reconnecting at the usual pace; and once the block is lifted the slow retry connects, with no
    /// `session_end` for the ended session on the new connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_blocked_on_the_live_connection_ends_what_runs_and_retries_slowly() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (mut agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let peer = live_session(&mut agent, "s1");
        let agent = agent.with_slow_retry(Duration::from_secs(4));
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let running = tokio::spawn(agent.run());

        let mut ws = accept_agent(&listener).await;
        wait_for(&mut events, &mut seen, connected).await;
        ws.send(Message::text(
            r#"{"type":"error","code":"device_blocked","message":"the PC is blocked"}"#,
        ))
        .await
        .expect("device_blocked");
        close_and_drain(ws).await;
        wait_for(&mut events, &mut seen, refused_with("device_blocked")).await;
        wait_for(&mut events, &mut seen, ended("s1")).await;
        assert!(
            seen.contains(&AgentEvent::SessionEnded {
                session_id: "s1".into(),
                reason: end_reason::BLOCKED.into(),
            }),
            "{seen:?}"
        );
        assert!(peer.close.is_asked(), "the session's peer was closed");
        // The event goes out a moment before the session leaves the shared state
        // (`wait_for_state`); one in five runs would look in between.
        wait_for_state(&control.state, "s1 off the shared state", |s| {
            s.sessions.is_empty()
        })
        .await;
        {
            let s = lock(&control.state);
            assert!(s.sessions.is_empty(), "nothing runs on a blocked PC");
            assert_eq!(s.refused.as_ref().map(Refusal::kind), Some("blocked"));
            assert!(!s.connected);
        }
        assert_no_fast_reconnect(&listener, "device_blocked on the live connection").await;

        // Lifted.
        let mut ws = accept_agent(&listener).await;
        wait_for(&mut events, &mut seen, connected).await;
        assert_eq!(lock(&control.state).refused, None);
        let frames = frames_until_quiet(&mut ws, Duration::from_millis(700)).await;
        assert!(
            !frames
                .iter()
                .any(|f| f["type"] == "session_end" && f["session_id"] == "s1"),
            "the server ended it; the agent tells it nothing: {frames:?}"
        );

        drop(control);
        close_and_drain(ws).await;
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the agent stops once nothing can command it")
            .expect("the agent task does not panic")
            .expect("and stops cleanly");
    }

    /* ── The pairing panel (`crate::pairing`) ──────────────────────────────────── */

    /// The orchestrator's side of the panel: opened offline it sends nothing (the next connection
    /// asks); a code that arrives after the panel closed is not shown; someone entering the code
    /// closes the panel and revokes the spent code; a binding made while it is open pairs it and
    /// takes the spent code off screen rather than leaving the panel open with nothing in it.
    #[tokio::test]
    async fn the_pairing_panel_follows_the_owner_and_the_backend() {
        use crate::pairing::PairingPanel;
        let (mut agent, tx, mut rx) = harness();

        agent
            .handle_command(AgentCommand::RequestPairing, &tx)
            .await;
        assert!(
            rx.try_recv().is_err(),
            "nothing is sent while signaling is down"
        );
        assert_eq!(lock(&agent.state).pairing_panel, PairingPanel::Open);

        lock(&agent.state).connected = true;
        agent
            .handle_command(AgentCommand::RequestPairing, &tx)
            .await;
        assert!(matches!(rx.try_recv(), Ok(AgentToServer::RequestPairing)));

        // Closed before the code came.
        agent.handle_command(AgentCommand::CancelPairing, &tx).await;
        assert!(matches!(rx.try_recv(), Ok(AgentToServer::PairingCancel)));
        agent
            .handle_server_msg(pairing_code("123456", None, None), &tx)
            .await;
        assert_eq!(lock(&agent.state).pairing_code, None, "not shown");
        assert!(
            rx.try_recv().is_err(),
            "nothing to revoke: the cancel that followed its request did"
        );

        // Opened, the code shown, then someone enters it: the panel closes, the code goes.
        agent
            .handle_command(AgentCommand::RequestPairing, &tx)
            .await;
        assert!(matches!(rx.try_recv(), Ok(AgentToServer::RequestPairing)));
        agent
            .handle_server_msg(pairing_code("111222", None, None), &tx)
            .await;
        agent
            .handle_server_msg(
                ServerToAgent::PairRequest {
                    request_id: "r1".into(),
                    telegram_user_id: 7,
                    username: Some("ann".into()),
                    first_name: None,
                    expires_at: 1,
                    has_owner: None,
                },
                &tx,
            )
            .await;
        {
            let s = lock(&agent.state);
            assert_eq!(s.pairing_panel.kind(), "redeemed");
            assert_eq!(s.pairing_code, None, "the spent code is off screen");
            assert!(s.pending_pair.is_some(), "the prompt is what remains");
        }
        assert!(
            matches!(rx.try_recv(), Ok(AgentToServer::PairingCancel)),
            "the spent code is revoked, as for any close"
        );
        // The prompt is declined; the window closes the panel on `redeemed`.
        agent
            .handle_server_msg(
                ServerToAgent::PairCancelled {
                    request_id: "r1".into(),
                    reason: afklink_protocol::PairDeclineReason::Declined,
                },
                &tx,
            )
            .await;
        agent.handle_command(AgentCommand::CancelPairing, &tx).await;
        assert!(matches!(rx.try_recv(), Ok(AgentToServer::PairingCancel)));
        assert_eq!(lock(&agent.state).pairing_panel, PairingPanel::Closed);

        // Opened again for a new code, then the binding it produced.
        agent
            .handle_command(AgentCommand::RequestPairing, &tx)
            .await;
        assert!(matches!(rx.try_recv(), Ok(AgentToServer::RequestPairing)));
        agent
            .handle_server_msg(pairing_code("654321", None, None), &tx)
            .await;
        assert_eq!(lock(&agent.state).pairing_code.as_deref(), Some("654321"));
        agent
            .handle_server_msg(
                ServerToAgent::BindingAdded {
                    telegram_user_id: 7,
                    username: Some("ann".into()),
                    first_name: None,
                    role: None,
                    via: None,
                },
                &tx,
            )
            .await;
        {
            let s = lock(&agent.state);
            assert_eq!(s.pairing_panel.kind(), "paired");
            assert_eq!(s.pairing_code, None, "the spent code is off screen");
            assert_eq!(s.bindings.len(), 1);
        }
        assert!(rx.try_recv().is_err(), "nothing else went to the backend");
    }

    /// The backend refuses the code (`rate_limited`, "pairing codes"): the open panel is not left
    /// waiting forever — the request goes again when its wait is over, and not before; another
    /// request's `rate_limited` schedules nothing; closing the panel ends the retries.
    #[tokio::test]
    async fn a_refused_pairing_code_is_asked_for_again_while_the_panel_is_open() {
        let (mut agent, tx, mut rx) = harness();
        lock(&agent.state).connected = true;
        agent
            .handle_command(AgentCommand::RequestPairing, &tx)
            .await;
        assert!(matches!(rx.try_recv(), Ok(AgentToServer::RequestPairing)));

        // Another request's refusal: not the code's.
        agent
            .handle_server_msg(
                ServerToAgent::Error {
                    code: "rate_limited".into(),
                    message: Some("unbind".into()),
                },
                &tx,
            )
            .await;
        assert_eq!(
            lock(&agent.state).pairing_retry,
            crate::pairing::CodeRetry::default()
        );

        let refused = || ServerToAgent::Error {
            code: "rate_limited".into(),
            message: Some(crate::pairing::CODE_REFUSED_MESSAGE.into()),
        };
        agent.handle_server_msg(refused(), &tx).await;
        let due = lock(&agent.state)
            .pairing_retry
            .due_ms
            .expect("a retry is scheduled");
        agent.retry_pairing_code(&tx);
        assert!(rx.try_recv().is_err(), "not before its wait is over");

        // Its wait over (moved into the past rather than slept through): asked again, once.
        lock(&agent.state).pairing_retry.due_ms = Some(due - 10_000);
        agent.retry_pairing_code(&tx);
        assert!(matches!(rx.try_recv(), Ok(AgentToServer::RequestPairing)));
        agent.retry_pairing_code(&tx);
        assert!(rx.try_recv().is_err(), "one request per wait");

        // Refused again, then the panel closes: nothing more.
        agent.handle_server_msg(refused(), &tx).await;
        assert_eq!(lock(&agent.state).pairing_retry.refusals, 2);
        agent.handle_command(AgentCommand::CancelPairing, &tx).await;
        assert!(matches!(rx.try_recv(), Ok(AgentToServer::PairingCancel)));
        assert_eq!(
            lock(&agent.state).pairing_retry,
            crate::pairing::CodeRetry::default()
        );
        agent.retry_pairing_code(&tx);
        assert!(rx.try_recv().is_err(), "a closed panel asks for nothing");
    }

    /// Through the real signaling client: someone enters the code, which closes the panel and
    /// revokes the code; the owner opens it again while the request is still pending; then the
    /// connection drops. The new code goes (the backend revoked it with the socket and cannot say
    /// so), and so does the request — its deadline here (1) is long past; one still in time is kept
    /// (`a_pairing_request_survives_a_signaling_reconnect`). The panel stays open, and the next
    /// connection asks for a new code. A panel opened while signaling is down asks on the next
    /// connection too; a closed one asks for nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_open_pairing_panel_gets_a_new_code_after_a_reconnect() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let running = tokio::spawn(agent.run());
        let disconnected = |e: &AgentEvent| *e == AgentEvent::SignalingDisconnected;
        /// The next frame that is not the PC's name, which the agent sends on every connection.
        async fn pairing_frame(
            ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        ) -> serde_json::Value {
            loop {
                let frame = next_frame(ws).await;
                if frame["type"] != "device_name" {
                    return frame;
                }
            }
        }

        let mut ws = accept_agent(&listener).await;
        wait_for(&mut events, &mut seen, connected).await;
        control
            .commands
            .send(AgentCommand::RequestPairing)
            .expect("the agent is running");
        assert_eq!(pairing_frame(&mut ws).await["type"], "request_pairing");
        ws.send(Message::text(
            r#"{"type":"pairing_code","code":"123456","expires_at":1}"#,
        ))
        .await
        .expect("pairing_code");
        ws.send(Message::text(
            r#"{"type":"pair_request","request_id":"r1","telegram_user_id":7,"username":"ann","first_name":null,"expires_at":1}"#,
        ))
        .await
        .expect("pair_request");
        assert_eq!(
            pairing_frame(&mut ws).await["type"],
            "pairing_cancel",
            "the entered code closes the panel and is revoked"
        );
        assert_eq!(lock(&control.state).pairing_panel.kind(), "redeemed");

        // The owner opens the panel again while the request waits for an answer.
        control
            .commands
            .send(AgentCommand::RequestPairing)
            .expect("the agent is running");
        assert_eq!(pairing_frame(&mut ws).await["type"], "request_pairing");
        ws.send(Message::text(
            r#"{"type":"pairing_code","code":"654321","expires_at":1}"#,
        ))
        .await
        .expect("pairing_code");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                {
                    let s = lock(&control.state);
                    if s.pairing_code.is_some() && s.pending_pair.is_some() {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the code and the request are on screen");

        ws.close(None).await.expect("close");
        drop(ws);
        wait_for(&mut events, &mut seen, disconnected).await;
        {
            let s = lock(&control.state);
            assert_eq!(s.pairing_code, None, "the code died with the connection");
            assert!(
                s.pending_pair.is_none(),
                "and the request, past its deadline: no prompt for it"
            );
            assert_eq!(s.pairing_panel.kind(), "open", "the panel stays open");
        }

        let mut ws = accept_agent(&listener).await;
        assert_eq!(
            pairing_frame(&mut ws).await["type"],
            "request_pairing",
            "the open panel asks for a new code"
        );

        // Closed; the connection drops; opened again while it is down.
        control
            .commands
            .send(AgentCommand::CancelPairing)
            .expect("the agent is running");
        assert_eq!(pairing_frame(&mut ws).await["type"], "pairing_cancel");
        ws.close(None).await.expect("close");
        drop(ws);
        wait_for(&mut events, &mut seen, disconnected).await;
        control
            .commands
            .send(AgentCommand::RequestPairing)
            .expect("the agent is running");

        let mut ws = accept_agent(&listener).await;
        assert_eq!(
            pairing_frame(&mut ws).await["type"],
            "request_pairing",
            "a panel opened offline asks on the next connection"
        );
        ws.send(Message::text(r#"{"type":"ping"}"#))
            .await
            .expect("ping");
        assert_eq!(
            pairing_frame(&mut ws).await["type"],
            "pong",
            "and only once"
        );

        drop(control);
        tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("the agent stops once nothing can command it")
            .expect("the agent task does not panic")
            .expect("and stops cleanly");
    }

    /// A pairing request that waits, as the backend sends it: two minutes from now, on a PC with
    /// no owner (it asks «Кто это?»).
    fn waiting_pair_request(request_id: &str, expires_at: i64) -> ServerToAgent {
        ServerToAgent::PairRequest {
            request_id: request_id.into(),
            telegram_user_id: 7,
            username: Some("ann".into()),
            first_name: Some("Аня".into()),
            expires_at,
            has_owner: Some(false),
        }
    }

    /// The orchestrator's side of a request kept across a break (`crate::pairing`): an answer while
    /// its link is down is not sent and the request stays; the backend's re-send of the same request
    /// makes it answerable again, without raising it anew (no panel closed, no code revoked); then
    /// the answer goes, with the role chosen at «Кто это?».
    #[tokio::test]
    async fn a_kept_pairing_request_takes_no_answer_until_the_backend_re_sends_it() {
        use afklink_protocol::BindingRole;
        let (mut agent, tx, mut rx) = harness();
        let id = "5895a646-0940-4d39-8635-64f4d21ad019";
        let now = crate::journal::now_ms();
        agent
            .handle_server_msg(waiting_pair_request(id, now + 120_000), &tx)
            .await;
        crate::pairing::connection_lost(&mut lock(&agent.state), now + 1_000);

        let answer = AgentCommand::RespondToPair {
            request_id: id.into(),
            accept: true,
            role: Some(BindingRole::Owner),
        };
        agent.handle_command(answer, &tx).await;
        assert!(
            rx.try_recv().is_err(),
            "nothing goes while the link is down"
        );
        {
            let s = lock(&agent.state);
            let p = s.pending_pair.as_ref().expect("the request stays");
            assert!(!p.answerable());
            assert!(p.asks_role());
        }

        crate::pairing::reconnected(&mut lock(&agent.state), now + 9_700, 2);
        // The owner opened the pairing panel meanwhile: the re-send is not someone entering its code.
        lock(&agent.state).pairing_panel = crate::pairing::PairingPanel::Open;
        agent
            .handle_server_msg(waiting_pair_request(id, now + 120_000), &tx)
            .await;
        assert!(rx.try_recv().is_err(), "a restore revokes no code");
        {
            let s = lock(&agent.state);
            assert_eq!(s.pairing_panel, crate::pairing::PairingPanel::Open);
            assert!(s.pending_pair.as_ref().is_some_and(PendingPair::answerable));
        }

        agent
            .handle_command(
                AgentCommand::RespondToPair {
                    request_id: id.into(),
                    accept: true,
                    role: Some(BindingRole::Owner),
                },
                &tx,
            )
            .await;
        let sent = rx.try_recv().expect("the answer went to the backend");
        assert!(
            matches!(
                &sent,
                AgentToServer::PairResponse { request_id, accept: true, role: Some(BindingRole::Owner), .. }
                    if request_id.as_str() == id
            ),
            "{sent:?}"
        );
        assert!(lock(&agent.state).pending_pair.is_none(), "answered");
    }

    /// Through the real signaling client and the relay: the backend goes away while the owner is
    /// at «Кто это?» and comes back 8.7 s later. The request is kept
    /// while the link is down — an answer then is not sent — and the backend's re-send of the same
    /// request after `agent_ready` puts it back; the answer then goes over the new connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pairing_request_survives_a_signaling_reconnect() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (agent, control) = test_agent(Some(format!("ws://{addr}/ws/agent")));
        let mut events = control.subscribe();
        let mut seen = Vec::new();
        let running = tokio::spawn(agent.run());
        let disconnected = |e: &AgentEvent| *e == AgentEvent::SignalingDisconnected;
        /// The next frame that is not the PC's name, which the agent sends on every connection.
        async fn own_frame(
            ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        ) -> serde_json::Value {
            loop {
                let frame = next_frame(ws).await;
                if frame["type"] != "device_name" {
                    return frame;
                }
            }
        }
        let until = |what: &'static str, done: fn(&AgentState) -> bool| {
            let control = control.clone();
            async move {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while !done(&lock(&control.state)) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .unwrap_or_else(|_| panic!("{what} in time"));
            }
        };
        let id = "5895a646-0940-4d39-8635-64f4d21ad019";
        let request = format!(
            r#"{{"type":"pair_request","request_id":"{id}","telegram_user_id":7,"username":"ann","first_name":"Аня","expires_at":{},"has_owner":false}}"#,
            crate::journal::now_ms() + 120_000
        );

        let mut ws = accept_agent(&listener).await;
        wait_for(&mut events, &mut seen, connected).await;
        ws.send(Message::text(request.clone()))
            .await
            .expect("pair_request");
        until("the prompt", |s| s.pending_pair.is_some()).await;

        // The backend goes away mid-question.
        ws.close(None).await.expect("close");
        drop(ws);
        wait_for(&mut events, &mut seen, disconnected).await;
        {
            let s = lock(&control.state);
            let p = s.pending_pair.as_ref().expect("the request is kept");
            assert_eq!(p.request_id, id);
            assert!(!p.answerable(), "its answer waits for the link");
        }
        // A decline typed now goes nowhere: were it held for the next connection, it would be the
        // first answer there. (Sent at once: the agent waits a second before its next attempt,
        // serving commands meanwhile.)
        let decline = || AgentCommand::RespondToPair {
            request_id: id.into(),
            accept: false,
            role: None,
        };
        control
            .commands
            .send(decline())
            .expect("the agent is running");

        // Back. Before the backend's re-send the request is still not answerable: a decline then
        // is not sent either.
        let mut ws = accept_agent(&listener).await;
        until("the request rechecked on the new link", |s| {
            s.pending_pair
                .as_ref()
                .is_some_and(|p| p.link.as_str() == "rechecking")
        })
        .await;
        control
            .commands
            .send(decline())
            .expect("the agent is running");
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The backend re-sends the same request right after `agent_ready`.
        ws.send(Message::text(request))
            .await
            .expect("pair_request again");
        until("the request answerable again", |s| {
            s.pending_pair
                .as_ref()
                .is_some_and(crate::agent::PendingPair::answerable)
        })
        .await;
        control
            .commands
            .send(AgentCommand::RespondToPair {
                request_id: id.into(),
                accept: true,
                role: Some(afklink_protocol::BindingRole::Owner),
            })
            .expect("the agent is running");
        let answer = own_frame(&mut ws).await;
        assert_eq!(answer["type"], "pair_response", "{answer}");
        assert_eq!(answer["request_id"], id);
        assert_eq!(
            answer["accept"], true,
            "the decline typed offline never went"
        );
        assert_eq!(answer["role"], "owner", "«Кто это?» answered as asked");

        drop(control);
        tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("the agent stops once nothing can command it")
            .expect("the agent task does not panic")
            .expect("and stops cleanly");
    }

    // ---- A session's start and end never hold the runtime ----
    //
    // A stuck platform call in a session's start or end must not stall the agent's runtime: a
    // stalled runtime stops answering the server's pings and never reconnects. These drive the real
    // orchestrator path — `end_session`, `start_pipeline` — on a multi-thread runtime of two workers
    // (as Tauri's), with platform calls that do not return, and check that the runtime's timers and
    // channels keep going, that a start gives up into a reason, and that a stuck end of one session
    // does not keep the next from starting.

    use crate::offload::tests::Gate;

    /// The input driver as the agent shares it: one slot lock behind `begin_session`, `end_session`,
    /// `release_all` and `input_reach` (`hid` in `afklink_input`). While `stuck`, each waits at
    /// `gate`, as behind a holder that does not let go.
    #[derive(Default)]
    struct DriverSlot {
        stuck: AtomicBool,
        gate: Gate,
        begun: AtomicU32,
        ended: AtomicU32,
        /// Injections asked for (before the slot), and done (after it).
        inject_started: AtomicU32,
        injected: AtomicU32,
        /// Releases of everything asked for, and done.
        release_started: AtomicU32,
        released: AtomicU32,
    }

    impl DriverSlot {
        fn slot(&self) {
            if self.stuck.load(Ordering::SeqCst) {
                self.gate.wait();
            }
        }
    }

    struct SlotInjector(Arc<DriverSlot>);
    impl InputInjector for SlotInjector {
        fn inject(&self, _event: &InputMessage) -> anyhow::Result<()> {
            self.0.inject_started.fetch_add(1, Ordering::SeqCst);
            self.0.slot();
            self.0.injected.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn release_all(&self) {
            self.0.release_started.fetch_add(1, Ordering::SeqCst);
            self.0.slot();
            self.0.released.fetch_add(1, Ordering::SeqCst);
        }
        fn begin_session(&self) {
            self.0.slot();
            self.0.begun.fetch_add(1, Ordering::SeqCst);
        }
        fn end_session(&self) {
            self.0.slot();
            self.0.ended.fetch_add(1, Ordering::SeqCst);
        }
        fn input_reach(&self) -> crate::traits::InputReach {
            self.0.slot();
            crate::traits::InputReach::default()
        }
    }

    /// The monitor capturers a test's agent makes: their starts wait at `start_gate` while one is
    /// set (a WGC start whose thread never comes up).
    #[derive(Default)]
    struct CaptureScript {
        start_gate: Mutex<Option<Arc<Gate>>>,
        /// How long a capture's start, and the encoder's making, take (a budget used up).
        start_takes: Mutex<Duration>,
        encoder_takes: Mutex<Duration>,
        starts: AtomicU32,
        stops: AtomicU32,
    }

    /// A capturer whose `start` follows its script and whose `stop` waits at `stop_gate` when given
    /// one (a WGC or game capture thread's join that never returns).
    struct ScriptedCapturer {
        script: Arc<CaptureScript>,
        stop_gate: Option<Arc<Gate>>,
        running: bool,
    }

    impl Capturer for ScriptedCapturer {
        fn start(
            &mut self,
            _sink: std::sync::mpsc::Sender<Frame>,
            _target: Arc<crate::quality::QualityTarget>,
        ) -> anyhow::Result<()> {
            let gate = lock(&self.script.start_gate).clone();
            if let Some(gate) = gate {
                gate.wait();
            }
            let takes = *lock(&self.script.start_takes);
            if !takes.is_zero() {
                std::thread::sleep(takes);
            }
            self.script.starts.fetch_add(1, Ordering::SeqCst);
            self.running = true;
            Ok(())
        }
        fn stop(&mut self) {
            if let Some(gate) = &self.stop_gate {
                gate.wait();
            }
            // Counted once per running capture: the encode thread's exit stops it too.
            if std::mem::take(&mut self.running) {
                self.script.stops.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// An agent whose capturers follow `script`, whose encoders are the pipeline's fakes and whose
    /// injector is `slot`; its session steps give up after 300 ms; viewer 42 is bound.
    fn stuck_rig(slot: &Arc<DriverSlot>, script: &Arc<CaptureScript>) -> (Agent, AgentControl) {
        use crate::pipeline::fakes::{fake_backends, CaptureWorld, EncoderWorld};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "afklink-core-stuck-test-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).expect("test dir");
        let config = Config::load_or_create_at(base.join("config.json")).expect("test config");
        let identity =
            Identity::load_or_create_at(base.join("identity.json")).expect("test identity");
        let fakes = fake_backends(
            &Arc::new(Mutex::new(CaptureWorld::default())),
            &Arc::new(Mutex::new(EncoderWorld::default())),
        );
        let made_from = script.clone();
        let encoder_script = script.clone();
        let backends = Backends {
            make_capturer: Box::new(move || {
                Ok(Box::new(ScriptedCapturer {
                    script: made_from.clone(),
                    stop_gate: None,
                    running: false,
                }) as Box<dyn Capturer>)
            }),
            make_game_capturer: Box::new(|_| Err(anyhow::anyhow!("no game capturer in test"))),
            make_encoder: Box::new(move || {
                let takes = *lock(&encoder_script.encoder_takes);
                if !takes.is_zero() {
                    std::thread::sleep(takes);
                }
                (fakes.make_encoder)()
            }),
            injector: Arc::new(SlotInjector(slot.clone())),
        };
        let (mut agent, control) = Agent::new(config, Arc::new(identity), backends);
        agent.setup_limit = Duration::from_millis(300);
        lock(&agent.state).bindings.push(BindingInfo {
            telegram_user_id: 42,
            username: None,
            first_name: None,
            role: None,
        });
        (agent, control)
    }

    /// The policy `start_session` hands `start_pipeline` for a request that carried no profile.
    fn no_profile() -> crate::quality_policy::SessionPolicy {
        crate::quality_policy::SessionPolicy::fallback(
            crate::quality_policy::FallbackReason::Absent,
        )
    }

    /// The far ends of a [`fake_peer`]: kept, so the session's tasks see a peer that is up.
    struct PeerEnds {
        close: afklink_transport::CloseSignal,
        _signals: transport::SignalReceiver,
        events: mpsc::Sender<PeerEvent>,
    }

    /// A peer as `spawn_peer_with` returns one, with no socket behind it; its media and control
    /// queues are drained on the runtime.
    fn fake_peer() -> (transport::Peer, PeerEnds) {
        let (media_tx, mut media_rx) = mpsc::channel::<transport::MediaSample>(64);
        let (control_tx, mut control_rx) = mpsc::channel::<PeerControl>(64);
        let (signals, signal_rx) = transport::signal_queue();
        let (closer, close) = PeerCloser::new();
        let (events_tx, events) = mpsc::channel(64);
        tokio::spawn(async move { while media_rx.recv().await.is_some() {} });
        tokio::spawn(async move { while control_rx.recv().await.is_some() {} });
        let peer = transport::Peer {
            answer_sdp: "v=0".into(),
            media_tx,
            signals,
            control_tx,
            closer,
            events,
            outstanding_bytes: Arc::default(),
            queued_media_bytes: Arc::default(),
            queue_age_ms: Arc::default(),
            drain_kbps: Arc::default(),
            egress_kbps: Arc::default(),
            egress_bytes_total: Arc::default(),
            discarded_frames: Arc::default(),
            nacks_received: Arc::default(),
            path_changes: Arc::default(),
            path_kind: Arc::default(),
            path: Arc::default(),
            socket_bytes: Arc::default(),
        };
        (
            peer,
            PeerEnds {
                close,
                _signals: signal_rx,
                events: events_tx,
            },
        )
    }

    /// What else runs on the runtime: a 10 ms timer, and a ping answered over a channel every 5 ms —
    /// the signaling pump's pong and silence timer, in miniature.
    struct Liveness {
        ticks: Arc<AtomicU32>,
        rounds: Arc<AtomicU32>,
    }

    impl Liveness {
        fn start() -> Self {
            let ticks = Arc::new(AtomicU32::new(0));
            let rounds = Arc::new(AtomicU32::new(0));
            let t = ticks.clone();
            tokio::spawn(async move {
                let mut every = tokio::time::interval(Duration::from_millis(10));
                loop {
                    every.tick().await;
                    t.fetch_add(1, Ordering::SeqCst);
                }
            });
            let (ping_tx, mut ping_rx) = mpsc::channel::<u32>(1);
            let (pong_tx, mut pong_rx) = mpsc::channel::<u32>(1);
            tokio::spawn(async move {
                while let Some(n) = ping_rx.recv().await {
                    if pong_tx.send(n).await.is_err() {
                        break;
                    }
                }
            });
            let r = rounds.clone();
            tokio::spawn(async move {
                for n in 0u32.. {
                    if ping_tx.send(n).await.is_err() || pong_rx.recv().await.is_none() {
                        break;
                    }
                    r.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
            Self { ticks, rounds }
        }

        fn now(&self) -> (u32, u32) {
            (
                self.ticks.load(Ordering::SeqCst),
                self.rounds.load(Ordering::SeqCst),
            )
        }

        /// Over `window` of wall time, watched from the test's own thread (not a worker), the timer
        /// and the ping both kept going.
        fn keeps_going_over(&self, window: Duration, while_what: &str) {
            let (t0, r0) = self.now();
            std::thread::sleep(window);
            let (t1, r1) = self.now();
            // A stalled runtime manages one at most. Not more than three asked for: on Windows a
            // 5–10 ms sleep lasts a whole timer tick (~15.6 ms), and a loaded machine stretches it.
            assert!(
                t1 - t0 >= 3 && r1 - r0 >= 3,
                "the runtime stalled while {while_what}: {} timer ticks and {} pings in {} ms",
                t1 - t0,
                r1 - r0,
                window.as_millis()
            );
        }
    }

    /// Wait on the test's thread until `cond` holds, at most five seconds.
    fn wait_on_thread(what: &str, cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The `session_end` for `id` among what reached the backend, if any.
    fn end_sent(rx: &mut mpsc::UnboundedReceiver<AgentToServer>, id: &str) -> Option<String> {
        while let Ok(msg) = rx.try_recv() {
            if let AgentToServer::SessionEnd {
                session_id, reason, ..
            } = msg
            {
                if session_id == id {
                    return reason;
                }
            }
        }
        None
    }

    /// A capture start that never comes back: the session gives up at its limit with
    /// `capture_error`, the runtime's timers and pings keep going all the while, the answer queued
    /// just before reaches the relay at once, and the capture that comes up late is stopped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_capture_start_that_never_returns_ends_the_session_and_holds_nothing() {
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let gate = Arc::new(Gate::default());
        *lock(&script.start_gate) = Some(gate.clone());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        let (tx, mut rx) = mpsc::unbounded_channel();
        bounded(
            "B's request",
            agent.handle_server_msg(session_request("b", 42), &tx),
        )
        .await;
        assert!(agent.pending.contains_key("b"));
        let live = Liveness::start();

        // The relay, in miniature: when the answer queued before the start reaches it.
        let (relay_tx, mut relay_rx) = mpsc::unbounded_channel::<AgentToServer>();
        let answer_at = Arc::new(Mutex::new(None::<Instant>));
        let seen = answer_at.clone();
        let (fwd_tx, mut fwd_rx) = mpsc::unbounded_channel();
        let relay = tokio::spawn(async move {
            while let Some(msg) = relay_rx.recv().await {
                if matches!(msg, AgentToServer::Sdp { .. }) {
                    *lock(&seen) = Some(Instant::now());
                }
                if fwd_tx.send(msg).is_err() {
                    break;
                }
            }
        });
        let (peer, ends) = fake_peer();
        let t0 = Instant::now();
        let orchestrator = tokio::spawn(async move {
            send_to_backend(
                &relay_tx,
                AgentToServer::Sdp {
                    session_id: "b".into(),
                    sdp_type: SdpType::Answer,
                    sdp: peer.answer_sdp.clone(),
                },
            );
            agent
                .start_pipeline(
                    "b".into(),
                    peer,
                    42,
                    no_profile(),
                    Instant::now(),
                    &relay_tx,
                )
                .await;
            agent
        });

        wait_on_thread("the capture start to hang", || {
            gate.waiting.load(Ordering::SeqCst) == 1
        });
        let stuck_at = Instant::now();
        live.keeps_going_over(Duration::from_millis(150), "a capture start hung");
        let answered = lock(&answer_at).expect("the answer reached the relay");
        assert!(
            answered <= stuck_at,
            "the answer went out while the capture was coming up, not after"
        );

        let agent = tokio::time::timeout(Duration::from_secs(3), orchestrator)
            .await
            .expect("the start gives up at its limit")
            .expect("the orchestrator does not panic");
        assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
        assert!(agent.sessions.is_empty(), "no session registered");
        // The relay ends once the orchestrator's sender is gone, having passed on everything.
        tokio::time::timeout(Duration::from_secs(3), relay)
            .await
            .expect("the relay drains")
            .expect("the relay does not panic");
        assert_eq!(
            end_sent(&mut fwd_rx, "b").as_deref(),
            Some(end_reason::CAPTURE_ERROR)
        );
        assert!(ends.close.is_asked(), "the peer is closed");
        assert_eq!(slot.begun.load(Ordering::SeqCst), 0, "no input was opened");
        drop(rx.try_recv());

        // The capture comes up after all: stopped at once, nothing left running.
        gate.open();
        wait_on_thread("the late capture to be stopped", || {
            script.stops.load(Ordering::SeqCst) == 1
        });
        assert_eq!(script.starts.load(Ordering::SeqCst), 1);
    }

    /// A's capture stop never returns (its capture thread's join), and A's input end waits on a
    /// driver lock that is not let go: A's end returns at once, the runtime keeps going, and B —
    /// which needs the driver too — gives up at its limit with a reason instead of waiting forever.
    /// Once the driver lets go, both inputs close and the driver's session count balances.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stuck_end_returns_at_once_and_the_next_start_waits_on_the_driver_with_a_limit() {
        let _serial = INPUT_OPEN_STUCK.lock().await;
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _peer_a = live_session(&mut agent, "a");
        assert_eq!(slot.begun.load(Ordering::SeqCst), 1, "A's input is open");
        let stop_gate = Arc::new(Gate::default());
        agent.sessions.get_mut("a").expect("A").capturer =
            Arc::new(Mutex::new(Box::new(ScriptedCapturer {
                script: script.clone(),
                stop_gate: Some(stop_gate.clone()),
                running: true,
            }) as Box<dyn Capturer>));
        bounded(
            "B's request",
            agent.handle_server_msg(session_request("b", 42), &tx),
        )
        .await;
        let live = Liveness::start();
        // The driver's lock is held by something that does not let go.
        slot.stuck.store(true, Ordering::SeqCst);

        let t0 = Instant::now();
        let (peer, _ends) = fake_peer();
        let orchestrator = tokio::spawn(async move {
            agent.end_session("a", true, "superseded", &tx);
            let ended_in = t0.elapsed();
            agent
                .start_pipeline("b".into(), peer, 42, no_profile(), Instant::now(), &tx)
                .await;
            (agent, ended_in)
        });
        wait_on_thread("A's teardown and B's input to hang", || {
            stop_gate.waiting.load(Ordering::SeqCst) == 1
                && slot.gate.waiting.load(Ordering::SeqCst) >= 2
        });
        live.keeps_going_over(Duration::from_millis(150), "A's end and B's input hung");

        let (mut agent, ended_in) = tokio::time::timeout(Duration::from_secs(3), orchestrator)
            .await
            .expect("B gives up at its limit")
            .expect("the orchestrator does not panic");
        assert!(
            ended_in < Duration::from_millis(200),
            "A's end: {ended_in:?}"
        );
        assert!(
            agent.sessions.is_empty(),
            "A is gone and B never registered"
        );
        let mut sent = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            if let AgentToServer::SessionEnd {
                session_id, reason, ..
            } = msg
            {
                sent.push((session_id, reason));
            }
        }
        assert_eq!(
            sent,
            [
                ("a".to_string(), Some("superseded".to_string())),
                (
                    "b".to_string(),
                    Some(end_reason::INTERNAL_ERROR.to_string())
                ),
            ]
        );
        assert_eq!(
            script.starts.load(Ordering::SeqCst),
            1,
            "B's capture had started"
        );

        // The driver lets go: A's input closes, B's late one is closed too, B's capture stopped.
        slot.stuck.store(false, Ordering::SeqCst);
        slot.gate.open();
        wait_on_thread("both inputs to close", || {
            slot.ended.load(Ordering::SeqCst) == 2
        });
        assert_eq!(slot.begun.load(Ordering::SeqCst), 2, "A's and B's");
        wait_on_thread("B's capture to stop", || {
            script.stops.load(Ordering::SeqCst) == 1
        });
        stop_gate.open();
        wait_on_thread("A's capture to stop", || {
            script.stops.load(Ordering::SeqCst) == 2
        });
        assert_eq!(
            agent.teardowns_done(Duration::from_secs(5)).await,
            0,
            "every teardown finished"
        );
    }

    /// A's capture stop never returns, its input ends normally: B, which needs nothing of A's,
    /// starts at once and runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stuck_capture_stop_does_not_keep_the_next_session_from_starting() {
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _peer_a = live_session(&mut agent, "a");
        let stop_gate = Arc::new(Gate::default());
        agent.sessions.get_mut("a").expect("A").capturer =
            Arc::new(Mutex::new(Box::new(ScriptedCapturer {
                script: script.clone(),
                stop_gate: Some(stop_gate.clone()),
                running: true,
            }) as Box<dyn Capturer>));
        bounded(
            "B's request",
            agent.handle_server_msg(session_request("b", 42), &tx),
        )
        .await;
        let live = Liveness::start();

        let (peer, ends) = fake_peer();
        let orchestrator = tokio::spawn(async move {
            agent.end_session("a", true, "superseded", &tx);
            let t0 = Instant::now();
            agent
                .start_pipeline("b".into(), peer, 42, no_profile(), Instant::now(), &tx)
                .await;
            (agent, t0.elapsed(), tx)
        });
        let (mut agent, started_in, tx) =
            tokio::time::timeout(Duration::from_secs(3), orchestrator)
                .await
                .expect("B starts")
                .expect("the orchestrator does not panic");
        assert!(
            started_in < Duration::from_millis(300),
            "B's start: {started_in:?}"
        );
        assert!(agent.sessions.contains_key("b"), "B is running");
        assert!(!agent.sessions.contains_key("a"));
        // A's stop thread reaches its gate on its own time — maybe after B is up — and stays there
        // until the test opens it: B's start never depended on it.
        wait_on_thread("A's capture stop to hang", || {
            stop_gate.waiting.load(Ordering::SeqCst) == 1
        });
        live.keeps_going_over(Duration::from_millis(300), "A's capture stop hung");
        wait_on_thread("A's input to close", || {
            slot.ended.load(Ordering::SeqCst) == 1
        });
        assert_eq!(end_sent(&mut rx, "b"), None, "B was not ended");

        agent.end_session("b", false, "test over", &tx);
        assert!(ends.close.is_asked());
        wait_on_thread("B's capture to stop", || {
            script.stops.load(Ordering::SeqCst) >= 1
        });
        stop_gate.open();
        wait_on_thread("A's capture to stop too", || {
            script.stops.load(Ordering::SeqCst) >= 2
        });
        assert_eq!(
            agent.teardowns_done(Duration::from_secs(5)).await,
            0,
            "A's stuck stop finished once let go"
        );
        assert_eq!(stop_gate.waiting.load(Ordering::SeqCst), 0);
        assert_eq!(slot.ended.load(Ordering::SeqCst), 2);
    }

    /// What is logged on this thread (at debug and above) while the guard lives: the orchestrator's
    /// lines when the test awaits it in its own body (not spawned).
    struct LogCapture {
        buf: Arc<Mutex<Vec<u8>>>,
        _guard: tracing::dispatcher::DefaultGuard,
        _second: tracing::Dispatch,
    }

    impl LogCapture {
        fn start() -> Self {
            #[derive(Clone)]
            struct Writer(Arc<Mutex<Vec<u8>>>);
            impl std::io::Write for Writer {
                fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                    lock(&self.0).extend_from_slice(data);
                    Ok(data.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let buf = Arc::new(Mutex::new(Vec::new()));
            let writer = Writer(buf.clone());
            let ours = tracing::Dispatch::new(
                tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::DEBUG)
                    .with_ansi(false)
                    .without_time()
                    .with_writer(move || writer.clone())
                    .finish(),
            );
            // A second live dispatcher keeps tracing from caching "off" for a call site another
            // test's subscriber saw first.
            let second = tracing::Dispatch::new(tracing_subscriber::registry());
            Self {
                buf,
                _guard: tracing::dispatcher::set_default(&ours),
                _second: second,
            }
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&lock(&self.buf)).into_owned()
        }
    }

    /// The driver's lock is held by something that does not let go, and an earlier session's input
    /// end is stuck behind it: the kill switch still returns at once, ends the live session with its
    /// reason, says which teardowns are still running, and the runtime keeps going.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_kill_switch_with_the_driver_stuck_returns_at_once_and_says_what_is_left() {
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _peer_a = live_session(&mut agent, "a");
        let peer_b = live_session(&mut agent, "b");
        let live = Liveness::start();
        slot.stuck.store(true, Ordering::SeqCst);
        agent.end_session("a", true, "superseded", &tx);
        wait_on_thread("A's input end to hang", || {
            slot.gate.waiting.load(Ordering::SeqCst) >= 1
        });

        let logs = LogCapture::start();
        let t0 = Instant::now();
        bounded(
            "the kill switch",
            agent.handle_command(AgentCommand::KillSwitch, &tx),
        )
        .await;
        let took = t0.elapsed();
        let said = logs.text();
        drop(logs);
        assert!(
            took < Duration::from_millis(200),
            "the kill switch: {took:?}"
        );
        // Its release of everything is on its way, behind the driver's lock.
        wait_on_thread("the kill switch's release to start", || {
            slot.release_started.load(Ordering::SeqCst) >= 1
        });
        assert_eq!(slot.released.load(Ordering::SeqCst), 0, "not through yet");
        assert!(peer_b.close.is_asked(), "B's peer is closed");
        assert!(agent.sessions.is_empty());
        assert_eq!(
            end_sent(&mut rx, "b").as_deref(),
            Some(end_reason::KILL_SWITCH)
        );
        assert!(
            said.contains("teardowns of earlier sessions are still running")
                && said.contains("input-end (a)"),
            "{said}"
        );
        assert!(said.contains("release-all (kill switch)"), "{said}");
        live.keeps_going_over(Duration::from_millis(150), "the kill switch's release hung");

        // The driver lets go: everything the kill switch handed off finishes, its release first
        // among them (neither session pressed anything, so it is the only one).
        slot.stuck.store(false, Ordering::SeqCst);
        slot.gate.open();
        assert_eq!(
            bounded(
                "the teardowns",
                agent.teardowns_done(Duration::from_secs(5))
            )
            .await,
            0
        );
        assert_eq!(
            slot.released.load(Ordering::SeqCst),
            1,
            "the kill switch's release ran once the driver let go"
        );
        assert_eq!(
            slot.ended.load(Ordering::SeqCst),
            2,
            "both inputs' injector sessions ended"
        );
    }

    /// `fut`, or a failed test after five seconds: blocking code must fail a test, not hang the
    /// suite.
    async fn bounded<F: std::future::Future>(what: &str, fut: F) -> F::Output {
        match tokio::time::timeout(Duration::from_secs(5), fut).await {
            Ok(out) => out,
            Err(_) => panic!("{what} did not come back within five seconds"),
        }
    }

    /// The exit with the driver stuck and part of its budget already spent before it reached the
    /// orchestrator: the answer still comes within the budget — the wait for the teardowns takes
    /// only what is left of it — and the line says which are left.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_exit_with_the_driver_stuck_answers_within_its_budget_and_says_what_is_left() {
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        let (tx, _rx) = mpsc::unbounded_channel();
        let _peer_a = live_session(&mut agent, "a");
        let _peer_b = live_session(&mut agent, "b");
        slot.stuck.store(true, Ordering::SeqCst);
        agent.end_session("a", true, "superseded", &tx);

        let asked = Instant::now()
            .checked_sub(Duration::from_millis(120))
            .expect("an instant in the past");
        let (done, answer) = std::sync::mpsc::sync_channel(1);
        let logs = LogCapture::start();
        bounded(
            "the exit",
            agent.handle_command(
                AgentCommand::EndForExit {
                    why: crate::goodbye::GoodbyeReason::Quit,
                    asked,
                    budget: EXIT_END_BUDGET,
                    done,
                },
                &tx,
            ),
        )
        .await;
        let answered_after = asked.elapsed();
        let release_started = slot.release_started.load(Ordering::SeqCst);
        let said = logs.text();
        drop(logs);
        let ended = answer.try_recv().expect("answered");
        assert_eq!(ended.sessions, 1, "B ended by the exit");
        // The 100 ms wait does not come on top of what was spent (120 + the barrier's 150 + 100
        // would be 370 ms): it ends 20 ms before the budget; the slack is for a loaded machine.
        assert!(
            answered_after < EXIT_END_BUDGET + Duration::from_millis(50),
            "answered {answered_after:?} after the ask\n{said}"
        );
        assert!(
            release_started >= 1,
            "the exit's release of everything is under way before it answers"
        );
        assert!(
            said.contains("session teardowns still running")
                && said.contains("input-end (a)")
                && said.contains("input-end (b)")
                && said.contains("release-all (exit)"),
            "{said}"
        );

        slot.stuck.store(false, Ordering::SeqCst);
        slot.gate.open();
        wait_on_thread("both inputs to end", || {
            slot.ended.load(Ordering::SeqCst) == 2
        });
        wait_on_thread("the exit's release to go through", || {
            slot.released.load(Ordering::SeqCst) >= 1
        });
    }

    /// No time left in the start's budget: its steps are skipped, not started and undone — no
    /// encoder, no capture, no input — and the session ends with a reason.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_start_with_no_time_left_starts_nothing_and_ends_with_a_reason() {
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        agent.setup_limit = Duration::ZERO;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let ends = start_b(&mut agent, &tx).await;
        assert!(agent.sessions.is_empty(), "no session registered");
        assert_eq!(
            end_sent(&mut rx, "b").as_deref(),
            Some(end_reason::ENCODER_ERROR)
        );
        assert!(ends.close.is_asked(), "the peer is closed");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            script.starts.load(Ordering::SeqCst),
            0,
            "no capture started"
        );
        assert_eq!(slot.begun.load(Ordering::SeqCst), 0, "no input opened");
    }

    /// The viewer leaves while the driver's lock is held: the session's event task closes the input
    /// on a thread of its own and tells the orchestrator at once; the close finishes once the
    /// driver lets go, and the session's own end then ends nothing twice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_peers_end_with_the_driver_stuck_reaches_the_orchestrator_at_once() {
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        let mut signals = agent.sess_ev_rx.take().expect("the session signals");
        let (tx, _rx) = mpsc::unbounded_channel();
        let ends = start_b(&mut agent, &tx).await;
        assert!(agent.sessions.contains_key("b"), "B is running");
        assert_eq!(slot.begun.load(Ordering::SeqCst), 1);
        let live = Liveness::start();

        slot.stuck.store(true, Ordering::SeqCst);
        let t0 = Instant::now();
        ends.events
            .send(PeerEvent::Disconnected {
                reason: transport::PeerEnd::ViewerClosed,
            })
            .await
            .expect("the event task listens");
        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match signals.recv().await {
                    Some(SessionSignal::Closed { id, .. }) if id == "b" => break,
                    Some(_) => {}
                    None => panic!("the session signals ended"),
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "the peer's end reached the orchestrator");
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "at once: {:?}",
            t0.elapsed()
        );
        wait_on_thread("the input's close to hang on the driver", || {
            slot.gate.waiting.load(Ordering::SeqCst) >= 1
        });
        assert_eq!(slot.ended.load(Ordering::SeqCst), 0, "not closed yet");
        live.keeps_going_over(Duration::from_millis(150), "the input's close hung");

        slot.stuck.store(false, Ordering::SeqCst);
        slot.gate.open();
        wait_on_thread("the input to close", || {
            slot.ended.load(Ordering::SeqCst) == 1
        });
        agent.end_session("b", true, "peer_closed", &tx);
        assert_eq!(
            bounded(
                "the teardowns",
                agent.teardowns_done(Duration::from_secs(5))
            )
            .await,
            0
        );
        assert_eq!(
            slot.ended.load(Ordering::SeqCst),
            1,
            "the injector session is ended once"
        );
    }

    /// B's start: its request, a fake peer, the pipeline (bounded). The peer's far ends returned.
    async fn start_b(agent: &mut Agent, tx: &mpsc::UnboundedSender<AgentToServer>) -> PeerEnds {
        bounded(
            "B's request",
            agent.handle_server_msg(session_request("b", 42), tx),
        )
        .await;
        let (peer, ends) = fake_peer();
        bounded(
            "B's start",
            agent.start_pipeline("b".into(), peer, 42, no_profile(), Instant::now(), tx),
        )
        .await;
        ends
    }

    /// A viewer's key going down, as its data channel carries it.
    fn key_data() -> PeerEvent {
        PeerEvent::InputData(br#"{"t":"k","d":1,"code":"KeyW"}"#.to_vec())
    }

    /// `n` keys from B's viewer, queued for its event task.
    async fn send_keys(ends: &PeerEnds, n: usize) {
        for _ in 0..n {
            bounded("a key into the queue", ends.events.send(key_data()))
                .await
                .expect("the event task listens");
        }
    }

    /// How a session's end comes about, for the tests of what may still be injected after it.
    #[derive(Clone, Copy)]
    enum Ending {
        EndSession,
        KillSwitch,
        /// `device_blocked` (`Agent::end_for_block`).
        Blocked,
        /// `replaced` in the CLI (`Agent::stop_after_replaced`), its bounded teardown wait included.
        Replaced,
    }

    impl Ending {
        /// How long the end may take with the driver stuck: at once, except the CLI's stop after
        /// `replaced`, which waits for the teardowns (asynchronously) at most its bound.
        fn limit(self) -> Duration {
            match self {
                Self::Replaced => REPLACED_TEARDOWN_WAIT + Duration::from_millis(300),
                Self::EndSession | Self::KillSwitch | Self::Blocked => Duration::from_millis(200),
            }
        }

        /// Releases of everything this end asks for besides each session's own (its gate's close).
        fn releases_of_all(self) -> u32 {
            match self {
                Self::EndSession => 0,
                Self::KillSwitch | Self::Blocked | Self::Replaced => 1,
            }
        }
    }

    async fn end_b(agent: &mut Agent, how: Ending, tx: &mpsc::UnboundedSender<AgentToServer>) {
        match how {
            Ending::EndSession => agent.end_session("b", true, "superseded", tx),
            Ending::KillSwitch => {
                bounded(
                    "the kill switch",
                    agent.handle_command(AgentCommand::KillSwitch, tx),
                )
                .await;
            }
            Ending::Blocked => agent.end_for_block(tx),
            Ending::Replaced => {
                bounded("the stop after replaced", agent.stop_after_replaced(tx)).await;
            }
        }
    }

    /// Lets the driver go after five seconds, should the code under test block the test's own
    /// thread on it (a synchronous wait inside a poll, which no timer can bound): the test then
    /// fails on its timing instead of hanging the suite.
    fn rescue_after_five_seconds(slot: &Arc<DriverSlot>) {
        let slot = slot.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(5));
            slot.stuck.store(false, Ordering::SeqCst);
            slot.gate.open();
        });
    }

    /// Negative: no viewer event is injected once the session's end has returned, with events
    /// still queued — at most the one already inside the injector at that moment.
    async fn nothing_injected_after_the_end(how: Ending) {
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        let (tx, _rx) = mpsc::unbounded_channel();
        let ends = start_b(&mut agent, &tx).await;
        assert!(agent.sessions.contains_key("b"), "B is running");
        send_keys(&ends, 40).await;
        end_b(&mut agent, how, &tx).await;
        let at_end = slot.inject_started.load(Ordering::SeqCst);
        // More keys after the end (the event task may be gone: then they go nowhere), and time for
        // it to try them all.
        for _ in 0..10 {
            if ends.events.send(key_data()).await.is_err() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let after = slot.inject_started.load(Ordering::SeqCst);
        assert!(
            after <= at_end + 1,
            "events injected after the end returned: {at_end} then {after}"
        );
        wait_on_thread("the input to close", || {
            slot.ended.load(Ordering::SeqCst) == 1
        });
        assert_eq!(
            bounded(
                "the teardowns",
                agent.teardowns_done(Duration::from_secs(5))
            )
            .await,
            0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_event_is_injected_after_end_session_returns() {
        nothing_injected_after_the_end(Ending::EndSession).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_event_is_injected_after_the_kill_switch_returns() {
        nothing_injected_after_the_end(Ending::KillSwitch).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_event_is_injected_after_device_blocked_ends_the_session() {
        nothing_injected_after_the_end(Ending::Blocked).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_event_is_injected_after_the_stop_after_replaced() {
        nothing_injected_after_the_end(Ending::Replaced).await;
    }

    /// Negative: an injection is stuck inside the driver (its lock held) with more of the viewer's
    /// keys queued behind it, and the session is ended: the end returns at once; once the driver
    /// lets go only that one key lands, none of the queued ones, and what it pressed is released.
    async fn only_the_inflight_event_lands_after_a_stuck_end(how: Ending) {
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        let (tx, _rx) = mpsc::unbounded_channel();
        let ends = start_b(&mut agent, &tx).await;
        let input = agent.sessions.get("b").expect("B is running").input.clone();
        slot.stuck.store(true, Ordering::SeqCst);
        rescue_after_five_seconds(&slot);
        send_keys(&ends, 1).await;
        wait_on_thread("the key to hang inside the driver", || {
            slot.inject_started.load(Ordering::SeqCst) == 1
        });
        send_keys(&ends, 5).await;
        let live = Liveness::start();
        let logs = LogCapture::start();
        let t0 = Instant::now();
        end_b(&mut agent, how, &tx).await;
        let took = t0.elapsed();
        let said = logs.text();
        drop(logs);
        assert!(took < how.limit(), "the end: {took:?}");
        if let Ending::Replaced = how {
            // It did wait for the release, as long as its bound, and said what it left behind.
            assert!(
                took + Duration::from_millis(50) >= REPLACED_TEARDOWN_WAIT,
                "waited for the teardowns: {took:?}"
            );
            assert!(
                said.contains("session teardowns still running")
                    && said.contains("release-all (replaced)"),
                "{said}"
            );
        }
        assert!(agent.sessions.is_empty(), "B is ended");
        // Refused at the end's return: inactive with the gate's close still stuck behind the
        // driver (the refusal flag is read first, without the gate's lock).
        assert!(!input.is_active(), "B's input is refused");
        assert_eq!(slot.injected.load(Ordering::SeqCst), 0, "still inside");
        // The release of everything is on its way, behind the driver's lock, not waited for.
        if how.releases_of_all() > 0 {
            wait_on_thread("the release of everything to start", || {
                slot.release_started.load(Ordering::SeqCst) >= 1
            });
            assert_eq!(slot.released.load(Ordering::SeqCst), 0, "not through yet");
        }
        live.keeps_going_over(Duration::from_millis(150), "the end hung the runtime");

        slot.stuck.store(false, Ordering::SeqCst);
        slot.gate.open();
        // The gate's close releases the key it pressed; and the release of everything, handed off
        // before it, when the end asks for one.
        let releases = 1 + how.releases_of_all();
        wait_on_thread("the input to close and release", || {
            slot.ended.load(Ordering::SeqCst) == 1
                && slot.released.load(Ordering::SeqCst) == releases
        });
        assert_eq!(
            bounded(
                "the teardowns",
                agent.teardowns_done(Duration::from_secs(5))
            )
            .await,
            0
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            slot.inject_started.load(Ordering::SeqCst),
            1,
            "none of the queued keys was tried"
        );
        assert_eq!(
            slot.injected.load(Ordering::SeqCst),
            1,
            "the one in flight landed"
        );
        assert_eq!(slot.released.load(Ordering::SeqCst), releases);
        assert_eq!(slot.ended.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stuck_injection_at_end_session_lets_only_itself_land() {
        only_the_inflight_event_lands_after_a_stuck_end(Ending::EndSession).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stuck_injection_at_the_kill_switch_lets_only_itself_land() {
        only_the_inflight_event_lands_after_a_stuck_end(Ending::KillSwitch).await;
    }

    /// `device_blocked` with the driver stuck: the orchestrator does not wait on it (calling
    /// `release_all` itself, it would freeze with the driver).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stuck_injection_at_device_blocked_lets_only_itself_land() {
        only_the_inflight_event_lands_after_a_stuck_end(Ending::Blocked).await;
    }

    /// `replaced` in the CLI with the driver stuck: the stop waits for the release at most its
    /// bound, without holding a thread, and the agent stops.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stuck_injection_at_the_stop_after_replaced_lets_only_itself_land() {
        only_the_inflight_event_lands_after_a_stuck_end(Ending::Replaced).await;
    }

    /// Negative: an input that opens after its start gave up is never handed to a session — it
    /// takes no event — and is closed, so the driver's session count balances.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_input_that_opens_after_its_start_gave_up_takes_nothing_and_is_closed() {
        let _serial = INPUT_OPEN_STUCK.lock().await;
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        let (tx, mut rx) = mpsc::unbounded_channel();
        slot.stuck.store(true, Ordering::SeqCst);
        let ends = start_b(&mut agent, &tx).await;
        assert!(agent.sessions.is_empty(), "B gave up");
        assert_eq!(
            end_sent(&mut rx, "b").as_deref(),
            Some(end_reason::INTERNAL_ERROR)
        );
        // The viewer's keys go nowhere: no event task was ever made for this input.
        assert!(
            ends.events.send(key_data()).await.is_err(),
            "nothing receives the viewer's events"
        );
        slot.stuck.store(false, Ordering::SeqCst);
        slot.gate.open();
        wait_on_thread("the late input to be closed", || {
            slot.ended.load(Ordering::SeqCst) == 1
        });
        assert_eq!(slot.begun.load(Ordering::SeqCst), 1);
        assert_eq!(
            slot.inject_started.load(Ordering::SeqCst),
            0,
            "it took no event"
        );
    }

    /// The encoder takes nearly the whole budget: the capture's start is not begun (nothing to
    /// stop), the session ends with `capture_error`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_capture_start_with_no_time_left_is_not_begun() {
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        *lock(&script.encoder_takes) = Duration::from_millis(260);
        let (mut agent, _control) = stuck_rig(&slot, &script);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _ends = start_b(&mut agent, &tx).await;
        assert!(agent.sessions.is_empty());
        assert_eq!(
            end_sent(&mut rx, "b").as_deref(),
            Some(end_reason::CAPTURE_ERROR)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(script.starts.load(Ordering::SeqCst), 0, "no capture begun");
        assert_eq!(slot.begun.load(Ordering::SeqCst), 0, "no input opened");
    }

    /// The capture's start takes nearly the whole budget: the input is not opened, the capture
    /// that did start is stopped, and the session ends with `internal_error`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_input_open_with_no_time_left_is_not_begun_and_the_capture_is_stopped() {
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        *lock(&script.start_takes) = Duration::from_millis(260);
        let (mut agent, _control) = stuck_rig(&slot, &script);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _ends = start_b(&mut agent, &tx).await;
        assert!(agent.sessions.is_empty());
        assert_eq!(
            end_sent(&mut rx, "b").as_deref(),
            Some(end_reason::INTERNAL_ERROR)
        );
        assert_eq!(
            script.starts.load(Ordering::SeqCst),
            1,
            "the capture had started"
        );
        wait_on_thread("the capture to be stopped", || {
            script.stops.load(Ordering::SeqCst) == 1
        });
        assert_eq!(slot.begun.load(Ordering::SeqCst), 0, "no input opened");
    }

    /// An earlier start's input opening is still stuck on the driver: with the bound at one, the
    /// next start is refused at once — nothing made, nothing waited for — with `internal_error`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_start_is_refused_at_once_while_earlier_input_openings_are_stuck() {
        let _serial = INPUT_OPEN_STUCK.lock().await;
        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        let (tx, mut rx) = mpsc::unbounded_channel();
        slot.stuck.store(true, Ordering::SeqCst);
        let _first = start_b(&mut agent, &tx).await;
        assert_eq!(
            end_sent(&mut rx, "b").as_deref(),
            Some(end_reason::INTERNAL_ERROR)
        );
        assert!(
            crate::offload::running("input-open") >= 1,
            "B's opening is stuck"
        );
        let starts_before = script.starts.load(Ordering::SeqCst);

        agent.start_refuse_stuck = 1;
        bounded(
            "C's request",
            agent.handle_server_msg(session_request("c", 42), &tx),
        )
        .await;
        let (peer, ends) = fake_peer();
        let t0 = Instant::now();
        bounded(
            "C's start",
            agent.start_pipeline("c".into(), peer, 42, no_profile(), Instant::now(), &tx),
        )
        .await;
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "refused at once: {:?}",
            t0.elapsed()
        );
        assert_eq!(
            end_sent(&mut rx, "c").as_deref(),
            Some(end_reason::INTERNAL_ERROR)
        );
        assert!(ends.close.is_asked());
        assert_eq!(
            script.starts.load(Ordering::SeqCst),
            starts_before,
            "no capture started for C"
        );

        slot.stuck.store(false, Ordering::SeqCst);
        slot.gate.open();
        wait_on_thread("B's late input to be closed", || {
            slot.ended.load(Ordering::SeqCst) == 1
        });
    }

    /// The tests that leave an input opening stuck on purpose (process-wide counts), and the one
    /// that needs those counts low, take turns.
    static INPUT_OPEN_STUCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Three capture stops stuck past their error bound: the next session still
    /// starts — only the input driver's stuck jobs refuse starts, and its input works.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stuck_capture_jobs_do_not_refuse_a_start() {
        let _serial = INPUT_OPEN_STUCK.lock().await;
        let gate = Arc::new(Gate::default());
        let mut stuck = Vec::new();
        for _ in 0..3 {
            stuck.push(
                bounded(
                    "a capture stop to be abandoned",
                    crate::offload::tests::abandoned_job("capture-stop", gate.clone()),
                )
                .await,
            );
        }
        assert!(crate::offload::abandoned_of("capture-stop") >= 3);

        let slot = Arc::new(DriverSlot::default());
        let script = Arc::new(CaptureScript::default());
        let (mut agent, _control) = stuck_rig(&slot, &script);
        agent.start_refuse_stuck = START_REFUSE_STUCK;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _ends = start_b(&mut agent, &tx).await;
        assert!(agent.sessions.contains_key("b"), "B started");
        assert_eq!(end_sent(&mut rx, "b"), None, "B was not refused");
        assert_eq!(slot.begun.load(Ordering::SeqCst), 1, "B's input opened");

        agent.end_session("b", false, "test over", &tx);
        gate.open();
        for job in stuck {
            assert!(job.wait(Duration::from_secs(5)).await);
        }
        assert_eq!(
            bounded(
                "the teardowns",
                agent.teardowns_done(Duration::from_secs(5))
            )
            .await,
            0
        );
    }
}
