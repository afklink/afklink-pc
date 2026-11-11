//! Clipboard sync for one session: the PC's clipboard to the viewer and back, text only.
//!
//! The wire, the limits and the chunking are the contract's (`afklink_protocol::clipboard`). This
//! is the agent's side of the flow:
//!
//! - **Off until the viewer asks.** Nothing is read or written until the viewer sends `cb_sync` with
//!   `on: true` (its browser's own switch); every `cb_sync` gets a `cb_state` answer.
//! - **The viewer's text on its paste.** A `cb_set` text is put on the PC's clipboard and answered
//!   with one `cb_ack` after the write: the website sends one only as part of a paste its guest
//!   makes, and holds the V press until that answer, so the PC pastes the text just written. The
//!   agent does nothing else for that side — no reading of the viewer's clipboard is ever asked.
//! - **Towards the PC only in «Только игра».** While the owner has the game-only mode on, whoever
//!   connects may see the game and nothing else: nothing of the PC's clipboard leaves it — not read,
//!   not watched, no `cb_pc`, and a `cb_pc` text still queued for the peer is taken back
//!   ([`PeerControl::RevokeQueued`]; the viewer's joiner abandons an unfinished one) — while the
//!   viewer's text still goes to the PC; `cb_state` says `pc: to_pc_only`. A flip is handled at once
//!   (the mode is looked at every second, and again right before anything is sent or written), and
//!   the viewer is told each time. Turned off again, the PC's changes from then on go to the
//!   viewer — never what was on its clipboard at the flip.
//! - **Changes only.** The PC's clipboard goes to the viewer when it changes after sync was turned
//!   on (or game-only off) — never what was on it before.
//! - **No echo.** A text this session put on the clipboard does not come back to its viewer: the
//!   clipboard's sequence number after each write is remembered, and a change with it is skipped.
//!   A text the same as the last one that crossed, either way, is not sent again either. Both hold
//!   across game-only flips (a text written in game-only mode is the last that crossed).
//! - **Off when the session ends**: this task ends with it, and with it the subscription.
//!
//! Never logged: the text. Lines carry sizes, chunk counts, ids, sequence numbers and the decision.
//!
//! The platform's clipboard is [`ClipboardBackend`] (`afklink_clipboard` on Windows); without one
//! (the CLI's bench, tests) the PC says `unavailable`.

use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use afklink_protocol::clipboard::{chunks, Joined, Joiner, CLIPBOARD_CHUNK_TEXT_BYTES};
use afklink_protocol::{
    AgentDataMessage, ClipboardAck, ClipboardChunk, ClipboardPc, ClipboardRefusal, ClipboardState,
    CLIPBOARD_MAX_BYTES, INPUT_MAX_BYTES,
};
use afklink_transport::PeerControl;
use tokio::sync::{broadcast, mpsc};

use crate::game::CaptureModeCell;

/// A change of the PC's clipboard, by anyone: its sequence number after the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardChange {
    pub seq: u32,
}

/// What is on the clipboard, as [`ClipboardBackend::read_text`] found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardContent {
    /// Text (`CF_UNICODETEXT`), up to its first NUL.
    Text(String),
    /// Text longer than [`CLIPBOARD_MAX_BYTES`] can be in UTF-8, never read whole: its length in
    /// UTF-16 units.
    TooLarge { units: usize },
    /// No text: an image, files, or nothing. How many formats it holds.
    NotText { formats: u32 },
}

/// Why the clipboard could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClipboardError {
    /// Another program held the clipboard open through every attempt.
    #[error(
        "the clipboard stayed open by another program ({attempts} attempts over {waited_ms} ms)"
    )]
    Busy { attempts: u32, waited_ms: u64 },
    /// Anything else Windows refused, said.
    #[error("{0}")]
    Failed(String),
}

/// The PC's clipboard. Implemented by `afklink_clipboard` on Windows.
pub trait ClipboardBackend: Send + Sync {
    /// Watch the clipboard: from now on every change is a [`ClipboardChange`] on the receiver
    /// returned (a broadcast: each session that watches gets each). Starts the platform's listener
    /// on first use; an error means this PC's clipboard cannot be watched.
    fn watch(&self) -> Result<broadcast::Receiver<ClipboardChange>, String>;

    /// The clipboard's text now. Blocking: it may wait, briefly, for another program to close the
    /// clipboard. Reads no more than [`CLIPBOARD_MAX_BYTES`] can need.
    fn read_text(&self) -> Result<ClipboardContent, ClipboardError>;

    /// Put `text` on the clipboard as text, replacing what is there. Blocking, as
    /// [`Self::read_text`]. The clipboard's sequence number after the write: the change it causes
    /// carries it.
    fn write_text(&self, text: &str) -> Result<u32, ClipboardError>;
}

/// What the viewer said about the clipboard, handed from the session's event task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewerClipboard {
    /// `cb_sync`.
    Sync(bool),
    /// `cb_set`, one chunk.
    Set(ClipboardChunk),
}

/// How many of the viewer's clipboard messages may wait for the task: a 64 KiB text is at most 99
/// chunks, so a burst of one text never overflows it; a flood is dropped and said.
const VIEWER_QUEUE: usize = 256;

/// How often the task looks at the game-only mode by itself.
const MODE_TICK: Duration = Duration::from_secs(1);

/// How many of this session's own writes are remembered for the echo check.
const OWN_WRITES: usize = 8;

/// Start the clipboard task of session `sid`. The sender takes the viewer's `cb_sync`/`cb_set`;
/// dropping it (the session's event task ends) or `stop` ends the task, and the subscription with
/// it.
pub fn spawn_session(
    sid: String,
    backend: Option<Arc<dyn ClipboardBackend>>,
    capture_mode: Arc<CaptureModeCell>,
    control_tx: mpsc::Sender<PeerControl>,
    stop: Arc<AtomicBool>,
) -> mpsc::Sender<ViewerClipboard> {
    let (tx, rx) = mpsc::channel(VIEWER_QUEUE);
    let session = Session::new(sid, backend, capture_mode, control_tx);
    tokio::spawn(session.run(rx, stop));
    tx
}

/// What crossed this session, for its last line. Counts and sizes only.
#[derive(Debug, Default)]
struct Tally {
    set: u64,
    set_bytes: u64,
    /// Of `set`: written while the PC was in game-only mode (towards the PC only).
    set_to_pc_only: u64,
    set_refused: u64,
    sent: u64,
    sent_bytes: u64,
    skipped: u64,
    /// Times what was still queued of the PC's texts was taken back (PC → viewer stopped).
    revoked: u64,
    /// Game-only flips seen during the session.
    flips: u64,
}

/// The last `cb_pc` text handed to the peer since PC → viewer last stopped: what a stop may cut
/// short. For the log.
#[derive(Debug, Clone, Copy)]
struct PcTextOut {
    id: u32,
    chunks: usize,
    bytes: usize,
    at: std::time::Instant,
}

/// The PC's clipboard is watched (and its text goes to the viewer) only in `state`: sync on, and
/// the PC giving its text (`ready`, not `to_pc_only` or `unavailable`).
fn watches(state: ClipboardState) -> bool {
    state.on && state.pc.gives_text()
}

/// One session's clipboard sync.
struct Session {
    sid: String,
    backend: Option<Arc<dyn ClipboardBackend>>,
    capture_mode: Arc<CaptureModeCell>,
    control_tx: mpsc::Sender<PeerControl>,
    /// The viewer asked for sync (its last `cb_sync`).
    wanted: bool,
    /// The viewer has spoken about the clipboard: only then does a change on the PC send a
    /// `cb_state` of its own (an older viewer has nothing to show it with).
    spoken: bool,
    /// The game-only mode as last seen.
    game_only: bool,
    /// The clipboard could not be watched (the backend's `watch` failed, or there is no backend).
    unavailable: bool,
    /// The clipboard's listener (which also writes) answered a `watch` in this session.
    listener_up: bool,
    /// The last `cb_state` sent.
    said: Option<ClipboardState>,
    /// While on both ways: the clipboard's changes.
    watch: Option<broadcast::Receiver<ClipboardChange>>,
    /// The last `cb_pc` text handed to the peer since PC → viewer last stopped.
    pc_out: Option<PcTextOut>,
    joiner: Joiner,
    /// The next `cb_pc` text's id.
    next_id: u32,
    /// Sequence numbers this session's writes left: their changes are its own echo.
    own_writes: VecDeque<u32>,
    /// The last change handled: the listener can say one change twice.
    last_seq: Option<u32>,
    /// A digest of the last text that crossed, either way (in Windows' line breaks).
    last_text: Option<u64>,
    tally: Tally,
}

impl Session {
    fn new(
        sid: String,
        backend: Option<Arc<dyn ClipboardBackend>>,
        capture_mode: Arc<CaptureModeCell>,
        control_tx: mpsc::Sender<PeerControl>,
    ) -> Self {
        let game_only = capture_mode.is_game();
        Self {
            sid,
            unavailable: backend.is_none(),
            backend,
            capture_mode,
            control_tx,
            wanted: false,
            spoken: false,
            game_only,
            listener_up: false,
            said: None,
            watch: None,
            pc_out: None,
            joiner: Joiner::new(),
            next_id: 0,
            own_writes: VecDeque::with_capacity(OWN_WRITES),
            last_seq: None,
            last_text: None,
            tally: Tally::default(),
        }
    }

    /// Which way the PC allows sync now. A clipboard that cannot be reached comes first: its
    /// listener also writes, so game-only mode cannot take text either then.
    fn pc(&self) -> ClipboardPc {
        if self.unavailable {
            ClipboardPc::Unavailable
        } else if self.game_only {
            ClipboardPc::ToPcOnly
        } else {
            ClipboardPc::Ready
        }
    }

    fn state(&self) -> ClipboardState {
        let pc = self.pc();
        ClipboardState {
            on: self.wanted && pc.takes_text(),
            pc,
        }
    }

    /// Look at the game-only mode now; a flip is said, with what it does to each way.
    fn look_at_mode(&mut self, why: &str) {
        let was = self.game_only;
        self.game_only = self.capture_mode.is_game();
        if was == self.game_only {
            return;
        }
        self.tally.flips += 1;
        tracing::debug!(
            session = %self.sid,
            game_only = self.game_only,
            wanted = self.wanted,
            watching = self.watch.is_some(),
            why,
            "clipboard: the game-only mode flipped on the PC: {}",
            if self.game_only {
                "PC → viewer stops at once (nothing read, a text still queued taken back); the \
                 viewer's text still goes to the PC"
            } else {
                "PC → viewer resumes with the clipboard's changes from now on, never what is on it \
                 now; the viewer's text goes to the PC as before"
            }
        );
    }

    async fn run(mut self, mut viewer: mpsc::Receiver<ViewerClipboard>, stop: Arc<AtomicBool>) {
        tracing::debug!(
            session = %self.sid,
            backend = self.backend.is_some(),
            game_only = self.game_only,
            "clipboard: the session's task is up; off until the viewer turns sync on"
        );
        let mut tick = tokio::time::interval(MODE_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let why = loop {
            tokio::select! {
                msg = viewer.recv() => match msg {
                    Some(ViewerClipboard::Sync(on)) => self.on_sync(on).await,
                    Some(ViewerClipboard::Set(chunk)) => self.on_set(chunk).await,
                    None => break "the session's input task ended",
                },
                change = next_change(&mut self.watch) => self.on_change(change).await,
                _ = tick.tick() => {
                    if stop.load(Ordering::SeqCst) {
                        break "the session ended";
                    }
                    self.refresh("the game-only mode changed on the PC").await;
                }
            }
        };
        self.watch = None;
        let t = &self.tally;
        tracing::debug!(
            session = %self.sid,
            why,
            wanted = self.wanted,
            game_only = self.game_only,
            set = t.set,
            set_bytes = t.set_bytes,
            set_to_pc_only = t.set_to_pc_only,
            set_refused = t.set_refused,
            sent = t.sent,
            sent_bytes = t.sent_bytes,
            skipped = t.skipped,
            revoked = t.revoked,
            flips = t.flips,
            "clipboard: the session's task ends; nothing more is read or written for it"
        );
    }

    /// Look at the game-only mode now; when the state changed, start or stop watching and — to a
    /// viewer that spoke about the clipboard — say so. `why` names the occasion for the log.
    async fn refresh(&mut self, why: &str) {
        self.look_at_mode(why);
        let wanted = self.state();
        if self.said == Some(wanted) && self.watch.is_some() == watches(wanted) {
            return;
        }
        self.follow(wanted, why).await;
        // Watching (or the listener's check) may have just failed.
        let state = self.state();
        if self.spoken && self.said != Some(state) {
            tracing::info!(
                session = %self.sid,
                on = state.on,
                pc = state.pc.as_str(),
                wanted = self.wanted,
                game_only = self.game_only,
                why,
                "clipboard: sync state changed on the PC; the viewer is told"
            );
            self.say(state).await;
        }
    }

    /// Watch the clipboard while `state` lets the PC's text go to the viewer, and not otherwise;
    /// on towards the PC only, make sure the listener (which writes) is up. `why` for the log.
    async fn follow(&mut self, state: ClipboardState, why: &str) {
        if !watches(state) {
            if self.watch.take().is_some() {
                tracing::debug!(
                    session = %self.sid,
                    on = state.on,
                    pc = state.pc.as_str(),
                    wanted = self.wanted,
                    why,
                    "clipboard: watching stops; the PC's clipboard is not read for this session"
                );
            }
            self.revoke_pc_text(state, why).await;
            if state.on && !self.listener_up {
                self.check_listener().await;
            }
            return;
        }
        if self.watch.is_some() {
            return;
        }
        let Some(backend) = self.backend.clone() else {
            self.unavailable = true;
            return;
        };
        match backend.watch() {
            Ok(rx) => {
                tracing::debug!(
                    session = %self.sid,
                    why,
                    "clipboard: watching starts; changes from now on go to the viewer, never what \
                     is on the clipboard now"
                );
                // What happened before is not this session's business: changes from here on.
                self.listener_up = true;
                self.last_seq = None;
                self.watch = Some(rx);
            }
            Err(e) => {
                tracing::warn!(
                    session = %self.sid,
                    "clipboard: this PC's clipboard cannot be watched ({e}); sync is unavailable"
                );
                self.unavailable = true;
            }
        }
    }

    /// PC → viewer stopped (game-only mode, the viewer's switch, the listener gone): what is still
    /// queued for the peer of the PC's texts handed since the last stop goes unsent. A text cut
    /// short is abandoned by the viewer's joiner at the next one.
    async fn revoke_pc_text(&mut self, state: ClipboardState, why: &str) {
        let Some(out) = self.pc_out.take() else {
            return;
        };
        self.tally.revoked += 1;
        tracing::debug!(
            session = %self.sid,
            id = out.id,
            chunks = out.chunks,
            bytes = out.bytes,
            handed_ms = out.at.elapsed().as_millis() as u64,
            pc = state.pc.as_str(),
            on = state.on,
            why,
            "clipboard: PC → viewer stopped: what is still queued of the PC's text is taken back \
             unsent (the peer says how much); one cut short is abandoned by the viewer's joiner"
        );
        if self
            .control_tx
            .send(PeerControl::RevokeQueued)
            .await
            .is_err()
        {
            tracing::debug!(
                session = %self.sid,
                "clipboard: nothing to take back, the peer has ended"
            );
        }
    }

    /// Towards the PC only: no watching, but the listener writes the viewer's text — start it now
    /// (a subscription dropped at once), so a PC whose clipboard cannot be reached says
    /// `unavailable` rather than refusing each text.
    async fn check_listener(&mut self) {
        let Some(backend) = self.backend.clone() else {
            self.unavailable = true;
            return;
        };
        match backend.watch() {
            Ok(rx) => {
                drop(rx);
                self.listener_up = true;
                tracing::debug!(
                    session = %self.sid,
                    "clipboard: the clipboard's listener is up (it writes the viewer's text); its \
                     changes are not watched in game-only mode"
                );
            }
            Err(e) => {
                tracing::warn!(
                    session = %self.sid,
                    "clipboard: this PC's clipboard cannot be reached ({e}); sync is unavailable"
                );
                self.unavailable = true;
            }
        }
    }

    /// Send `state` to the viewer and remember it.
    async fn say(&mut self, state: ClipboardState) {
        self.said = Some(state);
        self.send(vec![AgentDataMessage::ClipboardState(state)], "cb_state")
            .await;
    }

    async fn on_sync(&mut self, on: bool) {
        self.spoken = true;
        self.wanted = on;
        self.look_at_mode("the viewer's cb_sync");
        // Each time the viewer turns it on, a listener that failed before gets another chance.
        if on && self.unavailable && self.backend.is_some() {
            tracing::debug!(session = %self.sid, "clipboard: watching is tried again");
            self.unavailable = false;
            self.listener_up = false;
        }
        let mut state = self.state();
        self.follow(state, "the viewer's cb_sync").await;
        // Watching (or the listener's check) may have just failed.
        state = self.state();
        tracing::info!(
            session = %self.sid,
            asked = on,
            on = state.on,
            pc = state.pc.as_str(),
            game_only = self.game_only,
            "clipboard: the viewer {} sync; answered ({})",
            if on { "turned on" } else { "turned off" },
            match (state.on, state.pc) {
                (true, ClipboardPc::Ready) => "both ways",
                (true, _) => "towards the PC only: game-only mode",
                (false, ClipboardPc::Unavailable) => "off: the clipboard cannot be reached",
                (false, _) => "off: the viewer's switch",
            }
        );
        if !on {
            if let Some((id, joined, of)) = self.joiner.under_way() {
                self.joiner.refuse(id);
                tracing::debug!(
                    session = %self.sid,
                    id,
                    joined,
                    of,
                    "clipboard: a viewer's text under way dropped: sync turned off"
                );
            }
        }
        self.say(state).await;
    }

    /// A refusal for the text `id`, unless that text was refused already.
    async fn refuse(&mut self, id: u32, why: ClipboardRefusal, bytes: usize) {
        if !self.joiner.refuse(id) {
            tracing::trace!(session = %self.sid, id, why = why.as_str(), "clipboard: another chunk of a refused text");
            return;
        }
        self.ack(ClipboardAck::refused(id, why), bytes).await;
    }

    async fn ack(&mut self, ack: ClipboardAck, bytes: usize) {
        if ack.ok {
            self.tally.set += 1;
            self.tally.set_bytes += bytes as u64;
        } else {
            self.tally.set_refused += 1;
        }
        tracing::debug!(
            session = %self.sid,
            id = ack.id,
            ok = ack.ok,
            why = ack.why.map_or("-", ClipboardRefusal::as_str),
            bytes,
            "clipboard: the viewer's text answered"
        );
        self.send(vec![AgentDataMessage::ClipboardAck(ack)], "cb_ack")
            .await;
    }

    async fn on_set(&mut self, chunk: ClipboardChunk) {
        let (id, bytes) = (chunk.id, chunk.text.len());
        self.refresh("the viewer sent a text").await;
        let pc = self.pc();
        if !self.wanted {
            return self.refuse(id, ClipboardRefusal::Off, bytes).await;
        }
        // Game-only mode takes the viewer's text as ever (`to_pc_only`): only a clipboard that
        // cannot be reached refuses it.
        if !pc.takes_text() {
            return self.refuse(id, ClipboardRefusal::Failed, bytes).await;
        }
        // A chunk is one DataChannel message: its text can never be longer than one.
        if bytes > INPUT_MAX_BYTES {
            tracing::debug!(
                session = %self.sid,
                id,
                bytes,
                max = INPUT_MAX_BYTES,
                "clipboard: a chunk longer than one message can be"
            );
            return self.refuse(id, ClipboardRefusal::Malformed, bytes).await;
        }
        match self.joiner.accept(&chunk) {
            Joined::Partial => tracing::trace!(
                session = %self.sid,
                id,
                i = chunk.i,
                n = chunk.n,
                bytes,
                pc = pc.as_str(),
                "clipboard: a chunk of the viewer's text"
            ),
            Joined::Ignored => tracing::trace!(
                session = %self.sid,
                id,
                "clipboard: a chunk of a text already dropped"
            ),
            Joined::Dropped { id, why } => {
                tracing::debug!(
                    session = %self.sid,
                    id,
                    i = chunk.i,
                    n = chunk.n,
                    why = why.as_str(),
                    "clipboard: the viewer's text dropped"
                );
                self.ack(ClipboardAck::refused(id, why), bytes).await;
            }
            Joined::Done { id, text } => self.write(id, text).await,
        }
    }

    /// Put the viewer's whole text `id` on the PC's clipboard, in Windows' line breaks, and answer.
    async fn write(&mut self, id: u32, text: String) {
        // Once more right before the clipboard is touched: the mode may have changed this second
        // (either way the viewer's text goes; only sync off or an unreachable clipboard stop it).
        self.refresh("a viewer's text is about to be written").await;
        let pc = self.pc();
        if !pc.takes_text() || !self.wanted {
            let why = if !self.wanted {
                ClipboardRefusal::Off
            } else {
                ClipboardRefusal::Failed
            };
            tracing::debug!(
                session = %self.sid,
                id,
                bytes = text.len(),
                wanted = self.wanted,
                pc = pc.as_str(),
                why = why.as_str(),
                "clipboard: the viewer's whole text not written: sync went off while it came"
            );
            return self.ack(ClipboardAck::refused(id, why), text.len()).await;
        }
        let Some(backend) = self.backend.clone() else {
            return self
                .ack(
                    ClipboardAck::refused(id, ClipboardRefusal::Failed),
                    text.len(),
                )
                .await;
        };
        let windows = windows_newlines(&text).into_owned();
        let (chars, bytes) = (windows.chars().count(), windows.len());
        let digest = digest(&windows);
        let started = std::time::Instant::now();
        let written = tokio::task::spawn_blocking(move || backend.write_text(&windows)).await;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match written {
            Ok(Ok(seq)) => {
                if self.own_writes.len() == OWN_WRITES {
                    self.own_writes.pop_front();
                }
                self.own_writes.push_back(seq);
                self.last_text = Some(digest);
                if pc == ClipboardPc::ToPcOnly {
                    self.tally.set_to_pc_only += 1;
                }
                tracing::debug!(
                    session = %self.sid,
                    id,
                    chars,
                    bytes,
                    seq,
                    elapsed_ms,
                    pc = pc.as_str(),
                    "clipboard: the viewer's text is on the PC's clipboard{}; answered (the \
                     viewer's held V press goes on it)",
                    if pc == ClipboardPc::ToPcOnly {
                        " (game-only mode: towards the PC only)"
                    } else {
                        ""
                    }
                );
                self.ack(ClipboardAck::ok(id), bytes).await;
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    session = %self.sid,
                    id,
                    bytes,
                    elapsed_ms,
                    "clipboard: the viewer's text was not written: {e}"
                );
                self.ack(ClipboardAck::refused(id, ClipboardRefusal::Failed), bytes)
                    .await;
            }
            Err(e) => {
                tracing::warn!(
                    session = %self.sid,
                    id,
                    "clipboard: the write's task failed: {e}"
                );
                self.ack(ClipboardAck::refused(id, ClipboardRefusal::Failed), bytes)
                    .await;
            }
        }
    }

    /// The PC's clipboard changed (or the subscription lagged and a change may be missed).
    async fn on_change(&mut self, change: Result<ClipboardChange, broadcast::error::RecvError>) {
        let seq = match change {
            Ok(change) => Some(change.seq),
            Err(broadcast::error::RecvError::Lagged(missed)) => {
                tracing::debug!(
                    session = %self.sid,
                    missed,
                    "clipboard: changes came faster than they were read; reading the newest"
                );
                None
            }
            Err(broadcast::error::RecvError::Closed) => {
                tracing::warn!(
                    session = %self.sid,
                    "clipboard: the clipboard's listener stopped; sync is unavailable"
                );
                self.watch = None;
                self.unavailable = true;
                self.refresh("the clipboard's listener stopped").await;
                return;
            }
        };
        if let Some(seq) = seq {
            if self.own_writes.contains(&seq) {
                tracing::debug!(
                    session = %self.sid,
                    seq,
                    "clipboard: the change is this session's own write; not sent back"
                );
                return;
            }
            if self.last_seq == Some(seq) {
                tracing::trace!(session = %self.sid, seq, "clipboard: the same change again");
                return;
            }
            self.last_seq = Some(seq);
        }
        self.refresh("the PC's clipboard changed").await;
        if !watches(self.state()) {
            tracing::debug!(
                session = %self.sid,
                seq = ?seq,
                pc = self.pc().as_str(),
                wanted = self.wanted,
                "clipboard: a change while PC → viewer is off for this session; not read"
            );
            return;
        }
        let Some(backend) = self.backend.clone() else {
            return;
        };
        let started = std::time::Instant::now();
        let read = tokio::task::spawn_blocking(move || backend.read_text()).await;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        let text = match read {
            Ok(Ok(ClipboardContent::Text(text))) => text,
            Ok(Ok(ClipboardContent::TooLarge { units })) => {
                self.tally.skipped += 1;
                tracing::info!(
                    session = %self.sid,
                    seq = ?seq,
                    units,
                    max_bytes = CLIPBOARD_MAX_BYTES,
                    "clipboard: the PC's text is over the limit; not sent"
                );
                return;
            }
            Ok(Ok(ClipboardContent::NotText { formats })) => {
                tracing::debug!(
                    session = %self.sid,
                    seq = ?seq,
                    formats,
                    "clipboard: the PC's clipboard holds no text (an image, files); nothing sent"
                );
                return;
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    session = %self.sid,
                    seq = ?seq,
                    elapsed_ms,
                    "clipboard: the PC's clipboard was not read: {e}"
                );
                return;
            }
            Err(e) => {
                tracing::warn!(session = %self.sid, "clipboard: the read's task failed: {e}");
                return;
            }
        };
        self.send_pc_text(seq, &text, elapsed_ms).await;
    }

    /// Send the PC's new `text` to the viewer, unless it is empty, over the limit, the same as the
    /// last text that crossed — or PC → viewer stopped while it was read (game-only mode, the
    /// viewer's switch). Its chunks go revocable: a stop takes back what is still queued.
    async fn send_pc_text(&mut self, seq: Option<u32>, text: &str, read_ms: u64) {
        let digest = digest(&windows_newlines(text));
        if text.is_empty() {
            tracing::debug!(session = %self.sid, seq = ?seq, "clipboard: the PC's text is empty; nothing sent");
            return;
        }
        if self.last_text == Some(digest) {
            self.tally.skipped += 1;
            tracing::debug!(
                session = %self.sid,
                seq = ?seq,
                bytes = text.len(),
                "clipboard: the PC's text is the one that last crossed; not sent again"
            );
            return;
        }
        let id = self.next_id;
        let Some(parts) = chunks(id, text) else {
            self.tally.skipped += 1;
            tracing::info!(
                session = %self.sid,
                seq = ?seq,
                bytes = text.len(),
                max_bytes = CLIPBOARD_MAX_BYTES,
                "clipboard: the PC's text is over the limit; not sent"
            );
            return;
        };
        // The last look before anything leaves the PC.
        self.refresh("the PC's text is about to be sent").await;
        if !watches(self.state()) {
            tracing::debug!(
                session = %self.sid,
                seq = ?seq,
                pc = self.pc().as_str(),
                wanted = self.wanted,
                "clipboard: PC → viewer went off while the PC's text was read; not sent"
            );
            return;
        }
        self.next_id = self.next_id.wrapping_add(1);
        self.last_text = Some(digest);
        self.tally.sent += 1;
        self.tally.sent_bytes += text.len() as u64;
        tracing::debug!(
            session = %self.sid,
            seq = ?seq,
            id,
            chunks = parts.len(),
            bytes = text.len(),
            chars = text.chars().count(),
            read_ms,
            chunk_budget = CLIPBOARD_CHUNK_TEXT_BYTES,
            "clipboard: the PC's text goes to the viewer"
        );
        self.pc_out = Some(PcTextOut {
            id,
            chunks: parts.len(),
            bytes: text.len(),
            at: std::time::Instant::now(),
        });
        let messages = parts
            .into_iter()
            .map(AgentDataMessage::ClipboardPc)
            .collect();
        self.send_as(messages, "cb_pc", true).await;
    }

    /// Hand `messages` to the peer for the reliable channel, in order.
    async fn send(&mut self, messages: Vec<AgentDataMessage>, kind: &'static str) {
        self.send_as(messages, kind, false).await;
    }

    /// Hand `messages` to the peer for the reliable channel, in order; `revocable`: the PC's text,
    /// which [`PeerControl::RevokeQueued`] takes back while still queued.
    async fn send_as(
        &mut self,
        messages: Vec<AgentDataMessage>,
        kind: &'static str,
        revocable: bool,
    ) {
        let mut texts = Vec::with_capacity(messages.len());
        for message in &messages {
            match message.to_json() {
                Ok(json) => texts.push(json),
                Err(e) => {
                    tracing::warn!(session = %self.sid, kind, "clipboard: a message not serialized: {e}");
                    return;
                }
            }
        }
        let count = texts.len();
        let control = if revocable {
            PeerControl::SendRevocable(texts)
        } else {
            PeerControl::SendReliable(texts)
        };
        if self.control_tx.send(control).await.is_err() {
            tracing::debug!(
                session = %self.sid,
                kind,
                count,
                "clipboard: not sent, the peer has ended"
            );
        }
    }
}

/// The next change while watching; never while not.
async fn next_change(
    watch: &mut Option<broadcast::Receiver<ClipboardChange>>,
) -> Result<ClipboardChange, broadcast::error::RecvError> {
    match watch {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// `text` with every line break as Windows writes it, `\r\n`: a lone `\n` (how a browser has them)
/// gains its `\r`; one already there is left alone.
pub fn windows_newlines(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains('\n') {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + text.len() / 16);
    let mut prev = '\0';
    for c in text.chars() {
        if c == '\n' && prev != '\r' {
            out.push('\r');
        }
        out.push(c);
        prev = c;
    }
    std::borrow::Cow::Owned(out)
}

/// A digest of `text`, to tell one text from another without keeping it. Never logged.
fn digest(text: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::game::{CaptureMode, GameBinding};
    use std::sync::Mutex;

    /// A clipboard in memory: changes are broadcast like the real listener's.
    struct FakeClipboard {
        text: Mutex<Option<String>>,
        seq: Mutex<u32>,
        changes: broadcast::Sender<ClipboardChange>,
        reads: Mutex<u32>,
        watchable: bool,
    }

    impl FakeClipboard {
        fn new(watchable: bool) -> Arc<Self> {
            Arc::new(Self {
                text: Mutex::new(None),
                seq: Mutex::new(0),
                changes: broadcast::channel(16).0,
                reads: Mutex::new(0),
                watchable,
            })
        }

        /// Someone at the PC copies `text`.
        fn copy(&self, text: &str) {
            *crate::lock(&self.text) = Some(text.to_string());
            let seq = {
                let mut seq = crate::lock(&self.seq);
                *seq += 1;
                *seq
            };
            let _ = self.changes.send(ClipboardChange { seq });
        }
    }

    impl ClipboardBackend for FakeClipboard {
        fn watch(&self) -> Result<broadcast::Receiver<ClipboardChange>, String> {
            if self.watchable {
                Ok(self.changes.subscribe())
            } else {
                Err("no window station".into())
            }
        }
        fn read_text(&self) -> Result<ClipboardContent, ClipboardError> {
            *crate::lock(&self.reads) += 1;
            Ok(match crate::lock(&self.text).clone() {
                Some(t) => ClipboardContent::Text(t),
                None => ClipboardContent::NotText { formats: 0 },
            })
        }
        fn write_text(&self, text: &str) -> Result<u32, ClipboardError> {
            self.copy(text);
            Ok(*crate::lock(&self.seq))
        }
    }

    struct Harness {
        tx: mpsc::Sender<ViewerClipboard>,
        out: mpsc::Receiver<PeerControl>,
        mode: Arc<CaptureModeCell>,
        clipboard: Arc<FakeClipboard>,
        stop: Arc<AtomicBool>,
    }

    fn harness(watchable: bool) -> Harness {
        let clipboard = FakeClipboard::new(watchable);
        let mode = Arc::new(CaptureModeCell::new(CaptureMode::Monitor));
        let (control_tx, out) = mpsc::channel(64);
        let stop = Arc::new(AtomicBool::new(false));
        let tx = spawn_session(
            "s1".into(),
            Some(clipboard.clone() as Arc<dyn ClipboardBackend>),
            mode.clone(),
            control_tx,
            stop.clone(),
        );
        Harness {
            tx,
            out,
            mode,
            clipboard,
            stop,
        }
    }

    /// What the task handed the peer next, parsed.
    #[derive(Debug, PartialEq)]
    enum Out {
        /// [`PeerControl::SendReliable`]: `cb_state`, `cb_ack`.
        Reliable(Vec<AgentDataMessage>),
        /// [`PeerControl::SendRevocable`]: the PC's text.
        Revocable(Vec<AgentDataMessage>),
        /// [`PeerControl::RevokeQueued`].
        Revoke,
    }

    async fn next_out(out: &mut mpsc::Receiver<PeerControl>) -> Out {
        let control = tokio::time::timeout(Duration::from_secs(5), out.recv())
            .await
            .expect("a message in time")
            .expect("the task is up");
        let parse = |texts: Vec<String>| {
            texts
                .iter()
                .map(|t| serde_json::from_str(t).expect("contract JSON"))
                .collect()
        };
        match control {
            PeerControl::SendReliable(texts) => Out::Reliable(parse(texts)),
            PeerControl::SendRevocable(texts) => Out::Revocable(parse(texts)),
            PeerControl::RevokeQueued => Out::Revoke,
            other => panic!("expected clipboard messages, got {other:?}"),
        }
    }

    /// The next messages the task hands the peer: `cb_state` and `cb_ack` reliable, `cb_pc`
    /// revocable.
    async fn next(out: &mut mpsc::Receiver<PeerControl>) -> Vec<AgentDataMessage> {
        match next_out(out).await {
            Out::Reliable(m) => {
                assert!(
                    !m.iter()
                        .any(|m| matches!(m, AgentDataMessage::ClipboardPc(_))),
                    "the PC's text goes revocable"
                );
                m
            }
            Out::Revocable(m) => {
                assert!(
                    m.iter()
                        .all(|m| matches!(m, AgentDataMessage::ClipboardPc(_))),
                    "only the PC's text goes revocable"
                );
                m
            }
            Out::Revoke => panic!("expected messages, got a take-back"),
        }
    }

    async fn quiet(out: &mut mpsc::Receiver<PeerControl>) {
        assert!(
            tokio::time::timeout(Duration::from_millis(300), out.recv())
                .await
                .is_err(),
            "nothing should have been sent"
        );
    }

    fn state(on: bool, pc: ClipboardPc) -> Vec<AgentDataMessage> {
        vec![AgentDataMessage::ClipboardState(ClipboardState { on, pc })]
    }

    fn set(id: u32, i: u32, n: u32, text: &str) -> ViewerClipboard {
        ViewerClipboard::Set(ClipboardChunk {
            id,
            i,
            n,
            text: text.into(),
        })
    }

    fn game_only() -> CaptureMode {
        CaptureMode::GameWindow {
            binding: Some(GameBinding::new(r"C:\G\g.exe", "W")),
        }
    }

    #[tokio::test]
    async fn off_by_default_nothing_is_read_and_a_set_is_refused() {
        let mut h = harness(true);
        h.clipboard.copy("secret");
        quiet(&mut h.out).await;
        assert_eq!(*crate::lock(&h.clipboard.reads), 0, "never read while off");
        h.tx.send(set(1, 0, 1, "x")).await.expect("open");
        assert_eq!(
            next(&mut h.out).await,
            vec![AgentDataMessage::ClipboardAck(ClipboardAck::refused(
                1,
                ClipboardRefusal::Off
            ))]
        );
        // The viewer asks whether the PC allows it, with its switch off.
        h.tx.send(ViewerClipboard::Sync(false)).await.expect("open");
        assert_eq!(next(&mut h.out).await, state(false, ClipboardPc::Ready));
    }

    #[tokio::test]
    async fn on_the_pc_text_goes_to_the_viewer_on_change_and_the_viewer_text_comes_back_without_echo(
    ) {
        let mut h = harness(true);
        h.clipboard.copy("before sync: never sent");
        h.tx.send(ViewerClipboard::Sync(true)).await.expect("open");
        assert_eq!(next(&mut h.out).await, state(true, ClipboardPc::Ready));
        quiet(&mut h.out).await;

        h.clipboard.copy("copied on the PC\r\n");
        let sent = next(&mut h.out).await;
        assert_eq!(
            sent,
            vec![AgentDataMessage::ClipboardPc(ClipboardChunk {
                id: 0,
                i: 0,
                n: 1,
                text: "copied on the PC\r\n".into()
            })]
        );

        // The viewer's text, in two chunks with browser line breaks: written with Windows' ones,
        // answered once, and its own change not sent back.
        h.tx.send(set(5, 0, 2, "from the\n")).await.expect("open");
        h.tx.send(set(5, 1, 2, "viewer")).await.expect("open");
        assert_eq!(
            next(&mut h.out).await,
            vec![AgentDataMessage::ClipboardAck(ClipboardAck::ok(5))]
        );
        assert_eq!(
            crate::lock(&h.clipboard.text).as_deref(),
            Some("from the\r\nviewer")
        );
        quiet(&mut h.out).await;

        // The same text copied again on the PC is the one that last crossed: not sent again.
        h.clipboard.copy("from the\r\nviewer");
        quiet(&mut h.out).await;

        // Turned off: changes are not read any more, and what may still be queued of the PC's
        // text is taken back before the answer.
        h.tx.send(ViewerClipboard::Sync(false)).await.expect("open");
        assert_eq!(next_out(&mut h.out).await, Out::Revoke);
        assert_eq!(next(&mut h.out).await, state(false, ClipboardPc::Ready));
        let reads = *crate::lock(&h.clipboard.reads);
        h.clipboard.copy("after sync: never sent");
        quiet(&mut h.out).await;
        assert_eq!(*crate::lock(&h.clipboard.reads), reads);
        h.stop.store(true, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn game_only_takes_the_viewers_text_and_gives_nothing_back_and_flips_at_once() {
        let mut h = harness(true);
        h.mode.set(game_only(), "test");
        h.tx.send(ViewerClipboard::Sync(true)).await.expect("open");
        assert_eq!(next(&mut h.out).await, state(true, ClipboardPc::ToPcOnly));
        // Nothing of the PC's leaves it: not read, not sent.
        h.clipboard.copy("a password");
        quiet(&mut h.out).await;
        assert_eq!(*crate::lock(&h.clipboard.reads), 0);
        // The viewer's text goes to the PC as ever, answered after the write.
        h.tx.send(set(2, 0, 1, "pasted by the guest"))
            .await
            .expect("open");
        assert_eq!(
            next(&mut h.out).await,
            vec![AgentDataMessage::ClipboardAck(ClipboardAck::ok(2))]
        );
        assert_eq!(
            crate::lock(&h.clipboard.text).as_deref(),
            Some("pasted by the guest")
        );
        quiet(&mut h.out).await;

        // Turned off on the PC: both ways again, said by itself — and what is on the clipboard at
        // the flip stays on the PC.
        h.mode.set(CaptureMode::Monitor, "test");
        assert_eq!(next(&mut h.out).await, state(true, ClipboardPc::Ready));
        quiet(&mut h.out).await;
        assert_eq!(*crate::lock(&h.clipboard.reads), 0);
        // A change from then on goes.
        h.clipboard.copy("copied after the flip");
        assert_eq!(
            next(&mut h.out).await,
            vec![AgentDataMessage::ClipboardPc(ClipboardChunk {
                id: 0,
                i: 0,
                n: 1,
                text: "copied after the flip".into()
            })]
        );

        // On again mid-session, without a word from the viewer: what is still queued of the PC's
        // text is taken back first, then the state.
        h.mode.set(game_only(), "test");
        assert_eq!(next_out(&mut h.out).await, Out::Revoke);
        assert_eq!(next(&mut h.out).await, state(true, ClipboardPc::ToPcOnly));
        let reads = *crate::lock(&h.clipboard.reads);
        h.clipboard.copy("another password");
        quiet(&mut h.out).await;
        assert_eq!(*crate::lock(&h.clipboard.reads), reads);
        h.stop.store(true, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn no_echo_holds_across_a_flip() {
        let mut h = harness(true);
        h.mode.set(game_only(), "test");
        h.tx.send(ViewerClipboard::Sync(true)).await.expect("open");
        assert_eq!(next(&mut h.out).await, state(true, ClipboardPc::ToPcOnly));
        h.tx.send(set(1, 0, 1, "the guest's line\n"))
            .await
            .expect("open");
        assert_eq!(
            next(&mut h.out).await,
            vec![AgentDataMessage::ClipboardAck(ClipboardAck::ok(1))]
        );
        h.mode.set(CaptureMode::Monitor, "test");
        assert_eq!(next(&mut h.out).await, state(true, ClipboardPc::Ready));
        // The same text copied on the PC is the one that last crossed: not sent back.
        h.clipboard.copy("the guest's line\r\n");
        quiet(&mut h.out).await;
        // Something new is.
        h.clipboard.copy("new on the PC");
        assert!(matches!(
            next(&mut h.out).await.as_slice(),
            [AgentDataMessage::ClipboardPc(c)] if c.text == "new on the PC"
        ));
        h.stop.store(true, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn game_only_with_a_clipboard_that_cannot_be_reached_is_unavailable() {
        let mut h = harness(false);
        h.mode.set(game_only(), "test");
        h.tx.send(ViewerClipboard::Sync(true)).await.expect("open");
        assert_eq!(
            next(&mut h.out).await,
            state(false, ClipboardPc::Unavailable)
        );
        h.tx.send(set(4, 0, 1, "x")).await.expect("open");
        assert_eq!(
            next(&mut h.out).await,
            vec![AgentDataMessage::ClipboardAck(ClipboardAck::refused(
                4,
                ClipboardRefusal::Failed
            ))]
        );
    }

    #[tokio::test]
    async fn a_clipboard_that_cannot_be_watched_is_unavailable() {
        let mut h = harness(false);
        h.tx.send(ViewerClipboard::Sync(true)).await.expect("open");
        assert_eq!(
            next(&mut h.out).await,
            state(false, ClipboardPc::Unavailable)
        );
        h.tx.send(set(3, 0, 1, "x")).await.expect("open");
        assert_eq!(
            next(&mut h.out).await,
            vec![AgentDataMessage::ClipboardAck(ClipboardAck::refused(
                3,
                ClipboardRefusal::Failed
            ))]
        );
    }

    #[tokio::test]
    async fn bad_chunks_are_answered_once_and_a_large_pc_text_is_not_sent() {
        let mut h = harness(true);
        h.tx.send(ViewerClipboard::Sync(true)).await.expect("open");
        assert_eq!(next(&mut h.out).await, state(true, ClipboardPc::Ready));
        h.tx.send(set(7, 1, 2, "late")).await.expect("open");
        assert_eq!(
            next(&mut h.out).await,
            vec![AgentDataMessage::ClipboardAck(ClipboardAck::refused(
                7,
                ClipboardRefusal::Malformed
            ))]
        );
        h.tx.send(set(8, 0, 1, &"x".repeat(INPUT_MAX_BYTES + 1)))
            .await
            .expect("open");
        assert_eq!(
            next(&mut h.out).await,
            vec![AgentDataMessage::ClipboardAck(ClipboardAck::refused(
                8,
                ClipboardRefusal::Malformed
            ))]
        );
        h.clipboard.copy(&"y".repeat(CLIPBOARD_MAX_BYTES + 1));
        quiet(&mut h.out).await;
        // A long text goes in chunks, each one message.
        let long = "z".repeat(CLIPBOARD_MAX_BYTES);
        h.clipboard.copy(&long);
        let sent = next(&mut h.out).await;
        assert_eq!(sent.len(), 17);
        let joined: String = sent
            .iter()
            .map(|m| match m {
                AgentDataMessage::ClipboardPc(c) => c.text.clone(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(joined, long);
    }

    #[test]
    fn line_breaks_become_windows_ones_once() {
        assert_eq!(windows_newlines("a\nb"), "a\r\nb");
        assert_eq!(windows_newlines("a\r\nb\n"), "a\r\nb\r\n");
        assert_eq!(windows_newlines("\n\n"), "\r\n\r\n");
        assert_eq!(windows_newlines("no breaks"), "no breaks");
        assert!(matches!(
            windows_newlines("no breaks"),
            std::borrow::Cow::Borrowed(_)
        ));
    }
}
