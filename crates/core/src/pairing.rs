//! The owner's pairing panel, as the agent sees it.
//!
//! The agent owns the panel's state, not the window, because only the agent sees every edge of it:
//! the owner opening and closing it, the code arriving, the binding it produced, and the
//! connection that carried the code going away. A flag of the window's own beside `pairing_code`
//! drifts apart from it: after a successful pairing the spent code leaves the screen while the
//! window still says "open", an empty panel until the owner closes it by hand.
//!
//! [`PairingPanel`] holds what each edge does; [`PairLink`] holds how a pending request survives a
//! break of the signaling link; [`CodeRetry`] asks again for a code the backend refused.
//!
//! The code itself is never logged: it is a live credential while the panel is open.

use crate::agent::AgentState;

/// How long after the link comes back a kept request waits for the backend's re-send: it goes out
/// right after `agent_ready`, so one not back by then is one the backend does not have any more.
pub const PAIR_RECHECK_MS: i64 = 5_000;

/// Where a pending request stands with the signaling link its answer has to go over
/// ([`PendingPair::link`](crate::agent::PendingPair::link)).
///
/// Across a break of the link:
///
/// ```text
///   Live ──(signaling lost)──► Lost ──(connected)──► Rechecking ──(the same pair_request)──► Live
///                               │                        │
///                               └──(its deadline)──► closed   └──(not re-sent in PAIR_RECHECK_MS)──► closed
/// ```
///
/// While it is not `Live` the prompt stays on screen, at its step («Кто это?» included: the step is
/// the window's, keyed by the request id), with its answer buttons disabled and «Нет связи» by the
/// countdown: an answer goes only over a live link. Not queued for the next connection, because the
/// answer must reach the backend while the request still lives there: queued, it could land on a
/// backend that restarted (requests live in its memory) or after the grace window, and the owner
/// would believe he had answered while the person was never let in and nobody was told. The relay
/// drops `pair_response` while offline for the same reason.
///
/// The request is closed when the link is not back by its deadline, or when the backend does not
/// re-send it within [`PAIR_RECHECK_MS`] of the link coming back. The backend has lost it then:
/// it restarted (a deploy; accepted, the person asks again), or this agent was away longer than the
/// grace window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PairLink {
    /// On the link that raised it (or re-sent it): the answer can go.
    #[default]
    Live,
    /// Signaling was lost while it waited, at `since_ms` (Unix ms): kept, its answer waits for the
    /// link.
    Lost { since_ms: i64 },
    /// The link is back since `since_ms`, and the backend has not re-sent it yet.
    Rechecking { since_ms: i64 },
}

impl PairLink {
    /// `live`, `lost` or `rechecking`: for logs, and what the request window is told.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Lost { .. } => "lost",
            Self::Rechecking { .. } => "rechecking",
        }
    }
}

/// The waits before asking again for a code the backend refused with `rate_limited`, by refusal:
/// the first waits 5 s, the second 15 s, every later one 60 s. Refused requests cost the backend's
/// budget nothing (its `agentLimits.takePairingCode` counts issued codes), so asking once a minute
/// while the owner waits is cheap, and a code comes as soon as the budget has room.
pub const CODE_RETRY_DELAYS_MS: [i64; 3] = [5_000, 15_000, 60_000];

/// The `message` of the `rate_limited` error that refuses `request_pairing` (the backend's
/// `agentWs.ts`). The frame names no request, and other requests are refused with the same code
/// (`unbind` says `"unbind"`), so this is how the refusal is told apart.
pub const CODE_REFUSED_MESSAGE: &str = "pairing codes";

/// Asking again for a refused code ([`code_refused`], [`retry_due`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CodeRetry {
    /// Refusals in a row for the open panel: picks the next wait from [`CODE_RETRY_DELAYS_MS`].
    pub refusals: u32,
    /// When to ask again (Unix ms); `None`: nothing scheduled.
    pub due_ms: Option<i64>,
}

/// The wait after the `refusals`-th refusal in a row (1-based).
fn retry_delay_ms(refusals: u32) -> i64 {
    let i = usize::try_from(refusals.saturating_sub(1)).unwrap_or(usize::MAX);
    CODE_RETRY_DELAYS_MS
        .get(i)
        .or(CODE_RETRY_DELAYS_MS.last())
        .copied()
        .unwrap_or(60_000)
}

/// The backend refused the code with `rate_limited` at `now_ms`. While the panel is open and shows
/// no code, the request is scheduled again ([`CODE_RETRY_DELAYS_MS`]); returns whether it was.
pub(crate) fn code_refused(state: &mut AgentState, now_ms: i64) -> bool {
    if state.pairing_panel != PairingPanel::Open || state.pairing_code.is_some() {
        tracing::info!(
            panel = state.pairing_panel.kind(),
            has_code = state.pairing_code.is_some(),
            "pairing code refused (rate_limited) with no panel waiting for one: not asked again"
        );
        state.pairing_retry = CodeRetry::default();
        return false;
    }
    let refusals = state.pairing_retry.refusals.saturating_add(1);
    let delay_ms = retry_delay_ms(refusals);
    state.pairing_retry = CodeRetry {
        refusals,
        due_ms: Some(now_ms + delay_ms),
    };
    tracing::info!(
        refusals,
        delay_ms,
        "pairing code refused: the backend's budget of codes is spent (rate_limited); the open \
         panel waits and the code is asked for again"
    );
    true
}

/// Whether a refused code is due to be asked for again at `now_ms`, from the orchestrator's tick on
/// a live connection. Clears the schedule when it fires, and drops it (with a log) when the panel
/// has closed or a code is on screen in the meantime.
pub(crate) fn retry_due(state: &mut AgentState, now_ms: i64) -> bool {
    let retry = state.pairing_retry;
    if retry == CodeRetry::default() {
        return false;
    }
    if state.pairing_panel != PairingPanel::Open || state.pairing_code.is_some() {
        tracing::debug!(
            panel = state.pairing_panel.kind(),
            has_code = state.pairing_code.is_some(),
            refusals = retry.refusals,
            "pairing code retry dropped: no panel waits for a code any more"
        );
        state.pairing_retry = CodeRetry::default();
        return false;
    }
    let Some(due_ms) = retry.due_ms else {
        return false;
    };
    if now_ms < due_ms || !state.connected {
        return false;
    }
    state.pairing_retry.due_ms = None;
    tracing::info!(
        refusals = retry.refusals,
        late_ms = now_ms - due_ms,
        "pairing code refused before: asking the backend again"
    );
    true
}

/// Where the owner's pairing panel is.
///
/// What each edge does ([`AgentState::pairing_panel`], [`AgentState::pairing_code`]):
///
///   opened            `Open`. The code is asked for now, or on the next connection while signaling
///                     is down: a request sent offline would be dropped (`crate::relay`).
///   closed            `Closed`, and the code goes with it (`pairing_cancel`, held while offline).
///   code arrives      shown while `Open`. Otherwise it answers a request the panel has since
///                     withdrawn, and is dropped: it is already dead on the backend, which handles
///                     an agent's frames in order, so the `pairing_cancel` sent after its request
///                     (or the approval, for `Paired`) revoked it.
///   request arrives   `Redeemed` when the panel was open: someone entered the code, which the
///                     backend spends on entry, so it leaves the screen now and the confirmation
///                     prompt is what remains. The caller revokes it (`pairing_cancel`), as for any
///                     panel that closes; the window closes the panel on this. After a decline or a
///                     timeout the owner opens the panel again for a new code.
///   binding added     `Paired` when the panel was open. The code is spent either way: the backend
///                     revoked every code of this device when the owner approved.
///   code refused      the backend answered the request with `rate_limited` (its budget of codes
///                     is spent): while the panel stays open and no code is shown, asked again after
///                     [`CODE_RETRY_DELAYS_MS`] — 5 s, 15 s, then every 60 s ([`CodeRetry`]). The
///                     panel shows its usual wait meanwhile. Closing the panel ends the retries.
///   connection lost   the code dies with it: the backend revokes the codes of an agent whose socket
///                     closed. An open panel stays open and is sent a new code on the next
///                     connection. A pending request does not die (otherwise the prompt being
///                     answered, «Кто это?», vanishes with a backend redeploy): the
///                     backend keeps it for a grace window (`PAIR_AGENT_GRACE_MS`, 30 s,
///                     `server/src/signaling/pairRequests.ts`) and re-sends it to this device's next
///                     socket right after `agent_ready`. See [`PairLink`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PairingPanel {
    /// No code is wanted, and none is shown.
    #[default]
    Closed,
    /// The owner has the panel open. [`AgentState::pairing_code`] is the code once it has arrived;
    /// `None` while it is on its way or while signaling is down.
    Open,
    /// Someone entered the code while the panel was open, and a confirmation prompt is up: the code
    /// is spent and off screen. The window closes the panel on seeing this; `display_name` is who
    /// entered it.
    Redeemed { display_name: String },
    /// A binding was created while the panel was open: its code is spent. The window closes the
    /// panel on seeing this; `display_name` is who was paired.
    Paired { display_name: String },
}

impl PairingPanel {
    /// `closed`, `open`, `redeemed` or `paired`: for logs, and what the window is told.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::Redeemed { .. } => "redeemed",
            Self::Paired { .. } => "paired",
        }
    }
}

/// The owner opened the panel. Returns whether the code can be asked for now (signaling is up);
/// otherwise it is asked for on the next connection ([`wants_code_on_connect`]).
pub(crate) fn open(state: &mut AgentState) -> bool {
    let was = std::mem::replace(&mut state.pairing_panel, PairingPanel::Open);
    let connected = state.connected;
    // A panel opened afresh starts its retries from the first wait; the owner's «Повторить» on an
    // open one asks now, and a refusal of that continues the schedule.
    let retry = std::mem::take(&mut state.pairing_retry);
    if was == PairingPanel::Open {
        state.pairing_retry.refusals = retry.refusals;
    }
    if retry.due_ms.is_some() {
        tracing::debug!(
            refusals = retry.refusals,
            "pairing code retry superseded: the panel asks now"
        );
    }
    tracing::info!(
        was = was.kind(),
        connected,
        had_code = state.pairing_code.is_some(),
        "owner opened the pairing panel: {}",
        if connected {
            "asking the backend for a code"
        } else {
            "signaling is down; the code is asked for on the next connection"
        }
    );
    connected
}

/// The owner closed the panel: its code is revoked with it.
pub(crate) fn close(state: &mut AgentState) {
    let was = std::mem::take(&mut state.pairing_panel);
    let had_code = state.pairing_code.take().is_some();
    state.pairing_expires_at = None;
    let retry = std::mem::take(&mut state.pairing_retry);
    tracing::info!(
        was = was.kind(),
        had_code,
        connected = state.connected,
        retry_pending = retry.due_ms.is_some(),
        "owner closed the pairing panel: the code is revoked{}",
        if retry.due_ms.is_some() {
            "; the refused code is not asked for again"
        } else {
            ""
        }
    );
}

/// A code from the backend: whether it is wanted. `true` — the panel is open, and the caller shows
/// the code; `false` — the panel is not open, and the code is dropped (it is already dead on the
/// backend; see the module docs).
pub(crate) fn code_wanted(state: &AgentState, expires_at: i64) -> bool {
    if state.pairing_panel == PairingPanel::Open {
        tracing::debug!(
            expires_at,
            replaces = state.pairing_code.is_some(),
            "pairing code for the open panel: shown"
        );
        true
    } else {
        tracing::info!(
            panel = state.pairing_panel.kind(),
            expires_at,
            "pairing code arrived with the panel not open (withdrawn before the code came): not \
             shown; the backend revoked it already"
        );
        false
    }
}

/// Someone entered the code and a confirmation prompt is up. An open panel becomes `Redeemed` and
/// its spent code leaves the screen; returns whether it did, and the caller then revokes the code.
pub(crate) fn request_arrived(state: &mut AgentState, display_name: String) -> bool {
    if state.pairing_panel != PairingPanel::Open {
        tracing::debug!(
            panel = state.pairing_panel.kind(),
            "pairing request with the pairing panel not open: the panel is left as it is"
        );
        return false;
    }
    let had_code = state.pairing_code.take().is_some();
    state.pairing_expires_at = None;
    tracing::info!(
        had_code,
        "pairing panel: {display_name} entered the code; it is spent and taken off screen, the \
         panel closes and the confirmation prompt takes over"
    );
    state.pairing_panel = PairingPanel::Redeemed { display_name };
    true
}

/// A binding was created. The code that produced it is spent; an open panel becomes `Paired`.
pub(crate) fn binding_added(state: &mut AgentState, display_name: String) {
    let had_code = state.pairing_code.take().is_some();
    state.pairing_expires_at = None;
    let was = state.pairing_panel.kind();
    if state.pairing_panel == PairingPanel::Open {
        tracing::info!(
            had_code,
            bindings = state.bindings.len(),
            "pairing panel: paired with {display_name}; the spent code is taken off screen"
        );
        state.pairing_panel = PairingPanel::Paired { display_name };
    } else {
        tracing::debug!(
            panel = was,
            had_code,
            bindings = state.bindings.len(),
            "binding added with the pairing panel not open: the panel is left as it is"
        );
    }
}

/// The signaling connection ended at `now_ms`: the code died with it on the backend; a pending
/// request is kept, its answer waiting for the link ([`PairLink::Lost`]) — unless its deadline has
/// passed, when it goes as the backend's timeout would have taken it.
pub(crate) fn connection_lost(state: &mut AgentState, now_ms: i64) {
    let had_code = state.pairing_code.take().is_some();
    state.pairing_expires_at = None;
    // The next connection asks for a code at once (`wants_code_on_connect`); a refusal of that
    // continues from the refusals so far.
    if state.pairing_retry.due_ms.take().is_some() {
        tracing::debug!(
            refusals = state.pairing_retry.refusals,
            "signaling lost: the scheduled pairing code retry gives way to the next connection's \
             request"
        );
    }
    let panel = state.pairing_panel.kind();
    let open = state.pairing_panel == PairingPanel::Open;
    if had_code || open {
        tracing::info!(
            panel,
            had_code,
            "signaling lost: the pairing code died with the connection{}",
            if open {
                "; the open panel is sent a new code on the next connection"
            } else {
                ""
            }
        );
    }
    let Some(p) = state.pending_pair.as_mut() else {
        if !(had_code || open) {
            tracing::debug!(panel, "signaling lost: no pairing state to keep or drop");
        }
        return;
    };
    if p.expires_at <= now_ms {
        let (request_id, past_ms) = (p.request_id.clone(), now_ms - p.expires_at);
        state.pending_pair = None;
        tracing::info!(
            %request_id,
            past_ms,
            "signaling lost with the pairing request past its deadline: closed"
        );
        return;
    }
    let was = p.link;
    p.link = PairLink::Lost { since_ms: now_ms };
    tracing::info!(
        request_id = %p.request_id,
        was = was.as_str(),
        expires_in_ms = p.expires_at - now_ms,
        "signaling lost: the pairing request is kept, its answer buttons waiting for the link (the \
         backend keeps it for its grace window and re-sends it when this agent is back)"
    );
}

/// Whether a new connection should ask for a code: the owner has the panel open. `link` is the
/// connection's number, for the log.
pub(crate) fn wants_code_on_connect(state: &AgentState, link: u64) -> bool {
    let wants = state.pairing_panel == PairingPanel::Open;
    tracing::debug!(
        link,
        panel = state.pairing_panel.kind(),
        wants,
        "pairing panel on connect: {}",
        if wants {
            "open, asking for a new code (the old one died with the old connection)"
        } else {
            "no code to ask for"
        }
    );
    wants
}

/// A new connection is up (`agent_ready` read) at `now_ms`: a request kept across the break waits
/// for the backend to re-send it ([`PairLink::Rechecking`]). `link` is the connection's number.
pub(crate) fn reconnected(state: &mut AgentState, now_ms: i64, link: u64) {
    let Some(p) = state.pending_pair.as_mut() else {
        return;
    };
    match p.link {
        PairLink::Lost { since_ms } => {
            p.link = PairLink::Rechecking { since_ms: now_ms };
            tracing::debug!(
                link,
                request_id = %p.request_id,
                away_ms = now_ms - since_ms,
                recheck_ms = PAIR_RECHECK_MS,
                "signaling back: the kept pairing request waits for the backend to re-send it"
            );
        }
        other => tracing::debug!(
            link,
            request_id = %p.request_id,
            at = other.as_str(),
            "signaling connected with a pairing request that was not kept across a break; left as it is"
        ),
    }
}

/// A `pair_request` for `request_id` (deadline `expires_at`) arrived at `now_ms`. True when it is
/// the request already on screen — the backend re-sent it after a reconnect — which is then live
/// again where it was, at its step; the caller treats it as nothing new (no panel to close, no
/// prompt to raise). False for a new request, which the caller puts up as always.
pub(crate) fn restore(
    state: &mut AgentState,
    request_id: &str,
    expires_at: i64,
    now_ms: i64,
) -> bool {
    let Some(p) = state
        .pending_pair
        .as_mut()
        .filter(|p| p.request_id == request_id)
    else {
        return false;
    };
    let was = p.link;
    p.link = PairLink::Live;
    let moved = p.expires_at != expires_at;
    p.expires_at = expires_at;
    match was {
        PairLink::Live => tracing::debug!(
            %request_id,
            deadline_moved = moved,
            "pairing request sent again on a live link (the backend moved it to a newer socket of \
             this device); the prompt carries on"
        ),
        PairLink::Lost { since_ms } | PairLink::Rechecking { since_ms } => tracing::info!(
            %request_id,
            was = was.as_str(),
            since_ms = now_ms - since_ms,
            expires_in_ms = expires_at - now_ms,
            deadline_moved = moved,
            "pairing request restored after the reconnect: the same request, re-sent by the \
             backend; the prompt carries on at its step and can be answered again"
        ),
    }
    true
}

/// The kept request's waits at `now_ms`, from the orchestrator's tick: past its deadline with the
/// link not back, or not re-sent within [`PAIR_RECHECK_MS`] of the link coming back — closed, as
/// the backend's `pair_cancelled` would have closed it. A live request is the backend's to close.
/// True when one was closed.
pub(crate) fn tick(state: &mut AgentState, now_ms: i64) -> bool {
    let Some(p) = state.pending_pair.as_ref() else {
        return false;
    };
    let why = match p.link {
        PairLink::Live => return false,
        PairLink::Lost { since_ms } | PairLink::Rechecking { since_ms }
            if now_ms >= p.expires_at =>
        {
            tracing::info!(
                request_id = %p.request_id,
                at = p.link.as_str(),
                waited_ms = now_ms - since_ms,
                "pairing request past its deadline with the link not back: closed, as the \
                 backend's timeout would have"
            );
            "expired"
        }
        PairLink::Rechecking { since_ms } if now_ms - since_ms >= PAIR_RECHECK_MS => {
            tracing::info!(
                request_id = %p.request_id,
                waited_ms = now_ms - since_ms,
                expires_in_ms = p.expires_at - now_ms,
                "pairing request not re-sent after the reconnect: the backend no longer has it (it \
                 restarted, or this agent was away longer than its grace window); closed"
            );
            "not re-sent"
        }
        PairLink::Lost { .. } | PairLink::Rechecking { .. } => return false,
    };
    tracing::trace!(why, "pairing request closed by the tick");
    state.pending_pair = None;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::PendingPair;

    fn pending(request_id: &str) -> PendingPair {
        PendingPair {
            request_id: request_id.into(),
            telegram_user_id: 7,
            username: Some("ann".into()),
            first_name: None,
            expires_at: 1,
            has_owner: None,
            link: PairLink::Live,
        }
    }

    /// Unix ms for the tests that run a request's clock: well past `pending`'s deadline of 1.
    const T0: i64 = 1_791_320_000_000;

    /// A request with two minutes to go from [`T0`], on a PC with no owner (it asks «Кто это?»).
    fn waiting(request_id: &str) -> PendingPair {
        PendingPair {
            expires_at: T0 + 120_000,
            has_owner: Some(false),
            ..pending(request_id)
        }
    }

    /// An agent with [`waiting`] request `r1` on screen.
    fn with_waiting_request() -> AgentState {
        AgentState {
            pending_pair: Some(waiting("r1")),
            ..AgentState::default()
        }
    }

    /// What the orchestrator does with a `pairing_code`: shows it when it is wanted.
    fn arrive(s: &mut AgentState, code: &str) -> bool {
        let wanted = code_wanted(s, 99);
        if wanted {
            s.pairing_code = Some(code.into());
            s.pairing_expires_at = Some(99);
        }
        wanted
    }

    /// After a successful pairing the panel must not stay open with nothing in it: the binding
    /// moves an open panel to `Paired`, which is what the window closes it on.
    #[test]
    fn a_binding_made_while_the_panel_is_open_pairs_it_and_spends_the_code() {
        let mut s = AgentState {
            connected: true,
            ..AgentState::default()
        };
        assert!(open(&mut s), "signaling is up: the code is asked for now");
        assert!(arrive(&mut s, "123456"));
        assert_eq!(s.pairing_code.as_deref(), Some("123456"));

        binding_added(&mut s, "@ann".into());
        assert_eq!(
            s.pairing_panel,
            PairingPanel::Paired {
                display_name: "@ann".into()
            }
        );
        assert_eq!(s.pairing_code, None);
        assert_eq!(s.pairing_expires_at, None);

        // Opening it again starts over.
        assert!(open(&mut s));
        assert_eq!(s.pairing_panel, PairingPanel::Open);
    }

    /// A binding approved after the panel was closed (the prompt outlives the panel) leaves the
    /// panel closed: nothing reopens it.
    #[test]
    fn a_binding_made_with_the_panel_closed_leaves_it_closed() {
        let mut s = AgentState::default();
        binding_added(&mut s, "@ann".into());
        assert_eq!(s.pairing_panel, PairingPanel::Closed);
    }

    /// Closed before the code came: the code is not shown and the caller revokes it again.
    #[test]
    fn a_code_that_arrives_after_the_panel_closed_is_not_shown() {
        let mut s = AgentState {
            connected: true,
            ..AgentState::default()
        };
        open(&mut s);
        close(&mut s);
        assert!(!arrive(&mut s, "123456"));
        assert_eq!(s.pairing_code, None);
        assert_eq!(s.pairing_panel, PairingPanel::Closed);

        // Nor after a pairing, where the window is about to close the panel.
        s.pairing_panel = PairingPanel::Paired {
            display_name: "@ann".into(),
        };
        assert!(!arrive(&mut s, "654321"));
        assert_eq!(s.pairing_code, None);
    }

    /// Closing takes the code with it.
    #[test]
    fn closing_the_panel_takes_its_code() {
        let mut s = AgentState {
            connected: true,
            ..AgentState::default()
        };
        open(&mut s);
        assert!(arrive(&mut s, "123456"));
        close(&mut s);
        assert_eq!(s.pairing_panel, PairingPanel::Closed);
        assert_eq!(s.pairing_code, None);
        assert_eq!(s.pairing_expires_at, None);
    }

    /// Opened offline: nothing can be sent now, and the next connection asks for the code.
    #[test]
    fn a_panel_opened_offline_asks_for_its_code_on_the_next_connection() {
        let mut s = AgentState::default();
        assert!(!open(&mut s), "signaling is down: nothing is sent now");
        assert_eq!(s.pairing_panel, PairingPanel::Open);
        assert!(wants_code_on_connect(&s, 2));

        close(&mut s);
        assert!(
            !wants_code_on_connect(&s, 3),
            "closed again before the connection came back"
        );
    }

    /// The connection drops mid-pairing: the backend revoked the code, so it leaves the screen, and
    /// the panel stays open and asks again on the next connection. A request past its deadline goes
    /// with it — the backend's timeout has taken it.
    #[test]
    fn a_lost_connection_takes_the_code_and_a_request_past_its_deadline() {
        let mut s = AgentState {
            connected: true,
            ..AgentState::default()
        };
        open(&mut s);
        assert!(arrive(&mut s, "123456"));
        s.pending_pair = Some(pending("r1"));

        connection_lost(&mut s, T0);
        assert_eq!(s.pairing_code, None);
        assert_eq!(s.pairing_expires_at, None);
        assert!(s.pending_pair.is_none(), "its deadline (1) has passed");
        assert_eq!(s.pairing_panel, PairingPanel::Open);
        assert!(wants_code_on_connect(&s, 2));

        // A closed panel asks for nothing, and a paired one neither.
        close(&mut s);
        connection_lost(&mut s, T0);
        assert!(!wants_code_on_connect(&s, 3));
        s.pairing_panel = PairingPanel::Paired {
            display_name: "@ann".into(),
        };
        assert!(!wants_code_on_connect(&s, 4));
    }

    /// The backend redeploys while the owner is at «Кто это?»: the prompt is kept across the break,
    /// its answer waiting for the link, and the backend's re-send of the same request makes it live
    /// again.
    #[test]
    fn a_lost_connection_keeps_the_request_and_the_backends_re_send_restores_it() {
        let mut s = with_waiting_request();
        assert!(s.pending_pair.as_ref().is_some_and(PendingPair::answerable));

        connection_lost(&mut s, T0 + 10_000);
        let p = s.pending_pair.as_ref().expect("kept");
        assert_eq!(
            p.link,
            PairLink::Lost {
                since_ms: T0 + 10_000
            }
        );
        assert!(!p.answerable(), "no answer goes while the link is down");
        assert!(p.asks_role(), "still the PC with no owner: «Кто это?»");

        // The waits run, but neither has ended.
        assert!(!tick(&mut s, T0 + 15_000));
        reconnected(&mut s, T0 + 18_700, 2);
        assert_eq!(
            s.pending_pair.as_ref().map(|p| p.link),
            Some(PairLink::Rechecking {
                since_ms: T0 + 18_700
            })
        );
        assert!(!tick(&mut s, T0 + 18_700 + PAIR_RECHECK_MS - 1));

        // The same request again: restored, live, the deadline as the backend says.
        assert!(restore(&mut s, "r1", T0 + 120_000, T0 + 18_800));
        let p = s.pending_pair.as_ref().expect("restored");
        assert_eq!(p.link, PairLink::Live);
        assert!(p.answerable());
        assert!(!tick(&mut s, T0 + 119_000), "live: the backend's to close");

        // A new request is not a restore: the caller raises it as always.
        assert!(!restore(&mut s, "r2", T0 + 200_000, T0 + 20_000));
    }

    /// A kept request closes as today when the link is not back by its deadline, and when the
    /// backend does not re-send it after the link is back (it restarted, or the grace ran out).
    #[test]
    fn a_kept_request_closes_at_its_deadline_or_when_the_backend_does_not_re_send_it() {
        // The link never comes back in time.
        let mut s = with_waiting_request();
        connection_lost(&mut s, T0 + 100_000);
        assert!(!tick(&mut s, T0 + 119_999));
        assert!(tick(&mut s, T0 + 120_000));
        assert!(s.pending_pair.is_none());

        // Back, and not re-sent.
        let mut s = with_waiting_request();
        connection_lost(&mut s, T0);
        reconnected(&mut s, T0 + 9_000, 2);
        assert!(!tick(&mut s, T0 + 9_000 + PAIR_RECHECK_MS - 1));
        assert!(tick(&mut s, T0 + 9_000 + PAIR_RECHECK_MS));
        assert!(s.pending_pair.is_none());

        // Back past its deadline: the deadline closes it, the recheck need not wait.
        let mut s = with_waiting_request();
        connection_lost(&mut s, T0 + 110_000);
        reconnected(&mut s, T0 + 119_000, 2);
        assert!(tick(&mut s, T0 + 120_000));
    }

    #[test]
    fn the_link_is_told_one_word() {
        assert_eq!(PairLink::Live.as_str(), "live");
        assert_eq!(PairLink::Lost { since_ms: 1 }.as_str(), "lost");
        assert_eq!(PairLink::Rechecking { since_ms: 1 }.as_str(), "rechecking");
    }

    /// Someone entering the code closes the panel, so the spent code leaves
    /// the screen and the confirmation prompt is what remains. Nothing reopens it by itself: not a
    /// late code, not the reconnect, not the binding the prompt produces.
    #[test]
    fn a_request_for_an_open_panel_takes_its_code_and_closes_it() {
        let mut s = AgentState {
            connected: true,
            ..AgentState::default()
        };
        open(&mut s);
        assert!(arrive(&mut s, "123456"));

        assert!(request_arrived(&mut s, "Ann (@ann)".into()));
        assert_eq!(
            s.pairing_panel,
            PairingPanel::Redeemed {
                display_name: "Ann (@ann)".into()
            }
        );
        assert_eq!(s.pairing_code, None, "the spent code is off screen");
        assert_eq!(s.pairing_expires_at, None);

        assert!(!arrive(&mut s, "654321"), "a late code is not shown");
        assert!(!wants_code_on_connect(&s, 2), "nor asked for on reconnect");
        binding_added(&mut s, "Ann (@ann)".into());
        assert_eq!(
            s.pairing_panel.kind(),
            "redeemed",
            "the approval leaves it closed"
        );

        // The window closes it for good; opening it again asks for a new code.
        close(&mut s);
        assert_eq!(s.pairing_panel, PairingPanel::Closed);
        assert!(open(&mut s));
    }

    /// A request with the panel closed (it was closed after the code was read) changes nothing.
    #[test]
    fn a_request_with_the_panel_closed_leaves_it_closed() {
        let mut s = AgentState::default();
        assert!(!request_arrived(&mut s, "Ann (@ann)".into()));
        assert_eq!(s.pairing_panel, PairingPanel::Closed);
    }

    #[test]
    fn the_window_is_told_one_word() {
        assert_eq!(PairingPanel::Closed.kind(), "closed");
        assert_eq!(PairingPanel::Open.kind(), "open");
        assert_eq!(
            PairingPanel::Redeemed {
                display_name: "@ann".into()
            }
            .kind(),
            "redeemed"
        );
        assert_eq!(
            PairingPanel::Paired {
                display_name: "@ann".into()
            }
            .kind(),
            "paired"
        );
    }

    /// A refused code is asked for again after 5 s, 15 s, then every 60 s while the panel is open
    /// and shows no code; only on a live connection; a code on screen or a closed panel drops the
    /// schedule; a panel opened afresh starts from the first wait, the owner's «Повторить» on an
    /// open one continues it; a lost connection leaves the asking to the next one.
    #[test]
    fn a_refused_code_is_asked_for_again_on_a_widening_schedule() {
        let mut s = AgentState {
            connected: true,
            ..AgentState::default()
        };
        assert!(open(&mut s));
        let mut now = T0;
        for (n, wait) in [5_000, 15_000, 60_000, 60_000, 60_000]
            .into_iter()
            .enumerate()
        {
            assert!(code_refused(&mut s, now), "refusal {}", n + 1);
            assert_eq!(
                s.pairing_retry.refusals,
                u32::try_from(n + 1).expect("small")
            );
            assert!(!retry_due(&mut s, now + wait - 1), "not before {wait} ms");
            s.connected = false;
            assert!(!retry_due(&mut s, now + wait), "offline: not now");
            s.connected = true;
            assert!(retry_due(&mut s, now + wait), "after {wait} ms");
            assert!(!retry_due(&mut s, now + wait), "once");
            now += wait;
        }

        // The code came: the schedule goes; a refusal now (a code is shown) asks for nothing.
        assert!(code_refused(&mut s, now));
        s.pairing_code = Some("123456".into());
        assert!(!retry_due(&mut s, now + 60_000));
        assert_eq!(s.pairing_retry, CodeRetry::default());
        assert!(!code_refused(&mut s, now));
        s.pairing_code = None;

        // «Повторить» on the open panel continues the schedule; a fresh panel starts it again.
        assert!(code_refused(&mut s, now));
        assert!(code_refused(&mut s, now));
        assert!(open(&mut s));
        assert_eq!(s.pairing_retry.due_ms, None, "the request goes now");
        assert!(code_refused(&mut s, now));
        assert_eq!(s.pairing_retry.refusals, 3);
        close(&mut s);
        assert_eq!(s.pairing_retry, CodeRetry::default());
        assert!(!retry_due(&mut s, now + 120_000));
        assert!(
            !code_refused(&mut s, now),
            "a closed panel waits for nothing"
        );
        assert!(open(&mut s));
        assert!(code_refused(&mut s, now));
        assert_eq!(s.pairing_retry.refusals, 1);
        assert_eq!(s.pairing_retry.due_ms, Some(now + 5_000));

        // A lost connection: the next one asks at once, and its refusal continues the count.
        connection_lost(&mut s, now);
        assert_eq!(s.pairing_retry.due_ms, None);
        s.connected = true;
        assert!(!retry_due(&mut s, now + 120_000));
        assert!(code_refused(&mut s, now));
        assert_eq!(s.pairing_retry.refusals, 2);
        assert_eq!(s.pairing_retry.due_ms, Some(now + 15_000));
    }
}
