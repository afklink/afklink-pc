//! The PC's request to the owner («Сделать владельцем» on a guest, «Отвязать» on the owner) as the
//! «Доступ» list shows it on the person's row.
//!
//! The server keeps the roles and the requests; this is the PC's view of its own, fed by what it
//! sent and by `owner_request_state`, which is the request's truth (`owner_changed`,
//! `binding_added` and `agent_ready` are the roles'). At most one request is in flight on a PC (the
//! server holds it as `busy`, and so does this), and how recent ones ended stays on their rows for
//! [`ENDED_SHOWN_MS`].
//!
//! ```text
//!   ask ──► Asked ──(pending)──► Pending ──(cancel)──► Cancelling
//!            │                     │                        │
//!            │       reconnect ──► Rechecking ─(pending)─► Pending
//!            ▼                     ▼                        ▼
//!   confirmed / declined / expired / cancelled / refused ──► Ended note (shown, then gone)
//! ```
//!
//!
//! Every wait has an end of its own, so a row never waits for ever ([`OwnerRequests::tick`]). A
//! third kind of request, `pc_allow`, is the server's and never asked here ([`Newcomer`]).
//!
//! Times are Unix ms from the caller, so every step is a plain function a test drives; logging is
//! here, at debug for each decision and at info for each outcome, with ids and never a name.

use afklink_protocol::{
    BindingInfo, BindingRole, OwnerRequestKind, OwnerRequestReason, OwnerRequestState,
    OwnerStateKind,
};

/// How long an outcome stays on its row: long enough to read two words, short enough that the row
/// is back to normal by the next look.
pub const ENDED_SHOWN_MS: i64 = 8_000;

/// How long the server gets to answer a request, or a cancel, over a live connection.
pub const ANSWER_WAIT_MS: i64 = 15_000;

/// How long after a reconnect a request still pending is waited for (the server re-sends it right
/// after `agent_ready`).
pub const RECHECK_WAIT_MS: i64 = 5_000;

/// Past a pending request's deadline, how long the server's `expired` is waited for before the row
/// says so by itself: the server sweeps expired requests once a minute.
pub const EXPIRY_GRACE_MS: i64 = 90_000;

/// Where the request in flight is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Pressed on this PC; the server has not answered (the message may be held while offline).
    /// Nobody has been asked yet — on a PC with no owner nobody will be — so the row says nothing
    /// and holds its buttons.
    Asked,
    /// Opened by the server: waiting for the owner until `expires_at`.
    Pending,
    /// «Отменить запрос» pressed; the server's `cancelled` not heard yet.
    Cancelling,
    /// Pending before a reconnect, and not re-sent by the server yet.
    Rechecking,
}

impl Stage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Asked => "asked",
            Self::Pending => "pending",
            Self::Cancelling => "cancelling",
            Self::Rechecking => "rechecking",
        }
    }
}

/// The newcomer a `pc_allow` is about, as the server names them (`owner_request_state.username` /
/// `first_name`, raw: the window cleans them as it cleans every name): not in the PC's list yet.
///
/// `pc_allow` ([`OwnerStateKind::PcAllow`]) is «Разрешить» in the pairing prompt on a PC that has
/// an owner while someone other than the owner had a session there. The server binds nobody yet and
/// asks the owner; the PC hears of it as `owner_request_state` with the pairing's id, and the
/// request is the one in flight here like any other (one at a time: «Сделать владельцем» meanwhile
/// says «Уже есть запрос», as the server would). The newcomer has no row in «Доступ» yet, so the
/// window draws a row of its own for them ([`OwnerRequests::newcomer`]) with
/// «Ждём подтверждения · m:ss» and «Отменить запрос», the waiting words of the PC's own requests,
/// until the owner answers. Allowed, `binding_added` gives them their row and the outcome moves
/// onto it; anything else, the row says how it ended for [`ENDED_SHOWN_MS`] and goes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Newcomer {
    /// Without its `@`.
    pub username: Option<String>,
    pub first_name: Option<String>,
}

impl Newcomer {
    /// Neither name: the row can only say `#id`.
    pub fn is_empty(&self) -> bool {
        self.username.is_none() && self.first_name.is_none()
    }
}

/// The one request in flight on this PC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlight {
    pub kind: OwnerStateKind,
    /// The person whose row it is on: the guest for `make_owner`, the owner for `unbind_owner`, the
    /// newcomer for `pc_allow`.
    pub telegram_user_id: i64,
    /// `pc_allow`'s newcomer, named as the server named them (else as this PC's prompt did); `None`
    /// for the PC's own two kinds, whose person is in the list.
    pub newcomer: Option<Newcomer>,
    /// The server's id, once it opened the request.
    pub request_id: Option<String>,
    /// Unix ms the owner has until, once the server opened the request.
    pub expires_at: Option<i64>,
    pub stage: Stage,
    /// When the stage began, or when the connection that carries it came up: Unix ms, for the
    /// waits.
    pub since_ms: i64,
}

impl InFlight {
    /// The server opened the request: a confirmation was actually asked of the PC's owner (the bot,
    /// or the card in his app). Only then does the row say «Ждём подтверждения» and offer
    /// «Отменить запрос»; while `Asked` (no answer from the server yet, and none but `applied` on a
    /// PC with no owner) it does neither: the row holds its buttons, disabled, and says nothing.
    ///
    /// On a PC with no owner the server never asks anyone: it applies `make_owner` at once
    /// (`applied`). Saying «Ждём подтверждения» from the press would show it on the only binding of
    /// an ownerless PC until `applied` (0.3 s later) reached the window's next read.
    pub fn owner_asked(&self) -> bool {
        matches!(
            self.stage,
            Stage::Pending | Stage::Cancelling | Stage::Rechecking
        )
    }
}

/// How a request ended, as its row says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The owner confirmed: «Подтверждено»; for `pc_allow` «Разрешено», the word of his button (the
    /// window words it by the kind).
    Confirmed,
    /// The owner declined: «Отклонено».
    Declined,
    /// Nobody answered in time: «Время вышло».
    Expired,
    /// Withdrawn — by this PC, or the owner left: «Запрос отменён».
    Cancelled,
    /// Another request is in flight on this PC: «Уже есть запрос».
    Busy,
    /// Too many requests from this PC lately: «Слишком часто».
    RateLimited,
    /// Not opened: the server failed, refused it as stale, or never answered:
    /// «Не удалось отправить».
    Failed,
}

impl Outcome {
    /// `OwnerRequestOutcome` in the window (`tauri.ts`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Declined => "declined",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Busy => "busy",
            Self::RateLimited => "rate_limited",
            Self::Failed => "failed",
        }
    }
}

/// How a request ended, on its row until `until_ms`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    pub kind: OwnerStateKind,
    pub telegram_user_id: i64,
    /// `pc_allow`'s newcomer, for the row of their own the window draws until a binding gives them
    /// one ([`InFlight::newcomer`]).
    pub newcomer: Option<Newcomer>,
    pub outcome: Outcome,
    pub until_ms: i64,
}

/// What a press asks of the orchestrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask {
    /// Send `owner_request` with this kind for this person.
    Send,
    /// Nothing to send: another request is in flight (its row says so, this one's says
    /// «Уже есть запрос»).
    Busy,
}

/// The PC's requests to the owner: the one in flight and how recent ones ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnerRequests {
    pub current: Option<InFlight>,
    /// One per person at most, newest last.
    pub ended: Vec<Ended>,
    /// The last pairing approved on this PC, by Telegram id, with the names its prompt had: what a
    /// `pc_allow` state that comes without names is named by — a refusal at the press (`busy`,
    /// `rate_limited`, `failed`) opens no request, so nothing here was told the names before.
    approved: Option<(i64, Newcomer)>,
}

impl OwnerRequests {
    /// A request is in flight: the window holds back the other owner-level buttons.
    pub fn busy(&self) -> bool {
        self.current.is_some()
    }

    /// The person whose `pc_allow` is on screen — in flight, else the last that ended while its
    /// outcome is shown — with the names they go by: the row the window draws for someone who has
    /// no binding yet (it draws none once the list has them). The request itself is
    /// [`Self::in_flight_for`] / [`Self::ended_for`] of the id, as on any row.
    pub fn newcomer(&self) -> Option<(i64, Option<&Newcomer>)> {
        if let Some(c) = self
            .current
            .as_ref()
            .filter(|c| c.kind == OwnerStateKind::PcAllow)
        {
            return Some((c.telegram_user_id, c.newcomer.as_ref()));
        }
        self.ended
            .iter()
            .rev()
            .find(|e| e.kind == OwnerStateKind::PcAllow)
            .map(|e| (e.telegram_user_id, e.newcomer.as_ref()))
    }

    /// «Разрешить» pressed on this PC for `telegram_user_id`, whose prompt named them so: kept for
    /// a `pc_allow` state that names nobody (the last approval only — one pairing is answered at a
    /// time).
    pub fn note_approved(&mut self, telegram_user_id: i64, names: Newcomer) {
        tracing::debug!(
            telegram_user_id,
            named = !names.is_empty(),
            "owner request: a pairing approved on this PC; its names kept for a pc_allow the server \
             may hold it as"
        );
        self.approved = Some((telegram_user_id, names));
    }

    /// The names for `pc_allow`'s newcomer `telegram_user_id`: the state's, else the request's own
    /// from before, else this PC's last approval of that account. Which one is said at debug.
    fn newcomer_names(
        &self,
        telegram_user_id: i64,
        from_state: Option<Newcomer>,
        ours: bool,
    ) -> Newcomer {
        if let Some(names) = from_state.filter(|n| !n.is_empty()) {
            return names;
        }
        // The request's own: in flight, or ended already (its newcomer's binding came first).
        let kept = ours
            .then(|| self.current.as_ref().and_then(|c| c.newcomer.clone()))
            .flatten()
            .or_else(|| {
                self.ended
                    .iter()
                    .rev()
                    .find(|e| {
                        e.kind == OwnerStateKind::PcAllow && e.telegram_user_id == telegram_user_id
                    })
                    .and_then(|e| e.newcomer.clone())
            })
            .filter(|n| !n.is_empty());
        if let Some(names) = kept {
            tracing::debug!(
                telegram_user_id,
                "owner request: pc_allow named nobody this time; the names it came with are kept"
            );
            return names;
        }
        match self
            .approved
            .as_ref()
            .filter(|(id, _)| *id == telegram_user_id)
        {
            Some((_, names)) => {
                tracing::debug!(
                    telegram_user_id,
                    "owner request: pc_allow named nobody; named as this PC's prompt named them"
                );
                names.clone()
            }
            None => {
                tracing::debug!(
                    telegram_user_id,
                    "owner request: pc_allow named nobody, and no approval here names them: the \
                     row says #id"
                );
                Newcomer::default()
            }
        }
    }

    /// The request in flight on `telegram_user_id`'s row, if it is theirs.
    pub fn in_flight_for(&self, telegram_user_id: i64) -> Option<&InFlight> {
        self.current
            .as_ref()
            .filter(|c| c.telegram_user_id == telegram_user_id)
    }

    /// How the last request on `telegram_user_id`'s row ended, while it is shown.
    pub fn ended_for(&self, telegram_user_id: i64) -> Option<&Ended> {
        self.ended
            .iter()
            .rev()
            .find(|e| e.telegram_user_id == telegram_user_id)
    }

    /// The person pressed «Сделать владельцем» (or «Отвязать» on the owner) on this PC.
    pub fn ask(&mut self, kind: OwnerRequestKind, telegram_user_id: i64, now_ms: i64) -> Ask {
        if let Some(c) = &self.current {
            tracing::debug!(
                kind = kind.as_str(),
                telegram_user_id,
                in_flight_kind = c.kind.as_str(),
                in_flight_for = c.telegram_user_id,
                in_flight_stage = c.stage.as_str(),
                request_id = c.request_id.as_deref().unwrap_or("-"),
                "owner request: another is in flight on this PC (at most one): not sent, «Уже \
                 есть запрос» on the row"
            );
            self.end(kind.into(), telegram_user_id, None, Outcome::Busy, now_ms);
            return Ask::Busy;
        }
        self.ended
            .retain(|e| e.telegram_user_id != telegram_user_id);
        self.current = Some(InFlight {
            kind: kind.into(),
            telegram_user_id,
            newcomer: None,
            request_id: None,
            expires_at: None,
            stage: Stage::Asked,
            since_ms: now_ms,
        });
        tracing::debug!(
            kind = kind.as_str(),
            telegram_user_id,
            "owner request: asked on this PC; the row holds its buttons until the server answers \
             («Ждём подтверждения» only once it opens the request: pending)"
        );
        Ask::Send
    }

    /// «Отменить запрос»: the request's id to send `owner_request_cancel` with, or `None` when
    /// there is nothing the server can be told yet (not opened, or already being cancelled).
    pub fn cancel(&mut self, now_ms: i64) -> Option<String> {
        let Some(c) = self.current.as_mut() else {
            tracing::debug!("owner request: cancel pressed with nothing in flight; nothing to do");
            return None;
        };
        match (c.stage, c.request_id.clone()) {
            (Stage::Pending | Stage::Rechecking, Some(id)) => {
                tracing::debug!(
                    request_id = %id,
                    kind = c.kind.as_str(),
                    telegram_user_id = c.telegram_user_id,
                    was = c.stage.as_str(),
                    "owner request: cancel pressed; owner_request_cancel sent, the row waits for \
                     the server's cancelled"
                );
                c.stage = Stage::Cancelling;
                c.since_ms = now_ms;
                Some(id)
            }
            (stage, id) => {
                tracing::debug!(
                    request_id = id.as_deref().unwrap_or("-"),
                    stage = stage.as_str(),
                    "owner request: cancel pressed where it cannot go (not opened yet, or already \
                     being cancelled); nothing sent"
                );
                None
            }
        }
    }

    /// The server's word on a request (`owner_request_state`). `newcomer`: the names a `pc_allow`
    /// state carries (ignored for the PC's own two kinds).
    #[allow(
        clippy::too_many_arguments,
        reason = "the message's fields, one each, as the wire has them"
    )]
    pub fn on_state(
        &mut self,
        request_id: Option<&str>,
        kind: OwnerStateKind,
        telegram_user_id: i64,
        state: OwnerRequestState,
        expires_at: Option<i64>,
        reason: Option<OwnerRequestReason>,
        newcomer: Option<Newcomer>,
        now_ms: i64,
    ) {
        let ours = self.current.as_ref().is_some_and(|c| {
            match (&c.request_id, request_id) {
                (Some(mine), Some(theirs)) => mine == theirs,
                // Not opened when we last heard: the person and the kind say it is this one.
                _ => c.kind == kind && c.telegram_user_id == telegram_user_id,
            }
        });
        let was = self.current.as_ref().map_or("-", |c| c.stage.as_str());
        // Only `pc_allow`'s person needs naming: the PC's own two are about someone in its list.
        let newcomer = (kind == OwnerStateKind::PcAllow)
            .then(|| self.newcomer_names(telegram_user_id, newcomer, ours));
        if state == OwnerRequestState::Pending {
            let keep_cancelling = ours
                && self
                    .current
                    .as_ref()
                    .is_some_and(|c| c.stage == Stage::Cancelling);
            if keep_cancelling {
                tracing::debug!(
                    request_id = request_id.unwrap_or("-"),
                    kind = kind.as_str(),
                    "owner request: pending again while its cancel is on the way (re-sent after a \
                     reconnect); the row keeps waiting for the cancel"
                );
                if let Some(c) = self.current.as_mut() {
                    c.expires_at = expires_at.or(c.expires_at);
                    c.newcomer = newcomer.or(c.newcomer.take());
                }
                return;
            }
            if !ours {
                if let Some(c) = &self.current {
                    tracing::debug!(
                        replaced_kind = c.kind.as_str(),
                        replaced_for = c.telegram_user_id,
                        replaced_stage = c.stage.as_str(),
                        "owner request: the server names another request as the one pending on \
                         this PC; it replaces the one shown"
                    );
                }
            }
            self.ended
                .retain(|e| e.telegram_user_id != telegram_user_id);
            if kind == OwnerStateKind::PcAllow {
                tracing::debug!(
                    request_id = request_id.unwrap_or("-"),
                    telegram_user_id,
                    again = ours,
                    named = newcomer.as_ref().is_some_and(|n| !n.is_empty()),
                    "owner request: pc_allow — «Разрешить» on this PC came while someone other \
                     than the owner had a session here, so the server holds the pairing for the \
                     owner; «Доступ» shows a row of its own for the newcomer: «Ждём подтверждения» \
                     and «Отменить запрос»"
                );
            }
            self.current = Some(InFlight {
                kind,
                telegram_user_id,
                newcomer,
                request_id: request_id.map(str::to_string),
                expires_at,
                stage: Stage::Pending,
                since_ms: now_ms,
            });
            tracing::info!(
                request_id = request_id.unwrap_or("-"),
                kind = kind.as_str(),
                telegram_user_id,
                expires_at = expires_at.unwrap_or(0),
                was,
                "owner request pending: waiting for the owner's answer in Telegram"
            );
            return;
        }
        if ours {
            self.current = None;
        } else {
            tracing::debug!(
                request_id = request_id.unwrap_or("-"),
                kind = kind.as_str(),
                telegram_user_id,
                state = state.as_str(),
                in_flight = self.current.is_some(),
                "owner request: an outcome for a request not in flight here (settled while away, \
                 or another one); shown on its row all the same"
            );
        }
        let outcome = match (state, reason) {
            (OwnerRequestState::Confirmed, _) => Some(Outcome::Confirmed),
            // Done without asking (the PC had no owner): the role on the row is the result.
            (OwnerRequestState::Applied, _) => None,
            (OwnerRequestState::Declined, _) => Some(Outcome::Declined),
            (OwnerRequestState::Expired, _) => Some(Outcome::Expired),
            // The guest left: the row goes with the binding.
            (OwnerRequestState::Cancelled, Some(OwnerRequestReason::TargetLeft)) => None,
            (OwnerRequestState::Cancelled, _) => Some(Outcome::Cancelled),
            (OwnerRequestState::Refused, Some(OwnerRequestReason::Busy)) => Some(Outcome::Busy),
            (OwnerRequestState::Refused, Some(OwnerRequestReason::RateLimited)) => {
                Some(Outcome::RateLimited)
            }
            // `failed`, and the refusals that mean this PC's list was stale (`not_bound`,
            // `already_owner`, `not_owner`): the list follows the server's roles anyway.
            (OwnerRequestState::Refused, _) => Some(Outcome::Failed),
            (OwnerRequestState::Pending, _) => None,
        };
        tracing::info!(
            request_id = request_id.unwrap_or("-"),
            kind = kind.as_str(),
            telegram_user_id,
            state = state.as_str(),
            reason = reason.map_or("-", OwnerRequestReason::as_str),
            was,
            shown = outcome.map_or("nothing (the roles say it)", Outcome::as_str),
            "owner request ended"
        );
        if kind == OwnerStateKind::PcAllow {
            tracing::debug!(
                request_id = request_id.unwrap_or("-"),
                telegram_user_id,
                state = state.as_str(),
                "owner request: pc_allow ended — {}",
                if state == OwnerRequestState::Confirmed {
                    "the owner allowed: binding_added gives the newcomer a row, and «Разрешено» \
                     moves onto it"
                } else {
                    "the newcomer is not bound: their row says how it ended for a few seconds, \
                     then goes"
                }
            );
        }
        if let Some(outcome) = outcome {
            self.end(kind, telegram_user_id, newcomer, outcome, now_ms);
        } else {
            self.ended
                .retain(|e| e.telegram_user_id != telegram_user_id);
        }
    }

    /// `binding_added` for `telegram_user_id`: if that is `pc_allow`'s newcomer, the owner has
    /// allowed — the binding comes in the same step as `confirmed`, and either can be first. The
    /// request ends as confirmed now, so the newcomer's new row does not wait under
    /// «Ждём подтверждения» for the other; a `confirmed` after it finds nothing in flight and says
    /// the same.
    ///
    /// True when the binding is `pc_allow`'s — in flight until now, or allowed a moment ago: the
    /// owner made it in Telegram, so no pairing code was spent for it (the server revoked the
    /// prompt's code when it held the pairing) and the pairing panel, if open now, is another one.
    pub fn newcomer_bound(&mut self, telegram_user_id: i64, now_ms: i64) -> bool {
        let Some(c) = self.current.take_if(|c| {
            c.kind == OwnerStateKind::PcAllow && c.telegram_user_id == telegram_user_id
        }) else {
            return self.ended.iter().any(|e| {
                e.kind == OwnerStateKind::PcAllow
                    && e.telegram_user_id == telegram_user_id
                    && e.outcome == Outcome::Confirmed
            });
        };
        tracing::info!(
            request_id = c.request_id.as_deref().unwrap_or("-"),
            telegram_user_id,
            stage = c.stage.as_str(),
            "owner request: pc_allow's newcomer is bound (binding_added before the server's \
             confirmed): the owner allowed — «Разрешено» on their row"
        );
        self.end(
            c.kind,
            telegram_user_id,
            c.newcomer,
            Outcome::Confirmed,
            now_ms,
        );
        true
    }

    /// A new signaling connection is up: what was asked goes out now (held while offline), and a
    /// pending request is re-sent by the server if it still is.
    pub fn reconnected(&mut self, now_ms: i64) {
        let Some(c) = self.current.as_mut() else {
            return;
        };
        let was = c.stage;
        if matches!(c.stage, Stage::Pending) {
            c.stage = Stage::Rechecking;
        }
        c.since_ms = now_ms;
        tracing::debug!(
            request_id = c.request_id.as_deref().unwrap_or("-"),
            kind = c.kind.as_str(),
            telegram_user_id = c.telegram_user_id,
            was = was.as_str(),
            now = c.stage.as_str(),
            "owner request: signaling connected again; the server's answer is waited for afresh"
        );
    }

    /// The binding of `telegram_user_id` is gone: nothing more to show on a row that is gone.
    pub fn binding_removed(&mut self, telegram_user_id: i64) {
        let before = self.ended.len();
        self.ended
            .retain(|e| e.telegram_user_id != telegram_user_id);
        if before != self.ended.len() {
            tracing::debug!(
                telegram_user_id,
                "owner request: the person's binding is gone; their row's outcome with it"
            );
        }
    }

    /// The waits' ends and the outcomes' time on screen, at `now_ms`. `connected`: the signaling
    /// link is up (the server's answers can come only then). `bindings`: the roles as they are, for
    /// a request that settled while the PC was away.
    ///
    /// - No answer to the request within [`ANSWER_WAIT_MS`] of a live connection ends it as not
    ///   sent (a server older than roles answers `owner_request` with an `error` frame only).
    /// - No `cancelled` within [`ANSWER_WAIT_MS`] after «Отменить запрос» drops it (the server had
    ///   settled it otherwise; the roles say how).
    /// - After a reconnect the server re-sends a request still pending right after `agent_ready`;
    ///   one not re-sent within [`RECHECK_WAIT_MS`] settled while the PC was away: confirmed when
    ///   the roles show it, else dropped without a word on the row.
    /// - A pending request past its deadline and [`EXPIRY_GRACE_MS`] (the server sweeps once a
    ///   minute) ends as expired, connection or not.
    pub fn tick(&mut self, now_ms: i64, connected: bool, bindings: &[BindingInfo]) {
        let before = self.ended.len();
        self.ended.retain(|e| e.until_ms > now_ms);
        if self.ended.len() != before {
            tracing::debug!(
                gone = before - self.ended.len(),
                left = self.ended.len(),
                "owner request: outcomes shown long enough; their rows are back to normal"
            );
        }
        let Some(c) = self.current.clone() else {
            return;
        };
        let waited = now_ms.saturating_sub(c.since_ms);
        let past_deadline = c
            .expires_at
            .is_some_and(|at| now_ms > at.saturating_add(EXPIRY_GRACE_MS));
        let ctx = |what: &'static str| {
            tracing::info!(
                request_id = c.request_id.as_deref().unwrap_or("-"),
                kind = c.kind.as_str(),
                telegram_user_id = c.telegram_user_id,
                stage = c.stage.as_str(),
                waited_ms = waited,
                expires_at = c.expires_at.unwrap_or(0),
                "owner request: {what}"
            );
        };
        match c.stage {
            Stage::Pending | Stage::Rechecking | Stage::Cancelling if past_deadline => {
                ctx("past its deadline and the server never said: «Время вышло» on the row");
                self.current = None;
                self.end(
                    c.kind,
                    c.telegram_user_id,
                    c.newcomer,
                    Outcome::Expired,
                    now_ms,
                );
            }
            Stage::Asked if connected && waited >= ANSWER_WAIT_MS => {
                ctx(
                    "no answer from the server (one older than roles answers with an error \
                     frame only): «Не удалось отправить» on the row",
                );
                self.current = None;
                self.end(
                    c.kind,
                    c.telegram_user_id,
                    c.newcomer,
                    Outcome::Failed,
                    now_ms,
                );
            }
            Stage::Cancelling if connected && waited >= ANSWER_WAIT_MS => {
                ctx(
                    "no answer to the cancel: the server had settled the request otherwise; the \
                     row follows the roles",
                );
                self.current = None;
            }
            Stage::Rechecking if connected && waited >= RECHECK_WAIT_MS => {
                let role = bindings
                    .iter()
                    .find(|b| b.telegram_user_id == c.telegram_user_id)
                    .map(|b| b.role);
                let done = match c.kind {
                    OwnerStateKind::MakeOwner => role == Some(Some(BindingRole::Owner)),
                    OwnerStateKind::UnbindOwner => role.is_none(),
                    // The newcomer is bound: the owner allowed while the PC was away.
                    OwnerStateKind::PcAllow => role.is_some(),
                };
                self.current = None;
                if done {
                    ctx(
                        "not re-sent after the reconnect, and the roles show it done: settled \
                         while away, «Подтверждено» («Разрешено» for pc_allow) on the row",
                    );
                    self.end(
                        c.kind,
                        c.telegram_user_id,
                        c.newcomer,
                        Outcome::Confirmed,
                        now_ms,
                    );
                } else {
                    ctx(
                        "not re-sent after the reconnect, and the roles show nothing changed: \
                         settled while away (declined, expired or cancelled); the row goes back \
                         to normal",
                    );
                }
            }
            _ => {}
        }
    }

    fn end(
        &mut self,
        kind: OwnerStateKind,
        telegram_user_id: i64,
        newcomer: Option<Newcomer>,
        outcome: Outcome,
        now: i64,
    ) {
        self.ended
            .retain(|e| e.telegram_user_id != telegram_user_id);
        self.ended.push(Ended {
            kind,
            telegram_user_id,
            newcomer,
            outcome,
            until_ms: now.saturating_add(ENDED_SHOWN_MS),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUEST: i64 = 67890;
    const OWNER: i64 = 12345;
    const ID: &str = "e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b";
    const T0: i64 = 1_789_600_000_000;

    fn binding(id: i64, role: Option<BindingRole>) -> BindingInfo {
        BindingInfo {
            telegram_user_id: id,
            username: None,
            first_name: Some("x".into()),
            role,
        }
    }

    fn pending(r: &mut OwnerRequests, kind: OwnerRequestKind, uid: i64, now: i64) {
        r.on_state(
            Some(ID),
            kind.into(),
            uid,
            OwnerRequestState::Pending,
            Some(now + 600_000),
            None,
            None,
            now,
        );
    }

    #[test]
    fn a_request_goes_from_asked_to_pending_to_confirmed() {
        let mut r = OwnerRequests::default();
        assert_eq!(r.ask(OwnerRequestKind::MakeOwner, GUEST, T0), Ask::Send);
        assert!(r.busy());
        assert_eq!(r.in_flight_for(GUEST).map(|c| c.stage), Some(Stage::Asked));
        pending(&mut r, OwnerRequestKind::MakeOwner, GUEST, T0 + 200);
        let c = r.in_flight_for(GUEST).expect("in flight");
        assert_eq!(c.stage, Stage::Pending);
        assert_eq!(c.request_id.as_deref(), Some(ID));
        assert_eq!(c.expires_at, Some(T0 + 200 + 600_000));
        r.on_state(
            Some(ID),
            OwnerStateKind::MakeOwner,
            GUEST,
            OwnerRequestState::Confirmed,
            None,
            None,
            None,
            T0 + 60_000,
        );
        assert!(!r.busy());
        assert_eq!(
            r.ended_for(GUEST).map(|e| e.outcome),
            Some(Outcome::Confirmed)
        );
        // Shown briefly, then the row is back to normal.
        r.tick(T0 + 60_000 + ENDED_SHOWN_MS - 1, true, &[]);
        assert!(r.ended_for(GUEST).is_some());
        r.tick(T0 + 60_000 + ENDED_SHOWN_MS, true, &[]);
        assert!(r.ended_for(GUEST).is_none());
    }

    /// On an ownerless PC «Назначить владельцем» must not show «Ждём подтверждения» with
    /// nobody to confirm. A press is not a question to anyone until the server
    /// opens it; `applied` ends it with nothing on the row but the new role.
    #[test]
    fn the_owner_is_asked_only_once_the_server_opens_the_request() {
        // No owner: asked here, applied there — never asked of anyone.
        let mut r = OwnerRequests::default();
        r.ask(OwnerRequestKind::MakeOwner, GUEST, T0);
        let c = r.in_flight_for(GUEST).expect("in flight");
        assert_eq!(c.stage, Stage::Asked);
        assert!(
            !c.owner_asked(),
            "the server has not answered: nobody asked yet"
        );
        r.on_state(
            Some(ID),
            OwnerStateKind::MakeOwner,
            GUEST,
            OwnerRequestState::Applied,
            None,
            None,
            None,
            T0 + 300,
        );
        assert!(!r.busy());
        assert!(r.ended_for(GUEST).is_none(), "the role on the row says it");

        // An owner: asked once the server opens it, and through its cancel and a reconnect.
        let mut r = OwnerRequests::default();
        r.ask(OwnerRequestKind::MakeOwner, GUEST, T0);
        pending(&mut r, OwnerRequestKind::MakeOwner, GUEST, T0 + 300);
        assert!(r.in_flight_for(GUEST).is_some_and(InFlight::owner_asked));
        r.reconnected(T0 + 1_000);
        assert_eq!(
            r.in_flight_for(GUEST).map(|c| (c.stage, c.owner_asked())),
            Some((Stage::Rechecking, true))
        );
        pending(&mut r, OwnerRequestKind::MakeOwner, GUEST, T0 + 1_100);
        r.cancel(T0 + 2_000);
        assert_eq!(
            r.in_flight_for(GUEST).map(|c| (c.stage, c.owner_asked())),
            Some((Stage::Cancelling, true))
        );
    }

    #[test]
    fn every_ending_has_its_words_or_none() {
        use OwnerRequestReason as R;
        use OwnerRequestState as S;
        let cases: [(S, Option<R>, Option<Outcome>); 12] = [
            (S::Confirmed, None, Some(Outcome::Confirmed)),
            (S::Applied, None, None),
            (S::Declined, None, Some(Outcome::Declined)),
            (S::Expired, None, Some(Outcome::Expired)),
            (S::Cancelled, Some(R::ByPc), Some(Outcome::Cancelled)),
            (S::Cancelled, Some(R::OwnerLeft), Some(Outcome::Cancelled)),
            (S::Cancelled, Some(R::TargetLeft), None),
            (S::Refused, Some(R::Busy), Some(Outcome::Busy)),
            (S::Refused, Some(R::RateLimited), Some(Outcome::RateLimited)),
            (S::Refused, Some(R::Failed), Some(Outcome::Failed)),
            (S::Refused, Some(R::NotBound), Some(Outcome::Failed)),
            (S::Refused, Some(R::AlreadyOwner), Some(Outcome::Failed)),
        ];
        for (state, reason, shown) in cases {
            let mut r = OwnerRequests::default();
            r.ask(OwnerRequestKind::MakeOwner, GUEST, T0);
            let id = (state != S::Refused).then_some(ID);
            r.on_state(
                id,
                OwnerStateKind::MakeOwner,
                GUEST,
                state,
                None,
                reason,
                None,
                T0 + 1,
            );
            assert!(!r.busy(), "{state:?} {reason:?} ends the request");
            assert_eq!(
                r.ended_for(GUEST).map(|e| e.outcome),
                shown,
                "{state:?} {reason:?}"
            );
        }
    }

    #[test]
    fn at_most_one_request_in_flight_and_a_second_press_says_busy() {
        let mut r = OwnerRequests::default();
        assert_eq!(r.ask(OwnerRequestKind::MakeOwner, GUEST, T0), Ask::Send);
        assert_eq!(r.ask(OwnerRequestKind::UnbindOwner, OWNER, T0), Ask::Busy);
        assert_eq!(r.ended_for(OWNER).map(|e| e.outcome), Some(Outcome::Busy));
        assert_eq!(
            r.in_flight_for(GUEST).map(|c| c.kind),
            Some(OwnerStateKind::MakeOwner),
            "the first one carries on"
        );
    }

    /// The server's `busy` for one row, then the other request's `pending` it re-sends: both rows
    /// say theirs.
    #[test]
    fn a_busy_refusal_and_the_pending_one_both_show() {
        let mut r = OwnerRequests::default();
        r.ask(OwnerRequestKind::UnbindOwner, OWNER, T0);
        r.on_state(
            None,
            OwnerStateKind::UnbindOwner,
            OWNER,
            OwnerRequestState::Refused,
            None,
            Some(OwnerRequestReason::Busy),
            None,
            T0 + 1,
        );
        pending(&mut r, OwnerRequestKind::MakeOwner, GUEST, T0 + 2);
        assert_eq!(r.ended_for(OWNER).map(|e| e.outcome), Some(Outcome::Busy));
        assert_eq!(
            r.in_flight_for(GUEST).map(|c| c.stage),
            Some(Stage::Pending)
        );
    }

    #[test]
    fn cancel_goes_through_cancelling_and_a_re_sent_pending_does_not_undo_it() {
        let mut r = OwnerRequests::default();
        assert_eq!(r.cancel(T0), None, "nothing to cancel");
        r.ask(OwnerRequestKind::MakeOwner, GUEST, T0);
        assert_eq!(r.cancel(T0), None, "not opened yet: no id to name");
        pending(&mut r, OwnerRequestKind::MakeOwner, GUEST, T0 + 1);
        assert_eq!(r.cancel(T0 + 2).as_deref(), Some(ID));
        assert_eq!(
            r.in_flight_for(GUEST).map(|c| c.stage),
            Some(Stage::Cancelling)
        );
        assert_eq!(r.cancel(T0 + 3), None, "one cancel is enough");
        // A reconnect: the server re-sends the pending before it reads the held cancel.
        r.reconnected(T0 + 10);
        pending(&mut r, OwnerRequestKind::MakeOwner, GUEST, T0 + 11);
        assert_eq!(
            r.in_flight_for(GUEST).map(|c| c.stage),
            Some(Stage::Cancelling)
        );
        r.on_state(
            Some(ID),
            OwnerStateKind::MakeOwner,
            GUEST,
            OwnerRequestState::Cancelled,
            None,
            Some(OwnerRequestReason::ByPc),
            None,
            T0 + 12,
        );
        assert_eq!(
            r.ended_for(GUEST).map(|e| e.outcome),
            Some(Outcome::Cancelled)
        );
    }

    #[test]
    fn no_answer_from_a_server_older_than_roles_ends_as_not_sent() {
        let mut r = OwnerRequests::default();
        r.ask(OwnerRequestKind::MakeOwner, GUEST, T0);
        // Offline the message is held: no clock runs.
        r.tick(T0 + ANSWER_WAIT_MS * 4, false, &[]);
        assert!(r.busy());
        // Back online: it goes out now, and the wait starts now.
        r.reconnected(T0 + ANSWER_WAIT_MS * 4);
        r.tick(T0 + ANSWER_WAIT_MS * 5 - 1, true, &[]);
        assert!(r.busy());
        r.tick(T0 + ANSWER_WAIT_MS * 5, true, &[]);
        assert!(!r.busy());
        assert_eq!(r.ended_for(GUEST).map(|e| e.outcome), Some(Outcome::Failed));
    }

    #[test]
    fn a_cancel_nobody_answers_is_dropped() {
        let mut r = OwnerRequests::default();
        r.ask(OwnerRequestKind::MakeOwner, GUEST, T0);
        pending(&mut r, OwnerRequestKind::MakeOwner, GUEST, T0);
        r.cancel(T0);
        r.tick(T0 + ANSWER_WAIT_MS, true, &[]);
        assert!(!r.busy());
        assert!(r.ended_for(GUEST).is_none(), "the roles say how it went");
    }

    #[test]
    fn after_a_reconnect_a_request_not_re_sent_settles_by_the_roles() {
        // make_owner, and the guest is the owner now: it was confirmed while the PC was away.
        let mut r = OwnerRequests::default();
        r.ask(OwnerRequestKind::MakeOwner, GUEST, T0);
        pending(&mut r, OwnerRequestKind::MakeOwner, GUEST, T0);
        r.reconnected(T0 + 1_000);
        let roles = [
            binding(OWNER, Some(BindingRole::Guest)),
            binding(GUEST, Some(BindingRole::Owner)),
        ];
        r.tick(T0 + 1_000 + RECHECK_WAIT_MS - 1, true, &roles);
        assert_eq!(
            r.in_flight_for(GUEST).map(|c| c.stage),
            Some(Stage::Rechecking)
        );
        r.tick(T0 + 1_000 + RECHECK_WAIT_MS, true, &roles);
        assert_eq!(
            r.ended_for(GUEST).map(|e| e.outcome),
            Some(Outcome::Confirmed)
        );

        // unbind_owner, and the owner is still bound: nothing changed; no words on the row.
        let mut r = OwnerRequests::default();
        r.ask(OwnerRequestKind::UnbindOwner, OWNER, T0);
        pending(&mut r, OwnerRequestKind::UnbindOwner, OWNER, T0);
        r.reconnected(T0 + 1_000);
        r.tick(
            T0 + 1_000 + RECHECK_WAIT_MS,
            true,
            &[binding(OWNER, Some(BindingRole::Owner))],
        );
        assert!(!r.busy());
        assert!(r.ended_for(OWNER).is_none());

        // Re-sent by the server: still pending.
        let mut r = OwnerRequests::default();
        r.ask(OwnerRequestKind::MakeOwner, GUEST, T0);
        pending(&mut r, OwnerRequestKind::MakeOwner, GUEST, T0);
        r.reconnected(T0 + 1_000);
        pending(&mut r, OwnerRequestKind::MakeOwner, GUEST, T0 + 1_100);
        r.tick(T0 + 1_000 + RECHECK_WAIT_MS * 3, true, &[]);
        assert_eq!(
            r.in_flight_for(GUEST).map(|c| c.stage),
            Some(Stage::Pending)
        );
    }

    #[test]
    fn a_pending_request_past_its_deadline_expires_on_its_own() {
        let mut r = OwnerRequests::default();
        r.ask(OwnerRequestKind::MakeOwner, GUEST, T0);
        pending(&mut r, OwnerRequestKind::MakeOwner, GUEST, T0);
        let deadline = T0 + 600_000;
        r.tick(deadline + EXPIRY_GRACE_MS, false, &[]);
        assert!(r.busy(), "the server's word is waited for");
        r.tick(deadline + EXPIRY_GRACE_MS + 1, false, &[]);
        assert!(!r.busy());
        assert_eq!(
            r.ended_for(GUEST).map(|e| e.outcome),
            Some(Outcome::Expired)
        );
    }

    /// The server names a request pending this PC does not know (sent before a restart): it is the
    /// one in flight now.
    #[test]
    fn a_pending_request_from_before_a_restart_is_adopted() {
        let mut r = OwnerRequests::default();
        pending(&mut r, OwnerRequestKind::UnbindOwner, OWNER, T0);
        let c = r.in_flight_for(OWNER).expect("adopted");
        assert_eq!(c.kind, OwnerStateKind::UnbindOwner);
        assert_eq!(c.stage, Stage::Pending);
        assert_eq!(r.cancel(T0 + 1).as_deref(), Some(ID));
    }

    #[test]
    fn a_new_press_clears_the_rows_last_outcome_and_an_unbind_clears_it_too() {
        let mut r = OwnerRequests::default();
        r.ask(OwnerRequestKind::MakeOwner, GUEST, T0);
        r.on_state(
            Some(ID),
            OwnerStateKind::MakeOwner,
            GUEST,
            OwnerRequestState::Declined,
            None,
            None,
            None,
            T0 + 1,
        );
        assert!(r.ended_for(GUEST).is_some());
        r.ask(OwnerRequestKind::MakeOwner, GUEST, T0 + 2);
        assert!(r.ended_for(GUEST).is_none());
        r.on_state(
            Some(ID),
            OwnerStateKind::MakeOwner,
            GUEST,
            OwnerRequestState::Expired,
            None,
            None,
            None,
            T0 + 3,
        );
        r.binding_removed(GUEST);
        assert!(r.ended_for(GUEST).is_none());
    }

    // ── pc_allow: «Разрешить» on this PC held for the owner ──

    /// The contract's newcomer (`owner_request_state_pc_allow.json`).
    const NEWCOMER: i64 = 35791;
    const PAIRING_ID: &str = "5e6f7a8b-9c0d-4e1f-a2b3-c4d5e6f7a8b9";

    fn vasya() -> Newcomer {
        Newcomer {
            username: Some("vasya".into()),
            first_name: Some("Вася".into()),
        }
    }

    /// The server's word on the pairing it holds for the owner.
    fn pc_allow(
        r: &mut OwnerRequests,
        state: OwnerRequestState,
        reason: Option<OwnerRequestReason>,
        names: Option<Newcomer>,
        now: i64,
    ) {
        let id = (state != OwnerRequestState::Refused).then_some(PAIRING_ID);
        let expires_at = (state == OwnerRequestState::Pending).then_some(now + 600_000);
        r.on_state(
            id,
            OwnerStateKind::PcAllow,
            NEWCOMER,
            state,
            expires_at,
            reason,
            names,
            now,
        );
    }

    /// Pending: the request in flight is the newcomer's, asked of the owner, with the names their
    /// row is drawn by; it holds the PC's own requests as any other does. Allowed: «Разрешено» on
    /// the newcomer — on their own row until a binding gives them one — then gone.
    #[test]
    fn a_pc_allow_waits_on_the_newcomers_row_and_ends_allowed() {
        let mut r = OwnerRequests::default();
        assert_eq!(r.newcomer(), None);
        pc_allow(&mut r, OwnerRequestState::Pending, None, Some(vasya()), T0);
        let vasya = vasya();
        assert_eq!(r.newcomer(), Some((NEWCOMER, Some(&vasya))));
        let c = r.in_flight_for(NEWCOMER).expect("in flight");
        assert_eq!(
            (c.kind, c.stage, c.owner_asked()),
            (OwnerStateKind::PcAllow, Stage::Pending, true)
        );
        assert_eq!(c.request_id.as_deref(), Some(PAIRING_ID));
        assert_eq!(c.expires_at, Some(T0 + 600_000));
        // One question from the PC at a time: «Сделать владельцем» meanwhile is busy, as on the
        // server.
        assert!(r.busy());
        assert_eq!(r.ask(OwnerRequestKind::MakeOwner, GUEST, T0 + 1), Ask::Busy);
        assert_eq!(r.ended_for(GUEST).map(|e| e.outcome), Some(Outcome::Busy));
        // «Отменить запрос» names the pairing's id.
        let mut cancelled = r.clone();
        assert_eq!(cancelled.cancel(T0 + 2).as_deref(), Some(PAIRING_ID));

        pc_allow(
            &mut r,
            OwnerRequestState::Confirmed,
            None,
            None,
            T0 + 60_000,
        );
        assert!(!r.busy());
        let e = r.ended_for(NEWCOMER).expect("shown");
        assert_eq!(
            (e.kind, e.outcome, e.newcomer.as_ref()),
            (OwnerStateKind::PcAllow, Outcome::Confirmed, Some(&vasya)),
            "the names it came with, though the outcome named nobody"
        );
        assert_eq!(r.newcomer(), Some((NEWCOMER, Some(&vasya))));
        r.tick(T0 + 60_000 + ENDED_SHOWN_MS, true, &[]);
        assert_eq!(r.newcomer(), None);
    }

    /// Every way a `pc_allow` ends but the owner's «Разрешить»: the newcomer's row says it, with
    /// the PC's own requests' words, then goes. A refusal at the press opened no request at all.
    #[test]
    fn every_pc_allow_ending_has_its_words() {
        use OwnerRequestReason as R;
        use OwnerRequestState as S;
        let cases: [(S, Option<R>, Outcome); 10] = [
            (S::Declined, None, Outcome::Declined),
            (S::Expired, None, Outcome::Expired),
            (S::Cancelled, Some(R::ByPc), Outcome::Cancelled),
            (S::Cancelled, Some(R::ByRequester), Outcome::Cancelled),
            (S::Cancelled, Some(R::OwnerLeft), Outcome::Cancelled),
            (S::Cancelled, Some(R::Failed), Outcome::Cancelled),
            (S::Refused, Some(R::Busy), Outcome::Busy),
            (S::Refused, Some(R::RateLimited), Outcome::RateLimited),
            (S::Refused, Some(R::Failed), Outcome::Failed),
            (S::Confirmed, None, Outcome::Confirmed),
        ];
        for (state, reason, shown) in cases {
            let mut r = OwnerRequests::default();
            r.note_approved(NEWCOMER, vasya());
            if state != S::Refused {
                pc_allow(&mut r, S::Pending, None, Some(vasya()), T0);
            }
            pc_allow(&mut r, state, reason, None, T0 + 1);
            assert!(!r.busy(), "{state:?} {reason:?} ends it");
            let e = r.ended_for(NEWCOMER).expect("shown");
            assert_eq!(e.outcome, shown, "{state:?} {reason:?}");
            assert_eq!(e.newcomer, Some(vasya()), "{state:?} {reason:?}: named");
            assert_eq!(r.newcomer().map(|(id, _)| id), Some(NEWCOMER));
            r.tick(T0 + 1 + ENDED_SHOWN_MS, true, &[]);
            assert_eq!(r.newcomer(), None, "{state:?} {reason:?}: the row goes");
        }
    }

    /// The names: the state's when it has them; else the request's own; else this PC's last
    /// approval of that account (a refusal at the press, which no request preceded); else none —
    /// the row says `#id`. Another account's approval names nobody.
    #[test]
    fn a_pc_allow_that_names_nobody_is_named_as_best_it_can_be() {
        let mut r = OwnerRequests::default();
        pc_allow(&mut r, OwnerRequestState::Pending, None, Some(vasya()), T0);
        // Re-sent after a reconnect without the names: they stay.
        r.reconnected(T0 + 1);
        pc_allow(&mut r, OwnerRequestState::Pending, None, None, T0 + 2);
        assert_eq!(
            r.in_flight_for(NEWCOMER).and_then(|c| c.newcomer.clone()),
            Some(vasya())
        );

        let mut r = OwnerRequests::default();
        r.note_approved(NEWCOMER, vasya());
        pc_allow(
            &mut r,
            OwnerRequestState::Refused,
            Some(OwnerRequestReason::Busy),
            None,
            T0,
        );
        assert_eq!(
            r.ended_for(NEWCOMER).and_then(|e| e.newcomer.clone()),
            Some(vasya())
        );

        let mut r = OwnerRequests::default();
        r.note_approved(GUEST, vasya());
        pc_allow(
            &mut r,
            OwnerRequestState::Refused,
            Some(OwnerRequestReason::RateLimited),
            Some(Newcomer::default()),
            T0,
        );
        assert_eq!(
            r.ended_for(NEWCOMER).and_then(|e| e.newcomer.clone()),
            Some(Newcomer::default()),
            "no name for this account anywhere: #id"
        );
        // The PC's own kinds are never named: their person is in the list.
        let mut r = OwnerRequests::default();
        r.note_approved(GUEST, vasya());
        pending(&mut r, OwnerRequestKind::MakeOwner, GUEST, T0);
        assert_eq!(
            r.in_flight_for(GUEST).and_then(|c| c.newcomer.clone()),
            None
        );
        assert_eq!(r.newcomer(), None);
    }

    /// `binding_added` for the newcomer and `confirmed` come in the same step, in either order: the
    /// binding first ends the request as allowed, and the `confirmed` after it says the same; the
    /// binding after `confirmed` is told it is the held pairing's too. A binding for anyone else
    /// leaves it waiting, and is not one.
    #[test]
    fn the_newcomers_binding_ends_the_pc_allow_as_allowed() {
        let mut r = OwnerRequests::default();
        pc_allow(&mut r, OwnerRequestState::Pending, None, Some(vasya()), T0);
        assert!(!r.newcomer_bound(GUEST, T0 + 1));
        assert!(r.busy(), "someone else's binding");
        assert!(r.newcomer_bound(NEWCOMER, T0 + 2));
        assert!(!r.busy());
        assert_eq!(
            r.ended_for(NEWCOMER).map(|e| e.outcome),
            Some(Outcome::Confirmed)
        );
        pc_allow(&mut r, OwnerRequestState::Confirmed, None, None, T0 + 3);
        assert!(!r.busy());
        let e = r.ended_for(NEWCOMER).expect("shown");
        assert_eq!(
            (e.outcome, e.newcomer.clone()),
            (Outcome::Confirmed, Some(vasya()))
        );
        // `confirmed` first: the binding after it is the held pairing's all the same.
        let mut r = OwnerRequests::default();
        pc_allow(&mut r, OwnerRequestState::Pending, None, Some(vasya()), T0);
        pc_allow(&mut r, OwnerRequestState::Confirmed, None, None, T0 + 1);
        assert!(r.newcomer_bound(NEWCOMER, T0 + 2));
        // Declined, then bound some other way (an invite): not the held pairing's.
        let mut r = OwnerRequests::default();
        pc_allow(&mut r, OwnerRequestState::Pending, None, Some(vasya()), T0);
        pc_allow(&mut r, OwnerRequestState::Declined, None, None, T0 + 1);
        assert!(!r.newcomer_bound(NEWCOMER, T0 + 2));
        // A binding with no pc_allow in flight changes nothing.
        let mut r = OwnerRequests::default();
        r.ask(OwnerRequestKind::MakeOwner, GUEST, T0);
        assert!(!r.newcomer_bound(GUEST, T0 + 1));
        assert_eq!(r.in_flight_for(GUEST).map(|c| c.stage), Some(Stage::Asked));
    }

    /// Away while the owner decides: not re-sent after the reconnect, it settled — allowed if the
    /// newcomer is in the list now, else the row just goes; past its deadline, «Время вышло».
    #[test]
    fn a_pc_allow_settled_while_away_follows_the_list() {
        let mut r = OwnerRequests::default();
        pc_allow(&mut r, OwnerRequestState::Pending, None, Some(vasya()), T0);
        r.reconnected(T0 + 1_000);
        assert_eq!(
            r.in_flight_for(NEWCOMER)
                .map(|c| (c.stage, c.owner_asked())),
            Some((Stage::Rechecking, true))
        );
        r.tick(
            T0 + 1_000 + RECHECK_WAIT_MS,
            true,
            &[binding(NEWCOMER, Some(BindingRole::Guest))],
        );
        assert_eq!(
            r.ended_for(NEWCOMER).map(|e| e.outcome),
            Some(Outcome::Confirmed)
        );

        let mut r = OwnerRequests::default();
        pc_allow(&mut r, OwnerRequestState::Pending, None, Some(vasya()), T0);
        r.reconnected(T0 + 1_000);
        r.tick(T0 + 1_000 + RECHECK_WAIT_MS, true, &[]);
        assert!(!r.busy());
        assert_eq!(r.newcomer(), None, "declined, expired or withdrawn: no row");

        let mut r = OwnerRequests::default();
        pc_allow(&mut r, OwnerRequestState::Pending, None, Some(vasya()), T0);
        r.tick(T0 + 600_000 + EXPIRY_GRACE_MS + 1, false, &[]);
        assert_eq!(
            r.ended_for(NEWCOMER)
                .map(|e| (e.outcome, e.newcomer.clone())),
            Some((Outcome::Expired, Some(vasya())))
        );
    }
}
