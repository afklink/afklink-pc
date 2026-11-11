//! «Только игра» → «Только для гостей»: whether the game-only mode applies to a session, decided
//! for each session from the PC's settings and the role the server gave the viewer's binding.
//!
//! ## Where the role comes from
//!
//! Only from the server. Who connects is `session_request.telegram_user_id`: the server's word,
//! from the viewer's signed Telegram identity, never a field the viewer fills in. That account's
//! role is the role of its binding in the list the server keeps this PC told of:
//! `agent_ready.bindings[].role`, `binding_added.role` and `owner_changed` (`AgentState::bindings`,
//! mirrored here by the orchestrator at each of those, [`GameAccess::set_roles`]). Nothing the
//! viewer sends enters the decision.
//!
//! The decision table is on [`decide`]; how a change reaches live sessions is on [`GameAccess`];
//! when the game helper may act is on [`GameAccess::game_only_sessions`].
//!
//! ## Logs
//!
//! `debug`: the decision at each session's start and at every re-evaluation (the session, the
//! account, its role and the role before, both switches, the result and why), one line per
//! re-evaluation with its cause and how many sessions it moved, and a change of the settings or the
//! roles with what changed. The session's cell says each change of its capture mode at `info`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use afklink_protocol::BindingRole;
use afklink_transport::BindingInfo;

use crate::config::Config;
use crate::game::{CaptureMode, CaptureModeCell, GameBinding};
use crate::sync::lock;

/// The PC's game-only settings, as config.json has them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GamePolicy {
    /// «Показывать только игру» (`Config::game_only`).
    pub game_only: bool,
    /// «Только для гостей» (`Config::game_only_for_guests`).
    pub for_guests: bool,
    /// The game shown (`Config::game`).
    pub binding: Option<GameBinding>,
}

impl GamePolicy {
    pub fn from_config(config: &Config) -> Self {
        Self {
            game_only: config.game_only,
            for_guests: config.game_only_for_guests,
            binding: config.game.clone(),
        }
    }

    /// The capture mode of a session game-only applies to (`applies`), or does not.
    pub fn mode(&self, applies: bool) -> CaptureMode {
        if applies {
            CaptureMode::GameWindow {
                binding: self.binding.clone(),
            }
        } else {
            CaptureMode::Monitor
        }
    }

    /// For log lines.
    pub fn describe(&self) -> String {
        format!(
            "game-only {}, «Только для гостей» {}, game {}",
            if self.game_only { "on" } else { "off" },
            if self.for_guests { "on" } else { "off" },
            self.binding
                .as_ref()
                .map_or("none", GameBinding::shown_name)
        )
    }
}

/// The viewer's role on this PC, as the server's list has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerRole {
    /// The server lists the account as this PC's owner.
    Owner,
    /// The server lists it as a guest, and the PC has an owner.
    Guest,
    /// The server lists it as a guest, and nobody is the owner: everyone on this PC is a guest.
    GuestNoOwner,
    /// No role for it: a server older than roles sends none, or the account is not listed.
    Unknown,
}

impl ViewerRole {
    /// The role of `telegram_user_id` in the server's list `bindings`.
    pub fn of(bindings: &[BindingInfo], telegram_user_id: i64) -> Self {
        let role = bindings
            .iter()
            .find(|b| b.telegram_user_id == telegram_user_id)
            .and_then(|b| b.role);
        match role {
            Some(BindingRole::Owner) => Self::Owner,
            Some(BindingRole::Guest)
                if bindings.iter().any(|b| b.role == Some(BindingRole::Owner)) =>
            {
                Self::Guest
            }
            Some(BindingRole::Guest) => Self::GuestNoOwner,
            None => Self::Unknown,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Guest => "guest",
            Self::GuestNoOwner => "guest_no_owner",
            Self::Unknown => "unknown",
        }
    }

    /// The PC's owner, as the server says: the one role a guard on the owner's things lets through.
    /// No role (a server older than roles, an account not listed) is not the owner: the safe side.
    pub const fn is_owner(self) -> bool {
        matches!(self, Self::Owner)
    }

    const fn code(self) -> u8 {
        match self {
            Self::Owner => 0,
            Self::Guest => 1,
            Self::GuestNoOwner => 2,
            Self::Unknown => 3,
        }
    }

    const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Owner,
            1 => Self::Guest,
            2 => Self::GuestNoOwner,
            _ => Self::Unknown,
        }
    }
}

/// One live session's viewer role as last decided here, for what follows the role beyond game-only:
/// the guard that keeps a guest off AFKLink's own windows (`crate::own_windows`). Set at the
/// session's start and at every re-evaluation; read for every input event — one atomic load.
#[derive(Debug)]
pub struct RoleCell(AtomicU8);

impl RoleCell {
    fn new(role: ViewerRole) -> Self {
        Self(AtomicU8::new(role.code()))
    }

    /// A cell for a session no decision was made for: no role, so not the owner (the safe side).
    pub fn not_owner() -> Self {
        Self::new(ViewerRole::Unknown)
    }

    /// The role now.
    pub fn get(&self) -> ViewerRole {
        ViewerRole::from_code(self.0.load(Ordering::Relaxed))
    }

    fn set(&self, role: ViewerRole) {
        self.0.store(role.code(), Ordering::Relaxed);
    }

    /// A cell holding `role`, for the tests of what reads it.
    #[cfg(test)]
    pub fn fixed(role: ViewerRole) -> Self {
        Self::new(role)
    }

    /// Put `role` in it, for the tests of what reads it.
    #[cfg(test)]
    pub fn put(&self, role: ViewerRole) {
        self.set(role);
    }
}

/// Whether game-only applies to a session, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub applies: bool,
    pub why: &'static str,
}

/// The decision for a viewer of `role` under the two switches:
///
/// | «Только игра» | «Только для гостей» | the viewer, as the server says | game-only applies |
/// |---|---|---|---|
/// | off | either | anyone | no: the whole desktop |
/// | on | off | anyone | yes: everyone, as before the switch existed |
/// | on | on | the PC's owner | no: the owner's whole desktop |
/// | on | on | a guest | yes |
/// | on | on | a guest on a PC with no owner | yes: everyone there is a guest |
/// | on | on | no role (a server older than roles, or an account not listed) | yes: who the owner is cannot be told, so the safe side |
///
/// «Только для гостей» off (the default) is exactly the mode as it always was: roles are not looked
/// at, and a server without them changes nothing.
pub fn decide(game_only: bool, for_guests: bool, role: ViewerRole) -> Decision {
    let (applies, why) = match (game_only, for_guests, role) {
        (false, _, _) => (false, "«Только игра» is off: the whole desktop"),
        (true, false, _) => (
            true,
            "«Только игра» is on for everyone («Только для гостей» off): the game only",
        ),
        (true, true, ViewerRole::Owner) => (
            false,
            "the PC's owner, as the server says, with «Только для гостей» on: the whole desktop",
        ),
        (true, true, ViewerRole::Guest) => (
            true,
            "a guest, as the server says, with «Только для гостей» on: the game only",
        ),
        (true, true, ViewerRole::GuestNoOwner) => (
            true,
            "the PC has no owner, so everyone is a guest, with «Только для гостей» on: the game only",
        ),
        (true, true, ViewerRole::Unknown) => (
            true,
            "no role from the server for this account (a server older than roles) with «Только для \
             гостей» on: who the owner is cannot be told, so the safe side — the game only",
        ),
    };
    Decision { applies, why }
}

/// One live session, as decided last.
struct Entry {
    telegram_user_id: i64,
    role: ViewerRole,
    applies: bool,
    /// The viewer receives (str0m's `Connected`): from then on, and only then, the game helper may
    /// act for this session ([`GameAccess::connected`]).
    connected: bool,
    cell: Arc<CaptureModeCell>,
    /// `role`, for the session's guard on AFKLink's own windows ([`GameAccess::role_cell`]).
    role_cell: Arc<RoleCell>,
}

/// The live sessions as the game helper's signal reads them: one look, under one lock — the counts
/// and the lists always agree with each other.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HelperSessions {
    /// Sessions decided here (their capture made), connected or not.
    pub live: usize,
    /// Of them, connected: the viewer receives.
    pub connected: usize,
    /// Connected, with game-only applied: what the helper may act for, by id (sorted).
    pub game_only: Vec<String>,
    /// Game-only applied, not connected yet: the helper waits for them, by id (sorted). An attempt
    /// that never connects never lets it act.
    pub game_only_connecting: Vec<String>,
}

struct Inner {
    policy: GamePolicy,
    /// The server's list as the orchestrator last told it: who has which role.
    bindings: Vec<BindingInfo>,
    sessions: HashMap<String, Entry>,
}

/// Each live session's game-only decision and the cell that carries it; shared by the orchestrator
/// (sessions, roles) and `AgentControl` (the owner's settings).
///
/// Each live session has a [`CaptureModeCell`] of its own, made here when the session starts
/// ([`Self::open`]). A change of the PC's settings ([`Self::set_policy`]: the desktop app's
/// switches, through `AgentControl`) or of the roles ([`Self::set_roles`]: `agent_ready`,
/// `binding_added`, `binding_removed`, `owner_changed`) decides every live session again at once
/// and puts the result in its cell, the same path a mode switch takes mid-session:
///
/// - the encode loop refuses the old capture's frames from that moment
///   (`SessionCapture::admits_frames`), and the pipeline supervisor replaces the capture within
///   `pipeline::SUPERVISE_EVERY`;
/// - input is scoped by the cell on every event (`crate::game_input::InputScopeSource`);
/// - the clipboard looks at it every second and before anything it sends or writes
///   (`crate::clipboard`);
/// - the heartbeat's `game` (the viewer's «Игра запускается» and the rest), the pipeline line and
///   the journal's «Только игра» follow the session's `GameStatus`, which its capture sets.
pub struct GameAccess {
    inner: Mutex<Inner>,
}

/// The part of a binding list the decision reads: who, and with which role.
fn roles_of(bindings: &[BindingInfo]) -> Vec<(i64, Option<BindingRole>)> {
    let mut roles: Vec<_> = bindings
        .iter()
        .map(|b| (b.telegram_user_id, b.role))
        .collect();
    roles.sort_unstable_by_key(|(id, _)| *id);
    roles
}

impl GameAccess {
    pub fn new(policy: GamePolicy) -> Self {
        tracing::debug!(policy = %policy.describe(), "game access: the PC's game-only settings at start");
        Self {
            inner: Mutex::new(Inner {
                policy,
                bindings: Vec::new(),
                sessions: HashMap::new(),
            }),
        }
    }

    /// The settings in force.
    pub fn policy(&self) -> GamePolicy {
        lock(&self.inner).policy.clone()
    }

    /// Put the owner's settings in force (`why`: what changed them) and decide every live session
    /// again. True when they changed.
    pub fn set_policy(&self, policy: GamePolicy, why: &str) -> bool {
        let mut inner = lock(&self.inner);
        if inner.policy == policy {
            tracing::debug!(
                policy = %policy.describe(),
                why,
                "game access: settings unchanged; nothing to re-evaluate"
            );
            return false;
        }
        tracing::debug!(
            from = %inner.policy.describe(),
            to = %policy.describe(),
            why,
            "game access: the PC's game-only settings changed"
        );
        inner.policy = policy;
        Self::reevaluate(&mut inner, why);
        true
    }

    /// The server's list of bindings as it stands now (`why`: the message it came with), and every
    /// live session decided again when a role in it changed.
    pub fn set_roles(&self, bindings: &[BindingInfo], why: &str) {
        let mut inner = lock(&self.inner);
        Self::take_roles(&mut inner, bindings, why);
    }

    fn take_roles(inner: &mut Inner, bindings: &[BindingInfo], why: &str) -> bool {
        let (before, after) = (roles_of(&inner.bindings), roles_of(bindings));
        inner.bindings = bindings.to_vec();
        if before == after {
            tracing::debug!(
                why,
                bindings = bindings.len(),
                "game access: the roles are as before; nothing to re-evaluate"
            );
            return false;
        }
        let show = |r: &[(i64, Option<BindingRole>)]| {
            r.iter()
                .map(|(id, role)| format!("{id}:{}", role.map_or("-", BindingRole::as_str)))
                .collect::<Vec<_>>()
                .join(",")
        };
        tracing::debug!(
            why,
            from = %show(&before),
            to = %show(&after),
            "game access: the roles changed"
        );
        Self::reevaluate(inner, why);
        true
    }

    /// Session `session_id` of account `telegram_user_id` starts: its decision now, with the
    /// server's list as the orchestrator has it (`bindings` — the same as the last
    /// [`Self::set_roles`]; should it ever not be, the list is taken and the other sessions decided
    /// again with it). The cell its capture, input and clipboard follow.
    pub fn open(
        &self,
        session_id: &str,
        telegram_user_id: i64,
        bindings: &[BindingInfo],
    ) -> Arc<CaptureModeCell> {
        let mut inner = lock(&self.inner);
        if roles_of(&inner.bindings) != roles_of(bindings) {
            tracing::debug!(
                session = session_id,
                "game access: the roles here lagged the list a session started with; caught up"
            );
            Self::take_roles(&mut inner, bindings, "a session's start");
        }
        let role = ViewerRole::of(&inner.bindings, telegram_user_id);
        let decision = decide(inner.policy.game_only, inner.policy.for_guests, role);
        let mode = inner.policy.mode(decision.applies);
        tracing::debug!(
            session = session_id,
            telegram_user_id,
            role = role.as_str(),
            game_only = inner.policy.game_only,
            for_guests = inner.policy.for_guests,
            applies = decision.applies,
            capture = %mode.describe(),
            "game access: decided at the session's start: {}",
            decision.why
        );
        let cell = Arc::new(CaptureModeCell::for_session(session_id, mode));
        let replaced = inner.sessions.insert(
            session_id.to_string(),
            Entry {
                telegram_user_id,
                role,
                applies: decision.applies,
                connected: false,
                cell: cell.clone(),
                role_cell: Arc::new(RoleCell::new(role)),
            },
        );
        if replaced.is_some() {
            tracing::warn!(
                session = session_id,
                "game access: a session started twice under one id; the new decision replaces the old"
            );
        }
        cell
    }

    /// Session `session_id` ended: not decided any more, nor counted for the game helper.
    pub fn close(&self, session_id: &str) {
        let mut inner = lock(&self.inner);
        match inner.sessions.remove(session_id) {
            Some(e) => tracing::debug!(
                session = session_id,
                applied = e.applies,
                live = inner.sessions.len(),
                "game access: the session ended"
            ),
            None => tracing::trace!(
                session = session_id,
                "game access: an end for a session never decided (it failed before its capture)"
            ),
        }
    }

    /// The cell that holds `session_id`'s viewer role as decided here, kept current by every
    /// re-evaluation; `None` for a session not opened here.
    pub fn role_cell(&self, session_id: &str) -> Option<Arc<RoleCell>> {
        lock(&self.inner)
            .sessions
            .get(session_id)
            .map(|e| e.role_cell.clone())
    }

    /// Whether game-only applies to `session_id` now; `None` for a session not running.
    pub fn applies(&self, session_id: &str) -> Option<bool> {
        lock(&self.inner)
            .sessions
            .get(session_id)
            .map(|e| e.applies)
    }

    /// Session `session_id` connected — str0m's `Connected`, the viewer receiving: from now on the
    /// game helper may act for it, if game-only applies to it. Repeats change nothing. True the
    /// first time.
    pub fn connected(&self, session_id: &str) -> bool {
        let mut inner = lock(&self.inner);
        let Some(entry) = inner.sessions.get_mut(session_id) else {
            tracing::debug!(
                session = session_id,
                "game access: connected, but not decided here (it ended, or failed before its \
                 capture): nothing for the game helper"
            );
            return false;
        };
        if std::mem::replace(&mut entry.connected, true) {
            tracing::trace!(session = session_id, "game access: connected again");
            return false;
        }
        let applies = entry.applies;
        let role = entry.role;
        let game_only_connected = inner
            .sessions
            .values()
            .filter(|e| e.applies && e.connected)
            .count();
        tracing::debug!(
            session = session_id,
            role = role.as_str(),
            applies,
            game_only_connected,
            live = inner.sessions.len(),
            "game access: the session connected: {}",
            if applies {
                "game-only applies — the game helper may act for it from now"
            } else {
                "game-only does not apply — the game helper does not act for it"
            }
        );
        true
    }

    /// The connected sessions game-only applies to, by id (sorted): what the game helper may act
    /// for ([`Self::helper_sessions`] has them with the counts beside).
    ///
    /// The desktop app's game helper may act only while a live session has game-only applied: the
    /// owner's whole desktop never launches the game nor brings it back. And only once that session
    /// has **connected** (str0m's `Connected`, the viewer receiving: [`Self::connected`]), not from
    /// its request: counted from the request, two attempts of a guest that never connected let the
    /// helper act for 0.6–1.8 s each, and it launched the game after they were gone.
    pub fn game_only_sessions(&self) -> Vec<String> {
        self.helper_sessions().game_only
    }

    /// The live sessions as the game helper's signal reads them, in one look ([`HelperSessions`]).
    pub fn helper_sessions(&self) -> HelperSessions {
        let inner = lock(&self.inner);
        let mut seen = HelperSessions {
            live: inner.sessions.len(),
            ..HelperSessions::default()
        };
        for (id, e) in &inner.sessions {
            if e.connected {
                seen.connected += 1;
            }
            match (e.applies, e.connected) {
                (true, true) => seen.game_only.push(id.clone()),
                (true, false) => seen.game_only_connecting.push(id.clone()),
                (false, _) => {}
            }
        }
        seen.game_only.sort_unstable();
        seen.game_only_connecting.sort_unstable();
        seen
    }

    /// Decide every live session again (`cause`: what changed) and put each result in its cell.
    fn reevaluate(inner: &mut Inner, cause: &str) {
        let Inner {
            policy,
            bindings,
            sessions,
        } = inner;
        if sessions.is_empty() {
            tracing::debug!(cause, "game access: no live session to re-evaluate");
            return;
        }
        let mut moved = 0usize;
        for (id, e) in sessions.iter_mut() {
            let role = ViewerRole::of(bindings, e.telegram_user_id);
            let decision = decide(policy.game_only, policy.for_guests, role);
            tracing::debug!(
                session = %id,
                telegram_user_id = e.telegram_user_id,
                role = role.as_str(),
                was_role = e.role.as_str(),
                game_only = policy.game_only,
                for_guests = policy.for_guests,
                applies = decision.applies,
                applied = e.applies,
                cause,
                "game access: re-evaluated: {}",
                decision.why
            );
            e.role = role;
            e.role_cell.set(role);
            e.applies = decision.applies;
            if e.cell.set(policy.mode(decision.applies), cause) {
                moved += 1;
            }
        }
        tracing::debug!(
            cause,
            sessions = sessions.len(),
            moved,
            game_only_sessions = sessions.values().filter(|e| e.applies).count(),
            game_only_connected = sessions
                .values()
                .filter(|e| e.applies && e.connected)
                .count(),
            "game access: every live session re-evaluated"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::game::{fakes::binding, GameStatus, SessionCapture};
    use crate::game_input::InputScopeSource;
    use crate::pipeline::fakes::{fake_backends, CaptureWorld, EncoderWorld};
    use crate::traits::InputScope;

    fn b(id: i64, role: Option<BindingRole>) -> BindingInfo {
        BindingInfo {
            telegram_user_id: id,
            username: None,
            first_name: Some(format!("n{id}")),
            role,
        }
    }

    const OWNER: Option<BindingRole> = Some(BindingRole::Owner);
    const GUEST: Option<BindingRole> = Some(BindingRole::Guest);

    fn policy(game_only: bool, for_guests: bool) -> GamePolicy {
        GamePolicy {
            game_only,
            for_guests,
            binding: Some(binding()),
        }
    }

    fn game() -> CaptureMode {
        CaptureMode::GameWindow {
            binding: Some(binding()),
        }
    }

    /// The role comes from the server's list only: the owner, a guest beside an owner, a guest on
    /// a PC with nobody owning it, and no role (a server older than roles, or not listed).
    #[test]
    fn the_role_is_read_from_the_servers_list() {
        let owned = [b(1, OWNER), b(2, GUEST)];
        assert_eq!(ViewerRole::of(&owned, 1), ViewerRole::Owner);
        assert_eq!(ViewerRole::of(&owned, 2), ViewerRole::Guest);
        assert_eq!(ViewerRole::of(&owned, 3), ViewerRole::Unknown, "not listed");
        let ownerless = [b(2, GUEST), b(3, GUEST)];
        assert_eq!(ViewerRole::of(&ownerless, 2), ViewerRole::GuestNoOwner);
        let old_server = [b(1, None), b(2, None)];
        assert_eq!(ViewerRole::of(&old_server, 1), ViewerRole::Unknown);
        assert_eq!(ViewerRole::of(&[], 1), ViewerRole::Unknown);
    }

    /// The decision matrix: «Только для гостей» on and off, for the owner, a guest, a guest on a PC
    /// with no owner and a server without roles — and game-only off, where nothing applies.
    #[test]
    fn the_decision_follows_the_switch_and_the_role() {
        use ViewerRole::{Guest, GuestNoOwner, Owner, Unknown};
        let all = [Owner, Guest, GuestNoOwner, Unknown];
        // «Только для гостей» off: everyone, exactly as before the switch existed.
        for role in all {
            assert!(decide(true, false, role).applies, "{role:?}");
        }
        // On: everyone but the owner; no role is the safe side.
        assert!(!decide(true, true, Owner).applies);
        assert!(decide(true, true, Guest).applies);
        assert!(decide(true, true, GuestNoOwner).applies);
        assert!(decide(true, true, Unknown).applies);
        // Game-only off: nobody, whatever the other switch.
        for role in all {
            for for_guests in [false, true] {
                assert!(!decide(false, for_guests, role).applies, "{role:?}");
            }
        }
        // Each decision says why, in words naming the case.
        assert!(decide(true, true, Owner).why.contains("owner"));
        assert!(decide(true, true, GuestNoOwner).why.contains("no owner"));
        assert!(decide(true, true, Unknown).why.contains("older than roles"));
    }

    /// The same matrix end to end: sessions opened with the server's list get the capture mode
    /// their viewer's role calls for.
    #[test]
    fn a_session_starts_in_the_mode_its_role_calls_for() {
        let owned = [b(1, OWNER), b(2, GUEST)];
        let ownerless = [b(2, GUEST), b(3, GUEST)];
        let old_server = [b(1, None), b(2, None)];
        for (for_guests, list, user, expected) in [
            (false, &owned[..], 1, game()),
            (false, &owned[..], 2, game()),
            (false, &old_server[..], 1, game()),
            (true, &owned[..], 1, CaptureMode::Monitor),
            (true, &owned[..], 2, game()),
            (true, &ownerless[..], 2, game()),
            (true, &old_server[..], 1, game()),
        ] {
            let access = GameAccess::new(policy(true, for_guests));
            access.set_roles(list, "test");
            let cell = access.open("s", user, list);
            assert_eq!(
                cell.current().0,
                expected,
                "for_guests {for_guests}, user {user}, list {list:?}"
            );
            assert_eq!(access.applies("s"), Some(expected.is_game()));
        }
        // Game-only off: the monitor for everyone.
        let access = GameAccess::new(policy(false, true));
        let cell = access.open("s", 2, &owned);
        assert_eq!(cell.current().0, CaptureMode::Monitor);
    }

    /// Mid-session: the switch, the mode itself and the roles each decide every live session again
    /// at once — the owner's session leaves game-only and a guest's stays in it, a guest who
    /// becomes the owner leaves it, and the game helper's list follows.
    #[test]
    fn live_sessions_are_decided_again_on_every_change() {
        let access = GameAccess::new(policy(true, false));
        let list = [b(1, OWNER), b(2, GUEST)];
        access.set_roles(&list, "agent_ready");
        let owner = access.open("s-owner", 1, &list);
        let guest = access.open("s-guest", 2, &list);
        assert_eq!((owner.current().0, guest.current().0), (game(), game()));
        // Not connected yet: nothing for the game helper.
        assert!(access.game_only_sessions().is_empty());
        assert!(access.connected("s-owner") && access.connected("s-guest"));
        assert_eq!(access.game_only_sessions(), ["s-guest", "s-owner"]);

        // «Только для гостей» on: the owner's session gets the desktop back.
        assert!(access.set_policy(policy(true, true), "test: for guests on"));
        assert_eq!(owner.current().0, CaptureMode::Monitor);
        assert_eq!(guest.current().0, game());
        assert_eq!(access.game_only_sessions(), ["s-guest"]);
        // The same settings again move nothing.
        let generation = owner.generation();
        assert!(!access.set_policy(policy(true, true), "test: again"));
        assert_eq!(owner.generation(), generation);

        // The guest becomes the owner (`owner_changed`): the roles swap, and so do the modes.
        access.set_roles(&[b(1, GUEST), b(2, OWNER)], "owner_changed");
        assert_eq!(owner.current().0, game(), "the old owner is a guest now");
        assert_eq!(guest.current().0, CaptureMode::Monitor, "the new owner");
        assert_eq!(access.game_only_sessions(), ["s-owner"]);

        // The owner unbinds himself: nobody owns the PC, everyone is a guest.
        access.set_roles(&[b(1, GUEST)], "owner_changed");
        assert_eq!(guest.current().0, game());

        // Game-only off: both see the desktop; on again, back as the roles say.
        access.set_policy(policy(false, true), "test: off");
        assert_eq!(
            (owner.current().0, guest.current().0),
            (CaptureMode::Monitor, CaptureMode::Monitor)
        );
        assert!(access.game_only_sessions().is_empty());
        access.set_policy(policy(true, true), "test: on");
        assert_eq!((owner.current().0, guest.current().0), (game(), game()));

        // Another game: the game-only sessions follow it.
        let other = GameBinding::new(r"C:\Other\game.exe", "Window");
        access.set_policy(
            GamePolicy {
                binding: Some(other.clone()),
                ..policy(true, true)
            },
            "test: another game",
        );
        assert_eq!(
            owner.current().0,
            CaptureMode::GameWindow {
                binding: Some(other)
            }
        );

        // Ended: forgotten.
        access.close("s-owner");
        assert_eq!(access.applies("s-owner"), None);
        assert_eq!(access.game_only_sessions(), ["s-guest"]);
    }

    /// The session's role cell (the own-windows guard reads it) starts with the role the server
    /// gave and follows every change of the roles, game-only on or off; a session not opened has
    /// none.
    #[test]
    fn the_role_cell_follows_the_servers_roles() {
        let access = GameAccess::new(policy(false, false));
        let list = [b(1, OWNER), b(2, GUEST)];
        access.set_roles(&list, "agent_ready");
        access.open("s-owner", 1, &list);
        access.open("s-guest", 2, &list);
        let owner = access.role_cell("s-owner").expect("opened");
        let guest = access.role_cell("s-guest").expect("opened");
        assert_eq!(
            (owner.get(), guest.get()),
            (ViewerRole::Owner, ViewerRole::Guest)
        );
        assert!(owner.get().is_owner() && !guest.get().is_owner());
        access.set_roles(&[b(1, GUEST), b(2, OWNER)], "owner_changed");
        assert_eq!(
            (owner.get(), guest.get()),
            (ViewerRole::Guest, ViewerRole::Owner)
        );
        access.set_roles(&[b(1, GUEST)], "binding_removed");
        assert_eq!(owner.get(), ViewerRole::GuestNoOwner);
        assert_eq!(
            guest.get(),
            ViewerRole::Unknown,
            "not listed: not the owner"
        );
        assert!(!ViewerRole::Unknown.is_owner() && !ViewerRole::GuestNoOwner.is_owner());
        assert!(access.role_cell("s-none").is_none());
        for role in [
            ViewerRole::Owner,
            ViewerRole::Guest,
            ViewerRole::GuestNoOwner,
            ViewerRole::Unknown,
        ] {
            assert_eq!(RoleCell::fixed(role).get(), role);
        }
    }

    /// The game helper acts only for a session that connected: a
    /// session still connecting — or an attempt that never connects — is only counted as
    /// connecting; the counts and the lists come from one look.
    #[test]
    fn the_game_helper_counts_only_connected_sessions() {
        let access = GameAccess::new(policy(true, true));
        let list = [b(1, OWNER), b(2, GUEST)];
        access.set_roles(&list, "agent_ready");
        access.open("s-guest", 2, &list);
        access.open("s-owner", 1, &list);
        assert_eq!(
            access.helper_sessions(),
            HelperSessions {
                live: 2,
                connected: 0,
                game_only: Vec::new(),
                game_only_connecting: vec!["s-guest".to_string()],
            }
        );
        assert!(access.game_only_sessions().is_empty());
        // The owner's session connects: the whole desktop — still nothing for the helper.
        assert!(access.connected("s-owner"));
        assert!(access.game_only_sessions().is_empty());
        // The guest's connects: the helper may act. A repeat changes nothing.
        assert!(access.connected("s-guest"));
        assert!(!access.connected("s-guest"));
        assert_eq!(
            access.helper_sessions(),
            HelperSessions {
                live: 2,
                connected: 2,
                game_only: vec!["s-guest".to_string()],
                game_only_connecting: Vec::new(),
            }
        );
        // An attempt that never connects, then ends: never one the helper acts for.
        access.open("s-attempt", 2, &list);
        assert_eq!(access.helper_sessions().game_only_connecting, ["s-attempt"]);
        assert_eq!(access.game_only_sessions(), ["s-guest"]);
        access.close("s-attempt");
        assert_eq!(access.helper_sessions().live, 2);
        // Connected for a session not decided here: nothing.
        assert!(!access.connected("s-gone"));
    }

    /// A server without roles: «Только для гостей» off changes nothing, on is the safe side —
    /// game-only for everyone; when the roles arrive, the owner's session gets the desktop.
    #[test]
    fn without_roles_the_switch_is_the_safe_side() {
        let access = GameAccess::new(policy(true, true));
        let old = [b(1, None), b(2, None)];
        let one = access.open("s1", 1, &old);
        let two = access.open("s2", 2, &old);
        assert_eq!((one.current().0, two.current().0), (game(), game()));
        access.set_roles(&[b(1, OWNER), b(2, GUEST)], "agent_ready");
        assert_eq!(
            (one.current().0, two.current().0),
            (CaptureMode::Monitor, game())
        );
    }

    /// A re-evaluation goes the way the mode switch always went mid-session: the session's capture
    /// refuses its frames at once and is replaced at the supervisor's next look, its input is
    /// scoped by the cell on the next event, and its game status follows the capture.
    #[test]
    fn a_re_evaluation_takes_the_mode_switchs_own_path() {
        let backends = fake_backends(
            &Arc::new(Mutex::new(CaptureWorld::default())),
            &Arc::new(Mutex::new(EncoderWorld::default())),
        );
        let access = GameAccess::new(policy(true, true));
        let list = [b(1, OWNER), b(2, GUEST)];
        access.set_roles(&list, "agent_ready");
        let cell = access.open("s", 2, &list);
        let status = Arc::new(GameStatus::new());
        let mut capture = SessionCapture::new(backends, cell.clone(), status.clone());
        let input = InputScopeSource::new(cell.clone(), status.clone());
        assert!(capture.mode().is_game() && status.is_active());
        assert!(matches!(input.scope(), InputScope::Game(_)));
        assert!(capture.admits_frames());

        // The guest is made the owner: the desktop.
        access.set_roles(&[b(1, GUEST), b(2, OWNER)], "owner_changed");
        assert!(
            !capture.admits_frames(),
            "the game capture's frames stop at once"
        );
        assert_eq!(
            input.scope(),
            InputScope::Desktop,
            "input at the next event"
        );
        assert_eq!(
            capture.take_change(),
            Some(game()),
            "the supervisor replaces it"
        );
        assert_eq!(capture.mode(), &CaptureMode::Monitor);
        assert!(capture.admits_frames());
        assert!(!status.is_active(), "the heartbeat's `game` goes");
        assert!(status.heartbeat().is_none());

        // «Только для гостей» off: the game for everyone, the owner too.
        access.set_policy(policy(true, false), "test: for guests off");
        assert!(!capture.admits_frames());
        assert_eq!(capture.take_change(), Some(CaptureMode::Monitor));
        assert!(status.is_active() && status.heartbeat().is_some());
    }
}
