//! The main view's card: what each of its rows says, and the one-off autostart card above it — decided here, so the window only draws, and
//! every change of a decision is in the log with what it was decided from.
//!
//! The rows, top to bottom:
//!
//! - «Управление в играх» — the input driver ([`DriverRow`]), from the last read of it
//!   (`fakerinput_setup::last_read`: the window asks for one whenever its main view shows and after
//!   every operation) and from whether the agent saw controls not reach a game
//!   (`AgentState::input_not_reaching`: three presses in a row dropped within two seconds by a
//!   window running as administrator, without the driver — `afklink_core`'s `input_reach`; kept in
//!   config.json across a restart, cleared by an install or a session whose input got through;
//!   `driver_hint`). No row where the embedded installer does not run (not Windows x64).
//! - «Только игра» — the mode and the bound game ([`GameRow`]), from config.json. «Только для гостей»
//!   puts no mark on it: the `on` row shows the game's name alone.
//! - «Доступ» — the window counts the bindings itself.
//! - «Журнал» — the newest journal entry (`journal_view`), or «Пока пусто».
//!
//! The question «Запускать вместе с Windows?» ([`autostart_card`]) waits from the first pairing on
//! this PC until it is answered, while autostart is off (`Config::autostart_offer`).
//!
//! And what the zone under the hero shows ([`zone`]): one thing at a time — the loader, the refusal,
//! the pairing steps, the autostart question or the card — in a cell of one height, so the hero, its
//! caption and the footer never move between them. A pairing request is never in it: the request
//! window near the tray has it, whether the main window is open or not. The steps follow it,
//! though ([`steps`]): while it waits, steps 1 and 2 are done and step 3 — press «Разрешить» in
//! that window — is the one now, not «enter the code» with the request already up by the tray.

use std::sync::Mutex;

use afklink_core::config::AutostartOffer;
use serde::Serialize;

use crate::access_cache::AccessSource;
use crate::fakerinput_setup::{DriverRead, DriverState};
use crate::journal_view::JournalEntryDto;

/// The «Управление в играх» row.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DriverRow {
    /// Not Windows x64: no row.
    Hidden,
    /// Not read yet this run: «Проверка драйвера…», the button's place empty.
    Checking,
    /// «Драйвер не установлен», a tonal «Установить».
    NotInstalled,
    /// Not installed, and the agent saw controls not reach a game (`AgentState::input_not_reaching`):
    /// «Управление не доходит» in red, a lime «Установить».
    Needed,
    /// Installed, by our installer or another way: «Драйвер установлен» and ✓.
    Installed,
    /// The product without its device: «Драйвер не работает» in red, «Переустановить».
    Broken,
    /// The last read failed: «Не удалось проверить драйвер», nothing to press (Settings has
    /// «Проверить»).
    Unknown,
}

impl DriverRow {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Hidden => "hidden",
            Self::Checking => "checking",
            Self::NotInstalled => "not_installed",
            Self::Needed => "needed",
            Self::Installed => "installed",
            Self::Broken => "broken",
            Self::Unknown => "unknown",
        }
    }
}

/// The driver row from what is known of the driver.
pub(crate) fn driver_row(
    install_supported: bool,
    read: DriverRead,
    input_not_reaching: bool,
) -> DriverRow {
    if !install_supported {
        return DriverRow::Hidden;
    }
    match read {
        DriverRead::NotYet => DriverRow::Checking,
        DriverRead::Failed => DriverRow::Unknown,
        DriverRead::Read(DriverState::NotInstalled) if input_not_reaching => DriverRow::Needed,
        DriverRead::Read(DriverState::NotInstalled) => DriverRow::NotInstalled,
        DriverRead::Read(DriverState::Installed | DriverState::InstalledExternal) => {
            DriverRow::Installed
        }
        DriverRead::Read(DriverState::Broken) => DriverRow::Broken,
    }
}

/// The «Только игра» mode's row, «Показывать только игру».
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GameRow {
    /// Off, no game chosen: «Сейчас видно весь экран», a tonal «Выбрать игру».
    Choose,
    /// Off, a game chosen: «Сейчас видно весь экран», the switch off.
    Off,
    /// On, a game chosen: the game's name, the switch on.
    On,
    /// On, no game: «При подключении будет чёрный экран» in red, «Выбрать игру».
    NoGame,
}

impl GameRow {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Choose => "choose",
            Self::Off => "off",
            Self::On => "on",
            Self::NoGame => "no_game",
        }
    }
}

/// The game-only row from the mode and whether a game is bound.
pub(crate) fn game_row(enabled: bool, has_game: bool) -> GameRow {
    match (enabled, has_game) {
        (false, false) => GameRow::Choose,
        (false, true) => GameRow::Off,
        (true, true) => GameRow::On,
        (true, false) => GameRow::NoGame,
    }
}

/// Whether the autostart question is due: it was offered at the first pairing, not answered yet, and
/// autostart is still off (turned on in Settings meanwhile, it has nothing left to ask).
pub(crate) fn autostart_card(offer: AutostartOffer, autostart: bool) -> bool {
    offer == AutostartOffer::Pending && !autostart
}

/// What the zone under the hero shows. The window stacks every one of them in one grid cell, as
/// tall as the tallest, and shows this one (a 200 ms crossfade between them).
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Zone {
    /// Who has access is not known yet — no answer from the server this run, no cache, not a new
    /// device (`AccessSource::Unknown`): the lime loader.
    Loading,
    /// Not known, and the backend refuses this agent: why, and «Переподключиться» (the window shows
    /// the loader instead for a moment after the press).
    Refused,
    /// Nobody has access — as the server says, as it said last time, or a new device: the three
    /// pairing steps and «Начать привязку» (they stay while a request waits in its own window).
    Steps,
    /// «Запускать вместе с Windows?», after the first pairing, until answered.
    Autostart,
    /// The four rows.
    Card,
}

impl Zone {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Loading => "loading",
            Self::Refused => "refused",
            Self::Steps => "steps",
            Self::Autostart => "autostart",
            Self::Card => "card",
        }
    }
}

/// What the zone is decided from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ZoneInputs {
    /// Where the access list comes from (`access_cache`).
    pub(crate) access: AccessSource,
    /// How many people have access, by that list.
    pub(crate) bindings: usize,
    /// Sessions going on (one can outlive its binding by a poll: still someone, not first run).
    pub(crate) sessions: usize,
    /// The backend refuses this agent (`StatusDto.refusal`).
    pub(crate) refused: bool,
    /// The autostart question is due ([`autostart_card`]).
    pub(crate) autostart_card: bool,
}

/// The zone, first match wins: the loader or the refusal while who has access is not known; the
/// steps while nobody has; the autostart question; the card.
pub(crate) fn zone(z: ZoneInputs) -> Zone {
    if !z.access.known() {
        if z.refused {
            Zone::Refused
        } else {
            Zone::Loading
        }
    } else if z.bindings == 0 && z.sessions == 0 {
        Zone::Steps
    } else if z.autostart_card {
        Zone::Autostart
    } else {
        Zone::Card
    }
}

/// Where the first pairing's steps stand (the zone's `steps` layer).
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Steps {
    /// No request: step 1 is the one now — the lime «Начать привязку» under the card; 2 and 3 after.
    Start,
    /// A pairing request waits in its window near the tray: someone entered the code, so steps 1
    /// and 2 are done, and step 3 is the one now — its row brings the request window forward.
    /// «Начать привязку» stays in place, disabled: a second code could not raise a second request
    /// while this one waits (one per PC, `pairRequests.ts`), and the step it starts is done.
    Request,
}

impl Steps {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Request => "request",
        }
    }
}

/// The steps from whether a pairing request waits (`AgentState::pending_pair`, kept across a break
/// of the link too: it is still the request to answer, its window says «Нет связи»).
pub(crate) fn steps(request_waits: bool) -> Steps {
    if request_waits {
        Steps::Request
    } else {
        Steps::Start
    }
}

/// Why the zone is what it is, for the log.
fn zone_why(zone: Zone, z: ZoneInputs) -> &'static str {
    match zone {
        Zone::Loading => {
            "who has access is not known yet (no server answer, no cache, not a new device)"
        }
        Zone::Refused => "who has access is not known, and the backend refuses this agent",
        Zone::Steps => match z.access {
            AccessSource::NewDevice => "nobody has access: a new device",
            AccessSource::Cache => "nobody has access, as the server said last time",
            _ => "nobody has access, as the server says",
        },
        Zone::Autostart => {
            "the first pairing was made: «Запускать вместе с Windows?» waits for its answer"
        }
        Zone::Card => match z.access {
            AccessSource::Cache => "someone has access, as the server said last time",
            _ => "someone has access",
        },
    }
}

/// What the card is decided from, gathered by `get_status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Inputs {
    pub(crate) install_supported: bool,
    pub(crate) driver: DriverRead,
    pub(crate) input_not_reaching: bool,
    pub(crate) game_only: bool,
    /// «Только для гостей» (`Config::game_only_for_guests`).
    pub(crate) game_only_for_guests: bool,
    /// The bound game's name, as the window shows it.
    pub(crate) game: Option<String>,
    pub(crate) autostart_offer: AutostartOffer,
    pub(crate) autostart: bool,
    /// What the zone is decided from, but the autostart question (from the two above).
    pub(crate) access: AccessSource,
    pub(crate) bindings: usize,
    pub(crate) sessions: usize,
    pub(crate) refused: bool,
    /// A pairing request waits for the owner's answer (`AgentState::pending_pair`), for [`steps`].
    pub(crate) pairing_request: bool,
}

/// The main view's card, as the window draws it.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct HomeDto {
    driver: DriverRow,
    game: GameRow,
    /// The bound game's name (its exe's), for the `on` row; `None` without a game.
    game_name: Option<String>,
    /// «Только для гостей», as config.json has it — not for the row, which carries no mark of it
    /// but for Settings' switch, which opens in its place before the section's
    /// own read answers.
    game_for_guests: bool,
    /// «Запускать вместе с Windows?» is due (the zone shows it when nothing outranks it).
    autostart_card: bool,
    /// What the zone under the hero shows.
    zone: Zone,
    /// Where the first pairing's steps stand: what the `steps` zone shows.
    steps: Steps,
    /// The «Журнал» row: the newest entry — a session going on now first — or `None` for an empty
    /// journal («Пока пусто»).
    journal_last: Option<JournalEntryDto>,
}

/// The decisions as last logged, so each change is said once.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Decided {
    driver: DriverRow,
    game: GameRow,
    autostart_card: bool,
    zone: Zone,
    steps: Steps,
    /// The newest journal entry's id and whether it was going on.
    journal: Option<(String, bool)>,
}

/// Says each change of the card's decisions at `debug`, with its inputs. The window reads the status
/// once a second, so only changes are said.
#[derive(Debug, Default)]
pub(crate) struct HomeLog {
    last: Mutex<Option<Decided>>,
}

impl HomeLog {
    /// The card for `inputs` and the journal's newest entry, each change since the last call logged.
    pub(crate) fn home(&self, inputs: &Inputs, journal_last: Option<JournalEntryDto>) -> HomeDto {
        let autostart_card = autostart_card(inputs.autostart_offer, inputs.autostart);
        let zone_inputs = ZoneInputs {
            access: inputs.access,
            bindings: inputs.bindings,
            sessions: inputs.sessions,
            refused: inputs.refused,
            autostart_card,
        };
        let dto = HomeDto {
            driver: driver_row(
                inputs.install_supported,
                inputs.driver,
                inputs.input_not_reaching,
            ),
            game: game_row(inputs.game_only, inputs.game.is_some()),
            game_name: inputs.game.clone(),
            game_for_guests: inputs.game_only_for_guests,
            autostart_card,
            zone: zone(zone_inputs),
            steps: steps(inputs.pairing_request),
            journal_last,
        };
        let now = Decided {
            driver: dto.driver,
            game: dto.game,
            autostart_card: dto.autostart_card,
            zone: dto.zone,
            steps: dto.steps,
            journal: dto.journal_last.as_ref().map(|e| (e.id.clone(), e.live)),
        };
        let mut last = afklink_core::lock(&self.last);
        let was = last.as_ref();
        if was.map(|w| w.driver) != Some(now.driver) {
            tracing::debug!(
                from = was.map_or("-", |w| w.driver.as_str()),
                to = now.driver.as_str(),
                install_supported = inputs.install_supported,
                read = ?inputs.driver,
                input_not_reaching = inputs.input_not_reaching,
                "main view: the driver row"
            );
        }
        if was.map(|w| w.game) != Some(now.game) {
            tracing::debug!(
                from = was.map_or("-", |w| w.game.as_str()),
                to = now.game.as_str(),
                game_only = inputs.game_only,
                // Said for the record only: the row shows no mark of it.
                for_guests = inputs.game_only_for_guests,
                game = inputs.game.as_deref().unwrap_or("-"),
                "main view: the game-only row"
            );
        }
        if was.map(|w| w.autostart_card) != Some(now.autostart_card) {
            tracing::debug!(
                due = now.autostart_card,
                offer = inputs.autostart_offer.as_str(),
                autostart = inputs.autostart,
                "main view: the autostart question {}",
                if now.autostart_card {
                    "is due (offered at the first pairing, not answered, autostart off)"
                } else {
                    "is not due"
                }
            );
        }
        if was.map(|w| w.zone) != Some(now.zone) {
            tracing::debug!(
                from = was.map_or("-", |w| w.zone.as_str()),
                to = now.zone.as_str(),
                access = inputs.access.as_str(),
                bindings = inputs.bindings,
                sessions = inputs.sessions,
                refused = inputs.refused,
                autostart_due = autostart_card,
                "main view: the zone under the hero: {}",
                zone_why(now.zone, zone_inputs)
            );
        }
        if was.map(|w| w.steps) != Some(now.steps) {
            tracing::debug!(
                from = was.map_or("-", |w| w.steps.as_str()),
                to = now.steps.as_str(),
                pairing_request = inputs.pairing_request,
                zone = now.zone.as_str(),
                "main view: the pairing steps: {}",
                match now.steps {
                    Steps::Start => "no request waits: step 1 now, «Начать привязку» lime",
                    Steps::Request => {
                        "a request waits in its window: steps 1 and 2 done, step 3 now (its row brings \
                         the request window forward), «Начать привязку» disabled in place"
                    }
                }
            );
        }
        if was.map(|w| &w.journal) != Some(&now.journal) {
            tracing::debug!(
                entry = now.journal.as_ref().map_or("-", |(id, _)| id.as_str()),
                kind = dto.journal_last.as_ref().map_or("-", |e| e.kind),
                live = now.journal.as_ref().is_some_and(|(_, live)| *live),
                "main view: the journal row's entry"
            );
        }
        *last = Some(now);
        dto
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The driver row's table, row by row.
    #[test]
    fn the_driver_row_follows_the_design_table() {
        use DriverRead::{Failed, NotYet, Read};
        assert_eq!(
            driver_row(false, Read(DriverState::Installed), false),
            DriverRow::Hidden
        );
        assert_eq!(driver_row(false, NotYet, true), DriverRow::Hidden);
        assert_eq!(driver_row(true, NotYet, false), DriverRow::Checking);
        assert_eq!(driver_row(true, Failed, false), DriverRow::Unknown);
        assert_eq!(
            driver_row(true, Read(DriverState::NotInstalled), false),
            DriverRow::NotInstalled
        );
        assert_eq!(
            driver_row(true, Read(DriverState::NotInstalled), true),
            DriverRow::Needed,
            "controls not getting through without the driver"
        );
        assert_eq!(
            driver_row(true, Read(DriverState::Installed), true),
            DriverRow::Installed,
            "installed: nothing to install"
        );
        assert_eq!(
            driver_row(true, Read(DriverState::InstalledExternal), false),
            DriverRow::Installed,
            "installed some other way counts as installed"
        );
        assert_eq!(
            driver_row(true, Read(DriverState::Broken), false),
            DriverRow::Broken
        );
    }

    /// The game-only row's table.
    #[test]
    fn the_game_row_follows_the_design_table() {
        assert_eq!(game_row(false, false), GameRow::Choose);
        assert_eq!(game_row(false, true), GameRow::Off);
        assert_eq!(game_row(true, true), GameRow::On);
        assert_eq!(game_row(true, false), GameRow::NoGame);
    }

    #[test]
    fn the_autostart_card_waits_only_while_offered_and_autostart_is_off() {
        assert!(autostart_card(AutostartOffer::Pending, false));
        assert!(
            !autostart_card(AutostartOffer::Pending, true),
            "turned on in Settings meanwhile"
        );
        assert!(!autostart_card(AutostartOffer::NotYet, false));
        assert!(!autostart_card(AutostartOffer::Answered, false));
    }

    /// Someone has access, as the server says; nothing else going on.
    fn settled() -> ZoneInputs {
        ZoneInputs {
            access: AccessSource::Server,
            bindings: 1,
            sessions: 0,
            refused: false,
            autostart_card: false,
        }
    }

    /// The zone, phase by phase: the loader only while nothing is known; the steps at once for a new
    /// device and from the cache; the autostart question before the card. (A pairing request is
    /// never in it.)
    #[test]
    fn the_zone_shows_one_thing_at_a_time() {
        let unknown = ZoneInputs {
            access: AccessSource::Unknown,
            bindings: 0,
            ..settled()
        };
        assert_eq!(zone(unknown), Zone::Loading);
        assert_eq!(
            zone(ZoneInputs {
                refused: true,
                ..unknown
            }),
            Zone::Refused
        );
        // A new device: nobody, without waiting for the server — a refusal is the toast's then.
        let new_device = ZoneInputs {
            access: AccessSource::NewDevice,
            bindings: 0,
            ..settled()
        };
        assert_eq!(zone(new_device), Zone::Steps);
        assert_eq!(
            zone(ZoneInputs {
                refused: true,
                ..new_device
            }),
            Zone::Steps
        );
        // The cache: the card at once, or the steps when it said nobody.
        let cached = ZoneInputs {
            access: AccessSource::Cache,
            ..settled()
        };
        assert_eq!(zone(cached), Zone::Card);
        assert_eq!(
            zone(ZoneInputs {
                bindings: 0,
                ..cached
            }),
            Zone::Steps
        );
        // The server says nobody: the steps; a session outliving its binding by a poll is someone.
        let nobody = ZoneInputs {
            bindings: 0,
            ..settled()
        };
        assert_eq!(zone(nobody), Zone::Steps);
        assert_eq!(
            zone(ZoneInputs {
                sessions: 1,
                ..nobody
            }),
            Zone::Card
        );
        // First run, in order: the steps, the autostart question, the card.
        assert_eq!(
            zone(ZoneInputs {
                autostart_card: true,
                ..settled()
            }),
            Zone::Autostart
        );
        assert_eq!(zone(settled()), Zone::Card);
        // Everyone unbound while the question waited: the steps, not the question.
        assert_eq!(
            zone(ZoneInputs {
                bindings: 0,
                autostart_card: true,
                ..settled()
            }),
            Zone::Steps
        );
    }

    #[test]
    fn the_card_carries_the_decisions_and_the_game_name() {
        let log = HomeLog::default();
        let inputs = Inputs {
            install_supported: true,
            driver: DriverRead::Read(DriverState::NotInstalled),
            input_not_reaching: false,
            game_only: true,
            game_only_for_guests: false,
            game: Some("ScrydeGame.bin".to_string()),
            autostart_offer: AutostartOffer::Pending,
            autostart: false,
            access: AccessSource::Cache,
            bindings: 2,
            sessions: 0,
            refused: false,
            pairing_request: false,
        };
        let home = log.home(&inputs, None);
        assert_eq!(home.driver, DriverRow::NotInstalled);
        assert_eq!(home.game, GameRow::On);
        assert_eq!(home.game_name.as_deref(), Some("ScrydeGame.bin"));
        assert!(!home.game_for_guests);
        assert!(home.autostart_card);
        assert_eq!(home.zone, Zone::Autostart);
        assert_eq!(home.journal_last, None);
        // The same inputs again: the same card (and nothing new to log).
        assert_eq!(log.home(&inputs, None), home);
        // Answered: the card.
        let answered = Inputs {
            autostart_offer: AutostartOffer::Answered,
            ..inputs
        };
        assert_eq!(log.home(&answered, None).zone, Zone::Card);
        // «Только для гостей» on: the switch's state goes to the window for Settings' switch; the
        // row is the same `on` row with the game's name alone — no mark.
        let guests = Inputs {
            game_only_for_guests: true,
            ..answered
        };
        let home = log.home(&guests, None);
        assert_eq!(home.game, GameRow::On);
        assert_eq!(home.game_name.as_deref(), Some("ScrydeGame.bin"));
        assert!(home.game_for_guests);
    }

    /// The code entered and the request up by the tray, the main screen's steps must not still say
    /// «Введи код…» is next. They follow the request — on, while
    /// it waits; back to the start when it goes (answered with a decline, withdrawn, expired); and
    /// once it is approved the zone moves on from the steps altogether.
    #[test]
    fn the_steps_follow_a_pairing_request() {
        assert_eq!(steps(false), Steps::Start);
        assert_eq!(steps(true), Steps::Request);

        let log = HomeLog::default();
        let first_run = Inputs {
            install_supported: true,
            driver: DriverRead::Read(DriverState::Installed),
            input_not_reaching: false,
            game_only: false,
            game_only_for_guests: false,
            game: None,
            autostart_offer: AutostartOffer::NotYet,
            autostart: false,
            access: AccessSource::NewDevice,
            bindings: 0,
            sessions: 0,
            refused: false,
            pairing_request: false,
        };
        let home = log.home(&first_run, None);
        assert_eq!((home.zone, home.steps), (Zone::Steps, Steps::Start));
        let waiting = Inputs {
            pairing_request: true,
            ..first_run.clone()
        };
        let home = log.home(&waiting, None);
        assert_eq!((home.zone, home.steps), (Zone::Steps, Steps::Request));
        // Declined, withdrawn or expired: the start again.
        assert_eq!(log.home(&first_run, None).steps, Steps::Start);
        // Approved: a binding, the autostart question offered at the first pairing — the zone moves on.
        let approved = Inputs {
            access: AccessSource::Server,
            bindings: 1,
            autostart_offer: AutostartOffer::Pending,
            ..first_run
        };
        let home = log.home(&approved, None);
        assert_eq!((home.zone, home.steps), (Zone::Autostart, Steps::Start));
    }
}
