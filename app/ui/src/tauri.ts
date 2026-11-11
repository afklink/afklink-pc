/**
 * The typed edge between this window and the Rust side.
 *
 * Every `invoke` in the app goes through a named function here, for two reasons. The command names
 * and argument shapes are a contract with `src-tauri/src/lib.rs` that nothing checks at build time
 * — a renamed parameter fails at runtime with a message about a missing field — so collecting them
 * in one file at least makes the whole contract greppable. And the DTOs mirror the `Serialize`
 * structs on the Rust side, which is the second half of that contract.
 *
 * Note the camelCase argument keys: Tauri converts them to the snake_case parameter names the Rust
 * functions declare. Getting this wrong is the single most common way an invoke silently fails.
 */

interface TauriGlobal {
  core: { invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T> };
  event: {
    /** Resolves once the listener is registered: an event emitted after that is not missed. */
    listen: <T>(event: string, handler: (event: { payload: T }) => void) => Promise<() => void>;
  };
}

declare global {
  interface Window {
    __TAURI__?: TauriGlobal;
  }
}

/** True when running inside the Tauri webview rather than a plain `vite dev`. */
export const inTauri = typeof window !== "undefined" && window.__TAURI__ !== undefined;

function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const bridge = window.__TAURI__;
  if (!bridge) {
    // `vite dev` in a browser has no bridge. Rejecting rather than pretending keeps the failure
    // legible: the main window shows its empty frame rather than made-up state.
    return Promise.reject(new Error(`not running in Tauri: ${cmd}`));
  }
  return bridge.core.invoke<T>(cmd, args);
}

/* ── DTOs (mirror the Serialize structs in src-tauri/src/lib.rs) ───────────── */

/** A binding's role: one owner per PC at most, everyone else a guest. */
export type BindingRole = "owner" | "guest";

export interface BindingDto {
  telegram_user_id: number;
  username: string | null;
  first_name: string | null;
  /**
   * The role the server gives this person on this PC; null from a server older than roles — then
   * no role is shown and no role action offered. Absent from an older agent.
   */
  role?: BindingRole | null;
  /** The PC's request to the owner on this person's row, while in flight or just ended. */
  owner_request?: OwnerRequestDto | null;
}

/**
 * What the PC asked the owner (`afklink_core::owner_request`): `make_owner` — «Сделать владельцем»
 * on a guest; `unbind_owner` — «Отвязать» on the owner; `pc_allow` — this PC's «Разрешить» in a
 * pairing prompt, which the server held for the owner because someone other than him had a session
 * here: on the newcomer's own row (`StatusDto.held_pair`), and its
 * `confirmed` is «Разрешено». All three wait for the owner in Telegram.
 */
export type OwnerRequestKind = "make_owner" | "unbind_owner" | "pc_allow";

/**
 * Where the request on a row is: `asked` — sent, the server has not answered (nobody asked yet; on a
 * PC with no owner nobody will be: the server applies it at once); `pending` — waiting for the owner
 * until `expires_at`; `cancelling` — «Отменить запрос» pressed; `rechecking` — pending before a
 * reconnect, not re-sent yet; `ended` — `outcome` says how, shown for a few seconds.
 */
export type OwnerRequestStage = "asked" | "pending" | "cancelling" | "rechecking" | "ended";

/** How a request ended, as its row says it for a few seconds. */
export type OwnerRequestOutcome =
  | "confirmed"
  | "declined"
  | "expired"
  | "cancelled"
  | "busy"
  | "rate_limited"
  | "failed";

export interface OwnerRequestDto {
  kind: OwnerRequestKind;
  stage: OwnerRequestStage;
  /**
   * A confirmation was actually asked of the owner: the server opened the request (`pending`, and
   * on through `cancelling` and `rechecking`). Only then does the row say «Ждём подтверждения» and
   * offer «Отменить запрос»; before it the row holds its buttons, disabled, and says nothing.
   * Absent from an older agent: taken from `stage`.
   */
  owner_asked?: boolean;
  /** Unix ms the owner has until, once the server opened the request; null before. */
  expires_at: number | null;
  /** With `ended` only. */
  outcome: OwnerRequestOutcome | null;
}

/**
 * The newcomer of a pairing this PC allowed and the server holds for the owner (`pc_allow`): a row
 * of their own at the end of «Доступ» while he decides — «Ждём подтверждения · 9:41», «Отменить
 * запрос» — and while how it ended is shown; none once the list has them. Not a binding: no
 * «Отвязать», no role, not counted.
 */
export interface HeldPairDto {
  telegram_user_id: number;
  /** Without the @, or null. Cleaned by Rust, as every name. */
  username: string | null;
  first_name: string | null;
  /** Kind `pc_allow`, in flight or ended. */
  owner_request: OwnerRequestDto;
}

export interface SessionDto {
  session_id: string;
  telegram_user_id: number;
  username: string | null;
  /** First name, else "@username", else "#id" — resolved by Rust, the same name the toasts use. */
  display_name: string;
  /** False while ICE is still negotiating: requested, not yet watching. */
  connected: boolean;
}

export interface PendingPairDto {
  request_id: string;
  /**
   * The ready-made label, «Имя (@username)» when both exist (the pairing toast's), resolved by
   * Rust. The prompt shows the name and the handle on two lines from the fields below and falls
   * back to this only when an older agent sends neither.
   */
  display_name: string;
  /** The requester's Telegram first name, or null. Absent from an older agent. */
  first_name?: string | null;
  /** The requester's Telegram username without the @, or null. Absent from an older agent. */
  username?: string | null;
  telegram_user_id: number;
  /** Unix ms, after which the backend withdraws the request. */
  expires_at: number;
  /**
   * «Разрешить» leads to «Кто это?» («Владелец» / «Гость»): the PC has no owner. Absent from an
   * older agent: no question.
   */
  asks_role?: boolean;
  /**
   * The step the prompt is at, the same in both places (`pair_prompt::PairStep`): `consent` —
   * «Отклонить» / «Разрешить»; `role` — «Кто это?». Absent from an older agent: `consent`.
   */
  step?: PairStep;
  /**
   * Where the request stands with the link its answer goes over (`afklink_core::pairing::PairLink`):
   * `live` — answerable; `lost` — signaling dropped and the request is kept (the server keeps it
   * too, and sends it again when the PC is back): the buttons wait, disabled, and «Нет связи» stands
   * by the countdown; `rechecking` — the link is back and the server's re-send is a moment away: the
   * buttons still wait. Absent from an older agent: `live`.
   */
  link?: PairLink;
}

/** The pairing prompt's steps: «Отклонить» / «Разрешить», then «Кто это?» on a PC with no owner. */
export type PairStep = "consent" | "role";

/** A pairing request's link (`PendingPairDto.link`). */
export type PairLink = "live" | "lost" | "rechecking";

/**
 * Why the agent is not reconnecting at its usual pace. `replaced`: another agent with this
 * device's identity is running, and nothing is retried until the owner asks. `outdated`: the
 * backend does not serve this build's protocol (`protocol_unsupported`) — only an update helps.
 * `blocked`: an admin blocked this PC (`device_blocked`, the invite-only beta) — no press here can
 * help, so nothing is offered; the agent still tries every 15 minutes, and a lifted block brings the
 * PC back by itself. `fatal`: the backend refused this agent with another fatal code, and it retries
 * every 15 minutes. The code itself is in the log only.
 */
export type Refusal = "replaced" | "outdated" | "blocked" | "fatal";

/**
 * The pairing panel as the agent sees it (`afklink_core::pairing`). `redeemed`: someone entered the
 * code and the confirmation prompt is up; `paired`: a binding was made while the panel was open.
 * Either way the code is spent, and the window closes the panel.
 */
export type PairingPanel = "closed" | "open" | "redeemed" | "paired";

/** Why the window opens the pairing panel, for the agent's log. */
export type PairingOpenReason = "opened" | "retry";

/** Why the window closes the pairing panel, for the agent's log. */
export type PairingCloseReason = "closed" | "redeemed" | "paired" | "expired";

export interface StatusDto {
  connected: boolean;
  /**
   * The server cannot reach this PC, as the tray says it: the link has been down for three seconds
   * without a break (since the launch, or since it dropped — so the handshake at launch and a
   * reconnect never count), or the backend refuses this agent; once said, until the link is back.
   * Decided in Rust by one watch for the tray and this window (`tray_status::LinkWatch`), so the
   * two say it from the same moment, and a window shown mid-outage says it at once. The hero's
   * «Нет связи» and the «Нет связи с сервером» toast.
   */
  offline: boolean;
  /** Set while the backend refuses this agent; null otherwise. */
  refusal: Refusal | null;
  /** After «Приостановить доступ»: new connections are refused until Resume or an app restart. */
  paused: boolean;
  /** Six digits, or null when no pairing panel is open. */
  pairing_code: string | null;
  /** The pairing panel as the agent sees it; see `PairingPanel`. */
  pairing_panel: PairingPanel;
  /** The code's ceiling, Unix ms: the backend refuses it after this. Null without a code. */
  pairing_expires_at: number | null;
  /**
   * The pairing request waiting for the owner's answer. Only the request window near the tray draws
   * it (`PairRequestWindow`); the main window shows none.
   */
  pending_pair: PendingPairDto | null;
  /**
   * Who has access, as the window shows it: the server's list once heard this run; before that the
   * one it sent last time (kept on disk by Rust, `access_cache`), or empty — for a new device, or
   * while nothing is known. `access` says which.
   */
  bindings: BindingDto[];
  /**
   * The server's list has been heard this run: true from the first handshake on (about a second
   * after launch), and it stays true offline (the last list).
   */
  bindings_known: boolean;
  /** Where `bindings` comes from; see `AccessSource`. */
  access: AccessSource;
  /**
   * A request to the owner is in flight on this PC (at most one): «Сделать владельцем» and
   * «Отвязать» on the owner stay in place, disabled.
   */
  owner_request_busy: boolean;
  /**
   * The newcomer's row while the owner decides on a pairing this PC allowed (`pc_allow`); null when
   * there is none. Absent from an older agent.
   */
  held_pair?: HeldPairDto | null;
  sessions: SessionDto[];
  device_name: string;
  server_url: string;
  device_id: string;
  /** Mirrors `Config.autostart`: launch at sign-in, explicit opt-in. */
  autostart: boolean;
  deep_link: string | null;
  /** A data: URI, so the QR needs no file and no remote origin. */
  qr_svg: string | null;
  /**
   * How long someone has been in control — «меньше минуты», «12 мин», «1 ч 05 мин» — finished text
   * from Rust in the language passed to `getStatus`, the same the tray's menu line and tooltip show
   * (`tray_status.rs`). Null while nobody's video is up, and while the PC is paused.
   */
  live_for: string | null;
  /** The main view's card and the one-off autostart card, decided in Rust (`home.rs`). */
  home: HomeDto;
}

/**
 * The main view's «Управление в играх» row (`home::DriverRow`): `hidden` — not Windows x64, no row;
 * `checking` — not read yet; `needed` — not installed, and the agent saw controls not reach a game
 * (red «Управление не доходит», lime «Установить»); `installed` — by our installer or another way;
 * `broken` — the product without its device; `unknown` — the last read failed.
 */
export type DriverRow =
  | "hidden"
  | "checking"
  | "not_installed"
  | "needed"
  | "installed"
  | "broken"
  | "unknown";

/**
 * The main view's «Показывать только игру» row — the «Только игра» mode (`home::GameRow`):
 * `choose` — off, no game («Выбрать игру»); `off` — off, a game chosen (the switch); `on` — on with
 * a game (its name, the switch); `no_game` — on without one (red «При подключении будет чёрный
 * экран», «Выбрать игру»).
 */
export type GameRow = "choose" | "off" | "on" | "no_game";

/**
 * What a journal entry records (`afklink_core::journal::Kind`): `invited` — a guest the owner let in
 * from Telegram by his invite, nobody at the PC asked (`binding_added.via`).
 */
export type JournalKind = "session" | "granted" | "invited" | "revoked" | "paused";

/** The viewer's device, by its Telegram platform (`afklink_core::journal::Device`). */
export type ClientDevice = "iphone" | "android" | "mac" | "desktop" | "browser";

/** How a session ended, when it is worth a label (`afklink_core::journal::Ending`). */
export type JournalEnding = "pc" | "owner" | "revoked" | "lost" | "failed" | "app_closed";

/** One entry of the connection journal (`journal_view::JournalEntryDto`). */
export interface JournalEntryDto {
  /** The session's id, or the event's own. */
  id: string;
  kind: JournalKind;
  telegram_user_id: number;
  /** First name, else "@username", else "#id", as of the entry. */
  name: string;
  /** Unix ms: when the session's video came up, or when the event happened. */
  at_ms: number;
  /** A session going on now. */
  live: boolean;
  /** Sessions: «1 ч 05 мин», until now while it runs, in the language passed. */
  duration: string | null;
  /** Sessions: null when the platform is unknown or never came. */
  device: ClientDevice | null;
  /** Sessions: null for an ordinary end, an unknown reason and a session going on. */
  ending: JournalEnding | null;
  game_only: boolean;
  weak: boolean;
  /** Sessions: its log is still kept, so «Отправить логи» can carry it first. */
  logs: boolean;
}

/**
 * Where the window's access list comes from (`access_cache::AccessSource`): `server` — heard this
 * run; `cache` — the list the server sent last time, until it answers; `new_device` — config.json
 * was written at this launch, so nobody can have access yet; `unknown` — nothing known (a build
 * before the cache, or no list ever heard): the zone's loader.
 */
export type AccessSource = "server" | "cache" | "new_device" | "unknown";

/**
 * What the zone under the main view's hero shows (`home::Zone`), one at a time: `loading` — who has
 * access is not known yet; `refused` — not known, and the backend refuses this agent; `steps` —
 * nobody has access (the pairing steps); `autostart` — «Запускать вместе с Windows?»; `card` — the
 * four rows. (A pairing request is never in it: the request window near the tray has it.)
 */
export type Zone = "loading" | "refused" | "steps" | "autostart" | "card";

/** The main view's card (`home::HomeDto`). */
export interface HomeDto {
  driver: DriverRow;
  game: GameRow;
  /** The bound game's name (whether the mode is on or off); null without a game. */
  game_name: string | null;
  /**
   * «Только для гостей», as config.json has it: the mode applies to guests' sessions only. Not shown
   * on the main view (no mark there); Settings' switch opens in its place with it.
   */
  game_for_guests: boolean;
  /** «Запускать вместе с Windows?» is due: offered at the first pairing, not answered. */
  autostart_card: boolean;
  /** What the zone under the hero shows, decided in Rust. */
  zone: Zone;
  /** Where the first pairing's steps stand (the `steps` zone), decided in Rust; see `HomeSteps`. */
  steps: HomeSteps;
  /** The «Журнал» row's entry — a session going on first — or null: «Пока пусто». */
  journal_last: JournalEntryDto | null;
}

/**
 * The first pairing's steps (`home::Steps`): `start` — no request: step 1 now, «Начать привязку»
 * lime; `request` — a pairing request waits in its window near the tray: steps 1 and 2 done, step 3
 * now (its row brings the request window forward), «Начать привязку» disabled in place.
 */
export type HomeSteps = "start" | "request";

/** The «Журнал» screen (`journal_view::JournalDto`). */
export interface JournalDto {
  /** Newest first: the sessions going on now, then the rest by when they happened. */
  entries: JournalEntryDto[];
}

/**
 * The three levels Settings offers: `debug` «Подробные», `info` «Обычные», `off`
 * «Выключены» — `LogLevel::OFFERED` in `afklink_core::logging`.
 */
export const LOG_OPTIONS = ["off", "info", "debug"] as const;
export type LogOption = (typeof LOG_OPTIONS)[number];

export function isLogOption(value: string): value is LogOption {
  return (LOG_OPTIONS as readonly string[]).includes(value);
}

/** A level in effect: one of the three, or `trace`, which a hand edit of config.json can set. */
export type LogLevel = LogOption | "trace";

export interface LoggingDto {
  /** The level in effect for the agent's own crates (`RUST_LOG` aside). */
  level: LogLevel;
  /**
   * What config.json holds; null while nothing is chosen (a fresh install) and the build's default
   * applies — `debug` for a development build; for a release `debug` during the beta test and `info`
   * after it (`RELEASE_PHASE` in `afklink_core::logging`).
   */
  choice: LogLevel | null;
  /** The option selected: `level` as Settings shows it — `trace` as `debug`, «Подробные». */
  option: LogOption;
  /** The build's default. */
  default_level: LogOption;
  /** Anything is written now (the files, the recent lines in memory): false while the log is off. */
  writing: boolean;
  /** `RUST_LOG`, when it overrides the setting: the choice is saved but waits for a restart. */
  env_override: string | null;
  /** `%APPDATA%\AFKLink\logs`. */
  dir: string | null;
}

/* ── Commands ──────────────────────────────────────────────────────────────── */

/**
 * `lang` is the language this window renders in: the one piece of finished text in the answer,
 * `live_for`, comes back in it (the window switches language at once, the tray on restart).
 */
export const getStatus = (lang: string) => invoke<StatusDto>("get_status", { lang });

/** Which language the window should render in, and whether that was chosen or inferred. */
export const getLocale = () => invoke<{ locale: string; preference: string }>("get_locale");
export const setLang = (lang: string) => invoke<void>("set_lang", { lang });

/**
 * Open the pairing panel: mints a code, replacing any previous one for this device. While signaling
 * is down the agent asks for it on the next connection.
 */
export const requestPairing = (reason: PairingOpenReason) =>
  invoke<void>("request_pairing", { reason });

/**
 * Close the pairing panel, invalidating the code now.
 *
 * Not merely cosmetic: a live code left on screen is also in the video stream of anyone already
 * connected, which is enough for a viewer to mint itself a second, independent binding.
 */
export const cancelPairing = (reason: PairingCloseReason) =>
  invoke<void>("cancel_pairing", { reason });

/**
 * The owner's answer to a pending request. This is what turns a code into access; the request
 * window closes at once. `role`: the answer to «Кто это?» when the prompt asked it; without it an
 * approval makes the person a guest.
 */
export const respondPair = (requestId: string, accept: boolean, role?: BindingRole) =>
  invoke<void>("respond_pair", { requestId, accept, role: role ?? null });

/**
 * «Разрешить» on a prompt that asks «Кто это?»: the prompt becomes the question; nothing is sent
 * until a role is chosen (`respondPair`). Resolves to false when the request is no longer pending
 * (or does not ask), with why in Rust's log.
 */
export const allowPair = (requestId: string) => invoke<boolean>("allow_pair", { requestId });

/**
 * The main view's step 3 pressed while a request waits: the request window to the front — shown
 * again if it was closed by hand, activated if it is up (`pair_prompt::show_pair_request`). Resolves
 * to false when no request is up.
 */
export const showPairRequest = () => invoke<boolean>("show_pair_request");

/**
 * The request window's page has drawn `requestId` at `step` and is `height` CSS px tall, drawn at
 * `ratio` device pixels per CSS pixel (`devicePixelRatio`: the display scale times Windows' text
 * size): Rust sizes the window to it, places it near the tray and shows it
 * (`pair_prompt::fit_pair_window`). A height for one step never sizes the window for the other.
 */
export const fitPairWindow = (requestId: string, height: number, step: PairStep, ratio: number) =>
  invoke<void>("fit_pair_window", { requestId, height, step, ratio });

/** `pair_prompt::EVENT`: the pending request was raised, or went. */
const PAIR_PROMPT_EVENT = "pair-prompt";

/**
 * Called whenever a pending pairing request is raised or goes — the moment to re-read the status
 * rather than wait for the next poll. Resolves to the unsubscribe function.
 */
export function onPairPrompt(handler: () => void): Promise<() => void> {
  const bridge = window.__TAURI__;
  if (!bridge) return Promise.reject(new Error(`not running in Tauri: ${PAIR_PROMPT_EVENT}`));
  return bridge.event.listen(PAIR_PROMPT_EVENT, () => handler());
}

/**
 * «Отвязать»: a guest's access goes at once; the owner's waits for the owner's confirmation in
 * Telegram (Rust decides by the roles it has), and the row shows the request.
 */
export const unbind = (telegramUserId: number) => invoke<void>("unbind", { telegramUserId });

/** «Сделать владельцем» on a guest: a request the owner confirms in Telegram. */
export const makeOwner = (telegramUserId: number) => invoke<void>("make_owner", { telegramUserId });

/** «Отменить запрос»: withdraw the PC's pending request to the owner. */
export const cancelOwnerRequest = () => invoke<void>("cancel_owner_request");

/** End every session and refuse new ones until `resumeSessions`. The PC is not locked. */
export const killSwitch = () => invoke<void>("kill_switch");

/** Accept connections again after the kill switch. */
export const resumeSessions = () => invoke<void>("resume_sessions");

export const setName = (name: string) => invoke<void>("set_name", { name });

/** Connect now, while the backend refuses this agent: after `replaced`, the only way back. */
export const retryConnection = () => invoke<void>("retry_connection");

/** Launch at sign-in. Explicit opt-in, OFF by default; applies immediately. */
export const setAutostart = (enabled: boolean) => invoke<void>("set_autostart", { enabled });

/**
 * The main view's one-off card «Запускать вместе с Windows?»: «Включить» (`true`) turns autostart on
 * as Settings' switch does; «Не надо» (`false`) leaves it off. Either answer is the last.
 */
export const answerAutostartOffer = (enable: boolean) =>
  invoke<void>("answer_autostart_offer", { enable });

/** The connection journal's entries (the «Журнал» screen), durations in `lang`. */
export const getJournal = (lang: string) => invoke<JournalDto>("get_journal", { lang });

/** Where in the window a change was made, for Rust's log: the main view's row or Settings. */
export type ChangeOrigin = "home" | "settings";

export const getLogging = () => invoke<LoggingDto>("get_logging");

/** Applies at once (no restart) and is saved to config.json; answers with the new state. */
export const setLogLevel = (level: LogOption) => invoke<LoggingDto>("set_log_level", { level });

/**
 * The main window's page is drawn at `ratio` (`devicePixelRatio`: the display scale times Windows'
 * text size): Rust sizes the window's least size for a text size changed since launch
 * (`window_fit::main_window_ratio`).
 */
export const reportMainWindowRatio = (ratio: number) =>
  invoke<void>("main_window_ratio", { ratio });

/** Show `%APPDATA%\AFKLink\logs` in Explorer. */
export const openLogsDir = () => invoke<void>("open_logs_dir");

/**
 * How «Отправить логи» ended (`diagnostics::SendLogsDto`): `sent` — the server took the report;
 * `too_often` — over the server's budget (six an hour per PC); `failed` — not sent, why in the app's
 * log.
 */
export type SendLogsOutcome = "sent" | "too_often" | "failed";

export interface SendLogsDto {
  outcome: SendLogsOutcome;
  /** The server's id for the report, when sent (the status line's tooltip). */
  report_id: string | null;
  /** With `too_often`: when the server says to try again, seconds; null when it did not say. */
  retry_after_s: number | null;
  /** With `failed`: the kind (`network`, `refused`, …), for the console only. */
  failure: string | null;
}

/**
 * Pack the logs and send them to the developer, signed by this PC (`diagnostics::send_logs`).
 * Resolves when it is over, whatever the outcome; rejects only when nothing was started (a report is
 * already on its way). The comment is optional; Rust cleans it to the contract's rule and never logs
 * it. `sessionId`: the report is about that session (a journal entry's «Отправить логи»), whose log
 * goes in first.
 */
export const sendLogs = (comment: string, sessionId?: string | null) =>
  invoke<SendLogsDto>("send_logs", { comment, sessionId: sessionId ?? null });

/**
 * The FakerInput driver, from two facts (`fakerinput_setup::DriverState`): is the device present,
 * and does Windows Installer hold a FakerInput product. `installed_external`: the device without a
 * product (installed some other way) — nothing to remove it with. `broken`: the product without the
 * device (removed or disabled in Device Manager) — only a reinstall brings it back.
 */
export type FakerInputState = "not_installed" | "installed" | "installed_external" | "broken";

/**
 * The language Windows draws its own windows in — the UAC prompt, «Безопасность Windows» — which
 * the driver dialog quotes button by button (`fakerinput_setup::WindowsLanguage`). It is Windows'
 * display language (`GetUserDefaultUILanguage`), not the app's: the app's is the owner's choice
 * (or the regional format), and the two differ on, say, an English Windows set to Russian formats.
 * `other`: a language whose button names the app has not checked.
 */
export type WindowsLanguage = "ru" | "en" | "other";

export interface FakerInputStatus {
  state: FakerInputState;
  /** The embedded installer is x64: install and reinstall are offered only there. */
  install_supported: boolean;
  windows_language: WindowsLanguage;
}

/**
 * The section's three operations, each run by Windows Installer in its passive mode (a progress bar
 * and Windows' UAC prompt; the dialog here is the explanation and the confirmation).
 */
export type FakerInputAction = "install" | "remove" | "reinstall";

/**
 * How an operation ended (`fakerinput_setup::MaintenanceOutcome`): `cancelled` — the UAC prompt was
 * declined (or policy refused the elevation); `device_missing` — Windows Installer finished the
 * install, but the device did not appear in time (the last step stopped, not done); `failed` — it
 * started and failed, the reason in the app log.
 */
export type FakerInputOutcome =
  | "done"
  | "restart_required"
  | "cancelled"
  | "installer_busy"
  | "device_missing"
  | "failed";

/**
 * One of the dialog's three steps (`fakerinput_setup::progress::StepState`): `stopped` — the
 * operation ended there without finishing it, only in the final picture.
 */
export type FakerInputStep = "pending" | "active" | "done" | "stopped";

export type FakerInputSteps = [FakerInputStep, FakerInputStep, FakerInputStep];

/** A phase change while an operation runs (`progress::ProgressDto`), from Rust's real events. */
export interface FakerInputProgress {
  operation: FakerInputAction;
  steps: FakerInputSteps;
}

/**
 * The answer once an operation has run (`progress::MaintenanceReport`): the outcome and the final
 * steps, which do not depend on the last progress event having arrived first.
 */
export interface FakerInputReport {
  outcome: FakerInputOutcome;
  steps: FakerInputSteps;
}

/** `progress::PROGRESS_EVENT`. */
const FAKERINPUT_PROGRESS_EVENT = "fakerinput-progress";

const FAKERINPUT_COMMANDS = {
  install: "install_fakerinput",
  remove: "uninstall_fakerinput",
  reinstall: "reinstall_fakerinput",
} satisfies Record<FakerInputAction, string>;

/**
 * Read the driver's status. `recheck` (only «Проверить») also reopens the device for live sessions;
 * the mount and the re-read after an operation must leave it `false`, or they would undo the close
 * a removal made.
 */
export const getFakerInputStatus = (recheck = false) =>
  invoke<FakerInputStatus>("get_fakerinput_status", { recheck });

/**
 * Run an operation after the owner confirmed it in its dialog. Resolves when it is over, with the
 * outcome and the final steps; rejects only when it was refused before any step started.
 */
export const runFakerInputAction = (action: FakerInputAction) =>
  invoke<FakerInputReport>(FAKERINPUT_COMMANDS[action], { consent: true });

/**
 * Follow the running operation's steps. Await it before `runFakerInputAction`, so no change is
 * missed; call the returned function when the operation is over.
 */
export function onFakerInputProgress(
  handler: (progress: FakerInputProgress) => void,
): Promise<() => void> {
  const bridge = window.__TAURI__;
  if (!bridge)
    return Promise.reject(new Error(`not running in Tauri: ${FAKERINPUT_PROGRESS_EVENT}`));
  return bridge.event.listen<FakerInputProgress>(FAKERINPUT_PROGRESS_EVENT, (e) =>
    handler(e.payload),
  );
}

/* ── «Only the game window» (`game_only.rs`) ──────────────────────────────── */

/** The bound game (`game_only::GameDto`). */
export interface GameDto {
  exe_path: string;
  /** The exe's file name: what the section shows for the game. */
  exe_name: string;
  window_class: string;
}

/**
 * Why the installed game helper is not the one needed now (`game_helper::Mismatch`): not installed,
 * installed for another game window, with another launch exe, or the helper asks for the setup
 * again (Windows wanted administrator for the game). Each keeps the helper from acting. Another
 * build's helper is not one: see `GameHelperDto.outdated`.
 */
export type GameHelperMismatch = "not_installed" | "game" | "launch" | "needs_setup";

/** The helper's own state, from its `state.json` (`afklink_game_helper::HelperState`). */
export type GameHelperState =
  | "idle"
  | "waiting"
  | "launching"
  | "running"
  | "gave_up"
  | "needs_setup";

/**
 * «Запускать игру автоматически» (`game_helper::HelperDto`). `enabled`: the owner's switch.
 * `launch_exe`: what the helper launches for the game — the owner's choice, else the launcher
 * learned from the game's parent process, else the `.exe` beside the game's; null: none found, the
 * owner picks one. `mismatch` null: the installation is the one needed. `outdated`: the installed
 * helper is another build's (the app updated itself) — it works on, and `updateGameHelper` installs
 * this build's with the launch exe it has. `found_launch`: the learned launcher's full path, while
 * the helper works on with another launch exe installed — `applyFoundLaunch` installs it (with
 * another build's helper the window offers it only after the update). `state` null: no fresh state
 * from the helper. `failed_launch`: the helper gave up launching the game and it has not run since
 * («Игра не запускается») — kept across sessions and the helper's restarts until the game runs a
 * minute with its window; a setup clears it.
 */
export interface GameHelperDto {
  enabled: boolean;
  launch_exe: string | null;
  launch_name: string | null;
  installed: boolean;
  mismatch: GameHelperMismatch | null;
  outdated: boolean;
  found_launch: string | null;
  state: GameHelperState | null;
  failed_launch: boolean;
}

/**
 * The section's state (`game_only::GameOnlyDto`). `enabled`: every session it applies to shows the
 * game's window only — black while it cannot be shown — never the desktop. `for_guests`: «Только для
 * гостей» — it applies to guests' sessions only, the owner's get the whole desktop (who is the owner
 * is the server's word). `game` null with the mode on: black frames only.
 */
export interface GameOnlyDto {
  enabled: boolean;
  for_guests: boolean;
  game: GameDto | null;
  helper: GameHelperDto;
}

/** A window the picker offers (`game_only::GameWindowDto`); the title is shown, not bound on. */
export interface GameWindowDto {
  exe_path: string;
  exe_name: string;
  window_class: string;
  title: string;
  /**
   * Its program runs as administrator, this agent does not, and the driver is missing: controls
   * will not reach it. The picker says «Нужен драйвер» beside it (`app.gamePickerNeedsDriver`).
   */
  needs_driver: boolean;
}

export const getGameOnly = () => invoke<GameOnlyDto>("get_game_only");

/**
 * The game helper's switch: on runs its setup through Windows' confirmation when the installation
 * does not match (none when it does); off stops it at once, then asks Windows to remove it. Rejects
 * with `not_found` or `failed`; the owner declining Windows' prompt resolves, with nothing changed.
 */
export const setGameHelper = (enabled: boolean) =>
  invoke<GameOnlyDto>("set_game_helper", { enabled });

/**
 * «Обновить» by «Нужно обновление» (`outdated`): this build's game helper in place of another
 * build's, through Windows' confirmation, with the launch exe it is installed with — a learned
 * launcher (`found_launch`) is not applied with it, the window offers it after. With nothing
 * installed that matches it is «Разрешить»: the helper as the settings want it. Rejects as
 * `setGameHelper`; the owner declining resolves, and the installed helper works on as it was.
 */
export const updateGameHelper = () => invoke<GameOnlyDto>("update_game_helper");

/**
 * «Заменить» by «Найден другой файл запуска» (`found_launch`): the game helper with the launcher
 * learned from the game's parent in place of the installed launch exe, through Windows'
 * confirmation — this build's helper with it, as with any setup. Rejects and resolves as
 * `updateGameHelper`.
 */
export const applyFoundLaunch = () => invoke<GameOnlyDto>("apply_found_launch");

/**
 * Windows' Open dialog (an `.exe`, in the game's folder) for the helper's launch exe, then its setup
 * — which also turns the helper on when it is off. Rejects as `setGameHelper`.
 */
export const chooseGameLaunch = () => invoke<GameOnlyDto>("choose_game_launch");

/** Applies at once — live sessions too — and is saved; answers with the state in force. */
export const setGameOnly = (enabled: boolean, from: ChangeOrigin = "settings") =>
  invoke<GameOnlyDto>("set_game_only", { enabled, from });

/**
 * «Только для гостей» (Settings only): applies at once — every live session is decided again by
 * its viewer's role — and is saved; answers with the state in force.
 */
export const setGameOnlyForGuests = (enabled: boolean) =>
  invoke<GameOnlyDto>("set_game_only_for_guests", { enabled });

/** The visible windows of other apps, sorted by app. */
export const listGameWindows = () => invoke<GameWindowDto[]>("list_game_windows");

/**
 * Bind the chosen window's game: its exe path and its window class. `enable`: turn the mode on as
 * well — the main view's «Выбрать игру», whose choice puts «Только игра» in force at once.
 */
export const setGameWindow = (
  exePath: string,
  windowClass: string,
  options: { enable?: boolean; from?: ChangeOrigin } = {},
) =>
  invoke<GameOnlyDto>("set_game_window", {
    exePath,
    windowClass,
    enable: options.enable ?? false,
    from: options.from ?? "settings",
  });

/**
 * Which build this is (`afklink_core::build_info`), for Settings → «Обновления»: the version row
 * shows `label`, its tooltip the commit and the build time.
 */
export interface BuildInfoDto {
  /** The workspace version (`agent/Cargo.toml`). */
  version: string;
  /**
   * «0.1.0» for a release; «0.1.0 · 3a3bc46 · dev», «0.1.0 · 3a3bc46-dirty · dev» (built with
   * uncommitted changes), or «0.1.0 · dev» for a build without a stamp (`bun run portable` stamps
   * one). Formatted by Rust, as in the log.
   */
  label: string;
  channel: "release" | "dev";
  /** The full commit hash; null for a development build. */
  commit: string | null;
  dirty: boolean | null;
  /** `YYYY-MM-DDTHH:MM:SSZ`; null for a development build. */
  built_at: string | null;
}

export const getBuildInfo = () => invoke<BuildInfoDto>("get_build_info");

/**
 * Settings → «Обновления», as the updater's loop sees it (`updater::UpdateStatusDto`). `idle`:
 * nothing checked yet in this run. `available`: a newer version waits for «Установить» (automatic
 * updates off). `after_session`: it is downloaded and waits for the session to end; `later`: for the
 * server, a pairing prompt or a driver operation — with nobody connected and nothing in the way it is
 * `installing` at once. `rolled_back`: it failed before (the previous version was put back) and is
 * not retried yet. Why, in each case, is in the app log.
 */
export type UpdateState =
  | "idle"
  | "checking"
  | "up_to_date"
  | "available"
  | "downloading"
  | "after_session"
  | "later"
  | "installing"
  | "check_failed"
  | "download_failed"
  | "rolled_back";

/**
 * The one button under the status line, by what it does: `check` «Проверить» and `retry_check`
 * «Повторить» → `checkForUpdates`; `install` «Установить» and `retry_update` «Повторить» →
 * `applyUpdate`.
 */
export type UpdateAction = "check" | "retry_check" | "install" | "retry_update";

export interface UpdateStatusDto {
  /** This build's version. */
  version: string;
  /** Updates are off in this build: `dev` (a development build) or `off` (no key, not x64). */
  unavailable: "dev" | "off" | null;
  /** «Обновлять автоматически» (`config.auto_update`). */
  auto: boolean;
  state: UpdateState;
  /** The version the state is about, when it is about one («Доступна версия 0.1.2»). */
  latest: string | null;
  /**
   * The button to show, or null for none: nothing to do during a download, an install or a wait,
   * in a build without updates — and no «Установить» while someone is connected.
   */
  action: UpdateAction | null;
  /** A check, download or install is running: the button waits. */
  busy: boolean;
  /** `downloading` only: the whole percent received; null while the size is unknown. */
  progress: number | null;
  /** When this version's last check got an answer, Unix ms («проверено в 16:50»). */
  checked_at_ms: number | null;
  /** This run started right after an update to `version` («Обновлено до 0.1.1»). */
  updated: boolean;
  /** Grows with every change: a status with a smaller one than the shown one is older, dropped. */
  seq: number;
}

/** Polled while Settings is open; `onUpdateStatus` besides. */
export const getUpdateStatus = () => invoke<UpdateStatusDto>("get_update_status");

/** `updater::STATUS_EVENT`. */
const UPDATE_STATUS_EVENT = "update-status";

/**
 * Every change of the updater's status as it happens — a download's percent too, which a poll
 * would mostly miss (a release downloads in about a second). Resolves to the unsubscribe function.
 */
export function onUpdateStatus(handler: (status: UpdateStatusDto) => void): Promise<() => void> {
  const bridge = window.__TAURI__;
  if (!bridge) return Promise.reject(new Error(`not running in Tauri: ${UPDATE_STATUS_EVENT}`));
  return bridge.event.listen<UpdateStatusDto>(UPDATE_STATUS_EVENT, (e) => handler(e.payload));
}

/**
 * «Проверить», and «Повторить» after a failed check: the answer shows in the next status. With an
 * update already downloaded, Rust does not check again: it looks whether it may install it now.
 */
export const checkForUpdates = () => invoke<void>("check_for_updates");

/** «Установить», and «Повторить» after a failed download or update. */
export const applyUpdate = () => invoke<void>("apply_update");

/** «Обновлять автоматически»: applies at once and is saved to config.json. */
export const setAutoUpdate = (enabled: boolean) => invoke<void>("set_auto_update", { enabled });
