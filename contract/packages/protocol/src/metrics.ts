/**
 * Contract v2 of the telemetry (docs/metrics.md §4.2, §5, §6 in the umbrella): the vocabularies and
 * the bounds the agent, the viewer and the server share. The wire shapes that carry them are in
 * `metrics-wire.ts`; the session reports in `telemetry.ts`; the messages in `agent-ws.ts` and
 * `viewer-ws.ts`.
 *
 * Deliberately import-free, like `relay.ts` and `viewport.ts`: the Mini App needs these as values —
 * it names its engine, its input modes, an attempt's stages and an error's kind — and consumes the
 * schemas as types only, so a zod import here would drag the validator into a bundle people load
 * over mobile data. `metrics-wire.ts` imports from here, never the other way round. Keep this file
 * free of imports.
 *
 * ## Nothing personal
 *
 * What an app sends by itself is counters, codes, versions and verdicts: never an address, a typed
 * text, the screen's content, a window's title or a log. Every string below is an enum or a short id
 * held to a pattern; the one bounded free text is a client error's message (`CLIENT_ERROR_LIMITS`),
 * which is the error's own words, never a person's.
 *
 * ## Additive only
 *
 * Every field this file's vocabularies travel in is optional on the wire: a client older than contract
 * v2 sends none of them, and a server older than it drops them on parsing (a plain object strips
 * unknown keys) or answers a message type it does not know with `error bad_message`, the socket kept.
 * Nobody bumps the protocol for them.
 */

/* --- builds -------------------------------------------------------------------------------- */

/**
 * The agent's version as `CARGO_PKG_VERSION` has it: `0.5.0`, or with a pre-release tag
 * `0.6.0-beta.1` — the same rule as the start failure beacon's `version` (`start-failure.ts`).
 */
export const AGENT_VERSION_PATTERN = /^\d{1,5}\.\d{1,5}\.\d{1,5}(-[0-9A-Za-z.-]{1,24})?$/;

/** A commit a build was stamped with: 7 to 40 lowercase hex digits. */
export const BUILD_COMMIT_PATTERN = /^[0-9a-f]{7,40}$/;

/**
 * The Mini App's build (`BUILD_ID` in `miniapp/src/lib/logRing.ts`): the content hash in the entry
 * chunk's name, or `dev` for a dev server. Letters, digits, `_` and `-`, 1 to 40 of them.
 */
export const VIEWER_BUILD_PATTERN = /^[A-Za-z0-9_-]{1,40}$/;

/**
 * How the agent's previous process ended, as the next one finds it on disk (`agent_hello.last_exit`,
 * `agent_started.last_exit`):
 *
 *   app_exit     the owner closed the app (the tray's «Выход»), or the CLI was stopped
 *   update_exit  it restarted itself to install an update
 *   panic        a Rust panic: the hook wrote its summary before the process went
 *   crash        it died without a word (killed, a native fault, or the PC went down with it —
 *                `agent_started.pc_restarted` tells which when it can): no clean exit was recorded;
 *                also a record torn — empty, zeros, cut short — dated by the file's time (the PC
 *                lost power while it was being written)
 *   os_shutdown  Windows shut down, restarted or logged the user off
 *   unknown      the record is missing, could not be read, or is whole but not one this build
 *                reads (another build's) — a first run, or a build that keeps none
 */
export const AGENT_EXIT_KINDS = [
  "app_exit",
  "update_exit",
  "panic",
  "crash",
  "os_shutdown",
  "unknown",
] as const;
export type AgentExitKind = (typeof AGENT_EXIT_KINDS)[number];

/** The exits that mean the previous process died: what upgrades `agent_disconnected` to `crash`. */
export const AGENT_CRASH_EXITS: readonly AgentExitKind[] = ["panic", "crash"];

/**
 * What a start found of the record the previous process kept (`agent_started.previous_record`):
 *
 *   found       a record: `last_exit` is what it says
 *   missing     no file — a first run, or a build that kept none (`last_exit` `unknown`)
 *   unreadable  a torn file (empty, zeros, cut short: `last_exit` `crash` at the file's time), or
 *               one that could not be read or is not a record this build reads (`unknown`)
 */
export const PREVIOUS_RECORD_STATES = ["found", "missing", "unreadable"] as const;
export type PreviousRecordState = (typeof PREVIOUS_RECORD_STATES)[number];

/* --- the viewer's client ------------------------------------------------------------------- */

/**
 * Where the viewer runs (`viewer_hello.client.surface`):
 *
 *   tg   the Mini App inside Telegram (initData)
 *   web  the website in a browser (a web session's ticket)
 */
export const CLIENT_SURFACES = ["tg", "web"] as const;
export type ClientSurface = (typeof CLIENT_SURFACES)[number];

/**
 * The viewer's browser engine (`client.engine`). The same detection as `VIEWER_ENGINES` of the `vv`
 * report (`datachannel.ts`), with `other` for what that one calls `unknown`.
 */
export const CLIENT_ENGINES = ["webkit", "chromium", "gecko", "other"] as const;
export type ClientEngine = (typeof CLIENT_ENGINES)[number];

/**
 * A platform as the viewer names it (`client.platform`, `client_error.platform`): Telegram's
 * `platform` (`ios`, `android`, `macos`, `tdesktop`, `weba`, …) or `web` on the website. Letters,
 * digits, `_`, `.` and `-`, 1 to 32 of them.
 */
export const CLIENT_PLATFORM_PATTERN = /^[A-Za-z0-9_.-]{1,32}$/;

/** Telegram's own version (`WebApp.version`, the Bot API level it speaks): `8.0`, `9.1`. */
export const TELEGRAM_VERSION_PATTERN = /^\d{1,3}(\.\d{1,4}){0,3}$/;

/* --- the agent's summary of a session ------------------------------------------------------ */

/**
 * What happened during a session, as the agent's summary lists it (`summary.episodes[].kind`):
 *
 *   freeze           the viewer showed no frame for ≥ 2 s while the PC sent (from the `vv` reports)
 *   brake            the quality controller's brake: the rate cut hard on a congested link
 *   drain            the send queue drained: frames held back until it emptied
 *   path_change      the media moved to another candidate pair (a relay, a network switch)
 *   ice_restart      the viewer's ICE restart was applied
 *   capture_restart  the capturer was restarted (lost, recreated)
 *   rung_change      the ladder moved; `code` says why
 */
export const SESSION_EPISODE_KINDS = [
  "freeze",
  "brake",
  "drain",
  "path_change",
  "ice_restart",
  "capture_restart",
  "rung_change",
] as const;
export type SessionEpisodeKind = (typeof SESSION_EPISODE_KINDS)[number];

/** Input the agent applied, by kind (`summary.input`): counts only, never what was typed. */
export const INPUT_KINDS = ["abs", "rel", "buttons", "keys", "text"] as const;
export type InputKind = (typeof INPUT_KINDS)[number];

/** How the agent applied input (`summary.input_path`): `SendInput`, or the HID driver (FakerInput). */
export const INPUT_PATHS = ["sendinput", "hid"] as const;
export type InputPath = (typeof INPUT_PATHS)[number];

/** What the PC captured (`summary.capture_mode`): the whole screen, or «Только игра». */
export const CAPTURE_MODES = ["screen", "game_only"] as const;
export type CaptureMode = (typeof CAPTURE_MODES)[number];

/** The input driver on the PC (`summary.driver`). */
export const DRIVER_STATES = ["installed", "absent", "unknown"] as const;
export type DriverState = (typeof DRIVER_STATES)[number];

/* --- the viewer's usage of a session ------------------------------------------------------- */

/**
 * The viewer's input modes (`usage.input_ms`): on a touch profile «Планшет» (`direct`), «Тачпад»
 * (`trackpad`) and its game mode (`trackpad_game`), «Пады» (`pads`); on a desktop profile the mouse
 * (`desktop`) and its game mode (`desktop_game`).
 */
export const VIEWER_INPUT_MODES = [
  "direct",
  "trackpad",
  "trackpad_game",
  "pads",
  "desktop",
  "desktop_game",
] as const;
export type ViewerInputMode = (typeof VIEWER_INPUT_MODES)[number];

/** The viewer's keyboard (`usage.keyboard_ms`): hidden, the system keyboard with the strip, the sheet. */
export const KEYBOARD_STATES = ["hidden", "typing", "full"] as const;
export type KeyboardState = (typeof KEYBOARD_STATES)[number];

/* --- how a session ended (§5) -------------------------------------------------------------- */

/** Who ended a session (`sessions.ended_by`): written by the server, never sent. */
export const SESSION_ENDED_BY = ["viewer", "agent", "server"] as const;
export type SessionEndedBy = (typeof SESSION_ENDED_BY)[number];

/**
 * What one `ended_reason` glued together, split (`ended_detail`): a closed list per reason. The
 * reason's own vocabulary is untouched — the queries stand on it.
 *
 *   viewer_closed       the viewer's screen went away: «Отключиться» (`button`), «Назад» (`back`),
 *                       the screen unmounted otherwise (`unmount`), the page hidden for good
 *                       (`pagehide`)
 *   peer_closed         the agent's peer closed: the viewer said goodbye on the data channel
 *                       (`viewer`), or str0m closed it by itself — ICE, DTLS, SDP (`rtc`)
 *   agent_disconnected  the server's own: the agent's socket did not come back within the grace
 *                       window. Its goodbye on that socket (`goodbye:<reason>`), the next process
 *                       saying the last one died (`crash`), or neither (`network`)
 */
export const SESSION_END_DETAILS = {
  viewer_closed: ["button", "back", "unmount", "pagehide"],
  peer_closed: ["viewer", "rtc"],
  agent_disconnected: [
    "goodbye:quit",
    "goodbye:shutdown",
    "goodbye:sleep",
    "goodbye:update",
    "crash",
    "network",
  ],
} as const;
export type SessionEndDetailsByReason = typeof SESSION_END_DETAILS;

/**
 * The details a client may send in `session_end.detail.ended_detail`: those of the reasons a client
 * ends with. `agent_disconnected`'s are the server's, derived from what it saw.
 */
export const CLIENT_END_DETAILS = [
  ...SESSION_END_DETAILS.viewer_closed,
  ...SESSION_END_DETAILS.peer_closed,
] as const;
export type ClientEndDetail = (typeof CLIENT_END_DETAILS)[number];

/** Whether `detail` is one of `reason`'s (`SESSION_END_DETAILS`). */
export function isEndDetailOf(reason: string, detail: string): boolean {
  const list = (SESSION_END_DETAILS as Record<string, readonly string[] | undefined>)[reason];
  return list?.includes(detail) ?? false;
}

/**
 * The shape of every code in `session_end.detail` on the wire: a short id — lowercase letters,
 * digits, `_` and `:`, 1 to 32 of them.
 *
 * Deliberately not the closed lists themselves (`CLIENT_END_DETAILS`, `PEER_STAGES`, `DTLS_VERDICTS`,
 * `CANDIDATE_KINDS`): a `session_end` that fails to parse does not end the session at all, so a value
 * a newer client knows and this server does not must cost the detail, never the end. The server holds
 * each code to its list and drops (and logs) one it does not know. Nothing of this shape can carry an
 * address, a name or a sentence.
 */
export const END_DETAIL_CODE_PATTERN = /^[a-z0-9_:]{1,32}$/;

/**
 * How far the end's peer got when the session ended (`session_end.detail.stage`):
 *
 *   new        nothing yet: no candidate pair was checked
 *   ice        ICE checking, never connected
 *   dtls       ICE connected, DTLS not (the stall of «Установка застряла»)
 *   connected  DTLS done: the media path was up
 */
export const PEER_STAGES = ["new", "ice", "dtls", "connected"] as const;
export type PeerStage = (typeof PEER_STAGES)[number];

/**
 * The agent's verdict on a stalled DTLS handshake (`session_end.detail.verdict`): `Verdict::as_str`
 * in agent/crates/transport/src/paths.rs, word for word.
 */
export const DTLS_VERDICTS = [
  "nothing_from_viewer",
  "no_reply_sent",
  "viewer_resends_hello",
  "viewer_silent_after_hello",
  "second_flight_stuck",
  "nominated_path_silent",
  "no_hello_sent",
  "unclear",
] as const;
export type DtlsVerdict = (typeof DTLS_VERDICTS)[number];

/** An ICE candidate's type, as either end saw the selected pair (`pair_local_kind`, `pair_remote_kind`). */
export const CANDIDATE_KINDS = ["host", "srflx", "prflx", "relay"] as const;
export type CandidateKind = (typeof CANDIDATE_KINDS)[number];

/* --- the viewer's connect attempt ---------------------------------------------------------- */

/**
 * The stages of an attempt, in order (docs/metrics.md §3, «Этапы времени до картинки»): each a mark in
 * milliseconds from the tap on «Подключиться» (`connect_attempt.marks`), and the stage an attempt
 * failed before (`fail_stage`: the first one it did not reach).
 *
 *   chunk            the viewer's code loaded (from the cache or the network)
 *   connect          `connect` went to the server
 *   session_created  the server created the session
 *   answer           the agent's answer applied
 *   ice              ICE `connected`
 *   dtls             `connectionState` `connected`
 *   first_rtp        the first video packet arrived
 *   first_decoded    the first frame decoded
 *   first_presented  the first frame shown (`requestVideoFrameCallback`; the first decoded without it)
 */
export const CONNECT_STAGES = [
  "chunk",
  "connect",
  "session_created",
  "answer",
  "ice",
  "dtls",
  "first_rtp",
  "first_decoded",
  "first_presented",
] as const;
export type ConnectStage = (typeof CONNECT_STAGES)[number];

/**
 * How an attempt ended, sent at once when it did: a picture (`ok`), the person backed out before one
 * (`cancel`), or it failed (`fail`, with `fail_stage`).
 */
export const CONNECT_OUTCOMES = ["ok", "cancel", "fail"] as const;
export type ConnectOutcome = (typeof CONNECT_OUTCOMES)[number];

/**
 * The viewer's signaling socket's status (the Mini App's ws.ts `WsStatus`), as an attempt saw it at the
 * tap (`connect_attempt.signaling.at_tap`):
 *
 *   connecting    the first socket of the page is on its way
 *   ready         a socket said `viewer_ready`
 *   reconnecting  a socket was lost and the next one is on its way (or waits out its backoff)
 *   closed        none yet, or closed as the app asked
 *   stopped       a fatal error stopped it for good
 */
export const SIGNALING_STATUSES = [
  "connecting",
  "ready",
  "reconnecting",
  "closed",
  "stopped",
] as const;
export type SignalingStatus = (typeof SIGNALING_STATUSES)[number];

/** The way the API and the socket go on a page with the RU entry's box: the box, or Cloudflare. */
export const SIGNALING_WAYS = ["cf", "ru"] as const;
export type SignalingWay = (typeof SIGNALING_WAYS)[number];

/** Which way one socket went: `SIGNALING_WAYS`, or `own` — the page's own host, on a page with no box. */
export const SOCKET_VIAS = [...SIGNALING_WAYS, "own"] as const;
export type AttemptSocketVia = (typeof SOCKET_VIAS)[number];

/**
 * How a socket stopped being the one the viewer uses (`connect_attempt.signaling.sockets[].end`):
 *
 *   watchdog       it brought no frame within its watchdog's limit, and was replaced at once
 *   watchdog-late  the same, after a watchdog timer that fired late (the page was frozen)
 *   closed         it closed under the viewer (the browser's `close`), and a reconnect followed
 *   network        the browser said the network came back, and it was replaced for that
 *   not-created    `new WebSocket` threw
 *   superseded     another socket became the current one while it still was (never expected)
 *   asked          closed as the app asked (a spare: the session's setup ended)
 *   stopped        a fatal error stopped the signaling for good
 *   lost_race      closed because the other socket of a race opened first: a socket still connecting
 *                  got a spare beside it (`spare`), and whichever opened first said hello
 *
 * A spare's end is how it stopped being in flight beside the current socket.
 */
export const SOCKET_ENDS = [
  "watchdog",
  "watchdog-late",
  "closed",
  "network",
  "not-created",
  "superseded",
  "asked",
  "stopped",
  "lost_race",
] as const;
export type AttemptSocketEnd = (typeof SOCKET_ENDS)[number];

/* --- the viewer's errors ------------------------------------------------------------------- */

/**
 * What kind of error the viewer caught (`client_error.kind`):
 *
 *   render        React's error boundary caught a render
 *   promise       `unhandledrejection`
 *   chunk         a lazy chunk failed to load
 *   load_timeout  the page never finished starting (the inline watchdog in `index.html`)
 *   other         `window.onerror` and anything else
 */
export const CLIENT_ERROR_KINDS = ["render", "promise", "chunk", "load_timeout", "other"] as const;
export type ClientErrorKind = (typeof CLIENT_ERROR_KINDS)[number];

/** A stack's hash (`client_error.stack_hash`): 8 to 64 lowercase hex digits. */
export const STACK_HASH_PATTERN = /^[0-9a-f]{8,64}$/;

/* --- the agent's events -------------------------------------------------------------------- */

/**
 * What the agent tells the server outside any session (`agent_event.kind`), each a product event of
 * the same name (§6):
 *
 *   agent_started            a process started (its boot, its build, how the last one ended)
 *   agent_crashed            the last process panicked: its summary, written on the panic and sent
 *                            by the next start
 *   update_finished          an update ended: confirmed, or rolled back
 *   driver_install_finished  the input driver's installer ended
 *   pc_setting_changed       the owner changed a setting on the PC (`PC_SETTING_KEYS`)
 */
export const AGENT_EVENT_KINDS = [
  "agent_started",
  "agent_crashed",
  "update_finished",
  "driver_install_finished",
  "pc_setting_changed",
] as const;
export type AgentEventKind = (typeof AGENT_EVENT_KINDS)[number];

/** The settings on the PC whose changes are counted (`pc_setting_changed.key`): a closed list. */
export const PC_SETTING_KEYS = [
  "game_only",
  "game_only_for_guests",
  "game_helper",
  "autostart",
  "auto_update",
  "log_level",
] as const;
export type PcSettingKey = (typeof PC_SETTING_KEYS)[number];

/** How an update ended (`update_finished.outcome`). */
export const UPDATE_OUTCOMES = ["confirmed", "rolled_back"] as const;
export type UpdateOutcome = (typeof UPDATE_OUTCOMES)[number];

/** How the driver's installer ended (`driver_install_finished.outcome`): `cancelled` — UAC declined. */
export const DRIVER_INSTALL_OUTCOMES = ["ok", "failed", "cancelled"] as const;
export type DriverInstallOutcome = (typeof DRIVER_INSTALL_OUTCOMES)[number];

/**
 * A short identifier the agent names a step, a reason or a code by (`driver_install_finished.step`,
 * `update_finished.reason`, an episode's `code`): lowercase letters, digits and `_`, 1 to 32 — never
 * a sentence, a path or a name.
 */
export const SHORT_ID_PATTERN = /^[a-z0-9_]{1,32}$/;

/** A thread's name (`agent_crashed.thread`): `main`, `tokio-runtime-worker`, `capture`. */
export const THREAD_NAME_PATTERN = /^[A-Za-z0-9_.:-]{1,32}$/;

/** Where a panic happened, hashed (`agent_crashed.place_hash`): 8 to 64 lowercase hex digits. */
export const PLACE_HASH_PATTERN = /^[0-9a-f]{8,64}$/;

/* --- paths and bounds ---------------------------------------------------------------------- */

/**
 * `POST` target of the viewer's connect attempt when no socket came up (the same body as the
 * `connect_attempt` frame without `type`): `Authorization: tma <initData>` from the Mini App, the
 * session cookie from the website — `fetch` with `keepalive`, since `sendBeacon` cannot set a header.
 * `204` when taken.
 */
export const VIEWER_ATTEMPT_PATH = "/api/viewer/attempt";

/**
 * `POST` target of a client error when no socket came up (the body of the `client_error` frame
 * without `type`). Signed in as above when it can be; without either — a white screen may have no
 * initData — it is taken all the same, held to a strict budget per address, its `message` dropped.
 * `204` when taken.
 */
export const VIEWER_CLIENT_ERROR_PATH = "/api/viewer/client-error";

/**
 * `POST` target of the website's download beacon: «Скачать для Windows» went, and the browser fetched
 * the exe (`download_sent`, `via` `site`; `DOWNLOAD_VIAS`). Signed in as every viewer route — the
 * session cookie with its Origin check, `fetch` with `keepalive` so leaving the page does not cancel
 * it. Body `ViewerDownloadRequest` (`metrics-wire.ts`): the release's version when the page knows it
 * (`latest.json`). `204` when taken; a version not of the agent's form is left out of the event, never a
 * reason to lose the download.
 */
export const VIEWER_DOWNLOAD_PATH = "/api/viewer/download";

/**
 * Bounds every client keeps to. Past one, the whole frame is malformed and lost (`bad_message`), the
 * report's other numbers with it — so a client that cannot fit a value leaves the field out rather
 * than send it. They refuse what no real session produces, never a real one.
 */
export const TELEMETRY_LIMITS = {
  /** Episodes in one summary; past it the agent counts the rest in `episodes_dropped`. */
  episodes: 100,
  /** Rungs in `summary.rung_s` (keyed by encoded height). */
  rungs: 16,
  /** Milliseconds within a session (an episode's `at_ms`, `dur_ms`, a usage counter): 30 days. */
  sessionMs: 2_592_000_000,
  /** Seconds a summary counts (`rung_s`, `freeze_s`): 30 days. */
  sessionSeconds: 2_592_000,
  /** Milliseconds of an attempt from the tap (`marks`, `outcome_ms`, `first_presented_ms`): an hour. */
  attemptMs: 3_600_000,
  /**
   * Sockets an attempt lists (`signaling.sockets`); past it the first `attemptSockets - 1` and the last
   * are kept and the rest counted in `signaling.sockets_dropped`.
   */
  attemptSockets: 8,
  /** A counter of an attempt's page events (`signaling.offline_events`, `visibility_changes` …). */
  attemptEvents: 10_000,
  /** A client error's `message`, in characters (Unicode code points). */
  errorMessageChars: 300,
  /** The body of either viewer beacon, bytes; the largest the schemas allow is well under it. */
  beaconBodyBytes: 4 * 1024,
  /** Seconds a process may have run (`agent_crashed.uptime_s`): a year. */
  uptimeSeconds: 31_536_000,
} as const;
