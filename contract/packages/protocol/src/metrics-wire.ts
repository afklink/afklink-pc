/**
 * Contract v2 of the telemetry, as zod schemas (docs/metrics.md §4.2, §5, §6 in the umbrella): the
 * builds the agent and the viewer say they are, the agent's summary and the viewer's usage of a
 * session, how an end saw its peer, the agent's events, the viewer's connect attempts and errors.
 * The vocabularies are in `metrics.ts` (import-free, for the Mini App); the messages that carry these
 * are in `agent-ws.ts` and `viewer-ws.ts`, the session reports in `telemetry.ts`; the product events
 * the server records from all of them in `product-events-wire.ts`.
 *
 * Every object here is plain, not strict: a field a newer client adds is dropped by a server whose
 * contract does not know it, never a reason to refuse the frame. Every string is an enum or a short
 * id held to a pattern (`metrics.ts`); the one bounded free text is a client error's `message`.
 */
import { z } from "zod";
import { deviceIdSchema, sessionIdSchema } from "./common";
import {
  AGENT_EXIT_KINDS,
  AGENT_VERSION_PATTERN,
  type AgentEventKind,
  BUILD_COMMIT_PATTERN,
  CAPTURE_MODES,
  CLIENT_ENGINES,
  CLIENT_ERROR_KINDS,
  CLIENT_PLATFORM_PATTERN,
  CLIENT_SURFACES,
  CONNECT_OUTCOMES,
  CONNECT_STAGES,
  DRIVER_INSTALL_OUTCOMES,
  DRIVER_STATES,
  END_DETAIL_CODE_PATTERN,
  INPUT_PATHS,
  PC_SETTING_KEYS,
  PLACE_HASH_PATTERN,
  PREVIOUS_RECORD_STATES,
  SESSION_EPISODE_KINDS,
  SHORT_ID_PATTERN,
  SIGNALING_STATUSES,
  SIGNALING_WAYS,
  SOCKET_ENDS,
  SOCKET_VIAS,
  STACK_HASH_PATTERN,
  TELEGRAM_VERSION_PATTERN,
  TELEMETRY_LIMITS,
  THREAD_NAME_PATTERN,
  UPDATE_OUTCOMES,
  VIEWER_BUILD_PATTERN,
} from "./metrics";
import { AGENT_BUILD_CHANNELS } from "./start-failure";

/* --- primitives ---------------------------------------------------------------------------- */

/** Unix milliseconds on the sender's clock: from 1970 to the start of 2100. */
export const epochMsSchema = z.number().int().nonnegative().max(4_102_444_800_000);

/** A counter: whole, never negative. */
const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

/** Milliseconds within a session. */
const sessionMs = z.number().int().nonnegative().max(TELEMETRY_LIMITS.sessionMs);

/** Seconds within a session; fractions allowed (a rung held for 12.5 s). */
const sessionSeconds = z.number().nonnegative().max(TELEMETRY_LIMITS.sessionSeconds);

/** Milliseconds from the viewer's tap on «Подключиться». */
const attemptMs = z.number().int().nonnegative().max(TELEMETRY_LIMITS.attemptMs);

const shortId = z.string().regex(SHORT_ID_PATTERN, "expected a short id: a-z, 0-9, _");

/** An agent's version (`AGENT_VERSION_PATTERN`): the same rule as the start failure beacon's. */
export const agentVersionSchema = z
  .string()
  .max(32)
  .regex(AGENT_VERSION_PATTERN, "a version is major.minor.patch, optionally -prerelease");

/** A commit a build was stamped with (`BUILD_COMMIT_PATTERN`). */
export const buildCommitSchema = z
  .string()
  .regex(BUILD_COMMIT_PATTERN, "a commit is 7 to 40 lowercase hex digits");

/** The Mini App's `BUILD_ID` (`VIEWER_BUILD_PATTERN`). */
export const viewerBuildSchema = z
  .string()
  .regex(VIEWER_BUILD_PATTERN, "a build is 1 to 40 of letters, digits, _ and -");

/** A platform as the viewer names it (`CLIENT_PLATFORM_PATTERN`). */
export const clientPlatformSchema = z
  .string()
  .regex(CLIENT_PLATFORM_PATTERN, "a platform is 1 to 32 of letters, digits, _ . -");

/* --- builds -------------------------------------------------------------------------------- */

/**
 * The agent's build (`agent_hello.build`, `agent_started.build`): what `afklink_core::build_info`
 * stamps — the fields of the diagnostics' `agentBuildSchema` (`diagnostics.ts`) without the label and
 * the time, the version held to its pattern. Without it the server knows a PC's version only from its
 * last `User-Agent`, without the commit, and not per session.
 */
export const agentBuildInfoSchema = z.object({
  version: agentVersionSchema,
  /** Absent or null when the build was not stamped (a plain `cargo build`). */
  commit: buildCommitSchema.nullish(),
  channel: z.enum(AGENT_BUILD_CHANNELS),
  /** Built from a tree with uncommitted changes. Absent: not known. */
  dirty: z.boolean().optional(),
});
export type AgentBuildInfo = z.infer<typeof agentBuildInfoSchema>;

/** How the agent's previous process ended (`AGENT_EXIT_KINDS`), and when, if it knows. */
export const agentLastExitSchema = z.object({
  kind: z.enum(AGENT_EXIT_KINDS),
  /** When it ended, Unix ms on the PC's clock; absent when it does not know (`crash`, `unknown`). */
  at: epochMsSchema.optional(),
});
export type AgentLastExit = z.infer<typeof agentLastExitSchema>;

/**
 * Who the viewer is, as software (`viewer_hello.client`): where it runs, the platform, the engine and
 * the build. With it the server knows each session's surface, platform, engine and build, and records
 * an `app_opened`; without it — a Mini App older than contract v2 — none of them.
 */
export const clientInfoSchema = z.object({
  surface: z.enum(CLIENT_SURFACES),
  platform: clientPlatformSchema,
  engine: z.enum(CLIENT_ENGINES),
  build: viewerBuildSchema,
  /** Telegram's `WebApp.version` (the Bot API level the client speaks); absent on the website. */
  tg_version: z
    .string()
    .max(16)
    .regex(TELEGRAM_VERSION_PATTERN, "a Telegram version is numbers and dots")
    .optional(),
});
export type ClientInfo = z.infer<typeof clientInfoSchema>;

/* --- the agent's summary of a session ------------------------------------------------------ */

/** One thing that happened during a session (`SESSION_EPISODE_KINDS`). */
export const sessionEpisodeSchema = z.object({
  kind: z.enum(SESSION_EPISODE_KINDS),
  /** When it began, in milliseconds since the session's pipeline started. */
  at_ms: sessionMs,
  /** How long it lasted; absent for an instant (a path change, a rung change). */
  dur_ms: sessionMs.optional(),
  /** Why, as a short id: a rung change's reason (`brake`, `bwe`, `cpu`, `viewer`), and so on. */
  code: shortId.optional(),
});
export type SessionEpisode = z.infer<typeof sessionEpisodeSchema>;

/**
 * Input the agent applied, by kind (`INPUT_KINDS`): how many of each — moves to a point (`abs`),
 * relative moves (`rel`), button presses (`buttons`), key presses (`keys`), texts typed (`text`).
 * Counts only: never a key, a character or a position.
 */
export const inputCountsSchema = z.object({
  abs: count,
  rel: count,
  buttons: count,
  keys: count,
  text: count,
});
export type InputCounts = z.infer<typeof inputCountsSchema>;

/**
 * Where a session's quality profile came from: the server's `quality_profile`, or the agent's
 * compiled one — because the server sent none, or what it sent did not validate. Here and not in
 * `quality-profile.ts`, which no module of the index may import (its field map stays out of web
 * bundles; it is the subpath `@afklink/protocol/quality-profile`).
 */
export const QUALITY_PROFILE_SOURCES = ["server", "fallback"] as const;
export type QualityProfileSource = (typeof QUALITY_PROFILE_SOURCES)[number];

/** A rung's encoded height as a key of `rung_s`: `1080`, `720`, `540`. */
const RUNG_KEY_PATTERN = /^\d{2,5}$/;

/**
 * The agent's summary of a session (`session_stats.stats.summary`), cumulative like the rest of the
 * report: every report carries the whole session so far, the final one the whole session.
 *
 * Each field is optional on its own: an agent sends what it measures. The golden fixture has every
 * one, so a mirror that drops one fails its round-trip.
 */
export const agentSessionSummarySchema = z.object({
  /**
   * Seconds spent on each rung of the ladder, keyed by the rung's encoded height: `{"1080": 412.5,
   * "720": 31}`. At most `TELEMETRY_LIMITS.rungs` of them.
   */
  rung_s: z
    .record(z.string().regex(RUNG_KEY_PATTERN, "a rung is its encoded height"), sessionSeconds)
    .refine((r) => Object.keys(r).length <= TELEMETRY_LIMITS.rungs, {
      message: `at most ${TELEMETRY_LIMITS.rungs} rungs`,
    })
    .optional(),
  /**
   * Seconds of freeze (docs/metrics.md §3): seconds of motion — the PC sending ≥ 5 frames a second —
   * in which the viewer showed none, from its `vv` reports.
   */
  freeze_s: sessionSeconds.optional(),
  /** What happened, in order; at most `TELEMETRY_LIMITS.episodes`. */
  episodes: z.array(sessionEpisodeSchema).max(TELEMETRY_LIMITS.episodes).optional(),
  /** Episodes past the cap, counted rather than listed. */
  episodes_dropped: count.optional(),
  /** The 95th percentile of the time inside `encode()`, ms; null before the first encode. */
  encode_ms_p95: z.number().nonnegative().max(60_000).nullable().optional(),
  /** Input applied, by kind (`inputCountsSchema`). */
  input: inputCountsSchema.optional(),
  /** How input was applied (`INPUT_PATHS`): `SendInput`, or the HID driver. */
  input_path: z.enum(INPUT_PATHS).optional(),
  /** Times the viewer's input did not reach the window in front (`input_blocked` in the heartbeat). */
  input_blocked_n: count.optional(),
  /** What the PC captured (`CAPTURE_MODES`). */
  capture_mode: z.enum(CAPTURE_MODES).optional(),
  /** The input driver on the PC (`DRIVER_STATES`). */
  driver: z.enum(DRIVER_STATES).optional(),
  /**
   * Frames held back by the rate's token bucket (`frames_dropped_rate` in the agent): the live counter
   * that replaces `frames_dropped_paced`, which never moved.
   */
  dropped_rate: count.optional(),
  /** Bytes the session's media put on the socket, every path — not the encoder's output. */
  bytes_socket: count.optional(),
  /** Of those, bytes through a TURN relay. */
  bytes_relay: count.optional(),
  /**
   * The quality profile the session ran on, `"<id>.v<v>"` (`qualityProfileLabel`). Only a length
   * cap, not the label's pattern: the server parses the whole message, and a malformed label must
   * never cost the session's final report.
   */
  quality_profile: z.string().max(48).optional(),
  /** Where it came from: the server's `quality_profile`, or the agent's compiled fallback. */
  quality_profile_source: z.enum(QUALITY_PROFILE_SOURCES).optional(),
});
export type AgentSessionSummary = z.infer<typeof agentSessionSummarySchema>;

/* --- the viewer's usage of a session ------------------------------------------------------- */

/** Milliseconds in each input mode (`VIEWER_INPUT_MODES`); a mode never used is left out. */
export const inputModeMsSchema = z.object({
  direct: sessionMs.optional(),
  trackpad: sessionMs.optional(),
  trackpad_game: sessionMs.optional(),
  pads: sessionMs.optional(),
  desktop: sessionMs.optional(),
  desktop_game: sessionMs.optional(),
});

/** Milliseconds in each keyboard state (`KEYBOARD_STATES`); a state never entered is left out. */
export const keyboardMsSchema = z.object({
  hidden: sessionMs.optional(),
  typing: sessionMs.optional(),
  full: sessionMs.optional(),
});

/**
 * The viewer's usage of a session (`session_stats.stats.usage`), cumulative: counters only — how
 * long in each mode, how many switches and pastes, never what was typed or pasted.
 */
export const viewerUsageSchema = z.object({
  /** Milliseconds of picture in each input mode. */
  input_ms: inputModeMsSchema.optional(),
  /** Times the input mode changed. */
  mode_switches: count.optional(),
  /** Milliseconds in each keyboard state. */
  keyboard_ms: keyboardMsSchema.optional(),
  /** «Вставить» pressed (the website's clipboard). */
  pastes: count.optional(),
  /** Quality picked by hand (the `q` message). */
  quality_picks: count.optional(),
  /** «Повтор» and «Цепочка» runs started. */
  repeat_runs: count.optional(),
  chain_runs: count.optional(),
  /** Milliseconds the picture was on screen with the page visible. */
  visible_ms: sessionMs.optional(),
});
export type ViewerUsage = z.infer<typeof viewerUsageSchema>;

/* --- how an end saw its peer (§5, §7) ------------------------------------------------------ */

/** A code in `session_end.detail` (`END_DETAIL_CODE_PATTERN`): checked against its list by the server. */
const endDetailCode = z
  .string()
  .regex(END_DETAIL_CODE_PATTERN, "expected a short code: a-z, 0-9, _ and :");

/**
 * What the end that sent `session_end` knows of how it ended (`session_end.detail`): the reason split
 * (`ended_detail`, `SESSION_END_DETAILS`), and how its peer saw the media path — how far it got
 * (`stage`, `PEER_STAGES`), the agent's DTLS verdict (`verdict`, `DTLS_VERDICTS`), how long DTLS
 * waited after ICE, the selected pair's candidate types on both sides (`CANDIDATE_KINDS`) and how the
 * relay was reached (`RELAY_TRANSPORTS`). Kinds and verdicts only: no address, no candidate.
 *
 * Every code is a patterned short id rather than its enum (`END_DETAIL_CODE_PATTERN` says why); the
 * server keeps the ones on their lists.
 */
export const sessionEndDetailSchema = z.object({
  ended_detail: endDetailCode.optional(),
  stage: endDetailCode.optional(),
  verdict: endDetailCode.optional(),
  /** Milliseconds from ICE `connected` to DTLS done; absent when DTLS never came. */
  dtls_after_ice_ms: sessionMs.optional(),
  pair_local_kind: endDetailCode.optional(),
  pair_remote_kind: endDetailCode.optional(),
  relay_transport: endDetailCode.optional(),
});
export type SessionEndDetail = z.infer<typeof sessionEndDetailSchema>;

/* --- the agent's events -------------------------------------------------------------------- */

/** `agent_started`: a process started. */
export const agentStartedPropsSchema = z.object({
  /** This process's random id (`agent_hello.boot_id`). */
  boot_id: z.uuid(),
  /** The first start in this data folder: `identity.json` was created now. */
  first_run: z.boolean(),
  build: agentBuildInfoSchema,
  last_exit: agentLastExitSchema,
  /** Started by Windows' autostart, not by a person. */
  autostart: z.boolean(),
  /**
   * What this start found of the previous process's record (`PREVIOUS_RECORD_STATES`): whether
   * `last_exit` comes from a record, from none, or from a file that held none. Absent from agents
   * before it.
   */
  previous_record: z.enum(PREVIOUS_RECORD_STATES).optional(),
  /**
   * Whether the previous process went down with the PC. `true`: Windows booted afresh within three
   * minutes of its last sign of life (its record's last minute mark, or the file's time) — power
   * lost, a reset, a blue screen, a shutdown or restart. `false`: this Windows boot was running
   * already before that process ran, so it ended on its own (or across a fast startup, which resumes
   * Windows rather than booting it afresh). Absent when it cannot be told: no record, no boot time,
   * clocks that disagree, or a boot later than those three minutes — the process may have died alone
   * long before, or the PC slept and lost power asleep. A verdict only, never the boot time itself.
   */
  pc_restarted: z.boolean().optional(),
});

/** `agent_crashed`: the previous process panicked; its summary, sent by the next start. */
export const agentCrashedPropsSchema = z.object({
  version: agentVersionSchema,
  /** The panic's location (file, line, column) hashed: the same place hashes the same. */
  place_hash: z.string().regex(PLACE_HASH_PATTERN, "a place hash is 8 to 64 lowercase hex digits"),
  /** The panicking thread's name. */
  thread: z.string().regex(THREAD_NAME_PATTERN, "a thread name is 1 to 32 of A-Z a-z 0-9 _ . : -"),
  /** How long the process had run. */
  uptime_s: z.number().int().nonnegative().max(TELEMETRY_LIMITS.uptimeSeconds),
  /** The crashed process's `boot_id`, when it wrote one. */
  boot_id: z.uuid().optional(),
});

/** `update_finished`: an update ended, confirmed or rolled back (`state.json` on the PC). */
export const updateFinishedPropsSchema = z.object({
  from: agentVersionSchema,
  to: agentVersionSchema,
  outcome: z.enum(UPDATE_OUTCOMES),
  /** Why it rolled back, as a short id; absent when confirmed. */
  reason: shortId.optional(),
});

/** `driver_install_finished`: the input driver's installer ended. */
export const driverInstallFinishedPropsSchema = z.object({
  outcome: z.enum(DRIVER_INSTALL_OUTCOMES),
  /** The step it ended at, as a short id (`uac`, `msiexec`, `verify`). */
  step: shortId,
  /** `msiexec`'s exit code or an HRESULT, when there is one. */
  code: z.number().int().min(-2_147_483_648).max(4_294_967_295).optional(),
  /** How long it took. */
  ms: sessionMs,
});

/** `pc_setting_changed`: the owner changed a setting on the PC (`PC_SETTING_KEYS`). */
export const pcSettingChangedPropsSchema = z.object({
  key: z.enum(PC_SETTING_KEYS),
  /** The new value: a switch's state, or a short id (`log_level`: `debug`, `info`, `off`). */
  value: z.union([z.boolean(), shortId]),
});

/** Each agent event's props, by kind (`AGENT_EVENT_KINDS`). */
export const AGENT_EVENT_PROPS = {
  agent_started: agentStartedPropsSchema,
  agent_crashed: agentCrashedPropsSchema,
  update_finished: updateFinishedPropsSchema,
  driver_install_finished: driverInstallFinishedPropsSchema,
  pc_setting_changed: pcSettingChangedPropsSchema,
} as const satisfies Record<AgentEventKind, z.ZodObject>;

/* --- the viewer's connect attempt ---------------------------------------------------------- */

/** Each stage's mark, milliseconds from the tap (`CONNECT_STAGES`); a stage not reached is left out. */
export const connectMarksSchema = z.object({
  chunk: attemptMs.optional(),
  connect: attemptMs.optional(),
  session_created: attemptMs.optional(),
  answer: attemptMs.optional(),
  ice: attemptMs.optional(),
  dtls: attemptMs.optional(),
  first_rtp: attemptMs.optional(),
  first_decoded: attemptMs.optional(),
  first_presented: attemptMs.optional(),
});
export type ConnectMarks = z.infer<typeof connectMarksSchema>;

/** A counter of an attempt's page events (`TELEMETRY_LIMITS.attemptEvents`). */
const attemptCount = z.number().int().nonnegative().max(TELEMETRY_LIMITS.attemptEvents);

/**
 * One socket that was the viewer's signaling socket at some moment of an attempt, or a spare in flight
 * beside it (`signaling.sockets`). Its own times are milliseconds from its creation, bounded like a
 * session's: a socket carried over from before the tap may be days old. A time is left out when it
 * never came.
 */
export const attemptSocketSchema = z.object({
  /** The way it went (`SOCKET_VIAS`): `own` on a page with no box. */
  via: z.enum(SOCKET_VIAS),
  /**
   * Opened as a spare beside a socket still connecting (the viewer's race: whichever opened first said
   * hello, the other ended `lost_race`). A spare that won, or took the place of one its watchdog gave
   * up on, is current from then and keeps the mark.
   */
  spare: z.literal(true).optional(),
  /** It was created before the tap (carried over into the attempt); `created_ms` is then 0. */
  before_tap: z.literal(true).optional(),
  /** From the tap to its `new WebSocket`. */
  created_ms: attemptMs,
  /** From its creation to its `open`, its `viewer_ready`, its `error` and its `close`. */
  open_ms: sessionMs.optional(),
  ready_ms: sessionMs.optional(),
  error_ms: sessionMs.optional(),
  close_ms: sessionMs.optional(),
  /** From its creation to when it stopped being the current socket (`end`). */
  end_ms: sessionMs.optional(),
  /**
   * The browser's `CloseEvent.code` (1000–4999: 1006 for a connection lost, 1005 for none given, 4xxx
   * the server's). Its `reason` text is never sent. May come after `end`: a socket given up on still
   * says how it finally closed, if it did before the attempt ended.
   */
  close_code: z.number().int().min(1000).max(4999).optional(),
  /**
   * How it stopped being the current socket, or a spare in flight (`SOCKET_ENDS`); absent: still
   * current, or in flight, at the end.
   */
  end: z.enum(SOCKET_ENDS).optional(),
  /** Its `readyState` at the attempt's end (0 connecting … 3 closed), for the socket current then. */
  state_at_end: z.number().int().min(0).max(3).optional(),
});
export type AttemptSocket = z.infer<typeof attemptSocketSchema>;

/**
 * What the signaling socket did during an attempt (`connect_attempt.signaling`): its status at the
 * tap, every socket that was current at some moment of it or a spare beside one, in the order they
 * were made, and what the page and the network did
 * meanwhile — the story behind a `fail_stage` `connect` (no `viewer_ready` came). Codes, counters and
 * times only: no address, no host, no close reason, nothing about the person.
 *
 * Past `TELEMETRY_LIMITS.attemptSockets` sockets the first `attemptSockets - 1` and the last one are
 * listed (the start of the story and where it ended) and the rest counted in `sockets_dropped`.
 */
export const connectSignalingSchema = z.object({
  /**
   * Only for an attempt carried across a reload (its viewer's code was gone after a deploy, and the
   * page reloaded itself to finish the Connect): milliseconds from the tap to when this page picked the
   * attempt up and the story started. The «at the tap» fields below are then the pickup's, the counts
   * start there, and the sockets of the page before the reload are not in it.
   */
  picked_up_ms: attemptMs.optional(),
  /** The socket's status at the tap (`SIGNALING_STATUSES`). */
  at_tap: z.enum(SIGNALING_STATUSES),
  /** The socket current at the tap was created this long before it. */
  tap_socket_age_ms: sessionMs.optional(),
  /** At the tap a reconnect waited out its backoff: this much of it was left. */
  tap_backoff_ms: attemptMs.optional(),
  /** At the tap the hello's credential was on its way (the website's one-time ticket). */
  tap_hello_pending: z.literal(true).optional(),
  sockets: z.array(attemptSocketSchema).max(TELEMETRY_LIMITS.attemptSockets),
  /** Sockets past the cap, counted rather than listed. */
  sockets_dropped: attemptCount.optional(),
  /** `navigator.onLine` at the tap and at the end. */
  online_at_tap: z.boolean(),
  online_at_end: z.boolean(),
  /** The browser's `offline` and `online` events during the attempt. */
  offline_events: attemptCount,
  online_events: attemptCount,
  /** The page was hidden at the tap; its visibility changes during the attempt; time spent hidden. */
  hidden_at_tap: z.boolean(),
  visibility_changes: attemptCount,
  hidden_ms: attemptMs,
  /** On a page with the RU entry's box: the way at the tap and at the end, and changes seen between. */
  way_at_tap: z.enum(SIGNALING_WAYS).optional(),
  way_at_end: z.enum(SIGNALING_WAYS).optional(),
  way_switches: attemptCount.optional(),
});
export type ConnectSignaling = z.infer<typeof connectSignalingSchema>;

/**
 * One attempt to connect, from the tap on «Подключиться» to the first frame shown or the end: sent
 * once, as soon as it ended (`connect_attempt` on the socket, or `POST /api/viewer/attempt`).
 */
export const connectAttemptShape = {
  /** A random id, made at the tap. Repeats of one attempt (the socket and the beacon) count once. */
  attempt_id: z.uuid(),
  outcome: z.enum(CONNECT_OUTCOMES),
  /** With `fail` and `cancel`: the first stage it did not reach. */
  fail_stage: z.enum(CONNECT_STAGES).optional(),
  /**
   * Why, as the code the viewer was given: an error code answering `connect` (`device_offline`,
   * `not_bound`) or the session's end reason (`paused_on_pc`, `superseded`, `viewer_connect_timeout`).
   */
  fail_code: z
    .string()
    .regex(/^[a-z0-9_]{1,64}$/, "a code is 1 to 64 of a-z, 0-9, _")
    .optional(),
  marks: connectMarksSchema,
  /**
   * When it ended, milliseconds from the tap: the first frame shown (`ok`), the person backing out
   * (`cancel`), the failure (`fail`). What tells a cancel in the first 5 s — not an honest attempt
   * (docs/metrics.md §3) — from one after a long wait; the marks alone end at the last stage reached.
   */
  outcome_ms: attemptMs.optional(),
  /** Whether the list showed the PC online at the tap. */
  pc_online: z.boolean().optional(),
  /** The PC it was for. */
  device_id: deviceIdSchema.optional(),
  /** The session it got, once `session_created` came. */
  session_id: sessionIdSchema.optional(),
  /** Who the viewer is, for an attempt sent before (or without) a hello. */
  client: clientInfoSchema.optional(),
  /**
   * What the signaling socket did during the attempt (`connectSignalingSchema`); absent from a viewer
   * older than the field. A server older than the field drops it unread: `z.object` strips the keys it
   * does not know, so the rest of the attempt is taken as before.
   */
  signaling: connectSignalingSchema.optional(),
};
export const connectAttemptSchema = z.object(connectAttemptShape);
export type ConnectAttempt = z.infer<typeof connectAttemptSchema>;

/* --- the viewer's errors ------------------------------------------------------------------- */

/**
 * An error the viewer caught (`client_error` on the socket, or `POST /api/viewer/client-error`): its
 * kind, the build and platform it happened on, the error's own message and a hash of its stack.
 */
export const clientErrorShape = {
  kind: z.enum(CLIENT_ERROR_KINDS),
  build: viewerBuildSchema,
  platform: clientPlatformSchema,
  /**
   * The error's message, at most `TELEMETRY_LIMITS.errorMessageChars` characters: the one bounded free
   * text of the telemetry. The error's own words (`TypeError: …`), never anything a person typed.
   * Dropped by the server when the sender could not sign in.
   */
  message: z.string().max(TELEMETRY_LIMITS.errorMessageChars).optional(),
  /** A hash of the stack, so one bug is one row however often it happens. */
  stack_hash: z.string().regex(STACK_HASH_PATTERN, "a stack hash is 8 to 64 lowercase hex digits"),
  surface: z.enum(CLIENT_SURFACES).optional(),
  engine: z.enum(CLIENT_ENGINES).optional(),
};
export const clientErrorSchema = z.object(clientErrorShape);
export type ClientError = z.infer<typeof clientErrorSchema>;

/* --- the website's download beacon --------------------------------------------------------- */

/**
 * Body of `POST /api/viewer/download` (`VIEWER_DOWNLOAD_PATH`): the website's «Скачать для Windows»
 * went — `download_sent` with `via` `site`. `version`: the release the page fetched, as `latest.json`
 * names it; absent when the page did not learn it. The server takes a version not of this form as
 * none (the download still counts), and answers `204`.
 */
export const viewerDownloadRequestSchema = z.object({ version: agentVersionSchema.optional() });
export type ViewerDownloadRequest = z.infer<typeof viewerDownloadRequestSchema>;
