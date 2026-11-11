/**
 * The start failure beacon: `POST /api/agent/start-failure`.
 *
 * ## Why this exists
 *
 * When the desktop app cannot start (the Microsoft Edge WebView2 Runtime is missing), it logs the
 * error, shows a message box and exits before it has spoken to the server at all. Such a PC never
 * appears in `devices`, so without a signal "downloaded but could not start" would be invisible: the
 * funnel would begin at the first signaling handshake. On its way out the app sends this one
 * request, once, and exits whatever the answer.
 *
 * ## What it is, and what it is not
 *
 * Anonymous and unauthenticated: at that point the device's key (`identity.json`) is not loaded, so
 * nothing is signed, and the server takes `device_id` on trust — it only links a failure to the same
 * PC's later handshake, if one ever comes (`sql/analytics.sql` in the backend). Nothing personal:
 * why it failed (a closed list), the build (version, channel, commit), the Windows build as numbers,
 * the random device id, and an optional short code from the failing component. No name, no account,
 * no path, no free text; the server stores none of the request's addresses either.
 *
 * Fire and forget. The answer is `204` when the beacon was taken (a repeat within the server's
 * window included), `400 bad_message` when it is not this shape, `413 payload_too_large` past
 * {@link AGENT_START_FAILURE_LIMITS}`.bodyBytes`, `429 rate_limited` past the server's budgets. The
 * agent does not retry and does not act on any of them: the person is already looking at the
 * message box that says what to install.
 *
 * Unknown keys are dropped rather than refused (zod's default), as in `diagnostics.ts`: a newer
 * agent's extra field does not cost the beacon on an older server.
 *
 * Constants and the schema live together here, unlike `diagnostics-wire.ts` / `diagnostics.ts`: only
 * the server and the agent ever use this, and the Mini App's bundle never reaches the module.
 */
import { z } from "zod";
import { deviceIdSchema } from "./common";

/** `POST` target of the beacon, on the server the agent is configured with (`https://` of it). */
export const AGENT_START_FAILURE_PATH = "/api/agent/start-failure";

/**
 * Why the app could not start. A closed list, extended as new causes earn a place:
 *
 *   webview2_missing   the Microsoft Edge WebView2 Runtime is not installed (or its loader found no
 *                      usable version), so the window cannot exist
 *
 * Each value is a lowercase identifier of at most 32 characters (`[a-z0-9_]`), which is what the
 * server's stored form relies on.
 */
export const AGENT_START_FAILURE_REASONS = ["webview2_missing"] as const;
export type AgentStartFailureReason = (typeof AGENT_START_FAILURE_REASONS)[number];

/** The build channels, as `afklink_core::build_info` names them (the same as `agentBuildSchema`). */
export const AGENT_BUILD_CHANNELS = ["dev", "release"] as const;

/** Sizes the server holds the beacon to. Characters are Unicode code points; bytes are bytes. */
export const AGENT_START_FAILURE_LIMITS = {
  /** The whole body as sent, JSON. Past it: `413 payload_too_large`, unread when `Content-Length`
   *  says so. The largest beacon the schema allows is under 300 bytes of compact JSON. */
  bodyBytes: 2 * 1024,
  /** `version`. */
  versionChars: 32,
  /** `os`: `major.minor.build.revision` at their widest is 21. */
  osChars: 24,
  /** `detail_code`. */
  detailCodeChars: 32,
} as const;

/**
 * Body of `POST /api/agent/start-failure`: JSON, `Content-Type: application/json`.
 *
 * Every string has a fixed alphabet and length, so none can carry a name, a path or a sentence.
 */
export const agentStartFailureSchema = z.object({
  reason: z.enum(AGENT_START_FAILURE_REASONS),
  /**
   * The id this PC has or will have in `agent_hello` — the agent's random install id (a v4 UUID).
   * Unverified: nothing is signed at this point. Only for counting PCs rather than attempts, and for
   * seeing whether the same PC registered later.
   */
  device_id: deviceIdSchema,
  /** The agent's version, `CARGO_PKG_VERSION`: `0.5.0`, or with a pre-release tag `0.6.0-beta.1`. */
  version: z
    .string()
    .max(AGENT_START_FAILURE_LIMITS.versionChars)
    .regex(
      /^\d{1,5}\.\d{1,5}\.\d{1,5}(-[0-9A-Za-z.-]{1,24})?$/,
      "a version is major.minor.patch, optionally -prerelease",
    ),
  channel: z.enum(AGENT_BUILD_CHANNELS),
  /** The commit the build was stamped with, 7 to 40 lowercase hex digits; absent or null when the
   *  build was not stamped. */
  commit: z
    .string()
    .regex(/^[0-9a-f]{7,40}$/, "a commit is 7 to 40 lowercase hex digits")
    .nullish(),
  /**
   * Windows as numbers: `major.minor.build`, and `.revision` (the update build revision, UBR) when the
   * agent could read it — `10.0.19045.5371`, `10.0.26100`. Windows 11 is `10.0` with a build of
   * 22000 or more. No edition or product name: those are text the server would have to bound.
   */
  os: z
    .string()
    .max(AGENT_START_FAILURE_LIMITS.osChars)
    .regex(
      /^\d{1,3}\.\d{1,3}\.\d{1,6}(\.\d{1,6})?$/,
      "os is major.minor.build, optionally .revision",
    ),
  /**
   * A short code from the component that failed, when it gave one: for `webview2_missing` the
   * HRESULT of the WebView2 loader as `0x` and 8 hex digits (`0x80070002`), or a word of its own.
   * Letters, digits, `_`, `.` and `-` only; absent or null when there is none.
   */
  detail_code: z
    .string()
    .regex(
      new RegExp(`^[0-9A-Za-z_.-]{1,${AGENT_START_FAILURE_LIMITS.detailCodeChars}}$`),
      "a detail code is 1 to 32 of letters, digits, _ . -",
    )
    .nullish(),
});
export type AgentStartFailure = z.infer<typeof agentStartFailureSchema>;
