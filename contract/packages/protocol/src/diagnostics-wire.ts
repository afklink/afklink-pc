/**
 * Diagnostic reports: what a client needs at runtime to send one (protocol.md §1a).
 *
 * Deliberately in its own module with no imports, for the same reason as `channels.ts` and
 * `pairing-code.ts`: the Mini App needs the path, the limits and the level names as values, while
 * it consumes the schemas in `diagnostics.ts` as types only. A schema is built by a top-level zod
 * call, which a bundler cannot prove side-effect-free, so a constant living next to one drags the
 * whole validator into a bundle people open over mobile data. `diagnostics.ts` imports from here,
 * never the other way round. Keep this file free of imports.
 *
 * ## What a report is
 *
 * The person's own logs, sent to the developer because that person pressed «Отправить логи» on the
 * PC or «Отправить отчёт» in the viewer. The one exception is the agent's automatic report: after
 * a crash, an outage, a failed session or a hang it sends a short tail of its own log by itself,
 * held to the `agentAuto*` limits below and marked by `auto` in its metadata. The desktop app
 * sends a zip (the last days of its log files, the installer and updater logs, build info and the
 * in-memory flight recorder); the Mini App sends the lines of its own per-session ring buffer.
 * Neither ever carries typed text or screen content: those are not in any log to begin with, and
 * the device's private key (`identity.json`) never goes into a report.
 *
 * ## How the agent proves which PC it is
 *
 * The same Ed25519 key it answers the signaling challenge with (§2), over a canonical string that
 * names this exact request — see {@link agentRequestCanonical}. The server verifies the signature
 * from the headers alone, before it reads a byte of the body: the body's sha256 is declared in a
 * header and signed, and checked against what arrives once it has. So a request that is not from
 * the device costs the server one key lookup and one verify, never a 25 MB upload.
 */

/** `POST` target for the desktop app's zip. Signed by the device (headers below). */
export const DIAGNOSTICS_AGENT_PATH = "/api/diagnostics/agent";

/** `POST` target for the Mini App's report. Authenticated like every other REST call (`tma`). */
export const DIAGNOSTICS_VIEWER_PATH = "/api/diagnostics/viewer";

/**
 * Sizes and counts both ends hold to. The server refuses anything past them; a client that packs
 * to them never meets that refusal.
 *
 * Characters are Unicode code points, as zod and Rust's `chars()` count them. Bytes are bytes.
 */
export const DIAGNOSTICS_LIMITS = {
  /** The agent's zip, as sent. Past it: `413 payload_too_large`, before the body is read when
   *  `Content-Length` says so, the moment the count passes it otherwise. */
  agentBodyBytes: 25 * 1024 * 1024,
  /** The viewer's body as sent (gzip or not), and again after gunzip. */
  viewerBodyBytes: 3 * 1024 * 1024,
  /** UTF-8 bytes of all `msg` of one viewer report together: what the Mini App's ring may hold. */
  viewerLogBytes: 2 * 1024 * 1024,
  /** Lines in one viewer report. With JSON's framing of each (under 50 bytes) on top of the text
   *  budget above, a full report still fits the body limit with room for escaping. */
  viewerLines: 10_000,
  /** One viewer line's `msg`; the Mini App cuts a longer one and ends it with `…`. */
  lineChars: 2_000,
  /** «Что случилось?» — both clients. */
  commentChars: 500,
  /** The agent's `x-afklink-meta` header (base64url). Bun refuses a request whose headers pass
   *  16 KiB in all, and the proxies add theirs, so this is what fits with room to spare. The
   *  largest metadata the schema allows is tested to fit. */
  metaHeaderChars: 12 * 1024,
  /** Entries in the agent's `files` list, and the longest name. */
  files: 32,
  fileName: 96,
  /** Session ids an agent report may name (the live one first, then the most recent). */
  sessionIds: 8,
  /** How far the agent's clock may be from the server's, either way, in milliseconds. */
  signatureWindowMs: 5 * 60_000,
  /* An automatic report («автоотчёт», `auto` in the metadata): hard limits.
   * A manual report is held to none of these. */
  /** An automatic report's zip, as sent: a short tail of the log, not the days a manual report
   *  packs. Past it: `413 payload_too_large`, as for `agentBodyBytes`. */
  agentAutoBodyBytes: 200_000,
  /** Automatic reports one PC may send in any `agentAutoWindowMs`; the next one is refused and
   *  not stored. */
  agentAutoPerWindow: 3,
  agentAutoWindowMs: 24 * 60 * 60_000,
  /** Automatic reports from all PCs together in an hour: past it the server refuses the rest, so a
   *  bad release that crashes everywhere cannot fill the disk or the admins' chat. */
  agentAutoServicePerHour: 60,
  /** How long the agent's link to the server must have been down before coming back counts as
   *  `offline` (see `AGENT_AUTO_REPORT_TRIGGERS`). */
  agentAutoOutageMs: 60_000,
  /** The agent's own spacing between two automatic reports, whatever their triggers. */
  agentAutoMinGapMs: 15 * 60_000,
} as const;

/**
 * Why the agent sent a report by itself (`auto.trigger` in its metadata):
 *
 *   crash           the previous run ended in a crash or a panic (`AGENT_CRASH_EXITS`)
 *   offline         the agent's link to the server was down for `agentAutoOutageMs` or longer, and
 *                   came back
 *   session_failed  a session ended on the agent's side with an error reason from
 *                   `SESSION_END_REASONS`
 *   stall           the agent's stall watch logged an error: the main thread or the async runtime
 *                   hung for 30 s or longer
 */
export const AGENT_AUTO_REPORT_TRIGGERS = ["crash", "offline", "session_failed", "stall"] as const;
export type AgentAutoReportTrigger = (typeof AGENT_AUTO_REPORT_TRIGGERS)[number];

/** Levels of a viewer line, most severe first. The Mini App's console levels, `log` as `info`. */
export const VIEWER_LOG_LEVELS = ["error", "warn", "info", "debug"] as const;
export type ViewerLogLevel = (typeof VIEWER_LOG_LEVELS)[number];

/**
 * First line of the signed string. Names the scheme and its version, and keeps a report signature
 * from ever being mistaken for anything else the key signs: the signaling challenge is signed behind
 * its own prefix (`AGENT_CHALLENGE_PREFIX`, agent-ws.ts), which differs from this one, and the legacy
 * challenge form is 32 random bytes the server chose, while this string is longer than that and
 * starts with ASCII the server never sends as a nonce.
 */
export const AGENT_REQUEST_SCHEME = "AFKLINK-AGENT-REQUEST-V1";

/**
 * The headers of a signed agent request, lowercase (HTTP header names are case-insensitive; these
 * are how the server looks them up and how the fixtures spell them).
 *
 *   device          the device id, exactly as in `agent_hello` (the agent's config.json value)
 *   timestamp       the agent's clock, Unix milliseconds, decimal, no sign or leading zeros
 *   nonce           16 random bytes as 32 lowercase hex digits, fresh for every request
 *   content_sha256  sha256 of the body bytes as sent, 64 lowercase hex digits
 *   meta            the metadata JSON (UTF-8) as base64url without padding (RFC 4648 §5)
 *   signature       Ed25519 signature of {@link agentRequestCanonical}, standard base64 with
 *                   padding (88 characters) — the same encoding as `agent_auth.signature`
 */
export const AGENT_REQUEST_HEADERS = {
  device: "x-afklink-device",
  timestamp: "x-afklink-timestamp",
  nonce: "x-afklink-nonce",
  contentSha256: "x-afklink-content-sha256",
  meta: "x-afklink-meta",
  signature: "x-afklink-signature",
} as const;

/**
 * On `401 clock_skew` the server says what time it is, Unix milliseconds. The agent may retry once
 * with its timestamp moved by the difference (and a new nonce), and logs the skew it saw.
 */
export const SERVER_TIME_HEADER = "x-afklink-server-time";

/** The parts of a signed agent request, each exactly as it goes on the wire. */
export interface AgentRequestSigned {
  /** `POST`. */
  method: string;
  /** The path alone, no scheme, host or query: `/api/diagnostics/agent`. */
  path: string;
  device: string;
  timestamp: string;
  nonce: string;
  contentSha256: string;
  /** sha256 of the `x-afklink-meta` header's value — the base64url text, not the JSON it
   *  decodes to — as 64 lowercase hex digits. */
  metaSha256: string;
}

/**
 * The string the agent signs, byte for byte: eight lines joined by `\n` (0x0A), no trailing
 * newline, all ASCII.
 *
 * ```text
 * AFKLINK-AGENT-REQUEST-V1
 * POST
 * /api/diagnostics/agent
 * <device>
 * <timestamp>
 * <nonce>
 * <content_sha256>
 * <meta_sha256>
 * ```
 *
 * A part holding a line break would let one request's string pass for another's, so such a part is
 * refused here (the server has already refused it by the header's shape).
 */
export function agentRequestCanonical(p: AgentRequestSigned): string {
  const parts = [
    AGENT_REQUEST_SCHEME,
    p.method,
    p.path,
    p.device,
    p.timestamp,
    p.nonce,
    p.contentSha256,
    p.metaSha256,
  ];
  for (const part of parts) {
    if (part.includes("\n") || part.includes("\r")) {
      throw new Error("a signed part cannot hold a line break");
    }
  }
  return parts.join("\n");
}
