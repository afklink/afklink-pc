/**
 * Viewer device keys, milestone 1 (docs/design/viewer-device-keys-protocol.md rev 3 in the umbrella):
 * the constants, vocabularies and byte builders the agent, the server and the Mini App share. The
 * wire shapes are in `viewer-keys-wire.ts`; the test vectors in `vectors/viewer-keys/`, written by
 * `scripts/viewer-keys-vectors.ts` (`bun run vectors:viewer-keys`), never by `emit`.
 *
 * Imports nothing but `json-depth.ts`: the Mini App builds the bytes it signs with these functions
 * at runtime and takes the schemas as types only. Keep zod out so the validator stays out of a
 * bundle people load over mobile data.
 *
 * ## No crypto here
 *
 * Everything below is pure: it frames bytes (§1.1 `LP`), encodes and decodes base64url (§1.2), reads
 * the DTLS fingerprint out of an SDP (§3.3) and checks a P-256 SPKI's form (§1.3). Hashing, signing
 * and verifying belong to the caller (WebCrypto in the Mini App, `aws_lc_rs` on the PC): a builder
 * returns the message, and SHA-256 of it is `key_id`, `commit`, the SAS's `h`.
 *
 * ## The signer's rule (§1.1)
 *
 * A device key, a recovery key and an add-device secret sign (MAC) only bytes the client built itself
 * with the builders here, starting with `LP(domain)` — never bytes or a "challenge" that came from
 * outside. A new purpose is a new domain in `VIEWER_KEY_DOMAINS`.
 *
 * ## Logs (§1.4)
 *
 * Nothing here logs. A caller never logs a DTLS fingerprint, `nonce_pc`, a whole `proof`, a
 * signature, `attest.init_data`, the secret `s`, a MAC or a recovery key; a `key_id` only as its
 * first `KEY_ID_LOG_CHARS` characters (`keyIdForLog`).
 */

/* --- domains and prefixes (§1.1, §1.3) ------------------------------------------------------- */

/** The first `LP` field of every signed or hashed message (§1.1): one domain, one purpose. */
export const VIEWER_KEY_DOMAINS = {
  offer: "AFKLINK-OFFER-V1",
  keyReg: "AFKLINK-KEY-REG-V1",
  firstUse: "AFKLINK-FIRST-USE-V1",
  endorse: "AFKLINK-ENDORSE-V1",
  invite: "AFKLINK-INVITE-V1",
  /** `grant` (§7), with the PC's `grant_token`. */
  grant: "AFKLINK-GRANT-V2",
  recover: "AFKLINK-RECOVER-V1",
  addMac: "AFKLINK-ADD-MAC-V1",
  addCommit: "AFKLINK-ADD-COMMIT-V1",
  addSas: "AFKLINK-ADD-SAS-V1",
} as const;
export type ViewerKeyDomain = (typeof VIEWER_KEY_DOMAINS)[keyof typeof VIEWER_KEY_DOMAINS];

/** `key_id = SHA-256(KEY_ID_PREFIX || spki)` (§1.3): 22 bytes of ASCII with the trailing NUL, no `LP`. */
export const KEY_ID_PREFIX = "AFKLINK-VIEWER-KEY-V1\0";

/** The 26 bytes every P-256 SPKI starts with (§1.3), hex: then `04 || X(32) || Y(32)`. */
export const SPKI_P256_PREFIX_HEX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

/** Sizes of the binary values (§1.2), in bytes; on the wire `b64urlLength(bytes)` characters. */
export const VIEWER_KEY_BYTES = {
  /** `key_id`, and every fingerprint (`fp_viewer`). */
  keyId: 32,
  fingerprint: 32,
  /** `nonce_pc`, `endorse_id`, `grant_id`, `inv_id`, `grant_token`, the secret `s`, `nonce_n`, `nonce_o`. */
  nonce: 16,
  id: 16,
  /** `spki`, `rpk`. */
  spki: 91,
  /** An ECDSA P-256 signature as WebCrypto makes it: `r || s` (IEEE P1363), not DER. */
  signature: 64,
  /** HMAC-SHA-256 (`mac`) and SHA-256 (`commit`). */
  hmac: 32,
} as const;

/* --- constants (§12) ------------------------------------------------------------------------- */

/** `nonce_pc`: 16 bytes from the PC's CSPRNG (§2.2). */
export const NONCE_BYTES = 16;
/** Nonces per `session_nonces` batch. */
export const NONCE_BATCH = 4;
/** The PC sends a new batch this often while its socket lives. */
export const NONCE_ROTATE_MS = 60_000;
/** A refill asked by `session_request` (§2.2 (c)): at most once per this window, deferred, not lost. */
export const NONCE_REFILL_MIN_MS = 2_000;
/** The server hands out a batch's nonces only while the batch is at most this old (its clock). */
export const NONCE_SERVE_MS = 100_000;
/** A nonce is valid at most this long after its batch was issued, inclusive (the PC's clock). */
export const NONCE_TTL_MS = 180_000;
/** The PC's nonce book remembers batches this long, so an expired nonce is told from a foreign one. */
export const NONCE_BOOK_KEEP_MS = 360_000;
/** Batches the book holds at most; past it the oldest go (with a `warn`). */
export const NONCE_BOOK_MAX_BATCHES = 192;
/** An add-device rendezvous lives this long on the server (§6.1). */
export const ADD_TTL_MS = 600_000;
/**
 * The server keeps a closed rendezvous' reason for its account up to this long (§6.1): a
 * `device_add_resume` of that `add_id` meanwhile gets `device_add_closed {add_id, reason: <kept>}`
 * from any socket of the account (never `role_mismatch`), so a side that missed the close while its
 * socket was away still learns why; after it, `not_found`. A close pushed out earlier — by
 * `ADD_CLOSED_KEEP_MAX` newer closes of the account, or by the server's global bound on their volume —
 * answers `not_found` too (a client reads both as «the rendezvous ended»). That side's undelivered
 * steps are kept with the reason and go first, in order, then the close — and before them the
 * side's owed `device_add_joined` (the opener's socket was away at the join, §6.1 «Должное
 * отсутствующей стороне») — only to a resume that names that side from a socket that did not hold
 * the other side at the close (such a socket gets only the reason), and only once (a later resume
 * gets only the reason): O's `endorse` sent just before `done` still reaches N.
 */
export const ADD_CLOSED_KEEP_MS = 120_000;
/**
 * Kept closes (`ADD_CLOSED_KEEP_MS`) per account at most (§6.1): a new one forgets the account's
 * oldest kept close, whose resume then gets `not_found`. The server has its own global bound too.
 */
export const ADD_CLOSED_KEEP_MAX = 4;
/** Undelivered steps the server queues per side of a rendezvous. */
export const ADD_QUEUE = 8;
/**
 * A client that got no step for this long after its own last one shows «Начните заново» (§6.1) —
 * except N while the decision is the person's at O: after N's own `reveal` (§6.4) or `key` (§6.3),
 * while the person reads, types the six digits or presses «Подтвердить», N has no stall; only
 * `ADD_TTL_MS`, O's close or N's page going away ends the rendezvous then.
 */
export const ADD_STALL_MS = 60_000;
/**
 * `grant.issued_at - invite.issued_at` at most (§7): `INVITE_TTL_MS` (24 h) plus 1 h for two owner
 * devices' clocks; the difference may be negative down to -1 h.
 */
export const INVITE_GRANT_WINDOW_MS = 90_000_000;
/** The clock skew allowed between two of the owner's devices in an invite and its grant. */
export const INVITE_GRANT_SKEW_MS = 3_600_000;
/** The short code's digits (§6.4). */
export const SAS_DIGITS = 6;
/** Wrong SAS entries before the rendezvous closes (`sas_failed`). */
export const SAS_TRIES = 3;
/** Bases (`proof.admit`) in one proof at most. */
export const ADMIT_MAX = 4;
/** Active keys per person on one PC, all keys on one PC, revoked keys and spent ids (each list). */
export const KEYS_PER_PERSON = 16;
export const KEYS_MAX = 256;
export const REVOKED_MAX = 4096;
/*
 * Size caps and the verify rate below. Each number the spec states carries its section (§1.2 proof
 * 16 KB, depth 8, viewer_key 1 KB, init_data 4 KB; §6.1 msg 4 KB; §3.4 20 verifications per second);
 * the spec's KB is taken as 1024 bytes (KiB) and its bound as inclusive — these are contract-chosen readings.
 * `INVITE_SIG_MAX_BYTES` and `GRANT_MAX_BYTES` are contract-chosen bounds: the spec names none.
 */
/** `proof` at most, as compact JSON in UTF-8 (`JSON.stringify`; the agent: `serde_json::to_vec`). */
export const PROOF_MAX_BYTES = 16_384;
/** JSON nesting of a `proof` at most; the `proof` object itself is level 1 (`jsonDepth`). */
export const PROOF_MAX_DEPTH = 8;
/** `pair_request.viewer_key` (a `key_reg`) at most, compact JSON in UTF-8 (§1.2). */
export const VIEWER_KEY_MAX_BYTES = 1_024;
/** `attest.init_data` at most, UTF-8 bytes (§1.2). */
export const ATTEST_INIT_DATA_MAX_BYTES = 4_096;
/** A `device_add_send` / `device_add_msg` step at most, compact JSON in UTF-8 (§6.1). */
export const DEVICE_ADD_MSG_MAX_BYTES = 4_096;
/**
 * `invite_sig` and `grant` as the server stores and hands them on (REST, `pair_accepted`): contract-
 * chosen bounds, generous against the real sizes (≈ 300 and ≈ 500 bytes).
 */
export const INVITE_SIG_MAX_BYTES = 1_024;
export const GRANT_MAX_BYTES = 2_048;
/** Offers whose signatures the PC checks per second at most (§3.4, a token bucket); past it `busy`. */
export const VERIFY_RATE_PER_S = 20;
/** `proof.v`, `endorse.v`, `invite_sig.v`, `grant.v`. */
export const VIEWER_KEYS_VERSION = 1;
/** `viewer_ready.device_keys`: the server speaks the add-device rendezvous (§6.1). */
export const DEVICE_KEYS_SUPPORT = 1;
/** A `key_id` in a log: its first characters only (§1.4). */
export const KEY_ID_LOG_CHARS = 8;

/* --- vocabularies ------------------------------------------------------------------------------ */

/**
 * What a device says it is (§4, `key_reg.kind`): the Mini App in mobile Telegram, Telegram Desktop or
 * Telegram for macOS, the website. A claim for display only, never a decision.
 */
export const DEVICE_KINDS = ["telegram", "telegram_desktop", "browser"] as const;
export type DeviceKind = (typeof DEVICE_KINDS)[number];

/** `key_reg.platform` (§4). */
export const DEVICE_PLATFORMS = [
  "iphone",
  "ipad",
  "android",
  "mac",
  "windows",
  "linux",
  "unknown",
] as const;
export type DevicePlatform = (typeof DEVICE_PLATFORMS)[number];

/**
 * The form of `kind` and of `platform` (§4). A well-formed value off its list (a client newer than
 * the PC) is signed and stored as sent, and displayed as `unknown` (`displayDevice`).
 */
export const DEVICE_DESC_PATTERN = /^[a-z0-9_]{1,24}$/;

/** The bases a proof may carry (`proof.admit[].kind`); an unknown kind is skipped, never an error. */
export const KEY_ADMIT_KINDS = ["endorse", "grant", "recover", "first_use"] as const;
export type KeyAdmitKind = (typeof KEY_ADMIT_KINDS)[number];

/** What added a key (`ks.admit`, `summary.key_admit`): a base, or «Разрешить» at the PC. */
export const KEY_ADMITS = ["pair", ...KEY_ADMIT_KINDS] as const;
export type KeyAdmit = (typeof KEY_ADMITS)[number];

/** The PC's mode (`ks.mode`, `summary.key_mode`): watch only, or «Доверенные устройства» on. */
export const KEY_MODES = ["observe", "strict"] as const;
export type KeyMode = (typeof KEY_MODES)[number];

/**
 * The nine `session_end` reasons of device keys (§11), all in `SESSION_END_REASONS` (errors.ts); their
 * `ended_detail` lists are in `SESSION_END_DETAILS` (metrics.ts).
 */
export const KEY_END_REASONS = [
  "nonce_stale",
  "key_required",
  "key_unknown",
  "key_unconfirmed",
  "admit_refused",
  "key_revoked",
  "proof_invalid",
  "fingerprint_changed",
  "key_list_damaged",
] as const;
export type KeyEndReason = (typeof KEY_END_REASONS)[number];

/** `ks.verdict` (§3.7): the key is active and confirmed on this PC, or a reason (observe mode). */
export const KS_VERDICTS = ["signed", ...KEY_END_REASONS] as const;
export type KsVerdict = (typeof KS_VERDICTS)[number];

/** `summary.key_verdict` (§11.1): `ks`'s, and `unsigned` for an offer with no `proof`. */
export const KEY_VERDICTS = ["signed", "unsigned", ...KEY_END_REASONS] as const;
export type KeyVerdict = (typeof KEY_VERDICTS)[number];

/** `device_add_open.role` (§6.1): the device that is trusted already (`old`), or the new one. */
export const DEVICE_ADD_ROLES = ["old", "new"] as const;
export type DeviceAddRole = (typeof DEVICE_ADD_ROLES)[number];

/**
 * `device_add_open.mode` (§6.2): `secret` — the other device gets the rendezvous by its carrier
 * (QR or clipboard, `afkadd1.<add_id>.<s>`) and joins by `add_id`; `sas` — two computers without a
 * camera, the new one joins with no address (`device_add_join {}`) and the person compares six
 * digits (§6.4). `sas` only with `role: "old"`.
 */
export const DEVICE_ADD_MODES = ["secret", "sas"] as const;
export type DeviceAddMode = (typeof DEVICE_ADD_MODES)[number];

/** The steps a rendezvous carries (`msg.step`, §6.3, §6.4). */
export const DEVICE_ADD_STEPS = ["hello", "key", "endorse", "commit", "nonce", "reveal"] as const;
export type DeviceAddStep = (typeof DEVICE_ADD_STEPS)[number];

/**
 * Why a rendezvous closed (`device_add_close.reason`, `device_add_closed.reason`):
 *
 *   not_found      the server's answer to a `join {add_id}` of a rendezvous that is gone or taken
 *                  (§6.1), with that join's `req_id`; also its answer to a `send`/`resume` of an
 *                  `add_id` it does not have, which carries no `req_id`
 *   none_waiting   the server's answer to an address-less `join {req_id}` when no `role: "old"`,
 *                  `mode: "sas"` rendezvous of the account waits for a joiner (§6.1): with that
 *                  join's `req_id`, without an `add_id`
 *   busy           the server's answer to a `device_add_open` it refuses for its own bound on live
 *                  rendezvous (§6.1); no rendezvous existed, so no `add_id`, only the open's
 *                  `req_id`; the client says try later and never retries on its own
 *   role_mismatch  a resume names a side different from the server's (§6.1)
 *   mac_failed     the new device's `mac` did not check (§6.3)
 *   commit_failed  the revealed `nonce_n` does not match the commit (§6.4)
 *   sas_failed     `SAS_TRIES` wrong entries (§6.4)
 *   protocol       a step out of order or repeated (§6.4)
 *   expired        `ADD_TTL_MS` passed
 *   cancelled      the person closed the screen, or the page reloaded mid-way, or a third
 *                  `device_add_open` of the account evicted this, the oldest open one (§6.1)
 *   done           the old device sent `endorse` and closes (§6.3); the server delivers a queued
 *                  `endorse` before the close (also on a resume after it). N succeeds only on an
 *                  `endorse` it received and accepted: `done` without one ends with no result
 *
 * The full list is the spec's (§12). On the wire a reason is a patterned code
 * (`DEVICE_ADD_REASON_PATTERN`), so a newer one costs nothing.
 */
export const DEVICE_ADD_CLOSE_REASONS = [
  "not_found",
  "none_waiting",
  "busy",
  "role_mismatch",
  "mac_failed",
  "commit_failed",
  "sas_failed",
  "protocol",
  "expired",
  "cancelled",
  "done",
] as const;
export type DeviceAddCloseReason = (typeof DEVICE_ADD_CLOSE_REASONS)[number];
export const DEVICE_ADD_REASON_PATTERN = /^[a-z_]{1,32}$/;

/** The secret's carrier (§6.2): `afkadd1.<add_id>.<s>`, never through the server. */
export const ADD_CARRIER_PREFIX = "afkadd1";

/** The Mini App's launch parameter for recovery's attestation (§8.2): `k_<key_id>`. */
export const RECOVER_START_PARAM_PREFIX = "k_";

/* --- the person's own devices in the Mini App, a server copy for display (§11a) -------------- */

/*
 * The honesty rule (§11a): the PC's list (§10) is the only one that decides admission. The server's
 * copy below is a hint for the interface and may be wrong (the server may be the attacker; a PC may
 * have dropped a key with no session since). Neither the PC, the server nor the Mini App allows or
 * refuses anything by it: admission never reads it, and no basis (§5–§9) depends on it. The only
 * thing it may choose is which button a PC card shows — confirm this device instead of connect:
 * a new device that never spoke to a strict PC learns the PC is strict only from
 * other devices' rows. At worst a hostile or stale copy shows a false "strict", sending the person to
 * the confirm flow instead of connect; that screen keeps a quiet link to try connecting anyway (the
 * same connect to that PC), shown only when the copy, not the PC's own answer, chose the button.
 * So the worst is one refused attempt (if the PC really is strict), never a dead
 * end. A false "not strict" costs one
 * refusal, after which the end card offers the confirm. The confirm flow adds no risk beyond §6.4.
 * Every row says when the server last saw that PC's answer. For the client's own row its `ks`
 * (§3.7) knows better, and the client shows that.
 */

/** `GET` lists the calling account's own device keys (`deviceKeysResponseSchema`), nobody else's. */
export const DEVICE_KEYS_PATH = "/api/device-keys";
/** Device keys the server keeps per account; past it the longest unused one goes (§11a). */
export const DEVICE_KEYS_PER_ACCOUNT = 32;
/** A key unused this long (180 days) is dropped from the server's copy (§11a). */
export const DEVICE_KEY_RETENTION_MS = 15_552_000_000;

/** What a PC last answered about a key, for display only (§11a). */
export const DEVICE_KEY_PC_STATES = ["trusted", "unconfirmed", "refused", "unknown"] as const;
export type DeviceKeyPcState = (typeof DEVICE_KEY_PC_STATES)[number];

/** Verdicts that say the PC refused this key (§11a); `proof_invalid` except its detail `busy`. */
const PC_REFUSED_VERDICTS: readonly string[] = [
  "key_revoked",
  "key_unknown",
  "admit_refused",
  "proof_invalid",
];

/**
 * A PC's last answer about a key — the agent's `summary.key_verdict`/`key_detail` (§11.1) or a §11
 * reason of the agent's `session_end` — as the state the Mini App shows (§11a), for display only:
 *
 *   trusted      key_verdict signed
 *   unconfirmed  key_unconfirmed
 *   refused      key_revoked, key_unknown, admit_refused, proof_invalid (except detail busy)
 *   unknown      no answer yet (null/undefined), or one that says nothing about the key itself:
 *                unsigned, nonce_stale, key_required, proof_invalid:busy, key_list_damaged,
 *                fingerprint_changed, and any verdict this build does not know
 *
 * The verdict and its detail come separately, as `summary.key_verdict` and `key_detail` (or a
 * `session_end` reason and its bare `ended_detail`); a combined `"reason:detail"` string passed as the
 * verdict is not one this table knows, and maps to `unknown`.
 *
 * Never an input to admission (the honesty rule above).
 */
export function pcStateOf(
  keyVerdict: string | null | undefined,
  keyDetail?: string | null,
): DeviceKeyPcState {
  if (keyVerdict === "signed") return "trusted";
  if (keyVerdict === "key_unconfirmed") return "unconfirmed";
  if (keyVerdict === "proof_invalid" && keyDetail === "busy") return "unknown";
  if (keyVerdict != null && PC_REFUSED_VERDICTS.includes(keyVerdict)) return "refused";
  return "unknown";
}

/* --- base64url, strict (§1.2) ---------------------------------------------------------------- */

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Characters of `bytes` bytes as base64url without padding. */
export function b64urlLength(bytes: number): number {
  return Math.ceil((bytes * 4) / 3);
}

const patterns = new Map<number, RegExp>();

/**
 * The exact form of `bytes` bytes as strict base64url: the alphabet, no `=`, the exact length, and a
 * last character whose unused low bits are zero (so re-encoding gives the same string).
 */
export function b64urlPattern(bytes: number): RegExp {
  const known = patterns.get(bytes);
  if (known) return known;
  const len = b64urlLength(bytes);
  const rem = bytes % 3;
  let pattern: RegExp;
  if (rem === 0) {
    pattern = new RegExp(`^[A-Za-z0-9_-]{${len}}$`);
  } else {
    // 1 byte left: the last character carries 2 bits (index % 16 == 0); 2 bytes: 4 bits (% 4).
    const step = rem === 1 ? 16 : 4;
    const tail = [...B64URL_ALPHABET].filter((_, i) => i % step === 0).join("");
    pattern = new RegExp(`^[A-Za-z0-9_-]{${len - 1}}[${tail}]$`);
  }
  patterns.set(bytes, pattern);
  return pattern;
}

/** base64url without padding (RFC 4648 §5). */
export function b64urlEncode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  const at = (n: number) => B64URL_ALPHABET.charAt(n & 63);
  for (; i + 2 < bytes.length; i += 3) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += at(n >> 18) + at(n >> 12) + at(n >> 6) + at(n);
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] ?? 0) << 16;
    out += at(n >> 18) + at(n >> 12);
  } else if (rest === 2) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8);
    out += at(n >> 18) + at(n >> 12) + at(n >> 6);
  }
  return out;
}

/**
 * Strict base64url of exactly `bytes` bytes (§1.2), or null: anything else is not the field.
 * Allocating byte helpers return ArrayBuffer-backed views, usable directly by DOM WebCrypto.
 */
export function b64urlDecodeStrict(value: unknown, bytes: number): Uint8Array<ArrayBuffer> | null {
  if (typeof value !== "string" || !b64urlPattern(bytes).test(value)) return null;
  const out = new Uint8Array(bytes);
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const ch of value) {
    acc = ((acc << 6) | B64URL_ALPHABET.indexOf(ch)) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

/* --- LP framing (§1.1) ------------------------------------------------------------------------ */

/** A field of a signed message: raw bytes, or a string taken as its UTF-8 bytes as on the wire. */
export type LpField = Uint8Array | string;

const utf8 = (s: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(s);

/**
 * `LP(a) || LP(b) || …` (§1.1): each field as a u32 big-endian length, then its bytes; no separator,
 * no tail. An empty field (an absent or null value) is `LP("")` = `00000000`, never skipped.
 *
 * Framing only, not a message to sign. Signer rule (§1.1): a device key, the recovery key and the
 * secret `s` sign (MAC) only the output of the typed builders below (`offerMessage`, `keyRegMessage`,
 * …), each starting with its own `LP(domain)` — never bytes put together from fields received from
 * outside, and never this function's output called directly. Exported for the builders' tests and
 * the vector generator.
 */
export function lp(...fields: readonly LpField[]): Uint8Array<ArrayBuffer> {
  const parts = fields.map((f) => (typeof f === "string" ? utf8(f) : f));
  const out = new Uint8Array(parts.reduce((n, p) => n + 4 + p.length, 0));
  const view = new DataView(out.buffer);
  let at = 0;
  for (const p of parts) {
    view.setUint32(at, p.length, false);
    out.set(p, at + 4);
    at += 4 + p.length;
  }
  return out;
}

/** A u64 big-endian of a whole number of ms (`issued_at`), 8 bytes, for inside `LP`. */
export function u64be(n: number): Uint8Array<ArrayBuffer> {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError("expected a whole number ≥ 0");
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}

/** A Telegram user id as signed (§1.1): decimal ASCII, no sign, no leading zeros, 1…2⁵³−1. */
export function decimalId(n: number): string {
  if (!Number.isSafeInteger(n) || n < 1) throw new RangeError("expected an id in 1..2^53-1");
  return String(n);
}

function exact(bytes: Uint8Array, length: number, what: string): Uint8Array {
  if (bytes.length !== length) throw new RangeError(`${what}: expected ${length} bytes`);
  return bytes;
}

/* --- the messages (§3.1, §4, §6, §7, §8.3, §9) -------------------------------------------------- */

/**
 * `KEY_ID_PREFIX || spki`, the input of `key_id = SHA-256(…)` (§1.3). The SPKI must pass
 * `checkP256Spki` first.
 */
export function keyIdMessage(spki: Uint8Array): Uint8Array<ArrayBuffer> {
  const prefix = utf8(KEY_ID_PREFIX);
  const out = new Uint8Array(prefix.length + spki.length);
  out.set(prefix, 0);
  out.set(exact(spki, VIEWER_KEY_BYTES.spki, "spki"), prefix.length);
  return out;
}

/** `offer_proof` (§3.1): signed by the device key. */
export function offerMessage(f: {
  session_id: string;
  device_id: string;
  key_id: Uint8Array;
  nonce_pc: Uint8Array;
  fp_viewer: Uint8Array;
}): Uint8Array<ArrayBuffer> {
  return lp(
    VIEWER_KEY_DOMAINS.offer,
    f.session_id,
    f.device_id,
    exact(f.key_id, 32, "key_id"),
    exact(f.nonce_pc, 16, "nonce_pc"),
    exact(f.fp_viewer, 32, "fp_viewer"),
  );
}

/**
 * `key_reg` (§4): signed by the device key. `kind` and `platform` exactly as sent (their form is the
 * verifier's check, `DEVICE_DESC_PATTERN`); no `rpk` is `LP("")`.
 */
export function keyRegMessage(f: {
  key_id: Uint8Array;
  kind: string;
  platform: string;
  rpk?: Uint8Array | undefined;
}): Uint8Array<ArrayBuffer> {
  return lp(
    VIEWER_KEY_DOMAINS.keyReg,
    exact(f.key_id, 32, "key_id"),
    f.kind,
    f.platform,
    f.rpk === undefined ? new Uint8Array(0) : exact(f.rpk, 91, "rpk"),
  );
}

/** `endorse` (§6.5): signed by the old device's key (`by`). */
export function endorseMessage(f: {
  key_id: Uint8Array;
  by: Uint8Array;
  endorse_id: Uint8Array;
  issued_at: number;
}): Uint8Array<ArrayBuffer> {
  return lp(
    VIEWER_KEY_DOMAINS.endorse,
    exact(f.key_id, 32, "key_id"),
    exact(f.by, 32, "by"),
    exact(f.endorse_id, 16, "endorse_id"),
    u64be(f.issued_at),
  );
}

/** `invite_sig` (§7 p. 1): signed by the owner's device key when «Пригласить» is pressed. */
export function inviteMessage(f: {
  device_id: string;
  inv_id: Uint8Array;
  issued_at: number;
  by: Uint8Array;
}): Uint8Array<ArrayBuffer> {
  return lp(
    VIEWER_KEY_DOMAINS.invite,
    f.device_id,
    exact(f.inv_id, 16, "inv_id"),
    u64be(f.issued_at),
    exact(f.by, 32, "by"),
  );
}

/**
 * `grant` (§7): signed by the owner's device key, domain `AFKLINK-GRANT-V2`. `name` and `username`
 * null are `LP("")`. The role is always `guest` (no parameter: a client cannot sign a grant for
 * another role). `inv_id` null — a grant with no signed invite, accepted unconfirmed in observe mode
 * only — is `LP("")`.
 *
 * `grant_token` is the PC's grant token from the `add_guest` card: its 16 raw bytes, or empty when
 * the card had none (the JSON field is then `""`, framed `LP("")`). It sits between `grant_id` and
 * `issued_at`; the PC accepts the grant only while the token is still its current one
 * (`grant_stale` otherwise).
 */
export function grantMessage(f: {
  device_id: string;
  key_id: Uint8Array;
  telegram_user_id: number;
  name: string | null;
  username: string | null;
  inv_id: Uint8Array | null;
  grant_id: Uint8Array;
  grant_token: Uint8Array;
  issued_at: number;
  by: Uint8Array;
}): Uint8Array<ArrayBuffer> {
  return lp(
    VIEWER_KEY_DOMAINS.grant,
    f.device_id,
    exact(f.key_id, 32, "key_id"),
    decimalId(f.telegram_user_id),
    f.name ?? "",
    f.username ?? "",
    "guest",
    f.inv_id === null ? new Uint8Array(0) : exact(f.inv_id, 16, "inv_id"),
    exact(f.grant_id, 16, "grant_id"),
    f.grant_token.length === 0 ? f.grant_token : exact(f.grant_token, 16, "grant_token"),
    u64be(f.issued_at),
    exact(f.by, 32, "by"),
  );
}

/** `first_use` (§9): signed by the key being added. */
export function firstUseMessage(f: {
  device_id: string;
  key_id: Uint8Array;
  uid: number;
}): Uint8Array<ArrayBuffer> {
  return lp(
    VIEWER_KEY_DOMAINS.firstUse,
    f.device_id,
    exact(f.key_id, 32, "key_id"),
    decimalId(f.uid),
  );
}

/** Recovery (§8.3): signed by the recovery key `rk`. */
export function recoverMessage(f: {
  device_id: string;
  session_id: string;
  key_id: Uint8Array;
  nonce_pc: Uint8Array;
}): Uint8Array<ArrayBuffer> {
  return lp(
    VIEWER_KEY_DOMAINS.recover,
    f.device_id,
    f.session_id,
    exact(f.key_id, 32, "key_id"),
    exact(f.nonce_pc, 16, "nonce_pc"),
  );
}

/** The new device's `mac` input (§6.3): `mac = HMAC-SHA-256(s, this)`. */
export function addMacMessage(f: { add_id: string; key_id: Uint8Array }): Uint8Array<ArrayBuffer> {
  return lp(VIEWER_KEY_DOMAINS.addMac, f.add_id, exact(f.key_id, 32, "key_id"));
}

/** The commitment's input (§6.4 p. 2): `commit = SHA-256(this)`. */
export function addCommitMessage(f: {
  add_id: string;
  key_id: Uint8Array;
  nonce_n: Uint8Array;
}): Uint8Array<ArrayBuffer> {
  return lp(
    VIEWER_KEY_DOMAINS.addCommit,
    f.add_id,
    exact(f.key_id, 32, "key_id"),
    exact(f.nonce_n, 16, "nonce_n"),
  );
}

/** The short code's input (§6.4 p. 5): `h = SHA-256(this)`, then `sas(h)`. */
export function addSasMessage(f: {
  add_id: string;
  key_id: Uint8Array;
  nonce_n: Uint8Array;
  nonce_o: Uint8Array;
}): Uint8Array<ArrayBuffer> {
  return lp(
    VIEWER_KEY_DOMAINS.addSas,
    f.add_id,
    exact(f.key_id, 32, "key_id"),
    exact(f.nonce_n, 16, "nonce_n"),
    exact(f.nonce_o, 16, "nonce_o"),
  );
}

/** The six digits (§6.4 p. 5): the first 8 bytes of `h` as a u64 BE, mod 10⁶, zero-padded. */
export function sas(h: Uint8Array): string {
  exact(h, 32, "h");
  const v = new DataView(h.buffer, h.byteOffset, 8).getBigUint64(0, false);
  return (v % 10n ** BigInt(SAS_DIGITS)).toString().padStart(SAS_DIGITS, "0");
}

/* --- SPKI (§1.3) -------------------------------------------------------------------------------- */

const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

/** Why an SPKI is not a canonical P-256 public key, in the order checked. */
export type SpkiProblem = "length" | "prefix" | "point_format" | "coord_range" | "not_on_curve";

function hexOf(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/**
 * Whether `spki` is what §1.3 accepts: 91 bytes, the exact prefix, `04`, X < p and Y < p, the point
 * on P-256 (which also rules out infinity). Null when it is; else the first failed check.
 */
export function checkP256Spki(spki: Uint8Array): SpkiProblem | null {
  if (spki.length !== VIEWER_KEY_BYTES.spki) return "length";
  if (hexOf(spki.subarray(0, 26)) !== SPKI_P256_PREFIX_HEX) return "prefix";
  if (spki[26] !== 0x04) return "point_format";
  const x = BigInt(`0x${hexOf(spki.subarray(27, 59))}`);
  const y = BigInt(`0x${hexOf(spki.subarray(59, 91))}`);
  if (x >= P256_P || y >= P256_P) return "coord_range";
  const mod = (v: bigint) => ((v % P256_P) + P256_P) % P256_P;
  if (mod(y * y) !== mod(x * x * x - 3n * x + P256_B)) return "not_on_curve";
  return null;
}

/* --- the DTLS fingerprint in an SDP (§3.3) ------------------------------------------------------ */

const FINGERPRINT_ATTR = "a=fingerprint:";
const FINGERPRINT_VALUE = /^sha-256 ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){31})$/;
/**
 * A CR not followed by LF. str0m parses an SDP up to the first line it cannot parse and silently
 * drops the rest (`vendor/str0m/src/sdp/data.rs:30-34`); on a bare CR we and str0m would disagree on
 * where lines end. Without one, every line str0m reads a fingerprint from is one of our candidates.
 */
const BARE_CR = /\r(?!\n)/;
/** A line a lenient reader would take for a fingerprint: any case, after leading spaces or tabs. */
const FINGERPRINT_CANDIDATE = /^[ \t]*a=fingerprint:/i;

/**
 * `fp_viewer` from an SDP (§3.3). No bare CR anywhere (a CR not followed by LF). Lines split on
 * `\r\n` or `\n`; the candidates are every line that, after leading spaces and tabs, starts with
 * `a=fingerprint:` in any case — at session level and in every `m=`. Each candidate must start with
 * exactly the lowercase `a=fingerprint:` at its first character (str0m reads the attribute name case
 * sensitively and would not use `a=Fingerprint:` or ` a=fingerprint:`: such a line is refused, not
 * skipped), then be exactly `sha-256 <32 hex pairs joined by ':'>` — the algorithm lowercase and
 * not empty (`a=fingerprint: sha-256 …` is a form fault), one space, hex in any case, nothing more.
 * At least one candidate, all the same value: those 32 bytes. Anything else is null
 * (`proof_invalid:fp_bad`).
 *
 * Why no bare CR: str0m parses an SDP up to the first line it cannot parse and silently drops the
 * rest (`vendor/str0m/src/sdp/data.rs:30-34`), so on a bare CR we and str0m would disagree on line
 * boundaries; without one, every line str0m reads a fingerprint from is one of our candidates. The
 * guarantee: an accepted `fp_viewer` is the only fingerprint str0m can read from that SDP. Not the
 * converse — an SDP str0m reads none from (a BOM at its start, a line with NUL before the
 * fingerprint) may pass, and DTLS then fails closed. Only spaces and tabs are skipped before `a=`
 * (a BOM there makes no candidate); U+2028, NEL and the like do not end a line.
 */
export function sdpFingerprint(sdp: string): Uint8Array<ArrayBuffer> | null {
  if (BARE_CR.test(sdp)) return null;
  let found: string | null = null;
  for (const line of sdp.split(/\r?\n/)) {
    if (!FINGERPRINT_CANDIDATE.test(line)) continue;
    if (!line.startsWith(FINGERPRINT_ATTR)) return null;
    const m = FINGERPRINT_VALUE.exec(line.slice(FINGERPRINT_ATTR.length));
    const hex = m?.[1]?.replaceAll(":", "").toLowerCase();
    if (hex === undefined) return null;
    if (found !== null && found !== hex) return null;
    found = hex;
  }
  if (found === null) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(found.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/* --- smaller helpers ---------------------------------------------------------------------------- */

/** How the PC's window names a device (§4): a value off its list shows as `unknown`. */
export function displayDevice(
  kind: string,
  platform: string,
): { kind: DeviceKind | "unknown"; platform: DevicePlatform } {
  const k = (DEVICE_KINDS as readonly string[]).includes(kind) ? (kind as DeviceKind) : "unknown";
  const p = (DEVICE_PLATFORMS as readonly string[]).includes(platform)
    ? (platform as DevicePlatform)
    : "unknown";
  return { kind: k, platform: p };
}

/** A `key_id` as a log may name it (§1.4): `kid=AbCd1234`. */
export function keyIdForLog(keyId: string): string {
  return keyId.slice(0, KEY_ID_LOG_CHARS);
}

/** The launch parameter of recovery's reopen (§8.2): `k_<key_id>`, 45 characters. */
export function recoverStartParam(keyId: string): string {
  return RECOVER_START_PARAM_PREFIX + keyId;
}

/**
 * `attest.init_data` (§8.2): the raw `Telegram.WebApp.initData` without one `hash=<value>` pair (the
 * first) and one adjacent `&`; every other byte as received. Exactly one: a second `hash` pair stays,
 * so the verifier refuses the result (`attest_has_hash`) instead of seeing a cleaned string.
 */
export function stripInitDataHash(raw: string): string {
  const pairs = raw.split("&");
  const at = pairs.findIndex((pair) => pair.startsWith("hash="));
  if (at >= 0) pairs.splice(at, 1);
  return pairs.join("&");
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The secret's carrier (§6.2): `afkadd1.<add_id>.<s>`. */
export function formatAddCarrier(addId: string, secret: Uint8Array): string {
  return `${ADD_CARRIER_PREFIX}.${addId}.${b64urlEncode(exact(secret, 16, "s"))}`;
}

/** The carrier's parts, or null when it is not one exactly. */
export function parseAddCarrier(
  text: string,
): { add_id: string; s: Uint8Array<ArrayBuffer> } | null {
  const parts = text.split(".");
  if (parts.length !== 3 || parts[0] !== ADD_CARRIER_PREFIX) return null;
  const addId = parts[1] ?? "";
  const s = b64urlDecodeStrict(parts[2], 16);
  if (!UUID_PATTERN.test(addId) || s === null) return null;
  return { add_id: addId, s };
}

/** Bytes of `value` as compact JSON in UTF-8 (`JSON.stringify`): the size the limits count. */
export function jsonByteLength(value: unknown): number {
  return utf8(JSON.stringify(value) ?? "").length;
}

export { jsonDepth } from "./json-depth";
