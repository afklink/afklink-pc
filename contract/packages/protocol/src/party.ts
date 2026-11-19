/**
 * «Пати» (docs/design/party-protocol.md, edition 6, in the umbrella; the model is
 * docs/design/party-model.md): the domains, limits, closed lists, paths and byte builders the agent,
 * the server and the Mini App share. The wire shapes are in `party-wire.ts` and, for the admit item,
 * in `viewer-keys-wire.ts`; the signature checks in `party-verify.ts`; the vectors in
 * `vectors/party/`, written by `scripts/party-vectors.ts` (`bun run vectors:party`).
 *
 * Import-free but for `viewer-keys.ts` (itself import-free): the Mini App builds the bytes it signs
 * with these functions at runtime and takes the schemas as types only.
 *
 * ## One thought
 *
 * The leader hands out guest grants on the owner's behalf. A grant to a member (`party` in
 * `proof.admit`) is the keys' `grant` V2 field for field, with three differences: its domain, the
 * party's id where the invite's id stood, and the leader's key as `by`. The PC accepts it only while it
 * holds a delegation of that party naming that leader, which the owner's device signed («ПК в пати»,
 * `party_join`). Freshness of both is the PC's grant token; no clock is compared anywhere.
 *
 * ## The signer's rule (keys §1.1)
 *
 * A device key signs only bytes its client built with the builders here, starting with
 * `LP(domain)`; the owner signs a join only on his press of «Добавить» or «Подтвердить».
 */
import { decimalId, GRANT_MAX_BYTES, lp, u64be } from "./viewer-keys";

/* --- domains (§2.1) ---------------------------------------------------------------------------- */

/** The first `LP` field of each party message: never valid as any other domain's signature. */
export const PARTY_DOMAINS = {
  /** «ПК в пати» (§2.2), signed by the PC owner's device key. */
  join: "AFKLINK-PARTY-JOIN-V1",
  /** A grant to a member (§2.3), signed by the leader's device key. */
  grant: "AFKLINK-PARTY-GRANT-V1",
} as const;
export type PartyDomain = (typeof PARTY_DOMAINS)[keyof typeof PARTY_DOMAINS];

/* --- limits (§2.1, §3.1, §7.2, §8.6) ----------------------------------------------------------- */

/** `party_id`: 16 random bytes from the leader client's CSPRNG on «Создать пати», 22 characters. */
export const PARTY_ID_BYTES = 16;
/** A party's name: 1 to 64 characters (Unicode code points), no control characters (`\p{Cc}`). */
export const PARTY_NAME_MAX = 64;
/**
 * `leader.name`, `leader.username` and a party grant's `name`, `username` at most, in Unicode code
 * points: the released `grant`'s bounds in the unit its schema counts (`grantSchema`, zod's `max`).
 */
export const PARTY_LEADER_NAME_MAX = 128;
export const PARTY_LEADER_USERNAME_MAX = 64;
/** A join or a party grant at most, compact JSON in UTF-8: the PC checks it (`GRANT_MAX_BYTES`). */
export const PARTY_STATEMENT_MAX_BYTES = GRANT_MAX_BYTES;
/** `join.v` and the party grant's `v`. */
export const PARTY_STATEMENT_VERSION = 1;
/** People in one party at most. */
export const PARTY_PEOPLE_MAX = 12;
/** PCs in one party at most. */
export const PARTY_PCS_MAX = 24;
/** Delegations one PC keeps at most: the file's bound; past it a new party's join is `limit`. */
export const PARTY_DELEGATIONS_MAX = 256;
/** The leader's admission («приём»): a server record for 24 h, with no number of seats. */
export const PARTY_ADMISSION_TTL_MS = 86_400_000;
/** Grants in one upload (`POST …/grants`) at most, contract-chosen: a client sends more in batches. */
export const PARTY_GRANTS_PER_UPLOAD = 256;

/* --- closed lists (§4.1, §9) ------------------------------------------------------------------- */

/** `party_ack.op`: which statement the PC answers. */
export const PARTY_ACK_OPS = ["join", "leave"] as const;
export type PartyAckOp = (typeof PARTY_ACK_OPS)[number];

/**
 * `party_ack.result` (§4.2), the first failed check:
 *
 *   ok         the delegation was written or replaced (a join), or the party left or was never there
 *              (a leave)
 *   malformed  the form (§2), the size, a non-canonical `leader.spki`
 *   device     `device_id` is not this PC's
 *   signer     `by` is not an active owner key of this PC (in strict mode: or it is unconfirmed)
 *   bad_sig    the signature under `by`'s SPKI did not check
 *   stale      `grant_token` is not the PC's current one
 *   limit      a new party past `PARTY_DELEGATIONS_MAX`
 *   busy       the PC's signature bucket was empty (keys §3.4): the server repeats
 *   damaged    the PC's key list cannot be read: the server repeats
 *
 * A leave has no signature: it answers `ok`, `malformed`, `busy` or `damaged`.
 */
export const PARTY_ACK_RESULTS = [
  "ok",
  "malformed",
  "device",
  "signer",
  "bad_sig",
  "stale",
  "limit",
  "busy",
  "damaged",
] as const;
export type PartyAckResult = (typeof PARTY_ACK_RESULTS)[number];

/** `connect_busy.holder`: whose session holds the PC. */
export const CONNECT_BUSY_HOLDERS = ["owner", "guest"] as const;
export type ConnectBusyHolder = (typeof CONNECT_BUSY_HOLDERS)[number];

/** `party_requests.kind` on the leader's card: a new person, or a member's new device. */
export const PARTY_REQUEST_KINDS = ["new", "new_device"] as const;
export type PartyRequestKind = (typeof PARTY_REQUEST_KINDS)[number];

/**
 * What «Вступить» (`POST /api/parties/join`) and the look before it (`POST /api/parties/join/peek`)
 * answer the account asking:
 *
 *   open       peek only: the admission is open and this account may ask; «Вступить» never answers it
 *   waiting    the request went to the leader (or was there already)
 *   member     this account is in the party already: nothing asked
 *   declined   the leader declined this account's request
 *   full       the party has `PARTY_PEOPLE_MAX` people
 *   closed     the admission is closed or past its 24 h
 *   not_found  no admission has this token
 *
 * Two lists, so neither the type nor the emitted schema of «Вступить» can say `open`:
 * `PARTY_ENTER_VERDICTS` (all but `open`) and `PARTY_PEEK_VERDICTS` (`open` and those).
 */
export const PARTY_ENTER_VERDICTS = [
  "waiting",
  "member",
  "declined",
  "full",
  "closed",
  "not_found",
] as const;
export type PartyEnterVerdict = (typeof PARTY_ENTER_VERDICTS)[number];
export const PARTY_PEEK_VERDICTS = ["open", ...PARTY_ENTER_VERDICTS] as const;
export type PartyPeekVerdict = (typeof PARTY_PEEK_VERDICTS)[number];

/** The leader's answer to a request (`POST …/requests/<rid>`). */
export const PARTY_REQUEST_ANSWERS = ["accept", "decline"] as const;
export type PartyRequestAnswer = (typeof PARTY_REQUEST_ANSWERS)[number];

/* --- REST paths (§8.4) -------------------------------------------------------------------------- */

/** `POST` «Создать пати» (`PartyCreateRequest`), `GET` the account's parties (`PartiesResponse`). */
export const PARTIES_PATH = "/api/parties";
/**
 * The member's side of the admission link, the token in the body, never in the path (the web server
 * logs every address, as for invites): `enter` — `POST {token, viewer_key, viewer_key_uid}`
 * «Вступить» (`PartyEnterResponse`); `peek` — `POST {token}`, the party before «Вступить»
 * (`PartyPeekResponse`), which changes nothing.
 */
export const PARTY_ENTER_PATHS = {
  enter: "/api/parties/join",
  peek: "/api/parties/join/peek",
} as const;

/** `GET` one party (`PartyView`); the base of every route below. */
export function partyPath(partyId: string): string {
  return `${PARTIES_PATH}/${encodeURIComponent(partyId)}`;
}

/**
 * The routes under one party. `admission`: `POST` opens the admission (`PartyAdmissionResponse`),
 * `DELETE` closes it. `admissionShare`: `POST {token}` the admission's card for `shareMessage`
 * (`PartyAdmissionShareResponse`), asked again on every tap. `requests`: `POST` a member's new device. `request(rid)`: `POST` the leader's
 * answer (`PartyRequestAnswerResponse`).
 * `grants`: `POST` the leader's grants. `pcs`: `POST` add a PC with its join. `pcJoin(id)`: `POST` a
 * new join for a PC already in the party. `pc(id)`: `DELETE` the PC leaves. `member(uid)`: `DELETE`
 * remove or leave. `leader`: `POST` name a new leader. `roster`: `POST` «Подтвердить состав».
 */
export function partyPaths(partyId: string) {
  const base = partyPath(partyId);
  const enc = encodeURIComponent;
  return {
    admission: `${base}/admission`,
    admissionShare: `${base}/admission/share`,
    requests: `${base}/requests`,
    request: (requestId: string) => `${base}/requests/${enc(requestId)}`,
    grants: `${base}/grants`,
    pcs: `${base}/pcs`,
    pc: (deviceId: string) => `${base}/pcs/${enc(deviceId)}`,
    pcJoin: (deviceId: string) => `${base}/pcs/${enc(deviceId)}/join`,
    member: (telegramUserId: number) => `${base}/members/${enc(String(telegramUserId))}`,
    leader: `${base}/leader`,
    roster: `${base}/roster`,
  } as const;
}

/* --- the party's name (§2.1) -------------------------------------------------------------------- */

const CONTROL = /\p{Cc}/u;

/**
 * Whether `text` is well-formed UTF-16 — no unpaired surrogate — so its UTF-8 bytes, which a party
 * statement signs, are defined (a lone surrogate has none; `TextEncoder` would sign U+FFFD instead).
 * A plain loop over code units: no regex lookbehind and no `String.prototype.isWellFormed`, neither
 * of which the Mini App's oldest WebViews (iOS before 16.4, the ES2022 target) can load.
 */
export function isWellFormedText(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit < 0xd800 || unit > 0xdfff) continue;
    if (unit > 0xdbff) return false; // a low surrogate with no high one before it
    const next = text.charCodeAt(i + 1); // NaN past the end
    if (!(next >= 0xdc00 && next <= 0xdfff)) return false; // a high surrogate with no low one after it
    i++;
  }
  return true;
}

/** The builders' guard: a text field they sign must be well-formed (`isWellFormedText`). */
function wellFormed<T extends string | null>(text: T, what: string): T {
  if (text !== null && !isWellFormedText(text)) {
    throw new RangeError(`${what}: not well-formed UTF-16 (an unpaired surrogate)`);
  }
  return text;
}

/** Whether `name` is a party's name: 1 to 64 code points, well-formed, no control character. */
export function isPartyName(name: unknown): name is string {
  if (typeof name !== "string" || !isWellFormedText(name)) return false;
  const length = [...name].length;
  return length >= 1 && length <= PARTY_NAME_MAX && !CONTROL.test(name);
}

/* --- the bytes (§2.2, §2.3) ---------------------------------------------------------------------- */

function exact(bytes: Uint8Array, length: number, what: string): Uint8Array {
  if (bytes.length !== length) throw new RangeError(`${what}: expected ${length} bytes`);
  return bytes;
}

/** `grant_token` as signed: 16 raw bytes, or empty (`LP("")`) while the PC has none. */
function token(t: Uint8Array): Uint8Array {
  return t.length === 0 ? t : exact(t, 16, "grant_token");
}

/**
 * «ПК в пати» (§2.2), `j`: signed by the PC owner's device key (`by`) on his press only.
 * `leader_key_id` is `key_id(leader.spki)` (keys §1.3), which the caller derives itself — the JSON
 * carries only the SPKI. `name` and `username` null are `LP("")`. Throws `RangeError` on a wrong
 * byte length or a text field that is not well-formed (`isWellFormedText`), before any `LP`.
 */
export function partyJoinMessage(f: {
  device_id: string;
  party_id: Uint8Array;
  party: string;
  leader_telegram_user_id: number;
  leader_name: string | null;
  leader_username: string | null;
  leader_key_id: Uint8Array;
  grant_token: Uint8Array;
  issued_at: number;
  by: Uint8Array;
}): Uint8Array<ArrayBuffer> {
  return lp(
    PARTY_DOMAINS.join,
    wellFormed(f.device_id, "device_id"),
    exact(f.party_id, PARTY_ID_BYTES, "party_id"),
    wellFormed(f.party, "party"),
    decimalId(f.leader_telegram_user_id),
    wellFormed(f.leader_name, "leader_name") ?? "",
    wellFormed(f.leader_username, "leader_username") ?? "",
    exact(f.leader_key_id, 32, "leader key_id"),
    token(f.grant_token),
    u64be(f.issued_at),
    exact(f.by, 32, "by"),
  );
}

/**
 * A grant to a member (§2.3), `pg`: `grantMessage` (keys §7) with the domain
 * `AFKLINK-PARTY-GRANT-V1`, `party_id` (never empty) in the invite's place and the leader's key as
 * `by`. The role is always `guest`. Throws as `partyJoinMessage` does.
 */
export function partyGrantMessage(f: {
  device_id: string;
  key_id: Uint8Array;
  telegram_user_id: number;
  name: string | null;
  username: string | null;
  party_id: Uint8Array;
  grant_id: Uint8Array;
  grant_token: Uint8Array;
  issued_at: number;
  by: Uint8Array;
}): Uint8Array<ArrayBuffer> {
  return lp(
    PARTY_DOMAINS.grant,
    wellFormed(f.device_id, "device_id"),
    exact(f.key_id, 32, "key_id"),
    decimalId(f.telegram_user_id),
    wellFormed(f.name, "name") ?? "",
    wellFormed(f.username, "username") ?? "",
    "guest",
    exact(f.party_id, PARTY_ID_BYTES, "party_id"),
    exact(f.grant_id, 16, "grant_id"),
    token(f.grant_token),
    u64be(f.issued_at),
    exact(f.by, 32, "by"),
  );
}
