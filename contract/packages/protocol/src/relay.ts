/**
 * Our own TURN relays first, Cloudflare Realtime TURN as the fallback: the vocabularies the server
 * and the viewer share. The wire shapes that carry them are `iceServerEntrySchema` in `common.ts`,
 * `session_created` in `viewer-ws.ts` and the relay fields of `viewerSessionStatsSchema` in
 * `telemetry.ts`.
 *
 * Deliberately import-free, like `roles.ts` and `channels.ts`: the Mini App needs these values at
 * runtime (it builds `relay_checks` and names the server a candidate pair went through) and consumes
 * the schemas as types only, so a zod import here would drag the validator into a bundle people load
 * over mobile data.
 *
 * ## The model in four lines
 *
 *   - For every session the server hands the viewer a list of ICE servers in order of preference —
 *     ours first, Cloudflare last — and the A/B group it put the session in (`session_created`).
 *   - The viewer is the TURN client. The agent is not (a relay reaches it as the far end of the
 *     viewer's allocation), so nothing changes for it: `session_request.turn` stays as it is.
 *   - The viewer reports in its session stats which server's relay carried the video and, for each
 *     server it was given, whether that server gave it a relay candidate and how the checks through it
 *     ended.
 *   - The server keeps that per PC, to learn which server does not work for a given PC.
 */

/**
 * Who runs an ICE server:
 *
 *   own         one of our TURN relays
 *   cloudflare  Cloudflare Realtime TURN (protocol.md §5), the fallback
 */
export const ICE_SERVER_PROVIDERS = ["own", "cloudflare"] as const;
export type IceServerProvider = (typeof ICE_SERVER_PROVIDERS)[number];

/**
 * An ICE server's id (`fi1`, `cloudflare`): lowercase letters, digits and hyphens, 1 to 32 of them.
 * The server names a server by it in `session_created.ice_servers`, the viewer names the same server
 * by it in its stats (`relay_server`, `relay_checks[].id`), and the server keeps its per-PC memory
 * under it — so it is short, stable and safe to put in a log line or a database key as it is.
 */
export const ICE_SERVER_ID_PATTERN = /^[a-z0-9-]{1,32}$/;

/**
 * The A/B group the server put a session in (`session_created.relay_group`), which decides what its
 * ICE list holds:
 *
 *   control   Cloudflare only — the list as it was before our relays, the baseline to compare with
 *   test      ours first, Cloudflare last — the arrangement being tried
 *   own_only  ours only, no Cloudflare — how far our relays reach with nothing behind them
 *
 * The list the viewer gets already is what the group means; the viewer only logs the group, so a
 * session's lines say which arrangement it ran.
 */
export const RELAY_GROUPS = ["control", "test", "own_only"] as const;
export type RelayGroup = (typeof RELAY_GROUPS)[number];

/**
 * How the viewer reached the TURN server whose relay carried the video (`relay_via`): the
 * `relayProtocol` of the local relay candidate in `getStats()`.
 *
 *   udp  `turn:…` over UDP (the default, `?transport=udp`)
 *   tcp  `turn:…?transport=tcp`
 *   tls  `turns:…` — TCP with TLS, the viewer's fallback when a VPN lets STUN through and the DTLS
 *        handshake not (protocol.md §3a, «Установка застряла»)
 */
export const RELAY_TRANSPORTS = ["udp", "tcp", "tls"] as const;
export type RelayTransport = (typeof RELAY_TRANSPORTS)[number];

/**
 * How the connectivity checks through one server's relay went this session (`relay_checks[].pair`),
 * over the candidate pairs whose local candidate is that server's relay candidate:
 *
 *   succeeded    a pair through it passed its checks at some point this session — sticky: the server
 *                worked here, even if its pairs are gone since (an ICE restart drops old pairs)
 *   in_progress  none passed yet, and as of the report one is still waiting or being checked
 *                (`RTCStatsIceCandidatePairState` `frozen`, `waiting` or `in-progress`)
 *   failed       it had pairs and every one of them failed
 *   none         no pair with it at all: it gave no relay candidate, or the candidate was never paired
 *
 * Best first: the state reported is the first in this list that holds.
 */
export const RELAY_PAIR_STATES = ["succeeded", "in_progress", "failed", "none"] as const;
export type RelayPairState = (typeof RELAY_PAIR_STATES)[number];
