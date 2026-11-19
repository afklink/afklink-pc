/**
 * The PC's input on another Windows desktop — a UAC prompt, the lock screen — as the agent reports it.
 * Import-free: the Mini App reads the kinds, the server reads the limits.
 *
 * While Windows shows a secure desktop the agent's capture sees only the ordinary one: no new frames
 * arrive, and the viewer's picture stays on the last one. Input does not reach the PC either — the
 * agent never sends it to a secure desktop on purpose, so that a guest can never answer someone
 * else's UAC prompt. Only someone at the PC can answer or unlock; the picture comes back by itself
 * once the input is on the ordinary desktop again.
 *
 * One state on the PC, `none` or one of the kinds below; an episode runs from leaving `none` to
 * coming back to it, and the agent measures it. Three places carry it:
 *
 *   - the heartbeat's `secure_desktop` (`datachannel.ts`), agent -> viewer, every heartbeat while an
 *     episode runs: the viewer's status over the frozen picture;
 *   - `secure_desktop_ongoing` (`agent-ws.ts`), agent -> server, once per episode that has lasted
 *     `SECURE_DESKTOP_LIMITS.ongoingAfterMs` during a session: the owner's notice in the bot;
 *   - the `agent_event` `secure_desktop_ended` (`metrics-wire.ts`), agent -> server, once per finished
 *     episode, in a session or not: the analytics.
 */

/**
 * Which desktop has the PC's input:
 *
 *   uac    Windows' UAC consent prompt, on the secure desktop: a program asked for administrator
 *          rights, and only someone at the PC can answer. Unanswered, Windows closes it by itself
 *          (as a refusal) after about two minutes.
 *   lock   the session is locked: the lock screen (or the sign-in screen over it).
 *   other  another desktop has the input and it is neither of the above (Ctrl+Alt+Del's screen,
 *          another program's own desktop).
 *
 * No value — the input is on the ordinary desktop. A newer agent may add a kind; a reader that does
 * not know one treats it as `other`.
 */
export const SECURE_DESKTOP_KINDS = ["uac", "lock", "other"] as const;
export type SecureDesktopKind = (typeof SECURE_DESKTOP_KINDS)[number];

export const SECURE_DESKTOP_LIMITS = {
  /**
   * An episode during a session this long is sent to the server as `secure_desktop_ongoing`, once;
   * the agent counts it from the episode's start, so a session that begins during an older episode
   * sends it at once.
   */
  ongoingAfterMs: 10_000,
  /**
   * The server's notice to the owner (`secure_desktop_ongoing` with `desktop` `uac`): at most one
   * per PC in this long, whatever the number of episodes.
   */
  ownerNoticeGapMs: 5 * 60_000,
  /**
   * A finished episode's longest `duration_ms` (30 days, `TELEMETRY_LIMITS.sessionMs`): a PC left
   * locked longer is reported at this, and the server refuses a longer one.
   */
  durationMaxMs: 2_592_000_000,
} as const;
