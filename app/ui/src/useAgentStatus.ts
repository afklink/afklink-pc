/**
 * The window''s view of the agent.
 *
 * Polled rather than pushed. Tauri has an event channel that would be more elegant, but the Rust
 * side keeps its state in a `Mutex<AgentState>` that the orchestrator writes from several places;
 * emitting an event from each of them is several chances to forget one, and a missed event on this
 * window means the owner does not see that someone connected. A second-interval read of the whole
 * state cannot go stale — and this is a local IPC call into a struct, not a network request.
 *
 * The interval is paused while the window is hidden. Nobody is reading it, and the tray keeps the
 * app reachable; polling a hidden window is battery spent on nothing.
 *
 * One push on top: when a pairing request is raised or goes (`pair_prompt` in Rust), both windows
 * re-read at once — hidden or not, since the request window is drawn before it is shown.
 */
import { useCallback, useEffect, useRef, useState } from "react";

import { useLanguage } from "./i18n";
import { getStatus, inTauri, onPairPrompt, type StatusDto } from "./tauri";

const POLL_MS = 1000;

export interface AgentStatus {
  status: StatusDto | null;
  /** True once a poll has answered, so the shell can tell "loading" from "disconnected". */
  loaded: boolean;
  /** Re-read immediately — after an action, rather than waiting up to a second for the tick. */
  refresh: () => void;
}

export function useAgentStatus(): AgentStatus {
  const [status, setStatus] = useState<StatusDto | null>(null);
  const [loaded, setLoaded] = useState(false);
  const alive = useRef(true);
  // The status carries one finished text (`live_for`), worded in the language asked for. A change
  // of language restarts the poll with the new one, so the timer follows at once.
  const { locale } = useLanguage();

  const read = useCallback(async () => {
    try {
      const next = await getStatus(locale);
      if (alive.current) setStatus(next);
    } catch {
      // No bridge, or Rust is mid-restart. Keep the last known state: blanking the window on one
      // failed poll would flicker every list in it.
    } finally {
      if (alive.current) setLoaded(true);
    }
  }, [locale]);

  useEffect(() => {
    alive.current = true;
    let timer: number | undefined;

    const start = () => {
      if (timer !== undefined) return;
      void read();
      timer = window.setInterval(() => void read(), POLL_MS);
    };
    const stop = () => {
      if (timer === undefined) return;
      window.clearInterval(timer);
      timer = undefined;
    };
    const onVisibility = () => (document.visibilityState === "visible" ? start() : stop());

    let unlisten: (() => void) | undefined;
    let unmounted = false;
    onPairPrompt(() => void read())
      .then((off) => {
        if (unmounted) off();
        else unlisten = off;
      })
      .catch((e: unknown) => {
        // Outside Tauri (`vite dev`) there is nothing to listen to; the poll is all there is.
        if (inTauri) console.warn(`[ipc] pairing prompt events not followed: ${String(e)}`);
      });

    start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      alive.current = false;
      unmounted = true;
      unlisten?.();
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [read]);

  return { status, loaded, refresh: () => void read() };
}

/** Seconds until a deadline, floored at zero. Ticks once a second. */
export function useCountdown(until: number | null): number {
  const [left, setLeft] = useState(() => remaining(until));
  useEffect(() => {
    if (until === null) return;
    setLeft(remaining(until));
    const id = window.setInterval(() => setLeft(remaining(until)), 1000);
    return () => window.clearInterval(id);
  }, [until]);
  return left;
}

function remaining(until: number | null): number {
  return until === null ? 0 : Math.max(0, Math.ceil((until - Date.now()) / 1000));
}

/**
 * How long the backend keeps a pairing request open, in seconds: `PAIR_CONFIRM_TIMEOUT_MS` in
 * `@afklink/protocol` and `afklink_protocol`, which this package does not depend on. A countdown
 * drawn against a shorter time would sit full through the first part of the two minutes.
 */
export const PAIR_CONFIRM_TIMEOUT_S = 120;

/** The share of a pairing request's time left, 0..1: clamped, so a skewed clock cannot invert it. */
export function pairTimeLeft(secondsLeft: number): number {
  return Math.min(1, Math.max(0, secondsLeft / PAIR_CONFIRM_TIMEOUT_S));
}

/**
 * A pairing request's time left as a clock, «1:47»: minutes, then two-digit seconds. Numbers and
 * a colon read the same in Russian and English, so there is no string to translate.
 */
export function formatCountdown(secondsLeft: number): string {
  const s = Math.max(0, Math.floor(secondsLeft));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}
