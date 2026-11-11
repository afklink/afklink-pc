import type { TranslationKey } from "@afklink/i18n/pc";
import { CloudOff, RotateCw, TriangleAlert } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { useT } from "../i18n";
import { type Refusal, retryConnection } from "../tauri";
import { Button } from "./ui/button";
import { Toast, type ToastSpec, ToastViewport } from "./ui/toast";

/**
 * What the window says when the backend refuses this agent, two or three words each — in this toast
 * and in the zone under the hero while the access list has not come (`App`'s `BottomZone`).
 */
export const REFUSAL_TEXT: Record<Refusal, TranslationKey> = {
  replaced: "app.statusReplaced",
  outdated: "connection.outdated",
  // `device_blocked`: an admin blocked this PC (the invite-only beta). The viewer's words for it.
  blocked: "app.statusDeviceBlocked",
  fatal: "app.statusRefused",
};

/**
 * Whether a press here can help — «Повторить» in this toast, «Переподключиться» in the zone. Not for
 * `outdated` (only an update) nor `blocked` (only an admin lifting the block); the agent's slow retry
 * runs all the same.
 */
export function refusalOffersRetry(refusal: Refusal): boolean {
  return refusal !== "outdated" && refusal !== "blocked";
}

/**
 * How long Retry stays dead after its command has answered: longer than a double click and than
 * the toast's exit animation (160 ms), short enough that a Retry that changed nothing is pressable
 * again at once.
 */
const PRESS_HOLD_MS = 500;

/**
 * The connection toast: nothing while connected, "no connection" once the agent has been
 * reconnecting for a while, and — while the backend refuses this agent — why, with Retry (not for
 * `outdated`, which only an update fixes, nor for `blocked`, which only an admin lifting the block
 * does — the agent's slow retry finds that by itself). Each
 * stays for as long as its condition lasts and leaves when it ends; none times out, since each is
 * still true while shown. Server trouble only: the kill switch's pause is not a condition of the
 * link but a mode the owner chose, and lives where it was chosen — the footer turns into
 * «Возобновить» and the hero says «На паузе» (`KillBar`, `StatusHero`).
 *
 * "A while" is Rust's call (`StatusDto.offline`: three seconds down without a break, counted from
 * the launch too), the same that turns the hero's «Готов к подключению» into «Нет связи» and the
 * tray's with it — so the toast and the caption change on one poll, and neither flickers at a
 * launch or a reconnect. A refusal is not delayed: it will not clear on its own.
 *
 * Retry is the only way back after `replaced` short of restarting the app: the agent does not
 * retry by itself then, or two agents with one identity would take the connection from each other
 * forever. After any other refusal it retries every 15 minutes, and Retry connects now. The code and
 * the backend's detail are in the log only, as are the agent's connects and disconnects.
 *
 * A refusal while who has access is not known at all (no list from the server this run, no cached
 * one, not a new device) is said by the zone under the hero instead — why, and «Переподключиться»
 * where it helps (`App`'s `BottomZone`, Rust's zone `refused`) — so the toast stands down then
 * (`refusalInZone`), rather than say it twice with two buttons (the owner's call). Once the list is
 * known, from wherever, the zone shows it, and a refusal is the toast's again.
 */
export function ConnectionNotice({
  offline,
  refusal,
  refusalInZone,
  onRetried,
  className,
}: {
  /** The link has been down long enough to say so (`StatusDto.offline`). */
  offline: boolean;
  refusal: Refusal | null;
  /** The zone under the hero is showing this refusal: no toast for it. */
  refusalInZone: boolean;
  /** Re-read the status after Retry rather than waiting for the next poll. */
  onRetried: () => void;
  /** Where the toast sits (`ToastViewport`). */
  className?: string | undefined;
}) {
  const t = useT();
  const standDown = refusal !== null && refusalInZone;
  // Said once each time the toast stands down, with why.
  const stoodDown = useRef(false);
  useEffect(() => {
    if (standDown && !stoodDown.current) {
      // biome-ignore lint/suspicious/noConsole: once per stand-down, the reason for a missing toast
      console.info(
        `[status] connection toast hidden: the zone under the hero shows the refusal (${refusal}) — who has access is not known yet`,
      );
    }
    stoodDown.current = standDown;
  }, [standDown, refusal]);
  // Retry in flight: a second press is dropped rather than sent twice. A ref, not state, for the
  // guard itself: a leaving toast keeps showing the action it was built with, and that button's
  // handler would read a stale `pending`.
  const inFlight = useRef(false);
  const [pending, setPending] = useState(false);

  const retry = () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setPending(true);
    // Either way the status is re-read, so the toast shows what is actually in effect. A failure
    // (no bridge in `vite dev`, a broken IPC contract) leaves the toast as it is; Rust logs the
    // command itself when it arrives.
    retryConnection()
      .catch((e: unknown) => console.warn(`[ipc] retry_connection failed: ${String(e)}`))
      .finally(() => {
        onRetried();
        // Held a moment past the answer: the toast leaves only once the re-read status is in, and
        // its exit animation keeps the button under the cursor, where the second press of a double
        // click would send the command again.
        window.setTimeout(() => {
          inFlight.current = false;
          setPending(false);
        }, PRESS_HOLD_MS);
      });
  };

  // Amber belongs to the pairing request's countdown alone: a link that is down is an Ash mark (it
  // heals by itself), a refusal a Cut one (it waits for the owner's Retry).
  // A refusal the zone is showing leaves no toast at all (not the offline one either).
  let toast: ToastSpec | null = null;
  if (refusal !== null && !standDown) {
    toast = {
      id: refusal,
      icon: <TriangleAlert className="text-danger" />,
      text: t(REFUSAL_TEXT[refusal]),
      // No Retry for `outdated`: the server does not speak this build's protocol, and only an
      // update brings it back (the agent still tries every 15 minutes, for a server rollback). None
      // for `blocked` either: an admin blocked this PC, and a retry cannot help — the agent's own
      // every 15 minutes sees the block lifted (app.statusDeviceBlocked's comment in the contract).
      action: refusalOffersRetry(refusal) ? (
        <Button size="sm" aria-disabled={pending || undefined} onClick={retry}>
          <RotateCw aria-hidden="true" />
          {t("common.retry")}
        </Button>
      ) : undefined,
    };
  } else if (refusal === null && offline) {
    toast = {
      id: "offline",
      icon: <CloudOff className="text-muted" />,
      text: t("app.statusDisconnected"),
    };
  }

  return (
    <ToastViewport className={className}>
      <Toast toast={toast} />
    </ToastViewport>
  );
}
