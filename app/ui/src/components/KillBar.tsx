import { Play, Settings, Unplug } from "lucide-react";
import { type Ref, useRef, useState } from "react";

import { useT } from "../i18n";
import { killSwitch, resumeSessions } from "../tauri";
import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";

/**
 * The footer: the kill switch, and the settings gear beside it — the one part of the window that
 * never moves, so the emergency control is always in the same place.
 *
 * «Приостановить доступ» ends every session and pauses the PC: new connections are refused until
 * «Возобновить» or an app restart (the PC is not locked). The pause is a mode, not a notice, so it
 * lives where it was chosen: while paused, the same button, in the same place, is «Возобновить»
 * (lime — the one way out, and the one bright thing on the screen then); the hero shows the pause
 * (`StatusHero`).
 *
 * The kill button escalates with the stakes: a quiet outline when nobody is watching, tonal Cut
 * while someone is, and solid Cut only on the confirmation's own button — one saturated thing per
 * state (the lit screen is it while someone watches). One confirmation: the action is undone by
 * one click on «Возобновить», and anything heavier would trade away the speed this control exists
 * for. Duplicated in the tray menu for when the window is behind the session.
 *
 * The confirmation is a dialog over the window (`Dialog`): «Приостановить доступ?», «Отмена» and
 * «Приостановить». The footer keeps its height and nothing under the dialog moves: the window must
 * not jump, as it would if the confirmation opened in the footer and pushed the hero up. Focus
 * starts on «Отмена»; Escape, the ✕ or a press outside close it as «Отмена» does; focus then goes
 * back to the footer's button — after a kill, that is «Возобновить», in the same place.
 */
export function KillBar({
  live,
  paused,
  onSettings,
  onChanged,
  settingsRef,
}: {
  /** Someone is connected or connecting. */
  live: boolean;
  /** `StatusDto.paused`: after the kill switch, until Resume. */
  paused: boolean;
  onSettings: () => void;
  /** Re-read the status now, after a kill or a resume, rather than at the next poll. */
  onChanged: () => void;
  /** The gear, so the window can give it focus back on the way out of settings. */
  settingsRef?: Ref<HTMLButtonElement>;
}) {
  const t = useT();
  const [confirming, setConfirming] = useState(false);
  /** A command (`kill_switch`, `resume_sessions`) in flight: a second press is dropped. */
  const [pending, setPending] = useState(false);
  const mainRef = useRef<HTMLButtonElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  // Focus back on the footer's button once the dialog is gone (the dialog gives it back to what
  // opened it; this covers a dialog opened while nothing had focus).
  const refocus = () => window.requestAnimationFrame(() => mainRef.current?.focus());

  const cancel = () => {
    setConfirming(false);
    refocus();
  };

  const kill = () => {
    if (pending) return;
    setPending(true);
    // The confirmation closes once Rust has taken the command. If the call fails it stays open,
    // so the press visibly did not go through; Rust logs the command itself.
    killSwitch()
      .then(
        () => {
          setConfirming(false);
          onChanged();
          refocus();
        },
        (e: unknown) => console.warn(`[ipc] kill_switch failed: ${String(e)}`),
      )
      .finally(() => setPending(false));
  };

  const resume = () => {
    if (pending) return;
    setPending(true);
    // Either way the status is re-read, so the footer shows what is actually in effect; a failure
    // leaves «Возобновить» up. Rust logs the command itself when it arrives.
    resumeSessions()
      .catch((e: unknown) => console.warn(`[ipc] resume_sessions failed: ${String(e)}`))
      .finally(() => {
        setPending(false);
        onChanged();
      });
  };

  return (
    <div className="flex gap-2">
      {/* Both states render this one button, so focus stays on it when the state flips. */}
      <Button
        ref={mainRef}
        variant={paused ? "primary" : live ? "destructive" : "dangerQuiet"}
        size="block"
        className="flex-1"
        aria-disabled={(paused && pending) || undefined}
        aria-haspopup={paused ? undefined : "dialog"}
        onClick={paused ? resume : () => setConfirming(true)}
      >
        {paused ? <Play aria-hidden="true" /> : <Unplug aria-hidden="true" />}
        {paused ? t("app.resume") : t("app.killSwitch")}
      </Button>
      <Button
        ref={settingsRef}
        variant="ghost"
        size="iconBlock"
        aria-label={t("app.settings")}
        title={t("app.settings")}
        onClick={onSettings}
      >
        <Settings aria-hidden="true" />
      </Button>
      {confirming ? (
        <Dialog title={t("app.killSwitchConfirm")} onClose={cancel} initialFocus={cancelRef}>
          <div className="flex gap-2">
            <Button ref={cancelRef} className="flex-1" onClick={cancel}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="dangerSolid"
              className="flex-1"
              aria-disabled={pending || undefined}
              onClick={kill}
            >
              {t("app.killSwitchConfirmAction")}
            </Button>
          </div>
        </Dialog>
      ) : null}
    </div>
  );
}
