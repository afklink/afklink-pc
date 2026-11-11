import { Power } from "lucide-react";
import { useId, useRef, useState } from "react";

import { useT } from "../i18n";
import { answerAutostartOffer } from "../tauri";
import { Button } from "./ui/button";

/**
 * «Запускать вместе с Windows?» — once, in the main view's zone in place of the card, after the first
 * pairing on this PC while autostart is off (`home.rs` decides when): on first run the pairing steps give way to it, and it to the card. For an AFK PC
 * this is the setting that matters most: a PC restarted at night is gone until someone signs in and
 * starts the app.
 *
 * «Включить» turns autostart on the way Settings' switch does; «Не надо» leaves it off. Either is
 * the last answer: the card never comes back (config.json, by Rust). The status is re-read after
 * the answer, whatever it was, so the card goes when Rust says so — an «Включить» that could not
 * write the startup entry leaves it up, and the log says why.
 */
export function AutostartCard({ onAnswered }: { onAnswered: () => void }) {
  const t = useT();
  const titleId = useId();
  // One answer at a time: a second press while the first is in flight is dropped.
  const inFlight = useRef(false);
  const [pending, setPending] = useState(false);

  const answer = (enable: boolean) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setPending(true);
    // biome-ignore lint/suspicious/noConsole: the owner's answer, once
    console.info(`[home] autostart card answered: ${enable ? "«Включить»" : "«Не надо»"}`);
    answerAutostartOffer(enable)
      .catch((e: unknown) =>
        console.warn(`[ipc] answer_autostart_offer(${enable}) failed: ${String(e)}`),
      )
      .finally(() => {
        inFlight.current = false;
        setPending(false);
        onAnswered();
      });
  };

  return (
    <section
      aria-labelledby={titleId}
      className="flex flex-col gap-3 rounded-card border border-line-strong bg-panel px-4 py-3.5"
    >
      <div className="flex items-center gap-3">
        <span
          aria-hidden="true"
          className="flex size-9 shrink-0 items-center justify-center rounded-full border border-line-strong bg-panel-raised text-muted"
        >
          <Power className="size-4" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 id={titleId} className="text-body font-semibold text-ink">
            {t("app.cardAutostartTitle")}
          </h2>
          <p className="text-balance font-small text-hint text-muted">
            {t("app.cardAutostartText")}
          </p>
        </div>
      </div>
      <div className="flex gap-2">
        <Button
          size="sm"
          className="min-w-0 flex-1"
          aria-disabled={pending || undefined}
          onClick={() => answer(false)}
        >
          {t("app.cardAutostartNo")}
        </Button>
        <Button
          variant="primary"
          size="sm"
          className="min-w-0 flex-1"
          aria-disabled={pending || undefined}
          onClick={() => answer(true)}
        >
          {t("app.cardAutostartOn")}
        </Button>
      </div>
    </section>
  );
}
