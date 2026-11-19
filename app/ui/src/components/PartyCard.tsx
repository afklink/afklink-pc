import { ChevronDown, ChevronRight, Clock, Users, X } from "lucide-react";
import type { ReactNode } from "react";

import { useLanguage, useT } from "../i18n";
import {
  around,
  type PartyCard as Card,
  delegationLine,
  leaderName,
  waitsForLeader,
} from "../lib/party";
import { cn } from "../lib/utils";
import { Button } from "./ui/button";

/**
 * A party the PC is in, in «Доступ» (party spec §6, process §6): a card of its own under the people,
 * its mark a neutral disc — the lime discs in this window are the layers of protection, and a party
 * is not one. Closed: «Пати "Орлы"» over «Лидер: Лёха · 8 гостей» (the party's guests on this PC,
 * with a device here or not). Open on a press: while the PC lets in by key and nobody has come in
 * by the leader's grant yet, «Ждём лидера пати» and when they will; the people bound through
 * parties alone (`rows`: the list's own row — their devices and those buttons, or a plain row while
 * they have none); then «Убрать ПК из пати», named after the party when the PC is in several so it
 * is clear which one.
 *
 * «Убрать ПК из пати» is an organ of trust: disabled, as every trust control, while a session other
 * than a confirmed owner's is on (`locked`; the line under the layers says why), and refused by the
 * agent then whatever the window shows.
 */
export function PartyCard({
  card,
  mode,
  locked,
  named,
  open,
  onToggle,
  onLeave,
  rows,
}: {
  card: Card;
  /** «Доверенные устройства» is on. */
  mode: boolean;
  locked: boolean;
  /** The PC is in more than one party: the button names this one. */
  named: boolean;
  open: boolean;
  onToggle: () => void;
  onLeave: () => void;
  /** The rows of the people who stand under it, as the list draws them. */
  rows: ReactNode[];
}) {
  const t = useT();
  const { locale } = useLanguage();
  const { party } = card;
  const waits = waitsForLeader(card, mode);
  const shown = rows.length;
  return (
    <section
      aria-label={t("app.partyTitle", { party: party.party })}
      className="mt-4 shrink-0 overflow-hidden rounded-card border border-line bg-panel"
    >
      <button
        type="button"
        aria-expanded={open}
        onClick={onToggle}
        className={cn(
          "flex w-full cursor-pointer items-center gap-3 px-4 py-3 text-left transition-colors focus-visible:-outline-offset-2",
          !open && "hover:bg-white/4",
        )}
      >
        <span
          aria-hidden="true"
          className="flex size-7 shrink-0 items-center justify-center rounded-full bg-white/6 text-muted [&_svg]:size-3.5"
        >
          <Users />
        </span>
        <span className="block min-w-0 flex-1">
          <span
            className="block truncate text-body font-medium text-ink"
            title={t("app.partyTitle", { party: party.party })}
          >
            {t("app.partyTitle", { party: party.party })}
          </span>
          <span className="block truncate text-hint text-faint">
            {delegationLine(t, locale, party, card.guests.length)}
          </span>
        </span>
        <span aria-hidden="true" className="shrink-0 text-faint [&_svg]:size-4">
          {open ? <ChevronDown /> : <ChevronRight />}
        </span>
      </button>
      {open ? (
        <div className="animate-slide-up border-t border-line">
          {waits ? (
            <div className={cn("flex gap-3 px-4 pt-3", shown > 0 && "pb-3")}>
              <Clock aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-faint" />
              <div className="min-w-0">
                <p className="text-body font-medium text-ink">{t("app.partyWaitTitle")}</p>
                <p className="text-balance text-hint text-faint">
                  {t("app.partyWaitNote", { leader: leaderName(party) })}
                </p>
              </div>
            </div>
          ) : null}
          {shown > 0 ? (
            <ul
              aria-label={t("app.partyTitle", { party: party.party })}
              className={cn(waits && "border-t border-line")}
            >
              {rows}
            </ul>
          ) : null}
          <div className={cn("px-4 pb-3", shown > 0 ? "border-t border-line pt-3" : "pt-3")}>
            <Button
              size="block"
              className="text-danger"
              aria-haspopup="dialog"
              disabled={locked}
              aria-disabled={locked || undefined}
              onClick={() => !locked && onLeave()}
            >
              <X aria-hidden="true" />
              {named ? <LeaveNamed party={party.party} /> : t("app.partyLeave")}
            </Button>
          </div>
        </div>
      ) : null}
    </section>
  );
}

/** «Убрать ПК из пати "Орлы"» with the party's name alone giving way, whole in its tooltip. */
function LeaveNamed({ party }: { party: string }) {
  const t = useT();
  const { before, name, after } = around(t, "app.partyLeaveNamed", {}, "party", party);
  return (
    <span className="flex min-w-0">
      <span className="shrink-0 whitespace-pre">{before}</span>
      <span className="min-w-0 truncate" title={name ?? undefined}>
        {name}
      </span>
      <span className="shrink-0 whitespace-pre">{after}</span>
    </span>
  );
}
