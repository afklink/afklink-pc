import { Send, Unlink } from "lucide-react";
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";

import { useLanguage, useT } from "../i18n";
import { byDay, dayTitle, eventLabel, sessionMeta, timeText } from "../lib/journal";
import { cn } from "../lib/utils";
import { type BindingDto, getJournal, type JournalEntryDto } from "../tauri";
import { RevokeConfirm } from "./AccessScreen";
import { SendLogsDialog, useSendLogs } from "./SendLogs";
import { Button } from "./ui/button";
import { Spinner } from "./ui/spinner";

/** How often the open screen re-reads the journal: a new entry, the running session's minutes. */
const POLL_MS = 2000;

/**
 * The «Журнал» screen: who was on this PC, kept on this PC only.
 *
 * At the top, the session going on now — its name and «Сейчас», a Live dot, the device and how long
 * so far. Then the entries by day, «Сегодня», «Вчера», a date: a session in two lines (the
 * name and the time; under them, small, «iPhone · 1 ч 12 мин · Связь потеряна · Только игра»), an
 * event in one muted line («Вера · Доступ выдан»). Wherever a line is too long, the name gives way —
 * with its full self in a tooltip — and the time and the event stay whole. A session's entry opens
 * on a press, with what can be done from it: «Отвязать» while the person still has access (the
 * access list's confirmation), and «Отправить логи» while its log is kept — the Diagnostics dialog,
 * this session's log first. An entry with neither does not open. Under everything, «Хранится только
 * на этом ПК, 90 дней».
 *
 * Read when the screen opens and every `POLL_MS` while it is open and the window on screen; Rust
 * words the durations in the window's language.
 *
 * «Отвязать» on the PC's owner is a request to the owner: its confirmation
 * says the owner must confirm it, as in «Доступ», and it is held, in place, while another request
 * to the owner is in flight; «Доступ» shows how the request goes.
 */
export function JournalScreen({
  bindings,
  ownerRequestBusy,
  onChanged,
}: {
  bindings: BindingDto[];
  /** A request to the owner is in flight on this PC (`StatusDto.owner_request_busy`). */
  ownerRequestBusy: boolean;
  /** Re-read the status now, after a revoke. */
  onChanged: () => void;
}) {
  const t = useT();
  const { locale } = useLanguage();
  const entries = useJournal(locale);
  const [open, setOpen] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const sendLogs = useSendLogs();
  const rowButtons = useRef(new Map<string, HTMLButtonElement>());

  if (entries === null) {
    return (
      <div role="status" className="flex flex-1 items-center justify-center py-10">
        <Spinner />
        <span className="sr-only">{t("common.loading")}</span>
      </div>
    );
  }

  const now = Date.now();
  const live = entries.filter((e) => e.live);
  const days = byDay(entries);
  const sessions = entries.some((e) => e.kind === "session");
  const bound = new Set(bindings.map((b) => b.telegram_user_id));
  const owner = bindings.find((b) => b.role === "owner")?.telegram_user_id ?? null;

  const toggle = (id: string) => {
    setConfirming(null);
    setOpen((was) => (was === id ? null : id));
  };

  return (
    <div className="flex animate-fade-in flex-col">
      {live.length > 0 ? (
        <div className="overflow-hidden rounded-card border border-line bg-panel">
          {live.map((e) => (
            <div key={e.id} className="border-t border-line px-4 py-2.5 first:border-t-0">
              <div className="flex items-center gap-2.5">
                <span
                  role="img"
                  aria-label={t("app.watching")}
                  title={t("app.watching")}
                  className="size-2 shrink-0 rounded-full bg-live"
                />
                <span
                  className="min-w-0 flex-1 truncate text-body font-medium text-ink"
                  title={e.name}
                >
                  {e.name}
                </span>
                <span className="shrink-0 text-body text-muted tabular-nums">
                  {t("app.journalNow")}
                </span>
              </div>
              <p className="mt-0.5 pl-[18px] font-small text-hint text-faint tabular-nums">
                {sessionMeta(t, e)}
              </p>
            </div>
          ))}
        </div>
      ) : null}

      {sessions ? null : (
        <p className="mt-5 text-center text-body text-muted">{t("app.journalEmpty")}</p>
      )}

      {days.map((day, index) => {
        const first = day.items[0];
        if (first === undefined) return null;
        return (
          <section
            key={day.key}
            className={cn("mt-5", index === 0 && live.length === 0 && sessions && "mt-0")}
          >
            <h2 className="mb-2 px-1 text-body font-semibold text-muted">
              {dayTitle(t, locale, first.at_ms, now)}
            </h2>
            <ul className="overflow-hidden rounded-card border border-line bg-panel">
              {day.items.map((e) =>
                e.kind === "session" ? (
                  <SessionItem
                    key={e.id}
                    entry={e}
                    time={timeText(locale, e.at_ms)}
                    bound={bound.has(e.telegram_user_id)}
                    owner={owner === e.telegram_user_id}
                    ownerRequestBusy={ownerRequestBusy}
                    open={open === e.id}
                    confirming={confirming === e.id}
                    onToggle={() => toggle(e.id)}
                    onRevoke={() => setConfirming(e.id)}
                    onCancelRevoke={() => {
                      setConfirming(null);
                      window.requestAnimationFrame(() => rowButtons.current.get(e.id)?.focus());
                    }}
                    onRevoked={() => {
                      setConfirming(null);
                      rowButtons.current.get(e.id)?.focus();
                      onChanged();
                    }}
                    onSendLogs={() => sendLogs.show(e.id)}
                    buttonRef={(el) => {
                      if (el) rowButtons.current.set(e.id, el);
                      else rowButtons.current.delete(e.id);
                    }}
                  />
                ) : (
                  <li
                    key={e.id}
                    className="flex items-center gap-2.5 border-t border-line px-4 py-2 text-muted first:border-t-0"
                  >
                    {/* The name gives way, never the event: «Константин Констан… · Доступ
                        отозван», the name whole in its tooltip. */}
                    <span className="flex min-w-0 flex-1 text-body">
                      <span className="min-w-0 truncate" title={e.name}>
                        {e.name}
                      </span>
                      <span className="shrink-0 whitespace-pre">{` · ${eventLabel(t, e.kind)}`}</span>
                    </span>
                    <span className="shrink-0 text-body text-faint tabular-nums">
                      {timeText(locale, e.at_ms)}
                    </span>
                  </li>
                ),
              )}
            </ul>
          </section>
        );
      })}

      <p className="mt-5 text-center font-small text-hint text-faint">{t("app.journalKept")}</p>
      <SendLogsDialog model={sendLogs} />
    </div>
  );
}

/**
 * A button of the entry's pair: one width each where both fit on a line, each the whole line where
 * they do not, never a label cut short (the log row's pair in Settings). Both are as wide at least
 * as the wider face (`PairFace`), so on one line they are never one wide and one narrow either.
 */
const ACTION = "min-w-max grow basis-0";

/** What a button of the pair shows: its icon and its label. */
interface Face {
  key: string;
  icon: ReactNode;
  label: string;
}

/**
 * `face`, centred in a box as wide as the widest of `pair`: the other faces are laid in the same cell,
 * invisible and left out of the button's name, for their width only. So the pair's buttons share one
 * minimum width, and `ACTION`'s line breaks before they could differ — at 340 px «Отвязать» was
 * 111 px beside «Отправить логи»'s 147.
 */
function PairFace({ face, pair }: { face: Face; pair: Face[] }) {
  return (
    <span className="grid justify-items-center">
      {pair.map((f) => (
        <span
          key={f.key}
          aria-hidden={f.key === face.key ? undefined : true}
          className={cn(
            "col-start-1 row-start-1 inline-flex items-center gap-2",
            f.key !== face.key && "invisible",
          )}
        >
          {f.icon}
          {f.label}
        </span>
      ))}
    </span>
  );
}

/**
 * A session's entry: a button over its two lines that opens it, when it has anything to do.
 *
 * Open, it is one block: one tint from the row's top to under the buttons, the buttons inside it
 * with the row's side padding, as far from the block's bottom as the name is from its top. The two
 * lines then draw no hover of their own: a lighter band over them would stop dead on the buttons
 * and read as a layout fault. Closed rows keep their hover.
 *
 * The buttons: two of one kind — secondary, one height, one width each,
 * an icon on the left, one hover and focus — «Отвязать» (a broken link, in red) while the person
 * still has access, the access list's confirmation in their place when pressed; «Отправить логи»
 * while its log is kept.
 */
function SessionItem({
  entry,
  time,
  bound,
  owner,
  ownerRequestBusy,
  open,
  confirming,
  onToggle,
  onRevoke,
  onCancelRevoke,
  onRevoked,
  onSendLogs,
  buttonRef,
}: {
  entry: JournalEntryDto;
  time: string;
  /** The person still has access: «Отвязать» is offered. */
  bound: boolean;
  /** The person is the PC's owner, so «Отвязать» waits for the owner's confirmation. */
  owner: boolean;
  /** A request to the owner is in flight: the owner's «Отвязать» is held, in place. */
  ownerRequestBusy: boolean;
  open: boolean;
  confirming: boolean;
  onToggle: () => void;
  onRevoke: () => void;
  onCancelRevoke: () => void;
  onRevoked: () => void;
  onSendLogs: () => void;
  buttonRef: (el: HTMLButtonElement | null) => void;
}) {
  const t = useT();
  const actions = bound || entry.logs;
  const revoke: Face = {
    key: "revoke",
    icon: <Unlink aria-hidden="true" />,
    label: t("app.revokeAccess"),
  };
  const logs: Face = { key: "logs", icon: <Send aria-hidden="true" />, label: t("app.sendLogs") };
  const pair = [bound ? revoke : null, entry.logs ? logs : null].filter(
    (f): f is Face => f !== null,
  );
  const lines = (
    <>
      <span className="flex items-center gap-2.5">
        <span className="min-w-0 flex-1 truncate text-body font-medium text-ink" title={entry.name}>
          {entry.name}
        </span>
        <span className="shrink-0 text-body text-muted tabular-nums">{time}</span>
      </span>
      <span className="mt-0.5 block font-small text-hint text-faint">{sessionMeta(t, entry)}</span>
    </>
  );
  return (
    <li
      className={cn("border-t border-line first:border-t-0", open && "bg-white/4")}
      onKeyDown={(e) => {
        if (e.key === "Escape" && confirming) {
          e.stopPropagation();
          onCancelRevoke();
        }
      }}
    >
      {actions ? (
        <button
          ref={buttonRef}
          type="button"
          aria-expanded={open}
          onClick={onToggle}
          className={cn(
            "block w-full cursor-pointer px-4 py-2.5 text-left transition-colors focus-visible:-outline-offset-2",
            // Open, the whole entry is tinted already: no band of its own over the two lines.
            !open && "hover:bg-white/4",
          )}
        >
          {lines}
        </button>
      ) : (
        <div className="px-4 py-2.5">{lines}</div>
      )}
      {open && actions ? (
        // `pb-2.5`: the block's bottom as far under the buttons as its top is over the name.
        <div className="animate-slide-up px-4 pb-2.5">
          {confirming ? (
            <RevokeConfirm
              telegramUserId={entry.telegram_user_id}
              owner={owner}
              held={owner && ownerRequestBusy}
              onCancel={onCancelRevoke}
              onRevoked={onRevoked}
            />
          ) : (
            <div className="flex flex-wrap gap-2">
              {bound ? (
                <Button
                  size="sm"
                  className={cn(ACTION, "text-danger")}
                  aria-disabled={(owner && ownerRequestBusy) || undefined}
                  onClick={onRevoke}
                >
                  <PairFace face={revoke} pair={pair} />
                </Button>
              ) : null}
              {entry.logs ? (
                <Button size="sm" className={ACTION} aria-haspopup="dialog" onClick={onSendLogs}>
                  <PairFace face={logs} pair={pair} />
                </Button>
              ) : null}
            </div>
          )}
        </div>
      ) : null}
    </li>
  );
}

/**
 * The journal's entries, read now and every `POLL_MS` while the window is on screen; null until the
 * first answer. A failed read keeps what is shown.
 */
function useJournal(locale: string): JournalEntryDto[] | null {
  const [entries, setEntries] = useState<JournalEntryDto[] | null>(null);
  const alive = useRef(true);

  const read = useCallback(async () => {
    try {
      const dto = await getJournal(locale);
      if (alive.current) setEntries(dto.entries);
    } catch (e) {
      console.warn(`[ipc] get_journal failed: ${String(e)}`);
      // Nothing to show is not «no connections»: an empty list once, so the screen is not stuck on
      // its loader, and the next read may bring them.
      if (alive.current) setEntries((was) => was ?? []);
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
    start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      alive.current = false;
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [read]);

  // What the screen found, said once per opening, at the first answer.
  const reported = useRef(false);
  useEffect(() => {
    if (entries === null || reported.current) return;
    reported.current = true;
    // biome-ignore lint/suspicious/noConsole: once per screen opening, what it found
    console.debug(
      `[journal] opened: ${entries.length} entr${entries.length === 1 ? "y" : "ies"}, ${entries.filter((e) => e.live).length} going on`,
    );
  }, [entries]);

  return entries;
}
