import type { TranslationKey } from "@afklink/i18n/pc";
import { Crown, Link2, Unlink } from "lucide-react";
import { type ReactNode, useEffect, useRef, useState } from "react";

import { useT } from "../i18n";
import { cn } from "../lib/utils";
import {
  type BindingDto,
  type BindingRole,
  cancelOwnerRequest,
  type HeldPairDto,
  makeOwner,
  type OwnerRequestDto,
  type OwnerRequestOutcome,
  type SessionDto,
  unbind,
} from "../tauri";
import { formatCountdown, useCountdown } from "../useAgentStatus";
import { Button } from "./ui/button";

/** Whether a person is on the screen right now: video up, asked for, or neither. */
type Watch = "live" | "connecting" | null;

interface Person {
  id: number;
  name: string;
  /** The @handle under a first name, or the #id when there is no handle; absent when the handle or
   * the id is the name itself. */
  handle: string | undefined;
  watch: Watch;
  /** Has a binding, so it can be revoked (a session can outlive its binding by a poll). */
  bound: boolean;
  /**
   * The newcomer of a pairing this PC allowed and the server holds for the owner (`pc_allow`): no
   * binding yet, so nothing to revoke; the row opens only for «Отменить запрос» while he decides.
   */
  held: boolean;
  /** The role on this PC; null when the server sends none (older than roles) or for no binding. */
  role: BindingRole | null;
  /** The PC's request to the owner on this row: in flight, or how it just ended. */
  request: OwnerRequestDto | null;
}

/**
 * The «Доступ» screen, behind the main view's row of that name: everyone who can connect, and
 * «Начать привязку» at the bottom — the main view keeps only the count.
 *
 * Everyone with access (a binding outlives every session) is listed once; whoever is watching
 * carries a Live dot, whoever is still connecting a Live ring. The hero already says who is
 * watching, so there is no second list of sessions and no count of them. The owner's row says
 * «Владелец» at its end; a guest's says nothing — the role names the one
 * person who differs, and a server older than roles gives no role to anyone, so none is shown.
 *
 * A row opens on a press, with what can be done from it — the journal's pattern for a row with
 * actions: one tint from the row's top to under its buttons, two buttons of
 * one kind (secondary, one height, an icon on the left), each the whole line where both do not fit.
 * A guest's row: «Сделать владельцем» and «Отвязать» (in red); the owner's, and every row on a server
 * older than roles: «Отвязать» alone. «Отвязать» asks first, on the same line (`RevokeConfirm`, which
 * the journal's entries use too); on the owner the question says it needs the owner's confirmation.
 *
 * What the PC asks the owner — «Сделать владельцем», «Отвязать» on the owner — waits for the owner in
 * Telegram (Rust, `afklink_core::owner_request`); once the server has asked him (`owner_asked`) its
 * row says so under the name, open or not: «Ждём подтверждения · 9:41», and with the row open
 * «Отменить запрос» in place of the row's buttons. Until then — the server has not answered the
 * press yet, and on a PC with no owner it never asks anyone but applies it at once — the row says
 * nothing and keeps its buttons, the pressed one disabled (not «Ждём
 * подтверждения» with nobody to confirm). How it ended stays there for a few seconds —
 * «Подтверждено», «Отклонено», «Время вышло», «Запрос отменён»; «Уже есть запрос», «Слишком часто»,
 * «Не удалось отправить» in red — and the row is back to normal. The roles move by the server's word,
 * never by the press. One request at a time per PC: while one is in flight, «Сделать владельцем» on
 * every row and «Отвязать» on the owner stay in place, disabled.
 *
 * «Разрешить» in this PC's pairing prompt while someone other than the owner has a session here is
 * held by the server for the owner (`pc_allow`): the newcomer has no
 * binding yet, so they get a row of their own after everyone with access (`heldPair`) — the same
 * name lines, «Ждём подтверждения · 9:41» under them and, open, «Отменить запрос» alone: the words
 * and the button of the PC's own requests, the same wait. How it ended stays for a few seconds,
 * «Разрешено» (the owner's button was «Разрешить») rather than «Подтверждено»; allowed, the newcomer's
 * binding takes the row's place and the word moves onto it; otherwise the row goes.
 *
 * Focus: on a row's opening it stays on the row; «Отмена» takes it when a confirmation opens; Escape
 * or «Отмена» close the confirmation and give it back to the row; a revoke that went through gives
 * it to the list, since the row may be going away; «Сделать владельцем» and «Отменить запрос» give
 * it to the row, since the pressed button gives way to the request's — but «Отменить запрос» on the
 * newcomer's row gives it to the list, since that row is going away.
 */
export function AccessScreen({
  sessions,
  bindings,
  heldPair,
  ownerRequestBusy,
  onChanged,
  onShowCode,
}: {
  sessions: SessionDto[];
  bindings: BindingDto[];
  /** The newcomer of a pairing held for the owner (`StatusDto.held_pair`), or null. */
  heldPair: HeldPairDto | null;
  /** A request to the owner is in flight on this PC (`StatusDto.owner_request_busy`). */
  ownerRequestBusy: boolean;
  /** Re-read the status now, after a revoke or a request, rather than at the next poll. */
  onChanged: () => void;
  onShowCode: () => void;
}) {
  const t = useT();
  const [open, setOpen] = useState<number | null>(null);
  const [confirming, setConfirming] = useState<number | null>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const rowButtons = useRef(new Map<number, HTMLButtonElement>());

  const people = listPeople(bindings, sessions, heldPair);
  useRequestLog(people);
  useWatchLog(people);

  const toggle = (id: number) => {
    setConfirming(null);
    setOpen((was) => (was === id ? null : id));
  };

  const cancel = (id: number) => {
    setConfirming(null);
    // After the confirmation has unmounted.
    window.requestAnimationFrame(() => rowButtons.current.get(id)?.focus());
  };

  return (
    <div className="flex min-h-full flex-col">
      {people.length > 0 ? (
        <ul
          ref={listRef}
          tabIndex={-1}
          aria-label={t("app.access")}
          className="overflow-hidden rounded-card border border-line bg-panel outline-none"
        >
          {people.map((p) => (
            <PersonRow
              key={p.id}
              person={p}
              open={open === p.id}
              confirming={confirming === p.id}
              ownerRequestBusy={ownerRequestBusy}
              onToggle={() => toggle(p.id)}
              onRevoke={() => setConfirming(p.id)}
              onCancelRevoke={() => cancel(p.id)}
              onRevoked={() => {
                setConfirming(null);
                listRef.current?.focus();
                onChanged();
              }}
              onChanged={onChanged}
              // The pressed button gives way to the request's (or back to the pair): focus stays
              // on the row rather than falling to the page. The newcomer's row is going away once
              // its request is withdrawn: focus goes to the list, as after a revoke.
              onSent={() =>
                p.held ? listRef.current?.focus() : rowButtons.current.get(p.id)?.focus()
              }
              buttonRef={(el) => {
                if (el) rowButtons.current.set(p.id, el);
                else rowButtons.current.delete(p.id);
              }}
            />
          ))}
        </ul>
      ) : null}
      <div className="mt-auto pt-4">
        <Button variant="secondary" size="block" onClick={onShowCode}>
          <Link2 aria-hidden="true" />
          {t("app.showCode")}
        </Button>
      </div>
    </div>
  );
}

/**
 * A button of a row's pair: one width each where both fit on a line, each the whole line where
 * they do not, never a label cut short (the journal's `ACTION`).
 */
const ACTION = "min-w-max grow basis-0";

/**
 * A request on a row that the server has put to the owner (`owner_asked`): «Ждём подтверждения»
 * under the name, and its «Отменить запрос» in place of the row's buttons. A request still `asked`
 * is not one: nobody has been asked yet — on a PC with no owner nobody will be.
 */
function ownerAsked(request: OwnerRequestDto | null): boolean {
  if (request === null || request.stage === "ended") return false;
  // An older agent sends no `owner_asked`: everything past `asked` was opened by the server.
  return request.owner_asked ?? request.stage !== "asked";
}

function PersonRow({
  person: p,
  open,
  confirming,
  ownerRequestBusy,
  onToggle,
  onRevoke,
  onCancelRevoke,
  onRevoked,
  onChanged,
  onSent,
  buttonRef,
}: {
  person: Person;
  open: boolean;
  confirming: boolean;
  ownerRequestBusy: boolean;
  onToggle: () => void;
  onRevoke: () => void;
  onCancelRevoke: () => void;
  onRevoked: () => void;
  onChanged: () => void;
  /** A request (or its withdrawal) was sent from this row. */
  onSent: () => void;
  buttonRef: (el: HTMLButtonElement | null) => void;
}) {
  const owner = p.role === "owner";
  const lines = <PersonLines person={p} />;

  // Nothing to do from a row without a binding — but the newcomer's, while the owner is asked:
  // «Отменить запрос».
  if (!p.bound && !(p.held && ownerAsked(p.request))) {
    return <li className="border-t border-line px-4 py-2.5 first:border-t-0">{lines}</li>;
  }

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
      <button
        ref={buttonRef}
        type="button"
        aria-expanded={open}
        onClick={onToggle}
        className={cn(
          "block w-full cursor-pointer px-4 py-2.5 text-left transition-colors focus-visible:-outline-offset-2",
          // Open, the whole row is tinted already: no band of its own over the lines.
          !open && "hover:bg-white/4",
        )}
      >
        {lines}
      </button>
      {open ? (
        // `pb-2.5`: the block's bottom as far under the buttons as its top is over the name.
        <div className="animate-slide-up px-4 pb-2.5">
          {confirming ? (
            <RevokeConfirm
              telegramUserId={p.id}
              owner={owner}
              onCancel={onCancelRevoke}
              onRevoked={onRevoked}
            />
          ) : ownerAsked(p.request) ? (
            <CancelRequest request={p.request} onChanged={onChanged} onSent={onSent} />
          ) : (
            <RowActions
              person={p}
              ownerRequestBusy={ownerRequestBusy}
              onRevoke={onRevoke}
              onChanged={onChanged}
              onSent={onSent}
            />
          )}
        </div>
      ) : null}
    </li>
  );
}

/**
 * A row's lines: the dot, the name and the @handle under it (the #id without one), «Владелец» at
 * the end of the owner's row, and the request's line under them while there is one.
 */
function PersonLines({ person: p }: { person: Person }) {
  const t = useT();
  return (
    <>
      <span className="flex min-h-8 items-center gap-3">
        <WatchDot watch={p.watch} />
        <span className="block min-w-0 flex-1">
          <span className="block truncate text-body font-medium text-ink" title={p.name}>
            {p.name}
          </span>
          {p.handle ? (
            <span className="block truncate text-hint text-faint" title={p.handle}>
              {p.handle}
            </span>
          ) : null}
        </span>
        {p.role === "owner" ? (
          <span className="shrink-0 text-hint text-muted">{t("role.owner")}</span>
        ) : null}
      </span>
      {p.request ? <RequestLine request={p.request} className="mt-0.5 pl-5" /> : null}
    </>
  );
}

/**
 * An open row's pair: «Сделать владельцем» on a guest (only where the server speaks roles) and
 * «Отвязать» on everyone. While a request to the owner is in flight on this PC — on another row, or
 * on this one before the server has answered it (`asked`) — the owner-level ones — «Сделать
 * владельцем», «Отвязать» on the owner — stay in place, disabled.
 */
function RowActions({
  person: p,
  ownerRequestBusy,
  onRevoke,
  onChanged,
  onSent,
}: {
  person: Person;
  ownerRequestBusy: boolean;
  onRevoke: () => void;
  onChanged: () => void;
  onSent: () => void;
}) {
  const t = useT();
  const owner = p.role === "owner";
  const canMakeOwner = p.role === "guest";
  // A request put to the owner on this row shows «Отменить запрос» instead of this pair; any other
  // in flight — this row's own still `asked` included — holds the owner-level buttons.
  const held = ownerRequestBusy && !ownerAsked(p.request);
  const make: Face = {
    key: "make",
    icon: <Crown aria-hidden="true" />,
    label: t("app.makeOwner"),
  };
  const revoke: Face = {
    key: "revoke",
    icon: <Unlink aria-hidden="true" />,
    label: t("app.revokeAccess"),
  };
  const faces = canMakeOwner ? [make, revoke] : [revoke];
  return (
    <div className="flex flex-wrap gap-2">
      {canMakeOwner ? (
        <MakeOwnerButton
          telegramUserId={p.id}
          held={held}
          className={ACTION}
          onChanged={onChanged}
          onSent={onSent}
        >
          <PairFace face={make} pair={faces} />
        </MakeOwnerButton>
      ) : null}
      <Button
        size="sm"
        className={cn(ACTION, "text-danger")}
        // The owner's «Отвязать» is a request to the owner too: one at a time.
        aria-disabled={(owner && held) || undefined}
        onClick={onRevoke}
      >
        <PairFace face={revoke} pair={faces} />
      </Button>
    </div>
  );
}

/**
 * «Сделать владельцем»: one press, one request; the row then says how it goes. Held from the press
 * until the status shows the request in flight (`held`: the server has not answered it, and the row
 * says nothing yet) and after that while it is — so it does not light up for a moment between the
 * command's answer and the next read; at most `SEEN_MS` for a press the status never shows. On a PC
 * without an owner the server applies it at once: the row turns into the owner's,
 * with no «Ждём подтверждения» on the way; with an owner, the row's «Ждём подтверждения» and
 * «Отменить запрос» take over once the server has asked him.
 */
function MakeOwnerButton({
  telegramUserId,
  held,
  className,
  onChanged,
  onSent,
  children,
}: {
  telegramUserId: number;
  held: boolean;
  className: string;
  onChanged: () => void;
  onSent: () => void;
  children: ReactNode;
}) {
  const [sending, setSending] = useState(false);
  useEffect(() => {
    if (!sending) return;
    if (held) {
      setSending(false);
      return;
    }
    const timer = window.setTimeout(() => {
      // biome-ignore lint/suspicious/noConsole: once per press, when no request showed up
      console.debug(
        `[access] «Назначить владельцем» on #${telegramUserId}: no request in the status after ${SEEN_MS} ms; the button is back`,
      );
      setSending(false);
    }, SEEN_MS);
    return () => window.clearTimeout(timer);
  }, [sending, held, telegramUserId]);
  const press = () => {
    if (sending || held) return;
    setSending(true);
    // biome-ignore lint/suspicious/noConsole: the person's press, once per press
    console.info(`[access] «Назначить владельцем» on #${telegramUserId}`);
    makeOwner(telegramUserId).then(
      () => {
        onSent();
        onChanged();
      },
      (e: unknown) => {
        console.warn(`[ipc] make_owner #${telegramUserId} failed: ${String(e)}`);
        setSending(false);
      },
    );
  };
  return (
    <Button
      size="sm"
      className={className}
      aria-disabled={sending || held || undefined}
      onClick={press}
    >
      {children}
    </Button>
  );
}

/** How long a pressed button waits for the status to show what it did before it lights up again. */
const SEEN_MS = 3000;

/**
 * «Отменить запрос» while the request waits for the owner: disabled until the server has opened it
 * (nothing to name yet) and once pressed, in place — until the status shows the request not
 * waiting (`cancelling`, or gone with the row's buttons back), so it does not light up for a moment
 * between the command's answer and the next read; at most `SEEN_MS`.
 */
function CancelRequest({
  request,
  onChanged,
  onSent,
}: {
  request: OwnerRequestDto | null;
  onChanged: () => void;
  onSent: () => void;
}) {
  const t = useT();
  const [sending, setSending] = useState(false);
  const stage = request?.stage ?? null;
  const ready = stage === "pending" || stage === "rechecking";
  useEffect(() => {
    if (!sending) return;
    if (!ready) {
      setSending(false);
      return;
    }
    const timer = window.setTimeout(() => {
      // biome-ignore lint/suspicious/noConsole: once per press, when the request still waits
      console.debug(
        `[access] «Отменить запрос»: the request still ${stage} after ${SEEN_MS} ms; the button is back`,
      );
      setSending(false);
    }, SEEN_MS);
    return () => window.clearTimeout(timer);
  }, [sending, ready, stage]);
  const press = () => {
    if (sending || !ready) return;
    setSending(true);
    // biome-ignore lint/suspicious/noConsole: the person's press, once per press
    console.info(`[access] «Отменить запрос» (${request?.kind ?? "-"})`);
    cancelOwnerRequest().then(
      () => {
        onSent();
        onChanged();
      },
      (e: unknown) => {
        console.warn(`[ipc] cancel_owner_request failed: ${String(e)}`);
        setSending(false);
      },
    );
  };
  return (
    <div className="flex flex-wrap gap-2">
      <Button
        size="sm"
        className={ACTION}
        aria-disabled={sending || !ready || undefined}
        onClick={press}
      >
        {t("app.ownerRequestCancel")}
      </Button>
    </div>
  );
}

/** Words for how a request ended, and whether they say an error (red). */
const OUTCOME: Record<OwnerRequestOutcome, { key: TranslationKey; error: boolean }> = {
  confirmed: { key: "owner.confirmed", error: false },
  declined: { key: "owner.declined", error: false },
  expired: { key: "owner.expired", error: false },
  cancelled: { key: "owner.cancelled", error: false },
  busy: { key: "app.ownerRequestBusy", error: true },
  rate_limited: { key: "app.ownerRequestRateLimited", error: true },
  failed: { key: "app.ownerRequestFailed", error: true },
};

/**
 * How `request` ended, in words: `OUTCOME`, but a `pc_allow` the owner allowed is «Разрешено» — his
 * button was «Разрешить», as for an invite, and the bot's line says the same — not the roles'
 * «Подтверждено».
 */
function outcomeWords(request: OwnerRequestDto): { key: TranslationKey; error: boolean } | null {
  if (!request.outcome) return null;
  if (request.kind === "pc_allow" && request.outcome === "confirmed") {
    return { key: "owner.allowed", error: false };
  }
  return OUTCOME[request.outcome];
}

/**
 * The request's line under the name: «Ждём подтверждения · 9:41» — the time the owner has left —
 * once the server has put it to him (`ownerAsked`), and nothing before that; then how it ended, for a
 * few seconds. Muted — the owner's action, not this window's — and red for what did not go.
 */
function RequestLine({ request, className }: { request: OwnerRequestDto; className?: string }) {
  const t = useT();
  if (request.stage !== "ended" && !ownerAsked(request)) return null;
  if (request.stage === "ended") {
    const o = outcomeWords(request);
    if (!o) return null;
    return (
      <span
        role="status"
        className={cn(
          "block truncate text-hint",
          o.error ? "text-danger" : "text-muted",
          className,
        )}
      >
        {t(o.key)}
      </span>
    );
  }
  return (
    <span role="status" className={cn("block truncate text-hint text-muted", className)}>
      {t("app.ownerRequestPending")}
      {request.expires_at !== null ? <TimeLeft until={request.expires_at} /> : null}
    </span>
  );
}

/** « · 9:41»: the owner's time left, ticking; a `timer`, so a screen reader reads it when asked. */
function TimeLeft({ until }: { until: number }) {
  const left = useCountdown(until);
  return (
    <span role="timer" className="tabular-nums">
      {` · ${formatCountdown(left)}`}
    </span>
  );
}

/** What a button of the pair shows: its icon and its label. */
interface Face {
  key: string;
  icon: ReactNode;
  label: string;
}

/**
 * `face`, centred in a box as wide as the widest of `pair`: the other faces are laid in the same
 * cell, invisible and left out of the button's name, for their width only — so the pair's buttons
 * share one minimum width (the journal's `PairFace`).
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
 * «Отмена» / «Отвязать» under a person — in the access list and on a journal entry, the same
 * confirmation. «Отмена» takes focus when it opens. One revoke at a time: a second press while the
 * first is in flight is dropped, not sent again. On failure the confirmation stays, so the press
 * visibly did not go through; Rust logs the command itself.
 *
 * On the owner (`owner`) the line above the buttons says the owner must confirm it — in Telegram,
 * where the question goes: the access does not go at once, and the row then says «Ждём
 * подтверждения». `held`: another request to the owner is in flight, so this one would not go; the
 * button stays in place, disabled.
 */
export function RevokeConfirm({
  telegramUserId,
  owner = false,
  held = false,
  className,
  onCancel,
  onRevoked,
}: {
  telegramUserId: number;
  owner?: boolean;
  held?: boolean;
  className?: string;
  onCancel: () => void;
  onRevoked: () => void;
}) {
  const t = useT();
  const [revoking, setRevoking] = useState(false);

  const revoke = () => {
    if (revoking || held) return;
    setRevoking(true);
    unbind(telegramUserId)
      .then(onRevoked, (e: unknown) =>
        console.warn(`[ipc] unbind #${telegramUserId} failed: ${String(e)}`),
      )
      .finally(() => setRevoking(false));
  };

  return (
    <div className={className}>
      {owner ? <p className="mb-2 text-hint text-muted">{t("app.unbindOwnerNote")}</p> : null}
      <div className="flex gap-2">
        <Button size="sm" autoFocus className="flex-1" onClick={onCancel}>
          {t("common.cancel")}
        </Button>
        <Button
          variant="destructive"
          size="sm"
          className="flex-1"
          aria-disabled={revoking || held || undefined}
          onClick={revoke}
        >
          {t("app.revokeAccess")}
        </Button>
      </div>
    </div>
  );
}

/**
 * The 8px mark before every name: unlit (a dim dot) while the person is not on the screen, the Live
 * ring while they connect, the Live dot while they watch — so it lights up in place and no name
 * moves: a column that appeared only while someone watched would make every name jump 20 px right
 * and back. The unlit dot says nothing a screen reader needs.
 */
function WatchDot({ watch }: { watch: Watch }) {
  const t = useT();
  if (watch === null) {
    return <span aria-hidden="true" className="size-2 shrink-0 rounded-full bg-line-strong" />;
  }
  const label = watch === "live" ? t("app.watching") : t("app.sessionConnecting");
  return (
    <span
      role="img"
      aria-label={label}
      title={label}
      className={cn(
        "size-2 shrink-0 rounded-full",
        watch === "live" ? "bg-live" : "border-[1.5px] border-live",
      )}
    />
  );
}

/**
 * Every row's dot as it changes — someone starts watching, connecting, or leaves — said once per
 * change: the dot lights up or goes out in place. The window's console (devtools) only.
 */
function useWatchLog(people: Person[]) {
  const summary = people.map((p) => `${p.id}=${p.watch ?? "off"}`).join(" ");
  const last = useRef<string | null>(null);
  useEffect(() => {
    if (last.current === summary) return;
    const was = last.current;
    last.current = summary;
    // biome-ignore lint/suspicious/noConsole: once per change of who is on the screen
    console.debug(
      `[access] dots: ${summary || "nobody listed"}${was === null ? " (opened)" : ` (was ${was || "nobody listed"})`}; every row keeps its dot, so no name moves`,
    );
  }, [summary]);
}

/**
 * Every row's request as it changes, said once per change: which row, what was asked, where it
 * stands. The window's console (devtools) only; Rust logs the request itself with its id.
 */
function useRequestLog(people: Person[]) {
  const last = useRef(new Map<string, string>());
  // One line per row with a request, «id=kind stage outcome»: what changes, not the poll's new array.
  // The newcomer's row (`pc_allow`, no binding yet) says so: once its request goes, so does it.
  const summary = people
    .flatMap((p) =>
      p.request
        ? [
            `${p.id}=${p.request.kind} ${p.request.stage} ${p.request.outcome ?? ""}${p.held ? " (the newcomer's own row: no binding yet)" : ""}`.trim(),
          ]
        : [],
    )
    .join("\n");
  useEffect(() => {
    const now = new Map<string, string>();
    for (const line of summary === "" ? [] : summary.split("\n")) {
      const at = line.indexOf("=");
      now.set(line.slice(0, at), line.slice(at + 1));
    }
    for (const [id, what] of now) {
      if (last.current.get(id) !== what) {
        // biome-ignore lint/suspicious/noConsole: once per change of a row's request
        console.debug(`[access] row #${id}: request ${what}`);
      }
    }
    for (const id of last.current.keys()) {
      if (!now.has(id)) {
        // biome-ignore lint/suspicious/noConsole: once per change of a row's request
        console.debug(
          `[access] row #${id}: request gone; the row is back to normal (a newcomer's own row goes with it)`,
        );
      }
    }
    last.current = now;
  }, [summary]);
}

/**
 * What tells a person apart under their first name: the @handle, else the Telegram id — a first name
 * is self-chosen and not unique, so «Мама» alone could be anyone (found by a security audit).
 * The id is a number, not text to translate.
 */
function whoUnder(username: string | null | undefined, id: number): string {
  return username ? `@${username}` : `#${id}`;
}

/**
 * Everyone with access, in the agent's order, each once, with whether they are watching and their
 * role; then the newcomer of a pairing held for the owner (`held`), where their binding will be once
 * he allows; then anyone watching without a binding (a session can outlive its revoke by a poll), not
 * revocable.
 */
function listPeople(
  bindings: BindingDto[],
  sessions: SessionDto[],
  held: HeldPairDto | null,
): Person[] {
  const watch = new Map<number, Watch>();
  for (const s of sessions) {
    // Live wins over connecting when one person has two sessions.
    if (watch.get(s.telegram_user_id) !== "live") {
      watch.set(s.telegram_user_id, s.connected ? "live" : "connecting");
    }
  }
  const people: Person[] = bindings.map((b) => ({
    id: b.telegram_user_id,
    name: b.first_name ?? (b.username ? `@${b.username}` : `#${b.telegram_user_id}`),
    // A second line only under a first name: without one, the handle or the id is the title.
    handle: b.first_name ? whoUnder(b.username, b.telegram_user_id) : undefined,
    watch: watch.get(b.telegram_user_id) ?? null,
    bound: true,
    held: false,
    role: b.role ?? null,
    request: b.owner_request ?? null,
  }));
  const bound = new Set(bindings.map((b) => b.telegram_user_id));
  // Rust leaves it out once the list has the newcomer (`held_pair_dto`); the same rule here, so a
  // person is never listed twice whatever sent the status.
  if (held && !bound.has(held.telegram_user_id)) {
    bound.add(held.telegram_user_id);
    people.push({
      id: held.telegram_user_id,
      name: held.first_name ?? (held.username ? `@${held.username}` : `#${held.telegram_user_id}`),
      handle: held.first_name ? whoUnder(held.username, held.telegram_user_id) : undefined,
      watch: null,
      bound: false,
      held: true,
      role: null,
      request: held.owner_request,
    });
  }
  for (const s of sessions) {
    if (bound.has(s.telegram_user_id)) continue;
    bound.add(s.telegram_user_id);
    // `display_name` is the first name, else the @handle, else the #id: a second line only under the
    // first name.
    const titled =
      s.display_name === `@${s.username}` || s.display_name === `#${s.telegram_user_id}`;
    people.push({
      id: s.telegram_user_id,
      name: s.display_name,
      handle: titled ? undefined : whoUnder(s.username, s.telegram_user_id),
      watch: watch.get(s.telegram_user_id) ?? null,
      bound: false,
      held: false,
      role: null,
      request: null,
    });
  }
  return people;
}
