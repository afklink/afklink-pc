import type { TranslationKey } from "@afklink/i18n/pc";
import { Crown, Link2, Trash2, Unlink } from "lucide-react";
import { type ReactNode, useEffect, useRef, useState } from "react";

import { useT } from "../i18n";
import {
  alsoIn,
  cardsOf,
  leaveOffered,
  partyCards,
  revokeNotes,
  revokeStaysLine,
} from "../lib/party";
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
  type TrustedAttemptDto,
  type TrustedDeviceDto,
  type TrustedDto,
  type TrustedPartyDto,
  type TrustedPersonDto,
  unbind,
} from "../tauri";
import { formatCountdown, useCountdown } from "../useAgentStatus";
import { PartyCard } from "./PartyCard";
import {
  type AttemptNote,
  devicesOf,
  PersonAttempts,
  PersonDevices,
  personOf,
  TrustedDamaged,
  TrustedLayers,
  TrustLine,
  useTrustedQuestions,
} from "./TrustedDevices";
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
  /**
   * The person's trusted devices (`get_trusted`); null when the agent keeps no list (today's look),
   * and for the newcomer's row.
   */
  devices: TrustedDeviceDto[] | null;
  /**
   * Keys in the trusted list but no binding (`TrustedDto.people` beyond the access list): a row of
   * their own, «Доступа к этому ПК больше нет…», their devices and «Удалить все устройства» (in
   * both modes: with the mode off the removal counts once it goes on).
   */
  noAccess: boolean;
  /** Devices not in the list that tried to connect as this person (§10.2), newest first. */
  attempts: TrustedAttemptDto[];
  /** The role of the person's own keys here (`TrustedPersonDto.role`): the owner's attempts ask more. */
  keysOwner: boolean;
  /** In a party's card: «лидер» after the @handle for the party's leader. */
  tag?: string;
  /** «также в пати "…"» after the devices' count: the other parties that hold them here. */
  also?: string;
  /**
   * Under «Отвязать?» of a list's row whom a party of this PC also holds here: they stay a guest
   * through it (`revokeStaysLine`).
   */
  stays?: string;
  /**
   * The row under a party's card, of a person bound through parties alone: their devices and
   * those buttons, and «Удалить все устройства»; with no device yet, a plain row. The binding's own
   * buttons («Назначить владельцем», «Отвязать») stay off it: a member stays a guest through the
   * party whatever is done to the binding here — «Убрать ПК из пати» is what closes the PC to them.
   */
  partyRow?: boolean;
}

/** A row before the trusted list's attempts are added to it (`withTrust`). */
type BarePerson = Omit<Person, "attempts" | "keysOwner">;

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
 * The PC's parties (party spec §6) follow the list, a card each (`PartyCard`): whoever is bound
 * through parties alone stands under each of their cards rather than in the list, with the same
 * row — its devices and their buttons and «Удалить все устройства», without the binding's
 * (`partyRow`), or a plain row with no device yet; anyone with a personal reason keeps the list's
 * row, with «также в пати "…"» when a party holds them here too (`lib/party.ts`).
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
  trusted = null,
  onTrustedChanged,
  onChanged,
  onShowCode,
}: {
  sessions: SessionDto[];
  bindings: BindingDto[];
  /** The newcomer of a pairing held for the owner (`StatusDto.held_pair`), or null. */
  heldPair: HeldPairDto | null;
  /** A request to the owner is in flight on this PC (`StatusDto.owner_request_busy`). */
  ownerRequestBusy: boolean;
  /**
   * The PC's trusted devices (`get_trusted`, device keys milestone 1): the layers block and every
   * person's devices. Null — an agent that keeps no list — is today's screen, unchanged.
   */
  trusted?: TrustedDto | null;
  /** Re-read the trusted devices after a change from here. */
  onTrustedChanged?: () => void;
  /** Re-read the status now, after a revoke or a request, rather than at the next poll. */
  onChanged: () => void;
  onShowCode: () => void;
}) {
  const t = useT();
  /** The open row (and its inline «Отвязать?»), by `rowKey`: a person can be under two parties. */
  const [open, setOpen] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  /** The open party cards, by party id. */
  const [openParties, setOpenParties] = useState<ReadonlySet<string>>(new Set());
  const listRef = useRef<HTMLUListElement>(null);
  const rowButtons = useRef(new Map<string, HTMLButtonElement>());

  const everyone = listPeople(bindings, sessions, heldPair, trusted);
  const cards = partyCards(trusted, bindings);
  // Who is bound through parties alone stands under their cards, not in the list.
  const under = new Map(
    everyone.map((p) => [
      p.id,
      cardsOf(
        cards,
        bindings.find((b) => b.telegram_user_id === p.id) ?? null,
        p.devices,
        p.role === "owner",
      ),
    ]),
  );
  const people = everyone
    .filter((p) => (under.get(p.id) ?? []).length === 0)
    .map((p) => {
      const also = alsoIn(t, cards, null, p.id);
      const parties = bindings.find((b) => b.telegram_user_id === p.id)?.parties;
      const stays = revokeStaysLine(
        t,
        cards.map((c) => c.party),
        parties,
        p.name,
      );
      return { ...p, ...(also ? { also } : {}), ...(stays === null ? {} : { stays }) };
    });
  useRequestLog(everyone);
  useWatchLog(everyone);
  const trustChanged = () => {
    onTrustedChanged?.();
    onChanged();
  };
  const questions = useTrustedQuestions(
    trusted,
    {
      names: new Map(everyone.map((p) => [p.id, p.name])),
      bound: everyone.filter((p) => p.bound).map((p) => p.id),
      // A person under the party cards only has no «Отвязать» (`partyRow`): no line names it.
      unbinds: people.filter(unbindShown).map((p) => p.id),
      owners: everyone.filter((p) => p.bound && p.role === "owner").map((p) => p.id),
    },
    trustChanged,
  );
  const mode = trusted?.trusted_mode ?? false;
  const locked = trusted !== null && !trusted.clean;

  const toggle = (key: string, p: Person) => {
    setConfirming(null);
    if (open !== key && p.devices) {
      const unconfirmed = p.devices.filter((d) => d.unconfirmed).length;
      // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
      console.debug(
        `[access] row #${p.id}${key.startsWith("list:") ? "" : " (under a party)"} opened: ${p.devices.length} device(s), ${unconfirmed} unconfirmed, ${p.attempts.length} attempt(s), mode ${mode ? "on" : "off"}${p.noAccess ? ", no access left" : ""}${p.devices.length === 0 && mode && p.bound ? " — «Добавить доверенное устройство» offered" : ""}`,
      );
    }
    setOpen((was) => (was === key ? null : key));
  };

  const toggleParty = (partyId: string) => {
    const opening = !openParties.has(partyId);
    const card = cards.find((c) => c.party.party_id === partyId);
    const shown = everyone.filter((p) => under.get(p.id)?.includes(partyId)).length;
    // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
    console.debug(
      `[access] party ${partyId.slice(0, 8)} ${opening ? "opened" : "closed"}: ${card?.guests.length ?? 0} guest(s) here, ${card?.entered ?? 0} with a device of it, ${shown} under the card, ${cards.length} card(s), mode ${mode ? "on" : "off"}`,
    );
    setOpenParties((was) => {
      const next = new Set(was);
      if (opening) next.add(partyId);
      else next.delete(partyId);
      return next;
    });
  };

  const layers =
    trusted === null ? null : (
      <TrustedBlock trusted={trusted} questions={questions} mode={mode} locked={locked} />
    );

  const cancel = (key: string) => {
    setConfirming(null);
    // After the confirmation has unmounted.
    window.requestAnimationFrame(() => rowButtons.current.get(key)?.focus());
  };

  /** A person's row, in the list (`scope` "list") or under a party's card (its id). */
  const row = (p: Person, scope: string) => {
    const key = rowKey(scope, p.id);
    return (
      <PersonRow
        key={key}
        person={p}
        open={open === key}
        confirming={confirming === key}
        ownerRequestBusy={ownerRequestBusy}
        onToggle={() => toggle(key, p)}
        onRevoke={() => setConfirming(key)}
        onCancelRevoke={() => cancel(key)}
        onRevoked={() => {
          setConfirming(null);
          listRef.current?.focus();
          onChanged();
        }}
        onChanged={onChanged}
        // The pressed button gives way to the request's (or back to the pair): focus stays
        // on the row rather than falling to the page. The newcomer's row is going away once
        // its request is withdrawn: focus goes to the list, as after a revoke.
        onSent={() => (p.held ? listRef.current?.focus() : rowButtons.current.get(key)?.focus())}
        mode={mode}
        locked={locked}
        onRemoveDevice={(d) => questions.askRemove(p.id, d)}
        onConfirmDevice={(d) => questions.askConfirm(p.id, d)}
        onRemovePerson={() => questions.askRemovePerson(p.id)}
        notes={questions.attemptNotes.filter((n) => n.userId === p.id)}
        busy={questions.busy}
        full={questions.full}
        parties={trusted?.parties}
        onAllow={(a) => questions.pressAllow(p.id, a)}
        onHide={(a) => questions.pressHide(p.id, a)}
        onRemoveAttempts={() => questions.askRemoveAttempts(p.id)}
        onAddDevice={() => {
          // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
          console.debug(
            `[access] «Добавить доверенное устройство» on #${p.id}: the pairing dialog`,
          );
          onShowCode();
        }}
        buttonRef={(el) => {
          if (el) rowButtons.current.set(key, el);
          else rowButtons.current.delete(key);
        }}
      />
    );
  };

  return (
    // `shrink-0`: an item of the scrolling box's column with `min-h-full` may otherwise shrink to
    // the box's height while its content overflows it, and the box's bottom padding then lands
    // under that height, not under «Начать привязку».
    <div className="flex min-h-full shrink-0 flex-col">
      {layers}
      {people.length > 0 ? (
        <ul
          ref={listRef}
          tabIndex={-1}
          aria-label={t("app.access")}
          // `shrink-0`: the screen is at least the box's height (`min-h-full`), and a list taller than
          // that (open rows with their devices) would otherwise be squeezed into it and clipped
          // (`overflow-hidden` lets a flex item shrink below its content); the box scrolls instead.
          className="shrink-0 overflow-hidden rounded-card border border-line bg-panel outline-none"
        >
          {people.map((p) => row(p, "list"))}
        </ul>
      ) : null}
      {cards.map((card) => (
        <PartyCard
          key={card.party.party_id}
          card={card}
          mode={mode}
          locked={!leaveOffered(trusted)}
          named={cards.length > 1}
          open={openParties.has(card.party.party_id)}
          onToggle={() => toggleParty(card.party.party_id)}
          onLeave={() => questions.askLeaveParty(card.party.party_id, card.party.party)}
          rows={everyone
            .filter((p) => under.get(p.id)?.includes(card.party.party_id))
            .map((p) => {
              const leader = card.party.leader.telegram_user_id === p.id;
              const also = alsoIn(t, cards, card.party.party_id, p.id);
              return row(
                {
                  ...p,
                  partyRow: true,
                  ...(leader ? { tag: t("app.partyLeaderTag") } : {}),
                  ...(also ? { also } : {}),
                },
                card.party.party_id,
              );
            })}
        />
      ))}
      <div className="mt-auto pt-4">
        <Button variant="secondary" size="block" onClick={onShowCode}>
          <Link2 aria-hidden="true" />
          {t("app.showCode")}
        </Button>
      </div>
      {questions.dialog}
    </div>
  );
}

/**
 * The trust layers over the list: a damaged list's block, the layers, and under them what holds the
 * changes or is full — the session lock, a full list and the last command's notice.
 */
function TrustedBlock({
  trusted,
  questions,
  mode,
  locked,
}: {
  trusted: TrustedDto;
  questions: ReturnType<typeof useTrustedQuestions>;
  mode: boolean;
  locked: boolean;
}) {
  const t = useT();
  return (
    <div className="mb-4 flex shrink-0 flex-col gap-3">
      {trusted.state === "damaged" ? (
        <TrustedDamaged
          damage={trusted.damage}
          busy={questions.repairing}
          locked={locked}
          notice={questions.repairNotice}
          mode={mode}
          onRepair={questions.pressRepair}
        />
      ) : null}
      <TrustedLayers trusted={trusted} onAskMode={questions.askMode} />
      {trusted.full || questions.notice !== null || (locked && trusted.state !== "damaged") ? (
        <div role="status" className="-mt-1 flex flex-col gap-0.5 px-1 text-hint">
          {locked && trusted.state !== "damaged" ? (
            <p className="text-muted">{t("app.trustedLockedSession")}</p>
          ) : null}
          {trusted.full ? <p className="text-attention">{t("app.trustedFull")}</p> : null}
          {questions.notice !== null ? <p className="text-muted">{questions.notice}</p> : null}
        </div>
      ) : null}
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
  mode,
  locked,
  onRemoveDevice,
  onConfirmDevice,
  onRemovePerson,
  onAddDevice,
  notes,
  busy,
  full,
  onAllow,
  onHide,
  onRemoveAttempts,
  parties,
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
  /** «Доверенные устройства» is on. */
  mode: boolean;
  locked: boolean;
  onRemoveDevice: (device: TrustedDeviceDto) => void;
  onConfirmDevice: (device: TrustedDeviceDto) => void;
  onRemovePerson: () => void;
  onAddDevice: () => void;
  /** What the last presses on this person's attempts left to say. */
  notes: AttemptNote[];
  /** A trust command runs: the one-press actions wait. */
  busy: boolean;
  /** The list is full: «Разрешить» on an attempt is not offered. */
  full: boolean;
  onAllow: (attempt: TrustedAttemptDto) => void;
  onHide: (attempt: TrustedAttemptDto) => void;
  onRemoveAttempts: () => void;
  /** The PC's parties: a member's device names its party. */
  parties: TrustedPartyDto[] | undefined;
  buttonRef: (el: HTMLButtonElement | null) => void;
}) {
  const owner = p.role === "owner";
  const lines = <PersonLines person={p} mode={mode} />;

  if (!opens(p)) {
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
          {confirming ? null : (
            <RowTrust
              person={p}
              mode={mode}
              locked={locked}
              notes={notes}
              busy={busy}
              full={full}
              onRemoveDevice={onRemoveDevice}
              onConfirmDevice={onConfirmDevice}
              onAddDevice={onAddDevice}
              onAllow={onAllow}
              onHide={onHide}
              onRemoveAttempts={onRemoveAttempts}
              parties={parties}
            />
          )}
          {keysOnly(p) || p.partyRow ? (
            // Nothing but attempts: their own «Удалить попытки» says it.
            attemptsOnly(p) ? null : (
              <RemovePersonButton locked={locked} onPress={onRemovePerson} />
            )
          ) : confirming ? (
            <RevokeConfirm
              telegramUserId={p.id}
              owner={owner}
              stays={p.stays ?? null}
              onCancel={onCancelRevoke}
              onRevoked={onRevoked}
            />
          ) : unbindShown(p) ? (
            <RowActions
              person={p}
              ownerRequestBusy={ownerRequestBusy}
              onRevoke={onRevoke}
              onChanged={onChanged}
              onSent={onSent}
            />
          ) : (
            <CancelRequest request={p.request} onChanged={onChanged} onSent={onSent} />
          )}
        </div>
      ) : null}
    </li>
  );
}

/**
 * An open row's trust part: the devices (none and no binding: nothing about adding one — the
 * attempts alone), then the attempts with what the last presses left on them.
 */
function RowTrust({
  person: p,
  mode,
  locked,
  notes,
  busy,
  full,
  onRemoveDevice,
  onConfirmDevice,
  onAddDevice,
  onAllow,
  onHide,
  onRemoveAttempts,
  parties,
}: {
  person: Person;
  mode: boolean;
  locked: boolean;
  notes: AttemptNote[];
  busy: boolean;
  full: boolean;
  onRemoveDevice: (device: TrustedDeviceDto) => void;
  onConfirmDevice: (device: TrustedDeviceDto) => void;
  onAddDevice: () => void;
  onAllow: (attempt: TrustedAttemptDto) => void;
  onHide: (attempt: TrustedAttemptDto) => void;
  onRemoveAttempts: () => void;
  parties: TrustedPartyDto[] | undefined;
}) {
  return (
    <>
      {p.devices !== null && (p.bound || p.devices.length > 0) && !bareMember(p) ? (
        <PersonDevices
          devices={p.devices}
          mode={mode}
          locked={locked}
          parties={parties}
          onRemove={onRemoveDevice}
          onConfirm={onConfirmDevice}
          onAddDevice={onAddDevice}
        />
      ) : null}
      <PersonAttempts
        attempts={p.attempts}
        notes={notes}
        locked={locked}
        busy={busy}
        full={full}
        removable={attemptsOnly(p) && p.role !== "owner" && !p.keysOwner}
        onAllow={onAllow}
        onHide={onHide}
        onRemoveAttempts={onRemoveAttempts}
      />
    </>
  );
}

/** What decides a row's buttons. */
type RowFacts = Pick<Person, "bound" | "noAccess" | "held" | "request"> &
  Partial<Pick<Person, "partyRow" | "devices" | "attempts">>;

/**
 * Whether a row opens. Nothing to do from a row without a binding — but the newcomer's, while the
 * owner is asked («Отменить запрос»), and one whose devices are still in the trusted list; nor
 * from a party member's row with no device here yet (`bareMember`).
 */
function opens(p: RowFacts): boolean {
  return (p.bound && !bareMember(p)) || p.noAccess || (p.held && ownerAsked(p.request));
}

/**
 * A party member's row under a card with no device here yet: a plain row, no device line, nothing
 * to open (the leader's grant brings their devices; attempts of theirs still open it).
 */
function bareMember(p: RowFacts): boolean {
  return p.partyRow === true && (p.devices?.length ?? 0) === 0 && (p.attempts?.length ?? 0) === 0;
}

/** Devices in the trusted list and no binding: nothing to revoke, the devices only. */
function keysOnly(p: RowFacts): boolean {
  return p.noAccess && !p.bound;
}

/**
 * Whether the person's open row draws «Отвязать» (`RowActions`): a row that opens, with a binding to
 * revoke, and no request put to the owner on it (that row has «Отменить запрос» in its place). The
 * one reading for the row and for «Удалить из доверенных?», whose line `app.trustedUntrustCutOff`
 * names this button (`TrustedPeopleView.unbinds`, `untrustLines`). The row's own inline «Отвязать?»
 * (`confirming`) needs no case: it hides the devices, so that question cannot open beside it.
 */
export function unbindShown(p: RowFacts): boolean {
  return opens(p) && !keysOnly(p) && !ownerAsked(p.request);
}

/** Attempts and no device in the list: «Удалить попытки» rather than «Удалить все устройства». */
function attemptsOnly(p: Person): boolean {
  return p.attempts.length > 0 && (p.devices?.length ?? 0) === 0;
}

/**
 * «Удалить все устройства» on a row with no access left — in both modes, as «Удалить из
 * доверенных» (with the mode off the removal counts once it goes on).
 */
function RemovePersonButton({ locked, onPress }: { locked: boolean; onPress: () => void }) {
  const t = useT();
  return (
    <Button
      size="sm"
      className="w-full text-danger"
      aria-haspopup="dialog"
      disabled={locked}
      aria-disabled={locked || undefined}
      onClick={() => !locked && onPress()}
    >
      <Trash2 aria-hidden="true" />
      {t("app.trustedRemovePerson")}
    </Button>
  );
}

/**
 * A row's lines: the dot, the name and the @handle under it (the #id without one), «Владелец» at
 * the end of the owner's row, and the request's line under them while there is one.
 */
function PersonLines({ person: p, mode }: { person: Person; mode: boolean }) {
  const t = useT();
  return (
    <>
      <span className="flex min-h-8 items-center gap-3">
        <WatchDot watch={p.watch} />
        <span className="block min-w-0 flex-1">
          <span className="block truncate text-body font-medium text-ink" title={p.name}>
            {p.name}
          </span>
          {p.handle || p.tag ? (
            <span className="block truncate text-hint text-faint" title={p.handle}>
              {[p.handle, p.tag].filter(Boolean).join(" · ")}
            </span>
          ) : null}
        </span>
        {p.role === "owner" ? (
          <span className="shrink-0 text-hint text-muted">{t("role.owner")}</span>
        ) : null}
      </span>
      {p.request ? <RequestLine request={p.request} className="mt-0.5 pl-5" /> : null}
      {keysOnly(p) ? (
        <span className="block text-balance text-hint text-faint pl-5">
          {attemptsOnly(p) ? t("app.trustedOnAttempts") : t("app.trustedNoAccess")}
        </span>
      ) : p.partyRow && (p.devices?.length ?? 0) === 0 ? (
        // No device here yet: no «Нужно доверенное устройство» — the leader's grant brings them.
        p.also ? (
          <span className="block text-pretty text-hint text-faint pl-5">{p.also}</span>
        ) : null
      ) : p.devices !== null ? (
        <TrustLine devices={p.devices} mode={mode} also={p.also} className="pl-5" />
      ) : null}
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
  stays = null,
  className,
  onCancel,
  onRevoked,
}: {
  telegramUserId: number;
  owner?: boolean;
  held?: boolean;
  /** The person stays a guest through a party here: that line (`revokeStaysLine`), or null. */
  stays?: string | null;
  className?: string;
  onCancel: () => void;
  onRevoked: () => void;
}) {
  const t = useT();
  const [revoking, setRevoking] = useState(false);
  const notes = revokeNotes(t, owner, stays);
  useEffect(() => {
    if (stays === null) return;
    // biome-ignore lint/suspicious/noConsole: once per question, what it says
    console.debug(
      `[access] «Отвязать?» on #${telegramUserId}: the party line (a guest through a party stays)`,
    );
  }, [stays, telegramUserId]);

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
      {notes.map((line) => (
        <p key={line} className="mb-2 text-hint text-muted">
          {line}
        </p>
      ))}
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

/** A row's key: the person under the list or under a party's card (a person can be under two). */
function rowKey(scope: string, id: number): string {
  return `${scope}:${id}`;
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
 * revocable; then whoever has devices in the trusted list but no binding (`noAccess`).
 */
function listPeople(
  bindings: BindingDto[],
  sessions: SessionDto[],
  held: HeldPairDto | null,
  trusted: TrustedDto | null,
): Person[] {
  const watch = new Map<number, Watch>();
  for (const s of sessions) {
    // Live wins over connecting when one person has two sessions.
    if (watch.get(s.telegram_user_id) !== "live") {
      watch.set(s.telegram_user_id, s.connected ? "live" : "connecting");
    }
  }
  const people: BarePerson[] = bindings.map((b) => ({
    id: b.telegram_user_id,
    name: b.first_name ?? (b.username ? `@${b.username}` : `#${b.telegram_user_id}`),
    // A second line only under a first name: without one, the handle or the id is the title.
    handle: b.first_name ? whoUnder(b.username, b.telegram_user_id) : undefined,
    watch: watch.get(b.telegram_user_id) ?? null,
    bound: true,
    held: false,
    role: b.role ?? null,
    request: b.owner_request ?? null,
    devices: devicesOf(trusted, b.telegram_user_id),
    noAccess: false,
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
      devices: null,
      noAccess: false,
    });
  }
  const keyed = new Map((trusted?.people ?? []).map((p) => [p.telegram_user_id, p]));
  people.push(...unboundRows(sessions, watch, keyed, bound));
  return people.map((p) => withTrust(p, trusted));
}

/**
 * A row with what the trusted list says beside its devices: the attempts; none on the newcomer's
 * row.
 */
function withTrust(p: BarePerson, trusted: TrustedDto | null): Person {
  if (p.held) return { ...p, attempts: [], keysOwner: false };
  const own = personOf(trusted, p.id);
  return {
    ...p,
    attempts: own?.attempts ?? [],
    keysOwner: own?.role === "owner",
  };
}

/**
 * The rows with no binding: anyone watching without one (a session can outlive its revoke by a
 * poll) — with their devices while the list still has them — then whoever has devices in the
 * trusted list and no binding at all, named as a binding's row is. `bound` grows with each.
 */
function unboundRows(
  sessions: SessionDto[],
  watch: Map<number, Watch>,
  keyed: Map<number, TrustedPersonDto>,
  bound: Set<number>,
): BarePerson[] {
  const people: BarePerson[] = [];
  for (const s of sessions) {
    if (bound.has(s.telegram_user_id)) continue;
    bound.add(s.telegram_user_id);
    const own = keyed.get(s.telegram_user_id);
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
      // A session outliving its binding: its devices, when the list still has them.
      devices: own?.devices ?? null,
      noAccess: own !== undefined,
    });
  }
  // Keys with no binding left: their own rows, named as a binding's row is.
  for (const k of keyed.values()) {
    if (bound.has(k.telegram_user_id)) continue;
    bound.add(k.telegram_user_id);
    people.push({
      id: k.telegram_user_id,
      name: k.first_name ?? (k.username ? `@${k.username}` : `#${k.telegram_user_id}`),
      handle: k.first_name ? whoUnder(k.username, k.telegram_user_id) : undefined,
      watch: null,
      bound: false,
      held: false,
      role: null,
      request: null,
      devices: k.devices,
      noAccess: true,
    });
  }
  return people;
}
