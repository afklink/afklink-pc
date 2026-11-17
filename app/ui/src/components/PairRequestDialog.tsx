import { Crown, KeyRound, UserRound } from "lucide-react";
import { type RefObject, useEffect, useId, useLayoutEffect, useRef, useState } from "react";

import { useLanguage, useT } from "../i18n";
import {
  allowPair,
  type BindingRole,
  type DeviceLineName,
  type PairStep,
  type PendingPairDto,
  respondPair,
  type StatusDto,
} from "../tauri";
import { formatCountdown, pairTimeLeft, useCountdown } from "../useAgentStatus";
import { initialOf } from "./ScreenGlyph";
import { StepDisc } from "./Steps";
import { deviceName, whenText } from "./TrustedDevices";
import { Button } from "./ui/button";
import { Checkbox } from "./ui/checkbox";
import { MiddleEllipsis } from "./ui/middle-ellipsis";

/**
 * The pairing step a request is: the steps' third (press «Разрешить» here) at the first
 * pairing, and none otherwise — no steps led to a request while someone already has access. The
 * first pairing is Rust's own test for the zone's steps (`home::zone`): who has access is known (the
 * server's list, the cached one, or a new device's nobody), and nobody has it — no binding, no
 * session. Unknown counts as not the first: no mark rather than a wrong one.
 */
export function pairingStep(status: StatusDto): 3 | undefined {
  const first =
    status.access !== "unknown" && status.bindings.length === 0 && status.sessions.length === 0;
  return first ? 3 : undefined;
}

/**
 * The longest name the prompt spells out before an ellipsis. A Telegram first name can run to 64
 * characters; at 15px that is four lines in the request window, and «просит доступ к этому ПК»
 * after it is the part that must never be cut. Clamped in code, so what is cut is the name — in the
 * middle (the start and the end both stay), and shorter still where the heading's three
 * lines would not hold it with the action (`useFittedName`).
 */
const NAME_MAX = 36;

/** The fewest characters a cut name keeps, the ellipsis included: «Але…ая». */
const NAME_MIN = 6;

/** The most characters kept whole at a cut name's end, as `MiddleEllipsis` keeps them. */
const NAME_TAIL_MAX = 12;

/** The heading's lines (`line-clamp-3`): the name gives way before the action would. */
const TITLE_LINES = 3;

/**
 * A pairing request: who asks, how long is left, Decline and Allow.
 *
 * Entering the code does not grant access; only the person at this machine can answer. The request
 * is shown in one place only: the small always-on-top request window near the tray
 * (`PairRequestWindow`), whether the main window is open or not. A card in the main window would
 * squeeze Settings, «Доступ» and «Журнал» to a sliver for up to two minutes.
 * The window *is* the card: no frame around it, sized to it (`PairRequestWindow` reports the
 * height), and dragged by any part that is not a button.
 *
 * Read like a notification, top to bottom: the requester's initial in a circle beside «{name}
 * просит доступ к этому ПК» (always these words, «Только игра» too), the @username
 * under it — the #id when there is none; what «Разрешить» does to the trusted devices
 * (`TrustedDeviceLine`); the time left as a thin amber bar with «1:47» at its end; Decline and Allow.
 * Amber means that bar, the trusted line's «Раньше его удалили из доверенных» and the owner's line
 * — nothing else. A person removed earlier is let back with one press, as anyone.
 *
 * An owner on this PC (`owner_here`, the agent's reading) gets the owner's role, never a guest's
 * and never asked «Кто это?»: with a device line, under it in amber «Это устройство получит доступ
 * владельца» and the box «Это моё устройство»; «Разрешить» waits for it and sends the owner's role
 * with the step (`ownerStepShown`, `pairAllowPress`). Without a key the no-key lines give the
 * owner's own way back.
 *
 * At the first pairing (`step`, from `pairingStep`) the top row ends in the steps' lime «3»: the
 * request is their last (press «Разрешить» here) — the steps on the main view and in the pairing
 * dialog both end in it, so 1 → 2 → 3 reads on. A request while someone has access gets none.
 *
 * Focus starts on the prompt, never on a button (`usePromptFocus`); Decline comes first in the DOM,
 * so the first Tab lands on the safe button. Allow is the visual primary. Each answer is guarded
 * against a double press and a failed IPC call is logged and leaves the prompt up, as the other
 * commands do. An answer closes the request window at once (Rust); `onAnswered` re-reads the status
 * here without waiting for the next poll.
 *
 * On a PC with no owner (`asks_role`) «Разрешить» does not answer yet:
 * the card turns into its second step, «Кто это?», with two big buttons of one kind, «Владелец» and
 * «Гость», and the choice is the answer (`respondPair` with the role). The step is Rust's
 * (`pair_prompt`), so a window reloaded meanwhile comes back at it; this window shows the question at
 * once on the press, before Rust's word comes back. The countdown carries on — the server's deadline
 * holds for both steps — and a request that runs out at the question goes as it would at the first
 * step: the card disappears. Focus goes back to the prompt (never to a button) when the step changes,
 * so a key the owner meant for something else cannot pick a role either.
 *
 * A request outlives a break of the link to the server (`request.link`, Rust's
 * `afklink_core::pairing`): the server keeps it and sends it again when the PC is back, and the card
 * stays as it is — at its step, «Кто это?» included — with its buttons disabled in place and «Нет
 * связи» before the countdown while the link is down (`lost`); still disabled, without the words, in
 * the moment between the link coming back and the server's re-send (`rechecking`). An answer goes
 * only over a live link: one given now could reach a server that has dropped the request, and the
 * owner would believe he had answered. If the link is not back in time, the card goes as it would
 * have when the time ran out.
 */
export function PairRequestPrompt({
  request,
  step,
  onAnswered,
  onStep,
}: {
  request: PendingPairDto;
  /** The pairing step this request is, as its disc: only at the first pairing (`pairingStep`). */
  step?: number | undefined;
  onAnswered?: () => void;
  /** The step drawn, after each change: the request window reports its height for it. */
  onStep?: (step: PairStep) => void;
}) {
  const t = useT();
  const secondsLeft = useCountdown(request.expires_at);
  const promptRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const whoId = useId();
  const [pending, setPending] = useState(false);
  const { own } = useConsent(request);
  const at = pairPhase(request);
  // An older agent sends no `link`: always live.
  const link = request.link ?? "live";
  const live = link === "live";
  // Every answer button: in flight, or waiting for the link (disabled in place, never hidden).
  const held = pending || !live;
  const questionSince = useStepSince(`${request.request_id}:${at}`);
  usePromptFocus(promptRef, `${request.request_id}:${at}`);
  useStepLog(request.request_id, step);
  useRoleStepLog(request, at);
  useLinkLog(request.request_id, link);
  useEffect(() => onStep?.(at), [onStep, at]);

  const { name, handle } = requesterName(request);
  const [before, action] = splitAround(t("app.pairRequestTitle", { user: SLOT }), SLOT);
  // The action as drawn and as `useFittedName` measures it: its short words held together.
  const after = keepShortWordsTogether(action);
  const titleRef = useRef<HTMLParagraphElement>(null);
  const fitted = useFittedName(titleRef, name.full, before, after, at === "consent");

  const answer = (accept: boolean, role?: BindingRole) => {
    if (pending) return;
    if (!live) {
      // biome-ignore lint/suspicious/noConsole: a press dropped on purpose, said once per press
      console.debug(
        `[pair] answer on ${request.request_id} pressed while its link is ${link}: not sent (the buttons wait)`,
      );
      return;
    }
    // «Гость» and «Владелец» take the place of «Разрешить» and «Отклонить»: the second click of a
    // double click on «Разрешить» must not choose a role.
    const sinceMs = performance.now() - questionSince;
    if (role !== undefined && at === "role" && sinceMs < ROLE_ARM_MS) {
      // biome-ignore lint/suspicious/noConsole: a press dropped on purpose, said once per press
      console.debug(
        `[pair] «${role}» pressed ${Math.round(sinceMs)} ms after «Кто это?» appeared: taken for the rest of a double click on «Разрешить», ignored`,
      );
      return;
    }
    const press = answerPress(request, accept, own.ticked);
    if ("held" in press) {
      // biome-ignore lint/suspicious/noConsole: a press held on purpose, said once per press
      console.debug(
        `[pair] ${answerSaid(accept, role)} on ${request.request_id} held: ${press.held}`,
      );
      return;
    }
    const step = press.send;
    const said = answerSaid(accept, role ?? step.role);
    setPending(true);
    // biome-ignore lint/suspicious/noConsole: the owner's answer, once per press
    console.debug(`[pair] respond_pair ${request.request_id}: ${said}${stepSaid(step)}`);
    respondPair(request.request_id, accept, role ?? step.role, step.secondStep, request.shown)
      .then(() => onAnswered?.())
      .catch((e: unknown) =>
        console.warn(`[ipc] respond_pair ${said} (${request.request_id}) failed: ${String(e)}`),
      )
      .finally(() => setPending(false));
  };

  const allow = () => {
    if (!asksRole(request)) {
      answer(true);
      return;
    }
    if (pending) return;
    const press = pairAllowPress(request, own.ticked);
    if ("held" in press) {
      // biome-ignore lint/suspicious/noConsole: a press held on purpose, said once per press
      console.debug(`[pair] «Разрешить» on ${request.request_id} held: ${press.held}`);
      return;
    }
    if (!live) {
      // biome-ignore lint/suspicious/noConsole: a press dropped on purpose, said once per press
      console.debug(
        `[pair] «Разрешить» on ${request.request_id} pressed while its link is ${link}: the step waits`,
      );
      return;
    }
    setPending(true);
    allowPair(request.request_id)
      .then((ok) => {
        if (!ok) {
          // Rust's log says why (withdrawn, or the PC has an owner after all); the next read shows
          // what is so.
          console.warn(`[pair] «Кто это?» not taken for ${request.request_id}: no longer pending`);
        }
        // The step is Rust's (`step`): the read that follows shows «Кто это?».
        onAnswered?.();
      })
      .catch((e: unknown) =>
        console.warn(`[ipc] allow_pair (${request.request_id}) failed: ${String(e)}`),
      )
      .finally(() => setPending(false));
  };

  // «Разрешить» (and the roles) wait, in place, for «Это моё устройство».
  const stepWaits = "held" in pairAllowPress(request, own.ticked);
  const offer = allowOffer(request);
  useOfferLog(request.request_id, offer);
  const initial = initialOf(name.full);
  return (
    <div
      ref={promptRef}
      role="alertdialog"
      aria-modal="false"
      aria-label={t("notify.pairRequestTitle.native")}
      // At «Кто это?» the question and who it is about: the title alone names nobody there.
      aria-describedby={at === "role" ? `${titleId} ${whoId}` : titleId}
      tabIndex={-1}
      data-step={at}
      // The request window has no title bar: it moves by any part that is not a button.
      data-tauri-drag-region="deep"
      className="flex animate-fade-in flex-col gap-3 p-4 outline-none"
    >
      <div className="flex min-w-0 items-center gap-3">
        <span
          aria-hidden="true"
          className="flex size-9 shrink-0 items-center justify-center rounded-full border border-line-strong bg-panel-raised font-display text-heading font-semibold text-ink"
        >
          {initial ?? <UserRound className="size-4 text-muted" />}
        </span>
        {at === "role" ? (
          <div className="min-w-0 flex-1">
            <p id={titleId} className="truncate text-heading font-semibold text-ink">
              {t("app.roleQuestion")}
            </p>
            {/* Who the question is about: the name, and the handle when there is one — whole in
                the tooltip where the line cuts them. */}
            <p
              id={whoId}
              className="truncate text-body text-muted"
              title={handle ? `${name.full} · ${handle}` : name.full}
            >
              {handle ? `${name.shown} · ${handle}` : name.shown}
            </p>
          </div>
        ) : (
          <div className="min-w-0 flex-1">
            <p
              ref={titleRef}
              id={titleId}
              className="line-clamp-3 text-heading font-semibold break-words text-balance text-ink"
            >
              {before}
              <span title={name.full}>{fitted}</span>
              {after}
            </p>
            {handle ? (
              // A 32-character @username is cut in a narrow window — in the middle, as every name
              // — and whole in its tooltip.
              <MiddleEllipsis text={handle} className="text-body text-muted" />
            ) : null}
            <RemovedHereLine request={request} />
          </div>
        )}
        {step === undefined ? null : <StepDisc n={step} size="card" tone="now" />}
      </div>
      {at === "consent" ? (
        <ConsentKeyLine request={request} offer={offer} own={own} held={held} />
      ) : null}
      <Countdown secondsLeft={secondsLeft} offline={link === "lost"} />
      {at === "role" ? (
        // Two equal choices, one kind of button: neither is the default, neither the quieter one.
        <div className="grid grid-cols-2 gap-2">
          <Button
            className="h-14 flex-col gap-1 [&_svg]:size-5"
            aria-disabled={held || stepWaits || undefined}
            onClick={() => answer(true, "owner")}
          >
            <Crown aria-hidden="true" />
            {t("role.owner")}
          </Button>
          <Button
            className="h-14 flex-col gap-1 [&_svg]:size-5"
            aria-disabled={held || stepWaits || undefined}
            onClick={() => answer(true, "guest")}
          >
            <UserRound aria-hidden="true" />
            {t("role.guest")}
          </Button>
        </div>
      ) : (
        <ConsentButtons
          held={held}
          allowWaits={stepWaits}
          offered={offer.kind === "allow"}
          onDecline={() => answer(false)}
          onAllow={allow}
        />
      )}
    </div>
  );
}

/**
 * What «Разрешить» does to this PC's trusted devices (device keys), by the request's key
 * (`key_state`), under the person and before the countdown — one line with a key, and under it, small,
 * what the owner should know about it:
 * - `valid`: «Станет доверенным: Telegram на iPhone» — the device whose access key goes in the list;
 * - `was_removed`: «Станет снова доверенным: …» (the removal itself is said under the title);
 * - `absent` / `invalid`: «Не станет доверенным: нет ключа доступа» — no device line;
 * - with a device line, when a session that is not a confirmed owner's ran since the pairing panel
 *   opened (`will_be_unconfirmed`): «Добавится без подтверждения: …» in its place, and under it
 *   the note that a session ran during the request and the device is confirmed in «Доступ» (§10.1);
 * - `not_trusted_session`: strict mode and such a session — nothing is written: «Не станет
 *   доверенным: во время привязки шёл сеанс», and under it what to do (no device line).
 * An older agent sends no `key_state`: today's look — the «Станет доверенным» line when it names the
 * device, else none. Wraps rather than cuts: what «Разрешить» trusts is read whole. Nothing here
 * changes what «Отклонить» and «Разрешить» do.
 */
function TrustedDeviceLine({ request }: { request: PendingPairDto }) {
  const t = useT();
  const line = deviceLineOf(request);
  const ref = request.device ?? null;
  // Primitives, not the object: the status is read again every second.
  const kind = ref?.kind ?? "unknown";
  const platform = ref?.platform ?? "-";
  const keyState = request.key_state ?? "-";
  const unconfirmed = request.will_be_unconfirmed === true;
  useEffect(() => {
    // biome-ignore lint/suspicious/noConsole: once per request and change of what the line says
    console.debug(
      `[pair] request ${request.request_id}: key ${keyState}${unconfirmed ? ", will be unconfirmed" : ""}, device ${kind} on ${platform} → ${line}${keyState === "-" ? " (an older agent: no key state)" : ""}`,
    );
  }, [request.request_id, keyState, unconfirmed, kind, platform, line]);
  if (line === "none") return null;
  // Absent from an older agent with a `key_state` it has no device for: «Неизвестное устройство».
  const device = deviceName(t, ref ?? { kind: null, platform: null });
  const notes = NOTES[line] ?? [];
  return (
    <div className="flex items-start gap-2 text-body text-muted">
      <KeyRound className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <div className="min-w-0">
        <p className="text-balance">{t(MAIN[line], { device })}</p>
        {notes.map((note) => (
          <p
            key={note.key}
            className={`text-hint text-balance${note.attention ? " text-attention" : ""}`}
          >
            {t(note.key)}
          </p>
        ))}
      </div>
    </div>
  );
}

/**
 * Under the request at its consent step: the key line — and for an owner on this PC his line and
 * box (`OwnerBlock`) — or, not offered, why and what to do.
 */
function ConsentKeyLine({
  request,
  offer,
  own,
  held,
}: {
  request: PendingPairDto;
  offer: AllowOffer;
  own: OwnerStep;
  held: boolean;
}) {
  if (offer.kind !== "allow")
    return <NoOffer request={request} fact={offer.fact} step={offer.step} />;
  return (
    <>
      <TrustedDeviceLine request={request} />
      {own.shown ? (
        <OwnerBlock ticked={own.ticked} disabled={held} onTick={(next) => own.tick(next, held)} />
      ) : null}
    </>
  );
}

/** «Отклонить» and, only when it lets the person connect, the lime «Разрешить». */
function ConsentButtons({
  held,
  allowWaits,
  offered,
  onDecline,
  onAllow,
}: {
  held: boolean;
  /** «Разрешить» waits for «Это моё устройство». */
  allowWaits: boolean;
  offered: boolean;
  onDecline: () => void;
  onAllow: () => void;
}) {
  const t = useT();
  return (
    <div className="flex gap-2">
      <Button className="flex-1" aria-disabled={held || undefined} onClick={onDecline}>
        {t("app.pairDecline")}
      </Button>
      {offered ? (
        <Button
          variant="primary"
          className="flex-1"
          aria-disabled={held || allowWaits || undefined}
          onClick={onAllow}
        >
          {t("app.pairApprove")}
        </Button>
      ) : null}
    </div>
  );
}

/**
 * A request whose «Разрешить» would not let the person connect (`allowOffer`): in amber what
 * stands, under it what to do — in place of the key line, with no primary button.
 */
function NoOffer({
  request,
  fact,
  step,
}: {
  request: PendingPairDto;
  fact: NoOfferFact | null;
  step: NoOfferStep | null;
}) {
  const t = useT();
  if (fact === null) return null;
  const device = deviceName(t, request.device ?? { kind: null, platform: null });
  return (
    <div className="flex items-start gap-2 text-body">
      <KeyRound className="mt-0.5 size-4 shrink-0 text-attention" aria-hidden="true" />
      <div className="min-w-0">
        <p className="text-balance text-attention">{t(fact, { device })}</p>
        {step === null ? null : <p className="text-hint text-balance text-muted">{t(step)}</p>}
      </div>
    </div>
  );
}

/** Says once per request and change whether «Разрешить» is offered, and why not. */
function useOfferLog(requestId: string, offer: AllowOffer) {
  const said = offer.kind === "allow" ? "offered" : `not offered (${offer.gives})`;
  useEffect(() => {
    // biome-ignore lint/suspicious/noConsole: once per request and change of the offer
    console.debug(`[pair] request ${requestId}: «Разрешить» ${said}`);
  }, [requestId, said]);
}

/** The key line's text per device line (`{device}` where the string has it). */
const MAIN = {
  trusted: "app.pairTrustedDevice",
  again: "app.pairTrustedAgain",
  unconfirmed: "app.pairUnconfirmed",
  unconfirmed_again: "app.pairUnconfirmed",
  no_key: "app.pairNoKey",
  not_trusted: "app.pairNotTrustedSession",
  added: "app.trustedAttemptAdded",
  listed_waiting: "app.pairListedWaiting",
  // Observe: «Разрешить» binds, but the list writes no key — its cause, never «Станет доверенным».
  other_person: "app.trustedAttemptOtherPerson",
  list_full: "app.trustedFull",
  list_unavailable: "app.trustedHomeDamaged",
} as const satisfies Record<Exclude<DeviceLine, "none">, string>;

/** A small line under it: what «Разрешить» means for the owner. */
type Note = { key: NoteKey; attention: boolean };

const UNCONFIRMED_NOTE: Note = { key: "app.pairUnconfirmedAbout", attention: false };

/** The small lines under the key line, in order. */
const NOTES: Partial<Record<Exclude<DeviceLine, "none">, readonly Note[]>> = {
  unconfirmed: [UNCONFIRMED_NOTE],
  unconfirmed_again: [UNCONFIRMED_NOTE],
  not_trusted: [{ key: "app.pairNotTrustedSessionAbout", attention: false }],
  listed_waiting: [{ key: "app.pairListedConfirm", attention: false }],
};

type NoteKey =
  | "app.pairUnconfirmedAbout"
  | "app.pairNotTrustedSessionAbout"
  | "app.pairListedConfirm";

/**
 * «Удалено из доверенных: {when}» under the title: this request's key was removed at this PC
 * (`removed_here_at`, the time of its removed record of origin `pc`, the agent's reading). A fact:
 * it gates nothing and changes no other line.
 */

function RemovedHereLine({ request }: { request: PendingPairDto }) {
  const t = useT();
  const { locale } = useLanguage();
  const at = request.removed_here_at;
  useEffect(() => {
    // biome-ignore lint/suspicious/noConsole: once per request and change of the removal shown
    console.debug(
      `[pair] request ${request.request_id}: ${at === undefined ? "no removal at this PC to show" : `removed at this PC at ${at}: «Удалено из доверенных» under the title`}`,
    );
  }, [request.request_id, at]);
  if (at === undefined) return null;
  return (
    <p className="text-hint text-balance text-attention">
      {t("app.pairRemovedHere", { when: whenText(t, locale, at, Date.now()) })}
    </p>
  );
}

/** Which device line a request gets (`TrustedDeviceLine`): the agent's `device_line`. */
export type DeviceLine = DeviceLineName;

export function deviceLineOf(request: PendingPairDto): DeviceLine {
  // Device keys: the agent's reading of what the press does to the device — never worked out here.
  if (request.device_line !== undefined) return request.device_line;
  const state = request.key_state;
  // An older agent: the device line when it names the device, as before key states.
  if (state === undefined) return request.device ? "trusted" : "none";
  if (state === "absent" || state === "invalid") return "no_key";
  if (state === "not_trusted_session") return "not_trusted";
  const unconfirmed = request.will_be_unconfirmed === true;
  if (state === "was_removed") return unconfirmed ? "unconfirmed_again" : "again";
  return unconfirmed ? "unconfirmed" : "trusted";
}

/** The fact line of a request whose «Разрешить» is not offered (`allowOffer`). */
export type NoOfferFact =
  | "app.pairNoKey"
  | "app.pairNotTrustedSession"
  | "app.trustedAttemptOtherPerson"
  | "app.pairListClosed"
  | "app.pairListedWaiting";

/** What to do instead, under the fact line. */
export type NoOfferStep =
  | "app.pairNoKeyInvite"
  | "app.pairNoKeyOwner"
  | "app.pairNotTrustedSessionAbout"
  | "app.pairListedConfirm";

/**
 * Whether the window offers «Разрешить»: exactly when the agent says the press lets the person
 * connect (`allow_connects`, the core's one reading — never worked out here). Otherwise no primary
 * button: the fact and what to do for what the press gives (`allow_gives`), and «Отклонить». An
 * older agent says nothing: offered, as before.
 */
export type AllowOffer =
  | { kind: "allow" }
  | { kind: "none"; gives: string; fact: NoOfferFact | null; step: NoOfferStep | null };

export function allowOffer(r: PendingPairDto): AllowOffer {
  if (r.allow_connects !== false) return { kind: "allow" };
  const gives = r.allow_gives ?? "-";
  return { kind: "none", gives, ...noOfferLines(r) };
}

/**
 * The lines of a request whose «Разрешить» is not offered, by what the press gives: one fact and at
 * most one step. Causes a person would act on alike share their lines — a session (during the
 * pairing, or a guest's now: try again with none), the list (full or unreadable: open «Доступ»).
 */
function noOfferLines(r: PendingPairDto): { fact: NoOfferFact | null; step: NoOfferStep | null } {
  switch (r.allow_gives) {
    case "no_key":
      // The owner tries again at this PC; a guest asks a trusted device of the owner's.
      return {
        fact: "app.pairNoKey",
        step: r.owner_here === true ? "app.pairNoKeyOwner" : "app.pairNoKeyInvite",
      };
    case "session":
      return { fact: "app.pairNotTrustedSession", step: "app.pairNotTrustedSessionAbout" };
    // The list refuses the key: nothing to try here.
    case "other_person":
      return { fact: "app.trustedAttemptOtherPerson", step: null };
    case "list_closed":
      return { fact: "app.pairListClosed", step: null };
    // Strict: the key is listed for the person and works after «Подтвердить» in «Доступ».
    case "listed_waiting":
      return { fact: "app.pairListedWaiting", step: "app.pairListedConfirm" };
    default:
      return { fact: null, step: null };
  }
}

/**
 * What is on screen, which the window's consent «Это моё устройство» is for: the request, its
 * generation in the window's slot (`shown` — another request under the same id is another one) and
 * the role the press carries. Any change — another request, the same id received again, another
 * role — is another key, and finds the box unticked for good.
 */
export function consentKeyOf(r: PendingPairDto): string {
  return `${r.request_id}:${r.shown ?? "-"}:${r.role ?? "-"}`;
}

/** Whether «Разрешить» leads to «Кто это?»: the agent's reading (`asks_role`), never the window's. */
export function asksRole(r: PendingPairDto): boolean {
  return r.asks_role === true;
}

/**
 * The step the window is at, from the agent's reading alone — the window keeps no step of its own:
 * «Кто это?» only while the agent asks the role and Rust's step (`step`, kept by the prompt for the
 * request and generation «Разрешить» was pressed on) says so. The role derived meanwhile (the
 * requester an owner on this PC now): back at the consent, its consent dropped (`consentTick`) —
 * never at «Кто это?» with its answers held.
 */
export function pairPhase(r: PendingPairDto): PairStep {
  return asksRole(r) && r.step === "role" ? "role" : "consent";
}

/** What an approving press sends besides the request and the answer. */
export interface PairAllowSend {
  secondStep: boolean;
  /** The owner's role, with «Это моё устройство» (`ownerStepShown`); else the role the window picks. */
  role?: BindingRole;
}

/**
 * Whether the request window shows the owner's line «Это устройство получит доступ владельца» and
 * the box «Это моё устройство»: the agent says the press writes an owner-role key
 * (`needs_owner_step`) and «Разрешить» is offered — the owner's role goes only with that step.
 * With no key written there is nothing to consent to.
 */
export function ownerStepShown(r: PendingPairDto): boolean {
  return r.needs_owner_step === true && allowOffer(r).kind === "allow";
}

/**
 * An approving press («Разрешить», or a role at «Кто это?»): what it sends, or why it is held — the
 * owner's second step when the window shows his box, else a plain press.
 */
export function pairAllowPress(
  r: PendingPairDto,
  ownerTicked = false,
): { send: PairAllowSend } | { held: string } {
  const offer = allowOffer(r);
  if (offer.kind === "none") {
    return {
      held: `«Разрешить» is not offered: it would not let the person connect (${offer.gives})`,
    };
  }
  if (ownerStepShown(r)) {
    return ownerTicked
      ? { send: { secondStep: true, role: "owner" } }
      : { held: "an owner on this PC and «Это моё устройство» is not ticked" };
  }
  // The role the agent derives; none while it is chosen at «Кто это?».
  const role: BindingRole | undefined = r.role ?? undefined;
  return { send: role ? { secondStep: false, role } : { secondStep: false } };
}

/** What an answer sends: a decline needs no step; an approval may wait for «Это моё устройство». */
function answerPress(
  request: PendingPairDto,
  accept: boolean,
  ownerTicked: boolean,
): { send: PairAllowSend } | { held: string } {
  return accept ? pairAllowPress(request, ownerTicked) : { send: { secondStep: false } };
}

/** How the press's step is said in the log. */
function stepSaid(step: PairAllowSend): string {
  return step.secondStep ? " with the second step «Это моё устройство»" : ", no second step";
}

/**
 * «Это моё устройство» for the request (`ownerStepShown`): ticked only for what is on screen
 * (`consentKeyOf`, kept by `useConsent`). `tick`: the press on the box (ignored while the answer
 * buttons wait).
 */
interface OwnerStep {
  shown: boolean;
  ticked: boolean;
  tick: (next: boolean, held: boolean) => void;
}

/**
 * An owner on this PC with a device line: in amber what «Разрешить» gives — the owner's access —
 * and under it the box «Это моё устройство», where the lines' icons stand.
 */
function OwnerBlock({
  ticked,
  disabled,
  onTick,
}: {
  ticked: boolean;
  disabled: boolean;
  onTick: (next: boolean) => void;
}) {
  const t = useT();
  return (
    <div className="flex flex-col text-body">
      <div className="flex items-start gap-2">
        <Crown className="mt-0.5 size-4 shrink-0 text-attention" aria-hidden="true" />
        <p className="min-w-0 flex-1 text-balance text-attention">{t("app.trustedAllowOwner")}</p>
      </div>
      <Checkbox checked={ticked} held={disabled} onCheckedChange={onTick}>
        {t("app.trustedAllowOwnerCheck")}
      </Checkbox>
    </div>
  );
}

/** How an answer is said in the log: «accept as owner», «decline». */
function answerSaid(accept: boolean, role: BindingRole | undefined): string {
  if (!accept) return "decline";
  return role === undefined ? "accept" : `accept as ${role}`;
}

/**
 * The window's consent «Это моё устройство» (`ownerStepShown`), kept only for what is on screen
 * (`consentKeyOf`: the request, its generation and the role) and dropped for good when it changes
 * (`consentTick`). A tick is ignored while the answer buttons wait.
 */
function useConsent(request: PendingPairDto): { own: OwnerStep } {
  const key = consentKeyOf(request);
  const [held, setHeld] = useState<ConsentTick>({ seen: key, ownerFor: null, dropped: null });
  // Another request, generation or role on screen: the consent given goes for good.
  const now = consentTick(held, key);
  if (now !== held) setHeld(now);
  const ownerShown = ownerStepShown(request);
  const ownerTicked = ownerShown && now.ownerFor === key;
  useConsentDropLog(key, now.dropped);
  useEffect(() => {
    if (!ownerShown) return;
    // biome-ignore lint/suspicious/noConsole: once per request it shows for
    console.debug(
      `[pair] request ${request.request_id} (shown ${request.shown ?? "-"}): the press writes an owner key — the owner's line and «Это моё устройство», «Разрешить» waits for it`,
    );
  }, [request.request_id, request.shown, ownerShown]);
  const ownerTick = (next: boolean, wait: boolean) => {
    if (wait || !ownerShown) return;
    // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
    console.debug(
      `[pair] «Это моё устройство» ${next ? "ticked" : "unticked"} on ${key}: «Разрешить» ${next ? "may go with the owner's role" : "waits"}`,
    );
    setHeld({ ...now, ownerFor: next ? key : null, dropped: null });
  };
  return { own: { shown: ownerShown, ticked: ownerTicked, tick: ownerTick } };
}

/**
 * The window's consent as it keeps it: what was on screen when it was last looked at (`seen`, a
 * `consentKeyOf`), what «Это моё устройство» was ticked for, and the key whose consent was just
 * dropped (for the log).
 */
export interface ConsentTick {
  seen: string;
  ownerFor: string | null;
  dropped: string | null;
}

/**
 * The consent as what is on screen (`key`) now finds it: unchanged for the same request,
 * generation and role — `pc_allow` coming or going changes none of them — and unticked for good
 * once anything of it changes, so a request coming back (A, then B, then A again; the same id
 * received again with another key; owner, guest, owner again) finds its box unticked.
 */
export function consentTick(tick: ConsentTick, key: string): ConsentTick {
  if (tick.seen === key) return tick;
  return { seen: key, ownerFor: null, dropped: tick.ownerFor !== null ? tick.seen : null };
}

/** A consent dropped because another request or role is on screen: once per change. */
function useConsentDropLog(key: string, dropped: string | null) {
  useEffect(() => {
    if (dropped === null) return;
    // biome-ignore lint/suspicious/noConsole: once per consent dropped
    console.debug(
      `[pair] a consent was given for ${dropped}; now ${key} is on screen: dropped, the box unticked`,
    );
  }, [dropped, key]);
}

/**
 * How long after «Кто это?» appears its buttons take no press: longer than the gap between the two
 * clicks of a double click (Windows' default double-click time is 500 ms), short enough that a
 * deliberate choice is never refused.
 */
const ROLE_ARM_MS = 500;

/** When the step `key` names was first drawn (`performance.now()`), kept until the key changes. */
function useStepSince(key: string): number {
  const since = useRef<{ key: string; at: number } | null>(null);
  if (since.current?.key !== key) since.current = { key, at: performance.now() };
  return since.current.at;
}

/**
 * The prompt's steps, said once per request and step: whether «Разрешить» will ask «Кто это?», and
 * that it does now. The window's console (devtools) only; Rust logs the decisions.
 */
function useRoleStepLog(request: PendingPairDto, at: PairStep) {
  const asks = request.asks_role === true;
  useEffect(() => {
    // biome-ignore lint/suspicious/noConsole: once per request and step
    console.debug(
      `[pair] request ${request.request_id}: step ${at}${at === "consent" ? (asks ? " — «Разрешить» asks «Кто это?» (the PC has no owner)" : " — no role question") : " — «Кто это?»: «Владелец» / «Гость»"}`,
    );
  }, [request.request_id, at, asks]);
}

/** A placeholder no name contains, to find where the name goes in the translated sentence. */
const SLOT = "\u0000";

function splitAround(text: string, slot: string): [string, string] {
  const at = text.indexOf(slot);
  return at < 0 ? [text, ""] : [text.slice(0, at), text.slice(at + slot.length)];
}

const NBSP = " ";

/**
 * The heading's action, after the name, with its short words held together by no-break spaces: a
 * one- or two-letter word goes with the word after it, and the last word with the one before it (an
 * action of one word is left as it is: nothing in it to hold, and the name stays apart from it).
 * «просит доступ к этому ПК» then breaks only before «к этому ПК», "is requesting access to this
 * PC" before "to this PC": no line ends in «к» or "to", and «ПК» / "PC" never stands alone. The
 * line balancing (`text-balance`) avoids that for a name with spaces, but not when one long name
 * breaks mid-word: «Константинопольская_Алексан / дрина просит доступ к этому / ПК» at 304 px (on
 * the UI stand). Rendering only, the dictionary string is
 * as written; the name is never touched.
 */
function keepShortWordsTogether(text: string): string {
  return text
    .replace(/(?<=^|\s)(\p{L}{1,2})\s+(?=\S)/gu, `$1${NBSP}`)
    .replace(/(?<=\S)\s+(\S+)\s*$/u, `${NBSP}$1`);
}

/**
 * Who is asking: the first name (else the @handle, else the #id), cut in the middle to `NAME_MAX`
 * (`shown`, «Кто это?»'s line; the heading fits it further, `useFittedName`), and for the
 * line under a first name what tells the person apart — the @handle, or the #id when there is none:
 * a first name is self-chosen, and «Мама» alone could be anyone (found by a security audit).
 * Rust cleans both names before they come (no bidi controls, no invisible characters). An agent that
 * sends only the ready-made `display_name` («Имя (@username)») still gets a prompt: that label, and
 * no second line.
 */
function requesterName(r: PendingPairDto): {
  name: { shown: string; full: string };
  handle: string | undefined;
} {
  const legacy = r.first_name === undefined && r.username === undefined;
  const full = legacy
    ? r.display_name
    : (r.first_name ?? (r.username ? `@${r.username}` : `#${r.telegram_user_id}`));
  const shown = cutMiddle(full, NAME_MAX);
  const handle = r.first_name
    ? r.username
      ? `@${r.username}`
      : `#${r.telegram_user_id}`
    : undefined;
  return { name: { shown, full }, handle };
}

/**
 * `full` in at most `max` characters, the ellipsis one of them, cut in the middle as every name is
 * (`MiddleEllipsis`): the start, «…», and the end — up to `NAME_TAIL_MAX` characters,
 * half the rest at most. By code points, so no surrogate pair is split; no space is left against
 * the ellipsis.
 */
function cutMiddle(full: string, max: number): string {
  const chars = Array.from(full);
  if (chars.length <= max) return full;
  const keep = Math.max(max - 1, 2);
  const tail = Math.min(NAME_TAIL_MAX, Math.floor(keep / 2));
  const head = keep - tail;
  return `${chars.slice(0, head).join("").trimEnd()}…${chars
    .slice(chars.length - tail)
    .join("")
    .trimStart()}`;
}

/**
 * The name as the heading spells it: `cutMiddle` to `NAME_MAX`, and shorter while «{name} просит
 * доступ к этому ПК» would not fit the heading's `TITLE_LINES` — so `line-clamp` never reaches the
 * action (the action is never cut, the name beside it is). At 150 % text a
 * 36-character name would need four lines (measured on the UI stand); with the first pairing's step
 * disc in the row, five. With the current words the stand cuts a 36-character name at 150 % to 32
 * (ru) / 24 (en) characters, and to 20 / 17 beside the disc; at 125 % only beside the disc (34 /
 * 35); at 100 % never.
 *
 * Measured, not guessed: a hidden copy of the heading at its width, unclamped, takes the longest
 * name that keeps it within the lines (a binary search on the length), before paint and again when
 * the heading's width changes (the text size, the window, fonts settling). `active`: the consent
 * step, the only one with the heading. Each change of the cut is one line in the console.
 */
function useFittedName(
  ref: RefObject<HTMLParagraphElement | null>,
  full: string,
  before: string,
  after: string,
  active: boolean,
): string {
  const [fit, setFit] = useState<{ full: string; max: number } | null>(null);
  const logged = useRef<string | null>(null);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!active || !el) return;
    const measure = () => {
      const width = el.clientWidth;
      const lineHeight = Number.parseFloat(window.getComputedStyle(el).lineHeight);
      if (width <= 0 || !Number.isFinite(lineHeight)) return;
      const probe = headingProbe(el, width);
      const fits = (max: number) => {
        probe.textContent = `${before}${cutMiddle(full, max)}${after}`;
        return probe.scrollHeight <= lineHeight * TITLE_LINES + 0.5;
      };
      const length = Array.from(full).length;
      const max = longestFitting(Math.min(length, NAME_MAX), fits);
      const whole = fits(max);
      probe.remove();
      setFit((was) => (was?.full === full && was.max === max ? was : { full, max }));
      const key = `${full}\u0000${max}\u0000${width}`;
      if (logged.current === key) return;
      logged.current = key;
      // biome-ignore lint/suspicious/noConsole: once per change of the heading's cut
      console.debug(
        max >= length
          ? `[pair] heading: the name whole (${length} characters) in ${width} px`
          : `[pair] heading: the name cut in the middle to ${max} of ${length} characters, so the action stays whole in ${TITLE_LINES} lines of ${width} px${whole ? "" : " (even the shortest cut needs more: line-clamp has the rest)"}`,
      );
    };
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => observer.disconnect();
  }, [ref, full, before, after, active]);
  const max = fit?.full === full ? fit.max : NAME_MAX;
  return cutMiddle(full, max);
}

/**
 * A hidden, unclamped copy of the heading `el` at `width`, beside it (the same classes, so the same
 * font, size and wrapping): what `useFittedName` measures. The caller removes it.
 */
function headingProbe(el: HTMLElement, width: number): HTMLElement {
  const probe = el.cloneNode(false) as HTMLElement;
  probe.removeAttribute("id");
  probe.setAttribute("aria-hidden", "true");
  Object.assign(probe.style, {
    position: "absolute",
    visibility: "hidden",
    pointerEvents: "none",
    top: "0",
    left: "0",
    width: `${width}px`,
    display: "block",
    overflow: "visible",
    WebkitLineClamp: "unset",
  });
  el.parentElement?.appendChild(probe);
  return probe;
}

/** The longest length up to `max` that `fits`, else `NAME_MIN` (a binary search below `max`). */
function longestFitting(max: number, fits: (max: number) => boolean): number {
  if (fits(max)) return max;
  let lo = NAME_MIN;
  let hi = max - 1;
  let best = NAME_MIN;
  while (lo <= hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (fits(mid)) {
      best = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return best;
}

/**
 * The request's time left: a thin amber bar that shrinks from the right, and the same as a clock,
 * «1:47», at its end. `scaleX` rather than `width`, so the per-second step is a composited
 * transform; reduced motion makes each step instant (`styles.css`). The clock is a `timer`: a
 * screen reader reads it when asked, and does not announce every second.
 *
 * `offline`: the link to the server is down, and the answer buttons wait for it — «Нет связи · 1:47»
 * at the bar's end, the hero's and the tray's words for it (`app.heroOffline`), a `status` read out
 * once as it appears. The time keeps running: the server's deadline holds. On the clock's line, so
 * the card keeps its height and the window is not resized for it.
 */
function Countdown({ secondsLeft, offline }: { secondsLeft: number; offline: boolean }) {
  const t = useT();
  return (
    <div className="flex items-center gap-3">
      <div aria-hidden="true" className="h-1 flex-1 overflow-hidden rounded-full bg-attention/15">
        <div
          className="h-full origin-left rounded-full bg-attention transition-transform duration-1000 ease-linear"
          style={{ transform: `scaleX(${pairTimeLeft(secondsLeft)})` }}
        />
      </div>
      <span className="shrink-0 text-hint text-muted tabular-nums">
        {offline ? <span role="status">{`${t("app.heroOffline")} · `}</span> : null}
        <span role="timer">{formatCountdown(secondsLeft)}</span>
      </span>
    </div>
  );
}

/**
 * The request's link as it changes — lost, back and waiting for the server's re-send, live again —
 * said once per change, with what the buttons do. The window's console (devtools) only; Rust logs the
 * request's kept/restored/closed steps.
 */
function useLinkLog(requestId: string, link: string) {
  const last = useRef<string | null>(null);
  useEffect(() => {
    const was = last.current;
    last.current = `${requestId}:${link}`;
    if (was === last.current) return;
    if (was === null && link === "live") return;
    // biome-ignore lint/suspicious/noConsole: once per change of the request's link
    console.debug(
      `[pair] request ${requestId}: link ${link}${link === "live" ? " — the buttons answer again" : link === "lost" ? " — «Нет связи», the buttons wait" : " — back, the buttons wait for the server's re-send"}`,
    );
  }, [requestId, link]);
}

/** Whether a request is drawn as a pairing step, said once per request (and change). */
function useStepLog(requestId: string, step: number | undefined) {
  useEffect(() => {
    // biome-ignore lint/suspicious/noConsole: once per request, with why
    console.debug(
      `[pair] request ${requestId}: ${step === undefined ? "someone has access, or who is not known — no step mark" : `the first pairing — marked as step ${step}`}`,
    );
  }, [requestId, step]);
}

/** A field the owner may be typing into: focus is not taken from it. */
function isEditable(el: Element | null): boolean {
  if (!(el instanceof HTMLElement)) return false;
  return (
    el instanceof HTMLInputElement ||
    el instanceof HTMLTextAreaElement ||
    el instanceof HTMLSelectElement ||
    el.isContentEditable
  );
}

/**
 * Focus a pairing prompt (`tabIndex={-1}`) once per request — the prompt, never a button.
 *
 * Consent safety: a key the owner meant for something else must not answer the request. On the
 * prompt, Enter and Space do nothing: a stray key neither allows nor declines (on «Отклонить» it
 * would still throw away a real request). Tab then reaches «Отклонить» first. The request window is
 * shown without taking focus at all (Rust), so there nothing typed elsewhere reaches it until the
 * owner clicks or Alt+Tabs into it — and then focus is on the prompt. Focus moving into the
 * alertdialog is also what has a screen reader read it, so no live region wraps the per-second
 * countdown.
 *
 * Not taken from a field the owner is typing in: the caret stays, and Tab reaches the prompt.
 *
 * Tried after each render until it takes; once taken, it is not taken again for the same request
 * and step.
 */
export function usePromptFocus(ref: RefObject<HTMLElement | null>, requestId: string): void {
  const focusedFor = useRef<string | null>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el || focusedFor.current === requestId) return;
    if (isEditable(document.activeElement) && !el.contains(document.activeElement)) {
      focusedFor.current = requestId;
      return;
    }
    el.focus();
    if (document.activeElement === el) focusedFor.current = requestId;
  });
}
