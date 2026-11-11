import { Crown, UserRound } from "lucide-react";
import { type RefObject, useEffect, useId, useLayoutEffect, useRef, useState } from "react";

import { useT } from "../i18n";
import {
  allowPair,
  type BindingRole,
  type PairStep,
  type PendingPairDto,
  respondPair,
  type StatusDto,
} from "../tauri";
import { formatCountdown, pairTimeLeft, useCountdown } from "../useAgentStatus";
import { initialOf } from "./ScreenGlyph";
import { StepDisc } from "./Steps";
import { Button } from "./ui/button";
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
 * under it — the #id when there is none; the time left as a thin amber bar with «1:47» at its end
 * (amber means this and nothing else in the app); Decline and Allow.
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
  // «Разрешить» pressed here, before Rust's step comes back with the next read.
  const [allowedHere, setAllowedHere] = useState<string | null>(null);
  const at: PairStep =
    request.step === "role" || allowedHere === request.request_id ? "role" : "consent";
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
    if (role !== undefined && sinceMs < ROLE_ARM_MS) {
      // biome-ignore lint/suspicious/noConsole: a press dropped on purpose, said once per press
      console.debug(
        `[pair] «${role}» pressed ${Math.round(sinceMs)} ms after «Кто это?» appeared: taken for the rest of a double click on «Разрешить», ignored`,
      );
      return;
    }
    setPending(true);
    respondPair(request.request_id, accept, role)
      .then(() => onAnswered?.())
      .catch((e: unknown) =>
        console.warn(
          `[ipc] respond_pair ${accept ? `accept${role ? ` as ${role}` : ""}` : "decline"} (${request.request_id}) failed: ${String(e)}`,
        ),
      )
      .finally(() => setPending(false));
  };

  const allow = () => {
    if (!request.asks_role) {
      answer(true);
      return;
    }
    if (pending) return;
    if (!live) {
      // biome-ignore lint/suspicious/noConsole: a press dropped on purpose, said once per press
      console.debug(
        `[pair] «Разрешить» on ${request.request_id} pressed while its link is ${link}: the step waits`,
      );
      return;
    }
    setPending(true);
    setAllowedHere(request.request_id);
    allowPair(request.request_id)
      .then((ok) => {
        if (!ok) {
          // Rust's log says why (withdrawn, or the PC has an owner after all); the next read shows
          // what is so.
          console.warn(`[pair] «Кто это?» not taken for ${request.request_id}: no longer pending`);
          setAllowedHere(null);
        }
        onAnswered?.();
      })
      .catch((e: unknown) => {
        console.warn(`[ipc] allow_pair (${request.request_id}) failed: ${String(e)}`);
        setAllowedHere(null);
      })
      .finally(() => setPending(false));
  };

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
          </div>
        )}
        {step === undefined ? null : <StepDisc n={step} size="card" tone="now" />}
      </div>
      <Countdown secondsLeft={secondsLeft} offline={link === "lost"} />
      {at === "role" ? (
        // Two equal choices, one kind of button: neither is the default, neither the quieter one.
        <div className="grid grid-cols-2 gap-2">
          <Button
            className="h-14 flex-col gap-1 [&_svg]:size-5"
            aria-disabled={held || undefined}
            onClick={() => answer(true, "owner")}
          >
            <Crown aria-hidden="true" />
            {t("role.owner")}
          </Button>
          <Button
            className="h-14 flex-col gap-1 [&_svg]:size-5"
            aria-disabled={held || undefined}
            onClick={() => answer(true, "guest")}
          >
            <UserRound aria-hidden="true" />
            {t("role.guest")}
          </Button>
        </div>
      ) : (
        <div className="flex gap-2">
          <Button
            className="flex-1"
            aria-disabled={held || undefined}
            onClick={() => answer(false)}
          >
            {t("app.pairDecline")}
          </Button>
          <Button
            variant="primary"
            className="flex-1"
            aria-disabled={held || undefined}
            onClick={allow}
          >
            {t("app.pairApprove")}
          </Button>
        </div>
      )}
    </div>
  );
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
