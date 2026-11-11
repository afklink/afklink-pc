import { Check, Loader2, type LucideIcon, X } from "lucide-react";

import { cn } from "../lib/utils";

/** The disc a step's number (or its state) sits in. */
const DISC =
  "mt-px flex size-5 shrink-0 items-center justify-center rounded-full font-small text-hint font-semibold tabular-nums";

/** Tonal lime: quieter than the action the steps lead to. */
const LIME = "bg-accent-dim text-accent";
const LIME_DISC = cn(DISC, LIME);

/** A neutral disc: a step that comes later, or a process stopped without a fault. */
const QUIET = "bg-white/8 text-muted";

/**
 * The discs' two sizes: `list` — 20px with an 11px number, by 13px text in the pairing dialog
 * (`Steps`); `card` — 28px with a 13px number, in the main view's card of steps (`StepsCard`) and
 * on the pairing request's «3» after them.
 */
const DISCS = {
  list: DISC,
  card: "flex size-7 shrink-0 items-center justify-center rounded-full text-body font-semibold tabular-nums",
} as const;

/**
 * Where a step stands for the person reading it: `now` — theirs to do now (a lime disc, the text in
 * ink); `later` — after those (a neutral disc, the text muted); `done` — known to be done (a lime
 * disc with ✓ in place of the number, as `ProgressSteps` marks one, the text muted). Only the main
 * view's card knows a step done: while a pairing request waits, someone entered the code, so 1 and 2
 * are (`home.steps`). The pairing dialog never does: nothing tells it a phone step is done until the
 * code is entered, and that closes it.
 */
export type StepTone = "now" | "later" | "done";

const TONES = {
  now: { disc: LIME, text: "text-ink", icon: "text-accent" },
  later: { disc: QUIET, text: "text-muted", icon: "text-muted" },
  done: { disc: LIME, text: "text-muted", icon: "text-muted" },
} as const;

export interface Step {
  text: string;
  tone: StepTone;
}

/**
 * A step's number in its disc — in the steps, and the pairing request's «3» at the first pairing
 * (`PairRequestPrompt`), so the request reads as the steps' last. A step done shows ✓ instead.
 */
export function StepDisc({
  n,
  size,
  tone,
}: {
  n: number;
  size: keyof typeof DISCS;
  tone: StepTone;
}) {
  return (
    <span aria-hidden="true" className={cn(DISCS[size], TONES[tone].disc)}>
      {tone === "done" ? (
        <Check className={size === "card" ? "size-4" : "size-3.5"} strokeWidth={3} />
      ) : (
        n
      )}
    </span>
  );
}

/**
 * Numbered steps, 1-2-3, a few words each — the rule for instructions, used only where the
 * content really is a sequence (first pairing on the main view, the pairing modal). The numbers
 * sit in tonal discs, like the Mini App's step markers but quieter, so the one bright thing on the
 * screen stays the action the steps lead to.
 *
 * One numbering through the whole first pairing: the steps that are the person's to do now are
 * lime, the ones after them neutral — and nothing moves (no blinking step). On the main view only
 * the first is lime («Начать привязку», the button under the card, `StepsCard`) — until a request
 * waits, when 1 and 2 are ticked and 3 is the one now; in the pairing dialog (this list) the two
 * done on the phone are, and the third (press «Разрешить» here) waits its turn — the request it
 * leads to carries the «3» itself. None is ticked here: nothing tells the window a phone step is
 * done until the code is entered, and that closes the dialog. No step is marked current for a
 * screen reader either (`aria-current`): two are the person's at once, and the list is read in its
 * order.
 */
export function Steps({ items, className }: { items: Step[]; className?: string }) {
  return (
    <ol className={cn("flex w-full flex-col gap-2 text-left", className)}>
      {items.map((step, i) => (
        <li
          key={step.text}
          className={cn("flex items-start gap-2.5 text-body", TONES[step.tone].text)}
        >
          <StepDisc n={i + 1} size="list" tone={step.tone} />
          <span className="min-w-0">{step.text}</span>
        </li>
      ))}
    </ol>
  );
}

/** A step of the main view's card: a step, and the small icon at its row's end. */
export interface CardStep extends Step {
  icon: LucideIcon;
  /**
   * The row is a link to where the step is done — step 3 while a pairing request waits: it brings
   * the request window forward. Absent: the row is text.
   */
  onPress?: (() => void) | undefined;
}

/** A row's insides, laid out the same whether the row is text or a link. */
const CARD_ROW = "flex w-full items-center gap-3 py-2 pr-3 pl-4";

/**
 * The main view's first-run steps as a card —
 * the same card as `HomeCard`'s rows after the first pairing: the panel, its border, radius and
 * dividers, rows of at least 52px with the same insets and the name's 13px. So the zone's turn from
 * the steps to the autostart question and to the four rows reads as one card going on.
 *
 * A row: the step's number in a 28px disc (✓ once done), the step, and a 16px icon at the end (the
 * chevron's place in `HomeCard`) — lime with the number for the step to do now, muted with the text
 * for the rest. A row is text, but for the one that is a link (`onPress`: step 3 while a request
 * waits, which brings the request window forward): a whole-row button, tinted on hover and with the
 * window's focus outline, like `HomeCard`'s rows, with the chevron at its end; the action of every
 * other moment is the button under the card. While a step is done, the one now is the list's
 * current step for a screen reader (`aria-current`); before that none is — two are the person's at
 * once. The card takes the height its parent gives it (`flex-1` there) and its rows share what their
 * content leaves of it (`flex-auto`), so the card and the button fill the zone between them; a row is
 * never shorter than `HomeCard`'s 52px, and a step that wraps keeps its own height rather than being
 * squeezed.
 */
export function StepsCard({ items, className }: { items: CardStep[]; className?: string }) {
  const anyDone = items.some((s) => s.tone === "done");
  return (
    <ol
      className={cn(
        "flex flex-col overflow-hidden rounded-card border border-line bg-panel text-left",
        className,
      )}
    >
      {items.map((step, i) => {
        const inside = (
          <>
            <StepDisc n={i + 1} size="card" tone={step.tone} />
            <span className="min-w-0 flex-1">{step.text}</span>
            <step.icon
              className={cn("size-4 shrink-0", TONES[step.tone].icon)}
              aria-hidden="true"
            />
          </>
        );
        return (
          <li
            key={step.text}
            aria-current={anyDone && step.tone === "now" ? "step" : undefined}
            className={cn(
              "flex min-h-13 flex-auto border-t border-line text-body first:border-t-0",
              TONES[step.tone].text,
            )}
          >
            {step.onPress ? (
              <button
                type="button"
                onClick={step.onPress}
                className={cn(
                  CARD_ROW,
                  "cursor-pointer text-left transition-colors hover:bg-white/4 focus-visible:-outline-offset-2",
                )}
              >
                {inside}
              </button>
            ) : (
              <div className={CARD_ROW}>{inside}</div>
            )}
          </li>
        );
      })}
    </ol>
  );
}

/**
 * Where a step of a running process is: not reached, happening now, finished, or where the process
 * ended without finishing it.
 */
export type StepState = "pending" | "active" | "done" | "stopped";

export interface ProgressStep {
  title: string;
  /** The second line: what to do, or what to expect. Absent when there is nothing useful to say. */
  hint?: string | undefined;
  state: StepState;
}

/**
 * The same steps, each with a hint line where it has one, that also show where a process is — one
 * list before it starts (all numbered: what will happen) and while it runs (where it is now). A
 * number until the step is reached, a spinner while it runs, ✓ when done, ✕ where the process
 * stopped: in Cut when it failed (`stopTone="danger"`), neutral when it was cancelled or is waiting
 * for something.
 */
export function ProgressSteps({
  items,
  stopTone = "neutral",
  className,
}: {
  items: ProgressStep[];
  stopTone?: "neutral" | "danger";
  className?: string;
}) {
  return (
    <ol className={cn("flex w-full flex-col gap-3 text-left", className)}>
      {items.map((step, i) => (
        <li
          key={step.title}
          aria-current={step.state === "active" ? "step" : undefined}
          className="flex items-start gap-2.5"
        >
          <StepMark n={i + 1} state={step.state} stopTone={stopTone} />
          <div className="min-w-0">
            <p className="text-body text-ink">{step.title}</p>
            {/* Balanced: a two-line hint splits at its middle, not before a last lone word. */}
            {step.hint ? <p className="text-balance text-hint text-faint">{step.hint}</p> : null}
          </div>
        </li>
      ))}
    </ol>
  );
}

function StepMark({
  n,
  state,
  stopTone,
}: {
  n: number;
  state: StepState;
  stopTone: "neutral" | "danger";
}) {
  switch (state) {
    case "pending":
      return (
        <span aria-hidden="true" className={LIME_DISC}>
          {n}
        </span>
      );
    case "active":
      return (
        <span aria-hidden="true" className={LIME_DISC}>
          <Loader2 className="size-3.5 animate-spin motion-reduce:animate-none" />
        </span>
      );
    case "done":
      return (
        <span aria-hidden="true" className={LIME_DISC}>
          <Check className="size-3.5" strokeWidth={3} />
        </span>
      );
    case "stopped":
      return (
        <span
          aria-hidden="true"
          className={cn(DISC, stopTone === "danger" ? "bg-danger-dim text-danger" : QUIET)}
        >
          <X className="size-3.5" strokeWidth={3} />
        </span>
      );
  }
}
