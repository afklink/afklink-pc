import type { TranslationKey } from "@afklink/i18n/pc";
import { Check, Clock, Loader2, Send, TriangleAlert } from "lucide-react";
import { type ReactNode, type RefObject, useEffect, useRef, useState } from "react";
import { useT } from "../i18n";
import { cn } from "../lib/utils";
import { sendLogs } from "../tauri";
import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";
import { Textarea } from "./ui/input";
import { Spinner } from "./ui/spinner";

/**
 * «Что случилось?»: the contract's 500 characters. The field counts UTF-16 units, which is if
 * anything stricter than the characters Rust and the server count.
 */
const COMMENT_MAX = 500;

/**
 * Where a report is. `idle`: nothing on its way — the dialog is the form. `failed` offers
 * «Повторить» with the comment kept; `sent` and `too_often` are over, with one button to close.
 */
export type SendLogsState =
  | { kind: "idle" }
  | { kind: "sending" }
  | { kind: "sent"; reportId: string | null }
  | { kind: "failed" }
  /** `until`: when the server said to try again, ms since the epoch; null when it did not say. */
  | { kind: "too_often"; until: number | null };

type Kind = SendLogsState["kind"];

const IDLE: SendLogsState = { kind: "idle" };
const SENDING: SendLogsState = { kind: "sending" };

export interface SendLogsModel {
  state: SendLogsState;
  /** The dialog is up. Closing it does not stop a report on its way. */
  open: boolean;
  comment: string;
  setComment: (comment: string) => void;
  /**
   * Open the dialog: the form, or where the report is if one is on its way or ended unseen.
   * `sessionId`: the report is about that session (a journal entry's «Отправить логи») — its log
   * goes in first.
   */
  show: (sessionId?: string) => void;
  /** Close the dialog; `why` (the ✕, Esc, «Отмена»…) is for the console. */
  hide: (why: string) => void;
  send: () => void;
}

/** The dialog's decisions, to the window's console (devtools). Rust's log has the report itself. */
function debug(line: string): void {
  // biome-ignore lint/suspicious/noConsole: the dialog's decisions; never the comment's text
  console.debug(`[diagnostics] ${line}`);
}

/**
 * The report on its way, for the whole window. A model belongs to the view that holds it — Settings'
 * Diagnostics, or the journal, whose entries send theirs with that session's log first — and goes
 * with it; a view opened again while a report still goes follows this one to its end rather than
 * offer a second, which Rust would refuse («a report is already being sent») and the dialog would
 * then call «Не отправлено».
 */
let pending: Promise<SendLogsState> | null = null;

/**
 * Start a report: Rust packs the logs and sends them (`send_logs`) and logs every step and how it
 * ended, the comment's length and never its text. Resolves with the dialog's next state; never
 * rejects.
 */
function startReport(comment: string, sessionId: string | null): Promise<SendLogsState> {
  const report = sendLogs(comment, sessionId)
    .then((result): SendLogsState => {
      switch (result.outcome) {
        case "sent":
          debug(`sent (report ${result.report_id ?? "-"})`);
          return { kind: "sent", reportId: result.report_id };
        case "too_often":
          debug(`too often: the server says to wait ${result.retry_after_s ?? "?"} s`);
          return {
            kind: "too_often",
            until: result.retry_after_s === null ? null : Date.now() + result.retry_after_s * 1000,
          };
        case "failed":
          console.warn(
            `[diagnostics] logs not sent: ${result.failure ?? "?"} (the app log says why)`,
          );
          return { kind: "failed" };
      }
    })
    .catch((e: unknown): SendLogsState => {
      console.warn(`[ipc] send_logs failed: ${String(e)}`);
      return { kind: "failed" };
    })
    .finally(() => {
      if (pending === report) pending = null;
    });
  pending = report;
  return report;
}

/**
 * The report's state, held by the Diagnostics section rather than by the dialog: closing the dialog
 * while a report goes (the ✕, Esc, a press outside) only hides it — Rust cannot stop a report
 * halfway, so the report goes on, Rust logs how it ended, and the dialog opened again shows it.
 * Closed after an outcome, the dialog starts over: «Отправлено» clears the comment; «Не
 * отправлено» keeps it for the next try; «Попробуй позже» stays until the server's time to wait
 * has passed, so the dialog opened again meanwhile says why rather than offer «Отправить».
 */
export function useSendLogs(): SendLogsModel {
  const [state, setState] = useState<SendLogsState>(() => (pending === null ? IDLE : SENDING));
  const [open, setOpen] = useState(false);
  const [comment, setComment] = useState("");
  // The session the dialog was opened for (a journal entry), whose log goes in first.
  const [sessionId, setSessionId] = useState<string | null>(null);
  // Read by a report's end, which may come after several renders.
  const openRef = useRef(open);
  openRef.current = open;
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const follow = (report: Promise<SendLogsState>) => {
    void report.then((next) => {
      if (!mounted.current) {
        debug(`the report ended (${next.kind}) after Settings closed: nothing on screen to update`);
        return;
      }
      if (!openRef.current) {
        debug(`the report ended (${next.kind}) with the dialog closed: shown when it opens again`);
      }
      setState(next);
    });
  };

  // A report started from an earlier Settings view (see `pending`): follow it to its end.
  // biome-ignore lint/correctness/useExhaustiveDependencies: once, on mount
  useEffect(() => {
    if (pending === null) return;
    debug("a report started earlier is still on its way: following it");
    follow(pending);
  }, []);

  // «Попробуй позже» with the server's time: over when it has passed, and the form is back.
  useEffect(() => {
    if (state.kind !== "too_often" || state.until === null) return;
    const ms = Math.max(0, state.until - Date.now());
    const timer = window.setTimeout(() => {
      debug("the server's time to wait has passed: the form is back");
      setState(IDLE);
    }, ms);
    return () => window.clearTimeout(timer);
  }, [state]);

  const show = (forSession?: string) => {
    if (open) return;
    debug(
      `dialog opened (${state.kind})${forSession ? ` for session ${forSession}: its log goes first` : ""}`,
    );
    setSessionId(forSession ?? null);
    setOpen(true);
  };

  const hide = (why: string) => {
    if (!open) return;
    setOpen(false);
    switch (state.kind) {
      case "sending":
        debug(`dialog closed (${why}) while the report goes: it goes on, Rust logs how it ends`);
        return;
      case "sent":
        setComment("");
        setState(IDLE);
        break;
      case "failed":
        // The comment stays for the next try.
        setState(IDLE);
        break;
      case "too_often":
        // Without a time from the server nothing is gated: the next open is the form.
        if (state.until === null) setState(IDLE);
        break;
      case "idle":
        break;
    }
    debug(`dialog closed (${why}), ${state.kind}`);
  };

  const send = () => {
    if (pending !== null) {
      debug("«Отправить» while a report is on its way: ignored");
      return;
    }
    if (state.kind !== "idle" && state.kind !== "failed") {
      debug(`«Отправить» in ${state.kind}: ignored`);
      return;
    }
    // The length only: the comment's text is the owner's and goes nowhere but the report.
    debug(
      `${state.kind === "failed" ? "«Повторить»" : "«Отправить»"} pressed (comment: ${comment.trim().length} chars, session first: ${sessionId ?? "-"})`,
    );
    setState(SENDING);
    follow(startReport(comment, sessionId));
  };

  return { state, open, comment, setComment, show, hide, send };
}

/**
 * «Отправить логи» in Settings → Diagnostics: a secondary button that opens the dialog. While a
 * report is on its way with the dialog closed, a spinner stands in for its icon; the press opens
 * the dialog on it.
 *
 * `offTitle`: nothing is written (the log is off), so there is nothing to send — the button stays in
 * place, disabled, and these words («Логи выключены») are its tooltip. A disabled button takes no
 * pointer (`Button`'s disabled look), so the tooltip is on a box around it that takes its place in
 * the row (`className`), the button filling it.
 */
export function SendLogsButton({
  model,
  className,
  offTitle = null,
}: {
  model: SendLogsModel;
  className?: string;
  offTitle?: string | null;
}) {
  const t = useT();
  const off = offTitle !== null;
  const button = (
    <Button
      size="sm"
      className={off ? "w-full" : className}
      aria-haspopup="dialog"
      disabled={off}
      onClick={() => model.show()}
    >
      {model.state.kind === "sending" ? (
        <Loader2
          aria-hidden="true"
          className="animate-spin text-faint motion-reduce:animate-none"
        />
      ) : (
        <Send aria-hidden="true" />
      )}
      {t("app.sendLogs")}
    </Button>
  );
  return off ? (
    <span className={cn("flex", className)} title={offTitle ?? undefined}>
      {button}
    </span>
  ) : (
    button
  );
}

/** The words over the buttons once the form has gone, by state. */
const STAGE_TEXT = {
  sending: "app.sendLogsSending",
  sent: "app.sendLogsSent",
  failed: "app.sendLogsFailed",
  too_often: "app.sendLogsTooOften",
} satisfies Record<Exclude<Kind, "idle">, TranslationKey>;

/** A round badge for an outcome's mark: 40 px, tonal, like the steps' discs. */
const BADGE = "flex size-10 items-center justify-center rounded-full [&_svg]:size-5";

function stageMark(kind: Exclude<Kind, "idle">): ReactNode {
  switch (kind) {
    case "sending":
      return (
        <span className="flex size-10 items-center justify-center">
          <Spinner />
        </span>
      );
    case "sent":
      return (
        <span className={cn(BADGE, "bg-accent-dim text-accent")}>
          <Check aria-hidden="true" />
        </span>
      );
    case "failed":
      return (
        <span className={cn(BADGE, "bg-danger-dim text-danger")}>
          <TriangleAlert aria-hidden="true" />
        </span>
      );
    case "too_often":
      return (
        <span className={cn(BADGE, "bg-white/6 text-muted")}>
          <Clock aria-hidden="true" />
        </span>
      );
  }
}

/**
 * The dialog: the optional «Что случилось?» (focused on open; Enter is a new line, Ctrl+Enter
 * sends) over «Отмена» / «Отправить». Once pressed, the field's place shows where the report is —
 * the lime loader with «Отправка…», then «Отправлено» (the report id in its tooltip: the log has it
 * and the developer gets it with the report) with «Готово», «Не отправлено» with «Отмена» /
 * «Повторить», or «Попробуй позже» with «Закрыть». That place is the field's own grid cell, so the
 * dialog keeps one size throughout and nothing moves under the pointer; it is the live region too,
 * in the document from the start, so a screen reader hears each step.
 *
 * The ✕, Esc and a press outside close it before sending (a cancel) and while sending (the report
 * goes on; see `useSendLogs`); «Отмена» is off while sending, since it cannot cancel anything then.
 * The focus goes where the one thing to do or hear is — the field; while the report goes, the
 * progress itself (a screen reader reads «Отправка…»; no focus ring round a button that is off);
 * «Повторить», «Готово», «Закрыть» — and back to «Отправить логи» when the dialog closes (`Dialog`).
 */
export function SendLogsDialog({ model }: { model: SendLogsModel }) {
  const t = useT();
  const fieldRef = useRef<HTMLTextAreaElement>(null);
  const stageRef = useRef<HTMLDivElement>(null);
  const primaryRef = useRef<HTMLButtonElement>(null);
  const overRef = useRef<HTMLButtonElement>(null);
  const { state, open, comment, setComment, hide, send } = model;
  const kind = state.kind;
  const focusFor = (k: Kind): RefObject<HTMLElement | null> => {
    switch (k) {
      case "idle":
        return fieldRef;
      case "sending":
        return stageRef;
      case "failed":
        return primaryRef;
      case "sent":
      case "too_often":
        return overRef;
    }
  };

  // A change of state with the dialog up: the focus follows to the one action it leaves (the field
  // is hidden while the report goes, and the buttons that had it are gone once it is over). On open
  // the dialog itself places it (`initialFocus`).
  const shown = useRef<Kind | null>(null);
  // biome-ignore lint/correctness/useExhaustiveDependencies: `focusFor` reads refs only
  useEffect(() => {
    const was = shown.current;
    shown.current = open ? kind : null;
    if (!open || was === null || was === kind) return;
    focusFor(kind).current?.focus();
  }, [open, kind]);

  if (!open) return null;

  const form = kind === "idle";
  const over = kind === "sent" || kind === "too_often";

  return (
    <Dialog title={t("app.sendLogs")} onClose={hide} initialFocus={focusFor(kind)}>
      <div className="grid">
        <Textarea
          ref={fieldRef}
          rows={4}
          maxLength={COMMENT_MAX}
          placeholder={t("app.sendLogsComment")}
          aria-label={t("app.sendLogsComment")}
          spellCheck={false}
          value={comment}
          // Hidden, not removed, once pressed: the cell keeps the field's height for what follows.
          // Disabled as well, so the dialog's Tab trap, which counts laid-out fields, skips it.
          disabled={!form}
          className={cn("col-start-1 row-start-1", !form && "invisible")}
          onChange={(e) => setComment(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
              e.preventDefault();
              send();
            }
          }}
        />
        {/* Takes focus while the report goes (never by Tab): the progress is what there is then. */}
        <div
          ref={stageRef}
          role="status"
          tabIndex={-1}
          className={cn(
            "col-start-1 row-start-1 flex flex-col items-center justify-center gap-2 text-center outline-none",
            form && "pointer-events-none",
          )}
        >
          {state.kind === "idle" ? null : (
            <>
              {stageMark(state.kind)}
              <p
                className={cn("text-body", state.kind === "sending" ? "text-muted" : "text-ink")}
                title={state.kind === "sent" ? (state.reportId ?? undefined) : undefined}
              >
                {t(STAGE_TEXT[state.kind])}
              </p>
            </>
          )}
        </div>
      </div>
      <div className="mt-4 flex gap-2">
        {over ? (
          <Button
            ref={overRef}
            variant={kind === "sent" ? "primary" : "secondary"}
            className="flex-1"
            onClick={() => hide(kind === "sent" ? "«Готово»" : "«Закрыть»")}
          >
            {kind === "sent" ? t("common.done") : t("common.close")}
          </Button>
        ) : (
          <>
            <Button
              className="flex-1"
              disabled={kind === "sending"}
              onClick={() => hide("«Отмена»")}
            >
              {t("common.cancel")}
            </Button>
            <Button
              ref={primaryRef}
              variant="primary"
              className="flex-1"
              aria-disabled={kind === "sending" || undefined}
              onClick={send}
            >
              {kind === "failed" ? t("common.retry") : t("app.sendLogsSend")}
            </Button>
          </>
        )}
      </div>
    </Dialog>
  );
}
