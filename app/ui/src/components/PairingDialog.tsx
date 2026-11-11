import { Check, Copy, Loader2, RotateCw, WifiOff } from "lucide-react";
import { useCallback, useEffect, useId, useRef, useState } from "react";

import { useT } from "../i18n";
import { cn } from "../lib/utils";
import { type PairingCloseReason, requestPairing, type StatusDto } from "../tauri";
import { Steps } from "./Steps";
import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";

/** A code normally arrives well inside a second; after this long the loader gives way to Retry. */
const CODE_WAIT_MS = 10_000;

/** How long a copy shows its ✓ (the code's also «Скопировано»): the code's and the link's alike. */
const COPIED_MS = 1500;

/**
 * The code: 40px Segoe UI Variable Display with tabular figures, so any six digits measure the same
 * (the skeleton's box), in Bone — typography carries it, not the accent, which would read as a
 * link. The two groups of three are one string with a wider word space; a click copies the six
 * digits with no space («482913»), which pastes into any field.
 */
const CODE_TEXT =
  "font-display text-code font-semibold tabular-nums tracking-[0.02em] [word-spacing:0.25em]";

/**
 * The code's row, the same box with the code and with its skeleton: 44px tall (the code's line),
 * and as wide as the digits plus a 16px slot on each side — the copy icon on the right, an empty
 * slot balancing it on the left, so the digits stay on the dialog's centre line. The button's own
 * 1px (transparent) border is in the skeleton's row too, so the two measure the same.
 */
const CODE_ROW =
  "inline-flex h-11 items-center justify-center gap-3 border border-transparent px-3";
const ICON_SLOT = "size-4 shrink-0";

/**
 * The QR (168px) inside its 10px white padding — on a short window (`short:`, under 560px tall) the
 * QR is 112px in 8px, so the panel fits the 480px minimum without scrolling. Every state keeps this
 * box, so nothing moves. At 120px the Russian panel is 8px too tall at 340×480 once the first step
 * wraps («Открой AFKLink в Telegram или браузере»), and it scrolls; 112px still scans from a phone
 * held to the screen.
 */
const QR_FRAME =
  "flex size-[188px] shrink-0 items-center justify-center rounded-control short:size-[128px]";
const QR_IMAGE = "block size-[168px] short:size-[112px]";
const QR_PLACEHOLDER = cn(QR_FRAME, "border border-line bg-recessed");

/**
 * What the panel shows. `code`: the digits and the QR. `waiting`: the code is on its way.
 * `offline`: signaling is down, the code died with the connection, and the agent asks for a new
 * one when it is back. `stalled`: nothing came within `CODE_WAIT_MS`.
 */
type View = "code" | "waiting" | "offline" | "stalled";

/**
 * Pairing as a modal, not a card in the scroll.
 *
 * Closed by default — a security property: a live code left on screen also sits
 * in the video stream of anyone already connected. Opening mints the code,
 * closing invalidates it immediately. Digits grouped three-and-three so they
 * read back over the phone the way the Mini App shows them.
 *
 * Top to bottom: the code and «Действует, пока окно
 * открыто», the QR, «Скопировать ссылку» right under it — the other way in for the same link — and
 * the three steps. Under 560px of window height the QR shrinks, so the panel fits the 340×480
 * minimum without scrolling.
 *
 * The code is a button with a copy icon beside the digits: a click on the
 * digits or the icon copies the six digits, for the website on this PC or a message to someone —
 * the link opens Telegram, which covers neither. For 1.5s after a copy the icon is a ✓ and the hint
 * line says «Скопировано» in place of «Действует, пока окно открыто»; the code's ✓ and the link's
 * are separate. A clipboard that refuses shows neither — the digits are still there to type.
 *
 * The steps are numbered because they are a sequence — the same steps the Mini
 * App shows, from this side: open AFKLink, enter the code (or scan the QR), press «Разрешить» here.
 * The two done on the phone are lime — the person's to do now — and still: nothing in the list
 * blinks. The third is neutral: it is not the person's turn until the request
 * comes, and the request's card then carries that «3» itself (`PairRequestPrompt`). Nothing here is
 * ticked: the window cannot know AFKLink was opened on the phone, and the code entered closes the
 * panel. «Пока окно открыто» only once there is a code to be valid.
 *
 * One layout for every `View`, so nothing jumps when the code arrives: the code line (its icon's
 * slots included, `CODE_ROW`), its hint line and the QR frame keep their size, and only what is
 * inside them changes — a skeleton where the digits go, no icon, and a loader in the frame while the
 * code is on its way.
 *
 * A code without a link is the one other shape: the agent knows no bot to link to (an older
 * backend, none configured) or could not render the QR, and says which in its log. No QR is coming
 * then, so the panel shows the code alone — no QR frame, step two without the QR, and no «copy
 * link» when there is no link to copy.
 *
 * The window closes the panel when someone enters the code or a binding is made while it is open
 * (`App`), and here when the code's ceiling passes. Each close tells the agent why, for its log.
 */
export function PairingDialog({
  status,
  onClose,
}: {
  status: StatusDto;
  onClose: (reason: PairingCloseReason) => void;
}) {
  const t = useT();
  const codeCopy = useCopied();
  const linkCopy = useCopied();
  const code = status.pairing_code;
  const qr = code === null ? null : status.qr_svg;
  const wait = useCodeWait(status.connected && code === null);
  const view: View =
    code !== null ? "code" : !status.connected ? "offline" : wait.stalled ? "stalled" : "waiting";
  useCeiling(code, status.pairing_expires_at, onClose);

  // The digits alone, no space: «482913» goes into any field.
  const copyCode = (digits: string) => void copyText("code", digits, codeCopy.flash);
  const copyLink = () => {
    if (status.deep_link) void copyText("link", status.deep_link, linkCopy.flash);
  };

  const retry = () => {
    requestPairing("retry").catch((e: unknown) =>
      console.warn(`[ipc] request_pairing (retry) failed: ${String(e)}`),
    );
    wait.restart();
  };

  // A code without a QR: none is coming, so the frame goes (see the doc above).
  const qrArea = view !== "code" || qr !== null;
  // «Copy link» waits, disabled, for the code; with a code and no link it goes.
  const copyButton = view !== "code" || status.deep_link !== null;

  return (
    <Dialog title={t("pair.title")} onClose={() => onClose("closed")} wide>
      <div className="flex flex-col items-center text-center">
        <CodeLines
          code={code}
          pulsing={view === "waiting"}
          copied={codeCopy.copied}
          onCopy={copyCode}
        />

        {qrArea ? (
          <div className="mt-4">
            <QrFrame view={view} qr={qr} onRetry={retry} />
          </div>
        ) : null}

        {copyButton ? (
          <Button
            variant="ghost"
            size="sm"
            className="mt-2"
            onClick={copyLink}
            disabled={!status.deep_link}
          >
            {linkCopy.copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
            {linkCopy.copied ? t("app.copied") : t("app.copyLink")}
          </Button>
        ) : null}
      </div>

      <Steps
        className="mt-4"
        items={[
          { text: t("app.stepOpenApp"), tone: "now" },
          { text: qrArea ? t("app.stepCodeOrQr") : t("app.stepCode"), tone: "now" },
          { text: t("app.stepAllow", { button: t("app.pairApprove") }), tone: "later" },
        ]}
      />
      {/* Either copy, said once: the code's and the link's «Скопировано». */}
      <span className="sr-only" aria-live="polite">
        {codeCopy.copied || linkCopy.copied ? t("app.copied") : ""}
      </span>
    </Dialog>
  );
}

/**
 * Write `text` to the clipboard, then `flash` its ✓. A refusal (the clipboard denied) shows no ✓
 * and no «Скопировано» and says why in the window's console (devtools only, like every line of
 * this window's: nothing of it reaches the agent's log). Neither line carries what was copied — the
 * code is a secret while it lives, and the link carries it too.
 */
async function copyText(what: "code" | "link", text: string, flash: () => void): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    flash();
    // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
    console.debug(`[clipboard] pairing ${what} copied (${text.length} characters)`);
  } catch (e) {
    console.warn(`[clipboard] pairing ${what} not copied: ${String(e)}`);
  }
}

/**
 * A copy's ✓: `copied` for `COPIED_MS` after each `flash` — a second copy inside that starts the
 * wait again rather than being cut short by the first one's timer.
 */
function useCopied(): { copied: boolean; flash: () => void } {
  const [copied, setCopied] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const flash = useCallback(() => {
    window.clearTimeout(timer.current);
    setCopied(true);
    timer.current = window.setTimeout(() => setCopied(false), COPIED_MS);
  }, []);
  return { copied, flash };
}

/**
 * The code's two lines: the code and its hint.
 *
 * The six digits are one button that copies them — a click on the digits or on the copy icon beside
 * them — or, while they are on their way, a skeleton of their exact size in the same row
 * (`CODE_ROW`), with no icon and nothing to press. A screen reader gets the button as «Скопировать
 * 4 8 2 9 1 3»: the digits one by one, read back as the owner would read them out, then the hint
 * line as its description. The digits stay Bone, the icon is Ash and turns Bone with the hover,
 * like the ghost «Скопировать ссылку» under the QR; `title` says «Скопировать» to the mouse.
 *
 * The hint is kept, empty, until there is a code, so the frame under it does not move. For 1.5s
 * after the code is copied the same line says «Скопировано»: one line, one size, nothing moves.
 */
function CodeLines({
  code,
  pulsing,
  copied,
  onCopy,
}: {
  code: string | null;
  pulsing: boolean;
  copied: boolean;
  onCopy: (digits: string) => void;
}) {
  const t = useT();
  const hintId = useId();
  const Icon = copied ? Check : Copy;
  return (
    <>
      {code === null ? (
        <div className={cn(CODE_ROW, CODE_TEXT)} aria-hidden="true">
          <span className={ICON_SLOT} />
          <span className="relative inline-block">
            <span className="invisible">000 000</span>
            <span
              className={cn(
                "absolute inset-x-0 inset-y-1 rounded-control bg-white/8",
                pulsing && "animate-pulse motion-reduce:animate-none",
              )}
            />
          </span>
          <span className={ICON_SLOT} />
        </div>
      ) : (
        <Button
          variant="ghost"
          className={cn(CODE_ROW, CODE_TEXT, "group text-ink")}
          title={t("app.copyId")}
          aria-describedby={hintId}
          onClick={() => onCopy(code)}
          translate="no"
        >
          <span className={ICON_SLOT} aria-hidden="true" />
          <span className="sr-only">{`${t("app.copyId")} ${Array.from(code).join(" ")}`}</span>
          <span aria-hidden="true">
            {code.slice(0, 3)} {code.slice(3)}
          </span>
          <Icon aria-hidden="true" className="text-muted transition-colors group-hover:text-ink" />
        </Button>
      )}
      <p
        id={hintId}
        className={cn("mt-1 text-hint text-faint", code === null && "invisible")}
        aria-hidden={code === null}
      >
        {copied ? t("app.copied") : t("app.codeExpires")}
      </p>
    </>
  );
}

/** The QR's frame: the QR, or what stands in for it until the code comes. */
function QrFrame({ view, qr, onRetry }: { view: View; qr: string | null; onRetry: () => void }) {
  const t = useT();
  switch (view) {
    case "code":
      // Without a QR the caller shows no frame at all.
      return qr === null ? null : (
        <div className={cn(QR_FRAME, "bg-white")}>
          <img src={qr} alt={t("app.qrAlt")} width={168} height={168} className={QR_IMAGE} />
        </div>
      );
    case "waiting":
      return (
        <div role="status" aria-label={t("common.loading")} className={QR_PLACEHOLDER}>
          <Loader2
            className="size-6 animate-spin text-faint motion-reduce:animate-none"
            aria-hidden="true"
          />
        </div>
      );
    case "offline":
      return (
        <div role="status" className={cn(QR_PLACEHOLDER, "flex-col gap-2")}>
          <WifiOff className="size-6 text-faint" aria-hidden="true" />
          <p className="text-hint text-muted">{t("common.offline")}</p>
        </div>
      );
    case "stalled":
      return (
        <div className={QR_PLACEHOLDER}>
          <Button size="sm" onClick={onRetry}>
            <RotateCw aria-hidden="true" />
            {t("common.retry")}
          </Button>
        </div>
      );
  }
}

/**
 * Whether the code has been awaited for `CODE_WAIT_MS`. A wait starts whenever `awaiting` turns on
 * (the panel opened, or signaling came back) and again on `restart` (Retry).
 */
function useCodeWait(awaiting: boolean): { stalled: boolean; restart: () => void } {
  const [attempt, setAttempt] = useState(0);
  const [stalledAttempt, setStalledAttempt] = useState<number | null>(null);
  useEffect(() => {
    if (!awaiting) {
      setStalledAttempt(null);
      return;
    }
    const id = window.setTimeout(() => setStalledAttempt(attempt), CODE_WAIT_MS);
    return () => window.clearTimeout(id);
  }, [awaiting, attempt]);
  return {
    stalled: awaiting && stalledAttempt === attempt,
    restart: () => setAttempt((n) => n + 1),
  };
}

/**
 * Close the panel at the code's ceiling. The backend refuses the code after it, and a panel left
 * open that long is the case the ceiling exists for, so the panel closes rather than keep showing
 * a dead code. A code already past its ceiling by this PC's clock says the clocks disagree, not
 * that it expired: then nothing is closed (the agent logs the code's `expires_at`).
 */
function useCeiling(
  code: string | null,
  expiresAt: number | null,
  onClose: (reason: PairingCloseReason) => void,
) {
  useEffect(() => {
    if (code === null || expiresAt === null) return;
    const ttl = expiresAt - Date.now();
    if (ttl <= 0) return;
    const id = window.setTimeout(() => onClose("expired"), ttl);
    return () => window.clearTimeout(id);
  }, [code, expiresAt, onClose]);
}
