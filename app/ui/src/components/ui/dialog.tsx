import { X } from "lucide-react";
import { type ReactNode, type RefObject, useEffect, useId, useRef } from "react";
import { createPortal } from "react-dom";

import { useT } from "../../i18n";
import { cn } from "../../lib/utils";

/** What Tab can land on inside the dialog. */
const TABBABLE =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** What closed the dialog, for the caller's log: the ✕, Escape, or a press on the dimmed backdrop. */
export type DialogCloseReason = "✕" | "Esc" | "outside";

/**
 * Modal overlay — a dialog that behaves like a separate window inside this one.
 *
 * Used for pairing (code + QR). Fixed, centered, Escape closes, click outside
 * closes when `onClose` allows it. A sentence-case title and one close control,
 * the ✕ beside it — no second «Закрыть» button for the same thing. Taller than
 * the window (the 480px minimum), the panel scrolls rather than clips.
 *
 * Modal in behaviour, not only in looks. It renders into `<body>`, outside the app root, and the
 * app root is `inert` while it is open: nothing behind it takes focus, clicks or a screen reader's
 * attention (otherwise Enter on the button that opened it would mint a new code under the one being
 * read, and Tab would reach the kill switch and the gear). Focus moves to the dialog when it opens
 * — to the panel itself, or to `initialFocus` (a field to type in) — Tab and Shift+Tab cycle inside
 * it, and when it closes focus goes back to whatever had it before. The opener is noted before
 * anything in the dialog takes focus, which is why a field is focused through `initialFocus` and
 * not `autoFocus`: `autoFocus` runs first, and the dialog would then take the field for its opener.
 */
export function Dialog({
  children,
  onClose,
  wide,
  title,
  initialFocus,
}: {
  children: ReactNode;
  /** Absent: nothing closes the dialog (no ✕, no Escape, no press outside) — e.g. while it waits. */
  onClose?: ((why: DialogCloseReason) => void) | undefined;
  wide?: boolean;
  /** The dialog's visible title, which also names it. */
  title: string;
  /** What takes focus when the dialog opens; the panel when absent or not rendered. */
  initialFocus?: RefObject<HTMLElement | null> | undefined;
}) {
  const t = useT();
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();

  // Open: the rest of the window goes inert and the dialog takes focus. Close: inert is lifted
  // first — the opener is inside the app root and cannot take focus back before — then focus
  // returns to the opener, unless something else has taken it meanwhile.
  // biome-ignore lint/correctness/useExhaustiveDependencies: once, on open — `initialFocus` is read then
  useEffect(() => {
    const root = document.getElementById("root");
    const panel = panelRef.current;
    const active = document.activeElement;
    const opener = active instanceof HTMLElement && active !== document.body ? active : null;
    if (root) root.inert = true;
    (initialFocus?.current ?? panel)?.focus();
    return () => {
      if (root) root.inert = false;
      const now = document.activeElement;
      const focusIsOurs = now === null || now === document.body || (panel?.contains(now) ?? false);
      if (opener?.isConnected && focusIsOurs) opener.focus();
    };
  }, []);

  // Escape closes; Tab stays inside; a press outside the panel (on the dimmed backdrop) closes.
  // On `window`, so they hold wherever focus is, the dialog's own panel included (where it starts).
  // Escape while an input method is composing belongs to the composition, not to the dialog.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !e.isComposing) onClose?.("Esc");
      else if (e.key === "Tab" && panelRef.current) trapTab(e, panelRef.current);
    };
    const onDown = (e: MouseEvent) => {
      const panel = panelRef.current;
      if (panel && e.target instanceof Node && !panel.contains(e.target)) onClose?.("outside");
    };
    window.addEventListener("keydown", onKey);
    window.addEventListener("mousedown", onDown);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("mousedown", onDown);
    };
  }, [onClose]);

  return createPortal(
    <div className="fixed inset-0 z-50 flex animate-fade-in items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]">
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        // Holds focus when the dialog opens, so no control starts focused; not a Tab stop.
        tabIndex={-1}
        className={cn(
          "max-h-full w-full animate-zoom-in overflow-y-auto rounded-card border border-line-strong bg-panel p-5 shadow-dialog outline-none",
          wide ? "max-w-[360px]" : "max-w-[320px]",
        )}
      >
        {/* As tall with the ✕ as without it: a dialog that drops the ✕ while it waits does not jump. */}
        <header className="mb-4 flex min-h-7 items-center justify-between gap-3">
          <h2 id={titleId} className="truncate text-heading font-semibold text-ink">
            {title}
          </h2>
          {onClose ? (
            <button
              type="button"
              onClick={() => onClose("✕")}
              aria-label={t("common.close")}
              title={t("common.close")}
              // Looks 28×28 (its hover square), takes presses 32×32 (32 px, the least target with a
              // mouse): a transparent `::before` 2 px past each side, absolutely placed, so the
              // header keeps its 28 px and the title its place. It stays inside the panel, which
              // clips (12 px of its padding to spare on the right, 18 above), and 10 px clear of
              // the title, however long (the header's 12 px gap).
              className={cn(
                "-mr-1.5 shrink-0 rounded-control p-1.5 text-faint transition-colors hover:bg-white/6 hover:text-ink",
                "relative before:absolute before:-inset-0.5 before:content-['']",
              )}
            >
              <X className="size-4" aria-hidden="true" />
            </button>
          ) : null}
        </header>
        {children}
      </div>
    </div>,
    document.body,
  );
}

/** Keep Tab inside `panel`: past the last control back to the first, and the other way round. */
function trapTab(e: KeyboardEvent, panel: HTMLElement): void {
  const items = Array.from(panel.querySelectorAll<HTMLElement>(TABBABLE)).filter(
    (el) => el.getClientRects().length > 0,
  );
  const first = items[0];
  const last = items.at(-1);
  const now = document.activeElement;
  const outside = !panel.contains(now);
  let next: HTMLElement | undefined;
  if (!first || !last) next = panel;
  else if (e.shiftKey) next = now === first || now === panel || outside ? last : undefined;
  else next = now === last || outside ? first : undefined;
  // Otherwise the browser's own Tab order, which inside the panel is right.
  if (next) {
    e.preventDefault();
    next.focus();
  }
}
