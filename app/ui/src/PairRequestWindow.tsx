import { type RefObject, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

import { PairRequestPrompt, pairingStep } from "./components/PairRequestDialog";
import { useT } from "./i18n";
import { fitPairWindow, type PairStep } from "./tauri";
import { useAgentStatus } from "./useAgentStatus";

/**
 * The `pair-request` window: the pairing request near the tray, always on top — the one place a
 * request is shown, whether the main window is open or not. Rust decides
 * when it is shown and hides it again when the request goes (`pair_prompt`); the prompt is the whole
 * window, and the window is exactly its height — with the steps' «3» at the first pairing
 * (`pairingStep`).
 *
 * It draws the pending request as soon as there is one, while the window is still hidden, and
 * reports its height to Rust after every render that changes it (`fitPairWindow`): Rust sizes the
 * window to it and shows it only then — never empty, never at a stale size. Each report names the
 * step drawn — «Отклонить» / «Разрешить», or «Кто это?» on a PC with no owner — and Rust sizes the
 * window only by a height for the step the request is at.
 *
 * With the height goes the page's `devicePixelRatio`: Windows' «Размер текста» (Accessibility →
 * Text size) makes WebView2 draw every CSS pixel larger on top of the display scale, and a window
 * sized by the display scale alone is short of its page — at 150 % the buttons are gone. Rust takes
 * the text scale from the two (`pair_prompt::fit_pair_window`).
 */
export function PairRequestWindow() {
  const t = useT();
  const { loaded, status, refresh } = useAgentStatus();
  const boxRef = useRef<HTMLDivElement>(null);
  const request = status?.pending_pair ?? null;
  const [drawn, setDrawn] = useState<PairStep>("consent");
  useReportHeight(boxRef, request?.request_id ?? null, drawn);

  if (!loaded) {
    return <div className="h-full" aria-busy="true" />;
  }

  return request ? (
    <div ref={boxRef}>
      <PairRequestPrompt
        request={request}
        step={status ? pairingStep(status) : undefined}
        onAnswered={refresh}
        onStep={setDrawn}
      />
    </div>
  ) : (
    <div className="flex h-full items-center justify-center p-5">
      <p className="text-body text-faint">{t("app.noPendingRequests")}</p>
    </div>
  );
}

/**
 * Tell Rust the request's height whenever it changes: after a render (a new request, the status
 * re-read, the other step) and on a resize the render does not see (fonts settling, the window's
 * scale or Windows' text size changing). Once per request, step, height and pixel ratio; a failed
 * report is logged and tried again on the next change.
 */
function useReportHeight(
  ref: RefObject<HTMLElement | null>,
  requestId: string | null,
  step: PairStep,
) {
  const sent = useRef<string | null>(null);

  const report = useCallback(() => {
    const el = ref.current;
    if (!el || requestId === null) return;
    // The step drawn, from the page itself: a render with the new step lands before the parent
    // has heard of it.
    const drawn = el.querySelector<HTMLElement>("[data-step]")?.dataset.step;
    const at: PairStep = drawn === "role" || drawn === "consent" ? drawn : step;
    const height = Math.ceil(el.getBoundingClientRect().height);
    const ratio = window.devicePixelRatio;
    const key = `${requestId}:${at}:${height}:${ratio}`;
    if (height <= 0 || sent.current === key) return;
    sent.current = key;
    fitPairWindow(requestId, height, at, ratio).catch((e: unknown) => {
      sent.current = null;
      console.warn(
        `[ipc] fit_pair_window (${requestId}, ${at}, ${height}px at ×${ratio}) failed: ${String(e)}`,
      );
    });
  }, [ref, requestId, step]);

  // After every render: measured in layout, so a window about to be shown is sized first.
  useLayoutEffect(report);

  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => report());
    observer.observe(el);
    return () => observer.disconnect();
  }, [ref, report]);
}
