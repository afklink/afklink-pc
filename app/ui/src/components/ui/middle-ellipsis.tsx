import { type RefObject, useLayoutEffect, useRef } from "react";

import { cn } from "../../lib/utils";

/** The most characters kept whole at the end: «Shipping.exe», a UUID's last group, «M9QF». */
const TAIL_MAX = 12;

/**
 * One line of text cut in the middle when it does not fit — «TheElderScrollsOnl…Shipping.exe»,
 * «Игровой-ПК-в-гостиной…2026-x64» — so the start and the end both stay: the end is where an exe's
 * name and a PC's name differ from their neighbours' («…M9QF», «.exe»), which an end cut would
 * lose.
 *
 * No measuring: the text is two pieces in a row, the head (cut with the browser's own ellipsis,
 * `text-overflow`) and the tail (never cut) — up to `TAIL_MAX` characters, half the text at most.
 * Whole, the two read as the one string they are (a selection or a screen reader gets all of it),
 * and the full text is the tooltip. `whitespace-pre`, so a space where the two meet is not trimmed
 * from either end. `align` places the line in its box when it fits.
 *
 * `logAs`: for a name the user may need whole (the PC's, an exe's), each change of whether it is
 * cut goes to the window's console with the numbers.
 */
export function MiddleEllipsis({
  text,
  align = "start",
  className,
  title,
  logAs,
}: {
  text: string;
  align?: "start" | "center" | "end";
  className?: string;
  /** The tooltip; the text itself when absent. */
  title?: string | undefined;
  logAs?: string;
}) {
  const [head, tail] = splitTail(text);
  const headRef = useRef<HTMLSpanElement>(null);
  useCutLog(headRef, text, logAs);
  return (
    <span
      className={cn(
        "flex max-w-full min-w-0",
        align === "center" ? "justify-center" : align === "end" ? "justify-end" : "justify-start",
        className,
      )}
      title={title ?? text}
    >
      <span ref={headRef} className="min-w-0 overflow-hidden text-ellipsis whitespace-pre">
        {head}
      </span>
      {tail ? <span className="shrink-0 whitespace-pre">{tail}</span> : null}
    </span>
  );
}

/** `text` as the head and the tail kept whole, by characters (code points, not UTF-16 units). */
export function splitTail(text: string): [string, string] {
  const chars = Array.from(text);
  const n = Math.min(TAIL_MAX, Math.floor(chars.length / 2));
  return [chars.slice(0, chars.length - n).join(""), chars.slice(chars.length - n).join("")];
}

/**
 * Whether `logAs`'s text is cut, said once each time that changes (the window resized, the text
 * replaced): how wide the head needs to be and how wide it is. Nothing without `logAs`.
 */
function useCutLog(
  ref: RefObject<HTMLSpanElement | null>,
  text: string,
  logAs: string | undefined,
) {
  const last = useRef<string | null>(null);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el || logAs === undefined) return;
    const check = () => {
      const cut = el.scrollWidth > el.clientWidth + 0.5;
      const key = `${text}\u0000${cut}`;
      if (last.current === key) return;
      last.current = key;
      // biome-ignore lint/suspicious/noConsole: once per change of whether the name is cut
      console.debug(
        cut
          ? `[layout] ${logAs}: cut in the middle — the head needs ${el.scrollWidth} px, has ${el.clientWidth}; the last ${Array.from(splitTail(text)[1]).length} characters kept whole`
          : `[layout] ${logAs}: whole (${Array.from(text).length} characters)`,
      );
    };
    check();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(check);
    observer.observe(el);
    return () => observer.disconnect();
  }, [ref, text, logAs]);
}
