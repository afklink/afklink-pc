import { Check, ChevronDown } from "lucide-react";
import {
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";

import { cn } from "../../lib/utils";

/**
 * One option row (`py-2` and a 20px line), the list's own padding and border (`p-1`, 1px each
 * side), and the gap between it and the trigger (`mt-1.5` / `mb-1.5`), for placing the list.
 */
const OPTION_PX = 36;
const LIST_CHROME_PX = 10;
const LIST_GAP_PX = 6;

/**
 * Minimal native-feel select for the settings view. A real `<select>` would take
 * Windows chrome and clash with the dark window; a handful of options fits a tiny
 * popover, which is honest and stays in theme.
 *
 * Where the list opens is decided against what can be seen of the scrolling box that holds the
 * select (Settings' content under its top row), not the window: downward unless it would not fit
 * below and there is more room above. And opening it never moves that box: focus goes to the
 * current option without scrolling anything (`preventScroll`). Decided against the window, the
 * log-level picker low in a 480px-tall window would open upward past the top row, and focusing its
 * first option would then scroll Settings 252 px. When neither side holds the whole list,
 * it takes the larger one and scrolls inside itself, the current option in view.
 *
 * Naming: the trigger is named by the visible label (`labelId`) followed by its current value, so
 * a screen reader hears «Журнал, Отладка» rather than the label alone — an `aria-label` would
 * replace the value it shows. `id` goes on the trigger, for a `<label htmlFor>`.
 *
 * Keyboard, as a listbox should: ↓/↑ (or Enter/Space) on the trigger open the list with focus on
 * the current option; ↓/↑/Home/End move inside it; Enter/Space pick; Escape closes and puts focus
 * back on the trigger; Tab closes and moves on.
 */
export function Select({
  id,
  labelId,
  value,
  onChange,
  options,
  label,
  className,
}: {
  /** The trigger's id, for the visible `<label htmlFor>`. */
  id?: string;
  /** The id of the visible label that names the trigger (together with the value). */
  labelId: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: ReactNode }[];
  /** The list's accessible name. */
  label: string;
  /** Width and placement, from the row that holds it. */
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const [place, setPlace] = useState<{ up: boolean; maxHeight: number | null }>({
    up: false,
    maxHeight: null,
  });
  const ref = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const valueId = useId();

  const show = () => {
    if (ref.current) {
      const box = ref.current.getBoundingClientRect();
      const view = visibleArea(ref.current);
      const below = view.bottom - box.bottom - LIST_GAP_PX;
      const above = box.top - view.top - LIST_GAP_PX;
      const needed = options.length * OPTION_PX + LIST_CHROME_PX;
      const up = below < needed && above > below;
      const room = Math.floor(up ? above : below);
      // Never under two rows: below that a list is no use, and cut is better than unusable.
      const maxHeight = room < needed ? Math.max(room, 2 * OPTION_PX + LIST_CHROME_PX) : null;
      setPlace({ up, maxHeight });
      // biome-ignore lint/suspicious/noConsole: once per opening, with what decided where
      console.debug(
        `[select] ${label}: opens ${up ? "up" : "down"} — ${Math.round(above)} px visible above, ${Math.round(below)} below (in ${view.what}), the list needs ${needed}${maxHeight === null ? "" : `; neither side holds it: ${maxHeight} px, scrolling inside`}`,
      );
    }
    setOpen(true);
  };

  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) triggerRef.current?.focus();
  };

  // Open: focus goes to the current option, so arrows start from where the value is — without
  // scrolling the view the select is in. In a list that scrolls inside itself, the option is
  // brought into the list's own view.
  useEffect(() => {
    if (!open) return;
    const list = listRef.current;
    const items = optionButtons(list);
    const current = items.find((el) => el.getAttribute("aria-selected") === "true") ?? items[0];
    current?.focus({ preventScroll: true });
    if (list && current && list.scrollHeight > list.clientHeight) {
      list.scrollTop = Math.max(
        0,
        current.offsetTop - (list.clientHeight - current.offsetHeight) / 2,
      );
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", onDown);
    return () => window.removeEventListener("mousedown", onDown);
  }, [open]);

  const onTriggerKey = (e: ReactKeyboardEvent<HTMLButtonElement>) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!open) show();
    }
  };

  const onListKey = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    const items = optionButtons(listRef.current);
    const at = items.indexOf(document.activeElement as HTMLButtonElement);
    const move = (to: number) => {
      e.preventDefault();
      items[Math.max(0, Math.min(items.length - 1, to))]?.focus();
    };
    switch (e.key) {
      case "ArrowDown":
        return move(at + 1);
      case "ArrowUp":
        return move(at - 1);
      case "Home":
        return move(0);
      case "End":
        return move(items.length - 1);
      case "Escape":
        // Kept inside the select: a dialog or view behind must not also take this Escape.
        e.preventDefault();
        e.stopPropagation();
        return close(true);
      case "Tab":
        return close(false);
    }
  };

  const current = options.find((o) => o.value === value);

  return (
    <div ref={ref} className={cn("relative", className)}>
      <button
        ref={triggerRef}
        id={id}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-labelledby={`${labelId} ${valueId}`}
        onClick={() => (open ? close(false) : show())}
        onKeyDown={onTriggerKey}
        className={cn(
          "flex h-9 w-full cursor-pointer items-center justify-between gap-2 rounded-control border bg-ground px-3 text-body text-ink transition-colors",
          // Focus as on `Input`: accent border plus a soft ring, not the global outline; the ring
          // is a box-shadow that Contrast themes drop, and `outline-hidden` shows there instead.
          "focus-visible:border-accent/70 focus-visible:ring-2 focus-visible:ring-accent/25 focus-visible:outline-hidden",
          open ? "border-accent/70" : "border-line-strong hover:border-faint/50",
        )}
      >
        <span id={valueId} className="truncate">
          {current?.label ?? value}
        </span>
        <ChevronDown
          aria-hidden="true"
          className={cn("size-4 shrink-0 text-faint transition-transform", open && "rotate-180")}
        />
      </button>
      {open ? (
        <div
          ref={listRef}
          role="listbox"
          aria-label={label}
          onKeyDown={onListKey}
          className={cn(
            "absolute inset-x-0 z-20 min-w-40 animate-slide-up rounded-control border border-line-strong bg-panel-overlay p-1 shadow-popover",
            place.maxHeight === null ? "overflow-hidden" : "overflow-y-auto",
            place.up ? "bottom-full mb-1.5" : "top-full mt-1.5",
          )}
          style={place.maxHeight === null ? undefined : { maxHeight: place.maxHeight }}
        >
          {options.map((o) => (
            <button
              key={o.value}
              type="button"
              role="option"
              aria-selected={o.value === value}
              // One Tab stop for the whole list: arrows move between options.
              tabIndex={-1}
              onClick={() => {
                onChange(o.value);
                close(true);
              }}
              className={cn(
                "flex w-full cursor-pointer items-center justify-between gap-2 rounded-inner px-2.5 py-2 text-left text-body transition-colors",
                // Focus is an inset ring inside the list; Contrast themes drop box-shadows, and
                // there `outline-hidden`'s outline (2px out, within the list's 4px padding) shows.
                "focus-visible:ring-1 focus-visible:ring-accent/60 focus-visible:ring-inset focus-visible:outline-hidden",
                o.value === value
                  ? "bg-accent-dim text-ink"
                  : "text-muted hover:bg-white/6 hover:text-ink focus-visible:bg-white/6 focus-visible:text-ink",
              )}
            >
              <span className="truncate">{o.label}</span>
              {o.value === value ? (
                <Check aria-hidden="true" className="size-3.5 shrink-0 text-accent" />
              ) : null}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function optionButtons(list: HTMLElement | null): HTMLButtonElement[] {
  return list ? Array.from(list.querySelectorAll<HTMLButtonElement>('[role="option"]')) : [];
}

/**
 * The part of the window in which `el` can be seen: the visible box of its nearest scrolling
 * ancestor (its content edge, inside any border), clipped to the window; the window itself when it
 * has none. `what` names it for the log.
 */
function visibleArea(el: HTMLElement): { top: number; bottom: number; what: string } {
  for (let a = el.parentElement; a; a = a.parentElement) {
    const overflow = getComputedStyle(a).overflowY;
    if (overflow === "auto" || overflow === "scroll") {
      const r = a.getBoundingClientRect();
      const top = r.top + a.clientTop;
      return {
        top: Math.max(0, top),
        bottom: Math.min(window.innerHeight, top + a.clientHeight),
        what: `the scrolling <${a.tagName.toLowerCase()}>`,
      };
    }
  }
  return { top: 0, bottom: window.innerHeight, what: "the window" };
}
