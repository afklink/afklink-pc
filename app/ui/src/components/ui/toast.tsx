import { type ReactNode, useState } from "react";

import { cn } from "../../lib/utils";

/**
 * Toasts — the shadcn/Sonner look (raised panel, hairline border, popover shadow), driven by state
 * rather than fired.
 *
 * What this window toasts are conditions, not events: "no connection" is true until it is not, and
 * the toast has to leave by itself the moment it stops being true. Sonner's imperative `toast()` is
 * built for one-off events; here every toast would be opened and dismissed by hand from effects
 * tracking the poll, which is the same state machine plus a dependency. So: one declarative toast,
 * shown while its `toast` prop is set.
 */

export interface ToastSpec {
  /** A different id is a different toast and enters afresh; the same id updates in place. */
  id: string;
  /** A lucide icon, coloured by the caller for the toast's tone. */
  icon: ReactNode;
  text: string;
  /** At most one button (Retry). */
  action?: ReactNode;
}

/**
 * Where a toast appears. The caller places it (`className`): on the main view it floats in the
 * status hero's top air, full width, so it takes no row of its own and covers nothing. This element
 * is the live region and stays mounted while its view is, so a toast appearing in it is announced.
 * Clicks pass through it everywhere but the toast itself.
 */
export function ToastViewport({
  className,
  children,
}: {
  className?: string | undefined;
  children: ReactNode;
}) {
  return (
    <div role="status" className={cn("pointer-events-none z-10 flex flex-col", className)}>
      {children}
    </div>
  );
}

/**
 * One toast, shown while `toast` is set. When it is cleared, the last content stays through the
 * exit animation and is dropped at its end, so the text does not blank out as it leaves.
 */
export function Toast({ toast }: { toast: ToastSpec | null }) {
  const [shown, setShown] = useState<ToastSpec | null>(toast);
  // Adopted during render (React's "information from previous renders" pattern): the re-render this
  // causes sees the same `toast` and stops there.
  if (toast !== null && toast !== shown) setShown(toast);
  if (shown === null) return null;

  const open = toast !== null;
  const view = toast ?? shown;
  return (
    <div
      key={view.id}
      data-state={open ? "open" : "closed"}
      onAnimationEnd={(e) => {
        if (!open && e.target === e.currentTarget) setShown(null);
      }}
      className={cn(
        "pointer-events-auto flex min-h-11 w-full items-center gap-2.5 rounded-card border border-line-strong bg-panel-overlay py-1.5 pl-3.5 text-body text-ink shadow-popover",
        view.action ? "pr-1.5" : "pr-3.5",
        open ? "animate-toast-in" : "animate-toast-out",
      )}
    >
      <span aria-hidden="true" className="flex shrink-0 [&_svg]:size-4">
        {view.icon}
      </span>
      <p className="min-w-0 flex-1 truncate">{view.text}</p>
      {view.action ? <span className="flex shrink-0">{view.action}</span> : null}
    </div>
  );
}
