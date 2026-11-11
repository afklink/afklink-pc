import { cn } from "../../lib/utils";

/**
 * The loader: a lime arc turning on a faint ring, 28 px. Under reduced motion it stands still (the
 * arc on its ring), as every animation in this window does (`styles.css`). Decorative: whoever shows
 * it says what is loading, in words or for a screen reader.
 */
export function Spinner({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 28 28"
      aria-hidden="true"
      className={cn("size-7 animate-spin motion-reduce:animate-none", className)}
      fill="none"
      strokeWidth="2.5"
    >
      <circle cx="14" cy="14" r="11" className="stroke-white/10" />
      <path d="M14 3a11 11 0 0 1 11 11" strokeLinecap="round" className="stroke-accent" />
    </svg>
  );
}
