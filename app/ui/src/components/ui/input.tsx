import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";

/**
 * A field's look, shared by `Input` and `Textarea`: a Charcoal well (`bg-ground`) inside the
 * Graphite plates, with a field-edge border. Its focus is an accent border plus a soft ring instead
 * of the offset outline; the ring is a box-shadow, which Contrast themes drop, and `outline-hidden`
 * keeps a transparent outline that those themes paint, so focus still shows there. Disabled takes
 * the controls' one disabled look (see `button.tsx`), not an opacity.
 */
const FIELD = cn(
  "selectable w-full rounded-control border border-line-strong bg-ground px-3 text-body text-ink",
  "placeholder:text-faint hover:border-faint/50",
  "focus-visible:border-accent/70 focus-visible:ring-2 focus-visible:ring-accent/25 focus-visible:outline-hidden",
  "disabled:cursor-default disabled:border-line disabled:bg-transparent disabled:text-disabled",
  "transition-colors",
);

/** A text field. */
export function Input({ className, ...props }: ComponentProps<"input">) {
  return <input data-slot="input" className={cn(FIELD, "h-9", className)} {...props} />;
}

/** A field of a few lines: the same well as `Input`, as tall as its `rows`, not resizable. */
export function Textarea({ className, ...props }: ComponentProps<"textarea">) {
  return (
    <textarea
      data-slot="textarea"
      className={cn(FIELD, "block resize-none py-2", className)}
      {...props}
    />
  );
}

/** A form label: one style for every setting — body size, Bone. */
export function Label({
  htmlFor,
  children,
  className,
  ...props
}: ComponentProps<"label"> & { htmlFor: string }) {
  return (
    <label
      data-slot="label"
      htmlFor={htmlFor}
      className={cn("block text-body text-ink", className)}
      {...props}
    >
      {children}
    </label>
  );
}
