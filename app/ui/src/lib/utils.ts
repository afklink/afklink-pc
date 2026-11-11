import { type ClassValue, clsx } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

/**
 * tailwind-merge told about this window's own theme (`styles.css`). Without it, a custom size such
 * as `text-hint` looks like a text *colour* to the merger, and `cn("text-hint", "text-muted")`
 * would silently drop one of the two; the same goes for the radius and font-family names.
 */
const twMerge = extendTailwindMerge({
  extend: {
    theme: {
      text: ["hint", "body", "heading", "title", "code"],
      radius: ["inner", "control", "card"],
      font: ["display", "small"],
    },
  },
});

/**
 * Merge class names, with later Tailwind utilities beating earlier ones.
 *
 * The shadcn/ui convention, and the reason it exists: `clsx` alone would leave both `px-4` and a
 * caller's `px-2` in the string, and which one wins would come down to CSS source order rather
 * than to the caller's intent. `twMerge` resolves the conflict in favour of the last one, which
 * is what makes a `className` prop on a variant component actually override the variant.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
