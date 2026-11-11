import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";

/**
 * Buttons — shadcn/ui shape (cva variants + `cn` so `className` wins).
 *
 * Split by consequence, not looks:
 *   primary      acid lime with Charcoal text — the one action a state is for (first pairing,
 *                Resume, Allow); lighter on hover, darker while pressed;
 *   secondary    tonal Graphite — everything that is an action but not *the* action;
 *   ghost        text-weight, for rows and icon buttons;
 *   destructive  tonal Cut — ends sessions or revokes access, never the default in its group;
 *   dangerQuiet  a neutral outline that turns Cut on hover — the idle kill switch;
 *   dangerSolid  solid Cut with Charcoal text, like lime — only the kill switch's confirmation.
 *
 * No glows: a coloured shadow under a button says nothing the fill does not.
 *
 * Disabled is one explicit look for every variant — transparent fill, a Rule border that keeps
 * the control's shape, the disabled ink, no hover, no press — never a faded accent (opacity faded
 * the border with the fill, so a disabled button read as a different, borderless shape, and a
 * disabled primary as a murky lime). `aria-disabled` looks the same and is what a button in
 * flight uses: it keeps focus where it is, which a disabled button would lose; the handler drops
 * the press itself.
 *
 * Focus is the window's one focus outline (`styles.css`), not a box-shadow ring: an outline with
 * an offset leaves a transparent gap on any surface, and Windows Contrast themes keep outlines but
 * drop box-shadows.
 */
const DISABLED =
  "disabled:pointer-events-none disabled:cursor-default disabled:border-line disabled:bg-transparent disabled:text-disabled disabled:shadow-none aria-disabled:pointer-events-none aria-disabled:cursor-default aria-disabled:border-line aria-disabled:bg-transparent aria-disabled:text-disabled aria-disabled:shadow-none";

const buttonVariants = cva(
  `inline-flex cursor-pointer items-center justify-center gap-2 rounded-control border text-body font-medium whitespace-nowrap transition-colors select-none active:scale-[0.99] [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 ${DISABLED}`,
  {
    variants: {
      variant: {
        secondary: "border-line bg-panel text-ink hover:border-line-strong hover:bg-panel-raised",
        primary:
          "border-transparent bg-accent font-semibold text-accent-ink hover:bg-accent-strong active:bg-accent-pressed",
        ghost: "border-transparent bg-transparent text-muted hover:bg-white/6 hover:text-ink",
        destructive:
          "border-danger/35 bg-danger-dim font-semibold text-danger hover:border-danger/55 hover:bg-danger/15",
        dangerQuiet:
          "border-line bg-transparent text-muted hover:border-danger/45 hover:bg-danger-dim hover:text-danger",
        dangerSolid:
          "border-transparent bg-danger-solid font-semibold text-danger-ink hover:brightness-110 active:brightness-95",
      },
      size: {
        default: "h-9 px-3.5",
        sm: "h-8 px-3",
        /*
         * The status lines' actions, and only theirs: Settings → «Только игра», the helper's lines
         * under its switch («Выбрать» by «Нужен файл запуска», «Изменить», «Заменить», «Обновить»,
         * «Разрешить») — every button in those lines is this size (buttons of one kind look
         * alike), so a line is as tall as its button, 24px, not 32. The same fill,
         * border, ink, weight and 13px label as `sm`, and the same disabled look; less padding,
         * and the inner radius, so a 24px button keeps the shape of a 32px one (10px on 24px would
         * all but make it a pill).
         */
        xs: "h-6 rounded-inner px-2.5",
        block: "h-10 w-full px-4",
        icon: "size-9",
        iconBlock: "size-10",
      },
    },
    defaultVariants: { variant: "secondary", size: "default" },
  },
);

export type ButtonProps = ComponentProps<"button"> & VariantProps<typeof buttonVariants>;

export function Button({ className, variant, size, type = "button", ...props }: ButtonProps) {
  return (
    <button
      data-slot="button"
      type={type}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  );
}

export { buttonVariants };
