import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";

export type SwitchProps = Omit<
  ComponentProps<"button">,
  "type" | "role" | "value" | "onChange" | "aria-checked"
> & {
  checked: boolean;
  /** The new state, as in Radix: called with `!checked`; the caller owns the state. */
  onCheckedChange?: (checked: boolean) => void;
};

/**
 * On/off toggle — the shadcn/ui `Switch` (Radix `Switch.Root` + `Switch.Thumb`), rebuilt on a
 * plain `<button>` like the other primitives here rather than pulling in Radix for one control.
 *
 * A switch, not a checkbox: the settings it drives apply the moment they change, with no Save, and
 * that is what a switch says (shadcn's and Windows' own convention); a checkbox reads as a choice
 * a later button submits. Everything Radix gives is kept: `role="switch"` with `aria-checked`,
 * Space and Enter toggle (a native button's own activation), a `<label htmlFor>` pointing at its
 * `id` toggles it too, and `data-state` carries the state for styling. The transparent border is
 * what Windows high-contrast mode draws, so the track does not vanish there.
 *
 * Colours: a Charcoal thumb on acid lime when on, as shadcn's dark theme and Windows 11 both do
 * (dark on the accent); an Ash thumb on a field-edge track when off. Disabled: the controls' one
 * disabled look, as `Button`'s — an empty track with a Rule outline and the disabled ink for a
 * thumb, on the side its state says; not an opacity, never a dimmed lime.
 *
 * Each part has exactly one colour rule that can match: the state's colours only while enabled
 * (`enabled:` on the track, `group-enabled/switch:` on the thumb), the disabled look only while
 * disabled. Stacked instead — `disabled:bg-transparent` over `data-[state=checked]:bg-accent` — the
 * disabled look loses: Tailwind emits `data-*` variants after `disabled:` at the same specificity,
 * so a disabled switch that is on draws a lime track and one that is off a filled one (seen at
 * «Ждём Windows» in «Только игра»). Keyed on `:disabled`, not the prop: inside a disabled
 * `<fieldset>` it looks disabled too.
 *
 * The 36×20 track takes presses 36×32, its look unchanged (32 px, the least target with a mouse): a
 * transparent `::before` reaches 7 px above and
 * below the padding box (18 px inside the 1 px border, so 18 + 2 × 7 = 32), no wider than the
 * track. It is the button's own box, so a press on it is the switch's and the row under it never
 * sees it (on the main card a press just above or below would otherwise open Settings); absolutely
 * placed, it takes no room, so a row keeps its height. Every row a switch sits in is at least
 * 52 px tall with the switch centred, so the zone keeps 9.5 px or more inside it (the nearest
 * other control, «Выбрать» under the helper's switch, is 11 px off, measured). The outline
 * is solid, so the focus mark still follows the track; the hover tint shows wherever a press
 * would land, the zone included. Disabled, the cover takes no presses either (`pointer-events:
 * none` is inherited); it is there for the moment the switch is enabled.
 */
export function Switch({ checked, onCheckedChange, onClick, className, ...props }: SwitchProps) {
  const state = checked ? "checked" : "unchecked";
  return (
    <button
      {...props}
      type="button"
      role="switch"
      aria-checked={checked}
      data-slot="switch"
      data-state={state}
      className={cn(
        // Focus: the window's one outline (`styles.css`), which Contrast themes keep and which
        // leaves a transparent gap, rather than a box-shadow ring those themes drop.
        "group/switch inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border border-transparent p-px transition-colors",
        // The press zone, 36×32 (see above): the track's look is not touched.
        "relative before:absolute before:inset-x-0 before:-inset-y-[7px] before:content-['']",
        "enabled:data-[state=checked]:bg-accent enabled:data-[state=checked]:hover:bg-accent-strong",
        "enabled:data-[state=unchecked]:bg-line-strong enabled:data-[state=unchecked]:hover:bg-faint/45",
        "disabled:pointer-events-none disabled:cursor-default disabled:border-line disabled:bg-transparent",
        className,
      )}
      onClick={(e) => {
        onClick?.(e);
        if (!e.defaultPrevented) onCheckedChange?.(!checked);
      }}
    >
      <span
        data-slot="switch-thumb"
        data-state={state}
        className={cn(
          "pointer-events-none block size-4 rounded-full shadow-sm transition-transform",
          "data-[state=checked]:translate-x-4 data-[state=unchecked]:translate-x-0",
          "group-enabled/switch:data-[state=checked]:bg-accent-ink group-enabled/switch:data-[state=unchecked]:bg-muted",
          "group-disabled/switch:bg-disabled",
        )}
      />
    </button>
  );
}
