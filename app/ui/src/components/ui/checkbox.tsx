import { Check } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "../../lib/utils";

/**
 * A consent box with its words — the trust windows' one look («Вернуть доступ», «Я узнаю это
 * устройство», «Это моё устройство»). A native `<input type="checkbox">` keeps the keyboard, the
 * label's click and what screen readers say; `appearance-none` drops the system's grey square, and
 * the box is drawn in the window's own style: a field-edge outline when unticked, acid lime with a
 * Charcoal tick when ticked (as `Switch`), the controls' one disabled look when it cannot change.
 * Focus: the window's one outline (`styles.css`).
 *
 * The box is 16 px, as the 16 px icons that open the neighbouring lines, with the same 8 px gap:
 * placed where such an icon stands, its words line up with those lines' text. The whole row is
 * the target, at least 32 px high — the least target on a computer.
 *
 * `held`: the box shows its state but a press changes nothing (`aria-disabled`, still focusable,
 * as the windows' held buttons); `disabled`: it cannot be used at all.
 */
export function Checkbox({
  checked,
  onCheckedChange,
  held = false,
  disabled = false,
  className,
  children,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  held?: boolean;
  disabled?: boolean;
  className?: string;
  children: ReactNode;
}) {
  const still = held || disabled;
  return (
    <label
      className={cn(
        "flex min-h-8 items-center gap-2 text-ink",
        still ? "cursor-default" : "cursor-pointer",
        className,
      )}
    >
      <span className="relative flex size-4 shrink-0">
        <input
          type="checkbox"
          className={cn(
            "peer size-4 shrink-0 appearance-none rounded-[4px] border transition-colors",
            "enabled:border-line-strong enabled:bg-transparent",
            "enabled:checked:border-accent enabled:checked:bg-accent",
            !still &&
              "cursor-pointer enabled:hover:border-faint enabled:checked:hover:bg-accent-strong",
            "disabled:border-line disabled:bg-transparent disabled:checked:bg-disabled",
          )}
          checked={checked}
          disabled={disabled}
          aria-disabled={held || undefined}
          onChange={(e) => {
            if (!held) onCheckedChange(e.currentTarget.checked);
          }}
        />
        <Check
          aria-hidden="true"
          strokeWidth={3}
          className="pointer-events-none absolute inset-0.5 size-3 text-accent-ink opacity-0 peer-checked:opacity-100 peer-disabled:text-faint"
        />
      </span>
      <span className="min-w-0">{children}</span>
    </label>
  );
}
