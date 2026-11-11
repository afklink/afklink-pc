/**
 * The monitor pictogram — AFKLink's status mark, and the one image the desktop window and the
 * Mini App share whatever Telegram theme is on (the Mini App's device row is a monitor too). Its
 * *screen* is the status: dark when nobody is watching, lit when someone is — a tally light for
 * this PC's screen.
 *
 * Self-contained: one SVG, no dependency on this app's Tailwind theme, so the Mini App can mirror
 * it by copying this file.
 *
 * ## State API
 *
 * | state        | screen                                              | means                                   |
 * |--------------|-----------------------------------------------------|-----------------------------------------|
 * | `idle`       | the dark well, empty                                 | nobody is watching                      |
 * | `connecting` | the well, a lime inner outline, the initial in lime  | a session was asked for; no video yet   |
 * | `live`       | lit acid lime, the initial in Charcoal               | someone is watching this screen         |
 * | `paused`     | the well, two Ash pause bars                         | new connections refused until Resume    |
 * | `offline`    | the whole mark at half strength, screen empty        | the PC cannot be reached (device lists) |
 *
 * `initial` is the viewer's first letter (`initialOf`), drawn in `connecting` and `live` only.
 *
 * Live is the brand's acid lime — the same lime as the app icon's ping and the window's accent:
 * "someone is on this screen" is the moment the product exists for, and a second green beside the
 * lime would clash. The bezel is a dark body on every background, so the lime always sits on dark
 * (14:1) even where the page is white (the Mini App's light themes).
 *
 * ## Motion
 *
 * One moment, and only one: entering `live`, the screen lights up — its fill fades from the well to
 * lime over 240 ms (the initial with it). Leaving `live` is instant, and nothing else moves. The fill
 * is a CSS transition, so `prefers-reduced-motion` (which the host's stylesheet already turns into
 * near-zero durations) makes it instant too; mounting straight into `live` does not animate.
 *
 * ## Colours
 *
 * CSS custom properties with this window's palette as fallbacks — a host sets them on any ancestor
 * to re-skin the mark:
 *
 *   --screen-body   #1a1a1e  bezel and stand fill (Graphite) — keep it dark on every theme
 *   --screen-edge   #3d3d46  bezel and stand outline
 *   --screen-recess #0c0c0e  the unlit screen (the Well)
 *   --screen-live   #bff23a  the lit screen, the connecting outline (acid lime)
 *   --screen-ink    #121214  the initial on the lit screen (Charcoal, 14.2:1 on lime)
 *   --screen-muted  #9a9aa3  the pause bars (Ash)
 *   --screen-font   Segoe UI Variable Display, then system sans — the initial's face
 *
 * Decorative by default (`aria-hidden`): the caption beside it says the same in words. Pass `label`
 * where the mark stands alone.
 */

export const SCREEN_STATES = ["idle", "connecting", "live", "paused", "offline"] as const;
export type ScreenState = (typeof SCREEN_STATES)[number];

export interface ScreenGlyphProps {
  state: ScreenState;
  /** The viewer's first letter; shown in `connecting` and `live`. */
  initial?: string | undefined;
  /** Rendered width in CSS px; the height follows the 112 : 88 shape. Default 112. */
  width?: number;
  /** An accessible name, when no caption beside the mark says what it shows. */
  label?: string;
  className?: string;
}

const C = {
  body: "var(--screen-body, #1a1a1e)",
  edge: "var(--screen-edge, #3d3d46)",
  recess: "var(--screen-recess, #0c0c0e)",
  live: "var(--screen-live, #bff23a)",
  ink: "var(--screen-ink, #121214)",
  muted: "var(--screen-muted, #9a9aa3)",
  font: "var(--screen-font, 'Segoe UI Variable Display', 'Segoe UI', system-ui, sans-serif)",
} as const;

/** The lighting-up: only on the way into `live` (see "Motion" above). */
const LIGHT_UP = "fill 240ms ease-out";

export function ScreenGlyph({ state, initial, width = 112, label, className }: ScreenGlyphProps) {
  const lit = state === "live";
  const showInitial = (state === "live" || state === "connecting") && !!initial;
  const transition = lit ? LIGHT_UP : "none";

  return (
    <svg
      viewBox="0 0 112 88"
      width={width}
      height={(width * 88) / 112}
      className={className}
      data-state={state}
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      style={{ opacity: state === "offline" ? 0.5 : 1, overflow: "visible" }}
    >
      {/* Stand: neck, then base — under the bezel, so the bezel's edge runs over the neck's top. */}
      <rect x="48" y="68" width="16" height="12" style={{ fill: C.edge }} />
      <rect
        x="30.75"
        y="79.75"
        width="50.5"
        height="6.5"
        rx="3.25"
        style={{ fill: C.body, stroke: C.edge, strokeWidth: 1.5 }}
      />
      {/* Bezel */}
      <rect
        x="0.75"
        y="0.75"
        width="110.5"
        height="70.5"
        rx="11.25"
        style={{ fill: C.body, stroke: C.edge, strokeWidth: 1.5 }}
      />
      {/* Screen */}
      <rect
        x="7"
        y="7"
        width="98"
        height="57"
        rx="6"
        style={{ fill: lit ? C.live : C.recess, transition }}
      />
      {state === "connecting" ? (
        <rect
          x="8.75"
          y="8.75"
          width="94.5"
          height="53.5"
          rx="4.75"
          style={{ fill: "none", stroke: C.live, strokeWidth: 1.5 }}
        />
      ) : null}
      {showInitial ? (
        <text
          x="56"
          y="36.5"
          textAnchor="middle"
          dominantBaseline="central"
          style={{
            fill: lit ? C.ink : C.live,
            fontFamily: C.font,
            fontSize: 28,
            fontWeight: 600,
            transition,
          }}
        >
          {initial}
        </text>
      ) : null}
      {state === "paused" ? (
        <g style={{ fill: C.muted }}>
          <rect x="44" y="23" width="8" height="25" rx="2" />
          <rect x="60" y="23" width="8" height="25" rx="2" />
        </g>
      ) : null}
    </svg>
  );
}

/**
 * The letter drawn on the screen for a viewer: the first letter of their name, upper-cased. A
 * handle's `@` is skipped; a bare `#id` (no name, no handle) has no letter, so nothing is drawn.
 */
export function initialOf(name: string): string | undefined {
  const trimmed = name.trim();
  if (trimmed === "" || trimmed.startsWith("#")) return undefined;
  const first = Array.from(trimmed.replace(/^@/, ""))[0];
  return first ? first.toLocaleUpperCase() : undefined;
}
