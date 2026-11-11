import { type Locale, pluralRu, type TranslationKey } from "@afklink/i18n/pc";
import { type ReactNode, type RefObject, useEffect, useLayoutEffect, useRef } from "react";

import { useLanguage, useT } from "../i18n";
import { cn } from "../lib/utils";
import type { Refusal, SessionDto } from "../tauri";
import { initialOf, ScreenGlyph, type ScreenState } from "./ScreenGlyph";
import { MiddleEllipsis } from "./ui/middle-ellipsis";

/**
 * The hero — the answer to "is someone on my screen right now", told by the monitor pictogram
 * (`ScreenGlyph`) and a two-to-three-word caption under it. First match wins:
 *
 *   paused      the pause bars, «На паузе» / «Вход закрыт» — after «Приостановить доступ», until
 *               the footer's «Возобновить»; it outranks everything, since nobody can connect;
 *   live        the lit screen with the viewer's initial, «Вера управляет» / «@vera · 12 мин» —
 *               only people whose video is up (`SessionDto.connected`) count as in control; the
 *               time is how long they have been (`live_for`, the tray's own text). With the server
 *               gone as well: the video does not go through it;
 *   connecting  the outlined screen, «Вера подключается» — a session was asked for, no video yet;
 *   offline     the mark at half strength, «Нет связи» / this PC's name — nobody is on, and the
 *               server cannot reach this PC (`StatusDto.offline`: down for three seconds, or
 *               refused); the toast above says which;
 *   idle        the dark screen, «Готов к подключению» / this PC's name as the list of PCs shows it —
 *               nobody is on, and the server can reach this PC. Also while the link is down for
 *               less than three seconds — the handshake at launch, a reconnect — so a normal launch
 *               shows it from the first frame and never changes the text.
 *
 * «Готов к подключению» and «Нет связи» are the tray's first line too, from the same Rust decision
 * (`tray_status.rs`); the tray has no «подключается», so there a session still connecting counts as
 * nobody.
 *
 * The muted second line is in every state and keeps its height when empty, so the timer arriving
 * or going moves nothing.
 *
 * It takes the space the rest of the view leaves (centred in it), so the window is not half empty
 * and the status is the heaviest thing on it. Its top air is where the connection toast floats
 * (`notice`, placed by the caller): full width, no row of its own, and — the air being at least
 * the toast's height — over nothing.
 *
 * The caption is one polite live region, mounted in every state, so a change of state is announced
 * (a region mounted together with its content is not reliably read).
 *
 * One size in every state and phase of the main view — the 96 px mark (`GLYPH_WIDTH`) — so it never
 * moves: marks of other sizes for first run or beside the autostart card would make the window jump
 * at every turn. The hero keeps 12 px of air: the toast floats over the mark's top
 * in a window at its smallest, and over nothing at the default size, where the hero has the room.
 *
 * The caption about people is always one line: one person's name is cut
 * to fit it — «Константин Константино… управляет» — and the verb never is; two or more are their
 * number, «2 человека управляют», the names being in «Доступ». A caption of two lines would make
 * the main view scroll in a short window. This PC's name under «Готов к подключению» is cut in the
 * middle when it does not fit, so its end — where «DESKTOP-7K2M9QF» differs from the next PC —
 * stays.
 */
export function StatusHero({
  sessions,
  paused,
  offline,
  refusal,
  deviceName,
  liveFor,
  notice,
}: {
  sessions: SessionDto[];
  paused: boolean;
  /** The server cannot reach this PC, as the tray says it (`StatusDto.offline`). */
  offline: boolean;
  /** Why, when the backend refuses this agent — for the log only; `offline` already says it. */
  refusal: Refusal | null;
  deviceName: string;
  /** How long someone has been in control, «12 мин» (`StatusDto.live_for`); null when nobody is. */
  liveFor: string | null;
  /** The connection toast, floated in the top air. */
  notice?: ReactNode;
}) {
  const t = useT();
  const { locale } = useLanguage();
  const live = sessions.filter((s) => s.connected);
  const people = live.length > 0 ? live : sessions;
  const first = people[0];

  let hero: Hero;
  if (paused) {
    hero = { state: "paused", caption: t("app.heroPaused"), sub: t("app.heroPausedSub") };
  } else if (first === undefined) {
    hero = offline
      ? { state: "offline", caption: t("app.heroOffline"), sub: deviceName, subIsPcName: true }
      : { state: "idle", caption: t("app.heroIdle"), sub: deviceName, subIsPcName: true };
  } else {
    hero = peopleHero(t, locale, people, live.length > 0, liveFor);
  }
  const { state, caption, sub, name } = hero;
  const nameRef = useRef<HTMLSpanElement>(null);
  useHeroLog(state, offline, refusal, sessions.length);
  useCaptionLog(nameRef, state, people.length, name?.text ?? null, caption, locale);

  return (
    // 12px each way: the zone under it fits in the 340×480 minimum without a scroll; at the default
    // size the hero centres in the room it has.
    <section className="relative flex flex-1 flex-col items-center justify-center px-1 py-3">
      {notice}
      <ScreenGlyph
        state={state}
        initial={first ? initialOf(first.display_name) : undefined}
        width={GLYPH_WIDTH}
        className="shrink-0"
      />
      <div aria-live="polite" aria-atomic="true" className="mt-4 w-full text-center">
        {name ? (
          // One line: the name gives way (its own ellipsis), the words around it never do.
          <h1
            className="flex justify-center font-display text-title font-semibold text-ink"
            title={caption}
          >
            {name.before ? <span className="shrink-0 whitespace-pre">{name.before}</span> : null}
            <span ref={nameRef} className="min-w-0 overflow-hidden text-ellipsis whitespace-pre">
              {name.text}
            </span>
            {name.after ? <span className="shrink-0 whitespace-pre">{name.after}</span> : null}
          </h1>
        ) : (
          <h1
            className="line-clamp-2 font-display text-title font-semibold break-words text-balance text-ink"
            title={caption}
          >
            {caption}
          </h1>
        )}
        {/* The line is kept when empty, so a state without one does not move the glyph.
            Tabular figures: the timer's digits change width by nothing as the minutes turn. */}
        <p
          className={cn(
            "mt-1 min-h-5 text-body text-muted tabular-nums",
            !hero.subIsPcName && "truncate",
          )}
          title={hero.subIsPcName ? undefined : (sub ?? undefined)}
        >
          {hero.subIsPcName && sub ? (
            <MiddleEllipsis text={sub} align="center" logAs="the PC's name under the hero" />
          ) : (
            sub
          )}
        </p>
      </div>
    </section>
  );
}

/** The mark's width, CSS px, in every state. */
const GLYPH_WIDTH = 96;

/** What the hero shows: the pictogram's state, the caption, and the muted line under it. */
interface Hero {
  state: ScreenState;
  caption: string;
  sub: string | null;
  /** The muted line is this PC's name: cut in the middle, not at its end. */
  subIsPcName?: boolean;
  /** One person's caption, in its three pieces: the name is the one that gives way. */
  name?: { before: string; text: string; after: string };
}

/** A placeholder no name contains, to find where the name goes in the translated sentence. */
const SLOT = "\u0000";

/** «2 человека управляют» and the like: one template per plural form (`app.heroWatchingCount*`). */
const WATCHING_COUNT = {
  one: "app.heroWatchingCountOne",
  few: "app.heroWatchingCountFew",
  many: "app.heroWatchingCountMany",
} as const satisfies Record<string, TranslationKey>;

/** «2 человека подключаются» and the like (`app.heroConnectingCount*`). */
const CONNECTING_COUNT = {
  one: "app.heroConnectingCountOne",
  few: "app.heroConnectingCountFew",
  many: "app.heroConnectingCountMany",
} as const satisfies Record<string, TranslationKey>;

/**
 * The caption for `n` people, two or more: «2 человека управляют», «5 человек подключаются», «21
 * человек управляет» — the form by `pluralRu` in Russian; in English always "people" (the count is
 * never 1 here), "3 people are in control".
 */
function countCaption(
  t: ReturnType<typeof useT>,
  locale: Locale,
  n: number,
  live: boolean,
): string {
  const forms = live ? WATCHING_COUNT : CONNECTING_COUNT;
  const key = locale === "ru" ? pluralRu(n, forms) : forms.many;
  return t(key, { count: n });
}

/**
 * The hero for the people on this screen (`people`: those whose video is up when anyone's is —
 * `live` — else those still connecting), whatever the link to the server.
 *
 * One person: «Вера управляет», «Вера подключается» — on one line, the name cut to fit it, never the
 * verb. Two or more: how many, in words of their own — «2 человека управляют», «3 человека
 * подключаются» (`countCaption`) — and the names in «Доступ»; joined with «и» they would run to two
 * or three lines and cut the verb off. The tray
 * still names them (`Locale::and_list`): a menu line has no such limit.
 */
function peopleHero(
  t: ReturnType<typeof useT>,
  locale: Locale,
  people: SessionDto[],
  live: boolean,
  liveFor: string | null,
): Hero {
  const many = people.length > 1;
  const one = people[0]?.display_name ?? "";
  const caption = many
    ? countCaption(t, locale, people.length, live)
    : live
      ? t("app.heroWatching", { user: one })
      : t("app.heroConnecting", { user: one });
  const template = many
    ? null
    : live
      ? t("app.heroWatching", { user: SLOT })
      : t("app.heroConnecting", { user: SLOT });
  const at = template?.indexOf(SLOT) ?? -1;
  const name =
    template !== null && at >= 0
      ? { before: template.slice(0, at), text: one, after: template.slice(at + SLOT.length) }
      : undefined;
  // The handle under a name — not under a handle standing in for the name.
  const only = people.length === 1 ? people[0] : undefined;
  const handle =
    only?.username && only.display_name !== `@${only.username}` ? `@${only.username}` : null;
  // Then how long they have been in control, as in the pairing prompt's «@vera · 97 с». Only
  // once the video is up: Rust sends no time before that.
  const parts = [handle, live ? liveFor : null].filter((p) => p !== null);
  return {
    state: live ? "live" : "connecting",
    caption,
    sub: parts.length > 0 ? parts.join(" · ") : null,
    ...(name ? { name } : {}),
  };
}

/**
 * How the caption about people is put, said once each time that changes: their number (two or
 * more), with the words that count them in the window's language, or the one name — whole, or cut
 * to keep the caption on one line, with how wide it needed to be and how wide it is. The window's
 * console (devtools) only.
 */
function useCaptionLog(
  nameRef: RefObject<HTMLSpanElement | null>,
  state: ScreenState,
  count: number,
  name: string | null,
  caption: string,
  locale: Locale,
) {
  const last = useRef<string | null>(null);
  useLayoutEffect(() => {
    if (state !== "live" && state !== "connecting") {
      last.current = null;
      return;
    }
    const say = () => {
      const el = nameRef.current;
      const cut = name !== null && el !== null && el.scrollWidth > el.clientWidth + 0.5;
      const key = `${state}:${count}:${name ?? ""}:${cut}:${locale}`;
      if (last.current === key) return;
      last.current = key;
      // biome-ignore lint/suspicious/noConsole: once per change of how the caption is put
      console.debug(
        name === null
          ? `[status] hero caption (${state}): ${count} people — their number, not their names (the names are in «Доступ»): «${caption}» (${locale === "ru" ? `the Russian form for ${count}` : "the plural"})`
          : cut && el
            ? `[status] hero caption (${state}): one name, cut to keep one line — it needs ${el.scrollWidth} px, has ${el.clientWidth}; the verb whole`
            : `[status] hero caption (${state}): one name, whole on one line`,
      );
    };
    say();
    const el = nameRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(say);
    observer.observe(el);
    return () => observer.disconnect();
  }, [nameRef, state, count, name, caption, locale]);
}

/** Why each state is the one shown, for the log line below. */
const HERO_WHY: Record<ScreenState, string> = {
  paused: "paused after «Приостановить доступ»: outranks everything",
  live: "someone's video is up: shown whatever the link to the server",
  connecting: "a session was asked for, no video yet: shown whatever the link to the server",
  offline: "nobody on, and the server cannot reach this PC (down 3 s or refused)",
  idle: "nobody on, and the server can reach this PC (or the link is down for under 3 s)",
};

/**
 * The hero's state, said once each time it changes, with what chose it. The window's console
 * (devtools) only: the app log has the tray's line and the link's edges from the same decision
 * (`tray_status.rs`).
 */
function useHeroLog(
  state: ScreenState,
  offline: boolean,
  refusal: Refusal | null,
  sessions: number,
) {
  const last = useRef<ScreenState | null>(null);
  useEffect(() => {
    const was = last.current;
    last.current = state;
    if (was === state) return;
    // biome-ignore lint/suspicious/noConsole: once per change of the hero's state, with why
    console.debug(
      `[status] hero: ${was ?? "-"} → ${state} — ${HERO_WHY[state]} (offline: ${offline}, refusal: ${refusal ?? "-"}, sessions: ${sessions})`,
    );
  }, [state, offline, refusal, sessions]);
}
