import type { Locale, TranslationKey, Translator } from "@afklink/i18n/pc";

import type { ClientDevice, JournalEnding, JournalEntryDto, JournalKind } from "../tauri";

/**
 * How the connection journal reads in the window: the device's name, the labels, the day headers and
 * the main view's «Журнал» line. What the entries are and how a session ended is Rust's
 * (`journal_view.rs`); this only words it.
 */

/**
 * The device by its Telegram platform. «iPhone», «Android» and «Mac» are names, the same in every
 * language, so they live here rather than in the dictionary (whose check takes a string equal in ru
 * and en for a forgotten translation); «Компьютер» and «Браузер» are words.
 */
export function deviceLabel(t: Translator, device: ClientDevice): string {
  switch (device) {
    case "iphone":
      return "iPhone";
    case "android":
      return "Android";
    case "mac":
      return "Mac";
    case "desktop":
      return t("app.clientDesktop");
    case "browser":
      return t("app.clientBrowser");
  }
}

const ENDINGS: Record<JournalEnding, TranslationKey> = {
  pc: "app.journalEndPc",
  // `owner_ended`: the PC's owner pressed «Прервать сеанс» in the bot.
  owner: "app.journalEndOwner",
  revoked: "app.journalRevoked",
  lost: "app.journalEndLost",
  failed: "app.journalEndFailed",
  app_closed: "app.journalEndAppClosed",
};

/**
 * An event's words after the name: «Вера · Доступ выдан»; «Друг · Доступ по приглашению» for a guest
 * the owner let in from Telegram by his invite.
 */
const EVENTS: Record<Exclude<JournalKind, "session">, TranslationKey> = {
  granted: "app.journalGranted",
  invited: "app.journalInvited",
  revoked: "app.journalRevoked",
  paused: "app.journalPaused",
};

export function eventLabel(t: Translator, kind: Exclude<JournalKind, "session">): string {
  return t(EVENTS[kind]);
}

/**
 * A session's second line: «iPhone · 1 ч 12 мин · Связь потеряна · Только игра · Плохая связь» —
 * each part only when there is one. A session going on has its device and how long so far.
 */
export function sessionMeta(t: Translator, e: JournalEntryDto): string {
  const parts = [
    e.device ? deviceLabel(t, e.device) : null,
    e.duration,
    e.live || e.ending === null ? null : t(ENDINGS[e.ending]),
    e.game_only ? t("app.gameOnlyTitle") : null,
    e.live || !e.weak ? null : t("app.journalWeak"),
  ];
  return parts.filter((p): p is string => p !== null && p !== "").join(" · ");
}

/** The local calendar day of `ms`, as a key that sorts and compares. */
export function dayKey(ms: number): string {
  const d = new Date(ms);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

/** «Сегодня», «Вчера», or the date — day and month, with the year when it is not this one. */
export function dayTitle(t: Translator, locale: Locale, ms: number, now: number): string {
  const key = dayKey(ms);
  if (key === dayKey(now)) return t("app.journalToday");
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (key === dayKey(yesterday.getTime())) return t("app.journalYesterday");
  const at = new Date(ms);
  const sameYear = at.getFullYear() === new Date(now).getFullYear();
  return at.toLocaleDateString(locale, {
    day: "numeric",
    month: "long",
    ...(sameYear ? {} : { year: "numeric" }),
  });
}

/**
 * «21:40», «9:12» by the PC's clock, in the window's language — the hour without a leading zero, as
 * `UpdatesSettings` writes it: "9:12 AM" in English, where "09:12 AM" is not written.
 */
export function timeText(locale: Locale, ms: number): string {
  return new Date(ms).toLocaleTimeString(locale, { hour: "numeric", minute: "2-digit" });
}

/**
 * The main view's «Журнал» line in its three pieces, so the window can cut the name alone: what
 * comes before the name, the name, what comes after it.
 */
export interface JournalRowParts {
  before: string;
  /** Null for «Пока пусто», which names nobody (`before` is the whole line then). */
  name: string | null;
  after: string;
}

/**
 * The main view's «Журнал» line: «Сейчас · Вера» while a session goes on; «Сегодня 9:12 · Вера»
 * or «Вчера 21:40 · Вера» for a session of the last two days, the date and «· Вера» for an older
 * one; «Вера · Доступ выдан» for an event; «Пока пусто» only for an empty journal. In pieces: the
 * name is what gives way in a narrow window, never the event or the time.
 */
export function journalRowParts(
  t: Translator,
  locale: Locale,
  last: JournalEntryDto | null,
  now: number,
): JournalRowParts {
  if (last === null) return { before: t("app.journalRowEmpty"), name: null, after: "" };
  if (last.kind !== "session") {
    return { before: "", name: last.name, after: ` · ${eventLabel(t, last.kind)}` };
  }
  if (last.live) return { before: `${t("app.journalNow")} · `, name: last.name, after: "" };
  const day = dayTitle(t, locale, last.at_ms, now);
  const recent = dayKey(last.at_ms) === dayKey(now) || day === t("app.journalYesterday");
  return {
    before: recent ? `${day} ${timeText(locale, last.at_ms)} · ` : `${day} · `,
    name: last.name,
    after: "",
  };
}

/** The entries by day, newest first, the sessions going on now left out (they lead on their own). */
export function byDay(entries: JournalEntryDto[]): { key: string; items: JournalEntryDto[] }[] {
  const days: { key: string; items: JournalEntryDto[] }[] = [];
  for (const e of entries) {
    if (e.live) continue;
    const key = dayKey(e.at_ms);
    const last = days.at(-1);
    if (last && last.key === key) last.items.push(e);
    else days.push({ key, items: [e] });
  }
  return days;
}
