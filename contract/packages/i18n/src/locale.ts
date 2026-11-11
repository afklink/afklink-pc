/**
 * Which language to show, and how it is decided.
 *
 * Deliberately import-free, so a caller that only needs to resolve a locale tag — the
 * Mini App before it has rendered anything, a build script, the emit step — does not
 * pull the dictionaries in.
 *
 * The default comes from the platform, because that is the one signal present before the
 * user has told us anything: Telegram's `language_code` for the Mini App, the Windows UI
 * locale for the desktop client. Both are the setting the person already chose for
 * everything else on that device, so honouring it is the best available guess.
 *
 * It is only a guess, though, and it is wrong more often than it looks: one Telegram
 * account set to English while the PC runs a Russian desktop, or a work laptop imaged in
 * English by someone else. So the guess is overridable and the override is remembered —
 * see `LANGUAGE_PREFERENCE_VALUES`.
 */

/** Locales the product ships. */
export const LOCALES = ["ru", "en"] as const;
export type Locale = (typeof LOCALES)[number];

/**
 * Fallback when the platform reports something we do not ship, or nothing at all, and the
 * dictionary a missing key falls back to.
 *
 * English rather than Russian: `language_code` carries dozens of values, and a German, Persian or
 * Armenian speaker is far more likely to read English than Cyrillic they did not ask for. The
 * post-Soviet languages where Russian is commonly read are the exception —
 * `RUSSIAN_READING_LANGUAGES`.
 */
export const DEFAULT_LOCALE: Locale = "en";

/**
 * Primary language subtags whose speakers get Russian rather than English when the platform's
 * language is not one we ship: the post-Soviet languages where Russian is commonly read
 * (Ukrainian, Belarusian, Kazakh, Kyrgyz, Uzbek, Tajik, Azerbaijani). Armenian and Georgian stay
 * English.
 *
 * The rule has hand-written copies that cannot import this module, each with a test against this
 * list: the Mini App's boot script (`miniapp/index.html`), the desktop client's
 * `Locale::from_tag` (`agent/crates/i18n`) and the backend's data migration
 * `0031_ru_reading_languages.sql`.
 */
export const RUSSIAN_READING_LANGUAGES = ["uk", "be", "kk", "ky", "uz", "tg", "az"] as const;

/**
 * Each language's name in that language, for a language picker: the same whatever the interface is
 * in, so a person who opened it in a language they do not read still finds their own. Not a
 * translation, hence not in the dictionaries. The bot's /language buttons and the app's «Язык».
 */
export const LOCALE_NAMES: Readonly<Record<Locale, string>> = { ru: "Русский", en: "English" };

/**
 * What the Mini App can store as its language. `auto` re-reads the platform each launch.
 *
 * One language per account, for the bot and the app: the account's language is
 * one of `LOCALES`, set from Telegram's at the account's first contact and changed only by the
 * person. The app's «Язык» offers just the languages (`LOCALE_NAMES`) and never writes `auto`;
 * `auto` stays here for app builds that still offer «Автоматически» — the app reads a stored one as
 * no choice and clears it, and the server replaces it with Telegram's language at the next contact.
 */
export const LANGUAGE_PREFERENCE_VALUES = ["auto", ...LOCALES] as const;
export type LanguagePreference = (typeof LANGUAGE_PREFERENCE_VALUES)[number];

/** Where the Mini App remembers an explicit choice. */
export const LANGUAGE_STORAGE_KEY = "afklink.lang";

export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (LOCALES as readonly string[]).includes(value);
}

export function isLanguagePreference(value: unknown): value is LanguagePreference {
  return (
    typeof value === "string" && (LANGUAGE_PREFERENCE_VALUES as readonly string[]).includes(value)
  );
}

/**
 * Why a tag resolved the way it did, for logs: `shipped` — the tag's language is one we ship
 * (`ru`, `en`); `ru-reading` — one of `RUSSIAN_READING_LANGUAGES`, served Russian; `other` — any
 * other language, served `DEFAULT_LOCALE`; `none` — no tag (missing or blank), served
 * `DEFAULT_LOCALE`.
 */
export type LocaleRule = "shipped" | "ru-reading" | "other" | "none";

export interface LocaleDecision {
  locale: Locale;
  rule: LocaleRule;
}

/**
 * Resolve a platform language tag to a locale we ship, and say which rule did it.
 *
 * Accepts anything BCP-47-shaped and matches on the primary subtag, so `ru`, `ru-RU`, `ru_RU`
 * and `RU` all resolve to Russian, as do `uk-UA`, `uz-Latn-UZ` or `KK_kz`
 * (`RUSSIAN_READING_LANGUAGES`). Unknown or missing → [`DEFAULT_LOCALE`].
 */
export function localeDecision(tag: string | null | undefined): LocaleDecision {
  const primary = (tag ?? "").trim().toLowerCase().split(/[-_]/)[0] ?? "";
  if (!primary) return { locale: DEFAULT_LOCALE, rule: "none" };
  if (isLocale(primary)) return { locale: primary, rule: "shipped" };
  if ((RUSSIAN_READING_LANGUAGES as readonly string[]).includes(primary)) {
    return { locale: "ru", rule: "ru-reading" };
  }
  return { locale: DEFAULT_LOCALE, rule: "other" };
}

/** [`localeDecision`] without the reason. */
export function resolveLocale(tag: string | null | undefined): Locale {
  return localeDecision(tag).locale;
}

/**
 * Apply a stored preference over the platform tag.
 *
 * `auto` (or anything unrecognised, e.g. a value written by an older build) falls back
 * to the platform, which is what makes the preference safe to store loosely.
 */
export function effectiveLocale(
  preference: LanguagePreference | string | null | undefined,
  platformTag: string | null | undefined,
): Locale {
  if (isLocale(preference)) return preference;
  return resolveLocale(platformTag);
}
