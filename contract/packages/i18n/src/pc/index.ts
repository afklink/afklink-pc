/**
 * `@afklink/i18n/pc` — the desktop client's share of the product's strings, in Russian and
 * English: its window, and what Windows draws for it (keys ending in `.native`, emitted into the
 * agent's Rust by `scripts/emit.ts`).
 *
 * The same API as the package's main entry, over a smaller dictionary: the window imports this,
 * so its bundle carries its own strings and not the Mini App's, the bot's or the website's.
 * `ru.ts` and `en.ts` here are cut from the product's dictionaries by `scripts/pc.ts`.
 */
import { dictionaryIn, type TranslationValues, translatorIn } from "../core";
import type { Locale } from "../locale";
import { en } from "./en";
import { ru, type TranslationKey } from "./ru";

export { interpolate, pluralRu, type TranslationValues } from "../core";
export {
  DEFAULT_LOCALE,
  effectiveLocale,
  isLanguagePreference,
  isLocale,
  LANGUAGE_PREFERENCE_VALUES,
  LANGUAGE_STORAGE_KEY,
  type LanguagePreference,
  LOCALE_NAMES,
  LOCALES,
  type Locale,
  type LocaleDecision,
  type LocaleRule,
  localeDecision,
  RUSSIAN_READING_LANGUAGES,
  resolveLocale,
} from "../locale";
export { en, ru, type TranslationKey };

const DICTIONARIES: Record<Locale, Record<TranslationKey, string>> = { ru, en };

export type Translator = (key: TranslationKey, values?: TranslationValues) => string;

/** Every string for one locale. */
export function dictionary(locale: Locale): Record<TranslationKey, string> {
  return dictionaryIn(DICTIONARIES, locale);
}

/** Build a translator bound to one locale (fallbacks: `core.ts`). */
export function translator(locale: Locale): Translator {
  return translatorIn(DICTIONARIES, locale);
}
