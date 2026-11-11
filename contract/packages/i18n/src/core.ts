/**
 * The translator's machinery, apart from any dictionary.
 *
 * `translate.ts` binds it to the whole product's dictionaries; `pc/index.ts` binds it to the
 * desktop client's share of them. Keeping it free of dictionary imports is what lets the
 * desktop client's entry carry its own strings and nothing else.
 */
import { DEFAULT_LOCALE, type Locale } from "./locale";

/** Values substituted into `{placeholders}`. */
export type TranslationValues = Record<string, string | number>;

/** Every string for one locale out of `dictionaries`, the default locale's when it has none. */
export function dictionaryIn<K extends string>(
  dictionaries: Record<Locale, Record<K, string>>,
  locale: Locale,
): Record<K, string> {
  return dictionaries[locale] ?? dictionaries[DEFAULT_LOCALE];
}

/**
 * Build a translator bound to one locale of `dictionaries`.
 *
 * A missing key falls back to the default locale and then to the key itself. It cannot
 * happen through the typed API — the key type is closed — but it can happen when a key
 * arrives as data, from a server error code mapped at runtime, and a visible key beats a
 * blank space where a sentence should be.
 */
export function translatorIn<K extends string>(
  dictionaries: Record<Locale, Record<K, string>>,
  locale: Locale,
): (key: K, values?: TranslationValues) => string {
  const primary = dictionaryIn(dictionaries, locale);
  const fallback = dictionaries[DEFAULT_LOCALE];
  return (key, values) => interpolate(primary[key] ?? fallback[key] ?? key, values);
}

/** Substitute `{name}` placeholders. Unknown placeholders are left as written. */
export function interpolate(template: string, values?: TranslationValues): string {
  if (!values) return template;
  return template.replace(/\{(\w+)\}/g, (whole, name: string) => {
    const v = values[name];
    return v === undefined ? whole : String(v);
  });
}

/**
 * Pick the Russian plural form for `n`.
 *
 * Russian has three: one (1, 21, 31 — but not 11), few (2–4, 22–24) and many (0, 5–20,
 * 25–30). English has two and does not need this, which is why it is a separate helper
 * rather than something the translator does to every string.
 */
export function pluralRu<T>(n: number, forms: { one: T; few: T; many: T }): T {
  const abs = Math.abs(n) % 100;
  const last = abs % 10;
  if (abs > 10 && abs < 20) return forms.many;
  if (last === 1) return forms.one;
  if (last >= 2 && last <= 4) return forms.few;
  return forms.many;
}
