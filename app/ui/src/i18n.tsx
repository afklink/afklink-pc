/**
 * The window's binding to `@afklink/i18n/pc` (the window, tray and notification strings only).
 *
 * The locale comes from Rust, not from the browser. Only Rust can read the Windows UI locale, and
 * the tray menu — built before this window exists — has to agree with what the window shows; a
 * webview that decided for itself would put the tray in one language and the panel beside it in
 * another.
 *
 * Because that answer arrives over IPC, the first paint has no locale yet. It uses
 * `DEFAULT_LOCALE`, which is why `ready` exists: the shell holds the content back for that one
 * round trip rather than rendering English and snapping to Russian, which on a small window is a
 * visible flash.
 */
import {
  DEFAULT_LOCALE,
  isLanguagePreference,
  isLocale,
  type LanguagePreference,
  type Locale,
  type TranslationKey,
  type TranslationValues,
  translator,
} from "@afklink/i18n/pc";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

import { getLocale, setLang } from "./tauri";

interface I18nValue {
  locale: Locale;
  preference: LanguagePreference;
  t: (key: TranslationKey, values?: TranslationValues) => string;
  /** Persisted in config.json by Rust; `auto` re-reads the Windows locale each launch. */
  setPreference: (value: LanguagePreference) => void;
  /** False until Rust has answered. The shell renders nothing until then. */
  ready: boolean;
}

const I18nContext = createContext<I18nValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocale] = useState<Locale>(DEFAULT_LOCALE);
  const [preference, setPreferenceState] = useState<LanguagePreference>("auto");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getLocale()
      .then(({ locale: l, preference: p }) => {
        if (cancelled) return;
        if (isLocale(l)) setLocale(l);
        if (isLanguagePreference(p)) setPreferenceState(p);
      })
      .catch(() => {
        // No bridge (`vite dev` in a browser) or Rust failed to answer. The default locale is a
        // usable answer, and blocking the window on it would make the UI undevelopable.
      })
      .finally(() => {
        if (!cancelled) setReady(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const setPreference = useCallback((value: LanguagePreference) => {
    // Applied locally at once and persisted in the background: the click should feel immediate,
    // and a failed write means the choice lasts this launch rather than that it did not happen.
    setPreferenceState(value);
    if (isLocale(value)) setLocale(value);
    setLang(value)
      .then(() => {
        // `auto` resolves against the Windows locale, which only Rust knows — so re-read it
        // rather than guessing here.
        if (value === "auto")
          return getLocale().then(({ locale: l }) => {
            if (isLocale(l)) setLocale(l);
          });
      })
      .catch(() => undefined);
  }, []);

  const value = useMemo<I18nValue>(() => {
    document.documentElement.lang = locale;
    return { locale, preference, t: translator(locale), setPreference, ready };
  }, [locale, preference, setPreference, ready]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

function useI18n(): I18nValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n outside I18nProvider");
  return ctx;
}

export function useT(): I18nValue["t"] {
  return useI18n().t;
}

export function useLanguage(): Omit<I18nValue, "t"> {
  const { t: _t, ...rest } = useI18n();
  return rest;
}
