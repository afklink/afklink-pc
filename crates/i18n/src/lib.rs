//! Native-language strings for the Windows agent.
//!
//! The agent's window is a webview and gets its text from `@afklink/i18n` directly. This
//! crate covers the strings Windows draws instead of us (the tray menu and tooltip, and toast
//! notifications), which have to be `&'static str` available synchronously in Rust.
//!
//! [`generated`] is emitted from the same TypeScript dictionary by
//! `packages/i18n/scripts/emit.ts`, so the phrase on the tray menu and the phrase on the
//! button inside the window cannot diverge. Do not edit it; run `bun run i18n:emit`.
//!
//! ## Which language
//!
//! The default comes from the Windows UI locale, because that is the language the person
//! already chose for everything else on the machine. It is a guess, and a work laptop
//! imaged in English by someone else is exactly how it goes wrong, so [`Locale`] can be
//! overridden from config (`lang: "auto" | "ru" | "en"`), and the override wins.
//!
//! Russian is served for Russian and for the post-Soviet languages where Russian is commonly
//! read ([`RUSSIAN_READING_LANGUAGES`]); anything else is served English, matching
//! `resolveLocale` and `DEFAULT_LOCALE` on the TypeScript side: the alternative is showing
//! Cyrillic to someone who did not ask for it.

pub mod generated;

pub use generated::{NativeText, ALL_NATIVE_TEXT};

/// Primary language subtags served Russian although we do not ship them: the post-Soviet
/// languages where Russian is commonly read: Ukrainian, Belarusian, Kazakh, Kyrgyz, Uzbek, Tajik
/// and Azerbaijani. A hand-written copy of
/// `RUSSIAN_READING_LANGUAGES` in `@afklink/i18n` (`contract/packages/i18n/src/locale.ts`);
/// a test holds the two equal.
pub const RUSSIAN_READING_LANGUAGES: [&str; 7] = ["uk", "be", "kk", "ky", "uz", "tg", "az"];

/// Languages the product ships. Mirrors `LOCALES` in `@afklink/i18n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Locale {
    Ru,
    /// The fallback for every language we do not ship.
    #[default]
    En,
}

impl Locale {
    /// BCP-47 primary subtag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Ru => "ru",
            Self::En => "en",
        }
    }

    /// Resolve a platform language tag.
    ///
    /// Accepts what the various Windows APIs actually return — `ru-RU`, `ru_RU`, `RU`,
    /// `uz-Latn-UZ` — by matching on the primary subtag only. Russian for `ru` and for
    /// [`RUSSIAN_READING_LANGUAGES`]; unknown or empty gives [`Locale::En`].
    pub fn from_tag(tag: &str) -> Self {
        Self::decide(tag).0
    }

    /// [`Self::from_tag`] and the rule it went by, for the log — the contract's
    /// `localeDecision`: `shipped` (`ru`, `en`), `ru-reading` ([`RUSSIAN_READING_LANGUAGES`]),
    /// `other` (any other language: English), `none` (empty: English).
    pub fn decide(tag: &str) -> (Self, &'static str) {
        let primary = tag
            .trim()
            .split(['-', '_'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        match primary.as_str() {
            "" => (Self::En, "none"),
            "ru" => (Self::Ru, "shipped"),
            "en" => (Self::En, "shipped"),
            p if RUSSIAN_READING_LANGUAGES.contains(&p) => (Self::Ru, "ru-reading"),
            _ => (Self::En, "other"),
        }
    }

    /// Apply a configured preference over the platform locale.
    ///
    /// `None`, `Some("auto")`, and anything unrecognised defer to the platform — which is
    /// what makes the config value safe to store as a free-form string, including one
    /// written by a newer build.
    pub fn resolve(preference: Option<&str>) -> Self {
        match preference.map(str::trim) {
            Some("ru") => Self::Ru,
            Some("en") => Self::En,
            _ => Self::from_system(),
        }
    }

    /// The Windows UI locale, or [`Locale::En`] off Windows and on any failure.
    pub fn from_system() -> Self {
        #[cfg(windows)]
        {
            match sys::ui_locale() {
                Some(tag) => {
                    let (locale, rule) = Self::decide(&tag);
                    tracing::debug!(
                        "language from Windows: {tag:?} -> {} (rule {rule})",
                        locale.tag()
                    );
                    locale
                }
                None => {
                    tracing::debug!("could not read the UI locale; using {}", Self::En.tag());
                    Self::En
                }
            }
        }
        #[cfg(not(windows))]
        {
            Self::En
        }
    }

    /// `items` as one list joined by "and", as the window writes it with
    /// `Intl.ListFormat(locale, { type: "conjunction" })` — there is no ICU on this side, so CLDR's
    /// two patterns are spelled out: «Вера и Мама», «Дима, Вера и Мама»; "Vera and Mom", "Dima, Vera,
    /// and Mom" (`en` keeps the serial comma, `ru` has none). One item is itself; none is empty.
    ///
    /// For `{users}` (`tray.statusLiveMany.native`), so the names read «Вера и Мама управляют», not
    /// «Вера, Мама управляют».
    pub fn and_list<S: AsRef<str>>(self, items: &[S]) -> String {
        let (pair, last) = match self {
            Self::Ru => (" и ", " и "),
            Self::En => (" and ", ", and "),
        };
        match items {
            [] => String::new(),
            [one] => one.as_ref().to_string(),
            [a, b] => format!("{}{pair}{}", a.as_ref(), b.as_ref()),
            [head @ .., tail] => {
                let head: Vec<&str> = head.iter().map(AsRef::as_ref).collect();
                format!("{}{last}{}", head.join(", "), tail.as_ref())
            }
        }
    }
}

/// The placeholder a toast body carries for the person it is about.
pub const USER_PLACEHOLDER: &str = "{user}";

/// What parts a toast's bold line from the line under it, in the template: a line break, written
/// `\n` in the dictionary. Each line stands on its own and carries no full stop, so there is no
/// sentence end to cut at; and a break written into the string is explicit where a full stop is
/// not: one in a name («J. Smith») would look the same.
pub const TOAST_LINE_BREAK: char = '\n';

impl NativeText {
    /// Shorthand for [`NativeText::get`], for call sites that read better this way.
    pub const fn t(self, locale: Locale) -> &'static str {
        self.get(locale)
    }

    /// This string in `locale`, with [`USER_PLACEHOLDER`] replaced by a person's name.
    ///
    /// Single pass: a name that itself contains `{user}` is inserted as written, not expanded
    /// again. A string without the placeholder comes back unchanged.
    pub fn with_user(self, locale: Locale, user: &str) -> String {
        self.get(locale).replace(USER_PLACEHOLDER, user)
    }

    /// This string in `locale`, with each `{name}` in `values` replaced by its value — for the
    /// strings with placeholders other than `{user}` (`{users}`, `{minutes}`, `{hours}`).
    ///
    /// Single pass, like [`Self::with_user`]: a value that itself contains a placeholder is
    /// inserted as written. A placeholder without a value stays visible, as the TypeScript
    /// `interpolate` leaves it, so a missing argument shows on screen instead of reading like a
    /// finished phrase.
    pub fn fill(self, locale: Locale, values: &[(&str, &str)]) -> String {
        fill_template(self.get(locale), values)
    }

    /// This string as a Windows toast: its first line is the event, the line Windows draws bold;
    /// the second, if there is one, goes under it: «Управление не доходит до игры» over
    /// «Установи драйвер в окне AFKLink». Each line filled as [`Self::fill`] fills.
    ///
    /// No «AFKLink» title over the event: Windows already names the app, with its icon, at the top
    /// of every toast. Neither line ends in a full stop; they are cut at [`TOAST_LINE_BREAK`].
    ///
    /// Cut on the template, before any value goes in, so no value (a name with a full stop in it,
    /// «J. Smith», included) ever moves the cut.
    pub fn toast(self, locale: Locale, values: &[(&str, &str)]) -> ToastLines {
        let (event, detail) = toast_lines(self.get(locale));
        ToastLines {
            event: fill_template(event, values),
            detail: detail.map(|d| fill_template(d, values)),
            event_template: event,
            detail_template: detail,
        }
    }
}

/// A Windows toast's text ([`NativeText::toast`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToastLines {
    /// The first line: what happened, the bold one — «Вера управляет ПК».
    pub event: String,
    /// The line under it, when the string has a second one.
    pub detail: Option<String>,
    /// [`Self::event`] before the values went in, for the log — which never carries a name.
    pub event_template: &'static str,
    /// [`Self::detail`] before the values went in.
    pub detail_template: Option<&'static str>,
}

/// `template` cut at its first [`TOAST_LINE_BREAK`]: the line before it and, when there is any, the
/// rest, each trimmed. No break: one line. The dictionary's tests hold a toast to two lines; a third
/// would stay in the rest, under the event, rather than be dropped. A full stop is not a cut.
fn toast_lines(template: &str) -> (&str, Option<&str>) {
    let Some((event, rest)) = template.split_once(TOAST_LINE_BREAK) else {
        return (template, None);
    };
    let rest = rest.trim();
    (event.trim_end(), (!rest.is_empty()).then_some(rest))
}

/// [`NativeText::fill`] on any template.
fn fill_template(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            // An unclosed brace is text.
            out.push_str(&rest[open..]);
            return out;
        };
        let name = &after[..close];
        match values.iter().find(|(n, _)| *n == name) {
            Some((_, value)) => out.push_str(value),
            None => {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(windows)]
mod sys {
    use windows::Win32::Globalization::GetUserDefaultLocaleName;

    /// `GetUserDefaultLocaleName` — the user's own regional setting, e.g. `"ru-RU"`.
    ///
    /// Preferred over `GetUserDefaultUILanguage`, which returns an LCID that then has to
    /// be mapped, and over the *system* default, which is the machine's language rather
    /// than this person's.
    pub fn ui_locale() -> Option<String> {
        // LOCALE_NAME_MAX_LENGTH is 85 wide chars, including the terminator.
        let mut buf = [0u16; 85];
        // SAFETY: `buf` is a live, correctly sized slice; the call writes at most
        // `buf.len()` UTF-16 units and returns how many it wrote, including the NUL.
        let written = unsafe { GetUserDefaultLocaleName(&mut buf) };
        if written <= 1 {
            return None;
        }
        // Drop the trailing NUL that the count includes.
        let len = (written as usize) - 1;
        Some(String::from_utf16_lossy(&buf[..len]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_and_telegram_locale_spellings_both_resolve() {
        for tag in ["ru", "ru-RU", "ru_RU", "RU", " ru-ru "] {
            assert_eq!(Locale::from_tag(tag), Locale::Ru, "{tag}");
        }
        for tag in ["en", "en-GB", "en_US"] {
            assert_eq!(Locale::from_tag(tag), Locale::En, "{tag}");
        }
    }

    #[test]
    fn a_language_we_do_not_ship_becomes_english() {
        // Not Russian: showing Cyrillic to a German, Persian or Armenian speaker who never
        // asked is worse than showing English.
        for tag in ["de", "fa", "zh-Hans", "hy", "ka", "en-US", "tgk", "", "   "] {
            assert_eq!(Locale::from_tag(tag), Locale::En, "{tag:?}");
        }
    }

    #[test]
    fn languages_where_russian_is_read_become_russian() {
        // Windows spells them with a region and often a script.
        for tag in ["uk", "be", "kk", "ky", "uz", "tg", "az"] {
            assert_eq!(Locale::decide(tag), (Locale::Ru, "ru-reading"), "{tag:?}");
        }
        for tag in [
            "uk-UA",
            "be-BY",
            "kk-KZ",
            "ky-KG",
            "uz-Latn-UZ",
            "tg-Cyrl-TJ",
            "az-Latn-AZ",
            "KK_kz",
        ] {
            assert_eq!(Locale::from_tag(tag), Locale::Ru, "{tag:?}");
        }
        assert_eq!(Locale::decide("ru-RU"), (Locale::Ru, "shipped"));
        assert_eq!(Locale::decide("en-GB"), (Locale::En, "shipped"));
        assert_eq!(Locale::decide("hy-AM"), (Locale::En, "other"));
        assert_eq!(Locale::decide(" "), (Locale::En, "none"));
    }

    #[test]
    fn russian_reading_languages_are_the_contracts() {
        // The contract cannot be imported here: its list is read from its source.
        let source = include_str!("../../../contract/packages/i18n/src/locale.ts");
        let start = source
            .find("RUSSIAN_READING_LANGUAGES = [")
            .expect("the contract's locale.ts has no RUSSIAN_READING_LANGUAGES");
        let rest = &source[start..];
        let list = &rest[rest.find('[').unwrap() + 1..rest.find(']').unwrap()];
        let mut theirs: Vec<&str> = list
            .split(',')
            .map(|s| s.trim().trim_matches('"'))
            .filter(|s| !s.is_empty())
            .collect();
        let mut ours = RUSSIAN_READING_LANGUAGES.to_vec();
        theirs.sort_unstable();
        ours.sort_unstable();
        assert_eq!(ours, theirs);
    }

    #[test]
    fn an_explicit_preference_wins_and_auto_defers() {
        assert_eq!(Locale::resolve(Some("ru")), Locale::Ru);
        assert_eq!(Locale::resolve(Some("en")), Locale::En);
        // "auto", junk, and absent all fall through to the system; off Windows that is En.
        assert_eq!(Locale::resolve(Some("auto")), Locale::from_system());
        assert_eq!(Locale::resolve(Some("klingon")), Locale::from_system());
        assert_eq!(Locale::resolve(None), Locale::from_system());
    }

    #[test]
    fn every_native_string_exists_in_both_languages() {
        // The generated match is exhaustive, so this is really checking that emit did not
        // write an empty or placeholder value for one language.
        for text in ALL_NATIVE_TEXT {
            for locale in [Locale::Ru, Locale::En] {
                let s = text.get(locale);
                assert!(!s.is_empty(), "{} is empty in {}", text.key(), locale.tag());
                assert_eq!(s.trim(), s, "{} has stray whitespace", text.key());
            }
        }
    }

    #[test]
    fn keys_carry_the_native_marker() {
        // If this fails, emit picked up a key it should have left to the webview.
        for text in ALL_NATIVE_TEXT {
            assert!(text.key().ends_with(".native"), "{}", text.key());
        }
    }

    /// The `{name}` placeholders in a template, sorted and deduplicated.
    fn placeholders(s: &str) -> Vec<&str> {
        let mut names: Vec<&str> = s
            .split('{')
            .skip(1)
            .filter_map(|part| part.split_once('}').map(|(name, _)| name))
            .filter(|name| !name.is_empty() && name.chars().all(|c| c.is_alphanumeric()))
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    #[test]
    fn placeholders_survive_translation() {
        // Same check the TypeScript suite runs: a `{user}` or `{minutes}` renamed in one language
        // renders as a literal brace on someone's desktop.
        for text in ALL_NATIVE_TEXT {
            assert_eq!(
                placeholders(text.get(Locale::Ru)),
                placeholders(text.get(Locale::En)),
                "{} differs on its placeholders",
                text.key()
            );
        }
    }

    #[test]
    fn fill_is_a_single_pass_and_leaves_a_missing_value_visible() {
        assert_eq!(
            fill_template(
                "{hours} ч {minutes} мин",
                &[("hours", "1"), ("minutes", "05")]
            ),
            "1 ч 05 мин"
        );
        // A value holding a placeholder is not expanded again.
        assert_eq!(
            fill_template("{users} управляют", &[("users", "{users}, Мама")]),
            "{users}, Мама управляют"
        );
        assert_eq!(
            fill_template("{minutes} мин", &[]),
            "{minutes} мин",
            "missing"
        );
        assert_eq!(fill_template("a { b", &[("b", "x")]), "a { b", "unclosed");
        assert_eq!(fill_template("", &[]), "");
    }

    #[test]
    fn session_toasts_are_the_name_and_a_short_verb_phrase() {
        // A long body gets cut off by the toast, so each is the name and a short phrase, in the
        // present tense so the Russian carries no gender.
        use NativeText::{NotifyPairRequestBody, NotifySessionEnded, NotifySessionStarted};
        let ru = |text: NativeText| text.with_user(Locale::Ru, "Вера");
        let en = |text: NativeText| text.with_user(Locale::En, "Vera");

        // «ПК», as everywhere else in the window. No full stop: the line stands alone.
        assert_eq!(ru(NotifySessionStarted), "Вера управляет ПК");
        assert_eq!(ru(NotifySessionEnded), "Вера отключается");
        // The pairing request's toast says what the request window's heading says.
        assert_eq!(ru(NotifyPairRequestBody), "Вера просит доступ к компьютеру");
        assert_eq!(en(NotifySessionStarted), "Vera is controlling this PC");
        assert_eq!(en(NotifySessionEnded), "Vera disconnected");
        assert_eq!(
            en(NotifyPairRequestBody),
            "Vera is requesting access to the computer"
        );
        assert_eq!(
            NotifyPairRequestBody.with_user(Locale::Ru, "Вера (@vera)"),
            "Вера (@vera) просит доступ к компьютеру"
        );
        // No «AFKLink» title over them: each is the toast's bold line itself, alone.
        for (text, line) in [
            (NotifySessionStarted, "Вера управляет ПК"),
            (NotifySessionEnded, "Вера отключается"),
        ] {
            let toast = text.toast(Locale::Ru, &[("user", "Вера")]);
            assert_eq!(toast.event, line);
            assert_eq!(toast.detail, None, "{}", text.key());
        }
    }

    /// No «AFKLink» title: the event is the bold first line, and a second line, where a string has
    /// one, is the line under it. Neither ends in a full stop.
    #[test]
    fn a_toast_leads_with_the_event_and_puts_the_rest_under_it() {
        let driver = NativeText::NotifyDriverNeeded.toast(Locale::Ru, &[]);
        assert_eq!(driver.event, "Управление не доходит до игры");
        assert_eq!(
            driver.detail.as_deref(),
            Some("Установи драйвер в окне AFKLink")
        );
        assert_eq!(driver.event_template, "Управление не доходит до игры");
        assert_eq!(
            driver.detail_template,
            Some("Установи драйвер в окне AFKLink")
        );
        let driver = NativeText::NotifyDriverNeeded.toast(Locale::En, &[]);
        assert_eq!(driver.event, "Controls aren't reaching the game");
        assert_eq!(
            driver.detail.as_deref(),
            Some("Install the driver in the AFKLink window")
        );

        let updated = NativeText::NotifyUpdated.toast(Locale::Ru, &[("version", "0.3.1")]);
        assert_eq!(updated.event, "AFKLink обновлён до 0.3.1");
        assert_eq!(updated.detail, None);
        assert_eq!(updated.event_template, "AFKLink обновлён до {version}");
        let rolled_back =
            NativeText::NotifyUpdateRolledBack.toast(Locale::En, &[("version", "0.3.1")]);
        assert_eq!(rolled_back.event, "Couldn't update to 0.3.1");
        assert_eq!(rolled_back.detail, None);

        // Cut before the name goes in: a full stop in a name, or a line break, moves nothing.
        let started =
            NativeText::NotifySessionStarted.toast(Locale::En, &[("user", "J. R. R. Tolkien")]);
        assert_eq!(started.event, "J. R. R. Tolkien is controlling this PC");
        assert_eq!(started.detail, None);
        assert_eq!(started.event_template, "{user} is controlling this PC");
        let ended = NativeText::NotifySessionEnded.toast(Locale::Ru, &[("user", "Вера\nМама")]);
        assert_eq!(ended.event, "Вера\nМама отключается");
        assert_eq!(ended.detail, None);
    }

    /// Every `notify.*` string, in both languages (the toasts `NativeText::toast` cuts and the
    /// pairing request's own title and body): lines that stand alone, so none ends in a full stop,
    /// none is blank, none holds a second sentence the line break should have parted, and a toast
    /// has two lines at most.
    #[test]
    fn no_toast_line_ends_in_a_full_stop() {
        let toasts: Vec<NativeText> = ALL_NATIVE_TEXT
            .into_iter()
            .filter(|text| text.key().starts_with("notify."))
            .collect();
        assert!(toasts.len() >= 8, "{} notify.* strings", toasts.len());
        for text in toasts {
            let mut lines = Vec::new();
            for locale in [Locale::Ru, Locale::En] {
                let template = text.get(locale);
                let toast = text.toast(locale, &[]);
                let at = format!("{} in {}", text.key(), locale.tag());
                assert!(
                    template.matches(TOAST_LINE_BREAK).count() <= 1,
                    "{at}: more than two lines"
                );
                let mut shown = vec![toast.event_template];
                shown.extend(toast.detail_template);
                for line in &shown {
                    assert!(!line.is_empty(), "{at}: a blank line");
                    assert!(!line.ends_with('.'), "{at}: {line:?} ends in a full stop");
                    assert!(
                        !line.contains(['\n', '\r']),
                        "{at}: {line:?} still has a break"
                    );
                    assert!(
                        ![". ", "! ", "? "].iter().any(|stop| line.contains(stop)),
                        "{at}: {line:?} holds two sentences; part them with a line break"
                    );
                }
                lines.push(shown.len());
            }
            assert_eq!(
                lines[0],
                lines[1],
                "{}: the languages differ on the lines",
                text.key()
            );
        }
    }

    #[test]
    fn a_toast_is_cut_at_its_line_break() {
        assert_eq!(toast_lines("Один\nДва"), ("Один", Some("Два")));
        assert_eq!(
            toast_lines("Один \n  Два "),
            ("Один", Some("Два")),
            "trimmed"
        );
        assert_eq!(
            toast_lines("Один\r\nДва"),
            ("Один", Some("Два")),
            "a Windows break"
        );
        // Only the first break cuts: a third line stays under the event, not dropped.
        assert_eq!(toast_lines("Один\nДва\nТри"), ("Один", Some("Два\nТри")));
        // A full stop is not a break.
        assert_eq!(toast_lines("Один. Два."), ("Один. Два.", None));
        assert_eq!(toast_lines("v0.3.1 вышла"), ("v0.3.1 вышла", None));
        assert_eq!(toast_lines("Конец\n "), ("Конец", None), "nothing after it");
        assert_eq!(toast_lines(""), ("", None));
    }

    /// The window's `Intl.ListFormat(locale, { type: "conjunction" })`, as CLDR has it.
    #[test]
    fn names_join_with_and_as_the_window_joins_them() {
        let none: [&str; 0] = [];
        assert_eq!(Locale::Ru.and_list(&none), "");
        assert_eq!(Locale::Ru.and_list(&["Вера"]), "Вера");
        assert_eq!(Locale::Ru.and_list(&["Вера", "Мама"]), "Вера и Мама");
        assert_eq!(
            Locale::Ru.and_list(&["Дима", "Вера", "Мама"]),
            "Дима, Вера и Мама"
        );
        assert_eq!(Locale::En.and_list(&["Vera"]), "Vera");
        assert_eq!(Locale::En.and_list(&["Vera", "Mom"]), "Vera and Mom");
        assert_eq!(
            Locale::En.and_list(&["Dima", "Vera", "Mom"]),
            "Dima, Vera, and Mom"
        );
        assert_eq!(
            Locale::En.and_list(&["A".to_string(), "B".into(), "C".into(), "D".into()]),
            "A, B, C, and D"
        );
        assert_eq!(
            NativeText::TrayStatusLiveMany.fill(
                Locale::Ru,
                &[("users", &Locale::Ru.and_list(&["Вера", "Мама"]))]
            ),
            "Вера и Мама управляют"
        );
    }

    #[test]
    fn toast_bodies_are_short() {
        // Minimal on-screen text: the name plus two or three words. A body that grows past this
        // is what got cut off in the first place. English gets two more, for the auxiliary, the
        // article and the infinitive's "to" Russian does without («управляет ПК» / "is
        // controlling this PC").
        //
        // The pairing request's body is the one exception: it repeats the request window's
        // heading, so it may run to five words in Russian and six in English. It stands under the
        // toast's own title, «Запрос на доступ», not as a bold line alone that would be cut.
        for text in [
            NativeText::NotifySessionStarted,
            NativeText::NotifySessionEnded,
            NativeText::NotifyPairRequestBody,
        ] {
            for locale in [Locale::Ru, Locale::En] {
                let s = text.get(locale);
                assert!(s.contains(USER_PLACEHOLDER), "{} lost {{user}}", text.key());
                // One line, standing alone: no full stop.
                assert!(
                    !s.ends_with('.'),
                    "{} in {}: a final full stop",
                    text.key(),
                    locale.tag()
                );
                assert!(
                    !s.contains(TOAST_LINE_BREAK),
                    "{} in {}: one line",
                    text.key(),
                    locale.tag()
                );
                let words = s.split_whitespace().count() - 1;
                let max = match (text, locale) {
                    (NativeText::NotifyPairRequestBody, Locale::Ru) => 5,
                    (NativeText::NotifyPairRequestBody, Locale::En) => 6,
                    (_, Locale::Ru) => 3,
                    (_, Locale::En) => 5,
                };
                assert!(
                    (1..=max).contains(&words),
                    "{} in {}: {words} words besides the name",
                    text.key(),
                    locale.tag()
                );
            }
        }
    }

    #[test]
    fn with_user_is_a_single_pass_and_leaves_plain_strings_alone() {
        assert_eq!(
            NativeText::NotifySessionEnded.with_user(Locale::En, "{user}"),
            "{user} disconnected"
        );
        assert_eq!(
            NativeText::NotifyDriverNeeded.with_user(Locale::Ru, "Вера"),
            NativeText::NotifyDriverNeeded.get(Locale::Ru)
        );
    }
}
