//! A Telegram user's name as the owner reads it: in toasts, the tray tooltip and the window.
//!
//! One cascade for every place the agent names a viewer — first name, else `@username`, else
//! `#id` — so the toast that says someone connected names them the way the «Доступ разрешён» list
//! in the window does. The first name leads because it is what the owner calls this person; the
//! handle is for someone the server has no first name for; the bare id is the last resort, shown
//! only when nothing else exists.
//!
//! A pairing request is the exception ([`requester_name`]): «Имя (@username)» when both exist. The
//! owner is deciding whether to let a stranger in, and a first name is self-chosen and not unique
//! (anyone holding the code can call themselves «Мама») while the handle is unique. A session's
//! viewer is already bound, so the plain cascade is enough there.
//!
//! No last name: the server stores only `first_name` and `username` (`users` table), so none
//! reaches the agent.
//!
//! `session_request` carries a username but no first name. The first name comes from the binding
//! the session was admitted on: the agent accepts a session only from a user in its binding list
//! (`is_bound`, checked on the request and again on the offer), so that binding is always there when
//! a session starts, and it is the same record the window lists.
//!
//! Every name is shown without the characters that draw nothing or turn the text around
//! ([`clean_name`]): a name of them alone would look empty, and a
//! bidi control can make one read as someone else's. A name with nothing left falls through the
//! cascade as a blank one does.

use afklink_transport::BindingInfo;

/// What a shown name goes without, as inclusive ranges: every format character — Unicode `Cf`, as
/// `/\p{Cf}/u` gives it for Unicode 16: the soft hyphen, the Arabic letter mark (U+061C), zero-width
/// spaces and joiners (U+200B–U+200D), the marks and embeddings that turn text around (U+200E–U+200F,
/// U+202A–U+202E, U+2066–U+2069), word joiners and invisible operators (U+2060–U+2064), the byte
/// order mark (U+FEFF), the tags (U+E0000 block) and the rest — and the Hangul fillers, letters that
/// draw nothing (U+115F, U+1160, U+3164, U+FFA0).
const INVISIBLE: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x115F, 0x1160),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0x3164, 0x3164),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// Whether `c` is left out of a shown name: one of [`INVISIBLE`].
fn invisible(c: char) -> bool {
    let code = u32::from(c);
    INVISIBLE.iter().any(|&(lo, hi)| (lo..=hi).contains(&code))
}

/// `raw` as a name is shown: without format characters and Hangul fillers ([`INVISIBLE`]), and with
/// each control character a space — a line break in a name would split the toast's bold line, and
/// «Вера\tМ» still reads as two words (as the tray has blanked them, `tray_status`). May come out
/// empty or blank; the callers treat that as no name.
pub fn clean_name(raw: &str) -> String {
    raw.chars()
        .filter(|&c| !invisible(c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Which field a displayed name came from, for the debug line that explains a toast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    FirstName,
    /// Both, as «Имя (@username)»: pairing requests only ([`requester_name`]).
    FirstNameAndUsername,
    Username,
    /// Neither a first name nor a username: the numeric Telegram id.
    Id,
}

impl NameSource {
    /// Stable spelling for log fields.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstName => "first_name",
            Self::FirstNameAndUsername => "first_name+username",
            Self::Username => "username",
            Self::Id => "id",
        }
    }
}

/// A name ready to put on screen, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonName {
    pub text: String,
    pub source: NameSource,
}

/// A first name as it is shown: cleaned ([`clean_name`]) and trimmed; `None` when nothing is left —
/// a first name of spaces or of invisible characters alone is no name. What the toasts use, and the
/// window too, so no list carries the raw name.
pub fn shown_first_name(raw: Option<&str>) -> Option<String> {
    let cleaned = clean_name(raw?);
    let first = cleaned.trim();
    (!first.is_empty()).then(|| first.to_owned())
}

/// A username as it is shown, without its `@`: cleaned ([`clean_name`]) and trimmed, a stored `@`
/// dropped; `None` when nothing is left. As [`shown_first_name`], for the toasts and the window.
pub fn shown_username(raw: Option<&str>) -> Option<String> {
    let cleaned = clean_name(raw?);
    let handle = cleaned.trim().trim_start_matches('@');
    (!handle.is_empty()).then(|| handle.to_owned())
}

/// The cascade: first name, else `@username`, else `#id`.
///
/// Each value is cleaned first ([`shown_first_name`], [`shown_username`]). Blank values count as
/// absent — a first name of spaces or of invisible characters alone does not produce an empty
/// toast, and an empty username does not produce a bare `@`. A username stored with its `@` keeps
/// just the one.
pub fn person_name(
    telegram_user_id: i64,
    first_name: Option<&str>,
    username: Option<&str>,
) -> PersonName {
    if let Some(first) = shown_first_name(first_name) {
        return PersonName {
            text: first,
            source: NameSource::FirstName,
        };
    }
    if let Some(handle) = shown_username(username) {
        return PersonName {
            text: format!("@{handle}"),
            source: NameSource::Username,
        };
    }
    PersonName {
        text: format!("#{telegram_user_id}"),
        source: NameSource::Id,
    }
}

/// A pairing requester's name: «Имя (@username)» when both exist, else [`person_name`].
///
/// Used by the pairing toast and the pairing window alike, so the owner approves the same label
/// in both.
pub fn requester_name(
    telegram_user_id: i64,
    first_name: Option<&str>,
    username: Option<&str>,
) -> PersonName {
    let name = person_name(telegram_user_id, first_name, username);
    if name.source != NameSource::FirstName {
        return name;
    }
    match person_name(telegram_user_id, None, username) {
        PersonName {
            text: handle,
            source: NameSource::Username,
        } => PersonName {
            text: format!("{} ({handle})", name.text),
            source: NameSource::FirstNameAndUsername,
        },
        _ => name,
    }
}

/// Where a session's `username` came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernameFrom {
    /// `session_request`: read from the viewer's Telegram sign-in for this very connection.
    Request,
    /// The binding: what the server knew when it last listed bindings to this agent.
    Binding,
    None,
}

impl UsernameFrom {
    /// Stable spelling for log fields.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Binding => "binding",
            Self::None => "none",
        }
    }
}

/// The names a session's viewer is shown under, before the cascade picks one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionNames {
    /// From the binding; `session_request` has no first name.
    pub first_name: Option<String>,
    /// The request's, which is current; else the binding's.
    pub username: Option<String>,
    /// False only if the binding went away between admission and this lookup — the session is then
    /// being refused anyway, and the name falls back to the username or the id.
    pub binding_found: bool,
    pub username_from: UsernameFrom,
}

/// Gather a starting session's names from its request and the binding list, logging the choice.
pub fn session_names(
    bindings: &[BindingInfo],
    session_id: &str,
    telegram_user_id: i64,
    request_username: Option<String>,
) -> SessionNames {
    let binding = bindings
        .iter()
        .find(|b| b.telegram_user_id == telegram_user_id);
    let first_name = binding.and_then(|b| b.first_name.clone());
    let request_username = request_username.filter(|u| !u.trim().is_empty());
    let (username, username_from) = match (request_username, binding) {
        (Some(u), _) => (Some(u), UsernameFrom::Request),
        (None, Some(b)) if b.username.as_deref().is_some_and(|u| !u.trim().is_empty()) => {
            (b.username.clone(), UsernameFrom::Binding)
        }
        _ => (None, UsernameFrom::None),
    };
    let names = SessionNames {
        first_name,
        username,
        binding_found: binding.is_some(),
        username_from,
    };
    let shown = person_name(
        telegram_user_id,
        names.first_name.as_deref(),
        names.username.as_deref(),
    );
    if names.binding_found {
        tracing::debug!(
            session = %session_id,
            telegram_user_id,
            name_source = shown.source.as_str(),
            has_first_name = names.first_name.is_some(),
            username_from = names.username_from.as_str(),
            "viewer name for toasts and the window resolved"
        );
    } else {
        tracing::warn!(
            session = %session_id,
            telegram_user_id,
            name_source = shown.source.as_str(),
            username_from = names.username_from.as_str(),
            "starting session has no binding to name its viewer from; the toast falls back"
        );
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(id: i64, username: Option<&str>, first_name: Option<&str>) -> BindingInfo {
        BindingInfo {
            telegram_user_id: id,
            username: username.map(Into::into),
            first_name: first_name.map(Into::into),
            role: None,
        }
    }

    #[test]
    fn first_name_then_username_then_id() {
        let n = person_name(7, Some("Вера"), Some("vera"));
        assert_eq!((n.text.as_str(), n.source), ("Вера", NameSource::FirstName));

        let n = person_name(7, None, Some("vera"));
        assert_eq!((n.text.as_str(), n.source), ("@vera", NameSource::Username));

        let n = person_name(5_000_000_001, None, None);
        assert_eq!((n.text.as_str(), n.source), ("#5000000001", NameSource::Id));
    }

    #[test]
    fn blank_values_fall_through_and_the_at_sign_is_not_doubled() {
        let n = person_name(7, Some("   "), Some(""));
        assert_eq!((n.text.as_str(), n.source), ("#7", NameSource::Id));

        let n = person_name(7, Some(""), Some("@vera"));
        assert_eq!(n.text, "@vera");

        let n = person_name(7, Some("  Вера "), None);
        assert_eq!(n.text, "Вера");
    }

    /// What draws nothing or turns the text around is not shown.
    #[test]
    fn invisible_and_bidi_characters_are_not_shown() {
        for (raw, shown) in [
            // A right-to-left override: «Мама» typed backwards would read as «Мама».
            ("\u{202E}амаМ", "амаМ"),
            ("Ма\u{200B}ма", "Мама"),
            ("Ма\u{200C}\u{200D}ма", "Мама"),
            ("\u{061C}Вера\u{200E}\u{200F}", "Вера"),
            ("\u{2066}Вера\u{2069}\u{2067}\u{2068}", "Вера"),
            ("\u{202A}\u{202B}\u{202C}\u{202D}Вера", "Вера"),
            ("Ве\u{2060}\u{2061}\u{2062}\u{2063}\u{2064}ра", "Вера"),
            ("\u{FEFF}Вера", "Вера"),
            ("Вера\u{00AD}", "Вера"),
            ("Вера\u{E0001}\u{E0041}\u{E007F}", "Вера"),
            // A control character is a space: the words stay apart.
            ("Вера\tМ\n", "Вера М "),
            // Ordinary letters, emoji and spaces stay.
            ("Вера 🎮", "Вера 🎮"),
        ] {
            assert_eq!(clean_name(raw), shown, "{raw:?}");
        }
    }

    /// Every code point on the list, one by one, and the table in order without overlaps.
    #[test]
    fn the_reviews_list_is_covered() {
        let named = [
            (0x061C, 0x061C),
            (0x200B, 0x200D),
            (0x200E, 0x200F),
            (0x202A, 0x202E),
            (0x2060, 0x2064),
            (0x2066, 0x2069),
            (0xFEFF, 0xFEFF),
            (0x3164, 0x3164),
            (0x115F, 0x115F),
        ];
        for (lo, hi) in named {
            for code in lo..=hi {
                let c = char::from_u32(code).expect("a char");
                assert!(invisible(c), "U+{code:04X}");
            }
        }
        for pair in INVISIBLE.windows(2) {
            assert!(pair[0].1 < pair[1].0, "{pair:?}");
        }
        for &(lo, hi) in INVISIBLE {
            assert!(lo <= hi, "U+{lo:04X}..U+{hi:04X}");
        }
        assert!(!invisible('И') && !invisible(' ') && !invisible('🎮'));
    }

    /// A name of invisible characters alone is no name: the cascade goes on, as for a blank one —
    /// to the username, then to the id.
    #[test]
    fn a_name_with_nothing_left_falls_through_the_cascade() {
        for filler in [
            "\u{3164}",
            "\u{115F}",
            "\u{1160}",
            "\u{FFA0}",
            "\u{200B}\u{200D}",
            "\u{FEFF}",
            " \u{202E} ",
        ] {
            let n = person_name(7, Some(filler), Some("vera"));
            assert_eq!(
                (n.text.as_str(), n.source),
                ("@vera", NameSource::Username),
                "{filler:?}"
            );
            let n = person_name(7, Some(filler), Some(filler));
            assert_eq!(
                (n.text.as_str(), n.source),
                ("#7", NameSource::Id),
                "{filler:?}"
            );
            let n = requester_name(7, Some(filler), Some("vera"));
            assert_eq!(n.text, "@vera", "{filler:?}");
        }
        assert_eq!(
            requester_name(7, Some("\u{202E}Вера"), Some("ve\u{200B}ra")).text,
            "Вера (@vera)"
        );
    }

    /// The names the window shows go through the toasts' cleaning — no bidi controls, no
    /// invisible characters, no padding, no stored `@` — and one with nothing left is none.
    #[test]
    fn the_shown_names_are_cleaned_like_the_toasts() {
        assert_eq!(
            shown_first_name(Some("\u{202E}амаМ\u{200B} ")).as_deref(),
            Some("амаМ")
        );
        assert_eq!(shown_first_name(Some("Вера\tМ")).as_deref(), Some("Вера М"));
        for blank in ["", "   ", "\u{3164}", " \u{202E}\u{200D} "] {
            assert_eq!(shown_first_name(Some(blank)), None, "{blank:?}");
            assert_eq!(shown_username(Some(blank)), None, "{blank:?}");
        }
        assert_eq!(shown_first_name(None), None);
        assert_eq!(
            shown_username(Some(" @ve\u{2060}ra ")).as_deref(),
            Some("vera")
        );
        assert_eq!(shown_username(Some("@")), None);
        assert_eq!(shown_username(None), None);
        // The cascade says the same.
        assert_eq!(person_name(7, Some(" \u{202E}Мама"), None).text, "Мама");
        assert_eq!(
            person_name(7, Some("\u{3164}"), Some("@@vera")).text,
            "@vera"
        );
    }

    #[test]
    fn a_pairing_requester_shows_both_names_when_both_exist() {
        let n = requester_name(7, Some("Вера"), Some("vera"));
        assert_eq!(
            (n.text.as_str(), n.source),
            ("Вера (@vera)", NameSource::FirstNameAndUsername)
        );
        // A handle stored with its `@`, and padding, change nothing.
        assert_eq!(
            requester_name(7, Some(" Вера "), Some("@vera")).text,
            "Вера (@vera)"
        );

        // Otherwise the plain cascade.
        let n = requester_name(7, Some("Вера"), None);
        assert_eq!((n.text.as_str(), n.source), ("Вера", NameSource::FirstName));
        let n = requester_name(7, Some("Вера"), Some("  "));
        assert_eq!((n.text.as_str(), n.source), ("Вера", NameSource::FirstName));
        let n = requester_name(7, None, Some("vera"));
        assert_eq!((n.text.as_str(), n.source), ("@vera", NameSource::Username));
        let n = requester_name(7, Some(""), None);
        assert_eq!((n.text.as_str(), n.source), ("#7", NameSource::Id));
    }

    #[test]
    fn the_owners_case_a_viewer_without_a_username_is_named_from_the_binding() {
        // The report: «#5000000001 подключился…». The request had no username and no first name;
        // the binding the session was admitted on has the first name.
        let bindings = [
            binding(1, Some("other"), Some("Other")),
            binding(5_000_000_001, None, Some("Вера")),
        ];
        let names = session_names(&bindings, "s", 5_000_000_001, None);
        assert!(names.binding_found);
        assert_eq!(names.first_name.as_deref(), Some("Вера"));
        assert_eq!(names.username, None);
        assert_eq!(names.username_from, UsernameFrom::None);
        let shown = person_name(
            5_000_000_001,
            names.first_name.as_deref(),
            names.username.as_deref(),
        );
        assert_eq!(shown.text, "Вера");
    }

    #[test]
    fn the_request_username_is_current_and_wins_over_the_binding() {
        let bindings = [binding(9, Some("old_handle"), None)];
        let names = session_names(&bindings, "s", 9, Some("new_handle".into()));
        assert_eq!(names.username.as_deref(), Some("new_handle"));
        assert_eq!(names.username_from, UsernameFrom::Request);

        let names = session_names(&bindings, "s", 9, None);
        assert_eq!(names.username.as_deref(), Some("old_handle"));
        assert_eq!(names.username_from, UsernameFrom::Binding);

        // A blank request username is no username, not a reason to ignore the binding's.
        let names = session_names(&bindings, "s", 9, Some(" ".into()));
        assert_eq!(names.username.as_deref(), Some("old_handle"));
        assert_eq!(names.username_from, UsernameFrom::Binding);
    }

    #[test]
    fn no_binding_falls_back_to_the_request_then_the_id() {
        let names = session_names(&[], "s", 42, Some("viewer".into()));
        assert!(!names.binding_found);
        assert_eq!(names.first_name, None);
        assert_eq!(names.username.as_deref(), Some("viewer"));

        let names = session_names(&[], "s", 42, None);
        let shown = person_name(42, names.first_name.as_deref(), names.username.as_deref());
        assert_eq!((shown.text.as_str(), shown.source), ("#42", NameSource::Id));
    }
}
