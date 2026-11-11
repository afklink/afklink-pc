//! «Новый гость: {user}» over «По ссылке владельца»: the owner let a guest in from Telegram by
//! his invite, and nobody at the PC was asked (`binding_added.via: invite`). The person at the PC
//! hears of it at once, before the guest first connects — whether the window is open or not, as
//! with the session toasts.
//!
//! The orchestrator decides that the toast is due — a new guest, not a repeat of someone listed —
//! and says so with [`AgentEvent::GuestInvited`], logging every case it withholds it and why
//! (`afklink_core::agent`); this task only hands the toast to Windows (`crate::toast`: the event bold,
//! the line under it, no «AFKLink» title). The name as the pairing window gives it,
//! "Name (@username)" when both exist (`afklink_core::person_name::requester_name`): this is the
//! first the person at the PC hears of a stranger, and a first name alone is self-chosen;
//! without bidi controls and invisible characters (`clean_name`). The log has the templates and
//! where the name came from, never the name.

use afklink_core::{AgentEvent, PersonName};
use afklink_i18n::{Locale, NativeText, ToastLines};
use tauri::AppHandle;
use tokio::sync::broadcast;

/// The toast for a guest named `name`, in `locale`.
pub(crate) fn lines(locale: Locale, name: &PersonName) -> ToastLines {
    NativeText::NotifyGuestInvited.toast(locale, &[("user", &name.text)])
}

/// Show [`AgentEvent::GuestInvited`] as a toast, from `events` — subscribed before the agent runs,
/// so a guest let in as it connects is not missed; started once the toasts' name is registered
/// (`toast_identity`).
pub(crate) fn spawn(app: AppHandle, locale: Locale, mut events: broadcast::Receiver<AgentEvent>) {
    tauri::async_runtime::spawn(async move {
        loop {
            match events.recv().await {
                Ok(AgentEvent::GuestInvited {
                    telegram_user_id,
                    name,
                }) => {
                    let lines = lines(locale, &name);
                    // A new guest, and the person at the PC not told: a warning, as for the
                    // session-started toast.
                    match crate::toast::show(&app, &lines) {
                        Ok(()) => tracing::debug!(
                            telegram_user_id,
                            name_source = name.source.as_str(),
                            bold = lines.event_template,
                            under = lines.detail_template.unwrap_or("-"),
                            "new-guest toast handed to Windows"
                        ),
                        Err(e) => tracing::warn!(
                            telegram_user_id,
                            "new-guest toast not shown: {e}; the journal has the guest"
                        ),
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(missed)) => tracing::warn!(
                    missed,
                    "new-guest toasts: agent events missed; a guest let in by invite may have gone \
                     untold (the journal has every one)"
                ),
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::debug!(
                        "new-guest toasts: the agent's events ended; no more toasts for guests"
                    );
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use afklink_core::NameSource;

    fn named(text: &str) -> PersonName {
        PersonName {
            text: text.to_string(),
            source: NameSource::FirstName,
        }
    }

    /// The event bold with the name after the colon, where it came from under it; no full stop.
    #[test]
    fn the_toast_names_the_guest_and_says_where_from() {
        let ru = lines(Locale::Ru, &named("Друг"));
        assert_eq!(ru.event, "Новый гость: Друг");
        assert_eq!(ru.detail.as_deref(), Some("По ссылке владельца"));
        assert_eq!(ru.event_template, "Новый гость: {user}");
        let en = lines(Locale::En, &named("Friend"));
        assert_eq!(en.event, "New guest: Friend");
        assert_eq!(en.detail.as_deref(), Some("Via the owner's link"));
    }

    /// Cut on the template, before the name goes in: a name with a line break or a full stop in it
    /// moves nothing, and stays whole on the bold line.
    #[test]
    fn a_name_never_moves_the_cut() {
        let toast = lines(Locale::Ru, &named("J. R.\nR."));
        assert_eq!(toast.event, "Новый гость: J. R.\nR.");
        assert_eq!(toast.detail.as_deref(), Some("По ссылке владельца"));
        let by_id = lines(
            Locale::En,
            &afklink_core::person_name::requester_name(5_000_000_001, None, None),
        );
        assert_eq!(by_id.event, "New guest: #5000000001");
    }

    /// The name as the orchestrator gives it: "Name (@username)", cleaned of a bidi override
    /// and a zero-width space; a filler for a first name falls back to the username.
    #[test]
    fn the_guest_is_named_with_the_username_and_cleanly() {
        use afklink_core::person_name::requester_name;
        let toast = lines(
            Locale::Ru,
            &requester_name(42, Some("\u{202E}Друг\u{200B}"), Some("friend")),
        );
        assert_eq!(toast.event, "Новый гость: Друг (@friend)");
        let toast = lines(
            Locale::Ru,
            &requester_name(42, Some("\u{3164}"), Some("friend")),
        );
        assert_eq!(toast.event, "Новый гость: @friend");
    }
}
