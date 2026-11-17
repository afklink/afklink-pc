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
//!
//! The same task shows a person's new trusted device (device keys, spec §7, §3.4 step 9;
//! [`AgentEvent::NewTrustedDevice`], after its key is in the list's file): the dictionary's
//! `notify.deviceEndorsed.native` (vouched for by another of the person's devices) or
//! `notify.deviceOwnerAllowed.native` (a known guest's new device by the owner's grant).
//! A device is named as the window's «Доступ» names it (`deviceName` in TrustedDevices.tsx), from
//! the dictionary's `notify.device*.native`: «Telegram на iPhone», «Telegram Desktop на macOS»,
//! «Браузер на Android»; a platform this build does not list — `unknown` included — is never shown
//! raw (the key card's words are the viewer's): «Браузер» for a browser
//! (`notify.deviceBrowserAny.native`), «Неизвестное устройство» otherwise
//! (`notify.deviceUnknown.native`). A vouching device so named — or gone from the list — is
//! «другого устройства» (`notify.deviceEndorsedUnknown.native`). The platform names are
//! [`PLATFORMS`], the window's map exactly.

use afklink_core::agent::NewDeviceHow;
use afklink_core::journal::TrustedDevice;
use afklink_core::{AgentEvent, PersonName};
use afklink_i18n::{Locale, NativeText, ToastLines};
use tauri::AppHandle;
use tokio::sync::broadcast;

/// The toast for a guest named `name`, in `locale`.
pub(crate) fn lines(locale: Locale, name: &PersonName) -> ToastLines {
    NativeText::NotifyGuestInvited.toast(locale, &[("user", &name.text)])
}

/// The platforms with a name, as the key card says them (lowercase) — exactly the window's
/// `PLATFORMS` (agent/app/ui/src/components/TrustedDevices.tsx): change both together.
pub(crate) const PLATFORMS: [(&str, &str); 8] = [
    ("iphone", "iPhone"),
    ("ipad", "iPad"),
    ("ios", "iOS"),
    ("android", "Android"),
    ("mac", "Mac"),
    ("macos", "macOS"),
    ("windows", "Windows"),
    ("linux", "Linux"),
];

/// A platform's product name, case aside, as the window's `platformName`; `None` for `unknown` and
/// anything this build does not list — never the raw value, which is the viewer's own words.
pub(crate) fn platform_name(raw: &str) -> Option<&'static str> {
    let raw = raw.to_ascii_lowercase();
    PLATFORMS
        .iter()
        .find(|(key, _)| *key == raw)
        .map(|(_, name)| *name)
}

/// A device as the toasts name it — the window's `deviceName` in the native strings — and whether
/// that is the unknown fallback («Неизвестное устройство»).
pub(crate) fn device_text(locale: Locale, device: &TrustedDevice) -> (String, bool) {
    const UNKNOWN: &str = "unknown (kind or platform unnamed)";
    let platform = platform_name(&device.platform);
    let (text, how) = match (device.kind.as_str(), platform) {
        ("telegram", Some(p)) => (
            NativeText::NotifyDeviceTelegram.fill(locale, &[("platform", p)]),
            "named",
        ),
        ("telegram_desktop", Some(p)) => (
            NativeText::NotifyDeviceDesktop.fill(locale, &[("os", p)]),
            "named",
        ),
        ("browser", Some(p)) => (
            NativeText::NotifyDeviceBrowser.fill(locale, &[("platform", p)]),
            "named",
        ),
        ("browser", None) => (
            NativeText::NotifyDeviceBrowserAny.fill(locale, &[]),
            "a browser, platform unnamed",
        ),
        _ => (NativeText::NotifyDeviceUnknown.fill(locale, &[]), UNKNOWN),
    };
    tracing::debug!(
        kind_known = matches!(
            device.kind.as_str(),
            "telegram" | "telegram_desktop" | "browser"
        ),
        platform_named = platform.is_some(),
        how,
        "new-device toast: a device named"
    );
    (text, how == UNKNOWN)
}

/// The toast for `name`'s new trusted device, in `locale`.
pub(crate) fn new_device_lines(
    locale: Locale,
    name: &PersonName,
    device: &TrustedDevice,
    how: &NewDeviceHow,
) -> ToastLines {
    let (shown, _) = device_text(locale, device);
    match how {
        NewDeviceHow::Endorsed { by } => {
            let by = by
                .as_ref()
                .map(|b| device_text(locale, b))
                .filter(|(_, unknown)| !unknown);
            match by {
                Some((by, _)) => NativeText::NotifyDeviceEndorsed.toast(
                    locale,
                    &[("user", &name.text), ("device", &shown), ("by", &by)],
                ),
                // The vouching device left the list meanwhile, or it is an unknown device:
                // «другого устройства».
                None => NativeText::NotifyDeviceEndorsedUnknown
                    .toast(locale, &[("user", &name.text), ("device", &shown)]),
            }
        }
        NewDeviceHow::OwnerAllowed => NativeText::NotifyDeviceOwnerAllowed
            .toast(locale, &[("user", &name.text), ("device", &shown)]),
    }
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
                Ok(AgentEvent::NewTrustedDevice {
                    telegram_user_id,
                    name,
                    device,
                    how,
                }) => {
                    let lines = new_device_lines(locale, &name, &device, &how);
                    match crate::toast::show(&app, &lines) {
                        Ok(()) => tracing::debug!(
                            telegram_user_id,
                            ground = %device.source,
                            name_source = name.source.as_str(),
                            device_named = platform_name(&device.platform).is_some(),
                            bold = lines.event_template,
                            under = lines.detail_template.unwrap_or("-"),
                            "new-device toast handed to Windows"
                        ),
                        Err(e) => tracing::warn!(
                            telegram_user_id,
                            "new-device toast not shown: {e}; the journal has the device"
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

    fn device(platform: &str, source: &str) -> TrustedDevice {
        device_of("telegram", platform, source)
    }

    fn device_of(kind: &str, platform: &str, source: &str) -> TrustedDevice {
        TrustedDevice {
            kind: kind.into(),
            platform: platform.into(),
            source: source.into(),
        }
    }

    /// The platform map is the window's `PLATFORMS`, entry for entry (TrustedDevices.tsx): read
    /// from the source, so a change on one side fails here.
    #[test]
    fn the_platform_map_is_the_windows() {
        let tsx = include_str!("../../ui/src/components/TrustedDevices.tsx");
        let start = tsx.find("const PLATFORMS").expect("the window's PLATFORMS");
        let end = start + tsx[start..].find("]);").expect("its end");
        let window: Vec<(String, String)> = tsx[start..end]
            .lines()
            .filter_map(|l| {
                let l = l.trim().strip_prefix("[\"")?;
                let (key, rest) = l.split_once("\", \"")?;
                let name = rest.strip_suffix("\"],")?;
                Some((key.to_string(), name.to_string()))
            })
            .collect();
        let ours: Vec<(String, String)> = PLATFORMS
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        assert_eq!(window, ours);
        assert_eq!(platform_name("IOS"), Some("iOS"));
        assert_eq!(platform_name("macos"), Some("macOS"));
        for raw in ["unknown", "", "toaster", "iPhone\u{200B}"] {
            assert_eq!(platform_name(raw), None, "{raw}");
        }
    }

    /// Device names as the window says them, from the native strings; never a raw value.
    #[test]
    fn a_device_is_named_as_the_window_names_it() {
        let name = |kind: &str, platform: &str| {
            device_text(Locale::Ru, &device_of(kind, platform, "pair"))
        };
        assert_eq!(
            name("telegram", "iphone"),
            ("Telegram на iPhone".into(), false)
        );
        assert_eq!(
            name("telegram_desktop", "macos"),
            ("Telegram Desktop на macOS".into(), false)
        );
        assert_eq!(
            name("browser", "android"),
            ("Браузер на Android".into(), false)
        );
        assert_eq!(name("browser", "unknown"), ("Браузер".into(), false));
        assert_eq!(name("browser", "toaster"), ("Браузер".into(), false));
        for (kind, platform) in [
            ("telegram", "unknown"),
            ("telegram", "toaster"),
            ("telegram_desktop", "unknown"),
            ("toaster", "iphone"),
            ("", ""),
        ] {
            assert_eq!(
                name(kind, platform),
                ("Неизвестное устройство".into(), true),
                "{kind} {platform}"
            );
        }
        let en = device_text(Locale::En, &device_of("telegram", "ios", "pair"));
        assert_eq!(en.0, "Telegram on iOS");
        assert_eq!(
            device_text(Locale::En, &device_of("telegram", "unknown", "pair")).0,
            "Unknown device"
        );
        assert_eq!(
            device_text(Locale::En, &device_of("browser", "unknown", "pair")).0,
            "Browser"
        );
    }

    /// A vouched-for device names the device that vouched; a known guest's new device by the
    /// owner's grant says the owner allowed it. Devices as the window names them; an unknown
    /// vouching device, or one gone, is «другого устройства».
    #[test]
    fn a_new_device_toast_says_how_it_got_in() {
        let endorsed = new_device_lines(
            Locale::Ru,
            &named("Вера"),
            &device("iphone", "endorse"),
            &NewDeviceHow::Endorsed {
                by: Some(device_of("browser", "android", "pair")),
            },
        );
        assert_eq!(endorsed.event, "Вера: новое устройство");
        assert_eq!(
            endorsed.detail.as_deref(),
            Some("Telegram на iPhone · Подтверждено с «Браузер на Android»")
        );
        let allowed = new_device_lines(
            Locale::En,
            &named("Vera"),
            &device_of("telegram_desktop", "linux", "grant"),
            &NewDeviceHow::OwnerAllowed,
        );
        assert_eq!(allowed.event, "Vera: new device");
        assert_eq!(
            allowed.detail.as_deref(),
            Some("Telegram Desktop on Linux · Allowed by the owner")
        );
        // The vouching device gone: «другого устройства», never a raw value.
        let gone = new_device_lines(
            Locale::Ru,
            &named("Вера"),
            &device("iphone", "endorse"),
            &NewDeviceHow::Endorsed { by: None },
        );
        assert_eq!(
            gone.detail.as_deref(),
            Some("Telegram на iPhone · Подтверждено с другого устройства")
        );
        // A vouching browser with an unnamed platform is still a device with a name.
        let any = new_device_lines(
            Locale::Ru,
            &named("Вера"),
            &device("ios", "endorse"),
            &NewDeviceHow::Endorsed {
                by: Some(device_of("browser", "unknown", "pair")),
            },
        );
        assert_eq!(
            any.detail.as_deref(),
            Some("Telegram на iOS · Подтверждено с «Браузер»")
        );
        // Platforms this build does not know (the viewer's words): neither is shown raw — the
        // new one is «Неизвестное устройство», the vouching one «другого устройства».
        let strange = new_device_lines(
            Locale::Ru,
            &named("Вера"),
            &device("<b>evil</b>", "endorse"),
            &NewDeviceHow::Endorsed {
                by: Some(device("toaster", "pair")),
            },
        );
        assert_eq!(
            strange.detail.as_deref(),
            Some("Неизвестное устройство · Подтверждено с другого устройства")
        );
        let strange = new_device_lines(
            Locale::En,
            &named("Vera"),
            &device("unknown", "grant"),
            &NewDeviceHow::OwnerAllowed,
        );
        assert_eq!(
            strange.detail.as_deref(),
            Some("Unknown device · Allowed by the owner")
        );
        for locale in [Locale::Ru, Locale::En] {
            let l = new_device_lines(
                locale,
                &named("Vera"),
                &device("toaster", "endorse"),
                &NewDeviceHow::Endorsed {
                    by: Some(device("toaster", "pair")),
                },
            );
            let detail = l.detail.unwrap_or_default();
            assert!(
                !detail.contains("toaster") && !detail.contains('{'),
                "{detail}"
            );
        }
    }
}
