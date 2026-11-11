//! Windows toasts without an «AFKLink» title: the event is the bold first line
//! («Вера управляет ПК»), and a second line, where the string has one, is the line under it
//! («Управление не доходит до игры» over «Установи драйвер в окне AFKLink»). Windows already names
//! the app, with its icon, at the top of every toast, so a bold «AFKLink» would say it twice and
//! take the line the event belongs on. Each line stands alone, without a full stop, so the lines
//! are parted by a line break written into the string, not by a sentence's end, and cut there by
//! `afklink_i18n` ([`NativeText::toast`](afklink_i18n::NativeText::toast),
//! [`TOAST_LINE_BREAK`](afklink_i18n::TOAST_LINE_BREAK)) — before any name goes in.
//!
//! The event goes in as the toast's *title*; a toast given only a body would still get «AFKLink»:
//! - `tauri-plugin-notification` 2.4 (`desktop.rs`, `NotificationBuilder::show`) puts the config's
//!   `productName` in as the title when none is given;
//! - `notify-rust` 4.18 (`windows.rs`, `build_toast`) writes the title as the first `<text>` of the
//!   `ToastGeneric` binding — the one Windows draws bold — then the subtitle (empty here), then the
//!   body. An empty `<text>` takes no line: every toast with a title and a body has had that empty
//!   subtitle between them.
//!
//! The pairing request's toast (`pair_prompt`) has a title of its own, «Запрос на доступ», over
//! «Вера просит доступ к этому ПК» (the request window's heading), and keeps it.
//!
//! Each caller logs what it handed over (the lines' templates — never a name) and a failure.

use afklink_i18n::ToastLines;
use tauri::{AppHandle, Runtime};

/// Hand `lines` to Windows: the event as the bold line, the detail, if any, under it. `Ok` means
/// handed over, not seen: the plugin shows the toast on a task of its own and drops that result.
pub(crate) fn show<R: Runtime>(app: &AppHandle<R>, lines: &ToastLines) -> Result<(), String> {
    use tauri_plugin_notification::NotificationExt;
    let toast = app.notification().builder().title(lines.event.as_str());
    let toast = match &lines.detail {
        Some(detail) => toast.body(detail.as_str()),
        None => toast,
    };
    toast.show().map_err(|e| e.to_string())
}
