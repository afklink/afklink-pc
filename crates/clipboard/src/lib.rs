//! The PC's clipboard for clipboard sync (`afklink_core::clipboard`): its changes, and its text read
//! and written as `CF_UNICODETEXT`.
//!
//! # How
//!
//! One thread owns a hidden message-only window (`HWND_MESSAGE`) in Windows' clipboard listener list
//! (`AddClipboardFormatListener`). Every `WM_CLIPBOARDUPDATE` posted to it becomes a
//! [`ClipboardChange`] carrying the clipboard's sequence number, broadcast to every session that
//! watches. Reads and writes run on that thread too — handed to it and waited for — so the clipboard
//! is always opened with that window as its owner: after `OpenClipboard(NULL)`, `EmptyClipboard`
//! leaves no owner and `SetClipboardData` fails.
//!
//! The thread starts on first use — a session's viewer turning sync on — and stays: one idle thread
//! with a message queue. Nothing is read before a session asks.
//!
//! Another program may hold the clipboard open: opening is retried for a short while
//! ([`OPEN_ATTEMPTS`] × [`OPEN_RETRY`]) before the call fails as busy.
//!
//! Never logged: the text. Lines carry sizes, sequence numbers, attempts and Windows' errors.

#[cfg(windows)]
mod windows_impl;

use afklink_core::clipboard::{
    ClipboardBackend, ClipboardChange, ClipboardContent, ClipboardError,
};
use tokio::sync::broadcast;

/// How many times opening the clipboard is tried while another program holds it.
pub const OPEN_ATTEMPTS: u32 = 12;
/// The wait between those attempts.
pub const OPEN_RETRY: std::time::Duration = std::time::Duration::from_millis(25);

/// The PC's clipboard, Windows' when built for it; elsewhere every call says it is unavailable.
#[derive(Default)]
pub struct SystemClipboard {
    #[cfg(windows)]
    inner: windows_impl::Listener,
}

impl SystemClipboard {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ClipboardBackend for SystemClipboard {
    fn watch(&self) -> Result<broadcast::Receiver<ClipboardChange>, String> {
        #[cfg(windows)]
        {
            self.inner.watch()
        }
        #[cfg(not(windows))]
        {
            Err("clipboard sync is Windows-only".to_string())
        }
    }

    fn read_text(&self) -> Result<ClipboardContent, ClipboardError> {
        #[cfg(windows)]
        {
            self.inner.read_text()
        }
        #[cfg(not(windows))]
        {
            Err(ClipboardError::Failed(
                "clipboard sync is Windows-only".into(),
            ))
        }
    }

    fn write_text(&self, text: &str) -> Result<u32, ClipboardError> {
        #[cfg(windows)]
        {
            self.inner.write_text(text)
        }
        #[cfg(not(windows))]
        {
            let _ = text;
            Err(ClipboardError::Failed(
                "clipboard sync is Windows-only".into(),
            ))
        }
    }
}
