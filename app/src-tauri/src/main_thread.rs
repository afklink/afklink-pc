//! Which thread is the main thread — Tauri's event loop, where the windows and the tray live and
//! where every command the window calls without `async` runs — so that code called from anywhere can
//! tell whether a Tauri window call would be answered in place or would wait for that thread.
//!
//! From any other thread a window getter (`hwnd()`, `is_visible()`, `current_monitor()`, …) posts a
//! request to the event loop and blocks until the main thread has answered it. Waiting so while
//! holding a lock the main thread takes is a deadlock (`capture_guard`).
//!
//! Recorded once, first thing in `setup`, which Tauri runs on the event loop's thread. Before that —
//! and in the tests, where nothing records it — the thread named `main` counts: Rust names the thread
//! that runs `fn main` so, and Tauri's event loop runs on it.

use std::sync::OnceLock;
use std::thread::ThreadId;

/// The main thread, once [`note`] has recorded it.
static MAIN: OnceLock<ThreadId> = OnceLock::new();

/// Record the calling thread as the main thread. Called from `setup`, on the event loop's thread.
pub(crate) fn note() {
    let current = std::thread::current();
    match MAIN.set(current.id()) {
        Ok(()) => tracing::debug!(
            thread = ?current.id(),
            name = current.name().unwrap_or("-"),
            "main thread recorded: a window call from any other thread waits for it"
        ),
        Err(_) => tracing::debug!(
            thread = ?current.id(),
            "main thread recorded before in this process; the first record stays"
        ),
    }
}

/// Whether the calling thread is the main thread.
pub(crate) fn is_current() -> bool {
    let current = std::thread::current();
    is_main(MAIN.get().copied(), current.id(), current.name())
}

/// The thread `id` (named `name`) is the main thread: the recorded one, or with none recorded, the
/// one named `main`.
fn is_main(recorded: Option<ThreadId>, id: ThreadId, name: Option<&str>) -> bool {
    match recorded {
        Some(main) => main == id,
        None => name == Some("main"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recorded thread is the main thread, whatever the names say; with none recorded, the one
    /// named `main` is.
    #[test]
    fn the_recorded_thread_is_the_main_one_else_the_one_named_main() {
        let here = std::thread::current().id();
        let other = std::thread::spawn(|| std::thread::current().id())
            .join()
            .expect("a thread");
        assert!(is_main(Some(here), here, None));
        assert!(!is_main(Some(here), other, Some("main")), "the record wins");
        assert!(is_main(None, other, Some("main")));
        assert!(!is_main(None, here, Some("tokio-runtime-worker")));
        assert!(!is_main(None, here, None));
    }
}
