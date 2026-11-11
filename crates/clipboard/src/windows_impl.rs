//! Windows: the listener thread, its window, and the clipboard calls made on it. See the crate docs.

use std::sync::mpsc::{self, SyncSender};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use afklink_core::clipboard::{ClipboardChange, ClipboardContent, ClipboardError};
use afklink_protocol::CLIPBOARD_MAX_BYTES;
use tokio::sync::broadcast;
use windows::core::w;
use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND, LPARAM, WPARAM};
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, CloseClipboard, CountClipboardFormats, EmptyClipboard,
    GetClipboardData, GetClipboardSequenceNumber, GetOpenClipboardWindow,
    IsClipboardFormatAvailable, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DispatchMessageW, GetMessageW, PostMessageW, TranslateMessage, HWND_MESSAGE,
    MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_CLIPBOARDUPDATE,
};

use crate::{OPEN_ATTEMPTS, OPEN_RETRY};

/// Posted to the window when a request waits in the queue.
const WM_REQUEST: u32 = WM_APP + 1;

/// How long a caller waits for the thread to answer a request: the opening's retries and a copy of
/// at most a few hundred kilobytes, with a wide margin.
const ANSWER_WAIT: Duration = Duration::from_secs(5);

/// How many changes may wait for a slow session before it is told it lagged.
const CHANGES: usize = 16;

/// A request for the thread, with where its answer goes.
enum Request {
    Read(SyncSender<Result<ClipboardContent, ClipboardError>>),
    /// UTF-16, NUL-terminated.
    Write(Vec<u16>, SyncSender<Result<u32, ClipboardError>>),
}

/// The running thread: its window, its queue, its broadcast.
struct Running {
    /// The window, as a number: `HWND` is a pointer and does not cross threads.
    hwnd: isize,
    requests: mpsc::Sender<Request>,
    changes: broadcast::Sender<ClipboardChange>,
}

/// The listener, started on first use.
#[derive(Default)]
pub(crate) struct Listener {
    running: OnceLock<Result<Running, String>>,
}

impl Listener {
    fn running(&self) -> Result<&Running, String> {
        self.running
            .get_or_init(start)
            .as_ref()
            .map_err(Clone::clone)
    }

    pub(crate) fn watch(&self) -> Result<broadcast::Receiver<ClipboardChange>, String> {
        Ok(self.running()?.changes.subscribe())
    }

    pub(crate) fn read_text(&self) -> Result<ClipboardContent, ClipboardError> {
        self.call(Request::Read)
    }

    pub(crate) fn write_text(&self, text: &str) -> Result<u32, ClipboardError> {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        self.call(|answer| Request::Write(wide, answer))
    }

    /// Hand a request to the thread and wait for its answer.
    fn call<T>(
        &self,
        make: impl FnOnce(SyncSender<Result<T, ClipboardError>>) -> Request,
    ) -> Result<T, ClipboardError> {
        let running = self.running().map_err(ClipboardError::Failed)?;
        let (answer, answered) = mpsc::sync_channel(1);
        running
            .requests
            .send(make(answer))
            .map_err(|_| ClipboardError::Failed("the clipboard thread has stopped".into()))?;
        // SAFETY: a plain post to a window this process made; the handle is only compared by
        // Windows, which refuses a window that is gone.
        let posted = unsafe {
            PostMessageW(
                Some(HWND(running.hwnd as *mut _)),
                WM_REQUEST,
                WPARAM(0),
                LPARAM(0),
            )
        };
        if let Err(e) = posted {
            return Err(ClipboardError::Failed(format!(
                "the clipboard thread was not woken: {e}"
            )));
        }
        answered.recv_timeout(ANSWER_WAIT).map_err(|e| {
            ClipboardError::Failed(format!(
                "the clipboard thread did not answer within {} s: {e}",
                ANSWER_WAIT.as_secs()
            ))
        })?
    }
}

/// Start the thread and its window; the window, or why there is none.
fn start() -> Result<Running, String> {
    let (requests, queue) = mpsc::channel::<Request>();
    let (changes, _) = broadcast::channel(CHANGES);
    let (ready, started) = mpsc::sync_channel::<Result<isize, String>>(1);
    let thread_changes = changes.clone();
    let spawned = std::thread::Builder::new()
        .name("clipboard".into())
        .spawn(move || listen(queue, thread_changes, ready));
    if let Err(e) = spawned {
        let why = format!("the clipboard thread did not start: {e}");
        tracing::warn!("clipboard: {why}");
        return Err(why);
    }
    match started.recv_timeout(ANSWER_WAIT) {
        Ok(Ok(hwnd)) => {
            tracing::info!(
                seq = clipboard_seq(),
                "clipboard: listening for changes (a message-only window in the listener list)"
            );
            Ok(Running {
                hwnd,
                requests,
                changes,
            })
        }
        Ok(Err(why)) => {
            tracing::warn!("clipboard: not listening: {why}");
            Err(why)
        }
        Err(e) => {
            let why = format!("the clipboard thread did not say it started: {e}");
            tracing::warn!("clipboard: {why}");
            Err(why)
        }
    }
}

fn clipboard_seq() -> u32 {
    // SAFETY: no arguments, reads a counter of the window station.
    unsafe { GetClipboardSequenceNumber() }
}

/// The thread: make the window, join the listener list, then serve changes and requests until the
/// process ends.
fn listen(
    queue: mpsc::Receiver<Request>,
    changes: broadcast::Sender<ClipboardChange>,
    ready: SyncSender<Result<isize, String>>,
) {
    // SAFETY: a message-only window of the system's STATIC class, owned by this thread; nothing is
    // passed that outlives the call.
    let made = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("STATIC"),
            w!("AFKLink clipboard"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            None,
            None,
        )
    };
    let hwnd = match made {
        Ok(hwnd) => hwnd,
        Err(e) => {
            let _ = ready.send(Err(format!("no window for the listener: {e}")));
            return;
        }
    };
    // SAFETY: the window was just made by this thread.
    if let Err(e) = unsafe { AddClipboardFormatListener(hwnd) } {
        let _ = ready.send(Err(format!(
            "not added to the clipboard listener list: {e}"
        )));
        return;
    }
    if ready.send(Ok(hwnd.0 as isize)).is_err() {
        tracing::debug!("clipboard: the starter stopped waiting; the listener runs anyway");
    }
    let mut msg = MSG::default();
    loop {
        // SAFETY: `msg` is this frame's; the loop ends when the queue says quit or fails.
        let got = unsafe { GetMessageW(&mut msg, None, 0, 0) };
        if got.0 == 0 || got.0 == -1 {
            tracing::warn!(
                result = got.0,
                "clipboard: the listener's message loop ended; changes are no longer heard"
            );
            return;
        }
        match msg.message {
            WM_CLIPBOARDUPDATE => {
                let seq = clipboard_seq();
                // Per change, and changes are the person's copies: trace. Sessions log what they do.
                let receivers = changes.receiver_count();
                tracing::trace!(seq, receivers, "clipboard: changed");
                let _ = changes.send(ClipboardChange { seq });
            }
            WM_REQUEST => {
                while let Ok(request) = queue.try_recv() {
                    serve(hwnd, request);
                }
            }
            _ => {
                // SAFETY: the message GetMessageW just filled.
                unsafe {
                    let _ = TranslateMessage(&msg);
                    let _ = DispatchMessageW(&msg);
                }
            }
        }
    }
}

fn serve(hwnd: HWND, request: Request) {
    match request {
        Request::Read(answer) => {
            let started = Instant::now();
            let read = read(hwnd);
            match &read {
                Ok(ClipboardContent::Text(text)) => tracing::trace!(
                    bytes = text.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "clipboard: text read"
                ),
                Ok(other) => tracing::trace!(
                    content = ?ContentKind(other),
                    "clipboard: read, no text to send"
                ),
                Err(e) => tracing::debug!("clipboard: not read: {e}"),
            }
            let _ = answer.send(read);
        }
        Request::Write(wide, answer) => {
            let written = write(hwnd, &wide);
            if let Err(e) = &written {
                tracing::debug!(units = wide.len(), "clipboard: not written: {e}");
            }
            let _ = answer.send(written);
        }
    }
}

/// What was read, without the text: for the log.
struct ContentKind<'a>(&'a ClipboardContent);

impl std::fmt::Debug for ContentKind<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            ClipboardContent::Text(text) => write!(f, "text of {} bytes", text.len()),
            ClipboardContent::TooLarge { units } => write!(f, "text of {units} UTF-16 units"),
            ClipboardContent::NotText { formats } => write!(f, "no text ({formats} formats)"),
        }
    }
}

/// Open the clipboard for `hwnd`, waiting a little while another program holds it.
fn open(hwnd: HWND) -> Result<(), ClipboardError> {
    let started = Instant::now();
    for attempt in 1..=OPEN_ATTEMPTS {
        // SAFETY: the listener's own window, on its own thread.
        match unsafe { OpenClipboard(Some(hwnd)) } {
            Ok(()) => {
                if attempt > 1 {
                    tracing::debug!(
                        attempt,
                        waited_ms = started.elapsed().as_millis() as u64,
                        "clipboard: opened once another program let it go"
                    );
                }
                return Ok(());
            }
            Err(e) if attempt == OPEN_ATTEMPTS => {
                // SAFETY: no arguments; which window holds the clipboard, if any.
                let holder = unsafe { GetOpenClipboardWindow() }
                    .ok()
                    .map(|h| h.0 as usize);
                tracing::debug!(
                    attempts = OPEN_ATTEMPTS,
                    waited_ms = started.elapsed().as_millis() as u64,
                    holder = ?holder,
                    "clipboard: still held by another program: {e}"
                );
            }
            Err(_) => std::thread::sleep(OPEN_RETRY),
        }
    }
    Err(ClipboardError::Busy {
        attempts: OPEN_ATTEMPTS,
        waited_ms: started.elapsed().as_millis() as u64,
    })
}

fn close() {
    // SAFETY: closes what `open` opened on this thread.
    if let Err(e) = unsafe { CloseClipboard() } {
        tracing::debug!("clipboard: not closed: {e}");
    }
}

/// The clipboard's text, opened and closed here.
fn read(hwnd: HWND) -> Result<ClipboardContent, ClipboardError> {
    open(hwnd)?;
    let read = read_open();
    close();
    read
}

fn read_open() -> Result<ClipboardContent, ClipboardError> {
    let format = u32::from(CF_UNICODETEXT.0);
    // SAFETY: the clipboard is open on this thread.
    if unsafe { IsClipboardFormatAvailable(format) }.is_err() {
        // SAFETY: as above.
        let formats = unsafe { CountClipboardFormats() };
        return Ok(ClipboardContent::NotText {
            formats: u32::try_from(formats).unwrap_or(0),
        });
    }
    // SAFETY: as above; the handle belongs to the clipboard and is only read while it is open.
    let handle = unsafe { GetClipboardData(format) }
        .map_err(|e| ClipboardError::Failed(format!("GetClipboardData: {e}")))?;
    let memory = HGLOBAL(handle.0);
    // SAFETY: the clipboard's memory object for this format, locked for the copy below.
    let (units, ptr) = unsafe { (GlobalSize(memory) / 2, GlobalLock(memory) as *const u16) };
    if ptr.is_null() {
        return Err(ClipboardError::Failed(
            "GlobalLock of the clipboard's text failed".into(),
        ));
    }
    // A UTF-16 unit is at least one UTF-8 byte: past the limit's count of units, the text is over
    // the limit whatever it holds, and is not read further.
    let scan = units.min(CLIPBOARD_MAX_BYTES + 1);
    // SAFETY: `scan` units are within the object's size, which is locked.
    let slice = unsafe { std::slice::from_raw_parts(ptr, scan) };
    let content = match slice.iter().position(|&u| u == 0) {
        Some(len) => ClipboardContent::Text(String::from_utf16_lossy(&slice[..len])),
        None if units > scan => ClipboardContent::TooLarge { units },
        None if scan > CLIPBOARD_MAX_BYTES => ClipboardContent::TooLarge { units },
        None => ClipboardContent::Text(String::from_utf16_lossy(slice)),
    };
    // SAFETY: the lock taken above. Its "error" with no error set is the lock count reaching zero.
    let _ = unsafe { GlobalUnlock(memory) };
    Ok(content)
}

/// Put `wide` (NUL-terminated UTF-16) on the clipboard; its sequence number after.
fn write(hwnd: HWND, wide: &[u16]) -> Result<u32, ClipboardError> {
    // SAFETY: a fresh movable object of exactly the text's size, filled under its lock.
    let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, std::mem::size_of_val(wide)) }
        .map_err(|e| ClipboardError::Failed(format!("GlobalAlloc: {e}")))?;
    // SAFETY: as above.
    let ptr = unsafe { GlobalLock(memory) as *mut u16 };
    if ptr.is_null() {
        // SAFETY: the object is ours until the clipboard takes it.
        let _ = unsafe { GlobalFree(Some(memory)) };
        return Err(ClipboardError::Failed(
            "GlobalLock of the new text failed".into(),
        ));
    }
    // SAFETY: the object holds `wide.len()` units; the two never overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
        let _ = GlobalUnlock(memory);
    }
    if let Err(e) = open(hwnd) {
        // SAFETY: never handed to the clipboard.
        let _ = unsafe { GlobalFree(Some(memory)) };
        return Err(e);
    }
    let format = u32::from(CF_UNICODETEXT.0);
    // SAFETY: the clipboard is open on this thread for this window; on success it owns `memory`.
    let set = unsafe {
        EmptyClipboard()
            .map_err(|e| format!("EmptyClipboard: {e}"))
            .and_then(|()| {
                SetClipboardData(format, Some(HANDLE(memory.0)))
                    .map_err(|e| format!("SetClipboardData: {e}"))
            })
    };
    close();
    match set {
        Ok(_) => Ok(clipboard_seq()),
        Err(why) => {
            // SAFETY: the clipboard did not take it.
            let _ = unsafe { GlobalFree(Some(memory)) };
            Err(ClipboardError::Failed(why))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afklink_core::clipboard::ClipboardBackend;

    /// The real clipboard, end to end: written, changed, read back — and this write's change carries
    /// the sequence number the write returned. It replaces what is on this PC's clipboard, so it is
    /// run by hand: `cargo test -p afklink-clipboard -- --ignored`.
    #[test]
    #[ignore = "replaces this PC's clipboard"]
    fn a_written_text_is_read_back_and_its_change_is_seen() {
        let clipboard = crate::SystemClipboard::new();
        let mut changes = clipboard.watch().expect("listening");
        let text = "AFKLink clipboard test\r\nвторая строка 😀";
        let seq = clipboard.write_text(text).expect("written");
        assert_eq!(
            clipboard.read_text().expect("read"),
            ClipboardContent::Text(text.to_string())
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let seen = loop {
            match changes.try_recv() {
                Ok(change) => break change,
                Err(broadcast::error::TryRecvError::Empty) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("no change heard: {e:?}"),
            }
        };
        assert_eq!(seen.seq, seq);
        let big = "x".repeat(CLIPBOARD_MAX_BYTES + 1);
        clipboard.write_text(&big).expect("written");
        assert!(matches!(
            clipboard.read_text().expect("read"),
            ClipboardContent::TooLarge { .. }
        ));
    }
}
