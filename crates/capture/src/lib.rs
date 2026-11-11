//! Screen capture via Windows.Graphics.Capture (the `windows-capture` crate).
//!
//! Captures the primary monitor, or one game window, in the user's own session (no SYSTEM
//! service). Frames are delivered as BGRA8 (tightly packed) to a channel. A DXGI Desktop
//! Duplication implementation (dirty rects, secure desktop) would fit behind the same
//! [`Capturer`] trait.

use std::sync::mpsc::Sender;
use std::sync::Arc;

use afklink_core::game::{GameCaptureRequest, GameCapturer};
use afklink_core::quality::QualityTarget;
use afklink_core::traits::Capturer;
use afklink_core::types::Frame;
use anyhow::Result;

pub mod pace;

/// The WGC session's optional properties (cursor, border, secondary windows): each set only where
/// this Windows has it, so a property Windows 10 lacks never stops a capture. Every WGC start goes
/// through [`session_options::start`]. See the module.
pub mod session_options;

/// «Only the game window»: the window list, the window capture and the picker's list. See the
/// module, and `afklink_core::game` for the platform-free half.
#[cfg(windows)]
pub mod game;

#[cfg(windows)]
mod wgc;

/// The capturer of a session in game mode: the bound game's window only, black frames whenever it
/// cannot be shown (`afklink_core::game::GameCapturer`, over the Win32 window list and the WGC
/// window capture). Nothing it can do captures the monitor.
pub fn game_capturer(request: &GameCaptureRequest) -> Box<dyn Capturer> {
    #[cfg(windows)]
    {
        Box::new(GameCapturer::new(
            request,
            Box::new(game::Win32Windows::new()),
            Box::new(game::WgcWindowBackend),
        ))
    }
    #[cfg(not(windows))]
    {
        Box::new(GameCapturer::new(
            request,
            Box::new(unsupported::NoWindows),
            Box::new(unsupported::NoWindows),
        ))
    }
}

/// Elsewhere than Windows there is no window to find: the game is absent, the frames black.
#[cfg(not(windows))]
mod unsupported {
    use afklink_core::game::{
        GameBinding, WindowCapture, WindowCaptureBackend, WindowCaptureContext, WindowGeometry,
        WindowInfo, WindowSource,
    };

    pub struct NoWindows;

    impl WindowSource for NoWindows {
        fn windows(&mut self, _binding: &GameBinding) -> Result<Vec<WindowInfo>, String> {
            Err("window capture is only available on Windows".into())
        }
        fn geometry(&mut self, _hwnd: usize) -> Result<WindowGeometry, String> {
            Err("window capture is only available on Windows".into())
        }
    }

    impl WindowCaptureBackend for NoWindows {
        fn start(&mut self, _ctx: WindowCaptureContext) -> anyhow::Result<Box<dyn WindowCapture>> {
            Err(anyhow::anyhow!(
                "window capture is only available on Windows"
            ))
        }
    }
}

/// Hand-run probes for the "game window only" mode: ignored tests, built only into this crate's
/// test binary. See `probe/mod.rs`.
#[cfg(all(test, windows))]
mod probe;

/// Windows.Graphics.Capture-backed capturer.
///
/// Frames are delivered already scaled to fit `(max_w, max_h)`. That is deliberate and is where
/// the scale belongs: capture and encode run on separate threads, so the pipeline runs at the
/// speed of the slower one, and doing the scale here both balances the two and removes a copy
/// of the full-resolution frame. See `wgc::Handler` for the measurements.
pub struct WgcCapturer {
    #[cfg(windows)]
    control: Option<wgc::Control>,
}

impl WgcCapturer {
    #[must_use]
    pub fn new() -> Self {
        WgcCapturer {
            #[cfg(windows)]
            control: None,
        }
    }
}

impl Default for WgcCapturer {
    fn default() -> Self {
        Self::new()
    }
}

impl Capturer for WgcCapturer {
    fn start(&mut self, sink: Sender<Frame>, target: Arc<QualityTarget>) -> Result<()> {
        #[cfg(windows)]
        {
            let control = wgc::start(sink, target)?;
            self.control = Some(control);
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = (sink, target);
            Err(anyhow::anyhow!("WGC capture is only available on Windows"))
        }
    }

    fn stop(&mut self) {
        #[cfg(windows)]
        {
            if let Some(control) = self.control.take() {
                wgc::stop(control);
            }
        }
    }

    /// Whether the WGC thread is still running. See [`Capturer::check`].
    ///
    /// The capture thread exits on its own when the frame handler returns an error (a frame buffer
    /// that could not be mapped, a scale that failed), when the captured monitor closes, or when
    /// its message loop fails — and nothing else in the process noticed, because the frame sender
    /// lives on inside the handler that `CaptureControl` still holds, so the channel the encode
    /// thread waits on never closes. That is the frozen-picture-with-no-message failure.
    fn check(&mut self) -> Result<()> {
        #[cfg(windows)]
        {
            match self.control.take() {
                Some(control) if control.is_finished() => Err(wgc::reap(control)),
                Some(control) => {
                    self.control = Some(control);
                    Ok(())
                }
                None => Err(anyhow::anyhow!("WGC capture is not running")),
            }
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
}
