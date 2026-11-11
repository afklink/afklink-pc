//! Windows-only WGC handler and start/stop glue.

use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Instant;

use afklink_core::quality::QualityTarget;
use afklink_core::scale::Scaler;
use afklink_core::types::Frame;
use anyhow::{Context, Result};

use crate::pace;
use crate::session_options::{self, Resolved, SessionOption};

use windows_capture::capture::{CaptureControl, Context as WgcContext, GraphicsCaptureApiHandler};
use windows_capture::frame::Frame as WgcFrame;
use windows_capture::graphics_capture_api::InternalCaptureControl;
use windows_capture::monitor::Monitor;
use windows_capture::settings::{
    ColorFormat, DirtyRegionSettings, MinimumUpdateIntervalSettings, Settings,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The concrete free-threaded capture control handle we hold onto.
pub type Control = CaptureControl<Handler, BoxError>;

/// WGC event handler. Scales each frame to the encoder's resolution and sends it on the
/// channel; the newest frame wins downstream.
///
/// ## Why the scale happens here and not in the encoder
///
/// Capture and encode run on separate threads, so the pipeline's frame rate is the *slower* of the
/// two stages, not their sum. Measured on a 3600x2400 panel with the scale in the encoder, they
/// were unbalanced (capture 8 ms, encode 15 ms), so the encode thread set the rate.
///
/// Scaling here evens them out (about 10 ms each) and removes work, because the scale writes into
/// the `Frame`'s own buffer: there is no full-resolution owned copy (33 MB, 4.0 ms), only the
/// scale's output (7 MB). Smaller frames also make the channel between the threads five times
/// lighter, which matters when the consumer falls behind.
pub struct Handler {
    sink: Sender<Frame>,
    start: Instant,
    scratch: Vec<u8>,
    scaler: Scaler,
    target: Arc<QualityTarget>,
    /// When the next frame is due, for the pacing gate above.
    next_due: Option<Instant>,
    /// The last source size and scaled size seen, so a change is logged once rather than per frame.
    last_source: Option<(u32, u32)>,
    last_scaled: Option<(u32, u32)>,
}

/// What the handler needs at construction: where to send frames, and what to scale them to.
pub struct Flags {
    pub sink: Sender<Frame>,
    pub target: Arc<QualityTarget>,
}

impl GraphicsCaptureApiHandler for Handler {
    type Flags = Flags;
    type Error = BoxError;

    fn new(ctx: WgcContext<Self::Flags>) -> Result<Self, Self::Error> {
        tracing::debug!("WGC capture thread started");
        Ok(Handler {
            sink: ctx.flags.sink,
            start: Instant::now(),
            scratch: Vec::new(),
            scaler: Scaler::new(),
            target: ctx.flags.target,
            next_due: None,
            last_source: None,
            last_scaled: None,
        })
    }

    fn on_frame_arrived(
        &mut self,
        frame: &mut WgcFrame,
        capture_control: InternalCaptureControl,
    ) -> Result<(), Self::Error> {
        // Pace here, before any of the expensive work: pulling the frame across the bus, scaling
        // it and allocating several megabytes for the result. Pacing after that work discarded 29
        // of every 46 captured frames in a measured session, about a third of a core spent on
        // frames nobody looked at.
        //
        // This is the only pacer. The encode thread does not gate on a deadline; it drains to the
        // newest frame, discarding rather than waiting. So a frame refused here is a frame the
        // viewer does not get, and refusing one wrongly costs in full.
        //
        // It is a deadline, not "has an interval passed since the last one". WGC delivers
        // irregularly (measured between 1.6 and 61.6 frames a second in one session). Against an
        // irregular arrival grid, "reject anything sooner than 33 ms after the last accepted frame"
        // undershoots: a frame arriving at 32 ms is rejected, the next may not come until 50, and a
        // 30 fps target yields 20. Advancing a deadline by exactly one interval keeps the schedule
        // honest: an early frame waits for its slot, a slightly late one still fills it.
        //
        // The deadline resyncs when it has fallen more than one interval behind, which happens
        // whenever the screen goes still; otherwise a minute without frames would leave a minute of
        // deadlines in the past and the next burst would pass every frame.
        //
        // ## A slightly early frame is admitted, which the 60 fps rung needs
        //
        // `min_frame_interval` truncates: `1_000_000 / 60` is 16 666 µs against a 60 Hz panel's
        // 16 667 µs period. With a one-microsecond margin, a frame delivered half a millisecond
        // early (ordinary WGC jitter is ±1 ms) would be discarded and the next would arrive a full
        // period later: about half the frames lost, a 1080p60 rung delivering 30.
        //
        // So a frame inside [`pace::early_tolerance`] fills the slot, and the deadline still
        // advances by one interval from the *old* deadline rather than from `now`. That keeps the
        // tolerance from becoming a rate increase: the phase is untouched, and the next frame is
        // due when it was always due.
        //
        // The tolerance is `min(interval / 4, 4 ms)`; both bounds are argued from the source period
        // in `pace.rs`. In short: on a 60 Hz panel the nearest frame that must *not* be taken is
        // 16.7 ms early at 30 fps and 8.3 ms early at 8 fps, so 4 ms clears the tightest case twice
        // over; and a quarter of an interval can never be half of one.
        //
        // ## No congestion gate
        //
        // The capturer does not hold frames back while the link looks busy. A P-frame codes the
        // delta from the previous *encoded* frame; refusing one lengthens the interval the next
        // must describe, and the measured cost is `bytes/frame ~ interval^1.248`. With an exponent
        // above one, the byte rate does not fall as frames are dropped. Measured in one session:
        // 30 fps gave frames of 1558 B and 374 kbps; 2.4 fps gave frames of 44 375 B and 852 kbps.
        // Twelve times fewer frames, twenty-eight times larger, more bytes on the wire.
        //
        // A gate therefore amplifies congestion and has a stable bad equilibrium: every frame
        // effectively an intra, at whatever rate the link takes, entered by any frame larger than
        // the credit, which a keyframe always is. What bounds the queue instead is the encoder's
        // bitrate, the one actuator whose sign is not in doubt. The capturer's only job is to hand
        // over frames at the cadence the ladder asked for.
        self.target.note_offered();

        let now = Instant::now();
        let interval = self.target.min_frame_interval();
        let (decision, due) = pace::admit(now, self.next_due, interval);
        self.next_due = Some(due);
        if decision == pace::Admission::Early {
            self.target.note_early();
            return Ok(());
        }

        let buffer = frame
            .buffer()
            .map_err(|e| -> BoxError { format!("frame buffer: {e}").into() })?;
        let width = buffer.width();
        let height = buffer.height();
        // `as_nopadding_buffer` strips row padding into `scratch` if needed and
        // returns a tightly packed BGRA slice.
        let data = buffer.as_nopadding_buffer(&mut self.scratch);

        // Re-read per frame rather than caching: a quality change has to reach the pixels within
        // a frame or two, and this is the only place that decides how big they are. The width
        // bound is effectively unlimited — the ladder constrains height, and width follows from
        // the source's aspect ratio, so an ultrawide is not squeezed into 16:9.
        self.target.set_source(width, height);
        let max_h = self.target.max_h();
        let mut pixels = Vec::new();
        let (w, h) = self
            .scaler
            .fit_into(data, width, height, u32::MAX / 2, max_h, &mut pixels)
            .map_err(|e| -> BoxError { format!("scale frame: {e:#}").into() })?;

        // Per frame is trace; a change of either size is a state change and says so once — the
        // first frame, a display reconfiguration, or a rung change reaching the pixels.
        if self.last_source != Some((width, height)) {
            tracing::debug!(
                from = ?self.last_source,
                to = %format!("{width}x{height}"),
                "captured source size"
            );
            self.last_source = Some((width, height));
        }
        if self.last_scaled != Some((w, h)) {
            tracing::debug!(
                from = ?self.last_scaled,
                to = %format!("{w}x{h}"),
                max_h,
                "capture scales to a new size"
            );
            self.last_scaled = Some((w, h));
        }

        let out = Frame {
            data: pixels,
            width: w,
            height: h,
            timestamp_ms: self.start.elapsed().as_millis() as u64,
        };

        if self.sink.send(out).is_err() {
            // Consumer is gone — stop the capture session.
            tracing::debug!("frame consumer gone; stopping the capture");
            capture_control.stop();
        }
        Ok(())
    }

    fn on_closed(&mut self) -> Result<(), Self::Error> {
        // The captured item went away — for a monitor, it was disconnected or the display
        // configuration dropped it. Not our own `stop`, which does not raise this. The capture thread
        // exits after it, and the pipeline supervisor restarts capture on the next poll.
        tracing::warn!("WGC capture item closed; capture is ending");
        Ok(())
    }
}

/// Start capturing the primary monitor on a background thread, scaled to `target`.
pub fn start(sink: Sender<Frame>, target: Arc<QualityTarget>) -> Result<Control> {
    let monitor = Monitor::primary().context("get primary monitor")?;
    // What is being captured, once per start. Each property is best effort: a monitor that cannot
    // name itself is still captured, and `?` in the line says which one could not.
    let show = |v: Result<String, windows_capture::monitor::Error>| {
        v.unwrap_or_else(|e| format!("? ({e})"))
    };
    tracing::info!(
        name = %show(monitor.name()),
        device = %show(monitor.device_name()),
        width = %show(monitor.width().map(|v| v.to_string())),
        height = %show(monitor.height().map(|v| v.to_string())),
        refresh_hz = %show(monitor.refresh_rate().map(|v| v.to_string())),
        "starting WGC capture of the primary monitor"
    );
    // The cursor in the frames and no yellow border — each only where this Windows has the property
    // (`IsBorderRequired` is absent on Windows 10, whose captures run with the border). Asking for one
    // that Windows lacks fails the whole start: see `session_options`.
    //
    // The minimum update interval stays `Default` on purpose.
    //
    // `MinimumUpdateIntervalSettings::Custom(d)` asks Windows not to deliver faster than `d`. The
    // saving would be Windows' work, not ours: an unwanted frame costs this handler one atomic
    // increment, one clock read and a comparison, because the deadline gate in `on_frame_arrived`
    // runs before the buffer is touched.
    //
    // Setting it near our own interval would also make two independent pacers at the same period
    // beat against each other: a frame arriving at 30 ms against a 33 ms deadline is rejected, the
    // next does not come until 60, and a 30 fps target yields 20. The early tolerance absorbs a
    // beat of up to 4 ms, as a guard against delivery jitter, not a licence for a second pacer. If
    // this is ever set it must be comfortably *faster* than the fastest rung (16.7 ms). It also
    // exists only on Windows 11 24H2, so it would have to go through `session_options` like the
    // rest.
    let control = session_options::start::<Handler, Monitor>(
        "monitor",
        &[SessionOption::Cursor, SessionOption::NoBorder],
        |options: Resolved| {
            Settings::new(
                monitor,
                options.cursor,
                options.border,
                options.secondary,
                MinimumUpdateIntervalSettings::Default,
                DirtyRegionSettings::Default,
                ColorFormat::Bgra8,
                Flags {
                    sink: sink.clone(),
                    target: target.clone(),
                },
            )
        },
    )
    .context("start WGC capture")?;
    Ok(control)
}

/// Stop a running capture session.
pub fn stop(control: Control) {
    match control.stop() {
        Ok(()) => tracing::debug!("WGC capture stopped"),
        Err(e) => tracing::debug!("error stopping capture: {e}"),
    }
}

/// Collect a capture thread that has already exited on its own, and say why it did.
///
/// Only for a control whose thread `is_finished()`, so the join inside `wait` returns at once.
/// A clean exit is still an ending nobody asked for — it is what the captured item closing looks
/// like (`on_closed`), or the consumer having gone — so it is an error here too.
pub fn reap(control: Control) -> anyhow::Error {
    match control.wait() {
        Ok(()) => anyhow::anyhow!(
            "WGC capture ended without being stopped (the captured monitor closed, or the frame \
             consumer went away)"
        ),
        Err(e) => anyhow::anyhow!("WGC capture thread failed: {e}"),
    }
}
