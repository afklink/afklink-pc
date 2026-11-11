//! What a real captured frame costs before the encoder ever sees it.
//!
//! The encode-side bench (`afklink-encode`, `examples/pipeline_bench.rs`) measures synthetic
//! frames, which silently assumes the frame is already in main memory. It is not: WGC hands us a
//! GPU texture, and `FrameBuffer::buffer()` copies it across the bus into a staging texture and
//! maps it. On a 3600x2400 panel that is 33 MB per frame moving GPU -> CPU, and no amount of
//! encoder tuning makes it cheaper.
//!
//! This measures the three costs on the capture side, per frame:
//!
//!   - `buffer()`       the GPU -> CPU copy and map
//!   - `to_vec()`       the scale into the owned `Frame` the pipeline sends (`to_vec_us`)
//!   - arrival interval how often WGC actually delivers, which is *not* a frame rate:
//!     Windows.Graphics.Capture only produces a frame when something changed
//!
//! That last one is why a quiet screen legitimately reports single-digit fps, and why an fps
//! number on its own can never distinguish "the pipeline is slow" from "nothing moved". The
//! bench therefore jiggles the cursor so there is always something to capture.
//!
//! Run with:  cargo run --release --example capture_bench -p afklink-capture

#[cfg(not(windows))]
fn main() {
    eprintln!("capture_bench is Windows-only");
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    win::run()
}

#[cfg(windows)]
mod win {
    use std::sync::mpsc::{channel, Sender};
    use std::time::{Duration, Instant};

    use afklink_capture::session_options::{self, Resolved, SessionOption};
    use afklink_core::scale::{self, Scaler};
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::WindowsAndMessaging::{GetCursorPos, SetCursorPos};
    use windows_capture::capture::{Context, GraphicsCaptureApiHandler};
    use windows_capture::frame::Frame as WgcFrame;
    use windows_capture::graphics_capture_api::InternalCaptureControl;
    use windows_capture::monitor::Monitor;
    use windows_capture::settings::{
        ColorFormat, DirtyRegionSettings, MinimumUpdateIntervalSettings, Settings,
    };

    type BoxError = Box<dyn std::error::Error + Send + Sync>;

    const RUN_FOR: Duration = Duration::from_secs(5);

    /// One frame's timings, in microseconds.
    struct Sample {
        buffer_us: u64,
        to_vec_us: u64,
        since_prev_us: u64,
        width: u32,
        height: u32,
        bytes: usize,
    }

    struct Handler {
        sink: Sender<Sample>,
        scratch: Vec<u8>,
        prev: Option<Instant>,
        scaler: Scaler,
        max_w: u32,
        max_h: u32,
    }

    impl GraphicsCaptureApiHandler for Handler {
        type Flags = Sender<Sample>;
        type Error = BoxError;

        fn new(ctx: Context<Self::Flags>) -> Result<Self, Self::Error> {
            Ok(Handler {
                sink: ctx.flags,
                scratch: Vec::new(),
                prev: None,
                scaler: Scaler::new(),
                max_w: scale::DEFAULT_MAX_W,
                max_h: scale::DEFAULT_MAX_H,
            })
        }

        fn on_frame_arrived(
            &mut self,
            frame: &mut WgcFrame,
            control: InternalCaptureControl,
        ) -> Result<(), Self::Error> {
            let now = Instant::now();
            let since_prev_us = self
                .prev
                .replace(now)
                .map_or(0, |p| now.duration_since(p).as_micros() as u64);

            // The GPU -> CPU copy. This is the cost the encode-side bench cannot see.
            let t = Instant::now();
            let buffer = frame
                .buffer()
                .map_err(|e| -> BoxError { format!("{e}").into() })?;
            let width = buffer.width();
            let height = buffer.height();
            let data = buffer.as_nopadding_buffer(&mut self.scratch);
            let buffer_us = t.elapsed().as_micros() as u64;

            // Scale straight into the owned buffer the Frame will carry, as wgc.rs does. This
            // replaces a 33 MB `to_vec()` plus a scale on the encode thread.
            let t = Instant::now();
            let mut owned = Vec::new();
            let (dw, dh) = self
                .scaler
                .fit_into(data, width, height, self.max_w, self.max_h, &mut owned)
                .map_err(|e| -> BoxError { format!("{e:#}").into() })?;
            let to_vec_us = t.elapsed().as_micros() as u64;
            let bytes = std::hint::black_box(&owned).len();
            let _ = (dw, dh);

            if self
                .sink
                .send(Sample {
                    buffer_us,
                    to_vec_us,
                    since_prev_us,
                    width,
                    height,
                    bytes,
                })
                .is_err()
            {
                control.stop();
            }
            Ok(())
        }
    }

    pub fn run() -> Result<(), BoxError> {
        let (tx, rx) = channel::<Sample>();
        let monitor = Monitor::primary()?;
        // The same start as the agent's (`wgc::start`): cursor and no border where this Windows
        // has them, so the bench runs on Windows 10 too.
        let control = session_options::start::<Handler, Monitor>(
            "bench monitor",
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
                    tx.clone(),
                )
            },
        )?;
        drop(tx);

        // Keep the screen changing. WGC delivers on change, so a still desktop would measure how
        // long the bench waited rather than what a frame costs.
        let jiggle = std::thread::spawn(|| {
            let mut origin = POINT::default();
            // SAFETY: GetCursorPos writes a POINT we own; failure leaves it zeroed, which is a
            // fine starting point for a jiggle.
            let _ = unsafe { GetCursorPos(&mut origin) };
            let start = Instant::now();
            let mut i = 0i32;
            while start.elapsed() < RUN_FOR + Duration::from_millis(200) {
                // SAFETY: SetCursorPos takes plain coordinates and cannot fail destructively.
                let _ = unsafe { SetCursorPos(origin.x + (i % 40), origin.y + ((i / 7) % 40)) };
                i += 1;
                std::thread::sleep(Duration::from_millis(8));
            }
            // SAFETY: as above; puts the pointer back where the user left it.
            let _ = unsafe { SetCursorPos(origin.x, origin.y) };
        });

        let mut samples: Vec<Sample> = Vec::new();
        let deadline = Instant::now() + RUN_FOR;
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(s) => samples.push(s),
                Err(_) => break,
            }
        }
        let _ = control.stop();
        let _ = jiggle.join();

        report(&samples);
        Ok(())
    }

    fn report(samples: &[Sample]) {
        if samples.is_empty() {
            println!("no frames arrived in {RUN_FOR:?} — WGC delivers only on change");
            return;
        }
        // Drop the first: it carries session start-up and has no previous frame to interval from.
        let s = &samples[1.min(samples.len() - 1)..];
        let n = s.len().max(1) as f64;

        let first = &samples[0];
        println!(
            "{}x{} ({:.1} MB/frame), {} frames in {RUN_FOR:?}\n",
            first.width,
            first.height,
            first.bytes as f64 / (1024.0 * 1024.0),
            samples.len()
        );

        let mean = |f: fn(&Sample) -> u64| s.iter().map(f).sum::<u64>() as f64 / n / 1000.0;
        let p95 = |f: fn(&Sample) -> u64| {
            let mut v: Vec<u64> = s.iter().map(f).collect();
            v.sort_unstable();
            v[(v.len() * 95 / 100).min(v.len().saturating_sub(1))] as f64 / 1000.0
        };

        println!("                       mean      p95");
        println!(
            "buffer() GPU->CPU   {:7.2}  {:7.2} ms",
            mean(|s| s.buffer_us),
            p95(|s| s.buffer_us)
        );
        println!(
            "scale into Frame     {:7.2}  {:7.2} ms",
            mean(|s| s.to_vec_us),
            p95(|s| s.to_vec_us)
        );
        println!(
            "arrival interval    {:7.2}  {:7.2} ms   ({:.1} frames/s delivered)",
            mean(|s| s.since_prev_us),
            p95(|s| s.since_prev_us),
            1000.0 / mean(|s| s.since_prev_us).max(0.001)
        );
        println!(
            "\ncapture-side cost per frame: {:.2} ms",
            mean(|s| s.buffer_us) + mean(|s| s.to_vec_us)
        );
    }
}
