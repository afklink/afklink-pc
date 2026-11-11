//! A media-only session: the agent's encoder, quality controller and transport feedback over a
//! frame feed the host owns. For a host that runs its own capture, admission and input — it
//! publishes frames into a [`FramePublisher`], hands the peer's events and the viewer's media
//! messages to the [`MediaFeed`], and decides through [`MediaAdmission`] when media may flow. This
//! module never starts the ordinary agent, its capture management or its input routes.

use super::*;
use crate::game::{CaptureMode, CaptureModeCell, GameStatus, LatestFrame, SessionCapture};
use crate::quality::{Quality, QualityTarget};
use crate::quality_policy::QualityPolicy;
use tokio::sync::oneshot;

/// Whether media may flow, as the host decides, and how the pipeline tells the host it has ended.
/// Called from the encode thread and the host's threads: both must be cheap and non-blocking.
pub trait MediaAdmission: Send + Sync {
    /// Frames are accepted and encoded only while this holds.
    fn admits(&self) -> bool;
    /// The pipeline ended, or the session was dropped: nothing flows from here on.
    fn revoke(&self);
}

/// Makes the encoder again when the pipeline restarts it.
pub type EncoderFactory = Arc<dyn Fn() -> Result<Box<dyn Encoder>> + Send + Sync>;
/// Whether the host's frame source is still valid; a pending frame is not encoded when not.
pub type SourceHealthy = Arc<dyn Fn() -> bool + Send + Sync>;

/// Where the host publishes frames: the newest one waits for the encoder, as the agent's own
/// capture channel keeps only the newest.
pub struct FramePublisher {
    frames: LatestFrame<Frame>,
    gate: Arc<dyn MediaAdmission>,
    started: Instant,
    healthy: SourceHealthy,
}

impl FramePublisher {
    /// Keep the latest verified frame available even while the shared encoder is busy.
    pub fn publish(&self, mut frame: Frame, acquired: Instant) {
        if !self.gate.admits() {
            tracing::trace!("published frame refused: media is not admitted");
            return;
        }
        // The WGC clock starts again on each quiet revalidation. RTP time does not.
        frame.timestamp_ms = acquired.saturating_duration_since(self.started).as_millis() as u64;
        if !self.frames.publish(frame) {
            tracing::trace!("published frame refused during a capture hold or detach");
        }
    }

    pub fn discard_pending(&self) {
        self.frames.clear();
    }

    pub(super) fn receive(
        &self,
        timeout: Duration,
    ) -> Result<(Frame, u32), std::sync::mpsc::RecvTimeoutError> {
        use std::sync::mpsc::RecvTimeoutError;
        let batch = self
            .frames
            .take_timeout(timeout)
            .ok_or(RecvTimeoutError::Timeout)?;
        if !self.gate.admits() {
            tracing::trace!("pending frame discarded: media is no longer admitted");
            return Err(RecvTimeoutError::Disconnected);
        }
        if !(self.healthy)() {
            tracing::trace!("pending frame discarded: the host's source is not healthy");
            return Err(RecvTimeoutError::Timeout);
        }
        Ok(batch)
    }

    pub(super) fn permits(&self) -> bool {
        self.gate.admits()
    }
}

/// The pipeline's capturer over the host's feed. Recovery can reattach this receiver, but the host
/// alone owns and validates the actual capture.
struct Feed(Arc<FramePublisher>);

impl Capturer for Feed {
    fn start(&mut self, _: std::sync::mpsc::Sender<Frame>, _: Arc<QualityTarget>) -> Result<()> {
        self.0.frames.reset(true);
        tracing::debug!("encoder attached to the host's frame feed");
        Ok(())
    }

    fn stop(&mut self) {
        self.0.frames.reset(false);
        tracing::debug!("encoder detached from the host's frame feed");
    }

    fn check(&mut self) -> Result<()> {
        anyhow::ensure!((self.0.healthy)(), "the host's frame source is unavailable");
        Ok(())
    }

    fn hold(&mut self, held: bool) -> bool {
        self.0.frames.reset(!held);
        tracing::debug!(held, "frame feed delivery hold changed");
        true
    }
}

struct NoInput;

impl InputInjector for NoInput {
    fn inject(&self, _: &InputMessage) -> Result<()> {
        anyhow::bail!("input is unavailable in a media-only session")
    }

    fn release_all(&self) {}
}

/// A running media-only session. [`MediaFeed::close`] stops it and waits for its tasks.
pub struct MediaFeed {
    pub target: Arc<QualityTarget>,
    pub publisher: Arc<FramePublisher>,
    stop: Arc<AtomicBool>,
    encode_done: Option<oneshot::Receiver<()>>,
    control: Option<tokio::task::JoinHandle<()>>,
    feedback: MediaFeedback,
}

struct MediaFeedback {
    id: String,
    pin: Arc<AtomicU32>,
    pending_kf: Arc<AtomicBool>,
    viewer_kf: Arc<crate::keyframe_window::ViewerAsks>,
    counters: Arc<SessionCounters>,
    viewer: crate::viewer_report::ViewerReportLog,
    bg: Arc<crate::bg_hold::BgHold>,
    delivery_epoch: Instant,
    control: mpsc::Sender<PeerControl>,
}

impl MediaFeed {
    /// Set the actual opening probe ceiling before sending the SDP answer to the viewer.
    pub fn prime_peer(peer: &transport::Peer, policy: &QualityPolicy) -> Result<()> {
        let opening = session_opening(policy, Quality::default());
        peer.control_tx
            .try_send(PeerControl::SetDesiredBitrate(opening.probe_kbps))
            .map_err(|_| anyhow::anyhow!("initial media control unavailable"))
    }

    /// Start the pipeline on `peer` with the production quality `policy`. The encode thread is
    /// named `thread_name`. Media must be admitted already.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        id: String,
        peer: &transport::Peer,
        policy: Arc<QualityPolicy>,
        gate: Arc<dyn MediaAdmission>,
        factory: EncoderFactory,
        encoder: Box<dyn Encoder>,
        healthy: SourceHealthy,
        thread_name: &str,
    ) -> Result<Self> {
        anyhow::ensure!(gate.admits(), "a media-only session needs media admitted");
        let now = Instant::now();
        let quality_pref = Quality::default();
        let opening = session_opening(&policy, quality_pref);
        let target = Arc::new(QualityTarget::with_outstanding(
            opening.start,
            peer.outstanding_bytes.clone(),
        ));
        target.set_target_kbps(opening.target_kbps);
        let qp_ceiling = encoder.max_qp().map(|q| q as f32);
        let counters = Arc::new(SessionCounters::default());
        counters
            .lowest_height
            .store(opening.start.max_h, Ordering::Relaxed);
        let bg = Arc::new(crate::bg_hold::BgHold::new(id.clone(), target.clone()));
        let game_status = Arc::new(GameStatus::new());
        let capture_mode = Arc::new(CaptureModeCell::new(CaptureMode::GameWindow {
            binding: None,
        }));
        let publisher = Arc::new(FramePublisher {
            frames: LatestFrame::new(false),
            gate: gate.clone(),
            started: now,
            healthy,
        });
        let bridge = publisher.clone();
        let backends = Arc::new(Backends {
            make_capturer: Box::new(|| {
                anyhow::bail!("monitor capture is unavailable in a media-only session")
            }),
            make_game_capturer: Box::new(move |_| Ok(Box::new(Feed(bridge.clone())))),
            make_encoder: Box::new(move || factory()),
            injector: Arc::new(NoInput),
        });
        let capture = SessionCapture::new(backends, capture_mode, game_status.clone());
        let (frame_tx, frame_rx) = std::sync::mpsc::channel();
        let mut capturer = capture.make()?;
        capturer.start(frame_tx.clone(), target.clone())?;
        let stop = Arc::new(AtomicBool::new(false));
        let pending_kf = Arc::new(AtomicBool::new(false));
        let viewer_kf = Arc::new(crate::keyframe_window::ViewerAsks::default());
        let health = Arc::new(crate::pipeline::PipelineHealth::new(now));
        let pin = Arc::new(AtomicU32::new(NO_PIN_REQUEST));
        let supervisor = crate::pipeline::Supervisor::new(
            health.clone(),
            capture,
            Arc::new(Mutex::new(capturer)),
            frame_tx,
            target.clone(),
            pending_kf.clone(),
            now,
        );
        let (finished, encode_done) = oneshot::channel();
        let mode = EncodeControl {
            stop: stop.clone(),
            feed: Some(publisher.clone()),
        };
        let sink = MediaSink {
            tx: peer.media_tx.clone(),
            queued_bytes: peer.queued_media_bytes.clone(),
            nacks: peer.nacks_received.clone(),
        };
        let encode_target = target.clone();
        let encode_counters = counters.clone();
        let asks = viewer_kf.clone();
        std::thread::Builder::new()
            .name(thread_name.to_owned())
            .spawn(move || {
                let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    encode_loop(
                        encoder,
                        frame_rx,
                        sink,
                        mode,
                        encode_target,
                        encode_counters,
                        supervisor,
                        &asks,
                    )
                }));
                match ended {
                    Ok(Some(reason)) => tracing::warn!(reason, "media-only pipeline ended"),
                    Err(_) => tracing::error!("media-only pipeline panicked"),
                    Ok(None) => {}
                }
                gate.revoke();
                if finished.send(()).is_err() {
                    tracing::debug!("media-only completion waiter gone");
                }
            })
            .context("spawn the media-only encoder thread")?;
        let control = spawn_media_control(
            MediaPeerGauges::new(peer),
            MediaControl {
                session_id: id.clone(),
                policy,
                quality_pref,
                initial_desired_kbps: opening.probe_kbps,
                qp_ceiling,
                delivery_epoch: now,
                target: target.clone(),
                counters: counters.clone(),
                stop: stop.clone(),
                pin_request: pin.clone(),
                game_status,
                pending_kf: pending_kf.clone(),
                bg: bg.clone(),
                health,
                summary: MediaObservation(None),
                journal: None,
                calibrate: false,
            },
        );
        tracing::debug!(
            height = opening.start.max_h,
            fps = opening.start.fps,
            budget_kbps = opening.target_kbps,
            "media-only session started on the production profile"
        );
        Ok(Self {
            target,
            publisher,
            stop,
            encode_done: Some(encode_done),
            control: Some(control),
            feedback: MediaFeedback {
                id,
                pin,
                pending_kf,
                viewer_kf,
                counters,
                bg,
                delivery_epoch: now,
                viewer: crate::viewer_report::ViewerReportLog::default(),
                control: peer.control_tx.clone(),
            },
        })
    }

    pub async fn close(mut self) -> Result<()> {
        self.stop.store(true, Ordering::SeqCst);
        let encode = self
            .encode_done
            .take()
            .context("missing encode completion")?;
        let control = self.control.take().context("missing media control task")?;
        tokio::time::timeout(Duration::from_secs(1), async {
            let (encode, control) = tokio::join!(encode, control);
            encode.context("encode completion lost")?;
            control.context("media control task failed")
        })
        .await
        .context("media-only cleanup deadline")?
    }

    pub fn peer_event(&self, event: &PeerEvent) {
        let feedback = &self.feedback;
        match event {
            PeerEvent::BitrateEstimate { kbps } => {
                feedback
                    .counters
                    .estimate_kbps
                    .store(*kbps, Ordering::Relaxed);
            }
            PeerEvent::LinkStats {
                rtt_ms,
                loss,
                plis,
                nacks,
                ..
            } => {
                note_receiver_report(&feedback.counters, *rtt_ms, *loss, *plis, *nacks);
            }
            PeerEvent::KeyframeRequest(ask) => {
                if ask.from_viewer() {
                    feedback.viewer_kf.note(Instant::now());
                } else {
                    feedback.pending_kf.store(true, Ordering::SeqCst);
                }
            }
            _ => {}
        }
    }

    /// Accept only the production media controls. Return whether the viewer hid the page so the
    /// host can end its session. A stale feedback report is ignored and cannot become input.
    pub fn viewer_message(&mut self, bytes: &[u8], fresh: bool) -> Option<bool> {
        let message = InputMessage::parse(std::str::from_utf8(bytes).ok()?).ok()?;
        let now = Instant::now();
        let feedback = &mut self.feedback;
        match message {
            InputMessage::Quality { q } => {
                if fresh {
                    if let Some(pin) = parse_quality_pin(&q) {
                        feedback
                            .pin
                            .store(pin.unwrap_or(PIN_AUTO), Ordering::Relaxed);
                    } else {
                        tracing::debug!("unknown quality pin refused");
                    }
                }
            }
            InputMessage::ViewerLatency {
                jbuf_ms,
                frames,
                jitter_ms,
            } => {
                if fresh {
                    note_viewer_latency(
                        &feedback.counters,
                        jbuf_ms,
                        frames,
                        jitter_ms,
                        &feedback.id,
                    );
                }
            }
            InputMessage::ViewerVideo(report) => {
                if fresh {
                    // Viewer-supplied identifiers and diagnostics are unnecessary for adaptation.
                    let report = afklink_protocol::ViewerVideo {
                        frames_received: report.frames_received,
                        frames_decoded: report.frames_decoded,
                        current_ms: report.current_ms,
                        engine: report.engine.filter(|engine| {
                            matches!(engine.as_str(), "webkit" | "chromium" | "gecko" | "unknown")
                        }),
                        jbuf_target_ms: report.jbuf_target_ms,
                        freeze_count: report.freeze_count,
                        freeze_ms: report.freeze_ms,
                        ..Default::default()
                    };
                    note_viewer_delivery(
                        &feedback.counters,
                        &report,
                        feedback.delivery_epoch,
                        &feedback.id,
                    );
                    let playout = feedback.viewer.observe(
                        now,
                        report,
                        &feedback.id,
                        &feedback.counters.viewer,
                    );
                    if feedback
                        .control
                        .try_send(PeerControl::ViewerPlayout(playout))
                        .is_err()
                    {
                        tracing::trace!("viewer playout sample superseded during backpressure");
                    }
                }
            }
            InputMessage::KeyframeRequest { .. } => {
                if fresh {
                    feedback
                        .bg
                        .on_trigger(crate::bg_hold::Trigger::Keyframe, now);
                    if feedback.viewer.keyframe_request(now, None, &feedback.id) {
                        feedback.pending_kf.store(true, Ordering::SeqCst);
                    }
                }
            }
            InputMessage::Visibility { hidden, .. } => {
                if hidden {
                    return Some(true);
                }
                if fresh {
                    feedback.bg.on_vis(false, None, now);
                }
            }
            _ => return None,
        }
        Some(false)
    }
}

impl Drop for MediaFeed {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.publisher.gate.revoke();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Admission a test switches by hand.
    #[derive(Default)]
    struct TestAdmission {
        open: AtomicBool,
        revoked: AtomicBool,
    }

    impl MediaAdmission for TestAdmission {
        fn admits(&self) -> bool {
            self.open.load(Ordering::SeqCst) && !self.revoked.load(Ordering::SeqCst)
        }
        fn revoke(&self) {
            self.revoked.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn frame_publisher_keeps_latest_like_ordinary_encoder_and_clears_on_hold() {
        let now = Instant::now();
        let gate = Arc::new(TestAdmission::default());
        let publisher = Arc::new(FramePublisher {
            frames: LatestFrame::new(true),
            gate: gate.clone(),
            started: now,
            healthy: Arc::new(|| true),
        });
        let (sink, frames) = std::sync::mpsc::channel();
        let fed = EncodeControl {
            stop: Arc::default(),
            feed: Some(publisher.clone()),
        };
        let ordinary = EncodeControl::ordinary(Arc::default());
        let frame = crate::game::black_frame((2, 2), 0);
        publisher.publish(frame.clone(), now);
        assert!(fed.receive_latest(&frames, Duration::ZERO).is_err());
        gate.open.store(true, Ordering::SeqCst);

        // Virtual-time 60 fps. The first encode ends 17 ms after it acquired the previous
        // frame. The second acquisition at 16 ms must still be there, even if motion stops.
        publisher.publish(frame.clone(), now);
        assert_eq!(
            fed.receive_latest(&frames, Duration::ZERO)
                .unwrap()
                .0
                .timestamp_ms,
            0
        );
        publisher.publish(frame.clone(), now + Duration::from_millis(16));
        let (latest, offered) = fed.receive_latest(&frames, Duration::ZERO).unwrap();
        assert_eq!((latest.timestamp_ms, offered), (16, 1));
        println!("17 ms codec busy: next sample 16 ms, age 1 ms, dropped 0");

        // Drive the exact receiver used by encode_loop, including its ordinary branch.
        for burst in [1, 12] {
            let mut age_max = 0;
            let mut dropped = 0;
            for batch in (0..60).step_by(burst) {
                for index in batch..batch + burst {
                    let at = index as u64 * 1000 / 60;
                    publisher.publish(frame.clone(), now + Duration::from_millis(at));
                    sink.send(Frame {
                        timestamp_ms: at,
                        ..frame.clone()
                    })
                    .unwrap();
                }
                let (normal, normal_offered) =
                    ordinary.receive_latest(&frames, Duration::ZERO).unwrap();
                let (private, private_offered) =
                    fed.receive_latest(&frames, Duration::ZERO).unwrap();
                let consumer_at = (batch + burst) as u64 * 1000 / 60;
                age_max = age_max.max(consumer_at - private.timestamp_ms);
                dropped += private_offered - 1;
                assert_eq!(
                    (private.timestamp_ms, private_offered),
                    (normal.timestamp_ms, normal_offered)
                );
            }
            assert!(age_max <= 17);
            assert_eq!(dropped, 60 - 60 / burst as u32);
            println!("60 fps input, {burst} frames per encoder read: max age {age_max} ms, {dropped} replaced frames");
        }
        let mut feed = Feed(publisher.clone());
        publisher.publish(frame.clone(), now);
        assert!(feed.hold(true));
        publisher.publish(frame.clone(), now);
        assert!(feed.hold(false));
        assert!(fed.receive_latest(&frames, Duration::ZERO).is_err());
        publisher.publish(frame.clone(), now);
        gate.revoke();
        publisher.publish(frame, now);
        assert!(fed.receive_latest(&frames, Duration::ZERO).is_err());
    }
}
