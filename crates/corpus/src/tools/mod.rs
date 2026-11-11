//! Generators, the live recorder, the encode report and the manifest (feature `tools`).
//!
//! [`catalog`] is the default corpus: one entry per scenario, each a spec a generator turns into
//! a file. Adding a scenario is adding an entry here (see the crate docs).

pub mod drag;
pub mod edge;
pub mod editor;
pub mod emit;
pub mod html;
pub mod image;
pub mod manifest;
pub mod record;
pub mod scene;
pub mod scroll;
pub mod verify;
pub mod video;

use std::path::PathBuf;

use anyhow::Result;

use crate::format::Summary;
use crate::motion::ScrollProfile;

/// One scenario to generate.
#[derive(Debug, Clone)]
pub enum Scenario {
    Scroll(scroll::ScrollSpec),
    Typing(editor::TypingSpec),
    Idle(editor::IdleSpec),
    Drag(drag::DragSpec),
    Video(video::VideoSpec),
}

impl Scenario {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Scroll(s) => &s.name,
            Self::Typing(s) => &s.name,
            Self::Idle(s) => &s.name,
            Self::Drag(s) => &s.name,
            Self::Video(s) => &s.name,
        }
    }

    /// Set the seed (every generator is a pure function of its spec and seed).
    pub fn set_seed(&mut self, seed: u64) {
        match self {
            Self::Scroll(s) => s.seed = seed,
            Self::Typing(s) => s.seed = seed,
            Self::Idle(s) => s.seed = seed,
            Self::Drag(s) => s.seed = seed,
            Self::Video(s) => s.seed = seed,
        }
    }

    pub fn set_seconds(&mut self, seconds: f64) {
        match self {
            Self::Scroll(s) => s.seconds = seconds,
            Self::Typing(s) => s.seconds = seconds,
            Self::Idle(s) => s.seconds = seconds,
            Self::Drag(s) => s.seconds = seconds,
            Self::Video(s) => s.seconds = seconds,
        }
    }

    pub fn rename(&mut self, name: &str) {
        let n = name.to_string();
        match self {
            Self::Scroll(s) => s.name = n,
            Self::Typing(s) => s.name = n,
            Self::Idle(s) => s.name = n,
            Self::Drag(s) => s.name = n,
            Self::Video(s) => s.name = n,
        }
    }
}

/// Generate one scenario into `ctx.out_dir`.
pub fn generate(ctx: &mut scene::Ctx, s: &Scenario) -> Result<Summary> {
    match s {
        Scenario::Scroll(spec) => scroll::generate(ctx, spec),
        Scenario::Typing(spec) => editor::generate_typing(ctx, spec),
        Scenario::Idle(spec) => editor::generate_idle(ctx, spec),
        Scenario::Drag(spec) => drag::generate(ctx, spec),
        Scenario::Video(spec) => video::generate(ctx, spec),
    }
}

/// `%USERPROFILE%\Videos\Radeon ReLive\...`: the user's ReLive recordings on this PC.
fn relive(rel: &str) -> PathBuf {
    let home = std::env::var_os("USERPROFILE")
        .map_or_else(|| PathBuf::from(r"C:\Users\Player"), PathBuf::from);
    home.join(r"Videos\Radeon ReLive").join(rel)
}

/// The game recording the game scenario decodes (3600x2400, 60 fps, AV1).
#[must_use]
pub fn default_game_video() -> PathBuf {
    relive(r"Gothic 1 Remake\Gothic 1 Remake_replay_2026.09.05-17.54.mp4")
}

/// The cinematic cutscene the video scenarios decode (3840x2160, 60 fps, AV1).
#[must_use]
pub fn default_cutscene_video() -> PathBuf {
    relive(r"Clair Obscur Expedition 33\Clair Obscur Expedition 33_replay_2026.01.09-22.58.mp4")
}

/// The default corpus.
#[must_use]
pub fn catalog() -> Vec<Scenario> {
    use scroll::{Content, ScrollSpec};
    vec![
        Scenario::Scroll(ScrollSpec::new(
            "text_scroll_smooth_code",
            Content::Code,
            ScrollProfile::Steady,
            60.0,
            101,
        )),
        Scenario::Scroll(ScrollSpec::new(
            "text_scroll_wheel_article",
            Content::Article,
            ScrollProfile::Wheel,
            60.0,
            102,
        )),
        Scenario::Scroll(ScrollSpec::new(
            "text_scroll_jerky_article",
            Content::Article,
            ScrollProfile::Jerky,
            60.0,
            103,
        )),
        Scenario::Scroll(ScrollSpec::new(
            "text_scroll_jerky_code",
            Content::Code,
            ScrollProfile::Jerky,
            60.0,
            104,
        )),
        Scenario::Typing(editor::TypingSpec {
            name: "typing_code".into(),
            seed: 105,
            seconds: 60.0,
            key_median_s: 0.2,
        }),
        Scenario::Idle(editor::IdleSpec {
            name: "idle_static".into(),
            seed: 106,
            seconds: 60.0,
            caret: false,
        }),
        Scenario::Idle(editor::IdleSpec {
            name: "idle_caret".into(),
            seed: 107,
            seconds: 60.0,
            caret: true,
        }),
        Scenario::Drag(drag::DragSpec {
            name: "window_drag".into(),
            seed: 108,
            seconds: 30.0,
            resize_share: 0.3,
        }),
        Scenario::Video(video::VideoSpec {
            name: "video_windowed".into(),
            layout: video::Layout::Windowed,
            file: default_cutscene_video(),
            start_s: 184.0,
            seconds: 30.0,
            content_fps: 30.0,
            duplicates: true,
            seed: 109,
            source_w: 3840,
            source_h: 2160,
        }),
        Scenario::Video(video::VideoSpec {
            name: "video_fullscreen".into(),
            layout: video::Layout::Fullscreen,
            file: default_cutscene_video(),
            start_s: 184.0,
            seconds: 30.0,
            content_fps: 30.0,
            duplicates: true,
            seed: 110,
            source_w: 3840,
            source_h: 2160,
        }),
        Scenario::Video(video::VideoSpec {
            name: "game_fullscreen".into(),
            layout: video::Layout::Game,
            file: default_game_video(),
            start_s: 42.0,
            seconds: 30.0,
            content_fps: 60.0,
            duplicates: false,
            seed: 111,
            source_w: 3600,
            source_h: 2400,
        }),
    ]
}
