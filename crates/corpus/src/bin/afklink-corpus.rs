//! `afklink-corpus`: generate, record, inspect and verify the screen-content corpus.
//!
//! ```text
//! afklink-corpus gen <name>|all|list [--out-dir D] [--seed N] [--seconds S] [--as NAME]
//!                    [--video FILE --start S]                       (video/game scenarios)
//! afklink-corpus gen scroll --name N --content code|article --profile steady|wheel|jerky
//!                    [--speed PX_S] [--swipe LO,HI] [--pause LO,HI] [--page-instant P]
//!                    [--weights SWIPE,PAGE,DRAG,FLING] [--no-pointer] [--seed N] [--seconds S]
//! afklink-corpus record --out FILE --seconds S [--name N] [--description TEXT] [--max-h H]
//!                    [--zstd-level L] [--workers N] [--queue-mb M]
//! afklink-corpus info FILE...
//! afklink-corpus manifest [--dir D]
//! afklink-corpus verify [FILE...] [--dir D] [--budgets 1000,2500,5000] [--fps 30] [--max-h 1080]
//!                    [--seconds S] [--json OUT]
//! afklink-corpus verify FILE --replay-log LOG --window HH:MM:SS-HH:MM:SS [--json OUT]
//! afklink-corpus rescale-check (--video FILE --start S | --corpus FILE) [--frames N] [--kbps K]
//! afklink-corpus dump FILE --out-dir D [--every N] [--max N]
//! ```
//!
//! Logging: `RUST_LOG` if set, otherwise the project's development default (debug for our crates).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use afklink_corpus::format::Scaling;
use afklink_corpus::motion::ScrollProfile;
use afklink_corpus::tools::{self, scene::Ctx, scroll, verify, Scenario};
use afklink_corpus::Reader;
use anyhow::{bail, ensure, Context, Result};

/// Flags that take no value.
const FLAGS: &[&str] = &["no-pointer", "no-duplicates"];

struct Args {
    pos: Vec<String>,
    opts: BTreeMap<String, String>,
    flags: BTreeSet<String>,
    used: std::cell::RefCell<BTreeSet<String>>,
}

impl Args {
    fn parse(raw: Vec<String>) -> Result<Self> {
        let mut pos = Vec::new();
        let mut opts = BTreeMap::new();
        let mut flags = BTreeSet::new();
        let mut it = raw.into_iter();
        while let Some(a) = it.next() {
            if let Some(k) = a.strip_prefix("--") {
                if FLAGS.contains(&k) {
                    flags.insert(k.to_string());
                } else {
                    let v = it.next().with_context(|| format!("--{k} needs a value"))?;
                    opts.insert(k.to_string(), v);
                }
            } else {
                pos.push(a);
            }
        }
        Ok(Self {
            pos,
            opts,
            flags,
            used: std::cell::RefCell::new(BTreeSet::new()),
        })
    }

    fn get<T: FromStr>(&self, k: &str) -> Result<Option<T>>
    where
        T::Err: std::fmt::Display,
    {
        self.used.borrow_mut().insert(k.to_string());
        self.opts
            .get(k)
            .map(|v| {
                v.parse::<T>()
                    .map_err(|e| anyhow::anyhow!("--{k} {v:?}: {e}"))
            })
            .transpose()
    }

    fn pair(&self, k: &str) -> Result<Option<(f64, f64)>> {
        let Some(v) = self.get::<String>(k)? else {
            return Ok(None);
        };
        let (a, b) = v
            .split_once(',')
            .with_context(|| format!("--{k} wants LO,HI"))?;
        Ok(Some((a.trim().parse()?, b.trim().parse()?)))
    }

    fn list<T: FromStr>(&self, k: &str) -> Result<Option<Vec<T>>>
    where
        T::Err: std::error::Error + Send + Sync + 'static,
    {
        let Some(v) = self.get::<String>(k)? else {
            return Ok(None);
        };
        v.split(',')
            .map(|s| s.trim().parse::<T>().map_err(anyhow::Error::from))
            .collect::<Result<Vec<T>>>()
            .map(Some)
    }

    fn flag(&self, k: &str) -> bool {
        self.flags.contains(k)
    }

    /// Refuse options nobody read: a typo must not silently fall back to a default.
    fn finish(&self) -> Result<()> {
        let used = self.used.borrow();
        let unknown: Vec<&String> = self.opts.keys().filter(|k| !used.contains(*k)).collect();
        ensure!(unknown.is_empty(), "unknown option(s): {unknown:?}");
        Ok(())
    }
}

/// The agent repository's root (this crate is `crates/corpus`): where the rendered source files
/// are read from, and the default corpus directory `<root>/corpus/`.
fn repo_root() -> PathBuf {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    match here.canonicalize() {
        Ok(root) => {
            tracing::debug!(root = %root.display(), "repository root");
            root
        }
        Err(e) => {
            tracing::warn!(root = %here.display(), "cannot canonicalize the repository root ({e}); using it as is");
            here
        }
    }
}

fn default_dir() -> PathBuf {
    repo_root().join("corpus")
}

fn main() {
    // A development tool: the development channel's level, unless RUST_LOG says otherwise.
    let filter = afklink_core::logging::env_filter_override()
        .map(tracing_subscriber::EnvFilter::new)
        .unwrap_or_else(|| {
            afklink_core::logging::default_log_level(afklink_core::build_info::Channel::Dev)
                .filter()
        });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    if let Err(e) = run() {
        tracing::error!("{e:#}");
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() {
        bail!("usage: afklink-corpus gen|record|info|manifest|verify|rescale-check|dump ... (see the source header)");
    }
    let cmd = raw.remove(0);
    let args = Args::parse(raw)?;
    match cmd.as_str() {
        "gen" => cmd_gen(&args),
        "record" => cmd_record(&args),
        "info" => cmd_info(&args),
        "manifest" => {
            let dir = args.get::<PathBuf>("dir")?.unwrap_or_else(default_dir);
            args.finish()?;
            let report = std::fs::read_to_string(dir.join("encode-report.md")).ok();
            tools::manifest::write(&dir, report.as_deref())
        }
        "verify" => cmd_verify(&args),
        "rescale-check" => cmd_rescale(&args),
        "dump" => cmd_dump(&args),
        "repack" => cmd_repack(&args),
        other => bail!("unknown command {other:?}"),
    }
}

fn cmd_gen(args: &Args) -> Result<()> {
    let what = args
        .pos
        .first()
        .cloned()
        .context("gen <name>|all|list|scroll")?;
    let out_dir = args.get::<PathBuf>("out-dir")?.unwrap_or_else(default_dir);
    let seed = args.get::<u64>("seed")?;
    let seconds = args.get::<f64>("seconds")?;
    let rename = args.get::<String>("as")?;
    let video = args.get::<PathBuf>("video")?;
    let start = args.get::<f64>("start")?;

    let mut list: Vec<Scenario> = match what.as_str() {
        "list" => {
            args.finish()?;
            for s in tools::catalog() {
                println!("{}", s.name());
            }
            return Ok(());
        }
        "all" => tools::catalog(),
        "scroll" => {
            let name = args
                .get::<String>("name")?
                .context("gen scroll needs --name")?;
            let content: scroll::Content = args.get("content")?.unwrap_or(scroll::Content::Code);
            let profile: ScrollProfile = args.get("profile")?.unwrap_or(ScrollProfile::Jerky);
            let mut spec = scroll::ScrollSpec::new(&name, content, profile, 60.0, 1);
            spec.pointer = !args.flag("no-pointer");
            spec.speed_px_s = args.get("speed")?;
            spec.swipe_px = args.pair("swipe")?;
            spec.pause_s = args.pair("pause")?;
            spec.page_instant = args.get("page-instant")?;
            if let Some(w) = args.list::<f64>("weights")? {
                ensure!(w.len() == 4, "--weights wants four numbers");
                spec.weights = Some([w[0], w[1], w[2], w[3]]);
            }
            vec![Scenario::Scroll(spec)]
        }
        name => {
            let s = tools::catalog()
                .into_iter()
                .find(|s| s.name() == name)
                .with_context(|| format!("no scenario {name:?}; `gen list` shows them"))?;
            vec![s]
        }
    };
    args.finish()?;
    for s in &mut list {
        if let Some(seed) = seed {
            s.set_seed(seed);
        }
        if let Some(sec) = seconds {
            s.set_seconds(sec);
        }
        if let Scenario::Video(v) = s {
            if let Some(f) = &video {
                v.file.clone_from(f);
            }
            if let Some(st) = start {
                v.start_s = st;
            }
        }
    }
    if let Some(n) = &rename {
        ensure!(list.len() == 1, "--as renames a single scenario");
        list[0].rename(n);
    }

    let mut ctx = Ctx::new(repo_root(), out_dir.clone())?;
    let mut failed = Vec::new();
    for s in &list {
        if let Scenario::Video(v) = s {
            if !v.file.is_file() {
                tracing::warn!(scenario = s.name(), file = %v.file.display(), "video not found; skipped (use --video)");
                failed.push(format!("{} (video missing)", s.name()));
                continue;
            }
        }
        if let Scenario::Scroll(spec) = s {
            // The article is not in this repository (see `scroll::article_source`, which logs
            // where it looked); without it the scenario is skipped like a missing video.
            if spec.content == scroll::Content::Article
                && scroll::article_source(&ctx.repo).is_none()
            {
                tracing::warn!(
                    scenario = s.name(),
                    "article not found; skipped (set {})",
                    scroll::ARTICLE_ENV
                );
                failed.push(format!("{} (article missing)", s.name()));
                continue;
            }
        }
        match tools::generate(&mut ctx, s) {
            Ok(summary) => println!(
                "{}: {} frames ({} unique), {:.1} s",
                s.name(),
                summary.frame_count,
                summary.unique_frames(),
                summary.duration_us as f64 / 1e6
            ),
            Err(e) => {
                tracing::error!(scenario = s.name(), "generation failed: {e:#}");
                failed.push(s.name().to_string());
            }
        }
    }
    let report = std::fs::read_to_string(out_dir.join("encode-report.md")).ok();
    tools::manifest::write(&out_dir, report.as_deref())?;
    ensure!(failed.is_empty(), "not generated: {failed:?}");
    Ok(())
}

fn cmd_record(args: &Args) -> Result<()> {
    let out = args
        .get::<PathBuf>("out")?
        .context("record needs --out FILE")?;
    let seconds = args
        .get::<f64>("seconds")?
        .context("record needs --seconds")?;
    let name = args.get::<String>("name")?.unwrap_or_else(|| {
        out.file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "recorded".into())
    });
    let spec = tools::record::RecordSpec {
        out,
        scenario: name,
        description: args
            .get::<String>("description")?
            .unwrap_or_else(|| "Recorded from the live screen.".into()),
        seconds,
        max_h: args.get("max-h")?,
        zstd_level: args.get("zstd-level")?.unwrap_or(3),
        zstd_workers: args.get("workers")?.unwrap_or(4),
        queue_mb: args.get("queue-mb")?.unwrap_or(2048),
        display_hz: args.get("display-hz")?.unwrap_or(60.0),
        scale_factor: args.get("scale-factor")?.unwrap_or(2.0),
    };
    args.finish()?;
    let s = tools::record::record(&spec)?;
    println!(
        "{}: {} frames, {:.1} s, {} dropped",
        spec.out.display(),
        s.frame_count,
        s.duration_us as f64 / 1e6,
        s.dropped
    );
    Ok(())
}

fn cmd_info(args: &Args) -> Result<()> {
    args.finish()?;
    ensure!(!args.pos.is_empty(), "info FILE...");
    for f in &args.pos {
        let path = Path::new(f);
        let (meta, summary) = afklink_corpus::read_info(path)?;
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        println!("{}", serde_json::to_string_pretty(&meta)?);
        match summary {
            Some(s) => println!(
                "frames {} (key {}, inter {}, repeat {}), {:.1} s, {:.1} MB on disk, dropped {}",
                s.frame_count,
                s.key_frames,
                s.inter_frames,
                s.repeat_frames,
                s.duration_us as f64 / 1e6,
                size as f64 / 1e6,
                s.dropped
            ),
            None => println!(
                "truncated: no end record ({:.1} MB on disk)",
                size as f64 / 1e6
            ),
        }
    }
    Ok(())
}

fn cmd_verify(args: &Args) -> Result<()> {
    let dir = args.get::<PathBuf>("dir")?.unwrap_or_else(default_dir);
    let json = args.get::<PathBuf>("json")?;
    let limit = args.get::<f64>("seconds")?;
    let files: Vec<PathBuf> = if args.pos.is_empty() {
        tools::manifest::corpus_files(&dir)?
    } else {
        args.pos.iter().map(PathBuf::from).collect()
    };
    let targets: Vec<verify::Target> = if let Some(log) = args.get::<PathBuf>("replay-log")? {
        let window = args
            .get::<String>("window")?
            .context("--replay-log needs --window FROM-TO")?;
        let (from, to) = window
            .split_once('-')
            .context("--window HH:MM:SS-HH:MM:SS")?;
        let steps = verify::read_log_window(&log, from, to)?;
        vec![verify::Target::Replay {
            label: format!("replay {from}-{to}"),
            steps,
        }]
    } else {
        let budgets = args
            .list::<u32>("budgets")?
            .unwrap_or_else(|| vec![1000, 2500, 5000]);
        let fps = args.get::<u32>("fps")?.unwrap_or(30);
        let max_h = args.get::<u32>("max-h")?.unwrap_or(1080);
        budgets
            .into_iter()
            .map(|kbps| verify::Target::Fixed { kbps, max_h, fps })
            .collect()
    };
    args.finish()?;
    let mut reports = Vec::new();
    for f in &files {
        match verify::run(f, &targets, limit) {
            Ok(r) => {
                for t in &r.targets {
                    if !t.logged.is_empty() {
                        println!(
                            "\n{} — {}\n\n{}",
                            r.scenario,
                            t.target,
                            verify::format_replay(t)
                        );
                    }
                }
                reports.push(r);
            }
            Err(e) => tracing::error!(file = %f.display(), "verify failed: {e:#}"),
        }
    }
    let table = verify::format_table(&reports);
    println!("\n{table}");
    if let Some(p) = json {
        std::fs::write(&p, serde_json::to_vec_pretty(&reports)?)
            .with_context(|| format!("write {}", p.display()))?;
        let md = p.with_extension("md");
        std::fs::write(&md, &table).with_context(|| format!("write {}", md.display()))?;
    }
    Ok(())
}

fn cmd_rescale(args: &Args) -> Result<()> {
    let frames = args.get::<u64>("frames")?.unwrap_or(120);
    let kbps = args.get::<u32>("kbps")?.unwrap_or(1500);
    let rungs = [900u32, 720, 540, 360];
    let rows = if let Some(video) = args.get::<PathBuf>("video")? {
        let start = args.get::<f64>("start")?.unwrap_or(0.0);
        let w = args.get::<u32>("width")?.unwrap_or(3600);
        let h = args.get::<u32>("height")?.unwrap_or(2400);
        args.finish()?;
        // 30 fps from the recording, as the 30 fps rungs would take it.
        let mut dec = tools::video::MpvFrames::spawn(
            &video,
            start,
            frames as f64 / 30.0 + 0.5,
            "fps=30",
            w,
            h,
        )?;
        let mut left = frames;
        verify::rescale_check(
            |buf| {
                if left == 0 {
                    return Ok(false);
                }
                left -= 1;
                dec.next_frame(buf)
            },
            w,
            h,
            1080,
            &rungs,
            kbps,
            30,
        )?
    } else {
        let file = args
            .get::<PathBuf>("corpus")?
            .context("--video FILE or --corpus FILE")?;
        args.finish()?;
        let mut r = Reader::open(&file)?;
        ensure!(
            r.metadata().stored.scaling == Scaling::Native,
            "rescale-check needs a native-resolution corpus file"
        );
        let (w, h) = r.size();
        let mut left = frames;
        let mut last_t: Option<u64> = None;
        verify::rescale_check(
            |buf| loop {
                if left == 0 {
                    return Ok(false);
                }
                let Some(f) = r.next_frame()? else {
                    return Ok(false);
                };
                // Every picture change, at most 30 a second.
                if f.is_repeat() || last_t.is_some_and(|t| f.t_us < t + 33_000) {
                    continue;
                }
                last_t = Some(f.t_us);
                buf.clear();
                buf.extend_from_slice(f.data);
                left -= 1;
                return Ok(true);
            },
            w,
            h,
            1080,
            &rungs,
            kbps,
            30,
        )?
    };
    println!("| rung | PSNR two-step vs direct | kbps direct | kbps two-step | QP p50 direct | QP p50 two-step |");
    println!("|---|---|---|---|---|---|");
    for r in rows {
        println!(
            "| {}p | {:.1} dB | {:.0} | {:.0} | {:.1} | {:.1} |",
            r.max_h, r.psnr_db, r.direct_kbps, r.two_step_kbps, r.direct_qp_p50, r.two_step_qp_p50
        );
    }
    Ok(())
}

/// Rewrite a file with other codec settings (a recording made at a fast level, or to compare
/// settings). Pixels and timestamps are unchanged; moves from the original are not kept.
fn cmd_repack(args: &Args) -> Result<()> {
    let file = PathBuf::from(args.pos.first().context("repack FILE --out OUT")?);
    let out = args.get::<PathBuf>("out")?.context("--out")?;
    let defaults = afklink_corpus::WriterOptions::default();
    let opts = afklink_corpus::WriterOptions {
        zstd_level: args.get("level")?.unwrap_or(defaults.zstd_level),
        zstd_workers: args.get("workers")?.unwrap_or(0),
        key_trial_fraction: args
            .get("key-trial")?
            .unwrap_or(defaults.key_trial_fraction),
        key_predictor: match args.get::<String>("predictor")?.as_deref() {
            None => defaults.key_predictor,
            Some("med") => afklink_corpus::codec::Predictor::Med,
            Some("medctx") => afklink_corpus::codec::Predictor::MedCtx,
            Some("none") => afklink_corpus::codec::Predictor::None,
            Some(other) => bail!("--predictor medctx|med|none, not {other}"),
        },
        ..defaults
    };
    args.finish()?;
    let started = std::time::Instant::now();
    let mut r = Reader::open(&file)?;
    let meta = r.metadata().clone();
    let duration = r.duration_us();
    let mut w = afklink_corpus::Writer::create(&out, &meta, opts)?;
    while let Some(f) = r.next_frame()? {
        w.push(f.t_us, f.data, &[])?;
    }
    let s = w.finish(duration.unwrap_or(0))?;
    let (a, b) = (
        std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0),
        std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0),
    );
    println!(
        "{} -> {}: {:.1} MB -> {:.1} MB ({} key, {} inter, {} repeat) in {:.1} s",
        file.display(),
        out.display(),
        a as f64 / 1e6,
        b as f64 / 1e6,
        s.key_frames,
        s.inter_frames,
        s.repeat_frames,
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn cmd_dump(args: &Args) -> Result<()> {
    let file = args.pos.first().context("dump FILE --out-dir D")?;
    let out = args.get::<PathBuf>("out-dir")?.context("--out-dir")?;
    let every = args.get::<u64>("every")?.unwrap_or(60).max(1);
    let max = args.get::<u64>("max")?.unwrap_or(20);
    args.finish()?;
    std::fs::create_dir_all(&out)?;
    let mut r = Reader::open(Path::new(file))?;
    let mut written = 0;
    while let Some(f) = r.next_frame()? {
        if f.index % every != 0 {
            continue;
        }
        let p = out.join(format!("{:06}_{:08}us.png", f.index, f.t_us));
        tools::image::save_png_bgra(&p, f.width, f.height, f.data)?;
        written += 1;
        if written >= max {
            break;
        }
    }
    println!("{written} frames written to {}", out.display());
    Ok(())
}
