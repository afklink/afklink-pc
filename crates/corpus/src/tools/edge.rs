//! Rendering HTML to pixels with headless Microsoft Edge.
//!
//! Real text rendering is the point: DirectWrite glyphs with the same ClearType (coloured subpixel)
//! antialiasing the desktop uses, at the panel's 200% scale. Every run uses a private profile under
//! the work directory and `--headless=new`, so nothing touches the user's browser, no window
//! appears, and focus is never taken.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};

use super::image::Image;

/// Device scale factor of the panel (200%).
pub const DSF: u32 = 2;

/// How long one render may take before it is killed.
const RENDER_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Edge {
    exe: PathBuf,
    work: PathBuf,
    profile: PathBuf,
    seq: AtomicU32,
}

impl Edge {
    /// Find `msedge.exe` (or `$AFKLINK_CORPUS_EDGE`) and prepare `work` for pages and screenshots.
    pub fn locate(work: &Path) -> Result<Self> {
        let candidates: Vec<PathBuf> = std::env::var_os("AFKLINK_CORPUS_EDGE")
            .map(PathBuf::from)
            .into_iter()
            .chain([
                PathBuf::from(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
                PathBuf::from(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
            ])
            .collect();
        let exe = candidates
            .iter()
            .find(|p| p.is_file())
            .cloned()
            .with_context(|| {
                format!("headless Edge not found (tried {candidates:?}); set AFKLINK_CORPUS_EDGE")
            })?;
        std::fs::create_dir_all(work).with_context(|| format!("create {}", work.display()))?;
        let profile = work.join("edge-profile");
        tracing::debug!(exe = %exe.display(), work = %work.display(), "headless Edge located");
        Ok(Self {
            exe,
            work: work.to_path_buf(),
            profile,
            seq: AtomicU32::new(0),
        })
    }

    fn page(&self, name: &str, html: &str) -> Result<(PathBuf, String)> {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let path = self.work.join(format!("{n:03}-{name}.html"));
        std::fs::write(&path, html).with_context(|| format!("write {}", path.display()))?;
        let url = format!("file:///{}", path.display().to_string().replace('\\', "/"));
        Ok((path, url))
    }

    fn base_args(&self, css_w: u32, css_h: u32) -> Vec<String> {
        vec![
            "--headless=new".into(),
            "--disable-gpu".into(),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            "--disable-extensions".into(),
            "--disable-sync".into(),
            "--mute-audio".into(),
            "--hide-scrollbars".into(),
            "--allow-file-access-from-files".into(),
            format!("--user-data-dir={}", self.profile.display()),
            format!("--force-device-scale-factor={DSF}"),
            format!("--window-size={css_w},{css_h}"),
            // Let images and fonts arrive before the picture is taken.
            "--virtual-time-budget=4000".into(),
        ]
    }

    /// Render `html` in a `css_w x css_h` CSS-pixel window and return the screenshot
    /// (`css_w * 2 x css_h * 2`). `transparent` keeps the page background's alpha.
    pub fn screenshot(
        &self,
        name: &str,
        html: &str,
        css_w: u32,
        css_h: u32,
        transparent: bool,
    ) -> Result<Image> {
        let (page, url) = self.page(name, html)?;
        let png = page.with_extension("png");
        let _ = std::fs::remove_file(&png);
        let mut args = self.base_args(css_w, css_h);
        if transparent {
            args.push("--default-background-color=00000000".into());
        }
        args.push(format!("--screenshot={}", png.display()));
        args.push(url);
        let started = Instant::now();
        let (status, _) = self.run(&args, false)?;
        ensure!(
            status.success() && png.is_file(),
            "Edge failed to render {name} (status {status})"
        );
        let img = Image::load_png(&png)?;
        ensure!(
            img.w == css_w * DSF && img.h == css_h * DSF,
            "{name}: screenshot is {}x{}, expected {}x{} (device scale factor not applied?)",
            img.w,
            img.h,
            css_w * DSF,
            css_h * DSF
        );
        tracing::debug!(
            name,
            w = img.w,
            h = img.h,
            ms = started.elapsed().as_millis() as u64,
            png = %png.display(),
            "rendered"
        );
        Ok(img)
    }

    /// Load `html`, let its scripts run, and return the serialised DOM (for measurements a script
    /// writes into the page).
    pub fn dump_dom(&self, name: &str, html: &str, css_w: u32, css_h: u32) -> Result<String> {
        let (_, url) = self.page(name, html)?;
        let mut args = self.base_args(css_w, css_h);
        args.push("--dump-dom".into());
        args.push(url);
        let (status, out) = self.run(&args, true)?;
        ensure!(
            status.success(),
            "Edge --dump-dom failed for {name} ({status})"
        );
        tracing::debug!(name, bytes = out.len(), "DOM dumped");
        Ok(out)
    }

    fn run(&self, args: &[String], capture: bool) -> Result<(std::process::ExitStatus, String)> {
        let mut cmd = Command::new(&self.exe);
        cmd.args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(if capture {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // CREATE_NO_WINDOW: no console flashes up on the user's screen.
            cmd.creation_flags(0x0800_0000);
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("start {}", self.exe.display()))?;
        let reader = child.stdout.take().map(|mut out| {
            std::thread::spawn(move || {
                let mut s = String::new();
                let _ = std::io::Read::read_to_string(&mut out, &mut s);
                s
            })
        });
        let deadline = Instant::now() + RENDER_TIMEOUT;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if Instant::now() > deadline {
                if let Err(e) = child.kill() {
                    tracing::warn!("could not kill a stuck Edge render: {e}");
                }
                bail!("Edge render timed out after {RENDER_TIMEOUT:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let out = match reader {
            Some(h) => h.join().unwrap_or_default(),
            None => String::new(),
        };
        Ok((status, out))
    }
}

/// Extract the text content of `<pre id="measure" ...>…</pre>` from a dumped DOM (the serialiser
/// adds the script's `style` attribute to the tag).
pub fn measure_json(dom: &str) -> Result<&str> {
    let tag = dom
        .find("<pre id=\"measure\"")
        .context("no measurement in the dumped DOM (did the script run?)")?;
    let start = dom[tag..]
        .find('>')
        .context("unterminated measurement tag")?
        + tag
        + 1;
    let end = dom[start..]
        .find("</pre>")
        .context("unterminated measurement")?
        + start;
    Ok(&dom[start..end])
}
