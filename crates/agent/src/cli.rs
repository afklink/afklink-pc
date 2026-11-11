//! Command-line flags of `afklink-agent`, and the rules that keep a bench run off the owner's
//! desktop.
//!
//! Unknown arguments are refused rather than ignored: a mistyped `--bnech` would otherwise start
//! the agent as the owner's device, capturing the owner's screen, which is precisely what a bench
//! run must never do. What each bench flag means: [`help_text`].

use std::path::PathBuf;

/// What the command line asked for, after [`Options::resolve`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    pub help: bool,
    pub selftest: bool,
    /// Config, identity and everything else `afklink_core::paths::afklink_dir` holds live here: a
    /// different device.
    pub data_dir: Option<PathBuf>,
    /// Play this corpus file instead of capturing the screen.
    pub capture_corpus: Option<PathBuf>,
    /// Inject nothing, lock nothing.
    pub no_input: bool,
    /// Approve pairing requests without asking, and ask for a code while nobody is bound.
    pub auto_approve_pairing: bool,
    /// `--data-dir` required, `--capture-corpus` required, `--no-input` and
    /// `--auto-approve-pairing` implied.
    pub bench: bool,
    /// Link profile read once at start.
    pub link_profile: Option<PathBuf>,
    /// Link profile watched for changes.
    pub link_control: Option<PathBuf>,
}

impl Options {
    /// Parse arguments (without the program name). Syntax only; see [`Self::resolve`] for the rules.
    ///
    /// Values go after a space or an `=`: `--data-dir D:\bench` or `--data-dir=D:\bench`.
    pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Self, String> {
        let mut o = Options::default();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let (flag, inline) = match arg.split_once('=') {
                Some((flag, value)) if flag.starts_with("--") => {
                    (flag.to_string(), Some(value.to_string()))
                }
                _ => (arg.clone(), None),
            };
            let takes_value = matches!(
                flag.as_str(),
                "--data-dir" | "--capture-corpus" | "--link-profile" | "--link-control"
            );
            let value = if takes_value {
                let v = match inline {
                    Some(v) => v,
                    None => args.next().ok_or_else(|| format!("{flag} needs a value"))?,
                };
                if v.is_empty() || v.starts_with("--") {
                    return Err(format!("{flag} needs a value, got {v:?}"));
                }
                Some(PathBuf::from(v))
            } else {
                if inline.is_some() {
                    return Err(format!("{flag} takes no value"));
                }
                None
            };
            match (flag.as_str(), value) {
                ("--help" | "-h", _) => o.help = true,
                ("--selftest", _) => o.selftest = true,
                ("--no-input", _) => o.no_input = true,
                ("--auto-approve-pairing", _) => o.auto_approve_pairing = true,
                ("--bench", _) => o.bench = true,
                ("--data-dir", Some(v)) => set_once(&mut o.data_dir, v, "--data-dir")?,
                ("--capture-corpus", Some(v)) => {
                    set_once(&mut o.capture_corpus, v, "--capture-corpus")?;
                }
                ("--link-profile", Some(v)) => set_once(&mut o.link_profile, v, "--link-profile")?,
                ("--link-control", Some(v)) => set_once(&mut o.link_control, v, "--link-control")?,
                (other, _) => return Err(format!("unknown argument {other:?}")),
            }
        }
        Ok(o)
    }

    /// Apply what `--bench` implies and refuse the combinations that could touch the owner's
    /// desktop or identity.
    ///
    /// Beyond the bench contract, two guards of this build's own, both about the owner's machine:
    /// `--auto-approve-pairing` needs `--data-dir` (auto-approving on the owner's own device would
    /// bind anyone who saw a code to the owner's PC), and `--capture-corpus` needs `--no-input` (a
    /// viewer would otherwise drive the real mouse and keyboard while looking at a recording).
    pub fn resolve(mut self) -> Result<Self, String> {
        if self.bench {
            if self.data_dir.is_none() {
                return Err(
                    "--bench requires --data-dir <dir>: a bench run is a separate device with its \
                     own identity, never the owner's"
                        .into(),
                );
            }
            if self.capture_corpus.is_none() {
                return Err(
                    "--bench requires --capture-corpus <file.rcorp>: a bench run must never \
                     capture the real screen"
                        .into(),
                );
            }
            self.no_input = true;
            self.auto_approve_pairing = true;
        }
        if self.auto_approve_pairing && self.data_dir.is_none() {
            return Err(
                "--auto-approve-pairing requires --data-dir <dir>: approving pairing requests \
                 unattended on the owner's own device would bind anyone who saw a code"
                    .into(),
            );
        }
        if self.capture_corpus.is_some() && !self.no_input {
            return Err(
                "--capture-corpus requires --no-input: a viewer must not drive the real mouse and \
                 keyboard while it is shown a recording"
                    .into(),
            );
        }
        Ok(self)
    }

    /// Whether the link shaper is on.
    #[must_use]
    pub fn shaping(&self) -> bool {
        self.link_profile.is_some() || self.link_control.is_some()
    }

    /// Whether any bench flag is set (for the log's startup line).
    #[must_use]
    pub fn bench_mode(&self) -> bool {
        self.bench
            || self.data_dir.is_some()
            || self.capture_corpus.is_some()
            || self.no_input
            || self.auto_approve_pairing
            || self.shaping()
    }
}

fn set_once(slot: &mut Option<PathBuf>, value: PathBuf, flag: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{flag} given twice"));
    }
    *slot = Some(value);
    Ok(())
}

/// The `--help` text.
pub fn help_text() -> String {
    "afklink-agent — AFKLink Windows agent (headless)

  afklink-agent              run the agent
  afklink-agent --selftest   capture + encode a few frames, then exit
  afklink-agent --help       this help

Bench device:
  --bench                    shorthand: requires --data-dir and --capture-corpus,
                             implies --no-input and --auto-approve-pairing
  --data-dir <dir>           config.json, identity.json, ... live in <dir>: a separate device
  --capture-corpus <file>    play a .rcorp corpus instead of capturing the screen
                             (requires --no-input)
  --no-input                 inject no input (the real mouse and keyboard are never touched)
  --auto-approve-pairing     approve pairing requests unattended (requires --data-dir)
  --link-profile <file.json> shape the peer's UDP link with this profile (read once)
  --link-control <file.json> shape it with this profile, re-read whenever it changes
Machine-readable lines on stdout start with \"BENCH \".

Config: %APPDATA%\\AFKLink\\config.json + identity.json (or --data-dir)
Log level: \"log_level\" in config.json (off, info, debug; trace by hand); RUST_LOG overrides it"
        .to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Options, String> {
        Options::parse(args.iter().map(|s| s.to_string())).and_then(Options::resolve)
    }

    #[test]
    fn no_arguments_is_the_ordinary_agent() {
        let o = parse(&[]).unwrap();
        assert_eq!(o, Options::default());
        assert!(!o.bench_mode());
        assert!(!o.shaping());
    }

    #[test]
    fn bench_implies_no_input_and_auto_approval() {
        let o = parse(&[
            "--bench",
            "--data-dir",
            r"C:\bench\dev",
            "--capture-corpus=corpus\\x.rcorp",
        ])
        .unwrap();
        assert!(o.bench && o.no_input && o.auto_approve_pairing);
        assert_eq!(o.data_dir, Some(PathBuf::from(r"C:\bench\dev")));
        assert_eq!(o.capture_corpus, Some(PathBuf::from(r"corpus\x.rcorp")));
        assert!(o.bench_mode());
        assert!(!o.shaping());
    }

    #[test]
    fn the_bench_guard_refuses_to_capture_the_real_screen() {
        let e = parse(&["--bench", "--data-dir", "d"]).unwrap_err();
        assert!(e.contains("--capture-corpus"), "{e}");
        let e = parse(&["--bench", "--capture-corpus", "c.rcorp"]).unwrap_err();
        assert!(e.contains("--data-dir"), "{e}");
    }

    #[test]
    fn the_owner_guards_hold_without_bench() {
        let e = parse(&["--auto-approve-pairing"]).unwrap_err();
        assert!(e.contains("--data-dir"), "{e}");
        let e = parse(&["--capture-corpus", "c.rcorp"]).unwrap_err();
        assert!(e.contains("--no-input"), "{e}");
        let o = parse(&["--capture-corpus", "c.rcorp", "--no-input"]).unwrap();
        assert!(o.no_input && !o.auto_approve_pairing);
        let o = parse(&["--auto-approve-pairing", "--data-dir", "d"]).unwrap();
        assert!(o.auto_approve_pairing && !o.no_input);
    }

    #[test]
    fn link_flags_turn_the_shaper_on() {
        let o = parse(&["--link-profile", "p.json"]).unwrap();
        assert!(o.shaping() && o.bench_mode());
        let o = parse(&["--link-control=c.json", "--link-profile", "p.json"]).unwrap();
        assert_eq!(o.link_control, Some(PathBuf::from("c.json")));
        assert_eq!(o.link_profile, Some(PathBuf::from("p.json")));
    }

    #[test]
    fn mistakes_are_refused_not_ignored() {
        for bad in [
            &["--bnech"][..],
            &["--data-dir"],
            &["--data-dir", "--bench"],
            &["--data-dir="],
            &["--no-input=yes"],
            &["--data-dir", "a", "--data-dir", "b"],
            &["run"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(parse(&["-h"]).unwrap().help);
        assert!(parse(&["--selftest"]).unwrap().selftest);
    }
}
