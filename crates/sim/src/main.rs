//! `afklink-sim`: run one scenario file or a directory of them, write each session's log, print the
//! summary.
//!
//! ```text
//! cargo run -p afklink-sim --release -- <scenario.toml | dir> [more ...] [--out DIR] [--profile P] [--log-level LEVEL]
//! ```
//!
//! `--profile`: `reference` (the default: the contract's reference vector, the server's tuned
//! `default`, read at run time), `builtin` (the agent's compiled fallback) or a profile file.
//!
//! Each run's session log (the agent's `pipeline` lines and the rest, in the agent's format with
//! virtual timestamps) goes to `<out>/<scenario>.log`, default `target/sim`, so `ladder_replay` and
//! the table scripts can read simulated sessions. Diagnostics go to stderr at `--log-level`
//! (`off`..`trace`, default `info`), or as `RUST_LOG` says when it is set, stamped with virtual time.

use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use afklink_core::logging::{env_filter_override, LogLevel};
use afklink_sim::clock::VirtualTimer;
use afklink_sim::report;
use afklink_sim::scenario::collect;
use tracing_subscriber::EnvFilter;

struct Args {
    inputs: Vec<PathBuf>,
    out: PathBuf,
    level: LogLevel,
    /// `--profile`: `builtin`, `reference` (the default) or a profile file.
    profile: String,
}

fn usage() -> String {
    "usage: afklink-sim <scenario.toml | dir> [more ...] [--out DIR] [--profile builtin|reference|<file.json>] [--log-level off|error|warn|info|debug|trace]"
        .to_string()
}

fn parse_args() -> Result<Args, String> {
    let mut inputs = Vec::new();
    let mut out = PathBuf::from("target").join("sim");
    let mut level = LogLevel::Info;
    let mut profile = "reference".to_string();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = PathBuf::from(it.next().ok_or_else(usage)?),
            "--profile" => profile = it.next().ok_or_else(usage)?,
            "--log-level" => {
                let v = it.next().ok_or_else(usage)?;
                level = LogLevel::from_str(&v).map_err(|e| e.to_string())?;
            }
            "-h" | "--help" => return Err(usage()),
            _ if a.starts_with("--") => return Err(format!("unknown option {a}\n{}", usage())),
            _ => inputs.push(PathBuf::from(a)),
        }
    }
    if inputs.is_empty() {
        return Err(usage());
    }
    Ok(Args {
        inputs,
        out,
        level,
        profile,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let filter = env_filter_override().map_or_else(|| args.level.filter(), EnvFilter::new);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_timer(VirtualTimer)
        .with_writer(std::io::stderr)
        .init();

    let mut files = Vec::new();
    for input in &args.inputs {
        match collect(input) {
            Ok(mut f) => files.append(&mut f),
            Err(e) => {
                eprintln!("{e:#}");
                return ExitCode::from(2);
            }
        }
    }
    if let Err(e) = std::fs::create_dir_all(&args.out) {
        eprintln!("create {}: {e}", args.out.display());
        return ExitCode::from(2);
    }
    let (profile_label, policy) = match afklink_sim::profile_from_arg(&args.profile) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("--profile {}: {e:#}", args.profile);
            return ExitCode::from(2);
        }
    };
    tracing::info!(profile = %profile_label, "quality profile for every scenario");
    println!("profile {profile_label}");

    let mut summaries = Vec::new();
    let mut failed = 0usize;
    for file in &files {
        tracing::info!(scenario = %file.display(), "running");
        match afklink_sim::run_file_with(file, policy.clone()) {
            Ok(run) => {
                let path = args.out.join(format!("{}.log", run.summary.name));
                let mut text = run.log.join("\n");
                text.push('\n');
                match std::fs::write(&path, text) {
                    Ok(()) => println!(
                        "{}  (log: {})",
                        report::detail(&run.summary),
                        path.display()
                    ),
                    Err(e) => {
                        eprintln!("write {}: {e}", path.display());
                        println!("{}", report::detail(&run.summary));
                    }
                }
                summaries.push(run.summary);
            }
            Err(e) => {
                failed += 1;
                eprintln!("{}: {e:#}", file.display());
            }
        }
    }
    if !summaries.is_empty() {
        println!("\n{}", report::table(&summaries));
    }
    if failed > 0 {
        eprintln!("{failed} scenario(s) failed");
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
