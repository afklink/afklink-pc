//! Print the quality ladder for a given source resolution.
//!
//! The ladder is derived, not written down: RustDesk's resolution→bitrate table, scaled by pixel
//! count to whatever the source actually is, then by frame rate and the quality multiplier. That
//! makes it correct for odd panels — a 3:2 laptop, an ultrawide — but it also means nobody can
//! read the table and know what the agent will do. This prints it.
//!
//!   cargo run --release --example ladder -p afklink-core -- 3600 2400 [--profile <file.json> | --profile builtin]
//!
//! The profile is the contract's reference vector (the server's tuned `default`), read at run time,
//! unless `--profile` names a profile file or `builtin` (this build's compiled fallback).

use std::path::{Path, PathBuf};

use afklink_core::quality::{base_bitrate_kbps, Quality};
use afklink_core::quality_policy::{load_profile_file, QualityPolicy, REFERENCE_VECTOR};

fn main() {
    let mut numbers = Vec::new();
    let mut profile: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--profile" {
            profile = args.next();
        } else {
            numbers.push(a);
        }
    }
    let w: u32 = numbers.first().and_then(|a| a.parse().ok()).unwrap_or(3600);
    let h: u32 = numbers.get(1).and_then(|a| a.parse().ok()).unwrap_or(2400);

    let (label, policy) = match profile.as_deref() {
        Some("builtin") => (
            "builtin (this build's fallback)".to_string(),
            QualityPolicy::fallback(),
        ),
        other => {
            let path = other.map_or_else(
                || {
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../..")
                        .join(REFERENCE_VECTOR)
                },
                PathBuf::from,
            );
            match load_profile_file(&path) {
                Ok(p) => (p.label(), p.policy),
                Err(e) => {
                    eprintln!("!! {e}");
                    std::process::exit(2);
                }
            }
        }
    };

    println!("source {w}x{h}, profile {label}\n");
    println!("  rung              encoded      fps    Low     Balanced   Best");
    for r in &policy.ladder {
        let (rw, rh) = r.size_for(w, h);
        println!(
            "  {:>4}p @ {:>2} fps   {:>4}x{:<4}   {:>3}   {:>4}    {:>4}       {:>4}  kbps",
            r.max_h,
            r.fps,
            rw,
            rh,
            r.fps,
            r.required_kbps_with(&policy, w, h, Quality::Low),
            r.required_kbps_with(&policy, w, h, Quality::Balanced),
            r.required_kbps_with(&policy, w, h, Quality::Best),
        );
    }

    println!("\nfor reference, what each encoded size is 'worth' at 30 fps (RustDesk's table):");
    for r in &policy.ladder {
        let (rw, rh) = r.size_for(w, h);
        println!("  {rw:>4}x{rh:<4}  {:>5} kbps", base_bitrate_kbps(rw, rh));
    }
}
