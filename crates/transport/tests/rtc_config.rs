//! Every agent peer's str0m configuration holds the viewer's DTLS certificate to its offer's
//! fingerprint (device keys protocol §3.6): the fingerprint the viewer's device key signs is only
//! worth its signature if the handshake is refused for any other certificate.
//!
//! Two halves: [`peer_rtc_config`] has `fingerprint_verification` on, with and without the ICE
//! schedule override; and it is the only place the agent's product sources build an `Rtc`, so the
//! first half covers every peer. That a peer from this configuration does refuse another
//! certificate in a real handshake is `afklink-core`'s `tests/dtls_fingerprint.rs`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use afklink_transport::webrtc::{peer_rtc_config, IceTiming};

#[test]
fn every_peer_config_verifies_the_dtls_fingerprint() {
    assert!(
        peer_rtc_config(None).fingerprint_verification(),
        "production peers (no ICE override)"
    );
    let timing = IceTiming {
        initial_rto: Duration::from_millis(50),
        max_rto: Duration::from_millis(200),
        retransmits: 3,
    };
    assert!(
        peer_rtc_config(Some(timing)).fingerprint_verification(),
        "peers with the ICE schedule overridden"
    );
}

/// Ways to make an `Rtc` or its configuration other than [`peer_rtc_config`], and the one way to
/// turn the check off.
const CONSTRUCTIONS: [&str; 5] = [
    "Rtc::builder(",
    "Rtc::new(",
    "RtcConfig::new(",
    "RtcConfig::default(",
    "set_fingerprint_verification(false",
];

/// Outside tests, the agent's sources make an `Rtc` in exactly one place: [`peer_rtc_config`].
/// A second construction site would be a peer this file's first test says nothing about.
///
/// Scanned: every crate under `crates/` and the desktop app. Left out: `crates/sim`, the
/// session simulator, whose viewer and sender are str0m peers inside one process that never meet a
/// real viewer (its `sender_config` mirrors the agent's for the model, not for a session). Test
/// code is skipped: `tests/` directories, files named `tests.rs`, and a file's top-level
/// `#[cfg(test)] mod …` to its end (the convention every file here follows).
#[test]
fn the_peer_config_is_the_only_rtc_construction_in_the_product() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root.join("crates")).expect("crates/") {
        let dir = entry.expect("a crates/ entry").path();
        if dir.file_name().is_some_and(|n| n == "sim") {
            continue;
        }
        rust_files(&dir, &mut files);
    }
    rust_files(&root.join("app/src-tauri/src"), &mut files);
    assert!(
        files.len() > 50,
        "the scan found {} files: wrong root?",
        files.len()
    );

    let mut sites = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file)
            .expect("a source file")
            .replace("\r\n", "\n");
        let lines: Vec<&str> = text.lines().collect();
        let product_end = lines
            .windows(2)
            .position(|w| w[0] == "#[cfg(test)]" && w[1].starts_with("mod "))
            .unwrap_or(lines.len());
        for (i, line) in lines[..product_end].iter().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if CONSTRUCTIONS.iter().any(|c| code.contains(c)) {
                // The function the line is in: the nearest `fn` above it.
                let within = lines[..i]
                    .iter()
                    .rev()
                    .find(|l| l.starts_with("fn ") || l.starts_with("pub fn "))
                    .map(|l| l.trim().to_string())
                    .unwrap_or_default();
                sites.push(format!(
                    "{}:{}: {} (in `{within}`)",
                    file.strip_prefix(&root)
                        .unwrap_or(file)
                        .display()
                        .to_string()
                        .replace('\\', "/"),
                    i + 1,
                    line.trim()
                ));
            }
        }
    }
    assert_eq!(
        sites.len(),
        1,
        "exactly one Rtc construction outside tests, in peer_rtc_config: {sites:#?}"
    );
    assert!(
        sites[0].starts_with("crates/transport/src/webrtc.rs:")
            && sites[0].contains("Rtc::builder()")
            && sites[0].contains("in `pub fn peer_rtc_config("),
        "the one construction is peer_rtc_config's: {sites:#?}"
    );
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("a directory entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if matches!(
                name,
                "tests" | "target" | "node_modules" | "benches" | "examples"
            ) {
                continue;
            }
            rust_files(&path, out);
        } else if name.ends_with(".rs") && name != "tests.rs" {
            out.push(path);
        }
    }
}
