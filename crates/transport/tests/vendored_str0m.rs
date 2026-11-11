//! The vendored str0m (`vendor/str0m`, the str0m this transport runs on) is the crates.io package
//! byte for byte except the files our patch changes: every file's SHA-256 (raw bytes) must be the
//! one `vendor/str0m.sha256` pins, no file may be missing and none added. The manifest is written
//! from the crates.io archive by `vendor/str0m-manifest.ps1`, with the patched files pinned to
//! their vendored bytes, so an intended change to them updates the pin on purpose
//! (vendor/VENDORED.md).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

fn vendor_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor")
}

/// Every file under `dir`, by its path relative to `root` with `/` separators.
fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
    for entry in std::fs::read_dir(dir).expect("read a vendored directory") {
        let path = entry.expect("directory entry").path();
        // A build of the vendored crate run without `--target-dir` (it is its own workspace
        // root) lands in `vendor/str0m/target`: build output, not part of the copy. Only that
        // top-level directory is skipped; any other extra file fails below.
        if dir == root && path.is_dir() && path.file_name().is_some_and(|n| n == "target") {
            continue;
        }
        if path.is_dir() {
            walk(root, &path, out);
            continue;
        }
        let bytes = std::fs::read(&path).expect("read a vendored file");
        let mut hex = String::with_capacity(64);
        for b in Sha256::digest(&bytes) {
            let _ = write!(hex, "{b:02x}");
        }
        let rel = path
            .strip_prefix(root)
            .expect("under the vendored root")
            .to_string_lossy()
            .replace('\\', "/");
        out.insert(rel, hex);
    }
}

#[test]
fn the_vendored_str0m_is_the_published_crate_plus_our_patch() {
    let vendor = vendor_dir();
    let manifest_path = vendor.join("str0m.sha256");
    let manifest = std::fs::read_to_string(&manifest_path).expect("read vendor/str0m.sha256");
    let mut want = BTreeMap::new();
    for line in manifest.lines().filter(|l| !l.is_empty()) {
        let (hash, path) = line
            .split_once("  ")
            .expect("manifest lines are `<sha256>  <path>`");
        want.insert(path.to_string(), hash.to_string());
    }

    let root = vendor.join("str0m");
    let mut got = BTreeMap::new();
    walk(&root, &root, &mut got);

    let mut drift = Vec::new();
    for (path, hash) in &want {
        match got.get(path) {
            None => drift.push(format!("missing  {path}")),
            Some(h) if h != hash => drift.push(format!("changed  {path} ({h}, pinned {hash})")),
            Some(_) => {}
        }
    }
    for path in got.keys().filter(|p| !want.contains_key(*p)) {
        drift.push(format!("added    {path}"));
    }
    assert!(
        drift.is_empty(),
        "vendor/str0m differs from vendor/str0m.sha256 ({} of {} files):\n{}\n\
         An intended change to a patched file: rerun `pwsh -NoProfile -File \
         vendor/str0m-manifest.ps1` and commit the manifest with it (vendor/VENDORED.md).",
        drift.len(),
        want.len(),
        drift.join("\n")
    );
    assert!(want.len() > 200, "the manifest lists the whole package");
}
