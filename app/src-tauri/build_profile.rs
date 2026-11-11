//! The cargo profile the game helper is built with, from the app's build script's `OUT_DIR`.
//!
//! Shared by `build.rs` and its test (`tests/build_profile.rs`): a build script has no tests of its
//! own.

use std::path::Path;

/// The profile directory sits three levels up from `OUT_DIR` —
/// `<target dir>/[<triple>/]<profile>/build/<package>-<hash>/out` — and names the profile (cargo's
/// `PROFILE` variable only says `release` or `debug`). A shipping build (`dist`, see
/// scripts/lib/common.ts) builds the helper with `dist` too; anything else with `release`.
pub fn helper_profile(out_dir: &Path) -> &'static str {
    match out_dir.ancestors().nth(3).and_then(|p| p.file_name()) {
        Some(name) if name == "dist" => "dist",
        _ => "release",
    }
}
