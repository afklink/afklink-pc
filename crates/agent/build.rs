//! Hands the build stamp (`afklink_core::build_info`) to the binary.
//!
//! `bun run portable`, `bun run release:build` and `bun scripts/release-build.ts` stamp the desktop
//! app only; a CLI build gets a
//! stamp — the release channel included — when the same variables are set by hand, and says «dev»
//! otherwise. Each variable is re-read whenever it changes, and forwarded empty when unset — so a
//! build without a stamp never keeps the previous one.

/// The stamp's variables: `afklink_core::build_info::STAMP_VARS`, and the desktop app's build
/// script forwards the same four.
const STAMP_VARS: [&str; 4] = [
    "AFKLINK_BUILD_COMMIT",
    "AFKLINK_BUILD_DIRTY",
    "AFKLINK_BUILD_TIME",
    "AFKLINK_BUILD_CHANNEL",
];

#[allow(
    clippy::panic,
    reason = "a build script fails the build by panicking; the message is the whole diagnosis"
)]
fn main() {
    for var in STAMP_VARS {
        println!("cargo:rerun-if-env-changed={var}");
        let value = std::env::var_os(var)
            .map(|v| v.to_string_lossy().into_owned())
            .unwrap_or_default();
        // A line break would end the directive below and start another one.
        if value.contains(['\n', '\r']) {
            panic!("{var} contains a line break: {value:?}");
        }
        println!("cargo:rustc-env={var}={value}");
    }
}
