//! Tauri's code generation, the game helper built and embedded in the app, the pin on the
//! FakerInput installer embedded in the app, the build's stamp (`afklink_core::build_info`) that
//! `bun run portable`, `bun run release:build` and `bun scripts/release-build.ts` pass in, the
//! application manifest for the
//! integration tests, the exe's DLL search limited to System32, and the refusal of a test-key
//! (`updater-test-key`) release-channel build (`build_test_key.rs`).
//!
//! The version is not handled here: it is the workspace's (`agent/Cargo.toml`), which the crate
//! reads as `CARGO_PKG_VERSION`, and `tauri.conf.json` has no `version`, so Tauri takes the same
//! one — for `PackageInfo` (tauri-codegen) and for the exe's FileVersion/ProductVersion resource
//! (tauri-winres reads `CARGO_PKG_VERSION`).

use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// The game helper's profile from OUT_DIR; tested in `tests/build_profile.rs`.
mod build_profile;
/// The refusal of a test-key build where a release is built; tested in `tests/build_test_key.rs`.
mod build_test_key;

/// The package's name and hash, written once: the app uses the same file as a module.
#[allow(
    dead_code,
    reason = "the build script checks only the file; the app uses the codes and the version"
)]
mod pinned {
    include!("src/fakerinput_setup/pinned.rs");
}

/// Where the vendored package lives, relative to this crate.
const PACKAGE_DIR: &str = "resources/fakerinput";

/// The environment variable that hands the verified package's path to `include_bytes!`.
const PACKAGE_PATH_ENV: &str = "AFKLINK_FAKERINPUT_MSI";

/// The stamp's variables: `afklink_core::build_info::STAMP_VARS`, set by
/// `agent/scripts/portable.ts`, `agent/scripts/official-build.ts` and
/// `agent/scripts/release-build.ts`; the CLI's build script forwards the same four.
const STAMP_VARS: [&str; 4] = [
    "AFKLINK_BUILD_COMMIT",
    "AFKLINK_BUILD_DIRTY",
    "AFKLINK_BUILD_TIME",
    "AFKLINK_BUILD_CHANNEL",
];

fn main() {
    refuse_test_key_release();
    embed_game_helper();
    verify_fakerinput_package();
    forward_build_stamp();
    embed_integration_test_manifest();
    limit_static_import_search();
    tauri_build::build();
}

/// Refuse a release-channel build with the feature `updater-test-key` (`build_test_key::refusal`):
/// a release never trusts the TEST signing key. Only the test PC's rollback build, marked by
/// `build_test_key::ACK_VAR`, is let through, and never in CI (`build_test_key::CI_VARS`). The
/// feature itself reruns this script when it changes (cargo passes `CARGO_FEATURE_*` anew); every
/// variable read is declared. The CI variables are read as `OsString`: one that is not UTF-8 is
/// still set.
#[allow(
    clippy::panic,
    reason = "a build script fails the build by panicking; the message is the whole diagnosis"
)]
fn refuse_test_key_release() {
    for var in build_test_key::CI_VARS {
        println!("cargo:rerun-if-env-changed={var}");
    }
    println!("cargo:rerun-if-env-changed=AFKLINK_BUILD_CHANNEL");
    println!("cargo:rerun-if-env-changed={}", build_test_key::ACK_VAR);
    let feature = std::env::var_os("CARGO_FEATURE_UPDATER_TEST_KEY").is_some();
    let ci_values: Vec<(&str, Option<std::ffi::OsString>)> = build_test_key::CI_VARS
        .iter()
        .map(|&var| (var, std::env::var_os(var)))
        .collect();
    let ci_refs: Vec<(&str, Option<&std::ffi::OsStr>)> = ci_values
        .iter()
        .map(|(var, value)| (*var, value.as_deref()))
        .collect();
    let ci = build_test_key::ci_marker(&ci_refs);
    let channel = std::env::var("AFKLINK_BUILD_CHANNEL").ok();
    let acknowledged = std::env::var(build_test_key::ACK_VAR).ok();
    if let Some(why) =
        build_test_key::refusal(feature, ci, channel.as_deref(), acknowledged.as_deref())
    {
        panic!("{why}");
    }
    // The test build's deliberate breakage (`src/test_break.rs`, read there with `option_env!`):
    // declared so a change rebuilds; compiled in only with the feature.
    println!("cargo:rerun-if-env-changed=AFKLINK_TEST_BREAK_SERVER_URL");
    let broken = std::env::var("AFKLINK_TEST_BREAK_SERVER_URL").unwrap_or_default();
    if broken.contains(['\n', '\r']) {
        panic!("AFKLINK_TEST_BREAK_SERVER_URL contains a line break: {broken:?}");
    }
    if feature {
        // Into the build script's output file: which key this build embeds.
        println!("updater: TEST signing key build (feature updater-test-key): embeds updater-test.pub, not updater.pub");
        if !broken.trim().is_empty() {
            println!("test build: the signaling socket is broken to {broken}");
        }
    } else if !broken.trim().is_empty() {
        println!(
            "cargo:warning=AFKLINK_TEST_BREAK_SERVER_URL is set but ignored: only a test-key build \
             (feature updater-test-key) has that path at all"
        );
    }
}

/// `/DEPENDENTLOADFLAG:0x800` (`LOAD_LIBRARY_SEARCH_SYSTEM32`) on the app's exe alone: Windows
/// resolves its static imports from System32 only, not from the folder it lies in. The exe is
/// portable — kept in a folder its owner (and so any of their programs) can write to — and the game
/// helper's setup runs this same exe elevated (`game_helper::system::elevate`): without the flag a
/// DLL named like one of its imports and put beside it would load into an elevated process. Its
/// loads by name are limited at run time (`SetDefaultDllDirectories`, `game_helper::early`).
/// <https://learn.microsoft.com/en-us/cpp/build/reference/dependentloadflag> — honoured from
/// Windows 10 1607; `dumpbin /loadconfig` shows it as «Dependent Load Flag».
///
/// Only when the C runtime is linked in statically — `STATIC_VCRUNTIME=true`, which
/// `cargo tauri build` sets (portable and release builds; tauri-build then links `libvcruntime` and
/// `libcmt`). Then every import is a Windows DLL in System32 or an API set (`api-ms-win-*`, the
/// UCRT's among them): checked with `dumpbin /dependents`. A plain `cargo build` imports
/// `VCRUNTIME140.dll`, which only the Visual C++ Redistributable puts in System32: with the flag,
/// such a build would not start on a PC without it — so it goes without.
fn limit_static_import_search() {
    println!("cargo:rerun-if-env-changed=STATIC_VCRUNTIME");
    let msvc = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    let static_vcruntime = std::env::var_os("STATIC_VCRUNTIME").is_some_and(|v| v == "true");
    if msvc && static_vcruntime {
        println!("cargo:rustc-link-arg-bin=afklink-app=/DEPENDENTLOADFLAG:0x800");
    }
}

/// Build the game helper (`crates/game-helper`) and embed it in the app, with its SHA-256: the
/// setup installs exactly these bytes, and the app tells an installed helper of another build by
/// the hash in its record. An isolated target directory avoids the parent Cargo build's lock,
/// including for plain cargo test/build. Linked with `/Brepro` (no link-time stamp in the exe), so
/// the same source makes the same bytes and an app update that does not change the helper does not
/// offer the owner a new one. Its C runtime is linked in (`+crt-static`): the helper runs on PCs
/// without the Visual C++ Redistributable, and imports Windows DLLs only.
#[allow(
    clippy::panic,
    reason = "a build script fails the build by panicking; the message is the whole diagnosis"
)]
fn embed_game_helper() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let crate_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let helper = crate_dir.join("../../crates/game-helper");
    println!("cargo:rerun-if-changed={}", helper.display());
    println!("cargo:rerun-if-changed=../../Cargo.lock");
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let target_dir = out_dir.join("game-helper-build");
    let target = std::env::var("TARGET").expect("TARGET");
    // The app's own profile, read from OUT_DIR: `dist` for a shipping build, else `release`.
    let profile = build_profile::helper_profile(&out_dir);
    println!(
        "game helper: profile {profile} (from OUT_DIR {})",
        out_dir.display()
    );
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    let mut build = std::process::Command::new(std::env::var_os("CARGO").expect("CARGO"));
    build
        .args([
            "build",
            "--locked",
            "--profile",
            profile,
            "--bin",
            "afklink-game-helper",
            "--manifest-path",
        ])
        .arg(helper.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("--target")
        .arg(&target)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        // `cargo clippy`'s wrapper: the helper is built the same whatever command built the app.
        .env_remove("RUSTC_WORKSPACE_WRAPPER");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // The app's own path remaps (`--remap-path-prefix`, set by scripts/lib/paths.ts for portable
        // and release builds) go to the helper too: its flags replace the app's, and without them
        // its exe would name the build machine's CARGO_HOME in every dependency's panic location.
        let mut flags = vec![
            "-Clink-arg=/Brepro".to_string(),
            "-Ctarget-feature=+crt-static".to_string(),
        ];
        let parent = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
        let remaps: Vec<&str> = parent
            .split('\u{1f}')
            .filter(|f| f.starts_with("--remap-path-prefix="))
            .collect();
        // Into the build script's own output file (target/…/build/afklink-app-*/output), not a
        // cargo warning on every build.
        println!(
            "game helper: {} path remap(s) forwarded from the app's rustflags",
            remaps.len()
        );
        flags.extend(remaps.iter().map(|f| (*f).to_string()));
        // Flags separated by 0x1f, as Cargo reads this variable.
        build.env("CARGO_ENCODED_RUSTFLAGS", flags.join("\u{1f}"));
    }
    let status = build.status().expect("build game helper");
    assert!(status.success(), "game helper build failed");
    let exe = target_dir
        .join(target)
        .join(profile)
        .join("afklink-game-helper.exe");
    let bytes = match std::fs::read(&exe) {
        Ok(bytes) => bytes,
        Err(e) => panic!("the built game helper {} not read: {e}", exe.display()),
    };
    println!("cargo:rustc-env=AFKLINK_GAME_HELPER_EXE={}", exe.display());
    println!(
        "cargo:rustc-env=AFKLINK_GAME_HELPER_SHA256={}",
        upper_hex(&Sha256::digest(&bytes)).to_lowercase()
    );
}

/// Tauri's application manifest (tauri-build's `windows-app-manifest.xml`): Common Controls 6,
/// whose `TaskDialogIndirect` the Tauri runtime imports.
const COMMON_CONTROLS_MANIFEST: &str = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*" />
    </dependentAssembly>
  </dependency>
</assembly>
"#;

/// The same manifest for the integration tests (`tests/`), which build a (mock) Tauri app: tauri-build
/// embeds it in the app's exe only (`rustc-link-arg-bins`), and without it Windows refuses to start a
/// test binary that links the runtime (`STATUS_ENTRYPOINT_NOT_FOUND`, comctl32 v5 has no
/// `TaskDialogIndirect`). `rustc-link-arg-tests` reaches the integration tests alone: the app's exe
/// and the library's unit tests are linked exactly as before.
#[allow(
    clippy::panic,
    reason = "a build script fails the build by panicking; the message is the whole diagnosis"
)]
fn embed_integration_test_manifest() {
    let windows_msvc = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if !windows_msvc {
        return;
    }
    let Some(out) = std::env::var_os("OUT_DIR").map(PathBuf::from) else {
        panic!("OUT_DIR is not set; build afklink-app with cargo");
    };
    let path = out.join("integration-tests.manifest");
    if let Err(e) = std::fs::write(&path, COMMON_CONTROLS_MANIFEST) {
        panic!("{} not written: {e}", path.display());
    }
    println!("cargo:rustc-link-arg-tests=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-tests=/MANIFESTINPUT:{}",
        path.display()
    );
}

/// Hand each stamp variable to the crate, empty when unset, and rebuild whenever one changes — so a
/// build without a stamp never keeps the previous build's. Why the stamp comes from the environment
/// rather than from git here: `afklink_core::build_info`.
#[allow(
    clippy::panic,
    reason = "a build script fails the build by panicking; the message is the whole diagnosis"
)]
fn forward_build_stamp() {
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

/// Refuse to build unless the vendored MSI is byte-for-byte the pinned one, then tell the crate
/// where it is: the app embeds exactly the file checked here.
#[allow(
    clippy::panic,
    reason = "a build script fails the build by panicking; the message is the whole diagnosis"
)]
fn verify_fakerinput_package() {
    let relative = format!("{PACKAGE_DIR}/{}", pinned::PACKAGE_FILE_NAME);
    println!("cargo:rerun-if-changed={relative}");
    println!("cargo:rerun-if-changed=src/fakerinput_setup/pinned.rs");

    let manifest_dir = match std::env::var_os("CARGO_MANIFEST_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => panic!("CARGO_MANIFEST_DIR is not set; build afklink-app with cargo"),
    };
    // Component by component, so the path handed to `include_bytes!` uses the native separator.
    let path = PACKAGE_DIR
        .split('/')
        .fold(manifest_dir, |dir, part| dir.join(part))
        .join(pinned::PACKAGE_FILE_NAME);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => panic!(
            "the FakerInput installer embedded in afklink-app is missing: {} ({e}). It is \
             vendored in the repository (resources/fakerinput, `*.msi binary`); restore it from git",
            path.display()
        ),
    };
    let actual = upper_hex(&Sha256::digest(&bytes));
    if actual != pinned::PACKAGE_SHA256 {
        panic!(
            "the FakerInput installer {} does not match its pin: SHA-256 {actual} ({} bytes), \
             expected {}. If the package was updated on purpose, update \
             src/fakerinput_setup/pinned.rs (hash, version, ProductCode, UpgradeCode) and run \
             `cargo test -p afklink-app`; otherwise restore the file from git (a checkout that \
             converted line endings in a binary file also looks like this)",
            path.display(),
            bytes.len(),
            pinned::PACKAGE_SHA256,
        );
    }
    println!("cargo:rustc-env={PACKAGE_PATH_ENV}={}", path.display());
}

fn upper_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02X}");
        out
    })
}
