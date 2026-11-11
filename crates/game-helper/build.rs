//! The helper's version resource: Task Manager names the background process by its
//! FileDescription, «AFKLink Game Helper», rather than by the bare file name, and its properties
//! say whose it is — ProductName and CompanyName «AFKLink», as the app's own exe has them from
//! `tauri.conf.json`. FileVersion and ProductVersion are the workspace's version, as the app's
//! (`tauri-winres` reads `CARGO_PKG_VERSION`).
//!
//! The same tool as the app's resource (`tauri-build` → `tauri-winres` → `embed-resource`, which
//! finds `rc.exe` in the Windows SDK), linked into the helper's exe only. The app's build script
//! builds this crate on its own with `/Brepro` and embeds the exe (`app/src-tauri/build.rs`): the
//! resource adds no time stamp, so the same source still makes the same bytes.

/// What the resource says. The exe's name is `afklink_game_helper::EXE_NAME`'s.
const STRINGS: [(&str, &str); 6] = [
    ("FileDescription", "AFKLink Game Helper"),
    ("ProductName", "AFKLink"),
    ("CompanyName", "AFKLink"),
    ("LegalCopyright", "© 2026 AFKLink"),
    ("OriginalFilename", "afklink-game-helper.exe"),
    ("InternalName", "afklink-game-helper"),
];

#[allow(
    clippy::panic,
    reason = "a build script fails the build by panicking; the message is the whole diagnosis"
)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut resource = tauri_winres::WindowsResource::new();
    for (name, value) in STRINGS {
        resource.set(name, value);
    }
    // `tauri-winres` panics itself when `rc.exe` fails; an error here is the `.rc` not written.
    if let Err(e) = resource.compile_for(&["afklink-game-helper"]) {
        panic!("the game helper's version resource not compiled: {e}");
    }
}
