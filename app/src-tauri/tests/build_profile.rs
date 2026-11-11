//! The build script's choice of the game helper's profile (`build_profile.rs`), over the shapes of
//! `OUT_DIR` cargo produces.

#[path = "../build_profile.rs"]
mod build_profile;

use build_profile::helper_profile;
use std::path::Path;

#[test]
fn a_dist_build_builds_the_helper_with_dist() {
    let shapes = [
        // The default target dir, no --target.
        r"C:\work\agent\target\dist\build\afklink-app-1ff1eba636a81b33\out",
        // With --target: one more level, the profile still three up from `out`.
        r"C:\work\agent\target\x86_64-pc-windows-msvc\dist\build\afklink-app-0123\out",
        // A custom CARGO_TARGET_DIR.
        r"C:\Users\user\AppData\Local\Temp\agpA\dist\build\afklink-app-1ff1eba636a81b33\out",
        "/tmp/t/dist/build/afklink-app-1/out",
    ];
    for shape in shapes {
        assert_eq!(helper_profile(Path::new(shape)), "dist", "{shape}");
    }
}

#[test]
fn anything_else_builds_the_helper_with_release() {
    let shapes = [
        r"C:\work\agent\target\release\build\afklink-app-1ff1eba636a81b33\out",
        r"C:\work\agent\target\debug\build\afklink-app-1ff1eba636a81b33\out",
        r"C:\work\agent\target\x86_64-pc-windows-msvc\release\build\afklink-app-0123\out",
        // A target dir that is itself called `dist` does not count: only the profile's level.
        r"C:\dist\release\build\afklink-app-1\out",
        r"C:\work\target\bench\build\afklink-app-1\out",
        // Too short to have a profile level at all.
        r"out",
        "",
    ];
    for shape in shapes {
        assert_eq!(helper_profile(Path::new(shape)), "release", "{shape}");
    }
}
