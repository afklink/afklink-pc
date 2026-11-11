// The FakerInput driver package embedded in `afklink-app.exe`, and the identity it is held to.
//
// One place for all of it: the app uses this file as the module `fakerinput_setup::pinned`, and
// `build.rs` `include!`s the same file to check the package before it is embedded. Plain `//`
// comments up here, because an inner doc comment cannot be `include!`d.

/// The official FakerInput installer, vendored as `app/src-tauri/resources/fakerinput/<this name>`
/// next to upstream's `LICENSE` (MIT) and embedded into the app with `include_bytes!`.
///
/// To update the package:
/// 1. put the new official MSI (Ryochan7/FakerInput releases) in `resources/fakerinput/`, delete
///    the old one, refresh `LICENSE` if upstream's changed; set this name and [`PACKAGE_VERSION`];
/// 2. set [`PACKAGE_SHA256`] (`Get-FileHash -Algorithm SHA256`): the build fails until it matches;
/// 3. set [`PRODUCT_CODE`] and [`UPGRADE_CODE`] from the package's `Property` table;
///    `cargo test -p afklink-app` opens the embedded package with the MSI API and fails if either
///    code or `ProductVersion` disagrees with these constants;
/// 4. check that the device is still created by a custom action conditioned on `NOT Installed` and
///    removed on `REMOVE="ALL"`: the `broken` state's «Переустановить» (`/x`, then `/i`) relies on
///    a repair or a second `/i` not recreating it.
pub const PACKAGE_FILE_NAME: &str = "FakerInput_Setup_0.1.1_x64.msi";

/// The package's `ProductVersion`.
pub const PACKAGE_VERSION: &str = "0.1.1";

/// SHA-256 of the package, upper-case hex. Checked by `build.rs` on the vendored file and, at run
/// time, on the unpacked copy through the read-only handle held while msiexec runs.
pub const PACKAGE_SHA256: &str = "4C0AEFB7340051A91D606776243298B5CD1143EF5508BBAE6800C474F9ED0840";

/// The package's `ProductCode`: what `MsiQueryProductStateW` asks about and `msiexec /x` removes.
pub const PRODUCT_CODE: &str = "{17AA3E01-1012-4BF7-B908-1C499909B259}";

/// The package's `UpgradeCode`, shared by every FakerInput version: other versions (another
/// program, e.g. DS4Windows, may have installed one) are found by it with `MsiEnumRelatedProductsW`.
pub const UPGRADE_CODE: &str = "{BF63C434-BF91-4666-B817-AD7B5C249E91}";
