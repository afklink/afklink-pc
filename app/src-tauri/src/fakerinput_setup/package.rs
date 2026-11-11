//! The embedded FakerInput installer and its unpacked copy.
//!
//! msiexec needs a file path, and the user's temp directory is writable by any process running as
//! the owner — so the copy that goes under the owner's UAC prompt must provably be ours. The copy is
//! a [`StagedFile`] (`crate::staged_file`): written into a directory created fresh for this
//! operation, with `CREATE_NEW`, then reopened **read-only, sharing read only**, and hashed again
//! through that handle. From then on nobody can write, replace, rename or delete the file until the
//! handle closes, and what the hash saw is what msiexec reads. The handle stays open until msiexec
//! has exited; dropping [`StagedPackage`] closes it and removes the file and the directory — each
//! named, never recursively.

use std::path::Path;

use super::pinned::{PACKAGE_FILE_NAME, PACKAGE_SHA256};
use crate::staged_file::StagedFile;

/// The official installer, exactly the file `build.rs` checked against [`PACKAGE_SHA256`].
pub(super) static PACKAGE: &[u8] = include_bytes!(env!("AFKLINK_FAKERINPUT_MSI"));

/// The per-operation directory under the temp folder: this prefix and a fresh v4 UUID.
const STAGING_DIR_PREFIX: &str = "AFKLink-FakerInput-";

/// What the log calls this file.
const LABEL: &str = "FakerInput installer";

/// The unpacked, verified installer, held read-only until dropped.
pub(super) struct StagedPackage(StagedFile);

impl StagedPackage {
    /// Unpack the embedded installer into a new directory under the user's temp folder.
    pub(super) fn unpack() -> Result<Self, String> {
        Self::stage_in(&std::env::temp_dir(), PACKAGE, PACKAGE_SHA256)
    }

    /// Write `bytes` into a new directory under `parent`, reopen the file read-only and check it
    /// against `expected_sha256` through that handle. On any failure whatever was created is removed
    /// before the error returns.
    pub(super) fn stage_in(
        parent: &Path,
        bytes: &[u8],
        expected_sha256: &str,
    ) -> Result<Self, String> {
        StagedFile::stage_in(
            parent,
            STAGING_DIR_PREFIX,
            PACKAGE_FILE_NAME,
            bytes,
            expected_sha256,
            LABEL,
            "refusing to start Windows Installer",
        )
        .map(Self)
    }

    /// The verified package, for `msiexec /i`.
    pub(super) fn path(&self) -> &Path {
        self.0.path()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::path::PathBuf;

    use super::*;
    use crate::staged_file::sha256_upper_hex;

    /// A fresh parent directory per test, so what a test leaves behind is visible to it alone.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "afklink-app-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn entries(dir: &Path) -> usize {
        std::fs::read_dir(dir).unwrap().count()
    }

    #[test]
    fn the_embedded_package_is_the_pinned_one() {
        let (hash, len) = sha256_upper_hex(PACKAGE).unwrap();
        assert_eq!(hash, PACKAGE_SHA256);
        assert_eq!(len, PACKAGE.len() as u64);
    }

    #[test]
    fn unpacking_writes_the_verified_file_and_removes_it_afterwards() {
        let parent = scratch("stage");
        let staged = StagedPackage::stage_in(&parent, PACKAGE, PACKAGE_SHA256).unwrap();
        let path = staged.path().to_path_buf();
        let dir = path.parent().unwrap().to_path_buf();
        assert_eq!(dir.parent().unwrap(), parent);
        assert!(dir
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(STAGING_DIR_PREFIX));
        assert_eq!(path.file_name().unwrap(), PACKAGE_FILE_NAME);

        // Readable by others (msiexec), with exactly the pinned bytes.
        let (hash, _) = sha256_upper_hex(File::open(&path).unwrap()).unwrap();
        assert_eq!(hash, PACKAGE_SHA256);

        drop(staged);
        assert!(!path.exists(), "the unpacked copy must be removed");
        assert!(!dir.exists(), "the staging directory must be removed");
        assert_eq!(entries(&parent), 0);
        std::fs::remove_dir(&parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn while_held_nobody_can_write_replace_or_delete_the_copy() {
        const ERROR_SHARING_VIOLATION: i32 = 32;
        let parent = scratch("hold");
        let staged = StagedPackage::stage_in(&parent, PACKAGE, PACKAGE_SHA256).unwrap();
        let path = staged.path().to_path_buf();

        let write = OpenOptions::new().write(true).open(&path).unwrap_err();
        assert_eq!(
            write.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION),
            "{write}"
        );
        let delete = std::fs::remove_file(&path).unwrap_err();
        assert_eq!(
            delete.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION),
            "{delete}"
        );
        let rename = std::fs::rename(&path, parent.join("swapped.msi")).unwrap_err();
        assert_eq!(
            rename.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION),
            "{rename}"
        );

        drop(staged);
        assert_eq!(entries(&parent), 0);
        std::fs::remove_dir(&parent).unwrap();
    }

    #[test]
    fn a_copy_that_does_not_match_the_pin_is_refused_and_cleaned_up() {
        let parent = scratch("mismatch");
        let error = StagedPackage::stage_in(&parent, b"not the installer", PACKAGE_SHA256)
            .err()
            .unwrap();
        assert!(
            error.contains("refusing to start Windows Installer"),
            "{error}"
        );
        assert_eq!(entries(&parent), 0, "nothing may be left behind");
        std::fs::remove_dir(&parent).unwrap();
    }
}
