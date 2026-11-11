//! A file handed to another program — Windows Installer, or the exe swap of a self-update — that must
//! provably be the bytes this process checked.
//!
//! The folders such a file goes to (the user's temp folder, `%LOCALAPPDATA%`) are writable by any
//! process running as the owner. So the copy is written into a directory created fresh for this
//! operation (`create_dir` fails if the name exists), with `CREATE_NEW`, and closed; then reopened
//! **read-only, sharing read only**, and hashed again through that handle. From then on nobody can
//! write, replace, rename or delete the file until the handle closes, and what the hash saw is what
//! the other program reads. Dropping [`StagedFile`] closes the handle and removes the file and the
//! directory — each named, never recursively.
//!
//! Used by the embedded FakerInput installer (`fakerinput_setup::package`) and by the self-update
//! (`updater::apply`).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The staged, verified file, held read-only until dropped.
pub(crate) struct StagedFile {
    dir: PathBuf,
    path: PathBuf,
    /// For the log: «FakerInput installer», «update».
    label: &'static str,
    /// Whether `CREATE_NEW` made the file, i.e. whether it is ours to delete. A name someone else
    /// planted first is left alone (and so is the directory, which it keeps non-empty).
    file_created: bool,
    /// Opened read-only with `FILE_SHARE_READ` alone: others may read, nobody may write, rename or
    /// delete. `None` until verified, and while being dropped.
    reader: Option<File>,
}

impl StagedFile {
    /// Write `bytes` as `<parent>\<dir_prefix><fresh v4 UUID>\<file_name>`, reopen the file
    /// read-only and check it against `expected_sha256` (hex, either case) through that handle.
    /// `refusal` ends the mismatch error: what is not done because of it. On any failure whatever
    /// was created is removed before the error returns.
    pub(crate) fn stage_in(
        parent: &Path,
        dir_prefix: &str,
        file_name: &str,
        bytes: &[u8],
        expected_sha256: &str,
        label: &'static str,
        refusal: &str,
    ) -> Result<Self, String> {
        let dir = parent.join(format!("{dir_prefix}{}", uuid::Uuid::new_v4()));
        // Not `create_dir_all`: a directory that already exists is not ours.
        std::fs::create_dir(&dir).map_err(|e| {
            let error = format!("{label}: directory {} not created: {e}", dir.display());
            tracing::warn!("{error}");
            error
        })?;
        tracing::debug!(dir = %dir.display(), "{label}: staging directory created");
        let mut staged = Self {
            path: dir.join(file_name),
            dir,
            label,
            file_created: false,
            reader: None,
        };
        // On error `staged` drops here, which removes the file (if it was created) and the directory.
        staged.write_and_verify(bytes, expected_sha256, refusal)?;
        Ok(staged)
    }

    fn write_and_verify(
        &mut self,
        bytes: &[u8],
        expected_sha256: &str,
        refusal: &str,
    ) -> Result<(), String> {
        let path = self.path.clone();
        let label = self.label;
        let fail = |what: String| {
            tracing::warn!(path = %path.display(), "{label} not staged: {what}");
            what
        };
        {
            // CREATE_NEW: a file planted under this name between `create_dir` and now is refused.
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&self.path)
                .map_err(|e| fail(format!("create {}: {e}", self.path.display())))?;
            self.file_created = true;
            file.write_all(bytes)
                .and_then(|()| file.flush())
                .map_err(|e| fail(format!("write {}: {e}", self.path.display())))?;
        }
        tracing::debug!(
            path = %self.path.display(),
            bytes = bytes.len(),
            "{label}: written and closed; reopening read-only"
        );
        let mut reader = open_read_only_exclusive_writes(&self.path)
            .map_err(|e| fail(format!("reopen {} read-only: {e}", self.path.display())))?;
        let (actual, len) = sha256_upper_hex(&mut reader)
            .map_err(|e| fail(format!("read back {}: {e}", self.path.display())))?;
        // Held from here on, so the checked bytes are the ones the other program gets.
        self.reader = Some(reader);
        if !actual.eq_ignore_ascii_case(expected_sha256) {
            return Err(fail(format!(
                "SHA-256 of the staged copy is {actual} ({len} bytes), expected \
                 {expected_sha256}; {refusal}"
            )));
        }
        tracing::debug!(
            path = %self.path.display(),
            sha256 = %actual,
            bytes = len,
            "{label}: hash verified through the read-only handle, held until it is used"
        );
        Ok(())
    }

    /// The verified file.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagedFile {
    /// Close the handle, then remove the file and the directory — the two names this operation
    /// created, never a recursive delete. A failure is logged with the path, for the owner to delete.
    fn drop(&mut self) {
        let label = self.label;
        if let Some(reader) = self.reader.take() {
            drop(reader);
            tracing::debug!(path = %self.path.display(), "{label}: read-only handle closed");
        }
        if self.file_created {
            match std::fs::remove_file(&self.path) {
                Ok(()) => {
                    tracing::debug!(path = %self.path.display(), "{label}: staged copy removed")
                }
                Err(e) => tracing::warn!(
                    path = %self.path.display(),
                    "{label}: staged copy not removed: {e}"
                ),
            }
        } else {
            tracing::debug!(
                path = %self.path.display(),
                "{label}: no copy of ours to remove (staging stopped before it was created)"
            );
        }
        match std::fs::remove_dir(&self.dir) {
            Ok(()) => {
                tracing::debug!(dir = %self.dir.display(), "{label}: staging directory removed");
            }
            Err(e) => tracing::warn!(
                dir = %self.dir.display(),
                "{label}: staging directory not removed: {e}"
            ),
        }
    }
}

/// Open `path` for reading while denying everyone else write and delete access (and rename, which
/// needs delete): `FILE_SHARE_READ` alone.
#[cfg(windows)]
pub(crate) fn open_read_only_exclusive_writes(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
}

#[cfg(not(windows))]
pub(crate) fn open_read_only_exclusive_writes(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

/// SHA-256 of everything `reader` yields (from where it stands), upper-case hex, and the byte count.
pub(crate) fn sha256_upper_hex(mut reader: impl Read) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total += n as u64;
    }
    Ok((upper_hex(&hasher.finalize()), total))
}

/// SHA-256 of `bytes`, upper-case hex.
pub(crate) fn sha256_of(bytes: &[u8]) -> String {
    upper_hex(&Sha256::digest(bytes))
}

/// SHA-256 of the file at `path`, upper-case hex, and its length — read through a handle that
/// shares read and delete, as a running exe's image allows.
pub(crate) fn sha256_of_file(path: &Path) -> std::io::Result<(String, u64)> {
    sha256_upper_hex(File::open(path)?)
}

fn upper_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02X}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "AFKLink-test-";

    /// A fresh parent directory per test, so what a test leaves behind is visible to it alone.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "afklink-staged-{name}-{}-{}",
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
    fn a_staged_file_is_the_checked_bytes_and_goes_away_on_drop() {
        let parent = scratch("stage");
        let bytes = b"MZ an exe, as far as this test cares";
        let hash = sha256_of(bytes);
        // Lower case, as `release-build.ts` writes it into latest.json: accepted too.
        let staged = StagedFile::stage_in(
            &parent,
            PREFIX,
            "AFKLink-0.1.1.exe",
            bytes,
            &hash.to_lowercase(),
            "test",
            "refusing",
        )
        .unwrap();
        let path = staged.path().to_path_buf();
        assert_eq!(path.file_name().unwrap(), "AFKLink-0.1.1.exe");
        assert!(path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(PREFIX));
        // Readable by others — `std::fs::copy` is what `self_replace` does with it.
        let copy = parent.join("copy.exe");
        std::fs::copy(&path, &copy).unwrap();
        assert_eq!(sha256_of_file(&copy).unwrap(), (hash, bytes.len() as u64));
        std::fs::remove_file(&copy).unwrap();

        drop(staged);
        assert!(!path.exists());
        assert_eq!(entries(&parent), 0);
        std::fs::remove_dir(&parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn while_held_nobody_can_write_replace_or_delete_it() {
        const ERROR_SHARING_VIOLATION: i32 = 32;
        let parent = scratch("hold");
        let bytes = b"held";
        let staged = StagedFile::stage_in(
            &parent,
            PREFIX,
            "f.exe",
            bytes,
            &sha256_of(bytes),
            "test",
            "refusing",
        )
        .unwrap();
        let path = staged.path().to_path_buf();
        for error in [
            OpenOptions::new().write(true).open(&path).unwrap_err(),
            std::fs::remove_file(&path).unwrap_err(),
            std::fs::rename(&path, parent.join("swapped.exe")).unwrap_err(),
        ] {
            assert_eq!(
                error.raw_os_error(),
                Some(ERROR_SHARING_VIOLATION),
                "{error}"
            );
        }
        drop(staged);
        assert_eq!(entries(&parent), 0);
        std::fs::remove_dir(&parent).unwrap();
    }

    #[test]
    fn a_copy_that_does_not_match_is_refused_and_cleaned_up() {
        let parent = scratch("mismatch");
        let error = StagedFile::stage_in(
            &parent,
            PREFIX,
            "f.exe",
            b"not what was announced",
            &sha256_of(b"what was announced"),
            "test",
            "refusing to swap the exe",
        )
        .err()
        .unwrap();
        assert!(error.ends_with("refusing to swap the exe"), "{error}");
        assert_eq!(entries(&parent), 0, "nothing may be left behind");
        std::fs::remove_dir(&parent).unwrap();
    }

    #[test]
    fn hashes_are_upper_hex_of_sha256() {
        assert_eq!(
            sha256_of(b""),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        assert_eq!(sha256_upper_hex(&b""[..]).unwrap().1, 0);
    }
}
