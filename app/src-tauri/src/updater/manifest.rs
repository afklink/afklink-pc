//! What this app checks in a download: the minisign signature against `updater.pub`'s key
//! ([`verify_signature`], what tauri-plugin-updater's own check does), and beyond it the manifest's
//! extras and the signature's trusted comment.
//!
//! `latest.json` (written by `scripts/release-build.ts`) carries, next to the plugin's `signature`
//! and `url`, the exe's `sha256` (lower-case hex) and `size`. The plugin ignores them; here both are
//! required — `release-build` is the only producer of the manifest and always writes them — and the
//! downloaded bytes must match both. A field missing or of the wrong type, or the plugin's flat
//! (dynamic) form with no `platforms` at all, is an error before anything is downloaded: a manifest
//! this app cannot read in full is not one to install from.
//!
//! And the signature's trusted comment — covered by the signature, so trustworthy only after
//! [`verify_signature`] passed — must name exactly this release, both ways `release-build` signs it
//! (`cargo tauri signer sign --app-version <version>`): `file:AFKLink-<version>.exe` and
//! `version:<version>` ([`check_signed`]). Either field missing is a refusal. So a manifest that
//! announces 0.1.2 with the (validly signed) exe of 0.1.0 is refused, and so is a trial build of the
//! announced version itself: `release-build.ts --allow-untagged` signs
//! `AFKLink-<version>-untagged-<commit>[-dirty].exe` with the production key and the same `version:`
//! — never to be published, so never to be installed. The download is this app's (`super::fetch`),
//! so the check depends on no plugin setting (such as tauri-plugin-updater's
//! `requireSignedVersion`).
//!
//! The manifest itself is read here too ([`parse`]): this app's own bounded request brings its bytes
//! (`super::fetch`, at most `MAX_MANIFEST_BYTES`), and they are read into the typed [`Manifest`] —
//! the plugin's two forms (`platforms` per target, or one flat `url` and `signature`), its `name`
//! alias for `version` — never into a `serde_json::Value`.

use std::collections::HashMap;

use base64::Engine;
use serde::Deserialize;
use tauri::Url;

/// `latest.json` as `release-build.ts` writes it, in the shape tauri-plugin-updater 2.13 reads
/// (`RemoteRelease`): `version` (or `name`), `notes`, `pub_date`, and either `platforms` or the flat
/// `url` and `signature`. Unknown fields are ignored, as the plugin ignores them.
#[derive(Debug, Deserialize)]
pub(crate) struct Manifest {
    #[serde(alias = "name")]
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) notes: Option<String>,
    /// Not read for anything (the plugin required RFC 3339; nothing here uses the date).
    #[serde(default)]
    pub(crate) pub_date: Option<String>,
    #[serde(default)]
    pub(crate) platforms: Option<HashMap<String, Platform>>,
    /// The flat (dynamic) form's.
    #[serde(default)]
    pub(crate) url: Option<Url>,
    /// The flat (dynamic) form's.
    #[serde(default)]
    pub(crate) signature: Option<String>,
    /// `true` in a TEST manifest only (`release-build.ts --test-key` writes it: its builds are
    /// signed with the test key). A production build refuses a manifest that carries it; a test-key
    /// build refuses one that does not ([`check_world`]) — so even a test manifest copied over the
    /// real one, or the real one handed to a test PC, is refused before anything is downloaded.
    /// Anything but a boolean makes the manifest unreadable.
    #[serde(default)]
    pub(crate) afklink_test_key: Option<bool>,
}

/// The manifest's field that marks a TEST manifest ([`Manifest::afklink_test_key`]).
pub(crate) const TEST_MARKER: &str = "afklink_test_key";

/// Whether manifest `m` is for this build's world: a test manifest (`afklink_test_key: true`) for a
/// test-key build (`test_build`) only, any other for a production build only. Why not, when not.
pub(crate) fn check_world(m: &Manifest, test_build: bool) -> Result<(), String> {
    let marked = m.afklink_test_key == Some(true);
    match (marked, test_build) {
        (true, false) => Err(format!(
            "the manifest is a TEST manifest ({TEST_MARKER}: true): its builds are signed with the \
             test key, which this build does not trust; refused"
        )),
        (false, true) => Err(format!(
            "this test-key build takes only a TEST manifest ({TEST_MARKER}: true), and this one is \
             not; refused"
        )),
        _ => Ok(()),
    }
}

/// One `platforms` entry. `url` and `signature` are required in every entry, as the plugin requires
/// them; `sha256` and `size` are read loosely so that one missing or of the wrong type is refused
/// at the download, with its reason ([`extras`]), as before.
#[derive(Debug, Deserialize)]
pub(crate) struct Platform {
    pub(crate) url: Url,
    pub(crate) signature: String,
    #[serde(default)]
    pub(crate) sha256: Option<Loose>,
    #[serde(default)]
    pub(crate) size: Option<Loose>,
}

/// A manifest value whose type is checked later ([`extras`]): text, a byte count, or anything else.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub(crate) enum Loose {
    Text(String),
    Count(u64),
    Other(serde::de::IgnoredAny),
}

impl Loose {
    /// For a refusal's message and the entry's identity ([`identity`]): [`quoted`], 80 characters.
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Text(s) => quoted(s, 80),
            Self::Count(n) => n.to_string(),
            Self::Other(_) => "a value that is neither text nor a byte count".to_string(),
        }
    }
}

/// A string the server sent, made fit for a log line or an error: quoted, its control characters
/// escaped (`{:?}`: a `\n` stays two characters, never a line of its own), at most `max` characters
/// of it (`…` after the quote when cut).
pub(crate) fn quoted(text: &str, max: usize) -> String {
    if text.chars().count() > max {
        format!("{:?}…", text.chars().take(max).collect::<String>())
    } else {
        format!("{text:?}")
    }
}

/// Whether `c` reorders the text around it on screen (the bidirectional controls: embeddings and
/// overrides U+202A–202E, isolates U+2066–2069, the marks U+200E, U+200F and U+061C).
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
}

/// `text` with every control character, every whitespace but the plain space (U+2028, U+2029,
/// U+0085 and the like: line breaks to some readers) and every bidirectional control escaped, and
/// at most `max` characters of it (`…` when cut): for messages that quote the server's bytes in
/// their own way (serde's).
pub(crate) fn one_line(text: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, c) in text.chars().enumerate() {
        if i == max {
            out.push('…');
            break;
        }
        if c.is_control() {
            out.extend(c.escape_debug());
        } else if (c.is_whitespace() && c != ' ') || is_bidi_control(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// The first 12 characters of a manifest entry's [`identity`], for the log (the whole of a shorter
/// one).
pub(crate) fn short(identity: &str) -> &str {
    identity.get(..12).unwrap_or(identity)
}

/// The longest version a manifest may announce: it is in every update log line.
const MAX_VERSION_CHARS: usize = 64;

/// Read a manifest's bytes. Why not, when not (serde's message — line, column, what was expected —
/// on one line and cut at 300 characters: it may quote the server's text).
pub(crate) fn parse(body: &[u8]) -> Result<Manifest, String> {
    serde_json::from_slice(body).map_err(|e| {
        format!(
            "the manifest is not readable: {}",
            one_line(&e.to_string(), 300)
        )
    })
}

impl Manifest {
    /// The announced version, with leading `v`s dropped as the plugin drops them
    /// (`trim_start_matches('v')`); at most [`MAX_VERSION_CHARS`] long.
    pub(crate) fn version(&self) -> Result<semver::Version, String> {
        let shown = || quoted(&self.version, MAX_VERSION_CHARS);
        if self.version.chars().count() > MAX_VERSION_CHARS {
            return Err(format!(
                "the manifest's version {} is longer than {MAX_VERSION_CHARS} characters",
                shown()
            ));
        }
        semver::Version::parse(self.version.trim_start_matches('v')).map_err(|e| {
            format!(
                "the manifest's version {} is not SemVer: {}",
                shown(),
                one_line(&e.to_string(), 120)
            )
        })
    }
}

/// What identifies one manifest entry's release: its version, exe address, signature, `sha256`
/// and `size` as the manifest gives them — SHA-256 of them, upper hex. Any of them changed (a
/// corrected release of the same version: a new signature or hash) is another release.
pub(crate) fn identity(
    version: &str,
    url: &Url,
    signature: &str,
    entry: Option<&Platform>,
) -> String {
    let field = |v: Option<&Loose>| v.map_or_else(|| "-".to_string(), Loose::describe);
    let text = format!(
        "{version}\n{url}\n{signature}\n{}\n{}",
        field(entry.and_then(|e| e.sha256.as_ref())),
        field(entry.and_then(|e| e.size.as_ref())),
    );
    crate::staged_file::sha256_of(text.as_bytes())
}

/// `sha256` and `size` from the manifest entry for `target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extras {
    /// Upper hex.
    pub sha256: String,
    pub size: u64,
}

/// Read `sha256` and `size` from the manifest's entry for `target` (`None`: the flat form, or no
/// such entry); either missing, or of the wrong type, is an error.
pub(crate) fn extras(entry: Option<&Platform>, target: &str) -> Result<Extras, String> {
    let Some(entry) = entry else {
        // A URL and a signature without `platforms`: the dynamic (flat) form, no hash, no size —
        // not what release-build writes.
        return Err(format!(
            "the manifest has no platforms.{target} entry (no sha256, no size)"
        ));
    };
    let sha256 = match &entry.sha256 {
        None => return Err("the manifest has no sha256".to_string()),
        Some(Loose::Text(s)) if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) => {
            s.to_ascii_uppercase()
        }
        Some(other) => {
            return Err(format!(
                "manifest sha256 is not 64 hex digits: {}",
                other.describe()
            ))
        }
    };
    let size = match &entry.size {
        None => return Err("the manifest has no size".to_string()),
        Some(Loose::Count(n)) => *n,
        Some(other) => {
            return Err(format!(
                "manifest size is not a byte count: {}",
                other.describe()
            ))
        }
    };
    Ok(Extras { sha256, size })
}

/// Check the downloaded bytes against [`Extras`]; the SHA-256 (upper hex) on success.
pub(crate) fn check_download(bytes: &[u8], extras: &Extras) -> Result<String, String> {
    if bytes.len() as u64 != extras.size {
        return Err(format!(
            "downloaded {} bytes, the manifest says {}",
            bytes.len(),
            extras.size
        ));
    }
    let actual = crate::staged_file::sha256_of(bytes);
    if !actual.eq_ignore_ascii_case(&extras.sha256) {
        return Err(format!(
            "downloaded SHA-256 {actual}, the manifest says {}",
            extras.sha256
        ));
    }
    Ok(actual)
}

/// The fields of a signature's trusted comment this app checks (tab-separated `key:value`, as the
/// Tauri signer writes it: `timestamp:…\tfile:…\tversion:…`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Signed {
    /// `file:`, `None` without one.
    pub(crate) file: Option<String>,
    /// `version:`, `None` without one.
    pub(crate) version: Option<String>,
}

/// The `file:` and `version:` fields of a (verified, [`verify_signature`]) signature's trusted
/// comment.
/// `signature` is the manifest's value: base64 of the `.sig` file.
pub(crate) fn signed_fields(signature: &str) -> Result<Signed, String> {
    let text = base64::engine::general_purpose::STANDARD
        .decode(signature.trim())
        .map_err(|e| format!("signature is not base64: {e}"))?;
    let text = String::from_utf8(text).map_err(|_| "signature is not text".to_string())?;
    let sig = minisign_verify::Signature::decode(&text)
        .map_err(|e| format!("signature does not decode: {e}"))?;
    let comment = sig.trusted_comment();
    let field = |key: &str| {
        comment
            .split('\t')
            .find_map(|f| f.strip_prefix(key))
            .map(str::to_string)
    };
    Ok(Signed {
        file: field("file:"),
        version: field("version:"),
    })
}

/// The text inside a base64 value (`what` names it for the error).
fn base64_text(what: &str, b64: &str) -> Result<String, String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("{what} is not base64: {e}"))?;
    String::from_utf8(raw).map_err(|_| format!("{what} is not text"))
}

/// Verify `bytes` against `signature` (the manifest's value: base64 of the `.sig` file) with `key`
/// (`updater.pub`'s line: base64 of the `.pub` file) — what tauri-plugin-updater's
/// `verify_signature` does (2.13: both decoded the same way with `minisign-verify`), with two
/// differences. Legacy (`Ed`, not prehashed) signatures are refused: the two bytes that name the
/// algorithm are not covered by the global signature, so a genuine prehashed (`ED`) release
/// signature flipped to `Ed` "verifies" the 64-byte BLAKE2b digest of the real exe served as the
/// exe (the plugin allows legacy). Every release is prehashed — `cargo tauri signer` and `minisign`
/// sign no other way; the live 0.7.1 signature is `ED`. And no optional `version:` check:
/// [`check_signed`] requires it. Only after this passes is the trusted comment ([`signed_fields`])
/// worth reading.
pub(crate) fn verify_signature(bytes: &[u8], signature: &str, key: &str) -> Result<(), String> {
    let key = minisign_verify::PublicKey::decode(&base64_text("the key", key)?)
        .map_err(|e| format!("the key does not decode: {e}"))?;
    let sig = minisign_verify::Signature::decode(&base64_text("the signature", signature)?)
        .map_err(|e| format!("the signature does not decode: {e}"))?;
    key.verify(bytes, &sig, false).map_err(|e| {
        format!(
            "does not verify with {}'s key: {e}",
            super::pubkey::KEY_FILE
        )
    })
}

/// The key id a signature (the manifest's value: base64 of the `.sig` file) names, as
/// `super::pubkey` prints a key's: upper hex, byte order reversed. Not verified — for refusing a
/// signature by another key before its exe is fetched, never for accepting one.
pub(crate) fn signature_key_id(signature: &str) -> Result<String, String> {
    let text = base64_text("the signature", signature)?;
    let line = text
        .lines()
        .nth(1)
        .ok_or_else(|| "the signature has no signature line".to_string())?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(line.trim())
        .map_err(|e| format!("the signature line is not base64: {e}"))?;
    // Two bytes of algorithm, eight of key id, 64 of signature.
    match raw.get(2..10) {
        Some(id) if raw.len() == 74 => Ok(id.iter().rev().map(|b| format!("{b:02X}")).collect()),
        _ => Err(format!(
            "the signature line is {} bytes, not a minisign signature",
            raw.len()
        )),
    }
}

/// `version` without one leading `v`, as `release-build.ts` compares it (`replace(/^v/, "")`).
fn bare(version: &str) -> &str {
    version.strip_prefix('v').unwrap_or(version)
}

/// Whether a signed file name is the release exe of `version`: exactly `AFKLink-<version>.exe`.
/// Case is ignored, as Windows does; nothing else is (a trial build's
/// `AFKLink-<version>-untagged-<commit>.exe` is not a release).
pub(crate) fn file_names_version(file: &str, version: &str) -> bool {
    file.eq_ignore_ascii_case(&format!("AFKLink-{}.exe", bare(version)))
}

/// Check that the signature's trusted comment names exactly the release `version` (the version
/// the manifest announced): `file:AFKLink-<version>.exe` and `version:<version>` (one leading `v`
/// forgiven on either side, else the exact string). Why not, when not.
pub(crate) fn check_signed(signed: &Signed, version: &str) -> Result<(), String> {
    let expected = format!("AFKLink-{}.exe", bare(version));
    match signed.file.as_deref() {
        None => {
            return Err(format!(
                "the signature names no file (expected {expected}); not a release signature"
            ))
        }
        Some(file) if !file_names_version(file, version) => {
            return Err(format!(
                "the signature is for {file}, not {expected}, the exe of {version}"
            ))
        }
        Some(_) => {}
    }
    match signed.version.as_deref() {
        None => Err(format!(
            "the signature names no version (expected {version}); not a release signature"
        )),
        Some(signed_version) if bare(signed_version) != bare(version) => Err(format!(
            "the signature is for version {signed_version}, the manifest announces {version}"
        )),
        Some(_) => Ok(()),
    }
}

/// BLAKE2b-512 and the algorithm flip, shared with `tests/updater_http.rs`.
#[cfg(test)]
#[path = "../../tests/support/blake2b.rs"]
mod blake2b_for_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "windows-x86_64";

    /// A manifest with `entry` as its `windows-x86_64` platform (`url` and `signature` added when
    /// missing: every entry must have them).
    fn manifest(mut entry: serde_json::Value) -> serde_json::Value {
        let fields = entry.as_object_mut().unwrap();
        fields
            .entry("url")
            .or_insert_with(|| "https://api.afklink.app/download/AFKLink-0.1.1.exe".into());
        fields.entry("signature").or_insert_with(|| "x".into());
        serde_json::json!({
            "version": "0.1.1",
            "notes": "",
            "pub_date": "2026-09-28T20:15:07Z",
            "platforms": { TARGET: entry },
        })
    }

    /// [`extras`] of `raw` read as the check reads it ([`parse`]).
    fn extras_of(raw: &serde_json::Value, target: &str) -> Result<Extras, String> {
        let m = parse(&serde_json::to_vec(raw).unwrap()).unwrap();
        extras(m.platforms.as_ref().and_then(|p| p.get(target)), target)
    }

    #[test]
    fn release_build_extras_are_read_and_checked() {
        let bytes = b"the exe";
        // Lower case, as `release-build.ts` writes it.
        let hash = crate::staged_file::sha256_of(bytes).to_lowercase();
        let raw = manifest(serde_json::json!({
            "signature": "x", "url": "https://api.afklink.app/download/AFKLink-0.1.1.exe",
            "sha256": hash, "size": bytes.len(),
        }));
        let e = extras_of(&raw, TARGET).unwrap();
        assert_eq!(e.size, bytes.len() as u64);
        assert_eq!(e.sha256, hash.to_uppercase());
        assert_eq!(check_download(bytes, &e).unwrap(), hash.to_uppercase());

        assert!(check_download(b"the exf", &e)
            .unwrap_err()
            .contains("SHA-256"));
        assert!(check_download(b"short", &e).unwrap_err().contains("bytes"));
    }

    #[test]
    fn missing_extras_are_refused() {
        let hash = "ab".repeat(32);
        for (entry, why) in [
            (
                serde_json::json!({ "signature": "x", "url": "https://x/y.exe" }),
                "no sha256",
            ),
            (
                serde_json::json!({ "signature": "x", "url": "https://x/y.exe", "size": 5 }),
                "no sha256",
            ),
            (
                serde_json::json!({ "signature": "x", "url": "https://x/y.exe", "sha256": hash }),
                "no size",
            ),
            (
                serde_json::json!({ "sha256": null, "size": 5 }),
                "no sha256",
            ),
            (
                serde_json::json!({ "sha256": hash, "size": null }),
                "no size",
            ),
        ] {
            let err = extras_of(&manifest(entry.clone()), TARGET).unwrap_err();
            assert!(err.contains(why), "{entry}: {err}");
        }
        // The flat (dynamic) form has no platforms at all; another target's entry is not ours.
        let flat = serde_json::json!({ "version": "0.1.1", "url": "https://x", "signature": "x" });
        assert!(extras_of(&flat, TARGET)
            .unwrap_err()
            .contains("no platforms"));
        let other = serde_json::json!({
            "version": "0.1.1",
            "platforms": { "windows-aarch64": {
                "url": "https://x/y.exe", "signature": "x", "sha256": hash, "size": 5
            } },
        });
        assert!(extras_of(&other, TARGET)
            .unwrap_err()
            .contains("no platforms"));
    }

    /// The typed reader takes what the plugin's took (its `name` alias, leading `v`s, the flat form)
    /// and refuses what it refused (an entry without `url` or `signature`, a version that is not
    /// SemVer, no version at all); unknown fields are ignored.
    #[test]
    fn the_manifest_reads_as_the_plugin_read_it() {
        let m = parse(br#"{"name":"v0.2.0","url":"https://x/y.exe","signature":"s","extra":[1]}"#)
            .unwrap();
        assert_eq!(m.version().unwrap(), semver::Version::new(0, 2, 0));
        assert!(m.platforms.is_none());
        assert_eq!(m.signature.as_deref(), Some("s"));
        for bad in [
            &br#"{"version":"0.2.0","platforms":{"windows-x86_64":{"signature":"s"}}}"#[..],
            br#"{"version":"0.2.0","platforms":{"windows-x86_64":{"url":"https://x/y.exe"}}}"#,
            br#"{"version":"0.2.0","platforms":{"windows-x86_64":{"url":"not a url","signature":"s"}}}"#,
            br#"{"platforms":{}}"#,
            br#"not json"#,
            b"",
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        let m = parse(br#"{"version":"0.2"}"#).unwrap();
        assert!(m.version().unwrap_err().contains("not SemVer"));
    }

    /// The server's text never reaches an error (and so a log line) raw: a version or a value with a
    /// newline and a fake log line after it is escaped and cut.
    #[test]
    fn the_servers_text_is_escaped_and_cut_in_errors() {
        let fake = "0.9.0\n2026-10-26T00:00:00Z  INFO afklink_app_lib: owner pressed «Установить»";
        let m = parse(
            serde_json::json!({ "version": fake })
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        let why = m.version().unwrap_err();
        assert!(!why.contains('\n') && why.contains("\\n"), "{why}");
        let long = "9".repeat(10_000);
        let m = parse(
            serde_json::json!({ "version": long })
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        let why = m.version().unwrap_err();
        assert!(why.contains("longer than 64") && why.len() < 200, "{why}");
        // serde's own message quotes the bad value: one line, cut.
        let bad_url = format!("not a url\n{fake}{}", "x".repeat(10_000));
        let body = serde_json::json!({
            "version": "0.9.0",
            "platforms": { "windows-x86_64": { "url": bad_url, "signature": "s" } },
        });
        let why = parse(body.to_string().as_bytes()).unwrap_err();
        assert!(!why.contains('\n') && why.chars().count() < 400, "{why}");
        assert_eq!(quoted("a\nb\u{1b}[31m", 80), "\"a\\nb\\u{1b}[31m\"");
        assert_eq!(quoted("abcdef", 3), "\"abc\"…");
        assert_eq!(one_line("a\r\nb", 10), "a\\r\\nb");
        // Line and paragraph separators, NEL, other whitespace, and the bidirectional controls:
        // escaped by both, never raw; the plain space stays.
        for c in [
            '\u{2028}', '\u{2029}', '\u{85}', '\u{a0}', '\u{3000}', '\u{202A}', '\u{202B}',
            '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
            '\u{200E}', '\u{200F}', '\u{061C}',
        ] {
            let text = format!("a {c}b");
            let line = one_line(&text, 80);
            assert!(
                !line.contains(c) && line.contains("\\u{") && line.starts_with("a "),
                "{c:?}: {line}"
            );
            if c != '\u{a0}' && c != '\u{3000}' {
                assert!(!quoted(&text, 80).contains(c), "{c:?}");
            }
        }
        assert_eq!(short("74BF874FDC5E5A9E"), "74BF874FDC5E");
        assert_eq!(short("abc"), "abc");
        // Byte 12 inside an «é» (1 + 2·n bytes): the whole, never a panic.
        assert_eq!(short("aéééééé"), "aéééééé");
    }

    /// A 64 KiB manifest nested as deep as it goes — an array, a version that is an object, an
    /// unknown field, a loosely read `sha256` — fails cleanly (serde_json's depth limit), no stack
    /// overflow.
    #[test]
    fn a_deeply_nested_manifest_fails_cleanly() {
        let deep = |open: &str| open.repeat(64 * 1024 / open.len());
        for body in [
            deep("["),
            format!("{{\"version\":{}", deep("{\"a\":")),
            format!("{{\"version\":\"0.1.1\",\"x\":{}", deep("[")),
            format!(
                "{{\"version\":\"0.1.1\",\"platforms\":{{\"windows-x86_64\":{{\"url\":\"https://x/y\",\"signature\":\"s\",\"sha256\":{}",
                deep("[")
            ),
        ] {
            let why = parse(body.as_bytes()).unwrap_err();
            assert!(why.starts_with("the manifest is not readable"), "{why}");
        }
    }

    /// The two worlds refuse each other at the manifest: a TEST manifest (`afklink_test_key: true`)
    /// is refused by a production build, any other by a test-key build; a marker that is not a
    /// boolean makes the manifest unreadable (refused by both).
    #[test]
    fn a_test_manifest_is_for_a_test_key_build_only() {
        let with = |marker: &str| {
            format!(
                "{{\"version\":\"0.7.2\",{marker}\"url\":\"https://api.afklink.app/download/x.exe\",\"signature\":\"s\"}}"
            )
        };
        let marked = parse(with("\"afklink_test_key\":true,").as_bytes()).unwrap();
        let plain = parse(with("").as_bytes()).unwrap();
        let unmarked = parse(with("\"afklink_test_key\":false,").as_bytes()).unwrap();
        assert_eq!(marked.afklink_test_key, Some(true));
        assert_eq!(plain.afklink_test_key, None);

        let why = check_world(&marked, false).unwrap_err();
        assert!(why.contains("TEST manifest"), "{why}");
        assert_eq!(check_world(&plain, false), Ok(()));
        assert_eq!(check_world(&unmarked, false), Ok(()));

        assert_eq!(check_world(&marked, true), Ok(()));
        for m in [&plain, &unmarked] {
            let why = check_world(m, true).unwrap_err();
            assert!(why.contains("takes only a TEST manifest"), "{why}");
        }

        for odd in ["\"true\"", "1", "null", "{}"] {
            let body = with(&format!("\"afklink_test_key\":{odd},"));
            if odd == "null" {
                // null is no marker: the field's default.
                assert_eq!(parse(body.as_bytes()).unwrap().afklink_test_key, None);
                continue;
            }
            let why = parse(body.as_bytes()).unwrap_err();
            assert!(
                why.starts_with("the manifest is not readable"),
                "{odd}: {why}"
            );
        }
        // The live manifest has no marker: a production build's world.
        assert_eq!(TEST_MARKER, "afklink_test_key");
    }

    /// The identity of an entry changes with any of what makes the release: a corrected release of
    /// the same version (a new signature, hash or size) is another one.
    #[test]
    fn an_entrys_identity_changes_with_its_signature_hash_size_or_address() {
        let hash = "ab".repeat(32);
        let id = |entry: serde_json::Value| {
            let m = parse(&serde_json::to_vec(&manifest(entry)).unwrap()).unwrap();
            let p = m.platforms.as_ref().unwrap().get(TARGET).unwrap();
            identity(&m.version, &p.url, &p.signature, Some(p))
        };
        let base = id(serde_json::json!({ "signature": "s1", "sha256": hash, "size": 5 }));
        assert_eq!(base.len(), 64);
        assert_eq!(
            base,
            id(serde_json::json!({ "signature": "s1", "sha256": hash, "size": 5 }))
        );
        for other in [
            serde_json::json!({ "signature": "s2", "sha256": hash, "size": 5 }),
            serde_json::json!({ "signature": "s1", "sha256": "cd".repeat(32), "size": 5 }),
            serde_json::json!({ "signature": "s1", "sha256": hash, "size": 6 }),
            serde_json::json!({ "signature": "s1", "sha256": hash }),
            serde_json::json!({ "signature": "s1", "sha256": hash, "size": 5,
                                "url": "https://api.afklink.app/download/AFKLink-0.1.1.exe?x" }),
        ] {
            assert_ne!(base, id(other.clone()), "{other}");
        }
    }

    #[test]
    fn extras_of_the_wrong_shape_are_refused() {
        let hash = "ab".repeat(32);
        for entry in [
            serde_json::json!({ "sha256": 5, "size": 5 }),
            serde_json::json!({ "sha256": "abc", "size": 5 }),
            serde_json::json!({ "sha256": "zz".repeat(32), "size": 5 }),
            serde_json::json!({ "sha256": hash, "size": "100" }),
            serde_json::json!({ "sha256": hash, "size": -1 }),
            serde_json::json!({ "sha256": hash, "size": 1.5 }),
        ] {
            assert!(
                extras_of(&manifest(entry.clone()), TARGET).is_err(),
                "{entry}"
            );
        }
    }

    /// The live `latest.json` of 0.7.1 (fetched from api.afklink.app, public): its real
    /// signature, made by `release-build` with the production key. Only the trusted comment, the key
    /// id and the manifest's fields are checked here — the 35 MB exe the signature covers is not in
    /// the tests, so the signature over its bytes is not verified. The bytes as served (868, with
    /// the final newline), shared with `tests/updater_http.rs`.
    const LIVE_0_7_1: &str = include_str!("../../tests/support/latest-0.7.1.json");

    /// The algorithm bytes of a `.sig`'s signature line: `ED` prehashed, `Ed` legacy.
    fn algorithm(signature: &str) -> [u8; 2] {
        let text = base64_text("sig", signature).unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(text.lines().nth(1).unwrap().trim())
            .unwrap();
        [raw[0], raw[1]]
    }

    #[test]
    fn the_live_release_signature_names_its_release_and_our_key() {
        let raw: serde_json::Value = serde_json::from_str(LIVE_0_7_1).unwrap();
        let entry = &raw["platforms"][TARGET];
        let signature = entry["signature"].as_str().unwrap();
        let signed = signed_fields(signature).unwrap();
        assert_eq!(
            signed,
            Signed {
                file: Some("AFKLink-0.7.1.exe".to_string()),
                version: Some("0.7.1".to_string()),
            }
        );
        assert_eq!(check_signed(&signed, "0.7.1"), Ok(()));
        assert!(check_signed(&signed, "0.7.2").is_err());
        // Signed with the production key, updater.pub's: the key a production build trusts, and
        // one a test-key build does not (`pubkey`, «The test key»).
        // Read from disk, not embedded: a test-key build has no production key compiled in.
        let production = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("updater.pub"),
        )
        .unwrap();
        let super::super::pubkey::PubKey::Key { base64, key_id } =
            super::super::pubkey::parse(&production)
        else {
            unreachable!("updater.pub holds the key");
        };
        assert_eq!(signature_key_id(signature), Ok(key_id));
        if super::super::pubkey::TEST_SIGNING_KEY {
            assert_ne!(super::super::pubkey::embedded(), Some(base64));
            if let super::super::pubkey::PubKey::Key { key_id: test, .. } =
                super::super::pubkey::parse(super::super::pubkey::UPDATER_PUB)
            {
                assert_ne!(signature_key_id(signature), Ok(test));
            }
        } else {
            assert_eq!(super::super::pubkey::embedded(), Some(base64));
        }
        // Prehashed: what `verify_signature` accepts (legacy `Ed` is refused).
        assert_eq!(&algorithm(signature), b"ED");
        assert_eq!(LIVE_0_7_1.len(), 868, "the live 0.7.1 manifest's size");
        assert_eq!(
            extras_of(&raw, TARGET).unwrap(),
            Extras {
                sha256: "74BF874FDC5E5A9EC6156CDB828477B0BCFD7589ABD7A4AD2AB3199DCACA1A16"
                    .to_string(),
                size: 35_435_008,
            }
        );
    }

    #[test]
    fn the_signed_file_must_be_exactly_this_versions_release_exe() {
        assert!(file_names_version("AFKLink-0.1.1.exe", "0.1.1"));
        assert!(file_names_version("afklink-0.1.1.EXE", "0.1.1"));
        assert!(file_names_version("AFKLink-0.1.1.exe", "v0.1.1"));
        // A trial build of the very version announced: signed with the production key, never
        // published, never installed.
        assert!(!file_names_version(
            "AFKLink-0.1.1-untagged-3a3bc46-dirty.exe",
            "0.1.1"
        ));
        assert!(!file_names_version(
            "AFKLink-0.1.1-untagged-3a3bc46.exe",
            "0.1.1"
        ));
        // Looks like a pre-release of the announced version; is not its release exe.
        assert!(!file_names_version("AFKLink-0.1.1-beta.1.exe", "0.1.1"));
        assert!(!file_names_version("AFKLink-0.1.0.exe", "0.1.1"));
        assert!(!file_names_version("AFKLink-0.1.10.exe", "0.1.1"));
        assert!(!file_names_version("AFKLink-0.1.1.msi", "0.1.1"));
        assert!(!file_names_version("AFKLink-0.1.1.exe.exe", "0.1.1"));
        assert!(!file_names_version("dir/AFKLink-0.1.1.exe", "0.1.1"));
        assert!(!file_names_version("Other-0.1.1.exe", "0.1.1"));
    }

    fn signed(file: Option<&str>, version: Option<&str>) -> Signed {
        Signed {
            file: file.map(str::to_string),
            version: version.map(str::to_string),
        }
    }

    #[test]
    fn the_trusted_comment_must_name_this_release_both_ways() {
        // What the live latest.json carries (0.7.1).
        assert_eq!(
            check_signed(&signed(Some("AFKLink-0.7.1.exe"), Some("0.7.1")), "0.7.1"),
            Ok(())
        );
        // One leading `v` is forgiven on either side, as release-build forgives it.
        assert_eq!(
            check_signed(&signed(Some("AFKLink-0.7.1.exe"), Some("v0.7.1")), "0.7.1"),
            Ok(())
        );
        for (s, why) in [
            (signed(None, Some("0.7.1")), "names no file"),
            (signed(Some("AFKLink-0.7.1.exe"), None), "names no version"),
            (
                signed(Some("AFKLink-0.7.1.exe"), Some("0.7.0")),
                "version 0.7.0",
            ),
            // A version that SemVer would call equal is still not the same string.
            (
                signed(Some("AFKLink-0.7.1.exe"), Some("0.7.1+x")),
                "version 0.7.1+x",
            ),
            (
                signed(
                    Some("AFKLink-0.7.1-untagged-3a3bc46-dirty.exe"),
                    Some("0.7.1"),
                ),
                "untagged",
            ),
            (
                signed(Some("AFKLink-0.7.1-beta.1.exe"), Some("0.7.1")),
                "beta.1",
            ),
            (signed(None, None), "names no file"),
        ] {
            let err = check_signed(&s, "0.7.1").unwrap_err();
            assert!(err.contains(why), "{s:?}: {err}");
        }
    }

    /// A trial build announced under its own name's version (`0.1.1-untagged-abc1234`, a SemVer
    /// pre-release newer than 0.1.0): the file matches the announced name exactly, the signed
    /// `version:0.1.1` does not — this check alone refuses it.
    #[test]
    fn a_trial_build_announced_as_its_own_version_is_refused_by_the_signed_version() {
        for announced in ["0.1.1-untagged-abc1234", "0.1.1-untagged-abc1234-dirty"] {
            let s = signed(Some(&format!("AFKLink-{announced}.exe")), Some("0.1.1"));
            assert!(file_names_version(s.file.as_deref().unwrap(), announced));
            let err = check_signed(&s, announced).unwrap_err();
            assert!(
                err.contains(&format!(
                    "the signature is for version 0.1.1, the manifest announces {announced}"
                )),
                "{err}"
            );
        }
    }

    fn sign_comment(comment: &str) -> String {
        let key = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let sig = minisign::sign(
            Some(&key.pk),
            &key.sk,
            std::io::Cursor::new(b"exe"),
            Some(comment),
            Some("signature from tauri secret key"),
        )
        .unwrap();
        base64::engine::general_purpose::STANDARD.encode(sig.to_string())
    }

    /// The algorithm-flip attack: a genuine prehashed (`ED`) release signature turned to legacy
    /// `Ed` — bytes the global signature does not cover — "verifies" the 64-byte BLAKE2b-512 digest
    /// of the real exe as if it were the exe, when legacy signatures are allowed (as the plugin
    /// allows them: shown here with `minisign-verify` itself). `verify_signature` refuses it.
    #[test]
    fn a_prehashed_signature_flipped_to_legacy_does_not_verify_the_digest() {
        use super::blake2b_for_tests::{blake2b_512, flip_to_legacy, ABC};
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(&blake2b_512(b"abc")), ABC, "RFC 7693's vector");

        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let key =
            base64::engine::general_purpose::STANDARD.encode(pair.pk.to_box().unwrap().to_string());
        let exe = b"MZ the real AFKLink 0.1.1".repeat(1000);
        let sig = minisign::sign(
            Some(&pair.pk),
            &pair.sk,
            std::io::Cursor::new(&exe),
            Some("timestamp:1790000000\tfile:AFKLink-0.1.1.exe\tversion:0.1.1"),
            Some("signature from tauri secret key"),
        )
        .unwrap();
        let genuine = base64::engine::general_purpose::STANDARD.encode(sig.to_string());
        assert_eq!(&algorithm(&genuine), b"ED");
        assert_eq!(verify_signature(&exe, &genuine, &key), Ok(()));

        let flipped = flip_to_legacy(&genuine);
        assert_eq!(&algorithm(&flipped), b"Ed");
        let digest = blake2b_512(&exe);
        // The attack is real: with legacy allowed, the digest passes.
        let pk = minisign_verify::PublicKey::decode(&base64_text("key", &key).unwrap()).unwrap();
        let fs =
            minisign_verify::Signature::decode(&base64_text("sig", &flipped).unwrap()).unwrap();
        assert!(
            pk.verify(&digest, &fs, true).is_ok(),
            "the flip verifies with legacy allowed"
        );
        // And the trusted comment still names the release.
        assert_eq!(
            signed_fields(&flipped).unwrap(),
            signed(Some("AFKLink-0.1.1.exe"), Some("0.1.1"))
        );
        let err = verify_signature(&digest, &flipped, &key).unwrap_err();
        assert!(err.contains("does not verify"), "{err}");
        // Nor does the flipped signature verify the real exe.
        assert!(verify_signature(&exe, &flipped, &key).is_err());
    }

    /// A valid signature of 0.1.0 whose trusted comment was edited to name 0.1.1: the global
    /// signature covers the comment, so it does not verify.
    #[test]
    fn an_edited_trusted_comment_does_not_verify() {
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let key =
            base64::engine::general_purpose::STANDARD.encode(pair.pk.to_box().unwrap().to_string());
        let exe = b"MZ AFKLink 0.1.0";
        let sig = minisign::sign(
            Some(&pair.pk),
            &pair.sk,
            std::io::Cursor::new(exe),
            Some("timestamp:1790000000\tfile:AFKLink-0.1.0.exe\tversion:0.1.0"),
            Some("signature from tauri secret key"),
        )
        .unwrap();
        let genuine = base64::engine::general_purpose::STANDARD.encode(sig.to_string());
        assert_eq!(verify_signature(exe, &genuine, &key), Ok(()));
        let text = base64_text("sig", &genuine)
            .unwrap()
            .replace("file:AFKLink-0.1.0.exe", "file:AFKLink-0.1.1.exe")
            .replace("version:0.1.0", "version:0.1.1");
        let edited = base64::engine::general_purpose::STANDARD.encode(text);
        assert_eq!(
            signed_fields(&edited).unwrap(),
            signed(Some("AFKLink-0.1.1.exe"), Some("0.1.1"))
        );
        let err = verify_signature(exe, &edited, &key).unwrap_err();
        assert!(err.contains("does not verify"), "{err}");
    }

    #[test]
    fn the_signature_names_its_key_id() {
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let line =
            base64::engine::general_purpose::STANDARD.encode(pair.pk.to_box().unwrap().to_string());
        let sig = minisign::sign(
            Some(&pair.pk),
            &pair.sk,
            std::io::Cursor::new(b"x"),
            Some("timestamp:1"),
            None,
        )
        .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_string());
        let super::super::pubkey::PubKey::Key { key_id, .. } = super::super::pubkey::parse(&line)
        else {
            unreachable!("a key");
        };
        assert_eq!(signature_key_id(&b64), Ok(key_id));
        assert!(signature_key_id("!!").is_err());
        assert!(
            signature_key_id(&base64::engine::general_purpose::STANDARD.encode("a\nAAAA\n"))
                .is_err()
        );
    }

    #[test]
    fn the_signature_verifies_only_with_its_key_and_its_bytes() {
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let other = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let line = |pk: &minisign::PublicKey| {
            base64::engine::general_purpose::STANDARD.encode(pk.to_box().unwrap().to_string())
        };
        let sig = minisign::sign(
            Some(&pair.pk),
            &pair.sk,
            std::io::Cursor::new(b"MZ exe"),
            Some("timestamp:1790000000\tfile:AFKLink-0.1.1.exe\tversion:0.1.1"),
            Some("signature from tauri secret key"),
        )
        .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_string());
        assert_eq!(verify_signature(b"MZ exe", &b64, &line(&pair.pk)), Ok(()));
        let err = verify_signature(b"MZ exe", &b64, &line(&other.pk)).unwrap_err();
        assert!(err.contains("does not verify"), "{err}");
        let err = verify_signature(b"MZ exf", &b64, &line(&pair.pk)).unwrap_err();
        assert!(err.contains("does not verify"), "{err}");
        // No key is no verification (fail closed), nor is something that is not a key.
        for key in ["", "  ", "!!", &b64] {
            assert!(verify_signature(b"MZ exe", &b64, key).is_err(), "{key:?}");
        }
        assert!(verify_signature(b"MZ exe", "", &line(&pair.pk)).is_err());
    }

    #[test]
    fn the_trusted_comment_fields_are_read() {
        // Exactly the live 0.7.1 signature's trusted comment.
        let b64 = sign_comment("timestamp:1792088149\tfile:AFKLink-0.7.1.exe\tversion:0.7.1");
        assert_eq!(
            signed_fields(&b64).unwrap(),
            signed(Some("AFKLink-0.7.1.exe"), Some("0.7.1"))
        );
        let b64 = sign_comment("timestamp:1790000000\tfile:AFKLink-0.1.1.exe");
        assert_eq!(
            signed_fields(&b64).unwrap(),
            signed(Some("AFKLink-0.1.1.exe"), None)
        );
        let b64 = sign_comment("timestamp:1790000000");
        assert_eq!(signed_fields(&b64).unwrap(), signed(None, None));
        assert!(signed_fields("!!").is_err());
    }
}
