//! The one key an update must be signed with: `app/src-tauri/updater.pub`, embedded at build time.
//!
//! The file's format (its own comments say it too): the contents of the `<key>.pub` that `cargo tauri
//! signer generate` writes — one line of base64 — and any number of comment lines starting with `#`
//! and blank lines. No key line means no self-update in this build; more than one, or a line that is
//! not a minisign public key, the same, with a warning. Either way everything else works.
//!
//! The line is handed as it is to the check (which refuses to run without one) and to the download,
//! which refuses a signature by another key before fetching and verifies every exe with it (`super::manifest::verify_signature`, decoding it
//! with `minisign-verify`); it is decoded here the same way first, so a key the download would
//! refuse is found at startup, not at the first update.
//!
//! # The test key
//!
//! The update rollback tests install deliberately broken builds. Those are signed
//! with a separate TEST key, `app/src-tauri/updater-test.pub`, never with the production one — so
//! a broken build can never be installed by a production copy, whoever serves it. Only a build
//! compiled with the cargo feature `updater-test-key` embeds that file, and then INSTEAD of
//! `updater.pub`: a test build trusts the test key alone, so it can never install a production
//! release either (it stays in the test world, and a production release is never the target of a
//! rollback test by accident). Exactly one `include_str!` of a key file is compiled into any build
//! (a test holds the source to that). Only `bun scripts/release-build.ts --test-key` turns the
//! feature on; it refuses under GitHub Actions and beside the production signing key, and
//! `build.rs` refuses a release-channel test-key build under GitHub Actions. A test-key build says
//! so with a `warn` at every start ([`announce`]) and in its `User-Agent`
//! (`AFKLink/<v> (release; test-key)`).

use base64::Engine;

/// Whether this build trusts the TEST key (`updater-test.pub`) instead of the production one.
pub(crate) const TEST_SIGNING_KEY: bool = cfg!(feature = "updater-test-key");

/// The name of the key file this build embeds, for the log and the messages.
pub(crate) const KEY_FILE: &str = if TEST_SIGNING_KEY {
    "updater-test.pub"
} else {
    "updater.pub"
};

/// `updater.pub` as it was at build time (`include_str!` rebuilds the crate when it changes). The
/// production key: in every build but a test-key one.
#[cfg(not(feature = "updater-test-key"))]
pub(crate) static UPDATER_PUB: &str = include_str!("../../updater.pub");

/// `updater-test.pub` as it was at build time: the TEST key, in a test-key build alone (the feature
/// `updater-test-key`; the module docs). Never in a production build.
#[cfg(feature = "updater-test-key")]
pub(crate) static UPDATER_PUB: &str = include_str!("../../updater-test.pub");

/// What a key file (`updater.pub`, `updater-test.pub`) holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PubKey {
    Key {
        /// The line, as the check and the download take it.
        base64: String,
        /// The key id as `minisign` prints it (upper hex, byte order reversed), for the log.
        key_id: String,
    },
    /// Only comments: the owner has not made the key yet.
    Missing,
    /// Something there that is not one minisign public key; why.
    Invalid(String),
}

/// Read a `updater.pub` text.
pub(crate) fn parse(text: &str) -> PubKey {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    match lines.as_slice() {
        [] => PubKey::Missing,
        [line] => match decode(line) {
            Ok(key_id) => PubKey::Key {
                base64: (*line).to_string(),
                key_id,
            },
            Err(why) => PubKey::Invalid(why),
        },
        more => PubKey::Invalid(format!("{} key lines, expected one", more.len())),
    }
}

/// The key line the update task hands the check and the download: the one in `text`, `None`
/// (logged) when there is none or it is not usable — no self-update then. The only key anywhere:
/// there is no tauri-plugin-updater and no `plugins.updater` in `tauri.conf.json` (a test holds it).
pub(crate) fn resolve(text: &str) -> Option<String> {
    match parse(text) {
        PubKey::Key { base64, key_id } => {
            tracing::debug!(
                key_id,
                key_file = KEY_FILE,
                test_key = TEST_SIGNING_KEY,
                "updates: signature key from {KEY_FILE}"
            );
            Some(base64)
        }
        PubKey::Missing => {
            tracing::info!("updates: off, {KEY_FILE} has no key yet");
            None
        }
        PubKey::Invalid(why) => {
            tracing::warn!("updates: off, {KEY_FILE} holds no usable key: {why}");
            None
        }
    }
}

/// [`resolve`] of the embedded [`UPDATER_PUB`]: what `super::start` uses.
pub(crate) fn embedded() -> Option<String> {
    resolve(UPDATER_PUB)
}

/// Say which key this build trusts, at every start (`super::start`, before anything can turn the
/// updates off): a test-key build with a `warn` — so a test build that left the test PC is
/// recognisable in any log it sends — a production build at `debug`.
pub(crate) fn announce() {
    let key_id = match parse(UPDATER_PUB) {
        PubKey::Key { key_id, .. } => key_id,
        PubKey::Missing => "none".to_string(),
        PubKey::Invalid(_) => "unusable".to_string(),
    };
    if TEST_SIGNING_KEY {
        tracing::warn!(
            key_id,
            key_file = KEY_FILE,
            "updates: TEST signing key ({KEY_FILE}), key id {key_id}: this is a test build for the \
             rollback live tests; it installs only test-signed updates, never a published release, \
             and must not be given to anyone"
        );
    } else {
        tracing::debug!(
            key_id,
            key_file = KEY_FILE,
            "updates: production signing key ({KEY_FILE}), key id {key_id}"
        );
    }
}

/// Check a key line as the download will read it, and return its key id.
fn decode(line: &str) -> Result<String, String> {
    let outer = base64::engine::general_purpose::STANDARD
        .decode(line)
        .map_err(|e| format!("not base64: {e}"))?;
    let text = String::from_utf8(outer).map_err(|_| "not a minisign key file".to_string())?;
    // What the download does with it (`manifest::verify_signature`): decode as a minisign public
    // key file.
    minisign_verify::PublicKey::decode(&text)
        .map_err(|e| format!("not a minisign public key: {e}"))?;
    let body = text
        .lines()
        .nth(1)
        .ok_or_else(|| "no key line in the key file".to_string())?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| format!("key line not base64: {e}"))?;
    if raw.len() != 42 || &raw[..2] != b"Ed" {
        return Err(format!("{} bytes, not an Ed25519 minisign key", raw.len()));
    }
    Ok(raw[2..10]
        .iter()
        .rev()
        .map(|b| format!("{b:02X}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key file line as `cargo tauri signer generate` writes its `.pub` (a throwaway key): base64
    /// of «untrusted comment: minisign public key: <ID>\nRWQ…».
    fn sample_key() -> String {
        let key = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        base64::engine::general_purpose::STANDARD.encode(key.pk.to_box().unwrap().to_string())
    }

    /// A key file of this crate as it is on disk now: read, never embedded.
    fn on_disk(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// The key line of a key file's text, if it holds one.
    fn key_line(text: &str) -> Option<String> {
        match parse(text) {
            PubKey::Key { base64, .. } => Some(base64),
            PubKey::Missing => None,
            PubKey::Invalid(why) => unreachable!("not a usable key file: {why}"),
        }
    }

    #[test]
    fn the_shipped_key_is_embedded_and_is_what_the_task_gets() {
        // The file this build names is the one it embeds, byte for byte.
        assert_eq!(UPDATER_PUB, on_disk(KEY_FILE), "{KEY_FILE}");
        let parsed = parse(UPDATER_PUB);
        if TEST_SIGNING_KEY && parsed == PubKey::Missing {
            // A test-key build before `bun scripts/release-test-key.ts` made the key: no updates at
            // all (and `release-build.ts --test-key` refuses to build), nothing else to check.
            assert_eq!(embedded(), None);
            return;
        }
        let PubKey::Key { base64, key_id } = parsed else {
            unreachable!("{KEY_FILE} must hold the key: {parsed:?}");
        };
        assert_eq!(key_id.len(), 16);
        // `start` hands the task `embedded()`: the very line of the key file, nothing else.
        assert_eq!(embedded().as_deref(), Some(base64.as_str()));
        let line = UPDATER_PUB
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .unwrap();
        assert_eq!(base64, line);
    }

    /// The default build — every published release — embeds exactly `updater.pub` and has nothing of
    /// the test key: not its file, not its line.
    #[cfg(not(feature = "updater-test-key"))]
    #[test]
    fn a_production_build_embeds_updater_pub_and_never_the_test_key() {
        const { assert!(!TEST_SIGNING_KEY) };
        assert_eq!(KEY_FILE, "updater.pub");
        assert_eq!(UPDATER_PUB, on_disk("updater.pub"));
        let production = key_line(UPDATER_PUB).expect("updater.pub holds the production key");
        assert_eq!(embedded(), Some(production));
        if let Some(test) = key_line(&on_disk("updater-test.pub")) {
            assert!(
                !UPDATER_PUB.contains(&test),
                "the test key line is embedded"
            );
            assert_ne!(embedded(), Some(test));
        }
    }

    /// A test-key build embeds exactly `updater-test.pub` and does not trust the production key: it
    /// never installs a published release.
    #[cfg(feature = "updater-test-key")]
    #[test]
    fn a_test_key_build_embeds_updater_test_pub_and_never_the_production_key() {
        const { assert!(TEST_SIGNING_KEY) };
        assert_eq!(KEY_FILE, "updater-test.pub");
        assert_eq!(UPDATER_PUB, on_disk("updater-test.pub"));
        let production = key_line(&on_disk("updater.pub")).expect("updater.pub holds the key");
        assert!(
            !UPDATER_PUB.contains(&production),
            "the production key line is embedded"
        );
        assert_ne!(embedded(), Some(production));
    }

    /// The two files never hold the same key: a test build's signature could otherwise pass for a
    /// release's. Before the test key is made, `updater-test.pub` holds only comments — never
    /// anything that is not a key.
    #[test]
    fn the_test_key_is_not_the_production_key() {
        let PubKey::Key {
            base64: production,
            key_id: production_id,
        } = parse(&on_disk("updater.pub"))
        else {
            unreachable!("updater.pub holds the production key");
        };
        match parse(&on_disk("updater-test.pub")) {
            PubKey::Key { base64, key_id } => {
                assert_ne!(key_id, production_id, "the same key id in both files");
                assert_ne!(base64, production, "the same key in both files");
            }
            PubKey::Missing => {}
            PubKey::Invalid(why) => unreachable!("updater-test.pub: {why}"),
        }
    }

    /// Exactly one key file is compiled into any build: across `src/`, the only `include_str!` /
    /// `include_bytes!` of a `.pub` file are the two in this module, `updater.pub` under
    /// `cfg(not(feature = "updater-test-key"))` and `updater-test.pub` under
    /// `cfg(feature = "updater-test-key")`.
    #[test]
    fn the_test_key_is_compiled_in_only_behind_its_feature() {
        fn sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    sources(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        sources(&root.join("src"), &mut files);
        assert!(files.len() > 10, "{files:?}");
        // Spelled in two parts, so these lines are not found themselves.
        let includes = [concat!("include", "_str!("), concat!("include", "_bytes!(")];
        let mut found = Vec::new();
        for file in &files {
            let text = std::fs::read_to_string(file).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            for (n, line) in lines.iter().enumerate() {
                if includes.iter().any(|i| line.contains(i)) && line.contains(".pub\"") {
                    // The attribute right above, past the doc comment.
                    let attribute = lines[..n]
                        .iter()
                        .rev()
                        .map(|l| l.trim())
                        .find(|l| !l.starts_with("///"))
                        .unwrap_or_default();
                    found.push((line.trim().to_string(), attribute.to_string()));
                }
            }
        }
        let production = concat!("include", "_str!(\"../../updater.pub\");");
        let test = concat!("include", "_str!(\"../../updater-test.pub\");");
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found.iter().any(|(line, attr)| line.ends_with(production)
                && attr == "#[cfg(not(feature = \"updater-test-key\"))]"),
            "{found:?}"
        );
        assert!(
            found.iter().any(|(line, attr)| line.ends_with(test)
                && attr == "#[cfg(feature = \"updater-test-key\")]"),
            "{found:?}"
        );

        // That the feature is never on by default — in `default`, through any feature it turns on,
        // or from another member — is held on the resolved features (`cargo metadata`):
        // scripts/lib/testkey.test.ts, «the feature is off by default, as cargo resolves it».
    }

    /// The test build's deliberate breakage (`test_break`, the broken server address) is compiled
    /// into a test-key build alone: the module is declared under `cfg(feature = "updater-test-key")`,
    /// every use of it in `lib.rs` is under that cfg, and its build-time variable is read nowhere
    /// else in `src/`. A production build has no such path at all.
    #[test]
    fn the_test_breakage_is_compiled_in_only_behind_the_feature() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let attr = "#[cfg(feature = \"updater-test-key\")]";
        let lib = std::fs::read_to_string(root.join("src/lib.rs")).unwrap();
        let lines: Vec<&str> = lib.lines().collect();
        let mut uses = 0;
        for (n, line) in lines.iter().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            if !(code.contains("test_break::") || code.trim() == "mod test_break;") {
                continue;
            }
            uses += 1;
            let above = lines[..n]
                .iter()
                .rev()
                .map(|l| l.trim())
                .find(|l| !l.starts_with("//"))
                .unwrap_or_default();
            assert_eq!(above, attr, "lib.rs:{}: {line}", n + 1);
        }
        assert_eq!(uses, 2, "the module and its one call");

        fn sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    sources(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let mut files = Vec::new();
        sources(&root.join("src"), &mut files);
        // Spelled in two parts, so this line is not found itself.
        let var = concat!("AFKLINK_TEST_BREAK", "_SERVER_URL");
        let readers: Vec<String> = files
            .iter()
            .filter(|f| std::fs::read_to_string(f).unwrap().contains(var))
            .map(|f| f.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(readers, ["test_break.rs"]);
    }

    #[test]
    fn resolve_gives_no_key_for_no_usable_key() {
        assert_eq!(resolve("# nothing yet\n"), None);
        assert_eq!(resolve("not base64 !!"), None);
        let line = sample_key();
        assert_eq!(resolve(&format!("{line}\n{line}\n")), None);
        assert_eq!(resolve(&format!("# key\n{line}\n")), Some(line));
    }

    /// Every key in `value`, at any depth, with its path.
    fn json_keys(value: &serde_json::Value, path: &str, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, inner) in map {
                    let here = format!("{path}.{key}");
                    out.push(here.clone());
                    json_keys(inner, &here, out);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, inner) in items.iter().enumerate() {
                    json_keys(inner, &format!("{path}[{i}]"), out);
                }
            }
            _ => {}
        }
    }

    /// updater.pub is the only key, and the update is this app's code alone: tauri-plugin-updater
    /// is not used and must not come in silently — its `plugins.updater.pubkey` would be a second
    /// key, embedded from a config this code does not read, and its settings could loosen checks
    /// nobody here makes. So: not a dependency (nor in the lock, by way of another crate), no
    /// updater section or updater artifacts in `tauri.conf.json`, no `updater:` permission granted.
    #[test]
    fn the_updater_plugin_is_not_in_the_app() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let read = |rel: &str| {
            std::fs::read_to_string(dir.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
        };

        let conf: serde_json::Value = serde_json::from_str(&read("tauri.conf.json")).unwrap();
        let mut keys = Vec::new();
        json_keys(&conf, "", &mut keys);
        assert!(keys.iter().any(|k| k == ".bundle"), "{keys:?}");
        for key in &keys {
            let lower = key.to_ascii_lowercase();
            assert!(
                !lower.contains("updater") && !lower.contains("pubkey"),
                "tauri.conf.json: {key}"
            );
        }

        let manifest = read("Cargo.toml");
        assert!(manifest.contains("[dependencies]"));
        for (n, line) in manifest.lines().enumerate() {
            let code = line.split('#').next().unwrap_or_default();
            assert!(
                !code.contains("tauri-plugin-updater") && !code.contains("tauri_plugin_updater"),
                "Cargo.toml:{}: {line}",
                n + 1
            );
        }

        let lock = read("../../Cargo.lock");
        assert!(lock.contains("name = \"tauri-plugin-single-instance\""));
        assert!(
            !lock.contains("name = \"tauri-plugin-updater\""),
            "Cargo.lock has tauri-plugin-updater"
        );

        let capability = read("capabilities/default.json");
        assert!(capability.contains("core:default"));
        assert!(!capability.contains("updater:"), "{capability}");
    }

    #[test]
    fn comments_alone_are_no_key() {
        // The file before the owner had made the key: comments, blank lines.
        let placeholder = "# Открытый ключ обновлений AFKLink. Пока ключа нет.\n#\n\n   # ещё\n";
        assert_eq!(parse(placeholder), PubKey::Missing);
        assert_eq!(parse(""), PubKey::Missing);
    }

    #[test]
    fn the_key_id_is_the_one_minisign_prints() {
        let line = sample_key();
        let text = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(&line)
                .unwrap(),
        )
        .unwrap();
        // «untrusted comment: minisign public key: 8C9032D41C6CA821»
        let printed = text
            .lines()
            .next()
            .unwrap()
            .rsplit(' ')
            .next()
            .unwrap()
            .to_string();
        let PubKey::Key { key_id, .. } = parse(&line) else {
            unreachable!("a key: {:?}", parse(&line));
        };
        // minisign prints the number without leading zeros; ours is always 16 digits.
        assert_eq!(key_id.len(), 16);
        assert_eq!(
            u64::from_str_radix(&key_id, 16).unwrap(),
            u64::from_str_radix(&printed, 16).unwrap(),
            "{key_id} vs {printed}"
        );
    }

    #[test]
    fn one_key_line_among_comments_is_the_key() {
        let line = sample_key();
        let text = format!("# Открытый ключ\r\n#\r\n{line}\r\n# конец\r\n");
        let PubKey::Key { base64, key_id } = parse(&text) else {
            unreachable!("a key: {:?}", parse(&text));
        };
        assert_eq!(base64, line);
        assert_eq!(key_id.len(), 16);
        assert!(key_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
        // Surrounding spaces are forgiven.
        assert!(
            matches!(parse(&format!("  {line}  ")), PubKey::Key { base64, .. } if base64 == line)
        );
    }

    #[test]
    fn anything_else_is_no_key_with_a_reason() {
        let line = sample_key();
        for text in [
            format!("{line}\n{line}\n"),
            "not base64 !!".to_string(),
            base64::engine::general_purpose::STANDARD.encode("untrusted comment: x\nnot a key"),
            // A signature is not a key.
            base64::engine::general_purpose::STANDARD.encode("hello"),
        ] {
            assert!(matches!(parse(&text), PubKey::Invalid(_)), "{text}");
        }
    }
}
