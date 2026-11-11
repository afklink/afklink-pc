//! `--data-dir`: a separate device with its own config and identity.
//!
//! Everything `afklink_core::paths::afklink_dir` holds moves to the given directory, through the
//! process-wide override, before config or identity are read. A fresh directory gets a fresh
//! `config.json` (a new device id) and, on first use, a new `identity.json` — so the backend sees a
//! different device, and the owner's own device, whose identity lives in `%APPDATA%\AFKLink`, is
//! never connected from here (the server keeps only a device's latest connection, so sharing one
//! would knock the owner's desktop app offline).
//!
//! The one thing taken from the owner's install is *where to connect*: a new config's
//! `server_url`, `bot_username` and `miniapp_short_name` are copied from the owner's `config.json`,
//! read-only, because a CLI built without `AFKLINK_SERVER_URL` would otherwise point at localhost.
//!
//! The pre-rename directory, `%APPDATA%\Remoter`, counts as the owner's too: it is the owner's
//! device until the desktop app or an ordinary CLI run migrates it (a bench run never does), and a
//! migration by copy leaves the same identity behind in it.

use std::path::{Path, PathBuf};

use afklink_core::Config;
use anyhow::{bail, Context, Result};

/// A data directory made ready, and what was decided on the way (for the log, which does not
/// exist yet when this runs: the level is in the config this prepares).
#[derive(Debug)]
pub struct Prepared {
    pub dir: PathBuf,
    /// Whether this run created its `config.json`: a new device.
    pub created: bool,
    pub notes: Vec<String>,
}

/// Make `requested` this process's data directory. `bench` names a new device "<computer> (bench)".
pub fn prepare(requested: &Path, bench: bool) -> Result<Prepared> {
    prepare_with(
        requested,
        &afklink_core::paths::default_dir(),
        &afklink_core::paths::legacy_default_dir(),
        bench,
    )
}

/// [`prepare`], with the owner's data directory and its pre-rename one given (tests).
pub fn prepare_with(
    requested: &Path,
    owner_dir: &Path,
    legacy_owner_dir: &Path,
    bench: bool,
) -> Result<Prepared> {
    std::fs::create_dir_all(requested)
        .with_context(|| format!("create the data directory {}", requested.display()))?;
    let dir = std::path::absolute(requested)
        .with_context(|| format!("resolve the data directory {}", requested.display()))?;
    if same_dir(&dir, owner_dir) || same_dir(&dir, legacy_owner_dir) {
        bail!(
            "--data-dir {} is the owner's own data directory; a bench device needs a directory of \
             its own (omit --data-dir to run as this PC's device)",
            dir.display()
        );
    }
    let mut notes = vec![format!(
        "data directory {} (config, identity and everything else AFKLink keeps on disk)",
        dir.display()
    )];
    let config_path = dir.join("config.json");
    let created = !config_path.exists();
    afklink_core::paths::set_dir_override(dir.clone())?;
    if created {
        let source = owner_config_source(owner_dir, legacy_owner_dir, &mut notes);
        seed_config(&config_path, &source, bench, &mut notes)?;
    } else {
        notes.push(format!(
            "existing device: {} is reused as it is",
            config_path.display()
        ));
    }
    Ok(Prepared {
        dir,
        created,
        notes,
    })
}

/// The owner's `config.json` to read the server from: the current one, or the pre-rename one while
/// the owner's install has not been migrated yet.
fn owner_config_source(
    owner_dir: &Path,
    legacy_owner_dir: &Path,
    notes: &mut Vec<String>,
) -> PathBuf {
    let current = owner_dir.join("config.json");
    let legacy = legacy_owner_dir.join("config.json");
    if !current.exists() && legacy.exists() {
        notes.push(format!(
            "the owner's {} does not exist (not migrated yet); reading the pre-rename {} instead",
            current.display(),
            legacy.display()
        ));
        legacy
    } else {
        current
    }
}

/// Whether two paths name the same directory. A path that does not exist names nothing.
fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Write the new device's `config.json`: fresh device id, the owner's server.
fn seed_config(path: &Path, owner: &Path, bench: bool, notes: &mut Vec<String>) -> Result<()> {
    let mut cfg = Config::load_or_create_at(path.to_path_buf())
        .with_context(|| format!("create {}", path.display()))?;
    notes.push(format!(
        "new device: {} created with device_id {}",
        path.display(),
        cfg.device_id
    ));
    match owner_values(owner) {
        Ok(values) => {
            let mut copied = Vec::new();
            if let Some(url) = values.server_url {
                cfg.server_url = url;
                copied.push("server_url");
            }
            if values.bot_username.is_some() {
                cfg.bot_username = values.bot_username;
                copied.push("bot_username");
            }
            if values.miniapp_short_name.is_some() {
                cfg.miniapp_short_name = values.miniapp_short_name;
                copied.push("miniapp_short_name");
            }
            notes.push(format!(
                "copied [{}] from the owner's {} (read only); server {}",
                copied.join(", "),
                owner.display(),
                cfg.server_url
            ));
        }
        Err(e) => notes.push(format!(
            "the owner's {} was not read ({e:#}); the new device uses this build's default server \
             {} (edit {} to change it)",
            owner.display(),
            cfg.server_url,
            path.display()
        )),
    }
    if bench {
        cfg.name = format!("{} (bench)", cfg.name);
    }
    cfg.save()
        .with_context(|| format!("write {}", path.display()))?;
    notes.push(format!("device name {:?}", cfg.name));
    Ok(())
}

#[derive(Debug, Default)]
struct OwnerValues {
    server_url: Option<String>,
    bot_username: Option<String>,
    miniapp_short_name: Option<String>,
}

/// The three connection values of the owner's config, read without the config loader (which may
/// write the file back) and without anything else.
fn owner_values(path: &Path) -> Result<OwnerValues> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("parse {}", path.display()))?;
    let field = |name: &str| {
        json.get(name)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
    };
    Ok(OwnerValues {
        server_url: field("server_url"),
        bot_username: field("bot_username"),
        miniapp_short_name: field("miniapp_short_name"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use afklink_core::Identity;

    fn scratch(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "afklink-agent-datadir-{}-{nanos}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The whole isolation story in one test, because the override is set once per process.
    #[test]
    fn a_data_dir_is_a_separate_device_that_connects_where_the_owner_does() {
        let owner = scratch("owner");
        std::fs::write(
            owner.join("config.json"),
            "\u{feff}{\"device_id\":\"843eda6a-0000-4000-8000-000000000000\",\
             \"server_url\":\"wss://example.test/ws/agent\",\"name\":\"PC\",\
             \"bot_username\":\"afklink_bot\",\"miniapp_short_name\":\"app\",\"lang\":\"auto\"}",
        )
        .unwrap();
        let owner_before = std::fs::read(owner.join("config.json")).unwrap();
        // The pre-rename directory, still holding the owner's device.
        let legacy = scratch("legacy");

        // The owner's own directory is refused, before anything is overridden — the pre-rename
        // one as well.
        for own in [&owner, &legacy] {
            let e = prepare_with(own, &owner, &legacy, true).unwrap_err();
            assert!(
                e.to_string().contains("owner's own data directory"),
                "{e:#}"
            );
        }
        assert!(afklink_core::paths::dir_override().is_none());

        let bench = scratch("bench").join("device");
        let prepared = prepare_with(&bench, &owner, &legacy, true).unwrap();
        assert!(prepared.created);
        assert!(bench.join("config.json").exists());

        // Everything the agent loads now comes from there.
        let dir = afklink_core::paths::afklink_dir().unwrap();
        assert_eq!(dir, std::path::absolute(&bench).unwrap());
        let cfg = Config::load_or_create().unwrap();
        assert_eq!(cfg.path(), Some(bench.join("config.json").as_path()));
        assert_ne!(cfg.device_id, "843eda6a-0000-4000-8000-000000000000");
        assert_eq!(cfg.server_url, "wss://example.test/ws/agent");
        assert_eq!(cfg.bot_username.as_deref(), Some("afklink_bot"));
        assert!(cfg.name.ends_with(" (bench)"), "{}", cfg.name);
        let identity = Identity::load_or_create().unwrap();
        assert!(bench.join("identity.json").exists());
        assert!(!owner.join("identity.json").exists());
        assert!(!identity.public_key_b64().is_empty());
        assert_eq!(
            std::fs::read(owner.join("config.json")).unwrap(),
            owner_before,
            "the owner's config is only read"
        );

        // A second start reuses the device as it is.
        let again = prepare_with(&bench, &owner, &legacy, true).unwrap();
        assert!(!again.created);
        assert_eq!(Config::load_or_create().unwrap().device_id, cfg.device_id);

        let _ = std::fs::remove_dir_all(&owner);
        let _ = std::fs::remove_dir_all(&legacy);
        let _ = std::fs::remove_dir_all(bench.parent().unwrap());
    }

    #[test]
    fn the_server_comes_from_the_pre_rename_config_until_the_owner_migrates() {
        let owner = scratch("unmigrated").join("AFKLink");
        let legacy = scratch("unmigrated-legacy");
        std::fs::write(legacy.join("config.json"), "{}").unwrap();
        let mut notes = Vec::new();

        let source = owner_config_source(&owner, &legacy, &mut notes);
        assert_eq!(source, legacy.join("config.json"));
        assert_eq!(notes.len(), 1, "{notes:?}");

        // Once the owner's own config exists it wins, whatever is left in the old place.
        std::fs::create_dir_all(&owner).unwrap();
        std::fs::write(owner.join("config.json"), "{}").unwrap();
        let mut notes = Vec::new();
        assert_eq!(
            owner_config_source(&owner, &legacy, &mut notes),
            owner.join("config.json")
        );
        assert!(notes.is_empty(), "{notes:?}");

        let _ = std::fs::remove_dir_all(owner.parent().unwrap());
        let _ = std::fs::remove_dir_all(&legacy);
    }

    #[test]
    fn owner_values_tolerate_what_is_missing() {
        let dir = scratch("partial");
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            r#"{"server_url":"wss://x/ws/agent","bot_username":""}"#,
        )
        .unwrap();
        let v = owner_values(&path).unwrap();
        assert_eq!(v.server_url.as_deref(), Some("wss://x/ws/agent"));
        assert_eq!(v.bot_username, None);
        assert!(owner_values(&dir.join("missing.json")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
