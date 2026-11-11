//! Deliberate breakage for the update rollback tests: compiled ONLY into a
//! test-key build (`mod test_break` is under `cfg(feature = "updater-test-key")` in `lib.rs`; a test
//! in `updater::pubkey` holds that), never into a production one.
//!
//! **The server address.** `release-build.ts --test-key --break server-url=<url>` builds with
//! [`SERVER_URL_VAR`] set: the signaling socket then goes to that address instead of config.json's
//! `server_url` — so the new version never connects, and the watchdog rolls it back after its 180 s.
//! An installed PC keeps its `server_url` in config.json, so changing the build's default address
//! would change nothing; and config.json is not touched here either: the way is a separate entry
//! held in memory ([`afklink_core::entry::Entry::in_memory`]: no `entry.json` written), given to the
//! agent alone. The version restored by the rollback reads config.json and `entry.json` as they
//! were. The updater, «Отправить логи» and the start failure beacon keep the shared entry: the broken
//! build can still be seen and still report.

use std::sync::Arc;

use afklink_core::entry::Entry;

/// The build-time variable with the address to break the signaling socket with (`release-build.ts
/// --break server-url=<url>`); empty or unset — no breakage.
pub(crate) const SERVER_URL_VAR: &str = "AFKLINK_TEST_BREAK_SERVER_URL";

/// [`SERVER_URL_VAR`] as this build was compiled with it.
const SERVER_URL: &str = match option_env!("AFKLINK_TEST_BREAK_SERVER_URL") {
    Some(url) => url,
    None => "",
};

/// The broken address, when one was given: trimmed, non-empty.
fn broken(raw: &str) -> Option<&str> {
    Some(raw.trim()).filter(|url| !url.is_empty())
}

/// The way the agent's signaling socket goes: `shared` (config.json's `server_url`), or — when this
/// test build was compiled with a broken address — an in-memory entry for that address alone, with a
/// warning at every start.
pub(crate) fn signaling_entry(shared: &Arc<Entry>, configured: &str) -> Arc<Entry> {
    match broken(SERVER_URL) {
        Some(url) => {
            tracing::warn!(
                broken = url,
                configured,
                var = SERVER_URL_VAR,
                "TEST BUILD: the signaling socket is deliberately broken — it goes to {url} instead \
                 of {configured} (config.json is not changed); a rollback test, never a release"
            );
            Arc::new(Entry::in_memory(url))
        }
        None => {
            tracing::debug!(
                var = SERVER_URL_VAR,
                "test build: no broken server address; the signaling socket goes the usual way"
            );
            Arc::clone(shared)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_given_address_breaks_the_socket() {
        assert_eq!(broken(""), None);
        assert_eq!(broken("  "), None);
        assert_eq!(
            broken(" wss://api.afklink.app/ws/broken "),
            Some("wss://api.afklink.app/ws/broken")
        );
    }

    #[test]
    fn a_broken_address_gets_its_own_entry_and_none_the_shared_one() {
        let shared = Arc::new(Entry::in_memory("wss://api.afklink.app/ws/agent"));
        let entry = signaling_entry(&shared, "wss://api.afklink.app/ws/agent");
        if broken(SERVER_URL).is_some() {
            assert!(!Arc::ptr_eq(&entry, &shared));
            assert_eq!(
                entry
                    .url_of(afklink_core::entry::Endpoint::Primary)
                    .to_string(),
                SERVER_URL.trim()
            );
        } else {
            assert!(Arc::ptr_eq(&entry, &shared));
        }
    }
}
