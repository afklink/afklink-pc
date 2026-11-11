//! The self-update's check and download end to end, without the network: the app's own requests
//! (`updater::fetch`) against a local HTTP server serving a manifest and an "exe" signed with a
//! throwaway minisign key (what `cargo tauri signer` makes, made here with the same `minisign`
//! crate), and the download's progress as the Settings section gets it. Both requests name the
//! build in their `User-Agent`. Nothing is installed. The manifest's own limits too: its byte cap
//! (announced, chunked, endless), its time limit (a drip), https only.
//!
//! An integration test rather than a unit test: the requests run on Tauri's async runtime, and a
//! binary that links the Tauri runtime starts only with the Common Controls manifest, which
//! `build.rs` gives the integration tests alone.

#![allow(clippy::unwrap_used, reason = "test")]

use std::io::{Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afklink_app_lib::updater_testing::{self as fetch, DownloadError};
use base64::Engine;
use semver::Version;
use sha2::{Digest, Sha256};
use tauri::Url;

/// BLAKE2b-512 and the algorithm flip (shared with `src/updater/manifest.rs`'s unit tests).
#[path = "support/blake2b.rs"]
mod blake2b;

/// What a release build sends; the backend and Caddy's log read it.
const USER_AGENT: &str = "AFKLink/0.1.0 (release)";

/// The request heads a test server saw, one string per request.
type Seen = Arc<Mutex<Vec<String>>>;

/// Serve `routes` (path → body) on 127.0.0.1 until the test process ends; the base URL and what it
/// saw.
fn serve(routes: Vec<(String, Vec<u8>)>) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Seen = Arc::default();
    let record = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut head = Vec::new();
            let mut chunk = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&chunk[..n]),
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
            record.lock().unwrap().push(head);
            let (status, body) = routes
                .iter()
                .find(|(p, _)| *p == path)
                .map_or(("404 Not Found", &b""[..]), |(_, b)| {
                    ("200 OK", b.as_slice())
                });
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(body);
        }
    });
    (base, seen)
}

/// The `User-Agent` of each request `seen` holds.
fn user_agents(seen: &Seen) -> Vec<String> {
    seen.lock()
        .unwrap()
        .iter()
        .filter_map(|head| {
            head.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("user-agent")
                    .then(|| value.trim().to_string())
            })
        })
        .collect()
}

struct Key {
    pair: minisign::KeyPair,
    /// As `updater.pub` holds it: base64 of the `.pub` file.
    public: String,
}

fn key() -> Key {
    let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let public =
        base64::engine::general_purpose::STANDARD.encode(pair.pk.to_box().unwrap().to_string());
    Key { pair, public }
}

/// A `.sig` with `comment` as its trusted comment (base64 of the minisign signature file).
fn sign_comment(key: &Key, bytes: &[u8], comment: &str) -> String {
    let sig = minisign::sign(
        Some(&key.pair.pk),
        &key.pair.sk,
        Cursor::new(bytes),
        Some(comment),
        Some("signature from tauri secret key"),
    )
    .unwrap();
    base64::engine::general_purpose::STANDARD.encode(sig.to_string())
}

/// The trusted comment `cargo tauri signer sign --app-version <version>` writes for `file`.
fn comment(file: &str, version: &str) -> String {
    format!("timestamp:1790000000\tfile:{file}\tversion:{version}")
}

/// A `.sig` as `release-build.ts` makes it: `file` signed with `--app-version <version>`.
fn sign(key: &Key, bytes: &[u8], file: &str, version: &str) -> String {
    sign_comment(key, bytes, &comment(file, version))
}

/// `latest.json` as `release-build.ts` writes it.
fn manifest(version: &str, url: &str, signature: &str, sha256: &str, size: usize) -> Vec<u8> {
    manifest_with(
        version,
        serde_json::json!({ "signature": signature, "url": url, "sha256": sha256, "size": size }),
    )
}

/// `latest.json` with `entry` as its `windows-x86_64` platform — for this build's world: in a
/// test-key build (`--features updater-test-key`) with the test manifest's marker, which such a
/// build requires (`manifest::check_world`), so these tests run in either build.
fn manifest_with(version: &str, entry: serde_json::Value) -> Vec<u8> {
    manifest_marked(version, entry, fetch::TEST_SIGNING_KEY)
}

/// `latest.json` with `entry`, with the test marker (`afklink_test_key: true`) or without it.
fn manifest_marked(version: &str, entry: serde_json::Value, test_marker: bool) -> Vec<u8> {
    let mut m = serde_json::json!({
        "version": version,
        "notes": "- Обновляется сам",
        "pub_date": "2026-09-28T20:15:07Z",
        "platforms": { "windows-x86_64": entry }
    });
    if test_marker {
        m["afklink_test_key"] = serde_json::Value::Bool(true);
    }
    serde_json::to_vec(&m).unwrap()
}

/// The build that checks: 0.1.0.
fn current() -> Version {
    Version::new(0, 1, 0)
}

fn lower_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Serve one release, `exe` signed with `signer` under the trusted comment `signed`; check with
/// `trusted`; download.
fn round_trip(
    signer: &Key,
    trusted: &Key,
    version: &str,
    signed: &str,
    announced_sha: Option<&str>,
) -> (Option<String>, Option<Result<Vec<u8>, DownloadError>>) {
    let exe = b"MZ the new AFKLink".to_vec();
    let name = format!("AFKLink-{version}.exe");
    let sig = sign_comment(signer, &exe, signed);
    let sha = announced_sha.map_or_else(|| lower_sha256(&exe), str::to_string);
    // The manifest's URL must name the server's address, known only once it listens: two servers,
    // the exe first.
    let (exe_base, exe_seen) = serve(vec![(format!("/{name}"), exe.clone())]);
    let body = manifest(
        version,
        &format!("{exe_base}/{name}"),
        &sig,
        &sha,
        exe.len(),
    );
    let (base, seen) = serve(vec![("/latest.json".to_string(), body)]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();

    let result = tauri::async_runtime::block_on(async {
        let checked = fetch::check(&trusted.public, &endpoint, &current(), USER_AGENT, LOCAL)
            .await
            .unwrap();
        let remote = checked.remote.map(|v| v.to_string());
        let downloaded = match checked.update {
            Some(update) => {
                // What the window's progress is made of: every chunk, with the announced size.
                let mut heard: Vec<(u64, Option<u64>)> = Vec::new();
                let result =
                    fetch::download(&update, &trusted.public, LOCAL, &mut |received, total| {
                        heard.push((received, total));
                    })
                    .await;
                if !exe_seen.lock().unwrap().is_empty() {
                    let len = exe.len() as u64;
                    assert_eq!(heard.last(), Some(&(len, Some(len))), "{heard:?}");
                    assert!(heard.windows(2).all(|w| w[0].0 <= w[1].0), "{heard:?}");
                }
                Some(result.map(|d| {
                    assert_eq!(d.version.to_string(), version);
                    assert_eq!(d.sha256, lower_sha256(&exe).to_uppercase());
                    d.bytes
                }))
            }
            None => None,
        };
        (remote, downloaded)
    });
    // The check and the download name the build, not the plugin.
    assert_eq!(user_agents(&seen), [USER_AGENT]);
    let downloaded = user_agents(&exe_seen);
    // One download when there is an update — none when the signature names another key than the
    // one trusted: refused before the exe is fetched.
    assert_eq!(
        downloaded.len(),
        usize::from(result.1.is_some() && signer.public == trusted.public),
        "downloads"
    );
    assert!(
        downloaded.iter().all(|ua| ua == USER_AGENT),
        "{downloaded:?}"
    );
    // The manifest is asked for as JSON, the exe as the plugin asks for it.
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|head| header(head, "accept").as_deref() == Some("application/json")),
        "{:?}",
        seen.lock().unwrap()
    );
    assert!(
        exe_seen
            .lock()
            .unwrap()
            .iter()
            .all(|head| header(head, "accept").as_deref() == Some("application/octet-stream")),
        "{:?}",
        exe_seen.lock().unwrap()
    );
    result
}

/// The value of header `name` in a request head.
fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (n, value) = line.split_once(':')?;
        n.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

/// The app's limits, with plain http to this machine allowed and no proxy: the tests' servers are
/// plain http on 127.0.0.1 ([`fetch::Limits::plain_http_loopback`], [`fetch::Limits::no_proxy`]).
const LOCAL: fetch::Limits = fetch::Limits {
    plain_http_loopback: true,
    no_proxy: true,
    ..fetch::LIMITS
};

#[test]
fn our_signed_release_is_found_downloaded_and_verified() {
    let k = key();
    let (remote, downloaded) = round_trip(
        &k,
        &k,
        "0.1.1",
        &comment("AFKLink-0.1.1.exe", "0.1.1"),
        None,
    );
    assert_eq!(remote.as_deref(), Some("0.1.1"));
    assert_eq!(downloaded.unwrap().unwrap(), b"MZ the new AFKLink");
}

/// What a rejection says, or a panic naming what came instead.
fn rejected(downloaded: Option<Result<Vec<u8>, DownloadError>>) -> String {
    match downloaded.expect("an update was found") {
        Err(DownloadError::Rejected(why)) => why,
        other => unreachable!("expected a rejection, got {:?}", other.map(|b| b.len())),
    }
}

/// A signature by another key is refused before its exe is fetched (round_trip asserts no exe
/// request when the keys differ).
#[test]
fn a_release_signed_with_another_key_is_rejected() {
    let ours = key();
    let theirs = key();
    let (_, downloaded) = round_trip(
        &theirs,
        &ours,
        "0.1.1",
        &comment("AFKLink-0.1.1.exe", "0.1.1"),
        None,
    );
    let why = rejected(downloaded);
    assert!(
        why.starts_with("signature: made with key")
            && why.contains(&format!("not {}'s", fetch::KEY_FILE)),
        "{why}"
    );
}

/// The test key and the production key, as throwaway keys: a release signed with the "test" key is
/// refused by a client holding the "production" one before its exe is fetched, and the other way
/// round (round_trip asserts no exe request when the keys differ) — a broken test build never
/// reaches a production copy, and a test build never installs a release.
#[test]
fn a_test_signed_release_and_a_production_client_never_meet() {
    let production = key();
    let test = key();
    for (signer, trusted) in [(&test, &production), (&production, &test)] {
        let (remote, downloaded) = round_trip(
            signer,
            trusted,
            "0.7.2",
            &comment("AFKLink-0.7.2.exe", "0.7.2"),
            None,
        );
        assert_eq!(remote.as_deref(), Some("0.7.2"));
        let why = rejected(downloaded);
        assert!(why.starts_with("signature: made with key"), "{why}");
    }
}

/// The manifest's world marker end to end: a TEST manifest (`afklink_test_key: true`, what
/// `release-build.ts --test-key` writes) offered to a production build — say, copied over the real
/// `latest.json` by mistake — is refused at the check, its exe never asked for, even when the
/// signature is by the very key the build trusts; and a test-key build refuses a manifest without
/// the marker the same way.
#[test]
fn a_manifest_of_the_other_world_is_refused_before_anything_is_downloaded() {
    let k = key();
    let exe = b"MZ some build".to_vec();
    let name = "AFKLink-0.7.2.exe";
    let sig = sign(&k, &exe, name, "0.7.2");
    let (exe_base, exe_seen) = serve(vec![(format!("/{name}"), exe.clone())]);
    let entry = serde_json::json!({
        "signature": sig,
        "url": format!("{exe_base}/{name}"),
        "sha256": lower_sha256(&exe),
        "size": exe.len(),
    });
    // The other world's manifest: marked for a production build, unmarked for a test-key one.
    let other = manifest_marked("0.7.2", entry.clone(), !fetch::TEST_SIGNING_KEY);
    let (base, seen) = serve(vec![("/latest.json".to_string(), other)]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    let why = tauri::async_runtime::block_on(fetch::check(
        &k.public,
        &endpoint,
        &current(),
        USER_AGENT,
        LOCAL,
    ))
    .err()
    .expect("the other world's manifest is refused");
    if fetch::TEST_SIGNING_KEY {
        assert!(why.contains("takes only a TEST manifest"), "{why}");
    } else {
        assert!(
            why.contains("TEST manifest (afklink_test_key: true)"),
            "{why}"
        );
    }
    assert_eq!(
        user_agents(&seen).len(),
        1,
        "the manifest was asked for once"
    );
    assert!(exe_seen.lock().unwrap().is_empty(), "the exe was asked for");

    // This build's own world, the same release otherwise: found.
    let own = manifest_marked("0.7.2", entry, fetch::TEST_SIGNING_KEY);
    let (base, _) = serve(vec![("/latest.json".to_string(), own)]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    let checked = tauri::async_runtime::block_on(fetch::check(
        &k.public,
        &endpoint,
        &current(),
        USER_AGENT,
        LOCAL,
    ))
    .unwrap();
    assert_eq!(checked.update.map(|u| u.version).as_deref(), Some("0.7.2"));
}

/// The key line of a key file's text (`updater.pub`, `updater-test.pub`), if it holds one.
fn key_line_of(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
}

/// The key id bytes of a key line (base64 of the `.pub` file: `Ed` ‖ key id ‖ key on its 2nd line).
fn key_id_of(line: &str) -> [u8; 8] {
    let text = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(line)
            .unwrap(),
    )
    .unwrap();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(text.lines().nth(1).unwrap().trim())
        .unwrap();
    raw[2..10].try_into().unwrap()
}

/// `signature` (a `.sig`, base64) naming `key_id` as its signer instead: what a signature by that
/// key looks like to the pre-check, which reads the id alone (it would not verify — it is never
/// fetched far enough to try).
fn naming_key(signature: &str, key_id: [u8; 8]) -> String {
    let text = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(signature)
            .unwrap(),
    )
    .unwrap();
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(lines[1].trim())
        .unwrap();
    raw[2..10].copy_from_slice(&key_id);
    lines[1] = base64::engine::general_purpose::STANDARD.encode(raw);
    base64::engine::general_purpose::STANDARD.encode(lines.join("\n"))
}

/// The real files: a release whose signature names `updater-test.pub`'s key is refused by a
/// client holding `updater.pub`'s, before any exe request — and the live production release
/// (0.7.1, signed with updater.pub's key) by a client holding `updater-test.pub`'s. Until the test
/// key is made (`bun scripts/release-test-key.ts`) `updater-test.pub` holds only comments: nothing
/// to check yet.
#[test]
fn the_real_test_key_and_production_key_refuse_each_other_before_downloading() {
    let production = key_line_of(include_str!("../updater.pub")).unwrap();
    let Some(test) = key_line_of(include_str!("../updater-test.pub")) else {
        eprintln!("updater-test.pub holds no key yet: nothing to check");
        return;
    };
    assert_ne!(key_id_of(&test), key_id_of(&production));

    // Signed "by the test key", served to a production client.
    let exe = b"MZ a broken test build".to_vec();
    let name = "AFKLink-0.7.2.exe";
    let sig = naming_key(&sign(&key(), &exe, name, "0.7.2"), key_id_of(&test));
    let (exe_base, exe_seen) = serve(vec![(format!("/{name}"), exe.clone())]);
    let body = manifest(
        "0.7.2",
        &format!("{exe_base}/{name}"),
        &sig,
        &lower_sha256(&exe),
        exe.len(),
    );
    let (base, _) = serve(vec![("/latest.json".to_string(), body)]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    let downloaded = tauri::async_runtime::block_on(async {
        let checked = fetch::check(&production, &endpoint, &current(), USER_AGENT, LOCAL)
            .await
            .unwrap();
        let update = checked.update.expect("0.7.2 is newer than 0.1.0");
        fetch::download(&update, &production, LOCAL, &mut |_, _| {}).await
    });
    match downloaded {
        Err(DownloadError::Rejected(why)) => assert!(why.contains("made with key"), "{why}"),
        other => unreachable!("expected a refusal, got {:?}", other.map(|d| d.bytes.len())),
    }
    assert!(
        exe_seen.lock().unwrap().is_empty(),
        "the test-signed exe was fetched"
    );

    // The live production release, offered to a test-key client.
    const LIVE: &[u8] = include_bytes!("support/latest-0.7.1.json");
    let (base, _) = serve(vec![("/latest.json".to_string(), LIVE.to_vec())]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    if fetch::TEST_SIGNING_KEY {
        // A test-key build refuses the live manifest already: it carries no test marker.
        let why = tauri::async_runtime::block_on(fetch::check(
            &test,
            &endpoint,
            &Version::new(0, 7, 0),
            USER_AGENT,
            LOCAL,
        ))
        .err()
        .expect("the live manifest refused by a test-key build");
        assert!(why.contains("takes only a TEST manifest"), "{why}");
        return;
    }
    let release = tauri::async_runtime::block_on(fetch::check(
        &test,
        &endpoint,
        &Version::new(0, 7, 0),
        USER_AGENT,
        LOCAL,
    ))
    .unwrap()
    .update
    .expect("0.7.1 is newer than 0.7.0");
    let (exe_base, served) = serve_exe(
        "/AFKLink-0.7.1.exe",
        Framing::Length(10),
        b"MZ not 0.7".to_vec(),
        false,
    );
    let local = [Url::parse(&format!("{exe_base}/AFKLink-0.7.1.exe")).unwrap()];
    match tauri::async_runtime::block_on(fetch::download_any(
        &release,
        &test,
        &local,
        LOCAL,
        &mut |_, _| {},
    )) {
        Err(DownloadError::Rejected(why)) => assert!(why.contains("made with key"), "{why}"),
        other => unreachable!("expected a refusal, got {:?}", other.map(|d| d.bytes.len())),
    }
    assert_eq!(
        served.requests.load(Ordering::SeqCst),
        0,
        "the production exe was fetched by a test-key client"
    );
}

/// The key handed to `check` is the only one: the app config's is empty, and an empty key is no
/// key — the check refuses to run at all (fail closed), whatever the server offers.
#[test]
fn without_a_key_nothing_is_checked_or_downloaded() {
    let k = key();
    let exe = b"MZ the new AFKLink".to_vec();
    let name = "AFKLink-0.1.1.exe";
    let sig = sign(&k, &exe, name, "0.1.1");
    let (exe_base, exe_seen) = serve(vec![(format!("/{name}"), exe.clone())]);
    let body = manifest(
        "0.1.1",
        &format!("{exe_base}/{name}"),
        &sig,
        &lower_sha256(&exe),
        exe.len(),
    );
    let (base, seen) = serve(vec![("/latest.json".to_string(), body)]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    for empty in ["", "  "] {
        let result = tauri::async_runtime::block_on(fetch::check(
            empty,
            &endpoint,
            &current(),
            USER_AGENT,
            LOCAL,
        ));
        match result {
            Err(why) => assert!(why.contains("no signature key"), "{why}"),
            Ok(checked) => unreachable!(
                "checked without a key: {:?}",
                checked.update.map(|u| u.version)
            ),
        }
    }
    assert!(seen.lock().unwrap().is_empty(), "no manifest asked for");
    assert!(exe_seen.lock().unwrap().is_empty(), "no exe asked for");
}

#[test]
fn an_older_exe_announced_as_newer_is_rejected() {
    let k = key();
    // 0.1.0's real signature, served as 0.1.1: the signed version gives it away (the plugin's
    // check and ours).
    let (_, downloaded) = round_trip(
        &k,
        &k,
        "0.1.1",
        &comment("AFKLink-0.1.0.exe", "0.1.0"),
        None,
    );
    let why = rejected(downloaded);
    assert!(why.contains("0.1.0"), "{why}");
    // And with only the name to tell (a signature without a matching name): the name.
    let (_, downloaded) = round_trip(
        &k,
        &k,
        "0.1.1",
        &comment("AFKLink-0.1.0.exe", "0.1.1"),
        None,
    );
    let why = rejected(downloaded);
    assert!(why.contains("AFKLink-0.1.0.exe"), "{why}");
}

/// A trial build (`release-build.ts --allow-untagged`) of the very version announced: signed with
/// the production key and the same `version:`, never published — never installed.
#[test]
fn a_trial_build_of_the_announced_version_is_rejected() {
    let k = key();
    for trial in [
        "AFKLink-0.1.1-untagged-abc1234-dirty.exe",
        "AFKLink-0.1.1-untagged-abc1234.exe",
    ] {
        let (_, downloaded) = round_trip(&k, &k, "0.1.1", &comment(trial, "0.1.1"), None);
        let why = rejected(downloaded);
        assert!(why.contains(trial), "{why}");
    }
}

/// A name that looks like a pre-release of the announced version is not its release exe.
#[test]
fn a_pre_release_looking_name_is_rejected() {
    let k = key();
    let (_, downloaded) = round_trip(
        &k,
        &k,
        "0.1.1",
        &comment("AFKLink-0.1.1-beta.1.exe", "0.1.1"),
        None,
    );
    let why = rejected(downloaded);
    assert!(why.contains("AFKLink-0.1.1-beta.1.exe"), "{why}");
}

#[test]
fn a_signature_that_names_no_file_is_rejected() {
    let k = key();
    let (_, downloaded) = round_trip(&k, &k, "0.1.1", "timestamp:1790000000\tversion:0.1.1", None);
    let why = rejected(downloaded);
    assert!(why.contains("names no file"), "{why}");
}

/// No `version:`: refused by this app's own check — the check, the download and its verification
/// are this app's, so no setting in `tauri.conf.json` can drop it (there is no updater plugin).
#[test]
fn a_signature_that_names_no_version_is_rejected() {
    let k = key();
    let bare = "timestamp:1790000000\tfile:AFKLink-0.1.1.exe";
    let (_, downloaded) = round_trip(&k, &k, "0.1.1", bare, None);
    let why = rejected(downloaded);
    assert!(why.contains("names no version"), "{why}");
}

/// The download verifies with the key it is given — the one the check had, `updater.pub`'s in the
/// app: a key other than the signer's, and no key at all, are refused before the exe is asked for
/// (fail closed; no bytes spent on a signature that cannot pass).
#[test]
fn the_download_verifies_with_the_key_it_is_given_and_none_without_one() {
    let ours = key();
    let theirs = key();
    let name = "AFKLink-0.1.1.exe";
    let exe = exe_of(10 * 1024);
    let sig = sign(&ours, &exe, name, "0.1.1");
    let (exe_base, served) = serve_exe(&format!("/{name}"), Framing::Chunked, exe.clone(), false);
    let body = manifest(
        "0.1.1",
        &format!("{exe_base}/{name}"),
        &sig,
        &lower_sha256(&exe),
        exe.len(),
    );
    let (base, _) = serve(vec![("/latest.json".to_string(), body)]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    tauri::async_runtime::block_on(async {
        let update = fetch::check(&ours.public, &endpoint, &current(), USER_AGENT, SHORT)
            .await
            .unwrap()
            .update
            .expect("newer");
        for (key, why, asked) in [
            ("", "no signature key", 0),
            ("  ", "no signature key", 0),
            (theirs.public.as_str(), "made with key", 0),
            ("not a key", "the key", 0),
        ] {
            match fetch::download(&update, key, SHORT, &mut |_, _| {}).await {
                Err(DownloadError::Rejected(e)) => {
                    assert!(
                        e.starts_with("signature") && e.contains(why),
                        "{key:?}: {e}"
                    );
                }
                Err(e) => unreachable!("{key:?}: expected a rejection, got {e}"),
                Ok(d) => unreachable!("{key:?}: accepted {} bytes", d.bytes.len()),
            }
            assert_eq!(served.requests.load(Ordering::SeqCst), asked, "{key:?}");
        }
        // And the right key, for contrast.
        let d = fetch::download(&update, &ours.public, SHORT, &mut |_, _| {})
            .await
            .unwrap_or_else(|e| panic!("ours: {e}"));
        assert_eq!(d.bytes, exe);
    });
}

#[test]
fn a_signature_for_another_version_is_rejected() {
    let k = key();
    let (_, downloaded) = round_trip(
        &k,
        &k,
        "0.1.1",
        &comment("AFKLink-0.1.1.exe", "0.1.2"),
        None,
    );
    let why = rejected(downloaded);
    assert!(why.contains("0.1.2"), "{why}");
}

#[test]
fn a_hash_that_does_not_match_the_manifest_is_rejected() {
    let k = key();
    let wrong = "0".repeat(64);
    let (_, downloaded) = round_trip(
        &k,
        &k,
        "0.1.1",
        &comment("AFKLink-0.1.1.exe", "0.1.1"),
        Some(&wrong),
    );
    match downloaded.unwrap() {
        Err(DownloadError::Rejected(why)) => assert!(why.contains("SHA-256"), "{why}"),
        other => unreachable!("expected a rejection, got {:?}", other.map(|b| b.len())),
    }
}

/// Serve `path` with a body announced as `announced` bytes, sending only `body` of it and then
/// holding the connection silent until the test process ends — what a path that freezes what the
/// server sends after the first kilobytes looks like (as seen on the RU entry). The base URL and
/// what it saw.
fn serve_stalling(path: &str, announced: usize, body: Vec<u8>) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Seen = Arc::default();
    let record = Arc::clone(&seen);
    let path = path.to_string();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut head = Vec::new();
            let mut chunk = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&chunk[..n]),
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let asked = head.split_whitespace().nth(1).unwrap_or("/").to_string();
            record.lock().unwrap().push(head);
            if asked == path {
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {announced}\r\nContent-Type: application/octet-stream\r\n\r\n"
                );
                let _ = stream.write_all(&body);
                let _ = stream.flush();
                // Not a byte more, and the connection stays open.
                held.push(stream);
            } else {
                let _ = write!(
                    stream,
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
        }
    });
    (base, seen)
}

/// Short limits, so a stall is seen in half a second (and a manifest that drips ends in ten).
const SHORT: fetch::Limits = fetch::Limits {
    connect: std::time::Duration::from_secs(5),
    stall: std::time::Duration::from_millis(500),
    max_bytes: fetch::MAX_EXE_BYTES,
    plain_http_loopback: true,
    check_total: std::time::Duration::from_secs(10),
    no_proxy: true,
};

/// The freeze in a download: the exe's first way sends the head and 16 KiB of a 1 MiB body and then
/// nothing — given up at the stall limit, and the same exe comes the other way, verified as always.
#[test]
fn a_download_that_stalls_comes_the_other_way() {
    let k = key();
    let exe: Vec<u8> = (0..(1024 * 1024u32)).map(|i| (i % 251) as u8).collect();
    let name = "AFKLink-0.1.1.exe";
    let sig = sign(&k, &exe, name, "0.1.1");
    let (stalled_base, stalled_seen) =
        serve_stalling(&format!("/{name}"), exe.len(), exe[..16 * 1024].to_vec());
    let (good_base, good_seen) = serve(vec![(format!("/{name}"), exe.clone())]);
    // The manifest names the stalling way, as latest.json names api.afklink.app.
    let body = manifest(
        "0.1.1",
        &format!("{stalled_base}/{name}"),
        &sig,
        &lower_sha256(&exe),
        exe.len(),
    );
    let (base, _) = serve(vec![("/latest.json".to_string(), body)]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    let started = std::time::Instant::now();
    let downloaded = tauri::async_runtime::block_on(async {
        let (checked, used) =
            fetch::check_any(&k.public, &[endpoint], &current(), USER_AGENT, SHORT)
                .await
                .unwrap();
        assert_eq!(used, 0);
        let update = checked.update.expect("0.1.1 is newer");
        let urls = [
            update.download_url.clone(),
            Url::parse(&format!("{good_base}/{name}")).unwrap(),
        ];
        let mut heard: Vec<(u64, Option<u64>)> = Vec::new();
        fetch::download_any(&update, &k.public, &urls, SHORT, &mut |received, total| {
            heard.push((received, total));
        })
        .await
    });
    let downloaded = downloaded.unwrap_or_else(|e| panic!("the other way: {e}"));
    assert_eq!(downloaded.bytes, exe, "the whole exe, verified");
    assert_eq!(
        stalled_seen.lock().unwrap().len(),
        1,
        "the first way was tried"
    );
    assert_eq!(good_seen.lock().unwrap().len(), 1, "then the other");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "the stall limit, not the download's: {:?}",
        started.elapsed()
    );
}

/// The manifest's first way gets no connection, then one whose answer freezes mid-body: the check
/// goes on to the next way and says which answered.
#[test]
fn a_manifest_that_does_not_come_comes_the_other_way() {
    let k = key();
    let exe = b"MZ the new AFKLink".to_vec();
    let sig = sign(&k, &exe, "AFKLink-0.1.1.exe", "0.1.1");
    let body = manifest(
        "0.1.1",
        "http://127.0.0.1:9/AFKLink-0.1.1.exe",
        &sig,
        &lower_sha256(&exe),
        exe.len(),
    );
    // Nobody listening: the local end of a connected client socket.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let held = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let dead = Url::parse(&format!(
        "http://127.0.0.1:{}/latest.json",
        held.local_addr().unwrap().port()
    ))
    .unwrap();
    let (frozen_base, frozen_seen) =
        serve_stalling("/latest.json", body.len(), body[..10].to_vec());
    let frozen = Url::parse(&format!("{frozen_base}/latest.json")).unwrap();
    let (good_base, good_seen) = serve(vec![("/latest.json".to_string(), body)]);
    let good = Url::parse(&format!("{good_base}/latest.json")).unwrap();
    let (checked, used) = tauri::async_runtime::block_on(fetch::check_any(
        &k.public,
        &[dead, frozen, good],
        &current(),
        USER_AGENT,
        SHORT,
    ))
    .unwrap();
    assert_eq!(used, 2, "the third way answered");
    assert_eq!(
        checked.remote.map(|v| v.to_string()).as_deref(),
        Some("0.1.1")
    );
    assert_eq!(frozen_seen.lock().unwrap().len(), 1);
    assert_eq!(good_seen.lock().unwrap().len(), 1);
    drop((held, listener));
}

/// Bytes that are not the release's are never fetched again elsewhere: a rejected signature ends
/// the download, the other way untried.
#[test]
fn a_rejected_download_is_not_tried_the_other_way() {
    let ours = key();
    let theirs = key();
    let exe = b"MZ not ours".to_vec();
    let name = "AFKLink-0.1.1.exe";
    let sig = sign(&theirs, &exe, name, "0.1.1");
    let (first_base, _) = serve(vec![(format!("/{name}"), exe.clone())]);
    let (other_base, other_seen) = serve(vec![(format!("/{name}"), exe.clone())]);
    let body = manifest(
        "0.1.1",
        &format!("{first_base}/{name}"),
        &sig,
        &lower_sha256(&exe),
        exe.len(),
    );
    let (base, _) = serve(vec![("/latest.json".to_string(), body)]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    let result = tauri::async_runtime::block_on(async {
        let (checked, _) =
            fetch::check_any(&ours.public, &[endpoint], &current(), USER_AGENT, LOCAL)
                .await
                .unwrap();
        let update = checked.update.expect("newer");
        let urls = [
            update.download_url.clone(),
            Url::parse(&format!("{other_base}/{name}")).unwrap(),
        ];
        fetch::download_any(&update, &ours.public, &urls, LOCAL, &mut |_, _| {}).await
    });
    match result {
        Err(DownloadError::Rejected(why)) => assert!(why.starts_with("signature"), "{why}"),
        other => unreachable!(
            "expected a rejection, got {:?}",
            other.map(|d| d.bytes.len())
        ),
    }
    assert!(
        other_seen.lock().unwrap().is_empty(),
        "the other way untried"
    );
}

#[test]
fn the_same_or_an_older_version_is_not_an_update() {
    let k = key();
    for version in ["0.1.0", "0.0.9"] {
        let (remote, downloaded) = round_trip(
            &k,
            &k,
            version,
            &comment(&format!("AFKLink-{version}.exe"), version),
            None,
        );
        assert_eq!(remote.as_deref(), Some(version));
        assert!(downloaded.is_none(), "{version}");
    }
}

// ---------- The download's size ----------

/// How a test server frames the exe's body.
#[derive(Debug, Clone, Copy)]
enum Framing {
    /// `Content-Length: n` — `n` need not be what is sent.
    Length(usize),
    /// `Transfer-Encoding: chunked`: no length up front.
    Chunked,
    /// No length at all: the body ends when the server closes the connection.
    Close,
}

/// What a framed exe server did.
#[derive(Default)]
struct Served {
    requests: AtomicUsize,
    /// Body bytes the socket took.
    written: AtomicU64,
    /// A write failed: the client went away before the body ended.
    gone: AtomicBool,
}

/// A request's head, read up to the blank line.
fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Serve `body` at `path` framed as `framing`, in 16 KiB writes — once, or (`endless`) over and over
/// until the client goes away. The base URL and what the server did.
fn serve_exe(path: &str, framing: Framing, body: Vec<u8>, endless: bool) -> (String, Arc<Served>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let served: Arc<Served> = Arc::default();
    let record = Arc::clone(&served);
    let path = path.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let head = read_head(&mut stream);
            if head.split_whitespace().nth(1) != Some(path.as_str()) {
                let _ = write!(
                    stream,
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                continue;
            }
            record.requests.fetch_add(1, Ordering::SeqCst);
            let framing_header = match framing {
                Framing::Length(n) => format!("Content-Length: {n}\r\n"),
                Framing::Chunked => "Transfer-Encoding: chunked\r\n".to_string(),
                Framing::Close => "Connection: close\r\n".to_string(),
            };
            let head_sent = write!(
                stream,
                "HTTP/1.1 200 OK\r\n{framing_header}Content-Type: application/octet-stream\r\n\r\n"
            )
            .is_ok();
            if !head_sent || !send_body(&mut stream, framing, &body, endless, &record) {
                record.gone.store(true, Ordering::SeqCst);
                continue;
            }
            if matches!(framing, Framing::Chunked) {
                let _ = stream.write_all(b"0\r\n\r\n");
            }
            let _ = stream.flush();
            let _ = stream.shutdown(std::net::Shutdown::Write);
        }
    });
    (base, served)
}

/// Write `body` in 16 KiB pieces as `framing` frames it, once or (`endless`) until a write fails;
/// whether it all went out.
fn send_body(
    stream: &mut TcpStream,
    framing: Framing,
    body: &[u8],
    endless: bool,
    served: &Served,
) -> bool {
    loop {
        for piece in body.chunks(16 * 1024) {
            let written = match framing {
                Framing::Chunked => write!(stream, "{:x}\r\n", piece.len())
                    .and_then(|()| stream.write_all(piece))
                    .and_then(|()| stream.write_all(b"\r\n")),
                Framing::Length(_) | Framing::Close => stream.write_all(piece),
            };
            if written.is_err() {
                return false;
            }
            served
                .written
                .fetch_add(piece.len() as u64, Ordering::SeqCst);
        }
        if !endless {
            return true;
        }
    }
}

/// An "exe" of `len` bytes.
fn exe_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// What [`fetch_release`] saw.
struct Fetched {
    result: Result<fetch::Downloaded, DownloadError>,
    /// Every progress call.
    heard: Vec<(u64, Option<u64>)>,
    /// How long the download took.
    took: Duration,
}

/// Check `manifest_body` (as `latest.json`, key `k`) and download what it names with `max_bytes`
/// as the ceiling.
fn fetch_release(k: &Key, manifest_body: Vec<u8>, max_bytes: u64) -> Fetched {
    let (base, _) = serve(vec![("/latest.json".to_string(), manifest_body)]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    tauri::async_runtime::block_on(async {
        let checked = fetch::check(&k.public, &endpoint, &current(), USER_AGENT, SHORT)
            .await
            .unwrap();
        let update = checked.update.expect("newer than 0.1.0");
        let mut heard: Vec<(u64, Option<u64>)> = Vec::new();
        let started = Instant::now();
        // A cut that never comes would otherwise wait out the 15-minute download limit.
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            fetch::download(
                &update,
                &k.public,
                fetch::Limits { max_bytes, ..SHORT },
                &mut |received, total| {
                    heard.push((received, total));
                },
            ),
        )
        .await
        .expect("the download ended within 30 s");
        Fetched {
            result,
            heard,
            took: started.elapsed(),
        }
    })
}

/// What a rejection says, or a panic naming what came instead.
fn rejection(fetched: &Fetched) -> &str {
    match &fetched.result {
        Err(DownloadError::Rejected(why)) => why,
        Err(other) => unreachable!("expected a rejection, got {other}"),
        Ok(d) => unreachable!("expected a rejection, got {} bytes", d.bytes.len()),
    }
}

/// The number before `label` in an overrun's message («N received», «N buffered in all»).
fn number_before(why: &str, label: &str) -> u64 {
    let (before, _) = why.split_once(label).expect(why);
    before.rsplit(' ').next().unwrap().parse().expect(why)
}

/// What the cut let through to the progress: «N received».
fn received_in(why: &str) -> u64 {
    number_before(why, " received")
}

/// What the plugin took off the connection before its future was dropped: «N buffered in all».
fn buffered_in(why: &str) -> u64 {
    number_before(why, " buffered in all")
}

/// Wait (bounded) for the server to see the client go away.
fn wait_gone(served: &Served) -> bool {
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        if served.gone.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// The live `latest.json`: 0.7.1, `.../download/AFKLink-0.7.1.exe`, `size` 35 435 008,
/// trusted comment `timestamp:1792088149\tfile:AFKLink-0.7.1.exe\tversion:0.7.1` — with a small
/// body, served with `Content-Length` equal to the size, chunked, and close-delimited: accepted end
/// to end, the progress hearing every chunk with the totals the server announced.
#[test]
fn the_live_manifest_shape_is_accepted_with_and_without_a_content_length() {
    let k = key();
    let exe = exe_of(200 * 1024 + 7);
    let len = exe.len();
    let name = "AFKLink-0.7.1.exe";
    let sig = sign_comment(
        &k,
        &exe,
        "timestamp:1792088149\tfile:AFKLink-0.7.1.exe\tversion:0.7.1",
    );
    for framing in [Framing::Length(len), Framing::Chunked, Framing::Close] {
        let (exe_base, served) =
            serve_exe(&format!("/download/{name}"), framing, exe.clone(), false);
        let body = manifest_with(
            "0.7.1",
            serde_json::json!({
                "signature": sig,
                "url": format!("{exe_base}/download/{name}"),
                "sha256": lower_sha256(&exe),
                "size": len,
            }),
        );
        let fetched = fetch_release(&k, body, fetch::MAX_EXE_BYTES);
        let downloaded = match &fetched.result {
            Ok(d) => d,
            Err(e) => unreachable!("{framing:?}: {e}"),
        };
        assert_eq!(downloaded.version.to_string(), "0.7.1");
        assert_eq!(downloaded.bytes, exe, "{framing:?}");
        assert_eq!(downloaded.sha256, lower_sha256(&exe).to_uppercase());
        let total = match framing {
            Framing::Length(n) => Some(n as u64),
            Framing::Chunked | Framing::Close => None,
        };
        assert_eq!(
            fetched.heard.last(),
            Some(&(len as u64, total)),
            "{framing:?}"
        );
        assert!(
            fetched.heard.iter().all(|(_, t)| *t == total),
            "{framing:?}"
        );
        assert!(
            fetched.heard.windows(2).all(|w| w[0].0 < w[1].0),
            "every chunk heard: {framing:?}"
        );
        assert_eq!(served.requests.load(Ordering::SeqCst), 1);
        assert!(!served.gone.load(Ordering::SeqCst), "{framing:?}");
    }
}

/// The limit is the manifest's `size` in body bytes: exactly `size` passes (above), `size + 1` is
/// cut — counted as it comes (chunked) or announced (`Content-Length`).
#[test]
fn one_byte_over_the_manifest_size_is_rejected() {
    let k = key();
    let size = 100_000usize;
    let exact = exe_of(size);
    let over = exe_of(size + 1);
    let name = "AFKLink-0.1.1.exe";
    for (body, framing) in [
        (exact.clone(), Framing::Chunked),
        (exact.clone(), Framing::Length(size)),
        (over.clone(), Framing::Chunked),
        (over.clone(), Framing::Length(size + 1)),
    ] {
        let (exe_base, _) = serve_exe(&format!("/{name}"), framing, body.clone(), false);
        // A valid signature of what is sent: only the size can tell.
        let manifest_body = manifest_with(
            "0.1.1",
            serde_json::json!({
                "signature": sign(&k, &body, name, "0.1.1"),
                "url": format!("{exe_base}/{name}"),
                "sha256": lower_sha256(&body),
                "size": size,
            }),
        );
        let fetched = fetch_release(&k, manifest_body, fetch::MAX_EXE_BYTES);
        if body.len() == size {
            assert!(
                fetched.result.is_ok(),
                "{framing:?}: exactly the size passes"
            );
            continue;
        }
        let why = rejection(&fetched);
        assert!(
            why.contains("more than the 100000 bytes allowed (manifest size)"),
            "{framing:?}: {why}"
        );
        match framing {
            Framing::Length(n) => assert!(why.contains(&format!("{n} announced")), "{why}"),
            _ => assert!(why.contains("100001 received"), "{why}"),
        }
        // Never shown as progress past the size.
        assert!(
            fetched.heard.iter().all(|(r, _)| *r <= size as u64),
            "{:?}",
            fetched.heard.last()
        );
    }
}

/// The most one chunk off the connection may carry past what was kept (hyper reads at most some
/// 400 KiB at a time; 8–16 KiB measured over loopback): the crossing chunk is counted, never kept.
const ONE_CHUNK: u64 = 1024 * 1024;

/// A server that sends far more than the manifest's size (here: without end, no length) is cut
/// while the body is still coming — at the chunk that crosses the size, nothing past it kept — and
/// sees the client go. (The plugin's download drains whatever the connection has ready within one
/// poll: 98 KiB to 0.5 MiB here, up to the whole 100 MiB announced in the test below.)
#[test]
fn a_body_longer_than_the_manifest_size_is_cut_before_it_ends() {
    let k = key();
    let size = 64 * 1024usize;
    let name = "AFKLink-0.1.1.exe";
    let (exe_base, served) = serve_exe(&format!("/{name}"), Framing::Close, exe_of(size), true);
    let manifest_body = manifest_with(
        "0.1.1",
        serde_json::json!({
            "signature": sign(&k, &exe_of(size), name, "0.1.1"),
            "url": format!("{exe_base}/{name}"),
            "sha256": lower_sha256(&exe_of(size)),
            "size": size,
        }),
    );
    let fetched = fetch_release(&k, manifest_body, fetch::MAX_EXE_BYTES);
    let why = rejection(&fetched);
    assert!(why.contains("(manifest size)"), "{why}");
    let received = received_in(why);
    let buffered = buffered_in(why);
    // The chunk that crossed the limit is counted, not shown: progress never passed the size.
    assert!(received > size as u64, "{why}");
    assert!(
        fetched.heard.iter().all(|(r, _)| *r <= size as u64),
        "{:?}",
        fetched.heard.last()
    );
    // Nothing past the size is kept; what came off the wire is what was kept plus the one chunk.
    assert!(buffered <= size as u64, "kept past the size: {why}");
    assert!(received - buffered <= ONE_CHUNK, "{why}");
    assert!(fetched.took < Duration::from_secs(10), "{:?}", fetched.took);
    assert!(wait_gone(&served), "the server saw the client go away");
    let written = served.written.load(Ordering::SeqCst);
    eprintln!(
        "cut: limit {size}, received {received}, buffered {buffered}, server wrote {written}, \
         took {:?}",
        fetched.took
    );
}

/// A `Content-Length` above the limit is cut on the answer's head, before a byte of the body is
/// read: no progress shown at all.
#[test]
fn a_content_length_above_the_limit_is_cut_before_the_body() {
    let k = key();
    let size = 64 * 1024usize;
    let name = "AFKLink-0.1.1.exe";
    // Far more announced than the server gets out before the client is gone.
    let announced = 100 * 1024 * 1024usize;
    let (exe_base, served) = serve_exe(
        &format!("/{name}"),
        Framing::Length(announced),
        exe_of(size),
        true,
    );
    let manifest_body = manifest_with(
        "0.1.1",
        serde_json::json!({
            "signature": sign(&k, &exe_of(size), name, "0.1.1"),
            "url": format!("{exe_base}/{name}"),
            "sha256": lower_sha256(&exe_of(size)),
            "size": size,
        }),
    );
    let fetched = fetch_release(&k, manifest_body, fetch::MAX_EXE_BYTES);
    let why = rejection(&fetched);
    assert!(why.contains(&format!("{announced} announced")), "{why}");
    assert!(fetched.heard.is_empty(), "{:?}", fetched.heard);
    assert!(fetched.took < Duration::from_secs(10), "{:?}", fetched.took);
    assert!(wait_gone(&served), "the server saw the client go away");
    assert_eq!(received_in(why), 0, "{why}");
    assert_eq!(buffered_in(why), 0, "{why}");
    let written = served.written.load(Ordering::SeqCst);
    eprintln!("cut (Content-Length): limit {size}, server wrote {written}");
}

/// `sha256` and `size` are required (release-build always writes both): a manifest without either
/// — or in the plugin's flat form, which has neither — is refused before the exe is asked for.
#[test]
fn a_manifest_without_sha256_or_size_is_refused_before_downloading() {
    let k = key();
    let name = "AFKLink-0.1.1.exe";
    let exe = exe_of(10 * 1024);
    let sig = sign(&k, &exe, name, "0.1.1");
    for (missing, why) in [
        ("sha256", "no sha256"),
        ("size", "no size"),
        ("both", "no platforms"),
    ] {
        let (exe_base, served) =
            serve_exe(&format!("/{name}"), Framing::Chunked, exe.clone(), false);
        let url = format!("{exe_base}/{name}");
        let manifest_body = match missing {
            "sha256" => manifest_with(
                "0.1.1",
                serde_json::json!({ "signature": sig, "url": url, "size": exe.len() }),
            ),
            "size" => manifest_with(
                "0.1.1",
                serde_json::json!({ "signature": sig, "url": url, "sha256": lower_sha256(&exe) }),
            ),
            // The flat (dynamic) form: url and signature at the top, no platforms.
            // With this build's world marker, as `manifest_with` gives it.
            _ => serde_json::to_vec(&serde_json::json!({
                "version": "0.1.1",
                "notes": "",
                "pub_date": "2026-09-28T20:15:07Z",
                "url": url,
                "signature": sig,
                "afklink_test_key": fetch::TEST_SIGNING_KEY,
            }))
            .unwrap(),
        };
        let fetched = fetch_release(&k, manifest_body, fetch::MAX_EXE_BYTES);
        let refusal = rejection(&fetched);
        assert!(refusal.contains(why), "{missing}: {refusal}");
        assert_eq!(
            served.requests.load(Ordering::SeqCst),
            0,
            "{missing}: the exe was not asked for"
        );
        assert!(fetched.heard.is_empty(), "{missing}");
    }
}

/// A manifest naming more than any release may weigh is refused before a byte is fetched.
#[test]
fn a_manifest_size_above_the_ceiling_is_refused_before_downloading() {
    let k = key();
    let name = "AFKLink-0.1.1.exe";
    for (ceiling, size) in [
        (256 * 1024u64, 256 * 1024u64 + 1),
        (fetch::MAX_EXE_BYTES, fetch::MAX_EXE_BYTES + 1),
    ] {
        let (exe_base, served) = serve_exe(&format!("/{name}"), Framing::Close, exe_of(10), false);
        let manifest_body = manifest_with(
            "0.1.1",
            serde_json::json!({
                "signature": sign(&k, &exe_of(10), name, "0.1.1"),
                "url": format!("{exe_base}/{name}"),
                "sha256": lower_sha256(&exe_of(10)),
                "size": size,
            }),
        );
        let fetched = fetch_release(&k, manifest_body, ceiling);
        let why = rejection(&fetched);
        assert!(why.contains("more than any release may weigh"), "{why}");
        assert_eq!(served.requests.load(Ordering::SeqCst), 0, "nothing fetched");
        assert!(fetched.heard.is_empty());
    }
}

/// The realistic trial-build attack: the manifest announces the trial's own version
/// (`0.1.1-untagged-abc1234[-dirty]`, a SemVer pre-release newer than 0.1.0), so its `file:`
/// `AFKLink-0.1.1-untagged-abc1234.exe` matches the announced name exactly; the signer wrote
/// `version:0.1.1`. Refused by this app's own check of the signed version (the download and its
/// checks are this app's) — and so is a trial signature from a signer that wrote no `version:` at
/// all.
#[test]
fn a_trial_build_announced_as_its_own_version_is_rejected() {
    let k = key();
    for announced in ["0.1.1-untagged-abc1234", "0.1.1-untagged-abc1234-dirty"] {
        let file = format!("AFKLink-{announced}.exe");
        let (remote, downloaded) = round_trip(&k, &k, announced, &comment(&file, "0.1.1"), None);
        assert_eq!(remote.as_deref(), Some(announced), "found as an update");
        let why = rejected(downloaded);
        assert!(
            why.contains(&format!(
                "the signature is for version 0.1.1, the manifest announces {announced}"
            )),
            "{why}"
        );
        let (_, downloaded) = round_trip(
            &k,
            &k,
            announced,
            &format!("timestamp:1790000000\tfile:{file}"),
            None,
        );
        let why = rejected(downloaded);
        assert!(
            why.contains(&format!(
                "the signature names no version (expected {announced})"
            )),
            "{why}"
        );
    }
}

/// `download_any`: the first way stalls (a transfer failure, so the next is tried), the second
/// sends more than the manifest's size — cut and rejected, and the third way is never tried.
#[test]
fn a_size_cut_on_the_second_way_ends_the_download() {
    let k = key();
    let size = 64 * 1024usize;
    let name = "AFKLink-0.1.1.exe";
    let exe = exe_of(size);
    let sig = sign(&k, &exe, name, "0.1.1");
    let (stalled_base, stalled_seen) =
        serve_stalling(&format!("/{name}"), size, exe[..1024].to_vec());
    let (endless_base, endless) = serve_exe(&format!("/{name}"), Framing::Close, exe.clone(), true);
    let (good_base, good_seen) = serve(vec![(format!("/{name}"), exe.clone())]);
    let body = manifest(
        "0.1.1",
        &format!("{stalled_base}/{name}"),
        &sig,
        &lower_sha256(&exe),
        size,
    );
    let (base, _) = serve(vec![("/latest.json".to_string(), body)]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    let result = tauri::async_runtime::block_on(async {
        let (checked, _) = fetch::check_any(&k.public, &[endpoint], &current(), USER_AGENT, SHORT)
            .await
            .unwrap();
        let update = checked.update.expect("newer");
        let urls = [
            update.download_url.clone(),
            Url::parse(&format!("{endless_base}/{name}")).unwrap(),
            Url::parse(&format!("{good_base}/{name}")).unwrap(),
        ];
        tokio::time::timeout(
            Duration::from_secs(30),
            fetch::download_any(&update, &k.public, &urls, SHORT, &mut |_, _| {}),
        )
        .await
        .expect("the download ended within 30 s")
    });
    match result {
        Err(DownloadError::Rejected(why)) => {
            assert!(why.contains("(manifest size)"), "{why}");
        }
        Err(other) => unreachable!("expected a rejection, got {other}"),
        Ok(d) => unreachable!("expected a rejection, got {} bytes", d.bytes.len()),
    }
    assert_eq!(
        stalled_seen.lock().unwrap().len(),
        1,
        "the first way was tried"
    );
    assert_eq!(
        endless.requests.load(Ordering::SeqCst),
        1,
        "then the second"
    );
    assert!(good_seen.lock().unwrap().is_empty(), "the third never");
}

// ---------- Signature algorithm, https, answers ----------

/// The algorithm-flip attack end to end: a genuine prehashed (`ED`) signature of the real exe,
/// turned to legacy `Ed` (bytes the global signature does not cover), served with the exe's
/// 64-byte BLAKE2b-512 digest as "the exe" and a manifest whose size and SHA-256 match the digest.
/// With legacy signatures allowed (the plugin's `verify_signature`) this passed every check;
/// refused.
#[test]
fn a_prehashed_signature_flipped_to_legacy_over_the_digest_is_rejected() {
    let k = key();
    let name = "AFKLink-0.1.1.exe";
    let real = exe_of(300 * 1024);
    let genuine = sign(&k, &real, name, "0.1.1");
    let flipped = blake2b::flip_to_legacy(&genuine);
    let digest = blake2b::blake2b_512(&real).to_vec();
    let (exe_base, served) = serve_exe(
        &format!("/{name}"),
        Framing::Length(64),
        digest.clone(),
        false,
    );
    let manifest_body = manifest_with(
        "0.1.1",
        serde_json::json!({
            "signature": flipped,
            "url": format!("{exe_base}/{name}"),
            "sha256": lower_sha256(&digest),
            "size": digest.len(),
        }),
    );
    let fetched = fetch_release(&k, manifest_body, fetch::MAX_EXE_BYTES);
    let why = rejection(&fetched);
    assert!(why.starts_with("signature: does not verify"), "{why}");
    assert_eq!(
        served.requests.load(Ordering::SeqCst),
        1,
        "fetched, then refused"
    );
    // The digest is BLAKE2b-512 indeed (RFC 7693's vector; the unit test
    // `manifest::…flipped_to_legacy…` shows minisign-verify accepting it with legacy allowed).
    let hex: String = blake2b::blake2b_512(b"abc")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hex, blake2b::ABC);
}

/// Serve `path` with `status` (e.g. `"302 Found"`) and `headers` (each `Name: value\r\n`), no body.
fn serve_answer(path: &str, status: &str, headers: &str) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Seen = Arc::default();
    let record = Arc::clone(&seen);
    let (path, status, headers) = (path.to_string(), status.to_string(), headers.to_string());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let head = read_head(&mut stream);
            let asked = head.split_whitespace().nth(1) == Some(path.as_str());
            record.lock().unwrap().push(head);
            let status = if asked {
                status.as_str()
            } else {
                "404 Not Found"
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\n{headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
        }
    });
    (base, seen)
}

/// Check a manifest naming `url` (signed `exe`, key `k`) and download from `urls` (`url` first).
fn download_from(
    k: &Key,
    exe: &[u8],
    url: &str,
    others: &[String],
    limits: fetch::Limits,
) -> Result<fetch::Downloaded, DownloadError> {
    let name = "AFKLink-0.1.1.exe";
    let body = manifest(
        "0.1.1",
        url,
        &sign(k, exe, name, "0.1.1"),
        &lower_sha256(exe),
        exe.len(),
    );
    let (base, _) = serve(vec![("/latest.json".to_string(), body)]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    tauri::async_runtime::block_on(async {
        let update = fetch::check(&k.public, &endpoint, &current(), USER_AGENT, SHORT)
            .await
            .unwrap()
            .update
            .expect("newer");
        let mut urls = vec![update.download_url.clone()];
        urls.extend(others.iter().map(|u| Url::parse(u).unwrap()));
        tokio::time::timeout(
            Duration::from_secs(30),
            fetch::download_any(&update, &k.public, &urls, limits, &mut |_, _| {}),
        )
        .await
        .expect("the download ended within 30 s")
    })
}

/// A non-2xx answer for the exe (403, 502) is a transfer failure: the other way is tried, and the
/// exe it brings is accepted. The request carries `Accept: application/octet-stream`.
#[test]
fn a_refused_answer_on_the_first_way_tries_the_other() {
    let k = key();
    let name = "AFKLink-0.1.1.exe";
    let exe = exe_of(20 * 1024);
    for status in ["403 Forbidden", "502 Bad Gateway"] {
        let (bad_base, bad_seen) = serve_answer(&format!("/{name}"), status, "");
        let (good_base, good_seen) = serve(vec![(format!("/{name}"), exe.clone())]);
        let downloaded = download_from(
            &k,
            &exe,
            &format!("{bad_base}/{name}"),
            &[format!("{good_base}/{name}")],
            SHORT,
        )
        .unwrap_or_else(|e| panic!("{status}: {e}"));
        assert_eq!(downloaded.bytes, exe, "{status}");
        assert_eq!(
            bad_seen.lock().unwrap().len(),
            1,
            "{status}: the first way was tried"
        );
        let good = good_seen.lock().unwrap();
        assert_eq!(good.len(), 1, "{status}: then the other");
        assert_eq!(
            header(&good[0], "accept").as_deref(),
            Some("application/octet-stream"),
            "{}",
            good[0]
        );
        assert_eq!(header(&good[0], "user-agent").as_deref(), Some(USER_AGENT));
    }
}

/// The exe only over https: a plain-http address is refused before any request — this machine's
/// too unless the tests' `plain_http_loopback` allows it, and another host's even then.
#[test]
fn a_plain_http_exe_address_is_refused_before_any_request() {
    let k = key();
    let name = "AFKLink-0.1.1.exe";
    let exe = exe_of(1024);
    let (local_base, local_seen) = serve(vec![(format!("/{name}"), exe.clone())]);
    let app_limits = fetch::Limits {
        plain_http_loopback: false,
        ..SHORT
    };
    for (url, limits) in [
        (format!("{local_base}/{name}"), app_limits),
        (format!("http://example.invalid/{name}"), SHORT),
        (format!("http://example.invalid/{name}"), app_limits),
    ] {
        match download_from(&k, &exe, &url, &[], limits) {
            Err(DownloadError::Rejected(why)) => {
                assert!(why.contains("is not https"), "{url}: {why}")
            }
            Err(e) => unreachable!("{url}: expected a refusal before any request, got {e}"),
            Ok(_) => unreachable!("{url}: accepted"),
        }
    }
    assert!(
        local_seen.lock().unwrap().is_empty(),
        "nothing asked of the local server"
    );
}

/// A redirect is followed only where the exe may come from: to plain http on another host it is
/// refused (with the tests' loopback allowance on — off, every plain-http hop is refused by
/// `https_only` as well); to this machine (allowed in the tests) it is followed.
#[test]
fn a_redirect_to_plain_http_is_refused() {
    let k = key();
    let name = "AFKLink-0.1.1.exe";
    let exe = exe_of(4 * 1024);
    let (to_http_base, to_http_seen) = serve_answer(
        &format!("/{name}"),
        "302 Found",
        &format!("Location: http://example.invalid/{name}\r\n"),
    );
    match download_from(&k, &exe, &format!("{to_http_base}/{name}"), &[], SHORT) {
        Err(DownloadError::Transfer(why)) => assert!(why.contains("redirect refused"), "{why}"),
        Err(e) => unreachable!("expected a refused redirect, got {e}"),
        Ok(_) => unreachable!("followed a redirect to plain http"),
    }
    assert_eq!(to_http_seen.lock().unwrap().len(), 1);

    let (good_base, good_seen) = serve(vec![(format!("/{name}"), exe.clone())]);
    let (hop_base, _) = serve_answer(
        &format!("/{name}"),
        "302 Found",
        &format!("Location: {good_base}/{name}\r\n"),
    );
    let downloaded = download_from(&k, &exe, &format!("{hop_base}/{name}"), &[], SHORT)
        .unwrap_or_else(|e| panic!("a redirect to this machine: {e}"));
    assert_eq!(downloaded.bytes, exe);
    assert_eq!(good_seen.lock().unwrap().len(), 1);
}

// ---------- The manifest's own limits ----------

/// What a refused check says, or a panic naming what came instead.
fn refused(result: Result<fetch::Checked, String>) -> String {
    match result {
        Err(why) => why,
        Ok(c) => unreachable!("expected a refusal, got a manifest naming {:?}", c.remote),
    }
}

/// Check the manifest a server at `base` serves as `/latest.json`, with `limits` (bounded by a
/// minute, so a limit that does not hold fails the test instead of hanging it): the answer and how
/// long it took.
fn check_at(base: &str, limits: fetch::Limits) -> (Result<fetch::Checked, String>, Duration) {
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    let started = Instant::now();
    let result = tauri::async_runtime::block_on(async {
        tokio::time::timeout(
            Duration::from_secs(60),
            fetch::check(&key().public, &endpoint, &current(), USER_AGENT, limits),
        )
        .await
        .expect("the check ended within a minute")
    });
    (result, started.elapsed())
}

/// A readable manifest of 0.1.1, padded with spaces (JSON's own whitespace) to `len` bytes.
fn padded_manifest(len: usize) -> Vec<u8> {
    let mut body = manifest(
        "0.1.1",
        "http://127.0.0.1:9/AFKLink-0.1.1.exe",
        "c2lnbmF0dXJl",
        &"ab".repeat(32),
        10,
    );
    assert!(body.len() < len);
    body.resize(len, b' ');
    body
}

const CAP: usize = fetch::MAX_MANIFEST_BYTES as usize;

/// A manifest of exactly the cap is read; one byte more is refused — before its body when its
/// `Content-Length` says so, cut as it comes when chunked or close-delimited, never more than the
/// cap held.
#[test]
fn a_manifest_up_to_the_cap_is_read_and_one_byte_more_is_cut() {
    for framing in [Framing::Length(CAP), Framing::Chunked, Framing::Close] {
        let (base, _) = serve_exe("/latest.json", framing, padded_manifest(CAP), false);
        let (result, _) = check_at(&base, SHORT);
        let checked = result.unwrap_or_else(|e| panic!("{framing:?}: {e}"));
        assert!(checked.update.is_some(), "{framing:?}");
    }
    let (base, served) = serve_exe(
        "/latest.json",
        Framing::Length(CAP + 1),
        padded_manifest(CAP + 1),
        false,
    );
    let why = refused(check_at(&base, SHORT).0);
    assert!(
        why.contains(&format!("announces {} bytes", CAP + 1)),
        "{why}"
    );
    assert_eq!(served.requests.load(Ordering::SeqCst), 1);
    for framing in [Framing::Chunked, Framing::Close] {
        let (base, _) = serve_exe("/latest.json", framing, padded_manifest(CAP + 1), false);
        let why = refused(check_at(&base, SHORT).0);
        assert!(
            why.contains("longer than the 65536 bytes allowed"),
            "{framing:?}: {why}"
        );
        assert!(received_in(&why) > CAP as u64, "{framing:?}: {why}");
        assert!(
            number_before(&why, " buffered") <= CAP as u64,
            "{framing:?}: {why}"
        );
    }
}

/// A `Content-Length` far over the cap (10 MiB) is refused on the answer's head, whatever comes
/// after it.
#[test]
fn a_manifest_announced_over_the_cap_is_refused_before_its_body() {
    let (base, _) = serve_exe(
        "/latest.json",
        Framing::Length(10 * 1024 * 1024),
        padded_manifest(1024),
        false,
    );
    let (result, took) = check_at(&base, SHORT);
    let why = refused(result);
    assert!(why.contains("announces 10485760 bytes"), "{why}");
    assert!(took < Duration::from_secs(5), "{took:?}");
}

/// A server that never stops sending (chunked, or no length at all): cut at the cap at once, the
/// connection dropped, never more than the cap held.
#[test]
fn an_endless_manifest_ends_promptly_with_at_most_the_cap_held() {
    for framing in [Framing::Chunked, Framing::Close] {
        let (base, served) = serve_exe("/latest.json", framing, vec![b' '; 16 * 1024], true);
        let (result, took) = check_at(&base, SHORT);
        let why = refused(result);
        assert!(
            why.contains("longer than the 65536 bytes allowed"),
            "{framing:?}: {why}"
        );
        assert!(
            number_before(&why, " buffered") <= CAP as u64,
            "{framing:?}: {why}"
        );
        assert!(took < Duration::from_secs(5), "{framing:?}: {took:?}");
        assert!(
            wait_gone(&served),
            "{framing:?}: the connection was dropped"
        );
    }
}

/// Serve `path` announcing `body`'s length and sending it a byte every `every`, until the client
/// goes away: faster than any stall limit, slower than any manifest needs.
fn serve_drip(path: &str, body: Vec<u8>, every: Duration) -> (String, Arc<Served>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let served: Arc<Served> = Arc::default();
    let record = Arc::clone(&served);
    let path = path.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let head = read_head(&mut stream);
            if head.split_whitespace().nth(1) != Some(path.as_str()) {
                let _ = write!(
                    stream,
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                continue;
            }
            record.requests.fetch_add(1, Ordering::SeqCst);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                body.len()
            );
            for b in &body {
                if stream
                    .write_all(&[*b])
                    .and_then(|()| stream.flush())
                    .is_err()
                {
                    record.gone.store(true, Ordering::SeqCst);
                    break;
                }
                record.written.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(every);
            }
        }
    });
    (base, served)
}

/// A manifest that comes a byte every 100 ms — never quiet for the stall limit (500 ms here), and
/// 868 bytes would take 87 s — ends at the check's whole time limit (2 s here; 30 s in the app).
#[test]
fn a_manifest_that_drips_ends_at_the_time_limit() {
    let (base, served) = serve_drip(
        "/latest.json",
        padded_manifest(868),
        Duration::from_millis(100),
    );
    let limits = fetch::Limits {
        check_total: Duration::from_secs(2),
        ..SHORT
    };
    let (result, took) = check_at(&base, limits);
    let why = refused(result);
    assert!(
        took >= Duration::from_millis(1900) && took < Duration::from_secs(8),
        "{took:?}: {why}"
    );
    assert!(!why.contains("longer than"), "{why}");
    assert!(
        served.written.load(Ordering::SeqCst) < 868,
        "it was still dripping"
    );
    assert!(wait_gone(&served), "the connection was dropped");
}

/// The manifest only over https, as the exe: a redirect to plain http on another host is refused
/// (followed to this machine, the tests' allowance); a plain-http manifest address is refused
/// before any request when the tests' allowance is off, as in the app.
#[test]
fn a_manifest_over_plain_http_or_redirected_to_it_is_refused() {
    let (to_http, to_http_seen) = serve_answer(
        "/latest.json",
        "302 Found",
        "Location: http://example.invalid/latest.json\r\n",
    );
    let why = refused(check_at(&to_http, SHORT).0);
    assert!(
        why.contains("redirect refused") && why.contains("is not https"),
        "{why}"
    );
    assert_eq!(to_http_seen.lock().unwrap().len(), 1);

    let (good, good_seen) = serve(vec![("/latest.json".to_string(), padded_manifest(900))]);
    let (hop, _) = serve_answer(
        "/latest.json",
        "302 Found",
        &format!("Location: {good}/latest.json\r\n"),
    );
    let checked = check_at(&hop, SHORT)
        .0
        .unwrap_or_else(|e| panic!("a redirect to this machine: {e}"));
    assert!(checked.update.is_some());
    assert_eq!(good_seen.lock().unwrap().len(), 1);

    let as_the_app = fetch::Limits {
        plain_http_loopback: false,
        ..SHORT
    };
    let (plain, plain_seen) = serve(vec![("/latest.json".to_string(), padded_manifest(900))]);
    let why = refused(check_at(&plain, as_the_app).0);
    assert!(why.contains("is not https"), "{why}");
    assert!(plain_seen.lock().unwrap().is_empty(), "nothing asked");
}

/// The manifest is redirected only to our own hosts: a hop to another https host is refused before
/// any connection to it (and a hop to this machine, the tests' allowance, is followed: above).
#[test]
fn a_manifest_redirected_to_another_https_host_is_refused() {
    for to in [
        "https://evil.test/download/latest.json",
        "https://api.afklink.app.evil.test/download/latest.json",
        "https://api.afklink.app:8443/download/latest.json",
    ] {
        let (base, seen) =
            serve_answer("/latest.json", "302 Found", &format!("Location: {to}\r\n"));
        let (result, took) = check_at(&base, SHORT);
        let why = refused(result);
        assert!(why.contains("redirect refused"), "{to}: {why}");
        assert!(
            why.contains("is not api.afklink.app") || why.contains("port 8443"),
            "{to}: {why}"
        );
        assert_eq!(seen.lock().unwrap().len(), 1, "{to}");
        assert!(
            took < Duration::from_secs(5),
            "{to}: no connection tried, {took:?}"
        );
    }
}

/// `204 No Content` is "nothing newer", as the plugin read it: no update, no version, and the
/// other way is not asked.
#[test]
fn a_204_manifest_answer_is_nothing_newer_and_the_other_way_is_not_asked() {
    let (empty, empty_seen) = serve_answer("/latest.json", "204 No Content", "");
    let (other, other_seen) = serve(vec![("/latest.json".to_string(), padded_manifest(900))]);
    let urls = [
        Url::parse(&format!("{empty}/latest.json")).unwrap(),
        Url::parse(&format!("{other}/latest.json")).unwrap(),
    ];
    let (checked, used) = tauri::async_runtime::block_on(fetch::check_any(
        &key().public,
        &urls,
        &current(),
        USER_AGENT,
        SHORT,
    ))
    .unwrap();
    assert_eq!(used, 0);
    assert!(checked.update.is_none());
    assert_eq!(checked.remote, None);
    assert_eq!(empty_seen.lock().unwrap().len(), 1);
    assert!(
        other_seen.lock().unwrap().is_empty(),
        "the other way not asked"
    );
}

/// A refused answer for the manifest (404, 502) on the first way: the second is asked, and its
/// answer is the check's.
#[test]
fn a_refused_manifest_answer_on_the_first_way_tries_the_other() {
    for status in ["404 Not Found", "502 Bad Gateway"] {
        let (bad, bad_seen) = serve_answer("/latest.json", status, "");
        let (good, good_seen) = serve(vec![("/latest.json".to_string(), padded_manifest(900))]);
        let urls = [
            Url::parse(&format!("{bad}/latest.json")).unwrap(),
            Url::parse(&format!("{good}/latest.json")).unwrap(),
        ];
        let (checked, used) = tauri::async_runtime::block_on(fetch::check_any(
            &key().public,
            &urls,
            &current(),
            USER_AGENT,
            SHORT,
        ))
        .unwrap_or_else(|e| panic!("{status}: {e}"));
        assert_eq!(used, 1, "{status}");
        assert_eq!(checked.remote, Some(Version::new(0, 1, 1)), "{status}");
        assert!(checked.update.is_some(), "{status}");
        assert_eq!(bad_seen.lock().unwrap().len(), 1, "{status}");
        assert_eq!(good_seen.lock().unwrap().len(), 1, "{status}");
    }
}

/// A body that ends cleanly before the manifest's size (chunked or close-delimited: no other sign
/// of the cut) is not accepted and not verified — and is not a rejection of the entry.
#[test]
fn a_short_body_is_not_accepted_and_not_a_rejection() {
    let k = key();
    let name = "AFKLink-0.1.1.exe";
    let exe = exe_of(64 * 1024);
    let sig = sign(&k, &exe, name, "0.1.1");
    for framing in [Framing::Chunked, Framing::Close] {
        let (exe_base, served) = serve_exe(
            &format!("/{name}"),
            framing,
            exe[..20 * 1024].to_vec(),
            false,
        );
        let body = manifest(
            "0.1.1",
            &format!("{exe_base}/{name}"),
            &sig,
            &lower_sha256(&exe),
            exe.len(),
        );
        let fetched = fetch_release(&k, body, fetch::MAX_EXE_BYTES);
        match &fetched.result {
            Err(DownloadError::Unconfirmed(why)) => assert!(
                why.contains(&format!(
                    "ended after {} of the manifest's {} bytes",
                    20 * 1024,
                    exe.len()
                )),
                "{framing:?}: {why}"
            ),
            Err(other) => unreachable!("{framing:?}: expected a short body, got {other}"),
            Ok(d) => unreachable!("{framing:?}: accepted {} bytes", d.bytes.len()),
        }
        assert_eq!(served.requests.load(Ordering::SeqCst), 1, "{framing:?}");
    }
}

/// The live `latest.json` (868 bytes: 0.7.1) as served: offered to an older build exactly as the
/// plugin read it — version, address, signature, size and SHA-256 — and to 0.7.1 itself or a newer
/// build not at all. Its signature names updater.pub's key, so the download goes ahead (from a
/// local address standing in for the real one: a few bytes, a short body); by another key, refused
/// before any request.
#[test]
fn the_live_manifest_is_read_and_checked_as_before() {
    const LIVE: &[u8] = include_bytes!("support/latest-0.7.1.json");
    assert_eq!(LIVE.len(), 868);
    if fetch::TEST_SIGNING_KEY {
        // A test-key build reads no production manifest at all (no test marker):
        // `a_manifest_of_the_other_world_is_refused_before_anything_is_downloaded`.
        return;
    }
    let updater_pub = include_str!("../updater.pub")
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .unwrap()
        .to_string();
    let (base, seen) = serve(vec![("/latest.json".to_string(), LIVE.to_vec())]);
    let endpoint = Url::parse(&format!("{base}/latest.json")).unwrap();
    let check = |current: Version| {
        tauri::async_runtime::block_on(fetch::check(
            &updater_pub,
            &endpoint,
            &current,
            USER_AGENT,
            SHORT,
        ))
        .unwrap()
    };
    let checked = check(Version::new(0, 7, 0));
    assert_eq!(checked.remote, Some(Version::new(0, 7, 1)));
    let release = checked.update.expect("0.7.1 is newer than 0.7.0");
    assert_eq!(release.version, "0.7.1");
    assert_eq!(
        release.download_url.as_str(),
        "https://api.afklink.app/download/AFKLink-0.7.1.exe"
    );
    let extras = release.extras.clone().unwrap();
    assert_eq!(extras.size, 35_435_008);
    assert_eq!(
        extras.sha256,
        "74BF874FDC5E5A9EC6156CDB828477B0BCFD7589ABD7A4AD2AB3199DCACA1A16"
    );
    for current in [Version::new(0, 7, 1), Version::new(0, 7, 2)] {
        let checked = check(current.clone());
        assert_eq!(checked.remote, Some(Version::new(0, 7, 1)), "{current}");
        assert!(
            checked.update.is_none(),
            "{current}: no reinstall, no downgrade"
        );
    }
    assert_eq!(user_agents(&seen), [USER_AGENT; 3]);

    let (exe_base, served) = serve_exe(
        "/AFKLink-0.7.1.exe",
        Framing::Length(10),
        b"MZ not 0.7".to_vec(),
        false,
    );
    let local = [Url::parse(&format!("{exe_base}/AFKLink-0.7.1.exe")).unwrap()];
    let download = |key: &str| {
        tauri::async_runtime::block_on(fetch::download_any(
            &release,
            key,
            &local,
            SHORT,
            &mut |_, _| {},
        ))
    };
    match download(&key().public) {
        Err(DownloadError::Rejected(why)) => assert!(why.contains("made with key"), "{why}"),
        other => unreachable!("expected a refusal, got {:?}", other.map(|d| d.bytes.len())),
    }
    assert_eq!(
        served.requests.load(Ordering::SeqCst),
        0,
        "another key: not fetched"
    );
    // Fetched (every check before the download passed), and ten bytes of 35 435 008 are a cut
    // transfer: not accepted, not held against the entry.
    match download(&updater_pub) {
        Err(DownloadError::Unconfirmed(why)) => assert!(
            why.contains("ended after 10 of the manifest's 35435008 bytes"),
            "{why}"
        ),
        other => unreachable!(
            "expected a short body, got {:?}",
            other.map(|d| d.bytes.len())
        ),
    }
    assert_eq!(
        served.requests.load(Ordering::SeqCst),
        1,
        "updater.pub's key: fetched"
    );
}
