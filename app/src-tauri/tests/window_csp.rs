//! The window's Content-Security-Policy, pinned, and the configuration it relies on. The policy is
//! written twice and both copies are enforced:
//!
//! - `app.security.csp` in `tauri.conf.json`: the built app sends it as a response header with every
//!   HTML page it serves from the embedded assets (`tauri::manager::AppManager::get_asset`), with
//!   sha256 hashes of the bundle's scripts added to `script-src` next to `'self'`.
//! - the `<meta http-equiv="Content-Security-Policy">` in `app/ui/index.html`: the only policy under
//!   `vite dev` (the window loads `devUrl` straight from vite) and on the UI stand, and a second
//!   policy in the built app. A page under two policies gets what both allow, so a directive loosened
//!   in one copy alone changes nothing in the app but makes the copies lie about each other.
//!
//! This pins the source `app/ui/index.html`. What ships is vite's copy of it (`app/ui/dist`),
//! re-serialized by Tauri's codegen when it embeds the assets (it adds nonce attributes to scripts
//! and styles it may touch). Today the meta tag's policy in that copy is the same; a vite or Tauri
//! upgrade that rewrote it would not be caught here.
//!
//! `'unsafe-inline'` in `style-src`: the built window needs no inline styles today (React's `style`
//! props are CSSOM, which no CSP governs; Tailwind builds to a `.css` file). It is there for the
//! `<style>` vite injects under `vite dev` and for any `<style>` a library may insert at run time.
//! `dangerousDisableAssetCspModification` is `["style-src"]` so it keeps working: otherwise Tauri
//! adds a `'nonce-…'` to `style-src` once the built HTML holds a `<style>` element, a nonce makes the
//! browser ignore `'unsafe-inline'`, and such styles would be refused.
//!
//! The config's policy is compared as the exact string (a change to it is a decision, and this test
//! is where it shows up); the meta tag directive by directive, so its line wrapping and spacing are
//! free but its content is not. On top, a closed allowlist (`policy_violations`) says which source
//! may appear in which directive, so an edit to both copies and to `POLICY` still has to argue with
//! it.

#![allow(clippy::unwrap_used, reason = "test")]

use std::collections::{BTreeMap, BTreeSet};

const CONFIG: &str = include_str!("../tauri.conf.json");
const CAPABILITY: &str = include_str!("../capabilities/default.json");
const INDEX_HTML: &str = include_str!("../../ui/index.html");

/// The window's policy. `connect-src` names Tauri's IPC endpoint: `http://ipc.localhost` on Windows
/// (WebView2, `convertFileSrc(cmd, 'ipc')` with the http scheme), `ipc:` elsewhere; without it the
/// IPC's fetch is refused and every call falls back to `postMessage`. `'self'` keeps vite's HMR
/// websocket working under `vite dev`.
const POLICY: &str = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
script-src 'self'; connect-src 'self' ipc: http://ipc.localhost; object-src 'none'; \
base-uri 'none'; form-action 'none'; frame-src 'none'";

/// Every directive the policy has, no more and no fewer.
const DIRECTIVES: [&str; 9] = [
    "default-src",
    "img-src",
    "style-src",
    "script-src",
    "connect-src",
    "object-src",
    "base-uri",
    "form-action",
    "frame-src",
];

/// Sources allowed beyond `'self'` and `'none'`, each in the one directive that needs it:
/// `'unsafe-inline'` for styles (see the module docs), `data:` for images (the pairing QR is an SVG
/// data URI, `afklink_core::qr::qr_svg_data_uri`), Tauri's IPC endpoint for fetches.
const EXCEPTIONS: [(&str, &str); 4] = [
    ("'unsafe-inline'", "style-src"),
    ("data:", "img-src"),
    ("ipc:", "connect-src"),
    ("http://ipc.localhost", "connect-src"),
];

/// A policy as directive → its sources (lower-cased names, sources sorted), panicking on a directive
/// given twice: a browser enforces only the first of two, so the second would be a dead letter.
fn directives(policy: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for part in policy.split(';') {
        let mut words = part.split_ascii_whitespace();
        let Some(name) = words.next() else { continue };
        let name = name.to_ascii_lowercase();
        let sources: BTreeSet<String> = words.map(str::to_string).collect();
        assert!(
            out.insert(name.clone(), sources).is_none(),
            "directive `{name}` given twice in {policy:?}"
        );
    }
    out
}

/// What the closed allowlist finds wrong with `policy`; empty when it passes.
fn policy_violations(policy: &str) -> Vec<String> {
    let d = directives(policy);
    let mut bad = Vec::new();
    let names: BTreeSet<&str> = d.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = DIRECTIVES.into_iter().collect();
    if names != expected {
        bad.push(format!("directives {names:?}, expected {expected:?}"));
    }
    for (name, sources) in &d {
        if sources.is_empty() {
            bad.push(format!("{name} has no source"));
        }
        // 'none' next to anything else is ignored by the browser: the directive would admit the rest.
        if sources.contains("'none'") && sources.len() > 1 {
            bad.push(format!("{name}: 'none' with other sources {sources:?}"));
        }
        for s in sources {
            let allowed = s == "'self'"
                || s == "'none'"
                || EXCEPTIONS
                    .iter()
                    .any(|&(source, directive)| source == s && directive == name);
            if !allowed {
                bad.push(format!("{name} admits {s}"));
            }
        }
    }
    let exactly = |name: &str, source: &str| {
        let want = BTreeSet::from([source.to_string()]);
        (d.get(name) != Some(&want)).then(|| format!("{name} is {:?}, not {source}", d.get(name)))
    };
    // No script from anywhere but the bundle; nothing to embed, no <base>, no form to submit.
    bad.extend(exactly("default-src", "'self'"));
    bad.extend(exactly("script-src", "'self'"));
    for name in ["object-src", "base-uri", "form-action", "frame-src"] {
        bad.extend(exactly(name, "'none'"));
    }
    bad
}

fn config() -> serde_json::Value {
    serde_json::from_str(CONFIG).unwrap()
}

/// The page without its `<!-- … -->` comments: a commented-out tag is not a tag.
fn strip_comments(html: &str) -> String {
    let mut out = String::new();
    let mut rest = html;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        let end = rest[start..].find("-->").unwrap();
        rest = &rest[start + end + "-->".len()..];
    }
    out.push_str(rest);
    out
}

/// The offset (in `strip_comments(html)`) and `content` of every
/// `<meta http-equiv="Content-Security-Policy">` in the page.
fn meta_policies_at(html: &str) -> Vec<(usize, String)> {
    let html = strip_comments(html);
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(start) = html[from..].find("<meta").map(|i| from + i) {
        let end = start + html[start..].find('>').unwrap();
        let tag = &html[start..end];
        from = end;
        let lower = tag.to_ascii_lowercase();
        if !lower.contains(r#"http-equiv="content-security-policy""#) {
            continue;
        }
        let at = lower.find(r#"content=""#).unwrap() + r#"content=""#.len();
        let len = tag[at..].find('"').unwrap();
        found.push((start, tag[at..at + len].to_string()));
    }
    found
}

fn meta_policies(html: &str) -> Vec<String> {
    meta_policies_at(html).into_iter().map(|(_, c)| c).collect()
}

/// `POLICY` with `from` replaced by `to`, checked to have changed.
fn mutated(from: &str, to: &str) -> String {
    assert!(POLICY.contains(from), "{from:?} is not in POLICY");
    POLICY.replacen(from, to, 1)
}

#[test]
fn config_policy_is_the_pinned_policy() {
    let csp = &config()["app"]["security"]["csp"];
    assert_eq!(
        csp.as_str(),
        Some(POLICY),
        "app.security.csp in tauri.conf.json"
    );
}

#[test]
fn meta_tag_policy_matches_the_config() {
    let metas = meta_policies(INDEX_HTML);
    assert_eq!(
        metas.len(),
        1,
        "one CSP meta tag in app/ui/index.html: {metas:?}"
    );
    assert_eq!(
        directives(&metas[0]),
        directives(POLICY),
        "the meta tag in app/ui/index.html and app.security.csp in tauri.conf.json differ"
    );
}

#[test]
fn meta_tag_comes_before_any_script_or_stylesheet() {
    // A meta policy governs only what comes after it in the document: a <script> or <link> above
    // it would load unchecked under `vite dev` and on the stand.
    let html = strip_comments(INDEX_HTML).to_ascii_lowercase();
    let metas = meta_policies_at(INDEX_HTML);
    assert_eq!(metas.len(), 1, "{metas:?}");
    let meta = metas[0].0;
    for tag in ["<script", "<link"] {
        if let Some(at) = html.find(tag) {
            assert!(
                at > meta,
                "{tag} at {at} comes before the CSP meta tag at {meta}"
            );
        }
    }
}

#[test]
fn policy_passes_the_closed_allowlist() {
    assert_eq!(policy_violations(POLICY), Vec::<String>::new());
}

#[test]
fn closed_allowlist_refuses_what_it_should() {
    let cases = [
        // A host without a scheme, a directive the policy does not have, a remote host.
        mutated("style-src 'self'", "style-src 'self' evil.com"),
        format!("{POLICY}; font-src https://x.test"),
        mutated("connect-src 'self'", "connect-src 'self' wss://x.test"),
        // Exceptions outside their own directive.
        mutated("script-src 'self'", "script-src 'self' 'unsafe-inline'"),
        mutated("default-src 'self'", "default-src 'self' data:"),
        mutated("img-src 'self' data:", "img-src 'self' data: ipc:"),
        // What runs strings as code, wildcards, whole schemes.
        mutated("script-src 'self'", "script-src 'self' 'unsafe-eval'"),
        mutated("img-src 'self'", "img-src 'self' *"),
        mutated("img-src 'self'", "img-src 'self' https:"),
        mutated("img-src 'self'", "img-src 'self' blob:"),
        // 'none' that the browser would ignore, and a 'none' directive opened up.
        mutated("object-src 'none'", "object-src 'none' 'self'"),
        mutated("frame-src 'none'", "frame-src 'self'"),
        // A directive dropped (frame-src would fall back to default-src 'self').
        mutated("; frame-src 'none'", ""),
    ];
    for policy in cases {
        assert!(
            !policy_violations(&policy).is_empty(),
            "the allowlist let through {policy:?}"
        );
    }
}

#[test]
fn style_src_nonce_injection_is_off_and_nothing_else_is() {
    let security = &config()["app"]["security"];
    assert_eq!(
        security["dangerousDisableAssetCspModification"],
        serde_json::json!(["style-src"]),
        "only style-src is left alone: a nonce there voids 'unsafe-inline'"
    );
}

#[test]
fn security_config_has_nothing_the_policy_does_not_expect() {
    // Each key here is checked; any other `app.security` key fails until it is argued for here.
    // Absent on purpose:
    //   devCsp        under `cargo tauri dev` the window loads vite's page, which carries the meta
    //                 tag; a dev policy would be a third copy.
    //   headers       added to every response from the app's protocol; one could carry a second CSP
    //                 or loosen CORS on the IPC and asset answers. Nothing needs it.
    //   capabilities  inline capabilities would grant the window commands next to
    //                 `capabilities/default.json`, which the test below pins.
    //   (kebab-case aliases such as `asset-protocol`, `dev-csp`: unknown here, so they fail too.)
    let security = config()["app"]["security"].clone();
    let keys: BTreeSet<&str> = security
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let known = BTreeSet::from([
        "csp",
        "dangerousDisableAssetCspModification",
        "freezePrototype",
        "pattern",
        "assetProtocol",
    ]);
    assert!(
        keys.is_subset(&known),
        "app.security has keys this test does not check: {:?}",
        keys.difference(&known).collect::<Vec<_>>()
    );
    // The isolation pattern runs the IPC through an <iframe>, which `frame-src 'none'` refuses.
    let pattern = &security["pattern"];
    assert!(
        pattern.is_null() || pattern["use"] == "brownfield",
        "app.security.pattern: {pattern}"
    );
    // The asset protocol (`asset://`, `http://asset.localhost`) serves files from disk to the page;
    // the policy does not admit it, and nothing should be served that way.
    let asset = &security["assetProtocol"];
    assert!(
        asset.is_null() || asset["enable"].is_null() || asset["enable"] == false,
        "app.security.assetProtocol: {asset}"
    );
}

#[test]
fn windows_load_the_bundle_over_http() {
    let windows = config()["app"]["windows"].as_array().unwrap().clone();
    let labels: BTreeSet<&str> = windows
        .iter()
        .map(|w| w["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, BTreeSet::from(["main", "pair-request"]));
    for w in &windows {
        let label = &w["label"];
        // https would move the IPC to https://ipc.localhost, which connect-src does not name: every
        // call would quietly fall back to postMessage.
        for key in ["useHttpsScheme", "use-https-scheme"] {
            assert!(
                w[key].is_null() || w[key] == false,
                "window {label}: {key} = {}",
                w[key]
            );
        }
        // A window on a remote URL would get none of this policy (the header comes only with the
        // embedded assets).
        let url = &w["url"];
        assert!(
            url.is_null() || url.as_str().is_some_and(|u| !u.contains(':')),
            "window {label}: url {url}"
        );
    }
}

#[test]
fn window_capability_grants_only_what_the_windows_use() {
    // Tauri reads every file in `capabilities/`: one more file would grant more.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    let files: BTreeSet<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(files, BTreeSet::from(["default.json".to_string()]));

    let cap: serde_json::Value = serde_json::from_str(CAPABILITY).unwrap();
    // No `remote` (pages from other origins calling commands), no `webviews`, no `platforms`: the
    // keys are exactly these.
    let keys: BTreeSet<&str> = cap
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "$schema",
            "identifier",
            "description",
            "windows",
            "permissions"
        ])
    );
    assert!(cap.get("remote").is_none());
    assert_eq!(cap["windows"], serde_json::json!(["main", "pair-request"]));
    assert_eq!(
        cap["permissions"],
        serde_json::json!([
            "core:default",
            "core:window:allow-show",
            "core:window:allow-hide",
            "core:window:allow-set-focus",
            "core:window:allow-start-dragging"
        ])
    );
    // Plugin and core commands that would reach past the app's own commands. The window updates
    // only through the app's own commands (`src/updater.rs`), which check the signature and the
    // version themselves; an `updater:` permission would be a door around them.
    for p in cap["permissions"].as_array().unwrap() {
        let p = p.as_str().unwrap();
        for denied in ["updater:", "opener:", "shell:", "fs:", "http:"] {
            assert!(!p.starts_with(denied), "permission {p}");
        }
        assert_ne!(p, "core:webview:allow-create-webview");
    }
}

#[test]
fn directives_parser_reads_a_policy_and_refuses_a_repeat() {
    let d = directives("  Default-Src 'self' ;; img-src data:  'self';");
    assert_eq!(d.len(), 2);
    assert_eq!(d["default-src"], BTreeSet::from(["'self'".to_string()]));
    assert_eq!(
        d["img-src"],
        BTreeSet::from(["'self'".to_string(), "data:".to_string()])
    );
    let repeat = std::panic::catch_unwind(|| directives("img-src 'self'; img-src data:"));
    assert!(repeat.is_err(), "a directive given twice must fail");
}

#[test]
fn meta_policies_finds_the_tag_whatever_its_layout() {
    let html = r#"<head><meta charset="UTF-8" /><!-- <meta http-equiv="Content-Security-Policy"
      content="img-src *" /> --><meta
      http-equiv="Content-Security-Policy"
      content="default-src 'self'"
    /></head>"#;
    assert_eq!(meta_policies(html), vec!["default-src 'self'".to_string()]);
    assert!(meta_policies(r#"<meta name="color-scheme" content="dark" />"#).is_empty());
}
