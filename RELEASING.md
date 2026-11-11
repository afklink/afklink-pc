# Releasing AFKLink for Windows

Official builds of AFKLink are built, signed and published by GitHub Actions in this repository,
from a tag, by [`.github/workflows/release.yml`](.github/workflows/release.yml). The exe you download
from [Releases](https://github.com/afklink/afklink-pc/releases), the exe the app updates itself
to, and the exe whose hash you can look up are the same file.

## Cutting a release

1. The version is set once, in `[workspace.package]` of `Cargo.toml`, and `CHANGELOG.md` has a
   section `## <version> — <date>` for it. That section becomes the release notes.
2. The owner pushes the tag `v<version>` on that commit, which must be on `main`. Only the owner
   can create `v*` tags, and nobody can move or delete them.
3. The workflow runs five jobs:
   - **build** (Windows, no secrets): builds the app from the tag with the pinned Rust toolchain,
     Tauri CLI, NASM and Bun, as the release channel, stamped with the tag's commit. It never
     enables the test update key, and it refuses an exe that does not trust the update key in
     `app/src-tauri/updater.pub` or that trusts the test key in `app/src-tauri/updater-test.pub`.
     The debug symbols of that exe are encrypted to the owner's key before they are stored, and
     are never part of a release.
   - **notices** (Linux, no secrets): `THIRD-PARTY-NOTICES.txt` (`scripts/notices.ts`: the Rust
     crates for `x86_64-pc-windows-msvc` via cargo-about, the window's JavaScript packages, and the
     bundled str0m, OpenH264 and FakerInput) and a CycloneDX SBOM of the same commit.
   - **sign** (Linux, GitHub environment `release`): waits for the owner's approval, then signs
     the exe with the update key using the Tauri signer. The key exists only in that environment,
     and this job runs nothing from the repository. The owner approves a sign run only when its
     commit is the reviewed commit on `main`: a tag on a commit off `main` whose workflow was
     changed could skip the build's check that the commit is on `main`.
   - **verify** (Linux, read-only): checks the signature exactly as the app will
     (`scripts/official-check.ts`) and writes `SHA256SUMS`.
   - **publish** (Linux, no repository code): hashes the files again against `SHA256SUMS`, records
     a build provenance attestation for every file, creates a draft release, checks the draft
     holds exactly these files, and publishes it.
4. A release is never replaced: releases are immutable. A broken release is followed by a new
   version.

Running the workflow by hand (Actions → Release → Run workflow) is a dry run on any branch: it
builds the exe and the notices, and signs and publishes nothing.

Every tool the workflow downloads (Tauri CLI, NASM, Bun, age, cargo-about, cargo-cyclonedx) is
pinned by version and SHA-256, and every action by its full commit SHA. No Actions cache is used.

## Repository settings the release relies on

The owner keeps these settings; the workflow's guarantees depend on them.

- [ ] The repository is public before the first tag: on the Free plan, artifact attestations,
      rulesets and environment reviewers need it.
- [ ] Environment `release`: the owner as required reviewer, administrators cannot bypass it,
      deployments only from tags matching `v*`.
- [ ] The signing key and its password are secrets of the environment `release` only, never
      repository or organization secrets.
- [ ] Repository variable `SYMBOLS_AGE_RECIPIENT`: the owner's age public key (`age1…`). A
      release fails without it; a dry run only skips the symbols.
- [ ] Tag ruleset for `refs/tags/v*`: only the owner may create; nobody may update or delete.
- [ ] Branch ruleset for `main`: pull requests with review, no force pushes, no deletion.
- [ ] Immutable releases turned on.
- [ ] Actions: approval required for workflows from outside contributors; only selected actions
      allowed; actions must be pinned to a full commit SHA.

## What a release contains

| File | What it is |
|---|---|
| `AFKLink-<version>.exe` | the app: one portable exe, no installer |
| `AFKLink-<version>.exe.sig` | its update signature (minisign, base64), which the app checks before installing an update |
| `SHA256SUMS` | SHA-256 of every other file |
| `AFKLink-<version>.cdx.json` | the SBOM: every Rust crate in the exe (CycloneDX JSON) |
| `THIRD-PARTY-NOTICES.txt` | the licenses of the third-party software in the exe, with their texts |

The exe is not signed with an Authenticode certificate yet, so Windows SmartScreen may warn the
first time it runs.

## Verifying a download

**Provenance.** With the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify AFKLink-<version>.exe --repo afklink/afklink-pc
```

It confirms the file was built by this repository's release workflow on GitHub's runners, and
names the tag and the commit it was built from.

**Checksums.** In the folder with the downloaded files:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

(On Windows: `Get-FileHash AFKLink-<version>.exe` and compare with its line in `SHA256SUMS`.)

**Update signature.** The `.sig` file and the key line in `app/src-tauri/updater.pub` are base64
of a [minisign](https://jedisct1.github.io/minisign/) signature and public key:

```sh
grep -v '^#' app/src-tauri/updater.pub | grep -v '^$' | base64 -d > afklink-update.pub
base64 -d AFKLink-<version>.exe.sig > AFKLink-<version>.exe.minisig
minisign -V -p afklink-update.pub -m AFKLink-<version>.exe -x AFKLink-<version>.exe.minisig
```

minisign must report the signature verified, and its trusted comment must name
`file:AFKLink-<version>.exe` and `version:<version>`. The app refuses an update whose signature
does not.

## Building it yourself

The same build without signing: `bun install --frozen-lockfile`, then
`bun scripts/official-build.ts --dry-run` on Windows with the toolchain the workflow installs
(Rust from `rust-toolchain.toml`, Tauri CLI, NASM). The exe embeds its build time, so it is not
byte-identical to the official one.
