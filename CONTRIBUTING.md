# Contributing

Thanks for taking the time. For anything larger than a small fix, open an issue first so we can
agree on the approach before you write the code.

Security problems go to [SECURITY.md](SECURITY.md), not to issues or pull requests.

## Building and testing

The app runs on Windows 10 and 11 (x64), and that is where it builds and its tests run.
Toolchain versions are pinned in the repository: Rust in `rust-toolchain.toml`, Bun in the
`packageManager` field of `package.json`.

```sh
bun install --frozen-lockfile
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --tests
bun run typecheck
bun run lint --error-on-warnings
bun run test:scripts
```

These are the checks CI runs (`.github/workflows/ci.yml`); a pull request needs all of them
green. The desktop app itself is built with the Tauri CLI v2: `cargo tauri build`.

Tests that move the real cursor or type on the keyboard are marked `#[ignore]`. Do not remove
the marker; run them by hand, on a machine you are not using:
`cargo test -p afklink-input -- --ignored`.

## Developer Certificate of Origin

Every commit must be signed off: add `Signed-off-by: Your Name <you@example.com>` with
`git commit -s`. By signing off you certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org/) for that commit: you
wrote it, or otherwise have the right to submit it under this project's license
(AGPL-3.0-only). Pull requests with unsigned commits cannot be merged.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): summary`, for
example `fix(input): release held keys when a session ends`. Common types are `feat`, `fix`,
`perf`, `refactor`, `test`, `docs`, `build`, `ci` and `chore`. The summary is in English, in
the imperative, without a trailing period. The body, when needed, explains what changed and why.

## Code comments

- A comment explains why the code is the way it is now: the constraint, the invariant, the
  measurement behind a number.
- Write comments in English.
- No dates, names, issue or task labels, and no account of how the code looked before: that
  history belongs in commit messages.
- Keep them short; longer design notes belong in documentation.

## Pull requests

- Keep a pull request to one change; split unrelated fixes.
- Add or update tests for behavior you change.
- Run `cargo fmt` and `bun run format` before pushing.
