/**
 * The rules an official release of the desktop app is held to, shared by the release workflow's
 * scripts (`scripts/official-build.ts` on Windows, `scripts/official-check.ts` before publishing)
 * and their tests. Pure functions over bytes and text: no process, no network.
 *
 * An official release is `AFKLink-<version>.exe`, built from the tag `v<version>` with the release
 * channel and no cargo features, trusting the update key of `app/src-tauri/updater.pub` and never
 * the test key of `app/src-tauri/updater-test.pub`, and signed by the Tauri signer
 * (`cargo tauri signer sign --app-version <version>`), whose trusted comment names the file and
 * the version. The app's updater accepts nothing else (`app/src-tauri/src/updater/manifest.rs`:
 * a prehashed minisign signature by that key, `file:AFKLink-<version>.exe`, `version:<version>`).
 */
import { createHash } from "node:crypto";
import {
  assertPrehashed,
  decodePublicKey,
  decodeSignature,
  keyIdHex,
  type PublicKey,
  trustedField,
  verifySignature,
} from "./minisign";

/** A release tag: `v` and a version without leading zeros, nothing else. */
const TAG = /^v((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))$/;

/** The version a release tag names; `null` for anything that is not a release tag. */
export function tagVersion(tag: string): string | null {
  return TAG.exec(tag)?.[1] ?? null;
}

/** The file name of the release exe; the signature must name exactly this. */
export function releaseExeName(version: string): string {
  return `AFKLink-${version}.exe`;
}

/** The name of a dry run's exe, which no updater accepts as a release. */
export function dryRunExeName(version: string, shortCommit: string, dirty: boolean): string {
  return `AFKLink-${version}-untagged-${shortCommit}${dirty ? "-dirty" : ""}.exe`;
}

/** The SBOM's file name in a release. */
export function sbomName(version: string): string {
  return `AFKLink-${version}.cdx.json`;
}

export const NOTICES_FILE = "THIRD-PARTY-NOTICES.txt";
export const SUMS_FILE = "SHA256SUMS";

/** Every asset of a release, by name: what the release holds and nothing else. */
export function releaseAssets(version: string): string[] {
  const exe = releaseExeName(version);
  return [exe, `${exe}.sig`, sbomName(version), NOTICES_FILE, SUMS_FILE];
}

/** What a key file (`updater.pub`, `updater-test.pub`) holds: its one key line, or none. */
export interface KeyLine {
  line: string;
  key: PublicKey;
}

/**
 * The key line of a key file's text, read as the app reads it: one line of base64 among `#`
 * comments and blank lines. `null` when the file holds no key; throws when it holds anything else.
 */
export function parseKeyLine(text: string, what: string): KeyLine | null {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
  if (lines.length === 0) return null;
  if (lines.length > 1) throw new Error(`${what}: ${lines.length} key lines instead of one`);
  const line = lines[0] ?? "";
  try {
    return { line, key: decodePublicKey(line) };
  } catch (err) {
    throw new Error(`${what}: not a minisign public key (${(err as Error).message})`);
  }
}

/**
 * The update keys of a release: the production key must be there, and the test key, when there
 * is one, must be another key. Returns what was checked, for the log.
 */
export function assertKeyFiles(production: KeyLine | null, test: KeyLine | null): string[] {
  if (production === null) {
    throw new Error(
      "app/src-tauri/updater.pub holds no key: an official build must trust the update key",
    );
  }
  const notes = [`update key ${keyIdHex(production.key.keyId)} (updater.pub)`];
  if (test === null) {
    notes.push("updater-test.pub holds no key");
  } else if (test.key.keyId.equals(production.key.keyId) || test.line === production.line) {
    throw new Error("updater.pub and updater-test.pub hold the same key");
  } else {
    notes.push(`test key ${keyIdHex(test.key.keyId)} (updater-test.pub), never trusted here`);
  }
  return notes;
}

/**
 * The exe trusts the update key and not the test key: the key file's text is compiled into it as
 * it is (`include_str!`), so its key line is in the bytes. The test key's line in a release would
 * mean a build with the `updater-test-key` feature, which installs updates signed by the test key.
 */
export function assertEmbeddedKeys(
  exe: Uint8Array,
  production: KeyLine,
  test: KeyLine | null,
): string[] {
  const bytes = Buffer.from(exe.buffer, exe.byteOffset, exe.byteLength);
  const has = (line: string) => bytes.includes(Buffer.from(line, "utf8"));
  if (test !== null && has(test.line)) {
    throw new Error(
      "the exe carries the test key of updater-test.pub (a build with the updater-test-key " +
        "feature): it would install updates signed by the test key. Not a release",
    );
  }
  if (!has(production.line)) {
    throw new Error("the exe does not carry the update key of updater.pub: not a release");
  }
  return [
    "the key line of updater.pub is in the exe",
    test === null ? "updater-test.pub holds no key to look for" : "the test key line is not",
  ];
}

/** What a checked signature says. */
export interface CheckedSignature {
  keyId: string;
  trustedComment: string;
}

/**
 * A `.sig` checked the way the app checks it before installing (`updater/manifest.rs`):
 * prehashed, by the update key, over these bytes, its trusted comment naming exactly
 * `AFKLink-<version>.exe` and `<version>` (one leading `v` allowed on the version, as there).
 * The file name is held exactly here; the app ignores its case.
 */
export function checkReleaseSignature(
  exe: Uint8Array,
  sigText: string,
  key: PublicKey,
  version: string,
): CheckedSignature {
  const sig = decodeSignature(sigText);
  assertPrehashed(sig);
  verifySignature(exe, sig, key);
  const file = trustedField(sig, "file");
  const expected = releaseExeName(version);
  if (file !== expected) {
    throw new Error(`the signature names the file «${file ?? "-"}», not ${expected}`);
  }
  const signedVersion = trustedField(sig, "version");
  if (signedVersion === undefined || signedVersion.replace(/^v/, "") !== version) {
    throw new Error(`the signature names the version «${signedVersion ?? "-"}», not ${version}`);
  }
  return { keyId: keyIdHex(sig.keyId), trustedComment: sig.trustedComment };
}

export function sha256Of(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * `SHA256SUMS` as `sha256sum` writes it in text mode, one `<hex>  <name>` line per file, sorted by
 * name, so `sha256sum -c SHA256SUMS` checks every file. Names that would break the format (a
 * folder, a newline, a backslash, a leading `*`) are refused.
 */
export function sha256Sums(files: readonly { name: string; sha256: string }[]): string {
  const seen = new Set<string>();
  const lines = [...files]
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .map(({ name, sha256 }) => {
      if (!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(name)) {
        throw new Error(`«${name}» cannot be listed in ${SUMS_FILE}`);
      }
      if (!/^[0-9a-f]{64}$/.test(sha256)) throw new Error(`${name}: «${sha256}» is not a SHA-256`);
      if (seen.has(name)) throw new Error(`${name} is listed twice`);
      seen.add(name);
      return `${sha256}  ${name}\n`;
    });
  if (lines.length === 0) throw new Error(`${SUMS_FILE} would be empty`);
  return lines.join("");
}

/**
 * The text of a GitHub release: the version's CHANGELOG section as it is, then how to check the
 * files (in English: the repository's README is English first).
 */
export function releaseBody(notes: string, version: string, repo: string): string {
  const body = notes.trim();
  if (body === "") throw new Error(`the CHANGELOG section of ${version} is empty`);
  const exe = releaseExeName(version);
  return [
    body,
    "",
    "---",
    "",
    `Built, signed and attested by the release workflow of ${repo} from the tag v${version}.`,
    "Check the download before running it:",
    "",
    "```sh",
    `gh attestation verify ${exe} --repo ${repo}`,
    `sha256sum -c ${SUMS_FILE} --ignore-missing`,
    "```",
    "",
    `The update signature (${exe}.sig) is checked by the app itself against the key in`,
    "`app/src-tauri/updater.pub`; RELEASING.md explains how to check it by hand.",
    "",
  ].join("\n");
}
