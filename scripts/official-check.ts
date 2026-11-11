/**
 * `bun scripts/official-check.ts --dir <release folder> --version <X.Y.Z> --sha256 <hex>
 * --notes-out <file>` — the last check of an official release before anything is published, run by
 * `.github/workflows/release.yml` in its publish job (no signing key there). Needs no dependencies:
 * Bun's own modules and lib/{official,minisign,changelog}.ts.
 *
 *   1. The folder holds exactly the release's files but `SHA256SUMS` (lib/official.ts,
 *      `releaseAssets`): the exe, its `.sig`, the SBOM and THIRD-PARTY-NOTICES.txt; no symbols
 *      (lib/symbols.ts, `assertPublishSet`).
 *   2. The exe is the one the build job built (`--sha256`, its output), carries the key line of
 *      `app/src-tauri/updater.pub` and not the line of `updater-test.pub`.
 *   3. The `.sig` passes the app's own checks with the key of `updater.pub`: prehashed, valid over
 *      the exe and over its trusted comment, which names `AFKLink-<version>.exe` and `<version>`.
 *   4. The SBOM is a CycloneDX JSON document and the notices name the bundled components.
 *   5. Writes `SHA256SUMS` into the folder (every other file) and the release text (the version's
 *      CHANGELOG section and how to verify) to `--notes-out`.
 */
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { versionNotes } from "./lib/changelog";
import { CHANGELOG, Failure, runMain, shown, TEST_PUBKEY, UPDATER_PUBKEY } from "./lib/common";
import {
  assertEmbeddedKeys,
  assertKeyFiles,
  checkReleaseSignature,
  type KeyLine,
  NOTICES_FILE,
  parseKeyLine,
  releaseAssets,
  releaseBody,
  releaseExeName,
  SUMS_FILE,
  sbomName,
  sha256Of,
  sha256Sums,
} from "./lib/official";
import { assertPublishSet } from "./lib/symbols";

const TAG = "official-check";

/** What the notices must name besides the crates and packages (scripts/notices.ts). */
export const NOTICES_MUST_NAME = ["FakerInput", "str0m", "OpenH264"] as const;

interface Options {
  dir: string;
  version: string;
  sha256: string;
  notesOut: string;
  repo: string;
}

function parseArgs(argv: string[]): Options {
  const values: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i] ?? "";
    const value = argv[i + 1];
    if (!["--dir", "--version", "--sha256", "--notes-out", "--repo"].includes(flag)) {
      throw new Failure(`unknown argument «${flag}»`);
    }
    if (value === undefined || value === "") throw new Failure(`${flag} needs a value`);
    values[flag] = value;
  }
  const need = (flag: string) => {
    const v = values[flag];
    if (v === undefined) throw new Failure(`${flag} is required`);
    return v;
  };
  const version = need("--version");
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)) {
    throw new Failure(`--version «${version}» is not X.Y.Z`);
  }
  const sha256 = need("--sha256").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sha256)) throw new Failure(`--sha256 «${sha256}» is not a SHA-256`);
  return {
    dir: resolve(need("--dir")),
    version,
    sha256,
    notesOut: resolve(need("--notes-out")),
    repo: values["--repo"] ?? process.env.GITHUB_REPOSITORY ?? "afklink/afklink-pc",
  };
}

function keyFile(file: string): KeyLine | null {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Failure(`${shown(file)} not read: ${String(err)}`);
  }
  return parseKeyLine(text, shown(file));
}

/** Run `step`, turning its error into a Failure that says which check it was. */
function check<T>(what: string, step: () => T): T {
  try {
    return step();
  } catch (err) {
    throw new Failure(`${what}: ${(err as Error).message}`);
  }
}

async function main(): Promise<void> {
  const o = parseArgs(process.argv.slice(2));
  const exe = releaseExeName(o.version);
  const files = releaseAssets(o.version).filter((f) => f !== SUMS_FILE);
  const names = assertPublishSet(o.dir, join(o.dir, "..", "symbols-are-never-here"), files);
  console.log(`[${TAG}] ${shown(o.dir)}: ${names.join(", ")}`);

  const bytes = readFileSync(join(o.dir, exe));
  const hash = sha256Of(bytes);
  if (hash !== o.sha256) {
    throw new Failure(`${exe} has SHA-256 ${hash}, but the build job built ${o.sha256}`);
  }
  console.log(`[${TAG}] ${exe}: the build job's bytes, SHA-256 ${hash}, ${bytes.length} bytes`);

  const production = check("update keys", () => keyFile(UPDATER_PUBKEY));
  const test = check("update keys", () => keyFile(TEST_PUBKEY));
  console.log(
    `[${TAG}] ${check("update keys", () => assertKeyFiles(production, test)).join("; ")}`,
  );
  if (production === null) throw new Failure("unreachable: no update key");
  const embedded = check(exe, () => assertEmbeddedKeys(bytes, production, test));
  console.log(`[${TAG}] ${embedded.join("; ")}`);

  const sigText = readFileSync(join(o.dir, `${exe}.sig`), "utf8");
  const signed = check(`${exe}.sig`, () =>
    checkReleaseSignature(bytes, sigText, production.key, o.version),
  );
  console.log(`[${TAG}] signature verified: key ${signed.keyId}, «${signed.trustedComment}»`);

  const sbom = check(sbomName(o.version), () =>
    JSON.parse(readFileSync(join(o.dir, sbomName(o.version)), "utf8")),
  );
  if (sbom?.bomFormat !== "CycloneDX" || !Array.isArray(sbom?.components)) {
    throw new Failure(`${sbomName(o.version)} is not a CycloneDX JSON document with components`);
  }
  console.log(
    `[${TAG}] SBOM: CycloneDX ${sbom.specVersion ?? "?"}, ${sbom.components.length} components`,
  );
  const notices = readFileSync(join(o.dir, NOTICES_FILE), "utf8");
  const missing = NOTICES_MUST_NAME.filter((n) => !notices.includes(n));
  if (missing.length > 0) throw new Failure(`${NOTICES_FILE} does not name ${missing.join(", ")}`);
  console.log(
    `[${TAG}] ${NOTICES_FILE}: ${notices.length} chars, names ${NOTICES_MUST_NAME.join(", ")}`,
  );

  const sums = check(SUMS_FILE, () =>
    sha256Sums(files.map((name) => ({ name, sha256: sha256Of(readFileSync(join(o.dir, name))) }))),
  );
  writeFileSync(join(o.dir, SUMS_FILE), sums, "utf8");
  console.log(`[${TAG}] ${SUMS_FILE}:\n${sums.trimEnd()}`);

  const notes = versionNotes(readFileSync(CHANGELOG, "utf8"), o.version);
  if (notes === null) throw new Failure(`${shown(CHANGELOG)} has no section «## ${o.version} …»`);
  const body = check("release notes", () => releaseBody(notes, o.version, o.repo));
  writeFileSync(o.notesOut, body, "utf8");
  console.log(`[${TAG}] release text: ${shown(o.notesOut)}, ${body.length} chars`);

  const summary = process.env.GITHUB_STEP_SUMMARY;
  if (summary !== undefined && summary !== "") {
    appendFileSync(
      summary,
      `### AFKLink ${o.version}: checked before publishing\n\n` +
        `- signature by key \`${signed.keyId}\`: \`${signed.trustedComment}\`\n` +
        `- ${embedded.join("; ")}\n\n\`\`\`\n${sums}\`\`\`\n`,
      "utf8",
    );
  }
}

if (import.meta.main) await runMain(TAG, main);
