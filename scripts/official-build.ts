/**
 * `bun scripts/official-build.ts [--dry-run]` — the unsigned exe of an official release, built by
 * `.github/workflows/release.yml` on a Windows runner. It holds no signing key and signs nothing:
 * the workflow signs the exe in a job of its own (RELEASING.md).
 *
 *   1. A release (no `--dry-run`): HEAD is the commit of the tag `v<version>` (version:
 *      `[workspace.package]` in Cargo.toml), that commit is on `origin/main` (fetched), the tree is
 *      clean, and under GitHub Actions the pushed tag is that tag. The version's CHANGELOG section must exist: it becomes the release notes.
 *      `--dry-run` builds whatever HEAD is, under a name no updater accepts as a release.
 *   2. Refused before the build: a signing secret in the environment (this job must have none),
 *      another server address (`AFKLINK_SERVER_URL`), the test build's broken address, an update
 *      key file with no key or the same key in both key files, a missing NASM (OpenH264 would be
 *      built without its assembly) or Tauri CLI 2.
 *   3. `cargo tauri build --no-bundle -- --profile dist` with no cargo features (never
 *      `updater-test-key`) and the stamp: release channel, this commit, the build time and
 *      `wss://api.afklink.app/ws/agent` (`shipBuild` in lib/common.ts, which also refuses the test
 *      feature under GitHub Actions). The exe must carry the stamp, OpenH264's assembly, the key
 *      line of `app/src-tauri/updater.pub` and not the line of `updater-test.pub`.
 *   4. `dist/official/<version>/AFKLink-<version>.exe` (a dry run: `<version>-dry-run/` and
 *      `AFKLink-<version>-untagged-<commit>[-dirty].exe`), alone in its folder; its debug symbols
 *      in `dist/symbols/<version>[-dry-run]/` (lib/symbols.ts), never in the release.
 *   5. Under GitHub Actions: `version`, `exe`, `dir`, `sha256`, `size`, `symbols` and `release`
 *      (`true` or `false`) into $GITHUB_OUTPUT, and a summary.
 */
import { appendFileSync, copyFileSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { versionNotes } from "./lib/changelog";
import {
  assertCargoTauri,
  assertWritable,
  buildDesktopApp,
  CHANGELOG,
  DIST,
  Failure,
  gitAsk,
  headCommit,
  mib,
  PROD_SERVER_URL,
  printChanges,
  releaseExe,
  runMain,
  SHORT_COMMIT,
  SIGNING_ENV_VARS,
  type Stamp,
  shown,
  TEST_PUBKEY,
  treeChanges,
  UPDATER_PUBKEY,
  utcNow,
  workspaceVersion,
} from "./lib/common";
import {
  assertEmbeddedKeys,
  assertKeyFiles,
  dryRunExeName,
  type KeyLine,
  parseKeyLine,
  releaseExeName,
  sha256Of,
} from "./lib/official";
import { assertPublishSet, collectSymbols } from "./lib/symbols";
import { assertNasm } from "./lib/toolchain";

const TAG = "official-build";

/** The test build's broken signaling address (a test-key build only; never set for a release). */
const BREAK_VAR = "AFKLINK_TEST_BREAK_SERVER_URL";

/** The public repository's protected branch: a release tag must name a commit on it. */
const MAIN_BRANCH = "main";

/**
 * Refuse a commit that is not on `origin/<MAIN_BRANCH>`: a tag pushed on a side branch (or on a
 * commit never merged) is not a release. The branch is fetched first, so the answer is the
 * remote's, not a stale local ref.
 */
function assertOnMain(commit: string): void {
  const ref = `refs/remotes/origin/${MAIN_BRANCH}`;
  const fetched = gitAsk([
    "fetch",
    "--no-tags",
    "--quiet",
    "origin",
    `+refs/heads/${MAIN_BRANCH}:${ref}`,
  ]);
  if (fetched.code !== 0) {
    throw new Failure(
      `git fetch origin ${MAIN_BRANCH} failed (${fetched.code}): ${fetched.stderr.trim()}`,
    );
  }
  const tip = gitAsk(["rev-parse", "-q", "--verify", `${ref}^{commit}`]).stdout.trim();
  const ancestor = gitAsk(["merge-base", "--is-ancestor", commit, ref]);
  if (ancestor.code === 1) {
    throw new Failure(
      `${commit.slice(0, SHORT_COMMIT)} is not on ${MAIN_BRANCH} (its tip is ` +
        `${tip.slice(0, SHORT_COMMIT) || "?"}): a release is tagged on ${MAIN_BRANCH} only`,
    );
  }
  if (ancestor.code !== 0) {
    throw new Failure(
      `git merge-base --is-ancestor failed (${ancestor.code}): ${ancestor.stderr.trim()} ` +
        "(a shallow clone? the workflow checks out the whole history)",
    );
  }
  console.log(
    `[${TAG}] ${commit.slice(0, SHORT_COMMIT)} is on ${MAIN_BRANCH} (tip ${tip.slice(0, SHORT_COMMIT)})`,
  );
}

function parseArgs(argv: string[]): { dryRun: boolean } {
  let dryRun = false;
  for (const arg of argv) {
    if (arg === "--dry-run") dryRun = true;
    else throw new Failure(`unknown argument «${arg}». Usage: official-build.ts [--dry-run]`);
  }
  return { dryRun };
}

function readKeyFile(file: string): KeyLine | null {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Failure(`${shown(file)} not read: ${String(err)}`);
  }
  try {
    return parseKeyLine(text, shown(file));
  } catch (err) {
    throw new Failure((err as Error).message);
  }
}

/** Refuse what must never reach an official build from the environment. */
function assertCleanEnvironment(env: Record<string, string | undefined>): void {
  const secrets = SIGNING_ENV_VARS.filter((name) => (env[name] ?? "") !== "");
  if (secrets.length > 0) {
    throw new Failure(
      `${secrets.join(", ")} set: the build job holds no signing secret (the exe is signed in a ` +
        "job of its own). Remove them from this job",
    );
  }
  const server = env.AFKLINK_SERVER_URL?.trim();
  if (server !== undefined && server !== "" && server !== PROD_SERVER_URL) {
    throw new Failure(
      `AFKLINK_SERVER_URL=${server}: a release is always built with ${PROD_SERVER_URL}`,
    );
  }
  const broken = env[BREAK_VAR]?.trim();
  if (broken !== undefined && broken !== "") {
    throw new Failure(`${BREAK_VAR} is set: that is a test build's breakage, never a release's`);
  }
}

function githubOutput(values: Record<string, string>): void {
  const file = process.env.GITHUB_OUTPUT;
  if (file === undefined || file === "") return;
  appendFileSync(
    file,
    Object.entries(values)
      .map(([k, v]) => `${k}=${v}\n`)
      .join(""),
    "utf8",
  );
}

function githubSummary(markdown: string): void {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (file === undefined || file === "") return;
  appendFileSync(file, markdown, "utf8");
}

async function main(): Promise<void> {
  const { dryRun } = parseArgs(process.argv.slice(2));
  assertCleanEnvironment(process.env);
  const version = workspaceVersion();
  const commit = headCommit();
  const short = commit.slice(0, SHORT_COMMIT);
  const changes = treeChanges();
  const dirty = changes.length > 0;
  const tagName = `v${version}`;
  console.log(
    `[${TAG}] version ${version}, commit ${commit}${dirty ? ", with uncommitted changes" : ""}` +
      (dryRun ? ", DRY RUN (not a release)" : ""),
  );

  if (!dryRun) {
    const tagged = gitAsk(["rev-parse", "-q", "--verify", `refs/tags/${tagName}^{commit}`]);
    const tagCommit = tagged.code === 0 ? tagged.stdout.trim() : null;
    if (tagCommit !== commit) {
      throw new Failure(
        tagCommit === null
          ? `no tag ${tagName} here: a release is built only from the tag of Cargo.toml's version`
          : `HEAD ${short} is not the commit of ${tagName} (${tagCommit.slice(0, SHORT_COMMIT)})`,
      );
    }
    const pushed = process.env.GITHUB_REF_TYPE === "tag" ? process.env.GITHUB_REF_NAME : undefined;
    if (process.env.GITHUB_ACTIONS === "true" && pushed !== tagName) {
      throw new Failure(
        `this run is for ${process.env.GITHUB_REF ?? "no ref"}, but Cargo.toml says ${version}: ` +
          `a release runs on the push of the tag ${tagName}`,
      );
    }
    assertOnMain(commit);
    if (dirty) {
      printChanges(TAG, changes, "the tree is not clean");
      throw new Failure("uncommitted changes: a release is built from a clean tag only");
    }
    console.log(`[${TAG}] HEAD is the tag ${tagName}, the tree is clean`);
    const notes = versionNotes(readFileSync(CHANGELOG, "utf8"), version);
    if (notes === null || notes === "") {
      throw new Failure(
        `${shown(CHANGELOG)} has no text under «## ${version} …»: no release notes`,
      );
    }
    console.log(
      `[${TAG}] release notes: the CHANGELOG section of ${version}, ${notes.length} chars`,
    );
  } else if (dirty) {
    printChanges(TAG, changes, "dry run of a tree with changes");
  }

  const production = readKeyFile(UPDATER_PUBKEY);
  const test = readKeyFile(TEST_PUBKEY);
  let keyNotes: string[];
  try {
    keyNotes = assertKeyFiles(production, test);
  } catch (err) {
    throw new Failure((err as Error).message);
  }
  console.log(`[${TAG}] keys: ${keyNotes.join("; ")}`);

  const tauri = assertCargoTauri();
  const nasm = assertNasm();
  console.log(`[${TAG}] ${tauri}; NASM ${nasm.line} (${nasm.path ?? nasm.program})`);
  const built = releaseExe();
  assertWritable(built, "AFKLink from this folder", "official-build.ts");

  const name = dryRun ? dryRunExeName(version, short, dirty) : releaseExeName(version);
  const folder = dryRun ? `${version}-dry-run` : version;
  const outDir = join(DIST, "official", folder);
  const symbolsDir = join(DIST, "symbols", folder);
  const dest = join(outDir, name);

  const stamp: Stamp = {
    version,
    commit,
    dirty,
    builtAt: utcNow(),
    channel: "release",
    serverUrl: PROD_SERVER_URL,
  };
  console.log(`[${TAG}] channel release, server ${PROD_SERVER_URL}, no cargo features`);
  // No features: `updater-test-key` (or any other) never reaches an official build.
  const bytes = await buildDesktopApp(stamp, TAG, []);
  if (production === null) throw new Failure("unreachable: no update key");
  let embedded: string[];
  try {
    embedded = assertEmbeddedKeys(bytes, production, test);
  } catch (err) {
    throw new Failure((err as Error).message);
  }
  console.log(`[${TAG}] keys in the exe: ${embedded.join("; ")}`);

  // The folder holds this exe alone: it is what the workflow uploads.
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  try {
    copyFileSync(built, dest);
  } catch (err) {
    throw new Failure(`${shown(built)} not copied to ${shown(dest)}: ${String(err)}`);
  }
  const hash = sha256Of(readFileSync(dest));
  if (hash !== sha256Of(bytes)) throw new Failure(`${shown(dest)} is not the exe just built`);
  const size = statSync(dest).size;

  const symbols = collectSymbols({
    shippedExe: dest,
    builtExe: built,
    outDir: symbolsDir,
    version,
    channel: stamp.channel,
    commit,
    builtAt: stamp.builtAt,
    tag: TAG,
  });
  assertPublishSet(outDir, symbolsDir, [name]);

  githubOutput({
    version,
    exe: name,
    dir: outDir,
    sha256: hash,
    size: String(size),
    symbols: symbolsDir,
    release: dryRun ? "false" : "true",
  });
  githubSummary(
    `### AFKLink ${version}${dryRun ? " (dry run, not a release)" : ""}: unsigned build\n\n` +
      "| | |\n|---|---|\n" +
      `| commit | \`${commit}\` |\n` +
      `| exe | \`${name}\`, ${size} bytes |\n` +
      `| SHA-256 | \`${hash}\` |\n` +
      `| update key | ${embedded.join("; ")} |\n` +
      symbols.modules
        .map((m) => `| symbols ${m.module} | \`${m.pdb.file}\` GUID \`${m.codeview.guid}\` |\n`)
        .join(""),
  );
  console.log(`\n[${TAG}] done${dryRun ? " (dry run: never to be published)" : ""}`);
  console.log(`  exe      ${dest}`);
  console.log(`  size     ${size} bytes (${mib(size)})`);
  console.log(`  SHA-256  ${hash}`);
  console.log(`  symbols  ${symbolsDir} (not part of the release)`);
}

await runMain(TAG, main);
