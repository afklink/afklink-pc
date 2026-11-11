/**
 * What `portable.ts`, `release.ts` and `release-build.ts` share: where things are, running commands,
 * read-only git, the workspace version, the target directory (inside this checkout only), and
 * building the desktop app with a stamp.
 */
import { createHash } from "node:crypto";
import { closeSync, existsSync, openSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { checkOpenh264Assembly } from "./openh264";
import {
  awsLcCflags,
  encodedRustflags,
  type PathTrim,
  pathTrim,
  prefixHits,
  userProfile,
} from "./paths";
import { parseVersion } from "./version";

/** The agent repository: these scripts live in its `scripts/lib/`. */
export const AGENT = resolve(import.meta.dir, "..", "..");
export const TAURI_DIR = join(AGENT, "app", "src-tauri");
export const DIST = join(AGENT, "dist");
export const CARGO_TOML = join(AGENT, "Cargo.toml");
export const CARGO_LOCK = join(AGENT, "Cargo.lock");
/**
 * An optional nested workspace at crates/demo-agent, absent in the public tree. When present, it
 * repeats the agent's version and its lock pins the shared crates at it, so a release moves both
 * with the agent's (release.ts); when absent, there is nothing to move.
 */
export const DEMO_CARGO_TOML = join(AGENT, "crates", "demo-agent", "Cargo.toml");
export const DEMO_CARGO_LOCK = join(AGENT, "crates", "demo-agent", "Cargo.lock");
export const CHANGELOG = join(AGENT, "CHANGELOG.md");
/** The updater's public key (minisign, from `cargo tauri signer generate`); see the file itself. */
export const UPDATER_PUBKEY = join(TAURI_DIR, "updater.pub");
/**
 * The TEST public key of the rollback live tests (lib/testkey.ts): embedded only in a build with
 * `TEST_FEATURE`, and there instead of `UPDATER_PUBKEY`.
 */
export const TEST_PUBKEY = join(TAURI_DIR, "updater-test.pub");
/** The cargo feature of afklink-app that embeds `TEST_PUBKEY` (`updater::pubkey`, «The test key»). */
export const TEST_FEATURE = "updater-test-key";
/**
 * The mark of the one sanctioned release-channel test-key build (`ACK_VAR` in
 * app/src-tauri/build_test_key.rs): without it build.rs refuses any release-channel build with
 * `TEST_FEATURE`.
 */
export const TEST_KEY_BUILD_VAR = "AFKLINK_TEST_KEY_BUILD";

/**
 * `TEST_KEY_BUILD_VAR` for a shipping build of `features`: `1` for the test-key build, empty for
 * every other, so a value left in the shell never reaches a build.
 */
export function testKeyBuildEnv(features: readonly string[]): Record<string, string> {
  return { [TEST_KEY_BUILD_VAR]: features.includes(TEST_FEATURE) ? "1" : "" };
}

/**
 * The product's one server, stamped into portable and release builds as the default address of a
 * new config.json: the agents' own hostname, `api.afklink.app` (it serves what an agent calls and
 * nothing else). A build stamped with it connects to nothing else: the agent replaces any
 * other remote address in config.json at load (`PROD_SERVER_URL` in `afklink_core::config`, which
 * must say the same; a test below checks).
 */
export const PROD_SERVER_URL = "wss://api.afklink.app/ws/agent";

/**
 * Where releases are downloaded from: the agents' hostname's `/download/` (latest.json, the exe,
 * .sig) — the updater's one endpoint, and the base of the exe URL inside latest.json. `release.yml`'s
 * `PUBLIC_BASE` and the updater's `ENDPOINT` must say the same (a scripts test checks). People
 * download from the website's own `/download/` (the same directory on the server).
 */
export const DOWNLOAD_BASE_URL = "https://api.afklink.app/download/";

/** Hex digits of the commit in file names, as in the app's Settings («0.1.0 · 3a3bc46 · dev»). */
export const SHORT_COMMIT = 7;

/** Signing secrets: never handed to the build (vite exposes `TAURI_*` to the window's bundle). */
export const SIGNING_ENV_VARS = [
  "TAURI_SIGNING_PRIVATE_KEY",
  "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
  "TAURI_SIGNING_PRIVATE_KEY_PATH",
  "TAURI_PRIVATE_KEY",
  "TAURI_PRIVATE_KEY_PASSWORD",
  "TAURI_PRIVATE_KEY_PATH",
  "TAURI_KEY_PASSWORD",
] as const;

/** A failure whose message is the whole diagnosis. */
export class Failure extends Error {}

/** `path` as seen from the agent repository, for messages; a path outside it stays absolute. */
export function shown(path: string): string {
  const rel = relative(AGENT, path);
  return rel === "" || rel.startsWith("..") ? resolve(path) : rel;
}

export interface Ran {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Run a command to completion and capture its output; `null` when it cannot be started at all.
 * Without `env`: this process's environment minus the signing secrets (`buildEnv({})`) — in CI the
 * release step holds the updater's key, and the tools run before the build (git, cargo, rustc,
 * the downloaded NASM) must never see it; only `signer sign` is handed it, explicitly.
 */
export function run(
  cmd: string[],
  cwd = AGENT,
  env: Record<string, string | undefined> = buildEnv({}),
): Ran | null {
  try {
    const r = Bun.spawnSync({ cmd, cwd, env, stdout: "pipe", stderr: "pipe" });
    return { code: r.exitCode, stdout: r.stdout.toString(), stderr: r.stderr.toString() };
  } catch {
    return null;
  }
}

/**
 * Run a command with its output on this terminal; resolves to its exit code (-1: not started).
 * Without `env`, the signing secrets are left out, as for `run`.
 */
export async function runVisible(
  cmd: string[],
  cwd = AGENT,
  env: Record<string, string | undefined> = buildEnv({}),
): Promise<number> {
  try {
    const p = Bun.spawn({ cmd, cwd, env, stdin: "ignore", stdout: "inherit", stderr: "inherit" });
    return await p.exited;
  } catch {
    return -1;
  }
}

/**
 * `git` in `dir` (the agent repository by default). `--no-optional-locks`: a read does not even
 * refresh the index. Throws on a non-zero exit with git's own words.
 */
export function git(args: string[], dir = AGENT): string {
  const r = run(["git", "--no-optional-locks", "-C", dir, ...args]);
  if (r === null) throw new Failure("git не найден в PATH.");
  if (r.code !== 0) {
    throw new Failure(`git ${args.join(" ")} завершился с кодом ${r.code}: ${r.stderr.trim()}`);
  }
  return r.stdout;
}

/** `git` whose non-zero exit is an answer, not an error (`rev-parse --verify`, `merge-base`). */
export function gitAsk(args: string[], dir = AGENT): Ran {
  const r = run(["git", "--no-optional-locks", "-C", dir, ...args]);
  if (r === null) throw new Failure("git не найден в PATH.");
  return r;
}

/** The full hash of HEAD. */
export function headCommit(dir = AGENT): string {
  const commit = git(["rev-parse", "HEAD"], dir).trim();
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Failure(`git rev-parse HEAD: «${commit}»`);
  return commit;
}

/**
 * `git status` lines that make the agent's tree dirty; empty for a clean one. Tracked, untracked
 * (not ignored) and the contract submodule's own state: the window's text is bundled from
 * contract/, so a modified contract is a build that is not the commit either.
 */
export function treeChanges(dir = AGENT): string[] {
  return git(
    ["status", "--porcelain=v1", "--ignore-submodules=none", "--untracked-files=normal"],
    dir,
  )
    .split("\n")
    .map((line) => line.trimEnd())
    .filter((line) => line !== "");
}

/** Print up to 20 `git status` lines under a heading. */
export function printChanges(tag: string, changes: string[], what: string): void {
  const head = changes.slice(0, 20);
  console.log(`[${tag}] ${what}: ${changes.length} изменений:`);
  for (const line of head) console.log(`             ${line}`);
  if (changes.length > head.length) {
    console.log(`             … и ещё ${changes.length - head.length}`);
  }
}

/**
 * The workspace version — `[workspace.package] version` in Cargo.toml, the one place it is written
 * — as cargo sees it (`cargo metadata`): every member inherits it, and one that does not is a
 * mistake worth stopping on, because the exe, the log and the file name must say one number.
 */
export function workspaceVersion(): string {
  const r = run(["cargo", "metadata", "--no-deps", "--format-version", "1"]);
  if (r === null) {
    throw new Failure("cargo не найден в PATH: установите Rust через rustup (https://rustup.rs).");
  }
  if (r.code !== 0) throw new Failure(`cargo metadata завершился с кодом ${r.code}: ${r.stderr}`);
  let meta: { packages: { name: string; version: string }[] };
  try {
    meta = JSON.parse(r.stdout);
  } catch (err) {
    throw new Failure(`cargo metadata: ответ не разобран: ${String(err)}`);
  }
  const versions = new Map(meta.packages.map((p) => [p.name, p.version]));
  const app = versions.get("afklink-app");
  if (app === undefined) throw new Failure("cargo metadata: нет пакета afklink-app");
  const strays = [...versions].filter(([, v]) => v !== app);
  if (strays.length > 0) {
    throw new Failure(
      `версия должна быть одна на весь workspace (${app} у afklink-app), а у ` +
        `${strays.map(([n, v]) => `${n} — ${v}`).join(", ")}: верните им \`version.workspace = true\``,
    );
  }
  if (parseVersion(app) === null) {
    throw new Failure(`версия workspace «${app}» — не номер вида 1.2.3 (Cargo.toml)`);
  }
  return app;
}

/**
 * Whether `exe` can be opened for writing — the build has to replace it. A running exe is mapped by
 * Windows and refuses that (EBUSY; EPERM/EACCES for a read-only file). Nothing is closed from here.
 */
export function assertWritable(exe: string, what: string, retry: string): void {
  if (!existsSync(exe)) return;
  let fd: number;
  try {
    fd = openSync(exe, "r+");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? "?";
    if (code === "EBUSY" || code === "EPERM" || code === "EACCES") {
      throw new Failure(
        `${shown(exe)} занят (${code}): ${what} запущен. Закройте AFKLink из трея ` +
          `(правый клик по значку → «Выход») и повторите \`${retry}\`.`,
      );
    }
    throw new Failure(`${shown(exe)} не открывается для записи: ${String(err)}`);
  }
  closeSync(fd);
}

/** Tauri CLI 2, as `cargo tauri`; its version line. */
export function assertCargoTauri(): string {
  const r = run(["cargo", "tauri", "--version"]);
  if (r === null) {
    throw new Failure("cargo не найден в PATH: установите Rust через rustup (https://rustup.rs).");
  }
  const version = r.stdout.trim();
  if (r.code !== 0) {
    throw new Failure(
      "`cargo tauri` не найден. Установите Tauri CLI: `cargo install tauri-cli --version ^2 --locked` " +
        `(cargo ответил: ${(r.stderr || r.stdout).trim()})`,
    );
  }
  const major = /tauri-cli (\d+)\./.exec(version)?.[1];
  if (major !== "2") {
    throw new Failure(
      `нужен Tauri CLI 2, а \`cargo tauri --version\` говорит «${version}». ` +
        "Обновите: `cargo install tauri-cli --version ^2 --locked`",
    );
  }
  return version;
}

/** Now, UTC, to the second: `YYYY-MM-DDTHH:MM:SSZ` — the stamp's shape, and RFC 3339. */
export function utcNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * The variables that move cargo's target directory, in cargo's order of precedence:
 * `CARGO_TARGET_DIR`, then `CARGO_BUILD_TARGET_DIR` (`build.target-dir` given as a variable).
 */
export const TARGET_DIR_VARS = ["CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR"] as const;

/** Where cargo builds, and which variable said so. */
export interface TargetDir {
  /** Absolute, as given: links not followed. */
  dir: string;
  /** `null`: no variable, the workspace's own `target/`. */
  from: (typeof TARGET_DIR_VARS)[number] | null;
  /** The variable's value as it was set, for messages. */
  raw: string | null;
}

/**
 * The target directory the build in `checkout`/app/src-tauri will use: the first of
 * `TARGET_DIR_VARS` that is set — a relative value is relative to the directory cargo runs in,
 * app/src-tauri for `cargo tauri build` — else `checkout`/target.
 */
export function targetDir(
  env: Record<string, string | undefined> = process.env,
  checkout = AGENT,
): TargetDir {
  for (const from of TARGET_DIR_VARS) {
    const raw = env[from]?.trim();
    if (raw !== undefined && raw !== "") {
      return { dir: resolve(checkout, "app", "src-tauri", raw), from, raw };
    }
  }
  return { dir: join(checkout, "target"), from: null, raw: null };
}

/** Whether `path` is `dir` or lies under it, by path alone (another drive is not under it). */
export function isWithin(dir: string, path: string): boolean {
  const rel = relative(dir, path);
  return !(rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel));
}

/**
 * `path` with links followed as far as it exists: the deepest part that exists, through
 * `realpath`, plus the rest as written. A target directory not built yet is judged by where its
 * parent really is; one that is a link (a junction on Windows) by where it leads.
 */
export function realPath(path: string): string {
  const rest: string[] = [];
  let at = resolve(path);
  for (;;) {
    try {
      return join(realpathSync.native(at), ...rest);
    } catch {
      const up = dirname(at);
      // The root does not exist either (a drive that is not there): as written, then.
      if (up === at) return resolve(path);
      rest.unshift(basename(at));
      at = up;
    }
  }
}

/**
 * Refuse a target directory outside `checkout` — set by `TARGET_DIR_VARS`, or `target/` itself a
 * link that leads out.
 *
 * Cargo tells a workspace's own crates apart by their path relative to the workspace root, not by
 * the checkout they sit in, so two checkouts building into one directory share build units: a build
 * in one can link crates compiled from the other's sources, and the stamp checks in
 * `buildDesktopApp` do not see it — the stamp is compiled fresh either way. A portable from the
 * main tree has linked a stale `afklink-transport` that a scratch worktree of another commit
 * had built into the shared `agent\target`. A target directory inside
 * the checkout is this checkout's alone.
 */
export function assertTargetInCheckout(target: TargetDir, checkout = AGENT): void {
  const home = realPath(checkout);
  const real = realPath(target.dir);
  if (isWithin(home, real)) return;
  const said =
    (target.from === null ? `каталог сборки ${target.dir}` : `${target.from}=${target.raw}`) +
    // Where it really leads, when a link took it elsewhere than it says.
    (real === resolve(target.dir) ? "" : ` — это ${real}`);
  const fix =
    target.from === null
      ? `Сделайте ${target.dir} обычной папкой, не ссылкой.`
      : `Уберите ${target.from} (сборка пойдёт в target этой копии) ` +
        `или укажите каталог внутри ${home}.`;
  throw new Failure(
    `${said}: вне этой копии кода (${home}). Cargo узнаёт крейты workspace по пути ` +
      "от его корня, поэтому две копии в одном каталоге сборки делят скомпилированные крейты, и " +
      "exe может собраться со старым кодом другой копии (28 сент. portable так взял старый " +
      `afklink-transport из worktree). ${fix}`,
  );
}

/**
 * The cargo profile of what ships (`[profile.dist]` in Cargo.toml: release plus fat LTO, one
 * codegen unit and line tables in the PDB only), and so the directory under the target directory
 * its exe lands in.
 */
export const SHIP_PROFILE = "dist";

/**
 * Where cargo puts the shipping exe (`targetDir`/`SHIP_PROFILE`); a target directory outside this
 * checkout is refused here (`assertTargetInCheckout`), before anything is built.
 */
export function releaseExe(): string {
  const target = targetDir();
  assertTargetInCheckout(target);
  return join(target.dir, SHIP_PROFILE, "afklink-app.exe");
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function mib(bytes: number): string {
  return `${(bytes / 1024 / 1024).toFixed(1)} МиБ`;
}

/** A build's identity, handed to `cargo tauri build` in the environment (`afklink_core::build_info`). */
export interface Stamp {
  version: string;
  commit: string;
  dirty: boolean;
  builtAt: string;
  channel: "dev" | "release";
  serverUrl: string;
}

/**
 * Variables through which the Tauri CLI and tauri-build take configuration from outside
 * `tauri.conf.json`: `TAURI_CONFIG` (JSON merged over the file by tauri-build; the CLI sets it
 * itself from `--config`, which no build of ours passes) and `TAURI_CLI_CONFIG_DEPTH` (how far the
 * CLI searches for a config file). A value left in the shell must not change what ships, so a build
 * never gets them. Removed, not blanked: an empty `TAURI_CONFIG` is not JSON and fails the build.
 */
export const TAURI_CONFIG_ENV_VARS = ["TAURI_CONFIG", "TAURI_CLI_CONFIG_DEPTH"] as const;

/** `process.env` without the signing secrets and the Tauri config overrides, plus `extra`. */
export function buildEnv(extra: Record<string, string>): Record<string, string | undefined> {
  const env: Record<string, string | undefined> = { ...process.env };
  for (const name of SIGNING_ENV_VARS) delete env[name];
  for (const name of TAURI_CONFIG_ENV_VARS) delete env[name];
  return { ...env, ...extra };
}

/**
 * `cargo tauri build --no-bundle` in app/src-tauri with `stamp` in the environment, then the checks
 * that the exe is this build's: written by it, and carrying its commit, time and server address
 * (compiled in as plain strings — a build that reused a crate compiled without them lacks them).
 * The signing secrets are not passed on: the build runs third-party build scripts, and vite puts
 * `TAURI_*` variables within reach of the window's bundle. `features`: cargo features of afklink-app
 * — none for every build but the test-key one (`TEST_FEATURE`, `release-build.ts --test-key`).
 */
export async function buildDesktopApp(
  stamp: Stamp,
  tag: string,
  features: readonly string[] = [],
  env: Record<string, string> = {},
): Promise<Buffer> {
  const exe = releaseExe();
  const target = targetDir();
  console.log(
    `[${tag}] каталог сборки: ${shown(target.dir)}` +
      (target.from === null ? "" : ` (из ${target.from}=${target.raw})`),
  );
  const { started, trim } = await shipBuild(stamp, tag, features, env);

  if (!existsSync(exe)) throw new Failure(`после сборки нет ${shown(exe)}`);
  // Written by this build: a stale exe must never be published under this build's name.
  if (statSync(exe).mtimeMs < started - 2000) {
    throw new Failure(`${shown(exe)} не обновился этой сборкой (время файла раньше её начала)`);
  }
  const bytes = readFileSync(exe);
  for (const [what, value] of [
    ["коммит", stamp.commit],
    ["время сборки", stamp.builtAt],
    ["адрес сервера", stamp.serverUrl],
  ] as const) {
    if (!bytes.includes(Buffer.from(value, "utf8"))) {
      throw new Failure(`в ${shown(exe)} не найден ${what} «${value}»: сборка взяла старый код`);
    }
  }
  // What is left of the build machine's paths: said, not refused — a new dependency's C code can
  // bring some back, and that is a finding for the next change, not a reason to stop a release.
  reportLeftPaths(bytes, trim, tag);
  assertOpenh264Assembly(exe, target, started, tag);
  return bytes;
}

/** The PDB the linker writes beside the app's exe (`/PDBALTPATH:%_PDB%`, scripts/lib/symbols.ts). */
export const APP_PDB = "afklink_app.pdb";

/**
 * Refuse an exe whose OpenH264 was built without its assembly (scripts/lib/openh264.ts): the
 * openh264-sys2 build-script output of this profile, and OpenH264's assembly functions in the PDB
 * written beside `exe` by this build.
 */
export function assertOpenh264Assembly(
  exe: string,
  target: TargetDir,
  started: number,
  tag: string,
): void {
  const verdict = checkOpenh264Assembly(
    join(target.dir, SHIP_PROFILE),
    join(dirname(exe), APP_PDB),
    started,
    shown,
  );
  for (const note of verdict.notes) console.log(`[${tag}] OpenH264: ${note}`);
  if (verdict.problem !== null) throw new Failure(verdict.problem);
  console.log(`[${tag}] OpenH264: ассемблер в exe`);
}

/** Say what is left of the build machine's paths in `bytes`, per prefix and in total. */
export function reportLeftPaths(bytes: Buffer, trim: PathTrim, tag: string): number {
  const left = prefixHits(bytes, [...trim.prefixes, userProfile()]);
  for (const { prefix, hits } of left.per) {
    if (hits > 0) console.warn(`[${tag}] ВНИМАНИЕ: в exe осталось путей ${prefix}: ${hits}`);
  }
  console.log(
    `[${tag}] пути сборки в exe: ${left.total} (проверено ${left.per.length} префиксов, ` +
      "вложенные не считаются дважды)",
  );
  return left.total;
}

/** The triple a build with no `--target` builds for: rustc's `host:` (`rustc -vV`), as cargo does. */
export const FALLBACK_TRIPLE = "x86_64-pc-windows-msvc";

/** `rustc -vV`'s `host:` line; `FALLBACK_TRIPLE` (said) when rustc does not answer with one. */
export function hostTriple(tag: string): string {
  const r = run(["rustc", "-vV"]);
  const host = r === null ? undefined : /^host:\s*(\S+)\s*$/m.exec(r.stdout)?.[1];
  if (host === undefined) {
    console.warn(
      `[${tag}] ВНИМАНИЕ: rustc -vV не назвал host (` +
        (r === null ? "rustc не запустился" : `код ${r.code}`) +
        `), беру ${FALLBACK_TRIPLE}`,
    );
    return FALLBACK_TRIPLE;
  }
  console.log(`[${tag}] цель сборки (rustc host): ${host}`);
  return host;
}

/**
 * The variables the shipping build of `stamp` and `features` gets on top of `buildEnv`: the caller's
 * `env` (the test build's breakage), then what nothing may override — the test-key mark, which only
 * the features decide, the stamp, and rustc's flags (`rustflags`, already encoded).
 */
export function shipEnv(
  stamp: Stamp,
  features: readonly string[],
  env: Record<string, string>,
  rustflags: string,
): Record<string, string> {
  return {
    // The test build's breakage variable is always given (empty unless a test build asks): a value
    // left in the shell never reaches a build (`env` below may set it).
    AFKLINK_TEST_BREAK_SERVER_URL: "",
    ...env,
    // After `env`: only the features decide whether build.rs lets a release-channel test-key
    // build through.
    ...testKeyBuildEnv(features),
    AFKLINK_BUILD_COMMIT: stamp.commit,
    AFKLINK_BUILD_DIRTY: stamp.dirty ? "1" : "0",
    AFKLINK_BUILD_TIME: stamp.builtAt,
    AFKLINK_BUILD_CHANNEL: stamp.channel,
    AFKLINK_SERVER_URL: stamp.serverUrl,
    CARGO_ENCODED_RUSTFLAGS: rustflags,
  };
}

/**
 * The shipping build itself, without the target-directory guard (`buildDesktopApp` adds it):
 * `cargo fetch --locked` so the registry's sources are on disk, the path trims made from them
 * (scripts/lib/paths.ts), then `cargo tauri build --no-bundle -- --profile dist` with `stamp`.
 * Returns when it started (for the freshness check) and the trims (for the check of what is left).
 */
export async function shipBuild(
  stamp: Stamp,
  tag: string,
  features: readonly string[] = [],
  env: Record<string, string> = {},
): Promise<{ started: number; trim: PathTrim }> {
  // Refused before anything runs, whoever called: the test key never in a build under GitHub
  // Actions (build.rs refuses a release-channel one there too, and anywhere without
  // `TEST_KEY_BUILD_VAR`).
  const cargoArgs = shipCargoArgs(features, process.env);
  if ((env.AFKLINK_TEST_BREAK_SERVER_URL ?? "") !== "" && !features.includes(TEST_FEATURE)) {
    throw new Failure("сломанный адрес сервера — только у тестовой сборки (фича updater-test-key)");
  }
  // The registry's sources first: the trims are made from what is on disk, and on a cold cache
  // (CI after 7 days, a new PC) `registry\src` does not exist until cargo fetches.
  // Only the build's own target: no Linux or macOS crates, so a build that needs nothing new
  // does not depend on the network.
  const triple = hostTriple(tag);
  const fetch = ["cargo", "fetch", "--locked", "--target", triple];
  console.log(`[${tag}] ${fetch.join(" ")} (в ${shown(AGENT)})`);
  const fetched = await runVisible(fetch, AGENT, buildEnv({}));
  console.log(`[${tag}] cargo fetch: код ${fetched}`);
  if (fetched !== 0) throw new Failure(`${fetch.join(" ")} завершился с кодом ${fetched}`);

  // Build-machine paths out of the exe (scripts/lib/paths.ts): rustc's remaps and cl's trims.
  const trim = pathTrim(AGENT);
  console.log(
    `[${tag}] пути сборки в exe: ${trim.rustflags.length} замен для rustc, ` +
      `${trim.awsLcCflags.length} для cl (aws-lc)`,
  );
  for (const flag of [...trim.rustflags, ...trim.awsLcCflags]) console.log(`             ${flag}`);
  for (const p of trim.skipped) {
    console.warn(`[${tag}] ВНИМАНИЕ: путь с пробелом не передать cl, останется в exe: ${p}`);
  }
  if (process.env.CARGO_ENCODED_RUSTFLAGS !== undefined || process.env.RUSTFLAGS?.trim()) {
    console.log(`[${tag}] флаги rustc из окружения сохранены, замены путей добавлены после них`);
  }
  const extra = shipEnv(stamp, features, env, encodedRustflags(process.env, trim.rustflags));
  const cflags = awsLcCflags(process.env, trim.awsLcCflags, triple);
  if (cflags === null) {
    console.log(`[${tag}] флагов cl для aws-lc нет: AWS_LC_SYS_CFLAGS не задаётся`);
  } else {
    extra[cflags.name] = cflags.value;
    console.log(`[${tag}] ${cflags.name}=${cflags.value}`);
    if (cflags.note !== null) console.log(`[${tag}] ${cflags.note}`);
    for (const w of cflags.warnings) console.warn(`[${tag}] ВНИМАНИЕ: ${w}`);
  }
  const cmd = ["cargo", "tauri", ...cargoArgs];
  if (features.length > 0) console.log(`[${tag}] cargo-фичи afklink-app: ${features.join(", ")}`);
  console.log(`[${tag}] ${cmd.join(" ")} (в ${shown(TAURI_DIR)})\n`);
  const started = Date.now();
  const code = await runVisible(cmd, TAURI_DIR, buildEnv(extra));
  if (code !== 0) throw new Failure(`cargo tauri build завершился с кодом ${code}`);
  return { started, trim };
}

/**
 * The arguments of `cargo tauri` for the shipping build: `build --no-bundle [--features …] --
 * --profile dist`. Refuses `TEST_FEATURE` under GitHub Actions (`GITHUB_ACTIONS` set): a test-key
 * build is made only on the test PC, never where releases are built.
 */
export function shipCargoArgs(
  features: readonly string[],
  env: Record<string, string | undefined>,
): string[] {
  if (features.includes(TEST_FEATURE) && (env.GITHUB_ACTIONS ?? "").trim() !== "") {
    throw new Failure(
      `фича ${TEST_FEATURE} (тестовый ключ подписи) под GitHub Actions: тестовая сборка делается ` +
        "только на тестовом ПК (`bun scripts/release-build.ts --test-key`), выпуск тестовому ключу не доверяет",
    );
  }
  const featureArgs = features.length === 0 ? [] : ["--features", features.join(",")];
  return ["build", "--no-bundle", ...featureArgs, "--", "--profile", SHIP_PROFILE];
}

/** Run `main`, printing a `Failure` as the whole diagnosis (anything else with its stack); exit 1. */
export async function runMain(tag: string, main: () => Promise<void>): Promise<void> {
  try {
    await main();
  } catch (err) {
    const message =
      err instanceof Failure ? err.message : String(err instanceof Error ? err.stack : err);
    console.error(`\n[${tag}] ошибка: ${message}`);
    process.exit(1);
  }
}
