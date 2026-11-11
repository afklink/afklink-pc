/**
 * `bun run portable [--dev-fault]` — a development build of the desktop app as one portable exe,
 * built and stamped by one command. The official release build is `bun run release:build`
 * (official-build.ts).
 * `--dev-fault` compiles in the orchestrator's fault on demand (the cargo feature `dev-fault`,
 * app/src-tauri/src/dev_fault.rs), which no other build has.
 *
 *   1. The target directory (`target\`, or CARGO_TARGET_DIR / CARGO_BUILD_TARGET_DIR) must be inside
 *      this checkout: one shared with another checkout (a worktree, a scratch copy) can lend the
 *      build crates compiled from that copy's sources (`assertTargetInCheckout` in lib/common.ts).
 *      And `target\dist\afklink-app.exe` must not be in use: a running AFKLink holds it open and
 *      the build would fail at its very end. Nothing is closed from here — the owner quits AFKLink
 *      from the tray.
 *   2. `cargo tauri` (Tauri CLI 2) must be installed: the app is only ever built through it — it
 *      builds the window (app/ui) and embeds it; a plain `cargo build` makes an exe that looks for a
 *      dev server.
 *   3. The build's identity is worked out here and handed to the build in the environment:
 *      AFKLINK_BUILD_COMMIT / _DIRTY / _TIME, AFKLINK_BUILD_CHANNEL=dev (`afklink_core::build_info`
 *      says why not from git in a build script; the dev channel logs at `debug` until a level is
 *      chosen), and AFKLINK_SERVER_URL — the production server, which a build without it leaves at
 *      ws://localhost:8787 for every config.json it creates.
 *   4. `cargo fetch --locked`, then `cargo tauri build --no-bundle -- --profile dist` in
 *      app/src-tauri, with build-machine paths remapped (`shipBuild` in lib/common.ts).
 *   5. The exe is checked (written by this build, carrying this build's stamp and server address),
 *      copied to `dist\AFKLink-<version>-dev-<commit>[-dirty][-devfault].exe` with a `.sha256` beside it
 *      (`<HEX> *<name>`, what `sha256sum -c` reads; `Get-FileHash` prints the same hex), and the
 *      path, size and hash are printed.
 *
 * The version is the workspace's (`[workspace.package]` in Cargo.toml, via `cargo metadata`), the
 * same one the exe reports. Any failure prints why and exits 1.
 */
import { copyFileSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  assertCargoTauri,
  assertWritable,
  buildDesktopApp,
  DIST,
  Failure,
  headCommit,
  mib,
  PROD_SERVER_URL,
  printChanges,
  releaseExe,
  runMain,
  SHORT_COMMIT,
  type Stamp,
  sha256Hex,
  shown,
  treeChanges,
  utcNow,
  workspaceVersion,
} from "./lib/common";

const TAG = "portable";

/** The cargo feature of afklink-app behind `--dev-fault` (app/src-tauri/Cargo.toml). */
export const DEV_FAULT_FEATURE = "dev-fault";

/** The features of afklink-app that `args` (the command line after the script) ask for. */
export function portableFeatures(args: readonly string[]): string[] {
  const features: string[] = [];
  for (const arg of args) {
    if (arg === "--dev-fault") {
      if (!features.includes(DEV_FAULT_FEATURE)) features.push(DEV_FAULT_FEATURE);
    } else {
      throw new Failure(
        `непонятный аргумент «${arg}». Использование: bun run portable [--dev-fault]`,
      );
    }
  }
  return features;
}

async function main(): Promise<void> {
  const features = portableFeatures(process.argv.slice(2));
  const exe = releaseExe();
  assertWritable(exe, "AFKLink из этой папки", "bun run portable");
  const tauri = assertCargoTauri();
  const override = process.env.AFKLINK_SERVER_URL?.trim();
  const changes = treeChanges();
  const stamp: Stamp = {
    version: workspaceVersion(),
    commit: headCommit(),
    dirty: changes.length > 0,
    builtAt: utcNow(),
    channel: "dev",
    serverUrl: override !== undefined && override !== "" ? override : PROD_SERVER_URL,
  };
  const short = stamp.commit.slice(0, SHORT_COMMIT);
  // A build with the fault on demand says so in its name: it is never handed out as a plain one.
  const faulty = features.includes(DEV_FAULT_FEATURE) ? "-devfault" : "";
  const name = `AFKLink-${stamp.version}-dev-${short}${stamp.dirty ? "-dirty" : ""}${faulty}.exe`;
  const dest = join(DIST, name);
  // A copy of this very build that is running would make the copy fail after the whole build.
  assertWritable(dest, "portable-файл с этим именем", "bun run portable");

  console.log(`[${TAG}] ${tauri}`);
  console.log(
    `[${TAG}] версия ${stamp.version}, канал dev, коммит ${stamp.commit}` +
      `${stamp.dirty ? " + незакоммиченные изменения" : ""}, время сборки ${stamp.builtAt}`,
  );
  if (stamp.dirty) printChanges(TAG, changes, "-dirty, рабочее дерево agent/");
  if (stamp.serverUrl !== PROD_SERVER_URL) {
    console.warn(
      `[${TAG}] ВНИМАНИЕ: сервер из AFKLINK_SERVER_URL — ${stamp.serverUrl}, не ${PROD_SERVER_URL}`,
    );
  }
  console.log(`[${TAG}] сервер по умолчанию: ${stamp.serverUrl}`);

  if (features.length > 0) {
    console.log(`[${TAG}] с отказом оркестратора по запросу (фича ${DEV_FAULT_FEATURE})`);
  }
  const bytes = await buildDesktopApp(stamp, TAG, features);

  mkdirSync(DIST, { recursive: true });
  try {
    copyFileSync(exe, dest);
  } catch (err) {
    throw new Failure(`${shown(exe)} не скопирован в ${shown(dest)}: ${String(err)}`);
  }
  const hash = sha256Hex(readFileSync(dest)).toUpperCase();
  if (hash !== sha256Hex(bytes).toUpperCase()) {
    throw new Failure(`${shown(dest)} не совпадает с ${shown(exe)}`);
  }
  const sumFile = `${dest}.sha256`;
  writeFileSync(sumFile, `${hash} *${name}\n`, "utf8");
  const size = statSync(dest).size;

  console.log(`\n[${TAG}] готово`);
  console.log(`  файл     ${dest}`);
  console.log(`  размер   ${size} байт (${mib(size)})`);
  console.log(`  SHA-256  ${hash}`);
  console.log(`  хеш      ${sumFile}`);
  console.log(
    `  сборка   ${stamp.version} · ${short}${stamp.dirty ? "-dirty" : ""} · dev, ` +
      `${stamp.builtAt}, сервер ${stamp.serverUrl}`,
  );
  if (stamp.dirty) {
    console.log(
      "  -dirty: собрано с незакоммиченными изменениями; раздаётся только официальная сборка (`bun run release:build`)",
    );
  }
}

if (import.meta.main) await runMain(TAG, main);
