/**
 * `bun scripts/notices.ts --out <file> [--version <X.Y.Z>] [--cargo-json <file>]` —
 * THIRD-PARTY-NOTICES.txt of the Windows exe: every third-party license the exe ships under, with
 * its text. The release workflow runs it on Linux (no secrets) and publishes the file with each
 * release.
 *
 *   1. Rust crates: `cargo about generate --format json` for afklink-app (which embeds the game
 *      helper) on x86_64-pc-windows-msvc, with `scripts/notices/about.toml`. Needs cargo-about on
 *      PATH (`cargo about`), and network unless the crates are fetched. The workspace's own crates
 *      (AGPL-3.0-only, the program itself) are left out. `--cargo-json <file>` reads a saved output
 *      of that command instead.
 *   2. The window's JavaScript: the production dependencies of app/ui (`dependencies`, then theirs,
 *      as Node resolves them from node_modules after `bun install`), plus the build tools whose
 *      own code lands in the bundle (`BUNDLED_TOOLS`); license texts from each package's
 *      LICENSE/LICENCE/COPYING files. A package without one stops the script.
 *   3. Bundled components named on their own: str0m (vendored in vendor/str0m with a patch),
 *      OpenH264 (built from the source openh264-sys2 carries), FakerInput (the driver installer in
 *      app/src-tauri/resources/fakerinput).
 *
 * The output is plain text with LF line ends, the same for the same inputs.
 */
import {
  existsSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { AGENT, Failure, run, runMain, shown, TAURI_DIR, workspaceVersion } from "./lib/common";

const TAG = "notices";

/** The one target the exe is built for. */
export const TARGET = "x86_64-pc-windows-msvc";
export const ABOUT_CONFIG = join(AGENT, "scripts", "notices", "about.toml");
export const UI_DIR = join(AGENT, "app", "ui");
export const FAKERINPUT_DIR = join(TAURI_DIR, "resources", "fakerinput");
export const STR0M_DIR = join(AGENT, "vendor", "str0m");

/**
 * Build tools whose own code is compiled into the window's bundle, though they are not runtime
 * dependencies. `cut`: where their license file stops covering that code (vite's goes on with the
 * licenses of what vite itself bundles for the dev server, none of which reaches the window).
 */
export const BUNDLED_TOOLS: readonly { name: string; why: string; cut?: RegExp }[] = [
  { name: "tailwindcss", why: "its base styles are compiled into the window's stylesheet" },
  {
    name: "vite",
    why: "its module preload polyfill is part of the window's script",
    cut: /^#+\s*Licenses of bundled dependencies/m,
  },
];

/** One license text and what is under it. */
export interface Notice {
  /** A heading: the component's name, or the license's for a group of crates or packages. */
  title: string;
  /** The license expression as declared. */
  license: string;
  /** Who it applies to: `name version` lines. */
  usedBy: string[];
  /** A short remark under the heading (how it is used), if any. */
  note?: string;
  text: string;
}

// ── Rust crates (cargo-about) ────────────────────────────────────────────────────────────────

interface AboutPackage {
  name: string;
  version: string;
  manifest_path?: string;
}

interface AboutJson {
  licenses?: {
    name?: string;
    id?: string;
    text?: string;
    used_by?: { crate?: AboutPackage; krate?: AboutPackage }[];
  }[];
  crates?: { package?: AboutPackage; license?: unknown }[];
}

/** Parse cargo-about's JSON output; throws when it is not that. */
export function parseAbout(text: string): AboutJson {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (err) {
    throw new Error(`cargo-about output is not JSON: ${(err as Error).message}`);
  }
  const about = json as AboutJson;
  if (!Array.isArray(about?.licenses) || !Array.isArray(about?.crates)) {
    throw new Error("cargo-about output has no `licenses` and `crates`");
  }
  return about;
}

const byName = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * One notice per distinct license text, naming the crates under it; crates in `ours` (the
 * workspace's own) are left out, and a text left with no crate is dropped.
 */
export function crateNotices(about: AboutJson, ours: ReadonlySet<string>): Notice[] {
  const merged = new Map<string, Notice>();
  for (const lic of about.licenses ?? []) {
    const text = (lic.text ?? "").replace(/\r\n/g, "\n").trim();
    const users = (lic.used_by ?? [])
      .map((u) => u.crate ?? u.krate)
      .filter((p): p is AboutPackage => p !== undefined && !ours.has(p.name))
      .map((p) => `${p.name} ${p.version}`);
    if (users.length === 0) continue;
    if (text === "")
      throw new Error(`cargo-about gave no text for ${lic.id} (${users.join(", ")})`);
    const id = lic.id ?? lic.name ?? "?";
    const key = `${id}\n${text}`;
    const have = merged.get(key);
    if (have === undefined) {
      merged.set(key, { title: lic.name ?? id, license: id, usedBy: users, text });
    } else {
      have.usedBy.push(...users);
    }
  }
  const notices = [...merged.values()];
  for (const n of notices) n.usedBy = [...new Set(n.usedBy)].sort(byName);
  return notices.sort(
    (a, b) => byName(a.license, b.license) || byName(a.usedBy[0] ?? "", b.usedBy[0] ?? ""),
  );
}

/** A crate of cargo-about's list by name (and, optionally, where its manifest is). */
export function findCrate(about: AboutJson, name: string, under?: string): AboutPackage | null {
  for (const c of about.crates ?? []) {
    const p = c.package;
    if (p?.name !== name) continue;
    if (under !== undefined) {
      if (p.manifest_path === undefined || !isUnder(under, p.manifest_path)) continue;
    }
    return p;
  }
  return null;
}

/** `path` with links followed when it exists (cargo reports real paths), else as written. */
function real(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

function isUnder(dir: string, path: string): boolean {
  const rel = relative(real(dir), real(path));
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

// ── The window's packages (node_modules) ────────────────────────────────────────────────────

/** A package found in node_modules. */
export interface NpmPackage {
  name: string;
  version: string;
  license: string;
  /** Its folder, links followed. */
  dir: string;
}

interface PackageJson {
  name?: string;
  version?: string;
  license?: unknown;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

function readPackageJson(dir: string): PackageJson {
  const file = join(dir, "package.json");
  try {
    return JSON.parse(readFileSync(file, "utf8")) as PackageJson;
  } catch (err) {
    throw new Error(`${file}: ${(err as Error).message}`);
  }
}

/** Where Node would find `name` from `fromDir`: the nearest `node_modules/<name>` up the tree. */
export function resolvePackage(fromDir: string, name: string): string | null {
  let dir = resolve(fromDir);
  for (;;) {
    const candidate = join(dir, "node_modules", ...name.split("/"));
    if (existsSync(join(candidate, "package.json"))) return realpathSync(candidate);
    const up = dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

/** A folder of a workspace package (ours): not inside any node_modules once links are followed. */
function isWorkspaceDir(dir: string): boolean {
  return !dir.split(sep).includes("node_modules");
}

function licenseOf(pkg: PackageJson): string {
  const l = pkg.license;
  if (typeof l === "string") return l;
  if (l !== null && typeof l === "object" && typeof (l as { type?: unknown }).type === "string") {
    return (l as { type: string }).type;
  }
  return "UNKNOWN";
}

/**
 * The production dependency closure of the package in `rootDir`: its `dependencies` and
 * `optionalDependencies` (an optional one that is not installed is skipped), then theirs. Workspace
 * packages (ours) are walked through but not listed. A required dependency that cannot be found
 * stops it: the notices would be incomplete.
 */
export function npmClosure(rootDir: string): NpmPackage[] {
  const found = new Map<string, NpmPackage>();
  const visited = new Set<string>();
  const queue: string[] = [realpathSync(rootDir)];
  while (queue.length > 0) {
    const dir = queue.shift() as string;
    if (visited.has(dir)) continue;
    visited.add(dir);
    const pkg = readPackageJson(dir);
    if (!isWorkspaceDir(dir)) {
      const name = pkg.name ?? basename(dir);
      found.set(dir, { name, version: pkg.version ?? "?", license: licenseOf(pkg), dir });
    }
    const wanted: [string, boolean][] = [
      ...Object.keys(pkg.dependencies ?? {}).map((n): [string, boolean] => [n, true]),
      ...Object.keys(pkg.optionalDependencies ?? {}).map((n): [string, boolean] => [n, false]),
    ];
    for (const [name, required] of wanted) {
      const at = resolvePackage(dir, name);
      if (at === null) {
        if (required)
          throw new Error(`${name}, a dependency of ${pkg.name ?? dir}, is not installed`);
        continue;
      }
      queue.push(at);
    }
  }
  return [...found.values()].sort((a, b) => byName(a.name, b.name) || byName(a.version, b.version));
}

/** A package's license files (LICENSE, LICENCE, COPYING, with any suffix), in name order. */
export function licenseFiles(dir: string): string[] {
  return readdirSync(dir)
    .filter((f) => /^(licen[cs]e|copying)([.\-_].*)?$/i.test(f))
    .filter((f) => statSync(join(dir, f)).isFile())
    .sort(byName)
    .map((f) => join(dir, f));
}

/** The license text of a package: its license files, joined; `cut` ends it early. */
export function packageLicenseText(pkg: NpmPackage, cut?: RegExp): string {
  const files = licenseFiles(pkg.dir);
  if (files.length === 0) {
    throw new Error(
      `${pkg.name} ${pkg.version} (${pkg.license}) has no LICENSE file in ${pkg.dir}: ` +
        "its text cannot be included",
    );
  }
  let text = files.map((f) => readFileSync(f, "utf8").replace(/\r\n/g, "\n").trim()).join("\n\n");
  if (cut !== undefined) {
    const at = cut.exec(text);
    if (at !== null) text = text.slice(0, at.index).trim();
  }
  return text;
}

/** Packages grouped by identical license text, one notice each. */
export function packageNotices(
  items: { pkg: NpmPackage; text: string; note?: string }[],
): Notice[] {
  const merged = new Map<string, Notice>();
  for (const { pkg, text, note } of items) {
    const key = `${pkg.license}\n${note ?? ""}\n${text}`;
    const who = `${pkg.name} ${pkg.version}`;
    const have = merged.get(key);
    if (have === undefined) {
      merged.set(key, {
        title: pkg.license,
        license: pkg.license,
        usedBy: [who],
        ...(note === undefined ? {} : { note }),
        text,
      });
    } else if (!have.usedBy.includes(who)) {
      have.usedBy.push(who);
    }
  }
  const notices = [...merged.values()];
  for (const n of notices) n.usedBy.sort(byName);
  return notices.sort((a, b) => byName(a.usedBy[0] ?? "", b.usedBy[0] ?? ""));
}

// ── Rendering ────────────────────────────────────────────────────────────────────────────────

const RULE = "=".repeat(78);
const THIN = "-".repeat(78);

function renderNotice(n: Notice): string {
  const lines = [THIN, ...(n.title === n.license ? [] : [n.title]), `License: ${n.license}`];
  if (n.note !== undefined) lines.push(n.note);
  if (n.usedBy.length > 0) {
    lines.push(n.usedBy.length === 1 ? `Used by: ${n.usedBy[0]}` : "Used by:");
    if (n.usedBy.length > 1) for (const u of n.usedBy) lines.push(`  ${u}`);
  }
  lines.push("", n.text, "");
  return lines.join("\n");
}

/** The whole file. */
export function renderNotices(
  version: string,
  bundled: Notice[],
  crates: Notice[],
  packages: Notice[],
): string {
  const count = (ns: Notice[]) => new Set(ns.flatMap((n) => n.usedBy)).size;
  const sections: [string, Notice[]][] = [
    ["Bundled components", bundled],
    [`Rust crates (${count(crates)}), as built for ${TARGET}`, crates],
    [`JavaScript packages of the window (${count(packages)})`, packages],
  ];
  const head = [
    `THIRD-PARTY NOTICES: AFKLink for Windows ${version}`,
    "",
    "AFKLink is free software under the GNU Affero General Public License, version 3 only",
    "(LICENSE in the source repository). The program includes the third-party software listed",
    "below, each under its own license, whose text follows its entry.",
    "",
    ...sections.map(([title], i) => `${i + 1}. ${title}`),
    "",
  ];
  const body = sections.map(([title, ns], i) =>
    [RULE, `${i + 1}. ${title}`, RULE, "", ...ns.map(renderNotice)].join("\n"),
  );
  return `${[...head, ...body]
    .join("\n")
    .replace(/[ \t]+$/gm, "")
    .trimEnd()}\n`;
}

// ── Running it ───────────────────────────────────────────────────────────────────────────────

function parseArgs(argv: string[]): {
  out: string;
  version: string | null;
  cargoJson: string | null;
} {
  const values: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i] ?? "";
    const value = argv[i + 1];
    if (!["--out", "--version", "--cargo-json"].includes(flag)) {
      throw new Failure(
        `unknown argument «${flag}». Usage: notices.ts --out <file> [--version X.Y.Z] [--cargo-json <file>]`,
      );
    }
    if (value === undefined || value === "") throw new Failure(`${flag} needs a value`);
    values[flag] = value;
  }
  const out = values["--out"];
  if (out === undefined) throw new Failure("--out <file> is required");
  return {
    out: resolve(out),
    version: values["--version"] ?? null,
    cargoJson: values["--cargo-json"] ?? null,
  };
}

function cargoAbout(): string {
  const cmd = [
    "cargo",
    "about",
    "generate",
    "--format",
    "json",
    "--locked",
    "--fail",
    "--config",
    ABOUT_CONFIG,
    "--manifest-path",
    join(TAURI_DIR, "Cargo.toml"),
  ];
  console.log(`[${TAG}] ${cmd.join(" ")}`);
  const r = run(cmd, AGENT);
  if (r === null) throw new Failure("cargo not found in PATH");
  if (r.code !== 0) {
    throw new Failure(
      `cargo about exited with ${r.code}: ${(r.stderr || r.stdout).trim().slice(-2000)}` +
        "\n(cargo-about missing? It is installed by the release workflow; locally pass --cargo-json)",
    );
  }
  return r.stdout;
}

/** The names of the workspace's own crates (`cargo metadata --no-deps`). */
function workspaceCrates(): Set<string> {
  const r = run(["cargo", "metadata", "--no-deps", "--format-version", "1"], AGENT);
  if (r === null || r.code !== 0) {
    throw new Failure(`cargo metadata failed: ${r === null ? "cargo not found" : r.stderr.trim()}`);
  }
  const meta = JSON.parse(r.stdout) as { packages: { name: string }[] };
  return new Set(meta.packages.map((p) => p.name));
}

function readText(file: string, what: string): string {
  try {
    return readFileSync(file, "utf8").replace(/\r\n/g, "\n").trim();
  } catch (err) {
    throw new Failure(`${what}: ${shown(file)} not read: ${String(err)}`);
  }
}

function bundledNotices(about: AboutJson): Notice[] {
  const str0m = findCrate(about, "str0m", STR0M_DIR);
  if (str0m === null) throw new Failure("str0m from vendor/str0m is not in the crate graph");
  const openh264 = findCrate(about, "openh264-sys2");
  if (openh264?.manifest_path === undefined) {
    throw new Failure("openh264-sys2 is not in the crate graph (or cargo-about gave no path)");
  }
  const upstream = join(dirname(openh264.manifest_path), "upstream");
  // upstream/VERSION: the repository and the commit the crate's copy was taken from.
  const origin = existsSync(join(upstream, "VERSION"))
    ? readText(join(upstream, "VERSION"), "OpenH264")
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
    : [];
  const msi = readdirSync(FAKERINPUT_DIR).find((f) => /\.msi$/i.test(f));
  if (msi === undefined) throw new Failure(`no .msi in ${shown(FAKERINPUT_DIR)}`);
  const fakerVersion = /_(\d+\.\d+\.\d+)_/.exec(msi)?.[1] ?? "?";
  const strLicense = readText(join(STR0M_DIR, "LICENSE-MIT.txt"), "str0m");
  return [
    {
      title: `str0m ${str0m.version}`,
      license: "MIT OR Apache-2.0 (used under MIT)",
      usedBy: [],
      note: "The WebRTC stack, vendored in vendor/str0m with a patch to its delay-based estimator.",
      text: strLicense,
    },
    {
      title: "OpenH264",
      license: "BSD-2-Clause",
      usedBy: [],
      note:
        `The H.264 encoder, compiled from the source carried by openh264-sys2 ${openh264.version}` +
        (origin.length === 0 ? "" : ` (${origin.join(" at ")})`) +
        ", not Cisco's prebuilt binary.",
      text: readText(join(upstream, "LICENSE"), "OpenH264"),
    },
    {
      title: `FakerInput ${fakerVersion}`,
      license: "MIT",
      usedBy: [],
      note: `The input driver's installer (${msi}), embedded in the exe and installed only on request.`,
      text: readText(join(FAKERINPUT_DIR, "LICENSE"), "FakerInput"),
    },
  ];
}

function windowNotices(): Notice[] {
  const items: { pkg: NpmPackage; text: string; note?: string }[] = [];
  let closure: NpmPackage[];
  try {
    closure = npmClosure(UI_DIR);
  } catch (err) {
    throw new Failure(`${(err as Error).message} (run \`bun install --frozen-lockfile\` first)`);
  }
  for (const pkg of closure) {
    try {
      items.push({ pkg, text: packageLicenseText(pkg) });
    } catch (err) {
      throw new Failure((err as Error).message);
    }
  }
  for (const tool of BUNDLED_TOOLS) {
    const dir = resolvePackage(UI_DIR, tool.name);
    if (dir === null) throw new Failure(`${tool.name} is not installed in app/ui`);
    const p = readPackageJson(dir);
    const pkg: NpmPackage = {
      name: tool.name,
      version: p.version ?? "?",
      license: licenseOf(p),
      dir,
    };
    items.push({
      pkg,
      text: packageLicenseText(pkg, tool.cut),
      note: `A build tool: ${tool.why}.`,
    });
  }
  console.log(`[${TAG}] window: ${closure.length} packages, ${BUNDLED_TOOLS.length} build tools`);
  return packageNotices(items);
}

async function main(): Promise<void> {
  const o = parseArgs(process.argv.slice(2));
  const version = o.version ?? workspaceVersion();
  const aboutText = o.cargoJson === null ? cargoAbout() : readFileSync(o.cargoJson, "utf8");
  let about: AboutJson;
  try {
    about = parseAbout(aboutText);
  } catch (err) {
    throw new Failure((err as Error).message);
  }
  const ours = workspaceCrates();
  const crates = crateNotices(about, ours);
  console.log(
    `[${TAG}] Rust: ${crates.length} license texts over ` +
      `${new Set(crates.flatMap((n) => n.usedBy)).size} crates (${ours.size} of ours left out)`,
  );
  const text = renderNotices(version, bundledNotices(about), crates, windowNotices());
  writeFileSync(o.out, text, "utf8");
  console.log(`[${TAG}] ${shown(o.out)}: ${text.length} chars`);
}

if (import.meta.main) await runMain(TAG, main);
