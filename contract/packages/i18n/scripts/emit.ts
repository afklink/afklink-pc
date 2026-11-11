/**
 * Emits the Rust half of the dictionary.
 *
 * The desktop client's window is a webview and imports `@afklink/i18n` directly. A few
 * strings, though, are drawn by Windows rather than by us — the tray menu, the tray
 * tooltip, toast notifications — and only Rust can hand them over. Rust cannot import
 * TypeScript, so it needs its own copy.
 *
 * Generating that copy rather than hand-writing it is the whole point. A translation crate
 * like `rust-i18n` would read its own YAML, which means «Приостановить доступ»
 * exists twice in the repo and the two versions drift the moment someone edits the wording
 * in one place — and the copy that drifts is the one nobody has open. This is the same
 * arrangement `@afklink/protocol` uses for the wire types, for the same reason.
 *
 * Only keys ending in `.native` are emitted, so the agent binary carries the strings
 * Windows draws and not the whole Mini App's copy.
 *
 * The generated file lives in the agent's repository (afklink-agent,
 * `crates/i18n/src/generated.rs`), which carries this repository as a submodule at `contract/`.
 * This script cannot know where it is checked out relative to the agent, so the destination is
 * always given on the command line and resolved against the current working directory:
 *
 *   bun contract/packages/i18n/scripts/emit.ts --out crates/i18n/src/generated.rs
 *       Write the dictionary (from afklink-agent's root). The agent's CI re-emits and fails on
 *       a dirty tree, which is what makes the generated file trustworthy.
 *   ... --out <path> --check
 *       Write nothing; exit 1 when <path> is missing or differs from what would be written.
 *   ... --check
 *       Write nothing; only render the dictionary. This is what `bun run emit` does inside this
 *       repository on its own, where there is no agent to write into.
 *   ... --stdout
 *       Print the dictionary to stdout instead of writing it.
 *   ... --cut
 *       First re-cut src/pc/{ru,en}.ts with scripts/pc.ts, where that script exists (the private
 *       contract); where it does not (the published desktop client), skip the cut. `bun run emit`
 *       passes it, so the same command works in both trees. Without --cut, a present cutter only
 *       checks that the cut is current.
 *
 * Exit codes: 0 done, 1 check failed or nothing to emit, 2 bad command line.
 */
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { parseArgs } from "node:util";

import { LOCALES, type Locale } from "../src/locale";
// The desktop client's share (`scripts/pc.ts` cuts it from ../src/{ru,en}.ts): every `.native` key
// is in it, and it is all the published desktop client carries. Only its type is imported here:
// the values are loaded after the cut (`loadShare`), so a fresh cut is what gets rendered and a
// missing src/pc/ gets a hint rather than a bare module-not-found.
import type { TranslationKey } from "../src/pc/ru";

/** Suffix marking a string Rust renders. */
const NATIVE_SUFFIX = ".native";

/** Where afklink-agent keeps the dictionary, for the examples in messages. */
const AGENT_EXAMPLE =
  "bun contract/packages/i18n/scripts/emit.ts --out crates/i18n/src/generated.rs";

const USAGE = `usage: bun packages/i18n/scripts/emit.ts [--cut] (--out <path> [--check] | --check | --stdout)

  --out <path>  write the Rust dictionary to <path>, resolved against the current directory
                (from afklink-agent: ${AGENT_EXAMPLE})
  --check       write nothing; with --out, exit 1 if <path> is missing or out of date
  --stdout      print the Rust dictionary instead of writing it
  --cut         first re-cut src/pc/{ru,en}.ts with scripts/pc.ts, when that script exists
  -h, --help    show this help`;

type Dictionary = Record<TranslationKey, string>;

/** `tray.show.native` → `TRAY_SHOW`. */
function constName(key: string): string {
  return key
    .slice(0, -NATIVE_SUFFIX.length)
    .replace(/[.-]/g, "_")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toUpperCase();
}

/** `tray.show.native` → `TrayShow`, the enum variant. */
function variantName(key: string): string {
  return key
    .slice(0, -NATIVE_SUFFIX.length)
    .split(/[.\-_]/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
}

/**
 * A line break as the dictionary writes it, `\n`: what separates a toast's bold line from the line
 * under it (no full stop between them), so every literal and doc comment stays on one line.
 */
function escapeBreaks(s: string): string {
  return s.replace(/\r/g, "\\r").replace(/\n/g, "\\n");
}

/**
 * A Russian string as a doc line: `«…»`, so the comment reads as a quoted UI string rather than
 * prose. Quotes inside the string become the nested pair `„…“`, which keeps the outer «…» balanced
 * and leaves the literal itself untouched.
 */
function docQuote(s: string): string {
  return `«${escapeBreaks(s.replace(/«/g, "„").replace(/»/g, "“"))}»`;
}

function rustString(s: string): string {
  // Rust and JSON agree on \" and \\, and on \n and \r (escapeBreaks); nothing else in these
  // strings needs escaping, and the literals are UTF-8 source so Cyrillic goes in verbatim.
  return `"${escapeBreaks(s.replace(/\\/g, "\\\\").replace(/"/g, '\\"'))}"`;
}

function render(dictionaries: Record<Locale, Dictionary>, keys: TranslationKey[]): string {
  const ru = dictionaries.ru;
  const lines: string[] = [];

  // The header is part of the output the agent commits, so it changes only with this script. Its
  // paths are relative to this repository, and afklink-agent's `i18n:emit` script is the wrapper
  // around this CLI with its `--out`.
  lines.push("// @generated by packages/i18n/scripts/emit.ts — do not edit.");
  lines.push("//");
  lines.push("// Source: packages/i18n/src/{ru,en}.ts, keys ending in `.native`.");
  lines.push("// Run `bun run i18n:emit` from the repo root after changing a string.");
  lines.push("//");
  lines.push("// These are the strings Windows itself draws for the agent: the tray menu and");
  lines.push("// tooltip, and toast notifications. Everything the agent's own window shows is");
  lines.push("// rendered by the webview, which imports the TypeScript dictionary directly.");
  lines.push("");
  lines.push("use super::Locale;");
  lines.push("");

  // `#[rustfmt::skip]` on every generated item, so this emitter is the file's only author.
  //
  // Without it, `cargo fmt` rewraps any match arm whose Russian string pushes the line past
  // max_width, the next `bun run i18n:emit` writes the unwrapped form back, and CI's
  // "generated files are current" check fails on every run — with a diff that is pure
  // formatting and tells nobody anything. Generated code does not need a formatter's
  // opinion; it needs to be reproducible.
  const SKIP = "#[rustfmt::skip]";

  // An enum rather than string keys: the caller cannot mistype one, and adding a key
  // without handling it is a non-exhaustive match.
  lines.push("/// A string the agent renders natively.");
  lines.push(SKIP);
  lines.push("#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]");
  lines.push("pub enum NativeText {");
  for (const key of keys) {
    lines.push(`    /// ${docQuote(ru[key])}`);
    lines.push(`    ${variantName(key)},`);
  }
  lines.push("}");
  lines.push("");

  lines.push(SKIP);
  lines.push("impl NativeText {");
  lines.push("    /// The contract key this variant came from, for logs and tests.");
  lines.push("    pub const fn key(self) -> &'static str {");
  lines.push("        match self {");
  for (const key of keys) {
    lines.push(`            Self::${variantName(key)} => ${rustString(key)},`);
  }
  lines.push("        }");
  lines.push("    }");
  lines.push("");
  lines.push("    /// This string in `locale`.");
  lines.push("    pub const fn get(self, locale: Locale) -> &'static str {");
  lines.push("        match (self, locale) {");
  for (const key of keys) {
    for (const locale of LOCALES) {
      const value = dictionaries[locale][key];
      lines.push(
        `            (Self::${variantName(key)}, Locale::${
          locale.charAt(0).toUpperCase() + locale.slice(1)
        }) => ${rustString(value)},`,
      );
    }
  }
  lines.push("        }");
  lines.push("    }");
  lines.push("}");
  lines.push("");

  lines.push("/// Every native string, for tests that walk the set.");
  lines.push(SKIP);
  lines.push(`pub const ALL_NATIVE_TEXT: [NativeText; ${keys.length}] = [`);
  for (const key of keys) {
    lines.push(`    NativeText::${variantName(key)},`);
  }
  lines.push("];");
  lines.push("");

  // Named constants for the keys, so a grep for a key finds both languages and the Rust
  // side in one place.
  lines.push("/// Contract keys, for cross-referencing against the TypeScript dictionary.");
  lines.push(SKIP);
  for (const key of keys) {
    lines.push(`pub const KEY_${constName(key)}: &str = ${rustString(key)};`);
  }
  lines.push("");

  return lines.join("\n");
}

/** Exit 2 with the reason and the usage: the command line cannot mean what was intended. */
function usageError(message: string): never {
  console.error(`[i18n] ${message}\n\n${USAGE}`);
  process.exit(2);
}

interface Options {
  out: string | undefined;
  check: boolean;
  stdout: boolean;
  cut: boolean;
}

const ARGS = {
  out: { type: "string" },
  check: { type: "boolean" },
  stdout: { type: "boolean" },
  cut: { type: "boolean" },
  help: { type: "boolean", short: "h" },
} as const;

/** The raw flags; an unknown flag, a stray argument or `--out` without a value is a usage error. */
function readArgs(argv: string[]) {
  try {
    return parseArgs({ args: argv, options: ARGS, strict: true, allowPositionals: false }).values;
  } catch (err) {
    usageError(err instanceof Error ? err.message : String(err));
  }
}

function parseOptions(argv: string[]): Options {
  const values = readArgs(argv);

  if (values.help) {
    console.log(USAGE);
    process.exit(0);
  }
  const out = values.out;
  const check = values.check ?? false;
  const stdout = values.stdout ?? false;

  if (out !== undefined && out.trim() === "") usageError("--out needs a file path");
  if (stdout && (out !== undefined || check)) {
    usageError("--stdout prints the dictionary; it does not combine with --out or --check");
  }
  if (out === undefined && !check && !stdout) {
    usageError(
      "nothing to do: there is no default destination outside the agent's repository. " +
        `Pass --out <path> to write the dictionary (from afklink-agent: ${AGENT_EXAMPLE}), ` +
        "--check to only render it, or --stdout to print it.",
    );
  }
  return { out, check, stdout, cut: values.cut ?? false };
}

/** `path` as the person running the script would type it, for messages. */
function shown(path: string): string {
  return relative(process.cwd(), path).replace(/\\/g, "/") || path;
}

/** The file's current contents, or null when there is none yet. */
async function readExisting(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

const options = parseOptions(process.argv.slice(2));

// Where the product's whole dictionaries are (the private contract), the PC's share must be the
// current cut of them: a string edited in ../src/ru.ts and not re-cut would otherwise reach the
// agent stale. With --cut the cutter rewrites it first; without, it only checks. The published
// desktop client has only the share, and no cutter to run.
const cutter = new URL("./pc.ts", import.meta.url);
if (existsSync(cutter)) {
  // Typed here rather than as `typeof import("./pc")`: where the cutter is absent, so is its type.
  const { cutPc } = (await import(cutter.href)) as {
    cutPc: (check: boolean) => Promise<string[]>;
  };
  const stale = await cutPc(!options.cut);
  if (options.cut) {
    console.log(
      stale.length > 0
        ? `[i18n] cut: ${stale.join(", ")} written`
        : "[i18n] cut: src/pc/{ru,en}.ts are current",
    );
  } else if (stale.length > 0) {
    console.error(
      `[i18n] ${stale.join(", ")} out of date with src/{ru,en}.ts. ` +
        "Run: bun run emit (in the contract) or bun packages/i18n/scripts/pc.ts",
    );
    process.exit(1);
  }
} else if (options.cut) {
  console.log("[i18n] cut: skipped, no scripts/pc.ts here (src/pc/ is the source)");
}

/** The PC's share, loaded only now that it is cut; exit 1 with a hint when src/pc/ is missing. */
async function loadShare(): Promise<Record<Locale, Dictionary>> {
  const files = {
    ru: new URL("../src/pc/ru.ts", import.meta.url),
    en: new URL("../src/pc/en.ts", import.meta.url),
  };
  const missing = Object.values(files).filter((url) => !existsSync(url));
  if (missing.length > 0) {
    const names = missing.map((url) => shown(url.pathname)).join(", ");
    console.error(
      `[i18n] ${names} missing: the desktop client's dictionaries (src/pc/{ru,en}.ts) are what ` +
        "this script renders. " +
        (existsSync(cutter)
          ? "Cut them first: bun run emit (in the contract) or bun packages/i18n/scripts/pc.ts"
          : "This checkout has neither them nor scripts/pc.ts to cut them; restore src/pc/."),
    );
    process.exit(1);
  }
  const { ru } = (await import(files.ru.href)) as { ru: Dictionary };
  const { en } = (await import(files.en.href)) as { en: Dictionary };
  return { ru, en };
}

const dictionaries = await loadShare();

const nativeKeys = (Object.keys(dictionaries.ru) as TranslationKey[]).filter((k) =>
  k.endsWith(NATIVE_SUFFIX),
);

if (nativeKeys.length === 0) {
  console.error("[i18n] no `.native` keys found — refusing to emit an empty dictionary");
  process.exit(1);
}

// Sorted, so the generated file does not churn when a key is inserted mid-object.
nativeKeys.sort();

const rendered = render(dictionaries, nativeKeys);
const summary = `${nativeKeys.length} native string(s) × ${LOCALES.length} locales`;

if (options.stdout) {
  process.stdout.write(rendered);
  // stderr, so a redirect of stdout gets the Rust source and nothing else.
  console.error(`[i18n] ${summary} → stdout`);
} else if (options.out === undefined) {
  console.log(
    `[i18n] ${summary} rendered (${Buffer.byteLength(rendered, "utf8")} bytes); nothing written — ` +
      "the dictionary is written by the agent with --out",
  );
} else {
  const outFile = resolve(process.cwd(), options.out);
  const existing = await readExisting(outFile);
  const script = shown(import.meta.path);

  if (options.check) {
    if (existing === rendered) {
      console.log(`[i18n] ${shown(outFile)} is current (${summary})`);
    } else {
      const state = existing === null ? "does not exist" : "is out of date";
      console.error(
        `[i18n] ${shown(outFile)} ${state} (${summary}). ` +
          `Run: bun ${script} --out ${options.out}`,
      );
      process.exit(1);
    }
  } else if (existing === rendered) {
    console.log(`[i18n] ${summary} → ${shown(outFile)} (already current, not rewritten)`);
  } else {
    await mkdir(dirname(outFile), { recursive: true });
    await writeFile(outFile, rendered, "utf8");
    const what = existing === null ? "created" : "updated";
    console.log(`[i18n] ${summary} → ${shown(outFile)} (${what})`);
  }
}
