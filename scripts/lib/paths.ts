/**
 * Build-machine paths kept out of the shipped exe.
 *
 * rustc writes a source path into the binary wherever code names its own place: panic locations
 * (`unwrap`, `expect`, indexing), `file!()` in tracing's callsites. Our own crates are given to
 * rustc relative to the workspace (`crates\core\src\agent.rs`), but dependencies come from the
 * registry under CARGO_HOME and are named absolutely — `%USERPROFILE%\.cargo\registry\src\
 * index.crates.io-…\tokio-1.47.0\src\…`, 1437 of them in one release exe — and so is anything included
 * from the target directory (OUT_DIR). aws-lc's C code does the same through `__FILE__`
 * (OPENSSL_PUT_ERROR, assert), with 8.3 short names as aws-lc-sys hands its sources to cl.
 *
 * Cargo's own answer (`trim-paths`) is still unstable on the pinned toolchain (1.98.1: "feature
 * `trim-paths` is required"), and a `.cargo/config.toml` cannot name CARGO_HOME (no variables in
 * `rustflags`), so the build passes these as flags made here:
 *   rustc   `--remap-path-prefix=<from>=<to>`; the last one that matches wins, so the general one
 *           (CARGO_HOME → `cargo`) comes first and the registry's source directories (→ nothing:
 *           `tokio-1.47.0\src\…`, trim-paths' shape) after it; the agent checkout → nothing.
 *   cl      `/d1trimfile:<prefix>\` (aws-lc-sys reads `AWS_LC_SYS_CFLAGS`): cuts the prefix from
 *           `__FILE__`. It must match the path cl was given, so the short form goes too.
 * The registry's sources must exist when the flags are made (the short form is read from the disk):
 * `buildDesktopApp` runs `cargo fetch --locked` first. The game helper is built by
 * app/src-tauri/build.rs with flags of its own; it forwards the remaps.
 */
import { dlopen, FFIType, ptr } from "bun:ffi";
import { existsSync, readdirSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** Where the lines go: the build's console by default, a list in tests. */
export type Say = (line: string) => void;
const consoleSay: Say = (line) => console.log(`[paths] ${line}`);

/** What the build is given to keep build-machine paths out, and what it could not cover. */
export interface PathTrim {
  /** rustc flags, in order. */
  rustflags: string[];
  /** cl flags for aws-lc-sys. */
  awsLcCflags: string[];
  /** Prefixes a flag could not carry (cl's flags are split at spaces), for the log. */
  skipped: string[];
  /** The build-machine prefixes the exe must not contain (checked after the build). */
  prefixes: string[];
}

/** CARGO_HOME as cargo resolves it: the variable, else `~/.cargo`. */
export function cargoHome(env: Record<string, string | undefined> = process.env): string {
  const set = env.CARGO_HOME?.trim();
  return set !== undefined && set !== "" ? set : join(homedir(), ".cargo");
}

/** `path` and, when links lead elsewhere, where they lead: rustc sees whichever cargo passes. */
function withReal(path: string, say: Say): string[] {
  try {
    const real = realpathSync.native(path);
    return real.toLowerCase() === path.toLowerCase() ? [path] : [path, real];
  } catch (err) {
    say(`${path}: где на деле лежит, не узнать (${String(err)}); беру как написано`);
    return [path];
  }
}

/** The Windows 8.3 short form of an existing path (`null`: none, or not on Windows). */
export function shortPath(path: string, say: Say = consoleSay): string | null {
  if (process.platform !== "win32") return null;
  if (!existsSync(path)) {
    say(`${path}: нет на диске, короткого имени 8.3 нет`);
    return null;
  }
  try {
    // kernel32's own answer, as aws-lc-sys gets it: no shell, so no quoting to get wrong.
    const kernel32 = dlopen("kernel32.dll", {
      GetShortPathNameW: { args: [FFIType.ptr, FFIType.ptr, FFIType.u32], returns: FFIType.u32 },
    });
    try {
      const input = Buffer.from(`${path}\0`, "utf16le");
      const chars = 32768;
      const out = Buffer.alloc(chars * 2);
      const n = kernel32.symbols.GetShortPathNameW(ptr(input), ptr(out), chars);
      // 0: failed (8.3 names off on the volume answers with the long form, not 0).
      if (n === 0 || n >= chars) {
        say(`${path}: GetShortPathNameW вернул ${n}, короткого имени нет`);
        return null;
      }
      return out.toString("utf16le", 0, n * 2);
    } finally {
      kernel32.close();
    }
  } catch (err) {
    say(`${path}: короткое имя не прочитано (${String(err)})`);
    return null;
  }
}

/**
 * The flags, from the places alone (no file system): CARGO_HOME (each spelling), the registry's
 * source directories (`<CARGO_HOME>\registry\src\<index>`), the agent checkout (each spelling),
 * and the prefixes cl is to trim (the source directories, long and short).
 */
export function pathTrimFlags(
  homes: string[],
  registrySrcDirs: string[],
  checkouts: string[],
  clPrefixes: string[],
): PathTrim {
  const rustflags = [
    ...homes.map((h) => `--remap-path-prefix=${h}=cargo`),
    ...registrySrcDirs.map((d) => `--remap-path-prefix=${d}=`),
    ...checkouts.map((c) => `--remap-path-prefix=${c}=`),
  ];
  const awsLcCflags: string[] = [];
  const skipped: string[] = [];
  for (const p of clPrefixes) {
    if (/\s/.test(p)) skipped.push(p);
    else awsLcCflags.push(`/d1trimfile:${p.replace(/[\\/]+$/, "")}\\`);
  }
  return {
    rustflags,
    awsLcCflags,
    skipped,
    prefixes: [...new Set([...homes, ...checkouts, ...clPrefixes])],
  };
}

/** Directory names in `dir`; `[]` (said) when it cannot be read. */
function dirNames(dir: string, say: Say): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name);
  } catch (err) {
    say(`${dir}: не прочитан (${(err as NodeJS.ErrnoException).code ?? String(err)})`);
    return [];
  }
}

/**
 * The registry's index directories (`index.crates.io-<hash>`) under `home`: from `registry/src`,
 * else — sources not unpacked yet — from `registry/index` or `registry/cache`, which cargo names
 * the same.
 */
export function registryIndexNames(home: string, say: Say = consoleSay): string[] {
  for (const sub of ["src", "index", "cache"]) {
    const names = dirNames(join(home, "registry", sub), say);
    if (names.length > 0) {
      if (sub !== "src")
        say(`registry\\src в ${home} пуст или нет: имена индексов из registry\\${sub}`);
      return names;
    }
    say(`${join(home, "registry", sub)}: индексов нет`);
  }
  return [];
}

/** `pathTrimFlags` for this machine and `checkout`. */
export function pathTrim(
  checkout: string,
  env: Record<string, string | undefined> = process.env,
  say: Say = consoleSay,
): PathTrim {
  const homes = withReal(cargoHome(env), say);
  const registrySrcDirs: string[] = [];
  const clPrefixes: string[] = [];
  for (const home of homes) {
    const src = join(home, "registry", "src");
    const names = registryIndexNames(home, say);
    if (names.length === 0) {
      say(
        `в ${home} нет ни одного индекса реестра: останется общая замена CARGO_HOME → cargo, ` +
          "а __FILE__ в C-коде aws-lc не укоротится",
      );
    }
    for (const name of names) {
      const dir = join(src, name);
      registrySrcDirs.push(dir);
      clPrefixes.push(dir);
      const short = shortPath(dir, say);
      if (short !== null && short.toLowerCase() !== dir.toLowerCase()) clPrefixes.push(short);
    }
  }
  return pathTrimFlags(homes, [...new Set(registrySrcDirs)], withReal(checkout, say), [
    ...new Set(clPrefixes),
  ]);
}

/**
 * The value for `CARGO_ENCODED_RUSTFLAGS`: what the environment already gives rustc, read as cargo
 * reads it — `CARGO_ENCODED_RUSTFLAGS` when set at all (empty: no flags, and `RUSTFLAGS` is then
 * not looked at), else `RUSTFLAGS` split at whitespace; either overrides any config `rustflags` —
 * then `ours`.
 */
export function encodedRustflags(env: Record<string, string | undefined>, ours: string[]): string {
  const encoded = env.CARGO_ENCODED_RUSTFLAGS;
  const plain = env.RUSTFLAGS?.trim();
  const existing =
    encoded !== undefined
      ? encoded === ""
        ? []
        : encoded.split("\x1f")
      : plain !== undefined && plain !== ""
        ? plain.split(/\s+/)
        : [];
  return [...existing, ...ours].join("\x1f");
}

/** The variable to set for aws-lc-sys's cl flags, and why that one. */
export interface CflagsVar {
  name: string;
  value: string;
  /** A line for the log when the value carries over another variable's flags. */
  note: string | null;
  /** Lines for the log when the trims may still be lost (a variable cc reads before ours). */
  warnings: string[];
}

/**
 * Where `ours` go for aws-lc-sys. Building for the machine it runs on (not cross-compiling — our
 * case), aws-lc-sys 0.45 takes the first of these that is set at all (set but empty counts):
 *   AWS_LC_SYS_HOST_CFLAGS_<t>, AWS_LC_SYS_HOST_CFLAGS, HOST_CFLAGS_<t>, HOST_CFLAGS,
 *   AWS_LC_SYS_CFLAGS_<t>,      AWS_LC_SYS_CFLAGS,      CFLAGS_<t>,      CFLAGS
 * (`<t>` the target with underscores; builder/main.rs `get_crate_cflags`). `null` when there is
 * nothing to add — then nothing is set, so whatever is set keeps working. Ours go after what the
 * winner says: into the winner itself when it is aws-lc-sys's own, else into aws-lc-sys's own of
 * the same tier (`AWS_LC_SYS_HOST_CFLAGS` / `AWS_LC_SYS_CFLAGS`), which outranks it, with its flags
 * carried over and said. cc itself reads `CFLAGS_<target with dashes>` before the others: when that
 * is set, the trims may be lost — said as a warning.
 */
export function awsLcCflags(
  env: Record<string, string | undefined>,
  ours: string[],
  target = "x86_64-pc-windows-msvc",
): CflagsVar | null {
  if (ours.length === 0) return null;
  const t = target.replace(/-/g, "_");
  const warnings: string[] = [];
  const dashed = `CFLAGS_${target}`;
  if (env[dashed] !== undefined) {
    warnings.push(
      `задана ${dashed}: cc читает её раньше остальных, укорачивание путей aws-lc может пропасть`,
    );
  }
  const join = (v: string): string => [v.trim(), ...ours].filter((s) => s !== "").join(" ");
  const tiers = [
    { own: "AWS_LC_SYS_HOST_CFLAGS", plain: "HOST_CFLAGS" },
    { own: "AWS_LC_SYS_CFLAGS", plain: "CFLAGS" },
  ];
  for (const { own, plain } of tiers) {
    for (const name of [`${own}_${t}`, own]) {
      const v = env[name];
      if (v !== undefined) return { name, value: join(v), note: null, warnings };
    }
    for (const name of [`${plain}_${t}`, plain]) {
      const v = env[name];
      if (v !== undefined) {
        return {
          name: own,
          value: join(v),
          note: `${own} перекрывает для aws-lc ${name}; его флаги «${v.trim()}» перенесены`,
          warnings,
        };
      }
    }
  }
  return { name: "AWS_LC_SYS_CFLAGS", value: ours.join(" "), note: null, warnings };
}

/** Occurrences of each prefix, and their total without counting one place twice. */
export interface PrefixHits {
  per: { prefix: string; hits: number }[];
  /** The sum over the widest prefixes only: one inside another (profile ⊃ CARGO_HOME ⊃ index) is
   * already counted by the wider one. */
  total: number;
}

/** How many times each prefix occurs in `bytes`, as UTF-8 and as UTF-16LE (case as written). */
export function prefixHits(bytes: Buffer, prefixes: string[]): PrefixHits {
  const count = (needle: Buffer): number => {
    let n = 0;
    for (let i = bytes.indexOf(needle); i !== -1; i = bytes.indexOf(needle, i + 1)) n++;
    return n;
  };
  const distinct = [...new Set(prefixes)];
  const per = distinct.map((prefix) => ({
    prefix,
    hits: count(Buffer.from(prefix, "utf8")) + count(Buffer.from(prefix, "utf16le")),
  }));
  const lower = distinct.map((p) => p.toLowerCase());
  // Inside another only on a separator: `D:\Games` is not inside `D:\Game`.
  const inside = (p: string): boolean =>
    lower.some(
      (q) => q !== p && p.startsWith(q) && (/[\\/]$/.test(q) || /[\\/]/.test(p.charAt(q.length))),
    );
  const total = per
    .filter(({ prefix }) => !inside(prefix.toLowerCase()))
    .reduce((n, p) => n + p.hits, 0);
  return { per, total };
}

/** The user's profile folder (`%USERPROFILE%`): checked after the build too, as a catch-all. */
export function userProfile(): string {
  return homedir();
}
