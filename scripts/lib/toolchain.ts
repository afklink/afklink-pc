/**
 * Tools a release build needs besides cargo, checked before the build starts:
 *
 * - NASM. Without it openh264-sys2 compiles OpenH264 with no assembly at all and says so only in
 *   a build-script line cargo does not show (`try_compile_nasm` in its build.rs: `OPENH264_NO_ASM`
 *   set, or `nasm` not found or failing — «not using any assembly» — and the build goes on in plain
 *   C). The exe works, but the encoder is markedly slower, and nobody would notice until a session
 *   ran short of CPU. A NASM that is there but crashes is not caught here: NASM 3.02 crashes on 11
 *   of OpenH264's 23 files only with `-g`, and a tiny probe file assembles fine with it, so
 *   the shipping profile never asks for `-g` (Cargo.toml, `[profile.dist.package.openh264-sys2]`)
 *   and the build itself is checked afterwards (lib/openh264.ts: the build-script output and
 *   OpenH264's assembly functions in the exe's PDB).
 * - A Tauri CLI whose `signer sign` takes `--app-version` (2.12+): it writes the version into the
 *   signature's trusted comment, which the signature covers, so the updater can tell a manifest
 *   that pairs a new version number with an older release's exe.
 */
import { AGENT, buildEnv, Failure, type Ran, run } from "./common";
import { compareVersions, formatVersion, type Version } from "./version";

/** OpenH264's own floor for its assembly (upstream/README.md: «workable version 2.10.06 or above»). */
export const NASM_MIN: Version = { major: 2, minor: 10, patch: 6 };

/** The first Tauri CLI whose `signer sign` takes `--app-version` (tauri-cli 2.12.0). */
export const SIGNER_MIN: Version = { major: 2, minor: 12, patch: 0 };

/**
 * `NASM version 3.02 compiled on <date>` → 3.2.0. Read as nasm-rs reads it (the number after
 * «NASM version», an `rc` tail ignored, missing parts zero); any other text → null.
 */
export function parseNasmVersion(line: string): Version | null {
  const m = /^NASM version (\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(line.trim());
  if (m === null) return null;
  const [major, minor, patch] = [m[1], m[2], m[3]].map((part) => Number(part ?? 0)) as [
    number,
    number,
    number,
  ];
  if (![major, minor, patch].every(Number.isSafeInteger)) return null;
  return { major, minor, patch };
}

/** The NASM a build will use. */
export interface NasmFound {
  /** What was run: `$NASM` as given (nasm-rs runs exactly that), else `nasm`. */
  program: string;
  /** Where that is: `$NASM` itself, or the first `nasm` on PATH (null if the lookup found none). */
  path: string | null;
  /** The first line of its `-v`. */
  line: string;
  version: Version;
}

const WHY =
  "без него OpenH264 соберётся вообще без ассемблера — молча, — и энкодер станет заметно медленнее";
const HOW =
  `Поставьте NASM ${formatVersion(NASM_MIN)} или новее (https://www.nasm.us/; на этом ПК — ` +
  "`scoop install nasm`) так, чтобы `nasm -v` отвечал из PATH, или укажите путь к nasm.exe в " +
  "переменной NASM";

/**
 * The NASM openh264-sys2's build script will find (nasm-rs: `$NASM` if set, else `nasm` on PATH),
 * answering `-v` with a version OpenH264 accepts; otherwise a Failure saying what to do. Refuses
 * `OPENH264_NO_ASM` too: set to anything, it turns the assembly off the same silent way.
 */
export function assertNasm(
  env: Record<string, string | undefined> = process.env,
  // The signing secrets left out explicitly: `nasm.exe` in CI is a downloaded program, run in the
  // step that holds the updater's key.
  exec: (cmd: string[]) => Ran | null = (cmd) => run(cmd, AGENT, buildEnv({})),
  which: (name: string) => string | null = (name) => Bun.which(name),
): NasmFound {
  if (env.OPENH264_NO_ASM !== undefined) {
    throw new Failure(
      `задана переменная OPENH264_NO_ASM («${env.OPENH264_NO_ASM}»): с ней openh264-sys2 собирает ` +
        "OpenH264 вообще без ассемблера — молча, — и энкодер становится заметно медленнее. Уберите её",
    );
  }
  const program = env.NASM ?? "nasm";
  if (program.trim() === "") throw new Failure(`переменная NASM задана пустой. ${HOW}`);
  const path = env.NASM ?? which("nasm");
  const ran = exec([program, "-v"]);
  if (ran === null) {
    const where = env.NASM === undefined ? "в PATH его нет" : "путь из переменной NASM";
    throw new Failure(
      `NASM не найден: \`${program} -v\` не запускается (${where}); ${WHY}. ${HOW}`,
    );
  }
  const said = `${ran.stdout}\n${ran.stderr}`.trim();
  if (ran.code !== 0) {
    const output = said === "" ? "" : `: ${said}`;
    throw new Failure(`\`${program} -v\` завершился с кодом ${ran.code}${output}; ${WHY}. ${HOW}`);
  }
  const line = said.split(/\r?\n/)[0]?.trim() ?? "";
  const version = parseNasmVersion(line);
  if (version === null) {
    throw new Failure(
      `\`${program} -v\` ответил «${line}» — это не NASM («NASM version …»); ${WHY}. ${HOW}`,
    );
  }
  if (compareVersions(version, NASM_MIN) < 0) {
    throw new Failure(
      `NASM ${formatVersion(version)} (${line}) старше ${formatVersion(NASM_MIN)}, нужного ` +
        `ассемблеру OpenH264; ${WHY}. ${HOW}`,
    );
  }
  return { program, path, line, version };
}

/** `tauri-cli 2.12.1` (what `cargo tauri --version` says) → 2.12.1; anything else → null. */
export function parseTauriCliVersion(line: string): Version | null {
  const m = /^tauri-cli (\d+)\.(\d+)\.(\d+)/.exec(line.trim());
  if (m === null) return null;
  const [major, minor, patch] = [m[1], m[2], m[3]].map(Number) as [number, number, number];
  return { major, minor, patch };
}

/**
 * That the Tauri CLI (`cargo tauri --version`'s line) can bind the version into the signature
 * (`signer sign --app-version`); its version, or a Failure naming the one to install.
 */
export function assertSignerBindsVersion(line: string): Version {
  const version = parseTauriCliVersion(line);
  if (version === null) {
    throw new Failure(`\`cargo tauri --version\` ответил «${line.trim()}»: версия не прочитана`);
  }
  if (compareVersions(version, SIGNER_MIN) < 0) {
    throw new Failure(
      `Tauri CLI ${formatVersion(version)} не умеет записывать версию в подпись ` +
        `(\`signer sign --app-version\`, с ${formatVersion(SIGNER_MIN)}), а релиз подписывается только ` +
        "так: обновление сверяет подписанную версию с той, что объявляет latest.json. Поставьте ту, " +
        "что собирает релиз в CI (TAURI_CLI_VERSION в .github/workflows/release.yml): " +
        "`cargo install tauri-cli --version <она> --locked`",
    );
  }
  return version;
}
