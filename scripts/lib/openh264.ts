/**
 * That the shipping exe has OpenH264's assembly in it, checked after the build (`buildDesktopApp`).
 *
 * openh264-sys2 0.9.8 builds OpenH264's x86 assembly with NASM through nasm-rs and, when that fails
 * for any reason, says «Failed to compile NASM files, not using any assembly.» in its build-script
 * output — which cargo does not show — and goes on in plain C (`try_compile_nasm` in its build.rs).
 * The exe works, but encodes 3–5 times slower. One cause: line tables in a profile make nasm-rs
 * pass `-g`, and NASM 3.02 crashes on 11 of the 23 files with it (Cargo.toml, `[profile.dist.package.openh264-sys2]`). A 1080p game frame took
 * 15–25 ms to encode instead of 4–6, and the quality ladder stepped down for CPU.
 *
 * `toolchain.ts` refuses a missing NASM and `OPENH264_NO_ASM` before the build; this is the check
 * that holds whatever the cause: two pieces of evidence from the build itself.
 *
 * - The build-script output of openh264-sys2 under `<target>/<profile>/build/openh264-sys2-*`, but
 *   only of runs written by this build (`output` written between its start and the PDB, i.e. the
 *   link) — those must not say it
 *   went without assembly. Cargo reruns the script only when its inputs change, and other builds of
 *   the same profile with other features leave runs of their own under other hashes, so when this
 *   build reused a cached run, which of the older ones it linked cannot be told from the times (a
 *   `pipeline_bench` run can be newer than the portable's PDB): then the output is not
 *   judged, and only explains a PDB failure. openh264-sys2 prints nothing on success, so this is
 *   only ever the absence of the failure line.
 * - The positive marker, which decides: the PDB the linker wrote beside the exe names OpenH264's assembly
 *   functions (public symbols, there with or without debug info). They exist only in the .asm
 *   files — the C code calls them only when the assembly is built — so a plain-C OpenH264 leaves
 *   none of them (checked: 0 of these in a no-assembly `dist` PDB, all in a `release` PDB with
 *   assembly).
 *
 * No imports from common.ts (it calls this): verdicts come back as text, the caller throws.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/** The crate whose build script builds OpenH264, as its build directories are named. */
export const OPENH264_SYS = "openh264-sys2";

/** What openh264-sys2's build script prints when it builds without assembly (all its ways). */
export const NO_ASM_MARKERS = [
  // NASM missing, failing or crashing; or no NASM configuration for the target.
  "not using any assembly",
  // OPENH264_NO_ASM set.
  "NASM compilation disabled",
] as const;

/**
 * OpenH264 assembly functions, one or more from each part the encoder links (upstream/codec/…):
 * common/x86/cpuid.asm, common/x86/satd_sad.asm, common/x86/dct.asm, common/x86/deblock.asm,
 * processing/src/x86/vaa.asm, encoder/core/x86/score.asm. All but cpuid.asm and vaa.asm are among
 * the files NASM 3.02 crashed on with `-g`.
 */
export const ASM_SYMBOLS = [
  "WelsCPUId",
  "WelsSampleSad16x16_sse2",
  "WelsDctFourT4_sse2",
  "DeblockLumaLt4V_ssse3",
  "SampleVariance16x16_sse2",
  "WelsScan4x4DcAc_ssse3",
] as const;

/** The first line of a build-script output that says OpenH264 went without assembly; or null. */
export function noAsmLine(output: string): string | null {
  for (const line of output.split(/\r?\n/)) {
    if (NO_ASM_MARKERS.some((m) => line.includes(m))) return line.trim();
  }
  return null;
}

/**
 * Which of `ASM_SYMBOLS` are not in `pdb`. A PDB keeps a public symbol's name as plain text ended by
 * a NUL, so the name with its NUL is looked for: `WelsCPUId` does not count as found inside
 * `WelsCPUIdVerify`.
 */
export function missingAsmSymbols(pdb: Uint8Array): string[] {
  const bytes = Buffer.from(pdb.buffer, pdb.byteOffset, pdb.byteLength);
  return ASM_SYMBOLS.filter((name) => !bytes.includes(Buffer.from(`${name}\0`, "latin1")));
}

/** One run of openh264-sys2's build script: its directory, its output and when it was written. */
export interface BuildScriptRun {
  dir: string;
  outputFile: string;
  output: string;
  mtimeMs: number;
}

/**
 * The openh264-sys2 build-script runs under `profileDir`/build, newest first (by the time of their
 * `output`). Directories without `output` hold the compiled build script itself, not a run, and
 * are skipped.
 */
export function buildScriptRuns(profileDir: string): BuildScriptRun[] {
  const build = join(profileDir, "build");
  if (!existsSync(build)) return [];
  const runs: BuildScriptRun[] = [];
  for (const name of readdirSync(build)) {
    if (!name.startsWith(`${OPENH264_SYS}-`)) continue;
    const outputFile = join(build, name, "output");
    if (!existsSync(outputFile)) continue;
    runs.push({
      dir: join(build, name),
      outputFile,
      output: readFileSync(outputFile, "utf8"),
      mtimeMs: statSync(outputFile).mtimeMs,
    });
  }
  return runs.sort((a, b) => b.mtimeMs - a.mtimeMs);
}

const iso = (ms: number) => new Date(ms).toISOString();

/** What the check found: `problem` is the whole diagnosis (null: the assembly is there). */
export interface AsmVerdict {
  problem: string | null;
  /** What was looked at and what it said, for the build log. */
  notes: string[];
}

const SLOWER =
  "энкодер без ассемблера в 3–5 раз медленнее (27 окт.: кадр 1080p кодировался 15–25 мс вместо " +
  "4–6), и лестница качества уходит вниз из-за CPU";
const CAUSES =
  "Причины: NASM упал на файлах OpenH264 (NASM 3.02 падает с ключом -g — у openh264-sys2 в профиле " +
  "dist должно быть `debug = false`, Cargo.toml, [profile.dist.package.openh264-sys2]), NASM не " +
  "найден, или задана OPENH264_NO_ASM. Проверить NASM вручную: из исходников openh264-sys2 " +
  "`nasm -fwin64 -DWIN64 -Iupstream/codec/common/x86/ upstream/codec/common/x86/dct.asm -o dct.o`";

/**
 * Whether the build that started at `started` (ms) under `profileDir` (`<target>/<profile>`) linked
 * OpenH264 with its assembly into the exe whose PDB is `pdbPath`. `show` turns a path into what the
 * messages print.
 */
export function checkOpenh264Assembly(
  profileDir: string,
  pdbPath: string,
  started: number,
  show: (path: string) => string = (p) => p,
): AsmVerdict {
  const notes: string[] = [];
  if (!existsSync(pdbPath)) {
    return {
      problem: `нет ${show(pdbPath)}: не проверить, есть ли в exe ассемблер OpenH264`,
      notes,
    };
  }
  const pdbTime = statSync(pdbPath).mtimeMs;
  if (pdbTime < started - 2000) {
    return {
      problem:
        `${show(pdbPath)} не обновился этой сборкой (записан ${iso(pdbTime)}): ` +
        "по нему не проверить ассемблер OpenH264 в новом exe",
      notes,
    };
  }

  const build = show(join(profileDir, "build"));
  const runs = buildScriptRuns(profileDir);
  // Only this build's own runs are judged: written after it started and before it linked. An older
  // one may be another build's, not the one linked; a newer one is a later build's.
  const fresh = runs.filter((r) => r.mtimeMs >= started && r.mtimeMs <= pdbTime);
  if (runs.length === 0) {
    notes.push(`вывода сборочного скрипта ${OPENH264_SYS} в ${build} нет: решает PDB`);
  } else if (fresh.length === 0) {
    const newest = runs[0] as BuildScriptRun;
    notes.push(
      `сборочный скрипт ${OPENH264_SYS} в этой сборке не запускался (cargo взял прежний результат); ` +
        `запусков в ${build}: ${runs.length}, новейший ${show(newest.outputFile)} от ` +
        `${iso(newest.mtimeMs)}, PDB от ${iso(pdbTime)}. Какой из них слинкован, по времени не ` +
        "сказать: решает PDB",
    );
  }
  for (const run of fresh) {
    const said = noAsmLine(run.output);
    if (said !== null) {
      return {
        problem:
          `OpenH264 собран без ассемблера: сборочный скрипт ${OPENH264_SYS} в этой сборке написал ` +
          `«${said}» (${show(run.outputFile)}); ${SLOWER}. ${CAUSES}`,
        notes,
      };
    }
    notes.push(
      `вывод сборочного скрипта ${OPENH264_SYS} этой сборки: ${show(run.outputFile)} ` +
        `(записан ${iso(run.mtimeMs)}) — строк «${NO_ASM_MARKERS.join("» / «")}» нет`,
    );
  }

  const missing = missingAsmSymbols(readFileSync(pdbPath));
  if (missing.length > 0) {
    // The outputs only explain it now: which runs, of any build, said they went without assembly.
    const told = runs
      .map((r) => ({ r, said: noAsmLine(r.output) }))
      .filter((x) => x.said !== null)
      .map((x) => `${show(x.r.outputFile)} от ${iso(x.r.mtimeMs)}: «${x.said}»`);
    const why =
      told.length > 0
        ? `сборочный скрипт ${OPENH264_SYS} писал, что собирает без ассемблера: ${told.join("; ")}`
        : `ни один вывод сборочного скрипта ${OPENH264_SYS} в ${build} не говорит, почему`;
    return {
      problem:
        `OpenH264 собран без ассемблера: в ${show(pdbPath)} нет его функций ` +
        `${missing.join(", ")} (найдено ${ASM_SYMBOLS.length - missing.length} из ` +
        `${ASM_SYMBOLS.length}); ${why}; ${SLOWER}. ${CAUSES}`,
      notes,
    };
  }
  notes.push(
    `в ${show(pdbPath)} есть все проверяемые функции ассемблера OpenH264 ` +
      `(${ASM_SYMBOLS.length}): ${ASM_SYMBOLS.join(", ")}`,
  );
  return { problem: null, notes };
}
