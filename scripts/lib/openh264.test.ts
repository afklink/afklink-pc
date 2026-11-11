import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AGENT } from "./common";
import {
  ASM_SYMBOLS,
  buildScriptRuns,
  checkOpenh264Assembly,
  missingAsmSymbols,
  noAsmLine,
} from "./openh264";

// Build-script outputs as openh264-sys2 0.9.8 writes them (cut): cc's environment lookups, and on
// a failed or disabled NASM its own line first, once per OpenH264 library.
const CC_LINES =
  "cargo:rerun-if-env-changed=CC_FORCE_DISABLE\nCC_FORCE_DISABLE = None\n" +
  "cargo:rerun-if-env-changed=VCINSTALLDIR\nVCINSTALLDIR = None\n" +
  "cargo:rustc-link-lib=static=openh264_common\n";
const WITH_ASM = CC_LINES.repeat(4);
const NASM_FAILED = `Failed to compile NASM files, not using any assembly.\n${CC_LINES}`.repeat(4);
const NO_ASM_ENV = `NASM compilation disabled by environment variable.\r\n${CC_LINES}`;
const NO_CONFIG =
  "No NASM configuration found for target, not using any assembly.\nTarget: Target { … }\n" +
  CC_LINES;

/** A stand-in PDB: MSF junk around NUL-ended public names, as a real one keeps them. */
function pdb(names: readonly string[]): Buffer {
  const junk = Buffer.from("Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0", "latin1");
  return Buffer.concat([junk, ...names.map((n) => Buffer.from(`\x0e\x11${n}\0`, "latin1")), junk]);
}

describe("noAsmLine", () => {
  test("every way openh264-sys2 says it went without assembly", () => {
    expect(noAsmLine(NASM_FAILED)).toBe("Failed to compile NASM files, not using any assembly.");
    expect(noAsmLine(NO_ASM_ENV)).toBe("NASM compilation disabled by environment variable.");
    expect(noAsmLine(NO_CONFIG)).toBe(
      "No NASM configuration found for target, not using any assembly.",
    );
  });
  test("an output with the assembly built says nothing of it", () => {
    expect(noAsmLine(WITH_ASM)).toBeNull();
    expect(noAsmLine("")).toBeNull();
  });
});

describe("missingAsmSymbols", () => {
  test("all of them in a PDB of an exe with the assembly", () => {
    expect(missingAsmSymbols(pdb([...ASM_SYMBOLS, "WelsCPUIdVerify", "impl_avx2"]))).toEqual([]);
  });
  test("a plain-C OpenH264 leaves none of them; Rust's own _avx2 names do not count", () => {
    expect(missingAsmSymbols(pdb(["impl_avx2", "find_sse2", "WelsEncoderEncodeExt"]))).toEqual([
      ...ASM_SYMBOLS,
    ]);
  });
  test("a name counts only whole: WelsCPUIdVerify is not WelsCPUId", () => {
    const others = ASM_SYMBOLS.filter((n) => n !== "WelsCPUId");
    expect(missingAsmSymbols(pdb([...others, "WelsCPUIdVerify"]))).toEqual(["WelsCPUId"]);
  });
  test("a view into a larger buffer is read as itself", () => {
    const whole = Buffer.concat([pdb(ASM_SYMBOLS), Buffer.alloc(16)]);
    expect(missingAsmSymbols(new Uint8Array(whole.buffer, whole.byteOffset, 8))).toEqual([
      ...ASM_SYMBOLS,
    ]);
  });
});

describe("checkOpenh264Assembly", () => {
  let profile: string;
  let pdbPath: string;
  const started = Date.parse("2026-10-27T20:00:00Z");
  const at = (iso: string) => new Date(iso);

  /** One build-script run directory with `output` written at `iso`. */
  function run(hash: string, output: string, iso: string): string {
    const dir = join(profile, "build", `openh264-sys2-${hash}`);
    mkdirSync(join(dir, "out"), { recursive: true });
    const file = join(dir, "output");
    writeFileSync(file, output);
    utimesSync(file, at(iso), at(iso));
    return file;
  }

  function writePdb(names: readonly string[], iso = "2026-10-27T20:08:00Z"): void {
    writeFileSync(pdbPath, pdb(names));
    utimesSync(pdbPath, at(iso), at(iso));
  }

  beforeEach(() => {
    profile = mkdtempSync(join(tmpdir(), "afklink-openh264-"));
    pdbPath = join(profile, "afklink_app.pdb");
    // The compiled build script's own directory: no `output`, never a run.
    mkdirSync(join(profile, "build", "openh264-sys2-cabb10ff1bdc2bd4"), { recursive: true });
  });
  afterEach(() => rmSync(profile, { recursive: true, force: true }));

  test("assembly built and linked: no problem, and the log says what was looked at", () => {
    run("1111111111111111", WITH_ASM, "2026-10-27T20:01:00Z");
    writePdb(ASM_SYMBOLS);
    const v = checkOpenh264Assembly(profile, pdbPath, started);
    expect(v.problem).toBeNull();
    expect(v.notes.join("\n")).toContain("этой сборки: ");
    expect(v.notes.join("\n")).toContain("openh264-sys2-1111111111111111");
    expect(v.notes.join("\n")).toContain(
      `все проверяемые функции ассемблера OpenH264 (${ASM_SYMBOLS.length})`,
    );
  });

  test("the NASM failure line refuses, naming the cause and the profile fix", () => {
    const file = run("643e47316284b2e7", NASM_FAILED, "2026-10-27T20:01:00Z");
    writePdb([]);
    const v = checkOpenh264Assembly(profile, pdbPath, started);
    expect(v.problem).toContain("OpenH264 собран без ассемблера");
    expect(v.problem).toContain("«Failed to compile NASM files, not using any assembly.»");
    expect(v.problem).toContain(file);
    expect(v.problem).toContain("[profile.dist.package.openh264-sys2]");
    expect(v.problem).toContain("-g");
  });

  test("OPENH264_NO_ASM's line refuses too", () => {
    run("2222222222222222", NO_ASM_ENV, "2026-10-27T20:01:00Z");
    writePdb(ASM_SYMBOLS);
    expect(checkOpenh264Assembly(profile, pdbPath, started).problem).toContain(
      "NASM compilation disabled",
    );
  });

  test("a stale failing run of an earlier build beside this build's good one: no refusal", () => {
    run("643e47316284b2e7", NASM_FAILED, "2026-10-27T10:40:00Z");
    run("3333333333333333", WITH_ASM, "2026-10-27T20:01:00Z");
    writePdb(ASM_SYMBOLS);
    expect(checkOpenh264Assembly(profile, pdbPath, started).problem).toBeNull();
  });

  test("a stale failing run NEWER than this build's good one does not refuse either", () => {
    // A later `pipeline_bench` (other features, other hash) wrote its run after the
    // portable's link — only a run written between this build's start and its PDB counts.
    run("3333333333333333", WITH_ASM, "2026-10-27T20:01:00Z");
    run("cb7e2822661f1a32", NASM_FAILED, "2026-10-27T20:14:00Z");
    writePdb(ASM_SYMBOLS);
    const v = checkOpenh264Assembly(profile, pdbPath, started);
    expect(v.problem).toBeNull();
  });

  test("this build reused a cached run: the outputs are not judged, the PDB decides", () => {
    run("643e47316284b2e7", NASM_FAILED, "2026-10-27T19:30:00Z");
    run("4444444444444444", WITH_ASM, "2026-10-27T09:00:00Z");
    writePdb(ASM_SYMBOLS);
    const v = checkOpenh264Assembly(profile, pdbPath, started);
    expect(v.problem).toBeNull();
    expect(v.notes.join("\n")).toContain("в этой сборке не запускался");
    expect(v.notes.join("\n")).toContain("запусков в");
    expect(v.notes.join("\n")).toContain("решает PDB");
  });

  test("no failure line but no assembly in the PDB: refused on the positive marker", () => {
    run("5555555555555555", WITH_ASM, "2026-10-27T20:01:00Z");
    writePdb(["impl_avx2", "WelsCPUIdVerify"]);
    const v = checkOpenh264Assembly(profile, pdbPath, started);
    expect(v.problem).toContain(
      "нет его функций WelsCPUId, WelsSampleSad16x16_sse2, WelsDctFourT4_sse2",
    );
    expect(v.problem).toContain(`найдено 0 из ${ASM_SYMBOLS.length}`);
    expect(v.problem).toContain("ни один вывод сборочного скрипта openh264-sys2");
  });

  test("a PDB refusal is explained by an older run's failure line", () => {
    const file = run("643e47316284b2e7", NASM_FAILED, "2026-10-27T13:40:00Z");
    writePdb(["WelsSampleSad16x16_c"]);
    const v = checkOpenh264Assembly(profile, pdbPath, started);
    expect(v.problem).toContain("нет его функций");
    expect(v.problem).toContain(`${file} от 2026-10-27T13:40:00.000Z`);
    expect(v.problem).toContain("«Failed to compile NASM files, not using any assembly.»");
  });

  test("no build-script run at all: said, and the PDB decides", () => {
    writePdb(ASM_SYMBOLS);
    const v = checkOpenh264Assembly(profile, pdbPath, started);
    expect(v.problem).toBeNull();
    expect(v.notes.join("\n")).toContain("вывода сборочного скрипта openh264-sys2");
    rmSync(join(profile, "build"), { recursive: true });
    writePdb([]);
    expect(checkOpenh264Assembly(profile, pdbPath, started).problem).toContain("нет его функций");
  });

  test("a missing or stale PDB is refused, not trusted", () => {
    run("6666666666666666", WITH_ASM, "2026-10-27T20:01:00Z");
    expect(checkOpenh264Assembly(profile, pdbPath, started).problem).toContain(
      "afklink_app.pdb: не проверить",
    );
    writePdb(ASM_SYMBOLS, "2026-10-27T19:00:00Z");
    expect(checkOpenh264Assembly(profile, pdbPath, started).problem).toContain(
      "не обновился этой сборкой",
    );
  });

  test("buildScriptRuns skips the build script's own directory and other crates; newest first", () => {
    mkdirSync(join(profile, "build", "openh264-0123456789abcdef"), { recursive: true });
    writeFileSync(join(profile, "build", "openh264-0123456789abcdef", "output"), NASM_FAILED);
    expect(buildScriptRuns(profile)).toEqual([]);
    run("7777777777777777", WITH_ASM, "2026-10-27T20:01:00Z");
    run("8888888888888888", NASM_FAILED, "2026-10-27T10:01:00Z");
    expect(buildScriptRuns(profile).map((r) => r.output)).toEqual([WITH_ASM, NASM_FAILED]);
  });
});

describe("the fix and the guard stay in place", () => {
  const read = (...p: string[]) => readFileSync(join(AGENT, ...p), "utf8").replace(/\r\n/g, "\n");

  test("Cargo.toml: openh264-sys2 has no debug info in the dist profile (no `nasm -g`)", () => {
    const toml = read("Cargo.toml");
    const table = /^\[profile\.dist\.package\.openh264-sys2\]\n((?:[^[\n].*\n|\n)*)/m.exec(toml);
    expect(table).not.toBeNull();
    expect(table?.[1] ?? "").toMatch(/^debug = false$/m);
  });

  test("buildDesktopApp checks the assembly after the exe is proven this build's", () => {
    const common = read("scripts", "lib", "common.ts");
    const body = common.slice(common.indexOf("export async function buildDesktopApp("));
    const end = body.indexOf("\n}\n");
    const fn = body.slice(0, end);
    const fresh = fn.indexOf("statSync(exe).mtimeMs < started");
    const stamp = fn.indexOf("сборка взяла старый код");
    const guard = fn.indexOf("assertOpenh264Assembly(exe, target, started, tag)");
    expect(fresh).toBeGreaterThan(0);
    expect(stamp).toBeGreaterThan(fresh);
    expect(guard).toBeGreaterThan(stamp);
    expect(fn.indexOf("return bytes;")).toBeGreaterThan(guard);
  });
});
