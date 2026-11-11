import { describe, expect, test } from "bun:test";
import type { Ran } from "./common";
import {
  assertNasm,
  assertSignerBindsVersion,
  NASM_MIN,
  parseNasmVersion,
  parseTauriCliVersion,
  SIGNER_MIN,
} from "./toolchain";

const ok = (stdout: string): Ran => ({ code: 0, stdout, stderr: "" });

/** A fake `exec` that records what it was asked to run. */
function recorder(answer: Ran | null): { exec: (cmd: string[]) => Ran | null; calls: string[][] } {
  const calls: string[][] = [];
  return {
    calls,
    exec: (cmd) => {
      calls.push(cmd);
      return answer;
    },
  };
}

const onPath = () => "C:\\Users\\Player\\scoop\\shims\\nasm.exe";
const nowhere = () => null;

describe("parseNasmVersion", () => {
  test("what nasm -v says, as nasm-rs reads it", () => {
    expect(parseNasmVersion("NASM version 3.02 compiled on Jun 28 2026")).toEqual({
      major: 3,
      minor: 2,
      patch: 0,
    });
    expect(parseNasmVersion("NASM version 2.16.03 compiled on Apr 17 2024\r\n")).toEqual({
      major: 2,
      minor: 16,
      patch: 3,
    });
    expect(parseNasmVersion("NASM version 2.10.06")).toEqual({ major: 2, minor: 10, patch: 6 });
    expect(parseNasmVersion("NASM version 2.14rc2")).toEqual({ major: 2, minor: 14, patch: 0 });
  });

  test("anything else is not a NASM", () => {
    for (const bad of ["", "nasm 2.16", "yasm 1.3.0", "NASM version x", "Version 2.16"]) {
      expect(parseNasmVersion(bad)).toBeNull();
    }
  });
});

describe("assertNasm", () => {
  test("nasm from PATH: what ran, where it is, its version", () => {
    const r = recorder(ok("NASM version 3.02 compiled on Jun 28 2026\n"));
    const found = assertNasm({}, r.exec, onPath);
    expect(r.calls).toEqual([["nasm", "-v"]]);
    expect(found).toEqual({
      program: "nasm",
      path: "C:\\Users\\Player\\scoop\\shims\\nasm.exe",
      line: "NASM version 3.02 compiled on Jun 28 2026",
      version: { major: 3, minor: 2, patch: 0 },
    });
  });

  test("$NASM is run as given, as nasm-rs runs it", () => {
    const r = recorder(ok("NASM version 2.16.03"));
    const found = assertNasm({ NASM: "D:\\tools\\nasm.exe" }, r.exec, nowhere);
    expect(r.calls).toEqual([["D:\\tools\\nasm.exe", "-v"]]);
    expect(found.path).toBe("D:\\tools\\nasm.exe");
  });

  test("not there: refused, saying why it matters and what to do", () => {
    const r = recorder(null);
    expect(() => assertNasm({}, r.exec, nowhere)).toThrow(/NASM не найден.*в PATH его нет/);
    expect(() => assertNasm({}, r.exec, nowhere)).toThrow(/без ассемблера/);
    expect(() => assertNasm({}, r.exec, nowhere)).toThrow(/scoop install nasm/);
    expect(() => assertNasm({ NASM: "C:\\gone\\nasm.exe" }, r.exec, nowhere)).toThrow(
      /путь из переменной NASM/,
    );
  });

  test("a failing, foreign or too old nasm is refused", () => {
    const failing = recorder({ code: 1, stdout: "", stderr: "boom" });
    expect(() => assertNasm({}, failing.exec, onPath)).toThrow(/с кодом 1: boom/);
    expect(() => assertNasm({}, recorder(ok("yasm 1.3.0")).exec, onPath)).toThrow(/это не NASM/);
    const old = recorder(ok("NASM version 2.10.05 compiled on Jul 2 2012"));
    expect(() => assertNasm({}, old.exec, onPath)).toThrow(/2\.10\.5 .*старше 2\.10\.6/);
    // The floor itself passes.
    expect(assertNasm({}, recorder(ok("NASM version 2.10.06")).exec, onPath).version).toEqual(
      NASM_MIN,
    );
  });

  test("OPENH264_NO_ASM, set to anything, is refused before nasm is even asked", () => {
    for (const value of ["1", "0", ""]) {
      const r = recorder(ok("NASM version 3.02"));
      expect(() => assertNasm({ OPENH264_NO_ASM: value }, r.exec, onPath)).toThrow(
        /OPENH264_NO_ASM/,
      );
      expect(r.calls).toEqual([]);
    }
  });

  test("an empty NASM is refused", () => {
    const r = recorder(ok("NASM version 3.02"));
    expect(() => assertNasm({ NASM: " " }, r.exec, onPath)).toThrow(/NASM задана пустой/);
    expect(r.calls).toEqual([]);
  });
});

describe("the Tauri CLI that signs", () => {
  test("its version line", () => {
    expect(parseTauriCliVersion("tauri-cli 2.12.1\n")).toEqual({ major: 2, minor: 12, patch: 1 });
    expect(parseTauriCliVersion("tauri-cli 3.0.0-alpha.4")).toEqual({
      major: 3,
      minor: 0,
      patch: 0,
    });
    expect(parseTauriCliVersion("cargo-tauri 2.12.1")).toBeNull();
  });

  test("2.12 and later bind the version into the signature; 2.11 is refused", () => {
    expect(assertSignerBindsVersion("tauri-cli 2.12.0")).toEqual(SIGNER_MIN);
    expect(assertSignerBindsVersion("tauri-cli 2.12.1")).toEqual({ major: 2, minor: 12, patch: 1 });
    expect(() => assertSignerBindsVersion("tauri-cli 2.11.4")).toThrow(/--app-version/);
    expect(() => assertSignerBindsVersion("tauri-cli 2.11.4")).toThrow(/TAURI_CLI_VERSION/);
    expect(() => assertSignerBindsVersion("something else")).toThrow(/не прочитана/);
  });
});
