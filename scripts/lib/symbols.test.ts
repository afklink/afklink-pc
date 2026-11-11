import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Failure, sha256Hex } from "./common";
import {
  assertNoSymbolRefs,
  assertPdbMatches,
  assertPublishSet,
  collectSymbols,
  formatGuid,
  HELPER_EXE,
  readCodeView,
  readPdbIdentity,
  releaseFiles,
  SYMBOLS_MANIFEST,
  type SymbolsManifest,
  symbolKey,
} from "./symbols";

/** 16 GUID bytes from a seed: `seed, seed+1, …`. */
const guidBytes = (seed: number) => Uint8Array.from({ length: 16 }, (_, i) => (seed + i) & 0xff);

/**
 * A minimal PE32+ image (PE32 with `pe32`): one section holding the debug directory with one
 * CodeView (RSDS) entry (two with `twoCodeViews`), then `tail` after the image (an embedded
 * helper, its hash).
 */
function fakePe(
  guid: Uint8Array,
  age: number,
  pdbName: string,
  tail: Buffer = Buffer.alloc(0),
  opts: { pe32?: boolean; twoCodeViews?: boolean } = {},
) {
  const b = Buffer.alloc(0x400);
  b.write("MZ", 0, "latin1");
  b.writeUInt32LE(0x40, 0x3c);
  b.write("PE\0\0", 0x40, "latin1");
  const coff = 0x44;
  const optSize = opts.pe32 ? 224 : 240;
  b.writeUInt16LE(opts.pe32 ? 0x14c : 0x8664, coff);
  b.writeUInt16LE(1, coff + 2);
  b.writeUInt16LE(optSize, coff + 16);
  const opt = coff + 20;
  b.writeUInt16LE(opts.pe32 ? 0x10b : 0x20b, opt);
  const dirs = opt + (opts.pe32 ? 96 : 112);
  b.writeUInt32LE(16, dirs - 4);
  const entries = opts.twoCodeViews ? 2 : 1;
  b.writeUInt32LE(0x1000, dirs + 6 * 8);
  b.writeUInt32LE(28 * entries, dirs + 6 * 8 + 4);
  const sec = opt + optSize;
  b.write(".rdata", sec, "latin1");
  b.writeUInt32LE(0x200, sec + 8);
  b.writeUInt32LE(0x1000, sec + 12);
  b.writeUInt32LE(0x200, sec + 16);
  b.writeUInt32LE(0x200, sec + 20);
  const name = Buffer.from(`${pdbName}\0`, "utf8");
  const rec = 0x240;
  for (let e = 0; e < entries; e++) {
    const d = 0x200 + e * 28;
    b.writeUInt32LE(2, d + 12);
    b.writeUInt32LE(24 + name.length, d + 16);
    b.writeUInt32LE(0x1000 + (rec - 0x200), d + 20);
    b.writeUInt32LE(rec, d + 24);
  }
  b.write("RSDS", rec, "latin1");
  Buffer.from(guid).copy(b, rec + 4);
  b.writeUInt32LE(age, rec + 20);
  name.copy(b, rec + 24);
  return Buffer.concat([b, tail]);
}

/**
 * An MSF 7.00 PDB laid out as a real one may be: the stream directory over several blocks, out of
 * order (`200` empty streams make it 1 KB), and the info and DBI streams over several non-adjacent
 * blocks, out of order too.
 */
function scatteredPdb(guid: Uint8Array, age: number, dbiAge: number) {
  const bs = 512;
  const numBlocks = 16;
  const b = Buffer.alloc(bs * numBlocks);
  b.write("Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0", 0, "latin1");
  b.writeUInt32LE(bs, 32);
  b.writeUInt32LE(1, 36);
  b.writeUInt32LE(numBlocks, 40);
  const infoBlocks = [11, 7];
  const dbiBlocks = [13, 5, 9];
  const sizes = Array.from({ length: 200 }, () => 0);
  sizes[1] = 600;
  sizes[3] = 1100;
  const dir = Buffer.alloc(4 + sizes.length * 4 + (infoBlocks.length + dbiBlocks.length) * 4);
  dir.writeUInt32LE(sizes.length, 0);
  for (const [i, s] of sizes.entries()) dir.writeUInt32LE(s, 4 + i * 4);
  for (const [i, x] of [...infoBlocks, ...dbiBlocks].entries()) {
    dir.writeUInt32LE(x, 4 + sizes.length * 4 + i * 4);
  }
  const dirBlocks = [14, 4];
  b.writeUInt32LE(dir.length, 44);
  b.writeUInt32LE(3, 52);
  for (const [i, x] of dirBlocks.entries()) {
    b.writeUInt32LE(x, 3 * bs + i * 4);
    dir.copy(b, x * bs, i * bs, Math.min(dir.length, (i + 1) * bs));
  }
  b.writeUInt32LE(20000404, 11 * bs);
  b.writeUInt32LE(age, 11 * bs + 8);
  Buffer.from(guid).copy(b, 11 * bs + 12);
  b.writeInt32LE(-1, 13 * bs);
  b.writeUInt32LE(dbiAge, 13 * bs + 8);
  // Something in the following blocks too, so that reading the wrong one shows.
  b.fill(0xee, 7 * bs, 8 * bs);
  b.fill(0xdd, 5 * bs, 6 * bs);
  return b;
}

/**
 * A minimal MSF 7.00 PDB, 512-byte blocks: superblock, two free-page maps, the block map, the
 * directory, the info stream (1) and a DBI header (3).
 */
function fakePdb(guid: Uint8Array, age: number, dbiAge: number | null = age) {
  const bs = 512;
  const b = Buffer.alloc(bs * 7);
  b.write("Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0", 0, "latin1");
  b.writeUInt32LE(bs, 32);
  b.writeUInt32LE(1, 36);
  b.writeUInt32LE(7, 40);
  const sizes = [0, 28, 0, dbiAge === null ? 0xffffffff : 64];
  const blocks = dbiAge === null ? [5] : [5, 6];
  const dir = Buffer.alloc(4 + sizes.length * 4 + blocks.length * 4);
  dir.writeUInt32LE(sizes.length, 0);
  for (const [i, s] of sizes.entries()) dir.writeUInt32LE(s, 4 + i * 4);
  for (const [i, x] of blocks.entries()) dir.writeUInt32LE(x, 4 + sizes.length * 4 + i * 4);
  b.writeUInt32LE(dir.length, 44);
  b.writeUInt32LE(3, 52);
  b.writeUInt32LE(4, 3 * bs);
  dir.copy(b, 4 * bs);
  b.writeUInt32LE(20000404, 5 * bs);
  b.writeUInt32LE(0x5f5e100, 5 * bs + 4);
  b.writeUInt32LE(age, 5 * bs + 8);
  Buffer.from(guid).copy(b, 5 * bs + 12);
  if (dbiAge !== null) {
    b.writeInt32LE(-1, 6 * bs);
    b.writeUInt32LE(19990903, 6 * bs + 4);
    b.writeUInt32LE(dbiAge, 6 * bs + 8);
  }
  return b;
}

describe("reading the exe's CodeView record and the PDB's identity", () => {
  test("a GUID prints as Windows prints it: the first three fields little-endian", () => {
    expect(formatGuid(guidBytes(0))).toBe("03020100-0504-0706-0809-0A0B0C0D0E0F");
  });

  test("the exe's CodeView record: GUID, age and the PDB's file name", () => {
    const cv = readCodeView(fakePe(guidBytes(0x10), 3, "afklink_app.pdb"), "app.exe");
    expect(cv).toEqual({
      guid: "13121110-1514-1716-1819-1A1B1C1D1E1F",
      age: 3,
      pdbName: "afklink_app.pdb",
    });
    expect(symbolKey(cv)).toBe("afklink_app.pdb/131211101514171618191A1B1C1D1E1F3/afklink_app.pdb");
  });

  test("the PDB's GUID, its info age and its DBI age", () => {
    expect(readPdbIdentity(fakePdb(guidBytes(0x10), 2, 3), "x.pdb")).toEqual({
      guid: "13121110-1514-1716-1819-1A1B1C1D1E1F",
      age: 2,
      dbiAge: 3,
    });
    expect(readPdbIdentity(fakePdb(guidBytes(1), 4, null), "x.pdb").dbiAge).toBeNull();
  });

  test("what is not a PE, not a PDB or cut short is refused, never misread", () => {
    expect(() => readCodeView(Buffer.from("not an exe at all"), "a.exe")).toThrow(Failure);
    expect(() => readCodeView(Buffer.alloc(0x40, 0), "a.exe")).toThrow(/не PE/);
    const noDebug = fakePe(guidBytes(0), 1, "a.pdb");
    noDebug.writeUInt32LE(0, 0x58 + 112 + 6 * 8);
    expect(() => readCodeView(noDebug, "a.exe")).toThrow(/каталог отладки пуст/);
    expect(() =>
      readCodeView(fakePe(guidBytes(0), 1, "a.pdb").subarray(0, 0x220), "a.exe"),
    ).toThrow(/за пределами файла/);
    expect(() => readPdbIdentity(fakePe(guidBytes(0), 1, "a.pdb"), "a.pdb")).toThrow(/не PDB/);
    expect(() => readPdbIdentity(fakePdb(guidBytes(0), 1).subarray(0, 1024), "a.pdb")).toThrow(
      /обрезан/,
    );
  });

  test("a PE32 image is read as well as a PE32+ one", () => {
    expect(
      readCodeView(fakePe(guidBytes(3), 2, "x.pdb", undefined, { pe32: true }), "x.exe"),
    ).toEqual({ guid: formatGuid(guidBytes(3)), age: 2, pdbName: "x.pdb" });
  });

  test("two CodeView records: refused, the exe's PDB is not one thing", () => {
    expect(() =>
      readCodeView(fakePe(guidBytes(3), 2, "x.pdb", undefined, { twoCodeViews: true }), "x.exe"),
    ).toThrow(/записей CodeView 2/);
  });

  test("a PDB whose directory and streams lie over non-adjacent blocks out of order", () => {
    expect(readPdbIdentity(scatteredPdb(guidBytes(0x70), 4, 6), "s.pdb")).toEqual({
      guid: formatGuid(guidBytes(0x70)),
      age: 4,
      dbiAge: 6,
    });
  });

  test("a PDB matches only with the exe's GUID and age (DBI age when there is one)", () => {
    const cv = readCodeView(fakePe(guidBytes(7), 1, "a.pdb"), "a.exe");
    expect(
      assertPdbMatches(cv, readPdbIdentity(fakePdb(guidBytes(7), 1), "a.pdb"), "a.exe", "a.pdb"),
    ).toContain(cv.guid);
    // Another build's PDB: another GUID.
    expect(() =>
      assertPdbMatches(cv, readPdbIdentity(fakePdb(guidBytes(8), 1), "a.pdb"), "a.exe", "a.pdb"),
    ).toThrow(/не PDB этого exe/);
    // The same GUID written again (another age): not these bytes either.
    expect(() =>
      assertPdbMatches(cv, readPdbIdentity(fakePdb(guidBytes(7), 1, 2), "a.pdb"), "a.exe", "a.pdb"),
    ).toThrow(/не PDB этого exe/);
    // No DBI stream: the info stream's age decides.
    expect(() =>
      assertPdbMatches(
        cv,
        readPdbIdentity(fakePdb(guidBytes(7), 5, null), "a.pdb"),
        "a.exe",
        "a.pdb",
      ),
    ).toThrow(/age 5/);
  });
});

describe("collecting a release's symbols", () => {
  let root: string;
  let profile: string;
  let release: string;
  let out: string;
  const helperBytes = fakePe(guidBytes(0x40), 1, "afklink_game_helper.pdb", Buffer.from("helper"));
  const staleHelper = fakePe(guidBytes(0x50), 1, "afklink_game_helper.pdb", Buffer.from("old"));

  const helperDir = (unit: string) =>
    join(profile, "build", unit, "out", "game-helper-build", "x86_64-pc-windows-msvc", "dist");

  /** A dist profile directory as a shipping build leaves it, and the exe copied under its name. */
  function layout(
    opts: {
      appPdb?: Buffer;
      helperPdb?: Buffer;
      embed?: Buffer;
      appPdbName?: string;
      noHash?: boolean;
      twice?: boolean;
    } = {},
  ) {
    const embed = opts.embed ?? helperBytes;
    const app = fakePe(
      guidBytes(0x20),
      1,
      opts.appPdbName ?? "afklink_app.pdb",
      Buffer.concat([embed, Buffer.from(opts.noHash ? "" : sha256Hex(embed), "utf8")]),
    );
    mkdirSync(profile, { recursive: true });
    writeFileSync(join(profile, "afklink-app.exe"), app);
    writeFileSync(join(profile, "afklink_app.pdb"), opts.appPdb ?? fakePdb(guidBytes(0x20), 1));
    const units: [string, Buffer, number][] = [
      ["afklink-app-0123", helperBytes, 0x40],
      ["afklink-app-old9", staleHelper, 0x50],
    ];
    // Another build directory holding the very same helper (an unchanged helper rebuilt).
    if (opts.twice) units.push(["afklink-app-4567", helperBytes, 0x40]);
    // A build directory without a helper build, and one whose triple has no dist helper.
    mkdirSync(join(profile, "build", "afklink-app-noout"), { recursive: true });
    mkdirSync(join(profile, "build", "afklink-app-0123", "out", "game-helper-build", "other"), {
      recursive: true,
    });
    for (const [unit, exe, guid] of units) {
      mkdirSync(helperDir(unit), { recursive: true });
      writeFileSync(join(helperDir(unit), HELPER_EXE), exe);
      writeFileSync(
        join(helperDir(unit), "afklink_game_helper.pdb"),
        unit === "afklink-app-0123" && opts.helperPdb
          ? opts.helperPdb
          : fakePdb(guidBytes(guid), 1),
      );
    }
    mkdirSync(release, { recursive: true });
    copyFileSync(join(profile, "afklink-app.exe"), join(release, "AFKLink-9.9.9.exe"));
    return app;
  }

  const collect = () =>
    collectSymbols({
      shippedExe: join(release, "AFKLink-9.9.9.exe"),
      builtExe: join(profile, "afklink-app.exe"),
      outDir: out,
      version: "9.9.9",
      channel: "release",
      commit: "a".repeat(40),
      builtAt: "2026-10-26T00:00:00Z",
      tag: "test",
    });

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "afklink-symbols-"));
    profile = join(root, "target", "dist");
    release = join(root, "dist", "release", "9.9.9");
    out = join(root, "dist", "symbols", "9.9.9");
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  test("the app's PDB and the embedded helper's, matched, with the helper exe and symbols.json", () => {
    const app = layout();
    const manifest = collect();
    expect(readdirSync(out).sort()).toEqual(
      [HELPER_EXE, SYMBOLS_MANIFEST, "afklink_app.pdb", "afklink_game_helper.pdb"].sort(),
    );
    const written = JSON.parse(
      readFileSync(join(out, SYMBOLS_MANIFEST), "utf8"),
    ) as SymbolsManifest;
    expect(written).toEqual(manifest);
    expect(written.version).toBe("9.9.9");
    expect(written.channel).toBe("release");
    expect(written.exe).toEqual({
      name: "AFKLink-9.9.9.exe",
      sha256: sha256Hex(app),
      size: app.length,
    });
    const [a, h] = written.modules;
    expect(a?.module).toBe("AFKLink-9.9.9.exe");
    expect(a?.embedded_in).toBeNull();
    expect(a?.codeview).toEqual({
      guid: formatGuid(guidBytes(0x20)),
      age: 1,
      pdb_name: "afklink_app.pdb",
    });
    expect(a?.pdb.guid).toBe(a?.codeview.guid);
    expect(a?.pdb.sha256).toBe(sha256Hex(readFileSync(join(profile, "afklink_app.pdb"))));
    // The helper inside the app, not the stale one of an older build directory.
    expect(h?.module).toBe(HELPER_EXE);
    expect(h?.embedded_in).toBe("AFKLink-9.9.9.exe");
    expect(h?.exe.sha256).toBe(sha256Hex(helperBytes));
    expect(h?.codeview.guid).toBe(formatGuid(guidBytes(0x40)));
    expect(h?.pdb.guid).toBe(h?.codeview.guid);
    expect(readFileSync(join(out, HELPER_EXE)).equals(helperBytes)).toBe(true);
  });

  test("an app PDB of another build stops it, and nothing is written", () => {
    layout({ appPdb: fakePdb(guidBytes(0x21), 1) });
    expect(collect).toThrow(/не PDB этого exe/);
    expect(existsSync(out)).toBe(false);
  });

  test("a helper PDB of another build stops it", () => {
    layout({ helperPdb: fakePdb(guidBytes(0x40), 2) });
    expect(collect).toThrow(/не PDB этого exe/);
    expect(existsSync(out)).toBe(false);
  });

  test("the shipped exe's bytes stay as they were", () => {
    layout();
    const shipped = join(release, "AFKLink-9.9.9.exe");
    const before = sha256Hex(readFileSync(shipped));
    collect();
    expect(sha256Hex(readFileSync(shipped))).toBe(before);
  });

  test("an exe that names its PDB with a path (the build machine's) stops it", () => {
    for (const name of [
      "C:\\Users\\Player\\target\\dist\\afklink_app.pdb",
      "target/dist/afklink_app.pdb",
      "D:afklink_app.pdb",
    ]) {
      layout({ appPdbName: name });
      expect(collect).toThrow(/с путём/);
      expect(existsSync(out)).toBe(false);
    }
  });

  test("the same helper in two build directories is one module, not a refusal", () => {
    layout({ twice: true });
    const manifest = collect();
    expect(manifest.modules.map((m) => m.module)).toEqual(["AFKLink-9.9.9.exe", HELPER_EXE]);
    expect(manifest.modules[1]?.exe.sha256).toBe(sha256Hex(helperBytes));
  });

  test("an app exe without the embedded helper's SHA-256: stopped", () => {
    layout({ noHash: true });
    expect(collect).toThrow(/нет SHA-256 вшитого помощника/);
  });

  test("a previous symbols folder is replaced whole", () => {
    layout();
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, "stale.pdb"), "old");
    collect();
    expect(readdirSync(out)).not.toContain("stale.pdb");
  });

  test("a missing PDB stops it", () => {
    layout();
    rmSync(join(profile, "afklink_app.pdb"));
    expect(collect).toThrow(/не найден/);
  });

  test("no built helper is the embedded one: stopped", () => {
    layout({ embed: fakePe(guidBytes(0x60), 1, "afklink_game_helper.pdb", Buffer.from("x")) });
    expect(collect).toThrow(/не совпал с вшитым/);
  });

  test("a shipped exe that is not the built one: stopped", () => {
    layout();
    writeFileSync(
      join(release, "AFKLink-9.9.9.exe"),
      fakePe(guidBytes(0x20), 1, "afklink_app.pdb"),
    );
    expect(collect).toThrow(/не совпадает/);
  });

  test("a symbols folder that holds the build is never emptied", () => {
    layout();
    out = join(root, "target");
    expect(collect).toThrow(/содержит сборку/);
    expect(existsSync(join(profile, "afklink-app.exe"))).toBe(true);
  });
});

describe("what is published holds no symbols", () => {
  let root: string;
  let dir: string;
  let symbols: string;
  const name = "AFKLink-9.9.9.exe";

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "afklink-publish-"));
    dir = join(root, "release", "9.9.9");
    symbols = join(root, "symbols", "9.9.9");
    mkdirSync(dir, { recursive: true });
    for (const f of releaseFiles(name)) writeFileSync(join(dir, f), `contents of ${f}`);
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  test("the release's four files pass", () => {
    expect(releaseFiles(name)).toEqual([name, `${name}.sig`, `${name}.sha256`, "latest.json"]);
    expect(releaseFiles("t.exe", "test-latest.json")).toEqual([
      "t.exe",
      "t.exe.sig",
      "t.exe.sha256",
      "test-latest.json",
    ]);
    expect(assertPublishSet(dir, symbols, releaseFiles(name))).toEqual(
      [...releaseFiles(name)].sort(),
    );
  });

  test("a PDB by name, a PDB under another name, symbols.json or a folder is refused", () => {
    for (const [what, make] of [
      ["afklink_app.pdb", () => writeFileSync(join(dir, "afklink_app.pdb"), "x")],
      ["AFKLINK.PDB", () => writeFileSync(join(dir, "AFKLINK.PDB"), "x")],
      ["symbols.json", () => writeFileSync(join(dir, "symbols.json"), "{}")],
      ["это PDB", () => writeFileSync(join(dir, "notes.txt"), fakePdb(guidBytes(1), 1))],
      ["не файл", () => mkdirSync(join(dir, "symbols"))],
    ] as const) {
      make();
      // Refused with or without the expected list (a trial's folder is checked without it).
      expect(() => assertPublishSet(dir, symbols, releaseFiles(name))).toThrow(what);
      expect(() => assertPublishSet(dir, symbols, null)).toThrow(what);
      rmSync(join(root, "release"), { recursive: true, force: true });
      mkdirSync(dir, { recursive: true });
      for (const f of releaseFiles(name)) writeFileSync(join(dir, f), `contents of ${f}`);
    }
  });

  test("any other file breaks a tagged release's list; a trial's folder may hold older trials", () => {
    writeFileSync(join(dir, "AFKLink-9.9.8.exe"), "older");
    expect(() => assertPublishSet(dir, symbols, releaseFiles(name))).toThrow(/должны быть только/);
    expect(assertPublishSet(dir, symbols, null)).toContain("AFKLink-9.9.8.exe");
    rmSync(join(dir, "latest.json"));
    rmSync(join(dir, "AFKLink-9.9.8.exe"));
    expect(() => assertPublishSet(dir, symbols, releaseFiles(name))).toThrow(/должны быть только/);
  });

  test("a link (a junction) in the published folder is refused, whatever it leads to", () => {
    mkdirSync(join(root, "elsewhere"));
    symlinkSync(join(root, "elsewhere"), join(dir, "linked"), "junction");
    expect(() => assertPublishSet(dir, symbols, null)).toThrow(/не файл: linked/);
    expect(() => assertPublishSet(dir, symbols, releaseFiles(name))).toThrow(/не файл/);
  });

  test("the symbols folder inside the published one, or around it, is refused", () => {
    expect(() => assertPublishSet(dir, join(dir, "symbols"), null)).toThrow(/вложены/);
    expect(() => assertPublishSet(dir, root, null)).toThrow(/вложены/);
  });

  test("latest.json that names a PDB or the symbols is refused", () => {
    expect(() => assertNoSymbolRefs('{"url":"https://x/afklink_app.pdb"}', "latest.json")).toThrow(
      /afklink_app\.pdb/,
    );
    expect(() => assertNoSymbolRefs('{"notes":"see symbols.json"}', "latest.json")).toThrow(
      Failure,
    );
    assertNoSymbolRefs('{"version":"9.9.9","notes":"Быстрее и чище"}', "latest.json");
  });
});
