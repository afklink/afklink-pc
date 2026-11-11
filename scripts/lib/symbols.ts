/**
 * The release's debug symbols, kept privately: the PDB of the app and of the game
 * helper it embeds, matched to the shipped bytes, in a folder of their own that is never published.
 *
 * rustc on MSVC always links with `/DEBUG /PDBALTPATH:%_PDB%`, so a shipping build leaves
 * `<target>/dist/afklink_app.pdb` beside the exe, and the exe keeps only that file name, a GUID and an
 * age (its CodeView record, `RSDS`). The game helper is built by app/src-tauri/build.rs into the app's
 * `OUT_DIR/game-helper-build/<triple>/<profile>/` with its PDB beside it, and embedded in the app
 * byte for byte (`include_bytes!`); it runs as a process of its own, so its PDB matters too.
 *
 * A PDB is the one for an exe when its GUID and age are the exe's: what a debugger checks before it
 * uses one. `collectSymbols` reads both sides and refuses a mismatch — symbols that do not belong to
 * the shipped bytes would name the wrong functions. The folder:
 *
 *   afklink_app.pdb            the app's
 *   afklink_game_helper.pdb    the embedded helper's
 *   afklink-game-helper.exe    the embedded helper itself (symbolizers want the exe beside its PDB;
 *                              the app's exe is the published one, not copied here)
 *   symbols.json               what is here and whose it is (`SymbolsManifest`)
 *
 * `assertPublishSet` is the other half: what is published (the release folder, which CI uploads as the
 * release artifact and then over SFTP) holds no PDB, no symbols manifest and no folder, and the two
 * folders never lie inside each other.
 */
import {
  closeSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { Failure, isWithin, sha256Hex, shown } from "./common";

/** The manifest's file name in the symbols folder. */
export const SYMBOLS_MANIFEST = "symbols.json";

/** The game helper's exe as build.rs builds it. */
export const HELPER_EXE = "afklink-game-helper.exe";

/** The start of every PDB (MSF 7.00), all 32 bytes of it. */
const MSF7_MAGIC = Buffer.from("Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0", "latin1");

/** `IMAGE_DEBUG_TYPE_CODEVIEW`. */
const DEBUG_TYPE_CODEVIEW = 2;

/** The exe's side: its CodeView record. */
export interface CodeView {
  /** `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`, upper case, as Windows prints a GUID. */
  guid: string;
  age: number;
  /** The PDB's name as the exe records it (only the file name, with `/PDBALTPATH:%_PDB%`). */
  pdbName: string;
}

/** The PDB's side: the info stream (1) and the DBI stream's (3) age. */
export interface PdbIdentity {
  guid: string;
  /** The info stream's age. */
  age: number;
  /** The DBI stream's age, which debuggers compare with the exe's; `null` without a DBI stream. */
  dbiAge: number | null;
}

/** A GUID's 16 bytes as Windows prints it: the first three fields little-endian. */
export function formatGuid(b: Uint8Array): string {
  if (b.length !== 16) throw new Failure(`GUID: ${b.length} байт вместо 16`);
  const v = new DataView(b.buffer, b.byteOffset, 16);
  const hex = (n: number, w: number) => n.toString(16).toUpperCase().padStart(w, "0");
  const tail = [...b.subarray(8)].map((x) => hex(x, 2)).join("");
  return [
    hex(v.getUint32(0, true), 8),
    hex(v.getUint16(4, true), 4),
    hex(v.getUint16(6, true), 4),
    tail.slice(0, 4),
    tail.slice(4),
  ].join("-");
}

/**
 * The symbol-store key of a PDB (`symstore`, `_NT_SYMBOL_PATH` caches, `symchk`):
 * `<name>/<GUID without dashes><age in hex>/<name>`.
 */
export function symbolKey(cv: CodeView): string {
  const name = basename(cv.pdbName.replace(/\\/g, "/"));
  return `${name}/${cv.guid.replace(/-/g, "")}${cv.age.toString(16).toUpperCase()}/${name}`;
}

/** Bounds-checked little-endian reads with the file named in every refusal. */
class Reader {
  private readonly view: DataView;
  constructor(
    readonly bytes: Uint8Array,
    readonly what: string,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  private need(at: number, len: number, field: string): void {
    if (!Number.isInteger(at) || at < 0 || at + len > this.bytes.length) {
      throw new Failure(
        `${this.what}: ${field} за пределами файла (смещение ${at}, ${len} байт, файл ${this.bytes.length})`,
      );
    }
  }
  u16(at: number, field: string): number {
    this.need(at, 2, field);
    return this.view.getUint16(at, true);
  }
  u32(at: number, field: string): number {
    this.need(at, 4, field);
    return this.view.getUint32(at, true);
  }
  i32(at: number, field: string): number {
    this.need(at, 4, field);
    return this.view.getInt32(at, true);
  }
  slice(at: number, len: number, field: string): Uint8Array {
    this.need(at, len, field);
    return this.bytes.subarray(at, at + len);
  }
}

/**
 * The CodeView record (`RSDS`) of a PE image (PE32 or PE32+): through the debug data directory, by
 * its file offset. Exactly one CodeView entry, or the exe's PDB is not one thing.
 */
export function readCodeView(bytes: Uint8Array, what: string): CodeView {
  const r = new Reader(bytes, what);
  if (r.u16(0, "MZ") !== 0x5a4d) throw new Failure(`${what}: не PE (нет «MZ»)`);
  const pe = r.u32(0x3c, "e_lfanew");
  if (r.u32(pe, "сигнатура PE") !== 0x4550) throw new Failure(`${what}: не PE (нет «PE\\0\\0»)`);
  const coff = pe + 4;
  const sections = r.u16(coff + 2, "NumberOfSections");
  const optSize = r.u16(coff + 16, "SizeOfOptionalHeader");
  const opt = coff + 20;
  const magic = r.u16(opt, "Magic");
  let dirs: number;
  let count: number;
  if (magic === 0x20b) {
    count = r.u32(opt + 108, "NumberOfRvaAndSizes");
    dirs = opt + 112;
  } else if (magic === 0x10b) {
    count = r.u32(opt + 92, "NumberOfRvaAndSizes");
    dirs = opt + 96;
  } else {
    throw new Failure(`${what}: необычный заголовок PE (Magic 0x${magic.toString(16)})`);
  }
  if (count <= 6) throw new Failure(`${what}: нет каталога отладки (${count} каталогов данных)`);
  const debugRva = r.u32(dirs + 6 * 8, "каталог отладки");
  const debugSize = r.u32(dirs + 6 * 8 + 4, "размер каталога отладки");
  if (debugRva === 0 || debugSize === 0) {
    throw new Failure(`${what}: каталог отладки пуст — exe собран без PDB`);
  }
  const table = opt + optSize;
  const fileOffset = (rva: number): number => {
    for (let i = 0; i < sections; i++) {
      const s = table + i * 40;
      const vsize = r.u32(s + 8, "VirtualSize");
      const va = r.u32(s + 12, "VirtualAddress");
      const raw = r.u32(s + 16, "SizeOfRawData");
      const ptr = r.u32(s + 20, "PointerToRawData");
      if (rva >= va && rva < va + Math.max(vsize, raw)) return ptr + (rva - va);
    }
    throw new Failure(`${what}: RVA 0x${rva.toString(16)} ни в одной секции`);
  };
  const at = fileOffset(debugRva);
  const found: CodeView[] = [];
  for (let off = at; off + 28 <= at + debugSize; off += 28) {
    if (r.u32(off + 12, "Type") !== DEBUG_TYPE_CODEVIEW) continue;
    const size = r.u32(off + 16, "SizeOfData");
    const ptr = r.u32(off + 24, "PointerToRawData");
    const rec = r.slice(ptr, size, "запись CodeView");
    if (size < 25 || Buffer.from(rec.subarray(0, 4)).toString("latin1") !== "RSDS") {
      throw new Failure(`${what}: запись CodeView не RSDS (PDB 7.0)`);
    }
    const rr = new Reader(rec, `${what}, CodeView`);
    const nameBytes = rec.subarray(24);
    const end = nameBytes.indexOf(0);
    if (end <= 0) throw new Failure(`${what}: в записи CodeView нет имени PDB`);
    found.push({
      guid: formatGuid(rr.slice(4, 16, "GUID")),
      age: rr.u32(20, "age"),
      pdbName: Buffer.from(nameBytes.subarray(0, end)).toString("utf8"),
    });
  }
  if (found.length !== 1) {
    throw new Failure(`${what}: записей CodeView ${found.length}, нужна одна`);
  }
  return found[0] as CodeView;
}

/**
 * A PDB's GUID and ages: the MSF 7.00 superblock, the stream directory through its block map, then
 * the info stream (1: version, signature, age, GUID) and the DBI stream's header (3: age at 8).
 */
export function readPdbIdentity(bytes: Uint8Array, what: string): PdbIdentity {
  const r = new Reader(bytes, what);
  if (bytes.length < 56 || !Buffer.from(bytes.subarray(0, 32)).equals(MSF7_MAGIC)) {
    throw new Failure(`${what}: не PDB (нет заголовка MSF 7.00)`);
  }
  const bs = r.u32(32, "BlockSize");
  if (![512, 1024, 2048, 4096].includes(bs)) {
    throw new Failure(`${what}: размер блока ${bs} — не PDB`);
  }
  const numBlocks = r.u32(40, "NumBlocks");
  if (numBlocks * bs > bytes.length) {
    throw new Failure(`${what}: обрезан (${numBlocks} блоков по ${bs}, файл ${bytes.length} байт)`);
  }
  const dirBytes = r.u32(44, "NumDirectoryBytes");
  const mapBlock = r.u32(52, "BlockMapAddr");
  const dirBlocks = Math.ceil(dirBytes / bs);
  if (dirBlocks * 4 > bs) throw new Failure(`${what}: каталог потоков больше одного блока карты`);
  const block = (index: number, field: string): Uint8Array => {
    if (index >= numBlocks) throw new Failure(`${what}: ${field}: блок ${index} из ${numBlocks}`);
    return r.slice(index * bs, bs, field);
  };
  const dirParts: Uint8Array[] = [];
  for (let i = 0; i < dirBlocks; i++) {
    dirParts.push(block(r.u32(mapBlock * bs + i * 4, "карта каталога"), "каталог потоков"));
  }
  const dir = new Reader(Buffer.concat(dirParts).subarray(0, dirBytes), `${what}, каталог потоков`);
  const numStreams = dir.u32(0, "NumStreams");
  const sizes: number[] = [];
  for (let i = 0; i < numStreams; i++) {
    const s = dir.u32(4 + i * 4, "StreamSizes");
    sizes.push(s === 0xffffffff ? 0 : s);
  }
  let at = 4 + numStreams * 4;
  const streamBlocks: number[][] = [];
  for (const size of sizes) {
    const n = Math.ceil(size / bs);
    const list: number[] = [];
    for (let i = 0; i < n; i++) list.push(dir.u32(at + i * 4, "блоки потока"));
    at += n * 4;
    streamBlocks.push(list);
  }
  const stream = (index: number, len: number, field: string): Reader | null => {
    const size = sizes[index] ?? 0;
    if (size < len) return null;
    const parts = (streamBlocks[index] ?? []).map((b) => block(b, field));
    return new Reader(Buffer.concat(parts).subarray(0, size), `${what}, ${field}`);
  };
  const info = stream(1, 28, "поток сведений");
  if (info === null) throw new Failure(`${what}: нет потока сведений PDB (1)`);
  const dbi = stream(3, 12, "поток DBI");
  const dbiAge = dbi !== null && dbi.i32(0, "VersionSignature") === -1 ? dbi.u32(8, "Age") : null;
  return {
    guid: formatGuid(info.slice(12, 16, "GUID")),
    age: info.u32(8, "Age"),
    dbiAge,
  };
}

/**
 * Refuse a PDB that is not the exe's: another GUID, or another age (the DBI stream's, as debuggers
 * compare it; the info stream's when there is no DBI). Returns what was compared, for the log.
 */
export function assertPdbMatches(
  cv: CodeView,
  pdb: PdbIdentity,
  exe: string,
  file: string,
): string {
  const pdbAge = pdb.dbiAge ?? pdb.age;
  if (cv.guid !== pdb.guid || cv.age !== pdbAge) {
    throw new Failure(
      `${file} — не PDB этого exe: в ${exe} GUID ${cv.guid}, age ${cv.age}; в PDB GUID ${pdb.guid}, ` +
        `age ${pdbAge}${pdb.dbiAge === null ? " (сведения)" : " (DBI)"}. Символы чужой сборки ` +
        "назовут не те функции: релиз не собирается",
    );
  }
  return `GUID ${cv.guid}, age ${cv.age}${pdb.dbiAge !== null && pdb.dbiAge !== pdb.age ? ` (age сведений PDB ${pdb.age})` : ""}`;
}

/** One module of the release and its PDB, as `symbols.json` records them. */
export interface ModuleSymbols {
  module: string;
  /** The published exe this module is inside (the helper), or `null` for the published exe itself. */
  embedded_in: string | null;
  exe: { name: string; sha256: string; size: number };
  codeview: { guid: string; age: number; pdb_name: string };
  pdb: {
    file: string;
    sha256: string;
    size: number;
    guid: string;
    age: number;
    dbi_age: number | null;
  };
  /** Where a symbol server would keep it (`symbolKey`). */
  symbol_key: string;
}

export interface SymbolsManifest {
  schema: 1;
  version: string;
  channel: string;
  commit: string;
  built_at: string;
  exe: { name: string; sha256: string; size: number };
  modules: ModuleSymbols[];
}

/**
 * The game helper inside `appBytes`: among build.rs's outputs under `profileDir/build/afklink-app-*`
 * (`out/game-helper-build/<triple>/<profile>/afklink-game-helper.exe`), the one whose bytes the app
 * exe contains. Old build directories may hold other helpers; exactly one distinct helper must be
 * the embedded one.
 */
export function findEmbeddedHelper(
  profileDir: string,
  appBytes: Buffer,
  tag: string,
): { exe: string; bytes: Buffer } {
  const profile = basename(profileDir);
  const build = join(profileDir, "build");
  const candidates: string[] = [];
  const list = (dir: string): string[] => {
    try {
      return readdirSync(dir);
    } catch (err) {
      console.log(`[${tag}] символы: ${shown(dir)} не прочитан (${(err as Error).message})`);
      return [];
    }
  };
  for (const unit of list(build).filter((n) => n.startsWith("afklink-app-"))) {
    const helperBuild = join(build, unit, "out", "game-helper-build");
    if (!existsSync(helperBuild)) {
      console.log(`[${tag}] символы: ${unit} пропущен — нет out\\game-helper-build`);
      continue;
    }
    for (const triple of list(helperBuild)) {
      const exe = join(helperBuild, triple, profile, HELPER_EXE);
      if (existsSync(exe)) {
        candidates.push(exe);
      } else {
        console.log(
          `[${tag}] символы: ${unit}\\${triple} пропущен — нет ${profile}\\${HELPER_EXE}`,
        );
      }
    }
  }
  console.log(
    `[${tag}] символы: помощник игр — кандидатов в ${shown(build)}: ${candidates.length}`,
  );
  const matched = new Map<string, { exe: string; bytes: Buffer }>();
  for (const exe of candidates) {
    const bytes = readFileSync(exe);
    const hash = sha256Hex(bytes);
    const inside = appBytes.indexOf(bytes) !== -1;
    console.log(
      `[${tag}]   ${shown(exe)}: ${bytes.length} байт, SHA-256 ${hash.slice(0, 16)}…, ` +
        (inside ? "вшит в exe" : "не тот, что вшит"),
    );
    if (inside && !matched.has(hash)) matched.set(hash, { exe, bytes });
  }
  if (matched.size !== 1) {
    throw new Failure(
      matched.size === 0
        ? `ни один помощник игр из ${shown(build)} не совпал с вшитым в exe: его PDB не найти`
        : `с вшитым в exe совпали ${matched.size} разных помощника игр — так не бывает`,
    );
  }
  const only = [...matched.values()][0] as { exe: string; bytes: Buffer };
  // build.rs also compiles the helper's SHA-256 into the app (`HELPER_SHA256`): the same helper.
  const hash = sha256Hex(only.bytes);
  if (!appBytes.includes(Buffer.from(hash, "utf8"))) {
    throw new Failure(`в exe нет SHA-256 вшитого помощника игр ${hash}: сборка не та`);
  }
  console.log(`[${tag}] символы: вшитый помощник игр — ${shown(only.exe)}, SHA-256 ${hash}`);
  return only;
}

/** One exe and the PDB beside it, checked to belong together. */
function moduleSymbols(
  name: string,
  bytes: Buffer,
  pdbDir: string,
  embeddedIn: string | null,
  tag: string,
): { entry: ModuleSymbols; pdbPath: string } {
  const cv = readCodeView(bytes, name);
  // `/PDBALTPATH:%_PDB%` leaves the file name alone; anything with a separator (or a drive) is the
  // build machine's path in the shipped exe: refused, never published.
  if (/[\\/:]/.test(cv.pdbName) || cv.pdbName === "." || cv.pdbName === "..") {
    throw new Failure(
      `${name} записывает PDB с путём «${cv.pdbName}», а не только имя файла ` +
        "(/PDBALTPATH:%_PDB% не сработал): путь сборки в exe — релиз не собирается",
    );
  }
  const pdbFile = cv.pdbName;
  const pdbPath = join(pdbDir, pdbFile);
  console.log(
    `[${tag}] символы: ${name} — CodeView: ${cv.pdbName}, GUID ${cv.guid}, age ${cv.age}; ` +
      `ищу ${shown(pdbPath)}`,
  );
  if (!existsSync(pdbPath)) {
    throw new Failure(`нет ${shown(pdbPath)} — PDB для ${name} (GUID ${cv.guid}) не найден`);
  }
  const pdbBytes = readFileSync(pdbPath);
  const pdb = readPdbIdentity(pdbBytes, shown(pdbPath));
  console.log(
    `[${tag}] символы: ${pdbFile} — GUID ${pdb.guid}, age ${pdb.age}, DBI age ${pdb.dbiAge ?? "—"}, ` +
      `${pdbBytes.length} байт`,
  );
  const compared = assertPdbMatches(cv, pdb, name, shown(pdbPath));
  console.log(`[${tag}] символы: ${pdbFile} — PDB ${name}: ${compared}`);
  return {
    pdbPath,
    entry: {
      module: name,
      embedded_in: embeddedIn,
      exe: { name, sha256: sha256Hex(bytes), size: bytes.length },
      codeview: { guid: cv.guid, age: cv.age, pdb_name: cv.pdbName },
      pdb: {
        file: pdbFile,
        sha256: sha256Hex(pdbBytes),
        size: pdbBytes.length,
        guid: pdb.guid,
        age: pdb.age,
        dbi_age: pdb.dbiAge,
      },
      symbol_key: symbolKey(cv),
    },
  };
}

export interface CollectOptions {
  /** The exe as published (its release name): the bytes the symbols must belong to. */
  shippedExe: string;
  /** Where cargo put it: the app's PDB and the helper's build directories are beside it. */
  builtExe: string;
  /** The symbols folder; emptied and written whole. */
  outDir: string;
  version: string;
  channel: string;
  commit: string;
  builtAt: string;
  tag: string;
}

/** Copy `from` into `dir` and check the copy has the same bytes. */
function copyChecked(from: string, dir: string, sha256: string): string {
  const to = join(dir, basename(from));
  try {
    copyFileSync(from, to);
  } catch (err) {
    throw new Failure(`${shown(from)} не скопирован в ${shown(to)}: ${String(err)}`);
  }
  if (sha256Hex(readFileSync(to)) !== sha256) throw new Failure(`${shown(to)}: копия не совпала`);
  return to;
}

/**
 * The symbols of `shippedExe` into `outDir`: its PDB and the embedded game helper's (with the helper
 * exe), each checked to be the one for those bytes, and `symbols.json`. Refuses anything that does
 * not match, and an `outDir` that holds the build itself (it is emptied first).
 */
export function collectSymbols(opts: CollectOptions): SymbolsManifest {
  const { tag } = opts;
  const profileDir = dirname(opts.builtExe);
  if (isWithin(opts.outDir, profileDir) || isWithin(opts.outDir, dirname(opts.shippedExe))) {
    throw new Failure(`папка символов ${shown(opts.outDir)} содержит сборку или релиз — не очищаю`);
  }
  console.log(`[${tag}] символы: ${shown(opts.shippedExe)} → ${shown(opts.outDir)}`);
  const appBytes = readFileSync(opts.shippedExe);
  const builtBytes = readFileSync(opts.builtExe);
  if (!appBytes.equals(builtBytes)) {
    throw new Failure(`${shown(opts.shippedExe)} не совпадает с ${shown(opts.builtExe)}`);
  }
  const appName = basename(opts.shippedExe);
  const app = moduleSymbols(appName, appBytes, profileDir, null, tag);
  const helperFound = findEmbeddedHelper(profileDir, appBytes, tag);
  const helper = moduleSymbols(
    HELPER_EXE,
    helperFound.bytes,
    dirname(helperFound.exe),
    appName,
    tag,
  );
  if (app.entry.pdb.file.toLowerCase() === helper.entry.pdb.file.toLowerCase()) {
    throw new Failure(`у exe и помощника игр один PDB по имени: ${app.entry.pdb.file}`);
  }

  if (existsSync(opts.outDir)) {
    let before: string[] = [];
    try {
      before = readdirSync(opts.outDir);
    } catch (err) {
      console.warn(`[${tag}] символы: ${shown(opts.outDir)} не прочитан: ${String(err)}`);
    }
    console.log(
      `[${tag}] символы: заменяю прежнюю ${shown(opts.outDir)} (${before.length} файлов: ` +
        `${before.join(", ") || "—"})`,
    );
  }
  rmSync(opts.outDir, { recursive: true, force: true });
  mkdirSync(opts.outDir, { recursive: true });
  copyChecked(app.pdbPath, opts.outDir, app.entry.pdb.sha256);
  copyChecked(helper.pdbPath, opts.outDir, helper.entry.pdb.sha256);
  copyChecked(helperFound.exe, opts.outDir, helper.entry.exe.sha256);
  const manifest: SymbolsManifest = {
    schema: 1,
    version: opts.version,
    channel: opts.channel,
    commit: opts.commit,
    built_at: opts.builtAt,
    exe: { ...app.entry.exe },
    modules: [app.entry, helper.entry],
  };
  const file = join(opts.outDir, SYMBOLS_MANIFEST);
  writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  const back = JSON.parse(readFileSync(file, "utf8")) as SymbolsManifest;
  if (back.exe?.sha256 !== manifest.exe.sha256 || back.modules?.length !== 2) {
    throw new Failure(`${shown(file)} не прочитался обратно`);
  }
  const listed = readdirSync(opts.outDir).sort();
  console.log(`[${tag}] символы: ${shown(opts.outDir)} — ${listed.join(", ")}`);
  return manifest;
}

/**
 * Everything a release publishes, by name: the exe, its signature, its checksum and the manifest —
 * the release folder holds these and nothing else (`assertPublishSet`), and release.yml's upload
 * names the same (a scripts test holds the two together). `manifest`: a test build's is
 * `test-latest.json` (lib/testkey.ts) — the same four, under its own names.
 */
export function releaseFiles(exe: string, manifest = "latest.json"): string[] {
  return [exe, `${exe}.sig`, `${exe}.sha256`, manifest];
}

/**
 * Refuse a published set that could carry symbols: `dir` (what CI uploads as the release artifact and
 * over SFTP) holding a folder, a `.pdb`, a symbols manifest or any file that is a PDB by its bytes;
 * `dir` and `symbolsDir` inside one another; with `expected`, any file but those. Returns the names.
 */
export function assertPublishSet(
  dir: string,
  symbolsDir: string,
  expected: readonly string[] | null,
): string[] {
  if (isWithin(dir, symbolsDir) || isWithin(symbolsDir, dir)) {
    throw new Failure(
      `папка символов ${shown(symbolsDir)} и публикуемая ${shown(dir)} вложены одна в другую`,
    );
  }
  const names: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (!entry.isFile()) {
      throw new Failure(`в публикуемой ${shown(dir)} не файл: ${entry.name} — уйдёт в артефакт`);
    }
    if (/\.pdb$/i.test(entry.name) || entry.name.toLowerCase() === SYMBOLS_MANIFEST) {
      throw new Failure(`в публикуемой ${shown(dir)} символы: ${entry.name} — их не публикуют`);
    }
    const head = Buffer.alloc(MSF7_MAGIC.length);
    const fd = openSync(path, "r");
    let got: number;
    try {
      got = readSync(fd, head, 0, head.length, 0);
    } finally {
      closeSync(fd);
    }
    if (got === head.length && head.equals(MSF7_MAGIC)) {
      throw new Failure(`в публикуемой ${shown(dir)} файл ${entry.name} — это PDB`);
    }
    names.push(entry.name);
  }
  names.sort();
  if (expected !== null) {
    const want = [...expected].sort();
    if (names.length !== want.length || names.some((n, i) => n !== want[i])) {
      throw new Failure(
        `в публикуемой ${shown(dir)} файлы ${names.join(", ")}, а должны быть только ${want.join(", ")}`,
      );
    }
  }
  return names;
}

/** Refuse published text (latest.json) that names a PDB or the symbols. */
export function assertNoSymbolRefs(text: string, what: string): void {
  const hit = /[\w.-]*\.pdb\b|symbols\.json/i.exec(text);
  if (hit !== null) throw new Failure(`${what} упоминает символы («${hit[0]}») — не публиковать`);
}
