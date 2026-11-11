import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  awsLcCflags,
  cargoHome,
  encodedRustflags,
  pathTrim,
  pathTrimFlags,
  prefixHits,
} from "./paths";

const HOME = "C:\\Users\\builder\\.cargo";
const INDEX = `${HOME}\\registry\\src\\index.crates.io-1949cf8c6b5b557f`;
const CHECKOUT = "D:\\a\\afklink-agent\\afklink-agent";

describe("pathTrimFlags", () => {
  test("CARGO_HOME first, the registry's sources after it (rustc: the last match wins), then the checkout", () => {
    const t = pathTrimFlags([HOME], [INDEX], [CHECKOUT], []);
    expect(t.rustflags).toEqual([
      `--remap-path-prefix=${HOME}=cargo`,
      `--remap-path-prefix=${INDEX}=`,
      `--remap-path-prefix=${CHECKOUT}=`,
    ]);
  });

  test("cl gets a trim per prefix, ending in one separator; a path with a space is said, not passed", () => {
    const short = "C:\\Users\\builder\\CARGO~1\\registry\\src\\INDEXC~1.IO-";
    const t = pathTrimFlags(
      [HOME],
      [INDEX],
      [CHECKOUT],
      [INDEX, `${short}\\`, "C:\\Program Files\\x"],
    );
    expect(t.awsLcCflags).toEqual([`/d1trimfile:${INDEX}\\`, `/d1trimfile:${short}\\`]);
    expect(t.skipped).toEqual(["C:\\Program Files\\x"]);
  });

  test("the prefixes checked after the build: each place once", () => {
    const t = pathTrimFlags([HOME], [INDEX], [CHECKOUT], [INDEX]);
    expect(t.prefixes).toEqual([HOME, CHECKOUT, INDEX]);
  });
});

describe("cargoHome", () => {
  test("the variable when set, else ~/.cargo", () => {
    expect(cargoHome({ CARGO_HOME: HOME })).toBe(HOME);
    expect(cargoHome({ CARGO_HOME: "  " })).toMatch(/[\\/]\.cargo$/);
    expect(cargoHome({})).toMatch(/[\\/]\.cargo$/);
  });
});

describe("encodedRustflags", () => {
  const ours = ["--remap-path-prefix=a=b"];
  test("ours alone when the environment gives rustc nothing", () => {
    expect(encodedRustflags({}, ours)).toBe("--remap-path-prefix=a=b");
  });
  test("after CARGO_ENCODED_RUSTFLAGS, which wins over RUSTFLAGS as in cargo", () => {
    const env = { CARGO_ENCODED_RUSTFLAGS: "-Cfoo=1\x1f-Cbar", RUSTFLAGS: "-Cignored" };
    expect(encodedRustflags(env, ours)).toBe("-Cfoo=1\x1f-Cbar\x1f--remap-path-prefix=a=b");
  });
  test("after RUSTFLAGS, split at whitespace as cargo splits it", () => {
    expect(encodedRustflags({ RUSTFLAGS: " -Ca  -Cb " }, ours)).toBe(
      "-Ca\x1f-Cb\x1f--remap-path-prefix=a=b",
    );
  });
  test("CARGO_ENCODED_RUSTFLAGS set but empty is no flags, and RUSTFLAGS is not looked at", () => {
    expect(encodedRustflags({ CARGO_ENCODED_RUSTFLAGS: "", RUSTFLAGS: "-Cignored" }, ours)).toBe(
      "--remap-path-prefix=a=b",
    );
  });
});

describe("awsLcCflags", () => {
  const ours = ["/d1trimfile:x\\"];
  test("nothing to add: nothing set, so a plain CFLAGS keeps working", () => {
    expect(awsLcCflags({}, [])).toBeNull();
    expect(awsLcCflags({ CFLAGS: "/W3" }, [])).toBeNull();
  });
  test("alone when nothing is set", () => {
    expect(awsLcCflags({}, ours)).toEqual({
      name: "AWS_LC_SYS_CFLAGS",
      value: "/d1trimfile:x\\",
      note: null,
      warnings: [],
    });
  });
  test("after the crate's own variable, the target-specific one first", () => {
    expect(awsLcCflags({ AWS_LC_SYS_CFLAGS: "/W3" }, ours)?.value).toBe("/W3 /d1trimfile:x\\");
    const both = { AWS_LC_SYS_CFLAGS_x86_64_pc_windows_msvc: "/O1", AWS_LC_SYS_CFLAGS: "/W3" };
    expect(awsLcCflags(both, ours)).toEqual({
      name: "AWS_LC_SYS_CFLAGS_x86_64_pc_windows_msvc",
      value: "/O1 /d1trimfile:x\\",
      note: null,
      warnings: [],
    });
  });
  test("a plain CFLAGS is carried over, and said", () => {
    const r = awsLcCflags({ CFLAGS: "/W3" }, ours);
    expect(r?.name).toBe("AWS_LC_SYS_CFLAGS");
    expect(r?.value).toBe("/W3 /d1trimfile:x\\");
    expect(r?.note).toContain("CFLAGS");
  });
  test("HOST_CFLAGS outranks the plain tier: carried into AWS_LC_SYS_HOST_CFLAGS", () => {
    const r = awsLcCflags({ HOST_CFLAGS: "/W4", AWS_LC_SYS_CFLAGS: "/W3" }, ours);
    expect(r?.name).toBe("AWS_LC_SYS_HOST_CFLAGS");
    expect(r?.value).toBe("/W4 /d1trimfile:x\\");
    expect(r?.note).toContain("HOST_CFLAGS");
  });
  test("aws-lc-sys's own host variable is appended to as it stands", () => {
    const r = awsLcCflags({ AWS_LC_SYS_HOST_CFLAGS_x86_64_pc_windows_msvc: "" }, ours);
    expect(r).toEqual({
      name: "AWS_LC_SYS_HOST_CFLAGS_x86_64_pc_windows_msvc",
      value: "/d1trimfile:x\\",
      note: null,
      warnings: [],
    });
  });
  test("the dashed CFLAGS_<target> that cc reads first is warned about", () => {
    const r = awsLcCflags({ "CFLAGS_x86_64-pc-windows-msvc": "/W3" }, ours);
    expect(r?.name).toBe("AWS_LC_SYS_CFLAGS");
    expect(r?.warnings[0]).toContain("CFLAGS_x86_64-pc-windows-msvc");
  });
});

describe("pathTrim without unpacked sources", () => {
  test("index names come from registry/index; the remaps and cl trims still name registry/src", () => {
    const home = mkdtempSync(join(tmpdir(), "afk-cargo-home-"));
    try {
      const name = "index.crates.io-1949cf8c6b5b557f";
      mkdirSync(join(home, "registry", "index", name), { recursive: true });
      const said: string[] = [];
      const t = pathTrim("D:\\work\\agent", { CARGO_HOME: home }, (l) => said.push(l));
      const real = realpathSync.native(home);
      const src = join(real === home ? home : real, "registry", "src", name);
      expect(t.rustflags).toContain(`--remap-path-prefix=${src}=`);
      expect(t.awsLcCflags).toContain(`/d1trimfile:${src}\\`);
      expect(said.some((l) => l.includes("registry\\index"))).toBe(true);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  test("no registry at all: only the general remap, and said", () => {
    const home = mkdtempSync(join(tmpdir(), "afk-cargo-home-"));
    try {
      const said: string[] = [];
      const t = pathTrim("D:\\work\\agent", { CARGO_HOME: home }, (l) => said.push(l));
      expect(t.rustflags).toContain(`--remap-path-prefix=${home}=cargo`);
      expect(t.awsLcCflags).toEqual([]);
      expect(said.some((l) => l.includes("нет ни одного индекса"))).toBe(true);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});

describe("prefixHits", () => {
  test("counts UTF-8 and UTF-16LE occurrences", () => {
    const p = "C:\\Users\\builder";
    const bytes = Buffer.concat([
      Buffer.from(`x${p}\\a.rs y ${p}\\b.rs`, "utf8"),
      Buffer.from(`${p}\\c.c`, "utf16le"),
    ]);
    expect(prefixHits(bytes, [p, "nothere"])).toEqual({
      per: [
        { prefix: p, hits: 3 },
        { prefix: "nothere", hits: 0 },
      ],
      total: 3,
    });
  });

  test("a Cyrillic profile name is found as UTF-8", () => {
    const p = "C:\\Users\\Пользователь";
    const bytes = Buffer.from(`..${p}\\.cargo\\registry\\x.rs..`, "utf8");
    expect(prefixHits(bytes, [p]).total).toBe(1);
  });

  test("nesting is on a separator: C:\\Users\\Players is not inside C:\\Users\\Player", () => {
    const short = "C:\\Users\\Player";
    const long = "C:\\Users\\Players";
    const bytes = Buffer.from(`${long}\\a.rs`, "utf8");
    // `short` matches the bytes too (a plain prefix), so both count: they are different places.
    expect(prefixHits(bytes, [short, long]).total).toBe(2);
    expect(prefixHits(bytes, [short, `${short}\\.cargo`]).total).toBe(1);
  });

  test("nested prefixes are counted once in the total", () => {
    const profile = "C:\\Users\\builder";
    const home = `${profile}\\.cargo`;
    const bytes = Buffer.from(`${home}\\registry\\a.rs ${profile}\\other`, "utf8");
    const r = prefixHits(bytes, [home, profile, home]);
    expect(r.per).toEqual([
      { prefix: home, hits: 1 },
      { prefix: profile, hits: 2 },
    ]);
    expect(r.total).toBe(2);
  });
});
