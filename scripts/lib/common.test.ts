import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  AGENT,
  assertTargetInCheckout,
  buildEnv,
  DOWNLOAD_BASE_URL,
  isWithin,
  PROD_SERVER_URL,
  run,
  runVisible,
  SIGNING_ENV_VARS,
  targetDir,
} from "./common";

// The release step in CI holds the updater's signing key; the tools spawned before the build (git,
// cargo metadata, rustc -vV, cargo tauri --version, the downloaded nasm.exe) must not see it. Only
// `signer sign` is handed it, with an explicit env.
describe("spawned tools never get the signing secrets unless handed them", () => {
  // A child that exits 0 only when none of SIGNING_ENV_VARS is in its environment.
  const probe = [
    process.execPath,
    "-e",
    `process.exit(${JSON.stringify(SIGNING_ENV_VARS)}.some((n) => process.env[n] !== undefined) ? 3 : 0)`,
  ];
  const saved = new Map(SIGNING_ENV_VARS.map((n) => [n, process.env[n]]));
  const plant = () => {
    for (const n of SIGNING_ENV_VARS) process.env[n] = `planted-${n}`;
  };
  const restore = () => {
    for (const [n, v] of saved) {
      if (v === undefined) delete process.env[n];
      else process.env[n] = v;
    }
  };

  test("run and runVisible by default, and buildEnv", async () => {
    plant();
    try {
      expect(run(probe)?.code).toBe(0);
      expect(await runVisible(probe)).toBe(0);
      for (const n of SIGNING_ENV_VARS) expect(buildEnv({})[n]).toBeUndefined();
      // The signer's way: an explicit env does carry what it is given.
      expect(run(probe, AGENT, buildEnv({ TAURI_SIGNING_PRIVATE_KEY: "k" }))?.code).toBe(3);
    } finally {
      restore();
    }
  });

  test("assertNasm's own spawn leaves them out; nothing in scripts passes process.env to a spawn", () => {
    const toolchain = readFileSync(join(AGENT, "scripts", "lib", "toolchain.ts"), "utf8");
    expect(toolchain).toContain("(cmd) => run(cmd, AGENT, buildEnv({}))");
    for (const file of ["lib/common.ts", "lib/toolchain.ts", "portable.ts"]) {
      const text = readFileSync(join(AGENT, "scripts", file), "utf8");
      expect(text).not.toMatch(/\brun(?:Visible)?\([^)]*process\.env\b/);
      expect(text).not.toMatch(/Bun\.spawn(?:Sync)?\(\{[^}]*env:\s*process\.env/);
    }
  });
});

/** A checkout that need not exist: the path checks below never touch the disk for it. */
const CHECKOUT = resolve("/work/afklink/agent");

// The domain move: builds are stamped with the agents' own host, and the release's publish job
// checks latest.json against the same address (its URL is DOWNLOAD_BASE_URL + the exe).
describe("the server and download addresses", () => {
  test("builds point at api.afklink.app, the socket and the downloads alike", () => {
    expect(PROD_SERVER_URL).toBe("wss://api.afklink.app/ws/agent");
    expect(DOWNLOAD_BASE_URL).toBe("https://api.afklink.app/download/");
    expect(new URL(DOWNLOAD_BASE_URL).host).toBe(new URL(PROD_SERVER_URL).host);
  });

  test("the agent's own constants say the same: the config migration's target, the updater's endpoint", () => {
    const rustConst = (file: string, name: string) =>
      new RegExp(`^\\s*pub(?:\\(crate\\))? const ${name}: &str = "([^"]+)";$`, "m").exec(
        readFileSync(join(AGENT, file), "utf8"),
      )?.[1];
    expect(rustConst(join("crates", "core", "src", "config.rs"), "PROD_SERVER_URL")).toBe(
      PROD_SERVER_URL,
    );
    expect(rustConst(join("app", "src-tauri", "src", "updater.rs"), "ENDPOINT")).toBe(
      `${DOWNLOAD_BASE_URL}latest.json`,
    );
  });
});

describe("targetDir", () => {
  test("no variable: the checkout's own target/", () => {
    expect(targetDir({}, CHECKOUT)).toEqual({
      dir: join(CHECKOUT, "target"),
      from: null,
      raw: null,
    });
  });

  test("a relative value is relative to app/src-tauri, where cargo tauri build runs", () => {
    const t = targetDir({ CARGO_TARGET_DIR: "../../target-alt" }, CHECKOUT);
    expect(t).toEqual({
      dir: join(CHECKOUT, "target-alt"),
      from: "CARGO_TARGET_DIR",
      raw: "../../target-alt",
    });
  });

  test("CARGO_TARGET_DIR wins over CARGO_BUILD_TARGET_DIR; blank counts as unset", () => {
    const both = { CARGO_TARGET_DIR: "/a", CARGO_BUILD_TARGET_DIR: "/b" };
    expect(targetDir(both, CHECKOUT).from).toBe("CARGO_TARGET_DIR");
    const blank = { CARGO_TARGET_DIR: "  ", CARGO_BUILD_TARGET_DIR: "/b" };
    expect(targetDir(blank, CHECKOUT)).toMatchObject({
      dir: resolve("/b"),
      from: "CARGO_BUILD_TARGET_DIR",
    });
  });
});

describe("isWithin", () => {
  test("the directory itself and anything under it", () => {
    expect(isWithin(CHECKOUT, CHECKOUT)).toBe(true);
    expect(isWithin(CHECKOUT, join(CHECKOUT, "target", "release"))).toBe(true);
  });

  test("a parent, a sibling, and a sibling whose name merely starts the same", () => {
    expect(isWithin(CHECKOUT, resolve(CHECKOUT, ".."))).toBe(false);
    expect(isWithin(CHECKOUT, resolve(CHECKOUT, "..", "scratch", "target"))).toBe(false);
    expect(isWithin(CHECKOUT, `${CHECKOUT}-worktree`)).toBe(false);
    // A directory named `..x` inside is still inside.
    expect(isWithin(CHECKOUT, join(CHECKOUT, "..x"))).toBe(true);
  });

  test.skipIf(process.platform !== "win32")("Windows: case does not matter, a drive does", () => {
    expect(isWithin("C:\\Work\\agent", "c:\\work\\AGENT\\target")).toBe(true);
    expect(isWithin("C:\\Work\\agent", "D:\\Work\\agent\\target")).toBe(false);
  });
});

describe("assertTargetInCheckout", () => {
  test("the default target/ and a directory inside the checkout pass", () => {
    expect(() => assertTargetInCheckout(targetDir({}, CHECKOUT), CHECKOUT)).not.toThrow();
    const inside = targetDir({ CARGO_TARGET_DIR: "../../target/wt" }, CHECKOUT);
    expect(() => assertTargetInCheckout(inside, CHECKOUT)).not.toThrow();
    // This checkout, as `bun run portable` and `release:build` see it.
    expect(() => assertTargetInCheckout(targetDir({}))).not.toThrow();
    expect(() => assertTargetInCheckout(targetDir({}), AGENT)).not.toThrow();
  });

  test("a target directory outside the checkout is refused, naming the variable", () => {
    // A worktree beside the main tree, building into the main tree's target/ — seen from
    // the worktree, a CARGO_TARGET_DIR outside it.
    const worktree = resolve(CHECKOUT, "..", "..", "wt-3ed1e21", "agent");
    const shared = targetDir({ CARGO_TARGET_DIR: join(CHECKOUT, "target") }, worktree);
    expect(() => assertTargetInCheckout(shared, worktree)).toThrow(/вне этой копии кода/);
    expect(() => assertTargetInCheckout(shared, worktree)).toThrow(
      `CARGO_TARGET_DIR=${join(CHECKOUT, "target")}`,
    );
    // Relative, climbing out of app/src-tauri and past the checkout.
    const up = targetDir({ CARGO_BUILD_TARGET_DIR: "../../../target" }, CHECKOUT);
    expect(() => assertTargetInCheckout(up, CHECKOUT)).toThrow(/CARGO_BUILD_TARGET_DIR/);
  });

  describe("links", () => {
    const root = mkdtempSync(join(tmpdir(), "afklink-target-"));
    afterAll(() => rmSync(root, { recursive: true, force: true }));
    const checkout = join(root, "agent");
    const outside = join(root, "shared-target");
    mkdirSync(join(checkout, "app", "src-tauri"), { recursive: true });
    mkdirSync(outside);

    test("target/ that is a link out of the checkout is refused", () => {
      // A junction on Windows (no rights needed), a symlink elsewhere.
      symlinkSync(outside, join(checkout, "target"), "junction");
      try {
        expect(() => assertTargetInCheckout(targetDir({}, checkout), checkout)).toThrow(
          /не ссылкой/,
        );
        // And a directory not built yet under it, judged by where its parent leads.
        const nested = targetDir({ CARGO_TARGET_DIR: "../../target/nested" }, checkout);
        expect(() => assertTargetInCheckout(nested, checkout)).toThrow(/вне этой копии кода/);
      } finally {
        rmSync(join(checkout, "target"), { recursive: true, force: true });
      }
    });

    test("a directory not built yet inside a real checkout passes", () => {
      const fresh = targetDir({ CARGO_TARGET_DIR: "../../target-fresh/deep" }, checkout);
      expect(() => assertTargetInCheckout(fresh, checkout)).not.toThrow();
    });
  });
});
