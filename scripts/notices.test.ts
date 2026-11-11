/**
 * The notices generator's own logic: cargo-about's JSON into notices, the window's dependency
 * closure over a node_modules made here, and the rendered file.
 */
import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  crateNotices,
  findCrate,
  licenseFiles,
  type Notice,
  npmClosure,
  packageLicenseText,
  packageNotices,
  parseAbout,
  renderNotices,
} from "./notices";

const MIT_A = "MIT License\n\nCopyright (c) A";
const MIT_B = "MIT License\n\nCopyright (c) B";

const ABOUT = JSON.stringify({
  overview: [],
  licenses: [
    {
      name: "MIT License",
      id: "MIT",
      text: `${MIT_A}\r\n`,
      used_by: [
        { crate: { name: "zeta", version: "1.0.0" } },
        { crate: { name: "afklink-core", version: "0.9.0" } },
      ],
    },
    {
      name: "MIT License",
      id: "MIT",
      text: MIT_A,
      used_by: [{ crate: { name: "alpha", version: "2.0.0" } }],
    },
    {
      name: "MIT License",
      id: "MIT",
      text: MIT_B,
      used_by: [{ krate: { name: "beta", version: "0.1.0" } }],
    },
    {
      name: "GNU Affero General Public License v3.0 only",
      id: "AGPL-3.0-only",
      text: "AGPL text",
      used_by: [{ crate: { name: "afklink-app", version: "0.9.0" } }],
    },
  ],
  crates: [
    {
      package: { name: "str0m", version: "0.24.1", manifest_path: "/r/vendor/str0m/Cargo.toml" },
      license: "MIT",
    },
    {
      package: { name: "str0m", version: "0.23.1", manifest_path: "/reg/str0m-0.23.1/Cargo.toml" },
      license: "MIT",
    },
  ],
});

describe("Rust crates", () => {
  test("one notice per text, crates merged and sorted, our own crates left out", () => {
    const ns = crateNotices(parseAbout(ABOUT), new Set(["afklink-core", "afklink-app"]));
    expect(ns.map((n) => n.usedBy)).toEqual([["alpha 2.0.0", "zeta 1.0.0"], ["beta 0.1.0"]]);
    expect(ns[0]?.text).toBe(MIT_A);
    expect(ns.some((n) => n.license === "AGPL-3.0-only")).toBe(false);
  });

  test("a crate by name and folder", () => {
    const about = parseAbout(ABOUT);
    expect(findCrate(about, "str0m", "/r/vendor/str0m")?.version).toBe("0.24.1");
    expect(findCrate(about, "str0m")?.version).toBe("0.24.1");
    expect(findCrate(about, "nope")).toBeNull();
  });

  test("not cargo-about's output, or a license without text, is refused", () => {
    expect(() => parseAbout("{")).toThrow(/not JSON/);
    expect(() => parseAbout("{}")).toThrow(/no `licenses`/);
    const empty = parseAbout(
      JSON.stringify({
        licenses: [{ id: "MIT", text: "", used_by: [{ crate: { name: "x", version: "1" } }] }],
        crates: [],
      }),
    );
    expect(() => crateNotices(empty, new Set())).toThrow(/no text/);
  });
});

describe("the window's packages", () => {
  const root = mkdtempSync(join(tmpdir(), "notices-test-"));
  afterAll(() => rmSync(root, { recursive: true, force: true }));
  const pkg = (dir: string, json: object, license?: string) => {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify(json));
    if (license !== undefined) writeFileSync(join(dir, "LICENSE"), license);
  };
  // root/ui is ours (a workspace package); root/node_modules is hoisted, plus an isolated store
  // reached through a link, as bun lays it out.
  const ui = join(root, "ui");
  pkg(ui, {
    name: "ui",
    dependencies: { a: "^1", "@s/b": "^2", ours: "workspace:*" },
    optionalDependencies: { gone: "^1" },
    devDependencies: { tool: "^1" },
  });
  pkg(
    join(root, "node_modules", "a"),
    { name: "a", version: "1.0.0", license: "MIT", dependencies: { c: "^1" } },
    MIT_A,
  );
  pkg(
    join(root, "node_modules", "@s", "b"),
    { name: "@s/b", version: "2.0.0", license: "ISC" },
    "ISC text",
  );
  pkg(join(root, "node_modules", "c"), { name: "c", version: "1.1.0", license: "MIT" }, MIT_A);
  pkg(
    join(root, "node_modules", "tool"),
    { name: "tool", version: "9.0.0", license: "MIT" },
    MIT_B,
  );
  const ours = join(root, "packages", "ours");
  pkg(ours, { name: "ours", dependencies: { d: "^1" } });
  pkg(
    join(root, "node_modules", ".store", "d@1", "node_modules", "d"),
    { name: "d", version: "1.0.0", license: { type: "BSD-3-Clause" } },
    "BSD text",
  );
  mkdirSync(join(ui, "node_modules"), { recursive: true });
  symlinkSync(ours, join(ui, "node_modules", "ours"));
  mkdirSync(join(ours, "node_modules"), { recursive: true });
  symlinkSync(
    join(root, "node_modules", ".store", "d@1", "node_modules", "d"),
    join(ours, "node_modules", "d"),
  );

  test("production dependencies and theirs; not dev ones, not ours, missing optional skipped", () => {
    const names = npmClosure(ui).map((p) => `${p.name} ${p.version} ${p.license}`);
    expect(names).toEqual(["@s/b 2.0.0 ISC", "a 1.0.0 MIT", "c 1.1.0 MIT", "d 1.0.0 BSD-3-Clause"]);
  });

  test("a missing required dependency stops it", () => {
    const broken = join(root, "broken");
    pkg(broken, { name: "broken", dependencies: { missing: "^1" } });
    expect(() => npmClosure(broken)).toThrow(/missing, a dependency of broken, is not installed/);
  });

  test("license files by name, a package without one refused, a cut applied", () => {
    const dir = join(root, "lic");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "LICENSE.md"), "Core\n\n# Licenses of bundled dependencies\nlots");
    writeFileSync(join(dir, "license-extra"), "x");
    writeFileSync(join(dir, "LICENSES.txt"), "not matched");
    writeFileSync(join(dir, "README.md"), "no");
    expect(licenseFiles(dir).map((f) => f.slice(dir.length + 1))).toEqual([
      "LICENSE.md",
      "license-extra",
    ]);
    const p = { name: "v", version: "1", license: "MIT", dir };
    expect(packageLicenseText(p, /^#+\s*Licenses of bundled dependencies/m)).toBe("Core");
    const none = join(root, "none");
    mkdirSync(none, { recursive: true });
    expect(() => packageLicenseText({ ...p, dir: none })).toThrow(/no LICENSE file/);
  });

  test("packages with the same text share one notice", () => {
    const ns = packageNotices(npmClosure(ui).map((p) => ({ pkg: p, text: packageLicenseText(p) })));
    expect(ns.map((n) => n.usedBy)).toEqual([["@s/b 2.0.0"], ["a 1.0.0", "c 1.1.0"], ["d 1.0.0"]]);
  });
});

describe("the file", () => {
  test("sections in order, entries with who uses them, LF and no trailing blanks", () => {
    const bundled: Notice[] = [
      {
        title: "OpenH264 2.6.0",
        license: "BSD-2-Clause",
        usedBy: [],
        note: "The encoder.",
        text: "BSD  \ntext",
      },
    ];
    const crates: Notice[] = [
      { title: "MIT License", license: "MIT", usedBy: ["a 1", "b 2"], text: MIT_A },
    ];
    const text = renderNotices("1.2.3", bundled, crates, []);
    expect(text.startsWith("THIRD-PARTY NOTICES: AFKLink for Windows 1.2.3\n")).toBe(true);
    expect(text).toContain(
      "1. Bundled components\n2. Rust crates (2), as built for x86_64-pc-windows-msvc\n3. JavaScript packages of the window (0)",
    );
    expect(text).toContain("OpenH264 2.6.0\nLicense: BSD-2-Clause\nThe encoder.\n\nBSD\ntext\n");
    expect(text).toContain("License: MIT\nUsed by:\n  a 1\n  b 2\n\nMIT License");
    expect(text).not.toMatch(/[ \t]$/m);
    expect(text).not.toContain("\r");
    expect(text.endsWith("\n")).toBe(true);
    expect(renderNotices("1.2.3", bundled, crates, [])).toBe(text);
  });
});
