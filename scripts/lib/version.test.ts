import { describe, expect, test } from "bun:test";
import { compareVersions, parseVersion, targetVersion } from "./version";

describe("parseVersion", () => {
  test("plain MAJOR.MINOR.PATCH only", () => {
    expect(parseVersion("0.1.0")).toEqual({ major: 0, minor: 1, patch: 0 });
    expect(parseVersion("10.20.30")).toEqual({ major: 10, minor: 20, patch: 30 });
    for (const bad of [
      "",
      "1.2",
      "1.2.3.4",
      "v1.2.3",
      "01.2.3",
      "1.2.3-rc.1",
      "1.2.3+42",
      " 1.2.3",
    ]) {
      expect(parseVersion(bad)).toBeNull();
    }
  });
});

describe("compareVersions", () => {
  test("orders by major, then minor, then patch", () => {
    const v = (s: string) => parseVersion(s) ?? { major: -1, minor: -1, patch: -1 };
    expect(compareVersions(v("0.1.0"), v("0.1.0"))).toBe(0);
    expect(compareVersions(v("0.1.1"), v("0.1.0"))).toBeGreaterThan(0);
    expect(compareVersions(v("0.2.0"), v("0.1.9"))).toBeGreaterThan(0);
    expect(compareVersions(v("1.0.0"), v("0.99.99"))).toBeGreaterThan(0);
    expect(compareVersions(v("0.9.0"), v("0.10.0"))).toBeLessThan(0);
  });
});

describe("targetVersion", () => {
  test("bumps", () => {
    expect(targetVersion("0.1.0", "patch")).toBe("0.1.1");
    expect(targetVersion("0.1.7", "minor")).toBe("0.2.0");
    expect(targetVersion("0.4.2", "major")).toBe("1.0.0");
  });

  test("an explicit version is taken as it is, a leading v forgiven", () => {
    expect(targetVersion("0.1.0", "0.1.0")).toBe("0.1.0");
    expect(targetVersion("0.1.0", "v0.3.0")).toBe("0.3.0");
    // Older than current is a version all the same; refusing it is the caller's call.
    expect(targetVersion("0.2.0", "0.1.0")).toBe("0.1.0");
  });

  test("anything else is refused", () => {
    expect(() => targetVersion("0.1.0", "next")).toThrow();
    expect(() => targetVersion("0.1.0", "0.1")).toThrow();
    expect(() => targetVersion("0.1", "patch")).toThrow();
  });
});
