import { describe, expect, test } from "bun:test";
import { helperBumpVerdict, helperRevisionOf } from "./helper-revision";

describe("helperRevisionOf", () => {
  test("reads the declaration, null without one", () => {
    expect(helperRevisionOf("/// doc\npub const HELPER_REVISION: u32 = 2;\n")).toBe(2);
    expect(helperRevisionOf("pub const TASK_PRIORITY: u8 = 5;\n")).toBeNull();
  });
});

describe("helperBumpVerdict", () => {
  test("stops only on a changed helper with the same revision and no flag", () => {
    for (const helperChanged of [false, true]) {
      for (const revisionChanged of [false, true]) {
        for (const unchangedFlag of [false, true]) {
          const v = helperBumpVerdict({ helperChanged, revisionChanged, unchangedFlag });
          expect(v.ok).toBe(!helperChanged || revisionChanged || unchangedFlag);
          if (!v.ok) expect(v.line).toContain("--helper-unchanged");
        }
      }
    }
  });
});
