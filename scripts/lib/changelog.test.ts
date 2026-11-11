import { describe, expect, test } from "bun:test";
import { promoteUnreleased, unreleasedNotes, versionNotes } from "./changelog";

const FIRST = `# Изменения AFKLink

Коротко, для пользователей.

## Не выпущено

- Первое.
- Второе.
`;

describe("unreleasedNotes", () => {
  test("the text under «Не выпущено», trimmed", () => {
    expect(unreleasedNotes(FIRST)).toBe("- Первое.\n- Второе.");
  });

  test("empty when there is nothing; an error when there is no section", () => {
    expect(unreleasedNotes("# T\n\n## Не выпущено\n\n## 0.1.0 — 2026-09-28\n\n- x\n")).toBe("");
    expect(() => unreleasedNotes("# T\n\n## 0.1.0\n\n- x\n")).toThrow();
  });

  test("CRLF reads like LF", () => {
    expect(unreleasedNotes(FIRST.replace(/\n/g, "\r\n"))).toBe("- Первое.\n- Второе.");
  });
});

describe("promoteUnreleased", () => {
  test("the first release: the text moves under the version, «Не выпущено» stays empty", () => {
    const out = promoteUnreleased(FIRST, "0.1.0", "2026-09-28");
    expect(out).toBe(`# Изменения AFKLink

Коротко, для пользователей.

## Не выпущено

## 0.1.0 — 2026-09-28

- Первое.
- Второе.
`);
    expect(unreleasedNotes(out)).toBe("");
    expect(versionNotes(out, "0.1.0")).toBe("- Первое.\n- Второе.");
  });

  test("a later release goes above the earlier ones, which stay as they were", () => {
    const released = promoteUnreleased(FIRST, "0.1.0", "2026-09-28");
    const next = released.replace("## Не выпущено\n", "## Не выпущено\n\n- Третье.\n");
    const out = promoteUnreleased(next, "0.1.1", "2026-10-02");
    expect(out).toBe(`# Изменения AFKLink

Коротко, для пользователей.

## Не выпущено

## 0.1.1 — 2026-10-02

- Третье.

## 0.1.0 — 2026-09-28

- Первое.
- Второе.
`);
    expect(versionNotes(out, "0.1.1")).toBe("- Третье.");
    expect(versionNotes(out, "0.1.0")).toBe("- Первое.\n- Второе.");
    expect(versionNotes(out, "0.2.0")).toBeNull();
  });

  test("refuses an empty «Не выпущено» and a version already there", () => {
    const released = promoteUnreleased(FIRST, "0.1.0", "2026-09-28");
    expect(() => promoteUnreleased(released, "0.1.1", "2026-10-02")).toThrow(/пуст/);
    const again = released.replace("## Не выпущено\n", "## Не выпущено\n\n- Ещё.\n");
    expect(() => promoteUnreleased(again, "0.1.0", "2026-10-02")).toThrow(/уже есть/);
  });
});

describe("versionNotes", () => {
  test("a heading with or without a date, with an em dash or a hyphen", () => {
    expect(versionNotes("## 0.1.0\n\n- a\n", "0.1.0")).toBe("- a");
    expect(versionNotes("## 0.1.0 - 2026-09-28\n\n- a\n", "0.1.0")).toBe("- a");
    expect(versionNotes("## 0.1.0 — 2026-09-28\n\n- a\n", "0.1.0")).toBe("- a");
    // Not a prefix match: 0.1.0 is not 0.1.01 or 10.1.0.
    expect(versionNotes("## 10.1.0\n\n- a\n", "0.1.0")).toBeNull();
  });
});
