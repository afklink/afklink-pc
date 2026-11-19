/**
 * The «Доверенные устройства» card at the top of «Доступ» (TrustedLayers): one row — the mode's
 * mark, title, one note in both states and switch — with no row for the Telegram account and no
 * divider; and no source of the window names the removed keys.
 * Run: `bun test ./app/ui/tests` from agent/.
 */

import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { translator } from "@afklink/i18n/pc";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { TrustedLayers } from "../src/components/TrustedDevices";
import { I18nProvider } from "../src/i18n";
import type { TrustedDto } from "../src/tauri";

// The provider sets `document.documentElement.lang`; the server render has no document.
(globalThis as { document?: unknown }).document ??= { documentElement: {} };

const en = translator("en");

function trusted(over: Partial<TrustedDto> = {}): TrustedDto {
  return {
    state: "ok",
    damage: null,
    trusted_mode: false,
    people: [],
    waiting: [],
    owner_device: "ready",
    clean: true,
    token: "1",
    full: false,
    ...over,
  };
}

function card(dto: TrustedDto): string {
  return renderToStaticMarkup(
    createElement(
      I18nProvider,
      null,
      createElement(TrustedLayers, { trusted: dto, onAskMode() {} }),
    ),
  );
}

/** The layer marks: one disc per row. */
function marks(html: string): number {
  return html.match(/aria-hidden="true" class="flex size-7/g)?.length ?? 0;
}

describe("the trusted devices card", () => {
  for (const on of [false, true]) {
    test(`holds only the trusted devices row (mode ${on ? "on" : "off"})`, () => {
      const html = card(trusted({ trusted_mode: on }));
      expect(marks(html)).toBe(1);
      expect(html.split(en("app.trustedTitle")).length - 1).toBe(1);
      // The same note in both states.
      expect(html).toContain(en("app.trustedAboutOn"));
      expect(html).toContain('role="switch"');
      // No divider: nothing stands between rows.
      expect(html).not.toMatch(/[\s"]border-t[\s"]/);
      expect(html).not.toContain("Telegram");
    });
  }

  test("the switch's place says what to do while it is not offered", () => {
    const html = card(trusted({ owner_device: "needs_device" }));
    expect(marks(html)).toBe(1);
    expect(html).toContain(en("app.trustedAboutOn"));
    expect(html).toContain(en("app.trustedOnNeedOwnDevice"));
    expect(html).not.toContain('role="switch"');
  });
});

describe("the removed keys (the account row's, the off-note)", () => {
  test("no source of the window names them", () => {
    const root = join(import.meta.dir, "../src");
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) walk(path);
        else if (/\.(ts|tsx)$/.test(name)) files.push(path);
      }
    };
    walk(root);
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      expect({
        file,
        removed: /app\.trustedBase(Title|About)|app\.trustedAboutOff/.test(text),
      }).toEqual({ file, removed: false });
    }
  });
});
