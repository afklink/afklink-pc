/**
 * The journal's words for a refused connection (lib/journal.ts): the refusal's reason when the
 * window knows it, the kind's words otherwise — a reason a newer agent writes included.
 * Run: `bun test ./app/ui/tests` from agent/.
 */

import { describe, expect, test } from "bun:test";
import { translator } from "@afklink/i18n/pc";

import { eventLabel, journalRowParts } from "../src/lib/journal";
import type { JournalEntryDto } from "../src/tauri";

const ru = translator("ru");
const en = translator("en");

function refusal(over: Partial<JournalEntryDto> = {}): JournalEntryDto {
  return {
    id: "e1",
    kind: "declined_unknown",
    telegram_user_id: 7,
    name: "Вера",
    at_ms: 1_790_000_000_000,
    live: false,
    duration: null,
    device: null,
    ending: null,
    game_only: false,
    weak: false,
    logs: false,
    ...over,
  };
}

describe("a refusal's words", () => {
  test("each known reason has its own words", () => {
    expect(eventLabel(ru, "declined_unknown", "grant_stale")).toBe(
      ru("app.journalDeclinedGrantStale"),
    );
    expect(eventLabel(ru, "declined_unknown", "key_unconfirmed")).toBe(
      "Отклонено: устройство не подтверждено",
    );
    expect(eventLabel(en, "declined_unknown", "key_unconfirmed")).toBe(
      "Declined: device not confirmed",
    );
  });

  test("no reason, or one this build does not know, reads as the kind", () => {
    const unknown = ru("app.journalDeclinedUnknown");
    expect(eventLabel(ru, "declined_unknown")).toBe(unknown);
    expect(eventLabel(ru, "declined_unknown", null)).toBe(unknown);
    expect(eventLabel(ru, "declined_unknown", "a_newer_reason")).toBe(unknown);
    expect(eventLabel(ru, "declined_unknown", "toString")).toBe(unknown);
    expect(eventLabel(ru, "declined_no_key", "a_newer_reason")).toBe(
      ru("app.journalDeclinedNoKey"),
    );
  });

  test("the main view's «Журнал» line words it the same", () => {
    const parts = journalRowParts(ru, "ru", refusal({ declined_reason: "grant_stale" }), 0);
    expect(parts).toEqual({
      before: "",
      name: "Вера",
      after: ` · ${ru("app.journalDeclinedGrantStale")}`,
    });
    expect(journalRowParts(ru, "ru", refusal(), 0).after).toBe(
      ` · ${ru("app.journalDeclinedUnknown")}`,
    );
  });
});
