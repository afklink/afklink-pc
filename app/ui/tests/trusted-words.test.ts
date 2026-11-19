/**
 * The «Доступ» words for trusted devices (TrustedDevices.tsx): device names never raw, the endorsed
 * source with a gone or unknown confirming device, and the removal question in both modes.
 * Run: `bun test ./app/ui/tests` from agent/.
 */

import { describe, expect, test } from "bun:test";
import { translator } from "@afklink/i18n/pc";

import { unbindShown } from "../src/components/AccessScreen";
import {
  type Asking,
  commandFor,
  deviceActions,
  deviceName,
  platformName,
  repairPress,
  resetLines,
  sourceText,
  untrustLines,
} from "../src/components/TrustedDevices";
import type { OwnerRequestDto, TrustedDeviceDto, TrustedDto } from "../src/tauri";

const ru = translator("ru");
const en = translator("en");

function device(over: Partial<TrustedDeviceDto> = {}): TrustedDeviceDto {
  return {
    kind: "telegram",
    platform: "iphone",
    key_id: "A".repeat(43),
    key_short: "AAAAAAAA",
    role: "guest",
    source: "pairing",
    by: null,
    by_key_id: null,
    unconfirmed: false,
    dependents: 0,
    added_at: 1_731_400_000_000,
    last_used_at: null,
    in_session: false,
    ...over,
  };
}

function list(mode: boolean, devices: TrustedDeviceDto[]): TrustedDto {
  return {
    state: "ok",
    damage: null,
    trusted_mode: mode,
    people: [{ telegram_user_id: 5, first_name: "Мирон", username: null, devices }],
    waiting: [],
    clean: true,
    token: "1",
    full: false,
  };
}

describe("platformName", () => {
  test("names the listed platforms, case aside", () => {
    expect(platformName("iphone")).toBe("iPhone");
    expect(platformName("IOS")).toBe("iOS");
    expect(platformName("macos")).toBe("macOS");
    expect(platformName("windows")).toBe("Windows");
  });
  test("anything else is unknown, never raw", () => {
    for (const raw of ["unknown", "", "tizen", "constructor", "__proto__", "toString"]) {
      expect(platformName(raw)).toBeNull();
    }
  });
});

describe("deviceName", () => {
  test("a known platform", () => {
    expect(deviceName(ru, { kind: "telegram", platform: "iphone" })).toBe("Telegram на iPhone");
    expect(deviceName(en, { kind: "telegram_desktop", platform: "macos" })).toBe(
      "Telegram Desktop on macOS",
    );
    expect(deviceName(ru, { kind: "browser", platform: "android" })).toBe("Браузер на Android");
  });
  test("an unknown or unlisted platform: unknown device, a browser just «Браузер»", () => {
    for (const platform of ["unknown", "tizen", null]) {
      expect(deviceName(ru, { kind: "telegram", platform })).toBe("Неизвестное устройство");
      expect(deviceName(ru, { kind: "telegram_desktop", platform })).toBe("Неизвестное устройство");
      expect(deviceName(ru, { kind: "browser", platform })).toBe("Браузер");
      expect(deviceName(en, { kind: "browser", platform })).toBe("Browser");
    }
    expect(deviceName(ru, { kind: null, platform: "iphone" })).toBe("Неизвестное устройство");
  });
});

describe("sourceText", () => {
  test("endorsed by a device still in the list names it", () => {
    expect(sourceText(ru, "endorsed", { kind: "telegram", platform: "iphone" })).toBe(
      "Подтверждено с «Telegram на iPhone»",
    );
    expect(sourceText(ru, "endorsed", { kind: "browser", platform: "unknown" })).toBe(
      "Подтверждено с «Браузер»",
    );
  });
  test("a gone or unknown confirming device: «с другого устройства»", () => {
    expect(sourceText(ru, "endorsed", null)).toBe("Подтверждено с другого устройства");
    expect(sourceText(ru, "endorsed", { kind: "telegram", platform: "unknown" })).toBe(
      "Подтверждено с другого устройства",
    );
    expect(sourceText(en, "endorsed", { kind: null, platform: null })).toBe(
      "Confirmed from another device",
    );
  });
  test("nothing said (the journal): no line", () => {
    expect(sourceText(ru, "endorsed", undefined)).toBeNull();
  });
});

describe("untrustLines", () => {
  const root = device({ dependents: 1, in_session: true });
  const child = device({ key_id: "B".repeat(43), by_key_id: root.key_id, in_session: true });
  const miron = (unbind: boolean) => ({ userId: 5, user: "Мирон", unbind });
  const owned = (mode: boolean, devices: TrustedDeviceDto[]): TrustedDto => {
    const l = list(mode, devices);
    return { ...l, people: l.people.map((p) => ({ ...p, role: "owner" as const })) };
  };
  const sessions = [
    "Сеанс с него прервётся сразу",
    "Удалится и 1 устройство, которое добавили через это устройство",
    "Сеансы с этих устройств тоже прервутся сразу",
  ];
  test("mode on, the owner's device: the owner's note, never «Отвязать»'s line", () => {
    const { lines } = untrustLines(ru, "ru", owned(true, [root, child]), miron(true), root);
    expect(lines).toEqual([
      "«Telegram на iPhone» больше не подключится. Чтобы вернуть его, нажми «Начать привязку» на этом ПК или добавь его с другого доверенного устройства, если оно есть",
      ...sessions,
    ]);
  });
  test("mode on, a bound guest: the guest's note, then «Отвязать»'s line, then the sessions", () => {
    const { lines } = untrustLines(ru, "ru", list(true, [root, child]), miron(true), root);
    expect(lines).toEqual([
      "Мирон больше не подключится с «Telegram на iPhone». Вернуть его Мирон сможет с другого своего доверенного устройства, если оно есть",
      "Чтобы закрыть доступ совсем, нажми «Отвязать»",
      ...sessions,
    ]);
    const en1 = untrustLines(
      en,
      "en",
      list(true, [device()]),
      { ...miron(true), user: "Yolk" },
      device(),
    );
    expect(en1.lines).toEqual([
      "Yolk will no longer connect from Telegram on iPhone. They can bring it back from another trusted device, if they have one",
      "To cut them off completely, click “Unpair”",
    ]);
  });
  test("mode on, a person with devices and no binding: the guest's note alone", () => {
    const { lines } = untrustLines(ru, "ru", list(true, [device()]), miron(false), device());
    expect(lines).toEqual([
      "Мирон больше не подключится с «Telegram на iPhone». Вернуть его Мирон сможет с другого своего доверенного устройства, если оно есть",
    ]);
  });
  test("mode off: the observe note, and the session lines still (sessions end in both modes)", () => {
    for (const people of [list(false, [root, child]), owned(false, [root, child])]) {
      const { lines } = untrustLines(ru, "ru", people, miron(true), root);
      expect(lines).toEqual([
        "Пока «Доверенные устройства» выключены, Мирон сможет подключаться с «Telegram на iPhone». После включения его придётся добавить заново",
        ...sessions,
      ]);
    }
    const plain = untrustLines(
      en,
      "en",
      list(false, [device()]),
      { ...miron(false), user: "Yolk" },
      device(),
    );
    expect(plain.lines).toEqual([
      "While Trusted devices are off, Yolk can still connect from Telegram on iPhone. Once they're on, it will need to be added again",
    ]);
  });
});

describe("«Отвязать»'s line follows the row's «Отвязать» (unbindShown)", () => {
  const cutOff = "Чтобы закрыть доступ совсем, нажми «Отвязать»";
  const asked: OwnerRequestDto = {
    kind: "make_owner",
    stage: "pending",
    owner_asked: true,
    expires_at: 1_731_400_060_000,
    outcome: null,
  };
  const row = (over: Partial<Parameters<typeof unbindShown>[0]> = {}) => ({
    bound: true,
    noAccess: false,
    held: false,
    request: null,
    ...over,
  });
  /** The dialog's lines for the person's row, read through the row's own condition. */
  const linesFor = (r: Parameters<typeof unbindShown>[0], people: TrustedDto) =>
    untrustLines(ru, "ru", people, { userId: 5, user: "Мирон", unbind: unbindShown(r) }, device())
      .lines;

  test("a bound guest: the row has «Отвязать», the dialog names it", () => {
    expect(unbindShown(row())).toBe(true);
    expect(linesFor(row(), list(true, [device()]))).toContain(cutOff);
  });
  test("a bound guest with a request put to the owner: «Отменить запрос» instead, no line", () => {
    expect(unbindShown(row({ request: asked }))).toBe(false);
    expect(linesFor(row({ request: asked }), list(true, [device()]))).not.toContain(cutOff);
    // Sent but not yet put to the owner (`asked`): the row keeps «Отвязать», and so the line.
    const sent: OwnerRequestDto = { ...asked, stage: "asked", owner_asked: false };
    expect(unbindShown(row({ request: sent }))).toBe(true);
    expect(linesFor(row({ request: sent }), list(true, [device()]))).toContain(cutOff);
  });
  test("not bound (devices only): no «Отвязать», no line", () => {
    const r = row({ bound: false, noAccess: true });
    expect(unbindShown(r)).toBe(false);
    expect(linesFor(r, list(true, [device()]))).not.toContain(cutOff);
  });
  test("the owner's note and mode off never carry the line, whatever the row", () => {
    const owned: TrustedDto = {
      ...list(true, [device()]),
      people: list(true, [device()]).people.map((p) => ({ ...p, role: "owner" as const })),
    };
    expect(linesFor(row(), owned)).not.toContain(cutOff);
    expect(linesFor(row(), list(false, [device()]))).not.toContain(cutOff);
  });
});

describe("deviceActions: removal never disappears", () => {
  test("«Удалить из доверенных» on every device, «Подтвердить» on an unconfirmed one", () => {
    expect(deviceActions(device())).toEqual(["untrust"]);
    expect(deviceActions(device({ unconfirmed: true }))).toEqual(["confirm", "untrust"]);
  });
});

describe("resetLines", () => {
  test("«никто не подключится» exactly when the result is strict", () => {
    const damaged = (mode: boolean): TrustedDto => ({ ...list(mode, []), state: "damaged" });
    expect(resetLines(ru, damaged(true)).map((l) => l.attention)).toEqual([false, true]);
    expect(resetLines(ru, damaged(false)).map((l) => l.attention)).toEqual([false]);
    expect(resetLines(ru, null).map((l) => l.attention)).toEqual([false, true]);
  });
});

describe("restore and reset go only through their question", () => {
  test("pressing the damaged list's buttons: only «Повторить» runs at once", () => {
    expect(repairPress("reopen")).toBe("run");
    expect(repairPress("restore")).toBe("ask-restore");
    expect(repairPress("reset")).toBe("ask-reset");
  });

  const damaged: TrustedDto = { ...list(true, []), state: "damaged", token: "7" };
  test("«Восстановить» sends the restore with the dialog's token", () => {
    const a: Asking = { kind: "restore", token: "7", spent: false };
    expect(commandFor(a, damaged)).toEqual({
      command: { command: "repair_trusted", action: "restore", token: "7" },
      what: "repair_trusted(restore)",
    });
  });
  test("a restore is held: no token as it opened, a session since, one now, or `session` answered", () => {
    const held = (a: Asking, t: TrustedDto) => "held" in commandFor(a, t);
    expect(held({ kind: "restore", token: null, spent: false }, damaged)).toBe(true);
    expect(held({ kind: "restore", token: "6", spent: false }, damaged)).toBe(true);
    expect(held({ kind: "restore", token: "7", spent: true }, damaged)).toBe(true);
    expect(held({ kind: "restore", token: "7", spent: false }, { ...damaged, clean: false })).toBe(
      true,
    );
  });
  test("«Начать заново» sends the reset; removal is sent in both modes", () => {
    expect(commandFor({ kind: "reset" }, damaged)).toEqual({
      command: { command: "repair_trusted", action: "reset" },
      what: "repair_trusted(reset)",
    });
    for (const mode of [false, true]) {
      const d = device();
      const r = commandFor(
        { kind: "remove", userId: 5, user: "Мирон", device: d },
        list(mode, [d]),
      );
      expect(r).toEqual({
        command: { command: "remove_trusted_device", keyId: d.key_id },
        what: `remove_trusted_device #5 key ${d.key_short}`,
      });
      const p = commandFor(
        { kind: "person", userId: 7001, user: "Вера", count: 2, party: null },
        list(mode, []),
      );
      expect(p).toEqual({
        command: { command: "remove_person", userId: 7001 },
        what: "remove_person #7001",
      });
    }
  });
});

describe("«Подтвердить»: one press", () => {
  const d = device({ unconfirmed: true });
  const ask: Asking = {
    kind: "confirm",
    userId: 5,
    user: "Вера",
    device: d,
    token: "1",
    spent: false,
  };

  test("sent at once, with the window's token, attempts or not", () => {
    expect(commandFor(ask, list(true, [d]))).toEqual({
      command: { command: "confirm_trusted_device", keyId: d.key_id, token: "1" },
      what: `confirm_trusted_device #5 key ${d.key_short}`,
    });
  });
});
