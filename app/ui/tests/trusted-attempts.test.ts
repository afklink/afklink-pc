/**
 * Another device's attempts in «Доступ» (TrustedDevices.tsx): which press sends
 * what — one press or the owner's second step — what each answer leaves on the row, and
 * the attempt's hint. Run: `bun test ./app/ui/tests` from agent/.
 */

import { describe, expect, test } from "bun:test";
import { translator } from "@afklink/i18n/pc";

import {
  type Asking,
  type AttemptNote,
  allowAfterSecondStep,
  allowGivesOwner,
  allowNoteKind,
  allowPress,
  allowWaiting,
  attemptAllowOffered,
  attemptDevice,
  attemptKeyShort,
  attemptNoteSaid,
  attemptSpan,
  commandFor,
  failurePlan,
  followList,
  homeAccessLine,
  modeBlocked,
  modeNeeds,
  ownerMissingStep,
  questionAfter,
  questionHold,
  reviewAgain,
  reviewOf,
} from "../src/components/TrustedDevices";
import type { TrustedAttemptDto, TrustedDeviceDto, TrustedDto } from "../src/tauri";

const ru = translator("ru");

const KEY = "B".repeat(43);
const NOW = new Date(2026, 10, 15, 12, 0).getTime();

const attempt: TrustedAttemptDto = {
  at: NOW - 30 * 60_000,
  kind: "browser",
  platform: "android",
  key_id: KEY,
  key_short: "BBBBBBBB",
  count: 3,
  first_at: NOW - 5 * 86_400_000,
  last_at: NOW - 30 * 60_000,
};

/** Person 5 with the attempt, as the agent says them: the second step. */
function list(
  o: { needs?: boolean; clean?: boolean; token?: string; role?: "owner" | "guest" } = {},
): TrustedDto {
  return {
    state: "ok",
    damage: null,
    trusted_mode: true,
    people: [
      {
        telegram_user_id: 5,
        first_name: "Мирон",
        username: null,
        devices: [],
        attempts: [attempt],
        role: o.role ?? "guest",
        needs_second_step: o.needs === true,
      },
    ],
    waiting: [],
    clean: o.clean ?? true,
    token: o.token ?? "1",
    full: false,
  };
}

const allow = (
  over: Partial<Extract<Asking, { kind: "allow" }>> = {},
): Extract<Asking, { kind: "allow" }> => ({
  kind: "allow",
  userId: 5,
  user: "Мирон",
  attempt,
  keyId: KEY,
  keyShort: "BBBBBBBB",
  owner: false,
  token: "1",
  spent: false,
  recognized: false,
  waits: null,
  ...over,
});

describe("«Разрешить» on an attempt", () => {
  test("a guest the agent asks nothing more of: one press, no step", () => {
    expect(allowPress(list(), 5)).toBe("send");
    const r = commandFor(allow(), list());
    expect("command" in r && r.command).toEqual({
      command: "attempt_allow",
      userId: 5,
      keyId: KEY,
      token: "1",
      secondStep: false,
      role: "guest",
    });
  });

  test("the owner's second step: the dialog, held until its box is ticked", () => {
    const l = list({ needs: true, role: "owner" });
    expect(allowPress(l, 5)).toBe("ask");
    expect("held" in commandFor(allow({ owner: true }), l)).toBe(true);
    const r = commandFor(allow({ owner: true, recognized: true }), l);
    expect("command" in r && r.command).toEqual({
      command: "attempt_allow",
      userId: 5,
      keyId: KEY,
      token: "1",
      secondStep: true,
      role: "owner",
    });
  });

  test("a session on now, none when pressed, or `session` answered: held", () => {
    expect("held" in commandFor(allow(), list({ clean: false }))).toBe(true);
    expect("held" in commandFor(allow({ token: null }), list())).toBe(true);
    expect("held" in commandFor(allow({ spent: true }), list())).toBe(true);
  });

  test("a session that came and went since the dialog opened: held, as «Подтвердить»", () => {
    // The window is clean again but its token moved: the agent would refuse the press (tainted),
    // so the dialog shows the held line and a disabled action, the same as «Подтвердить»'s.
    const moved = list({ token: "2" });
    expect("held" in commandFor(allow(), moved)).toBe(true);
    expect(questionHold(allow(), moved)).not.toBeNull();
    expect(questionHold(allow(), moved)).toBe(
      questionHold(
        {
          kind: "confirm",
          userId: 5,
          user: "Мирон",
          device: {} as TrustedDeviceDto,
          token: "1",
          spent: false,
        },
        moved,
      ),
    );
    // The same list as the dialog opened with: sent.
    expect("command" in commandFor(allow(), list())).toBe(true);
  });

  test("«Удалить попытки» is the removal at this PC", () => {
    expect(commandFor({ kind: "attempts", userId: 5, user: "Мирон" }, list())).toEqual({
      command: { command: "remove_person", userId: 5 },
      what: "remove_person #5 (attempts only)",
    });
  });
});

describe("what an answer leaves on the row", () => {
  const note = (kind: AttemptNote["kind"], code?: AttemptNote["code"]): AttemptNote => ({
    userId: 5,
    keyId: KEY,
    device: { kind: "browser", platform: "android" },
    kind,
    ...(code ? { code } : {}),
  });

  test("one table: every answer to «Разрешить», its lines on the row", () => {
    const gone = ["app.trustedAttemptGone", "app.trustedAttemptAddDevice"];
    const tainted = ["app.trustedTaintNotTrusted", "app.trustedTaintNotTrustedAbout"];
    const cases = [
      // [answer, lines] — null: the question's own handling; []: no line, the list shows it.
      ["expired", gone],
      ["not_found", gone],
      ["tainted", tainted],
      ["session", tainted],
      ["key_other_person", ["app.trustedAttemptOtherPerson"]],
      ["write_failed", ["app.trustedSaveFailed"]],
      ["busy", ["app.trustedSaveFailed"]],
      ["refused", ["app.trustedSaveFailed"]],
      ["added", []],
      ["full", []],
      ["damaged", null],
      ["newer_version", null],
      ["slow", null],
    ] as const;
    for (const [answer, lines] of cases) {
      const kind = allowNoteKind(answer);
      if (lines === null) {
        expect(kind).toBeNull();
        continue;
      }
      if (lines.length === 0) {
        expect(kind).toBe("quiet");
        continue;
      }
      expect(kind !== null && kind !== "quiet").toBe(true);
      if (kind === null || kind === "quiet") continue;
      const said = attemptNoteSaid(ru, note(kind, kind === "failed" ? answer : undefined));
      expect(said.map((l) => l.text)).toEqual(lines.map((k) => ru(k)));
    }
  });
});

describe("an attempt's hint", () => {
  test("how many and from when to when; one day — only the latest", () => {
    expect(attemptSpan(ru, "ru", attempt, NOW)).toBe(
      `3 попытки · ${ru("app.trustedAttemptRange", { first: "10 ноября", last: "сегодня 11:30" })}`,
    );
    const once = { ...attempt, count: 1, first_at: attempt.last_at };
    expect(attemptSpan(ru, "ru", once, NOW)).toBe("1 попытка · сегодня 11:30");
  });
});

describe("a removal answered `damaged`", () => {
  test("the question closes with no line, and the list read again shows the damage", () => {
    expect(failurePlan("damaged")).toEqual({ question: "close", line: null, slow: false });
    // Nothing in the question says it went through: no line, no «Сохраняем изменение…».
    expect(failurePlan("newer_version").line).toBeNull();
    // Unlike a failure the owner can press again.
    expect(failurePlan("write_failed")).toEqual({
      question: "keep",
      line: "write_failed",
      slow: false,
    });
    expect(failurePlan("session").question).toBe("spend");
  });
});

describe("the review before the mode goes on", () => {
  const view = (owners: number[]) => ({
    names: new Map([
      [5, "Мирон"],
      [8, "Дима"],
      [9, "Вера"],
    ]),
    bound: [5, 8, 9],
    owners,
  });
  const withOwner = (): TrustedDto => {
    const l = list();
    const [p] = l.people;
    if (p === undefined) throw new Error("no person");
    const device = {
      kind: "telegram" as const,
      platform: "iphone",
      key_id: "D".repeat(43),
      key_short: "DDDDDDDD",
      role: "owner" as const,
      source: "pairing" as const,
      by: null,
      by_key_id: null,
      unconfirmed: false,
      dependents: 0,
      added_at: NOW - 86_400_000,
      last_used_at: null,
      in_session: false,
    };
    return {
      ...l,
      people: [p, { telegram_user_id: 8, first_name: "Дима", username: null, devices: [device] }],
    };
  };

  test("every owner device under «Владелец», attempts apart, the bound with nothing last", () => {
    const r = reviewOf(withOwner(), view([8]));
    expect(r.owner.map((p) => p.id)).toEqual([8]);
    expect(r.guests).toEqual([]);
    expect(r.attempts.map((p) => p.id)).toEqual([5]);
    expect(r.missing).toEqual(["Мирон", "Вера"]);
  });

  test("the owner by the role of their keys too, and nothing from a damaged list", () => {
    const l = withOwner();
    const byKeys = {
      ...l,
      people: l.people.map((p) =>
        p.telegram_user_id === 8 ? { ...p, role: "owner" as const } : p,
      ),
    };
    expect(reviewOf(byKeys, view([])).owner.map((p) => p.id)).toEqual([8]);
    expect(reviewOf(withOwner(), view([])).guests.map((p) => p.id)).toEqual([8]);
    expect(reviewOf({ ...withOwner(), state: "damaged" }, view([8])).owner).toEqual([]);
  });
});

describe("the home «Доступ» line", () => {
  test("amber while the list is damaged and the mode is on (or unknown: on)", () => {
    expect(homeAccessLine(ru, { ...list(), state: "damaged" })).toEqual({
      text: ru("app.trustedHomeDamaged"),
      attention: true,
    });
    expect(homeAccessLine(ru, { ...list(), state: "damaged", trusted_mode: false }).attention).toBe(
      false,
    );
    expect(homeAccessLine(ru, list())).toEqual({ text: ru("app.trustedHomeOn"), attention: false });
  });
});

describe("what «Разрешить» gives: the core's role only", () => {
  test("an owner by the binding with no key here: the core says the owner's role, the promise shows", () => {
    const l = list({ needs: true, role: "owner" });
    expect(allowGivesOwner(l, 5)).toBe(true);
    expect(allowPress(l, 5)).toBe("ask");
    // The press names the role the dialog showed.
    const r = commandFor(allow({ owner: true, recognized: true }), l);
    expect("command" in r && r.command.command === "attempt_allow" && r.command.role).toBe("owner");
  });

  test("a working owner key here: the owner line and «Это моё устройство»", () => {
    expect(allowGivesOwner(list({ needs: true, role: "owner" }), 5)).toBe(true);
    expect(allowGivesOwner(null, 5)).toBe(false);
    expect(allowGivesOwner(list({ role: "owner" }), 6)).toBe(false);
    // An `owner` refusal stays the generic failure on the row.
    expect(allowNoteKind("owner")).toBe("failed");
  });
});

describe("an open question follows the list", () => {
  const device = {
    kind: "browser" as const,
    platform: "android",
    key_id: "C".repeat(43),
    key_short: "CCCCCCCC",
    role: "guest" as const,
    source: "pairing" as const,
    by: null,
    by_key_id: null,
    unconfirmed: true,
    dependents: 0,
    added_at: NOW - 86_400_000,
    last_used_at: null,
    in_session: false,
  };
  const confirm: Asking = {
    kind: "confirm",
    userId: 5,
    user: "Мирон",
    device,
    token: "1",
    spent: false,
  };

  test("a confirm question has nothing to follow: the very same question", () => {
    expect(followList(confirm, list({ needs: true }))).toBe(confirm);
  });

  test("another role under a ticked allow (an owner came or went): the role the list gives, unticked", () => {
    const ticked = allow({ owner: true, recognized: true });
    const demoted = followList(ticked, list({ needs: false, role: "guest" }));
    expect(demoted.kind === "allow" && !demoted.owner && !demoted.recognized).toBe(true);
    const promoted = followList(allow({ recognized: true }), list({ needs: true, role: "owner" }));
    expect(promoted.kind === "allow" && promoted.owner && !promoted.recognized).toBe(true);
    // The same role: the very same question.
    expect(followList(ticked, list({ needs: true, role: "owner" }))).toBe(ticked);
  });

  test("the same role: the very same question, its box kept", () => {
    const l = list({ needs: true, role: "owner" });
    const a = allow({ owner: true, recognized: true });
    expect(followList(a, l)).toBe(a);
    const mode: Asking = { kind: "mode", on: true, token: "1", spent: false };
    expect(followList(mode, l)).toBe(mode);
  });
});

describe("a one press answered `second_step`", () => {
  test("the box cleared, the list read again, nothing sent again", () => {
    // `run` reads the list again after every command; the plan itself sends nothing.
    expect(failurePlan("second_step")).toEqual({ question: "untick", line: null, slow: false });
    // `role`: the agent gives another role now — the same: unticked, the list read again.
    expect(failurePlan("role")).toEqual({ question: "untick", line: null, slow: false });
    const ticked = allow({ owner: true, recognized: true });
    const after = questionAfter(ticked, failurePlan("second_step"));
    expect(after).toEqual({ ...ticked, recognized: false });
    expect(questionAfter(ticked, failurePlan("session"))).toEqual({ ...ticked, spent: true });
    expect(questionAfter(ticked, failurePlan("damaged"))).toBeNull();
  });

  test("the dialog opens unticked and held until the next list, then takes its role", () => {
    const old = list();
    const a = allowAfterSecondStep(allow({ recognized: true }), old);
    expect(a.recognized).toBe(false);
    expect(allowWaiting(a, old)).toBe(true);
    // Held on the list the press was refused against, even with the box ticked.
    expect("held" in commandFor({ ...a, recognized: true }, old)).toBe(true);
    expect(followList(a, old)).toBe(a);
    // The list read again: the owner the agent asked about, still unticked, the wait over.
    const fresh = list({ needs: true, role: "owner" });
    const next = followList(a, fresh);
    expect(next.kind === "allow" && next.waits === null).toBe(true);
    if (next.kind !== "allow") return;
    expect(allowWaiting(next, fresh)).toBe(false);
    expect(next.owner).toBe(true);
    expect(next.recognized).toBe(false);
    expect("held" in commandFor(next, fresh)).toBe(true);
    const sent = commandFor({ ...next, recognized: true }, fresh);
    expect("command" in sent && sent.command.command === "attempt_allow" && sent.command.role).toBe(
      "owner",
    );
  });

  test("answered `role`: held until the next list, then the role it gives", () => {
    const old = list({ needs: true, role: "owner" });
    const a = allowAfterSecondStep(allow({ owner: true, recognized: true }), old);
    expect(allowWaiting(a, old)).toBe(true);
    const fresh = list({ needs: false, role: "guest" });
    const next = followList(a, fresh);
    expect(next.kind === "allow" && next.waits === null && !next.owner).toBe(true);
    if (next.kind !== "allow") return;
    const sent = commandFor(next, fresh);
    expect("command" in sent && sent.command.command === "attempt_allow" && sent.command.role).toBe(
      "guest",
    );
  });
});

describe("the review again after a row's question asked from it", () => {
  test("a clean window: the review with the list's token", () => {
    expect(reviewAgain(list({ token: "7" }), false)).toEqual({
      kind: "mode",
      on: true,
      token: "7",
      spent: false,
    });
    expect(reviewAgain(list({ clean: false }), false)).toEqual({
      kind: "mode",
      on: true,
      token: null,
      spent: false,
    });
  });

  test("the row's question closed as a session came: the review with no token", () => {
    const again = reviewAgain(list({ token: "7" }), true);
    expect(again).toEqual({ kind: "mode", on: true, token: null, spent: false });
    if (again === null) return;
    expect(questionHold(again, list({ token: "7" }))).not.toBeNull();
  });

  test("nothing over a damaged or unread list", () => {
    expect(reviewAgain({ ...list(), state: "damaged" }, false)).toBeNull();
    expect(reviewAgain(null, false)).toBeNull();
  });
});

describe("an attempt's key on its row", () => {
  test("the agent's first 8, else cut from the key id, none without either", () => {
    expect(attemptKeyShort(attempt)).toBe("BBBBBBBB");
    expect(attemptKeyShort({ ...attempt, key_short: undefined, key_id: "E".repeat(43) })).toBe(
      "EEEEEEEE",
    );
    expect(attemptKeyShort({ at: NOW })).toBeNull();
    expect(ru("app.trustedConfirmKey", { key: "BBBBBBBB" })).toContain("BBBBBBBB");
  });
});

describe("the switch, as the agent reads the owner's own device", () => {
  test("offered when ready, on already, or an older agent; otherwise what to do", () => {
    expect(modeNeeds({ ...list(), trusted_mode: false, owner_device: "ready" })).toBeNull();
    expect(modeNeeds({ ...list(), trusted_mode: false })).toBeNull();
    expect(modeNeeds({ ...list(), trusted_mode: false, owner_device: "needs_device" })).toBe(
      "app.trustedOnNeedOwnDevice",
    );
    expect(modeNeeds({ ...list(), trusted_mode: false, owner_device: "needs_confirm" })).toBe(
      "app.trustedOnConfirmOwnDevice",
    );
    // Turning it off is never held.
    expect(modeNeeds({ ...list(), trusted_mode: true, owner_device: "needs_device" })).toBeNull();
  });

  test("the enable dialog's step under «Включить нельзя», by the agent's reading", () => {
    expect(ownerMissingStep({ ...list(), owner_device: "needs_confirm" })).toBe(
      "app.trustedOnConfirmOwnDeviceShort",
    );
    expect(ownerMissingStep({ ...list(), owner_device: "needs_device" })).toBe(
      "app.trustedOnNeedOwnDeviceShort",
    );
    expect(ownerMissingStep(null)).toBe("app.trustedOnNeedOwnDeviceShort");
  });

  test("the review names the owner without a device with the others who will not connect", () => {
    const l = list();
    const r = reviewOf(l, {
      names: new Map([
        [5, "Мирон"],
        [8, "Дима"],
        [9, "Вера"],
      ]),
      bound: [5, 8, 9],
      owners: [8],
    });
    expect(r.missing).toEqual(["Мирон", "Дима", "Вера"]);
  });

  test("«Включить» waits only while no confirmed owner device is here, whoever has none", () => {
    const off = (owner_device: "ready" | "needs_device" | "needs_confirm"): TrustedDto => ({
      ...list(),
      trusted_mode: false,
      owner_device,
    });
    expect(modeBlocked(off("ready"))).toBe(false);
    expect(modeBlocked(off("needs_device"))).toBe(true);
    expect(modeBlocked(off("needs_confirm"))).toBe(true);
    expect(modeBlocked(null)).toBe(false);
  });
});

describe("an attempt's «Разрешить» over a full list", () => {
  test("is not offered while the list is full, nor for another person's device", () => {
    expect(attemptAllowOffered(undefined, false)).toBe(true);
    expect(attemptAllowOffered(undefined, true)).toBe(false);
    const other: AttemptNote = {
      userId: 5,
      keyId: KEY,
      device: attemptDevice(attempt),
      kind: "other_person",
    };
    expect(attemptAllowOffered(other, false)).toBe(false);
  });
});
