/**
 * The pairing request window's presses (PairRequestDialog.tsx): which press sends what, the
 * owner's «Это моё устройство», and that a press without the step sends nothing that allows.
 * Run: `bun test ./app/ui/tests` from agent/.
 */

import { describe, expect, test } from "bun:test";

import {
  allowOffer,
  type ConsentTick,
  consentKeyOf,
  consentTick,
  deviceLineOf,
  ownerStepShown,
  pairAllowPress,
  pairPhase,
} from "../src/components/PairRequestDialog";
import type { PendingPairDto } from "../src/tauri";

const AT = 1_731_300_000_000;

function request(over: Partial<PendingPairDto> = {}): PendingPairDto {
  return {
    request_id: "r1",
    display_name: "Вера",
    first_name: "Вера",
    username: "vera",
    telegram_user_id: 7001,
    expires_at: AT + 120_000,
    key_state: "valid",
    device: { kind: "telegram", platform: "iphone" },
    via_pc_allow: false,
    shown: 1,
    ...over,
  };
}

describe("a plain press (`pairAllowPress`)", () => {
  test("a guest: no step", () => {
    expect(pairAllowPress(request())).toEqual({ send: { secondStep: false } });
  });
});

describe("«Разрешить» only where it lets the person connect (`allowOffer`)", () => {
  test("the agent says it connects, or says nothing (an older agent): offered", () => {
    expect(allowOffer(request({ allow_gives: "connects" }))).toEqual({ kind: "allow" });
    expect(allowOffer(request())).toEqual({ kind: "allow" });
  });

  test("the same key listed for the person already: offered, and the line says it is there", () => {
    const r = request({ allow_gives: "added", device_line: "added" });
    expect(allowOffer(r)).toEqual({ kind: "allow" });
    expect(deviceLineOf(r)).toBe("added");
    expect(pairAllowPress(r)).toEqual({ send: { secondStep: false } });
  });

  test("listed but not working: strict says it waits for «Подтвердить», observe binds and says the same of the device", () => {
    expect(allowOffer(request({ allow_gives: "listed_waiting", allow_connects: false }))).toEqual({
      kind: "none",
      gives: "listed_waiting",
      fact: "app.pairListedWaiting",
      step: "app.pairListedConfirm",
    });
    const observe = request({ allow_gives: "connects", device_line: "listed_waiting" });
    expect(allowOffer(observe)).toEqual({ kind: "allow" });
    expect(deviceLineOf(observe)).toBe("listed_waiting");
  });

  test("observe, a key the list does not write: the device line says why, never «Станет доверенным»", () => {
    for (const line of ["other_person", "list_full", "list_unavailable"] as const) {
      const r = request({ allow_gives: "connects", device_line: line });
      expect(allowOffer(r)).toEqual({ kind: "allow" });
      expect(deviceLineOf(r)).toBe(line);
    }
  });

  test("one table: every answer, its fact and step; «Разрешить» exactly when it connects", () => {
    const cases = [
      // [allow_gives, allow_connects, owner_here, fact, step]
      ["connects", true, false, null, null],
      ["added", true, false, null, null],
      ["no_key", false, false, "app.pairNoKey", "app.pairNoKeyInvite"],
      ["no_key", false, true, "app.pairNoKey", "app.pairNoKeyOwner"],
      ["session", false, false, "app.pairNotTrustedSession", "app.pairNotTrustedSessionAbout"],
      ["session", false, true, "app.pairNotTrustedSession", "app.pairNotTrustedSessionAbout"],
      ["other_person", false, false, "app.trustedAttemptOtherPerson", null],
      ["list_closed", false, false, "app.pairListClosed", null],
      ["listed_waiting", false, false, "app.pairListedWaiting", "app.pairListedConfirm"],
    ] as const;
    for (const [gives, connects, owner, fact, step] of cases) {
      const r = request({ allow_gives: gives, allow_connects: connects, owner_here: owner });
      if (connects) {
        expect(allowOffer(r)).toEqual({ kind: "allow" });
        continue;
      }
      expect(allowOffer(r)).toEqual({ kind: "none", gives, fact, step });
      // Nothing can be sent for it, whatever the box says.
      expect("held" in pairAllowPress(r, true)).toBe(true);
    }
  });
});

describe("every consent is for what is on screen (`consentKeyOf`, `consentTick`)", () => {
  const owner = (over: Partial<PendingPairDto> = {}) =>
    request({
      owner_here: true,
      role: "owner",
      needs_owner_step: true,
      allow_gives: "connects",
      device_line: "trusted",
      ...over,
    });
  const ownerTicked = (r: PendingPairDto): ConsentTick => ({
    seen: consentKeyOf(r),
    ownerFor: consentKeyOf(r),
    dropped: null,
  });
  /** The owner's tick as the window would hold it after these screens, in order. */
  const after = (start: PendingPairDto, ...screens: PendingPairDto[]) =>
    screens.reduce((t, r) => consentTick(t, consentKeyOf(r)), ownerTicked(start));
  const sent = (r: PendingPairDto, t: ConsentTick) =>
    pairAllowPress(r, t.ownerFor === consentKeyOf(r));

  test("the same id cancelled and received again with another key: «Это моё устройство» is dropped", () => {
    const a = owner({ shown: 1 });
    const again = owner({ shown: 2, device: { kind: "browser", platform: "android" } });
    const t = after(a, again);
    expect(t.ownerFor).toBeNull();
    expect("held" in sent(again, t)).toBe(true);
  });

  test("A, then B, then A again: unticked", () => {
    const a = owner({ shown: 1 });
    const b = owner({ request_id: "r2", shown: 2 });
    const back = owner({ shown: 3 });
    expect("held" in sent(back, after(a, b, back))).toBe(true);
  });

  test("owner, then guest, then owner again: unticked", () => {
    const a = owner();
    const guest = request({ role: "guest", allow_gives: "connects", device_line: "trusted" });
    expect("held" in sent(a, after(a, guest, a))).toBe(true);
  });

  test("the same screen read again: the consent stays and the press goes", () => {
    const a = owner();
    const t = after(a, owner());
    expect(sent(a, t)).toEqual({ send: { secondStep: true, role: "owner" } });
  });
});

describe("the step the window is at (`pairPhase`), from the agent's reading alone", () => {
  const asks = (over: Partial<PendingPairDto> = {}) =>
    request({ asks_role: true, allow_gives: "connects", device_line: "trusted", ...over });

  test("«Кто это?» while the agent asks the role and Rust's step says it", () => {
    expect(pairPhase(asks())).toBe("consent");
    expect(pairPhase(asks({ step: "role" }))).toBe("role");
  });

  test("the requester becomes an owner on this PC at «Кто это?»: back to the consent, the owner's box there", () => {
    expect(pairPhase(asks({ step: "role" }))).toBe("role");
    const now = request({
      asks_role: false,
      step: "role",
      owner_here: true,
      role: "owner",
      needs_owner_step: true,
      allow_gives: "connects",
      device_line: "trusted",
    });
    expect(pairPhase(now)).toBe("consent");
    // The rendered controls finish it: the owner's box, then «Разрешить» with the owner's role.
    expect(ownerStepShown(now)).toBe(true);
    expect("held" in pairAllowPress(now, false)).toBe(true);
    expect(pairAllowPress(now, true)).toEqual({ send: { secondStep: true, role: "owner" } });
  });
});

describe("an owner on this PC: the owner's role with «Это моё устройство» (`owner_here`)", () => {
  const owner = (over: Partial<PendingPairDto> = {}) =>
    request({
      owner_here: true,
      role: "owner",
      needs_owner_step: true,
      allow_gives: "connects",
      ...over,
    });

  test("with a device line: the owner's line and box, «Разрешить» waits for the tick", () => {
    for (const key_state of ["valid", "was_removed"] as const) {
      for (const unconfirmed of [false, true]) {
        const r = owner({ key_state, will_be_unconfirmed: unconfirmed });
        expect(ownerStepShown(r)).toBe(true);
        expect("held" in pairAllowPress(r)).toBe(true);
        expect(pairAllowPress(r, true)).toEqual({
          send: { secondStep: true, role: "owner" },
        });
      }
    }
  });

  test("a guest, or no device line: no owner box", () => {
    expect(ownerStepShown(request({ allow_gives: "connects" }))).toBe(false);
    // Observe and no key: «Разрешить» binds, nothing to consent to; the role is still the owner's.
    const keyless = owner({ key_state: "absent", needs_owner_step: false, device_line: "no_key" });
    expect(ownerStepShown(keyless)).toBe(false);
    expect(pairAllowPress(keyless)).toEqual({
      send: { secondStep: false, role: "owner" },
    });
    // Via `pc_allow` his key is not taken: no device line, no box.
    const guestSession = owner({
      via_pc_allow: true,
      needs_owner_step: false,
      device_line: "none",
      allow_gives: "session",
      allow_connects: false,
    });
    expect(deviceLineOf(guestSession)).toBe("none");
    expect(ownerStepShown(guestSession)).toBe(false);
    // His own key listed already: nothing written, nothing to consent to.
    const added = owner({ allow_gives: "added", needs_owner_step: false, device_line: "added" });
    expect(ownerStepShown(added)).toBe(false);
    expect(pairAllowPress(added)).toEqual({ send: { secondStep: false, role: "owner" } });
  });

  test("not offered: nothing to tick, nothing sent", () => {
    for (const gives of ["no_key", "session", "other_person", "list_closed"] as const) {
      const r = owner({ allow_gives: gives, allow_connects: false });
      expect(ownerStepShown(r)).toBe(false);
      expect("held" in pairAllowPress(r, true)).toBe(true);
    }
  });
});
