/**
 * The PC's parties in the window (party spec §5.4, §6): the cards in «Доступ» and who stands under
 * them, the leave's question and its gate, the device's party mark and the journal's words.
 * Run: `bun test ./app/ui/tests` from agent/.
 */

import { describe, expect, test } from "bun:test";
import { translator } from "@afklink/i18n/pc";

import {
  type Asking,
  commandFor,
  failurePlan,
  partyName,
  questionHold,
  sourceText,
  untrustLines,
} from "../src/components/TrustedDevices";
import { eventLabel, journalRowParts, namesNobody, partyParts } from "../src/lib/journal";
import {
  alsoIn,
  around,
  cardsOf,
  delegationLine,
  devicesParty,
  leaveOffered,
  partyCards,
  partyQuestionGone,
  revokeNotes,
  revokeStaysLine,
  waitsForLeader,
} from "../src/lib/party";
import type {
  BindingDto,
  JournalEntryDto,
  TrustedDeviceDto,
  TrustedDto,
  TrustedPartyDto,
  TrustedPersonDto,
} from "../src/tauri";

const ru = translator("ru");
const en = translator("en");

const EAGLES = `${"A".repeat(21)}Q`;
const NIGHT = `${"B".repeat(21)}A`;

function party(id: string, name: string, leader: number): TrustedPartyDto {
  return {
    party_id: id,
    party: name,
    leader: { telegram_user_id: leader, first_name: "Лёха", username: "lekha" },
  };
}

function device(key: string, partyId: string | null): TrustedDeviceDto {
  return {
    kind: "telegram",
    platform: "iphone",
    key_id: key.padEnd(43, "A"),
    key_short: key.slice(0, 8),
    role: "guest",
    source: partyId ? "party" : "pairing",
    party_id: partyId,
    by: null,
    by_key_id: null,
    unconfirmed: false,
    dependents: 0,
    added_at: 1,
    last_used_at: null,
    in_session: false,
  };
}

function person(id: number, devices: TrustedDeviceDto[]): TrustedPersonDto {
  return { telegram_user_id: id, first_name: null, username: null, devices };
}

function list(over: Partial<TrustedDto> = {}): TrustedDto {
  return {
    state: "ok",
    damage: null,
    trusted_mode: true,
    people: [
      person(1, [device("own1", null)]),
      // The leader came by «Орлы»; another guest by both parties; a third by «Орлы» and on his own.
      person(7, [device("lekha1", EAGLES)]),
      person(8, [device("kolya1", EAGLES), device("kolya2", NIGHT)]),
      person(9, [device("petya1", EAGLES), device("petya2", null)]),
    ],
    waiting: [],
    clean: true,
    token: "5",
    full: false,
    parties: [party(EAGLES, "Орлы", 7), party(NIGHT, "Ночные", 8)],
    ...over,
  };
}

/** A binding as the server sends it: `via` and `parties` when it says them. */
function binding(
  id: number,
  over: Partial<Pick<BindingDto, "via" | "parties" | "role">> = {},
): BindingDto {
  return { telegram_user_id: id, username: null, first_name: null, role: "guest", ...over };
}

/**
 * The server's people: 1 the owner; 7 the leader, through «Орлы» alone; 8 through both parties
 * alone; 9 through «Орлы» with a personal reason too; 10 and 11 through «Орлы» alone with no
 * device here yet; 12 through «Ночные» alone with no device yet.
 */
function bindings(): BindingDto[] {
  return [
    binding(1, { role: "owner" }),
    binding(7, { via: "party", parties: [EAGLES] }),
    binding(8, { via: "party", parties: [EAGLES, NIGHT] }),
    binding(9, { parties: [EAGLES] }),
    binding(10, { via: "party", parties: [EAGLES] }),
    binding(11, { via: "party", parties: [EAGLES] }),
    binding(12, { via: "party", parties: [NIGHT] }),
  ];
}

describe("the party cards", () => {
  test("one card per party, its guests every person bound through it or with a device of it", () => {
    const cards = partyCards(list(), bindings());
    expect(cards.map((c) => [c.party.party, c.guests, c.entered])).toEqual([
      ["Орлы", [7, 8, 9, 10, 11], 3],
      ["Ночные", [8, 12], 1],
    ]);
    // An older server: the devices alone tell.
    expect(partyCards(list(), []).map((c) => c.guests)).toEqual([[7, 8, 9], [8]]);
  });

  test("no card: the PC in no party, an older agent, a damaged list", () => {
    expect(partyCards(list({ parties: [] }), bindings())).toEqual([]);
    const { parties: _gone, ...older } = list();
    expect(partyCards(older, bindings())).toEqual([]);
    expect(partyCards(list({ state: "damaged" }), bindings())).toEqual([]);
    expect(partyCards(null, bindings())).toEqual([]);
  });

  test("who stands under which card, and who stays in the list", () => {
    const t = list();
    const cards = partyCards(t, bindings());
    const under = (id: number, owner = false) =>
      cardsOf(
        cards,
        bindings().find((b) => b.telegram_user_id === id) ?? null,
        t.people.find((p) => p.telegram_user_id === id)?.devices ?? null,
        owner,
      );
    // Through parties alone, with devices: under its card; under both for both parties.
    expect(under(7)).toEqual([EAGLES]);
    expect(under(8)).toEqual([EAGLES, NIGHT]);
    // Through parties alone, no device here yet: under the card all the same.
    expect(under(10)).toEqual([EAGLES]);
    expect(under(12)).toEqual([NIGHT]);
    // A personal reason and a party: the list.
    expect(under(9)).toEqual([]);
    // The owner: the list.
    expect(under(1, true)).toEqual([]);
    // A party the PC is not in any more names no card: the devices tell, or the list.
    const night = partyCards(list({ parties: [party(NIGHT, "Ночные", 8)] }), bindings());
    expect(cardsOf(night, binding(7, { via: "party", parties: [EAGLES] }), [], false)).toEqual([]);
  });

  test("a server that does not say: whoever came by parties alone by the devices", () => {
    const t = list();
    const cards = partyCards(t, []);
    const of = (id: number) => t.people.find((p) => p.telegram_user_id === id)?.devices ?? null;
    const plain = (id: number) => binding(id);
    expect(cardsOf(cards, plain(7), of(7), false)).toEqual([EAGLES]);
    expect(cardsOf(cards, plain(8), of(8), false)).toEqual([EAGLES, NIGHT]);
    // A device of his own besides the party's: his row stays.
    expect(cardsOf(cards, plain(9), of(9), false)).toEqual([]);
    expect(cardsOf(cards, null, [], false)).toEqual([]);
    expect(cardsOf(cards, null, null, false)).toEqual([]);
  });

  test("the delegation line: the leader and the guests' count, or none yet", () => {
    const p = party(EAGLES, "Орлы", 7);
    expect(delegationLine(ru, "ru", p, 8)).toBe("Лидер: Лёха · 8 гостей");
    expect(delegationLine(ru, "ru", p, 3)).toBe("Лидер: Лёха · 3 гостя");
    expect(delegationLine(ru, "ru", p, 1)).toBe("Лидер: Лёха · 1 гость");
    expect(delegationLine(ru, "ru", p, 0)).toBe("Лидер: Лёха · гостей пока нет");
    expect(delegationLine(en, "en", p, 0)).toBe(`Leader: Лёха · ${en("app.partyGuestsNone")}`);
    expect(delegationLine(en, "en", p, 1)).toBe("Leader: Лёха · 1 guest");
    expect(delegationLine(en, "en", p, 2)).toBe("Leader: Лёха · 2 guests");
    const noName = { ...p, leader: { telegram_user_id: 7, first_name: null, username: null } };
    expect(delegationLine(ru, "ru", noName, 2)).toBe("Лидер: #7 · 2 гостя");
  });

  test("«также в пати» names the other parties under a card, every party in the list", () => {
    const cards = partyCards(list(), bindings());
    expect(alsoIn(ru, cards, NIGHT, 8)).toBe("также в пати «Орлы»");
    expect(alsoIn(ru, cards, EAGLES, 8)).toBe("также в пати «Ночные»");
    expect(alsoIn(ru, cards, EAGLES, 7)).toBe("");
    // A personal reason and a party: the list's row names the party.
    expect(alsoIn(ru, cards, null, 9)).toBe("также в пати «Орлы»");
    expect(alsoIn(ru, cards, null, 1)).toBe("");
  });

  test("the wait for the leader: nobody in by its grant yet, guests bound or none", () => {
    const [eagles, night] = partyCards(list(), bindings());
    if (eagles === undefined || night === undefined) throw new Error("two cards");
    // Guests bound here, none with a device of the party yet.
    const bound = { ...eagles, entered: 0 };
    expect(bound.guests.length).toBeGreaterThan(0);
    expect(waitsForLeader(bound, true)).toBe(true);
    // No guest at all.
    expect(waitsForLeader({ ...eagles, guests: [], entered: 0 }, true)).toBe(true);
    // Only while the PC lets in by key.
    expect(waitsForLeader(bound, false)).toBe(false);
    // Someone came in by the grant: the guests.
    expect(waitsForLeader(eagles, true)).toBe(false);
    expect(waitsForLeader(night, true)).toBe(false);
  });

  test("one helper cuts a sentence around its value, never the words", () => {
    expect(around(ru, "app.partyLeaveNamed", {}, "party", "Орлы")).toEqual({
      before: "Убрать ПК из пати «",
      name: "Орлы",
      after: "»",
    });
    expect(around(ru, "app.partyLeave", {}, "party", "Орлы")).toEqual({
      before: "Убрать ПК из пати",
      name: null,
      after: "",
    });
  });
});

describe("«Отвязать?» of a person a party also holds here", () => {
  const cards = partyCards(list(), bindings()).map((c) => c.party);

  test("one party: the One line with the person and the party", () => {
    expect(revokeStaysLine(ru, cards, [EAGLES], "Петя")).toBe(
      "Петя останется гостем через пати «Орлы». Убрать человека из пати может её лидер",
    );
    expect(revokeStaysLine(en, cards, [NIGHT], "Petya")).toBe(
      en("app.revokePartyStaysOne", { user: "Petya", party: "Ночные" }),
    );
  });

  test("two parties: the Many line with the person", () => {
    expect(revokeStaysLine(ru, cards, [EAGLES, NIGHT], "Петя")).toBe(
      "Петя останется гостем через пати. Убрать человека из пати могут их лидеры",
    );
  });

  test("no parties, or only ones without a card here: no line", () => {
    expect(revokeStaysLine(ru, cards, undefined, "Петя")).toBe(null);
    expect(revokeStaysLine(ru, cards, [], "Петя")).toBe(null);
    const stale = `${"C".repeat(21)}A`;
    expect(revokeStaysLine(ru, cards, [stale], "Петя")).toBe(null);
    // A stale mark beside a real one counts the real one alone.
    expect(revokeStaysLine(ru, cards, [stale, EAGLES], "Петя")).toBe(
      ru("app.revokePartyStaysOne", { user: "Петя", party: "Орлы" }),
    );
  });

  test("«Журнал»: the same line from the list's parties and the entry's binding", () => {
    // What JournalScreen passes: `TrustedDto.parties`, the binding's parties, the entry's name.
    const here = list().parties ?? [];
    const konst = binding(9, { parties: [EAGLES] });
    expect(revokeStaysLine(ru, here, konst.parties, "Константин")).toBe(
      "Константин останется гостем через пати «Орлы». Убрать человека из пати может её лидер",
    );
    // An agent whose list says no parties (an older one, a damaged list): no line.
    expect(revokeStaysLine(ru, [], konst.parties, "Константин")).toBe(null);
  });

  test("the lines over the buttons: the owner's note as before, the party line after it", () => {
    expect(revokeNotes(ru, true, null)).toEqual(["Владельцу придёт запрос в Telegram"]);
    expect(revokeNotes(ru, false, null)).toEqual([]);
    const stays = revokeStaysLine(ru, cards, [EAGLES], "Петя");
    expect(revokeNotes(ru, false, stays)).toEqual([stays]);
    expect(revokeNotes(ru, true, stays)).toEqual([ru("app.unbindOwnerNote"), stays]);
  });
});

describe("«Убрать ПК из пати»: an organ of trust", () => {
  const asking: Asking = { kind: "party", partyId: EAGLES, party: "Орлы" };

  test("offered only while no session but a confirmed owner's is on", () => {
    expect(leaveOffered(list())).toBe(true);
    expect(leaveOffered(list({ clean: false }))).toBe(false);
    expect(leaveOffered(null)).toBe(false);
  });

  test("the question sends the leave for its party; nothing else holds it", () => {
    expect(commandFor(asking, list())).toEqual({
      command: { command: "leave_party", partyId: EAGLES },
      what: `leave_party ${EAGLES.slice(0, 8)}`,
    });
    expect(questionHold(asking, list())).toBe(null);
  });

  test("the question closes once its party is gone from the list", () => {
    expect(partyQuestionGone(list(), EAGLES)).toBe(false);
    expect(partyQuestionGone(list({ parties: [party(NIGHT, "Ночные", 8)] }), EAGLES)).toBe(true);
    expect(partyQuestionGone(list({ parties: [] }), EAGLES)).toBe(true);
    const { parties: _gone, ...older } = list();
    expect(partyQuestionGone(older, EAGLES)).toBe(true);
    // No list read yet says nothing.
    expect(partyQuestionGone(null, EAGLES)).toBe(false);
  });

  test("the agent's answers: a session keeps it open with the line, gone or damaged close it", () => {
    expect(failurePlan("session")).toEqual({ question: "spend", line: "session", slow: false });
    expect(failurePlan("not_found").question).toBe("close");
    expect(failurePlan("damaged").question).toBe("close");
    expect(ru("app.trustedBusySession")).toBe(
      "Сейчас идёт сеанс. Попробуй ещё раз, когда он закончится",
    );
  });
});

describe("a party's device and the journal", () => {
  test("a member's device names its party; with the party unknown, no mark", () => {
    const parties = list().parties;
    expect(partyName(parties, EAGLES)).toBe("Орлы");
    expect(sourceText(ru, "party", null, partyName(parties, EAGLES))).toBe("Принято в пати «Орлы»");
    expect(sourceText(ru, "party", null, partyName(parties, "x"))).toBe(null);
    expect(sourceText(en, "party", undefined, "Eagles")).toBe("Accepted into “Eagles”");
  });

  test("removing a party guest's device or the person names the party in the note", () => {
    const t = list();
    const lekha = t.people.find((p) => p.telegram_user_id === 7)?.devices ?? [];
    const [d] = lekha;
    if (d === undefined) throw new Error("a device");
    const who = { userId: 7, user: "Лёха", unbind: false };
    expect(untrustLines(ru, "ru", t, who, d).lines).toEqual([
      ru("app.trustedUntrustNoteParty", {
        user: "Лёха",
        device: "Telegram на iPhone",
        party: "Орлы",
      }),
    ]);
    expect(untrustLines(ru, "ru", t, who, d).lines[0]).toContain('«Убрать ПК из пати "Орлы"»');
    // A device of his own: the guest's note, as before.
    const own = t.people.find((p) => p.telegram_user_id === 9)?.devices[1];
    if (own === undefined) throw new Error("his own device");
    expect(untrustLines(ru, "ru", t, { userId: 9, user: "Петя", unbind: true }, own).lines).toEqual(
      [
        ru("app.trustedUntrustNote", { user: "Петя", device: "Telegram на iPhone" }),
        ru("app.trustedUntrustCutOff"),
      ],
    );
    // «Удалить все устройства»: the party their devices came by, or none.
    expect(devicesParty(t, lekha)).toBe("Орлы");
    expect(devicesParty(t, t.people.find((p) => p.telegram_user_id === 1)?.devices ?? [])).toBe(
      null,
    );
    expect(ru("app.trustedRemovePersonNoteParty", { user: "Лёха", party: "Орлы" })).toContain(
      "через пати они не вернутся",
    );
  });

  function entry(over: Partial<JournalEntryDto>): JournalEntryDto {
    return {
      id: "e",
      kind: "party_added",
      telegram_user_id: 0,
      name: "",
      at_ms: 1_790_000_000_000,
      live: false,
      duration: null,
      device: null,
      ending: null,
      game_only: false,
      weak: false,
      logs: false,
      party: "Орлы",
      ...over,
    };
  }

  test("each party kind's words, the person apart so the name alone gives way", () => {
    expect(partyParts(ru, "party_added", "Орлы", "")).toEqual({
      before: "ПК добавлен в пати «Орлы»",
      name: null,
      after: "",
    });
    expect(partyParts(ru, "party_left", "Орлы", "")).toEqual({
      before: "ПК убран из пати «Орлы»",
      name: null,
      after: "",
    });
    expect(partyParts(ru, "party_leader", "Орлы", "Лёха")).toEqual({
      before: "Новый лидер пати «Орлы»: ",
      name: "Лёха",
      after: "",
    });
    expect(partyParts(ru, "party_guest", "Орлы", "Коля")).toEqual({
      before: "Новый гость: ",
      name: "Коля",
      after: "",
    });
    expect(namesNobody("party_added")).toBe(true);
    expect(namesNobody("party_left")).toBe(true);
    expect(namesNobody("party_guest")).toBe(false);
  });

  test("the main view's «Журнал» line for a party's entry", () => {
    const now = 1_790_000_000_000;
    expect(journalRowParts(ru, "ru", entry({}), now)).toEqual({
      before: "ПК добавлен в пати «Орлы»",
      name: null,
      after: "",
    });
    expect(
      journalRowParts(
        ru,
        "ru",
        entry({ kind: "party_guest", telegram_user_id: 8, name: "Коля" }),
        now,
      ),
    ).toEqual({ before: "Новый гость: ", name: "Коля", after: "" });
  });

  test("the refusal for a leader the PC does not take has its own words", () => {
    expect(eventLabel(ru, "declined_unknown", "party_leader")).toBe("Отклонено: ПК не в этой пати");
    expect(eventLabel(en, "declined_unknown", "party_leader")).toBe(
      en("app.journalDeclinedPartyLeader"),
    );
  });
});
