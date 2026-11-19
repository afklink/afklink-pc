import { type Locale, pluralRu, type TranslationKey, type Translator } from "@afklink/i18n/pc";

import type { BindingDto, TrustedDeviceDto, TrustedDto, TrustedPartyDto } from "../tauri";

/**
 * The parties in «Доступ» (party spec §3.1, process §6): a card per party the PC is in. The server
 * says who is a guest here through which party (`BindingDto.parties`) and whose binding lives through
 * parties alone (`via: "party"`); the trusted list says whose device a party's leader let in
 * (`TrustedDeviceDto.party_id`). A server that does not say leaves the devices alone to tell.
 *
 * Who stands where: a person bound through parties alone stands under the card of each of those
 * parties (with their devices, or a plain row while they have none) and not in the list; anyone with
 * a personal reason stays in the list, with «также в пати "…"» when they are in a party too.
 */

/** A party's card. */
export interface PartyCard {
  party: TrustedPartyDto;
  /** Telegram ids of the party's guests on this PC: bound through it, or with a device it let in. */
  guests: number[];
  /** How many of them have a device this party's leader let in here. */
  entered: number;
}

/** The PC's parties, each with its guests; none from an older agent or a damaged list. */
export function partyCards(
  trusted: TrustedDto | null,
  bindings: readonly BindingDto[],
): PartyCard[] {
  if (trusted === null || trusted.state === "damaged") return [];
  return (trusted.parties ?? []).map((party) => {
    const id = party.party_id;
    const entered = trusted.people
      .filter((p) => p.devices.some((d) => d.party_id === id))
      .map((p) => p.telegram_user_id);
    const bound = bindings
      .filter((b) => b.role !== "owner" && (b.parties ?? []).includes(id))
      .map((b) => b.telegram_user_id);
    return { party, guests: [...new Set([...bound, ...entered])], entered: entered.length };
  });
}

/**
 * The cards a person stands under rather than in the list (ids, in the cards' order); empty: they
 * stay in the list. `binding` is theirs (null: none); `devices` theirs in the trusted list.
 *
 * - The owner, and anyone the server names with a personal reason (no `via`, some `parties`): the
 *   list.
 * - `via: "party"`: under each card of their parties (with or without devices).
 * - The server does not say (an older one, or no binding): under the cards of their devices when
 *   every device of theirs came by a party the PC is in.
 */
export function cardsOf(
  cards: readonly PartyCard[],
  binding: BindingDto | null,
  devices: readonly TrustedDeviceDto[] | null,
  owner: boolean,
): string[] {
  if (owner) return [];
  const ids = cards.map((c) => c.party.party_id);
  const parties = binding?.parties ?? [];
  if (binding?.via === "party") {
    const under = ids.filter((id) => parties.includes(id));
    if (under.length > 0) return under;
  } else if (parties.length > 0) {
    return [];
  }
  if (devices === null || devices.length === 0) return [];
  if (!devices.every((d) => d.party_id != null && ids.includes(d.party_id))) return [];
  return ids.filter((id) => devices.some((d) => d.party_id === id));
}

/** The leader as the card names him: the first name, else the @handle, else the #id. */
export function leaderName(party: TrustedPartyDto): string {
  const l = party.leader;
  return l.first_name ?? (l.username ? `@${l.username}` : `#${l.telegram_user_id}`);
}

const GUESTS = {
  one: "app.partyGuestsOne",
  few: "app.partyGuestsFew",
  many: "app.partyGuestsMany",
} as const satisfies Record<string, TranslationKey>;

/** «Лидер: Лёха · 8 гостей», or «… · гостей пока нет». */
export function delegationLine(
  t: Translator,
  locale: Locale,
  party: TrustedPartyDto,
  guests: number,
): string {
  const key: TranslationKey =
    guests === 0
      ? "app.partyGuestsNone"
      : locale === "ru"
        ? pluralRu(guests, GUESTS)
        : guests === 1
          ? GUESTS.one
          : GUESTS.many;
  return t("app.partyDelegation", {
    leader: leaderName(party),
    guests: t(key, { count: guests }),
  });
}

/**
 * What else holds a person here, as «также в пати "Орлы"» for each of the cards that have them as a
 * guest, but `except` (the card the row stands under; null: a row in the list) — so removing the PC
 * from one party alone is not read as closing it to them.
 */
export function alsoIn(
  t: Translator,
  cards: readonly PartyCard[],
  except: string | null,
  userId: number,
): string {
  return cards
    .filter((c) => c.party.party_id !== except && c.guests.includes(userId))
    .map((c) => t("app.partyAlsoIn", { party: c.party.party }))
    .join(" · ");
}

/** A sentence cut around one value: `name` null when the sentence does not have it. */
export interface Around {
  before: string;
  name: string | null;
  after: string;
}

/** Where the value goes in a sentence, cut apart there. */
const MARK = "\u0000";

/**
 * `key` said with `values`, cut around the value of `slot` (`shown`), so the window can cut that
 * value alone and never the words around it: «Убрать ПК из пати "» «Орлы» «"», «Новый гость: »
 * «Коля» «». A sentence without the slot is all `before`.
 */
export function around(
  t: Translator,
  key: TranslationKey,
  values: Record<string, string>,
  slot: string,
  shown: string,
): Around {
  const text = t(key, { ...values, [slot]: MARK });
  const at = text.indexOf(MARK);
  if (at < 0) return { before: text, name: null, after: "" };
  return { before: text.slice(0, at), name: shown, after: text.slice(at + MARK.length) };
}

/**
 * «Убрать ПК из пати» may be pressed: no session other than a confirmed owner's is live or pending
 * (`clean`). It is an organ of trust (party spec §6): the agent refuses it `session` otherwise,
 * whatever the window shows; the window shows it disabled, as every trust control.
 */
export function leaveOffered(trusted: TrustedDto | null): boolean {
  return trusted?.clean === true;
}

/**
 * The wait for the leader (process §6, the card's two states «гости пати» / «ждёт лидера»): with
 * «Доверенные устройства» on, nobody has a device this party's leader let in here yet — whether the
 * party has guests bound here or none at all.
 */
export function waitsForLeader(card: PartyCard, mode: boolean): boolean {
  return mode && card.entered === 0;
}

/**
 * The question about leaving `partyId` has nothing left to ask: the party is gone from the list (left
 * by the server's word meanwhile). A list not read yet says nothing.
 */
export function partyQuestionGone(trusted: TrustedDto | null, partyId: string): boolean {
  if (trusted === null) return false;
  return trusted.parties?.some((p) => p.party_id === partyId) !== true;
}

/** The first of a person's devices' parties the PC is in, by name: what the removal notes name. */
export function devicesParty(
  trusted: TrustedDto | null,
  devices: readonly TrustedDeviceDto[] | null,
): string | null {
  for (const d of devices ?? []) {
    const p = trusted?.parties?.find((x) => x.party_id === d.party_id);
    if (p) return p.party;
  }
  return null;
}

/**
 * Under «Отвязать?» of a person a party of this PC also holds here: they stay a guest through it —
 * `app.revokePartyStaysOne` naming the one party, `app.revokePartyStaysMany` for several. Only the
 * person's parties (`BindingDto.parties`) the PC is in (`here`, the list's parties: the cards)
 * count; none: no line.
 */
export function revokeStaysLine(
  t: Translator,
  here: readonly TrustedPartyDto[],
  parties: readonly string[] | undefined,
  user: string,
): string | null {
  const held = here.filter((p) => (parties ?? []).includes(p.party_id));
  const [only] = held;
  if (only === undefined) return null;
  if (held.length === 1) return t("app.revokePartyStaysOne", { user, party: only.party });
  return t("app.revokePartyStaysMany", { user });
}

/**
 * The lines over «Отвязать?»'s buttons: the owner's request note (`app.unbindOwnerNote`) on the
 * owner, then the party line (`revokeStaysLine`) when there is one.
 */
export function revokeNotes(t: Translator, owner: boolean, stays: string | null): string[] {
  return [...(owner ? [t("app.unbindOwnerNote")] : []), ...(stays === null ? [] : [stays])];
}
