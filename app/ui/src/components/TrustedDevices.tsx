import { type Locale, pluralRu, type TranslationKey } from "@afklink/i18n/pc";
import { KeyRound, Send, ShieldCheck, Trash2, TriangleAlert } from "lucide-react";
import { type ReactNode, useCallback, useEffect, useId, useRef, useState } from "react";

import { useLanguage, useT } from "../i18n";
import { dayKey, dayTitle, timeText } from "../lib/journal";
import { cn } from "../lib/utils";
import {
  attemptAllow,
  attemptHide,
  confirmTrustedDevice,
  getTrusted,
  removePerson,
  removeTrustedDevice,
  repairTrusted,
  setTrustedMode,
  type TrustedAttemptDto,
  type TrustedDamageDto,
  type TrustedDeviceDto,
  type TrustedDeviceRefDto,
  type TrustedDto,
  type TrustedError,
  type TrustedPersonDto,
  type TrustedRepair,
  type TrustedSource,
  trustedError,
} from "../tauri";
import { Button } from "./ui/button";
import { Checkbox } from "./ui/checkbox";
import { Dialog } from "./ui/dialog";
import { Switch } from "./ui/switch";

/*
 * «Доверенные устройства» — device keys milestone 1 (docs/design/viewer-device-keys.md §3.2, §9.1,
 * §10, §16 1b, §18), on the window's IPC (`get_trusted` and the commands beside it in `tauri.ts`).
 *
 * Presented as layers: the Telegram account is the base — always on, no switch;
 * «Доверенные устройства» is an extra layer over it. Off is neutral grey, never red, amber or a
 * warning sign (off is not "unprotected": the base still holds); on is the brand's lime. Amber only
 * for what cannot connect while the mode is on: a person with no confirmed device, an unconfirmed
 * device, a damaged list.
 *
 * Only confirmed devices are trusted (§10.1): an unconfirmed one is listed with «Ждёт подтверждения»
 * and «Подтвердить», and counts nowhere. Restoring an access key on the same device (§9.1) is always
 * on, with no switch. «Удалить из доверенных» and «Удалить все устройства» show
 * in both modes: with the mode off the question says the removal counts once it
 * goes on (`app.trustedUntrustNoteObserve`); its live sessions end at once either way. Every trust control asks first in a dialog and waits for a clean window (`clean`); confirming and
 * turning the mode on also carry the list's `token`, so a session that started meanwhile turns them down.
 *
 * Logs never carry a key id whole: `key_short` (its first 8 characters) names a key.
 */

/**
 * The PC's trusted devices, read when the window opens a view, when the agent says the list moved
 * (`key` carries `StatusDto.trusted_rev`) and after every change from here. Null while unknown — and
 * for good when the agent never answers `get_trusted` (an agent without trusted devices): the window
 * then keeps today's look, said once. A failed read after a good one keeps the last list.
 */
export function useTrusted(key: string): { trusted: TrustedDto | null; reload: () => void } {
  const [trusted, setTrusted] = useState<TrustedDto | null>(null);
  const [tick, setTick] = useState(0);
  const loaded = useRef(false);
  const missingSaid = useRef(false);
  const lastSummary = useRef<string | null>(null);
  const lastFailure = useRef<string | null>(null);

  // biome-ignore lint/correctness/useExhaustiveDependencies: `key` and `tick` are what re-read it
  useEffect(() => {
    let alive = true;
    getTrusted().then(
      (dto) => {
        if (!alive) return;
        loaded.current = true;
        lastFailure.current = null;
        setTrusted(dto);
        const summary = trustedSummary(dto);
        if (summary !== lastSummary.current) {
          lastSummary.current = summary;
          // biome-ignore lint/suspicious/noConsole: once per change of what the agent says
          console.debug(`[access] trusted devices: ${summary}`);
        }
      },
      (e: unknown) => {
        if (!alive) return;
        if (loaded.current) {
          // A newer agent that answered before: keep its last list rather than drop the layers.
          const why = String(e);
          if (why !== lastFailure.current) {
            lastFailure.current = why;
            console.warn(`[ipc] get_trusted failed, the last list stays: ${why}`);
          }
          return;
        }
        setTrusted(null);
        if (!missingSaid.current) {
          missingSaid.current = true;
          // biome-ignore lint/suspicious/noConsole: once per window, the fallback taken
          console.debug(
            `[access] get_trusted not answered (an agent without trusted devices?): today's look, no layers — ${String(e)}`,
          );
        }
      },
    );
    return () => {
      alive = false;
    };
  }, [key, tick]);

  const reload = useCallback(() => setTick((n) => n + 1), []);
  return { trusted, reload };
}

/** One line of what the list says, for the log: no ids, no names. */
function trustedSummary(dto: TrustedDto): string {
  const devices = dto.people.flatMap((p) => p.devices);
  const unconfirmed = devices.filter((d) => d.unconfirmed).length;
  const damage = dto.damage
    ? ` (${dto.damage.reason}, restore ${dto.damage.can_restore ? "yes" : "no"}, reset ${dto.damage.can_reset ? "yes" : "no"})`
    : "";
  return `${dto.state}${damage}, mode ${dto.trusted_mode ? "on" : "off"}, ${devices.length} device(s) (${unconfirmed} unconfirmed) for ${dto.people.length} people, ${dto.waiting.length} waiting, clean ${dto.clean ? "yes" : "no"}${dto.full ? ", full" : ""}`;
}

/**
 * A person's devices, or null when the agent keeps no list (today's look) — and while the list is
 * damaged: it names nobody then, and «Нужно доверенное устройство» on every row would blame the
 * people for what the block at the top says.
 */
export function devicesOf(trusted: TrustedDto | null, id: number): TrustedDeviceDto[] | null {
  if (trusted === null || trusted.state === "damaged") return null;
  return trusted.people.find((p) => p.telegram_user_id === id)?.devices ?? [];
}

/** The devices that count as trusted: confirmed ones (§10.1). */
export function confirmedOf(devices: TrustedDeviceDto[]): TrustedDeviceDto[] {
  return devices.filter((d) => !d.unconfirmed);
}

/* ── Words ─────────────────────────────────────────────────────────────────────────────────── */

type T = ReturnType<typeof useT>;

/**
 * The platforms with a name. The store keeps a platform as it came (spec §4: `iphone`, `windows`,
 * `unknown`…); one listed here gets its name, and anything else — `unknown`, or a value this build
 * does not list — is shown as unknown («Неизвестное устройство», a browser's «Браузер»), never as
 * it came. The Windows notifications name devices by the same map (`guest_toast.rs`, `PLATFORMS`):
 * change both together.
 */
const PLATFORMS: ReadonlyMap<string, string> = new Map([
  ["iphone", "iPhone"],
  ["ipad", "iPad"],
  ["ios", "iOS"],
  ["android", "Android"],
  ["mac", "Mac"],
  ["macos", "macOS"],
  ["windows", "Windows"],
  ["linux", "Linux"],
]);

/** Raw platforms already said in the console as unnamed: once each per window. */
const unnamedSaid = new Set<string>();

/** A platform's name, or null: unknown or not listed (shown as unknown). */
export function platformName(raw: string): string | null {
  const name = PLATFORMS.get(raw.toLowerCase());
  if (name === undefined && !unnamedSaid.has(raw) && unnamedSaid.size < 32) {
    unnamedSaid.add(raw);
    // biome-ignore lint/suspicious/noConsole: once per raw value, the fallback taken
    console.debug(
      `[access] platform ${JSON.stringify(raw.slice(0, 32))} has no name here: shown as unknown`,
    );
  }
  return name ?? null;
}

/** A device's words: the key and its values («Telegram на iPhone», «Браузер», «Неизвестное…»). */
function deviceWords(d: TrustedDeviceRefDto): {
  key: TranslationKey;
  values?: Record<string, string>;
} {
  const platform = d.platform ? platformName(d.platform) : null;
  switch (d.kind) {
    case "telegram":
      return platform
        ? { key: "app.trustedDeviceTelegram", values: { platform } }
        : { key: "app.trustedDeviceUnknown" };
    case "telegram_desktop":
      return platform
        ? { key: "app.trustedDeviceDesktop", values: { os: platform } }
        : { key: "app.trustedDeviceUnknown" };
    case "browser":
      return platform
        ? { key: "app.trustedDeviceBrowser", values: { platform } }
        : { key: "app.trustedDeviceBrowserAny" };
    default:
      return { key: "app.trustedDeviceUnknown" };
  }
}

/** «Telegram на iPhone», «Браузер на Mac», «Браузер», «Неизвестное устройство». */
export function deviceName(t: T, d: TrustedDeviceRefDto): string {
  const { key, values } = deviceWords(d);
  return t(key, values);
}

const SOURCES: Record<TrustedSource, TranslationKey> = {
  pairing: "app.trustedSourcePairing",
  endorsed: "app.trustedSourceEndorsed",
  owner: "app.trustedSourceOwner",
  migrated: "app.trustedSourceMigrated",
  restored: "app.trustedSourceRestored",
};

/**
 * «Разрешено на ПК», «Подтверждено с …» with the confirming device's name quoted,
 * so it keeps its own capital. `by`: the device that confirmed it — null when it is no longer in
 * the list; that, or a device whose name is unknown, says «Подтверждено с другого устройства»
 * (`app.trustedSourceEndorsedUnknown`). Undefined where nothing says (the journal's entries): an
 * endorsed device then has no source line rather than an unknown one.
 */
export function sourceText(
  t: T,
  source: TrustedSource | null | undefined,
  by?: TrustedDeviceRefDto | null,
): string | null {
  if (!source) return null;
  if (source === "endorsed") {
    if (by === undefined) return null;
    if (by === null || deviceWords(by).key === "app.trustedDeviceUnknown") {
      return t("app.trustedSourceEndorsedUnknown");
    }
    return t(SOURCES.endorsed, { device: deviceName(t, by) });
  }
  return t(SOURCES[source]);
}

/** The day and the month in words, with the year when it is not this one. */
export function dateText(locale: Locale, ms: number, now: number): string {
  const sameYear = new Date(ms).getFullYear() === new Date(now).getFullYear();
  return new Date(ms).toLocaleDateString(locale, {
    day: "numeric",
    month: "long",
    ...(sameYear ? {} : { year: "numeric" }),
  });
}

/**
 * When, as the journal says it but inside a sentence, after «Последнее подключение:» — «сегодня
 * 9:12», «вчера 21:40» or a date: the journal's day titles begin with a capital only because
 * they stand alone as headings, so «Сегодня» and «Вчера» are lowered here (a date has none).
 */
export function whenText(t: T, locale: Locale, ms: number, now: number): string {
  const day = dayTitle(t, locale, ms, now);
  const recent = dayKey(ms) === dayKey(now) || day === t("app.journalYesterday");
  if (!recent) return day;
  const word = day.charAt(0).toLocaleLowerCase(locale) + day.slice(1);
  return `${word} ${timeText(locale, ms)}`;
}

/** «Последнее подключение: сегодня 9:12» or «Подключений пока не было». */
function lastUsedText(t: T, locale: Locale, d: TrustedDeviceDto, now: number): string {
  return d.last_used_at === null
    ? t("app.trustedNoConnections")
    : t("app.trustedLastSeen", { when: whenText(t, locale, d.last_used_at, now) });
}

type Forms = { one: TranslationKey; few: TranslationKey; many: TranslationKey };

/**
 * The form for `n`: by `pluralRu` in Russian; in English one for 1 and the `many` text otherwise
 * (English `few` repeats it).
 */
function plural(locale: Locale, n: number, forms: Forms): TranslationKey {
  return locale === "ru" ? pluralRu(n, forms) : n === 1 ? forms.one : forms.many;
}

const COUNT = {
  one: "app.trustedCountOne",
  few: "app.trustedCountFew",
  many: "app.trustedCountMany",
} as const satisfies Forms;

const DEPENDENTS = {
  one: "app.trustedUntrustDependentsOne",
  few: "app.trustedUntrustDependentsFew",
  many: "app.trustedUntrustDependentsMany",
} as const satisfies Forms;

/**
 * The main card's «Доступ» line: the topmost layer in force — or, in amber, that nobody connects
 * while the list is damaged and the mode is on (a damaged list's mode is the mode file's, on when it
 * says nothing: so «unknown» reads as on here).
 */
export function homeAccessLine(t: T, trusted: TrustedDto): { text: string; attention: boolean } {
  if (trusted.state === "damaged" && trusted.trusted_mode) {
    return { text: t("app.trustedHomeDamaged"), attention: true };
  }
  return {
    text: trusted.trusted_mode ? t("app.trustedHomeOn") : t("app.trustedHomeBase"),
    attention: false,
  };
}

/** What a command's failure says, where it says anything (`damaged`, `not_found`: a reload). */
function failureText(t: T, code: TrustedError | "slow"): string | null {
  switch (code) {
    case "session":
      return t("app.trustedBusySession");
    case "full":
      return t("app.trustedFull");
    case "slow":
      return t("app.trustedSaveSlow");
    case "write_failed":
    case "busy":
    case "refused":
    // Never sent by this window (no «Удалить все устройства» for the owner): the generic failure
    // if the agent says so. `second_step` and `role` on «Подтвердить» / «Разрешить» ask again
    // instead (`run`).
    case "owner":
    case "second_step":
    case "role":
      return t("app.trustedSaveFailed");
    case "no_owner_device":
      return t("app.trustedOnOwnerMissing");
    default:
      return null;
  }
}

/**
 * The devices removed with `keyId` that the list can name: its descendants by `by_key_id` (endorse,
 * grant). An invite's descendants carry no `by_key_id`, so `found` can be less than the device's
 * `dependents`; `live` is then what the named ones say.
 */
export function dependentsOf(trusted: TrustedDto, keyId: string): { found: number; live: boolean } {
  const children = new Map<string, TrustedDeviceDto[]>();
  for (const d of trusted.people.flatMap((p) => p.devices)) {
    if (d.by_key_id === null) continue;
    const list = children.get(d.by_key_id) ?? [];
    list.push(d);
    children.set(d.by_key_id, list);
  }
  const seen = new Set<string>([keyId]);
  const queue = [keyId];
  let found = 0;
  let live = false;
  for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
    for (const child of children.get(next) ?? []) {
      if (seen.has(child.key_id)) continue;
      seen.add(child.key_id);
      found += 1;
      live ||= child.in_session;
      queue.push(child.key_id);
    }
  }
  return { found, live };
}

/**
 * What pressing a damaged list's repair button does: «Повторить» runs at once; «Восстановить из
 * копии» and «Начать список заново» only open their question (the restore asks
 * first) — the command goes from the question's action (`commandFor`).
 */
export function repairPress(action: TrustedRepair): "run" | "ask-restore" | "ask-reset" {
  switch (action) {
    case "reopen":
      return "run";
    case "restore":
      return "ask-restore";
    case "reset":
      return "ask-reset";
  }
}

/**
 * A device's quiet actions: «Подтвердить» while unconfirmed, and «Удалить из доверенных» always —
 * in both modes.
 */
export function deviceActions(d: TrustedDeviceDto): ("confirm" | "untrust")[] {
  return d.unconfirmed ? ["confirm", "untrust"] : ["untrust"];
}

/** The person's row in the list (`people`), or undefined: none there, no list, or damaged. */
export function personOf(trusted: TrustedDto | null, id: number): TrustedPersonDto | undefined {
  if (trusted === null || trusted.state === "damaged") return undefined;
  return trusted.people.find((p) => p.telegram_user_id === id);
}

/** The device an attempt's key card names, as a device line reads it. */
export function attemptDevice(a: TrustedAttemptDto): TrustedDeviceRefDto {
  return { kind: a.kind ?? null, platform: a.platform ?? null };
}

const ATTEMPTS = {
  one: "app.trustedAttemptCountOne",
  few: "app.trustedAttemptCountFew",
  many: "app.trustedAttemptCountMany",
} as const satisfies Forms;

/**
 * An attempt's hint: how many times it tried and when — «3 попытки · {first} – сегодня 9:12»;
 * only the latest when every try fell on one day.
 */
export function attemptSpan(t: T, locale: Locale, a: TrustedAttemptDto, now: number): string {
  const count = a.count ?? 1;
  const last = a.last_at ?? a.at;
  const first = a.first_at ?? last;
  const lastText = whenText(t, locale, last, now);
  const when =
    dayKey(first) === dayKey(last)
      ? lastText
      : t("app.trustedAttemptRange", { first: dateText(locale, first, now), last: lastText });
  return `${t(plural(locale, count, ATTEMPTS), { count })} · ${when}`;
}

/**
 * What a press on an attempt left to say on its row: how «Разрешить» went where the device is not
 * trusted now — `tainted` (a session ran during the check or runs now: nothing written), `gone`
 * (expired, or not in the list), `other_person` — or why the press failed (`failed`, with the
 * agent's code).
 */
export type AttemptNoteKind = "tainted" | "gone" | "other_person" | "failed";

export interface AttemptNote {
  userId: number;
  keyId: string;
  device: TrustedDeviceRefDto;
  kind: AttemptNoteKind;
  /** `failed`: what the agent answered. */
  code?: TrustedError;
}

/**
 * What a refusal of «Разрешить» leaves: the note on the row; `quiet` — no line, the question closes
 * and the list read again shows it (the device in the list, the list full); or null — the
 * question's own handling (damaged, a write still going on).
 */
export function allowNoteKind(answer: TrustedError): AttemptNoteKind | "quiet" | null {
  switch (answer) {
    case "damaged":
    case "newer_version":
    case "slow":
      return null;
    case "added":
    case "full":
      return "quiet";
    case "tainted":
    case "session":
      return "tainted";
    case "expired":
    case "not_found":
      return "gone";
    case "key_other_person":
      return "other_person";
    default:
      return "failed";
  }
}

/** A note's lines, in order, each with its tone: amber what went wrong, muted what to do next. */
export function attemptNoteSaid(
  t: T,
  note: AttemptNote,
): { text: string; tone: "attention" | "muted" | "danger" }[] {
  switch (note.kind) {
    case "tainted":
      return [
        { text: t("app.trustedTaintNotTrusted"), tone: "attention" },
        { text: t("app.trustedTaintNotTrustedAbout"), tone: "muted" },
      ];
    case "gone":
      return [
        { text: t("app.trustedAttemptGone"), tone: "attention" },
        { text: t("app.trustedAttemptAddDevice"), tone: "muted" },
      ];
    case "other_person":
      return [{ text: t("app.trustedAttemptOtherPerson"), tone: "attention" }];
    case "failed": {
      const code = note.code ?? "refused";
      return [
        {
          text: failureText(t, code) ?? t("app.trustedSaveFailed"),
          tone: code === "session" ? "attention" : "danger",
        },
      ];
    }
  }
}

/** The allow dialog still has only the list its one press was refused against (`waits`). */
export function allowWaiting(
  a: Extract<Asking, { kind: "allow" }>,
  trusted: TrustedDto | null,
): boolean {
  return a.waits !== null && a.waits === trusted;
}

/**
 * A one press of «Разрешить» answered `second_step` (or `role`): the agent knows an owner the list
 * read at the press does not. The dialog opens unticked and waits for the list read again (`waits`,
 * the list as the answer came) — a role or a box from the old list is never shown or sent.
 */
export function allowAfterSecondStep(
  a: Extract<Asking, { kind: "allow" }>,
  trusted: TrustedDto | null,
): Extract<Asking, { kind: "allow" }> {
  return { ...a, recognized: false, waits: trusted };
}

/**
 * An open allow question as the list says it now: the first list after `waits` ends the wait; the
 * role the press gives (`owner`, the agent's «owner on this PC») moving replaces it and clears the
 * box — a step given for one role is never sent for another. The same question when nothing moved.
 */
export function followList(asking: Asking, trusted: TrustedDto): Asking {
  if (asking.kind !== "allow") return asking;
  const owner = allowGivesOwner(trusted, asking.userId);
  if (asking.waits !== null) {
    if (asking.waits === trusted) return asking;
    return { ...asking, waits: null, owner, recognized: false };
  }
  if (asking.owner === owner) return asking;
  return { ...asking, owner, recognized: false };
}

/**
 * The «Включить…?» review again after a row's question asked from it ended: none over a damaged
 * or unread list; the list's token only while the window is clean and the row's question did not
 * close because a session came (`heldForGood`) — the review never takes a window it was not opened
 * in, it is held and asked again.
 */
export function reviewAgain(trusted: TrustedDto | null, heldForGood: boolean): Asking | null {
  if (trusted === null || trusted.state === "damaged") return null;
  return {
    kind: "mode",
    on: true,
    token: trusted.clean && !heldForGood ? trusted.token : null,
    spent: false,
  };
}

/** An open question after a failed command, as `failurePlan` says (`spend`, `untick`). */
export function questionAfter(
  a: Asking | null,
  plan: ReturnType<typeof failurePlan>,
): Asking | null {
  switch (plan.question) {
    case "spend":
      return a !== null && "spent" in a ? { ...a, spent: true } : a;
    case "untick":
      return a?.kind === "allow" ? { ...a, recognized: false } : a;
    case "close":
      return null;
    case "keep":
      return a;
  }
}

/**
 * Whether «Разрешить» on this person's attempt gives owner access: what the core says the press
 * gives (`TrustedPersonDto.role`, its reading «owner on this PC» — a working owner key here, or the
 * owner by the bindings).
 */
export function allowGivesOwner(trusted: TrustedDto | null, id: number): boolean {
  return personOf(trusted, id)?.role === "owner";
}

/**
 * «Разрешить» on an attempt: one press for a guest the agent asks nothing more of; the dialog with
 * its box when it wants the second step (`needs_second_step`: the owner).
 */
export function allowPress(trusted: TrustedDto | null, id: number): "send" | "ask" {
  return personOf(trusted, id)?.needs_second_step === true ? "ask" : "send";
}

/** A trust command the window sends (`send`): the IPC's name and its arguments. */
export type TrustedCommand =
  | { command: "set_trusted_mode"; enabled: boolean; token: string | null }
  | { command: "remove_trusted_device"; keyId: string }
  | {
      command: "confirm_trusted_device";
      keyId: string;
      token: string;
    }
  | { command: "remove_person"; userId: number }
  | {
      command: "attempt_allow";
      userId: number;
      keyId: string;
      token: string;
      secondStep: boolean;
      /** The role the dialog showed: the owner's line («Это моё устройство») or a guest's. */
      role: "owner" | "guest";
    }
  | { command: "repair_trusted"; action: "restore"; token: string }
  | { command: "repair_trusted"; action: "reset" };

/**
 * The question's action pressed: the command it sends, or why it is held — mode-on, confirm and
 * restore need the clean window they opened with (`windowHold`). The only way a restore or a reset
 * is sent.
 */
export function commandFor(
  a: Asking,
  trusted: TrustedDto | null,
): { command: TrustedCommand; what: string } | { held: string } {
  switch (a.kind) {
    case "mode": {
      if (!a.on) {
        return {
          command: { command: "set_trusted_mode", enabled: false, token: null },
          what: "set_trusted_mode(off)",
        };
      }
      const held = windowHold(a, trusted);
      if (held !== null || a.token === null) return { held: held ?? "no token" };
      return {
        command: { command: "set_trusted_mode", enabled: true, token: a.token },
        what: "set_trusted_mode(on)",
      };
    }
    case "remove":
      return {
        command: { command: "remove_trusted_device", keyId: a.device.key_id },
        what: `remove_trusted_device #${a.userId} key ${a.device.key_short}`,
      };
    case "confirm":
      return confirmCommand(a, trusted);
    case "person":
      return {
        command: { command: "remove_person", userId: a.userId },
        what: `remove_person #${a.userId}`,
      };
    case "attempts":
      return {
        command: { command: "remove_person", userId: a.userId },
        what: `remove_person #${a.userId} (attempts only)`,
      };
    case "allow":
      return allowCommand(a, trusted);
    case "restore": {
      const held = windowHold(a, trusted);
      if (held !== null || a.token === null) return { held: held ?? "no token" };
      return {
        command: { command: "repair_trusted", action: "restore", token: a.token },
        what: "repair_trusted(restore)",
      };
    }
    case "reset":
      return {
        command: { command: "repair_trusted", action: "reset" },
        what: "repair_trusted(reset)",
      };
  }
}

/** «Подтвердить» pressed (`commandFor`): the command, or why it is held (one press). */
function confirmCommand(
  a: Extract<Asking, { kind: "confirm" }>,
  trusted: TrustedDto | null,
): { command: TrustedCommand; what: string } | { held: string } {
  const held = windowHold(a, trusted);
  if (held !== null || a.token === null) return { held: held ?? "no token" };
  return {
    command: { command: "confirm_trusted_device", keyId: a.device.key_id, token: a.token },
    what: `confirm_trusted_device #${a.userId} key ${a.device.key_short}`,
  };
}

/**
 * «Разрешить» on an attempt (`commandFor`): the command, or why it is held. It needs the clean window
 * it was pressed in (`windowHold`): a session that came and went since moved the token, and the agent
 * would refuse the press (`tainted`, in both modes). One press without the dialog takes its token at
 * the press, so only the dialog can be overtaken.
 */
function allowCommand(
  a: Extract<Asking, { kind: "allow" }>,
  trusted: TrustedDto | null,
): { command: TrustedCommand; what: string } | { held: string } {
  if (allowWaiting(a, trusted)) {
    return { held: `#${a.userId}: the agent wants the second step, the list is being read again` };
  }
  const needs = allowPress(trusted, a.userId) === "ask";
  if (needs && !a.recognized) {
    return {
      held: `#${a.userId} needs the second step and its box is not ticked`,
    };
  }
  const held = windowHold(a, trusted);
  if (held !== null || a.token === null) return { held: held ?? "no token" };
  return {
    command: {
      command: "attempt_allow",
      userId: a.userId,
      keyId: a.keyId,
      token: a.token,
      secondStep: needs && a.recognized,
      role: a.owner ? "owner" : "guest",
    },
    what: `attempt_allow #${a.userId} key ${a.keyShort} as ${a.owner ? "owner" : "guest"}${needs && a.recognized ? " with the second step" : ""}`,
  };
}

/** Send a command (`commandFor`) over the window's IPC. */
function send(c: TrustedCommand): Promise<unknown> {
  switch (c.command) {
    case "set_trusted_mode":
      return setTrustedMode(c.enabled, c.token);
    case "remove_trusted_device":
      return removeTrustedDevice(c.keyId);
    case "confirm_trusted_device":
      return confirmTrustedDevice(c.keyId, c.token);
    case "remove_person":
      return removePerson(c.userId);
    case "attempt_allow":
      return attemptAllow(c.userId, c.keyId, c.token, c.secondStep, c.role);
    case "repair_trusted":
      return c.action === "restore" ? repairTrusted("restore", c.token) : repairTrusted("reset");
  }
}

/* ── The layers block ──────────────────────────────────────────────────────────────────────── */

/**
 * A layer's mark: a disc with its icon — lime and filled while the layer is in force, a grey outline
 * while it is not (neutral: off is not a fault).
 */
function LayerMark({ on, children }: { on: boolean; children: ReactNode }) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        "flex size-7 shrink-0 items-center justify-center rounded-full border [&_svg]:size-3.5",
        on ? "border-transparent bg-accent text-accent-ink" : "border-line-strong text-faint",
      )}
    >
      {children}
    </span>
  );
}

/**
 * What stands before «Включить», as the agent reads the owner's own device (§10.2): null — the
 * switch is offered (on already, or the owner's confirmed device is here, or an older agent that
 * does not say); otherwise the line that says what to do in its place — add a device at this PC,
 * or confirm the one here. Turning the mode off is never held.
 */
export function modeNeeds(
  trusted: TrustedDto,
): "app.trustedOnNeedOwnDevice" | "app.trustedOnConfirmOwnDevice" | null {
  if (trusted.trusted_mode) return null;
  switch (trusted.owner_device) {
    case "needs_device":
      return "app.trustedOnNeedOwnDevice";
    case "needs_confirm":
      return "app.trustedOnConfirmOwnDevice";
    default:
      return null;
  }
}

/**
 * The step under «Включить нельзя: у тебя нет доверенного устройства» in the enable dialog, by the
 * agent's reading: confirm the owner's device that is here, else add one at this PC.
 */
export function ownerMissingStep(
  trusted: TrustedDto | null,
): "app.trustedOnConfirmOwnDeviceShort" | "app.trustedOnNeedOwnDeviceShort" {
  return trusted?.owner_device === "needs_confirm"
    ? "app.trustedOnConfirmOwnDeviceShort"
    : "app.trustedOnNeedOwnDeviceShort";
}

/**
 * Whether the enable dialog's «Включить» waits: no confirmed owner-role device here
 * (`app.trustedOnOwnerMissing` and its step). With one — anyone's — the switch is open, and an
 * owner by the bindings with no device of his own is one of those who will not connect
 * (`wontConnect`). The agent's reading (`owner_device`).
 */
export function modeBlocked(trusted: TrustedDto | null): boolean {
  return trusted !== null && modeNeeds(trusted) !== null;
}

/** Says once per change why the switch is not offered. */
function useModeNeedsLog(needs: ReturnType<typeof modeNeeds>) {
  useEffect(() => {
    if (needs === null) return;
    // biome-ignore lint/suspicious/noConsole: once per change of what holds the switch
    console.debug(
      `[access] the switch is not offered: ${needs === "app.trustedOnNeedOwnDevice" ? "no device of the owner's here" : "the owner's device here is unconfirmed"}`,
    );
  }, [needs]);
}

/**
 * «Telegram-аккаунт» (the base, always on: no switch) over «Доверенные устройства» (the switch,
 * asked first in a dialog). The switch waits while the list is damaged or a session locks changes;
 * it is not offered at all while turning it on would shut the owner out (`modeNeeds`).
 */
export function TrustedLayers({
  trusted,
  onAskMode,
  className,
}: {
  trusted: TrustedDto;
  onAskMode: (on: boolean) => void;
  className?: string;
}) {
  const t = useT();
  const modeId = useId();
  const modeAbout = useId();
  const on = trusted.trusted_mode;
  const needs = modeNeeds(trusted);
  useModeNeedsLog(needs);
  return (
    <div className={cn("overflow-hidden rounded-card border border-line bg-panel", className)}>
      <div className="flex items-start gap-3 px-4 py-3">
        <LayerMark on>
          <Send />
        </LayerMark>
        <div className="min-w-0 flex-1">
          <p className="text-body text-ink">{t("app.trustedBaseTitle")}</p>
          <p className="mt-0.5 text-balance text-hint text-muted">{t("app.trustedBaseAbout")}</p>
        </div>
      </div>
      <div className="flex items-start gap-3 border-t border-line px-4 py-3">
        <LayerMark on={on}>
          <KeyRound />
        </LayerMark>
        <div className="min-w-0 flex-1">
          <label htmlFor={modeId} className="block cursor-pointer text-body text-ink">
            {t("app.trustedTitle")}
          </label>
          <p id={modeAbout} className="mt-0.5 text-balance text-hint text-muted">
            {on ? t("app.trustedAboutOn") : t("app.trustedAboutOff")}
          </p>
          {needs === null ? null : (
            <p className="mt-0.5 text-balance text-hint text-attention">{t(needs)}</p>
          )}
        </div>
        {needs === null ? (
          <Switch
            id={modeId}
            aria-describedby={modeAbout}
            className="mt-1"
            checked={on}
            disabled={trusted.state === "damaged" || !trusted.clean}
            // Asked first: the dialog turns it, not the press.
            onCheckedChange={(next) => trusted.clean && onAskMode(next)}
          />
        ) : null}
      </div>
    </div>
  );
}

/**
 * The damaged list (§10). With the mode on — or unknown: the mode file says nothing, and the agent
 * reports it on — it denies everyone until repaired here (`app.trustedDamagedAbout`); with it off
 * everyone with access connects as before and only the repairs wait (`trustedDamagedAboutObserve`).
 * «Повторить» always; «Восстановить из копии» (asked first) with a readable backup; «Начать список
 * заново» (asked first) where the agent allows it. A list a newer AFKLink wrote says so instead of
 * offering either.
 */
export function TrustedDamaged({
  damage,
  mode,
  busy,
  locked,
  notice,
  onRepair,
}: {
  damage: TrustedDamageDto | null;
  /** `TrustedDto.trusted_mode`: while damaged, the mode file's switch (on when it says nothing). */
  mode: boolean;
  /** A repair is in flight: the buttons wait. */
  busy: boolean;
  locked: boolean;
  /** How the last repair from here went, when it says anything. */
  notice: string | null;
  /** A repair button pressed: `repairPress` decides — reopen at once, restore and reset asked. */
  onRepair: (action: TrustedRepair) => void;
}) {
  const t = useT();
  const newer = damage?.reason === "newer_version";
  const restore = !newer && damage?.can_restore === true;
  const reset = !newer && damage?.can_reset === true;
  const action = "min-w-max grow basis-0";
  return (
    <div className="rounded-card border border-attention/40 bg-attention-dim px-4 py-3">
      <p className="flex items-start gap-2 text-body text-ink">
        <TriangleAlert className="mt-0.5 size-4 shrink-0 text-attention" aria-hidden="true" />
        <span className="min-w-0">{t("app.trustedDamagedTitle")}</span>
      </p>
      <p className="mt-0.5 pl-6 text-balance text-hint text-muted">
        {mode ? t("app.trustedDamagedAbout") : t("app.trustedDamagedAboutObserve")}
      </p>
      {newer ? (
        <p className="mt-1 pl-6 text-balance text-hint text-attention">
          {t("app.trustedNewerVersion")}
        </p>
      ) : null}
      {locked ? (
        <p className="mt-1 pl-6 text-balance text-hint text-muted">
          {t("app.trustedLockedSession")}
        </p>
      ) : null}
      <div className="mt-2.5 flex flex-wrap gap-2">
        <Button
          size="sm"
          className={action}
          disabled={locked}
          aria-disabled={busy || locked || undefined}
          onClick={() => !busy && !locked && onRepair("reopen")}
        >
          {t("app.trustedRepairReopen")}
        </Button>
        {restore ? (
          <Button
            size="sm"
            className={action}
            aria-haspopup="dialog"
            disabled={locked}
            aria-disabled={busy || locked || undefined}
            onClick={() => !busy && !locked && onRepair("restore")}
          >
            {t("app.trustedRepairRestore")}
          </Button>
        ) : null}
        {reset ? (
          <Button
            size="sm"
            className={cn(action, "text-danger")}
            aria-haspopup="dialog"
            disabled={locked}
            aria-disabled={busy || locked || undefined}
            onClick={() => !busy && !locked && onRepair("reset")}
          >
            {t("app.trustedRepairReset")}
          </Button>
        ) : null}
      </div>
      <p role="status" className="mt-1.5 text-hint text-muted empty:hidden">
        {notice}
      </p>
    </div>
  );
}

/* ── A person's devices ────────────────────────────────────────────────────────────────────── */

/**
 * The line under a person's name, counting confirmed devices only: «2 доверенных устройства»; none —
 * muted with the mode off («Доверенных устройств пока нет»: the first connection adds one), amber
 * with the mode on («Нужно доверенное устройство»: this person cannot connect).
 */
export function TrustLine({
  devices,
  mode,
  className,
}: {
  devices: TrustedDeviceDto[];
  mode: boolean;
  className?: string;
}) {
  const t = useT();
  const { locale } = useLanguage();
  const confirmed = confirmedOf(devices).length;
  if (confirmed > 0) {
    return (
      <span className={cn("block truncate text-hint text-faint", className)}>
        {t(plural(locale, confirmed, COUNT), { count: confirmed })}
      </span>
    );
  }
  return (
    <span
      className={cn("block truncate text-hint", mode ? "text-attention" : "text-faint", className)}
    >
      {mode ? t("app.trustedNeeded") : t("app.trustedNoneYet")}
    </span>
  );
}

/**
 * A card's quiet text actions (a device's, an attempt's): `ghost` `sm`, 32 px tall, the least
 * target with a mouse (ui-rules §7). The words stay under the card's text: each button's padding is
 * 6 px and the line is pulled left by as much, so the hover's fill and the focus outline (2 px
 * past a 2 px gap) stay inside the card's 12 px padding, clear of its border (with 12 px and
 * `-ml-3` the fill ran to the border and the outline was cut by it). The gap keeps the words 24 px
 * apart, as they were.
 */
const CARD_ACTIONS = "mt-0.5 -ml-1.5 flex flex-wrap gap-x-3";
const CARD_ACTION = "px-1.5";

/**
 * An open person's devices: each with its name, an unconfirmed one's mark («Ждёт подтверждения»,
 * amber with the mode on, faint with it off) and why, where it came from and when, its last
 * connection; «Подтвердить» on an unconfirmed one and «Удалить из доверенных» (both in both modes).
 * None — what happens next, and with the mode on «Добавить доверенное
 * устройство», which opens today's pairing dialog (the same code).
 */
export function PersonDevices({
  devices,
  mode,
  locked,
  review = false,
  onRemove,
  onConfirm,
  onAddDevice,
}: {
  devices: TrustedDeviceDto[];
  mode: boolean;
  locked: boolean;
  /**
   * The review before the mode goes on: each key's first 8 characters too, and the removal's
   * button is «Удалить» (its question is the same «Удалить из доверенных?»).
   */
  review?: boolean;
  onRemove: (device: TrustedDeviceDto) => void;
  onConfirm: (device: TrustedDeviceDto) => void;
  onAddDevice: () => void;
}) {
  const t = useT();
  const { locale } = useLanguage();
  const now = Date.now();
  if (devices.length === 0) {
    return (
      <div className="mb-2 flex flex-col gap-2">
        <p className="text-hint text-muted">
          {mode ? t("app.trustedNeededAbout") : t("app.trustedNoneYetAbout")}
        </p>
        {mode ? (
          <Button
            size="sm"
            className="w-full"
            aria-haspopup="dialog"
            disabled={locked}
            onClick={() => !locked && onAddDevice()}
          >
            <ShieldCheck aria-hidden="true" />
            {t("app.trustedConfirmDevice")}
          </Button>
        ) : null}
      </div>
    );
  }
  return (
    <ul className="mb-2 overflow-hidden rounded-inner border border-line bg-ground/40">
      {devices.map((d) => {
        const source = sourceText(t, d.source, d.by);
        const added = dateText(locale, d.added_at, now);
        return (
          <li key={d.key_id} className="border-t border-line px-3 py-2 first:border-t-0">
            <p className="truncate text-body text-ink" title={deviceName(t, d)}>
              {deviceName(t, d)}
            </p>
            {d.unconfirmed ? <UnconfirmedMark mode={mode} /> : null}
            <p className="text-hint text-faint">{source ? `${source} · ${added}` : added}</p>
            <p className="text-hint text-faint">{lastUsedText(t, locale, d, now)}</p>
            {review ? (
              <p className="text-hint text-faint tabular-nums">
                {t("app.trustedConfirmKey", { key: d.key_short })}
              </p>
            ) : null}
            {d.unconfirmed ? (
              <p className="mt-1 text-balance text-hint text-muted">
                {t("app.trustedUnconfirmedAbout")}
              </p>
            ) : null}
            {/* Quiet text actions, neutral: red is only the dialog's confirmation (`CARD_ACTIONS`). */}
            <div className={CARD_ACTIONS}>
              {deviceActions(d).includes("confirm") ? (
                <Button
                  variant="ghost"
                  size="sm"
                  className={CARD_ACTION}
                  aria-haspopup="dialog"
                  disabled={locked}
                  aria-disabled={locked || undefined}
                  onClick={() => !locked && onConfirm(d)}
                >
                  {t("app.trustedConfirm")}
                </Button>
              ) : null}
              {deviceActions(d).includes("untrust") ? (
                <Button
                  variant="ghost"
                  size="sm"
                  className={CARD_ACTION}
                  aria-haspopup="dialog"
                  disabled={locked}
                  aria-disabled={locked || undefined}
                  onClick={() => !locked && onRemove(d)}
                >
                  {review ? t("app.trustedRemove") : t("app.trustedUntrust")}
                </Button>
              ) : null}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/** «Ждёт подтверждения»: amber while the mode is on (it cannot connect), faint while it is off. */
function UnconfirmedMark({ mode }: { mode: boolean }) {
  const t = useT();
  return (
    <p
      className={cn("flex items-center gap-1.5 text-hint", mode ? "text-attention" : "text-faint")}
    >
      <span aria-hidden="true" className="size-1.5 shrink-0 rounded-full bg-current" />
      {t("app.trustedUnconfirmed")}
    </p>
  );
}

/* ── The questions ─────────────────────────────────────────────────────────────────────────── */

/**
 * `token`: the window token as the list said it when the question opened — only if no session was
 * on then (`clean`); `null` otherwise, and the action stays held for the question's life. `spent`:
 * the agent answered `session` — the question is held until it is opened again (never re-pressed
 * with a fresher token).
 */
export type Asking =
  | { kind: "mode"; on: boolean; token: string | null; spent: boolean }
  | {
      kind: "remove";
      userId: number;
      user: string;
      device: TrustedDeviceDto;
    }
  | {
      kind: "confirm";
      userId: number;
      user: string;
      device: TrustedDeviceDto;
      token: string | null;
      spent: boolean;
    }
  | { kind: "person"; userId: number; user: string; count: number }
  | {
      kind: "allow";
      userId: number;
      user: string;
      attempt: TrustedAttemptDto;
      keyId: string;
      keyShort: string;
      /**
       * The press gives owner access — the core's reading «owner on this PC» (`allowGivesOwner`):
       * the amber owner line and «Это моё устройство».
       */
      owner: boolean;
      token: string | null;
      spent: boolean;
      /** «Это моё устройство» ticked; cleared when the role the press gives moves (`followList`). */
      recognized: boolean;
      /**
       * The list a one press was answered `second_step` against (`allowAfterSecondStep`): that list
       * knows no step. Held, its box locked, until the next list comes (`followList`); null
       * otherwise.
       */
      waits: TrustedDto | null;
    }
  | { kind: "attempts"; userId: number; user: string }
  | { kind: "restore"; token: string | null; spent: boolean }
  | { kind: "reset" };

/**
 * Why a question that needs a clean window (mode-on, confirm, allow, restore) is held now, or `null`: no token was
 * taken as it opened (a session was on), the agent already answered `session`, a session is on now,
 * or one began since it opened (the list's token moved: the agent moves it at every start and end).
 */
export function windowHold(
  a: { token: string | null; spent: boolean },
  trusted: TrustedDto | null,
): string | null {
  if (a.token === null) return "a session was on when the question opened";
  if (a.spent) return "the agent answered session: ask again";
  if (trusted === null) return "the list is not read";
  if (!trusted.clean) return "a session is on";
  if (trusted.token !== a.token) return "a session went on since the question opened";
  return null;
}

/** Who is on the «Доступ» list, as the questions need them. */
export interface TrustedPeopleView {
  /** Every row's name, by Telegram id. */
  names: Map<number, string>;
  /** The ids with a binding: who can connect at all. */
  bound: number[];
  /**
   * The ids whose open row draws «Отвязать» (`AccessScreen` `unbindShown`, the row's own reading):
   * «Удалить из доверенных?» names that button only for them (`untrustLines`).
   */
  unbinds: number[];
  /** The ids the bindings name the owner. */
  owners: number[];
}

/** A person in the review before the mode goes on. */
export interface ReviewPerson {
  id: number;
  name: string;
  devices: TrustedDeviceDto[];
  attempts: TrustedAttemptDto[];
  /** The owner by the bindings or by the role of their keys here: listed under «Владелец». */
  owner: boolean;
}

/**
 * The review before the mode goes on (§10.2), by people: «Владелец» — every device of the owner,
 * confirmed or not; «Гости» — every guest's devices; «Пытались подключиться» — everyone with
 * attempts; «Ещё не подключались с ключом доступа» — the bound with no device, an owner by the
 * bindings among them (`wontConnect`).
 */
export function reviewOf(
  trusted: TrustedDto | null,
  view: TrustedPeopleView,
): {
  owner: ReviewPerson[];
  guests: ReviewPerson[];
  attempts: ReviewPerson[];
  missing: string[];
} {
  const owner: ReviewPerson[] = [];
  const guests: ReviewPerson[] = [];
  const attempts: ReviewPerson[] = [];
  if (trusted === null || trusted.state === "damaged") {
    return { owner, guests, attempts, missing: [] };
  }
  for (const p of trusted.people) {
    const id = p.telegram_user_id;
    const person: ReviewPerson = {
      id,
      name: view.names.get(id) ?? p.first_name ?? (p.username ? `@${p.username}` : `#${id}`),
      devices: p.devices,
      attempts: p.attempts ?? [],
      owner: view.owners.includes(id) || p.role === "owner",
    };
    if (person.devices.length > 0) (person.owner ? owner : guests).push(person);
    if (person.attempts.length > 0) attempts.push(person);
  }
  const { missing } = wontConnect(trusted, view);
  return { owner, guests, attempts, missing };
}

/** What the review's rows do: the list's own presses, each asking its own question. */
export interface ReviewActions {
  notes: AttemptNote[];
  busy: boolean;
  /** The list is full (`TrustedDto.full`): «Разрешить» on an attempt would be refused. */
  full: boolean;
  onConfirm: (userId: number, device: TrustedDeviceDto) => void;
  onRemove: (userId: number, device: TrustedDeviceDto) => void;
  onAllow: (userId: number, attempt: TrustedAttemptDto) => void;
  onHide: (userId: number, attempt: TrustedAttemptDto) => void;
  onRemoveAttempts: (userId: number) => void;
}

/**
 * The trust controls ask first, in the window's dialog (the kill switch's pattern: the question,
 * then «Отмена» and the action). The dialog stays open while its command runs; a failure the owner
 * can act on is said in it (`session`, `write_failed`, `full`…), and it can be pressed again; `slow`
 * closes it and says «Сохраняем изменение…» under the layers until the list changes; `damaged` and
 * `not_found` close it — the list read again shows why. Every decision is said in the console, and
 * the list is read again after every command.
 */
export function useTrustedQuestions(
  trusted: TrustedDto | null,
  view: TrustedPeopleView,
  onChanged: () => void,
): {
  askMode: (on: boolean) => void;
  askRemove: (userId: number, device: TrustedDeviceDto) => void;
  askConfirm: (userId: number, device: TrustedDeviceDto) => void;
  askRemovePerson: (userId: number) => void;
  /** «Разрешить» on an attempt: sent at once, or asked first (`allowPress`). */
  pressAllow: (userId: number, attempt: TrustedAttemptDto) => void;
  /** «Скрыть» on an attempt: sent at once. */
  pressHide: (userId: number, attempt: TrustedAttemptDto) => void;
  askRemoveAttempts: (userId: number) => void;
  /** What the last presses on attempts left to say, by attempt (`AttemptNote`). */
  attemptNotes: AttemptNote[];
  /** A command runs: the one-press actions wait. */
  busy: boolean;
  /** The list is full: «Разрешить» on an attempt is not offered (`PersonAttempts`). */
  full: boolean;
  askRestore: () => void;
  askReset: () => void;
  /** A damaged list's button pressed (`repairPress`): reopen at once, restore and reset asked. */
  pressRepair: (action: TrustedRepair) => void;
  repair: (action: Exclude<TrustedRepair, "reset" | "restore">) => void;
  repairing: boolean;
  repairNotice: string | null;
  notice: string | null;
  dialog: ReactNode;
} {
  const t = useT();
  const [asking, setAsking] = useState<Asking | null>(null);
  const [sending, setSending] = useState(false);
  const [failure, setFailure] = useState<TrustedError | null>(null);
  const [repairing, setRepairing] = useState(false);
  const [repairFailure, setRepairFailure] = useState<TrustedError | null>(null);
  const [attemptNotes, setAttemptNotes] = useState<AttemptNote[]>([]);
  /** A row's question opened from the «Включить…?» review: the review comes back after it. */
  const [fromReview, setFromReview] = useState(false);
  const locked = trusted !== null && !trusted.clean;
  const lastLoggedLock = useRef<boolean | null>(null);
  useEffect(() => {
    if (lastLoggedLock.current === locked) return;
    lastLoggedLock.current = locked;
    // biome-ignore lint/suspicious/noConsole: once per lock state change
    console.debug(`[access] trust controls ${locked ? "locked by session" : "unlocked"}`);
  }, [locked]);
  /** `slow`: the list as it was when the write went on in the background; cleared once it moves. */
  const [slowFrom, setSlowFrom] = useState<string | null>(null);
  /** A question closed because its window passed: «Сейчас идёт сеанс…» under the layers a while. */
  const [heldClosed, setHeldClosed] = useState(false);
  useEffect(() => {
    if (!heldClosed) return;
    const id = window.setTimeout(() => setHeldClosed(false), 15_000);
    return () => window.clearTimeout(id);
  }, [heldClosed]);
  /** The list as it is when an answer comes, not as it was at the press. */
  const trustedNow = useRef(trusted);
  trustedNow.current = trusted;
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const fingerprint = trusted === null ? "" : JSON.stringify(trusted);
  useEffect(() => {
    if (slowFrom === null) return;
    if (fingerprint !== slowFrom) {
      // biome-ignore lint/suspicious/noConsole: once per slow write, when it lands
      console.debug("[access] the slow write landed: the list moved, «Сохраняем изменение…» off");
      setSlowFrom(null);
      return;
    }
    // The list may land unchanged (a write that changed nothing visible): not said for ever.
    const id = window.setTimeout(() => {
      // biome-ignore lint/suspicious/noConsole: once per slow write, the timeout taken
      console.debug("[access] «Сохраняем изменение…» off after 15 s with no change in the list");
      setSlowFrom(null);
    }, 15_000);
    return () => window.clearTimeout(id);
  }, [fingerprint, slowFrom]);

  // A device the open question is about went from the list (or got confirmed elsewhere): the
  // question has nothing left to ask.
  useEffect(() => {
    if (asking?.kind !== "allow" || trusted === null || sending) return;
    const still = personOf(trusted, asking.userId)?.attempts?.some(
      (a) => a.key_id === asking.keyId,
    );
    if (still === true) return;
    // biome-ignore lint/suspicious/noConsole: once per question overtaken by the list
    console.debug(
      `[access] allow question closed: the attempt of key ${asking.keyShort} is no longer in the list`,
    );
    setAsking(null);
    setFailure(null);
  }, [asking, trusted, sending]);

  // «Устройство другого человека» stays on its attempt while the attempt does: «Разрешить» would
  // only be refused again. Gone with the attempt.
  useEffect(() => {
    if (trusted === null) return;
    setAttemptNotes((notes) => {
      const kept = notes.filter(
        (n) =>
          n.kind !== "other_person" ||
          personOf(trusted, n.userId)?.attempts?.some((a) => a.key_id === n.keyId) === true,
      );
      return kept.length === notes.length ? notes : kept;
    });
  }, [trusted]);

  useEffect(() => {
    if (asking === null || trusted === null || sending) return;
    if (asking.kind !== "remove" && asking.kind !== "confirm") return;
    const now = trusted.people
      .flatMap((p) => p.devices)
      .find((d) => d.key_id === asking.device.key_id);
    const gone = now === undefined || (asking.kind === "confirm" && !now.unconfirmed);
    if (!gone) return;
    // biome-ignore lint/suspicious/noConsole: once per question overtaken by the list
    console.debug(
      `[access] ${asking.kind} question closed: key ${asking.device.key_short} is ${now === undefined ? "no longer in the list" : "confirmed already"}`,
    );
    setAsking(null);
    setFailure(null);
  }, [asking, trusted, sending]);

  // The allow question follows the role the press gives as the list says it now: a role that moved
  // replaces the shown one and clears «Это моё устройство» — a step given for one role is never
  // sent for another.
  useEffect(() => {
    if (asking === null || trusted === null || sending) return;
    const next = followList(asking, trusted);
    if (next === asking || next.kind !== "allow" || asking.kind !== "allow") return;
    const why =
      asking.waits !== null ? "the list read again after second_step came" : "the role moved";
    // biome-ignore lint/suspicious/noConsole: once per change under an open question
    console.debug(
      `[access] allow question for #${asking.userId}, key ${asking.keyShort}: ${why} (${asking.owner ? "owner" : "guest"} → ${next.owner ? "owner" : "guest"}); shown anew, its box ${asking.recognized ? "cleared" : "unticked"}`,
    );
    setAsking(next);
  }, [asking, trusted, sending]);

  // A row's question asked from the review has ended (answered, cancelled or closed): the review
  // again, with the window as it is now — never over a damaged list.
  useEffect(() => {
    if (!fromReview || asking !== null || sending) return;
    setFromReview(false);
    const again = reviewAgain(trusted, heldClosed);
    if (again === null) return;
    const said = heldClosed
      ? "the row's question closed as a session came: held, no token"
      : trusted?.clean
        ? "clean, token taken"
        : "not clean: held";
    // biome-ignore lint/suspicious/noConsole: once per row question asked from the review
    console.debug(`[access] back to the «Включить…?» review (window ${said})`);
    setAsking(again);
  }, [fromReview, asking, sending, trusted, heldClosed]);

  // A question held for good (no token taken as it opened, `session` answered, or the token moved)
  // while no session is on any more: it cannot pass, and a reopen takes a fresh token — closed.
  useEffect(() => {
    if (asking === null || trusted === null || sending || !trusted.clean) return;
    const held = questionHold(asking, trusted);
    if (held === null) return;
    // biome-ignore lint/suspicious/noConsole: once per question overtaken by the window
    console.debug(
      `[access] ${asking.kind} question closed: ${held}, and no session is on now — ask again for a fresh window`,
    );
    setAsking(null);
    setFailure(null);
    setHeldClosed(true);
  }, [asking, trusted, sending]);

  /** A new press: the last presses' notes go, but «Устройство другого человека» (it still holds). */
  const freshNotes = () =>
    setAttemptNotes((notes) =>
      notes.every((n) => n.kind === "other_person")
        ? notes
        : notes.filter((n) => n.kind === "other_person"),
    );

  /** A note on an attempt, in place of the one it had. */
  const note = (n: AttemptNote) => {
    // biome-ignore lint/suspicious/noConsole: once per answer that leaves a line on the row
    console.debug(
      `[access] attempt of #${n.userId}, key ${n.keyId.slice(0, 8)}: «${n.kind}»${n.code ? ` (${n.code})` : ""} on its row`,
    );
    setAttemptNotes((notes) => [...notes.filter((x) => x.keyId !== n.keyId), n]);
  };

  const open = (a: Asking, said: string) => {
    if (locked) return;
    if (asking?.kind === "mode" && asking.on && a.kind !== "mode") setFromReview(true);
    // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
    console.debug(`[access] ${said}: asking`);
    freshNotes();
    setFailure(null);
    setHeldClosed(false);
    setAsking(a);
  };

  const nameOf = (userId: number) => view.names.get(userId) ?? `#${userId}`;

  /** The token this question may use: the list's, if no session is on as it opens. */
  const openToken = () => (trusted?.clean ? trusted.token : null);

  const askMode = (on: boolean) =>
    open(
      { kind: "mode", on, token: on ? openToken() : null, spent: false },
      `mode switch pressed: asking to turn it ${on ? "on" : "off"}${on ? ` (window ${trusted?.clean ? "clean, token taken" : "not clean: held"})` : ""}`,
    );

  const askRemove = (userId: number, device: TrustedDeviceDto) => {
    const unbind = view.unbinds.includes(userId);
    open(
      { kind: "remove", userId, user: nameOf(userId), device },
      `«Удалить из доверенных» pressed on #${userId}, key ${device.key_short} (${device.kind ?? "unknown"}, ${device.dependents} dependent(s)${device.in_session ? ", in a session now" : ""}${unbind ? ", the row has «Отвязать»" : ", no «Отвязать» on the row"})`,
    );
  };

  const askConfirm = (userId: number, device: TrustedDeviceDto) =>
    open(
      {
        kind: "confirm",
        userId,
        user: nameOf(userId),
        device,
        token: openToken(),
        spent: false,
      },
      `«Подтвердить» pressed on #${userId}, key ${device.key_short} (${device.kind ?? "unknown"}, clean ${trusted?.clean ? "yes" : "no"}, ${attemptsOf(trusted, userId).length} attempt(s) from another device)`,
    );

  /** «Это моё устройство» ticked or unticked in the open allow question. */
  const recognize = (next: boolean) => {
    if (asking?.kind !== "allow" || sending) return;
    // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
    console.debug(
      `[access] «Это моё устройство» ${next ? "ticked" : "unticked"} for #${asking.userId}, key ${asking.keyShort}: the action ${next ? "may go" : "waits"}`,
    );
    setAsking({ ...asking, recognized: next });
  };

  const askRemovePerson = (userId: number) => {
    const count = devicesOf(trusted, userId)?.length ?? 0;
    open(
      { kind: "person", userId, user: nameOf(userId), count },
      `«Удалить все устройства» pressed on #${userId} (${count} device(s))`,
    );
  };

  /** The «Разрешить» question for an attempt, as it opens now. */
  const allowAsking = (
    userId: number,
    attempt: TrustedAttemptDto,
    keyId: string,
  ): Extract<Asking, { kind: "allow" }> => ({
    kind: "allow",
    userId,
    user: nameOf(userId),
    attempt,
    keyId,
    keyShort: attempt.key_short ?? keyId.slice(0, 8),
    owner: allowGivesOwner(trusted, userId),
    token: openToken(),
    spent: false,
    recognized: false,
    waits: null,
  });

  const pressAllow = (userId: number, attempt: TrustedAttemptDto) => {
    if (locked || sending) return;
    const keyId = attempt.key_id;
    if (keyId === undefined) return;
    const a = allowAsking(userId, attempt, keyId);
    const said = `«Разрешить» pressed on #${userId}'s attempt, key ${a.keyShort} (${attempt.kind ?? "unknown"}, ${attempt.count ?? 1} tries, gives ${a.owner ? "owner" : "guest"} access, clean ${trusted?.clean ? "yes" : "no"})`;
    if (allowPress(trusted, userId) === "ask") {
      open(a, `${said}, the second step needed`);
      return;
    }
    // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
    console.debug(`[access] ${said}: one press, no second step needed`);
    freshNotes();
    const next = commandFor(a, trusted);
    if ("held" in next) {
      // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
      console.debug(`[access] allow held: ${next.held}`);
      return;
    }
    const device = attemptDevice(attempt);
    run(next.what, () => send(next.command), {
      keep: asking !== null,
      failed: (code) => {
        if (code === "second_step" || code === "role") {
          // The agent knows an owner this list does not: asked, unticked, held for the next list
          // (which brings the role the press gives now).
          open(
            allowAfterSecondStep(a, trustedNow.current),
            `${said}: the agent ${code === "role" ? "gives another role now" : "wants the second step"} — held until the list is read again`,
          );
          return true;
        }
        const kind = allowNoteKind(code);
        if (kind === null) return false;
        if (kind === "quiet") {
          // biome-ignore lint/suspicious/noConsole: once per refusal, what the row does
          console.debug(`[access] ${said}: ${code} — no line, the list read again shows it`);
          return true;
        }
        note({ userId, keyId, device, kind, ...(kind === "failed" ? { code } : {}) });
        return true;
      },
    });
  };

  const pressHide = (userId: number, attempt: TrustedAttemptDto) => {
    if (locked || sending) return;
    const keyId = attempt.key_id;
    const token = openToken();
    if (keyId === undefined || token === null) return;
    const what = `attempt_hide #${userId} key ${attempt.key_short ?? keyId.slice(0, 8)}`;
    // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
    console.debug(`[access] «Скрыть» pressed on #${userId}'s attempt: one press`);
    freshNotes();
    run(what, () => attemptHide(userId, keyId, token), {
      keep: asking !== null,
      failed: (code) => {
        // Gone already, or the list read again shows the damage: nothing to add.
        if (code === "not_found" || code === "damaged" || code === "newer_version") return false;
        note({ userId, keyId, device: attemptDevice(attempt), kind: "failed", code });
        return true;
      },
    });
  };

  const askRemoveAttempts = (userId: number) =>
    open(
      { kind: "attempts", userId, user: nameOf(userId) },
      `«Удалить попытки» pressed on #${userId} (${personOf(trusted, userId)?.attempts?.length ?? 0} attempt(s), no device)`,
    );

  const askRestore = () =>
    open(
      { kind: "restore", token: openToken(), spent: false },
      `«Восстановить из копии» pressed (window ${trusted?.clean ? "clean, token taken" : "not clean: held"})`,
    );

  /** A damaged list's button: «Повторить» runs at once, the other two ask first. */
  const pressRepair = (action: TrustedRepair) => {
    switch (repairPress(action)) {
      case "run":
        repair("reopen");
        return;
      case "ask-restore":
        askRestore();
        return;
      case "ask-reset":
        askReset();
        return;
    }
  };

  const askReset = () => open({ kind: "reset" }, "«Начать список заново» pressed");

  const cancel = (why: string) => {
    if (sending) {
      // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
      console.debug(`[access] ${asking?.kind ?? "-"} question: ${why} ignored, its command runs`);
      return;
    }
    // biome-ignore lint/suspicious/noConsole: the owner's answer, once per question
    console.debug(`[access] ${asking?.kind ?? "-"} question closed: ${why}, nothing changed`);
    setAsking(null);
    setFailure(null);
  };

  /** What a question does with a failed command (`failurePlan`). */
  const afterFailure = (what: string, code: TrustedError) => {
    const plan = failurePlan(code);
    if (plan.question === "untick") {
      // biome-ignore lint/suspicious/noConsole: once per refusal, what the question does
      console.debug(
        `[access] ${what}: the agent wants the second step for the role it gives now — its box cleared, the list read again`,
      );
    }
    if (plan.question === "close") {
      // biome-ignore lint/suspicious/noConsole: once per refusal, what the question does
      console.debug(
        `[access] ${what}: ${code} — the question closes, the list read again says it${plan.slow ? " («Сохраняем изменение…»)" : ""}`,
      );
    }
    setAsking((a) => questionAfter(a, plan));
    if (plan.slow) setSlowFrom(fingerprint);
    if (plan.line !== null) setFailure(plan.line);
  };

  /** The answer to a question: its command, with the dialog open until it answers. */
  const run = (
    what: string,
    call: () => Promise<unknown>,
    on: {
      /** Handles a failure itself (true) or leaves it to the question (false). */
      failed?: (code: TrustedError) => boolean;
      /** A one-press action under an open question (the review): the question stays. */
      keep?: boolean;
    } = {},
  ) => {
    setSending(true);
    setFailure(null);
    // biome-ignore lint/suspicious/noConsole: the owner's answer, once per question
    console.info(`[access] ${what}: sending`);
    call()
      .then(
        (answer) => {
          // biome-ignore lint/suspicious/noConsole: once per command, its outcome
          console.info(
            `[access] ${what}: done${typeof answer === "number" ? `, ${answer} counted` : typeof answer === "string" ? `, ${answer}` : ""}`,
          );
          if (!alive.current) return;
          if (on.keep !== true) setAsking(null);
        },
        (e: unknown) => {
          const code = trustedError(e);
          console.warn(
            `[ipc] ${what} failed: ${code}${code === "refused" ? ` (${String(e)})` : ""}`,
          );
          if (!alive.current) return;
          // The press's own handler may say it itself (a line on the row, the question anew).
          if (on.failed?.(code) !== true) afterFailure(what, code);
        },
      )
      .finally(() => {
        if (alive.current) setSending(false);
        onChanged();
      });
  };

  const confirm = () => {
    if (asking === null || sending || locked) return;
    const next = commandFor(asking, trusted);
    if ("held" in next) {
      // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
      console.debug(`[access] ${asking.kind} held: ${next.held}`);
      return;
    }
    if (asking.kind !== "allow") {
      run(next.what, () => send(next.command));
      return;
    }
    // The dialog closes on an answer about the attempt; its line goes on the row (none when the
    // list read again shows it). `second_step` and a failed write stay in the dialog, as
    // «Подтвердить»'s.
    const { userId, keyId } = asking;
    const device = attemptDevice(asking.attempt);
    run(next.what, () => send(next.command), {
      failed: (code) => {
        const kind = allowNoteKind(code);
        if (kind === null || kind === "failed") return false;
        setAsking(null);
        setFailure(null);
        if (kind === "quiet") {
          // biome-ignore lint/suspicious/noConsole: once per refusal, what the dialog does
          console.debug(
            `[access] ${next.what}: ${code} — closed, no line, the list read again shows it`,
          );
          return true;
        }
        note({ userId, keyId, device, kind });
        return true;
      },
    });
  };

  const repair = (action: Exclude<TrustedRepair, "reset" | "restore">) => {
    if (repairing || locked) return;
    setRepairing(true);
    setRepairFailure(null);
    // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
    console.info(`[access] repair_trusted(${action}): sending`);
    repairTrusted(action)
      .then(
        () => {
          // biome-ignore lint/suspicious/noConsole: once per command, its outcome
          console.info(`[access] repair_trusted(${action}): done`);
        },
        (e: unknown) => {
          const code = trustedError(e);
          console.warn(
            `[ipc] repair_trusted(${action}) failed: ${code}${code === "refused" ? ` (${String(e)})` : ""}`,
          );
          // `damaged` / `newer_version`: still damaged, the block says so already.
          if (alive.current && failureText(t, code) !== null) setRepairFailure(code);
        },
      )
      .finally(() => {
        if (alive.current) setRepairing(false);
        onChanged();
      });
  };

  const dialog =
    asking === null
      ? null
      : questionDialog(
          asking,
          trusted,
          view,
          recognize,
          {
            sending,
            failure,
            locked,
            onCancel: cancel,
            onConfirm: confirm,
          },
          t("app.trustedBusySession"),
          {
            notes: attemptNotes,
            busy: sending,
            full: trusted?.full === true,
            onConfirm: (userId, d) => askConfirm(userId, d),
            onRemove: (userId, d) => askRemove(userId, d),
            onAllow: (userId, a) => pressAllow(userId, a),
            onHide: (userId, a) => pressHide(userId, a),
            onRemoveAttempts: (userId) => askRemoveAttempts(userId),
          },
        );

  return {
    askMode,
    askRemove,
    askConfirm,
    askRemovePerson,
    pressAllow,
    pressHide,
    askRemoveAttempts,
    attemptNotes,
    busy: sending,
    full: trusted?.full === true,
    askRestore,
    askReset,
    pressRepair,
    repair,
    repairing,
    repairNotice: repairFailure === null ? null : failureText(t, repairFailure),
    notice:
      slowFrom !== null
        ? t("app.trustedSaveSlow")
        : heldClosed
          ? t("app.trustedBusySession")
          : null,
    dialog,
  };
}

/**
 * What a question does with a failed command — the list is read again after every command
 * either way:
 * - `session`: the window it opened with is over — held until asked again, the line said;
 * - `second_step`: the agent wants the owner's step the list at the press did not ask for — its
 *   box cleared, asked again, never sent again by itself;
 * - `role`: the agent derives another role for the person than the dialog showed (an owner came or
 *   went) — as `second_step`, the dialog follows the list to the role it gives now;
 * - `slow`: closed, «Сохраняем изменение…» under the layers until the list moves;
 * - `damaged`, `newer_version`, `not_found`: closed, nothing said — the list read again shows
 *   the damaged block or the device gone, so nothing is left looking done;
 * - anything else: kept open with its line (`failureText`), to be pressed again.
 */
export function failurePlan(code: TrustedError): {
  question: "spend" | "untick" | "close" | "keep";
  line: TrustedError | null;
  slow: boolean;
} {
  switch (code) {
    case "session":
      return { question: "spend", line: code, slow: false };
    case "second_step":
    case "role":
      return { question: "untick", line: null, slow: false };
    case "slow":
      return { question: "close", line: null, slow: true };
    case "damaged":
    case "newer_version":
    case "not_found":
      return { question: "close", line: null, slow: false };
    default:
      return { question: "keep", line: code, slow: false };
  }
}

/**
 * Why an open question's action is held by the window (a session on, or one since it opened), or
 * null: mode-on, confirm, «Разрешить» and restore need the clean window they opened with
 * (`windowHold`); the rest nothing.
 */
export function questionHold(a: Asking, trusted: TrustedDto | null): string | null {
  switch (a.kind) {
    case "mode":
      return a.on ? windowHold(a, trusted) : null;
    case "confirm":
    case "allow":
    case "restore":
      return windowHold(a, trusted);
    default:
      return null;
  }
}

/** The open question's dialog. */
function questionDialog(
  asking: Asking,
  trusted: TrustedDto | null,
  view: TrustedPeopleView,
  onRecognize: (next: boolean) => void,
  props: QuestionProps,
  /** The line a held action shows: «Сейчас идёт сеанс…». */
  busy: string,
  review: ReviewActions,
): ReactNode {
  const hold = questionHold(asking, trusted) === null ? null : busy;
  switch (asking.kind) {
    case "mode":
      return (
        <ModeDialog
          on={asking.on}
          trusted={trusted}
          view={view}
          hold={hold}
          review={review}
          {...props}
        />
      );
    case "remove":
      return (
        <RemoveDialog
          asking={asking}
          unbind={view.unbinds.includes(asking.userId)}
          trusted={trusted}
          {...props}
        />
      );
    case "confirm":
      return (
        <ConfirmDialog
          asking={asking}
          attempt={attemptsOf(trusted, asking.userId)[0]?.at ?? null}
          hold={hold}
          {...props}
        />
      );
    case "person":
      return <RemovePersonDialog asking={asking} {...props} />;
    case "allow":
      return (
        <AllowDialog
          asking={asking}
          needsStep={allowWaiting(asking, trusted) || allowPress(trusted, asking.userId) === "ask"}
          waiting={allowWaiting(asking, trusted)}
          onRecognize={onRecognize}
          hold={hold}
          {...props}
        />
      );
    case "attempts":
      return <RemoveAttemptsDialog asking={asking} {...props} />;
    case "restore":
      return <RestoreDialog hold={hold} {...props} />;
    case "reset":
      return <ResetDialog trusted={trusted} {...props} />;
  }
}

interface QuestionProps {
  sending: boolean;
  failure: TrustedError | null;
  locked: boolean;
  onCancel: (why: string) => void;
  onConfirm: () => void;
}

/**
 * The question's lines, one paragraph each, over its two buttons; under the lines, what holds the
 * action (`hold`: a session is on) or how the last press went. The action waits (`aria-disabled`,
 * focus kept) while its command runs and while held.
 */
function Question({
  title,
  lines,
  action,
  actionVariant,
  hold = null,
  gated = false,
  sending,
  failure,
  locked,
  onCancel,
  onConfirm,
}: {
  title: string;
  lines: ReactNode[];
  action: string;
  actionVariant: "primary" | "destructive";
  /** The action is held, with this line as the reason. */
  hold?: string | null;
  /** The action waits for something in the lines (a box to tick), with no line of its own. */
  gated?: boolean;
} & QuestionProps) {
  const t = useT();
  const cancelRef = useRef<HTMLButtonElement>(null);
  const said = locked
    ? t("app.trustedBusySession")
    : failure !== null
      ? failureText(t, failure)
      : hold;
  const waits = sending || locked || gated || hold !== null;
  // The status line and the buttons stay whole under the lines, however long the review grows:
  // the lines scroll, the answer to the press never hides under them.
  const footer = (
    <div className="flex flex-col gap-3">
      <p
        role="status"
        className={cn(
          "text-body empty:hidden",
          failure !== null && failure !== "session" ? "text-danger" : "text-attention",
        )}
      >
        {said}
      </p>
      <div className="flex gap-2">
        <Button ref={cancelRef} className="flex-1" onClick={() => onCancel("«Отмена»")}>
          {t("common.cancel")}
        </Button>
        <Button
          variant={actionVariant}
          className="flex-1"
          disabled={locked}
          aria-disabled={waits || undefined}
          onClick={() => !waits && onConfirm()}
        >
          {action}
        </Button>
      </div>
    </div>
  );
  return (
    <Dialog
      title={title}
      titleWraps
      onClose={(why) => onCancel(why)}
      initialFocus={cancelRef}
      footer={footer}
    >
      <div className="flex flex-col gap-2 text-body text-muted">
        {lines.map((line, i) => (
          // The lines are fixed for the dialog's life: their place is their key.
          // biome-ignore lint/suspicious/noArrayIndexKey: see above
          <div key={i}>{line}</div>
        ))}
      </div>
    </Dialog>
  );
}

/**
 * «Включить…?» shows who will not connect through the review sections (`ReviewSections`), under
 * the owner-device warning when there is none. Both actions wait while a session locks changes;
 * turning on also observes the question's clean-window token.
 */
function ModeDialog({
  on,
  trusted,
  view,
  hold,
  review,
  ...props
}: {
  on: boolean;
  trusted: TrustedDto | null;
  view: TrustedPeopleView;
  /** «Включить» held, with this line (`windowHold`). */
  hold: string | null;
  review: ReviewActions;
} & QuestionProps) {
  const t = useT();
  const { locale } = useLanguage();
  const { missing, owners, unconfirmed } = wontConnect(on ? trusted : null, view);
  const blocked = modeBlocked(trusted);
  useModeLog(
    on,
    { missing: missing.length, owners, blocked },
    unconfirmed.length,
    trusted?.clean ?? false,
    locale,
  );
  if (!on) {
    return (
      <Question
        title={t("app.trustedOffTitle")}
        lines={[t("app.trustedOffNote")]}
        action={t("app.trustedOffAction")}
        actionVariant="primary"
        {...props}
      />
    );
  }
  const lines: ReactNode[] = [t("app.trustedOnNote")];
  // No confirmed owner-role device here (it went while the dialog was open, or an older list never
  // had one): «Включить» waits, and says what to do. The agent's reading (`owner_device`), not
  // worked out here. With one — anyone's — the switch is open, and an owner by the bindings with
  // no device of his own is named once, with the others who will not connect (the review's
  // «Ещё не подключались с ключом доступа»).
  if (blocked) {
    lines.push(
      <div>
        <p className="text-balance text-attention">{t("app.trustedOnOwnerMissing")}</p>
        <p className="text-balance text-hint text-muted">{t(ownerMissingStep(trusted))}</p>
      </div>,
    );
  }
  lines.push(<p className="text-balance">{t("app.trustedOnReview")}</p>);
  lines.push(
    <ReviewSections trusted={trusted} view={view} locked={props.locked} review={review} />,
  );
  return (
    <Question
      title={t("app.trustedOnTitle")}
      lines={lines}
      action={t("app.trustedOnAction")}
      actionVariant="primary"
      hold={hold}
      gated={blocked}
      {...props}
    />
  );
}

/**
 * The review's sections under «Включить…?»'s intro, each under its heading and only when it has
 * someone: the owner's devices, the guests', the attempts, then who has no device at all. Every
 * row has the list's own actions — «Подтвердить» / «Удалить», «Разрешить» / «Скрыть» — which ask
 * their own question and bring the review back after it; a session locks them as it locks the list.
 */
function ReviewSections({
  trusted,
  view,
  locked,
  review,
}: {
  trusted: TrustedDto | null;
  view: TrustedPeopleView;
  locked: boolean;
  review: ReviewActions;
}) {
  const t = useT();
  const { owner, guests, attempts, missing } = reviewOf(trusted, view);
  const devicesOfPeople = (people: ReviewPerson[]) =>
    people.map((p) => (
      <div key={p.id}>
        <p className="mb-1 truncate text-hint text-muted" title={p.name}>
          {p.name}
        </p>
        <PersonDevices
          devices={p.devices}
          mode
          locked={locked}
          review
          onRemove={(d) => review.onRemove(p.id, d)}
          onConfirm={(d) => review.onConfirm(p.id, d)}
          onAddDevice={() => undefined}
        />
      </div>
    ));
  const [onlyMissing] = missing;
  return (
    <div className="flex flex-col gap-3">
      {owner.length > 0 ? (
        <ReviewSection title={t("app.trustedOnOwner")}>{devicesOfPeople(owner)}</ReviewSection>
      ) : null}
      {guests.length > 0 ? (
        <ReviewSection title={t("app.trustedOnGuests")}>{devicesOfPeople(guests)}</ReviewSection>
      ) : null}
      {attempts.length > 0 ? (
        <ReviewSection title={t("app.trustedOnAttempts")}>
          {attempts.map((p) => (
            <div key={p.id}>
              <p className="mb-1 truncate text-hint text-muted" title={p.name}>
                {p.name}
              </p>
              <PersonAttempts
                attempts={p.attempts}
                notes={review.notes.filter((n) => n.userId === p.id)}
                locked={locked}
                busy={review.busy}
                full={review.full}
                removable={p.devices.length === 0 && !p.owner}
                about={false}
                onAllow={(a) => review.onAllow(p.id, a)}
                onHide={(a) => review.onHide(p.id, a)}
                onRemoveAttempts={() => review.onRemoveAttempts(p.id)}
              />
            </div>
          ))}
          <p className="text-balance text-hint text-muted">{t("app.trustedAttemptAbout")}</p>
        </ReviewSection>
      ) : null}
      {onlyMissing !== undefined ? (
        <ReviewSection title={t("app.trustedOnNoKey")}>
          <p className="text-balance text-attention">
            {missing.length === 1
              ? t("app.trustedOnMissingOne", { name: onlyMissing })
              : t("app.trustedOnMissingMany", { names: missing.join(", ") })}
          </p>
        </ReviewSection>
      ) : null}
    </div>
  );
}

/** A section of the review: its heading over its rows. */
function ReviewSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-1">
      <h3 className="text-body font-medium text-ink">{title}</h3>
      {children}
    </section>
  );
}

/**
 * Who will not connect once the mode is on: people with access and no device at all — an owner by
 * the bindings among them (`owners` counts those, for the log) — and the unconfirmed devices of
 * the others. Nothing without a list.
 */
function wontConnect(
  trusted: TrustedDto | null,
  view: TrustedPeopleView,
): {
  missing: string[];
  owners: number;
  unconfirmed: { user: string; device: TrustedDeviceDto }[];
} {
  const missing: string[] = [];
  let owners = 0;
  const unconfirmed: { user: string; device: TrustedDeviceDto }[] = [];
  if (trusted === null) return { missing, owners, unconfirmed };
  for (const id of view.bound) {
    const devices = devicesOf(trusted, id) ?? [];
    const user = view.names.get(id) ?? `#${id}`;
    if (devices.length === 0) {
      missing.push(user);
      if (view.owners.includes(id)) owners += 1;
    }
    for (const d of devices) if (d.unconfirmed) unconfirmed.push({ user, device: d });
  }
  return { missing, owners, unconfirmed };
}

/** What «Включить…?» says, once per change («Выключить…?» says nothing to count). */
function useModeLog(
  on: boolean,
  { missing, owners, blocked }: { missing: number; owners: number; blocked: boolean },
  unconfirmed: number,
  clean: boolean,
  locale: Locale,
) {
  useEffect(() => {
    if (!on) return;
    const ownersSaid = blocked
      ? "no confirmed owner device here — «Включить» held"
      : "the switch open";
    // biome-ignore lint/suspicious/noConsole: once per change of the question's lines
    console.debug(
      `[access] «Включить…?»: ${missing} person(s) without a device (${owners} of them owner(s) by the bindings), ${ownersSaid}, ${unconfirmed} unconfirmed device(s), clean ${clean ? "yes" : "no — «Включить» held"} (${locale})`,
    );
  }, [on, missing, owners, blocked, unconfirmed, clean, locale]);
}

/**
 * What «Удалить из доверенных?» says about `d` of `who`: the note for the mode — on: the owner's
 * (`app.trustedUntrustNoteOwn`) when the device's person is the owner on this PC (the core's reading,
 * `allowGivesOwner`), else the guest's (`app.trustedUntrustNote`) and, only when the person's row
 * draws «Отвязать» (`who.unbind`: `TrustedPeopleView.unbinds`, the row's `unbindShown`),
 * `app.trustedUntrustCutOff` right under it; off:
 * `app.trustedUntrustNoteObserve` — then «Сеанс с него прервётся сразу» while `d` is in a session, the
 * dependents' count, and their sessions' line while one of them is — all but the note in both modes.
 * `chain`: what the list names of the dependents.
 */
export function untrustLines(
  t: T,
  locale: Locale,
  trusted: TrustedDto | null,
  who: { userId: number; user: string; unbind: boolean },
  d: TrustedDeviceDto,
): { lines: string[]; chain: { found: number; live: boolean } } {
  const mode = trusted?.trusted_mode ?? false;
  const values = { user: who.user, device: deviceName(t, d) };
  const own = allowGivesOwner(trusted, who.userId);
  const lines = !mode
    ? [t("app.trustedUntrustNoteObserve", values)]
    : own
      ? [t("app.trustedUntrustNoteOwn", values)]
      : [
          t("app.trustedUntrustNote", values),
          ...(who.unbind ? [t("app.trustedUntrustCutOff")] : []),
        ];
  // The sessions end at once in both modes (the agent's sweep ends every session a removed key
  // signed): said whenever one is live.
  if (d.in_session) lines.push(t("app.trustedUntrustLive"));
  const chain = trusted === null ? { found: 0, live: false } : dependentsOf(trusted, d.key_id);
  if (d.dependents > 0) {
    lines.push(t(plural(locale, d.dependents, DEPENDENTS), { count: d.dependents }));
    if (chain.live) lines.push(t("app.trustedUntrustDependentsLive"));
  }
  return { lines, chain };
}

/**
 * «Удалить из доверенных?»: the device, its session ending at once while it has one, and the devices
 * removed with it (`dependents`, with «Сеансы с этих устройств…» when one of those the list can
 * name is in a session — `dependentsOf`). With the mode off the question says
 * the device still connects until the mode goes on (`app.trustedUntrustNoteObserve`); the session
 * lines stay — the sessions end at once in both modes.
 */
function RemoveDialog({
  asking,
  unbind,
  trusted,
  ...props
}: {
  asking: Extract<Asking, { kind: "remove" }>;
  /** The person's row draws «Отвязать» now (`TrustedPeopleView.unbinds`). */
  unbind: boolean;
  trusted: TrustedDto | null;
} & QuestionProps) {
  const t = useT();
  const { locale } = useLanguage();
  const d = asking.device;
  const mode = trusted?.trusted_mode ?? false;
  const { lines, chain } = untrustLines(
    t,
    locale,
    trusted,
    { userId: asking.userId, user: asking.user, unbind },
    d,
  );
  const own = allowGivesOwner(trusted, asking.userId);
  useEffect(() => {
    const note = !mode
      ? "off — the observe note"
      : own
        ? "on — the owner's note"
        : `on — the guest's note${unbind ? " and «Отвязать»'s line (the row has «Отвязать»)" : " (no «Отвязать» on the row: no line)"}`;
    // biome-ignore lint/suspicious/noConsole: once per question, what it says
    console.debug(
      `[access] «Удалить из доверенных?» key ${d.key_short}, mode ${note}: ${d.in_session ? "in a session, " : ""}${d.dependents} dependent(s), ${chain.found} named by by_key_id, ${chain.live ? "one in a session" : "none in a session"}${chain.found < d.dependents ? " (the rest have no by_key_id: their sessions unknown)" : ""}`,
    );
  }, [mode, own, unbind, d.key_short, d.in_session, d.dependents, chain.found, chain.live]);
  return (
    <Question
      title={t("app.trustedUntrustTitle")}
      lines={lines}
      action={t("app.trustedUntrustAction")}
      actionVariant="destructive"
      {...props}
    />
  );
}

/**
 * «Подтвердить устройство?»: the device — its name, where it came from, the first characters of its
 * key, when it was added, its last connection — then what confirming means. Held while a session is
 * on (`clean`).
 *
 * When someone tried to connect as the person from a device not in the list, the latest attempt is
 * said in amber («{user}: попытка подключения с другого устройства. Последняя: {when}»): the
 * device to confirm may be that other one. One press: no box.
 */
function ConfirmDialog({
  asking,
  attempt,
  hold,
  ...props
}: {
  asking: Extract<Asking, { kind: "confirm" }>;
  /** The latest attempt from another device (unix ms), or null: none. */
  attempt: number | null;
  /** «Подтвердить» held, with this line (`windowHold`). */
  hold: string | null;
} & QuestionProps) {
  const t = useT();
  const { locale } = useLanguage();
  const now = Date.now();
  const d = asking.device;
  const name = deviceName(t, d);
  const source = sourceText(t, d.source, d.by);
  const details = (
    <div className="rounded-inner border border-line bg-ground/40 px-3 py-2">
      <p className="truncate text-body text-ink" title={name}>
        {name}
      </p>
      {source ? <p className="text-hint text-faint">{source}</p> : null}
      <p className="text-hint text-faint tabular-nums">
        {t("app.trustedConfirmKey", { key: d.key_short })}
      </p>
      <p className="text-hint text-faint">
        {t("app.trustedConfirmAdded", { when: whenText(t, locale, d.added_at, now) })}
      </p>
      <p className="text-hint text-faint">{lastUsedText(t, locale, d, now)}</p>
    </div>
  );
  const lines: ReactNode[] = [
    details,
    t("app.trustedConfirmNote", { user: asking.user, device: name }),
  ];
  if (attempt !== null) {
    lines.push(
      <p className="text-attention">
        {t("app.trustedConfirmAttempt", {
          user: asking.user,
          when: whenText(t, locale, attempt, now),
        })}
      </p>,
    );
  }
  return (
    <Question
      title={t("app.trustedConfirmTitle")}
      lines={lines}
      action={t("app.trustedConfirmAction")}
      actionVariant="primary"
      hold={hold}
      {...props}
    />
  );
}

/** A person's connection attempts from devices not in the list, newest first (none: an older agent). */
function attemptsOf(trusted: TrustedDto | null, id: number): { at: number }[] {
  return trusted?.people.find((p) => p.telegram_user_id === id)?.attempts ?? [];
}

/** «Удалить все устройства?» for a person with no access left. */
function RemovePersonDialog({
  asking,
  ...props
}: { asking: Extract<Asking, { kind: "person" }> } & QuestionProps) {
  const t = useT();
  return (
    <Question
      title={t("app.trustedRemovePersonTitle")}
      lines={[t("app.trustedRemovePersonNote", { user: asking.user, count: asking.count })]}
      action={t("app.trustedRemovePersonAction")}
      actionVariant="destructive"
      {...props}
    />
  );
}

/**
 * «Разрешить устройство?» — an attempt of the owner (`needs_second_step`): the device as its key
 * card names it, «Не проверено» and its tries; that the person will connect with it even with the
 * mode on; in amber, that it gets the owner's access, and the box «Это моё устройство».
 * «Разрешить» waits for the box.
 */
function AllowDialog({
  asking,
  needsStep,
  waiting,
  onRecognize,
  hold,
  ...props
}: {
  asking: Extract<Asking, { kind: "allow" }>;
  /** The agent wants the second step (`allowPress`, or its `second_step` answer): the box. */
  needsStep: boolean;
  /** The list is being read again after `second_step` (`allowWaiting`): the box waits for it. */
  waiting: boolean;
  onRecognize: (next: boolean) => void;
  /** «Разрешить» held, with this line (`windowHold`). */
  hold: string | null;
} & QuestionProps) {
  const t = useT();
  const { locale } = useLanguage();
  const now = Date.now();
  const a = asking.attempt;
  const name = deviceName(t, attemptDevice(a));
  const details = (
    <div className="rounded-inner border border-line bg-ground/40 px-3 py-2">
      <p className="truncate text-body text-ink" title={name}>
        {name}
      </p>
      <NotVerifiedMark />
      <p className="text-hint text-faint">{attemptSpan(t, locale, a, now)}</p>
      <p className="text-hint text-faint tabular-nums">
        {t("app.trustedConfirmKey", { key: asking.keyShort })}
      </p>
    </div>
  );
  const lines: ReactNode[] = [
    details,
    t("app.trustedAllowNote", { user: asking.user, device: name }),
  ];
  if (asking.owner) {
    lines.push(<p className="text-attention">{t("app.trustedAllowOwner")}</p>);
  }
  if (needsStep) {
    lines.push(
      <Checkbox
        checked={asking.recognized}
        disabled={props.sending || waiting}
        onCheckedChange={onRecognize}
      >
        {t("app.trustedAllowOwnerCheck")}
      </Checkbox>,
    );
  }
  return (
    <Question
      title={t("app.trustedAllowTitle")}
      lines={lines}
      action={t("app.trustedAllowAction")}
      actionVariant="primary"
      hold={hold}
      gated={needsStep && !asking.recognized}
      {...props}
    />
  );
}

/** «Не проверено» in amber: whose device an attempt is, the PC cannot tell. */
export function NotVerifiedMark() {
  const t = useT();
  return (
    <p className="flex items-center gap-1.5 text-hint text-attention">
      <span aria-hidden="true" className="size-1.5 shrink-0 rounded-full bg-current" />
      {t("app.trustedNotVerified")}
    </p>
  );
}

/** «Удалить попытки подключения?» — a guest with attempts and no device: a removal at this PC. */
function RemoveAttemptsDialog({
  asking,
  ...props
}: { asking: Extract<Asking, { kind: "attempts" }> } & QuestionProps) {
  const t = useT();
  return (
    <Question
      title={t("app.trustedRemoveAttemptsTitle")}
      lines={[t("app.trustedRemoveAttemptsNote", { user: asking.user })]}
      action={t("app.trustedRemove")}
      actionVariant="destructive"
      {...props}
    />
  );
}

/**
 * «Восстановить из копии?» (asked first, as «Начать список заново»): the list goes
 * back to the backup — a device may come back, one may go — and the switch stays as it is. The
 * restore runs only on «Восстановить».
 */
function RestoreDialog({ hold, ...props }: { hold: string | null } & QuestionProps) {
  const t = useT();
  return (
    <Question
      title={t("app.trustedRestoreTitle")}
      lines={[t("app.trustedRestoreNote")]}
      action={t("app.trustedRestoreAction")}
      actionVariant="primary"
      hold={hold}
      {...props}
    />
  );
}

/**
 * What «Начать список заново?» says: the switch stays (the agent keeps the effective one), and —
 * exactly when the result is strict, `trusted_mode` (while damaged: the mode file's, on when it
 * says nothing) — that nobody connects until devices are added again (`attention`).
 */
export function resetLines(
  t: T,
  trusted: TrustedDto | null,
): { text: string; attention: boolean }[] {
  const lines = [{ text: t("app.trustedResetNote"), attention: false }];
  if (trusted?.trusted_mode ?? true) {
    lines.push({ text: t("app.trustedResetNoteOn"), attention: true });
  }
  return lines;
}

/** «Начать список заново?» (`resetLines`). */
function ResetDialog({ trusted, ...props }: { trusted: TrustedDto | null } & QuestionProps) {
  const t = useT();
  const lines: ReactNode[] = resetLines(t, trusted).map((l) =>
    l.attention ? (
      <span key={l.text} className="text-attention">
        {l.text}
      </span>
    ) : (
      l.text
    ),
  );
  return (
    <Question
      title={t("app.trustedResetTitle")}
      lines={lines}
      action={t("app.trustedResetAction")}
      actionVariant="destructive"
      {...props}
    />
  );
}

/*
 * A person's connection attempts in «Доступ» (§10.2): devices the PC does not know that tried to
 * connect as this person. Each is shown as its key card names it, with «Не проверено» — whose device it is,
 * the PC cannot tell — how many times and when, and the row's two quiet actions «Разрешить» and
 * «Скрыть». What a press left to say stays under its attempt (`AttemptNote`), or above the list once
 * the attempt is gone (past its time or taken by a removal); a device added meanwhile shows in the
 * list with no line.
 */

/**
 * Whether an attempt row offers «Разрешить»: not when the press would be refused for a reason the
 * list already says — the device is another person's (`other_person`: refused again), or the list
 * is full (`full`). The row says what to do instead.
 */
export function attemptAllowOffered(note: AttemptNote | undefined, full: boolean): boolean {
  return note?.kind !== "other_person" && !full;
}

/**
 * The first 8 characters of an attempt's key, as the owner compares it with the device's own
 * («Ключ доступа: …»): the agent's `key_short`, else cut from `key_id`; null with neither.
 */
export function attemptKeyShort(a: TrustedAttemptDto): string | null {
  return a.key_short ?? a.key_id?.slice(0, 8) ?? null;
}

/**
 * The attempts block of an open row: the attempts, newest first; under them, once, why «Разрешить»
 * needs care (`app.trustedAttemptAbout`); and «Удалить попытки» for a guest with nothing but attempts
 * (`removable`). `notes`: this person's notes.
 */
export function PersonAttempts({
  attempts,
  notes,
  locked,
  busy,
  full = false,
  removable,
  about = true,
  onAllow,
  onHide,
  onRemoveAttempts,
}: {
  attempts: TrustedAttemptDto[];
  notes: AttemptNote[];
  /** A session locks the controls (`clean` false). */
  locked: boolean;
  /** A command runs: the presses wait. */
  busy: boolean;
  /**
   * The list is full (`TrustedDto.full`): «Разрешить» would be refused `full`, so it is not
   * offered, and the row says what to do instead.
   */
  full?: boolean;
  removable: boolean;
  /** The explanation under the list; off where a section says it once for everyone (the review). */
  about?: boolean;
  onAllow: (attempt: TrustedAttemptDto) => void;
  onHide: (attempt: TrustedAttemptDto) => void;
  onRemoveAttempts: () => void;
}) {
  const t = useT();
  const { locale } = useLanguage();
  const now = Date.now();
  const held = locked || busy;
  const listed = new Set(attempts.map((a) => a.key_id));
  const gone = notes.filter((n) => !listed.has(n.keyId));
  if (attempts.length === 0 && gone.length === 0) return null;
  return (
    <div className="mb-2 flex flex-col gap-2">
      {gone.map((n) => (
        <div key={n.keyId} className="px-1">
          <p className="truncate text-hint text-faint">{deviceName(t, n.device)}</p>
          <NoteLines note={n} />
        </div>
      ))}
      {attempts.length > 0 ? (
        <>
          <ul className="overflow-hidden rounded-inner border border-line bg-ground/40">
            {attempts.map((a) => {
              const name = deviceName(t, attemptDevice(a));
              const note = notes.find((n) => n.keyId === a.key_id);
              // «Устройство другого человека»: «Разрешить» would be refused again — «Скрыть» alone.
              const allow = attemptAllowOffered(note, full);
              const key = attemptKeyShort(a);
              return (
                <li
                  key={a.key_id ?? a.at}
                  className="border-t border-line px-3 py-2 first:border-t-0"
                >
                  <p className="truncate text-body text-ink" title={name}>
                    {name}
                  </p>
                  <NotVerifiedMark />
                  <p className="text-hint text-faint">{attemptSpan(t, locale, a, now)}</p>
                  {key === null ? null : (
                    <p className="text-hint text-faint tabular-nums">
                      {t("app.trustedConfirmKey", { key })}
                    </p>
                  )}
                  {note ? <NoteLines note={note} /> : null}
                  {full && note?.kind !== "other_person" ? (
                    <p className="text-hint text-balance text-attention">{t("app.trustedFull")}</p>
                  ) : null}
                  {/* Quiet text actions, neutral, as a device's (`CARD_ACTIONS`). */}
                  <div className={CARD_ACTIONS}>
                    {allow ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        className={CARD_ACTION}
                        disabled={locked}
                        aria-disabled={held || undefined}
                        onClick={() => !held && onAllow(a)}
                      >
                        {t("app.trustedAttemptAllow")}
                      </Button>
                    ) : null}
                    <Button
                      variant="ghost"
                      size="sm"
                      className={CARD_ACTION}
                      disabled={locked}
                      aria-disabled={held || undefined}
                      onClick={() => !held && onHide(a)}
                    >
                      {t("app.trustedAttemptHide")}
                    </Button>
                  </div>
                </li>
              );
            })}
          </ul>
          {about ? (
            <p className="text-balance text-hint text-muted">{t("app.trustedAttemptAbout")}</p>
          ) : null}
        </>
      ) : null}
      {removable && attempts.length > 0 ? (
        <Button
          size="sm"
          className="w-full text-danger"
          aria-haspopup="dialog"
          disabled={locked}
          aria-disabled={held || undefined}
          onClick={() => !held && onRemoveAttempts()}
        >
          <Trash2 aria-hidden="true" />
          {t("app.trustedRemoveAttempts")}
        </Button>
      ) : null}
    </div>
  );
}

/** A note's lines under its attempt: amber what went wrong, muted what to do, red a failed write. */
function NoteLines({ note }: { note: AttemptNote }) {
  const t = useT();
  return (
    <div role="status" className="mt-1">
      {attemptNoteSaid(t, note).map((line) => (
        <p
          key={line.text}
          className={cn(
            "text-balance text-hint",
            line.tone === "attention" && "text-attention",
            line.tone === "muted" && "text-muted",
            line.tone === "danger" && "text-danger",
          )}
        >
          {line.text}
        </p>
      ))}
    </div>
  );
}
