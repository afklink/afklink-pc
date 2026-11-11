import type { LanguagePreference, Locale, TranslationKey } from "@afklink/i18n/pc";
import { Check, ChevronDown, Copy, FolderOpen, Loader2 } from "lucide-react";
import { type ReactNode, useEffect, useId, useRef, useState } from "react";
import { useLanguage, useT } from "../i18n";
import { cn } from "../lib/utils";
import {
  getLogging,
  isLogOption,
  type LoggingDto,
  type LogOption,
  openLogsDir,
  type StatusDto,
  setAutostart,
  setLogLevel,
  setName,
} from "../tauri";
import { FakerInputSettings } from "./FakerInputSettings";
import { GameOnlySettings } from "./GameOnlySettings";
import { SendLogsButton, SendLogsDialog, type SendLogsModel, useSendLogs } from "./SendLogs";
import { UpdatesSettings } from "./UpdatesSettings";
import { Button } from "./ui/button";
import { Input, Label } from "./ui/input";
import { MiddleEllipsis } from "./ui/middle-ellipsis";
import { Select } from "./ui/select";
import { Switch } from "./ui/switch";

/**
 * The longest device name: `LIMITS.deviceName` in `@afklink/protocol`, `DEVICE_NAME_MAX` in the
 * agent, which refuses a longer one (the old name stays). The field stops there rather than let the
 * owner type a name that is then silently not kept. The browser counts UTF-16 units, the agent
 * characters, so the field is if anything the stricter of the two.
 */
const DEVICE_NAME_MAX = 64;

/**
 * How long a rename may take to show up in the agent's state before the field says it was not
 * kept. The command goes through the orchestrator, which refuses a name outside the device-name
 * rule and logs why (the old name stays); the window sees the result on its next status read.
 */
const NAME_CONFIRM_MS = 4000;

/** How long the ✓ stays after a rename went through. */
const SAVED_SHOWN_MS = 2000;

/**
 * A picker at the right end of a setting's row: one width for all of them, so their edges line up
 * from row to row, and allowed to give way (the value truncates) in the 340px-minimum window
 * rather than push past the plate. Wide enough for the longest value at the default width, the
 * language's «Автоматически (Русский)»; the log level has no «Автоматически (…)», and
 * its three values, «Подробные» the longest, fit at 340 px too.
 */
const PICKER = "w-60 min-w-0 shrink";

/**
 * One of the log row's two buttons: they grow from nothing, so the two on one line are one width;
 * no narrower than the label, so a line too short for both wraps the second under the first, and
 * each then takes the whole line.
 */
const ACTION = "min-w-max grow basis-0";

/** Each language by its own name — the way a picker lists them, whatever language it is in. */
const LANGUAGE_NAMES: Record<Locale, string> = { ru: "Русский", en: "English" };

/**
 * The log level's three options, in the order the picker lists them — «Подробные», «Обычные»,
 * «Выключены» — each with its words.
 */
const LOG_OPTION_LABELS: readonly (readonly [LogOption, TranslationKey])[] = [
  ["debug", "app.logLevelDetailed"],
  ["info", "app.logLevelStandard"],
  ["off", "app.logLevelOff"],
];

/**
 * Settings — behind the gear, and behind the main view's «Только игра» and «Управление в играх»
 * rows, which open it at their section. Its groups:
 *
 *   «Этот ПК»      the PC's name as the list of PCs shows it, the language, launch with Windows — what
 *                  an owner sets once;
 *   «Только игра»  the viewer sees the chosen game's window and nothing else, and input goes to the
 *                  game only (`GameOnlySettings`);
 *   the FakerInput driver (`FakerInputSettings`) and «Обновления» (`UpdatesSettings`, which also
 *                  names the build: «0.1.1», or «0.1.1 · a9dd98f · dev» for a development one);
 *   «Диагностика»  collapsed: log level, «Открыть папку логов» and «Отправить логи» (a dialog,
 *                  `SendLogs`), the device ID — what support asks for. No «Версия» row: it would
 *                  only repeat the one in «Обновления».
 *
 * One commit model: everything applies the moment it changes. The name saves on Enter or when the
 * field loses focus, with «Сохранить» inside the field only while it is edited, then a ✓ — or «Не
 * сохранено» under it if the agent did not take it. Space for every line that comes and goes is
 * kept, so nothing moves under the pointer.
 *
 * The server address field is deliberately gone: the product has one server, and an editable
 * address is a footgun that breaks connectivity with a typo. The way back is in the window's top
 * row (`App`), outside the scroll.
 */
export function SettingsView({
  status,
  onRefresh,
  focus = null,
}: {
  status: StatusDto;
  /** Re-read now — after a change, rather than waiting for the poll tick. */
  onRefresh: () => void;
  /**
   * The section to show first: Settings opened from the main view's «Только игра» or «Управление
   * в играх» row, whose section here holds what the row does not (another game, the helper;
   * «Удалить», «Проверить»).
   */
  focus?: SettingsFocus | null;
}) {
  const t = useT();
  const thisPcId = useId();
  const logging = useLogging();
  const gameOnlyRef = useRef<HTMLDivElement>(null);
  const driverRef = useRef<HTMLDivElement>(null);

  // Once, on opening: the section scrolled to the top of the view's scrolling area — that area only,
  // not the page around it (`scrollIntoView` would move every scrolling ancestor).
  // biome-ignore lint/correctness/useExhaustiveDependencies: once, on mount
  useEffect(() => {
    if (focus === null) return;
    const target = (focus === "gameOnly" ? gameOnlyRef : driverRef).current;
    const scroller = target?.closest("main");
    if (!target || !scroller) return;
    const offset = target.getBoundingClientRect().top - scroller.getBoundingClientRect().top;
    scroller.scrollTop += offset - SECTION_AIR;
    // biome-ignore lint/suspicious/noConsole: once per opening from a row, with where
    console.debug(
      `[settings] opened from the main view's row at ${focus}: scrolled ${Math.round(offset)} px`,
    );
  }, []);

  return (
    <div className="flex animate-fade-in flex-col gap-6 pb-2">
      <section aria-labelledby={thisPcId}>
        <h2 id={thisPcId} className="mb-2 px-1 text-body font-semibold text-muted">
          {t("app.sectionThisPc")}
        </h2>
        <div className="rounded-card border border-line bg-panel">
          <NameField status={status} onRefresh={onRefresh} />
          <LanguageRow />
          <AutostartRow status={status} onRefresh={onRefresh} />
        </div>
      </section>

      <div ref={gameOnlyRef}>
        <GameOnlySettings home={status.home} />
      </div>
      <div ref={driverRef}>
        <FakerInputSettings />
      </div>
      <UpdatesSettings />
      <Diagnostics deviceId={status.device_id} logging={logging} />
    </div>
  );
}

/** A section Settings can be opened at (`SettingsView`'s `focus`). */
export type SettingsFocus = "gameOnly" | "driver";

/** Air left above a section Settings opens at, so its heading does not touch the top row. */
const SECTION_AIR = 4;

/* ── «Этот ПК» ───────────────────────────────────────────────────────────────── */

type SaveState =
  | { kind: "idle" }
  | { kind: "saving"; name: string }
  | { kind: "saved" }
  | { kind: "failed" };

function NameField({ status, onRefresh }: { status: StatusDto; onRefresh: () => void }) {
  const t = useT();
  const id = useId();
  const hintId = useId();
  const [name, setNameLocal] = useState(status.device_name);
  const [save, setSave] = useState<SaveState>({ kind: "idle" });
  // The agent's name the field last showed: a change from elsewhere replaces an unedited field,
  // never one the owner is typing in.
  const shown = useRef(status.device_name);

  const trimmed = name.trim();
  const dirty = trimmed !== status.device_name;

  // biome-ignore lint/correctness/useExhaustiveDependencies: only the agent's name drives this; `name` is read, not watched
  useEffect(() => {
    if (name === shown.current) setNameLocal(status.device_name);
    shown.current = status.device_name;
  }, [status.device_name]);

  // The rename shows up in the agent's state: kept. It does not within `NAME_CONFIRM_MS`: not.
  useEffect(() => {
    if (save.kind !== "saving") return;
    if (status.device_name === save.name) {
      setSave({ kind: "saved" });
      setNameLocal(status.device_name);
      return;
    }
    const timer = window.setTimeout(() => {
      console.warn(
        `[settings] name not taken by the agent within ${NAME_CONFIRM_MS} ms (the agent's log says why)`,
      );
      setSave({ kind: "failed" });
    }, NAME_CONFIRM_MS);
    return () => window.clearTimeout(timer);
  }, [save, status.device_name]);

  useEffect(() => {
    if (save.kind !== "saved") return;
    const timer = window.setTimeout(() => setSave({ kind: "idle" }), SAVED_SHOWN_MS);
    return () => window.clearTimeout(timer);
  }, [save]);

  const commit = () => {
    if (save.kind === "saving") return;
    // Emptied: nothing to save, the name stays as it was.
    if (trimmed === "") {
      setNameLocal(status.device_name);
      return;
    }
    if (!dirty) {
      setNameLocal(status.device_name);
      return;
    }
    setSave({ kind: "saving", name: trimmed });
    setName(trimmed).then(onRefresh, (e: unknown) => {
      console.warn(`[ipc] set_name failed: ${String(e)}`);
      setSave({ kind: "failed" });
    });
  };

  const failed = save.kind === "failed" && dirty;

  return (
    <div className="px-4 pt-3.5 pb-3">
      <Label htmlFor={id}>{t("app.deviceName")}</Label>
      <div className="relative mt-2">
        <Input
          id={id}
          name="device-name"
          autoComplete="off"
          value={name}
          maxLength={DEVICE_NAME_MAX}
          spellCheck={false}
          aria-describedby={hintId}
          aria-invalid={failed || undefined}
          // Refused: the field's edge says so in Cut, focused or not (the lime focus would hide it).
          className={cn(
            "pr-28",
            failed &&
              "border-danger/60 focus-visible:border-danger/70 focus-visible:ring-danger/25",
          )}
          onChange={(e) => {
            setNameLocal(e.target.value);
            if (save.kind === "failed" || save.kind === "saved") setSave({ kind: "idle" });
          }}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") commit();
            if (e.key === "Escape" && dirty) {
              // Kept here: Escape reverts the field, it does not also leave the view.
              e.stopPropagation();
              setNameLocal(status.device_name);
              setSave({ kind: "idle" });
            }
          }}
        />
        {/* The field's right end: «Сохранить» while edited, a spinner while it goes, then ✓. */}
        <div className="absolute inset-y-0 right-1 flex items-center">
          {save.kind === "saving" ? (
            <Loader2
              className="mr-2 size-4 animate-spin text-faint motion-reduce:animate-none"
              aria-label={t("common.loading")}
            />
          ) : dirty && trimmed !== "" ? (
            <Button
              variant="primary"
              size="sm"
              className="h-7 px-2.5"
              // Pressed before the field blurs, so the blur's own save does not race this one.
              onMouseDown={(e) => e.preventDefault()}
              onClick={commit}
            >
              {t("app.save")}
            </Button>
          ) : save.kind === "saved" ? (
            <Check className="mr-2 size-4 text-live" aria-label={t("app.nameSaved")} />
          ) : null}
        </div>
      </div>
      <p
        id={hintId}
        aria-live="polite"
        className={cn("mt-1.5 text-hint", failed ? "text-danger" : "text-faint")}
      >
        {failed ? t("app.nameFailed") : t("app.deviceNameHint")}
      </p>
    </div>
  );
}

function LanguageRow() {
  const t = useT();
  const { preference, locale, setPreference } = useLanguage();
  const id = useId();
  const labelId = useId();

  const options: { value: string; label: ReactNode }[] = [
    {
      value: "auto",
      label: (
        <>
          {t("common.languageAuto")} (<span lang={locale}>{LANGUAGE_NAMES[locale]}</span>)
        </>
      ),
    },
    { value: "ru", label: <span lang="ru">{LANGUAGE_NAMES.ru}</span> },
    { value: "en", label: <span lang="en">{LANGUAGE_NAMES.en}</span> },
  ];

  return (
    <Row>
      <Label htmlFor={id} id={labelId} className="shrink-0">
        {t("common.language")}
      </Label>
      <Select
        id={id}
        labelId={labelId}
        label={t("common.language")}
        value={preference}
        options={options}
        className={PICKER}
        // `setPreference` persists it too (`set_lang`, logged by Rust).
        onChange={(v) => setPreference(v as LanguagePreference)}
      />
    </Row>
  );
}

function AutostartRow({ status, onRefresh }: { status: StatusDto; onRefresh: () => void }) {
  const t = useT();
  const id = useId();
  return (
    <Row>
      <Label htmlFor={id} className="cursor-pointer">
        {t("app.autostart")}
      </Label>
      <Switch
        id={id}
        checked={status.autostart}
        onCheckedChange={(enabled) => {
          // Rust logs the change and any failure (`set_autostart`). Re-read once it has answered,
          // either way: the switch then shows what is actually in effect.
          setAutostart(enabled).then(onRefresh, (e: unknown) => {
            console.warn(`[ipc] set_autostart(${enabled}) failed: ${String(e)}`);
            onRefresh();
          });
        }}
      />
    </Row>
  );
}

/** A setting on one line: its label left, its control right; a hairline above all but the first. */
function Row({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-13 items-center justify-between gap-3 border-t border-line px-4 py-2">
      {children}
    </div>
  );
}

/* ── «Диагностика» ───────────────────────────────────────────────────────────── */

function Diagnostics({ deviceId, logging }: { deviceId: string; logging: LoggingState }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const idLabelId = useId();
  const [copied, setCopied] = useState(false);
  // Held here, not in the collapsible panel: collapsing it while a report goes keeps the outcome.
  // The dialog too, so it outlives the panel it was opened from.
  const sendLogs = useSendLogs();

  const copyId = async () => {
    try {
      await navigator.clipboard.writeText(deviceId);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      // The ID itself is selectable text, the fallback.
      console.warn(`[clipboard] device id not copied: ${String(e)}`);
    }
  };

  return (
    <section className="rounded-card border border-line bg-panel">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
        className="flex h-12 w-full cursor-pointer items-center gap-3 rounded-card px-4 text-left transition-colors hover:bg-white/4"
      >
        <span className="text-body text-ink">{t("app.sectionDiagnostics")}</span>
        <ChevronDown
          className={cn(
            "ml-auto size-4 shrink-0 text-faint transition-transform",
            open && "rotate-180",
          )}
          aria-hidden="true"
        />
      </button>

      {open ? (
        <div id={panelId} className="animate-slide-up">
          <LogRow logging={logging} sendLogs={sendLogs} />
          {/*
            The ID is text, not a control, so no `<label>`: a group named by its caption holds it
            and Copy. `min-w-0`: a fieldset is min-content wide by default, which would stop the
            ID truncating. The row itself — hairline, height, flex — is a `<div>` inside it, like
            every other row: Chromium lays a fieldset's content out in an inner box as tall as the
            content, not as the fieldset's own min height, so a flex fieldset of `min-h-13` would hold
            its caption, ID and Copy at the row's top, off its centre line.
          */}
          <fieldset aria-labelledby={idLabelId} className="min-w-0">
            <div className="flex min-h-13 items-center gap-2 border-t border-line py-2 pr-2 pl-4">
              <p id={idLabelId} className="shrink-0 text-body text-ink">
                {t("app.deviceId")}
              </p>
              {/*
                `pt-0.5`: the 11px mono figures sit 1.5px higher in their line box than the 13px
                caption's capitals do in theirs; 1px down puts the ID, the caption and Copy on one
                visual centre line (measured by ink in Edge). Padding, not a transform: a
                fractional translate at 125% scaling blurs the text.
              */}
              <p
                className="selectable min-w-0 flex-1 pt-0.5 font-mono text-hint text-faint"
                translate="no"
              >
                {/* Cut in the middle: both ends of the ID stay, as support reads it out. */}
                <MiddleEllipsis text={deviceId} align="end" logAs="the device ID in Settings" />
              </p>
              <Button
                variant="ghost"
                size="icon"
                className="size-8 shrink-0"
                aria-label={t("app.copyId")}
                title={t("app.copyId")}
                onClick={() => void copyId()}
              >
                {copied ? (
                  <Check aria-hidden="true" className="text-live" />
                ) : (
                  <Copy aria-hidden="true" />
                )}
              </Button>
              <span className="sr-only" aria-live="polite">
                {copied ? t("app.copied") : ""}
              </span>
            </div>
          </fieldset>
        </div>
      ) : null}
      <SendLogsDialog model={sendLogs} />
    </section>
  );
}

/**
 * How much the agent writes to its log, plus a way to the files.
 *
 * Three levels — detailed for development, minimal for everyday use (enough to analyse a user's
 * problem), and off: «Подробные» (`debug`), «Обычные» (`info`), «Выключены» (`off`). The picker
 * shows the level in effect, with no «Автоматически»: with nothing chosen the build decides —
 * `debug` for a development build; for a release `debug` during the beta test and `info` after it —
 * and that level is the one selected. `trace`, which a hand edit of config.json can set and nothing
 * here offers, shows as «Подробные». Any pick is saved (`pickLogLevel`) — the build's own level
 * too, so a level picked during the beta stays after it — except the option already chosen, which
 * changes nothing (a `trace` stays `trace`).
 *
 * Applies at once — Rust swaps the filter in place — so there is no "restart to apply" to explain,
 * except when `RUST_LOG` is set: then the environment wins, and the hint says so (its value in the
 * tooltip) instead of letting the picker look broken. A hint only where there is something to say,
 * four words at most; its line is kept either way, so the rows under it do not move — it is also
 * the gap between the picker and the buttons under it, so an empty one is spacing, not a hole.
 *
 * Under it, two secondary buttons, a pair: «Открыть папку логов» and «Отправить логи» (a dialog,
 * `SendLogs`: the files, with the last quarter of an hour in detail, to the developer). They share
 * a line, one width each, where both fit on it (English); where they do not (Russian), each takes
 * the whole line, one under the other — never one wide and one narrow, nor a label cut short.
 * While nothing is written («Выключены», or `RUST_LOG=off`) «Отправить логи» stays in place,
 * disabled — there is nothing to send — with «Логи выключены» in its tooltip; the hint above it
 * already says «Логи не пишутся».
 */
function LogRow({ logging, sendLogs }: { logging: LoggingState; sendLogs: SendLogsModel }) {
  const t = useT();
  const id = useId();
  const labelId = useId();
  const { dto, choose } = logging;
  // Until the state is read the button stays as it always was: enabled.
  const sendOff = dto !== null && !dto.writing;
  useSendOffLog(dto);

  const hint =
    dto === null
      ? null
      : dto.env_override !== null
        ? t("app.logLevelEnvOverride")
        : dto.option === "off"
          ? t("app.logLevelOffHint")
          : null;

  return (
    <div className="border-t border-line px-4 pt-2 pb-3">
      <div className="flex min-h-11 items-center justify-between gap-3">
        <Label htmlFor={id} id={labelId} className="shrink-0">
          {t("app.logLevel")}
        </Label>
        {dto === null ? (
          // The level is on its way (one IPC round trip): a box of the picker's size, not a jump.
          <div aria-hidden="true" className={cn(PICKER, "h-9 rounded-control bg-white/5")} />
        ) : (
          <Select
            id={id}
            labelId={labelId}
            label={t("app.logLevel")}
            value={dto.option}
            options={LOG_OPTION_LABELS.map(([option, key]) => ({
              value: option,
              label: t(key),
            }))}
            className={PICKER}
            onChange={(value) => {
              const choice = pickLogLevel(dto, value);
              if (choice !== null) choose(choice);
            }}
          />
        )}
      </div>
      <p className="min-h-4 text-right text-hint text-faint" title={dto?.env_override ?? undefined}>
        {hint}
      </p>
      <div className="mt-1 flex flex-wrap gap-2">
        <Button
          size="sm"
          className={ACTION}
          title={dto?.dir ?? undefined}
          onClick={() =>
            openLogsDir().catch((e: unknown) =>
              console.warn(`[ipc] open_logs_dir failed: ${String(e)}`),
            )
          }
        >
          <FolderOpen aria-hidden="true" />
          {t("app.openLogs")}
        </Button>
        <SendLogsButton
          model={sendLogs}
          className={ACTION}
          offTitle={sendOff ? t("app.sendLogsOff") : null}
        />
      </div>
    </div>
  );
}

/**
 * What a pick in the log-level picker stores (`LogRow`): the option picked — any pick is saved, the
 * build's own level too (no «Автоматически») — except the option already chosen in
 * config.json, which changes nothing: a `trace` written by hand, shown as «Подробные», stays `trace`
 * when «Подробные» is picked again. Said in the window's console with why; Rust logs what it applies
 * and saves (`set_log_level`).
 */
function pickLogLevel(dto: LoggingDto, value: string): LogOption | null {
  if (!isLogOption(value)) {
    console.warn(`[settings] log level picker gave «${value}», not one of the three; ignored`);
    return null;
  }
  if (dto.choice !== null && dto.option === value) {
    // biome-ignore lint/suspicious/noConsole: once per press
    console.debug(
      `[settings] log level «${value}» picked: already chosen (config.json: ${dto.choice}); nothing changes`,
    );
    return null;
  }
  // biome-ignore lint/suspicious/noConsole: once per press
  console.debug(
    `[settings] log level «${value}» picked: saved (was ${dto.choice ?? `none chosen — the build's ${dto.default_level}`}; in effect ${dto.level})`,
  );
  return value;
}

/**
 * «Отправить логи» turning off while nothing is written, or back on, said once each time it does,
 * with why. The window's console (devtools) only.
 */
function useSendOffLog(dto: LoggingDto | null) {
  const writing = dto === null ? null : dto.writing;
  const why =
    dto === null ? "" : dto.env_override !== null ? `RUST_LOG=${dto.env_override}` : dto.level;
  const last = useRef<boolean | null>(null);
  useEffect(() => {
    if (writing === null || last.current === writing) return;
    const was = last.current;
    last.current = writing;
    if (was === null && writing) return;
    // biome-ignore lint/suspicious/noConsole: once per change, with why
    console.debug(
      writing
        ? `[settings] «Отправить логи» enabled: the log is written again (${why})`
        : `[settings] «Отправить логи» disabled: nothing is written (${why}), nothing to send`,
    );
  }, [writing, why]);
}

interface LoggingState {
  /** Null until `get_logging` answers (or forever without a bridge, in `vite dev`). */
  dto: LoggingDto | null;
  choose: (value: LogOption) => void;
}

/** The logging state, read when Settings opens so it is there by the time Diagnostics is. */
function useLogging(): LoggingState {
  const [dto, setDto] = useState<LoggingDto | null>(null);

  useEffect(() => {
    let cancelled = false;
    getLogging()
      .then((next) => {
        if (!cancelled) setDto(next);
      })
      .catch((e: unknown) => console.warn(`[ipc] get_logging failed: ${String(e)}`));
    return () => {
      cancelled = true;
    };
  }, []);

  const choose = (value: LogOption) => {
    if (dto === null) return;
    // Shown at once, confirmed by Rust's answer; on failure, re-read what is actually in effect.
    setDto({
      ...dto,
      choice: value,
      level: value,
      option: value,
      writing: dto.env_override === null ? value !== "off" : dto.writing,
    });
    setLogLevel(value)
      .then(setDto)
      .catch((e: unknown) => {
        console.warn(`[ipc] set_log_level(${value}) failed: ${String(e)}`);
        getLogging()
          .then(setDto)
          .catch((e2: unknown) => console.warn(`[ipc] get_logging failed: ${String(e2)}`));
      });
  };

  return { dto, choose };
}
