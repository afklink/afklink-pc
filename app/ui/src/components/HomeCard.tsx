import type { TranslationKey } from "@afklink/i18n/pc";
import { Check, ChevronRight } from "lucide-react";
import { type ReactNode, type Ref, useCallback, useEffect, useRef, useState } from "react";

import { useLanguage, useT } from "../i18n";
import { type JournalRowParts, journalRowParts } from "../lib/journal";
import { cn } from "../lib/utils";
import {
  type DriverRow,
  type FakerInputStatus,
  type GameRow,
  type GameWindowDto,
  getFakerInputStatus,
  type StatusDto,
  setGameOnly,
  setGameWindow,
} from "../tauri";
import { MaintenanceDialog, useDriverMaintenance } from "./DriverMaintenance";
import { WindowPicker } from "./GamePicker";
import { Button } from "./ui/button";
import { MiddleEllipsis } from "./ui/middle-ellipsis";
import { Switch } from "./ui/switch";

/** The card's rows, by what pressing one opens. */
export type HomeRow = "driver" | "game" | "access" | "journal";

/**
 * The main view's card: four rows styled as
 * Settings' rows — the name and, small, the state on the left; the action or an arrow on the right.
 *
 *   «Управление в играх»  the input driver: «Установить» / «Переустановить» open the same dialog as
 *                         Settings (`DriverMaintenance`), ✓ once installed;
 *   «Показывать только игру»  the «Только игра» mode, named here by what its switch does (Settings
 *                         keeps the mode's name): «Выбрать игру» opens «Окно игры» (`WindowPicker`),
 *                         and the choice turns the mode on at once; with a game chosen, the switch —
 *                         at once, for every session, a live one too;
 *   «Доступ»              how many people have access › the «Доступ» screen;
 *   «Журнал»              the newest entry › the «Журнал» screen.
 *
 * What each row says is decided in Rust (`home.rs`, `StatusDto.home`), which logs every change;
 * this draws it. A press on a row itself (not on its action) opens what is behind it: Settings at
 * the row's section for the first two, the screens for the last two. The rows always stand: lime
 * and red only when there is cause. The names of the first two rows carry their
 * approved descriptions as a tooltip.
 */
export function HomeCard({
  status,
  onOpen,
  onChanged,
  rowRef,
}: {
  status: StatusDto;
  onOpen: (row: HomeRow) => void;
  /** Re-read the status now, after an action, rather than at the next poll. */
  onChanged: () => void;
  /** Each row's own button, so the window can give it focus back on the way out of its screen. */
  rowRef: (row: HomeRow, el: HTMLButtonElement | null) => void;
}) {
  const t = useT();
  const { locale } = useLanguage();
  const home = status.home;

  return (
    <div className="overflow-hidden rounded-card border border-line bg-panel">
      <DriverRowView
        row={home.driver}
        onOpen={() => onOpen("driver")}
        onChanged={onChanged}
        buttonRef={(el) => rowRef("driver", el)}
      />
      <GameRowView
        row={home.game}
        gameName={home.game_name}
        onOpen={() => onOpen("game")}
        onChanged={onChanged}
        buttonRef={(el) => rowRef("game", el)}
      />
      <CardRow
        title={t("app.access")}
        onOpen={() => onOpen("access")}
        buttonRef={(el) => rowRef("access", el)}
        trailing={
          <>
            <span className="text-body text-muted tabular-nums">{status.bindings.length}</span>
            <ChevronRight className="size-4" aria-hidden="true" />
          </>
        }
      />
      <CardRow
        title={t("app.journal")}
        sub={<JournalLine line={journalRowParts(t, locale, home.journal_last, Date.now())} />}
        onOpen={() => onOpen("journal")}
        buttonRef={(el) => rowRef("journal", el)}
        trailing={<ChevronRight className="size-4" aria-hidden="true" />}
      />
    </div>
  );
}

/**
 * The «Журнал» row's line on one line: the name is the part that gives way, its own ellipsis and its
 * full self in a tooltip — what happened («Доступ отозван») and when («Вчера 21:40 ·») stay whole,
 * as the time does in the journal's session rows. One string cut at its end would take the event
 * off: «Константин Константинопольский · Доступ от…».
 */
function JournalLine({ line }: { line: JournalRowParts }) {
  useJournalLineLog(line);
  if (line.name === null) return <>{line.before}</>;
  return (
    <span className="flex min-w-0">
      {line.before ? <span className="shrink-0 whitespace-pre">{line.before}</span> : null}
      <span className="min-w-0 truncate" title={line.name}>
        {line.name}
      </span>
      {line.after ? <span className="shrink-0 whitespace-pre">{line.after}</span> : null}
    </span>
  );
}

/** The «Журнал» row's line as it changes (a new entry, the day turning), said once per change. */
function useJournalLineLog(line: JournalRowParts) {
  const key = `${line.before}\u0000${line.name ?? ""}\u0000${line.after}`;
  const last = useRef<string | null>(null);
  useEffect(() => {
    if (last.current === key) return;
    last.current = key;
    // biome-ignore lint/suspicious/noConsole: once per change of the row's entry
    console.debug(
      line.name === null
        ? "[home] journal row: nothing to name («Пока пусто»)"
        : `[home] journal row: the name (${Array.from(line.name).length} characters) gives way first; «${line.before}…${line.after}» stays whole`,
    );
  }, [key, line]);
}

/** The driver row's second line, by its state. */
const DRIVER_SUB: Record<Exclude<DriverRow, "hidden">, TranslationKey> = {
  checking: "app.fakerInputChecking",
  not_installed: "app.fakerInputUnavailable",
  needed: "app.homeDriverNeeded",
  installed: "app.fakerInputAvailable",
  broken: "app.fakerInputDeviceMissing",
  unknown: "app.fakerInputUnknown",
};

/**
 * «Управление в играх». The window asks Rust to read the driver when this row mounts and whenever
 * the window shows again (the row is Rust's decision from the last read, which the once-a-second
 * status does not repeat), and after every operation; the answer also names Windows' language for
 * the dialog's hints. «Установить» is tonal when it is merely the next sensible step and lime when
 * the agent saw controls not reach a game without the driver (`needed`).
 */
function DriverRowView({
  row,
  onOpen,
  onChanged,
  buttonRef,
}: {
  row: DriverRow;
  onOpen: () => void;
  onChanged: () => void;
  buttonRef: Ref<HTMLButtonElement>;
}) {
  const t = useT();
  const [device, setDevice] = useState<FakerInputStatus | null>(null);
  // The caller's re-read is a new function every render; the reads below must not follow it.
  const changed = useRef(onChanged);
  changed.current = onChanged;

  const reread = useCallback(async () => {
    try {
      setDevice(await getFakerInputStatus());
    } catch (e) {
      console.warn(`[ipc] get_fakerinput_status (main view) failed: ${String(e)}`);
    } finally {
      changed.current();
    }
  }, []);

  useEffect(() => {
    void reread();
    const onVisibility = () => {
      if (document.visibilityState === "visible") void reread();
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, [reread]);

  const maintenance = useDriverMaintenance(reread);
  if (row === "hidden") return null;

  let control: ReactNode = null;
  if (row === "not_installed" || row === "needed") {
    control = (
      <Button
        size="sm"
        variant={row === "needed" ? "primary" : "secondary"}
        disabled={maintenance.busy}
        onClick={() => maintenance.open("install")}
      >
        {t("app.fakerInputInstall")}
      </Button>
    );
  } else if (row === "broken") {
    control = (
      <Button size="sm" disabled={maintenance.busy} onClick={() => maintenance.open("reinstall")}>
        {t("app.fakerInputReinstall")}
      </Button>
    );
  } else if (row === "installed") {
    control = (
      <span className="flex pr-1 text-muted" aria-hidden="true">
        <Check className="size-4" />
      </span>
    );
  }

  return (
    <>
      <CardRow
        title={t("app.fakerInputTitle")}
        about={t("app.fakerInputAbout")}
        sub={t(DRIVER_SUB[row])}
        danger={row === "needed" || row === "broken"}
        onOpen={onOpen}
        buttonRef={buttonRef}
        control={control}
      />
      <MaintenanceDialog maintenance={maintenance} windows={device?.windows_language} />
    </>
  );
}

/**
 * «Показывать только игру» — the «Только игра» mode, its row named by what the switch does, its
 * tooltip the mode's description as in Settings. Its switch and «Выбрать игру»
 * act at once, for every session, a live one too (the mode is the PC's, and the phone cannot reach
 * it); the choice from here turns the mode on with it. Rust logs each change and
 * where it came from (`from: "home"`).
 *
 * «Только для гостей» (Settings only) leaves no mark here: the `on` row shows the game's name alone,
 * whether the mode is for everyone or for guests only.
 */
function GameRowView({
  row,
  gameName,
  onOpen,
  onChanged,
  buttonRef,
}: {
  row: GameRow;
  gameName: string | null;
  onOpen: () => void;
  onChanged: () => void;
  buttonRef: Ref<HTMLButtonElement>;
}) {
  const t = useT();
  const [picking, setPicking] = useState(false);
  // A switch or a choice in flight: a second press is dropped.
  const inFlight = useRef(false);

  const settle = (what: string) => (e: unknown) =>
    console.warn(`[ipc] ${what} (main view) failed: ${String(e)}`);

  const toggle = (enabled: boolean) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setGameOnly(enabled, "home")
      .catch(settle(`set_game_only(${enabled})`))
      .finally(() => {
        inFlight.current = false;
        onChanged();
      });
  };

  const choose = (w: GameWindowDto) => {
    setPicking(false);
    if (inFlight.current) return;
    inFlight.current = true;
    // biome-ignore lint/suspicious/noConsole: the owner's choice, once; Rust logs the game itself
    console.info("[home] a game chosen from «Выбрать игру»: game-only goes on with it");
    setGameWindow(w.exe_path, w.window_class, { enable: true, from: "home" })
      .catch(settle("set_game_window"))
      .finally(() => {
        inFlight.current = false;
        onChanged();
      });
  };

  const choosing = row === "choose" || row === "no_game";
  const sub =
    row === "on"
      ? (gameName ?? "")
      : row === "no_game"
        ? t("app.gameOnlyNoGame")
        : t("app.homeGameOnlyOff");

  return (
    <>
      <CardRow
        title={t("app.homeGameOnlyTitle")}
        about={t("app.gameOnlyAbout")}
        sub={sub}
        subIsName={row === "on"}
        // «При подключении будет чёрный экран» is the one line that says why the viewer will see
        // black: it takes a second line rather than lose its end in the 340 px window.
        subWraps={row === "no_game"}
        danger={row === "no_game"}
        onOpen={onOpen}
        buttonRef={buttonRef}
        control={
          choosing ? (
            <Button size="sm" onClick={() => setPicking(true)}>
              {t("app.homeChooseGame")}
            </Button>
          ) : (
            <Switch
              checked={row === "on"}
              aria-label={t("app.gameOnlyToggle")}
              title={t("app.gameOnlyToggle")}
              // Its 36×32 press zone is the primitive's own: a press a little above or below the
              // track is the switch's, not the row's (which would open Settings).
              onCheckedChange={toggle}
            />
          )
        }
      />
      {picking ? <WindowPicker onPick={choose} onClose={() => setPicking(false)} /> : null}
    </>
  );
}

/**
 * One of the card's rows. The row's own button covers the whole row (its `::after`), so a press
 * anywhere on it opens what is behind it; the action on the right (`control`) sits above that and
 * takes its own presses. Read-only things on the right (`trailing`: a count, the arrow) are part of
 * the button, so a screen reader hears «Доступ 2». The name's tooltip (`about`) is the name's own,
 * above the button's cover, so it shows on the name and not over the whole row.
 */
function CardRow({
  title,
  about,
  sub,
  subIsName = false,
  subWraps = false,
  danger = false,
  control,
  trailing,
  onOpen,
  buttonRef,
}: {
  title: string;
  about?: string;
  sub?: ReactNode;
  /**
   * The second line is a name (the game's exe): cut in the middle, so «.exe» and the end of the
   * name stay, its full self the tooltip; not translated by the browser.
   */
  subIsName?: boolean;
  /** The second line may take two lines rather than be cut (a warning to be read whole). */
  subWraps?: boolean;
  danger?: boolean;
  control?: ReactNode;
  trailing?: ReactNode;
  onOpen: () => void;
  buttonRef?: Ref<HTMLButtonElement>;
}) {
  return (
    <div className="relative flex min-h-13 items-center gap-3 border-t border-line py-2 pr-3 pl-4 transition-colors first:border-t-0 hover:bg-white/4">
      <button
        ref={buttonRef}
        type="button"
        onClick={onOpen}
        className={cn(
          "flex min-w-0 flex-1 cursor-pointer items-center gap-1 text-left",
          "after:absolute after:inset-0 after:content-['']",
          "focus-visible:outline-none focus-visible:after:outline-2 focus-visible:after:-outline-offset-2 focus-visible:after:outline-accent",
        )}
      >
        <span className="block min-w-0 flex-1">
          <span
            className="relative z-[1] inline-block max-w-full truncate align-top text-body text-ink"
            title={about}
          >
            {title}
          </span>
          {sub ? (
            <span
              className={cn(
                "block font-small text-hint",
                subWraps ? "line-clamp-2 text-balance" : "truncate",
                danger ? "text-danger" : "text-faint",
              )}
              translate={subIsName ? "no" : undefined}
            >
              {subIsName && typeof sub === "string" ? (
                <MiddleEllipsis text={sub} logAs="the game's exe on the main card" />
              ) : (
                sub
              )}
            </span>
          ) : null}
        </span>
        {trailing ? (
          <span className="flex shrink-0 items-center gap-1 text-faint">{trailing}</span>
        ) : null}
      </button>
      {control ? <div className="relative z-10 flex shrink-0 items-center">{control}</div> : null}
    </div>
  );
}
