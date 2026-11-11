import { useCallback, useEffect, useId, useState } from "react";
import { useT } from "../i18n";
import { cn } from "../lib/utils";
import {
  applyFoundLaunch,
  chooseGameLaunch,
  type GameHelperDto,
  type GameOnlyDto,
  type GameWindowDto,
  getGameOnly,
  type HomeDto,
  setGameHelper,
  setGameOnly,
  setGameOnlyForGuests,
  setGameWindow,
  updateGameHelper,
} from "../tauri";
import { WindowPicker } from "./GamePicker";
import { Button } from "./ui/button";
import { Label } from "./ui/input";
import { MiddleEllipsis } from "./ui/middle-ellipsis";
import { Switch } from "./ui/switch";

/**
 * «Только игра»: the viewer sees the chosen game's window and nothing else — black while it cannot
 * be shown, never the desktop — and input goes to the game only. The game is bound on its exe and
 * window class; the title is shown in the picker only. Everything applies at once (a live session
 * too) and is saved by Rust (`game_only.rs`), which logs every change. The words are `app.gameOnly*`
 * in `@afklink/i18n`.
 *
 * The card, top to bottom, a rule between each block and the next:
 *
 *   the game    first: the game is what the two switches are about (squeezed between them, its
 *               block with buttons looks bad);
 *   the switch  with a line under its label on what the mode hides and forbids (in the hint style
 *               of «Управление в играх»'s line);
 *   for guests  «Только для гостей» (`ForGuestsRow`): the
 *               mode for guests' sessions only, the owner's own with the whole screen — who is the
 *               owner is the server's word (the binding's role), never the viewer's. Directly under
 *               the mode's switch and indented, as its dependent option; built like it, with its own
 *               line under the label;
 *   the helper  its row (`HelperRow`, `game_helper.rs`), with its status lines and its errors — last,
 *               so its lines coming and going move nothing under them.
 *
 * Lines under a label speak in three tones, as everywhere in the window: a plain
 * status muted, one that waits for the owner's action amber (`text-attention`), an error red. The
 * buttons beside them stay ordinary — one look for every button here — only the text is coloured.
 * The helper's status lines' buttons are all of the compact `xs` size, so a line is no taller than
 * it needs; the game's «Выбрать», a row's own button, is the usual `sm`.
 * A control that cannot work yet stays in its place, disabled; nothing takes its place.
 *
 * The game's row is of one shape, a game chosen or not: «Игра» and under it,
 * small like the lines under the switches, the exe's name, muted — cut with an ellipsis, the full
 * path its tooltip — or «Не выбрана», amber: nothing in the section works without a game. The
 * ellipsis is in the middle (as on the main card and in «Файл запуска»), so
 * «.exe» and the end of the name stay: «TheElderScrollsOnl…Shipping.exe».
 * «Выбрать» on the right, centred on both. As tall either way: choosing the first game moves
 * nothing.
 *
 * No «Сбросить»: it would have no use of its own — another game is «Выбрать», the whole
 * screen again is the mode's switch, no launching is the helper's — and all it could add was the
 * mode on without a game, black for the viewer. The game stays bound while the mode is off.
 *
 * «При подключении будет чёрный экран», red, under the name's line only while the mode is on without a
 * game — which this window does not make: left so by an old build's «Сбросить», or config.json
 * edited by hand. No line is kept for it otherwise; the live region that says it is always there,
 * empty and of no height.
 *
 * `home`: the status's reading of the same config (`home.rs`), what the switch and the game's row
 * show until the section's own read (`get_game_only`) answers — so they open at their final height.
 * `home` says nothing of the helper: its status lines, when it has any, come with that answer, at
 * the bottom of the card.
 *
 * The switch cannot be turned on before a game is chosen; turned off, the game stays for next time.
 * Here, unlike on the main view, choosing a game leaves the switch as it is.
 *
 * «Только для гостей» is a dependent option of the mode's switch, directly under it and indented
 * (it belongs to that setting), before the helper. The section's pattern for such
 * a control: off, it waits for what it depends on — the mode on — disabled in its place, nothing
 * swapped in; on, it can always be turned off. Turned on and then the mode off, it stays on, in
 * force again the moment the mode is.
 */
export function GameOnlySettings({
  home,
}: {
  home: Pick<HomeDto, "game" | "game_name" | "game_for_guests">;
}) {
  const t = useT();
  const titleId = useId();
  const switchId = useId();
  const aboutId = useId();
  const [state, setState] = useState<GameOnlyDto | null>(null);
  const [picking, setPicking] = useState(false);
  const [helperChange, setHelperChange] = useState<HelperChange | null>(null);
  const [helperError, setHelperError] = useState<HelperError>(null);
  const helperBusy = helperChange !== null;

  useEffect(() => {
    let cancelled = false;
    getGameOnly()
      .then((next) => {
        if (!cancelled) setState(next);
      })
      .catch((e: unknown) => console.warn(`[ipc] get_game_only failed: ${String(e)}`));
    return () => {
      cancelled = true;
    };
  }, []);

  const reread = useCallback(() => {
    getGameOnly()
      .then(setState)
      .catch((e: unknown) => console.warn(`[ipc] get_game_only failed: ${String(e)}`));
  }, []);

  const toggle = (enabled: boolean) => {
    setGameOnly(enabled).then(setState, (e: unknown) => {
      console.warn(`[ipc] set_game_only(${enabled}) failed: ${String(e)}`);
      reread();
    });
  };

  const toggleForGuests = (enabled: boolean) => {
    setGameOnlyForGuests(enabled).then(setState, (e: unknown) => {
      console.warn(`[ipc] set_game_only_for_guests(${enabled}) failed: ${String(e)}`);
      reread();
    });
  };

  // Declining Windows' prompt (or closing the Open dialog) is not an error: the answer is the
  // state, unchanged.
  const runHelper = (change: HelperChange, call: () => Promise<GameOnlyDto>, what: string) => {
    setHelperChange(change);
    setHelperError(null);
    call()
      .then(setState, (e: unknown) => {
        console.warn(`[ipc] ${what} failed: ${String(e)}`);
        setHelperError(String(e) === "not_found" ? "not_found" : "failed");
        reread();
      })
      .finally(() => setHelperChange(null));
  };
  // A button's change: the switch moves only by its outcome.
  const byOutcome: HelperChange = { switchTo: null };

  const choose = (w: GameWindowDto) => {
    setPicking(false);
    setGameWindow(w.exe_path, w.window_class).then(setState, (e: unknown) => {
      console.warn(`[ipc] set_game_window failed: ${String(e)}`);
      reread();
    });
  };

  const enabled = state ? state.enabled : home.game === "on" || home.game === "no_game";
  const forGuests = state ? state.for_guests : home.game_for_guests;
  const gameName = state ? (state.game?.exe_name ?? null) : home.game_name;
  const noGame = enabled && gameName === null;

  return (
    <section aria-labelledby={titleId}>
      <h2 id={titleId} className="mb-2 px-1 text-body font-semibold text-muted">
        {t("app.gameOnlyTitle")}
      </h2>
      <div className="rounded-card border border-line bg-panel">
        {/*
          The game's row, first, one shape with a game and without. The path for the name's tooltip
          comes with the section's own read: `home` has the name only. No game is amber: it waits
          for the owner's choice.
        */}
        <div className="flex items-center justify-between gap-3 px-4 py-3">
          <div className="min-w-0">
            <p className="text-body text-ink">{t("app.gameOnlyGame")}</p>
            <p
              className={cn(
                "mt-0.5 truncate text-hint",
                gameName !== null ? "text-muted" : "text-attention",
              )}
              title={gameName !== null ? state?.game?.exe_path : undefined}
              translate={gameName !== null ? "no" : undefined}
            >
              {gameName !== null ? (
                <MiddleEllipsis
                  text={gameName}
                  title={state?.game?.exe_path}
                  logAs="the game's exe in Settings"
                />
              ) : (
                t("app.gameOnlyNone")
              )}
            </p>
            {/* Empty, it has no height: no line is kept for a warning that is not there. */}
            <p className={cn("text-hint text-danger", noGame && "mt-0.5")} aria-live="polite">
              {noGame ? t("app.gameOnlyNoGame") : null}
            </p>
          </div>
          <Button size="sm" disabled={helperBusy} onClick={() => setPicking(true)}>
            {t("app.gameOnlyChoose")}
          </Button>
        </div>
        {/*
          The description under the switch's own label, the switch centred beside both: it says
          what this switch does, not what the section is. Balanced, so the narrow window breaks it
          at its comma (the semicolon in English) rather than leaving a word alone on a line.
        */}
        <div className="flex items-center justify-between gap-3 border-t border-line px-4 py-3">
          <div className="min-w-0">
            <Label htmlFor={switchId} className="cursor-pointer">
              {t("app.gameOnlyToggle")}
            </Label>
            <p id={aboutId} className="mt-0.5 text-balance text-hint text-muted">
              {t("app.gameOnlyAbout")}
            </p>
          </div>
          <Switch
            id={switchId}
            aria-describedby={aboutId}
            checked={enabled}
            // Off, it waits for a game; on, it can always be turned off.
            disabled={helperBusy || (!enabled && gameName === null)}
            onCheckedChange={toggle}
          />
        </div>
        <ForGuestsRow
          on={forGuests}
          // A dependent option of the mode's switch: off, it waits for the mode to be on (which
          // waits for a game); on, it can always be turned off.
          disabled={helperBusy || (!forGuests && !enabled)}
          onToggle={toggleForGuests}
        />
        <HelperRow
          helper={state?.helper ?? null}
          hasGame={gameName !== null}
          change={helperChange}
          error={helperError}
          onToggle={(on) =>
            runHelper({ switchTo: on }, () => setGameHelper(on), `set_game_helper(${on})`)
          }
          onConfirm={() => runHelper(byOutcome, () => setGameHelper(true), "set_game_helper(true)")}
          onChoose={() => runHelper(byOutcome, chooseGameLaunch, "choose_game_launch")}
          onUpdate={() => runHelper(byOutcome, updateGameHelper, "update_game_helper")}
          onApply={() => runHelper(byOutcome, applyFoundLaunch, "apply_found_launch")}
        />
      </div>
      {picking ? <WindowPicker onPick={choose} onClose={() => setPicking(false)} /> : null}
    </section>
  );
}

/**
 * «Только для гостей» and, under it, small, «Владелец видит весь экран»:
 * the mode for guests' sessions only. Built like the mode's switch above it — the label, its line
 * under it, the switch centred beside both — indented under it as its dependent option, and, like
 * the section's other dependent controls, disabled in its place while it cannot be turned on (the
 * mode off). The line has about 202 px at 340 px (36–37 characters on one line, measured).
 * Rust logs each change (`game_only::set_game_only_for_guests`) and every session it moves
 * (`afklink_core::game_access`).
 */
function ForGuestsRow({
  on,
  disabled,
  onToggle,
}: {
  on: boolean;
  disabled: boolean;
  onToggle: (on: boolean) => void;
}) {
  const t = useT();
  const switchId = useId();
  const aboutId = useId();
  // Indented under the mode's switch, as its dependent option: the rule
  // above it and its words start one step (16 px) in; its switch stays in the column of the
  // section's other switches.
  return (
    <div className="ml-4 flex items-center justify-between gap-3 border-t border-line py-3 pr-4 pl-4">
      <div className="min-w-0">
        <Label
          htmlFor={switchId}
          className={cn("text-balance", disabled ? "cursor-default" : "cursor-pointer")}
        >
          {t("app.gameOnlyForGuests")}
        </Label>
        <p id={aboutId} className="mt-0.5 text-balance text-hint text-muted">
          {t("app.gameOnlyForGuestsAbout")}
        </p>
      </div>
      <Switch
        id={switchId}
        aria-describedby={aboutId}
        checked={on}
        disabled={disabled}
        onCheckedChange={onToggle}
      />
    </div>
  );
}

/**
 * The helper's change while it runs — Windows' Open dialog, its prompt, the setup. `switchTo`: the
 * switch's own change and the position it is heading for — it moves at once, as the owner moved it,
 * and back if they decline. `null`: a button's change («Выбрать», «Изменить», «Разрешить»,
 * «Обновить», «Заменить»), which moves the switch by its outcome only: «Выбрать» with the helper
 * off turns it on once the setup is done, and a cancelled one leaves it off without a jump there
 * and back.
 */
interface HelperChange {
  switchTo: boolean | null;
}

/** How the helper's last change failed: «Файл не найден», or «Не удалось применить». */
type HelperError = "not_found" | "failed" | null;

/** A status line's tone: a plain status, or one that waits for the owner's action. */
type Tone = "muted" | "attention";

const TONE: Record<Tone, string> = { muted: "text-muted", attention: "text-attention" };

/**
 * A line under the helper's switch: a short status in its tone, the button that goes with it (the
 * compact `xs` size, as every button in these lines), and the full path its tooltip shows (the
 * launch exe's, or the one found).
 */
interface HelperLine {
  /** What the line is: stable while it stays, so React keeps its element. */
  key: string;
  text: string;
  tone: Tone;
  title?: string;
  /** The line ends in a file's name: cut in the middle, so «.exe» stays. */
  middle?: boolean;
  button?: { label: string; onClick: () => void };
}

/** The status lines, and whether «Игра не запускается» goes under them (`helperStatus`). */
interface HelperStatus {
  lines: HelperLine[];
  gaveUp: boolean;
}

/** What the helper's buttons do: `game_helper.rs` commands, each through `runHelper`. */
interface HelperActions {
  /** «Разрешить»: the switch's setup (`setGameHelper(true)`). */
  confirm: () => void;
  /** «Выбрать», «Изменить»: the Open dialog, then the setup (`chooseGameLaunch`). */
  choose: () => void;
  /** «Обновить»: this build's helper, the installed launch exe kept (`updateGameHelper`). */
  update: () => void;
  /** «Заменить»: the learned launcher in place of the installed one (`applyFoundLaunch`). */
  apply: () => void;
}

/**
 * The helper's status lines, by its state (`game_helper::HelperDto`), outside a change — the change
 * itself is «Ждём Windows…» (`helperView`). Out of the component to keep its complexity down.
 *
 *   no game                    nothing (the game's row says «Не выбрана»)
 *   no launch exe, off or on   «Нужен файл запуска» (amber) + «Выбрать»: the helper cannot work
 *                              without it; off, its switch stays in place, disabled
 *   off                        nothing
 *   on, not as installed       «Нужно разрешение» (amber) + «Разрешить»: it does nothing until the
 *                              setup again — another game or file, the task gone, Windows' 740
 *   on, as installed           by what else is true, the first that is:
 *     another build's helper   «Нужно обновление» (amber) + «Обновить», in the file line's place: it
 *                              works on with the old build meanwhile, but without the new one's
 *                              fixes — updating it is all but a must. The pair is
 *                              built like «Нужно разрешение» + «Разрешить»: what is needed, amber,
 *                              and the verb that gives it — though there the helper does nothing at
 *                              all. «Обновить» keeps the installed launch exe
 *     a launcher learned       «Файл запуска: <exe>» + «Изменить», and under it «Найден другой файл
 *                              запуска» + «Заменить», muted, the found path its tooltip: the game was
 *                              started by another file than the installed one; the helper works on
 *                              with the installed one meanwhile. «Заменить» installs the found one
 *     otherwise                «Файл запуска: <exe>» + «Изменить», muted, the full path its tooltip
 *   and, whatever the lines,   «Игра не запускается», red, under them (`gaveUp`): the helper's
 *     the game won't start     failed-launch mark, kept until the game runs a minute with its window
 *
 * When they meet, the update goes first (updating the helper matters more than offering another
 * launch file):
 *
 *   another build's helper + a launcher learned     «Нужно обновление» alone. «Обновить» installs
 *     this build's helper with the launch exe it has; if the found file still differs after it, the
 *     launcher's line comes, «Заменить» a step of its own;
 *   another build's helper + the game won't start   «Нужно обновление», and the red line under it.
 *     The old build may be what fails, and updating is the cheapest thing to try: one prompt, the
 *     same file, and its setup takes the mark off (a new `state.json`), so this build tries again
 *     at the next session. If it fails too, the file line + «Изменить» come back over the red line,
 *     the build ruled out. (If the red line hid the update, nothing would replace the old build:
 *     «Изменить» installs this build's too, but a file that is right gives no reason to press it);
 *   all three                                       the same: the update, the red line under it;
 *   a launcher learned + the game won't start       the file line, the launcher's line and the red
 *     one under them — the found file may be the one that starts the game.
 */
function helperStatus(
  t: ReturnType<typeof useT>,
  helper: GameHelperDto | null,
  hasGame: boolean,
  actions: HelperActions,
): HelperStatus {
  const none: HelperStatus = { lines: [], gaveUp: false };
  if (helper === null || !hasGame) return none;
  if (helper.launch_exe === null) {
    return {
      lines: [
        {
          key: "no-launch",
          text: t("app.gameHelperNoLaunch"),
          tone: "attention",
          button: { label: t("app.gameHelperPickFile"), onClick: actions.choose },
        },
      ],
      gaveUp: false,
    };
  }
  if (!helper.enabled) return none;
  if (helper.mismatch !== null) {
    return {
      lines: [
        {
          key: "confirm",
          text: t("app.gameHelperConfirmNeeded"),
          tone: "attention",
          button: { label: t("app.gameHelperConfirm"), onClick: actions.confirm },
        },
      ],
      gaveUp: false,
    };
  }
  // «Игра не запускается» goes under whatever lines are shown.
  const gaveUp = helper.failed_launch;
  // Amber, first: the old build works on, but without the new one's fixes.
  if (helper.outdated) {
    return {
      lines: [
        {
          key: "update",
          text: t("app.gameHelperUpdate"),
          tone: "attention",
          button: { label: t("app.gameHelperUpdateInstall"), onClick: actions.update },
        },
      ],
      gaveUp,
    };
  }
  const file: HelperLine = {
    key: "launch",
    text: t("app.gameHelperLaunch", { name: helper.launch_name ?? "" }),
    tone: "muted",
    title: helper.launch_exe,
    middle: true,
    button: { label: t("app.gameHelperChange"), onClick: actions.choose },
  };
  if (helper.found_launch !== null) {
    const found: HelperLine = {
      key: "found",
      text: t("app.gameHelperFound"),
      tone: "muted",
      title: helper.found_launch,
      button: { label: t("app.gameHelperApply"), onClick: actions.apply },
    };
    return { lines: [file, found], gaveUp };
  }
  return { lines: [file], gaveUp };
}

/** What the helper's row shows (`HelperRow`); out of the component, like `helperStatus`. */
interface HelperView {
  /** The switch's position: where its own running change is heading, else the saved one. */
  on: boolean;
  switchDisabled: boolean;
  lines: HelperLine[];
  /** Red, under the lines: «Игра не запускается», then the last change's failure. */
  errors: string[];
}

function helperView(
  t: ReturnType<typeof useT>,
  helper: GameHelperDto | null,
  hasGame: boolean,
  change: HelperChange | null,
  error: HelperError,
  actions: HelperActions,
): HelperView {
  const busy = change !== null;
  const on = change?.switchTo ?? helper?.enabled ?? false;
  const noLaunch = helper !== null && helper.launch_exe === null;
  const status = helperStatus(t, helper, hasGame, actions);
  const failure =
    error === "not_found"
      ? t("app.gameHelperNotFound")
      : error === "failed"
        ? t("app.gameHelperFailed")
        : null;
  return {
    on,
    // Off, it waits for a game and a launch exe; on, it can always be turned off.
    switchDisabled: busy || helper === null || (!on && (!hasGame || noLaunch)),
    // A change in flight is one line, whatever was there: no button to press twice.
    lines: busy
      ? [{ key: "waiting", text: t("app.gameHelperWaiting"), tone: "muted" }]
      : status.lines,
    errors: [
      ...(status.gaveUp ? [t("app.gameHelperGaveUp")] : []),
      ...(failure !== null ? [failure] : []),
    ],
  };
}

/**
 * «Запускать игру автоматически» and, under it, «Если она закроется или свернётся во время
 * сеанса»: during a session, with «Только игра» on, the helper launches the game if it is closed and
 * brings it back to the front if it is minimized or behind other windows; outside one it does
 * nothing. The label and that line, the switch beside them — always the switch, disabled while it
 * cannot be turned on (no game, no launch exe). Under them the status lines (`helperStatus`), each
 * as tall as the compact `xs` button its action is (`min-h-6`, 24px), with its button or without —
 * so «Ждём Windows…» in a line's place moves nothing — 8px under the switch's block and 4px apart;
 * under those, red, 4px apart too, «Игра не запускается» and what the last change failed with (the
 * lines without the air of 32px buttons). The label and its line are balanced:
 * when they wrap (in the narrow window) they break into even lines rather than leave a word alone
 * on the last one.
 *
 * While a change runs — the Open dialog, Windows' prompt, the setup — the lines are one muted «Ждём
 * Windows…» with no button, and the switch is disabled where it was (or where the owner moved it).
 * Declining Windows' prompt just leaves everything as it was.
 *
 * It is the card's last row, so its height moves nothing in the card; the card grows or shrinks at
 * the bottom when a line comes or goes. The switch is described by its line and by the first status
 * line, so «Нужен файл запуска» says why it cannot be turned on.
 */
function HelperRow({
  helper,
  hasGame,
  change,
  error,
  onToggle,
  onConfirm,
  onChoose,
  onUpdate,
  onApply,
}: {
  helper: GameHelperDto | null;
  hasGame: boolean;
  change: HelperChange | null;
  error: HelperError;
  onToggle: (on: boolean) => void;
  onConfirm: () => void;
  onChoose: () => void;
  onUpdate: () => void;
  onApply: () => void;
}) {
  const t = useT();
  const switchId = useId();
  const aboutId = useId();
  const lineId = useId();
  const busy = change !== null;
  const { on, switchDisabled, lines, errors } = helperView(t, helper, hasGame, change, error, {
    confirm: onConfirm,
    choose: onChoose,
    update: onUpdate,
    apply: onApply,
  });

  return (
    <div className="border-t border-line px-4 py-3">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <Label
            htmlFor={switchId}
            className={cn("text-balance", switchDisabled ? "cursor-default" : "cursor-pointer")}
          >
            {t("app.gameHelperToggle")}
          </Label>
          <p id={aboutId} className="mt-0.5 text-balance text-hint text-muted">
            {t("app.gameHelperAbout")}
          </p>
        </div>
        <Switch
          id={switchId}
          aria-describedby={lines.length > 0 ? `${aboutId} ${lineId}` : aboutId}
          checked={on}
          disabled={switchDisabled}
          onCheckedChange={onToggle}
        />
      </div>
      {/* Empty, each has no height. */}
      <div aria-live="polite">
        {lines.map((line, i) => (
          <div
            key={line.key}
            className={cn(
              "flex min-h-6 items-center justify-between gap-3",
              i === 0 ? "mt-2" : "mt-1",
            )}
          >
            <p
              id={i === 0 ? lineId : undefined}
              className={cn("min-w-0 truncate text-hint", TONE[line.tone])}
              title={line.title}
            >
              {line.middle ? (
                <MiddleEllipsis
                  text={line.text}
                  title={line.title}
                  logAs="«Файл запуска» in Settings"
                />
              ) : (
                line.text
              )}
            </p>
            {line.button ? (
              <Button size="xs" disabled={busy} onClick={line.button.onClick}>
                {line.button.label}
              </Button>
            ) : null}
          </div>
        ))}
      </div>
      <div role="status">
        {errors.map((text) => (
          <p key={text} className="mt-1 text-hint text-danger">
            {text}
          </p>
        ))}
      </div>
    </div>
  );
}
