import type { TranslationKey, Translator } from "@afklink/i18n/pc";
import { useCallback, useEffect, useRef, useState } from "react";
import { useT } from "../i18n";
import { cn } from "../lib/utils";
import {
  type FakerInputAction,
  type FakerInputOutcome,
  type FakerInputStep,
  type FakerInputSteps,
  onFakerInputProgress,
  runFakerInputAction,
  type WindowsLanguage,
} from "../tauri";
import { ProgressSteps } from "./Steps";
import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";

/**
 * The driver's three operations — install, remove, reinstall — each through one dialog, shared by
 * Settings' «Управление в играх» section (`FakerInputSettings`) and the main view's row of the same
 * name (`HomeCard`): the same explanation, the same steps, the same outcomes, wherever it starts.
 */

/** How long a success stays before the dialog closes itself. */
const DONE_SHOWN_MS = 1500;

/**
 * The dialog's last line, by how the operation ended. «Готово» is for a screen reader only: on
 * screen the title already says it («Драйвер установлен»).
 */
const RESULTS = {
  done: "common.done",
  restart_required: "app.fakerInputRestartRequired",
  cancelled: "app.fakerInputCancelled",
  installer_busy: "app.fakerInputInstallerBusy",
  // Installed, but the device did not appear: the card behind now offers «Переустановить».
  device_missing: "app.fakerInputNotStarted",
  failed: "app.fakerInputFailed",
} satisfies Record<FakerInputOutcome, TranslationKey>;

/** Outcomes told as a failure: the stopped step and the last line in the danger tone. */
function isFailure(outcome: FakerInputOutcome | null): boolean {
  return outcome === "failed" || outcome === "device_missing";
}

function resultClass(outcome: FakerInputOutcome): string {
  if (outcome === "done") return "sr-only";
  return cn("mt-4 text-balance text-body", isFailure(outcome) ? "text-danger" : "text-ink");
}

/**
 * What Windows' own windows say during an operation, word for word — the buttons to press and the
 * window to recognise. Not translations but Windows' data, in Windows' display language whatever
 * the app's is (`WindowsLanguage`), so they live here rather than in the dictionary; the hints'
 * templates in `@afklink/i18n` take them as `{yes}`, `{install}` and `{window}`.
 *
 * Checked against Windows 11 26100's own resources in ru-RU and en-US, and against Microsoft's
 * «How User Account Control works» (en and ru):
 * - `yes`: the UAC prompt's button — «Да» / «Нет», "Yes" / "No" (Microsoft Learn: «выбирает Да или
 *   Нет», "selects Yes or No"); the prompt's title is «Контроль учетных записей» / "User Account
 *   Control";
 * - `window`, `install`: the driver prompt Windows shows while the package installs, until its
 *   publisher is trusted (`pnpui.dll.mui`, `Windows.UI.CredDialogController.dll.mui`) — titled
 *   «Безопасность Windows» / "Windows Security", asking «Установить программное обеспечение для
 *   данного устройства?» / "Would you like to install this device software?", with «Установить» /
 *   «Не устанавливать», "Install" / "Don't Install".
 *
 * Any other Windows language gets the hints' `other` wording, which names no button: a name Windows
 * does not show would mislead more than none. The window's name keeps its words on one line (a
 * no-break space), so it reads as the name it is.
 */
const WINDOWS_WORDS = {
  ru: { yes: "Да", install: "Установить", window: "Безопасность\u00a0Windows" },
  en: { yes: "Yes", install: "Install", window: "Windows\u00a0Security" },
} satisfies Record<Exclude<WindowsLanguage, "other">, Record<"yes" | "install" | "window", string>>;

type WindowsWords = (typeof WINDOWS_WORDS)[keyof typeof WINDOWS_WORDS];

function windowsWords(language: WindowsLanguage | undefined): WindowsWords | null {
  return language === "ru" || language === "en" ? WINDOWS_WORDS[language] : null;
}

/**
 * A step's second line: the same in every case, or quoting Windows' words — `windows` when they
 * are known, `other` when Windows speaks a language they are not checked in.
 */
type Hint = TranslationKey | { windows: TranslationKey; other: TranslationKey };

interface StepText {
  title: TranslationKey;
  /** Absent where there is nothing useful to add to the title. */
  hint?: Hint;
}

function hintText(
  t: Translator,
  hint: Hint | undefined,
  words: WindowsWords | null,
): string | undefined {
  if (hint === undefined) return undefined;
  if (typeof hint === "string") return t(hint);
  return words ? t(hint.windows, words) : t(hint.other);
}

/** The UAC prompt, the first thing every operation meets. */
const CONSENT_HINT: Hint = {
  windows: "app.fakerInputStepConsentHint",
  other: "app.fakerInputStepConsentHintOther",
};

/**
 * Each operation's card button (also its dialog's confirm button), dialog titles and three steps —
 * in the order Rust reports them (`fakerinput_setup::progress`). The title asks before the press,
 * names the operation while it runs (and when it ended short of done — the last line says why),
 * and says the result once done.
 */
export const DRIVER_ACTIONS = {
  install: {
    button: "app.fakerInputInstall",
    titles: {
      ask: "app.fakerInputInstallTitle",
      running: "app.fakerInputInstallRunningTitle",
      done: "app.fakerInputInstallDoneTitle",
    },
    steps: [
      { title: "app.fakerInputStepConsent", hint: CONSENT_HINT },
      // «Безопасность Windows» comes up inside this step, while msiexec runs; the app cannot see
      // it, and the user's answer to it can make this step ~22 s long.
      {
        title: "app.fakerInputStepInstall",
        hint: {
          windows: "app.fakerInputStepInstallHint",
          other: "app.fakerInputStepInstallHintOther",
        },
      },
      { title: "app.fakerInputStepStart", hint: "app.fakerInputStepStartHint" },
    ],
  },
  // No driver prompt on removal: only UAC.
  remove: {
    button: "app.fakerInputRemove",
    titles: {
      ask: "app.fakerInputRemoveTitle",
      running: "app.fakerInputRemoveRunningTitle",
      done: "app.fakerInputRemoveDoneTitle",
    },
    steps: [
      { title: "app.fakerInputStepConsent", hint: CONSENT_HINT },
      { title: "app.fakerInputStepRemove", hint: "app.fakerInputStepRemoveHint" },
      { title: "app.fakerInputStepVerify" },
    ],
  },
  // Two UAC prompts, one inside each of the first two steps, and the driver prompt in the second.
  reinstall: {
    button: "app.fakerInputReinstall",
    titles: {
      ask: "app.fakerInputReinstallTitle",
      running: "app.fakerInputReinstallRunningTitle",
      done: "app.fakerInputReinstallDoneTitle",
    },
    steps: [
      { title: "app.fakerInputStepRemove", hint: CONSENT_HINT },
      {
        title: "app.fakerInputStepInstall",
        hint: {
          windows: "app.fakerInputStepReinstallHint",
          other: "app.fakerInputStepReinstallHintOther",
        },
      },
      { title: "app.fakerInputStepStart", hint: "app.fakerInputStepStartHint" },
    ],
  },
} satisfies Record<
  FakerInputAction,
  {
    button: TranslationKey;
    titles: { ask: TranslationKey; running: TranslationKey; done: TranslationKey };
    steps: [StepText, StepText, StepText];
  }
>;

/** The title for where the operation is: not started, running or ended short of done, done. */
function titleKey(action: FakerInputAction, run: Run | null): TranslationKey {
  const titles = DRIVER_ACTIONS[action].titles;
  if (run === null) return titles.ask;
  return run.outcome === "done" ? titles.done : titles.running;
}

const NOT_STARTED: FakerInputSteps = ["pending", "pending", "pending"];

/** An operation in the dialog: its steps now and, once it is over, how it ended. */
export interface Run {
  steps: FakerInputSteps;
  outcome: FakerInputOutcome | null;
}

/**
 * The final picture when Rust sent none — the command rejected: the operation was refused before it
 * started, or the IPC itself failed. The running step(s) are where it stopped; if none was running,
 * the first not reached.
 */
function stoppedAt(steps: FakerInputSteps): FakerInputSteps {
  if (steps.includes("active")) {
    const stop = (s: FakerInputStep) => (s === "active" ? "stopped" : s);
    return [stop(steps[0]), stop(steps[1]), stop(steps[2])];
  }
  const next: FakerInputSteps = [...steps];
  const first = next.indexOf("pending");
  if (first >= 0) next[first] = "stopped";
  return next;
}

/** An operation's dialog and run, wherever it was started from. */
export interface DriverMaintenance {
  /** The operation whose dialog is up, or null. */
  dialog: FakerInputAction | null;
  run: Run | null;
  /** An operation is running: its buttons wait. */
  busy: boolean;
  /** Open the dialog for `action` (it asks before anything runs). */
  open: (action: FakerInputAction) => void;
  close: () => void;
  confirm: () => void;
}

/**
 * The dialog's state and its «Установить» / «Удалить» / «Переустановить» press: progress from Rust's
 * events, the outcome from its answer. `reread` runs once the operation is over, whatever the
 * outcome — the caller re-reads the driver there, so its row or section shows the new state before
 * the dialog tells the outcome (and a success closes).
 */
export function useDriverMaintenance(reread: () => Promise<void>): DriverMaintenance {
  const [dialog, setDialog] = useState<FakerInputAction | null>(null);
  const [run, setRun] = useState<Run | null>(null);
  // A second press before the first re-render has disabled the button starts nothing.
  const starting = useRef(false);
  const busy = run !== null && run.outcome === null;

  // Stable, so the dialog's «Готово» timer is not restarted by every render.
  const close = useCallback(() => {
    setDialog(null);
    setRun(null);
  }, []);

  const confirm = async () => {
    if (!dialog || run || starting.current) return;
    starting.current = true;
    const chosen = dialog;
    setRun({ steps: NOT_STARTED, outcome: null });
    // Listening before the command starts, so no step is missed. Without it the steps stay as they
    // are and the final picture still comes with the answer.
    const stopListening = await onFakerInputProgress((progress) => {
      if (progress.operation !== chosen) return;
      setRun((r) => (r && r.outcome === null ? { ...r, steps: progress.steps } : r));
    }).catch((e: unknown) => {
      console.warn(`[ipc] FakerInput progress not followed: ${String(e)}`);
      return null;
    });
    const settle = await runFakerInputAction(chosen).then(
      (report) => (): Run => ({ steps: report.steps, outcome: report.outcome }),
      (e: unknown) => {
        console.warn(`[ipc] FakerInput ${chosen} refused or failed: ${String(e)}`);
        return (r: Run | null): Run => ({
          steps: stoppedAt(r?.steps ?? NOT_STARTED),
          outcome: "failed",
        });
      },
    );
    stopListening?.();
    // Refused or failed operations re-read too: the driver may not be where the caller thought.
    await reread();
    setRun(settle);
    starting.current = false;
  };

  return { dialog, run, busy, open: setDialog, close, confirm: () => void confirm() };
}

/**
 * One dialog for the whole operation. Before the press, its three steps say what will happen, each
 * with a line on what to press in Windows' own windows — named as Windows names them, in Windows'
 * language — or what to expect; after it, the same steps show where the operation is, moved by
 * Rust's real events (the UAC prompt answered, msiexec done, the device found or gone) — never by
 * a timer. While it runs nothing closes it and its buttons are off. At the end, the last line says
 * how it ended and the step where it stopped is marked; a success says itself in the title and
 * closes after `DONE_SHOWN_MS`, anything else waits for «Закрыть». The row or section behind has
 * re-read the driver by then, so the dialog is the one place an outcome is told.
 */
export function MaintenanceDialog({
  maintenance,
  windows,
}: {
  maintenance: DriverMaintenance;
  /** Windows' display language, for the buttons the hints name. */
  windows: WindowsLanguage | undefined;
}) {
  const t = useT();
  const closeRef = useRef<HTMLButtonElement>(null);
  const { dialog: action, run, close: onClose, confirm: onConfirm } = maintenance;
  const outcome = run?.outcome ?? null;
  const running = run !== null && outcome === null;

  // Over: focus to «Закрыть» (the buttons that had it are gone); a success closes by itself.
  useEffect(() => {
    if (outcome === null) return;
    closeRef.current?.focus();
    if (outcome !== "done") return;
    const timer = window.setTimeout(onClose, DONE_SHOWN_MS);
    return () => window.clearTimeout(timer);
  }, [outcome, onClose]);

  if (!action) return null;
  const stepTexts: readonly StepText[] = DRIVER_ACTIONS[action].steps;
  const steps = run?.steps ?? NOT_STARTED;
  const words = windowsWords(windows);
  return (
    <Dialog title={t(titleKey(action, run))} onClose={running ? undefined : onClose}>
      <ProgressSteps
        items={stepTexts.map((step, i) => ({
          title: t(step.title),
          hint: hintText(t, step.hint, words),
          state: steps[i] ?? "pending",
        }))}
        stopTone={isFailure(outcome) ? "danger" : "neutral"}
      />
      <div aria-live="polite">
        {outcome === null ? null : <p className={resultClass(outcome)}>{t(RESULTS[outcome])}</p>}
      </div>
      <div className="mt-4 flex flex-col gap-2">
        {outcome === null ? (
          <>
            <Button variant="primary" disabled={running} onClick={onConfirm}>
              {t(DRIVER_ACTIONS[action].button)}
            </Button>
            <Button variant="ghost" disabled={running} onClick={onClose}>
              {t("common.cancel")}
            </Button>
          </>
        ) : (
          <Button ref={closeRef} onClick={onClose}>
            {t("common.close")}
          </Button>
        )}
      </div>
    </Dialog>
  );
}
