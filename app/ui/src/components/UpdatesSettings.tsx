import type { Locale, TranslationKey, Translator } from "@afklink/i18n/pc";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { useLanguage, useT } from "../i18n";
import {
  applyUpdate,
  type BuildInfoDto,
  checkForUpdates,
  getBuildInfo,
  getUpdateStatus,
  onUpdateStatus,
  setAutoUpdate,
  type UpdateAction,
  type UpdateState,
  type UpdateStatusDto,
} from "../tauri";
import { Button } from "./ui/button";
import { Label } from "./ui/input";
import { Switch } from "./ui/switch";

/** How often the section re-reads the updater while Settings is open (its events come besides). */
const POLL_MS = 1000;

/**
 * A download that is over sooner than this shows no progress: a release downloads in about a
 * second on a good line, and a bar that appears and vanishes at once is only a flash.
 */
const PROGRESS_AFTER_MS = 300;

/**
 * A line that says something is under way — «Проверка…», «Загрузка 45 %» — once shown, stays at
 * least this long, so the answer does not replace it before it can be read (a download that ends
 * meanwhile fills its bar first).
 */
const HOLD_MS = 600;

/** The states a line says something is under way in: held for `HOLD_MS` once shown. */
const UNDER_WAY: ReadonlySet<UpdateState> = new Set(["checking", "downloading"]);

/** The one button under the status line, by what Rust says it does (`UpdateStatusDto.action`). */
const ACTIONS: Record<
  UpdateAction,
  { label: TranslationKey; run: () => Promise<void>; command: string }
> = {
  check: { label: "app.updateCheck", run: checkForUpdates, command: "check_for_updates" },
  retry_check: { label: "common.retry", run: checkForUpdates, command: "check_for_updates" },
  install: { label: "app.updateInstall", run: applyUpdate, command: "apply_update" },
  retry_update: { label: "common.retry", run: applyUpdate, command: "apply_update" },
};

/** The status line for the states that say one thing, whatever else is known. */
const PLAIN: Partial<Record<UpdateState, TranslationKey>> = {
  checking: "app.updateChecking",
  after_session: "app.updateAfterSession",
  later: "app.updateLater",
  installing: "app.updateInstalling",
  check_failed: "app.updateCheckFailed",
  download_failed: "app.updateDownloadFailed",
  rolled_back: "app.updateRolledBack",
};

interface Line {
  /** Two or three words: what is true now. */
  text: string;
  /** After a middle dot, muted: when the last check was. */
  muted: string | null;
  /** What a screen reader is told when it changes: the line without its percent. */
  spoken: string;
}

/**
 * The status line under «Версия», or null when there is nothing to say yet (the very first start,
 * before the first check, which comes within seconds): the line is then gone, not an empty gap.
 */
function statusLine(t: Translator, locale: Locale, s: UpdateStatusDto, now: number): Line | null {
  const plain = (text: string): Line => ({ text, muted: null, spoken: text });
  if (s.unavailable === "dev") return plain(t("app.updateDevBuild"));
  if (s.unavailable === "off") return plain(t("app.updateUnavailable"));
  const key = PLAIN[s.state];
  if (key !== undefined) return plain(t(key));
  // For the whole first run after an update: «Обновлено до 0.1.1», where it would say
  // «Последняя версия» (or nothing yet).
  const current = s.updated
    ? t("app.updateUpdated", { version: s.version })
    : t("app.updateUpToDate");
  switch (s.state) {
    case "idle":
      return s.updated ? plain(current) : null;
    case "up_to_date": {
      const muted = s.checked_at_ms === null ? null : checkedAt(t, locale, s.checked_at_ms, now);
      return { text: current, muted, spoken: muted === null ? current : `${current}, ${muted}` };
    }
    case "available":
      return plain(t("app.updateAvailable", { version: s.latest ?? "" }));
    case "downloading":
      return {
        text:
          s.progress === null
            ? t("app.updateDownloading")
            : t("app.updateDownloadingPercent", { percent: s.progress }),
        muted: null,
        spoken: t("app.updateDownloading"),
      };
    default:
      // A state this window does not know (a newer Rust side): nothing rather than a guess.
      return null;
  }
}

/**
 * «проверено в 16:50» today, «проверено вчера в 22:10», «проверено» and the date before — by the
 * PC's clock, in the window's language.
 */
function checkedAt(t: Translator, locale: Locale, atMs: number, now: number): string {
  const at = new Date(atMs);
  const time = at.toLocaleTimeString(locale, { hour: "numeric", minute: "2-digit" });
  const today = new Date(now);
  if (sameDay(at, today)) return t("app.updateCheckedAt", { time });
  const yesterday = new Date(now);
  yesterday.setDate(today.getDate() - 1);
  if (sameDay(at, yesterday)) return t("app.updateCheckedYesterday", { time });
  return t("app.updateCheckedOn", {
    date: at.toLocaleDateString(locale, { day: "numeric", month: "long" }),
  });
}

function sameDay(a: Date, b: Date): boolean {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

/**
 * Settings → «Обновления», in three rows: the version with its status under it, the one button the
 * status calls for, and «Обновлять автоматически».
 *
 * The status always says something true — never an empty line before the check or after the
 * restart, «Скачивается» with no progress, «Установится после сеанса» with nobody connected, or
 * «Проверить» flipping it: «Последняя версия · проверено в
 * 16:50», «Обновлено до 0.1.1» for the run after an update, «Проверка…», «Загрузка 45 %» over a thin
 * lime bar, «Установка…», «Установится после сеанса» only while someone is connected, «Доступна
 * версия 0.1.2» with «Установить» when automatic updates are off, and «Не удалось …» with
 * «Повторить». Which state and which button is Rust's decision (`updater::status_dto`); this only
 * words it, and keeps what is under way on screen long enough to read (`useSteadyStatus`).
 *
 * The version row names the build — «0.1.1» for a release, «0.1.1 · a9dd98f · dev» for a
 * development build — with the commit and the build time in its tooltip.
 */
export function UpdatesSettings() {
  const t = useT();
  const { locale } = useLanguage();
  const titleId = useId();
  const autoId = useId();
  const build = useBuildInfo();
  const { latest, read, setAuto } = useUpdateStatus();
  const shown = useSteadyStatus(latest);

  const on = latest !== null && latest.unavailable === null;
  const line = shown === null ? null : statusLine(t, locale, shown, Date.now());
  const action = on && shown !== null ? shown.action : null;
  const progress = shown?.state === "downloading" ? shown.progress : null;

  return (
    <section aria-labelledby={titleId}>
      <h2 id={titleId} className="mb-2 px-1 text-body font-semibold text-muted">
        {t("app.sectionUpdates")}
      </h2>
      <div className="rounded-card border border-line bg-panel">
        <div className="px-4 pt-3.5 pb-3.5">
          <div className="flex items-center justify-between gap-3">
            <p className="shrink-0 text-body text-ink">{t("app.version")}</p>
            {/* Untranslated: a technical identifier. */}
            <p
              className="selectable min-w-0 truncate text-body text-muted tabular-nums"
              translate="no"
              title={build ? buildTooltip(build) : undefined}
            >
              {build?.label ?? latest?.version ?? "—"}
            </p>
          </div>
          {line !== null ? (
            <p className="mt-1 text-body text-ink tabular-nums">
              {line.text}
              {line.muted !== null ? <span className="text-muted"> · {line.muted}</span> : null}
            </p>
          ) : null}
          {progress !== null ? (
            <ProgressBar percent={progress} label={t("app.updateDownloading")} />
          ) : null}
          <span className="sr-only" aria-live="polite">
            {line?.spoken ?? ""}
          </span>
          {action !== null && shown !== null ? (
            <div className="mt-3 flex">
              <Button
                size="sm"
                variant={action === "install" ? "primary" : "secondary"}
                disabled={shown.busy}
                onClick={() => {
                  const { run, command } = ACTIONS[action];
                  // Rust logs the press and what follows; the answer comes as the next status.
                  run()
                    .catch((e: unknown) => console.warn(`[ipc] ${command} failed: ${String(e)}`))
                    .finally(() => void read());
                }}
              >
                {t(ACTIONS[action].label)}
              </Button>
            </div>
          ) : null}
        </div>
        {on ? (
          <div className="flex min-h-13 items-center justify-between gap-3 border-t border-line px-4 py-2">
            <Label htmlFor={autoId} className="cursor-pointer">
              {t("app.updateAuto")}
            </Label>
            <Switch id={autoId} checked={latest.auto} onCheckedChange={setAuto} />
          </div>
        ) : null}
      </div>
    </section>
  );
}

/** The download's percent: a thin lime bar under «Загрузка 45 %». */
function ProgressBar({ percent, label }: { percent: number; label: string }) {
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={percent}
      className="mt-2 h-1 overflow-hidden rounded-full bg-line"
    >
      <div
        className="h-full rounded-full bg-accent transition-[width] duration-200 ease-out"
        style={{ width: `${percent}%` }}
      />
    </div>
  );
}

/**
 * The updater's status: read now, every `POLL_MS`, and on each `update-status` event (a download's
 * percent, a change of state). A status older than the one held — a poll overtaken by an event —
 * is dropped by its sequence number.
 */
function useUpdateStatus() {
  const [latest, setLatest] = useState<UpdateStatusDto | null>(null);

  const take = useCallback((next: UpdateStatusDto) => {
    setLatest((held) => (held !== null && next.seq < held.seq ? held : next));
  }, []);

  const read = useCallback(async () => {
    try {
      take(await getUpdateStatus());
    } catch (e) {
      console.warn(`[ipc] get_update_status failed: ${String(e)}`);
    }
  }, [take]);

  useEffect(() => {
    let stop: (() => void) | null = null;
    let gone = false;
    onUpdateStatus(take)
      .then((unlisten) => {
        if (gone) unlisten();
        else stop = unlisten;
      })
      .catch((e: unknown) => console.warn(`[ipc] update status events not followed: ${String(e)}`));
    void read();
    const timer = window.setInterval(() => void read(), POLL_MS);
    return () => {
      gone = true;
      stop?.();
      window.clearInterval(timer);
    };
  }, [read, take]);

  const setAuto = (enabled: boolean) => {
    // Shown at once; Rust applies, saves and logs it (`set_auto_update`), and the next read shows
    // what is in effect.
    setLatest((held) => (held === null ? held : { ...held, auto: enabled }));
    setAutoUpdate(enabled)
      .catch((e: unknown) => console.warn(`[ipc] set_auto_update(${enabled}) failed: ${String(e)}`))
      .finally(() => void read());
  };

  return { latest, read, setAuto };
}

interface Shown {
  status: UpdateStatusDto;
  /** When its state began to show (`performance.now()`). */
  since: number;
}

/**
 * What to show for `latest` now — null: keep what is shown — and in how many ms to look again.
 *
 * - A line of something under way stays `HOLD_MS` once shown; a download that is over meanwhile
 *   shows its bar full until then.
 * - A download shows only once it has run `PROGRESS_AFTER_MS` (`downloadSince`); a quicker one goes
 *   straight from what was on screen to what follows it.
 */
function steady(
  latest: UpdateStatusDto,
  shown: Shown | null,
  downloadSince: number | null,
  now: number,
): { show: UpdateStatusDto | null; again: number | null } {
  if (shown === null) return { show: latest, again: null };
  const s = shown.status;
  const heldFor = now - shown.since;
  if (UNDER_WAY.has(s.state) && latest.state !== s.state && heldFor < HOLD_MS) {
    const full =
      s.state === "downloading" && s.progress !== null && s.progress < 100
        ? { ...s, progress: 100 }
        : null;
    return { show: full, again: HOLD_MS - heldFor };
  }
  if (latest.state === "downloading" && s.state !== "downloading" && downloadSince !== null) {
    const ran = now - downloadSince;
    if (ran < PROGRESS_AFTER_MS) return { show: null, again: PROGRESS_AFTER_MS - ran };
  }
  return { show: latest, again: null };
}

/** `latest`, as the section shows it: nothing under way flashes (`steady`). */
function useSteadyStatus(latest: UpdateStatusDto | null): UpdateStatusDto | null {
  const [shown, setShown] = useState<UpdateStatusDto | null>(null);
  const memo = useRef<{
    latest: UpdateStatusDto | null;
    shown: Shown | null;
    downloadSince: number | null;
    timer: number;
  }>({ latest: null, shown: null, downloadSince: null, timer: 0 });

  const step = useCallback(() => {
    const m = memo.current;
    window.clearTimeout(m.timer);
    if (m.latest === null) return;
    const now = performance.now();
    const { show, again } = steady(m.latest, m.shown, m.downloadSince, now);
    if (show !== null) {
      const since = m.shown !== null && m.shown.status.state === show.state ? m.shown.since : now;
      m.shown = { status: show, since };
      setShown(show);
    }
    if (again !== null) m.timer = window.setTimeout(step, again);
  }, []);

  useEffect(() => {
    const m = memo.current;
    m.latest = latest;
    if (latest?.state === "downloading") m.downloadSince ??= performance.now();
    else m.downloadSince = null;
    step();
  }, [latest, step]);

  useEffect(() => () => window.clearTimeout(memo.current.timer), []);

  return shown;
}

/** The version row's tooltip: «<commit>[-dirty] · <build time UTC>», what the label leaves out. */
function buildTooltip(build: BuildInfoDto): string | undefined {
  const commit = build.commit === null ? null : `${build.commit}${build.dirty ? "-dirty" : ""}`;
  const parts = [commit, build.built_at].filter((p): p is string => p !== null);
  return parts.length > 0 ? parts.join(" · ") : undefined;
}

/** Which build this is, read once; null until it answers (or without a bridge). */
function useBuildInfo(): BuildInfoDto | null {
  const [build, setBuild] = useState<BuildInfoDto | null>(null);
  useEffect(() => {
    let cancelled = false;
    getBuildInfo()
      .then((b) => {
        if (!cancelled) setBuild(b);
      })
      .catch((e: unknown) => console.warn(`[ipc] build info not read: ${String(e)}`));
    return () => {
      cancelled = true;
    };
  }, []);
  return build;
}
