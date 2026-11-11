import { RefreshCw } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useT } from "../i18n";
import { cn } from "../lib/utils";
import { type GameWindowDto, listGameWindows } from "../tauri";
import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";
import { MiddleEllipsis } from "./ui/middle-ellipsis";

/** The picker's list, as it loads. `loading` is the first read only: a re-read keeps what is shown. */
type Listing =
  | { kind: "loading" }
  | { kind: "failed" }
  | { kind: "ready"; windows: GameWindowDto[] };

/** One turn of «Обновить»'s icon (`animate-spin`). */
const TURN_MS = 1000;

/** What the picker's box says when it holds no list: centred in it, one line. */
const MESSAGE = "flex h-full items-center justify-center px-3 text-center text-body";

/**
 * The listed windows with their React keys. Two alike (one app, class and title — two windows of
 * one editor, say) are told apart by count: a re-read now updates the list in place, and twin keys
 * there could drop or duplicate a row.
 */
function keyed(windows: GameWindowDto[]): { key: string; w: GameWindowDto }[] {
  const seen = new Map<string, number>();
  return windows.map((w) => {
    const base = `${w.exe_path}|${w.window_class}|${w.title}`;
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    return { key: n === 0 ? base : `${base}#${n}`, w };
  });
}

/**
 * «Окно игры»: the open windows of other apps, each by its app's exe and its title; one press binds
 * it. Opened by Settings' «Выбрать» (`GameOnlySettings`) and by the main view's «Выбрать игру»
 * (`HomeCard`), whose choice turns «Только игра» on as well. Read when the dialog opens and on
 * «Обновить» — a game started meanwhile shows up then.
 *
 * Its height never changes, so «Обновить» does not make the window jump. The list's box has
 * one fixed height whatever it holds — the list, scrolling inside it, or «Загрузка…», «Нет открытых
 * окон» or the failure, centred in it — and nothing else in the dialog changes size, so `Dialog`,
 * which centres its panel, keeps it where it is. «Загрузка…» is for the first read only, with
 * nothing yet to show; a re-read leaves what is shown in place until the answer replaces it, dimmed
 * if it takes a moment (a quick one would only flash), and turns the button's icon. The icon stops
 * on a whole turn, upright, rather than snapping back from mid-turn: the button stays in flight
 * until then, and a press meanwhile is dropped.
 *
 * A long exe's name is cut in the middle, so «.exe» and the end of the name stay; a long title is cut
 * at its end, and a row's tooltip has both whole, the title over the exe's path.
 *
 * A window whose program runs as administrator while the driver is missing carries «Нужен драйвер»
 * in red beside its name (`needs_driver`, decided in Rust): without the driver, controls will not
 * reach it. It can still be chosen; «Установить» is in the driver's row.
 */
export function WindowPicker({
  onPick,
  onClose,
}: {
  onPick: (w: GameWindowDto) => void;
  onClose: () => void;
}) {
  const t = useT();
  const [listing, setListing] = useState<Listing>({ kind: "loading" });
  // A read out: the box keeps what it shows until the answer.
  const [reading, setReading] = useState(false);
  // «Обновить»'s icon turning: from the press to the first whole turn after the answer.
  const [turning, setTurning] = useState(false);
  // The guard itself is a ref: a second press before the re-render would read a stale state.
  const inFlight = useRef(false);
  const stopTimer = useRef<number | undefined>(undefined);

  // `turn`: pressed «Обновить», whose icon turns; the first read has «Загрузка…» to say it.
  const load = useCallback((turn: boolean) => {
    if (inFlight.current) return;
    inFlight.current = true;
    const started = performance.now();
    setReading(true);
    if (turn) setTurning(true);
    listGameWindows()
      .then((windows) => setListing({ kind: "ready", windows }))
      .catch((e: unknown) => {
        console.warn(`[ipc] list_game_windows failed: ${String(e)}`);
        setListing({ kind: "failed" });
      })
      .finally(() => {
        setReading(false);
        if (!turn) {
          inFlight.current = false;
          return;
        }
        const elapsed = performance.now() - started;
        stopTimer.current = window.setTimeout(
          () => {
            inFlight.current = false;
            setTurning(false);
          },
          TURN_MS - (elapsed % TURN_MS),
        );
      });
  }, []);

  useEffect(() => {
    load(false);
    return () => window.clearTimeout(stopTimer.current);
  }, [load]);

  // What a re-read leaves on screen, dimmed only past 150 ms; back at once with the answer.
  const dim = cn(
    "transition-opacity",
    reading && listing.kind !== "loading" && "opacity-60 delay-150",
  );

  return (
    <Dialog title={t("app.gameOnlyPickerTitle")} wide onClose={onClose}>
      <p className="mb-3 text-hint text-faint">{t("app.gameOnlyPickerHint")}</p>
      <div
        className="h-72 overflow-y-auto rounded-control border border-line"
        aria-busy={reading || undefined}
      >
        {listing.kind === "loading" ? (
          <p className={cn(MESSAGE, "text-faint")}>{t("common.loading")}</p>
        ) : listing.kind === "failed" ? (
          <p className={cn(MESSAGE, "text-danger", dim)}>{t("app.gameOnlyPickerFailed")}</p>
        ) : listing.windows.length === 0 ? (
          <p className={cn(MESSAGE, "text-faint", dim)}>{t("app.gameOnlyPickerEmpty")}</p>
        ) : (
          <ul className={dim}>
            {keyed(listing.windows).map(({ key, w }) => (
              <li key={key} className="border-t border-line first:border-t-0">
                <button
                  type="button"
                  onClick={() => onPick(w)}
                  className="flex w-full cursor-pointer flex-col items-start gap-0.5 px-3 py-2 text-left transition-colors hover:bg-white/4"
                  // The title whole over the path: the title is what tells two windows of one
                  // program apart, and the row cuts it.
                  title={`${w.title}\n${w.exe_path}`}
                >
                  <span className="flex w-full min-w-0 items-baseline gap-2">
                    <span className="min-w-0 text-body text-ink" translate="no">
                      <MiddleEllipsis text={w.exe_name} title={`${w.title}\n${w.exe_path}`} />
                    </span>
                    {w.needs_driver && (
                      <span className="ml-auto shrink-0 text-hint text-danger">
                        {t("app.gamePickerNeedsDriver")}
                      </span>
                    )}
                  </span>
                  <span className="max-w-full truncate text-hint text-faint">{w.title}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="mt-3 flex justify-end">
        {/* `aria-disabled` while in flight, not `disabled`: focus stays on it (`Button`). */}
        <Button
          size="sm"
          variant="ghost"
          aria-disabled={reading || turning || undefined}
          onClick={() => load(true)}
        >
          <RefreshCw
            aria-hidden="true"
            className={cn(turning && "animate-spin motion-reduce:animate-none")}
          />
          {t("app.gameOnlyRefresh")}
        </Button>
      </div>
    </Dialog>
  );
}
