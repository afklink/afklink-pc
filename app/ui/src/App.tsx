import {
  ArrowLeft,
  ChevronRight,
  Link2,
  RectangleEllipsis,
  RotateCw,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { type ReactNode, type RefObject, useCallback, useEffect, useRef, useState } from "react";
import { AccessScreen } from "./components/AccessScreen";
import { AutostartCard } from "./components/AutostartCard";
import { ConnectionNotice, REFUSAL_TEXT, refusalOffersRetry } from "./components/ConnectionNotice";
import { HomeCard, type HomeRow } from "./components/HomeCard";
import { JournalScreen } from "./components/JournalScreen";
import { KillBar } from "./components/KillBar";
import { PairingDialog } from "./components/PairingDialog";
import { type SettingsFocus, SettingsView } from "./components/SettingsView";
import { StatusHero } from "./components/StatusHero";
import { StepsCard } from "./components/Steps";
import { Button } from "./components/ui/button";
import { Spinner } from "./components/ui/spinner";
import { useLanguage, useT } from "./i18n";
import { cn } from "./lib/utils";
import {
  cancelPairing,
  type PairingCloseReason,
  type Refusal,
  reportMainWindowRatio,
  requestPairing,
  retryConnection,
  type StatusDto,
  showPairRequest,
  type Zone,
} from "./tauri";
import { useAgentStatus } from "./useAgentStatus";

/** The window's views: the main one, and the screens behind it, each with a way back. */
type View = "main" | "settings" | "access" | "journal";

/** What opened a screen, so focus can go back to it on the way out. */
type Opener = HomeRow | "gear";

/**
 * The desktop client's window — a tray-first tool, not a settings page: the «Панель».
 *
 * The main view, top to bottom:
 *
 *   the status hero  the 96 px monitor pictogram answering "is someone on my screen", and its
 *                    caption — one size in every state; connection trouble is a toast floating in
 *                    its top air (`ConnectionNotice`);
 *   the zone         one thing at a time (`BottomZone`, decided in Rust: `StatusDto.home.zone`) —
 *                    the pairing steps while nobody has access, the one-off «Запускать вместе с
 *                    Windows?», the card of four rows (`HomeCard`), or the loader while who has
 *                    access is not known — in a cell of one height, so nothing above or below it
 *                    moves when it changes;
 *   the footer       the kill switch and the settings gear, which never move.
 *
 * Behind the main view, each with an arrow back and a title in a top row of their own: «Доступ» (the
 * access list and «Начать привязку»), «Журнал» (the connection journal) and «Настройки» —
 * opened by the gear, or by the «Показывать только игру» and «Управление в играх» rows at their
 * section («Только игра» there). Each
 * view has exactly one scrolling box — the content under the top row (or, on the main view, above
 * the footer) — and that box is the containing block of everything positioned in it (`relative`):
 * an absolutely positioned descendant without one (a screen reader's `sr-only` text) is placed
 * against the page instead, and makes the page itself scroll, with empty space under the window's
 * content.
 *
 * Launch: who has access comes from the server's handshake, about a second in. Rust knows the answer
 * sooner when it can (`access_cache`): a new device (config.json written at this launch) has nobody,
 * and the list the server sent last time is kept on disk — so the zone shows the steps or the card
 * from the first frame, and the server's list replaces the cached one when it comes. Only without
 * either (a build before the cache) does the zone show the lime loader, then what the server says;
 * the loader turns for as long as the agent is reconnecting by itself, and a refusal it will not get
 * past alone puts why and «Переподключиться» in its place. The hero needs no wait: who is on the
 * screen is known locally from the first read, and the link only once it has been down for three
 * seconds (`StatusDto.offline`, counted from the launch), so a normal launch shows «Готов к
 * подключению» from the first frame.
 *
 * A pairing request is not shown here at all: the small always-on-top `pair-request` window near the
 * tray has it, whether this window is open or not. A card in this window's zone and at the top of
 * every other view would squeeze Settings to a sliver for up to two minutes.
 *
 * Nothing here decides anything: every action is an `invoke` into Rust, and what the card's rows and
 * the zone say is Rust's (`StatusDto.home`). The exceptions: when to close the pairing panel by
 * itself (someone entered its code, a binding was made while it was open, or the code's ceiling
 * passed — the close tells Rust why, for the log), and the loader standing in for the refusal for a
 * moment after «Переподключиться».
 */
export function App() {
  const t = useT();
  const { ready } = useLanguage();
  const { status, loaded, refresh } = useAgentStatus();
  const [view, setView] = useState<View>("main");
  const [settingsFocus, setSettingsFocus] = useState<SettingsFocus | null>(null);
  const [wantPairing, setWantPairing] = useState(false);
  const panel = status?.pairing_panel ?? "closed";
  const backRef = useRef<HTMLButtonElement>(null);
  // The buttons that open a screen, so focus goes back to the one that did.
  const openers = useRef(new Map<Opener, HTMLButtonElement>());
  const opener = useRef<Opener | null>(null);
  const gearRef = useCallback((el: HTMLButtonElement | null) => {
    if (el) openers.current.set("gear", el);
    else openers.current.delete("gear");
  }, []);
  const rowRef = useCallback((row: HomeRow, el: HTMLButtonElement | null) => {
    if (el) openers.current.set(row, el);
    else openers.current.delete(row);
  }, []);

  // The window's own intent decides whether the panel is shown, so a close takes effect at once;
  // the agent's state only closes it (below). Shown whenever the agent had a code as well, a code
  // that arrived after a quick close would reopen the panel by itself.
  const closePairing = useCallback((reason: PairingCloseReason) => {
    cancelPairing(reason).catch((e: unknown) =>
      console.warn(`[ipc] cancel_pairing (${reason}) failed: ${String(e)}`),
    );
    setWantPairing(false);
  }, []);

  const openPairing = () => {
    requestPairing("opened").catch((e: unknown) =>
      console.warn(`[ipc] request_pairing (opened) failed: ${String(e)}`),
    );
    setWantPairing(true);
  };

  // The code on the open panel is spent — someone entered it (`redeemed`: the confirmation prompt
  // is what remains) or the binding it produced was made (`paired`) — so the panel closes. It used
  // to stay open with the code gone and nothing else in it, until the owner closed it by hand.
  // On the agent's change into either state, not on the state itself: a status still saying
  // `paired` from the last close must not close a panel the owner has just opened again.
  const lastPanel = useRef(panel);
  useEffect(() => {
    const was = lastPanel.current;
    lastPanel.current = panel;
    if (!wantPairing || was === panel) return;
    if (panel === "redeemed" || panel === "paired") closePairing(panel);
  }, [wantPairing, panel, closePairing]);

  // After a reload of this window the agent may still have the panel open with a live code: show
  // it rather than leave it live and unseen. Once, at the first answer.
  const synced = useRef(false);
  useEffect(() => {
    if (synced.current || status === null) return;
    synced.current = true;
    if (status.pairing_panel === "open") setWantPairing(true);
  }, [status]);

  useAccessWaitLog(status);
  useReportPixelRatio();

  const go = (next: View, from: Opener, focus: SettingsFocus | null = null) => {
    opener.current = from;
    setSettingsFocus(focus);
    // biome-ignore lint/suspicious/noConsole: the owner's navigation, once per press
    console.debug(`[view] ${view} → ${next} (from ${from}${focus ? `, at ${focus}` : ""})`);
    setView(next);
  };

  const openRow = (row: HomeRow) => {
    switch (row) {
      case "driver":
        go("settings", row, "driver");
        break;
      case "game":
        go("settings", row, "gameOnly");
        break;
      case "access":
      case "journal":
        go(row, row);
        break;
    }
  };

  const back = () => {
    // biome-ignore lint/suspicious/noConsole: the owner's navigation, once per press
    console.debug(`[view] ${view} → main (back)`);
    setView("main");
  };

  // A view switch unmounts the button that was pressed, and focus would fall to <body>: it goes to
  // the way back on entering a screen, and back to what opened it on leaving.
  const lastView = useRef(view);
  useEffect(() => {
    if (lastView.current === view) return;
    lastView.current = view;
    if (view !== "main") {
      backRef.current?.focus();
      return;
    }
    const from = opener.current;
    if (from !== null) openers.current.get(from)?.focus();
  }, [view]);

  if (!ready || !loaded) {
    return <div className="h-full" aria-busy="true" />;
  }

  /*
    No answer from Rust (`vite dev` in a plain browser, where there is no bridge): nothing to
    show, and nothing true to say — it is not the server that is missing. In the app this does
    not happen: the first poll is an in-process read that cannot fail.
  */
  if (status === null) return <div className="h-full" />;

  return (
    <div className="mx-auto flex h-full max-w-[400px] flex-col">
      {view === "main" ? (
        <MainView
          status={status}
          onChanged={refresh}
          onShowCode={openPairing}
          onOpenRow={openRow}
          onSettings={() => go("settings", "gear")}
          gearRef={gearRef}
          rowRef={rowRef}
        />
      ) : (
        <Screen
          title={
            view === "settings"
              ? t("app.settings")
              : view === "access"
                ? t("app.access")
                : t("app.journal")
          }
          onBack={back}
          backRef={backRef}
        >
          {view === "settings" ? (
            <SettingsView status={status} onRefresh={refresh} focus={settingsFocus} />
          ) : view === "access" ? (
            <AccessScreen
              sessions={status.sessions}
              bindings={status.bindings}
              heldPair={status.held_pair ?? null}
              ownerRequestBusy={status.owner_request_busy}
              onChanged={refresh}
              onShowCode={openPairing}
            />
          ) : (
            <JournalScreen
              bindings={status.bindings}
              ownerRequestBusy={status.owner_request_busy}
              onChanged={refresh}
            />
          )}
        </Screen>
      )}

      {wantPairing ? <PairingDialog status={status} onClose={closePairing} /> : null}
    </div>
  );
}

/**
 * The one scrolling box of a view: the containing block of what is positioned inside it too
 * (`relative`), so nothing in it can make the page scroll as well (see `App`).
 */
const SCROLLER = "relative flex flex-1 flex-col overflow-y-auto";

/**
 * A screen behind the main view: the way back and the title in a top row of their own, the content
 * scrolling below.
 */
function Screen({
  title,
  onBack,
  backRef,
  children,
}: {
  title: string;
  onBack: () => void;
  backRef: RefObject<HTMLButtonElement | null>;
  children: ReactNode;
}) {
  const t = useT();
  return (
    <>
      <header className="flex h-14 shrink-0 items-center gap-1 px-3">
        <button
          ref={backRef}
          type="button"
          onClick={onBack}
          aria-label={t("common.back")}
          title={t("common.back")}
          className="rounded-control p-2 text-muted transition-colors hover:bg-white/6 hover:text-ink"
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
        </button>
        <h1 className="truncate text-heading font-semibold text-ink">{title}</h1>
      </header>
      <main className={cn(SCROLLER, "px-5 pt-1 pb-5")}>{children}</main>
    </>
  );
}

/** The main view: the hero, the zone under it, and the footer. */
function MainView({
  status,
  onChanged,
  onShowCode,
  onOpenRow,
  onSettings,
  gearRef,
  rowRef,
}: {
  status: StatusDto;
  onChanged: () => void;
  onShowCode: () => void;
  onOpenRow: (row: HomeRow) => void;
  onSettings: () => void;
  gearRef: (el: HTMLButtonElement | null) => void;
  rowRef: (row: HomeRow, el: HTMLButtonElement | null) => void;
}) {
  return (
    <>
      <main className={cn(SCROLLER, "px-5 pt-4")}>
        <StatusHero
          sessions={status.sessions}
          paused={status.paused}
          offline={status.offline}
          refusal={status.refusal}
          deviceName={status.device_name}
          liveFor={status.live_for}
          notice={
            <ConnectionNotice
              offline={status.offline}
              refusal={status.refusal}
              refusalInZone={status.home.zone === "refused"}
              onRetried={onChanged}
              className="absolute inset-x-0 top-3"
            />
          }
        />
        <BottomZone
          status={status}
          onChanged={onChanged}
          onShowCode={onShowCode}
          onOpenRow={onOpenRow}
          rowRef={rowRef}
        />
      </main>
      <footer className="shrink-0 border-t border-line px-5 py-3">
        <KillBar
          live={status.sessions.length > 0}
          paused={status.paused}
          onSettings={onSettings}
          onChanged={onChanged}
          settingsRef={gearRef}
        />
      </footer>
    </>
  );
}

/**
 * How long the loader stands in for the refusal after «Переподключиться». The agent keeps its
 * refusal until the new attempt ends, so the status cannot say "trying again"; a refusal comes back
 * within about a second (connect, hello, challenge, error), and an attempt that gets further clears
 * it or brings the list, either of which ends the wait by itself.
 */
const RETRY_SPIN_MS = 2500;

/**
 * Under the hero, one thing at a time — Rust's `StatusDto.home.zone`:
 *
 *   steps      nobody has access (the server says so, it said so last time, or this is a new
 *              device): the three pairing steps as the rows of a card like `HomeCard`'s — the first
 *              lime (it is the button under them), the two after it neutral (`StepsCard`) — and
 *              «Начать привязку», lime. While a pairing request waits (`home.steps`: `request`) —
 *              in its own window near the tray, with the steps' «3» on it — they follow it:
 *              1 and 2 ticked, 3 the one now, its row a link that brings the request window
 *              forward, and «Начать привязку» in place, disabled; back as they were when the request
 *              goes (declined, withdrawn, run out), and on to the autostart question once approved;
 *   autostart  «Запускать вместе с Windows?» (`AutostartCard`), once, after the first pairing — so
 *              on first run the steps give way to it, and it to the card, in the same place;
 *   card       the four rows (`HomeCard`);
 *   loading    who has access is not known yet (no server answer, no cache, not a new device): the
 *              lime loader — for as long as the agent is reconnecting by itself (1 s doubling to 30 s,
 *              `afklink_core::reconnect`), beside the «Нет связи с сервером» toast;
 *   refused    not known, and the backend refuses this agent (`StatusDto.refusal`) — it will not be
 *              back by itself soon: after `replaced` not at all until asked, after another fatal code
 *              every 15 minutes. Why, and «Переподключиться» (the same `retry_connection` as the
 *              toast's «Повторить», which stands down meanwhile); after the press the loader turns
 *              again for `RETRY_SPIN_MS`. `outdated` (`protocol_unsupported`) gets the words alone: no
 *              retry brings back a build the server does not speak to, only an update. So does
 *              `blocked` (`device_blocked`, «ПК заблокирован»): only an admin lifting the block helps,
 *              and the agent's slow retry finds it lifted by itself.
 *
 * Every layer is stacked in one grid cell, only the current one visible: the cell is as tall as the
 * tallest of them (the card), whatever is shown, so the hero above (centred in what the zone leaves)
 * and the footer below never move. The shorter layers stand at the cell's foot, their action where
 * the card's last row ends; the loader at its centre. The steps fill the cell instead, top to foot:
 * their card takes the height the button leaves, its three rows sharing it (52.7px each, against the
 * four rows' 52.5 — no gap above the card, none between the blocks but the layer's 12px). No step
 * wraps at the 340px minimum width (the longest, the Russian first, takes 171 of its 202px there);
 * a wrapped one would make the cell 2px taller. Layers change by a 200 ms crossfade; the
 * hidden ones are inert and hidden from a screen reader.
 */
function BottomZone({
  status,
  onChanged,
  onShowCode,
  onOpenRow,
  rowRef,
}: {
  status: StatusDto;
  onChanged: () => void;
  onShowCode: () => void;
  onOpenRow: (row: HomeRow) => void;
  rowRef: (row: HomeRow, el: HTMLButtonElement | null) => void;
}) {
  const t = useT();
  const [retrying, startRetry] = useRetryHold();
  const zone = status.home.zone;
  const phase: Zone = zone === "refused" && retrying ? "loading" : zone;
  // A request waits in its window: steps 1 and 2 are done, 3 is the one now (`home::Steps`).
  const requestWaits = status.home.steps === "request";
  useRefusedLog(phase, status.refusal);
  usePhaseLog(phase, zone, status);

  // Step 3's row while a request waits: the request window to the front (Rust logs the outcome).
  const showRequest = () => {
    // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
    console.info("[home] step 3 pressed: the request window to the front");
    showPairRequest()
      .then((shown) => {
        if (!shown) console.warn("[home] step 3 pressed with no request up (it went meanwhile)");
      })
      .catch((e: unknown) => console.warn(`[ipc] show_pair_request failed: ${String(e)}`));
  };

  const startPairing = () => {
    if (requestWaits) {
      // biome-ignore lint/suspicious/noConsole: a press dropped on purpose, said once per press
      console.debug(
        "[home] «Начать привязку» pressed while a request waits: disabled (one request per PC)",
      );
      return;
    }
    onShowCode();
  };

  const reconnect = () => {
    if (retrying) return;
    // biome-ignore lint/suspicious/noConsole: the owner's press, once per press
    console.info(`[status] «Переподключиться» pressed (refusal: ${status.refusal ?? "-"})`);
    startRetry();
    // Rust logs the command itself (`retry_connection`); either way the status is re-read.
    retryConnection()
      .catch((e: unknown) => console.warn(`[ipc] retry_connection failed: ${String(e)}`))
      .finally(onChanged);
  };

  const layer = (own: Zone, place: "foot" | "centre" = "foot") => ({
    inert: phase !== own,
    "aria-hidden": phase !== own || undefined,
    "data-layer": own,
    className: cn(
      "col-start-1 row-start-1 flex min-w-0 flex-col gap-3 transition-[opacity,visibility] duration-200 ease-out",
      place === "foot" ? "justify-end" : "justify-center",
      phase === own ? "visible opacity-100" : "invisible opacity-0",
    ),
  });

  return (
    <div className="grid shrink-0 pb-4" data-zone={phase}>
      <div {...layer("loading", "centre")}>
        <div role="status" className="flex items-center justify-center">
          <Spinner />
          <span className="sr-only">{t("common.loading")}</span>
        </div>
      </div>
      <div {...layer("refused")}>
        <RefusedOffer refusal={status.refusal} onReconnect={reconnect} />
      </div>
      <div {...layer("steps")}>
        {/* The card takes the height the button leaves, so the layer fills the zone (see the doc). */}
        <StepsCard
          className="flex-1"
          items={[
            {
              text: t("app.stepShowCode", { button: t("app.showCode") }),
              tone: requestWaits ? "done" : "now",
              icon: Link2,
            },
            {
              text: t("app.stepEnterInApp"),
              tone: requestWaits ? "done" : "later",
              icon: RectangleEllipsis,
            },
            {
              text: t("app.stepAllow", { button: t("app.pairApprove") }),
              tone: requestWaits ? "now" : "later",
              // A link to the request window while it waits: the chevron of `HomeCard`'s rows.
              icon: requestWaits ? ChevronRight : ShieldCheck,
              onPress: requestWaits ? showRequest : undefined,
            },
          ]}
        />
        <Button
          variant="primary"
          size="block"
          aria-disabled={requestWaits || undefined}
          onClick={startPairing}
        >
          <Link2 aria-hidden="true" />
          {t("app.showCode")}
        </Button>
      </div>
      <div {...layer("autostart")}>
        <AutostartCard onAnswered={onChanged} />
      </div>
      <div {...layer("card")}>
        <HomeCard status={status} onOpen={onOpenRow} onChanged={onChanged} rowRef={rowRef} />
      </div>
    </div>
  );
}

/**
 * The zone's refusal: why, in the toast's words, over «Переподключиться» — the one action left, so
 * lime. `outdated` has no button: only an update helps; nor has `blocked` («ПК заблокирован»): only
 * an admin lifting the block helps, and the agent's slow retry sees it by itself.
 */
function RefusedOffer({
  refusal,
  onReconnect,
}: {
  refusal: Refusal | null;
  onReconnect: () => void;
}) {
  const t = useT();
  // Kept while the layer fades out after the refusal has cleared, so its text does not blank.
  const last = useRef<Refusal>("fatal");
  if (refusal !== null) last.current = refusal;
  const shown = last.current;
  return (
    <div className="flex flex-col gap-3">
      <p className="flex items-center justify-center gap-2 text-center text-body text-muted">
        <TriangleAlert className="size-4 shrink-0 text-danger" aria-hidden="true" />
        {t(REFUSAL_TEXT[shown])}
      </p>
      {refusalOffersRetry(shown) ? (
        <Button variant="primary" size="block" onClick={onReconnect}>
          <RotateCw aria-hidden="true" />
          {t("app.reconnect")}
        </Button>
      ) : null}
    </div>
  );
}

/** Loader in place of the refusal for `RETRY_SPIN_MS` after a press, and the press itself. */
function useRetryHold(): [boolean, () => void] {
  const [until, setUntil] = useState<number | null>(null);
  useEffect(() => {
    if (until === null) return;
    const id = window.setTimeout(() => setUntil(null), Math.max(0, until - Date.now()));
    return () => window.clearTimeout(id);
  }, [until]);
  return [until !== null, () => setUntil(Date.now() + RETRY_SPIN_MS)];
}

/** The zone turning into the refusal offer, said once each time it does. */
function useRefusedLog(phase: Zone, refusal: Refusal | null) {
  const last = useRef<Zone | null>(null);
  useEffect(() => {
    const was = last.current;
    last.current = phase;
    if (phase === "refused" && was !== "refused") {
      const offer =
        refusal === "outdated"
          ? "update needed, no retry offered"
          : refusal === "blocked"
            ? "the PC is blocked by an admin, no retry offered (the agent retries every 15 minutes)"
            : "offering «Переподключиться»";
      console.warn(
        `[status] the server refuses this agent (${refusal ?? "-"}) before the access list came: ${offer}`,
      );
    }
  }, [phase, refusal]);
}

/**
 * What the zone shows, said once each time it changes: Rust's zone (its log has why) and the
 * window's own part — the loader held after «Переподключиться» — with where the access list came
 * from. The window's console (devtools) only.
 */
function usePhaseLog(phase: Zone, zone: Zone, status: StatusDto) {
  const last = useRef<Zone | null>(null);
  const { access } = status;
  const bindings = status.bindings.length;
  useEffect(() => {
    const was = last.current;
    last.current = phase;
    if (was === phase) return;
    const held = phase !== zone ? ` (Rust: ${zone}; the loader held after «Переподключиться»)` : "";
    // biome-ignore lint/suspicious/noConsole: once per change of the zone, with what it shows
    console.debug(
      `[home] zone: ${was ?? "-"} → ${phase}${held} — access list from ${access}, ${bindings} binding(s)`,
    );
  }, [phase, zone, access, bindings]);
}

/**
 * Tell Rust the pixel ratio this window's page is drawn at — at load and whenever it changes (a
 * monitor of another scale, Windows' text size turned up or down) — so the window's least size
 * follows Windows' text size (`window_fit::main_window_ratio`: at 125 % the 340×480 window's
 * page is 272×384 CSS px). Once per ratio; a failed report is said and tried again at the next
 * change.
 */
function useReportPixelRatio() {
  useEffect(() => {
    let sent: number | null = null;
    let media: MediaQueryList | null = null;
    const report = () => {
      const ratio = window.devicePixelRatio;
      if (ratio === sent) return;
      sent = ratio;
      // biome-ignore lint/suspicious/noConsole: once per change of the window's pixel ratio
      console.debug(`[window] drawn at ×${ratio}: told to Rust (the window follows the text size)`);
      reportMainWindowRatio(ratio).catch((e: unknown) => {
        sent = null;
        console.warn(`[ipc] main_window_ratio (×${ratio}) failed: ${String(e)}`);
      });
    };
    // A media query for the ratio now: it stops matching when the ratio changes.
    function watch() {
      media?.removeEventListener("change", onChange);
      media = window.matchMedia(`(resolution: ${window.devicePixelRatio}dppx)`);
      media.addEventListener("change", onChange);
    }
    function onChange() {
      report();
      watch();
    }
    report();
    watch();
    return () => media?.removeEventListener("change", onChange);
  }, []);
}

/**
 * The launch's wait for the server's access list, said once per window when it ends: how long after
 * the window's first read, how many bindings came, and what the window showed until then (the cached
 * list, a new device's nobody, or the loader). Nothing while it waits — the agent's log has the
 * connection attempts.
 */
function useAccessWaitLog(status: StatusDto | null) {
  const firstRead = useRef<number | null>(null);
  const before = useRef<string | null>(null);
  const reported = useRef(false);
  useEffect(() => {
    if (status === null || reported.current) return;
    firstRead.current ??= performance.now();
    if (!status.bindings_known) {
      before.current ??= `${status.access}${status.access === "cache" ? ` (${status.bindings.length})` : ""}`;
      return;
    }
    reported.current = true;
    const waited = Math.round(performance.now() - firstRead.current);
    // biome-ignore lint/suspicious/noConsole: the one line for the launch's loading → ready
    console.info(
      `[status] access list from the server ${waited} ms after the first read: ${status.bindings.length} binding(s); shown before it: ${before.current ?? "nothing (it was there at the first read)"}`,
    );
  }, [status]);
}
