import type { TranslationKey } from "@afklink/i18n/pc";
import { useCallback, useEffect, useId, useState } from "react";
import { useT } from "../i18n";
import { type FakerInputAction, type FakerInputStatus, getFakerInputStatus } from "../tauri";
import { DRIVER_ACTIONS, MaintenanceDialog, useDriverMaintenance } from "./DriverMaintenance";
import { Button } from "./ui/button";

/** The status line. Kept out of the component to keep its complexity down. */
function statusKey(
  checking: boolean,
  probeFailed: boolean,
  device: FakerInputStatus | null,
): TranslationKey {
  if (checking) return "app.fakerInputChecking";
  if (probeFailed || !device) return "app.fakerInputUnknown";
  switch (device.state) {
    case "installed":
    case "installed_external":
      return "app.fakerInputAvailable";
    case "broken":
      return "app.fakerInputDeviceMissing";
    case "not_installed":
      return "app.fakerInputUnavailable";
  }
}

/**
 * The operation the card offers, or `null` for a driver installed outside Windows Installer (there
 * is nothing to remove it with). Before the first answer, a disabled «Установить» holds the place.
 */
function actionFor(device: FakerInputStatus | null): FakerInputAction | null {
  switch (device?.state) {
    case "installed":
      return "remove";
    case "broken":
      return "reinstall";
    case "installed_external":
      return null;
    default:
      return "install";
  }
}

/** Install and reinstall run the embedded x64 package; removal needs no package. */
function needsPackage(action: FakerInputAction | null): boolean {
  return action === "install" || action === "reinstall";
}

/**
 * Settings → «Управление в играх»: the driver's state, the operation it allows, «Проверить», and
 * what the driver is for. Each operation runs through the dialog the main view's row opens too
 * (`DriverMaintenance`).
 */
export function FakerInputSettings() {
  const t = useT();
  const titleId = useId();
  const aboutId = useId();
  const [device, setDevice] = useState<FakerInputStatus | null>(null);
  const [checking, setChecking] = useState(true);
  const [probeFailed, setProbeFailed] = useState(false);
  const action = actionFor(device);

  // `recheck` only for the owner's «Проверить»: the mount and the re-read after an operation stay
  // read-only, so a device closed for a removal stays closed.
  const refresh = useCallback(async (recheck = false) => {
    setChecking(true);
    try {
      setDevice(await getFakerInputStatus(recheck));
      setProbeFailed(false);
    } catch (e) {
      console.warn(`[ipc] get_fakerinput_status failed: ${String(e)}`);
      setProbeFailed(true);
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const maintenance = useDriverMaintenance(() => refresh());
  const busy = maintenance.busy;
  const unsupported = device !== null && !device.install_supported && needsPackage(action);

  return (
    <section aria-labelledby={titleId}>
      <h2 id={titleId} className="mb-2 px-1 text-body font-semibold text-muted">
        {t("app.fakerInputTitle")}
      </h2>
      {/*
        The status, its buttons, then what the driver is for — last, under the buttons, in every
        state. The action button names it as its description, so a screen reader
        still hears it before pressing, though it comes last on screen.
      */}
      <div className="rounded-card border border-line bg-panel px-4 pt-3.5 pb-3">
        <p className="min-h-5 text-body text-ink" aria-live="polite">
          {t(statusKey(checking, probeFailed, device))}
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          {action ? (
            <Button
              size="sm"
              aria-describedby={aboutId}
              disabled={busy || checking || device === null || unsupported}
              onClick={() => maintenance.open(action)}
            >
              {t(DRIVER_ACTIONS[action].button)}
            </Button>
          ) : null}
          <Button
            variant="ghost"
            size="sm"
            disabled={busy || checking}
            onClick={() => void refresh(true)}
          >
            {t("app.fakerInputRefresh")}
          </Button>
        </div>
        {/* Only the platform limit is said here; how an operation ended, its dialog says. */}
        {unsupported ? (
          <p className="mt-2 text-hint text-faint">{t("app.fakerInputUnsupported")}</p>
        ) : null}
        {/* Balanced, so a narrow window breaks it into even lines rather than leave a word alone. */}
        <p id={aboutId} className="mt-2 text-balance text-hint text-muted">
          {t("app.fakerInputAbout")}
        </p>
      </div>
      <MaintenanceDialog maintenance={maintenance} windows={device?.windows_language} />
    </section>
  );
}
