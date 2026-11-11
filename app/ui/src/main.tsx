import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { I18nProvider } from "./i18n";
import { PairRequestWindow } from "./PairRequestWindow";
import "./styles.css";

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("Root element #root not found");

/**
 * One bundle, two windows. The `pair-request` window renders only the
 * confirmation prompt; everything else renders the main tool. The window
 * identifies itself by its Tauri label — no router, no URL convention between
 * the Rust and TS sides to drift apart.
 *
 * Outside Tauri (`vite dev` in a browser) there is no label, so `#/pair-request`
 * doubles as a preview route for the prompt window.
 */
function Root() {
  const [pairWindow, setPairWindow] = useState<boolean | null>(() =>
    typeof window !== "undefined" && window.location.hash === "#/pair-request" ? true : null,
  );

  useEffect(() => {
    if (pairWindow !== null) return;
    let live = true;
    import("@tauri-apps/api/window")
      .then(({ getCurrentWindow }) => {
        if (live) setPairWindow(getCurrentWindow().label === "pair-request");
      })
      .catch(() => {
        if (live) setPairWindow(false);
      });
    return () => {
      live = false;
    };
  }, [pairWindow]);

  if (pairWindow === null) {
    return <div className="h-full" aria-busy="true" />;
  }
  return pairWindow ? <PairRequestWindow /> : <App />;
}

createRoot(rootEl).render(
  <StrictMode>
    <I18nProvider>
      <Root />
    </I18nProvider>
  </StrictMode>,
);
