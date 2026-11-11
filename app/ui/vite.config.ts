import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/**
 * The desktop client's window.
 *
 * Built to `dist/`, which `src-tauri/tauri.conf.json` points at. Two things differ from a web
 * app and both come from running inside a webview on someone's own machine:
 *
 *   base: "./"    the bundle is loaded from a file:// or tauri:// origin, where an absolute
 *                 /assets/... path resolves to the filesystem root and finds nothing.
 *   sourcemap     off, minified (vite's default). Tauri embeds every file of `dist/` into
 *                 afklink-app.exe, a `.map` included, so a map — even a "hidden" one — would hand
 *                 anyone holding the exe the window's whole TypeScript source (`sourcesContent`).
 *                 It bought nothing: the window reports no errors or stacks anywhere (no
 *                 onerror / unhandledrejection handler) and a release build has no devtools.
 *                 For local debugging, `bun run dev` serves the sources as they are.
 */
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "./",
  build: {
    target: "es2022",
    sourcemap: false,
    minify: true,
    emptyOutDir: true,
  },
  server: {
    port: 5174,
    strictPort: true,
  },
  // Tauri surfaces build-time values under this prefix.
  envPrefix: ["VITE_", "TAURI_"],
});
