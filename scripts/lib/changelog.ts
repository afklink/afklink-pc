/**
 * `CHANGELOG.md`: a `# ` title and its preface, then `## ` sections — «Не выпущено» first (what the
 * next release will say), then one per release, newest first: `## 0.1.0 — YYYY-MM-DD`.
 *
 * `bun scripts/release.ts` moves the text of «Не выпущено» under a new version heading and leaves
 * «Не выпущено» empty; `bun scripts/release-build.ts` puts a version's text into `latest.json` as the
 * release notes the updater and the bot show.
 */

export const UNRELEASED = "Не выпущено";

/** `## 0.1.0 — YYYY-MM-DD` (the date optional, an ASCII hyphen accepted for the dash). */
const VERSION_HEADING = /^## (\d+\.\d+\.\d+)(?:\s+[—–-]\s+(\d{4}-\d{2}-\d{2}))?\s*$/;

interface Section {
  /** The heading without `## `. */
  title: string;
  /** Index of the heading line. */
  start: number;
  /** Index of the line after the section's last one. */
  end: number;
  /** The text under the heading, blank lines around it trimmed. */
  body: string;
}

/** The text with `\r\n` as `\n`: a checkout with CRLF must not look like different content. */
function lines(text: string): string[] {
  return text.replace(/\r\n/g, "\n").split("\n");
}

function sections(all: string[]): Section[] {
  const starts = all.flatMap((line, i) => (line.startsWith("## ") ? [i] : []));
  return starts.map((start, k) => {
    const end = starts[k + 1] ?? all.length;
    return {
      title: (all[start] ?? "").slice(3).trim(),
      start,
      end,
      body: all
        .slice(start + 1, end)
        .join("\n")
        .trim(),
    };
  });
}

/** The text of «Не выпущено»; throws when the section is missing. Empty when there is nothing. */
export function unreleasedNotes(text: string): string {
  const s = sections(lines(text)).find((x) => x.title === UNRELEASED);
  if (s === undefined) throw new Error(`в CHANGELOG.md нет раздела «## ${UNRELEASED}»`);
  return s.body;
}

/** The text under `## <version> …`; `null` when there is no such heading. */
export function versionNotes(text: string, version: string): string | null {
  const all = lines(text);
  const s = sections(all).find((x) => VERSION_HEADING.exec(all[x.start] ?? "")?.[1] === version);
  return s === undefined ? null : s.body;
}

/**
 * The changelog after releasing `version` on `date` (`YYYY-MM-DD`): «Не выпущено» stays, empty, and
 * its text moves under `## <version> — <date>` right below it. Throws when «Не выпущено» is missing
 * or empty, or `version` already has a heading.
 */
export function promoteUnreleased(text: string, version: string, date: string): string {
  const all = lines(text);
  const found = sections(all);
  const unreleased = found.find((x) => x.title === UNRELEASED);
  if (unreleased === undefined) throw new Error(`в CHANGELOG.md нет раздела «## ${UNRELEASED}»`);
  if (unreleased.body === "") throw new Error(`раздел «## ${UNRELEASED}» в CHANGELOG.md пуст`);
  if (versionNotes(text, version) !== null) {
    throw new Error(`в CHANGELOG.md уже есть раздел «## ${version}»`);
  }
  const before = all.slice(0, unreleased.start);
  const after = all.slice(unreleased.end);
  // Trailing blank lines of the preface and leading ones of the rest are re-made as one each.
  while (before.length > 0 && before[before.length - 1]?.trim() === "") before.pop();
  while (after.length > 0 && after[0]?.trim() === "") after.shift();
  const out = [
    ...(before.length > 0 ? [...before, ""] : []),
    `## ${UNRELEASED}`,
    "",
    `## ${version} — ${date}`,
    "",
    unreleased.body,
    ...(after.length > 0 ? ["", ...after] : []),
  ];
  return `${out.join("\n").trimEnd()}\n`;
}
