/**
 * Release numbers: SemVer `MAJOR.MINOR.PATCH`, plain — no pre-release or build suffix (the owner's
 * decision; the updater compares these, and a suffix would be one more way for two builds to look
 * alike).
 */

export interface Version {
  major: number;
  minor: number;
  patch: number;
}

const PLAIN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

/** `1.2.3` → its parts; anything else (leading zeros, suffixes, a `v`) → null. */
export function parseVersion(text: string): Version | null {
  const m = PLAIN.exec(text);
  if (m === null) return null;
  const [major, minor, patch] = [m[1], m[2], m[3]].map(Number) as [number, number, number];
  if (![major, minor, patch].every(Number.isSafeInteger)) return null;
  return { major, minor, patch };
}

export function formatVersion(v: Version): string {
  return `${v.major}.${v.minor}.${v.patch}`;
}

/** Negative when `a` is older than `b`, zero when equal, positive when newer. */
export function compareVersions(a: Version, b: Version): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch;
}

/**
 * The version a release of `current` makes: `patch`/`minor`/`major` bump it, an explicit `X.Y.Z` is
 * taken as it is. Throws on a target that is not a version; whether it is allowed (not older than
 * `current`) is the caller's to decide.
 */
export function targetVersion(current: string, wanted: string): string {
  const now = parseVersion(current);
  if (now === null) throw new Error(`текущая версия «${current}» — не номер вида 1.2.3`);
  switch (wanted) {
    case "patch":
      return formatVersion({ ...now, patch: now.patch + 1 });
    case "minor":
      return formatVersion({ major: now.major, minor: now.minor + 1, patch: 0 });
    case "major":
      return formatVersion({ major: now.major + 1, minor: 0, patch: 0 });
  }
  const explicit = parseVersion(wanted.startsWith("v") ? wanted.slice(1) : wanted);
  if (explicit === null) {
    throw new Error(`«${wanted}» — не patch, minor, major и не номер вида 1.2.3`);
  }
  return formatVersion(explicit);
}
