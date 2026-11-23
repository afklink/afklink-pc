/**
 * The game helper's revision at release (`HELPER_REVISION` in `crates/game-helper/src/lib.rs`):
 * the app asks people to update the installed helper only when that number changes, so a release
 * that changed the helper's code but not the number would leave every PC on the old helper,
 * silently. `release.ts` stops then, unless told the helper's behaviour did not change
 * (`--helper-unchanged`: only comments, tests or formatting moved).
 */

/** What the helper's sources are compared on: since the previous release's tag. */
export const HELPER_PATHS = ["crates/game-helper/src", "crates/game-helper/Cargo.toml"] as const;

/** `HELPER_REVISION` as `lib.rs` declares it; `null` when there is none (a build before it). */
export function helperRevisionOf(libRs: string): number | null {
  const m = /^pub const HELPER_REVISION: u32 = (\d+);$/m.exec(libRs);
  return m ? Number(m[1]) : null;
}

export interface HelperBump {
  /** The helper's sources differ from the previous release's. */
  helperChanged: boolean;
  /** `HELPER_REVISION` differs from the previous release's (or that one had none). */
  revisionChanged: boolean;
  /** `--helper-unchanged`: the release says the helper's behaviour is the same. */
  unchangedFlag: boolean;
}

/** Whether the release may go on, and the line that says why. */
export function helperBumpVerdict(b: HelperBump): { ok: boolean; line: string } {
  if (!b.helperChanged) {
    return { ok: true, line: "помощник игры не менялся с прошлого выпуска" };
  }
  if (b.revisionChanged) {
    return {
      ok: true,
      line: "помощник игры изменился, HELPER_REVISION поднят: у людей попросит обновить",
    };
  }
  if (b.unchangedFlag) {
    return {
      ok: true,
      line:
        "помощник игры изменился без HELPER_REVISION — по --helper-unchanged его поведение то же, " +
        "обновлять не попросит",
    };
  }
  return {
    ok: false,
    line:
      "помощник игры (crates/game-helper) изменился с прошлого выпуска, а HELPER_REVISION нет: " +
      "у людей останется прежний. Поднимите HELPER_REVISION в crates/game-helper/src/lib.rs или, " +
      "если поведение помощника не менялось (комментарии, тесты), запустите с --helper-unchanged",
  };
}
