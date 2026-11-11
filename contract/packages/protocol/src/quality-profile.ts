/**
 * The quality controller's tuning, sent by the server with a `session_request` (`quality_profile`,
 * agent WS §2 in docs/protocol.md).
 *
 * The values are the agent's `QualityPolicy` (`agent/crates/core/src/quality_policy.rs`): one key per
 * Rust field, the same snake_case names, every key required. Durations are whole milliseconds
 * (`*_ms`), rates kbps, percentages integers; shares and ratios are floats. The rationale for each
 * value is on its Rust field; what is here is only what keeps a value from hurting the PC it is sent
 * to.
 *
 * ## What the bounds are and are not
 *
 * Every field has a sanity range: wide limits that refuse a value no tuning would choose — a zero
 * divisor, a duration of hours, a share past one, a shift that overflows, a clamp whose bounds cross.
 * They are not the tuning, and a value inside them is not a recommendation. The cross-field rules in
 * `.superRefine` are the invariants the Rust comments state; each has a stable issue path, which the
 * invalid vectors (`vectors/quality-profile-invalid.json`) pin and the agent's own validator answers
 * with the same path.
 *
 * ## Versioning
 *
 * `id` names a profile and `v` its version: a published `{id, v}` never changes its values, so a
 * session's `"<id>.v<v>"` (reported back in `session_stats.stats.summary.quality_profile`) is
 * enough to know what it ran on. A newer server may know fields an older agent does not: the values
 * object is not strict, unknown keys are stripped.
 *
 * The agent parses the profile leniently — any failure falls back to its compiled profile and never
 * drops the `session_request` — and never logs the values, only `id`, `v` and the source.
 *
 * ## Not in the index
 *
 * This module is the subpath `@afklink/protocol/quality-profile`, and nothing the index re-exports
 * imports it at runtime (`agent-ws.ts` takes its type only): the Mini App's admin page runs zod from
 * the index, and the profile's field map must not ship in public web JS. On the wire
 * `session_request.quality_profile` is opaque; the server validates every profile file with
 * `qualityProfileSchema` when it loads them.
 */
import { z } from "zod";

/* --- constants the bounds and invariants read, restated from the agent -------------------------- */

/** `QUEUE_GUARD_MS` in `agent/crates/core/src/quality.rs`: the local queue every latency line is
 * measured against. `clean_rtt_margin_ms` is the floor of `clamp(.., clean_rtt_margin_ms,
 * QUEUE_GUARD_MS)` (quality.rs, `clean_rtt_margin`), which panics if it is above this. */
export const QUALITY_QUEUE_GUARD_MS = 75;

/** `TICK` in quality.rs: the controller's 200 ms tick. */
export const QUALITY_TICK_MS = 200;

/** `DELIVERY_HISTORY_TICKS` in quality.rs (320 ticks, 64 s): the ring the delivery windows read. The
 * Rust comment on `delivery_floor_window_ms` says the ring "must cover it". */
export const QUALITY_DELIVERY_HISTORY_MS = 320 * QUALITY_TICK_MS;

/** `RTT_BASE_REPORTS` in quality.rs: the ring of fresh round trips the baseline is the least of. A
 * `rtt_base_min_reports` above it would never be reached. */
export const QUALITY_RTT_BASE_REPORTS = 30;

/** `MAX_DESIRED_KBPS` in quality.rs, the encoder's `MAX_BITRATE_KBPS`: no rate field goes past it. */
export const QUALITY_MAX_DESIRED_KBPS = 12_000;

/** `QP_MIN` / `QP_MAX` in `agent/crates/encode/src/lib.rs`: the quantiser band the encoder is held
 * to. Its compile-time assert wants `QP_MIN < qp_up` and `qp_down + 4 <= QP_MAX` (`starved` fires at
 * `QP_MAX - 1` and must be told apart from `qp_down`). */
export const QUALITY_ENCODER_QP_MIN = 16;
export const QUALITY_ENCODER_QP_MAX = 46;
/** The steps `starved` needs between `qp_down` and `QP_MAX` (encode/src/lib.rs). */
export const QUALITY_STARVED_QP_STEPS = 4;

/** str0m 0.24.1's `MIN_TIME_BETWEEN_ALR_PROBES` (5 s, `bwe/probe/control.rs:31`): the periodic probe
 * at twice desired waits this long after the last probe, and the probe opening must end before it.
 * Pinned to str0m 0.24.1: recheck this value on every str0m bump. */
export const QUALITY_STR0M_ALR_PROBE_GAP_MS = 5_000;
/** How long after `probe_opening_ms` the opening's end can reach str0m: media flows within a tick of
 * the opening probes and the end goes out on its tick — "at most 3.4 s after them" for the 3 s
 * opening (quality_policy.rs, `probe_opening_ms`). */
export const QUALITY_PROBE_OPENING_SLACK_MS = 2 * QUALITY_TICK_MS;

/** The three presets a viewer picks between (`Quality` in quality.rs, less `Custom`). */
export const QUALITY_PRESET_NAMES = ["low", "balanced", "best"] as const;

/* --- bounds ------------------------------------------------------------------------------------ */

/** The widest duration any field may have: two minutes. */
export const QUALITY_MAX_DURATION_MS = 120_000;

const int = (min: number, max: number) => z.number().int().min(min).max(max);
const num = (min: number, max: number) => z.number().min(min).max(max);
/** A duration in whole milliseconds. */
const ms = (min = 0, max = QUALITY_MAX_DURATION_MS) => int(min, max);
/** A rate in kbps, up to the encoder's ceiling. */
const kbps = () => int(0, QUALITY_MAX_DESIRED_KBPS);
/** An integer percentage of `0..max`. */
const pct = (min = 0, max = 100) => int(min, max);
/** A float share of one. */
const share = () => num(0, 1);
/** A count of reports or intervals. */
const reports = () => int(1, 30);

/** A rung's encoded height: from 144p to 4K. */
const RUNG_MIN_H = 144;
const RUNG_MAX_H = 2160;
/** A frame rate a rung may ask for. */
const RUNG_MAX_FPS = 120;

export const qualityRungSchema = z.object({
  max_h: int(RUNG_MIN_H, RUNG_MAX_H),
  fps: int(1, RUNG_MAX_FPS),
});
export type QualityRung = z.infer<typeof qualityRungSchema>;

/** The most rungs a ladder may have; the reference has eight. */
export const QUALITY_MAX_RUNGS = 16;
/** The most frame rates a pinned ladder may walk; the reference has four. */
export const QUALITY_MAX_PINNED_FPS = 8;

/**
 * Every field of the agent's `QualityPolicy`, by section as the struct has them. Not strict: an
 * unknown key is stripped, so a field a newer server adds never fails an older agent's parse here.
 */
const qualityPolicyFields = z.object({
  // ── ladder and pricing ──
  fps_factor_exp: num(0, 2),
  quality_ratio_best: num(0.05, 8),
  quality_ratio_balanced: num(0.05, 8),
  quality_ratio_low: num(0.05, 8),
  ladder: z.array(qualityRungSchema).min(1).max(QUALITY_MAX_RUNGS),
  pinned_fps: z.array(int(1, RUNG_MAX_FPS)).min(1).max(QUALITY_MAX_PINNED_FPS),
  start_rung_index: int(0, QUALITY_MAX_RUNGS - 1),
  absorb_ratio: num(1, 8),
  up_headroom: num(1, 4),
  // ── budget ──
  spend_pct: pct(10, 100),
  pushback_depth: num(0, 0.9),
  explore_margin_kbps: kbps(),
  explore_growth_pct: pct(100, 1000),
  loaded_share_pct: pct(1, 100),
  leading_share_pct: pct(1, 1000),
  loaded_confirm_ms: ms(),
  loaded_floor_kbps: kbps(),
  informative_half_life_ms: ms(100),
  app_limited_pct: pct(),
  // ── dwells ──
  settle_after_move_ms: ms(),
  down_after_ms: ms(),
  up_after_ms: ms(),
  // ── probe target ──
  probe_capacity_multiple: int(1, 10),
  probe_target_change_pct: pct(),
  probe_target_every_ms: ms(),
  probe_opening_ms: ms(),
  probe_opening_latest_ms: ms(),
  // ── re-anchor ──
  reanchor_after_pause_ms: ms(),
  reanchor_resume_window_ms: ms(),
  reanchor_divergence_pct: pct(100, 1000),
  real_loss_memory_ms: ms(),
  clean_rtt_margin_ms: int(0, QUALITY_QUEUE_GUARD_MS),
  clean_rtt_margin_pct: pct(),
  clean_rtt_for_ms: ms(),
  clean_collapse_hold_ms: ms(),
  reanchor_backoff_max: int(0, 8),
  media_egress_kbps: kbps(),
  reanchor_resume_spend: share(),
  reanchor_every_ms: ms(1_000),
  // ── path change ──
  path_judge_window_ms: ms(),
  path_reprobe_every_ms: ms(1_000),
  path_reprobe_rtt_factor: int(1, 10),
  // ── brake ──
  brake_loss: num(0.01, 1),
  brake_clear_loss: share(),
  brake_backoff: num(0.1, 1),
  rtt_inflation: int(1, 10),
  rtt_margin_ms: ms(),
  brake_rtt_reports: reports(),
  rtt_base_min_reports: int(1, QUALITY_RTT_BASE_REPORTS),
  path_step_flat_ms: ms(),
  path_step_flat_pct: pct(),
  path_step_max_ms: ms(),
  path_step_drift_div: int(1, 100),
  brake_stale_reports: reports(),
  hold_wake_window_ms: ms(),
  hold_wake_loss: share(),
  silence_media_floor_kbps: kbps(),
  silence_media_share_pct: pct(),
  brake_stale_backoff: num(0.1, 1),
  outage_divergence_pct: pct(100, 1000),
  // Above one: at 1.0 `held * rate^dt` never grows and a released brake holds all session.
  brake_release_per_sec: z.number().gt(1).max(10),
  // ── drain mode and the viewer's delivery ──
  drain_enter_rtt_ms: ms(200),
  drain_evidence: reports(),
  drain_drained_stale: reports(),
  drain_max_ms: ms(),
  drain_max_proven_ms: ms(),
  drain_resume_share_pct: pct(1, 100),
  delivery_fresh_late_ms: ms(),
  delivery_report_age_ms: ms(),
  delivery_floor_window_ms: ms(0, QUALITY_DELIVERY_HISTORY_MS),
  drain_veto_within_ms: ms(),
  drain_leave_within_ms: ms(),
  delivery_rate_window_ms: ms(QUALITY_TICK_MS, QUALITY_DELIVERY_HISTORY_MS),
  drain_leave_one_report: num(1, 10),
  // ── startup ──
  startup_decide_after_ms: ms(),
  startup_trying_ms: ms(),
  startup_thin_below_h: int(RUNG_MIN_H, RUNG_MAX_H),
  startup_queue_standing_ms: ms(),
  startup_queue_window_ms: ms(),
  // ── quantiser and processor ──
  qp_down: z
    .number()
    .gt(QUALITY_ENCODER_QP_MIN)
    .max(QUALITY_ENCODER_QP_MAX - QUALITY_STARVED_QP_STEPS),
  qp_up: z
    .number()
    .gt(QUALITY_ENCODER_QP_MIN)
    .max(QUALITY_ENCODER_QP_MAX - QUALITY_STARVED_QP_STEPS),
  qp_min_samples: int(1, 600),
  spending_share: share(),
  trying_share: share(),
  drop_share: share(),
  encode_budget_share: num(0.05, 1),
  encode_climb_share: num(0.05, 1),
  cpu_climb_dwell_max_ms: ms(),
  cpu_streak_forget_ms: ms(),
  roomy_late_factor: num(1, 10),
});

/** The field names, in the struct's order: what a complete profile has. */
export const QUALITY_POLICY_FIELDS = Object.keys(qualityPolicyFields.shape) as readonly string[];

/* --- cross-field invariants --------------------------------------------------------------------- */

type Ctx = z.RefinementCtx<z.infer<typeof qualityPolicyFields>>;

/** One rule's failure, at its own path. */
function fail(ctx: Ctx, path: (string | number)[], message: string): void {
  ctx.addIssue({ code: "custom", path, message });
}

/** Each a strict `a < b` (or `<=`) the Rust comments state, at the path of the field it names. */
const ORDER_RULES: readonly {
  path: keyof QualityPolicyValues;
  ok: (v: QualityPolicyValues) => boolean;
  message: string;
}[] = [
  {
    // quality_policy.rs, brake_clear_loss: "Between this and BRAKE_LOSS a report neither cuts nor
    // releases".
    path: "brake_clear_loss",
    ok: (v) => v.brake_clear_loss < v.brake_loss,
    message: "brake_clear_loss must be under brake_loss",
  },
  {
    // A contract rule, protecting the brake: for 4 s after a background hold a report with
    // `hold_wake_loss` of its interval lost is read as the woken page's, not the path's (quality.rs
    // ~4835-4841, quality_policy.rs `hold_wake_loss`: a merely lossy path "reads REAL_LOSS to tens
    // of percent — which brakes as always"). Under `brake_loss` it would excuse a loss the brake
    // acts on alone.
    path: "hold_wake_loss",
    ok: (v) => v.hold_wake_loss >= v.brake_loss,
    message: "hold_wake_loss must be at least brake_loss",
  },
  {
    // quality_policy.rs, probe_opening_latest_ms: the latest the opening ends.
    path: "probe_opening_latest_ms",
    ok: (v) => v.probe_opening_ms <= v.probe_opening_latest_ms,
    message: "probe_opening_latest_ms must be at least probe_opening_ms",
  },
  {
    // quality_policy.rs, probe_opening_ms "Why three seconds": "It has to end before those five
    // seconds" — str0m's first periodic probe; its end reaches str0m up to two ticks later. Pins
    // str0m 0.24.1's 5 s periodic probe (`QUALITY_STR0M_ALR_PROBE_GAP_MS`): recheck on a str0m bump.
    path: "probe_opening_ms",
    ok: (v) => v.probe_opening_ms + QUALITY_PROBE_OPENING_SLACK_MS < QUALITY_STR0M_ALR_PROBE_GAP_MS,
    message: "probe_opening_ms must end before str0m's periodic probe",
  },
  {
    // quality_policy.rs, qp_up: "Ten below QP_DOWN ... leaves a band where the ladder holds still".
    path: "qp_up",
    ok: (v) => v.qp_up < v.qp_down,
    message: "qp_up must be under qp_down",
  },
  {
    // quality_policy.rs, drain_max_proven_ms: "The longest drain mode lasts whatever the receiver
    // says"; drain_max_ms is the bound without proof.
    path: "drain_max_proven_ms",
    ok: (v) => v.drain_max_ms <= v.drain_max_proven_ms,
    message: "drain_max_proven_ms must be at least drain_max_ms",
  },
  {
    // quality_policy.rs, leading_share_pct: the band `[LOADED_SHARE_PCT, LEADING_SHARE_PCT]`.
    path: "leading_share_pct",
    ok: (v) => v.loaded_share_pct < v.leading_share_pct,
    message: "leading_share_pct must be above loaded_share_pct",
  },
  {
    // quality_policy.rs, trying_share: "half of SPENDING_SHARE" — trying is the weaker test.
    path: "trying_share",
    ok: (v) => v.trying_share <= v.spending_share,
    message: "trying_share must be at most spending_share",
  },
  {
    // quality_policy.rs, encode_climb_share: "ten points under ENCODE_BUDGET_SHARE, so a climb
    // lands inside the line that would take it back down rather than on it".
    path: "encode_climb_share",
    ok: (v) => v.encode_climb_share < v.encode_budget_share,
    message: "encode_climb_share must be under encode_budget_share",
  },
  {
    // quality_policy.rs, cpu_climb_dwell_max_ms: the dwell doubles from UP_AFTER up to this.
    path: "cpu_climb_dwell_max_ms",
    ok: (v) => v.up_after_ms <= v.cpu_climb_dwell_max_ms,
    message: "cpu_climb_dwell_max_ms must be at least up_after_ms",
  },
  {
    // quality_policy.rs, startup_trying_ms: "How much of the startup window the encoder must have
    // spent trying".
    path: "startup_trying_ms",
    ok: (v) => v.startup_trying_ms <= v.startup_decide_after_ms,
    message: "startup_trying_ms must fit in startup_decide_after_ms",
  },
  {
    // quality_policy.rs, clean_rtt_margin_ms: "forty is under a third of the brake's own
    // RTT_MARGIN_MS, so everything the brake would call a queue this calls unclean long before".
    path: "clean_rtt_margin_ms",
    ok: (v) => v.clean_rtt_margin_ms <= v.rtt_margin_ms,
    message: "clean_rtt_margin_ms must be at most rtt_margin_ms",
  },
];

/** The ladder best first (quality.rs, `LADDER`: "The ladder, best first"): heights never rise, and
 * at one height the frame rate falls — so no rung repeats. A lower height may have a higher frame
 * rate (1080p30 then 720p60). */
function checkLadderOrder(v: QualityPolicyValues, ctx: Ctx): void {
  for (let i = 1; i < v.ladder.length; i++) {
    const prev = v.ladder[i - 1] as QualityRung;
    const cur = v.ladder[i] as QualityRung;
    const ok = cur.max_h < prev.max_h || (cur.max_h === prev.max_h && cur.fps < prev.fps);
    if (!ok) {
      fail(ctx, ["ladder", i], "the ladder goes best first: heights fall, fps falls within one");
    }
  }
}

/** The pinned ladder walks falling frame rates (quality_policy.rs, `pinned_fps`). */
function checkPinnedOrder(v: QualityPolicyValues, ctx: Ctx): void {
  for (let i = 1; i < v.pinned_fps.length; i++) {
    if ((v.pinned_fps[i] as number) >= (v.pinned_fps[i - 1] as number)) {
      fail(ctx, ["pinned_fps", i], "pinned frame rates fall, best first");
    }
  }
}

const RATIO_MESSAGES = {
  low: "absorb_ratio must be at least quality_ratio_low",
  balanced: "absorb_ratio must be at least quality_ratio_balanced",
  best: "absorb_ratio must be at least quality_ratio_best",
} as const;

/**
 * quality.rs `every_rung_can_absorb_at_least_what_it_is_worth`: absorbable >= required on every rung,
 * or the budget's `spend.clamp(floor, ceiling)` crosses. Both prices are the same base times the same
 * fps factor, once by `absorb_ratio` (f64) and once by the preset's ratio (f32 widened to f64), so
 * the rule reduces to `absorb_ratio >= f64::from(quality_ratio_*)` for each preset — reported at that
 * preset's ratio. Whether the probe ceiling reaches every rung depends on the source, which the
 * server does not know: that stays with the agent, which does not refuse a profile for it.
 */
function checkRatios(v: QualityPolicyValues, ctx: Ctx): void {
  for (const q of QUALITY_PRESET_NAMES) {
    if (v.absorb_ratio < Math.fround(v[`quality_ratio_${q}`])) {
      fail(ctx, [`quality_ratio_${q}`], RATIO_MESSAGES[q]);
    }
  }
}

export const qualityPolicyValuesSchema = qualityPolicyFields.superRefine((v, ctx) => {
  for (const rule of ORDER_RULES) {
    if (!rule.ok(v)) fail(ctx, [rule.path], rule.message);
  }
  // quality_policy.rs, start_rung_index: an index into the ladder (`start_rung` indexes it). An
  // empty ladder is its own issue, at `ladder`.
  if (v.ladder.length > 0 && v.start_rung_index >= v.ladder.length) {
    fail(ctx, ["start_rung_index"], "start_rung_index must be a rung of the ladder");
  }
  checkLadderOrder(v, ctx);
  checkPinnedOrder(v, ctx);
  checkRatios(v, ctx);
});
export type QualityPolicyValues = z.infer<typeof qualityPolicyFields>;

/* --- the profile and its label ------------------------------------------------------------------ */

/** A profile's id: a lowercase slug. */
export const QUALITY_PROFILE_ID_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;
/** The largest version a profile may have. */
export const QUALITY_PROFILE_MAX_V = 1_000_000;

export const qualityProfileSchema = z.object({
  id: z.string().regex(QUALITY_PROFILE_ID_PATTERN, "a profile id is a lowercase slug"),
  v: z.number().int().min(1).max(QUALITY_PROFILE_MAX_V),
  values: qualityPolicyValuesSchema,
});
export type QualityProfile = z.infer<typeof qualityProfileSchema>;

/** `"<id>.v<v>"`: how a session names the profile it ran on. */
export const QUALITY_PROFILE_LABEL_PATTERN = /^[a-z][a-z0-9-]{0,31}\.v([1-9][0-9]{0,6})$/;

export const qualityProfileLabelSchema = z
  .string()
  .max(48)
  .regex(QUALITY_PROFILE_LABEL_PATTERN, 'a profile label is "<id>.v<v>"')
  .refine((s) => Number(QUALITY_PROFILE_LABEL_PATTERN.exec(s)?.[1]) <= QUALITY_PROFILE_MAX_V, {
    message: "a profile version is at most 1000000",
  });

/** The label of a profile. */
export function qualityProfileLabel(p: Pick<QualityProfile, "id" | "v">): string {
  return `${p.id}.v${p.v}`;
}
