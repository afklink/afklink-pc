# Vendored crates

Everything under `vendor/` is R3 (`docs/security/boundaries.md` in the umbrella repo): it is built
into the agent, and `vendor/str0m` is the WebRTC stack itself (DTLS, SRTP, ICE, congestion control).

## str0m 0.24.1 (`vendor/str0m`)

- **Upstream:** crates.io `str0m` 0.24.1 (git `8c4c5284cb11b1e3c82962639cda5b3e95af73e8`, per its
  `.cargo_vcs_info.json`). The `.crate` archive's SHA-256, as Cargo.lock had it before the patch:
  `3e80c4a4ef148e4a9fd15b9525c7f376d97e86729f19880b591ad220f1288c0f`.
- **Wiring:** `[patch.crates-io] str0m = { path = "vendor/str0m" }` in the workspace `Cargo.toml`, and
  `exclude = ["vendor/str0m"]` in `[workspace]`. It keeps its own manifest, and the workspace's
  clippy, fmt and tests leave it alone; biome skips `vendor/` too (`biome.json`). Only `0.24.x`
  requirements resolve to it. The simulator's viewer (`str0m_023`, `=0.23.1`) stays the registry's
  crate. In Cargo.lock the 0.24.1 entry has no `source`/`checksum` lines, because it is a path
  package now.
- **Bytes:** the copy is the `.crate` archive unpacked, as published. `vendor/.gitattributes` turns
  off end-of-line conversion for it. str0m's own `.gitignore` (and the agent's `*.pem`) hide 15 of its
  files from `git add` (pcaps, SVGs, `.vscode`, the example certificate and key). The build needs
  none of them; add the copy with `git add -f vendor/str0m` so it stays whole, as the manifest
  expects.
- **The two PEMs:** `vendor/str0m/cert.pem` and `vendor/str0m/examples/{cer,key}.pem` are str0m's
  public example material for its `chat` example, published with the crate. Nothing of ours reads
  them, and they must never be used for anything else. A secret scanner will flag `key.pem`:
  allowlist that exact path.

### Why we patch

iPhone/WebKit viewers on Wi-Fi stall every 3-8 s: no loss, the one-way delay jumps by ~80-150 ms and
collapses back when the held packets arrive in a burst (25 Oct: relay base RTT 30 → 90-138 ms; LAN
5 → 84-139 ms; the sim's `lan-wifi-spikes` and `iphone-wifi-1025`). Upstream's trendline calls each
stall overuse 10 ms after the trend crosses its threshold. AIMD then cuts to 0.85x of the acked rate
and climbs back at ~40 kbps/s. Probing never rises again (ALR only, refused while overusing). The
encoder ends up starved at 2-4 Mbps and QP 46, where the same viewer got 17.6 Mbps on a day without
stalls.

### What the patch changes

Changes are in `src/bwe/delay/trendline.rs`; `src/bwe/delay/control.rs` gains a test module only.
Every change is marked `AFKLink patch`.

While the delay is still rising, a stall looks like a link that suddenly carries far less than we
send. What tells them apart is what comes next: a stall collapses by itself within ~100-200 ms, and a
queue keeps growing until we slow down. So the patch only acts where upstream would declare overuse
(its threshold, time and count rules are untouched), and there it may wait.

#### The bounds

Four review rounds kept finding a new input that the shape rules below misread. Two bounds now cap
what ignoring can hide, whatever the shape rules decide:

- **G1, cooldown** (`STALL_COOLDOWN_MS`, 2 s of arrival time): at most one stall is ignored per 2 s.
  Within it, a stall-shaped rise is neither held nor ignored: it is overuse at once, latched as a
  held rise's overuse is. Other signals are upstream's overuse anyway. Stalls come every 3-8 s (25
  Oct; the simulator's at least 3 s apart); stall-shaped rises closer together are a queue our own
  bursts build. The cooldown runs from the ignore (the collapse), not from the stall's start, so
  from start to start it is ~2.3 s: in the review, two +80..+140 ms stalls 2.0 s apart had the
  second cut in 231 of 384 cases, 2.15 s apart in 10, 2.3 s or more apart in none.
- **G2, floor** (`FLOOR_HORIZON_MS`, 5 s): a rise counts as collapsed only once the delay is back
  within its collapse level of the path's floor, the lowest raw delay of the last 5 s (kept as
  minima of 250 ms buckets), not of the 20-group window, which climbs along with a queue.
- **The episode:** upstream stays in overuse for as long as the trend stays above the threshold. When
  the patch swallows a signal (a stall ignored, or its lingering trend), it re-checks every variation
  of that episode: once the delay is a rise (`STALL_MIN_RISE_MS`, 10 ms) above the ignored stall's
  collapse level of the floor, the variation is judged as an overuse signal. Without this, a queue
  that started right behind an ignored stall drew no new signal while the trend stayed up without
  rising (a 3x queue reached 267 ms of queue, 400 ms in). The 10 ms are for jitter: checked on every
  variation, the collapse level alone (20 ms for stalls under 80 ms) was crossed by single samples
  of 20 ms jitter, and the cooldown then cut on them (2 of 1120 such stalls). A queue behind the
  stall builds at most those 10 ms more before it is judged.

What that guarantees, pinned by tests:

- **Burst trains are called.** The review's escape of round 4: a big frame of 3-8 frame intervals
  every 6 or 12 groups into a link we overrun by 2-5% (or by an overrun growing 1-3% a second), each
  burst's queue jumping and draining back to the window's low like a short stall while the floor
  crept up 20-50 ms/s. Round 4 ignored every one (147 in 15 s, 776 ms of queue). Now at most one is
  ignored before the first overuse, and the train is called at most one burst cycle and one hold
  after upstream. The tests pin 1.02-1.05x and the growing overrun: at most 388 ms later (33 ms
  groups, a big frame every 12, 1.05x: upstream at 292 ms and 193 ms of queue, patched at 680 ms
  and 251), 374 ms with the growing overrun. The review's sweep over 1.02-1.2x (136 trains): never
  uncalled, at most 404 ms later (1.1x). At the controller (1.02-1.1x), the estimate is cut in all
  45 configurations, at most 400 ms after upstream's cut; round 4 never cut 16 of them.
- **Stall-shaped bursts without a growing queue** (big frames into a link with room on average, each
  queue draining fully): one ignored per 2 s at most, the rest overuse.
- **Slow bursts cannot hide a creeping floor.** Whatever their spacing, ignored stalls cannot let the
  delay floor rise by more than one collapse level per 5 s: 20 ms for stalls peaking under 80 ms, at
  most 50 ms (the 200 ms maximum), i.e. 4-10 ms/s. A queue growing faster gets no ignore once it is
  that far above its 5 s floor. Test: a stall-like burst every 2.5 s (beyond the cooldown) on a floor
  creeping ~15 ms/s, too gently for the trend: overuse at the second burst. Smooth growth slower
  than that is below what upstream's own trendline sees on a smooth queue (its modified trend,
  4 x 60 x slope, against a threshold of at least 6: about 25 ms/s).

The costs of the bounds: two stalls less than ~2.3 s apart (start to start), the second is
overuse; after the path itself gets longer (a new route, a remote clock stepping forward), stalls
within 5 s of it can be overuse (the review: a stall 1-3 s after the path got 20 or 40 ms longer
was cut).

#### The rules

- **`TrendlineEstimator::detect`:** where upstream declares overuse, it calls `on_overuse_signal`;
  while the trend stays above the threshold after a swallowed signal, `recheck_swallowed_overuse`.
  After each delay variation it calls `settle_stall`.
- **`on_overuse_signal`**, built on `rise_shape` and the `RiseShape` it returns:
  - *A stall already ignored* (`ignored_stall_lingers`): the window's peak is from before the last
    ignore, or the trend has stayed above the threshold since, and the delay is within that stall's
    collapse level of the path's floor. The signal is that stall's lagging trend and is ignored. With
    one group per frame (16.7-33 ms) the trend crosses the threshold again after the collapse.
  - *Not stall-shaped:* overuse, as upstream declares it. Stall-shaped is either of:
    - *a stall that already collapsed:* the window holds a stall-sized peak (40-200 ms) that is
      either jump-shaped (one step carries half of it) or steep (as below, taken up to the peak),
      and the delay is back within its collapse level of the floor. This happens with sparse
      streams, where the trend crosses the threshold only after the burst;
    - *a stall-shaped rise:* at least `STALL_MIN_RISE_MS` (10) above the window's lowest raw delay,
      under `STALL_MAX_RISE_MS` (200), and either
      - steep (`STALL_MIN_STEEPNESS` 0.5): twice the slope, in ms of delay per ms of arrival, from
        the last sample where the delay sat within max(2 ms, half the rise) of its low to now, or to
        the rise's own peak, whichever is steeper. A 1.33x queue reads 0.5. The slope uses the low
        sample's actual delay, since with a group per 30 fps frame that sample sits well below half
        way. It is measured to the peak because the trend often signals on a stall's falling edge,
        where the current rise is smaller; but only while the delay falls from the peak at
        `STALL_MIN_FALL_STEEPNESS` (2.5 ms per ms) or faster (see "What it costs");
      - or jump-shaped (`STALL_MIN_JUMP_SHARE` 0.5: one step carries half the rise), a stall's first
        step behind a pause between frames.
  - *Within the cooldown (G1):* a stall-shaped signal is overuse, latched.
  - *A stall that already collapsed:* ignored.
  - *A stall-shaped rise:* held back as a `StallCandidate`. Its peak starts as the rise's own peak
    (the highest delay since the low), not the current rise: opened on a falling edge, a 60-110 ms
    stall once got a 13-40 ms peak and was then cut as "a small queue" when it drained.
- **`settle_stall`**, on every variation while a rise is held back:
  - It passes 200 ms: overuse.
  - It has not collapsed when `STALL_MAX_HOLD_MS` (250 ms of remote arrival time) runs out:
    overuse. The cause says whether it came back to where it rose from but not to the floor (a
    growing queue). This check comes before the collapse, so a collapse first seen after the hold
    ran out (the stream had a gap) is overuse too: when it collapsed is unknown, so it gets
    upstream's call. Before this ordering, `wifi-0924-4m` had queues of 120-175 ms "ignored" after
    390-460 ms.
  - It is back within the collapse level of the path's floor (G2): max(`STALL_RETURN_FRACTION`
    0.25 x peak, min(`STALL_RETURN_MS` 20, 0.5 x peak)), so it always has to halve. If it peaked at
    `STALL_MIN_PEAK_MS` (40) or more, or came in one step (`STALL_ONE_STEP_SHARE`: one step carries
    0.9 of its peak), it was a stall: ignored. Otherwise it was a small queue that drained, such as
    a keyframe overrunning a narrow link (20-30 ms peaks in `wifi-0924-4m`, where ignoring them
    doubled the queue drops): overuse, as upstream. The one-step exception: our pacer spreads a big
    frame over many groups, so a queue we build grows group by group, and str0m's arrival grouping
    can shrink a ramp stall to a one-step bump of 22-30 ms (the group at its top is merged with the
    burst queued behind it, and a group's delay is its last packet's). In `iphone-wifi-1025` three
    such ramps (+80..+110 ms) a run were cut before it. Pinned by
    `afklink_a_small_stall_in_one_step_is_ignored_and_a_small_ramp_is_not` (5 ms groups: +22 ms
    for 80 ms in one step is ignored, the same +22 ms in four steps is overuse).
- **Latch** (`overuse_latched`): an overuse that comes out of a hold (or the cooldown) is not ended
  by the trend before `OVERUSE_LATCH_MIN_MS` (200 ms of arrival time). After that it ends once the
  delay has drained to the collapse level, and after `OVERUSE_LATCH_MAX_MS` (300 ms) the trend
  decides, as upstream. Why:
  - By the time a hold runs out, the queue has often stopped growing (a shallow buffer is full, or
    the path got longer), so the trend is already inside the threshold. Without the latch, the next
    variation ends the overuse within one group.
  - The delay controller reads the hypothesis once per TWCC report (50-100 ms), and the rate
    controller cuts only once a round trip has passed since the estimate last changed, which every
    increase does: an overuse seen by one report is never acted on when the round trip exceeds the
    report interval. 200 ms spans two reports at 100 ms; with 100 ms, one of the 45 burst trains
    was never cut at the controller and another only after 3.2 s, and `wifi-0924-4m` dropped 32.5
    packets a run against 23.4 (12 seeds).
  - The cap matters for a path that got longer for good: it never drains, and an endless overuse
    would cut the rate to its floor.

  Measured overuse length, upstream → patched (unit tests):

  | Case | Upstream | Patched |
  |---|---|---|
  | 1.5x, 40 ms buffer | 255 ms | 300 ms |
  | 2x, 40 ms buffer | 270 ms | 300 ms |
  | 2x, 80 ms buffer | 390 ms | 300 ms |
  | 3x, 40 ms buffer | 315 ms | 300 ms |
  | 3x, 60 ms buffer | 405 ms | 300 ms |
  | 3x, 80 ms buffer | 465 ms | 300 ms |
  | Path +100 ms for good | 220 ms | 300 ms |

  Driven through `DelayController::update` with 100 ms reports, the estimate falls as upstream's
  does:

  | Case | Upstream (kbps) | Patched (kbps) |
  |---|---|---|
  | 2x, 40 ms buffer | 5742 → 2040 | 5742 → 2040 |
  | 2x, 80 ms buffer | 5742 → 2040 | 5742 → 2040 |
  | 3x, 60 ms buffer | 5742 → 1387 | 5742 → 1305 |
  | Path +100 ms for good | 5742 → 4080 | 5742 → 4080 |

  Over 30 s of stalls every 3-5 s (step and ramp taking turns) with one group per frame, the
  patched estimate is never cut. Upstream cuts 6202 → 2611 kbps at 16.7 ms frames and 6202 → 3916
  at 33 ms frames. The trendline tests run each stall shape at 5, 16.7, 20.8 and 33 ms groups, with
  0-20 ms of jitter (peak to peak) and four offsets within a group: no overuse onset that the same
  path without the stall lacks.

  The review's sweep: 2048 stalls of +40..+140 ms for 80-200 ms of sending, both shapes, four
  spacings, four offsets, 0 and 10 ms of jitter. Every stall the patch is for passes: peaking at
  50 ms or more, a step or a ramp rising at least 0.5 ms per ms of sending, and over within the
  hold (`len + extra` ≤ 230 ms). 136 cases outside that class are cut, by design: gentler ramps rise
  like a queue at up to ~1.5x overrun and are called as upstream calls one, +40 ms ramps peak at the
  40 ms floor, and longer stalls outlast the hold.
- **Clock:** `last_arrival_ms` is the latest arrival seen (the max), so a reordered variation
  cannot move a hold's or a latch's clock back. A receive time more than `CLOCK_STEP_BACK_MS`
  (1 s) before it is the far end's clock stepping back. The hold, the latch, the cooldown, the floor
  and the log's clocks move back with it, so a latched overuse still ends. Without that it would
  have lasted as long as the step, 10 s in the test.
- **`update_hypothesis`** takes the trend, the modified trend and a cause, and logs (see below).
- **State:** `Timing` gains `raw_delay_ms`. The estimator gains:
  - the candidate and the latch;
  - the floor's buckets;
  - the last ignore's time and peak, and whether an overuse is being swallowed;
  - counters for the log;
  - a test-only `upstream_only` switch.

Round 4's re-climb guard and its jitter measure are gone: the floor's collapse level and the
episode's re-check do their job (a queue climbing behind a stall leaves the floor), and an
alternating delay could inflate the jitter measure to 113 ms of guard.

**What it costs.** A queue growing about as steeply as a stall (we send at least ~1.33x what the
link carries: the link suddenly lost a quarter or more) is called overuse up to 250 ms of arrival
time later than upstream, sooner if it passes 200 ms. While such a rise is held, the hypothesis
stays where it was (normal), so for those up to 250 ms:
- AIMD may keep increasing;
- `is_overusing()` is false, so probes are not refused.

Both are the price of not cutting on a stall. More costs:
- **A real collapse builds more queue while the decision waits.** With an unlimited buffer the
  queue peaked at 299 ms against upstream's 180 ms at a 2x overrun, and at ~680 ms against
  451-510 ms at 3x (the reviewer's closed-loop model, round 3). Users feel this as latency during a
  real collapse of their link.
- **A burst that looks like a stall goes uncut**, at most once per 2 s and only if it comes back
  near the 5 s floor: a burst that overruns a narrow link, with a queue that peaks at a stall's size
  (40-200 ms) and drains within the hold. Smaller ones are cut as upstream. The same holds for a
  short dip of the link: 300 ms at 1/1.5 of our rate builds ~100 ms of queue that drains within the
  hold, and is not cut.
- **A stall that drains slowly gets a longer overuse.** If the link carries only ~1.1x our rate,
  the stall doesn't collapse within the hold; it gets 300 ms of overuse (the latch) against
  upstream's 194-220 ms. At 1.25x, closed loop, it still cuts no more often than upstream.
- **The fall gate cuts some stalls on a link without much room.** A stall's backlog drains at the
  link's headroom over our rate, C/R - 1, like a queue at a narrow link (`wifi-0924-4m`'s keyframe
  queues mostly at 0.2-2.3 ms per ms). Without `STALL_MIN_FALL_STEEPNESS`, those queues are held on
  their falling edge and, drained within the hold, ignored: 31.8 queue drops a run against 23.4 (12
  seeds); they neither repeat within 2 s nor leave the floor, so the bounds don't catch them. With
  it, a stall the trend first sees on its falling edge, on a link with less than 3.5x our rate, is
  cut: of the sweep's targeted stalls redone with their backlog draining at 1-2.4 ms per ms, 21-27
  of 736 (19-22 of those that drain within the hold), nearly all small short ramps (+50-60 ms over
  80-120 ms at 16.7-20.8 ms groups); none at 3 ms per ms and faster. The 25 Oct link had ~3.5x room
  (25 Mbps for ~7 Mbps sent). Pinned by `afklink_a_stall_on_a_link_without_room_is_overuse_on_its_
  falling_edge` (16.7 ms groups, +60 ms over 80 ms: ignored draining at 5 ms per ms, called at
  1 ms per ms).
- **A queue right behind an ignored stall is called later.** While the trend stays up after the
  ignore, the queue is judged once it is a collapse level and a rise (30-45 ms) above the floor;
  after that,
  the stall's fall in the 20-group window holds the trend down (upstream's own trend is as blind
  there, though upstream is often still in its stall overuse). It is always called. Measured
  against the same path without the stall, both shapes, starting 0-500 ms after it, 1.05-3x, 0-20
  ms of jitter, three seeds: at most 184, 421, 371 and 450 ms later at 5, 16.7, 20.8 and 33 ms
  groups, all at 20 ms of jitter (the test's one seed: 163, 386, 371, 450); the worst are 1.05x
  queues, where that is 10-25 ms more queue; `afklink_a_queue_behind_an_ignored_stall_is_
  overuse` pins 215/485/430/520 ms. A 2-3x queue starting within 60 ms of the stall is called
  within the hold plus 3 groups. With 25-40 ms of jitter, outside what the patch claims, the review
  measured up to ~620 ms.
- **A gentle queue on a jittery path can be held.** On a quiet path a queue gentler than ~1.33x is
  too gradual for a stall and is called as upstream calls it; with jitter as large as its rise, its
  low point can be a jitter dip and the rise reads steep. Then it is held: called at most the hold
  later (254 ms at 5 ms groups with 10-20 ms of jitter, 1.3x; pinned by a test).
- **A stall followed by a pause in sending is a cut.** The hold's deadline is checked first, so if
  we send nothing for ~250 ms or more right after a stall (a static screen, an idle encoder), the
  collapse is first seen after the hold ran out and gets upstream's call: overuse.

Queues away from a stall are called as upstream calls them: from the moment the link narrows if
gentler than ~1.33x (on a quiet path), within the hold if steeper. Loss-based control, the rate
controller's rules and the pacer are unchanged. First overuse, in the unit tests:

| Overrun | Upstream | Patched |
|---|---|---|
| 1.5x | 60 ms | 315 ms |
| 2x | 70 ms | 320 ms |
| 3x | 75 ms | 300 ms |
| 5x | 100 ms | 250 ms |
| 10x | 200 ms | 250 ms |

**Simulator A/B** (27 Oct). Unpatched str0m (base), round 4 of the patch and this one, with the same
simulator code and seeds.

| Scenario (seeds) | Build | QP ≥ 44, s | Estimate, kbps | p95 latency, ms | Queue drops / run |
|---|---|---|---|---|---|
| `iphone-wifi-1025` (10) | unpatched | 4.0 | 5811 | 152 | 0 |
| | round 4 | 0.3 | 7571 | 173 | 0 |
| | this | 0.3 | 7800 | 173 | 0 |
| `lan-wifi-spikes` (10) | unpatched | 18.6 | 2771 | 200 | 0.7 |
| | round 4 | 25.3 (at 1080p instead of 720p) | 6748 | 170 | 13.7 |
| | this | 25.4 | 6737 | 171 | 13.7 |
| `wifi-0924-4m` (12) | unpatched | 36.5 | 2395 | 327 | 20.5 |
| | this | 37.3 | 2558 | 288 | 23.4 |
| | this, seeds 1-6 (round 4: 24.8) | 36.7 | 2552 | 284 | 18.2 |
| `3g-0919` (12) | unpatched | 21.7 | 358 | mean 4540, median 2990 | 131.7 |
| | round 4 | 15.2 | 408 | mean 5825, median 3129 | 133.2 |
| | this | 18.7 | 397 | mean 5514, median 3367 | 126.5 |

What the table says:
- **`iphone-wifi-1025`:** as round 4, at a higher estimate; no estimate collapse in 10 runs.
- **`wifi-0924-4m`:** the 4 Mbps bottleneck drops ~3 more packets a run at its queue than
  unpatched (of ~31,000), fewer than round 4 on the same seeds; latency p95 is lower. Per seed the
  drops are lumpy (0 or 20-130), so compare over seeds.
- **`3g-0919`:** inside its seed spread. Per seed p95 runs from under 1 s to 17 s in either build;
  against unpatched it is lower on 6 seeds and higher on 6.
- The simulator could not show a burst train in closed loop: in trial scenarios (a big frame every
  250 ms on 1-5 Mbps links) the agent's own ladder kept the encoder at 0.4-1.2 Mbps, under the link,
  and round 4 dropped nothing either. The unit tests above carry that case.

**Logs.** Target `afklink_str0m::trendline`. The agent's `debug` level passes it (the `afklink`
prefix, pinned by `afklink_core::logging` tests); `info` hides it.

- `debug` lines:
  - every transition into or out of overuse: `delay detector state change`, with from/to/cause,
    trend, modified trend, threshold, rise, steepness, time and groups in the old state;
  - every stall decision: `delay rise held back as a possible Wi-Fi stall` (with the floor's lift),
    `delay spike ignored as a Wi-Fi stall: …` (with how far above the floor), `held-back delay rise
    is a queue, not a stall: <cause>` (with the floor and the collapse level), `stall-shaped delay
    rise within the cooldown of an ignored stall: overuse` (with the time since the ignore), `delay
    climbed off the path's floor while the trend stayed above the threshold since an ignored stall`;
  - the latch's release: `latched overuse released`;
  - normal ↔ underuse flips, which can come with every variation on a jittery path (and the peer
    chooses arrival times), and remote clock step-backs (a clock flipping between two offsets steps
    back with every other variation): each summed into one line at most once per 1000 ms of arrival
    time *and* per 100 variations; the first step-back always.
- `trace` lines: each such flip and step, the latch held against the trend, the lingering trend of
  an ignored stall, and the window (arrival ms, raw delay ms) every overuse signal is judged on.

Tests bound the debug lines: under a peer-driven flapping trend, at most one per 100 variations plus
20; under a remote clock flipping between two offsets, 21 for 2000 groups (one per step before).

### Proving the copy is upstream plus the patch

- **Automatic:** `vendor/str0m.sha256` lists the SHA-256 (raw bytes) of every file of the package,
  taken from the crates.io archive. The patched files (`src/bwe/delay/trendline.rs`,
  `src/bwe/delay/control.rs`) are pinned to their vendored bytes. The workspace test
  `crates/transport/tests/vendored_str0m.rs` (run by `cargo test --workspace --tests`) fails on any
  file missing, added or changed.
- **After an intended change** to a patched file, regenerate the manifest and commit it with the
  change:

  ```powershell
  pwsh -NoProfile -File vendor/str0m-manifest.ps1   # from agent/; checks the archive's checksum first
  ```

  The script reads the archive from `$env:CARGO_HOME\registry\cache` (or `-Crate <path>`). On this
  PC `CARGO_HOME` is `C:\Users\user\scoop\persist\rustup-msvc\.cargo`.
- **By hand:**

  ```powershell
  $tmp = Join-Path $env:TEMP "str0m-pristine"; New-Item -ItemType Directory -Force $tmp | Out-Null
  tar -xzf <the .crate> -C $tmp
  git diff --no-index --stat "$tmp\str0m-0.24.1" vendor/str0m   # from agent/: only the patched files
  ```

### Tests of the vendored crate (in the gate)

The workspace tests do not cover it, because the crate is excluded. `ci.yml` runs it next to the
workspace tests, and so does the umbrella's `checks` skill (through the heavy-job queue). The
command, from `agent/`:

```powershell
cargo test --manifest-path vendor/str0m/Cargo.toml --target-dir target/vendor-str0m --locked --no-default-features --features rust-crypto,_internal_test_exports --lib --test dtls-security --test srtp-replay-attack --test malformed-packet-injection --test twcc --test network-conditions
```

- `--target-dir` is required: the crate is its own workspace root, so without it (and without
  `CARGO_TARGET_DIR`) the build lands in `vendor/str0m/target`, gigabytes inside the copy. The
  identity test skips that one directory; any other extra file fails it.
- `--locked` uses str0m's own Cargo.lock; the first run downloads its dev-dependencies.
- It runs all lib tests, the patch's among them (`-- delay:: --nocapture` prints the numbers
  above).
- It also runs the integration tests on str0m's trust boundary and its congestion control.

**Formatting:** `rustfmt --edition 2024 src/bwe/delay/{trendline,control}.rs` from `vendor/str0m`.
Upstream's files are clean under it, so the diff stays the patch alone.

### Re-vendoring on a str0m bump

1. Bump the version in the workspace `Cargo.toml`. Remove the `[patch]` line first, so that `cargo
   update -p str0m` fetches and locks the new registry crate and its checksum (note the checksum).
2. Unpack the new `.crate` from the cargo cache into `vendor/str0m` (delete the old copy first).
3. Re-apply the `AFKLink patch` hunks to `src/bwe/delay/trendline.rs` and `control.rs`; check that
   upstream has not changed the detector in the meantime.
4. Restore the `[patch]` line and run `cargo metadata` (Cargo.lock loses the str0m `source`).
5. Set the version, checksum and patched files in `vendor/str0m-manifest.ps1` and run it.
6. Run the vendored tests above, the workspace tests (the manifest test among them) and the
   simulator A/B (`lan-wifi-spikes`, `iphone-wifi-1025` and the congestion guards, over seeds).
   Update this file: version, checksum, commit.
7. If upstream has fixed the stall case itself, drop the patch and the vendored copy instead.
