# Input backends

`create_input_backend()` returns a **per-session selector** (the CLI takes just its injector via
`create_input_injector()`). It opens no device and sends nothing until a session begins: on the first
live session it probes for a compatible FakerInput API v1 device (a read-only probe that reads
descriptors and the API feature and emits no keyboard or mouse report) and, if present, opens it; on
the last session's end it closes it. Between sessions no device handle is held open. Concurrent
sessions share one open device (opened on the first, closed on the last). Each session logs, at
`info`, which backend it uses and why.

## Installing the driver

The desktop app carries the official, signed FakerInput 0.1.1 x64 MSI inside `afklink-app.exe`
(`app/src-tauri/resources/fakerinput/`, upstream's MIT `LICENSE` beside it; nothing is downloaded).
`build.rs` refuses to build unless the file matches its pinned SHA-256; the name, version, hash,
ProductCode and UpgradeCode live in `app/src-tauri/src/fakerinput_setup/pinned.rs`, which also says
how to update the package. Settings → «Клавиатура и мышь» runs `msiexec.exe` from the system
directory with `/passive` — no wizard, no licence page (MIT, its text ships beside the MSI), no «Are
you sure?»: only Windows Installer's progress bar and Windows' own UAC prompt, which basic UI keeps
(never `/quiet` or `/qn`, which would skip it and fail) — and a verbose MSI log flushed line by line
next to the app log (`/l*v!`, `%APPDATA%\AFKLink\logs\msiexec-fakerinput-*.log`; the app log's 7-day
rotation does not reach these, so each run first removes all but the newest nine — ten with its
own):

- «Установить»: the package is unpacked into a new directory under the user's temp folder
  (`CREATE_NEW`), reopened read-only sharing read only, re-hashed through that handle — so the copy
  msiexec gets under UAC is provably ours and cannot be swapped — and `msiexec /i "<copy>"` runs while
  the handle is held; the file and directory are removed afterwards;
- «Удалить»: `msiexec /x {ProductCode}` of the product Windows Installer actually holds (another
  version, e.g. one DS4Windows installed, is found by the UpgradeCode);
- «Переустановить»: `/x`, then `/i` (two UAC prompts).

The app's own dialog is the confirmation: three steps that say what will happen, then follow it by
real events — the UAC answer, read from that log while msiexec runs (`MSI_LUA: Elevated credential
consent provided`, or the service's `Doing action: InstallInitialize` when no prompt was needed),
msiexec's exit, the device appearing or going (`app/src-tauri/src/fakerinput_setup/progress.rs`,
`msi_log.rs`). A declined prompt ends msiexec with 1602 (1625 when policy refuses the elevation):
«Отменено».

The device is found as the official client finds it: every present HID interface is opened with no
access (enough for its attributes and descriptor; it never contends with Windows' hold on keyboards
and mice), and FakerInput's collections are those whose `HidD_GetAttributes` report VID `FE0F` /
PID `00FF`; of those, vendor page `FF00` usage 1 (control) and 2 (API), 65-byte output reports, are
the only two ever opened for writing. The interface path is not used: FakerInput is
root-enumerated, so its paths read `\\?\hid#system&colNN#…` with no VID/PID in them. Each probe
writes one aggregated `debug` line (`FakerInput probe`: interfaces looked at, FakerInput's
collections by usage, the outcome); a probe that saw the same as the last one goes to `trace`.

The section's state comes from two read-only facts — is the device present (`fakerinput_available`),
is a FakerInput product registered (`MsiQueryProductStateW`, `MsiEnumRelatedProductsW`):
`not_installed` (neither), `installed` (both), `installed_external` (device only: installed some
other way, status only) and `broken` (product only: device removed or disabled in Device Manager).
The package creates the device only on first install (`InstallAction`, `NOT Installed`), so a repair
or a second `/i` does not bring it back; that is why `broken` offers a reinstall.

Installing or removing the driver takes effect **without a restart**. The desktop app keeps the
selector's handle (`InputBackendHandle`) in Tauri state, and:

- after a successful install it waits for the device (up to 10 s, a look every 300 ms: PnP may
  still be starting its HID collections when msiexec returns) and then, if sessions are live, opens
  it and switches them to HID at once. A device that does not appear in time ends the install as
  `device_missing` — the dialog stops at its last step, never «Готово»;
- before `msiexec /x` it closes the device for any live session (so our open handle does not make
  Windows demand a reboot); those sessions continue on SendInput. After a successful removal it waits
  (up to 10 s) for the device to go and reports that Windows needs a restart if it does not; a removal
  that was cancelled, refused (another installation in progress) or failed reopens the device for
  live sessions at once, and one that needs a restart keeps it closed until «Проверить» or the first
  session after none were live;
- «Проверить» does the same re-probe as after an install (single attempt). It is the only status read
  that reopens: the section's mount and the re-read after every operation are read-only
  (`get_fakerinput_status` without `recheck`), or they would undo the close made for a removal.

Every live switch releases everything held on **both** paths first (like `ra`), then flips, so a key
pressed on one path is never released on the other. When there is no live session, nothing switches —
the next session's probe picks up the change.

## Which path each event takes

When the device is open, the single invariant is: **the path that pressed a key or button releases
it.** An HID report holds a press down until a neutral HID report clears it, so a press on one path
and a release on the other would strand state.

- Presses (`d`, key-down) and moves (`r`, `m`) follow the current **target**: HID when the Default
  desktop of the active console session has the input, SendInput otherwise. HID is deliberately
  **not** gated by the foreground window's privilege — the owner controls their own PC, so HID
  behaves like a physical keyboard and reaches administrator windows exactly as a real keyboard
  would. The target is re-evaluated at most every ~100 ms (a held HID key auto-repeats after
  250–500 ms, so a switch away must be noticed well inside that); the decision is logged only on a
  change of state.
- Releases (`u`, key-up, `ra`, `release_all`) follow **who is holding** the key/button, whatever the
  target is now.
- The **wheel** depends on where it comes from. The viewer marks the wheel of its game (MMO) mode —
  the pinch — with `game: true`; that one follows the target like a move and goes as HID Wheel / AC
  Pan reports, because games that read the mouse directly see only HID (Lineage 2 ignores the
  SendInput wheel). Every other wheel — the desktop's, no `game` or `false` — stays on smooth
  SendInput with the device open wherever SendInput reaches: the FakerInput descriptor has no wheel Resolution Multiplier, so HID turns only in
  whole notches and smooth trackpad scrolling would become steppy. Where SendInput cannot go it
  takes HID too, in whole notches: in game-only mode, and when the foreground window runs
  elevated and the agent does not — the text's decision (`game_guard::Reach`), made when the wheel
  is sent. See *The wheel on HID* below. Without the driver every wheel is SendInput.
- **Text** depends on where it comes from, like the wheel. Text typed in the viewer's game mode is
  marked `game: true`; with the device open and the target allowed it is typed as real key presses
  on the PC's layout (below), because games that read the keyboard directly see only HID keys
  (Lineage 2 ignores `SendInput`'s Unicode text). Every other
  text — no `game` or `false`, IME text on the desktop — and game text where HID may not go stays
  Unicode through SendInput, with two exceptions the game guard makes (below, «Only the game
  window»): in game-only mode all text goes by the driver's typing, and outside it so does text for
  a foreground window that runs elevated while the agent does not (Unicode cannot reach it).
- The **absolute position** (`m`: the tablet mode's touch, the desktop viewer's plain mouse) follows
  the target like any move: where HID may go it is FakerInput's absolute report
  (report 4) onto the pixel's centre — the pixel and mapping of the cursor sync's point move
  (`cursor_sync::target_pixel`, `absolute_wire`) — also while a button is held (a drag: the button
  stays on the relative report's collection, the positions come on report 4 with its button field
  0, and Windows keeps one button state for both). Where HID may not go (blocked, unknown), with the
  device broken and without the driver it is today's SendInput event. A failed report is not
  replayed (the next `m` replaces it) but leaves the mouse dirty, so the recovery writes the
  relative report's neutral report and a device that takes neither sends the rest of the session to
  SendInput. See *The absolute position and its clicks* below.
- F13–F24 stay on SendInput (outside the upstream keyboard descriptor, which ends at usage 0x65),
  and a **seventh** simultaneous non-modifier key overflows the six-key HID rollover and is sent (and
  released) through SendInput rather than dropped.

Physical `k` keys go as USB usages (Windows derives the scan codes); buttons as HID reports; what an
`r` sends — on either path — is the cursor-sync planner's (below): the camera's relative counts,
FakerInput's absolute report onto the viewer's pointer, or relative counts that move the cursor by
exactly the intended distance. Relative reports carry the held buttons, and large ones are split.

## Cursor sync (`src/cursor_sync.rs`)

The viewer's `r` carries the hand's delta as a fraction of the screen and, from a viewer that points
at the picture (the desktop game mode without pointer capture), the pointer's position (`x`, `y`).
One planner per process (kept with the SendInput ledger and asked by both paths) decides every `r`
from a fresh `GetCursorInfo` — microseconds, never the viewer's round-trip-late reports:

- **camera** — the cursor is hidden (not `CURSOR_SHOWING`, a null shape, or `CURSOR_SUPPRESSED`),
  off the captured screen, or unreadable: relative counts exactly as before the planner (fraction ×
  physical screen, the path's own sub-pixel carry). Camera sensitivity is unchanged.
- **point** — a target, a visible cursor, and no mouse button held by what this agent injected: one
  absolute move onto the target's pixel — FakerInput report 4 (`{4, buttons 0, X, Y, wheel 0}`) on
  the HID path, `SendInput`'s absolute event otherwise. Windows maps report 4's `0..32767` as
  `floor(X · width / 32768)` (the probe's eight data points), so the wire aims at the pixel's centre,
  `round((px + 0.5) · 32768 / width)`, and lands on it (the old edge-aimed mapping landed one short:
  2188 → 2187). `SendInput` gets the centre too (`floor(dx · width / 65536)`).
- **exact** — any other visible cursor (a button held — a drag, the first milliseconds of a
  right-button camera turn — or no target, the phone's finger modes): relative counts that move it
  by exactly the intended physical pixels (to the target, or `dx·width`, `dy·height`). Windows moves
  a visible cursor `S × speed factor` physical px per count with "Enhance pointer precision" (EPP)
  off (measured: 1.5 at 150 %; `S = dpi / 96` in the injecting thread's DPI awareness, the speed factor
  the slider's table); with EPP on, along its acceleration curve, which the planner learns per
  report size from its own moves (interpolated between sizes, extrapolated along their slope, seeded
  with the linear gain) rather than rebuilding it from `SmoothMouse*Curve` and Windows' undocumented
  constants. It keeps an intended position (the aim, clamped to the screen) and closes the loop on
  `GetCursorPos` (a report shows ~2 ms after it is written, the next `r` is ~16 ms away): each move
  sends the aim's motion, the counts rounding left over (exactly), and half of any remaining error
  (at most `max(3 px, half the hand's motion)`; nothing within 1 px). Sends not yet visible are in
  flight (40 ms at most), so nothing is corrected twice. The aim re-anchors on the real cursor when
  exact mode starts (after a camera turn, a point move, a release) and when the cursor moved in a
  way our sends cannot explain (the PC's own mouse, a game's warp) or not at all (UIPI). With EPP off
  the model is checked too: if thirty samples say Windows moves more than 12 % off it, the measured
  gain is used (with a `warn`).

Settings (DPI, EPP, speed) are read at session start and at most once a second on a move; a change
re-anchors and rebuilds the gain. The heartbeat's `rel_exact: true` tells the viewer that `r` now
means exactly this fraction of the screen.

An `m` is not the planner's to decide — it is always one absolute move — but it is told of every
one, on either path (`CursorSync::absolute`), and keeps its books as for a point move: it looks at
the cursor, puts the move in flight and forgets exact mode's aim. So an `r` after an `m` (the owner
switching from the tablet mode to the trackpad mode) moves from where the `m` put the cursor, and is
not taken for someone else's motion (no re-anchor line). On HID the planner also gives the `m` its
pixel, so `m` and a point move aim identically.

**The moves the cursor shows (the cursor report's `ack`).** The viewer's marker is the agent's
cursor report plus the numbered moves (`r.s`) sent after the one the report's `ack` names. A report
shows on the cursor about 2 ms after it is written, so an `ack` naming every move handed in would
claim, for a report sampled in those 2 ms, a move its position does not include, and the marker
would step back by it — about every eighth report of a stroke. So every cursor poll (`InputInjector::cursor`, ~30 Hz) looks at the cursor under the planner's
lock and asks it for the lowest numbered move that look does not show (`CursorSync::unshown`): a send
the cursor's movement does not account for yet (the same in-order matching the planner closes its
loop with, read only), or a move the HID router queued behind a click, a key or a tap's minimum hold
(`rel_queued`). The `ack` stays below it (`afklink_core::cursor_report::Ack`). It never hangs: a send
counts as shown once the cursor moved at all, when the game hid the cursor (the camera's move drops
what is in flight), or 40 ms after it was made; a queued move when the router's queue is released, or
after 250 ms. Unnumbered moves (an older viewer) and `m` are never waited for, and the wire is the
same: an older viewer gets what it always got, minus the steps back.

Logs: `debug` — the settings (session start, changes), every mode change with its inputs (visible,
buttons, target, scale, DPI, EPP, speed, gain; more than eight a second go to `trace`, counted),
every re-anchor that is not a mode change with why, the foreground window's exe and whether it runs
elevated (and whether the agent does) on every change, and a `cursor sync` line per second of moves
(moves per mode and path, absolute moves, counts, the residual error after correction, re-anchors,
external motion, moves with no effect, the gain in use and measured, the learned sizes; `m_hid` and
`m_sendinput`, the `m` per path; `order_waits`, `order_wait_max_ms` and `order_timeouts`, the buttons
that waited for an absolute move to show; `wheel_sendinput`, `wheel_hid_game`, `wheel_hid_stepped`,
`wheel_hid_notches` and `wheel_carry_resets`, the wheel's messages per way, the whole notches written
to HID and the unfinished notches dropped — the paths tell it, the planner only counts;
`unshown_polls`, `queued_moves` and `queued_expired`, the cursor polls that found a numbered move not
shown yet, the numbered moves queued behind other input and those given up in the queue). `trace` —
every move (with its number), every `m`, every poll that found a move not shown yet, every move
queued. Nothing per move or per poll at `debug`.

**Cursor shapes** (`src/cursor_shape.rs`). The cursor report says each new cursor shape of a session
once at `debug` (`cursor shape: new this session`, `afklink_core::cursor_report::ShapeLog`): the
picture's size, its hotspot (the pixel a click lands on, which is `GetCursorInfo`'s position), the box
of the pixels it draws relative to the hotspot (alpha, or the AND/XOR masks), colour or monochrome,
and the window under the cursor — exe, class, DPI awareness (`unaware`, `unaware (GDI scaled)`,
`system aware`, `per-monitor aware`, `per-monitor aware v2`), its DPI and the monitor's. Reads only:
`GetIconInfo` and `GetDIBits` of the copies it returns (deleted), `WindowFromPoint`, the window's
class and DPI, and its exe through a `PROCESS_QUERY_LIMITED_INFORMATION` handle closed at once. At
most 32 lines a session; further new shapes are counted in the report's summary line.

**Absolute moves and their clicks.** Report 4 and the buttons' report 3 are two collections — to
Windows two mice, each read on its own — and nothing promises that two reports written back to back
reach Windows in order. A tap of the tablet mode is `m`, `d`, `u` back to back, a long press `m`,
`d2`, `u2`, the desktop viewer's press `m`, `d`, and a click of the desktop game mode a point move
(`r` with `x`, `y`), then `d`: a button that overtook its move would click where the cursor was. So a
mouse button going down or up on HID right after an absolute move — an `m` or a point move — waits
until `GetCursorPos` shows the move (within a pixel), at most 8 ms after the move was written
(`ORDER_WAIT_MAX`; the probe saw a report show 1.6–1.8 ms after its write), then goes anyway. It waits at
the head of the queue the typing worker works (polled every 0.5 ms; never on the session's event
task), so whatever comes after it — the tap's release, the next move — waits behind it, in order;
the release still keeps its minimum hold after the press. A button long after the move, or with the
cursor already there (the desktop viewer presses where its last `m` put the cursor), goes at once,
as does one when the cursor cannot be read or while the queue is sent at once. `ra` drops a waiting
press with the queue. The `m`'s path is said at `debug` when it changes (`position (m) path`, with
the reason: the target, the device unusable, no driver), a wait that gave up at `debug` with its
numbers (`button after an absolute move: the cursor did not show the move in time`), each wait at
`trace`, and the waits per second in the `cursor sync` line.

**Short taps.** A key or mouse button the viewer releases through HID sooner than `TAP_MIN_HOLD`
(30 ms) after its press is released 30 ms after the press: a phone's Enter, Backspace or Delete tap,
or a tap on the trackpad, sends the down and the up back to back, and a game that polls once a frame
never saw it. The release waits at the head of the typing queue (below), so everything that comes
after it — keys, buttons, text, and moves and the wheel too — waits behind it: the next key cannot
overtake it, and a move cannot drag with the button still down. Each deferral is a `trace` line with a
running count, and each burst's total is in its `debug` line; `ra` drops a waiting release together
with everything it releases.

**Game text on HID** (`src/fakerinput/typing.rs`, `src/fakerinput/layouts.rs`).

- *Normalisation* (owner's defaults): newlines are dropped, so a chat line is not sent early; iOS
  typography becomes ASCII (’ ‘ → ', “ ” → ", — – → -, … → ..., no-break space → space).
- *Each character, on the PC's layout*: the layout of the thread that owns the focused window
  (`GetGUIThreadInfo` → focus or active window → `GetWindowThreadProcessId` → `GetKeyboardLayout`).
  `VkKeyScanExW` gives the virtual key and its Shift/AltGr state,
  `MapVirtualKeyExW(MAPVK_VK_TO_VSC_EX)` the scan code, a fixed table the HID usage of that physical
  key (digits, letters, punctuation, Space, the ISO key; not the keypad, whose keys change with Num
  Lock, nor anything past the descriptor). `ToUnicodeEx` with flag 4 — it leaves the keyboard state,
  and any pending dead key, alone — checks the key really makes the character: a dead key is never
  typed, and with Caps Lock on the other Shift is tried (lowercase then goes with Shift). Caps Lock is
  read once per message (`debug`) as the focused window's thread sees it — the worker attaches to that
  thread for the read (`AttachThreadInput`, always detached again; if attaching fails it reads its
  own view, and says so), since a thread that reads no keyboard messages never sees the toggle
  change. A Caps Lock press the agent itself sent through HID counts for the next message even before
  that window has read it (for up to 500 ms). AltGr is left Ctrl + right Alt.
- *Another layout, switched automatically*: a character the current layout cannot
  type but another installed one can (`GetKeyboardLayoutList`; the most recently used such layout
  first) switches the focused window to it — `WM_INPUTLANGCHANGEREQUEST` to the focus window, else
  the foreground one, with `INPUTLANGCHANGE_SYSCHARSET` when the layout's code page is the system's —
  and the layout is polled every 10 ms for up to `SWITCH_CONFIRM` (300 ms). A window that does not
  take it (some games ignore it; an administrator window refuses our message) gets the user's own
  language hotkey (`HKCU\Keyboard Layout\Toggle`, `Language Hotkey`, else `Hotkey`: 1 Alt+Shift, 2
  Ctrl+Shift, 3 none) pressed through HID, checked after each press, at most once per installed
  layout; that window then gets the hotkey straight away next time. A window where the hotkey
  changed nothing is never pressed again this session: its characters that need another layout go
  by Unicode at once (said once at `debug`). Never pressed: Win+Space (a lone Win release opens Start
  and the switcher's overlay can take the focus from a full-screen game) and the grave accent
  (setting 4; it opens the console of many raw-input games). The language hotkey switches
  languages, not the layouts of one language: a second layout of the same language (English (US)
  and US-International, say) is said to be out of its reach. When nothing works the character goes
  by Unicode in its place, as does every other character in the message that needs that layout. The
  layout is left switched afterwards, as a person would leave it; later characters switch back only
  when they need to.
- *Pacing*: a worker thread per open device, alive only while something is queued, types one
  character at a time — modifiers `MODIFIER_LEAD` (10 ms) ahead, the key held `KEY_HOLD` (30 ms),
  `KEY_GAP` (20 ms) before the next; Shift stays down across consecutive capitals. All are named
  constants to tune live. `inject` only queues and returns: the session's event task, which also
  carries WebRTC, never sleeps. The worker sleeps with the lock released, so a camera turn waits for
  at most one report.
- *The desktop, before every report*: the worker types unattended, so before every report it writes
  — a typed key, a hotkey press, a queued event, a held wheel — it looks at the desktop afresh, not
  from the 100 ms cache. If a UAC prompt, the lock screen, another session or a desktop it cannot
  confirm has the input, everything queued is dropped and everything held released (a key that was
  down gets its release, so it cannot auto-repeat into the prompt); nothing else is written, and a
  queued Enter never confirms a prompt.
- *The ordering barrier*: while text is queued, `k`, `d`, `u`, `combo` and further `text` wait behind
  it, so the Enter after a chat line comes after its last key. Moves (`r`, `m`) and the wheel go at
  once while nothing but text waits — the camera keeps turning while a line is typed — but once a
  click, a key or a combo waits, everything after it waits too, in order: a click lands where the
  pointer was, and a queued button release is not outrun by a drag. A wheel that comes while the
  typing holds a modifier down (a capital's Shift) would be a Shift+wheel: it waits for the modifier
  to go up, and the typing lets it up at the next character for it. Queued input is replayed with the
  gaps it came with, each capped at `MAX_REPLAY_GAP` (1 s): a queued tap stays a tap, a key held
  900 ms stays held 900 ms. A layout switch pauses the queue, never reorders it.
- *Held keys*: every typed report carries the keys and modifiers the panel holds plus the typed key,
  and the held state is restored afterwards; a Shift the panel holds is lifted for a lowercase
  character. Ctrl, Alt or Win held on either path — or Shift held through SendInput, which HID cannot
  lift — sends the whole message by Unicode. A character whose key the panel already holds, or that
  finds the six-key rollover full, goes by Unicode alone. The first key typed stops SendInput's
  emulated repeat, once per message.
- *Failure and release*: `ra`, `release_all`, the session's end and a desktop HID may not drive
  drop what is queued (counted in a `debug` line) and release everything held on both paths; a
  failed write stops typing the same way, is never replayed, and follows the existing rules (a
  cleanup that fails too makes the device unusable for the session); a report the reserved-sequence
  check refuses is never written and stops typing too, said as such. The queue is only ever dropped
  together with that full release, so a key-up waiting in it cannot strand its key. The silence
  release (2 s without viewer data) does not cut a line: the viewer's once-a-second `vv` report keeps
  it off while the viewer is alive. If the worker thread cannot start, or the queue overflows (1024
  entries; 256 characters — about 13 s of typing — past which a text goes by Unicode in its turn),
  everything queued is sent at once, in order, text by Unicode (after the typing's modifiers go up,
  and 10 ms later).
- *Logs* never name a character, virtual key, scan code or usage, and say nothing per character or
  per report: which characters were capitals, needed AltGr or a switch is the shape of a password.
  Tests capture every level while typing and check that no typed character appears, and that two
  passwords of one length with capitals and AltGr in different places log the same lines. `debug`:
  the path game text takes when it changes (`game text path`), Caps Lock once per message, each
  layout switch with its method, time and the layouts' language ids (`keyboard layout switched for
  game text`, or why not), drops, and one `game text typed` line per burst — messages, characters as
  keys and by Unicode with the reasons, switches and their time, short taps held (the taps are `k`
  and button releases, never text: `tap_keys` names the viewer's own keys, `k.src`, and
  `tap_keys_other` counts the rest, with `tap_buttons` and `tap_shortest_ms`). `trace`: per message
  and per queued event, never per character.

**The wheel on HID** (`src/wheel.rs`, `State::wheel_scaled`). The delta is read in notches exactly as
on the SendInput path — pixels at `HID_PIXELS_PER_NOTCH` for the game wheel (100, the same as
SendInput's `PIXELS_PER_NOTCH`; the constant to tune after a live check) and at SendInput's own
`PIXELS_PER_NOTCH` for every other wheel, 3 lines or a fifth of a page per notch — with SendInput's
signs (`dy` > 0 scrolls down = HID Wheel < 0; `dx` > 0 = AC Pan > 0). One HID unit is one notch, a
`WHEEL_DELTA` of 120 to Windows. HID takes whole notches only, so the fraction is carried to the next
message: ten messages of 10 px turn the wheel once. A change of direction drops the old direction's
unfinished notch (100 px back is one notch back, not 190); so does any change of the wheel's route
(the game wheel, game-only mode, an elevated window, smooth SendInput, the target), and
`release_all`. Large turns go as reports of at most ±127; one message is capped at 508 notches (four
reports) per axis. Held HID buttons ride along in every wheel report.

Which wheel goes there:

- the game wheel (`game: true`) wherever the target allows, as it always did — its fraction kept
  across any pause (the pinch sends whole notches anyway);
- every other wheel only where SendInput cannot go — in game-only mode (the game reads the mouse
  directly) and to a foreground window that runs elevated while the agent does not (UIPI drops
  SendInput there: Task Manager, Notepad run as administrator) — decided when it is sent, from the
  foreground window's elevation looked at afresh (`CursorSync::foreground_elevation`), by the text's
  rule (`game_guard::Reach`). There it scrolls in steps (three lines in Notepad per notch) where
  before it did not scroll at all; everywhere else it stays smooth, and never even looks at the
  target. Its unfinished notch is also forgotten after `STEPPED_CARRY_PAUSE` (300 ms) without a
  message: in a gesture the viewer sends one every frame (16–33 ms) and a trackpad's momentum keeps
  sending, so only a finished gesture waits that long, and its remainder must not turn the wheel at
  the start of the next one. A gesture shorter than a notch (100 px) therefore scrolls nothing there;
- where HID may not go (blocked, unknown), with the device broken and without the driver: SendInput,
  as before.

The path is logged at `debug` (`wheel path`, with the reason — the game wheel, game-only mode, the
elevated window with its exe, back to smooth and why) on the first wheel after the device opens and
on every change — at most one such line per 2 s, the rest at `trace` and counted; without the driver,
a wheel not marked `game` says once per reason that it goes by SendInput, and that Windows drops it
when the foreground window runs elevated. Each message's route, each report and the accumulation are
at `trace`; the messages per way, the notches and the dropped remainders are in the planner's
per-second `cursor sync` line.

**Key auto-repeat.** A keyboard does not repeat keys; its host does — HID 1.11 (Appendix C) leaves
the repeat delay and rate to the host, and on Windows the HID keyboard mapper driver (`kbdhid.sys`)
runs that timer. So a key held through the FakerInput keyboard repeats by itself, like a physical
one. A key pressed through `SendInput` never passes through a keyboard driver and does **not**
repeat, and the Mini App holds a key while the finger is on its button (`k d=1` … `k d=0`) without
sending repeats. `SendInputInjector` therefore repeats the last key it holds (`src/repeat.rs`): after
Windows' keyboard delay, at Windows' repeat rate (`SPI_GETKEYBOARDDELAY`: 0–3 → 250–1000 ms;
`SPI_GETKEYBOARDSPEED`: 0–31 → 2.5–30 a second), read at each press. Modifiers and lock keys never
repeat. Its release, a press of any other key (on either path — a key pressed on HID ends it; a
re-press of a modifier already down does not), `release_all` and the last session's end stop it.
The viewer's own repeats (a physical keyboard at the viewer: the browser sends `k d=1` again) are
injected as they come and push the emulated repeat a whole delay away, so the two never interleave;
emulation resumes only if they stop for a delay with the key still down. A worker thread lives only
while a key repeats and exits when nothing does. It presses a key again only under the held-key
ledger's lock and only while the key is in the ledger, and every release removes the key from the
ledger before its key-up — so a repeat can precede a release, never follow it. Start and stop at
`debug` (a tap that never repeated: `trace`), each repeat at `trace`; the key is never named. Keys
on the HID path are not emulated — Windows repeats them.

**Administrator windows.** Because HID is not privilege-gated, keys, buttons, relative motion, the
cursor sync's absolute moves, the absolute position (`m`: the tablet mode's cursor follows the
finger, and its tap clicks there), the game wheel and game text reach an administrator window on
the HID path (its layout switch goes by the language hotkey: UIPI refuses our request message).
Text and the desktop wheel, which go by SendInput elsewhere, reach it through the driver too when it
is the foreground window and the agent is not elevated: text by the driver's typing, the wheel in
whole notches (steps instead of smooth scrolling). Windows' UIPI takes `SendInput` into a
higher-integrity window, answers success and drops it (measured: Lineage 2's `ScrydeGame.bin` runs
elevated), so without the driver, or where HID may not go, `m`, text and the desktop wheel are
SendInput again and do not reach it. The wheel is routed by the *foreground* window, as text is;
whether UIPI judges the wheel by that window or by the one under the cursor («Scroll inactive
windows») was never probed (П2 in the research), so an elevated window scrolled from behind an
ordinary one in front may still get the smooth wheel and drop it. The log says the foreground
window's exe and elevation on every change, and the planner counts moves that moved nothing
(`no_effect`). This is a strict improvement over the SendInput-only past, where *nothing* reached an
administrator window; it is called out here so the gap in those cases is understood rather than
surprising.

**Blocked / unknown target.** A surface Windows keeps for itself — the UAC secure desktop, the lock
screen (a non-Default desktop), or another session — is never driven by HID; input there goes via
SendInput, which Windows gates on its own. On the transition into that state, held input is released
once (a physical HID key must not stay down across the switch). A rare internal query failure counts
as "unknown": input is routed via SendInput but held HID is left undisturbed, since it is a transient
blip, not a known-bad surface. Ctrl+Alt+Delete and Win+L are blocked on the HID path (a real virtual
HID keyboard would otherwise trigger the SAS or lock). The HID path never reads or hooks local
keyboard/mouse input, and implements no elevation, policy change or protected-process workaround;
only the owner's visible installer workflow requests ordinary UAC.

## «Only the game window» (`src/game_guard.rs`)

While the owner limits the viewer to the game's window (`afklink_core::game`), every event comes with the session's scope
(`InputInjector::inject_scoped`): the game's window as the session's capture last saw it — its
handle, the process that owns it (from the window list, never opened) and its client area on screen
— or none while it is absent, starting, minimized or not captured yet. The process-wide backend asks
the game guard before either path sees the event:

- **Coordinates.** `m`, `r.x/y` and `r.dx/dy` are fractions of the picture the viewer sees, which is
  the game's client area as the capture crops it (`afklink_core::game::client_crop` placed back on
  screen: on a game Windows stretches for DPI, a row or column inside the client area Windows
  reports, so the cursor never lands on the title bar's last row the crop leaves out). The
  cursor-sync planner is given that area as its space on every event and
  maps a target to `left + floor(x · width)` of it (clamped to it and to the screen), then today's
  paths send it: report 4 onto the pixel's centre, `SendInput`'s absolute event onto the pixel's
  centre (in this mode also for `m`), exact counts. Exact mode's aim is clamped to the area, so the
  cursor cannot be moved out of the window (a cursor found outside it — on a windowed game's title
  bar — is brought in); the hand's delta is a fraction of the area. `ClipCursor` is not used (Windows
  resets it on every change of the foreground window, and it would confine the owner's own mouse).
  The camera — a cursor the game hid — is untouched: its counts are the fraction times the physical
  screen, as always. The cursor report `cp` is in the same space (`afklink_core::game_input`):
  fractions of the client area, `hidden` outside it and while the window is not shown.
- **Only while the game has the front.** The game's window must be the foreground window, looked at
  for every event and every 100 ms by the session's focus watch (`InputInjector::game_focus`).
  Otherwise moves, presses, new key-downs, the wheel, text and combos are dropped; releases (`u`,
  key-up, `ra`) always pass; everything held on both paths is released the moment the game loses the
  front (or stops being shown, or the mode begins); the typing worker sends nothing queued unless the
  game's window is in front (the chat line is dropped with the release, as for a secure desktop); and
  the heartbeat says `unfocused`. On the viewer's input, at most every 2 s, the game is asked back
  with `SetForegroundWindow` — from an unelevated agent Windows usually refuses and flashes the game's
  taskbar button (§14). No other window is minimized or touched.
- **A press lands only on the game.** Before a button goes down, `WindowFromPoint` at the pixel it
  will land on (the planner's: where the move just sent puts the cursor, else the cursor) must be a
  window of the game's process, or its top-level window must be — pids compared, no process opened.
  An always-on-top window over the game swallows no click.
- **Escape keys.** Win (either, alone or with anything), Alt+Tab, Alt+Esc, Ctrl+Esc, Ctrl+Shift+Esc
  and every `combo` (`ctrl_alt_del`) are dropped before either path, whichever key of a combination
  comes second; a dropped key's release is dropped with it (and a lone Win release with no press of
  ours), a passed key's release always passes, so no modifier strands. **Alt+F4 passes, for everyone**
  — a guest too: one key list for every session; each Alt+F4 let through is
  said at `debug`.
- **Text** goes by the driver's typing whatever the viewer's mode (the path of `text.game`).
- **The wheel** goes as whole HID notches whatever the viewer's mode (a wheel the viewer did not
  mark `game` is stepped in the router, see *The wheel on HID*); the guard passes it unchanged.

Outside the mode, text goes by the driver's typing when the foreground window runs elevated and the
agent does not (`SendInput`'s Unicode cannot reach it: UIPI) and the driver is open, from the
planner's foreground tracking looked at afresh; otherwise Unicode, as before. The wheel not marked
`game` takes the same decision (`Reach`) in the router, when it is sent: whole HID notches to such a
window, smooth SendInput otherwise.

Logs: `debug` — every change of where input may go (with the foreground window's exe when another
has the front; the game's own process is never opened for a line) with what was down through us at
that moment (`held_keys`, `held_mods`, `held_buttons`, `held_ours`, `held_other`: `released=true`
only says releases were sent, whether or not anything was held), each focus attempt and Windows'
answer, each blocked key or combo with its combination and `src`, each Alt+F4 let through with its
`src`, each dropped press with why, each change of the text's route, the coordinate space at session
start and on each change (at most one line a second), the typing worker's queue gate on each change,
and a `game input` line a second while anything was dropped, blocked or attempted (`moves_dropped`,
`presses_dropped`, `presses_off_game`, `keys_dropped`, `keys_blocked`, `other_dropped`,
`focus_attempts`, `focus_won`, `releases`). `trace` — every event held back. The session's side logs
its focus watch's changes and the cursor report's space.

Which keys (`src/key_log.rs`, kept by the guard, in every mode): a key is named only when the viewer
tagged it as one of its own (`k.src`: `cell`, a key cell of the Mini App's keys layer; `sheet`, its
keys sheet — cut-down binds on which no password can be typed), or when it is a key
of the system combination a guard line is about (a modifier, Tab, Escape, F4). A key from the viewer's
own keyboard or the phone's system keyboard (no tag, or one this build does not know) is `-` and
counted; `text` never comes here. `debug` — one `keys` line a second while key messages come: ours by
name as the PC got them, each non-modifier with the modifiers down at its press (`AltLeft+KeyB×9`, a
modifier not ours written `mod`), `cells=` and `sheet=` apart, `other` (the rest), `dropped`,
`repeats`, `ups`, `max_held` and `under_held_mod` (a key of ours pressed while a modifier and another
key were already down: two chords at once); and the flight recorder — the last 12 key events of ours
with how long before, `dropped` where the guard did not let one through, and how many key messages
not ours came among them — written out when the game's window loses the front, stops being shown, or
Alt+F4 is let through. Nothing here reads the PC's keyboard: "held" is what the viewer pressed
through us.

## The button watch (`src/fakerinput/button_watch.rs`)

Lineage 2 (Scryde) hides the cursor while the right button is held — its camera turn — and shows
it again 10–50 ms after the button comes up. About one button change in thirty, either way, it did
not take: the router's ledger was balanced and the
release went out in its HID report, yet the cursor stayed hidden for 37 s while every move turned the
camera. How the game loses one is not known yet; the watch both logs what is needed to find out and
repairs the case that hurts.

In game-only mode, every mouse button change the router writes for `d` / `u` is watched while the
cursor can be read: looked at every 5 ms until it reacts or 50 ms passed (then the probe line), and
once more 250 ms after the change when that decides something (on the typing worker, which lives
while anything is watched). A **normal pair**: the cursor showed before the press, was hidden after
it, and showed again within 250 ms of the release — counted per button for the device's open period.
A **missed release**: a pair that began so and the cursor still hidden 250 ms after the release. It
is sent once more — the same button's press at once, its release after the tap minimum (30 ms),
through the queue a short tap's release waits in, so moves that come meanwhile wait behind it —
when that button made at least 3 normal pairs, the release is not a re-send itself, no re-send in
the last 300 ms, the button was not given up on, the game's window has the front, nothing is held on
either path (buttons, keys, modifiers), nothing waits in the queue, HID may drive the desktop and the
device works. Still hidden 250 ms after the re-sent release: a `warn`, and the button is left alone
until the viewer presses it again. A **missed press** (a button with 3 normal pairs pressed while the
cursor showed, still held 250 ms later, the cursor never hid) is only logged. «Держать ПКМ» is a
press with no release: nothing to re-send. `ra`, the game losing the front, a blocked desktop and a
failed write end every watch (their neutral report is not judged).

Logs: `debug` — per button change, 50 ms after it, how the cursor took it (hidden or shown after N ms,
or no change), the buttons Windows' async key state has down (`GetAsyncKeyState` of the three mouse
buttons, never a key), ours, and for the right button the game's thread's mouse capture
(`GetGUIThreadInfo`), the window under the cursor and the foreground window (handle, class, and an exe
unless it is the game's process, which is never opened); every missed release and press with its
numbers; each re-send and whether it helped (`warn` when not); the session's account when the device
closes (normal pairs per button, re-sends, helped, failed, not re-sent, missed presses). The planner
(`src/cursor_sync.rs`) says every change of the cursor's visibility the cursor poll sees with the
buttons held then on either path and the router's last button change (`cursor visibility changed`).
`trace` — every look. A raw-input witness (counting the driver's `RI_MOUSE_*_BUTTON_UP` against the
reports written) is not built: raw input registration is per process and usage, so it would take the
mouse's raw input from the desktop app's own window (its event loop registers it), and it would read
the PC's own mouse too.

## «Управление не доходит» (`src/reach.rs`)

Without the driver, a click, a key and a text go by `SendInput`, which a window running as
administrator never gets while the agent runs without (UIPI drops it and answers success). The
process-wide backend tells the reach watch of every fresh press either path takes — a button going
down, a key going down the `SendInput` path does not already hold, a text; never moves or the wheel —
and where it went: through the driver, reached; by `SendInput`, the text's and the wheel's decision
(`Reach`, the foreground window's elevation looked at afresh) — dropped into such a window, reached
elsewhere, unknown when the elevation cannot be read. Three dropped in a row within 2 s are
**blocked** (a press that got through ends the run; one window left open as administrator that nobody
presses into never is), held while presses keep being dropped and 10 s after the last one.
`InputInjector::input_reach` answers with that, the driver (`open`, or `missing` where the x64
installer runs) and the counts since the process started; `afklink_core::input_reach` turns it into
the heartbeat's `no_driver` / `input_blocked`, the desktop app's «Управление не доходит» highlight and
its toast. The desktop app's «Окно игры» asks `window_blocks_sendinput` — the same read, its process
opened for limited information and its token for a query — for each window it lists while the driver
is missing.

Logs: `debug` — blocked begins (how many, within how long, the foreground exe) and ends (how long,
how many dropped in it), and an `input reach` line a second while presses are dropped, unreadable or
blocked (`dropped_buttons`, `dropped_keys`, `dropped_text`, `reached`, `unknown`); `trace` — each
press, and the second's line when everything got through.

## Robustness and logging

Reports and held state share a mutex. Failed writes never silently forget a potentially held
key/button; cleanup sends neutral reports, attempts every dirty report family even if one fails, and
retains unsuccessful releases for retry. Relative movement is never replayed after an ambiguous write
failure. If the device stops accepting writes mid-session (a write **and** the neutral cleanup both
fail — the device was removed or broke), the rest of that session runs on SendInput; the failed event
is not replayed, and the fall-back is logged once at `warn`. No reports are produced by an idle
injector or its idle cleanup.

Warnings are rate-limited like the SendInput path: a failed HID write and a rejected event each warn
once immediately, then at most once every 10 s with the suppressed count — a wrong target or a
failing device cannot write sixty lines a second. Per-event decisions on the hot path (each mouse
move) are never logged at `debug`; only state transitions (backend choice, target change, fall-back,
device open/close) are.

## Verification

From `agent/`, `cargo test -p afklink-input` exercises report bytes, physical key mapping, fractions,
the game wheel (carried notches, change of direction, AC Pan, ±127 splitting, the cap, release), the wheel not
marked `game` through the router (smooth SendInput for an ordinary window, an elevated agent and an
unreadable elevation, with no look at the target; whole notches at SendInput's scale — pixels, lines,
pages — for an elevated window and in game-only mode; SendInput where HID may not go and with the
device broken; small deltas adding up, the remainder carried and dropped on a change of direction or of
route and a 300 ms pause but not a 299 ms one; AC Pan; the game wheel unchanged, its remainder kept
across a pause; the route's `debug` line with its exe and the per-second counts, nothing per message
at `debug`), the text's and the wheel's shared decision (`Reach`), six-key
rollover refusal, the held-state and overflow helpers, failed writes and neutral cleanup using a fake
output transport, and the key auto-repeat's state machine on a virtual clock plus its worker with a
recording sink. Game text and short taps run through the real router (`HidRuntime`) on a fake world
(`src/fakerinput/fake.rs`: a recording device and SendInput path, the target, and US, Russian,
German and French layouts that answer as user32 would) on a virtual clock: mapping, Caps Lock (and
a Caps Lock press the worker sent), dead keys, AltGr, automatic switching (message, then hotkey,
then Unicode; the grave hotkey never pressed; a dead hotkey remembered; a same-language layout out of
reach), held panel keys, rollover, Ctrl/Alt/Win held, mixed Latin and Cyrillic in order, pacing
timestamps, the barrier (moves behind a queued click, a held button's release before a drag, a wheel
during a capital), replay with the original gaps, `ra`, a failed write, the desktop turning secure
mid-line (between two reports, too), the repeat stopped once, the key and button tap deferral, the
non-game routing as before, and log captures showing no typed character and no per-character
pattern reaches the log. The cursor-sync planner runs against a simulated Windows
(`src/cursor_sync/sim.rs`: a virtual cursor with the sub-pixel remainder, linear or accelerated
ballistics, inputs showing late, the report-4 mapping): exact travel at 100/125/150/200 % and every
speed slider value, EPP convergence without ringing through speed changes, a wrong gain closing a gap
without overshoot, a slow reflection not corrected twice, re-anchoring on someone else's motion and
on moves that move nothing, the edges, a camera turn (its counts byte for byte today's) and the
cursor coming back elsewhere, point → drag → point, a held button following the target, half a
target, report 4 landing on every pixel of common widths, a settings change, and the logs (nothing
per move at `debug`, the foreground window's elevation); the router's HID reports for point, drag and
camera moves run on the fake world with the real planner. The absolute position runs there too:
`m` as report 4 onto the pixel's centre (edges included) where HID may go and by SendInput where it
may not, a failed `m` not replayed and a dead device leaving `m` to SendInput, a tap's press waiting
for its `m` to show (and at most the bound) and a desktop game-mode click waiting for its
point move the same way, no wait when the cursor is already there or the
`m` is old, a drag with the button on report 3 and every position on report 4, an `m` waiting behind
a waiting tap, `ra` dropping a waiting press, an `r` after an `m` moving from where the `m` put the
cursor (no re-anchor, on either path), and the logs (the path on a change, nothing per `m` at
`debug`, `m` and the waits in the per-second line). Game-only mode: the planner maps every pixel of
a windowed client area (3576×2268 at +12+47) and report 4 lands on it, `m` and point moves land in
it, exact moves and drags stop at its edge and bring a cursor on the title bar in, the hand is a
fraction of it and the camera is untouched, a press is judged where the move before it puts the
cursor; the game guard on a fake PC (`src/game_guard/tests.rs`) drops input while another window
has the front and passes every release, releases once on focus loss (by the focus watch alone too)
and on entering the mode, asks the game back at most every 2 s and only on input, takes nothing but
releases while the window is not shown, blocks every listed escape either way round with its
release and nothing stranded, routes text (game-only, an elevated window with and without the
driver, the agent elevated, ordinary), passes the wheel unchanged, and lets a press through only
onto a window of the game's process; the typing worker drops a line when the game loses the front
mid-line. The button watch (`src/fakerinput/button_watch/tests.rs`) runs through the router against
a fake game that hides the cursor while the right button is held and loses the presses or releases
a test tells it to: pairs it takes are counted and nothing is re-sent; a missed release goes once
more 250 ms after it (the release 30 ms after the press, moves meanwhile behind it) and counts as
helped; nothing with fewer than 3 normal pairs, outside game-only mode, with the game's window not
in front, a blocked desktop, another button held, «Держать ПКМ» or after `ra`; a re-send that does not
help warns once and nothing more until the viewer's next press; a missed press is only logged; one
probe line per change. It never opens a device, calls `SendInput` or moves the real cursor.
`the_us_layout_answers_as_typing_expects` (ignored; run with `--ignored`) checks the real user32 on
this PC's English (US) layout, read-only.

Read-only hardware discovery (does not launch AFKLink or inject input):

```powershell
cargo test -p afklink-input probe_installed_driver_without_input -- --ignored --nocapture
```

For manual acceptance only, after installing through Settings and focusing a safe HID/Raw Input
target, the following ignored test opens the device, sends W, holds the right mouse button, moves
relatively, then releases both:

```powershell
cargo test -p afklink-input manual_hid_key_and_relative_motion -- --ignored
```

The mouse probe (`src/fakerinput/mouse_probe.rs`, ignored; parameters in its header) moves the real
cursor through every way the agent can — including `hid_abs` (the point move's report 4) and
`exact_rel` (the planner's exact move, 150 px per move: it should land within a pixel of 150 px, at
any display scale, with EPP on as well) — and writes a JSON record under `target\`.

The click probe (`src/fakerinput/click_probe.rs`, ignored; details in its header) checks the absolute
position through the real router and driver, and **presses the left mouse button** — over Notepad's
text only: it refuses any other foreground, checks that the window under every point is Notepad's
text control before anything moves, and again before every press and every step of the drag. With
Notepad big on the primary monitor and some text pasted into it (for the administrator case, start
Notepad elevated; the probe stays unelevated), from an unelevated terminal with no session live:

```powershell
cargo test -p afklink-input --release click_probe -- --ignored --nocapture
```

then focus Notepad. `position`: each `m` lands on its pixel. `click_after_move`: taps (`m`, `d`,
`u`) whose press a raw-input sink hears after the report-4 move and at the new point (`MSG.pt`).
`click_raw`: the same taps written to the device with no wait — whether the two collections keep
their order on their own (informational). `drag`: press at the start, every move with the button
down, one release at the end, text selected. The record goes to `target\click-probe-*.json`.

Also verify an authorized viewer session: hold W/right mouse, disconnect it, use Stop all sessions,
and let input go silent while viewer statistics continue. Each case must release held input. Without
the driver, verify the logged SendInput selection and ordinary viewer control. With the driver, the
tablet mode's cursor must follow the finger and its tap, double tap, long press and drag must land
there over an administrator window (Task Manager) too (`position (m) path` … `hid`, the `cursor sync`
line's `m_hid` and `order_waits`, no `order_timeouts`), and a UAC prompt must turn it to
`sendinput` with `HID target blocked`. A game-mode pinch must zoom in a game that reads the mouse
directly (`wheel path` … `hid` in the log)
while the desktop wheel stays smooth (`sendinput`); a two-finger scroll of «Тачпад» and the desktop
viewer's mouse wheel over Task Manager or Notepad run as administrator must scroll it in steps
(`wheel path` … `hid` with `foreground="Taskmgr.exe"`, `wheel_hid_stepped` in the `cursor sync`
line) and over an ordinary window stay smooth (`wheel path` … `sendinput`, an ordinary window);
without it, holding an on-screen key must repeat
after Windows' delay (`key auto-repeat started` / `stopped`). With the driver, text typed in game
mode must appear in a game's chat (`game text path via="hid"`, `game text typed`), switching between
English and Russian by itself (`keyboard layout switched for game text` with its method), with Caps
Lock on and off; a long line must not stall the video or the camera while it is typed; the Enter
after it must send the whole line; a phone's Enter tap must register. Live checks are separate from
unit tests; do not run the ignored real-input tests unattended.

Wire format references:
[driver declarations](https://github.com/Ryochan7/FakerInput/blob/master/FakerInput/fakerinputcommon.h),
[HID descriptor](https://github.com/Ryochan7/FakerInput/blob/master/FakerInput/Device.c),
[official client](https://github.com/Ryochan7/FakerInputDll/blob/master/FakerInputDll/fakerinputclient.cpp).
