//! The WGC capture session's optional properties, and a start that never fails over one of them.
//!
//! ## Why this exists
//!
//! `GraphicsCaptureSession` grew its knobs one Windows at a time: `IsCursorCaptureEnabled` arrived in
//! Windows 10 2004 (build 19041), `IsBorderRequired` in build 20348 (Windows Server 2022, Windows 11),
//! `IncludeSecondaryWindows` in Windows 11 24H2 (26100). `windows-capture` refuses to start a session
//! at all when it is asked to set one this Windows does not have. Asking for
//! `IsBorderRequired = false` unconditionally makes every Windows 10 capture fail 0.2 s after the
//! offer («Toggling the capture border is not supported by the Graphics Capture API on this
//! platform»), and the viewer gets «Экран недоступен».
//!
//! None of these properties is worth a capture: each only adjusts the picture. So the rule here is
//! that a property is set only where Windows says it has it, and otherwise left to WGC's own default:
//!
//! 1. Before every start, `ApiInformation::IsPropertyPresent` is asked about each property the caller
//!    wants ([`Plan::decide`]). Present: set. Absent, or the question itself failed: left alone.
//! 2. If the capture still refuses one at start (`windows-capture` checks again, the same way), the
//!    start is tried once more without it ([`Plan::after_failure`]) — at most once per property.
//!
//! What leaving each one alone looks like is in [`SessionOption::without_it`]: only the border is a
//! visible difference (a yellow frame around what is captured); WGC's default for the cursor draws it
//! anyway, and its default for secondary windows includes none.
//!
//! `MinUpdateInterval` and `DirtyRegionMode` (both Windows 11 24H2) are never set — pacing is ours
//! (`wgc::start`), and dirty regions are unused — so they are not options here.
//!
//! The decision is plain data in, plain data out, and tested on any machine; the Windows half
//! (asking `ApiInformation`, the build from `RtlGetVersion`, the start loop) is [`start`].

use std::fmt;

/// An optional property of `Windows.Graphics.Capture.GraphicsCaptureSession` the agent sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionOption {
    /// `IsCursorCaptureEnabled = true`: the cursor drawn into the frames.
    Cursor,
    /// `IsBorderRequired = false`: no yellow frame around what is captured.
    NoBorder,
    /// `IncludeSecondaryWindows = false`: no other window composited into a window capture. A
    /// window capture's option; a monitor capture does not ask for it.
    NoSecondaryWindows,
}

impl SessionOption {
    /// Every option, in the order the log names them.
    pub const ALL: [Self; 3] = [Self::Cursor, Self::NoBorder, Self::NoSecondaryWindows];

    /// The session property, as `ApiInformation::IsPropertyPresent` is asked about it.
    #[must_use]
    pub const fn property(self) -> &'static str {
        match self {
            Self::Cursor => "IsCursorCaptureEnabled",
            Self::NoBorder => "IsBorderRequired",
            Self::NoSecondaryWindows => "IncludeSecondaryWindows",
        }
    }

    /// The value it is set to.
    #[must_use]
    pub const fn value(self) -> bool {
        match self {
            Self::Cursor => true,
            Self::NoBorder | Self::NoSecondaryWindows => false,
        }
    }

    /// The first Windows build that has the property (Microsoft's API reference). For the log only:
    /// the decision is what `ApiInformation` answers, never this number.
    #[must_use]
    pub const fn first_build(self) -> u32 {
        match self {
            Self::Cursor => 19_041,
            Self::NoBorder => 20_348,
            Self::NoSecondaryWindows => 26_100,
        }
    }

    /// The log field's name.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Cursor => "cursor",
            Self::NoBorder => "border",
            Self::NoSecondaryWindows => "secondary_windows",
        }
    }

    /// What the setting is for, in a sentence's subject.
    const fn what(self) -> &'static str {
        match self {
            Self::Cursor => "turning cursor capture on",
            Self::NoBorder => "turning the WGC capture border off",
            Self::NoSecondaryWindows => "keeping other windows out of a window capture",
        }
    }

    /// What the capture is when the property is left to WGC's default.
    #[must_use]
    pub const fn without_it(self) -> &'static str {
        match self {
            Self::Cursor => "WGC's default stands, and it draws the cursor into the frames anyway",
            Self::NoBorder => {
                "the capture runs with the yellow border Windows draws around what is captured"
            }
            Self::NoSecondaryWindows => "WGC's default stands, and it includes no other window",
        }
    }

    /// Whether WGC's default looks different from the setting. Only the border does.
    #[must_use]
    pub const fn default_differs(self) -> bool {
        matches!(self, Self::NoBorder)
    }

    const fn index(self) -> usize {
        match self {
            Self::Cursor => 0,
            Self::NoBorder => 1,
            Self::NoSecondaryWindows => 2,
        }
    }
}

/// What `ApiInformation::IsPropertyPresent` answered about one property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    Present,
    Absent,
    /// The question failed: its error.
    Unknown(String),
}

/// Why a wanted option was left to WGC's default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// Windows does not have the property.
    Absent,
    /// Whether it has it could not be asked: the error.
    Unknown(String),
    /// Windows said it has it, and the capture still refused it at start: the start's error.
    Refused(String),
}

/// One wanted option, set or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    Set,
    Default(Skip),
}

/// Which of the wanted options a start sets, and why each one left out is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    choices: Vec<(SessionOption, Choice)>,
}

/// Why a start failed, as far as the optional settings go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartFailure {
    /// The capture refused this option: it found the property missing itself.
    Refused(SessionOption),
    /// Anything else (no WGC at all, no D3D device, the item gone, the handler): not the options'
    /// doing, so not tried again without them.
    Other,
}

impl Plan {
    /// Set each wanted option where Windows has the property, and leave it to WGC's default
    /// otherwise — also when Windows could not say, since a start refused over a property that only
    /// adjusts the picture leaves the viewer on black. `presence` is asked about wanted options only.
    pub fn decide(
        wanted: &[SessionOption],
        mut presence: impl FnMut(SessionOption) -> Presence,
    ) -> Self {
        let mut choices: Vec<(SessionOption, Choice)> = Vec::with_capacity(wanted.len());
        for &option in wanted {
            if choices.iter().any(|(o, _)| *o == option) {
                continue;
            }
            let choice = match presence(option) {
                Presence::Present => Choice::Set,
                Presence::Absent => Choice::Default(Skip::Absent),
                Presence::Unknown(e) => Choice::Default(Skip::Unknown(e)),
            };
            choices.push((option, choice));
        }
        Self { choices }
    }

    /// Whether the start sets `option`.
    #[must_use]
    pub fn sets(&self, option: SessionOption) -> bool {
        self.choice(option) == Some(&Choice::Set)
    }

    /// The choice made for `option`; `None` when it was not wanted.
    #[must_use]
    pub fn choice(&self, option: SessionOption) -> Option<&Choice> {
        self.choices
            .iter()
            .find(|(o, _)| *o == option)
            .map(|(_, c)| c)
    }

    /// The wanted options left to WGC's default, and why.
    pub fn skipped(&self) -> impl Iterator<Item = (SessionOption, &Skip)> {
        self.choices.iter().filter_map(|(o, c)| match c {
            Choice::Default(skip) => Some((*o, skip)),
            Choice::Set => None,
        })
    }

    /// The plan to start again with after a start failed with `failure` (its text `error`): the
    /// refused option left to the default. `None` when there is nothing to leave out — the failure
    /// is not an option's, or the option it names was not set — and the start's error stands.
    #[must_use]
    pub fn after_failure(&self, failure: StartFailure, error: &str) -> Option<Self> {
        let StartFailure::Refused(option) = failure else {
            return None;
        };
        if !self.sets(option) {
            return None;
        }
        let mut next = self.clone();
        for (o, c) in &mut next.choices {
            if *o == option {
                *c = Choice::Default(Skip::Refused(error.to_string()));
            }
        }
        Some(next)
    }

    /// The log field for `option`: `set`, why it is not, or `not used`.
    #[must_use]
    pub fn describe(&self, option: SessionOption) -> String {
        match self.choice(option) {
            None => "not used".to_string(),
            Some(Choice::Set) => format!("set ({} = {})", option.property(), option.value()),
            Some(Choice::Default(skip)) => format!("default ({skip})"),
        }
    }
}

impl fmt::Display for Skip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("absent on this Windows"),
            Self::Unknown(e) => write!(f, "unknown whether present: {e}"),
            Self::Refused(e) => write!(f, "refused at start: {e}"),
        }
    }
}

/// How loud a skipped option's one line per process is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// The picture differs from what was asked (the border shows), or the answer is unexpected.
    Warn,
    /// WGC's default gives the same picture: worth knowing, nothing degraded.
    Info,
}

/// The line logged once per process for an option left to the default, and its level. `build` is
/// this Windows' build number, or why it is unknown.
#[must_use]
pub fn notice(option: SessionOption, skip: &Skip, build: &Result<u32, String>) -> (Level, String) {
    let on = match build {
        Ok(b) => format!("build {b}"),
        Err(e) => format!("build unknown: {e}"),
    };
    let first = option.first_build();
    match skip {
        Skip::Absent => {
            // A build that should have it and does not is a surprise worth a warning either way.
            let unexpected = matches!(build, Ok(b) if *b >= first);
            let level = if unexpected || option.default_differs() {
                Level::Warn
            } else {
                Level::Info
            };
            let since = if unexpected {
                format!("although Windows has had it since build {first}")
            } else {
                format!("it arrived in build {first}")
            };
            (
                level,
                format!(
                    "{} is not possible on this Windows ({on}: {} is absent, {since}): {}",
                    option.what(),
                    option.property(),
                    option.without_it()
                ),
            )
        }
        Skip::Unknown(e) => (
            Level::Warn,
            format!(
                "{}: whether this Windows has {} is unknown ({on}; ApiInformation: {e}), so it is \
                 not set: {}",
                option.what(),
                option.property(),
                option.without_it()
            ),
        ),
        Skip::Refused(e) => (
            Level::Warn,
            format!(
                "{}: the capture refused {} at start although Windows reported it present ({on}; \
                 {e}): {}",
                option.what(),
                option.property(),
                option.without_it()
            ),
        ),
    }
}

#[cfg(windows)]
mod win {
    use std::mem::size_of;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::OnceLock;

    use windows::core::HSTRING;
    use windows::Foundation::Metadata::ApiInformation;
    use windows::Wdk::System::SystemServices::RtlGetVersion;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
    use windows_capture::capture::{
        CaptureControl, GraphicsCaptureApiError, GraphicsCaptureApiHandler,
    };
    use windows_capture::graphics_capture_api::Error as ApiError;
    use windows_capture::settings::{
        CursorCaptureSettings, DrawBorderSettings, GraphicsCaptureItemType,
        SecondaryWindowSettings, Settings,
    };

    use super::{notice, Level, Plan, Presence, SessionOption, Skip, StartFailure};
    use crate::game::error_text;

    type BoxError = Box<dyn std::error::Error + Send + Sync>;

    const SESSION_CLASS: &str = "Windows.Graphics.Capture.GraphicsCaptureSession";

    /// What `windows-capture` is given for a [`Plan`]: each option set, or left to the default.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Resolved {
        pub cursor: CursorCaptureSettings,
        pub border: DrawBorderSettings,
        /// Never `Include`: with it WGC composites other processes' windows into the game's frames
        /// (measured: Telegram and the Snipping Tool's overlay).
        /// `Exclude` where the property exists; `Default` — which includes none — where it does not.
        pub secondary: SecondaryWindowSettings,
    }

    impl Resolved {
        #[must_use]
        pub fn of(plan: &Plan) -> Self {
            Self {
                cursor: if plan.sets(SessionOption::Cursor) {
                    CursorCaptureSettings::WithCursor
                } else {
                    CursorCaptureSettings::Default
                },
                border: if plan.sets(SessionOption::NoBorder) {
                    DrawBorderSettings::WithoutBorder
                } else {
                    DrawBorderSettings::Default
                },
                secondary: if plan.sets(SessionOption::NoSecondaryWindows) {
                    SecondaryWindowSettings::Exclude
                } else {
                    SecondaryWindowSettings::Default
                },
            }
        }
    }

    /// Which failures are an option's: the capture's own "not supported on this platform" for a
    /// property it was asked to set.
    pub(super) fn failure_of<E>(error: &GraphicsCaptureApiError<E>) -> StartFailure {
        match error {
            GraphicsCaptureApiError::GraphicsCaptureApiError(ApiError::CursorConfigUnsupported) => {
                StartFailure::Refused(SessionOption::Cursor)
            }
            GraphicsCaptureApiError::GraphicsCaptureApiError(ApiError::BorderConfigUnsupported) => {
                StartFailure::Refused(SessionOption::NoBorder)
            }
            GraphicsCaptureApiError::GraphicsCaptureApiError(
                ApiError::SecondaryWindowsUnsupported,
            ) => StartFailure::Refused(SessionOption::NoSecondaryWindows),
            _ => StartFailure::Other,
        }
    }

    /// This Windows' build number, from `RtlGetVersion` (which, unlike `GetVersionEx`, does not
    /// answer what the exe's manifest lets it). Read once per process.
    pub fn windows_build() -> Result<u32, String> {
        static BUILD: OnceLock<Result<u32, String>> = OnceLock::new();
        BUILD
            .get_or_init(|| {
                let mut info = OSVERSIONINFOW {
                    dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
                    ..Default::default()
                };
                // SAFETY: a live struct with its size set, as the call requires.
                let status = unsafe { RtlGetVersion(&mut info) };
                if status.is_ok() {
                    tracing::debug!(
                        major = info.dwMajorVersion,
                        minor = info.dwMinorVersion,
                        build = info.dwBuildNumber,
                        "Windows version (RtlGetVersion)"
                    );
                    Ok(info.dwBuildNumber)
                } else {
                    let why = format!("RtlGetVersion: NTSTATUS {:#010x}", status.0 as u32);
                    tracing::warn!("Windows build unknown: {why}");
                    Err(why)
                }
            })
            .clone()
    }

    /// What `ApiInformation` answers about `option`'s property.
    pub(super) fn presence(option: SessionOption) -> Presence {
        match ApiInformation::IsPropertyPresent(
            &HSTRING::from(SESSION_CLASS),
            &HSTRING::from(option.property()),
        ) {
            Ok(true) => Presence::Present,
            Ok(false) => Presence::Absent,
            Err(e) => Presence::Unknown(error_text(&e)),
        }
    }

    /// One flag per option: its skipped line has been logged in this process.
    static NOTICED: [AtomicBool; 3] = [
        AtomicBool::new(false),
        AtomicBool::new(false),
        AtomicBool::new(false),
    ];

    /// The plan, as one debug line per start, and each option left out once per process.
    fn report(what: &str, plan: &Plan, build: &Result<u32, String>, attempt: u32) {
        tracing::debug!(
            what,
            attempt,
            build = %match build {
                Ok(b) => b.to_string(),
                Err(e) => format!("unknown ({e})"),
            },
            cursor = %plan.describe(SessionOption::Cursor),
            border = %plan.describe(SessionOption::NoBorder),
            secondary_windows = %plan.describe(SessionOption::NoSecondaryWindows),
            min_update_interval = "default (never set: pacing is ours)",
            dirty_regions = "default (never set: unused)",
            "WGC session options"
        );
        for (option, skip) in plan.skipped() {
            // A refusal was logged as a warning where it happened, with the start's error.
            if matches!(skip, Skip::Refused(_)) {
                continue;
            }
            if NOTICED[option.index()].swap(true, Ordering::Relaxed) {
                continue;
            }
            let (level, line) = notice(option, skip, build);
            match level {
                Level::Warn => tracing::warn!(what, option = option.key(), "{line}"),
                Level::Info => tracing::info!(what, option = option.key(), "{line}"),
            }
        }
    }

    /// Start a free-threaded WGC capture with each of `wanted` set where this Windows has it.
    ///
    /// `settings` builds the crate's settings for one attempt (the item and the handler's flags are
    /// consumed by each). A start the capture refuses over an option is tried again without it; any
    /// other failure is returned as it came. `what` names the capture in the log.
    pub fn start<H, T>(
        what: &str,
        wanted: &[SessionOption],
        mut settings: impl FnMut(Resolved) -> Settings<H::Flags, T>,
    ) -> Result<CaptureControl<H, BoxError>, GraphicsCaptureApiError<BoxError>>
    where
        H: GraphicsCaptureApiHandler<Error = BoxError> + Send + 'static,
        H::Flags: Send,
        T: TryInto<GraphicsCaptureItemType> + Send + 'static,
    {
        let build = windows_build();
        let mut plan = Plan::decide(wanted, presence);
        let mut attempt = 1u32;
        loop {
            report(what, &plan, &build, attempt);
            match H::start_free_threaded(settings(Resolved::of(&plan))) {
                Ok(control) => {
                    tracing::debug!(what, attempt, "WGC capture session started");
                    return Ok(control);
                }
                Err(e) => {
                    let text = e.to_string();
                    let Some(next) = plan.after_failure(failure_of(&e), &text) else {
                        return Err(e);
                    };
                    let refused: Vec<&str> = next
                        .skipped()
                        .filter(|(_, s)| matches!(s, Skip::Refused(_)))
                        .map(|(o, _)| o.property())
                        .collect();
                    tracing::warn!(
                        what,
                        attempt,
                        error = %text,
                        left_to_default = ?refused,
                        "WGC capture refused an optional session setting that Windows reported \
                         present; starting again without it"
                    );
                    plan = next;
                    attempt += 1;
                }
            }
        }
    }
}

#[cfg(windows)]
pub use win::{start, windows_build, Resolved};

#[cfg(test)]
mod tests {
    use super::SessionOption::{Cursor, NoBorder, NoSecondaryWindows};
    use super::*;

    /// What `ApiInformation` answers about `[IsCursorCaptureEnabled, IsBorderRequired,
    /// IncludeSecondaryWindows]` on each Windows (Microsoft's API reference).
    const WINDOWS: [(&str, u32, [bool; 3]); 7] = [
        ("Windows 10 1909", 18_363, [false, false, false]),
        ("Windows 10 22H2", 19_045, [true, false, false]),
        ("Windows Server 2022", 20_348, [true, true, false]),
        ("Windows 11 21H2", 22_000, [true, true, false]),
        ("Windows 11 22H2", 22_621, [true, true, false]),
        ("Windows 11 23H2", 22_631, [true, true, false]),
        ("Windows 11 24H2", 26_100, [true, true, true]),
    ];

    const MONITOR: [SessionOption; 2] = [Cursor, NoBorder];

    fn answers(present: [bool; 3]) -> impl FnMut(SessionOption) -> Presence {
        move |o| {
            if present[o.index()] {
                Presence::Present
            } else {
                Presence::Absent
            }
        }
    }

    fn on(build: u32) -> Plan {
        let (_, _, present) = WINDOWS
            .iter()
            .find(|(_, b, _)| *b == build)
            .copied()
            .unwrap_or_else(|| unreachable!("build {build} is not in the table"));
        Plan::decide(&SessionOption::ALL, answers(present))
    }

    #[test]
    fn windows_10_22h2_captures_with_the_border_instead_of_failing() {
        // Windows 10 22H2 (build 19045) has the cursor property and not the border's.
        let plan = Plan::decide(&MONITOR, answers([true, false, false]));
        assert!(plan.sets(Cursor));
        assert!(!plan.sets(NoBorder), "the border is left to WGC's default");
        assert_eq!(plan.choice(NoBorder), Some(&Choice::Default(Skip::Absent)));
        assert_eq!(
            plan.choice(NoSecondaryWindows),
            None,
            "a monitor does not ask"
        );

        let game = on(19_045);
        assert!(game.sets(Cursor));
        assert!(!game.sets(NoBorder));
        assert!(!game.sets(NoSecondaryWindows));
    }

    #[test]
    fn windows_11_before_24h2_turns_the_border_off_and_leaves_secondary_windows() {
        for build in [22_000, 22_621, 22_631, 20_348] {
            let plan = on(build);
            assert!(plan.sets(Cursor), "build {build}");
            assert!(plan.sets(NoBorder), "build {build}");
            assert_eq!(
                plan.choice(NoSecondaryWindows),
                Some(&Choice::Default(Skip::Absent)),
                "build {build}"
            );
        }
    }

    #[test]
    fn windows_11_24h2_sets_everything() {
        let plan = on(26_100);
        for option in SessionOption::ALL {
            assert!(plan.sets(option), "{option:?}");
        }
        assert_eq!(plan.skipped().count(), 0);
    }

    #[test]
    fn windows_10_1909_sets_nothing_and_still_starts() {
        let plan = on(18_363);
        assert_eq!(plan.skipped().count(), 3);
        for option in SessionOption::ALL {
            assert!(!plan.sets(option), "{option:?}");
        }
    }

    #[test]
    fn the_first_builds_in_the_log_agree_with_the_table() {
        for (name, build, present) in WINDOWS {
            for option in SessionOption::ALL {
                assert_eq!(
                    build >= option.first_build(),
                    present[option.index()],
                    "{name} ({build}), {}",
                    option.property()
                );
            }
        }
    }

    #[test]
    fn an_unanswered_question_leaves_that_option_alone_and_no_other() {
        let plan = Plan::decide(&SessionOption::ALL, |o| match o {
            NoBorder => Presence::Unknown("0x80004005 Unspecified error".into()),
            _ => Presence::Present,
        });
        assert!(plan.sets(Cursor));
        assert!(plan.sets(NoSecondaryWindows));
        assert_eq!(
            plan.choice(NoBorder),
            Some(&Choice::Default(Skip::Unknown(
                "0x80004005 Unspecified error".into()
            )))
        );
    }

    #[test]
    fn only_wanted_options_are_asked_about_once_each() {
        let mut asked = Vec::new();
        let plan = Plan::decide(&[Cursor, NoBorder, Cursor], |o| {
            asked.push(o);
            Presence::Present
        });
        assert_eq!(asked, vec![Cursor, NoBorder]);
        assert_eq!(plan.describe(NoSecondaryWindows), "not used");
    }

    #[test]
    fn a_refused_option_is_dropped_and_the_rest_kept() {
        let plan = on(26_100);
        let error = "Graphics capture error: Toggling the capture border is not supported by the \
                     Graphics Capture API on this platform.";
        let next = plan
            .after_failure(StartFailure::Refused(NoBorder), error)
            .unwrap_or_else(|| unreachable!("the border was set, so there is a retry"));
        assert!(next.sets(Cursor));
        assert!(next.sets(NoSecondaryWindows));
        assert_eq!(
            next.choice(NoBorder),
            Some(&Choice::Default(Skip::Refused(error.into())))
        );
        // The same refusal again has nothing left to drop: the error stands.
        assert_eq!(
            next.after_failure(StartFailure::Refused(NoBorder), error),
            None
        );
    }

    #[test]
    fn other_failures_are_not_retried() {
        let plan = on(26_100);
        assert_eq!(
            plan.after_failure(StartFailure::Other, "no D3D device"),
            None
        );
        let none_set = on(18_363);
        assert_eq!(
            none_set.after_failure(StartFailure::Refused(Cursor), "refused"),
            None,
            "an option that was not set cannot be what was refused"
        );
    }

    #[test]
    fn retries_end_once_every_option_is_left_out() {
        let mut plan = on(26_100);
        let mut retries = 0;
        for option in SessionOption::ALL {
            plan = plan
                .after_failure(StartFailure::Refused(option), "refused")
                .unwrap_or_else(|| unreachable!("{option:?} was set"));
            retries += 1;
        }
        assert_eq!(retries, 3);
        for option in SessionOption::ALL {
            assert_eq!(
                plan.after_failure(StartFailure::Refused(option), "refused"),
                None
            );
        }
    }

    #[test]
    fn the_border_left_on_is_a_warning_naming_the_build() {
        let (level, line) = notice(NoBorder, &Skip::Absent, &Ok(19_045));
        assert_eq!(level, Level::Warn);
        assert!(line.contains("build 19045"), "{line}");
        assert!(line.contains("IsBorderRequired is absent"), "{line}");
        assert!(line.contains("yellow border"), "{line}");
    }

    #[test]
    fn an_absent_property_whose_default_looks_the_same_is_info() {
        let (level, line) = notice(Cursor, &Skip::Absent, &Ok(18_363));
        assert_eq!(level, Level::Info, "{line}");
        let (level, line) = notice(NoSecondaryWindows, &Skip::Absent, &Ok(19_045));
        assert_eq!(level, Level::Info, "{line}");
    }

    #[test]
    fn a_property_missing_where_it_should_be_is_a_warning() {
        let (level, line) = notice(NoSecondaryWindows, &Skip::Absent, &Ok(26_100));
        assert_eq!(level, Level::Warn);
        assert!(
            line.contains("although Windows has had it since build 26100"),
            "{line}"
        );
    }

    #[test]
    fn unknown_answers_and_refusals_are_warnings_with_their_errors() {
        let build = Err("RtlGetVersion: NTSTATUS 0xc0000001".to_string());
        let (level, line) = notice(Cursor, &Skip::Unknown("0x80004005".into()), &build);
        assert_eq!(level, Level::Warn);
        assert!(line.contains("0x80004005"), "{line}");
        assert!(line.contains("build unknown"), "{line}");
        let (level, line) = notice(NoBorder, &Skip::Refused("no".into()), &Ok(22_631));
        assert_eq!(level, Level::Warn);
        assert!(line.contains("refused"), "{line}");
    }

    #[cfg(windows)]
    mod windows_capture_errors {
        use windows_capture::capture::GraphicsCaptureApiError;
        use windows_capture::graphics_capture_api::Error as ApiError;
        use windows_capture::settings::{
            CursorCaptureSettings, DrawBorderSettings, SecondaryWindowSettings,
        };

        use super::super::win::{failure_of, presence};
        use super::super::*;
        use super::{on, MONITOR};

        type BoxError = Box<dyn std::error::Error + Send + Sync>;

        fn api(e: ApiError) -> GraphicsCaptureApiError<BoxError> {
            GraphicsCaptureApiError::GraphicsCaptureApiError(e)
        }

        #[test]
        fn the_border_error_from_windows_10_leads_to_a_start_without_the_border() {
            // The error `windows-capture` returns on Windows 10 for a border it cannot toggle.
            let error = api(ApiError::BorderConfigUnsupported);
            assert_eq!(
                error.to_string(),
                "Graphics capture error: Toggling the capture border is not supported by the \
                 Graphics Capture API on this platform."
            );
            assert_eq!(
                failure_of(&error),
                StartFailure::Refused(SessionOption::NoBorder)
            );

            // Say ApiInformation had answered "present" and the crate disagreed.
            let plan = Plan::decide(&MONITOR, |_| Presence::Present);
            assert_eq!(
                Resolved::of(&plan).border,
                DrawBorderSettings::WithoutBorder
            );
            let retry = plan
                .after_failure(failure_of(&error), &error.to_string())
                .unwrap_or_else(|| unreachable!("the border was set"));
            let settings = Resolved::of(&retry);
            assert_eq!(settings.border, DrawBorderSettings::Default);
            assert_eq!(settings.cursor, CursorCaptureSettings::WithCursor);
        }

        #[test]
        fn each_option_error_names_its_option_and_nothing_else_is_an_options() {
            assert_eq!(
                failure_of(&api(ApiError::CursorConfigUnsupported)),
                StartFailure::Refused(SessionOption::Cursor)
            );
            assert_eq!(
                failure_of(&api(ApiError::SecondaryWindowsUnsupported)),
                StartFailure::Refused(SessionOption::NoSecondaryWindows)
            );
            for other in [
                api(ApiError::Unsupported),
                api(ApiError::MinimumUpdateIntervalUnsupported),
                api(ApiError::DirtyRegionUnsupported),
                api(ApiError::AlreadyStarted),
                GraphicsCaptureApiError::ItemConvertFailed,
                GraphicsCaptureApiError::FailedToInitWinRT,
            ] {
                assert_eq!(failure_of(&other), StartFailure::Other, "{other}");
            }
        }

        #[test]
        fn secondary_windows_are_never_included() {
            for build in [18_363, 19_045, 22_000, 22_621, 26_100] {
                let settings = Resolved::of(&on(build));
                assert_ne!(
                    settings.secondary,
                    SecondaryWindowSettings::Include,
                    "build {build}"
                );
            }
            assert_eq!(
                Resolved::of(&on(26_100)).secondary,
                SecondaryWindowSettings::Exclude,
                "set explicitly off where Windows has the property"
            );
        }

        #[test]
        fn what_each_windows_gets() {
            let monitor_19045 = Resolved::of(&Plan::decide(&MONITOR, |o| match o {
                SessionOption::Cursor => Presence::Present,
                _ => Presence::Absent,
            }));
            assert_eq!(monitor_19045.cursor, CursorCaptureSettings::WithCursor);
            assert_eq!(monitor_19045.border, DrawBorderSettings::Default);
            assert_eq!(monitor_19045.secondary, SecondaryWindowSettings::Default);

            let game_22621 = Resolved::of(&on(22_621));
            assert_eq!(game_22621.cursor, CursorCaptureSettings::WithCursor);
            assert_eq!(game_22621.border, DrawBorderSettings::WithoutBorder);
            assert_eq!(game_22621.secondary, SecondaryWindowSettings::Default);

            let old = Resolved::of(&on(18_363));
            assert_eq!(old.cursor, CursorCaptureSettings::Default);
            assert_eq!(old.border, DrawBorderSettings::Default);
        }

        /// This machine's own answers, through the same calls a start makes: the build is read,
        /// every question is answered, and each answer agrees with the build.
        #[test]
        fn this_machine() {
            let build = windows_build();
            let Ok(build) = build else {
                unreachable!("RtlGetVersion failed: {build:?}");
            };
            for option in SessionOption::ALL {
                let answer = presence(option);
                let expected = if build >= option.first_build() {
                    Presence::Present
                } else {
                    Presence::Absent
                };
                assert_eq!(answer, expected, "build {build}: {}", option.property());
            }
        }
    }
}
