//! The dialog's three steps, moved by what really happens — never by a timer.
//!
//! Each operation shows three steps (`app.fakerInputStep*` in the contract): install
//! «Разрешение Windows» → «Установка» → «Запуск», removal «Разрешение Windows» → «Удаление» →
//! «Проверка», reinstall «Удаление» → «Установка» → «Запуск» (a UAC prompt inside each of the first
//! two). The backend knows where it is ([`Phase`]); [`steps`] turns that into what each step shows,
//! and [`Progress`] sends every change to the window as the Tauri event [`PROGRESS_EVENT`] and logs
//! it. The command's answer ([`MaintenanceReport`]) carries the final steps as well, so the
//! dialog's last picture never depends on an event arriving before the answer.
//!
//! Where each phase comes from:
//!
//! - [`Phase::Consent`] — from the moment a msiexec run is being started (its package is unpacked
//!   first, milliseconds) until its log shows Windows Installer past the UAC consent;
//! - [`Phase::Working`] — that line was seen (`msi_log`): Windows Installer works with the rights it
//!   was given;
//! - [`Phase::Unobserved`] — the log cannot be read, so consent and work cannot be told apart: both
//!   steps show as running together until msiexec exits (honest, not a guess);
//! - [`Phase::Device`] — msiexec succeeded; the app polls for the device to appear (install) or to
//!   go (removal), up to 10 s. An install whose device does not appear ends
//!   [`MaintenanceOutcome::DeviceMissing`]: this step is marked where it stopped, never ✓.

use serde::Serialize;
use std::time::Instant;

use super::{Maintenance, MaintenanceOutcome, MsiOperation};

/// The Tauri event the dialog listens to while an operation runs; its payload is [`ProgressDto`].
pub(crate) const PROGRESS_EVENT: &str = "fakerinput-progress";

/// What one step shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    /// Not reached yet.
    Pending,
    /// Happening now (the spinner).
    Active,
    /// Finished (✓).
    Done,
    /// The operation ended here without finishing it: cancelled, refused, failed, the device not
    /// appearing, or waiting for a restart. Only in a final picture.
    Stopped,
}

/// The operation's three steps, in order.
pub type Steps = [StepState; 3];

/// Where an operation is, as the backend knows it. Each carries the msiexec run it belongs to: a
/// reinstall has two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "Working and Unobserved come from msiexec's log, on Windows only"
    )
)]
pub(super) enum Phase {
    /// The run is being started, or waits for the owner's answer to the UAC prompt.
    Consent(MsiOperation),
    /// Its log shows Windows Installer past the consent, at work.
    Working(MsiOperation),
    /// Its log cannot be read: consent and work go together until msiexec exits.
    Unobserved(MsiOperation),
    /// msiexec succeeded; waiting for the device to appear (install) or go (removal).
    Device(MsiOperation),
}

impl Phase {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Consent(_) => "consent",
            Self::Working(_) => "working",
            Self::Unobserved(_) => "consent_or_working",
            Self::Device(_) => "device",
        }
    }

    fn msi(self) -> MsiOperation {
        match self {
            Self::Consent(msi) | Self::Working(msi) | Self::Unobserved(msi) | Self::Device(msi) => {
                msi
            }
        }
    }
}

/// What the three steps show while `op` is at `phase` (`None`: nothing has started yet).
pub(super) fn steps(op: Maintenance, phase: Option<Phase>) -> Steps {
    use StepState::{Active as A, Done as D, Pending as P};
    let Some(phase) = phase else {
        return [P, P, P];
    };
    match op {
        // One msiexec run: consent, the run itself, the device.
        Maintenance::Install | Maintenance::Remove => match phase {
            Phase::Consent(_) => [A, P, P],
            Phase::Unobserved(_) => [A, A, P],
            Phase::Working(_) => [D, A, P],
            Phase::Device(_) => [D, D, A],
        },
        // Two runs, each with its own prompt inside its step: «Удаление» is the whole removal (the
        // wait for the device to go included), «Установка» the install's run, «Запуск» the
        // device.
        Maintenance::Reinstall => match (phase, phase.msi()) {
            (_, MsiOperation::Uninstall) => [A, P, P],
            (Phase::Device(_), MsiOperation::Install) => [D, D, A],
            (_, MsiOperation::Install) => [D, A, P],
        },
    }
}

/// The final picture: all done on success; otherwise the step(s) running when it ended are marked
/// where it stopped — or, when nothing had started, the first.
pub(super) fn final_steps(
    op: Maintenance,
    phase: Option<Phase>,
    outcome: MaintenanceOutcome,
) -> Steps {
    if outcome == MaintenanceOutcome::Done {
        return [StepState::Done; 3];
    }
    let mut steps = steps(op, phase);
    let mut marked = false;
    for step in &mut steps {
        if *step == StepState::Active {
            *step = StepState::Stopped;
            marked = true;
        }
    }
    if !marked {
        if let Some(step) = steps.iter_mut().find(|s| **s == StepState::Pending) {
            *step = StepState::Stopped;
        }
    }
    steps
}

/// The event's payload: which operation, and its three steps now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProgressDto {
    /// `install`, `remove` or `reinstall`, as the window names its actions.
    pub operation: &'static str,
    pub steps: Steps,
}

/// The command's answer once an operation has run: how it ended and the final steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MaintenanceReport {
    pub outcome: MaintenanceOutcome,
    pub steps: Steps,
}

/// Where one operation is: every change logged at `info` and sent to the window.
pub(super) struct Progress {
    op: Maintenance,
    started: Instant,
    phase: Option<Phase>,
    sink: Box<dyn FnMut(&ProgressDto) + Send>,
}

impl Progress {
    /// `sink` delivers each change to the window (and logs its own failures).
    pub(super) fn new(op: Maintenance, sink: impl FnMut(&ProgressDto) + Send + 'static) -> Self {
        Self {
            op,
            started: Instant::now(),
            phase: None,
            sink: Box::new(sink),
        }
    }

    /// Move to `phase`; the same phase again changes nothing.
    pub(super) fn enter(&mut self, phase: Phase) {
        if self.phase == Some(phase) {
            return;
        }
        let from = self.phase.map_or("-", Phase::name);
        self.phase = Some(phase);
        let steps = steps(self.op, self.phase);
        tracing::info!(
            operation = self.op.name(),
            msi = phase.msi().name(),
            from,
            phase = phase.name(),
            elapsed_ms = elapsed_ms(self.started),
            steps = ?steps,
            "FakerInput maintenance phase"
        );
        (self.sink)(&ProgressDto {
            operation: self.op.name(),
            steps,
        });
    }

    #[cfg(test)]
    pub(super) fn phase(&self) -> Option<Phase> {
        self.phase
    }

    /// The command's answer. An operation that started and then failed is a report too (`failed`,
    /// the step where it stopped marked); one refused before anything started stays an `Err`.
    pub(super) fn report(
        self,
        result: Result<MaintenanceOutcome, String>,
    ) -> Result<MaintenanceReport, String> {
        let elapsed_ms = elapsed_ms(self.started);
        let phase = self.phase.map_or("-", Phase::name);
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) if self.phase.is_some() => {
                tracing::warn!(
                    operation = self.op.name(),
                    phase,
                    elapsed_ms,
                    %error,
                    "FakerInput maintenance failed after it started"
                );
                MaintenanceOutcome::Failed
            }
            Err(error) => {
                tracing::debug!(
                    operation = self.op.name(),
                    %error,
                    "FakerInput maintenance refused before any step started"
                );
                return Err(error);
            }
        };
        let steps = final_steps(self.op, self.phase, outcome);
        tracing::debug!(
            operation = self.op.name(),
            ?outcome,
            phase,
            elapsed_ms,
            steps = ?steps,
            "FakerInput maintenance: the dialog's final steps"
        );
        Ok(MaintenanceReport { outcome, steps })
    }
}

fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use MsiOperation::{Install as I, Uninstall as U};
    use StepState::{Active as A, Done as D, Pending as P, Stopped as S};

    #[test]
    fn install_and_remove_walk_consent_work_device() {
        for (op, msi) in [(Maintenance::Install, I), (Maintenance::Remove, U)] {
            assert_eq!(steps(op, None), [P, P, P], "{op:?}");
            assert_eq!(steps(op, Some(Phase::Consent(msi))), [A, P, P], "{op:?}");
            assert_eq!(steps(op, Some(Phase::Working(msi))), [D, A, P], "{op:?}");
            // An unreadable log: the first two steps run together, neither is claimed done.
            assert_eq!(steps(op, Some(Phase::Unobserved(msi))), [A, A, P], "{op:?}");
            assert_eq!(steps(op, Some(Phase::Device(msi))), [D, D, A], "{op:?}");
        }
    }

    #[test]
    fn reinstall_keeps_each_prompt_inside_its_step() {
        let op = Maintenance::Reinstall;
        // The whole removal, its device wait included, is «Удаление».
        for phase in [
            Phase::Consent(U),
            Phase::Working(U),
            Phase::Unobserved(U),
            Phase::Device(U),
        ] {
            assert_eq!(steps(op, Some(phase)), [A, P, P], "{phase:?}");
        }
        for phase in [Phase::Consent(I), Phase::Working(I), Phase::Unobserved(I)] {
            assert_eq!(steps(op, Some(phase)), [D, A, P], "{phase:?}");
        }
        assert_eq!(steps(op, Some(Phase::Device(I))), [D, D, A]);
    }

    #[test]
    fn every_outcome_marks_where_it_stopped() {
        use MaintenanceOutcome::{
            Cancelled, DeviceMissing, Done, Failed, InstallerBusy, RestartRequired,
        };
        use Phase::{Consent, Device, Unobserved, Working};
        let [ins, rem, re] = [
            Maintenance::Install,
            Maintenance::Remove,
            Maintenance::Reinstall,
        ];
        let cases: &[(Maintenance, Option<Phase>, MaintenanceOutcome, Steps)] = &[
            // Success: all done, whatever the last phase was.
            (ins, Some(Device(I)), Done, [D, D, D]),
            (rem, Some(Device(U)), Done, [D, D, D]),
            (re, Some(Device(I)), Done, [D, D, D]),
            // UAC declined (1602) or refused by policy (1625): the permission step.
            (ins, Some(Consent(I)), Cancelled, [S, P, P]),
            (rem, Some(Consent(U)), Cancelled, [S, P, P]),
            // Declined with the log unreadable: both steps that ran together.
            (ins, Some(Unobserved(I)), Cancelled, [S, S, P]),
            // Another installation running (1618): msiexec ends before any consent.
            (ins, Some(Consent(I)), InstallerBusy, [S, P, P]),
            (rem, Some(Consent(U)), InstallerBusy, [S, P, P]),
            // msiexec failed at work.
            (ins, Some(Working(I)), Failed, [D, S, P]),
            (rem, Some(Working(U)), Failed, [D, S, P]),
            // 3010 from msiexec: the run itself needs the restart.
            (ins, Some(Working(I)), RestartRequired, [D, S, P]),
            (rem, Some(Working(U)), RestartRequired, [D, S, P]),
            // Removed, but the device is still there after the wait: the check needs the restart.
            (rem, Some(Device(U)), RestartRequired, [D, D, S]),
            // Installed, but the device never appeared: «Запуск» is where it stopped — for
            // an install and for a reinstall's second half alike.
            (ins, Some(Device(I)), DeviceMissing, [D, D, S]),
            (re, Some(Device(I)), DeviceMissing, [D, D, S]),
            // Reinstall: the first prompt declined, the removal needing a restart, the second
            // prompt declined, the embedded package failing to unpack, another installation.
            (re, Some(Consent(U)), Cancelled, [S, P, P]),
            (re, Some(Device(U)), RestartRequired, [S, P, P]),
            (re, Some(Working(U)), RestartRequired, [S, P, P]),
            (re, Some(Consent(I)), Cancelled, [D, S, P]),
            (re, Some(Consent(I)), Failed, [D, S, P]),
            (re, Some(Working(I)), InstallerBusy, [D, S, P]),
            // Nothing started: the first step.
            (ins, None, Failed, [S, P, P]),
            (re, None, Cancelled, [S, P, P]),
        ];
        for &(op, phase, outcome, want) in cases {
            assert_eq!(
                final_steps(op, phase, outcome),
                want,
                "{op:?} {phase:?} {outcome:?}"
            );
        }
    }

    type Sent = Arc<Mutex<Vec<ProgressDto>>>;

    fn recording(op: Maintenance) -> (Progress, Sent) {
        let sent: Sent = Arc::default();
        let sink = Arc::clone(&sent);
        let progress = Progress::new(op, move |dto: &ProgressDto| {
            sink.lock().unwrap().push(dto.clone());
        });
        (progress, sent)
    }

    #[test]
    fn each_change_is_sent_once() {
        let (mut progress, sent) = recording(Maintenance::Install);
        progress.enter(Phase::Consent(I));
        // The watch can report the same thing twice; the window hears it once.
        progress.enter(Phase::Consent(I));
        progress.enter(Phase::Working(I));
        progress.enter(Phase::Device(I));
        assert_eq!(progress.phase(), Some(Phase::Device(I)));
        let sent = sent.lock().unwrap();
        let pictures: Vec<Steps> = sent.iter().map(|d| d.steps).collect();
        assert_eq!(pictures, vec![[A, P, P], [D, A, P], [D, D, A]]);
        assert!(sent.iter().all(|d| d.operation == "install"));
    }

    #[test]
    fn a_failure_after_the_start_is_a_report_a_refusal_is_not() {
        let (mut started, _) = recording(Maintenance::Remove);
        started.enter(Phase::Consent(U));
        started.enter(Phase::Working(U));
        assert_eq!(
            started.report(Err("msiexec exit 1603".into())),
            Ok(MaintenanceReport {
                outcome: MaintenanceOutcome::Failed,
                steps: [D, S, P],
            })
        );

        let (refused, sent) = recording(Maintenance::Install);
        assert_eq!(
            refused.report(Err("install refused".into())),
            Err("install refused".to_owned())
        );
        assert!(sent.lock().unwrap().is_empty());

        let (mut done, _) = recording(Maintenance::Reinstall);
        done.enter(Phase::Device(I));
        assert_eq!(
            done.report(Ok(MaintenanceOutcome::Done)),
            Ok(MaintenanceReport {
                outcome: MaintenanceOutcome::Done,
                steps: [D, D, D],
            })
        );
    }

    #[test]
    fn a_device_that_does_not_appear_is_never_done() {
        // Install: consent, the run, then the wait for the device — which ends without it.
        let (mut install, sent) = recording(Maintenance::Install);
        for phase in [Phase::Consent(I), Phase::Working(I), Phase::Device(I)] {
            install.enter(phase);
        }
        assert_eq!(
            install.report(Ok(MaintenanceOutcome::DeviceMissing)),
            Ok(MaintenanceReport {
                outcome: MaintenanceOutcome::DeviceMissing,
                steps: [D, D, S],
            })
        );
        // No step was ever claimed done that was not: the last picture sent had step 3 running.
        assert_eq!(
            sent.lock().unwrap().last().map(|d| d.steps),
            Some([D, D, A])
        );

        // Reinstall: the removal went through, the install too, the device did not come.
        let (mut reinstall, _) = recording(Maintenance::Reinstall);
        for phase in [
            Phase::Consent(U),
            Phase::Working(U),
            Phase::Device(U),
            Phase::Consent(I),
            Phase::Working(I),
            Phase::Device(I),
        ] {
            reinstall.enter(phase);
        }
        assert_eq!(
            reinstall.report(Ok(MaintenanceOutcome::DeviceMissing)),
            Ok(MaintenanceReport {
                outcome: MaintenanceOutcome::DeviceMissing,
                steps: [D, D, S],
            })
        );
    }

    #[test]
    fn the_window_gets_the_shapes_it_expects() {
        assert_eq!(
            serde_json::to_value(ProgressDto {
                operation: "reinstall",
                steps: [D, A, P],
            })
            .unwrap(),
            serde_json::json!({ "operation": "reinstall", "steps": ["done", "active", "pending"] })
        );
        assert_eq!(
            serde_json::to_value(MaintenanceReport {
                outcome: MaintenanceOutcome::Cancelled,
                steps: [S, P, P],
            })
            .unwrap(),
            serde_json::json!({ "outcome": "cancelled", "steps": ["stopped", "pending", "pending"] })
        );
    }
}
