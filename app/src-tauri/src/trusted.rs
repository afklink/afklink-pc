//! The window's trusted devices (device keys, milestone 1): the commands of the IPC contract and
//! their DTOs, mapped from the orchestrator's published view (`afklink_core::trusted`).
//!
//! `get_trusted` reads the view the orchestrator last published and never waits on it; the
//! changes (mode, remove, remove person, confirm, repair, and §10.2's allow / hide of another
//! device's attempt) go to the orchestrator as `AgentCommand::Trusted` and wait for its answer at most
//! `afklink_core::trusted::REPLY_LIMIT` (`slow` past it: the change goes on and the view moves
//! when it lands — `trusted_rev` in the status says so).
//!
//! # Threads
//!
//! Every command is `async` on Tauri's runtime: it copies the `AgentControl` out of managed state,
//! reads a `watch` channel (no lock held across anything) or sends on the orchestrator's channel and
//! awaits a `oneshot` with a timeout. No window, tray or file call; nothing blocking.
//!
//! # Logs
//!
//! `debug` for every decision and refusal (the command, its outcome code); a key by its first
//! 8 characters only (`KeyId::short`), never in full, and no names.

use serde::Serialize;
use tauri::State;

use afklink_core::trusted::{
    DeviceRef, RepairAction, TrustedAsk, TrustedAttempt, TrustedDeviceView, TrustedError,
    TrustedView,
};
use afklink_core::viewer_keys::{DamageKind, KeyId, KEY_ID_SHORT_LEN};
use afklink_core::{AgentControl, BindingRole};

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedDto {
    /// `"ok"` | `"damaged"`.
    state: &'static str,
    damage: Option<TrustedDamageDto>,
    trusted_mode: bool,
    people: Vec<TrustedPersonDto>,
    waiting: Vec<i64>,
    /// Where the owner's own device stands for the switch (§10.2): `"ready"` — «Включить» may
    /// go on; `"needs_confirm"` — «Подтвердить» the owner's device first; `"needs_device"` — add
    /// one at the PC first.
    owner_device: &'static str,
    clean: bool,
    /// The window token: the epoch, as a decimal string.
    token: String,
    full: bool,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedDamageDto {
    /// `"unreadable"` | `"corrupt"` | `"newer_version"`.
    reason: &'static str,
    can_restore: bool,
    can_reset: bool,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedPersonDto {
    telegram_user_id: i64,
    first_name: Option<String>,
    username: Option<String>,
    devices: Vec<TrustedDeviceDto>,
    /// Devices this PC does not know that tried to get in as this person (spec §10.2), newest
    /// first: «Разрешить» / «Скрыть», and the confirm dialog's warning.
    attempts: Vec<TrustedAttemptDto>,
    /// `"owner"` | `"guest"`: the role of the person's own keys on this PC (none: guest) — what
    /// «Разрешить» gives.
    role: &'static str,
    /// «Разрешить» needs the owner's explicit second step (the owner by bindings or keys).
    needs_second_step: bool,
}

/// Another device's attempt (§10.2).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedAttemptDto {
    #[serde(flatten)]
    device: TrustedDeviceRefDto,
    /// In full, for the IPC only (`attempt_allow`, `attempt_hide`).
    key_id: String,
    /// Its first 8 characters.
    key_short: String,
    /// How many times it tried.
    count: u32,
    /// Unix ms, the PC's clock: the first and the latest try.
    first_at: i64,
    last_at: i64,
    /// The latest try again (`last_at`), the field the confirm dialog read before.
    at: i64,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedDeviceRefDto {
    /// `"telegram"` | `"telegram_desktop"` | `"browser"`; `None` for a value this build does not know.
    kind: Option<&'static str>,
    /// The raw value the list keeps.
    platform: Option<String>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedDeviceDto {
    #[serde(flatten)]
    device: TrustedDeviceRefDto,
    /// In full, for the IPC only.
    key_id: String,
    /// Its first 8 characters (§10.1, the confirm dialog).
    key_short: String,
    /// `"owner"` | `"guest"`.
    role: &'static str,
    /// `"pairing"` | `"endorsed"` | `"owner"` | `"restored"` | `"migrated"`.
    source: &'static str,
    by: Option<TrustedDeviceRefDto>,
    by_key_id: Option<String>,
    unconfirmed: bool,
    dependents: u32,
    added_at: i64,
    last_used_at: Option<i64>,
    in_session: bool,
}

/// The contract's name for a list's damage: an unreadable file, one a newer agent wrote, or one
/// whose content is broken (everything else).
fn damage_reason(kind: DamageKind) -> &'static str {
    match kind {
        DamageKind::Unreadable => "unreadable",
        DamageKind::NewerVersion => "newer_version",
        DamageKind::TooLarge
        | DamageKind::NotParsable
        | DamageKind::BadVersion
        | DamageKind::Invariant
        | DamageKind::PrimaryMissing => "corrupt",
    }
}

/// The contract's name for how a key got in, from the list's (`KeySource::as_str`).
pub(crate) fn source_name(source: &str) -> &'static str {
    match source {
        "pair" => "pairing",
        "endorse" => "endorsed",
        "grant" => "owner",
        "recover" => "restored",
        "first_use" => "migrated",
        other => {
            tracing::debug!(
                source = other,
                "trusted devices: a source this window build does not name; shown as a pairing"
            );
            "pairing"
        }
    }
}

fn device_ref(d: &DeviceRef) -> TrustedDeviceRefDto {
    device_ref_raw(d.kind.as_str(), d.platform.as_str())
}

/// A device by its key card's raw `kind` and `platform` (the pairing request window's too).
pub(crate) fn device_ref_raw(kind: &str, platform: &str) -> TrustedDeviceRefDto {
    TrustedDeviceRefDto {
        // Display only: a value this build does not know is shown as unknown.
        kind: match kind {
            "telegram" => Some("telegram"),
            "telegram_desktop" => Some("telegram_desktop"),
            "browser" => Some("browser"),
            _ => None,
        },
        platform: Some(platform.to_string()),
    }
}

fn key_short(key_id: &KeyId) -> String {
    key_id.as_str().chars().take(KEY_ID_SHORT_LEN).collect()
}

fn device_dto(d: &TrustedDeviceView) -> TrustedDeviceDto {
    TrustedDeviceDto {
        device: device_ref(&d.device),
        key_id: d.key_id.as_str().to_string(),
        key_short: key_short(&d.key_id),
        role: role_name(d.role),
        source: source_name(d.source),
        by: d.by.as_ref().map(device_ref),
        by_key_id: d.by_key_id.as_ref().map(|k| k.as_str().to_string()),
        unconfirmed: d.unconfirmed,
        dependents: u32::try_from(d.dependents).unwrap_or(u32::MAX),
        added_at: d.added_at,
        last_used_at: d.last_used_at,
        in_session: d.in_session,
    }
}

fn attempt_dto(a: &TrustedAttempt) -> TrustedAttemptDto {
    TrustedAttemptDto {
        device: device_ref(&a.device),
        key_id: a.key_id.as_str().to_string(),
        key_short: key_short(&a.key_id),
        count: a.count,
        first_at: a.first_at_ms,
        last_at: a.last_at_ms,
        at: a.last_at_ms,
    }
}

const fn role_name(role: BindingRole) -> &'static str {
    match role {
        BindingRole::Owner => "owner",
        BindingRole::Guest => "guest",
    }
}

/// `in_session` on each device a live session is signed with (`live`: full key ids).
fn mark_live(dto: &mut TrustedDto, live: &std::collections::BTreeSet<String>) {
    for d in dto.people.iter_mut().flat_map(|p| p.devices.iter_mut()) {
        d.in_session |= live.contains(&d.key_id);
    }
}

/// The published view as the contract has it.
pub(crate) fn trusted_dto(view: &TrustedView) -> TrustedDto {
    TrustedDto {
        state: if view.damage.is_some() {
            "damaged"
        } else {
            "ok"
        },
        damage: view.damage.map(|d| TrustedDamageDto {
            reason: damage_reason(d.kind),
            can_restore: d.can_restore,
            can_reset: d.can_reset,
        }),
        trusted_mode: view.trusted_mode,
        people: view
            .people
            .iter()
            .map(|p| TrustedPersonDto {
                telegram_user_id: p.telegram_user_id,
                first_name: p.first_name.clone(),
                username: p.username.clone(),
                devices: p.devices.iter().map(device_dto).collect(),
                // The view keeps them newest last; the window reads newest first.
                attempts: p.attempts.iter().rev().map(attempt_dto).collect(),
                role: role_name(p.role),
                needs_second_step: p.needs_second_step,
            })
            .collect(),
        waiting: view.waiting.clone(),
        owner_device: view.owner_device.as_str(),
        clean: view.clean,
        token: view.token.to_string(),
        full: view.full,
    }
}

/// The window's token back as the epoch; anything else is a window that cannot match.
fn token_of(command: &'static str, token: Option<&str>) -> Option<u64> {
    let parsed = token.and_then(|t| t.parse::<u64>().ok());
    if token.is_some() && parsed.is_none() {
        tracing::debug!(
            command,
            "trusted devices: a token that is not a number; it matches no window"
        );
    }
    parsed
}

/// A `key_id` from the window, or `not_found`.
fn key_of(command: &'static str, key_id: &str) -> Result<KeyId, String> {
    KeyId::parse(key_id).ok_or_else(|| {
        tracing::debug!(
            command,
            len = key_id.len(),
            "trusted devices: refused not_found (not a key_id)"
        );
        TrustedError::NotFound.as_str().to_string()
    })
}

/// Ask the orchestrator, and log the outcome.
async fn ask(
    control: &AgentControl,
    command: &'static str,
    ask: TrustedAsk,
) -> Result<u32, String> {
    let kid = match &ask {
        TrustedAsk::Remove { key_id }
        | TrustedAsk::Confirm { key_id, .. }
        | TrustedAsk::AttemptAllow { key_id, .. }
        | TrustedAsk::AttemptHide { key_id, .. } => Some(key_id.short().to_string()),
        _ => None,
    };
    let outcome = control.ask_trusted(ask).await;
    match outcome {
        Ok(n) => tracing::debug!(
            command,
            kid = kid.as_deref().unwrap_or("-"),
            removed = n,
            "trusted devices: done"
        ),
        // not-a-key-name: `code` is the window's refusal code (session, damaged, …)
        Err(e) => tracing::debug!(
            command,
            kid = kid.as_deref().unwrap_or("-"),
            code = e.as_str(),
            "trusted devices: refused ({e})"
        ),
    }
    outcome.map_err(|e| e.as_str().to_string())
}

/// The trusted devices as the orchestrator last published them; never waits on a write.
#[tauri::command]
pub(crate) async fn get_trusted(control: State<'_, AgentControl>) -> Result<TrustedDto, String> {
    let view = control.trusted_view();
    let (generation, live) = control.live_key_ids();
    tracing::trace!(
        rev = view.rev,
        live_generation = generation,
        live = live.len(),
        "trusted devices: the window read the view"
    );
    let mut dto = trusted_dto(&view);
    mark_live(&mut dto, &live);
    Ok(dto)
}

/// «Доверенные устройства» on (with the window's token) or off.
#[tauri::command]
pub(crate) async fn set_trusted_mode(
    control: State<'_, AgentControl>,
    enabled: bool,
    token: Option<String>,
) -> Result<(), String> {
    let control = control.inner().clone();
    let token = token_of("set_trusted_mode", token.as_deref());
    ask(
        &control,
        "set_trusted_mode",
        TrustedAsk::SetMode { on: enabled, token },
    )
    .await
    .map(|_| ())
}

/// «Удалить»: the key and every key that descends from it. The number of keys removed.
#[tauri::command]
pub(crate) async fn remove_trusted_device(
    control: State<'_, AgentControl>,
    key_id: String,
) -> Result<u32, String> {
    let control = control.inner().clone();
    let key_id = key_of("remove_trusted_device", &key_id)?;
    ask(
        &control,
        "remove_trusted_device",
        TrustedAsk::Remove { key_id },
    )
    .await
}

/// Every key of a person. The number of keys removed.
#[tauri::command]
pub(crate) async fn remove_person(
    control: State<'_, AgentControl>,
    telegram_user_id: i64,
) -> Result<u32, String> {
    let control = control.inner().clone();
    ask(
        &control,
        "remove_person",
        TrustedAsk::RemovePerson { telegram_user_id },
    )
    .await
}

/// The dialog's window token, required: none or not a number is a window that cannot match
/// (`session`, as for confirm).
fn dialog_token(command: &'static str, token: &str) -> Result<u64, String> {
    token_of(command, Some(token)).ok_or_else(|| {
        tracing::debug!(
            command,
            "trusted devices: refused session (no usable window token from the dialog)"
        );
        TrustedError::Session.as_str().to_string()
    })
}

/// «Подтвердить» as the window asks it: the key (`not_found` when not a key id) and the dialog's
/// token (`session`).
fn confirm_ask(key_id: &str, token: &str) -> Result<TrustedAsk, String> {
    Ok(TrustedAsk::Confirm {
        key_id: key_of("confirm_trusted_device", key_id)?,
        token: dialog_token("confirm_trusted_device", token)?,
    })
}

/// «Подтвердить»: clear a key's `unconfirmed` mark (with the window's token).
#[tauri::command]
pub(crate) async fn confirm_trusted_device(
    control: State<'_, AgentControl>,
    key_id: String,
    token: String,
) -> Result<(), String> {
    let control = control.inner().clone();
    let ask_for = confirm_ask(&key_id, &token)?;
    ask(&control, "confirm_trusted_device", ask_for)
        .await
        .map(|_| ())
}

/// «Разрешить» as the window asks it (§10.2): the person, the attempt's key (`not_found` when not
/// a key id), the dialog's token (`session`), the owner's second step, and the role the dialog
/// showed (`role` when it is not a role's name).
fn attempt_allow_ask(
    telegram_user_id: i64,
    key_id: &str,
    token: &str,
    second_step: bool,
    role: &str,
) -> Result<TrustedAsk, String> {
    let role = match role {
        "owner" => BindingRole::Owner,
        "guest" => BindingRole::Guest,
        other => {
            tracing::debug!(
                len = other.len(),
                "trusted devices: attempt_allow refused role (not a role's name)"
            );
            return Err(TrustedError::Role.as_str().to_string());
        }
    };
    Ok(TrustedAsk::AttemptAllow {
        telegram_user_id,
        key_id: key_of("attempt_allow", key_id)?,
        token: dialog_token("attempt_allow", token)?,
        second_step,
        role,
    })
}

/// «Разрешить» on another device's attempt (§10.2): the key is in the list, confirmed; refusals
/// `second_step`, `role`, `tainted` (a session since the dialog opened, either mode), `expired`,
/// `added`, `not_found`, `session`, `damaged`, `full`, `write_failed`, `slow`. `role`: the role
/// the dialog showed (`owner` | `guest`).
#[tauri::command]
pub(crate) async fn attempt_allow(
    control: State<'_, AgentControl>,
    telegram_user_id: i64,
    key_id: String,
    token: String,
    second_step: bool,
    role: String,
) -> Result<(), String> {
    let control = control.inner().clone();
    let ask_for = attempt_allow_ask(telegram_user_id, &key_id, &token, second_step, &role)?;
    ask(&control, "attempt_allow", ask_for).await.map(|_| ())
}

/// «Скрыть» as the window asks it: the person, the attempt's key, the dialog's token.
fn attempt_hide_ask(
    telegram_user_id: i64,
    key_id: &str,
    token: &str,
) -> Result<TrustedAsk, String> {
    Ok(TrustedAsk::AttemptHide {
        telegram_user_id,
        key_id: key_of("attempt_hide", key_id)?,
        token: dialog_token("attempt_hide", token)?,
    })
}

/// «Скрыть» on another device's attempt (§10.2).
#[tauri::command]
pub(crate) async fn attempt_hide(
    control: State<'_, AgentControl>,
    telegram_user_id: i64,
    key_id: String,
    token: String,
) -> Result<(), String> {
    let control = control.inner().clone();
    let ask_for = attempt_hide_ask(telegram_user_id, &key_id, &token)?;
    ask(&control, "attempt_hide", ask_for).await.map(|_| ())
}

/// The repair the window asks for: `"reopen"`, `"reset"`, or `"restore"` with the window token
/// its dialog opened with (none, or not a number: `session`, as for confirm). Anything else:
/// `refused`.
fn repair_ask(action: &str, token: Option<&str>) -> Result<TrustedAsk, String> {
    let action = match action {
        "reopen" => RepairAction::Reopen,
        "restore" => {
            let Some(token) = token_of("repair_trusted(restore)", token) else {
                tracing::debug!(
                    "trusted devices: restore refused session (no window token from the dialog)"
                );
                return Err(TrustedError::Session.as_str().to_string());
            };
            RepairAction::Restore { token }
        }
        "reset" => RepairAction::Reset,
        other => {
            tracing::debug!(
                action = other,
                "trusted devices: refused, not a repair this build knows"
            );
            return Err(TrustedError::Refused.as_str().to_string());
        }
    };
    Ok(TrustedAsk::Repair(action))
}

/// A repair at the PC: `"reopen"`, `"restore"` (with the dialog's window token) or `"reset"`.
#[tauri::command]
pub(crate) async fn repair_trusted(
    control: State<'_, AgentControl>,
    action: String,
    token: Option<String>,
) -> Result<(), String> {
    let control = control.inner().clone();
    let ask_for = repair_ask(&action, token.as_deref())?;
    ask(&control, "repair_trusted", ask_for).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use afklink_core::trusted::{TrustedDamage, TrustedPerson};
    use afklink_core::viewer_keys::{ClientKind, Platform};

    fn kid(c: char) -> KeyId {
        // 43 base64url characters whose last one leaves no stray bits ('A').
        KeyId::parse(&format!("{}A", c.to_string().repeat(42))).expect("a key id")
    }

    fn device(key: KeyId, kind: &str, source: &'static str) -> TrustedDeviceView {
        TrustedDeviceView {
            key_id: key,
            device: DeviceRef {
                kind: ClientKind::parse(kind).expect("kind"),
                platform: Platform::parse("iphone").expect("platform"),
            },
            role: BindingRole::Guest,
            source,
            by: None,
            by_key_id: None,
            unconfirmed: true,
            dependents: 2,
            added_at: 10,
            last_used_at: Some(20),
            in_session: false,
        }
    }

    #[test]
    fn the_view_maps_to_the_contract() {
        let owner = kid('B');
        let mut endorsed = device(kid('C'), "telegram_desktop", "endorse");
        endorsed.by = Some(DeviceRef {
            kind: ClientKind::parse("telegram").expect("kind"),
            platform: Platform::parse("mac").expect("platform"),
        });
        endorsed.by_key_id = Some(owner.clone());
        let view = TrustedView {
            rev: 7,
            damage: None,
            trusted_mode: true,
            people: vec![TrustedPerson {
                telegram_user_id: 5,
                first_name: Some("Вера".into()),
                username: None,
                devices: vec![
                    device(owner.clone(), "smart_fridge", "pair"),
                    endorsed,
                    device(kid('D'), "browser", "grant"),
                    device(kid('E'), "telegram", "recover"),
                    device(kid('F'), "telegram", "first_use"),
                ],
                attempts: [100, 300]
                    .into_iter()
                    .map(|at_ms| afklink_core::trusted::TrustedAttempt {
                        key_id: kid('G'),
                        device: DeviceRef {
                            kind: ClientKind::parse("telegram").expect("kind"),
                            platform: Platform::parse("iphone").expect("platform"),
                        },
                        count: 2,
                        first_at_ms: at_ms - 50,
                        last_at_ms: at_ms,
                    })
                    .collect(),
                role: BindingRole::Owner,
                needs_second_step: true,
            }],
            waiting: vec![9],
            owner_device: afklink_core::viewer_keys::OwnerDevice::Ready,
            clean: false,
            token: 42,
            full: true,
        };
        let dto = trusted_dto(&view);
        let json = serde_json::to_value(&dto).expect("json");
        assert_eq!(json["state"], "ok");
        assert_eq!(json["damage"], serde_json::Value::Null);
        assert_eq!(json["token"], "42");
        assert_eq!(json["waiting"], serde_json::json!([9]));
        assert_eq!(json["owner_device"], "ready");
        assert_eq!(json["full"], true);
        assert_eq!(json["clean"], false);
        let devices = &json["people"][0]["devices"];
        assert_eq!(json["people"][0]["first_name"], "Вера");
        assert_eq!(devices[0]["kind"], serde_json::Value::Null, "unknown kind");
        assert_eq!(devices[0]["platform"], "iphone");
        assert_eq!(devices[0]["key_id"], owner.as_str());
        assert_eq!(devices[0]["key_short"], &owner.as_str()[..8]);
        assert_eq!(devices[0]["role"], "guest");
        assert_eq!(devices[0]["dependents"], 2);
        assert_eq!(devices[0]["last_used_at"], 20);
        assert_eq!(devices[0]["in_session"], false);
        let sources: Vec<&str> = (0..5)
            .map(|i| devices[i]["source"].as_str().expect("source"))
            .collect();
        assert_eq!(
            sources,
            ["pairing", "endorsed", "owner", "restored", "migrated"]
        );
        assert_eq!(devices[1]["kind"], "telegram_desktop");
        assert_eq!(
            devices[1]["by"],
            serde_json::json!({"kind": "telegram", "platform": "mac"})
        );
        assert_eq!(devices[1]["by_key_id"], owner.as_str());
        assert_eq!(devices[2]["by"], serde_json::Value::Null);
        let g = kid('G');
        let attempt = |at: i64| {
            serde_json::json!({
                "kind": "telegram",
                "platform": "iphone",
                "key_id": g.as_str(),
                "key_short": &g.as_str()[..8],
                "count": 2,
                "first_at": at - 50,
                "last_at": at,
                "at": at,
            })
        };
        assert_eq!(
            json["people"][0]["attempts"],
            serde_json::json!([attempt(300), attempt(100)]),
            "newest first"
        );
        assert_eq!(json["people"][0]["role"], "owner");
        assert_eq!(json["people"][0]["needs_second_step"], true);
        assert_eq!(json["people"][0].get("mark"), None, "no mark field");
        assert_eq!(json.get("marked"), None, "no marks list");
    }

    /// The new commands' arguments from the window: a key that is not a key id is `not_found`, a
    /// dialog token that is not a number (or none) is `session`; the second step goes as given.
    #[test]
    fn attempt_and_confirm_asks_from_the_window() {
        let k = kid('B');
        assert_eq!(
            attempt_allow_ask(5, k.as_str(), "42", true, "owner"),
            Ok(TrustedAsk::AttemptAllow {
                telegram_user_id: 5,
                key_id: k.clone(),
                token: 42,
                second_step: true,
                role: BindingRole::Owner,
            })
        );
        assert_eq!(
            attempt_allow_ask(5, "short", "42", false, "guest"),
            Err("not_found".to_string())
        );
        // The role the dialog showed, by its name only.
        for bad in ["", "Owner", "admin"] {
            assert_eq!(
                attempt_allow_ask(5, k.as_str(), "42", false, bad),
                Err("role".to_string()),
                "{bad:?}"
            );
        }
        for bad in ["", "x", "-1"] {
            assert_eq!(
                attempt_allow_ask(5, k.as_str(), bad, false, "guest"),
                Err("session".to_string()),
                "{bad:?}"
            );
            assert_eq!(
                attempt_hide_ask(5, k.as_str(), bad),
                Err("session".to_string())
            );
            assert_eq!(confirm_ask(k.as_str(), bad), Err("session".to_string()));
        }
        assert_eq!(
            attempt_hide_ask(5, k.as_str(), "7"),
            Ok(TrustedAsk::AttemptHide {
                telegram_user_id: 5,
                key_id: k.clone(),
                token: 7,
            })
        );
        assert_eq!(
            attempt_hide_ask(5, "short", "7"),
            Err("not_found".to_string())
        );
        assert_eq!(
            confirm_ask(k.as_str(), "8"),
            Ok(TrustedAsk::Confirm {
                key_id: k.clone(),
                token: 8,
            })
        );
        assert_eq!(confirm_ask("short", "8"), Err("not_found".to_string()));
        // Every refusal code of the core reaches the window as itself (the TS union mirrors it).
        for (e, code) in [
            (TrustedError::Owner, "owner"),
            (TrustedError::SecondStep, "second_step"),
            (TrustedError::Tainted, "tainted"),
            (TrustedError::Expired, "expired"),
            (TrustedError::Added, "added"),
            (TrustedError::OtherPerson, "key_other_person"),
            (TrustedError::NoOwnerDevice, "no_owner_device"),
            (TrustedError::Role, "role"),
        ] {
            assert_eq!(e.as_str(), code);
        }
    }

    /// `in_session` marks exactly the devices a live session is signed with.
    #[test]
    fn the_live_keys_mark_their_devices_in_session() {
        let view = TrustedView {
            rev: 1,
            damage: None,
            trusted_mode: false,
            people: vec![TrustedPerson {
                telegram_user_id: 5,
                first_name: None,
                username: None,
                devices: vec![
                    device(kid('B'), "telegram", "pair"),
                    device(kid('C'), "telegram", "pair"),
                ],
                attempts: Vec::new(),
                role: BindingRole::Guest,
                needs_second_step: false,
            }],
            waiting: vec![],
            owner_device: afklink_core::viewer_keys::OwnerDevice::Missing,
            clean: true,
            token: 1,
            full: false,
        };
        let mut dto = trusted_dto(&view);
        let live: std::collections::BTreeSet<String> =
            std::iter::once(kid('C').as_str().to_string()).collect();
        mark_live(&mut dto, &live);
        let json = serde_json::to_value(&dto).expect("json");
        let devices = &json["people"][0]["devices"];
        assert_eq!(devices[0]["in_session"], false);
        assert_eq!(devices[1]["in_session"], true);
    }

    #[test]
    fn a_damaged_view_maps_its_reason() {
        for (kind, reason) in [
            (DamageKind::Unreadable, "unreadable"),
            (DamageKind::NewerVersion, "newer_version"),
            (DamageKind::NotParsable, "corrupt"),
            (DamageKind::Invariant, "corrupt"),
            (DamageKind::PrimaryMissing, "corrupt"),
            (DamageKind::TooLarge, "corrupt"),
            (DamageKind::BadVersion, "corrupt"),
        ] {
            let view = TrustedView {
                rev: 1,
                damage: Some(TrustedDamage {
                    kind,
                    can_restore: true,
                    can_reset: false,
                }),
                trusted_mode: false,
                people: vec![],
                waiting: vec![],
                owner_device: afklink_core::viewer_keys::OwnerDevice::Missing,
                clean: true,
                token: 1,
                full: false,
            };
            let json = serde_json::to_value(trusted_dto(&view)).expect("json");
            assert_eq!(json["state"], "damaged");
            assert_eq!(
                json["damage"],
                serde_json::json!({"reason": reason, "can_restore": true, "can_reset": false})
            );
        }
    }

    #[test]
    fn a_restore_carries_the_dialogs_token() {
        assert_eq!(
            repair_ask("restore", Some("42")),
            Ok(TrustedAsk::Repair(RepairAction::Restore { token: 42 }))
        );
        for bad in [None, Some(""), Some("x"), Some("-1")] {
            assert_eq!(
                repair_ask("restore", bad),
                Err("session".to_string()),
                "{bad:?}"
            );
        }
        assert_eq!(
            repair_ask("reopen", None),
            Ok(TrustedAsk::Repair(RepairAction::Reopen))
        );
        assert_eq!(
            repair_ask("reset", Some("7")),
            Ok(TrustedAsk::Repair(RepairAction::Reset))
        );
        assert_eq!(repair_ask("wipe", Some("1")), Err("refused".to_string()));
    }

    #[test]
    fn tokens_and_key_ids_from_the_window() {
        assert_eq!(token_of("t", Some("17")), Some(17));
        assert_eq!(token_of("t", Some("x")), None);
        assert_eq!(token_of("t", None), None);
        assert_eq!(key_of("t", "short"), Err("not_found".to_string()));
        assert!(key_of("t", kid('B').as_str()).is_ok());
    }
}
