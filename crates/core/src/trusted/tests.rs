#![allow(clippy::unwrap_used, clippy::panic, reason = "tests")]

use std::path::PathBuf;
use std::sync::Mutex;

use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use tokio::sync::mpsc::UnboundedReceiver;

use super::*;
use crate::viewer_keys::{
    GrantToken, Ground, GroundId, KnownBinding, Lookup, NewKey, Person, ViewerKey, FILE_NAME,
    UNBOUND_KEY_GRACE_MS,
};

/// The canonical SPKI prefix of a P-256 key (id-ecPublicKey, prime256v1, a 66-byte BIT STRING).
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

const NOW: i64 = 1_731_400_000_000;
/// An endorse's `issued_at` later than every removal these tests make.
const ISSUED: u64 = 1_731_500_000_000;

/// The tests' limit before a write answers `slow` — a loaded machine (the full gate, the
/// Windows runner) starts a blocking job or ends its file calls seconds late, which a limit of a
/// few seconds turns into `slow` for a test that waits for the write's result. Longer than
/// [`STEP_WAIT`], so such a test never hears `slow`: a job that late fails the test as one that
/// did not end. Only the slow path's own tests set a short one ([`Loop::gated_slow`]); the
/// product's [`WRITE_LIMIT`] is unchanged.
const TEST_WRITE_LIMIT: Duration = Duration::from_secs(600);

/// How long [`Loop::step`] waits for a job's result before the test fails as hung.
const STEP_WAIT: Duration = Duration::from_secs(60);

fn key() -> ViewerKey {
    let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    let mut spki = SPKI_PREFIX.to_vec();
    spki.extend_from_slice(pair.public_key().as_ref());
    ViewerKey::from_spki(&spki).unwrap()
}

fn new_key(k: &ViewerKey) -> NewKey {
    NewKey {
        key: k.clone(),
        rpk: None,
        kind: ClientKind::parse("telegram").unwrap(),
        platform: Platform::parse("iphone").unwrap(),
    }
}

fn person(uid: i64) -> Person {
    Person {
        telegram_user_id: uid,
        first_name: Some(format!("P{uid}")),
        username: None,
    }
}

fn pair(uid: i64, role: BindingRole, unconfirmed: bool) -> Ground {
    Ground::Pair {
        person: person(uid),
        role,
        unconfirmed,
    }
}

fn gid(n: u8) -> GroundId {
    GroundId::parse(&URL_SAFE_NO_PAD.encode([n; 16])).unwrap()
}

/// A scratch data directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("afklink-trusted-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The main loop, played by the test: the queue, its results' channel, the journal.
struct Loop {
    trusted: Trusted,
    done: UnboundedReceiver<TrustedDone>,
    view: watch::Receiver<Arc<TrustedView>>,
    journal: Journal,
    live: usize,
    /// Releases one gated file job per `()`.
    release: Option<std::sync::mpsc::Sender<()>>,
    dir: Scratch,
}

impl Loop {
    /// The queue over the list in `dir` as it is on disk.
    fn open(dir: Scratch) -> Self {
        let (tx, done) = tokio::sync::mpsc::unbounded_channel();
        let (mut trusted, view) = Trusted::new(Arc::new(move |d: TrustedDone| {
            let _ = tx.send(d);
        }));
        trusted.attach(TrustStore::open_in(&dir.0));
        trusted.write_limit = TEST_WRITE_LIMIT;
        let journal = Journal::open(Some(dir.0.join("connections.jsonl")), NOW);
        Self {
            trusted,
            done,
            view,
            journal,
            live: 0,
            release: None,
            dir,
        }
    }

    /// Every file job waits for [`Self::release`]; the limit stays the tests' own, so no answer
    /// here is `slow` however late the machine runs the job.
    fn gated(mut self) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        self.trusted.gate = Some(Arc::new(Mutex::new(rx)));
        self.release = Some(tx);
        self
    }

    /// [`Self::gated`] with a short `limit`, for the tests of the `slow` answer itself.
    fn gated_slow(mut self, limit: Duration) -> Self {
        self = self.gated();
        self.trusted.write_limit = limit;
        self
    }

    fn release(&self) {
        self.release.as_ref().unwrap().send(()).unwrap();
    }

    fn ask(&mut self, ask: TrustedAsk) -> oneshot::Receiver<TrustedReply> {
        let (reply, rx) = oneshot::channel();
        self.trusted
            .command(TrustedRequest { ask, reply }, self.live);
        rx
    }

    fn view(&self) -> Arc<TrustedView> {
        Arc::clone(&self.view.borrow())
    }

    /// Take the next job's result in, as the main loop would.
    async fn step(&mut self) -> &'static str {
        let done = tokio::time::timeout(STEP_WAIT, self.done.recv())
            .await
            .expect("a job's result in time")
            .expect("the channel is open");
        let kind = done.kind();
        self.trusted.on_done(done, self.live, Some(&self.journal));
        kind
    }

    /// Run until nothing is in flight or queued.
    async fn settle(&mut self) {
        while self.trusted.busy() || !self.trusted.queue.is_empty() {
            self.step().await;
        }
    }

    fn kinds(&self) -> Vec<Kind> {
        self.journal
            .entries()
            .iter()
            .map(|v| v.entry.kind)
            .collect()
    }
}

fn answered(rx: &mut oneshot::Receiver<TrustedReply>) -> Option<TrustedReply> {
    rx.try_recv().ok()
}

/// «Восстановить» from a dialog opened now: the window token as the view says it.
fn restore_ask(l: &Loop) -> TrustedAsk {
    TrustedAsk::Repair(RepairAction::Restore {
        token: l.view().token,
    })
}

/// A list with an owner (confirmed), a guest, and the owner's laptop endorsed by his phone.
fn seeded() -> (Scratch, ViewerKey, ViewerKey, ViewerKey) {
    let dir = Scratch::new();
    let mut store = TrustStore::open_in(&dir.0);
    let owner = key();
    store
        .add(new_key(&owner), pair(1, BindingRole::Owner, false), NOW)
        .unwrap();
    let guest = key();
    store
        .add(new_key(&guest), pair(5, BindingRole::Guest, true), NOW)
        .unwrap();
    let laptop = key();
    store
        .add(
            new_key(&laptop),
            Ground::Endorse {
                by: owner.key_id().clone(),
                endorse_id: gid(1),
                issued_at: ISSUED,
            },
            NOW,
        )
        .unwrap();
    (dir, owner, guest, laptop)
}

#[tokio::test]
async fn the_view_names_people_devices_signers_and_dependents() {
    let (dir, owner, guest, laptop) = seeded();
    let l = Loop::open(dir);
    let view = l.view();
    assert!(view.damage.is_none());
    assert!(view.clean);
    assert!(!view.trusted_mode && !view.full);
    let uids: Vec<i64> = view.people.iter().map(|p| p.telegram_user_id).collect();
    assert_eq!(uids, [1, 5]);
    let owner_dev = &view.people[0].devices[0];
    assert_eq!(&owner_dev.key_id, owner.key_id());
    assert_eq!(owner_dev.source, "pair");
    assert_eq!(owner_dev.dependents, 1, "the laptop goes with it");
    assert!(owner_dev.by.is_none() && owner_dev.by_key_id.is_none());
    let laptop_dev = &view.people[0].devices[1];
    assert_eq!(&laptop_dev.key_id, laptop.key_id());
    assert_eq!(laptop_dev.source, "endorse");
    assert_eq!(laptop_dev.by_key_id.as_ref(), Some(owner.key_id()));
    assert_eq!(
        laptop_dev.by.as_ref().map(|b| b.platform.as_str()),
        Some("iphone")
    );
    let guest_dev = &view.people[1].devices[0];
    assert_eq!(&guest_dev.key_id, guest.key_id());
    assert!(guest_dev.unconfirmed);
    assert_eq!(guest_dev.role, BindingRole::Guest);
    assert!(!guest_dev.in_session);
    assert_eq!(view.people[1].first_name.as_deref(), Some("P5"));
}

/// Mode-on and confirm need a clean window and the token it was opened with: a session that went
/// on since (even one that ended), or one live now, refuses `session`; mode-off is always allowed.
#[tokio::test]
async fn mode_on_and_confirm_refuse_a_stale_token_or_a_live_session() {
    let (dir, _owner, guest, _) = seeded();
    let mut l = Loop::open(dir);
    let opened = l.view().token;

    // A session begins and is live.
    l.trusted.session_began("session_request", "s1");
    l.live = 1;
    let view = l.view();
    assert!(!view.clean);
    assert_ne!(view.token, opened);
    let mut rx = l.ask(TrustedAsk::SetMode {
        on: true,
        token: Some(opened),
    });
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::Session)));
    let fresh = l.view().token;
    let mut rx = l.ask(TrustedAsk::Confirm {
        key_id: guest.key_id().clone(),
        token: fresh,
    });
    assert_eq!(
        answered(&mut rx),
        Some(Err(TrustedError::Session)),
        "live now"
    );

    // It ended: clean again, but the window opened before it is stale.
    l.live = 0;
    l.trusted.sync_live(0);
    assert!(l.view().clean);
    let mut rx = l.ask(TrustedAsk::Confirm {
        key_id: guest.key_id().clone(),
        token: opened,
    });
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::Session)));
    let mut rx = l.ask(TrustedAsk::SetMode {
        on: true,
        token: None,
    });
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::Session)));
    assert!(!l.trusted.busy(), "nothing was staged");

    // Mode off: refused too while a session counts (§3.4) …
    l.live = 2;
    let mut rx = l.ask(TrustedAsk::SetMode {
        on: false,
        token: None,
    });
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::Session)));
    // … and goes without a token once none does.
    l.live = 0;
    let mut rx = l.ask(TrustedAsk::SetMode {
        on: false,
        token: None,
    });
    assert_eq!(
        answered(&mut rx),
        Some(Ok(0)),
        "off already: nothing to write"
    );

    // A window opened now, with nothing live: both go.
    l.live = 0;
    l.trusted.sync_live(0);
    let token = l.view().token;
    let mut confirm = l.ask(TrustedAsk::Confirm {
        key_id: guest.key_id().clone(),
        token,
    });
    let mut on = l.ask(TrustedAsk::SetMode {
        on: true,
        token: Some(token),
    });
    l.settle().await;
    assert_eq!(answered(&mut confirm), Some(Ok(0)));
    assert_eq!(answered(&mut on), Some(Ok(0)));
    let view = l.view();
    assert!(view.trusted_mode);
    assert!(!view.people[1].devices[0].unconfirmed);
    assert_eq!(l.kinds(), [Kind::TrustedOn]);
}

/// A session that begins while a confirm waits behind a write refuses it at its stage.
#[tokio::test]
async fn a_session_that_begins_while_a_confirm_waits_refuses_it() {
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let token = l.view().token;
    let mut off = l.ask(TrustedAsk::SetMode {
        on: true,
        token: Some(token),
    });
    let mut confirm = l.ask(TrustedAsk::Confirm {
        key_id: guest.key_id().clone(),
        token,
    });
    assert!(answered(&mut confirm).is_none(), "queued behind the write");
    l.trusted.session_began("session_request", "s9");
    l.live = 1;
    l.release();
    l.settle().await;
    assert_eq!(answered(&mut off), Some(Ok(0)));
    assert_eq!(answered(&mut confirm), Some(Err(TrustedError::Session)));
    assert!(l.view().people[1].devices[0].unconfirmed);
}

/// A removal asked while a write is in flight is denied at once, waits ahead of every other
/// change, and lands after the write; the journal hears each only once it is installed.
#[tokio::test]
async fn a_removal_during_a_write_is_denied_at_once_and_lands_after_it() {
    let (dir, owner, guest, laptop) = seeded();
    let mut l = Loop::open(dir).gated();
    let token = l.view().token;
    let mut on = l.ask(TrustedAsk::SetMode {
        on: true,
        token: Some(token),
    });
    assert!(l.trusted.busy());
    let mut confirm = l.ask(TrustedAsk::Confirm {
        key_id: guest.key_id().clone(),
        token,
    });
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: owner.key_id().clone(),
    });
    // Denied now, the laptop with it; queued ahead of the confirm.
    let store = l.trusted.store().unwrap();
    assert!(matches!(
        store.lookup(owner.key_id()),
        Lookup::PendingRemoval(_)
    ));
    assert!(matches!(
        store.lookup(laptop.key_id()),
        Lookup::PendingRemoval(_)
    ));
    let order: Vec<&str> = l.trusted.queue.iter().map(|o| o.kind.as_str()).collect();
    assert_eq!(order, ["remove_tree", "confirm"]);
    assert!(l.kinds().is_empty(), "nothing journaled before an install");

    l.release();
    assert_eq!(l.step().await, "trusted_written");
    assert_eq!(answered(&mut on), Some(Ok(0)));
    assert_eq!(l.kinds(), [Kind::TrustedOn]);
    assert!(l.view().trusted_mode);
    // The removal is staged next (the confirm still waits).
    assert_eq!(l.trusted.queue.len(), 1);
    l.release();
    l.release();
    l.settle().await;
    assert_eq!(answered(&mut remove), Some(Ok(2)));
    assert_eq!(answered(&mut confirm), Some(Ok(0)));
    let view = l.view();
    let uids: Vec<i64> = view.people.iter().map(|p| p.telegram_user_id).collect();
    assert_eq!(uids, [5], "the owner's phone and laptop are gone");
    let kinds = l.kinds();
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == Kind::DeviceUntrusted)
            .count(),
        2
    );
    let untrusted = l
        .journal
        .entries()
        .into_iter()
        .find(|v| v.entry.kind == Kind::DeviceUntrusted)
        .unwrap();
    assert_eq!(untrusted.entry.user, 1);
    assert_eq!(untrusted.entry.name, "P1");
    assert_eq!(
        untrusted.entry.trusted_device.map(|d| d.platform),
        Some("iphone".to_string())
    );
    // On disk too.
    let reopened = TrustStore::open_in(&l.dir.0);
    assert!(matches!(
        reopened.lookup(owner.key_id()),
        Lookup::Removed(_)
    ));
    assert!(reopened.switches().unwrap().trusted_devices_mode);
}

/// A write past its limit answers `slow`; it lands later, and the view moves on then.
#[tokio::test]
async fn a_slow_write_answers_slow_then_is_installed() {
    let (dir, owner, _, _) = seeded();
    let mut l = Loop::open(dir).gated_slow(Duration::from_millis(50));
    let rev = l.view().rev;
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: owner.key_id().clone(),
    });
    assert_eq!(l.step().await, "trusted_slow");
    assert_eq!(answered(&mut remove), Some(Err(TrustedError::Slow)));
    assert!(l.trusted.busy(), "still in flight");
    // Denied meanwhile.
    assert!(matches!(
        l.trusted.store().unwrap().lookup(owner.key_id()),
        Lookup::PendingRemoval(_)
    ));
    l.release();
    assert_eq!(l.step().await, "trusted_written");
    assert!(!l.trusted.busy());
    let view = l.view();
    assert!(view.rev > rev);
    assert!(view.people.iter().all(|p| p.telegram_user_id != 1));
    assert_eq!(
        l.kinds()
            .iter()
            .filter(|k| **k == Kind::DeviceUntrusted)
            .count(),
        2
    );
}

/// The file changed under a staged write: the write is abandoned (the list reloaded), tried
/// again, and installed; the journal hears it once, and the other process's key is in the view.
#[tokio::test]
async fn a_change_on_disk_is_retried_and_journaled_once() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let token = l.view().token;
    let mut on = l.ask(TrustedAsk::SetMode {
        on: true,
        token: Some(token),
    });
    // Another writer adds a key while the write waits.
    let mut other = TrustStore::open_in(&l.dir.0);
    let stranger = key();
    other
        .add(new_key(&stranger), pair(7, BindingRole::Guest, false), NOW)
        .unwrap();
    l.release();
    assert_eq!(l.step().await, "trusted_written");
    assert!(answered(&mut on).is_none(), "retried, not answered");
    assert!(l.kinds().is_empty());
    l.release();
    l.settle().await;
    assert_eq!(answered(&mut on), Some(Ok(0)));
    assert_eq!(l.kinds(), [Kind::TrustedOn]);
    let view = l.view();
    assert!(view.trusted_mode);
    assert!(view.people.iter().any(|p| p.telegram_user_id == 7));
}

/// A key that joins as a descendant of a key whose removal is pending gets a removal of its own,
/// carried with its root's origin (`pc`); the tree removal's retry is a write of memory and
/// answers what its press decided (the owner and the laptop). All three leave.
#[tokio::test]
async fn a_key_that_joins_under_a_denied_key_is_removed_too() {
    let (dir, owner, _, laptop) = seeded();
    let mut l = Loop::open(dir).gated();
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: owner.key_id().clone(),
    });
    // Another writer adds a key the owner's laptop endorsed, under the staged removal.
    let mut other = TrustStore::open_in(&l.dir.0);
    let tablet = key();
    other
        .add(
            new_key(&tablet),
            Ground::Endorse {
                by: laptop.key_id().clone(),
                endorse_id: gid(2),
                issued_at: ISSUED,
            },
            NOW,
        )
        .unwrap();
    l.release();
    assert_eq!(l.step().await, "trusted_written");
    // The reload brought the tablet in, under denied keys: denied too.
    assert!(matches!(
        l.trusted.store().unwrap().lookup(tablet.key_id()),
        Lookup::PendingRemoval(_)
    ));
    l.release();
    l.release();
    l.settle().await;
    assert_eq!(answered(&mut remove), Some(Ok(2)));
    let store = l.trusted.store().unwrap();
    for k in [&owner, &laptop, &tablet] {
        assert_eq!(origin_of(store, k), "pc");
    }
    assert!(store.pending_without_removal().is_empty());
}

/// «Удалить» the guest's key K at the PC (carried `pc`; its write waits), a key P that K
/// endorsed is added by another writer meanwhile, and then the server unbinds the guest. P joins
/// as K's descendant: it is removed as the press decided K — `pc`, in memory and on disk — never
/// with the server's later origin (the first decision's origin stays the record's, §10.1).
#[tokio::test]
async fn a_key_that_joins_under_a_pressed_key_keeps_the_press_origin_after_a_server_unbind() {
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    let mut other = TrustStore::open_in(&l.dir.0);
    let tablet = key();
    other
        .add(
            new_key(&tablet),
            Ground::Endorse {
                by: guest.key_id().clone(),
                endorse_id: gid(2),
                issued_at: ISSUED,
            },
            NOW,
        )
        .unwrap();
    l.trusted.guest_removed_on_server(5, 0);
    assert_eq!(
        l.trusted.store().unwrap().removal_decided(guest.key_id()),
        Some("pc"),
        "the PC's carry stays pc"
    );
    l.release();
    assert_eq!(l.step().await, "trusted_written");
    assert!(matches!(
        l.trusted.store().unwrap().lookup(tablet.key_id()),
        Lookup::PendingRemoval(_)
    ));
    assert_eq!(
        l.trusted.store().unwrap().removal_decided(tablet.key_id()),
        Some("pc"),
        "the descendant is carried with its root's origin"
    );
    for _ in 0..4 {
        l.release();
    }
    l.settle().await;
    assert_eq!(answered(&mut remove), Some(Ok(1)));
    for store in [l.trusted.store().unwrap(), &TrustStore::open_in(&l.dir.0)] {
        assert_eq!(origin_of(store, &guest), "pc");
        assert_eq!(origin_of(store, &tablet), "pc", "P on its root's press");
    }
    assert!(l
        .trusted
        .store()
        .unwrap()
        .pending_without_removal()
        .is_empty());
}

/// A damaged list: the view says so with what can be done; every change but a repair answers
/// `damaged`; a restore brings the backup back; a reopen reads a fixed file.
#[tokio::test]
async fn a_damaged_list_answers_damaged_and_repairs() {
    let (dir, owner, _, _) = seeded();
    let primary = dir.0.join(FILE_NAME);
    let good = std::fs::read(&primary).unwrap();
    std::fs::write(&primary, b"{ not json").unwrap();
    let mut l = Loop::open(dir);
    let view = l.view();
    let damage = view.damage.unwrap();
    assert_eq!(damage.kind, DamageKind::NotParsable);
    assert!(damage.can_restore && damage.can_reset);
    assert!(view.people.is_empty() && view.waiting.is_empty() && !view.trusted_mode);

    let token = view.token;
    for ask in [
        TrustedAsk::SetMode {
            on: true,
            token: Some(token),
        },
        TrustedAsk::SetMode {
            on: false,
            token: None,
        },
        TrustedAsk::Confirm {
            key_id: owner.key_id().clone(),
            token,
        },
        TrustedAsk::Remove {
            key_id: owner.key_id().clone(),
        },
        TrustedAsk::RemovePerson {
            telegram_user_id: 1,
        },
    ] {
        let what = ask.as_str();
        let mut rx = l.ask(ask);
        assert_eq!(
            answered(&mut rx),
            Some(Err(TrustedError::Damaged)),
            "{what}"
        );
    }
    // §10 «Повреждённый список»: the removal presses are refused like every other change, and
    // nothing waits for the repair.
    assert!(l.trusted.parked.is_empty() && l.trusted.queue.is_empty());

    // The restore brings the backup back (the owner's key in it), as it was.
    let mut restore = l.ask(restore_ask(&l));
    assert_eq!(l.step().await, "trusted_written");
    assert_eq!(answered(&mut restore), Some(Ok(0)));
    l.settle().await;
    let view = l.view();
    assert!(view.damage.is_none());
    assert!(matches!(
        l.trusted.store().unwrap().lookup(owner.key_id()),
        Lookup::Active(_)
    ));
    assert!(l.trusted.parked.is_empty());

    // Broken again, then fixed by hand: a reopen reads it.
    std::fs::write(&primary, b"[]").unwrap();
    let mut reopen = l.ask(TrustedAsk::Repair(RepairAction::Reopen));
    l.settle().await;
    assert_eq!(answered(&mut reopen), Some(Ok(0)));
    assert!(l.view().damage.is_some());
    std::fs::write(&primary, &good).unwrap();
    let mut reopen = l.ask(TrustedAsk::Repair(RepairAction::Reopen));
    l.settle().await;
    assert_eq!(answered(&mut reopen), Some(Ok(0)));
    assert!(l.view().damage.is_none());
}

/// A list of a newer version can be neither restored over nor reset: upgrade instead.
#[tokio::test]
async fn a_newer_list_cannot_be_restored_or_reset() {
    let (dir, _, _, _) = seeded();
    std::fs::write(dir.0.join(FILE_NAME), br#"{"version":99}"#).unwrap();
    let mut l = Loop::open(dir);
    let damage = l.view().damage.unwrap();
    assert_eq!(damage.kind, DamageKind::NewerVersion);
    assert!(!damage.can_restore && !damage.can_reset);
    let mut reset = l.ask(TrustedAsk::Repair(RepairAction::Reset));
    let mut restore = l.ask(restore_ask(&l));
    l.settle().await;
    assert_eq!(answered(&mut reset), Some(Err(TrustedError::NewerVersion)));
    assert_eq!(
        answered(&mut restore),
        Some(Err(TrustedError::NewerVersion))
    );
    // The newer file is untouched.
    assert_eq!(
        std::fs::read(l.dir.0.join(FILE_NAME)).unwrap(),
        br#"{"version":99}"#
    );
}

/// A reset of a corrupt list empties it and keeps the switch the window showed (its mode file
/// says observe here; `viewer_keys::store` tests every direction).
#[tokio::test]
async fn a_reset_empties_a_corrupt_list() {
    let (dir, _, _, _) = seeded();
    std::fs::write(dir.0.join(FILE_NAME), b"garbage").unwrap();
    let mut l = Loop::open(dir);
    let mut reset = l.ask(TrustedAsk::Repair(RepairAction::Reset));
    l.settle().await;
    assert_eq!(answered(&mut reset), Some(Ok(0)));
    let view = l.view();
    assert!(view.damage.is_none());
    assert!(view.people.is_empty());
    assert!(!view.trusted_mode, "the switch stays off");
}

/// A guest unbound at the PC loses their keys (origin pc, journaled); a person whose keys
/// include an owner's keeps them; unknown people and no list change nothing.
#[tokio::test]
async fn untrusting_a_guest_removes_their_keys_but_never_an_owners() {
    let (dir, owner, guest, _) = seeded();
    let mut l = Loop::open(dir);
    l.trusted.untrust_guest(1, 0);
    assert!(!l.trusted.busy(), "the owner's keys stay");
    l.trusted.untrust_guest(42, 0);
    assert!(!l.trusted.busy(), "nobody's keys");
    l.trusted.untrust_guest(5, 0);
    assert!(matches!(
        l.trusted.store().unwrap().lookup(guest.key_id()),
        Lookup::PendingRemoval(_)
    ));
    l.settle().await;
    let store = l.trusted.store().unwrap();
    match store.lookup(guest.key_id()) {
        Lookup::Removed(t) => assert_eq!(t.origin.as_str(), "pc"),
        other => panic!("not removed: {other:?}"),
    }
    assert!(matches!(store.lookup(owner.key_id()), Lookup::Active(_)));
    assert_eq!(l.kinds(), [Kind::DeviceUntrusted]);

    let (mut none, _) = Trusted::new(Arc::new(|_| {}));
    none.untrust_guest(5, 0);
    assert!(!none.busy());
}

/// Without a list (the CLI) every change is refused and the view says unreadable.
#[tokio::test]
async fn no_list_refuses_everything() {
    let (mut t, view) = Trusted::new(Arc::new(|_| {}));
    let (reply, mut rx) = oneshot::channel();
    t.command(
        TrustedRequest {
            ask: TrustedAsk::SetMode {
                on: false,
                token: None,
            },
            reply,
        },
        0,
    );
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::Refused)));
    assert_eq!(
        view.borrow().damage.map(|d| d.kind),
        Some(DamageKind::Unreadable)
    );
}

/// The window's wait: an answer when the orchestrator gives one, `refused` with no agent. (The
/// `slow` past [`REPLY_LIMIT`] is a plain `tokio::time::timeout`; not waited out here.)
#[tokio::test]
async fn the_windows_wait_takes_the_answer_or_refuses() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let waiter = tokio::spawn(async move {
        ask(
            &tx,
            TrustedAsk::SetMode {
                on: false,
                token: None,
            },
        )
        .await
    });
    let Some(crate::AgentCommand::Trusted(req)) = rx.recv().await else {
        panic!("a trusted request");
    };
    req.reply.send(Ok(0)).unwrap();
    assert_eq!(waiter.await.unwrap(), Ok(0));

    // Dropped unanswered: refused.
    let (tx, mut rx) = mpsc::unbounded_channel();
    let waiter = tokio::spawn(async move {
        ask(
            &tx,
            TrustedAsk::SetMode {
                on: false,
                token: None,
            },
        )
        .await
    });
    drop(rx.recv().await);
    assert_eq!(waiter.await.unwrap(), Err(TrustedError::Refused));

    let (tx, rx) = mpsc::unbounded_channel();
    drop(rx);
    assert_eq!(
        ask(
            &tx,
            TrustedAsk::SetMode {
                on: false,
                token: None,
            },
        )
        .await,
        Err(TrustedError::Refused)
    );
}

/// A token read while a session was on never passes once it ended; a token read while clean does
/// not pass after a session came and went.
#[tokio::test]
async fn a_token_from_a_window_with_a_session_never_passes() {
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir);
    l.trusted.session_began("session_request", "s1");
    l.live = 1;
    let dirty = l.view();
    assert!(!dirty.clean);
    l.live = 0;
    l.trusted.sync_live(0);
    assert!(l.view().clean);
    assert_ne!(l.view().token, dirty.token, "the end moved the token");
    let mut confirm = l.ask(TrustedAsk::Confirm {
        key_id: guest.key_id().clone(),
        token: dirty.token,
    });
    let mut on = l.ask(TrustedAsk::SetMode {
        on: true,
        token: Some(dirty.token),
    });
    assert_eq!(answered(&mut confirm), Some(Err(TrustedError::Session)));
    assert_eq!(answered(&mut on), Some(Err(TrustedError::Session)));

    // Read while clean; a session comes and goes (as the loop's count sees it).
    let clean = l.view().token;
    l.trusted.sync_live(1);
    l.trusted.sync_live(0);
    let mut confirm = l.ask(TrustedAsk::Confirm {
        key_id: guest.key_id().clone(),
        token: clean,
    });
    assert_eq!(answered(&mut confirm), Some(Err(TrustedError::Session)));
    // A window opened now passes.
    let fresh = l.view().token;
    let mut confirm = l.ask(TrustedAsk::Confirm {
        key_id: guest.key_id().clone(),
        token: fresh,
    });
    l.settle().await;
    assert_eq!(answered(&mut confirm), Some(Ok(0)));
}

/// A reset or a restore asked while the list was damaged is refused once a reopen made it healthy:
/// the keys stay.
#[tokio::test]
async fn a_repair_of_a_list_healthy_by_its_stage_is_refused() {
    let (dir, owner, guest, laptop) = seeded();
    let primary = dir.0.join(FILE_NAME);
    let good = std::fs::read(&primary).unwrap();
    std::fs::write(&primary, b"{ not json").unwrap();
    let mut l = Loop::open(dir);
    assert!(
        l.view().damage.is_some(),
        "the dialog opens on a damaged list"
    );
    std::fs::write(&primary, &good).unwrap();
    let mut reopen = l.ask(TrustedAsk::Repair(RepairAction::Reopen));
    let mut reset = l.ask(TrustedAsk::Repair(RepairAction::Reset));
    let mut restore = l.ask(restore_ask(&l));
    l.settle().await;
    assert_eq!(answered(&mut reopen), Some(Ok(0)));
    assert_eq!(answered(&mut reset), Some(Err(TrustedError::Refused)));
    assert_eq!(answered(&mut restore), Some(Err(TrustedError::Refused)));
    let store = l.trusted.store().unwrap();
    for k in [&owner, &guest, &laptop] {
        assert!(matches!(store.lookup(k.key_id()), Lookup::Active(_)));
    }
    assert_eq!(std::fs::read(&primary).unwrap(), good, "nothing written");
}

/// A removal refused for good does not undeny a key another waiting removal still takes.
#[tokio::test]
async fn undeny_spares_keys_another_waiting_removal_takes() {
    let (dir, owner, _, laptop) = seeded();
    let mut l = Loop::open(dir);
    l.trusted
        .store
        .as_mut()
        .unwrap()
        .deny_now(&[owner.key_id().clone(), laptop.key_id().clone()]);
    l.trusted.queue.push_back(Op {
        denied: vec![owner.key_id().clone(), laptop.key_id().clone()],
        ..Op::new(OpKind::RemovePerson { uid: 1 }, None)
    });
    let refused = || Op {
        denied: vec![laptop.key_id().clone()],
        ..Op::new(OpKind::RemoveTree(laptop.key_id().clone()), None)
    };
    let not_found = StoreError::NotFound(laptop.key_id().clone());
    l.trusted.retry_or_fail(refused(), &not_found);
    assert!(matches!(
        l.trusted.store().unwrap().lookup(laptop.key_id()),
        Lookup::PendingRemoval(_)
    ));
    l.trusted.queue.clear();
    l.trusted.retry_or_fail(refused(), &not_found);
    assert!(matches!(
        l.trusted.store().unwrap().lookup(laptop.key_id()),
        Lookup::Active(_)
    ));
}

/// The contract's `not_found`: a key the list does not know. A person with no key is no
/// `not_found`: the press replaces the token and takes nothing.
#[tokio::test]
async fn removals_of_nothing_answer_not_found() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir);
    let mut person = l.ask(TrustedAsk::RemovePerson {
        telegram_user_id: 42,
    });
    let stranger = key();
    let mut device = l.ask(TrustedAsk::Remove {
        key_id: stranger.key_id().clone(),
    });
    l.settle().await;
    // «Удалить человека» of a person the PC does not know still replaces the token (§10: on
    // every press) and takes nothing.
    assert_eq!(answered(&mut person), Some(Ok(0)));
    assert_eq!(answered(&mut device), Some(Err(TrustedError::NotFound)));
    assert!(l.trusted.parked.is_empty());
}

/// Out of attempts (the file changed under each of three writes): `write_failed`, the key stays
/// denied and the removal parked; the timer tries it again and it lands.
#[tokio::test]
async fn a_removal_out_of_attempts_is_parked_and_lands_on_the_timer() {
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    for n in 0..MAX_ATTEMPTS {
        let mut other = TrustStore::open_in(&l.dir.0);
        let k = key();
        other
            .add(
                new_key(&k),
                pair(100 + i64::from(n), BindingRole::Guest, false),
                NOW,
            )
            .unwrap();
        drop(other);
        l.release();
        assert_eq!(l.step().await, "trusted_written");
    }
    assert_eq!(answered(&mut remove), Some(Err(TrustedError::WriteFailed)));
    assert_eq!(l.trusted.parked.len(), 1);
    assert!(!l.trusted.busy());
    assert!(matches!(
        l.trusted.store().unwrap().lookup(guest.key_id()),
        Lookup::PendingRemoval(_)
    ));
    // Not yet due.
    l.trusted.tick(Instant::now());
    assert_eq!(l.trusted.parked.len(), 1);
    l.trusted
        .tick(Instant::now() + PARKED_RETRY + Duration::from_secs(1));
    assert!(l.trusted.parked.is_empty());
    l.release();
    l.settle().await;
    assert!(matches!(
        l.trusted.store().unwrap().lookup(guest.key_id()),
        Lookup::Removed(_)
    ));
    assert_eq!(l.kinds(), [Kind::DeviceUntrusted]);
}

/// A file job whose thread panicked: the change is lost, the list is read again, and the removal
/// is tried again and lands.
#[tokio::test]
async fn a_lost_job_is_retried_after_a_reopen() {
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir);
    l.trusted.panic_next = true;
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    assert_eq!(l.step().await, "trusted_lost");
    assert!(answered(&mut remove).is_none(), "retried, not answered");
    assert_eq!(l.step().await, "trusted_reopened");
    l.settle().await;
    assert_eq!(answered(&mut remove), Some(Ok(1)));
    assert!(matches!(
        l.trusted.store().unwrap().lookup(guest.key_id()),
        Lookup::Removed(_)
    ));
}

/// §3.4 «Органы доверия»: while a session not signed by a confirmed owner
/// key is live or pending, every trust command of the window is refused `session` — the person at
/// the PC too — and nothing is denied, queued or staged.
#[tokio::test]
async fn every_window_command_is_refused_while_a_session_counts() {
    let (dir, owner, guest, _) = seeded();
    let mut l = Loop::open(dir);
    l.live = 1;
    let token = l.view().token;
    let asks = [
        TrustedAsk::SetMode {
            on: true,
            token: Some(token),
        },
        TrustedAsk::SetMode {
            on: false,
            token: None,
        },
        TrustedAsk::Confirm {
            key_id: guest.key_id().clone(),
            token,
        },
        TrustedAsk::Remove {
            key_id: owner.key_id().clone(),
        },
        TrustedAsk::RemovePerson {
            telegram_user_id: 5,
        },
        TrustedAsk::Repair(RepairAction::Reopen),
        restore_ask(&l),
        TrustedAsk::Repair(RepairAction::Reset),
    ];
    for ask in asks {
        let what = ask.as_str();
        let mut rx = l.ask(ask);
        assert_eq!(
            answered(&mut rx),
            Some(Err(TrustedError::Session)),
            "{what}: refused session"
        );
        assert!(!l.trusted.busy(), "{what}: nothing staged");
        assert!(l.trusted.queue.is_empty(), "{what}: nothing queued");
    }
    // Nothing was denied: both keys still answer active.
    let store = l.trusted.store().unwrap();
    assert!(matches!(store.lookup(owner.key_id()), Lookup::Active(_)));
    assert!(matches!(store.lookup(guest.key_id()), Lookup::Active(_)));
    // The queue's own changes are not gated: a guest's untrust still goes.
    l.trusted.untrust_guest(5, l.live);
    l.settle().await;
    assert!(matches!(
        l.trusted.store().unwrap().lookup(guest.key_id()),
        Lookup::Removed(_)
    ));
}

/// The admission's changes go through the queue (after removals, one in flight) and come out of
/// `take_landed`: installed, refused by the store at their turn, or `slow` then installed.
#[tokio::test]
async fn admission_changes_land_through_the_queue() {
    use crate::admission::{AdmitOp, LandedOutcome, StoreOp};
    let (dir, _owner, _guest, _) = seeded();
    let mut l = Loop::open(dir);
    l.live = 1; // not gated: the admission decided it
    let k = key();
    l.trusted.admit(AdmitOp {
        ticket: 7,
        op: StoreOp::add(new_key(&k), pair(9, BindingRole::Guest, false)),
    });
    l.settle().await;
    let landed = l.trusted.take_landed();
    assert_eq!(landed.len(), 1);
    assert_eq!(landed[0].ticket, 7);
    assert!(!landed[0].slow);
    match &landed[0].result {
        Ok(LandedOutcome::Added(a)) => assert_eq!(&a.key_id, k.key_id()),
        other => panic!("not added: {other:?}"),
    }
    // The same key again: the store refuses it at the queue's turn.
    l.trusted.admit(AdmitOp {
        ticket: 8,
        op: StoreOp::add(new_key(&k), pair(9, BindingRole::Guest, false)),
    });
    l.settle().await;
    let landed = l.trusted.take_landed();
    assert!(matches!(
        landed[0].result,
        Err(StoreError::AlreadyActive(_))
    ));
    // A touch not due writes nothing and lands at once.
    l.trusted.admit(AdmitOp {
        ticket: 9,
        op: StoreOp::Touch {
            key_id: k.key_id().clone(),
        },
    });
    l.settle().await;
    let first = l.trusted.take_landed();
    assert_eq!(first[0].ticket, 9);
}

#[tokio::test]
async fn a_slow_admission_write_lands_slow_then_installed() {
    use crate::admission::{AdmitOp, LandedOutcome, StoreOp};
    let (dir, _owner, _guest, _) = seeded();
    let mut l = Loop::open(dir).gated_slow(Duration::from_millis(50));
    let k = key();
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(new_key(&k), pair(9, BindingRole::Guest, false)),
    });
    assert_eq!(l.step().await, "trusted_slow");
    let slow = l.trusted.take_landed();
    assert_eq!(slow.len(), 1);
    assert!(slow[0].slow && slow[0].result.is_err());
    l.release();
    l.settle().await;
    let landed = l.trusted.take_landed();
    assert!(matches!(landed[0].result, Ok(LandedOutcome::Added(_))));
}

// --- A guest's removal holds across retries and orderings ----------------------------------------

/// The landed results of the admission's changes, by ticket.
fn landed_of(l: &mut Loop) -> HashMap<u64, Result<crate::admission::LandedOutcome, StoreError>> {
    l.trusted
        .take_landed()
        .into_iter()
        .filter(|d| !d.slow)
        .map(|d| (d.ticket, d.result))
        .collect()
}

/// The server removes guest `uid` (`binding_removed`): they leave the stored binding list (the
/// handler's rule notes it: the one shared step, its notes queued), and their guest-role keys go
/// (`Admission::remove_person` on the server's word).
fn server_removes(l: &mut Loop, uid: i64) {
    use crate::admission::{AdmitOp, StoreOp};
    assert!(l
        .trusted
        .store_for_notes()
        .unwrap()
        .person_removed(uid, "test: left the stored binding list"));
    l.trusted.admit(AdmitOp {
        ticket: 990,
        op: StoreOp::Notes,
    });
    l.trusted.guest_removed_on_server(uid, 0);
}

/// Item 1, on the removal (§7, §10): a guest's first key is being written when the server removes
/// the guest, and the write fails retryably (the file changed on disk): its retry — after the
/// removal, which replaced the grant token — is refused at its stage (`grant_stale`, checked
/// before the mark): never written, never active, on disk neither.
#[tokio::test]
async fn a_guest_write_retried_after_the_removal_is_refused_at_its_stage() {
    use crate::admission::{AdmitOp, StoreOp};
    let (dir, owner, _guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let k = key();
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(
            new_key(&k),
            grant_for(&owner, 9, 3, current(l.trusted.store().unwrap())),
        ),
    });
    server_removes(&mut l, 9);
    // Another writer: the guest key's write fails `changed_on_disk` and is retried.
    TrustStore::open_in(&l.dir.0)
        .add(new_key(&key()), pair(7, BindingRole::Guest, false), NOW)
        .unwrap();
    l.release();
    assert_eq!(l.step().await, "trusted_written");
    l.release();
    l.release();
    l.settle().await;
    let landed = landed_of(&mut l);
    assert!(
        matches!(&landed[&3], Err(StoreError::GrantStale)),
        "{:?}",
        landed[&3]
    );
    assert!(matches!(
        l.trusted.store().unwrap().lookup(k.key_id()),
        Lookup::Unknown
    ));
    let fresh = TrustStore::open_in(&l.dir.0);
    assert!(matches!(fresh.lookup(k.key_id()), Lookup::Unknown));
}

/// On the mark (the install decides again): a guest's key in flight when the
/// server removes the guest lands denied at once — never active, also while another change is
/// written before its removal — and leaves as a tombstone `server`; the admission hears
/// `grant_stale` (the removal replaced the grant token: the grant's own check before the mark,
/// §7). Another person's key written meanwhile is theirs as it is.
#[tokio::test]
async fn a_guest_key_landing_during_the_removal_is_never_active() {
    use crate::admission::{AdmitOp, LandedOutcome, StoreOp};
    let (dir, owner, _guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let k = key();
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(
            new_key(&k),
            grant_for(&owner, 9, 3, current(l.trusted.store().unwrap())),
        ),
    });
    server_removes(&mut l, 9);
    let other = key();
    l.trusted.admit(AdmitOp {
        ticket: 4,
        op: StoreOp::add(
            new_key(&other),
            grant_for(&owner, 11, 4, current(l.trusted.store().unwrap())),
        ),
    });
    let mut steps = 0;
    while l.trusted.busy() || !l.trusted.queue.is_empty() {
        l.release();
        l.step().await;
        steps += 1;
        let lookup = l.trusted.store().unwrap().lookup(k.key_id());
        assert!(
            !matches!(lookup, Lookup::Active(_)),
            "step {steps}: the key is never active: {lookup:?}"
        );
    }
    assert!(
        steps >= 3,
        "the add, the other change and the removal: {steps}"
    );
    let landed = landed_of(&mut l);
    assert!(
        matches!(&landed[&3], Err(StoreError::GrantStale)),
        "{:?}",
        landed[&3]
    );
    assert!(matches!(&landed[&4], Ok(LandedOutcome::Added(_))));
    assert_eq!(origin_of(l.trusted.store().unwrap(), &k), "server");
    // After a reopen too.
    let reopened = TrustStore::open_in(&l.dir.0);
    assert_eq!(origin_of(&reopened, &k), "server");
}

/// A person removed on the server's word runs the shared step (attempts dropped, the token
/// replaced) and the queue writes the notes.
fn server_removes_keyless(l: &mut Loop, uid: i64, ticket: u64) -> bool {
    use crate::admission::{AdmitOp, StoreOp};
    let removed = l
        .trusted
        .store_for_notes()
        .unwrap()
        .person_removed(uid, "test: removed on the server's word");
    l.trusted.admit(AdmitOp {
        ticket,
        op: StoreOp::Notes,
    });
    removed
}

/// Run the queue out, asserting after every job that `k` is never active in memory (a key in
/// flight before the removal is on disk until the next write carries its denial).
async fn settle_never_active(l: &mut Loop, k: &ViewerKey) {
    let mut steps = 0;
    while l.trusted.busy() || !l.trusted.queue.is_empty() {
        l.release();
        l.step().await;
        steps += 1;
        let lookup = l.trusted.store().unwrap().lookup(k.key_id());
        assert!(
            !matches!(lookup, Lookup::Active(_)),
            "step {steps}: the key is never active: {lookup:?}"
        );
    }
}

/// `binding_removed` builds the whole removal in memory — the person's guest keys denied, the
/// token replaced — and writes it once: one write in all; journaled once. «Удалить» of the
/// person at the PC (`pc`) the same.
#[tokio::test]
async fn a_binding_removed_writes_the_keys_and_the_token_in_one_snapshot() {
    for (by, name) in [(Removal::Server, "server"), (Removal::Pc, "pc")] {
        let (dir, _owner, guest, _) = seeded();
        let mut l = Loop::open(dir).gated();
        let token = current(l.trusted.store().unwrap());
        let mut admission = crate::admission::Admission::new(
            "dev".to_string(),
            crate::viewer_keys::TelegramVerifier::production(),
        );
        assert!(admission.remove_person(&mut l.trusted, 5, Some(BindingRole::Guest), by, 1));
        let mut writes = 0;
        while l.trusted.busy() || !l.trusted.queue.is_empty() {
            l.release();
            l.step().await;
            writes += 1;
        }
        assert_eq!(writes, 1, "{name}: one snapshot");
        let disk = TrustStore::open_in(&l.dir.0);
        assert_eq!(origin_of(&disk, &guest), name);
        assert_ne!(current(&disk), token, "{name}: the token replaced");
        assert_eq!(l.kinds(), [Kind::DeviceUntrusted], "{name}");
    }
}

/// Item 5: a flood of `BindingRemoved` while an admission's write is in flight keeps the queue
/// bounded: people with no key queue nothing; the same guest again joins the removal already
/// waiting, and the PC's unbind makes it the PC's in the store's carry (only «Разрешить» lifts
/// it); the waiting op needs no origin of its own.
#[tokio::test]
async fn a_flood_of_unbinds_during_a_write_keeps_the_queue_bounded() {
    use crate::admission::{AdmitOp, StoreOp};
    let (dir, _owner, guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(new_key(&key()), pair(9, BindingRole::Guest, false)),
    });
    for uid in 1000..1200 {
        l.trusted.guest_removed_on_server(uid, 0);
    }
    assert!(l.trusted.queue.is_empty(), "nothing queued for nobody");
    for _ in 0..50 {
        l.trusted.guest_removed_on_server(5, 0);
        l.trusted.untrust_guest(5, 0);
    }
    assert_eq!(l.trusted.queue.len(), 1, "one removal of the guest");
    assert!(matches!(
        l.trusted.queue[0].kind,
        OpKind::UntrustGuest { uid: 5, .. }
    ));
    assert_eq!(
        l.trusted.store().unwrap().removal_decided(guest.key_id()),
        Some("pc"),
        "the carry is the PC's"
    );
    l.release();
    l.release();
    l.settle().await;
    assert_eq!(
        origin_of(l.trusted.store().unwrap(), &guest),
        "pc",
        "the PC's origin"
    );
}

/// Item 4, on the list (§10.2): another device's attempt is the list's — a fresh process (a
/// restart) shows it with its count and times; one whose last try is more than 30 days old is
/// gone. The window is published for a new attempt.
#[tokio::test]
async fn attempts_come_back_after_a_restart_from_the_list() {
    let (dir, _owner, _guest, _) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let attempt = |k: &ViewerKey, at: i64| crate::viewer_keys::Attempt {
        telegram_user_id: 5,
        role: BindingRole::Guest,
        key: k.clone(),
        kind: ClientKind::parse("telegram").unwrap(),
        platform: Platform::parse("iphone").unwrap(),
        rpk: None,
        first_at: at,
        last_at: at,
        count: 1,
    };
    let (recent, old) = (key(), key());
    let old_at = now - crate::viewer_keys::ATTEMPT_KEEP_MS - 60_000;
    {
        let store = l.trusted.store_for_notes().unwrap();
        assert!(store.note_attempt(attempt(&old, old_at), old_at));
        // Noting the next one drops the old one (§10.2: 30 days).
        assert!(store.note_attempt(attempt(&recent, now - 10), now - 10));
        assert!(!store.note_attempt(attempt(&recent, now), now), "a repeat");
    }
    let rev = l.view().rev;
    l.trusted.attempt_noted(5, recent.key_id(), true, now);
    assert!(l.view().rev > rev, "published");
    let shown = |v: &TrustedView| -> Vec<TrustedAttempt> {
        v.people
            .iter()
            .find(|p| p.telegram_user_id == 5)
            .map(|p| p.attempts.clone())
            .unwrap_or_default()
    };
    let now_shown = shown(&l.view());
    assert_eq!(
        now_shown.len(),
        1,
        "the old one is not shown: {now_shown:?}"
    );
    assert_eq!(
        (
            now_shown[0].count,
            now_shown[0].first_at_ms,
            now_shown[0].last_at_ms
        ),
        (2, now - 10, now)
    );
    assert!(l.trusted.store_for_notes().unwrap().flush().unwrap());
    // A restart: a fresh process over the same files.
    let (mut again, view) = Trusted::new(Arc::new(|_| {}));
    again.attach(TrustStore::open_in(&l.dir.0));
    let after = shown(&view.borrow());
    assert_eq!(after.len(), 1, "{after:?}");
    assert_eq!(after[0].key_id, *recent.key_id());
    assert_eq!(after[0].count, 2);
    assert_eq!(again.attempts_of(5), after);
}

/// §10.2 «Попытка старше 30 дней не показывается»: with nothing else happening, the
/// orchestrator's tick republishes the view once the earliest shown attempt crosses its 30 days
/// by the PC's clock — the published view never keeps it. Before that the tick publishes nothing.
#[tokio::test]
async fn an_attempt_leaves_the_published_view_at_30_days_while_idle() {
    let (dir, _owner, _guest, _) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let attempt = |k: &ViewerKey, at: i64| crate::viewer_keys::Attempt {
        telegram_user_id: 5,
        role: BindingRole::Guest,
        key: k.clone(),
        kind: ClientKind::parse("telegram").unwrap(),
        platform: Platform::parse("iphone").unwrap(),
        rpk: None,
        first_at: at,
        last_at: at,
        count: 1,
    };
    let (early, later) = (key(), key());
    {
        let store = l.trusted.store_for_notes().unwrap();
        store.set_wall_now(now);
        assert!(store.note_attempt(attempt(&early, now - 1000), now - 1000));
        assert!(store.note_attempt(attempt(&later, now), now));
    }
    l.trusted.attempt_noted(5, later.key_id(), true, now);
    let shown = |l: &Loop| -> Vec<KeyId> {
        l.view()
            .people
            .iter()
            .find(|p| p.telegram_user_id == 5)
            .map(|p| p.attempts.iter().map(|a| a.key_id.clone()).collect())
            .unwrap_or_default()
    };
    assert_eq!(shown(&l).len(), 2);
    let keep = crate::viewer_keys::ATTEMPT_KEEP_MS;
    // Exactly 30 days after the early one: it still counts; the tick publishes nothing.
    let rev = l.view().rev;
    l.trusted
        .store_for_notes()
        .unwrap()
        .set_wall_now(now - 1000 + keep);
    l.trusted.tick(Instant::now());
    assert_eq!(l.view().rev, rev, "nothing aged out: no publish");
    // One ms past: the early one leaves the view; the later one stays.
    l.trusted
        .store_for_notes()
        .unwrap()
        .set_wall_now(now - 999 + keep);
    l.trusted.tick(Instant::now());
    assert_eq!(
        shown(&l),
        vec![later.key_id().clone()],
        "the early one aged out"
    );
    // Past the later one's 30 days too: nobody's attempts are shown.
    l.trusted
        .store_for_notes()
        .unwrap()
        .set_wall_now(now + 1 + keep);
    l.trusted.tick(Instant::now());
    assert!(shown(&l).is_empty(), "the later one aged out");
}

/// On the removal (§7, §10): a guest's grant refused at its stage under their removal — the
/// removal replaced the grant token, so `grant_stale` — is not written at all — nothing waits to
/// be written removed — and the same grant replayed later, after a restart, is still refused
/// `grant_stale`: the token closes it, not a spent id.
#[tokio::test]
async fn a_guest_grant_refused_under_the_removal_stays_refused_after_a_restart() {
    use crate::admission::{AdmitOp, StoreOp};
    let (dir, owner, _guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    // A change in flight ahead of the guest's grant.
    l.trusted.admit(AdmitOp {
        ticket: 2,
        op: StoreOp::add(
            new_key(&key()),
            grant_for(&owner, 11, 2, current(l.trusted.store().unwrap())),
        ),
    });
    let k = key();
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(
            new_key(&k),
            grant_for(&owner, 9, 3, current(l.trusted.store().unwrap())),
        ),
    });
    server_removes(&mut l, 9);
    for _ in 0..4 {
        l.release();
    }
    l.settle().await;
    let landed = landed_of(&mut l);
    assert!(
        matches!(&landed[&3], Err(StoreError::GrantStale)),
        "{:?}",
        landed[&3]
    );
    assert!(l.trusted.parked.is_empty(), "nothing waits");
    assert!(matches!(
        l.trusted.store().unwrap().lookup(k.key_id()),
        Lookup::Unknown
    ));
    let fresh = TrustStore::open_in(&l.dir.0);
    assert_eq!(
        fresh.check_add(
            &new_key(&k),
            &grant_for(&owner, 9, 3, GrantToken::default()),
            NOW + 2_000
        ),
        Err(StoreError::GrantStale),
        "the old grant replayed"
    );
}

/// The race (§7 «Смена», §10.1): K, granted by the laptop, was removed at the PC; the owner's
/// new invited grant over the current token is being written (staged, in flight) when «Удалить»
/// is pressed at the PC on the guest's key — any accepted removal press replaces the token. The
/// grant installs after the press: decided again by the token, it is `grant_stale`; K is denied
/// at once, never active, and leaves again (a removal of its own, `server`, as for every stale
/// landing). The removal press itself is answered and written. Without the token change at the
/// press the grant would land K.
#[tokio::test]
async fn a_removal_press_between_a_grants_stage_and_install_makes_it_stale() {
    use crate::admission::{AdmitOp, StoreOp};
    let (dir, _owner, guest, laptop) = seeded();
    let k = key();
    {
        let mut store = TrustStore::open_in(&dir.0);
        store
            .add(new_key(&k), grant_for(&laptop, 9, 3, current(&store)), NOW)
            .unwrap();
        store.remove(k.key_id(), Removal::Pc, NOW + 1).unwrap();
    }
    let mut l = Loop::open(dir).gated();
    let before = current(l.trusted.store().unwrap());
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(new_key(&k), grant_for(&laptop, 9, 4, before)),
    });
    assert!(l.trusted.busy(), "the returning grant is being written");
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    assert_ne!(
        current(l.trusted.store().unwrap()),
        before,
        "the press replaced the token at once"
    );
    let mut steps = 0;
    while l.trusted.busy() || !l.trusted.queue.is_empty() {
        l.release();
        l.step().await;
        steps += 1;
        let lookup = l.trusted.store().unwrap().lookup(k.key_id());
        assert!(
            !matches!(lookup, Lookup::Active(_)),
            "step {steps}: K is never active: {lookup:?}"
        );
    }
    let landed = landed_of(&mut l);
    assert!(
        matches!(&landed[&3], Err(StoreError::GrantStale)),
        "{:?}",
        landed[&3]
    );
    assert!(matches!(answered(&mut remove), Some(Ok(_))));
    let fresh = TrustStore::open_in(&l.dir.0);
    assert!(!matches!(fresh.lookup(k.key_id()), Lookup::Active(_)));
    assert_eq!(origin_of(&fresh, &guest), "pc");
    assert_ne!(current(&fresh), before, "the new token is written");
}

/// §7 «Смена», at the queue: an accepted «Удалить» of an owner-role key replaces the
/// grant token; a refused one (`not_found`, a key the list does not know; `session`, the trust
/// window locked) keeps it. A restart between the press and its write loses the press and its
/// token change together: the file has neither; after the write it has both.
#[tokio::test]
async fn a_removal_press_and_its_token_change_go_together() {
    let (dir, owner, guest, laptop) = seeded();
    let mut l = Loop::open(dir).gated();
    let start = current(l.trusted.store().unwrap());
    let mut unknown = l.ask(TrustedAsk::Remove {
        key_id: key().key_id().clone(),
    });
    assert_eq!(answered(&mut unknown), Some(Err(TrustedError::NotFound)));
    l.live = 1;
    let mut locked = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    assert_eq!(answered(&mut locked), Some(Err(TrustedError::Session)));
    l.live = 0;
    assert_eq!(current(l.trusted.store().unwrap()), start, "refused: kept");
    // The owner's laptop (an owner-role key): decided at the press, written later.
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: laptop.key_id().clone(),
    });
    let decided = current(l.trusted.store().unwrap());
    assert_ne!(decided, start, "an owner-role key's removal replaces it");
    // A restart now (the write not landed): neither the removal nor the token is on disk.
    let restarted = TrustStore::open_in(&l.dir.0);
    assert!(matches!(
        restarted.lookup(laptop.key_id()),
        Lookup::Active(_)
    ));
    assert_eq!(current(&restarted), start);
    drop(restarted);
    l.release();
    assert_eq!(l.step().await, "trusted_written");
    assert!(matches!(answered(&mut remove), Some(Ok(_))));
    let written = TrustStore::open_in(&l.dir.0);
    assert_eq!(origin_of(&written, &laptop), "pc");
    assert_eq!(current(&written), decided, "both landed in one write");
    assert!(matches!(written.lookup(owner.key_id()), Lookup::Active(_)));
}

/// An invited grant of `n` for `uid` signed by `by` whose invitation `inviter` signed.
fn grant_invited_by(
    by: &ViewerKey,
    inviter: &ViewerKey,
    uid: i64,
    n: u8,
    token: GrantToken,
) -> Ground {
    let Ground::Grant {
        by,
        grant_id,
        inv_id,
        invite,
        person,
        token,
    } = grant_for(by, uid, n, token)
    else {
        unreachable!("grant_for builds a grant")
    };
    Ground::Grant {
        by,
        grant_id,
        inv_id,
        invite: invite.map(|i| crate::viewer_keys::Invite {
            by: inviter.key_id().clone(),
            ..i
        }),
        person,
        token,
    }
}

/// Negative (§10.1, §7): a guest's invited grant K — granted by the owner's laptop, its
/// invitation signed by the owner's tablet — is being written (in flight) when «Удалить» is
/// pressed at the PC on its GRANTER, and separately on its INVITER that is not the granter. K
/// descends from the pressed key either way: it is never active at any step, the admission hears
/// `key_revoked` (its removal decided during its write), and K is removed `pc` on disk.
#[tokio::test]
async fn a_grant_in_flight_whose_granter_or_inviter_is_removed_never_lands_active() {
    use crate::admission::{AdmitOp, StoreOp};
    for pressed in ["granter", "inviter"] {
        let (dir, owner, _guest, laptop) = seeded();
        let tablet = key();
        {
            let mut store = TrustStore::open_in(&dir.0);
            store
                .add(
                    new_key(&tablet),
                    Ground::Endorse {
                        by: owner.key_id().clone(),
                        endorse_id: gid(2),
                        issued_at: ISSUED,
                    },
                    NOW,
                )
                .unwrap();
        }
        let mut l = Loop::open(dir).gated();
        let k = key();
        l.trusted.admit(AdmitOp {
            ticket: 3,
            op: StoreOp::add(
                new_key(&k),
                grant_invited_by(&laptop, &tablet, 9, 3, current(l.trusted.store().unwrap())),
            ),
        });
        assert!(l.trusted.busy(), "{pressed}: the grant is being written");
        let target = if pressed == "granter" {
            &laptop
        } else {
            &tablet
        };
        let mut remove = l.ask(TrustedAsk::Remove {
            key_id: target.key_id().clone(),
        });
        settle_never_active(&mut l, &k).await;
        let landed = landed_of(&mut l);
        assert!(
            // `Removed` is what the admission answers `key_revoked` (`store_fail`).
            matches!(&landed[&3], Err(StoreError::Removed { .. })),
            "{pressed}: key_revoked: {:?}",
            landed[&3]
        );
        assert!(matches!(answered(&mut remove), Some(Ok(_))), "{pressed}");
        let fresh = TrustStore::open_in(&l.dir.0);
        assert_eq!(origin_of(&fresh, &k), "pc", "{pressed}: K removed on disk");
        assert_eq!(origin_of(&fresh, target), "pc", "{pressed}");
        let spared = if pressed == "granter" {
            &tablet
        } else {
            &laptop
        };
        assert!(
            matches!(fresh.lookup(spared.key_id()), Lookup::Active(_)),
            "{pressed}: the other signer stays"
        );
    }
}

/// Negative (§10.1): a key P that the guest's key endorsed is being written (in flight, through
/// the trusted queue — no other writer) when «Удалить» is pressed at the PC on its signer. P is
/// never active at any step, the admission hears `key_revoked`, and P is removed `pc` on disk.
#[tokio::test]
async fn an_endorse_in_flight_whose_signer_is_removed_never_lands_active() {
    use crate::admission::{AdmitOp, StoreOp};
    let (dir, _owner, guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let p = key();
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(
            new_key(&p),
            Ground::Endorse {
                by: guest.key_id().clone(),
                endorse_id: gid(7),
                issued_at: ISSUED,
            },
        ),
    });
    assert!(l.trusted.busy(), "the endorse is being written");
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    settle_never_active(&mut l, &p).await;
    let landed = landed_of(&mut l);
    assert!(
        // `Removed` is what the admission answers `key_revoked` (`store_fail`).
        matches!(&landed[&3], Err(StoreError::Removed { .. })),
        "key_revoked: {:?}",
        landed[&3]
    );
    assert!(matches!(answered(&mut remove), Some(Ok(_))));
    let fresh = TrustStore::open_in(&l.dir.0);
    assert_eq!(origin_of(&fresh, &p), "pc", "P removed on disk");
    assert_eq!(origin_of(&fresh, &guest), "pc");
}

/// §10 «Одно правило возврата»: a key removed at the PC comes back by a new endorse of its
/// person's device; a removal press on that signer during the endorse's write (the install
/// decides again) refuses it `key_revoked` — never active, both removals on disk as `pc`.
#[tokio::test]
async fn a_returning_key_whose_signer_is_removed_during_its_write_never_lands_active() {
    use crate::admission::{AdmitOp, StoreOp};
    let (dir, _owner, guest, _) = seeded();
    let p = key();
    {
        let mut store = TrustStore::open_in(&dir.0);
        store
            .add(new_key(&p), pair(5, BindingRole::Guest, false), NOW)
            .unwrap();
        store.remove(p.key_id(), Removal::Pc, NOW + 1).unwrap();
    }
    let mut l = Loop::open(dir).gated();
    assert_eq!(origin_of(l.trusted.store().unwrap(), &p), "pc");
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(
            new_key(&p),
            Ground::Endorse {
                by: guest.key_id().clone(),
                endorse_id: gid(7),
                issued_at: ISSUED,
            },
        ),
    });
    assert!(l.trusted.busy(), "the returning endorse is being written");
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    settle_never_active(&mut l, &p).await;
    let landed = landed_of(&mut l);
    assert!(
        // `Removed` is what the admission answers `key_revoked` (`store_fail`).
        matches!(&landed[&3], Err(StoreError::Removed { .. })),
        "key_revoked: {:?}",
        landed[&3]
    );
    assert!(matches!(answered(&mut remove), Some(Ok(_))));
    let fresh = TrustStore::open_in(&l.dir.0);
    assert_eq!(origin_of(&fresh, &p), "pc", "P removed again on disk");
    assert_eq!(origin_of(&fresh, &guest), "pc");
}

/// Negative (§7 «Смена», the covered press): «Удалить» on the guest's key replaces the token —
/// the new one unsaved while its write is in flight — and «Удалить» on the laptop meanwhile is
/// covered by it (no second replacement: the new token was never heard). The server hears only a
/// written token: the old one until the first write lands, then the new one — never a token it
/// held at either press. A grant over the old token is `grant_stale`; a grant over the token the
/// server hears next passes, and only once both removals are in the written snapshot.
#[tokio::test]
async fn a_covered_press_lets_a_grant_over_the_next_heard_token_land_only_after_both_removals() {
    use crate::admission::{AdmitOp, LandedOutcome, StoreOp};
    let (dir, owner, guest, laptop) = seeded();
    let mut l = Loop::open(dir).gated();
    let heard = |l: &Loop| l.trusted.store().unwrap().saved_grant_token().unwrap();
    let before = heard(&l);
    let mut first = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    let replaced = current(l.trusted.store().unwrap());
    assert_ne!(replaced, before, "the first press replaced the token");
    assert!(l.trusted.store().unwrap().grant_token_unsaved());
    let mut second = l.ask(TrustedAsk::Remove {
        key_id: laptop.key_id().clone(),
    });
    assert_eq!(
        current(l.trusted.store().unwrap()),
        replaced,
        "covered: replaced once until written"
    );
    assert_eq!(heard(&l), before, "nothing new heard before a write");
    let (old, new) = (key(), key());
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(new_key(&old), grant_for(&owner, 9, 3, before)),
    });
    let both_written = |l: &Loop| {
        let disk = TrustStore::open_in(&l.dir.0);
        [&guest, &laptop]
            .iter()
            .all(|k| matches!(disk.lookup(k.key_id()), Lookup::Removed(_)))
    };
    let mut landed = HashMap::new();
    let mut asked_new = false;
    let mut steps = 0;
    while l.trusted.busy() || !l.trusted.queue.is_empty() || !asked_new {
        if !asked_new && heard(&l) != before {
            // The server hears the next token now — the first removal written, the second still
            // on its way: the owner's grant over it waits behind that removal's write.
            assert_eq!(
                heard(&l),
                replaced,
                "step {steps}: the covered token, not a third"
            );
            assert!(
                !both_written(&l),
                "step {steps}: heard before the second write"
            );
            l.trusted.admit(AdmitOp {
                ticket: 4,
                op: StoreOp::add(new_key(&new), grant_for(&owner, 11, 4, replaced)),
            });
            asked_new = true;
        }
        assert!(
            heard(&l) == before || heard(&l) == replaced,
            "step {steps}: only a written token is heard"
        );
        l.release();
        l.step().await;
        steps += 1;
        for (ticket, result) in landed_of(&mut l) {
            if ticket == 4 && result.is_ok() {
                assert!(
                    both_written(&l),
                    "step {steps}: the grant over the new token landed before both removals were written"
                );
            }
            landed.insert(ticket, result);
        }
    }
    assert!(
        matches!(&landed[&3], Err(StoreError::GrantStale)),
        "{:?}",
        landed[&3]
    );
    assert!(
        matches!(&landed[&4], Ok(LandedOutcome::Added(_))),
        "{:?}",
        landed[&4]
    );
    assert!(matches!(answered(&mut first), Some(Ok(_))));
    assert!(matches!(answered(&mut second), Some(Ok(_))));
    let fresh = TrustStore::open_in(&l.dir.0);
    assert_eq!(
        current(&fresh),
        replaced,
        "one token for both presses, written"
    );
    assert!(matches!(fresh.lookup(new.key_id()), Lookup::Active(_)));
    assert!(!matches!(fresh.lookup(old.key_id()), Lookup::Active(_)));
}

// --- A recovery landing under a removal ---------------------------------------------------------

/// Item 6 (b): B's recovery (Y replaces B) is being written when the person removes B at the PC
/// («Удалить», denied at once). The recovery installs: Y joins as the replacer of a denied key —
/// denied too, never active — and the tree removal, walked again at its stage, does not reach Y
/// (a recovery is not a descendant of the record it replaced: the walk goes from a recovery on
/// to its replaced records, never back), so Y's own removal comes from the fallback after the
/// change (`after_change`): the landing is refused as removed (`key_revoked`), Y ends removed
/// `pc`, on disk too, and nothing stays denied without a removal. Through the PC's window this order cannot happen — the recovery is a first offer
/// waiting for its write, which locks «Удалить» (§10.1) — so this is defence in depth: the queue
/// is driven directly here (no live session counted).
#[tokio::test]
async fn a_recovery_landing_after_its_replaced_key_was_removed_is_removed_too() {
    use crate::admission::{AdmitOp, RecoverChange, StoreOp};
    use aws_lc_rs::rand::SystemRandom;
    let (dir, _owner, _guest, _) = seeded();
    // B: the owner's tablet, with a recovery key.
    let rk = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    let mut spki = SPKI_PREFIX.to_vec();
    spki.extend_from_slice(rk.public_key().as_ref());
    let rpk = ViewerKey::from_spki(&spki).unwrap();
    let b = key();
    TrustStore::open_in(&dir.0)
        .add(
            NewKey {
                rpk: Some(rpk.clone()),
                ..new_key(&b)
            },
            pair(1, BindingRole::Owner, false),
            NOW,
        )
        .unwrap();
    let mut l = Loop::open(dir).gated();
    let y = key();
    let nonce_pc = [7u8; 16];
    let r = crate::viewer_keys::wire::recover_message("dev-1", "s-rec", y.key_id(), &nonce_pc);
    let rsig = rk.sign(&SystemRandom::new(), &r).unwrap().as_ref().to_vec();
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::Recover(Box::new(RecoverChange {
            rpk,
            attested: crate::viewer_keys::TelegramIdentity::for_tests(
                1,
                Some("P1"),
                None,
                y.key_id().clone(),
            ),
            device_id: "dev-1".into(),
            session_id: "s-rec".into(),
            nonce_pc,
            rsig,
            new_key: y.clone(),
            kind: ClientKind::parse("telegram").unwrap(),
            platform: Platform::parse("iphone").unwrap(),
        })),
    });
    assert!(l.trusted.busy(), "the recovery is staged, its write held");
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: b.key_id().clone(),
    });
    assert!(matches!(
        l.trusted.store().unwrap().lookup(b.key_id()),
        Lookup::PendingRemoval(_)
    ));
    l.release();
    assert_eq!(l.step().await, "trusted_written");
    let landed = landed_of(&mut l);
    // Its removal was decided during its write: the landing is refused as removed (`key_revoked`).
    assert!(
        matches!(&landed[&3], Err(StoreError::Removed { key_id, origin: "pc" }) if key_id == y.key_id()),
        "{:?}",
        landed[&3]
    );
    // Installed under the denied B: Y is denied, its mark inherited from B.
    let store = l.trusted.store().unwrap();
    assert!(matches!(
        store.lookup(y.key_id()),
        Lookup::PendingRemoval(_)
    ));
    let pending = store.pending_without_removal();
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(&pending[0].key_id, y.key_id());
    assert_eq!(pending[0].inherited_from.as_ref(), Some(b.key_id()));
    let mut steps = 0;
    while l.trusted.busy() || !l.trusted.queue.is_empty() {
        l.release();
        l.step().await;
        steps += 1;
        assert!(steps < 10, "the queue settles");
        let lookup = l.trusted.store().unwrap().lookup(y.key_id());
        assert!(
            !matches!(lookup, Lookup::Active(_)),
            "step {steps}: Y is never active: {lookup:?}"
        );
    }
    assert!(answered(&mut remove).is_some(), "the removal answered");
    let store = l.trusted.store().unwrap();
    match store.lookup(y.key_id()) {
        Lookup::Removed(t) => assert_eq!(t.origin.as_str(), "pc"),
        other => panic!("Y removed: {other:?}"),
    }
    assert!(store.pending_without_removal().is_empty());
    let reopened = TrustStore::open_in(&l.dir.0);
    assert!(matches!(reopened.lookup(y.key_id()), Lookup::Removed(_)));
    assert!(matches!(reopened.lookup(b.key_id()), Lookup::Removed(_)));
}

/// The window's removals («Удалить из доверенных», «Удалить все устройства») pass in both modes
/// (with the switch off they matter once it goes on): a device with its
/// descendants, and a person's every key.
#[tokio::test]
async fn the_windows_removals_pass_with_the_mode_off_and_on() {
    for strict in [false, true] {
        let (dir, owner, guest, laptop) = seeded();
        if strict {
            TrustStore::open_in(&dir.0)
                .set_trusted_devices_mode(true)
                .unwrap();
        }
        let mut l = Loop::open(dir);
        assert_eq!(l.view().trusted_mode, strict);
        let mut device = l.ask(TrustedAsk::Remove {
            key_id: owner.key_id().clone(),
        });
        let mut person = l.ask(TrustedAsk::RemovePerson {
            telegram_user_id: 5,
        });
        l.settle().await;
        assert_eq!(answered(&mut device), Some(Ok(2)), "strict {strict}");
        assert_eq!(answered(&mut person), Some(Ok(1)), "strict {strict}");
        let store = l.trusted.store().unwrap();
        for k in [&owner, &laptop, &guest] {
            assert!(
                matches!(store.lookup(k.key_id()), Lookup::Removed(_)),
                "strict {strict}"
            );
        }
        let view = l.view();
        assert!(view.people.is_empty(), "strict {strict}");
        assert_eq!(view.trusted_mode, strict, "the switch stays");
    }
}

/// A damaged list's view carries the switch the admission decides by: the mode file's, strict
/// when the file is missing (the window then says the strict «никто не подключится»).
#[tokio::test]
async fn a_damaged_lists_view_says_the_mode_files_switch() {
    for (strict, mode_file) in [(false, true), (true, true), (true, false)] {
        let (dir, _, _, _) = seeded();
        if strict {
            TrustStore::open_in(&dir.0)
                .set_trusted_devices_mode(true)
                .unwrap();
        }
        if !mode_file {
            std::fs::remove_file(dir.0.join("viewer_keys.mode")).unwrap();
        }
        std::fs::write(dir.0.join(FILE_NAME), b"{ not json").unwrap();
        let l = Loop::open(dir);
        let view = l.view();
        assert!(view.damage.is_some());
        assert_eq!(
            view.trusted_mode, strict,
            "switch {strict}, mode file {mode_file}"
        );
    }
    let (_, view) = Trusted::new(Arc::new(|_| {}));
    assert!(view.borrow().trusted_mode, "no list: strict");
}

/// «Восстановить» carries the token its dialog opened with (as confirm and mode-on): a session
/// that came and went since refuses it with `session` and the list stays damaged; a fresh dialog's
/// token restores it.
#[tokio::test]
async fn a_restore_from_a_dialog_older_than_a_session_is_refused() {
    let (dir, _, _, _) = seeded();
    std::fs::write(dir.0.join(FILE_NAME), b"{ not json").unwrap();
    let mut l = Loop::open(dir);
    assert!(l.view().damage.unwrap().can_restore);
    let opened = l.view().token;
    l.trusted.session_began("session_request", "s1");
    l.live = 1;
    l.live = 0;
    l.trusted.sync_live(0);
    assert!(l.view().clean);
    let mut stale = l.ask(TrustedAsk::Repair(RepairAction::Restore { token: opened }));
    assert_eq!(answered(&mut stale), Some(Err(TrustedError::Session)));
    assert!(!l.trusted.busy(), "nothing staged");
    assert!(l.view().damage.is_some(), "still damaged");
    let mut fresh = l.ask(restore_ask(&l));
    l.settle().await;
    assert_eq!(answered(&mut fresh), Some(Ok(0)));
    assert!(l.view().damage.is_none());
}

/// A restore accepted into the queue (behind a write in flight) whose window passes before it is
/// staged — a session began meanwhile — is refused `session` at its stage, and the list stays
/// damaged.
#[tokio::test]
async fn a_restore_queued_behind_a_write_is_refused_when_a_session_begins_before_its_stage() {
    let (dir, _, _, _) = seeded();
    std::fs::write(dir.0.join(FILE_NAME), b"{ not json").unwrap();
    let mut l = Loop::open(dir).gated();
    assert!(l.view().damage.unwrap().can_restore);
    let mut reopen = l.ask(TrustedAsk::Repair(RepairAction::Reopen));
    assert!(l.trusted.busy(), "the reopen is in flight");
    let mut restore = l.ask(restore_ask(&l));
    assert!(
        answered(&mut restore).is_none(),
        "accepted, queued behind it"
    );
    l.trusted.session_began("session_request", "s9");
    l.live = 1;
    l.release();
    l.settle().await;
    assert!(answered(&mut reopen).is_some(), "the reopen answered");
    assert_eq!(answered(&mut restore), Some(Err(TrustedError::Session)));
    assert!(l.view().damage.is_some(), "still damaged: nothing restored");
    assert_eq!(
        std::fs::read(l.dir.0.join(FILE_NAME)).unwrap(),
        b"{ not json",
        "the damaged file untouched"
    );
}

// --- «Удалить человека» (§10, §10.2) and carried removals (§10.1) -------------------------------

/// Every write of the list fails from now on (an injected I/O error: the backup's path is a
/// directory) until [`unjam`].
fn jam(dir: &Scratch) -> PathBuf {
    let jam = dir.0.join(crate::viewer_keys::BACKUP_FILE_NAME);
    let _ = std::fs::remove_file(&jam);
    std::fs::create_dir_all(jam.join("jam")).unwrap();
    jam
}

fn unjam(jam: &PathBuf) {
    std::fs::remove_dir_all(jam).unwrap();
}

fn origin_of(store: &TrustStore, k: &ViewerKey) -> &'static str {
    match store.lookup(k.key_id()) {
        Lookup::Removed(t) => t.origin.as_str(),
        other => panic!("{} is not removed: {other:?}", k.key_id().short()),
    }
}

/// An invited grant of `n` for `uid` signed by `by` over the grant token `token`.
fn grant_for(by: &ViewerKey, uid: i64, n: u8, token: GrantToken) -> Ground {
    Ground::Grant {
        by: by.key_id().clone(),
        grant_id: gid(n),
        inv_id: Some(gid(n.wrapping_add(100))),
        invite: Some(crate::viewer_keys::Invite {
            inv_id: gid(n.wrapping_add(100)),
            by: by.key_id().clone(),
        }),
        person: person(uid),
        token,
    }
}

/// The PC's current grant token: what a grant signed now carries.
fn current(store: &TrustStore) -> GrantToken {
    store.grant_token().unwrap_or_default()
}

/// «Удалить человека» for guest 5 (an active key G, a key G2 the server removed): the press
/// decides at once — G denied, the token replaced; G2 stays `server` (a walk changes no
/// tombstone) — while its write FAILS (injected)
/// and parks: nothing of it is on disk. The next write that lands — an unrelated mode switch —
/// carries the keys; the parked retry then finds nothing left and writes and journals nothing
/// (G journaled once, with the write that took it). A fresh process reads G `pc`, G2 `server`; a later
/// grant for 5 over the current token passes, one over the old token is `grant_stale`; an
/// unconfirmed add of G is refused, a confirmed pairing at the PC brings G back.
#[tokio::test]
async fn a_person_removed_at_the_pc_is_carried_by_the_next_write() {
    let (dir, owner, guest, _) = seeded();
    let g2 = key();
    {
        let mut store = TrustStore::open_in(&dir.0);
        store
            .add(new_key(&g2), pair(5, BindingRole::Guest, false), NOW)
            .unwrap();
        store.remove(g2.key_id(), Removal::Server, NOW).unwrap();
    }
    let jammed = jam(&dir);
    let mut l = Loop::open(dir);
    let mut remove = l.ask(TrustedAsk::RemovePerson {
        telegram_user_id: 5,
    });
    // Decided at the press, before any write.
    {
        let store = l.trusted.store().unwrap();
        assert!(matches!(
            store.lookup(guest.key_id()),
            Lookup::PendingRemoval(_)
        ));
        assert_eq!(origin_of(store, &g2), "server");
    }
    l.settle().await;
    assert_eq!(answered(&mut remove), Some(Err(TrustedError::WriteFailed)));
    assert_eq!(l.trusted.parked.len(), 1);
    let on_disk = TrustStore::open_in(&l.dir.0);
    assert!(matches!(on_disk.lookup(guest.key_id()), Lookup::Active(_)));
    assert_eq!(origin_of(&on_disk, &g2), "server");
    // Memory still denies the key.
    {
        let store = l.trusted.store().unwrap();
        assert!(matches!(
            store.lookup(guest.key_id()),
            Lookup::PendingRemoval(_)
        ));
        assert_eq!(origin_of(store, &g2), "server");
    }
    assert!(
        l.kinds().is_empty(),
        "nothing journaled while nothing landed"
    );

    // An unrelated write lands: it carries the removal.
    unjam(&jammed);
    let token = l.view().token;
    let mut on = l.ask(TrustedAsk::SetMode {
        on: true,
        token: Some(token),
    });
    // The mode switch's write alone (the parked retry is queued only after it lands).
    assert_eq!(l.step().await, "trusted_written");
    assert_eq!(answered(&mut on), Some(Ok(0)));
    {
        let carried = TrustStore::open_in(&l.dir.0);
        assert_eq!(origin_of(&carried, &guest), "pc");
        assert_eq!(origin_of(&carried, &g2), "server");
    }
    l.settle().await;
    assert!(l.trusted.parked.is_empty(), "the parked retry ran");
    assert_eq!(
        l.kinds()
            .iter()
            .filter(|k| **k == Kind::DeviceUntrusted)
            .count(),
        1,
        "G journaled once, with the write that took it; the retry journals nothing"
    );
    let fresh = TrustStore::open_in(&l.dir.0);
    assert_eq!(origin_of(&fresh, &guest), "pc");
    assert_eq!(origin_of(&fresh, &g2), "server");
    assert!(fresh.switches().unwrap().trusted_devices_mode);

    // A later grant for 5 by the confirmed owner: it passes over the current token; one signed
    // over the token before the press is grant_stale.
    let now = crate::journal::now_ms();
    let fresh_key = key();
    for (n, token, refused) in [
        (20, current(&fresh), None),
        (21, GrantToken::default(), Some("grant_stale")),
    ] {
        let got = fresh.check_add(&new_key(&fresh_key), &grant_for(&owner, 5, n, token), now);
        assert_eq!(
            got.map(|_| ()).map_err(|e| e.as_str()).err(),
            refused,
            "{n}"
        );
    }
    // A pairing at the PC: an unconfirmed add of G is refused (its tombstone is `pc`), a
    // confirmed one brings G back. (Observe mode, so that the refusal is the removal's and not
    // strict mode's.)
    drop(fresh);
    TrustStore::open_in(&l.dir.0)
        .set_trusted_devices_mode(false)
        .unwrap();
    let mut fresh = TrustStore::open_in(&l.dir.0);
    assert!(matches!(
        fresh.add(new_key(&guest), pair(5, BindingRole::Guest, true), now),
        Err(StoreError::Removed { origin: "pc", .. })
    ));
    fresh
        .add(new_key(&guest), pair(5, BindingRole::Guest, false), now)
        .unwrap();
    assert!(matches!(fresh.lookup(guest.key_id()), Lookup::Active(_)));
}

/// Never for the owner: by the PC's keys (person 1), or by the server's bindings (person 5 bound
/// as the owner) — refused `owner` at the press, nothing denied, nothing queued.
#[tokio::test]
async fn removing_the_owner_as_a_person_is_refused() {
    let (dir, owner, guest, laptop) = seeded();
    let mut l = Loop::open(dir);
    let mut by_keys = l.ask(TrustedAsk::RemovePerson {
        telegram_user_id: 1,
    });
    assert_eq!(answered(&mut by_keys), Some(Err(TrustedError::Owner)));
    let (reply, mut by_binding) = oneshot::channel();
    l.trusted.command_at(
        TrustedRequest {
            ask: TrustedAsk::RemovePerson {
                telegram_user_id: 5,
            },
            reply,
        },
        0,
        Some(BindingRole::Owner),
    );
    assert_eq!(answered(&mut by_binding), Some(Err(TrustedError::Owner)));
    assert!(!l.trusted.busy() && l.trusted.queue.is_empty() && l.trusted.parked.is_empty());
    let store = l.trusted.store().unwrap();
    for k in [&owner, &laptop, &guest] {
        assert!(matches!(store.lookup(k.key_id()), Lookup::Active(_)));
    }
    assert_eq!(TrustedError::Owner.as_str(), "owner");
}

/// A guest with attempts only (no key, no removed key) — «Удалить попытки», the same action: the
/// attempts go and the token is replaced, in one write; a fresh process reads both.
#[tokio::test]
async fn a_guest_with_attempts_only_loses_them() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let tried = key();
    {
        let store = l.trusted.store.as_mut().unwrap();
        assert!(store.note_attempt(
            crate::viewer_keys::Attempt {
                telegram_user_id: 9,
                role: BindingRole::Guest,
                key: tried.clone(),
                kind: ClientKind::parse("telegram").unwrap(),
                platform: Platform::parse("android").unwrap(),
                rpk: None,
                first_at: now,
                last_at: now,
                count: 1,
            },
            now,
        ));
        assert!(store.flush().unwrap());
    }
    assert_eq!(TrustStore::open_in(&l.dir.0).attempts().len(), 1);
    let (reply, mut rx) = oneshot::channel();
    l.trusted.command_at(
        TrustedRequest {
            ask: TrustedAsk::RemovePerson {
                telegram_user_id: 9,
            },
            reply,
        },
        0,
        Some(BindingRole::Guest),
    );
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Ok(0)));
    let fresh = TrustStore::open_in(&l.dir.0);
    assert!(fresh.attempts().is_empty(), "the attempts went");
    // A person the PC does not know at all: the press goes too, and replaces the token (every
    // removal press does, §7).
    let token = current(l.trusted.store().unwrap());
    let mut stranger = l.ask(TrustedAsk::RemovePerson {
        telegram_user_id: 77,
    });
    l.settle().await;
    assert_eq!(answered(&mut stranger), Some(Ok(0)));
    assert_ne!(current(l.trusted.store().unwrap()), token);
}

/// «Удалить попытки» for a person whose attempts aged out (31 days old: the PC holds nothing of
/// them) is no `not_found` (§7: every accepted removal press replaces the token): answered with
/// nothing removed, the token replaced once at the press, and a write queued that carries it — the
/// file holds the press's token after it, and no second replacement follows.
#[tokio::test]
async fn removing_the_attempts_of_a_person_whose_attempts_aged_out_replaces_the_token_once() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let now = crate::journal::now_ms();
    let old = now - crate::viewer_keys::ATTEMPT_KEEP_MS - 86_400_000;
    let tried_9 = key();
    tried(&mut l, 9, &tried_9, old);
    assert!(l.trusted.attempts_of(9).is_empty(), "aged out");
    let start = current(l.trusted.store().unwrap());
    let mut attempts = l.ask(TrustedAsk::RemovePerson {
        telegram_user_id: 9,
    });
    let decided = current(l.trusted.store().unwrap());
    assert_ne!(decided, start, "the press replaced the token");
    assert!(l.trusted.busy(), "a write is queued");
    l.release();
    assert_eq!(l.step().await, "trusted_written");
    assert!(!l.trusted.busy() && l.trusted.queue.is_empty(), "one write");
    assert_eq!(
        answered(&mut attempts),
        Some(Ok(0)),
        "accepted, nothing removed"
    );
    assert_eq!(
        current(l.trusted.store().unwrap()),
        decided,
        "replaced once"
    );
    assert_eq!(current(&TrustStore::open_in(&l.dir.0)), decided, "written");
}

/// A guest untrusted at the PC whose write fails (injected) and parks: their key is carried by
/// the next write that lands — an unrelated mode switch — as `pc`, journaled once with it; the
/// parked retry finds nothing left. Without the carry the key stays active on disk after it.
#[tokio::test]
async fn a_parked_guest_untrust_is_carried_by_the_next_write() {
    let (dir, _, guest, _) = seeded();
    let jammed = jam(&dir);
    let mut l = Loop::open(dir);
    l.trusted.untrust_guest(5, 0);
    l.settle().await;
    assert_eq!(l.trusted.parked.len(), 1);
    assert!(matches!(
        TrustStore::open_in(&l.dir.0).lookup(guest.key_id()),
        Lookup::Active(_)
    ));
    unjam(&jammed);
    let token = l.view().token;
    let mut on = l.ask(TrustedAsk::SetMode {
        on: true,
        token: Some(token),
    });
    // Only the mode switch's write: the parked untrust is queued after it lands.
    assert_eq!(l.step().await, "trusted_written");
    assert_eq!(answered(&mut on), Some(Ok(0)));
    assert_eq!(origin_of(&TrustStore::open_in(&l.dir.0), &guest), "pc");
    l.settle().await;
    assert!(l.trusted.parked.is_empty());
    assert_eq!(
        l.kinds()
            .iter()
            .filter(|k| **k == Kind::DeviceUntrusted)
            .count(),
        1
    );
}

// --- §10.2 «Разрешить» / «Скрыть», §10 «Забыть удаления», the second steps ---------------------

/// Another device's attempt for `uid` with key `k`, tried last at `at`, noted on the list (memory)
/// and written.
fn tried(l: &mut Loop, uid: i64, k: &ViewerKey, at: i64) {
    let store = l.trusted.store.as_mut().unwrap();
    assert!(store.note_attempt(
        crate::viewer_keys::Attempt {
            telegram_user_id: uid,
            role: BindingRole::Guest,
            key: k.clone(),
            kind: ClientKind::parse("telegram").unwrap(),
            platform: Platform::parse("android").unwrap(),
            rpk: None,
            first_at: at,
            last_at: at,
            count: 1,
        },
        at,
    ));
    store.flush().unwrap();
    l.trusted.publish("test: an attempt");
}

/// «Разрешить» as the window sends it for a guest's attempt (the role it shows: a guest's).
fn allow(k: &ViewerKey, uid: i64, token: u64, second_step: bool) -> TrustedAsk {
    allow_as(k, uid, token, second_step, BindingRole::Guest)
}

/// «Разрешить» naming `role`, the one the window showed.
fn allow_as(
    k: &ViewerKey,
    uid: i64,
    token: u64,
    second_step: bool,
    role: BindingRole,
) -> TrustedAsk {
    TrustedAsk::AttemptAllow {
        telegram_user_id: uid,
        key_id: k.key_id().clone(),
        token,
        second_step,
        role,
    }
}

/// «Разрешить» with the owner's second step «Это моё устройство».
fn allow_step_as(k: &ViewerKey, uid: i64, token: u64, role: BindingRole) -> TrustedAsk {
    allow_as(k, uid, token, true, role)
}

fn on_disk(l: &Loop, k: &ViewerKey) -> Option<(BindingRole, bool)> {
    match TrustStore::open_in(&l.dir.0).lookup(k.key_id()) {
        Lookup::Active(r) => Some((r.role, r.unconfirmed)),
        _ => None,
    }
}

/// «Разрешить» for a guest is one press: the key joins confirmed as a guest's (a pairing at the
/// PC), the attempt goes, the journal says «Новое устройство». A guest removed at the PC is let
/// back the same way: one press, no second step.
#[tokio::test]
async fn allow_lets_a_guest_in_with_one_press_even_after_a_removal() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let plain = key();
    tried(&mut l, 9, &plain, now);
    let token = l.view().token;
    let mut rx = l.ask(allow(&plain, 9, token, false));
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Ok(0)), "confirmed");
    assert_eq!(on_disk(&l, &plain), Some((BindingRole::Guest, false)));
    assert!(TrustStore::open_in(&l.dir.0).attempts().is_empty());
    assert!(l.kinds().contains(&Kind::DeviceAdded));

    // The seeded guest removed at the PC, then a new device of theirs tries.
    l.trusted.untrust_guest(5, 0);
    l.settle().await;
    let back = key();
    tried(&mut l, 5, &back, now);
    let token = l.view().token;
    let mut rx = l.ask(allow(&back, 5, token, false));
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Ok(0)), "one press");
    assert_eq!(on_disk(&l, &back), Some((BindingRole::Guest, false)));
}

/// The owner — by the PC's keys or by the server's bindings — needs the second step too, and gets
/// only the owner's role (§5): an owner by the bindings with no key here too — the view promises
/// it (`role`) and the press writes it.
#[tokio::test]
async fn allow_for_the_owner_needs_the_second_step() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let phone = key();
    tried(&mut l, 1, &phone, now);
    let token = l.view().token;
    let mut rx = l.ask(allow_as(&phone, 1, token, false, BindingRole::Owner));
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::SecondStep)));
    let mut rx = l.ask(allow_step_as(&phone, 1, token, BindingRole::Owner));
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Ok(0)));
    assert_eq!(on_disk(&l, &phone), Some((BindingRole::Owner, false)));

    // Bound as the owner (the bindings the agent keeps), no key here.
    let other = key();
    tried(&mut l, 12, &other, now);
    let token = l.view().token;
    assert!(!l
        .view()
        .people
        .iter()
        .any(|p| p.telegram_user_id == 12 && p.needs_second_step));
    l.trusted.set_bound_owners([12]);
    let person = l
        .view()
        .people
        .iter()
        .find(|p| p.telegram_user_id == 12)
        .cloned()
        .unwrap();
    assert!(person.needs_second_step && person.devices.is_empty());
    assert_eq!(
        person.role,
        BindingRole::Owner,
        "the owner by the bindings, no key here: the owner's role all the same"
    );
    let mut rx = l.ask(allow_as(&other, 12, token, false, BindingRole::Owner));
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::SecondStep)));
    let mut rx = l.ask(allow_step_as(&other, 12, token, BindingRole::Owner));
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Ok(0)));
    assert_eq!(on_disk(&l, &other), Some((BindingRole::Owner, false)));
}

/// §5, §10.2: the owner by the bindings with no key at all gets his device back with an attempt's «Разрешить» and «Это моё устройство»:
/// an owner key, confirmed, and the strict switch's reading turns ready. Never a guest key.
#[tokio::test]
async fn an_owner_by_bindings_without_keys_gets_an_owner_key_and_the_switch() {
    let (dir, _) = list_of(&[]);
    let mut l = Loop::open(dir);
    l.trusted.set_bound_owners([1]);
    assert_eq!(l.view().owner_device, OwnerDevice::Missing);
    let now = crate::journal::now_ms();
    let phone = key();
    tried(&mut l, 1, &phone, now);
    let person = l
        .view()
        .people
        .iter()
        .find(|p| p.telegram_user_id == 1)
        .cloned()
        .unwrap();
    assert_eq!(person.role, BindingRole::Owner, "the owner's promise");
    assert!(person.needs_second_step);
    let token = l.view().token;
    let mut rx = l.ask(allow(&phone, 1, token, true));
    assert_eq!(
        answered(&mut rx),
        Some(Err(TrustedError::Role)),
        "a guest's press: the window showed no owner"
    );
    let mut rx = l.ask(allow_as(&phone, 1, token, false, BindingRole::Owner));
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::SecondStep)));
    assert_eq!(on_disk(&l, &phone), None, "no step: nothing written");
    let mut rx = l.ask(allow_step_as(&phone, 1, token, BindingRole::Owner));
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Ok(0)));
    assert_eq!(on_disk(&l, &phone), Some((BindingRole::Owner, false)));
    assert_eq!(l.view().owner_device, OwnerDevice::Ready);
    assert!(
        matches!(mode_on(&mut l).await, Some(Ok(_))),
        "the switch goes on now"
    );
}

/// §10.2: «Разрешить» names the role the window showed. Another one derived at the press is
/// refused `role` at once; one derived otherwise at the write — the bindings moved while the press
/// waited in the queue behind another change — cancels it whole (`role`): nothing written, the
/// attempt stays. Control: the role kept, the owner's key lands.
#[tokio::test]
async fn an_attempts_allow_keeps_the_role_its_press_named() {
    for moved in [true, false] {
        let (dir, _) = list_of(&[(1, BindingRole::Owner, false)]);
        let mut l = Loop::open(dir).gated();
        l.trusted.set_bound_owners([1, 3]);
        let now = crate::journal::now_ms();
        let phone = key();
        tried(&mut l, 3, &phone, now);
        let other = key();
        tried(&mut l, 9, &other, now);
        let token = l.view().token;
        let mut rx = l.ask(allow_as(&phone, 3, token, true, BindingRole::Guest));
        assert_eq!(
            answered(&mut rx),
            Some(Err(TrustedError::Role)),
            "a guest's press for the owner by the bindings"
        );
        // A guest's allow in flight first: the owner's press waits behind it.
        let mut first = l.ask(allow(&other, 9, token, false));
        let mut rx = l.ask(allow_as(&phone, 3, token, true, BindingRole::Owner));
        if moved {
            l.trusted.set_bound_owners([1]);
        }
        l.release();
        l.release();
        l.settle().await;
        assert_eq!(
            answered(&mut first),
            Some(Ok(0)),
            "moved {moved}: the guest's"
        );
        if moved {
            assert_eq!(answered(&mut rx), Some(Err(TrustedError::Role)));
            assert_eq!(on_disk(&l, &phone), None, "nothing written");
            assert_eq!(l.trusted.attempts_of(3).len(), 1, "the attempt stays");
        } else {
            assert_eq!(answered(&mut rx), Some(Ok(0)));
            assert_eq!(on_disk(&l, &phone), Some((BindingRole::Owner, false)));
        }
    }
}

/// §5 «Владелец на этом ПК», the one reading: a working owner-role key, or the owner by the
/// bindings without a mark; an unconfirmed owner key is one (it works) yet opens no switch; a
/// leaving one is not; with an owner anywhere on the PC the pairing role is derived.
#[tokio::test]
async fn the_owner_on_this_pc_is_one_reading() {
    let (dir, keys) = list_of(&[
        (1, BindingRole::Owner, true),
        (2, BindingRole::Guest, false),
    ]);
    let mut l = Loop::open(dir);
    assert!(l.trusted.owner_on_pc(1), "an unconfirmed owner key works");
    assert_eq!(l.view().owner_device, OwnerDevice::Unconfirmed);
    assert!(!l.trusted.owner_on_pc(2) && !l.trusted.owner_on_pc(3));
    assert_eq!(l.trusted.pair_role(1), Some(BindingRole::Owner));
    assert_eq!(l.trusted.pair_role(3), Some(BindingRole::Guest));
    l.trusted.set_bound_owners([3]);
    assert!(l.trusted.owner_on_pc(3), "by the bindings");
    l.trusted
        .store_mut()
        .unwrap()
        .deny_now(&[keys[0].key_id().clone()]);
    assert!(!l.trusted.owner_on_pc(1), "a leaving owner key is none");

    let (dir, _) = list_of(&[(2, BindingRole::Guest, false)]);
    let l = Loop::open(dir);
    assert_eq!(
        l.trusted.pair_role(2),
        None,
        "no owner: the role is chosen at the PC"
    );
}

/// A session that went on since the dialog opened (it may have ended): «Разрешить» writes nothing
/// in either mode and keeps the attempt (`tainted`; the vectors' `key_unconfirmed`). A clean
/// dialog writes it confirmed.
#[tokio::test]
async fn a_session_since_the_dialog_opened_taints_allow() {
    for strict in [false, true] {
        let (dir, _, _, _) = seeded();
        let mut l = Loop::open(dir);
        let now = crate::journal::now_ms();
        l.trusted
            .store_mut()
            .unwrap()
            .set_trusted_devices_mode(strict)
            .unwrap();
        let b = key();
        tried(&mut l, 9, &b, now);
        let opened = l.view().token;
        l.trusted.session_began("session_request", "s2");
        l.trusted.sync_live(0);
        let mut rx = l.ask(allow(&b, 9, opened, false));
        l.settle().await;
        assert_eq!(
            answered(&mut rx),
            Some(Err(TrustedError::Tainted)),
            "strict {strict}"
        );
        assert_eq!(on_disk(&l, &b), None, "strict {strict}: nothing written");
        assert!(
            l.trusted.store().unwrap().attempt(9, b.key_id()).is_some(),
            "strict {strict}: the attempt stays"
        );
        let clean = l.view().token;
        let mut rx = l.ask(allow(&b, 9, clean, false));
        l.settle().await;
        assert_eq!(answered(&mut rx), Some(Ok(0)), "strict {strict}");
        assert_eq!(
            on_disk(&l, &b),
            Some((BindingRole::Guest, false)),
            "strict {strict}"
        );
    }
}

/// «Разрешить» on an attempt older than 30 days: `expired` (it goes); on one whose device joined
/// meanwhile: `added`; on none: `not_found`. Nothing is written.
#[tokio::test]
async fn allow_refuses_an_expired_an_added_or_a_gone_attempt() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let old = key();
    tried(
        &mut l,
        9,
        &old,
        now - crate::viewer_keys::ATTEMPT_KEEP_MS - 60_000,
    );
    let token = l.view().token;
    let mut rx = l.ask(allow(&old, 9, token, false));
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::Expired)));
    assert!(l
        .trusted
        .store()
        .unwrap()
        .attempt(9, old.key_id())
        .is_none());
    assert_eq!(on_disk(&l, &old), None);

    let joined = key();
    tried(&mut l, 9, &joined, now);
    l.trusted
        .store_mut()
        .unwrap()
        .add(new_key(&joined), pair(9, BindingRole::Guest, false), now)
        .unwrap();
    let mut rx = l.ask(allow(&joined, 9, token, false));
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::Added)));
    let mut rx = l.ask(allow(&key(), 9, token, false));
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::NotFound)));
}

/// «Скрыть» needs the clean window its dialog opened with (`session` otherwise, nothing
/// changes); then the notes are written: the attempt gone.
#[tokio::test]
async fn hide_needs_a_clean_window_and_writes_the_notes() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let a = key();
    tried(&mut l, 9, &a, now);
    let hide = |token| TrustedAsk::AttemptHide {
        telegram_user_id: 9,
        key_id: a.key_id().clone(),
        token,
    };
    let opened = l.view().token;
    l.trusted.session_began("session_request", "s1");
    l.trusted.sync_live(0);
    let mut rx = l.ask(hide(opened));
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::Session)));
    assert!(l.trusted.store().unwrap().attempt(9, a.key_id()).is_some());
    let mut rx = l.ask(hide(l.view().token));
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Ok(0)));
    assert!(TrustStore::open_in(&l.dir.0).attempts().is_empty());
    let mut rx = l.ask(hide(l.view().token));
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::NotFound)));
}

/// «Подтвердить» is one press even when the person has attempts: the key is confirmed.
#[tokio::test]
async fn confirm_with_attempts_is_one_press() {
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    tried(&mut l, 5, &key(), now);
    let token = l.view().token;
    assert!(
        !l.view().people[1].needs_second_step,
        "a guest's row asks none"
    );
    let mut rx = l.ask(TrustedAsk::Confirm {
        key_id: guest.key_id().clone(),
        token,
    });
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Ok(0)));
    assert_eq!(on_disk(&l, &guest), Some((BindingRole::Guest, false)));
}

/// §10.2: an attempt whose last try is more than 30 days before the PC's clock counts for
/// nothing, whoever reads it — with no prune by the caller (none runs here: the attempts are
/// noted at their own old time, so the note itself keeps them). It is not shown.
#[tokio::test]
async fn an_attempt_older_than_30_days_counts_for_nothing() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let old = now - crate::viewer_keys::ATTEMPT_KEEP_MS - 86_400_000;
    let (tried_5, tried_9) = (key(), key());
    tried(&mut l, 5, &tried_5, old);
    // 9: no key, no removed key, and that old attempt.
    tried(&mut l, 9, &tried_9, old);
    l.trusted.publish("test: 31-day-old attempts");
    let view = l.view();
    let shown: Vec<(i64, usize)> = view
        .people
        .iter()
        .map(|p| (p.telegram_user_id, p.attempts.len()))
        .collect();
    assert!(shown.iter().all(|(_, n)| *n == 0), "not shown: {shown:?}");
    assert!(l.trusted.attempts_of(5).is_empty());
    {
        let store = l.trusted.store().unwrap();
        assert!(store.attempts().is_empty(), "{:?}", store.attempts());
        assert!(store.attempt(5, tried_5.key_id()).is_none());
    }
}

/// «Удалить человека» for guest 5 decides at the press (their key denied) while its write
/// fails (injected) and parks. «Подтвердить» on that key afterwards is refused (the key is
/// removed already), and the key is written `pc`.
#[tokio::test]
async fn confirm_of_a_key_whose_removal_is_pending_is_refused() {
    let (dir, _, guest, _) = seeded();
    let jammed = jam(&dir);
    let mut l = Loop::open(dir);
    let mut rx = l.ask(TrustedAsk::RemovePerson {
        telegram_user_id: 5,
    });
    l.settle().await;
    assert_eq!(l.trusted.parked.len(), 1, "{:?}", answered(&mut rx));
    assert_eq!(on_disk(&l, &guest), Some((BindingRole::Guest, true)));
    unjam(&jammed);
    let token = l.view().token;
    let mut rx = l.ask(TrustedAsk::Confirm {
        key_id: guest.key_id().clone(),
        token,
    });
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::NotFound)));
    // The parked removal lands on the timer's retry (no other write came).
    l.trusted
        .tick(Instant::now() + PARKED_RETRY + Duration::from_secs(1));
    l.settle().await;
    let fresh = TrustStore::open_in(&l.dir.0);
    assert_eq!(origin_of(&fresh, &guest), "pc");
}

/// The owner's keys are removed at the PC («Удалить» on his phone takes the laptop it
/// endorsed) and the write parks. «Разрешить» on another device's attempt of his then takes the
/// role of his keys here — none left (their removal is decided): a guest's, never the owner's.
#[tokio::test]
async fn allow_takes_no_owner_role_from_keys_whose_removal_is_pending() {
    let (dir, owner, _, laptop) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let phone = key();
    tried(&mut l, 1, &phone, now);
    let jammed = jam(&l.dir);
    let mut rx = l.ask(TrustedAsk::Remove {
        key_id: owner.key_id().clone(),
    });
    l.settle().await;
    assert_eq!(l.trusted.parked.len(), 1, "{:?}", answered(&mut rx));
    unjam(&jammed);
    let token = l.view().token;
    let mut rx = l.ask(allow_as(&phone, 1, token, true, BindingRole::Guest));
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Ok(0)));
    assert_eq!(on_disk(&l, &phone), Some((BindingRole::Guest, false)));
    let fresh = TrustStore::open_in(&l.dir.0);
    assert_eq!(origin_of(&fresh, &owner), "pc");
    assert_eq!(origin_of(&fresh, &laptop), "pc");
}

/// Contract 7593e83 (§10.2, `key_other_person`): «Разрешить» on an attempt whose key is active at
/// another person writes nothing — the window hears `key_other_person`, the record stays the other
/// person's and the attempt stays («Скрыть» removes it). Reachable since a key entering the list
/// for one person leaves another person's attempt with it in place.
#[tokio::test]
async fn allow_of_a_key_at_another_person_is_refused_and_keeps_the_attempt() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let guest = key();
    tried(&mut l, 9, &guest, now);
    l.trusted
        .store_mut()
        .unwrap()
        .add(new_key(&guest), pair(5, BindingRole::Guest, false), now)
        .unwrap();
    l.trusted.publish("test: the key enters for person 5");
    let token = l.view().token;
    let mut rx = l.ask(allow_as(&guest, 9, token, true, BindingRole::Guest));
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Err(TrustedError::OtherPerson)));
    assert_eq!(TrustedError::OtherPerson.as_str(), "key_other_person");
    let store = l.trusted.store().unwrap();
    assert!(matches!(
        store.lookup(guest.key_id()),
        Lookup::Active(r) if r.person.telegram_user_id == 5
    ));
    assert!(
        store.attempt(9, guest.key_id()).is_some(),
        "the attempt stays"
    );
}

/// The view: a person with attempts and no key is listed (a guest's role, no devices); the owner's
/// role comes from his keys; only the owner's row asks the second step.
#[tokio::test]
async fn the_view_lists_attempts_and_second_steps() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let a = key();
    tried(&mut l, 9, &a, now);
    let view = l.view();
    let uids: Vec<i64> = view.people.iter().map(|p| p.telegram_user_id).collect();
    assert_eq!(uids, [1, 5, 9]);
    let (owner, guest, stranger) = (&view.people[0], &view.people[1], &view.people[2]);
    assert_eq!(owner.role, BindingRole::Owner);
    assert!(owner.needs_second_step);
    assert_eq!(guest.role, BindingRole::Guest);
    assert!(!guest.needs_second_step);
    assert!(stranger.devices.is_empty());
    assert_eq!(stranger.attempts.len(), 1);
    assert_eq!(&stranger.attempts[0].key_id, a.key_id());
    assert!(!stranger.needs_second_step);
}

// --- G1: freshness of a press -------------------------------------------------------------------

/// «Подтвердить» (a check; a guard, not a fix): the confirm of guest 5's unconfirmed key,
/// queued or in flight when «Удалить человека» is pressed: the press denies the key at once, so
/// the key is never active again.
#[tokio::test]
async fn a_removal_after_a_confirm_press_wins() {
    for in_flight in [true, false] {
        let (dir, owner, guest, _) = seeded();
        let mut l = Loop::open(dir).gated();
        if !in_flight {
            use crate::admission::{AdmitOp, StoreOp};
            l.trusted.admit(AdmitOp {
                ticket: 2,
                op: StoreOp::add(
                    new_key(&key()),
                    grant_for(&owner, 11, 2, current(l.trusted.store().unwrap())),
                ),
            });
        }
        let token = l.view().token;
        let _confirm = l.ask(TrustedAsk::Confirm {
            key_id: guest.key_id().clone(),
            token,
        });
        assert!(l.trusted.busy());
        let _remove = l.ask(TrustedAsk::RemovePerson {
            telegram_user_id: 5,
        });
        settle_never_active(&mut l, &guest).await;
        let reopened = TrustStore::open_in(&l.dir.0);
        assert!(!matches!(
            reopened.lookup(guest.key_id()),
            Lookup::Active(_)
        ));
    }
}

/// The server removes guest 5 and its write of B (the guest's key) is in
/// flight when «Удалить» B is pressed at the PC: B is still active in the list, so the press
/// carries `pc` for it and replaces the grant token. The server's write lands B as a `server`
/// tombstone, which stays as written (a press changes no tombstone); the PC's own write then
/// fails and parks. The next write that lands — a snapshot of the notes — carries the press's
/// token: after a restart right then the file has it, B removed `server`.
#[tokio::test]
async fn a_press_during_a_server_removal_write_lands_its_token_by_the_next_snapshot() {
    use crate::admission::{AdmitOp, StoreOp};
    let (dir, _owner, guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    server_removes(&mut l, 5);
    // The notes' write lands; the guest's untrust (`server`) is staged next and in flight.
    l.release();
    assert_eq!(l.step().await, "trusted_written");
    assert!(l.trusted.busy(), "the server removal's write is in flight");
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    assert_eq!(
        answered(&mut remove),
        None,
        "queued behind the server's write"
    );
    let pressed = current(l.trusted.store().unwrap());
    // The server's write lands: B is a `server` tombstone in the list now.
    l.release();
    assert_eq!(l.step().await, "trusted_written");
    // The PC's write fails until it parks.
    let jammed = jam(&l.dir);
    while l.trusted.parked.is_empty() && (l.trusted.busy() || !l.trusted.queue.is_empty()) {
        l.release();
        l.step().await;
    }
    assert_eq!(l.trusted.parked.len(), 1, "{:?}", answered(&mut remove));
    unjam(&jammed);
    // A snapshot of the notes lands (another person's attempt meanwhile).
    tried_again(&mut l, 77, &key(), NOW + 2_000);
    l.trusted.admit(AdmitOp {
        ticket: 901,
        op: StoreOp::Notes,
    });
    l.release();
    assert_eq!(l.step().await, "trusted_written");
    // A restart right after it.
    let reopened = TrustStore::open_in(&l.dir.0);
    assert_eq!(current(&reopened), pressed, "the press's token on disk");
    assert_eq!(
        origin_of(&reopened, &guest),
        "server",
        "as the server's write wrote it"
    );
    assert_eq!(origin_of(l.trusted.store().unwrap(), &guest), "server");
}

/// The device tries again: its attempt noted anew in memory only (no write of its own: the queue
/// writes the notes with its next change).
fn tried_again(l: &mut Loop, uid: i64, k: &ViewerKey, at: i64) {
    let store = l.trusted.store_for_notes().unwrap();
    assert!(store.note_attempt(
        crate::viewer_keys::Attempt {
            telegram_user_id: uid,
            role: BindingRole::Guest,
            key: k.clone(),
            kind: ClientKind::parse("telegram").unwrap(),
            platform: Platform::parse("android").unwrap(),
            rpk: None,
            first_at: at,
            last_at: at,
            count: 1,
        },
        at,
    ));
    l.trusted.publish("test: an attempt again");
}

/// The list turned damaged (garbage over the primary) and read again: the backup restorable.
async fn damaged(l: &mut Loop) {
    std::fs::write(l.dir.0.join(FILE_NAME), b"garbage").unwrap();
    let mut reopen = l.ask(TrustedAsk::Repair(RepairAction::Reopen));
    l.settle().await;
    assert_eq!(answered(&mut reopen), Some(Ok(0)));
    assert!(l.trusted.store().unwrap().is_damaged());
}

/// §10.2: the view and its age-out deadline are read at one instant. The wall clock
/// crossing the shown attempt's 30 days right after the view is built leaves the deadline at
/// that attempt's age-out, so the next tick takes it out of the view.
#[tokio::test]
async fn the_age_out_deadline_is_the_shown_views() {
    let (dir, _owner, _guest, _) = seeded();
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let keep = crate::viewer_keys::ATTEMPT_KEEP_MS;
    let k = key();
    {
        let store = l.trusted.store_for_notes().unwrap();
        store.set_wall_now(now);
        assert!(store.note_attempt(
            crate::viewer_keys::Attempt {
                telegram_user_id: 5,
                role: BindingRole::Guest,
                key: k.clone(),
                kind: ClientKind::parse("telegram").unwrap(),
                platform: Platform::parse("iphone").unwrap(),
                rpk: None,
                first_at: now,
                last_at: now,
                count: 1,
            },
            now
        ));
        // Exactly 30 days: it still counts.
        store.set_wall_now(now + keep);
    }
    l.trusted.cross_after_view = Some(now + keep + 1);
    l.trusted.publish("test: the clock crosses");
    let shown = |l: &Loop| {
        l.view()
            .people
            .iter()
            .find(|p| p.telegram_user_id == 5)
            .map_or(0, |p| p.attempts.len())
    };
    assert_eq!(shown(&l), 1, "built while it counted");
    l.trusted.tick(Instant::now());
    assert_eq!(shown(&l), 0, "the tick takes it out");
}

/// A loaded machine (a blocking job that starts 2.5 s late) does not turn a write a
/// test waits for into `slow`: the tests' limit is not the product's [`WRITE_LIMIT`] (the
/// slow path's own tests set theirs, [`Loop::gated_slow`]).
#[tokio::test]
async fn a_loaded_machine_does_not_make_a_tests_write_slow() {
    let (dir, _, _, _) = seeded();
    std::fs::write(dir.0.join(FILE_NAME), b"garbage").unwrap();
    let mut l = Loop::open(dir);
    let (tx, rx) = std::sync::mpsc::channel();
    l.trusted.gate = Some(Arc::new(Mutex::new(rx)));
    let late = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(2500));
        let _ = tx.send(());
    });
    let mut reset = l.ask(TrustedAsk::Repair(RepairAction::Reset));
    l.settle().await;
    late.join().unwrap();
    assert_eq!(answered(&mut reset), Some(Ok(0)));
}

/// A gated loop keeps the tests' limit, longer than a step waits: a write held up by a loaded
/// machine is waited for, or fails the test as hung — never heard as `slow` (a jammed removal's
/// retries answered `slow` before they ran out under a 5 s limit). Only `gated_slow` shortens it.
#[test]
fn a_gated_loop_never_answers_slow_before_a_step_gives_up() {
    const { assert!(TEST_WRITE_LIMIT.as_secs() > STEP_WAIT.as_secs()) };
    let (dir, _, _, _) = seeded();
    let l = Loop::open(dir).gated();
    assert_eq!(l.trusted.write_limit, TEST_WRITE_LIMIT);
    let l = Loop::open(Scratch::new()).gated_slow(Duration::from_millis(50));
    assert_eq!(l.trusted.write_limit, Duration::from_millis(50));
}

// --- «Удалить человека» and the known binding list --------------------------------------------

fn owner_and_guest() -> [(i64, BindingRole); 2] {
    [(1, BindingRole::Owner), (5, BindingRole::Guest)]
}

/// A run that heard `bindings` at its `agent_ready` (the rule wrote them as the stored last
/// list), ended.
async fn ran_with(dir: Scratch, bindings: &[(i64, BindingRole)]) -> Scratch {
    let mut l = Loop::open(dir);
    l.trusted.agent_ready(bindings.iter().copied());
    l.trusted.bring_to_rule("test: agent_ready");
    l.settle().await;
    l.dir
}

/// The key's origin when removed, else what the lookup says (for a failure that names its case).
fn state_of(store: &TrustStore, k: &ViewerKey) -> String {
    match store.lookup(k.key_id()) {
        Lookup::Removed(t) => t.origin.as_str().to_string(),
        other => format!("{other:?}").chars().take(16).collect(),
    }
}

/// «Удалить человека» reads the owner guard from working keys — guest 5's owner-role key whose removal is decided («Удалить», its write held) guards
/// nobody, so removing 5 at the PC is not refused `owner`: 5 is marked `pc` and 5's guest key
/// is denied at once; after both land the keys are `pc` and the mark is on disk.
#[tokio::test]
async fn remove_person_is_not_refused_owner_for_a_leaving_owner_key() {
    let (dir, _, guest, _) = seeded();
    let own = key();
    TrustStore::open_in(&dir.0)
        .add(new_key(&own), pair(5, BindingRole::Owner, false), NOW)
        .unwrap();
    let mut l = Loop::open(dir).gated();
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: own.key_id().clone(),
    });
    assert!(matches!(
        l.trusted.store().unwrap().lookup(own.key_id()),
        Lookup::PendingRemoval(_)
    ));
    let mut person = l.ask(TrustedAsk::RemovePerson {
        telegram_user_id: 5,
    });
    assert_ne!(
        answered(&mut person),
        Some(Err(TrustedError::Owner)),
        "a leaving owner-role key is no owner guard"
    );
    {
        let store = l.trusted.store().unwrap();
        assert!(store.removal_decided(guest.key_id()).is_some());
    }
    while l.trusted.busy() || !l.trusted.queue.is_empty() {
        l.release();
        l.step().await;
    }
    assert!(answered(&mut remove).is_some(), "the key's removal landed");
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert_eq!(state_of(store, &guest), "pc", "{at}: 5's guest key");
        assert_eq!(state_of(store, &own), "pc", "{at}: 5's owner key");
    }
}

/// §10 «владельца это не трогает никогда»: the owner (1) presses
/// «Удалить» of their phone (its laptop goes with it: every owner-role key of 1 has its removal
/// decided, so the keys guard nobody), then «Удалить человека» for themselves before any
/// `agent_ready` of this run gave the admission a binding (`bound` none). The latest known list
/// still names them the owner — the stored one on a fresh start, or the bound owners — so the
/// press is refused `owner` and nobody is marked, in memory or on disk.
#[tokio::test]
async fn remove_person_is_refused_owner_by_the_known_list_while_their_owner_keys_leave() {
    for stored in [true, false] {
        let case = if stored {
            "fresh start, stored list"
        } else {
            "bound owners"
        };
        let (dir, owner, _, laptop) = seeded();
        let dir = if stored {
            ran_with(dir, &owner_and_guest()).await
        } else {
            dir
        };
        let mut l = Loop::open(dir).gated();
        if !stored {
            l.trusted.set_bound_owners([1]);
        }
        let mut remove = l.ask(TrustedAsk::Remove {
            key_id: owner.key_id().clone(),
        });
        {
            let store = l.trusted.store().unwrap();
            assert!(store.removal_decided(owner.key_id()).is_some(), "{case}");
            assert!(store.removal_decided(laptop.key_id()).is_some(), "{case}");
            assert!(
                store.person_keys(1).unwrap().owner_keys_not_working(),
                "{case}: no owner key guards 1"
            );
        }
        let mut person = l.ask(TrustedAsk::RemovePerson {
            telegram_user_id: 1,
        });
        assert_eq!(
            answered(&mut person),
            Some(Err(TrustedError::Owner)),
            "{case}: the owner by the known list is never removed as a person"
        );
        while l.trusted.busy() || !l.trusted.queue.is_empty() {
            l.release();
            l.step().await;
        }
        assert!(
            answered(&mut remove).is_some(),
            "{case}: the removal landed"
        );
        for (store, at) in [
            (l.trusted.store().unwrap(), "memory"),
            (&TrustStore::open_in(&l.dir.0), "disk"),
        ] {
            assert_eq!(state_of(store, &owner), "pc", "{case}, {at}");
        }
    }
}

// --- §10 «Сверка со списком сервера: одно правило»: the one decision point --------------------

/// This connection's `agent_ready` with `bindings`, then the rule, as the orchestrator does.
fn ready_and_rule(l: &mut Loop, bindings: &[(i64, BindingRole)]) {
    l.trusted.agent_ready(bindings.iter().copied());
    l.trusted.bring_to_rule("test: agent_ready");
}

/// Run until nothing is in flight or queued, counting the writes (at most `max` jobs: a loop
/// fails here, not by hanging).
async fn settle_counting(l: &mut Loop, max: usize) -> usize {
    let (mut jobs, mut writes) = (0usize, 0usize);
    while l.trusted.busy() || !l.trusted.queue.is_empty() {
        jobs += 1;
        assert!(jobs <= max, "more than {max} jobs: a write loop?");
        if l.step().await == "trusted_written" {
            writes += 1;
        }
    }
    writes
}

fn last_known(store: &TrustStore) -> Option<Vec<(i64, BindingRole)>> {
    store
        .last_bindings()
        .map(|l| l.iter().map(|b| (b.telegram_user_id, b.role)).collect())
}

/// Guest 5, whom this connection's `agent_ready` does not name, is taken by the rule —
/// the guest key denied at once (pending, origin `server`), 5 marked `server`, their sessions
/// to end — and ONE write carries the tombstone, the mark and the stored list (journaled once);
/// the owner and the laptop stay. A second run queues nothing. Refutes a rule whose parts land
/// in several writes or that runs again on its own result.
#[tokio::test]
async fn the_rule_at_agent_ready_takes_an_unnamed_guest_in_one_write() {
    let (dir, owner, guest, laptop) = seeded();
    let mut l = Loop::open(dir);
    ready_and_rule(&mut l, &[(1, BindingRole::Owner)]);
    {
        let store = l.trusted.store().unwrap();
        assert!(matches!(
            store.lookup(guest.key_id()),
            Lookup::PendingRemoval(_)
        ));
    }
    assert_eq!(l.trusted.take_ruled(), (vec![5], true));
    assert_eq!(settle_counting(&mut l, 4).await, 1, "one write");
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert_eq!(origin_of(store, &guest), "server", "{at}");
        assert!(
            matches!(store.lookup(owner.key_id()), Lookup::Active(_)),
            "{at}"
        );
        assert!(
            matches!(store.lookup(laptop.key_id()), Lookup::Active(_)),
            "{at}"
        );
        assert_eq!(
            last_known(store),
            Some(vec![(1, BindingRole::Owner)]),
            "{at}"
        );
    }
    assert_eq!(
        l.kinds()
            .iter()
            .filter(|k| **k == Kind::DeviceUntrusted)
            .count(),
        1,
        "the guest key journaled once, by the write that took it"
    );
    l.trusted.bring_to_rule("test: again");
    assert!(
        !l.trusted.busy() && l.trusted.queue.is_empty(),
        "nothing queued"
    );
    assert_eq!(l.trusted.take_ruled(), (vec![], false));
}

/// No current list — before this connection's `agent_ready` (a binding message makes none),
/// and from a link loss until the next `agent_ready` — no rule: nothing changes. The next
/// `agent_ready` brings the list, and the rule runs. Refutes a rule run by a list of no live
/// connection.
#[tokio::test]
async fn the_rule_runs_only_against_a_live_connections_list() {
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir);
    let untouched = |l: &Loop, why: &str| {
        let store = l.trusted.store().unwrap();
        assert!(
            matches!(store.lookup(guest.key_id()), Lookup::Active(_)),
            "{why}"
        );
        assert!(l.trusted.queue.is_empty() && !l.trusted.busy(), "{why}");
    };
    l.trusted.bring_to_rule("test: no list");
    untouched(&l, "no list");
    l.trusted.set_bound_people([(1, BindingRole::Owner)]);
    l.trusted
        .bring_to_rule("test: a binding message before agent_ready");
    untouched(&l, "a message before agent_ready");
    l.trusted
        .agent_ready([(1, BindingRole::Owner), (5, BindingRole::Guest)]);
    l.trusted.forget_bound_people("test: the link went down");
    l.trusted.set_bound_people([(1, BindingRole::Owner)]);
    l.trusted.bring_to_rule("test: after the link went");
    untouched(&l, "after the link went");
    ready_and_rule(&mut l, &[(1, BindingRole::Owner)]);
}

/// The rule after an installed change, and no «last owner key» rule of its own: P (6), not
/// named, holds a working owner-role key and a guest-role key — P is not touched at all, the guest
/// key stays. Then «Удалить» takes P's owner key: the rule run after its install takes P's guest
/// key `server`. Refutes a decision point that misses the install, or an owner guard read from a
/// key that left.
#[tokio::test]
async fn the_rule_after_an_install_takes_a_person_whose_owner_key_left() {
    let (dir, _, _, _) = seeded();
    let (k_o, k_g) = (key(), key());
    {
        let mut store = TrustStore::open_in(&dir.0);
        store
            .add(new_key(&k_o), pair(6, BindingRole::Owner, false), NOW)
            .unwrap();
        store
            .add(new_key(&k_g), pair(6, BindingRole::Guest, false), NOW)
            .unwrap();
    }
    let mut l = Loop::open(dir);
    ready_and_rule(&mut l, &[(1, BindingRole::Owner), (5, BindingRole::Guest)]);
    assert_eq!(l.trusted.take_ruled(), (vec![], false), "P is not touched");
    l.settle().await;
    {
        let store = l.trusted.store().unwrap();
        assert!(matches!(store.lookup(k_g.key_id()), Lookup::Active(_)));
        assert!(matches!(store.lookup(k_o.key_id()), Lookup::Active(_)));
    }
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: k_o.key_id().clone(),
    });
    l.settle().await;
    assert_eq!(answered(&mut remove), Some(Ok(1)));
    assert_eq!(l.trusted.take_ruled(), (vec![6], true));
    l.settle().await;
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert_eq!(origin_of(store, &k_o), "pc", "{at}");
        assert_eq!(origin_of(store, &k_g), "server", "{at}");
    }
}

/// «Запас»: a guest whose key is younger than the grace is not taken at `agent_ready`; the
/// tick takes them once it ends (not before). Refutes a grace that never ends, or a tick that
/// does not run the rule.
#[tokio::test]
async fn the_rule_takes_a_fresh_key_on_the_tick_when_its_grace_ends() {
    let dir = Scratch::new();
    let fresh = key();
    let w = NOW + 86_400_000;
    {
        let mut store = TrustStore::open_in(&dir.0);
        store
            .add(new_key(&key()), pair(1, BindingRole::Owner, false), NOW)
            .unwrap();
        store
            .add(new_key(&fresh), pair(5, BindingRole::Guest, false), w)
            .unwrap();
    }
    let mut l = Loop::open(dir);
    l.trusted.store_for_notes().unwrap().set_wall_now(w + 1_000);
    ready_and_rule(&mut l, &[(1, BindingRole::Owner)]);
    l.settle().await;
    assert!(matches!(
        l.trusted.store().unwrap().lookup(fresh.key_id()),
        Lookup::Active(_)
    ));
    assert_eq!(l.trusted.take_ruled(), (vec![], false));
    l.trusted
        .store_for_notes()
        .unwrap()
        .set_wall_now(w + UNBOUND_KEY_GRACE_MS - 1);
    l.trusted.tick(Instant::now());
    assert!(matches!(
        l.trusted.store().unwrap().lookup(fresh.key_id()),
        Lookup::Active(_)
    ));
    l.trusted
        .store_for_notes()
        .unwrap()
        .set_wall_now(w + UNBOUND_KEY_GRACE_MS);
    l.trusted.tick(Instant::now());
    assert!(matches!(
        l.trusted.store().unwrap().lookup(fresh.key_id()),
        Lookup::PendingRemoval(_)
    ));
    assert_eq!(l.trusted.take_ruled(), (vec![5], true));
    l.settle().await;
    assert_eq!(origin_of(&TrustStore::open_in(&l.dir.0), &fresh), "server");
}

/// Nobody named — the owner, a working owner-role key holder, is not touched at all: his owner
/// keys (the phone, the laptop it endorsed) and his own guest-role key stay; guest 5 is taken.
/// Refutes a rule that removes an owner-role key or touches a working owner on the server's word.
#[tokio::test]
async fn the_rule_never_takes_an_owner_key_nor_its_holder() {
    let (dir, owner, guest, laptop) = seeded();
    let owners_guest = key();
    TrustStore::open_in(&dir.0)
        .add(
            new_key(&owners_guest),
            pair(1, BindingRole::Guest, false),
            NOW,
        )
        .unwrap();
    let mut l = Loop::open(dir);
    ready_and_rule(&mut l, &[]);
    assert_eq!(l.trusted.take_ruled(), (vec![5], true));
    l.settle().await;
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert!(
            matches!(store.lookup(owner.key_id()), Lookup::Active(_)),
            "{at}"
        );
        assert!(
            matches!(store.lookup(laptop.key_id()), Lookup::Active(_)),
            "{at}"
        );
        assert!(
            matches!(store.lookup(owners_guest.key_id()), Lookup::Active(_)),
            "{at}: his guest-role key stays"
        );
        assert_eq!(origin_of(store, &guest), "server", "{at}");
    }
}

/// The rule's result is in order — a second run, and the next run's `agent_ready` with the
/// same list after a restart, queue no write and keep the token the run set.
/// Refutes a rule that rewrites at every run or start.
#[tokio::test]
async fn the_rule_changes_nothing_again_nor_after_a_restart() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir);
    ready_and_rule(&mut l, &[(1, BindingRole::Owner)]);
    l.settle().await;
    let t = l.trusted.store().unwrap().grant_token();
    l.trusted.bring_to_rule("test: again");
    assert!(l.trusted.queue.is_empty() && !l.trusted.busy());
    let mut l = Loop::open(l.dir);
    ready_and_rule(&mut l, &[(1, BindingRole::Owner)]);
    assert!(
        l.trusted.queue.is_empty() && !l.trusted.busy(),
        "nothing to write after a restart"
    );
    assert_eq!(l.trusted.store().unwrap().grant_token(), t);
    assert_eq!(l.trusted.take_ruled(), (vec![], false));
}

/// After a repair lands the rule runs by the current list: the damaged list changed nothing at
/// the `agent_ready`; «Восстановить» brings guest 5's key back and the rule takes it. Refutes a
/// rule run on a damaged list, or none after the repair.
#[tokio::test]
async fn the_rule_waits_for_a_damaged_list_and_runs_after_the_restore() {
    let (dir, owner, guest, _) = seeded();
    let mut l = Loop::open(dir);
    damaged(&mut l).await;
    ready_and_rule(&mut l, &[(1, BindingRole::Owner)]);
    assert!(
        l.trusted.queue.is_empty() && !l.trusted.busy(),
        "nothing on a damaged list"
    );
    assert_eq!(l.trusted.take_ruled(), (vec![], false));
    let mut restore = l.ask(restore_ask(&l));
    l.settle().await;
    assert!(matches!(answered(&mut restore), Some(Ok(_))));
    assert_eq!(l.trusted.take_ruled(), (vec![5], true));
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert_eq!(origin_of(store, &guest), "server", "{at}");
        assert!(
            matches!(store.lookup(owner.key_id()), Lookup::Active(_)),
            "{at}"
        );
    }
}

/// §10: while memory may be behind the disk (a reopen's load went stale: the store changed under
/// it) the rule is not run — nothing is denied or queued for guest 5, whom the current
/// list does not name. The reopen that lands then runs it: 5's key leaves `server`, and the
/// window's reopen is answered. Refutes a rule decided on memory that may be stale.
#[tokio::test]
async fn the_rule_waits_while_a_reopen_is_needed_and_runs_when_it_lands() {
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    l.trusted.agent_ready([(1, BindingRole::Owner)]);
    let mut reopen = l.ask(TrustedAsk::Repair(RepairAction::Reopen));
    // The store changes under the waiting load: the load is stale when it comes in.
    let _ = l.trusted.store_mut().unwrap().reopen();
    l.release();
    assert_eq!(l.step().await, "trusted_reopened");
    assert!(l.trusted.store().unwrap().needs_reopen(), "a reopen first");
    l.trusted.bring_to_rule("test: while a reopen is needed");
    let store = l.trusted.store().unwrap();
    assert!(matches!(store.lookup(guest.key_id()), Lookup::Active(_)));
    assert!(
        l.trusted
            .queue
            .iter()
            .all(|o| matches!(o.kind, OpKind::Reopen)),
        "nothing but the reopen waits"
    );
    assert_eq!(l.trusted.take_ruled(), (vec![], false));
    for _ in 0..8 {
        if !l.trusted.busy() && l.trusted.queue.is_empty() {
            break;
        }
        l.release();
        l.step().await;
    }
    assert_eq!(answered(&mut reopen), Some(Ok(0)));
    assert_eq!(
        l.trusted.take_ruled(),
        (vec![5], true),
        "run at the landing"
    );
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert_eq!(origin_of(store, &guest), "server", "{at}");
    }
}

// --- §10 «Повреждённый список»: nothing changes while damaged, nothing replays after it -------

/// Presses whose ops are waiting when the list turns damaged are lost with memory, exactly as
/// at a restart before the write. Here «Удалить человека» 5 is in flight and «Удалить» of the
/// owner's phone is queued behind it when the primary turns damaged. Both are answered `damaged`
/// and dropped; nothing is queued or parked. After «Восстановить» (the copy before the laptop's
/// add), neither applies: 5's key and the phone are back, in memory and on disk. Refutes a press
/// that replays after the repair.
#[tokio::test]
async fn presses_waiting_when_the_list_turns_damaged_answer_damaged_and_never_apply() {
    let (dir, owner, guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let mut person = l.ask(TrustedAsk::RemovePerson {
        telegram_user_id: 5,
    });
    let mut tree = l.ask(TrustedAsk::Remove {
        key_id: owner.key_id().clone(),
    });
    std::fs::write(l.dir.0.join(FILE_NAME), b"garbage").unwrap();
    until_damaged(&mut l).await;
    assert!(l.trusted.queue.is_empty() && l.trusted.parked.is_empty());
    assert_eq!(answered(&mut person), Some(Err(TrustedError::Damaged)));
    assert_eq!(answered(&mut tree), Some(Err(TrustedError::Damaged)));
    let mut restore = l.ask(restore_ask(&l));
    for _ in 0..8 {
        if !l.trusted.busy() && l.trusted.queue.is_empty() {
            break;
        }
        l.release();
        l.step().await;
    }
    assert!(matches!(answered(&mut restore), Some(Ok(_))));
    assert!(l.trusted.queue.is_empty() && l.trusted.parked.is_empty());
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        for k in [&guest, &owner] {
            assert!(
                matches!(store.lookup(k.key_id()), Lookup::Active(_)),
                "{at}: {} back and working",
                k.key_id().short()
            );
        }
    }
}

/// While the list is damaged a `binding_removed` changes nothing — no token replaced, no op
/// queued or parked — and the in-memory current list still follows the message. After
/// «Восстановить» the rule, by that list, takes 5: the guest key `server`. Refutes a damaged list
/// that remembers the server's word, or a current list that stops following it.
#[tokio::test]
async fn binding_removed_while_damaged_changes_nothing_and_the_rule_decides_after_the_restore() {
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir);
    ready_and_rule(&mut l, &[(1, BindingRole::Owner), (5, BindingRole::Guest)]);
    l.settle().await;
    damaged(&mut l).await;
    assert!(!l
        .trusted
        .store_for_notes()
        .unwrap()
        .person_removed(5, "test: while damaged"));
    l.trusted.guest_removed_on_server(5, 0);
    l.trusted.set_bound_people([(1, BindingRole::Owner)]);
    l.trusted.bring_to_rule("test: binding_removed");
    assert!(l.trusted.queue.is_empty() && l.trusted.parked.is_empty() && !l.trusted.busy());
    assert_eq!(l.trusted.take_ruled(), (vec![], false));
    let mut restore = l.ask(restore_ask(&l));
    l.settle().await;
    assert!(matches!(answered(&mut restore), Some(Ok(_))));
    assert_eq!(l.trusted.take_ruled(), (vec![5], true));
    l.settle().await;
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert_eq!(origin_of(store, &guest), "server", "{at}");
    }
}

/// While the list is damaged a removal press («Удалить» of a key) is refused `damaged` at once and
/// changes nothing: no key denied, no op queued or parked. Refutes a press that waits for the
/// repair and applies to the repaired list.
#[tokio::test]
async fn a_removal_press_while_damaged_is_refused_and_changes_nothing() {
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir);
    damaged(&mut l).await;
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    assert_eq!(answered(&mut remove), Some(Err(TrustedError::Damaged)));
    assert!(l.trusted.queue.is_empty() && l.trusted.parked.is_empty() && !l.trusted.busy());
    assert_eq!(
        l.trusted.store().unwrap().removal_decided(guest.key_id()),
        None
    );
    let mut restore = l.ask(restore_ask(&l));
    l.settle().await;
    assert!(matches!(answered(&mut restore), Some(Ok(_))));
    assert!(matches!(
        l.trusted.store().unwrap().lookup(guest.key_id()),
        Lookup::Active(_)
    ));
}

// --- §10 «Повреждённый список»: a retried removal write decides nothing; the damage drops it ----

/// A removal decided while the list is healthy whose write keeps failing parks. Its retry is a
/// write of memory: a later decision at the PC wins over it.
///
/// Here the server removes guest 5: the mark is `server` and the guest key is denied. The
/// writes fail until the removal parks. Then 5 is let in again at the PC with the second step: a
/// new device, confirmed, which lifts the mark. Once that write lands, the parked removal runs
/// again and must leave 5 unmarked and the new key working, in memory and on disk; the old key
/// leaves `server`. Refutes a retry that sets the mark again or walks the person's keys again.
#[tokio::test]
async fn a_parked_server_removal_retry_keeps_a_later_approval() {
    let (dir, _, guest, _) = seeded();
    let jammed = jam(&dir);
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    server_removes(&mut l, 5);
    l.settle().await;
    assert_eq!(l.trusted.parked.len(), 1, "the server's removal parked");
    unjam(&jammed);
    let fresh = key();
    tried(&mut l, 5, &fresh, now + 1);
    let token = l.view().token;
    let mut rx = l.ask(allow_as(&fresh, 5, token, true, BindingRole::Guest));
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Ok(0)));
    assert!(l.trusted.parked.is_empty() && l.trusted.queue.is_empty());
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert!(
            matches!(store.lookup(fresh.key_id()), Lookup::Active(_)),
            "{at}: the new key works"
        );
        assert_eq!(origin_of(store, &guest), "server", "{at}");
    }
}

/// «Удалить человека» 5 at the PC parks the same way. Meanwhile 5 is let in again with the
/// second step, and the owner pairs a new device, which takes the owner role. After the retry,
/// 5 stays unmarked, both new keys work and the old guest key leaves `pc`. Refutes a retry that
/// walks the person's keys again or restores the press's mark.
#[tokio::test]
async fn a_parked_person_removal_retry_keeps_a_later_approval_and_an_owners_new_key() {
    let (dir, _, guest, _) = seeded();
    let jammed = jam(&dir);
    let mut l = Loop::open(dir);
    let now = crate::journal::now_ms();
    let (reply, mut person) = oneshot::channel();
    l.trusted.command_at(
        TrustedRequest {
            ask: TrustedAsk::RemovePerson {
                telegram_user_id: 5,
            },
            reply,
        },
        0,
        Some(BindingRole::Guest),
    );
    l.settle().await;
    assert_eq!(answered(&mut person), Some(Err(TrustedError::WriteFailed)));
    assert_eq!(l.trusted.parked.len(), 1, "the press's removal parked");
    unjam(&jammed);
    let fresh = key();
    tried(&mut l, 5, &fresh, now + 1);
    let token = l.view().token;
    let mut rx = l.ask(allow_as(&fresh, 5, token, true, BindingRole::Guest));
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Ok(0)));
    let owners = key();
    tried(&mut l, 1, &owners, now + 2);
    let token = l.view().token;
    let mut rx = l.ask(allow_step_as(&owners, 1, token, BindingRole::Owner));
    l.settle().await;
    assert_eq!(answered(&mut rx), Some(Ok(0)));
    assert!(l.trusted.parked.is_empty() && l.trusted.queue.is_empty());
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert!(
            matches!(store.lookup(fresh.key_id()), Lookup::Active(_)),
            "{at}: 5's new key works"
        );
        match store.lookup(owners.key_id()) {
            Lookup::Active(r) => assert_eq!(r.role, BindingRole::Owner, "{at}"),
            other => panic!("{at}: the owner's new key works: {other:?}"),
        }
        assert_eq!(origin_of(store, &guest), "pc", "{at}");
    }
}

/// Run a gated queue until the list is damaged and nothing is in flight (at most 8 jobs).
async fn until_damaged(l: &mut Loop) {
    for _ in 0..8 {
        if l.trusted.store().unwrap().is_damaged() && !l.trusted.busy() {
            return;
        }
        l.release();
        l.step().await;
    }
    panic!("the list never turned damaged");
}

/// The server removes keyless 9; the notes-only write is in flight when the list turns damaged
/// under it. The damage loses the unwritten notes: nothing is queued or parked. The next
/// `agent_ready` names 9, and then the repair lands. Nothing is replayed: the queue is empty, and
/// the rule runs once on the repaired list (it notes the list and takes no one). The lost token
/// is the accepted residual. Refutes a removal that replays after the repair.
#[tokio::test]
async fn a_removal_lost_with_the_damage_is_not_replayed_after_the_repair() {
    let (dir, _, _, _) = seeded();
    let mut l = Loop::open(dir).gated();
    assert!(server_removes_keyless(&mut l, 9, 902));
    assert!(l.trusted.busy(), "the notes-only write in flight");
    std::fs::write(l.dir.0.join(FILE_NAME), b"garbage").unwrap();
    until_damaged(&mut l).await;
    assert!(
        l.trusted.queue.is_empty() && l.trusted.parked.is_empty(),
        "the damage dropped every waiting change"
    );
    let named = [
        (1, BindingRole::Owner),
        (5, BindingRole::Guest),
        (9, BindingRole::Guest),
    ];
    ready_and_rule(&mut l, &named);
    assert!(
        l.trusted.queue.is_empty() && !l.trusted.busy(),
        "no rule while damaged"
    );
    let mut restore = l.ask(restore_ask(&l));
    for _ in 0..8 {
        if !l.trusted.busy() && l.trusted.queue.is_empty() {
            break;
        }
        l.release();
        l.step().await;
    }
    assert!(matches!(answered(&mut restore), Some(Ok(_))));
    assert!(l.trusted.queue.is_empty() && l.trusted.parked.is_empty() && !l.trusted.busy());
    assert_eq!(l.trusted.take_ruled(), (vec![], false));
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        let mut known = last_known(store).unwrap_or_default();
        known.sort_unstable_by_key(|(uid, _)| *uid);
        assert_eq!(
            known,
            named.to_vec(),
            "{at}: the rule ran on the repaired list"
        );
    }
    l.trusted.bring_to_rule("test: again");
    assert!(
        l.trusted.queue.is_empty() && !l.trusted.busy(),
        "a second run changes nothing"
    );
}

/// A server removal of guest 5 waits, parked on failing writes, when the list turns damaged.
/// The damage drops it. «Отвязать» 5 at the PC while damaged changes nothing in the trust state
/// or in any op; the unbind itself goes to the server. After the repair, the current list
/// (which does not name 5) brings the guest key in as `server`. No `pc` tombstone comes from the
/// press. Refutes an unbind that upgrades a waiting op before the damaged check.
#[tokio::test]
async fn an_unbind_while_damaged_leaves_a_waiting_removal_and_the_rule_takes_it_server() {
    let (dir, _, guest, _) = seeded();
    let jammed = jam(&dir);
    let mut l = Loop::open(dir);
    server_removes(&mut l, 5);
    l.settle().await;
    assert_eq!(l.trusted.parked.len(), 1, "the server's removal parked");
    unjam(&jammed);
    // A backup to restore from (the jam took its place): the list as on disk, 5's key active.
    std::fs::copy(l.dir.0.join(FILE_NAME), &jammed).unwrap();
    damaged(&mut l).await;
    assert!(
        l.trusted.queue.is_empty() && l.trusted.parked.is_empty(),
        "the damage dropped the waiting removal"
    );
    l.trusted.untrust_guest(5, 0);
    assert!(l.trusted.queue.is_empty() && l.trusted.parked.is_empty() && !l.trusted.busy());
    assert_eq!(
        l.trusted.store().unwrap().removal_decided(guest.key_id()),
        None
    );
    ready_and_rule(&mut l, &[(1, BindingRole::Owner)]);
    let mut restore = l.ask(restore_ask(&l));
    l.settle().await;
    assert!(matches!(answered(&mut restore), Some(Ok(_))));
    assert_eq!(l.trusted.take_ruled(), (vec![5], true));
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert_eq!(origin_of(store, &guest), "server", "{at}");
    }
}

/// K's device paired back at the PC («Разрешить» in the pairing panel): the admission's `pair`
/// of guest 5, queued.
fn pair_back(l: &mut Loop, k: &ViewerKey, ticket: u64) {
    use crate::admission::{AddChange, AdmitOp, StoreOp};
    l.trusted.admit(AdmitOp {
        ticket,
        op: StoreOp::Add(Box::new(AddChange {
            new: new_key(k),
            ground: pair(5, BindingRole::Guest, false),
            server_word: false,
            press: None,
        })),
    });
}

fn assert_paired_back(l: &mut Loop, ticket: u64) {
    let landed = l.trusted.take_landed();
    assert!(
        landed
            .iter()
            .any(|x| x.ticket == ticket && matches!(x.result, Ok(LandedOutcome::Added(_)))),
        "paired back: {landed:?}"
    );
}

// --- A retried removal write decides nothing: the key paired back since stays ------------------

/// «Удалить» K whose write keeps failing parks. A write that lands next (straight on the store,
/// so the parked one stays parked) takes K's removal, `pc`; then K is paired back at the PC. The
/// parked retry runs after that and must leave K working, in memory and on disk. Refutes a retry
/// that walks K's tree again.
#[tokio::test]
async fn a_parked_delete_retry_leaves_a_key_paired_back_since() {
    let (dir, _, guest, _) = seeded();
    let jammed = jam(&dir);
    let mut l = Loop::open(dir);
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    l.settle().await;
    assert_eq!(answered(&mut remove), Some(Err(TrustedError::WriteFailed)));
    assert_eq!(l.trusted.parked.len(), 1, "the press's write parked");
    unjam(&jammed);
    assert_eq!(l.trusted.store_mut().unwrap().flush(), Ok(true));
    assert_eq!(origin_of(&TrustStore::open_in(&l.dir.0), &guest), "pc");
    assert_eq!(l.trusted.parked.len(), 1, "still parked");
    pair_back(&mut l, &guest, 81);
    l.settle().await;
    assert_paired_back(&mut l, 81);
    assert!(
        l.trusted.parked.is_empty() && l.trusted.queue.is_empty(),
        "the retry ran"
    );
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert!(
            matches!(store.lookup(guest.key_id()), Lookup::Active(_)),
            "{at}: K works"
        );
    }
}

/// A key P that joins under the pressed key K gets a removal of its own; both writes keep
/// failing and park. A write that lands next takes both (`pc`); then P is paired back at the PC.
/// P's parked removal, run after that, finds P's removal decided no more and writes nothing: P
/// stays working, in memory and on disk. Refutes a retry that stages a removal memory does not
/// decide now.
#[tokio::test]
async fn a_parked_inherited_removal_retry_leaves_a_key_paired_back_since() {
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    let mut other = TrustStore::open_in(&l.dir.0);
    let tablet = key();
    other
        .add(
            new_key(&tablet),
            Ground::Endorse {
                by: guest.key_id().clone(),
                endorse_id: gid(2),
                issued_at: ISSUED,
            },
            NOW,
        )
        .unwrap();
    let jammed = jam(&l.dir);
    for _ in 0..16 {
        l.release();
    }
    l.settle().await;
    assert_eq!(answered(&mut remove), Some(Err(TrustedError::WriteFailed)));
    assert!(
        l.trusted.parked.iter().any(
            |o| matches!(&o.kind, OpKind::RemoveKey { key_id, .. } if key_id == tablet.key_id())
        ),
        "P's own removal parked"
    );
    unjam(&jammed);
    assert_eq!(l.trusted.store_mut().unwrap().flush(), Ok(true));
    assert_eq!(origin_of(&TrustStore::open_in(&l.dir.0), &tablet), "pc");
    pair_back(&mut l, &tablet, 82);
    for _ in 0..16 {
        l.release();
    }
    l.settle().await;
    assert_paired_back(&mut l, 82);
    assert!(
        l.trusted.parked.is_empty() && l.trusted.queue.is_empty(),
        "the retries ran"
    );
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert!(
            matches!(store.lookup(tablet.key_id()), Lookup::Active(_)),
            "{at}: P works"
        );
        assert_eq!(origin_of(store, &guest), "pc", "{at}");
    }
}

/// The write job, released until a write's result comes in.
async fn write_step(l: &mut Loop) {
    loop {
        l.release();
        if l.step().await == "trusted_written" {
            return;
        }
    }
}

/// A removal's last write attempt meets a file changed on disk, and reading it again finds the
/// list damaged: the press hears `damaged` (what is true now, §10 «Повреждённый список»), not
/// `write_failed`, and nothing waits or parks.
#[tokio::test]
async fn a_removals_last_attempt_that_finds_the_list_damaged_answers_damaged() {
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let mut remove = l.ask(TrustedAsk::Remove {
        key_id: guest.key_id().clone(),
    });
    for uid in [7, 8] {
        TrustStore::open_in(&l.dir.0)
            .add(new_key(&key()), pair(uid, BindingRole::Guest, false), NOW)
            .unwrap();
        write_step(&mut l).await;
        assert!(answered(&mut remove).is_none(), "retried");
    }
    std::fs::write(l.dir.0.join(FILE_NAME), b"garbage").unwrap();
    write_step(&mut l).await;
    assert!(l.trusted.store().unwrap().is_damaged());
    assert_eq!(answered(&mut remove), Some(Err(TrustedError::Damaged)));
    assert!(l.trusted.queue.is_empty() && l.trusted.parked.is_empty() && !l.trusted.busy());
}

/// An admission's change waiting behind a write when the list turns damaged is dropped and
/// heard at once as its landing with `damaged` (the admission answers its session then, never
/// at its timeout).
#[tokio::test]
async fn an_admission_change_waiting_at_damage_lands_damaged_at_once() {
    use crate::admission::{AdmitOp, StoreOp};
    let (dir, owner, _, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let mut tree = l.ask(TrustedAsk::Remove {
        key_id: owner.key_id().clone(),
    });
    l.trusted.admit(AdmitOp {
        ticket: 77,
        op: StoreOp::Notes,
    });
    assert!(l.trusted.take_landed().is_empty(), "it waits");
    std::fs::write(l.dir.0.join(FILE_NAME), b"garbage").unwrap();
    until_damaged(&mut l).await;
    assert_eq!(answered(&mut tree), Some(Err(TrustedError::Damaged)));
    let landed = l.trusted.take_landed();
    assert_eq!(landed.len(), 1);
    assert_eq!(landed[0].ticket, 77);
    assert!(
        matches!(landed[0].result, Err(StoreError::Damaged)),
        "{:?}",
        landed[0].result
    );
    assert!(l.trusted.queue.is_empty() && l.trusted.parked.is_empty());
}

// --- The grant token (§7) where the vectors do not reach: the rule, writes that wait or fail ---

/// A grant for guest 5's new device, signed over `token`; the store's word on it now.
fn stale_or_not(store: &TrustStore, owner: &ViewerKey, token: GrantToken) -> Option<StoreError> {
    store
        .check_add(&new_key(&key()), &grant_for(owner, 5, 9, token), NOW)
        .err()
}

/// The rule by the binding list (§10, §14): the PC was offline when guest 5 was removed; the
/// connection's `agent_ready` does not name 5 — 5's key leaves, 5 is marked, and the grant token
/// is replaced, all in one write. A grant signed before (over the old token) is `grant_stale` in
/// memory at once (before the write) and after it; the server's token (the saved one) changes only
/// with the write. The same list again changes nothing and keeps the token.
#[tokio::test]
async fn a_guest_removed_while_offline_leaves_with_a_new_grant_token() {
    let (dir, owner, guest, _) = seeded();
    let mut l = Loop::open(dir);
    let before = current(l.trusted.store().unwrap());
    assert_ne!(
        stale_or_not(l.trusted.store().unwrap(), &owner, before),
        Some(StoreError::GrantStale)
    );
    ready_and_rule(&mut l, &[(1, BindingRole::Owner)]);
    let token = {
        let store = l.trusted.store().unwrap();
        let token = current(store);
        assert!(token != before && !token.is_empty(), "replaced");
        assert_eq!(store.saved_grant_token(), Some(before), "not written yet");
        assert_eq!(
            stale_or_not(store, &owner, before),
            Some(StoreError::GrantStale),
            "stale at once"
        );
        token
    };
    assert_eq!(settle_counting(&mut l, 4).await, 1, "one write");
    let disk = TrustStore::open_in(&l.dir.0);
    assert_eq!(disk.grant_token(), Some(token));
    assert_eq!(l.trusted.store().unwrap().saved_grant_token(), Some(token));
    assert_eq!(origin_of(&disk, &guest), "server");
    assert_eq!(
        stale_or_not(&disk, &owner, before),
        Some(StoreError::GrantStale)
    );
    ready_and_rule(&mut l, &[(1, BindingRole::Owner)]);
    assert!(
        l.trusted.queue.is_empty() && !l.trusted.busy(),
        "the same list: nothing"
    );
    assert_eq!(current(l.trusted.store().unwrap()), token, "kept");
}

/// The same on the timer (§10 «Запас», §14): guest 5's key is younger than the grace at
/// `agent_ready` — spared, the token kept; the tick once the grace ended takes 5 and replaces the
/// token, so a grant signed before is `grant_stale`.
#[tokio::test]
async fn a_spared_guest_taken_on_the_tick_replaces_the_grant_token() {
    let dir = Scratch::new();
    let owner = key();
    let w = NOW + 86_400_000;
    {
        let mut store = TrustStore::open_in(&dir.0);
        store
            .add(new_key(&owner), pair(1, BindingRole::Owner, false), NOW)
            .unwrap();
        store
            .add(new_key(&key()), pair(5, BindingRole::Guest, false), w)
            .unwrap();
    }
    let mut l = Loop::open(dir);
    let before = current(l.trusted.store().unwrap());
    l.trusted.store_for_notes().unwrap().set_wall_now(w + 1_000);
    ready_and_rule(&mut l, &[(1, BindingRole::Owner)]);
    l.settle().await;
    assert_eq!(current(l.trusted.store().unwrap()), before, "spared: kept");
    l.trusted
        .store_for_notes()
        .unwrap()
        .set_wall_now(w + UNBOUND_KEY_GRACE_MS);
    l.trusted.tick(Instant::now());
    assert_eq!(l.trusted.take_ruled(), (vec![5], true));
    let token = current(l.trusted.store().unwrap());
    assert_ne!(token, before, "taken: replaced");
    assert_eq!(
        stale_or_not(l.trusted.store().unwrap(), &owner, before),
        Some(StoreError::GrantStale)
    );
    l.settle().await;
    let disk = TrustStore::open_in(&l.dir.0);
    assert_eq!(disk.grant_token(), Some(token));
}

/// A person with no key here who drops out of the binding list (§10, §14): known only by the
/// stored last list, not named now — the token replaced in that write; the same list again
/// replaces nothing. A keyless former owner leaving the stored list at a reconciliation is a
/// removed person too: a new token (the owner's own `binding_removed` runs no rule:
/// `agent::…::a_keyless_owners_unbind_keeps_the_token_until_the_next_reconciliation`).
#[tokio::test]
async fn a_keyless_person_leaving_the_list_replaces_the_token_once() {
    for former_owner in [false, true] {
        let (dir, _, _, _) = seeded();
        let role = if former_owner {
            BindingRole::Owner
        } else {
            BindingRole::Guest
        };
        {
            let mut store = TrustStore::open_in(&dir.0);
            assert!(store.note_last_bindings([
                KnownBinding {
                    telegram_user_id: 1,
                    role: BindingRole::Owner,
                },
                KnownBinding {
                    telegram_user_id: 5,
                    role: BindingRole::Guest,
                },
                KnownBinding {
                    telegram_user_id: 7,
                    role,
                },
            ]));
            assert!(store.flush().unwrap());
        }
        let mut l = Loop::open(dir);
        let before = current(l.trusted.store().unwrap());
        let named = [(1, BindingRole::Owner), (5, BindingRole::Guest), (7, role)];
        ready_and_rule(&mut l, &named);
        l.settle().await;
        assert_eq!(current(l.trusted.store().unwrap()), before, "all named");
        // The next reconciliation: the list as it is now leaves 7 out.
        ready_and_rule(&mut l, &named[..2]);
        let token = current(l.trusted.store().unwrap());
        assert!(token != before, "former owner {former_owner}: replaced");
        assert_eq!(settle_counting(&mut l, 4).await, 1, "one write");
        let disk = TrustStore::open_in(&l.dir.0);
        assert_eq!(disk.grant_token(), Some(token));
        ready_and_rule(&mut l, &named[..2]);
        assert!(
            l.trusted.queue.is_empty() && !l.trusted.busy(),
            "former owner {former_owner}: the same list again: nothing"
        );
        assert_eq!(current(l.trusted.store().unwrap()), token, "kept");
    }
}

/// A reopen that reads the same healthy file again after a transient damage (§10, §7): while the
/// list was damaged the rule could not run; it runs at the reopen's landing — 5's key denied, 5
/// marked, the token replaced — before any offer is decided: a grant over the token from before
/// is `grant_stale` at once, and the one write carries it all. Refutes a rule that waits for the
/// next binding list or a later write after a repair.
#[tokio::test]
async fn a_healthy_reopen_after_transient_damage_runs_the_rule_first() {
    let (dir, owner, guest, _) = seeded();
    let primary = dir.0.join(FILE_NAME);
    let good = std::fs::read(&primary).unwrap();
    let mut l = Loop::open(dir);
    let before = current(l.trusted.store().unwrap());
    std::fs::write(&primary, b"garbage").unwrap();
    let mut reopen = l.ask(TrustedAsk::Repair(RepairAction::Reopen));
    l.settle().await;
    assert_eq!(answered(&mut reopen), Some(Ok(0)));
    assert!(l.trusted.store().unwrap().is_damaged());
    ready_and_rule(&mut l, &[(1, BindingRole::Owner)]);
    assert!(
        l.trusted.queue.is_empty() && !l.trusted.busy(),
        "not run while damaged"
    );
    std::fs::write(&primary, &good).unwrap();
    let mut reopen = l.ask(TrustedAsk::Repair(RepairAction::Reopen));
    let mut got = None;
    for _ in 0..4 {
        l.step().await;
        got = answered(&mut reopen);
        if got.is_some() {
            break;
        }
    }
    assert_eq!(got, Some(Ok(0)));
    {
        let store = l.trusted.store().unwrap();
        assert!(!store.is_damaged());
        assert!(matches!(
            store.lookup(guest.key_id()),
            Lookup::PendingRemoval(_)
        ));
        assert!(current(store) != before, "replaced at the landing");
        assert_eq!(
            stale_or_not(store, &owner, before),
            Some(StoreError::GrantStale)
        );
    }
    assert_eq!(settle_counting(&mut l, 4).await, 1, "one write");
    let disk = TrustStore::open_in(&l.dir.0);
    assert_eq!(
        disk.grant_token(),
        Some(current(l.trusted.store().unwrap()))
    );
    assert!(matches!(disk.lookup(guest.key_id()), Lookup::Removed(_)));
}

/// The stored list's departure alone (§7, §10): a keyless person drops out of the binding list —
/// the rule has nothing of theirs to remove, and the departure replaces the token, in one write.
/// The same list again replaces nothing. Refutes a departure that rotates nothing because the
/// person has no key.
#[tokio::test]
async fn a_keyless_person_leaving_the_stored_list_replaces_the_token_once() {
    let (dir, _, _, _) = seeded();
    {
        let mut store = TrustStore::open_in(&dir.0);
        assert!(store.note_last_bindings([
            KnownBinding {
                telegram_user_id: 1,
                role: BindingRole::Owner,
            },
            KnownBinding {
                telegram_user_id: 5,
                role: BindingRole::Guest,
            },
            KnownBinding {
                telegram_user_id: 7,
                role: BindingRole::Guest,
            },
        ]));
        assert!(store.flush().unwrap());
    }
    let mut l = Loop::open(dir);
    let before = current(l.trusted.store().unwrap());
    let named = [(1, BindingRole::Owner), (5, BindingRole::Guest)];
    ready_and_rule(&mut l, &named);
    let token = current(l.trusted.store().unwrap());
    assert!(token != before, "the departure replaced it");
    assert_eq!(settle_counting(&mut l, 4).await, 1, "one write");
    {
        let store = l.trusted.store().unwrap();
        assert_eq!(store.saved_grant_token(), Some(token));
    }
    let disk = TrustStore::open_in(&l.dir.0);
    assert_eq!(disk.grant_token(), Some(token));
    ready_and_rule(&mut l, &named);
    assert!(
        l.trusted.queue.is_empty() && !l.trusted.busy(),
        "the same list again: nothing"
    );
    assert_eq!(current(l.trusted.store().unwrap()), token, "kept");
}

/// A removal whose write fails (§7, §14): «Удалить человека» 5 decides at once — the token is
/// replaced in memory — and its write fails and waits. Meanwhile a grant over the old token is
/// `grant_stale`, and the token the server may hear (the saved one) is still the old one. The
/// retry once the disk takes writes replaces nothing again: the file gets the token decided at
/// the press.
#[tokio::test]
async fn a_removals_failed_write_keeps_its_one_new_token() {
    let (dir, owner, _, _) = seeded();
    let jammed = jam(&dir);
    let mut l = Loop::open(dir);
    let before = current(l.trusted.store().unwrap());
    let mut remove = l.ask(TrustedAsk::RemovePerson {
        telegram_user_id: 5,
    });
    l.settle().await;
    assert_eq!(answered(&mut remove), Some(Err(TrustedError::WriteFailed)));
    assert!(!l.trusted.parked.is_empty(), "the removal waits");
    let token = {
        let store = l.trusted.store().unwrap();
        let token = current(store);
        assert!(token != before && !token.is_empty());
        assert_eq!(store.saved_grant_token(), Some(before), "not written");
        assert_eq!(
            stale_or_not(store, &owner, before),
            Some(StoreError::GrantStale)
        );
        token
    };
    unjam(&jammed);
    l.trusted
        .tick(Instant::now() + PARKED_RETRY + Duration::from_secs(1));
    l.settle().await;
    assert!(l.trusted.parked.is_empty(), "landed");
    let store = l.trusted.store().unwrap();
    assert_eq!(current(store), token, "the retry replaced nothing");
    assert_eq!(store.saved_grant_token(), Some(token));
    let disk = TrustStore::open_in(&l.dir.0);
    assert_eq!(disk.grant_token(), Some(token));
}

/// An admission's write that fails after a removal was decided during it (§14): guest 7's key
/// (a pairing) is being written when the server removes guest 5; the disk then refuses every
/// write. The admission's change fails and only its key is gone — 5's mark and the new token stay
/// in memory, and land with the removal's own write once the disk takes writes.
#[tokio::test]
async fn a_failed_admission_write_takes_only_its_key_back() {
    use crate::admission::{AdmitOp, StoreOp};
    let (dir, _, guest, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let before = current(l.trusted.store().unwrap());
    let k = key();
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(new_key(&k), pair(7, BindingRole::Guest, false)),
    });
    assert!(l.trusted.busy(), "the admission's write is in flight");
    server_removes(&mut l, 5);
    let token = current(l.trusted.store().unwrap());
    assert!(token != before, "replaced during the admission's write");
    let jammed = jam(&l.dir);
    for _ in 0..(3 * MAX_ATTEMPTS + 6) {
        l.release();
    }
    l.settle().await;
    let landed = landed_of(&mut l);
    assert!(
        landed[&3].is_err(),
        "the admission failed: {:?}",
        landed[&3]
    );
    {
        let store = l.trusted.store().unwrap();
        assert!(
            matches!(store.lookup(k.key_id()), Lookup::Unknown),
            "its key gone"
        );
        assert_eq!(current(store), token, "the new token stays");
        assert_eq!(store.saved_grant_token(), Some(before));
    }
    unjam(&jammed);
    l.trusted
        .tick(Instant::now() + PARKED_RETRY + Duration::from_secs(1));
    for _ in 0..(MAX_ATTEMPTS + 4) {
        l.release();
    }
    l.settle().await;
    let disk = TrustStore::open_in(&l.dir.0);
    assert_eq!(disk.grant_token(), Some(token));
    assert_eq!(origin_of(&disk, &guest), "server");
    assert!(matches!(disk.lookup(k.key_id()), Lookup::Unknown));
}

// --- A rotation during a write: only a grant is decided by the token -------------------------

/// Release the gate and run every job out (at most `max`: a loop fails here, not by hanging).
async fn release_all(l: &mut Loop, max: usize) {
    let mut jobs = 0;
    while l.trusted.busy() || !l.trusted.queue.is_empty() {
        jobs += 1;
        assert!(jobs <= max, "more than {max} jobs: a write loop?");
        l.release();
        l.step().await;
    }
}

/// An endorse by the owner's phone is in flight when another person's removal replaces the grant
/// token (§6.5, §7): the key lands active and its endorse is spent. Refutes an install that
/// refuses every ground written under a new token.
#[tokio::test]
async fn an_endorse_landing_during_a_rotation_is_active() {
    use crate::admission::{AdmitOp, LandedOutcome, StoreOp};
    let (dir, owner, _, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let before = current(l.trusted.store().unwrap());
    let k = key();
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(
            new_key(&k),
            Ground::Endorse {
                by: owner.key_id().clone(),
                endorse_id: gid(40),
                issued_at: ISSUED,
            },
        ),
    });
    assert!(l.trusted.busy(), "in flight");
    assert!(server_removes_keyless(&mut l, 201, 901));
    assert!(
        current(l.trusted.store().unwrap()) != before,
        "replaced during the write"
    );
    release_all(&mut l, 8).await;
    let landed = landed_of(&mut l);
    assert!(
        matches!(&landed[&3], Ok(LandedOutcome::Added(_))),
        "{:?}",
        landed[&3]
    );
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert!(
            matches!(store.lookup(k.key_id()), Lookup::Active(_)),
            "{at}"
        );
        assert!(store.spent().unwrap().0.contains(&gid(40)), "{at}: spent");
    }
}

/// «Удалить человека» of the grantee pressed at the PC while the grant's write runs (§5, §7,
/// §10): the token is replaced, so the grant lands stale — `grant_stale`, its key denied and
/// removed `server`. A new invited grant over the current token then passes: the removal at the
/// PC keeps no person out. Refutes a grant over the old token that slips past the removal.
#[tokio::test]
async fn the_grantee_removed_at_the_pc_during_the_grants_write() {
    use crate::admission::{AdmitOp, StoreOp};
    let (dir, owner, _, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let k = key();
    let token = current(l.trusted.store().unwrap());
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(new_key(&k), grant_for(&owner, 5, 9, token)),
    });
    assert!(l.trusted.busy(), "in flight");
    let mut remove = l.ask(TrustedAsk::RemovePerson {
        telegram_user_id: 5,
    });
    release_all(&mut l, 10).await;
    assert_eq!(answered(&mut remove).map(|r| r.is_ok()), Some(true));
    let landed = landed_of(&mut l);
    assert!(
        matches!(&landed[&3], Err(StoreError::GrantStale)),
        "{:?}",
        landed[&3]
    );
    for (store, at) in [
        (l.trusted.store().unwrap(), "memory"),
        (&TrustStore::open_in(&l.dir.0), "disk"),
    ] {
        assert_eq!(origin_of(store, &k), "server", "{at}");
    }
    let store = l.trusted.store().unwrap();
    let now_token = current(store);
    assert!(now_token != token, "replaced");
    assert_eq!(
        store
            .check_add(
                &new_key(&key()),
                &grant_for(&owner, 5, 21, token),
                NOW + 5_000
            )
            .err(),
        Some(StoreError::GrantStale),
        "the old grant"
    );
    assert!(
        store
            .check_add(
                &new_key(&key()),
                &grant_for(&owner, 5, 22, now_token),
                NOW + 5_000
            )
            .is_ok(),
        "a new invited grant passes"
    );
}

/// A stale landing is one refusal and one journal line (§7): the grant's ticket lands once,
/// `grant_stale`, and the PC's journal gets one entry for its key — its removal, written with the
/// write that took it — never an addition before it. Refutes a stale key journaled as added, or
/// refused twice.
#[tokio::test]
async fn a_stale_landing_is_one_refusal_and_one_journal_line() {
    use crate::admission::{AdmitOp, StoreOp};
    let (dir, owner, _, _) = seeded();
    let mut l = Loop::open(dir).gated();
    let kinds_before = l.kinds().len();
    let k = key();
    l.trusted.admit(AdmitOp {
        ticket: 3,
        op: StoreOp::add(
            new_key(&k),
            grant_for(&owner, 9, 3, current(l.trusted.store().unwrap())),
        ),
    });
    assert!(server_removes_keyless(&mut l, 201, 901));
    release_all(&mut l, 8).await;
    let mine: Vec<_> = l
        .trusted
        .take_landed()
        .into_iter()
        .filter(|d| d.ticket == 3)
        .collect();
    assert_eq!(mine.len(), 1, "landed once");
    assert!(
        matches!(mine[0].result, Err(StoreError::GrantStale)),
        "{:?}",
        mine[0].result
    );
    assert_eq!(l.kinds()[kinds_before..], [Kind::DeviceUntrusted]);
    assert_eq!(origin_of(&TrustStore::open_in(&l.dir.0), &k), "server");
}

// --- Strict mode goes on only over the owner's own confirmed device (§10.2) --------------------

/// A list of exactly `grounds` (each a person, a role and whether it is unconfirmed).
fn list_of(grounds: &[(i64, BindingRole, bool)]) -> (Scratch, Vec<ViewerKey>) {
    let dir = Scratch::new();
    let mut store = TrustStore::open_in(&dir.0);
    let keys: Vec<ViewerKey> = grounds
        .iter()
        .map(|&(uid, role, unconfirmed)| {
            let k = key();
            store
                .add(new_key(&k), pair(uid, role, unconfirmed), NOW)
                .unwrap();
            k
        })
        .collect();
    (dir, keys)
}

/// «Включить» from a window opened now: its answer once the loop has run.
async fn mode_on(l: &mut Loop) -> Option<TrustedReply> {
    let token = l.view().token;
    let mut rx = l.ask(TrustedAsk::SetMode {
        on: true,
        token: Some(token),
    });
    l.settle().await;
    answered(&mut rx)
}

/// No key, only an unconfirmed owner key, only a guest key: «Включить» is refused
/// `no_owner_device`, nothing is written, and the view says the switch may not go on. Refutes a
/// switch that shuts the owner out of his own PC.
#[tokio::test]
async fn strict_mode_is_refused_without_a_confirmed_owner_device() {
    for (what, grounds, says) in [
        ("no key", vec![], OwnerDevice::Missing),
        (
            "an unconfirmed owner key",
            vec![(1, BindingRole::Owner, true)],
            OwnerDevice::Unconfirmed,
        ),
        (
            "a guest key",
            vec![(5, BindingRole::Guest, false)],
            OwnerDevice::Missing,
        ),
    ] {
        let (dir, _) = list_of(&grounds);
        let mut l = Loop::open(dir);
        assert_eq!(l.view().owner_device, says, "{what}: the view says why");
        assert_eq!(
            mode_on(&mut l).await,
            Some(Err(TrustedError::NoOwnerDevice)),
            "{what}"
        );
        assert!(!l.view().trusted_mode, "{what}: still off");
        let disk = TrustStore::open_in(&l.dir.0);
        assert!(
            !disk.switches().unwrap().trusted_devices_mode,
            "{what}: not on disk"
        );
    }
}

/// An owner key that does not work — its removal decided — does not let the mode on either.
#[tokio::test]
async fn a_leaving_owner_key_does_not_let_strict_mode_on() {
    let (dir, keys) = list_of(&[(1, BindingRole::Owner, false)]);
    let mut l = Loop::open(dir);
    assert_eq!(l.view().owner_device, OwnerDevice::Ready);
    l.trusted
        .store_mut()
        .unwrap()
        .deny_now(&[keys[0].key_id().clone()]);
    assert_eq!(
        mode_on(&mut l).await,
        Some(Err(TrustedError::NoOwnerDevice)),
        "leaving"
    );
}

/// Two owner keys, one confirmed: ready whichever comes first in the list.
#[tokio::test]
async fn one_confirmed_owner_key_among_unconfirmed_ones_is_ready() {
    let (dir, _) = list_of(&[
        (1, BindingRole::Owner, true),
        (1, BindingRole::Owner, false),
    ]);
    let l = Loop::open(dir);
    assert_eq!(l.view().owner_device, OwnerDevice::Ready);
}

/// One working, confirmed owner key: the mode goes on; off always goes, with or without one.
#[tokio::test]
async fn strict_mode_goes_on_over_a_confirmed_owner_device_and_off_always() {
    let (dir, _) = list_of(&[
        (1, BindingRole::Owner, false),
        (5, BindingRole::Guest, true),
    ]);
    let mut l = Loop::open(dir);
    assert_eq!(l.view().owner_device, OwnerDevice::Ready);
    assert!(matches!(mode_on(&mut l).await, Some(Ok(_))));
    assert!(l.view().trusted_mode);

    let (dir, _) = list_of(&[]);
    let mut l = Loop::open(dir);
    {
        let store = l.trusted.store_mut().unwrap();
        assert_eq!(store.set_trusted_devices_mode(true), Ok(()));
    }
    let mut off = l.ask(TrustedAsk::SetMode {
        on: false,
        token: None,
    });
    l.settle().await;
    assert!(
        matches!(answered(&mut off), Some(Ok(_))),
        "off with no owner device"
    );
    assert!(!l.view().trusted_mode);
}

/// The owner's last such device leaves between the press and the stage (its removal decided
/// while another write is in flight): the stage refuses the switch again. Refutes a check made at
/// the press only.
#[tokio::test]
async fn strict_mode_is_refused_at_its_stage_once_the_owner_device_is_leaving() {
    let (dir, keys) = list_of(&[
        (1, BindingRole::Owner, false),
        (5, BindingRole::Guest, true),
    ]);
    let mut l = Loop::open(dir).gated();
    // A write in flight («Подтвердить» the guest's key), so the switch waits in the queue.
    let mut confirm = l.ask(TrustedAsk::Confirm {
        key_id: keys[1].key_id().clone(),
        token: l.view().token,
    });
    let token = l.view().token;
    let mut on = l.ask(TrustedAsk::SetMode {
        on: true,
        token: Some(token),
    });
    assert!(answered(&mut on).is_none(), "passed at the press, queued");
    l.trusted
        .store_mut()
        .unwrap()
        .deny_now(&[keys[0].key_id().clone()]);
    for _ in 0..4 {
        l.release();
    }
    l.settle().await;
    assert!(matches!(answered(&mut confirm), Some(Ok(_))));
    assert_eq!(answered(&mut on), Some(Err(TrustedError::NoOwnerDevice)));
    assert!(!l.view().trusted_mode);
}
