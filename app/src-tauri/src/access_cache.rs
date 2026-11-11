//! Who has access, as the main view shows it before the server has answered this run.
//!
//! The backend sends this device's bindings at every handshake (`AgentState::bindings`, from
//! `bindings_known` on), about a second after launch. Waiting for it with a loader in the zone
//! under the hero, then putting the pairing steps or the card there, moves the hero each time. Two
//! things are known without the server:
//!
//! - **a new device** — config.json was written by this launch (`Config::created`): its device id is
//!   one the backend has never seen, so nobody can have access, and the window shows the pairing
//!   steps at once ([`AccessSource::NewDevice`]);
//! - **the last list** — the one the server sent last time, kept in [`FILE_NAME`] beside config.json
//!   ([`AccessSource::Cache`]): shown at once, and replaced by the server's as soon as it comes. The
//!   server wins whatever it says («nobody» included, and the zone then turns to the steps); how its
//!   list differs from the cache is logged.
//!
//! With neither — a build before this file, or a device whose list never came — the loader
//! ([`AccessSource::Unknown`]).
//!
//! The file holds what the window shows of each person — the Telegram id, first name, @username and
//! role («Владелец» on the owner's row) — and the device id and server the list
//! was heard for: a list written for another device or another server is not shown. A file from a
//! build before roles has no role on anyone and is read as it is (no role shown until the server
//! answers); the layout's version stays, since nothing it had is read differently. It is written whenever the server's list differs from it — at the handshake,
//! after a pairing or an unbind — by the state watcher (`lib.rs`, every half second whether the
//! window is open or not), and once more on the way out.
//!
//! A file of its own rather than a field of config.json: config.json is the owner's settings, shared
//! with the CLI and carried by «Отправить логи» field by field; this is the server's data, disposable
//! (deleted, it comes back at the next handshake), rewritten at every change of the list, and a broken
//! one must never stop the config from loading. It stays out of the diagnostics report, which reads
//! only the files it names (`diagnostics::package`).
//!
//! Threads (KB-4): the window's [`AccessCache::view`] runs on the main thread (`get_status`), so
//! the state's lock is never held over the file. A write is planned under the lock
//! ([`AccessCache::plan`]: a snapshot and a generation), done without it ([`AccessCache::write`]:
//! on the blocking pool for the state watcher, inline at the exit), and only the latest planned
//! list is written: writes go one at a time under a lock of their own that `view` never takes, and
//! one overtaken by a newer list is skipped, so an older list never lands over a newer one.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use afklink_core::{BindingInfo, BindingRole};
use serde::{Deserialize, Serialize};

/// The cache's file, in the data directory beside config.json.
pub(crate) const FILE_NAME: &str = "access-cache.json";

/// The file's layout. A file of another version is not read (and is rewritten at the handshake).
const VERSION: u32 = 1;

/// A write longer than this is a warning: a slow disk or an antivirus holding the file.
const SLOW_WRITE: Duration = Duration::from_secs(1);

/// `from` of the exit's write (`lib.rs`): the one write the process waits for.
pub(crate) const FROM_EXIT: &str = "exit";

/// One person with access, as the window shows them.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct CachedBinding {
    pub(crate) telegram_user_id: i64,
    #[serde(default)]
    pub(crate) first_name: Option<String>,
    #[serde(default)]
    pub(crate) username: Option<String>,
    /// The role the server last gave; absent from a file written before roles, and for a server
    /// that sends none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) role: Option<BindingRole>,
}

impl From<&BindingInfo> for CachedBinding {
    fn from(b: &BindingInfo) -> Self {
        Self {
            telegram_user_id: b.telegram_user_id,
            first_name: b.first_name.clone(),
            username: b.username.clone(),
            role: b.role,
        }
    }
}

/// [`FILE_NAME`] on disk.
#[derive(Serialize, Deserialize, Debug)]
struct CacheFile {
    version: u32,
    /// The device the list was heard for (config.json's `device_id`).
    device_id: String,
    /// The server it was heard from (config.json's `server_url`): a development server has other
    /// bindings for the same device id.
    server_url: String,
    /// When it was written, Unix ms: how old the list is, for the log.
    saved_at_ms: i64,
    bindings: Vec<CachedBinding>,
}

/// Where the window's access list comes from (`StatusDto.access`).
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccessSource {
    /// The server's list, heard this run.
    Server,
    /// Not heard yet this run; the list the server sent last time.
    Cache,
    /// Not heard yet, and this device is new (config.json written by this launch): nobody.
    NewDevice,
    /// Not heard yet, and nothing else known: the loader.
    Unknown,
}

impl AccessSource {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Cache => "cache",
            Self::NewDevice => "new_device",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the list is known, from wherever: the zone shows the steps or the card, not the loader.
    pub(crate) const fn known(self) -> bool {
        !matches!(self, Self::Unknown)
    }

    const fn why(self) -> &'static str {
        match self {
            Self::Server => "the server's list, heard this run",
            Self::Cache => {
                "the list the server sent last time (access-cache.json), until it answers this run"
            }
            Self::NewDevice => {
                "a new device (config.json written at this launch): nobody can have access yet, \
                 no need to wait for the server"
            }
            Self::Unknown => {
                "nothing known yet: no answer from the server this run and no cache (a build \
                 before it, or no list ever heard) — the loader"
            }
        }
    }
}

/// Where the list comes from, by what is known: the server's once heard, else a new device's
/// nobody, else the cache, else nothing.
pub(crate) fn source(heard: bool, new_device: bool, cached: bool) -> AccessSource {
    if heard {
        AccessSource::Server
    } else if new_device {
        AccessSource::NewDevice
    } else if cached {
        AccessSource::Cache
    } else {
        AccessSource::Unknown
    }
}

/// The access list the window shows, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessView {
    pub(crate) source: AccessSource,
    pub(crate) bindings: Vec<CachedBinding>,
}

/// How the server's first list of a run differs from the cache it replaces.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Divergence {
    /// In the server's list, not in the cache.
    pub(crate) added: Vec<i64>,
    /// In the cache, not in the server's list (unbound while this app was not running).
    pub(crate) removed: Vec<i64>,
    /// In both, under another first name or @username.
    pub(crate) renamed: Vec<i64>,
    /// In both, with another role (the owner changed while this app was not running).
    pub(crate) role_changed: Vec<i64>,
}

impl Divergence {
    pub(crate) fn none(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.renamed.is_empty()
            && self.role_changed.is_empty()
    }
}

/// How `server` differs from `cached`, by Telegram id; the order of the lists does not count.
pub(crate) fn compare(cached: &[CachedBinding], server: &[CachedBinding]) -> Divergence {
    let mut d = Divergence::default();
    for s in server {
        match cached
            .iter()
            .find(|c| c.telegram_user_id == s.telegram_user_id)
        {
            None => d.added.push(s.telegram_user_id),
            Some(c) => {
                if c.first_name != s.first_name || c.username != s.username {
                    d.renamed.push(s.telegram_user_id);
                }
                if c.role != s.role {
                    d.role_changed.push(s.telegram_user_id);
                }
            }
        }
    }
    for c in cached {
        if !server
            .iter()
            .any(|s| s.telegram_user_id == c.telegram_user_id)
        {
            d.removed.push(c.telegram_user_id);
        }
    }
    d
}

/// What the run has done with the file.
#[derive(Debug, Default)]
struct SyncState {
    /// What the file holds, as far as this run knows: the list read at launch (for this device and
    /// server), then the one last written. `None`: nothing usable is on disk.
    on_disk: Option<Vec<CachedBinding>>,
    /// The server's first list of this run has been compared with the cache (logged once).
    compared: bool,
    /// Writes planned this run; the latest one's number is the generation that may write (an
    /// older one, overtaken while it waited, is skipped).
    planned: u64,
    /// The latest planned list while its write is not done: the file is about to hold it, so the
    /// next ticks do not plan it again.
    queued: Option<Vec<CachedBinding>>,
    /// A write of this list failed: not tried again until the list changes, so the warning is said
    /// once per list, not every half second.
    failed: Option<Vec<CachedBinding>>,
    /// The window's source as last logged, so each change is said once.
    shown: Option<AccessSource>,
}

/// A write planned by [`AccessCache::plan`]: the snapshot to put on disk, done by
/// [`AccessCache::write`] without the state's lock.
#[derive(Debug)]
pub(crate) struct PendingWrite {
    /// The plan's number (`SyncState::planned`): written only while it is still the latest.
    generation: u64,
    path: PathBuf,
    /// Who asked, for the log (the state watcher, the exit).
    from: &'static str,
    why: &'static str,
    file: CacheFile,
}

impl PendingWrite {
    /// The plan's number, for [`AccessCache::lost`] when the write never ran or did not finish.
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Test-only: called inside the write, before the file is touched (a slow disk, parked).
#[cfg(test)]
struct WriteHook(Box<dyn Fn() + Send + Sync>);

#[cfg(test)]
impl std::fmt::Debug for WriteHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WriteHook")
    }
}

/// The cache, its launch reading, and this device's newness.
#[derive(Debug)]
pub(crate) struct AccessCache {
    /// `None`: no data directory (said at launch); nothing is read or written.
    path: Option<PathBuf>,
    device_id: String,
    server_url: String,
    /// config.json was written by this launch.
    new_device: bool,
    /// The list read at launch for this device and server; `None` when there was none.
    launch: Option<Vec<CachedBinding>>,
    /// Short decisions only: never held over the file (the window's `view` takes it on the main
    /// thread).
    state: Mutex<SyncState>,
    /// Held over the file by the one write going on, so writes land in order. Taken before
    /// `state`, never the other way round; `view` and `plan` never take it.
    writing: Mutex<()>,
    #[cfg(test)]
    hook: Option<WriteHook>,
}

impl AccessCache {
    /// The cache at [`FILE_NAME`] in the data directory (`afklink_core::paths::afklink_dir`), read now.
    pub(crate) fn open_default(device_id: &str, server_url: &str, new_device: bool) -> Self {
        let path = match afklink_core::paths::afklink_dir() {
            Ok(dir) => Some(dir.join(FILE_NAME)),
            Err(e) => {
                tracing::warn!(
                    "access cache: no data directory ({e:#}); the main view waits for the server's \
                     list at every launch"
                );
                None
            }
        };
        Self::open(
            path,
            device_id,
            server_url,
            new_device,
            afklink_core::journal::now_ms(),
        )
    }

    /// The cache at `path`, read now (`now_ms`: for the age in the log). Every outcome is logged:
    /// which list the main view starts with, and why.
    pub(crate) fn open(
        path: Option<PathBuf>,
        device_id: &str,
        server_url: &str,
        new_device: bool,
        now_ms: i64,
    ) -> Self {
        let launch = path
            .as_deref()
            .and_then(|p| read(p, device_id, server_url, now_ms));
        let start = source(false, new_device, launch.is_some());
        tracing::info!(
            source = start.as_str(),
            bindings = launch.as_ref().map_or(0, Vec::len),
            new_device,
            "main view at launch: {}",
            start.why()
        );
        if new_device && launch.is_some() {
            // `read` refuses another device's list, and a new device's id was generated just now.
            tracing::warn!(
                "access cache: a list for a device id generated at this launch; ignored"
            );
        }
        Self {
            path,
            device_id: device_id.to_string(),
            server_url: server_url.to_string(),
            new_device,
            state: Mutex::new(SyncState {
                on_disk: launch.clone(),
                ..SyncState::default()
            }),
            writing: Mutex::new(()),
            #[cfg(test)]
            hook: None,
            launch,
        }
    }

    /// Test-only: `hook` runs inside every write, before the file is touched.
    #[cfg(test)]
    fn with_write_hook(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.hook = Some(WriteHook(Box::new(hook)));
        self
    }

    /// The list read at launch — the one the server sent last time, for this device and server — as
    /// the agent compares the first list of this run with it (access given or taken away while
    /// the app was not running is journaled and announced). `None`: none was read, or this is a new
    /// device (nobody can have had access).
    pub(crate) fn last_list(&self) -> Option<Vec<BindingInfo>> {
        if self.new_device {
            return None;
        }
        self.launch.as_ref().map(|list| {
            list.iter()
                .map(|c| BindingInfo {
                    telegram_user_id: c.telegram_user_id,
                    username: c.username.clone(),
                    first_name: c.first_name.clone(),
                    role: c.role,
                })
                .collect()
        })
    }

    /// The list for the window: the server's once `heard` this run (`bindings_known`), else what is
    /// known without it. Each change of where it comes from is logged once.
    pub(crate) fn view(&self, server: &[BindingInfo], heard: bool) -> AccessView {
        let source = source(heard, self.new_device, self.launch.is_some());
        let bindings = match source {
            AccessSource::Server => server.iter().map(CachedBinding::from).collect(),
            AccessSource::Cache => self.launch.clone().unwrap_or_default(),
            AccessSource::NewDevice | AccessSource::Unknown => Vec::new(),
        };
        let mut s = afklink_core::lock(&self.state);
        if s.shown != Some(source) {
            tracing::debug!(
                from = s.shown.map_or("-", AccessSource::as_str),
                to = source.as_str(),
                bindings = bindings.len(),
                "window's access list: {}",
                source.why()
            );
            s.shown = Some(source);
        }
        AccessView { source, bindings }
    }

    /// Bring the file in line with the server's list, once it is `heard`, here and now: [`plan`],
    /// then [`write`] on this thread. A list planned earlier whose write is not done (still waiting
    /// on the blocking pool, which may never run it once the process ends) is written here too.
    /// Blocks on the file and on a write already going on, so only where blocking is allowed: the
    /// exit, the tests — never on the async runtime.
    ///
    /// [`plan`]: Self::plan
    /// [`write`]: Self::write
    pub(crate) fn sync(&self, server: &[BindingInfo], heard: bool, from: &'static str) {
        let job = self
            .plan(server, heard, from)
            .or_else(|| self.plan_queued(from));
        if let Some(job) = job {
            self.write(job);
        }
    }

    /// The list planned earlier and not on disk yet, planned again under a new generation, so this
    /// caller writes it and the earlier write, when its turn comes, is skipped.
    fn plan_queued(&self, from: &'static str) -> Option<PendingWrite> {
        let path = self.path.clone()?;
        let mut s = afklink_core::lock(&self.state);
        let list = s.queued.clone()?;
        s.planned += 1;
        let generation = s.planned;
        tracing::debug!(
            generation,
            bindings = list.len(),
            from,
            "access cache: a planned write is not done yet; written here and now"
        );
        Some(PendingWrite {
            generation,
            path,
            from,
            why: "planned before and not written yet",
            file: CacheFile {
                version: VERSION,
                device_id: self.device_id.clone(),
                server_url: self.server_url.clone(),
                saved_at_ms: afklink_core::journal::now_ms(),
                bindings: list,
            },
        })
    }

    /// What to write so the file follows the server's list, once it is `heard`: `None` when the
    /// file holds it or is about to (a write of it going on), or a write of it failed and the list
    /// has not changed since. `from`: who asks, for the log (the state watcher, the exit). The
    /// server's first list of a run is compared with the cache it replaces, and the difference
    /// logged. Takes the state's lock for the decision only: no file is touched.
    pub(crate) fn plan(
        &self,
        server: &[BindingInfo],
        heard: bool,
        from: &'static str,
    ) -> Option<PendingWrite> {
        if !heard {
            return None;
        }
        let list: Vec<CachedBinding> = server.iter().map(CachedBinding::from).collect();
        let mut s = afklink_core::lock(&self.state);
        if !s.compared {
            s.compared = true;
            self.log_first_list(&list);
        }
        // What the file will hold once the write going on is done, else what it holds. Checked
        // every half second: no log when nothing is to be done.
        if s.queued.as_ref().or(s.on_disk.as_ref()) == Some(&list) {
            return None;
        }
        if s.queued.is_none() && s.failed.as_ref() == Some(&list) {
            return None;
        }
        let Some(path) = self.path.clone() else {
            // Said at launch: there is nowhere to write.
            return None;
        };
        let why = if s.planned == 0 {
            "the server's list of this run"
        } else {
            "the list changed (a pairing, an unbind, a new owner, or a reconnect's new list)"
        };
        s.planned += 1;
        let generation = s.planned;
        if let Some(older) = &s.queued {
            tracing::debug!(
                generation,
                overtaken = older.len(),
                bindings = list.len(),
                from,
                "access cache: a newer list while a write is going on; the older one is written \
                 over or skipped"
            );
        }
        s.queued = Some(list.clone());
        Some(PendingWrite {
            generation,
            path,
            from,
            why,
            file: CacheFile {
                version: VERSION,
                device_id: self.device_id.clone(),
                server_url: self.server_url.clone(),
                saved_at_ms: afklink_core::journal::now_ms(),
                bindings: list,
            },
        })
    }

    /// Put a planned list on disk, without the state's lock: blocks on the file, so off the async
    /// runtime (the blocking pool) or where blocking is allowed (the exit). One write at a time;
    /// a plan overtaken by a newer one before its turn is skipped, so the file ends with the latest
    /// list whatever order the writes come in.
    pub(crate) fn write(&self, job: PendingWrite) {
        let PendingWrite {
            generation,
            path,
            from,
            why,
            file,
        } = job;
        let _writing = afklink_core::lock(&self.writing);
        {
            let s = afklink_core::lock(&self.state);
            if s.planned != generation {
                tracing::debug!(
                    generation,
                    latest = s.planned,
                    bindings = file.bindings.len(),
                    from,
                    "access cache: write skipped, a newer list was planned after it"
                );
                return;
            }
        }
        #[cfg(test)]
        if let Some(hook) = &self.hook {
            (hook.0)();
        }
        let started = Instant::now();
        let result = write_file(&path, &file);
        let took = started.elapsed();
        let took_ms = u64::try_from(took.as_millis()).unwrap_or(u64::MAX);
        let mut s = afklink_core::lock(&self.state);
        // Still the latest: what was planned is settled. Overtaken while on disk (planned again
        // during the write): the newer plan stays queued, and its write comes next.
        let latest = s.planned == generation;
        if took > SLOW_WRITE {
            let waited = if from == FROM_EXIT {
                "the exit waited for it"
            } else {
                "on the blocking pool: the window and the state watcher did not wait for it"
            };
            tracing::warn!(
                took_ms,
                from,
                path = %path.display(),
                "access cache: the write was slow (a busy disk or an antivirus); {waited}"
            );
        }
        match result {
            Ok(()) => {
                tracing::debug!(
                    bindings = file.bindings.len(),
                    was = s.on_disk.as_ref().map_or(-1, |l| l.len() as i64),
                    generation,
                    latest,
                    took_ms,
                    from,
                    path = %path.display(),
                    "access cache written: {why}"
                );
                if latest {
                    s.queued = None;
                    s.failed = None;
                }
                s.on_disk = Some(file.bindings);
            }
            Err(e) => {
                tracing::warn!(
                    bindings = file.bindings.len(),
                    generation,
                    latest,
                    took_ms,
                    from,
                    "access cache not written ({e}); the next launch shows the list it had before \
                     until the server answers"
                );
                if latest {
                    s.queued = None;
                    s.failed = Some(file.bindings);
                }
            }
        }
    }

    /// A planned write that never ran or did not finish (its blocking task panicked or was
    /// cancelled): while it is still the latest plan, its list is no longer counted as on its way,
    /// so the next tick plans it again rather than leaving it to the exit. An overtaken plan
    /// changes nothing: the newer one is on its way.
    pub(crate) fn lost(&self, generation: u64, why: &str) {
        let mut s = afklink_core::lock(&self.state);
        if s.planned != generation {
            tracing::warn!(
                generation,
                latest = s.planned,
                "access cache: a write was lost ({why}); a newer list is on its way, nothing to \
                 plan again"
            );
            return;
        }
        let bindings = s.queued.take().map_or(0, |l| l.len());
        tracing::warn!(
            generation,
            bindings,
            "access cache: a write was lost ({why}); the list is planned again at the next tick"
        );
    }

    /// The server's first list of this run against what the window showed before it.
    fn log_first_list(&self, list: &[CachedBinding]) {
        match (&self.launch, self.new_device) {
            (_, true) if !list.is_empty() => tracing::warn!(
                bindings = list.len(),
                "access: the server lists bindings for a device created at this launch; the window \
                 follows the server"
            ),
            (_, true) => tracing::debug!(
                "access: the server's first list is empty, as for any new device: the pairing steps \
                 shown at launch stay"
            ),
            (None, false) => tracing::debug!(
                bindings = list.len(),
                "access: the server's first list of this run; there was no cache (the loader was \
                 shown until now)"
            ),
            (Some(cached), false) => {
                let d = compare(cached, list);
                if d.none() {
                    tracing::debug!(
                        bindings = list.len(),
                        "access: the server's list matches the cache: nothing changes on screen"
                    );
                } else {
                    let turn = match (cached.is_empty(), list.is_empty()) {
                        (false, true) => "; nobody has access now: the card gives way to the steps",
                        (true, false) => "; the steps give way to the card",
                        _ => "",
                    };
                    tracing::debug!(
                        cached = cached.len(),
                        bindings = list.len(),
                        added = ?d.added,
                        removed = ?d.removed,
                        renamed = ?d.renamed,
                        role_changed = ?d.role_changed,
                        "access: the server's list differs from the cache; the window follows the \
                         server{turn}"
                    );
                }
            }
        }
    }
}

/// The list in the file at `path`, when it is one for this device and server.
fn read(path: &Path, device_id: &str, server_url: &str, now_ms: i64) -> Option<Vec<CachedBinding>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(
                path = %path.display(),
                "access cache: none on disk (a build before it, a new device, or no list heard yet)"
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), "access cache not read: {e}; ignored");
            return None;
        }
    };
    let file: CacheFile = match serde_json::from_str(&text) {
        Ok(file) => file,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                "access cache unreadable ({e}); ignored, and rewritten at the next handshake"
            );
            return None;
        }
    };
    if file.version != VERSION {
        tracing::debug!(
            version = file.version,
            expected = VERSION,
            "access cache of another layout; ignored, and rewritten at the next handshake"
        );
        return None;
    }
    if file.device_id != device_id {
        tracing::debug!(
            cached_for = %file.device_id,
            device_id,
            "access cache is another device's (config.json was replaced); ignored"
        );
        return None;
    }
    if file.server_url != server_url {
        tracing::debug!(
            cached_from = %file.server_url,
            server = server_url,
            "access cache is from another server; ignored"
        );
        return None;
    }
    tracing::debug!(
        bindings = file.bindings.len(),
        age_s = (now_ms - file.saved_at_ms) / 1000,
        "access cache read: the list the server sent last time"
    );
    Some(file.bindings)
}

/// Write `file` to `path` whole: a temporary file beside it, then renamed over it, so a crash
/// halfway leaves the old list rather than half a new one.
fn write_file(path: &Path, file: &CacheFile) -> Result<(), String> {
    let text = serde_json::to_string_pretty(file).map_err(|e| format!("serialize: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        if let Err(gone) = std::fs::remove_file(&tmp) {
            tracing::debug!(tmp = %tmp.display(), "access cache: temporary file not removed: {gone}");
        }
        format!("replace {}: {e}", path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: &str = "843eda6a-0000-4000-8000-000000000000";
    const SERVER: &str = "wss://example.test/ws/agent";

    /// A data directory of its own under the temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("afklink-access-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn file(&self) -> PathBuf {
            self.0.join(FILE_NAME)
        }

        fn open(&self, new_device: bool) -> AccessCache {
            AccessCache::open(Some(self.file()), DEVICE, SERVER, new_device, 0)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn binding(id: i64, first_name: &str, username: Option<&str>) -> BindingInfo {
        BindingInfo {
            telegram_user_id: id,
            first_name: Some(first_name.to_string()),
            username: username.map(str::to_string),
            role: None,
        }
    }

    fn with_role(mut b: BindingInfo, role: BindingRole) -> BindingInfo {
        b.role = Some(role);
        b
    }

    /// The roles are kept for the next launch, so the owner's row says «Владелец» from the first
    /// frame; a file written before roles reads as no role on anyone; a new owner is a change.
    #[test]
    fn the_roles_are_kept_and_a_file_without_them_still_reads() {
        let dir = TempDir::new();
        let cache = dir.open(false);
        let owner = with_role(binding(7, "Вера", Some("vera")), BindingRole::Owner);
        let guest = with_role(binding(9, "Аня", None), BindingRole::Guest);
        cache.sync(&[owner.clone(), guest.clone()], true, "test");
        let next = dir.open(false);
        let view = next.view(&[], false);
        assert_eq!(view.bindings[0].role, Some(BindingRole::Owner));
        assert_eq!(view.bindings[1].role, Some(BindingRole::Guest));

        // The owner changed while the app was not running: a difference, and written.
        let swapped = [
            with_role(binding(7, "Вера", Some("vera")), BindingRole::Guest),
            with_role(binding(9, "Аня", None), BindingRole::Owner),
        ];
        let d = compare(
            &[CachedBinding::from(&owner), CachedBinding::from(&guest)],
            &swapped.iter().map(CachedBinding::from).collect::<Vec<_>>(),
        );
        assert_eq!(d.role_changed, [7, 9]);
        assert!(d.renamed.is_empty());
        assert!(!d.none());

        // A file from a build before roles.
        let old = format!(
            r#"{{"version": 1, "device_id": "{DEVICE}", "server_url": "{SERVER}",
            "saved_at_ms": 0, "bindings": [{{"telegram_user_id": 7, "first_name": "Вера"}}]}}"#
        );
        std::fs::write(dir.file(), old).expect("write");
        let view = dir.open(false).view(&[], false);
        assert_eq!(view.source, AccessSource::Cache);
        assert_eq!(view.bindings[0].role, None);
        // And no role is written for a server that sends none.
        dir.open(false)
            .sync(&[binding(7, "Вера", Some("vera"))], true, "test");
        let text = std::fs::read_to_string(dir.file()).expect("written");
        assert!(text.contains("vera"), "rewritten: {text}");
        assert!(!text.contains("role"), "{text}");
    }

    fn ids(view: &AccessView) -> Vec<i64> {
        view.bindings.iter().map(|b| b.telegram_user_id).collect()
    }

    #[test]
    fn the_source_follows_what_is_known() {
        // The server's list, once heard, whatever else is known.
        assert_eq!(source(true, false, false), AccessSource::Server);
        assert_eq!(source(true, true, false), AccessSource::Server);
        assert_eq!(source(true, false, true), AccessSource::Server);
        // Before it: a new device is nobody; else the cache; else nothing.
        assert_eq!(source(false, true, false), AccessSource::NewDevice);
        assert_eq!(source(false, true, true), AccessSource::NewDevice);
        assert_eq!(source(false, false, true), AccessSource::Cache);
        assert_eq!(source(false, false, false), AccessSource::Unknown);
        assert!(!AccessSource::Unknown.known());
        assert!(AccessSource::NewDevice.known() && AccessSource::Cache.known());
    }

    /// A new device shows nobody before the server says a word: the pairing steps at once.
    #[test]
    fn a_new_device_is_nobody_without_waiting() {
        let dir = TempDir::new();
        let cache = dir.open(true);
        let view = cache.view(&[], false);
        assert_eq!(view.source, AccessSource::NewDevice);
        assert!(view.bindings.is_empty());
        // The server's empty list changes nothing on screen, and is written.
        cache.sync(&[], true, "test");
        let view = cache.view(&[], true);
        assert_eq!(view.source, AccessSource::Server);
        assert!(view.bindings.is_empty());
        assert!(dir.file().exists());
    }

    /// The list heard in one run is what the next run shows until the server answers.
    #[test]
    fn a_written_list_is_read_back_at_the_next_launch() {
        let dir = TempDir::new();
        let first = dir.open(false);
        assert_eq!(first.view(&[], false).source, AccessSource::Unknown);
        // Nothing is written before the server answers.
        first.sync(&[], false, "test");
        assert!(!dir.file().exists());

        let server = [binding(7, "Вера", Some("vera")), binding(9, "Аня", None)];
        first.sync(&server, true, "test");
        assert!(dir.file().exists());

        let next = dir.open(false);
        let view = next.view(&[], false);
        assert_eq!(view.source, AccessSource::Cache);
        assert_eq!(ids(&view), [7, 9]);
        assert_eq!(view.bindings[0].first_name.as_deref(), Some("Вера"));
        assert_eq!(view.bindings[0].username.as_deref(), Some("vera"));
        assert_eq!(view.bindings[1].username, None);
        // Only what the window shows is kept.
        let text = std::fs::read_to_string(dir.file()).expect("written");
        assert!(text.contains(DEVICE) && text.contains(SERVER), "{text}");
    }

    /// The server wins over the cache, «nobody» included, and the file follows it.
    #[test]
    fn the_server_wins_over_the_cache() {
        let dir = TempDir::new();
        dir.open(false).sync(
            &[binding(7, "Вера", None), binding(9, "Аня", None)],
            true,
            "test",
        );

        let cache = dir.open(false);
        assert_eq!(ids(&cache.view(&[], false)), [7, 9]);
        // Unbound in the Mini App while the app was not running.
        let server = [binding(7, "Вера", None)];
        let view = cache.view(&server, true);
        assert_eq!(view.source, AccessSource::Server);
        assert_eq!(ids(&view), [7]);
        cache.sync(&server, true, "test");
        assert_eq!(ids(&dir.open(false).view(&[], false)), [7]);

        // Then everyone unbound: the next launch starts on the steps, from the cache.
        cache.sync(&[], true, "test");
        let next = dir.open(false);
        let view = next.view(&[], false);
        assert_eq!(view.source, AccessSource::Cache);
        assert!(view.bindings.is_empty());
    }

    #[test]
    fn the_difference_is_counted_by_id() {
        let cached = [
            CachedBinding::from(&binding(1, "A", None)),
            CachedBinding::from(&binding(2, "B", Some("b"))),
            CachedBinding::from(&binding(3, "C", None)),
        ];
        let server = [
            CachedBinding::from(&binding(2, "B", Some("b_new"))),
            CachedBinding::from(&binding(3, "C", None)),
            CachedBinding::from(&binding(4, "D", None)),
        ];
        let d = compare(&cached, &server);
        assert_eq!(d.added, [4]);
        assert_eq!(d.removed, [1]);
        assert_eq!(d.renamed, [2]);
        assert!(!d.none());
        // The same people in another order: no difference.
        let mut reversed = cached.clone();
        reversed.reverse();
        assert!(compare(&cached, &reversed).none());
    }

    /// The file is written when the list changes, not on every tick.
    #[test]
    fn the_file_is_written_only_when_the_list_changes() {
        let dir = TempDir::new();
        let cache = dir.open(false);
        let server = [binding(7, "Вера", None)];
        cache.sync(&server, true, "test");
        std::fs::remove_file(dir.file()).expect("written");
        // The same list again: the run knows the file has it, and does not write.
        cache.sync(&server, true, "test");
        assert!(!dir.file().exists());
        // A pairing: written.
        cache.sync(
            &[binding(7, "Вера", None), binding(8, "Боря", None)],
            true,
            "test",
        );
        assert_eq!(ids(&dir.open(false).view(&[], false)), [7, 8]);
    }

    /// A list for another device id (config.json replaced) or another server is not shown, and is
    /// replaced by this device's at the handshake.
    #[test]
    fn another_device_or_server_is_not_shown() {
        let dir = TempDir::new();
        AccessCache::open(Some(dir.file()), "another-device", SERVER, false, 0).sync(
            &[binding(7, "Вера", None)],
            true,
            "test",
        );
        assert_eq!(
            dir.open(false).view(&[], false).source,
            AccessSource::Unknown
        );
        // A new device never shows an old one's list.
        assert_eq!(
            dir.open(true).view(&[], false).source,
            AccessSource::NewDevice
        );

        AccessCache::open(
            Some(dir.file()),
            DEVICE,
            "ws://localhost:8787/ws/agent",
            false,
            0,
        )
        .sync(&[binding(7, "Вера", None)], true, "test");
        assert_eq!(
            dir.open(false).view(&[], false).source,
            AccessSource::Unknown
        );

        // This device's list replaces it.
        dir.open(false)
            .sync(&[binding(9, "Аня", None)], true, "test");
        assert_eq!(ids(&dir.open(false).view(&[], false)), [9]);
    }

    /// A list heard from another server is not this one's: not shown under the production server
    /// (a config.json that named another address moves to it at load, `afklink_core::config`), nor
    /// the other way round. It is rewritten at the next handshake.
    #[test]
    fn a_list_heard_from_another_server_is_ignored() {
        use afklink_core::config::PROD_SERVER_URL;
        let other = "wss://old.example.test/ws/agent";
        for (from, to) in [(other, PROD_SERVER_URL), (PROD_SERVER_URL, other)] {
            let dir = TempDir::new();
            AccessCache::open(Some(dir.file()), DEVICE, from, false, 0).sync(
                &[binding(7, "Вера", None)],
                true,
                "test",
            );
            let moved = AccessCache::open(Some(dir.file()), DEVICE, to, false, 0);
            assert_eq!(
                moved.view(&[], false).source,
                AccessSource::Unknown,
                "{from} -> {to}"
            );
        }
    }

    #[test]
    fn a_broken_or_foreign_file_is_ignored() {
        let dir = TempDir::new();
        std::fs::write(dir.file(), "{ not json").expect("write");
        assert_eq!(
            dir.open(false).view(&[], false).source,
            AccessSource::Unknown
        );
        let other = r#"{"version": 99, "device_id": "843eda6a-0000-4000-8000-000000000000",
            "server_url": "wss://example.test/ws/agent", "saved_at_ms": 0, "bindings": []}"#;
        std::fs::write(dir.file(), other).expect("write");
        assert_eq!(
            dir.open(false).view(&[], false).source,
            AccessSource::Unknown
        );
        // Rewritten at the handshake.
        dir.open(false).sync(&[], true, "test");
        assert_eq!(dir.open(false).view(&[], false).source, AccessSource::Cache);
    }

    /// A write that fails is said once for its list and tried again when the list changes; the
    /// window keeps the server's list either way.
    #[test]
    fn a_failed_write_is_not_retried_every_tick() {
        let dir = TempDir::new();
        let path = dir.0.join("missing-dir").join(FILE_NAME);
        let cache = AccessCache::open(Some(path.clone()), DEVICE, SERVER, false, 0);
        let server = [binding(7, "Вера", None)];
        cache.sync(&server, true, "test");
        assert!(!path.exists());
        assert_eq!(
            afklink_core::lock(&cache.state).failed.as_deref(),
            Some(&[CachedBinding::from(&server[0])][..])
        );
        assert_eq!(ids(&cache.view(&server, true)), [7]);
        // The directory comes back: the next change of the list is written.
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create");
        cache.sync(&server, true, "test");
        assert!(!path.exists(), "the same list is not tried again");
        cache.sync(&[], true, "test");
        assert!(path.exists());
    }

    /// What must answer while a write is parked on a slow disk, as KB-4 asks. Generous for a loaded gate (thread start included): a write parked on the barrier never
    /// lets a blocked reader answer at all, so any bound tells the two apart.
    const QUICK: Duration = Duration::from_millis(1500);

    /// A hook that parks the `nth` write (1-based) inside it: says so on `entered`, then waits on
    /// `release`. Other writes go through.
    fn park_write(
        nth: usize,
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::Arc<std::sync::Barrier>,
    ) -> impl Fn() + Send + Sync + 'static {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let entered = Mutex::new(entered);
        move || {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == nth {
                let _ = afklink_core::lock(&entered).send(());
                release.wait();
            }
        }
    }

    /// KB-4: a write parked on a slow disk does not hold the window. `view` (the main thread's
    /// `get_status`) and a status-like read — the agent's state copied out under its own lock, the
    /// cache asked after — answer at once, and the agent's state stays free for the orchestrator;
    /// the next tick's `plan` answers at once too, and does not plan the same list again.
    #[test]
    fn a_slow_write_does_not_hold_the_window() {
        use std::sync::mpsc;
        use std::sync::{Arc, Barrier};

        let dir = TempDir::new();
        let (entered_tx, entered) = mpsc::channel();
        let release = Arc::new(Barrier::new(2));
        let cache = Arc::new(dir.open(false).with_write_hook(park_write(
            1,
            entered_tx,
            Arc::clone(&release),
        )));
        let server = vec![binding(7, "Вера", None)];
        // Stands in for `AgentControl::state`: the server's list and whether it was heard.
        let control = Arc::new(Mutex::new((server.clone(), true)));

        let writer = {
            let cache = Arc::clone(&cache);
            let server = server.clone();
            std::thread::spawn(move || cache.sync(&server, true, "test"))
        };
        let parked = entered.recv_timeout(Duration::from_secs(5));

        let (tx, answered) = mpsc::channel();
        {
            let (cache, control) = (Arc::clone(&cache), Arc::clone(&control));
            std::thread::spawn(move || {
                let t = Instant::now();
                let window = cache.view(&[], false);
                let (bindings, heard) = {
                    let s = afklink_core::lock(&control);
                    (s.0.clone(), s.1)
                };
                let status = cache.view(&bindings, heard);
                let again = cache.plan(&bindings, heard, "test");
                let _ = tx.send((t.elapsed(), window, status, again.is_none()));
            });
        }
        let got = answered.recv_timeout(QUICK);
        let orchestrator = {
            let t = Instant::now();
            let s = afklink_core::lock(&control);
            drop(s);
            t.elapsed()
        };
        // Let the write go before any assertion, so a failure does not leave a thread parked.
        release.wait();
        writer.join().expect("writer");

        parked.expect("the write reached the disk step");
        let (took, window, status, not_again) =
            got.expect("view() and a status-like read answer while the write is parked");
        assert!(took < QUICK, "{took:?}");
        assert_eq!(window.source, AccessSource::Unknown);
        assert_eq!(status.source, AccessSource::Server);
        assert_eq!(ids(&status), [7]);
        assert!(not_again, "the list being written is not planned again");
        assert!(orchestrator < QUICK, "{orchestrator:?}");
        assert_eq!(ids(&dir.open(false).view(&[], false)), [7]);
    }

    /// Two quick changes of the list: whatever order their writes run in, the file ends with the
    /// newer one — an older write that comes late is skipped, one already on disk is written over.
    #[test]
    fn two_quick_syncs_leave_the_newer_list() {
        // The newer write runs first: the older one, coming after, is skipped.
        let dir = TempDir::new();
        let cache = dir.open(false);
        let older = cache
            .plan(&[binding(7, "Вера", None)], true, "test")
            .expect("planned");
        let newer = cache
            .plan(&[binding(9, "Аня", None)], true, "test")
            .expect("planned");
        cache.write(newer);
        cache.write(older);
        assert_eq!(ids(&dir.open(false).view(&[], false)), [9]);
        {
            let s = afklink_core::lock(&cache.state);
            assert_eq!(s.on_disk.as_ref().map(Vec::len), Some(1));
            assert_eq!(s.on_disk.as_ref().expect("on disk")[0].telegram_user_id, 9);
            assert!(s.queued.is_none());
        }
        // Settled: the same list is not planned again.
        assert!(cache
            .plan(&[binding(9, "Аня", None)], true, "test")
            .is_none());
    }

    /// The older write is on the disk when the list changes back: the newer plan waits for it and
    /// lands after it.
    #[test]
    fn a_change_during_a_write_lands_after_it() {
        use std::sync::mpsc;
        use std::sync::{Arc, Barrier};

        let dir = TempDir::new();
        let (entered_tx, entered) = mpsc::channel();
        let release = Arc::new(Barrier::new(2));
        // The first write (the launch's list) goes through; the second parks.
        let cache = Arc::new(dir.open(false).with_write_hook(park_write(
            2,
            entered_tx,
            Arc::clone(&release),
        )));
        let before = [binding(7, "Вера", None)];
        cache.sync(&before, true, "test");

        let paired = [binding(7, "Вера", None), binding(9, "Аня", None)];
        let job = cache.plan(&paired, true, "test").expect("planned");
        let first = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || cache.write(job))
        };
        let parked = entered.recv_timeout(Duration::from_secs(5));
        // The same list while it is written: nothing new.
        let same = cache.plan(&paired, true, "test");
        // Unbound again at once: back to the list the file held before — planned, since the file
        // is about to hold the other.
        let back = cache.plan(&before, true, "test");
        let second = back.map(|job| {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || cache.write(job))
        });
        release.wait();
        first.join().expect("first write");
        let had_second = second.map(|h| h.join().expect("second write")).is_some();

        parked.expect("the first write reached the disk step");
        assert!(
            same.is_none(),
            "the list being written is not planned again"
        );
        assert!(
            had_second,
            "the change back is planned while the other is written"
        );
        assert_eq!(ids(&dir.open(false).view(&[], false)), [7]);
        assert!(afklink_core::lock(&cache.state).queued.is_none());
    }

    /// The exit writes a list the watcher planned that the blocking pool never ran; the late
    /// write, if it runs after all, is skipped.
    #[test]
    fn the_exit_writes_a_planned_write_not_done_yet() {
        let dir = TempDir::new();
        let cache = dir.open(false);
        let server = [binding(7, "Вера", None)];
        let pending = cache.plan(&server, true, "state watcher").expect("planned");
        assert!(!dir.file().exists());
        cache.sync(&server, true, FROM_EXIT);
        assert_eq!(ids(&dir.open(false).view(&[], false)), [7]);
        std::fs::remove_file(dir.file()).expect("written");
        cache.write(pending);
        assert!(!dir.file().exists(), "the overtaken write is skipped");
    }

    /// A write that fails after a newer list was planned during it: not counted as this list's
    /// failure (the newer plan stays on its way), and the newer list lands.
    #[test]
    fn a_failed_write_overtaken_during_it_leaves_the_newer_one() {
        use std::sync::mpsc;
        use std::sync::{Arc, Barrier};

        let dir = TempDir::new();
        let path = dir.0.join("missing-dir").join(FILE_NAME);
        let (entered_tx, entered) = mpsc::channel();
        let release = Arc::new(Barrier::new(2));
        let cache = Arc::new(
            AccessCache::open(Some(path.clone()), DEVICE, SERVER, false, 0)
                .with_write_hook(park_write(1, entered_tx, Arc::clone(&release))),
        );
        let older = cache
            .plan(&[binding(7, "Вера", None)], true, "test")
            .expect("planned");
        let first = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || cache.write(older))
        };
        let parked = entered.recv_timeout(Duration::from_secs(5));
        let newer = cache.plan(&[binding(9, "Аня", None)], true, "test");
        release.wait();
        first.join().expect("first write");

        parked.expect("the first write reached the disk step");
        let newer = newer.expect("the change is planned while the other is written");
        {
            let s = afklink_core::lock(&cache.state);
            assert!(
                s.failed.is_none(),
                "an overtaken failure is not the list's failure"
            );
            assert_eq!(
                s.queued.as_deref(),
                Some(&[CachedBinding::from(&binding(9, "Аня", None))][..])
            );
            assert!(s.on_disk.is_none());
        }
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create");
        cache.write(newer);
        let s = afklink_core::lock(&cache.state);
        assert!(s.queued.is_none() && s.failed.is_none());
        assert_eq!(s.on_disk.as_ref().map(|l| l[0].telegram_user_id), Some(9));
        assert!(path.exists());
    }

    /// The latest write fails: settled as failed, and the same list is not planned again on the
    /// next ticks (the warning once per list); another list is.
    #[test]
    fn a_failed_latest_write_is_not_planned_again() {
        let dir = TempDir::new();
        let path = dir.0.join("missing-dir").join(FILE_NAME);
        let cache = AccessCache::open(Some(path), DEVICE, SERVER, false, 0);
        let server = [binding(7, "Вера", None)];
        let job = cache.plan(&server, true, "test").expect("planned");
        cache.write(job);
        {
            let s = afklink_core::lock(&cache.state);
            assert!(s.queued.is_none());
            assert!(s.failed.is_some());
        }
        assert!(cache.plan(&server, true, "test").is_none());
        assert!(cache.plan(&server, true, "test").is_none());
        assert!(cache.plan(&[], true, "test").is_some());
    }

    /// A write that never ran (its blocking task panicked or was cancelled) is planned again at
    /// the next tick once reported lost; a lost plan already overtaken changes nothing.
    #[test]
    fn a_lost_write_is_planned_again() {
        let dir = TempDir::new();
        let cache = dir.open(false);
        let server = [binding(7, "Вера", None)];
        let job = cache.plan(&server, true, "state watcher").expect("planned");
        // On its way: not planned again.
        assert!(cache.plan(&server, true, "state watcher").is_none());
        cache.lost(job.generation(), "test: the task panicked");
        drop(job);
        let again = cache
            .plan(&server, true, "state watcher")
            .expect("planned again after the loss");
        cache.write(again);
        assert_eq!(ids(&dir.open(false).view(&[], false)), [7]);

        // Overtaken, then lost: the newer list stays on its way.
        let older = cache
            .plan(&[binding(8, "Боря", None)], true, "test")
            .expect("planned");
        let newer = cache.plan(&[], true, "test").expect("planned");
        cache.lost(older.generation(), "test: the task panicked");
        assert!(cache.plan(&[], true, "test").is_none());
        cache.write(newer);
        assert!(dir.open(false).view(&[], false).bindings.is_empty());
    }
}
