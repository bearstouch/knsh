//! `knshd`'s state store: the live grants and the policy snapshots the authority pushed, kept in one file so they
//! survive a restart (FR-POL-60, `specs/02-architecture/process-model.md`; KNSH-071).
//!
//! # The file
//!
//! `state.json` in the engine data directory ([`knsh_platform::EnginePaths::state_file`]), a versioned JSON object:
//!
//! ```json
//! {"version": 1,
//!  "snapshots": [{"profile": "web-app", "policy": "name = \"web-app\"\n…", "expires_at": "…"}],
//!  "grants": [{"grant_id": "01J…", "scope": "session", "session_id": "01J…", "profile": null,
//!              "rule": "git push", "exact": false, "expires_at": "…"}]}
//! ```
//!
//! - **Atomic and owner-only.** Every change rewrites the whole file with [`Fs::atomic_replace`] (temporary file,
//!   flush, rename) as `0600` (NFR-SEC-08). The data directory is `0700` and among the fixed denies of every profile,
//!   so no agent can read or write it.
//! - **One writer.** Only this module writes the file, under its own lock: the grant store and the pushed policies
//!   each hand it their whole half after a change, while holding their own lock, so the file always follows the
//!   latest change of each half (lock order: the half's lock, then this one's; this one is a leaf).
//! - **Never overwritten when unusable: set aside instead (KNSH-074).** A file that is not a `0600` regular file of
//!   this user, is too large, does not parse, or has a newer `version` is never written over. At start `knshd`
//!   renames it, without replacing anything ([`Fs::rename_new`]), to `state.json.corrupt-<µs>` (or
//!   `state.json.newer-<µs>` for a newer version; `.<n>` is appended if that name is taken), logs that it did, and
//!   starts with no grants and no pushed policy. The set-aside file keeps its bytes for the user or a newer `knshd`
//!   to inspect; this one never reads it again. Starting empty fails closed: a lost grant only removes a permission,
//!   and a lost snapshot leaves its sessions on local profiles or paused (KNSH-072), never on a weaker policy.
//! - **Frozen when it cannot be set aside.** A file that cannot even be examined (an I/O or permission error, which
//!   may pass) or whose rename fails is left exactly as it is: the store is *frozen*, every save fails, and the
//!   callers refuse the change (`-32603`) rather than lose what the file holds. The next start tries again.
//! - **What is restored.** [`StateStore::open`] returns what a readable file holds; `knshd` gives the snapshots back
//!   to the pushed policies and the unexpired grants back to the grant store. Expired grants are dropped then and
//!   are never written again. Secrets the authority supplies are memory-only and never reach this file.
//!
//! # Privacy
//!
//! Nothing here logs a profile's text, a rule or a session: only fixed reasons.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::{Grant, GrantId, GrantScope, MAX_GRANTS, ProfileName, SessionId, Timestamp};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};
use knsh_platform::engine_dirs::FILE_MODE;
use knsh_platform::{Field, FileKind, Fs, Level, PlatformError, SystemLog};

use crate::pushed::{MAX_SNAPSHOTS, Snapshot};

/// The file format this build writes and reads.
const VERSION: u64 = 1;

/// How many set-aside names [`set_aside`] tries for one start: `-<µs>`, then `-<µs>.1` and so on. Another file of
/// the same microsecond needs a clock that went back, so more than one attempt is already rare.
const ASIDE_ATTEMPTS: u32 = 8;

/// Largest state file read, in bytes: every snapshot at the profile size limit, each character escaped, plus the
/// grants. Anything larger was not written by `knshd`.
const MAX_STATE_LEN: usize = MAX_SNAPSHOTS * knsh_core::MAX_PROFILE_LEN * 2 + MAX_GRANTS * 8192 + 4096;

/// Why the state could not be saved. Either way the change that asked for the save is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SaveError {
    /// The file on disk could not be read when `knshd` started: it is kept as it is (module documentation).
    Frozen,
    /// Encoding or writing the file failed; the previous file is still in place.
    Write,
}

/// What the state file holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct State {
    /// Pushed policy, one snapshot per profile.
    pub(crate) snapshots: Vec<Snapshot>,
    /// Grants, live when written.
    pub(crate) grants: Vec<Grant>,
}

/// The state store (module documentation).
pub(crate) struct StateStore {
    /// Where to write, or `None` for a store kept in memory only (tests).
    file: Option<StateFile>,
    /// The last state saved: each half is replaced by its owner, and the whole is written.
    state: Mutex<State>,
    /// Set when the file on disk could not be read: never written then.
    frozen: bool,
    log: Arc<dyn SystemLog>,
}

/// The file and how it is written.
struct StateFile {
    fs: Arc<dyn Fs>,
    path: PathBuf,
}

impl StateStore {
    /// A store that keeps nothing on disk, for tests: every save succeeds and nothing survives a restart.
    #[cfg(test)]
    pub(crate) fn in_memory(log: Arc<dyn SystemLog>) -> Arc<Self> {
        Arc::new(Self {
            file: None,
            state: Mutex::new(State::default()),
            frozen: false,
            log,
        })
    }

    /// Opens the state file at `path`, owned by `uid`, and returns the store with what the file holds (module
    /// documentation, "What is restored"). A missing file is an empty state. An unusable file is set aside, named
    /// after `now` (the start time, or the Unix epoch when the clock failed), and the state starts empty; a file that
    /// cannot be examined or set aside is left as it is and the store is frozen. Either is reported to `log`.
    pub(crate) fn open(
        fs: Arc<dyn Fs>,
        path: PathBuf,
        uid: u32,
        now: Option<Timestamp>,
        log: Arc<dyn SystemLog>,
    ) -> (Arc<Self>, State) {
        let (state, frozen) = match read_state(fs.as_ref(), &path, uid) {
            Ok(state) => (state, false),
            Err(unusable) => (
                State::default(),
                !recover(fs.as_ref(), &path, unusable, now, log.as_ref()),
            ),
        };
        let store = Arc::new(Self {
            file: Some(StateFile { fs, path }),
            state: Mutex::new(state.clone()),
            frozen,
            log,
        });
        (store, state)
    }

    /// Saves `snapshots` as the pushed-policy half (module documentation, "One writer").
    ///
    /// # Errors
    ///
    /// [`SaveError`]: nothing was written, and the half the store keeps is unchanged.
    pub(crate) fn save_snapshots(&self, snapshots: Vec<Snapshot>) -> Result<(), SaveError> {
        self.save(|state| state.snapshots = snapshots)
    }

    /// Saves `grants` as the grants half.
    ///
    /// # Errors
    ///
    /// As [`StateStore::save_snapshots`].
    pub(crate) fn save_grants(&self, grants: Vec<Grant>) -> Result<(), SaveError> {
        self.save(|state| state.grants = grants)
    }

    /// The state as last saved.
    #[cfg(test)]
    pub(crate) fn saved(&self) -> State {
        lock(&self.state).clone()
    }

    /// Applies `change` to a copy of the state, writes the copy, and keeps it once written.
    fn save(&self, change: impl FnOnce(&mut State)) -> Result<(), SaveError> {
        if self.frozen {
            return Err(SaveError::Frozen);
        }
        let mut state = lock(&self.state);
        let mut next = state.clone();
        change(&mut next);
        if let Some(file) = &self.file {
            let written = knsh_json::write(&encode(&next).map_err(|_| SaveError::Write)?)
                .map_err(|_| SaveError::Write)
                // Never write a file the next start could not read back (it would freeze the store and lose every
                // grant and snapshot): a grant made from an answer carries an agent's line, up to 64 KiB, which
                // can exceed the per-grant share of the bound. The change is refused instead (fail closed).
                .and_then(|text| {
                    if text.len() > MAX_STATE_LEN {
                        Err(SaveError::Write)
                    } else {
                        Ok(text)
                    }
                })
                .and_then(|text| {
                    file.fs
                        .atomic_replace(&file.path, text.as_bytes(), FILE_MODE)
                        .map_err(|_| SaveError::Write)
                });
            if let Err(error) = written {
                self.log.log(Level::Error, "state file not written", &[]);
                return Err(error);
            }
        }
        *state = next;
        Ok(())
    }
}

/// Sets the `unusable` file at `path` aside, named after `now`, and reports what happened to `log`. Returns whether
/// the path is now free to write; `false` leaves the file exactly where and as it is, and the store must be frozen.
fn recover(
    fs: &dyn Fs,
    path: &std::path::Path,
    unusable: Unusable,
    now: Option<Timestamp>,
    log: &dyn SystemLog,
) -> bool {
    // Not examinable (an I/O or permission error that may pass): leave it alone and try again at the next start.
    let Some(kind) = unusable.aside_kind() else {
        log_frozen(
            log,
            "state file unreadable; kept as it is, and grants and pushed policy cannot be saved",
            unusable.reason(),
        );
        return false;
    };
    // The rename failed: the file stays where it is, so nothing may write over it.
    let Some(stamp) = set_aside(fs, path, kind, now) else {
        log_frozen(
            log,
            "state file unusable and could not be set aside; kept as it is, and grants and pushed policy cannot be saved",
            unusable.reason(),
        );
        return false;
    };
    log.log(
        Level::Error,
        "state file unusable; set aside, and grants and pushed policy start empty",
        &[
            Field::new("reason", knsh_platform::Value::Static(unusable.reason())),
            Field::new("kept_as", knsh_platform::Value::Static(kind)),
            Field::new("stamp", knsh_platform::Value::U64(stamp)),
        ],
    );
    true
}

/// Logs that the file was left in place and the store is frozen.
fn log_frozen(log: &dyn SystemLog, message: &'static str, reason: &'static str) {
    log.log(
        Level::Error,
        message,
        &[Field::new("reason", knsh_platform::Value::Static(reason))],
    );
}

/// Why the state file at start cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unusable {
    /// It could not be examined or read: an I/O or permission error, which may pass.
    Unreadable,
    /// Not a `0600` regular file of this user (a symlink, a directory, another owner, other modes).
    NotPrivate,
    /// Larger than any file `knshd` writes.
    TooLarge,
    /// Not the format: bad JSON, an unknown member, a value out of range, an older version.
    Corrupt,
    /// Written by a newer `knshd`.
    NewerVersion,
}

impl Unusable {
    /// The fixed reason for the log.
    fn reason(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::NotPrivate => "not_private",
            Self::TooLarge => "too_large",
            Self::Corrupt => "corrupt",
            Self::NewerVersion => "newer_version",
        }
    }

    /// The set-aside name's kind, or `None` when the file is left in place (module documentation). Only a file this
    /// build read and judged is moved: an error reading it says nothing about its contents.
    fn aside_kind(self) -> Option<&'static str> {
        match self {
            Self::Unreadable => None,
            Self::NotPrivate | Self::TooLarge | Self::Corrupt => Some("corrupt"),
            Self::NewerVersion => Some("newer"),
        }
    }
}

/// Renames the file at `path` to `<name>.<kind>-<µs>` (or `…-<µs>.<n>` when taken) next to it, never replacing an
/// entry, and returns the microseconds used, or `None` when nothing moved. A symlink is moved itself, never its
/// target.
fn set_aside(fs: &dyn Fs, path: &std::path::Path, kind: &str, now: Option<Timestamp>) -> Option<u64> {
    let stamp = now.map_or(0, Timestamp::as_unix_micros);
    let name = path.file_name()?.to_string_lossy();
    for attempt in 0..ASIDE_ATTEMPTS {
        let aside = if attempt == 0 {
            format!("{name}.{kind}-{stamp}")
        } else {
            format!("{name}.{kind}-{stamp}.{attempt}")
        };
        match fs.rename_new(path, &path.with_file_name(aside)) {
            Ok(()) => return Some(stamp),
            // Taken (a clock that went back, or a set-aside of the same microsecond): try the next name.
            Err(error) if error.is_already_exists() => {}
            Err(_) => return None,
        }
    }
    None
}

/// Reads the state file, or why it cannot be used.
fn read_state(fs: &dyn Fs, path: &std::path::Path, uid: u32) -> Result<State, Unusable> {
    match fs.metadata(path) {
        Ok(meta) if meta.kind == FileKind::File && meta.uid == uid && meta.mode == FILE_MODE => {}
        Ok(_) => return Err(Unusable::NotPrivate),
        Err(error) if error.is_not_found() => return Ok(State::default()),
        Err(_) => return Err(Unusable::Unreadable),
    }
    let bytes = fs.read(path, MAX_STATE_LEN as u64).map_err(|error| match error {
        PlatformError::TooLarge { .. } => Unusable::TooLarge,
        _ => Unusable::Unreadable,
    })?;
    let value = knsh_json::parse(&bytes, MAX_STATE_LEN).map_err(|_| Unusable::Corrupt)?;
    decode(&value)
}

/// The file's JSON (module documentation).
fn encode(state: &State) -> Result<Value, JsonError> {
    let snapshots = state
        .snapshots
        .iter()
        .map(|snapshot| {
            Object::new()
                .with("profile", snapshot.profile.as_str())?
                .with("policy", snapshot.policy.as_str())?
                .with("expires_at", snapshot.expires_at.to_string())
                .map(Value::Object)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let grants = state
        .grants
        .iter()
        .map(|grant| {
            let (scope, session_id, profile) = match grant.scope() {
                GrantScope::Session(session_id) => ("session", Some(session_id.to_string()), None),
                GrantScope::Profile(profile) => ("profile", None, Some(profile.as_str().to_owned())),
            };
            Object::new()
                .with("grant_id", grant.id().to_string())?
                .with("scope", scope)?
                .with("session_id", session_id.to_json()?)?
                .with("profile", profile.to_json()?)?
                .with("rule", grant.rule())?
                .with("exact", grant.is_exact())?
                .with("expires_at", grant.expires_at().to_string())
                .map(Value::Object)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Object::new()
        .with("version", VERSION.to_json()?)?
        .with("snapshots", Value::Array(snapshots))?
        .with("grants", Value::Array(grants))
        .map(Value::Object)
}

/// Reads the file's JSON. Closed objects throughout: a member this build does not know means a format it does not
/// understand, and guessing would rewrite the file without it.
fn decode(value: &Value) -> Result<State, Unusable> {
    let corrupt = |_| Unusable::Corrupt;
    let mut fields = Fields::new(value).map_err(corrupt)?;
    let version: u64 = fields.required("version").map_err(corrupt)?;
    if version > VERSION {
        // A newer knshd wrote it: set aside for that version, never downgraded by this one.
        return Err(Unusable::NewerVersion);
    }
    if version != VERSION {
        return Err(Unusable::Corrupt);
    }
    let snapshots: Vec<Value> = fields.required("snapshots").map_err(corrupt)?;
    let grants: Vec<Value> = fields.required("grants").map_err(corrupt)?;
    fields.finish_closed().map_err(corrupt)?;
    if snapshots.len() > MAX_SNAPSHOTS || grants.len() > MAX_GRANTS {
        return Err(Unusable::Corrupt);
    }
    let snapshots = snapshots
        .iter()
        .map(|value| Snapshot::from_json(value).map_err(corrupt))
        .collect::<Result<Vec<_>, _>>()?;
    let grants = grants
        .iter()
        .map(|value| StoredGrant::from_json(value).map(|stored| stored.0).map_err(corrupt))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(State { snapshots, grants })
}

impl FromJson for Snapshot {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let profile: String = fields.required("profile")?;
        let policy: String = fields.required("policy")?;
        let expires_at: String = fields.required("expires_at")?;
        fields.finish_closed()?;
        let invalid = || JsonError::OutOfRange { field: None };
        Ok(Self {
            profile: ProfileName::new(&profile).map_err(|_| invalid())?,
            policy,
            expires_at: expires_at.parse().map_err(|_| invalid())?,
        })
    }
}

/// A grant as the file holds it; its rule is checked again as it is read, as when it was made.
struct StoredGrant(Grant);

impl FromJson for StoredGrant {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let grant_id: String = fields.required("grant_id")?;
        let scope: String = fields.required("scope")?;
        let session_id: Option<String> = fields.optional("session_id")?;
        let profile: Option<String> = fields.optional("profile")?;
        let rule: String = fields.required("rule")?;
        let exact: bool = fields.required("exact")?;
        let expires_at: String = fields.required("expires_at")?;
        fields.finish_closed()?;
        let invalid = || JsonError::OutOfRange { field: None };
        let id: GrantId = grant_id.parse().map_err(|_| invalid())?;
        let scope = match (scope.as_str(), session_id, profile) {
            ("session", Some(session_id), None) => {
                GrantScope::Session(session_id.parse::<SessionId>().map_err(|_| invalid())?)
            }
            ("profile", None, Some(profile)) => GrantScope::Profile(ProfileName::new(&profile).map_err(|_| invalid())?),
            _ => return Err(invalid()),
        };
        let expires_at: Timestamp = expires_at.parse().map_err(|_| invalid())?;
        let grant = if exact {
            Grant::exact(id, scope, &rule, expires_at)
        } else {
            Grant::new(id, scope, &rule, expires_at)
        };
        grant.map(Self).map_err(|_| invalid())
    }
}

/// Takes the lock even if a thread panicked while holding it: the state is replaced whole, after its write.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;

    use knsh_core::Ulid;
    use knsh_platform::Operation;
    use knsh_platform::testing::{DEFAULT_UID, MemFs, RecordingLog};

    use super::*;

    /// The state file of the test home, from the one place engine paths are built.
    pub(crate) fn path() -> PathBuf {
        knsh_platform::EnginePaths::for_home(Path::new("/Users/u"))
            .unwrap()
            .state_file()
    }

    /// A file system holding the test home's data directory.
    pub(crate) fn fs() -> Arc<MemFs> {
        let fs = Arc::new(MemFs::new());
        fs.add_dir_all(path().parent().unwrap()).unwrap();
        fs
    }

    fn at(seconds: u64) -> Timestamp {
        Timestamp::from_unix_micros(seconds * 1_000_000).unwrap()
    }

    pub(crate) fn snapshot(profile: &str, expires_at: Timestamp) -> Snapshot {
        Snapshot {
            profile: ProfileName::new(profile).unwrap(),
            policy: format!("name = \"{profile}\"\n"),
            expires_at,
        }
    }

    fn grants() -> Vec<Grant> {
        let id = |n| GrantId::from_ulid(Ulid::from_u128(n));
        vec![
            Grant::new(
                id(1),
                GrantScope::Session(SessionId::from_ulid(Ulid::from_u128(7))),
                "git push",
                at(100),
            )
            .unwrap(),
            Grant::exact(
                id(2),
                GrantScope::Profile(ProfileName::new("web").unwrap()),
                "rm -r build",
                at(200),
            )
            .unwrap(),
        ]
    }

    /// The start time the tests open the store at, which names a set-aside file.
    const STARTED: u64 = 1_000;

    fn open(fs: &Arc<MemFs>) -> (Arc<StateStore>, State, Arc<RecordingLog>) {
        let log = Arc::new(RecordingLog::new());
        let (store, state) = StateStore::open(fs.clone(), path(), DEFAULT_UID, Some(at(STARTED)), log.clone());
        (store, state, log)
    }

    /// `state.json.<kind>-<STARTED in µs><suffix>`, next to the state file.
    fn aside(kind: &str, suffix: &str) -> PathBuf {
        path().with_file_name(format!("state.json.{kind}-{}{suffix}", STARTED * 1_000_000))
    }

    // FR-POL-60 (KNSH-071): pushed policy and grants are written owner-only, and read back as they were.
    #[test]
    fn persists_snapshots_and_grants_owner_only() {
        let fs = fs();
        let (store, state, _) = open(&fs);
        assert_eq!(state, State::default(), "no file yet: empty");
        store.save_snapshots(vec![snapshot("web", at(50))]).unwrap();
        store.save_grants(grants()).unwrap();
        let meta = fs.metadata(&path()).unwrap();
        assert_eq!((meta.kind, meta.mode), (FileKind::File, FILE_MODE));

        let (_, restored, log) = open(&fs);
        assert_eq!(
            restored,
            State {
                snapshots: vec![snapshot("web", at(50))],
                grants: grants(),
            }
        );
        assert_eq!(log.entries().len(), 0);
    }

    // A failed write keeps the previous file and the previous state: the change is refused, nothing half done.
    #[test]
    fn keeps_previous_file_when_a_write_fails() {
        let fs = fs();
        let (store, _, _) = open(&fs);
        store.save_snapshots(vec![snapshot("web", at(50))]).unwrap();
        let before = fs.contents(&path()).unwrap();
        fs.inject_fault(Operation::Rename, 5);
        assert_eq!(store.save_grants(grants()), Err(SaveError::Write));
        assert_eq!(fs.contents(&path()).unwrap(), before);
        assert_eq!(store.saved().grants.len(), 0);
    }

    // Persistence rules (KNSH-074): a corrupt, newer, foreign or oversized file is never overwritten. It is set aside
    // with its bytes intact, the state starts empty, and saves work again, writing a fresh file in its place; the
    // set-aside file is never touched again.
    #[test]
    fn corrupt_state_file_is_not_overwritten() {
        let too_large = vec![b' '; MAX_STATE_LEN + 1];
        for (bytes, mode, kind) in [
            (b"{not json".to_vec(), FILE_MODE, "corrupt"),
            (
                br#"{"version":2,"snapshots":[],"grants":[]}"#.to_vec(),
                FILE_MODE,
                "newer",
            ),
            (
                br#"{"version":0,"snapshots":[],"grants":[]}"#.to_vec(),
                FILE_MODE,
                "corrupt",
            ),
            (
                br#"{"version":1,"snapshots":[],"grants":[],"secrets":[]}"#.to_vec(),
                FILE_MODE,
                "corrupt",
            ),
            (
                br#"{"version":1,"snapshots":[],"grants":[]}"#.to_vec(),
                0o644,
                "corrupt",
            ),
            (too_large, FILE_MODE, "corrupt"),
        ] {
            let fs = fs();
            fs.write(&path(), &bytes, mode).unwrap();
            let (store, state, log) = open(&fs);
            assert_eq!(state, State::default());
            assert_eq!(fs.contents(&aside(kind, "")).unwrap(), bytes, "kept, byte for byte");
            assert_eq!(log.entries().len(), 1, "the recovery is reported");

            store.save_grants(grants()).unwrap();
            assert_eq!(
                fs.contents(&aside(kind, "")).unwrap(),
                bytes,
                "still untouched after a save"
            );
            let (_, restored, _) = open(&fs);
            assert_eq!(restored.grants, grants(), "the fresh file is read at the next start");
        }
    }

    // KNSH-074: a symlink in place of the file is set aside itself; its target is never read, followed or written.
    #[test]
    fn sets_aside_a_symlink_without_touching_its_target() {
        let fs = fs();
        let target = path().with_file_name("elsewhere");
        fs.write(&target, b"theirs", FILE_MODE).unwrap();
        fs.add_symlink(&path(), &target).unwrap();
        let (store, _, _) = open(&fs);
        assert_eq!(fs.metadata(&aside("corrupt", "")).unwrap().kind, FileKind::Symlink);
        store.save_grants(grants()).unwrap();
        assert_eq!(fs.contents(&target).unwrap(), b"theirs");
        assert_eq!(fs.metadata(&path()).unwrap().kind, FileKind::File);
    }

    // KNSH-074: an earlier set-aside file of the same name is never replaced: the next free name is used.
    #[test]
    fn set_aside_never_replaces_an_earlier_one() {
        let fs = fs();
        fs.write(&aside("corrupt", ""), b"earlier", FILE_MODE).unwrap();
        fs.write(&path(), b"{", FILE_MODE).unwrap();
        let _ = open(&fs);
        assert_eq!(fs.contents(&aside("corrupt", "")).unwrap(), b"earlier");
        assert_eq!(fs.contents(&aside("corrupt", ".1")).unwrap(), b"{");
    }

    // Persistence rules: a file that cannot be set aside, or cannot even be examined, stays exactly where and as it
    // is; the store is frozen and refuses every save rather than write over it.
    #[test]
    fn freezes_when_the_file_cannot_be_set_aside_or_examined() {
        for fault in [Operation::Rename, Operation::Metadata] {
            let fs = fs();
            fs.write(&path(), b"{not json", FILE_MODE).unwrap();
            fs.inject_fault(fault, 5);
            let (store, state, log) = open(&fs);
            assert_eq!(state, State::default());
            assert_eq!(store.save_grants(grants()), Err(SaveError::Frozen), "{fault:?}");
            assert_eq!(fs.contents(&path()).unwrap(), b"{not json", "{fault:?}: left as it was");
            assert!(fs.contents(&aside("corrupt", "")).is_none());
            assert_eq!(log.entries().len(), 1);
        }
    }
}
