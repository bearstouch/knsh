//! The shadow builder: a copy-on-write clone of each checkpoint root, built file by file in the background when an
//! agent session starts, so that pre-images exist for any later change (FR-CKP-01, NFR-PERF-06, KNSH-079).
//!
//! [`start_shadow`] returns at once with a [`Shadow`] handle; the build runs on its own threads and never blocks
//! session start. How a build proceeds (decision 15, `specs/09-reference/decisions.md`):
//!
//! - **Per-file clones on a pool of [`SHADOW_THREADS`] threads at the utility quality of service.** Each folder of the root becomes a
//!   new folder in the shadow (owner-only), and each regular file is cloned into it ([`ShadowFiles::clone_file`]).
//!   Folders are shared out from one queue, so a wide tree keeps every thread busy.
//! - **Nothing outside the root is ever followed.** Each entry is read with `lstat`: a symlink is cloned as the link
//!   itself (its text, never its target), and a folder is entered only when `lstat` says it is a folder, so a link to
//!   a folder elsewhere (`/etc`, another project) is never walked into.
//!   **Known limit:** the walk goes by path, so a folder replaced by a symlink between its `lstat` and its listing
//!   is followed for that folder (intermediate components are resolved by the kernel). Closing this needs an
//!   `openat`-relative walk with `O_NOFOLLOW` in `knsh-platform`; recorded as pending in KNSH-079.
//! - **Excluded folders are skipped** by name at any depth (`checkpoints.exclude`, default `node_modules`, `target`,
//!   `.venv`, `dist`, `build`; FR-CKP-31). Only folders are excluded: a file called `build` is still cloned.
//! - **Special files** (sockets, FIFOs, devices) cannot be cloned and hold no contents to restore: they are skipped
//!   and listed in the summary ([`ShadowSummary::special`], at most [`MAX_LISTED_SPECIAL`] paths).
//! - **Engine paths are never shadowed.** Folders the caller names in [`ShadowPlan::skip`] (the checkpoint store,
//!   the engine directories) are not entered, so a root that contains its own store (a whole home folder) never
//!   clones the shadow into itself.
//! - **Races with live writers.** An entry removed between listing and cloning is skipped: the watcher (KNSH-080)
//!   keeps the shadow current from then on. Any other error fails the build ([`ShadowStatus::Failed`]): a shadow with
//!   holes would let a change go unprotected while reporting it protected.
//! - **Timing.** Each build records its file count and duration, and marks a build that took longer than
//!   [`SHADOW_BUDGET`] (NFR-PERF-06: under 10 s for 100,000 files) so `knshd` can report it.
//!
//! # Lines that touch a root (FR-CKP-02)
//!
//! [`line_touches_root`] says whether a line can change files in a root, and [`gate`] decides what happens to it from
//! the state of each such root's shadow and the profile's `checkpoints.required`: run, wait, `-32010`, or deny (fail
//! closed). Both are pure functions; `knshd` performs the waiting.
//!
//! # Boundaries
//!
//! Every effect goes through [`ShadowFiles`]: [`PlatformShadowFiles`] over `knsh_platform::Fs` and
//! `knsh_platform::Volumes` in `knshd`, and an in-memory fake in tests. Keeping the shadow current is KNSH-080;
//! removing a shadow when its session ends is not done yet (retention, KNSH-087).

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use knsh_core::{CanonicalPath, UnprotectedReason};
use knsh_platform::engine_dirs::{DIR_MODE, FILE_MODE};
use knsh_platform::{Clock, ContentHash, FileIdentity, FileKind, Fs, Monotonic, PlatformError, Volumes};

/// Threads cloning one root (decision 15): 4 reached 7.4 to 7.7 s for 100,000 files on macOS 26.6; 8 gained nothing.
pub const SHADOW_THREADS: usize = 4;

/// The time an initial shadow should take at most (NFR-PERF-06). A slower build still completes; it is only
/// reported ([`ShadowSummary::over_budget`]).
pub const SHADOW_BUDGET: Duration = Duration::from_secs(10);

/// Special files listed by path in a summary at most; beyond it they are only counted.
pub const MAX_LISTED_SPECIAL: usize = 100;

/// Entries read from one folder at most. A folder with more fails the build rather than leaving a hole in it.
pub const MAX_FOLDER_ENTRIES: usize = 1 << 20;

/// The folder below a store that holds shadows: `<store>/shadows/<session>/<root index>/`.
pub const SHADOWS_DIR: &str = "shadows";

/// The file operations a shadow build needs. Object safe; implemented over the platform traits by
/// [`PlatformShadowFiles`].
///
/// All paths are absolute. Nothing here follows a final symlink.
pub trait ShadowFiles: Send + Sync {
    /// What `path` names, read with `lstat`.
    ///
    /// # Errors
    ///
    /// A [`PlatformError`]; `ENOENT` (see [`PlatformError::is_not_found`]) if nothing is there.
    fn kind(&self, path: &Path) -> Result<FileKind, PlatformError>;

    /// The names in the folder `path`, at most `limit` of them.
    ///
    /// # Errors
    ///
    /// [`PlatformError::TooLarge`] above `limit`; another [`PlatformError`] if the folder cannot be read.
    fn list(&self, path: &Path, limit: usize) -> Result<Vec<OsString>, PlatformError>;

    /// Creates the folder `path`, owner-only. Nothing may exist there yet.
    ///
    /// # Errors
    ///
    /// A [`PlatformError`], `EEXIST` if anything is there already.
    fn make_dir(&self, path: &Path) -> Result<(), PlatformError>;

    /// Clones the file or symlink `src` to the new path `dst`, copy-on-write, without following a final symlink.
    ///
    /// # Errors
    ///
    /// A [`PlatformError`]; nothing is left at `dst`.
    fn clone_file(&self, src: &Path, dst: &Path) -> Result<(), PlatformError>;

    /// The identity of `path` itself, read with `lstat`. The watcher (KNSH-080) compares a live entry with its shadow
    /// copy by kind, size and modification time, which a clone keeps (KNSH-077, claim C3); the inode differs by
    /// design.
    ///
    /// # Errors
    ///
    /// A [`PlatformError`]; `ENOENT` (see [`PlatformError::is_not_found`]) if nothing is there.
    fn identity(&self, path: &Path) -> Result<FileIdentity, PlatformError>;

    /// Removes the file or symlink at `path` (`folder` false), or the empty folder at `path` (`folder` true). A final
    /// symlink is never followed.
    ///
    /// # Errors
    ///
    /// A [`PlatformError`]; `ENOENT` if nothing is there, `ENOTEMPTY` for a folder with entries.
    fn remove(&self, path: &Path, folder: bool) -> Result<(), PlatformError>;

    /// Creates the new, empty, owner-only file `path`: the watcher's line-end marker (decision 16).
    ///
    /// # Errors
    ///
    /// A [`PlatformError`], `EEXIST` if anything is there already.
    fn create_file(&self, path: &Path) -> Result<(), PlatformError>;

    /// Moves the file, symlink or folder `from` to the new path `to` in one step, without following either final
    /// component and never replacing anything at `to` (KNSH-082: a shadow copy becomes a pre-image). Both paths are on
    /// one volume.
    ///
    /// # Errors
    ///
    /// A [`PlatformError`], `EEXIST` if anything is at `to`; nothing has moved then.
    fn rename_new(&self, from: &Path, to: &Path) -> Result<(), PlatformError>;

    /// The SHA-256 of the regular file `path`, or `None` if it is larger than `limit` bytes (a post-image identity
    /// hashes files under 64 MiB only, FR-CKP-09). A final symlink is never followed.
    ///
    /// # Errors
    ///
    /// A [`PlatformError`]; `ENOENT` if nothing is there.
    fn hash(&self, path: &Path, limit: u64) -> Result<Option<ContentHash>, PlatformError>;

    /// Writes the contents of the regular file `src` into the existing regular file `dst` in place, keeping its inode,
    /// hard links and open descriptors, then sets its modification time to now (KNSH-084, FR-CKP-22, FR-CKP-23). With
    /// `expect`, only while `dst` still has that identity ([`Volumes::write_in_place`]).
    ///
    /// # Errors
    ///
    /// A [`PlatformError`]; [`PlatformError::Changed`] if `dst` no longer matches `expect` (nothing written).
    fn write_in_place(&self, src: &Path, dst: &Path, expect: Option<&FileIdentity>) -> Result<(), PlatformError>;

    /// Sets the modification time of `path` itself to now (KNSH-084, FR-CKP-23).
    ///
    /// # Errors
    ///
    /// A [`PlatformError`]; `ENOENT` if nothing is there.
    fn touch(&self, path: &Path) -> Result<(), PlatformError>;

    /// Replaces the owner-only file `path` with `data`, atomically and durably: the restore journal (KNSH-084).
    ///
    /// # Errors
    ///
    /// A [`PlatformError`]; the previous file is untouched on error.
    fn write_file(&self, path: &Path, data: &[u8]) -> Result<(), PlatformError>;

    /// Reads the whole file `path`, refusing one larger than `limit` bytes before allocating.
    ///
    /// # Errors
    ///
    /// A [`PlatformError`]; [`PlatformError::TooLarge`] above `limit`, `ENOENT` if nothing is there.
    fn read_file(&self, path: &Path, limit: u64) -> Result<Vec<u8>, PlatformError>;

    /// Called once on each build thread before it does anything else: the real backend lowers the thread to the
    /// utility class (decision 15). Best effort.
    fn prepare_thread(&self) {}
}

/// [`ShadowFiles`] over the platform's file system and volume services.
pub struct PlatformShadowFiles {
    fs: Arc<dyn Fs>,
    volumes: Arc<dyn Volumes>,
}

impl PlatformShadowFiles {
    /// The operations over `fs` (listing, `lstat`, folders) and `volumes` (clones).
    #[must_use]
    pub fn new(fs: Arc<dyn Fs>, volumes: Arc<dyn Volumes>) -> Self {
        Self { fs, volumes }
    }
}

impl ShadowFiles for PlatformShadowFiles {
    fn kind(&self, path: &Path) -> Result<FileKind, PlatformError> {
        self.fs.metadata(path).map(|meta| meta.kind)
    }

    fn list(&self, path: &Path, limit: usize) -> Result<Vec<OsString>, PlatformError> {
        self.fs.list_dir(path, limit)
    }

    fn make_dir(&self, path: &Path) -> Result<(), PlatformError> {
        self.fs.create_dir(path, DIR_MODE)
    }

    fn clone_file(&self, src: &Path, dst: &Path) -> Result<(), PlatformError> {
        self.volumes.clone_file(src, dst)
    }

    fn identity(&self, path: &Path) -> Result<FileIdentity, PlatformError> {
        self.volumes.identity(path)
    }

    fn remove(&self, path: &Path, folder: bool) -> Result<(), PlatformError> {
        if folder {
            self.fs.remove_dir(path)
        } else {
            self.fs.remove_file(path)
        }
    }

    fn create_file(&self, path: &Path) -> Result<(), PlatformError> {
        self.fs.create_new(path, FILE_MODE)
    }

    fn rename_new(&self, from: &Path, to: &Path) -> Result<(), PlatformError> {
        self.fs.rename_new(from, to)
    }

    fn hash(&self, path: &Path, limit: u64) -> Result<Option<ContentHash>, PlatformError> {
        self.volumes.hash(path, limit)
    }

    fn write_in_place(&self, src: &Path, dst: &Path, expect: Option<&FileIdentity>) -> Result<(), PlatformError> {
        self.volumes.write_in_place(src, dst, expect)
    }

    fn touch(&self, path: &Path) -> Result<(), PlatformError> {
        self.volumes.touch(path)
    }

    fn write_file(&self, path: &Path, data: &[u8]) -> Result<(), PlatformError> {
        self.fs.atomic_replace(path, data, FILE_MODE)
    }

    fn read_file(&self, path: &Path, limit: u64) -> Result<Vec<u8>, PlatformError> {
        self.fs.read(path, limit)
    }

    fn prepare_thread(&self) {
        #[cfg(target_os = "macos")]
        {
            // Best effort: a thread left at its default class is only faster.
            let _ = knsh_platform::macos::set_current_thread_utility_qos();
        }
    }
}

/// What to shadow and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowPlan {
    /// The checkpoint root: a folder.
    pub root: CanonicalPath,
    /// The new folder the shadow is built in, inside the root's store ([`shadow_dir`]). Its parent folders are
    /// created if missing; the folder itself must not exist.
    pub dir: PathBuf,
    /// Folders the build creates `dir` below if they are missing: the store's [`SHADOWS_DIR`] and the session's
    /// folder in it, outermost first. Each must be inside the store, which already exists.
    pub parents: Vec<PathBuf>,
    /// Folder names not shadowed, at any depth (`checkpoints.exclude`, FR-CKP-31).
    pub exclude: Vec<String>,
    /// Folders never entered, by full path: the checkpoint store and the engine directories.
    pub skip: Vec<PathBuf>,
    /// Build threads; [`SHADOW_THREADS`] in `knshd`. At least one is used.
    pub threads: usize,
}

/// Where the shadow of a session's root number `index` lives in `store`: `<store>/shadows/<session>/<index>`.
/// Returns the folder and its parents to create, outermost first ([`ShadowPlan::parents`]).
#[must_use]
pub fn shadow_dir(store: &Path, session: &str, index: usize) -> (PathBuf, Vec<PathBuf>) {
    let shadows = store.join(SHADOWS_DIR);
    let session_dir = shadows.join(session);
    (session_dir.join(index.to_string()), vec![shadows, session_dir])
}

/// How far a build has come. Counts only grow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShadowProgress {
    /// Files and symlinks cloned so far.
    pub files: u64,
    /// Folders fully listed so far.
    pub folders: u64,
    /// Folders found but not listed yet.
    pub folders_pending: u64,
}

/// A finished build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowSummary {
    /// Files and symlinks cloned.
    pub files: u64,
    /// Folders shadowed, the root included.
    pub folders: u64,
    /// Folders skipped because their name is excluded (FR-CKP-31).
    pub excluded_folders: u64,
    /// Special files (sockets, FIFOs, devices) skipped, at most [`MAX_LISTED_SPECIAL`] of them, in the order found.
    pub special: Vec<PathBuf>,
    /// Special files skipped in all, listed or not.
    pub special_count: u64,
    /// From the start of the build to its end, on the monotonic clock.
    pub duration: Duration,
    /// Whether it took longer than [`SHADOW_BUDGET`] (decision 15: reported, not an error).
    pub over_budget: bool,
}

/// Why a build failed. The root is then not protected (`none` in the capability report).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowFailure {
    /// The root is not a folder (or is a symlink to one, which a canonical root never is).
    RootNotAFolder,
    /// The shadow folder already existed: it is never built into, since its contents are unknown.
    ShadowExists,
    /// A build thread could not be started.
    Threads,
    /// A file operation failed.
    Platform(PlatformError),
}

/// The state of one root's shadow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShadowStatus {
    /// Still being built.
    Building(ShadowProgress),
    /// Built: every file of the root not excluded has its clone.
    Complete(ShadowSummary),
    /// The build failed; the root is not protected.
    Failed(ShadowFailure),
    /// The build was stopped ([`Shadow::cancel`]) before it completed, because its session ended.
    Cancelled,
}

/// How a build ended, as its threads report it.
enum Ending {
    Complete,
    Failed(ShadowFailure),
    Cancelled,
}

/// Counters shared by a build's threads.
#[derive(Default)]
struct Counters {
    files: AtomicU64,
    folders: AtomicU64,
    excluded: AtomicU64,
    special_count: AtomicU64,
}

/// One root's shadow and its build. Shared between the build threads and everyone who asks about it.
pub struct Shadow {
    root: CanonicalPath,
    dir: PathBuf,
    /// The final state, once the build ended; `None` while building.
    ended: Mutex<Option<ShadowStatus>>,
    /// Signalled when `ended` is set.
    settled: Condvar,
    /// Set to stop the build: on cancellation, and by a thread that hit an error.
    stop: AtomicBool,
    counters: Counters,
    /// Folders waiting to be listed, and how many threads are listing one now.
    queue: Mutex<Queue>,
    /// Signalled when a folder is queued, or the last busy thread finds the queue empty.
    work: Condvar,
    /// Special files found, bounded.
    special: Mutex<Vec<PathBuf>>,
    /// The first error hit; later ones are dropped.
    failure: Mutex<Option<ShadowFailure>>,
}

/// Folders to list, as paths relative to the root ("" is the root).
#[derive(Default)]
struct Queue {
    folders: VecDeque<PathBuf>,
    busy: usize,
}

/// Takes a lock even if another thread panicked while holding it: every critical section here leaves its data
/// consistent at each step.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shadow {
    /// The root this shadow is of.
    #[must_use]
    pub fn root(&self) -> &CanonicalPath {
        &self.root
    }

    /// The folder the shadow is built in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The state now.
    #[must_use]
    pub fn status(&self) -> ShadowStatus {
        self.state(lock(&self.ended).as_ref())
    }

    /// Waits at most `timeout` for the build to end, and returns the state then. Returns at once if it has ended.
    #[must_use]
    pub fn wait(&self, timeout: Duration) -> ShadowStatus {
        let ended = lock(&self.ended);
        let (ended, _) = self
            .settled
            .wait_timeout_while(ended, timeout, |ended| ended.is_none())
            .unwrap_or_else(PoisonError::into_inner);
        self.state(ended.as_ref())
    }

    /// Stops the build: its threads finish the entry in hand and exit, and the state becomes
    /// [`ShadowStatus::Cancelled`]. Does nothing to a build that has ended.
    pub fn cancel(&self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wakes idle threads so they see the flag; taking the lock orders this after any wait in progress.
        let _queue = lock(&self.queue);
        self.work.notify_all();
    }

    /// The final state in `ended`, or the progress so far while it is unset.
    fn state(&self, ended: Option<&ShadowStatus>) -> ShadowStatus {
        match ended {
            Some(ended) => ended.clone(),
            None => ShadowStatus::Building(self.progress()),
        }
    }

    fn progress(&self) -> ShadowProgress {
        ShadowProgress {
            files: self.counters.files.load(Ordering::Relaxed),
            folders: self.counters.folders.load(Ordering::Relaxed),
            folders_pending: lock(&self.queue).folders.len() as u64,
        }
    }

    /// Records the build's end and wakes every waiter. The first end wins.
    fn end(&self, status: ShadowStatus) {
        let mut ended = lock(&self.ended);
        if ended.is_none() {
            *ended = Some(status);
        }
        self.settled.notify_all();
    }

    /// Keeps the first error and stops the build.
    fn fail(&self, failure: ShadowFailure) {
        lock(&self.failure).get_or_insert(failure);
        self.cancel();
    }
}

/// Starts building the shadow `plan` describes on its own threads, and returns its handle at once (FR-CKP-01: session
/// start never waits for it). `clock` times the build.
#[must_use]
pub fn start_shadow(files: Arc<dyn ShadowFiles>, clock: Arc<dyn Clock>, plan: ShadowPlan) -> Arc<Shadow> {
    let shadow = Arc::new(Shadow {
        root: plan.root.clone(),
        dir: plan.dir.clone(),
        ended: Mutex::new(None),
        settled: Condvar::new(),
        stop: AtomicBool::new(false),
        counters: Counters::default(),
        queue: Mutex::new(Queue::default()),
        work: Condvar::new(),
        special: Mutex::new(Vec::new()),
        failure: Mutex::new(None),
    });
    let lead = {
        let shadow = Arc::clone(&shadow);
        move || lead(&shadow, files.as_ref(), clock.as_ref(), &plan)
    };
    if thread::Builder::new().name("knsh-shadow".into()).spawn(lead).is_err() {
        shadow.end(ShadowStatus::Failed(ShadowFailure::Threads));
    }
    shadow
}

/// The lead thread: prepares the shadow folder, runs the helpers and itself as workers, and records the end.
fn lead(shadow: &Arc<Shadow>, files: &dyn ShadowFiles, clock: &dyn Clock, plan: &ShadowPlan) {
    files.prepare_thread();
    let started = clock.monotonic();
    let ending = match prepare(files, plan) {
        Ok(()) => run_workers(shadow, files, plan),
        Err(failure) => Ending::Failed(failure),
    };
    let status = match ending {
        Ending::Complete => ShadowStatus::Complete(summary(shadow, clock, started)),
        Ending::Failed(failure) => ShadowStatus::Failed(failure),
        Ending::Cancelled => ShadowStatus::Cancelled,
    };
    shadow.end(status);
}

/// Checks the root is a folder and creates the empty shadow folder, with its parents if missing.
fn prepare(files: &dyn ShadowFiles, plan: &ShadowPlan) -> Result<(), ShadowFailure> {
    match files.kind(plan.root.as_path()) {
        Ok(FileKind::Directory) => {}
        Ok(FileKind::File | FileKind::Symlink | FileKind::Other) => return Err(ShadowFailure::RootNotAFolder),
        Err(error) => return Err(ShadowFailure::Platform(error)),
    }
    for parent in &plan.parents {
        match files.make_dir(parent) {
            Ok(()) => {}
            // Made by an earlier root of the same session, or an earlier session: fine only if it is a real folder,
            // never a symlink that would carry the shadow elsewhere.
            Err(error) if is_exists(&error) => match files.kind(parent) {
                Ok(FileKind::Directory) => {}
                Ok(FileKind::File | FileKind::Symlink | FileKind::Other) => {
                    return Err(ShadowFailure::Platform(PlatformError::UnexpectedKind));
                }
                Err(error) => return Err(ShadowFailure::Platform(error)),
            },
            Err(error) => return Err(ShadowFailure::Platform(error)),
        }
    }
    files.make_dir(&plan.dir).map_err(|error| {
        if is_exists(&error) {
            ShadowFailure::ShadowExists
        } else {
            ShadowFailure::Platform(error)
        }
    })
}

/// Runs `plan.threads` workers (this thread and the helpers) until the queue is drained, an error stops them, or the
/// build is cancelled.
fn run_workers(shadow: &Arc<Shadow>, files: &dyn ShadowFiles, plan: &ShadowPlan) -> Ending {
    lock(&shadow.queue).folders.push_back(PathBuf::new());
    let helpers = plan.threads.max(1) - 1;
    let spawned = thread::scope(|scope| {
        let mut spawned = true;
        for _ in 0..helpers {
            let started = thread::Builder::new()
                .name("knsh-shadow".into())
                .spawn_scoped(scope, || {
                    files.prepare_thread();
                    work(shadow, files, plan);
                });
            if started.is_err() {
                // Fewer threads only slow the build, but a pool that cannot start is reported, not hidden.
                spawned = false;
                shadow.fail(ShadowFailure::Threads);
                break;
            }
        }
        work(shadow, files, plan);
        spawned
    });
    if let Some(failure) = *lock(&shadow.failure) {
        return Ending::Failed(failure);
    }
    if !spawned {
        return Ending::Failed(ShadowFailure::Threads);
    }
    if shadow.stop.load(Ordering::SeqCst) {
        return Ending::Cancelled;
    }
    Ending::Complete
}

/// One worker: takes folders off the queue and shadows them until there is no work left anywhere or the build stops.
fn work(shadow: &Shadow, files: &dyn ShadowFiles, plan: &ShadowPlan) {
    loop {
        let folder = {
            let mut queue = lock(&shadow.queue);
            loop {
                if shadow.stop.load(Ordering::SeqCst) {
                    return;
                }
                if let Some(folder) = queue.folders.pop_front() {
                    queue.busy += 1;
                    break folder;
                }
                // Nothing queued and nobody listing a folder that could queue more: the build is done.
                if queue.busy == 0 {
                    shadow.work.notify_all();
                    return;
                }
                queue = shadow.work.wait(queue).unwrap_or_else(PoisonError::into_inner);
            }
        };
        let result = shadow_folder(shadow, files, plan, &folder);
        let mut queue = lock(&shadow.queue);
        queue.busy -= 1;
        if let Err(failure) = result {
            drop(queue);
            shadow.fail(failure);
            return;
        }
        if queue.busy == 0 && queue.folders.is_empty() {
            shadow.work.notify_all();
        }
    }
}

/// Shadows the entries of one folder (`relative` to the root): clones its files and symlinks, creates and queues its
/// sub-folders, skips excluded folders and special files.
fn shadow_folder(
    shadow: &Shadow,
    files: &dyn ShadowFiles,
    plan: &ShadowPlan,
    relative: &Path,
) -> Result<(), ShadowFailure> {
    let source = plan.root.as_path().join(relative);
    let names = match files.list(&source, MAX_FOLDER_ENTRIES) {
        Ok(names) => names,
        // The folder was removed after it was queued (not the root, whose kind was just read): the watcher catches up.
        Err(error) if error.is_not_found() && !relative.as_os_str().is_empty() => Vec::new(),
        Err(error) => return Err(ShadowFailure::Platform(error)),
    };
    for name in names {
        if shadow.stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        // `list` never returns these, but a name that would leave the folder is never joined.
        if name == "." || name == ".." || name.is_empty() {
            continue;
        }
        let entry = relative.join(&name);
        let src = plan.root.as_path().join(&entry);
        let dst = plan.dir.join(&entry);
        let kind = match files.kind(&src) {
            Ok(kind) => kind,
            Err(error) if error.is_not_found() => continue,
            Err(error) => return Err(ShadowFailure::Platform(error)),
        };
        match kind {
            FileKind::Directory => {
                let excluded = name
                    .to_str()
                    .is_some_and(|name| plan.exclude.iter().any(|ex| ex == name));
                if excluded {
                    shadow.counters.excluded.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                // The store and the engine folders: never shadowed, so a root holding its own store never recurses.
                if plan.skip.iter().any(|skip| skip == &src) || src == plan.dir {
                    continue;
                }
                files.make_dir(&dst).map_err(ShadowFailure::Platform)?;
                let mut queue = lock(&shadow.queue);
                queue.folders.push_back(entry);
                shadow.work.notify_one();
            }
            // A symlink is cloned as the link itself: its target, inside the root or not, is never read or entered.
            FileKind::File | FileKind::Symlink => match files.clone_file(&src, &dst) {
                Ok(()) => {
                    shadow.counters.files.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) if error.is_not_found() => {}
                Err(error) => return Err(ShadowFailure::Platform(error)),
            },
            FileKind::Other => {
                shadow.counters.special_count.fetch_add(1, Ordering::Relaxed);
                let mut special = lock(&shadow.special);
                if special.len() < MAX_LISTED_SPECIAL {
                    special.push(src);
                }
            }
        }
    }
    shadow.counters.folders.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// The summary of a completed build.
fn summary(shadow: &Shadow, clock: &dyn Clock, started: Monotonic) -> ShadowSummary {
    let duration = clock.monotonic().saturating_duration_since(started);
    ShadowSummary {
        files: shadow.counters.files.load(Ordering::SeqCst),
        folders: shadow.counters.folders.load(Ordering::SeqCst),
        excluded_folders: shadow.counters.excluded.load(Ordering::SeqCst),
        special: lock(&shadow.special).clone(),
        special_count: shadow.counters.special_count.load(Ordering::SeqCst),
        duration,
        over_budget: duration > SHADOW_BUDGET,
    }
}

/// `EEXIST` from any operation.
fn is_exists(error: &PlatformError) -> bool {
    // `libc` is reserved to `knsh-platform` (NFR-SUP-02); `EEXIST` is 17 on every system this builds for.
    const EEXIST: i32 = 17;
    matches!(error, PlatformError::Os { errno: EEXIST, .. })
}

/// Whether a line can change files in `root`: its working folder is in the root, or the profile lets lines write
/// somewhere in it (an `fs.write` path inside the root, or one that contains it). Lines run in a sandbox whose writes
/// are limited to `fs.write` (FR-SBX-01), so a line meeting neither condition cannot touch the root. Deliberately
/// broad, since a line that touches a root unprotected is the failure this guards against (FR-CKP-02).
#[must_use]
pub fn line_touches_root(root: &CanonicalPath, cwd: &CanonicalPath, write: &[CanonicalPath]) -> bool {
    let root = root.as_path();
    cwd.as_path().starts_with(root)
        || write
            .iter()
            .any(|path| path.as_path().starts_with(root) || root.starts_with(path.as_path()))
}

/// A root a line touches, and how far its shadow is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootReadiness {
    /// The shadow is complete.
    Ready,
    /// The shadow is still being built.
    Building(ShadowProgress),
    /// There is no usable shadow, and there will not be one.
    Unavailable(UnprotectedReason),
}

impl RootReadiness {
    /// The readiness a shadow in `status` gives its root.
    #[must_use]
    pub fn of(status: &ShadowStatus) -> Self {
        match status {
            ShadowStatus::Complete(_) => Self::Ready,
            ShadowStatus::Building(progress) => Self::Building(*progress),
            ShadowStatus::Failed(_) | ShadowStatus::Cancelled => Self::Unavailable(UnprotectedReason::ShadowFailed),
        }
    }
}

/// What happens to a line touching checkpoint roots (FR-CKP-02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// Run it. Changes in the roots listed are not protected, and its record says so (`required = false`).
    Run {
        /// Each root whose changes are not protected, and why.
        unprotected: Vec<(CanonicalPath, UnprotectedReason)>,
    },
    /// Wait for the shadow of `root`, then ask again.
    Wait {
        /// The first root still being built.
        root: CanonicalPath,
    },
    /// The caller does not wait: answer `-32010` with `root` and `progress`.
    NotReady {
        /// The first root still being built.
        root: CanonicalPath,
        /// How far its build is.
        progress: ShadowProgress,
    },
    /// Refuse it: `root` will never be protected and the profile requires checkpoints (fail closed).
    Deny {
        /// The first root without a shadow.
        root: CanonicalPath,
        /// Why it has none.
        reason: UnprotectedReason,
    },
}

/// Decides a line touching `roots` (each with its shadow's readiness) under `checkpoints.required = required`;
/// `wait` is whether the caller waits for a shadow (FR-CKP-02):
///
/// - Not required: the line runs at once, and every root not ready is listed as not protected.
/// - Required: a root that will never have a shadow denies the line (fail closed, checked first so nobody waits for
///   a refusal); else a root still building makes the caller wait, or `-32010` if it does not wait; else it runs.
#[must_use]
pub fn gate(required: bool, wait: bool, roots: &[(CanonicalPath, RootReadiness)]) -> Gate {
    if !required {
        let unprotected = roots
            .iter()
            .filter_map(|(root, readiness)| match readiness {
                RootReadiness::Ready => None,
                RootReadiness::Building(_) => Some((root.clone(), UnprotectedReason::ShadowBuilding)),
                RootReadiness::Unavailable(reason) => Some((root.clone(), *reason)),
            })
            .collect();
        return Gate::Run { unprotected };
    }
    if let Some((root, reason)) = roots.iter().find_map(|(root, readiness)| match readiness {
        RootReadiness::Unavailable(reason) => Some((root, *reason)),
        RootReadiness::Ready | RootReadiness::Building(_) => None,
    }) {
        return Gate::Deny {
            root: root.clone(),
            reason,
        };
    }
    if let Some((root, progress)) = roots.iter().find_map(|(root, readiness)| match readiness {
        RootReadiness::Building(progress) => Some((root, *progress)),
        RootReadiness::Ready | RootReadiness::Unavailable(_) => None,
    }) {
        return if wait {
            Gate::Wait { root: root.clone() }
        } else {
            Gate::NotReady {
                root: root.clone(),
                progress,
            }
        };
    }
    Gate::Run {
        unprotected: Vec::new(),
    }
}

#[cfg(test)]
mod tests;
