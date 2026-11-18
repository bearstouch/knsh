//! The shadow registry over fake volumes and an in-memory tree (KNSH-079).

use std::path::Path;
use std::sync::Mutex;

use knsh_checkpoint::testing::FakeTree;
use knsh_core::{ProfileName, SessionId, Ulid};
use knsh_platform::testing::{FakeClock, FakeVolumes, MemFs, RecordingLog, ScriptedFileEvents};
use knsh_platform::{FileEvent, FileEventFlags, FileSystemKind, ensure_engine_dirs};

use super::*;

pub(crate) const HOME: &str = "/Users/u";
pub(crate) const ROOT: &str = "/Users/u/app";

/// Long enough for any build here; a hung build fails the test instead of hanging it.
pub(crate) const SETTLE: Duration = Duration::from_secs(20);

/// Every checkpoint event published, by session.
#[derive(Default)]
pub(crate) struct RecordedEvents {
    pub(crate) changed: Mutex<Vec<(SessionId, PathBuf)>>,
    pub(crate) uncertain: Mutex<Vec<(SessionId, Option<RecordId>, UncertainReason)>>,
}

impl CheckpointEvents for RecordedEvents {
    fn file_changed(&self, session_id: SessionId, _root: &CanonicalPath, path: &CanonicalPath) {
        self.changed
            .lock()
            .unwrap()
            .push((session_id, path.as_path().to_path_buf()));
    }

    fn uncertain(
        &self,
        session_id: SessionId,
        _root: &CanonicalPath,
        record_id: Option<RecordId>,
        reason: UncertainReason,
    ) {
        self.uncertain.lock().unwrap().push((session_id, record_id, reason));
    }
}

/// File events whose flushes deliver the event of every marker file present in a watched marker folder (the second
/// folder of each stream), as the real stream does after the line-end procedure creates one.
pub(crate) fn echoing_events(tree: &Arc<FakeTree>) -> ScriptedFileEvents {
    let events = ScriptedFileEvents::new();
    let tree = Arc::clone(tree);
    events.on_flush(Box::new(move |watched| {
        let Some(markers) = watched.get(1) else {
            return Vec::new();
        };
        tree.paths_below(markers)
            .into_iter()
            .filter(|relative| !relative.as_os_str().is_empty())
            .map(|relative| FileEvent::new(markers.join(relative), FileEventFlags::ITEM_CREATED))
            .collect()
    }));
    events
}

/// A machine whose home is on one APFS volume, with a non-APFS stick, and the engine directories ready. Returns the
/// shadows over `tree`, which already holds the home store and `ROOT` with a few files.
pub(crate) fn shadows(tree: &Arc<FakeTree>) -> Arc<Shadows> {
    shadows_with(tree, echoing_events(tree), Arc::new(RecordedEvents::default()))
}

/// [`shadows`], with the file events and the checkpoint event sink given.
pub(crate) fn shadows_with(
    tree: &Arc<FakeTree>,
    file_events: ScriptedFileEvents,
    events: Arc<dyn CheckpointEvents>,
) -> Arc<Shadows> {
    let fs = MemFs::new();
    for dir in [HOME, ROOT, "/Volumes/Stick/code"] {
        fs.add_dir_all(Path::new(dir)).unwrap();
    }
    let paths = EnginePaths::for_home(Path::new(HOME)).unwrap();
    ensure_engine_dirs(&fs, &paths, fs.uid()).unwrap();
    let volumes = FakeVolumes::new();
    volumes.add_volume("/", FileSystemKind::Apfs, false);
    volumes.add_volume("/Volumes/Stick", FileSystemKind::Other, false);
    tree.add_dir(paths.checkpoints_dir());
    tree.add_file(Path::new(ROOT).join("src/main.rs"), b"fn main() {}");
    tree.add_file(Path::new(ROOT).join("README"), b"hi");
    tree.add_file(Path::new(ROOT).join("node_modules/x/index.js"), b"excluded");
    let uid = fs.uid();
    Shadows::new(ShadowParts {
        fs: Arc::new(fs),
        volumes: Arc::new(volumes),
        files: Arc::clone(tree) as Arc<dyn ShadowFiles>,
        clock: Arc::new(FakeClock::new(
            knsh_core::Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
        )),
        paths,
        uid,
        log: Arc::new(RecordingLog::new()),
        file_events: Arc::new(file_events),
        events,
    })
}

/// A profile protecting `roots`, loaded as the supervisor loads profiles, with `extra` TOML appended.
pub(crate) fn profile_with(roots: &[&str], required: bool, extra: &str) -> Profile {
    let roots = roots
        .iter()
        .map(|root| format!("\"{root}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let text = format!("name = \"ckpt\"\n[checkpoints]\nroots = [{roots}]\nrequired = {required}\n{extra}");
    let fs = MemFs::new();
    for dir in [HOME, ROOT, "/tmp", "/Volumes/Stick/code", "/Users/u/lib"] {
        fs.add_dir_all(Path::new(dir)).unwrap();
    }
    let policies = EnginePaths::for_home(Path::new(HOME)).unwrap().policies_dir();
    fs.add_dir_all(&policies).unwrap();
    fs.write(
        &policies.join("ckpt.toml"),
        &crate::policy::tests::signed("ckpt", &text),
        0o600,
    )
    .unwrap();
    crate::policy::tests::loader(fs)
        .load(&ProfileName::new("ckpt").unwrap(), Path::new(ROOT))
        .unwrap()
}

/// [`profile_with`] and nothing else.
pub(crate) fn profile(roots: &[&str], required: bool) -> Profile {
    profile_with(roots, required, "")
}

fn session(n: u128) -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(n))
}

fn root(path: &str) -> CanonicalPath {
    CanonicalPath::new(path).unwrap()
}

/// Waits until the shadow of `root` for `session_id` has settled, through the sessions it is attached to.
pub(crate) fn settled_in(
    sessions: &crate::sessions::Sessions,
    session_id: SessionId,
    root: &CanonicalPath,
) -> RootReadiness {
    sessions.wait_for_shadow(session_id, root, SETTLE)
}

/// Waits until the shadow of `root` for `session_id` has settled.
pub(crate) fn settled(shadows: &Shadows, session_id: SessionId, root: &CanonicalPath) -> RootReadiness {
    shadows.wait(session_id, root, SETTLE)
}

// FR-CKP-01: starting a session starts one background build per root and returns without waiting for any.
#[test]
fn starting_a_session_starts_one_background_build_per_root() {
    let tree = Arc::new(FakeTree::new());
    tree.add_file("/Users/u/lib/a.rs", b"a");
    let shadows = shadows(&tree);
    tree.hold();
    // Returns while every clone is held: nothing in `start` waits for a build.
    shadows.start(session(1), &profile(&[ROOT, "/Users/u/lib"], true));
    for path in [ROOT, "/Users/u/lib"] {
        assert!(
            matches!(shadows.readiness(session(1), &root(path)), RootReadiness::Building(_)),
            "{path}"
        );
    }
    // Building roots are not in the capability report yet.
    assert!(shadows.capability_report().is_empty());
    tree.release();
    for path in [ROOT, "/Users/u/lib"] {
        assert_eq!(
            settled(&shadows, session(1), &root(path)),
            RootReadiness::Ready,
            "{path}"
        );
    }
    // Each root in its own folder of the home store, without the excluded folder.
    let store = EnginePaths::for_home(Path::new(HOME)).unwrap().checkpoints_dir();
    let shadow = store.join("shadows").join(session(1).to_string());
    assert!(tree.node(shadow.join("0/src/main.rs")).is_some());
    assert!(tree.node(shadow.join("0/node_modules")).is_none());
    assert!(tree.node(shadow.join("1/a.rs")).is_some());
    let report = shadows.capability_report();
    assert_eq!(report.get(ROOT), Some(&CheckpointBackend::ApfsClone));
    assert_eq!(report.get("/Users/u/lib"), Some(&CheckpointBackend::ApfsClone));
}

// A failed build is reported as `none`, and the root is not protected.
#[test]
fn a_failed_build_reports_none() {
    let tree = Arc::new(FakeTree::new());
    let shadows = shadows(&tree);
    tree.fail_clone(Path::new(ROOT).join("README"), 5);
    shadows.start(session(1), &profile(&[ROOT], true));
    assert_eq!(
        settled(&shadows, session(1), &root(ROOT)),
        RootReadiness::Unavailable(UnprotectedReason::ShadowFailed)
    );
    assert_eq!(shadows.capability_report().get(ROOT), Some(&CheckpointBackend::None));
}

// A root on a volume without clones gets no shadow yet: `none`, never a false `plain-copy` claim.
#[test]
fn a_root_without_clones_has_no_shadow_and_reports_none() {
    let tree = Arc::new(FakeTree::new());
    let shadows = shadows(&tree);
    shadows.start(session(1), &profile(&["/Volumes/Stick/code"], false));
    assert_eq!(
        shadows.readiness(session(1), &root("/Volumes/Stick/code")),
        RootReadiness::Unavailable(UnprotectedReason::NoShadow)
    );
    assert_eq!(
        shadows.capability_report().get("/Volumes/Stick/code"),
        Some(&CheckpointBackend::None)
    );
    // A root the session never had, or a session that does not exist, has no shadow either.
    assert_eq!(
        shadows.readiness(session(1), &root("/elsewhere")),
        RootReadiness::Unavailable(UnprotectedReason::NoShadow)
    );
    assert_eq!(
        shadows.readiness(session(9), &root(ROOT)),
        RootReadiness::Unavailable(UnprotectedReason::NoShadow)
    );
}

// Ending a session stops its builds and drops its roots from the report.
#[test]
fn ending_a_session_stops_its_builds() {
    let tree = Arc::new(FakeTree::new());
    let shadows = shadows(&tree);
    tree.hold();
    shadows.start(session(1), &profile(&[ROOT], true));
    let shadow = shadows.shadow_of(session(1), &root(ROOT)).unwrap();
    shadows.end(session(1));
    tree.release();
    assert_eq!(shadow.wait(SETTLE), ShadowStatus::Cancelled);
    assert!(shadows.capability_report().is_empty());
    assert_eq!(
        shadows.readiness(session(1), &root(ROOT)),
        RootReadiness::Unavailable(UnprotectedReason::NoShadow)
    );
}

// Two sessions sharing a root: the report shows the weaker of the two.
#[test]
fn a_shared_root_reports_the_weaker_state() {
    let tree = Arc::new(FakeTree::new());
    let shadows = shadows(&tree);
    shadows.start(session(1), &profile(&[ROOT], true));
    assert_eq!(settled(&shadows, session(1), &root(ROOT)), RootReadiness::Ready);
    tree.fail_clone(Path::new(ROOT).join("README"), 5);
    shadows.start(session(2), &profile(&[ROOT], true));
    let _ = settled(&shadows, session(2), &root(ROOT));
    assert_eq!(shadows.capability_report().get(ROOT), Some(&CheckpointBackend::None));
}

// A session with no roots gets nothing.
#[test]
fn a_session_without_roots_starts_nothing() {
    let tree = Arc::new(FakeTree::new());
    let shadows = shadows(&tree);
    shadows.start(session(1), &profile(&[], true));
    assert!(shadows.table().is_empty());
    assert_eq!(tree.clones(), 0);
}

/// A session over `ROOT` whose shadow is ready, with its file events and checkpoint events recorded.
fn watched_session() -> (Arc<FakeTree>, ScriptedFileEvents, Arc<RecordedEvents>, Arc<Shadows>) {
    let tree = Arc::new(FakeTree::new());
    let file_events = echoing_events(&tree);
    let events = Arc::new(RecordedEvents::default());
    let shadows = shadows_with(
        &tree,
        file_events.clone(),
        Arc::clone(&events) as Arc<dyn CheckpointEvents>,
    );
    shadows.start(session(1), &profile(&[ROOT], true));
    assert_eq!(settled(&shadows, session(1), &root(ROOT)), RootReadiness::Ready);
    (tree, file_events, events, shadows)
}

fn store_dir() -> PathBuf {
    EnginePaths::for_home(Path::new(HOME)).unwrap().checkpoints_dir()
}

// KNSH-080 (FR-EVT-08, FR-CKP-03): each shadowed root gets a stream on itself and its marker folder in the store; a
// change by any process reaches the shadow and is published as `file.changed` on the session.
#[test]
fn a_change_under_a_root_is_published_as_file_changed() {
    let (tree, file_events, events, shadows) = watched_session();
    let markers = store_dir().join("markers").join(session(1).to_string()).join("0");
    assert_eq!(file_events.watched(), [vec![PathBuf::from(ROOT), markers]]);
    let new = Path::new(ROOT).join("new.txt");
    tree.add_file(&new, b"by another process");
    file_events.emit(&[FileEvent::new(&new, FileEventFlags::ITEM_CREATED)]);
    let lines = shadows.open_lines(session(1), &[root(ROOT)]);
    assert_eq!(close_lines(lines), Vec::new());
    assert_eq!(*events.changed.lock().unwrap(), [(session(1), new.clone())]);
    let shadow = store_dir()
        .join("shadows")
        .join(session(1).to_string())
        .join("0/new.txt");
    assert!(tree.node(shadow).is_some());
}

// KNSH-080 (FR-CKP-04): a drop while a line runs makes that line's root uncertain at its end; a drop while no line
// runs is published at once, with no record.
#[test]
fn dropped_events_make_the_line_uncertain() {
    let (_tree, file_events, events, shadows) = watched_session();
    let drop = || {
        file_events.emit(&[FileEvent::new(
            ROOT,
            FileEventFlags::MUST_SCAN_SUB_DIRS.union(FileEventFlags::USER_DROPPED),
        )]);
    };
    let lines = shadows.open_lines(session(1), &[root(ROOT)]);
    drop();
    assert_eq!(close_lines(lines), [(root(ROOT), UncertainReason::EventsDropped)]);
    assert_eq!(*events.uncertain.lock().unwrap(), Vec::new());
    drop();
    let lines = shadows.open_lines(session(1), &[root(ROOT)]);
    assert_eq!(close_lines(lines), Vec::new());
    assert_eq!(
        *events.uncertain.lock().unwrap(),
        [(session(1), None, UncertainReason::EventsDropped)]
    );
}

// KNSH-080: ending the session stops its watchers; roots without a shadow are not opened at all.
#[test]
fn ending_the_session_stops_its_watchers() {
    let (_tree, file_events, _events, shadows) = watched_session();
    assert_eq!(file_events.live_streams(), 1);
    assert!(shadows.open_lines(session(1), &[root("/Users/u/elsewhere")]).is_empty());
    let lines = shadows.open_lines(session(1), &[root(ROOT)]);
    shadows.end(session(1));
    assert_eq!(file_events.live_streams(), 0);
    // A line that was running when its session ended: its root is no longer watched.
    assert_eq!(close_lines(lines), [(root(ROOT), UncertainReason::NotWatched)]);
    assert!(shadows.open_lines(session(1), &[root(ROOT)]).is_empty());
}

// KNSH-080: a watcher that cannot start leaves the shadow built (the gate still lets lines run) but every line in the
// root is uncertain, and the failure is logged.
#[test]
fn a_watcher_that_cannot_start_makes_lines_uncertain() {
    let tree = Arc::new(FakeTree::new());
    let file_events = echoing_events(&tree);
    file_events.fail_next_watch(knsh_platform::testing::watch_failure());
    let shadows = shadows_with(&tree, file_events.clone(), Arc::new(RecordedEvents::default()));
    shadows.start(session(1), &profile(&[ROOT], true));
    assert_eq!(settled(&shadows, session(1), &root(ROOT)), RootReadiness::Ready);
    let lines = shadows.open_lines(session(1), &[root(ROOT)]);
    assert_eq!(close_lines(lines), [(root(ROOT), UncertainReason::NotWatched)]);
    assert_eq!(file_events.live_streams(), 0);
}
