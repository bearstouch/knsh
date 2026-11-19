//! File-event watcher (KNSH-080) over an in-memory tree and scripted file events.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use knsh_core::Timestamp;
use knsh_platform::FileEventFlags as F;
use knsh_platform::testing::FlushHook;
use knsh_platform::testing::{FakeClock, ScriptedFileEvents};

use super::*;
use crate::shadow::{SHADOW_THREADS, ShadowPlan, shadow_dir, start_shadow};
use crate::testing::{FakeNode, FakeTree};

const ROOT: &str = "/code/app";
const STORE: &str = "/store";

/// Long enough for anything here; a hang fails the test instead.
const SETTLE: Duration = Duration::from_secs(20);

fn canonical(path: &str) -> CanonicalPath {
    CanonicalPath::new(path).unwrap()
}

fn live(relative: &str) -> PathBuf {
    Path::new(ROOT).join(relative)
}

fn shadow() -> PathBuf {
    shadow_dir(Path::new(STORE), "S1", 0).0
}

fn copy(relative: &str) -> PathBuf {
    shadow().join(relative)
}

fn markers() -> PathBuf {
    marker_dir(Path::new(STORE), "S1", 0).0
}

fn exclude() -> Vec<String> {
    ["node_modules", "target"].into_iter().map(String::from).collect()
}

/// What the watcher reported.
#[derive(Default)]
struct Reports {
    changed: Mutex<Vec<PathBuf>>,
    uncertain: Mutex<Vec<UncertainReason>>,
    excluded: Mutex<Vec<PathBuf>>,
}

impl WatchReport for Reports {
    fn changed(&self, root: &CanonicalPath, change: Change) {
        assert_eq!(root.as_path(), Path::new(ROOT));
        lock(&self.changed).push(change.path.as_path().to_path_buf());
    }

    fn uncertain(&self, root: &CanonicalPath, reason: UncertainReason) {
        assert_eq!(root.as_path(), Path::new(ROOT));
        lock(&self.uncertain).push(reason);
    }

    fn excluded(&self, root: &CanonicalPath, folder: CanonicalPath) {
        assert_eq!(root.as_path(), Path::new(ROOT));
        lock(&self.excluded).push(folder.into_path_buf());
    }
}

impl Reports {
    fn changed(&self) -> Vec<PathBuf> {
        lock(&self.changed).clone()
    }

    fn uncertain(&self) -> Vec<UncertainReason> {
        lock(&self.uncertain).clone()
    }

    fn excluded(&self) -> Vec<PathBuf> {
        lock(&self.excluded).clone()
    }
}

/// A root with a few files, its store, scripted events whose flushes deliver every marker file present (as the real
/// stream would), and a watcher over it whose shadow is built.
struct Setup {
    tree: Arc<FakeTree>,
    events: ScriptedFileEvents,
    clock: Arc<FakeClock>,
    reports: Arc<Reports>,
    watcher: Arc<Watcher>,
}

fn tree() -> Arc<FakeTree> {
    let tree = Arc::new(FakeTree::new());
    tree.add_dir(STORE);
    tree.add_file(live("README"), b"hello");
    tree.add_file(live("src/main.rs"), b"fn main() {}");
    tree.add_file(live("src/lib.rs"), b"pub fn f() {}");
    tree.add_file(live("docs/guide.md"), b"# guide");
    tree.add_file(live("node_modules/x/index.js"), b"excluded");
    tree
}

fn plan() -> WatchPlan {
    let (markers, marker_parents) = marker_dir(Path::new(STORE), "S1", 0);
    let (held, held_parents) = held_dir(Path::new(STORE), "S1", 0);
    WatchPlan {
        root: canonical(ROOT),
        shadow: shadow(),
        markers,
        marker_parents,
        held,
        held_parents,
        exclude: exclude(),
        skip: vec![PathBuf::from(STORE)],
        latency: STREAM_LATENCY,
        flush_deadline: FLUSH_DEADLINE,
    }
}

/// A flush that delivers the events of the marker files present, like the real stream after their creation.
fn echo_markers(tree: &Arc<FakeTree>) -> FlushHook {
    let tree = Arc::clone(tree);
    Box::new(move |_| {
        tree.paths_below(markers())
            .into_iter()
            .filter(|relative| !relative.as_os_str().is_empty())
            .map(|relative| FileEvent::new(markers().join(relative), F::ITEM_CREATED.union(F::ITEM_IS_FILE)))
            .collect()
    })
}

/// Starts the watcher, without saying what the shadow is.
fn watching(tree: &Arc<FakeTree>) -> Setup {
    let events = ScriptedFileEvents::new();
    events.on_flush(echo_markers(tree));
    let clock = Arc::new(FakeClock::new(
        Timestamp::from_unix_micros(1_700_000_000_000_000).unwrap(),
    ));
    let reports = Arc::new(Reports::default());
    let watcher = start_watch(
        &events,
        Arc::clone(tree) as Arc<dyn ShadowFiles>,
        Arc::clone(&clock) as Arc<dyn Clock>,
        Arc::clone(&reports) as Arc<dyn WatchReport>,
        plan(),
    )
    .unwrap();
    Setup {
        tree: Arc::clone(tree),
        events,
        clock,
        reports,
        watcher,
    }
}

/// Builds the shadow of `tree`'s root.
fn build(tree: &Arc<FakeTree>, clock: &Arc<FakeClock>) -> Arc<Shadow> {
    let (dir, parents) = shadow_dir(Path::new(STORE), "S1", 0);
    let plan = ShadowPlan {
        root: canonical(ROOT),
        dir,
        parents,
        exclude: exclude(),
        skip: vec![PathBuf::from(STORE)],
        threads: SHADOW_THREADS,
    };
    start_shadow(
        Arc::clone(tree) as Arc<dyn ShadowFiles>,
        Arc::clone(clock) as Arc<dyn Clock>,
        plan,
    )
}

/// A watcher following a complete shadow.
fn ready() -> Setup {
    let setup = watching(&tree());
    let shadow = build(&setup.tree, &setup.clock);
    assert!(matches!(shadow.wait(SETTLE), ShadowStatus::Complete(_)));
    setup.watcher.follow(shadow);
    setup
}

impl Setup {
    /// Emits one event, as the stream would deliver it.
    fn emit(&self, path: impl Into<PathBuf>, flags: F) {
        self.events.emit(&[FileEvent::new(path, flags)]);
    }

    /// Closes an empty line: once it returns, everything emitted before is applied.
    fn settle(&self) -> LineClose {
        let mark = self.watcher.open_line();
        self.watcher.close_line(mark)
    }

    /// The root's entries, excluded folders left out, as the shadow should hold them.
    fn live_tree(&self) -> BTreeMap<PathBuf, FakeNode> {
        self.tree
            .snapshot(ROOT)
            .into_iter()
            .filter(|(path, _)| !path.starts_with("node_modules"))
            .collect()
    }

    fn shadow_tree(&self) -> BTreeMap<PathBuf, FakeNode> {
        self.tree.snapshot(shadow())
    }

    fn pending(&self) -> usize {
        lock(&self.watcher.inner.state).pending.len()
    }
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "compared with `FakeTree::node`, which returns an `Option`"
)]
fn file(contents: &[u8]) -> Option<FakeNode> {
    Some(FakeNode::File(contents.to_vec()))
}

// FR-EVT-08, FR-CKP-03: a change by a process that is not an agent (here the test, writing the tree directly) is
// applied to the shadow and reported as `file.changed`: a new file, a modified one and a removed one.
#[test]
fn event_from_unrelated_process_emits_file_changed() {
    let setup = ready();
    setup.tree.add_file(live("new.txt"), b"new");
    setup.tree.add_file(live("README"), b"hello, world");
    setup.tree.remove_all(live("src/lib.rs"));
    setup.emit(live("new.txt"), F::ITEM_CREATED.union(F::ITEM_IS_FILE));
    setup.emit(live("README"), F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
    setup.emit(live("src/lib.rs"), F::ITEM_REMOVED.union(F::ITEM_IS_FILE));
    assert_eq!(setup.settle(), LineClose::Certain);

    assert_eq!(setup.tree.node(copy("new.txt")), file(b"new"));
    assert_eq!(setup.tree.node(copy("README")), file(b"hello, world"));
    assert_eq!(setup.tree.node(copy("src/lib.rs")), None);
    let mut changed = setup.reports.changed();
    changed.sort();
    assert_eq!(changed, [live("README"), live("new.txt"), live("src/lib.rs")]);
    assert_eq!(setup.live_tree(), setup.shadow_tree());
    assert_eq!(setup.reports.uncertain(), Vec::<UncertainReason>::new());
}

// Decision 16: flags are hints. An event for a path that did not change (the system's provenance attribute, a repeated
// flag) changes nothing and reports nothing.
#[test]
fn event_for_an_unchanged_path_reports_nothing() {
    let setup = ready();
    let clones = setup.tree.clones();
    setup.emit(
        live("README"),
        F::ITEM_CREATED.union(F::ITEM_XATTR_MOD).union(F::ITEM_IS_FILE),
    );
    setup.emit(live("never-existed"), F::ITEM_CREATED.union(F::ITEM_REMOVED));
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.reports.changed(), Vec::<PathBuf>::new());
    assert_eq!(setup.tree.clones(), clones);
}

// FR-CKP-04, decision 16: a drop flag on the root rescans it, so changes whose events were lost reach the shadow; with
// no line open, the window is reported uncertain at once.
#[test]
fn dropped_event_flag_triggers_rescan_of_folder() {
    let setup = ready();
    // Changes whose events never arrive.
    setup.tree.add_file(live("lost/new.txt"), b"lost");
    setup.tree.add_file(live("src/main.rs"), b"fn main() { changed() }");
    setup.tree.remove_all(live("docs"));
    setup.emit(ROOT, F::MUST_SCAN_SUB_DIRS.union(F::USER_DROPPED));
    assert_eq!(setup.settle(), LineClose::Certain);

    assert_eq!(setup.live_tree(), setup.shadow_tree());
    assert_eq!(setup.tree.node(copy("lost/new.txt")), file(b"lost"));
    assert_eq!(setup.reports.uncertain(), [UncertainReason::EventsDropped]);
    // Excluded folders stay out, even on a full rescan (FR-CKP-31).
    assert_eq!(setup.tree.node(copy("node_modules")), None);
}

// FR-CKP-04: a drop naming a folder below the root rescans that folder only.
#[test]
fn dropped_event_on_a_folder_rescans_only_that_folder() {
    let setup = ready();
    setup.tree.add_file(live("src/new.rs"), b"new");
    setup.tree.add_file(live("docs/new.md"), b"not rescanned");
    setup.emit(live("src"), F::MUST_SCAN_SUB_DIRS);
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.tree.node(copy("src/new.rs")), file(b"new"));
    assert_eq!(setup.tree.node(copy("docs/new.md")), None);
    assert_eq!(setup.reports.uncertain(), [UncertainReason::EventsDropped]);
}

// FR-CKP-04: a drop between a line's start and its end makes that line's checkpoints uncertain, reported by the line
// (not as a window outside lines); the next line, without a drop, is certain again.
#[test]
fn checkpoint_in_dropped_window_is_marked_uncertain() {
    let setup = ready();
    let mark = setup.watcher.open_line();
    setup.tree.add_file(live("during.txt"), b"x");
    setup.emit(ROOT, F::MUST_SCAN_SUB_DIRS.union(F::USER_DROPPED));
    assert_eq!(
        setup.watcher.close_line(mark),
        LineClose::Uncertain(UncertainReason::EventsDropped)
    );
    // The rescan still brought the shadow in step.
    assert_eq!(setup.tree.node(copy("during.txt")), file(b"x"));
    assert!(
        setup.reports.uncertain().is_empty(),
        "the line reports it, with its record"
    );

    // A drop before the next line starts does not make it uncertain.
    let mark = setup.watcher.open_line();
    setup.tree.add_file(live("after.txt"), b"y");
    setup.emit(live("after.txt"), F::ITEM_CREATED);
    assert_eq!(setup.watcher.close_line(mark), LineClose::Certain);
}

// Decision 16: a line whose marker never arrives is uncertain (`flush_timed_out`) after the deadline on the injected
// clock, flushing every millisecond meanwhile, and the root is rescanned.
#[test]
fn line_whose_marker_never_arrives_is_uncertain_after_the_deadline() {
    let setup = ready();
    setup.events.on_flush(Box::new(|_| Vec::new()));
    let start = setup.clock.monotonic();
    let mark = setup.watcher.open_line();
    setup.tree.add_file(live("unseen.txt"), b"z");
    assert_eq!(
        setup.watcher.close_line(mark),
        LineClose::Uncertain(UncertainReason::FlushTimedOut)
    );
    let waited = setup.clock.monotonic().saturating_duration_since(start);
    assert!(
        waited >= FLUSH_DEADLINE && waited < FLUSH_DEADLINE + Duration::from_millis(10),
        "{waited:?}"
    );
    assert!(
        setup.events.flushes() >= 999,
        "flushed every millisecond: {}",
        setup.events.flushes()
    );
    // The marker is removed again.
    assert!(
        setup
            .tree
            .paths_below(markers())
            .iter()
            .all(|path| path.as_os_str().is_empty())
    );
    // The rescan it forced finds the change whose event never came.
    setup.events.on_flush(echo_markers(&setup.tree));
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.tree.node(copy("unseen.txt")), file(b"z"));
}

// NFR-REL-04: a watcher taking over a shadow an earlier `knshd` left rescans the whole root against it and reports the
// gap as uncertain.
#[test]
fn restart_rescans_roots_and_marks_gap() {
    let tree = tree();
    // The shadow as the earlier run left it: one file since changed, one since removed, one cloned and unchanged,
    // and some never seen.
    tree.add_file(copy("README"), b"old");
    tree.add_file(copy("gone.txt"), b"removed while knshd was away");
    tree.add_dir(copy("src"));
    tree.clone_file(&live("src/main.rs"), &copy("src/main.rs")).unwrap();
    let setup = watching(&tree);
    setup.watcher.resume();
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.live_tree(), setup.shadow_tree());
    assert_eq!(setup.reports.uncertain(), [UncertainReason::RestartGap]);
    let changed = setup.reports.changed();
    for path in ["README", "gone.txt", "src/lib.rs", "docs/guide.md"] {
        assert!(changed.contains(&live(path)), "{path} in {changed:?}");
    }
    assert!(!changed.contains(&live("src/main.rs")), "unchanged since the gap");
}

// Bounded memory: many events for one path are one entry; more distinct paths than the bound collapse into a rescan
// of the root, which still brings every path in step and is reported as `too_many_events`.
#[test]
fn burst_of_events_is_coalesced_within_memory_bound() {
    let setup = watching(&tree());
    for _ in 0..1000 {
        setup.emit(live("README"), F::ITEM_MODIFIED);
    }
    assert_eq!(setup.pending(), 1);
    let burst: Vec<FileEvent> = (0..MAX_PENDING_PATHS + 100)
        .map(|n| FileEvent::new(live(&format!("burst/{n}")), F::ITEM_CREATED))
        .collect();
    for chunk in burst.chunks(512) {
        setup.events.emit(chunk);
        assert!(setup.pending() <= MAX_PENDING_PATHS);
    }
    assert_eq!(setup.pending(), 0, "collapsed into one rescan");
    assert!(lock(&setup.watcher.inner.state).rescan_root);

    // Before the shadow is complete, an overflow only completes the build; once it is, the same burst is reported.
    for n in 0..20 {
        setup.tree.add_file(live(&format!("burst/{n}")), b"b");
    }
    let shadow = build(&setup.tree, &setup.clock);
    assert!(matches!(shadow.wait(SETTLE), ShadowStatus::Complete(_)));
    setup.watcher.follow(shadow);
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.live_tree(), setup.shadow_tree());
    assert_eq!(setup.reports.uncertain(), Vec::<UncertainReason>::new());

    setup.events.emit(&burst);
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.reports.uncertain(), [UncertainReason::TooManyEvents]);
}

// FR-CKP-03: changes made while the shadow is still being built are kept, then applied once it is complete.
#[test]
fn changes_during_the_build_are_applied_once_it_completes() {
    let tree = tree();
    let setup = watching(&tree);
    tree.hold();
    let shadow = build(&tree, &setup.clock);
    setup.watcher.follow(Arc::clone(&shadow));
    // Not ready yet: a line closing now has nothing to settle against (its record says unprotected).
    assert_eq!(setup.settle(), LineClose::Certain);
    tree.add_file(live("while-building.txt"), b"w");
    setup.emit(live("while-building.txt"), F::ITEM_CREATED);
    tree.release();
    assert!(matches!(shadow.wait(SETTLE), ShadowStatus::Complete(_)));
    // The first close after completion may run before the worker noticed; the shadow catches up within a few.
    let deadline = std::time::Instant::now() + SETTLE;
    while setup.tree.node(copy("while-building.txt")).is_none() && std::time::Instant::now() < deadline {
        let _ = setup.settle();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(setup.tree.node(copy("while-building.txt")), file(b"w"));
    assert_eq!(setup.live_tree(), setup.shadow_tree());
}

// A shadow that failed cannot be kept in step: the watcher stops, and a line in that root is uncertain.
#[test]
fn a_failed_build_stops_the_watcher() {
    let tree = tree();
    tree.fail_clone(live("README"), 5);
    let setup = watching(&tree);
    let shadow = build(&tree, &setup.clock);
    setup.watcher.follow(Arc::clone(&shadow));
    assert!(matches!(shadow.wait(SETTLE), ShadowStatus::Failed(_)));
    let deadline = std::time::Instant::now() + SETTLE;
    while setup.watcher.is_running() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!setup.watcher.is_running());
    assert_eq!(setup.settle(), LineClose::Uncertain(UncertainReason::NotWatched));
}

// Moving a folder in reports only the folder: everything below it is brought in step too.
#[test]
fn a_folder_moved_into_the_root_is_shadowed_with_its_contents() {
    let setup = ready();
    setup.tree.add_file("/elsewhere/pkg/a.txt", b"a");
    setup.tree.add_file("/elsewhere/pkg/sub/b.txt", b"b");
    setup.tree.rename("/elsewhere/pkg", live("pkg"));
    setup.emit(live("pkg"), F::ITEM_RENAMED.union(F::ITEM_IS_DIR));
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.tree.node(copy("pkg/a.txt")), file(b"a"));
    assert_eq!(setup.tree.node(copy("pkg/sub/b.txt")), file(b"b"));
    assert_eq!(setup.live_tree(), setup.shadow_tree());

    // And moving it out removes it, with everything below it.
    setup.tree.rename(live("pkg"), "/elsewhere/pkg");
    setup.emit(live("pkg"), F::ITEM_RENAMED.union(F::ITEM_IS_DIR));
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.tree.node(copy("pkg")), None);
    assert_eq!(setup.live_tree(), setup.shadow_tree());
}

// A file replaced by a folder (and back) replaces its shadow copy; a file whose parent's change was not applied yet
// gets its parent first.
#[test]
fn kind_changes_and_missing_parents_are_handled() {
    let setup = ready();
    setup.tree.remove_all(live("README"));
    setup.tree.add_file(live("README/inside.txt"), b"i");
    setup.emit(live("README/inside.txt"), F::ITEM_CREATED);
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.tree.node(copy("README")), Some(FakeNode::Dir));
    assert_eq!(setup.tree.node(copy("README/inside.txt")), file(b"i"));

    setup.tree.remove_all(live("README"));
    setup.tree.add_file(live("README"), b"a file again");
    setup.emit(live("README"), F::ITEM_CREATED.union(F::ITEM_REMOVED));
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.tree.node(copy("README")), file(b"a file again"));
    assert_eq!(setup.live_tree(), setup.shadow_tree());
}

// FR-CKP-31: excluded folders, the store and anything outside the root are never shadowed, whatever the events say.
#[test]
fn excluded_and_engine_paths_are_never_shadowed() {
    let setup = ready();
    setup.tree.add_file(live("node_modules/y/new.js"), b"excluded");
    setup.tree.add_file(live("deep/target/out.o"), b"excluded too");
    setup.emit(live("node_modules/y/new.js"), F::ITEM_CREATED);
    setup.emit(live("deep/target/out.o"), F::ITEM_CREATED);
    setup.emit(live("deep/target"), F::ITEM_CREATED.union(F::ITEM_IS_DIR));
    setup.emit(live("../escape"), F::ITEM_CREATED);
    setup.emit(shadow().join("README"), F::ITEM_MODIFIED);
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.tree.node(copy("node_modules")), None);
    assert_eq!(setup.tree.node(copy("deep/target")), None);
    // `deep` itself is a new folder that is not excluded: shadowed, and the only change reported.
    assert_eq!(setup.tree.node(copy("deep")), Some(FakeNode::Dir));
    assert_eq!(setup.reports.changed(), [live("deep")]);
    // FR-CKP-31 (KNSH-084): each excluded folder something changed in is reported, outermost excluded name first;
    // the store, the shadow and paths leaving the root are not.
    let mut excluded = setup.reports.excluded();
    excluded.sort();
    excluded.dedup();
    assert_eq!(excluded, [live("deep/target"), live("node_modules")]);
}

// Decision 16: `RootChanged` rescans the root; while the root is gone, the shadow keeps its last known state rather
// than being emptied.
#[test]
fn a_root_that_moved_away_keeps_its_shadow() {
    let setup = ready();
    let before = setup.shadow_tree();
    setup.tree.rename(ROOT, "/code/app-moved");
    setup.emit(ROOT, F::ROOT_CHANGED);
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.shadow_tree(), before);
    assert_eq!(setup.reports.uncertain(), [UncertainReason::RootChanged]);

    // Back, with a change: rescanned.
    setup.tree.rename("/code/app-moved", ROOT);
    setup.tree.add_file(live("README"), b"changed while away");
    setup.emit(ROOT, F::ROOT_CHANGED);
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.tree.node(copy("README")), file(b"changed while away"));
}

// `EventIdsWrapped` rescans every watched root, and a drop on the marker folder counts as a drop for the root.
#[test]
fn wrapped_ids_and_marker_folder_drops_rescan_the_root() {
    let setup = ready();
    setup.tree.add_file(live("a.txt"), b"a");
    setup.emit(ROOT, F::EVENT_IDS_WRAPPED);
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.tree.node(copy("a.txt")), file(b"a"));
    setup.tree.add_file(live("b.txt"), b"b");
    setup.emit(markers(), F::MUST_SCAN_SUB_DIRS.union(F::USER_DROPPED));
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.tree.node(copy("b.txt")), file(b"b"));
    assert_eq!(
        setup.reports.uncertain(),
        [UncertainReason::EventIdsWrapped, UncertainReason::EventsDropped]
    );
}

// A shadow operation that fails leaves the window uncertain instead of claiming the shadow follows the tree.
#[test]
fn a_failed_shadow_update_marks_the_window_uncertain() {
    let setup = ready();
    setup.tree.add_file(live("bad.txt"), b"x");
    setup.tree.fail_clone(live("bad.txt"), 5);
    let mark = setup.watcher.open_line();
    setup.emit(live("bad.txt"), F::ITEM_CREATED);
    assert_eq!(
        setup.watcher.close_line(mark),
        LineClose::Uncertain(UncertainReason::ShadowUpdateFailed)
    );
}

// Stopping drops the stream and the worker; later lines are uncertain, and events are ignored.
#[test]
fn stop_drops_the_stream() {
    let setup = ready();
    assert_eq!(setup.events.live_streams(), 1);
    assert_eq!(
        setup.events.watched(),
        [vec![PathBuf::from(ROOT), markers()]],
        "one stream on the root and its marker folder"
    );
    setup.watcher.stop();
    setup.watcher.stop();
    assert_eq!(setup.events.live_streams(), 0);
    assert!(!setup.watcher.is_running());
    assert_eq!(setup.settle(), LineClose::Uncertain(UncertainReason::NotWatched));
}

// A stream that cannot start fails the watcher, and nothing keeps running.
#[test]
fn a_stream_that_cannot_start_is_an_error() {
    let tree = tree();
    let events = ScriptedFileEvents::new();
    events.fail_next_watch(knsh_platform::testing::watch_failure());
    let result = start_watch(
        &events,
        Arc::clone(&tree) as Arc<dyn ShadowFiles>,
        Arc::new(FakeClock::new(Timestamp::from_unix_micros(0).unwrap())),
        Arc::new(Reports::default()),
        plan(),
    );
    assert!(matches!(result, Err(CheckpointError::Platform(_))));
    assert_eq!(events.live_streams(), 0);
}

// The marker folder is made owner-only inside the store; a symlink in its place is refused.
#[test]
fn marker_folder_must_be_a_real_folder() {
    let tree = tree();
    tree.add(
        Path::new(STORE).join(MARKERS_DIR),
        FakeNode::Symlink(PathBuf::from("/elsewhere")),
    );
    let result = start_watch(
        &ScriptedFileEvents::new(),
        Arc::clone(&tree) as Arc<dyn ShadowFiles>,
        Arc::new(FakeClock::new(Timestamp::from_unix_micros(0).unwrap())),
        Arc::new(Reports::default()),
        plan(),
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Platform(PlatformError::UnexpectedKind))
    ));
}

// FR-CKP-03, security: a folder replaced by a symlink makes its shadow copy a symlink too. A path below it that is
// still pending (its own event) must never be read, cloned into or removed through that copy, which would reach
// outside the shadow. The fake resolves nothing, so a node "below" the shadow's symlink stands for the file the
// symlink would reach.
#[test]
fn a_pending_path_below_a_folder_turned_symlink_never_goes_through_it() {
    let setup = ready();
    setup.tree.remove_all(live("src"));
    setup
        .tree
        .add(live("src"), FakeNode::Symlink(PathBuf::from("../../../../victim")));
    setup.emit(
        live("src"),
        F::ITEM_REMOVED.union(F::ITEM_CREATED).union(F::ITEM_IS_SYMLINK),
    );
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(
        setup.tree.node(copy("src")),
        Some(FakeNode::Symlink(PathBuf::from("../../../../victim")))
    );

    // What `<shadow>/src/main.rs` would reach through the symlink; the live `src/main.rs` is gone.
    setup.tree.add_file(copy("src/main.rs"), b"not the shadow's");
    let removed_from_shadow = || {
        setup
            .tree
            .removed()
            .into_iter()
            .filter(|path| path.starts_with(shadow()))
            .count()
    };
    let removed = removed_from_shadow();
    setup.emit(live("src/main.rs"), F::ITEM_REMOVED.union(F::ITEM_IS_FILE));
    // And a pending folder below the symlink whose live side reaches somewhere else.
    setup
        .tree
        .add_file(live("src/new/file.txt"), b"through the live symlink");
    setup.emit(live("src/new"), F::ITEM_CREATED.union(F::ITEM_IS_DIR));
    assert_eq!(setup.settle(), LineClose::Certain);
    assert_eq!(setup.tree.node(copy("src/main.rs")), file(b"not the shadow's"));
    assert_eq!(removed_from_shadow(), removed, "nothing removed through the symlink");
    assert_eq!(
        setup.tree.node(copy("src/new")),
        None,
        "nothing created through the symlink"
    );
}

// When the root holds the store, the worker's own clones into the shadow come back as events: they are dropped at
// once, so they never fill the pending set or open a `too_many_events` window.
#[test]
fn events_for_a_store_inside_the_root_are_dropped_at_once() {
    let tree = Arc::new(FakeTree::new());
    let store = live(".knsh-checkpoints");
    tree.add_dir(&store);
    tree.add_file(live("README"), b"hello");
    let (markers, marker_parents) = marker_dir(&store, "S1", 0);
    let (held, held_parents) = held_dir(&store, "S1", 0);
    let shadow = shadow_dir(&store, "S1", 0).0;
    let plan = WatchPlan {
        root: canonical(ROOT),
        shadow: shadow.clone(),
        markers,
        marker_parents,
        held,
        held_parents,
        exclude: exclude(),
        skip: vec![store.clone()],
        latency: STREAM_LATENCY,
        flush_deadline: FLUSH_DEADLINE,
    };
    let events = ScriptedFileEvents::new();
    let watcher = start_watch(
        &events,
        Arc::clone(&tree) as Arc<dyn ShadowFiles>,
        Arc::new(FakeClock::new(Timestamp::from_unix_micros(0).unwrap())),
        Arc::new(Reports::default()),
        plan,
    )
    .unwrap();
    let burst: Vec<FileEvent> = (0..=MAX_PENDING_PATHS)
        .map(|n| FileEvent::new(shadow.join(format!("f{n}")), F::ITEM_CREATED.union(F::ITEM_IS_FILE)))
        .collect();
    events.emit(&burst);
    events.emit(&[FileEvent::new(store.join("other"), F::ITEM_CREATED)]);
    {
        let state = lock(&watcher.inner.state);
        assert!(state.pending.is_empty());
        assert!(!state.rescan_root);
    }
    // A real change in the root is still kept.
    events.emit(&[FileEvent::new(live("README"), F::ITEM_MODIFIED)]);
    assert_eq!(lock(&watcher.inner.state).pending.len(), 1);
    watcher.stop();
}

// KNSH-082: once more orphans exist than are remembered, any path missing from the shadow may be one, so its pre-image
// is reported lost, never "did not exist" (a wrong marker would let undo delete what the path held).
#[test]
fn orphans_beyond_the_limit_make_every_missing_path_lost() {
    let mut orphans = Orphans::default();
    for n in 0..MAX_ORPHANS {
        orphans.remember(Path::new(&format!("f{n}")));
    }
    assert!(orphans.may_hold(Path::new("f0")));
    assert!(!orphans.may_hold(Path::new("never")));
    orphans.remember(Path::new("one-more"));
    assert_eq!(orphans.paths.len(), MAX_ORPHANS);
    assert!(orphans.may_hold(Path::new("one-more")));
    assert!(orphans.may_hold(Path::new("never")));
}
