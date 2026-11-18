//! Capture (KNSH-082) over an in-memory tree and scripted file events: a watcher reports each change to a ledger and
//! the captures, glued as `knshd` glues them.

use std::sync::Arc;
use std::time::Duration;

use knsh_core::Timestamp;
use knsh_platform::testing::{FakeClock, ScriptedFileEvents, SeededRandom};
use knsh_platform::{FileEvent, FileEventFlags as F};

use super::*;
use crate::attribution::Ledger;
use crate::identity::HASH_LIMIT;
use crate::shadow::{SHADOW_THREADS, ShadowPlan, ShadowStatus, shadow_dir, start_shadow};
use crate::testing::{FakeNode, FakeTree};
use crate::watcher::{
    FLUSH_DEADLINE, LineClose, STREAM_LATENCY, WatchPlan, WatchReport, Watcher, held_dir, marker_dir, start_watch,
};

const ROOT: &str = "/code/app";
const STORE: &str = "/store";
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

fn held() -> PathBuf {
    held_dir(Path::new(STORE), "S1", 0).0
}

fn session() -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(1))
}

fn record(n: u128) -> RecordId {
    RecordId::from_ulid(Ulid::from_u128(100 + n))
}

/// The glue `knshd` has: each change is attributed and begun under the ledger's lock, then added; closed edges finish
/// checkpoints.
struct Glue {
    ledger: Mutex<Ledger>,
    captures: Captures,
    finished: Mutex<Vec<Checkpoint>>,
}

impl Glue {
    fn with<R>(&self, change: impl FnOnce(&mut Ledger, &Captures) -> R) -> R {
        let mut ledger = lock(&self.ledger);
        let result = change(&mut ledger, &self.captures);
        let closed = ledger.take_closed();
        let finished = self.captures.closed(&closed);
        lock(&self.finished).extend(finished);
        result
    }
}

impl WatchReport for Glue {
    fn changed(&self, root: &CanonicalPath, change: Change) {
        let ticket = self.with(|ledger, captures| ledger.changed(root, &change.path).map(|edge| captures.begin(edge)));
        match ticket {
            Some(ticket) => {
                let finished = self.captures.add(ticket, session(), Path::new(STORE), root, change);
                lock(&self.finished).extend(finished);
            }
            None => self.captures.discard(change),
        }
    }

    fn uncertain(&self, _root: &CanonicalPath, _reason: UncertainReason) {}
}

struct Setup {
    tree: Arc<FakeTree>,
    events: ScriptedFileEvents,
    glue: Arc<Glue>,
    watcher: Arc<Watcher>,
}

fn tree() -> Arc<FakeTree> {
    let tree = Arc::new(FakeTree::new());
    tree.add_dir(STORE);
    tree.add_file(live("README"), b"hello");
    tree.add_file(live("src/main.rs"), b"fn main() {}");
    tree.add_file(live("src/lib.rs"), b"pub fn f() {}");
    tree.add_file(live("docs/guide.md"), b"# guide");
    tree
}

/// A watcher over `tree` with a complete shadow, reporting to the glue. The root is watched by an envelope session,
/// so changes outside lines are agent edits.
fn ready(tree: &Arc<FakeTree>) -> Setup {
    let events = ScriptedFileEvents::new();
    let markers = marker_dir(Path::new(STORE), "S1", 0).0;
    let echo = Arc::clone(tree);
    let marker_folder = markers.clone();
    // The real stream reports each marker file created; the line-end flush waits for it.
    events.on_flush(Box::new(move |_| {
        echo.paths_below(&marker_folder)
            .into_iter()
            .filter(|relative| !relative.as_os_str().is_empty())
            .map(|relative| FileEvent::new(marker_folder.join(relative), F::ITEM_CREATED.union(F::ITEM_IS_FILE)))
            .collect()
    }));
    let clock = Arc::new(FakeClock::new(
        Timestamp::from_unix_micros(1_700_000_000_000_000).unwrap(),
    ));
    let files = Arc::clone(tree) as Arc<dyn ShadowFiles>;
    let glue = Arc::new(Glue {
        ledger: Mutex::new(Ledger::new()),
        captures: Captures::new(
            Arc::clone(&files),
            Arc::clone(&clock) as Arc<dyn Clock>,
            Arc::new(SeededRandom::new(7)),
        ),
        finished: Mutex::new(Vec::new()),
    });
    glue.with(|ledger, _| ledger.watch(&canonical(ROOT), session(), true));
    let (markers, marker_parents) = marker_dir(Path::new(STORE), "S1", 0);
    let (held, held_parents) = held_dir(Path::new(STORE), "S1", 0);
    let watcher = start_watch(
        &events,
        Arc::clone(&files),
        Arc::clone(&clock) as Arc<dyn Clock>,
        Arc::clone(&glue) as Arc<dyn WatchReport>,
        WatchPlan {
            root: canonical(ROOT),
            shadow: shadow(),
            markers,
            marker_parents,
            held,
            held_parents,
            exclude: vec!["node_modules".to_owned()],
            skip: vec![PathBuf::from(STORE)],
            latency: STREAM_LATENCY,
            flush_deadline: FLUSH_DEADLINE,
        },
    )
    .unwrap();
    let (dir, parents) = shadow_dir(Path::new(STORE), "S1", 0);
    let build = start_shadow(
        files,
        clock,
        ShadowPlan {
            root: canonical(ROOT),
            dir,
            parents,
            exclude: vec!["node_modules".to_owned()],
            skip: vec![PathBuf::from(STORE)],
            threads: SHADOW_THREADS,
        },
    );
    assert!(matches!(build.wait(SETTLE), ShadowStatus::Complete(_)));
    watcher.follow(build);
    Setup {
        tree: Arc::clone(tree),
        events,
        glue,
        watcher,
    }
}

impl Setup {
    fn emit(&self, relative: &str, flags: F) {
        self.events.emit(&[FileEvent::new(live(relative), flags)]);
    }

    /// Runs line `n`: `change` makes its changes and emits their events; the line is then closed (decision 16) and
    /// ended in the ledger. Returns the checkpoint it finished.
    fn line(&self, n: u128, change: impl FnOnce(&Self)) -> Checkpoint {
        let root = canonical(ROOT);
        self.glue
            .with(|ledger, _| ledger.line_started(record(n), session(), std::slice::from_ref(&root)));
        let mark = self.watcher.open_line();
        change(self);
        assert_eq!(self.watcher.close_line(mark), LineClose::Certain);
        self.glue.with(|ledger, _| ledger.line_ended(record(n)));
        let finished = lock(&self.glue.finished);
        let checkpoint = finished
            .iter()
            .find(|checkpoint| checkpoint.records.contains(&record(n)))
            .cloned()
            .expect("the line's checkpoint");
        assert_eq!(checkpoint.attribution, Attribution::Command);
        checkpoint
    }

    fn live_tree(&self) -> BTreeMap<PathBuf, FakeNode> {
        self.tree.snapshot(ROOT)
    }

    fn shadow_tree(&self) -> BTreeMap<PathBuf, FakeNode> {
        self.tree.snapshot(shadow())
    }
}

fn captured<'a>(checkpoint: &'a Checkpoint, relative: &str) -> &'a CapturedPath {
    &checkpoint.paths[&canonical(ROOT)][&CanonicalPath::new(live(relative)).unwrap()]
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "compared with `FakeTree::node`, which returns an `Option`"
)]
fn file(contents: &[u8]) -> Option<FakeNode> {
    Some(FakeNode::File(contents.to_vec()))
}

/// The contents a kept pre-image holds.
fn kept(tree: &FakeTree, captured: &CapturedPath) -> Option<FakeNode> {
    match &captured.pre {
        StoredPreImage::Kept(path) => {
            assert!(path.starts_with(Path::new(STORE).join(CHECKPOINTS_DIR)), "{path:?}");
            tree.node(path)
        }
        other => panic!("not kept: {other:?}"),
    }
}

// FR-CKP-08: a file the line created did not exist before: its pre-image is the "did not exist" marker, and nothing
// is stored for it.
#[test]
fn created_file_records_not_existed_marker() {
    let setup = ready(&tree());
    let checkpoint = setup.line(1, |setup| {
        setup.tree.add_file(live("new.txt"), b"new");
        setup.emit("new.txt", F::ITEM_CREATED.union(F::ITEM_IS_FILE));
    });
    let new = captured(&checkpoint, "new.txt");
    assert_eq!(new.pre, StoredPreImage::NotExisted);
    assert_eq!(new.change(), Some(FileChange::Created));
    assert!(matches!(new.post, PostImage::Present(identity) if identity.identity.size == 3));
    assert_eq!(checkpoint.path_count(), 1);
    assert!(!checkpoint.is_uncertain());
    assert_eq!(setup.tree.node(shadow().join("new.txt")), file(b"new"));
    assert_eq!(setup.live_tree(), setup.shadow_tree());
    // Nothing is left in the holding folder.
    assert_eq!(setup.tree.paths_below(held()), [PathBuf::new()]);
}

// FR-CKP-08: a modified file's shadow copy is moved, never copied, into the checkpoint as its pre-image, and the new
// version is cloned into the shadow.
#[test]
fn modified_file_moves_shadow_copy_to_pre_image() {
    let setup = ready(&tree());
    let clones = setup.tree.clones();
    let checkpoint = setup.line(1, |setup| {
        setup.tree.add_file(live("README"), b"hello, world");
        setup.emit("README", F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
    });
    let readme = captured(&checkpoint, "README");
    assert_eq!(kept(&setup.tree, readme), file(b"hello"));
    assert_eq!(readme.change(), Some(FileChange::Modified));
    // Moved twice (shadow → holding folder → checkpoint), cloned once: the new version into the shadow.
    let renames = setup.tree.renames();
    assert_eq!(renames.len(), 2, "{renames:?}");
    assert_eq!(renames[0].0, shadow().join("README"));
    assert_eq!(renames[0].1, renames[1].0);
    assert_eq!(StoredPreImage::Kept(renames[1].1.clone()), readme.pre);
    assert_eq!(setup.tree.clones(), clones + 1);
    assert_eq!(setup.tree.node(shadow().join("README")), file(b"hello, world"));
    assert_eq!(setup.live_tree(), setup.shadow_tree());

    // FR-CKP-11: the record's `files_changed` lists it with its post-image identity.
    let files = checkpoint.files_changed();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path.as_path(), live("README"));
    let identity = files[0].post_image.unwrap();
    assert_eq!(identity.size, 12);
    assert_eq!(identity.sha256, Some(*FakeTree::digest_of(b"hello, world").as_bytes()));
}

// FR-CKP-08: a deleted file keeps its pre-image and gets a "deleted" post-image; a deleted folder lists itself and
// every entry that was below it, each with its own pre-image.
#[test]
fn deleted_file_keeps_pre_image() {
    let setup = ready(&tree());
    let checkpoint = setup.line(1, |setup| {
        setup.tree.remove_all(live("src/lib.rs"));
        setup.tree.remove_all(live("docs"));
        setup.emit("src/lib.rs", F::ITEM_REMOVED.union(F::ITEM_IS_FILE));
        setup.emit("docs", F::ITEM_REMOVED.union(F::ITEM_IS_DIR));
    });
    let lib = captured(&checkpoint, "src/lib.rs");
    assert_eq!(kept(&setup.tree, lib), file(b"pub fn f() {}"));
    assert_eq!(lib.post, PostImage::Deleted);
    assert_eq!(lib.change(), Some(FileChange::Deleted));
    let docs = captured(&checkpoint, "docs");
    assert_eq!((&docs.pre, docs.post), (&StoredPreImage::Folder, PostImage::Deleted));
    let guide = captured(&checkpoint, "docs/guide.md");
    assert_eq!(kept(&setup.tree, guide), file(b"# guide"));
    assert_eq!(guide.post, PostImage::Deleted);
    assert_eq!(checkpoint.path_count(), 3);
    assert_eq!(setup.live_tree(), setup.shadow_tree());
    let files = checkpoint.files_changed();
    assert!(
        files
            .iter()
            .all(|file| file.change == FileChange::Deleted && file.post_image.is_none())
    );
}

// FR-CKP-09: the post-image identity has inode, size and modification time, and a content hash only under 64 MiB.
#[test]
fn post_image_identity_has_hash_under_64_mib_only() {
    let setup = ready(&tree());
    let under = vec![0x5a; usize::try_from(HASH_LIMIT - 1).unwrap()];
    let at = vec![0x5a; usize::try_from(HASH_LIMIT).unwrap()];
    let checkpoint = setup.line(1, |setup| {
        setup.tree.add_file(live("under.bin"), &under);
        setup.tree.add_file(live("at.bin"), &at);
        setup.emit("under.bin", F::ITEM_CREATED.union(F::ITEM_IS_FILE));
        setup.emit("at.bin", F::ITEM_CREATED.union(F::ITEM_IS_FILE));
    });
    let identity = |relative: &str| match captured(&checkpoint, relative).post {
        PostImage::Present(identity) => identity,
        other => panic!("{relative}: {other:?}"),
    };
    let small = identity("under.bin");
    assert_eq!(small.identity, setup.tree.identity(&live("under.bin")).unwrap());
    assert_eq!(small.hash, Some(FakeTree::digest_of(&under)));
    let large = identity("at.bin");
    assert_eq!(large.identity.size, HASH_LIMIT);
    assert_eq!(large.hash, None);
    // A file of 64 MiB is not even read.
    assert!(!setup.tree.hashed().contains(&live("at.bin")));
}

// FR-CKP-10: capture touches only the changed paths: no folder of the root is listed, and only the changed files are
// moved and hashed, however many files the root holds.
#[test]
fn capture_touches_only_changed_paths() {
    let tree = tree();
    for n in 0..500 {
        tree.add_file(live(&format!("many/f{n}")), b"unchanged");
    }
    let setup = ready(&tree);
    let listed = setup.tree.listed().len();
    let checkpoint = setup.line(1, |setup| {
        setup.tree.add_file(live("README"), b"changed");
        setup.tree.add_file(live("many/f7"), b"changed");
        setup.emit("README", F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
        setup.emit("many/f7", F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
    });
    assert_eq!(checkpoint.path_count(), 2);
    assert_eq!(setup.tree.listed().len(), listed, "no folder was listed");
    assert_eq!(setup.tree.renames().len(), 4, "two pre-images, each moved twice");
    assert_eq!(setup.tree.hashed(), [live("README"), live("many/f7")]);
}

// A capture failure leaves the shadow consistent and marks the checkpoint uncertain, never recording wrong data: a
// shadow copy that cannot be moved is a lost pre-image (not "did not exist"), and a post-image that cannot be read is
// unknown.
#[test]
fn capture_failure_marks_checkpoint_uncertain() {
    // `libc` is reserved to `knsh-platform`; `EIO` is 5.
    const EIO: i32 = 5;
    let setup = ready(&tree());
    setup.tree.fail_rename(shadow().join("README"), EIO);
    setup.tree.fail_hash(live("src/main.rs"), EIO);
    let checkpoint = setup.line(1, |setup| {
        setup.tree.add_file(live("README"), b"changed");
        setup.tree.add_file(live("src/main.rs"), b"changed");
        setup.emit("README", F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
        setup.emit("src/main.rs", F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
    });
    assert!(checkpoint.is_uncertain());
    assert!(checkpoint.uncertain.contains(&UncertainReason::CaptureFailed));
    let readme = captured(&checkpoint, "README");
    assert_eq!(readme.pre, StoredPreImage::Lost);
    assert_eq!(readme.change(), Some(FileChange::Modified));
    let main = captured(&checkpoint, "src/main.rs");
    assert_eq!(kept(&setup.tree, main), file(b"fn main() {}"));
    assert_eq!(main.post, PostImage::Unknown);
    // The shadow follows the live tree all the same.
    assert_eq!(setup.live_tree(), setup.shadow_tree());
    // The record never gets an identity it does not have.
    let files = checkpoint.files_changed();
    let main = files
        .iter()
        .find(|file| file.path.as_path() == live("src/main.rs"))
        .unwrap();
    assert_eq!(main.post_image, None);
}

// A new version that cannot be cloned puts the held copy back: the shadow keeps its last known state, and the change
// is captured when a later event retries it.
#[test]
fn failed_clone_puts_the_pre_image_back() {
    const EIO: i32 = 5;
    let setup = ready(&tree());
    setup.tree.fail_clone(live("README"), EIO);
    setup.tree.add_file(live("README"), b"changed");
    setup.emit("README", F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
    let mark = setup.watcher.open_line();
    assert_eq!(
        setup.watcher.close_line(mark),
        LineClose::Uncertain(UncertainReason::ShadowUpdateFailed)
    );
    assert_eq!(setup.tree.node(shadow().join("README")), file(b"hello"));
    assert_eq!(setup.tree.paths_below(held()), [PathBuf::new()]);
}

// A name in the holding folder already taken (a pre-image an earlier run left behind) is never replaced and never
// costs the pre-image: the next free name is used.
#[test]
fn taken_holding_name_does_not_lose_the_pre_image() {
    let setup = ready(&tree());
    setup.tree.add_file(held().join("p-0"), b"left behind");
    setup.tree.add_file(held().join("p-1"), b"left behind");
    let checkpoint = setup.line(1, |setup| {
        setup.tree.add_file(live("README"), b"changed");
        setup.emit("README", F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
    });
    assert!(!checkpoint.is_uncertain(), "{:?}", checkpoint.uncertain);
    assert_eq!(kept(&setup.tree, captured(&checkpoint, "README")), file(b"hello"));
    assert_eq!(setup.tree.node(held().join("p-0")), file(b"left behind"));
    assert_eq!(setup.live_tree(), setup.shadow_tree());
}

// A path changed twice in one edge keeps its first pre-image (what it held before the edge) and its last post-image;
// the intermediate version is not kept.
#[test]
fn second_change_in_one_edge_keeps_first_pre_image() {
    let setup = ready(&tree());
    let checkpoint = setup.line(1, |setup| {
        setup.tree.add_file(live("README"), b"second");
        setup.emit("README", F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
        let mark = setup.watcher.open_line();
        assert_eq!(setup.watcher.close_line(mark), LineClose::Certain);
        setup.tree.add_file(live("README"), b"third!");
        setup.emit("README", F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
    });
    let readme = captured(&checkpoint, "README");
    assert_eq!(kept(&setup.tree, readme), file(b"hello"));
    assert!(matches!(readme.post, PostImage::Present(identity) if identity.identity.size == 6));
    assert_eq!(setup.tree.paths_below(held()), [PathBuf::new()]);
    let kept_files = setup
        .tree
        .paths_below(Path::new(STORE).join(CHECKPOINTS_DIR).join(checkpoint.id.to_string()));
    assert_eq!(kept_files.len(), 2, "the folder and one pre-image: {kept_files:?}");
}

// A file created and removed within one edge changed nothing: the checkpoint does not list it.
#[test]
fn created_then_removed_in_one_edge_is_not_listed() {
    let setup = ready(&tree());
    let checkpoint = setup.line(1, |setup| {
        setup.tree.add_file(live("tmp"), b"tmp");
        setup.emit("tmp", F::ITEM_CREATED.union(F::ITEM_IS_FILE));
        let mark = setup.watcher.open_line();
        assert_eq!(setup.watcher.close_line(mark), LineClose::Certain);
        setup.tree.remove_all(live("tmp"));
        setup.emit("tmp", F::ITEM_REMOVED.union(F::ITEM_IS_FILE));
        setup.tree.add_file(live("README"), b"changed");
        setup.emit("README", F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
    });
    assert_eq!(checkpoint.path_count(), 1);
    assert!(
        checkpoint
            .files_changed()
            .iter()
            .all(|file| file.path.as_path() != live("tmp"))
    );
}

// Agent edits between lines are their own checkpoint, closed when the next line starts; changes nobody claims (the
// root is no longer watched) keep nothing.
#[test]
fn agent_edits_get_their_own_checkpoint() {
    let setup = ready(&tree());
    setup.tree.add_file(live("README"), b"edited");
    setup.emit("README", F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
    let mark = setup.watcher.open_line();
    assert_eq!(setup.watcher.close_line(mark), LineClose::Certain);
    // The next line starts: the run of agent edits closes. The line itself changes nothing, so has no checkpoint.
    let root = canonical(ROOT);
    setup
        .glue
        .with(|ledger, _| ledger.line_started(record(1), session(), std::slice::from_ref(&root)));
    setup.glue.with(|ledger, _| ledger.line_ended(record(1)));
    let finished = lock(&setup.glue.finished).clone();
    assert_eq!(finished.len(), 1);
    let edit = finished
        .iter()
        .find(|checkpoint| checkpoint.attribution == Attribution::AgentEdit)
        .expect("the agent edit's checkpoint");
    assert!(edit.records.is_empty());
    assert_eq!(edit.sessions, BTreeSet::from([session()]));
    assert_eq!(kept(&setup.tree, captured(edit, "README")), file(b"hello"));

    // No session protects the root any more: a late change is dropped, its held copy removed.
    setup
        .glue
        .with(|ledger, _| ledger.unwatch(&canonical(ROOT), session(), true));
    setup.tree.add_file(live("README"), b"late");
    setup.emit("README", F::ITEM_MODIFIED.union(F::ITEM_IS_FILE));
    let mark = setup.watcher.open_line();
    assert_eq!(setup.watcher.close_line(mark), LineClose::Certain);
    assert_eq!(setup.tree.paths_below(held()), [PathBuf::new()]);
    setup.watcher.stop();
}

// FR-CKP-04: an edge marked uncertain has a checkpoint saying so even if nothing of it was captured, and a summary
// is available while it is open and once it is finished.
#[test]
fn uncertain_edge_without_changes_still_has_a_checkpoint() {
    let tree = tree();
    let captures = Captures::new(
        Arc::clone(&tree) as Arc<dyn ShadowFiles>,
        Arc::new(FakeClock::new(Timestamp::from_unix_micros(0).unwrap())),
        Arc::new(SeededRandom::new(1)),
    );
    let mut ledger = Ledger::new();
    let root = canonical(ROOT);
    ledger.watch(&root, session(), true);
    ledger.line_started(record(1), session(), std::slice::from_ref(&root));
    let edge = ledger.running_edge(record(1)).unwrap().id;
    captures.mark_uncertain(edge, UncertainReason::EventsDropped);
    let open = captures.summary(edge).unwrap();
    assert!(open.uncertain);
    assert_eq!(open.count, 0);
    ledger.line_ended(record(1));
    let finished = captures.closed(&ledger.take_closed());
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].uncertain, BTreeSet::from([UncertainReason::EventsDropped]));
    assert_eq!(captures.summary(edge).unwrap().id, open.id);

    // An edge that changed nothing has none.
    ledger.line_started(record(2), session(), std::slice::from_ref(&root));
    let quiet = ledger.running_edge(record(2)).unwrap().id;
    ledger.line_ended(record(2));
    assert_eq!(captures.closed(&ledger.take_closed()), Vec::new());
    assert_eq!(captures.summary(quiet), None);
}

// The checkpoint is not finished while a change of its edge is still being added: the edge closing in between waits
// for it.
#[test]
fn edge_closing_during_an_add_finishes_after_it() {
    let tree = tree();
    tree.add_file(held().join("p-0"), b"before");
    let captures = Captures::new(
        Arc::clone(&tree) as Arc<dyn ShadowFiles>,
        Arc::new(FakeClock::new(Timestamp::from_unix_micros(0).unwrap())),
        Arc::new(SeededRandom::new(1)),
    );
    let mut ledger = Ledger::new();
    let root = canonical(ROOT);
    ledger.watch(&root, session(), true);
    let path = CanonicalPath::new(live("README")).unwrap();
    let edge = ledger.changed(&root, &path).unwrap();
    let ticket = captures.begin(edge);
    // The next line starts: the agent-edit run closes before the change is added.
    ledger.line_started(record(1), session(), std::slice::from_ref(&root));
    assert_eq!(captures.closed(&ledger.take_closed()), Vec::new());
    let change = Change {
        path,
        pre: PreImage::Held(held().join("p-0")),
        post: PostImage::Deleted,
    };
    let finished = captures.add(ticket, session(), Path::new(STORE), &root, change);
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].attribution, Attribution::AgentEdit);
    assert_eq!(kept(&tree, captured(&finished[0], "README")), file(b"before"));
}
