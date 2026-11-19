//! Undo and redo through the history (KNSH-084), over an in-memory tree.

use std::path::Path;
use std::sync::Mutex;

use knsh_core::{ConflictReason, RestoreConflict, Timestamp, TornPath, TornReason};
use knsh_platform::testing::{FakeClock, SeededRandom};

use super::*;
use crate::capture::{PostImage, StoredPreImage};
use crate::restore::RESTORES_DIR;
use crate::restore::tests::{Fixture, ROOT, STORE, Taken, canonical, live, record, session};

/// Every `checkpoint.restored` published, in order.
#[derive(Default)]
struct Events(Mutex<Vec<(SessionId, EventData)>>);

impl RestoreEvents for Events {
    fn restored(&self, session_id: SessionId, data: EventData) {
        self.0.lock().unwrap().push((session_id, data));
    }
}

impl Events {
    fn take(&self) -> Vec<(SessionId, EventData)> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

fn history(fixture: &Fixture) -> History {
    History::new(
        Arc::clone(&fixture.tree) as Arc<dyn ShadowFiles>,
        Arc::new(FakeClock::new(
            Timestamp::from_unix_micros(1_763_000_000_000_000).unwrap(),
        )),
        Arc::new(SeededRandom::new(7)),
    )
}

fn user(n: u128) -> Request {
    Request {
        target: Target::Record(record(n)),
        caller: Caller::User,
        force: false,
    }
}

fn agent(n: u128) -> Request {
    Request {
        caller: Caller::Agent(session(1)),
        ..user(n)
    }
}

/// A history holding one line's change of `a.txt` from `old` to `new`.
fn edited() -> (Fixture, History, Events) {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"old");
    let mut history = history(&fixture);
    history
        .record(fixture.command(1, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"new")))
        .unwrap();
    (fixture, history, Events::default())
}

// FR-CKP-20: the live file still matches its post-image, so the change is undone.
#[test]
fn undo_restores_when_identity_matches() {
    let (fixture, mut history, events) = edited();
    let restored = history.undo(&agent(1), &events).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"old"[..]));
    assert_eq!(restored.operation, RestoreOperation::Undo);
    assert_eq!(restored.records, vec![record(1)]);
    assert_eq!(restored.restored, vec![canonical(live("a.txt"))]);
    assert_eq!(restored.head, history.tree().root());
    assert!(!restored.forced);
}

// FR-CKP-20: a file changed after the change was captured is a conflict, and stays as it is.
#[test]
fn undo_is_conflict_when_file_changed_after_capture() {
    let (fixture, mut history, events) = edited();
    fixture.tree.add_file(live("a.txt"), b"human edit");
    let head = history.tree().head();

    let error = history.undo(&agent(1), &events).unwrap_err();

    assert_eq!(
        error,
        CheckpointError::Conflicts(vec![RestoreConflict {
            path: canonical(live("a.txt")),
            reason: ConflictReason::Changed,
        }])
    );
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"human edit"[..]));
    assert_eq!(history.tree().head(), head, "the history did not move");
    assert!(
        events.take().is_empty(),
        "nothing was restored, so nothing is published"
    );
}

// Decision 17: a write through a mapping moves neither size nor time; the content hash still sees it.
#[test]
fn undo_is_conflict_when_only_contents_changed() {
    let (fixture, mut history, events) = edited();
    let identity = fixture.identity("a.txt");
    // Same length, time put back: only the contents differ.
    fixture.tree.add_file(live("a.txt"), b"NEW");
    let mut changed = history
        .checkpoint(history.tree().edge_for_record(record(1)).unwrap().checkpoint)
        .unwrap()
        .clone();
    for captured in changed.paths.values_mut().flat_map(BTreeMap::values_mut) {
        if let PostImage::Present(post) = &mut captured.post {
            post.identity = fixture.identity("a.txt");
            assert_eq!(post.identity.size, identity.size);
        }
    }
    history.checkpoints.insert(changed.id, changed);
    let error = history.undo(&user(1), &events).unwrap_err();
    assert!(
        matches!(&error, CheckpointError::Conflicts(c) if c[0].reason == ConflictReason::Changed),
        "{error:?}"
    );
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"NEW"[..]));
}

// No partial restore: one conflicting path refuses the whole undo, and no other path changes.
#[test]
fn conflict_changes_nothing_across_all_paths() {
    let fixture = Fixture::new();
    for name in ["a.txt", "b.txt", "c.txt"] {
        fixture.tree.add_file(live(name), b"old");
    }
    let mut history = history(&fixture);
    history
        .record(fixture.command(1, &["a.txt", "b.txt", "c.txt", "d.txt"], |tree| {
            for name in ["a.txt", "b.txt", "c.txt", "d.txt"] {
                tree.add_file(live(name), b"new");
            }
        }))
        .unwrap();
    fixture.tree.add_file(live("b.txt"), b"human");
    fixture.tree.remove_all(live("d.txt"));
    let before = fixture.tree.snapshot("/");

    let error = history.undo(&user(1), &Events::default()).unwrap_err();

    assert_eq!(
        error,
        CheckpointError::Conflicts(vec![
            RestoreConflict {
                path: canonical(live("b.txt")),
                reason: ConflictReason::Changed,
            },
            RestoreConflict {
                path: canonical(live("d.txt")),
                reason: ConflictReason::Missing,
            },
        ])
    );
    assert_eq!(fixture.tree.snapshot("/"), before, "not a byte changed, nothing saved");
    assert_eq!(fixture.tree.writes(), Vec::new());
}

// FR-CKP-22: the old contents go into the existing file: same inode, so a hard link and an open descriptor read
// the restored contents.
#[test]
fn restore_preserves_inode_and_hard_links() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"old");
    let mut history = history(&fixture);
    // `sed -i`: the edit is a new file renamed over the old one.
    history
        .record(fixture.command(1, &["a.txt"], |tree| tree.replace_file(live("a.txt"), b"new")))
        .unwrap();
    fixture.tree.link(live("a.txt"), "/elsewhere/link.txt");
    let inode = fixture.identity("a.txt").inode;
    let descriptor = fixture.tree.open(live("a.txt")).unwrap();

    history.undo(&user(1), &Events::default()).unwrap();

    assert_eq!(fixture.identity("a.txt").inode, inode);
    assert_eq!(
        fixture.tree.identity(Path::new("/elsewhere/link.txt")).unwrap().inode,
        inode
    );
    assert_eq!(
        fixture.tree.node("/elsewhere/link.txt"),
        Some(crate::testing::FakeNode::File(b"old".to_vec()))
    );
    assert_eq!(fixture.tree.read(descriptor).as_deref(), Some(&b"old"[..]));
}

// FR-CKP-23: the restored file's time is now, later than both the change and the pre-image it came from.
#[test]
fn restore_sets_mtime_to_now() {
    let (fixture, mut history, events) = edited();
    let after_change = fixture.identity("a.txt").modified;
    let checkpoint = history.tree().edge_for_record(record(1)).unwrap().checkpoint;
    let pre_image_time = history.checkpoint(checkpoint).unwrap().paths[&canonical(ROOT)]
        .values()
        .find_map(|captured| match &captured.pre {
            StoredPreImage::Kept(copy) => Some(fixture.tree.identity(copy).unwrap().modified),
            _ => None,
        })
        .unwrap();

    history.undo(&user(1), &events).unwrap();

    let now = fixture.identity("a.txt").modified;
    assert!(now > after_change && now > pre_image_time, "{now:?}");
}

// Undo saves the versions it replaces; redo puts them back, and the change is in effect again.
#[test]
fn redo_after_undo_restores_saved_versions() {
    let (fixture, mut history, events) = edited();
    let head = history.tree().head();
    history.undo(&agent(1), &events).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"old"[..]));

    let redone = history.redo(&agent(1), &events).unwrap();

    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"new"[..]));
    assert_eq!(redone.operation, RestoreOperation::Redo);
    assert_eq!(redone.head, head);
    let checkpoint = history.tree().edge_for_record(record(1)).unwrap().checkpoint;
    assert!(history.tree().is_in_effect(checkpoint));
    assert_eq!(
        history.tree().edge(checkpoint).unwrap().saved,
        None,
        "the saved versions were released"
    );
    assert_eq!(history.checkpoints.len(), 1, "and their checkpoint removed");

    // Undo and redo again: each round trip works from the current versions.
    history.undo(&user(1), &events).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"old"[..]));
    history.redo(&user(1), &events).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"new"[..]));
}

// Redo checks identity too: a file edited after the undo is not overwritten.
#[test]
fn redo_is_conflict_when_file_changed_after_undo() {
    let (fixture, mut history, events) = edited();
    history.undo(&user(1), &events).unwrap();
    fixture.tree.add_file(live("a.txt"), b"human");
    let error = history.redo(&user(1), &events).unwrap_err();
    assert!(matches!(error, CheckpointError::Conflicts(_)), "{error:?}");
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"human"[..]));
}

// FR-CKP-21: `force` from an agent is refused before anything is checked; the user's is honoured.
#[test]
fn force_rejected_for_agent_scoped_caller() {
    let (fixture, mut history, events) = edited();
    fixture.tree.add_file(live("a.txt"), b"human");
    let forced = Request {
        force: true,
        ..agent(1)
    };
    assert_eq!(history.undo(&forced, &events), Err(CheckpointError::ForceNotAllowed));
    assert_eq!(history.redo(&forced, &events), Err(CheckpointError::ForceNotAllowed));
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"human"[..]));

    for caller in [Caller::User, Caller::Authority] {
        assert!(caller.may_force());
    }
    let restored = history.undo(&Request { force: true, ..user(1) }, &events).unwrap();
    assert!(restored.forced);
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"old"[..]));
}

// FR-CKP-31: excluded folders the change touched are listed as not restored; protected paths are restored.
#[test]
fn excluded_paths_listed_as_not_restored() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("package.json"), b"{}");
    let mut history = history(&fixture);
    let mut checkpoint = fixture.command(1, &["package.json"], |tree| {
        tree.add_file(live("package.json"), b"{\"dependencies\":{}}");
        tree.add_file(live("node_modules/x/index.js"), b"x");
    });
    checkpoint.excluded = [(canonical(ROOT), [canonical(live("node_modules"))].into())].into();
    history.record(checkpoint).unwrap();

    let restored = history.undo(&user(1), &Events::default()).unwrap();

    assert_eq!(restored.not_restored, vec![canonical(live("node_modules"))]);
    assert!(!restored.not_restored_incomplete);
    assert_eq!(restored.restored, vec![canonical(live("package.json"))]);
    assert_eq!(fixture.contents("package.json").as_deref(), Some(&b"{}"[..]));
    assert_eq!(fixture.contents("node_modules/x/index.js").as_deref(), Some(&b"x"[..]));
}

// FR-CKP-25: `checkpoint.restored` is published on each session of the change, after the files were restored.
#[test]
fn checkpoint_restored_is_published_on_each_session() {
    let (fixture, mut history, events) = edited();
    let checkpoint = history.tree().edge_for_record(record(1)).unwrap().checkpoint;
    history.undo(&user(1), &events).unwrap();
    let published = events.take();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].0, session(1));
    let EventData::CheckpointRestored {
        checkpoint_id,
        operation,
        record_ids,
        roots,
        files_restored,
        forced,
    } = &published[0].1
    else {
        panic!("not a checkpoint.restored payload");
    };
    assert_eq!(*checkpoint_id, checkpoint);
    assert_eq!(*operation, RestoreOperation::Undo);
    assert_eq!(record_ids, &vec![record(1)]);
    assert_eq!(roots, &vec![canonical(ROOT)]);
    assert_eq!((*files_restored, *forced), (1, false));
    assert_eq!(published[0].1.name(), "checkpoint.restored");
    let _ = fixture;
}

// FR-CKP-36: an irreversible change's files are still restored, and its undo lists what cannot be undone.
#[test]
fn irreversible_change_is_restored_and_listed() {
    let (fixture, mut history, events) = edited();
    let checkpoint = history.tree().edge_for_record(record(1)).unwrap().checkpoint;
    history.mark_irreversible(checkpoint, ["network_request".to_owned()]);
    let restored = history.undo(&user(1), &events).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"old"[..]));
    assert_eq!(restored.irreversible, vec!["network_request".to_owned()]);
}

// An agent undoes only its own session's changes, and never external edits.
#[test]
fn agent_cannot_undo_another_sessions_or_external_change() {
    let fixture = Fixture::new();
    let mut history = history(&fixture);
    history
        .record(fixture.change(
            &Taken {
                n: 1,
                attribution: Attribution::Command,
                session: session(2),
                paths: &["a.txt"],
            },
            |tree| tree.add_file(live("a.txt"), b"theirs"),
        ))
        .unwrap();
    let external = fixture.change(
        &Taken {
            n: 2,
            attribution: Attribution::External,
            session: session(1),
            paths: &["b.txt"],
        },
        |tree| tree.add_file(live("b.txt"), b"external"),
    );
    let external_id = external.id;
    history.record(external).unwrap();

    assert_eq!(
        history.undo(&agent(1), &Events::default()),
        Err(CheckpointError::NotOwnChange)
    );
    let external_request = Request {
        target: Target::Checkpoint(external_id),
        ..agent(1)
    };
    assert_eq!(
        history.undo(&external_request, &Events::default()),
        Err(CheckpointError::NotOwnChange)
    );
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"theirs"[..]));
    // The user may undo either.
    history
        .undo(
            &Request {
                caller: Caller::User,
                ..external_request
            },
            &Events::default(),
        )
        .unwrap();
    assert_eq!(fixture.contents("b.txt"), None);
}

// FR-CKP-30: an older change no later change overlaps is reverted on top of them; its redo undoes the revert.
#[test]
fn undo_of_older_change_reverts_and_redo_undoes_the_revert() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"a-old");
    let mut history = history(&fixture);
    history
        .record(fixture.command(1, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"a-new")))
        .unwrap();
    history
        .record(fixture.command(2, &["b.txt"], |tree| tree.add_file(live("b.txt"), b"b-new")))
        .unwrap();

    history.undo(&user(1), &Events::default()).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a-old"[..]));
    assert_eq!(fixture.contents("b.txt").as_deref(), Some(&b"b-new"[..]));

    history.redo(&user(1), &Events::default()).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a-new"[..]));
    assert_eq!(fixture.contents("b.txt").as_deref(), Some(&b"b-new"[..]));

    // In effect again, with post-images that describe the rewritten file: it can be undone once more.
    history.undo(&user(1), &Events::default()).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a-old"[..]));
}

// FR-CKP-30: overlapped by a later change, an older change cannot be undone; the paths are listed.
#[test]
fn undo_of_overlapped_older_change_is_refused() {
    let fixture = Fixture::new();
    let mut history = history(&fixture);
    history
        .record(fixture.command(1, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"one")))
        .unwrap();
    history
        .record(fixture.command(2, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"two")))
        .unwrap();
    let error = history.undo(&user(1), &Events::default()).unwrap_err();
    assert!(
        matches!(error, CheckpointError::History(HistoryError::Conflict { .. })),
        "{error:?}"
    );
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"two"[..]));
}

// A failed restore leaves the history where it was, and nothing of the attempt behind.
#[test]
fn failed_restore_leaves_history_unchanged() {
    let (fixture, mut history, events) = edited();
    fixture
        .tree
        .fail_write_once(live("a.txt"), crate::restore::tests::ENOSPC);
    let head = history.tree().head();
    let error = history.undo(&user(1), &events).unwrap_err();
    assert!(matches!(error, CheckpointError::RolledBack(_)), "{error:?}");
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"new"[..]));
    assert_eq!(history.tree().head(), head);
    assert_eq!(history.checkpoints.len(), 1);
    assert!(
        fixture.tree.paths_below(Path::new(STORE).join(RESTORES_DIR)).len() <= 1,
        "no journal left"
    );
    assert!(events.take().is_empty());
}

// FR-CKP-20: undoing a change rewrites its file (new time), which is what the change before it left there; undoing
// that one next must not see the file as changed. Redone in turn, each redo checks what the other restore left.
#[test]
fn successive_undos_and_redos_of_one_file_do_not_conflict() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"v0");
    let mut history = history(&fixture);
    history
        .record(fixture.command(1, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"v1")))
        .unwrap();
    history
        .record(fixture.command(2, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"v2")))
        .unwrap();

    history.undo(&user(2), &Events::default()).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"v1"[..]));
    history.undo(&user(1), &Events::default()).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"v0"[..]));
    history.redo(&user(1), &Events::default()).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"v1"[..]));
    history.redo(&user(2), &Events::default()).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"v2"[..]));
    history.undo(&user(2), &Events::default()).unwrap();
    history.undo(&user(1), &Events::default()).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"v0"[..]));
}

// FR-CKP-20: a post-image is refreshed only to the same contents. A human edit between two changes that the history
// never recorded is not laundered: undoing the older change after the newer one is still a conflict.
#[test]
fn unrecorded_edit_between_changes_still_conflicts_after_undo() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"v0");
    let mut history = history(&fixture);
    history
        .record(fixture.command(1, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"v1")))
        .unwrap();
    fixture.tree.add_file(live("a.txt"), b"human");
    history
        .record(fixture.command(2, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"v2")))
        .unwrap();

    history.undo(&user(2), &Events::default()).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"human"[..]));
    let error = history.undo(&user(1), &Events::default()).unwrap_err();
    assert_eq!(
        error,
        CheckpointError::Conflicts(vec![RestoreConflict {
            path: canonical(live("a.txt")),
            reason: ConflictReason::Changed,
        }])
    );
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"human"[..]));
}

/// A history holding one line's change of `a.txt` (old to new) and `app.db` (v1 to v2), with `app.db` possibly torn.
fn torn_edit() -> (Fixture, History, Events) {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"old");
    fixture.tree.add_file(live("app.db"), b"v1");
    let mut history = history(&fixture);
    let mut checkpoint = fixture.command(1, &["a.txt", "app.db"], |tree| {
        tree.add_file(live("a.txt"), b"new");
        tree.add_file(live("app.db"), b"v2");
    });
    checkpoint
        .possibly_torn
        .insert(canonical(live("app.db")), TornReason::SqliteJournal);
    history.record(checkpoint).unwrap();
    (fixture, history, Events::default())
}

// FR-CKP-24: without `force`, a possibly-torn file is skipped and listed with its reason; the rest is restored.
#[test]
fn possibly_torn_file_skipped_without_force() {
    let (fixture, mut history, events) = torn_edit();
    let restored = history.undo(&agent(1), &events).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"old"[..]));
    assert_eq!(
        fixture.contents("app.db").as_deref(),
        Some(&b"v2"[..]),
        "left as the change left it"
    );
    assert_eq!(restored.restored, vec![canonical(live("a.txt"))]);
    assert_eq!(
        restored.skipped_torn,
        vec![TornPath {
            path: canonical(live("app.db")),
            reason: TornReason::SqliteJournal,
        }]
    );
    assert_eq!(restored.forced_torn, Vec::<TornPath>::new());
    assert!(!restored.forced);
    // Redo puts back only what the undo restored.
    let redone = history.redo(&agent(1), &events).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"new"[..]));
    assert_eq!(redone.restored, vec![canonical(live("a.txt"))]);
    assert_eq!(redone.skipped_torn, Vec::<TornPath>::new());
}

// FR-CKP-24, FR-CKP-21: with `force` (user or authority only) the file is restored and the result says it was
// forced; its redo needs `force` too, since the version the undo replaced is the one that may be torn.
#[test]
fn forced_restore_of_torn_file_is_reported() {
    let (fixture, mut history, events) = torn_edit();
    let forced = Request { force: true, ..user(1) };
    let restored = history.undo(&forced, &events).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"old"[..]));
    assert_eq!(fixture.contents("app.db").as_deref(), Some(&b"v1"[..]));
    assert_eq!(
        restored.restored,
        vec![canonical(live("a.txt")), canonical(live("app.db"))]
    );
    let torn = vec![TornPath {
        path: canonical(live("app.db")),
        reason: TornReason::SqliteJournal,
    }];
    assert_eq!(restored.forced_torn, torn);
    assert_eq!(restored.skipped_torn, Vec::<TornPath>::new());
    assert!(restored.forced);
    let published = events.take();
    assert!(
        matches!(&published[0].1, EventData::CheckpointRestored { forced: true, .. }),
        "checkpoint.restored says it was forced"
    );

    // An agent can never force (FR-CKP-21): its redo skips the file.
    let redone = history.redo(&agent(1), &events).unwrap();
    assert_eq!(redone.skipped_torn, torn);
    assert_eq!(fixture.contents("app.db").as_deref(), Some(&b"v1"[..]));
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"new"[..]));
}

// FR-CKP-21: `force` from an agent is refused before anything else, possibly-torn files or not.
#[test]
fn agent_cannot_force_a_torn_file() {
    let (fixture, mut history, events) = torn_edit();
    let error = history
        .undo(
            &Request {
                force: true,
                ..agent(1)
            },
            &events,
        )
        .unwrap_err();
    assert_eq!(error, CheckpointError::ForceNotAllowed);
    assert_eq!(fixture.contents("app.db").as_deref(), Some(&b"v2"[..]));
}

// A folder the change created, holding a possibly-torn file, cannot be removed without `force`: the skipped file
// would still be in it. The whole undo is refused and nothing changes.
#[test]
fn folder_holding_a_skipped_torn_file_is_not_removed() {
    let fixture = Fixture::new();
    let mut history = history(&fixture);
    let mut checkpoint = fixture.command(1, &["data", "data/app.db"], |tree| {
        tree.add_dir(live("data"));
        tree.add_file(live("data/app.db"), b"v1");
    });
    checkpoint
        .possibly_torn
        .insert(canonical(live("data/app.db")), TornReason::MappedWritable);
    history.record(checkpoint).unwrap();
    let error = history.undo(&agent(1), &Events::default()).unwrap_err();
    assert_eq!(
        error,
        CheckpointError::Conflicts(vec![RestoreConflict {
            path: canonical(live("data")),
            reason: ConflictReason::FolderNotEmpty,
        }])
    );
    assert_eq!(fixture.contents("data/app.db").as_deref(), Some(&b"v1"[..]));
}

// --- Restoring a state (KNSH-086) ---

fn to_state(state: StateId) -> StateRequest {
    StateRequest {
        state,
        caller: Caller::User,
        force: false,
    }
}

/// Three lines from the root state: (1) `a.txt` a0 to a1 and `e.txt` e0 to e1, (2) `b.txt` created, (3) `a.txt` a1
/// to a2 and `c.txt` created. Returns the states after each.
fn three_changes() -> (Fixture, History, [StateId; 3]) {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"a0");
    fixture.tree.add_file(live("e.txt"), b"e0");
    let mut history = history(&fixture);
    let s1 = history
        .record(fixture.command(1, &["a.txt", "e.txt"], |tree| {
            tree.add_file(live("a.txt"), b"a1");
            tree.add_file(live("e.txt"), b"e1");
        }))
        .unwrap();
    let s2 = history
        .record(fixture.command(2, &["b.txt"], |tree| tree.add_file(live("b.txt"), b"b1")))
        .unwrap();
    let s3 = history
        .record(fixture.command(3, &["a.txt", "c.txt"], |tree| {
            tree.add_file(live("a.txt"), b"a2");
            tree.add_file(live("c.txt"), b"c1");
        }))
        .unwrap();
    (fixture, history, [s1, s2, s3])
}

fn files_of(fixture: &Fixture) -> Vec<(&'static str, Option<Vec<u8>>)> {
    ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"]
        .into_iter()
        .map(|name| (name, fixture.contents(name)))
        .collect()
}

fn expect(pairs: [(&'static str, Option<&[u8]>); 5]) -> Vec<(&'static str, Option<Vec<u8>>)> {
    pairs
        .into_iter()
        .map(|(name, contents)| (name, contents.map(<[u8]>::to_vec)))
        .collect()
}

// KNSH-086, FR-CKP-20: restoring an earlier state undoes every later change at once, newest first, each with its
// identity checks; each is published, and the result lists every path restored.
#[test]
fn restore_to_state_undoes_all_later_changes() {
    let (fixture, mut history, [s1, _, s3]) = three_changes();
    let events = Events::default();

    let restored = history.restore_state(&to_state(s1), &events).unwrap();

    assert_eq!(
        files_of(&fixture),
        expect([
            ("a.txt", Some(b"a1")),
            ("b.txt", None),
            ("c.txt", None),
            ("d.txt", None),
            ("e.txt", Some(b"e1")),
        ])
    );
    assert_eq!((restored.from, restored.head), (s3, s1));
    assert_eq!(history.tree().head(), s1);
    let undone: Vec<(RestoreOperation, Vec<RecordId>)> = restored
        .steps
        .iter()
        .map(|step| (step.operation, step.records.clone()))
        .collect();
    assert_eq!(
        undone,
        vec![
            (RestoreOperation::Undo, vec![record(3)]),
            (RestoreOperation::Undo, vec![record(2)]),
        ]
    );
    assert_eq!(
        restored.restored(),
        ["a.txt", "b.txt", "c.txt"].map(|name| canonical(live(name))).to_vec()
    );
    assert_eq!(events.take().len(), 2, "one checkpoint.restored per change undone");

    // All the way back to the root, then forward again to where it started: redo of every change.
    history
        .restore_state(&to_state(history.tree().root()), &events)
        .unwrap();
    assert_eq!(
        files_of(&fixture),
        expect([
            ("a.txt", Some(b"a0")),
            ("b.txt", None),
            ("c.txt", None),
            ("d.txt", None),
            ("e.txt", Some(b"e0")),
        ])
    );
    let redone = history.restore_state(&to_state(s3), &events).unwrap();
    assert!(redone.steps.iter().all(|step| step.operation == RestoreOperation::Redo));
    assert_eq!(
        files_of(&fixture),
        expect([
            ("a.txt", Some(b"a2")),
            ("b.txt", Some(b"b1")),
            ("c.txt", Some(b"c1")),
            ("d.txt", None),
            ("e.txt", Some(b"e1")),
        ])
    );
    assert_eq!(history.tree().head(), s3);
}

// KNSH-086: a state on another branch (which redo cannot reach, `RedoBlocked`) is reached by going back to the
// shared state and forward down the other branch. `a.txt` is changed on both branches, by steps that are not next to
// each other, so each step must find the identities the previous ones left.
#[test]
fn restore_reaches_a_state_on_another_branch() {
    let (fixture, mut history, [_, _, s3]) = three_changes();
    let events = Events::default();
    history
        .restore_state(&to_state(history.tree().root()), &events)
        .unwrap();
    // A new branch from the root: (4) `d.txt` created, (5) `a.txt` a0 to a5.
    history
        .record(fixture.command(4, &["d.txt"], |tree| tree.add_file(live("d.txt"), b"d4")))
        .unwrap();
    history
        .record(fixture.command(5, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"a5")))
        .unwrap();
    assert_eq!(
        history.redo(&user(1), &events).unwrap_err(),
        CheckpointError::History(HistoryError::RedoBlocked)
    );
    events.take();

    let restored = history.restore_state(&to_state(s3), &events).unwrap();

    assert_eq!(
        files_of(&fixture),
        expect([
            ("a.txt", Some(b"a2")),
            ("b.txt", Some(b"b1")),
            ("c.txt", Some(b"c1")),
            ("d.txt", None),
            ("e.txt", Some(b"e1")),
        ])
    );
    assert_eq!(history.tree().head(), s3);
    let steps: Vec<(RestoreOperation, Vec<RecordId>)> = restored
        .steps
        .iter()
        .map(|step| (step.operation, step.records.clone()))
        .collect();
    assert_eq!(
        steps,
        vec![
            (RestoreOperation::Undo, vec![record(5)]),
            (RestoreOperation::Undo, vec![record(4)]),
            (RestoreOperation::Redo, vec![record(1)]),
            (RestoreOperation::Redo, vec![record(2)]),
            (RestoreOperation::Redo, vec![record(3)]),
        ]
    );
    assert_eq!(events.take().len(), 5);
    // And back to the other branch's end: undo and redo keep working after a restore.
    let other = history.tree().edge_for_record(record(5)).unwrap().to;
    history.restore_state(&to_state(other), &events).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a5"[..]));
    assert_eq!(fixture.contents("d.txt").as_deref(), Some(&b"d4"[..]));
    history.undo(&user(5), &events).unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a0"[..]));
}

// KNSH-086, FR-CKP-20: a conflict anywhere on the way, even in the oldest change (whose step would come last), is
// `-32004` with the paths before anything is written: no file, saved copy or journal, and the history stays.
#[test]
fn restore_conflict_changes_nothing() {
    let (fixture, mut history, [_, _, s3]) = three_changes();
    let events = Events::default();
    // Only change 1 touched `e.txt`; changes 3 and 2 alone would restore fine.
    fixture.tree.add_file(live("e.txt"), b"human edit");
    fixture.tree.remove_all(live("c.txt"));
    let before = fixture.tree.snapshot("/");

    let error = history
        .restore_state(&to_state(history.tree().root()), &events)
        .unwrap_err();

    assert_eq!(
        error,
        CheckpointError::Conflicts(vec![
            RestoreConflict {
                path: canonical(live("c.txt")),
                reason: ConflictReason::Missing,
            },
            RestoreConflict {
                path: canonical(live("e.txt")),
                reason: ConflictReason::Changed,
            },
        ])
    );
    assert_eq!(fixture.tree.snapshot("/"), before, "not a byte changed, nothing saved");
    assert_eq!(fixture.tree.writes(), Vec::new());
    assert_eq!(history.tree().head(), s3);
    assert!(events.take().is_empty());
}

// KNSH-086: only the user and the authority may restore a state; an agent is refused before anything is checked.
#[test]
fn restore_is_only_for_user_and_authority() {
    let (fixture, mut history, [s1, _, s3]) = three_changes();
    let events = Events::default();
    let request = StateRequest {
        caller: Caller::Agent(session(1)),
        ..to_state(s1)
    };
    assert_eq!(
        history.restore_state(&request, &events),
        Err(CheckpointError::RestoreNotAllowed)
    );
    assert_eq!(history.tree().head(), s3);
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a2"[..]));
    let request = StateRequest {
        caller: Caller::Authority,
        ..to_state(s1)
    };
    assert_eq!(history.restore_state(&request, &events).unwrap().head, s1);
}

// KNSH-086: the current state is a no-op; an unknown state is refused.
#[test]
fn restore_to_current_or_unknown_state() {
    let (fixture, mut history, [_, _, s3]) = three_changes();
    let events = Events::default();
    let same = history.restore_state(&to_state(s3), &events).unwrap();
    assert_eq!((same.from, same.head, same.steps.len()), (s3, s3, 0));
    assert_eq!(fixture.tree.writes(), Vec::new());
    assert_eq!(
        history.restore_state(&to_state(StateId::new(99).unwrap()), &events),
        Err(CheckpointError::History(HistoryError::UnknownState))
    );
}

// KNSH-086, never mixed: a step that fails part-way is rolled back, then the steps already taken are taken back,
// newest first: files and history are as before. A later try succeeds.
#[test]
fn restore_failure_part_way_takes_back_earlier_steps() {
    let (fixture, mut history, [_, _, s3]) = three_changes();
    let events = Events::default();
    // `e.txt` is written only by the last step (undo of change 1).
    fixture
        .tree
        .fail_write_once(live("e.txt"), crate::restore::tests::ENOSPC);
    let before = files_of(&fixture);

    let error = history
        .restore_state(&to_state(history.tree().root()), &events)
        .unwrap_err();

    assert!(matches!(error, CheckpointError::RolledBack(_)), "{error:?}");
    assert_eq!(files_of(&fixture), before);
    assert_eq!(history.tree().head(), s3);
    assert!(
        events.take().is_empty(),
        "nothing is published for a restore that did not happen"
    );
    assert!(fixture.journals().is_empty(), "no journal left");

    history
        .restore_state(&to_state(history.tree().root()), &events)
        .unwrap();
    assert_eq!(fixture.contents("e.txt").as_deref(), Some(&b"e0"[..]));
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a0"[..]));
}

// KNSH-086, FR-CKP-24: a path possibly torn in any change on the way is skipped by every step without `force`, and
// listed; with `force` it is restored and reported forced.
#[test]
fn restore_skips_possibly_torn_paths_without_force() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("app.db"), b"v0");
    let mut history = history(&fixture);
    let mut first = fixture.command(1, &["app.db"], |tree| tree.add_file(live("app.db"), b"v1"));
    first
        .possibly_torn
        .insert(canonical(live("app.db")), TornReason::SqliteJournal);
    history.record(first).unwrap();
    history
        .record(fixture.command(2, &["app.db", "a.txt"], |tree| {
            tree.add_file(live("app.db"), b"v2");
            tree.add_file(live("a.txt"), b"new");
        }))
        .unwrap();
    let events = Events::default();
    let root = history.tree().root();

    let restored = history.restore_state(&to_state(root), &events).unwrap();

    assert_eq!(
        fixture.contents("app.db").as_deref(),
        Some(&b"v2"[..]),
        "skipped by both steps"
    );
    assert_eq!(fixture.contents("a.txt"), None);
    assert_eq!(
        restored.skipped_torn(),
        vec![TornPath {
            path: canonical(live("app.db")),
            reason: TornReason::SqliteJournal,
        }]
    );
    assert!(!restored.forced());

    // Forward again, then back with `force`: the file is restored and reported.
    let end = restored.from;
    history.restore_state(&to_state(end), &events).unwrap();
    let forced = history
        .restore_state(
            &StateRequest {
                force: true,
                ..to_state(root)
            },
            &events,
        )
        .unwrap();
    assert_eq!(fixture.contents("app.db").as_deref(), Some(&b"v0"[..]));
    assert!(forced.forced());
    assert_eq!(forced.forced_torn().len(), 1);
}

// FR-CKP-20, KNSH-086: a conflict refreshes nothing it did not write. A file replaced by another entry with the same
// contents (a new inode: possibly a hard link to a file outside the root, which a write in place would change) still
// conflicts on the next try, and only `force` restores it.
#[test]
fn conflict_on_a_new_inode_with_the_same_contents_is_not_refreshed() {
    let (fixture, mut history, [_, s2, s3]) = three_changes();
    let events = Events::default();
    fixture.tree.remove_all(live("c.txt"));
    fixture.tree.add_file(live("c.txt"), b"c1");
    let conflict = CheckpointError::Conflicts(vec![RestoreConflict {
        path: canonical(live("c.txt")),
        reason: ConflictReason::Changed,
    }]);

    assert_eq!(history.undo(&user(3), &events).unwrap_err(), conflict);
    assert_eq!(
        history.undo(&user(3), &events).unwrap_err(),
        conflict,
        "still a conflict"
    );
    assert_eq!(history.restore_state(&to_state(s2), &events).unwrap_err(), conflict);
    assert_eq!(
        history.restore_state(&to_state(s2), &events).unwrap_err(),
        conflict,
        "still a conflict"
    );
    assert_eq!(history.tree().head(), s3);
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a2"[..]));
}

// KNSH-088: `checkpoint.list` on agent.sock shows an agent only what it could undo: its own session's changes and
// their reverts, never another session's or external edits. The user and the authority see every change.
#[test]
fn agents_see_only_their_own_changes() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"a0");
    let mut history = history(&fixture);
    let own = fixture.command(1, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"a1"));
    let own_id = own.id;
    history.record(own).unwrap();
    let theirs = fixture.change(
        &Taken {
            n: 2,
            attribution: Attribution::Command,
            session: session(2),
            paths: &["b.txt"],
        },
        |tree| tree.add_file(live("b.txt"), b"b1"),
    );
    let theirs_id = theirs.id;
    history.record(theirs).unwrap();
    let external = fixture.change(
        &Taken {
            n: 3,
            attribution: Attribution::External,
            session: session(1),
            paths: &["c.txt"],
        },
        |tree| tree.add_file(live("c.txt"), b"c1"),
    );
    let external_id = external.id;
    history.record(external).unwrap();
    // A revert of the agent's own change is its too.
    history.undo(&user(1), &Events::default()).unwrap();
    let revert = history
        .tree()
        .edges()
        .find(|edge| matches!(edge.kind, EdgeKind::Undo { of } if of == own_id))
        .map(|edge| edge.checkpoint)
        .unwrap();

    let agent = Caller::Agent(session(1));
    assert!(history.visible_to(agent, own_id));
    assert!(history.visible_to(agent, revert));
    assert!(!history.visible_to(agent, theirs_id));
    assert!(!history.visible_to(agent, external_id));
    for id in [own_id, revert, theirs_id, external_id] {
        assert!(history.visible_to(Caller::User, id));
        assert!(history.visible_to(Caller::Authority, id));
    }
}

// KNSH-088: knshd stops attributing changes in exactly the roots a restore may write in.
#[test]
fn roots_of_a_target_and_a_state() {
    let (_fixture, mut history, [s1, _, _]) = three_changes();
    let root = canonical(ROOT);
    assert_eq!(history.target_roots(Target::Record(record(2))), vec![root.clone()]);
    assert_eq!(history.state_roots(s1), vec![root.clone()]);
    assert!(history.target_roots(Target::Record(record(9))).is_empty(), "unknown");
    assert!(history.state_roots(StateId::new(99).unwrap()).is_empty(), "unknown");
    assert!(
        history.state_roots(history.tree().head()).is_empty(),
        "nothing on the way"
    );
    // After an undo, the redo writes the versions it saved: still the same root.
    history.undo(&user(3), &Events::default()).unwrap();
    assert_eq!(history.target_roots(Target::Record(record(3))), vec![root]);
}
