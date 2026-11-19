//! Undo and redo through the history (KNSH-084), over an in-memory tree.

use std::path::Path;
use std::sync::Mutex;

use knsh_core::{ConflictReason, RestoreConflict, Timestamp};
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
