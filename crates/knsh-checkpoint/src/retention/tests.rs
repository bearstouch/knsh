//! Retention, sensitive pre-images and forget (KNSH-087), over an in-memory tree.

use std::path::Path;
use std::sync::Arc;

use knsh_core::{Attribution, ConflictReason, DiffTarget, HistoryError, HistoryTree, RestoreConflict, Ulid};
use knsh_platform::Clock;
use knsh_platform::testing::{FakeClock, SeededRandom};

use super::*;
use crate::capture::{CHECKPOINTS_DIR, CapturedPath};
use crate::diff::DiffRequest;
use crate::identity::post_image;
use crate::restore::tests::{Fixture, ROOT, STORE, Taken, canonical, live, record, session};
use crate::shadow::ShadowFiles;
use crate::testing::FakeNode;
use crate::undo::{Caller, Request, RestoreEvents, StateRequest, Target};

/// "Now" in the tests, in Unix milliseconds (November 2025).
const NOW: u64 = 1_763_000_000_000;
const HOUR: u64 = 60 * 60 * 1000;
const DAY: u64 = 24 * HOUR;

/// Publishes nothing: these tests look at what is restored, not at events.
struct NoEvents;

impl RestoreEvents for NoEvents {
    fn restored(&self, _: SessionId, _: knsh_core::EventData) {}
}

/// A history whose clock is at [`NOW`], and the clock, to move it.
fn setup(fixture: &Fixture) -> (History, Arc<FakeClock>) {
    let clock = Arc::new(FakeClock::new(Timestamp::from_unix_micros(NOW * 1000).unwrap()));
    let history = History::new(
        Arc::clone(&fixture.tree) as Arc<dyn ShadowFiles>,
        Arc::clone(&clock) as Arc<dyn Clock>,
        Arc::new(SeededRandom::new(7)),
    );
    (history, clock)
}

/// Line `n`'s change, taken at `at` (Unix milliseconds), writing `new` into each of `paths` (which exist before).
fn change_at(fixture: &Fixture, history: &mut History, n: u128, at: u64, paths: &[&str]) -> CheckpointId {
    for path in paths {
        if fixture.tree.node(live(path)).is_none() {
            fixture.tree.add_file(live(path), format!("old {path}").as_bytes());
        }
    }
    fixture.at.set(at);
    let checkpoint = fixture.command(n, paths, |tree| {
        for path in paths {
            tree.add_file(live(path), format!("new {path} {n}").as_bytes());
        }
    });
    let id = checkpoint.id;
    history.record(checkpoint).unwrap();
    id
}

/// The kept copies of checkpoint `id` still on disk.
fn copies(fixture: &Fixture, id: CheckpointId) -> Vec<PathBuf> {
    fixture
        .tree
        .paths_below(Path::new(STORE).join(CHECKPOINTS_DIR).join(id.to_string()))
        .into_iter()
        .filter(|path| !path.as_os_str().is_empty())
        .collect()
}

fn undo(n: u128) -> Request {
    Request {
        target: Target::Record(record(n)),
        caller: Caller::User,
        force: false,
    }
}

fn expired() -> CheckpointError {
    CheckpointError::History(HistoryError::Expired)
}

// FR-CKP-32: 200 changes per root are kept; the 201st removes the oldest, whose undo then says it expired.
#[test]
fn retention_removes_oldest_after_200_checkpoints_per_root() {
    let fixture = Fixture::new();
    let (mut history, _) = setup(&fixture);
    let mut ids = Vec::new();
    for n in 1..=200 {
        ids.push(change_at(&fixture, &mut history, n, NOW, &[&format!("f{n}.txt")]));
    }
    assert_eq!(
        history.retain(&Retention::default()).unwrap().removed,
        Vec::<CheckpointId>::new(),
        "200 is within the limit"
    );

    ids.push(change_at(&fixture, &mut history, 201, NOW, &["f201.txt"]));
    let swept = history.retain(&Retention::default()).unwrap();

    assert_eq!(swept.removed, vec![ids[0]]);
    assert!(copies(&fixture, ids[0]).is_empty(), "its pre-images are deleted");
    assert!(history.checkpoint(ids[0]).is_none());
    assert_eq!(history.undo(&undo(1), &NoEvents), Err(expired()));
    assert!(!copies(&fixture, ids[1]).is_empty(), "the next oldest stays");
    // The latest change still undoes.
    history.undo(&undo(201), &NoEvents).unwrap();
    assert_eq!(fixture.contents("f201.txt").as_deref(), Some(&b"old f201.txt"[..]));
}

// FR-CKP-32: the count is per root; changes in another root do not push a root's changes out.
#[test]
fn retention_counts_each_root_on_its_own() {
    let fixture = Fixture::new();
    let (mut history, _) = setup(&fixture);
    let limits = Retention {
        per_root: 2,
        ..Retention::default()
    };
    let first = change_at(&fixture, &mut history, 1, NOW, &["a.txt"]);
    // Two changes in another root (only its path list matters for counting).
    for n in 2..=3 {
        fixture.at.set(NOW);
        let mut other = fixture.command(n, &[], |_| {});
        other.paths = [(canonical("/code/other"), BTreeMap::new())].into();
        other.stores = [(canonical("/code/other"), PathBuf::from(STORE))].into();
        history.record(other).unwrap();
    }
    assert_eq!(history.retain(&limits).unwrap().removed, Vec::<CheckpointId>::new());
    change_at(&fixture, &mut history, 4, NOW, &["b.txt"]);
    change_at(&fixture, &mut history, 5, NOW, &["c.txt"]);
    assert_eq!(history.retain(&limits).unwrap().removed, vec![first]);
}

// FR-CKP-32: a change 7 days old is removed; a younger one stays, and the next sweep is due when it turns 7 days.
#[test]
fn retention_removes_checkpoints_older_than_7_days() {
    let fixture = Fixture::new();
    let (mut history, clock) = setup(&fixture);
    let old = change_at(&fixture, &mut history, 1, NOW - 7 * DAY, &["a.txt"]);
    let young = change_at(&fixture, &mut history, 2, NOW - 7 * DAY + HOUR, &["b.txt"]);

    let swept = history.retain(&Retention::default()).unwrap();

    assert_eq!(swept.removed, vec![old]);
    assert_eq!(copies(&fixture, old), Vec::<PathBuf>::new());
    assert_eq!(history.undo(&undo(1), &NoEvents), Err(expired()));
    assert_eq!(
        swept.next_due,
        Some(Timestamp::from_unix_micros((NOW + HOUR) * 1000).unwrap())
    );
    assert!(history.checkpoint(young).is_some());

    clock.advance(Duration::from_millis(HOUR));
    assert_eq!(history.retain(&Retention::default()).unwrap().removed, vec![young]);
    assert!(history.tree().is_empty(), "every expired edge at the root is gone");
}

// FR-CKP-32: the kept pre-images of one volume are bounded (5 GB); past it the oldest changes there go first, and
// another volume's changes are not touched. Bytes are scaled down: the fake tree holds contents in memory.
#[test]
fn retention_enforces_5_gb_per_volume() {
    assert_eq!(RETAINED_BYTES_PER_VOLUME, 5 * 1024 * 1024 * 1024);
    assert_eq!(Retention::default().bytes_per_volume, RETAINED_BYTES_PER_VOLUME);
    let fixture = Fixture::new();
    let (mut history, _) = setup(&fixture);
    // Each change keeps one pre-image of 1,000 bytes.
    let big = vec![b'x'; 1000];
    let mut ids = Vec::new();
    for n in 1..=3 {
        let name = format!("f{n}.bin");
        fixture.tree.add_file(live(&name), &big);
        ids.push(change_at(&fixture, &mut history, n, NOW, &[&name]));
    }
    // A change on another volume: its own store, older than all of them.
    let other_store = Path::new("/Volumes/data/.knsh-checkpoints");
    let other_root = canonical("/Volumes/data/app");
    fixture.tree.add_dir(other_root.as_path());
    fixture.tree.add_file(other_root.as_path().join("g.bin"), &big);
    let other_id = CheckpointId::from_ulid(Ulid::from_u128((u128::from(NOW - 1) << 80) | 0x4d));
    let folder = other_store.join(CHECKPOINTS_DIR).join(other_id.to_string());
    fixture.tree.add_dir(&folder);
    fixture
        .tree
        .clone_file(&other_root.as_path().join("g.bin"), &folder.join("0"))
        .unwrap();
    let g = canonical(other_root.as_path().join("g.bin"));
    let other = Checkpoint {
        id: other_id,
        paths: [(
            other_root.clone(),
            [(
                g.clone(),
                CapturedPath {
                    pre: StoredPreImage::Kept(folder.join("0")),
                    post: post_image(fixture.tree.as_ref(), g.as_path()),
                },
            )]
            .into(),
        )]
        .into(),
        stores: [(other_root, other_store.to_path_buf())].into(),
        records: [record(77)].into(),
        ..fixture.command(77, &[], |_| {})
    };
    // Recorded first, so it is the oldest change of all.
    let mut first = History::new(
        Arc::clone(&fixture.tree) as Arc<dyn ShadowFiles>,
        Arc::clone(&history.clock),
        Arc::new(SeededRandom::new(9)),
    );
    first.record(other).unwrap();
    for id in &ids {
        first.record(history.checkpoint(*id).unwrap().clone()).unwrap();
    }
    let mut history = first;
    let limits = Retention {
        bytes_per_volume: 2000,
        ..Retention::default()
    };

    let swept = history.retain(&limits).unwrap();

    // 3,000 bytes in the home store: the oldest change there goes; the other volume holds only 1,000.
    assert_eq!(swept.removed, vec![ids[0]]);
    assert!(
        history.checkpoint(other_id).is_some(),
        "another volume's change is not removed"
    );
    assert!(history.checkpoint(ids[1]).is_some() && history.checkpoint(ids[2]).is_some());
    assert_eq!(history.retain(&limits).unwrap().removed, Vec::<CheckpointId>::new());
}

// FR-CKP-33, NFR-PRIV-07: a sensitive file's pre-image is deleted once 24 hours old; the change's other pre-images stay,
// and its undo reports the lost one rather than writing anything.
#[test]
fn sensitive_pre_image_deleted_after_24_hours() {
    let fixture = Fixture::new();
    let (mut history, clock) = setup(&fixture);
    let names = [".env", ".env.local", "server.pem", "tls.key", "id_ed25519", "a.txt"];
    let id = change_at(&fixture, &mut history, 1, NOW, &names);
    let kept = |history: &History, name: &str| {
        let checkpoint = history.checkpoint(id).unwrap();
        match &checkpoint.paths[&canonical(ROOT)][&canonical(live(name))].pre {
            StoredPreImage::Kept(copy) => matches!(fixture.tree.node(copy), Some(FakeNode::File(_))),
            StoredPreImage::NotExisted | StoredPreImage::Folder | StoredPreImage::Lost => false,
        }
    };

    clock.advance(Duration::from_millis(DAY - 1));
    let swept = history.retain(&Retention::default()).unwrap();
    assert_eq!(swept.sensitive, 0, "not 24 hours yet");
    assert!(names.iter().all(|name| kept(&history, name)));
    assert_eq!(
        swept.next_due,
        Some(Timestamp::from_unix_micros((NOW + DAY) * 1000).unwrap()),
        "the next sweep is due exactly when the copies turn 24 hours old"
    );

    clock.advance(Duration::from_millis(1));
    let swept = history.retain(&Retention::default()).unwrap();

    assert_eq!(swept.sensitive, 5);
    assert!(swept.removed.is_empty(), "the checkpoint itself stays");
    for name in &names[..5] {
        assert!(!kept(&history, name), "{name}");
    }
    assert!(kept(&history, "a.txt"));
    assert_eq!(copies(&fixture, id).len(), 1);
    assert_eq!(
        swept.next_due,
        Some(Timestamp::from_unix_micros((NOW + 7 * DAY) * 1000).unwrap())
    );
    let error = history.undo(&undo(1), &NoEvents).unwrap_err();
    let CheckpointError::Conflicts(conflicts) = error else {
        panic!("{error:?}");
    };
    assert!(conflicts.contains(&RestoreConflict {
        path: canonical(live(".env")),
        reason: ConflictReason::PreImageLost,
    }));
    assert_eq!(
        fixture.contents("a.txt").as_deref(),
        Some(&b"new a.txt 1"[..]),
        "nothing was restored"
    );
}

// FR-CKP-33: versions an undo saved are pre-images too: a sensitive one goes 24 hours after the undo.
#[test]
fn sensitive_saved_versions_expire_from_their_own_time() {
    let fixture = Fixture::new();
    let (mut history, clock) = setup(&fixture);
    change_at(&fixture, &mut history, 1, NOW - 2 * DAY, &[".env"]);
    assert_eq!(history.retain(&Retention::default()).unwrap().sensitive, 1);
    // The change's own copy is gone, so add a new change to undo now.
    change_at(&fixture, &mut history, 2, NOW, &[".env"]);
    history.undo(&undo(2), &NoEvents).unwrap();
    let saved = history.tree().edge_for_record(record(2)).unwrap().saved.unwrap();
    assert!(history.checkpoint(saved).is_some());

    clock.advance(Duration::from_millis(DAY));
    let swept = history.retain(&Retention::default()).unwrap();
    assert_eq!(swept.sensitive, 2, "the change's copy and the saved version");
    let saved = history.checkpoint(saved).unwrap();
    assert!(
        saved
            .paths
            .values()
            .flat_map(BTreeMap::values)
            .all(|captured| captured.pre == StoredPreImage::Lost)
    );
}

// FR-CKP-34: forget removes the session's checkpoints at once, whatever their age, and leaves other sessions' alone.
#[test]
fn forget_with_checkpoints_removes_immediately() {
    let fixture = Fixture::new();
    let (mut history, _) = setup(&fixture);
    let first = change_at(&fixture, &mut history, 1, NOW, &["secret-plan.txt"]);
    let second = change_at(&fixture, &mut history, 2, NOW, &["b.txt"]);
    fixture.tree.add_file(live("c.txt"), b"old c.txt");
    fixture.at.set(NOW);
    let other = fixture.change(
        &Taken {
            n: 3,
            attribution: Attribution::Command,
            session: session(2),
            paths: &["c.txt"],
        },
        |tree| tree.add_file(live("c.txt"), b"new c.txt"),
    );
    let other_id = other.id;
    history.record(other).unwrap();

    assert_eq!(Forget::new(None, None), None, "a selector always selects something");
    let swept = history.forget(&Forget::new(Some(session(1)), None).unwrap());

    assert_eq!(swept.removed, vec![first, second]);
    assert_eq!(copies(&fixture, first), Vec::<PathBuf>::new());
    assert_eq!(copies(&fixture, second), Vec::<PathBuf>::new());
    assert_eq!(history.undo(&undo(1), &NoEvents), Err(expired()));
    assert_eq!(history.undo(&undo(2), &NoEvents), Err(expired()));
    let stored = history.tree().encode().unwrap();
    assert!(
        !stored.contains("secret-plan.txt") && !stored.contains("b.txt"),
        "{stored}"
    );
    // The other session's change is untouched.
    assert_ne!(copies(&fixture, other_id), Vec::<PathBuf>::new());
    history.undo(&undo(3), &NoEvents).unwrap();
    assert_eq!(fixture.contents("c.txt").as_deref(), Some(&b"old c.txt"[..]));

    // `--since`: changes made at or after the instant.
    let fixture = Fixture::new();
    let (mut history, _) = setup(&fixture);
    let before = change_at(&fixture, &mut history, 1, NOW - DAY, &["a.txt"]);
    let after = change_at(&fixture, &mut history, 2, NOW, &["b.txt"]);
    let since = Timestamp::from_unix_micros(NOW * 1000).unwrap();
    let swept = history.forget(&Forget::new(None, Some(since)).unwrap());
    assert_eq!(swept.removed, vec![after]);
    assert!(history.checkpoint(before).is_some());
    // Both: none of session 2's changes are this old.
    let swept = history.forget(&Forget::new(Some(session(2)), Some(since)).unwrap());
    assert_eq!(swept.removed, Vec::<CheckpointId>::new());
}

// KNSH-084 "Who" with KNSH-087: while an expired change is still in the tree its session is known, so another
// session's agent is refused as not its own and learns nothing about it, not even that it expired.
#[test]
fn agent_of_another_session_is_refused_before_expiry_is_reported() {
    let fixture = Fixture::new();
    let (mut history, _) = setup(&fixture);
    change_at(&fixture, &mut history, 1, NOW - DAY, &["a.txt"]);
    let after = change_at(&fixture, &mut history, 2, NOW, &["b.txt"]);
    let since = Timestamp::from_unix_micros(NOW * 1000).unwrap();
    assert_eq!(
        history.forget(&Forget::new(None, Some(since)).unwrap()).removed,
        vec![after]
    );
    assert!(
        history.tree().edge(after).is_some(),
        "kept as expired on the head's path"
    );

    let by = |session| Request {
        target: Target::Checkpoint(after),
        caller: Caller::Agent(session),
        force: false,
    };
    assert_eq!(
        history.undo(&by(session(9)), &NoEvents),
        Err(CheckpointError::NotOwnChange)
    );
    assert_eq!(
        history.redo(&by(session(9)), &NoEvents),
        Err(CheckpointError::NotOwnChange)
    );
    assert_eq!(history.undo(&by(session(1)), &NoEvents), Err(expired()));
    assert_eq!(history.undo(&undo(2), &NoEvents), Err(expired()));
    // The same for a diff of the line's change.
    let diff = |caller| DiffRequest {
        target: DiffTarget::Record(record(2)),
        caller,
        after: None,
        limit: 10,
    };
    assert_eq!(
        history.diff(&diff(Caller::Agent(session(9)))).unwrap_err(),
        CheckpointError::NotOwnChange
    );
    assert_eq!(history.diff(&diff(Caller::Agent(session(1)))).unwrap_err(), expired());
    assert_eq!(history.diff(&diff(Caller::User)).unwrap_err(), expired());
}

// FR-CKP-34: `--since` also selects a change made before the instant but stepped back over after it, whose saved
// versions hold the files as they were after the instant.
#[test]
fn forget_since_selects_a_change_stepped_back_over_after_the_instant() {
    let fixture = Fixture::new();
    let (mut history, clock) = setup(&fixture);
    let before = change_at(&fixture, &mut history, 1, NOW - 2 * DAY, &["a.txt"]);
    let older = change_at(&fixture, &mut history, 2, NOW - 2 * DAY, &["b.txt"]);
    clock.advance(Duration::from_millis(DAY));
    history.undo(&undo(2), &NoEvents).unwrap();
    let saved = history.tree().edge(older).unwrap().saved.unwrap();
    assert!(history.checkpoint(saved).is_some());

    let since = Timestamp::from_unix_micros((NOW + DAY / 2) * 1000).unwrap();
    let swept = history.forget(&Forget::new(None, Some(since)).unwrap());

    assert!(
        swept.removed.contains(&older) && swept.removed.contains(&saved),
        "{:?}",
        swept.removed
    );
    assert!(history.checkpoint(saved).is_none());
    assert!(history.checkpoint(before).is_some(), "never stepped back over");
    assert_eq!(history.redo(&undo(2), &NoEvents), Err(expired()));
}

// KNSH-087: undo, redo, restore and diff of a change whose checkpoint was removed report it expired, never crash.
#[test]
fn undo_of_expired_edge_reports_expired() {
    let fixture = Fixture::new();
    let (mut history, _) = setup(&fixture);
    let first = change_at(&fixture, &mut history, 1, NOW, &["a.txt"]);
    let second = change_at(&fixture, &mut history, 2, NOW, &["b.txt"]);
    let start = history.tree().root();
    // Undo the latest, so it can be redone.
    history.undo(&undo(2), &NoEvents).unwrap();
    let limits = Retention {
        per_root: 1,
        ..Retention::default()
    };

    // Two changes in the root, limit 1: the oldest goes, the undone one stays redoable.
    assert_eq!(history.retain(&limits).unwrap().removed, vec![first]);

    assert_eq!(history.undo(&undo(1), &NoEvents), Err(expired()));
    let by_checkpoint = Request {
        target: Target::Checkpoint(first),
        ..undo(1)
    };
    assert_eq!(history.undo(&by_checkpoint, &NoEvents), Err(expired()));
    assert_eq!(history.redo(&undo(1), &NoEvents), Err(expired()));
    let agent = Request {
        caller: Caller::Agent(session(1)),
        ..undo(1)
    };
    assert_eq!(history.undo(&agent, &NoEvents), Err(expired()));
    let diff = DiffRequest {
        target: DiffTarget::Record(record(1)),
        caller: Caller::User,
        after: None,
        limit: 10,
    };
    assert_eq!(history.diff(&diff).unwrap_err(), expired());
    // The state before it is gone with it.
    let restore = StateRequest {
        state: start,
        caller: Caller::User,
        force: false,
    };
    assert_eq!(
        history.restore_state(&restore, &NoEvents).unwrap_err(),
        CheckpointError::History(HistoryError::UnknownState)
    );
    assert_eq!(
        fixture.contents("a.txt").as_deref(),
        Some(&b"new a.txt 1"[..]),
        "nothing was written"
    );

    history.redo(&undo(2), &NoEvents).unwrap();
    assert_eq!(fixture.contents("b.txt").as_deref(), Some(&b"new b.txt 2"[..]));

    // Forgetting the redone change: its undo and redo are expired too, and its saved versions are gone.
    history.undo(&undo(2), &NoEvents).unwrap();
    let saved = history.tree().edge(second).unwrap().saved.unwrap();
    let swept = history.forget(&Forget::new(Some(session(1)), None).unwrap());
    assert!(swept.removed.contains(&second) && swept.removed.contains(&saved));
    assert_eq!(copies(&fixture, saved), Vec::<PathBuf>::new());
    assert_eq!(history.redo(&undo(2), &NoEvents), Err(expired()));
    assert_eq!(history.undo(&undo(2), &NoEvents), Err(expired()));
}

// A clock that cannot be read removes nothing.
#[test]
fn unreadable_clock_removes_nothing() {
    let fixture = Fixture::new();
    let (mut history, clock) = setup(&fixture);
    let id = change_at(&fixture, &mut history, 1, NOW - 30 * DAY, &[".env"]);
    clock.set_wall(u64::MAX);
    assert!(matches!(
        history.retain(&Retention::default()),
        Err(CheckpointError::Platform(_))
    ));
    assert_eq!(copies(&fixture, id).len(), 1);
}

// FR-CKP-34: a revert whose reverted change retention already removed from the tree still lists that change's paths;
// forget scrubs it, since the change's sessions are no longer known (privacy first, fail closed for FR-CKP-30).
#[test]
fn forget_scrubs_a_revert_whose_change_is_gone() {
    let fixture = Fixture::new();
    let (mut history, _) = setup(&fixture);
    change_at(&fixture, &mut history, 1, NOW, &["secret-plan.txt"]);
    // Another session's change, which forget keeps.
    fixture.tree.add_file(live("b.txt"), b"old b.txt");
    fixture.at.set(NOW);
    let other = fixture.change(
        &Taken {
            n: 2,
            attribution: Attribution::Command,
            session: session(2),
            paths: &["b.txt"],
        },
        |tree| tree.add_file(live("b.txt"), b"new b.txt"),
    );
    history.record(other).unwrap();
    // Reverting the older change adds an `undo` edge listing its paths.
    history.undo(&undo(1), &NoEvents).unwrap();
    let limits = Retention {
        per_root: 2,
        ..Retention::default()
    };
    // Three changes in the root: the oldest goes, with its revert; it leaves the root, the revert stays expired.
    let swept = history.retain(&limits).unwrap();
    assert_eq!(swept.removed.len(), 2);
    assert!(history.tree().encode().unwrap().contains("secret-plan.txt"));

    history.forget(&Forget::new(Some(session(1)), None).unwrap());

    let stored = history.tree().encode().unwrap();
    assert!(!stored.contains("secret-plan.txt"), "{stored}");
    assert!(HistoryTree::decode(stored.as_bytes()).is_ok());
}
