//! `checkpoint.diff` over an in-memory tree (KNSH-086).

use std::path::PathBuf;
use std::sync::Arc;

use knsh_core::{Attribution, EventData, SessionId, Timestamp};
use knsh_platform::testing::{FakeClock, SeededRandom};

use super::*;
use crate::restore::tests::{Fixture, Taken, canonical, live, record, session};
use crate::testing::FakeNode;
use crate::undo::{Request, RestoreEvents, StateRequest, Target};

struct NoEvents;

impl RestoreEvents for NoEvents {
    fn restored(&self, _: SessionId, _: EventData) {}
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

fn request(target: DiffTarget) -> DiffRequest {
    DiffRequest {
        target,
        caller: Caller::User,
        after: None,
        limit: MAX_DIFF_PAGE,
    }
}

fn text(file: &FileDiff) -> String {
    match &file.text {
        TextDiff::Unified(bytes) => String::from_utf8(bytes.clone()).unwrap(),
        TextDiff::Omitted(reason) => format!("<{}>", reason.as_str()),
    }
}

/// One line that modifies `a.txt`, creates `b.txt` and deletes `c.txt`.
fn one_change() -> (Fixture, History) {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"one\ntwo\n");
    fixture.tree.add_file(live("c.txt"), b"gone\n");
    let mut history = history(&fixture);
    history
        .record(fixture.command(1, &["a.txt", "b.txt", "c.txt"], |tree| {
            tree.add_file(live("a.txt"), b"one\n2\n");
            tree.add_file(live("b.txt"), b"new\n");
            tree.remove_all(live("c.txt"));
        }))
        .unwrap();
    (fixture, history)
}

// KNSH-086: a line's diff lists each path it created, modified or deleted, with the kinds before and after and a
// unified diff of each text file.
#[test]
fn diff_lists_created_modified_deleted_paths() {
    let (_fixture, history) = one_change();

    let page = history.diff(&request(DiffTarget::Record(record(1)))).unwrap();

    assert!(!page.more);
    assert_eq!(page.diff.from, history.tree().root());
    assert_eq!(page.diff.to, history.tree().head());
    let listed: Vec<(PathBuf, FileChange, EntryKind, EntryKind)> = page
        .diff
        .files
        .iter()
        .map(|file| (file.path.as_path().to_path_buf(), file.change, file.before, file.after))
        .collect();
    assert_eq!(
        listed,
        vec![
            (live("a.txt"), FileChange::Modified, EntryKind::File, EntryKind::File),
            (live("b.txt"), FileChange::Created, EntryKind::Absent, EntryKind::File),
            (live("c.txt"), FileChange::Deleted, EntryKind::File, EntryKind::Absent),
        ]
    );
    assert_eq!(
        text(&page.diff.files[0]),
        "--- /code/app/a.txt\n+++ /code/app/a.txt\n@@ -1,2 +1,2 @@\n one\n-two\n+2\n"
    );
    assert_eq!(
        text(&page.diff.files[1]),
        "--- /dev/null\n+++ /code/app/b.txt\n@@ -0,0 +1 @@\n+new\n"
    );
    assert_eq!(
        text(&page.diff.files[2]),
        "--- /code/app/c.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n"
    );
}

// KNSH-086: a line's diff is the same after it was undone: its after-versions come from the versions its undo saved.
// A state's diff is what restoring that state would change.
#[test]
fn diff_of_undone_change_and_of_a_state() {
    let (fixture, mut history) = one_change();
    let root = history.tree().root();
    let expected = history.diff(&request(DiffTarget::Record(record(1)))).unwrap();
    history
        .record(fixture.command(2, &["d.txt"], |tree| tree.add_file(live("d.txt"), b"d\n")))
        .unwrap();

    let state = history.diff(&request(DiffTarget::State(root))).unwrap();
    let paths: Vec<PathBuf> = state
        .diff
        .files
        .iter()
        .map(|file| file.path.as_path().to_path_buf())
        .collect();
    assert_eq!(paths, ["a.txt", "b.txt", "c.txt", "d.txt"].map(live).to_vec());
    assert_eq!((state.diff.from, state.diff.to), (root, history.tree().head()));

    history
        .restore_state(
            &StateRequest {
                state: root,
                caller: Caller::User,
                force: false,
            },
            &NoEvents,
        )
        .unwrap();
    assert_eq!(history.diff(&request(DiffTarget::Record(record(1)))).unwrap(), expected);
    assert!(
        history
            .diff(&request(DiffTarget::State(root)))
            .unwrap()
            .diff
            .files
            .is_empty(),
        "nothing differs from the state the history is in"
    );
}

// KNSH-086: a change and its revert leave the path as it was: a diff across both does not list it.
#[test]
fn reverted_path_is_not_listed() {
    let (fixture, mut history) = one_change();
    let root = history.tree().root();
    history
        .record(fixture.command(2, &["d.txt"], |tree| tree.add_file(live("d.txt"), b"d\n")))
        .unwrap();
    // Undoing the older change reverts it on top of the later one (FR-CKP-30).
    history
        .undo(
            &Request {
                target: Target::Record(record(1)),
                caller: Caller::User,
                force: false,
            },
            &NoEvents,
        )
        .unwrap();
    let page = history.diff(&request(DiffTarget::State(root))).unwrap();
    let paths: Vec<PathBuf> = page
        .diff
        .files
        .iter()
        .map(|file| file.path.as_path().to_path_buf())
        .collect();
    assert_eq!(paths, vec![live("d.txt")]);
}

// KNSH-086: binary files are reported as changed without a text diff; so are files too large to diff, and files
// named like secrets (whose contents are never read).
#[test]
fn binary_large_and_sensitive_files_have_no_text_diff() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("logo.png"), b"\x89PNG\0\0one");
    fixture.tree.add_file(live(".env"), b"TOKEN=old\n");
    let large = vec![b'x'; usize::try_from(MAX_DIFF_FILE).unwrap() + 1];
    let mut history = history(&fixture);
    history
        .record(fixture.command(1, &["logo.png", ".env", "big.txt"], |tree| {
            tree.add_file(live("logo.png"), b"\x89PNG\0\0two");
            tree.add_file(live(".env"), b"TOKEN=new\n");
            tree.add_file(live("big.txt"), &large);
        }))
        .unwrap();

    let page = history.diff(&request(DiffTarget::Record(record(1)))).unwrap();

    let reasons: Vec<(PathBuf, FileChange, TextDiff)> = page
        .diff
        .files
        .iter()
        .map(|file| (file.path.as_path().to_path_buf(), file.change, file.text.clone()))
        .collect();
    assert_eq!(
        reasons,
        vec![
            (
                live(".env"),
                FileChange::Modified,
                TextDiff::Omitted(NoTextDiff::Sensitive)
            ),
            (
                live("big.txt"),
                FileChange::Created,
                TextDiff::Omitted(NoTextDiff::TooLarge)
            ),
            (
                live("logo.png"),
                FileChange::Modified,
                TextDiff::Omitted(NoTextDiff::Binary)
            ),
        ]
    );
}

// Security: `knshd` is not sandboxed. A live file an agent swapped for a symlink to a secret outside the root is
// never read: it is listed as a symlink, with no contents.
#[test]
fn live_file_swapped_for_a_symlink_is_not_followed() {
    let (fixture, history) = one_change();
    fixture.tree.add_file("/Users/me/.ssh/key", b"SECRET\n");
    fixture.tree.remove_all(live("a.txt"));
    fixture
        .tree
        .add(live("a.txt"), FakeNode::Symlink(PathBuf::from("/Users/me/.ssh/key")));

    let page = history.diff(&request(DiffTarget::Record(record(1)))).unwrap();

    let file = &page.diff.files[0];
    assert_eq!(file.path, canonical(live("a.txt")));
    assert_eq!((file.before, file.after), (EntryKind::File, EntryKind::Symlink));
    assert_eq!(file.text, TextDiff::Omitted(NoTextDiff::NotAFile));
    for file in &page.diff.files {
        assert!(!text(file).contains("SECRET"));
    }
}

// KNSH-086: an agent sees only diffs made of its own session's changes.
#[test]
fn agent_sees_only_its_own_changes() {
    let (fixture, mut history) = one_change();
    let root = history.tree().root();
    history
        .record(fixture.change(
            &Taken {
                n: 2,
                attribution: Attribution::Command,
                session: session(2),
                paths: &["d.txt"],
            },
            |tree| tree.add_file(live("d.txt"), b"theirs\n"),
        ))
        .unwrap();
    let agent = |target| DiffRequest {
        caller: Caller::Agent(session(1)),
        ..request(target)
    };
    assert!(history.diff(&agent(DiffTarget::Record(record(1)))).is_ok());
    assert_eq!(
        history.diff(&agent(DiffTarget::Record(record(2)))),
        Err(CheckpointError::NotOwnChange)
    );
    assert_eq!(
        history.diff(&agent(DiffTarget::State(root))),
        Err(CheckpointError::NotOwnChange),
        "the way back to the root crosses another session's change"
    );
}

// KNSH-086: unknown records and states are refused.
#[test]
fn unknown_record_or_state_is_refused() {
    let (_fixture, history) = one_change();
    assert_eq!(
        history.diff(&request(DiffTarget::Record(record(9)))),
        Err(CheckpointError::History(HistoryError::UnknownChange))
    );
    assert_eq!(
        history.diff(&request(DiffTarget::State(StateId::new(99).unwrap()))),
        Err(CheckpointError::History(HistoryError::UnknownState))
    );
}

// KNSH-086: pages: at most `limit` paths, then the rest after the last path returned.
#[test]
fn diff_pages_by_path() {
    let (_fixture, history) = one_change();
    let first = history
        .diff(&DiffRequest {
            limit: 2,
            ..request(DiffTarget::Record(record(1)))
        })
        .unwrap();
    assert_eq!(first.diff.files.len(), 2);
    assert!(first.more);
    let second = history
        .diff(&DiffRequest {
            limit: 2,
            after: Some(first.diff.files[1].path.clone()),
            ..request(DiffTarget::Record(record(1)))
        })
        .unwrap();
    assert_eq!(second.diff.files.len(), 1);
    assert_eq!(second.diff.files[0].path, canonical(live("c.txt")));
    assert!(!second.more);
}
