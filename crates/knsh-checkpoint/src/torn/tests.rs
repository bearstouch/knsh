//! Possibly-torn detection (KNSH-085): SQLite journals by name, files held for writing by the line's processes, and
//! how both reach a finished checkpoint.

use std::sync::Arc;

use knsh_core::{RecordId, SessionId, Timestamp, Ulid};
use knsh_platform::testing::{FakeClock, FakeWriteHolders, SeededRandom};
use knsh_platform::{Clock, HeldFile, Operation};

use super::*;
use crate::attribution::Ledger;
use crate::capture::{Captures, Change, Checkpoint, PreImage};
use crate::identity::post_image;
use crate::testing::FakeTree;

const ROOT: &str = "/code/app";
const STORE: &str = "/store";

fn canonical(path: &str) -> CanonicalPath {
    CanonicalPath::new(path).unwrap()
}

fn live(relative: &str) -> CanonicalPath {
    canonical(&format!("{ROOT}/{relative}"))
}

fn session() -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(1))
}

fn record() -> RecordId {
    RecordId::from_ulid(Ulid::from_u128(101))
}

fn key(pid: i32) -> ProcessKey {
    ProcessKey::new(pid, 1000 + u64::try_from(pid).unwrap())
}

fn entry(pid: i32, parent: i32, group: i32) -> ProcessEntry {
    ProcessEntry {
        key: key(pid),
        parent_unique_id: 1000 + u64::try_from(parent).unwrap(),
        group,
    }
}

fn held(path: &str, how: HoldKind) -> HeldFile {
    HeldFile {
        path: PathBuf::from(path),
        how,
    }
}

/// A line's checkpoint, captured the way `knshd` glues the ledger and the captures: `edit` changes the tree, each of
/// `paths` is reported as changed, and `mark` runs under the ledger's lock before the line ends.
fn line(
    tree: &Arc<FakeTree>,
    paths: &[&str],
    edit: impl FnOnce(&FakeTree),
    mark: impl FnOnce(&Captures, crate::EdgeId),
) -> Checkpoint {
    let clock = Arc::new(FakeClock::new(
        Timestamp::from_unix_micros(1_700_000_000_000_000).unwrap(),
    ));
    let captures = Captures::new(
        Arc::clone(tree) as Arc<dyn ShadowFiles>,
        clock as Arc<dyn Clock>,
        Arc::new(SeededRandom::new(7)),
    );
    let mut ledger = Ledger::new();
    let root = canonical(ROOT);
    ledger.watch(&root, session(), true);
    ledger.line_started(record(), session(), std::slice::from_ref(&root));
    let pres: Vec<_> = paths
        .iter()
        .map(|relative| match tree.node(live(relative).as_path()) {
            None => PreImage::NotExisted,
            Some(_) => PreImage::Lost,
        })
        .collect();
    edit(tree);
    let mut finished = Vec::new();
    for (relative, pre) in paths.iter().zip(pres) {
        let path = live(relative);
        let edge = ledger.changed(&root, &path).unwrap();
        let ticket = captures.begin(edge);
        let post = post_image(tree.as_ref(), path.as_path());
        finished.extend(captures.add(ticket, session(), Path::new(STORE), &root, Change { path, pre, post }));
    }
    let edge = ledger.running_edge(record()).unwrap().id;
    mark(&captures, edge);
    ledger.line_ended(record());
    finished.extend(captures.closed(&ledger.take_closed()));
    assert_eq!(finished.len(), 1);
    finished.pop().unwrap()
}

fn tree() -> Arc<FakeTree> {
    let tree = Arc::new(FakeTree::new());
    tree.add_dir(STORE);
    tree.add_dir(ROOT);
    tree
}

// FR-CKP-24: a database written while its write-ahead log sits beside it is possibly torn; one without is not.
#[test]
fn sqlite_with_wal_is_possibly_torn() {
    let tree = tree();
    tree.add_file(live("app.db").as_path(), b"v1");
    tree.add_file(live("app.db-wal").as_path(), b"log");
    tree.add_file(live("plain.db").as_path(), b"v1");
    let checkpoint = line(
        &tree,
        &["app.db", "plain.db"],
        |tree| {
            tree.add_file(live("app.db").as_path(), b"v2");
            tree.add_file(live("plain.db").as_path(), b"v2");
        },
        |_, _| {},
    );
    assert_eq!(
        checkpoint.possibly_torn.get(&live("app.db")),
        Some(&TornReason::SqliteJournal)
    );
    assert!(!checkpoint.possibly_torn.contains_key(&live("plain.db")));
}

// FR-CKP-24: a rollback journal that came and went within the line still marks its database and itself, and so do
// a `-shm` beside it.
#[test]
fn sqlite_journal_marks_its_database() {
    let tree = tree();
    tree.add_file(live("data.sqlite").as_path(), b"v1");
    tree.add_file(live("other.db").as_path(), b"v1");
    tree.add_file(live("other.db-shm").as_path(), b"index");
    let checkpoint = line(
        &tree,
        &["data.sqlite-journal", "data.sqlite", "other.db"],
        |tree| {
            tree.add_file(live("data.sqlite").as_path(), b"v2");
            tree.add_file(live("other.db").as_path(), b"v2");
        },
        |_, _| {},
    );
    assert_eq!(
        checkpoint.possibly_torn.get(&live("data.sqlite")),
        Some(&TornReason::SqliteJournal)
    );
    assert_eq!(
        checkpoint.possibly_torn.get(&live("data.sqlite-journal")),
        Some(&TornReason::SqliteJournal)
    );
    assert_eq!(
        checkpoint.possibly_torn.get(&live("other.db")),
        Some(&TornReason::SqliteJournal)
    );
}

#[test]
fn sidecar_suffix_alone_is_not_a_database() {
    assert_eq!(database_of(&canonical("/code/app/-wal")), None);
    assert_eq!(
        database_of(&canonical("/code/app/db-wal")),
        Some(canonical("/code/app/db"))
    );
}

// FR-CKP-24, decision 17: a file a process of the line still maps writable when it ends is possibly torn, as is one
// open for writing; files outside the line's roots, and processes outside its group and envelopes, are not.
#[test]
fn mapped_file_is_possibly_torn() {
    let holders = FakeWriteHolders::new();
    // 10: the envelope root (the agent), 11 its child; 20: a straggler of the line's group 20; 30: unrelated.
    holders.add(
        entry(10, 1, 10),
        vec![held("/code/app/notes.txt", HoldKind::OpenForWriting)],
    );
    holders.add(
        entry(11, 10, 11),
        vec![held("/code/app/cache.bin", HoldKind::MappedWritable)],
    );
    holders.add(
        entry(20, 1, 20),
        vec![
            held("/code/app/server.log", HoldKind::OpenForWriting),
            held("/tmp/elsewhere", HoldKind::OpenForWriting),
        ],
    );
    holders.add(
        entry(30, 1, 30),
        vec![held("/code/app/unrelated", HoldKind::MappedWritable)],
    );
    let scan = held_in_roots(
        &holders,
        &LineProcesses {
            group: Some(20),
            envelopes: vec![key(10)],
        },
        &[canonical(ROOT)],
    );
    let HeldScan::Held(paths) = scan else {
        panic!("every process could be read");
    };
    assert_eq!(
        paths,
        [
            (live("cache.bin"), TornReason::MappedWritable),
            (live("notes.txt"), TornReason::OpenForWriting),
            (live("server.log"), TornReason::OpenForWriting),
        ]
        .into()
    );
    assert!(!holders.asked().contains(&key(30)));

    // And the line's checkpoint lists them.
    let tree = tree();
    tree.add_file(live("cache.bin").as_path(), b"v1");
    let checkpoint = line(
        &tree,
        &["cache.bin"],
        |tree| tree.add_file(live("cache.bin").as_path(), b"v2"),
        |captures, edge| {
            for (path, reason) in paths {
                captures.mark_possibly_torn(edge, path, reason);
            }
        },
    );
    assert_eq!(
        checkpoint.possibly_torn.get(&live("cache.bin")),
        Some(&TornReason::MappedWritable)
    );
}

// A mapping is the stronger reason when a process holds a file both ways.
#[test]
fn mapping_wins_over_descriptor() {
    let holders = FakeWriteHolders::new();
    holders.add(
        entry(10, 1, 10),
        vec![
            held("/code/app/a", HoldKind::OpenForWriting),
            held("/code/app/a", HoldKind::MappedWritable),
        ],
    );
    let line = LineProcesses {
        group: Some(10),
        envelopes: Vec::new(),
    };
    assert_eq!(
        held_in_roots(&holders, &line, &[canonical(ROOT)]),
        HeldScan::Held([(live("a"), TornReason::MappedWritable)].into())
    );
}

// Fail closed: a process table that cannot be read, or a process that cannot be read, leaves nothing shown untorn;
// a process that exited holds nothing.
#[test]
fn unreadable_processes_leave_the_change_unchecked() {
    let line = LineProcesses {
        group: Some(10),
        envelopes: Vec::new(),
    };
    let roots = [canonical(ROOT)];
    let holders = FakeWriteHolders::new();
    holders.add(entry(10, 1, 10), Vec::new());
    holders.fail_table(Some(PlatformError::Os {
        operation: Operation::ProcessInfo,
        errno: 5,
    }));
    assert_eq!(held_in_roots(&holders, &line, &roots), HeldScan::Unchecked);

    holders.fail_table(None);
    holders.fail_process(
        key(10),
        PlatformError::Os {
            operation: Operation::ProcessInfo,
            errno: 1,
        },
    );
    assert_eq!(held_in_roots(&holders, &line, &roots), HeldScan::Unchecked);

    let exited = FakeWriteHolders::new();
    exited.add(entry(10, 1, 10), Vec::new());
    exited.fail_process(
        key(10),
        PlatformError::Os {
            operation: Operation::ProcessInfo,
            errno: ESRCH,
        },
    );
    assert_eq!(held_in_roots(&exited, &line, &roots), HeldScan::Held(BTreeMap::new()));
}

// Fail closed: an unchecked line marks every file of its change, but not a folder it only created.
#[test]
fn unchecked_line_marks_every_file() {
    let tree = tree();
    tree.add_file(live("a.txt").as_path(), b"v1");
    let checkpoint = line(
        &tree,
        &["a.txt", "new", "new/b.txt"],
        |tree| {
            tree.add_file(live("a.txt").as_path(), b"v2");
            tree.add_dir(live("new").as_path());
            tree.add_file(live("new/b.txt").as_path(), b"b");
        },
        |captures, edge| captures.mark_all_possibly_torn(edge, TornReason::Unchecked),
    );
    assert_eq!(
        checkpoint.possibly_torn,
        [
            (live("a.txt"), TornReason::Unchecked),
            (live("new/b.txt"), TornReason::Unchecked),
        ]
        .into()
    );
}

// A process whose pid was reused is not taken for an envelope root: only the exact unique id is followed.
#[test]
fn reused_pid_is_not_an_envelope() {
    let holders = FakeWriteHolders::new();
    holders.add(
        ProcessEntry {
            key: ProcessKey::new(10, 9999),
            parent_unique_id: 1001,
            group: 10,
        },
        vec![held("/code/app/x", HoldKind::OpenForWriting)],
    );
    let line = LineProcesses {
        group: None,
        envelopes: vec![key(10)],
    };
    assert_eq!(
        held_in_roots(&holders, &line, &[canonical(ROOT)]),
        HeldScan::Held(BTreeMap::new())
    );
    assert_eq!(holders.asked(), Vec::<ProcessKey>::new());
}

// Past the bound, the change is unchecked rather than cut short.
#[test]
fn too_many_held_files_leave_the_change_unchecked() {
    let holders = FakeWriteHolders::new();
    let files = (0..=MAX_TORN_PATHS)
        .map(|n| held(&format!("/code/app/f{n}"), HoldKind::OpenForWriting))
        .collect();
    holders.add(entry(10, 1, 10), files);
    let line = LineProcesses {
        group: Some(10),
        envelopes: Vec::new(),
    };
    assert_eq!(held_in_roots(&holders, &line, &[canonical(ROOT)]), HeldScan::Unchecked);
}
