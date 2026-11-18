//! The attribution ledger (KNSH-081): lines, agent edits, concurrent sets and external changes.

use knsh_core::Ulid;

use super::*;

const APP: &str = "/Users/u/app";
const LIB: &str = "/Users/u/lib";

fn root(path: &str) -> CanonicalPath {
    CanonicalPath::new(path).unwrap()
}

fn path(root_path: &str, name: &str) -> CanonicalPath {
    CanonicalPath::new(format!("{root_path}/{name}")).unwrap()
}

fn record(n: u128) -> RecordId {
    RecordId::from_ulid(Ulid::from_u128(n))
}

fn session(n: u128) -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(n))
}

/// A ledger where session 1, an envelope, watches `APP` and `LIB`.
fn watched() -> Ledger {
    let mut ledger = Ledger::new();
    ledger.watch(&root(APP), session(1), true);
    ledger.watch(&root(LIB), session(1), true);
    ledger
}

fn paths_of(edge: &Edge, root_path: &str) -> Vec<CanonicalPath> {
    edge.paths
        .get(&root(root_path))
        .map(|paths| paths.iter().cloned().collect())
        .unwrap_or_default()
}

// FR-CKP-05: a change while a supervised line runs alone in the root is that line's, `command`; the record's
// attribution is the attribution of the closed edge that holds it.
#[test]
fn change_during_line_is_attributed_to_line() {
    let mut ledger = watched();
    ledger.line_started(record(1), session(1), &[root(APP)]);
    ledger.changed(&root(APP), &path(APP, "src/main.rs"));
    assert!(
        ledger.take_closed().is_empty(),
        "the edge closes only when the line ends"
    );
    let ended = ledger.line_ended(record(1)).unwrap();
    assert_eq!(ended.attribution, Attribution::Command);
    let closed = ledger.take_closed();
    assert_eq!(closed.len(), 1);
    let edge = &closed[0];
    assert_eq!(edge.id, ended.edge);
    assert_eq!(edge.attribution, ended.attribution);
    assert_eq!(edge.records, BTreeSet::from([record(1)]));
    assert_eq!(edge.sessions, BTreeSet::from([session(1)]));
    assert_eq!(paths_of(edge, APP), [path(APP, "src/main.rs")]);
    // A line's changes are never reported as agent edits.
    assert_eq!(ledger.take_agent_edits(&root(APP)), None);
}

// FR-CKP-06: a change inside an envelope while no line runs in the root is an agent edit: reported for `agent.edit`,
// and kept apart from the lines before and after it.
#[test]
fn change_between_lines_in_envelope_is_agent_edit() {
    let mut ledger = watched();
    ledger.line_started(record(1), session(1), &[root(APP)]);
    ledger.changed(&root(APP), &path(APP, "a"));
    ledger.line_ended(record(1)).unwrap();
    ledger.changed(&root(APP), &path(APP, "b"));
    ledger.changed(&root(APP), &path(APP, "c"));
    let edits = ledger.take_agent_edits(&root(APP)).unwrap();
    assert_eq!(edits.root, root(APP));
    assert_eq!(edits.sessions, BTreeSet::from([session(1)]));
    assert_eq!(edits.paths, [path(APP, "b"), path(APP, "c")]);
    assert_eq!(edits.omitted, 0);
    // Reported once.
    assert_eq!(ledger.take_agent_edits(&root(APP)), None);
    // The next line closes the agent-edit run before it starts.
    ledger.line_started(record(2), session(1), &[root(APP)]);
    ledger.changed(&root(APP), &path(APP, "d"));
    ledger.line_ended(record(2)).unwrap();
    let closed = ledger.take_closed();
    let kinds: Vec<_> = closed.iter().map(|edge| edge.attribution).collect();
    assert_eq!(
        kinds,
        [Attribution::Command, Attribution::AgentEdit, Attribution::Command]
    );
    let agent_edit = &closed[1];
    assert!(agent_edit.records.is_empty());
    assert_eq!(agent_edit.sessions, BTreeSet::from([session(1)]));
    assert_eq!(paths_of(agent_edit, APP), [path(APP, "b"), path(APP, "c")]);
    assert!(agent_edit.agent_may_undo());
    assert_eq!(paths_of(&closed[2], APP), [path(APP, "d")]);
}

// FR-CKP-07: two lines overlapping in time in one root form one concurrent set: both records are `concurrent`, and
// one closed edge holds both lines and every change made while either ran.
#[test]
fn overlapping_lines_in_same_root_form_concurrent_set() {
    let mut ledger = watched();
    ledger.line_started(record(1), session(1), &[root(APP)]);
    ledger.changed(&root(APP), &path(APP, "a"));
    ledger.line_started(record(2), session(1), &[root(APP)]);
    ledger.changed(&root(APP), &path(APP, "b"));
    let first = ledger.line_ended(record(1)).unwrap();
    // Still running: the set is not closed yet, and changes keep going to it.
    assert_eq!(ledger.take_closed(), Vec::new());
    ledger.changed(&root(APP), &path(APP, "c"));
    let second = ledger.line_ended(record(2)).unwrap();
    assert_eq!(first.attribution, Attribution::Concurrent);
    assert_eq!(second.attribution, Attribution::Concurrent);
    assert_eq!(first.edge, second.edge, "undone together: one edge");
    let closed = ledger.take_closed();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].attribution, Attribution::Concurrent);
    assert_eq!(closed[0].records, BTreeSet::from([record(1), record(2)]));
    assert_eq!(
        paths_of(&closed[0], APP),
        [path(APP, "a"), path(APP, "b"), path(APP, "c")]
    );
}

// Lines overlapping in time but in different roots are separate `command` edges.
#[test]
fn non_overlapping_lines_in_different_roots_stay_separate() {
    let mut ledger = watched();
    ledger.line_started(record(1), session(1), &[root(APP)]);
    ledger.line_started(record(2), session(1), &[root(LIB)]);
    ledger.changed(&root(APP), &path(APP, "a"));
    ledger.changed(&root(LIB), &path(LIB, "b"));
    let first = ledger.line_ended(record(1)).unwrap();
    let second = ledger.line_ended(record(2)).unwrap();
    assert_eq!(first.attribution, Attribution::Command);
    assert_eq!(second.attribution, Attribution::Command);
    assert_ne!(first.edge, second.edge);
    let closed = ledger.take_closed();
    assert_eq!(closed.len(), 2);
    assert_eq!(paths_of(&closed[0], APP), [path(APP, "a")]);
    assert_eq!(paths_of(&closed[0], LIB), Vec::new());
    assert_eq!(paths_of(&closed[1], LIB), [path(LIB, "b")]);
}

// Lines one after the other in the same root, never overlapping, stay separate too.
#[test]
fn consecutive_lines_in_same_root_stay_separate() {
    let mut ledger = watched();
    ledger.line_started(record(1), session(1), &[root(APP)]);
    let first = ledger.line_ended(record(1)).unwrap();
    ledger.line_started(record(2), session(1), &[root(APP)]);
    let second = ledger.line_ended(record(2)).unwrap();
    assert_eq!(first.attribution, Attribution::Command);
    assert_eq!(second.attribution, Attribution::Command);
    assert_ne!(first.edge, second.edge);
}

// A change while no envelope watches the root is `external`: not reported as an agent edit, and never offered for
// agent undo.
#[test]
fn change_without_agent_session_is_external() {
    let mut ledger = Ledger::new();
    // A session without an envelope (`session.create`) watching the root does not make changes agent edits.
    ledger.watch(&root(APP), session(2), false);
    ledger.changed(&root(APP), &path(APP, "a"));
    assert_eq!(ledger.take_agent_edits(&root(APP)), None);
    ledger.close_idle_runs();
    let closed = ledger.take_closed();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].attribution, Attribution::External);
    assert!(closed[0].sessions.is_empty());
    assert!(!closed[0].agent_may_undo());
}

// When the last envelope stops watching, its agent-edit run closes and later changes are external; when an envelope
// starts watching, an external run closes and later changes are agent edits.
#[test]
fn envelope_coming_and_going_splits_idle_runs() {
    let mut ledger = Ledger::new();
    // A session without an envelope watches the root throughout.
    ledger.watch(&root(APP), session(2), false);
    ledger.changed(&root(APP), &path(APP, "before"));
    ledger.watch(&root(APP), session(1), true);
    ledger.changed(&root(APP), &path(APP, "during"));
    ledger.unwatch(&root(APP), session(1), true);
    ledger.changed(&root(APP), &path(APP, "after"));
    ledger.close_idle_runs();
    let closed = ledger.take_closed();
    let kinds: Vec<_> = closed.iter().map(|edge| edge.attribution).collect();
    assert_eq!(
        kinds,
        [Attribution::External, Attribution::AgentEdit, Attribution::External]
    );
    assert_eq!(paths_of(&closed[1], APP), [path(APP, "during")]);
}

// FR-CKP-07: overlap is transitive and crosses roots through a line touching both: A and C overlap B in different
// roots, so all three are one set, though A and C never shared a root.
#[test]
fn line_touching_two_busy_roots_merges_their_sets() {
    let mut ledger = watched();
    ledger.line_started(record(1), session(1), &[root(APP)]);
    ledger.line_started(record(3), session(2), &[root(LIB)]);
    ledger.changed(&root(APP), &path(APP, "a"));
    ledger.changed(&root(LIB), &path(LIB, "c"));
    ledger.line_started(record(2), session(1), &[root(APP), root(LIB)]);
    let ends: Vec<_> = [1, 2, 3]
        .into_iter()
        .map(|n| ledger.line_ended(record(n)).unwrap())
        .collect();
    assert!(ends.iter().all(|end| end.attribution == Attribution::Concurrent));
    assert!(ends.iter().all(|end| end.edge == ends[0].edge));
    let closed = ledger.take_closed();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].records, BTreeSet::from([record(1), record(2), record(3)]));
    assert_eq!(closed[0].sessions, BTreeSet::from([session(1), session(2)]));
    assert_eq!(paths_of(&closed[0], APP), [path(APP, "a")]);
    assert_eq!(paths_of(&closed[0], LIB), [path(LIB, "c")]);
}

// A chain A-B-C in one root, where A ends before C starts, is still one set: B overlapped both.
#[test]
fn chained_overlaps_in_one_root_form_one_set() {
    let mut ledger = watched();
    ledger.line_started(record(1), session(1), &[root(APP)]);
    ledger.line_started(record(2), session(1), &[root(APP)]);
    let a = ledger.line_ended(record(1)).unwrap();
    ledger.line_started(record(3), session(1), &[root(APP)]);
    let b = ledger.line_ended(record(2)).unwrap();
    let c = ledger.line_ended(record(3)).unwrap();
    assert_eq!(a.edge, b.edge);
    assert_eq!(b.edge, c.edge);
    assert_eq!(c.attribution, Attribution::Concurrent);
    assert_eq!(ledger.take_closed().len(), 1);
}

// Lines of two sessions protecting the same root overlap there: the ledger is per root, so one session's line is
// never reported as the other's agent edit.
#[test]
fn line_of_another_session_in_shared_root_is_not_an_agent_edit() {
    let mut ledger = Ledger::new();
    ledger.watch(&root(APP), session(1), true);
    ledger.watch(&root(APP), session(2), true);
    ledger.line_started(record(1), session(2), &[root(APP)]);
    // Both sessions' watchers report the same change.
    ledger.changed(&root(APP), &path(APP, "a"));
    ledger.changed(&root(APP), &path(APP, "a"));
    assert_eq!(ledger.take_agent_edits(&root(APP)), None);
    let end = ledger.line_ended(record(1)).unwrap();
    assert_eq!(end.attribution, Attribution::Command);
    assert_eq!(paths_of(&ledger.take_closed()[0], APP), [path(APP, "a")]);
}

// An `agent.edit` batch lists at most `AGENT_EDIT_PATHS` paths and counts the rest; an edge lists at most
// `MAX_EDGE_PATHS` and is then marked overflowed.
#[test]
fn reports_and_edges_are_bounded() {
    let mut ledger = watched();
    let extra = 5;
    for n in 0..AGENT_EDIT_PATHS + extra {
        ledger.changed(&root(APP), &path(APP, &format!("f{n}")));
    }
    let edits = ledger.take_agent_edits(&root(APP)).unwrap();
    assert_eq!(edits.paths.len(), AGENT_EDIT_PATHS);
    assert_eq!(edits.omitted, u32::try_from(extra).unwrap());

    ledger.line_started(record(1), session(1), &[root(APP)]);
    for n in 0..=MAX_EDGE_PATHS {
        ledger.changed(&root(APP), &path(APP, &format!("g{n}")));
    }
    ledger.line_ended(record(1)).unwrap();
    let closed = ledger.take_closed();
    let line = closed.last().unwrap();
    assert_eq!(line.path_count(), MAX_EDGE_PATHS);
    assert!(line.overflowed);
}

// A line ended twice, or never started, has no attribution; a line started twice is one line.
#[test]
fn unknown_and_repeated_lines_are_ignored() {
    let mut ledger = watched();
    assert_eq!(ledger.line_ended(record(9)), None);
    ledger.line_started(record(1), session(1), &[root(APP)]);
    ledger.line_started(record(1), session(1), &[root(APP)]);
    assert!(ledger.line_ended(record(1)).is_some());
    assert_eq!(ledger.line_ended(record(1)), None);
    assert_eq!(ledger.take_closed().len(), 1);
}

// A line listing a root twice is counted once in it, and ends cleanly.
#[test]
fn line_listing_a_root_twice_counts_it_once() {
    let mut ledger = watched();
    ledger.line_started(record(1), session(1), &[root(APP), root(APP)]);
    let end = ledger.line_ended(record(1)).unwrap();
    assert_eq!(end.attribution, Attribution::Command);
    // The root is idle again: a change now is an agent edit.
    ledger.changed(&root(APP), &path(APP, "a"));
    assert!(ledger.take_agent_edits(&root(APP)).is_some());
}

// While a line runs, its open edge says what it would be attributed now.
#[test]
fn running_edge_shows_current_attribution() {
    let mut ledger = watched();
    ledger.line_started(record(1), session(1), &[root(APP)]);
    assert_eq!(
        ledger.running_edge(record(1)).map(|edge| edge.attribution),
        Some(Attribution::Command)
    );
    ledger.line_started(record(2), session(1), &[root(APP)]);
    assert_eq!(
        ledger.running_edge(record(1)).map(|edge| edge.attribution),
        Some(Attribution::Concurrent)
    );
}

// Roots are forgotten once nothing refers to them, so the ledger does not grow with roots no longer in use.
#[test]
fn unused_roots_are_forgotten() {
    let mut ledger = Ledger::new();
    ledger.watch(&root(APP), session(1), true);
    ledger.line_started(record(1), session(1), &[root(APP)]);
    ledger.line_ended(record(1)).unwrap();
    ledger.unwatch(&root(APP), session(1), true);
    assert!(ledger.roots.is_empty());
    assert!(ledger.lines.is_empty());
    assert!(ledger.open.is_empty());
}

// A root watched only by sessions without an envelope: when the last one stops watching, its external run closes and
// the root is forgotten; a change its stopped watcher still reports afterwards belongs to nobody and opens nothing.
#[test]
fn last_watcher_leaving_closes_external_run_and_drops_late_changes() {
    let mut ledger = Ledger::new();
    ledger.watch(&root(APP), session(2), false);
    ledger.changed(&root(APP), &path(APP, "a"));
    ledger.unwatch(&root(APP), session(2), false);
    let closed = ledger.take_closed();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].attribution, Attribution::External);
    // The stopped watcher's last batch.
    ledger.changed(&root(APP), &path(APP, "late"));
    assert_eq!(ledger.take_agent_edits(&root(APP)), None);
    ledger.close_idle_runs();
    assert_eq!(ledger.take_closed(), Vec::new());
    assert!(ledger.roots.is_empty());
    assert!(ledger.open.is_empty());
}

// The same after an envelope session ends: its late changes are not agent edits, and nothing stays open.
#[test]
fn changes_after_the_envelope_ended_are_dropped() {
    let mut ledger = Ledger::new();
    ledger.watch(&root(APP), session(1), true);
    ledger.changed(&root(APP), &path(APP, "a"));
    let _ = ledger.take_agent_edits(&root(APP));
    ledger.unwatch(&root(APP), session(1), true);
    ledger.changed(&root(APP), &path(APP, "late"));
    assert_eq!(ledger.take_agent_edits(&root(APP)), None);
    let closed = ledger.take_closed();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].attribution, Attribution::AgentEdit);
    assert!(ledger.roots.is_empty());
    assert!(ledger.open.is_empty());
}

// A line still running when its session (the root's only watcher) ended keeps its changes until it ends.
#[test]
fn line_outliving_its_session_keeps_its_changes() {
    let mut ledger = Ledger::new();
    ledger.watch(&root(APP), session(1), true);
    ledger.line_started(record(1), session(1), &[root(APP)]);
    ledger.unwatch(&root(APP), session(1), true);
    ledger.changed(&root(APP), &path(APP, "a"));
    let end = ledger.line_ended(record(1)).unwrap();
    assert_eq!(end.attribution, Attribution::Command);
    let closed = ledger.take_closed();
    assert_eq!(paths_of(&closed[0], APP), [path(APP, "a")]);
    assert!(ledger.roots.is_empty());
}
