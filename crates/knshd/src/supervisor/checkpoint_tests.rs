//! KNSH-079: lines touching a checkpoint root whose shadow is not ready (FR-CKP-02), through the orchestrator with a
//! real record store and shadows built from an in-memory tree.

use std::thread;

use knsh_checkpoint::testing::FakeTree;
use knsh_core::{AgentId, NoAuthority, NoHooks, ProfileName, StillWaiting};
use knsh_json::Value;
use knsh_platform::testing::{FakeClock, ScriptedFileEvents, SeededRandom};
use knsh_platform::{FileEvent, FileEventFlags};
use knsh_store::{PageSize, RecordQuery, Scope};

use super::tests::{FakeSpawner, Journal, filesystem, forwarded};
use super::*;
use crate::sessions::tests::{Fixture, fixture};
use crate::shadows::CheckpointEvents;
use crate::shadows::EdgeSink;
use crate::shadows::tests::{ROOT, RecordedEdges, SETTLE, echoing_events, profile_with, shadows, shadows_with_edges};

/// Lines the profile allows, and `github.com` as an approval host (KNSH-093).
const ALLOW: &str =
    "[exec]\nallow = [\"echo\", \"ls\"]\n[network]\nmode = \"allowlist\"\napproval_hosts = [\"github.com\"]\n";

/// A session on profile `ckpt`, protecting `ROOT`, with shadows built from `tree`.
struct Rig {
    fixture: Fixture,
    session_id: SessionId,
    journal: Arc<Journal>,
    lifecycle: Arc<Lifecycle>,
    /// Every edge closed (KNSH-081).
    edges: Arc<RecordedEdges>,
}

impl Rig {
    /// The session's shadows start building at once; `hold` keeps every clone waiting until the tree is released.
    fn new(tree: &Arc<FakeTree>, required: bool, hold: bool) -> Self {
        Self::with_spawner(tree, required, hold, |journal, _| Arc::new(FakeSpawner::new(journal)))
    }

    /// [`Rig::new`] with the spawner `spawner` makes from the journal and the root's scripted file events; checkpoint
    /// events are published on the real hub (KNSH-080).
    fn with_spawner(
        tree: &Arc<FakeTree>,
        required: bool,
        hold: bool,
        spawner: impl FnOnce(Arc<Journal>, ScriptedFileEvents) -> Arc<dyn Spawner>,
    ) -> Self {
        let fixture = fixture();
        let file_events = echoing_events(tree);
        let edges = Arc::new(RecordedEdges::default());
        fixture.sessions.attach_shadows(shadows_with_edges(
            tree,
            file_events.clone(),
            Arc::clone(&fixture.hub) as Arc<dyn CheckpointEvents>,
            Arc::clone(&edges) as Arc<dyn EdgeSink>,
        ));
        let opened = fixture
            .sessions
            .open_agent(
                Actor::Agent(AgentId::new("claude-code").unwrap()),
                ProfileName::new("ckpt").unwrap(),
            )
            .unwrap();
        let text = format!("name = \"ckpt\"\n[checkpoints]\nroots = [\"{ROOT}\"]\nrequired = {required}\n{ALLOW}");
        if hold {
            tree.hold();
        }
        fixture
            .sessions
            .start_shadows(opened.session_id, &profile_with(&[ROOT], required, ALLOW));
        let journal = Arc::new(Journal::default());
        let profiles = crate::policy::tests::loader(filesystem(&[("ckpt", text.as_str())]));
        let lifecycle = Lifecycle::new(Parts {
            sessions: Arc::clone(&fixture.sessions),
            profiles,
            events: Arc::clone(&fixture.hub),
            store: Some(fixture.store.clone()),
            clock: Arc::new(FakeClock::new(
                Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
            )),
            random: Arc::new(SeededRandom::new(5)),
            hooks: Arc::new(NoHooks),
            authority: Arc::new(NoAuthority),
            approvals: crate::approvals::tests::unanswered(Duration::from_millis(50)),
            grants: crate::grants::GrantStore::new(),
            spawner: spawner(Arc::clone(&journal), file_events),
            redactors: crate::redaction::Redactors::none(),
            shim_dir: std::path::PathBuf::from("/Users/u/.knsh/shims"),
        });
        Self {
            session_id: opened.session_id,
            fixture,
            journal,
            lifecycle,
            edges,
        }
    }

    fn line(&self, command: &str, wait: bool) -> ForwardedLine {
        let mut line = forwarded(self.session_id, command);
        line.checkpoint_wait = wait;
        line
    }

    fn spawns(&self) -> usize {
        self.journal
            .entries()
            .iter()
            .filter(|entry| entry.starts_with("spawn"))
            .count()
    }

    fn records(&self) -> Vec<ExecutionRecord> {
        let query = RecordQuery {
            session: Some(self.session_id),
            since: None,
            until: None,
            text: None,
            after: None,
            limit: PageSize::new(100).unwrap(),
        };
        let page = self.fixture.store.query(Scope::All, query).unwrap();
        page.records.into_iter().map(|stored| stored.record).collect()
    }

    fn root() -> CanonicalPath {
        CanonicalPath::new(ROOT).unwrap()
    }
}

fn data(error: &RpcError, name: &str) -> Option<Value> {
    error.data.as_ref()?.as_object()?.get(name).cloned()
}

// FR-CKP-02: with `required = true`, a line in the root waits for the shadow, and runs once it is complete.
#[test]
fn line_touching_root_waits_until_shadow_complete() {
    let tree = Arc::new(FakeTree::new());
    let rig = Rig::new(&tree, true, true);
    let lifecycle = Arc::clone(&rig.lifecycle);
    let line = rig.line("echo hi", true);
    let running = thread::spawn(move || lifecycle.run(line, &StillWaiting));
    // Several wait slices pass with the shadow held: the line has not been spawned.
    thread::sleep(Duration::from_millis(350));
    assert!(!running.is_finished());
    assert_eq!(rig.spawns(), 0);
    tree.release();
    let finished = running
        .join()
        .unwrap()
        .expect("the line runs once the shadow is complete");
    assert_eq!(finished.status, LineStatus::Exited(0));
    assert_eq!(rig.spawns(), 1);
    let records = rig.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].details.unprotected, []);
}

// FR-CKP-02: a caller that does not wait gets `-32010` with the root and the build's progress; nothing runs.
#[test]
fn non_waiting_caller_gets_minus_32010_with_progress() {
    let tree = Arc::new(FakeTree::new());
    let rig = Rig::new(&tree, true, true);
    let error = rig
        .lifecycle
        .run(rig.line("echo hi", false), &StillWaiting)
        .unwrap_err();
    tree.release();
    assert_eq!(error.code, ErrorCode::CheckpointNotReady);
    assert_eq!(error.code.code(), -32010);
    assert_eq!(data(&error, "root"), Some(Value::from(ROOT)));
    let progress = data(&error, "progress").expect("progress");
    let progress = progress.as_object().unwrap();
    for field in ["files", "folders", "folders_pending"] {
        assert!(progress.get(field).and_then(Value::as_i64).is_some(), "{field}");
    }
    assert_eq!(rig.spawns(), 0);
    // Recorded as a deny, like a held line, so the decision is not lost.
    let records = rig.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].exit_code, None);
    assert_eq!(
        records[0].details.decision.as_ref().map(|decision| decision.verdict),
        Some(knsh_core::DecisionVerdict::Deny)
    );
}

// Fail closed: with `required = true`, a root whose shadow failed denies the line rather than run it unprotected.
#[test]
fn shadow_failure_with_required_true_denies_line() {
    let tree = Arc::new(FakeTree::new());
    tree.fail_clone(std::path::Path::new(ROOT).join("README"), 5);
    let rig = Rig::new(&tree, true, false);
    let shadows_settled = rig
        .fixture
        .sessions
        .wait_for_shadow(rig.session_id, &Rig::root(), SETTLE);
    assert_eq!(
        shadows_settled,
        knsh_checkpoint::RootReadiness::Unavailable(UnprotectedReason::ShadowFailed)
    );
    for wait in [true, false] {
        let error = rig.lifecycle.run(rig.line("echo hi", wait), &StillWaiting).unwrap_err();
        assert_eq!(error.code, ErrorCode::Denied, "wait = {wait}");
    }
    assert_eq!(rig.spawns(), 0);
    // The capability report says the root is not protected.
    assert_eq!(
        rig.fixture.sessions.checkpoint_report().get(ROOT),
        Some(&knsh_proto::CheckpointBackend::None)
    );
}

// FR-CKP-02 with `required = false`: the line runs at once, and its record says the change was not protected.
#[test]
fn required_false_runs_at_once_and_records_unprotected_root() {
    let tree = Arc::new(FakeTree::new());
    let rig = Rig::new(&tree, false, true);
    let finished = rig.lifecycle.run(rig.line("echo hi", true), &StillWaiting).unwrap();
    tree.release();
    assert_eq!(finished.status, LineStatus::Exited(0));
    let records = rig.records();
    assert_eq!(
        records[0].details.unprotected,
        [UnprotectedRoot {
            root: Rig::root(),
            reason: UnprotectedReason::ShadowBuilding,
        }]
    );
    // Once the shadow is complete, later lines are protected.
    assert_eq!(settled_root(&rig), knsh_checkpoint::RootReadiness::Ready);
    rig.lifecycle.run(rig.line("ls", true), &StillWaiting).unwrap();
    let records = rig.records();
    assert!(records.iter().any(|record| record.details.unprotected.is_empty()));
}

fn settled_root(rig: &Rig) -> knsh_checkpoint::RootReadiness {
    rig.fixture
        .sessions
        .wait_for_shadow(rig.session_id, &Rig::root(), SETTLE)
}

// A line that cannot touch the root (cwd elsewhere, no write path in it) never waits for its shadow.
#[test]
fn line_outside_every_root_does_not_wait() {
    let tree = Arc::new(FakeTree::new());
    let rig = Rig::new(&tree, true, true);
    let mut line = rig.line("echo hi", false);
    line.proposal.cwd = CanonicalPath::new("/tmp").unwrap();
    let result = rig.lifecycle.run(line, &StillWaiting);
    tree.release();
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(rig.spawns(), 1);
}

/// A caller that leaves when told to.
struct Leaves(Arc<std::sync::atomic::AtomicBool>);

impl Caller for Leaves {
    fn gone(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// FR-LC-41: a caller that leaves while its line waits for a shadow cancels it; it never runs.
#[test]
fn caller_leaving_while_waiting_cancels_the_line() {
    let tree = Arc::new(FakeTree::new());
    let rig = Rig::new(&tree, true, true);
    let left = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let lifecycle = Arc::clone(&rig.lifecycle);
    let line = rig.line("echo hi", true);
    let caller = Leaves(Arc::clone(&left));
    let running = thread::spawn(move || lifecycle.run(line, &caller));
    thread::sleep(Duration::from_millis(250));
    assert!(!running.is_finished(), "the line should be waiting for the shadow");
    left.store(true, std::sync::atomic::Ordering::SeqCst);
    let error = running.join().unwrap().unwrap_err();
    tree.release();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(rig.spawns(), 0);
}

// A complete shadow lets a required line run at once, even for a caller that does not wait.
#[test]
fn complete_shadow_lets_required_line_run() {
    let tree = Arc::new(FakeTree::new());
    let rig = Rig::new(&tree, true, false);
    assert_eq!(settled_root(&rig), knsh_checkpoint::RootReadiness::Ready);
    assert!(rig.lifecycle.run(rig.line("echo hi", false), &StillWaiting).is_ok());
    assert_eq!(rig.spawns(), 1);
}

// "Held lines": a session paused while its line waits for a shadow is held, even when the shadow completes in the same
// wait slice; the line never starts.
#[test]
fn session_paused_while_waiting_holds_the_line_even_if_the_shadow_completes() {
    let tree = Arc::new(FakeTree::new());
    let rig = Rig::new(&tree, true, true);
    let lifecycle = Arc::clone(&rig.lifecycle);
    let line = rig.line("echo hi", true);
    let running = thread::spawn(move || lifecycle.run(line, &StillWaiting));
    thread::sleep(Duration::from_millis(250));
    assert!(!running.is_finished(), "the line should be waiting for the shadow");
    rig.fixture
        .sessions
        .change_state(rig.session_id, crate::sessions::StateChange::Pause)
        .unwrap();
    tree.release();
    let error = running.join().unwrap().unwrap_err();
    assert_eq!(error.code, ErrorCode::SessionHeld);
    assert_eq!(rig.spawns(), 0);
}

// KNSH-079: shadows started for a session that has already ended are stopped at once, never left building.
#[test]
fn shadows_of_a_session_that_already_ended_are_stopped() {
    let tree = Arc::new(FakeTree::new());
    let fixture = fixture();
    fixture.sessions.attach_shadows(shadows(&tree));
    let opened = fixture
        .sessions
        .open_agent(
            Actor::Agent(AgentId::new("claude-code").unwrap()),
            ProfileName::new("ckpt").unwrap(),
        )
        .unwrap();
    fixture.sessions.end_agent(opened.session_id);
    tree.hold();
    fixture
        .sessions
        .start_shadows(opened.session_id, &profile_with(&[ROOT], true, ALLOW));
    tree.release();
    assert_eq!(
        fixture
            .sessions
            .shadow_readiness(opened.session_id, &CanonicalPath::new(ROOT).unwrap()),
        knsh_checkpoint::RootReadiness::Unavailable(UnprotectedReason::NoShadow)
    );
    assert!(fixture.sessions.checkpoint_report().is_empty());
}

/// A spawner whose line runs while the system drops file events of the root (KNSH-080).
struct DroppingSpawner {
    inner: FakeSpawner,
    file_events: ScriptedFileEvents,
}

impl Spawner for DroppingSpawner {
    fn spawn(&self, plan: SpawnPlan, events: &dyn LineEvents) -> SpawnReport {
        self.file_events.emit(&[FileEvent::new(
            ROOT,
            FileEventFlags::MUST_SCAN_SUB_DIRS.union(FileEventFlags::USER_DROPPED),
        )]);
        self.inner.spawn(plan, events)
    }
}

// KNSH-080 (FR-CKP-04): events dropped while a line runs in a protected root make its checkpoints uncertain:
// `checkpoint.uncertain` names the line's record, after its `command.finished`.
#[test]
fn line_during_dropped_events_publishes_checkpoint_uncertain() {
    let tree = Arc::new(FakeTree::new());
    let rig = Rig::with_spawner(&tree, true, false, |journal, file_events| {
        Arc::new(DroppingSpawner {
            inner: FakeSpawner::new(journal),
            file_events,
        })
    });
    assert_eq!(
        crate::shadows::tests::settled_in(&rig.fixture.sessions, rig.session_id, &Rig::root()),
        knsh_checkpoint::RootReadiness::Ready
    );
    let subscriber = crate::events::Subscriber::new();
    subscriber
        .subscribe(&rig.fixture.hub, knsh_core::EventScope::Session(rig.session_id), None)
        .unwrap();
    let finished = rig.lifecycle.run(rig.line("echo hi", true), &StillWaiting).unwrap();
    let record_id = finished.record_id.unwrap();
    let names: Vec<(String, Option<EventData>)> = subscriber
        .take(100)
        .into_iter()
        .filter_map(|(_, delivery)| match delivery {
            knsh_core::Delivery::Event(event) => Some((event.name().to_owned(), Some(event.data.clone()))),
            _ => None,
        })
        .collect();
    let finished_at = names.iter().position(|(name, _)| name == "command.finished").unwrap();
    let uncertain_at = names
        .iter()
        .position(|(name, _)| name == "checkpoint.uncertain")
        .unwrap();
    assert!(finished_at < uncertain_at);
    let Some(EventData::CheckpointUncertain {
        root,
        record_id: uncertain_record,
        reason,
    }) = &names[uncertain_at].1
    else {
        panic!("not a checkpoint.uncertain payload");
    };
    assert_eq!(root, &Rig::root());
    assert_eq!(*uncertain_record, Some(record_id));
    assert_eq!(*reason, knsh_core::UncertainReason::EventsDropped);
}

// KNSH-080: a line in a protected root without drops publishes no `checkpoint.uncertain`.
#[test]
fn line_without_drops_is_certain() {
    let tree = Arc::new(FakeTree::new());
    let rig = Rig::new(&tree, true, false);
    assert_eq!(
        crate::shadows::tests::settled_in(&rig.fixture.sessions, rig.session_id, &Rig::root()),
        knsh_checkpoint::RootReadiness::Ready
    );
    let subscriber = crate::events::Subscriber::new();
    subscriber
        .subscribe(&rig.fixture.hub, knsh_core::EventScope::Session(rig.session_id), None)
        .unwrap();
    rig.lifecycle.run(rig.line("echo hi", true), &StillWaiting).unwrap();
    let uncertain = subscriber
        .take(100)
        .into_iter()
        .filter(|(_, delivery)| {
            matches!(delivery, knsh_core::Delivery::Event(event) if event.name() == "checkpoint.uncertain")
        })
        .count();
    assert_eq!(uncertain, 0);
}

/// A spawner whose line writes `ROOT/built.txt` while it runs, as a build would (KNSH-081).
struct WritingSpawner {
    inner: FakeSpawner,
    tree: Arc<FakeTree>,
    file_events: ScriptedFileEvents,
}

impl Spawner for WritingSpawner {
    fn spawn(&self, plan: SpawnPlan, events: &dyn LineEvents) -> SpawnReport {
        let built = std::path::Path::new(ROOT).join("built.txt");
        self.tree.add_file(&built, b"output");
        self.file_events
            .emit(&[FileEvent::new(&built, FileEventFlags::ITEM_CREATED)]);
        self.inner.spawn(plan, events)
    }
}

// KNSH-081 (FR-CKP-05): a change a line makes in a protected root is attributed to it: its record says `command`, as
// does the closed edge that holds the record and the change, so the record matches the history-tree edge.
#[test]
fn line_record_attribution_matches_its_edge() {
    let tree = Arc::new(FakeTree::new());
    let writer_tree = Arc::clone(&tree);
    let rig = Rig::with_spawner(&tree, true, false, move |journal, file_events| {
        Arc::new(WritingSpawner {
            inner: FakeSpawner::new(journal),
            tree: writer_tree,
            file_events,
        })
    });
    assert_eq!(
        crate::shadows::tests::settled_in(&rig.fixture.sessions, rig.session_id, &Rig::root()),
        knsh_checkpoint::RootReadiness::Ready
    );
    let finished = rig.lifecycle.run(rig.line("echo hi", true), &StillWaiting).unwrap();
    let record_id = finished.record_id.unwrap();
    let records = rig.records();
    let record = records.iter().find(|record| record.record_id == record_id).unwrap();
    assert_eq!(record.details.attribution, Some(knsh_core::Attribution::Command));
    let edges = rig.edges.0.lock().unwrap();
    let edge = edges
        .iter()
        .find(|edge| edge.records.contains(&record_id))
        .expect("the line's edge closed");
    assert_eq!(Some(edge.attribution), record.details.attribution);
    let built = CanonicalPath::new(format!("{ROOT}/built.txt")).unwrap();
    assert!(edge.paths[&Rig::root()].contains(&built));
}

// KNSH-081: a denied line never ran, so its record has no attribution.
#[test]
fn denied_line_has_no_attribution() {
    let tree = Arc::new(FakeTree::new());
    let rig = Rig::new(&tree, true, false);
    let _ = rig.lifecycle.run(rig.line("rm -rf /", true), &StillWaiting);
    let records = rig.records();
    assert!(!records.is_empty());
    assert!(records.iter().all(|record| record.details.attribution.is_none()));
}

// KNSH-082 (FR-CKP-08, FR-CKP-09, FR-CKP-11): a line's change is captured as a checkpoint: `checkpoint.created` names
// it and the line, the record carries `checkpoint_id` and `files_changed` with the post-image identity, and the
// `exec.run` result counts the change.
#[test]
fn line_record_carries_checkpoint_and_files_changed() {
    let tree = Arc::new(FakeTree::new());
    let writer_tree = Arc::clone(&tree);
    let rig = Rig::with_spawner(&tree, true, false, move |journal, file_events| {
        Arc::new(WritingSpawner {
            inner: FakeSpawner::new(journal),
            tree: writer_tree,
            file_events,
        })
    });
    assert_eq!(
        crate::shadows::tests::settled_in(&rig.fixture.sessions, rig.session_id, &Rig::root()),
        knsh_checkpoint::RootReadiness::Ready
    );
    let subscriber = crate::events::Subscriber::new();
    subscriber
        .subscribe(&rig.fixture.hub, knsh_core::EventScope::Session(rig.session_id), None)
        .unwrap();
    let finished = rig.lifecycle.run(rig.line("echo hi", true), &StillWaiting).unwrap();
    let record_id = finished.record_id.unwrap();
    let checkpoint_id = finished.checkpoint_id.expect("the line's checkpoint");
    assert_eq!(finished.files_changed, Some(1));

    let records = rig.records();
    let record = records.iter().find(|record| record.record_id == record_id).unwrap();
    assert_eq!(record.details.checkpoint_id, Some(checkpoint_id));
    let files = record.details.files_changed.as_ref().expect("files_changed");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path.as_path(), std::path::Path::new(ROOT).join("built.txt"));
    assert_eq!(files[0].change, knsh_core::FileChange::Created);
    let identity = files[0].post_image.expect("a post-image identity");
    assert_eq!(identity.size, 6);
    assert_eq!(identity.sha256, Some(*FakeTree::digest_of(b"output").as_bytes()));

    let created: Vec<EventData> = subscriber
        .take(100)
        .into_iter()
        .filter_map(|(_, delivery)| match delivery {
            knsh_core::Delivery::Event(event) if event.name() == "checkpoint.created" => Some(event.data.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(created.len(), 1, "{created:?}");
    let EventData::CheckpointCreated {
        checkpoint_id: created_id,
        attribution,
        record_ids,
        roots,
        files_changed,
        uncertain,
    } = &created[0]
    else {
        panic!("not a checkpoint.created payload");
    };
    assert_eq!(*created_id, checkpoint_id);
    assert_eq!(*attribution, knsh_core::Attribution::Command);
    assert_eq!(record_ids, &[record_id]);
    assert_eq!(roots, &[Rig::root()]);
    assert_eq!((*files_changed, *uncertain), (1, false));
}

// KNSH-082: a protected line that changed nothing has `files_changed` 0 and no checkpoint; one outside every root
// has neither, since nothing was counted.
#[test]
fn files_changed_is_zero_in_a_root_and_null_outside() {
    let tree = Arc::new(FakeTree::new());
    let rig = Rig::new(&tree, true, false);
    assert_eq!(settled_root(&rig), knsh_checkpoint::RootReadiness::Ready);
    let quiet = rig.lifecycle.run(rig.line("echo hi", true), &StillWaiting).unwrap();
    assert_eq!((quiet.files_changed, quiet.checkpoint_id), (Some(0), None));
    let mut outside = rig.line("ls", true);
    outside.proposal.cwd = CanonicalPath::new("/tmp").unwrap();
    let outside = rig.lifecycle.run(outside, &StillWaiting).unwrap();
    assert_eq!((outside.files_changed, outside.checkpoint_id), (None, None));
    let records = rig.records();
    let record = |id| records.iter().find(|record| Some(record.record_id) == id).unwrap();
    assert_eq!(record(quiet.record_id).details.files_changed, Some(Vec::new()));
    assert_eq!(record(outside.record_id).details.files_changed, None);
    assert_eq!(record(quiet.record_id).details.checkpoint_id, None);
}

/// Irreversible marks as the history receives them, each with the `command.finished` events published by then.
struct RecordedMarks {
    subscriber: crate::events::Subscriber,
    /// Every event taken off the subscriber, in order, with a `mark` entry where a mark arrived.
    seen: Mutex<Vec<String>>,
}

impl RecordedMarks {
    fn take(&self) {
        let names = self
            .subscriber
            .take(usize::MAX)
            .into_iter()
            .filter_map(|(_, delivery)| match delivery {
                knsh_core::Delivery::Event(event) => Some(event.name().to_owned()),
                _ => None,
            });
        self.seen.lock().unwrap().extend(names);
    }
}

impl IrreversibleMarks for RecordedMarks {
    fn mark(&self, checkpoint: CheckpointId, reasons: &[String]) {
        self.take();
        self.seen.lock().unwrap().push(format!("mark {checkpoint} {reasons:?}"));
    }
}

// FR-IRR-03, FR-IRR-04 (KNSH-093): a line the proxy reports reaching an `approval_hosts` destination is marked
// irreversible with `network` and the host, on its record and on its checkpoint, before `command.finished` is
// published.
#[test]
fn marks_present_before_command_finished() {
    let tree = Arc::new(FakeTree::new());
    let writer_tree = Arc::clone(&tree);
    let rig = Rig::with_spawner(&tree, true, false, move |journal, file_events| {
        let mut inner = FakeSpawner::new(journal);
        inner.network = vec![
            knsh_core::NetworkEntry::new(
                knsh_core::Redacted::new("github.com".to_owned()),
                443,
                knsh_core::NetworkResult::Contacted,
            ),
            knsh_core::NetworkEntry::new(
                knsh_core::Redacted::new("example.com".to_owned()),
                443,
                knsh_core::NetworkResult::Refused("host_not_allowed".to_owned()),
            ),
        ];
        Arc::new(WritingSpawner {
            inner,
            tree: writer_tree,
            file_events,
        })
    });
    assert_eq!(settled_root(&rig), knsh_checkpoint::RootReadiness::Ready);
    let marks = Arc::new(RecordedMarks {
        subscriber: crate::events::Subscriber::new(),
        seen: Mutex::new(Vec::new()),
    });
    marks
        .subscriber
        .subscribe(&rig.fixture.hub, knsh_core::EventScope::Session(rig.session_id), None)
        .unwrap();
    rig.lifecycle
        .attach_marks(Arc::clone(&marks) as Arc<dyn IrreversibleMarks>);

    let finished = rig.lifecycle.run(rig.line("echo hi", true), &StillWaiting).unwrap();
    let checkpoint_id = finished.checkpoint_id.expect("the line's checkpoint");
    marks.take();
    let seen = marks.seen.lock().unwrap().clone();
    let mark = format!("mark {checkpoint_id} [\"network\", \"github.com\"]");
    let marked_at = seen
        .iter()
        .position(|entry| *entry == mark)
        .expect("the checkpoint was marked");
    let finished_at = seen
        .iter()
        .position(|entry| entry == "command.finished")
        .expect("command.finished");
    assert!(marked_at < finished_at, "{seen:?}");

    let records = rig.records();
    let record = records
        .iter()
        .find(|record| Some(record.record_id) == finished.record_id)
        .unwrap();
    let flag = record.details.irreversible.as_ref().expect("the record's flag");
    assert!(flag.value());
    assert_eq!(flag.reasons(), ["network", "github.com"]);
}

// FR-IRR-04 (KNSH-093): a line that ran without doing anything irreversible is recorded `{"value": false}`, and its
// checkpoint is not marked.
#[test]
fn reversible_line_is_recorded_unflagged_and_not_marked() {
    let tree = Arc::new(FakeTree::new());
    let rig = Rig::new(&tree, true, false);
    assert_eq!(settled_root(&rig), knsh_checkpoint::RootReadiness::Ready);
    let marks = Arc::new(RecordedMarks {
        subscriber: crate::events::Subscriber::new(),
        seen: Mutex::new(Vec::new()),
    });
    rig.lifecycle
        .attach_marks(Arc::clone(&marks) as Arc<dyn IrreversibleMarks>);
    let finished = rig.lifecycle.run(rig.line("echo hi", true), &StillWaiting).unwrap();
    let records = rig.records();
    let record = records
        .iter()
        .find(|record| Some(record.record_id) == finished.record_id)
        .unwrap();
    assert_eq!(record.details.irreversible, Some(knsh_core::Irreversibility::none()));
    assert!(marks.seen.lock().unwrap().is_empty());
}
