//! KNSH-079: lines touching a checkpoint root whose shadow is not ready (FR-CKP-02), through the orchestrator with a
//! real record store and shadows built from an in-memory tree.

use std::thread;

use knsh_checkpoint::testing::FakeTree;
use knsh_core::{AgentId, NoAuthority, NoHooks, ProfileName, StillWaiting};
use knsh_json::Value;
use knsh_platform::testing::{FakeClock, SeededRandom};
use knsh_store::{PageSize, RecordQuery, Scope};

use super::tests::{FakeSpawner, Journal, filesystem, forwarded};
use super::*;
use crate::sessions::tests::{Fixture, fixture};
use crate::shadows::tests::{ROOT, SETTLE, profile_with, shadows};

/// Lines the profile allows.
const ALLOW: &str = "[exec]\nallow = [\"echo\", \"ls\"]\n";

/// A session on profile `ckpt`, protecting `ROOT`, with shadows built from `tree`.
struct Rig {
    fixture: Fixture,
    session_id: SessionId,
    journal: Arc<Journal>,
    lifecycle: Arc<Lifecycle>,
}

impl Rig {
    /// The session's shadows start building at once; `hold` keeps every clone waiting until the tree is released.
    fn new(tree: &Arc<FakeTree>, required: bool, hold: bool) -> Self {
        let fixture = fixture();
        fixture.sessions.attach_shadows(shadows(tree));
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
            spawner: Arc::new(FakeSpawner::new(Arc::clone(&journal))),
            redaction: Arc::new(knsh_core::NoOutputRedaction),
        });
        Self {
            session_id: opened.session_id,
            fixture,
            journal,
            lifecycle,
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
