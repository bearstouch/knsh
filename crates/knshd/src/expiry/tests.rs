//! Pushed-policy expiry and `profile.use` (KNSH-072): sessions on the session registry with a real record store and
//! event hub, snapshots pushed with `policy.set` on a fake clock, and a scripted Touch ID prompt.

use std::time::Duration;

use knsh_core::{Actor, AgentId, SessionState, Timestamp};
use knsh_json::{FromJson, Value};
use knsh_platform::NotAuthenticated;
use knsh_platform::testing::{FakeClock, RecordingLog, ScriptedPresence, SeededRandom};
use knsh_proto::ErrorCode;

use super::*;
use crate::dispatch::Endpoint;
use crate::grants::GrantStore;
use crate::policy::tests::{WEB, call_with, fs, loader};
use crate::policy_admin::{PolicyAdmin, PolicyAdminParts};
use crate::sessions::tests::{Fixture, event_names, fixture, watch};
use crate::sessions::{SessionBinding, StateChange};
use crate::state::StateStore;

/// The fake clock's start, as the session fixture's: 2027-01-15T08:00:00Z.
const NOW: u64 = 1_800_000_000;

/// A signed local profile.
const LOCAL: &str = "name = \"local\"\n[exec]\nallow = [\"ls\"]\n";

/// A signed local profile extending `web`.
const CHILD: &str = "name = \"child\"\nextends = \"web\"\n";

/// The `web` snapshot the authority pushes.
const PUSHED_WEB: &str = "name = \"web\"\n[exec]\nallow = [\"npm test\"]\n";

/// Everything one test drives.
struct Harness {
    fixture: Fixture,
    clock: Arc<FakeClock>,
    presence: Arc<ScriptedPresence>,
    expiry: Arc<PolicyExpiry>,
    profiles: ProfileLoader,
    /// `policy.set` and the other control-service policy methods.
    admin: Handlers,
}

/// The service over a fresh fixture, with the signed files `web`, `local` and `child` on disk and nothing pushed.
fn harness() -> Harness {
    let fixture = fixture();
    let clock = Arc::new(FakeClock::new(at(NOW)));
    let log = Arc::new(RecordingLog::new());
    let state = StateStore::in_memory(log.clone());
    let pushed = PushedPolicies::new(state, clock.clone(), Vec::new());
    let profiles = loader(fs(&[("web", WEB), ("local", LOCAL), ("child", CHILD)])).with_pushed(Arc::clone(&pushed));
    let presence = Arc::new(ScriptedPresence::new());
    let expiry = PolicyExpiry::new(
        Arc::clone(&fixture.sessions),
        Arc::clone(&pushed),
        profiles.clone(),
        presence.clone(),
        log.clone(),
    );
    let admin = PolicyAdmin::new(PolicyAdminParts {
        profiles: profiles.clone(),
        pushed,
        grants: GrantStore::new(),
        sessions: Arc::clone(&fixture.sessions),
        events: Arc::clone(&fixture.hub),
        expiry: Arc::clone(&expiry),
        clock: clock.clone(),
        random: Arc::new(SeededRandom::new(5)),
        presence: Arc::new(knsh_platform::testing::ScriptedPresence::new()),
        log,
    })
    .handlers();
    Harness {
        fixture,
        clock,
        presence,
        expiry,
        profiles,
        admin,
    }
}

fn at(seconds: u64) -> Timestamp {
    Timestamp::from_unix_micros(seconds * 1_000_000).unwrap()
}

impl Harness {
    /// An agent session on `profile`, opened as `knsh agent` opens one.
    fn agent(&self, profile: &str) -> SessionId {
        self.fixture
            .sessions
            .open_agent(
                Actor::Agent(AgentId::new("claude-code").unwrap()),
                ProfileName::new(profile).unwrap(),
            )
            .unwrap()
            .session_id
    }

    /// The authority pushes `text` for `profile`, expiring at `expires_at`.
    fn push(&self, profile: &str, text: &str, expires_at: u64) -> Reply {
        let text = knsh_json::write(&Value::from(text)).unwrap();
        let params = format!(
            r#"{{"profile":"{profile}","policy":{text},"expires_at":"{}"}}"#,
            at(expires_at)
        );
        call_with(
            &self.admin,
            Endpoint::Control,
            &SessionBinding::new(),
            "policy.set",
            &params,
        )
    }

    /// Moves the fake clock on by `seconds` and runs one watcher check.
    fn pass(&self, seconds: u64) {
        self.clock.advance(Duration::from_secs(seconds));
        self.expiry.check();
    }

    fn state(&self, session_id: SessionId) -> SessionState {
        self.fixture.sessions.info_of(session_id).unwrap().session.state()
    }

    fn profile(&self, session_id: SessionId) -> String {
        self.fixture
            .sessions
            .profile_of(session_id)
            .unwrap()
            .as_str()
            .to_owned()
    }

    /// Whether `profile` loads now, as a line would load it.
    fn loads(&self, profile: &str) -> bool {
        self.profiles
            .load(&ProfileName::new(profile).unwrap(), self.profiles.home())
            .is_ok()
    }

    /// `profile.use` with `params` on `endpoint`.
    fn use_on(&self, endpoint: Endpoint, params: &str) -> Reply {
        call_with(
            &self.expiry.handlers(),
            endpoint,
            &SessionBinding::new(),
            "profile.use",
            params,
        )
    }

    /// `profile.use` of `profile` on `user.sock`.
    fn use_profile(&self, profile: &str) -> Reply {
        self.use_on(Endpoint::User, &format!(r#"{{"profile":"{profile}"}}"#))
    }
}

fn used(reply: Reply) -> ProfileUseResult {
    ProfileUseResult::from_json(&reply.unwrap().result).unwrap()
}

/// `data.reason` of an error.
fn reason(error: &RpcError) -> String {
    error
        .data
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|data| data.get("reason"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

// FR-POL-51, FR-SES-13 (fake clock): at `expires_at`, every active agent session using the snapshot is paused with
// `session.state_changed`: its own profile or one extending it. Sessions on other profiles, and human sessions, are
// not touched; nothing is paused before expiry, and a second check changes nothing.
#[test]
fn pauses_sessions_on_snapshot_expiry() {
    let harness = harness();
    harness.push("web", PUSHED_WEB, NOW + 60).unwrap();
    let web = harness.agent("web");
    let child = harness.agent("child");
    let local = harness.agent("local");
    let watcher = watch(&harness.fixture.hub);

    harness.pass(59);
    assert_eq!(harness.state(web), SessionState::Active, "not yet expired");
    assert_eq!(event_names(&watcher), Vec::<String>::new());

    harness.pass(1);
    assert_eq!(harness.state(web), SessionState::Paused);
    assert_eq!(
        harness.state(child),
        SessionState::Paused,
        "extends the expired snapshot"
    );
    assert_eq!(harness.state(local), SessionState::Active, "uses no pushed policy");
    assert_eq!(
        event_names(&watcher),
        ["session.state_changed", "session.state_changed"]
    );
    let paused: Vec<SessionId> = harness
        .fixture
        .sessions
        .expiry_paused()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(paused.len(), 2);
    assert!(paused.contains(&web) && paused.contains(&child));

    harness.pass(1);
    assert!(event_names(&watcher).is_empty(), "already paused");
}

// FR-SES-22: a session under human control is the human's; it is paused once handed back. A human session is never
// paused.
#[test]
fn pauses_sessions_handed_back_after_expiry() {
    let harness = harness();
    harness.push("web", PUSHED_WEB, NOW + 60).unwrap();
    let web = harness.agent("web");
    harness
        .fixture
        .sessions
        .change_state(web, StateChange::TakeControl)
        .unwrap();
    harness.pass(60);
    assert_eq!(harness.state(web), SessionState::HumanControl);
    harness
        .fixture
        .sessions
        .change_state(web, StateChange::HandBack)
        .unwrap();
    harness.expiry.check();
    assert_eq!(harness.state(web), SessionState::Paused);
    assert!(
        harness.fixture.sessions.pause_for_expiry(web).is_err(),
        "already paused"
    );

    let binding = SessionBinding::new();
    call_with(
        &harness.fixture.sessions.handlers(),
        Endpoint::User,
        &binding,
        "session.start_human",
        "{}",
    )
    .unwrap();
    let human = binding.session_id().unwrap();
    assert_eq!(
        harness.fixture.sessions.pause_for_expiry(human).unwrap_err().code,
        ErrorCode::NotAllowed
    );
    assert_eq!(harness.state(human), SessionState::Active);
}

// FR-POL-51: a new valid snapshot resumes the sessions paused by its expiry, under their own profile; the new
// snapshot is what they load. A session the authority paused itself before expiry stays paused.
#[test]
fn resumes_on_new_snapshot() {
    let harness = harness();
    harness.push("web", PUSHED_WEB, NOW + 60).unwrap();
    let web = harness.agent("web");
    let child = harness.agent("child");
    let held = harness.agent("web");
    harness.fixture.sessions.change_state(held, StateChange::Pause).unwrap();
    harness.pass(60);
    assert_eq!(harness.state(web), SessionState::Paused);

    let watcher = watch(&harness.fixture.hub);
    harness.push("web", PUSHED_WEB, NOW + 3600).unwrap();
    assert_eq!(harness.state(web), SessionState::Active);
    assert_eq!(harness.state(child), SessionState::Active);
    assert_eq!(harness.profile(web), "web", "its own profile, from the new snapshot");
    assert!(harness.loads("web"));
    assert_eq!(
        harness.state(held),
        SessionState::Paused,
        "paused by the authority, not by expiry"
    );
    assert_eq!(
        event_names(&watcher),
        ["session.state_changed", "session.state_changed"]
    );
    assert_eq!(harness.fixture.sessions.expiry_paused(), Vec::new());
}

// FR-POL-51: a snapshot that does not let the session's profile load (another profile's) resumes nothing.
#[test]
fn snapshot_of_another_profile_resumes_nothing() {
    let harness = harness();
    harness.push("web", PUSHED_WEB, NOW + 60).unwrap();
    let web = harness.agent("web");
    harness.pass(60);
    harness.push("other", "name = \"other\"\n", NOW + 3600).unwrap();
    assert_eq!(harness.state(web), SessionState::Paused);
}

// FR-POL-51, NFR-SEC-04: `knsh profile use` moves nothing without knshd's own prompt succeeding; the prompt names
// the profile and how many sessions; after it, the paused sessions run under the local profile and resume.
#[test]
fn profile_use_requires_authentication() {
    let harness = harness();
    harness.push("web", PUSHED_WEB, NOW + 60).unwrap();
    let web = harness.agent("web");
    let child = harness.agent("child");
    harness.pass(60);

    for refusal in [NotAuthenticated::TimedOut, NotAuthenticated::Cancelled] {
        if refusal != NotAuthenticated::TimedOut {
            harness.presence.refuse_next(refusal);
        }
        let error = harness.use_profile("local").unwrap_err();
        assert_eq!(error.code, ErrorCode::Denied);
        assert_eq!(harness.state(web), SessionState::Paused);
        assert_eq!(harness.profile(web), "web", "nothing changed");
    }
    let prompts = harness.presence.prompts();
    assert_eq!(prompts.len(), 2);
    assert_eq!(
        prompts[0].reason,
        "use the local policy profile: local for 2 agent sessions paused by expired pushed policy"
    );

    harness.presence.approve_next();
    let watcher = watch(&harness.fixture.hub);
    let result = used(harness.use_profile("local"));
    assert_eq!(result.profile.as_str(), "local");
    // In ID order; both IDs are from the same millisecond, so compare them as a set.
    let mut moved = result.sessions.clone();
    moved.sort();
    let mut expected = vec![web, child];
    expected.sort();
    assert_eq!(moved, expected);
    for session in [web, child] {
        assert_eq!(harness.state(session), SessionState::Active);
        assert_eq!(harness.profile(session), "local");
    }
    assert_eq!(
        event_names(&watcher),
        ["session.state_changed", "session.state_changed"]
    );

    // Nothing paused any more: no prompt, nothing moved.
    let again = used(harness.use_profile("local"));
    assert_eq!(again.sessions, Vec::new());
    assert_eq!(harness.presence.prompts().len(), 3);
}

// FR-POL-51: only signed local profiles are accepted, before any prompt: not the built-in profile, not a pushed one,
// not one extending a pushed one, not an unsigned or missing file. Only `user.sock` may select one.
#[test]
fn profile_use_accepts_only_signed_local_profiles() {
    let harness = harness();
    harness.push("web", PUSHED_WEB, NOW + 60).unwrap();
    let web = harness.agent("web");
    harness.pass(60);
    for (profile, expected) in [
        ("unattended", "built in"),
        ("web", "pushed by the authority"),
        ("child", "extends web"),
        ("missing", "not found"),
    ] {
        let error = harness.use_profile(profile).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams, "{profile}");
        assert!(reason(&error).contains(expected), "{profile}: {}", reason(&error));
    }
    let error = harness.use_profile("../web").unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidParams);

    for endpoint in [Endpoint::Agent, Endpoint::Control] {
        harness.presence.approve_next();
        assert_eq!(
            harness.use_on(endpoint, r#"{"profile":"local"}"#).unwrap_err().code,
            ErrorCode::NotAllowed
        );
    }
    assert!(harness.presence.prompts().is_empty(), "nothing was asked");
    assert_eq!(harness.state(web), SessionState::Paused);
}

// FR-POL-51: an unsigned local file is refused, as the loader ignores it (FR-POL-42).
#[test]
fn profile_use_refuses_unsigned_files() {
    let harness = harness();
    harness
        .profiles
        .fs()
        .write(
            &crate::policy::tests::policies().join("plain.toml"),
            b"name = \"plain\"\n",
            0o600,
        )
        .unwrap();
    harness.push("web", PUSHED_WEB, NOW + 60).unwrap();
    harness.agent("web");
    harness.pass(60);
    let error = harness.use_profile("plain").unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidParams);
    assert_eq!(harness.presence.prompts().len(), 0);
}

// FR-POL-52: after expiry a session keeps its profile, which loads from nothing (never from the file of its name);
// the authority's `session.resume` cannot resume it, and neither the watcher nor anything else switches it. Only a
// new snapshot or `knsh profile use` does (the two tests above).
#[test]
fn never_falls_back_silently() {
    let harness = harness();
    harness.push("web", PUSHED_WEB, NOW + 60).unwrap();
    let web = harness.agent("web");
    harness.pass(60);
    for _ in 0..3 {
        harness.pass(3600);
    }
    assert_eq!(harness.profile(web), "web");
    assert!(
        !harness.loads("web"),
        "the signed file of the same name is never read in its place"
    );
    assert_eq!(harness.state(web), SessionState::Paused);
    assert_eq!(
        harness
            .fixture
            .sessions
            .change_state(web, StateChange::Resume)
            .unwrap_err()
            .code,
        ErrorCode::SessionNotFound,
        "session.resume cannot resume it"
    );
    assert_eq!(
        harness
            .fixture
            .sessions
            .release_from_expiry(harness.agent("local"))
            .unwrap_err()
            .code,
        ErrorCode::SessionNotFound,
        "only sessions paused by expiry are released"
    );
    assert_eq!(harness.state(web), SessionState::Paused);
    assert_eq!(harness.profile(web), "web");
}

// The mark goes with the session: one that ends while paused by expiry is not listed or moved afterwards.
#[test]
fn ended_sessions_are_forgotten() {
    let harness = harness();
    harness.push("web", PUSHED_WEB, NOW + 60).unwrap();
    let web = harness.agent("web");
    harness.pass(60);
    harness.fixture.sessions.end_agent(web);
    assert_eq!(harness.fixture.sessions.expiry_paused(), Vec::new());
    assert_eq!(used(harness.use_profile("local")).sessions, Vec::new());
}

// FR-SES-13: the watcher thread pauses sessions on its own, with no call to wake it.
#[test]
fn watcher_pauses_without_a_call() {
    let harness = harness();
    harness.push("web", PUSHED_WEB, NOW + 60).unwrap();
    let web = harness.agent("web");
    harness.expiry.watch(Duration::from_millis(5)).unwrap();
    harness.clock.advance(Duration::from_secs(60));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while harness.state(web) != SessionState::Paused && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(harness.state(web), SessionState::Paused);
}
