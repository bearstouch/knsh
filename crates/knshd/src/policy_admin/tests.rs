//! The authority's policy and grant methods (KNSH-071): pushed snapshots through the profile loader, grants in the
//! state store, `policy.updated` on the event hub.

use std::path::Path;

use knsh_core::{AgentId, Delivery, EventScope, ProfileName, SessionId};
use knsh_json::{Object, Value};
use knsh_platform::engine_dirs::FILE_MODE;
use knsh_platform::testing::{DEFAULT_UID, FakeClock, MemFs, RecordingLog, SeededRandom};
use knsh_platform::{FileKind, Fs};

use super::*;
use crate::dispatch::{Endpoint, Handlers};
use crate::events::Subscriber;
use crate::policy::tests::{WEB, call_with, fs, loader};
use crate::sessions::SessionBinding;
use crate::sessions::tests::{Fixture, fixture};
use crate::state::StateStore;

/// The fake clock's start: 2027-01-15T08:00:00Z.
const NOW: u64 = 1_800_000_000;

fn at(seconds: u64) -> String {
    Timestamp::from_unix_micros(seconds * 1_000_000).unwrap().to_string()
}

/// Everything one test drives: the handlers and what they act on.
struct Admin {
    fixture: Fixture,
    handlers: Handlers,
    profiles: ProfileLoader,
    grants: Arc<GrantStore>,
    /// The file system holding the state file.
    state_fs: Arc<MemFs>,
    clock: Arc<FakeClock>,
}

impl Admin {
    /// The methods over a fresh fixture, a state file on its own file system, and the signed profile `web` on disk.
    fn new() -> Self {
        let state_fs = crate::state::tests::fs();
        Self::with_state(state_fs)
    }

    /// The methods with the state store opened from `state_fs` (restoring what it holds, as `knshd` does at start).
    fn with_state(state_fs: Arc<MemFs>) -> Self {
        let fixture = fixture();
        let clock = Arc::new(FakeClock::new(Timestamp::from_unix_micros(NOW * 1_000_000).unwrap()));
        let log = Arc::new(RecordingLog::new());
        let (state, restored) =
            StateStore::open(state_fs.clone(), crate::state::tests::path(), DEFAULT_UID, log.clone());
        let pushed = PushedPolicies::new(Arc::clone(&state), clock.clone(), restored.snapshots);
        let grants = GrantStore::persisted(state, log.clone(), restored.grants, clock.now().ok());
        let profiles = loader(fs(&[("web", WEB)])).with_pushed(Arc::clone(&pushed));
        let expiry = crate::expiry::PolicyExpiry::new(
            Arc::clone(&fixture.sessions),
            Arc::clone(&pushed),
            profiles.clone(),
            Arc::new(knsh_platform::testing::ScriptedPresence::new()),
            log.clone(),
        );
        let handlers = PolicyAdmin::new(PolicyAdminParts {
            profiles: profiles.clone(),
            pushed,
            grants: Arc::clone(&grants),
            sessions: Arc::clone(&fixture.sessions),
            events: Arc::clone(&fixture.hub),
            expiry,
            clock: clock.clone(),
            random: Arc::new(SeededRandom::new(9)),
            log,
        })
        .handlers();
        Self {
            fixture,
            handlers,
            profiles,
            grants,
            state_fs,
            clock,
        }
    }

    fn call(&self, method: &'static str, params: &str) -> Reply {
        call_with(
            &self.handlers,
            Endpoint::Control,
            &SessionBinding::new(),
            method,
            params,
        )
    }

    fn ok(&self, method: &'static str, params: &str) -> Object {
        self.call(method, params).unwrap().result.as_object().cloned().unwrap()
    }

    fn code(&self, method: &'static str, params: &str) -> ErrorCode {
        self.call(method, params).unwrap_err().code
    }

    /// An agent session running `web`.
    fn agent(&self) -> SessionId {
        self.fixture
            .sessions
            .open_agent(
                knsh_core::Actor::Agent(AgentId::new("claude-code").unwrap()),
                ProfileName::new("web").unwrap(),
            )
            .unwrap()
            .session_id
    }

    /// The state file's JSON.
    fn state_file(&self) -> String {
        String::from_utf8(self.state_fs.contents(&crate::state::tests::path()).unwrap()).unwrap()
    }
}

/// `policy.set` params for profile `profile` with `text`, expiring at `expires_at` (omitted when `None`).
fn set_params(profile: &str, text: &str, expires_at: Option<u64>) -> String {
    let text = knsh_json::write(&Value::from(text)).unwrap();
    match expires_at {
        Some(seconds) => format!(
            r#"{{"profile":"{profile}","policy":{text},"expires_at":"{}"}}"#,
            at(seconds)
        ),
        None => format!(r#"{{"profile":"{profile}","policy":{text}}}"#),
    }
}

/// A pushed `web` that allows `npm test` only.
const PUSHED_WEB: &str = "name = \"web\"\n[exec]\nallow = [\"npm test\"]\n";

// FR-POL-50 (KNSH-071): a snapshot is accepted only with an `expires_at` still to come, and only when it loads with
// the loader files go through (FR-POL-01); `unattended` is never replaced. Nothing refused changes what loads.
#[test]
fn policy_set_requires_expires_at() {
    let admin = Admin::new();
    assert_eq!(
        admin.code("policy.set", &set_params("web", PUSHED_WEB, None)),
        ErrorCode::InvalidParams
    );
    assert_eq!(
        admin.code("policy.set", &set_params("web", PUSHED_WEB, Some(NOW))),
        ErrorCode::InvalidParams,
        "already expired"
    );
    assert_eq!(
        admin.code(
            "policy.set",
            &set_params("web", "name = \"web\"\n[exec\n", Some(NOW + 60))
        ),
        ErrorCode::InvalidParams,
        "not a profile"
    );
    assert_eq!(
        admin.code(
            "policy.set",
            &set_params("web", "name = \"web\"\nextends = \"missing\"\n", Some(NOW + 60))
        ),
        ErrorCode::InvalidParams,
        "its parent does not load"
    );
    assert_eq!(
        admin.code(
            "policy.set",
            &set_params("unattended", "name = \"unattended\"\n", Some(NOW + 60))
        ),
        ErrorCode::InvalidParams
    );
    let web = ProfileName::new("web").unwrap();
    let home = Path::new("/Users/u/app");
    let file = admin.profiles.load(&web, home).unwrap();
    assert!(file.exec.allow.iter().any(|rule| rule.contains("git status")));

    let set = admin.ok("policy.set", &set_params("web", PUSHED_WEB, Some(NOW + 60)));
    assert_eq!(set.get("replaced"), Some(&Value::Bool(false)));
    let pushed = admin.profiles.load(&web, home).unwrap();
    assert!(pushed.exec.allow.iter().any(|rule| rule.contains("npm test")));
    assert!(!pushed.exec.allow.iter().any(|rule| rule.contains("git status")));

    // FR-POL-52: once it expires, the profile loads from nothing, never from its file again.
    admin.clock.advance(std::time::Duration::from_secs(60));
    assert!(admin.profiles.load(&web, home).is_err());
    let got = admin.ok("policy.get", r#"{"profile":"web"}"#);
    assert_eq!(got.get("expired"), Some(&Value::Bool(true)));
}

// FR-POL-53 (KNSH-071): loading a snapshot publishes `policy.updated`, an engine event naming the profile and its
// expiry, to subscriptions to every session; a refused snapshot publishes nothing.
#[test]
fn policy_set_emits_policy_updated() {
    let admin = Admin::new();
    let watcher = Subscriber::new();
    watcher.subscribe(&admin.fixture.hub, EventScope::All, None).unwrap();
    admin.code("policy.set", &set_params("web", PUSHED_WEB, None));
    admin.ok("policy.set", &set_params("web", PUSHED_WEB, Some(NOW + 60)));
    let engine: Vec<_> = watcher
        .take(100)
        .into_iter()
        .filter_map(|(_, delivery)| match delivery {
            Delivery::Engine(event) => Some(event.data.clone()),
            Delivery::Event(_) | Delivery::Lost(_) | Delivery::EngineLost(_) => None,
        })
        .collect();
    assert_eq!(
        engine,
        [EngineEventData::PolicyUpdated {
            profile: ProfileName::new("web").unwrap(),
            expires_at: Timestamp::from_unix_micros((NOW + 60) * 1_000_000).unwrap(),
        }]
    );
}

// KNSH-071: `policy.get` says where a name loads from: a pushed snapshot, a signed file, or the built-in profile.
#[test]
fn policy_get_reports_where_a_profile_comes_from() {
    let admin = Admin::new();
    let file = admin.ok("policy.get", r#"{"profile":"web"}"#);
    assert_eq!(file.get("source"), Some(&Value::from("file")));
    assert_eq!(file.get("policy"), Some(&Value::from(WEB)));
    assert_eq!(file.get("expires_at"), Some(&Value::Null));
    admin.ok("policy.set", &set_params("web", PUSHED_WEB, Some(NOW + 60)));
    let pushed = admin.ok("policy.get", r#"{"profile":"web"}"#);
    assert_eq!(pushed.get("source"), Some(&Value::from("pushed")));
    assert_eq!(pushed.get("policy"), Some(&Value::from(PUSHED_WEB)));
    assert_eq!(pushed.get("expired"), Some(&Value::Bool(false)));
    let builtin = admin.ok("policy.get", r#"{"profile":"unattended"}"#);
    assert_eq!(builtin.get("source"), Some(&Value::from("builtin")));
    assert_eq!(
        admin.code("policy.get", r#"{"profile":"nope"}"#),
        ErrorCode::InvalidParams
    );
}

// FR-POL-60, FR-POL-61 (KNSH-071): a grant has an ID, a scope and an `expires_at`; it is listed, applies to lines,
// and `policy.revoke` removes it at once, from the list, the live grants and the state file.
#[test]
fn grant_revoke_removes_grant() {
    let admin = Admin::new();
    let session_id = admin.agent();
    let granted = admin.ok(
        "policy.grant",
        &format!(r#"{{"scope":"session","session_id":"{session_id}","rule":"git push","duration_s":3600}}"#),
    );
    let grant_id = granted.get("grant_id").and_then(Value::as_str).unwrap().to_owned();
    assert_eq!(granted.get("expires_at"), Some(&Value::from(at(NOW + 3600))));
    let listed = admin.ok("policy.grants", "{}");
    let grants = listed.get("grants").and_then(Value::as_array).unwrap();
    assert_eq!(grants.len(), 1);
    let entry = grants[0].as_object().unwrap();
    assert_eq!(entry.get("grant_id"), Some(&Value::from(grant_id.as_str())));
    assert_eq!(entry.get("scope"), Some(&Value::from("session")));
    assert_eq!(entry.get("session_id"), Some(&Value::from(session_id.to_string())));
    assert_eq!(entry.get("rule"), Some(&Value::from("git push")));
    assert!(admin.state_file().contains(&grant_id), "saved before it applies");
    assert_eq!(admin.grants.snapshot().list(admin.clock.now().unwrap()).count(), 1);

    let revoke = format!(r#"{{"grant_id":"{grant_id}"}}"#);
    assert_eq!(
        admin.ok("policy.revoke", &revoke).get("revoked"),
        Some(&Value::Bool(true))
    );
    let listed = admin.ok("policy.grants", "{}");
    assert_eq!(listed.get("grants").and_then(Value::as_array).map(Vec::len), Some(0));
    assert_eq!(admin.grants.snapshot().list(admin.clock.now().unwrap()).count(), 0);
    assert!(!admin.state_file().contains(&grant_id));
    assert_eq!(
        admin.ok("policy.revoke", &revoke).get("revoked"),
        Some(&Value::Bool(false))
    );
}

// FR-POL-62: grants are checked as they are made: a rule that is not a command pattern, a session that is not a
// live agent session, or a duration out of range is refused and nothing is granted.
#[test]
fn refuses_grants_it_cannot_make() {
    let admin = Admin::new();
    let session_id = admin.agent();
    assert_eq!(
        admin.code(
            "policy.grant",
            &format!(r#"{{"scope":"session","session_id":"{session_id}","rule":"/bin/rm -rf","duration_s":60}}"#)
        ),
        ErrorCode::InvalidParams
    );
    let gone = SessionId::from_ulid(knsh_core::Ulid::from_u128(77));
    assert_eq!(
        admin.code(
            "policy.grant",
            &format!(r#"{{"scope":"session","session_id":"{gone}","rule":"ls","duration_s":60}}"#)
        ),
        ErrorCode::SessionNotFound
    );
    assert_eq!(
        admin.code(
            "policy.grant",
            r#"{"scope":"profile","profile":"web","rule":"ls","duration_s":0}"#
        ),
        ErrorCode::InvalidParams
    );
    assert_eq!(admin.grants.list(admin.clock.now().unwrap()).len(), 0);
    // A profile-scoped grant needs no live session.
    admin.ok(
        "policy.grant",
        r#"{"scope":"profile","profile":"web","rule":"ls","duration_s":60}"#,
    );
}

// FR-POL-60, NFR-SEC-08 (KNSH-071): pushed policy and grants are saved owner-only, atomically, and come back when the
// state store is opened again, as after a restart.
#[test]
fn persists_pushed_policy_and_grants() {
    let admin = Admin::new();
    admin.ok("policy.set", &set_params("web", PUSHED_WEB, Some(NOW + 600)));
    admin.ok(
        "policy.grant",
        r#"{"scope":"profile","profile":"web","rule":"npm test","duration_s":600}"#,
    );
    let meta = admin.state_fs.metadata(&crate::state::tests::path()).unwrap();
    assert_eq!(
        (meta.kind, meta.mode, meta.uid),
        (FileKind::File, FILE_MODE, DEFAULT_UID)
    );

    let restarted = Admin::with_state(admin.state_fs.clone());
    let got = restarted.ok("policy.get", r#"{"profile":"web"}"#);
    assert_eq!(got.get("source"), Some(&Value::from("pushed")));
    assert_eq!(restarted.grants.list(restarted.clock.now().unwrap()).len(), 1);
}

// The methods answer on the control service only.
#[test]
fn refuses_calls_off_the_control_service() {
    let admin = Admin::new();
    for endpoint in [Endpoint::User, Endpoint::Agent] {
        let error = call_with(&admin.handlers, endpoint, &SessionBinding::new(), "policy.grants", "{}").unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed);
    }
}
