//! The authority's policy and grant methods (KNSH-071): pushed snapshots through the profile loader, grants in the
//! state store, `policy.updated` on the event hub.

use std::path::Path;

use knsh_core::{AgentId, Delivery, EventScope, ProfileName, SessionId};
use knsh_json::{Object, Value};
use knsh_platform::engine_dirs::FILE_MODE;
use std::sync::Mutex;
use std::time::Duration;

use knsh_platform::testing::{DEFAULT_UID, FakeClock, MemFs, RecordingLog, ScriptedPresence, SeededRandom};
use knsh_platform::{Authenticated, FileKind, Fs, NotAuthenticated};
use knsh_proto::Denial;

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

/// Something that happens while the prompt is on the screen.
type DuringPrompt = Box<dyn FnOnce() + Send>;

/// The scripted prompt, which can also run something while it is up (the user takes their time).
#[derive(Default)]
struct Presence {
    scripted: ScriptedPresence,
    during: Mutex<Option<DuringPrompt>>,
}

impl Presence {
    /// Runs `action` during the next prompt, before it is answered.
    fn during_next(&self, action: impl FnOnce() + Send + 'static) {
        *self.during.lock().unwrap() = Some(Box::new(action));
    }
}

impl UserPresence for Presence {
    fn authenticate(&self, reason: &PromptReason, timeout: Duration) -> Result<Authenticated, NotAuthenticated> {
        if let Some(action) = self.during.lock().unwrap().take() {
            action();
        }
        self.scripted.authenticate(reason, timeout)
    }
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
    /// The prompt the user's `policy.grant` shows.
    presence: Arc<Presence>,
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
        let (state, restored) = StateStore::open(
            state_fs.clone(),
            crate::state::tests::path(),
            DEFAULT_UID,
            clock.now().ok(),
            log.clone(),
        );
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
        let presence = Arc::new(Presence::default());
        let handlers = PolicyAdmin::new(PolicyAdminParts {
            profiles: profiles.clone(),
            pushed,
            grants: Arc::clone(&grants),
            sessions: Arc::clone(&fixture.sessions),
            events: Arc::clone(&fixture.hub),
            expiry,
            clock: clock.clone(),
            random: Arc::new(SeededRandom::new(9)),
            presence: presence.clone(),
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
            presence,
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

    /// `method` on `user.sock`.
    fn user(&self, method: &'static str, params: &str) -> Reply {
        call_with(&self.handlers, Endpoint::User, &SessionBinding::new(), method, params)
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

// Pushing and reading policy answer on the control service only.
#[test]
fn refuses_calls_off_the_control_service() {
    let admin = Admin::new();
    for endpoint in [Endpoint::User, Endpoint::Agent] {
        for method in ["policy.set", "policy.get"] {
            let error = call_with(&admin.handlers, endpoint, &SessionBinding::new(), method, "{}").unwrap_err();
            assert_eq!(error.code, ErrorCode::NotAllowed, "{method}");
        }
    }
}

/// `policy.grant` params for profile `web`.
fn profile_grant(rule: &str, duration_s: u64) -> String {
    format!(r#"{{"scope":"profile","profile":"web","rule":"{rule}","duration_s":{duration_s}}}"#)
}

// FR-POL-62, NFR-SEC-04 (KNSH-073): on user.sock a grant is made only after knshd's own prompt succeeds, and the prompt
// names the rule, the scope and the duration. A refusal, a cancel, and no answer at all (nobody at the Mac) each deny
// with source `user`, and nothing is granted or saved. No parameter skips the prompt.
#[test]
fn user_grant_requires_authentication() {
    let admin = Admin::new();
    admin.presence.scripted.refuse_next(NotAuthenticated::Failed);
    admin.presence.scripted.refuse_next(NotAuthenticated::Cancelled);
    for _ in 0..3 {
        let error = admin
            .user("policy.grant", &profile_grant("git push", 5400))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Denied);
        let denial = Denial::from_error(&error).unwrap();
        assert_eq!(denial.source.as_deref(), Some("user"));
        assert!(denial.reason.unwrap().starts_with("not authenticated: "));
        assert!(
            admin.grants.list(admin.clock.now().unwrap()).is_empty(),
            "nothing was granted"
        );
        let saved = admin
            .state_fs
            .contents(&crate::state::tests::path())
            .unwrap_or_default();
        assert!(!String::from_utf8_lossy(&saved).contains("git push"), "nothing saved");
    }
    // A member claiming the user is present is ignored like any unknown one: the prompt still decides.
    let claimed = r#"{"scope":"profile","profile":"web","rule":"git push","duration_s":60,"authenticated":true}"#;
    assert_eq!(admin.user("policy.grant", claimed).unwrap_err().code, ErrorCode::Denied);

    admin.presence.scripted.approve_next();
    let granted = admin.user("policy.grant", &profile_grant("git push", 5400)).unwrap();
    let granted = granted.result.as_object().unwrap();
    assert_eq!(granted.get("expires_at"), Some(&Value::from(at(NOW + 5400))));
    assert_eq!(admin.grants.list(admin.clock.now().unwrap()).len(), 1);

    let prompts = admin.presence.scripted.prompts();
    assert_eq!(prompts.len(), 5, "every attempt prompts afresh");
    assert_eq!(
        prompts[4].reason,
        "grant the agent command rule: git push (profile web, for 1h 30m)"
    );
    assert_eq!(prompts[4].timeout, GRANT_PROMPT_TIMEOUT);

    // A session-scoped grant names the session; the rule is escaped so it reads exactly as it applies: an invisible
    // zero-width space is shown, never hidden.
    let session = admin.agent();
    admin.presence.scripted.approve_next();
    let params = format!(r#"{{"scope":"session","session_id":"{session}","rule":"git\u200bpush","duration_s":86461}}"#);
    admin.user("policy.grant", &params).unwrap();
    assert_eq!(
        admin.presence.scripted.prompts()[5].reason,
        format!("grant the agent command rule: git\\u{{200B}}push (session {session}, for 1d 1m 1s)")
    );
}

// FR-POL-62: nothing the engine would refuse is put to the user: a rule that is not a command pattern, a session that
// is not a live agent session, or a duration out of range is refused without a prompt.
#[test]
fn user_grant_checks_before_prompting() {
    let admin = Admin::new();
    let unknown = SessionId::from_ulid(knsh_core::Ulid::from_u128(77));
    for (params, code) in [
        (profile_grant("/bin/rm", 60), ErrorCode::InvalidParams),
        (profile_grant("   ", 60), ErrorCode::InvalidParams),
        (profile_grant("ls", 0), ErrorCode::InvalidParams),
        (
            format!(r#"{{"scope":"session","session_id":"{unknown}","rule":"ls","duration_s":60}}"#),
            ErrorCode::SessionNotFound,
        ),
    ] {
        assert_eq!(admin.user("policy.grant", &params).unwrap_err().code, code, "{params}");
    }
    assert!(admin.presence.scripted.prompts().is_empty(), "nothing was asked");
}

// FR-POL-62: the session may end while the prompt is up; no grant is made for it, even once the user agrees. And a
// grant lasts its duration from when the user agreed, not from when it was asked.
#[test]
fn user_grant_rechecks_after_the_prompt() {
    let admin = Admin::new();
    let session = admin.agent();
    let sessions = Arc::clone(&admin.fixture.sessions);
    admin.presence.during_next(move || sessions.end_agent(session));
    admin.presence.scripted.approve_next();
    let params = format!(r#"{{"scope":"session","session_id":"{session}","rule":"ls","duration_s":60}}"#);
    assert_eq!(
        admin.user("policy.grant", &params).unwrap_err().code,
        ErrorCode::SessionNotFound
    );
    assert!(
        admin.grants.list(admin.clock.now().unwrap()).is_empty(),
        "nothing was granted"
    );

    let clock = Arc::clone(&admin.clock);
    admin
        .presence
        .during_next(move || clock.advance(Duration::from_secs(90)));
    admin.presence.scripted.approve_next();
    let granted = admin.user("policy.grant", &profile_grant("ls", 60)).unwrap();
    assert_eq!(
        granted.result.as_object().unwrap().get("expires_at"),
        Some(&Value::from(at(NOW + 90 + 60)))
    );
}

// FR-POL-61, FR-POL-62 (KNSH-073): the user's grants are the authority's kind: both list them, both revoke them, and
// listing or revoking on user.sock needs no prompt.
#[test]
fn user_grants_are_listed_and_revocable_like_authority_grants() {
    let admin = Admin::new();
    admin.presence.scripted.approve_next();
    let granted = admin.user("policy.grant", &profile_grant("git push", 60)).unwrap();
    let grant_id = granted
        .result
        .as_object()
        .unwrap()
        .get("grant_id")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let by_authority = admin.ok("policy.grant", &profile_grant("npm test", 60));
    let authority_id = by_authority.get("grant_id").and_then(Value::as_str).unwrap().to_owned();
    assert!(admin.state_file().contains(&grant_id), "saved before it applies");

    for endpoint in [Endpoint::User, Endpoint::Control] {
        let listed = call_with(&admin.handlers, endpoint, &SessionBinding::new(), "policy.grants", "{}").unwrap();
        let grants = listed
            .result
            .as_object()
            .unwrap()
            .get("grants")
            .and_then(Value::as_array)
            .unwrap()
            .clone();
        let mut ids: Vec<_> = grants
            .iter()
            .map(|grant| {
                grant
                    .as_object()
                    .unwrap()
                    .get("grant_id")
                    .and_then(Value::as_str)
                    .unwrap()
                    .to_owned()
            })
            .collect();
        // Listed in ID order; both were made in the same millisecond, so compare as a set.
        ids.sort();
        let mut expected = [grant_id.clone(), authority_id.clone()];
        expected.sort();
        assert_eq!(ids, expected, "{}", endpoint.name());
    }
    // The authority revokes the user's grant, the user the authority's.
    for (endpoint, id) in [(Endpoint::Control, &grant_id), (Endpoint::User, &authority_id)] {
        let revoke = format!(r#"{{"grant_id":"{id}"}}"#);
        let answer = call_with(
            &admin.handlers,
            endpoint,
            &SessionBinding::new(),
            "policy.revoke",
            &revoke,
        )
        .unwrap();
        assert_eq!(
            answer.result.as_object().unwrap().get("revoked"),
            Some(&Value::from(true))
        );
    }
    assert!(
        admin.grants.list(admin.clock.now().unwrap()).is_empty(),
        "nothing was granted"
    );
    assert_eq!(admin.presence.scripted.prompts().len(), 1, "only the grant prompted");
}

// FR-POL-62 (KNSH-073): agent.sock can never make, list or revoke a grant, whatever it sends; the prompt never shows.
#[test]
fn user_grant_absent_on_agent_socket() {
    let admin = Admin::new();
    admin.presence.scripted.approve_next();
    for (method, params) in [
        ("policy.grant", profile_grant("git push", 60)),
        ("policy.grants", String::from("{}")),
        (
            "policy.revoke",
            format!(r#"{{"grant_id":"{}"}}"#, knsh_core::Ulid::from_u128(1)),
        ),
    ] {
        let error = call_with(
            &admin.handlers,
            Endpoint::Agent,
            &SessionBinding::new(),
            method,
            &params,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed, "{method}");
    }
    assert!(admin.presence.scripted.prompts().is_empty(), "nothing was asked");
    assert!(
        admin.grants.list(admin.clock.now().unwrap()).is_empty(),
        "nothing was granted"
    );
}
