//! The authority's session methods (KNSH-071), on the session registry with a real record store and event hub.

use knsh_core::{AgentId, ProfileName, Redacted, SessionId};
use knsh_json::Value;
use knsh_proto::ErrorCode;

use super::*;
use crate::dispatch::Handlers;
use crate::policy::tests::{WEB, call_with, fs, loader};
use crate::sessions::SessionBinding;
use crate::sessions::tests::{Fixture, event_names, fixture, watch};

/// The fixture and the authority's session handlers over it, with the profile `web` signed on disk.
fn setup() -> (Fixture, Handlers) {
    let fixture = fixture();
    let handlers = Supervise::new(Arc::clone(&fixture.sessions), loader(fs(&[("web", WEB)]))).handlers();
    (fixture, handlers)
}

/// `method` with `params` on the control service.
pub(crate) fn control(handlers: &Handlers, method: &'static str, params: &str) -> Reply {
    call_with(handlers, Endpoint::Control, &SessionBinding::new(), method, params)
}

fn result(reply: Reply) -> knsh_json::Object {
    reply.unwrap().result.as_object().cloned().unwrap()
}

fn text<'a>(object: &'a knsh_json::Object, key: &str) -> &'a str {
    object.get(key).and_then(Value::as_str).unwrap()
}

/// An agent session opened as `knsh agent` opens one.
fn agent(fixture: &Fixture) -> SessionId {
    fixture
        .sessions
        .open_agent(
            Actor::Agent(AgentId::new("claude-code").unwrap()),
            ProfileName::new("web").unwrap(),
        )
        .unwrap()
        .session_id
}

/// A human session, as `knsh` starts one.
fn human(fixture: &Fixture) -> (SessionBinding, SessionId) {
    let binding = SessionBinding::new();
    call_with(
        &fixture.sessions.handlers(),
        Endpoint::User,
        &binding,
        "session.start_human",
        "{}",
    )
    .unwrap();
    let session_id = binding.session_id().unwrap();
    (binding, session_id)
}

// FR-SES-02 (KNSH-071): the authority creates an agent session with no envelope; its token binds an `agent.sock`
// connection to it, and the session is listed. A profile that does not exist creates nothing.
#[test]
fn creates_agent_sessions_for_the_authority() {
    let (fixture, handlers) = setup();
    let watcher = watch(&fixture.hub);
    let created = result(control(
        &handlers,
        "session.create",
        r#"{"agent":"my-agent","profile":"web"}"#,
    ));
    let session_id: SessionId = text(&created, "session_id").parse().unwrap();
    let token = Redacted::new(text(&created, "session_token").to_owned());
    let binding = SessionBinding::new();
    assert_eq!(fixture.sessions.bind_agent(&binding, Some(&token)), Ok(session_id));
    let info = fixture.sessions.info_of(session_id).unwrap();
    assert!(!info.session.envelope());
    assert_eq!(info.session.actor().agent_id().unwrap().as_str(), "my-agent");
    assert_eq!(event_names(&watcher), ["session.started"]);

    let listed = result(control(&handlers, "session.list", "{}"));
    let sessions = listed.get("sessions").and_then(Value::as_array).unwrap();
    assert_eq!(sessions.len(), 1);

    let error = control(&handlers, "session.create", r#"{"agent":"my-agent","profile":"nope"}"#).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidParams);
    let error = control(&handlers, "session.create", r#"{"agent":"bad agent","profile":"web"}"#).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidParams);
    assert_eq!(fixture.sessions.live(), 1);
}

// KNSH-071: the authority moves and ends agent sessions; a human session is never paused, controlled or ended by it
// (FR-SES-22), and an ended or unknown session is -32006.
#[test]
fn moves_and_ends_agent_sessions_only() {
    let (fixture, handlers) = setup();
    let session_id = agent(&fixture);
    let target = format!(r#"{{"session_id":"{session_id}"}}"#);
    for (method, state) in [
        ("session.pause", "paused"),
        ("session.resume", "active"),
        ("session.take_control", "human_control"),
        ("session.release_control", "active"),
    ] {
        assert_eq!(
            text(&result(control(&handlers, method, &target)), "state"),
            state,
            "{method}"
        );
    }
    let error = control(&handlers, "session.resume", &target).unwrap_err();
    assert_eq!(error.code, ErrorCode::SessionNotFound, "not in the diagram");

    let (_binding, human_id) = human(&fixture);
    let human_target = format!(r#"{{"session_id":"{human_id}"}}"#);
    for method in ["session.pause", "session.take_control", "session.end"] {
        let error = control(&handlers, method, &human_target).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed, "{method}");
    }
    assert!(fixture.sessions.info_of(human_id).is_ok(), "the human session lives on");

    assert_eq!(
        text(&result(control(&handlers, "session.end", &target)), "state"),
        "ended"
    );
    let error = control(&handlers, "session.end", &target).unwrap_err();
    assert_eq!(error.code, ErrorCode::SessionNotFound);
}

// FR-SES-25 (KNSH-071): `recording.set` changes an agent session's recording, `session.info` on its own connection
// reports it, and the stored row follows; a human session's recording is not the authority's to change.
#[test]
fn recording_set_updates_session_info() {
    let (fixture, handlers) = setup();
    let created = result(control(
        &handlers,
        "session.create",
        r#"{"agent":"my-agent","profile":"web"}"#,
    ));
    let session_id: SessionId = text(&created, "session_id").parse().unwrap();
    let binding = SessionBinding::new();
    let token = Redacted::new(text(&created, "session_token").to_owned());
    fixture.sessions.bind_agent(&binding, Some(&token)).unwrap();
    let info = |binding: &SessionBinding| {
        result(call_with(
            &fixture.sessions.handlers(),
            Endpoint::Agent,
            binding,
            "session.info",
            "{}",
        ))
    };
    let before = info(&binding);
    assert_eq!(before.get("recording"), Some(&Value::Bool(true)));
    assert_eq!(before.get("output_recording"), Some(&Value::Bool(false)));

    let set = result(control(
        &handlers,
        "recording.set",
        &format!(r#"{{"session_id":"{session_id}","commands":false,"output":true}}"#),
    ));
    assert_eq!(set.get("recording"), Some(&Value::Bool(false)));
    assert_eq!(set.get("output_recording"), Some(&Value::Bool(true)));
    let after = info(&binding);
    assert_eq!(after.get("recording"), Some(&Value::Bool(false)));
    assert_eq!(after.get("output_recording"), Some(&Value::Bool(true)));
    assert_eq!(fixture.sessions.output_recording_of(session_id), Some(true));

    let (_human_binding, human_id) = human(&fixture);
    let error = control(
        &handlers,
        "recording.set",
        &format!(r#"{{"session_id":"{human_id}","output":true}}"#),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotAllowed);
    assert_eq!(fixture.sessions.output_recording_of(human_id), None);
}

// The methods answer on the control service only, whatever reaches them.
#[test]
fn refuses_calls_off_the_control_service() {
    let (_fixture, handlers) = setup();
    for endpoint in [Endpoint::User, Endpoint::Agent] {
        let error = call_with(&handlers, endpoint, &SessionBinding::new(), "session.list", "{}").unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed);
    }
}
