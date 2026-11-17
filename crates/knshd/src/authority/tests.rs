use std::sync::atomic::{AtomicUsize, Ordering};

use knsh_core::{BundleVersion, Delivery, EventScope, SigningIdentifier, TeamId};
use knsh_json::FromJson;
use knsh_platform::testing::{MemTrustStore, RecordingLog, ScriptedPresence};
use knsh_proto::{ByteTransport, MethodName, Request, RequestId};

use super::*;
use crate::dispatch::tests::{no_descriptors, stream, subscriber};
use crate::events::Subscriber;
use crate::events::tests::hub;
use crate::sessions::SessionBinding;

/// `authority.trust`, `authority.register`, `decision.respond` and the supervision methods (KNSH-071) with a store
/// holding nothing and a prompt nobody answers: for dispatcher tests that need every catalogued handler.
pub(crate) fn idle_handlers() -> Handlers {
    let log: Arc<dyn SystemLog> = Arc::new(RecordingLog::new());
    let mut handlers = AuthorityTrust::new(
        Arc::new(MemTrustStore::new()),
        Arc::new(ScriptedPresence::new()),
        Arc::clone(&log),
    )
    .handlers();
    handlers.extend(Registration::new(hub(), Arc::clone(&log)).handlers());
    // `decision.respond` (KNSH-069) is served with the authority's methods.
    let decisions = crate::decisions::Decisions::with_default_timeout(
        Arc::new(knsh_platform::testing::FakeClock::new(
            knsh_core::Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
        )),
        Arc::new(knsh_platform::testing::SeededRandom::new(1)),
        Arc::clone(&log),
        crate::grants::GrantStore::new(),
    );
    handlers.extend(decisions.handlers());
    // The supervision methods (KNSH-071) over sessions that cannot record, an empty filesystem and a state store
    // in memory.
    let sessions = crate::hello::tests::sessions();
    let profiles = crate::policy::tests::loader(knsh_platform::testing::MemFs::new());
    handlers.extend(crate::supervise::Supervise::new(Arc::clone(&sessions), profiles.clone()).handlers());
    let clock = Arc::new(knsh_platform::testing::FakeClock::new(
        knsh_core::Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
    ));
    let state = crate::state::StateStore::in_memory(Arc::clone(&log));
    let pushed = crate::pushed::PushedPolicies::new(Arc::clone(&state), clock.clone(), Vec::new());
    handlers.extend(
        crate::policy_admin::PolicyAdmin::new(crate::policy_admin::PolicyAdminParts {
            profiles: profiles.with_pushed(Arc::clone(&pushed)),
            pushed,
            grants: crate::grants::GrantStore::new(),
            sessions,
            events: hub(),
            clock,
            random: Arc::new(knsh_platform::testing::SeededRandom::new(1)),
            log,
        })
        .handlers(),
    );
    handlers
}

fn authority(team: &str, identifier: &str, version: &str) -> TrustedAuthority {
    TrustedAuthority {
        team_id: TeamId::new(team).unwrap(),
        identifier: SigningIdentifier::new(identifier).unwrap(),
        min_version: BundleVersion::parse(version).unwrap(),
    }
}

fn first() -> TrustedAuthority {
    authority("ABCDE12345", "com.example.authority", "1.4")
}

fn params_of(record: &TrustedAuthority) -> String {
    format!(
        r#"{{"team_id":"{}","identifier":"{}","min_version":"{}"}}"#,
        record.team_id, record.identifier, record.min_version
    )
}

/// Calls `method` with `params` on `endpoint`, as connection `control` when on the control service.
fn call(
    handlers: &Handlers,
    endpoint: Endpoint,
    control: Option<ConnectionId>,
    method: &'static str,
    params: &str,
) -> Reply {
    let request = Request {
        id: RequestId::from(1u32),
        method: MethodName::new(method).unwrap(),
        params: knsh_json::parse(params.as_bytes(), 1 << 20)
            .unwrap()
            .as_object()
            .cloned(),
    };
    handlers[method](&Call {
        endpoint,
        bytes: ByteTransport::BinaryFrames,
        stream: stream(),
        request: &request,
        subscriber: subscriber(),
        binding: &SessionBinding::new(),
        descriptors: no_descriptors(),
        caller: &knsh_core::StillWaiting,
        control,
    })
}

fn code(reply: Reply) -> ErrorCode {
    reply.unwrap_err().code
}

struct Trust {
    store: Arc<MemTrustStore>,
    presence: Arc<ScriptedPresence>,
    service: Arc<AuthorityTrust>,
    applied: Arc<AtomicUsize>,
}

/// The trust service over `store`, counting how often a new record was applied to the control service.
fn trust_over(store: MemTrustStore) -> Trust {
    let store = Arc::new(store);
    let presence = Arc::new(ScriptedPresence::new());
    let service = AuthorityTrust::new(store.clone(), presence.clone(), Arc::new(RecordingLog::new()));
    let applied = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&applied);
    service.when_trusted(Arc::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    Trust {
        store,
        presence,
        service,
        applied,
    }
}

impl Trust {
    fn trust(&self, params: &str) -> Reply {
        call(&self.service.handlers(), Endpoint::User, None, AUTHORITY_TRUST, params)
    }
}

fn trusted(reply: Reply) -> AuthorityTrustResult {
    AuthorityTrustResult::from_json(&reply.unwrap().result).unwrap()
}

// FR-AUTH-10, FR-AUTH-11: after the user passes knshd's own prompt, which names the authority, the record is stored
// and applied to the control service.
#[test]
fn stores_trust_after_authentication() {
    let trust = trust_over(MemTrustStore::new());
    trust.presence.approve_next();
    let result = trusted(trust.trust(&params_of(&first())));
    assert!(result.changed && !result.replaced);
    assert_eq!(result.authority, first());
    assert_eq!(trust.store.record(), Some(first()));
    assert_eq!(trust.applied.load(Ordering::SeqCst), 1);
    let prompts = trust.presence.prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(
        prompts[0].reason,
        "trust the authority app: com.example.authority (team ABCDE12345, version 1.4.0 or later)"
    );
    assert_eq!(prompts[0].timeout, TRUST_PROMPT_TIMEOUT);
    // The same record again: nothing is asked, written or applied.
    let again = trusted(trust.trust(&params_of(&first())));
    assert!(!again.changed && !again.replaced);
    assert_eq!(trust.presence.prompts().len(), 1);
    assert_eq!(trust.store.writes(), 1);
    assert_eq!(trust.applied.load(Ordering::SeqCst), 1);
}

// FR-AUTH-10: any outcome of the prompt but success refuses the trust (`-32001`, source user); nothing is stored.
#[test]
fn refuses_without_authentication() {
    for refusal in [
        NotAuthenticated::Cancelled,
        NotAuthenticated::Failed,
        NotAuthenticated::TimedOut,
        NotAuthenticated::Error { code: -1 },
    ] {
        let trust = trust_over(MemTrustStore::new());
        trust.presence.refuse_next(refusal);
        let error = trust.trust(&params_of(&first())).unwrap_err();
        assert_eq!(error.code, ErrorCode::Denied, "{refusal:?}");
        assert_eq!(Denial::from_error(&error).unwrap().source.as_deref(), Some("user"));
        assert_eq!(trust.store.record(), None);
        assert_eq!(trust.applied.load(Ordering::SeqCst), 0);
    }
    // A prompt nobody answers is refused the same way (the fake times out).
    let trust = trust_over(MemTrustStore::new());
    assert_eq!(code(trust.trust(&params_of(&first()))), ErrorCode::Denied);
    assert_eq!(trust.store.writes(), 0);
}

// AC "replacing an existing trust record also requires authentication": the prompt names both records; refused, the
// old record stays in force.
#[test]
fn replacing_trust_requires_authentication() {
    let second = authority("ZZZZZ99999", "org.other.authority", "2");
    let trust = trust_over(MemTrustStore::with_record(first()));
    trust.presence.refuse_next(NotAuthenticated::Cancelled);
    assert_eq!(code(trust.trust(&params_of(&second))), ErrorCode::Denied);
    assert_eq!(trust.store.record(), Some(first()));
    assert_eq!(trust.applied.load(Ordering::SeqCst), 0);

    trust.presence.approve_next();
    let result = trusted(trust.trust(&params_of(&second)));
    assert!(result.changed && result.replaced);
    assert_eq!(trust.store.record(), Some(second));
    assert_eq!(trust.applied.load(Ordering::SeqCst), 1);
    let prompts = trust.presence.prompts();
    assert_eq!(prompts.len(), 2);
    assert_eq!(
        prompts[1].reason,
        "replace the trusted authority app: com.example.authority (team ABCDE12345, version 1.4.0 or later) with \
         org.other.authority (team ZZZZZ99999, version 2.0.0 or later)"
    );
}

// FR-AUTH-10, AC "invalid arguments are rejected before the prompt": a malformed team ID, identifier or version is
// `-32602`, and no prompt is shown, nothing read or written.
#[test]
fn validates_team_id_and_version_format() {
    let trust = trust_over(MemTrustStore::new());
    for bad in [
        r#"{"team_id":"abcde12345","identifier":"com.example.authority","min_version":"1.4"}"#,
        r#"{"team_id":"ABCDE1234","identifier":"com.example.authority","min_version":"1.4"}"#,
        r#"{"team_id":"ABCDE12345","identifier":"com.example.authority","min_version":"1.4-beta"}"#,
        r#"{"team_id":"ABCDE12345","identifier":"com.example.authority","min_version":"1.2.3.4"}"#,
        r#"{"team_id":"ABCDE12345","identifier":"com.example\" or anchor apple","min_version":"1"}"#,
        r#"{"team_id":"ABCDE12345","identifier":"com.example.authority"}"#,
    ] {
        assert_eq!(code(trust.trust(bad)), ErrorCode::InvalidParams, "{bad}");
    }
    assert_eq!(trust.presence.prompts(), Vec::new());
    assert_eq!(trust.store.reads(), 0);
    assert_eq!(trust.store.writes(), 0);
}

// Decision 11: a record that cannot be read is tampering. No prompt, nothing written, and at start nothing is trusted.
#[test]
fn refuses_when_the_record_cannot_be_read() {
    let trust = trust_over(MemTrustStore::with_record(first()));
    trust.store.fail_reads(-25293);
    trust.presence.approve_next();
    assert_eq!(code(trust.trust(&params_of(&first()))), ErrorCode::InternalError);
    assert_eq!(trust.presence.prompts(), Vec::new());
    assert_eq!(trust.store.writes(), 0);
    assert_eq!(trust.service.current(), None);
}

// A failed write keeps the previous record in force, and nothing is applied.
#[test]
fn keeps_the_previous_record_when_the_write_fails() {
    let trust = trust_over(MemTrustStore::with_record(first()));
    trust.store.fail_writes(-61);
    trust.presence.approve_next();
    let second = authority("ZZZZZ99999", "org.other.authority", "2");
    assert_eq!(code(trust.trust(&params_of(&second))), ErrorCode::InternalError);
    assert_eq!(trust.store.record(), Some(first()));
    assert_eq!(trust.applied.load(Ordering::SeqCst), 0);
}

// Only the user trusts an authority: never from an envelope or from the authority itself.
#[test]
fn trust_is_refused_off_user_sock() {
    let trust = trust_over(MemTrustStore::new());
    trust.presence.approve_next();
    for endpoint in [Endpoint::Agent, Endpoint::Control] {
        let reply = call(
            &trust.service.handlers(),
            endpoint,
            None,
            AUTHORITY_TRUST,
            &params_of(&first()),
        );
        assert_eq!(code(reply), ErrorCode::NotAllowed);
    }
    assert_eq!(trust.presence.prompts(), Vec::new());
}

struct Registered {
    observer: Subscriber,
    registration: Arc<Registration>,
}

/// A registration over a fresh hub, with an observer subscribed to every session.
fn registration() -> Registered {
    let events = hub();
    let observer = Subscriber::new();
    observer.subscribe(&events, EventScope::All, None).unwrap();
    let registration = Registration::new(events, Arc::new(RecordingLog::new()));
    Registered { observer, registration }
}

impl Registered {
    fn register(&self, connection: u64) -> Reply {
        call(
            &self.registration.handlers(),
            Endpoint::Control,
            Some(ConnectionId(connection)),
            AUTHORITY_REGISTER,
            "{}",
        )
    }

    /// The names of the engine events the observer received since the last call.
    fn seen(&self) -> Vec<&'static str> {
        self.observer
            .take(usize::MAX)
            .into_iter()
            .map(|(_, delivery)| match delivery {
                Delivery::Engine(event) => event.name(),
                other => panic!("unexpected delivery {other:?}"),
            })
            .collect()
    }
}

// FR-AUTH-01: the first verified connection to register becomes the authority.
#[test]
fn first_registration_succeeds() {
    let registered = registration();
    let answer = registered.register(1).unwrap();
    assert_eq!(knsh_json::write(&answer.result).unwrap(), r#"{"registered":true}"#);
    assert!(registered.registration.is_registered());
    // Registering again on the same connection changes nothing.
    assert!(registered.register(1).is_ok());
    assert_eq!(registered.seen(), ["authority.connected"]);
}

// FR-AUTH-01: a second registration is refused (`-32003`) until the first connection ends.
#[test]
fn second_registration_refused() {
    let registered = registration();
    registered.register(1).unwrap();
    assert_eq!(code(registered.register(2)), ErrorCode::NotAllowed);
    // Another connection's end does not free the place.
    registered.registration.disconnected(ConnectionId(2));
    assert_eq!(code(registered.register(2)), ErrorCode::NotAllowed);
    registered.registration.disconnected(ConnectionId(1));
    assert!(registered.register(2).is_ok());
}

// FR-AUTH-02: `authority.connected` on register and `authority.disconnected` when the authority's connection ends,
// once each, as engine events.
#[test]
fn emits_connected_and_disconnected() {
    let registered = registration();
    registered.register(1).unwrap();
    registered.registration.disconnected(ConnectionId(1));
    // A connection that never registered ends without an event.
    registered.registration.disconnected(ConnectionId(3));
    registered.register(3).unwrap();
    assert_eq!(
        registered.seen(),
        ["authority.connected", "authority.disconnected", "authority.connected"]
    );
}

// Only a control connection can be the authority.
#[test]
fn registration_is_refused_off_the_control_service() {
    let registered = registration();
    let handlers = registered.registration.handlers();
    for endpoint in [Endpoint::User, Endpoint::Agent] {
        assert_eq!(
            code(call(&handlers, endpoint, None, AUTHORITY_REGISTER, "{}")),
            ErrorCode::NotAllowed
        );
    }
    // The control endpoint without a connection identity (never happens in knshd) is refused too.
    assert_eq!(
        code(call(&handlers, Endpoint::Control, None, AUTHORITY_REGISTER, "{}")),
        ErrorCode::NotAllowed
    );
    assert!(!registered.registration.is_registered());
    assert_eq!(registered.seen(), Vec::<&str>::new());
}
