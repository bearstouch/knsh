//! The live session registry and human telemetry: `session.start_human`, `telemetry.command`, `telemetry.cwd`,
//! `telemetry.idle` and `session.info` (`specs/06-api/user-socket.md#human-sessions`, KNSH-021).
//!
//! # Human sessions
//!
//! `knsh` hosting a recorded shell connects to `user.sock` and calls `session.start_human`. The session (actor
//! `human`, recording on, never an envelope) is bound to that connection ([`SessionBinding`]): the telemetry calls
//! on the same connection report its command lines, and it ends (`session.state_changed` to `ended`, then
//! `session.ended`) when the connection closes, however `knsh` went away. No call names a session, so one
//! connection can never write into another's session.
//!
//! - `telemetry.command`: one finished command line. The record keeps only `command`, `cwd`, `started_at`,
//!   `ended_at` and `exit_code` (FR-REC-09; the store drops anything else for a human actor too), is committed, and
//!   only then is `command.finished` published.
//! - `telemetry.cwd`: `cwd.changed`.
//! - `telemetry.idle`: `session.idle`, at most once between two commands (FR-SES-24). `knsh` already sends it only
//!   once; the daemon checks again, so a confused client cannot flood subscribers.
//! - `session.info`: the bound session's actor, profile, state and recording settings (FR-SES-25, NFR-PRIV-05).
//!   On `agent.sock` no session is bound to a connection until KNSH-048, so it is refused there with `-32003`.
//!
//! These methods exist on `user.sock` only (the catalogue keeps them off `agent.sock`, and each handler checks the
//! endpoint again): nothing inside an envelope may create a session (FR-SES-02) or write records as a human.
//!
//! # Errors
//!
//! A telemetry call or `session.info` on a connection without a session is `-32003`; a second `session.start_human`
//! on the same connection is `-32602`. A store that is unavailable or fails is `-32603`: the reason never reaches the
//! answer. Events are best effort: a record that was written is answered even if its event could not be published.
//!
//! # Locks
//!
//! Lock order: a connection's [`SessionBinding`], then the registry, then the event hub's own lock. The registry
//! lock is never held while waiting for the record store.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::{
    Actor, CoreError, EventData, ExecutionRecord, ProfileName, RecordDetails, RecordId, Redacted, SessionId,
    SessionRegistry, SessionSpec, Timestamp, Transition, Ulid,
};
use knsh_json::{Object, Value};
use knsh_platform::{Clock, Random};
use knsh_proto::{
    ErrorCode, RpcError, SessionInfoResult, SessionStartHumanParams, SessionStartHumanResult, TelemetryCommandParams,
    TelemetryCommandResult, TelemetryCwdParams, TelemetryIdleParams,
};
use knsh_store::RecordStore;

use crate::dispatch::{Answer, Call, Endpoint, Handler, Handlers, Reply, answer, params};
use crate::events::EventHub;
use crate::lifetime::Activity;

/// The profile recorded for human sessions. Nothing in a human session is enforced (FR-SES-22); profiles are loaded
/// from files in phase 2 (KNSH-039), and until then every session runs under this name.
const HUMAN_PROFILE: &str = "default";

/// Takes a lock even if another thread panicked while holding it: every critical section below leaves its data
/// consistent at each step.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The engine's live sessions and the human telemetry handlers. One per `knshd`, shared by every connection.
pub(crate) struct Sessions {
    registry: Mutex<SessionRegistry>,
    /// Absent when the record store could not be opened: recorded sessions are then refused (`-32603`).
    store: Option<RecordStore>,
    events: Arc<EventHub>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
}

/// The session bound to one connection, if any. Created by the connection, released when it closes.
#[derive(Default)]
pub(crate) struct SessionBinding {
    bound: Mutex<Option<Bound>>,
}

/// A connection's human session.
struct Bound {
    session_id: SessionId,
    /// Whether `session.idle` was already published since the last command (FR-SES-24).
    idle_reported: bool,
    /// Ends the session when the connection closes.
    owner: Arc<Sessions>,
}

impl SessionBinding {
    /// A binding with no session.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Ends the bound session, if any: the connection closed. Called once, after the last call of the connection.
    pub(crate) fn release(&self) {
        let bound = lock(&self.bound).take();
        if let Some(bound) = bound {
            bound.owner.end(bound.session_id);
        }
    }

    /// The bound session, for a telemetry call.
    fn session_id(&self) -> Result<SessionId, RpcError> {
        lock(&self.bound)
            .as_ref()
            .map(|bound| bound.session_id)
            .ok_or_else(|| RpcError::new(ErrorCode::NotAllowed))
    }
}

impl Drop for SessionBinding {
    /// A connection that ends without reaching [`SessionBinding::release`] (its thread unwound) still ends its
    /// session: a session left in the registry would never end and would keep `knshd` alive forever.
    fn drop(&mut self) {
        self.release();
    }
}

impl Sessions {
    /// The registry, empty, writing to `store` and publishing to `events`; IDs come from `clock` and `random`.
    pub(crate) fn new(
        store: Option<RecordStore>,
        events: Arc<EventHub>,
        clock: Arc<dyn Clock>,
        random: Arc<dyn Random>,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry: Mutex::new(SessionRegistry::new()),
            store,
            events,
            clock,
            random,
        })
    }

    /// Every session handler, by method name.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        [
            ("session.start_human", self.handler(Self::start_human)),
            (
                "telemetry.command",
                self.handler(|sessions, call| sessions.command(call)),
            ),
            ("telemetry.cwd", self.handler(|sessions, call| sessions.cwd(call))),
            ("telemetry.idle", self.handler(|sessions, call| sessions.idle(call))),
            ("session.info", self.handler(|sessions, call| sessions.info(call))),
        ]
        .into_iter()
        .collect()
    }

    /// A handler running `method` on its own reference to the registry, so that it outlives the caller's.
    fn handler(self: &Arc<Self>, method: impl Fn(&Arc<Self>, &Call<'_>) -> Reply + Send + Sync + 'static) -> Handler {
        let sessions = Arc::clone(self);
        Arc::new(move |call: &Call<'_>| method(&sessions, call))
    }

    /// The number of live sessions.
    #[cfg(test)]
    pub(crate) fn live(&self) -> usize {
        lock(&self.registry).len()
    }

    /// `session.start_human`: creates a recorded human session, writes its row, publishes `session.started` and binds
    /// it to the calling connection.
    fn start_human(self: &Arc<Self>, call: &Call<'_>) -> Reply {
        user_only(call.endpoint)?;
        let SessionStartHumanParams = params(call)?;
        let store = self.store()?;
        let mut binding = lock(&call.binding.bound);
        if binding.is_some() {
            // One session per connection: a second one would make "the caller's session" ambiguous.
            return Err(RpcError::new(ErrorCode::InvalidParams));
        }
        let now = self.clock.now().map_err(|_| internal_error())?;
        let session_id = SessionId::from_ulid(self.ulid(now)?);
        let profile = ProfileName::new(HUMAN_PROFILE).map_err(|_| internal_error())?;
        let session = lock(&self.registry)
            .create(SessionSpec {
                session_id,
                actor: Actor::Human,
                profile,
                envelope: false,
                recording: Some(true),
                parent_session_id: None,
            })
            .cloned()
            .map_err(|_| internal_error())?;
        if store.write_session(&session, now).is_err() {
            // Without its row, its records could not be written either: undo, silently (nothing was published).
            let _ = lock(&self.registry).transition(session_id, Transition::End);
            return Err(internal_error());
        }
        // Best effort: a session whose start could not be published still records (see the module docs).
        let _ = self.events.session_started(&session);
        *binding = Some(Bound {
            session_id,
            idle_reported: false,
            owner: Arc::clone(self),
        });
        answer(&SessionStartHumanResult {
            session_id,
            recording: session.recording(),
        })
    }

    /// `telemetry.command`: writes the record of one finished command line, then publishes `command.finished`.
    fn command(&self, call: &Call<'_>) -> Reply {
        user_only(call.endpoint)?;
        let TelemetryCommandParams {
            command,
            cwd,
            started_at,
            ended_at,
            exit_code,
        } = params(call)?;
        let session_id = call.binding.session_id()?;
        let store = self.store()?;
        let now = self.clock.now().map_err(|_| internal_error())?;
        // Records sort by ID in creation order, so the ID is made from now, not from when the line started.
        let record_id = RecordId::from_ulid(self.ulid(now)?);
        let command = Redacted::new(command);
        let record = ExecutionRecord {
            record_id,
            session_id,
            actor: Actor::Human,
            command: command.clone(),
            cwd: cwd.clone(),
            started_at,
            ended_at: Some(ended_at),
            exit_code: Some(i32::from(exit_code)),
            // FR-REC-09: a human record has none of the agent fields.
            details: RecordDetails::default(),
        };
        // The event follows the commit: a subscriber never hears of a record that was not stored.
        store
            .write_record(record, knsh_store::RecordedOutput::default())
            .map_err(|_| internal_error())?;
        let _ = self.events.publish(
            session_id,
            &Actor::Human,
            EventData::CommandFinished {
                record_id,
                command,
                cwd,
                started_at,
                ended_at,
                exit_code: Some(i32::from(exit_code)),
            },
        );
        // A new command: the next idle prompt is reported again (FR-SES-24).
        if let Some(bound) = lock(&call.binding.bound).as_mut() {
            bound.idle_reported = false;
        }
        answer(&TelemetryCommandResult { record_id })
    }

    /// `telemetry.cwd`: publishes `cwd.changed`.
    fn cwd(&self, call: &Call<'_>) -> Reply {
        user_only(call.endpoint)?;
        let TelemetryCwdParams { cwd } = params(call)?;
        let session_id = call.binding.session_id()?;
        let _ = self
            .events
            .publish(session_id, &Actor::Human, EventData::CwdChanged { cwd });
        Ok(Answer::from(Value::Object(Object::new())))
    }

    /// `telemetry.idle`: publishes `session.idle` unless it was already published since the last command. Answers
    /// whether it was.
    fn idle(&self, call: &Call<'_>) -> Reply {
        user_only(call.endpoint)?;
        let TelemetryIdleParams = params(call)?;
        let mut binding = lock(&call.binding.bound);
        let bound = binding.as_mut().ok_or_else(|| RpcError::new(ErrorCode::NotAllowed))?;
        let emitted = !bound.idle_reported;
        if emitted {
            bound.idle_reported = true;
            let _ = self
                .events
                .publish(bound.session_id, &Actor::Human, EventData::SessionIdle);
        }
        let result = Object::new().with("emitted", emitted).map_err(|_| internal_error())?;
        Ok(Answer::from(Value::Object(result)))
    }

    /// `session.info`: the caller's own session.
    fn info(&self, call: &Call<'_>) -> Reply {
        // agent.sock: no session is bound to an agent connection before KNSH-048. Fail closed rather than guess.
        user_only(call.endpoint)?;
        let session_id = call.binding.session_id()?;
        let session = lock(&self.registry)
            .get(session_id)
            .cloned()
            // Bound sessions end only when their connection closes, after its last call; kept for safety.
            .map_err(|_| session_gone(session_id))?;
        answer(&SessionInfoResult {
            session,
            // Human sessions never record output (FR-REC-09).
            output_recording: false,
        })
    }

    /// The profile of the live session `session_id`, for `policy.check` (KNSH-043). Reads the registry only.
    ///
    /// # Errors
    ///
    /// `-32006` naming the session if it is not live (never started, or ended).
    pub(crate) fn profile_of(&self, session_id: SessionId) -> Result<ProfileName, RpcError> {
        lock(&self.registry)
            .get(session_id)
            .map(|session| session.profile().clone())
            .map_err(|_| session_gone(session_id))
    }

    /// Ends `session_id`: its connection closed. Writes the ended state and publishes `session.state_changed` to
    /// `ended`, then `session.ended`.
    fn end(&self, session_id: SessionId) {
        let (session, change) = {
            let mut registry = lock(&self.registry);
            // Already gone (never expected: each binding ends its session once): nothing to write or publish.
            let Ok(mut session) = registry.get(session_id).cloned() else {
                return;
            };
            let Ok(change) = registry.transition(session_id, Transition::End) else {
                return;
            };
            // The registry dropped the session; the copy follows it to `ended` for the store row.
            let _ = session.apply(Transition::End);
            (session, change)
        };
        // Best effort, like every event: the connection is already closed, so there is no one to report a failure to.
        if let (Some(store), Ok(now)) = (&self.store, self.clock.now()) {
            let _ = store.write_session(&session, now);
        }
        let _ = self.events.state_changed(&change);
    }

    /// The record store, or `-32603` when it could not be opened at start.
    fn store(&self) -> Result<&RecordStore, RpcError> {
        self.store.as_ref().ok_or_else(internal_error)
    }

    /// A fresh ULID stamped `now`.
    fn ulid(&self, now: Timestamp) -> Result<Ulid, RpcError> {
        let mut random = [0; 10];
        self.random.fill(&mut random).map_err(|_| internal_error())?;
        Ulid::new(now.as_unix_millis(), random).map_err(|_: CoreError| internal_error())
    }
}

impl Activity for Sessions {
    /// A recording human session keeps `knshd` alive (`specs/02-architecture/process-model.md`).
    fn keeps_alive(&self) -> bool {
        lock(&self.registry).keeps_alive()
    }
}

/// These methods serve `user.sock` only; the catalogue already says so, checked again so that a routing mistake can
/// never let an envelope create a session or write human records.
fn user_only(endpoint: Endpoint) -> Result<(), RpcError> {
    match endpoint {
        Endpoint::User => Ok(()),
        Endpoint::Agent => Err(RpcError::new(ErrorCode::NotAllowed)),
    }
}

/// `-32603`, without the reason (see the module docs).
fn internal_error() -> RpcError {
    RpcError::new(ErrorCode::InternalError)
}

/// `-32006` naming the session.
fn session_gone(session_id: SessionId) -> RpcError {
    let error = RpcError::new(ErrorCode::SessionNotFound);
    match Object::new().with("session_id", session_id.to_string()) {
        Ok(data) => error.with_data(Value::Object(data)),
        Err(_) => error,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use knsh_core::Timestamp;
    use knsh_platform::macos::{RealFs, effective_uid};
    use knsh_platform::testing::{FakeClock, SeededRandom};
    use knsh_proto::{ByteTransport, MethodName, Request, RequestId};
    use knsh_store::{PageSize, RecordQuery, Scope, StoreConfig};

    use super::*;
    use crate::dispatch::tests::{stream, subscriber};
    use crate::events::Subscriber;

    /// A temporary directory for the record store, removed on drop.
    pub(crate) struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("knshd-sessions-{}-{n}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The live sessions with a real record store and event hub, so a test can see what was written and published.
    pub(crate) struct Fixture {
        _dir: TempDir,
        pub(crate) store: RecordStore,
        pub(crate) hub: Arc<EventHub>,
        pub(crate) sessions: Arc<Sessions>,
    }

    pub(crate) fn fixture() -> Fixture {
        let dir = TempDir::new();
        let clock = Arc::new(FakeClock::new(
            Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
        ));
        let store = RecordStore::open(
            &RealFs::new(),
            &dir.0.join("records.db"),
            effective_uid(),
            clock.clone(),
            StoreConfig::default(),
        )
        .unwrap();
        let hub = crate::events::tests::hub();
        let sessions = Sessions::new(
            Some(store.clone()),
            Arc::clone(&hub),
            clock,
            Arc::new(SeededRandom::new(3)),
        );
        Fixture {
            _dir: dir,
            store,
            hub,
            sessions,
        }
    }

    fn call_on(
        sessions: &Arc<Sessions>,
        endpoint: Endpoint,
        binding: &SessionBinding,
        method: &'static str,
        params: &str,
    ) -> Reply {
        let request = Request {
            id: RequestId::from(1u32),
            method: MethodName::new(method).unwrap(),
            params: knsh_json::parse(params.as_bytes(), 1 << 16)
                .unwrap()
                .as_object()
                .cloned(),
        };
        sessions.handlers()[method](&Call {
            endpoint,
            bytes: ByteTransport::BinaryFrames,
            stream: stream(),
            request: &request,
            subscriber: subscriber(),
            binding,
        })
    }

    fn call(sessions: &Arc<Sessions>, binding: &SessionBinding, method: &'static str, params: &str) -> Reply {
        call_on(sessions, Endpoint::User, binding, method, params)
    }

    fn field<'a>(answer: &'a Answer, name: &str) -> &'a Value {
        answer.result.as_object().unwrap().get(name).unwrap()
    }

    const COMMAND: &str = r#"{"command":"ls -la","cwd":"/Users/u","started_at":"2027-01-15T08:00:00Z",
        "ended_at":"2027-01-15T08:00:02Z","exit_code":1}"#;

    /// Subscribes to every session's events on a fresh connection subscriber.
    fn watch(hub: &Arc<EventHub>) -> Subscriber {
        let watcher = Subscriber::new();
        watcher.subscribe(hub, knsh_core::EventScope::All, None).unwrap();
        watcher
    }

    fn event_names(watcher: &Subscriber) -> Vec<String> {
        watcher
            .take(100)
            .into_iter()
            .filter_map(|(_, delivery)| match delivery {
                knsh_core::Delivery::Event(event) => Some(event.name().to_owned()),
                knsh_core::Delivery::Lost(_) => None,
            })
            .collect()
    }

    // KNSH-021 (FR-SES-21, FR-REC-09): a human session records each typed line with the telemetry fields only, emits
    // `session.started`, `command.finished`, `cwd.changed`, and ends with `session.ended` when its connection closes.
    #[test]
    fn human_session_records_commands_and_ends_with_its_connection() {
        let fixture = fixture();
        let watcher = watch(&fixture.hub);
        let binding = SessionBinding::new();
        let started = call(&fixture.sessions, &binding, "session.start_human", "{}").unwrap();
        assert_eq!(field(&started, "recording"), &Value::from(true));
        let session_id: SessionId = field(&started, "session_id").as_str().unwrap().parse().unwrap();
        assert!(fixture.sessions.keeps_alive(), "a recording session keeps knshd alive");

        for _ in 0..3 {
            call(&fixture.sessions, &binding, "telemetry.command", COMMAND).unwrap();
        }
        call(&fixture.sessions, &binding, "telemetry.cwd", r#"{"cwd":"/tmp"}"#).unwrap();

        let page = fixture
            .store
            .query(
                Scope::All,
                RecordQuery {
                    session: Some(session_id),
                    since: None,
                    until: None,
                    text: None,
                    after: None,
                    limit: PageSize::new(100).unwrap(),
                },
            )
            .unwrap();
        assert_eq!(page.records.len(), 3);
        let record = &page.records[0].record;
        assert_eq!(record.actor, Actor::Human);
        assert_eq!(record.command.expose(), "ls -la");
        assert_eq!(record.exit_code, Some(1));
        assert!(record.ended_at.is_some());
        assert!(record.details.is_empty());
        assert!(page.records[0].stdout.is_none() && page.records[0].stderr.is_none());

        binding.release();
        assert_eq!(fixture.sessions.live(), 0);
        assert!(!fixture.sessions.keeps_alive());
        assert_eq!(
            event_names(&watcher),
            [
                "session.started",
                "command.finished",
                "command.finished",
                "command.finished",
                "cwd.changed",
                "session.state_changed",
                "session.ended",
            ]
        );
        // Released twice (never happens): nothing more.
        binding.release();
        assert_eq!(event_names(&watcher), Vec::<String>::new());
    }

    // KNSH-021 (FR-SES-25, NFR-PRIV-05): `session.info` reports actor, profile, state and recording for the caller's
    // session; without one it is refused, and agent.sock is refused until KNSH-048.
    #[test]
    fn session_info_reports_recording_state() {
        let fixture = fixture();
        let binding = SessionBinding::new();
        let refused = call(&fixture.sessions, &binding, "session.info", "{}").unwrap_err();
        assert_eq!(refused.code, ErrorCode::NotAllowed);
        call(&fixture.sessions, &binding, "session.start_human", "{}").unwrap();
        let info = call(&fixture.sessions, &binding, "session.info", "{}").unwrap();
        assert_eq!(field(&info, "recording"), &Value::from(true));
        assert_eq!(field(&info, "output_recording"), &Value::from(false));
        assert_eq!(field(&info, "state"), &Value::from("active"));
        assert_eq!(field(&info, "profile"), &Value::from(HUMAN_PROFILE));
        assert_eq!(
            field(&info, "actor").as_object().unwrap().get("kind"),
            Some(&Value::from("human"))
        );
        let agent = call_on(&fixture.sessions, Endpoint::Agent, &binding, "session.info", "{}").unwrap_err();
        assert_eq!(agent.code, ErrorCode::NotAllowed);
        binding.release();
    }

    // FR-SES-24: the daemon publishes `session.idle` once per idle prompt, even if a client repeats it.
    #[test]
    fn idle_is_published_once_between_commands() {
        let fixture = fixture();
        let binding = SessionBinding::new();
        call(&fixture.sessions, &binding, "session.start_human", "{}").unwrap();
        let watcher = watch(&fixture.hub);
        let emitted = |answer: Answer| field(&answer, "emitted") == &Value::from(true);
        assert!(emitted(
            call(&fixture.sessions, &binding, "telemetry.idle", "{}").unwrap()
        ));
        assert!(!emitted(
            call(&fixture.sessions, &binding, "telemetry.idle", "{}").unwrap()
        ));
        call(&fixture.sessions, &binding, "telemetry.command", COMMAND).unwrap();
        assert!(emitted(
            call(&fixture.sessions, &binding, "telemetry.idle", "{}").unwrap()
        ));
        assert_eq!(
            event_names(&watcher),
            ["session.idle", "command.finished", "session.idle"]
        );
        binding.release();
    }

    // Fail closed: telemetry without a session, a second session on one connection, any of these methods on
    // agent.sock, and malformed params are all refused, and nothing is written.
    #[test]
    fn telemetry_is_refused_outside_a_bound_session() {
        let fixture = fixture();
        let binding = SessionBinding::new();
        for (method, params) in [
            ("telemetry.command", COMMAND),
            ("telemetry.cwd", r#"{"cwd":"/"}"#),
            ("telemetry.idle", "{}"),
        ] {
            let error = call(&fixture.sessions, &binding, method, params).unwrap_err();
            assert_eq!(error.code, ErrorCode::NotAllowed, "{method}");
        }
        for method in ["session.start_human", "telemetry.idle"] {
            let error = call_on(&fixture.sessions, Endpoint::Agent, &binding, method, "{}").unwrap_err();
            assert_eq!(error.code, ErrorCode::NotAllowed, "{method}");
        }
        assert_eq!(fixture.sessions.live(), 0);

        call(&fixture.sessions, &binding, "session.start_human", "{}").unwrap();
        let again = call(&fixture.sessions, &binding, "session.start_human", "{}").unwrap_err();
        assert_eq!(again.code, ErrorCode::InvalidParams);
        assert_eq!(fixture.sessions.live(), 1);
        let bad = call(
            &fixture.sessions,
            &binding,
            "telemetry.command",
            r#"{"command":"x","cwd":"relative","started_at":"2027-01-15T08:00:00Z","ended_at":"2027-01-15T08:00:00Z","exit_code":0}"#,
        )
        .unwrap_err();
        assert_eq!(bad.code, ErrorCode::InvalidParams);
        binding.release();
    }

    // KNSH-021: over a real connection, the session lives as long as the connection: when `knsh` goes away the
    // connection loop ends it, and `session.ended` is published.
    #[test]
    fn closing_the_connection_ends_its_session() {
        use crate::dispatch::tests::ok_handler;
        use crate::dispatch::{Dispatcher, HELLO, Table};

        let fixture = fixture();
        let watcher = watch(&fixture.hub);
        let mut user = Table::new().with(HELLO, ok_handler());
        for (name, handler) in fixture.sessions.handlers() {
            user = user.with(name, handler);
        }
        let dispatcher = Dispatcher::from_tables(user, Table::new());
        let mut input = knsh_json::FrameWriter::new(Vec::new());
        for text in [
            r#"{"jsonrpc":"2.0","id":1,"method":"hello"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"session.start_human"}"#,
        ] {
            input
                .write_json(&knsh_json::parse(text.as_bytes(), 4096).unwrap())
                .unwrap();
        }
        let mut output = Vec::new();
        crate::connection::serve(
            std::io::Cursor::new(input.into_inner()),
            &mut output,
            Endpoint::User,
            &dispatcher,
            &mut || {},
            &|| {},
        );
        assert_eq!(fixture.sessions.live(), 0);
        assert_eq!(
            event_names(&watcher),
            ["session.started", "session.state_changed", "session.ended"]
        );
    }

    // A connection that unwinds before `release` still ends its session, so knshd is not kept alive forever.
    #[test]
    fn dropping_a_binding_ends_its_session() {
        let fixture = fixture();
        let binding = SessionBinding::new();
        call(&fixture.sessions, &binding, "session.start_human", "{}").unwrap();
        assert_eq!(fixture.sessions.live(), 1);
        drop(binding);
        assert_eq!(fixture.sessions.live(), 0);
        assert!(!fixture.sessions.keeps_alive());
    }

    // Without a record store a recorded session cannot exist: refused, and nothing is left in the registry.
    #[test]
    fn no_store_refuses_recorded_sessions() {
        let sessions = Sessions::new(
            None,
            crate::events::tests::hub(),
            Arc::new(FakeClock::new(Timestamp::UNIX_EPOCH)),
            Arc::new(SeededRandom::new(1)),
        );
        let binding = SessionBinding::new();
        let error = call(&sessions, &binding, "session.start_human", "{}").unwrap_err();
        assert_eq!(error.code, ErrorCode::InternalError);
        assert_eq!(sessions.live(), 0);
    }
}
