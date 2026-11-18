//! The `hello` handler and the phase-1 method set (KNSH-014, `specs/06-api/handshake.md`).
//!
//! `hello` settles the protocol, reports the platform and the probed capabilities, and lists the methods callable on
//! the caller's endpoint. That list comes from [`Catalogue::available`] with the same capabilities the dispatch
//! tables were generated from ([`dispatcher_with_violations`]), so `hello` never lists a method the endpoint does not serve.
//!
//! - No protocol in common: `-32005` with `capability: "protocol"`; the connection loop then closes the connection.
//! - Malformed parameters: `-32602`, which also closes the connection (a failed `hello`).
//! - On `agent.sock`, `hello` binds the connection to one agent session (KNSH-048, [`crate::agents`]): by its
//!   `session_token`, else by the caller's audit token if it runs inside a registered envelope. The result carries
//!   that `session_id`. With neither it is `-32009`, and the connection is closed. On `user.sock` the token is read
//!   (bounded, redacted) and ignored, and no `session_id` is reported.
//! - Phase 1 builds report `advisory: true`: no security guarantees, not for running agents unattended (KNSH-024).

use std::sync::Arc;

use knsh_json::ToJson;
use knsh_proto::{Catalogue, ErrorCode, HelloParams, HelloResult, PROTOCOL_CAPABILITY, RpcError, negotiate};

use crate::dispatch::{
    BuildError, Call, Dispatcher, Endpoint, HELLO, Handler, Handlers, Reply, capability_unavailable,
};
use crate::probe::Probed;
use crate::sessions::Sessions;
use crate::violations::ReaderStatus;

/// Phase 1 is advisory (`specs/01-overview/roadmap.md`): the label is in every `hello` until phase 2 qualifies.
const ADVISORY: bool = true;

/// What `hello` reports, fixed for the lifetime of this `knshd`.
struct Handshake {
    /// The catalogue the tables were generated from.
    catalogue: Catalogue,
    /// The probe result.
    probed: Probed,
    /// The violation reader's state, the one capability read live (KNSH-047).
    violations: Arc<ReaderStatus>,
    /// Whether this build is advisory only.
    advisory: bool,
    /// The live sessions `agent.sock` connections are bound to.
    sessions: Arc<Sessions>,
}

impl Handshake {
    /// Answers one `hello`. Bad params are `-32602` and no shared protocol is `-32005`; either way the connection
    /// loop closes the connection, since a failed `hello` ends it.
    fn answer(&self, call: &Call<'_>) -> Reply {
        let params: HelloParams = call.request.params().map_err(|error| RpcError::from(&error))?;
        let protocol = negotiate(&params.protocols).ok_or_else(|| capability_unavailable(PROTOCOL_CAPABILITY))?;
        // agent.sock: every later call acts for exactly this session; without one the caller is refused (-32009).
        // The control service acts across all sessions, like user.sock.
        let session_id = match call.endpoint {
            Endpoint::User | Endpoint::Control => None,
            Endpoint::Agent => Some(self.sessions.bind_agent(call.binding, params.session_token.as_ref())?),
        };
        // The probed backends, with the violation reader's state as it is now: the reader can stop and restart
        // while this process runs, and a failed reader must be visible (KNSH-047). No method depends on it, so the
        // method list is the same either way.
        let mut capabilities = self.probed.capabilities.as_ref().clone();
        capabilities.sandbox_violations = self.violations.current();
        // The methods come from the capabilities the dispatch tables were built from, so `hello` never lists one the
        // endpoint does not serve.
        let methods = self
            .catalogue
            .available(call.endpoint.catalogue(), &capabilities)
            .collect();
        // KNSH-079: the checkpoint roots of running agent sessions, read live, each once its shadow has settled.
        capabilities.checkpoints = self.sessions.checkpoint_report();
        let result = HelloResult {
            engine_version: env!("CARGO_PKG_VERSION"),
            protocol,
            platform: self.probed.platform,
            session_id,
            advisory: self.advisory,
            bytes: params.bytes,
            capabilities: &capabilities,
            methods,
        };
        // Writing fixed keys and bounded values cannot fail; if it ever did, the client gets no partial report.
        result
            .to_json()
            .map(Into::into)
            .map_err(|_| RpcError::new(ErrorCode::InternalError))
    }
}

/// The `hello` handler over `handshake`.
fn handler(handshake: Arc<Handshake>) -> Handler {
    Arc::new(move |call: &Call<'_>| handshake.answer(call))
}

/// [`dispatcher_with_violations`] with no violation reader (always `none`) and no agent sessions, for tests.
#[cfg(test)]
pub(crate) fn phase1_dispatcher(probed: Probed, others: Handlers) -> Result<Dispatcher, BuildError> {
    dispatcher_with_violations(probed, others, ReaderStatus::stopped(), tests::sessions())
}

/// The dispatcher `knshd` serves: the engine catalogue, the probed capabilities, `hello`, and the `others`
/// implemented elsewhere, with `hello` reporting `violations` as `capabilities.sandbox_violations` (KNSH-047) and
/// binding `agent.sock` connections to `sessions` (KNSH-048).
///
/// # Errors
///
/// [`BuildError`] if the catalogue and the handlers disagree (a programming error caught at start-up).
pub(crate) fn dispatcher_with_violations(
    probed: Probed,
    others: Handlers,
    violations: Arc<ReaderStatus>,
    sessions: Arc<Sessions>,
) -> Result<Dispatcher, BuildError> {
    let catalogue = Catalogue::ENGINE;
    let capabilities = Arc::clone(&probed.capabilities);
    let handshake = Arc::new(Handshake {
        catalogue,
        probed,
        violations,
        advisory: ADVISORY,
        sessions,
    });
    let mut handlers = others;
    handlers.insert(HELLO, handler(handshake));
    Dispatcher::build(catalogue, capabilities, &handlers)
}

#[cfg(test)]
pub(crate) mod tests {
    use knsh_json::{Object, Value};
    use knsh_proto::{ByteTransport, MethodName, Request, RequestId};

    use super::*;
    use crate::dispatch::Endpoint;
    use crate::probe::probe;
    use crate::probe::tests::Machine;

    fn hello_request(params: &str) -> Request {
        let params = knsh_json::parse(params.as_bytes(), 1 << 16).unwrap();
        Request {
            id: RequestId::from(1u32),
            method: MethodName::new(HELLO).unwrap(),
            params: params.as_object().cloned(),
        }
    }

    /// Sessions that cannot record (no store), on an empty event bus and process table.
    pub(crate) fn sessions() -> Arc<Sessions> {
        Sessions::new(
            None,
            crate::events::tests::hub(),
            Arc::new(knsh_platform::testing::FakeClock::new(knsh_core::Timestamp::UNIX_EPOCH)),
            Arc::new(knsh_platform::testing::SeededRandom::new(1)),
            Arc::new(knsh_platform::testing::FakeProcessTree::new()),
        )
    }

    /// Every handler besides `hello`: records without a store, events on an empty bus, sessions that cannot record
    /// (no store), `policy.check`, `policy.read` and `policy.edit` over an empty filesystem (with a prompt nobody
    /// answers), `approval.*` with nothing pending, and `exec.run` without a supervisor.
    pub(crate) fn handlers() -> Handlers {
        let mut handlers = crate::records::Records::unavailable().handlers();
        let hub = crate::events::tests::hub();
        handlers.extend(hub.handlers());
        let sessions = sessions();
        handlers.extend(sessions.handlers());
        handlers.extend(crate::policy::tests::service(sessions, knsh_platform::testing::MemFs::new()).handlers());
        handlers.extend(crate::policy_edit::tests::idle_handlers());
        handlers.extend(crate::approvals::tests::idle_handlers());
        handlers.extend(crate::authority::tests::idle_handlers());
        handlers.extend(crate::exec::unserved_handlers());
        handlers.extend(crate::start_agent::unserved_handlers());
        handlers
    }

    const PARAMS: &str = r#"{"client":"test","client_version":"1.0","protocols":[1]}"#;

    fn hello(dispatcher: &Dispatcher, endpoint: Endpoint, params: &str) -> Result<Object, RpcError> {
        let request = hello_request(params);
        // A fresh binding per call: an agent hello binds it, and a binding is never moved to another session.
        let binding = crate::sessions::SessionBinding::new();
        dispatcher
            .call(&Call {
                endpoint,
                bytes: ByteTransport::BinaryFrames,
                stream: crate::dispatch::tests::stream(),
                request: &request,
                subscriber: crate::dispatch::tests::subscriber(),
                binding: &binding,
                descriptors: crate::dispatch::tests::no_descriptors(),
                caller: &knsh_core::StillWaiting,
                control: None,
            })
            .map(|answer| answer.result.as_object().cloned().unwrap())
    }

    /// Hello params carrying the token of a fresh agent session of `sessions`, and that session's ID.
    fn agent_params(sessions: &Sessions) -> (String, knsh_core::SessionId) {
        let opened = sessions
            .open_agent(
                knsh_core::Actor::Agent(knsh_core::AgentId::new("claude-code").unwrap()),
                knsh_core::ProfileName::new("default").unwrap(),
            )
            .unwrap();
        let params = format!(
            r#"{{"client":"test","client_version":"1.0","protocols":[1],"session_token":"{}"}}"#,
            opened.token.encode().expose()
        );
        (params, opened.session_id)
    }

    fn capabilities(result: &Object) -> &Object {
        result.get("capabilities").and_then(Value::as_object).unwrap()
    }

    fn methods(result: &Object) -> Vec<&str> {
        capabilities(result)
            .get("methods")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .map(|m| m.as_str().unwrap())
            .collect()
    }

    #[test]
    fn hello_reports_version_protocol_platform_and_advisory() {
        let dispatcher = phase1_dispatcher(probe(&Machine::working().probes()), handlers()).unwrap();
        let result = hello(&dispatcher, Endpoint::User, PARAMS).unwrap();
        assert_eq!(
            result.get("engine_version").and_then(Value::as_str),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(result.get("protocol").and_then(Value::as_i64), Some(1));
        let platform = result.get("platform").and_then(Value::as_str).unwrap();
        assert!(platform.contains("-15-"), "{platform}");
        // KNSH-014 / KNSH-024: phase 1 builds say they are advisory.
        assert_eq!(result.get("advisory").and_then(Value::as_bool), Some(true));
        assert_eq!(result.get("binary_frames").and_then(Value::as_bool), Some(true));
        assert!(!result.contains_key("session_id"), "no session on user.sock");
        assert_eq!(
            capabilities(&result).get("sandbox").and_then(Value::as_str),
            Some("seatbelt")
        );
        assert_eq!(
            capabilities(&result).get("file_events").and_then(Value::as_str),
            Some("fsevents")
        );
    }

    // KNSH-014: single source of truth. `methods` is exactly what the endpoint's dispatch table serves.
    #[test]
    fn methods_list_matches_catalogue_for_endpoint() {
        for machine in [Machine::working(), Machine::failing()] {
            let probed = probe(&machine.probes());
            let capabilities = Arc::clone(&probed.capabilities);
            let fixture = crate::sessions::tests::fixture();
            let dispatcher = dispatcher_with_violations(
                probed,
                handlers(),
                ReaderStatus::stopped(),
                Arc::clone(&fixture.sessions),
            )
            .unwrap();
            let (agent_params, _) = agent_params(&fixture.sessions);
            for endpoint in Endpoint::ALL {
                let params = match endpoint {
                    Endpoint::User => PARAMS,
                    Endpoint::Agent => &agent_params,
                    Endpoint::Control => unreachable!("Endpoint::ALL lists the sockets"),
                };
                let result = hello(&dispatcher, endpoint, params).unwrap();
                let mut listed = methods(&result);
                let from_catalogue: Vec<&str> = Catalogue::ENGINE
                    .available(endpoint.catalogue(), &capabilities)
                    .map(|spec| spec.name)
                    .collect();
                assert_eq!(listed, from_catalogue, "{}", endpoint.name());
                // KNSH-043: dry runs are listed on both sockets.
                assert!(listed.contains(&"policy.check"), "{}", endpoint.name());
                listed.sort_unstable();
                assert_eq!(listed, dispatcher.methods(endpoint), "{}", endpoint.name());
            }
            // KNSH-067: the control service is dispatched from the same catalogue; `hello` there names no session.
            let result = hello(&dispatcher, Endpoint::Control, PARAMS).unwrap();
            assert!(result.get("session_id").is_none());
            let mut listed = methods(&result);
            let from_catalogue: Vec<&str> = Catalogue::ENGINE
                .available(knsh_proto::Endpoint::Control, &capabilities)
                .map(|spec| spec.name)
                .collect();
            assert_eq!(listed, from_catalogue);
            assert!(!listed.contains(&"policy.check"), "dry runs are for the sockets only");
            listed.sort_unstable();
            assert_eq!(listed, dispatcher.methods(Endpoint::Control));
        }
    }

    // KNSH-014: version negotiation. No shared protocol is refused with -32005 naming `protocol`.
    #[test]
    fn unsupported_protocol_list_is_refused() {
        let dispatcher = phase1_dispatcher(probe(&Machine::working().probes()), handlers()).unwrap();
        let error = hello(
            &dispatcher,
            Endpoint::User,
            r#"{"client":"test","client_version":"1.0","protocols":[2,3]}"#,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(
            error
                .data
                .as_ref()
                .and_then(Value::as_object)
                .and_then(|d| d.get("capability"))
                .and_then(Value::as_str),
            Some("protocol")
        );
        // Highest shared version wins when several are offered.
        let result = hello(
            &dispatcher,
            Endpoint::User,
            r#"{"client":"test","client_version":"1.0","protocols":[9,1]}"#,
        )
        .unwrap();
        assert_eq!(result.get("protocol").and_then(Value::as_i64), Some(1));
    }

    // KNSH-048: on agent.sock hello binds the connection to the token's session and reports it; a token on
    // user.sock is ignored; an agent hello with no token and no envelope is -32009.
    #[test]
    fn agent_hello_reports_the_bound_session() {
        let fixture = crate::sessions::tests::fixture();
        let dispatcher = dispatcher_with_violations(
            probe(&Machine::working().probes()),
            handlers(),
            ReaderStatus::stopped(),
            Arc::clone(&fixture.sessions),
        )
        .unwrap();
        let (params, session_id) = agent_params(&fixture.sessions);
        let result = hello(&dispatcher, Endpoint::Agent, &params).unwrap();
        assert_eq!(
            result.get("session_id").and_then(Value::as_str),
            Some(session_id.to_string().as_str())
        );
        let user = hello(&dispatcher, Endpoint::User, &params).unwrap();
        assert!(!user.contains_key("session_id"), "no session on user.sock");
        let refused = hello(&dispatcher, Endpoint::Agent, PARAMS).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidSessionToken);
        assert!(refused.data.is_none(), "-32009 says nothing about why");
    }

    #[test]
    fn malformed_hello_params_are_invalid_params() {
        let dispatcher = phase1_dispatcher(probe(&Machine::working().probes()), handlers()).unwrap();
        for params in ["{}", r#"{"client":"c","client_version":"1","protocols":"1"}"#] {
            let error = hello(&dispatcher, Endpoint::User, params).unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidParams, "{params}");
        }
    }

    // KNSH-014, NFR-SEC-10: missing backends are reported as `none`, never omitted.
    #[test]
    fn missing_backend_reported_as_none() {
        let dispatcher = phase1_dispatcher(probe(&Machine::failing().probes()), handlers()).unwrap();
        let result = hello(&dispatcher, Endpoint::User, PARAMS).unwrap();
        let capabilities = capabilities(&result);
        for field in ["sandbox", "network_filter", "file_events", "secrets"] {
            assert_eq!(capabilities.get(field).and_then(Value::as_str), Some("none"), "{field}");
        }
        assert_eq!(
            capabilities
                .get("checkpoints")
                .and_then(Value::as_object)
                .map(Object::len),
            Some(0)
        );
        let platform = result.get("platform").and_then(Value::as_str).unwrap();
        assert!(platform.contains("-unknown-"), "{platform}");
    }

    #[test]
    fn binary_opt_out_is_echoed() {
        let dispatcher = phase1_dispatcher(probe(&Machine::working().probes()), handlers()).unwrap();
        let result = hello(
            &dispatcher,
            Endpoint::User,
            r#"{"client":"test","client_version":"1.0","protocols":[1],"binary_frames":false}"#,
        )
        .unwrap();
        assert_eq!(result.get("binary_frames").and_then(Value::as_bool), Some(false));
    }

    // KNSH-014, KNSH-046: results are cached per knshd lifetime. Any number of `hello`s reuse the one probe, and
    // knsh-exec ran once for it.
    #[test]
    fn probe_runs_once_per_lifetime() {
        let system = Arc::new(knsh_platform::testing::FakeSystemProbe::working(15));
        let machine = Machine::new(
            knsh_platform::testing::Script::Exits(crate::probe::PROBE_DENIED_EXIT),
            system.clone(),
        );
        let dispatcher = phase1_dispatcher(probe(&machine.probes()), handlers()).unwrap();
        let after_probe = system.calls();
        for _ in 0..3 {
            hello(&dispatcher, Endpoint::User, PARAMS).unwrap();
        }
        assert_eq!(after_probe, 2, "os version and file events, once each");
        assert_eq!(system.calls(), after_probe, "hello never probes again");
        assert_eq!(machine.processes.scripted.spawned().len(), 1, "knsh-exec ran once");
        let result = hello(&dispatcher, Endpoint::User, PARAMS).unwrap();
        assert_eq!(
            capabilities(&result).get("sandbox").and_then(Value::as_str),
            Some("seatbelt")
        );
    }

    // KNSH-047: `sandbox_violations` is read at each `hello`, so a reader that stops (or never confirmed its stream)
    // is reported as `none`, and the method list does not change with it.
    #[test]
    fn reports_the_violation_reader_live() {
        let status = ReaderStatus::stopped();
        let dispatcher = dispatcher_with_violations(
            probe(&Machine::working().probes()),
            handlers(),
            Arc::clone(&status),
            sessions(),
        )
        .unwrap();
        let reported = || {
            let result = hello(&dispatcher, Endpoint::User, PARAMS).unwrap();
            let value = capabilities(&result)
                .get("sandbox_violations")
                .and_then(Value::as_str)
                .map(str::to_owned);
            (value, methods(&result).len())
        };
        let (before, methods_before) = reported();
        assert_eq!(before.as_deref(), Some("none"));
        status.set(true);
        let (live, methods_live) = reported();
        assert_eq!(live.as_deref(), Some("unified_log"));
        assert_eq!(methods_live, methods_before);
        status.set(false);
        assert_eq!(reported().0.as_deref(), Some("none"));
    }
}
