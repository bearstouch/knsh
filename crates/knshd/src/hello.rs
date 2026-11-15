//! The `hello` handler and the phase-1 method set (KNSH-014, `specs/06-api/handshake.md`).
//!
//! `hello` settles the protocol, reports the platform and the probed capabilities, and lists the methods callable on
//! the caller's endpoint. That list comes from [`Catalogue::available`] with the same capabilities the dispatch
//! tables were generated from ([`phase1_dispatcher`]), so `hello` never lists a method the endpoint does not serve.
//!
//! - No protocol in common: `-32005` with `capability: "protocol"`; the connection loop then closes the connection.
//! - Malformed parameters: `-32602`, which also closes the connection (a failed `hello`).
//! - `session_token` and `session_id` belong to `agent.sock`, whose connections are not served until phase 2
//!   (KNSH-048). The token is read (bounded, redacted) and otherwise ignored; no `session_id` is reported.
//! - Phase 1 builds report `advisory: true`: no security guarantees, not for running agents unattended (KNSH-024).

use std::sync::Arc;

use knsh_json::ToJson;
use knsh_proto::{Catalogue, ErrorCode, HelloParams, HelloResult, PROTOCOL_CAPABILITY, RpcError, negotiate};

use crate::dispatch::{BuildError, Call, Dispatcher, HELLO, Handler, Handlers, Reply, capability_unavailable};
use crate::probe::Probed;

/// Phase 1 is advisory (`specs/01-overview/roadmap.md`): the label is in every `hello` until phase 2 qualifies.
const ADVISORY: bool = true;

/// What `hello` reports, fixed for the lifetime of this `knshd`.
struct Handshake {
    /// The catalogue the tables were generated from.
    catalogue: Catalogue,
    /// The probe result.
    probed: Probed,
    /// Whether this build is advisory only.
    advisory: bool,
}

impl Handshake {
    /// Answers one `hello`. Bad params are `-32602` and no shared protocol is `-32005`; either way the connection
    /// loop closes the connection, since a failed `hello` ends it.
    fn answer(&self, call: &Call<'_>) -> Reply {
        let params: HelloParams = call.request.params().map_err(|error| RpcError::from(&error))?;
        let protocol = negotiate(&params.protocols).ok_or_else(|| capability_unavailable(PROTOCOL_CAPABILITY))?;
        let capabilities = self.probed.capabilities.as_ref();
        let result = HelloResult {
            engine_version: env!("CARGO_PKG_VERSION"),
            protocol,
            platform: self.probed.platform,
            session_id: None,
            advisory: self.advisory,
            bytes: params.bytes,
            capabilities,
            methods: self
                .catalogue
                .available(call.endpoint.catalogue(), capabilities)
                .collect(),
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

/// The dispatcher `knshd` serves in phase 1: the engine catalogue, the probed capabilities, `hello`, and the
/// `others` implemented elsewhere (`records.query` and `records.output`, KNSH-016).
///
/// # Errors
///
/// [`BuildError`] if the catalogue and the handlers disagree (a programming error caught at start-up).
pub(crate) fn phase1_dispatcher(probed: Probed, others: Handlers) -> Result<Dispatcher, BuildError> {
    let catalogue = Catalogue::ENGINE;
    let capabilities = Arc::clone(&probed.capabilities);
    let handshake = Arc::new(Handshake {
        catalogue,
        probed,
        advisory: ADVISORY,
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

    /// Every handler besides `hello`: records without a store, events on an empty bus, sessions that cannot record
    /// (no store), and `policy.check` over an empty filesystem.
    pub(crate) fn handlers() -> Handlers {
        let mut handlers = crate::records::Records::unavailable().handlers();
        let hub = crate::events::tests::hub();
        handlers.extend(hub.handlers());
        let sessions = crate::sessions::Sessions::new(
            None,
            hub,
            std::sync::Arc::new(knsh_platform::testing::FakeClock::new(knsh_core::Timestamp::UNIX_EPOCH)),
            std::sync::Arc::new(knsh_platform::testing::SeededRandom::new(1)),
        );
        handlers.extend(sessions.handlers());
        handlers.extend(crate::policy::tests::service(sessions, knsh_platform::testing::MemFs::new()).handlers());
        handlers
    }

    const PARAMS: &str = r#"{"client":"test","client_version":"1.0","protocols":[1]}"#;

    fn hello(dispatcher: &Dispatcher, endpoint: Endpoint, params: &str) -> Result<Object, RpcError> {
        let request = hello_request(params);
        dispatcher
            .call(&Call {
                endpoint,
                bytes: ByteTransport::BinaryFrames,
                stream: crate::dispatch::tests::stream(),
                request: &request,
                subscriber: crate::dispatch::tests::subscriber(),
                binding: crate::dispatch::tests::binding(),
            })
            .map(|answer| answer.result.as_object().cloned().unwrap())
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
            let dispatcher = phase1_dispatcher(probed, handlers()).unwrap();
            for endpoint in Endpoint::ALL {
                let result = hello(&dispatcher, endpoint, PARAMS).unwrap();
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

    // KNSH-014: results are cached per knshd lifetime. Any number of `hello`s reuse the one probe.
    #[test]
    fn probe_runs_once_per_lifetime() {
        let system = Arc::new(knsh_platform::testing::FakeSystemProbe::working(15));
        let machine = Machine::new(knsh_platform::testing::Script::Exits(0), system.clone());
        let dispatcher = phase1_dispatcher(probe(&machine.probes()), handlers()).unwrap();
        let after_probe = system.calls();
        for _ in 0..3 {
            hello(&dispatcher, Endpoint::User, PARAMS).unwrap();
        }
        assert_eq!(after_probe, 2, "os version and file events, once each");
        assert_eq!(system.calls(), after_probe, "hello never probes again");
        assert_eq!(machine.processes.spawned().len(), 1, "sandbox-exec ran once");
    }
}
