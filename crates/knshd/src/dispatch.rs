//! Per-endpoint dispatch tables, generated from the method catalogue (KNSH-013, KNSH-014).
//!
//! [`Dispatcher::build`] fills each endpoint's [`Table`] from [`Catalogue::available`], the same query `hello` lists
//! its `methods` from, so a method is callable exactly when `hello` lists it on that endpoint. A handler for a method
//! the catalogue does not mark available, or an available method without a handler, is a build error: the catalogue
//! stays the single source of truth.
//!
//! A call to a method not in the endpoint's table is answered from the catalogue:
//!
//! - another endpoint's method: `-32003` (known, but not for this caller);
//! - available here but its backend is `none`: `-32005` with `data.capability`;
//! - planned, unknown, or anything else: `-32601`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use knsh_json::{Object, StreamId, Value};
use knsh_proto::{
    Availability, Backend, ByteTransport, Capabilities, Catalogue, CatalogueError, ErrorCode, Lookup, MethodName,
    Release, Request, RpcError,
};

use crate::events::Subscriber;

/// The name of the handshake method, which every connection must call first.
pub(crate) const HELLO: &str = "hello";

/// A Unix-socket endpoint (`specs/02-architecture/endpoints.md`). The control service (XPC) is not served here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Endpoint {
    /// `user.sock`: user processes outside envelopes.
    User,
    /// `agent.sock`: processes inside envelopes.
    Agent,
}

impl Endpoint {
    /// Both socket endpoints.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 2] = [Self::User, Self::Agent];

    /// A fixed name for the system log.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Agent => "agent",
        }
    }

    /// The same endpoint in the method catalogue.
    pub(crate) const fn catalogue(self) -> knsh_proto::Endpoint {
        match self {
            Self::User => knsh_proto::Endpoint::User,
            Self::Agent => knsh_proto::Endpoint::Agent,
        }
    }
}

/// One call as a handler sees it.
pub(crate) struct Call<'a> {
    /// The endpoint the call arrived on.
    pub(crate) endpoint: Endpoint,
    /// How this connection receives raw bytes, as settled by `hello` (binary frames until then).
    pub(crate) bytes: ByteTransport,
    /// The stream ID this call's raw bytes go on if the handler returns any ([`Answer::bytes`]). The handler names
    /// it in its result; the connection writes the bytes on it right after the result.
    pub(crate) stream: StreamId,
    /// The request.
    pub(crate) request: &'a Request,
    /// The connection's event subscriptions (`events.subscribe`, KNSH-018). Closed with the connection.
    pub(crate) subscriber: &'a Subscriber,
}

/// A successful answer: the `result`, and raw bytes to send after it on [`Call::stream`]
/// (`specs/06-api/wire-format.md#frames-unix-sockets`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Answer {
    /// The `result` member of the success response. When `bytes` is set, it names [`Call::stream`] and its size.
    pub(crate) result: Value,
    /// Raw bytes for a binary stream, sent in chunks after the result and closed with an end-of-stream frame.
    pub(crate) bytes: Option<Vec<u8>>,
}

impl From<Value> for Answer {
    /// A result with no raw bytes.
    fn from(result: Value) -> Self {
        Self { result, bytes: None }
    }
}

/// What a handler returns: the answer of a success response, or the error to answer with.
pub(crate) type Reply = Result<Answer, RpcError>;

/// A method implementation. Shared by every connection thread, so it must be `Send + Sync`; it owns whatever
/// services it needs.
pub(crate) type Handler = Arc<dyn Fn(&Call<'_>) -> Reply + Send + Sync>;

/// The handlers `knshd` implements, by method name.
pub(crate) type Handlers = BTreeMap<&'static str, Handler>;

/// The methods one endpoint serves, by name.
#[derive(Clone, Default)]
pub(crate) struct Table {
    methods: BTreeMap<&'static str, Handler>,
}

impl Table {
    /// An empty table: every call is refused.
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The table with `handler` serving `name`, replacing any earlier handler for it.
    #[must_use]
    pub(crate) fn with(mut self, name: &'static str, handler: Handler) -> Self {
        self.methods.insert(name, handler);
        self
    }

    fn get(&self, name: &str) -> Option<&Handler> {
        self.methods.get(name)
    }

    /// The names served, in name order.
    #[cfg(test)]
    pub(crate) fn names(&self) -> Vec<&'static str> {
        self.methods.keys().copied().collect()
    }
}

/// Why the dispatch tables could not be built. Every case is a programming error caught at start-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// The catalogue is inconsistent.
    Catalogue(CatalogueError),
    /// The catalogue marks a method available but no handler implements it.
    MissingHandler(&'static str),
    /// A handler implements a method the catalogue does not mark available.
    UnlistedHandler(&'static str),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalogue(error) => write!(f, "method catalogue: {error}"),
            Self::MissingHandler(name) => write!(f, "no handler for available method {name:?}"),
            Self::UnlistedHandler(name) => write!(f, "handler for {name:?}, which the catalogue does not list"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Where a call goes.
pub(crate) enum Route<'a> {
    /// This endpoint serves the method.
    Serve(&'a Handler),
    /// Another endpoint serves it, this one does not (`-32003`).
    NotAllowed,
    /// The method needs a backend this machine lacks (`-32005`).
    Unavailable(Backend),
    /// Not callable here (`-32601`).
    Unknown,
}

/// The dispatch tables of both endpoints, with the catalogue and capabilities they were generated from.
#[derive(Clone)]
pub(crate) struct Dispatcher {
    catalogue: Catalogue,
    capabilities: Arc<Capabilities>,
    user: Table,
    agent: Table,
}

impl Dispatcher {
    /// Generates both endpoints' tables from `catalogue`, the probed `capabilities` and the implemented `handlers`.
    ///
    /// # Errors
    ///
    /// [`BuildError`] if the catalogue is invalid for this release, an available method has no handler, or a handler
    /// implements a method the catalogue does not mark available.
    pub(crate) fn build(
        catalogue: Catalogue,
        capabilities: Arc<Capabilities>,
        handlers: &Handlers,
    ) -> Result<Self, BuildError> {
        catalogue.validate(Release::current()).map_err(BuildError::Catalogue)?;
        // Checked against the catalogue, not the tables: a handler whose backend is missing here is still listed.
        for &name in handlers.keys() {
            match catalogue.find(name) {
                Some(spec) if spec.availability == Availability::Available => {}
                Some(_) | None => return Err(BuildError::UnlistedHandler(name)),
            }
        }
        let table = |endpoint: Endpoint| {
            catalogue
                .available(endpoint.catalogue(), &capabilities)
                .try_fold(Table::default(), |table, spec| {
                    let handler = handlers.get(spec.name).ok_or(BuildError::MissingHandler(spec.name))?;
                    Ok(table.with(spec.name, Arc::clone(handler)))
                })
        };
        let user = table(Endpoint::User)?;
        let agent = table(Endpoint::Agent)?;
        Ok(Self {
            catalogue,
            capabilities,
            user,
            agent,
        })
    }

    /// Tables given directly, for tests of the connection loop and server. Calls outside them are still answered
    /// from the engine catalogue, with every backend `none`.
    #[cfg(test)]
    pub(crate) fn from_tables(user: Table, agent: Table) -> Self {
        Self {
            catalogue: Catalogue::ENGINE,
            capabilities: Arc::new(tests::no_backends()),
            user,
            agent,
        }
    }

    fn table(&self, endpoint: Endpoint) -> &Table {
        match endpoint {
            Endpoint::User => &self.user,
            Endpoint::Agent => &self.agent,
        }
    }

    /// The methods `endpoint` serves, in name order.
    #[cfg(test)]
    pub(crate) fn methods(&self, endpoint: Endpoint) -> Vec<&'static str> {
        self.table(endpoint).names()
    }

    /// Finds where `method` goes on `endpoint`.
    pub(crate) fn route(&self, endpoint: Endpoint, method: &MethodName) -> Route<'_> {
        let name = method.as_str();
        if let Some(handler) = self.table(endpoint).get(name) {
            return Route::Serve(handler);
        }
        match self.catalogue.lookup(endpoint.catalogue(), name, &self.capabilities) {
            Lookup::NotOnEndpoint => Route::NotAllowed,
            Lookup::Unavailable(backend) => Route::Unavailable(backend),
            // `Available` without a table entry only happens with hand-built test tables: not callable here.
            Lookup::Available(_) | Lookup::Planned | Lookup::Unknown => Route::Unknown,
        }
    }

    /// Calls the handler for `call` on its endpoint, or answers why it cannot be called.
    pub(crate) fn call(&self, call: &Call<'_>) -> Reply {
        match self.route(call.endpoint, &call.request.method) {
            Route::Serve(handler) => handler(call),
            Route::NotAllowed => Err(RpcError::new(ErrorCode::NotAllowed)),
            Route::Unavailable(backend) => Err(capability_unavailable(backend.name())),
            Route::Unknown => Err(RpcError::new(ErrorCode::MethodNotFound)),
        }
    }
}

/// `-32005` naming the missing `capability` (`specs/06-api/errors.md`).
pub(crate) fn capability_unavailable(capability: &'static str) -> RpcError {
    let error = RpcError::new(ErrorCode::CapabilityUnavailable);
    match Object::new().with("capability", capability) {
        Ok(data) => error.with_data(Value::Object(data)),
        // A one-key object with a fixed key cannot fail to build; without data the code still says enough.
        Err(_) => error,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use knsh_proto::{Endpoints, FileEvents, MethodSpec, NetworkFilter, RequestId, Sandbox, Secrets};

    use super::*;

    /// Capabilities with every backend `none`.
    pub(crate) fn no_backends() -> Capabilities {
        Capabilities {
            sandbox: Sandbox::None,
            network_filter: NetworkFilter::None,
            file_events: FileEvents::None,
            secrets: Secrets::None,
            checkpoints: BTreeMap::new(),
        }
    }

    /// A request for `method` with id 1 and no params.
    pub(crate) fn request(method: &str) -> Request {
        Request {
            id: RequestId::from(1u32),
            method: MethodName::new(method).unwrap(),
            params: None,
        }
    }

    /// A connection subscriber for test calls that do not subscribe.
    pub(crate) fn subscriber() -> &'static Subscriber {
        static SUBSCRIBER: std::sync::LazyLock<Subscriber> = std::sync::LazyLock::new(Subscriber::new);
        &SUBSCRIBER
    }

    /// The stream ID test calls use.
    pub(crate) fn stream() -> StreamId {
        StreamId::new(1).unwrap()
    }

    /// Calls `method` on `endpoint` with binary frames.
    pub(crate) fn call(dispatcher: &Dispatcher, endpoint: Endpoint, method: &str) -> Reply {
        dispatcher.call(&Call {
            endpoint,
            bytes: ByteTransport::BinaryFrames,
            stream: stream(),
            request: &request(method),
            subscriber: subscriber(),
        })
    }

    /// A handler that answers `true`.
    pub(crate) fn ok_handler() -> Handler {
        Arc::new(|_: &Call<'_>| Ok(Value::from(true).into()))
    }

    const TEST_METHODS: &[MethodSpec] = &[
        MethodSpec {
            name: "hello",
            endpoints: Endpoints::ALL,
            availability: Availability::Available,
            requires: None,
            deprecated: None,
        },
        MethodSpec {
            name: "exec.run",
            endpoints: Endpoints::AGENT,
            availability: Availability::Available,
            requires: Some(Backend::Sandbox),
            deprecated: None,
        },
        MethodSpec {
            name: "session.start_agent",
            endpoints: Endpoints::USER,
            availability: Availability::Available,
            requires: None,
            deprecated: None,
        },
        MethodSpec {
            name: "records.query",
            endpoints: Endpoints::SOCKETS,
            availability: Availability::Planned,
            requires: None,
            deprecated: None,
        },
    ];

    fn handlers(names: &[&'static str]) -> Handlers {
        names.iter().map(|&name| (name, ok_handler())).collect()
    }

    fn built(sandbox: Sandbox) -> Dispatcher {
        let capabilities = Capabilities {
            sandbox,
            ..no_backends()
        };
        Dispatcher::build(
            Catalogue::new(TEST_METHODS),
            Arc::new(capabilities),
            &handlers(&["hello", "exec.run", "session.start_agent"]),
        )
        .unwrap()
    }

    // KNSH-013: endpoint scoping. A method another endpoint serves is known but not allowed here (-32003).
    #[test]
    fn method_not_on_endpoint_returns_minus_32003() {
        let dispatcher = built(Sandbox::Seatbelt);
        let error = call(&dispatcher, Endpoint::Agent, "session.start_agent").unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed);
        let error = call(&dispatcher, Endpoint::User, "exec.run").unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed);
        // Each endpoint still serves its own.
        assert!(call(&dispatcher, Endpoint::User, "session.start_agent").is_ok());
        assert!(call(&dispatcher, Endpoint::Agent, "exec.run").is_ok());
    }

    #[test]
    fn unknown_or_planned_method_returns_minus_32601() {
        let dispatcher = built(Sandbox::Seatbelt);
        for name in ["no.such", "records.query"] {
            let error = call(&dispatcher, Endpoint::User, name).unwrap_err();
            assert_eq!(error.code, ErrorCode::MethodNotFound, "{name}");
        }
    }

    // KNSH-014, NFR-SEC-10: a method whose backend is `none` is not served and says which capability is missing.
    #[test]
    fn method_without_its_backend_returns_minus_32005() {
        let dispatcher = built(Sandbox::None);
        let error = call(&dispatcher, Endpoint::Agent, "exec.run").unwrap_err();
        assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
        let data = error.data.unwrap();
        assert_eq!(
            data.as_object()
                .and_then(|d| d.get("capability"))
                .and_then(Value::as_str),
            Some("sandbox")
        );
        assert_eq!(dispatcher.methods(Endpoint::Agent), ["hello"]);
    }

    // KNSH-014: single source of truth. The tables hold exactly the catalogue's available methods per endpoint.
    #[test]
    fn tables_are_generated_from_the_catalogue() {
        let dispatcher = built(Sandbox::Seatbelt);
        let capabilities = Capabilities {
            sandbox: Sandbox::Seatbelt,
            ..no_backends()
        };
        for endpoint in Endpoint::ALL {
            let mut expected: Vec<&str> = Catalogue::new(TEST_METHODS)
                .available(endpoint.catalogue(), &capabilities)
                .map(|spec| spec.name)
                .collect();
            expected.sort_unstable();
            assert_eq!(dispatcher.methods(endpoint), expected, "{}", endpoint.name());
        }
        assert_eq!(dispatcher.methods(Endpoint::User), ["hello", "session.start_agent"]);
        assert_eq!(dispatcher.methods(Endpoint::Agent), ["exec.run", "hello"]);
    }

    #[test]
    fn handlers_must_match_the_catalogue() {
        let catalogue = Catalogue::new(TEST_METHODS);
        let capabilities = Arc::new(no_backends());
        let missing = Dispatcher::build(catalogue, Arc::clone(&capabilities), &handlers(&["hello", "exec.run"]));
        assert_eq!(missing.err(), Some(BuildError::MissingHandler("session.start_agent")));
        // A planned method cannot be served by registering a handler for it.
        let planned = Dispatcher::build(
            catalogue,
            Arc::clone(&capabilities),
            &handlers(&["hello", "exec.run", "session.start_agent", "records.query"]),
        );
        assert_eq!(planned.err(), Some(BuildError::UnlistedHandler("records.query")));
        let unknown = Dispatcher::build(catalogue, capabilities, &handlers(&["hello", "no.such"]));
        assert_eq!(unknown.err(), Some(BuildError::UnlistedHandler("no.such")));
    }

    #[test]
    fn invalid_catalogue_is_a_build_error() {
        const NO_HELLO: &[MethodSpec] = &[];
        let result = Dispatcher::build(Catalogue::new(NO_HELLO), Arc::new(no_backends()), &Handlers::new());
        assert_eq!(result.err(), Some(BuildError::Catalogue(CatalogueError::Hello)));
    }
}
