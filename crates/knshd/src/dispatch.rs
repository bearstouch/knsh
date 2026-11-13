//! Per-endpoint dispatch tables (KNSH-013).
//!
//! Each endpoint has its own [`Table`]: a method is callable on an endpoint only if that endpoint's table holds it.
//! A method in no table is unknown (`-32601`); a method in another endpoint's table is known but not allowed here
//! (`-32003`), so an agent learns that `session.start_agent` exists but is not for `agent.sock`, and never reaches
//! its handler (`specs/06-api/README.md`, `specs/02-architecture/endpoints.md`).
//!
//! The method catalogue that fills the tables, and the real `hello`, arrive with KNSH-014; until then
//! [`Dispatcher::phase1`] holds a minimal `hello` on `user.sock` only.

use std::collections::BTreeMap;
use std::sync::Arc;

use knsh_json::{Object, Value};
use knsh_proto::{ErrorCode, MethodName, Request, RpcError};

/// The name of the handshake method, which every connection must call first.
pub(crate) const HELLO: &str = "hello";

/// The protocol version this engine speaks (`specs/06-api/handshake.md`).
const PROTOCOL: i64 = 1;

/// A Unix-socket endpoint (`specs/02-architecture/endpoints.md`). The control service (XPC) is not served here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Endpoint {
    /// `user.sock`: user processes outside envelopes.
    User,
    /// `agent.sock`: processes inside envelopes.
    Agent,
}

impl Endpoint {
    /// A fixed name for the system log.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Agent => "agent",
        }
    }
}

/// What a handler returns: the `result` of a success response, or the error to answer with.
pub(crate) type Reply = Result<Value, RpcError>;

/// A method implementation. Shared by every connection thread, so it must be `Send + Sync`; it owns whatever
/// services it needs.
pub(crate) type Handler = Arc<dyn Fn(&Request) -> Reply + Send + Sync>;

/// The methods one endpoint serves, by name.
#[derive(Clone, Default)]
pub(crate) struct Table {
    methods: BTreeMap<&'static str, Handler>,
}

impl Table {
    /// An empty table: every call is refused.
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

    fn contains(&self, name: &str) -> bool {
        self.methods.contains_key(name)
    }
}

/// Where a call goes.
pub(crate) enum Route<'a> {
    /// This endpoint serves the method.
    Serve(&'a Handler),
    /// Another endpoint serves it, this one does not (`-32003`).
    NotAllowed,
    /// No endpoint serves it (`-32601`).
    Unknown,
}

/// The dispatch tables of both endpoints.
#[derive(Clone)]
pub(crate) struct Dispatcher {
    user: Table,
    agent: Table,
}

impl Dispatcher {
    /// A dispatcher over the two endpoints' tables.
    pub(crate) fn new(user: Table, agent: Table) -> Self {
        Self { user, agent }
    }

    /// The tables `knshd` serves in phase 1, before the method catalogue (KNSH-014): `hello` on `user.sock`.
    /// `agent.sock` has an empty table; its connections are closed unserved until phase 2 (KNSH-048).
    pub(crate) fn phase1() -> Self {
        Self::new(Table::new().with(HELLO, Arc::new(placeholder_hello)), Table::new())
    }

    /// Finds where `method` goes on `endpoint`.
    pub(crate) fn route(&self, endpoint: Endpoint, method: &MethodName) -> Route<'_> {
        let (own, other) = match endpoint {
            Endpoint::User => (&self.user, &self.agent),
            Endpoint::Agent => (&self.agent, &self.user),
        };
        let name = method.as_str();
        match own.get(name) {
            Some(handler) => Route::Serve(handler),
            None if other.contains(name) => Route::NotAllowed,
            None => Route::Unknown,
        }
    }

    /// Calls the handler for `request` on `endpoint`, or answers why it cannot be called.
    pub(crate) fn call(&self, endpoint: Endpoint, request: &Request) -> Reply {
        match self.route(endpoint, &request.method) {
            Route::Serve(handler) => handler(request),
            Route::NotAllowed => Err(RpcError::new(ErrorCode::NotAllowed)),
            Route::Unknown => Err(RpcError::new(ErrorCode::MethodNotFound)),
        }
    }
}

/// `hello` until KNSH-014: names the engine version and protocol 1, nothing more. It claims no capability, so it
/// cannot overstate one (NFR-SEC-10); version negotiation and the capability report arrive with the catalogue.
fn placeholder_hello(_request: &Request) -> Reply {
    let internal = |_| RpcError::new(ErrorCode::InternalError);
    let result = Object::new()
        .with("engine_version", env!("CARGO_PKG_VERSION"))
        .map_err(internal)?
        .with("protocol", Value::int(PROTOCOL).map_err(internal)?)
        .map_err(internal)?;
    Ok(Value::Object(result))
}

#[cfg(test)]
pub(crate) mod tests {
    use knsh_proto::RequestId;

    use super::*;

    /// A request for `method` with id 1 and no params.
    pub(crate) fn request(method: &str) -> Request {
        Request {
            id: RequestId::from(1u32),
            method: MethodName::new(method).unwrap(),
            params: None,
        }
    }

    /// A handler that answers `true`.
    pub(crate) fn ok_handler() -> Handler {
        Arc::new(|_: &Request| Ok(Value::from(true)))
    }

    fn dispatcher() -> Dispatcher {
        Dispatcher::new(
            Table::new()
                .with(HELLO, ok_handler())
                .with("session.start_agent", ok_handler()),
            Table::new().with(HELLO, ok_handler()).with("exec.run", ok_handler()),
        )
    }

    // KNSH-013: endpoint scoping. A method another endpoint serves is known but not allowed here (-32003).
    #[test]
    fn method_not_on_endpoint_returns_minus_32003() {
        let dispatcher = dispatcher();
        let error = dispatcher
            .call(Endpoint::Agent, &request("session.start_agent"))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed);
        let error = dispatcher.call(Endpoint::User, &request("exec.run")).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed);
        // Each endpoint still serves its own.
        assert!(dispatcher.call(Endpoint::User, &request("session.start_agent")).is_ok());
        assert!(dispatcher.call(Endpoint::Agent, &request("exec.run")).is_ok());
    }

    #[test]
    fn method_in_no_table_returns_minus_32601() {
        let error = dispatcher().call(Endpoint::User, &request("no.such")).unwrap_err();
        assert_eq!(error.code, ErrorCode::MethodNotFound);
    }

    // Phase 1 serves `hello` on user.sock only; agent.sock serves nothing until phase 2.
    #[test]
    fn phase1_tables_serve_hello_on_user_sock_only() {
        let dispatcher = Dispatcher::phase1();
        let result = dispatcher.call(Endpoint::User, &request(HELLO)).unwrap();
        let Value::Object(result) = result else {
            panic!("hello result is not an object")
        };
        assert_eq!(result.get("protocol").and_then(Value::as_i64), Some(PROTOCOL));
        assert_eq!(
            dispatcher.call(Endpoint::Agent, &request(HELLO)).unwrap_err().code,
            ErrorCode::NotAllowed
        );
    }
}
