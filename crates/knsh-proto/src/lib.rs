//! JSON-RPC protocol types for the engine endpoints.
//!
//! Method parameters and results, the API error codes and the capability model.
//!
//! # Boundaries
//!
//! API error codes (`-32001`...) live only in this crate, in [`ErrorCode`]. Depends on `knsh-json` and `knsh-core`.
//! Messages arrive from untrusted processes: they are read strictly and never repaired, and errors built here never
//! echo text from the input.
//!
//! # Specification
//!
//! - `specs/06-api/README.md` (envelope and method names)
//! - `specs/06-api/errors.md`
//! - `specs/06-api/wire-format.md#strict-json-profile`
//! - `specs/06-api/handshake.md`
//! - `specs/05-models/capabilities.md`
//!
//! # JSON-RPC envelope (KNSH-008)
//!
//! - [`decode`] reads one frame payload into a [`Message`]: a [`Request`], [`Notification`], [`SuccessResponse`] or
//!   [`ErrorResponse`]. Anything else is a [`Rejection`]: strict-profile violations are [`ErrorCode::ParseError`]
//!   (`-32700`), envelope faults [`ErrorCode::InvalidRequest`], malformed method names
//!   [`ErrorCode::MethodNotFound`], and parameters that do not fit [`ErrorCode::InvalidParams`].
//!   [`Rejection::response`] builds the answer, or nothing for notifications and responses.
//! - [`encode`] writes a message as strict-profile JSON.
//! - [`ErrorCode`] defines every code with its meaning and `data` fields, checked against `errors.md` by a test.
//! - [`MethodName`] validates `area.verb` names for the method catalogue (KNSH-014).
//!
//! # Handshake, method catalogue and capabilities (KNSH-014)
//!
//! - [`Catalogue::ENGINE`] declares every client-callable method once: its [`Endpoints`], its [`Availability`] in
//!   this build, the [`Backend`] it needs and its [`Deprecation`]. [`Catalogue::available`] is the single query
//!   `knshd` builds both its dispatch tables and `hello`'s `methods` list from.
//! - [`Capabilities`] models what the probe found; every backend is an enum with an explicit `none`, so a missing
//!   backend is reported, never omitted (NFR-SEC-10, NFR-REL-08). [`Platform`] writes `macos-<major>-<arch>`.
//! - [`HelloParams`], [`negotiate`] and [`HelloResult`] are the handshake itself; [`ByteTransport`] records a
//!   client's opt-out of binary frames (base64 inside JSON instead).
//!
//! Parameters and results of the other methods arrive with the stories that implement them.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod capability;
mod catalogue;
mod envelope;
mod error;
mod error_code;
mod hello;
mod method;

pub use capability::{
    Backend, Capabilities, CheckpointBackend, FileEvents, NONE, NetworkFilter, Platform, Sandbox, Secrets,
};
pub use catalogue::{
    Availability, Catalogue, CatalogueError, DEPRECATION_WINDOW, Deprecation, Endpoint, Endpoints, Lookup, MethodSpec,
    Release,
};
pub use hello::{
    ByteTransport, HelloParams, HelloResult, MAX_CLIENT_FIELD_LEN, MAX_PROTOCOLS, MAX_SESSION_TOKEN_LEN,
    PROTOCOL_CAPABILITY, SUPPORTED_PROTOCOLS, negotiate,
};

pub use envelope::{
    ErrorResponse, MAX_ID_LEN, Message, Notification, Rejection, Request, RequestId, RpcError, SuccessResponse, decode,
    encode,
};
pub use error::{EnvelopeFault, ProtoError};
pub use error_code::ErrorCode;
pub use method::{MAX_METHOD_NAME_LEN, MethodName};
