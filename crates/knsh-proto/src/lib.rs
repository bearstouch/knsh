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
//! # Records (KNSH-016)
//!
//! [`RecordsQueryParams`] and [`RecordsOutputParams`] read `records.query` and `records.output` strictly (canonical
//! IDs, the engine's timestamp form, byte counts as strings); [`RecordsQueryResult`] and [`RecordsOutputResult`]
//! write their answers, with the raw bytes either announced as a binary stream or inlined as base64
//! ([`OutputData`]).
//!
//! # Forget (KNSH-017)
//!
//! [`RecordsForgetParams`] reads and writes `records.forget` (`user.sock` only): a session, an instant, or both, and
//! never neither. [`RecordsForgetResult`] carries the number of records deleted.
//!
//! # Events (KNSH-018)
//!
//! [`EventsSubscribeParams`], [`EventsSubscribeResult`] and [`EventsUnsubscribeParams`] read and write
//! `events.subscribe` and `events.unsubscribe`. [`event_notification`] writes an event as a notification named after
//! it, whose params are the envelope of `specs/05-models/event.md` ([`event_envelope`]) plus `subscription_id`;
//! [`lost_notification`] announces events a subscriber fell too far behind to receive ([`EVENTS_LOST`]).
//!
//! # Human sessions (KNSH-021)
//!
//! [`SessionStartHumanParams`] and [`SessionStartHumanResult`] start a recorded human session bound to a `user.sock`
//! connection. [`TelemetryCommandParams`] carries one typed command line with only the fields of FR-REC-09,
//! [`TelemetryCwdParams`] a working directory change and [`TelemetryIdleParams`] an idle prompt (FR-SES-24).
//! [`SessionInfoResult`] answers `session.info` with the caller's session and its recording state (FR-SES-25,
//! NFR-PRIV-05).
//!
//! # Policy dry runs (KNSH-043)
//!
//! [`PolicyCheckParams`] reads `policy.check` strictly: a bounded line, a resolved working directory, an optional
//! `PATH`, and at most one [`PolicyCheckTarget`] (`session_id` or `profile`). [`PolicyCheckResult`] writes the
//! verdict, its source and rule, every matched rule, each command's class and dynamic reason, the line's dynamic
//! parts and its network classes (FR-POL-70).
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
mod events;
mod hello;
mod method;
mod policy;
mod records;
mod session;

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
pub use events::{
    EVENTS_LOST, EventsSubscribeParams, EventsSubscribeResult, EventsUnsubscribeParams, event_envelope,
    event_notification, lost_notification,
};
pub use method::{MAX_METHOD_NAME_LEN, MethodName};
pub use policy::{
    DEFAULT_POLICY_CHECK_PATH, MAX_POLICY_CHECK_COMMAND_LEN, MAX_POLICY_CHECK_PATH_LEN, PolicyCheckParams,
    PolicyCheckResult, PolicyCheckTarget,
};
pub use records::{
    DEFAULT_RECORDS_PAGE, MAX_BASE64_OUTPUT, MAX_RECORDS_PAGE, MAX_RECORDS_TEXT_LEN, OUTPUT_CONTENT_TYPE, OutputData,
    RecordEntry, RecordsForgetParams, RecordsForgetResult, RecordsOutputParams, RecordsOutputResult,
    RecordsQueryParams, RecordsQueryResult,
};
pub use session::{
    MAX_TELEMETRY_COMMAND_LEN, MAX_TELEMETRY_CWD_LEN, SessionInfoResult, SessionStartHumanParams,
    SessionStartHumanResult, TelemetryCommandParams, TelemetryCommandResult, TelemetryCwdParams, TelemetryIdleParams,
};
