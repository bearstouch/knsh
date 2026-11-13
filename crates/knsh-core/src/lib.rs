//! Pure domain model of Kinetic Shell.
//!
//! Sessions, records, events, the policy model and its evaluation, verdict combining, grants and rate limiting.
//!
//! # Boundaries
//!
//! No I/O of any kind: effects are injected by callers. Depends only on the parser crates.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/policy.md`
//! - `specs/03-functional-requirements/sessions.md`
//! - `specs/05-models/session.md`
//! - `specs/05-models/policy-profile.md`
//! - `specs/05-models/grant.md`
//! - `specs/05-models/execution-record.md`
//!
//! # Value types (KNSH-002)
//!
//! Typed building blocks that make common mix-ups fail to compile:
//!
//! - [`Ulid`] and the ID newtypes over it ([`SessionId`], [`RecordId`], [`EventId`], [`RequestId`],
//!   [`CheckpointId`], [`GrantId`]), which never convert into one another implicitly.
//! - [`CanonicalPath`], an absolute, already-resolved path (FR-POL-11).
//! - [`Redacted`], which never prints its inner value (NFR-PRIV-02).
//! - [`Timestamp`], UTC microseconds formatted as RFC 3339.
//!
//! # Sessions (KNSH-015)
//!
//! - [`Session`]: one actor fixed at creation (FR-SES-01), recording defaults per actor (FR-SES-04), and the state
//!   machine of `specs/03-functional-requirements/sessions.md#states`, where every change yields a
//!   [`StateChanged`] value (FR-SES-14) and a refused transition leaves the state unchanged.
//! - [`SessionRegistry`]: the live sessions, unique IDs, parent links (FR-SES-03) with the [`ProfileOrder`] hook
//!   for agent children, and "not found or ended" for sessions that have ended (`-32006`).
//!
//! # Execution records (KNSH-016)
//!
//! [`ExecutionRecord`] is one record of `specs/05-models/execution-record.md`: its text fields are [`Redacted`] or
//! typed (FR-REC-11), and the agent-only fields sit in [`RecordDetails`] so a human record can drop them as one unit
//! (FR-REC-09). [`OutputInfo`] describes a capped output stream (FR-REC-06) and [`OutputStream`] names it.
//! [`Timestamp`] also parses its own text form, for time filters.
//!
//! All failures are reported through the single crate error, [`CoreError`].

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod error;
mod id;
mod path;
mod record;
mod redacted;
mod registry;
mod session;
mod time;
mod ulid;

pub use error::CoreError;
pub use id::{CheckpointId, EventId, GrantId, RecordId, RequestId, SessionId};
pub use path::CanonicalPath;
pub use record::{ExecutionRecord, OutputInfo, OutputStream, RecordDetails};
pub use redacted::{REDACTED_MARKER, Redacted};
pub use registry::{EqualProfileOnly, ProfileOrder, SessionRegistry};
pub use session::{
    Actor, ActorKind, AgentId, MAX_NAME_LEN, ProfileName, STATE_CHANGED_EVENT, Session, SessionSpec, SessionState,
    StateChanged, Transition, default_recording,
};
pub use time::Timestamp;
pub use ulid::{MAX_MILLIS, Ulid};
