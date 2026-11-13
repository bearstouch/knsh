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
//! All failures are reported through the single crate error, [`CoreError`].

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod error;
mod id;
mod path;
mod redacted;
mod time;
mod ulid;

pub use error::CoreError;
pub use id::{CheckpointId, EventId, GrantId, RecordId, RequestId, SessionId};
pub use path::CanonicalPath;
pub use redacted::{REDACTED_MARKER, Redacted};
pub use time::Timestamp;
pub use ulid::{MAX_MILLIS, Ulid};
