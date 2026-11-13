//! Per-user daemon and supervisor.
//!
//! Endpoints, the supervisor, the event bus and the wiring between services.
//!
//! # Boundaries
//!
//! Thin: logic lives in the library crates. The supervisor is the only process that starts agent commands, always
//! through `knsh-exec`.
//!
//! # Specification
//!
//! - `specs/02-architecture/process-model.md`
//! - `specs/02-architecture/endpoints.md`
//! - `specs/02-architecture/system-overview.md`
//!
//! Skeleton created by KNSH-001; functionality arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

/// Entry point. Does nothing until the binary is implemented.
fn main() {}
