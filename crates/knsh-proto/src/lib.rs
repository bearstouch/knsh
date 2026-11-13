//! JSON-RPC protocol types for the engine endpoints.
//!
//! Method parameters and results, the API error codes and the capability model.
//!
//! # Boundaries
//!
//! API error codes (`-32001`...) live only in this crate. Depends on `knsh-json` and `knsh-core`.
//!
//! # Specification
//!
//! - `specs/06-api/README.md`
//! - `specs/06-api/errors.md`
//! - `specs/06-api/handshake.md`
//! - `specs/05-models/capabilities.md`
//!
//! Skeleton created by KNSH-001; functionality arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]
