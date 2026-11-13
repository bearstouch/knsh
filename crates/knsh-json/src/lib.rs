//! Strict JSON (I-JSON profile) reader and writer and the length-prefixed frame codec.
//!
//! Reads and writes the strict JSON profile used on every engine socket, and encodes and decodes frames.
//!
//! # Boundaries
//!
//! No workspace or third-party dependencies. Input is untrusted: size limits are checked before allocating and
//! malformed input is rejected, never repaired.
//!
//! # Specification
//!
//! - `specs/06-api/wire-format.md`
//! - `specs/02-architecture/implementation.md`
//! - `specs/07-testing/fuzzing.md`
//!
//! Skeleton created by KNSH-001; functionality arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]
