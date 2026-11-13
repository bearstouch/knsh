//! Parser for the TOML subset used by policy and configuration files.
//!
//! Reads the TOML subset the specification uses; anything outside the subset is rejected.
//!
//! # Boundaries
//!
//! No workspace or third-party dependencies. Input is untrusted and the parser is fuzzed.
//!
//! # Specification
//!
//! - `specs/05-models/policy-profile.md`
//! - `specs/02-architecture/implementation.md`
//! - `specs/07-testing/fuzzing.md`
//!
//! Skeleton created by KNSH-001; functionality arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]
