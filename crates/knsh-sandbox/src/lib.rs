//! Seatbelt profile compiler.
//!
//! Compiles policy into Seatbelt profile text as a pure function: the same input always gives the same bytes.
//!
//! # Boundaries
//!
//! No I/O. Depends only on `knsh-core`.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/sandbox-profiles.md`
//! - `specs/02-architecture/enforcement-model.md`
//!
//! Skeleton created by KNSH-001; functionality arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]
