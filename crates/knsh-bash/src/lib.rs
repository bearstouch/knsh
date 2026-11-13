//! In-house bash parser and classifier.
//!
//! Parses bash command lines and classifies wrappers, dynamic code and irreversible actions. Anything it cannot read
//! with confidence is classified as dynamic code, so parser gaps fail closed.
//!
//! # Boundaries
//!
//! No workspace or third-party dependencies. A parser result is an intent filter, never a security boundary.
//!
//! # Specification
//!
//! - `specs/02-architecture/implementation.md`
//! - `specs/07-testing/conformance.md`
//! - `specs/09-reference/decisions.md`
//!
//! Skeleton created by KNSH-001; functionality arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]
