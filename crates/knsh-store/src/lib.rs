//! Execution record store.
//!
//! Record store on the system SQLite library, retention, and redaction at write time.
//!
//! # Boundaries
//!
//! Redacts before anything is stored. Depends on `knsh-core` and `knsh-platform`.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/execution-records.md`
//! - `specs/05-models/execution-record.md`
//! - `specs/04-non-functional-requirements/privacy.md`
//!
//! Skeleton created by KNSH-001; functionality arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]
