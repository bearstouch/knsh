//! Checkpoints and best-effort undo.
//!
//! Shadows, capture, post-image identity, the history tree and restore rules.
//!
//! # Boundaries
//!
//! Checkpoints live on the same APFS volume as the files they protect. Depends on `knsh-core` and `knsh-platform`.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/checkpoints.md`
//! - `specs/05-models/checkpoint.md`
//!
//! Skeleton created by KNSH-001; functionality arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]
