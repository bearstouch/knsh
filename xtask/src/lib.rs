//! Dev-only workspace checks for Kinetic Shell. Never shipped.
//!
//! The checks live in `tests/` so they run with `cargo test --workspace --offline` and fail the build like any other
//! test. They parse `Cargo.lock` and `Cargo.toml` files by hand instead of calling `cargo metadata`, which keeps this
//! crate free of third-party dependencies.
//!
//! # Boundaries
//!
//! No runtime code and no dependencies. Nothing here may be depended on by a shipped crate.
//!
//! # Specification
//!
//! - `specs/04-non-functional-requirements/supply-chain.md` (NFR-SUP-01, NFR-SUP-02)
//! - `specs/00-stories/KNSH-001-workspace-toolchain-lint-baseline-and-ci.md`

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]
