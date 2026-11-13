//! Shell front end, agent client, shims and CLI.
//!
//! Integration mode for human shells, the in-envelope agent client, the shims and the `knsh` command-line interface.
//!
//! # Boundaries
//!
//! Talks to `knshd` only through the protocol. Depends on `knsh-proto` and `knsh-json`.
//!
//! # Specification
//!
//! - `specs/06-api/cli.md`
//! - `specs/03-functional-requirements/agent-integration.md`
//! - `specs/08-integrations/terminals-and-shells.md`
//!
//! Skeleton created by KNSH-001; functionality arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

/// Entry point. Does nothing until the binary is implemented.
fn main() {}
