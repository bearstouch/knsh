//! Shell front end, agent client, shims and CLI.
//!
//! Integration mode for human shells, the in-envelope agent client, the shims and the `knsh` command-line interface.
//! The binary (`src/main.rs`) is a thin wrapper; the logic lives here so it can be tested as pure functions.
//!
//! # Boundaries
//!
//! Talks to `knshd` only through the protocol. Depends on `knsh-proto` and `knsh-json`. Command-line parsing is
//! written in-house ([`cli::args`]): the dependency policy allows no CLI-parsing crate.
//!
//! # Specification
//!
//! - `specs/06-api/cli.md` (commands, `--json`, shell invocation) — [`cli`], KNSH-009
//! - `specs/04-non-functional-requirements/supply-chain.md` (no third-party CLI crate)
//! - `specs/03-functional-requirements/agent-integration.md`
//! - `specs/08-integrations/terminals-and-shells.md` (login shell)

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

pub mod cli;
