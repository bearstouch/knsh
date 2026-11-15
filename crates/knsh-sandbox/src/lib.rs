//! Seatbelt profile compiler.
//!
//! Compiles policy into Seatbelt profile text as a pure function: the same input always gives the same bytes.
//!
//! # Boundaries
//!
//! No I/O. Depends only on `knsh-core`. Writing the profile to its private file (FR-SBX-07) and applying it through
//! `knsh-exec` are the supervisor's.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/sandbox-profiles.md`
//! - `specs/02-architecture/enforcement-model.md`
//! - `specs/07-testing/verification-claims.md#seatbelt-results-knsh-025-c1-c2-c8` (observed Seatbelt behaviour)
//!
//! # File rules (KNSH-044)
//!
//! [`compile`] turns a [`ProfileInput`] (a resolved profile, the session and command it confines, and the home
//! directory) into [`SbplText`]: deny by default (FR-SBX-01); reads of everything, or of the listed paths, except
//! `fs.deny`; writes to the write roots; then the fixed write denies (`.git` entries, hooks and config, shell startup
//! files, `~/Library/LaunchAgents`, `~/.ssh`, the entries of their ancestors) and the engine paths (FR-SBX-10), after every allow so they always win
//! (FR-SBX-02). Every deny is tagged `knsh:<session>:<command>:<rule>` (FR-SBX-06). Paths are written as escaped
//! string literals (the `sbpl` module), the only place input enters the text (NFR-SEC-03).
//!
//! Executables, system services, Unix sockets, network, process information and profile files arrive with KNSH-045.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod compile;
mod sbpl;

#[cfg(test)]
mod tests;

pub use compile::{CommandTag, ProfileInput, compile};
pub use sbpl::SbplText;
