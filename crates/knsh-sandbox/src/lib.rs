//! Seatbelt profile compiler.
//!
//! Compiles policy into Seatbelt profile text as a pure function: the same input always gives the same bytes.
//!
//! # Boundaries
//!
//! No I/O. Depends only on `knsh-core`. Writing the profile to its private file (FR-SBX-07) and applying it through
//! `knsh-exec` are the supervisor's. The input names everything that is not in the profile: the session and command
//! (tags), the home directory (fixed denies, sockets), the binaries the supervisor resolved and the proxy's port.
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
//! # Executables, services, sockets, network, processes (KNSH-045)
//!
//! The same [`compile`] adds the rest of the profile table: `exec` only of trusted folders, the system tool folders
//! ([`SYSTEM_TOOL_FOLDERS`]), `exec.bash`, the binaries the supervisor names and, if allowed, project executables
//! (FR-SBX-04, FR-LC-15); `LaunchServices`, Apple Events, launchd jobs, the DNS resolver and the control service
//! denied (FR-NET-08); `agent.sock` for envelopes only, no Unix socket for commands, `user.sock` always denied
//! (FR-SBX-05); outbound network only to the proxy port and `network.loopback` ports; signals and process
//! information within the sandbox (decision 8, FR-SEC-05); system settings read-only. What Seatbelt cannot enforce
//! is listed in every profile's header comment ([`GAPS`]). The rule forms are KNSH-025's measured ones.
//!
//! Writing each profile to its private file, named by its hash (FR-SBX-07), is `knshd`'s (`profiles` module).

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod compile;
mod sbpl;

#[cfg(test)]
mod tests;

pub use compile::{CommandTag, GAPS, ProfileInput, SYSTEM_TOOL_FOLDERS, compile};
pub use sbpl::SbplText;
