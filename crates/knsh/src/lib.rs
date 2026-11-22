//! Shell front end, agent client, shims and CLI.
//!
//! Integration mode for human shells, the in-envelope agent client, the shims and the `knsh` command-line interface.
//! The binary (`src/main.rs`) is a thin wrapper; the logic lives here so it can be tested as pure functions.
//!
//! # Boundaries
//!
//! Talks to `knshd` only through the protocol. Depends on `knsh-proto` and `knsh-json`, on `knsh-core` for the ID and
//! timestamp types it validates before sending, on `knsh-platform` for engine paths and the launchd agent that
//! `knsh daemon` installs (KNSH-012), on `knsh-toml` for the user settings file (KNSH-021), and on `knsh-interp` for
//! native mode (KNSH-107). Command-line parsing is
//! written in-house ([`cli::args`]): the dependency policy allows no CLI-parsing crate.
//!
//! # Specification
//!
//! - `specs/06-api/cli.md` (commands, `--json`, shell invocation) — [`cli`], KNSH-009
//! - `specs/06-api/cli.md` "Daemon installation", `specs/02-architecture/process-model.md` — `cli::daemon`, KNSH-012
//! - `specs/06-api/cli.md` (`knsh forget`), `specs/06-api/user-socket.md#recordsforget`, FR-REC-10, NFR-PRIV-03 —
//!   [`cli::forget`] over [`cli::client`], KNSH-017
//! - `specs/04-non-functional-requirements/supply-chain.md` (no third-party CLI crate)
//! - `specs/03-functional-requirements/agent-integration.md`
//! - `specs/08-integrations/terminals-and-shells.md` (login shell; integration mode) — [`integration`], KNSH-019:
//!   hosting stock zsh with its startup files unchanged, FR-SES-20, FR-SES-22, NFR-COMPAT-01, NFR-COMPAT-03,
//!   NFR-COMPAT-06; KNSH-020: hosting stock bash (3.2 and 5) the same way, NFR-COMPAT-04
//! - `specs/08-integrations/terminals-and-shells.md#recording-a-human-session`,
//!   `specs/06-api/user-socket.md#human-sessions` — `integration::config` and `integration::recorder`, KNSH-021:
//!   the recording switch, human telemetry to `knshd`, the idle prompt and `KNSH_RECORDING`, FR-SES-21, FR-SES-23, FR-SES-24, FR-SES-25, FR-REC-09, NFR-REL-02,
//!   NFR-PRIV-05
//! - `specs/03-functional-requirements/agent-integration.md`, `specs/06-api/agent-socket.md#execrun` — [`agent`],
//!   KNSH-049: `knsh -c` forwarding to the supervisor with stdio passed as descriptors, and the `sh`/`bash`/`zsh`
//!   shims, FR-AGT-10, FR-LC-14, FR-LC-31, FR-OUT-04, FR-AGT-31, NFR-COMPAT-09, NFR-REL-01
//! - `specs/06-api/cli.md` "Version and the advisory label", `specs/01-overview/roadmap.md` — [`cli::version`],
//!   KNSH-024: `knsh --version` labels phase 1 builds advisory
//! - `specs/08-integrations/terminals-and-shells.md#native-mode-knsh-107` — `native`, KNSH-107: the native interpreter
//!   (`knsh-interp`) as a human's interactive shell with its line editor, opt-in with `[shell] hosted = "native"`,
//!   NFR-COMPAT-06, NFR-COMPAT-10, NFR-PERF-04, FR-SES-22
//! - `specs/03-functional-requirements/command-lifecycle.md#native-mode-knsh-108` — [`native_line`], KNSH-108: the
//!   sandboxed interpreter of a native-mode agent line, every command of which the supervisor decides and starts,
//!   FR-LC-52 to FR-LC-57, NFR-SEC-02, NFR-REL-01

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

#[cfg(unix)]
pub mod agent;
pub mod cli;
pub mod integration;
#[cfg(target_os = "macos")]
pub mod native;
pub mod native_line;
