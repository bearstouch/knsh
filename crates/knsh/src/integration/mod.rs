//! Integration mode: hosting the user's stock shell for human sessions (`specs/08-integrations/terminals-and-shells.md`,
//! FR-SES-20, FR-SES-22, NFR-COMPAT-01, NFR-COMPAT-03, NFR-COMPAT-06).
//!
//! `knsh` started interactively on a terminal runs the user's own zsh or bash, with all their startup files
//! unchanged. When recording is on, hooks report each command line as telemetry (zsh's `preexec`/`precmd`; for bash
//! a `DEBUG` trap and `PROMPT_COMMAND`). Nothing is decided, rewritten or blocked, and the hooks are never relied on
//! for security (FR-SES-22).
//!
//! - [`zsh`]: the zsh startup wrapper and the pure launch plan (KNSH-019).
//! - [`bash`]: the bash wrapper, its hooks and the pure launch plan (KNSH-020).
//! - [`telemetry`]: the line format between the hooks and `knsh`.
//! - [`host`]: installing the wrappers and starting the shell, by `exec` (recording off) or as a child with a
//!   forwarder (recording on).
//! - [`config`]: the recording switch, `[recording] human` in the user's `config.toml` (KNSH-021).
//! - [`recorder`]: forwarding the telemetry of a recorded session to `knshd`, with the idle prompt event (KNSH-021).
//!
//! A recorded shell gets [`RECORDING_VAR`] set to `1` so that prompts can show it (FR-SES-25); an unrecorded one never
//! has it, even when `knsh` inherited it.

/// Set to `1` in a recorded shell's environment (FR-SES-25, NFR-PRIV-05), and removed otherwise.
pub const RECORDING_VAR: &str = "KNSH_RECORDING";

pub mod bash;
pub mod config;
#[cfg(unix)]
pub mod host;
pub mod marks;
#[cfg(unix)]
pub mod recorder;
#[cfg(unix)]
pub mod shells;
pub mod telemetry;
pub mod zsh;
