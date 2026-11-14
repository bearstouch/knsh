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

pub mod bash;
#[cfg(unix)]
pub mod host;
pub mod telemetry;
pub mod zsh;
