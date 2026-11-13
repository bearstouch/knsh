//! Integration mode: hosting the user's stock shell for human sessions (`specs/08-integrations/terminals-and-shells.md`,
//! FR-SES-20, FR-SES-22, NFR-COMPAT-01, NFR-COMPAT-03, NFR-COMPAT-06).
//!
//! `knsh` started interactively on a terminal runs the user's own zsh, with all their startup files unchanged. When
//! recording is on, `preexec`/`precmd` hooks report each command line as telemetry. Nothing is decided, rewritten
//! or blocked, and the hooks are never relied on for security (FR-SES-22).
//!
//! - [`zsh`]: the startup wrapper and the pure launch plan (KNSH-019).
//! - [`telemetry`]: the line format between the hooks and `knsh`.
//! - [`host`]: installing the wrapper and starting zsh, by `exec` (recording off) or as a child with a forwarder
//!   (recording on).

#[cfg(unix)]
pub mod host;
pub mod telemetry;
pub mod zsh;
