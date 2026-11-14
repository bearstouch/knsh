//! The `knsh` command-line interface (`specs/06-api/cli.md`).
//!
//! [`args`] is the in-house argument parser and help generator (KNSH-009); [`commands`] declares every command it
//! parses. [`daemon`] implements `knsh daemon install` and `uninstall` (KNSH-012, macOS only). [`client`] is the
//! JSON-RPC client the API commands use, and [`forget`] implements `knsh forget` (KNSH-017). [`history`] and
//! [`events`] implement `knsh history` and `knsh events` (KNSH-023), printing engine text through [`terminal`] so it
//! is always terminal-safe. [`shell`] implements `knsh shell install` (KNSH-022, Unix only); the other commands'
//! behaviour arrives in later stories. [`version`] is the text of `knsh --version`, with the phase 1 advisory label
//! (KNSH-024).

pub mod args;
pub mod client;
pub mod commands;
#[cfg(target_os = "macos")]
pub mod daemon;
pub mod events;
pub mod forget;
pub mod history;
#[cfg(unix)]
pub mod shell;
pub mod terminal;
pub mod version;
