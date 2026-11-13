//! The `knsh` command-line interface (`specs/06-api/cli.md`).
//!
//! [`args`] is the in-house argument parser and help generator (KNSH-009); [`commands`] declares every command it
//! parses. [`daemon`] implements `knsh daemon install` and `uninstall` (KNSH-012, macOS only). [`client`] is the
//! JSON-RPC client the API commands use, and [`forget`] implements `knsh forget` (KNSH-017); the other commands'
//! behaviour arrives in later stories.

pub mod args;
pub mod client;
pub mod commands;
#[cfg(target_os = "macos")]
pub mod daemon;
pub mod forget;
