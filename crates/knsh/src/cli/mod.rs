//! The `knsh` command-line interface (`specs/06-api/cli.md`).
//!
//! [`args`] is the in-house argument parser and help generator (KNSH-009); [`commands`] declares every command it
//! parses. The commands' behaviour arrives in later stories.

pub mod args;
pub mod commands;
