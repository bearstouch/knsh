//! The `knsh` command-line interface (`specs/06-api/cli.md`).
//!
//! [`agent`] implements `knsh agent` (KNSH-056): it starts an agent CLI through `session.start_agent`, after
//! [`agent_sandbox`] checked that the CLI's own sandbox is off (KNSH-058).
//! [`args`] is the in-house argument parser and help generator (KNSH-009); [`commands`] declares every command it
//! parses. [`daemon`] implements `knsh daemon install` and `uninstall` (KNSH-012, macOS only). [`client`] is the
//! JSON-RPC client the API commands use, and [`forget`] implements `knsh forget` (KNSH-017). [`history`] and
//! [`events`] implement `knsh history` and `knsh events` (KNSH-023), printing engine text through [`terminal`] so it
//! is always terminal-safe. [`shell`] implements `knsh shell install` (KNSH-022, Unix only); the other commands'
//! behaviour arrives in later stories. [`version`] is the text of `knsh --version`, with the phase 1 advisory label
//! (KNSH-024). [`policy`] implements `knsh policy edit` (KNSH-065): `knshd` signs the edited file after Touch ID or
//! the password. [`approvals`] implements `knsh approvals`, `knsh approve` and `knsh deny` (KNSH-066), and
//! [`authority`] implements `knsh authority trust` (KNSH-068): `knshd` stores the trust record after Touch ID or the
//! password. [`profile`] implements `knsh profile use` (KNSH-072): `knshd` moves the sessions paused by expired pushed
//! policy to a signed local profile after Touch ID or the password. [`grants`] implements `knsh policy grant`,
//! `knsh policy grants` and `knsh policy revoke` (KNSH-073): `knshd` makes a grant after Touch ID or the password.

#[cfg(unix)]
pub mod agent;
pub mod agent_sandbox;
pub mod approvals;
pub mod args;
pub mod authority;
pub mod client;
pub mod commands;
#[cfg(target_os = "macos")]
pub mod daemon;
pub mod events;
pub mod forget;
pub mod grants;
pub mod history;
pub mod policy;
pub mod profile;
#[cfg(unix)]
pub mod shell;
pub mod terminal;
pub mod version;
