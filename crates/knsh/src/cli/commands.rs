//! The declaration of every `knsh` command, from `specs/06-api/cli.md`.
//!
//! This table is the single source for both parsing and help ([`crate::cli::args`]). Only the syntax lives here;
//! what each command does arrives with its own story. Options a spec page marks as "to be specified" are left out
//! until the page specifies them, so they are rejected rather than accepted and ignored.

use crate::cli::args::{Command, OptionSpec, Positional, Trailing};

/// The root of the `knsh` command tree.
pub static KNSH: Command = group(
    "knsh",
    "Kinetic Shell: a bash/zsh-compatible shell that records, enforces and reports what agents run",
    &[
        Command {
            options: &[
                OptionSpec {
                    long: "profile",
                    value: Some("p"),
                    required: false,
                    help: "Envelope profile to use",
                },
                OptionSpec {
                    long: "agent",
                    value: Some("name"),
                    required: false,
                    help: "Agent name recorded as the actor (default: derived from the command)",
                },
            ],
            // The agent's own argv follows `--`, so none of its flags can be mistaken for ours.
            trailing: Trailing::Required("command"),
            ..leaf("agent", "Start an agent CLI inside an envelope")
        },
        leaf("run", "Run a line through the engine"),
        Command {
            options: &[
                OptionSpec {
                    long: "session",
                    value: Some("id"),
                    required: false,
                    help: "Only this session's records",
                },
                OptionSpec {
                    long: "since",
                    value: Some("date"),
                    required: false,
                    help: "Only records started at or after this UTC date or timestamp",
                },
                OptionSpec {
                    long: "until",
                    value: Some("date"),
                    required: false,
                    help: "Only records started before this UTC date or timestamp",
                },
                OptionSpec {
                    long: "text",
                    value: Some("text"),
                    required: false,
                    help: "Only commands containing this text (case-sensitive)",
                },
                OptionSpec {
                    long: "limit",
                    value: Some("n"),
                    required: false,
                    help: "Show the newest n matching records (default 100)",
                },
            ],
            ..leaf("history", "Query records, newest first")
        },
        leaf("undo", "Undo a change"),
        leaf("redo", "Redo a change"),
        leaf("checkpoints", "List checkpoints and states"),
        Command {
            options: &[
                OptionSpec {
                    long: "session",
                    value: Some("id"),
                    required: false,
                    help: "Only this session's events",
                },
                OptionSpec {
                    long: "since",
                    value: Some("seq"),
                    required: false,
                    help: "First replay the session's buffered events after this seq (needs --session)",
                },
            ],
            ..leaf("events", "Stream events until interrupted")
        },
        leaf("approvals", "List pending asks"),
        Command {
            positionals: &[Positional {
                name: "request_id",
                help: "The ask to approve (from 'knsh approvals')",
            }],
            ..leaf("approve", "Approve an ask; knshd shows a Touch ID or password prompt")
        },
        Command {
            positionals: &[Positional {
                name: "request_id",
                help: "The ask to deny (from 'knsh approvals')",
            }],
            ..leaf("deny", "Deny an ask")
        },
        group(
            "policy",
            "Check or edit policy",
            &[
                leaf("check", "Dry-run a line against policy"),
                Command {
                    positionals: &[Positional {
                        name: "profile",
                        help: "The profile to edit (its file in the policies directory); created if new",
                    }],
                    ..leaf("edit", "Edit a policy file; saving needs Touch ID or password")
                },
            ],
        ),
        group(
            "profile",
            "Manage local profiles",
            &[Command {
                positionals: &[Positional {
                    name: "profile",
                    help: "The local profile to select",
                }],
                ..leaf("use", "Select a local profile; needs Touch ID")
            }],
        ),
        group(
            "authority",
            "Manage the trusted authority",
            &[Command {
                options: &[
                    OptionSpec {
                        long: "team-id",
                        value: Some("id"),
                        required: true,
                        help: "Code-signing team identifier",
                    },
                    OptionSpec {
                        long: "identifier",
                        value: Some("bundle-id"),
                        required: true,
                        help: "Bundle identifier",
                    },
                    OptionSpec {
                        long: "min-version",
                        value: Some("v"),
                        required: true,
                        help: "Lowest accepted version",
                    },
                ],
                ..leaf("trust", "Trust an authority; needs Touch ID or password")
            }],
        ),
        Command {
            options: &[
                OptionSpec {
                    long: "session",
                    value: Some("id"),
                    required: false,
                    help: "Only this session's records",
                },
                OptionSpec {
                    long: "since",
                    value: Some("date"),
                    required: false,
                    help: "Only records since this date",
                },
                OptionSpec {
                    long: "with-checkpoints",
                    value: None,
                    required: false,
                    help: "Delete the matching checkpoints too",
                },
            ],
            ..leaf("forget", "Delete records and optionally checkpoints")
        },
        group(
            "shell",
            "Set knsh up as a login shell",
            &[leaf(
                "install",
                "Add knsh to /etc/shells after asking, so that chsh accepts it",
            )],
        ),
        group(
            "daemon",
            "Install or remove the knshd launch agent",
            &[
                leaf("install", "Install and load the knshd launch agent"),
                leaf(
                    "uninstall",
                    "Unload the knshd launch agent and remove it; engine data is kept",
                ),
            ],
        ),
    ],
);

/// A leaf command with no options or arguments besides the global ones. Commands that take some override the
/// relevant fields with struct-update syntax (`Command { options: …, ..leaf(name, about) }`).
const fn leaf(name: &'static str, about: &'static str) -> Command {
    Command {
        name,
        about,
        options: &[],
        positionals: &[],
        trailing: Trailing::None,
        subcommands: &[],
    }
}

/// A command group that only selects one of `subcommands`.
const fn group(name: &'static str, about: &'static str, subcommands: &'static [Command]) -> Command {
    Command {
        subcommands,
        ..leaf(name, about)
    }
}
