//! The `knsh` binary: parses its argv and dispatches. Logic lives in the `knsh` library crate.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use knsh::cli::args::{self, ArgsError, Invocation};
use knsh::cli::commands::KNSH;

/// Exit status while a parsed invocation has no behaviour yet (the subcommands arrive in later stories).
const NOT_IMPLEMENTED_STATUS: u8 = 1;

/// Entry point: parse argv, then print help, report a usage error, or dispatch.
fn main() -> ExitCode {
    match args::parse(&KNSH, std::env::args_os()) {
        Ok(Invocation::Help(text)) => {
            // A closed stdout (`knsh --help | head -1`) is not an error worth reporting.
            let _ = std::io::stdout().write_all(text.as_bytes());
            ExitCode::SUCCESS
        }
        Ok(Invocation::Shell(_)) => not_implemented("shell mode"),
        Ok(Invocation::Command(parsed)) => not_implemented(&format!("'knsh {}'", parsed.path.join(" "))),
        // Usage errors run nothing and exit with 2, like bash (KNSH-009).
        Err(error) => {
            report(&format!("knsh: {error}\nTry 'knsh --help' for more information.\n"));
            ExitCode::from(ArgsError::EXIT_STATUS)
        }
    }
}

/// Reports that a correctly parsed invocation has no behaviour yet.
fn not_implemented(what: &str) -> ExitCode {
    report(&format!("knsh: {what} is not implemented yet\n"));
    ExitCode::from(NOT_IMPLEMENTED_STATUS)
}

/// Writes `message` to stderr, ignoring failure: there is nowhere left to report it.
fn report(message: &str) {
    let _ = std::io::stderr().write_all(message.as_bytes());
}
