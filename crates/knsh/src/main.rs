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
        Ok(Invocation::Command(parsed)) => match parsed.path.as_slice() {
            ["daemon", action @ ("install" | "uninstall")] => daemon(action, parsed.json()),
            ["forget"] => forget(&parsed),
            _ => not_implemented(&format!("'knsh {}'", parsed.path.join(" "))),
        },
        // Usage errors run nothing and exit with 2, like bash (KNSH-009).
        Err(error) => {
            report(&format!("knsh: {error}\nTry 'knsh --help' for more information.\n"));
            ExitCode::from(ArgsError::EXIT_STATUS)
        }
    }
}

/// Runs `knsh daemon install` or `uninstall` against the real filesystem and launchd (KNSH-012). Exits with 1 and
/// the reason on stderr on failure.
#[cfg(target_os = "macos")]
fn daemon(action: &str, json: bool) -> ExitCode {
    use knsh::cli::daemon::{self, Environment};
    use knsh_platform::macos::{Launchctl, RealFs, effective_uid};

    let home = std::env::var_os("HOME");
    let Ok(knsh_exe) = std::env::current_exe() else {
        report("knsh: cannot locate the running knsh binary\n");
        return ExitCode::FAILURE;
    };
    let env = Environment {
        home: home.as_deref(),
        knsh_exe: &knsh_exe,
        uid: effective_uid(),
    };
    let (fs, launchctl) = (RealFs::new(), Launchctl::new());
    let outcome = if action == "install" {
        daemon::install(&fs, &launchctl, env).map(|agent| daemon::installed_report(&agent, json))
    } else {
        daemon::uninstall(&fs, &launchctl, env).map(|removed| daemon::uninstalled_report(removed, json))
    };
    match outcome {
        Ok(text) => {
            let _ = std::io::stdout().write_all(text.as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&format!("knsh: daemon {action} failed: {error}\n"));
            ExitCode::FAILURE
        }
    }
}

/// The launchd agent exists only on macOS so far (a systemd unit on Linux, KNSH-112).
#[cfg(not(target_os = "macos"))]
fn daemon(action: &str, _json: bool) -> ExitCode {
    not_implemented(&format!("'knsh daemon {action}' on this platform"))
}

/// Runs `knsh forget` (KNSH-017): validates the selectors, calls `records.forget` on `user.sock` and reports the
/// count. A command line without a selector, or with a malformed one, is a usage error (exit 2) and sends nothing;
/// a failed call exits with 1 and the reason on stderr.
#[cfg(unix)]
fn forget(parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    use knsh::cli::{client, forget};
    use knsh_platform::EnginePaths;

    let params = match forget::params(parsed) {
        Ok(params) => params,
        Err(error) => {
            report(&format!(
                "knsh: {error}\nTry 'knsh forget --help' for more information.\n"
            ));
            return ExitCode::from(ArgsError::EXIT_STATUS);
        }
    };
    let Some(home) = std::env::var_os("HOME") else {
        report("knsh: HOME is not set\n");
        return ExitCode::FAILURE;
    };
    let paths = match EnginePaths::for_home(std::path::Path::new(&home)) {
        Ok(paths) => paths,
        Err(error) => {
            report(&format!("knsh: unusable HOME: {error}\n"));
            return ExitCode::FAILURE;
        }
    };
    let outcome = client::connect_user(&paths.user_socket()).and_then(|mut client| forget::run(&mut client, &params));
    match outcome {
        Ok(deleted) => {
            let _ = std::io::stdout().write_all(forget::report(deleted, parsed.json()).as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&forget::failure_message(&error));
            ExitCode::FAILURE
        }
    }
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn forget(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh forget' on this platform")
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
