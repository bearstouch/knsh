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

/// Exit status when the hosted shell cannot be started, as a shell reports a command it cannot run.
#[cfg(target_os = "macos")]
const EXEC_FAILED_STATUS: u8 = 127;

/// Entry point: parse argv, then print help, report a usage error, or dispatch.
fn main() -> ExitCode {
    match args::parse(&KNSH, std::env::args_os()) {
        Ok(Invocation::Help(text)) => {
            // A closed stdout (`knsh --help | head -1`) is not an error worth reporting.
            let _ = std::io::stdout().write_all(text.as_bytes());
            ExitCode::SUCCESS
        }
        Ok(Invocation::Shell(shell)) => shell_mode(&shell),
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

/// Runs a shell-mode invocation. A human interactive shell is hosted in integration mode (KNSH-019); `-c` lines and
/// scripts (the agent and unattended paths) arrive in later stories.
fn shell_mode(shell: &knsh::cli::args::ShellInvocation) -> ExitCode {
    use std::io::IsTerminal;

    use knsh::integration::zsh;

    let on_terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    if zsh::is_human_interactive(
        shell.command.as_deref(),
        &shell.operands,
        shell.interactive,
        on_terminal,
    ) {
        human_shell(shell)
    } else {
        not_implemented("shell mode")
    }
}

/// Hosts the user's stock shell for a human: their bash when `$SHELL` is one (KNSH-020), zsh otherwise (KNSH-019).
#[cfg(target_os = "macos")]
fn human_shell(shell: &knsh::cli::args::ShellInvocation) -> ExitCode {
    use knsh::integration::bash;

    let login_shell = std::env::var_os(bash::SHELL_VAR);
    match bash::user_bash(login_shell.as_deref()) {
        // A "bash" that is knsh itself would exec knsh again, forever.
        Some(bash) if !is_this_program(bash) => human_bash(shell, bash),
        _ => human_zsh(shell),
    }
}

/// Whether `path` resolves to the running `knsh` binary. Unknown counts as no.
#[cfg(target_os = "macos")]
fn is_this_program(path: &std::path::Path) -> bool {
    let this = std::env::current_exe().and_then(std::fs::canonicalize);
    matches!((this, std::fs::canonicalize(path)), (Ok(this), Ok(path)) if this == path)
}

/// Hosts the user's bash (KNSH-020). Recording is off until KNSH-021 adds the switch, so `knsh` replaces itself with
/// plain bash: no file or variable of `knsh`'s, so every startup file runs exactly as under plain bash, and bash's
/// own exit status, signals and terminal handling.
///
/// If that bash cannot be started (for example `$SHELL` names a bash since uninstalled), zsh starts instead after a
/// one-line warning: a human shell is never refused (FR-SES-22).
#[cfg(target_os = "macos")]
fn human_bash(shell: &knsh::cli::args::ShellInvocation, bash: &std::path::Path) -> ExitCode {
    use knsh::integration::bash::BashLaunch;
    use knsh::integration::host;

    let plan = BashLaunch {
        bash,
        startup_dir: None,
        login: shell.login,
        force_interactive: shell.interactive,
        telemetry: None,
        user_prompt_command: None,
    }
    .plan();
    let error = host::exec(&plan);
    report(&format!(
        "knsh: cannot start {}: {error}; starting zsh\n",
        bash.display()
    ));
    human_zsh(shell)
}

/// Hosts stock zsh (KNSH-019). Recording is off until KNSH-021 adds the switch, so `knsh` replaces itself with zsh:
/// no telemetry, no `knshd`, and zsh's own exit status, signals and terminal handling.
///
/// If the startup directory cannot be installed, plain zsh starts without it after a one-line warning: a human
/// shell is never refused (FR-SES-22).
#[cfg(target_os = "macos")]
fn human_zsh(shell: &knsh::cli::args::ShellInvocation) -> ExitCode {
    use std::path::Path;

    use knsh::integration::{host, zsh};
    use knsh_platform::EnginePaths;
    use knsh_platform::macos::{RealFs, effective_uid};

    let installed = std::env::var_os("HOME")
        .ok_or_else(|| "HOME is not set".to_owned())
        .and_then(|home| EnginePaths::for_home(Path::new(&home)).map_err(|error| error.to_string()))
        .and_then(|paths| {
            host::install_zsh_startup_dir(&RealFs::new(), &paths, effective_uid()).map_err(|error| error.to_string())
        });
    let startup_dir = match installed {
        Ok(dir) => Some(dir),
        Err(reason) => {
            report(&format!(
                "knsh: integration unavailable ({reason}); starting plain zsh\n"
            ));
            None
        }
    };
    let user_zdotdir = std::env::var_os(zsh::ZDOTDIR_VAR);
    let plan = zsh::ZshLaunch {
        zsh: Path::new(zsh::SYSTEM_ZSH),
        startup_dir: startup_dir.as_deref(),
        user_zdotdir: user_zdotdir.as_deref(),
        login: shell.login,
        force_interactive: shell.interactive,
        telemetry_fd: None,
    }
    .plan();
    exec_shell(&plan, Path::new(zsh::SYSTEM_ZSH))
}

/// Replaces this process with the shell `plan` starts. Returns only on failure, like a shell that cannot find a
/// command: 127 with the reason on stderr.
#[cfg(target_os = "macos")]
fn exec_shell(plan: &knsh::integration::zsh::LaunchPlan, program: &std::path::Path) -> ExitCode {
    let error = knsh::integration::host::exec(plan);
    report(&format!("knsh: cannot start {}: {error}\n", program.display()));
    ExitCode::from(EXEC_FAILED_STATUS)
}

/// Integration mode is built for macOS first; other platforms arrive with the Linux stories.
#[cfg(not(target_os = "macos"))]
fn human_shell(_shell: &knsh::cli::args::ShellInvocation) -> ExitCode {
    not_implemented("integration mode on this platform")
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
