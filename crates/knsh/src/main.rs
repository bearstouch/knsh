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
/// Recorded when `[recording] human = true` is set (KNSH-021); otherwise `knsh` never contacts `knshd` (FR-SES-23).
#[cfg(target_os = "macos")]
fn human_shell(shell: &knsh::cli::args::ShellInvocation) -> ExitCode {
    use knsh::integration::bash;

    let host = Host::new();
    let login_shell = std::env::var_os(bash::SHELL_VAR);
    match bash::user_bash(login_shell.as_deref()) {
        // A "bash" that is knsh itself would exec knsh again, forever.
        Some(bash) if !is_this_program(bash) => human_bash(&host, shell, bash),
        _ => human_zsh(&host, shell),
    }
}

/// What every way of hosting the shell needs: the engine paths and whether this session is recorded.
#[cfg(target_os = "macos")]
struct Host {
    /// The reason when `HOME` is unset or unusable: then no startup wrapper and no configuration, so no recording.
    paths: Result<knsh_platform::EnginePaths, String>,
    /// `[recording] human` (KNSH-021). Off unless the configuration says `true`.
    recording: bool,
}

#[cfg(target_os = "macos")]
impl Host {
    /// Resolves the engine paths from `HOME` and reads the recording switch.
    fn new() -> Self {
        use std::path::Path;

        use knsh::integration::config;
        use knsh_platform::EnginePaths;
        use knsh_platform::macos::RealFs;

        let paths = std::env::var_os("HOME")
            .ok_or_else(|| "HOME is not set".to_owned())
            .and_then(|home| EnginePaths::for_home(Path::new(&home)).map_err(|error| error.to_string()));
        let recording = match &paths {
            Ok(paths) => {
                let file = paths.config_file();
                config::human_recording(&RealFs::new(), &file).unwrap_or_else(|error| {
                    // Unclear means off (privacy first), and is said once; the shell still starts.
                    report(&format!("knsh: {}: {error}; recording is off\n", file.display()));
                    false
                })
            }
            // No configuration to read: recording keeps its default, off (FR-SES-04).
            Err(_) => false,
        };
        Self { paths, recording }
    }

    /// Starts recording, when it is on (KNSH-021): the worker that forwards telemetry to `knshd` over `user.sock`.
    /// Nothing connects until the shell has started.
    fn start_recording(&self) -> Option<knsh::integration::recorder::RecordingHandle> {
        use std::os::unix::ffi::OsStringExt;
        use std::sync::Arc;

        use knsh::integration::recorder::{UserSocketConnector, start_recording};
        use knsh_platform::macos::SystemClock;

        let paths = self.paths.as_ref().ok()?;
        // The shell starts in knsh's own directory, as `$PWD` names it when that is still accurate.
        let cwd = std::env::var_os("PWD")
            .or_else(|| std::env::current_dir().ok().map(std::path::PathBuf::into_os_string))
            .map(OsStringExt::into_vec);
        start_recording(
            self.recording,
            || UserSocketConnector::new(paths.user_socket()),
            Arc::new(SystemClock::new()),
            cwd,
        )
    }
}

/// How long `knsh` waits, after the shell has exited, for the last command lines to reach `knshd`. Bounded: exiting
/// the shell must never hang on the daemon (NFR-REL-02); the session ends when `knsh`'s connection closes anyway.
#[cfg(target_os = "macos")]
const TELEMETRY_FINISH: std::time::Duration = std::time::Duration::from_millis(500);

/// Whether `path` resolves to the running `knsh` binary. Unknown counts as no.
#[cfg(target_os = "macos")]
fn is_this_program(path: &std::path::Path) -> bool {
    let this = std::env::current_exe().and_then(std::fs::canonicalize);
    matches!((this, std::fs::canonicalize(path)), (Ok(this), Ok(path)) if this == path)
}

/// Hosts the user's bash (KNSH-020). Recording off: `knsh` replaces itself with plain bash, with no file or variable
/// of `knsh`'s, so every startup file runs exactly as under plain bash, with bash's own exit status, signals and
/// terminal handling. Recording on (KNSH-021): bash runs as a child with the hooks and its telemetry goes to `knshd`.
///
/// If that bash cannot be started (for example `$SHELL` names a bash since uninstalled), zsh starts instead after a
/// one-line warning: a human shell is never refused (FR-SES-22).
#[cfg(target_os = "macos")]
fn human_bash(host: &Host, shell: &knsh::cli::args::ShellInvocation, bash: &std::path::Path) -> ExitCode {
    use knsh::integration::bash::BashLaunch;
    use knsh::integration::host;

    let launch = BashLaunch {
        bash,
        startup_dir: None,
        login: shell.login,
        force_interactive: shell.interactive,
        telemetry: None,
        user_prompt_command: None,
    };
    if let Some(code) = recorded_bash(host, shell, launch) {
        return code;
    }
    let error = host::exec(&launch.plan());
    report(&format!(
        "knsh: cannot start {}: {error}; starting zsh\n",
        bash.display()
    ));
    human_zsh(host, shell)
}

/// Hosts `launch` as a recorded child (KNSH-021) and returns its exit code. `None` when it is not recorded: recording
/// is off, the bash wrapper cannot be installed (no hook would exist to record with) or the worker cannot start; the
/// caller then replaces itself with plain bash, as with recording off.
#[cfg(target_os = "macos")]
fn recorded_bash(
    host: &Host,
    shell: &knsh::cli::args::ShellInvocation,
    launch: knsh::integration::bash::BashLaunch<'_>,
) -> Option<ExitCode> {
    use knsh::integration::bash::BashLaunch;
    use knsh::integration::host::{self, HostError};
    use knsh_platform::macos::{RealFs, effective_uid};

    if !host.recording {
        return None;
    }
    let paths = host.paths.as_ref().ok()?;
    let startup_dir = match host::install_bash_startup_dir(&RealFs::new(), paths, effective_uid()) {
        Ok(dir) => dir,
        Err(error) => {
            report(&format!("knsh: recording unavailable ({error}); starting plain bash\n"));
            return None;
        }
    };
    let recording = host.start_recording()?;
    // A recorded login shell would otherwise lose the user's own PROMPT_COMMAND to the hooks' bootstrap.
    let user_prompt_command = std::env::var_os("PROMPT_COMMAND");
    let launch = BashLaunch {
        startup_dir: Some(&startup_dir),
        user_prompt_command: user_prompt_command.as_deref(),
        ..launch
    };
    let code = match run_recorded(recording, launch) {
        Ok(code) => code,
        // This bash cannot run at all: zsh, as when it fails unrecorded.
        Err(HostError::Start(error)) => {
            report(&format!(
                "knsh: cannot start {}: {error}; starting zsh\n",
                launch.bash.display()
            ));
            human_zsh(host, shell)
        }
        // The shell was never started: start it unrecorded rather than not at all.
        Err(HostError::Telemetry(error)) => {
            report(&format!(
                "knsh: recording unavailable ({error}); starting bash unrecorded\n"
            ));
            let plain = BashLaunch {
                startup_dir: None,
                ..launch
            };
            exec_shell(&plain.plan(), launch.bash)
        }
        // The shell ran but its end could not be observed: no exit status to pass on.
        Err(error @ HostError::Wait(_)) => {
            report(&format!("knsh: {error}\n"));
            ExitCode::from(EXEC_FAILED_STATUS)
        }
    };
    Some(code)
}

/// Hosts stock zsh (KNSH-019). Recording off: `knsh` replaces itself with zsh, so no telemetry, no `knshd`, and zsh's
/// own exit status, signals and terminal handling. Recording on (KNSH-021): zsh runs as a child with the hooks and
/// its telemetry goes to `knshd`.
///
/// If the startup directory cannot be installed, plain zsh starts without it after a one-line warning: a human
/// shell is never refused (FR-SES-22).
#[cfg(target_os = "macos")]
fn human_zsh(host: &Host, shell: &knsh::cli::args::ShellInvocation) -> ExitCode {
    use std::path::Path;

    use knsh::integration::host::{self as hosting, HostError};
    use knsh::integration::zsh;
    use knsh_platform::macos::{RealFs, effective_uid};

    let installed = host.paths.clone().and_then(|paths| {
        hosting::install_zsh_startup_dir(&RealFs::new(), &paths, effective_uid()).map_err(|error| error.to_string())
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
    let launch = zsh::ZshLaunch {
        zsh: Path::new(zsh::SYSTEM_ZSH),
        startup_dir: startup_dir.as_deref(),
        user_zdotdir: user_zdotdir.as_deref(),
        login: shell.login,
        force_interactive: shell.interactive,
        telemetry_fd: None,
    };
    // Without the wrapper no hook exists to record with: plain zsh, as with recording off.
    if startup_dir.is_some()
        && let Some(recording) = host.start_recording()
    {
        return match run_recorded(recording, launch) {
            Ok(code) => code,
            // The shell was never started: start it unrecorded rather than not at all (`launch` carries no telemetry
            // descriptor).
            Err(HostError::Telemetry(error)) => {
                report(&format!(
                    "knsh: recording unavailable ({error}); starting zsh unrecorded\n"
                ));
                exec_shell(&launch.plan(), Path::new(zsh::SYSTEM_ZSH))
            }
            // The system zsh cannot start, or its end could not be observed: there is no other shell to fall back to.
            Err(error @ (HostError::Start(_) | HostError::Wait(_))) => {
                report(&format!("knsh: {error}\n"));
                ExitCode::from(EXEC_FAILED_STATUS)
            }
        };
    }
    exec_shell(&launch.plan(), Path::new(zsh::SYSTEM_ZSH))
}

/// Runs `launch` as a child whose telemetry `recording` forwards to `knshd`, and returns the shell's exit code. Once
/// the shell has exited, the last lines get at most [`TELEMETRY_FINISH`] to reach `knshd`, whatever the outcome.
///
/// # Errors
///
/// [`knsh::integration::host::HostError`] if the shell could not be started or waited for.
#[cfg(target_os = "macos")]
fn run_recorded<'a>(
    recording: knsh::integration::recorder::RecordingHandle,
    launch: impl Into<knsh::integration::host::HostedLaunch<'a>>,
) -> Result<ExitCode, knsh::integration::host::HostError> {
    use knsh::integration::host;

    let outcome = host::run_recorded(launch, recording.sink(), None);
    recording.finish(TELEMETRY_FINISH);
    outcome.map(|status| ExitCode::from(host::finish(status)))
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
