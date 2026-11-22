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

/// Exit status of an agent line that did not run (denied, no supervisor, refused input): 126 (FR-LC-31).
#[cfg(unix)]
const NOT_RUN_STATUS: u8 = knsh::agent::forward::NOT_RUN_STATUS;

/// Entry point: parse argv, then print help, report a usage error, or dispatch.
///
/// Started under a shim's name (`sh`, `bash`, `zsh`, KNSH-049) `knsh` is always a shell: `bash script.sh` names a
/// script, never a `knsh` command.
fn main() -> ExitCode {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let interpreter = interpreter(&argv);
    let parsed = if interpreter == knsh_proto::Interpreter::Knsh {
        args::parse(&KNSH, argv)
    } else {
        args::parse_shell_argv(argv).map(Invocation::Shell)
    };
    match parsed {
        Ok(Invocation::Help(text)) => {
            // A closed stdout (`knsh --help | head -1`) is not an error worth reporting.
            let _ = std::io::stdout().write_all(text.as_bytes());
            ExitCode::SUCCESS
        }
        // KNSH-024: the version, labelled advisory in phase 1.
        Ok(Invocation::Version) => {
            let _ = std::io::stdout().write_all(knsh::cli::version::text().as_bytes());
            ExitCode::SUCCESS
        }
        Ok(Invocation::Shell(shell)) => shell_mode(&shell, interpreter),
        Ok(Invocation::Command(parsed)) => match parsed.path.as_slice() {
            ["agent"] => agent(&parsed),
            ["approvals"] => approvals(&parsed),
            ["approve"] => answer_approval(&parsed, knsh::cli::approvals::Answer::Approve),
            ["deny"] => answer_approval(&parsed, knsh::cli::approvals::Answer::Deny),
            ["authority", "trust"] => authority_trust(&parsed),
            ["daemon", action @ ("install" | "uninstall")] => daemon(action, parsed.json()),
            ["forget"] => forget(&parsed),
            ["undo"] => checkpoint_step(&parsed, knsh::cli::checkpoints::Step::Undo),
            ["redo"] => checkpoint_step(&parsed, knsh::cli::checkpoints::Step::Redo),
            ["checkpoints"] => checkpoints(&parsed),
            ["history"] => history(&parsed),
            ["policy", "edit"] => policy_edit(&parsed),
            ["policy", "grant"] => policy_grant(&parsed),
            ["policy", "grants"] => policy_grants(&parsed),
            ["policy", "revoke"] => policy_revoke(&parsed),
            ["profile", "use"] => profile_use(&parsed),
            ["events"] => events(&parsed),
            ["shell", "install"] => shell_install(parsed.json()),
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

    let params = match forget::params(parsed) {
        Ok(params) => params,
        Err(error) => return usage(&error, "forget"),
    };
    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    let outcome = client::connect_user(&socket).and_then(|mut client| forget::run(&mut client, &params));
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

/// Runs `knsh undo` or `knsh redo` (KNSH-088): a malformed ID is a usage error (exit 2) and sends nothing; otherwise
/// it calls `checkpoint.undo` or `checkpoint.redo` on `user.sock` and reports what was restored. A refusal exits with
/// 1 and says why on stderr, with each conflicting path.
#[cfg(unix)]
fn checkpoint_step(parsed: &knsh::cli::args::ParsedCommand, how: knsh::cli::checkpoints::Step) -> ExitCode {
    use knsh::cli::{checkpoints, client};

    let params = match checkpoints::step_params(parsed) {
        Ok(params) => params,
        Err(error) => return usage(&error, how.command()),
    };
    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    let outcome = client::connect_user(&socket)
        .and_then(|mut client| checkpoints::step(&mut client, how, &params))
        .map_err(|error| checkpoints::failure_message(how.command(), &error))
        .and_then(|result| {
            checkpoints::step_report(how, &result, parsed.json())
                .map_err(|error| format!("knsh: {} failed: {error}\n", how.command()))
        });
    match outcome {
        Ok(text) => {
            let _ = std::io::stdout().write_all(text.as_bytes());
            ExitCode::SUCCESS
        }
        Err(message) => {
            report(&message);
            ExitCode::FAILURE
        }
    }
}

/// Runs `knsh checkpoints` (KNSH-088): reads every page of `checkpoint.list` on `user.sock` and prints each change,
/// oldest first, then the current state. A failed call exits with 1 and the reason on stderr.
#[cfg(unix)]
fn checkpoints(parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    use knsh::cli::{checkpoints, client};

    let session = match checkpoints::list_session(parsed) {
        Ok(session) => session,
        Err(error) => return usage(&error, "checkpoints"),
    };
    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    let listed = client::connect_user(&socket)
        .and_then(|mut client| checkpoints::list(&mut client, session))
        .map_err(|error| checkpoints::failure_message("checkpoints", &error))
        .and_then(|(changes, head)| {
            checkpoints::list_report(&changes, head, parsed.json())
                .map_err(|error| format!("knsh: checkpoints failed: {error}\n"))
        });
    match listed {
        Ok(text) => {
            let _ = std::io::stdout().write_all(text.as_bytes());
            ExitCode::SUCCESS
        }
        Err(message) => {
            report(&message);
            ExitCode::FAILURE
        }
    }
}

/// Runs `knsh approvals` (KNSH-066, FR-AUTH-40): lists the pending asks through `approval.list` on `user.sock`. A
/// failed call exits with 1 and the reason on stderr.
#[cfg(unix)]
fn approvals(parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    use knsh::cli::{approvals, client};

    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    let listed = client::connect_user(&socket)
        .and_then(|mut client| approvals::list(&mut client))
        .map_err(|error| approvals::failure_message("approvals", &error))
        .and_then(|list| {
            approvals::list_report(&list, parsed.json()).map_err(|error| format!("knsh: approvals failed: {error}\n"))
        });
    match listed {
        Ok(text) => {
            // A closed stdout (`knsh approvals | head`) is not an error worth reporting.
            let _ = std::io::stdout().write_all(text.as_bytes());
            ExitCode::SUCCESS
        }
        Err(message) => {
            report(&message);
            ExitCode::FAILURE
        }
    }
}

/// Runs `knsh approve <request_id>` or `knsh deny <request_id>` (KNSH-066, FR-AUTH-41, FR-AUTH-42). A malformed ID is
/// a usage error (exit 2) and sends nothing. An approval says on stderr that `knshd` shows the Touch ID or password
/// prompt, then waits for it: the CLI never asks anything on the terminal (FR-AUTH-43). A refusal exits with 1.
#[cfg(unix)]
fn answer_approval(parsed: &knsh::cli::args::ParsedCommand, how: knsh::cli::approvals::Answer) -> ExitCode {
    use knsh::cli::approvals::{self, Answer};
    use knsh::cli::client;

    let request_id = match approvals::request_id(parsed) {
        Ok(request_id) => request_id,
        Err(error) => return usage(&error, how.command()),
    };
    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    if how == Answer::Approve {
        report(&approvals::confirm_notice(request_id));
    }
    match client::connect_user(&socket).and_then(|mut client| approvals::answer(&mut client, how, request_id)) {
        Ok(result) => {
            let _ = std::io::stdout().write_all(approvals::answer_report(&result, parsed.json()).as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&approvals::failure_message(how.command(), &error));
            ExitCode::FAILURE
        }
    }
}

/// Runs `knsh authority trust` (KNSH-068, FR-AUTH-10): a malformed team ID, identifier or version is a usage error
/// (exit 2) and sends nothing. Otherwise it says on stderr that `knshd` may show the Touch ID or password prompt, then
/// waits for `authority.trust`: the CLI never asks anything on the terminal and cannot skip the prompt. A refusal exits
/// with 1.
#[cfg(unix)]
fn authority_trust(parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    use knsh::cli::{authority, client};

    let params = match authority::params(parsed) {
        Ok(params) => params,
        Err(error) => return usage(&error, "authority trust"),
    };
    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    report(&authority::confirm_notice(&params));
    match client::connect_user(&socket).and_then(|mut client| authority::trust(&mut client, &params)) {
        Ok(result) => {
            let _ = std::io::stdout().write_all(authority::report(&result, parsed.json()).as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&authority::failure_message(&error));
            ExitCode::FAILURE
        }
    }
}

/// Runs `knsh profile use <profile>` (KNSH-072, FR-POL-51): a malformed name is a usage error (exit 2) and sends
/// nothing. Otherwise it says on stderr that `knshd` may show the Touch ID or password prompt, then waits for
/// `profile.use`: the CLI never asks anything on the terminal and cannot skip the prompt. A refusal exits with 1.
#[cfg(unix)]
fn profile_use(parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    use knsh::cli::{client, profile};

    let params = match profile::params(parsed) {
        Ok(params) => params,
        Err(error) => return usage(&error, "profile use"),
    };
    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    report(&profile::confirm_notice(&params));
    match client::connect_user(&socket).and_then(|mut client| profile::use_profile(&mut client, &params)) {
        Ok(result) => {
            let _ = std::io::stdout().write_all(profile::report(&result, parsed.json()).as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&profile::failure_message(&error));
            ExitCode::FAILURE
        }
    }
}

/// Runs `knsh policy grant` (KNSH-073, FR-POL-62): a malformed command line is a usage error (exit 2) and sends
/// nothing. Otherwise it says on stderr that `knshd` shows the Touch ID or password prompt, then waits for
/// `policy.grant`: the CLI never asks anything on the terminal and cannot skip the prompt. A refusal exits with 1.
#[cfg(unix)]
fn policy_grant(parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    use knsh::cli::{client, grants};

    let params = match grants::grant_params(parsed) {
        Ok(params) => params,
        Err(error) => return usage(&error, "policy grant"),
    };
    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    report(&grants::confirm_notice(&params));
    match client::connect_user(&socket).and_then(|mut client| grants::grant(&mut client, &params)) {
        Ok(result) => {
            let _ = std::io::stdout().write_all(grants::grant_report(&result, parsed.json()).as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&grants::grant_failure_message(&error));
            ExitCode::FAILURE
        }
    }
}

/// Runs `knsh policy grants` (KNSH-073, FR-POL-61): every live grant, the authority's and the user's.
#[cfg(unix)]
fn policy_grants(parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    use knsh::cli::{client, grants};

    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    let listed = client::connect_user(&socket)
        .and_then(|mut client| grants::list(&mut client))
        .map_err(|error| grants::failure_message("grants", &error))
        .and_then(|list| {
            grants::list_report(&list, parsed.json()).map_err(|error| format!("knsh: policy grants failed: {error}\n"))
        });
    match listed {
        Ok(text) => {
            // A closed stdout (`knsh policy grants | head`) is not an error worth reporting.
            let _ = std::io::stdout().write_all(text.as_bytes());
            ExitCode::SUCCESS
        }
        Err(message) => {
            report(&message);
            ExitCode::FAILURE
        }
    }
}

/// Runs `knsh policy revoke <grant_id>` (KNSH-073, FR-POL-61): a malformed ID is a usage error (exit 2). No prompt:
/// a revocation only removes a permission. A grant that was not live is reported, not an error.
#[cfg(unix)]
fn policy_revoke(parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    use knsh::cli::{client, grants};

    let grant_id = match grants::grant_id(parsed) {
        Ok(grant_id) => grant_id,
        Err(error) => return usage(&error, "policy revoke"),
    };
    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    match client::connect_user(&socket).and_then(|mut client| grants::revoke(&mut client, grant_id)) {
        Ok(result) => {
            let _ = std::io::stdout().write_all(grants::revoke_report(&result, grant_id, parsed.json()).as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&grants::failure_message("revoke", &error));
            ExitCode::FAILURE
        }
    }
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn policy_grant(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh policy grant' on this platform")
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn policy_grants(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh policy grants' on this platform")
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn policy_revoke(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh policy revoke' on this platform")
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn profile_use(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh profile use' on this platform")
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn authority_trust(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh authority trust' on this platform")
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn approvals(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh approvals' on this platform")
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn answer_approval(_parsed: &knsh::cli::args::ParsedCommand, how: knsh::cli::approvals::Answer) -> ExitCode {
    not_implemented(&format!("'knsh {}' on this platform", how.command()))
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn checkpoint_step(_parsed: &knsh::cli::args::ParsedCommand, how: knsh::cli::checkpoints::Step) -> ExitCode {
    not_implemented(&format!("'knsh {}' on this platform", how.command()))
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn checkpoints(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh checkpoints' on this platform")
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn forget(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh forget' on this platform")
}

/// Runs `knsh policy edit <profile>` (KNSH-065, FR-POL-41): reads the profile from `knshd`, opens it in the user's
/// editor in a private temporary file, and sends the result to be signed; `knshd` shows the Touch ID or password
/// prompt itself. A bad profile name is a usage error (exit 2); a failed editor or call exits with 1, nothing saved,
/// and the edited text is kept in its temporary file. The connection is closed while the editor runs, so a long edit
/// never holds `knshd` or meets a read timeout.
#[cfg(target_os = "macos")]
fn policy_edit(parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    use knsh::cli::{client, policy};

    let profile = match policy::profile(parsed) {
        Ok(profile) => profile,
        Err(error) => return usage(&error, "policy edit"),
    };
    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    let current = match client::connect_user(&socket).and_then(|mut client| policy::read(&mut client, &profile)) {
        Ok(current) => current,
        Err(error) => {
            report(&policy::failure_message(&error));
            return ExitCode::FAILURE;
        }
    };
    if let Some(warning) = policy::state_warning(&current) {
        report(&warning);
    }
    let path = match edit_file::create(&profile, &current.text) {
        Ok(path) => path,
        Err(error) => {
            report(&format!("knsh: policy edit: cannot create a temporary file: {error}\n"));
            return ExitCode::FAILURE;
        }
    };
    // Every failure after the file exists reports why, then where the edited text is kept, so no work is lost.
    let not_saved = |message: &str| {
        report(message);
        report(&format!("knsh: policy edit: your text is kept in {}\n", path.display()));
        ExitCode::FAILURE
    };
    let visual = std::env::var("VISUAL").ok();
    let editor = std::env::var("EDITOR").ok();
    let editor = policy::editor(visual.as_deref(), editor.as_deref());
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(policy::editor_script(&editor))
        .arg("knsh-policy-edit")
        .arg(&path)
        .status();
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => {
            return not_saved(&format!(
                "knsh: policy edit: the editor exited with {status}; nothing was saved\n"
            ));
        }
        Err(error) => {
            return not_saved(&format!(
                "knsh: policy edit: cannot run the editor: {error}; nothing was saved\n"
            ));
        }
    }
    let edited = match edit_file::read(&path) {
        Ok(text) => policy::as_signed(&text),
        Err(error) => return not_saved(&format!("knsh: policy edit: {error}; nothing was saved\n")),
    };
    let result = if policy::unchanged(&current, &edited) {
        Ok(knsh_proto::PolicyEditResult {
            profile: profile.clone(),
            changed: false,
        })
    } else {
        let sha256 = knsh_platform::macos::sha256(edited.as_bytes());
        report(&policy::confirm_notice(&profile, edited.len(), &sha256));
        client::connect_user(&socket).and_then(|mut client| policy::save(&mut client, &profile, edited))
    };
    match result {
        Ok(result) => {
            let _ = std::fs::remove_file(&path);
            let _ = std::io::stdout().write_all(policy::report(&result, parsed.json()).as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => not_saved(&policy::failure_message(&error)),
    }
}

/// Policy files are signed by `knshd` with the Keychain and Touch ID: macOS only so far.
#[cfg(not(target_os = "macos"))]
fn policy_edit(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh policy edit' on this platform")
}

/// The private temporary file `knsh policy edit` opens in the editor.
#[cfg(target_os = "macos")]
mod edit_file {
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;

    use knsh_core::ProfileName;

    /// Creates `<TMPDIR>/knsh-policy-<profile>-<pid>-<n>.toml`, new and owner-only (`0600`), holding `text`. Never
    /// opens an existing file, so nothing planted at the name is followed or reused.
    pub(super) fn create(profile: &ProfileName, text: &str) -> std::io::Result<PathBuf> {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let mut attempt = 0u32;
        loop {
            let path = dir.join(format!("knsh-policy-{profile}-{pid}-{attempt}.toml"));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(mut file) => {
                    file.write_all(text.as_bytes())?;
                    return Ok(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempt < 100 => attempt += 1,
                Err(error) => return Err(error),
            }
        }
    }

    /// The edited text: UTF-8, at most the profile limit.
    pub(super) fn read(path: &std::path::Path) -> Result<String, String> {
        let limit = knsh_proto::MAX_POLICY_TEXT_LEN;
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| {
                file.take(u64::try_from(limit).unwrap_or(u64::MAX) + 1)
                    .read_to_end(&mut bytes)
            })
            .map_err(|error| format!("cannot read the edited file: {error}"))?;
        if bytes.len() > limit {
            return Err(format!("the edited text is longer than {limit} bytes"));
        }
        String::from_utf8(bytes).map_err(|_| String::from("the edited text is not UTF-8"))
    }
}

/// Runs `knsh agent` (KNSH-056): checks the command line, asks `knshd` over `user.sock` to start the agent CLI on
/// this process's terminal, waits, and exits as the CLI did. A malformed option is a usage error (exit 2) and a
/// command that cannot be found exits with 127, both before anything is sent; a refusal or a lost `knshd` exits with
/// 1 and the reason on stderr.
#[cfg(target_os = "macos")]
fn agent(parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    use knsh::cli::agent;

    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => {
            report(&format!("knsh: agent: cannot read the working directory: {error}\n"));
            return ExitCode::FAILURE;
        }
    };
    let env: Vec<_> = std::env::vars_os().collect();
    let executable = |path: &std::path::Path| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    };
    let params = match agent::params(parsed, &cwd, &env, &executable) {
        Ok(params) => params,
        Err(refusal) => {
            report(&format!("knsh: agent: {refusal}\n"));
            return ExitCode::from(refusal.status());
        }
    };
    warn_if_cli_sandboxed(&params);
    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    match agent::run(&socket, &params) {
        Ok(result) => {
            let (status, line) = agent::finished(&result, parsed.json());
            if let Some(line) = line {
                let _ = std::io::stdout().write_all(line.as_bytes());
            }
            ExitCode::from(status)
        }
        Err(error) => {
            report(&agent::failure_message(&error));
            ExitCode::FAILURE
        }
    }
}

/// FR-AGT-05 (KNSH-058): warns on stderr when the agent CLI's own sandbox is still on, or cannot be checked. Never
/// stops the CLI: the warning says how to turn the sandbox off.
#[cfg(target_os = "macos")]
fn warn_if_cli_sandboxed(params: &knsh_proto::SessionStartAgentParams) {
    use knsh::cli::agent_sandbox::{Cli, check, read_file, warning};

    let Some(cli) = params.command.first().and_then(|program| Cli::of_program(program)) else {
        return;
    };
    // Without HOME the CLI's user settings cannot be found; `check` then reports the files it could not read.
    let home = params
        .env
        .iter()
        .find(|(name, _)| name == "HOME")
        .map_or_else(std::path::PathBuf::new, |(_, home)| std::path::PathBuf::from(home));
    let state = check(
        cli,
        &params.command,
        &params.env,
        &home,
        params.cwd.as_path(),
        &read_file,
    );
    if let Some(text) = warning(cli, &state) {
        report(&text);
    }
}

/// Envelopes need the macOS sandbox; no other platform has one yet.
#[cfg(not(target_os = "macos"))]
fn agent(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh agent' on this platform")
}

/// The path of `user.sock` under `HOME`. On failure the reason is already on stderr and the exit code (1) is returned.
#[cfg(unix)]
fn user_socket() -> Result<std::path::PathBuf, ExitCode> {
    use knsh_platform::EnginePaths;

    let Some(home) = std::env::var_os("HOME") else {
        report("knsh: HOME is not set\n");
        return Err(ExitCode::FAILURE);
    };
    match EnginePaths::for_home(std::path::Path::new(&home)) {
        Ok(paths) => Ok(paths.user_socket()),
        Err(error) => {
            report(&format!("knsh: unusable HOME: {error}\n"));
            Err(ExitCode::FAILURE)
        }
    }
}

/// Runs `knsh history` (KNSH-023): validates the filters, reads every matching page of `records.query` on
/// `user.sock`, and prints the newest records first, terminal-safe. Malformed values are a usage error (exit 2) and
/// send nothing; an unreachable `knshd` or a failed query exits with 1 and the reason on stderr.
#[cfg(unix)]
fn history(parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    use knsh::cli::{client, history};

    let query = match history::query(parsed) {
        Ok(query) => query,
        Err(error) => return usage(&error, "history"),
    };
    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    let records = match client::connect_user(&socket).and_then(|mut client| history::run(&mut client, &query)) {
        Ok(records) => records,
        Err(error) => {
            report(&history::failure_message(&error));
            return ExitCode::FAILURE;
        }
    };
    match history::report(&records, parsed.json()) {
        Ok(text) => {
            // A closed stdout (`knsh history | head`) is not an error worth reporting.
            let _ = std::io::stdout().write_all(text.as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&format!("knsh: history failed: {error}\n"));
            ExitCode::FAILURE
        }
    }
}

/// Runs `knsh events` (KNSH-023): validates the options, subscribes on `user.sock` and prints each event as it
/// arrives until interrupted. Malformed options are a usage error (exit 2) and send nothing. An unreachable `knshd`,
/// a refused subscription or a connection that ends exits with 1 and the reason on stderr; a reader that goes away
/// (`knsh events | head`) ends the command quietly with 0.
#[cfg(unix)]
fn events(parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    use knsh::cli::client::{self, ClientError};
    use knsh::cli::events::{self, FollowError};

    let params = match events::params(parsed) {
        Ok(params) => params,
        Err(error) => return usage(&error, "events"),
    };
    let socket = match user_socket() {
        Ok(socket) => socket,
        Err(code) => return code,
    };
    let subscribed = client::connect_user_with_handle(&socket).and_then(|(mut client, handle)| {
        // Once subscribed, silence is normal (no events for hours), so reads wait without a deadline; interrupting the
        // command (Ctrl-C) is how it ends. The deadline is lifted before subscribing, while `knshd` has just answered
        // `hello`: macOS refuses to change a socket option once the peer has closed, which `knshd` may do right after
        // the first events, and that must read as the end of the stream, not as a failure to subscribe.
        handle.set_read_timeout(None).map_err(ClientError::Io)?;
        let result = events::subscribe(&mut client, &params)?;
        Ok((client, result))
    });
    let (mut client, result) = match subscribed {
        Ok(subscribed) => subscribed,
        Err(error) => {
            report(&events::failure_message(&error));
            return ExitCode::FAILURE;
        }
    };
    if let Some(notice) = events::gap_notice(&params, &result) {
        report(&notice);
    }
    let Err(error) = events::follow(&mut client, parsed.json(), &mut std::io::stdout().lock());
    match error {
        FollowError::Output(error) if error.kind() == std::io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        FollowError::Client(ClientError::Closed) => {
            report("knsh: events: knshd closed the connection\n");
            ExitCode::FAILURE
        }
        other => {
            report(&format!("knsh: events failed: {other}\n"));
            ExitCode::FAILURE
        }
    }
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn history(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh history' on this platform")
}

/// `user.sock` is a Unix socket; no other platform has one.
#[cfg(not(unix))]
fn events(_parsed: &knsh::cli::args::ParsedCommand) -> ExitCode {
    not_implemented("'knsh events' on this platform")
}

/// Reports a command's usage error the way the argument parser does, and returns its exit status (2).
#[cfg(unix)]
fn usage(error: &dyn std::fmt::Display, command: &str) -> ExitCode {
    report(&format!(
        "knsh: {error}\nTry 'knsh {command} --help' for more information.\n"
    ));
    ExitCode::from(ArgsError::EXIT_STATUS)
}

/// Runs `knsh shell install` (KNSH-022): adds the running `knsh` to `/etc/shells` after an explicit yes on the
/// terminal. Exits with 1 and the reason on stderr when it cannot; `/etc/shells` is then unchanged.
#[cfg(unix)]
fn shell_install(json: bool) -> ExitCode {
    use knsh::cli::shell::{self, SystemShellsHost};

    // Resolved, so /etc/shells names the binary itself and not a symlink that may later point elsewhere.
    let knsh = match std::env::current_exe().and_then(std::fs::canonicalize) {
        Ok(path) => path,
        Err(error) => {
            report(&format!("knsh: cannot locate the running knsh binary: {error}\n"));
            return ExitCode::FAILURE;
        }
    };
    match shell::install(&mut SystemShellsHost, &knsh) {
        Ok(outcome) => {
            let _ = std::io::stdout().write_all(shell::report(outcome, &knsh, json).as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&format!("knsh: shell install failed: {error}\n"));
            ExitCode::FAILURE
        }
    }
}

/// `/etc/shells` exists only on Unix.
#[cfg(not(unix))]
fn shell_install(_json: bool) -> ExitCode {
    not_implemented("'knsh shell install' on this platform")
}

/// The interpreter `knsh` was started as: a shim's name, or `knsh` itself.
#[cfg(unix)]
fn interpreter(argv: &[std::ffi::OsString]) -> knsh_proto::Interpreter {
    knsh::agent::shims::interpreter(argv.first().map(std::ffi::OsString::as_os_str))
}

/// Shims exist only on Unix.
#[cfg(not(unix))]
fn interpreter(_argv: &[std::ffi::OsString]) -> knsh_proto::Interpreter {
    knsh_proto::Interpreter::Knsh
}

/// Runs a shell-mode invocation. A human interactive shell is hosted in integration mode (KNSH-019). Everything else
/// (`-c` lines, scripts, commands on stdin) is an agent line, forwarded to the supervisor and never run here
/// (KNSH-049).
fn shell_mode(shell: &knsh::cli::args::ShellInvocation, interpreter: knsh_proto::Interpreter) -> ExitCode {
    use std::io::IsTerminal;

    use knsh::integration::zsh;

    let on_terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    // FR-AGT-20, FR-AGT-22: inside an envelope (its session token is in the environment) there is no human shell.
    // An interactive `knsh` there, on the envelope's terminal, is forwarded as an agent line like any other, so the
    // commands typed into it are the agent's. Without the token, the envelope's sandbox still confines it.
    // An empty value names no session (tokens are 64 hex characters), so it never takes a human's shell away.
    let in_envelope = std::env::var_os(knsh_proto::SESSION_TOKEN_VAR).is_some_and(|token| !token.is_empty());
    if !in_envelope
        && zsh::is_human_interactive(
            shell.command.as_deref(),
            &shell.operands,
            shell.interactive,
            on_terminal,
        )
    {
        human_shell(shell)
    } else {
        agent_line(shell, interpreter)
    }
}

/// Forwards the line `shell` names to the supervisor over `agent.sock` and exits as the line did (KNSH-049,
/// FR-AGT-10). Nothing is ever run here: whatever fails, the line does not run, the reason goes to stderr and the
/// exit status is 126 (FR-LC-31, NFR-REL-01).
#[cfg(target_os = "macos")]
fn agent_line(shell: &knsh::cli::args::ShellInvocation, interpreter: knsh_proto::Interpreter) -> ExitCode {
    use knsh::agent::forward;
    use knsh::agent::socket::UnixAgentSocket;
    use knsh_platform::EnginePaths;

    let not_run = |reason: &str| {
        report(&format!("knsh: {reason}; the line did not run\n"));
        ExitCode::from(NOT_RUN_STATUS)
    };
    let Some(home) = std::env::var_os("HOME") else {
        return not_run("the supervisor is unavailable (HOME is not set, so agent.sock cannot be found)");
    };
    let path = match EnginePaths::for_home(std::path::Path::new(&home)) {
        Ok(paths) => paths.agent_socket(),
        Err(error) => return not_run(&format!("the supervisor is unavailable (unusable HOME: {error})")),
    };
    // Before anything else opens a descriptor: the line's stdio is this process's own.
    let mut socket = match UnixAgentSocket::new(path) {
        Ok(socket) => socket,
        Err(error) => return not_run(&format!("cannot pass the standard streams ({error})")),
    };
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => return not_run(&format!("the working directory cannot be read ({error})")),
    };
    // The whole environment, unchanged (FR-AGT-10); `knshd` removes the shims and the token before the line runs.
    let env: Vec<_> = std::env::vars_os().collect();
    // Only the token (or, without it, the audit token) decides whether this is an envelope (FR-AGT-23); a token that
    // is not text cannot be valid, and the audit token decides.
    let token = std::env::var_os(knsh_proto::SESSION_TOKEN_VAR).and_then(|token| token.into_string().ok());
    let params = match forward::request(&forward::line(shell, interpreter), &cwd, &env) {
        Ok(params) => params,
        Err(refusal) => return not_run(&refusal.to_string()),
    };
    let exit = forward::forward(
        &mut socket,
        token.as_deref(),
        &params,
        &mut std::thread::sleep,
        &mut report,
    );
    if let Some(message) = &exit.message {
        report(message);
    }
    ExitCode::from(exit.status)
}

/// The supervisor is reached over a macOS socket only so far; elsewhere no agent line can run.
#[cfg(not(target_os = "macos"))]
fn agent_line(_shell: &knsh::cli::args::ShellInvocation, _interpreter: knsh_proto::Interpreter) -> ExitCode {
    not_implemented("agent lines on this platform")
}

/// Hosts the user's stock shell for a human: the one `[shell] hosted` names (KNSH-022), else their bash when `$SHELL`
/// is one (KNSH-020), else zsh (KNSH-019). Recorded when `[recording] human = true` is set (KNSH-021); otherwise
/// `knsh` never contacts `knshd` (FR-SES-23). A login invocation (`-knsh`, `-l`, `--login`) starts the hosted shell as
/// a login shell (NFR-COMPAT-08).
#[cfg(target_os = "macos")]
fn human_shell(shell: &knsh::cli::args::ShellInvocation) -> ExitCode {
    use knsh::integration::config::HostedShell;

    let host = Host::new();
    match &host.hosted {
        HostedShell::Bash(bash) => human_bash(&host, shell, bash),
        HostedShell::Zsh(zsh) => human_zsh(&host, shell, zsh),
        HostedShell::Native => human_native(&host, shell),
    }
}

/// Runs `knsh`'s own interactive shell (KNSH-107, `[shell] hosted = "native"`), and exits as it did: with its
/// status, or by the signal whose default action ended it.
#[cfg(target_os = "macos")]
fn human_native(host: &Host, shell: &knsh::cli::args::ShellInvocation) -> ExitCode {
    use knsh::native::{self, NativeExit, NativeStart};

    if host.recording {
        // Said, never hidden: the setting asks for recording, which native mode does not do yet.
        report("knsh: recording is not available in native mode yet; this session is not recorded\n");
    }
    let start = NativeStart {
        login: shell.login,
        marks: host.marks,
    };
    match native::run(start) {
        NativeExit::Status(code) => ExitCode::from(code),
        NativeExit::Signal(signal) => {
            knsh_platform::macos::reraise_default(signal);
            ExitCode::from(128_u8.saturating_add(u8::try_from(signal).unwrap_or(0)))
        }
    }
}

/// What every way of hosting the shell needs: the engine paths, the settings, and whether the terminal gets marks.
#[cfg(target_os = "macos")]
struct Host {
    /// The reason when `HOME` is unset or unusable: then no startup wrapper and no configuration, so no recording.
    paths: Result<knsh_platform::EnginePaths, String>,
    /// `[recording] human` (KNSH-021). Off unless the configuration says `true`.
    recording: bool,
    /// The shell to host (KNSH-022): always one that can be started, `/bin/zsh` when the choice cannot.
    hosted: knsh::integration::config::HostedShell,
    /// OSC 7 and OSC 133 (KNSH-022): only when `knsh`'s standard output is a terminal.
    marks: bool,
}

#[cfg(target_os = "macos")]
impl Host {
    /// Resolves the engine paths from `HOME`, reads the settings once and chooses the shell. An unclear setting is
    /// reported once on stderr; the shell starts either way.
    fn new() -> Self {
        use std::io::IsTerminal;
        use std::path::Path;

        use knsh::integration::config::{self, Settings};
        use knsh::integration::{bash, marks, shells};
        use knsh_platform::EnginePaths;
        use knsh_platform::macos::RealFs;

        let paths = std::env::var_os("HOME")
            .ok_or_else(|| "HOME is not set".to_owned())
            .and_then(|home| EnginePaths::for_home(Path::new(&home)).map_err(|error| error.to_string()));
        let (settings, file) = match &paths {
            Ok(paths) => {
                let file = paths.config_file();
                (config::read_settings(&RealFs::new(), &file), file.display().to_string())
            }
            // No configuration to read: every setting keeps its default (recording off, FR-SES-04).
            Err(_) => (Settings::default(), String::new()),
        };
        let login_shell = std::env::var_os(bash::SHELL_VAR);
        let choice = shells::choose_hosted_shell(&settings.hosted_shell, login_shell.as_deref(), &is_usable_shell);
        // A file that cannot be read or parsed spoils both settings with the same error: said once, with both effects.
        let same_error = matches!((&settings.recording, &settings.hosted_shell), (Err(a), Err(b)) if a == b);
        if let Err(error) = &settings.recording {
            // Unclear means off (privacy first).
            let also = if same_error { " and /bin/zsh starts" } else { "" };
            report(&format!("knsh: {file}: {error}; recording is off{also}\n"));
        }
        if let Some(warning) = &choice.warning
            && !same_error
        {
            let source = if settings.hosted_shell.is_err() {
                format!("{file}: ")
            } else {
                String::new()
            };
            report(&format!("knsh: {source}{warning}\n"));
        }
        Self {
            paths,
            recording: settings.recording.unwrap_or(false),
            hosted: choice.shell,
            marks: marks::wanted(std::io::stdout().is_terminal()),
        }
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

/// Whether `path` can be started as the hosted shell: an executable regular file that is not `knsh` itself (which
/// would start `knsh` again, forever).
#[cfg(target_os = "macos")]
fn is_usable_shell(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let executable =
        std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0);
    executable && !is_this_program(path)
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

/// Hosts the user's bash (KNSH-020). Not recorded: `knsh` replaces itself with bash, so exit status, signals and
/// terminal handling are bash's own; bash reads `knsh`'s wrapper only for the terminal marks (KNSH-022), and none
/// at all without them. Recording on (KNSH-021): bash runs as a child with the hooks and its telemetry goes to
/// `knshd`.
///
/// If that bash cannot be started (for example it has been uninstalled), zsh starts instead after a one-line
/// warning: a human shell is never refused (FR-SES-22).
#[cfg(target_os = "macos")]
fn human_bash(host: &Host, shell: &knsh::cli::args::ShellInvocation, bash: &std::path::Path) -> ExitCode {
    use std::path::Path;

    use knsh::integration::bash::{BashLaunch, PROMPT_COMMAND_VAR};
    use knsh::integration::host as hosting;
    use knsh::integration::zsh::SYSTEM_ZSH;
    use knsh_platform::macos::{RealFs, effective_uid};

    // A login bash that reads the wrapper starts with the bootstrap in PROMPT_COMMAND, followed by the user's own.
    let user_prompt_command = std::env::var_os(PROMPT_COMMAND_VAR);
    let launch = BashLaunch {
        bash,
        startup_dir: None,
        login: shell.login,
        force_interactive: shell.interactive,
        telemetry_fd: None,
        marks: host.marks,
        // knsh replaces itself with bash, so bash's parent is knsh's.
        parent_pid: std::os::unix::process::parent_id(),
        user_prompt_command: user_prompt_command.as_deref(),
    };
    if let Some(code) = recorded_bash(host, shell, launch) {
        return code;
    }
    // Not recorded: only the marks need the wrapper now; without them, or without the wrapper, plain bash.
    let startup_dir = match &host.paths {
        Ok(paths) if host.marks => match hosting::install_bash_startup_dir(&RealFs::new(), paths, effective_uid()) {
            Ok(dir) => Some(dir),
            Err(error) => {
                report(&format!(
                    "knsh: terminal marks unavailable ({error}); starting plain bash\n"
                ));
                None
            }
        },
        _ => None,
    };
    let launch = BashLaunch {
        startup_dir: startup_dir.as_deref(),
        ..launch
    };
    let error = hosting::exec(&launch.plan());
    report(&format!(
        "knsh: cannot start {}: {error}; starting zsh\n",
        bash.display()
    ));
    human_zsh(host, shell, Path::new(SYSTEM_ZSH))
}

/// Hosts `launch` as a recorded child (KNSH-021) and returns its exit code. `None` when it is not recorded: recording
/// is off, the bash wrapper cannot be installed (no hook would exist to record with) or the worker cannot start; the
/// caller then replaces itself with bash, as with recording off.
#[cfg(target_os = "macos")]
fn recorded_bash(
    host: &Host,
    shell: &knsh::cli::args::ShellInvocation,
    launch: knsh::integration::bash::BashLaunch<'_>,
) -> Option<ExitCode> {
    use std::path::Path;

    use knsh::integration::bash::BashLaunch;
    use knsh::integration::host::{self, HostError};
    use knsh::integration::zsh::SYSTEM_ZSH;
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
    let launch = BashLaunch {
        startup_dir: Some(&startup_dir),
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
            human_zsh(host, shell, Path::new(SYSTEM_ZSH))
        }
        // The shell was never started: start it unrecorded rather than not at all (`launch` carries no telemetry
        // descriptor, and its parent is knsh's own once knsh is replaced by it).
        Err(HostError::Telemetry(error)) => {
            report(&format!(
                "knsh: recording unavailable ({error}); starting bash unrecorded\n"
            ));
            let unrecorded = BashLaunch {
                parent_pid: std::os::unix::process::parent_id(),
                ..launch
            };
            // Returns only when bash cannot be started: zsh, as when it fails unrecorded (FR-SES-22).
            let error = host::exec(&unrecorded.plan());
            report(&format!(
                "knsh: cannot start {}: {error}; starting zsh\n",
                launch.bash.display()
            ));
            human_zsh(host, shell, Path::new(SYSTEM_ZSH))
        }
        // The shell ran but its end could not be observed: no exit status to pass on.
        Err(error @ HostError::Wait(_)) => {
            report(&format!("knsh: {error}\n"));
            ExitCode::from(EXEC_FAILED_STATUS)
        }
    };
    Some(code)
}

/// Hosts zsh (KNSH-019): `/bin/zsh`, or the zsh `[shell] hosted` names (KNSH-022). Recording off: `knsh` replaces
/// itself with zsh, so no telemetry, no `knshd`, and zsh's own exit status, signals and terminal handling. Recording
/// on (KNSH-021): zsh runs as a child with the hooks and its telemetry goes to `knshd`. The terminal marks come with
/// the wrapper either way (KNSH-022).
///
/// If the startup directory cannot be installed, plain zsh starts without it after a one-line warning; if a zsh
/// other than `/bin/zsh` cannot be started, `/bin/zsh` starts instead: a human shell is never refused (FR-SES-22).
#[cfg(target_os = "macos")]
fn human_zsh(host: &Host, shell: &knsh::cli::args::ShellInvocation, zsh_path: &std::path::Path) -> ExitCode {
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
        zsh: zsh_path,
        startup_dir: startup_dir.as_deref(),
        user_zdotdir: user_zdotdir.as_deref(),
        login: shell.login,
        force_interactive: shell.interactive,
        telemetry_fd: None,
        marks: host.marks,
    };
    let system_zsh = Path::new(zsh::SYSTEM_ZSH);
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
                // A chosen zsh that cannot be started falls back to /bin/zsh here too (FR-SES-22).
                if zsh_path != system_zsh {
                    let error = hosting::exec(&launch.plan());
                    return system_zsh_instead(host, shell, zsh_path, &error);
                }
                exec_shell(&launch.plan(), zsh_path)
            }
            Err(HostError::Start(error)) if zsh_path != system_zsh => system_zsh_instead(host, shell, zsh_path, &error),
            // The system zsh cannot start, or its end could not be observed: there is no other shell to fall back to.
            Err(error @ (HostError::Start(_) | HostError::Wait(_))) => {
                report(&format!("knsh: {error}\n"));
                ExitCode::from(EXEC_FAILED_STATUS)
            }
        };
    }
    // A chosen zsh may be gone or broken, so its exec failing is not the end: the system one is the last resort, and
    // only its failure goes to `exec_shell`.
    if zsh_path != system_zsh {
        let error = hosting::exec(&launch.plan());
        return system_zsh_instead(host, shell, zsh_path, &error);
    }
    exec_shell(&launch.plan(), zsh_path)
}

/// A chosen zsh (`failed`) could not be started: says why once and hosts `/bin/zsh` instead (FR-SES-22).
#[cfg(target_os = "macos")]
fn system_zsh_instead(
    host: &Host,
    shell: &knsh::cli::args::ShellInvocation,
    failed: &std::path::Path,
    error: &dyn std::fmt::Display,
) -> ExitCode {
    use knsh::integration::zsh::SYSTEM_ZSH;

    report(&format!(
        "knsh: cannot start {}: {error}; starting {SYSTEM_ZSH}\n",
        failed.display()
    ));
    human_zsh(host, shell, std::path::Path::new(SYSTEM_ZSH))
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
