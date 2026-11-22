//! The native interpreter of a native-mode agent line (KNSH-108, FR-LC-52 to FR-LC-57,
//! `specs/03-functional-requirements/command-lifecycle.md#native-mode-knsh-108`).
//!
//! `knshd` starts this through `knsh-exec`'s program mode, under the interpreter profile (no `fork`, no network, exec
//! of nothing but `knsh`), as
//!
//! ```text
//! knsh --native-line <fd> <line> [<$0> [<$1>…]]
//! ```
//!
//! where `<fd>` is the interpreter's end of the line's supervision channel. The line is run by `knsh`'s interpreter
//! as `bash -c` runs it, with every external command started through
//! [`knsh_platform::supervision::SupervisedSpawner`]: decided and spawned by the supervisor, never here. A descriptor
//! that is not a socket, or a channel that fails, leaves the line with no supervisor, and every command is then
//! denied with 126 (FR-LC-57).
//!
//! Not an agent's way in: the entry point is undocumented, and started by anything but `knshd` it has no supervisor
//! to ask, so it runs nothing (an agent that hands it a channel of its own gains nothing it could not already run).

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

/// The first argument naming this mode.
pub const NATIVE_LINE: &str = "--native-line";

/// Status of a line that could not be started (usage error, bad state), as bash's for a bad invocation.
const USAGE_STATUS: u8 = 2;

/// Writes one message on standard error, ignoring failure.
fn report(message: &str) {
    let _ = std::io::stderr().write_all(message.as_bytes());
}

/// The arguments after `--native-line`: the channel's descriptor, the line, `$0` and the positional parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLine {
    /// The channel's descriptor number.
    pub fd: i32,
    /// The line to run.
    pub line: String,
    /// `$0`; `knsh` when absent.
    pub name: String,
    /// `$1`, `$2`, ….
    pub positional: Vec<String>,
}

/// Reads the arguments after `--native-line`. `None` for anything else: a descriptor that is not a decimal number,
/// no line, or an argument that is not UTF-8 (`exec.run` lines and operands always are).
#[must_use]
pub fn parse(args: &[OsString]) -> Option<NativeLine> {
    let mut args = args.iter().map(|arg| arg.to_str().map(str::to_owned));
    let fd = args.next()??;
    if fd.is_empty() || !fd.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let fd = fd.parse().ok()?;
    let line = args.next()??;
    let rest: Option<Vec<String>> = args.collect();
    let mut rest = rest?.into_iter();
    let name = rest.next().unwrap_or_else(|| "knsh".to_owned());
    Some(NativeLine {
        fd,
        line,
        name,
        positional: rest.collect(),
    })
}

/// Runs the native-mode line described by `args` (the arguments after `--native-line`) and returns its status.
#[cfg(target_os = "macos")]
#[must_use]
pub fn run(args: &[OsString]) -> u8 {
    use knsh_interp::{Interpreter, ShellState};
    use knsh_platform::macos::{
        RealFs, SocketLink, SystemCollation, SystemDescriptors, SystemLocalTime, SystemShellTimes, SystemUserHomes,
        ignored_signals, inherited_stream,
    };
    use knsh_platform::supervision::{SupervisedSpawner, SupervisionError, SupervisorLink};
    use knsh_platform::{Descriptors, Fs};

    /// The link of a line whose channel could not be opened: every command is denied (FR-LC-57).
    struct NoSupervisor;

    impl SupervisorLink for NoSupervisor {
        fn start(
            &self,
            _submission: &knsh_platform::supervision::Submission,
            _descriptors: &[std::os::fd::BorrowedFd<'_>],
        ) -> Result<knsh_platform::supervision::StartAnswer, SupervisionError> {
            Err(SupervisionError::Closed)
        }

        fn wait(&self, _child: u64) -> Result<knsh_platform::ExitStatus, SupervisionError> {
            Err(SupervisionError::Closed)
        }
    }

    let Some(native) = parse(args) else {
        report("knsh: --native-line: usage: knsh --native-line <fd> <line> [name [arg…]]\n");
        return USAGE_STATUS;
    };
    let ignored = ignored_signals();
    let link: Arc<dyn SupervisorLink> = match inherited_stream(native.fd).and_then(SocketLink::new) {
        Ok(link) => Arc::new(link),
        Err(_) => Arc::new(NoSupervisor),
    };
    let spawner = Arc::new(SupervisedSpawner::new(
        link,
        Box::new(std::io::stdout()),
        Box::new(std::io::stderr()),
    ));
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let environment: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let state = match ShellState::new(native.name.clone(), cwd) {
        Ok(state) => state,
        Err(error) => {
            report(&format!("knsh: {error}\n"));
            return USAGE_STATUS;
        }
    };
    let state = state
        .with_environment(environment)
        .with_ignored_signals(ignored)
        .with_positional(native.positional.clone());
    let fs: Arc<dyn Fs> = Arc::new(RealFs::new());
    let descriptors: Arc<dyn Descriptors> = Arc::new(SystemDescriptors::new());
    let shell = Interpreter::new(
        state,
        fs,
        spawner,
        Arc::new(SystemUserHomes::new()),
        Arc::new(SystemCollation::new()),
        descriptors,
        Box::new(std::io::stderr()),
    )
    .with_output(Box::new(std::io::stdout()))
    .with_times(Arc::new(SystemShellTimes::new()));
    let mut shell = match shell.with_local_time(Arc::new(SystemLocalTime::new())) {
        Ok(shell) => shell,
        Err(error) => {
            report(&format!("knsh: {error}\n"));
            return USAGE_STATUS;
        }
    };
    let options = knsh_bash::ParseOptions::default()
        .with_redirection_variables(true)
        .with_arrays(true)
        .with_coproc(true);
    let script = match knsh_bash::parse_with(&native.line, options) {
        Ok(script) => script,
        Err(error) => {
            // bash -c: a syntax error runs nothing and exits 2.
            report(&format!("knsh: -c: {error}\n"));
            return USAGE_STATUS;
        }
    };
    let status = match shell.run(&script, &native.line) {
        Ok(status) => status.code(),
        Err(error) => {
            // A line the interpreter could not finish (a construct it refuses, a command that could not start)
            // fails: `$?` was never set, so `finish` would report the status from before the error, often 0
            // (found by the KNSH-109 conformance gate). The `EXIT` trap still runs, as bash runs it after a fatal
            // error (an agent's cleanup, `trap 'rm -f "$tmp"' EXIT`), but its status is not the line's.
            report(&format!("knsh: {error}\n"));
            if let Err(error) = shell.finish() {
                report(&format!("knsh: {error}\n"));
            }
            return 1;
        }
    };
    if shell.has_exited() {
        return status;
    }
    match shell.finish() {
        Ok(status) => status.code(),
        Err(error) => {
            report(&format!("knsh: {error}\n"));
            status
        }
    }
}

/// No native-mode line runs elsewhere yet: the line is not run (126, as for a command that cannot run).
#[cfg(not(target_os = "macos"))]
#[must_use]
pub fn run(_args: &[OsString]) -> u8 {
    report("knsh: --native-line is not available on this platform\n");
    126
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    // KNSH-108: `knsh --native-line <fd> <line> [name args…]`, as `knshd` builds it.
    #[test]
    fn parses_the_native_line_invocation() {
        assert_eq!(
            parse(&args(&["7", "git push", "script", "a", "b"])),
            Some(NativeLine {
                fd: 7,
                line: "git push".into(),
                name: "script".into(),
                positional: vec!["a".into(), "b".into()],
            })
        );
        assert_eq!(parse(&args(&["7", "ls"])).map(|line| line.name), Some("knsh".into()));
        for bad in [&["x", "ls"][..], &["-1", "ls"], &["7"], &[], &["", "ls"]] {
            assert_eq!(parse(&args(bad)), None, "{bad:?}");
        }
    }

    // KNSH-109: a line the interpreter refuses fails (status 1), never 0: `$?` was not set by the aborted run. Fd
    // 999 is not a socket, so there is no supervisor, and the refused expansion needs none.
    #[cfg(target_os = "macos")]
    #[test]
    fn refused_line_fails_instead_of_reporting_the_old_status() {
        assert_eq!(run(&args(&["999", "true; echo $EPOCHSECONDS"])), 1);
    }

    // KNSH-109: the `EXIT` trap still runs after a line the interpreter could not finish (bash runs it after a
    // fatal error), and the line still fails.
    #[cfg(target_os = "macos")]
    #[test]
    fn refused_line_still_runs_the_exit_trap() {
        let dir = std::env::temp_dir().join(format!("knsh-native-line-exit-trap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("trapped");
        // `eval` defers the refusal to run time (a refused construct in the line itself runs nothing at all).
        let line = format!(
            "trap 'echo ran > \"{}\"' EXIT; eval 'echo $EPOCHSECONDS'",
            marker.display()
        );
        assert_eq!(run(&args(&["999", &line])), 1);
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "ran\n");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
