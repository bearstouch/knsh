//! The candidate shell: `knsh`'s native interpreter started the way `bash` is started by the suites.
//!
//! ```text
//! knsh-native [--posix] [-o NAME | +o NAME | -LETTERS | +LETTERS]... [-c COMMAND [NAME [ARG...]] | FILE [ARG...]]
//! ```
//!
//! (or `knsh-conformance native …`). With neither `-c` nor a file, the script is read from standard input, as the
//! Oils spec tests feed it. The interpreter is built as `knsh --native-line` builds it (`crates/knsh/src/native_line.rs`:
//! the same state, the same platform services, the same parse options), with one difference: commands are started
//! through [`ProcessCommandSpawner`] directly instead of the supervisor, since the gate measures the interpreter's
//! behaviour, not policy. This entry point exists only in this dev-only tool, never in a shipped binary, so it
//! offers no way around the supervisor (FR-LC-52 to FR-LC-57).
//!
//! Start-up options become a `set` command run before the script (`-e` is `set -e`), so they take effect exactly
//! as the interpreter's own `set` builtin applies them. `--posix`, `-o posix` and the name `sh` start the shell in
//! POSIX mode ([`knsh_interp::posix_mode_requested`]). Interactive and login shells (`-i`, `-l`, `--login`) are not
//! what these suites measure, and are refused with status 2.
//!
//! Known differences of this runner itself (documented on the compatibility page): a script is parsed whole before
//! it runs, so a syntax error late in a file runs none of it (bash runs the lines before it), and a script read
//! from standard input is read to its end first, so the script's own `read` sees nothing of it.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use knsh_interp::{Interpreter, ShellState};
use knsh_platform::macos::{
    RealFs, SystemCollation, SystemDescriptors, SystemLocalTime, SystemProcesses, SystemShellTimes, SystemUserHomes,
    ignored_signals, reraise_default,
};
use knsh_platform::{Descriptors, Fs, ProcessCommandSpawner, Stdio};

/// The `argv[0]` file name under which the binary acts as the native shell.
pub const NATIVE_NAME: &str = "knsh-native";

/// Bash's status for a bad invocation or a syntax error in `-c`.
const USAGE_STATUS: u8 = 2;

/// Where the script comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `-c COMMAND`.
    Command(String),
    /// A script file.
    File(PathBuf),
    /// Standard input.
    Stdin,
}

/// A parsed native-shell command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeArgs {
    /// The `set` arguments the start-up options amount to (`-e`, `-o`, `pipefail`, …), in order.
    pub set: Vec<String>,
    /// Where the script comes from.
    pub source: Source,
    /// `$0`, when given (`-c COMMAND NAME`); otherwise `argv[0]`, or the file name.
    pub name: Option<String>,
    /// `$1`, `$2`, ….
    pub positional: Vec<String>,
}

/// Reads the arguments after `argv[0]`, as bash's `shell.c` reads them for the options the suites use.
///
/// # Errors
///
/// A message for bash's `invalid option` cases: an unknown long option, `-i`, `-l`, `-o` without a name, `-c`
/// without a command, or an argument that is not UTF-8.
pub fn parse_args(args: &[OsString]) -> Result<NativeArgs, String> {
    let mut words = args.iter().map(|arg| {
        arg.to_str()
            .map(str::to_owned)
            .ok_or_else(|| "an argument is not UTF-8".to_owned())
    });
    let mut set = Vec::new();
    let mut command = false;
    let mut rest = Vec::new();
    while let Some(word) = words.next() {
        let word = word?;
        match word.as_str() {
            "--" => break,
            "--posix" => {
                set.push("-o".to_owned());
                set.push("posix".to_owned());
            }
            "--norc" | "--noprofile" | "--noediting" => {}
            "--login" | "--rcfile" | "--init-file" => return Err(format!("{word}: not run by the conformance runner")),
            long if long.starts_with("--") => return Err(format!("{long}: invalid option")),
            "-o" | "+o" => {
                let name = words
                    .next()
                    .ok_or_else(|| format!("{word}: option requires an argument"))??;
                set.push(word.clone());
                set.push(name);
            }
            flags if (flags.starts_with('-') || flags.starts_with('+')) && flags.len() > 1 => {
                let sign = &flags[..1];
                let mut letters = String::new();
                for letter in flags[1..].chars() {
                    match letter {
                        'c' => command = true,
                        's' | 'O' => {}
                        'i' | 'l' => return Err(format!("-{letter}: not run by the conformance runner")),
                        other => letters.push(other),
                    }
                }
                if !letters.is_empty() {
                    set.push(format!("{sign}{letters}"));
                }
            }
            _ => {
                rest.push(word);
                break;
            }
        }
    }
    for word in words {
        rest.push(word?);
    }
    let mut rest = rest.into_iter();
    let (source, name) = if command {
        let line = rest
            .next()
            .ok_or_else(|| "-c: option requires an argument".to_owned())?;
        (Source::Command(line), rest.next())
    } else if let Some(file) = rest.next() {
        let name = file.clone();
        (Source::File(PathBuf::from(file)), Some(name))
    } else {
        (Source::Stdin, None)
    };
    Ok(NativeArgs {
        set,
        source,
        name,
        positional: rest.collect(),
    })
}

/// Writes one message on standard error, ignoring failure.
fn report(message: &str) {
    let _ = std::io::stderr().write_all(message.as_bytes());
}

/// Runs the native shell with `argv0` and `args` and returns its status; ends this process by a signal when the
/// script was ended by one, as bash does.
#[must_use]
pub fn run(argv0: &OsString, args: &[OsString]) -> u8 {
    let parsed = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            report(&format!("{}: {message}\n", argv0.to_string_lossy()));
            return USAGE_STATUS;
        }
    };
    let shell_name = argv0.to_string_lossy().into_owned();
    let (script, name) = match &parsed.source {
        Source::Command(line) => (line.clone(), parsed.name.clone().unwrap_or(shell_name.clone())),
        Source::File(path) => match std::fs::read(path) {
            Ok(bytes) => (String::from_utf8_lossy(&bytes).into_owned(), path.display().to_string()),
            Err(error) => {
                report(&format!("{shell_name}: {}: {}\n", path.display(), plain(&error)));
                return 127;
            }
        },
        Source::Stdin => {
            let mut bytes = Vec::new();
            if let Err(error) = std::io::stdin().read_to_end(&mut bytes) {
                report(&format!("{shell_name}: {error}\n"));
                return USAGE_STATUS;
            }
            (String::from_utf8_lossy(&bytes).into_owned(), shell_name.clone())
        }
    };
    let status = run_script(argv0, args, &parsed, &script, &name);
    std::io::stdout().flush().ok();
    status
}

/// An I/O error as bash words it (`No such file or directory`), without Rust's `(os error 2)`.
fn plain(error: &std::io::Error) -> String {
    let text = error.to_string();
    text.split(" (os error").next().unwrap_or(&text).to_owned()
}

/// Builds the interpreter (as `native_line::run` does, with a direct spawner) and runs `set …` then `script`.
fn run_script(argv0: &OsString, args: &[OsString], parsed: &NativeArgs, script: &str, name: &str) -> u8 {
    let ignored = ignored_signals();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let environment: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let state = match ShellState::new(name.to_owned(), cwd) {
        Ok(state) => state,
        Err(error) => {
            report(&format!("{name}: {error}\n"));
            return USAGE_STATUS;
        }
    };
    let mut state = state
        .with_environment(environment)
        .with_ignored_signals(ignored)
        .with_positional(parsed.positional.clone());
    if knsh_interp::posix_mode_requested(argv0, args) {
        state = state.with_posix_mode();
    }
    let fs: Arc<dyn Fs> = Arc::new(RealFs::new());
    let descriptors: Arc<dyn Descriptors> = Arc::new(SystemDescriptors::new());
    let spawner = Arc::new(ProcessCommandSpawner::new(
        Arc::new(SystemProcesses::new()),
        Stdio::Inherit,
    ));
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
            report(&format!("{name}: {error}\n"));
            return USAGE_STATUS;
        }
    };
    // The parse options of `knsh --native-line` (KNSH-108).
    let options = knsh_bash::ParseOptions::default()
        .with_redirection_variables(true)
        .with_arrays(true)
        .with_coproc(true);
    if !parsed.set.is_empty() {
        let line = format!("set {}", parsed.set.join(" "));
        match knsh_bash::parse_with(&line, options) {
            Ok(prelude) => {
                if let Ok(status) = shell.run(&prelude, &line)
                    && status.code() != 0
                {
                    return USAGE_STATUS;
                }
            }
            Err(error) => {
                report(&format!("{name}: {error}\n"));
                return USAGE_STATUS;
            }
        }
    }
    let tree = match knsh_bash::parse_with(script, options) {
        Ok(tree) => tree,
        Err(error) => {
            report(&format!("{name}: {error}\n"));
            return USAGE_STATUS;
        }
    };
    let status = match shell.run(&tree, script) {
        Ok(status) => status.code(),
        Err(error) => {
            // `$?` was never set: `finish` would report the status from before the error, so the line fails; the
            // `EXIT` trap still runs (as `native_line`).
            report(&format!("{name}: {error}\n"));
            if let Err(error) = shell.finish() {
                report(&format!("{name}: {error}\n"));
            }
            return 1;
        }
    };
    let status = if shell.has_exited() {
        status
    } else {
        match shell.finish() {
            Ok(status) => status.code(),
            Err(error) => {
                report(&format!("{name}: {error}\n"));
                status
            }
        }
    };
    if let Some(signal) = shell.terminating_signal() {
        drop(shell);
        std::io::stdout().flush().ok();
        reraise_default(signal);
    }
    status
}
