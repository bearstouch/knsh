//! Oracles: shells that say whether they accept a command line.
//!
//! The real oracle is bash run as `bash -n -c -- <line>`: `-n` reads the line without executing anything, `-c`
//! reads it the way agent lines are run (`bash -c`, NFR-COMPAT-04), and `--` keeps a line that starts with `-` from
//! being taken for options. The environment is cleared (no `BASH_ENV`, no locale surprises), standard input,
//! output and error are closed or discarded (corpus lines are never echoed into CI logs), and every run has a
//! deadline.
//!
//! [`Role::Gate`] oracles (bash) decide the gates. [`Role::Reference`] oracles (brush or another shell, "as an
//! oracle where helpful") are reported only: their parsers are not the contract.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::DiffError;

/// The `bash` every run must compare with: macOS `/bin/bash`, bash 3.2, which agent lines use by default
/// (NFR-COMPAT-04).
pub const SYSTEM_BASH: &str = "/bin/bash";

/// Where a newer bash (4+, normally 5.x) is looked for when no `--bash` is given: Homebrew on Apple silicon and on
/// Intel. Used when present ("and 5.x when available").
pub const MODERN_BASH_CANDIDATES: [&str; 2] = ["/opt/homebrew/bin/bash", "/usr/local/bin/bash"];

/// How long one shell run may take. `bash -n` on a corpus line takes milliseconds; a run that takes longer is
/// stuck, and the harness fails rather than waits.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(10);

/// The exit status `bash -n` gives for a syntax error.
const BASH_SYNTAX_ERROR: i32 = 2;

/// Whether an oracle's verdicts decide the gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A bash the exit criterion is measured against; a disagreement fails the run.
    Gate,
    /// Another shell used as a reference (for example brush); disagreements are listed but never fail the run.
    Reference,
}

/// What the report records about an oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleInfo {
    /// The shell's path.
    pub path: PathBuf,
    /// The first line of its `--version` output, for example `GNU bash, version 3.2.57(1)-release (…)`.
    pub version: String,
    /// The major bash version, when the version line names one (`3` for bash 3.2).
    pub major: Option<u32>,
    /// Whether its verdicts gate the run.
    pub role: Role,
}

impl OracleInfo {
    /// Whether this is bash 3.x, which lacks the constructs corpus lines tagged `b32-missing` use (NFR-COMPAT-05).
    #[must_use]
    pub fn is_bash3(&self) -> bool {
        self.major == Some(3)
    }
}

/// A shell that says whether it accepts a command line.
pub trait Oracle {
    /// What the report records about it.
    fn info(&self) -> &OracleInfo;

    /// Whether the shell accepts `command` as syntactically valid.
    ///
    /// # Errors
    ///
    /// [`DiffError::Oracle`] when no verdict could be had: the shell did not start, timed out, was killed by a
    /// signal, or exited with a status that is neither accept nor reject.
    fn accepts(&self, command: &str) -> Result<bool, DiffError>;
}

/// A shell run as a separate process with `-n -c`.
#[derive(Debug, Clone)]
pub struct ShellOracle {
    info: OracleInfo,
}

impl ShellOracle {
    /// Starts `path --version` to learn the shell's version, and returns an oracle for it.
    ///
    /// # Errors
    ///
    /// [`DiffError::Oracle`] when the shell cannot be run or prints no version.
    pub fn probe(path: &Path, role: Role) -> Result<Self, DiffError> {
        let mut child = shell_command(path)
            .arg("--version")
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| oracle_error(path, format!("cannot start: {e}")))?;
        let status = wait_with_deadline(&mut child, path)?;
        let mut output = String::new();
        // `--version` output is a few lines, well within a pipe buffer, so reading after the exit cannot deadlock.
        if let Some(stdout) = child.stdout.take() {
            stdout
                .take(64 * 1024)
                .read_to_string(&mut output)
                .map_err(|e| oracle_error(path, format!("cannot read --version output: {e}")))?;
        }
        let version = output.lines().next().unwrap_or_default().trim().to_owned();
        if !status.success() || version.is_empty() {
            return Err(oracle_error(path, "`--version` gave no version".into()));
        }
        Ok(Self {
            info: OracleInfo {
                path: path.to_owned(),
                major: bash_major(&version),
                version,
                role,
            },
        })
    }
}

impl Oracle for ShellOracle {
    fn info(&self) -> &OracleInfo {
        &self.info
    }

    fn accepts(&self, command: &str) -> Result<bool, DiffError> {
        let path = &self.info.path;
        let mut child = shell_command(path)
            .args(["-n", "-c", "--", command])
            .stdout(Stdio::null())
            .spawn()
            .map_err(|e| oracle_error(path, format!("cannot start: {e}")))?;
        let status = wait_with_deadline(&mut child, path)?;
        match (status.code(), self.info.role) {
            (Some(0), _) => Ok(true),
            // Bash's syntax-error status; a reference shell may use another, so any exit is a verdict for it.
            (Some(BASH_SYNTAX_ERROR), _) | (Some(_), Role::Reference) => Ok(false),
            // For bash, any other status (or a signal) is not a parse verdict: fail rather than guess.
            (Some(code), Role::Gate) => Err(oracle_error(path, format!("unexpected exit status {code}"))),
            (None, _) => Err(oracle_error(path, "killed by a signal".into())),
        }
    }
}

/// The bashes to compare with when none is named: `/bin/bash` always, then every newer-bash candidate that exists.
#[must_use]
pub fn default_bashes() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(SYSTEM_BASH)];
    paths.extend(
        MODERN_BASH_CANDIDATES
            .iter()
            .map(PathBuf::from)
            .filter(|path| path.is_file()),
    );
    paths
}

/// The major version from a bash version line (`GNU bash, version 5.2.37(1)-release …` gives `5`), or `None` when
/// the line does not name a bash version (a reference shell).
#[must_use]
pub fn bash_major(version: &str) -> Option<u32> {
    let rest = version.split_once("bash, version ")?.1;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// A command for `path` with a cleared environment and no input. `PATH` is set only so a shell that needs it for
/// startup finds the system tools; `-n` never runs anything. `LC_ALL=C` keeps the reading locale-independent.
fn shell_command(path: &Path) -> Command {
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// Waits for `child` up to [`RUN_TIMEOUT`], killing and reaping it on timeout so no process is left behind.
fn wait_with_deadline(child: &mut Child, path: &Path) -> Result<ExitStatus, DiffError> {
    let start = Instant::now();
    let failure = loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if start.elapsed() < RUN_TIMEOUT => thread::sleep(Duration::from_millis(1)),
            Ok(None) => break format!("no verdict within {RUN_TIMEOUT:?}"),
            Err(e) => break format!("cannot wait: {e}"),
        }
    };
    // Best effort: the child may exit between the check and the kill; either way it is reaped.
    let _ = child.kill();
    let _ = child.wait();
    Err(oracle_error(path, failure))
}

fn oracle_error(path: &Path, message: String) -> DiffError {
    DiffError::Oracle {
        path: path.to_owned(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_bash_major_version() {
        assert_eq!(
            bash_major("GNU bash, version 3.2.57(1)-release (arm64-apple-darwin25)"),
            Some(3)
        );
        assert_eq!(
            bash_major("GNU bash, version 5.2.37(1)-release (aarch64-apple-darwin24.0.0)"),
            Some(5)
        );
        assert_eq!(bash_major("brush 0.2.18"), None);
    }

    // KNSH-034: the real bash gives accept for valid lines and reject for syntax errors, and never runs the line.
    #[test]
    fn system_bash_accepts_and_rejects_without_running() {
        let path = Path::new(SYSTEM_BASH);
        if !path.is_file() {
            return; // Not every host has /bin/bash; the corpus gate test reports that case.
        }
        let bash = ShellOracle::probe(path, Role::Gate).unwrap();
        assert!(bash.info().version.contains("bash"));
        assert!(bash.accepts("ls -la | wc -l").unwrap());
        assert!(!bash.accepts("if true; then").unwrap());
        assert!(!bash.accepts("echo $(").unwrap());
        // A leading `-` is the command, not an option, thanks to `--`.
        assert!(bash.accepts("-x foo").unwrap());
        // `-n` reads only: the redirection would create the file if the line ran.
        let marker = std::env::temp_dir().join(format!("knsh-difftest-ran-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        assert!(bash.accepts(&format!("touch '{}'", marker.display())).unwrap());
        assert!(!marker.exists());
    }

    #[test]
    fn missing_shell_is_an_error_not_a_verdict() {
        let missing = std::env::temp_dir().join("knsh-difftest-no-such-shell");
        assert!(matches!(
            ShellOracle::probe(&missing, Role::Gate),
            Err(DiffError::Oracle { .. })
        ));
    }
}
