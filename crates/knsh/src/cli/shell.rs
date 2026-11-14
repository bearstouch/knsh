//! `knsh shell install` (KNSH-022, NFR-COMPAT-08, `specs/06-api/cli.md#login-shell`): adds `knsh` to `/etc/shells`
//! so that `chsh -s` accepts it as the login shell.
//!
//! `/etc/shells` belongs to root and lists the shells every user may choose, so it is never changed silently: the
//! user is shown the exact line and must answer yes on a terminal, and the change is then made by `sudo`, which asks
//! for their password itself. Without a terminal to ask on, nothing is changed. Nothing else is touched: `chsh` stays
//! the user's own step.
//!
//! The effects (reading the file, asking, appending as root) go through [`ShellsHost`], so the flow is tested with a
//! fake; [`SystemShellsHost`] is the real one.

use std::fmt;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use knsh_json::{Object, Value};

use crate::integration::shells::{ETC_SHELLS, ShellsError, entry_to_append, lists_shell};

/// Said next to the `chsh` line until `knsh -c` exists: a login shell is also what `ssh host cmd`, `scp` and apps that
/// read the login environment run with `-c`, and `knsh` cannot run those lines yet (`specs/06-api/cli.md`).
const C_LIMIT: &str = "Note: 'knsh -c' is not implemented yet, so commands run through the login shell (ssh host cmd, \
                       scp, rsync, apps that read the login environment) fail while knsh is the login shell.\n";

/// The largest `/etc/shells` read; far above any real one.
const ETC_SHELLS_READ_LIMIT: u64 = 64 * 1024;

/// The effects `knsh shell install` needs.
pub trait ShellsHost {
    /// The current contents of `/etc/shells`; empty when the file does not exist.
    ///
    /// # Errors
    ///
    /// The I/O error when it exists but cannot be read.
    fn read_etc_shells(&mut self) -> io::Result<Vec<u8>>;

    /// Asks `question` and returns `true` only for an explicit yes.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::Unsupported`] when there is no terminal to ask on; any I/O error while asking.
    fn confirm(&mut self, question: &str) -> io::Result<bool>;

    /// Appends `entry` to `/etc/shells` with the privileges needed.
    ///
    /// # Errors
    ///
    /// The reason it was not appended.
    fn append_as_root(&mut self, entry: &[u8]) -> Result<(), String>;
}

/// What `knsh shell install` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// `/etc/shells` already lists `knsh`; nothing was asked or changed.
    AlreadyListed,
    /// The user said yes and the line was appended.
    Added,
    /// The user said no; nothing was changed.
    Declined,
}

/// Why `knsh shell install` failed. `/etc/shells` is unchanged in every case.
#[derive(Debug)]
pub enum ShellInstallError {
    /// `/etc/shells` could not be read.
    Read(io::Error),
    /// The path of `knsh` cannot be written to `/etc/shells`.
    Path(ShellsError),
    /// There is no terminal to ask on, or asking failed: the file is never changed without an answer.
    Confirm(io::Error),
    /// Appending failed (for example `sudo` was refused).
    Append(String),
}

impl fmt::Display for ShellInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(f, "cannot read {ETC_SHELLS}: {error}"),
            Self::Path(error) => write!(f, "cannot add this knsh to {ETC_SHELLS}: {error}"),
            Self::Confirm(error) if error.kind() == io::ErrorKind::Unsupported => write!(
                f,
                "{ETC_SHELLS} is changed only after a yes on a terminal; run 'knsh shell install' in a terminal"
            ),
            Self::Confirm(error) => write!(f, "cannot ask for confirmation: {error}"),
            Self::Append(reason) => write!(f, "{ETC_SHELLS} was not changed: {reason}"),
        }
    }
}

impl std::error::Error for ShellInstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) | Self::Confirm(error) => Some(error),
            Self::Path(error) => Some(error),
            Self::Append(_) => None,
        }
    }
}

/// Adds `knsh` (the absolute, resolved path of the running binary) to `/etc/shells`, after an explicit yes.
///
/// Already listed: nothing is asked. Otherwise the question names the exact line; anything but yes changes nothing.
///
/// # Errors
///
/// [`ShellInstallError`]; `/etc/shells` is unchanged then.
pub fn install(host: &mut dyn ShellsHost, knsh: &Path) -> Result<InstallOutcome, ShellInstallError> {
    let contents = host.read_etc_shells().map_err(ShellInstallError::Read)?;
    if lists_shell(&contents, knsh) {
        return Ok(InstallOutcome::AlreadyListed);
    }
    // Checked before asking, so the user is never asked for a change that cannot be made.
    let entry = entry_to_append(&contents, knsh).map_err(ShellInstallError::Path)?;
    let question = format!(
        "Add {} to {ETC_SHELLS} so that 'chsh' accepts it as a login shell? This needs administrator rights (sudo). [y/N] ",
        knsh.display()
    );
    if !host.confirm(&question).map_err(ShellInstallError::Confirm)? {
        return Ok(InstallOutcome::Declined);
    }
    host.append_as_root(&entry).map_err(ShellInstallError::Append)?;
    Ok(InstallOutcome::Added)
}

/// The text `knsh shell install` prints for `outcome` (a JSON object with `--json`).
#[must_use]
pub fn report(outcome: InstallOutcome, knsh: &Path, json: bool) -> String {
    if json {
        let listed = matches!(outcome, InstallOutcome::AlreadyListed | InstallOutcome::Added);
        let fields = [
            ("shell", Value::from(knsh.display().to_string())),
            ("listed", Value::from(listed)),
            ("added", Value::from(outcome == InstallOutcome::Added)),
        ];
        // The keys are distinct literals, so building it cannot fail; if it ever did, an empty object is printed.
        let mut object = Object::new();
        for (key, value) in fields {
            if object.insert(key, value).is_err() {
                object = Object::new();
                break;
            }
        }
        let mut text = knsh_json::write(&Value::from(object)).unwrap_or_else(|_| "{}".to_owned());
        text.push('\n');
        return text;
    }
    let shell = knsh.display();
    match outcome {
        InstallOutcome::AlreadyListed => {
            format!("{shell} is already in {ETC_SHELLS}.\nTo make it your login shell: chsh -s {shell}\n{C_LIMIT}")
        }
        InstallOutcome::Added => {
            format!("Added {shell} to {ETC_SHELLS}.\nTo make it your login shell: chsh -s {shell}\n{C_LIMIT}")
        }
        InstallOutcome::Declined => format!("{ETC_SHELLS} was not changed.\n"),
    }
}

/// The real effects: the file itself, the terminal on standard input and standard error, and `sudo tee -a`.
#[derive(Debug, Default)]
pub struct SystemShellsHost;

impl ShellsHost for SystemShellsHost {
    fn read_etc_shells(&mut self) -> io::Result<Vec<u8>> {
        use std::io::Read;

        match std::fs::File::open(ETC_SHELLS) {
            Ok(file) => {
                let mut contents = Vec::new();
                file.take(ETC_SHELLS_READ_LIMIT).read_to_end(&mut contents)?;
                Ok(contents)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    fn confirm(&mut self, question: &str) -> io::Result<bool> {
        // Only a person at a terminal can say yes: piped input could be anything.
        if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        let mut stderr = io::stderr();
        stderr.write_all(question.as_bytes())?;
        stderr.flush()?;
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer)?;
        Ok(is_yes(&answer))
    }

    fn append_as_root(&mut self, entry: &[u8]) -> Result<(), String> {
        // Absolute paths: the user's PATH never chooses what runs as root. `tee -a` appends, so the rest of the file
        // is never rewritten; sudo asks for the password on the terminal itself.
        let mut child = Command::new("/usr/bin/sudo")
            .args(["/usr/bin/tee", "-a", ETC_SHELLS])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .map_err(|error| format!("cannot run sudo: {error}"))?;
        let written = child
            .stdin
            .take()
            .ok_or_else(|| "cannot write to sudo".to_owned())
            .and_then(|mut stdin| stdin.write_all(entry).map_err(|error| error.to_string()));
        let status = child.wait().map_err(|error| error.to_string())?;
        written?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("sudo tee exited with {status}"))
        }
    }
}

/// Whether `answer` is an explicit yes: `y` or `yes`, in any case, with surrounding blanks.
fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A fake host: the file's contents, the answer given, and what was appended.
    struct Fake {
        contents: Vec<u8>,
        answer: io::Result<bool>,
        asked: Vec<String>,
        appended: Vec<Vec<u8>>,
        append_fails: bool,
    }

    impl Fake {
        fn new(contents: &[u8], answer: io::Result<bool>) -> Self {
            Self {
                contents: contents.to_vec(),
                answer,
                asked: Vec::new(),
                appended: Vec::new(),
                append_fails: false,
            }
        }
    }

    impl ShellsHost for Fake {
        fn read_etc_shells(&mut self) -> io::Result<Vec<u8>> {
            Ok(self.contents.clone())
        }

        fn confirm(&mut self, question: &str) -> io::Result<bool> {
            self.asked.push(question.to_owned());
            match &self.answer {
                Ok(answer) => Ok(*answer),
                Err(error) => Err(io::Error::from(error.kind())),
            }
        }

        fn append_as_root(&mut self, entry: &[u8]) -> Result<(), String> {
            if self.append_fails {
                return Err("refused".to_owned());
            }
            self.appended.push(entry.to_vec());
            Ok(())
        }
    }

    fn knsh() -> PathBuf {
        PathBuf::from("/usr/local/bin/knsh")
    }

    // KNSH-022 (NFR-COMPAT-08): /etc/shells changes only after an explicit yes, and then by exactly one line.
    #[test]
    fn etc_shells_changes_only_after_a_yes() {
        let mut host = Fake::new(b"/bin/zsh\n", Ok(true));
        assert!(matches!(install(&mut host, &knsh()), Ok(InstallOutcome::Added)));
        assert_eq!(host.asked.len(), 1);
        assert!(host.asked[0].contains("/usr/local/bin/knsh"));
        assert_eq!(host.appended, [b"/usr/local/bin/knsh\n".to_vec()]);

        let mut host = Fake::new(b"/bin/zsh\n", Ok(false));
        assert!(matches!(install(&mut host, &knsh()), Ok(InstallOutcome::Declined)));
        assert_eq!(host.appended.len(), 0);

        // No terminal to ask on: an error, and nothing changed.
        let mut host = Fake::new(b"/bin/zsh\n", Err(io::Error::from(io::ErrorKind::Unsupported)));
        let error = install(&mut host, &knsh()).expect_err("no terminal");
        assert!(error.to_string().contains("only after a yes on a terminal"), "{error}");
        assert_eq!(host.appended.len(), 0);
    }

    #[test]
    fn listed_shell_is_left_alone_and_nothing_is_asked() {
        let mut host = Fake::new(b"/bin/zsh\n/usr/local/bin/knsh\n", Ok(true));
        assert!(matches!(install(&mut host, &knsh()), Ok(InstallOutcome::AlreadyListed)));
        assert_eq!(host.asked.len(), 0);
        assert_eq!(host.appended.len(), 0);
    }

    // A path /etc/shells cannot hold is refused before the user is asked anything.
    #[test]
    fn unrepresentable_path_is_refused_before_asking() {
        let mut host = Fake::new(b"", Ok(true));
        let error = install(&mut host, Path::new("/Users/a b/knsh")).expect_err("space");
        assert!(matches!(error, ShellInstallError::Path(ShellsError::Unrepresentable)));
        assert_eq!(host.asked.len(), 0);
    }

    #[test]
    fn failed_append_is_reported() {
        let mut host = Fake::new(b"", Ok(true));
        host.append_fails = true;
        let error = install(&mut host, &knsh()).expect_err("refused");
        assert!(matches!(error, ShellInstallError::Append(_)));
    }

    #[test]
    fn only_y_or_yes_is_a_yes() {
        for yes in ["y\n", "Y\n", "yes\n", " YES \n"] {
            assert!(is_yes(yes), "{yes:?}");
        }
        for no in ["\n", "n\n", "no\n", "yess\n", "", "sure\n"] {
            assert!(!is_yes(no), "{no:?}");
        }
    }

    #[test]
    fn report_says_what_happened() {
        let added = report(InstallOutcome::Added, &knsh(), false);
        assert!(added.contains("Added /usr/local/bin/knsh") && added.contains("chsh -s /usr/local/bin/knsh"));
        // Until `knsh -c` exists, the user is told what a login shell without it breaks.
        assert!(added.contains("'knsh -c' is not implemented yet"));
        assert!(report(InstallOutcome::Declined, &knsh(), false).contains("not changed"));
        let json = report(InstallOutcome::AlreadyListed, &knsh(), true);
        assert!(
            json.contains("\"listed\":true") && json.contains("\"added\":false"),
            "{json}"
        );
    }
}
