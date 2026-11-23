//! Login shell support (KNSH-022, NFR-COMPAT-08, `specs/08-integrations/terminals-and-shells.md#login-shell`): which
//! shell integration mode hosts, and the `/etc/shells` entry that lets `chsh` make `knsh` the login shell.
//!
//! When `knsh` is the login shell, `$SHELL` names `knsh` itself, so the hosted shell comes from the user's settings
//! (`[shell] hosted`, [`super::config`]). Every way of getting it wrong ends in `/bin/zsh` with a warning, never in
//! no shell at all ([`choose_hosted_shell`]).
//!
//! `/etc/shells` is only ever changed by `knsh shell install`, after the user has said yes; this module holds the pure
//! part: whether the file lists a shell, and the exact bytes to append.

use std::ffi::OsStr;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::bash;
use super::config::{ConfigError, HostedShell};
use super::zsh::SYSTEM_ZSH;

/// The list of shells `chsh` accepts for a user.
pub const ETC_SHELLS: &str = "/etc/shells";

/// The shell to host and, when it is not the one asked for, why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    /// The shell to host.
    pub shell: HostedShell,
    /// Set when `/bin/zsh` replaces a choice that cannot be used; the caller prints it once on stderr.
    pub warning: Option<String>,
}

/// The shell to host: `force_native` (`--native`, FR-SES-26) first, else the `[shell] hosted` setting, then `$SHELL` (`login_shell`), then zsh.
///
/// - A valid setting naming a program that `usable` accepts: that shell.
/// - No setting: the bash `$SHELL` names, when it is one and `usable` accepts it (KNSH-020), otherwise `/bin/zsh`.
///   When `knsh` is the login shell, `$SHELL` names `knsh`, so this is zsh by default.
/// - Anything else (an invalid setting, an unreadable file, a program that cannot run or that is `knsh` itself):
///   `/bin/zsh` with a warning, so the user is never left without a shell.
///
/// `usable` says whether a path can be started as the hosted shell; the caller checks that it is an executable file
/// and not `knsh` itself.
#[must_use]
pub fn choose_hosted_shell(
    setting: &Result<Option<HostedShell>, ConfigError>,
    login_shell: Option<&OsStr>,
    usable: &dyn Fn(&Path) -> bool,
    force_native: bool,
) -> Choice {
    // FR-SES-26: `--native` beats every setting, so an unreadable or invalid file cannot get in its way.
    if force_native {
        return Choice {
            shell: HostedShell::Native,
            warning: None,
        };
    }
    let system_zsh = || HostedShell::Zsh(PathBuf::from(SYSTEM_ZSH));
    let fallback = |warning: String| Choice {
        shell: system_zsh(),
        warning: Some(warning),
    };
    match setting {
        // Native mode runs no other program: always usable (KNSH-107).
        Ok(Some(shell)) if shell.path().is_none_or(usable) => Choice {
            shell: shell.clone(),
            warning: None,
        },
        Ok(Some(shell)) => fallback(format!(
            "the hosted shell {} cannot be run; starting {SYSTEM_ZSH}",
            shell.path().map_or_else(String::new, |path| path.display().to_string())
        )),
        Ok(None) => match bash::user_bash(login_shell) {
            Some(path) if usable(path) => Choice {
                shell: HostedShell::Bash(path.to_path_buf()),
                warning: None,
            },
            Some(path) => fallback(format!(
                "{} (from $SHELL) cannot be run; starting {SYSTEM_ZSH}",
                path.display()
            )),
            // No bash in $SHELL is the ordinary zsh default, not a failed choice: no warning.
            None => Choice {
                shell: system_zsh(),
                warning: None,
            },
        },
        Err(error) => fallback(format!("{error}; starting {SYSTEM_ZSH}")),
    }
}

/// Why a path cannot be written to `/etc/shells`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellsError {
    /// The path is relative.
    NotAbsolute,
    /// The path holds whitespace, a control character or `#`, which `/etc/shells` cannot represent: the file has one
    /// path per line, and `#` starts a comment.
    Unrepresentable,
}

impl fmt::Display for ShellsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute => f.write_str("the path is not absolute"),
            Self::Unrepresentable => f.write_str("the path holds whitespace, a control character or '#'"),
        }
    }
}

impl std::error::Error for ShellsError {}

/// Whether `contents` (an `/etc/shells` file) lists `shell`: a line that, without surrounding blanks and without a
/// comment, is exactly the path.
#[must_use]
pub fn lists_shell(contents: &[u8], shell: &Path) -> bool {
    let wanted = shell.as_os_str().as_bytes();
    contents.split(|&byte| byte == b'\n').any(|line| {
        let line = line.split(|&byte| byte == b'#').next().unwrap_or_default();
        line.trim_ascii() == wanted
    })
}

/// The bytes to append to `contents` so that it lists `shell`: the path and a line feed, preceded by a line feed
/// when the file does not end with one (so the path never joins the last line).
///
/// # Errors
///
/// [`ShellsError`] when `shell` is not a path `/etc/shells` can hold.
pub fn entry_to_append(contents: &[u8], shell: &Path) -> Result<Vec<u8>, ShellsError> {
    if !shell.is_absolute() {
        return Err(ShellsError::NotAbsolute);
    }
    let path = shell.as_os_str().as_bytes();
    if path
        .iter()
        .any(|&byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'#')
    {
        return Err(ShellsError::Unrepresentable);
    }
    let mut entry = Vec::with_capacity(path.len() + 2);
    if contents.last().is_some_and(|&last| last != b'\n') {
        entry.push(b'\n');
    }
    entry.extend_from_slice(path);
    entry.push(b'\n');
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zsh() -> HostedShell {
        HostedShell::Zsh(PathBuf::from(SYSTEM_ZSH))
    }

    // KNSH-022 unit test (NFR-COMPAT-08): an invalid hosted shell, in any form, never locks the user out: /bin/zsh
    // starts, with a warning.
    #[test]
    fn invalid_hosted_shell_falls_back_to_zsh() {
        let any = |_: &Path| true;
        let none = |_: &Path| false;
        // An invalid setting, or a file that cannot be read.
        for error in [
            ConfigError::InvalidHostedShell,
            ConfigError::UnknownShellKey,
            ConfigError::Unreadable,
        ] {
            let choice = choose_hosted_shell(&Err(error), Some(OsStr::new("/bin/bash")), &any, false);
            assert_eq!(choice.shell, zsh());
            assert!(
                choice
                    .warning
                    .as_deref()
                    .is_some_and(|w| w.ends_with("starting /bin/zsh"))
            );
        }
        // A valid setting whose program cannot run (missing, not executable, or knsh itself).
        let missing = HostedShell::Bash(PathBuf::from("/opt/nowhere/bash"));
        let choice = choose_hosted_shell(&Ok(Some(missing)), None, &none, false);
        assert_eq!(choice.shell, zsh());
        assert!(choice.warning.is_some_and(|w| w.contains("/opt/nowhere/bash")));
    }

    #[test]
    fn hosted_shell_follows_the_setting_then_shell_then_zsh() {
        let any = |_: &Path| true;
        let bash5 = HostedShell::Bash(PathBuf::from("/opt/homebrew/bin/bash"));
        let choice = choose_hosted_shell(&Ok(Some(bash5.clone())), Some(OsStr::new("/bin/zsh")), &any, false);
        assert_eq!(
            choice,
            Choice {
                shell: bash5,
                warning: None
            }
        );
        // The setting wins over $SHELL.
        let choice = choose_hosted_shell(&Ok(Some(zsh())), Some(OsStr::new("/bin/bash")), &any, false);
        assert_eq!(choice.shell, zsh());
        // No setting: $SHELL's bash (KNSH-020) ...
        let choice = choose_hosted_shell(&Ok(None), Some(OsStr::new("/bin/bash")), &any, false);
        assert_eq!(choice.shell, HostedShell::Bash(PathBuf::from("/bin/bash")));
        // ... and zsh otherwise, which is the case when knsh is the login shell ($SHELL names knsh).
        for shell in [Some("/usr/local/bin/knsh"), Some("/bin/zsh"), None] {
            let choice = choose_hosted_shell(&Ok(None), shell.map(OsStr::new), &any, false);
            assert_eq!(
                choice,
                Choice {
                    shell: zsh(),
                    warning: None
                },
                "{shell:?}"
            );
        }
        // A $SHELL bash that cannot run (or is knsh itself under that name): zsh, with a warning.
        let choice = choose_hosted_shell(&Ok(None), Some(OsStr::new("/bin/bash")), &|_: &Path| false, false);
        assert_eq!(choice.shell, zsh());
        assert!(choice.warning.is_some());
    }

    #[test]
    fn etc_shells_listing_ignores_blanks_and_comments() {
        let knsh = Path::new("/usr/local/bin/knsh");
        let file = b"# List of acceptable shells\n/bin/bash\n/bin/zsh\n";
        assert!(!lists_shell(file, knsh));
        assert!(lists_shell(b"/bin/zsh\n  /usr/local/bin/knsh  # ours\n", knsh));
        assert!(lists_shell(b"/usr/local/bin/knsh", knsh));
        assert!(!lists_shell(b"# /usr/local/bin/knsh\n", knsh));
        assert!(!lists_shell(b"/usr/local/bin/knsh2\n", knsh));
    }

    #[test]
    fn etc_shells_entry_is_one_line() {
        let knsh = Path::new("/usr/local/bin/knsh");
        assert_eq!(
            entry_to_append(b"/bin/zsh\n", knsh),
            Ok(b"/usr/local/bin/knsh\n".to_vec())
        );
        assert_eq!(entry_to_append(b"", knsh), Ok(b"/usr/local/bin/knsh\n".to_vec()));
        // Never joined to an unterminated last line.
        assert_eq!(
            entry_to_append(b"/bin/zsh", knsh),
            Ok(b"\n/usr/local/bin/knsh\n".to_vec())
        );
        assert_eq!(entry_to_append(b"", Path::new("knsh")), Err(ShellsError::NotAbsolute));
        for bad in ["/a b/knsh", "/a\nb/knsh", "/a#b/knsh", "/a\tb/knsh"] {
            assert_eq!(
                entry_to_append(b"", Path::new(bad)),
                Err(ShellsError::Unrepresentable),
                "{bad:?}"
            );
        }
    }

    // KNSH-107: native mode needs no program, so it is always usable.
    // FR-SES-26: `--native` beats the setting, whatever it holds, and never warns.
    #[test]
    fn native_flag_overrides_the_hosted_setting() {
        let any = |_: &Path| true;
        for setting in [Ok(Some(zsh())), Ok(None), Err(ConfigError::InvalidHostedShell)] {
            let choice = choose_hosted_shell(&setting, Some(OsStr::new("/bin/bash")), &any, true);
            assert_eq!(choice.shell, HostedShell::Native);
            assert_eq!(choice.warning, None);
        }
    }

    #[test]
    fn native_mode_is_always_usable() {
        let choice = choose_hosted_shell(&Ok(Some(HostedShell::Native)), None, &|_| false, false);
        assert_eq!(choice.shell, HostedShell::Native);
        assert_eq!(choice.warning, None);
    }
}
