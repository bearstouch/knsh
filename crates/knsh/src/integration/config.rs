//! The user's settings for integration mode, in `config.toml` in the engine's configuration directory
//! ([`EnginePaths::config_file`]):
//!
//! - the human recording switch, `[recording] human` (KNSH-021, FR-SES-04, FR-SES-23,
//!   `specs/08-integrations/terminals-and-shells.md#recording-a-human-session`);
//! - the hosted shell, `[shell] hosted` (KNSH-022, NFR-COMPAT-08,
//!   `specs/08-integrations/terminals-and-shells.md#login-shell`).
//!
//! ```toml
//! [recording]
//! human = true
//!
//! [shell]
//! hosted = "bash"     # "zsh", "bash", "native", or an absolute path to a program named zsh or bash
//! banner = true       # the start and end messages of an interactive session; false silences them
//! ```
//!
//! Each setting is read on its own: an unclear one never changes the other. [`read_settings`] reads the file once.
//!
//! ## `[recording] human`
//!
//! Recording is off unless the file says `human = true`. Everything else keeps it off: no file, an unreadable or
//! over-long file, TOML outside the configuration subset, a `[recording]` that is not a table, a `human` that is not a
//! boolean, or an unknown key inside `[recording]` (a typo such as `humans = true` must not look like a choice that was
//! honoured). Those are reported once on stderr by the caller; the shell itself always starts (FR-SES-22). Other
//! top-level tables belong to other settings and are not read here.
//!
//! ## `[shell] hosted`
//!
//! Which shell integration mode hosts. Absent means the default ([`super::shells::choose_hosted_shell`]).
//! `"native"` chooses `knsh`'s own interpreter with its line editor instead (KNSH-107, phase 4): opt-in until the
//! phase 4 gate (KNSH-109) is green, so it is never the default. Anything
//! else that is not one of the accepted values (another type, a relative path, a program not named `zsh` or `bash`, an
//! unknown key inside `[shell]`), and a file that cannot be read, is an invalid choice: `/bin/zsh` starts, with a
//! warning, so that a typo never leaves the user without a shell.

use std::fmt;
use std::path::{Path, PathBuf};

#[cfg(doc)]
use knsh_platform::EnginePaths;
use knsh_platform::Fs;
use knsh_toml::{Table, TomlError, Value};

/// The largest configuration file read. Far above any real one; a bigger file is refused rather than read.
const CONFIG_READ_LIMIT: u64 = 64 * 1024;

/// The table holding recording settings.
const RECORDING_TABLE: &str = "recording";

/// The key that turns human recording on.
const HUMAN_KEY: &str = "human";

/// The table holding shell settings.
const SHELL_TABLE: &str = "shell";

/// The key that names the hosted shell.
const HOSTED_KEY: &str = "hosted";

/// The key that turns the session start and end messages on or off.
const BANNER_KEY: &str = "banner";

/// Why the recording setting could not be read. Recording is then off. Messages name no value from the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The file exists but could not be read, or is larger than the limit.
    Unreadable,
    /// The file is not valid TOML of the configuration subset.
    Toml(TomlError),
    /// `[recording]` is not a table.
    RecordingNotATable,
    /// `recording.human` is not `true` or `false`.
    HumanNotABoolean,
    /// `[recording]` has a key other than `human`.
    UnknownKey,
    /// `[shell]` is not a table.
    ShellNotATable,
    /// `shell.hosted` is not `"zsh"`, `"bash"`, or an absolute path to a program named `zsh` or `bash`.
    InvalidHostedShell,
    /// `[shell]` has a key other than `hosted` and `banner`.
    UnknownShellKey,
    /// `shell.banner` is not `true` or `false`.
    BannerNotABoolean,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable => f.write_str("cannot read the file"),
            Self::Toml(error) => write!(f, "{error}"),
            Self::RecordingNotATable => f.write_str("'recording' must be a table"),
            Self::HumanNotABoolean => f.write_str("'recording.human' must be true or false"),
            Self::UnknownKey => f.write_str("unknown key in [recording]"),
            Self::ShellNotATable => f.write_str("'shell' must be a table"),
            Self::InvalidHostedShell => f.write_str(
                "'shell.hosted' must be \"zsh\", \"bash\", or an absolute path to a program named zsh or bash",
            ),
            Self::UnknownShellKey => f.write_str("unknown key in [shell]"),
            Self::BannerNotABoolean => f.write_str("'shell.banner' must be true or false"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// The shell integration mode hosts, as `[shell] hosted` names it (KNSH-022), or native mode (KNSH-107).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedShell {
    /// zsh, at this path.
    Zsh(PathBuf),
    /// bash, at this path.
    Bash(PathBuf),
    /// No hosted shell: `knsh`'s own interpreter and line editor (`hosted = "native"`, KNSH-107).
    Native,
}

impl HostedShell {
    /// The program to run; `None` for native mode, which runs no other program.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Zsh(path) | Self::Bash(path) => Some(path),
            Self::Native => None,
        }
    }
}

/// Every setting integration mode reads, each with its own outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// `[recording] human`: off unless `Ok(true)`.
    pub recording: Result<bool, ConfigError>,
    /// `[shell] hosted`: `Ok(None)` when not set.
    pub hosted_shell: Result<Option<HostedShell>, ConfigError>,
    /// `[shell] banner`: the session start and end messages; on unless `Ok(false)`. An unclear value keeps them on:
    /// they are only text on a terminal's standard error.
    pub banner: Result<bool, ConfigError>,
}

/// Every setting at its default: recording off (FR-SES-04), no hosted shell chosen.
impl Default for Settings {
    fn default() -> Self {
        Self {
            recording: Ok(false),
            hosted_shell: Ok(None),
            banner: Ok(true),
        }
    }
}

/// Reads the file at `path` once and every setting in it. A missing file means every default. When the file itself
/// cannot be read or parsed, both settings carry that same error.
#[must_use]
pub fn read_settings(fs: &dyn Fs, path: &Path) -> Settings {
    match fs.read(path, CONFIG_READ_LIMIT) {
        Ok(bytes) => parse_settings(&bytes),
        Err(error) if error.is_not_found() => Settings::default(),
        Err(_) => Settings {
            recording: Err(ConfigError::Unreadable),
            hosted_shell: Err(ConfigError::Unreadable),
            banner: Err(ConfigError::Unreadable),
        },
    }
}

/// [`read_settings`] on the file's contents.
#[must_use]
pub fn parse_settings(bytes: &[u8]) -> Settings {
    match knsh_toml::parse(bytes) {
        Ok(root) => Settings {
            recording: recording_setting(&root),
            hosted_shell: hosted_shell_setting(&root),
            banner: banner_setting(&root),
        },
        Err(error) => Settings {
            recording: Err(ConfigError::Toml(error)),
            hosted_shell: Err(ConfigError::Toml(error)),
            banner: Err(ConfigError::Toml(error)),
        },
    }
}

/// `[shell] hosted` in the parsed file.
fn hosted_shell_setting(root: &Table) -> Result<Option<HostedShell>, ConfigError> {
    let Some(shell) = root.get(SHELL_TABLE) else {
        return Ok(None);
    };
    let Value::Table(shell) = shell.value() else {
        return Err(ConfigError::ShellNotATable);
    };
    if shell.iter().any(|(key, _)| key != HOSTED_KEY && key != BANNER_KEY) {
        return Err(ConfigError::UnknownShellKey);
    }
    match shell.get(HOSTED_KEY).map(knsh_toml::Item::value) {
        None => Ok(None),
        Some(Value::String(name)) => parse_hosted_shell(name).map(Some),
        Some(Value::Boolean(_) | Value::Integer(_) | Value::Array(_) | Value::Table(_)) => {
            Err(ConfigError::InvalidHostedShell)
        }
    }
}

/// `[shell] banner` in the parsed file: absent means on.
fn banner_setting(root: &Table) -> Result<bool, ConfigError> {
    let Some(shell) = root.get(SHELL_TABLE) else {
        return Ok(true);
    };
    let Value::Table(shell) = shell.value() else {
        return Err(ConfigError::ShellNotATable);
    };
    match shell.get(BANNER_KEY).map(knsh_toml::Item::value) {
        None => Ok(true),
        Some(Value::Boolean(on)) => Ok(*on),
        Some(Value::String(_) | Value::Integer(_) | Value::Array(_) | Value::Table(_)) => {
            Err(ConfigError::BannerNotABoolean)
        }
    }
}

/// `"zsh"` and `"bash"` are the system shells; an absolute path is accepted when the program is named `zsh` or
/// `bash` (Homebrew's, for example), since only those two can be hosted; `"native"` is `knsh`'s own interpreter.
fn parse_hosted_shell(name: &str) -> Result<HostedShell, ConfigError> {
    match name {
        "zsh" => return Ok(HostedShell::Zsh(PathBuf::from(super::zsh::SYSTEM_ZSH))),
        "bash" => return Ok(HostedShell::Bash(PathBuf::from(super::bash::SYSTEM_BASH))),
        "native" => return Ok(HostedShell::Native),
        _ => {}
    }
    let path = Path::new(name);
    if !path.is_absolute() {
        return Err(ConfigError::InvalidHostedShell);
    }
    match path.file_name().and_then(std::ffi::OsStr::to_str) {
        Some("zsh") => Ok(HostedShell::Zsh(path.to_path_buf())),
        Some("bash") => Ok(HostedShell::Bash(path.to_path_buf())),
        _ => Err(ConfigError::InvalidHostedShell),
    }
}

/// Whether human sessions are recorded, from the file at `path`. A missing file means off.
///
/// # Errors
///
/// [`ConfigError`] when the file exists but does not say clearly; recording is off then.
pub fn human_recording(fs: &dyn Fs, path: &Path) -> Result<bool, ConfigError> {
    match fs.read(path, CONFIG_READ_LIMIT) {
        Ok(bytes) => parse_human_recording(&bytes),
        Err(error) if error.is_not_found() => Ok(false),
        Err(_) => Err(ConfigError::Unreadable),
    }
}

/// [`human_recording`] on the file's contents.
///
/// # Errors
///
/// As [`human_recording`].
pub fn parse_human_recording(bytes: &[u8]) -> Result<bool, ConfigError> {
    let root = knsh_toml::parse(bytes).map_err(ConfigError::Toml)?;
    recording_setting(&root)
}

/// `[recording] human` in the parsed file.
fn recording_setting(root: &Table) -> Result<bool, ConfigError> {
    let Some(recording) = root.get(RECORDING_TABLE) else {
        return Ok(false);
    };
    let Value::Table(recording) = recording.value() else {
        return Err(ConfigError::RecordingNotATable);
    };
    human_key(recording)
}

/// `human` inside the `[recording]` table; absent means off.
fn human_key(recording: &Table) -> Result<bool, ConfigError> {
    if recording.iter().any(|(key, _)| key != HUMAN_KEY) {
        return Err(ConfigError::UnknownKey);
    }
    match recording.get(HUMAN_KEY).map(knsh_toml::Item::value) {
        None => Ok(false),
        Some(Value::Boolean(on)) => Ok(*on),
        Some(Value::String(_) | Value::Integer(_) | Value::Array(_) | Value::Table(_)) => {
            Err(ConfigError::HumanNotABoolean)
        }
    }
}

#[cfg(test)]
mod tests {
    use knsh_platform::EnginePaths;
    use knsh_platform::testing::MemFs;

    use super::*;

    #[test]
    fn only_an_explicit_true_turns_recording_on() {
        assert_eq!(parse_human_recording(b"[recording]\nhuman = true\n"), Ok(true));
        assert_eq!(parse_human_recording(b"recording.human = true\n"), Ok(true));
        assert_eq!(parse_human_recording(b"[recording]\nhuman = false\n"), Ok(false));
        assert_eq!(parse_human_recording(b""), Ok(false));
        assert_eq!(parse_human_recording(b"[recording]\n"), Ok(false));
        // Other settings are not this reader's concern.
        assert_eq!(
            parse_human_recording(b"[other]\nx = 1\n[recording]\nhuman = true\n"),
            Ok(true)
        );
    }

    // Privacy: anything unclear keeps recording off, and is reported.
    #[test]
    fn unclear_settings_are_errors() {
        assert_eq!(
            parse_human_recording(b"[recording]\nhuman = \"yes\"\n"),
            Err(ConfigError::HumanNotABoolean)
        );
        assert_eq!(
            parse_human_recording(b"[recording]\nhumans = true\n"),
            Err(ConfigError::UnknownKey)
        );
        assert_eq!(
            parse_human_recording(b"recording = true\n"),
            Err(ConfigError::RecordingNotATable)
        );
        assert!(matches!(
            parse_human_recording(b"[recording\nhuman = true\n"),
            Err(ConfigError::Toml(_))
        ));
    }

    // KNSH-022: `[shell] hosted` accepts the two system shells by name and absolute paths to programs named zsh or
    // bash; everything else is an invalid choice (which starts /bin/zsh, see `shells`).
    #[test]
    fn banner_setting_is_on_unless_false() {
        let banner = |text: &str| parse_settings(text.as_bytes()).banner;
        assert_eq!(banner(""), Ok(true));
        assert_eq!(banner("[shell]\nbanner = true\n"), Ok(true));
        assert_eq!(banner("[shell]\nbanner = false\n"), Ok(false));
        assert_eq!(
            banner("[shell]\nbanner = \"no\"\n"),
            Err(ConfigError::BannerNotABoolean)
        );
        // The key does not disturb the hosted shell choice.
        let settings = parse_settings(b"[shell]\nhosted = \"native\"\nbanner = false\n");
        assert_eq!(settings.hosted_shell, Ok(Some(HostedShell::Native)));
    }

    #[test]
    fn hosted_shell_setting_accepts_only_zsh_or_bash() {
        let hosted = |text: &str| parse_settings(text.as_bytes()).hosted_shell;
        assert_eq!(hosted(""), Ok(None));
        assert_eq!(hosted("[shell]\n"), Ok(None));
        assert_eq!(
            hosted("[shell]\nhosted = \"zsh\"\n"),
            Ok(Some(HostedShell::Zsh(PathBuf::from("/bin/zsh"))))
        );
        assert_eq!(
            hosted("shell.hosted = \"bash\"\n"),
            Ok(Some(HostedShell::Bash(PathBuf::from("/bin/bash"))))
        );
        assert_eq!(
            hosted("[shell]\nhosted = \"/opt/homebrew/bin/bash\"\n"),
            Ok(Some(HostedShell::Bash(PathBuf::from("/opt/homebrew/bin/bash"))))
        );
        for invalid in [
            "[shell]\nhosted = \"fish\"\n",
            "[shell]\nhosted = \"/bin/sh\"\n",
            "[shell]\nhosted = \"bin/bash\"\n",
            "[shell]\nhosted = \"\"\n",
            "[shell]\nhosted = true\n",
        ] {
            assert_eq!(hosted(invalid), Err(ConfigError::InvalidHostedShell), "{invalid}");
        }
        // KNSH-107: native mode is chosen by name only.
        assert_eq!(hosted("[shell]\nhosted = \"native\"\n"), Ok(Some(HostedShell::Native)));
        assert_eq!(
            hosted("[shell]\nhosted = \"/bin/native\"\n"),
            Err(ConfigError::InvalidHostedShell)
        );
        assert_eq!(hosted("[shell]\nhost = \"zsh\"\n"), Err(ConfigError::UnknownShellKey));
        assert_eq!(hosted("shell = \"zsh\"\n"), Err(ConfigError::ShellNotATable));
    }

    // One unclear setting never changes the other; an unreadable file affects both.
    #[test]
    fn settings_are_independent() {
        let settings = parse_settings(b"[recording]\nhuman = true\n[shell]\nhosted = \"fish\"\n");
        assert_eq!(settings.recording, Ok(true));
        assert_eq!(settings.hosted_shell, Err(ConfigError::InvalidHostedShell));
        let settings = parse_settings(b"[recording]\nhuman = 1\n[shell]\nhosted = \"bash\"\n");
        assert_eq!(settings.recording, Err(ConfigError::HumanNotABoolean));
        assert!(settings.hosted_shell.is_ok());
        let settings = parse_settings(b"[shell\n");
        assert!(matches!(settings.recording, Err(ConfigError::Toml(_))));
        assert!(matches!(settings.hosted_shell, Err(ConfigError::Toml(_))));
    }

    // FR-SES-04: off by default, so no file means off.
    #[test]
    fn missing_file_means_off() {
        let fs = MemFs::with_uid(501);
        fs.add_dir_all(Path::new("/Users/u")).expect("home");
        let paths = EnginePaths::for_home(Path::new("/Users/u")).expect("paths");
        assert_eq!(human_recording(&fs, &paths.config_file()), Ok(false));
        fs.add_dir_all(paths.config_dir()).expect("config dir");
        fs.atomic_replace(&paths.config_file(), b"[recording]\nhuman = true\n", 0o600)
            .expect("write");
        assert_eq!(human_recording(&fs, &paths.config_file()), Ok(true));
    }
}
