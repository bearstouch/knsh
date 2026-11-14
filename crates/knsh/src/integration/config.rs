//! The human recording switch: `[recording] human` in the user's configuration file, `config.toml` in the engine's
//! configuration directory ([`EnginePaths::config_file`]) (KNSH-021, FR-SES-04,
//! FR-SES-23, `specs/08-integrations/terminals-and-shells.md#recording-a-human-session`).
//!
//! ```toml
//! [recording]
//! human = true
//! ```
//!
//! Recording is off unless the file says `human = true`. Everything else keeps it off: no file, an unreadable or
//! over-long file, TOML outside the configuration subset, a `[recording]` that is not a table, a `human` that is not a
//! boolean, or an unknown key inside `[recording]` (a typo such as `humans = true` must not look like a choice that was
//! honoured). Those are reported once on stderr by the caller; the shell itself always starts (FR-SES-22). Other
//! top-level tables belong to other settings and are not read here.

use std::fmt;
use std::path::Path;

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
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable => f.write_str("cannot read the file"),
            Self::Toml(error) => write!(f, "{error}"),
            Self::RecordingNotATable => f.write_str("'recording' must be a table"),
            Self::HumanNotABoolean => f.write_str("'recording.human' must be true or false"),
            Self::UnknownKey => f.write_str("unknown key in [recording]"),
        }
    }
}

impl std::error::Error for ConfigError {}

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
