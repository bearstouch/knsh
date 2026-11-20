//! Shell state: variables, positional parameters, `$?`, options and the working directory (KNSH-096).
//!
//! Values are kept as [`OsString`]: an inherited environment value need not be UTF-8, and the shell passes it on to
//! commands unchanged.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::error::InterpError;
use crate::status::Status;

/// One shell variable.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Variable {
    /// Its value.
    value: OsString,
    /// Whether commands receive it in their environment.
    exported: bool,
}

/// Shell options set by `set` and `shopt`.
///
/// A placeholder: none is implemented yet, so every option has bash's default for a non-interactive shell. KNSH-104
/// adds `set -e`, `set -u`, `pipefail` and the rest here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShellOptions {}

/// Everything a script reads and changes besides the filesystem and processes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellState {
    /// `$0`: the shell's or script's name, also the prefix of the shell's own error messages.
    name: String,
    /// `$1`, `$2`, …
    positional: Vec<String>,
    /// Variables by name. Every name is a valid identifier.
    variables: BTreeMap<String, Variable>,
    /// Inherited environment entries whose name is not a valid identifier or not UTF-8. Bash keeps them out of its
    /// variables but passes them to every command unchanged; so does this.
    passthrough: Vec<(OsString, OsString)>,
    /// `$?`.
    last_status: Status,
    /// `set` and `shopt` options.
    options: ShellOptions,
    /// The working directory, absolute.
    cwd: PathBuf,
}

impl ShellState {
    /// A state named `name` (`$0`) in the working directory `cwd`, with no variables, no positional parameters and
    /// `$?` at 0.
    ///
    /// # Errors
    ///
    /// [`InterpError::RelativeWorkingDirectory`] if `cwd` is not absolute: commands and the filesystem are only ever
    /// given absolute paths.
    pub fn new(name: impl Into<String>, cwd: impl Into<PathBuf>) -> Result<Self, InterpError> {
        let cwd = cwd.into();
        if !cwd.is_absolute() {
            return Err(InterpError::RelativeWorkingDirectory);
        }
        Ok(Self {
            name: name.into(),
            positional: Vec::new(),
            variables: BTreeMap::new(),
            passthrough: Vec::new(),
            last_status: Status::SUCCESS,
            options: ShellOptions::default(),
            cwd,
        })
    }

    /// Imports `environment` as bash does at start-up: each entry whose name is a valid identifier becomes an
    /// exported variable (a later duplicate wins); the others are passed to commands unchanged.
    #[must_use]
    pub fn with_environment(mut self, environment: impl IntoIterator<Item = (OsString, OsString)>) -> Self {
        for (name, value) in environment {
            match name.to_str().filter(|name| is_name(name)) {
                Some(valid) => {
                    self.variables
                        .insert(valid.to_owned(), Variable { value, exported: true });
                }
                None => self.passthrough.push((name, value)),
            }
        }
        self
    }

    /// Sets the positional parameters `$1`, `$2`, … to `parameters`.
    #[must_use]
    pub fn with_positional(mut self, parameters: Vec<String>) -> Self {
        self.positional = parameters;
        self
    }

    /// `$0`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `$1`, `$2`, …
    #[must_use]
    pub fn positional(&self) -> &[String] {
        &self.positional
    }

    /// The value of variable `name`, or `None` if it is unset.
    #[must_use]
    pub fn variable(&self, name: &str) -> Option<&OsStr> {
        self.variables.get(name).map(|variable| variable.value.as_os_str())
    }

    /// Whether variable `name` is set and exported.
    #[must_use]
    pub fn is_exported(&self, name: &str) -> bool {
        self.variables.get(name).is_some_and(|variable| variable.exported)
    }

    /// Sets variable `name` to `value`, keeping whether it is exported (a new variable is not). Returns `false` and
    /// changes nothing if `name` is not a valid identifier.
    pub fn set_variable(&mut self, name: &str, value: impl Into<OsString>) -> bool {
        if !is_name(name) {
            return false;
        }
        let value = value.into();
        self.variables
            .entry(name.to_owned())
            .and_modify(|variable| variable.value.clone_from(&value))
            .or_insert(Variable { value, exported: false });
        true
    }

    /// `$?`: the status of the last pipeline run.
    #[must_use]
    pub fn last_status(&self) -> Status {
        self.last_status
    }

    /// Sets `$?`.
    pub(crate) fn set_last_status(&mut self, status: Status) {
        self.last_status = status;
    }

    /// The `set` and `shopt` options.
    #[must_use]
    pub fn options(&self) -> &ShellOptions {
        &self.options
    }

    /// The working directory, absolute.
    #[must_use]
    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    /// The environment of a command run with `assignments` before its name (`A=1 cmd`): the passed-through entries,
    /// every exported variable, and the assignments, which win over a variable of the same name.
    pub(crate) fn environment(&self, assignments: &[(String, OsString)]) -> Vec<(OsString, OsString)> {
        let mut named: BTreeMap<&str, &OsStr> = self
            .variables
            .iter()
            .filter(|(_, variable)| variable.exported)
            .map(|(name, variable)| (name.as_str(), variable.value.as_os_str()))
            .collect();
        for (name, value) in assignments {
            named.insert(name, value);
        }
        self.passthrough
            .iter()
            .cloned()
            .chain(named.into_iter().map(|(name, value)| (name.into(), value.to_owned())))
            .collect()
    }
}

/// Whether `name` is a valid shell identifier: `[A-Za-z_][A-Za-z0-9_]*`.
pub(crate) fn is_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> ShellState {
        ShellState::new("knsh", "/work").unwrap()
    }

    #[test]
    fn refuses_a_relative_working_directory() {
        assert_eq!(
            ShellState::new("knsh", "work"),
            Err(InterpError::RelativeWorkingDirectory)
        );
    }

    #[test]
    fn imports_valid_names_as_exported_and_passes_others_through() {
        let state = state().with_environment([("HOME".into(), "/Users/me".into()), ("a-b".into(), "1".into())]);
        assert_eq!(state.variable("HOME"), Some(OsStr::new("/Users/me")));
        assert!(state.is_exported("HOME"));
        assert_eq!(state.variable("a-b"), None);
        assert_eq!(
            state.environment(&[]),
            vec![("a-b".into(), "1".into()), ("HOME".into(), "/Users/me".into())]
        );
    }

    #[test]
    fn new_variables_are_not_exported_and_assignments_override_the_environment() {
        let mut state = state().with_environment([("X".into(), "1".into())]);
        assert!(state.set_variable("Y", "2"));
        assert!(state.set_variable("X", "3"));
        assert!(state.is_exported("X"));
        assert!(!state.is_exported("Y"));
        assert!(!state.set_variable("1x", "bad"));
        let env = state.environment(&[("X".into(), "4".into()), ("Z".into(), "5".into())]);
        assert_eq!(env, vec![("X".into(), "4".into()), ("Z".into(), "5".into())]);
    }

    #[test]
    fn names_follow_the_identifier_rule() {
        for name in ["a", "_", "A_1", "_x9"] {
            assert!(is_name(name), "{name}");
        }
        for name in ["", "1a", "a-b", "a b", "é"] {
            assert!(!is_name(name), "{name}");
        }
    }
}
