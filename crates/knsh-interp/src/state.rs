//! Shell state: variables, positional parameters, `$?`, options and the working directory (KNSH-096, KNSH-097).
//!
//! Values are kept as [`OsString`]: an inherited environment value need not be UTF-8, and the shell passes it on to
//! commands unchanged.
//!
//! At start-up bash sets a few variables itself, and this state does the same: `IFS` is space, tab and newline
//! (never taken from the environment), `PWD` names the working directory and `SHLVL` is one more than inherited,
//! both exported. Variables bash keeps up to date itself (`RANDOM`, `LINENO`, `BASH_VERSION`, `$_` …) are not
//! emulated: reading one is refused ([`is_unemulated`]) rather than answered with a value bash would never give.

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
/// Each has bash's default for a non-interactive shell until set. The `set` builtin itself arrives with KNSH-104;
/// until then an embedder sets them as `bash -u` would, through [`ShellState::options_mut`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShellOptions {
    /// `set -u`: expanding an unset parameter is an error that ends the script with status 1 (KNSH-097).
    pub nounset: bool,
}

/// `IFS` as bash sets it at start-up: space, tab, newline.
pub(crate) const DEFAULT_IFS: &str = " \t\n";

/// Variables bash computes or sets itself whatever the environment says. Reading one is refused: the interpreter
/// does not keep them up to date yet (KNSH-101 and later), and any value it gave would differ from bash's.
const UNEMULATED: &[&str] = &[
    "_",
    "BASH",
    "BASHOPTS",
    "BASHPID",
    "BASH_ALIASES",
    "BASH_ARGC",
    "BASH_ARGV",
    "BASH_ARGV0",
    "BASH_CMDS",
    "BASH_COMMAND",
    "BASH_EXECUTION_STRING",
    "BASH_LINENO",
    "BASH_REMATCH",
    "BASH_SOURCE",
    "BASH_SUBSHELL",
    "BASH_VERSINFO",
    "BASH_VERSION",
    // A dynamic variable in bash 4 and later, set even in a non-interactive shell.
    "COMP_WORDBREAKS",
    "DIRSTACK",
    "EPOCHREALTIME",
    "EPOCHSECONDS",
    "EUID",
    "FUNCNAME",
    "GROUPS",
    "HISTCMD",
    "LINENO",
    "OLDPWD",
    "OPTERR",
    "OPTIND",
    "PIPESTATUS",
    "PPID",
    "RANDOM",
    "SECONDS",
    "SHELLOPTS",
    "SRANDOM",
    "UID",
];

/// Variables bash sets at start-up only when the environment does not: refused while unset, for the same reason.
const UNEMULATED_WHEN_UNSET: &[&str] = &[
    "HISTFILE",
    "HISTFILESIZE",
    "HISTSIZE",
    "HOSTNAME",
    "HOSTTYPE",
    "MACHTYPE",
    "MAILCHECK",
    "OSTYPE",
    // Bash's default search path (`DEFAULT_PATH_VALUE`) when the environment has none.
    "PATH",
    "PS2",
    "PS4",
    "SHELL",
    "TERM",
];

/// Whether `name` is always one of the variables bash maintains itself, whatever the state.
pub(crate) fn is_always_unemulated(name: &str) -> bool {
    UNEMULATED.contains(&name)
}

/// Whether `${!prefix*}` could list one of the variables bash always maintains itself, whatever the state.
pub(crate) fn lists_always_unemulated(prefix: &str) -> bool {
    UNEMULATED.iter().any(|name| name.starts_with(prefix))
}

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
    /// `$$`.
    pid: u32,
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
        let mut state = Self {
            name: name.into(),
            positional: Vec::new(),
            variables: BTreeMap::new(),
            passthrough: Vec::new(),
            last_status: Status::SUCCESS,
            options: ShellOptions::default(),
            cwd,
            pid: std::process::id(),
        };
        state.start_up(None);
        Ok(state)
    }

    /// Imports `environment` as bash does at start-up: each entry whose name is a valid identifier becomes an
    /// exported variable (a later duplicate wins); the others are passed to commands unchanged. Then `IFS`, `PWD`
    /// and `SHLVL` are set again as bash sets them: `IFS` is never imported, `PWD` is kept only if it names the
    /// working directory, and `SHLVL` is the inherited level plus one.
    #[must_use]
    pub fn with_environment(mut self, environment: impl IntoIterator<Item = (OsString, OsString)>) -> Self {
        let mut inherited_level = None;
        for (name, value) in environment {
            match name.to_str().filter(|name| is_name(name)) {
                Some(valid) => {
                    if valid == "SHLVL" {
                        inherited_level = Some(value.clone());
                    }
                    self.variables
                        .insert(valid.to_owned(), Variable { value, exported: true });
                }
                None => self.passthrough.push((name, value)),
            }
        }
        self.start_up(inherited_level.as_deref());
        self
    }

    /// Sets the variables bash sets at start-up, given the inherited `SHLVL` if any.
    fn start_up(&mut self, inherited_level: Option<&OsStr>) {
        self.set_variable("IFS", DEFAULT_IFS);
        let cwd = self.cwd.clone().into_os_string();
        if self.variable("PWD") != Some(cwd.as_os_str()) {
            self.set_exported("PWD", cwd);
        }
        // Bash: a level that is not a number counts as 0; past 1000 it starts again from 1.
        let level = inherited_level
            .and_then(OsStr::to_str)
            .and_then(|level| level.trim().parse::<i64>().ok())
            .unwrap_or(0)
            .saturating_add(1);
        let level = if (0..1000).contains(&level) { level } else { 1 };
        self.set_exported("SHLVL", level.to_string());
    }

    /// Sets `name` to `value` and exports it.
    fn set_exported(&mut self, name: &str, value: impl Into<OsString>) {
        self.variables.insert(
            name.to_owned(),
            Variable {
                value: value.into(),
                exported: true,
            },
        );
    }

    /// Sets `$$` to `pid` instead of this process's id: the interpreter stands for a shell whose process id may be
    /// another one.
    #[must_use]
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = pid;
        self
    }

    /// `$$`.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
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

    /// Removes variable `name` (the `unset` builtin arrives with KNSH-101).
    #[cfg(test)]
    pub(crate) fn unset_variable(&mut self, name: &str) {
        self.variables.remove(name);
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

    /// The `set` and `shopt` options, to change (as `bash -u` would before running a script).
    pub fn options_mut(&mut self) -> &mut ShellOptions {
        &mut self.options
    }

    /// The names of the set variables, sorted as bash sorts them for `${!prefix*}` (byte order).
    pub(crate) fn variable_names(&self) -> impl Iterator<Item = &str> {
        self.variables.keys().map(String::as_str)
    }

    /// Whether reading variable `name` must be refused because bash would answer with a value it maintains itself
    /// ([`Unsupported::ShellVariable`](crate::Unsupported::ShellVariable)).
    pub(crate) fn is_unemulated(&self, name: &str) -> bool {
        is_always_unemulated(name) || (UNEMULATED_WHEN_UNSET.contains(&name) && !self.variables.contains_key(name))
    }

    /// Whether `${!prefix*}` could list a variable whose reading [`ShellState::is_unemulated`] refuses: bash would
    /// list it, this state does not hold it.
    pub(crate) fn lists_unemulated(&self, prefix: &str) -> bool {
        lists_always_unemulated(prefix)
            || UNEMULATED_WHEN_UNSET
                .iter()
                .any(|name| name.starts_with(prefix) && self.is_unemulated(name))
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
            vec![
                ("a-b".into(), "1".into()),
                ("HOME".into(), "/Users/me".into()),
                ("PWD".into(), "/work".into()),
                ("SHLVL".into(), "1".into()),
            ]
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
        assert_eq!(
            env,
            vec![
                ("PWD".into(), "/work".into()),
                ("SHLVL".into(), "1".into()),
                ("X".into(), "4".into()),
                ("Z".into(), "5".into()),
            ]
        );
    }

    // KNSH-097, environment import: bash never imports IFS, keeps PWD only when it names the working directory, and
    // raises SHLVL by one.
    #[test]
    fn start_up_sets_ifs_pwd_and_shlvl_like_bash() {
        let fresh = state();
        assert_eq!(fresh.variable("IFS"), Some(OsStr::new(" \t\n")));
        assert!(!fresh.is_exported("IFS"));
        assert_eq!(fresh.variable("PWD"), Some(OsStr::new("/work")));
        assert_eq!(fresh.variable("SHLVL"), Some(OsStr::new("1")));
        let imported = state().with_environment([
            ("IFS".into(), ":".into()),
            ("PWD".into(), "/elsewhere".into()),
            ("SHLVL".into(), "2".into()),
        ]);
        assert_eq!(imported.variable("IFS"), Some(OsStr::new(" \t\n")));
        assert_eq!(imported.variable("PWD"), Some(OsStr::new("/work")));
        assert_eq!(imported.variable("SHLVL"), Some(OsStr::new("3")));
        let odd = state().with_environment([("SHLVL".into(), "x".into())]);
        assert_eq!(odd.variable("SHLVL"), Some(OsStr::new("1")));
        let deep = state().with_environment([("SHLVL".into(), "999".into())]);
        assert_eq!(deep.variable("SHLVL"), Some(OsStr::new("1")));
    }

    #[test]
    fn variables_bash_maintains_are_not_emulated() {
        let state = state().with_environment([("TERM".into(), "xterm".into())]);
        for name in ["RANDOM", "LINENO", "BASH_VERSION", "_", "PPID", "OLDPWD"] {
            assert!(state.is_unemulated(name), "{name}");
        }
        assert!(state.is_unemulated("HOSTNAME"));
        assert!(!state.is_unemulated("TERM"));
        assert!(!state.is_unemulated("HOME"));
        assert!(!state.is_unemulated("PWD"));
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
