//! Shell state: variables, positional parameters, `$?`, options and the working directory (KNSH-096, KNSH-097), and
//! what the core builtins keep (KNSH-101): variable attributes, the command hash table, aliases and the umask.
//!
//! Values are kept as [`OsString`]: an inherited environment value need not be UTF-8, and the shell passes it on to
//! commands unchanged.
//!
//! A variable may be declared without a value (`declare x`, `export x`): it then has attributes but reads as unset,
//! as in bash. Every assignment the shell makes goes through [`ShellState::assign`], which refuses a read-only
//! variable and applies the integer and case attributes, as bash's `bind_variable` does; changing `PATH` empties
//! the hash table, as bash's `sv_path` does.
//!
//! At start-up bash sets a few variables itself, and this state does the same: `IFS` is space, tab and newline
//! (never taken from the environment), `PWD` names the working directory and `SHLVL` is one more than inherited,
//! both exported. Variables bash keeps up to date itself (`RANDOM`, `LINENO`, `BASH_VERSION`, `$_` …) are not
//! emulated: reading one is refused ([`is_unemulated`]) rather than answered with a value bash would never give.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::arith::Failure;
use crate::error::{InterpError, Unsupported};
use crate::status::Status;

/// The attributes `declare` sets on a variable (KNSH-101), bash's `att_*` flags but the array ones (KNSH-103).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Attributes {
    /// `-x`: commands receive it in their environment (when it has a value).
    pub(crate) exported: bool,
    /// `-r`: it can be neither assigned nor unset.
    pub(crate) readonly: bool,
    /// `-i`: each value assigned is evaluated as an arithmetic expression.
    pub(crate) integer: bool,
    /// `-l`: each value assigned is converted to lower case.
    pub(crate) lowercase: bool,
    /// `-u`: each value assigned is converted to upper case.
    pub(crate) uppercase: bool,
    /// `-t`: the trace attribute, which only functions use; kept so `declare -p` shows it.
    pub(crate) trace: bool,
}

impl Attributes {
    /// The letters `declare -p` and `${x@a}` show, in bash's order (`show_var_attributes`: `i`, `r`, `t`, `x`, `l`,
    /// `u` among the ones kept here).
    pub(crate) fn letters(self) -> String {
        [
            (self.integer, 'i'),
            (self.readonly, 'r'),
            (self.trace, 't'),
            (self.exported, 'x'),
            (self.lowercase, 'l'),
            (self.uppercase, 'u'),
        ]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, letter)| *letter)
        .collect()
    }
}

/// One shell variable.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Variable {
    /// Its value, or `None` for a variable declared without one, which reads as unset.
    value: Option<OsString>,
    /// Its attributes.
    attributes: Attributes,
}

impl Variable {
    /// An exported variable holding `value`, as one imported from the environment.
    fn exported(value: OsString) -> Self {
        Self {
            value: Some(value),
            attributes: Attributes {
                exported: true,
                ..Attributes::default()
            },
        }
    }
}

/// Why an assignment or `unset` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AssignError {
    /// The name is not a valid identifier.
    Invalid,
    /// The variable is read-only: bash's `name: readonly variable`.
    Readonly,
    /// The variable has the integer attribute and the value is not a valid expression (bash's arithmetic error,
    /// which discards the line).
    Arithmetic(Failure),
    /// The value cannot be handled yet (a case conversion of a value that is not UTF-8).
    Unsupported(Unsupported),
}

/// A command remembered in the hash table: where `PATH` found it and how often it was run since (`hash`'s `hits`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hashed {
    /// The program found.
    pub(crate) path: PathBuf,
    /// Times it was found through the table.
    pub(crate) hits: u32,
    /// When it was added, to list the table in bash's order (newest first within a bucket).
    seq: u64,
}

/// A variable as it was, or `None` if it did not exist, to put back after a temporary assignment.
#[derive(Debug, Clone)]
pub(crate) struct SavedVariable(Option<Variable>);

/// Shell options set by `set` and `shopt`.
///
/// Each has bash's default for a non-interactive shell until set (all off). The `set` and `shopt` builtins arrive
/// with KNSH-104; until then an embedder sets them as `bash -u` or `bash -O extglob` would, through
/// [`ShellState::options_mut`]. A script using `extglob` patterns in its own text must also be parsed with them on
/// ([`knsh_bash::parse_with`]), as bash reads a line with the options set before it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
pub struct ShellOptions {
    /// `set -u`: expanding an unset parameter is an error that ends the script with status 1 (KNSH-097).
    pub nounset: bool,
    /// `set -f`: no pathname expansion (KNSH-098).
    pub noglob: bool,
    /// `shopt -s dotglob`: patterns match names starting with `.` (never `.` and `..`) (KNSH-098).
    pub dotglob: bool,
    /// `shopt -s nullglob`: a pattern that matches no file name is removed instead of kept as written (KNSH-098).
    pub nullglob: bool,
    /// `shopt -s failglob`: a pattern that matches no file name is bash's `no match` error, which abandons the
    /// command and the rest of its line with status 1; it wins over `nullglob`, as in bash (KNSH-098).
    pub failglob: bool,
    /// `shopt -s nocaseglob`: file names match patterns regardless of case (KNSH-098).
    pub nocaseglob: bool,
    /// `shopt -s globstar`: `**` as a whole path component matches any depth of directories (KNSH-098).
    pub globstar: bool,
    /// `shopt -s extglob`: the groups `?(…)`, `*(…)`, `+(…)`, `@(…)` and `!(…)` in pathname expansion, `case`
    /// patterns and the pattern operators of `${…}` (KNSH-098).
    pub extglob: bool,
    /// `set -C` (`set -o noclobber`): `>` and `&>` refuse to overwrite an existing regular file; `>|` still does
    /// (KNSH-099).
    pub noclobber: bool,
    /// `set -o pipefail`: a pipeline's status is that of its last command to fail, or 0 when every command
    /// succeeded (KNSH-100).
    pub pipefail: bool,
    /// `shopt -s lastpipe`: while job control is off, the last command of a pipeline runs in the shell itself, so
    /// its assignments last (KNSH-100).
    pub lastpipe: bool,
    /// `set -m`: job control. Each pipeline and background list runs as a job in a process group of its own; an
    /// interactive shell ([`Interpreter::with_job_control`](crate::Interpreter::with_job_control)) also hands its
    /// terminal to the foreground job and reports stopped jobs. Off, every command stays in the shell's own process
    /// group, as bash runs a script (KNSH-100).
    pub monitor: bool,
    /// `shopt -s expand_aliases`: aliases defined before a line is read are expanded in it. Off in a script, on in
    /// an interactive shell ([`Interpreter::with_job_control`](crate::Interpreter::with_job_control)), as in bash
    /// (KNSH-101).
    pub expand_aliases: bool,
    /// `shopt -s xpg_echo`: `echo` interprets backslash escapes without `-e` (KNSH-101).
    pub xpg_echo: bool,
    /// `set -o physical` (`set -P`): `cd` and `pwd` resolve symbolic links, as if given `-P` (KNSH-101).
    pub physical: bool,
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
    "OPTERR",
    "OPTIND",
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

/// The array of the last pipeline's statuses, which the shell keeps itself (KNSH-100). It is read like any variable
/// (`$PIPESTATUS`, `${PIPESTATUS[@]}`); assigning it is refused, as bash would overwrite it after the next pipeline
/// and the interpreter has no arrays to hold another value (KNSH-103).
pub(crate) const PIPESTATUS: &str = "PIPESTATUS";

/// The array `[[ string =~ regex ]]` sets to the match and its subexpressions (KNSH-102). It is read like
/// `PIPESTATUS` (`$BASH_REMATCH`, `${BASH_REMATCH[1]}`, `${#BASH_REMATCH[@]}`); assigning it is refused for the same
/// reason.
pub(crate) const BASH_REMATCH: &str = "BASH_REMATCH";

/// Whether assigning `name` must be refused: a variable bash maintains itself, `PIPESTATUS` or `BASH_REMATCH`.
pub(crate) fn refuses_assignment(name: &str) -> bool {
    is_always_unemulated(name) || name == PIPESTATUS || name == BASH_REMATCH
}

/// What `$!` names: the last background job's last command (KNSH-100).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LastBackground {
    /// A process with this id.
    Process(i32),
    /// A command the shell runs itself (a compound command or a list): bash's would be a forked subshell's process
    /// id, which does not exist here, so reading `$!` is refused rather than given a number that may name a
    /// stranger's process.
    InShell,
}

/// Whether `${!prefix*}` could list one of the variables bash always maintains itself, whatever the state.
pub(crate) fn lists_always_unemulated(prefix: &str) -> bool {
    // `BASH_REMATCH` is held as an array the listing does not see (KNSH-102).
    UNEMULATED.iter().any(|name| name.starts_with(prefix)) || BASH_REMATCH.starts_with(prefix)
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
    /// `PIPESTATUS`: the statuses of the last foreground pipeline's commands, in order (KNSH-100).
    pipestatus: Vec<Status>,
    /// `BASH_REMATCH`: the last `=~` match and its subexpressions, empty before any match and after one that failed
    /// (KNSH-102).
    bash_rematch: Vec<String>,
    /// `$!`, unset until a job runs in the background.
    last_background: Option<LastBackground>,
    /// Whether this is an interactive shell (`i` in `$-`).
    interactive: bool,
    /// Names of [`UNEMULATED_WHEN_UNSET`] variables the script assigned, declared or unset itself: from then on
    /// their state is the script's, not the default bash would have given them.
    touched: BTreeSet<String>,
    /// The command hash table: names found on `PATH`, by name (KNSH-101).
    hashed: BTreeMap<String, Hashed>,
    /// Entries added to the hash table so far, to order them.
    hash_seq: u64,
    /// Aliases, by name (KNSH-101).
    aliases: BTreeMap<String, String>,
    /// The file mode creation mask commands and redirections use (`umask`, KNSH-101), or `None` while it is the
    /// process's own, which the shell does not know.
    umask: Option<u32>,
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
            pipestatus: vec![Status::SUCCESS],
            bash_rematch: Vec::new(),
            last_background: None,
            interactive: false,
            touched: BTreeSet::new(),
            hashed: BTreeMap::new(),
            hash_seq: 0,
            aliases: BTreeMap::new(),
            umask: None,
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
                    self.variables.insert(valid.to_owned(), Variable::exported(value));
                }
                None => self.passthrough.push((name, value)),
            }
        }
        self.start_up(inherited_level.as_deref());
        self
    }

    /// Sets the variables bash sets at start-up, given the inherited `SHLVL` if any. `OLDPWD` is exported without a
    /// value unless inherited (bash's `set_pwd`; the interpreter drops an inherited one that is not a directory).
    fn start_up(&mut self, inherited_level: Option<&OsStr>) {
        self.set_variable("IFS", DEFAULT_IFS);
        self.variables.entry("OLDPWD".to_owned()).or_insert(Variable {
            value: None,
            attributes: Attributes {
                exported: true,
                ..Attributes::default()
            },
        });
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
        self.variables.insert(name.to_owned(), Variable::exported(value.into()));
    }

    /// Sets the shell's umask (the file mode creation mask commands and redirections start with) to `umask`: the
    /// embedder passes the umask the shell's process inherited, as bash starts with it. Without it commands and
    /// redirections keep the process's own umask until the `umask` builtin sets one, and `umask` cannot print it
    /// (that use is refused), since the interpreter never reads or changes the process's umask.
    #[must_use]
    pub fn with_umask(mut self, umask: u32) -> Self {
        self.umask = Some(umask & 0o777);
        self
    }

    /// The umask (`umask`, KNSH-101), or `None` while it is the process's own.
    #[must_use]
    pub fn umask(&self) -> Option<u32> {
        self.umask
    }

    /// Sets the umask.
    pub(crate) fn set_umask(&mut self, umask: u32) {
        self.umask = Some(umask & 0o777);
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

    /// The value of variable `name`, or `None` if it is unset (or declared without a value).
    #[must_use]
    pub fn variable(&self, name: &str) -> Option<&OsStr> {
        self.variables.get(name).and_then(|variable| variable.value.as_deref())
    }

    /// Whether variable `name` exists (set, or declared without a value) and is exported.
    #[must_use]
    pub fn is_exported(&self, name: &str) -> bool {
        self.attributes(name).is_some_and(|attributes| attributes.exported)
    }

    /// Whether variable `name` is read-only (`readonly`, `declare -r`, KNSH-101).
    #[must_use]
    pub fn is_readonly(&self, name: &str) -> bool {
        self.attributes(name).is_some_and(|attributes| attributes.readonly)
    }

    /// The attributes of variable `name`, if it exists (set or declared without a value).
    pub(crate) fn attributes(&self, name: &str) -> Option<Attributes> {
        self.variables.get(name).map(|variable| variable.attributes)
    }

    /// Every variable that exists, in byte order of names: name, value (`None` when declared without one) and
    /// attributes, for `declare -p` and `export -p`.
    pub(crate) fn all_variables(&self) -> impl Iterator<Item = (&str, Option<&OsStr>, Attributes)> {
        self.variables
            .iter()
            .map(|(name, variable)| (name.as_str(), variable.value.as_deref(), variable.attributes))
    }

    /// Sets variable `name` to `value` as the embedder does between runs, keeping its attributes (a new variable has
    /// none) but applying none of them: neither read-only nor integer stops or changes it. Returns `false` and changes
    /// nothing if `name` is not a valid identifier. The shell's own assignments apply both, as bash does.
    pub fn set_variable(&mut self, name: &str, value: impl Into<OsString>) -> bool {
        if !is_name(name) {
            return false;
        }
        self.store(name, value.into());
        true
    }

    /// Stores `value` in `name` (a valid identifier) as it is, keeping its attributes.
    fn store(&mut self, name: &str, value: OsString) {
        self.noticed(name);
        match self.variables.get_mut(name) {
            Some(variable) => variable.value = Some(value),
            None => {
                self.variables.insert(
                    name.to_owned(),
                    Variable {
                        value: Some(value),
                        attributes: Attributes::default(),
                    },
                );
            }
        }
    }

    /// Records that the script changed `name` itself: a default bash would have set no longer applies, and changing
    /// `PATH` empties the hash table (bash's `sv_path`).
    fn noticed(&mut self, name: &str) {
        if UNEMULATED_WHEN_UNSET.contains(&name) && !self.touched.contains(name) {
            self.touched.insert(name.to_owned());
        }
        if name == "PATH" {
            self.hashed.clear();
        }
    }

    /// Assigns `value` to variable `name` as bash's `bind_variable` does (`append`: `name+=value`): refused if `name`
    /// is not an identifier or the variable is read-only; with the integer attribute the value (and, appending, the
    /// old value) is evaluated as an arithmetic expression; with `-l` or `-u` it is converted to that case.
    ///
    /// # Errors
    ///
    /// [`AssignError`]; nothing changes then (an integer expression may have assigned other variables already, as in
    /// bash).
    pub(crate) fn assign(&mut self, name: &str, value: OsString, append: bool) -> Result<(), AssignError> {
        if !is_name(name) {
            return Err(AssignError::Invalid);
        }
        let attributes = self.attributes(name).unwrap_or_default();
        if attributes.readonly {
            return Err(AssignError::Readonly);
        }
        let old = || self.variable(name).map(ToOwned::to_owned).unwrap_or_default();
        let value = if attributes.integer {
            let utf8 = |text: OsString| {
                text.into_string()
                    .map_err(|_| AssignError::Unsupported(Unsupported::NonUtf8Value))
            };
            let base = if append {
                let old = utf8(old())?;
                crate::arith::evaluate_arithmetic(&old, self).map_err(AssignError::Arithmetic)?
            } else {
                0
            };
            let added = crate::arith::evaluate_arithmetic(&utf8(value)?, self).map_err(AssignError::Arithmetic)?;
            OsString::from(base.wrapping_add(added).to_string())
        } else {
            let mut whole = if append { old() } else { OsString::new() };
            whole.push(value);
            if attributes.lowercase || attributes.uppercase {
                let text = whole
                    .into_string()
                    .map_err(|_| AssignError::Unsupported(Unsupported::NonUtf8Value))?;
                OsString::from(convert_case(&text, attributes.uppercase))
            } else {
                whole
            }
        };
        self.store(name, value);
        Ok(())
    }

    /// Removes variable `name` (`unset`).
    ///
    /// # Errors
    ///
    /// [`AssignError::Invalid`] for a name that is not an identifier, [`AssignError::Readonly`] for a read-only
    /// variable, which is kept.
    pub(crate) fn unset(&mut self, name: &str) -> Result<(), AssignError> {
        if !is_name(name) {
            return Err(AssignError::Invalid);
        }
        if self.is_readonly(name) {
            return Err(AssignError::Readonly);
        }
        self.noticed(name);
        self.variables.remove(name);
        Ok(())
    }

    /// Changes the attributes of variable `name` (a valid identifier), creating it without a value if it does not
    /// exist, through `change`. Its value is not converted: bash applies `-i`, `-l` and `-u` only to values assigned
    /// later.
    pub(crate) fn change_attributes(&mut self, name: &str, change: impl FnOnce(&mut Attributes)) {
        self.noticed(name);
        let variable = self.variables.entry(name.to_owned()).or_insert(Variable {
            value: None,
            attributes: Attributes::default(),
        });
        change(&mut variable.attributes);
    }

    /// Removes `name`'s value but keeps the variable and its attributes, as bash's `invisible` variables: an
    /// inherited `OLDPWD` that is not a directory.
    pub(crate) fn clear_value(&mut self, name: &str) {
        if let Some(variable) = self.variables.get_mut(name) {
            variable.value = None;
        }
    }

    /// Changes the working directory to `cwd` (absolute): `cd`. `PWD` and `OLDPWD` are the caller's to set.
    pub(crate) fn set_cwd(&mut self, cwd: PathBuf) {
        debug_assert!(cwd.is_absolute(), "the working directory is always absolute");
        if cwd.is_absolute() {
            self.cwd = cwd;
        }
    }

    /// The command hash table entry of `name`, counting one more use of it.
    pub(crate) fn hash_use(&mut self, name: &str) -> Option<PathBuf> {
        self.hashed.get_mut(name).map(|entry| {
            entry.hits = entry.hits.saturating_add(1);
            entry.path.clone()
        })
    }

    /// Remembers that `name` runs `path`, with `hits` uses so far (bash's `phash_insert`: an entry already there
    /// keeps its place in the table).
    pub(crate) fn hash_insert(&mut self, name: &str, path: PathBuf, hits: u32) {
        let seq = if let Some(entry) = self.hashed.get(name) {
            entry.seq
        } else {
            self.hash_seq += 1;
            self.hash_seq
        };
        self.hashed.insert(name.to_owned(), Hashed { path, hits, seq });
    }

    /// Forgets `name`; whether it was remembered.
    pub(crate) fn hash_remove(&mut self, name: &str) -> bool {
        self.hashed.remove(name).is_some()
    }

    /// Forgets every command (`hash -r`).
    pub(crate) fn hash_clear(&mut self) {
        self.hashed.clear();
    }

    /// The hash table in the order bash's `hash` lists it: by bucket of bash's 256-bucket table (FNV-1 of the
    /// name), newest first within a bucket.
    pub(crate) fn hash_entries(&self) -> Vec<(&str, &Hashed)> {
        let mut entries: Vec<(&str, &Hashed)> =
            self.hashed.iter().map(|(name, entry)| (name.as_str(), entry)).collect();
        entries.sort_by_key(|(name, entry)| (bash_hash_bucket(name), std::cmp::Reverse(entry.seq)));
        entries
    }

    /// The value of alias `name`.
    pub(crate) fn alias(&self, name: &str) -> Option<&str> {
        self.aliases.get(name).map(String::as_str)
    }

    /// Defines alias `name` as `value`.
    pub(crate) fn set_alias(&mut self, name: &str, value: String) {
        self.aliases.insert(name.to_owned(), value);
    }

    /// Removes alias `name`; whether it existed.
    pub(crate) fn remove_alias(&mut self, name: &str) -> bool {
        self.aliases.remove(name).is_some()
    }

    /// Removes every alias (`unalias -a`).
    pub(crate) fn clear_aliases(&mut self) {
        self.aliases.clear();
    }

    /// Every alias, by name in byte order, as `alias` lists them.
    pub(crate) fn aliases(&self) -> &BTreeMap<String, String> {
        &self.aliases
    }

    /// What variable `name` is now, to put back with [`ShellState::restore_variable`].
    pub(crate) fn save_variable(&self, name: &str) -> SavedVariable {
        SavedVariable(self.variables.get(name).cloned())
    }

    /// Puts variable `name` back as `saved` holds it.
    pub(crate) fn restore_variable(&mut self, name: &str, saved: SavedVariable) {
        self.noticed(name);
        match saved.0 {
            Some(variable) => {
                self.variables.insert(name.to_owned(), variable);
            }
            None => {
                self.variables.remove(name);
            }
        }
    }

    /// Sets `name` to `value`, exported, for one builtin's run (bash's temporary environment). Its other attributes
    /// are kept.
    pub(crate) fn set_temporary(&mut self, name: &str, value: OsString) {
        self.store(name, value);
        if let Some(variable) = self.variables.get_mut(name) {
            variable.attributes.exported = true;
        }
    }

    /// Sets the positional parameters (`set --`, `shift`, `source` with arguments).
    pub(crate) fn set_positional(&mut self, parameters: Vec<String>) {
        self.positional = parameters;
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

    /// `PIPESTATUS`: the status of each command of the last foreground pipeline, in order, before `!` and
    /// `pipefail` (KNSH-100). A simple command or a subshell is a pipeline of one; a compound command run in the
    /// shell (`{ …; }`, `if`, loops) leaves it as its last pipeline set it, as in bash. This is what fills an
    /// execution record's `pipestatus` field.
    #[must_use]
    pub fn pipestatus(&self) -> &[Status] {
        &self.pipestatus
    }

    /// `BASH_REMATCH`: what the last `[[ … =~ … ]]` matched, then each subexpression (empty for one that took no
    /// part), or nothing before any match and after one that failed (KNSH-102).
    #[must_use]
    pub fn bash_rematch(&self) -> &[String] {
        &self.bash_rematch
    }

    /// Sets `BASH_REMATCH`.
    pub(crate) fn set_bash_rematch(&mut self, matched: Vec<String>) {
        self.bash_rematch = matched;
    }

    /// Sets `PIPESTATUS`.
    pub(crate) fn set_pipestatus(&mut self, statuses: Vec<Status>) {
        self.pipestatus = statuses;
    }

    /// Whether this is an interactive shell.
    pub(crate) fn is_interactive(&self) -> bool {
        self.interactive
    }

    /// Marks the shell interactive or not.
    pub(crate) fn set_interactive(&mut self, interactive: bool) {
        self.interactive = interactive;
    }

    /// `$!`.
    pub(crate) fn last_background(&self) -> Option<LastBackground> {
        self.last_background
    }

    /// Sets `$!`.
    pub(crate) fn set_last_background(&mut self, last: LastBackground) {
        self.last_background = Some(last);
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

    /// The names of the set variables, sorted as bash sorts them for `${!prefix*}` (byte order). A variable declared
    /// without a value is not set, and not listed.
    pub(crate) fn variable_names(&self) -> impl Iterator<Item = &str> {
        self.variables
            .iter()
            .filter(|(_, variable)| variable.value.is_some())
            .map(|(name, _)| name.as_str())
    }

    /// Whether reading variable `name` must be refused because bash would answer with a value it maintains itself
    /// ([`Unsupported::ShellVariable`](crate::Unsupported::ShellVariable)).
    pub(crate) fn is_unemulated(&self, name: &str) -> bool {
        is_always_unemulated(name)
            || (UNEMULATED_WHEN_UNSET.contains(&name)
                && !self.variables.contains_key(name)
                && !self.touched.contains(name))
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
            .filter(|(_, variable)| variable.attributes.exported)
            .filter_map(|(name, variable)| Some((name.as_str(), variable.value.as_deref()?)))
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

/// The bucket of `name` in bash's command hash table: FNV-1 (`hash_string`) masked to its 256 buckets
/// (`FILENAME_HASH_BUCKETS`).
fn bash_hash_bucket(name: &str) -> u32 {
    let mut hash: u32 = 2_166_136_261;
    for byte in name.bytes() {
        hash = hash.wrapping_mul(16_777_619);
        hash ^= u32::from(byte);
    }
    hash & 255
}

/// `text` in upper case (`upper`) or lower case, one character at a time as bash's `sh_modcase` does with
/// `towupper` and `towlower`: a character whose conversion is more than one character (`ß`) is kept.
pub(crate) fn convert_case(text: &str, upper: bool) -> String {
    text.chars()
        .map(|ch| {
            let mut converted: Vec<char> = if upper {
                ch.to_uppercase().collect()
            } else {
                ch.to_lowercase().collect()
            };
            match converted.len() {
                1 => converted.pop().unwrap_or(ch),
                _ => ch,
            }
        })
        .collect()
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
        for name in ["RANDOM", "LINENO", "BASH_VERSION", "_", "PPID"] {
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
