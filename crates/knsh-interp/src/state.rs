//! Shell state: variables, positional parameters, `$?`, options and the working directory (KNSH-096, KNSH-097), what
//! the core builtins keep (KNSH-101): variable attributes, the command hash table, aliases and the umask, and
//! functions, scopes and arrays (KNSH-103).
//!
//! Values are kept as [`OsString`]: an inherited environment value need not be UTF-8, and the shell passes it on to
//! commands unchanged. A variable holds a string, an indexed array or an associative array ([`Value`]).
//!
//! A variable may be declared without a value (`declare x`, `export x`): it then has attributes but reads as unset,
//! as in bash. Every assignment the shell makes goes through [`ShellState::assign`] (or its element and list forms),
//! which refuses a read-only variable and applies the integer and case attributes, as bash's `bind_variable` does;
//! changing `PATH` empties the hash table, as bash's `sv_path` does.
//!
//! Scopes are bash's dynamic scopes (KNSH-103): each function call pushes one, holding the variables `local` (or
//! `declare` inside a function) makes there and the assignments written before the call; a name is looked up from
//! the innermost scope outwards to the global variables, and an assignment to a name no scope holds creates a global
//! variable. `unset` of a variable local to the running function leaves it local and unset until the function
//! returns; `unset` of one local to a calling function removes it, so the variable it shadowed shows again.
//!
//! A name reference (`declare -n`) holds the name of another variable: reading, assigning and unsetting it act on
//! that variable, followed through at most bash's `NAMEREF_MAX` (8) references. A reference that leads back to
//! itself is bash's `circular name reference` warning; a reference without a value is assigned the name it is given.
//!
//! At start-up bash sets a few variables itself, and this state does the same: `IFS` is space, tab and newline
//! (never taken from the environment), `PWD` names the working directory and `SHLVL` is one more than inherited,
//! both exported. The arrays bash keeps for the call stack (`FUNCNAME`, `BASH_SOURCE`, `BASH_LINENO`) are kept from
//! [`ShellState::push_frame`]; other variables bash keeps up to date itself (`RANDOM`, `LINENO`, `BASH_VERSION`,
//! `$_` …) are not emulated: reading one is refused ([`is_unemulated`]) rather than answered with a value bash would
//! never give.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use knsh_bash::CompoundCommand;

use crate::arith::Failure;
use crate::error::{InterpError, Unsupported};
use crate::status::Status;
use crate::trap::Traps;
pub(crate) use crate::vars::{Assoc, Key, Kind, Value};

/// Bash's `NAMEREF_MAX`: the most name references followed in one lookup.
const NAMEREF_MAX: usize = 8;

/// The attributes `declare` sets on a variable (KNSH-101, KNSH-103). Whether it is an indexed or associative array
/// is its value's kind ([`Kind`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Attributes {
    /// `-x`: commands receive it in their environment (when it has a string value).
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
    /// `-n`: a name reference; its string value names the variable it stands for (KNSH-103).
    pub(crate) nameref: bool,
}

impl Attributes {
    /// The letters `declare -p` and `${x@a}` show for a variable of `kind`, in bash's order (`var_attribute_string`:
    /// `a`, `A`, `i`, `n`, `r`, `t`, `x`, `l`, `u` among the ones kept here).
    pub(crate) fn letters(self, kind: Kind) -> String {
        [
            (kind == Kind::Indexed, 'a'),
            (kind == Kind::Assoc, 'A'),
            (self.integer, 'i'),
            (self.nameref, 'n'),
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
pub(crate) struct Variable {
    /// Its value, or `None` for a variable declared without one, which reads as unset.
    pub(crate) value: Option<Value>,
    /// Its attributes.
    pub(crate) attributes: Attributes,
}

impl Variable {
    /// An exported variable holding `value`, as one imported from the environment.
    fn exported(value: OsString) -> Self {
        Self {
            value: Some(Value::Scalar(value)),
            attributes: Attributes {
                exported: true,
                ..Attributes::default()
            },
        }
    }

    /// A variable without a value or attributes.
    const fn empty() -> Self {
        Self {
            value: None,
            attributes: Attributes {
                exported: false,
                readonly: false,
                integer: false,
                lowercase: false,
                uppercase: false,
                trace: false,
                nameref: false,
            },
        }
    }

    /// The kind of its value.
    pub(crate) fn kind(&self) -> Kind {
        self.value.as_ref().map_or(Kind::Scalar, Value::kind)
    }

    /// The value `$name` reads.
    fn first(&self) -> Option<&OsString> {
        self.value.as_ref().and_then(Value::first)
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
    /// The value cannot be handled yet (a case conversion of a value that is not UTF-8, a name reference this
    /// interpreter does not follow).
    Unsupported(Unsupported),
    /// A negative index before an array's first element: bash's `name[sub]: bad array subscript` (KNSH-103).
    BadSubscript,
    /// An associative array assigned as an indexed one or the reverse (bash's `cannot convert associative to
    /// indexed array` and the like): refused rather than reported.
    Kind,
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

/// Where a variable is held: a function's scope (by depth) or the global variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// The scope at this depth (0 for the outermost function).
    Scope(usize),
    /// The global variables.
    Global,
}

/// A variable as it was, or `None` if it did not exist, with where it was, to put back after a temporary
/// assignment.
#[derive(Debug, Clone)]
pub(crate) struct SavedVariable(Place, Option<Variable>);

/// A shell function (KNSH-103): its body and the text its spans index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FunctionBody {
    /// The body, with the redirections applied on every call.
    pub(crate) body: CompoundCommand,
    /// The text of the script, `eval` string or sourced file that defined it, which the body's spans index.
    pub(crate) source: Arc<str>,
    /// The sourced file it was defined in, as `source` named it: the name of its messages and its `BASH_SOURCE`
    /// element. `None` for the main script, whose name is `$0`.
    pub(crate) origin: Option<Arc<str>>,
    /// Lines before the text's first line, in the file messages number lines of.
    pub(crate) line_base: usize,
}

/// A function with its attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Function {
    /// What it runs.
    pub(crate) body: Arc<FunctionBody>,
    /// `readonly -f`: it can be neither redefined nor unset.
    pub(crate) readonly: bool,
    /// `declare -ft`.
    pub(crate) trace: bool,
}

/// One entry of the call stack `FUNCNAME`, `BASH_SOURCE` and `BASH_LINENO` describe (KNSH-103).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    /// The function called, or `None` for a file being sourced (`source` in `FUNCNAME`).
    pub(crate) function: Option<String>,
    /// The file the function was defined in, or the file sourced: its `BASH_SOURCE` element. `None` for a function
    /// of the main script, which bash 5.2 lists as `main` and bash 3.2 not at all: reading that element is refused.
    pub(crate) file: Option<String>,
    /// The line it was called on, in the caller's file: its `BASH_LINENO` element.
    pub(crate) line: usize,
}

/// Shell options set by `set` and `shopt`.
///
/// Each has bash's default for a non-interactive shell until set (all off). Scripts change them with the `set` and
/// `shopt` builtins (KNSH-104); an embedder sets them as `bash -u` or `bash -O extglob` would, through
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
    /// `set -e` (`set -o errexit`): a command that fails ends the shell with its status, except where bash ignores
    /// it (a condition, a command of an `&&` or `||` list but the last, a `!` pipeline, and everything run inside
    /// those) (KNSH-104).
    pub errexit: bool,
    /// `set -x` (`set -o xtrace`): each command is written to standard error after expansion, after `PS4`
    /// (KNSH-104).
    pub xtrace: bool,
    /// `set -v` (`set -o verbose`): each line of input is written to standard error as it is read (KNSH-104).
    pub verbose: bool,
    /// `set -n` (`set -o noexec`): commands are read but not run; ignored by an interactive shell (KNSH-104).
    pub noexec: bool,
    /// `set -E` (`set -o errtrace`): functions and subshells inherit the `ERR` trap (KNSH-104).
    pub errtrace: bool,
    /// `set -T` (`set -o functrace`): functions and subshells inherit the `DEBUG` and `RETURN` traps (KNSH-104).
    pub functrace: bool,
    /// `shopt -s inherit_errexit`: command substitutions inherit `set -e` (KNSH-104). Held and reported; it acts with
    /// command substitution (KNSH-105). Subshells always inherit `set -e`, as in bash.
    pub inherit_errexit: bool,
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
    "BASH_SUBSHELL",
    "BASH_VERSINFO",
    "BASH_VERSION",
    // KNSH-104: bash 4.1 and later write `set -x` traces to this descriptor, which is not reproduced.
    "BASH_XTRACEFD",
    // A dynamic variable in bash 4 and later, set even in a non-interactive shell.
    "COMP_WORDBREAKS",
    "DIRSTACK",
    "EPOCHREALTIME",
    "EPOCHSECONDS",
    "EUID",
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
    "SHELL",
    "TERM",
];

/// Whether `name` is always one of the variables bash maintains itself, whatever the state.
pub(crate) fn is_always_unemulated(name: &str) -> bool {
    UNEMULATED.contains(&name)
}

/// The array of the last pipeline's statuses, which the shell keeps itself (KNSH-100). It is read like any array
/// (`$PIPESTATUS`, `${PIPESTATUS[@]}`); assigning it is refused, as bash would overwrite it after the next pipeline.
pub(crate) const PIPESTATUS: &str = "PIPESTATUS";

/// The array `[[ string =~ regex ]]` sets to the match and its subexpressions (KNSH-102). It is read like
/// `PIPESTATUS`; assigning it is refused for the same reason.
pub(crate) const BASH_REMATCH: &str = "BASH_REMATCH";

/// The arrays of the call stack (KNSH-103), kept by the shell and read like `PIPESTATUS`: the functions called,
/// innermost first (`source` for a file being sourced), unset outside every function; the files they were defined
/// in (or sourced); and the lines they were called on.
pub(crate) const CALL_STACK_ARRAYS: [&str; 3] = ["FUNCNAME", "BASH_SOURCE", "BASH_LINENO"];

/// Whether `name` is one of the arrays the shell keeps itself: `PIPESTATUS`, `BASH_REMATCH` and the call stack's.
pub(crate) fn is_shell_array(name: &str) -> bool {
    name == PIPESTATUS || name == BASH_REMATCH || CALL_STACK_ARRAYS.contains(&name)
}

/// Whether assigning `name` must be refused: a variable bash maintains itself or one of the shell's own arrays.
pub(crate) fn refuses_assignment(name: &str) -> bool {
    is_always_unemulated(name) || is_shell_array(name)
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
    // The shell's own arrays are not among the variables the listing walks (KNSH-102, KNSH-103).
    UNEMULATED.iter().any(|name| name.starts_with(prefix))
        || [PIPESTATUS, BASH_REMATCH]
            .iter()
            .chain(CALL_STACK_ARRAYS.iter())
            .any(|name| name.starts_with(prefix))
}

/// What a name stands for once name references are followed (KNSH-103).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Resolved {
    /// This variable (which may not exist yet).
    Name(String),
    /// A name reference without a value, by name: assigning it sets the name it refers to.
    Dangling(String),
    /// References that lead back to themselves: bash's `circular name reference`.
    Circular,
    /// A reference this interpreter does not follow (to an array element, more than `NAMEREF_MAX` deep, or
    /// circular inside a function, where bash looks for a global variable instead).
    Refused,
}

/// Everything a script reads and changes besides the filesystem and processes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellState {
    /// `$0`: the shell's or script's name, also the prefix of the shell's own error messages.
    name: String,
    /// `$1`, `$2`, …
    positional: Vec<String>,
    /// Global variables by name. Every name is a valid identifier.
    globals: BTreeMap<String, Variable>,
    /// The scope of each function running, outermost first (KNSH-103).
    scopes: Vec<BTreeMap<String, Variable>>,
    /// Functions by name (KNSH-103).
    functions: BTreeMap<String, Function>,
    /// The call stack, outermost first: every function call and every file being sourced (KNSH-103).
    frames: Vec<Frame>,
    /// Messages found while reading variables (a circular name reference, a bad array subscript), which bash
    /// reports and goes on: the evaluator writes them out.
    notes: RefCell<Vec<String>>,
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
    /// The traps set and the signals the shell was started ignoring (KNSH-104).
    traps: Traps,
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
            globals: BTreeMap::new(),
            scopes: Vec::new(),
            functions: BTreeMap::new(),
            frames: Vec::new(),
            notes: RefCell::new(Vec::new()),
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
            traps: Traps::default(),
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
                    self.globals.insert(valid.to_owned(), Variable::exported(value));
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
        // KNSH-104: bash's `PS4` unless the environment gives one (bash 4.4 and later ignore an inherited one when
        // running as root, which the state cannot tell).
        if self.find("PS4").is_none() {
            self.set_variable("PS4", "+ ");
        }
        self.globals.entry("OLDPWD".to_owned()).or_insert(Variable {
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

    /// Sets global `name` to `value` and exports it.
    fn set_exported(&mut self, name: &str, value: impl Into<OsString>) {
        self.globals.insert(name.to_owned(), Variable::exported(value.into()));
    }

    /// The same state for a shell started with `ignored` ignored (the host reads them at start-up, as
    /// [`knsh_platform::macos::ignored_signals`] does): as in bash, a non-interactive shell can neither trap nor reset
    /// them, and every command it starts inherits them ignored (KNSH-104).
    #[must_use]
    pub fn with_ignored_signals(mut self, ignored: knsh_platform::SignalSet) -> Self {
        self.traps = Traps::with_hard_ignored(ignored);
        self
    }

    /// The traps (KNSH-104).
    pub(crate) fn traps(&self) -> &Traps {
        &self.traps
    }

    /// The traps, to change (KNSH-104).
    pub(crate) fn traps_mut(&mut self) -> &mut Traps {
        &mut self.traps
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

    // ---- Finding variables ----

    /// Where the variable `name` is held, without following name references: the innermost scope holding it, or the
    /// global variables.
    fn place(&self, name: &str) -> Option<Place> {
        if let Some(depth) = self.scopes.iter().rposition(|scope| scope.contains_key(name)) {
            return Some(Place::Scope(depth));
        }
        self.globals.contains_key(name).then_some(Place::Global)
    }

    /// The variable `name` as seen from here, without following name references.
    fn find(&self, name: &str) -> Option<&Variable> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name))
            .or_else(|| self.globals.get(name))
    }

    /// The variable held at `place` under `name`, to change.
    fn at_mut(&mut self, place: Place, name: &str) -> Option<&mut Variable> {
        match place {
            Place::Scope(depth) => self.scopes.get_mut(depth)?.get_mut(name),
            Place::Global => self.globals.get_mut(name),
        }
    }

    /// The table of `place`.
    fn table_mut(&mut self, place: Place) -> &mut BTreeMap<String, Variable> {
        match place {
            Place::Scope(depth) if depth < self.scopes.len() => &mut self.scopes[depth],
            Place::Scope(_) | Place::Global => &mut self.globals,
        }
    }

    /// What `name` stands for after following name references, as bash's `find_variable_nameref` does: a reference
    /// leading back to the variable it started from, or to itself, is circular.
    pub(crate) fn resolve(&self, name: &str) -> Resolved {
        let mut current = name.to_owned();
        for _ in 0..=NAMEREF_MAX {
            let Some(variable) = self.find(&current) else {
                return Resolved::Name(current);
            };
            if !variable.attributes.nameref {
                return Resolved::Name(current);
            }
            let target = match variable.first().and_then(|value| value.to_str()) {
                Some(target) if !target.is_empty() => target.to_owned(),
                _ => return Resolved::Dangling(current),
            };
            if !is_name(&target) {
                return Resolved::Refused;
            }
            if target == name || target == current {
                // Bash then looks for a global variable of that name inside a function: not followed here.
                return if self.scopes.is_empty() {
                    Resolved::Circular
                } else {
                    Resolved::Refused
                };
            }
            current = target;
        }
        Resolved::Refused
    }

    /// The variable reading `name` reads (following references), noting bash's warning for a circular reference.
    ///
    /// # Errors
    ///
    /// [`Unsupported::Nameref`] for a reference this interpreter does not follow.
    fn read(&self, name: &str) -> Result<Option<(String, &Variable)>, Unsupported> {
        match self.resolve(name) {
            Resolved::Name(target) => Ok(self.find(&target).map(|variable| (target, variable))),
            Resolved::Dangling(_) => Ok(None),
            Resolved::Circular => {
                self.note(format!("warning: {name}: circular name reference"));
                Ok(None)
            }
            Resolved::Refused => Err(Unsupported::Nameref),
        }
    }

    /// The name an assignment to `name` assigns (following references): `Ok(None)` when `name` is a reference
    /// without a value, which is itself given the value as the name it refers to.
    fn write_target(&self, name: &str) -> Result<Option<String>, AssignError> {
        match self.resolve(name) {
            Resolved::Name(target) => Ok(Some(target)),
            Resolved::Dangling(reference) if reference == name => Ok(None),
            // A reference to a reference without a value: bash sets the last one.
            Resolved::Dangling(_) | Resolved::Circular | Resolved::Refused => {
                Err(AssignError::Unsupported(Unsupported::Nameref))
            }
        }
    }

    /// Records a message bash reports while expanding, without stopping (`warning: x: circular name reference`).
    pub(crate) fn note(&self, message: String) {
        self.notes.borrow_mut().push(message);
    }

    /// The messages recorded since the last call.
    pub(crate) fn take_notes(&self) -> Vec<String> {
        std::mem::take(&mut *self.notes.borrow_mut())
    }

    // ---- Reading ----

    /// The value of variable `name`, or `None` if it is unset (or declared without a value): its string, or element
    /// 0 of an array. Name references are followed; one this interpreter does not follow reads as unset here (the
    /// expansions that read variables refuse it, KNSH-103).
    #[must_use]
    pub fn variable(&self, name: &str) -> Option<&OsStr> {
        match self.read(name) {
            Ok(found) => found
                .and_then(|(_, variable)| variable.first())
                .map(OsString::as_os_str),
            Err(_) => None,
        }
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

    /// The attributes of variable `name` (following references), if it exists.
    pub(crate) fn attributes(&self, name: &str) -> Option<Attributes> {
        self.read(name).ok().flatten().map(|(_, variable)| variable.attributes)
    }

    /// The attributes of variable `name` itself, without following references, if it exists.
    pub(crate) fn own_attributes(&self, name: &str) -> Option<Attributes> {
        self.find(name).map(|variable| variable.attributes)
    }

    /// The value of `name` itself, without following references (a reference's target name).
    pub(crate) fn own_value(&self, name: &str) -> Option<&Value> {
        self.find(name).and_then(|variable| variable.value.as_ref())
    }

    /// What kind of value `name` holds (following references): [`Kind::Unset`] when no such variable exists.
    pub(crate) fn kind(&self, name: &str) -> Kind {
        if is_shell_array(name) {
            return Kind::Indexed;
        }
        match self.read(name) {
            Ok(Some((_, variable))) => variable.kind(),
            Ok(None) | Err(_) => Kind::Unset,
        }
    }

    /// The whole value of `name` (following references), `None` when unset or declared without a value. The shell's
    /// own arrays are built from what it keeps.
    ///
    /// # Errors
    ///
    /// [`Unsupported::Nameref`] for a reference not followed; [`Unsupported::ShellVariable`] for a `BASH_SOURCE`
    /// holding an element this interpreter cannot give as bash would.
    pub(crate) fn value(&self, name: &str) -> Result<Option<Cow<'_, Value>>, Unsupported> {
        if let Some(array) = self.shell_array(name)? {
            return Ok(array.map(Cow::Owned));
        }
        Ok(self
            .read(name)?
            .and_then(|(_, variable)| variable.value.as_ref())
            .map(Cow::Borrowed))
    }

    /// Element `key` of `name` (following references). `Err(Ok(()))`-like failures: [`ElementError`].
    ///
    /// # Errors
    ///
    /// [`ElementError::BadSubscript`] for a negative index before the first element (bash's message, then unset);
    /// [`ElementError::Unsupported`] for what [`ShellState::value`] refuses.
    pub(crate) fn element(&self, name: &str, key: &Key) -> Result<Option<OsString>, ElementError> {
        if name == "BASH_SOURCE" {
            return self.bash_source_element(key);
        }
        let Some(value) = self.value(name).map_err(ElementError::Unsupported)? else {
            return Ok(None);
        };
        value
            .element(key)
            .map(|found: Option<&OsString>| found.cloned())
            .map_err(|()| ElementError::BadSubscript)
    }

    /// One element of `BASH_SOURCE`: refused only when that element is one bash 5.2 and 3.2 give differently.
    fn bash_source_element(&self, key: &Key) -> Result<Option<OsString>, ElementError> {
        let files: Vec<Option<&String>> = self.frames.iter().rev().map(|frame| frame.file.as_ref()).collect();
        let index = match key {
            Key::Index(index) => *index,
            Key::Name(name) => name.parse().unwrap_or(0),
        };
        let index = if index < 0 {
            i64::try_from(files.len()).unwrap_or(i64::MAX).saturating_add(index)
        } else {
            index
        };
        if index < 0 {
            return Err(ElementError::BadSubscript);
        }
        match usize::try_from(index).ok().and_then(|at| files.get(at)) {
            None => Ok(None),
            Some(Some(file)) => Ok(Some(OsString::from(file.as_str()))),
            Some(None) => Err(ElementError::Unsupported(Unsupported::ShellVariable)),
        }
    }

    /// The shell's own array `name`, if it is one: `Some(None)` while it is unset (`FUNCNAME` outside functions).
    #[allow(clippy::option_option)] // Not one of the shell's arrays, or one that is unset.
    fn shell_array(&self, name: &str) -> Result<Option<Option<Value>>, Unsupported> {
        let items: Vec<String> = match name {
            PIPESTATUS => self.pipestatus.iter().map(ToString::to_string).collect(),
            BASH_REMATCH => self.bash_rematch.clone(),
            "FUNCNAME" => {
                if !self.frames.iter().any(|frame| frame.function.is_some()) {
                    return Ok(Some(None));
                }
                self.frames
                    .iter()
                    .rev()
                    .map(|frame| frame.function.clone().unwrap_or_else(|| "source".to_owned()))
                    .collect()
            }
            "BASH_SOURCE" => self
                .frames
                .iter()
                .rev()
                .map(|frame| frame.file.clone().ok_or(Unsupported::ShellVariable))
                .collect::<Result<_, _>>()?,
            "BASH_LINENO" => self.frames.iter().rev().map(|frame| frame.line.to_string()).collect(),
            _ => return Ok(None),
        };
        let elements = items
            .into_iter()
            .enumerate()
            .map(|(at, item)| (i64::try_from(at).unwrap_or(i64::MAX), OsString::from(item)))
            .collect();
        Ok(Some(Some(Value::Indexed(elements))))
    }

    /// Every variable visible from here (the innermost of each name), in byte order of names, for `declare -p` and
    /// `export -p`.
    pub(crate) fn all_variables(&self) -> Vec<(&str, &Variable)> {
        let mut visible: BTreeMap<&str, &Variable> = self.globals.iter().map(|(name, v)| (name.as_str(), v)).collect();
        for scope in &self.scopes {
            for (name, variable) in scope {
                visible.insert(name, variable);
            }
        }
        visible.into_iter().collect()
    }

    /// The names of the set variables visible from here, sorted as bash sorts them for `${!prefix*}` (byte order).
    /// A variable declared without a value is not set, and not listed.
    pub(crate) fn variable_names(&self) -> Vec<&str> {
        self.all_variables()
            .into_iter()
            .filter(|(_, variable)| variable.value.is_some())
            .map(|(name, _)| name)
            .collect()
    }

    // ---- Assigning ----

    /// Sets variable `name` to `value` as the embedder does between runs, keeping its attributes (a new variable has
    /// none) but applying none of them: neither read-only nor integer stops or changes it. Returns `false` and changes
    /// nothing if `name` is not a valid identifier. The shell's own assignments apply both, as bash does.
    pub fn set_variable(&mut self, name: &str, value: impl Into<OsString>) -> bool {
        if !is_name(name) {
            return false;
        }
        self.store(name, Value::Scalar(value.into()));
        true
    }

    /// Stores `value` in the visible variable `name` (a valid identifier) as it is, keeping its attributes; a new
    /// variable is global, as bash creates it.
    fn store(&mut self, name: &str, value: Value) {
        self.noticed(name);
        let place = self.place(name).unwrap_or(Place::Global);
        self.table_mut(place)
            .entry(name.to_owned())
            .or_insert_with(Variable::empty)
            .value = Some(value);
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

    /// `value` as a variable with `attributes` stores it, given its `old` value when appending: the integer
    /// attribute evaluates it (and the old value) as arithmetic, `-l` and `-u` convert its case.
    fn converted(
        &mut self,
        attributes: Attributes,
        old: Option<OsString>,
        value: OsString,
        append: bool,
    ) -> Result<OsString, AssignError> {
        let old = old.unwrap_or_default();
        if attributes.integer {
            let utf8 = |text: OsString| {
                text.into_string()
                    .map_err(|_| AssignError::Unsupported(Unsupported::NonUtf8Value))
            };
            let base = if append {
                let old = utf8(old)?;
                crate::arith::evaluate_arithmetic(&old, self).map_err(AssignError::Arithmetic)?
            } else {
                0
            };
            let added = crate::arith::evaluate_arithmetic(&utf8(value)?, self).map_err(AssignError::Arithmetic)?;
            return Ok(OsString::from(base.wrapping_add(added).to_string()));
        }
        let mut whole = if append { old } else { OsString::new() };
        whole.push(value);
        if attributes.lowercase || attributes.uppercase {
            let text = whole
                .into_string()
                .map_err(|_| AssignError::Unsupported(Unsupported::NonUtf8Value))?;
            return Ok(OsString::from(convert_case(&text, attributes.uppercase)));
        }
        Ok(whole)
    }

    /// Assigns `value` to variable `name` as bash's `bind_variable` does (`append`: `name+=value`): refused if `name`
    /// is not an identifier or the variable is read-only; with the integer attribute the value (and, appending, the
    /// old value) is evaluated as an arithmetic expression; with `-l` or `-u` it is converted to that case. An array
    /// has its element 0 assigned (`a=x`), as in bash; a name reference assigns the variable it refers to.
    ///
    /// # Errors
    ///
    /// [`AssignError`]; nothing changes then (an integer expression may have assigned other variables already, as in
    /// bash).
    pub(crate) fn assign(&mut self, name: &str, value: OsString, append: bool) -> Result<(), AssignError> {
        if !is_name(name) {
            return Err(AssignError::Invalid);
        }
        let Some(target) = self.write_target(name)? else {
            return self.set_reference(name, value);
        };
        match self.kind(&target) {
            Kind::Indexed => return self.assign_element(&target, &Key::Index(0), value, append),
            Kind::Assoc => return self.assign_element(&target, &Key::Name("0".to_owned()), value, append),
            Kind::Unset | Kind::Scalar => {}
        }
        let attributes = self.attributes(&target).unwrap_or_default();
        if attributes.readonly {
            return Err(AssignError::Readonly);
        }
        let old = self.variable(&target).map(ToOwned::to_owned);
        let value = self.converted(attributes, old, value, append)?;
        self.store(&target, Value::Scalar(value));
        Ok(())
    }

    /// Sets `name` itself to the string `value`, without following references or applying attributes but read-only
    /// (`declare -n ref=target` stores the target's name).
    ///
    /// # Errors
    ///
    /// [`AssignError::Readonly`] for a read-only variable.
    pub(crate) fn assign_own(&mut self, name: &str, value: OsString) -> Result<(), AssignError> {
        if self.own_attributes(name).is_some_and(|attributes| attributes.readonly) {
            return Err(AssignError::Readonly);
        }
        self.store(name, Value::Scalar(value));
        Ok(())
    }

    /// Hides every function scope, so what follows acts on the global variables (`declare -g`); give them back to
    /// [`ShellState::show_scopes`].
    pub(crate) fn hide_scopes(&mut self) -> Vec<BTreeMap<String, Variable>> {
        std::mem::take(&mut self.scopes)
    }

    /// Gives back the scopes [`ShellState::hide_scopes`] hid.
    pub(crate) fn show_scopes(&mut self, scopes: Vec<BTreeMap<String, Variable>>) {
        self.scopes = scopes;
    }

    /// Gives the name reference `name`, which has no value, `value` as the name it refers to.
    fn set_reference(&mut self, name: &str, value: OsString) -> Result<(), AssignError> {
        if self.own_attributes(name).is_some_and(|attributes| attributes.readonly) {
            return Err(AssignError::Readonly);
        }
        if !value.to_str().is_some_and(is_name) {
            return Err(AssignError::Unsupported(Unsupported::Nameref));
        }
        let place = self.place(name).unwrap_or(Place::Global);
        if let Some(variable) = self.at_mut(place, name) {
            variable.value = Some(Value::Scalar(value));
        }
        Ok(())
    }

    /// Assigns element `key` of array `name` (`name[key]=value`, `+=` when `append`), as bash's
    /// `assign_array_element` does: a string or a new variable becomes an indexed array (the string its element 0);
    /// a negative index counts back from the end. The integer and case attributes apply to the element.
    ///
    /// # Errors
    ///
    /// [`AssignError`]; nothing changes then.
    pub(crate) fn assign_element(
        &mut self,
        name: &str,
        key: &Key,
        value: OsString,
        append: bool,
    ) -> Result<(), AssignError> {
        if !is_name(name) {
            return Err(AssignError::Invalid);
        }
        let target = self
            .write_target(name)?
            .ok_or(AssignError::Unsupported(Unsupported::Nameref))?;
        if refuses_assignment(&target) {
            return Err(AssignError::Unsupported(Unsupported::ShellVariable));
        }
        let attributes = self.attributes(&target).unwrap_or_default();
        if attributes.readonly {
            return Err(AssignError::Readonly);
        }
        if attributes.nameref {
            return Err(AssignError::Unsupported(Unsupported::Nameref));
        }
        let kind = self.kind(&target);
        let key = match (kind, key) {
            (Kind::Assoc, Key::Name(_)) => key.clone(),
            (Kind::Assoc, Key::Index(index)) => Key::Name(index.to_string()),
            (Kind::Unset | Kind::Scalar | Kind::Indexed, Key::Index(index)) if *index >= 0 => key.clone(),
            (Kind::Unset | Kind::Scalar | Kind::Indexed, Key::Index(index)) => {
                // Counted back from one past the greatest index, read in place: copying the array for every
                // element assigned would make `mapfile` and `a[i]=x` loops quadratic.
                let end = self.indexed_end(&target);
                let resolved = end.saturating_add(*index);
                if resolved < 0 {
                    return Err(AssignError::BadSubscript);
                }
                Key::Index(resolved)
            }
            (Kind::Unset | Kind::Scalar | Kind::Indexed, Key::Name(_)) => return Err(AssignError::Kind),
        };
        let old = self
            .value(&target)
            .ok()
            .flatten()
            .and_then(|whole| whole.element(&key).ok().flatten().cloned());
        let value = self.converted(attributes, old, value, append)?;
        self.noticed(&target);
        let place = self.place(&target).unwrap_or(Place::Global);
        let variable = self
            .table_mut(place)
            .entry(target.clone())
            .or_insert_with(Variable::empty);
        match (&mut variable.value, key) {
            (Some(Value::Assoc(entries)), Key::Name(key)) => entries.insert(&key, value),
            (Some(Value::Indexed(elements)), Key::Index(index)) => {
                elements.insert(index, value);
            }
            (held, Key::Index(index)) => {
                let mut elements = held.take().map(Value::into_indexed).unwrap_or_default();
                elements.insert(index, value);
                *held = Some(Value::Indexed(elements));
            }
            (_, Key::Name(_)) => return Err(AssignError::Kind),
        }
        Ok(())
    }

    /// One past the greatest index of `name` read as an indexed array (a string is its element 0), 0 when unset.
    fn indexed_end(&self, name: &str) -> i64 {
        match self.value(name).ok().flatten().as_deref() {
            Some(Value::Scalar(_)) => 1,
            Some(Value::Indexed(elements)) => elements.keys().next_back().map_or(0, |last| last.saturating_add(1)),
            Some(Value::Assoc(entries)) => i64::try_from(entries.len()).unwrap_or(i64::MAX),
            None => 0,
        }
    }

    /// Assigns the list `items` to `name` (`name=(…)`, or `name+=(…)` when `append`), as bash's
    /// `assign_compound_array_list` does: each item is `(key, value, append)`, a missing key meaning the index after
    /// the last one assigned (or after the greatest index when appending); `assoc` makes a new variable
    /// associative. Without `append` the old elements go first.
    ///
    /// # Errors
    ///
    /// [`AssignError`]; nothing changes then, but integer elements' expressions may have run.
    pub(crate) fn assign_list(
        &mut self,
        name: &str,
        items: Vec<(Option<Key>, OsString, bool)>,
        append: bool,
        assoc: bool,
    ) -> Result<(), AssignError> {
        if !is_name(name) {
            return Err(AssignError::Invalid);
        }
        let target = self
            .write_target(name)?
            .ok_or(AssignError::Unsupported(Unsupported::Nameref))?;
        if refuses_assignment(&target) {
            return Err(AssignError::Unsupported(Unsupported::ShellVariable));
        }
        let attributes = self.attributes(&target).unwrap_or_default();
        if attributes.readonly {
            return Err(AssignError::Readonly);
        }
        if attributes.nameref {
            return Err(AssignError::Unsupported(Unsupported::Nameref));
        }
        let held = self.value(&target).ok().flatten();
        let has_value = held.is_some();
        let emptied = match held.as_deref() {
            Some(Value::Assoc(entries)) => Some(entries.emptied()),
            Some(Value::Scalar(_) | Value::Indexed(_)) | None => None,
        };
        let kind = match self.kind(&target) {
            Kind::Unset if assoc => Kind::Assoc,
            // A variable declared without a value keeps the kind `declare` gave it, or is indexed.
            Kind::Scalar if !has_value && assoc => Kind::Assoc,
            other => other,
        };
        // Appending takes the old value out rather than copying it, so `a+=(x)` in a loop is not quadratic. That is
        // done only when nothing below can fail (keys checked first, no attribute that evaluates or converts), so
        // an error still leaves the variable as it was.
        let current = if !append {
            None
        } else if !(attributes.integer || attributes.lowercase || attributes.uppercase)
            && self.list_keys_valid(&target, kind, &items)
        {
            let place = self.place(&target).unwrap_or(Place::Global);
            self.at_mut(place, &target).and_then(|variable| variable.value.take())
        } else {
            self.value(&target).ok().flatten().map(Cow::into_owned)
        };
        let value = if kind == Kind::Assoc {
            let mut entries = match current {
                Some(Value::Assoc(entries)) => entries,
                Some(Value::Scalar(_) | Value::Indexed(_)) | None => emptied.filter(|_| !append).unwrap_or_default(),
            };
            for (key, value, item_append) in items {
                let Some(Key::Name(key)) = key else {
                    return Err(AssignError::Kind);
                };
                let old = entries.get(&key).cloned();
                let value = self.converted(attributes, old, value, item_append)?;
                entries.insert(&key, value);
            }
            Value::Assoc(entries)
        } else {
            let mut elements = current.map(Value::into_indexed).unwrap_or_default();
            let mut next = elements.keys().next_back().map_or(0, |last| last.saturating_add(1));
            for (key, value, item_append) in items {
                let index = match key {
                    None => next,
                    Some(Key::Index(index)) => {
                        crate::vars::resolve_index(&elements, index).map_err(|()| AssignError::BadSubscript)?
                    }
                    Some(Key::Name(_)) => return Err(AssignError::Kind),
                };
                let old = elements.get(&index).cloned();
                let value = self.converted(attributes, old, value, item_append)?;
                elements.insert(index, value);
                next = index.saturating_add(1);
            }
            Value::Indexed(elements)
        };
        self.store(&target, value);
        Ok(())
    }

    /// Whether every key of `items`, assigned in turn to `target` (appending) as an array of `kind`, is one
    /// [`ShellState::assign_list`] accepts: a key for an associative array, an index (or none) for an indexed one,
    /// and no negative index before the first element at its turn.
    fn list_keys_valid(&self, target: &str, kind: Kind, items: &[(Option<Key>, OsString, bool)]) -> bool {
        if kind == Kind::Assoc {
            return items.iter().all(|(key, _, _)| matches!(key, Some(Key::Name(_))));
        }
        let mut end = self.indexed_end(target);
        let mut next = end;
        for (key, _, _) in items {
            let index = match key {
                None => next,
                Some(Key::Index(index)) if *index >= 0 => *index,
                Some(Key::Index(index)) => match end.checked_add(*index) {
                    Some(resolved) if resolved >= 0 => resolved,
                    _ => return false,
                },
                Some(Key::Name(_)) => return false,
            };
            next = index.saturating_add(1);
            end = end.max(next);
        }
        true
    }

    /// Makes `name` an empty array of the kind `assoc` says, if it is not one already (`declare -a x`, `declare -A
    /// h`): a string becomes element 0 of an indexed array.
    ///
    /// # Errors
    ///
    /// [`AssignError::Kind`] to turn an associative array into an indexed one or the reverse.
    pub(crate) fn make_array(&mut self, name: &str, assoc: bool) -> Result<(), AssignError> {
        let target = match self.write_target(name)? {
            Some(target) => target,
            None => name.to_owned(),
        };
        let current = self.find(&target).and_then(|variable| variable.value.clone());
        let value = match (current, assoc) {
            (Some(Value::Assoc(entries)), true) => Value::Assoc(entries),
            (Some(Value::Indexed(elements)), false) => Value::Indexed(elements),
            (Some(Value::Assoc(_)), false) | (Some(Value::Indexed(_)), true) => return Err(AssignError::Kind),
            // A string becomes element 0 (key `0`), as bash's `convert_var_to_array` and `convert_var_to_assoc`.
            (Some(Value::Scalar(text)), true) => {
                let mut entries = Assoc::default();
                entries.insert("0", text);
                Value::Assoc(entries)
            }
            (Some(Value::Scalar(text)), false) => Value::Indexed(BTreeMap::from([(0, text)])),
            (None, true) => Value::Assoc(Assoc::default()),
            (None, false) => Value::Indexed(BTreeMap::new()),
        };
        self.store(&target, value);
        Ok(())
    }

    // ---- Unsetting ----

    /// Removes variable `name` (`unset`), following references, as bash's `makunbound` does: a variable local to the
    /// running function stays local, unset, until it returns; any other is removed from where it is held.
    ///
    /// # Errors
    ///
    /// [`AssignError::Invalid`] for a name that is not an identifier, [`AssignError::Readonly`] for a read-only
    /// variable, which is kept.
    pub(crate) fn unset(&mut self, name: &str) -> Result<(), AssignError> {
        if !is_name(name) {
            return Err(AssignError::Invalid);
        }
        let target = match self.resolve(name) {
            Resolved::Name(target) => target,
            // Bash unsets the reference itself when it has no value.
            Resolved::Dangling(reference) => reference,
            Resolved::Circular | Resolved::Refused => return Err(AssignError::Unsupported(Unsupported::Nameref)),
        };
        self.unset_own(&target)
    }

    /// Removes variable `name` itself, without following references (`unset -n`).
    ///
    /// # Errors
    ///
    /// As [`ShellState::unset`].
    pub(crate) fn unset_own(&mut self, name: &str) -> Result<(), AssignError> {
        if !is_name(name) {
            return Err(AssignError::Invalid);
        }
        if self.own_attributes(name).is_some_and(|attributes| attributes.readonly) {
            return Err(AssignError::Readonly);
        }
        self.noticed(name);
        match self.place(name) {
            None => {}
            Some(Place::Scope(depth)) if depth + 1 == self.scopes.len() => {
                // Bash resets its attributes and makes it invisible: it stays local, without a value.
                self.scopes[depth].insert(name.to_owned(), Variable::empty());
            }
            Some(place) => {
                self.table_mut(place).remove(name);
            }
        }
        Ok(())
    }

    /// Removes element `key` of array `name` (`unset 'a[i]'`); a string's element 0 is the string itself.
    ///
    /// # Errors
    ///
    /// [`AssignError::Readonly`] for a read-only array, [`AssignError::BadSubscript`] for a negative index before
    /// the first element.
    pub(crate) fn unset_element(&mut self, name: &str, key: &Key) -> Result<(), AssignError> {
        let target = match self.resolve(name) {
            Resolved::Name(target) => target,
            Resolved::Dangling(_) => return Ok(()),
            Resolved::Circular | Resolved::Refused => return Err(AssignError::Unsupported(Unsupported::Nameref)),
        };
        if self.attributes(&target).is_some_and(|attributes| attributes.readonly) {
            return Err(AssignError::Readonly);
        }
        let Some(place) = self.place(&target) else {
            return Ok(());
        };
        let Some(variable) = self.at_mut(place, &target) else {
            return Ok(());
        };
        match (&mut variable.value, key) {
            (Some(Value::Indexed(elements)), Key::Index(index)) => {
                let index = crate::vars::resolve_index(elements, *index).map_err(|()| AssignError::BadSubscript)?;
                elements.remove(&index);
            }
            (Some(Value::Assoc(entries)), Key::Name(key)) => {
                entries.remove(key);
            }
            (Some(Value::Assoc(entries)), Key::Index(index)) => {
                entries.remove(&index.to_string());
            }
            // Bash unsets a string when element 0 is unset.
            (Some(Value::Scalar(_)), Key::Index(0 | -1)) => return self.unset(&target),
            (Some(Value::Scalar(_)), Key::Index(index)) if *index < -1 => return Err(AssignError::BadSubscript),
            _ => {}
        }
        Ok(())
    }

    // ---- Attributes ----

    /// Changes the attributes of variable `name` (a valid identifier; references followed unless `own`), creating
    /// it without a value if it does not exist, through `change`. Its value is not converted: bash applies `-i`,
    /// `-l` and `-u` only to values assigned later.
    pub(crate) fn change_attributes(&mut self, name: &str, own: bool, change: impl FnOnce(&mut Attributes)) {
        let target = if own {
            name.to_owned()
        } else {
            match self.resolve(name) {
                Resolved::Name(target) => target,
                Resolved::Dangling(_) | Resolved::Circular | Resolved::Refused => name.to_owned(),
            }
        };
        self.noticed(&target);
        let place = self.place(&target).unwrap_or(Place::Global);
        let variable = self.table_mut(place).entry(target).or_insert_with(Variable::empty);
        change(&mut variable.attributes);
    }

    /// Removes `name`'s value but keeps the variable and its attributes, as bash's `invisible` variables: an
    /// inherited `OLDPWD` that is not a directory.
    pub(crate) fn clear_value(&mut self, name: &str) {
        if let Some(place) = self.place(name)
            && let Some(variable) = self.at_mut(place, name)
        {
            variable.value = None;
        }
    }

    // ---- Scopes and functions (KNSH-103) ----

    /// Enters a function: a new scope holding `temporaries` (the assignments written before the call), exported,
    /// as bash makes the temporary environment the function's own scope.
    pub(crate) fn push_scope(&mut self, temporaries: &[(String, OsString)]) {
        let mut scope = BTreeMap::new();
        for (name, value) in temporaries {
            scope.insert(name.clone(), Variable::exported(value.clone()));
        }
        self.scopes.push(scope);
    }

    /// Leaves the innermost function's scope, dropping its local variables.
    pub(crate) fn pop_scope(&mut self) {
        // Leaving a scope that held `PATH` changes the visible `PATH`: bash's `sv_path` runs then too.
        if self.scopes.pop().is_some_and(|scope| scope.contains_key("PATH")) {
            self.hashed.clear();
        }
    }

    /// Whether a function is running (bash's `variable_context` is not 0).
    pub(crate) fn in_function(&self) -> bool {
        !self.scopes.is_empty()
    }

    /// Makes `name` local to the running function (`local name`, `declare name` inside a function), as bash's
    /// `make_local_variable` does: one already local there is kept; a new one has no value and only the export
    /// attribute of the variable it shadows.
    ///
    /// # Errors
    ///
    /// [`AssignError::Readonly`] when the variable it would shadow is read-only.
    pub(crate) fn make_local(&mut self, name: &str) -> Result<(), AssignError> {
        let Some(scope) = self.scopes.len().checked_sub(1) else {
            return Ok(());
        };
        if self.scopes[scope].contains_key(name) {
            return Ok(());
        }
        let shadowed = self.find(name).map(|variable| variable.attributes);
        if shadowed.is_some_and(|attributes| attributes.readonly) {
            return Err(AssignError::Readonly);
        }
        self.noticed(name);
        let mut variable = Variable::empty();
        variable.attributes.exported = shadowed.is_some_and(|attributes| attributes.exported);
        self.scopes[scope].insert(name.to_owned(), variable);
        Ok(())
    }

    /// Function `name`, if defined.
    pub(crate) fn function(&self, name: &str) -> Option<&Function> {
        self.functions.get(name)
    }

    /// Every function, by name in byte order.
    pub(crate) fn functions(&self) -> &BTreeMap<String, Function> {
        &self.functions
    }

    /// Defines function `name` to run `body`, keeping the attributes of one it replaces.
    ///
    /// # Errors
    ///
    /// [`AssignError::Readonly`] for a read-only function, which is kept.
    pub(crate) fn define_function(&mut self, name: &str, body: Arc<FunctionBody>) -> Result<(), AssignError> {
        match self.functions.get_mut(name) {
            Some(function) if function.readonly => Err(AssignError::Readonly),
            Some(function) => {
                function.body = body;
                Ok(())
            }
            None => {
                self.functions.insert(
                    name.to_owned(),
                    Function {
                        body,
                        readonly: false,
                        trace: false,
                    },
                );
                Ok(())
            }
        }
    }

    /// Removes function `name`; whether it existed.
    ///
    /// # Errors
    ///
    /// [`AssignError::Readonly`] for a read-only function, which is kept.
    pub(crate) fn remove_function(&mut self, name: &str) -> Result<bool, AssignError> {
        match self.functions.get(name) {
            Some(function) if function.readonly => Err(AssignError::Readonly),
            Some(_) => Ok(self.functions.remove(name).is_some()),
            None => Ok(false),
        }
    }

    /// Function `name`, to change its attributes.
    pub(crate) fn function_mut(&mut self, name: &str) -> Option<&mut Function> {
        self.functions.get_mut(name)
    }

    /// Enters `frame` of the call stack.
    pub(crate) fn push_frame(&mut self, frame: Frame) {
        self.frames.push(frame);
    }

    /// Leaves the innermost frame of the call stack.
    pub(crate) fn pop_frame(&mut self) {
        self.frames.pop();
    }

    /// Functions running (bash's `funcnest`).
    pub(crate) fn function_depth(&self) -> usize {
        self.frames.iter().filter(|frame| frame.function.is_some()).count()
    }

    // ---- Everything else ----

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

    /// What the visible variable `name` is now, with where it is held, to put back with
    /// [`ShellState::restore_variable`].
    pub(crate) fn save_variable(&self, name: &str) -> SavedVariable {
        let place = self.place(name).unwrap_or(Place::Global);
        let held = match place {
            Place::Scope(depth) => self.scopes.get(depth).and_then(|scope| scope.get(name)),
            Place::Global => self.globals.get(name),
        };
        SavedVariable(place, held.cloned())
    }

    /// Puts variable `name` back as `saved` holds it, where it was held.
    pub(crate) fn restore_variable(&mut self, name: &str, saved: SavedVariable) {
        self.noticed(name);
        let SavedVariable(place, held) = saved;
        let table = self.table_mut(place);
        match held {
            Some(variable) => {
                table.insert(name.to_owned(), variable);
            }
            None => {
                table.remove(name);
            }
        }
    }

    /// Sets the visible variable `name` to `value`, exported, for one builtin's run (bash's temporary environment).
    /// Its other attributes are kept; an array has its element 0 set.
    pub(crate) fn set_temporary(&mut self, name: &str, value: OsString) {
        let place = self.place(name).unwrap_or(Place::Global);
        self.noticed(name);
        let variable = self
            .table_mut(place)
            .entry(name.to_owned())
            .or_insert_with(Variable::empty);
        match &mut variable.value {
            Some(Value::Indexed(elements)) => {
                elements.insert(0, value);
            }
            Some(Value::Assoc(entries)) => entries.insert("0", value),
            held => *held = Some(Value::Scalar(value)),
        }
        variable.attributes.exported = true;
    }

    /// Sets the positional parameters (`set --`, `shift`, `source` with arguments, a function call).
    pub(crate) fn set_positional(&mut self, parameters: Vec<String>) {
        self.positional = parameters;
    }

    /// The positional parameters, to replace for a function call and put back after it.
    pub(crate) fn positional_mut(&mut self) -> &mut Vec<String> {
        &mut self.positional
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

    /// Whether reading variable `name` must be refused because bash would answer with a value it maintains itself
    /// ([`Unsupported::ShellVariable`](crate::Unsupported::ShellVariable)).
    pub(crate) fn is_unemulated(&self, name: &str) -> bool {
        is_always_unemulated(name)
            || (UNEMULATED_WHEN_UNSET.contains(&name) && self.find(name).is_none() && !self.touched.contains(name))
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
    /// every exported variable visible from here that holds a string (bash exports no array), and the assignments,
    /// which win over a variable of the same name.
    pub(crate) fn environment(&self, assignments: &[(String, OsString)]) -> Vec<(OsString, OsString)> {
        let mut named: BTreeMap<&str, &OsStr> = self
            .all_variables()
            .into_iter()
            .filter(|(_, variable)| variable.attributes.exported)
            .filter_map(|(name, variable)| match &variable.value {
                Some(Value::Scalar(value)) => Some((name, value.as_os_str())),
                Some(Value::Indexed(_) | Value::Assoc(_)) | None => None,
            })
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

/// Why reading an array element failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ElementError {
    /// A negative index before the first element: bash reports `name: bad array subscript` and reads it as unset.
    BadSubscript,
    /// Refused ([`ShellState::value`]).
    Unsupported(Unsupported),
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
