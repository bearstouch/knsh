//! The `[[hooks]]` registrations of the user's configuration file (`specs/05-models/hook.md`, KNSH-062).
//!
//! [`parse_hooks`] turns the parsed TOML into a [`HookConfig`]. It never drops a hook: an entry that cannot be used
//! stays in the list as an invalid registration, which denies every line it would match (FR-HOOK-04). Whether `run`
//! names an executable is a filesystem question, answered by the caller with [`HookEntry::mark_not_executable`] or
//! [`HookEntry::set_program`].

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use knsh_bash::{Classification, ClassifiedCommand};
use knsh_toml::{Item, Table, Value};

/// The top-level key of the hook registrations.
pub const HOOKS_KEY: &str = "hooks";

/// The one event a hook may be registered for.
pub const HOOK_EVENT: &str = "command.proposed";

/// Most hooks the configuration may register; more is an invalid configuration.
pub const MAX_HOOKS: usize = 32;

/// Longest `timeout_ms` accepted, in milliseconds.
pub const MAX_HOOK_TIMEOUT_MS: u64 = 60_000;

/// Most names one `match.binary` list may hold.
pub const MAX_MATCH_BINARIES: usize = 64;

/// Longest name in a `match.binary` list, in bytes: a file name's limit.
const MAX_BINARY_NAME_LEN: usize = 255;

/// A hook's name: its place among the registrations, shown as `hooks[N]` in records and decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HookId(usize);

impl HookId {
    /// The hook at `index` in the configuration file.
    #[must_use]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    /// Its index in the configuration file.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

impl fmt::Display for HookId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{HOOKS_KEY}[{}]", self.0)
    }
}

/// Which lines a hook runs for (`specs/05-models/hook.md#match`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookMatch {
    /// Every agent line: no `match`, or a `match` that could not be read (fail closed).
    Every,
    /// Lines running a command with one of these names (`match.binary`).
    Binaries(Vec<String>),
}

impl HookMatch {
    /// Whether the line classified as `classification` matches.
    ///
    /// A line with dynamic code matches every `binary` list: what it runs is not known from the line, and a hook
    /// guarding `rm` must also see `bash -c 'rm -rf …'`.
    #[must_use]
    pub fn matches(&self, classification: &Classification) -> bool {
        match self {
            Self::Every => true,
            Self::Binaries(names) => {
                classification.is_dynamic()
                    || classification.is_whole_line()
                    || classification
                        .commands()
                        .iter()
                        .any(|command| names.iter().any(|name| command_named(command, name)))
            }
        }
    }
}

/// Whether `command` resolved to a binary named `name`, or was written as `name` (with or without a directory).
fn command_named(command: &ClassifiedCommand, name: &str) -> bool {
    let resolved = command
        .program
        .as_ref()
        .and_then(knsh_bash::Program::path)
        .and_then(Path::file_name);
    let written = command.name.as_deref().and_then(|text| text.rsplit('/').next());
    resolved == Some(OsStr::new(name)) || written == Some(name)
}

/// Why one registration cannot be used. Fixed codes: never any text from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookProblem {
    /// The entry is not a table.
    NotATable,
    /// A key other than `event`, `match`, `run` and `timeout_ms`, or other than `binary` inside `match`.
    UnknownKey,
    /// `event` is missing.
    MissingEvent,
    /// `event` is not `command.proposed`.
    UnsupportedEvent,
    /// `match` is not a table with a valid, non-empty `binary` list of names.
    InvalidMatch,
    /// `run` is missing.
    MissingRun,
    /// `run` is not a string naming an absolute path or one under `~/`.
    InvalidRun,
    /// `run` does not name an existing, executable regular file the user owns, writable by no one else, inside the
    /// configuration directory (where no envelope can plant it).
    NotExecutable,
    /// `timeout_ms` is missing.
    MissingTimeout,
    /// `timeout_ms` is not an integer from 1 to [`MAX_HOOK_TIMEOUT_MS`].
    InvalidTimeout,
}

impl HookProblem {
    /// A stable code naming the problem, for logs and diagnostics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotATable => "not_a_table",
            Self::UnknownKey => "unknown_key",
            Self::MissingEvent => "missing_event",
            Self::UnsupportedEvent => "unsupported_event",
            Self::InvalidMatch => "invalid_match",
            Self::MissingRun => "missing_run",
            Self::InvalidRun => "invalid_run",
            Self::NotExecutable => "not_executable",
            Self::MissingTimeout => "missing_timeout",
            Self::InvalidTimeout => "invalid_timeout",
        }
    }
}

/// Why the configuration as a whole cannot be used: every agent line is then denied, since whether hooks are
/// registered cannot be known (FR-HOOK-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigProblem {
    /// The file exists but could not be read, or is too large.
    Unreadable,
    /// The file is not valid TOML of the configuration subset.
    InvalidToml,
    /// `hooks` is not an array.
    NotAnArray,
    /// More than [`MAX_HOOKS`] hooks.
    TooManyHooks,
}

impl ConfigProblem {
    /// A stable code naming the problem, for logs and diagnostics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::InvalidToml => "invalid_toml",
            Self::NotAnArray => "not_an_array",
            Self::TooManyHooks => "too_many_hooks",
        }
    }
}

/// A valid registration: what to run and for how long.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookSpec {
    /// The executable: `run` with `~` expanded, absolute; canonical once the caller has checked it.
    pub program: PathBuf,
    /// `timeout_ms`.
    pub timeout: Duration,
}

/// One `[[hooks]]` entry, valid or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookEntry {
    /// Its name.
    pub id: HookId,
    /// Which lines it runs for. An invalid entry still matches them, to deny them.
    pub matcher: HookMatch,
    /// What to run, or why it cannot be run.
    pub registration: Result<HookSpec, HookProblem>,
}

impl HookEntry {
    /// Marks a registration whose `run` turned out not to name an executable regular file: it now denies every line
    /// it matches.
    pub fn mark_not_executable(&mut self) {
        if self.registration.is_ok() {
            self.registration = Err(HookProblem::NotExecutable);
        }
    }

    /// Replaces a valid registration's program by `program`: the canonical path the caller checked, so the file
    /// that runs is the one that was checked, not whatever a symlink points at later.
    pub fn set_program(&mut self, program: PathBuf) {
        if let Ok(spec) = &mut self.registration {
            spec.program = program;
        }
    }
}

/// The hook configuration: the registrations in declared order, or a configuration that cannot be used at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookConfig {
    /// The registrations, in the order they are declared (FR-HOOK-10). Empty when none are.
    Hooks(Vec<HookEntry>),
    /// The configuration cannot be used: every agent line is denied.
    Invalid(ConfigProblem),
}

impl HookConfig {
    /// No hooks registered.
    #[must_use]
    pub const fn none() -> Self {
        Self::Hooks(Vec::new())
    }
}

/// Reads the `[[hooks]]` registrations from the configuration file's parsed root table, expanding a `run` that
/// starts with `~` against `home` (`specs/05-models/hook.md`).
///
/// Never fails and never drops a hook: problems become invalid entries, or [`HookConfig::Invalid`] for the whole
/// configuration. Other top-level keys belong to other settings and are not read.
#[must_use]
pub fn parse_hooks(root: &Table, home: &Path) -> HookConfig {
    let Some(item) = root.get(HOOKS_KEY) else {
        return HookConfig::none();
    };
    let Some(array) = item.value().as_array() else {
        return HookConfig::Invalid(ConfigProblem::NotAnArray);
    };
    if array.len() > MAX_HOOKS {
        return HookConfig::Invalid(ConfigProblem::TooManyHooks);
    }
    let entries = array
        .iter()
        .enumerate()
        .map(|(index, item)| parse_entry(HookId::new(index), item, home))
        .collect();
    HookConfig::Hooks(entries)
}

/// One `[[hooks]]` entry.
fn parse_entry(id: HookId, item: &Item, home: &Path) -> HookEntry {
    let Some(table) = item.value().as_table() else {
        return HookEntry {
            id,
            matcher: HookMatch::Every,
            registration: Err(HookProblem::NotATable),
        };
    };
    // The match is read first and on its own, so an entry broken elsewhere still denies only the lines it would
    // have matched; a match that cannot be read matches every line (fail closed).
    let (matcher, registration) = match table.get("match").map_or(Ok(HookMatch::Every), parse_match) {
        Ok(matcher) => (matcher, parse_spec(table, home)),
        Err(problem) => (HookMatch::Every, Err(problem)),
    };
    HookEntry {
        id,
        matcher,
        registration,
    }
}

/// Every key but `match`, which [`parse_entry`] reads.
fn parse_spec(table: &Table, home: &Path) -> Result<HookSpec, HookProblem> {
    if table
        .iter()
        .any(|(key, _)| !matches!(key, "event" | "match" | "run" | "timeout_ms"))
    {
        return Err(HookProblem::UnknownKey);
    }
    match table.get("event").map(Item::value) {
        None => return Err(HookProblem::MissingEvent),
        Some(Value::String(event)) if event == HOOK_EVENT => {}
        Some(_) => return Err(HookProblem::UnsupportedEvent),
    }
    let program = match table.get("run").map(Item::value) {
        None => return Err(HookProblem::MissingRun),
        Some(Value::String(run)) => expand_run(run, home).ok_or(HookProblem::InvalidRun)?,
        Some(_) => return Err(HookProblem::InvalidRun),
    };
    let timeout_ms = match table.get("timeout_ms").map(Item::value) {
        None => return Err(HookProblem::MissingTimeout),
        Some(Value::Integer(ms)) => u64::try_from(*ms)
            .ok()
            .filter(|ms| (1..=MAX_HOOK_TIMEOUT_MS).contains(ms))
            .ok_or(HookProblem::InvalidTimeout)?,
        Some(_) => return Err(HookProblem::InvalidTimeout),
    };
    Ok(HookSpec {
        program,
        timeout: Duration::from_millis(timeout_ms),
    })
}

/// `match = { binary = [...] }`: a table whose only key is `binary`, a non-empty list of plain command names.
fn parse_match(item: &Item) -> Result<HookMatch, HookProblem> {
    let table = item.value().as_table().ok_or(HookProblem::InvalidMatch)?;
    if table.iter().any(|(key, _)| key != "binary") {
        return Err(HookProblem::InvalidMatch);
    }
    let list = table
        .get("binary")
        .and_then(|item| item.value().as_array())
        .ok_or(HookProblem::InvalidMatch)?;
    if list.is_empty() || list.len() > MAX_MATCH_BINARIES {
        return Err(HookProblem::InvalidMatch);
    }
    let names = list
        .iter()
        .map(|item| {
            item.value()
                .as_str()
                .filter(|name| is_binary_name(name))
                .map(str::to_owned)
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(HookProblem::InvalidMatch)?;
    Ok(HookMatch::Binaries(names))
}

/// A plain command name: a basename, so it is compared with basenames only.
fn is_binary_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_BINARY_NAME_LEN && name != "." && name != ".." && !name.contains(['/', '\0'])
}

/// `run` as a path: `~` alone is `home`, `~/rest` is under `home`, anything else must already be absolute. `~user`
/// is refused rather than looked up.
fn expand_run(run: &str, home: &Path) -> Option<PathBuf> {
    if run.contains('\0') {
        return None;
    }
    let path = if run == "~" {
        home.to_path_buf()
    } else if let Some(rest) = run.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(run)
    };
    path.is_absolute().then_some(path)
}
