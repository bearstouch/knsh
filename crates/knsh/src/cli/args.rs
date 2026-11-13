//! In-house command-line argument parser (KNSH-009).
//!
//! A small declarative parser: commands are described once as static [`Command`] tables, and the same tables drive
//! parsing and the generated help, so the two cannot drift apart. No third-party CLI crate is used (the dependency
//! policy in `specs/04-non-functional-requirements/supply-chain.md` allows `libc` only).
//!
//! # Two kinds of invocation
//!
//! `knsh` is both a shell and a command-line tool (`specs/06-api/cli.md`). [`parse`] first decides which one it was
//! started as, and only then parses subcommands, so `knsh -c 'history'` runs a shell line and never `knsh history`:
//!
//! - **Shell mode** ([`Invocation::Shell`]): no arguments at all; `argv[0]` starting with `-` (how `login(1)` starts
//!   a login shell, e.g. `-knsh`); or a first argument that is a short option cluster (`-c`, `-i`, `-l`, `-lc`, …),
//!   `--login`, `-` or `--`. These follow bash's invocation syntax.
//! - **Command mode** ([`Invocation::Command`]): anything else, parsed against the declared commands.
//!
//! # Grammar of command mode
//!
//! ```text
//! knsh <command> [<subcommand>] [--flag | --option <value> | --option=<value> | <positional>]... [-- <argv>...]
//! ```
//!
//! - Every command accepts `--json` and `--help` without declaring them ([`GLOBAL_OPTIONS`]).
//! - Everything after the first `--` is passed through byte for byte, unparsed, to commands that declare
//!   [`Command::trailing`] (e.g. `knsh agent -- claude --flag`).
//! - Fail safe: an unknown flag, a missing or unexpected value, a repeated option, a missing required argument or
//!   any leftover argument is an [`ArgsError`], and the caller must exit with [`ArgsError::EXIT_STATUS`] (2, as bash
//!   does for usage errors) without running anything.
//!
//! Parsing is a pure function of `argv`; it reads no environment and performs no I/O.

use std::ffi::OsString;
use std::fmt;

/// The declaration of one command or command group, from which both the parser and the help text are derived.
///
/// A command with [`subcommands`](Command::subcommands) is a group (`knsh policy`): it only selects one of them and
/// takes no options or arguments of its own. A command without subcommands is a leaf that takes options,
/// positionals and, when declared, trailing argv.
#[derive(Debug)]
pub struct Command {
    /// The word that selects this command (`agent`). The root's name is the program name (`knsh`).
    pub name: &'static str,
    /// One-line description shown in help.
    pub about: &'static str,
    /// Long options this command takes, besides the [`GLOBAL_OPTIONS`].
    pub options: &'static [OptionSpec],
    /// Required positional arguments, in order.
    pub positionals: &'static [Positional],
    /// Whether the command takes trailing argv after `--`, and how help names it.
    pub trailing: Trailing,
    /// Nested commands. Non-empty makes this command a group.
    pub subcommands: &'static [Command],
}

/// The declaration of a long option (`--profile <p>`, `--with-checkpoints`).
#[derive(Debug)]
pub struct OptionSpec {
    /// The name without the leading `--`.
    pub long: &'static str,
    /// `Some(name)` when the option takes a value, shown in help as `<name>`; `None` for a plain flag.
    pub value: Option<&'static str>,
    /// Whether parsing fails when the option is absent.
    pub required: bool,
    /// One-line description shown in help.
    pub help: &'static str,
}

/// The declaration of a required positional argument (`<request_id>`).
#[derive(Debug)]
pub struct Positional {
    /// The name shown in help as `<name>`.
    pub name: &'static str,
    /// One-line description shown in help.
    pub help: &'static str,
}

/// Whether a command takes trailing argv after `--`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trailing {
    /// `--` is not accepted.
    None,
    /// `--` followed by at least one argument is required; help shows it as `-- <name>...`.
    Required(&'static str),
}

/// Options every command accepts without declaring them. `--json` is required on every command by
/// `specs/06-api/cli.md`; `--help` prints the generated help.
pub const GLOBAL_OPTIONS: &[OptionSpec] = &[
    OptionSpec {
        long: JSON,
        value: None,
        required: false,
        help: "Print machine-readable JSON output",
    },
    OptionSpec {
        long: HELP,
        value: None,
        required: false,
        help: "Show this help",
    },
];

/// The name of the global JSON output flag.
const JSON: &str = "json";
/// The name of the global help flag.
const HELP: &str = "help";

/// The bash invocation options `knsh` recognises in shell mode.
///
/// Only the options bash users and agent CLIs actually pass are supported; any other letter is an error rather than
/// being silently ignored, so a script never runs with an option it asked for missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellOption {
    /// `-c`: read the command line from the first operand.
    Command,
    /// `-i`: force an interactive shell.
    Interactive,
    /// `-l` (or `--login`): act as a login shell.
    Login,
}

/// Each shell option's letter and help text: the single declaration used by both the shell-mode parser and the
/// top-level help.
pub const SHELL_OPTIONS: &[(char, ShellOption, &str)] = &[
    ('c', ShellOption::Command, "Run the given command line, then exit"),
    ('i', ShellOption::Interactive, "Force an interactive shell"),
    (
        'l',
        ShellOption::Login,
        "Act as a login shell (also --login, or argv[0] starting with '-')",
    ),
];

/// What `knsh` was asked to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Invocation {
    /// Started as a shell (see the module docs for how this is detected).
    Shell(ShellInvocation),
    /// Started as a command-line tool.
    Command(ParsedCommand),
    /// `--help` was given: print this generated text to stdout and exit with status 0.
    Help(String),
}

/// A shell-mode invocation, classified but not interpreted: what to do with it belongs to later stories.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ShellInvocation {
    /// The command line given with `-c`, if any. Kept as raw bytes: bash accepts any bytes here.
    pub command: Option<OsString>,
    /// `-i` was given. Whether the shell is actually interactive also depends on the terminal, decided by the caller.
    pub interactive: bool,
    /// `-l`, `--login` or an `argv[0]` starting with `-`.
    pub login: bool,
    /// The remaining operands, unchanged: with `-c` they become `$0`, `$1`, …; without it, bash would treat the
    /// first one as a script.
    pub operands: Vec<OsString>,
}

/// A command-mode invocation that passed every check in its declaration.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedCommand {
    /// The selected command words below the root, e.g. `["policy", "check"]`.
    pub path: Vec<&'static str>,
    /// The options that were given, by long name, with their value (`None` for flags). Each name appears at most
    /// once.
    options: Vec<(&'static str, Option<String>)>,
    /// The positional arguments, one per declared [`Positional`], in order.
    pub positionals: Vec<String>,
    /// The argv after `--`, unchanged (not even required to be UTF-8).
    pub trailing: Vec<OsString>,
}

impl ParsedCommand {
    /// Whether `--json` was given.
    #[must_use]
    pub fn json(&self) -> bool {
        self.flag(JSON)
    }

    /// Whether the option `long` (name without `--`) was given.
    #[must_use]
    pub fn flag(&self, long: &str) -> bool {
        self.options.iter().any(|(name, _)| *name == long)
    }

    /// The value of the option `long` (name without `--`), if it was given and takes a value.
    #[must_use]
    pub fn value(&self, long: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(name, _)| *name == long)
            .and_then(|(_, value)| value.as_deref())
    }
}

/// Why an argv was rejected. Every variant means "nothing runs, exit with [`ArgsError::EXIT_STATUS`]".
///
/// Flag and argument text comes from the user's own command line and is shown back to them so they can see what was
/// wrong; [`Display`](fmt::Display) escapes control characters and truncates long text, so the message cannot
/// rewrite the terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgsError {
    /// A flag that the command does not declare, e.g. `--bogus`, or a shell option other than `-c`, `-i`, `-l`.
    UnknownFlag {
        /// The flag as written, including its dashes (without any `=value`).
        flag: String,
    },
    /// An option that needs a value was last on the line, was followed by another flag, or had an empty `=value`.
    MissingValue {
        /// The option, including its dashes.
        flag: String,
    },
    /// A plain flag was given a value with `--flag=value`.
    UnexpectedValue {
        /// The flag, including its dashes.
        flag: String,
    },
    /// The same option was given twice. Refused instead of letting one silently win.
    DuplicateFlag {
        /// The flag, including its dashes.
        flag: String,
    },
    /// A required option was not given.
    MissingOption {
        /// The option, including its dashes.
        flag: String,
    },
    /// A word that names no command.
    UnknownCommand {
        /// The word as written.
        name: String,
    },
    /// A command group was given without one of its subcommands, e.g. `knsh policy`.
    MissingCommand {
        /// The group's full name, e.g. `knsh policy`.
        group: String,
    },
    /// A declared positional argument was not given.
    MissingArgument {
        /// The positional's declared name.
        name: &'static str,
    },
    /// An argument the command has no place for (an extra positional, or `--` on a command without trailing argv).
    UnexpectedArgument {
        /// The argument as written.
        arg: String,
    },
    /// A command that requires `-- <argv>...` was given none.
    MissingTrailing {
        /// The trailing argv's declared name.
        name: &'static str,
    },
    /// A flag, option value or positional that is not valid UTF-8. Only trailing argv and shell operands may hold
    /// arbitrary bytes.
    NotUtf8 {
        /// The flag whose value was invalid, or `None` when the argument itself was.
        flag: Option<String>,
    },
}

impl ArgsError {
    /// The exit status for every usage error. Matches bash, which exits with 2 on an invalid option.
    pub const EXIT_STATUS: u8 = 2;
}

impl fmt::Display for ArgsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFlag { flag } => write!(f, "unknown option '{}'", Shown(flag)),
            Self::MissingValue { flag } => write!(f, "option '{}' requires a value", Shown(flag)),
            Self::UnexpectedValue { flag } => write!(f, "option '{}' does not take a value", Shown(flag)),
            Self::DuplicateFlag { flag } => write!(f, "option '{}' given more than once", Shown(flag)),
            Self::MissingOption { flag } => write!(f, "missing required option '{}'", Shown(flag)),
            Self::UnknownCommand { name } => write!(f, "unknown command '{}'", Shown(name)),
            Self::MissingCommand { group } => write!(f, "'{}' needs a subcommand", Shown(group)),
            Self::MissingArgument { name } => write!(f, "missing argument <{name}>"),
            Self::UnexpectedArgument { arg } => write!(f, "unexpected argument '{}'", Shown(arg)),
            Self::MissingTrailing { name } => write!(f, "missing '-- <{name}>...'"),
            Self::NotUtf8 { flag: Some(flag) } => write!(f, "value of option '{}' is not valid UTF-8", Shown(flag)),
            Self::NotUtf8 { flag: None } => f.write_str("argument is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ArgsError {}

/// Displays user-supplied text safely inside an error message: control characters are escaped (so an argument
/// cannot inject terminal escape sequences) and anything past [`Shown::MAX_CHARS`] is cut off with `…`.
struct Shown<'a>(&'a str);

impl Shown<'_> {
    /// Longest text shown, in characters. Enough for any real flag or command name.
    const MAX_CHARS: usize = 64;
}

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (count, c) in self.0.chars().enumerate() {
            if count == Self::MAX_CHARS {
                return f.write_str("…");
            }
            if c.is_control() {
                write!(f, "{}", c.escape_default())?;
            } else {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

/// Parses a full `argv` (including `argv[0]`) against the command tree rooted at `root`.
///
/// Shell-mode invocations are recognised first and never reach subcommand parsing (module docs).
///
/// # Errors
///
/// Returns an [`ArgsError`] naming the offending flag or argument for any argv that does not match the
/// declarations. The caller must then run nothing and exit with [`ArgsError::EXIT_STATUS`].
pub fn parse(root: &'static Command, argv: impl IntoIterator<Item = OsString>) -> Result<Invocation, ArgsError> {
    let mut words = argv.into_iter();
    // `login(1)` and terminal emulators start a login shell by prefixing argv[0] with '-' (`-knsh`). An empty argv
    // (possible through `execve`) has no argv[0] and is treated as a plain shell start.
    let login_argv0 = words
        .next()
        .is_some_and(|argv0| argv0.as_encoded_bytes().first() == Some(&b'-'));
    let rest: Vec<OsString> = words.collect();

    if login_argv0 || starts_shell_mode(rest.first()) {
        parse_shell(login_argv0, rest).map(Invocation::Shell)
    } else {
        parse_command(root, rest)
    }
}

/// Whether the first argument after `argv[0]` selects shell mode.
///
/// No argument starts an interactive shell. A single-dash argument is always a bash option cluster (`-c`, `-lc`)
/// or `-`, since commands take long options only; `--` ends bash's options; `--login` is bash's long login flag.
/// Any other `--flag` (`--help`, typos) is left to command mode, which reports unknown ones.
fn starts_shell_mode(first: Option<&OsString>) -> bool {
    let Some(first) = first else { return true };
    match first.as_encoded_bytes() {
        b"--" | b"--login" => true,
        [b'-', b'-', ..] => false,
        [b'-', ..] => true,
        _ => false,
    }
}

/// Classifies a shell-mode argv (without `argv[0]`) following bash's invocation syntax: option clusters up to the
/// first operand, `-` or `--`; with `-c`, the first operand is the command line.
fn parse_shell(login_argv0: bool, args: Vec<OsString>) -> Result<ShellInvocation, ArgsError> {
    let mut shell = ShellInvocation {
        login: login_argv0,
        ..ShellInvocation::default()
    };
    let mut has_command = false;
    let mut args = args.into_iter().peekable();

    while let Some(arg) = args.peek() {
        match arg.as_encoded_bytes() {
            // Both end option processing; bash consumes them.
            b"--" | b"-" => {
                args.next();
                break;
            }
            b"--login" => shell.login = true,
            [b'-', b'-', ..] => return Err(ArgsError::UnknownFlag { flag: lossy_flag(arg) }),
            [b'-', letters @ ..] => {
                for &letter in letters {
                    match shell_option(letter) {
                        Some(ShellOption::Command) => has_command = true,
                        Some(ShellOption::Interactive) => shell.interactive = true,
                        Some(ShellOption::Login) => shell.login = true,
                        // Report just the offending letter, as bash does (`bash: -x: invalid option`).
                        None => {
                            let flag = format!("-{}", String::from_utf8_lossy(&[letter]));
                            return Err(ArgsError::UnknownFlag { flag });
                        }
                    }
                }
            }
            // The first operand ends option processing.
            _ => break,
        }
        args.next();
    }

    shell.operands = args.collect();
    if has_command {
        // bash: "-c: option requires an argument", exit status 2.
        if shell.operands.is_empty() {
            return Err(ArgsError::MissingValue { flag: "-c".to_owned() });
        }
        shell.command = Some(shell.operands.remove(0));
    }
    Ok(shell)
}

/// Looks up a shell option letter in [`SHELL_OPTIONS`].
fn shell_option(letter: u8) -> Option<ShellOption> {
    SHELL_OPTIONS
        .iter()
        .find(|(c, _, _)| *c == char::from(letter))
        .map(|&(_, option, _)| option)
}

/// Parses a command-mode argv (without `argv[0]`): first descends through command groups, then parses the selected
/// leaf's options and arguments.
fn parse_command(root: &'static Command, args: Vec<OsString>) -> Result<Invocation, ArgsError> {
    let mut command = root;
    let mut path: Vec<&'static str> = Vec::new();
    let mut args = args.into_iter();

    // Descend: each group consumes exactly one word, which must name one of its subcommands (or be `--help`).
    while !command.subcommands.is_empty() {
        let Some(arg) = args.next() else {
            return Err(ArgsError::MissingCommand {
                group: full_name(root, &path),
            });
        };
        let word = utf8_arg(arg)?;
        if word == "--help" {
            return Ok(Invocation::Help(help(root, &path, command)));
        }
        if word.starts_with('-') {
            return Err(ArgsError::UnknownFlag {
                flag: flag_name(&word).to_owned(),
            });
        }
        command = command
            .subcommands
            .iter()
            .find(|sub| sub.name == word)
            .ok_or(ArgsError::UnknownCommand { name: word })?;
        path.push(command.name);
    }

    let mut parsed = ParsedCommand {
        path,
        options: Vec::new(),
        positionals: Vec::new(),
        trailing: Vec::new(),
    };

    while let Some(arg) = args.next() {
        if arg == "--" {
            if command.trailing == Trailing::None {
                return Err(ArgsError::UnexpectedArgument { arg: "--".to_owned() });
            }
            // Everything after the separator belongs to the child command, unparsed and unchanged.
            parsed.trailing = args.by_ref().collect();
            break;
        }

        let arg = utf8_arg(arg)?;
        if let Some(body) = arg.strip_prefix("--") {
            let (name, inline_value) = match body.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (body, None),
            };
            let flag = format!("--{name}");
            let spec = command
                .options
                .iter()
                .chain(GLOBAL_OPTIONS)
                .find(|spec| spec.long == name)
                .ok_or_else(|| ArgsError::UnknownFlag { flag: flag.clone() })?;

            if spec.long == HELP {
                if inline_value.is_some() {
                    return Err(ArgsError::UnexpectedValue { flag });
                }
                return Ok(Invocation::Help(help(root, &parsed.path, command)));
            }
            if parsed.flag(spec.long) {
                return Err(ArgsError::DuplicateFlag { flag });
            }

            let value = match (spec.value, inline_value) {
                (None, None) => None,
                (None, Some(_)) => return Err(ArgsError::UnexpectedValue { flag }),
                // `--profile=` is as useless as no value at all.
                (Some(_), Some(value)) if value.is_empty() => return Err(ArgsError::MissingValue { flag }),
                (Some(_), Some(value)) => Some(value),
                (Some(_), None) => Some(next_value(&mut args, &flag)?),
            };
            parsed.options.push((spec.long, value));
        } else if arg.starts_with('-') && arg != "-" {
            // Commands take long options only; short options exist only in shell mode.
            return Err(ArgsError::UnknownFlag { flag: arg });
        } else if parsed.positionals.len() < command.positionals.len() {
            parsed.positionals.push(arg);
        } else {
            return Err(ArgsError::UnexpectedArgument { arg });
        }
    }

    check_complete(command, &parsed)?;
    Ok(Invocation::Command(parsed))
}

/// Converts a flag or positional to UTF-8; only trailing argv and shell operands may hold arbitrary bytes.
fn utf8_arg(arg: OsString) -> Result<String, ArgsError> {
    arg.into_string().map_err(|_| ArgsError::NotUtf8 { flag: None })
}

/// Takes the separate value of an option (`--profile web-app`).
///
/// A following argument that starts with `-` is not taken as the value: `--profile --json` is far more likely a
/// forgotten value than a profile named `--json`, and swallowing the next flag would silently change what runs. A
/// value that really starts with `-` can be given as `--profile=-x`.
fn next_value(args: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<String, ArgsError> {
    let missing = || ArgsError::MissingValue { flag: flag.to_owned() };
    let value = args.next().ok_or_else(missing)?;
    if value.as_encoded_bytes().first() == Some(&b'-') {
        return Err(missing());
    }
    let value = value.into_string().map_err(|_| ArgsError::NotUtf8 {
        flag: Some(flag.to_owned()),
    })?;
    if value.is_empty() {
        return Err(missing());
    }
    Ok(value)
}

/// Checks that everything the leaf `command` requires was given.
fn check_complete(command: &Command, parsed: &ParsedCommand) -> Result<(), ArgsError> {
    if let Some(missing) = command.positionals.get(parsed.positionals.len()) {
        return Err(ArgsError::MissingArgument { name: missing.name });
    }
    if let Some(missing) = command
        .options
        .iter()
        .find(|spec| spec.required && !parsed.flag(spec.long))
    {
        return Err(ArgsError::MissingOption {
            flag: format!("--{}", missing.long),
        });
    }
    match command.trailing {
        Trailing::Required(name) if parsed.trailing.is_empty() => Err(ArgsError::MissingTrailing { name }),
        Trailing::Required(_) | Trailing::None => Ok(()),
    }
}

/// The part of a long flag before any `=value`, for error messages.
fn flag_name(arg: &str) -> &str {
    arg.split_once('=').map_or(arg, |(name, _)| name)
}

/// A non-UTF-8-safe rendering of a long flag (without its `=value`), for error messages.
fn lossy_flag(arg: &OsString) -> String {
    flag_name(&arg.to_string_lossy()).to_owned()
}

/// The full command name for `path`, e.g. `knsh policy check`.
fn full_name(root: &Command, path: &[&str]) -> String {
    std::iter::once(root.name)
        .chain(path.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generates the help text for `command`, reached from `root` through `path`, from its declaration alone.
#[must_use]
pub fn help(root: &Command, path: &[&str], command: &Command) -> String {
    Help {
        name: full_name(root, path),
        is_root: path.is_empty(),
        command,
    }
    .to_string()
}

/// The help page of one command, rendered by [`Display`](fmt::Display).
struct Help<'a> {
    /// The command's full name, e.g. `knsh policy check`.
    name: String,
    /// Whether this is the root, whose page also documents shell mode.
    is_root: bool,
    /// The command's declaration.
    command: &'a Command,
}

impl fmt::Display for Help<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { name, is_root, command } = self;
        writeln!(f, "{}\n", command.about)?;

        if *is_root {
            // The root also documents shell mode, from the same SHELL_OPTIONS table the shell parser uses.
            let letters: String = SHELL_OPTIONS.iter().map(|(c, _, _)| *c).collect();
            writeln!(f, "Usage: {name} [-{letters}] [<command line>] [<arg>...]")?;
            writeln!(f, "       {name} <command> [options]\n\nShell options:")?;
            write_rows(f, SHELL_OPTIONS.iter().map(|(c, _, help)| (format!("-{c}"), *help)))?;
        } else {
            writeln!(f, "Usage: {}", Usage { name, command })?;
        }

        if !command.subcommands.is_empty() {
            writeln!(f, "\nCommands:")?;
            write_rows(
                f,
                command.subcommands.iter().map(|sub| (sub.name.to_owned(), sub.about)),
            )?;
            return writeln!(f, "\nRun '{name} <command> --help' for a command's options.");
        }

        if !command.positionals.is_empty() {
            writeln!(f, "\nArguments:")?;
            write_rows(f, command.positionals.iter().map(|p| (format!("<{}>", p.name), p.help)))?;
        }

        writeln!(f, "\nOptions:")?;
        write_rows(
            f,
            command
                .options
                .iter()
                .chain(GLOBAL_OPTIONS)
                .map(|spec| (option_syntax(spec), spec.help)),
        )
    }
}

/// The one-line usage of a leaf command: required options, positionals, `[options]` and trailing argv.
struct Usage<'a> {
    /// The command's full name.
    name: &'a str,
    /// The command's declaration.
    command: &'a Command,
}

impl fmt::Display for Usage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)?;
        if !self.command.subcommands.is_empty() {
            // A group takes nothing but the word that selects one of its subcommands.
            return f.write_str(" <command>");
        }
        for spec in self.command.options.iter().filter(|spec| spec.required) {
            write!(f, " {}", option_syntax(spec))?;
        }
        for positional in self.command.positionals {
            write!(f, " <{}>", positional.name)?;
        }
        f.write_str(" [options]")?;
        match self.command.trailing {
            Trailing::Required(trailing) => write!(f, " -- <{trailing}>..."),
            Trailing::None => Ok(()),
        }
    }
}

/// How an option is written: `--json`, `--profile <p>`.
fn option_syntax(spec: &OptionSpec) -> String {
    match spec.value {
        Some(value) => format!("--{} <{value}>", spec.long),
        None => format!("--{}", spec.long),
    }
}

/// Writes two-column rows, aligning the second column.
fn write_rows<'a>(f: &mut fmt::Formatter<'_>, rows: impl Iterator<Item = (String, &'a str)>) -> fmt::Result {
    let rows: Vec<(String, &str)> = rows.collect();
    let width = rows.iter().map(|(left, _)| left.chars().count()).max().unwrap_or(0);
    for (left, right) in rows {
        writeln!(f, "  {left:<width$}  {right}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::commands::KNSH;

    /// Builds an argv from string literals, with `knsh` as `argv[0]`.
    fn argv(args: &[&str]) -> Vec<OsString> {
        std::iter::once("knsh")
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect()
    }

    fn command(args: &[&str]) -> ParsedCommand {
        match parse(&KNSH, argv(args)) {
            Ok(Invocation::Command(parsed)) => parsed,
            other => panic!("expected a command for {args:?}, got {other:?}"),
        }
    }

    fn shell(argv: Vec<OsString>) -> ShellInvocation {
        match parse(&KNSH, argv) {
            Ok(Invocation::Shell(shell)) => shell,
            other => panic!("expected shell mode, got {other:?}"),
        }
    }

    fn error(args: &[&str]) -> ArgsError {
        match parse(&KNSH, argv(args)) {
            Err(error) => error,
            other => panic!("expected an error for {args:?}, got {other:?}"),
        }
    }

    fn unknown_flag(flag: &str) -> ArgsError {
        ArgsError::UnknownFlag { flag: flag.to_owned() }
    }

    fn help_text(args: &[&str]) -> String {
        match parse(&KNSH, argv(args)) {
            Ok(Invocation::Help(text)) => text,
            other => panic!("expected help for {args:?}, got {other:?}"),
        }
    }

    /// Every leaf command with its full path, found by walking the declarations.
    fn leaves() -> Vec<(Vec<&'static str>, &'static Command)> {
        fn walk(
            command: &'static Command,
            path: &[&'static str],
            out: &mut Vec<(Vec<&'static str>, &'static Command)>,
        ) {
            for sub in command.subcommands {
                let mut sub_path = path.to_vec();
                sub_path.push(sub.name);
                if sub.subcommands.is_empty() {
                    out.push((sub_path, sub));
                } else {
                    walk(sub, &sub_path, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(&KNSH, &[], &mut out);
        out
    }

    /// The minimal argv that satisfies a leaf's declaration: its path, a value for each positional and required
    /// option, and trailing argv if it takes one.
    fn minimal_args(path: &[&'static str], command: &Command) -> Vec<String> {
        let mut args: Vec<String> = path.iter().map(|word| (*word).to_owned()).collect();
        args.extend(command.positionals.iter().map(|p| format!("x-{}", p.name)));
        for spec in command.options.iter().filter(|spec| spec.required) {
            args.push(format!("--{}", spec.long));
            if spec.value.is_some() {
                args.push("v".to_owned());
            }
        }
        if let Trailing::Required(_) = command.trailing {
            args.extend(["--".to_owned(), "true".to_owned()]);
        }
        args
    }

    // KNSH-009 acceptance: trailing argv after `--` is untouched (specs/06-api/cli.md, `knsh agent`).
    #[test]
    fn double_dash_passes_remaining_argv_unchanged() {
        let parsed = command(&["agent", "--profile", "web-app", "--", "claude", "--flag"]);
        assert_eq!(parsed.path, ["agent"]);
        assert_eq!(parsed.value("profile"), Some("web-app"));
        assert_eq!(parsed.trailing, [OsString::from("claude"), OsString::from("--flag")]);

        // Flags, a second `--`, `--help` and `--json` after the separator are the child's, not ours.
        let parsed = command(&["agent", "--", "claude", "--", "--help", "--json", "-c", "x"]);
        assert!(!parsed.json());
        assert_eq!(
            parsed.trailing,
            ["claude", "--", "--help", "--json", "-c", "x"].map(OsString::from)
        );
    }

    #[cfg(unix)]
    #[test]
    fn trailing_argv_may_hold_arbitrary_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let raw = OsString::from_vec(vec![0xff, b'a', 0x00, b'\n']);
        let mut args = argv(&["agent", "--"]);
        args.push(raw.clone());
        match parse(&KNSH, args) {
            Ok(Invocation::Command(parsed)) => assert_eq!(parsed.trailing, [raw]),
            other => panic!("unexpected {other:?}"),
        }
    }

    // KNSH-009 acceptance; specs/06-api/cli.md: "Every command takes `--json`".
    #[test]
    fn json_flag_accepted_by_every_subcommand() {
        let leaves = leaves();
        // The 16 leaf commands of specs/06-api/cli.md; a mismatch means the table and the page have drifted.
        assert_eq!(
            leaves.len(),
            16,
            "{:?}",
            leaves.iter().map(|(p, _)| p).collect::<Vec<_>>()
        );
        for (path, leaf) in leaves {
            let args = minimal_args(&path, leaf);
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            assert!(!command(&refs).json(), "{path:?} without --json");

            // `--json` goes before any `--`, which hands everything after it to the child.
            let mut with_json = refs.clone();
            let at = with_json.iter().position(|a| *a == "--").unwrap_or(with_json.len());
            with_json.insert(at, "--json");
            assert!(command(&with_json).json(), "{path:?} rejects --json");
        }
    }

    // KNSH-009 acceptance: fail safe. An error is returned (so nothing runs) and names the flag.
    #[test]
    fn unknown_flag_is_error_and_runs_nothing() {
        let err = error(&["history", "--bogus"]);
        assert_eq!(err, unknown_flag("--bogus"));
        assert!(err.to_string().contains("--bogus"));
        assert_eq!(ArgsError::EXIT_STATUS, 2);

        assert_eq!(error(&["agent", "--bogus=1", "--", "x"]), unknown_flag("--bogus"));
        assert_eq!(error(&["history", "-x"]), unknown_flag("-x"));
        assert_eq!(error(&["--bogus"]), unknown_flag("--bogus"));
        assert_eq!(error(&["policy", "--json"]), unknown_flag("--json"));
        // An option of another command is unknown here.
        assert_eq!(error(&["history", "--profile", "p"]), unknown_flag("--profile"));
    }

    // KNSH-009 acceptance: a missing value is an error naming the flag.
    #[test]
    fn missing_value_is_error_naming_the_flag() {
        let missing = ArgsError::MissingValue {
            flag: "--profile".to_owned(),
        };
        assert_eq!(error(&["agent", "--profile"]), missing);
        assert_eq!(error(&["agent", "--profile", "--", "claude"]), missing);
        assert_eq!(error(&["agent", "--profile", "--json", "--", "claude"]), missing);
        assert_eq!(error(&["agent", "--profile=", "--", "claude"]), missing);
        assert!(missing.to_string().contains("--profile"));

        // A value that starts with '-' is still possible, explicitly.
        assert_eq!(
            command(&["agent", "--profile=-x", "--", "c"]).value("profile"),
            Some("-x")
        );
        assert_eq!(
            command(&["agent", "--profile=a=b", "--", "c"]).value("profile"),
            Some("a=b")
        );
    }

    #[test]
    fn other_usage_errors_are_rejected() {
        assert_eq!(
            error(&["history", "--json=yes"]),
            ArgsError::UnexpectedValue {
                flag: "--json".to_owned()
            }
        );
        assert_eq!(
            error(&["history", "--json", "--json"]),
            ArgsError::DuplicateFlag {
                flag: "--json".to_owned()
            }
        );
        assert_eq!(
            error(&["agent", "--profile", "a", "--profile", "b", "--", "c"]),
            ArgsError::DuplicateFlag {
                flag: "--profile".to_owned()
            }
        );
        assert_eq!(
            error(&["frobnicate"]),
            ArgsError::UnknownCommand {
                name: "frobnicate".to_owned()
            }
        );
        assert_eq!(
            error(&["policy"]),
            ArgsError::MissingCommand {
                group: "knsh policy".to_owned()
            }
        );
        assert_eq!(
            error(&["policy", "nope"]),
            ArgsError::UnknownCommand {
                name: "nope".to_owned()
            }
        );
        assert_eq!(error(&["approve"]), ArgsError::MissingArgument { name: "request_id" });
        assert_eq!(
            error(&["approve", "a", "b"]),
            ArgsError::UnexpectedArgument { arg: "b".to_owned() }
        );
        assert_eq!(
            error(&["history", "--"]),
            ArgsError::UnexpectedArgument { arg: "--".to_owned() }
        );
        assert_eq!(error(&["agent"]), ArgsError::MissingTrailing { name: "command" });
        assert_eq!(error(&["agent", "--"]), ArgsError::MissingTrailing { name: "command" });
        // The agent command must be separated by `--`, so its flags can never be mistaken for ours.
        assert_eq!(
            error(&["agent", "claude"]),
            ArgsError::UnexpectedArgument {
                arg: "claude".to_owned()
            }
        );
        assert_eq!(
            error(&["authority", "trust", "--team-id", "T", "--identifier", "i"]),
            ArgsError::MissingOption {
                flag: "--min-version".to_owned()
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_flags_and_values_are_rejected() {
        use std::os::unix::ffi::OsStringExt;
        let bad = || OsString::from_vec(vec![b'-', b'-', 0xff]);
        let mut args = argv(&["history"]);
        args.push(bad());
        assert_eq!(parse(&KNSH, args), Err(ArgsError::NotUtf8 { flag: None }));

        let mut args = argv(&["agent", "--profile"]);
        args.push(OsString::from_vec(vec![b'p', 0xff]));
        assert_eq!(
            parse(&KNSH, args),
            Err(ArgsError::NotUtf8 {
                flag: Some("--profile".to_owned())
            })
        );

        let mut args = argv(&[]);
        args.push(OsString::from_vec(vec![b'h', 0xff]));
        assert_eq!(parse(&KNSH, args), Err(ArgsError::NotUtf8 { flag: None }));
    }

    // KNSH-009 acceptance: shell-mode argv is classified before subcommand parsing.
    #[test]
    fn dash_c_is_shell_mode_not_subcommand() {
        let parsed = shell(argv(&["-c", "history"]));
        assert_eq!(parsed.command, Some(OsString::from("history")));
        assert_eq!(parsed.operands, Vec::<OsString>::new());
        assert!(!parsed.login && !parsed.interactive);

        // `$0` and positional parameters follow the command line, as in bash.
        let parsed = shell(argv(&["-c", "echo \"$1\"", "name", "--json"]));
        assert_eq!(parsed.command, Some(OsString::from("echo \"$1\"")));
        assert_eq!(parsed.operands, [OsString::from("name"), OsString::from("--json")]);

        // Clusters and separate options, in any order, before the command line.
        let parsed = shell(argv(&["-lc", "agent"]));
        assert_eq!(parsed.command, Some(OsString::from("agent")));
        assert!(parsed.login);
        let parsed = shell(argv(&["-i", "-c", "--", "-not-a-flag"]));
        assert!(parsed.interactive);
        assert_eq!(parsed.command, Some(OsString::from("-not-a-flag")));

        assert_eq!(error(&["-c"]), ArgsError::MissingValue { flag: "-c".to_owned() });
        assert_eq!(error(&["-x", "history"]), unknown_flag("-x"));
        assert_eq!(error(&["-cz", "true"]), unknown_flag("-z"));
        assert_eq!(error(&["-l", "--norc"]), unknown_flag("--norc"));
    }

    // KNSH-009 acceptance: login shell detection.
    #[test]
    fn login_argv0_dash_prefix_detected() {
        let login = shell(vec![OsString::from("-knsh")]);
        assert!(login.login);
        assert_eq!(
            login,
            ShellInvocation {
                login: true,
                ..ShellInvocation::default()
            }
        );

        // A login argv[0] wins over anything that looks like a subcommand.
        let login = shell(vec![OsString::from("-knsh"), OsString::from("history")]);
        assert!(login.login && login.command.is_none());
        assert_eq!(login.operands, [OsString::from("history")]);

        assert!(shell(argv(&["-l"])).login);
        assert!(shell(argv(&["--login"])).login);
        assert!(shell(argv(&["--login", "-c", "true"])).login);
    }

    #[test]
    fn plain_shell_starts_are_shell_mode() {
        assert_eq!(shell(argv(&[])), ShellInvocation::default());
        assert_eq!(shell(Vec::new()), ShellInvocation::default());
        assert_eq!(shell(argv(&["-"])), ShellInvocation::default());
        assert_eq!(shell(argv(&["--", "script"])).operands, [OsString::from("script")]);
        assert!(shell(argv(&["-i"])).interactive);
    }

    // KNSH-009 acceptance: help is generated from the same declarations the parser uses.
    #[test]
    fn help_is_generated_from_declarations() {
        let top = help_text(&["--help"]);
        for sub in KNSH.subcommands {
            assert!(
                top.contains(sub.name) && top.contains(sub.about),
                "top-level help misses {}",
                sub.name
            );
        }
        for (letter, _, about) in SHELL_OPTIONS {
            assert!(top.contains(&format!("-{letter}")) && top.contains(about));
        }

        for (path, leaf) in leaves() {
            let mut args = path.clone();
            args.push("--help");
            let text = help_text(&args);
            assert!(text.contains(&format!("knsh {}", path.join(" "))), "{path:?}");
            assert!(text.contains(leaf.about), "{path:?}");
            for spec in leaf.options.iter().chain(GLOBAL_OPTIONS) {
                assert!(
                    text.contains(&format!("--{}", spec.long)) && text.contains(spec.help),
                    "{path:?}"
                );
                if let Some(value) = spec.value {
                    assert!(text.contains(&format!("<{value}>")), "{path:?}");
                }
            }
            for positional in leaf.positionals {
                assert!(text.contains(&format!("<{}>", positional.name)), "{path:?}");
            }
        }

        let agent = help_text(&["agent", "--help"]);
        assert!(agent.contains("Usage: knsh agent [options] -- <command>..."), "{agent}");
        assert!(help_text(&["policy", "--help"]).contains("check"));
        assert!(help_text(&["policy", "--help"]).contains("Usage: knsh policy <command>\n"));
        // `--help` wins over missing required arguments, but not over earlier errors.
        help_text(&["approve", "--help"]);
        assert_eq!(error(&["history", "--bogus", "--help"]), unknown_flag("--bogus"));
        assert_eq!(
            error(&["history", "--help=x"]),
            ArgsError::UnexpectedValue {
                flag: "--help".to_owned()
            }
        );
    }

    #[test]
    fn declarations_are_well_formed() {
        fn check(command: &Command, seen_paths: &mut Vec<String>, prefix: &str) {
            let mut names: Vec<&str> = command.options.iter().map(|spec| spec.long).collect();
            names.extend(GLOBAL_OPTIONS.iter().map(|spec| spec.long));
            let count = names.len();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), count, "duplicate option in {prefix}");
            for name in names {
                assert!(
                    !name.is_empty() && !name.contains('=') && !name.starts_with('-'),
                    "{prefix}: {name}"
                );
            }
            if !command.subcommands.is_empty() {
                assert!(
                    command.options.is_empty() && command.positionals.is_empty(),
                    "group {prefix} has args"
                );
                assert_eq!(command.trailing, Trailing::None, "group {prefix} has trailing argv");
            }
            for sub in command.subcommands {
                assert!(
                    !sub.name.starts_with('-') && !sub.name.is_empty(),
                    "{prefix}: {}",
                    sub.name
                );
                let path = format!("{prefix} {}", sub.name);
                assert!(!seen_paths.contains(&path), "duplicate command {path}");
                seen_paths.push(path.clone());
                check(sub, seen_paths, &path);
            }
        }
        check(&KNSH, &mut Vec::new(), "knsh");
    }

    #[test]
    fn error_messages_escape_control_characters_and_truncate() {
        let error = ArgsError::UnknownFlag {
            flag: "--\u{1b}[2J".to_owned(),
        };
        assert!(!error.to_string().contains('\u{1b}'));
        let long = ArgsError::UnknownCommand { name: "a".repeat(1000) };
        assert!(long.to_string().len() < 100);
    }

    /// Deterministic exhaustive sweep over short argvs built from tricky tokens: parsing never panics, and
    /// whatever is accepted is consistent with the declarations.
    #[test]
    fn parser_never_panics_on_token_combinations() {
        const TOKENS: &[&str] = &[
            "agent",
            "policy",
            "check",
            "approve",
            "--",
            "-",
            "--json",
            "--profile",
            "--profile=",
            "-c",
            "-lc",
            "--help",
            "x",
            "",
            "=",
            "--=",
            "---",
            "-cl",
            "--login",
            "--with-checkpoints",
        ];
        let optional = || std::iter::once(None).chain(TOKENS.iter().copied().map(Some));
        for &first in TOKENS {
            for second in optional() {
                for third in optional() {
                    let args: Vec<&str> = [Some(first), second, third].into_iter().flatten().collect();
                    // Whatever is accepted as a command selected one: the root itself is never a runnable command.
                    if let Ok(Invocation::Command(parsed)) = parse(&KNSH, argv(&args)) {
                        assert_ne!(parsed.path, Vec::<&str>::new(), "{args:?}");
                    }
                }
            }
        }
    }
}
