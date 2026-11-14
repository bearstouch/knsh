//! The classifier: wrappers unwrapped and dynamic code marked, per simple command (KNSH-036; FR-LC-04, FR-LC-05,
//! FR-POL-20, FR-POL-21, decision 6).
//!
//! [`classify`] starts from the parser's [`ParseOutcome`] and gives every simple command of the line, at any depth,
//! one [`ClassifiedCommand`] with the class its record shows (`argv[].class`: `static`, `wrapper`, `dynamic`,
//! `project_executable`; `specs/05-models/execution-record.md`):
//!
//! - **Wrappers** (FR-LC-04): `env FOO=1 nice -n 5 git push` gives three entries, `env` and `nice` as
//!   [`CommandClass::Wrapper`] and `git` classified as if run directly, each linked to the wrapper that runs it
//!   ([`ClassifiedCommand::wrapper`]). Wrappers nest; the `time` keyword wraps every command of its pipeline. Each
//!   wrapper's option grammar is explicit (`wrappers`), and an option outside it makes the command dynamic, never
//!   mis-parsed. `command -v x` runs nothing. `xargs` runs its command (or `echo`) with arguments read at run time,
//!   so that command's arguments are marked incomplete ([`ClassifiedCommand::arguments_complete`]) and any rule
//!   that depends on them must treat them as unknown.
//! - **Dynamic code** (FR-LC-05): a command is [`CommandClass::Dynamic`] with a [`DynamicReason`] from a closed set
//!   for `eval`; `source` or `.` of a file under the session's write roots or not resolvable; a shell or interpreter
//!   given code with `-c`/`-e` (or a code subcommand), or no script so it reads standard input; a command name built
//!   from an expansion; a here-document fed to an interpreter (KNSH-031); a wrapper option outside its grammar or
//!   built from an expansion. Builtins that store code for bash to run later are `eval` too: `trap` with an action,
//!   `mapfile -C` and `alias` with a value. A variable whose value a shell or program runs as code (`BASH_ENV`,
//!   `PS4`, `NODE_OPTIONS`, `GIT_PAGER`, …; [`CODE_VARIABLES`]) set for a command, by `env` or by `export` and its
//!   kin makes that command dynamic ([`CodeVariable`](DynamicReason::CodeVariable)). Everything
//!   [`parse_line`](crate::parse_line) marks dynamic stays dynamic (KNSH-032). Dynamic code never inherits classes
//!   (FR-POL-20): the entry carries no program class, only its reason.
//!
//! Interpreters are recognised by their family ([`Interpreters`], data a profile can extend): the base name of the
//! **resolved** binary with any version suffix removed, so a `py` alias resolving to `python3.12` is `python`. The
//! name as written is checked too, so a resolution to an unexpected base name can only add a dynamic mark, never
//! remove one. Running a script file (`python3 script.py`) is not dynamic; it is classified by the interpreter's own
//! resolution, `static` or `project_executable`.
//!
//! # Effects
//!
//! Pure: the filesystem and the session are reached only through the caller's [`Resolver`], which resolves names
//! (KNSH-035's `resolve` in `knsh-core`) and judges files read by `source`. The same inputs always give the same
//! classification.
//!
//! # Fail closed
//!
//! Every gap leans towards dynamic: a line the parser could not read has no commands and is dynamic as a whole;
//! an unknown option, an expansion where a wrapper's command or an interpreter's script would be, or arguments only
//! known at run time make the command dynamic. Wrapper names are matched by the resolved binary's base name and the
//! name as written, so a renamed wrapper is still unwrapped; a wrapper found outside the trusted folders is unwrapped
//! too, but keeps class `project_executable`, so `exec.project_executables` still governs it, and a name that only
//! *reads* like a wrapper (a `nice` that resolves to `/bin/rm`) is unwrapped but keeps its program's class, so name
//! rules still see what really runs. An interpreter is checked before a wrapper, so a name that is both cannot hide
//! code. Bash evaluates array subscripts in arithmetic, so a quoted `'a[$(cmd)]'` given to `printf -v`, `let`,
//! `read` and other builtins runs `cmd`; that is not detected here. A classification is an
//! intent filter, never a security boundary: dynamic code's network and secrets are limited by the sandbox and the
//! proxy (FR-POL-21).

use std::path::{Path, PathBuf};

use crate::ast::{Command, CommandWord, DeepCommand, SimpleCommand, TimeKeyword};
use crate::functions::static_text;
use crate::interpreter_table::{ArgumentText, Interpreter, InterpreterRun, Interpreters};
use crate::outcome::{DynamicPart, DynamicReason, ParseOutcome, command_name_text};
use crate::token::{SegmentKind, Span, Word};
use crate::wrappers::{Unwrap, Wrapper, Xargs};

/// What the classifier asks of the session: name resolution and the trust of files read by `source`.
///
/// `knsh-core` implements it over KNSH-035's `resolve` and the profile's write roots and trusted folders; tests use a
/// fake. Every answer may be the cautious one (`NotFound`, [`SourceFile::Unresolved`]): that only makes a line fail or
/// be dynamic.
pub trait Resolver {
    /// What `name` (after quote removal; never a function call, which the parser marks) runs, looked up as `lookup`
    /// says. Never returns [`Program::Function`].
    fn resolve(&self, name: &str, lookup: Lookup) -> Program;

    /// How far a file `source` or `.` reads can be trusted. `path` is the operand as written after quote removal;
    /// a name without `/` is searched on `PATH`, then in the working directory, as bash does.
    ///
    /// [`SourceFile::Trusted`] only if the file was resolved to a canonical path, is readable, is outside every write
    /// root of the session and sits in a trusted location. Anything else is dynamic code.
    fn source_file(&self, path: &str) -> SourceFile;
}

/// How a command name is looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lookup {
    /// As bash looks up a command name: builtins, then `PATH` (functions are decided by the parser). Also how
    /// `command` and `builtin` find theirs, which never reach functions.
    Shell,
    /// As `execvp` does, for a program run by a wrapper program or `exec`: `PATH` only, never a builtin.
    Program,
}

/// What a command name resolves to (KNSH-035's `Resolution`, without the crate dependency).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Program {
    /// A binary in a trusted folder, by canonical path: name rules match it.
    Trusted(PathBuf),
    /// A binary anywhere else, by canonical path: governed by `exec.project_executables`.
    ProjectExecutable(PathBuf),
    /// A bash builtin.
    Builtin,
    /// A function defined earlier in the line; its body is classified separately.
    Function,
    /// Nothing to run: the line fails with 127.
    NotFound,
}

impl Program {
    /// The binary's canonical path, for [`Trusted`](Self::Trusted) and
    /// [`ProjectExecutable`](Self::ProjectExecutable).
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Trusted(path) | Self::ProjectExecutable(path) => Some(path),
            Self::Builtin | Self::Function | Self::NotFound => None,
        }
    }

    /// The class of a command that runs this program and is neither a wrapper nor dynamic code.
    const fn class(&self) -> CommandClass {
        match self {
            Self::ProjectExecutable(_) => CommandClass::ProjectExecutable,
            Self::Trusted(_) | Self::Builtin | Self::Function | Self::NotFound => CommandClass::Static,
        }
    }

    /// The class of a wrapper running this program: `wrapper`, except outside the trusted folders, where
    /// `project_executables` must still decide it.
    const fn wrapper_class(&self) -> CommandClass {
        match self {
            Self::ProjectExecutable(_) => CommandClass::ProjectExecutable,
            Self::Trusted(_) | Self::Builtin | Self::Function | Self::NotFound => CommandClass::Wrapper,
        }
    }
}

/// How far a file read by `source` or `.` can be trusted (FR-LC-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceFile {
    /// Resolved, readable, outside every write root and in a trusted location: not dynamic.
    Trusted,
    /// Under one of the session's write roots: the agent could have written it. Dynamic.
    AgentWritable,
    /// Not found, not readable, or not resolvable to a canonical path. Dynamic.
    Unresolved,
}

/// A command's class, as its record shows it (`argv[].class`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandClass {
    /// A binary from a trusted folder, matched by name rules; also builtins, function calls and names not found.
    Static,
    /// A known wrapper that was unwrapped; the command it runs has its own entry.
    Wrapper,
    /// A binary from an agent-writable place, governed by `exec.project_executables`.
    ProjectExecutable,
    /// Dynamic code: never inherits classes, network limited to `network.hosts`, no secrets (FR-POL-20, FR-POL-21).
    Dynamic {
        /// Why.
        reason: DynamicReason,
    },
}

impl CommandClass {
    /// The class's name in records: `static`, `wrapper`, `project_executable` or `dynamic`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Wrapper => "wrapper",
            Self::ProjectExecutable => "project_executable",
            Self::Dynamic { .. } => "dynamic",
        }
    }

    /// Whether the command is dynamic code.
    #[must_use]
    pub const fn is_dynamic(self) -> bool {
        matches!(self, Self::Dynamic { .. })
    }
}

/// One argument of a classified command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argument {
    /// The text after quote removal, or `None` when it is built from an expansion.
    pub text: Option<String>,
    /// Where it is on the line (see [`ClassifiedCommand::span`]).
    pub span: Span,
}

/// One entry of a line's `argv`: a simple command, a wrapper or the command a wrapper runs (KNSH-036).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedCommand {
    /// The command name after quote removal, or `None` when it is built from an expansion.
    pub name: Option<String>,
    /// Where the name is on the line; `None` for the `echo` that `xargs` runs when given no command.
    pub name_span: Option<Span>,
    /// The arguments: for a wrapper, its own (options, assignments, a duration) up to the command it runs; otherwise
    /// every word after the name.
    pub arguments: Vec<Argument>,
    /// `false` when the command receives more arguments at run time (the command `xargs` runs, and anything it
    /// wraps): argument-sensitive rules must treat its arguments as unknown.
    pub arguments_complete: bool,
    /// What the name resolved to; `None` when the name is not known from the line, or for `eval` and `source`,
    /// which are not resolved.
    pub program: Option<Program>,
    /// The class.
    pub class: CommandClass,
    /// The index (in [`Classification::commands`]) of the wrapper running this command, if any.
    pub wrapper: Option<usize>,
    /// The command on the line: the whole simple command for the outermost entry, from the name to the end for one a
    /// wrapper runs, and the keyword for `time`. Spans index the line; inside a backtick substitution bash
    /// un-escapes before reading, every span is that substitution's.
    pub span: Span,
}

/// Every simple command of a line classified, and the line's dynamic parts (KNSH-036). Built only by [`classify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// The entries in source order: each wrapper before the command it runs, each command before those in its
    /// substitutions.
    commands: Vec<ClassifiedCommand>,
    /// Every dynamic part of the line, in source order without duplicates.
    parts: Vec<DynamicPart>,
    /// Whether the parser could not read the line, which is then dynamic as a whole and has no entries.
    whole_line: bool,
}

impl Classification {
    /// The `argv` entries, in source order.
    #[must_use]
    pub fn commands(&self) -> &[ClassifiedCommand] {
        &self.commands
    }

    /// The dynamic parts of the line, in source order: the parser's (KNSH-032), less `source` of trusted files, plus
    /// the classifier's.
    #[must_use]
    pub fn dynamic_parts(&self) -> &[DynamicPart] {
        &self.parts
    }

    /// Whether any part of the line is dynamic code.
    #[must_use]
    pub fn is_dynamic(&self) -> bool {
        !self.parts.is_empty()
    }

    /// Whether the parser could not read the line, so it is dynamic as a whole and has no entries.
    #[must_use]
    pub const fn is_whole_line(&self) -> bool {
        self.whole_line
    }
}

/// Classifies every simple command of a parsed line: unwraps wrappers and marks dynamic code (see the module
/// documentation). `input` is the line `outcome` was parsed from.
///
/// Never fails: anything it cannot read is dynamic.
///
/// # Example
///
/// ```
/// use std::path::PathBuf;
/// use knsh_bash::{
///     classify, parse_line, CommandClass, DynamicReason, Interpreters, Lookup, Program, Resolver, SourceFile,
/// };
///
/// struct Session;
/// impl Resolver for Session {
///     fn resolve(&self, name: &str, _lookup: Lookup) -> Program {
///         Program::Trusted(PathBuf::from("/usr/bin").join(name))
///     }
///     fn source_file(&self, _path: &str) -> SourceFile {
///         SourceFile::Unresolved
///     }
/// }
///
/// let line = "env FOO=1 nice -n 5 git push && bash -c \"$x\"";
/// let classes = classify(&parse_line(line), line, &Session, &Interpreters::defaults());
/// let found: Vec<_> = classes.commands().iter().map(|c| (c.name.as_deref(), c.class)).collect();
/// assert_eq!(found, [
///     (Some("env"), CommandClass::Wrapper),
///     (Some("nice"), CommandClass::Wrapper),
///     (Some("git"), CommandClass::Static),
///     (Some("bash"), CommandClass::Dynamic { reason: DynamicReason::InterpreterCode }),
/// ]);
/// ```
#[must_use]
pub fn classify<R: Resolver + ?Sized>(
    outcome: &ParseOutcome,
    input: &str,
    resolver: &R,
    interpreters: &Interpreters,
) -> Classification {
    let Some(script) = outcome.script() else {
        return Classification {
            commands: Vec::new(),
            parts: outcome.dynamic_parts().to_vec(),
            whole_line: true,
        };
    };
    // `source` is decided again below, with the resolver; every other reason of the parser stands.
    let parts = outcome
        .dynamic_parts()
        .iter()
        .filter(|part| part.reason != DynamicReason::Source)
        .copied()
        .collect();
    let mut classifier = Classifier {
        resolver,
        interpreters,
        commands: Vec::new(),
        parts,
        timed: Vec::new(),
        code_variable: None,
    };
    for deep in script.deep_commands(input) {
        let parent = deep.time.map(|time| classifier.time_keyword(time, &deep));
        if let Command::Simple(simple) = deep.command {
            classifier.simple(simple, &deep, parent);
        }
    }
    let mut parts = classifier.parts;
    parts.sort_by_key(|part| (part.span.start, part.span.end));
    parts.dedup();
    Classification {
        commands: classifier.commands,
        parts,
        whole_line: false,
    }
}

/// The classification being built.
struct Classifier<'a, R: ?Sized> {
    /// Name resolution and `source` trust.
    resolver: &'a R,
    /// The interpreter families.
    interpreters: &'a Interpreters,
    /// The entries so far.
    commands: Vec<ClassifiedCommand>,
    /// The dynamic parts so far, unsorted.
    parts: Vec<DynamicPart>,
    /// The `time` keywords given an entry, by the text their spans index and the keyword's span, with the entry's
    /// index: every command of a timed pipeline links to the same entry.
    timed: Vec<((*const u8, Span), usize)>,
    /// Where the simple command being classified sets a [code variable](CODE_VARIABLES), before its name or as an
    /// `env` operand: every command it runs is dynamic.
    code_variable: Option<Span>,
}

/// The command a wrapper runs, as the unwrapping reaches it.
struct Inner<'a> {
    /// Where its name is among the simple command's words.
    start: usize,
    /// How its name is looked up.
    lookup: Lookup,
    /// The wrapper running it.
    parent: Option<usize>,
    /// Set under `xargs`: the arguments are incomplete, and words holding the placeholder are only known at run time.
    xargs: Option<Xargs>,
    /// The words of the simple command.
    words: &'a [CommandWord],
}

impl<R: Resolver + ?Sized> Classifier<'_, R> {
    /// The entry for a `time` keyword, made when the first command of its pipeline is reached.
    fn time_keyword(&mut self, time: TimeKeyword, deep: &DeepCommand<'_>) -> usize {
        let key = (deep.source.as_ptr(), time.keyword);
        if let Some((_, index)) = self.timed.iter().find(|(seen, _)| *seen == key) {
            return *index;
        }
        let index = self.commands.len();
        self.commands.push(ClassifiedCommand {
            name: Some("time".to_owned()),
            name_span: Some(deep.on_line(time.keyword)),
            arguments: time
                .posix
                .map(|posix| Argument {
                    text: Some("-p".to_owned()),
                    span: deep.on_line(posix),
                })
                .into_iter()
                .collect(),
            arguments_complete: true,
            program: Some(Program::Builtin),
            class: CommandClass::Wrapper,
            wrapper: None,
            span: deep.on_line(time.span()),
        });
        self.timed.push((key, index));
        index
    }

    /// Classifies one simple command, unwrapping wrappers one at a time. `parent` is the `time` keyword timing its
    /// pipeline, if any.
    fn simple(&mut self, simple: &SimpleCommand, deep: &DeepCommand<'_>, parent: Option<usize>) {
        let first = self.commands.len();
        // `PS4='$(cmd)'` alone is code too once `set -x` runs, and `set -a` exports any assignment.
        self.code_variable = simple
            .assignments
            .iter()
            .find(|assignment| {
                let text = static_text(&assignment.word, deep.source);
                let value = text
                    .as_deref()
                    .and_then(|text| text.split_once('='))
                    .map(|(_, value)| value);
                sets_code_variable(&assignment.name, value)
            })
            .map(|assignment| deep.on_line(assignment.span));
        if simple.name().is_some() {
            let mut inner = Inner {
                start: 0,
                lookup: Lookup::Shell,
                parent,
                xargs: None,
                words: &simple.words,
            };
            // Each turn classifies one command name; a wrapper hands over to the command it runs. Every turn moves
            // `start` forward, so the loop ends within the number of words.
            while let Some(next) = self.one(simple, deep, &inner) {
                inner = next;
            }
        }
        if let Some(span) = self.code_variable.take() {
            // Every command run with the variable may start a shell or program that runs its value; the wrappers
            // only pass it on.
            let reason = DynamicReason::CodeVariable;
            self.parts.push(DynamicPart { reason, span });
            let wrappers: Vec<usize> = self.commands[first..]
                .iter()
                .filter_map(|command| command.wrapper)
                .collect();
            for (index, command) in self.commands.iter_mut().enumerate().skip(first) {
                if !command.class.is_dynamic() && !wrappers.contains(&index) {
                    command.class = CommandClass::Dynamic { reason };
                }
            }
        }
    }

    /// Classifies the command named at `inner.start` and pushes its entry. Returns the command it runs if it is a
    /// wrapper that runs one.
    fn one<'w>(&mut self, simple: &SimpleCommand, deep: &DeepCommand<'_>, inner: &Inner<'w>) -> Option<Inner<'w>> {
        let words = inner.words;
        let name_word = words.get(inner.start)?;
        let source = deep.source;
        let placeholder = inner.xargs.as_ref().and_then(|xargs| xargs.placeholder.as_deref());
        // A word holding `xargs`'s placeholder is replaced at run time, so its value is unknown.
        let known = |text: Option<String>| text.filter(|text| placeholder.is_none_or(|marker| !text.contains(marker)));
        let start = if inner.start == 0 {
            simple.span.start
        } else {
            name_word.span.start
        };
        let span = deep.on_line(Span::new(start, simple.span.end));
        let name_span = deep.on_line(name_word.span);
        let arguments: Vec<Argument> = words[inner.start + 1..]
            .iter()
            .map(|word| Argument {
                text: argument_text(&word.word, source),
                span: deep.on_line(word.span),
            })
            .collect();
        let texts: Vec<Option<String>> = arguments.iter().map(|argument| known(argument.text.clone())).collect();
        let texts: Vec<ArgumentText<'_>> = texts.iter().map(Option::as_deref).collect();
        let complete = inner.xargs.is_none();
        let mut entry = ClassifiedCommand {
            name: command_name_text(&name_word.word, source),
            name_span: Some(name_span),
            arguments,
            arguments_complete: complete,
            program: None,
            class: CommandClass::Static,
            wrapper: inner.parent,
            span,
        };

        let Some(name) = known(entry.name.clone()) else {
            self.push_dynamic_at(entry, DynamicReason::ExpandedCommandName, name_span);
            return None;
        };
        // `eval` and `source` are checked before functions, as the parser does: a function of that name is still
        // reported, since erring towards dynamic is safe.
        if name == "eval" {
            entry.program = Some(Program::Builtin);
            self.push_dynamic(entry, DynamicReason::Eval);
            return None;
        }
        if name == "source" || name == "." {
            entry.program = Some(Program::Builtin);
            if complete && self.trusted_source(texts.first().copied().flatten()) {
                self.commands.push(entry);
            } else {
                self.push_dynamic(entry, DynamicReason::Source);
            }
            return None;
        }
        if inner.start == 0 && simple.function_call.is_some() {
            entry.program = Some(Program::Function);
            self.commands.push(entry);
            return None;
        }
        if stores_code(&name, &texts) {
            self.push_dynamic(entry, DynamicReason::Eval);
            return None;
        }
        if DECLARATION_BUILTINS.contains(&name.as_str())
            && words[inner.start + 1..]
                .iter()
                .any(|word| declares_code_variable(&word.word, source))
        {
            self.push_dynamic(entry, DynamicReason::CodeVariable);
            return None;
        }

        let program = self.resolver.resolve(&name, inner.lookup);
        entry.program = Some(program.clone());
        // Interpreters first: a name that is both (an `env` that resolves to `/bin/bash`) cannot hide code.
        if let Some(interpreter) = self.interpreter_of(&program, &name) {
            let reason = match interpreter.run(&texts, complete) {
                InterpreterRun::Code => Some(DynamicReason::InterpreterCode),
                InterpreterRun::Stdin => Some(DynamicReason::InterpreterStdin),
                InterpreterRun::Expanded => Some(DynamicReason::ExpandedArgument),
                InterpreterRun::Script => None,
            };
            if let Some(reason) = reason {
                self.push_dynamic(entry, reason);
                return None;
            }
        }
        if let Some((wrapper, resolved)) = wrapper_of(&program, &name) {
            // A name that only reads like a wrapper keeps its program's class, so name rules see what runs.
            let class = if resolved {
                program.wrapper_class()
            } else {
                program.class()
            };
            return self.unwrap(wrapper, entry, class, &texts, inner);
        }
        entry.class = if simple.redirections.iter().any(|redirect| redirect.feeds_interpreter) {
            // The parser already reported the here-document itself (KNSH-031); the command is dynamic too.
            CommandClass::Dynamic {
                reason: DynamicReason::InterpreterInput,
            }
        } else {
            program.class()
        };
        self.commands.push(entry);
        None
    }

    /// Records a wrapper and finds the command it runs, if any.
    fn unwrap<'w>(
        &mut self,
        wrapper: Wrapper,
        mut entry: ClassifiedCommand,
        class: CommandClass,
        texts: &[ArgumentText<'_>],
        inner: &Inner<'w>,
    ) -> Option<Inner<'w>> {
        let complete = inner.xargs.is_none();
        match wrapper.unwrap(texts) {
            Unwrap::Runs { index, xargs } => {
                if wrapper == Wrapper::Env && self.code_variable.is_none() {
                    // `env BASH_ENV=… bash x.sh`: the operands before the command are its assignments.
                    self.code_variable = texts
                        .iter()
                        .zip(&entry.arguments)
                        .take(index)
                        .find(|(text, _)| {
                            text.and_then(|text| text.split_once('='))
                                .is_some_and(|(name, value)| sets_code_variable(name, Some(value)))
                        })
                        .map(|(_, argument)| argument.span);
                }
                entry.class = class;
                entry.arguments.truncate(index);
                let parent = self.commands.len();
                self.commands.push(entry);
                Some(Inner {
                    start: inner.start + 1 + index,
                    lookup: wrapper.inner_lookup(),
                    parent: Some(parent),
                    // Once arguments are supplied at run time, every command further in receives them.
                    xargs: xargs.or_else(|| inner.xargs.clone()),
                    words: inner.words,
                })
            }
            // Under `xargs` the wrapper's missing command (or the `echo` default) is supplied at run time.
            Unwrap::Echo(_) | Unwrap::Nothing if !complete => {
                self.push_dynamic(entry, DynamicReason::ExpandedCommandName);
                None
            }
            Unwrap::Echo(_) => {
                entry.class = class;
                let parent = self.commands.len();
                let span = entry.span;
                self.commands.push(entry);
                let echo = self.resolver.resolve("echo", Lookup::Program);
                self.commands.push(ClassifiedCommand {
                    name: Some("echo".to_owned()),
                    name_span: None,
                    arguments: Vec::new(),
                    arguments_complete: false,
                    class: echo.class(),
                    program: Some(echo),
                    wrapper: Some(parent),
                    span,
                });
                None
            }
            Unwrap::Nothing => {
                // Nothing else runs, so the entry is the program itself.
                entry.class = match class {
                    CommandClass::Wrapper => CommandClass::Static,
                    CommandClass::Static | CommandClass::ProjectExecutable | CommandClass::Dynamic { .. } => class,
                };
                self.commands.push(entry);
                None
            }
            Unwrap::Dynamic(reason) => {
                self.push_dynamic(entry, reason);
                None
            }
        }
    }

    /// Records `entry` as dynamic code for `reason`, the whole command being the dynamic part.
    fn push_dynamic(&mut self, entry: ClassifiedCommand, reason: DynamicReason) {
        let span = entry.span;
        self.push_dynamic_at(entry, reason, span);
    }

    /// Records `entry` as dynamic code for `reason`, with the dynamic part at `span`.
    fn push_dynamic_at(&mut self, mut entry: ClassifiedCommand, reason: DynamicReason, span: Span) {
        entry.class = CommandClass::Dynamic { reason };
        self.commands.push(entry);
        self.parts.push(DynamicPart { reason, span });
    }

    /// Whether `source` of `path` is not dynamic: the file is known, and the resolver trusts it.
    fn trusted_source(&self, path: ArgumentText<'_>) -> bool {
        // No operand, an expansion, or an option (`source -p`, bash 5.3) is never trusted.
        path.filter(|path| !path.starts_with('-'))
            .is_some_and(|path| self.resolver.source_file(path) == SourceFile::Trusted)
    }

    /// The interpreter a program is, by the resolved binary's family, else by the name as written.
    fn interpreter_of(&self, program: &Program, name: &str) -> Option<&Interpreter> {
        match program {
            Program::Builtin | Program::Function => None,
            Program::Trusted(_) | Program::ProjectExecutable(_) | Program::NotFound => program
                .path()
                .and_then(file_name)
                .and_then(|base| self.interpreters.find(base))
                .or_else(|| self.interpreters.find(name)),
        }
    }
}

/// The wrapper a program is, by the resolved binary's base name, else by the name as written; never a function. The
/// flag says whether the program itself is that wrapper: a builtin or a name not found has only its name, and a
/// binary whose base name is not a wrapper (a `nice` that resolves to `/bin/rm`) only reads like one.
///
/// Builtin and program wrappers are not told apart by how the name resolved: `nice command eval x` runs
/// `/usr/bin/command`, a script macOS ships that runs the `command` builtin, and a project binary named like a
/// wrapper is unwrapped too. Unwrapping only adds entries.
pub(crate) fn wrapper_of(program: &Program, name: &str) -> Option<(Wrapper, bool)> {
    match program {
        Program::Function => None,
        Program::Trusted(_) | Program::ProjectExecutable(_) => program
            .path()
            .and_then(file_name)
            .and_then(Wrapper::from_name)
            .map(|wrapper| (wrapper, true))
            .or_else(|| Wrapper::from_name(name).map(|wrapper| (wrapper, false))),
        Program::Builtin | Program::NotFound => Wrapper::from_name(name).map(|wrapper| (wrapper, true)),
    }
}

/// Variables whose value a shell or a program started with them runs as code, or which load code into it: the shells'
/// startup file, trace prompt and options (`BASH_ENV='$(cmd)' bash x.sh` runs `cmd`), exported functions, the
/// interpreters' option variables, library injection, and the commands git, ssh and pagers run through a shell. Not
/// exhaustive: a parser result is an intent filter, and the sandbox limits what dynamic code can reach (FR-POL-21).
pub(crate) const CODE_VARIABLES: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "PS4",
    "SHELLOPTS",
    "BASHOPTS",
    "PROMPT_COMMAND",
    "NODE_OPTIONS",
    "PERL5OPT",
    "PERL5DB",
    "RUBYOPT",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "GIT_CONFIG",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_PAGER",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "GIT_EXTERNAL_DIFF",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "PAGER",
    "MANPAGER",
    "EDITOR",
    "VISUAL",
    "LESSOPEN",
    "LESSCLOSE",
];

/// Prefixes of [code variables](CODE_VARIABLES): exported functions (`BASH_FUNC_name%%`), git configuration
/// (`GIT_CONFIG_GLOBAL`, `GIT_CONFIG_KEY_0`, which can set `core.pager`) and the dynamic linker (`DYLD_INSERT_LIBRARIES`).
const CODE_VARIABLE_PREFIXES: &[&str] = &["BASH_FUNC_", "GIT_CONFIG_", "DYLD_"];

/// Whether setting `name` can make a program run code from its value.
fn is_code_variable(name: &str) -> bool {
    CODE_VARIABLES.contains(&name) || CODE_VARIABLE_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// Code variables whose value is a program to run, through a shell or not (`GIT_PAGER=cat git log`). A bare program
/// name there is a command lookup, not code, and agents set these constantly to avoid an interactive pager or editor;
/// any other value (`PAGER='sh -c …'`, `EDITOR=./x`) is still code. `BASH_ENV` and the like are not here: a file name
/// there is a file bash sources.
const PROGRAM_VARIABLES: &[&str] = &[
    "GIT_PAGER",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "PAGER",
    "MANPAGER",
    "EDITOR",
    "VISUAL",
];

/// Whether assigning `value` (`None` when built from an expansion) to `name` can make a program run code from it: a
/// [code variable](CODE_VARIABLES), unless it is a [program variable](PROGRAM_VARIABLES) set to a bare program name or
/// to nothing.
fn sets_code_variable(name: &str, value: Option<&str>) -> bool {
    let plain_program = |value: &str| {
        !value.starts_with('-')
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'+' | b'-'))
    };
    is_code_variable(name) && !(PROGRAM_VARIABLES.contains(&name) && value.is_some_and(plain_program))
}

/// The builtins that set variables, and export them with `-x` (`export BASH_ENV=…`, `declare -x PS4=…`).
const DECLARATION_BUILTINS: &[&str] = &["export", "declare", "typeset", "local", "readonly"];

/// Whether an argument of a declaration builtin may set or export a [code variable](CODE_VARIABLES): it names one, or
/// its name is not known from the line (`export "$(cat .env)"`). An option (`-x`) names nothing.
fn declares_code_variable(word: &Word, source: &str) -> bool {
    if let Some(text) = static_text(word, source) {
        if text.starts_with(['-', '+']) {
            return false;
        }
        let (name, value) = text
            .split_once('=')
            .map_or((text.as_str(), None), |(name, value)| (name, Some(value)));
        // `export PAGER` exports whatever it holds: unknown, so judged like an expanded value.
        return sets_code_variable(name.strip_suffix('+').unwrap_or(name), value);
    }
    // Not certain as a whole: an assignment whose name is written out (`PATH="$PATH:/x"`) is judged by that name.
    let literal = word
        .segments
        .first()
        .filter(|segment| matches!(segment.kind, SegmentKind::Literal))
        .and_then(|segment| segment.span.text(source));
    match literal.and_then(|literal| literal.split_once('=')) {
        Some((name, _)) => {
            let name = name.strip_suffix('+').unwrap_or(name);
            !is_variable_name(name) || is_code_variable(name)
        }
        None => true,
    }
}

/// `[A-Za-z_][A-Za-z0-9_]*`.
fn is_variable_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

/// Whether a builtin stores code for bash to run later, as `eval` runs it now: `trap` with an action, `mapfile` or
/// `readarray` with a `-C` callback, and `alias` with a value (run by a later line once `expand_aliases` is set).
/// An argument built from an expansion could be any of them.
fn stores_code(name: &str, arguments: &[ArgumentText<'_>]) -> bool {
    match name {
        "trap" => trap_sets_action(arguments),
        "mapfile" | "readarray" => mapfile_has_callback(arguments),
        "alias" => arguments
            .iter()
            .any(|argument| argument.is_none_or(|text| text.contains('='))),
        _ => false,
    }
}

/// Whether `trap` is given an action to run: after its options (`-l`, `-p`, `--`), an operand other than `''` or `-`
/// (which ignore or reset), an unsigned number (a signal) or a lone signal name (which resets it).
fn trap_sets_action(arguments: &[ArgumentText<'_>]) -> bool {
    let operands = match arguments.split_first() {
        Some((None, _)) => return true,
        Some((Some("--"), rest)) => rest,
        // `trap -p` and `trap -l` print and run nothing; an unknown option fails.
        Some((Some(text), _)) if text.starts_with('-') && text.len() > 1 => return false,
        Some(_) | None => arguments,
    };
    match operands {
        [] | [_] => operands.first().is_some_and(Option::is_none),
        [action, ..] => action.is_none_or(|action| {
            !(action.is_empty() || action == "-" || action.bytes().all(|byte| byte.is_ascii_digit()))
        }),
    }
}

/// Whether `mapfile` or `readarray` is given a `-C` callback, read as `getopt` would (`-d`, `-n`, `-O`, `-s`, `-u`,
/// `-C` and `-c` take values).
fn mapfile_has_callback(arguments: &[ArgumentText<'_>]) -> bool {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let Some(argument) = *argument else {
            return true;
        };
        index += 1;
        if argument == "--" || !argument.starts_with('-') || argument == "-" {
            return false;
        }
        for (offset, letter) in argument[1..].char_indices() {
            if letter == 'C' {
                return true;
            }
            if "dnOsuc".contains(letter) {
                if argument[1 + offset + letter.len_utf8()..].is_empty() {
                    index += 1;
                }
                break;
            }
        }
    }
    false
}

/// The last part of a path, as text.
fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

/// An argument's text after quote removal, when certain (see `static_text`). `{}` alone counts as text: bash does
/// not brace-expand it, and it is `xargs` and `find`'s usual placeholder.
fn argument_text(word: &Word, source: &str) -> Option<String> {
    static_text(word, source).or_else(|| match word.segments.as_slice() {
        [segment] if matches!(segment.kind, SegmentKind::Literal) && segment.span.text(source) == Some("{}") => {
            Some("{}".to_owned())
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outcome::parse_line;

    /// A session: `PATH` holds `/usr/bin` with the usual tools, `/opt/homebrew/bin` with versioned interpreters, and
    /// the project's `/p/node_modules/.bin`; the project `/p` is the write root.
    struct Session;

    impl Resolver for Session {
        fn resolve(&self, name: &str, lookup: Lookup) -> Program {
            if lookup == Lookup::Shell && crate::is_builtin(name) {
                return Program::Builtin;
            }
            let trusted = |path: &str| Program::Trusted(PathBuf::from(path));
            match name {
                "git" | "env" | "nice" | "nohup" | "time" | "xargs" | "rm" | "echo" | "bash" | "sh" | "zsh"
                | "python3" | "ls" | "mv" | "cat" => trusted(&format!("/usr/bin/{name}")),
                "timeout" => trusted("/opt/homebrew/bin/timeout"),
                "node" => trusted("/opt/homebrew/bin/node"),
                // A Homebrew link resolved to its canonical, versioned binary.
                "python" | "py" => trusted("/opt/homebrew/bin/python3.12"),
                "tool" => Program::ProjectExecutable(PathBuf::from("/p/node_modules/.bin/tool")),
                "gtimeout" => Program::ProjectExecutable(PathBuf::from("/opt/homebrew/Cellar/coreutils/bin/gtimeout")),
                "mytool" => trusted("/usr/bin/mytool"),
                _ if name.starts_with('/') => Program::ProjectExecutable(PathBuf::from(name)),
                _ => Program::NotFound,
            }
        }

        fn source_file(&self, path: &str) -> SourceFile {
            match path {
                "/etc/bashrc" => SourceFile::Trusted,
                _ if path.starts_with("/p/") || !path.starts_with('/') => SourceFile::AgentWritable,
                _ => SourceFile::Unresolved,
            }
        }
    }

    fn classify_line(line: &str) -> Classification {
        classify(&parse_line(line), line, &Session, &Interpreters::defaults())
    }

    /// Each entry as (name, class code, wrapper index).
    fn entries(line: &str) -> Vec<(Option<String>, CommandClass, Option<usize>)> {
        classify_line(line)
            .commands()
            .iter()
            .map(|command| (command.name.clone(), command.class, command.wrapper))
            .collect()
    }

    /// The classes of the entries, by name.
    fn classes(line: &str) -> Vec<(String, &'static str)> {
        classify_line(line)
            .commands()
            .iter()
            .map(|command| (command.name.clone().unwrap_or_default(), command.class.code()))
            .collect()
    }

    fn dynamic(reason: DynamicReason) -> CommandClass {
        CommandClass::Dynamic { reason }
    }

    /// The class of the last entry: the command that finally runs.
    fn last_class(line: &str) -> CommandClass {
        classify_line(line).commands().last().expect(line).class
    }

    #[allow(clippy::unnecessary_wraps)] // Builds the `Option` field it is compared with.
    fn name(text: &str) -> Option<String> {
        Some(text.to_owned())
    }

    // ---- Wrapper unwrapping (FR-LC-04) ----

    #[test]
    fn unwraps_env_with_assignments_and_flags() {
        let line = "env -i FOO=1 -u X git push";
        // `-u` after an assignment is the command `-u`: `env` stops reading options at its first operand.
        assert_eq!(
            classes(line),
            [("env".to_owned(), "wrapper"), ("-u".to_owned(), "static")]
        );
        let line = "env -i -u HOME FOO=1 BAR='a b' git push";
        let classification = classify_line(line);
        let commands = classification.commands();
        assert_eq!(
            classes(line),
            [("env".to_owned(), "wrapper"), ("git".to_owned(), "static")]
        );
        assert_eq!(commands[1].wrapper, Some(0));
        assert_eq!(
            commands[1].program,
            Some(Program::Trusted(PathBuf::from("/usr/bin/git")))
        );
        // The wrapper keeps its own arguments; the command keeps its own.
        let texts = |command: &ClassifiedCommand| -> Vec<String> {
            command
                .arguments
                .iter()
                .map(|argument| argument.text.clone().unwrap())
                .collect()
        };
        assert_eq!(texts(&commands[0]), ["-i", "-u", "HOME", "FOO=1", "BAR=a b"]);
        assert_eq!(texts(&commands[1]), ["push"]);
        assert_eq!(&line[commands[1].span.range()], "git push");
        assert_eq!(&line[commands[1].name_span.unwrap().range()], "git");
        assert!(!classification.is_dynamic());
        // `env` alone runs nothing else.
        assert_eq!(classes("env FOO=1"), [("env".to_owned(), "static")]);
    }

    #[test]
    fn unwraps_nested_wrappers() {
        let line = "env FOO=1 nice -n 5 timeout 5 git push";
        assert_eq!(
            entries(line),
            [
                (name("env"), CommandClass::Wrapper, None),
                (name("nice"), CommandClass::Wrapper, Some(0)),
                (name("timeout"), CommandClass::Wrapper, Some(1)),
                (name("git"), CommandClass::Static, Some(2)),
            ]
        );
        assert_eq!(
            entries("time -p command exec nohup git status"),
            [
                (name("time"), CommandClass::Wrapper, None),
                (name("command"), CommandClass::Wrapper, Some(0)),
                (name("exec"), CommandClass::Wrapper, Some(1)),
                (name("nohup"), CommandClass::Wrapper, Some(2)),
                (name("git"), CommandClass::Static, Some(3)),
            ]
        );
        // A program running `command` reaches macOS's `/usr/bin/command`, which runs the builtin: still unwrapped.
        assert_eq!(last_class("nice command eval x"), dynamic(DynamicReason::Eval));
        // The innermost command is what policy decides: dynamic code stays dynamic however deep.
        assert_eq!(
            last_class("env nice timeout 5 bash -c 'rm -rf x'"),
            dynamic(DynamicReason::InterpreterCode)
        );
        assert_eq!(last_class("command eval x"), dynamic(DynamicReason::Eval));
        assert_eq!(last_class("builtin eval x"), dynamic(DynamicReason::Eval));
        // Where a wrapper's option or its command could be, an expansion is either: not guessed at.
        assert_eq!(last_class("exec $CMD"), dynamic(DynamicReason::ExpandedArgument));
        assert_eq!(last_class("nice -n 5 $CMD x"), dynamic(DynamicReason::ExpandedArgument));
        assert_eq!(
            last_class("timeout 5 $CMD"),
            dynamic(DynamicReason::ExpandedCommandName)
        );
    }

    // The `time` keyword wraps its pipeline.
    #[test]
    fn time_keyword_wraps_its_pipeline() {
        let line = "time -p git log | grep x";
        let classification = classify_line(line);
        let commands = classification.commands();
        assert_eq!(commands[0].name.as_deref(), Some("time"));
        assert_eq!(commands[0].class, CommandClass::Wrapper);
        assert_eq!(&line[commands[0].span.range()], "time -p");
        assert_eq!(commands[1].name.as_deref(), Some("git"));
        assert_eq!(commands[1].wrapper, Some(0));
        assert_eq!(commands[2].name.as_deref(), Some("grep"));
        assert_eq!(commands[2].wrapper, Some(0));
        assert_eq!(last_class("time ! bash -c x"), dynamic(DynamicReason::InterpreterCode));
        // As a program (not in keyword position) it is unwrapped by its own grammar.
        assert_eq!(
            classes("X=1 time -p git"),
            [("time".to_owned(), "wrapper"), ("git".to_owned(), "static")]
        );
    }

    #[test]
    fn command_v_is_not_execution() {
        for line in ["command -v eval", "command -V bash", "command -pv git", "command"] {
            let classification = classify_line(line);
            assert_eq!(classification.commands().len(), 1, "{line}");
            assert_eq!(classification.commands()[0].class, CommandClass::Static, "{line}");
            assert!(!classification.is_dynamic(), "{line}");
        }
        assert_eq!(
            entries("command -p git push"),
            [
                (name("command"), CommandClass::Wrapper, None),
                (name("git"), CommandClass::Static, Some(0)),
            ]
        );
    }

    #[test]
    fn timeout_with_signal_option_unwraps() {
        for line in [
            "timeout -s KILL 5 git push",
            "timeout --signal=TERM -k 2 5m git push",
            "timeout --preserve-status --kill-after 1 30 git push",
        ] {
            assert_eq!(
                entries(line),
                [
                    (name("timeout"), CommandClass::Wrapper, None),
                    (name("git"), CommandClass::Static, Some(0)),
                ],
                "{line}"
            );
        }
        // Outside the trusted folders a wrapper is still unwrapped, but keeps `project_executable`.
        assert_eq!(
            entries("gtimeout 5 bash -c x"),
            [
                (name("gtimeout"), CommandClass::ProjectExecutable, None),
                (name("bash"), dynamic(DynamicReason::InterpreterCode), Some(0)),
            ]
        );
    }

    #[test]
    fn xargs_inner_command_is_classified() {
        let classification = classify_line("find . -name '*.o' | xargs rm -f");
        let rm = &classification.commands()[2];
        assert_eq!(rm.name.as_deref(), Some("rm"));
        assert_eq!(rm.class, CommandClass::Static);
        assert_eq!(rm.wrapper, Some(1));
        // The arguments `xargs` supplies are unknown to argument-sensitive rules.
        assert!(!rm.arguments_complete);
        assert!(classification.commands()[1].arguments_complete);
        // With placeholders the command is still classified.
        let classification = classify_line("xargs -I {} mv {} /tmp/x");
        assert_eq!(classification.commands()[1].name.as_deref(), Some("mv"));
        assert!(!classification.commands()[1].arguments_complete);
        assert!(!classification.is_dynamic());
        assert_eq!(
            classes("xargs -J % cp % x"),
            [("xargs".to_owned(), "wrapper"), ("cp".to_owned(), "static")]
        );
        // With no command, `xargs` runs `echo`.
        let classification = classify_line("xargs -0");
        let echo = &classification.commands()[1];
        assert_eq!(echo.name.as_deref(), Some("echo"));
        assert_eq!(echo.name_span, None);
        assert_eq!(echo.wrapper, Some(0));
        assert_eq!(echo.program, Some(Program::Trusted(PathBuf::from("/usr/bin/echo"))));
        // A command whose name or script comes from the input is dynamic.
        assert_eq!(
            last_class("xargs -I {} {} x"),
            dynamic(DynamicReason::ExpandedCommandName)
        );
        assert_eq!(
            last_class("xargs -I@ bash @ x"),
            dynamic(DynamicReason::ExpandedArgument)
        );
        assert_eq!(last_class("xargs bash"), dynamic(DynamicReason::InterpreterStdin));
        assert_eq!(
            last_class("xargs sh -c 'echo $0'"),
            dynamic(DynamicReason::InterpreterCode)
        );
        assert_eq!(last_class("xargs env"), dynamic(DynamicReason::ExpandedCommandName));
        assert_eq!(last_class("xargs xargs"), dynamic(DynamicReason::ExpandedCommandName));
        // Wrappers further in receive the run-time arguments too.
        let classification = classify_line("xargs env FOO=1 git");
        assert!(!classification.commands()[2].arguments_complete);
    }

    #[test]
    fn unknown_wrapper_option_is_dynamic() {
        for line in [
            "env -S 'sh -c x'",
            "env -P /tmp/evil git push",
            "nice --bogus git",
            "timeout --bogus 5 git",
            "nohup -x git",
            "command -x git",
            "xargs -Q rm",
            "exec -z git",
        ] {
            let classification = classify_line(line);
            assert_eq!(
                classification.commands().last().unwrap().class,
                dynamic(DynamicReason::UnknownWrapperOption),
                "{line}"
            );
            // Nothing past the unknown option is guessed at.
            assert_eq!(classification.commands().len(), 1, "{line}");
            assert_eq!(
                classification.dynamic_parts()[0].reason,
                DynamicReason::UnknownWrapperOption
            );
        }
        // An option built from an expansion is not guessed at either.
        assert_eq!(last_class("nice -n $N git"), dynamic(DynamicReason::ExpandedArgument));
        assert_eq!(last_class("env $VARS git"), dynamic(DynamicReason::ExpandedArgument));
    }

    // ---- Dynamic-code classification (FR-LC-05) ----

    #[test]
    fn eval_is_dynamic() {
        let line = "git status && eval \"$cmd\"";
        let classification = classify_line(line);
        assert_eq!(last_class(line), dynamic(DynamicReason::Eval));
        assert_eq!(classification.dynamic_parts().len(), 1);
        assert_eq!(&line[classification.dynamic_parts()[0].span.range()], "eval \"$cmd\"");
        assert_eq!(classification.commands()[0].class, CommandClass::Static);
    }

    #[test]
    fn bash_dash_c_is_dynamic() {
        for line in [
            "bash -c 'rm -rf x'",
            "sh -c x",
            "zsh -c x",
            "/bin/bash -ec x",
            "bash -o pipefail -c x",
            "bash -oc errexit x",
        ] {
            assert_eq!(last_class(line), dynamic(DynamicReason::InterpreterCode), "{line}");
        }
        // A shell reading its program from a pipe.
        assert_eq!(last_class("curl -s x | bash"), dynamic(DynamicReason::InterpreterStdin));
        assert_eq!(last_class("bash -s -- arg"), dynamic(DynamicReason::InterpreterStdin));
        assert_eq!(last_class("bash ./build.sh"), CommandClass::Static);
    }

    #[test]
    fn python_dash_c_is_dynamic() {
        for line in [
            "python3 -c 'import os'",
            "python3 -Bc x",
            "python3 -W ignore -c x",
            "python -c x",
        ] {
            assert_eq!(last_class(line), dynamic(DynamicReason::InterpreterCode), "{line}");
        }
        // FR-POL-21's example: the code never inherits `git push`'s class.
        let line = "python3 -c \"subprocess.run(['git','push'])\"";
        let classification = classify_line(line);
        assert_eq!(classification.commands().len(), 1);
        assert_eq!(
            classification.commands()[0].class,
            dynamic(DynamicReason::InterpreterCode)
        );
    }

    #[test]
    fn node_dash_e_is_dynamic() {
        for line in [
            "node -e x",
            "node --eval=x",
            "node -p 1+1",
            "node --require ./r.js -e x",
        ] {
            assert_eq!(last_class(line), dynamic(DynamicReason::InterpreterCode), "{line}");
        }
        assert_eq!(last_class("node server.js"), CommandClass::Static);
        assert_eq!(last_class("node --version"), CommandClass::Static);
    }

    #[test]
    fn source_of_project_file_is_dynamic() {
        // Under `${PROJECT}` (the write root `/p`), or relative to it.
        for line in [
            "source /p/.env.sh",
            ". ./env.sh",
            "source env.sh",
            "command source /p/x",
        ] {
            assert_eq!(last_class(line), dynamic(DynamicReason::Source), "{line}");
        }
        // Not resolvable, an expansion, or no file at all.
        for line in [
            "source /nowhere",
            "source \"$f\"",
            "source",
            ". ~/.profile",
            "source -p x",
        ] {
            assert_eq!(last_class(line), dynamic(DynamicReason::Source), "{line}");
        }
        // Outside the write roots, readable and in a trusted location: not dynamic.
        let classification = classify_line("source /etc/bashrc && git status");
        assert!(!classification.is_dynamic());
        assert_eq!(classification.commands()[0].class, CommandClass::Static);
        assert_eq!(classification.commands()[0].program, Some(Program::Builtin));
        // The parser's mark for a trusted file is dropped; the others stand.
        let line = "source /etc/bashrc; source /p/x";
        let parts = classify_line(line).dynamic_parts().to_vec();
        assert_eq!(parts.len(), 1);
        assert_eq!(&line[parts[0].span.range()], "source /p/x");
    }

    #[test]
    fn variable_command_name_is_dynamic() {
        for line in ["$X arg", "${X} arg", "\"$X\" arg", "$(which git) push", "env $X"] {
            let classification = classify_line(line);
            assert!(classification.is_dynamic(), "{line}");
            // The outer command comes first, before the commands of its substitutions.
            assert!(classification.commands()[0].class.is_dynamic(), "{line}");
        }
        let line = "ls; ${X} -rf x";
        let classification = classify_line(line);
        assert_eq!(
            classification.commands()[1].class,
            dynamic(DynamicReason::ExpandedCommandName)
        );
        assert_eq!(classification.commands()[1].name, None);
        assert_eq!(classification.commands()[1].program, None);
        assert_eq!(&line[classification.dynamic_parts()[0].span.range()], "${X}");
        // After `env`'s assignments an expansion may be another assignment or the command.
        assert_eq!(last_class("env FOO=1 $X"), dynamic(DynamicReason::ExpandedArgument));
        assert_eq!(
            last_class("command -- \"$X\" y"),
            dynamic(DynamicReason::ExpandedCommandName)
        );
    }

    #[test]
    fn interpreter_family_matches_versioned_basename() {
        // `py` resolves to `/opt/homebrew/bin/python3.12`: its family is `python`.
        assert_eq!(last_class("py -c x"), dynamic(DynamicReason::InterpreterCode));
        assert_eq!(
            last_class("/opt/homebrew/bin/python3.12 -c x"),
            dynamic(DynamicReason::InterpreterCode)
        );
        assert_eq!(last_class("python3 -c x"), dynamic(DynamicReason::InterpreterCode));
        // A non-interpreter resolution with a non-interpreter name is not one.
        assert_eq!(last_class("mytool -c x"), CommandClass::Static);
    }

    #[test]
    fn python_running_a_script_is_not_dynamic() {
        assert_eq!(classes("python3 script.py -c x"), [("python3".to_owned(), "static")]);
        assert_eq!(classes("python3 -m pytest -e"), [("python3".to_owned(), "static")]);
        // By the interpreter's resolution: a project interpreter is a project executable.
        assert_eq!(
            classes("/p/.venv/bin/python3 manage.py"),
            [("/p/.venv/bin/python3".to_owned(), "project_executable")]
        );
        assert!(!classify_line("python3 script.py").is_dynamic());
        // But a script named by an expansion could be `-c`.
        assert_eq!(last_class("python3 \"$f\""), dynamic(DynamicReason::ExpandedArgument));
    }

    #[test]
    fn here_document_into_interpreter_keeps_its_mark() {
        let line = "python3 - <<'EOF'\nprint(1)\nEOF\n";
        let classification = classify_line(line);
        assert!(classification.commands()[0].class.is_dynamic());
        assert!(
            classification
                .dynamic_parts()
                .iter()
                .any(|part| part.reason == DynamicReason::InterpreterInput)
        );
        // A here-document to a wrapped interpreter is the parser's mark too.
        let classification = classify_line("env bash <<EOF\nls\nEOF\n");
        assert!(classification.commands().last().unwrap().class.is_dynamic());
    }

    #[test]
    fn line_the_parser_could_not_read_is_dynamic_as_a_whole() {
        let classification = classify_line("echo 'open");
        assert!(classification.is_whole_line());
        assert_eq!(classification.commands(), []);
        assert_eq!(classification.dynamic_parts()[0].reason, DynamicReason::SyntaxError);
        // Parts the classifier does not decide (an unsupported construct) are kept.
        let classification = classify_line("[[ -f x ]] && git status");
        assert_eq!(classification.dynamic_parts()[0].reason.code(), "unsupported");
        assert_eq!(classification.commands()[0].class, CommandClass::Static);
    }

    #[test]
    fn commands_in_substitutions_functions_and_project_binaries_are_classified() {
        assert_eq!(
            classes("echo $(bash -c x) && f() { tool --x; }; f"),
            [
                ("echo".to_owned(), "static"),
                ("bash".to_owned(), "dynamic"),
                ("tool".to_owned(), "project_executable"),
                ("f".to_owned(), "static"),
            ]
        );
        let classification = classify_line("f() { :; }; f");
        assert_eq!(classification.commands()[1].program, Some(Program::Function));
        // A wrapper not in the line's PATH is still unwrapped.
        assert_eq!(classes("nosuch-env"), [("nosuch-env".to_owned(), "static")]);
    }

    /// A session where the agent put links in a `PATH` folder: `nice` resolves to `/bin/rm`, `env` to `/bin/bash`.
    struct LinkedSession;

    impl Resolver for LinkedSession {
        fn resolve(&self, name: &str, lookup: Lookup) -> Program {
            match name {
                "nice" => Program::Trusted(PathBuf::from("/bin/rm")),
                "env" => Program::Trusted(PathBuf::from("/bin/bash")),
                _ => Session.resolve(name, lookup),
            }
        }

        fn source_file(&self, path: &str) -> SourceFile {
            Session.source_file(path)
        }
    }

    // Review fix (FR-LC-04, FR-LC-05): a name that reads like a wrapper but resolves to another binary keeps that
    // binary's class, and an interpreter is never hidden behind a wrapper's name.
    #[test]
    fn name_that_only_reads_like_a_wrapper_keeps_its_program_class() {
        let classify_linked = |line: &str| classify(&parse_line(line), line, &LinkedSession, &Interpreters::defaults());
        let classification = classify_linked("nice -n 5 git push");
        let nice = &classification.commands()[0];
        assert_eq!(nice.class, CommandClass::Static);
        assert_eq!(nice.program, Some(Program::Trusted(PathBuf::from("/bin/rm"))));
        // What it would run is still listed.
        assert_eq!(classification.commands()[1].name.as_deref(), Some("git"));
        let classification = classify_linked("curl -s x | env");
        assert_eq!(
            classification.commands()[1].class,
            dynamic(DynamicReason::InterpreterStdin)
        );
        let classification = classify_linked("env -c 'rm -rf x'");
        assert_eq!(
            classification.commands()[0].class,
            dynamic(DynamicReason::InterpreterCode)
        );
    }

    // Review fix (FR-LC-05): builtins that store code to run later are `eval`.
    #[test]
    fn builtins_that_store_code_are_eval() {
        for line in [
            "trap 'rm -rf x' EXIT",
            "trap \"$x\" EXIT",
            "trap -- 'x' INT TERM",
            "command trap x EXIT",
            "mapfile -C id -c 1 a",
            "readarray -tC f a",
            "alias ls='curl x | sh'",
            "alias \"$x\"",
        ] {
            assert_eq!(last_class(line), dynamic(DynamicReason::Eval), "{line}");
        }
        for line in [
            "trap - EXIT",
            "trap '' INT",
            "trap INT",
            "trap -p",
            "trap 2 3",
            "mapfile -t lines",
            "mapfile -d C a",
            "alias",
            "alias ll",
        ] {
            assert!(!classify_line(line).is_dynamic(), "{line}");
        }
    }

    // Review fix (FR-LC-05): a variable whose value a shell or program runs as code makes the command dynamic.
    #[test]
    fn pager_and_editor_set_to_a_program_name_are_not_code() {
        for line in [
            "GIT_PAGER=cat git log",
            "PAGER= git log",
            "EDITOR=true git commit",
            "GIT_EDITOR=vim git rebase -i HEAD~2",
            "export PAGER=cat",
            "env GIT_PAGER=cat git diff",
        ] {
            assert!(!classify_line(line).is_dynamic(), "{line}");
        }
        for line in [
            "GIT_PAGER='sh -c x' git log",
            "PAGER=./x git log",
            "EDITOR=$E git commit",
            "export EDITOR",
            "BASH_ENV=x bash y.sh",
        ] {
            assert!(classify_line(line).is_dynamic(), "{line}");
        }
    }

    #[test]
    fn code_variable_makes_the_command_dynamic() {
        for line in [
            "BASH_ENV='$(curl x | sh)' bash ./build.sh",
            "PS4='$(id)' bash -x ./build.sh",
            "GIT_PAGER='sh -c x' git log",
            "NODE_OPTIONS='--require ./x.js' node server.js",
            "DYLD_INSERT_LIBRARIES=/p/x.dylib git status",
            "env BASH_ENV=/p/rc bash ./build.sh",
            "env -i 'BASH_FUNC_ls%%=() { id; }' bash ./build.sh",
            "time BASH_ENV=x bash ./build.sh",
        ] {
            let classification = classify_line(line);
            assert_eq!(
                classification.commands().last().unwrap().class,
                dynamic(DynamicReason::CodeVariable),
                "{line}"
            );
            assert!(
                classification
                    .dynamic_parts()
                    .iter()
                    .any(|part| part.reason == DynamicReason::CodeVariable),
                "{line}"
            );
        }
        // The wrappers that pass it on stay wrappers.
        assert_eq!(classes("env PAGER=x git log")[0], ("env".to_owned(), "wrapper"));
        // Set or exported without a command, it is dynamic too.
        for line in [
            "PS4='$(id)'",
            "export BASH_ENV=/p/rc",
            "declare -x PS4",
            "readonly 'EDITOR=sh -c x'",
            "export $(cat .env)",
        ] {
            assert!(classify_line(line).is_dynamic(), "{line}");
        }
        for line in [
            "X=1 git status",
            "env FOO=1 git",
            "export PATH=\"$PATH:/x\"",
            "local -r i=$((i+1))",
            "declare -x FOO",
        ] {
            assert!(!classify_line(line).is_dynamic(), "{line}");
        }
    }

    #[test]
    fn class_codes_match_the_record_model() {
        assert_eq!(CommandClass::Static.code(), "static");
        assert_eq!(CommandClass::Wrapper.code(), "wrapper");
        assert_eq!(CommandClass::ProjectExecutable.code(), "project_executable");
        assert_eq!(dynamic(DynamicReason::Eval).code(), "dynamic");
    }
}
