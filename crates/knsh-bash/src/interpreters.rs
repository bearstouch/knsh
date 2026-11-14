//! Marks the here-documents and here-strings whose text a shell or interpreter reads as code (KNSH-031; decision 6:
//! "here-documents fed to shells or interpreters" are dynamic; FR-LC-05).
//!
//! `bash <<EOF` runs every line of the body as a command, and `python3 <<< "…"` runs the string as a program, so the
//! text is code the parser cannot decide. The redirection is marked ([`Redirect::feeds_interpreter`]) and the caller
//! classifies it as dynamic (KNSH-032). Marking errs towards marking: a wrong mark only sends a line to dynamic
//! classification, while a missed one would let code through unseen.
//!
//! The text is taken as code when the command reading it:
//!
//! - is named by an expansion (`$SHELL <<EOF`), so what reads it is unknown;
//! - is a shell or interpreter ([`INTERPRETERS`]), by the last part of its path with any version suffix removed
//!   (`/usr/bin/python3.12` is `python`); `ssh` and `su` count, since they hand their input to a shell;
//! - has a shell or interpreter among its arguments (`env bash`, `uv run python`, `docker exec -i box sh`, `xargs sh`),
//!   or is a wrapper ([`WRAPPERS`]) with an argument built from an expansion or a shell option (`sudo -s`);
//! - is a function defined in the same script, whose body may run any of the above;
//! - for a redirection on a compound command (`{ cat; bash; } <<EOF`), when any command inside it qualifies, or it
//!   holds an unsupported construct whose commands are unknown.
//!
//! A pipeline into an interpreter (`cat <<EOF | bash`) is not marked here: the here-document feeds `cat`, and `bash`
//! reading its standard input is dynamic code in its own right, classified with wrappers and interpreters (KNSH-036).
//! Substitutions are marked when their own scripts are parsed.

use std::collections::BTreeSet;

use crate::ast::{Command, CompoundCommand, ListItem, Pipeline, Redirect, SimpleCommand, collect_commands};
use crate::functions::static_text;
use crate::token::RedirectionOperator;

/// Shells and interpreters that run their standard input as code when given no script, by base name without a
/// version suffix. `ssh` and `su` run it in a remote or another user's shell.
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "rbash",
    "zsh",
    "dash",
    "ash",
    "ksh",
    "mksh",
    "oksh",
    "pdksh",
    "yash",
    "fish",
    "csh",
    "tcsh",
    "busybox",
    "python",
    "pypy",
    "ipython",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "irb",
    "jruby",
    "perl",
    "php",
    "lua",
    "luajit",
    "tclsh",
    "wish",
    "expect",
    "osascript",
    "pwsh",
    "powershell",
    "Rscript",
    "R",
    "julia",
    "groovy",
    "jshell",
    "swift",
    "ssh",
    "su",
];

/// Commands that run another command given as arguments (FR-LC-04 and common relatives). With an argument built from
/// an expansion, the command they run is unknown.
const WRAPPERS: &[&str] = &[
    "env",
    "command",
    "builtin",
    "exec",
    "nice",
    "nohup",
    "time",
    "timeout",
    "gtimeout",
    "xargs",
    "sudo",
    "doas",
    "stdbuf",
    "caffeinate",
    "arch",
    "chroot",
    "script",
    "setsid",
    "flock",
    "unbuffer",
];

/// Wrapper options that start a shell reading standard input (`sudo -s`, `sudo -i`, `su -l`).
const SHELL_OPTIONS: &[&str] = &["-s", "-i", "-l", "--shell", "--login"];

/// Sets [`Redirect::feeds_interpreter`] on every here-document and here-string in `items` (not inside substitutions)
/// whose text a shell or interpreter may read. `input` is the text the spans index.
pub(crate) fn mark_interpreter_inputs(items: &mut [ListItem], input: &str) {
    let mut commands = Vec::new();
    collect_commands(items, &mut commands);
    let functions = commands
        .iter()
        .filter_map(|command| match command {
            Command::FunctionDefinition(definition) => static_text(&definition.name.word, input),
            Command::Simple(_) | Command::Compound(_) | Command::Unsupported(_) => None,
        })
        .collect();
    Marker { input, functions }.list(items);
}

/// What the marking needs about the script.
struct Marker<'a> {
    /// The text the spans index.
    input: &'a str,
    /// The names of the script's functions.
    functions: BTreeSet<String>,
}

impl Marker<'_> {
    /// Marks the redirections of every command of `items`, nested lists included.
    fn list(&self, items: &mut [ListItem]) {
        for item in items {
            self.pipeline(&mut item.and_or.first);
            for part in &mut item.and_or.rest {
                self.pipeline(&mut part.pipeline);
            }
        }
    }

    /// Marks the redirections of every command of `pipeline`.
    fn pipeline(&self, pipeline: &mut Pipeline) {
        self.command(&mut pipeline.first);
        for part in &mut pipeline.rest {
            self.command(&mut part.command);
        }
    }

    /// Marks the here-documents and here-strings of `command`. An unsupported construct is opaque and classified
    /// as dynamic as a whole, so nothing inside it needs marking.
    fn command(&self, command: &mut Command) {
        match command {
            Command::Simple(simple) => {
                if simple.redirections.iter().any(feeds_text) {
                    let code = self.runs_input_as_code(simple);
                    mark(&mut simple.redirections, code);
                }
            }
            Command::Compound(compound) => self.compound(compound),
            Command::FunctionDefinition(definition) => self.compound(&mut definition.body),
            Command::Unsupported(_) => {}
        }
    }

    /// A redirection on a compound command feeds every command inside it, so any of them may read the text.
    fn compound(&self, compound: &mut CompoundCommand) {
        if compound.redirections.iter().any(feeds_text) {
            let mut inside = Vec::new();
            for list in compound.kind.lists() {
                collect_commands(list, &mut inside);
            }
            let code = inside.into_iter().any(|command| match command {
                Command::Simple(simple) => self.runs_input_as_code(simple),
                Command::Compound(_) | Command::FunctionDefinition(_) => false,
                Command::Unsupported(_) => true,
            });
            mark(&mut compound.redirections, code);
        }
        for list in compound.kind.lists_mut() {
            self.list(list);
        }
    }

    /// Whether `simple` may read its standard input as code (see the module documentation).
    fn runs_input_as_code(&self, simple: &SimpleCommand) -> bool {
        let Some(name) = simple.name() else {
            // Only assignments and redirections: nothing reads the text.
            return false;
        };
        let Some(name) = static_text(&name.word, self.input) else {
            return true;
        };
        if self.functions.contains(&name) || is_interpreter(&name) {
            return true;
        }
        let wrapper = WRAPPERS.contains(&program_name(&name));
        simple
            .arguments()
            .iter()
            .any(|argument| match static_text(&argument.word, self.input) {
                Some(argument) => is_interpreter(&argument) || (wrapper && SHELL_OPTIONS.contains(&argument.as_str())),
                None => wrapper,
            })
    }
}

/// Whether a redirection hands text to the command: a here-document or a here-string.
fn feeds_text(redirect: &Redirect) -> bool {
    match redirect.operator {
        RedirectionOperator::HereDocument
        | RedirectionOperator::HereDocumentStripTabs
        | RedirectionOperator::HereString => true,
        RedirectionOperator::Input
        | RedirectionOperator::Output
        | RedirectionOperator::Append
        | RedirectionOperator::Clobber
        | RedirectionOperator::ReadWrite
        | RedirectionOperator::DuplicateInput
        | RedirectionOperator::DuplicateOutput
        | RedirectionOperator::OutputAll
        | RedirectionOperator::AppendAll => false,
    }
}

/// Sets `code` on every here-document and here-string of `redirections`.
fn mark(redirections: &mut [Redirect], code: bool) {
    for redirect in redirections.iter_mut().filter(|redirect| feeds_text(redirect)) {
        redirect.feeds_interpreter = code;
    }
}

/// Whether the program `text` names is a shell or interpreter.
fn is_interpreter(text: &str) -> bool {
    INTERPRETERS.contains(&program_name(text))
}

/// The base name of a program path without a version suffix: `/usr/bin/python3.12` is `python`.
fn program_name(text: &str) -> &str {
    let base = text.rsplit('/').next().unwrap_or(text);
    base.trim_end_matches(|character: char| character.is_ascii_digit() || character == '.')
}
