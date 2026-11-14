//! The syntax tree [`parse`](crate::parse) builds: lists, and-or lists, pipelines and simple commands with their
//! assignments, words and redirections (KNSH-029).
//!
//! Every node keeps the [`Span`] of the source it came from, so a decision can point at the exact part of the line it
//! is about. The tree is deliberately flat: a list is a vector of items, an and-or list a vector of pipelines, and a
//! pipeline a vector of commands. A line such as `a && a && …` repeated many times therefore never builds a deep chain
//! of boxes, so neither building, walking nor dropping the tree recurses on untrusted input (CLAUDE.md "Untrusted
//! input": bound recursion).

use crate::token::{IoNumber, RedirectionOperator, Span, Word};

/// A parsed command line: a list of and-or lists, separated by `;`, `&` or newlines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    /// The and-or lists, in source order. Empty for a line of only blanks, comments and newlines.
    pub items: Vec<ListItem>,
    /// The whole input.
    pub span: Span,
}

impl Script {
    /// Every simple command of the line, in source order, including those inside pipelines and lists (FR-LC-09:
    /// policy sees every part of the line).
    ///
    /// `a | b && c; d` yields `a`, `b`, `c`, `d`.
    pub fn simple_commands(&self) -> impl Iterator<Item = &SimpleCommand> + '_ {
        self.items
            .iter()
            .flat_map(|item| item.and_or.pipelines())
            .flat_map(Pipeline::commands)
            .map(|command| match command {
                Command::Simple(simple) => simple,
            })
    }
}

/// One and-or list of a [`Script`] and the separator that ends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListItem {
    /// The and-or list.
    pub and_or: AndOr,
    /// What ends it: `;`, `&` or a newline. `None` only for the last item of the line when nothing follows it.
    pub separator: Option<Separator>,
}

impl ListItem {
    /// Whether the and-or list runs in the background (ended by `&`), so the line goes on without waiting for it.
    #[must_use]
    pub fn is_background(&self) -> bool {
        self.separator
            .is_some_and(|separator| separator.kind == SeparatorKind::Background)
    }
}

/// The operator that ends a [`ListItem`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Separator {
    /// Which separator.
    pub kind: SeparatorKind,
    /// Where it is.
    pub span: Span,
}

/// The separators of a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SeparatorKind {
    /// `;`: run, wait, go on.
    Semicolon,
    /// `&`: run in the background, go on at once.
    Background,
    /// A newline, which separates like `;`.
    Newline,
}

/// Pipelines joined by `&&` and `||`.
///
/// Both operators have the same precedence and associate to the left, as in bash: `a && b || c` is `(a && b) || c`,
/// so `c` runs when either `a` or `b` fails. The list is stored flat, in source order: `first`, then each operator
/// with the pipeline after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndOr {
    /// The first pipeline.
    pub first: Pipeline,
    /// Each later pipeline with the operator before it.
    pub rest: Vec<AndOrPart>,
    /// From the first pipeline to the last.
    pub span: Span,
}

impl AndOr {
    /// The pipelines, in source order.
    pub fn pipelines(&self) -> impl Iterator<Item = &Pipeline> + '_ {
        std::iter::once(&self.first).chain(self.rest.iter().map(|part| &part.pipeline))
    }
}

/// A pipeline of an [`AndOr`] after the first, with the operator before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndOrPart {
    /// `&&` or `||`.
    pub operator: AndOrOperator,
    /// Where the operator is.
    pub operator_span: Span,
    /// The pipeline it runs conditionally.
    pub pipeline: Pipeline,
}

/// The operators of an and-or list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AndOrOperator {
    /// `&&`: run the next pipeline if the previous status is zero.
    And,
    /// `||`: run the next pipeline if the previous status is not zero.
    Or,
}

/// Commands joined by `|` or `|&`, optionally negated by `!`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    /// The `!` before the pipeline, which inverts its status. Bash 3.2 (`/bin/bash` on macOS) accepts at most one.
    pub negation: Option<Span>,
    /// The first command.
    pub first: Command,
    /// Each later command with the pipe before it.
    pub rest: Vec<PipelinePart>,
    /// From the `!` (or the first command) to the last command.
    pub span: Span,
}

impl Pipeline {
    /// Whether the pipeline's status is inverted by `!`.
    #[must_use]
    pub const fn is_negated(&self) -> bool {
        self.negation.is_some()
    }

    /// The commands, in source order.
    pub fn commands(&self) -> impl Iterator<Item = &Command> + '_ {
        std::iter::once(&self.first).chain(self.rest.iter().map(|part| &part.command))
    }
}

/// A command of a [`Pipeline`] after the first, with the pipe before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelinePart {
    /// `|` or `|&`.
    pub operator: PipeOperator,
    /// Where the operator is.
    pub operator_span: Span,
    /// The command reading the pipe.
    pub command: Command,
}

/// The pipe operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PipeOperator {
    /// `|`: standard output into the next command.
    Pipe,
    /// `|&`: standard output and standard error into the next command (bash 4; bash 3.2 rejects the line).
    PipeAll,
}

/// A command. Compound commands (subshells, groups, `if`, loops, `case`, functions) arrive with KNSH-030; until then
/// the parser rejects them as [`Unsupported`](crate::ParseError::Unsupported).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// A simple command.
    Simple(SimpleCommand),
}

impl Command {
    /// Where the command is.
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Simple(simple) => simple.span,
        }
    }
}

/// A simple command: assignments, then the command name and its arguments, with redirections anywhere among them.
///
/// Any part can be missing, but not all: `X=1` has only an assignment, `>f` only a redirection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    /// The assignments before the command name, in source order (`A=1 B=2 cmd`). A word shaped like an assignment
    /// after the name is an ordinary argument (`env A=1`).
    pub assignments: Vec<Assignment>,
    /// The command name followed by its arguments, in source order. Empty for a line of only assignments or
    /// redirections.
    pub words: Vec<CommandWord>,
    /// The redirections, in source order, wherever they were written (`>out cmd arg`, `cmd >out arg`).
    pub redirections: Vec<Redirect>,
    /// From the first part to the last.
    pub span: Span,
}

impl SimpleCommand {
    /// The command name: the first word that is not an assignment or a redirection. `None` for a line of only
    /// assignments or redirections, which runs no program.
    #[must_use]
    pub fn name(&self) -> Option<&CommandWord> {
        self.words.first()
    }

    /// The arguments after the command name.
    #[must_use]
    pub fn arguments(&self) -> &[CommandWord] {
        self.words.get(1..).unwrap_or_default()
    }
}

/// A word of a command with its place in the line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandWord {
    /// The word, with its quoting structure.
    pub word: Word,
    /// Where it is.
    pub span: Span,
}

/// An assignment before a command name: `NAME=value` or `NAME+=value`.
///
/// Before a command name it sets the variable in that command's environment only; without a command name it sets it
/// in the shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The variable name (`[A-Za-z_][A-Za-z0-9_]*`), with any line continuations inside it removed.
    pub name: String,
    /// Whether it appends (`+=`) instead of replacing (`=`).
    pub append: bool,
    /// The value, after the `=` (possibly empty). Its segments are those of [`word`](Self::word) inside this span.
    pub value: Span,
    /// The whole word, with its quoting structure.
    pub word: Word,
    /// The whole assignment.
    pub span: Span,
}

/// A redirection with its target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    /// The file-descriptor number written before the operator (`2` in `2>&1`), if any.
    pub fd: Option<IoNumber>,
    /// The operator.
    pub operator: RedirectionOperator,
    /// The target word: a file, a descriptor number or `-` for `>&` and `<&`, or the string of a here-string.
    pub target: CommandWord,
    /// From the descriptor number (or operator) to the end of the target.
    pub span: Span,
}
