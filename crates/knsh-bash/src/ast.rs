//! The syntax tree [`parse`](crate::parse) builds: lists, and-or lists, pipelines and simple commands with their
//! assignments, words and redirections (KNSH-029), compound commands and function definitions (KNSH-030), and the
//! command substitutions, backticks, process substitutions and here-documents inside them, each substitution parsed
//! into a nested [`Script`] (KNSH-031).
//!
//! Every node keeps the [`Span`] of the source it came from, and every reserved word and operator of a compound
//! command keeps its own, so a decision can point at the exact part of the line it is about. The tree is deliberately
//! flat: a list is a vector of items, an and-or list a vector of pipelines, and a pipeline a vector of commands. A line
//! such as `a && a && …` repeated many times therefore never builds a deep chain of boxes. The tree only deepens where
//! the source nests lists (compound commands, function bodies), and the parser bounds that nesting by
//! [`MAX_NESTING_DEPTH`](crate::MAX_NESTING_DEPTH), so building, walking and dropping the tree recurse a bounded
//! number of levels on untrusted input (CLAUDE.md "Untrusted input": bound recursion). Nested scripts count towards
//! the same limit as the lists that hold them.
//!
//! # Which text a span indexes
//!
//! Spans index the line, except inside a backtick substitution whose body bash un-escapes before reading it
//! (a body such as `` a \`b\` ``): that substitution keeps the un-escaped body as [`Substitution::text`], and the spans of
//! its nested script index that text. [`Script::commands_with_source`] pairs every command with the text its spans
//! index.

use crate::error::UnsupportedConstruct;
use crate::token::{IoNumber, RedirectionOperator, Segment, Span, Word};

/// A parsed command line, or the body of a substitution inside one: a list of and-or lists, separated by `;`, `&` or
/// newlines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    /// The and-or lists, in source order. Empty for a line of only blanks, comments and newlines.
    pub items: Vec<ListItem>,
    /// The whole input; for a nested script, the substitution's body.
    pub span: Span,
}

impl Script {
    /// Every command of the line in source order, each one before the commands nested in it: compound commands are
    /// followed by the commands of their conditions, bodies and case arms, function definitions by the commands of
    /// their bodies, and every command by the commands of the substitutions in its words, assignments, redirection
    /// targets and here-documents (KNSH-031: commands hidden in substitutions are decided too).
    ///
    /// [`Command::Unsupported`] nodes are yielded too (never skipped), but nothing inside them: their contents are
    /// opaque, and the caller classifies them as dynamic (decision 6, KNSH-032).
    ///
    /// The spans of a command inside an un-escaped backtick substitution index that substitution's
    /// [`text`](Substitution::text), not the line; use [`Script::commands_with_source`] to read them.
    pub fn commands(&self) -> impl Iterator<Item = &Command> + '_ {
        self.commands_with_source("").map(|(_, command)| command)
    }

    /// [`Script::commands`], each command paired with the text its spans index: `input` (the line this script was
    /// parsed from), or the [`text`](Substitution::text) of the innermost backtick substitution holding it.
    pub fn commands_with_source<'a>(&'a self, input: &'a str) -> impl Iterator<Item = (&'a str, &'a Command)> + 'a {
        self.deep_commands(input)
            .into_iter()
            .map(|deep| (deep.source, deep.command))
    }

    /// Every command in the order of [`Script::commands`], with the text its spans index and, for a command inside an
    /// un-escaped backtick substitution, the span on the line of the outermost such substitution.
    pub(crate) fn deep_commands<'a>(&'a self, input: &'a str) -> Vec<DeepCommand<'a>> {
        let mut commands = Vec::new();
        collect_deep(&self.items, input, None, &mut commands);
        commands
    }

    /// Every simple command of the line, in source order, including those inside pipelines, lists, compound commands,
    /// function bodies and substitutions (FR-LC-09: policy sees every part of the line).
    ///
    /// `a | b && c; d` yields `a`, `b`, `c`, `d`; `f() { rm -rf x; }; f` yields `rm`, then the call `f`; `echo $(a $(b))`
    /// yields `echo`, `a`, `b`. A function body is walked as code wherever it is defined, whether or not the line calls
    /// it, so its commands are always decided. See [`Script::commands`] for the spans of commands inside backticks.
    pub fn simple_commands(&self) -> impl Iterator<Item = &SimpleCommand> + '_ {
        self.simple_commands_with_source("").map(|(_, command)| command)
    }

    /// [`Script::simple_commands`], each command paired with the text its spans index (see
    /// [`Script::commands_with_source`]).
    pub fn simple_commands_with_source<'a>(
        &'a self,
        input: &'a str,
    ) -> impl Iterator<Item = (&'a str, &'a SimpleCommand)> + 'a {
        self.commands_with_source(input)
            .filter_map(|(source, command)| match command {
                Command::Simple(simple) => Some((source, simple)),
                Command::Compound(_) | Command::FunctionDefinition(_) | Command::Unsupported(_) => None,
            })
    }

    /// Every function definition of the line, in source order, nested ones included (those inside substitutions too).
    /// A [`FunctionCall`] names the definitions it may run by their spans.
    pub fn function_definitions(&self) -> impl Iterator<Item = &FunctionDefinition> + '_ {
        self.commands().filter_map(|command| match command {
            Command::FunctionDefinition(definition) => Some(definition),
            Command::Simple(_) | Command::Compound(_) | Command::Unsupported(_) => None,
        })
    }
}

/// A command found by [`Script::deep_commands`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeepCommand<'a> {
    /// The text the command's spans index: the line, or the [`text`](Substitution::text) of the innermost un-escaped
    /// backtick substitution holding it.
    pub(crate) source: &'a str,
    /// For a command inside an un-escaped backtick substitution, whose spans do not index the line: the span on the
    /// line of the outermost such substitution. `None` when the command's spans index the line.
    pub(crate) anchor: Option<Span>,
    /// The command.
    pub(crate) command: &'a Command,
    /// For a command directly in a pipeline timed by the `time` keyword (not nested inside one of its commands),
    /// that keyword (KNSH-036). Its spans index [`source`](Self::source).
    pub(crate) time: Option<TimeKeyword>,
}

impl DeepCommand<'_> {
    /// `span` (which indexes [`source`](Self::source)) as a span on the line: itself, or the anchor when the command
    /// is inside an un-escaped backtick substitution.
    pub(crate) fn on_line(&self, span: Span) -> Span {
        self.anchor.unwrap_or(span)
    }
}

/// Appends every command of `items` to `out` in the order of [`Script::commands`], substitutions included, each with
/// the text its spans index (`source` for `items`) and its `anchor` (see [`DeepCommand::anchor`]). Recurses once per
/// nested list or script, so its depth is bounded by the parser's nesting limit.
fn collect_deep<'a>(items: &'a [ListItem], source: &'a str, anchor: Option<Span>, out: &mut Vec<DeepCommand<'a>>) {
    for (time, command) in items
        .iter()
        .flat_map(|item| item.and_or.pipelines())
        .flat_map(|pipeline| pipeline.commands().map(|command| (pipeline.time, command)))
    {
        out.push(DeepCommand {
            source,
            anchor,
            command,
            time,
        });
        match command {
            Command::Simple(simple) => {
                let mut substitutions: Vec<&Substitution> = simple.substitutions().collect();
                // Assignments come first, but words and redirections interleave: sort into source order.
                substitutions.sort_by_key(|substitution| substitution.span.start);
                collect_substitutions(substitutions, source, anchor, out);
            }
            Command::Compound(compound) => collect_compound_deep(compound, source, anchor, out),
            Command::FunctionDefinition(definition) => {
                collect_substitutions(&definition.name.substitutions, source, anchor, out);
                collect_compound_deep(&definition.body, source, anchor, out);
            }
            Command::Unsupported(_) => {}
        }
    }
}

/// The commands of a compound command's header words, lists and redirections, in source order (see
/// [`collect_deep`]).
fn collect_compound_deep<'a>(
    compound: &'a CompoundCommand,
    source: &'a str,
    anchor: Option<Span>,
    out: &mut Vec<DeepCommand<'a>>,
) {
    match &compound.kind {
        CompoundKind::For(command) => {
            collect_substitutions(&command.variable.substitutions, source, anchor, out);
            for word in command.items.iter().flat_map(|items| &items.words) {
                collect_substitutions(&word.substitutions, source, anchor, out);
            }
            collect_deep(&command.body.body, source, anchor, out);
        }
        CompoundKind::Case(command) => {
            collect_substitutions(&command.subject.substitutions, source, anchor, out);
            for clause in &command.clauses {
                for pattern in &clause.patterns {
                    collect_substitutions(&pattern.substitutions, source, anchor, out);
                }
                collect_deep(&clause.body, source, anchor, out);
            }
        }
        CompoundKind::Subshell(_)
        | CompoundKind::Group(_)
        | CompoundKind::If(_)
        | CompoundKind::While(_)
        | CompoundKind::Until(_) => {
            for list in compound.kind.lists() {
                collect_deep(list, source, anchor, out);
            }
        }
    }
    let substitutions = compound.redirections.iter().flat_map(Redirect::substitutions);
    collect_substitutions(substitutions, source, anchor, out);
}

/// The commands of each substitution's script, in the text its spans index. Entering the first un-escaped backtick
/// substitution sets the anchor to its span, which indexes `source` and, since no anchor was set yet, the line.
fn collect_substitutions<'a>(
    substitutions: impl IntoIterator<Item = &'a Substitution>,
    source: &'a str,
    anchor: Option<Span>,
    out: &mut Vec<DeepCommand<'a>>,
) {
    for substitution in substitutions {
        let anchor = anchor.or_else(|| substitution.text.is_some().then_some(substitution.span));
        collect_deep(&substitution.script.items, substitution.source(source), anchor, out);
    }
}

/// Appends every command of `items` to `out` in the order of [`Script::commands`], but without entering
/// substitutions: only the commands of this script, whose spans all index the same text. Recurses once per nested
/// list, so its depth is bounded by the parser's nesting limit.
pub(crate) fn collect_commands<'a>(items: &'a [ListItem], out: &mut Vec<&'a Command>) {
    for command in items
        .iter()
        .flat_map(|item| item.and_or.pipelines())
        .flat_map(Pipeline::commands)
    {
        out.push(command);
        let nested = match command {
            Command::Compound(compound) => &compound.kind,
            Command::FunctionDefinition(definition) => &definition.body.kind,
            Command::Simple(_) | Command::Unsupported(_) => continue,
        };
        for list in nested.lists() {
            collect_commands(list, out);
        }
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

/// Commands joined by `|` or `|&`, optionally timed by the `time` keyword and negated by `!`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    /// The `time` keyword before the pipeline (KNSH-036), which reports how long the whole pipeline took and runs it
    /// unchanged: a wrapper (FR-LC-04) whose commands are decided as if it were not there.
    pub time: Option<TimeKeyword>,
    /// The `!` before the pipeline, which inverts its status. Bash 3.2 (`/bin/bash` on macOS) accepts at most one.
    pub negation: Option<Span>,
    /// The first command.
    pub first: Command,
    /// Each later command with the pipe before it.
    pub rest: Vec<PipelinePart>,
    /// From the `time` keyword or the `!`, whichever comes first (or the first command), to the last command.
    pub span: Span,
}

/// The `time` keyword before a pipeline, `time` or `time -p` (KNSH-036).
///
/// Read only where bash 3.2 and later bash agree it is the keyword: first in a pipeline that is not after `!` or `|`,
/// followed by a command. Elsewhere (`! time ls`, `a | time b`, `time` alone, `time --`) bash versions differ between
/// the keyword and the `time` program, and the parser refuses the line (KNSH-032), so it is dynamic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimeKeyword {
    /// The `time` word.
    pub keyword: Span,
    /// The `-p` option (POSIX output format), the only one bash 3.2 takes.
    pub posix: Option<Span>,
}

impl TimeKeyword {
    /// From `time` to its option, if any.
    #[must_use]
    pub fn span(&self) -> Span {
        Span::new(
            self.keyword.start,
            self.posix.map_or(self.keyword.end, |posix| posix.end),
        )
    }
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

/// A command: one element of a [`Pipeline`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// A simple command.
    Simple(SimpleCommand),
    /// A compound command decision 6 makes exact: a subshell, a group, `if`, `for`, `while`, `until` or `case`.
    Compound(CompoundCommand),
    /// A function definition, `name () body` or `function name body`.
    FunctionDefinition(FunctionDefinition),
    /// Valid bash outside decision 6's exact list (`select`, `[[ … ]]`, `(( … ))`, `for (( … ))`, or a function whose
    /// body is one of them). Its extent is known, so the rest of the line is still read exactly, but nothing inside it
    /// is: the caller must classify it as dynamic (KNSH-032), never skip it.
    Unsupported(UnsupportedCommand),
}

impl Command {
    /// Where the command is, redirections on a compound command included.
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Simple(simple) => simple.span,
            Self::Compound(compound) => compound.span,
            Self::FunctionDefinition(definition) => definition.span,
            Self::Unsupported(unsupported) => unsupported.span,
        }
    }
}

/// A compound command with the redirections written after it, which apply to everything it runs
/// (`{ a; b; } 2>&1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompoundCommand {
    /// Which compound command, with its parts.
    pub kind: CompoundKind,
    /// The redirections after the closing word or operator, in source order. Bash allows nothing else there.
    pub redirections: Vec<Redirect>,
    /// From the opening word or operator to the end of the last redirection (or the closing word or operator).
    pub span: Span,
}

/// The compound commands decision 6 makes exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompoundKind {
    /// `( list )`: runs the list in a child shell, so its assignments and definitions do not outlive it.
    Subshell(Subshell),
    /// `{ list; }`: runs the list in the current shell.
    Group(Group),
    /// `if list; then list; [elif list; then list;]… [else list;] fi`.
    If(IfCommand),
    /// `for name [in words]; do list; done` (or with `{ list; }` as the body).
    For(ForCommand),
    /// `while list; do list; done`.
    While(LoopCommand),
    /// `until list; do list; done`.
    Until(LoopCommand),
    /// `case word in [pattern) list ;;]… esac`.
    Case(CaseCommand),
}

impl CompoundKind {
    /// The lists of [`CompoundKind::lists`], mutably, for the passes that annotate the tree after parsing.
    pub(crate) fn lists_mut(&mut self) -> Vec<&mut Vec<ListItem>> {
        match self {
            Self::Subshell(subshell) => vec![&mut subshell.body],
            Self::Group(group) => vec![&mut group.body],
            Self::If(command) => {
                let mut lists = Vec::with_capacity(command.clauses.len() * 2 + 1);
                for clause in &mut command.clauses {
                    lists.push(&mut clause.condition);
                    lists.push(&mut clause.body);
                }
                if let Some(otherwise) = &mut command.else_clause {
                    lists.push(&mut otherwise.body);
                }
                lists
            }
            Self::For(command) => vec![&mut command.body.body],
            Self::While(command) | Self::Until(command) => vec![&mut command.condition, &mut command.body.body],
            Self::Case(command) => command.clauses.iter_mut().map(|clause| &mut clause.body).collect(),
        }
    }

    /// The lists of commands the compound command holds, in source order: conditions, bodies and case arms.
    #[must_use]
    pub fn lists(&self) -> Vec<&[ListItem]> {
        match self {
            Self::Subshell(subshell) => vec![&subshell.body],
            Self::Group(group) => vec![&group.body],
            Self::If(command) => {
                let mut lists = Vec::with_capacity(command.clauses.len() * 2 + 1);
                for clause in &command.clauses {
                    lists.push(clause.condition.as_slice());
                    lists.push(clause.body.as_slice());
                }
                if let Some(otherwise) = &command.else_clause {
                    lists.push(&otherwise.body);
                }
                lists
            }
            Self::For(command) => vec![&command.body.body],
            Self::While(command) | Self::Until(command) => vec![&command.condition, &command.body.body],
            Self::Case(command) => command.clauses.iter().map(|clause| clause.body.as_slice()).collect(),
        }
    }
}

/// `( list )`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subshell {
    /// The `(`.
    pub open: Span,
    /// The commands, never empty.
    pub body: Vec<ListItem>,
    /// The `)`.
    pub close: Span,
}

/// `{ list; }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The `{`.
    pub open: Span,
    /// The commands, never empty.
    pub body: Vec<ListItem>,
    /// The `}`.
    pub close: Span,
}

/// `if … fi`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfCommand {
    /// The `if` clause, then each `elif` clause, in source order. Never empty.
    pub clauses: Vec<IfClause>,
    /// The `else` clause, if any.
    pub else_clause: Option<ElseClause>,
    /// The `fi`.
    pub fi: Span,
}

/// An `if` or `elif` clause: a condition and the body it guards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfClause {
    /// The `if` or `elif`.
    pub keyword: Span,
    /// The condition's commands, never empty.
    pub condition: Vec<ListItem>,
    /// The `then`.
    pub then: Span,
    /// The commands run when the condition succeeds, never empty.
    pub body: Vec<ListItem>,
}

/// The `else` clause of an `if`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElseClause {
    /// The `else`.
    pub keyword: Span,
    /// The commands, never empty.
    pub body: Vec<ListItem>,
}

/// `for name [in words]; do list; done`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForCommand {
    /// The `for`.
    pub keyword: Span,
    /// The loop variable, as written (bash checks that it is a valid name only when the loop runs).
    pub variable: CommandWord,
    /// The `in` list. `None` when it is left out, so the loop runs over the positional parameters (`"$@"`).
    pub items: Option<ForItems>,
    /// The body.
    pub body: LoopBody,
}

/// The `in words` part of a `for` loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForItems {
    /// The `in`.
    pub keyword: Span,
    /// The words the loop runs over, possibly none (`for x in; do …`).
    pub words: Vec<CommandWord>,
}

/// `while list; do list; done` or `until list; do list; done`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopCommand {
    /// The `while` or `until`.
    pub keyword: Span,
    /// The condition's commands, never empty. Bash runs them at least once.
    pub condition: Vec<ListItem>,
    /// The body.
    pub body: LoopBody,
}

/// The body of a loop: `do list; done`, or `{ list; }` (accepted by bash after a `for` header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopBody {
    /// The `do` or `{`.
    pub open: Span,
    /// The commands, never empty.
    pub body: Vec<ListItem>,
    /// The `done` or `}`.
    pub close: Span,
}

/// `case word in … esac`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseCommand {
    /// The `case`.
    pub keyword: Span,
    /// The word matched against the patterns.
    pub subject: CommandWord,
    /// The `in`.
    pub in_keyword: Span,
    /// The arms, in source order, possibly none (`case x in esac`).
    pub clauses: Vec<CaseClause>,
    /// The `esac`.
    pub esac: Span,
}

/// One arm of a `case`: `[(] pattern [| pattern]… ) list [;; | ;& | ;;&]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseClause {
    /// The optional `(` before the first pattern.
    pub open: Option<Span>,
    /// The patterns, never empty.
    pub patterns: Vec<CommandWord>,
    /// The `)` after the patterns.
    pub close: Span,
    /// The commands run when a pattern matches, possibly none.
    pub body: Vec<ListItem>,
    /// What ends the arm. `None` only for the last arm when `esac` follows its body directly.
    pub terminator: Option<CaseTerminator>,
}

/// The operator that ends a [`CaseClause`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaseTerminator {
    /// Which one.
    pub kind: CaseTerminatorKind,
    /// Where it is.
    pub span: Span,
}

/// What a `case` arm does after its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaseTerminatorKind {
    /// `;;`: leave the `case`.
    Break,
    /// `;&`: run the next arm's body too, without testing its patterns (bash 4; bash 3.2 rejects the line).
    FallThrough,
    /// `;;&`: go on testing the next arms' patterns (bash 4; bash 3.2 rejects the line).
    Continue,
}

/// A function definition: `name () body` or `function name [()] body`.
///
/// Defining a function runs nothing; calling it runs the body. The body is walked as code wherever it is written
/// ([`Script::simple_commands`]), and calls that certainly reach it are marked ([`SimpleCommand::function_call`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionDefinition {
    /// The `function` reserved word, when that form is used.
    pub keyword: Option<Span>,
    /// The name, as written. Bash refuses a quoted name or one with `$` when the definition runs, and only a plain
    /// identifier is ever matched to a call.
    pub name: CommandWord,
    /// The `()` (from `(` to `)`), required without `function`, optional with it.
    pub parens: Option<Span>,
    /// The body: a compound command, with the redirections applied on every call.
    pub body: CompoundCommand,
    /// From the `function` (or the name) to the end of the body.
    pub span: Span,
}

/// A construct outside decision 6's exact list, kept whole so that it is never dropped (see
/// [`Command::Unsupported`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedCommand {
    /// What it is.
    pub construct: UnsupportedConstruct,
    /// All of it, redirections written after it included.
    pub span: Span,
    /// For `(( … ))` and `for (( … ))` (not as a function body): the parts an evaluator needs, as the parser read
    /// them (KNSH-097). The node stays opaque to the classifier: this only saves the native interpreter from reading
    /// the construct a second time.
    pub arithmetic: Option<Box<ArithmeticParts>>,
}

/// The parts of an arithmetic command or arithmetic `for` loop (KNSH-097), kept inside a
/// [`Command::Unsupported`] node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArithmeticParts {
    /// `(( expression ))`.
    Command {
        /// The expression, between `((` and `))`.
        expression: Span,
        /// The closing `))`. Anything in the node's span after it is a redirection.
        close: Span,
    },
    /// `for (( init; test; update ))` and its body.
    For {
        /// The three expressions and the `;` between them, between `((` and `))`, as written.
        expressions: Span,
        /// The body, `do … done` or `{ … }`. Anything in the node's span after its close is a redirection.
        body: LoopBody,
    },
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
    /// Set when the command certainly calls a function defined earlier in the line, so its name is not a program to
    /// resolve (KNSH-035): the function's body is what runs. `None` means the name may run a program, and the caller
    /// resolves it as one; that is also the answer whenever the parser is not certain (FR-LC-09: a call is never
    /// hidden behind a guess that it is a function).
    pub function_call: Option<FunctionCall>,
    /// From the first part to the last.
    pub span: Span,
}

/// How a [`SimpleCommand`] that calls a function was resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionCall {
    /// The spans of the [`FunctionDefinition`]s the call may run, in source order: the last one certainly run
    /// before it, and any run conditionally after that one. Never empty.
    pub definitions: Vec<Span>,
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

    /// Every substitution of the command: in its assignments, then its words, then its redirections (targets and
    /// here-document bodies). Bash runs them all before the command itself.
    pub fn substitutions(&self) -> impl Iterator<Item = &Substitution> + '_ {
        let assignments = self.assignments.iter().flat_map(|assignment| &assignment.substitutions);
        let words = self.words.iter().flat_map(|word| &word.substitutions);
        let redirections = self.redirections.iter().flat_map(Redirect::substitutions);
        assignments.chain(words).chain(redirections)
    }
}

/// A word of a command with its place in the line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandWord {
    /// The word, with its quoting structure.
    pub word: Word,
    /// Where it is.
    pub span: Span,
    /// The command substitutions, backticks and process substitutions in the word (inside double quotes too), in
    /// source order, each parsed into a nested script (KNSH-031). Empty for a here-document delimiter, which bash
    /// never expands.
    pub substitutions: Vec<Substitution>,
}

/// A command substitution, backtick or process substitution, with its body parsed (KNSH-031; decision 6: parsed
/// recursively). Its commands run in a child shell before the command that holds it, or alongside it for a process
/// substitution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Substitution {
    /// Which form.
    pub kind: SubstitutionKind,
    /// The whole substitution, delimiters included, in the text that holds it.
    pub span: Span,
    /// For a backtick substitution whose body bash un-escapes before reading it: the un-escaped body. Bash removes
    /// the backslash of `\$`, ``\` `` and `\\` (and of `\"` when the backticks are inside double quotes) and removes line
    /// continuations; the spans of [`script`](Self::script) then index this text. `None` when the body is read as
    /// written, and the script's spans index the text that holds the substitution.
    pub text: Option<String>,
    /// The body, parsed. Its span is the body (between the delimiters), or all of [`text`](Self::text).
    pub script: Script,
}

impl Substitution {
    /// The text the spans of [`script`](Self::script) index, given `enclosing`, the text that holds the
    /// substitution.
    #[must_use]
    pub fn source<'a>(&'a self, enclosing: &'a str) -> &'a str {
        self.text.as_deref().unwrap_or(enclosing)
    }
}

/// The forms of [`Substitution`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubstitutionKind {
    /// `$( … )`.
    Command,
    /// `` `…` ``.
    Backtick,
    /// `<( … )`: the body's output is read as a file.
    InputProcess,
    /// `>( … )`: the body's input is written as a file.
    OutputProcess,
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
    /// The substitutions in the value, each parsed into a nested script (KNSH-031): `X=$(curl …) cmd` runs `curl`.
    pub substitutions: Vec<Substitution>,
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
    /// The target word: a file, a descriptor number or `-` for `>&` and `<&`, the string of a here-string, or the
    /// delimiter of a here-document.
    pub target: CommandWord,
    /// For `<<` and `<<-`: the here-document's body, read from the lines after the one holding the operator.
    /// `None` for every other operator.
    pub here_document: Option<HereDocument>,
    /// Set on a here-document or here-string whose text is read by a shell or interpreter (`bash <<EOF`,
    /// `python3 <<< "…"`), or by a command that may run one (`env bash`, `ssh host`, a function of the line, a name
    /// built from an expansion, a compound command holding such a command). Its text is then code, which the caller
    /// classifies as dynamic (decision 6, FR-LC-05, KNSH-031). Never set on other redirections.
    pub feeds_interpreter: bool,
    /// From the descriptor number (or operator) to the end of the target. A here-document's body lies elsewhere.
    pub span: Span,
}

impl Redirect {
    /// The substitutions of the redirection: in its target, then in its here-document body.
    pub fn substitutions(&self) -> impl Iterator<Item = &Substitution> + '_ {
        let body = self.here_document.iter().flat_map(|document| &document.substitutions);
        self.target.substitutions.iter().chain(body)
    }
}

/// A here-document's body (KNSH-031).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HereDocument {
    /// Set for `<<-`: leading tabs are removed from each line of the body (they stay in the spans and segments).
    pub strip_tabs: bool,
    /// Set when the delimiter is quoted (`<<'EOF'`): the body is literal and runs nothing. Otherwise bash expands it,
    /// running its substitutions.
    pub quoted: bool,
    /// The body lines, up to (not including) the delimiter line. May be empty.
    pub body: Span,
    /// The body split into segments (see [`HereDocumentBody::segments`](crate::HereDocumentBody::segments)).
    pub segments: Vec<Segment>,
    /// The substitutions bash runs while expanding an unquoted body, in source order, each parsed into a nested
    /// script. Always empty for a quoted body.
    pub substitutions: Vec<Substitution>,
    /// The line that ends the body, its newline included (absent when the input ends right after it).
    pub delimiter: Span,
}
