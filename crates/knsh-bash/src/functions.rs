//! Marks the calls that certainly reach a function defined earlier in the line (KNSH-030; FR-LC-09).
//!
//! A simple command whose name is a function runs the function's body, not a program, so the supervisor should not
//! resolve the name as a binary (KNSH-035). Getting this wrong in one direction is dangerous: a call marked as a
//! function that actually runs a program (`(rm() { :; }); rm -rf x`, where the definition dies with its subshell)
//! would hide the program from policy. Getting it wrong in the other direction is harmless: an unmarked call is
//! resolved as a program, and the function's body is decided anyway, because [`Script::simple_commands`] walks every
//! function body as code wherever it is defined. So a call is marked only when the analysis is certain, and every
//! doubt leaves it unmarked.
//!
//! The analysis follows bash's execution order over the tree, tracking which names are certainly functions:
//!
//! - A definition makes its name certain in the shell environment it runs in. Subshells `( … )`, every command of a
//!   multi-command pipeline and background items `… &` run in child environments whose definitions die with them
//!   (the last command of a pipeline is merged as uncertain, in case `shopt -s lastpipe` is on).
//! - Code that may or may not run (the right side of `&&` and `||`, `then`, `elif` and `else` branches, case arms,
//!   loop bodies) is walked from a copy of the environment, and the copy is merged back: a name stays certain only if
//!   it is certain on both paths. A loop that defines functions or may remove them (see below) makes every name
//!   uncertain before it is walked, since an earlier iteration may have changed them.
//! - A function body is walked once, where it is defined, starting from no certain names: when it runs, the caller's
//!   functions may differ, so only definitions earlier in the same body count for calls inside it.
//! - A compound command with redirections may not run at all (a redirection that fails skips it), and a `while` or
//!   `until` condition may stop early (`break` in it, or in a function it calls, leaves the loop), so both are walked
//!   as code that may or may not run. So are the arms after a `;&` or `;;&` arm, which may run after it.
//! - Bash runs a line one top-level command at a time (up to a newline), and some errors abandon the rest of the
//!   current one without ending the shell: a failed arithmetic expansion, a bad `${…}` substitution, a glob that
//!   matches nothing under `shopt -s failglob`, an assignment to a read-only variable such as `UID`. So when such an
//!   error is possible in a top-level command, the definitions it makes count only as possible after it; calls inside
//!   it are not affected, since the error skips them too.
//! - `unset`, an unsupported construct that hides commands (`select`, `for (( … ))`), and a call to a function whose
//!   body could define, remove or call functions make every name uncertain from then on.
//! - Some commands can change functions in ways the tree does not show, or change how names are looked up: `eval`,
//!   `source`, `.`, `command`, `builtin`, `trap` (its handlers run between commands), `alias`, `readonly`, `declare`,
//!   `typeset`, and any command whose name is not plain text (`$cmd`, `"$(…)"`, globs). If the line holds one
//!   anywhere, no call is marked at all. Such lines are dynamic anyway (decision 6, KNSH-032).
//!
//! Only plain identifiers (`[A-Za-z_][A-Za-z0-9_]*`, unquoted) are matched, since POSIX mode (`POSIXLY_CORRECT`, which
//! an agent can set) refuses other names, and POSIX special builtins (`exec`, `export`, `set`, …) are never matched,
//! since POSIX mode finds them before functions. Past [`MAX_FUNCTION_DEFINITIONS`] definitions nothing is marked,
//! which keeps the analysis linear in the length of the line.

use std::collections::{BTreeMap, BTreeSet};

use crate::ast::{
    AndOr, Assignment, CaseTerminatorKind, Command, CompoundCommand, CompoundKind, FunctionCall, ListItem, Pipeline,
    Redirect, Script, SeparatorKind, SimpleCommand, UnsupportedCommand, collect_commands,
};
use crate::error::{CompoundStart, UnsupportedConstruct};
use crate::limits::MAX_FUNCTION_DEFINITIONS;
use crate::token::{ReservedWord, Segment, SegmentKind, Span, Word};

/// Commands that can change the function table or how names are found in ways the tree does not show. One anywhere
/// in the line turns marking off.
const OPAQUE_COMMANDS: &[&str] = &[
    "eval", "source", ".", "command", "builtin", "trap", "alias", "readonly", "declare", "typeset",
];

/// POSIX special builtins: in POSIX mode bash finds them before functions, so a function with one of these names may
/// never run.
const SPECIAL_BUILTINS: &[&str] = &[
    "break", ":", ".", "continue", "eval", "exec", "exit", "export", "readonly", "return", "set", "shift", "times",
    "trap", "unset",
];

/// Variables bash makes read-only itself (3.2 and later). An assignment to one fails, and outside a command's prefix
/// that abandons the rest of the top-level command; prefixes and `for` variables are treated alike, to be safe.
const READ_ONLY_VARIABLES: &[&str] = &["BASHOPTS", "BASH_VERSINFO", "EUID", "PPID", "SHELLOPTS", "UID"];

/// Sets [`SimpleCommand::function_call`] on every call in `script` that certainly reaches a function defined earlier
/// in the line (see the module documentation for what "certainly" covers).
pub(crate) fn mark_function_calls(script: &mut Script, input: &str) {
    if let Some(resolver) = Resolver::new(script, input) {
        resolver.walk_top_level(&mut script.items, &mut Env::default());
    }
}

/// Facts about the whole line that the walk needs.
struct Resolver<'a> {
    input: &'a str,
    /// The definitions whose name can be matched to calls, by the start of their span: the definition's index (its
    /// bit in [`Env::current`]) and its name's index (its bit in [`Env::certain`]).
    definitions: BTreeMap<usize, (usize, usize)>,
    /// The span of each matchable definition, by index, in source order.
    definition_spans: Vec<Span>,
    /// Each matchable name and its index.
    names: BTreeMap<String, usize>,
    /// For each name index, the bits of its definitions.
    definitions_of_name: Vec<u64>,
    /// Names with at least one definition whose body could define, remove or call functions, or hides commands. A
    /// call to one of them (marked or not) makes every name uncertain.
    unsettling: BTreeSet<String>,
    /// Every name defined anywhere in the line, matchable or not: a call to one runs a body that may do anything.
    defined: BTreeSet<String>,
}

impl<'a> Resolver<'a> {
    /// Gathers the facts, or `None` when nothing may be marked: the line holds an opaque command or a command name
    /// that is not plain text, or more than [`MAX_FUNCTION_DEFINITIONS`] matchable definitions.
    fn new(script: &Script, input: &'a str) -> Option<Self> {
        let mut resolver = Self {
            input,
            definitions: BTreeMap::new(),
            definition_spans: Vec::new(),
            names: BTreeMap::new(),
            definitions_of_name: Vec::new(),
            unsettling: BTreeSet::new(),
            defined: BTreeSet::new(),
        };
        // Only this script's own commands: substitutions run in child shells, whose definitions never reach the line,
        // and their spans may index another text (un-escaped backticks).
        let mut commands = Vec::new();
        collect_commands(&script.items, &mut commands);
        for &command in &commands {
            match command {
                Command::Simple(simple) => {
                    if let Some(name) = simple.name() {
                        let name = static_text(&name.word, input)?;
                        if OPAQUE_COMMANDS.contains(&name.as_str()) {
                            return None;
                        }
                    }
                }
                Command::FunctionDefinition(definition) => {
                    // Bash refuses a name with `$` in it when the definition runs, but which name it would have is
                    // not known here.
                    let name = static_text(&definition.name.word, input)?;
                    if matchable_definition_name(&definition.name.word, &name) {
                        resolver.add_definition(&name, definition.span)?;
                    }
                    resolver.defined.insert(name);
                }
                Command::Compound(_) | Command::Unsupported(_) => {}
            }
        }
        let definitions = commands.iter().filter_map(|command| match command {
            Command::FunctionDefinition(definition) => Some(definition),
            Command::Simple(_) | Command::Compound(_) | Command::Unsupported(_) => None,
        });
        for definition in definitions {
            if !resolver.is_settled_body(&definition.body)
                && let Some(name) = static_text(&definition.name.word, input)
            {
                resolver.unsettling.insert(name);
            }
        }
        Some(resolver)
    }

    /// Records a matchable definition, or `None` past the limit.
    fn add_definition(&mut self, name: &str, span: Span) -> Option<()> {
        let index = self.definition_spans.len();
        if index >= MAX_FUNCTION_DEFINITIONS {
            return None;
        }
        self.definition_spans.push(span);
        let next_name = self.names.len();
        let name_index = *self.names.entry(name.to_owned()).or_insert(next_name);
        if name_index == self.definitions_of_name.len() {
            self.definitions_of_name.push(0);
        }
        let mask = self.definitions_of_name.get_mut(name_index)?;
        *mask |= 1 << index;
        self.definitions.insert(span.start, (index, name_index));
        Some(())
    }

    /// Whether running `body` certainly leaves every function as it was: it defines none, removes none (`unset`),
    /// calls none of the line's function names, and holds no unsupported construct whose contents are unknown.
    fn is_settled_body(&self, body: &CompoundCommand) -> bool {
        let mut commands = Vec::new();
        for list in body.kind.lists() {
            collect_commands(list, &mut commands);
        }
        commands.into_iter().all(|command| match command {
            Command::Simple(simple) => self
                .command_name(simple)
                .is_none_or(|name| name != "unset" && !self.defined.contains(&name)),
            Command::Compound(_) => true,
            Command::FunctionDefinition(_) => false,
            Command::Unsupported(unsupported) => !self.unsupported_may_change(unsupported),
        })
    }

    /// Whether running `items` may change any function: they define one, remove one, call an unsettling function,
    /// or hold an unsupported construct.
    fn may_change_functions(&self, items: &[ListItem]) -> bool {
        let mut commands = Vec::new();
        collect_commands(items, &mut commands);
        commands.into_iter().any(|command| match command {
            Command::Simple(simple) => self.command_name(simple).is_some_and(|name| self.unsettles(&name)),
            Command::Compound(_) => false,
            Command::FunctionDefinition(_) => true,
            Command::Unsupported(unsupported) => self.unsupported_may_change(unsupported),
        })
    }

    /// Whether an unsupported construct may change functions: it hides commands, or it is not a bare `[[ … ]]` or
    /// `(( … ))` but a function definition whose body is one (`f() [[ … ]]` redefines `f`, and its name is unknown
    /// here).
    fn unsupported_may_change(&self, unsupported: &UnsupportedCommand) -> bool {
        hides_commands(unsupported.construct)
            || !unsupported
                .span
                .text(self.input)
                .is_some_and(|text| text.starts_with("[[") || text.starts_with("(("))
    }

    /// Whether running `items` may abandon the rest of the top-level command they belong to (see the module
    /// documentation) before their last definition has run. Function bodies are not looked into where they are
    /// defined; a call to any function of the line counts as possibly abandoning instead.
    fn may_abandon(&self, items: &[ListItem]) -> bool {
        items
            .iter()
            .flat_map(|item| item.and_or.pipelines())
            .flat_map(Pipeline::commands)
            .any(|command| self.command_may_abandon(command))
    }

    fn command_may_abandon(&self, command: &Command) -> bool {
        match command {
            Command::Simple(simple) => {
                let assignment_fails = |assignment: &Assignment| {
                    READ_ONLY_VARIABLES.contains(&assignment.name.as_str())
                        || word_may_abandon(&assignment.word, self.input, true)
                };
                // A call to a function of the line runs a body that may fail this way.
                let calls_a_function = simple.name().is_some()
                    && self
                        .command_name(simple)
                        .is_none_or(|name| self.defined.contains(&name));
                simple.assignments.iter().any(assignment_fails)
                    || simple
                        .words
                        .iter()
                        .any(|word| word_may_abandon(&word.word, self.input, false))
                    || redirections_may_abandon(&simple.redirections, self.input)
                    || calls_a_function
            }
            Command::Compound(compound) => {
                redirections_may_abandon(&compound.redirections, self.input)
                    || match &compound.kind {
                        CompoundKind::For(command) => {
                            static_text(&command.variable.word, self.input)
                                .is_none_or(|name| READ_ONLY_VARIABLES.contains(&name.as_str()))
                                || command.items.as_ref().is_some_and(|items| {
                                    items
                                        .words
                                        .iter()
                                        .any(|word| word_may_abandon(&word.word, self.input, false))
                                })
                        }
                        CompoundKind::Case(command) => {
                            word_may_abandon(&command.subject.word, self.input, true)
                                || command.clauses.iter().any(|clause| {
                                    clause
                                        .patterns
                                        .iter()
                                        .any(|pattern| word_may_abandon(&pattern.word, self.input, true))
                                })
                        }
                        CompoundKind::Subshell(_)
                        | CompoundKind::Group(_)
                        | CompoundKind::If(_)
                        | CompoundKind::While(_)
                        | CompoundKind::Until(_) => false,
                    }
                    || compound.kind.lists().into_iter().any(|list| self.may_abandon(list))
            }
            // Defining runs nothing: the body and its redirections are used only when it is called.
            Command::FunctionDefinition(_) => false,
            // Its contents are unknown (`(( 1/0 ))`, `[[ … ]]` with arithmetic).
            Command::Unsupported(_) => true,
        }
    }

    /// The plain text of `simple`'s name, or `None` when it has no name or the name is not plain text.
    fn command_name(&self, simple: &SimpleCommand) -> Option<String> {
        simple.name().and_then(|name| static_text(&name.word, self.input))
    }

    /// Whether a command named `name` may change the functions of the shell it runs in.
    fn unsettles(&self, name: &str) -> bool {
        name == "unset" || self.unsettling.contains(name)
    }

    // ---- The walk, in execution order ----

    /// The line's items, one top-level command (up to a newline) at a time: when one may be abandoned partway, what
    /// it defines is only possible after it.
    fn walk_top_level(&self, items: &mut [ListItem], env: &mut Env) {
        let mut rest = items;
        while !rest.is_empty() {
            let end = rest
                .iter()
                .position(|item| {
                    item.separator
                        .is_some_and(|separator| separator.kind == SeparatorKind::Newline)
                })
                .map_or(rest.len(), |index| index + 1);
            let (command, tail) = rest.split_at_mut(end);
            if self.may_abandon(command) {
                env.maybe(|branch| self.walk_list(command, branch));
            } else {
                self.walk_list(command, env);
            }
            rest = tail;
        }
    }

    fn walk_list(&self, items: &mut [ListItem], env: &mut Env) {
        for item in items {
            if item.is_background() {
                // `… &` runs in a child shell: nothing it defines or removes reaches the line.
                let mut child = *env;
                self.walk_and_or(&mut item.and_or, &mut child);
            } else {
                self.walk_and_or(&mut item.and_or, env);
            }
        }
    }

    fn walk_and_or(&self, and_or: &mut AndOr, env: &mut Env) {
        self.walk_pipeline(&mut and_or.first, env);
        // Each later pipeline may or may not run.
        for part in &mut and_or.rest {
            env.maybe(|branch| self.walk_pipeline(&mut part.pipeline, branch));
        }
    }

    fn walk_pipeline(&self, pipeline: &mut Pipeline, env: &mut Env) {
        let Some((last, middle)) = pipeline.rest.split_last_mut() else {
            self.walk_command(&mut pipeline.first, env);
            return;
        };
        // Every command of a pipeline runs in a child shell; with `shopt -s lastpipe` the last one runs in this shell,
        // so its effects are merged as uncertain.
        let mut child = *env;
        self.walk_command(&mut pipeline.first, &mut child);
        for part in middle {
            let mut child = *env;
            self.walk_command(&mut part.command, &mut child);
        }
        env.maybe(|branch| self.walk_command(&mut last.command, branch));
    }

    fn walk_command(&self, command: &mut Command, env: &mut Env) {
        match command {
            Command::Simple(simple) => self.walk_call(simple, env),
            // A redirection that fails skips the whole compound command.
            Command::Compound(compound) if !compound.redirections.is_empty() => {
                env.maybe(|branch| self.walk_compound(compound, branch));
            }
            Command::Compound(compound) => self.walk_compound(compound, env),
            Command::FunctionDefinition(definition) => {
                // The body runs only when called, with whatever functions the caller has: walked from none.
                self.walk_compound(&mut definition.body, &mut Env::default());
                if let Some(&(index, name)) = self.definitions.get(&definition.span.start)
                    && let Some(&mask) = self.definitions_of_name.get(name)
                {
                    env.define(name, index, mask);
                }
            }
            // Commands inside it are unknown, so they may change anything.
            Command::Unsupported(unsupported) => {
                if self.unsupported_may_change(unsupported) {
                    env.unsettle();
                }
            }
        }
    }

    fn walk_compound(&self, compound: &mut CompoundCommand, env: &mut Env) {
        match &mut compound.kind {
            CompoundKind::Subshell(subshell) => {
                let mut child = *env;
                self.walk_list(&mut subshell.body, &mut child);
            }
            CompoundKind::Group(group) => self.walk_list(&mut group.body, env),
            CompoundKind::If(command) => {
                for (index, clause) in command.clauses.iter_mut().enumerate() {
                    // Only the first condition certainly runs.
                    if index == 0 {
                        self.walk_list(&mut clause.condition, env);
                    } else {
                        env.maybe(|branch| self.walk_list(&mut clause.condition, branch));
                    }
                    env.maybe(|branch| self.walk_list(&mut clause.body, branch));
                }
                if let Some(otherwise) = &mut command.else_clause {
                    env.maybe(|branch| self.walk_list(&mut otherwise.body, branch));
                }
            }
            CompoundKind::For(command) => self.walk_loop(None, &mut command.body.body, env),
            CompoundKind::While(command) | CompoundKind::Until(command) => {
                self.walk_loop(Some(&mut command.condition), &mut command.body.body, env);
            }
            CompoundKind::Case(command) => {
                // An arm after a `;&` or `;;&` arm may run after it, so it starts from either state; keeping every
                // such arm's state for all later arms is wider than bash, which is safe.
                let start = *env;
                let mut carried: Option<Env> = None;
                for clause in &mut command.clauses {
                    let mut branch = start;
                    if let Some(carried) = carried {
                        branch.merge(carried);
                    }
                    self.walk_list(&mut clause.body, &mut branch);
                    env.merge(branch);
                    match clause.terminator.map(|terminator| terminator.kind) {
                        Some(CaseTerminatorKind::FallThrough | CaseTerminatorKind::Continue) => {
                            carried = Some(carried.map_or(branch, |mut carried| {
                                carried.merge(branch);
                                carried
                            }));
                        }
                        Some(CaseTerminatorKind::Break) | None => {}
                    }
                }
            }
        }
    }

    /// A loop: the condition (if any) starts at least once, the body runs any number of times. The condition is still
    /// walked as code that may not run to its end: a `break` in it (or in a function it calls) leaves the loop
    /// (`while break; f() { …; }; do …; done; f` runs a program `f`). Each command is walked once,
    /// so its mark must hold on every iteration: if the loop may change functions at all, every name is made uncertain
    /// first, since an earlier iteration may have changed it.
    fn walk_loop(&self, condition: Option<&mut Vec<ListItem>>, body: &mut [ListItem], env: &mut Env) {
        let changes = condition
            .as_deref()
            .is_some_and(|condition| self.may_change_functions(condition))
            || self.may_change_functions(body);
        if changes {
            env.unsettle();
        }
        if let Some(condition) = condition {
            env.maybe(|branch| self.walk_list(condition, branch));
        }
        env.maybe(|branch| self.walk_list(body, branch));
    }

    /// Marks `simple` if it certainly calls a function, then applies what it may do to the functions.
    fn walk_call(&self, simple: &mut SimpleCommand, env: &mut Env) {
        let Some(name) = self.command_name(simple) else {
            // No name runs nothing. A name that is not plain text was ruled out in `new`; stay safe regardless.
            if simple.name().is_some() {
                env.unsettle();
            }
            return;
        };
        if let Some(&index) = self.names.get(&name)
            && env.is_certain(index)
            && let Some(&mask) = self.definitions_of_name.get(index)
        {
            let definitions: Vec<Span> = self
                .definition_spans
                .iter()
                .enumerate()
                .filter(|&(bit, _)| env.current & mask & (1 << bit) != 0)
                .map(|(_, span)| *span)
                .collect();
            if !definitions.is_empty() {
                simple.function_call = Some(FunctionCall { definitions });
            }
        }
        if self.unsettles(&name) {
            env.unsettle();
        }
    }
}

/// What is known about the functions at one point of the line, as bit sets (at most
/// [`MAX_FUNCTION_DEFINITIONS`] definitions, so they fit a `u64`). Copying it is free, which keeps the walk linear.
#[derive(Debug, Clone, Copy, Default)]
struct Env {
    /// Bit per name index: the name is certainly a function here.
    certain: u64,
    /// Bit per definition index: the definition may be the current one for its name here.
    current: u64,
}

impl Env {
    /// A definition of name `name` (index), definition `index`, runs: the name is certainly a function and that
    /// definition replaces the name's others. `mask` holds the bits of all of the name's definitions.
    fn define(&mut self, name: usize, index: usize, mask: u64) {
        self.certain |= 1 << name;
        self.current = (self.current & !mask) | (1 << index);
    }

    /// Something may have removed or replaced any function: no name is certain any more.
    fn unsettle(&mut self) {
        self.certain = 0;
    }

    fn is_certain(self, name: usize) -> bool {
        self.certain & (1 << name) != 0
    }

    /// Joins the state after another path into this one: certain only if certain on both, and any definition current
    /// on either may be current.
    fn merge(&mut self, other: Self) {
        self.certain &= other.certain;
        self.current |= other.current;
    }

    /// Walks code that may or may not run: from a copy of this state, merged back.
    fn maybe(&mut self, walk: impl FnOnce(&mut Self)) {
        let mut branch = *self;
        walk(&mut branch);
        self.merge(branch);
    }
}

/// Whether an unsupported construct holds commands the tree does not show (`select` and `for (( … ))` bodies), which
/// could change functions. `[[ … ]]` and `(( … ))` hold expressions only: any command substitution in them runs in a
/// child shell, which cannot change this one's functions.
fn hides_commands(construct: UnsupportedConstruct) -> bool {
    match construct {
        UnsupportedConstruct::Compound(
            CompoundStart::Arithmetic | CompoundStart::ReservedWord(ReservedWord::DoubleLeftBracket),
        ) => false,
        UnsupportedConstruct::Compound(CompoundStart::ArithmeticFor | CompoundStart::ReservedWord(_))
        | UnsupportedConstruct::SubstitutionInExpansion
        | UnsupportedConstruct::OpaqueHereDocument
        | UnsupportedConstruct::ArrayAssignment
        | UnsupportedConstruct::SubscriptAssignment
        | UnsupportedConstruct::RedirectionVariable => true,
    }
}

/// Whether expanding the targets of `redirections`, or the bodies of unquoted here-documents among them, may abandon
/// the top-level command. A body is expanded like double-quoted text (no globbing), so only its arithmetic and `${…}`
/// expansions count.
fn redirections_may_abandon(redirections: &[Redirect], input: &str) -> bool {
    redirections.iter().any(|redirect| {
        word_may_abandon(&redirect.target.word, input, false)
            || redirect.here_document.as_ref().is_some_and(|document| {
                !document.quoted
                    && document
                        .segments
                        .iter()
                        .any(|segment| segment_may_abandon(segment, input, true))
            })
    })
}

/// Whether expanding `word` may fail in a way that abandons the rest of the top-level command: arithmetic and `${…}`
/// expansions (division by zero, bad substitution), and unquoted glob characters or unquoted expansion results
/// (`failglob`). Quoted command substitutions fail only in their own child shell. `quoted` is set inside double
/// quotes, and for words bash does not glob (assignments, `case` subjects and patterns).
fn word_may_abandon(word: &Word, input: &str, quoted: bool) -> bool {
    word.segments
        .iter()
        .any(|segment| segment_may_abandon(segment, input, quoted))
}

fn segment_may_abandon(segment: &Segment, input: &str, quoted: bool) -> bool {
    match &segment.kind {
        // A literal that is not text cannot happen; count it as a failure, to be safe.
        SegmentKind::Literal => {
            !quoted
                && segment
                    .span
                    .text(input)
                    .is_none_or(|literal| literal.contains(['*', '?', '[']))
        }
        SegmentKind::Escape
        | SegmentKind::SingleQuoted
        | SegmentKind::LineContinuation
        | SegmentKind::AnsiC
        | SegmentKind::InputProcessSubstitution
        | SegmentKind::OutputProcessSubstitution => false,
        SegmentKind::DoubleQuoted(inner) | SegmentKind::Locale(inner) => {
            inner.iter().any(|part| segment_may_abandon(part, input, true))
        }
        SegmentKind::Parameter | SegmentKind::CommandSubstitution | SegmentKind::Backtick => !quoted,
        SegmentKind::ParameterExpansion | SegmentKind::Arithmetic => true,
    }
}

/// Whether a definition's name can be matched to calls: written as plain unquoted text (bash refuses a quoted name
/// when the definition runs), a valid identifier (POSIX mode refuses others), and not a POSIX special builtin.
fn matchable_definition_name(word: &Word, name: &str) -> bool {
    word.segments
        .iter()
        .all(|segment| matches!(segment.kind, SegmentKind::Literal | SegmentKind::LineContinuation))
        && is_identifier(name)
        && !SPECIAL_BUILTINS.contains(&name)
}

/// `[A-Za-z_][A-Za-z0-9_]*`.
fn is_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

/// The text a word stands for after quote removal, when it is certain without running anything: unquoted text
/// without glob, brace or tilde characters (which could expand into other words), escapes, line continuations,
/// single quotes, and double quotes holding only text and escapes. `None` for anything else (expansions, `$'…'`).
/// A call is looked up by this text: `"f"` and `\f` both call function `f`.
pub(crate) fn static_text(word: &Word, input: &str) -> Option<String> {
    let mut text = String::new();
    for segment in &word.segments {
        push_static_segment(segment, input, false, &mut text)?;
    }
    Some(text)
}

/// Appends the text of one segment for [`static_text`]. `quoted` is set inside double quotes, where glob characters
/// are literal.
fn push_static_segment(segment: &Segment, input: &str, quoted: bool, text: &mut String) -> Option<()> {
    match &segment.kind {
        SegmentKind::Literal => {
            let literal = segment.span.text(input)?;
            if !quoted && literal.contains(['*', '?', '[', '{', '~']) {
                return None;
            }
            text.push_str(literal);
        }
        SegmentKind::Escape | SegmentKind::SingleQuoted => text.push_str(segment.body.text(input)?),
        SegmentKind::LineContinuation => {}
        SegmentKind::DoubleQuoted(inner) => {
            for part in inner {
                push_static_segment(part, input, true, text)?;
            }
        }
        SegmentKind::AnsiC
        | SegmentKind::Locale(_)
        | SegmentKind::Parameter
        | SegmentKind::ParameterExpansion
        | SegmentKind::CommandSubstitution
        | SegmentKind::Backtick
        | SegmentKind::Arithmetic
        | SegmentKind::InputProcessSubstitution
        | SegmentKind::OutputProcessSubstitution => return None,
    }
    Some(())
}
