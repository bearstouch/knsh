//! The check of a whole script before it runs (KNSH-096, KNSH-097): every construct a later story implements is
//! refused here, with its span, so a script the interpreter cannot evaluate runs none of its commands.
//!
//! Expansions are read but not performed: each `${…}` body is parsed, and the words and expressions inside it are
//! scanned, so an array, a command substitution or a variable bash maintains itself is refused wherever it is
//! written. What depends on a value (a variable named only at run time, a command name produced by an expansion, a
//! value bash would split) is refused when the expansion happens instead.
//!
//! The walk mirrors [`crate::eval`] and counts nesting the same way, under the same limit, so a tree nested deeper
//! than the limit is refused before evaluation and the check itself never overflows the stack.

use knsh_bash::{
    AndOr, ArithmeticParts, Command, CommandWord, CompoundCommand, CompoundKind, ListItem, Pipeline, SimpleCommand,
    Span, UnsupportedCommand,
};

use crate::error::{InterpError, Unsupported};
use crate::eval::{external_builtin_differs, is_refused_builtin, trailing_redirection};
use crate::expand::MAX_EXPANSION_DEPTH;
use crate::param::{self, Name, Op, Parsed};
use crate::scan::{self, Mode, Part};
use crate::state::{is_always_unemulated, lists_always_unemulated};
use crate::word::{self, Context, has_brace_expansion, has_glob, literal_view};

/// Checks `items` (a script's top-level list) against `source`, nesting at most `max_depth` lists.
///
/// # Errors
///
/// [`InterpError::Unsupported`] for the first unsupported construct in source order, [`InterpError::DepthExceeded`]
/// past `max_depth`, [`InterpError::SourceMismatch`] if a span does not index `source`.
pub(crate) fn check(items: &[ListItem], source: &str, max_depth: usize) -> Result<(), InterpError> {
    Checker { source, max_depth }.list(items, 0)
}

/// The walk's fixed inputs.
struct Checker<'a> {
    source: &'a str,
    max_depth: usize,
}

const fn refuse(feature: Unsupported, span: Span) -> InterpError {
    InterpError::Unsupported { feature, span }
}

impl Checker<'_> {
    /// A list nested `depth` lists deep (0 for the script itself).
    fn list(&self, items: &[ListItem], depth: usize) -> Result<(), InterpError> {
        if depth >= self.max_depth {
            return Err(InterpError::DepthExceeded { limit: self.max_depth });
        }
        for item in items {
            self.and_or(&item.and_or, depth + 1)?;
            if item.is_background()
                && let Some(separator) = item.separator
            {
                return Err(refuse(Unsupported::Background, separator.span));
            }
        }
        Ok(())
    }

    fn and_or(&self, and_or: &AndOr, depth: usize) -> Result<(), InterpError> {
        and_or
            .pipelines()
            .try_for_each(|pipeline| self.pipeline(pipeline, depth))
    }

    fn pipeline(&self, pipeline: &Pipeline, depth: usize) -> Result<(), InterpError> {
        if let Some(time) = pipeline.time {
            return Err(refuse(Unsupported::Time, time.span()));
        }
        self.command(&pipeline.first, depth)?;
        match pipeline.rest.first() {
            Some(part) => Err(refuse(Unsupported::Pipeline, part.operator_span)),
            None => Ok(()),
        }
    }

    fn command(&self, command: &Command, depth: usize) -> Result<(), InterpError> {
        match command {
            Command::Simple(simple) => self.simple(simple),
            Command::Compound(compound) => self.compound(compound, depth),
            Command::FunctionDefinition(definition) => Err(refuse(Unsupported::FunctionDefinition, definition.span)),
            Command::Unsupported(unsupported) => self.opaque(unsupported, depth),
        }
    }

    /// `(( … ))` and `for (( … ))`, which the parser keeps opaque but describes; anything else opaque is refused.
    fn opaque(&self, unsupported: &UnsupportedCommand, depth: usize) -> Result<(), InterpError> {
        let construct = || refuse(Unsupported::Construct(unsupported.construct), unsupported.span);
        match unsupported.arithmetic.as_deref() {
            None => Err(construct()),
            Some(ArithmeticParts::Command { expression, close }) => {
                self.arithmetic(*expression, unsupported.span)?;
                match trailing_redirection(self.source, close.end, unsupported.span) {
                    Some(redirect) => Err(refuse(Unsupported::Redirection, redirect)),
                    None => Ok(()),
                }
            }
            Some(ArithmeticParts::For { expressions, body }) => {
                let header = scan::arithmetic_for_header(self.source, *expressions).ok_or_else(construct)?;
                for expression in header {
                    self.arithmetic(expression, unsupported.span)?;
                }
                self.list(&body.body, depth)?;
                match trailing_redirection(self.source, body.close.end, unsupported.span) {
                    Some(redirect) => Err(refuse(Unsupported::Redirection, redirect)),
                    None => Ok(()),
                }
            }
        }
    }

    fn simple(&self, simple: &SimpleCommand) -> Result<(), InterpError> {
        for assignment in &simple.assignments {
            // Bash maintains these itself, and refuses some (`UID`, `PPID`) as read-only, running nothing.
            if is_always_unemulated(&assignment.name) {
                return Err(refuse(Unsupported::ShellVariable, assignment.span));
            }
            let parts = word::parts(&assignment.word.segments, self.source, assignment.value.start)?;
            self.parts(&parts, false, 0)?;
        }
        let mut literals = Vec::with_capacity(simple.words.len());
        for command_word in &simple.words {
            literals.push(word::literal(&self.word(command_word, Context::Argument)?));
        }
        // A builtin named literally is refused now; one produced by an expansion when it runs.
        if let (Some(Some(name)), Some(first)) = (literals.first(), simple.words.first()) {
            let args: Option<Vec<String>> = literals.iter().skip(1).cloned().collect();
            let differs = args.is_some_and(|args| external_builtin_differs(name, &args));
            if is_refused_builtin(name) || differs {
                return Err(refuse(Unsupported::Builtin, first.span));
            }
        }
        match simple.redirections.first() {
            Some(redirect) => Err(refuse(Unsupported::Redirection, redirect.span)),
            None => Ok(()),
        }
    }

    fn compound(&self, compound: &CompoundCommand, depth: usize) -> Result<(), InterpError> {
        match &compound.kind {
            CompoundKind::Subshell(_) => return Err(refuse(Unsupported::Subshell, compound.span)),
            CompoundKind::For(command) => {
                self.word(&command.variable, Context::Plain)?;
                for item in command.items.iter().flat_map(|items| &items.words) {
                    self.word(item, Context::Argument)?;
                }
                self.list(&command.body.body, depth)?;
            }
            CompoundKind::Case(command) => {
                self.word(&command.subject, Context::Plain)?;
                for clause in &command.clauses {
                    for pattern in &clause.patterns {
                        self.word(pattern, Context::Pattern)?;
                    }
                    self.list(&clause.body, depth)?;
                }
            }
            CompoundKind::Group(_) | CompoundKind::If(_) | CompoundKind::While(_) | CompoundKind::Until(_) => {
                for list in compound.kind.lists() {
                    self.list(list, depth)?;
                }
            }
        }
        match compound.redirections.first() {
            Some(redirect) => Err(refuse(Unsupported::Redirection, redirect.span)),
            None => Ok(()),
        }
    }

    /// Checks a word in `context` and returns its parts. Brace expansion and literal pathname patterns are refused
    /// in arguments.
    fn word(&self, command_word: &CommandWord, context: Context) -> Result<Vec<Part>, InterpError> {
        let parts = word::parts(&command_word.word.segments, self.source, 0)?;
        self.parts(&parts, false, 0)?;
        if context == Context::Argument {
            let view = literal_view(&parts);
            if has_brace_expansion(&view) {
                return Err(refuse(Unsupported::BraceExpansion, command_word.span));
            }
            if has_glob(&view) {
                return Err(refuse(Unsupported::PathnameExpansion, command_word.span));
            }
        }
        Ok(parts)
    }

    /// An arithmetic expression spanning `expression` (of a construct at `span`).
    fn arithmetic(&self, expression: Span, span: Span) -> Result<(), InterpError> {
        let parts = scan::scan(self.source, expression, Mode::Double).map_err(|error| at(error, span))?;
        self.parts(&parts, true, 1)
    }

    /// The expansions in `parts` (`quoted`: inside double quotes), `depth` expansions deep.
    fn parts(&self, parts: &[Part], quoted: bool, depth: usize) -> Result<(), InterpError> {
        if depth > MAX_EXPANSION_DEPTH {
            return Err(InterpError::DepthExceeded {
                limit: MAX_EXPANSION_DEPTH,
            });
        }
        for part in parts {
            match part {
                Part::Text(_) | Part::Quoted(_) => {}
                Part::Double(inner) => self.parts(inner, true, depth)?,
                Part::Param { name, span } => {
                    if is_always_unemulated(name) {
                        return Err(refuse(Unsupported::ShellVariable, *span));
                    }
                }
                Part::Brace { body, span } => self.brace(*body, *span, quoted, depth + 1)?,
                Part::Arith { body, span } => {
                    let inner = scan::scan(self.source, *body, Mode::Double).map_err(|error| at(error, *span))?;
                    self.parts(&inner, true, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    /// The body of a `${…}` spanning `span`: its parameter, operator and the words the operator takes. A bad
    /// substitution is bash's error when it runs, not a refusal.
    fn brace(&self, body: Span, span: Span, quoted: bool, depth: usize) -> Result<(), InterpError> {
        let text = word::text(body, self.source)?;
        let name_refused = |name: &Name| matches!(name, Name::Variable(variable) if is_always_unemulated(variable));
        match param::parse(text, body) {
            Parsed::Unsupported(feature) => Err(refuse(feature, span)),
            Parsed::Length(name) | Parsed::Param { name, .. } if name_refused(&name) => {
                Err(refuse(Unsupported::ShellVariable, span))
            }
            Parsed::Names { prefix, .. } if lists_always_unemulated(&prefix) => {
                Err(refuse(Unsupported::ShellVariable, span))
            }
            Parsed::Bad | Parsed::Length(_) | Parsed::Names { .. } => Ok(()),
            Parsed::Param {
                op: Op::Transform('P'), ..
            } => Err(refuse(Unsupported::PromptExpansion, span)),
            Parsed::Param { op, .. } => {
                let words: Vec<(Span, Mode)> = match op {
                    Op::None | Op::Transform(_) => Vec::new(),
                    Op::Default { word, .. } => vec![(word, if quoted { Mode::Double } else { Mode::Unquoted })],
                    Op::Substring { offset, length } => std::iter::once(offset)
                        .chain(length)
                        .map(|expression| (expression, Mode::Double))
                        .collect(),
                    Op::Remove { pattern, .. } | Op::Case { pattern, .. } => vec![(pattern, Mode::Unquoted)],
                    Op::Replace {
                        pattern, replacement, ..
                    } => std::iter::once(pattern)
                        .chain(replacement)
                        .map(|word| (word, Mode::Unquoted))
                        .collect(),
                };
                for (word_span, mode) in words {
                    let parts = scan::scan(self.source, word_span, mode).map_err(|error| at(error, span))?;
                    self.parts(&parts, mode == Mode::Double, depth)?;
                }
                Ok(())
            }
        }
    }
}

/// `error`, with a refusal placed at `span` when the scanner could only place it within its own text.
fn at(error: InterpError, span: Span) -> InterpError {
    match error {
        InterpError::Unsupported { feature, span: inner } if inner.start < span.start || inner.end > span.end => {
            refuse(feature, span)
        }
        other => other,
    }
}
