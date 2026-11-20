//! The check of a whole script before it runs (KNSH-096): every construct a later story implements is refused here,
//! with its span, so a script the interpreter cannot evaluate fully runs none of its commands.
//!
//! The walk mirrors [`crate::eval`] and counts nesting the same way, under the same limit, so a tree nested deeper
//! than the limit is refused before evaluation and the check itself never overflows the stack.

use knsh_bash::{AndOr, Command, CompoundCommand, CompoundKind, ListItem, Pipeline, SimpleCommand, Span};

use crate::error::{InterpError, Unsupported};
use crate::eval::{external_builtin_differs, is_refused_builtin};
use crate::word::{self, Context};

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
            Command::Unsupported(unsupported) => {
                Err(refuse(Unsupported::Construct(unsupported.construct), unsupported.span))
            }
        }
    }

    fn simple(&self, simple: &SimpleCommand) -> Result<(), InterpError> {
        for assignment in &simple.assignments {
            word::assignment_value(assignment, self.source)?;
        }
        let words = simple
            .words
            .iter()
            .map(|command_word| word::expand(command_word, self.source, Context::Argument))
            .collect::<Result<Vec<_>, _>>()?;
        if let (Some((name, args)), Some(first)) = (words.split_first(), simple.words.first())
            && (is_refused_builtin(name) || external_builtin_differs(name, args))
        {
            return Err(refuse(Unsupported::Builtin, first.span));
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
                word::expand(&command.variable, self.source, Context::Plain)?;
                for item in command.items.iter().flat_map(|items| &items.words) {
                    word::expand(item, self.source, Context::Argument)?;
                }
                self.list(&command.body.body, depth)?;
            }
            CompoundKind::Case(command) => {
                word::expand(&command.subject, self.source, Context::Plain)?;
                for clause in &command.clauses {
                    for pattern in &clause.patterns {
                        word::characters(pattern, self.source, Context::Pattern)?;
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
}
