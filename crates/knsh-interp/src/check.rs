//! The check of a whole script before it runs (KNSH-096 to KNSH-103): every construct a later story
//! implements is refused here, with its span, so a script the interpreter cannot evaluate runs none of its commands.
//! A function's body is checked where the function is defined, as its commands are written there (KNSH-103).
//!
//! Expansions are read but not performed: each `${…}` body is parsed, and the words and expressions inside it are
//! scanned, so an array, a command substitution or a variable bash maintains itself is refused wherever it is
//! written. Brace expansion, which depends only on the text, is performed, so a word past its bounds runs nothing.
//! What depends on a value or the filesystem (a variable named only at run time, a command name produced by an
//! expansion or a pattern) is refused when the expansion happens instead.
//!
//! The walk mirrors [`crate::eval`] and counts nesting the same way, under the same limit, so a tree nested deeper
//! than the limit is refused before evaluation and the check itself never overflows the stack.

use knsh_bash::{
    AndOr, ArithmeticParts, Command, CommandWord, CompoundCommand, CompoundKind, ListItem, Pipeline, Redirect,
    RedirectionOperator, SimpleCommand, Span, UnsupportedCommand,
};

use crate::brace;
use crate::cond;
use crate::error::{InterpError, Unsupported};
use crate::eval::{is_conditional, is_refused_builtin, refused_form, trailing_redirection};
use crate::expand::MAX_EXPANSION_DEPTH;
use crate::param::{self, Name, Op, Parsed, Subscript};
use crate::pattern;
use crate::scan::{self, Mode, Part};
use crate::state::{is_always_unemulated, lists_always_unemulated, refuses_assignment};
use crate::word::{self, Context, WordChar};

/// Checks `items` (a script's top-level list) against `source`, nesting at most `max_depth` lists.
///
/// # Errors
///
/// [`InterpError::Unsupported`] for the first unsupported construct in source order, [`InterpError::DepthExceeded`]
/// past `max_depth`, [`InterpError::SourceMismatch`] if a span does not index `source`.
/// `times`: whether the interpreter has clocks for the `time` keyword, which is refused without them.
pub(crate) fn check(items: &[ListItem], source: &str, max_depth: usize, times: bool) -> Result<(), InterpError> {
    Checker {
        source,
        max_depth,
        times,
    }
    .list(items, 0)
}

/// The walk's fixed inputs.
struct Checker<'a> {
    source: &'a str,
    max_depth: usize,
    /// The interpreter has clocks for `time`.
    times: bool,
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
        }
        Ok(())
    }

    fn and_or(&self, and_or: &AndOr, depth: usize) -> Result<(), InterpError> {
        and_or
            .pipelines()
            .try_for_each(|pipeline| self.pipeline(pipeline, depth))
    }

    fn pipeline(&self, pipeline: &Pipeline, depth: usize) -> Result<(), InterpError> {
        if let Some(time) = pipeline.time
            && !self.times
        {
            return Err(refuse(Unsupported::Time, time.span()));
        }
        pipeline.commands().try_for_each(|command| self.command(command, depth))
    }

    fn command(&self, command: &Command, depth: usize) -> Result<(), InterpError> {
        match command {
            Command::Simple(simple) => self.simple(simple),
            Command::Compound(compound) => self.compound(compound, depth),
            Command::FunctionDefinition(definition) => {
                self.word(&definition.name, Context::Plain)?;
                self.compound(&definition.body, depth)
            }
            Command::Unsupported(unsupported) => self.opaque(unsupported, depth),
        }
    }

    /// `(( … ))` and `for (( … ))`, which the parser keeps opaque but describes, and `[[ … ]]`, read here as the
    /// evaluator reads it (KNSH-102); anything else opaque is refused.
    fn opaque(&self, unsupported: &UnsupportedCommand, depth: usize) -> Result<(), InterpError> {
        let construct = || refuse(Unsupported::Construct(unsupported.construct), unsupported.span);
        match unsupported.arithmetic.as_deref() {
            None if is_conditional(unsupported) => self.conditional(unsupported.span),
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

    /// A `[[ … ]]` spanning `span`: its expression must read as bash reads it, each word's expansions are checked,
    /// and nothing may follow its `]]` (a redirection the parser kept inside the node).
    fn conditional(&self, span: Span) -> Result<(), InterpError> {
        let conditional = cond::parse(self.source, span)?;
        let mut operands = Vec::new();
        conditional.expr.operands(&mut operands);
        for operand in operands {
            let parts = scan::scan(self.source, operand.span, Mode::Unquoted).map_err(|error| at(error, span))?;
            self.parts(&parts, false, 0)?;
        }
        match trailing_redirection(self.source, conditional.close.end, span) {
            Some(redirect) => Err(refuse(Unsupported::Conditional, redirect)),
            None => Ok(()),
        }
    }

    fn simple(&self, simple: &SimpleCommand) -> Result<(), InterpError> {
        for assignment in &simple.assignments {
            // Bash maintains these itself, and refuses some (`UID`, `PPID`) as read-only, running nothing.
            if refuses_assignment(&assignment.name) {
                return Err(refuse(Unsupported::ShellVariable, assignment.span));
            }
            if let Some(subscript) = assignment.subscript {
                self.subscript(subscript, assignment.span)?;
            }
            if let Some(array) = &assignment.array {
                self.array(array)?;
            } else {
                let parts = word::parts(&assignment.word.segments, self.source, assignment.value.start)?;
                self.parts(&parts, false, 0)?;
            }
        }
        for command_word in &simple.words {
            if let Some(array) = &command_word.array {
                self.array(array)?;
            }
        }
        let mut literals = Vec::with_capacity(simple.words.len());
        for command_word in &simple.words {
            literals.push(self.literal_argument(command_word)?);
        }
        // A builtin named literally is refused now; one produced by an expansion when it runs. So is a form of a
        // builtin the interpreter runs that a later story implements (`set -e`, `declare -a`), when its words are
        // literal; the builtin refuses it again when it runs.
        if let (Some(Some(name)), Some(first)) = (literals.first(), simple.words.first()) {
            let args: Option<Vec<String>> = literals.iter().skip(1).cloned().collect();
            if is_refused_builtin(name) {
                return Err(refuse(Unsupported::Builtin, first.span));
            }
            if let Some(feature) = args.as_deref().and_then(|args| refused_form(name, args)) {
                return Err(refuse(feature, first.span));
            }
        }
        self.redirections(&simple.redirections)
    }

    /// The subscript at `subscript` of an element assignment (of a command at `span`): its expansions, read both as
    /// an arithmetic expression's and as an associative array's key would be.
    fn subscript(&self, subscript: Span, span: Span) -> Result<(), InterpError> {
        for mode in [Mode::Double, Mode::Unquoted] {
            let parts = scan::scan(self.source, subscript, mode).map_err(|error| at(error, span))?;
            self.parts(&parts, mode == Mode::Double, 1)?;
        }
        Ok(())
    }

    /// The elements of a compound assignment's list (KNSH-103): each word, and each `[subscript]=` subscript.
    fn array(&self, array: &knsh_bash::ArrayValue) -> Result<(), InterpError> {
        for element in &array.elements {
            self.word(element, Context::Argument)?;
            if let Some(text) = element.span.text(self.source)
                && let Some(inner) = text.strip_prefix('[')
                && let Some(close) = scan::subscript_end(inner)
            {
                let start = element.span.start + 1;
                self.subscript(Span::new(start, start + close), element.span)?;
            }
        }
        Ok(())
    }

    /// A command's redirections (KNSH-099): here-documents are refused (KNSH-105), a `{name}` variable bash
    /// maintains itself too; each target is checked as an argument word (a here-string's as a plain word).
    fn redirections(&self, redirects: &[Redirect]) -> Result<(), InterpError> {
        for redirect in redirects {
            let context = match redirect.operator {
                RedirectionOperator::HereDocument | RedirectionOperator::HereDocumentStripTabs => {
                    return Err(refuse(Unsupported::HereDocument, redirect.span));
                }
                RedirectionOperator::HereString => Context::Plain,
                RedirectionOperator::Input
                | RedirectionOperator::Output
                | RedirectionOperator::Append
                | RedirectionOperator::Clobber
                | RedirectionOperator::ReadWrite
                | RedirectionOperator::DuplicateInput
                | RedirectionOperator::DuplicateOutput
                | RedirectionOperator::OutputAll
                | RedirectionOperator::AppendAll => Context::Argument,
            };
            if let Some(variable) = &redirect.variable
                && refuses_assignment(&variable.name)
            {
                return Err(refuse(Unsupported::ShellVariable, variable.span));
            }
            self.word(&redirect.target, context)?;
        }
        Ok(())
    }

    fn compound(&self, compound: &CompoundCommand, depth: usize) -> Result<(), InterpError> {
        match &compound.kind {
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
            CompoundKind::Subshell(_)
            | CompoundKind::Group(_)
            | CompoundKind::If(_)
            | CompoundKind::While(_)
            | CompoundKind::Until(_) => {
                for list in compound.kind.lists() {
                    self.list(list, depth)?;
                }
            }
        }
        self.redirections(&compound.redirections)
    }

    /// Checks a word in `context` (only arguments are brace-expanded, which is checked here too, so a word past
    /// the brace expansion limits runs nothing) and returns its parts.
    fn word(&self, command_word: &CommandWord, context: Context) -> Result<Vec<Part>, InterpError> {
        let pieces = word::pieces(&command_word.word.segments, self.source, 0)?;
        let parts: Vec<Part> = pieces.iter().map(|piece| piece.part.clone()).collect();
        self.parts(&parts, false, 0)?;
        if context == Context::Argument {
            brace::expand(&pieces, command_word.span)?;
        }
        Ok(parts)
    }

    /// Checks an argument word and returns the single word it spells when nothing can change it: no expansion, no
    /// brace expansion and no pattern bash would match against file names (with any option). A builtin named that
    /// way is refused before anything runs; any other is found when the command runs.
    fn literal_argument(&self, command_word: &CommandWord) -> Result<Option<String>, InterpError> {
        let parts = self.word(command_word, Context::Argument)?;
        let pieces = word::pieces(&command_word.word.segments, self.source, 0)?;
        if brace::expand(&pieces, command_word.span)?.len() != 1 || has_pattern(&parts) {
            return Ok(None);
        }
        Ok(word::literal(&parts))
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
        let name_refused = |name: &Name| matches!(name, Name::Variable(variable) | Name::Element(variable, _) if is_always_unemulated(variable));
        if let Parsed::Length(Name::Element(_, Subscript::Source { span: inner, .. }))
        | Parsed::Param {
            name: Name::Element(_, Subscript::Source { span: inner, .. }),
            ..
        } = param::parse(text, body)
        {
            self.subscript(inner, span)?;
        }
        match param::parse(text, body) {
            Parsed::Unsupported(feature) => Err(refuse(feature, span)),
            Parsed::Length(name) | Parsed::Param { name, .. } if name_refused(&name) => {
                Err(refuse(Unsupported::ShellVariable, span))
            }
            Parsed::Keys { name, .. } if is_always_unemulated(&name) => Err(refuse(Unsupported::ShellVariable, span)),
            Parsed::Names { prefix, .. } if lists_always_unemulated(&prefix) => {
                Err(refuse(Unsupported::ShellVariable, span))
            }
            Parsed::Bad | Parsed::Length(_) | Parsed::Names { .. } | Parsed::Keys { .. } => Ok(()),
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

/// Whether `parts` (a word without expansions) is a pattern bash would match against file names, with `extglob`
/// on or off: its literal text read with bash's test, its quoted text never a pattern.
fn has_pattern(parts: &[Part]) -> bool {
    fn chars(parts: &[Part], quoted: bool, out: &mut Vec<WordChar>) {
        for part in parts {
            match part {
                Part::Text(text) => out.extend(text.chars().map(|ch| WordChar {
                    ch,
                    quoted,
                    expanded: false,
                })),
                Part::Quoted(text) => out.extend(text.chars().map(|ch| WordChar {
                    ch,
                    quoted: true,
                    expanded: false,
                })),
                Part::Double(inner) => chars(inner, true, out),
                Part::Param { .. } | Part::Brace { .. } | Part::Arith { .. } => {}
            }
        }
    }
    let mut view = Vec::new();
    chars(parts, false, &mut view);
    pattern::has_glob(&view, true)
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
