//! The parser: lexer tokens to a [`Script`] of lists, and-or lists, pipelines and simple commands (KNSH-029;
//! FR-LC-02, decision 6).
//!
//! The grammar read here is bash's, restricted to what decision 6 makes exact for phase 2 so far:
//!
//! ```text
//! script    := newlines? (and_or (separator newlines? and_or)* separator?)? newlines?
//! separator := ';' | '&' | newline
//! and_or    := pipeline (('&&' | '||') newlines? pipeline)*
//! pipeline  := '!'? command (('|' | '|&') newlines? command)*
//! command   := simple command: assignments, words and redirections
//! ```
//!
//! Anything else that bash accepts (compound commands, function definitions, here-documents, array assignments) is
//! refused with [`ParseError::Unsupported`] until a later story reads it exactly, and anything bash rejects is a
//! syntax error. Either way the caller classifies the line as dynamic (KNSH-032): no error path leads to an allow.
//!
//! The parser is a loop over the token stream, not a recursion over it: lists, and-or lists and pipelines are read
//! iteratively, so the length of a line never deepens the call stack. Nested lists (subshells, groups, substitutions)
//! will enter [`Parser::list`] again; each entry passes its depth, which is checked against [`MAX_NESTING_DEPTH`].

use std::iter::Peekable;
use std::vec;

use crate::ast::{
    AndOr, AndOrOperator, AndOrPart, Assignment, Command, CommandWord, ListItem, PipeOperator, Pipeline, PipelinePart,
    Redirect, Script, Separator, SeparatorKind, SimpleCommand,
};
use crate::error::{CompoundStart, ParseError, Unexpected, UnsupportedConstruct};
use crate::lex::lex;
use crate::limits::MAX_NESTING_DEPTH;
use crate::token::{Operator, Redirection, RedirectionOperator, ReservedWord, Span, Token, TokenKind, Word};

/// Parses a whole command line into a [`Script`].
///
/// Pure: no I/O and no global state, and the same input always gives the same result. Every simple command of the
/// line is reachable from the result through [`Script::simple_commands`] (FR-LC-02, FR-LC-09).
///
/// # Errors
///
/// Returns the first problem found, with its span: a [`LexError`](crate::LexError) wrapped in
/// [`ParseError::Lex`], a bash syntax error, or a construct this parser does not read yet. A caller must treat any
/// error as dynamic code, never as an allow (decision 6, KNSH-032).
///
/// # Example
///
/// ```
/// let script = knsh_bash::parse("FOO=1 npm test | tee log && echo done").unwrap();
/// let names: Vec<&str> = script
///     .simple_commands()
///     .filter_map(|command| command.name())
///     .map(|name| &"FOO=1 npm test | tee log && echo done"[name.span.range()])
///     .collect();
/// assert_eq!(names, ["npm", "tee", "echo"]);
/// ```
pub fn parse(input: &str) -> Result<Script, ParseError> {
    let mut tokens = lex(input)?;
    // Blanks and comments separate words but never change the structure; newlines do, so they stay.
    tokens.retain(|token| !matches!(token.kind, TokenKind::Blank | TokenKind::Comment));
    let mut parser = Parser {
        input,
        tokens: tokens.into_iter().peekable(),
    };
    let items = parser.list(0)?;
    // `list` stops only at the end of the input or on an error, so nothing can be left over here.
    Ok(Script {
        items,
        span: Span::new(0, input.len()),
    })
}

/// The parser state: the remaining significant tokens.
struct Parser<'a> {
    /// The line, needed to read assignment names out of word spans.
    input: &'a str,
    /// Tokens with blanks and comments removed.
    tokens: Peekable<vec::IntoIter<Token>>,
}

impl Parser<'_> {
    /// Reads a list up to the end of the input. `depth` is how many lists enclose this one; it bounds the recursion
    /// that nested lists will add (KNSH-030, KNSH-031).
    fn list(&mut self, depth: usize) -> Result<Vec<ListItem>, ParseError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(ParseError::NestingTooDeep {
                span: self.peek_span().unwrap_or(self.end_span()),
                limit: MAX_NESTING_DEPTH,
            });
        }
        let mut items = Vec::new();
        self.skip_newlines();
        while self.tokens.peek().is_some() {
            let and_or = self.and_or()?;
            let separator = self.separator()?;
            items.push(ListItem { and_or, separator });
            if separator.is_none() {
                // `separator` returns `None` only at the end of the input.
                break;
            }
            self.skip_newlines();
        }
        Ok(items)
    }

    /// Reads the separator after an and-or list: `;`, `&`, a newline, or nothing at the end of the input. Any other
    /// token there is a syntax error (`a ;; b`, `a )`).
    fn separator(&mut self) -> Result<Option<Separator>, ParseError> {
        let Some(token) = self.tokens.peek() else {
            return Ok(None);
        };
        let kind = match token.kind {
            TokenKind::Operator(Operator::Semicolon) => SeparatorKind::Semicolon,
            TokenKind::Operator(Operator::Background) => SeparatorKind::Background,
            TokenKind::Newline => SeparatorKind::Newline,
            // `and_or` stops only before an operator or a newline (words and redirections all belong to commands), so
            // this is an operator that cannot end a list here: `;;`, `)`, `(` after a complete command.
            TokenKind::Operator(_)
            | TokenKind::Word(_)
            | TokenKind::Redirection(_)
            | TokenKind::Blank
            | TokenKind::Comment => {
                return Err(ParseError::UnexpectedToken {
                    token: unexpected(&token.kind),
                    span: token.span,
                });
            }
        };
        let span = token.span;
        self.tokens.next();
        Ok(Some(Separator { kind, span }))
    }

    /// Reads pipelines joined by `&&` and `||`. A newline may follow either operator, as in bash.
    fn and_or(&mut self) -> Result<AndOr, ParseError> {
        let first = self.pipeline(None)?;
        let mut rest = Vec::new();
        while let Some((operator, operator_span)) = self.next_if_map(and_or_operator) {
            self.skip_newlines();
            let pipeline = self.pipeline(Some(operator_span))?;
            rest.push(AndOrPart {
                operator,
                operator_span,
                pipeline,
            });
        }
        let end = rest.last().map_or(first.span.end, |part| part.pipeline.span.end);
        let span = Span::new(first.span.start, end);
        Ok(AndOr { first, rest, span })
    }

    /// Reads an optionally negated pipeline. `after` is the operator before it, if any, for the error when the line
    /// ends there.
    fn pipeline(&mut self, after: Option<Span>) -> Result<Pipeline, ParseError> {
        let negation = self
            .tokens
            .next_if(|token| is_reserved(&token.kind, ReservedWord::Bang))
            .map(|token| token.span);
        // Bash 3.2 rejects `!` followed by a newline (and `! ! a`, see `command`); so does this parser, rather than
        // guess.
        if negation.is_some()
            && let Some(token) = self.tokens.peek()
            && matches!(token.kind, TokenKind::Newline)
        {
            return Err(ParseError::UnexpectedToken {
                token: Unexpected::Newline,
                span: token.span,
            });
        }
        let first = self.command(negation.or(after))?;
        let mut rest = Vec::new();
        while let Some((operator, operator_span)) = self.next_if_map(pipe_operator) {
            self.skip_newlines();
            let command = self.command(Some(operator_span))?;
            rest.push(PipelinePart {
                operator,
                operator_span,
                command,
            });
        }
        let start = negation.map_or(first.span().start, |bang| bang.start);
        let end = rest.last().map_or(first.span().end, |part| part.command.span().end);
        Ok(Pipeline {
            negation,
            first,
            rest,
            span: Span::new(start, end),
        })
    }

    /// Reads one command. `after` is the operator before it, reported if the line ends instead.
    ///
    /// Bash recognises reserved words only as the first token of a command (`A=1 if` runs a program named `if`), so
    /// that is the only place they are checked.
    fn command(&mut self, after: Option<Span>) -> Result<Command, ParseError> {
        let Some(token) = self.tokens.peek() else {
            return Err(ParseError::MissingCommand {
                span: after.unwrap_or(self.end_span()),
            });
        };
        let span = token.span;
        match &token.kind {
            TokenKind::Word(word) => {
                if let Some(reserved) = word.reserved {
                    reserved_word_in_command_position(reserved, span)?;
                }
            }
            TokenKind::Redirection(_) => {}
            TokenKind::Operator(Operator::LeftParen) => {
                return Err(ParseError::Unsupported {
                    construct: UnsupportedConstruct::Compound(CompoundStart::Subshell),
                    span,
                });
            }
            TokenKind::Operator(operator) => {
                return Err(ParseError::UnexpectedToken {
                    token: Unexpected::Operator(*operator),
                    span,
                });
            }
            // A newline cannot start a command here: every caller has already skipped the newlines bash allows.
            TokenKind::Newline | TokenKind::Blank | TokenKind::Comment => {
                return Err(ParseError::UnexpectedToken {
                    token: unexpected(&token.kind),
                    span,
                });
            }
        }
        self.simple_command(span.start).map(Command::Simple)
    }

    /// Reads a simple command starting at byte `start`: words and redirections up to the next operator or newline.
    /// The words before the first one that is not an assignment are assignments; the rest are the name and arguments.
    /// Redirections may stand anywhere.
    ///
    /// `command` has checked that the next token is a word or a redirection, so at least one part is read and the
    /// span is never empty.
    fn simple_command(&mut self, start: usize) -> Result<SimpleCommand, ParseError> {
        let mut assignments = Vec::new();
        let mut words: Vec<CommandWord> = Vec::new();
        let mut redirections = Vec::new();
        let mut end = start;
        // Where the last word read ends, if it is spelled `{…}`: bash 4.1 and later read `{name}>file` as a
        // redirection that stores a new descriptor in `name` (in any position), not as a word.
        let mut braced_word_end = None;
        while let Some(token) = self.tokens.next_if(|token| continues_simple_command(&token.kind)) {
            match token.kind {
                TokenKind::Word(word) => {
                    let word = CommandWord { word, span: token.span };
                    end = word.span.end;
                    braced_word_end = self.is_braced(word.span).then_some(word.span.end);
                    // Only words before the command name can be assignments: `env A=1` passes `A=1` as an argument.
                    if words.is_empty()
                        && let Some(assignment) = self.assignment_shape(&word.word, word.span)?
                    {
                        self.reject_array_value(&assignment)?;
                        assignments.push(assignment);
                    } else {
                        words.push(word);
                    }
                }
                TokenKind::Redirection(redirection) => {
                    if redirection.fd.is_none() && braced_word_end == Some(token.span.start) {
                        // Under bash 3.2 `{fd}>f cmd` runs a program named `{fd}`; under bash 4.1 and later it runs
                        // `cmd`. Refused rather than guess which bash runs the line.
                        return Err(ParseError::Unsupported {
                            construct: UnsupportedConstruct::RedirectionVariable,
                            span: token.span,
                        });
                    }
                    let redirect = self.redirect(redirection, token.span)?;
                    end = redirect.span.end;
                    braced_word_end = self.is_braced(redirect.target.span).then_some(redirect.target.span.end);
                    redirections.push(redirect);
                }
                TokenKind::Operator(Operator::LeftParen) => {
                    // Every outcome is an error, so the `(` is consumed to see whether `)` follows it.
                    let empty_parens = matches!(
                        self.tokens.peek().map(|token| &token.kind),
                        Some(TokenKind::Operator(Operator::RightParen))
                    );
                    return Err(self.left_paren_in_command(
                        &assignments,
                        &words,
                        &redirections,
                        token.span,
                        empty_parens,
                    ));
                }
                // `continues_simple_command` lets none of these through.
                TokenKind::Operator(_) | TokenKind::Newline | TokenKind::Blank | TokenKind::Comment => break,
            }
        }
        Ok(SimpleCommand {
            assignments,
            words,
            redirections,
            span: Span::new(start, end),
        })
    }

    /// Reads the target word of a redirection whose operator token (at `operator_span`) was just consumed.
    /// Here-documents are refused until their bodies are read (KNSH-031).
    fn redirect(&mut self, redirection: Redirection, operator_span: Span) -> Result<Redirect, ParseError> {
        match redirection.operator {
            RedirectionOperator::HereDocument | RedirectionOperator::HereDocumentStripTabs => {
                return Err(ParseError::Unsupported {
                    construct: UnsupportedConstruct::HereDocument,
                    span: operator_span,
                });
            }
            RedirectionOperator::Input
            | RedirectionOperator::Output
            | RedirectionOperator::Append
            | RedirectionOperator::Clobber
            | RedirectionOperator::ReadWrite
            | RedirectionOperator::HereString
            | RedirectionOperator::DuplicateInput
            | RedirectionOperator::DuplicateOutput
            | RedirectionOperator::OutputAll
            | RedirectionOperator::AppendAll => {}
        }
        // The target must be the very next token: a newline or an operator there is a syntax error in bash.
        let target = match self.tokens.next_if(|token| matches!(token.kind, TokenKind::Word(_))) {
            Some(Token {
                kind: TokenKind::Word(word),
                span,
            }) => CommandWord { word, span },
            Some(_) | None => return Err(ParseError::MissingRedirectionTarget { span: operator_span }),
        };
        Ok(Redirect {
            fd: redirection.fd,
            operator: redirection.operator,
            span: Span::new(operator_span.start, target.span.end),
            target,
        })
    }

    /// Reads `word` as an assignment if it is one: an unquoted name, then an unquoted `=` or `+=`, as bash requires.
    /// `"A"=1` and `A\=1` are words. `name[…]=…` (an array element) is refused rather than taken for a command name.
    fn assignment_shape(&self, word: &Word, span: Span) -> Result<Option<Assignment>, ParseError> {
        let mut name = String::new();
        // Set after a `+` that follows the name, which must be followed by `=`.
        let mut plus = false;
        for (index, segment) in word.segments.iter().enumerate() {
            if !segment.kind.is_unquoted_text() {
                // Quoting or an expansion before the `=`: not an assignment.
                return Ok(None);
            }
            // Line continuations have an empty body, so they contribute nothing, as bash removes them first.
            let text = segment.body.text(self.input).unwrap_or_default();
            for (offset, byte) in text.bytes().enumerate() {
                let at = segment.body.start + offset;
                match byte {
                    b'=' if !name.is_empty() => {
                        return Ok(Some(Assignment {
                            name,
                            append: plus,
                            value: Span::new(at + 1, span.end),
                            word: word.clone(),
                            span,
                        }));
                    }
                    b'+' if !name.is_empty() && !plus => plus = true,
                    b'[' if !name.is_empty() && !plus => {
                        // `a[i]=x` assigns an element; `a[i]` alone is an ordinary (glob) word. Where a command
                        // starts, bash reads the subscript up to its matching `]` across blanks and operators
                        // (`a[ 1 ]=x rm f` assigns and runs `rm`; `a[;]=1 b` runs `b`), so a subscript that the
                        // word does not close is refused rather than split into other words.
                        let rest = span.text(self.input).unwrap_or_default();
                        let closed = self.subscript_closes(word, index, at + 1);
                        return if rest.contains('=') || !closed {
                            Err(ParseError::Unsupported {
                                construct: UnsupportedConstruct::SubscriptAssignment,
                                span,
                            })
                        } else {
                            Ok(None)
                        };
                    }
                    b'A'..=b'Z' | b'a'..=b'z' | b'_' if !plus => name.push(char::from(byte)),
                    b'0'..=b'9' if !plus && !name.is_empty() => name.push(char::from(byte)),
                    _ => return Ok(None),
                }
            }
        }
        Ok(None)
    }

    /// Whether the word at `span` is spelled `{…}` with something between the braces, the shape of a bash 4.1
    /// descriptor variable (`{fd}>file`). Quoting is not looked at, so the check errs towards refusing.
    fn is_braced(&self, span: Span) -> bool {
        span.text(self.input)
            .is_some_and(|text| text.len() > 2 && text.starts_with('{') && text.ends_with('}'))
    }

    /// Whether the subscript opened by the `[` just before byte `from` (inside segment `index` of `word`) is closed by
    /// a matching `]` within the word. Like bash, nested brackets are counted and quoted, escaped or substituted text
    /// is skipped; only unquoted literal brackets count.
    fn subscript_closes(&self, word: &Word, index: usize, from: usize) -> bool {
        let mut depth: usize = 1;
        for segment in word.segments.iter().skip(index) {
            if !segment.kind.is_unquoted_text() {
                continue;
            }
            let start = segment.body.start.max(from);
            let text = self.input.get(start..segment.body.end.max(start)).unwrap_or_default();
            for byte in text.bytes() {
                match byte {
                    b'[' => depth = depth.saturating_add(1),
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
        false
    }

    /// Refuses `name=(…)`: bash reads the parenthesised list as an array value, which this parser does not read yet.
    /// The `(` must touch the assignment; `name= (…)` is a different error, found by `left_paren_in_command`.
    fn reject_array_value(&mut self, assignment: &Assignment) -> Result<(), ParseError> {
        if let Some(token) = self.tokens.peek()
            && matches!(token.kind, TokenKind::Operator(Operator::LeftParen))
            && token.span.start == assignment.span.end
        {
            return Err(ParseError::Unsupported {
                construct: UnsupportedConstruct::ArrayAssignment,
                span: assignment.span,
            });
        }
        Ok(())
    }

    /// The error for a `(` inside a simple command. After a lone name and followed by `)` it starts a function
    /// definition (`f() …`); glued to an assignment-shaped argument it is an array value (`declare -a x=(1)`);
    /// elsewhere bash reports a syntax error (`echo (a)`).
    fn left_paren_in_command(
        &self,
        assignments: &[Assignment],
        words: &[CommandWord],
        redirections: &[Redirect],
        span: Span,
        empty_parens: bool,
    ) -> ParseError {
        if empty_parens
            && assignments.is_empty()
            && redirections.is_empty()
            && let [name] = words
        {
            return ParseError::Unsupported {
                construct: UnsupportedConstruct::FunctionDefinition,
                span: name.span,
            };
        }
        if let Some(last) = words.last()
            && last.span.end == span.start
            && last.span.text(self.input).is_some_and(|text| text.ends_with('='))
        {
            return ParseError::Unsupported {
                construct: UnsupportedConstruct::ArrayAssignment,
                span: last.span,
            };
        }
        ParseError::UnexpectedToken {
            token: Unexpected::Operator(Operator::LeftParen),
            span,
        }
    }

    /// Consumes the next token if `classify` recognises it, returning what it recognised and where the token was.
    fn next_if_map<T>(&mut self, classify: impl FnOnce(&TokenKind) -> Option<T>) -> Option<(T, Span)> {
        let found = classify(&self.tokens.peek()?.kind)?;
        let token = self.tokens.next()?;
        Some((found, token.span))
    }

    fn peek_span(&mut self) -> Option<Span> {
        self.tokens.peek().map(|token| token.span)
    }

    fn skip_newlines(&mut self) {
        while self
            .tokens
            .next_if(|token| matches!(token.kind, TokenKind::Newline))
            .is_some()
        {}
    }

    /// An empty span at the end of the input, for errors at the end of the line.
    const fn end_span(&self) -> Span {
        Span::new(self.input.len(), self.input.len())
    }
}

/// Whether a token belongs to the simple command being read. A `(` does too, only so that the command can report
/// the precise error for it (`f()`, `x=(1)`, `echo (a)`); operators and newlines end the command.
const fn continues_simple_command(kind: &TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Word(_) | TokenKind::Redirection(_) | TokenKind::Operator(Operator::LeftParen)
    )
}

/// The and-or operator a token is, if it is one.
const fn and_or_operator(kind: &TokenKind) -> Option<AndOrOperator> {
    match kind {
        TokenKind::Operator(Operator::And) => Some(AndOrOperator::And),
        TokenKind::Operator(Operator::Or) => Some(AndOrOperator::Or),
        TokenKind::Operator(
            Operator::Pipe
            | Operator::PipeAmpersand
            | Operator::Background
            | Operator::Semicolon
            | Operator::DoubleSemicolon
            | Operator::SemicolonAmpersand
            | Operator::DoubleSemicolonAmpersand
            | Operator::LeftParen
            | Operator::RightParen,
        )
        | TokenKind::Word(_)
        | TokenKind::Redirection(_)
        | TokenKind::Newline
        | TokenKind::Blank
        | TokenKind::Comment => None,
    }
}

/// The pipe operator a token is, if it is one.
const fn pipe_operator(kind: &TokenKind) -> Option<PipeOperator> {
    match kind {
        TokenKind::Operator(Operator::Pipe) => Some(PipeOperator::Pipe),
        TokenKind::Operator(Operator::PipeAmpersand) => Some(PipeOperator::PipeAll),
        TokenKind::Operator(
            Operator::Or
            | Operator::And
            | Operator::Background
            | Operator::Semicolon
            | Operator::DoubleSemicolon
            | Operator::SemicolonAmpersand
            | Operator::DoubleSemicolonAmpersand
            | Operator::LeftParen
            | Operator::RightParen,
        )
        | TokenKind::Word(_)
        | TokenKind::Redirection(_)
        | TokenKind::Newline
        | TokenKind::Blank
        | TokenKind::Comment => None,
    }
}

/// Whether a token is an unquoted word spelled like `reserved`.
fn is_reserved(kind: &TokenKind, reserved: ReservedWord) -> bool {
    matches!(kind, TokenKind::Word(Word { reserved: Some(found), .. }) if *found == reserved)
}

/// Checks a reserved word found as the first token of a command. Only `!` starts a pipeline, and the pipeline has
/// already consumed it, so a `!` here is a second one (`! ! a`) or follows a pipe (`a | ! b`): bash 3.2 rejects both.
/// Words that start compound commands are refused until KNSH-030; words that only continue or close one are syntax
/// errors where a command should start, as in bash.
fn reserved_word_in_command_position(reserved: ReservedWord, span: Span) -> Result<(), ParseError> {
    match reserved {
        ReservedWord::LeftBrace
        | ReservedWord::DoubleLeftBracket
        | ReservedWord::Case
        | ReservedWord::Coproc
        | ReservedWord::For
        | ReservedWord::Function
        | ReservedWord::If
        | ReservedWord::Select
        | ReservedWord::Time
        | ReservedWord::Until
        | ReservedWord::While => Err(ParseError::Unsupported {
            construct: UnsupportedConstruct::Compound(CompoundStart::ReservedWord(reserved)),
            span,
        }),
        ReservedWord::Bang
        | ReservedWord::RightBrace
        | ReservedWord::DoubleRightBracket
        | ReservedWord::Do
        | ReservedWord::Done
        | ReservedWord::Elif
        | ReservedWord::Else
        | ReservedWord::Esac
        | ReservedWord::Fi
        | ReservedWord::In
        | ReservedWord::Then => Err(ParseError::UnexpectedToken {
            token: Unexpected::ReservedWord(reserved),
            span,
        }),
    }
}

/// The [`Unexpected`] naming a token.
fn unexpected(kind: &TokenKind) -> Unexpected {
    match kind {
        TokenKind::Operator(operator) => Unexpected::Operator(*operator),
        TokenKind::Word(Word {
            reserved: Some(reserved),
            ..
        }) => Unexpected::ReservedWord(*reserved),
        TokenKind::Word(_) | TokenKind::Redirection(_) => Unexpected::Word,
        // Blanks and comments are removed before parsing, so only a newline reaches this arm in practice.
        TokenKind::Newline | TokenKind::Blank | TokenKind::Comment => Unexpected::Newline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::LexError;

    fn text(input: &str, span: Span) -> &str {
        span.text(input).unwrap()
    }

    /// The text of each simple command's name, `None` for a command without one.
    fn names(input: &str) -> Vec<Option<&str>> {
        parse(input)
            .unwrap()
            .simple_commands()
            .map(|command| command.name().map(|name| text(input, name.span)))
            .collect()
    }

    /// The only simple command of `input`.
    fn only_command(input: &str) -> SimpleCommand {
        let script = parse(input).unwrap();
        let commands: Vec<&SimpleCommand> = script.simple_commands().collect();
        assert_eq!(commands.len(), 1, "{input:?} gave {commands:#?}");
        commands[0].clone()
    }

    fn word_texts<'a>(input: &'a str, words: &[CommandWord]) -> Vec<&'a str> {
        words.iter().map(|word| text(input, word.span)).collect()
    }

    fn unsupported(input: &str) -> UnsupportedConstruct {
        match parse(input) {
            Err(ParseError::Unsupported { construct, .. }) => construct,
            other => panic!("{input:?} gave {other:?}"),
        }
    }

    fn unexpected_token(input: &str) -> (Unexpected, &str) {
        match parse(input) {
            Err(ParseError::UnexpectedToken { token, span }) => (token, text(input, span)),
            other => panic!("{input:?} gave {other:?}"),
        }
    }

    // ---- Story unit tests (KNSH-029) ----

    #[test]
    fn parses_assignments_before_command() {
        // KNSH-029: assignments before the name are separated from the arguments.
        let input = "FOO=1 npm test";
        let command = only_command(input);
        assert_eq!(command.assignments.len(), 1);
        let assignment = &command.assignments[0];
        assert_eq!(assignment.name, "FOO");
        assert!(!assignment.append);
        assert_eq!(text(input, assignment.value), "1");
        assert_eq!(text(input, assignment.span), "FOO=1");
        assert_eq!(text(input, command.name().unwrap().span), "npm");
        assert_eq!(word_texts(input, command.arguments()), ["test"]);
        assert_eq!(text(input, command.span), input);
    }

    #[test]
    fn parses_pipeline_with_negation_and_pipe_amp() {
        let input = "! a |& b";
        let script = parse(input).unwrap();
        assert_eq!(script.items.len(), 1);
        let pipeline = &script.items[0].and_or.first;
        assert!(pipeline.is_negated());
        assert_eq!(text(input, pipeline.negation.unwrap()), "!");
        assert_eq!(pipeline.rest.len(), 1);
        assert_eq!(pipeline.rest[0].operator, PipeOperator::PipeAll);
        assert_eq!(text(input, pipeline.rest[0].operator_span), "|&");
        assert_eq!(text(input, pipeline.span), input);
        assert_eq!(names(input), [Some("a"), Some("b")]);
    }

    #[test]
    fn parses_and_or_list_left_associative() {
        // `a && b || c` is `(a && b) || c`: one flat and-or list read left to right, which is how bash evaluates it.
        let input = "a && b || c";
        let script = parse(input).unwrap();
        assert_eq!(script.items.len(), 1);
        let and_or = &script.items[0].and_or;
        let operators: Vec<AndOrOperator> = and_or.rest.iter().map(|part| part.operator).collect();
        assert_eq!(operators, [AndOrOperator::And, AndOrOperator::Or]);
        let pipelines: Vec<&str> = and_or.pipelines().map(|pipeline| text(input, pipeline.span)).collect();
        assert_eq!(pipelines, ["a", "b", "c"]);
        assert_eq!(text(input, and_or.span), input);
    }

    #[test]
    fn parses_background_and_sequential_lists() {
        let input = "a & b; c";
        let script = parse(input).unwrap();
        let separators: Vec<Option<SeparatorKind>> = script
            .items
            .iter()
            .map(|item| item.separator.map(|separator| separator.kind))
            .collect();
        assert_eq!(
            separators,
            [Some(SeparatorKind::Background), Some(SeparatorKind::Semicolon), None]
        );
        let background: Vec<bool> = script.items.iter().map(ListItem::is_background).collect();
        assert_eq!(background, [true, false, false]);
        assert_eq!(names(input), [Some("a"), Some("b"), Some("c")]);
    }

    #[test]
    fn attaches_redirections_anywhere_in_command() {
        let input = ">f echo hi 2>&1";
        let command = only_command(input);
        assert_eq!(word_texts(input, &command.words), ["echo", "hi"]);
        assert_eq!(command.redirections.len(), 2);
        let first = &command.redirections[0];
        assert_eq!(first.operator, RedirectionOperator::Output);
        assert_eq!(first.fd, None);
        assert_eq!(text(input, first.target.span), "f");
        let second = &command.redirections[1];
        assert_eq!(second.operator, RedirectionOperator::DuplicateOutput);
        assert_eq!(second.fd.unwrap().value, Some(2));
        assert_eq!(text(input, second.target.span), "1");
        assert_eq!(text(input, second.span), "2>&1");
        assert_eq!(text(input, command.span), input);

        // In the middle too, and the redirection target is never taken for the command name.
        let input = "cmd >out arg";
        let command = only_command(input);
        assert_eq!(word_texts(input, &command.words), ["cmd", "arg"]);
        assert_eq!(text(input, command.redirections[0].target.span), "out");
    }

    #[test]
    fn yields_every_simple_command_in_order() {
        // FR-LC-09: policy sees every part of the line.
        assert_eq!(names("a | b && c; d"), [Some("a"), Some("b"), Some("c"), Some("d")]);
    }

    #[test]
    fn reports_error_for_dangling_operator() {
        let input = "a &&";
        let error = parse(input).unwrap_err();
        assert_eq!(error, ParseError::MissingCommand { span: Span::new(2, 4) });
        assert_eq!(text(input, error.span().unwrap()), "&&");
        // Trailing newlines do not supply the missing command.
        for input in ["a ||\n\n", "a |", "a |& \n", "!"] {
            assert!(
                matches!(parse(input), Err(ParseError::MissingCommand { .. })),
                "{input:?}"
            );
        }
    }

    #[test]
    fn assignment_only_line_has_no_command_name() {
        let input = "X=1";
        let command = only_command(input);
        assert!(command.name().is_none());
        assert_eq!(command.arguments(), &[] as &[CommandWord]);
        assert_eq!(command.assignments[0].name, "X");
        assert_eq!(text(input, command.span), "X=1");
    }

    // ---- Assignments ----

    #[test]
    fn several_assignments_and_append() {
        let input = "A=1 B+='two words' C= cmd D=4";
        let command = only_command(input);
        let assignments: Vec<(&str, bool, &str)> = command
            .assignments
            .iter()
            .map(|assignment| {
                (
                    assignment.name.as_str(),
                    assignment.append,
                    text(input, assignment.value),
                )
            })
            .collect();
        assert_eq!(
            assignments,
            [("A", false, "1"), ("B", true, "'two words'"), ("C", false, "")]
        );
        // After the name, an assignment-shaped word is an argument (`env A=1`).
        assert_eq!(word_texts(input, &command.words), ["cmd", "D=4"]);
    }

    #[test]
    fn quoted_or_escaped_names_are_not_assignments() {
        // Bash needs the name and `=` unquoted: these run a program instead.
        for input in ["\"A\"=1", "A\\=1", "'A=1'", "$A=1", "1A=2", "=1", "A-B=1", "A+B=1"] {
            let command = only_command(input);
            assert!(command.assignments.is_empty(), "{input:?}");
            assert_eq!(command.words.len(), 1, "{input:?}");
        }
    }

    #[test]
    fn line_continuation_inside_assignment_name_is_removed() {
        // Bash removes `\` newline before reading the line, so this is `AB=1`.
        let input = "A\\\nB=1 cmd";
        let command = only_command(input);
        assert_eq!(command.assignments[0].name, "AB");
        assert_eq!(text(input, command.name().unwrap().span), "cmd");
    }

    #[test]
    fn assignment_value_may_hold_quotes_and_expansions() {
        let input = "X=\"$HOME\"/bin PATH=$X:$PATH run";
        let command = only_command(input);
        assert_eq!(command.assignments.len(), 2);
        assert_eq!(text(input, command.assignments[0].value), "\"$HOME\"/bin");
        assert_eq!(text(input, command.assignments[1].value), "$X:$PATH");
    }

    #[test]
    fn redirection_only_command_has_no_name() {
        let input = ">out";
        let command = only_command(input);
        assert!(command.name().is_none());
        assert_eq!(command.redirections.len(), 1);
    }

    #[test]
    fn reserved_words_after_assignment_or_redirection_are_ordinary_words() {
        // Bash 3.2: `A=1 if` runs a program named `if`; reserved words count only as a command's first token.
        let command = only_command("A=1 if x");
        assert_eq!(command.words.len(), 2);
        let command = only_command(">f ! x");
        assert_eq!(command.words.len(), 2);
        let command = only_command("echo if then fi { } !");
        assert_eq!(command.words.len(), 7);
    }

    // ---- Lists, pipelines and newlines ----

    #[test]
    fn newlines_separate_and_may_follow_operators() {
        let input = "\n\na &&\n\n b |\n c\n\nd\n";
        assert_eq!(names(input), [Some("a"), Some("b"), Some("c"), Some("d")]);
        let script = parse(input).unwrap();
        assert_eq!(script.items.len(), 2);
        assert_eq!(script.items[0].separator.unwrap().kind, SeparatorKind::Newline);
    }

    #[test]
    fn empty_and_comment_only_lines_have_no_commands() {
        for input in ["", "  ", "\n\n", "# just a comment", " # c\n# d\n"] {
            let script = parse(input).unwrap();
            assert!(script.items.is_empty(), "{input:?}");
            assert_eq!(script.span, Span::new(0, input.len()));
        }
    }

    #[test]
    fn comments_do_not_hide_later_commands() {
        assert_eq!(names("a # c && b\nd"), [Some("a"), Some("d")]);
        assert_eq!(names("a && # c\n b"), [Some("a"), Some("b")]);
    }

    #[test]
    fn trailing_separators_are_kept() {
        let script = parse("a;").unwrap();
        assert_eq!(script.items[0].separator.unwrap().kind, SeparatorKind::Semicolon);
        let script = parse("a &").unwrap();
        assert!(script.items[0].is_background());
    }

    #[test]
    fn negation_applies_after_and_or_operators() {
        let script = parse("a && ! b").unwrap();
        assert!(!script.items[0].and_or.first.is_negated());
        assert!(script.items[0].and_or.rest[0].pipeline.is_negated());
    }

    // ---- Syntax errors (bash 3.2 rejects all of these) ----

    #[test]
    fn misplaced_operators_are_syntax_errors() {
        assert_eq!(
            unexpected_token("; a"),
            (Unexpected::Operator(Operator::Semicolon), ";")
        );
        assert_eq!(
            unexpected_token("a ; ; b"),
            (Unexpected::Operator(Operator::Semicolon), ";")
        );
        assert_eq!(
            unexpected_token("a & ; b"),
            (Unexpected::Operator(Operator::Semicolon), ";")
        );
        assert_eq!(
            unexpected_token("a ;; b"),
            (Unexpected::Operator(Operator::DoubleSemicolon), ";;")
        );
        assert_eq!(
            unexpected_token("a ) b"),
            (Unexpected::Operator(Operator::RightParen), ")")
        );
        assert_eq!(
            unexpected_token("a | && b"),
            (Unexpected::Operator(Operator::And), "&&")
        );
        assert_eq!(unexpected_token("&& a"), (Unexpected::Operator(Operator::And), "&&"));
        assert_eq!(
            unexpected_token("echo (a)"),
            (Unexpected::Operator(Operator::LeftParen), "(")
        );
    }

    #[test]
    fn misplaced_reserved_words_are_syntax_errors() {
        for (input, word) in [
            ("then", ReservedWord::Then),
            ("a; fi", ReservedWord::Fi),
            ("}", ReservedWord::RightBrace),
            ("in", ReservedWord::In),
            ("a; ]]", ReservedWord::DoubleRightBracket),
            ("done", ReservedWord::Done),
            // Bash 3.2 accepts one `!` per pipeline, and only at its start.
            ("! ! a", ReservedWord::Bang),
            ("a | ! b", ReservedWord::Bang),
        ] {
            assert_eq!(unexpected_token(input).0, Unexpected::ReservedWord(word), "{input:?}");
        }
        assert_eq!(unexpected_token("!\na").0, Unexpected::Newline);
    }

    #[test]
    fn missing_redirection_target_is_an_error() {
        for input in ["cmd >", "cmd > ;", "cmd 2>\nx", "cmd > | x", "<"] {
            match parse(input) {
                Err(ParseError::MissingRedirectionTarget { span }) => {
                    assert!(text(input, span).ends_with(['>', '<']), "{input:?}");
                }
                other => panic!("{input:?} gave {other:?}"),
            }
        }
    }

    #[test]
    fn lexer_errors_are_passed_through() {
        let error = parse("echo 'open").unwrap_err();
        assert!(matches!(error, ParseError::Lex(LexError::Unterminated { .. })));
        assert_eq!(error.span(), Some(Span::new(5, 10)));
    }

    #[test]
    fn errors_never_echo_input() {
        // NFR-PRIV-02: messages name fixed spellings and offsets only.
        for input in [
            "secret-token && ",
            "secret-token ;; x",
            "if secret-token",
            "secret=(x)",
            "cat <<secret",
        ] {
            let message = parse(input).unwrap_err().to_string();
            assert!(!message.contains("secret"), "{input:?}: {message}");
        }
    }

    // ---- Constructs refused until a later story (fail closed, decision 6) ----

    #[test]
    fn compound_commands_are_unsupported_for_now() {
        assert_eq!(
            unsupported("(a; b)"),
            UnsupportedConstruct::Compound(CompoundStart::Subshell)
        );
        for (input, word) in [
            ("{ a; }", ReservedWord::LeftBrace),
            ("if a; then b; fi", ReservedWord::If),
            ("for x in a; do b; done", ReservedWord::For),
            ("while a; do b; done", ReservedWord::While),
            ("until a; do b; done", ReservedWord::Until),
            ("case x in a) b;; esac", ReservedWord::Case),
            ("select x in a; do b; done", ReservedWord::Select),
            ("[[ -f x ]]", ReservedWord::DoubleLeftBracket),
            ("function f { a; }", ReservedWord::Function),
            ("coproc a", ReservedWord::Coproc),
            ("time a", ReservedWord::Time),
            ("a && if b; then c; fi", ReservedWord::If),
            ("! { a; }", ReservedWord::LeftBrace),
        ] {
            assert_eq!(
                unsupported(input),
                UnsupportedConstruct::Compound(CompoundStart::ReservedWord(word)),
                "{input:?}"
            );
        }
    }

    #[test]
    fn function_definitions_are_unsupported_for_now() {
        assert_eq!(
            unsupported("f() { rm -rf x; }; f"),
            UnsupportedConstruct::FunctionDefinition
        );
        assert_eq!(unsupported("f () { a; }"), UnsupportedConstruct::FunctionDefinition);
    }

    #[test]
    fn here_documents_are_unsupported_for_now() {
        assert_eq!(unsupported("cat <<EOF"), UnsupportedConstruct::HereDocument);
        assert_eq!(unsupported("cat <<-EOF"), UnsupportedConstruct::HereDocument);
        // A here-string is an ordinary redirection with its word as target.
        let input = "cat <<< 'text'";
        let command = only_command(input);
        assert_eq!(command.redirections[0].operator, RedirectionOperator::HereString);
        assert_eq!(text(input, command.redirections[0].target.span), "'text'");
    }

    #[test]
    fn array_assignments_are_unsupported_for_now() {
        assert_eq!(unsupported("a=(1 2)"), UnsupportedConstruct::ArrayAssignment);
        assert_eq!(unsupported("a+=(3) cmd"), UnsupportedConstruct::ArrayAssignment);
        assert_eq!(unsupported("declare -a x=(1 2)"), UnsupportedConstruct::ArrayAssignment);
        assert_eq!(unsupported("x[1]=a"), UnsupportedConstruct::SubscriptAssignment);
        assert_eq!(
            unsupported("x[$(rm -rf y)]=a cmd"),
            UnsupportedConstruct::SubscriptAssignment
        );
        // Without `=`, `x[1]` is an ordinary (glob) word.
        assert_eq!(names("x[1] arg"), [Some("x[1]")]);
    }

    #[test]
    fn subscript_open_across_words_where_a_command_starts_is_unsupported() {
        // Review regression (FR-LC-09): where a command starts, bash 3.2 reads `name[` on to the matching `]` across
        // blanks and operators. `a[ 1 ]=x rm f` assigns and runs `rm`, and `a[;]=1 b` runs `b`; split at the blank
        // or `;`, the line would name `a[` and `]=1` instead. Refused, never split.
        for input in [
            "a[ 1 ]=x rm f",
            "a[;]=1 b",
            "a[ 1 ] b",
            "true && a[ 1 ]=x rm f",
            "x | a[ 1 ]=x rm f",
            "A=1 a[ 1 ]=x rm f",
            "a[ [1] ]=x rm f",
            "a\\\n[ 1 ]=x rm f",
        ] {
            assert_eq!(
                unsupported(input),
                UnsupportedConstruct::SubscriptAssignment,
                "{input:?}"
            );
        }
        // A subscript the word closes is still an ordinary word, quoted brackets not counting.
        assert_eq!(names("a[[1]] b"), [Some("a[[1]]")]);
        assert_eq!(unsupported("a[\"]\" ]=1 b"), UnsupportedConstruct::SubscriptAssignment);
        // After the command name bash splits as usual, so these stay arguments.
        let input = "echo a[ 1 ]=x";
        assert_eq!(
            word_texts(input, &only_command(input).words),
            ["echo", "a[", "1", "]=x"]
        );
    }

    #[test]
    fn descriptor_variable_redirection_is_unsupported() {
        // Review regression: bash 4.1+ reads `{fd}>f cmd` as a redirection and runs `cmd`; bash 3.2 runs `{fd}`.
        // Taking `{fd}` for the command name would hide `rm` under bash 5, so the line is refused.
        for input in [
            "{fd}>/dev/null rm f",
            "rm f {fd}>/dev/null",
            "{fd}<&- x",
            ">a {fd}>b x",
            "x >{fd}>b",
        ] {
            assert_eq!(
                unsupported(input),
                UnsupportedConstruct::RedirectionVariable,
                "{input:?}"
            );
        }
        // Not adjacent, with a descriptor number, or not braced: ordinary words and redirections.
        assert_eq!(names("{fd} >f x"), [Some("{fd}")]);
        assert_eq!(names("echo {} 2>f"), [Some("echo")]);
        assert_eq!(names("echo {a}2>f"), [Some("echo")]);
    }

    // ---- Limits ----

    #[test]
    fn nested_list_depth_is_bounded() {
        // KNSH-032: nested lists (KNSH-030, KNSH-031) enter `list` with their depth; past the limit it refuses.
        let parser = || Parser {
            input: "a",
            tokens: lex("a").unwrap().into_iter().peekable(),
        };
        assert_eq!(
            parser().list(MAX_NESTING_DEPTH + 1),
            Err(ParseError::NestingTooDeep {
                span: Span::new(0, 1),
                limit: MAX_NESTING_DEPTH,
            })
        );
        assert!(parser().list(MAX_NESTING_DEPTH).is_ok());
    }

    #[test]
    fn long_lists_do_not_recurse() {
        // Length must not deepen the stack: 100 000 commands in one and-or list and one pipeline.
        let input = "a && ".repeat(100_000) + "a";
        assert_eq!(parse(&input).unwrap().simple_commands().count(), 100_001);
        let input = "a | ".repeat(100_000) + "a";
        assert_eq!(parse(&input).unwrap().simple_commands().count(), 100_001);
    }

    #[test]
    fn oversized_input_is_rejected_by_the_lexer() {
        let input = "a".repeat(crate::MAX_INPUT_LEN + 1);
        assert!(matches!(
            parse(&input),
            Err(ParseError::Lex(LexError::InputTooLarge { .. }))
        ));
    }
}
