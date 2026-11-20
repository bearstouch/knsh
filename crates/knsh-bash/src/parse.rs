//! The parser: lexer tokens to a [`Script`] of lists, and-or lists, pipelines, simple commands (KNSH-029), compound
//! commands and function definitions (KNSH-030; FR-LC-02, decision 6).
//!
//! The grammar read here is bash's, restricted to what decision 6 makes exact for phase 2 so far:
//!
//! ```text
//! script    := list
//! list      := newlines? (and_or (separator newlines? and_or)* separator?)? newlines?
//!              (stops before a word or operator that closes an enclosing construct)
//! separator := ';' | '&' | newline
//! and_or    := pipeline (('&&' | '||') newlines? pipeline)*
//! pipeline  := '!'? command (('|' | '|&') newlines? command)*
//! command   := simple | compound redirection* | function
//! compound  := '(' list ')' | '{' list '}'
//!            | 'if' list 'then' list ('elif' list 'then' list)* ('else' list)? 'fi'
//!            | 'for' word (';' | newlines ('in' word* (';' | newline))?)? newlines? body
//!            | ('while' | 'until') list 'do' list 'done'
//!            | 'case' word newlines? 'in' newlines? clause* 'esac'
//!            | 'select' …  | '[[' … ']]'  | '((' … '))'  | 'for' '((' … '))' …   (kept whole, unsupported)
//! body      := 'do' list 'done' | '{' list '}'
//! clause    := '('? word ('|' word)* ')' list (';;' | ';&' | ';;&')? newlines?
//! function  := word '(' ')' newlines? compound redirection*
//!            | 'function' word ('(' ')')? newlines? compound redirection*
//! ```
//!
//! Lists inside compound commands must hold at least one command, except a `case` arm's. Reserved words are only
//! recognised where a command starts (`echo fi` passes `fi` as an argument), which is also where a list stops at a
//! closing word (`then`, `fi`, `done`, `}`, …). Bash 3.2 (`/bin/bash` on macOS) is the reference; constructs bash 4
//! added (`;&`, `;;&`) are parsed the bash 4 way, as KNSH-029 did for `|&`.
//!
//! Words are read recursively (KNSH-031): every `$( … )`, backtick, `<( … )` and `>( … )` in a word, an assignment, a
//! redirection target or an unquoted here-document body is lexed and parsed again as a nested [`Script`], so the
//! commands it runs are in the tree. A backtick body is first un-escaped the way bash does it. A here-document's body
//! (read by the lexer) is attached to its `<<` or `<<-` redirection, and a here-document or here-string read by a
//! shell or interpreter is marked ([`Redirect::feeds_interpreter`], see `interpreters`).
//!
//! Anything else that bash accepts is either kept whole as a [`Command::Unsupported`] node, when its extent is
//! certain (`select`, `[[ … ]]`, `(( … ))`, `for (( … ))`), or refused with [`ParseError::Unsupported`] (array
//! assignments, `coproc`, `time` anywhere but at the start of a pipeline, a substitution inside `${ … }` or
//! `$(( … ))`), and anything bash rejects is a syntax error. Either way the caller classifies the construct or the line
//! as dynamic (KNSH-032): no error path and no unsupported node leads to an allow.
//!
//! Lists, and-or lists and pipelines are read iteratively, so the length of a line never deepens the call stack. Each
//! nested list (inside a compound command, function body or substitution) enters [`Parser::list`] again with its
//! depth, which is checked against [`MAX_NESTING_DEPTH`]; scanning `[[ … ]]` and `(( … ))` is iterative. A nested
//! script starts one list deeper than the list holding its word, and its lexer starts at the quote and substitution
//! depth of its body, so neither limit resets inside a substitution.
//!
//! After parsing, [`mark_function_calls`] marks the calls that certainly reach a function defined earlier in the line.
//! Calls inside substitutions are never marked: their bodies run in child shells parsed under conditions the line does
//! not show (aliases, functions of the parent), so they are always resolved as programs, which is safe.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::mem;

use crate::ast::{
    AndOr, AndOrOperator, AndOrPart, ArithmeticParts, Assignment, CaseClause, CaseCommand, CaseTerminator,
    CaseTerminatorKind, Command, CommandWord, CompoundCommand, CompoundKind, ElseClause, ForCommand, ForItems,
    FunctionDefinition, Group, HereDocument, IfClause, IfCommand, ListItem, LoopBody, LoopCommand, PipeOperator,
    Pipeline, PipelinePart, Redirect, Script, Separator, SeparatorKind, SimpleCommand, Subshell, Substitution,
    SubstitutionKind, TimeKeyword, UnsupportedCommand,
};
use crate::error::{CompoundStart, LexError, ParseError, Unexpected, UnsupportedConstruct};
use crate::functions::mark_function_calls;
use crate::interpreters::mark_interpreter_inputs;
use crate::lex::{LexContext, lex_range};
use crate::limits::{MAX_INPUT_LEN, MAX_NESTING_DEPTH, MAX_TOKENS};
use crate::token::{
    HereDocumentBody, Operator, Redirection, RedirectionOperator, ReservedWord, Segment, SegmentKind, Span, Token,
    TokenKind, Word,
};

/// Parses a whole command line into a [`Script`].
///
/// Pure: no I/O and no global state, and the same input always gives the same result. Every simple command of the
/// line, including those in compound commands and function bodies, is reachable from the result through
/// [`Script::simple_commands`] (FR-LC-02, FR-LC-09), and every construct outside decision 6's exact list through a
/// [`Command::Unsupported`] node.
///
/// # Errors
///
/// Returns the first problem found, with its span: a [`LexError`] wrapped in [`ParseError::Lex`], a bash syntax error,
/// or a construct this parser cannot delimit. The line is lexed whole before anything is parsed, so a lexer error in
/// the line always wins; errors inside a substitution's body come from parsing it, with spans in the line. A caller
/// must treat any error as dynamic code, never as an allow (decision 6, KNSH-032).
///
/// # Example
///
/// ```
/// let line = "f() { rm -rf build; }; FOO=1 npm test | tee log && f";
/// let script = knsh_bash::parse(line).unwrap();
/// let names: Vec<&str> = script
///     .simple_commands()
///     .filter_map(|command| command.name())
///     .map(|name| &line[name.span.range()])
///     .collect();
/// assert_eq!(names, ["rm", "npm", "tee", "f"]);
/// // The last `f` calls the function defined first, whose body is what runs.
/// let call = script.simple_commands().last().unwrap();
/// assert!(call.function_call.is_some());
/// ```
pub fn parse(input: &str) -> Result<Script, ParseError> {
    parse_with(input, ParseOptions::default())
}

/// Shell options that change how bash reads a line, set before it is read (bash reads a whole line before running
/// any of it, so a `shopt` on the line itself never changes how that line is read).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseOptions {
    /// `shopt -s extglob`: `?(…)`, `*(…)`, `+(…)`, `@(…)` and `!(…)` are read as part of a word, with nothing inside
    /// the parentheses ending it, instead of being a syntax error (KNSH-098). Off by default, as in bash.
    pub extglob: bool,
}

impl ParseOptions {
    /// These options with `extglob` set to `on`.
    #[must_use]
    pub const fn with_extglob(mut self, on: bool) -> Self {
        self.extglob = on;
        self
    }
}

/// [`parse`], with the shell options `options` that change how a line is read.
///
/// # Errors
///
/// As [`parse`]; with [`ParseOptions::extglob`], an extended glob group still open at the end of the input is
/// [`LexError::Unterminated`].
pub fn parse_with(input: &str, options: ParseOptions) -> Result<Script, ParseError> {
    // Checked before anything is read, as `lex` does (nested sources skip the check: they lie inside this one).
    if input.len() > MAX_INPUT_LEN {
        return Err(LexError::InputTooLarge {
            len: input.len(),
            limit: MAX_INPUT_LEN,
        }
        .into());
    }
    // One token budget for the line and every substitution body in it: each body is lexed again when it is parsed,
    // and a per-lex limit alone would let a line of many substitutions hold many times the limit (KNSH-032).
    let tokens_left = Cell::new(MAX_TOKENS);
    let context = LexContext {
        extglob: options.extglob,
        ..LexContext::default()
    };
    let mut script = parse_source(input, Span::new(0, input.len()), context, 0, &tokens_left)?;
    mark_function_calls(&mut script, input);
    Ok(script)
}

/// Parses the part of `input` at `range` (the whole line, or a substitution body) as a script whose lists start at
/// nesting `depth`, lexing it in `context` (see [`LexContext`]). Spans index `input`. Here-documents and here-strings
/// fed to an interpreter are marked; function calls are not (only [`parse`] marks them, for the top-level script).
/// The tokens read are taken from `tokens_left`, the line's budget of [`MAX_TOKENS`].
fn parse_source(
    input: &str,
    range: Span,
    context: LexContext,
    depth: usize,
    tokens_left: &Cell<usize>,
) -> Result<Script, ParseError> {
    let tokens = lex_range(input, range, context, tokens_left.get())?;
    // `lex_range` never returns more than it was given, so this cannot underflow; saturating keeps it panic-free.
    tokens_left.set(tokens_left.get().saturating_sub(tokens.len()));
    // Blanks and comments separate words but never change the structure; newlines do, so they stay. Comment spans
    // are kept aside for the one place that must know about them (`(( … ))`). Here-document bodies are set aside by
    // operator, to be attached to the redirection that reads them.
    let mut comments = Vec::new();
    let mut here_documents = BTreeMap::new();
    let tokens: Vec<Token> = tokens
        .into_iter()
        .filter_map(|token| match token.kind {
            TokenKind::Blank => None,
            TokenKind::Comment => {
                comments.push(token.span);
                None
            }
            TokenKind::HereDocumentBody(body) => {
                here_documents.insert(body.operator.start, body);
                None
            }
            TokenKind::Word(_) | TokenKind::Operator(_) | TokenKind::Redirection(_) | TokenKind::Newline => Some(token),
        })
        .collect();
    let mut parser = Parser {
        input,
        end: range.end,
        tokens,
        position: 0,
        comments,
        here_documents,
        context,
        depth,
        tokens_left,
    };
    let items = parser.list(depth)?;
    // The top-level list stops at the end of the input or before a token that only closes a construct (`)`, `;;`,
    // `fi`, `}`, …), which has nothing to close here.
    if let Some(token) = parser.peek() {
        return Err(ParseError::UnexpectedToken {
            token: unexpected(&token.kind),
            span: token.span,
        });
    }
    // A body no redirection took belongs to a `<<` the parser kept inside an unsupported construct, where bash reads
    // a shift or a comparison (`(( x << 2 ))`), not a here-document. The lines the lexer took for its body would then
    // be commands nobody sees, so the line is refused.
    if let Some(body) = parser.here_documents.values().next() {
        return Err(ParseError::Unsupported {
            construct: UnsupportedConstruct::OpaqueHereDocument,
            span: body.operator,
        });
    }
    let mut script = Script { items, span: range };
    mark_interpreter_inputs(&mut script.items, input);
    Ok(script)
}

/// The parser state: the significant tokens and how far they are read.
struct Parser<'a> {
    /// The text the spans index: the line, or the un-escaped body of a backtick substitution.
    input: &'a str,
    /// Where the source being parsed ends in `input` (the end of the input, or of a substitution body).
    end: usize,
    /// Tokens with blanks and comments removed. A consumed token is left behind as a blank placeholder, so taking it
    /// never clones its word; the parser never looks behind `position`.
    tokens: Vec<Token>,
    /// Index of the next token to read.
    position: usize,
    /// Where the comments were, in source order.
    comments: Vec<Span>,
    /// The here-document bodies not yet attached to a redirection, by where their operator starts.
    here_documents: BTreeMap<usize, HereDocumentBody>,
    /// How the source was lexed, from which a substitution body's lexing context follows.
    context: LexContext,
    /// The nesting depth of the list being read; a substitution's script starts one deeper.
    depth: usize,
    /// What is left of the line's token budget ([`MAX_TOKENS`]), shared with the scripts of its substitutions.
    tokens_left: &'a Cell<usize>,
}

/// The constructs that start with a word or operator in command position, other than simple commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompoundStartToken {
    /// `(`: a subshell, or `((` an arithmetic command.
    Paren,
    /// `{`
    Group,
    /// `if`
    If,
    /// `for`
    For,
    /// `select`
    Select,
    /// `while`
    While,
    /// `until`
    Until,
    /// `case`
    Case,
    /// `[[`
    Conditional,
}

/// A compound command as read: exact, or kept whole as unsupported.
enum Compound {
    /// Read exactly.
    Exact(CompoundCommand),
    /// Outside decision 6's exact list.
    Unsupported(UnsupportedCommand),
}

impl Compound {
    const fn span(&self) -> Span {
        match self {
            Self::Exact(compound) => compound.span,
            Self::Unsupported(unsupported) => unsupported.span,
        }
    }

    fn into_command(self) -> Command {
        match self {
            Self::Exact(compound) => Command::Compound(compound),
            Self::Unsupported(unsupported) => Command::Unsupported(unsupported),
        }
    }
}

/// The core of a compound command, before its redirections: what was read, and where its closing token ends.
enum CompoundCore {
    /// An exact compound command.
    Exact(CompoundKind, Span),
    /// An unsupported construct, with the parts of an arithmetic command or loop.
    Unsupported(UnsupportedConstruct, Span, Option<Box<ArithmeticParts>>),
}

impl Parser<'_> {
    // ---- Lists ----

    /// Reads a list: and-or lists separated by `;`, `&` or newlines. It ends at the end of the input or before a
    /// token that closes an enclosing construct (`)`, `;;`, `;&`, `;;&`, or `then`, `elif`, `else`, `fi`, `do`,
    /// `done`, `esac`, `}` where a command would start), which the caller checks. The list may be empty.
    ///
    /// `depth` is how many lists enclose this one; past [`MAX_NESTING_DEPTH`] the line is refused, which bounds the
    /// recursion of compound commands (CLAUDE.md "Untrusted input").
    fn list(&mut self, depth: usize) -> Result<Vec<ListItem>, ParseError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(ParseError::NestingTooDeep {
                span: self.peek_span().unwrap_or(self.end_span()),
                limit: MAX_NESTING_DEPTH,
            });
        }
        // Words read in this list nest their substitutions one level below it; the enclosing list's depth is put
        // back on the way out.
        let enclosing = mem::replace(&mut self.depth, depth);
        let items = self.list_items(depth)?;
        self.depth = enclosing;
        Ok(items)
    }

    /// The loop of [`Parser::list`].
    fn list_items(&mut self, depth: usize) -> Result<Vec<ListItem>, ParseError> {
        let mut items = Vec::new();
        loop {
            self.skip_newlines();
            match self.peek() {
                None => break,
                Some(token) if closes_list(&token.kind) => break,
                Some(_) => {}
            }
            let and_or = self.and_or(depth)?;
            let separator = self.separator()?;
            let ended = separator.is_none();
            items.push(ListItem { and_or, separator });
            if ended {
                break;
            }
        }
        Ok(items)
    }

    /// Reads the separator after an and-or list: `;`, `&` or a newline. `None` at the end of the input or before a
    /// token that closes an enclosing construct, which ends the list. Any other token is a syntax error: a word after
    /// a compound command (`{ a; } b`), or an operator that cannot follow a command (`(a) (b)`).
    fn separator(&mut self) -> Result<Option<Separator>, ParseError> {
        let Some(token) = self.peek() else {
            return Ok(None);
        };
        let kind = match token.kind {
            TokenKind::Operator(Operator::Semicolon) => SeparatorKind::Semicolon,
            TokenKind::Operator(Operator::Background) => SeparatorKind::Background,
            TokenKind::Newline => SeparatorKind::Newline,
            _ if closes_list(&token.kind) => return Ok(None),
            TokenKind::Operator(_)
            | TokenKind::Word(_)
            | TokenKind::Redirection(_)
            | TokenKind::Blank
            | TokenKind::Comment
            | TokenKind::HereDocumentBody(_) => {
                return Err(ParseError::UnexpectedToken {
                    token: unexpected(&token.kind),
                    span: token.span,
                });
            }
        };
        let span = token.span;
        self.advance();
        Ok(Some(Separator { kind, span }))
    }

    /// Reads a list that must hold at least one command, as bash requires inside every compound command except a
    /// `case` arm. `opener` is the construct's opening token, reported if the line ends first.
    fn compound_list(&mut self, depth: usize, opener: Span) -> Result<Vec<ListItem>, ParseError> {
        let items = self.list(depth + 1)?;
        if items.is_empty() {
            return Err(self.unexpected_or_unclosed(opener));
        }
        Ok(items)
    }

    /// Reads pipelines joined by `&&` and `||`. A newline may follow either operator, as in bash.
    fn and_or(&mut self, depth: usize) -> Result<AndOr, ParseError> {
        let first = self.pipeline(None, depth)?;
        let mut rest = Vec::new();
        while let Some((operator, operator_span)) = self.next_if_map(and_or_operator) {
            self.skip_newlines();
            let pipeline = self.pipeline(Some(operator_span), depth)?;
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

    /// Reads a pipeline, optionally timed by the `time` keyword and negated by `!`. `after` is the operator before
    /// it, if any, for the error when the line ends there.
    fn pipeline(&mut self, after: Option<Span>, depth: usize) -> Result<Pipeline, ParseError> {
        let time = self.time_keyword()?;
        let negation = self
            .next_if(|kind| is_reserved(kind, ReservedWord::Bang))
            .map(|token| token.span);
        // Bash 3.2 rejects `!` followed by a newline (and `! ! a`, see `command`); so does this parser, rather than
        // guess.
        if negation.is_some()
            && let Some(token) = self.peek()
            && matches!(token.kind, TokenKind::Newline)
        {
            return Err(ParseError::UnexpectedToken {
                token: Unexpected::Newline,
                span: token.span,
            });
        }
        let first = self.command(negation.or(time.map(|time| time.span())).or(after), depth)?;
        let mut rest = Vec::new();
        while let Some((operator, operator_span)) = self.next_if_map(pipe_operator) {
            self.skip_newlines();
            let command = self.command(Some(operator_span), depth)?;
            rest.push(PipelinePart {
                operator,
                operator_span,
                command,
            });
        }
        let start = time
            .map(|time| time.keyword)
            .or(negation)
            .map_or(first.span().start, |prefix| prefix.start);
        let end = rest.last().map_or(first.span().end, |part| part.command.span().end);
        Ok(Pipeline {
            time,
            negation,
            first,
            rest,
            span: Span::new(start, end),
        })
    }

    /// Reads the `time` keyword and its `-p` option at the start of a pipeline, if there (KNSH-036).
    ///
    /// Only the form every bash reads the same way is accepted: `time` or `time -p`, then a command. The rest is
    /// refused as unsupported, so the line is dynamic (KNSH-032) rather than read the way one bash version would:
    /// `time` with no command (`time`, `time -p;`), another word starting with `-` (bash 3.2 runs `time --` as a
    /// command named `--`, later bash takes `--` as the end of the options), and a second `time` (bash 3.2 runs the
    /// `time` program, later bash may time the pipeline twice). `!` may follow (`time ! ls`). `time` after `!` or a
    /// pipe never reaches here: bash 3.2 runs the `time` program there, and [`Parser::command`] refuses it.
    fn time_keyword(&mut self) -> Result<Option<TimeKeyword>, ParseError> {
        let Some(keyword) = self.next_if(|kind| is_reserved(kind, ReservedWord::Time)) else {
            return Ok(None);
        };
        let keyword = keyword.span;
        let input = self.input;
        let posix = self
            .peek()
            .filter(|token| matches!(token.kind, TokenKind::Word(_)) && token.span.text(input) == Some("-p"))
            .map(|token| token.span);
        if posix.is_some() {
            self.advance();
        }
        let refuse = || ParseError::Unsupported {
            construct: UnsupportedConstruct::Compound(CompoundStart::ReservedWord(ReservedWord::Time)),
            span: keyword,
        };
        let Some(next) = self.peek() else {
            return Err(refuse());
        };
        let ambiguous = match &next.kind {
            TokenKind::Word(word) => {
                word.reserved == Some(ReservedWord::Time)
                    || next
                        .span
                        .text(input)
                        .is_some_and(|text| text.trim_start_matches(['"', '\'', '\\']).starts_with('-'))
            }
            // `time ( … )` times a subshell; any other operator or a newline ends a `time` with no command.
            TokenKind::Operator(operator) => *operator != Operator::LeftParen,
            TokenKind::Newline => true,
            TokenKind::Redirection(_) | TokenKind::Blank | TokenKind::Comment | TokenKind::HereDocumentBody(_) => false,
        };
        if ambiguous {
            return Err(refuse());
        }
        Ok(Some(TimeKeyword { keyword, posix }))
    }

    // ---- Commands ----

    /// Reads one command. `after` is the operator before it, reported if the line ends instead.
    ///
    /// Bash recognises reserved words only as the first token of a command (`A=1 if` runs a program named `if`), so
    /// this is the only place they start compound commands. A word followed by `()` starts a function definition.
    fn command(&mut self, after: Option<Span>, depth: usize) -> Result<Command, ParseError> {
        let Some(token) = self.peek() else {
            return Err(ParseError::MissingCommand {
                span: after.unwrap_or(self.end_span()),
            });
        };
        let span = token.span;
        if let Some(start) = compound_start(&token.kind) {
            return Ok(self.compound_command(start, depth)?.into_command());
        }
        match &token.kind {
            TokenKind::Word(Word {
                reserved: Some(reserved),
                ..
            }) => {
                if *reserved == ReservedWord::Function {
                    return self.function_definition(depth);
                }
                return Err(misplaced_reserved_word(*reserved, span));
            }
            TokenKind::Word(_) => {
                if self.function_name_ahead() {
                    return self.function_definition(depth);
                }
            }
            TokenKind::Redirection(_) => {}
            TokenKind::Operator(operator) => {
                return Err(ParseError::UnexpectedToken {
                    token: Unexpected::Operator(*operator),
                    span,
                });
            }
            // A newline cannot start a command here: every caller has already skipped the newlines bash allows.
            TokenKind::Newline | TokenKind::Blank | TokenKind::Comment | TokenKind::HereDocumentBody(_) => {
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
        while let Some(token) = self.next_if(continues_simple_command) {
            match token.kind {
                TokenKind::Word(word) => {
                    let span = token.span;
                    end = span.end;
                    braced_word_end = self.is_braced(span).then_some(span.end);
                    // Only words before the command name can be assignments: `env A=1` passes `A=1` as an argument.
                    if words.is_empty()
                        && let Some(mut assignment) = self.assignment_shape(&word, span)?
                    {
                        self.reject_array_value(&assignment)?;
                        assignment.substitutions = self.substitutions(&assignment.word.segments, 0)?;
                        assignments.push(assignment);
                    } else {
                        words.push(self.command_word(word, span)?);
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
                    return Err(self.left_paren_in_command(&words, token.span));
                }
                // `continues_simple_command` lets none of these through.
                TokenKind::Operator(_)
                | TokenKind::Newline
                | TokenKind::Blank
                | TokenKind::Comment
                | TokenKind::HereDocumentBody(_) => break,
            }
        }
        Ok(SimpleCommand {
            assignments,
            words,
            redirections,
            function_call: None,
            span: Span::new(start, end),
        })
    }

    /// Reads the target word of a redirection whose operator token (at `operator_span`) was just consumed, and for a
    /// here-document attaches the body the lexer read for it.
    fn redirect(&mut self, redirection: Redirection, operator_span: Span) -> Result<Redirect, ParseError> {
        // The target must be the very next token: a newline or an operator there is a syntax error in bash.
        let target = match self.next_if(|kind| matches!(kind, TokenKind::Word(_))) {
            Some(Token {
                kind: TokenKind::Word(word),
                span,
            }) => self.command_word(word, span)?,
            Some(_) | None => return Err(ParseError::MissingRedirectionTarget { span: operator_span }),
        };
        let here_document = match redirection.operator {
            RedirectionOperator::HereDocument | RedirectionOperator::HereDocumentStripTabs => {
                Some(self.here_document(operator_span)?)
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
            | RedirectionOperator::AppendAll => None,
        };
        Ok(Redirect {
            fd: redirection.fd,
            operator: redirection.operator,
            span: Span::new(operator_span.start, target.span.end),
            target,
            here_document,
            // Set afterwards, once the command reading it is known (`mark_interpreter_inputs`).
            feeds_interpreter: false,
        })
    }

    /// The body of the here-document whose operator is at `operator`, with the substitutions of an unquoted body
    /// parsed. The lexer reads a body only at the newline ending the operator's line, so a line that ends first has
    /// none: bash would read an empty body with a warning, and the line is refused instead (KNSH-031).
    fn here_document(&mut self, operator: Span) -> Result<HereDocument, ParseError> {
        let Some(body) = self.here_documents.remove(&operator.start) else {
            return Err(ParseError::MissingHereDocumentBody { span: operator });
        };
        let substitutions = if body.quoted {
            Vec::new()
        } else {
            // The body is one nesting level, like double quotes (the lexer entered it as one). It is not double-quoted
            // text for a backtick in it, though: bash 3.2 keeps the backslash of `\"` there (checked).
            self.substitutions(&body.segments, 1)?
        };
        Ok(HereDocument {
            strip_tabs: body.strip_tabs,
            quoted: body.quoted,
            body: body.body,
            segments: body.segments,
            substitutions,
            delimiter: body.delimiter,
        })
    }

    // ---- Substitutions ----

    /// A word with the substitutions in it parsed.
    fn command_word(&self, word: Word, span: Span) -> Result<CommandWord, ParseError> {
        let substitutions = self.substitutions(&word.segments, 0)?;
        Ok(CommandWord {
            word,
            span,
            substitutions,
        })
    }

    /// The substitutions in `segments`, in source order, each parsed into a nested script. `quotes` is how many
    /// quotes (or here-document bodies) enclose the segments, for the nested lexer's depth; the segments themselves
    /// are never inside double quotes (a here-document body is not, for the un-escaping of its backticks).
    fn substitutions(&self, segments: &[Segment], quotes: usize) -> Result<Vec<Substitution>, ParseError> {
        let mut found = Vec::new();
        self.collect_substitutions(segments, quotes, false, &mut found)?;
        Ok(found)
    }

    /// The recursion of [`Parser::substitutions`]: appends the substitutions of `segments` to `found`.
    /// `in_double_quotes` is set inside `"…"` or `$"…"`, where a backtick body also loses the backslash of `\"`.
    fn collect_substitutions(
        &self,
        segments: &[Segment],
        quotes: usize,
        in_double_quotes: bool,
        found: &mut Vec<Substitution>,
    ) -> Result<(), ParseError> {
        for segment in segments {
            match &segment.kind {
                // `$"…"` is read like `"…"`, and both count as a quote towards the nesting depth, as in the lexer.
                SegmentKind::DoubleQuoted(inner) | SegmentKind::Locale(inner) => {
                    self.collect_substitutions(inner, quotes + 1, true, found)?;
                }
                SegmentKind::CommandSubstitution => {
                    found.push(self.nested(segment, SubstitutionKind::Command, quotes)?);
                }
                SegmentKind::InputProcessSubstitution => {
                    found.push(self.nested(segment, SubstitutionKind::InputProcess, quotes)?);
                }
                SegmentKind::OutputProcessSubstitution => {
                    found.push(self.nested(segment, SubstitutionKind::OutputProcess, quotes)?);
                }
                SegmentKind::Backtick => found.push(self.backtick(segment, quotes, in_double_quotes)?),
                SegmentKind::ParameterExpansion | SegmentKind::Arithmetic => {
                    if self.hides_substitution(segment.body) {
                        return Err(ParseError::Unsupported {
                            construct: UnsupportedConstruct::SubstitutionInExpansion,
                            span: segment.span,
                        });
                    }
                }
                SegmentKind::Literal
                | SegmentKind::Escape
                | SegmentKind::LineContinuation
                | SegmentKind::SingleQuoted
                | SegmentKind::AnsiC
                | SegmentKind::Parameter => {}
            }
        }
        Ok(())
    }

    /// Parses the body of `$( … )`, `<( … )` or `>( … )` in place: its spans index the same text as the word's.
    fn nested(&self, segment: &Segment, kind: SubstitutionKind, quotes: usize) -> Result<Substitution, ParseError> {
        let process = matches!(kind, SubstitutionKind::InputProcess | SubstitutionKind::OutputProcess);
        // The body is lexed again exactly as the enclosing lexer read it: inside one more substitution (so the bash
        // 3.2 comment and here-document rules still apply), at the depth it had there.
        let context = LexContext {
            depth: self.context.depth + quotes + 1,
            substitutions: self.context.substitutions + 1,
            process_substitutions: self.context.process_substitutions + usize::from(process),
            extglob: self.context.extglob,
        };
        let script = parse_source(self.input, segment.body, context, self.depth + 1, self.tokens_left)?;
        Ok(Substitution {
            kind,
            span: segment.span,
            text: None,
            script,
        })
    }

    /// Parses the body of a backtick substitution, after un-escaping it as bash does ([`unescape_backtick`]). Bash
    /// reads the un-escaped body afresh when it runs it, so its lexing starts outside any substitution; only the depth
    /// carries on. When un-escaping changes nothing the body is parsed in place; otherwise the un-escaped text is
    /// parsed and kept, and an error's span is mapped back onto the line. `in_double_quotes` is set when the backticks
    /// are inside `"…"` or `$"…"` (not in a here-document body, where bash keeps the backslash of `\"`).
    fn backtick(&self, segment: &Segment, quotes: usize, in_double_quotes: bool) -> Result<Substitution, ParseError> {
        let context = LexContext {
            depth: self.context.depth + quotes + 1,
            substitutions: 0,
            process_substitutions: 0,
            extglob: self.context.extglob,
        };
        let body = segment.body.text(self.input).unwrap_or_default();
        let (text, script) = match unescape_backtick(body, in_double_quotes, None) {
            Cow::Borrowed(_) => (
                None,
                parse_source(self.input, segment.body, context, self.depth + 1, self.tokens_left)?,
            ),
            Cow::Owned(text) => {
                let script = parse_source(
                    &text,
                    Span::new(0, text.len()),
                    context,
                    self.depth + 1,
                    self.tokens_left,
                )
                .map_err(|error| error_on_line(error, segment.body, body, in_double_quotes))?;
                (Some(text), script)
            }
        };
        Ok(Substitution {
            kind: SubstitutionKind::Backtick,
            span: segment.span,
            text,
            script,
        })
    }

    /// Whether the body of `${ … }`, `$(( … ))` or `$[ … ]` at `body` may hold a command substitution, backtick or
    /// process substitution. The lexer keeps those bodies whole, so a substitution there would run unseen; any
    /// `` ` ``, `$(`, `<(` or `>(` (line continuations removed, quotes not looked at) counts, which errs towards
    /// refusing.
    fn hides_substitution(&self, body: Span) -> bool {
        let text = body.text(self.input).unwrap_or_default().replace("\\\n", "");
        text.contains('`') || text.contains("$(") || text.contains("<(") || text.contains(">(")
    }

    /// Reads the redirections written after a compound command; bash allows nothing else before the next operator.
    fn trailing_redirections(&mut self) -> Result<Vec<Redirect>, ParseError> {
        let mut redirections = Vec::new();
        while let Some((redirection, span)) = self.next_if_map(|kind| match kind {
            TokenKind::Redirection(redirection) => Some(*redirection),
            TokenKind::Word(_)
            | TokenKind::Operator(_)
            | TokenKind::Newline
            | TokenKind::Blank
            | TokenKind::Comment
            | TokenKind::HereDocumentBody(_) => None,
        }) {
            redirections.push(self.redirect(redirection, span)?);
        }
        Ok(redirections)
    }

    // ---- Compound commands ----

    /// Reads the compound command starting at the next token (which `start` classifies) and the redirections after
    /// it.
    fn compound_command(&mut self, start: CompoundStartToken, depth: usize) -> Result<Compound, ParseError> {
        let opener = self.peek_span().unwrap_or(self.end_span());
        let core = match start {
            CompoundStartToken::Paren => self.subshell(depth)?,
            CompoundStartToken::Group => self.group(depth)?,
            CompoundStartToken::If => self.if_command(depth)?,
            CompoundStartToken::For => self.for_command(depth)?,
            CompoundStartToken::Select => self.select_command(depth)?,
            CompoundStartToken::While => self.loop_command(depth, CompoundKind::While)?,
            CompoundStartToken::Until => self.loop_command(depth, CompoundKind::Until)?,
            CompoundStartToken::Case => self.case_command(depth)?,
            CompoundStartToken::Conditional => self.conditional()?,
        };
        let redirections = self.trailing_redirections()?;
        let (CompoundCore::Exact(_, close) | CompoundCore::Unsupported(_, close, _)) = core;
        let end = redirections.last().map_or(close.end, |redirect| redirect.span.end);
        let span = Span::new(opener.start, end);
        Ok(match core {
            CompoundCore::Exact(kind, _) => Compound::Exact(CompoundCommand {
                kind,
                redirections,
                span,
            }),
            // The redirections of an unsupported construct stay inside its opaque span.
            CompoundCore::Unsupported(construct, _, arithmetic) => Compound::Unsupported(UnsupportedCommand {
                construct,
                span,
                arithmetic,
            }),
        })
    }

    /// `( list )`, or `(( … ))` when bash would read an arithmetic command there.
    fn subshell(&mut self, depth: usize) -> Result<CompoundCore, ParseError> {
        let open = self.advance_span();
        if let Some(close) = self.arithmetic_close(open)? {
            // `close` is the second `)`; the expression lies between the second `(` and the first `)`.
            let expression = Span::new(open.end + 1, close.start - 1);
            return Ok(CompoundCore::Unsupported(
                UnsupportedConstruct::Compound(CompoundStart::Arithmetic),
                close,
                Some(Box::new(ArithmeticParts::Command { expression, close })),
            ));
        }
        let body = self.compound_list(depth, open)?;
        let close = self.expect_operator(Operator::RightParen, open)?;
        Ok(CompoundCore::Exact(
            CompoundKind::Subshell(Subshell { open, body, close }),
            close,
        ))
    }

    /// After a `(` at `open`, decides whether it starts an arithmetic command `(( … ))` the way bash 3.2 does: the
    /// next token must be a `(` touching it, and the `)` that matches that second `(` must be touched by another `)`.
    /// Then the tokens up to that second `)` are consumed and its span is returned. Otherwise nothing is consumed and
    /// bash reads nested subshells (`((a); (b))`), so `None` is returned.
    ///
    /// The scan counts paren tokens. Bash counts characters instead, and treats `#` as text inside `(( … ))`, where the
    /// lexer starts a comment, so a comment in the scanned part could make the two close it at different places: such
    /// a line is refused. Bash reports an unclosed `((` as an error, and so does this parser.
    fn arithmetic_close(&mut self, open: Span) -> Result<Option<Span>, ParseError> {
        match self.peek() {
            Some(token) if is_operator(&token.kind, Operator::LeftParen) && token.span.start == open.end => {}
            Some(_) | None => return Ok(None),
        }
        // Inside the second `(`; find the `)` that matches it.
        let mut nesting = 1_usize;
        let mut index = self.position + 1;
        let close = loop {
            let Some(token) = self.tokens.get(index) else {
                return Err(ParseError::Unclosed { span: open });
            };
            match token.kind {
                TokenKind::Operator(Operator::LeftParen) => nesting += 1,
                TokenKind::Operator(Operator::RightParen) => {
                    nesting -= 1;
                    if nesting == 0 {
                        break token.span;
                    }
                }
                TokenKind::Word(_)
                | TokenKind::Operator(_)
                | TokenKind::Redirection(_)
                | TokenKind::Newline
                | TokenKind::Blank
                | TokenKind::Comment
                | TokenKind::HereDocumentBody(_) => {}
            }
            index += 1;
        };
        if self.comment_within(Span::new(open.start, close.end)) {
            return Err(ParseError::Unsupported {
                construct: UnsupportedConstruct::Compound(CompoundStart::Arithmetic),
                span: open,
            });
        }
        match self.tokens.get(index + 1) {
            Some(next) if is_operator(&next.kind, Operator::RightParen) && next.span.start == close.end => {
                self.position = index + 2;
                Ok(Some(next.span))
            }
            Some(_) | None => Ok(None),
        }
    }

    /// `{ list }`.
    fn group(&mut self, depth: usize) -> Result<CompoundCore, ParseError> {
        let open = self.advance_span();
        let body = self.compound_list(depth, open)?;
        let close = self.expect_reserved(ReservedWord::RightBrace, open)?;
        Ok(CompoundCore::Exact(
            CompoundKind::Group(Group { open, body, close }),
            close,
        ))
    }

    /// `if list then list [elif list then list]… [else list] fi`.
    fn if_command(&mut self, depth: usize) -> Result<CompoundCore, ParseError> {
        let start = self.advance_span();
        let mut keyword = start;
        let mut clauses = Vec::new();
        loop {
            let condition = self.compound_list(depth, start)?;
            let then = self.expect_reserved(ReservedWord::Then, start)?;
            let body = self.compound_list(depth, start)?;
            clauses.push(IfClause {
                keyword,
                condition,
                then,
                body,
            });
            match self.next_reserved(ReservedWord::Elif) {
                Some(elif) => keyword = elif,
                None => break,
            }
        }
        let else_clause = match self.next_reserved(ReservedWord::Else) {
            Some(otherwise) => Some(ElseClause {
                keyword: otherwise,
                body: self.compound_list(depth, start)?,
            }),
            None => None,
        };
        let fi = self.expect_reserved(ReservedWord::Fi, start)?;
        Ok(CompoundCore::Exact(
            CompoundKind::If(IfCommand {
                clauses,
                else_clause,
                fi,
            }),
            fi,
        ))
    }

    /// `for name [in words]; do list; done`, or `for (( … ))` kept whole as unsupported.
    fn for_command(&mut self, depth: usize) -> Result<CompoundCore, ParseError> {
        let keyword = self.advance_span();
        if let Some(token) = self.peek()
            && is_operator(&token.kind, Operator::LeftParen)
        {
            let open = self.advance_span();
            // Bash accepts only `((` here; a lone `(` or nested parens are syntax errors.
            let Some(close) = self.arithmetic_close(open)? else {
                return Err(ParseError::UnexpectedToken {
                    token: Unexpected::Operator(Operator::LeftParen),
                    span: open,
                });
            };
            let expressions = Span::new(open.end + 1, close.start - 1);
            self.next_if(|kind| is_operator(kind, Operator::Semicolon));
            self.skip_newlines();
            let body = self.loop_body(depth, keyword, true)?;
            let close = body.close;
            return Ok(CompoundCore::Unsupported(
                UnsupportedConstruct::Compound(CompoundStart::ArithmeticFor),
                close,
                Some(Box::new(ArithmeticParts::For { expressions, body })),
            ));
        }
        let (variable, items, body) = self.for_header_and_body(depth, keyword)?;
        let close = body.close;
        Ok(CompoundCore::Exact(
            CompoundKind::For(ForCommand {
                keyword,
                variable,
                items,
                body,
            }),
            close,
        ))
    }

    /// `select name [in words]; do list; done`: read like `for` to find its end, then kept whole as unsupported
    /// (decision 6 does not list it).
    fn select_command(&mut self, depth: usize) -> Result<CompoundCore, ParseError> {
        let keyword = self.advance_span();
        let (_, _, body) = self.for_header_and_body(depth, keyword)?;
        Ok(CompoundCore::Unsupported(
            UnsupportedConstruct::Compound(CompoundStart::ReservedWord(ReservedWord::Select)),
            body.close,
            None,
        ))
    }

    /// The part of `for` and `select` after the reserved word at `keyword`: the variable, the optional `in` list and
    /// the body. As in bash 3.2: `for x; do`, `for x do`, `for x in; do`, a newline before `in`, and `{ … }` instead of
    /// `do … done` are all accepted; `in` is not recognised after a `;`, and the words after `in` are never reserved.
    fn for_header_and_body(
        &mut self,
        depth: usize,
        keyword: Span,
    ) -> Result<(CommandWord, Option<ForItems>, LoopBody), ParseError> {
        let variable = self.expect_word(keyword)?;
        let items = if self.next_if(|kind| is_operator(kind, Operator::Semicolon)).is_some() {
            None
        } else {
            self.skip_newlines();
            self.next_reserved(ReservedWord::In)
                .map(|in_keyword| self.for_items(in_keyword, keyword))
                .transpose()?
        };
        self.skip_newlines();
        let body = self.loop_body(depth, keyword, true)?;
        Ok((variable, items, body))
    }

    /// The words after `in`, up to the `;` or newline that ends them.
    fn for_items(&mut self, in_keyword: Span, start: Span) -> Result<ForItems, ParseError> {
        let mut words = Vec::new();
        loop {
            let Some(token) = self.advance() else {
                return Err(ParseError::Unclosed { span: start });
            };
            match token.kind {
                TokenKind::Word(word) => words.push(self.command_word(word, token.span)?),
                TokenKind::Operator(Operator::Semicolon) | TokenKind::Newline => break,
                TokenKind::Operator(_)
                | TokenKind::Redirection(_)
                | TokenKind::Blank
                | TokenKind::Comment
                | TokenKind::HereDocumentBody(_) => {
                    return Err(ParseError::UnexpectedToken {
                        token: unexpected(&token.kind),
                        span: token.span,
                    });
                }
            }
        }
        Ok(ForItems {
            keyword: in_keyword,
            words,
        })
    }

    /// `while list do list done` or `until list do list done`; `kind` wraps the loop as one or the other.
    fn loop_command(
        &mut self,
        depth: usize,
        kind: fn(LoopCommand) -> CompoundKind,
    ) -> Result<CompoundCore, ParseError> {
        let keyword = self.advance_span();
        let condition = self.compound_list(depth, keyword)?;
        let body = self.loop_body(depth, keyword, false)?;
        let close = body.close;
        let command = LoopCommand {
            keyword,
            condition,
            body,
        };
        Ok(CompoundCore::Exact(kind(command), close))
    }

    /// `do list done`, or `{ list }` when `braces` allows it (after a `for` or `select` header, as in bash).
    fn loop_body(&mut self, depth: usize, start: Span, braces: bool) -> Result<LoopBody, ParseError> {
        let (open, closing) = if let Some(open) = self.next_reserved(ReservedWord::Do) {
            (open, ReservedWord::Done)
        } else if let Some(open) = braces.then(|| self.next_reserved(ReservedWord::LeftBrace)).flatten() {
            (open, ReservedWord::RightBrace)
        } else {
            return Err(self.unexpected_or_unclosed(start));
        };
        let body = self.compound_list(depth, start)?;
        let close = self.expect_reserved(closing, start)?;
        Ok(LoopBody { open, body, close })
    }

    /// `case word in [clause]… esac`.
    fn case_command(&mut self, depth: usize) -> Result<CompoundCore, ParseError> {
        let keyword = self.advance_span();
        let subject = self.expect_word(keyword)?;
        self.skip_newlines();
        let in_keyword = self.expect_reserved(ReservedWord::In, keyword)?;
        let mut clauses = Vec::new();
        let esac = loop {
            self.skip_newlines();
            // `esac` ends the command where a pattern would start, unless a `(` opens the pattern list (`(esac)`).
            if let Some(esac) = self.next_reserved(ReservedWord::Esac) {
                break esac;
            }
            let clause = self.case_clause(depth, keyword)?;
            let ended = clause.terminator.is_none();
            clauses.push(clause);
            if ended {
                // Without a terminator, only `esac` may follow the arm's body.
                break self.expect_reserved(ReservedWord::Esac, keyword)?;
            }
        };
        Ok(CompoundCore::Exact(
            CompoundKind::Case(CaseCommand {
                keyword,
                subject,
                in_keyword,
                clauses,
                esac,
            }),
            esac,
        ))
    }

    /// One `case` arm: `[(] pattern [| pattern]… ) list [;; | ;& | ;;&]`.
    fn case_clause(&mut self, depth: usize, start: Span) -> Result<CaseClause, ParseError> {
        let open = self
            .next_if(|kind| is_operator(kind, Operator::LeftParen))
            .map(|token| token.span);
        let mut patterns = vec![self.expect_word(start)?];
        while self.next_if(|kind| is_operator(kind, Operator::Pipe)).is_some() {
            patterns.push(self.expect_word(start)?);
        }
        let close = self.expect_operator(Operator::RightParen, start)?;
        // An arm's body may be empty (`a) ;;`).
        let body = self.list(depth + 1)?;
        let terminator = self
            .next_if_map(|kind| match kind {
                TokenKind::Operator(Operator::DoubleSemicolon) => Some(CaseTerminatorKind::Break),
                TokenKind::Operator(Operator::SemicolonAmpersand) => Some(CaseTerminatorKind::FallThrough),
                TokenKind::Operator(Operator::DoubleSemicolonAmpersand) => Some(CaseTerminatorKind::Continue),
                TokenKind::Word(_)
                | TokenKind::Operator(_)
                | TokenKind::Redirection(_)
                | TokenKind::Newline
                | TokenKind::Blank
                | TokenKind::Comment
                | TokenKind::HereDocumentBody(_) => None,
            })
            .map(|(kind, span)| CaseTerminator { kind, span });
        Ok(CaseClause {
            open,
            patterns,
            close,
            body,
            terminator,
        })
    }

    /// `[[ … ]]`, kept whole as unsupported: everything up to the first `]]` word. Bash 3.2 ends the expression at
    /// that word too and rejects a newline inside it; so does this parser rather than guess.
    fn conditional(&mut self) -> Result<CompoundCore, ParseError> {
        let open = self.advance_span();
        let close = loop {
            let Some(token) = self.advance() else {
                return Err(ParseError::Unclosed { span: open });
            };
            match token.kind {
                TokenKind::Word(Word {
                    reserved: Some(ReservedWord::DoubleRightBracket),
                    ..
                }) => break token.span,
                TokenKind::Newline => {
                    return Err(ParseError::UnexpectedToken {
                        token: Unexpected::Newline,
                        span: token.span,
                    });
                }
                TokenKind::Word(_)
                | TokenKind::Operator(_)
                | TokenKind::Redirection(_)
                | TokenKind::Blank
                | TokenKind::Comment
                | TokenKind::HereDocumentBody(_) => {}
            }
        };
        Ok(CompoundCore::Unsupported(
            UnsupportedConstruct::Compound(CompoundStart::ReservedWord(ReservedWord::DoubleLeftBracket)),
            close,
            None,
        ))
    }

    // ---- Function definitions ----

    /// Whether the next tokens are `name ( )`, the start of a function definition without `function`. The name must
    /// not be shaped like an assignment: bash rejects `a=b() …`.
    fn function_name_ahead(&self) -> bool {
        let (Some(name), Some(open), Some(close)) = (
            self.tokens.get(self.position),
            self.tokens.get(self.position + 1),
            self.tokens.get(self.position + 2),
        ) else {
            return false;
        };
        let TokenKind::Word(word) = &name.kind else {
            return false;
        };
        is_operator(&open.kind, Operator::LeftParen)
            && is_operator(&close.kind, Operator::RightParen)
            && matches!(self.assignment_shape(word, name.span), Ok(None))
    }

    /// `name () body` or `function name [()] body`, where the body is a compound command and its redirections. As in
    /// bash 3.2, newlines may come before the body but not between `function name` and its `()`, and with `function`
    /// a `(` must be followed by `)` (`function f ( a )` is a syntax error).
    ///
    /// A body outside decision 6's exact list makes the whole definition a [`Command::Unsupported`] node, so its name
    /// never counts as defined and calls to it resolve as programs.
    fn function_definition(&mut self, depth: usize) -> Result<Command, ParseError> {
        let keyword = self
            .next_if(|kind| is_reserved(kind, ReservedWord::Function))
            .map(|token| token.span);
        let start = keyword.unwrap_or(self.peek_span().unwrap_or(self.end_span()));
        let name = self.expect_word(start)?;
        let parens = if keyword.is_none()
            || self
                .peek()
                .is_some_and(|token| is_operator(&token.kind, Operator::LeftParen))
        {
            let open = self.expect_operator(Operator::LeftParen, start)?;
            let close = self.expect_operator(Operator::RightParen, start)?;
            Some(Span::new(open.start, close.end))
        } else {
            None
        };
        self.skip_newlines();
        let Some(body_start) = self.peek().and_then(|token| compound_start(&token.kind)) else {
            return Err(self.unexpected_or_unclosed(start));
        };
        let body = self.compound_command(body_start, depth)?;
        let span = Span::new(start.start, body.span().end);
        Ok(match body {
            Compound::Exact(body) => Command::FunctionDefinition(FunctionDefinition {
                keyword,
                name,
                parens,
                body,
                span,
            }),
            // The parts of an arithmetic body are not the definition's: the node stands for the whole definition.
            Compound::Unsupported(body) => Command::Unsupported(UnsupportedCommand {
                construct: body.construct,
                span,
                arithmetic: None,
            }),
        })
    }

    // ---- Words and assignments ----

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
                            // Parsed by the caller once the word is known to be an assignment.
                            substitutions: Vec::new(),
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
    fn reject_array_value(&self, assignment: &Assignment) -> Result<(), ParseError> {
        if let Some(token) = self.peek()
            && is_operator(&token.kind, Operator::LeftParen)
            && token.span.start == assignment.span.end
        {
            return Err(ParseError::Unsupported {
                construct: UnsupportedConstruct::ArrayAssignment,
                span: assignment.span,
            });
        }
        Ok(())
    }

    /// The error for a `(` inside a simple command (a lone `name ()` was already read as a function definition by
    /// `command`). Glued to an assignment-shaped argument it is an array value (`declare -a x=(1)`); elsewhere bash
    /// reports a syntax error (`echo (a)`, `A=1 f()`).
    fn left_paren_in_command(&self, words: &[CommandWord], span: Span) -> ParseError {
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

    // ---- Token access ----

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn peek_span(&self) -> Option<Span> {
        self.peek().map(|token| token.span)
    }

    /// Takes the next token, leaving a placeholder behind.
    fn advance(&mut self) -> Option<Token> {
        let slot = self.tokens.get_mut(self.position)?;
        self.position += 1;
        let placeholder = Token {
            kind: TokenKind::Blank,
            span: slot.span,
        };
        Some(mem::replace(slot, placeholder))
    }

    /// Takes the next token, which the caller has already looked at, and returns its span.
    fn advance_span(&mut self) -> Span {
        self.advance().map_or(self.end_span(), |token| token.span)
    }

    /// Takes the next token if `accept` says so.
    fn next_if(&mut self, accept: impl FnOnce(&TokenKind) -> bool) -> Option<Token> {
        if accept(&self.peek()?.kind) {
            self.advance()
        } else {
            None
        }
    }

    /// Consumes the next token if `classify` recognises it, returning what it recognised and where the token was.
    fn next_if_map<T>(&mut self, classify: impl FnOnce(&TokenKind) -> Option<T>) -> Option<(T, Span)> {
        let found = classify(&self.peek()?.kind)?;
        let token = self.advance()?;
        Some((found, token.span))
    }

    /// Takes the next token if it is the reserved word `reserved`, returning its span.
    fn next_reserved(&mut self, reserved: ReservedWord) -> Option<Span> {
        self.next_if(|kind| is_reserved(kind, reserved)).map(|token| token.span)
    }

    /// Takes the reserved word `reserved`, which must come next. `start` is the construct's opening token, reported
    /// if the line ends first.
    fn expect_reserved(&mut self, reserved: ReservedWord, start: Span) -> Result<Span, ParseError> {
        self.next_reserved(reserved)
            .ok_or_else(|| self.unexpected_or_unclosed(start))
    }

    /// Takes the operator `operator`, which must come next.
    fn expect_operator(&mut self, operator: Operator, start: Span) -> Result<Span, ParseError> {
        self.next_if(|kind| is_operator(kind, operator))
            .map(|token| token.span)
            .ok_or_else(|| self.unexpected_or_unclosed(start))
    }

    /// Takes a word, which must come next. Reserved-word spellings are plain words here (`for do in …`).
    fn expect_word(&mut self, start: Span) -> Result<CommandWord, ParseError> {
        match self.next_if(|kind| matches!(kind, TokenKind::Word(_))) {
            Some(Token {
                kind: TokenKind::Word(word),
                span,
            }) => self.command_word(word, span),
            Some(_) | None => Err(self.unexpected_or_unclosed(start)),
        }
    }

    /// The error when the next token is not what a construct opened at `start` needs: the unexpected token, or
    /// [`ParseError::Unclosed`] at the end of the input.
    fn unexpected_or_unclosed(&self, start: Span) -> ParseError {
        match self.peek() {
            Some(token) => ParseError::UnexpectedToken {
                token: unexpected(&token.kind),
                span: token.span,
            },
            None => ParseError::Unclosed { span: start },
        }
    }

    /// Whether a comment starts inside `span`.
    fn comment_within(&self, span: Span) -> bool {
        let first_at_or_after = self.comments.partition_point(|comment| comment.start < span.start);
        self.comments
            .get(first_at_or_after)
            .is_some_and(|comment| comment.start < span.end)
    }

    fn skip_newlines(&mut self) {
        while self.next_if(|kind| matches!(kind, TokenKind::Newline)).is_some() {}
    }

    /// An empty span at the end of the source, for errors at the end of the line (or of a substitution body).
    const fn end_span(&self) -> Span {
        Span::new(self.end, self.end)
    }
}

/// Moves `error`, found while parsing the un-escaped text of the backtick body at `body_span` (whose text in the line
/// is `body`), back onto the line. The body is un-escaped again with origins recorded: only the error path pays for
/// them. An offset past the un-escaped text (an error at its end) maps to the end of the body.
fn error_on_line(error: ParseError, body_span: Span, body: &str, in_double_quotes: bool) -> ParseError {
    let mut origins = Vec::new();
    unescape_backtick(body, in_double_quotes, Some(&mut origins));
    let origin = |offset: usize| {
        origins
            .get(offset)
            .map_or(body_span.end, |origin| body_span.start + origin)
    };
    error.map_span(|span| Span::new(origin(span.start), origin(span.end)))
}

/// Un-escapes a backtick body as bash does before reading it as commands: a backslash is removed before `$`, `` ` ``
/// and `\` (and before `"` when the backticks are inside double quotes), and a line continuation (`\` newline) is
/// removed entirely; any other backslash stays. Checked against bash 3.2: the body `` echo \`date\` `` runs `date`, and a
/// comment ending in `\` newline inside backticks swallows the next line. Returns `body` itself when nothing changes.
///
/// With `origins`, records for each byte of the result its offset in `body`, to map spans back onto the line.
fn unescape_backtick<'b>(body: &'b str, in_double_quotes: bool, mut origins: Option<&mut Vec<usize>>) -> Cow<'b, str> {
    let bytes = body.as_bytes();
    let mut text = String::new();
    let mut changed = false;
    // Up to where `body` has been copied into `text`.
    let mut copied = 0;
    let mut at = 0;
    while at < bytes.len() {
        if bytes.get(at) != Some(&b'\\') {
            at += 1;
            continue;
        }
        let (resume, next_copy) = match bytes.get(at + 1) {
            // `\` newline: both bytes go.
            Some(b'\n') => (at + 2, at + 2),
            // The backslash goes; the byte it escapes is kept, and never read as an escape itself.
            Some(b'$' | b'`' | b'\\') => (at + 2, at + 1),
            Some(b'"') if in_double_quotes => (at + 2, at + 1),
            // A backslash before anything else is kept, with the byte it precedes.
            Some(_) | None => {
                at += 2;
                continue;
            }
        };
        text.push_str(body.get(copied..at).unwrap_or_default());
        if let Some(origins) = origins.as_deref_mut() {
            origins.extend(copied..at);
        }
        changed = true;
        copied = next_copy;
        at = resume;
    }
    if !changed && origins.is_none() {
        return Cow::Borrowed(body);
    }
    text.push_str(body.get(copied..).unwrap_or_default());
    if let Some(origins) = origins {
        origins.extend(copied..bytes.len());
    }
    Cow::Owned(text)
}

/// The compound command a token starts in command position, if any. A `(` always starts one (a subshell or `((`).
fn compound_start(kind: &TokenKind) -> Option<CompoundStartToken> {
    match kind {
        TokenKind::Operator(Operator::LeftParen) => Some(CompoundStartToken::Paren),
        TokenKind::Word(Word {
            reserved: Some(reserved),
            ..
        }) => match reserved {
            ReservedWord::LeftBrace => Some(CompoundStartToken::Group),
            ReservedWord::If => Some(CompoundStartToken::If),
            ReservedWord::For => Some(CompoundStartToken::For),
            ReservedWord::Select => Some(CompoundStartToken::Select),
            ReservedWord::While => Some(CompoundStartToken::While),
            ReservedWord::Until => Some(CompoundStartToken::Until),
            ReservedWord::Case => Some(CompoundStartToken::Case),
            ReservedWord::DoubleLeftBracket => Some(CompoundStartToken::Conditional),
            ReservedWord::Bang
            | ReservedWord::RightBrace
            | ReservedWord::DoubleRightBracket
            | ReservedWord::Coproc
            | ReservedWord::Do
            | ReservedWord::Done
            | ReservedWord::Elif
            | ReservedWord::Else
            | ReservedWord::Esac
            | ReservedWord::Fi
            | ReservedWord::Function
            | ReservedWord::In
            | ReservedWord::Then
            | ReservedWord::Time => None,
        },
        TokenKind::Word(_)
        | TokenKind::Operator(_)
        | TokenKind::Redirection(_)
        | TokenKind::Newline
        | TokenKind::Blank
        | TokenKind::Comment
        | TokenKind::HereDocumentBody(_) => None,
    }
}

/// Whether a token, where a command would start, ends the list being read instead: a closing operator, or a
/// reserved word that only continues or closes an enclosing construct. The enclosing construct checks that it is the
/// one it expects; at the top level any of them is a syntax error.
fn closes_list(kind: &TokenKind) -> bool {
    match kind {
        TokenKind::Operator(
            Operator::RightParen
            | Operator::DoubleSemicolon
            | Operator::SemicolonAmpersand
            | Operator::DoubleSemicolonAmpersand,
        ) => true,
        TokenKind::Word(Word {
            reserved: Some(reserved),
            ..
        }) => matches!(
            reserved,
            ReservedWord::Then
                | ReservedWord::Elif
                | ReservedWord::Else
                | ReservedWord::Fi
                | ReservedWord::Do
                | ReservedWord::Done
                | ReservedWord::Esac
                | ReservedWord::RightBrace
        ),
        TokenKind::Word(_)
        | TokenKind::Operator(_)
        | TokenKind::Redirection(_)
        | TokenKind::Newline
        | TokenKind::Blank
        | TokenKind::Comment
        | TokenKind::HereDocumentBody(_) => false,
    }
}

/// Whether a token belongs to the simple command being read. A `(` does too, only so that the command can report
/// the precise error for it (`x=(1)`, `echo (a)`); operators and newlines end the command.
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
        | TokenKind::Comment
        | TokenKind::HereDocumentBody(_) => None,
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
        | TokenKind::Comment
        | TokenKind::HereDocumentBody(_) => None,
    }
}

/// Whether a token is an unquoted word spelled like `reserved`.
fn is_reserved(kind: &TokenKind, reserved: ReservedWord) -> bool {
    matches!(kind, TokenKind::Word(Word { reserved: Some(found), .. }) if *found == reserved)
}

/// Whether a token is the control operator `operator`.
fn is_operator(kind: &TokenKind, operator: Operator) -> bool {
    matches!(kind, TokenKind::Operator(found) if *found == operator)
}

/// The error for a reserved word in command position that starts neither a compound command nor a function
/// definition. Only `!` starts a pipeline, and the pipeline has already consumed it, so a `!` here is a second one
/// (`! ! a`) or follows a pipe (`a | ! b`): bash 3.2 rejects both. `coproc` is refused as unsupported (it prefixes a
/// pipeline, which this parser does not delimit), and so is `time` here, after `!` or a pipe, where bash 3.2 runs the
/// `time` program but later bash may read the keyword ([`Parser::time_keyword`] reads it where they agree); words
/// that only continue or close a construct are syntax errors where a command should start, as in bash.
fn misplaced_reserved_word(reserved: ReservedWord, span: Span) -> ParseError {
    match reserved {
        ReservedWord::Coproc | ReservedWord::Time => ParseError::Unsupported {
            construct: UnsupportedConstruct::Compound(CompoundStart::ReservedWord(reserved)),
            span,
        },
        ReservedWord::Bang
        | ReservedWord::LeftBrace
        | ReservedWord::RightBrace
        | ReservedWord::DoubleLeftBracket
        | ReservedWord::DoubleRightBracket
        | ReservedWord::Case
        | ReservedWord::Do
        | ReservedWord::Done
        | ReservedWord::Elif
        | ReservedWord::Else
        | ReservedWord::Esac
        | ReservedWord::Fi
        | ReservedWord::For
        | ReservedWord::Function
        | ReservedWord::If
        | ReservedWord::In
        | ReservedWord::Select
        | ReservedWord::Then
        | ReservedWord::Until
        | ReservedWord::While => ParseError::UnexpectedToken {
            token: Unexpected::ReservedWord(reserved),
            span,
        },
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
        TokenKind::Newline | TokenKind::Blank | TokenKind::Comment | TokenKind::HereDocumentBody(_) => {
            Unexpected::Newline
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::FunctionCall;
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
            "if secret-token; then",
            "case secret in secret) x;; fi",
            "secret() echo",
            "(( secret # x ))",
            "secret=(x)",
            "cat <<secret",
        ] {
            let message = parse(input).unwrap_err().to_string();
            assert!(!message.contains("secret"), "{input:?}: {message}");
        }
    }

    // ---- Constructs refused until a later story (fail closed, decision 6) ----

    #[test]
    fn here_string_is_a_redirection_with_its_word_as_target() {
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
        let tokens_left = Cell::new(MAX_TOKENS);
        let parser = || Parser {
            input: "a",
            end: 1,
            tokens: crate::lex::lex("a").unwrap(),
            position: 0,
            comments: Vec::new(),
            here_documents: BTreeMap::new(),
            context: LexContext::default(),
            depth: 0,
            tokens_left: &tokens_left,
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
        // Length must not deepen the stack: as many commands in one and-or list and one pipeline as the token limit
        // allows (`a && ` is four tokens: a word, a blank, the operator and a blank).
        let count = MAX_TOKENS / 4 - 1;
        let input = "a && ".repeat(count) + "a";
        assert_eq!(parse(&input).unwrap().simple_commands().count(), count + 1);
        let input = "a | ".repeat(count) + "a";
        assert_eq!(parse(&input).unwrap().simple_commands().count(), count + 1);
        // KNSH-032: past the limit the line is refused instead.
        let input = "a && ".repeat(100_000) + "a";
        assert!(matches!(
            parse(&input),
            Err(ParseError::Lex(LexError::TooManyTokens { .. }))
        ));
    }

    #[test]
    fn oversized_input_is_rejected_by_the_lexer() {
        let input = "a".repeat(crate::MAX_INPUT_LEN + 1);
        assert!(matches!(
            parse(&input),
            Err(ParseError::Lex(LexError::InputTooLarge { .. }))
        ));
    }

    // ---- KNSH-030 helpers ----

    /// The only command of a one-command line.
    fn only(input: &str) -> Command {
        let script = parse(input).unwrap();
        assert_eq!(script.items.len(), 1, "{input:?}");
        let pipeline = &script.items[0].and_or.first;
        assert!(
            pipeline.rest.is_empty() && script.items[0].and_or.rest.is_empty(),
            "{input:?}"
        );
        pipeline.first.clone()
    }

    fn only_compound(input: &str) -> CompoundCommand {
        match only(input) {
            Command::Compound(compound) => compound,
            other => panic!("{input:?} gave {other:?}"),
        }
    }

    fn only_unsupported(input: &str) -> UnsupportedCommand {
        match only(input) {
            Command::Unsupported(unsupported) => unsupported,
            other => panic!("{input:?} gave {other:?}"),
        }
    }

    fn only_function(input: &str) -> FunctionDefinition {
        match only(input) {
            Command::FunctionDefinition(definition) => definition,
            other => panic!("{input:?} gave {other:?}"),
        }
    }

    /// For each simple command with a name: its name and whether it is marked as a function call.
    fn calls(input: &str) -> Vec<(&str, bool)> {
        parse(input)
            .unwrap()
            .simple_commands()
            .filter_map(|command| {
                let name = command.name()?;
                Some((text(input, name.span), command.function_call.is_some()))
            })
            .collect()
    }

    /// Whether the last simple command of `input` is marked as a function call.
    fn last_is_function_call(input: &str) -> bool {
        parse(input)
            .unwrap()
            .simple_commands()
            .last()
            .unwrap()
            .function_call
            .is_some()
    }

    fn list_names<'a>(input: &'a str, items: &[ListItem]) -> Vec<&'a str> {
        let script = Script {
            items: items.to_vec(),
            span: Span::new(0, input.len()),
        };
        script
            .simple_commands()
            .filter_map(|command| command.name().map(|name| text(input, name.span)))
            .collect()
    }

    fn unclosed(input: &str) -> &str {
        match parse(input) {
            Err(ParseError::Unclosed { span }) => text(input, span),
            other => panic!("{input:?} gave {other:?}"),
        }
    }

    // ---- Story unit tests (KNSH-030) ----

    #[test]
    fn parses_if_elif_else_fi() {
        // KNSH-030: every branch's commands are visible, with each reserved word's span.
        let input = "if a; then b; elif c\nthen d; else e; fi";
        let compound = only_compound(input);
        assert_eq!(text(input, compound.span), input);
        let CompoundKind::If(command) = &compound.kind else {
            panic!("{compound:?}")
        };
        assert_eq!(command.clauses.len(), 2);
        let clause = &command.clauses[1];
        assert_eq!(text(input, clause.keyword), "elif");
        assert_eq!(text(input, clause.then), "then");
        assert_eq!(list_names(input, &clause.condition), ["c"]);
        assert_eq!(list_names(input, &clause.body), ["d"]);
        let otherwise = command.else_clause.as_ref().unwrap();
        assert_eq!(text(input, otherwise.keyword), "else");
        assert_eq!(text(input, command.fi), "fi");
        assert_eq!(names(input), [Some("a"), Some("b"), Some("c"), Some("d"), Some("e")]);
        // Without elif and else, and with newlines everywhere bash allows them.
        assert_eq!(names("if\na\nthen\nb\nfi"), [Some("a"), Some("b")]);
    }

    #[test]
    fn parses_for_in_and_for_without_in() {
        let input = "for x in a 'b c' $d; do echo $x; done";
        let compound = only_compound(input);
        let CompoundKind::For(command) = &compound.kind else {
            panic!("{compound:?}")
        };
        assert_eq!(text(input, command.keyword), "for");
        assert_eq!(text(input, command.variable.span), "x");
        let items = command.items.as_ref().unwrap();
        assert_eq!(text(input, items.keyword), "in");
        assert_eq!(word_texts(input, &items.words), ["a", "'b c'", "$d"]);
        assert_eq!(text(input, command.body.open), "do");
        assert_eq!(text(input, command.body.close), "done");
        assert_eq!(names(input), [Some("echo")]);

        // Without `in` the loop runs over "$@"; every form bash 3.2 accepts.
        for input in [
            "for x; do a; done",
            "for x do a; done",
            "for x\ndo a; done",
            "for x; { a; }",
            "for x\nin; do a; done",
        ] {
            let compound = only_compound(input);
            let CompoundKind::For(command) = &compound.kind else {
                panic!("{input:?}")
            };
            assert_eq!(names(input), [Some("a")], "{input:?}");
            assert_eq!(text(input, compound.span), input, "{input:?}");
            if input.contains("in;") {
                assert_eq!(command.items.as_ref().unwrap().words, []);
            } else {
                assert!(command.items.is_none(), "{input:?}");
            }
        }
        // Reserved spellings are plain words after `in`.
        let input = "for x in do done; do a; done";
        let CompoundKind::For(command) = only_compound(input).kind else {
            panic!()
        };
        assert_eq!(word_texts(input, &command.items.unwrap().words), ["do", "done"]);
    }

    #[test]
    fn parses_while_and_until_loops() {
        let input = "while a; b; do c; done";
        let compound = only_compound(input);
        let CompoundKind::While(command) = &compound.kind else {
            panic!("{compound:?}")
        };
        assert_eq!(text(input, command.keyword), "while");
        assert_eq!(list_names(input, &command.condition), ["a", "b"]);
        assert_eq!(list_names(input, &command.body.body), ["c"]);
        assert_eq!(text(input, compound.span), input);

        let input = "until a\ndo\nb\ndone";
        let compound = only_compound(input);
        let CompoundKind::Until(command) = &compound.kind else {
            panic!("{compound:?}")
        };
        assert_eq!(text(input, command.keyword), "until");
        assert_eq!(names(input), [Some("a"), Some("b")]);
        // `while` takes no `{ … }` body: the `{` is a command of the condition, and `do` never comes.
        assert_eq!(unclosed("while a; { b; }"), "while");
    }

    #[test]
    fn parses_case_with_multiple_patterns_and_fallthrough_terminators() {
        // `;&` and `;;&` are bash 4 (bash 3.2 rejects them), parsed as the story asks.
        let input = "case $x in a|b) one;; (c) two;& d|e|f) three;;& *) four\nesac";
        let compound = only_compound(input);
        let CompoundKind::Case(command) = &compound.kind else {
            panic!("{compound:?}")
        };
        assert_eq!(text(input, command.keyword), "case");
        assert_eq!(text(input, command.subject.span), "$x");
        assert_eq!(text(input, command.in_keyword), "in");
        assert_eq!(text(input, command.esac), "esac");
        let patterns: Vec<Vec<&str>> = command
            .clauses
            .iter()
            .map(|clause| word_texts(input, &clause.patterns))
            .collect();
        assert_eq!(patterns, [vec!["a", "b"], vec!["c"], vec!["d", "e", "f"], vec!["*"]]);
        let terminators: Vec<Option<CaseTerminatorKind>> = command
            .clauses
            .iter()
            .map(|clause| clause.terminator.map(|terminator| terminator.kind))
            .collect();
        assert_eq!(
            terminators,
            [
                Some(CaseTerminatorKind::Break),
                Some(CaseTerminatorKind::FallThrough),
                Some(CaseTerminatorKind::Continue),
                None,
            ]
        );
        assert_eq!(text(input, command.clauses[1].open.unwrap()), "(");
        assert_eq!(text(input, command.clauses[2].terminator.unwrap().span), ";;&");
        assert_eq!(names(input), [Some("one"), Some("two"), Some("three"), Some("four")]);
    }

    #[test]
    fn parses_subshell_and_group_with_redirection() {
        let input = "(a; b) >f";
        let compound = only_compound(input);
        let CompoundKind::Subshell(subshell) = &compound.kind else {
            panic!("{compound:?}")
        };
        assert_eq!(text(input, subshell.open), "(");
        assert_eq!(text(input, subshell.close), ")");
        assert_eq!(list_names(input, &subshell.body), ["a", "b"]);
        assert_eq!(compound.redirections.len(), 1);
        assert_eq!(text(input, compound.redirections[0].span), ">f");
        assert_eq!(text(input, compound.span), input);

        let input = "{ a; } 2>&1";
        let compound = only_compound(input);
        let CompoundKind::Group(group) = &compound.kind else {
            panic!("{compound:?}")
        };
        assert_eq!(text(input, group.open), "{");
        assert_eq!(text(input, group.close), "}");
        assert_eq!(compound.redirections[0].fd.unwrap().value, Some(2));
        assert_eq!(text(input, compound.redirections[0].target.span), "1");
        assert_eq!(text(input, compound.span), input);
        // The redirections belong to the compound command, not to its last simple command.
        assert_eq!(only_command(input).redirections, []);
    }

    #[test]
    fn parses_both_function_definition_forms() {
        for (input, keyword, parens) in [
            ("f() { a; }", false, true),
            ("f () { a; }", false, true),
            ("f( ) { a; }", false, true),
            ("f()\n\n{ a; }", false, true),
            ("function f { a; }", true, false),
            ("function f\n{ a; }", true, false),
            ("function f() { a; }", true, true),
            ("function f () ( a )", true, true),
        ] {
            let definition = only_function(input);
            assert_eq!(text(input, definition.name.span), "f", "{input:?}");
            assert_eq!(definition.keyword.is_some(), keyword, "{input:?}");
            assert_eq!(definition.parens.is_some(), parens, "{input:?}");
            assert_eq!(text(input, definition.span), input, "{input:?}");
            assert_eq!(names(input), [Some("a")], "{input:?}");
        }
        let input = "function f() { a; }";
        let definition = only_function(input);
        assert_eq!(text(input, definition.keyword.unwrap()), "function");
        assert_eq!(text(input, definition.parens.unwrap()), "()");
        // Any compound command is a body, with redirections that apply on every call.
        let input = "f() if a; then b; fi >log";
        let definition = only_function(input);
        assert!(matches!(definition.body.kind, CompoundKind::If(_)));
        assert_eq!(text(input, definition.body.redirections[0].span), ">log");
        assert_eq!(text(input, definition.span), input);
    }

    #[test]
    fn descends_into_function_bodies() {
        // KNSH-030: `f() { rm -rf x; }; f` exposes `rm`, and the call is marked as reaching that body.
        let input = "f() { rm -rf x; }; f";
        let script = parse(input).unwrap();
        let commands: Vec<&SimpleCommand> = script.simple_commands().collect();
        assert_eq!(commands.len(), 2);
        assert_eq!(text(input, commands[0].name().unwrap().span), "rm");
        assert_eq!(word_texts(input, commands[0].arguments()), ["-rf", "x"]);
        assert_eq!(commands[0].function_call, None);
        let definition = script.function_definitions().next().unwrap();
        assert_eq!(
            commands[1].function_call,
            Some(FunctionCall {
                definitions: vec![definition.span]
            })
        );
        // A body is walked even when nothing calls it, and nested bodies too.
        assert_eq!(names("f() { g() { rm x; }; }"), [Some("rm")]);
    }

    #[test]
    fn marks_select_as_unsupported() {
        // Decision 6 does not list `select`: it is kept whole, never omitted, and the rest of the line is still read.
        let input = "select x in a b; do rm $x; done >out; echo after";
        let script = parse(input).unwrap();
        let commands: Vec<&Command> = script.commands().collect();
        let Command::Unsupported(unsupported) = commands[0] else {
            panic!("{commands:?}")
        };
        assert_eq!(
            unsupported.construct,
            UnsupportedConstruct::Compound(CompoundStart::ReservedWord(ReservedWord::Select))
        );
        assert_eq!(text(input, unsupported.span), "select x in a b; do rm $x; done >out");
        assert_eq!(names(input), [Some("echo")]);
        let input = "select x; { a; }";
        assert_eq!(text(input, only_unsupported(input).span), input);
    }

    // ---- Other constructs outside decision 6 ----

    #[test]
    fn conditional_and_arithmetic_commands_are_unsupported_nodes() {
        for (input, construct, extent) in [
            (
                "[[ -f x && $y == *.c ]] 2>/dev/null",
                CompoundStart::ReservedWord(ReservedWord::DoubleLeftBracket),
                "[[ -f x && $y == *.c ]] 2>/dev/null",
            ),
            ("(( i += 1 ))", CompoundStart::Arithmetic, "(( i += 1 ))"),
            ("((a > (b)))", CompoundStart::Arithmetic, "((a > (b)))"),
            ("((x)) >f", CompoundStart::Arithmetic, "((x)) >f"),
            (
                "for ((i = 0; i < 3; i++)); do a; done",
                CompoundStart::ArithmeticFor,
                "for ((i = 0; i < 3; i++)); do a; done",
            ),
            ("for ((;;))\n{ a; }", CompoundStart::ArithmeticFor, "for ((;;))\n{ a; }"),
            // A function whose body is unsupported is unsupported as a whole.
            (
                "f() [[ -n x ]]",
                CompoundStart::ReservedWord(ReservedWord::DoubleLeftBracket),
                "f() [[ -n x ]]",
            ),
            (
                "function g { select x; do a; done; }",
                CompoundStart::ReservedWord(ReservedWord::Select),
                "",
            ),
        ] {
            let command = only(input);
            let unsupported = match command {
                Command::Unsupported(unsupported) => unsupported,
                // An unsupported construct nested in a compound body is a node inside it.
                Command::FunctionDefinition(definition) => {
                    let script = Script {
                        items: definition.body.kind.lists()[0].to_vec(),
                        span: Span::new(0, input.len()),
                    };
                    match script.commands().next() {
                        Some(Command::Unsupported(unsupported)) => unsupported.clone(),
                        other => panic!("{input:?} gave {other:?}"),
                    }
                }
                other => panic!("{input:?} gave {other:?}"),
            };
            assert_eq!(
                unsupported.construct,
                UnsupportedConstruct::Compound(construct),
                "{input:?}"
            );
            if !extent.is_empty() {
                assert_eq!(text(input, unsupported.span), extent, "{input:?}");
            }
        }
        // The rest of the line is still read exactly.
        assert_eq!(names("[[ -d x ]] && rm -r x"), [Some("rm")]);
        assert_eq!(names("(( n > 2 )) || { echo small; }"), [Some("echo")]);
    }

    // KNSH-097: the evaluator reads the expression and the loop body from the node instead of parsing them again.
    #[test]
    fn arithmetic_nodes_keep_their_expression_and_loop_body() {
        let input = "((a > (b))) >f";
        let Command::Unsupported(unsupported) = only(input) else {
            panic!("not unsupported");
        };
        let Some(ArithmeticParts::Command { expression, close }) = unsupported.arithmetic.as_deref() else {
            panic!("no arithmetic parts: {unsupported:?}");
        };
        assert_eq!(text(input, *expression), "a > (b)");
        assert_eq!(text(input, *close), ")");
        assert_eq!(&input[close.end..], " >f");

        let input = "for (( i = 0; i < 3; i++ )); do a; b; done";
        let Command::Unsupported(unsupported) = only(input) else {
            panic!("not unsupported");
        };
        let Some(ArithmeticParts::For { expressions, body }) = unsupported.arithmetic.as_deref() else {
            panic!("no arithmetic parts: {unsupported:?}");
        };
        assert_eq!(text(input, *expressions), " i = 0; i < 3; i++ ");
        assert_eq!(body.body.len(), 2);
        assert_eq!(text(input, body.close), "done");

        // Other opaque nodes, and a function whose body is arithmetic, carry no parts.
        for input in ["[[ -n x ]]", "f() (( 1 ))", "select x; do a; done"] {
            let Command::Unsupported(unsupported) = only(input) else {
                panic!("{input}: not unsupported");
            };
            assert_eq!(unsupported.arithmetic, None, "{input}");
        }
    }

    #[test]
    fn double_paren_that_does_not_close_as_arithmetic_is_nested_subshells() {
        // Bash 3.2: `((echo a); (echo b))` runs two nested subshells, because the `)` matching the second `(` is not
        // followed by `)`.
        let input = "((echo a); (echo b))";
        let compound = only_compound(input);
        assert!(matches!(compound.kind, CompoundKind::Subshell(_)));
        assert_eq!(names(input), [Some("echo"), Some("echo")]);
        assert_eq!(names("( (a) )"), [Some("a")]);
        assert_eq!(names("((a) )"), [Some("a")]);
    }

    #[test]
    fn arithmetic_with_comment_or_unclosed_is_refused() {
        // Bash reads `#` as text inside `(( ))` where the lexer starts a comment: the two could close it in
        // different places, so the line is refused rather than guessed.
        assert_eq!(
            unsupported("(( 1 # ))\n)); rm x"),
            UnsupportedConstruct::Compound(CompoundStart::Arithmetic)
        );
        assert_eq!(unclosed("(( 1 + 2"), "(");
        assert_eq!(unclosed("[[ -f x"), "[[");
        // A newline inside `[[ ]]` is a syntax error in bash 3.2.
        assert_eq!(unexpected_token("[[ a\n== a ]]").0, Unexpected::Newline);
        // `for` takes only `((` before its arithmetic header.
        assert_eq!(
            unexpected_token("for (a) do b; done"),
            (Unexpected::Operator(Operator::LeftParen), "(")
        );
    }

    #[test]
    fn coproc_and_ambiguous_time_stay_refused() {
        // `coproc` prefixes a pipeline rather than forming a command, and decision 6 makes it dynamic. `time` is
        // refused wherever bash 3.2 and later bash read it differently (KNSH-036).
        for (input, word) in [
            ("coproc a", ReservedWord::Coproc),
            ("{ coproc a; }", ReservedWord::Coproc),
            ("time", ReservedWord::Time),
            ("time -p", ReservedWord::Time),
            ("time -p; a", ReservedWord::Time),
            ("time\na", ReservedWord::Time),
            ("time -- a", ReservedWord::Time),
            ("time -x a", ReservedWord::Time),
            ("time -p -p a", ReservedWord::Time),
            ("time \"-p\" a", ReservedWord::Time),
            ("time time a", ReservedWord::Time),
            ("time | a", ReservedWord::Time),
            ("! time a", ReservedWord::Time),
            ("a | time b", ReservedWord::Time),
        ] {
            assert_eq!(
                unsupported(input),
                UnsupportedConstruct::Compound(CompoundStart::ReservedWord(word)),
                "{input:?}"
            );
        }
    }

    // KNSH-036: the `time` keyword at the start of a pipeline is read, with `-p`, before or after `!`.
    #[test]
    fn time_keyword_prefixes_a_pipeline() {
        let input = "time -p a | b && time ! { c; } || time ( d ); x=1 time e";
        let script = parse(input).unwrap();
        let and_or = &script.items[0].and_or;
        let time = and_or.first.time.unwrap();
        assert_eq!(text(input, time.keyword), "time");
        assert_eq!(text(input, time.posix.unwrap()), "-p");
        assert_eq!(text(input, time.span()), "time -p");
        assert_eq!(text(input, and_or.first.span), "time -p a | b");
        assert_eq!(and_or.first.rest.len(), 1);
        let second = &and_or.rest[0].pipeline;
        assert_eq!(second.time.unwrap().posix, None);
        assert!(second.is_negated());
        assert_eq!(text(input, second.span), "time ! { c; }");
        assert!(and_or.rest[1].pipeline.time.is_some());
        // After an assignment `time` is an ordinary word: the program `time`.
        assert_eq!(script.items[1].and_or.first.time, None);
        assert_eq!(names(input), ["a", "b", "c", "d", "time"].map(Some));
        // `time ! ! a` is still the error bash 3.2 reports.
        assert_eq!(
            unexpected_token("time ! ! a").0,
            Unexpected::ReservedWord(ReservedWord::Bang)
        );
    }

    // ---- Structure ----

    #[test]
    fn simple_commands_descend_into_every_body_and_condition() {
        // FR-LC-09: commands at every depth, in source order.
        let input = "a | { b; (c && d) } && if e; then while f; do g; done; fi; case x in y) h;; esac; i() { j; }";
        assert_eq!(names(input), ["a", "b", "c", "d", "e", "f", "g", "h", "j"].map(Some));
        // `commands` yields each compound command before the commands inside it.
        let script = parse("{ a; }").unwrap();
        let kinds: Vec<bool> = script
            .commands()
            .map(|command| matches!(command, Command::Compound(_)))
            .collect();
        assert_eq!(kinds, [true, false]);
    }

    #[test]
    fn compound_commands_combine_with_lists_and_pipelines() {
        let input = "! { a; } | (b) && for x in y; do c; done & d";
        let script = parse(input).unwrap();
        assert_eq!(script.items.len(), 2);
        assert!(script.items[0].is_background());
        let and_or = &script.items[0].and_or;
        assert!(and_or.first.is_negated());
        assert_eq!(and_or.first.rest.len(), 1);
        assert_eq!(names(input), [Some("a"), Some("b"), Some("c"), Some("d")]);
    }

    #[test]
    fn closing_words_are_recognised_right_after_a_compound_command() {
        // Bash 3.2 accepts these: after `)` or `}`, a closing reserved word needs no separator.
        for input in [
            "{ (a) }",
            "if (a) then b; fi",
            "while (a) do b; done",
            "{ { a; } }",
            "case x in y) (a) esac",
            "if a; then { b; } fi",
        ] {
            assert!(parse(input).is_ok(), "{input:?}: {:?}", parse(input));
        }
        // After a simple command they are arguments, so the construct stays open.
        assert_eq!(unclosed("{ echo a }"), "{");
        assert_eq!(unclosed("{ echo a; }}"), "{");
        assert_eq!(names("echo }"), [Some("echo")]);
    }

    #[test]
    fn reserved_words_inside_compound_commands_are_arguments_after_a_command_name() {
        let input = "if echo then fi; then echo done; fi";
        let script = parse(input).unwrap();
        let commands: Vec<&SimpleCommand> = script.simple_commands().collect();
        assert_eq!(word_texts(input, &commands[0].words), ["echo", "then", "fi"]);
        assert_eq!(word_texts(input, &commands[1].words), ["echo", "done"]);
    }

    #[test]
    fn case_edge_cases_bash_accepts() {
        // No arms; an empty arm body; `esac` as a pattern when opened with `(`; newline before `in`.
        assert!(parse("case a in esac").is_ok());
        assert_eq!(names("case a in a) ;; b) c;; esac"), [Some("c")]);
        let input = "case a in (esac) b;; esac";
        let CompoundKind::Case(command) = only_compound(input).kind else {
            panic!()
        };
        assert_eq!(word_texts(input, &command.clauses[0].patterns), ["esac"]);
        assert!(parse("case a\nin a) b;; esac").is_ok());
        assert_eq!(names("case a in a) b;; c) esac"), [Some("b")]);
    }

    // ---- Syntax errors (bash 3.2 rejects all of these) ----

    #[test]
    fn compound_syntax_errors() {
        for (input, token, at) in [
            ("{ a; } b", Unexpected::Word, "b"),
            ("(a) b", Unexpected::Word, "b"),
            ("(a) (b)", Unexpected::Operator(Operator::LeftParen), "("),
            ("( )", Unexpected::Operator(Operator::RightParen), ")"),
            ("{ }", Unexpected::ReservedWord(ReservedWord::RightBrace), "}"),
            ("if then fi", Unexpected::ReservedWord(ReservedWord::Then), "then"),
            ("if a; then fi", Unexpected::ReservedWord(ReservedWord::Fi), "fi"),
            (
                "if a; then b; done",
                Unexpected::ReservedWord(ReservedWord::Done),
                "done",
            ),
            (
                "for x in a; do done",
                Unexpected::ReservedWord(ReservedWord::Done),
                "done",
            ),
            (
                "for x in a b & do c; done",
                Unexpected::Operator(Operator::Background),
                "&",
            ),
            (
                "for x; in a; do b; done",
                Unexpected::ReservedWord(ReservedWord::In),
                "in",
            ),
            ("case\na in a) b;; esac", Unexpected::Newline, "\n"),
            ("case a in a) b;; esac c", Unexpected::Word, "c"),
            ("case a in a) b; fi", Unexpected::ReservedWord(ReservedWord::Fi), "fi"),
            ("function f ( echo a )", Unexpected::Word, "echo"),
            ("function f() echo x", Unexpected::Word, "echo"),
            ("f() echo x", Unexpected::Word, "echo"),
            ("function f\n() { a; }", Unexpected::Operator(Operator::RightParen), ")"),
            ("A=1 f() { a; }", Unexpected::Operator(Operator::LeftParen), "("),
            (">x f() { a; }", Unexpected::Operator(Operator::LeftParen), "("),
            ("{ a; } ; }", Unexpected::ReservedWord(ReservedWord::RightBrace), "}"),
            ("a; esac", Unexpected::ReservedWord(ReservedWord::Esac), "esac"),
            ("a ;& b", Unexpected::Operator(Operator::SemicolonAmpersand), ";&"),
        ] {
            assert_eq!(unexpected_token(input), (token, at), "{input:?}");
        }
        // Bash rejects `a=b() …` too; this parser already refuses it as an array value.
        assert_eq!(unsupported("a=b() { a; }"), UnsupportedConstruct::ArrayAssignment);
    }

    #[test]
    fn unclosed_compound_commands_are_errors() {
        for (input, opener) in [
            ("(a", "("),
            ("{ a;", "{"),
            ("if a", "if"),
            ("if a; then b", "if"),
            ("if a; then b; else", "if"),
            ("for", "for"),
            ("for x in a b", "for"),
            ("for x in a; do b", "for"),
            ("while a; do b; ", "while"),
            ("case a", "case"),
            ("case a in a) b;;", "case"),
            ("f()", "f"),
            ("function f", "function"),
            ("function", "function"),
        ] {
            assert_eq!(unclosed(input), opener, "{input:?}");
        }
    }

    // ---- Function calls (KNSH-030, KNSH-035) ----

    #[test]
    fn marks_call_to_function_defined_earlier_in_the_line() {
        assert_eq!(calls("f() { a; }; f x"), [("a", false), ("f", true)]);
        assert_eq!(calls("function f { a; }\nf"), [("a", false), ("f", true)]);
        // Quoting does not change which function is called.
        assert_eq!(
            calls("f() { a; }; \"f\"; \\f; 'f'"),
            [("a", false), ("\"f\"", true), ("\\f", true), ("'f'", true)]
        );
        // Inside a group, a pipeline's first command, an and-or list's first pipeline, a condition, a body.
        assert!(last_is_function_call("f() { a; }; { f; }"));
        assert!(last_is_function_call("f() { a; }; if b; then f; fi"));
        assert_eq!(calls("f() { a; }; f | cat")[1], ("f", true));
        assert!(last_is_function_call("f() { a; }; while b; do f; done"));
        assert!(last_is_function_call("f() { a; } && b; f"));
        // A later redefinition replaces the earlier one.
        let input = "f() { a; }; f() { b; }; f";
        let script = parse(input).unwrap();
        let second = script.function_definitions().nth(1).unwrap().span;
        let call = script.simple_commands().last().unwrap();
        assert_eq!(call.function_call.as_ref().unwrap().definitions, [second]);
    }

    #[test]
    fn call_to_undefined_or_later_defined_name_is_a_program() {
        // KNSH-035 resolves these as binaries.
        assert_eq!(calls("f; f() { a; }"), [("f", false), ("a", false)]);
        assert_eq!(calls("g() { a; }; f"), [("a", false), ("f", false)]);
    }

    #[test]
    fn definitions_that_do_not_reach_the_call_leave_it_unmarked() {
        // Each of these runs the program, not the function, in bash (or may): marking it would hide the program.
        for input in [
            "(rm() { :; }); rm -rf x",
            "rm() { :; } | cat; rm -rf x",
            "rm() { :; } & rm -rf x",
            "{ rm() { :; }; } & rm -rf x",
            "false && rm() { :; }; rm -rf x",
            "if a; then rm() { :; }; fi; rm -rf x",
            "case a in b) rm() { :; };; esac; rm -rf x",
            "for x in; do rm() { :; }; done; rm -rf x",
            "rm() { :; }; unset -f rm; rm -rf x",
            "rm() { :; }; (unset -f rm); rm -rf x; unset rm; rm -rf x",
        ] {
            let script = parse(input).unwrap();
            let last = script.simple_commands().last().unwrap();
            assert_eq!(text(input, last.name().unwrap().span), "rm", "{input:?}");
            assert!(last.function_call.is_none(), "{input:?}");
        }
        // The definition in a subshell still marks calls inside that subshell.
        assert!(last_is_function_call("(f() { a; }; f)"));
    }

    #[test]
    fn calls_inside_a_function_body_count_only_definitions_in_that_body() {
        // When `f` runs, `g` may have been removed: the call inside `f` is not marked.
        assert_eq!(
            calls("g() { a; }; f() { g; }; unset -f g; f"),
            [("a", false), ("g", false), ("unset", false), ("f", false)]
        );
        assert_eq!(calls("f() { g() { a; }; g; }"), [("a", false), ("g", true)]);
    }

    #[test]
    fn calling_a_function_that_may_change_functions_unsettles_them() {
        // `u` removes `f` when called, so the later `f` is not certain.
        assert_eq!(
            calls("f() { a; }; u() { unset -f f; }; u; f").last(),
            Some(&("f", false))
        );
        // `d` calls `u`, which may do anything a function body does.
        assert!(!last_is_function_call("f() { a; }; u() { b; }; d() { u; }; d; f"));
        // A settled body leaves the functions alone.
        assert!(last_is_function_call("f() { a; }; s() { echo hi; }; s; f"));
    }

    #[test]
    fn loops_that_change_functions_leave_calls_inside_unmarked() {
        // On the second iteration `f` may be the new definition, or removed.
        assert!(!calls("f() { a; }; while b; do f; unset -f f; done")[2].1);
        assert_eq!(
            calls("for x in 1 2; do f() { a; }; f; done"),
            [("a", false), ("f", true)]
        );
    }

    #[test]
    fn opaque_commands_turn_marking_off() {
        // They can change functions or name lookup in ways the tree does not show; such lines are dynamic anyway.
        for input in [
            "f() { a; }; eval x; f",
            "f() { a; }; trap 'unset -f f' DEBUG; f",
            "f() { a; }; alias f=rm; f",
            "f() { a; }; command unset -f f; f",
            "f() { a; }; source x; f",
            "f() { a; }; . x; f",
            "f() { a; }; readonly -f f; f() { b; }; f",
            "f() { a; }; $cmd; f",
        ] {
            assert!(!last_is_function_call(input), "{input:?}");
        }
        // Even when the opaque command comes after the call, or inside a body.
        assert!(!last_is_function_call("f() { a; }; g() { eval x; }; f"));
    }

    #[test]
    fn only_plain_identifier_names_that_are_not_special_builtins_are_matched() {
        // POSIX mode finds special builtins before functions and refuses other names; bash refuses quoted names.
        assert!(!last_is_function_call("exec() { a; }; exec rm -rf x"));
        assert!(!last_is_function_call("foo-bar() { a; }; foo-bar"));
        assert!(!last_is_function_call("x[1]() { a; }; x[1]"));
        assert!(!last_is_function_call("function \"g\" { a; }; g"));
        assert!(!last_is_function_call("function \\g { a; }; g"));
        assert!(last_is_function_call("cd() { a; }; cd x"));
        // A call spelled with glob characters may expand to another name.
        assert!(!last_is_function_call("f() { a; }; f*"));
    }

    #[test]
    fn unsupported_constructs_that_hide_commands_unsettle_functions() {
        // `select` and `for ((…))` bodies are opaque and may remove functions; `[[ ]]` and `(( ))` hold expressions only.
        assert!(!last_is_function_call("f() { a; }; select x; do unset -f f; done; f"));
        assert!(!last_is_function_call("f() { a; }; for ((;;)); do unset -f f; done; f"));
        assert!(last_is_function_call("f() { a; }; [[ -n x ]] && (( 1 )) && f"));
    }

    #[test]
    fn definitions_skipped_by_a_failed_redirection_or_break_leave_calls_unmarked() {
        // Checked against /bin/bash 3.2: each runs the program `rm`, since the definition never ran.
        for input in [
            "{ rm() { :; }; } >/nonexistent/x; rm -rf x",
            "if a; then rm() { :; }; fi </nonexistent; rm -rf x",
            "while break; rm() { :; }; do b; done; rm -rf x",
            "b() { break; }; until b; rm() { :; }; do c; done; rm -rf x",
        ] {
            assert!(!last_is_function_call(input), "{input:?}");
        }
        // Calls the skipped part would also skip are still marked.
        assert!(last_is_function_call("{ f() { a; }; f; } >x"));
    }

    #[test]
    fn errors_that_abandon_a_top_level_command_make_its_definitions_uncertain() {
        // Bash abandons the rest of the top-level command (up to a newline) on these errors and runs the next one, so
        // `rm` below is the program (checked against /bin/bash 3.2).
        for input in [
            "{ echo $((1/0)); rm() { :; }; }\nrm -rf x",
            "{ echo ${x@Q}; rm() { :; }; }\nrm -rf x",
            "UID=5; rm() { :; }\nrm -rf x",
            "shopt -s failglob\n{ echo /none*; rm() { :; }; }\nrm -rf x",
            "g() { echo $((1/0)); }\ng; rm() { :; }\nrm -rf x",
            // Possible only in some cases (`failglob` with a pattern in `$x`) or not in bash 3.2, refused anyway.
            "{ a >$x; rm() { :; }; }\nrm -rf x",
            "(( 1/0 )); rm() { :; }\nrm -rf x",
        ] {
            assert!(!last_is_function_call(input), "{input:?}");
        }
        // A top-level command that cannot fail this way keeps its definitions certain, and a call in the same one is
        // skipped along with the definition.
        assert!(last_is_function_call("X=1; f() { echo \"$1\"; }\nf x"));
        assert!(last_is_function_call("echo $((1/0)); f() { a; }; f"));
        assert!(last_is_function_call("case $x in *) b;; esac; f() { a; }\nf"));
    }

    #[test]
    fn case_arms_after_fall_through_name_every_definition_they_may_run() {
        // After `;&` the second arm runs with the first arm's `f`, so both definitions are named.
        let input = "f() { a; }; case x in x) f() { b; } ;& y) f ;; esac";
        let script = parse(input).unwrap();
        let definitions: Vec<Span> = script
            .function_definitions()
            .map(|definition| definition.span)
            .collect();
        let call = script.simple_commands().last().unwrap();
        assert_eq!(call.function_call.as_ref().unwrap().definitions, definitions);
        let input = "f() { a; }; case x in x) f() { b; } ;;& z) c;; y) f ;; esac";
        let script = parse(input).unwrap();
        let call = script.simple_commands().last().unwrap();
        assert_eq!(call.function_call.as_ref().unwrap().definitions.len(), 2);
    }

    #[test]
    fn a_definition_with_an_unsupported_body_unsettles_functions() {
        // `rm() [[ x ]]` replaces the first `rm`, whose name the opaque node does not give.
        assert!(!last_is_function_call("rm() { :; }; rm() [[ x ]]; rm -rf x"));
        assert!(!last_is_function_call(
            "rm() { :; }; g() { rm() (( 1 )); }; g; rm -rf x"
        ));
    }

    #[test]
    fn too_many_definitions_turn_marking_off() {
        let line = |count: usize| {
            let mut line = String::new();
            for index in 0..count {
                line.push('f');
                line.push_str(&index.to_string());
                line.push_str("() { a; }\n");
            }
            line + "f0"
        };
        assert!(last_is_function_call(&line(crate::MAX_FUNCTION_DEFINITIONS)));
        assert!(!last_is_function_call(&line(crate::MAX_FUNCTION_DEFINITIONS + 1)));
    }

    // ---- Limits ----

    #[test]
    fn deeply_nested_compound_commands_are_refused() {
        // KNSH-032: nested compound commands deepen the parser's recursion, which the depth limit bounds.
        let depth = MAX_NESTING_DEPTH;
        let ok = "{ ".repeat(depth) + "a" + &"; }".repeat(depth);
        assert!(parse(&ok).is_ok());
        let too_deep = "{ ".repeat(depth + 1) + "a" + &"; }".repeat(depth + 1);
        assert!(matches!(parse(&too_deep), Err(ParseError::NestingTooDeep { .. })));
        let too_deep = "( ".repeat(10_000) + "a" + &" )".repeat(10_000);
        assert!(matches!(parse(&too_deep), Err(ParseError::NestingTooDeep { .. })));
        let too_deep = "f() { ".repeat(depth + 1) + "a" + &"; }".repeat(depth + 1);
        assert!(matches!(parse(&too_deep), Err(ParseError::NestingTooDeep { .. })));
    }

    #[test]
    fn long_compound_lines_do_not_blow_up() {
        // Many sequential compound commands and conditional regions stay linear, function analysis included. Each
        // `if b; then f; fi && ` is 14 tokens, so 4 000 of them stay under the token limit (KNSH-032).
        let input = "f() { a; }\n".to_owned() + &"if b; then f; fi && ".repeat(4_000) + "f";
        let script = parse(&input).unwrap();
        assert_eq!(script.simple_commands().count(), 1 + 2 * 4_000 + 1);
        assert!(script.simple_commands().last().unwrap().function_call.is_some());
    }

    // ---- Story unit tests (KNSH-031) ----

    /// The name of every simple command of `input`, substitutions included, read in the text its spans index.
    fn deep_names(input: &str) -> Vec<String> {
        parse(input)
            .unwrap()
            .simple_commands_with_source(input)
            .filter_map(|(source, command)| command.name().map(|name| text(source, name.span).to_owned()))
            .collect()
    }

    /// The first simple command of the top-level script.
    fn only_top_command(input: &str) -> SimpleCommand {
        let script = parse(input).unwrap();
        match &script.items[0].and_or.first.first {
            Command::Simple(simple) => simple.clone(),
            other => panic!("{input:?} gave {other:?}"),
        }
    }

    /// The redirections of the only simple command of `input` at the top level.
    fn top_redirections(input: &str) -> Vec<Redirect> {
        let script = parse(input).unwrap();
        match &script.items[0].and_or.first.first {
            Command::Simple(simple) => simple.redirections.clone(),
            other => panic!("{input:?} gave {other:?}"),
        }
    }

    fn here_document_body<'a>(input: &'a str, redirect: &Redirect) -> &'a str {
        text(input, redirect.here_document.as_ref().unwrap().body)
    }

    #[test]
    fn parses_nested_command_substitution() {
        // FR-LC-02, decision 6: substitutions are parsed recursively, and their commands are decided too.
        let input = "echo $(a $(b))";
        assert_eq!(deep_names(input), ["echo", "a", "b"]);
        let command = only_top_command(input);
        let outer = &command.words[1].substitutions[0];
        assert_eq!(outer.kind, SubstitutionKind::Command);
        assert_eq!(text(input, outer.span), "$(a $(b))");
        assert_eq!(text(input, outer.script.span), "a $(b)");
        assert!(outer.text.is_none());
    }

    #[test]
    fn parses_backticks_with_escaped_backtick() {
        // Bash un-escapes `\`` before reading the body, so the inner backticks are a nested substitution.
        let input = r"echo `a \`b\``";
        assert_eq!(deep_names(input), ["echo", "a", "b"]);
        let command = only_top_command(input);
        let outer = &command.words[1].substitutions[0];
        assert_eq!(outer.kind, SubstitutionKind::Backtick);
        assert_eq!(outer.text.as_deref(), Some("a `b`"));
        let inner = parse(input).unwrap();
        let (source, b) = inner.simple_commands_with_source(input).nth(2).unwrap();
        assert_eq!(source, "a `b`");
        assert_eq!(text(source, b.span), "b");
        // A body that needs no un-escaping is parsed in place, with spans in the line.
        let input = "echo `date`";
        let command = only_top_command(input);
        assert!(command.words[1].substitutions[0].text.is_none());
        assert_eq!(deep_names(input), ["echo", "date"]);
    }

    #[test]
    fn substitution_in_assignment_is_visible() {
        let input = "X=$(curl https://example.test) cmd";
        assert_eq!(deep_names(input), ["cmd", "curl"]);
        let command = only_top_command(input);
        assert_eq!(command.assignments[0].substitutions.len(), 1);
        // An assignment alone runs its substitution too.
        assert_eq!(deep_names("X=\"`id -u`\""), ["id"]);
    }

    #[test]
    fn parses_heredoc_quoted_delimiter_body_literal() {
        // A quoted delimiter makes the body literal: the `$( … )` in it is text, never run.
        let input = "cat <<'EOF'\n$(rm -rf /)\nEOF\n";
        assert_eq!(deep_names(input), ["cat"]);
        let redirect = &top_redirections(input)[0];
        let document = redirect.here_document.as_ref().unwrap();
        assert!(document.quoted && !document.strip_tabs);
        assert_eq!(document.substitutions.len(), 0);
        assert_eq!(here_document_body(input, redirect), "$(rm -rf /)\n");
        assert_eq!(text(input, document.delimiter), "EOF\n");
        assert_eq!(text(input, redirect.target.span), "'EOF'");
        // The same body with an unquoted delimiter runs `rm`.
        let input = "cat <<EOF\n$(rm -rf /)\nEOF\n";
        assert_eq!(deep_names(input), ["cat", "rm"]);
        // Every quoting form of the delimiter counts (checked against bash 3.2).
        for input in [
            "cat <<\"EOF\"\n$(a)\nEOF",
            "cat <<\\EOF\n$(a)\nEOF",
            "cat <<E'OF'\n$(a)\nEOF",
        ] {
            assert_eq!(deep_names(input), ["cat"], "{input:?}");
        }
    }

    #[test]
    fn strips_tabs_for_dash_heredoc() {
        // `<<-` removes leading tabs, so the indented delimiter ends the body; `<<` does not.
        let input = "cat <<-EOF\n\tbody\n\t\tEOF\necho after";
        assert_eq!(deep_names(input), ["cat", "echo"]);
        let redirect = &top_redirections(input)[0];
        assert!(redirect.here_document.as_ref().unwrap().strip_tabs);
        assert_eq!(here_document_body(input, redirect), "\tbody\n");
        let input = "cat <<EOF\n\tEOF\nEOF\necho after";
        assert_eq!(here_document_body(input, &top_redirections(input)[0]), "\tEOF\n");
    }

    #[test]
    fn matches_two_heredocs_on_one_line_in_order() {
        // Bash reads the bodies in the order of the operators.
        let input = "cat <<A 3<<-B; tac <<C\na\nA\n\tb\nB\nc\nC\nnext";
        let script = parse(input).unwrap();
        let bodies: Vec<&str> = script
            .simple_commands()
            .flat_map(|command| &command.redirections)
            .map(|redirect| here_document_body(input, redirect))
            .collect();
        assert_eq!(bodies, ["a\n", "\tb\n", "c\n"]);
        assert_eq!(deep_names(input), ["cat", "tac", "next"]);
    }

    #[test]
    fn marks_heredoc_into_bash_as_dynamic_candidate() {
        // Decision 6: a here-document fed to a shell or interpreter is dynamic code.
        let input = "bash <<EOF\nrm -rf /\nEOF";
        assert!(top_redirections(input)[0].feeds_interpreter);
        for input in [
            "/usr/bin/python3.12 - <<'EOF'\nprint(1)\nEOF",
            "node <<< 'process.exit(1)'",
            "env FOO=1 sh <<EOF\nx\nEOF",
            "sudo -s <<EOF\nx\nEOF",
            "ssh host <<EOF\nx\nEOF",
            "$SHELL <<EOF\nx\nEOF",
            "docker exec -i box sh <<EOF\nx\nEOF",
        ] {
            assert!(top_redirections(input)[0].feeds_interpreter, "{input:?}");
        }
        for input in ["cat <<EOF\nx\nEOF", "grep -c x <<< 'text'", "<<EOF\nx\nEOF"] {
            assert!(!top_redirections(input)[0].feeds_interpreter, "{input:?}");
        }
        // On a compound command, any command inside may read it; a function of the line may run an interpreter.
        let script = parse("{ cat; perl; } <<EOF\nx\nEOF").unwrap();
        let Command::Compound(compound) = &script.items[0].and_or.first.first else {
            panic!("not a compound command");
        };
        assert!(compound.redirections[0].feeds_interpreter);
        let script = parse("f() { cat; }\nf <<EOF\nx\nEOF").unwrap();
        let call = script.simple_commands().last().unwrap();
        assert!(call.redirections[0].feeds_interpreter);
        // Inside a substitution too.
        let script = parse("x=$(python3 <<< 'print(1)')").unwrap();
        let (_, inner) = script.simple_commands_with_source("").last().unwrap();
        assert!(inner.redirections[0].feeds_interpreter);
    }

    #[test]
    fn errors_on_missing_heredoc_delimiter() {
        // KNSH-031: bash runs these with a warning; the parser refuses them.
        let error = parse("cat <<EOF\nbody").unwrap_err();
        assert_eq!(
            error,
            ParseError::Lex(LexError::Unterminated {
                construct: crate::error::Construct::HereDocument,
                span: Span::new(4, 14)
            })
        );
        assert_eq!(
            parse("cat <<EOF").unwrap_err(),
            ParseError::MissingHereDocumentBody { span: Span::new(4, 6) }
        );
        // A delimiter followed by more text on its line is not the delimiter.
        assert!(parse("cat <<EOF\nEOF \n").is_err());
        assert!(matches!(
            parse("cat <<"),
            Err(ParseError::MissingRedirectionTarget { .. })
        ));
    }

    // ---- Substitutions and here-documents (KNSH-031) ----

    #[test]
    fn substitutions_everywhere_are_parsed_in_source_order() {
        // Words, double quotes, redirection targets, process substitutions, `for` items, `case` subject and patterns.
        assert_eq!(
            deep_names("X=$(a) cmd \"$(b)\" >$(c) <(d) >(e)"),
            ["cmd", "a", "b", "c", "d", "e"]
        );
        assert_eq!(deep_names("for x in $(ls); do echo; done"), ["ls", "echo"]);
        assert_eq!(deep_names("case $(a) in $(b)) c;; esac"), ["a", "b", "c"]);
        assert_eq!(deep_names("{ x; } >$(y)"), ["x", "y"]);
        assert_eq!(deep_names("f() { x; } <$(y)"), ["x", "y"]);
        let input = "diff <(ls a) >(tee b)";
        let command = only_top_command(input);
        let kinds: Vec<SubstitutionKind> = command
            .words
            .iter()
            .flat_map(|word| &word.substitutions)
            .map(|substitution| substitution.kind)
            .collect();
        assert_eq!(kinds, [SubstitutionKind::InputProcess, SubstitutionKind::OutputProcess]);
    }

    #[test]
    fn unquoted_heredoc_body_runs_its_substitutions() {
        let input = "cat <<EOF\nuser: $(id -un) `hostname` \"$(pwd)\" \\$(not run)\nEOF\n";
        assert_eq!(deep_names(input), ["cat", "id", "hostname", "pwd"]);
        let document = top_redirections(input)[0].here_document.clone().unwrap();
        assert_eq!(document.substitutions.len(), 3);
    }

    #[test]
    fn heredoc_line_continuation_joins_lines_only_for_unquoted_delimiters() {
        // Bash 3.2: `foo\` newline `EOF` is the line `fooEOF`; an escaped backslash does not join.
        let input = "cat <<EOF\nfoo\\\nEOF\nEOF\necho after";
        assert_eq!(here_document_body(input, &top_redirections(input)[0]), "foo\\\nEOF\n");
        let input = "cat <<EOF\nfoo\\\\\nEOF\necho after";
        assert_eq!(here_document_body(input, &top_redirections(input)[0]), "foo\\\\\n");
        let input = "cat <<'EOF'\nfoo\\\nEOF\necho after";
        assert_eq!(here_document_body(input, &top_redirections(input)[0]), "foo\\\n");
        // The delimiter may end the input without a newline, and may be empty.
        let input = "cat <<EOF\nx\nEOF";
        assert_eq!(here_document_body(input, &top_redirections(input)[0]), "x\n");
        let input = "cat <<''\nx\n\necho after";
        assert_eq!(here_document_body(input, &top_redirections(input)[0]), "x\n");
        assert_eq!(deep_names(input), ["cat", "echo"]);
    }

    #[test]
    fn refuses_heredocs_bash_versions_read_differently() {
        // Bash 3.2 closes `$( … )` at a `)` in a here-document body, and runs the lines after `$(cat <<EOF)`.
        for input in [
            "echo $(cat <<EOF\na)b\nEOF\n)",
            "echo $(cat <<EOF\ndon't\nEOF\n)",
            "echo $(cat <<EOF)\nhi\nEOF",
            "cat <<EOF; echo $(a\nb)\nbody\nEOF",
            "cat <(cat <<EOF\n$x\nEOF\n)",
        ] {
            assert!(
                matches!(
                    parse(input),
                    Err(ParseError::Lex(LexError::AmbiguousHereDocument { .. }))
                ),
                "{input:?}"
            );
        }
        // A plain body inside a substitution is read the same by every version.
        assert_eq!(deep_names("echo $(cat <<EOF\nplain text\nEOF\n)"), ["echo", "cat"]);
        // So is any here-document inside backticks, whose body bash parses afresh.
        assert_eq!(deep_names("echo `cat <<EOF\na)b\nEOF\n`"), ["echo", "cat"]);
    }

    #[test]
    fn refuses_dash_heredoc_substitution_running_onto_a_tab_indented_line() {
        // FR-LC-02: bash strips the tabs before it reads the substitution, so `\tX` ends the inner here-document and
        // runs `X` (bash 3.2 checked); read with its tabs, the body would hide `X`.
        assert!(matches!(
            parse("cat <<-O\n$(cat <<X\n\tX\nX\n)\nO\n"),
            Err(ParseError::Lex(LexError::AmbiguousHereDocument { .. }))
        ));
        assert!(matches!(
            parse("cat <<-O\n`cat <<X\n\tX\nX\n`\nO\n"),
            Err(ParseError::Lex(LexError::AmbiguousHereDocument { .. }))
        ));
        // Indented one-line substitutions and `<<` bodies are unaffected.
        assert_eq!(deep_names("cat <<-O\n\t$(a)\n\t`b`\n\tO\n"), ["cat", "a", "b"]);
        assert_eq!(deep_names("cat <<O\n$(a\n\tb)\nO\n"), ["cat", "a", "b"]);
    }

    #[test]
    fn heredoc_backtick_keeps_backslash_before_double_quote() {
        // FR-LC-02: a here-document body is not double-quoted text for its backticks; bash 3.2 keeps `\"` there and
        // runs `echo HIDDEN` here, unlike inside "…".
        let input = "cat <<EOF\n`echo \\\"; echo HIDDEN; \\\"`\nEOF\n";
        assert_eq!(deep_names(input), ["cat", "echo", "echo", "\\\""]);
        let input = "echo \"`echo \\\"; echo x; \\\"`\"";
        assert_eq!(deep_names(input), ["echo", "echo"]);
    }

    #[test]
    fn refuses_heredoc_delimiters_with_expansions() {
        for input in ["cat <<$EOF\nx\n$EOF", "cat <<\"$(x)\"\nx\n$(x)", "cat <<$'E'\nx\nE"] {
            assert!(
                matches!(
                    parse(input),
                    Err(ParseError::Lex(LexError::HereDocumentDelimiter { .. }))
                ),
                "{input:?}"
            );
        }
    }

    #[test]
    fn shift_inside_arithmetic_command_is_not_a_heredoc() {
        // `(( … ))` is opaque; a `<<` in it is a shift, but its "body" would hide the next lines, so those are refused.
        assert!(parse("(( x << 2 ))").is_ok());
        assert!(matches!(
            parse("(( x << y ))\nrm -rf /\ny\n"),
            Err(ParseError::Unsupported {
                construct: UnsupportedConstruct::OpaqueHereDocument,
                ..
            })
        ));
    }

    #[test]
    fn refuses_substitutions_hidden_in_expansions() {
        // `${x:-$(rm f)}` and `$(( $(a) ))` run commands the lexer keeps inside the expansion.
        for input in [
            "echo ${x:-$(rm f)}",
            "echo \"${x:-`rm f`}\"",
            "echo $(( $(a) + 1 ))",
            "echo $[`a`]",
        ] {
            assert_eq!(
                unsupported(input),
                UnsupportedConstruct::SubstitutionInExpansion,
                "{input:?}"
            );
        }
        assert!(parse("echo ${x:-default} $((1 + 2))").is_ok());
    }

    #[test]
    fn errors_inside_substitutions_point_into_the_line() {
        // A syntax error inside a substitution is the line's error.
        let input = "echo $(if)";
        let error = parse(input).unwrap_err();
        assert_eq!(text(input, error.span().unwrap()), "if");
        // Inside an un-escaped backtick body, the span is mapped back onto the line.
        let input = r"echo `a \$(b`";
        let error = parse(input).unwrap_err();
        assert!(matches!(error, ParseError::Lex(LexError::Unterminated { .. })));
        assert_eq!(text(input, error.span().unwrap()), "$(b");
        let input = r"echo `fi \`x\``";
        assert_eq!(text(input, parse(input).unwrap_err().span().unwrap()), "fi");
    }

    #[test]
    fn substitution_nesting_is_bounded() {
        // KNSH-032: the lexer's quote and substitution depth and the parser's list depth carry into substitutions.
        let nested = |depth: usize| format!("{}x{}", "$(".repeat(depth), ")".repeat(depth));
        assert!(parse(&nested(MAX_NESTING_DEPTH)).is_ok());
        assert!(matches!(
            parse(&nested(MAX_NESTING_DEPTH + 1)),
            Err(ParseError::Lex(LexError::NestingTooDeep { .. }))
        ));
        // Backtick bodies are not lexed with the line, so the limit must hold when they are parsed.
        let input = format!("`{}`", nested(MAX_NESTING_DEPTH));
        assert!(matches!(
            parse(&input),
            Err(ParseError::Lex(LexError::NestingTooDeep { .. }))
        ));
        // Lists nested through substitutions count towards the list depth.
        let input = format!(
            "{}x{}",
            "$({ ".repeat(MAX_NESTING_DEPTH),
            "; })".repeat(MAX_NESTING_DEPTH)
        );
        assert!(matches!(
            parse(&input),
            Err(ParseError::NestingTooDeep { .. } | ParseError::Lex(LexError::NestingTooDeep { .. }))
        ));
    }

    #[test]
    fn calls_inside_substitutions_are_never_marked() {
        // The body runs in a child shell parsed under conditions the line does not show: resolved as a program.
        let script = parse("x=$(f() { :; }; f)").unwrap();
        assert!(script.simple_commands().all(|command| command.function_call.is_none()));
        // A definition inside a substitution does not reach the line either.
        let script = parse("echo $(f() { :; }); f").unwrap();
        assert!(script.simple_commands().all(|command| command.function_call.is_none()));
    }

    #[test]
    fn unescapes_backticks_like_bash() {
        let unescape = |body: &str, quoted: bool| unescape_backtick(body, quoted, None).into_owned();
        assert_eq!(unescape(r"a \$b \`c\` \\ \x", false), r"a $b `c` \ \x");
        // `\"` is un-escaped only inside double quotes (bash 3.2: "`echo \"hi\"`" prints hi).
        assert_eq!(unescape(r#"echo \"hi\""#, false), r#"echo \"hi\""#);
        assert_eq!(unescape(r#"echo \"hi\""#, true), r#"echo "hi""#);
        // A line continuation goes entirely; `\\` then `$` is an escaped backslash before a plain `$`.
        assert_eq!(unescape("a\\\nb \\\\$x é\\", false), "ab \\$x é\\");
        let mut origins = Vec::new();
        let text = unescape_backtick(r"a\$b", false, Some(&mut origins));
        assert_eq!(text, "a$b");
        assert_eq!(origins, [0, 2, 3]);
    }

    /// The text of each word of the single simple command `line`, read with `extglob` on.
    fn extglob_words(line: &str) -> Vec<String> {
        let script = parse_with(line, ParseOptions::default().with_extglob(true)).unwrap();
        let command = script.simple_commands().next().unwrap();
        command
            .words
            .iter()
            .map(|word| line[word.span.range()].to_owned())
            .collect()
    }

    // KNSH-098: with `extglob` on, a group is part of its word, as in `bash -O extglob`; off, it is bash's syntax
    // error.
    #[test]
    fn extglob_groups_are_words_only_when_the_option_is_on() {
        assert_eq!(
            extglob_words("ls @(a|b).rs !(*.o) x+(1|2)y ?(a) *(b|'c d')"),
            ["ls", "@(a|b).rs", "!(*.o)", "x+(1|2)y", "?(a)", "*(b|'c d')"]
        );
        // Nested groups, blanks and operators inside a group, and a group in a `case` pattern.
        assert_eq!(extglob_words("ls @(a|@(b c;d))"), ["ls", "@(a|@(b c;d))"]);
        let script = parse_with("case x in @(a|b)) y;; esac", ParseOptions::default().with_extglob(true)).unwrap();
        assert_eq!(script.simple_commands().count(), 1);
        // A `(` after anything else still ends the word.
        assert!(parse_with("ls a(b)", ParseOptions::default().with_extglob(true)).is_err());
        assert!(parse("ls @(a|b)").is_err());
        assert!(matches!(
            parse_with("ls @(a|b", ParseOptions::default().with_extglob(true)),
            Err(ParseError::Lex(LexError::Unterminated {
                construct: crate::error::Construct::ExtglobGroup,
                ..
            }))
        ));
        // `(( … ))` still closes where bash closes it when a `*(` or `!(` in it reads as a group.
        for line in [
            "(( 2*(3+1) ))",
            "(( !(0) ))",
            "(( (1)*(2) ))",
            "for ((i=0; i<2*(3); i++)); do x; done",
        ] {
            let script = parse_with(line, ParseOptions::default().with_extglob(true)).unwrap();
            assert!(
                matches!(&script.items[0].and_or.first.first, Command::Unsupported(u) if u.arithmetic.is_some()),
                "{line}"
            );
        }
        // Inside a command substitution the option still applies.
        assert!(parse_with("echo $(ls @(a|b))", ParseOptions::default().with_extglob(true)).is_ok());
    }
}
