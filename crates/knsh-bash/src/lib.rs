//! In-house bash parser and classifier.
//!
//! Parses bash command lines and classifies wrappers, dynamic code and irreversible actions. Anything it cannot read
//! with confidence is classified as dynamic code, so parser gaps fail closed.
//!
//! The first stage is the lexer, [`lex`] (KNSH-028): it turns a whole agent command line into [`Token`]s with exact
//! byte spans, so the supervisor parses every part of the line (FR-LC-02). It reads words with their quoting
//! structure, control and redirection operators, comments, newlines and every quoting form decision 6 puts in scope
//! (single and double quotes, `$'…'`, `$"…"`, backslash escapes, line continuations), and finds the extent of each
//! substitution (`$( … )`, backticks, `${ … }`, `$(( … ))`, `<( … )`) without expanding anything. Reserved words
//! are only marked as candidates; whether they act as such depends on position, which the parser decides.
//!
//! The second stage is the parser, [`parse`] (KNSH-029): it builds a [`Script`] of lists (`;`, `&`, newlines),
//! and-or lists (`&&`, `||`), pipelines (`|`, `|&`, `!`) and simple commands, with the assignments before each
//! command separated from its words and redirections attached wherever they were written. Every node keeps its span,
//! and [`Script::simple_commands`] yields every simple command of the line in source order, so policy sees each part
//! of the line (FR-LC-09). It also reads the compound commands decision 6 makes exact (subshells, `{ }` groups, `if`,
//! `for`, `while`, `until`, `case`) and function definitions (KNSH-030). `simple_commands` descends into every
//! condition, body, case arm and function body, and a call that certainly reaches a function defined earlier in the
//! line is marked ([`SimpleCommand::function_call`]), so it is not resolved as a program. Constructs outside decision
//! 6 whose extent is certain (`select`, `[[ … ]]`, `(( … ))`) are kept whole as [`Command::Unsupported`] nodes; other
//! valid bash that later stories read (here-documents, `coproc`, `time`) is refused with [`ParseError::Unsupported`]
//! rather than read partly.
//!
//! # Boundaries
//!
//! No workspace or third-party dependencies, no I/O, no global state, no `unsafe`. Input is untrusted (NFR-SEC-05):
//! its size is checked before it is read ([`MAX_INPUT_LEN`]), recursion is bounded ([`MAX_NESTING_DEPTH`]), the first
//! problem ends the lex or parse with a [`LexError`] or [`ParseError`] (never a guess), and both stages are fuzzed
//! (`fuzz/`, targets `bash_lex` and `bash_parse`). Callers treat every error as dynamic code, never as an allow
//! (decision 6, KNSH-032). A parser result is an intent filter, never a security boundary.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/command-lifecycle.md` (FR-LC-02: parse the whole line with a bash grammar;
//!   FR-LC-09: policy is evaluated for every part of the line)
//! - `specs/09-reference/decisions.md` (decision 6: parser scope for phase 2)
//! - `specs/04-non-functional-requirements/security.md` (NFR-SEC-05: memory-safe, fuzzed parsers)
//! - `specs/02-architecture/implementation.md`
//! - `specs/07-testing/conformance.md`

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod ast;
mod error;
mod functions;
mod lex;
mod limits;
mod parse;
mod token;

pub use ast::{
    AndOr, AndOrOperator, AndOrPart, Assignment, CaseClause, CaseCommand, CaseTerminator, CaseTerminatorKind, Command,
    CommandWord, CompoundCommand, CompoundKind, ElseClause, ForCommand, ForItems, FunctionCall, FunctionDefinition,
    Group, IfClause, IfCommand, ListItem, LoopBody, LoopCommand, PipeOperator, Pipeline, PipelinePart, Redirect,
    Script, Separator, SeparatorKind, SimpleCommand, Subshell, UnsupportedCommand,
};
pub use error::{CompoundStart, Construct, LexError, ParseError, Unexpected, UnsupportedConstruct};
pub use lex::lex;
pub use limits::{MAX_FUNCTION_DEFINITIONS, MAX_INPUT_LEN, MAX_NESTING_DEPTH};
pub use parse::parse;
pub use token::{
    IoNumber, Operator, Redirection, RedirectionOperator, ReservedWord, Segment, SegmentKind, Span, Token, TokenKind,
    Word,
};
