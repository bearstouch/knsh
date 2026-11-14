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
//! # Boundaries
//!
//! No workspace or third-party dependencies, no I/O, no global state, no `unsafe`. Input is untrusted (NFR-SEC-05):
//! its size is checked before it is read ([`MAX_INPUT_LEN`]), recursion is bounded ([`MAX_NESTING_DEPTH`]), the first
//! problem ends the lex with a [`LexError`] (never a guess), and the lexer is fuzzed (`fuzz/`, target `bash_lex`). A
//! parser result is an intent filter, never a security boundary.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/command-lifecycle.md` (FR-LC-02: parse the whole line with a bash grammar)
//! - `specs/09-reference/decisions.md` (decision 6: parser scope for phase 2)
//! - `specs/04-non-functional-requirements/security.md` (NFR-SEC-05: memory-safe, fuzzed parsers)
//! - `specs/02-architecture/implementation.md`
//! - `specs/07-testing/conformance.md`

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod error;
mod lex;
mod limits;
mod token;

pub use error::{Construct, LexError};
pub use lex::lex;
pub use limits::{MAX_INPUT_LEN, MAX_NESTING_DEPTH};
pub use token::{
    IoNumber, Operator, Redirection, RedirectionOperator, ReservedWord, Segment, SegmentKind, Span, Token, TokenKind,
    Word,
};
