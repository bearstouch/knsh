//! The crate's error type.
//!
//! Messages never echo the rejected input: command lines may hold paths, hosts or secrets, and errors are recorded
//! and shown to agents (NFR-PRIV-02). Variants carry spans and limits, never text taken from the input.

use std::fmt;

use crate::token::Span;

/// A delimited construct that can be left open at the end of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Construct {
    /// `'…'`
    SingleQuote,
    /// `"…"`
    DoubleQuote,
    /// `$'…'`
    AnsiCQuote,
    /// `$"…"`
    LocaleQuote,
    /// `` `…` ``
    Backtick,
    /// `$(…)`
    CommandSubstitution,
    /// `<(…)` or `>(…)`
    ProcessSubstitution,
    /// `${…}`
    ParameterExpansion,
    /// `$((…))` or `$[…]`
    ArithmeticExpansion,
}

impl fmt::Display for Construct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SingleQuote => "single quote",
            Self::DoubleQuote => "double quote",
            Self::AnsiCQuote => "ANSI-C quote",
            Self::LocaleQuote => "locale quote",
            Self::Backtick => "backtick substitution",
            Self::CommandSubstitution => "command substitution",
            Self::ProcessSubstitution => "process substitution",
            Self::ParameterExpansion => "parameter expansion",
            Self::ArithmeticExpansion => "arithmetic expansion",
        })
    }
}

/// Why [`lex`](crate::lex) rejected a line. The lexer has no recovery mode: the first problem ends it, and no
/// tokens are returned. Callers treat every error as dynamic code, never as an allow (KNSH-032).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LexError {
    /// The input is longer than [`MAX_INPUT_LEN`](crate::MAX_INPUT_LEN); nothing was read.
    InputTooLarge {
        /// Input length in bytes.
        len: usize,
        /// The limit it exceeds.
        limit: usize,
    },
    /// A quote or substitution is still open at the end of the input. The lexer never guesses where it would end.
    Unterminated {
        /// What is open.
        construct: Construct,
        /// From the opening delimiter to the end of the input.
        span: Span,
    },
    /// Quotes and substitutions are nested deeper than [`MAX_NESTING_DEPTH`](crate::MAX_NESTING_DEPTH). Bounds the
    /// lexer's recursion (CLAUDE.md "Untrusted input").
    NestingTooDeep {
        /// The opening delimiter of the construct that went over the limit.
        span: Span,
        /// The limit.
        limit: usize,
    },
    /// A newline follows a here-document operator, so a here-document body starts there. Bodies are not lexed yet
    /// (KNSH-031); lexing them as commands would misread them, so the line is refused instead.
    HereDocumentBody {
        /// The first here-document operator (`<<` or `<<-`) still waiting for its body.
        span: Span,
    },
    /// A `#` inside `$( … )`, `<( … )` or `>( … )` that bash versions read differently. Bash 4 and later read the
    /// body with the full grammar, so `#` at the start of a token begins a comment. Bash 3.2 (`/bin/bash` on macOS)
    /// starts a comment there only after a blank or a newline, never in a process substitution, and runs the rest
    /// (`$(a;#) b` runs `b`). Taking either reading could hide a command that the other bash runs, so the line is
    /// refused.
    AmbiguousComment {
        /// The `#`.
        span: Span,
    },
}

impl LexError {
    /// The part of the input the error points at, if any.
    #[must_use]
    pub const fn span(&self) -> Option<Span> {
        match self {
            Self::InputTooLarge { .. } => None,
            Self::Unterminated { span, .. }
            | Self::NestingTooDeep { span, .. }
            | Self::HereDocumentBody { span }
            | Self::AmbiguousComment { span } => Some(*span),
        }
    }
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { len, limit } => {
                write!(f, "command line is {len} bytes, over the {limit}-byte limit")
            }
            Self::Unterminated { construct, span } => {
                write!(f, "unterminated {construct} starting at byte {}", span.start)
            }
            Self::NestingTooDeep { span, limit } => {
                write!(
                    f,
                    "quotes and substitutions nested deeper than {limit} levels at byte {}",
                    span.start
                )
            }
            Self::HereDocumentBody { span } => {
                write!(
                    f,
                    "here-document body for the operator at byte {} is not supported yet",
                    span.start
                )
            }
            Self::AmbiguousComment { span } => {
                write!(
                    f,
                    "comment at byte {} inside a substitution is read differently by bash versions",
                    span.start
                )
            }
        }
    }
}

impl std::error::Error for LexError {}
