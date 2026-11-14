//! The crate's error types: [`LexError`] for the lexer and [`ParseError`], which wraps it, for the parser.
//!
//! Messages never echo the rejected input: command lines may hold paths, hosts or secrets, and errors are recorded
//! and shown to agents (NFR-PRIV-02). Variants carry spans and limits, never text taken from the input.

use std::fmt;

use crate::token::{Operator, ReservedWord, Span};

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

/// Why [`parse`](crate::parse) rejected a line. Like the lexer, the parser has no recovery mode: the first problem ends
/// it and no tree is returned. Callers treat every error as dynamic code, never as an allow (KNSH-032; decision 6).
///
/// Messages never echo the input: they name fixed operator and reserved-word spellings and byte offsets only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The lexer rejected the line.
    Lex(LexError),
    /// An operator that needs a command after it is at the end of the line (`a &&`, `a |`, `!`).
    MissingCommand {
        /// The operator left dangling.
        span: Span,
    },
    /// A redirection operator has no target word after it (`cmd >`, `cmd > ;`).
    MissingRedirectionTarget {
        /// The redirection operator, with its descriptor number.
        span: Span,
    },
    /// A token that bash reports as a syntax error where it stands (`; a`, `a ;; b`, `then`, `a | ! b`).
    UnexpectedToken {
        /// What the token is.
        token: Unexpected,
        /// Where it is.
        span: Span,
    },
    /// Valid bash that this parser does not read yet. The line is refused rather than read partly (decision 6:
    /// anything the parser cannot read is dynamic).
    Unsupported {
        /// The construct.
        construct: UnsupportedConstruct,
        /// Where it starts.
        span: Span,
    },
    /// Commands are nested deeper than [`MAX_NESTING_DEPTH`](crate::MAX_NESTING_DEPTH). Bounds the parser's
    /// recursion (CLAUDE.md "Untrusted input"; final limits in KNSH-032).
    NestingTooDeep {
        /// Where the construct that went over the limit starts.
        span: Span,
        /// The limit.
        limit: usize,
    },
}

impl ParseError {
    /// The part of the input the error points at, if any.
    #[must_use]
    pub const fn span(&self) -> Option<Span> {
        match self {
            Self::Lex(error) => error.span(),
            Self::MissingCommand { span }
            | Self::MissingRedirectionTarget { span }
            | Self::UnexpectedToken { span, .. }
            | Self::Unsupported { span, .. }
            | Self::NestingTooDeep { span, .. } => Some(*span),
        }
    }
}

impl From<LexError> for ParseError {
    fn from(error: LexError) -> Self {
        Self::Lex(error)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lex(error) => error.fmt(f),
            Self::MissingCommand { span } => {
                write!(f, "missing command after the operator at byte {}", span.start)
            }
            Self::MissingRedirectionTarget { span } => {
                write!(f, "missing target for the redirection at byte {}", span.start)
            }
            Self::UnexpectedToken { token, span } => {
                write!(f, "syntax error near unexpected {token} at byte {}", span.start)
            }
            Self::Unsupported { construct, span } => {
                write!(f, "{construct} at byte {} is not supported yet", span.start)
            }
            Self::NestingTooDeep { span, limit } => {
                write!(f, "commands nested deeper than {limit} levels at byte {}", span.start)
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// The token a [`ParseError::UnexpectedToken`] is about, named without echoing input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unexpected {
    /// A control operator.
    Operator(Operator),
    /// A reserved word in command position that cannot start a command (`then`, `fi`, `}`, a second `!`).
    ReservedWord(ReservedWord),
    /// A word or redirection where none can stand.
    Word,
    /// A newline (`!` followed by a newline).
    Newline,
}

impl fmt::Display for Unexpected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operator(operator) => write!(f, "operator `{}`", operator_text(*operator)),
            Self::ReservedWord(word) => write!(f, "reserved word `{}`", reserved_word_text(*word)),
            Self::Word => f.write_str("word"),
            Self::Newline => f.write_str("newline"),
        }
    }
}

/// Valid bash constructs [`parse`](crate::parse) refuses until a later story reads them exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnsupportedConstruct {
    /// A compound command or other reserved-word construct in command position: `{`, `(`, `if`, `for`, `while`,
    /// `until`, `case`, `select`, `[[`, `function` (KNSH-030), `coproc` (dynamic by decision 6), or `time`.
    Compound(CompoundStart),
    /// `name() …`, a function definition (KNSH-030).
    FunctionDefinition,
    /// `<<` or `<<-`, a here-document (KNSH-031).
    HereDocument,
    /// `name=(…)`, an array assignment.
    ArrayAssignment,
    /// `name[subscript]=value`, an assignment to an array element, or a `name[` where a command starts whose
    /// subscript the word does not close (bash reads it on across blanks and operators: `a[ 1 ]=x cmd`).
    SubscriptAssignment,
    /// `{name}>file`, a redirection that stores a new descriptor in a variable (bash 4.1 and later; bash 3.2 reads
    /// `{name}` as a word).
    RedirectionVariable,
}

impl fmt::Display for UnsupportedConstruct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compound(CompoundStart::Subshell) => f.write_str("subshell `(`"),
            Self::Compound(CompoundStart::ReservedWord(word)) => {
                write!(f, "compound command `{}`", reserved_word_text(*word))
            }
            Self::FunctionDefinition => f.write_str("function definition"),
            Self::HereDocument => f.write_str("here-document"),
            Self::ArrayAssignment => f.write_str("array assignment"),
            Self::SubscriptAssignment => f.write_str("array element assignment"),
            Self::RedirectionVariable => f.write_str("descriptor variable redirection"),
        }
    }
}

/// The token that starts a construct reported as [`UnsupportedConstruct::Compound`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompoundStart {
    /// `(`, a subshell.
    Subshell,
    /// A reserved word that starts a compound command or a timed or coprocess pipeline.
    ReservedWord(ReservedWord),
}

/// The fixed spelling of a control operator.
const fn operator_text(operator: Operator) -> &'static str {
    match operator {
        Operator::Pipe => "|",
        Operator::PipeAmpersand => "|&",
        Operator::Or => "||",
        Operator::And => "&&",
        Operator::Background => "&",
        Operator::Semicolon => ";",
        Operator::DoubleSemicolon => ";;",
        Operator::SemicolonAmpersand => ";&",
        Operator::DoubleSemicolonAmpersand => ";;&",
        Operator::LeftParen => "(",
        Operator::RightParen => ")",
    }
}

/// The fixed spelling of a reserved word.
const fn reserved_word_text(word: ReservedWord) -> &'static str {
    match word {
        ReservedWord::Bang => "!",
        ReservedWord::LeftBrace => "{",
        ReservedWord::RightBrace => "}",
        ReservedWord::DoubleLeftBracket => "[[",
        ReservedWord::DoubleRightBracket => "]]",
        ReservedWord::Case => "case",
        ReservedWord::Coproc => "coproc",
        ReservedWord::Do => "do",
        ReservedWord::Done => "done",
        ReservedWord::Elif => "elif",
        ReservedWord::Else => "else",
        ReservedWord::Esac => "esac",
        ReservedWord::Fi => "fi",
        ReservedWord::For => "for",
        ReservedWord::Function => "function",
        ReservedWord::If => "if",
        ReservedWord::In => "in",
        ReservedWord::Select => "select",
        ReservedWord::Then => "then",
        ReservedWord::Time => "time",
        ReservedWord::Until => "until",
        ReservedWord::While => "while",
    }
}
