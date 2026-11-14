//! The crate's error types: [`LexError`] for the lexer and [`ParseError`], which wraps it, for the parser, and
//! [`InterpreterTableError`] for interpreter entries a profile adds (KNSH-036).
//!
//! Messages never echo the rejected input: command lines may hold paths, hosts or secrets, and errors are recorded
//! and shown to agents (NFR-PRIV-02). Variants carry spans and limits, never text taken from the input. The
//! interpreter table's errors name the profile entry at fault: a profile is configuration, not an agent command line.

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
    /// A here-document (`<<` or `<<-`) whose body never ends: no line matches the delimiter. Bash runs such a line
    /// with a warning; this lexer refuses it (KNSH-031).
    HereDocument,
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
            Self::HereDocument => "here-document",
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
    /// The line produces more than [`MAX_TOKENS`](crate::MAX_TOKENS) tokens, counted over the line and every
    /// substitution body parsed in it. Lexing stops at the first token over the limit, so the token lists never grow
    /// past it (KNSH-032).
    TooManyTokens {
        /// The first token over the limit.
        span: Span,
        /// The limit.
        limit: usize,
    },
    /// A here-document that bash versions read differently (KNSH-031), refused because either reading could hide a
    /// command the other runs. Bash 3.2 (`/bin/bash` on macOS) finds the end of `$( … )`, `<( … )` and `>( … )` by
    /// matching characters, not by reading commands, so for a here-document inside one it does not know where the
    /// body is: a `)`, quote, backslash, `$` or backtick in the body (or its delimiter line) can close the
    /// substitution or open a quote there, and the line that follows a here-document operator written inside one but
    /// ended outside it (`$(cat <<EOF)`) is run as commands. Later versions read such bodies as here-documents. A
    /// newline inside a substitution while a here-document outside it still waits for its body is refused the same
    /// way, and so is a substitution in an unquoted `<<-` body that runs onto a line starting with a tab: bash strips
    /// the tab before it reads the substitution, which this parser reads with its tabs.
    AmbiguousHereDocument {
        /// The here-document operator (`<<` or `<<-`).
        span: Span,
    },
    /// A here-document delimiter word holding an expansion or an ANSI-C or locale quote (`<<$EOF`, `<<"$(x)"`,
    /// `<<$'E'`). Bash compares body lines with the delimiter's text after quote removal, never expanding it; this
    /// lexer reads only delimiters made of plain text, escapes, single quotes and double quotes holding plain text,
    /// and refuses the others rather than guess where the body ends (KNSH-031).
    HereDocumentDelimiter {
        /// The delimiter word.
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
            | Self::TooManyTokens { span, .. }
            | Self::AmbiguousHereDocument { span }
            | Self::HereDocumentDelimiter { span }
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
            Self::TooManyTokens { span, limit } => {
                write!(f, "command line has more than {limit} tokens, at byte {}", span.start)
            }
            Self::AmbiguousHereDocument { span } => {
                write!(
                    f,
                    "here-document at byte {} is read differently by bash versions",
                    span.start
                )
            }
            Self::HereDocumentDelimiter { span } => {
                write!(
                    f,
                    "here-document delimiter at byte {} holds an expansion, which is not supported",
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
    /// Valid bash that this parser does not read yet and whose extent it cannot find with confidence. The line is
    /// refused rather than read partly (decision 6: anything the parser cannot read is dynamic). Constructs outside
    /// decision 6 whose extent is certain (`select`, `[[ … ]]`, `(( … ))`) are not errors but
    /// [`Command::Unsupported`](crate::Command::Unsupported) nodes, so the rest of the line is still read.
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
    /// A here-document whose body never starts: the input (or the substitution holding the operator) ends before a
    /// newline does. Bash reads an empty body with a warning; the line is refused instead (KNSH-031: a missing
    /// delimiter is an error).
    MissingHereDocumentBody {
        /// The here-document operator (`<<` or `<<-`).
        span: Span,
    },
    /// The line ends inside a compound command or function definition (`if a; then b`, `{ a;`, `for x in a`), so
    /// the word or operator that closes it never comes. Bash reports an unexpected end of file.
    Unclosed {
        /// The reserved word or operator that opened the construct left open.
        span: Span,
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
            | Self::MissingHereDocumentBody { span }
            | Self::UnexpectedToken { span, .. }
            | Self::Unsupported { span, .. }
            | Self::NestingTooDeep { span, .. }
            | Self::Unclosed { span } => Some(*span),
        }
    }

    /// The same error with its span passed through `map`, used to move an error found in an un-escaped backtick body
    /// back onto the line.
    pub(crate) fn map_span(self, map: impl Fn(Span) -> Span) -> Self {
        match self {
            Self::Lex(error) => Self::Lex(match error {
                LexError::InputTooLarge { .. } => error,
                LexError::Unterminated { construct, span } => LexError::Unterminated {
                    construct,
                    span: map(span),
                },
                LexError::NestingTooDeep { span, limit } => LexError::NestingTooDeep { span: map(span), limit },
                LexError::TooManyTokens { span, limit } => LexError::TooManyTokens { span: map(span), limit },
                LexError::AmbiguousHereDocument { span } => LexError::AmbiguousHereDocument { span: map(span) },
                LexError::HereDocumentDelimiter { span } => LexError::HereDocumentDelimiter { span: map(span) },
                LexError::AmbiguousComment { span } => LexError::AmbiguousComment { span: map(span) },
            }),
            Self::MissingCommand { span } => Self::MissingCommand { span: map(span) },
            Self::MissingRedirectionTarget { span } => Self::MissingRedirectionTarget { span: map(span) },
            Self::MissingHereDocumentBody { span } => Self::MissingHereDocumentBody { span: map(span) },
            Self::UnexpectedToken { token, span } => Self::UnexpectedToken { token, span: map(span) },
            Self::Unsupported { construct, span } => Self::Unsupported {
                construct,
                span: map(span),
            },
            Self::NestingTooDeep { span, limit } => Self::NestingTooDeep { span: map(span), limit },
            Self::Unclosed { span } => Self::Unclosed { span: map(span) },
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
            Self::MissingHereDocumentBody { span } => {
                write!(f, "missing body for the here-document at byte {}", span.start)
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
            Self::Unclosed { span } => {
                write!(f, "compound command opened at byte {} is not closed", span.start)
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

/// Valid bash constructs [`parse`](crate::parse) does not read exactly: either refused with
/// [`ParseError::Unsupported`] or kept whole as a [`Command::Unsupported`](crate::Command::Unsupported) node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnsupportedConstruct {
    /// A command outside decision 6's exact list. As a [`Command::Unsupported`](crate::Command::Unsupported) node:
    /// `select`, `[[ … ]]`, `(( … ))` and `for (( … ))`, alone or as a function body. As a [`ParseError::Unsupported`]:
    /// `coproc` (dynamic by decision 6) and `time` where bash versions read it differently (after `!` or a pipe, with
    /// no command, or with an option other than `-p`; see [`TimeKeyword`](crate::TimeKeyword)), and a `(( … ))`
    /// that holds a comment, which bash and this parser could close at different places.
    Compound(CompoundStart),
    /// A command substitution, backtick or process substitution inside `${…}`, `$((…))` or `$[…]`
    /// (`${x:-$(rm f)}`). Bash runs it when the expansion is evaluated, but the lexer keeps those bodies whole, so its
    /// commands would not be seen: the line is refused rather than read without them (KNSH-031).
    SubstitutionInExpansion,
    /// A `<<` inside `(( … ))`, `[[ … ]]` or `for (( … ))`, where bash reads a shift or a comparison, followed by a
    /// newline: the lexer took the next lines for a here-document body, which would hide them, so the line is
    /// refused.
    OpaqueHereDocument,
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
            Self::Compound(CompoundStart::Arithmetic) => f.write_str("arithmetic command `((`"),
            Self::Compound(CompoundStart::ArithmeticFor) => f.write_str("arithmetic loop `for ((`"),
            Self::Compound(CompoundStart::ReservedWord(word)) => {
                write!(f, "compound command `{}`", reserved_word_text(*word))
            }
            Self::OpaqueHereDocument => f.write_str("`<<` inside an arithmetic or conditional command"),
            Self::SubstitutionInExpansion => {
                f.write_str("command substitution inside a parameter or arithmetic expansion")
            }
            Self::ArrayAssignment => f.write_str("array assignment"),
            Self::SubscriptAssignment => f.write_str("array element assignment"),
            Self::RedirectionVariable => f.write_str("descriptor variable redirection"),
        }
    }
}

/// What starts a construct reported as [`UnsupportedConstruct::Compound`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompoundStart {
    /// `((`, an arithmetic command.
    Arithmetic,
    /// `for ((`, an arithmetic `for` loop.
    ArithmeticFor,
    /// A reserved word: `select`, `[[`, `coproc` or `time`.
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

/// An interpreter entry a profile adds that the table refuses (KNSH-036). The table is left unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpreterTableError {
    /// The family name is empty, holds `/` or NUL, or ends in a version suffix, so no base name could match it as
    /// written (the family of `python3` is `python`).
    InvalidFamily {
        /// The name as given.
        family: String,
    },
    /// An option is not spelled `-x` or `--name`.
    InvalidOption {
        /// The entry's family.
        family: String,
        /// The option as given.
        option: String,
    },
}

impl fmt::Display for InterpreterTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFamily { family } => {
                write!(
                    f,
                    "interpreter family {family:?} is not a base name without a version suffix"
                )
            }
            Self::InvalidOption { family, option } => {
                write!(
                    f,
                    "interpreter {family:?}: option {option:?} is not spelled -x or --name"
                )
            }
        }
    }
}

impl std::error::Error for InterpreterTableError {}
