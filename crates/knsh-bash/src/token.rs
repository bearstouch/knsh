//! Tokens produced by [`lex`](crate::lex): byte spans, words with their quoting structure, operators and
//! redirections.
//!
//! Every token and every segment carries a [`Span`] into the input. Token spans tile the input with no gap or overlap,
//! and the segments of a word tile the word's span, so nothing in the line can hide between tokens (FR-LC-02: the
//! whole line is seen). Spans always start and end on UTF-8 character boundaries.

use std::ops::Range;

/// A half-open byte range `start..end` into the lexed input.
///
/// Invariant (for spans produced by the lexer): `start <= end <= input.len()`, and both ends fall on character
/// boundaries, so [`Span::text`] always succeeds on the input the span came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    /// Offset of the first byte.
    pub start: usize,
    /// Offset one past the last byte.
    pub end: usize,
}

impl Span {
    /// The span `start..end`.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Length in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether the span covers no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// The span as a `Range`, for slicing.
    #[must_use]
    pub const fn range(self) -> Range<usize> {
        self.start..self.end
    }

    /// The text this span covers in `source`, or `None` if the span does not fit `source` (it came from another
    /// input).
    #[must_use]
    pub fn text(self, source: &str) -> Option<&str> {
        source.get(self.range())
    }
}

/// One token of a command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// What the token is.
    pub kind: TokenKind,
    /// Where it is. For a redirection with a file-descriptor number, this includes the number (`2>`).
    pub span: Span,
}

/// The kinds of token.
///
/// Whitespace and comments are tokens too, so that the spans of all tokens concatenate to the input exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    /// A word, with its quoting structure.
    Word(Word),
    /// A control operator.
    Operator(Operator),
    /// A redirection operator, with its optional file-descriptor number. The target is the next word token.
    Redirection(Redirection),
    /// A newline that ends a command (`\n` outside any quote, substitution or comment).
    Newline,
    /// Spaces, tabs and line continuations (`\` newline) between tokens.
    Blank,
    /// A comment, from `#` up to (not including) the next newline. `#` starts a comment only where a word could
    /// start: `a#b` is one word, `a #b` is a word and a comment.
    Comment,
}

/// A control operator.
///
/// `{` and `}` are not operators in bash but reserved words (`echo {}` is one word), so they arrive as words marked
/// [`ReservedWord::LeftBrace`] and [`ReservedWord::RightBrace`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operator {
    /// `|`
    Pipe,
    /// `|&` (bash 4: pipes standard error too)
    PipeAmpersand,
    /// `||`
    Or,
    /// `&&`
    And,
    /// `&`
    Background,
    /// `;`
    Semicolon,
    /// `;;` (ends a `case` item)
    DoubleSemicolon,
    /// `;&` (bash 4: `case` fall-through)
    SemicolonAmpersand,
    /// `;;&` (bash 4: `case` continue matching)
    DoubleSemicolonAmpersand,
    /// `(`
    LeftParen,
    /// `)`
    RightParen,
}

/// A redirection: the operator and the file-descriptor number written before it, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Redirection {
    /// The number before the operator, as in `2>&1`. `None` when the operator is written alone.
    pub fd: Option<IoNumber>,
    /// The operator.
    pub operator: RedirectionOperator,
}

/// A file-descriptor number written directly before a redirection operator (`2` in `2>file`).
///
/// A word is a file-descriptor number when it is made only of unquoted digits and the next character is `<` or
/// `>`, as in bash; `"2">file` and `a2>file` are words followed by a redirection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IoNumber {
    /// Where the digits are (line continuations inside the number included).
    pub span: Span,
    /// The number, or `None` when it exceeds the largest descriptor bash accepts (`i32::MAX`). Bash 3.2 reports such
    /// a number as an error when the command runs; it never becomes an argument.
    pub value: Option<u32>,
}

/// A redirection operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedirectionOperator {
    /// `<`
    Input,
    /// `>`
    Output,
    /// `>>`
    Append,
    /// `>|` (overwrite even with `noclobber`)
    Clobber,
    /// `<>`
    ReadWrite,
    /// `<<` (here-document)
    HereDocument,
    /// `<<-` (here-document with leading tabs stripped)
    HereDocumentStripTabs,
    /// `<<<` (here-string)
    HereString,
    /// `<&` (duplicate an input descriptor, or close it with `-`)
    DuplicateInput,
    /// `>&` (duplicate an output descriptor, or close it with `-`; `>&word` without a number also redirects
    /// standard error)
    DuplicateOutput,
    /// `&>` (standard output and standard error)
    OutputAll,
    /// `&>>` (bash 4: append standard output and standard error)
    AppendAll,
}

/// A word: a run of characters with no unquoted metacharacter, split into [`Segment`]s by quoting form.
///
/// The segments tile the token's span in order. Nothing is expanded or unquoted here (expansion semantics belong to
/// later stages); each segment says which form it is and where its body is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    /// The parts of the word, in source order.
    pub segments: Vec<Segment>,
    /// Set when the word is spelled exactly like a reserved word with no quoting (`if`, `{`, `!`). It is only a
    /// candidate: whether it acts as a reserved word depends on its position, which the parser decides.
    pub reserved: Option<ReservedWord>,
}

/// One quoting or expansion form inside a word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The form.
    pub kind: SegmentKind,
    /// The whole segment, delimiters included (`'abc'`, `$(cmd)`).
    pub span: Span,
    /// The text between the delimiters (`abc`, `cmd`); for an escape, the escaped character; for a parameter, its
    /// name; for a literal, the same as `span`; for a line continuation, an empty span at its end. Inside expansion
    /// bodies, line continuations are kept as written.
    pub body: Span,
}

/// The quoting and expansion forms a word is made of (decision 6: every quoting form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentKind {
    /// Characters taken literally: unquoted text, or plain text inside double quotes (where a backslash that escapes
    /// nothing is literal too).
    Literal,
    /// `\c`: a backslash and the one character it quotes. A backslash at the very end of the input has an empty body.
    Escape,
    /// `\` followed by a newline, which bash removes before reading the line (`ec\` newline `ho` is `echo`).
    LineContinuation,
    /// `'…'`: every character literal, no escapes.
    SingleQuoted,
    /// `$'…'`: ANSI-C quoting, where backslash escapes such as `\n` and `\x41` are decoded.
    AnsiC,
    /// `"…"`, with the segments inside it (literals, escapes, parameters, substitutions).
    DoubleQuoted(Vec<Segment>),
    /// `$"…"`: double quotes translated through the locale, with the segments inside it.
    Locale(Vec<Segment>),
    /// `$name`, `$1`, or a special parameter such as `$@`, `$?` or `$$`.
    Parameter,
    /// `${…}`.
    ParameterExpansion,
    /// `$(…)`: the body is a command line, to be parsed recursively.
    CommandSubstitution,
    /// `` `…` ``: the body is a command line with backslash escapes, to be un-escaped and parsed recursively.
    Backtick,
    /// `$((…))` or the legacy `$[…]`.
    Arithmetic,
    /// `<(…)`: the body is a command line whose output is read as a file.
    InputProcessSubstitution,
    /// `>(…)`: the body is a command line whose input is written as a file.
    OutputProcessSubstitution,
}

impl SegmentKind {
    /// Whether this is unquoted text as bash reads it before expansion: a literal, or a line continuation (which bash
    /// removes before tokenising). Reserved words and file-descriptor numbers must be spelled only with these.
    pub(crate) const fn is_unquoted_text(&self) -> bool {
        match self {
            Self::Literal | Self::LineContinuation => true,
            Self::Escape
            | Self::SingleQuoted
            | Self::AnsiC
            | Self::DoubleQuoted(_)
            | Self::Locale(_)
            | Self::Parameter
            | Self::ParameterExpansion
            | Self::CommandSubstitution
            | Self::Backtick
            | Self::Arithmetic
            | Self::InputProcessSubstitution
            | Self::OutputProcessSubstitution => false,
        }
    }
}

/// The reserved words of bash, which the lexer marks as candidates on unquoted words spelled exactly like them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReservedWord {
    /// `!`
    Bang,
    /// `{`
    LeftBrace,
    /// `}`
    RightBrace,
    /// `[[`
    DoubleLeftBracket,
    /// `]]`
    DoubleRightBracket,
    /// `case`
    Case,
    /// `coproc`
    Coproc,
    /// `do`
    Do,
    /// `done`
    Done,
    /// `elif`
    Elif,
    /// `else`
    Else,
    /// `esac`
    Esac,
    /// `fi`
    Fi,
    /// `for`
    For,
    /// `function`
    Function,
    /// `if`
    If,
    /// `in`
    In,
    /// `select`
    Select,
    /// `then`
    Then,
    /// `time`
    Time,
    /// `until`
    Until,
    /// `while`
    While,
}

impl ReservedWord {
    /// The longest reserved word, in bytes (`function`); longer words are never looked up.
    pub(crate) const MAX_LEN: usize = 8;

    /// The reserved word spelled `text`, if any.
    #[must_use]
    pub fn from_text(text: &[u8]) -> Option<Self> {
        Some(match text {
            b"!" => Self::Bang,
            b"{" => Self::LeftBrace,
            b"}" => Self::RightBrace,
            b"[[" => Self::DoubleLeftBracket,
            b"]]" => Self::DoubleRightBracket,
            b"case" => Self::Case,
            b"coproc" => Self::Coproc,
            b"do" => Self::Do,
            b"done" => Self::Done,
            b"elif" => Self::Elif,
            b"else" => Self::Else,
            b"esac" => Self::Esac,
            b"fi" => Self::Fi,
            b"for" => Self::For,
            b"function" => Self::Function,
            b"if" => Self::If,
            b"in" => Self::In,
            b"select" => Self::Select,
            b"then" => Self::Then,
            b"time" => Self::Time,
            b"until" => Self::Until,
            b"while" => Self::While,
            _ => return None,
        })
    }

    /// Whether the word after this one (used as a reserved word) starts a command, as after `then` or `!`. Used only
    /// to find where a `case` inside `$( … )` begins and ends, so that its `)` patterns do not close the
    /// substitution. `in` counts so that `esac` right after `case x in` is seen.
    pub(crate) const fn starts_command(self) -> bool {
        match self {
            Self::Bang
            | Self::LeftBrace
            | Self::Do
            | Self::Elif
            | Self::Else
            | Self::If
            | Self::In
            | Self::Then
            | Self::Time
            | Self::Until
            | Self::While => true,
            Self::RightBrace
            | Self::DoubleLeftBracket
            | Self::DoubleRightBracket
            | Self::Case
            | Self::Coproc
            | Self::Done
            | Self::Esac
            | Self::Fi
            | Self::For
            | Self::Function
            | Self::Select => false,
        }
    }
}
