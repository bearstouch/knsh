//! The crate's single error type.
//!
//! Messages never echo the rejected input: configuration files may hold host names, paths or secret names, and
//! errors are logged and shown to agents (NFR-PRIV-02). Variants carry positions, limits and reasons taken from our
//! own code, never text taken from the input.

use std::fmt;

/// A place in the input: 1-based line and 1-based column, counted in Unicode scalar values (a tab counts as one).
///
/// Lines are separated by `\n` (a `\r\n` pair ends a line too). Every [`Item`](crate::Item) carries the position
/// where its value starts, and every [`TomlError::Parse`] the position where the problem was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position {
    /// Line number, starting at 1.
    pub line: usize,
    /// Column number within the line, starting at 1.
    pub column: usize,
}

impl Position {
    /// The first character of the input.
    pub const START: Self = Self { line: 1, column: 1 };
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}, column {}", self.line, self.column)
    }
}

/// A TOML construct that is valid TOML 1.0 but outside the subset this crate reads. Wrapped in
/// [`Reason::OutsideSubset`].
///
/// The subset is deliberately narrow (crate header): anything a spec example does not need is refused rather than
/// guessed at, and widening it starts in the spec (KNSH-006).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Construct {
    /// An offset or local date-time, local date or local time (`1979-05-27`, `07:32:00`).
    DateTime,
    /// A float, including `inf` and `nan` (`3.14`, `1e6`, `-inf`).
    Float,
    /// A multi-line basic or literal string (`"""…"""`, `'''…'''`).
    MultiLineString,
    /// A hexadecimal, octal or binary integer (`0xff`, `0o755`, `0b1010`).
    NonDecimalInteger,
}

/// Why the parser rejected its input. Wrapped in [`TomlError::Parse`] together with a [`Position`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The input is not valid UTF-8.
    InvalidUtf8,
    /// A control character (other than tab) in a string or comment, or a carriage return not followed by a line
    /// feed.
    ControlCharacter,
    /// A character that cannot start or continue anything here.
    UnexpectedCharacter,
    /// The input ended inside an array, inline table, header or key.
    UnexpectedEnd,
    /// A key is not followed by `=`.
    ExpectedEquals,
    /// A key/value pair or table header is followed by something other than a comment and the end of the line.
    ExpectedEndOfLine,
    /// `=` is followed by the end of the line or of the input instead of a value.
    MissingValue,
    /// A string is not closed before the end of its line or of the input.
    UnterminatedString,
    /// An unknown escape (`\x`, `\e`), a `\u`/`\U` escape without enough hex digits, or one naming a surrogate or a
    /// code point above U+10FFFF.
    InvalidEscape,
    /// An integer with a leading zero, misplaced underscores or other characters that make it no number.
    InvalidInteger,
    /// A decimal integer outside the range of a signed 64-bit integer.
    IntegerOutOfRange,
    /// A `,` directly before the `}` of an inline table (allowed in arrays, not in inline tables).
    TrailingComma,
    /// A line break inside an inline table, which TOML requires on one line.
    NewlineInInlineTable,
    /// A key that is already defined in the same table (NFR-SEC-06's strictness, applied to configuration).
    DuplicateKey,
    /// A table defined twice: a repeated `[header]`, a `[header]` for a table already created by dotted keys, an
    /// inline table or an array of tables, or dotted keys reaching into a table defined by a header.
    TableRedefined,
    /// A key path goes through something that cannot hold more keys: a string, integer, boolean, static array,
    /// inline table (closed once written), or an array of tables reached with dotted keys.
    NotATable,
    /// More than [`MAX_DEPTH`](crate::MAX_DEPTH) levels of nested tables and arrays.
    TooDeep,
    /// A valid TOML construct that this subset does not read.
    OutsideSubset(Construct),
}

/// Every way parsing can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TomlError {
    /// The input was larger than [`MAX_INPUT_LEN`](crate::MAX_INPUT_LEN); it was rejected before any parsing or
    /// allocation.
    InputTooLarge {
        /// Length of the input, in bytes.
        len: usize,
        /// The limit, in bytes.
        limit: usize,
    },
    /// The parser rejected the input. It never attempts recovery and returns no partial result.
    Parse {
        /// Where the problem was detected.
        position: Position,
        /// What was wrong.
        reason: Reason,
    },
}

impl TomlError {
    /// The position of a parse error; `None` for [`TomlError::InputTooLarge`], which is detected before reading.
    #[must_use]
    pub const fn position(&self) -> Option<Position> {
        match self {
            Self::InputTooLarge { .. } => None,
            Self::Parse { position, .. } => Some(*position),
        }
    }
}

impl fmt::Display for Construct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DateTime => "date-time",
            Self::Float => "float",
            Self::MultiLineString => "multi-line string",
            Self::NonDecimalInteger => "hexadecimal, octal or binary integer",
        })
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => f.write_str("invalid UTF-8"),
            Self::ControlCharacter => f.write_str("control character"),
            Self::UnexpectedCharacter => f.write_str("unexpected character"),
            Self::UnexpectedEnd => f.write_str("unexpected end of input"),
            Self::ExpectedEquals => f.write_str("expected `=` after the key"),
            Self::ExpectedEndOfLine => f.write_str("expected the end of the line"),
            Self::MissingValue => f.write_str("missing value"),
            Self::UnterminatedString => f.write_str("unterminated string"),
            Self::InvalidEscape => f.write_str("invalid escape sequence"),
            Self::InvalidInteger => f.write_str("malformed integer"),
            Self::IntegerOutOfRange => f.write_str("integer outside the 64-bit range"),
            Self::TrailingComma => f.write_str("trailing comma in inline table"),
            Self::NewlineInInlineTable => f.write_str("line break inside inline table"),
            Self::DuplicateKey => f.write_str("duplicate key"),
            Self::TableRedefined => f.write_str("table defined more than once"),
            Self::NotATable => f.write_str("key path goes through a value that is not an open table"),
            Self::TooDeep => f.write_str("nesting deeper than 32 levels"),
            Self::OutsideSubset(construct) => write!(f, "{construct} is outside the supported TOML subset"),
        }
    }
}

impl fmt::Display for TomlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { len, limit } => write!(f, "input of {len} bytes exceeds the {limit}-byte limit"),
            Self::Parse { position, reason } => write!(f, "{reason} at {position}"),
        }
    }
}

impl std::error::Error for TomlError {}
