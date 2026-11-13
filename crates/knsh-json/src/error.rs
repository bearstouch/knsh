//! The crate's single error type.
//!
//! Messages never echo the rejected input: JSON frames come from untrusted processes and may carry secrets, and
//! errors are logged and sent back over the wire (NFR-PRIV-02). Variants carry byte offsets, limits and field names
//! taken from our own code, never text taken from the input.

use std::fmt;

/// Why the strict reader rejected its input. Wrapped in [`JsonError::Parse`] together with a byte offset.
///
/// Every reason is a strict-profile violation (`specs/06-api/wire-format.md#strict-json-profile`): `knsh-proto`
/// maps all of them to the JSON-RPC parse error `-32700`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseReason {
    /// The input is not valid UTF-8.
    InvalidUtf8,
    /// The input ended in the middle of a value (including empty input).
    UnexpectedEnd,
    /// A byte that cannot start or continue a value here: comments, `NaN`, `Infinity`, single quotes, a missing
    /// `,` or `:`, a misspelt literal.
    UnexpectedByte,
    /// A non-whitespace byte after the top-level value.
    TrailingData,
    /// A `,` directly before `]` or `}`.
    TrailingComma,
    /// A number with a superfluous leading zero (`01`, `-00`).
    LeadingZero,
    /// A number that does not follow the RFC 8259 grammar (`-`, `1.`, `.5`, `1e`).
    InvalidNumber,
    /// An integer literal outside ±2^53.
    IntegerOutOfRange,
    /// A raw control character (U+0000 to U+001F) inside a string; it must be escaped.
    ControlCharacter,
    /// An unknown escape (`\x`) or a `\u` escape without four hex digits.
    InvalidEscape,
    /// A `\u` escape for a surrogate that is not part of a high-low pair (`"\ud800"`).
    UnpairedSurrogate,
    /// An object with the same key twice, compared after unescaping (NFR-SEC-06).
    DuplicateKey,
    /// More than [`MAX_DEPTH`](crate::MAX_DEPTH) levels of nested arrays and objects.
    TooDeep,
}

/// Why the frame codec refused a frame or a stream operation. Wrapped in [`JsonError::Frame`].
///
/// Every reason is a framing violation (`specs/06-api/wire-format.md#frames-unix-sockets`): the byte stream can no
/// longer be trusted to be in step with the peer, so the connection must close ([`JsonError::is_fatal`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameReason {
    /// The length prefix is smaller than the type byte plus the stream ID, so the frame has no room for its header.
    TooShort,
    /// The input ended in the middle of a frame (after the first byte of its length prefix).
    Truncated,
    /// The type byte is not `0x01` (JSON), `0x02` (binary chunk) or `0x03` (end of stream).
    UnknownType,
    /// A JSON frame named a stream other than 0.
    JsonOnStream,
    /// A binary chunk or end-of-stream frame named stream 0, which is reserved for JSON messages.
    StreamZero,
    /// An end-of-stream frame carried a payload; it must be empty.
    EndWithPayload,
    /// A binary chunk or end-of-stream frame named a stream that is not open: never opened, or already ended.
    UnknownStream,
    /// A stream was opened while a stream with the same ID was still open.
    StreamAlreadyOpen,
    /// Opening one more stream would exceed [`MAX_OPEN_STREAMS`](crate::MAX_OPEN_STREAMS).
    TooManyStreams,
    /// A stream carried more bytes than the size its opening message declared, or ended with fewer.
    LengthMismatch,
}

/// The JSON type a conversion expected, reported by [`JsonError::WrongType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool,
    /// Any number.
    Number,
    /// A number whose value is an integer within the range of the target type.
    Integer,
    /// A string.
    String,
    /// An array.
    Array,
    /// An object.
    Object,
}

/// Every way reading, building, writing or converting JSON can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    /// The input was larger than the caller's limit; it was rejected before any parsing or allocation.
    InputTooLarge {
        /// Length of the input, in bytes.
        len: usize,
        /// The caller's limit, in bytes.
        limit: usize,
    },
    /// The strict reader rejected the input. It never attempts recovery.
    Parse {
        /// Byte offset in the input where the problem was detected.
        offset: usize,
        /// What was wrong.
        reason: ParseReason,
    },
    /// [`Object::insert`](crate::Object::insert) was given a key the object already holds.
    DuplicateKey,
    /// An integer outside ±2^53 was given where a JSON number is built; send it as a string instead
    /// ([`IntString`](crate::IntString)).
    IntegerOutOfRange,
    /// [`Number::decimal`](crate::Number::decimal) was given text that is not a JSON number with a fraction or an
    /// exponent.
    InvalidDecimal,
    /// The writer was given a value nested deeper than [`MAX_DEPTH`](crate::MAX_DEPTH), which no strict reader
    /// would accept.
    TooDeep,
    /// A required object field was absent.
    MissingField(&'static str),
    /// A value had the wrong JSON type. `field` names the object field when the value was one.
    WrongType {
        /// The field holding the value, if it was read through [`Fields`](crate::Fields).
        field: Option<&'static str>,
        /// The type that was expected.
        expected: Kind,
    },
    /// An integer had the right type but did not fit the target Rust type.
    OutOfRange {
        /// The field holding the value, if it was read through [`Fields`](crate::Fields).
        field: Option<&'static str>,
    },
    /// A closed object ([`Fields::finish_closed`](crate::Fields::finish_closed)) held a field the reader does not
    /// know. The name is not reported because it comes from untrusted input.
    UnknownField,
    /// A frame's payload exceeds the limit. Detected from the length prefix alone, before any memory is allocated
    /// for the payload (NFR-SEC-07). Fatal: the connection must close.
    ///
    /// [`FrameWriter::write_json`](crate::FrameWriter::write_json) also returns it for an oversized message,
    /// before writing anything; that writer stays usable, so closing is merely the safe default there.
    FrameTooLarge {
        /// Payload length the frame declared (or the writer was given), in bytes.
        len: usize,
        /// The payload limit, in bytes ([`MAX_PAYLOAD`](crate::MAX_PAYLOAD)).
        limit: usize,
    },
    /// The frame codec refused a frame or a stream operation. Fatal: the connection must close.
    Frame(FrameReason),
    /// Reading or writing the underlying transport failed. Only the error kind is kept, so the error stays `Copy`
    /// and carries no text from the operating system. Fatal: the connection must close.
    Io(std::io::ErrorKind),
    /// A base64 string (the fallback for clients without binary frames) was not canonical standard base64 with
    /// padding.
    InvalidBase64,
}

impl JsonError {
    /// Whether this error came from the strict reader, so that `knsh-proto` answers with the JSON-RPC parse error
    /// `-32700` (`specs/06-api/wire-format.md#strict-json-profile`). The other variants come from building or
    /// converting values (`-32602` or an internal error, decided by `knsh-proto`).
    #[must_use]
    pub const fn is_parse_error(&self) -> bool {
        match self {
            Self::InputTooLarge { .. } | Self::Parse { .. } => true,
            Self::DuplicateKey
            | Self::IntegerOutOfRange
            | Self::InvalidDecimal
            | Self::TooDeep
            | Self::MissingField(_)
            | Self::WrongType { .. }
            | Self::OutOfRange { .. }
            | Self::UnknownField
            | Self::FrameTooLarge { .. }
            | Self::Frame(_)
            | Self::Io(_)
            | Self::InvalidBase64 => false,
        }
    }

    /// Whether the connection must close: the frame codec refused the byte stream or the transport failed, so the
    /// next byte can no longer be trusted to start a frame (`specs/06-api/wire-format.md#frames-unix-sockets`,
    /// NFR-SEC-07). Every other error concerns one message and leaves the connection usable.
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        match self {
            Self::FrameTooLarge { .. } | Self::Frame(_) | Self::Io(_) => true,
            Self::InputTooLarge { .. }
            | Self::Parse { .. }
            | Self::DuplicateKey
            | Self::IntegerOutOfRange
            | Self::InvalidDecimal
            | Self::TooDeep
            | Self::MissingField(_)
            | Self::WrongType { .. }
            | Self::OutOfRange { .. }
            | Self::UnknownField
            | Self::InvalidBase64 => false,
        }
    }

    /// Attaches a field name to a type or range error that does not name one yet. Errors from nested values keep
    /// the innermost field name, which is the most precise.
    pub(crate) const fn in_field(self, name: &'static str) -> Self {
        match self {
            Self::WrongType { field: None, expected } => Self::WrongType {
                field: Some(name),
                expected,
            },
            Self::OutOfRange { field: None } => Self::OutOfRange { field: Some(name) },
            other => other,
        }
    }
}

impl fmt::Display for ParseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidUtf8 => "invalid UTF-8",
            Self::UnexpectedEnd => "unexpected end of input",
            Self::UnexpectedByte => "unexpected character",
            Self::TrailingData => "trailing data after the value",
            Self::TrailingComma => "trailing comma",
            Self::LeadingZero => "number with a leading zero",
            Self::InvalidNumber => "malformed number",
            Self::IntegerOutOfRange => "integer outside ±2^53",
            Self::ControlCharacter => "unescaped control character in string",
            Self::InvalidEscape => "invalid escape sequence",
            Self::UnpairedSurrogate => "unpaired surrogate escape",
            Self::DuplicateKey => "duplicate object key",
            Self::TooDeep => "nesting deeper than 32 levels",
        })
    }
}

impl fmt::Display for FrameReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooShort => "frame length shorter than its header",
            Self::Truncated => "input ended in the middle of a frame",
            Self::UnknownType => "unknown frame type",
            Self::JsonOnStream => "JSON frame on a stream other than 0",
            Self::StreamZero => "binary frame on stream 0",
            Self::EndWithPayload => "end-of-stream frame with a payload",
            Self::UnknownStream => "frame for a stream that is not open",
            Self::StreamAlreadyOpen => "stream is already open",
            Self::TooManyStreams => "too many open streams",
            Self::LengthMismatch => "stream length differs from the declared size",
        })
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Null => "null",
            Self::Bool => "boolean",
            Self::Number => "number",
            Self::Integer => "integer",
            Self::String => "string",
            Self::Array => "array",
            Self::Object => "object",
        })
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { len, limit } => write!(f, "JSON input of {len} bytes exceeds the {limit}-byte limit"),
            Self::Parse { offset, reason } => write!(f, "invalid JSON at byte {offset}: {reason}"),
            Self::DuplicateKey => f.write_str("object already holds this key"),
            Self::IntegerOutOfRange => f.write_str("integer outside ±2^53 must be sent as a string"),
            Self::InvalidDecimal => f.write_str("not a JSON number with a fraction or exponent"),
            Self::TooDeep => f.write_str("value nested deeper than 32 levels"),
            Self::MissingField(name) => write!(f, "missing field `{name}`"),
            Self::WrongType {
                field: Some(name),
                expected,
            } => write!(f, "field `{name}` must be {expected}"),
            Self::WrongType { field: None, expected } => write!(f, "value must be {expected}"),
            Self::OutOfRange { field: Some(name) } => write!(f, "field `{name}` is out of range"),
            Self::OutOfRange { field: None } => f.write_str("value is out of range"),
            Self::UnknownField => f.write_str("object has an unknown field"),
            Self::FrameTooLarge { len, limit } => {
                write!(f, "frame payload of {len} bytes exceeds the {limit}-byte limit")
            }
            Self::Frame(reason) => write!(f, "invalid frame: {reason}"),
            Self::Io(kind) => write!(f, "transport error: {kind}"),
            Self::InvalidBase64 => f.write_str("invalid base64"),
        }
    }
}

impl std::error::Error for JsonError {}
