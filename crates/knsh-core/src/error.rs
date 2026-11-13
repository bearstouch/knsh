//! The crate's single error type.
//!
//! Messages never echo the rejected input: a path or identifier may come from an untrusted agent line or carry
//! private data, and errors are logged and sent over the wire (NFR-PRIV-02).

use std::fmt;

/// Every way a `knsh-core` constructor or parser can refuse its input.
///
/// Variants carry only positions and lengths, never the offending text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreError {
    /// A ULID string did not have exactly 26 characters. Carries the length that was seen, in bytes.
    UlidLength(usize),
    /// A ULID string held a character outside the uppercase Crockford base32 alphabet. Carries its byte index.
    UlidInvalidChar(usize),
    /// A ULID string's first character was above `7`, so the value would not fit in 128 bits.
    UlidOverflow,
    /// A ULID time was above the 48-bit maximum (`2^48 - 1` milliseconds).
    UlidTimeOutOfRange,
    /// A canonical path was empty.
    PathEmpty,
    /// A canonical path did not start with `/`.
    PathRelative,
    /// A canonical path contained a `.` or `..` component.
    PathDotComponent,
    /// A canonical path contained an empty component (`//`) or a trailing `/`.
    PathEmptyComponent,
    /// A canonical path contained a NUL byte, which no real path can contain.
    PathNul,
    /// A timestamp was outside the range RFC 3339 can express (years 1970 to 9999 here).
    TimestampOutOfRange,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UlidLength(len) => write!(f, "ULID must be 26 characters, got {len}"),
            Self::UlidInvalidChar(index) => write!(f, "ULID has an invalid character at index {index}"),
            Self::UlidOverflow => f.write_str("ULID overflows 128 bits (first character above 7)"),
            Self::UlidTimeOutOfRange => f.write_str("ULID time exceeds 48 bits"),
            Self::PathEmpty => f.write_str("canonical path is empty"),
            Self::PathRelative => f.write_str("canonical path is not absolute"),
            Self::PathDotComponent => f.write_str("canonical path contains a '.' or '..' component"),
            Self::PathEmptyComponent => f.write_str("canonical path contains an empty component or trailing '/'"),
            Self::PathNul => f.write_str("canonical path contains a NUL byte"),
            Self::TimestampOutOfRange => f.write_str("timestamp is outside 1970-01-01 to 9999-12-31 UTC"),
        }
    }
}

impl std::error::Error for CoreError {}
