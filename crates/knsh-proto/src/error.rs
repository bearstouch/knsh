//! The crate error, [`ProtoError`], and the reasons an envelope is invalid, [`EnvelopeFault`].

use std::error::Error;
use std::fmt;

use knsh_json::JsonError;

use crate::error_code::ErrorCode;

/// Why a strict-JSON message is not a valid envelope (`specs/06-api/README.md#envelope`). Each maps to `-32600`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeFault {
    /// The message is a JSON array: batches are not supported, one frame carries one message.
    Batch,
    /// The message is neither an object nor an array.
    NotAnObject,
    /// `jsonrpc` is missing or is not exactly the string `"2.0"`.
    WrongVersion,
    /// The envelope has a member other than `jsonrpc`, `id`, `method`, `params`, `result` and `error`.
    UnknownMember,
    /// `id` is not an integer within ±2^53 or a string of at most [`MAX_ID_LEN`](crate::MAX_ID_LEN) bytes, or is
    /// `null` where a request or success response needs one.
    InvalidId,
    /// `method` is not a string.
    MethodNotString,
    /// `params` is present but neither an object nor an array.
    ParamsNotStructured,
    /// The members do not identify exactly one kind of message: for example both `method` and `result`, both
    /// `result` and `error`, `params` on a response, or none of `method`, `result` and `error`.
    Ambiguous,
    /// A response has no `id` member.
    MissingId,
    /// `error` is not an object with an integer `code`, a string `message` and an optional `data`, and nothing else.
    InvalidErrorObject,
    /// `error.code` is an integer that is not one of [`ErrorCode`].
    UnknownErrorCode,
}

impl fmt::Display for EnvelopeFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Batch => "batches are not supported",
            Self::NotAnObject => "message is not an object",
            Self::WrongVersion => "jsonrpc is not \"2.0\"",
            Self::UnknownMember => "unknown envelope member",
            Self::InvalidId => "invalid id",
            Self::MethodNotString => "method is not a string",
            Self::ParamsNotStructured => "params is neither an object nor an array",
            Self::Ambiguous => "message kind is ambiguous",
            Self::MissingId => "response without id",
            Self::InvalidErrorObject => "malformed error object",
            Self::UnknownErrorCode => "unknown error code",
        })
    }
}

/// Every way reading or writing a JSON-RPC message can fail. [`ProtoError::code`] gives the code to answer with.
///
/// The variants carry only values from our own code (field names, reasons), never text from the input, so an error
/// can be logged or displayed without reflecting untrusted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    /// The message is not strict-profile JSON (`-32700`). Holds the reader's error.
    Parse(JsonError),
    /// The message is strict JSON but not a valid envelope (`-32600`).
    InvalidRequest(EnvelopeFault),
    /// The method name is malformed or names no method (`-32601`).
    MethodNotFound,
    /// `params` does not fit the method (`-32602`). Holds the conversion error naming the field.
    InvalidParams(JsonError),
    /// Building or writing an outgoing message failed (`-32603`).
    Encode(JsonError),
}

impl ProtoError {
    /// The JSON-RPC code this error is answered with.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Parse(_) => ErrorCode::ParseError,
            Self::InvalidRequest(_) => ErrorCode::InvalidRequest,
            Self::MethodNotFound => ErrorCode::MethodNotFound,
            Self::InvalidParams(_) => ErrorCode::InvalidParams,
            Self::Encode(_) => ErrorCode::InternalError,
        }
    }
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) | Self::InvalidParams(error) | Self::Encode(error) => {
                write!(f, "{}: {error}", self.code().meaning())
            }
            Self::InvalidRequest(fault) => write!(f, "{}: {fault}", self.code().meaning()),
            Self::MethodNotFound => f.write_str(self.code().meaning()),
        }
    }
}

impl Error for ProtoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(error) | Self::InvalidParams(error) | Self::Encode(error) => Some(error),
            Self::InvalidRequest(_) | Self::MethodNotFound => None,
        }
    }
}
