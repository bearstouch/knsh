//! Strict JSON (I-JSON profile) reader and writer and the length-prefixed frame codec.
//!
//! Reads and writes the strict JSON profile used on every engine socket, and encodes and decodes frames.
//!
//! # Boundaries
//!
//! No workspace or third-party dependencies. Input is untrusted: size limits are checked before allocating and
//! malformed input is rejected, never repaired.
//!
//! # Specification
//!
//! - `specs/06-api/wire-format.md` (strict JSON profile)
//! - `specs/06-api/handshake.md` (additive protocol: unknown fields are ignored)
//! - `specs/02-architecture/implementation.md`
//! - `specs/07-testing/fuzzing.md`
//! - `specs/06-api/wire-format.md#frames-unix-sockets` (frame codec)
//! - NFR-SEC-05, NFR-SEC-06, NFR-SEC-07, NFR-SUP-06
//!
//! # Strict JSON (KNSH-003)
//!
//! - [`parse`] accepts only the strict profile: valid UTF-8, no unpaired surrogates, no duplicate keys (compared
//!   after unescaping), integers within ±2^53, at most [`MAX_DEPTH`] levels, no comments, trailing commas,
//!   `NaN`/`Infinity`, leading zeros, raw control characters or trailing data. Input above the caller's limit is
//!   refused before it is read. Every rejection is a typed [`JsonError`] for which
//!   [`JsonError::is_parse_error`] holds (`-32700` in `knsh-proto`); the reader never recovers.
//! - [`Value`], [`Object`] and [`Number`] can only hold strict-profile data: objects keep insertion order and refuse
//!   duplicate keys, integers outside ±2^53 cannot become numbers (use [`IntString`] / [`Value::int_string`]),
//!   and non-integer numbers are kept as their exact decimal text rather than rounded through `f64`.
//! - [`write()`] emits compact JSON that [`parse`] reads back to an equal value.
//! - [`ToJson`], [`FromJson`] and [`Fields`] replace `serde` for hand-written protocol structs.
//!
//! # Frames and binary streams (KNSH-004)
//!
//! - [`FrameReader`] reads length-prefixed frames (`specs/06-api/wire-format.md#frames-unix-sockets`) from any
//!   [`std::io::Read`]: the 4-byte length is checked against [`MAX_PAYLOAD`] before anything else is read or
//!   allocated (NFR-SEC-07); unknown types, JSON off stream 0, binary frames on stream 0 or on a stream not opened
//!   through [`FrameReader::open_stream`], streams that break their declared size, and input ending inside a frame
//!   or an open stream are all fatal ([`JsonError::is_fatal`]). Interleaved streams are delivered chunk by chunk
//!   with their [`StreamId`].
//! - [`FrameWriter`] writes frames to any [`std::io::Write`], splitting binary data into chunks of at most
//!   [`MAX_PAYLOAD`] bytes.
//! - [`base64_encode`], [`base64_decode`] and [`Base64Bytes`] carry raw bytes inside JSON for clients that declared
//!   in `hello` that they cannot handle binary frames (`specs/06-api/handshake.md`).

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod base64;
mod convert;
mod error;
mod frame;
mod number;
mod read;
mod value;
mod write;

pub use base64::{Base64Bytes, base64_decode, base64_encode};
pub use convert::{Fields, FromJson, IntString, ToJson};
pub use error::{FrameReason, JsonError, Kind, ParseReason};
pub use frame::{Frame, FrameReader, FrameWriter, MAX_OPEN_STREAMS, MAX_PAYLOAD, StreamId};
pub use number::{MAX_SAFE_INTEGER, Number};
pub use read::{MAX_DEPTH, parse};
pub use value::{Object, Value};
pub use write::write;
