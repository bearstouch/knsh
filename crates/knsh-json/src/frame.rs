//! The length-prefixed frame codec and binary stream demultiplexer.
//!
//! Layout (`specs/06-api/wire-format.md#frames-unix-sockets`), all integers big-endian:
//!
//! | Part | Size | Content |
//! | --- | --- | --- |
//! | Length | 4 bytes | size of type + stream ID + payload |
//! | Type | 1 byte | `0x01` JSON message, `0x02` binary chunk, `0x03` end of stream |
//! | Stream ID | 4 bytes | 0 for JSON; the stream a JSON message opened for chunks and end of stream |
//! | Payload | ≤ [`MAX_PAYLOAD`] | UTF-8 JSON, raw bytes, or nothing (end of stream) |
//!
//! The peer is untrusted, so the reader:
//!
//! - reads the 4-byte length on its own and refuses an oversized frame before reading or allocating anything else
//!   (NFR-SEC-07);
//! - checks the type and stream ID before allocating the payload;
//! - accepts binary frames only for streams the protocol layer opened ([`FrameReader::open_stream`]) after reading
//!   the JSON message that announced them, and checks the size that message declared;
//! - treats every violation, transport error and end of input inside a frame or an open stream as fatal
//!   ([`JsonError::is_fatal`]): the connection must close. After one, every later read fails the same way, so a
//!   caller cannot resynchronise on bytes that may be attacker-chosen.
//!
//! Both halves work on any blocking [`Read`] or [`Write`]: short reads and interrupted calls are retried, and
//! nothing is buffered internally (wrap the transport in a `BufReader`/`BufWriter` if wanted). A non-blocking
//! transport that returns [`std::io::ErrorKind::WouldBlock`] mid-frame is reported as a fatal error.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::num::NonZeroU32;

use crate::convert::{FromJson, ToJson};
use crate::error::{FrameReason, JsonError};
use crate::value::Value;
use crate::write::write;

/// Largest payload a frame may carry: 1 MB (2^20 bytes). The length prefix may be up to [`MAX_PAYLOAD`] + 5,
/// because it also counts the type byte and the stream ID.
pub const MAX_PAYLOAD: usize = 1 << 20;

/// Most binary streams a [`FrameReader`] keeps open at once. Each open stream costs a little memory, and the
/// messages that open them come from the peer, so the count is bounded.
pub const MAX_OPEN_STREAMS: usize = 256;

/// Bytes of the length prefix.
const LENGTH_LEN: usize = 4;
/// Bytes the length prefix counts besides the payload: the type byte and the stream ID.
const PREFIX_LEN: usize = 5;

const TYPE_JSON: u8 = 0x01;
const TYPE_CHUNK: u8 = 0x02;
const TYPE_END: u8 = 0x03;

/// The ID of a binary stream. Never 0: stream 0 is reserved for JSON messages, so a binary frame on stream 0 cannot
/// even be expressed on the write side.
///
/// The ID travels in the JSON message that opens the stream, and is read and written there through [`FromJson`]
/// and [`ToJson`] (a JSON integer from 1 to 2^32 - 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(NonZeroU32);

impl StreamId {
    /// The stream with this wire ID, or `None` for 0, which is reserved for JSON messages.
    #[must_use]
    pub const fn new(id: u32) -> Option<Self> {
        match NonZeroU32::new(id) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    /// The wire ID, never 0.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl ToJson for StreamId {
    fn to_json(&self) -> Result<Value, JsonError> {
        self.get().to_json()
    }
}

impl FromJson for StreamId {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        Self::new(u32::from_json(value)?).ok_or(JsonError::OutOfRange { field: None })
    }
}

/// One decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A JSON message (stream 0). The payload is not parsed here: the protocol layer parses it with
    /// [`parse`](crate::parse) and [`MAX_PAYLOAD`]. A parse error there is not a framing error: the reader stays
    /// usable, and the protocol layer decides what follows (`knshd` answers `-32700` and closes, KNSH-013).
    Json(Vec<u8>),
    /// A piece of a binary stream. Chunks of different streams may interleave; chunks of one stream arrive in
    /// order.
    Chunk {
        /// The stream the bytes belong to.
        stream: StreamId,
        /// The bytes; possibly empty.
        data: Vec<u8>,
    },
    /// The end of a binary stream: no more chunks follow, and the stream is closed.
    End {
        /// The stream that ended.
        stream: StreamId,
    },
}

/// Reads frames and demultiplexes binary streams, enforcing every framing rule.
///
/// The protocol layer reads a [`Frame::Json`], and if that message opens a stream, calls
/// [`open_stream`](Self::open_stream) before reading the next frame. Chunks and end-of-stream frames for any other
/// stream are fatal.
///
/// # Example
///
/// ```
/// use knsh_json::{Frame, FrameReader, FrameWriter, StreamId, Value};
///
/// let stream = StreamId::new(7).unwrap();
/// let mut wire = FrameWriter::new(Vec::new());
/// wire.write_json(&Value::from("opens stream 7"))?;
/// wire.write_chunk(stream, b"raw bytes")?;
/// wire.write_end(stream)?;
///
/// let bytes = wire.into_inner();
/// let mut reader = FrameReader::new(bytes.as_slice());
/// assert!(matches!(reader.read_frame()?, Some(Frame::Json(_))));
/// reader.open_stream(stream, Some(9))?;
/// assert_eq!(reader.read_frame()?, Some(Frame::Chunk { stream, data: b"raw bytes".to_vec() }));
/// assert_eq!(reader.read_frame()?, Some(Frame::End { stream }));
/// assert_eq!(reader.read_frame()?, None);
/// # Ok::<(), knsh_json::JsonError>(())
/// ```
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    streams: BTreeMap<StreamId, StreamState>,
    /// The first fatal error. Once set, every read returns it without touching the transport.
    failed: Option<JsonError>,
}

/// Progress of one open stream.
#[derive(Debug, Clone, Copy)]
struct StreamState {
    /// Size the opening message declared, if it declared one.
    declared: Option<u64>,
    /// Bytes received so far.
    received: u64,
}

impl<R: Read> FrameReader<R> {
    /// A reader over `inner` with no open streams.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            streams: BTreeMap::new(),
            failed: None,
        }
    }

    /// Opens `stream`, as announced by the JSON message just read. `declared_len` is the size that message
    /// declared, if any: the stream must then carry exactly that many bytes.
    ///
    /// An ID may be reused once its earlier stream has ended.
    ///
    /// # Errors
    ///
    /// Fatal [`JsonError::Frame`] errors: [`FrameReason::StreamAlreadyOpen`] if the stream is open, and
    /// [`FrameReason::TooManyStreams`] if [`MAX_OPEN_STREAMS`] are open. Also the earlier fatal error, if one
    /// occurred.
    pub fn open_stream(&mut self, stream: StreamId, declared_len: Option<u64>) -> Result<(), JsonError> {
        self.check_failed()?;
        let result = if self.streams.contains_key(&stream) {
            Err(JsonError::Frame(FrameReason::StreamAlreadyOpen))
        } else if self.streams.len() >= MAX_OPEN_STREAMS {
            Err(JsonError::Frame(FrameReason::TooManyStreams))
        } else {
            self.streams.insert(
                stream,
                StreamState {
                    declared: declared_len,
                    received: 0,
                },
            );
            Ok(())
        };
        self.remember(result)
    }

    /// Whether `stream` is open: opened and not yet ended.
    #[must_use]
    pub fn is_open(&self, stream: StreamId) -> bool {
        self.streams.contains_key(&stream)
    }

    /// Reads the next frame. Returns `None` when the input ends cleanly: between frames, with no stream open.
    ///
    /// # Errors
    ///
    /// Every error is fatal ([`JsonError::is_fatal`]); the connection must close, and every later call returns the
    /// same error:
    ///
    /// - [`JsonError::FrameTooLarge`]: the length prefix announces a payload over [`MAX_PAYLOAD`]. Nothing past
    ///   the 4-byte length has been read or allocated (NFR-SEC-07).
    /// - [`JsonError::Frame`]: [`FrameReason::TooShort`], [`FrameReason::UnknownType`],
    ///   [`FrameReason::JsonOnStream`], [`FrameReason::StreamZero`] or [`FrameReason::EndWithPayload`] for a
    ///   malformed frame; [`FrameReason::UnknownStream`] for a chunk or end on a stream that is not open;
    ///   [`FrameReason::LengthMismatch`] when a stream exceeds or falls short of its declared size;
    ///   [`FrameReason::Truncated`] when the input ends inside a frame or with a stream still open.
    /// - [`JsonError::Io`]: the transport failed.
    pub fn read_frame(&mut self) -> Result<Option<Frame>, JsonError> {
        self.check_failed()?;
        let result = self.read_and_track();
        self.remember(result)
    }

    /// Returns the transport, dropping the stream state.
    pub fn into_inner(self) -> R {
        self.inner
    }

    fn read_and_track(&mut self) -> Result<Option<Frame>, JsonError> {
        let Some(frame) = decode(&mut self.inner)? else {
            // A clean end between frames still truncates any stream the peer has not ended.
            return if self.streams.is_empty() {
                Ok(None)
            } else {
                Err(JsonError::Frame(FrameReason::Truncated))
            };
        };
        match &frame {
            Frame::Json(_) => {}
            Frame::Chunk { stream, data } => {
                let state = self
                    .streams
                    .get_mut(stream)
                    .ok_or(JsonError::Frame(FrameReason::UnknownStream))?;
                let len = u64::try_from(data.len()).map_err(|_| JsonError::Frame(FrameReason::LengthMismatch))?;
                state.received = state
                    .received
                    .checked_add(len)
                    .ok_or(JsonError::Frame(FrameReason::LengthMismatch))?;
                // Refuse the first byte past the declared size rather than waiting for the end of the stream.
                if state.declared.is_some_and(|declared| state.received > declared) {
                    return Err(JsonError::Frame(FrameReason::LengthMismatch));
                }
            }
            Frame::End { stream } => {
                let state = self
                    .streams
                    .remove(stream)
                    .ok_or(JsonError::Frame(FrameReason::UnknownStream))?;
                if state.declared.is_some_and(|declared| state.received != declared) {
                    return Err(JsonError::Frame(FrameReason::LengthMismatch));
                }
            }
        }
        Ok(Some(frame))
    }

    fn check_failed(&self) -> Result<(), JsonError> {
        self.failed.map_or(Ok(()), Err)
    }

    /// Records a fatal error so the reader stays failed.
    fn remember<T>(&mut self, result: Result<T, JsonError>) -> Result<T, JsonError> {
        if let Err(error) = &result {
            self.failed = Some(*error);
        }
        result
    }
}

/// Writes frames. Never emits a frame that a [`FrameReader`] would refuse on layout grounds: JSON is checked
/// against [`MAX_PAYLOAD`] before anything is written, binary data is split into chunks of at most
/// [`MAX_PAYLOAD`] bytes, and [`StreamId`] cannot be 0.
///
/// Opening streams is the caller's job: write the JSON message that announces a stream before its chunks.
///
/// After a transport error a frame may be half written, so every later call fails with the same error.
#[derive(Debug)]
pub struct FrameWriter<W> {
    inner: W,
    /// The first transport error. Once set, nothing more is written.
    failed: Option<JsonError>,
}

impl<W: Write> FrameWriter<W> {
    /// A writer over `inner`.
    pub fn new(inner: W) -> Self {
        Self { inner, failed: None }
    }

    /// Writes `value` as compact strict-profile JSON in one JSON frame.
    ///
    /// # Errors
    ///
    /// [`JsonError::TooDeep`] from the JSON writer and [`JsonError::FrameTooLarge`] if the JSON exceeds
    /// [`MAX_PAYLOAD`]; in both cases nothing is written and the writer stays usable. [`JsonError::Io`] if the
    /// transport fails.
    pub fn write_json(&mut self, value: &Value) -> Result<(), JsonError> {
        self.check_failed()?;
        let text = write(value)?;
        if text.len() > MAX_PAYLOAD {
            return Err(JsonError::FrameTooLarge {
                len: text.len(),
                limit: MAX_PAYLOAD,
            });
        }
        self.write_frame(TYPE_JSON, 0, text.as_bytes())
    }

    /// Writes `data` to `stream` as one or more binary chunks of at most [`MAX_PAYLOAD`] bytes. Writes nothing
    /// for empty `data`.
    ///
    /// # Errors
    ///
    /// [`JsonError::Io`] if the transport fails.
    pub fn write_chunk(&mut self, stream: StreamId, data: &[u8]) -> Result<(), JsonError> {
        self.check_failed()?;
        for piece in data.chunks(MAX_PAYLOAD) {
            self.write_frame(TYPE_CHUNK, stream.get(), piece)?;
        }
        Ok(())
    }

    /// Writes the end-of-stream frame for `stream`.
    ///
    /// # Errors
    ///
    /// [`JsonError::Io`] if the transport fails.
    pub fn write_end(&mut self, stream: StreamId) -> Result<(), JsonError> {
        self.check_failed()?;
        self.write_frame(TYPE_END, stream.get(), &[])
    }

    /// Flushes the transport.
    ///
    /// # Errors
    ///
    /// [`JsonError::Io`] if the transport fails.
    pub fn flush(&mut self) -> Result<(), JsonError> {
        self.check_failed()?;
        let result = self.inner.flush().map_err(|error| JsonError::Io(error.kind()));
        self.remember(result)
    }

    /// Returns the transport.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Writes one frame. The caller guarantees `payload.len() <= MAX_PAYLOAD`.
    fn write_frame(&mut self, kind: u8, stream: u32, payload: &[u8]) -> Result<(), JsonError> {
        let length = u32::try_from(PREFIX_LEN + payload.len()).map_err(|_| JsonError::FrameTooLarge {
            len: payload.len(),
            limit: MAX_PAYLOAD,
        })?;
        let mut header = [0u8; LENGTH_LEN + PREFIX_LEN];
        header[..LENGTH_LEN].copy_from_slice(&length.to_be_bytes());
        header[LENGTH_LEN] = kind;
        header[LENGTH_LEN + 1..].copy_from_slice(&stream.to_be_bytes());
        let result = self
            .inner
            .write_all(&header)
            .and_then(|()| self.inner.write_all(payload))
            .map_err(|error| JsonError::Io(error.kind()));
        self.remember(result)
    }

    fn check_failed(&self) -> Result<(), JsonError> {
        self.failed.map_or(Ok(()), Err)
    }

    fn remember(&mut self, result: Result<(), JsonError>) -> Result<(), JsonError> {
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }
}

/// Decodes one frame, checking everything that does not depend on which streams are open. Returns `None` if the
/// input ends before the first byte of a frame.
fn decode<R: Read>(reader: &mut R) -> Result<Option<Frame>, JsonError> {
    // The length alone comes first, and is checked before anything else is read or allocated (NFR-SEC-07).
    let mut length = [0u8; LENGTH_LEN];
    match fill(reader, &mut length)? {
        0 => return Ok(None),
        LENGTH_LEN => {}
        _ => return Err(JsonError::Frame(FrameReason::Truncated)),
    }
    // A u32 always fits a usize on the 64-bit targets the engine supports; saturating keeps an exotic target safe
    // (the payload check below then refuses it).
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    let payload_len = length
        .checked_sub(PREFIX_LEN)
        .ok_or(JsonError::Frame(FrameReason::TooShort))?;
    if payload_len > MAX_PAYLOAD {
        return Err(JsonError::FrameTooLarge {
            len: payload_len,
            limit: MAX_PAYLOAD,
        });
    }

    let mut prefix = [0u8; PREFIX_LEN];
    read_exact(reader, &mut prefix)?;
    let [kind, s0, s1, s2, s3] = prefix;
    let stream = u32::from_be_bytes([s0, s1, s2, s3]);
    // Type and stream ID are checked before the payload is allocated, so a malformed frame costs no memory.
    let binary_stream = || StreamId::new(stream).ok_or(JsonError::Frame(FrameReason::StreamZero));
    let shape = match kind {
        TYPE_JSON if stream == 0 => Shape::Json,
        TYPE_JSON => return Err(JsonError::Frame(FrameReason::JsonOnStream)),
        TYPE_CHUNK => Shape::Chunk(binary_stream()?),
        TYPE_END => {
            let stream = binary_stream()?;
            // End of stream has nothing left to read, so it is complete without touching the transport again.
            return if payload_len == 0 {
                Ok(Some(Frame::End { stream }))
            } else {
                Err(JsonError::Frame(FrameReason::EndWithPayload))
            };
        }
        _ => return Err(JsonError::Frame(FrameReason::UnknownType)),
    };

    let mut payload = vec![0u8; payload_len];
    read_exact(reader, &mut payload)?;
    Ok(Some(match shape {
        Shape::Json => Frame::Json(payload),
        Shape::Chunk(stream) => Frame::Chunk { stream, data: payload },
    }))
}

/// A frame whose header has been validated and whose payload is still to be read.
enum Shape {
    Json,
    Chunk(StreamId),
}

/// Reads exactly `buf.len()` bytes; the input ending first means the frame was cut short.
fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), JsonError> {
    if fill(reader, buf)? == buf.len() {
        Ok(())
    } else {
        Err(JsonError::Frame(FrameReason::Truncated))
    }
}

/// Reads until `buf` is full or the input ends, retrying short reads and interrupted calls. Returns the number of
/// bytes read, which is less than `buf.len()` only at the end of the input.
fn fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, JsonError> {
    let mut filled = 0;
    while let Some(rest) = buf.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        match reader.read(rest) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(JsonError::Io(error.kind())),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn id(n: u32) -> StreamId {
        StreamId::new(n).unwrap()
    }

    /// One raw frame, bypassing the writer's checks.
    fn raw(kind: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(PREFIX_LEN + payload.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        out.push(kind);
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn fatal(reason: FrameReason) -> JsonError {
        JsonError::Frame(reason)
    }

    /// Serves a 4-byte length prefix and fails the test if anything past it is requested.
    struct HeaderOnly {
        header: [u8; LENGTH_LEN],
        served: bool,
    }

    impl Read for HeaderOnly {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(!self.served, "reader asked for bytes past the length prefix");
            assert!(buf.len() <= LENGTH_LEN, "reader asked for {} bytes at once", buf.len());
            buf.copy_from_slice(&self.header[..buf.len()]);
            self.served = true;
            Ok(buf.len())
        }
    }

    /// Hands out one byte per call, with an interruption before each.
    struct Trickle<'a> {
        data: &'a [u8],
        interrupt: bool,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let Some((&first, rest)) = self.data.split_first() else {
                return Ok(0);
            };
            buf[0] = first;
            self.data = rest;
            Ok(1)
        }
    }

    #[test]
    fn rejects_oversized_frame_before_allocating() {
        // NFR-SEC-07: the length alone decides; nothing past it is read, so no payload buffer can exist.
        let limit = u32::try_from(PREFIX_LEN + MAX_PAYLOAD).unwrap();
        for length in [limit + 1, u32::MAX] {
            let mut reader = FrameReader::new(HeaderOnly {
                header: length.to_be_bytes(),
                served: false,
            });
            let error = reader.read_frame().unwrap_err();
            assert_eq!(
                error,
                JsonError::FrameTooLarge {
                    len: usize::try_from(length).unwrap() - PREFIX_LEN,
                    limit: MAX_PAYLOAD
                }
            );
            assert!(error.is_fatal());
            // The reader stays failed without touching the transport again (HeaderOnly would panic).
            assert_eq!(reader.read_frame(), Err(error));
        }
    }

    #[test]
    fn accepts_payload_of_exactly_the_limit() {
        let data = vec![0xa5; MAX_PAYLOAD];
        let bytes = raw(TYPE_CHUNK, 1, &data);
        let mut reader = FrameReader::new(bytes.as_slice());
        reader.open_stream(id(1), None).unwrap();
        assert_eq!(reader.read_frame().unwrap(), Some(Frame::Chunk { stream: id(1), data }));
    }

    #[test]
    fn rejects_length_shorter_than_header() {
        for length in 0..u32::try_from(PREFIX_LEN).unwrap() {
            let bytes = length.to_be_bytes();
            assert_eq!(
                FrameReader::new(bytes.as_slice()).read_frame(),
                Err(fatal(FrameReason::TooShort))
            );
        }
    }

    #[test]
    fn json_frame_requires_stream_zero() {
        let bytes = raw(TYPE_JSON, 1, b"{}");
        let mut reader = FrameReader::new(bytes.as_slice());
        reader.open_stream(id(1), None).unwrap();
        assert_eq!(reader.read_frame(), Err(fatal(FrameReason::JsonOnStream)));

        // And binary frames may never use stream 0.
        for kind in [TYPE_CHUNK, TYPE_END] {
            let bytes = raw(kind, 0, b"");
            assert_eq!(
                FrameReader::new(bytes.as_slice()).read_frame(),
                Err(fatal(FrameReason::StreamZero))
            );
        }
    }

    #[test]
    fn binary_chunk_for_unknown_stream_is_fatal() {
        // Never opened.
        let bytes = raw(TYPE_CHUNK, 9, b"data");
        let mut reader = FrameReader::new(bytes.as_slice());
        let error = reader.read_frame().unwrap_err();
        assert_eq!(error, fatal(FrameReason::UnknownStream));
        assert!(error.is_fatal());

        // Already ended.
        let mut bytes = raw(TYPE_END, 9, b"");
        bytes.extend(raw(TYPE_CHUNK, 9, b"late"));
        let mut reader = FrameReader::new(bytes.as_slice());
        reader.open_stream(id(9), None).unwrap();
        assert_eq!(reader.read_frame().unwrap(), Some(Frame::End { stream: id(9) }));
        assert!(!reader.is_open(id(9)));
        assert_eq!(reader.read_frame(), Err(fatal(FrameReason::UnknownStream)));

        // An end for a stream that is not open is just as fatal.
        let bytes = raw(TYPE_END, 3, b"");
        assert_eq!(
            FrameReader::new(bytes.as_slice()).read_frame(),
            Err(fatal(FrameReason::UnknownStream))
        );
    }

    #[test]
    fn unknown_frame_type_is_fatal() {
        for kind in [0x00, 0x04, 0xff] {
            let bytes = raw(kind, 0, b"{}");
            let error = FrameReader::new(bytes.as_slice()).read_frame().unwrap_err();
            assert_eq!(error, fatal(FrameReason::UnknownType));
            assert!(error.is_fatal());
        }
    }

    #[test]
    fn end_of_stream_must_be_empty() {
        let bytes = raw(TYPE_END, 1, b"x");
        let mut reader = FrameReader::new(bytes.as_slice());
        reader.open_stream(id(1), None).unwrap();
        assert_eq!(reader.read_frame(), Err(fatal(FrameReason::EndWithPayload)));
    }

    #[test]
    fn interleaved_streams_are_demultiplexed() {
        let mut wire = FrameWriter::new(Vec::new());
        wire.write_json(&Value::from("open 1 and 2")).unwrap();
        wire.write_chunk(id(1), b"one-a ").unwrap();
        wire.write_chunk(id(2), b"two-a ").unwrap();
        wire.write_chunk(id(1), b"one-b").unwrap();
        wire.write_end(id(1)).unwrap();
        wire.write_chunk(id(2), b"two-b").unwrap();
        wire.write_end(id(2)).unwrap();
        let bytes = wire.into_inner();

        let mut reader = FrameReader::new(bytes.as_slice());
        let mut received: HashMap<StreamId, Vec<u8>> = HashMap::new();
        let mut ended = Vec::new();
        while let Some(frame) = reader.read_frame().unwrap() {
            match frame {
                Frame::Json(_) => {
                    reader.open_stream(id(1), Some(11)).unwrap();
                    reader.open_stream(id(2), None).unwrap();
                }
                Frame::Chunk { stream, data } => received.entry(stream).or_default().extend(data),
                Frame::End { stream } => ended.push(stream),
            }
        }
        assert_eq!(received[&id(1)], b"one-a one-b");
        assert_eq!(received[&id(2)], b"two-a two-b");
        assert_eq!(ended, [id(1), id(2)]);
    }

    #[test]
    fn eof_mid_frame_is_error() {
        let mut wire = FrameWriter::new(Vec::new());
        wire.write_json(&Value::from("message")).unwrap();
        let bytes = wire.into_inner();
        // Cutting anywhere inside the frame is an error, never a shorter message; only an empty input is clean.
        assert_eq!(FrameReader::new(&bytes[..0]).read_frame(), Ok(None));
        for cut in 1..bytes.len() {
            assert_eq!(
                FrameReader::new(&bytes[..cut]).read_frame(),
                Err(fatal(FrameReason::Truncated)),
                "cut at {cut}"
            );
        }
        assert!(FrameReader::new(bytes.as_slice()).read_frame().unwrap().is_some());

        // The input ending between frames while a stream is open truncates the stream.
        let bytes = raw(TYPE_CHUNK, 4, b"partial");
        let mut reader = FrameReader::new(bytes.as_slice());
        reader.open_stream(id(4), None).unwrap();
        assert!(reader.read_frame().unwrap().is_some());
        assert_eq!(reader.read_frame(), Err(fatal(FrameReason::Truncated)));
    }

    #[test]
    fn short_reads_and_interruptions_are_retried() {
        let mut wire = FrameWriter::new(Vec::new());
        wire.write_json(&Value::from("slow")).unwrap();
        wire.write_chunk(id(5), b"bytes").unwrap();
        wire.write_end(id(5)).unwrap();
        let bytes = wire.into_inner();

        let mut reader = FrameReader::new(Trickle {
            data: &bytes,
            interrupt: false,
        });
        assert_eq!(reader.read_frame().unwrap(), Some(Frame::Json(br#""slow""#.to_vec())));
        reader.open_stream(id(5), Some(5)).unwrap();
        assert_eq!(
            reader.read_frame().unwrap(),
            Some(Frame::Chunk {
                stream: id(5),
                data: b"bytes".to_vec()
            })
        );
        assert_eq!(reader.read_frame().unwrap(), Some(Frame::End { stream: id(5) }));
        assert_eq!(reader.read_frame().unwrap(), None);
    }

    #[test]
    fn round_trips_json_and_binary_frames() {
        let message = Value::from(
            crate::Object::new()
                .with("method", "records.output")
                .unwrap()
                .with("stream", 3)
                .unwrap(),
        );
        // Larger than one frame, so the writer must split it.
        let big: Vec<u8> = (0..MAX_PAYLOAD + 10).map(|i| u8::try_from(i % 251).unwrap()).collect();

        let mut wire = FrameWriter::new(Vec::new());
        wire.write_json(&message).unwrap();
        wire.write_chunk(id(3), &big).unwrap();
        wire.write_chunk(id(3), b"").unwrap();
        wire.write_end(id(3)).unwrap();
        wire.flush().unwrap();
        let bytes = wire.into_inner();

        let mut reader = FrameReader::new(bytes.as_slice());
        let Some(Frame::Json(payload)) = reader.read_frame().unwrap() else {
            panic!("expected a JSON frame");
        };
        assert_eq!(crate::parse(&payload, MAX_PAYLOAD).unwrap(), message);
        let declared = u64::try_from(big.len()).unwrap();
        reader.open_stream(id(3), Some(declared)).unwrap();

        let mut data = Vec::new();
        let mut chunks = 0;
        loop {
            match reader.read_frame().unwrap() {
                Some(Frame::Chunk { stream, data: piece }) => {
                    assert_eq!(stream, id(3));
                    assert!(piece.len() <= MAX_PAYLOAD);
                    data.extend(piece);
                    chunks += 1;
                }
                Some(Frame::End { stream }) => {
                    assert_eq!(stream, id(3));
                    break;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(chunks, 2, "an empty write must not emit a frame");
        assert_eq!(data, big);
        assert_eq!(reader.read_frame().unwrap(), None);
    }

    #[test]
    fn enforces_declared_stream_length() {
        // More bytes than declared: refused at the chunk that overshoots.
        let bytes = raw(TYPE_CHUNK, 1, b"12345");
        let mut reader = FrameReader::new(bytes.as_slice());
        reader.open_stream(id(1), Some(4)).unwrap();
        assert_eq!(reader.read_frame(), Err(fatal(FrameReason::LengthMismatch)));

        // Fewer bytes than declared: refused at the end of the stream.
        let mut bytes = raw(TYPE_CHUNK, 1, b"123");
        bytes.extend(raw(TYPE_END, 1, b""));
        let mut reader = FrameReader::new(bytes.as_slice());
        reader.open_stream(id(1), Some(4)).unwrap();
        assert!(reader.read_frame().unwrap().is_some());
        assert_eq!(reader.read_frame(), Err(fatal(FrameReason::LengthMismatch)));
    }

    #[test]
    fn bounds_open_streams() {
        let mut reader = FrameReader::new(io::empty());
        reader.open_stream(id(1), None).unwrap();
        assert_eq!(
            reader.open_stream(id(1), None),
            Err(fatal(FrameReason::StreamAlreadyOpen))
        );

        let mut reader = FrameReader::new(io::empty());
        for n in 1..=u32::try_from(MAX_OPEN_STREAMS).unwrap() {
            reader.open_stream(id(n), None).unwrap();
        }
        assert_eq!(
            reader.open_stream(id(100_000), None),
            Err(fatal(FrameReason::TooManyStreams))
        );
    }

    #[test]
    fn reader_stays_failed_after_a_fatal_error() {
        // A valid frame after the bad one must not be delivered: the byte stream is out of step.
        let mut bytes = raw(0x7f, 0, b"");
        bytes.extend(raw(TYPE_JSON, 0, b"{}"));
        let mut reader = FrameReader::new(bytes.as_slice());
        assert_eq!(reader.read_frame(), Err(fatal(FrameReason::UnknownType)));
        assert_eq!(reader.read_frame(), Err(fatal(FrameReason::UnknownType)));
        assert_eq!(reader.open_stream(id(1), None), Err(fatal(FrameReason::UnknownType)));
    }

    #[test]
    fn transport_errors_are_fatal() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::ConnectionReset.into())
            }
        }
        let error = FrameReader::new(Broken).read_frame().unwrap_err();
        assert_eq!(error, JsonError::Io(io::ErrorKind::ConnectionReset));
        assert!(error.is_fatal());
    }

    #[test]
    fn writer_refuses_oversized_json_without_writing() {
        let value = Value::from("x".repeat(MAX_PAYLOAD));
        let mut wire = FrameWriter::new(Vec::new());
        assert!(matches!(wire.write_json(&value), Err(JsonError::FrameTooLarge { .. })));
        assert_eq!(wire.into_inner(), Vec::<u8>::new());
    }

    #[test]
    fn writer_stays_failed_after_a_transport_error() {
        struct Full(usize);
        impl Write for Full {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if self.0 == 0 {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                let n = buf.len().min(self.0);
                self.0 -= n;
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        // Room for the header only: the frame is half written.
        let mut wire = FrameWriter::new(Full(9));
        let broken = JsonError::Io(io::ErrorKind::BrokenPipe);
        assert_eq!(wire.write_chunk(id(1), b"data"), Err(broken));
        assert_eq!(wire.write_end(id(1)), Err(broken));
        assert_eq!(wire.flush(), Err(broken));
    }

    #[test]
    fn stream_id_json_conversion_refuses_zero() {
        assert_eq!(StreamId::from_json(&Value::from(7)).unwrap(), id(7));
        assert_eq!(id(7).to_json().unwrap(), Value::from(7));
        assert!(StreamId::from_json(&Value::from(0)).is_err());
        assert!(StreamId::from_json(&Value::int(i64::from(u32::MAX) + 1).unwrap()).is_err());
        assert_eq!(StreamId::new(0), None);
    }
}
