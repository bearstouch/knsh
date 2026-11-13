//! The properties each fuzz target checks (`specs/07-testing/fuzzing.md`, NFR-SUP-06).
//!
//! Every check takes the raw fuzzer input and panics when a property fails; a panic is what libFuzzer records as a
//! crash. The same functions are replayed on stable Rust, without libFuzzer, by
//! `crates/knsh-json/tests/fuzz_regressions.rs` (which includes this file by path), so a saved crash in
//! `fuzz/regressions/<target>/` stays an ordinary failing test until it is fixed. This file must therefore depend
//! on nothing but `knsh-json` and `std`.
//!
//! What a check cannot see, libFuzzer flags enforce: `frame_reader` runs with `-malloc_limit_mb=2`, so any single
//! allocation above the 1 MB payload limit (plus slack for the harness) is a crash (NFR-SEC-07). See
//! `scripts/fuzz.sh`.

use std::collections::BTreeMap;

use knsh_json::{
    Fields, Frame, FrameReader, FrameReason, JsonError, MAX_DEPTH, MAX_OPEN_STREAMS, MAX_PAYLOAD, MAX_SAFE_INTEGER,
    Number, Object, StreamId, Value, parse, write,
};

/// `json_reader`: the strict reader never panics, rejects only with a parse error (`-32700`), and everything it
/// accepts is valid UTF-8, within the depth limit, and survives a write/parse round trip unchanged. The writer's
/// output is also a fixed point: writing the re-read value gives the same text.
pub fn json_reader(data: &[u8]) {
    let value = match parse(data, MAX_PAYLOAD) {
        Ok(value) => value,
        Err(error) => {
            assert!(
                error.is_parse_error(),
                "reader rejected with a non-parse error: {error:?}"
            );
            return;
        }
    };
    assert!(std::str::from_utf8(data).is_ok(), "reader accepted invalid UTF-8");
    assert!(
        depth(&value) <= MAX_DEPTH,
        "reader accepted nesting deeper than {MAX_DEPTH}"
    );

    let text = write(&value).expect("an accepted value must be writable");
    // Escaping can make the text longer than the input, so the re-read is not held to the frame limit.
    let reread = parse(text.as_bytes(), usize::MAX).expect("the writer's output must be strict JSON");
    assert_eq!(reread, value, "accepted value did not round-trip");
    assert_eq!(
        write(&reread).expect("re-read value must be writable"),
        text,
        "writer output is not canonical"
    );
}

/// `json_writer_roundtrip`: a value built through the public API from fuzzer bytes is either written as strict JSON
/// that reads back equal, or refused with [`JsonError::TooDeep`] exactly when it nests deeper than the profile
/// allows. Covers what the reader-driven target cannot reach easily: raw control characters and unusual code points
/// in strings, integers at the ±2^53 edge, and decimal text accepted by [`Number::decimal`].
pub fn json_writer_roundtrip(data: &[u8]) {
    let value = Builder { data, pos: 0 }.value(0);
    match write(&value) {
        Ok(text) => {
            assert!(
                depth(&value) <= MAX_DEPTH,
                "writer emitted nesting deeper than {MAX_DEPTH}"
            );
            let reread = parse(text.as_bytes(), usize::MAX).expect("the writer's output must be strict JSON");
            assert_eq!(reread, value, "written value did not read back equal");
        }
        Err(JsonError::TooDeep) => assert!(depth(&value) > MAX_DEPTH, "writer refused a value within the limit"),
        Err(error) => panic!("writer failed with {error:?}"),
    }
}

/// `frame_reader`: the reader never panics, and every frame it delivers obeys the framing rules
/// (`specs/06-api/wire-format.md#frames-unix-sockets`) according to an independent model of the open streams:
/// payloads within [`MAX_PAYLOAD`], chunks and ends only for open streams, declared sizes never exceeded and met
/// exactly at the end, a clean end of input only with no stream open. Every error is fatal and sticky.
///
/// The harness plays the protocol layer: a JSON message `{"stream": <id>, "size": <bytes>}` (size optional) opens
/// that stream, so the fuzzer can reach the stream rules and interleaving.
pub fn frame_reader(data: &[u8]) {
    let mut reader = FrameReader::new(data);
    // Stream ID -> (declared size, bytes received so far).
    let mut open: BTreeMap<StreamId, (Option<u64>, u64)> = BTreeMap::new();
    loop {
        let frame = match reader.read_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                assert!(open.is_empty(), "clean end of input with a stream still open");
                return;
            }
            Err(error) => {
                assert_sticky_fatal(&mut reader, error);
                return;
            }
        };
        match frame {
            Frame::Json(payload) => {
                assert!(payload.len() <= MAX_PAYLOAD, "JSON payload over the limit");
                let Some((stream, declared)) = stream_opening(&payload) else {
                    continue;
                };
                // The duplicate check comes first: reopening an open stream is refused even when the table is full.
                let expected = if open.contains_key(&stream) {
                    Err(JsonError::Frame(FrameReason::StreamAlreadyOpen))
                } else if open.len() >= MAX_OPEN_STREAMS {
                    Err(JsonError::Frame(FrameReason::TooManyStreams))
                } else {
                    Ok(())
                };
                let result = reader.open_stream(stream, declared);
                assert_eq!(result, expected, "open_stream disagrees with the model");
                match result {
                    Ok(()) => {
                        open.insert(stream, (declared, 0));
                    }
                    Err(error) => {
                        assert_sticky_fatal(&mut reader, error);
                        return;
                    }
                }
            }
            Frame::Chunk { stream, data } => {
                assert!(data.len() <= MAX_PAYLOAD, "chunk payload over the limit");
                let (declared, received) = open
                    .get_mut(&stream)
                    .expect("chunk delivered for a stream that is not open");
                *received += u64::try_from(data.len()).expect("payload length fits u64");
                assert!(
                    declared.is_none_or(|declared| *received <= declared),
                    "stream exceeded its declared size"
                );
            }
            Frame::End { stream } => {
                let (declared, received) = open
                    .remove(&stream)
                    .expect("end delivered for a stream that is not open");
                assert!(
                    declared.is_none_or(|declared| received == declared),
                    "stream ended short of its size"
                );
            }
        }
    }
}

/// After a fatal error, the reader must refuse everything with the same error, without resynchronising.
fn assert_sticky_fatal(reader: &mut FrameReader<&[u8]>, error: JsonError) {
    assert!(error.is_fatal(), "frame reader returned a non-fatal error: {error:?}");
    assert_eq!(reader.read_frame(), Err(error), "reader did not stay failed");
    let any_stream = StreamId::new(1).expect("1 is a valid stream ID");
    assert_eq!(
        reader.open_stream(any_stream, None),
        Err(error),
        "reader did not stay failed"
    );
}

/// Reads the harness's stream-opening message: an object with an integer `stream` and an optional integer
/// `size`. Anything else is an ordinary message that opens nothing.
fn stream_opening(payload: &[u8]) -> Option<(StreamId, Option<u64>)> {
    let value = parse(payload, MAX_PAYLOAD).ok()?;
    let mut fields = Fields::new(&value).ok()?;
    let stream = fields.required::<StreamId>("stream").ok()?;
    let size = fields.optional::<u64>("size").ok()?;
    Some((stream, size))
}

/// Nesting depth: 0 for a scalar, one more than the deepest child for an array or object (as the reader counts).
fn depth(value: &Value) -> usize {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => 0,
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Value::Object(object) => 1 + object.iter().map(|(_, item)| depth(item)).max().unwrap_or(0),
    }
}

/// Builds a [`Value`] from fuzzer bytes. Each decision consumes bytes; once the input runs out every byte reads as
/// 0, which selects `null` and empty containers, so the value's size is bounded by the input's.
struct Builder<'a> {
    data: &'a [u8],
    pos: usize,
}

/// Characters that exercise escaping: quotes, backslash, every kind of control character, the line separators
/// JavaScript treats specially, a non-BMP character (a surrogate pair in `\u` form) and the replacement character.
const INTERESTING_CHARS: &[char] = &[
    '"', '\\', '/', '\0', '\u{8}', '\t', '\n', '\u{c}', '\r', '\u{1f}', '\u{7f}', '\u{2028}', '\u{2029}', '😀',
    '\u{fffd}',
];

impl Builder<'_> {
    fn byte(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        byte
    }

    fn u64(&mut self) -> u64 {
        (0..8).fold(0, |acc, _| acc << 8 | u64::from(self.byte()))
    }

    /// A value at nesting `depth`. Containers stop two levels past the limit, so the writer's refusal is reached
    /// without unbounded recursion.
    fn value(&mut self, depth: usize) -> Value {
        let choice = self.byte();
        match choice % 8 {
            1 => Value::Bool(choice & 0x80 != 0),
            2 => self.integer(),
            3 => self.decimal(),
            4 => Value::String(self.string()),
            5 if depth <= MAX_DEPTH + 1 => self.array(depth),
            6 if depth <= MAX_DEPTH + 1 => self.object(depth),
            // 0, 7, and containers past the depth cap.
            _ => Value::Null,
        }
    }

    /// An array of up to 7 items, one level below `depth`.
    fn array(&mut self, depth: usize) -> Value {
        let len = usize::from(self.byte() % 8);
        Value::Array((0..len).map(|_| self.value(depth + 1)).collect())
    }

    /// An object of up to 7 members, one level below `depth`.
    fn object(&mut self, depth: usize) -> Value {
        let len = usize::from(self.byte() % 8);
        let mut object = Object::new();
        for _ in 0..len {
            let key = self.string();
            let item = self.value(depth + 1);
            // A repeated key is refused by construction; the model keeps the first.
            if let Err(error) = object.insert(key, item) {
                assert_eq!(error, JsonError::DuplicateKey, "insert failed for another reason");
            }
        }
        Value::Object(object)
    }

    /// An integer anywhere in i64, biased towards the ±2^53 edge. Out-of-range values must be refused as numbers and
    /// travel as strings.
    fn integer(&mut self) -> Value {
        let raw = self.u64().cast_signed();
        let edge = MAX_SAFE_INTEGER;
        let value = match self.byte() % 4 {
            0 => raw,
            1 => edge.saturating_add(raw % 3),
            2 => (-edge).saturating_sub(raw % 3),
            _ => raw % 1000,
        };
        match Value::int(value) {
            Ok(number) => {
                assert!(
                    value.unsigned_abs() <= edge.unsigned_abs(),
                    "Value::int accepted an out-of-range integer"
                );
                number
            }
            Err(error) => {
                assert_eq!(error, JsonError::IntegerOutOfRange);
                Value::int_string(i128::from(value))
            }
        }
    }

    /// Decimal text, either well-formed by construction or arbitrary bytes. Whatever [`Number::decimal`] accepts
    /// must then round-trip through the reader, which checks that the two agree on the grammar.
    fn decimal(&mut self) -> Value {
        let text = if self.byte().is_multiple_of(4) {
            let len = usize::from(self.byte() % 12);
            (0..len)
                .map(|_| char::from(b"0123456789.eE+-x"[usize::from(self.byte() % 16)]))
                .collect()
        } else {
            let mut text = String::new();
            if self.byte().is_multiple_of(2) {
                text.push('-');
            }
            text.push_str(&(self.u64() % 1_000_000).to_string());
            let shape = self.byte();
            if shape & 1 != 0 {
                text.push('.');
                text.push_str(&(self.u64() % 100_000).to_string());
            }
            // Without a fraction the exponent is forced: `Number::decimal` refuses plain integer text.
            if shape & 2 != 0 || shape & 1 == 0 {
                text.push(if shape & 4 != 0 { 'e' } else { 'E' });
                text.push_str(["", "+", "-"][usize::from(shape >> 3) % 3]);
                text.push_str(&(self.u64() % 400).to_string());
            }
            text
        };
        Number::decimal(&text).map_or(Value::Null, Value::Number)
    }

    /// A short string mixing interesting characters with arbitrary Unicode scalar values.
    fn string(&mut self) -> String {
        let len = usize::from(self.byte() % 12);
        (0..len)
            .map(|_| {
                let pick = self.byte();
                if pick.is_multiple_of(2) {
                    INTERESTING_CHARS[usize::from(pick / 2) % INTERESTING_CHARS.len()]
                } else {
                    let code = u32::from(self.byte()) << 12 | u32::from(self.byte()) << 4 | u32::from(pick >> 4);
                    char::from_u32(code % 0x11_0000).unwrap_or('\u{fffd}')
                }
            })
            .collect()
    }
}
