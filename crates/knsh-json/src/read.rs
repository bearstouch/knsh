//! The strict reader: accepts only the strict JSON profile (I-JSON, RFC 7493) and rejects everything else.
//!
//! Its input comes from untrusted processes on `agent.sock`, so (`specs/06-api/wire-format.md#strict-json-profile`,
//! NFR-SEC-05, NFR-SEC-06):
//!
//! - The size limit is checked before anything else, and the whole input is validated as UTF-8 up front, so no
//!   later step can see an invalid sequence.
//! - Recursion goes one level per array or object and stops at [`MAX_DEPTH`], so the stack is bounded whatever the
//!   input.
//! - Duplicate keys, unpaired surrogates, out-of-range integers, comments, trailing commas, `NaN`/`Infinity`,
//!   leading zeros, unescaped control characters and trailing data are all rejected. The first problem ends the
//!   parse: there is no recovery and no partial result.
//! - No indexing that can panic: every byte is read with `get`.

use crate::error::{JsonError, ParseReason};
use crate::number::Number;
use crate::value::{Object, Value};

/// Deepest nesting of arrays and objects the strict profile allows. `[[1]]` has depth 2; a scalar has depth 0.
pub const MAX_DEPTH: usize = 32;

/// Parses one strict-profile JSON value.
///
/// `max_len` is the caller's size limit in bytes (for example the frame payload limit); larger input is rejected
/// before it is read at all.
///
/// # Errors
///
/// [`JsonError::InputTooLarge`] above `max_len`, otherwise [`JsonError::Parse`] with the byte offset and the first
/// [`ParseReason`] found. Both are parse errors in the JSON-RPC sense ([`JsonError::is_parse_error`]).
///
/// # Example
///
/// ```
/// let value = knsh_json::parse(br#"{"id":1,"ok":true}"#, 1024)?;
/// assert_eq!(value.as_object().and_then(|o| o.get("id")).and_then(knsh_json::Value::as_i64), Some(1));
/// assert!(knsh_json::parse(br#"{"a":1,"a":2}"#, 1024).is_err());
/// # Ok::<(), knsh_json::JsonError>(())
/// ```
pub fn parse(input: &[u8], max_len: usize) -> Result<Value, JsonError> {
    if input.len() > max_len {
        return Err(JsonError::InputTooLarge {
            len: input.len(),
            limit: max_len,
        });
    }
    let text = std::str::from_utf8(input).map_err(|error| JsonError::Parse {
        offset: error.valid_up_to(),
        reason: ParseReason::InvalidUtf8,
    })?;
    let mut reader = Reader { text, pos: 0 };
    reader
        .document()
        .map_err(|(offset, reason)| JsonError::Parse { offset, reason })
}

/// An internal rejection: byte offset and reason.
type Rejection = (usize, ParseReason);

/// Cursor over input already known to be valid UTF-8. `pos` only ever stops on ASCII bytes (structural characters
/// and string delimiters), which are always `char` boundaries, so slicing `text` between two positions is safe.
struct Reader<'a> {
    text: &'a str,
    pos: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    fn reject<T>(&self, reason: ParseReason) -> Result<T, Rejection> {
        Err((self.pos, reason))
    }

    /// Rejects whatever is at the cursor where a specific byte was required: running out of input and finding the
    /// wrong byte are reported differently, so a truncated frame is distinguishable from a malformed one.
    fn reject_unexpected<T>(&self) -> Result<T, Rejection> {
        match self.peek() {
            None => self.reject(ParseReason::UnexpectedEnd),
            Some(_) => self.reject(ParseReason::UnexpectedByte),
        }
    }

    /// RFC 8259 whitespace only: space, tab, LF, CR. A byte order mark or other Unicode space is not whitespace.
    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// Consumes `byte` if it is next.
    fn eat(&mut self, byte: u8) -> bool {
        let found = self.peek() == Some(byte);
        if found {
            self.pos += 1;
        }
        found
    }

    /// One value surrounded by optional whitespace, then the end of input.
    fn document(&mut self) -> Result<Value, Rejection> {
        self.skip_whitespace();
        let value = self.value(0)?;
        self.skip_whitespace();
        if self.pos == self.text.len() {
            Ok(value)
        } else {
            self.reject(ParseReason::TrailingData)
        }
    }

    /// A value at nesting `depth` (the number of arrays and objects around it).
    fn value(&mut self, depth: usize) -> Result<Value, Rejection> {
        match self.peek() {
            None => self.reject(ParseReason::UnexpectedEnd),
            // Check the limit before descending, so the recursion never goes past MAX_DEPTH frames.
            Some(b'[' | b'{') if depth == MAX_DEPTH => self.reject(ParseReason::TooDeep),
            Some(b'[') => self.array(depth + 1),
            Some(b'{') => self.object(depth + 1),
            Some(b'"') => self.string().map(Value::String),
            Some(b'-' | b'0'..=b'9') => {
                let (number, end) = Number::read(self.text.as_bytes(), self.pos)?;
                self.pos = end;
                Ok(Value::Number(number))
            }
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            // Comments, quotes other than `"`, `NaN`, `Infinity`, `+1`, `.5`, stray punctuation.
            Some(_) => self.reject(ParseReason::UnexpectedByte),
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, Rejection> {
        if self.text.get(self.pos..).is_some_and(|rest| rest.starts_with(word)) {
            self.pos += word.len();
            Ok(value)
        } else {
            self.reject(ParseReason::UnexpectedByte)
        }
    }

    /// After a `,`: a closing bracket here would be a trailing comma, which the strict profile rejects.
    fn reject_trailing_comma(&self, close: u8) -> Result<(), Rejection> {
        if self.peek() == Some(close) {
            self.reject(ParseReason::TrailingComma)
        } else {
            Ok(())
        }
    }

    /// After an element or field: `,` to continue (returns true), `close` to finish (returns false).
    fn separator(&mut self, close: u8) -> Result<bool, Rejection> {
        self.skip_whitespace();
        match self.peek() {
            Some(b',') => {
                self.pos += 1;
                self.skip_whitespace();
                self.reject_trailing_comma(close)?;
                Ok(true)
            }
            Some(byte) if byte == close => {
                self.pos += 1;
                Ok(false)
            }
            _ => self.reject_unexpected(),
        }
    }

    /// An array whose own depth is `depth`; the `[` is next.
    fn array(&mut self, depth: usize) -> Result<Value, Rejection> {
        self.pos += 1;
        self.skip_whitespace();
        let mut items = Vec::new();
        if self.eat(b']') {
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth)?);
            if !self.separator(b']')? {
                return Ok(Value::Array(items));
            }
        }
    }

    /// An object whose own depth is `depth`; the `{` is next.
    fn object(&mut self, depth: usize) -> Result<Value, Rejection> {
        self.pos += 1;
        self.skip_whitespace();
        let mut object = Object::new();
        if self.eat(b'}') {
            return Ok(Value::Object(object));
        }
        loop {
            let key_start = self.pos;
            // Rejects unquoted and single-quoted keys.
            if self.peek() != Some(b'"') {
                return self.reject_unexpected();
            }
            // Keys are compared after unescaping: `"a"` and `"\u0061"` are the same key (NFR-SEC-06).
            let key = self.string()?;
            self.skip_whitespace();
            if !self.eat(b':') {
                return self.reject_unexpected();
            }
            self.skip_whitespace();
            let value = self.value(depth)?;
            object
                .insert(key, value)
                .map_err(|_| (key_start, ParseReason::DuplicateKey))?;
            if !self.separator(b'}')? {
                return Ok(Value::Object(object));
            }
        }
    }

    /// A string; the opening `"` is next. Returns the unescaped text.
    fn string(&mut self) -> Result<String, Rejection> {
        self.pos += 1;
        let mut out = String::new();
        let mut run_start = self.pos;
        loop {
            match self.peek() {
                None => return self.reject(ParseReason::UnexpectedEnd),
                Some(b'"') => {
                    out.push_str(self.slice(run_start)?);
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    out.push_str(self.slice(run_start)?);
                    out.push(self.escape()?);
                    run_start = self.pos;
                }
                Some(0x00..=0x1F) => return self.reject(ParseReason::ControlCharacter),
                // Any other byte, including UTF-8 continuation bytes, is copied as part of the current run.
                Some(_) => self.pos += 1,
            }
        }
    }

    /// The text from `start` to the cursor. Both ends sit on ASCII bytes, so this cannot split a character; the
    /// fallible `get` is still used so that a logic error is a rejection, not a panic.
    fn slice(&self, start: usize) -> Result<&str, Rejection> {
        self.text.get(start..self.pos).ok_or((start, ParseReason::InvalidUtf8))
    }

    /// One escape sequence; the `\` is next. Surrogate escapes must come as a high-low pair that forms one
    /// character: a lone half has no UTF-8 encoding and is read differently by different parsers.
    fn escape(&mut self) -> Result<char, Rejection> {
        let start = self.pos;
        self.pos += 1;
        let simple = match self.peek() {
            None => return self.reject(ParseReason::UnexpectedEnd),
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                self.pos += 1;
                return self.unicode_escape(start);
            }
            Some(_) => return self.reject(ParseReason::InvalidEscape),
        };
        self.pos += 1;
        Ok(simple)
    }

    /// The rest of a `\uXXXX` escape (the `\u` is consumed), plus its low half if it is a high surrogate.
    fn unicode_escape(&mut self, start: usize) -> Result<char, Rejection> {
        let unpaired = Err((start, ParseReason::UnpairedSurrogate));
        let first = self.hex4()?;
        let code = match first {
            0xD800..=0xDBFF => {
                if !(self.eat(b'\\') && self.eat(b'u')) {
                    return unpaired;
                }
                let second = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return unpaired;
                }
                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
            }
            0xDC00..=0xDFFF => return unpaired,
            _ => first,
        };
        // Surrogates were handled above, so every remaining code is a valid scalar value.
        char::from_u32(code).ok_or((start, ParseReason::UnpairedSurrogate))
    }

    /// Four hex digits (either case).
    fn hex4(&mut self) -> Result<u32, Rejection> {
        let mut code = 0;
        for _ in 0..4 {
            let Some(byte) = self.peek() else {
                return self.reject(ParseReason::UnexpectedEnd);
            };
            let Some(digit) = char::from(byte).to_digit(16) else {
                return self.reject(ParseReason::InvalidEscape);
            };
            code = code * 16 + digit;
            self.pos += 1;
        }
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: usize = 1 << 20;

    fn reason(input: &[u8]) -> ParseReason {
        match parse(input, LIMIT) {
            Err(JsonError::Parse { reason, .. }) => reason,
            other => panic!("expected a parse error for {input:?}, got {other:?}"),
        }
    }

    fn nested(depth: usize) -> String {
        format!("{}{}", "[".repeat(depth), "]".repeat(depth))
    }

    #[test]
    fn rejects_duplicate_keys_after_unescaping() {
        // NFR-SEC-06: two parsers that disagree on which duplicate wins are a classic security bug.
        assert_eq!(reason(br#"{"a":1,"a":2}"#), ParseReason::DuplicateKey);
        assert_eq!(reason(br#"{"a":1,"\u0061":2}"#), ParseReason::DuplicateKey);
        assert_eq!(reason(br#"{"\/":1,"/":2}"#), ParseReason::DuplicateKey);
        assert_eq!(reason(br#"{"x":{"k":1},"y":{"k":2,"k":3}}"#), ParseReason::DuplicateKey);
        // Same key in different objects is fine.
        assert!(parse(br#"{"x":{"k":1},"y":{"k":2}}"#, LIMIT).is_ok());
    }

    #[test]
    fn rejects_unpaired_surrogate_escape() {
        assert_eq!(reason(br#""\ud800""#), ParseReason::UnpairedSurrogate);
        assert_eq!(reason(br#""\udc00""#), ParseReason::UnpairedSurrogate);
        assert_eq!(reason(br#""\ud800x""#), ParseReason::UnpairedSurrogate);
        assert_eq!(reason(br#""\ud800\u0041""#), ParseReason::UnpairedSurrogate);
        assert_eq!(reason(br#""\ud800\ud800""#), ParseReason::UnpairedSurrogate);
        assert_eq!(reason(br#""\udc00\ud800""#), ParseReason::UnpairedSurrogate);
        // A proper pair is one character.
        assert_eq!(parse(br#""\ud83d\ude00""#, LIMIT), Ok(Value::from("\u{1F600}")));
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(reason(b"\"\xff\""), ParseReason::InvalidUtf8);
        assert_eq!(reason(b"\"\xc3\""), ParseReason::InvalidUtf8); // truncated sequence
        assert_eq!(reason(b"\"\xc0\xaf\""), ParseReason::InvalidUtf8); // overlong '/'
        assert_eq!(reason(b"\"\xed\xa0\x80\""), ParseReason::InvalidUtf8); // encoded surrogate (CESU-8)
        assert_eq!(reason(b"\xef\xbb\xbf{}"), ParseReason::UnexpectedByte); // BOM is not whitespace
        assert_eq!(parse("\"é漢\"".as_bytes(), LIMIT), Ok(Value::from("é漢")));
    }

    #[test]
    fn rejects_integer_beyond_2_pow_53() {
        assert_eq!(reason(b"9007199254740993"), ParseReason::IntegerOutOfRange);
        assert_eq!(reason(b"-9007199254740993"), ParseReason::IntegerOutOfRange);
        assert_eq!(reason(b"18446744073709551616"), ParseReason::IntegerOutOfRange);
        assert_eq!(reason("1".repeat(10_000).as_bytes()), ParseReason::IntegerOutOfRange);
    }

    #[test]
    fn accepts_integer_at_2_pow_53_boundary() {
        assert_eq!(parse(b"9007199254740992", LIMIT).unwrap().as_i64(), Some(1 << 53));
        assert_eq!(parse(b"-9007199254740992", LIMIT).unwrap().as_i64(), Some(-(1 << 53)));
        assert_eq!(parse(b"9007199254740991", LIMIT).unwrap().as_i64(), Some((1 << 53) - 1));
    }

    #[test]
    fn keeps_non_integer_numbers_as_decimal_text() {
        let value = parse(b"[0.1,1e400,-2.50E-3]", LIMIT).unwrap();
        let texts: Vec<_> = value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_number().unwrap().as_decimal_text())
            .collect();
        assert_eq!(texts, [Some("0.1"), Some("1e400"), Some("-2.50E-3")]);
        // Where an integer is required, inexact numbers are refused rather than rounded.
        assert_eq!(parse(b"1.5", LIMIT).unwrap().as_i64(), None);
        assert_eq!(parse(b"1e300", LIMIT).unwrap().as_i64(), None);
        assert_eq!(parse(b"2.0", LIMIT).unwrap().as_i64(), Some(2));
    }

    #[test]
    fn rejects_depth_33_accepts_depth_32() {
        assert!(parse(nested(32).as_bytes(), LIMIT).is_ok());
        assert_eq!(reason(nested(33).as_bytes()), ParseReason::TooDeep);
        let objects = format!("{}1{}", r#"{"a":"#.repeat(32), "}".repeat(32));
        assert!(parse(objects.as_bytes(), LIMIT).is_ok());
        let objects = format!("{}1{}", r#"{"a":"#.repeat(33), "}".repeat(33));
        assert_eq!(reason(objects.as_bytes()), ParseReason::TooDeep);
        // Far deeper input is rejected at depth 33 without exhausting the stack.
        assert_eq!(reason("[".repeat(1_000_000).as_bytes()), ParseReason::TooDeep);
    }

    #[test]
    fn rejects_trailing_comma_comment_and_trailing_data() {
        assert_eq!(reason(b"[1,]"), ParseReason::TrailingComma);
        assert_eq!(reason(b"[1, ]"), ParseReason::TrailingComma);
        assert_eq!(reason(br#"{"a":1,}"#), ParseReason::TrailingComma);
        assert_eq!(reason(b"[1]// c"), ParseReason::TrailingData);
        assert_eq!(reason(b"/* c */ 1"), ParseReason::UnexpectedByte);
        assert_eq!(reason(b"[1 /* c */]"), ParseReason::UnexpectedByte);
        assert_eq!(reason(b"1 2"), ParseReason::TrailingData);
        assert_eq!(reason(b"{}x"), ParseReason::TrailingData);
        assert_eq!(reason(b"{} {}"), ParseReason::TrailingData);
    }

    #[test]
    fn rejects_non_finite_numbers_leading_zeros_and_control_characters() {
        for input in [&b"NaN"[..], b"Infinity", b"-Infinity", b"+1", b".5"] {
            assert!(parse(input, LIMIT).is_err(), "{input:?}");
        }
        assert_eq!(reason(b"01"), ParseReason::LeadingZero);
        assert_eq!(reason(b"-01"), ParseReason::LeadingZero);
        assert_eq!(reason(b"00.5"), ParseReason::LeadingZero);
        assert_eq!(reason(b"1."), ParseReason::InvalidNumber);
        assert_eq!(reason(b"-"), ParseReason::InvalidNumber);
        assert_eq!(reason(b"\"a\nb\""), ParseReason::ControlCharacter);
        assert_eq!(reason(b"\"\x00\""), ParseReason::ControlCharacter);
        assert_eq!(reason(b"\"\x1f\""), ParseReason::ControlCharacter);
        // Escaped control characters are fine.
        assert_eq!(parse(br#""a\nb\u0000""#, LIMIT), Ok(Value::from("a\nb\0")));
    }

    #[test]
    fn rejects_input_larger_than_limit_before_parsing() {
        // Invalid JSON larger than the limit reports the size, proving the limit is checked first.
        assert_eq!(
            parse(b"\xff\xff\xff", 2),
            Err(JsonError::InputTooLarge { len: 3, limit: 2 })
        );
        assert!(parse(b"[1]", 3).is_ok());
    }

    #[test]
    fn every_rejection_is_a_parse_error() {
        for input in [&b""[..], b"[", b"{\"a\"", b"tru", b"\"\\x\"", b"\"\\u12\"", b"\xff"] {
            let error = parse(input, LIMIT).unwrap_err();
            assert!(error.is_parse_error(), "{input:?}: {error:?}");
        }
        assert!(parse(b"[1]", 1).unwrap_err().is_parse_error());
    }

    #[test]
    fn reports_byte_offset_without_echoing_input() {
        let error = parse(br#"{"secret-token":1,"secret-token":2}"#, LIMIT).unwrap_err();
        assert_eq!(
            error,
            JsonError::Parse {
                offset: 18,
                reason: ParseReason::DuplicateKey
            }
        );
        assert!(!error.to_string().contains("secret"));
    }
}
