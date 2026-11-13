//! The writer: compact strict-profile JSON.
//!
//! Everything the engine sends must conform to the strict profile (`specs/06-api/wire-format.md`). The value model
//! already guarantees valid UTF-8, unique keys and in-range integers; the writer adds the one rule the model cannot
//! see, the nesting limit, and escapes every control character. Output has no insignificant whitespace.

use crate::error::JsonError;
use crate::read::MAX_DEPTH;
use crate::value::Value;

/// Writes `value` as compact strict-profile JSON. [`parse`](crate::parse) reads the output back to an equal value.
///
/// # Errors
///
/// [`JsonError::TooDeep`] if arrays and objects nest deeper than [`MAX_DEPTH`]: no strict reader would accept the
/// output, so none is produced.
///
/// # Example
///
/// ```
/// use knsh_json::{Object, Value};
/// let object = Object::new().with("name", "a\"b")?.with("n", 3)?;
/// assert_eq!(knsh_json::write(&Value::from(object))?, r#"{"name":"a\"b","n":3}"#);
/// # Ok::<(), knsh_json::JsonError>(())
/// ```
pub fn write(value: &Value) -> Result<String, JsonError> {
    let mut out = String::new();
    write_value(value, 0, &mut out)?;
    Ok(out)
}

/// Writes a value at nesting `depth` (the number of arrays and objects around it). Recursion stops at
/// [`MAX_DEPTH`], mirroring the reader.
fn write_value(value: &Value, depth: usize, out: &mut String) -> Result<(), JsonError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => number.write_to(out),
        Value::String(text) => write_string(text, out),
        Value::Array(_) | Value::Object(_) if depth == MAX_DEPTH => return Err(JsonError::TooDeep),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, depth + 1, out)?;
            }
            out.push(']');
        }
        Value::Object(object) => {
            out.push('{');
            for (i, (key, item)) in object.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(item, depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Writes a quoted string. Only `"`, `\` and U+0000 to U+001F must be escaped (RFC 8259 section 7); everything else
/// is copied as UTF-8, which a Rust `str` always is.
fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\0'..='\u{1f}' => {
                // Two hex digits suffice below U+0020.
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let code = usize::from(c as u8);
                out.push_str("\\u00");
                out.push(char::from(HEX[code >> 4]));
                out.push(char::from(HEX[code & 0xf]));
            }
            _ => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Number, Object, parse};

    fn sample() -> Value {
        let inner = Object::new()
            .with("z", Value::Null)
            .unwrap()
            .with("a", vec![Value::from(true)])
            .unwrap();
        let object = Object::new()
            .with(
                "text",
                "quote\" backslash\\ slash/ nl\n tab\t nul\0 unit\u{1f} del\u{7f} é 😀 \u{2028}",
            )
            .unwrap()
            .with(
                "ints",
                vec![
                    Value::from(0),
                    Value::int(1 << 53).unwrap(),
                    Value::int(-(1 << 53)).unwrap(),
                ],
            )
            .unwrap()
            .with(
                "decimals",
                vec![
                    Value::from(Number::decimal("-0.0").unwrap()),
                    Number::decimal("1E+400").unwrap().into(),
                ],
            )
            .unwrap()
            .with("big", Value::int_string(i128::from(u64::MAX)))
            .unwrap()
            .with("", Value::from(""))
            .unwrap()
            .with("nested", inner)
            .unwrap()
            .with("empty", Value::Array(Vec::new()))
            .unwrap()
            .with("empty_object", Object::new())
            .unwrap();
        Value::from(object)
    }

    #[test]
    fn writer_output_is_accepted_by_strict_reader() {
        let value = sample();
        let text = write(&value).unwrap();
        assert_eq!(parse(text.as_bytes(), text.len()), Ok(value));
    }

    #[test]
    fn writer_escapes_control_characters_and_emits_no_whitespace() {
        let text = write(&Value::from("a\u{1}\n\"")).unwrap();
        assert_eq!(text, r#""a\u0001\n\"""#);
        let text = write(&sample()).unwrap();
        assert!(text.bytes().all(|b| b >= 0x20), "raw control character in output");
        // The only spaces in the output are the ones inside the sample string.
        assert_eq!(text.matches(' ').count(), 10);
        assert!(!text.contains(": ") && !text.contains(", "));
    }

    #[test]
    fn writer_rejects_depth_beyond_limit() {
        let mut value = Value::Null;
        for _ in 0..MAX_DEPTH {
            value = Value::Array(vec![value]);
        }
        let text = write(&value).unwrap();
        assert_eq!(parse(text.as_bytes(), text.len()), Ok(value.clone()));
        assert_eq!(write(&Value::Array(vec![value])), Err(JsonError::TooDeep));
    }

    #[test]
    fn large_integer_must_be_written_as_string() {
        // The ±2^53 rule: the API has no way to put an out-of-range integer in a JSON number.
        assert_eq!(Value::int((1 << 53) + 1), Err(JsonError::IntegerOutOfRange));
        assert_eq!(Number::int(i64::MAX), Err(JsonError::IntegerOutOfRange));
        let big = Value::int_string((1 << 53) + 1);
        assert_eq!(write(&big).unwrap(), r#""9007199254740993""#);
    }
}
