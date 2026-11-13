//! Base64 fallback for clients that cannot handle binary frames.
//!
//! A client that says so in `hello` receives raw bytes base64-encoded inside JSON instead of as binary chunks
//! (`specs/06-api/wire-format.md#frames-unix-sockets`, `specs/06-api/handshake.md`). Standard alphabet (RFC 4648
//! section 4) with padding.
//!
//! Decoding is strict, like the JSON reader: there is exactly one accepted encoding for any byte string. Missing
//! padding, whitespace, the URL-safe alphabet and non-zero unused bits are all rejected, so two decoders can never
//! disagree about what a string means.

use crate::convert::{FromJson, ToJson};
use crate::error::{JsonError, Kind};
use crate::value::Value;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `bytes` as standard base64 with padding.
///
/// # Example
///
/// ```
/// assert_eq!(knsh_json::base64_encode(b"knsh"), "a25zaA==");
/// ```
#[must_use]
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let b0 = group.first().copied().unwrap_or(0);
        let b1 = group.get(1).copied().unwrap_or(0);
        let b2 = group.get(2).copied().unwrap_or(0);
        let triple = u32::from(b0) << 16 | u32::from(b1) << 8 | u32::from(b2);
        // A group of n input bytes yields n + 1 significant characters; the rest of the quad is padding.
        for index in 0..4 {
            if index <= group.len() {
                out.push(sextet_char(triple >> (18 - 6 * index)));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes canonical standard base64 with padding.
///
/// # Errors
///
/// [`JsonError::InvalidBase64`] if the length is not a multiple of four, a character is outside the standard
/// alphabet, padding is missing or misplaced, or the unused bits of the last group are not zero (a non-canonical
/// encoding).
///
/// # Example
///
/// ```
/// assert_eq!(knsh_json::base64_decode("a25zaA==")?, b"knsh");
/// assert!(knsh_json::base64_decode("a25zaA").is_err());
/// # Ok::<(), knsh_json::JsonError>(())
/// ```
pub fn base64_decode(text: &str) -> Result<Vec<u8>, JsonError> {
    let input = text.as_bytes();
    let (quads, remainder) = input.as_chunks::<4>();
    if !remainder.is_empty() {
        return Err(JsonError::InvalidBase64);
    }
    let mut out = Vec::with_capacity(quads.len() * 3);
    let last = quads.len().saturating_sub(1);
    for (index, quad) in quads.iter().enumerate() {
        // Padding may only appear at the very end: one `=` leaves two output bytes, two leave one.
        let padding = quad.iter().rev().take_while(|&&byte| byte == b'=').count();
        if padding > 2 || (padding > 0 && index != last) {
            return Err(JsonError::InvalidBase64);
        }
        let mut triple = 0u32;
        for (position, &byte) in quad.iter().enumerate() {
            let sextet = if position < 4 - padding {
                sextet_value(byte).ok_or(JsonError::InvalidBase64)?
            } else {
                0
            };
            triple = triple << 6 | sextet;
        }
        let [_, b0, b1, b2] = triple.to_be_bytes();
        let decoded = [b0, b1, b2];
        let (kept, dropped) = decoded.split_at(3 - padding);
        // Canonical form: the bits that padding drops must be zero, otherwise several strings decode to the same
        // bytes.
        if dropped.iter().any(|&byte| byte != 0) {
            return Err(JsonError::InvalidBase64);
        }
        out.extend_from_slice(kept);
    }
    Ok(out)
}

/// Raw bytes carried as a base64 JSON string, for messages sent to a client that declared in `hello` that it cannot
/// handle binary frames.
///
/// # Example
///
/// ```
/// use knsh_json::{Base64Bytes, FromJson, ToJson};
/// let value = Base64Bytes(b"\x00\xff".to_vec()).to_json()?;
/// assert_eq!(value.as_str(), Some("AP8="));
/// assert_eq!(Base64Bytes::from_json(&value)?.0, b"\x00\xff");
/// # Ok::<(), knsh_json::JsonError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Base64Bytes(pub Vec<u8>);

impl ToJson for Base64Bytes {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::String(base64_encode(&self.0)))
    }
}

impl FromJson for Base64Bytes {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let text = value.as_str().ok_or(JsonError::WrongType {
            field: None,
            expected: Kind::String,
        })?;
        base64_decode(text).map(Self)
    }
}

/// The alphabet character for the low six bits of `bits`.
fn sextet_char(bits: u32) -> char {
    // The mask keeps the index below 64, so the lookup always succeeds; `'A'` is unreachable.
    let index = usize::try_from(bits & 0x3f).unwrap_or(0);
    ALPHABET.get(index).map_or('A', |&byte| char::from(byte))
}

/// The six-bit value of a standard-alphabet character, or `None` for anything else (including `=`, `-` and `_`).
fn sextet_value(byte: u8) -> Option<u32> {
    let value = match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc4648_test_vectors() {
        // RFC 4648 section 10.
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (bytes, text) in vectors {
            assert_eq!(base64_encode(bytes), text);
            assert_eq!(base64_decode(text).unwrap(), bytes);
        }
    }

    #[test]
    fn round_trips_every_byte_value_and_length() {
        let bytes: Vec<u8> = (0..=255).collect();
        for len in 0..bytes.len() {
            let slice = &bytes[..len];
            assert_eq!(base64_decode(&base64_encode(slice)).unwrap(), slice, "length {len}");
        }
        assert_eq!(base64_encode(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn rejects_non_canonical_base64() {
        // Missing padding, whitespace, URL-safe alphabet, padding in the middle or too much of it, and non-zero
        // bits under the padding ("Zh==" decodes to "f" in lenient decoders).
        for text in [
            "Zg",
            "Zg=",
            "Zm9v Yg==",
            "Zm9v\nYg==",
            "-_8=",
            "Zg==Zg==",
            "Z===",
            "====",
            "Zh==",
            "Zm9=",
            "é=",
        ] {
            assert_eq!(base64_decode(text), Err(JsonError::InvalidBase64), "{text:?}");
        }
    }

    #[test]
    fn base64_bytes_requires_a_string() {
        assert!(matches!(
            Base64Bytes::from_json(&Value::Null),
            Err(JsonError::WrongType { .. })
        ));
    }
}
