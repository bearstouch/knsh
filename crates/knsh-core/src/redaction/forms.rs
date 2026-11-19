//! The encoded forms of a secret value that the redactor looks for (FR-SEC-10).
//!
//! Base64 and hex are produced here and matched literally. Percent-encoding is not produced: there are too many ways
//! to write it (which bytes are escaped, upper- or lower-case digits, `+` for space), so the redactor decodes `%HH`
//! in the stream instead and looks for the value in the decoded bytes (see the module documentation).

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 alphabet (RFC 4648 section 4 or 5).
#[derive(Clone, Copy)]
pub(super) enum Alphabet {
    /// `+` and `/`.
    Standard,
    /// `-` and `_`.
    UrlSafe,
}

/// `value` in base64, with `=` padding when `pad`.
pub(super) fn base64(value: &[u8], alphabet: Alphabet, pad: bool) -> Vec<u8> {
    let table = match alphabet {
        Alphabet::Standard => STANDARD,
        Alphabet::UrlSafe => URL_SAFE,
    };
    let mut out = Vec::with_capacity(value.len().div_ceil(3) * 4);
    for group in value.chunks(3) {
        let b = [
            group[0],
            group.get(1).copied().unwrap_or(0),
            group.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let chars = group.len() + 1;
        for i in 0..4 {
            if i < chars {
                out.push(table[(n >> (18 - 6 * i) & 63) as usize]);
            } else if pad {
                out.push(b'=');
            }
        }
    }
    out
}

/// `value` in hex, two digits per byte.
pub(super) fn hex(value: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Vec::with_capacity(value.len() * 2);
    for &byte in value {
        out.push(digits[usize::from(byte >> 4)]);
        out.push(digits[usize::from(byte & 15)]);
    }
    out
}

/// The value of a hex digit of either case.
pub(super) const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Overwrites `bytes` before it is freed (best effort, see `Automaton`'s `Drop`).
pub(super) fn wipe(mut bytes: Vec<u8>) {
    bytes.fill(0);
    std::hint::black_box(&mut bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (value, encoded) in vectors {
            assert_eq!(base64(value, Alphabet::Standard, true), encoded.as_bytes());
            assert_eq!(
                base64(value, Alphabet::Standard, false),
                encoded.trim_end_matches('=').as_bytes()
            );
        }
        assert_eq!(base64(&[0xfb, 0xff, 0xfe], Alphabet::Standard, true), b"+//+");
        assert_eq!(base64(&[0xfb, 0xff, 0xfe], Alphabet::UrlSafe, true), b"-__-");
    }

    #[test]
    fn hex_has_both_cases() {
        assert_eq!(hex(&[0x00, 0xab, 0x5f], false), b"00ab5f");
        assert_eq!(hex(&[0x00, 0xab, 0x5f], true), b"00AB5F");
        assert_eq!(hex_digit(b'f'), Some(15));
        assert_eq!(hex_digit(b'F'), Some(15));
        assert_eq!(hex_digit(b'g'), None);
    }
}
