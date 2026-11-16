//! A strict base64 decoder for `Proxy-Authorization: Basic` (RFC 7617, RFC 4648 section 4).
//!
//! Strict on purpose (NFR-SEC-05): the standard alphabet only, padding required to a multiple of four, padding only
//! at the end, no whitespace, and the unused bits of the last character zero. Anything else is refused, so one set of
//! credentials has exactly one encoding.

/// The value of `byte` in the standard alphabet, or `None`.
fn value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes `text`, or `None` if it is not canonical, padded base64 (module documentation). The output is at most
/// three quarters of the input, which the caller has already bounded.
#[must_use]
pub fn decode(text: &[u8]) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return None;
    }
    let padding = text.iter().rev().take_while(|&&byte| byte == b'=').count();
    if padding > 2 {
        return None;
    }
    let body = &text[..text.len() - padding];
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &byte in body {
        acc = (acc << 6) | u32::from(value(byte)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // The byte just completed: `acc` holds fewer than 8 bits besides it.
            out.push((acc >> bits).to_le_bytes()[0]);
            acc &= (1 << bits) - 1;
        }
    }
    // Left-over bits must be zero: `QQ==` and `QR==` must not both decode to `A`.
    (acc == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 section 10 test vectors.
    #[test]
    fn decodes_rfc_vectors() {
        for (encoded, decoded) in [
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
            ("a25zaC0xOnRvaw==", "knsh-1:tok"),
        ] {
            assert_eq!(decode(encoded.as_bytes()).unwrap(), decoded.as_bytes(), "{encoded}");
        }
    }

    // NFR-SEC-05: anything but canonical padded base64 is refused.
    #[test]
    fn refuses_non_canonical_input() {
        for bad in [
            "",
            "Zg",
            "Zg=",
            "Zm9v Yg==",
            "Zg===",
            "Z===",
            "=Zg=",
            "Zg=a",
            "Zm9v\n",
            "QR==",
            "Zm9-",
            "Zm9_",
        ] {
            assert!(decode(bad.as_bytes()).is_none(), "{bad:?}");
        }
    }
}
