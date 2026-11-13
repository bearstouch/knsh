//! In-house ULID: 48-bit millisecond time followed by 80 bits of randomness, as 26 Crockford base32 characters.
//!
//! The time and the random bytes are passed in, never read from the system, so construction is pure and tests are
//! deterministic. The clock and the random source are effects that callers inject through `knsh-platform`.
//!
//! Because the time occupies the most significant bits, both the numeric order and the text order of ULIDs follow
//! creation time (`specs/05-models/session.md`: "sortable by start time").

use std::fmt;
use std::str::FromStr;

use crate::error::CoreError;

/// Crockford base32 alphabet: digits and uppercase letters without `I`, `L`, `O` and `U`.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Length of the text form: 128 bits in 5-bit groups, rounded up.
const ENCODED_LEN: usize = 26;

/// Largest time a ULID can hold, in milliseconds since the Unix epoch.
pub const MAX_MILLIS: u64 = (1 << 48) - 1;

/// Marks bytes that are not in [`ALPHABET`] in [`DECODE`].
const INVALID: u8 = 0xFF;

/// Reverse lookup from ASCII byte to 5-bit value. Only the canonical uppercase characters map to a value: lowercase
/// and the Crockford aliases (`I`, `L`, `O`) are rejected so that every ULID has exactly one text form, which keeps
/// string comparison and storage keys consistent with value comparison.
const DECODE: [u8; 256] = {
    let mut table = [INVALID; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        // `i < 32`, so the cast is lossless.
        #[allow(clippy::cast_possible_truncation)]
        let value = i as u8;
        table[ALPHABET[i] as usize] = value;
        i += 1;
    }
    table
};

/// A 128-bit universally unique, lexicographically sortable identifier.
///
/// # Invariants
///
/// - The top 48 bits are the creation time in milliseconds since the Unix epoch; the low 80 bits are random.
/// - `Ord` follows the 128-bit value, so ULIDs with a greater time always sort later. Within one millisecond the
///   order follows the random bits and is arbitrary.
/// - [`Display`](fmt::Display) yields exactly 26 uppercase Crockford base32 characters, and [`FromStr`] accepts only
///   that form, so `s.parse::<Ulid>()?.to_string() == s` for every accepted `s`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ulid(u128);

impl Ulid {
    /// Builds a ULID from a time and 80 bits of randomness. Pure: reads no clock and no random source.
    ///
    /// # Errors
    ///
    /// [`CoreError::UlidTimeOutOfRange`] if `millis` is above [`MAX_MILLIS`] (year 10889). Rejecting instead of
    /// truncating keeps the sort-by-time invariant: a wrapped time would sort before older IDs.
    pub fn new(millis: u64, random_bytes: [u8; 10]) -> Result<Self, CoreError> {
        if millis > MAX_MILLIS {
            return Err(CoreError::UlidTimeOutOfRange);
        }
        // Place the random bytes in the low 10 bytes of a big-endian u128; the mirror of `random_bytes`.
        let mut bytes = [0; 16];
        bytes[6..].copy_from_slice(&random_bytes);
        Ok(Self((u128::from(millis) << 80) | u128::from_be_bytes(bytes)))
    }

    /// Builds a ULID from its 128-bit value, for example when reading one back from storage. Every value is valid.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        Self(value)
    }

    /// The 128-bit value.
    #[must_use]
    pub const fn to_u128(self) -> u128 {
        self.0
    }

    /// The creation time in milliseconds since the Unix epoch; always at most [`MAX_MILLIS`].
    #[must_use]
    pub const fn millis(self) -> u64 {
        // The shift leaves 48 significant bits, so the cast is lossless.
        #[allow(clippy::cast_possible_truncation)]
        let millis = (self.0 >> 80) as u64;
        millis
    }

    /// The 80 random bits, big-endian.
    #[must_use]
    pub fn random_bytes(self) -> [u8; 10] {
        let bytes = self.0.to_be_bytes();
        let mut random = [0; 10];
        random.copy_from_slice(&bytes[6..]);
        random
    }

    /// Encodes into the fixed 26-byte ASCII form without allocating.
    fn encode(self) -> [u8; ENCODED_LEN] {
        let mut out = [0; ENCODED_LEN];
        let mut value = self.0;
        // Fill from the least significant end: the last character holds the low 5 bits, and the first character
        // holds only the top 3 bits (26 * 5 = 130 bits, two more than a u128 has).
        for slot in out.iter_mut().rev() {
            // Masked to 5 bits, so the index is below 32.
            #[allow(clippy::cast_possible_truncation)]
            let index = (value & 0x1F) as usize;
            *slot = ALPHABET[index];
            value >>= 5;
        }
        out
    }
}

impl fmt::Display for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = self.encode();
        // Every byte comes from ALPHABET, which is ASCII, so this cannot fail; fall back to an error rather than
        // panic to respect the crate's no-panic rule.
        let text = std::str::from_utf8(&encoded).map_err(|_| fmt::Error)?;
        f.write_str(text)
    }
}

impl fmt::Debug for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ulid({self})")
    }
}

impl FromStr for Ulid {
    type Err = CoreError;

    /// Parses the canonical 26-character uppercase form.
    ///
    /// # Errors
    ///
    /// - [`CoreError::UlidLength`] unless the input is exactly 26 bytes. Checked first, before any decoding.
    /// - [`CoreError::UlidInvalidChar`] for any byte outside the uppercase Crockford alphabet, including lowercase
    ///   letters, the aliases `I`, `L`, `O`, and non-ASCII bytes.
    /// - [`CoreError::UlidOverflow`] if the first character is above `7`: it would need bits beyond 128.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() != ENCODED_LEN {
            return Err(CoreError::UlidLength(bytes.len()));
        }
        let mut value: u128 = 0;
        for (index, &byte) in bytes.iter().enumerate() {
            let digit = DECODE[usize::from(byte)];
            if digit == INVALID {
                return Err(CoreError::UlidInvalidChar(index));
            }
            // The first character carries only 3 bits; anything above 7 would be shifted out of the u128.
            if index == 0 && digit > 7 {
                return Err(CoreError::UlidOverflow);
            }
            value = (value << 5) | u128::from(digit);
        }
        Ok(Self(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM: [u8; 10] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23];

    #[test]
    fn ulid_formats_as_26_crockford_chars() {
        let ulid = Ulid::new(1_469_918_176_385, RANDOM).unwrap();
        let text = ulid.to_string();
        assert_eq!(text.len(), 26);
        assert!(text.bytes().all(|b| ALPHABET.contains(&b)));
        // The 48-bit time 1469918176385 is "01ARYZ6S41" in the reference ULID specification.
        assert!(text.starts_with("01ARYZ6S41"), "{text}");

        assert_eq!(Ulid::from_u128(0).to_string(), "00000000000000000000000000");
        assert_eq!(Ulid::from_u128(u128::MAX).to_string(), "7ZZZZZZZZZZZZZZZZZZZZZZZZZ");
        assert_eq!(Ulid::new(MAX_MILLIS, [0xFF; 10]).unwrap(), Ulid::from_u128(u128::MAX));
    }

    #[test]
    fn ulid_round_trips_through_text_and_parts() {
        let ulid = Ulid::new(1_700_000_000_123, RANDOM).unwrap();
        assert_eq!(ulid.millis(), 1_700_000_000_123);
        assert_eq!(ulid.random_bytes(), RANDOM);
        assert_eq!(ulid.to_string().parse::<Ulid>().unwrap(), ulid);
        assert_eq!(Ulid::from_u128(ulid.to_u128()), ulid);
        assert_eq!(format!("{ulid:?}"), format!("Ulid({ulid})"));
    }

    #[test]
    fn ulid_new_rejects_time_beyond_48_bits() {
        assert_eq!(Ulid::new(MAX_MILLIS + 1, RANDOM), Err(CoreError::UlidTimeOutOfRange));
        assert_eq!(Ulid::new(u64::MAX, RANDOM), Err(CoreError::UlidTimeOutOfRange));
    }

    #[test]
    fn ulid_parse_rejects_invalid_chars_and_length() {
        // Length is checked before content.
        assert_eq!("".parse::<Ulid>(), Err(CoreError::UlidLength(0)));
        assert_eq!("0".repeat(25).parse::<Ulid>(), Err(CoreError::UlidLength(25)));
        assert_eq!("0".repeat(27).parse::<Ulid>(), Err(CoreError::UlidLength(27)));
        // Excluded letters, lowercase, punctuation and non-ASCII are all rejected at their index.
        for (bad, index) in [('I', 3), ('L', 3), ('O', 3), ('U', 3), ('a', 25), ('-', 10), (' ', 0)] {
            let mut text = "0".repeat(26);
            text.replace_range(index..=index, &bad.to_string());
            assert_eq!(
                text.parse::<Ulid>(),
                Err(CoreError::UlidInvalidChar(index)),
                "{bad:?} at {index}"
            );
        }
        // Length is counted in bytes: a two-byte UTF-8 character plus 24 digits is 26 bytes, and its first byte is
        // not in the alphabet.
        assert_eq!(
            format!("é{}", "0".repeat(24)).parse::<Ulid>(),
            Err(CoreError::UlidInvalidChar(0))
        );
        assert_eq!(
            format!("é{}", "0".repeat(25)).parse::<Ulid>(),
            Err(CoreError::UlidLength(27))
        );
        // The first character may only carry 3 bits.
        assert_eq!(
            format!("8{}", "0".repeat(25)).parse::<Ulid>(),
            Err(CoreError::UlidOverflow)
        );
        assert_eq!(
            format!("Z{}", "Z".repeat(25)).parse::<Ulid>(),
            Err(CoreError::UlidOverflow)
        );
        assert!(format!("7{}", "Z".repeat(25)).parse::<Ulid>().is_ok());
    }

    #[test]
    fn ulid_sorts_by_time() {
        // Later time sorts later regardless of the random bits, both as values and as text.
        let times = [0, 1, 999, 1_000, 1_469_918_176_385, 1_700_000_000_000, MAX_MILLIS];
        let ulids: Vec<Ulid> = times
            .iter()
            .enumerate()
            .map(|(i, &t)| {
                // Descending randomness so that a sort by random bits would give the wrong order.
                #[allow(clippy::cast_possible_truncation)]
                let fill = 0xFF - i as u8;
                Ulid::new(t, [fill; 10]).unwrap()
            })
            .collect();
        for pair in ulids.windows(2) {
            assert!(pair[0] < pair[1]);
            assert!(pair[0].to_string() < pair[1].to_string());
        }
    }
}
