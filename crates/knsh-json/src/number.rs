//! JSON numbers under the strict profile: integers within ±2^53, everything else kept as decimal text.
//!
//! No floating point is involved anywhere. Converting text to `f64` and back would silently round (`0.1`,
//! `1e400`), so a value could be read two ways; keeping the text verbatim makes `parse(write(v)) == v` exact.

use crate::error::{JsonError, ParseReason};

/// Largest integer magnitude a JSON number may carry: 2^53. Beyond it IEEE 754 doubles, which many clients use for
/// every number, can no longer represent each integer exactly (`specs/06-api/wire-format.md`). The bound is
/// inclusive, as the spec says "within ±2^53".
pub const MAX_SAFE_INTEGER: i64 = 1 << 53;

/// Most decimal digits an in-range integer can have (`9007199254740992` has 16).
const MAX_SAFE_DIGITS: usize = 16;

/// A strict-profile JSON number.
///
/// # Invariants
///
/// - An integer is within ±[`MAX_SAFE_INTEGER`]; out-of-range integers cannot be constructed.
/// - A decimal is the exact text of a valid RFC 8259 number that has a fraction or an exponent (so it can never be
///   mistaken for an integer literal when read back), stored verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Number(Repr);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Repr {
    Int(i64),
    Decimal(Box<str>),
}

impl Number {
    /// An integer number.
    ///
    /// # Errors
    ///
    /// [`JsonError::IntegerOutOfRange`] if `value` is outside ±2^53. The API forces such values to travel as
    /// strings ([`IntString`](crate::IntString)), per the strict profile.
    pub const fn int(value: i64) -> Result<Self, JsonError> {
        if value.unsigned_abs() > MAX_SAFE_INTEGER.unsigned_abs() {
            return Err(JsonError::IntegerOutOfRange);
        }
        Ok(Self(Repr::Int(value)))
    }

    /// An integer from a type of at most 32 bits, which is always within ±2^53, so no check is needed.
    pub(crate) const fn from_small(value: i64) -> Self {
        debug_assert!(value.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs());
        Self(Repr::Int(value))
    }

    /// A non-integer number given as its JSON text, for example `"0.25"` or `"6.02e23"`.
    ///
    /// # Errors
    ///
    /// [`JsonError::InvalidDecimal`] if `text` is not a complete RFC 8259 number or has neither a fraction nor an
    /// exponent (use [`Number::int`] for those).
    pub fn decimal(text: &str) -> Result<Self, JsonError> {
        match scan(text.as_bytes(), 0) {
            Ok(Scanned { end, is_integer: false }) if end == text.len() => Ok(Self(Repr::Decimal(text.into()))),
            Ok(_) | Err(_) => Err(JsonError::InvalidDecimal),
        }
    }

    /// The value as an integer, if it is exactly one within ±2^53. Decimals convert only when exact: `1.0` and
    /// `2e3` convert, `1.5` and `1e300` do not. This is the check for "an integer is required" in the strict
    /// profile: never round.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match &self.0 {
            Repr::Int(value) => Some(*value),
            Repr::Decimal(text) => exact_integer(text),
        }
    }

    /// The verbatim text of a decimal, or `None` for an integer.
    #[must_use]
    pub fn as_decimal_text(&self) -> Option<&str> {
        match &self.0 {
            Repr::Int(_) => None,
            Repr::Decimal(text) => Some(text),
        }
    }

    /// Appends the number's JSON text. Both forms are valid strict-profile JSON by construction.
    pub(crate) fn write_to(&self, out: &mut String) {
        match &self.0 {
            Repr::Int(value) => out.push_str(&value.to_string()),
            Repr::Decimal(text) => out.push_str(text),
        }
    }

    /// Reads the number starting at `start`, returning it and the offset just after it. Shared with the reader so
    /// both use one grammar.
    pub(crate) fn read(bytes: &[u8], start: usize) -> Result<(Self, usize), (usize, ParseReason)> {
        let Scanned { end, is_integer } = scan(bytes, start)?;
        let text = bytes.get(start..end).ok_or((start, ParseReason::InvalidNumber))?;
        // The scanner accepted only ASCII digits, signs, `.` and `e`, so this cannot fail; it is still not unwrapped.
        let text = std::str::from_utf8(text).map_err(|_| (start, ParseReason::InvalidNumber))?;
        if !is_integer {
            return Ok((Self(Repr::Decimal(text.into())), end));
        }
        // Bound the digit count before converting so that a 1 MB run of digits cannot overflow anything.
        let digits = text.strip_prefix('-').unwrap_or(text).len();
        if digits > MAX_SAFE_DIGITS {
            return Err((start, ParseReason::IntegerOutOfRange));
        }
        let value: i64 = text.parse().map_err(|_| (start, ParseReason::InvalidNumber))?;
        Self::int(value)
            .map(|number| (number, end))
            .map_err(|_| (start, ParseReason::IntegerOutOfRange))
    }
}

/// Result of scanning a number's text.
struct Scanned {
    /// Offset just after the number.
    end: usize,
    /// No fraction and no exponent: the literal must satisfy the integer range rule.
    is_integer: bool,
}

/// Scans `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?` from `start` (RFC 8259 section 6). Leading zeros, a bare
/// `-`, `.5`, `1.` and `1e` are rejected; `+1`, `NaN` and `Infinity` never reach here as they do not start a number.
fn scan(bytes: &[u8], start: usize) -> Result<Scanned, (usize, ParseReason)> {
    let at = |i: usize| bytes.get(i).copied();
    let digits_from = |mut i: usize| {
        while at(i).is_some_and(|b| b.is_ascii_digit()) {
            i += 1;
        }
        i
    };

    let mut pos = start;
    if at(pos) == Some(b'-') {
        pos += 1;
    }
    match at(pos) {
        Some(b'0') => {
            pos += 1;
            if at(pos).is_some_and(|b| b.is_ascii_digit()) {
                return Err((pos, ParseReason::LeadingZero));
            }
        }
        Some(b'1'..=b'9') => pos = digits_from(pos),
        _ => return Err((pos, ParseReason::InvalidNumber)),
    }

    let mut is_integer = true;
    if at(pos) == Some(b'.') {
        let end = digits_from(pos + 1);
        if end == pos + 1 {
            return Err((end, ParseReason::InvalidNumber));
        }
        pos = end;
        is_integer = false;
    }
    if matches!(at(pos), Some(b'e' | b'E')) {
        pos += 1;
        if matches!(at(pos), Some(b'+' | b'-')) {
            pos += 1;
        }
        let end = digits_from(pos);
        if end == pos {
            return Err((end, ParseReason::InvalidNumber));
        }
        pos = end;
        is_integer = false;
    }
    Ok(Scanned { end: pos, is_integer })
}

/// Exact integer value of valid decimal number text, if it is an integer within ±2^53. Works on the digits
/// directly (no floating point), so `0.1e1` is 1 but `1.0000000000000001` is not an integer.
fn exact_integer(text: &str) -> Option<i64> {
    let (negative, unsigned) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(index) => (unsigned.get(..index)?, parse_exponent(unsigned.get(index + 1..)?)),
        None => (unsigned, 0),
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));

    // value = digits × 10^scale, where digits are the integer and fraction digits run together.
    let all_digits = || int_part.bytes().chain(frac_part.bytes());
    let frac_len = i64::try_from(frac_part.len()).ok()?;
    let mut scale = exponent.checked_sub(frac_len)?;

    // Drop leading zeros (no value) and trailing zeros (move them into the scale) to get the significant digits.
    let significant: Vec<u8> = all_digits().skip_while(|&d| d == b'0').collect();
    let trailing_zeros = significant.iter().rev().take_while(|&&d| d == b'0').count();
    let significant = significant.get(..significant.len() - trailing_zeros)?;
    if significant.is_empty() {
        return Some(0);
    }
    scale = scale.checked_add(i64::try_from(trailing_zeros).ok()?)?;

    // A negative scale leaves a nonzero fraction; a too-long result exceeds 2^53 (16 digits) before multiplying.
    let scale = usize::try_from(scale).ok()?;
    if significant.len().checked_add(scale)? > MAX_SAFE_DIGITS {
        return None;
    }
    let mut magnitude: u64 = 0;
    for digit in significant.iter().copied().chain(std::iter::repeat_n(b'0', scale)) {
        magnitude = magnitude.checked_mul(10)?.checked_add(u64::from(digit - b'0'))?;
    }
    if magnitude > MAX_SAFE_INTEGER.unsigned_abs() {
        return None;
    }
    let magnitude = i64::try_from(magnitude).ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

/// Parses an exponent (`[+-]?[0-9]+`, already validated), saturating at ±10^17 so a long digit run cannot overflow
/// (`10^17 × 10 + 9` still fits in `i64`). The cap must exceed any possible digit count: the caller offsets the
/// exponent by the fraction length and trailing zeros, and a cap those can reach (a 1 MB frame holds a million
/// digits) would let `0.<999999 zeros>1e1000000000` cancel out to exactly 1 instead of a huge number.
fn parse_exponent(text: &str) -> i64 {
    const CAP: i64 = 100_000_000_000_000_000;
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, text.get(1..).unwrap_or("")),
        Some(b'+') => (false, text.get(1..).unwrap_or("")),
        _ => (false, text),
    };
    let magnitude = digits
        .bytes()
        .fold(0_i64, |acc, d| (acc * 10 + i64::from(d - b'0')).min(CAP));
    if negative { -magnitude } else { magnitude }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_constructor_enforces_inclusive_2_pow_53_bound() {
        assert!(Number::int(MAX_SAFE_INTEGER).is_ok());
        assert!(Number::int(-MAX_SAFE_INTEGER).is_ok());
        assert_eq!(Number::int(MAX_SAFE_INTEGER + 1), Err(JsonError::IntegerOutOfRange));
        assert_eq!(Number::int(i64::MIN), Err(JsonError::IntegerOutOfRange));
    }

    #[test]
    fn decimal_constructor_requires_fraction_or_exponent() {
        assert!(Number::decimal("0.5").is_ok());
        assert!(Number::decimal("-1E+9").is_ok());
        for bad in ["1", "-0", "01.5", "1.", ".5", "1e", "+1.0", "1.0 ", "NaN", ""] {
            assert_eq!(Number::decimal(bad), Err(JsonError::InvalidDecimal), "{bad:?}");
        }
    }

    #[test]
    fn decimal_converts_to_integer_only_when_exact() {
        let int = |text: &str| Number::decimal(text).unwrap().as_i64();
        assert_eq!(int("1.0"), Some(1));
        assert_eq!(int("-2.50e1"), Some(-25));
        assert_eq!(int("0.1e1"), Some(1));
        assert_eq!(int("0.0"), Some(0));
        assert_eq!(int("-0.0e-99999999999999999999"), Some(0));
        assert_eq!(int("9.007199254740992e15"), Some(MAX_SAFE_INTEGER));
        assert_eq!(int("9.007199254740993e15"), None);
        assert_eq!(int("1.5"), None);
        assert_eq!(int("1.0000000000000001"), None);
        assert_eq!(int("1e300"), None);
        assert_eq!(int("1e99999999999999999999"), None);
        assert_eq!(int("100e-2"), Some(1));
        assert_eq!(int("1e-2"), None);
    }

    #[test]
    fn saturated_exponent_cannot_cancel_long_digit_runs() {
        // Strict profile: an integer is required only when exact. A saturating exponent must not be offset back to
        // zero by a long fraction or a long run of trailing zeros.
        let tiny_fraction = format!("0.{}1e1000000000", "0".repeat(999_999));
        assert_eq!(Number::decimal(&tiny_fraction).unwrap().as_i64(), None);
        let many_zeros = format!("1{}e-1000000000", "0".repeat(1_000_000));
        assert_eq!(Number::decimal(&many_zeros).unwrap().as_i64(), None);
        assert_eq!(int_of(&format!("1{}e-1000000", "0".repeat(1_000_000))), Some(1));
    }

    fn int_of(text: &str) -> Option<i64> {
        Number::decimal(text).unwrap().as_i64()
    }
}
