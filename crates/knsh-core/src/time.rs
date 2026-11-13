//! UTC timestamps with microsecond precision.
//!
//! Records and events carry `started_at`, `ended_at` and similar fields as UTC microseconds
//! (`specs/05-models/execution-record.md`) and print them as RFC 3339 with exactly six fractional digits and a `Z`
//! suffix. The current time is an effect: callers read it from the injected clock and pass it in.

use std::fmt;
use std::str::FromStr;

use crate::error::CoreError;

const MICROS_PER_SECOND: u64 = 1_000_000;
const SECONDS_PER_DAY: u64 = 86_400;
const MICROS_PER_DAY: u64 = MICROS_PER_SECOND * SECONDS_PER_DAY;

/// Microseconds from the Unix epoch to 9999-12-31T23:59:59.999999Z, the last instant with a four-digit year.
const MAX_MICROS: u64 = 253_402_300_800 * MICROS_PER_SECOND - 1;

/// A UTC instant, in microseconds since 1970-01-01T00:00:00Z.
///
/// # Invariants
///
/// - Between 1970-01-01T00:00:00.000000Z and 9999-12-31T23:59:59.999999Z inclusive, so the text form always has a
///   four-digit year, as RFC 3339 requires. Instants before the epoch are refused: engine timestamps come from the
///   current clock and are never older than 1970.
/// - No time zone or leap seconds: always UTC, as a plain count.
/// - [`Display`](fmt::Display) yields `YYYY-MM-DDTHH:MM:SS.ffffffZ` (27 characters), e.g.
///   `2026-11-12T18:02:11.204913Z`. The text form sorts in the same order as the value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// The Unix epoch, 1970-01-01T00:00:00.000000Z.
    pub const UNIX_EPOCH: Self = Self(0);

    /// Builds a timestamp from microseconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// [`CoreError::TimestampOutOfRange`] after 9999-12-31T23:59:59.999999Z.
    pub const fn from_unix_micros(micros: u64) -> Result<Self, CoreError> {
        if micros > MAX_MICROS {
            return Err(CoreError::TimestampOutOfRange);
        }
        Ok(Self(micros))
    }

    /// Microseconds since the Unix epoch.
    #[must_use]
    pub const fn as_unix_micros(self) -> u64 {
        self.0
    }

    /// Milliseconds since the Unix epoch, rounded down; the time component of a ULID created at this instant.
    #[must_use]
    pub const fn as_unix_millis(self) -> u64 {
        self.0 / 1_000
    }
}

/// Converts days since 1970-01-01 to a proleptic Gregorian `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days` algorithm, restricted to non-negative day counts so that all arithmetic is
/// unsigned. It shifts the year to start on 1 March, so the leap day is the last day of the shifted year, and counts
/// in 400-year eras of 146 097 days.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    // 719 468 days separate 0000-03-01 (the start of era 0) from 1970-01-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097; // [0, 146096]
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365; // [0, 399]
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100); // [0, 365], from 1 March
    let shifted_month = (5 * day_of_year + 2) / 153; // [0, 11], March = 0
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1; // [1, 31]
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    }; // [1, 12]
    // January and February belong to the next calendar year in the shifted calendar.
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (year, month, day) = civil_from_days(self.0 / MICROS_PER_DAY);
        let micros_of_day = self.0 % MICROS_PER_DAY;
        let seconds_of_day = micros_of_day / MICROS_PER_SECOND;
        let fraction = micros_of_day % MICROS_PER_SECOND;
        let hour = seconds_of_day / 3_600;
        let minute = seconds_of_day / 60 % 60;
        let second = seconds_of_day % 60;
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{fraction:06}Z"
        )
    }
}

/// Converts a proleptic Gregorian date to days since 1970-01-01: the inverse of [`civil_from_days`], with the same
/// March-based year. `None` before 1970.
fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    // January and February count as months 10 and 11 of the previous shifted year.
    let shifted_year = if month <= 2 { year.checked_sub(1)? } else { year };
    let era = shifted_year / 400;
    let year_of_era = shifted_year - era * 400; // [0, 399]
    let shifted_month = if month > 2 { month - 3 } else { month + 9 }; // [0, 11], March = 0
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1; // [0, 365]
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year; // [0, 146096]
    (era * 146_097 + day_of_era).checked_sub(719_468)
}

/// The number of days in `month` of `year`.
const fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        2 if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Reads a non-empty run of ASCII digits as a number; `None` for anything else. Callers pass at most six digits, so
/// the value cannot overflow.
fn digits(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0u64, |acc, &byte| {
        byte.is_ascii_digit().then(|| acc * 10 + u64::from(byte - b'0'))
    })
}

impl FromStr for Timestamp {
    type Err = CoreError;

    /// Parses the engine's own RFC 3339 form: `YYYY-MM-DDTHH:MM:SS` followed by an optional `.` and one to six
    /// fractional digits, then `Z`. Nothing else is accepted: no offsets other than `Z`, no lowercase `t`/`z`, no
    /// leap second (`:60`), no more than microsecond precision. Clients filter records with the same text the
    /// engine sends them, so a stricter reader costs nothing and leaves no room for two readings of one instant.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidTimestamp`] for any other text or an impossible date (such as February 30th);
    /// [`CoreError::TimestampOutOfRange`] before 1970.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        // `YYYY-MM-DDTHH:MM:SS` is 19 bytes, then an optional fraction, then `Z`.
        let (Some(head), Some((&b'Z', rest))) = (bytes.get(..19), bytes.get(19..).and_then(<[u8]>::split_last)) else {
            return Err(CoreError::InvalidTimestamp);
        };
        let separators_ok = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')]
            .iter()
            .all(|&(index, expected)| head.get(index) == Some(&expected));
        if !separators_ok {
            return Err(CoreError::InvalidTimestamp);
        }
        // The separators are checked above, so each range is a fixed-width numeric field.
        let number =
            |range: std::ops::Range<usize>| head.get(range).and_then(digits).ok_or(CoreError::InvalidTimestamp);
        let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
        let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
        let fraction = match rest {
            [] => 0,
            // One to six digits, scaled to microseconds: `.5` is 500000.
            [b'.', fraction @ ..] if (1..=6).contains(&fraction.len()) => {
                let value = digits(fraction).ok_or(CoreError::InvalidTimestamp)?;
                (fraction.len()..6).fold(value, |value, _| value * 10)
            }
            _ => return Err(CoreError::InvalidTimestamp),
        };
        let date_ok = (1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month);
        if !date_ok || hour > 23 || minute > 59 || second > 59 {
            return Err(CoreError::InvalidTimestamp);
        }
        let days = days_from_civil(year, month, day).ok_or(CoreError::TimestampOutOfRange)?;
        let seconds = days * SECONDS_PER_DAY + hour * 3_600 + minute * 60 + second;
        Self::from_unix_micros(seconds * MICROS_PER_SECOND + fraction)
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64, micros: u64) -> Timestamp {
        Timestamp::from_unix_micros(seconds * MICROS_PER_SECOND + micros).unwrap()
    }

    #[test]
    fn timestamp_formats_utc_microseconds() {
        // The example from the story; 1794506531 is `date -u -j -f %Y-%m-%dT%H:%M:%S 2026-11-12T18:02:11 +%s`.
        assert_eq!(at(1_794_506_531, 204_913).to_string(), "2026-11-12T18:02:11.204913Z");
        // Always six fractional digits, zero-padded.
        assert_eq!(Timestamp::UNIX_EPOCH.to_string(), "1970-01-01T00:00:00.000000Z");
        assert_eq!(at(0, 1).to_string(), "1970-01-01T00:00:00.000001Z");
        assert_eq!(at(59, 999_999).to_string(), "1970-01-01T00:00:59.999999Z");
        // Leap days, century rules and year boundaries.
        assert_eq!(at(951_782_400, 0).to_string(), "2000-02-29T00:00:00.000000Z");
        assert_eq!(at(951_868_800, 0).to_string(), "2000-03-01T00:00:00.000000Z");
        assert_eq!(at(4_107_542_400, 0).to_string(), "2100-03-01T00:00:00.000000Z"); // 2100 is not a leap year
        assert_eq!(at(1_704_067_199, 999_999).to_string(), "2023-12-31T23:59:59.999999Z");
        assert_eq!(at(1_704_067_200, 0).to_string(), "2024-01-01T00:00:00.000000Z");
        // The upper bound.
        assert_eq!(
            Timestamp::from_unix_micros(MAX_MICROS).unwrap().to_string(),
            "9999-12-31T23:59:59.999999Z"
        );
        assert_eq!(format!("{:?}", at(0, 0)), "Timestamp(1970-01-01T00:00:00.000000Z)");
    }

    #[test]
    fn timestamp_rejects_values_beyond_year_9999() {
        assert_eq!(
            Timestamp::from_unix_micros(MAX_MICROS + 1),
            Err(CoreError::TimestampOutOfRange)
        );
        assert_eq!(
            Timestamp::from_unix_micros(u64::MAX),
            Err(CoreError::TimestampOutOfRange)
        );
    }

    #[test]
    fn timestamp_converts_units_and_orders_like_its_text() {
        let earlier = at(1_794_506_531, 204_913);
        let later = at(1_794_506_531, 204_914);
        assert_eq!(earlier.as_unix_micros(), 1_794_506_531_204_913);
        assert_eq!(earlier.as_unix_millis(), 1_794_506_531_204);
        assert!(earlier < later);
        assert!(earlier.to_string() < later.to_string());
    }

    // KNSH-016: `records.query` time filters read back exactly what the engine prints.
    #[test]
    fn timestamp_parses_its_own_text_form() {
        for ts in [
            Timestamp::UNIX_EPOCH,
            at(1_794_506_531, 204_913),
            at(951_782_400, 0),
            Timestamp::from_unix_micros(MAX_MICROS).unwrap(),
        ] {
            assert_eq!(ts.to_string().parse::<Timestamp>(), Ok(ts));
        }
        // Shorter fractions and no fraction at all.
        assert_eq!("1970-01-01T00:00:01Z".parse::<Timestamp>(), Ok(at(1, 0)));
        assert_eq!("1970-01-01T00:00:01.5Z".parse::<Timestamp>(), Ok(at(1, 500_000)));
        assert_eq!(
            "2026-11-12T18:02:11.204913Z".parse::<Timestamp>(),
            Ok(at(1_794_506_531, 204_913))
        );
    }

    #[test]
    fn timestamp_parse_rejects_anything_but_the_canonical_form() {
        for bad in [
            "",
            "2026-11-12",
            "2026-11-12T18:02:11",
            "2026-11-12T18:02:11+00:00",
            "2026-11-12t18:02:11Z",
            "2026-11-12T18:02:11z",
            "2026-11-12T18:02:11.Z",
            "2026-11-12T18:02:11.1234567Z",
            "2026-11-12T18:02:60Z",
            "2026-11-12T24:00:00Z",
            "2026-02-30T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "+026-11-12T18:02:11Z",
            "2026-11-12T18:02:11.12a4Z",
            "2026-11-12 18:02:11Z",
            "2026-11-12T18:02:11Zjunk",
        ] {
            assert_eq!(bad.parse::<Timestamp>(), Err(CoreError::InvalidTimestamp), "{bad}");
        }
        assert_eq!(
            "1969-12-31T23:59:59Z".parse::<Timestamp>(),
            Err(CoreError::TimestampOutOfRange)
        );
        assert_eq!("2000-02-29T00:00:00Z".parse::<Timestamp>(), Ok(at(951_782_400, 0)));
    }

    #[test]
    fn days_from_civil_inverts_civil_from_days() {
        for days in (0..(431 * 366)).step_by(7) {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), Some(days));
        }
    }

    #[test]
    fn civil_from_days_matches_every_day_of_a_leap_cycle() {
        // Walk day by day across 1970..2401 and compare with a naive calendar, covering every era boundary case.
        let (mut year, mut month, mut day) = (1970, 1, 1);
        for days in 0..(431 * 366) {
            assert_eq!(civil_from_days(days), (year, month, day), "day {days}");
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            let month_len = match month {
                2 if leap => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
            day += 1;
            if day > month_len {
                day = 1;
                month += 1;
                if month > 12 {
                    month = 1;
                    year += 1;
                }
            }
        }
    }
}
