//! A fixed clock and a UTC formatter for `printf %(…)T` tests (KNSH-102).

use std::ffi::OsString;
use std::fmt::Write as _;

use crate::error::PlatformError;
use crate::local_time::{LocalTime, MAX_TIME_TEXT};

/// [`LocalTime`] at a fixed time, converting in UTC whatever the zone it reports. It formats `%Y %m %d %H %M %S %s
/// %F %T %%`; any other conversion is copied as written, which a test never relies on.
#[derive(Debug, Clone, Default)]
pub struct FakeLocalTime {
    now: i64,
    zone: Option<OsString>,
}

impl FakeLocalTime {
    /// A clock stopped at `now` (seconds since the epoch), in the system's zone (`TZ` unset).
    #[must_use]
    pub const fn new(now: i64) -> Self {
        Self { now, zone: None }
    }

    /// The same clock reporting `zone` as the process's `TZ`.
    #[must_use]
    pub fn with_time_zone(mut self, zone: &str) -> Self {
        self.zone = Some(zone.into());
        self
    }
}

/// The civil date of `days` since 1970-01-01 (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

impl LocalTime for FakeLocalTime {
    fn now(&self) -> Result<i64, PlatformError> {
        Ok(self.now)
    }

    fn time_zone(&self) -> Option<OsString> {
        self.zone.clone()
    }

    fn format(&self, format: &str, seconds: i64, _locale: &str) -> Result<Vec<u8>, PlatformError> {
        let (year, month, day) = civil(seconds.div_euclid(86_400));
        let within = seconds.rem_euclid(86_400);
        let (hour, minute, second) = (within / 3600, within % 3600 / 60, within % 60);
        let mut out = String::new();
        let mut chars = format.chars();
        while let Some(ch) = chars.next() {
            if ch != '%' {
                out.push(ch);
                continue;
            }
            let _ = match chars.next() {
                Some('Y') => write!(out, "{year}"),
                Some('m') => write!(out, "{month:02}"),
                Some('d') => write!(out, "{day:02}"),
                Some('H') => write!(out, "{hour:02}"),
                Some('M') => write!(out, "{minute:02}"),
                Some('S') => write!(out, "{second:02}"),
                Some('s') => write!(out, "{seconds}"),
                Some('F') => write!(out, "{year}-{month:02}-{day:02}"),
                Some('T') => write!(out, "{hour:02}:{minute:02}:{second:02}"),
                Some(other) if other != '%' => write!(out, "%{other}"),
                Some(_) | None => write!(out, "%"),
            };
        }
        if out.len() > MAX_TIME_TEXT {
            out.clear();
        }
        Ok(out.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_dates() {
        let time = FakeLocalTime::new(0);
        assert_eq!(
            time.format("%F %T|%s", 951_782_400 + 3661, "C").unwrap(),
            b"2000-02-29 01:01:01|951786061"
        );
        assert_eq!(time.format("%Y", -1, "C").unwrap(), b"1969");
    }
}
