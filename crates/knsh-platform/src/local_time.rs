//! Local time for the native interpreter's `printf %(format)T` (KNSH-102).
//!
//! Bash converts a time to local time with `localtime` in the time zone its `TZ` variable names and formats it with
//! `strftime` into a 128-byte buffer (a result that does not fit is empty). The conversion reads the process's own
//! time zone, which a multithreaded process cannot change safely (`setenv` is not thread-safe), so the backend tells
//! the zone it converts in ([`LocalTime::time_zone`]) and the interpreter refuses a `TZ` that differs.

use std::ffi::OsString;

use crate::error::PlatformError;

/// Bash's buffer for one `%(…)T` conversion (`timebuf[128]`): a result needing more is empty.
pub const MAX_TIME_TEXT: usize = 127;

/// The clock and local-time conversion of `printf %(…)T`. Object safe: hold it as `Arc<dyn LocalTime>`.
pub trait LocalTime: Send + Sync {
    /// The current time in whole seconds since the Unix epoch (`time(NULL)`).
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::Clock`](crate::Operation::Clock).
    fn now(&self) -> Result<i64, PlatformError>;

    /// The time zone [`LocalTime::format`] converts in: this process's `TZ` environment variable, `None` when it is
    /// unset (the system's zone).
    fn time_zone(&self) -> Option<OsString>;

    /// `strftime(format)` of `localtime(seconds)`, with the time names of `locale` (`LC_TIME`: `%a`, `%c`): the bytes,
    /// empty when the result needs more than [`MAX_TIME_TEXT`] bytes or is empty, as in bash. A time `localtime`
    /// cannot convert is converted as 0, as bash does.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::LocalTime`](crate::Operation::LocalTime) when neither time could be
    /// converted, or no locale object could be made.
    fn format(&self, format: &str, seconds: i64, locale: &str) -> Result<Vec<u8>, PlatformError>;
}
