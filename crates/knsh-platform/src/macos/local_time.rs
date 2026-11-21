//! [`LocalTime`] with `time`, `localtime_r` and `strftime_l` (KNSH-102).

use std::ffi::{CString, OsString};

use crate::error::{Operation, PlatformError};
use crate::local_time::{LocalTime, MAX_TIME_TEXT};

/// The system's clock and local time, in this process's time zone.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemLocalTime;

impl SystemLocalTime {
    /// The real backend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LocalTime for SystemLocalTime {
    fn now(&self) -> Result<i64, PlatformError> {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| PlatformError::Os {
                operation: Operation::Clock,
                errno: libc::EINVAL,
            })?;
        Ok(i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
    }

    fn time_zone(&self) -> Option<OsString> {
        std::env::var_os("TZ")
    }

    fn format(&self, format: &str, seconds: i64, locale: &str) -> Result<Vec<u8>, PlatformError> {
        let failure = |errno| PlatformError::Os {
            operation: Operation::LocalTime,
            errno,
        };
        let Ok(c_format) = CString::new(format) else {
            return Ok(Vec::new());
        };
        let convert = |seconds: i64| {
            let time = libc::time_t::try_from(seconds).ok()?;
            // SAFETY: an all-zero `tm` is a valid value of the plain C struct; `localtime_r` overwrites it.
            let mut tm: libc::tm = unsafe { std::mem::zeroed() };
            // SAFETY: `time` and `tm` are valid for the duration of the call; `localtime_r` is the thread-safe form.
            let converted = unsafe { libc::localtime_r(&raw const time, &raw mut tm) };
            (!converted.is_null()).then_some(tm)
        };
        let tm = convert(seconds)
            .or_else(|| convert(0))
            .ok_or_else(|| failure(libc::EOVERFLOW))?;
        let locale_name = CString::new(locale).unwrap_or_default();
        // SAFETY: `locale_name` is a valid NUL-terminated string; a null base asks for a new object, and a null
        // result (no such locale) is checked.
        let mut object = unsafe { libc::newlocale(libc::LC_TIME_MASK, locale_name.as_ptr(), std::ptr::null_mut()) };
        if object.is_null() {
            // SAFETY: as above, for the C locale, which always exists.
            object = unsafe { libc::newlocale(libc::LC_TIME_MASK, c"C".as_ptr(), std::ptr::null_mut()) };
        }
        if object.is_null() {
            return Err(failure(libc::ENOMEM));
        }
        let mut buffer = [0_u8; MAX_TIME_TEXT + 1];
        // SAFETY: `buffer` is writable for its full length, which is the size passed; `c_format` and `tm` are valid
        // for the call; `object` is a valid locale object, freed right after.
        let written = unsafe {
            let written = libc::strftime_l(
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                c_format.as_ptr(),
                &raw const tm,
                object,
            );
            libc::freelocale(object);
            written
        };
        Ok(buffer.get(..written).unwrap_or_default().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-102: `%s` is the time itself in any zone; a result past bash's buffer is empty.
    #[test]
    fn formats_like_strftime_with_bash_buffer() {
        let time = SystemLocalTime::new();
        assert_eq!(time.format("%s|%%", 86_400, "C").unwrap(), b"86400|%");
        assert_eq!(time.format(&"x".repeat(200), 0, "C").unwrap(), b"");
        assert!(time.now().unwrap() > 1_700_000_000);
    }
}
