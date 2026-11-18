//! The macOS [`SystemProbe`]: the OS version from `sysctl`, and an `FSEvents` stream started and stopped (KNSH-014).

use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use super::fsevents::FsEventStreams;
use crate::error::{Operation, PlatformError};
use crate::file_events::{FileEvent, FileEventSink, FileEvents};
use crate::probe::SystemProbe;

/// Reads system facts for the capability probe from the running system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProbes;

impl SystemProbes {
    /// The system probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SystemProbe for SystemProbes {
    fn os_major_version(&self) -> Result<u32, PlatformError> {
        // "15.1.1": the product version, which is the real one even for binaries built against an old SDK.
        let mut buffer = [0u8; 32];
        let mut length = buffer.len();
        // SAFETY: the name is a NUL-terminated C string; `buffer` is writable for `length` bytes and `length` is a
        // valid in/out pointer; no new value is set (null pointer, size 0).
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.osproductversion".as_ptr(),
                buffer.as_mut_ptr().cast(),
                &raw mut length,
                ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(PlatformError::Os {
                operation: Operation::SystemInfo,
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO),
            });
        }
        let written = buffer.get(..length.min(buffer.len())).unwrap_or_default();
        parse_major(written).ok_or(PlatformError::Os {
            operation: Operation::SystemInfo,
            errno: libc::EINVAL,
        })
    }

    fn check_file_events(&self) -> Result<(), PlatformError> {
        check_fsevents()
    }
}

/// The major version from a product version such as `b"15.1.1\0"`: the digits before the first dot (or the end).
fn parse_major(version: &[u8]) -> Option<u32> {
    let text = version.split(|&b| b == 0).next()?;
    let major = text.split(|&b| b == b'.').next()?;
    if major.is_empty() || major.len() > 4 || !major.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(major).ok()?.parse().ok()
}

// --- FSEvents -------------------------------------------------------------------------------------------------------

/// Receives events for the probe stream and ignores them: the probe only checks that a stream starts.
struct IgnoreEvents;

impl FileEventSink for IgnoreEvents {
    fn deliver(&self, _events: &[FileEvent]) {}
}

/// Creates a stream on `/` from now on, starts it on a private dispatch queue, then stops, invalidates and releases
/// everything (dropping the stream). No event is read: events arrive only after the start, and the stream is stopped
/// at once.
fn check_fsevents() -> Result<(), PlatformError> {
    let stream = FsEventStreams::new().watch(&[PathBuf::from("/")], Duration::from_secs(1), Arc::new(IgnoreEvents))?;
    drop(stream);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_major_version() {
        assert_eq!(parse_major(b"15.1.1\0\0\0"), Some(15));
        assert_eq!(parse_major(b"26.0"), Some(26));
        assert_eq!(parse_major(b"14\0"), Some(14));
        for bad in [&b""[..], b"\0", b".1", b"x.1", b"15a.1", b"123456.0", b"-1.0"] {
            assert_eq!(parse_major(bad), None, "{bad:?}");
        }
    }

    // The real checks on this machine: macOS 14 or later, and FSEvents works for an ordinary user.
    #[test]
    fn probes_this_machine() {
        let probes = SystemProbes::new();
        assert!(probes.os_major_version().unwrap() >= 14);
        probes.check_file_events().unwrap();
    }

    // The real bounded runner: `sandbox-exec` with an allow-all profile runs `/usr/bin/true` for an ordinary user.
    #[test]
    fn runs_sandbox_exec_on_this_machine() {
        let processes = crate::macos::SystemProcesses::new();
        let clock = crate::macos::SystemClock::new();
        let request = crate::SpawnRequest::new(crate::probe::SANDBOX_EXEC)
            .arg("-p")
            .arg("(version 1)(allow default)")
            .arg("/usr/bin/true");
        let status = crate::probe::run_to_exit(&processes, &clock, &request, std::time::Duration::from_secs(10));
        assert_eq!(status, Ok(crate::ExitStatus::Exited(0)));
    }
}
