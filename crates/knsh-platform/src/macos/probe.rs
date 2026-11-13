//! The macOS [`SystemProbe`]: the OS version from `sysctl`, and an `FSEvents` stream started and stopped (KNSH-014).

use std::ffi::{c_char, c_void};
use std::ptr;

use crate::error::{Operation, PlatformError};
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

type CFAllocatorRef = *const c_void;
type CFArrayRef = *const c_void;
type CFStringRef = *const c_void;
type CFIndex = isize;
type FSEventStreamRef = *mut c_void;
type DispatchQueue = *mut c_void;
type FSEventStreamCallback = extern "C" fn(*const c_void, *mut c_void, usize, *mut c_void, *const u32, *const u64);

/// `CFArrayCallBacks`; only its address is used.
#[repr(C)]
struct CFArrayCallBacks {
    version: CFIndex,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
    equal: *const c_void,
}

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const K_FS_EVENT_STREAM_EVENT_ID_SINCE_NOW: u64 = u64::MAX;
const K_FS_EVENT_STREAM_CREATE_FLAG_NONE: u32 = 0;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeArrayCallBacks: CFArrayCallBacks;
    fn CFStringCreateWithCString(allocator: CFAllocatorRef, text: *const c_char, encoding: u32) -> CFStringRef;
    fn CFArrayCreate(
        allocator: CFAllocatorRef,
        values: *const *const c_void,
        count: CFIndex,
        callbacks: *const CFArrayCallBacks,
    ) -> CFArrayRef;
    fn CFRelease(object: *const c_void);
}

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventStreamCreate(
        allocator: CFAllocatorRef,
        callback: FSEventStreamCallback,
        context: *mut c_void,
        paths: CFArrayRef,
        since_when: u64,
        latency: f64,
        flags: u32,
    ) -> FSEventStreamRef;
    fn FSEventStreamSetDispatchQueue(stream: FSEventStreamRef, queue: DispatchQueue);
    fn FSEventStreamStart(stream: FSEventStreamRef) -> u8;
    fn FSEventStreamStop(stream: FSEventStreamRef);
    fn FSEventStreamInvalidate(stream: FSEventStreamRef);
    fn FSEventStreamRelease(stream: FSEventStreamRef);
}

// libdispatch is part of libSystem.
unsafe extern "C" {
    fn dispatch_queue_create(label: *const c_char, attributes: *const c_void) -> DispatchQueue;
    fn dispatch_release(object: *mut c_void);
}

/// Receives events for the probe stream and ignores them: the probe only checks that a stream starts.
extern "C" fn ignore_events(
    _stream: *const c_void,
    _info: *mut c_void,
    _count: usize,
    _paths: *mut c_void,
    _flags: *const u32,
    _ids: *const u64,
) {
}

fn file_events_error() -> PlatformError {
    PlatformError::Os {
        operation: Operation::FileEvents,
        // FSEvents reports failure as a null stream or `false`, without an errno.
        errno: libc::EIO,
    }
}

/// Creates a stream on `/` from now on, starts it on a private dispatch queue, then stops, invalidates and releases
/// everything. No event is read: events arrive only after the start, and the stream is stopped at once.
fn check_fsevents() -> Result<(), PlatformError> {
    // SAFETY: a static NUL-terminated string and the default allocator (null).
    let path = unsafe { CFStringCreateWithCString(ptr::null(), c"/".as_ptr(), K_CF_STRING_ENCODING_UTF8) };
    if path.is_null() {
        return Err(file_events_error());
    }
    let values = [path];
    // SAFETY: `values` holds one valid CFString for the duration of the call; the array retains it through
    // `kCFTypeArrayCallBacks`, whose address is taken without reading it.
    let paths = unsafe { CFArrayCreate(ptr::null(), values.as_ptr(), 1, &raw const kCFTypeArrayCallBacks) };
    // SAFETY: `path` came from a Create call and is released exactly once; the array holds its own reference.
    unsafe { CFRelease(path) };
    if paths.is_null() {
        return Err(file_events_error());
    }
    // SAFETY: valid callback and path array; a null context is allowed; the stream copies the array.
    let stream = unsafe {
        FSEventStreamCreate(
            ptr::null(),
            ignore_events,
            ptr::null_mut(),
            paths,
            K_FS_EVENT_STREAM_EVENT_ID_SINCE_NOW,
            1.0,
            K_FS_EVENT_STREAM_CREATE_FLAG_NONE,
        )
    };
    // SAFETY: created above and released exactly once.
    unsafe { CFRelease(paths) };
    if stream.is_null() {
        return Err(file_events_error());
    }
    // SAFETY: a static label; null attributes make a serial queue.
    let queue = unsafe { dispatch_queue_create(c"knsh.probe.fsevents".as_ptr(), ptr::null()) };
    if queue.is_null() {
        // SAFETY: the stream was created above, never scheduled, and is released exactly once.
        unsafe { FSEventStreamRelease(stream) };
        return Err(file_events_error());
    }
    // SAFETY: `stream` and `queue` are valid. The stream is scheduled once, then stopped (if it started),
    // invalidated and released in the order FSEvents requires, and the queue is released after the stream no longer
    // uses it.
    let started = unsafe {
        FSEventStreamSetDispatchQueue(stream, queue);
        let started = FSEventStreamStart(stream) != 0;
        if started {
            FSEventStreamStop(stream);
        }
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
        dispatch_release(queue);
        started
    };
    if started { Ok(()) } else { Err(file_events_error()) }
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

    // The real sandbox probe: `sandbox-exec` with the trivial profile exits 0 for an ordinary user.
    #[test]
    fn sandbox_probe_passes_on_this_machine() {
        let processes = crate::macos::SystemProcesses::new();
        let clock = crate::macos::SystemClock::new();
        crate::probe::check_sandbox(&processes, &clock, std::time::Duration::from_secs(10)).unwrap();
    }
}
