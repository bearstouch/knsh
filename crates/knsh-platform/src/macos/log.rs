//! Unified logging, subsystem `knsh` (`specs/08-integrations/macos-services.md`).
//!
//! `os_log` is a C macro, so this module does what the macro expands to: it creates a log object with
//! `os_log_create` and calls `_os_log_impl` with a constant `%{public}s` format and a hand-encoded argument buffer
//! holding one string pointer. The text is rendered by [`crate::log::render`] from a static message and typed
//! fields, so it cannot carry command output or secrets, and is therefore safe to mark `public` (otherwise the
//! system would show `<private>` for it).
//!
//! Read entries back with `log show --predicate 'subsystem == "knsh"'`.

use std::ffi::{CStr, CString, c_char, c_void};

use crate::log::{Field, Level, SystemLog, render};

/// The subsystem every engine entry is filed under.
const SUBSYSTEM: &CStr = c"knsh";

/// Longest rendered line passed to the system, in bytes. Unified logging truncates long entries anyway; capping here
/// bounds the allocation for any field list.
const MAX_LINE: usize = 1024;

/// The format string. `_os_log_impl` records it as an offset into the calling binary image, which the log tools read
/// back later, so it lives in the dedicated `__oslogstring` section exactly where the `os_log` macro puts it.
#[unsafe(link_section = "__TEXT,__oslogstring,cstring_literals")]
static FORMAT: [u8; 11] = *b"%{public}s\0";

// `os_log_type_t` values from `<os/log.h>`.
const OS_LOG_TYPE_DEFAULT: u8 = 0x00;
const OS_LOG_TYPE_INFO: u8 = 0x01;
const OS_LOG_TYPE_DEBUG: u8 = 0x02;
const OS_LOG_TYPE_ERROR: u8 = 0x10;
const OS_LOG_TYPE_FAULT: u8 = 0x11;

// Argument-buffer encoding used by the `os_log` macro (`<os/trace_base.h>`, `os_log_fmt_*`): a summary byte, an
// argument count, then per argument a descriptor byte, a size byte and the value.
/// Summary flag: the buffer holds a non-scalar argument (a pointer).
const SUMMARY_HAS_NON_SCALAR: u8 = 0x02;
/// Descriptor: string argument (type 2, high nibble) marked public (flag 2, low nibble).
const DESCRIPTOR_PUBLIC_STRING: u8 = 0x22;
/// Size of the argument buffer: summary, count, descriptor and size bytes, then one 8-byte pointer.
const ARG_BUFFER_LEN: u32 = 12;

// libSystem (libsystem_trace) is linked into every macOS binary by default.
unsafe extern "C" {
    /// The Mach-O header of the image that contains the caller, provided by the linker.
    static __dso_handle: u8;
    fn os_log_create(subsystem: *const c_char, category: *const c_char) -> *mut c_void;
    fn _os_log_impl(dso: *const c_void, log: *mut c_void, kind: u8, format: *const c_char, buf: *mut u8, size: u32);
}

/// Writes to unified logging under subsystem `knsh` and one category.
#[derive(Debug)]
pub struct UnifiedLog {
    /// The `os_log_t` returned by `os_log_create`. Never null; never released (log objects live for the process).
    handle: *mut c_void,
}

// SAFETY: Apple documents `os_log_t` objects as thread-safe: they may be used from any thread concurrently. The
// pointer is never freed, so it cannot dangle when moved or shared.
unsafe impl Send for UnifiedLog {}
// SAFETY: as above; `log` only reads `handle`.
unsafe impl Sync for UnifiedLog {}

impl UnifiedLog {
    /// A log for `category` (for example `c"daemon"`) under subsystem `knsh`. The category is a compile-time constant
    /// so that it, too, cannot carry runtime data.
    #[must_use]
    pub fn new(category: &'static CStr) -> Self {
        // SAFETY: both arguments are valid NUL-terminated strings that outlive the call (`'static`). `os_log_create`
        // never returns null: on failure it returns the shared disabled log object.
        let handle = unsafe { os_log_create(SUBSYSTEM.as_ptr(), category.as_ptr()) };
        Self { handle }
    }
}

fn os_log_type(level: Level) -> u8 {
    match level {
        Level::Debug => OS_LOG_TYPE_DEBUG,
        Level::Info => OS_LOG_TYPE_INFO,
        Level::Notice => OS_LOG_TYPE_DEFAULT,
        Level::Error => OS_LOG_TYPE_ERROR,
        Level::Fault => OS_LOG_TYPE_FAULT,
    }
}

/// Turns the rendered line into a C string: interior NUL bytes (only possible from a static string in the source)
/// are dropped and the length is capped at a character boundary.
fn to_c_line(line: String) -> CString {
    let mut bytes = line.into_bytes();
    bytes.retain(|&b| b != 0);
    if bytes.len() > MAX_LINE {
        let mut end = MAX_LINE;
        // Back up to the start of a UTF-8 character (continuation bytes are 0b10xx_xxxx).
        while end > 0 && bytes[end] & 0xC0 == 0x80 {
            end -= 1;
        }
        bytes.truncate(end);
    }
    // No NUL remains, so this cannot fail; an empty string is the harmless fallback.
    CString::new(bytes).unwrap_or_default()
}

impl SystemLog for UnifiedLog {
    fn log(&self, level: Level, message: &'static str, fields: &[Field]) {
        let line = to_c_line(render(message, fields));
        let pointer = (line.as_ptr() as usize as u64).to_ne_bytes();
        let mut buf = [0u8; ARG_BUFFER_LEN as usize];
        buf[0] = SUMMARY_HAS_NON_SCALAR;
        buf[1] = 1; // one argument
        buf[2] = DESCRIPTOR_PUBLIC_STRING;
        buf[3] = 8; // pointer size
        buf[4..].copy_from_slice(&pointer);
        // SAFETY: `__dso_handle` is the linker-provided header of this image; only its address is taken. `handle`
        // is a live `os_log_t`. `FORMAT` is a static NUL-terminated string in this image. `buf` is a correctly
        // encoded argument buffer of `ARG_BUFFER_LEN` bytes whose one argument points at `line`, a NUL-terminated
        // string that outlives the call. `_os_log_impl` copies everything it needs before returning.
        unsafe {
            _os_log_impl(
                (&raw const __dso_handle).cast(),
                self.handle,
                os_log_type(level),
                FORMAT.as_ptr().cast(),
                buf.as_mut_ptr(),
                ARG_BUFFER_LEN,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::Value;

    #[test]
    fn c_line_drops_nul_and_caps_length_on_a_char_boundary() {
        assert_eq!(to_c_line("a\0b".into()).as_bytes(), b"ab");
        let long = "é".repeat(MAX_LINE); // 2 bytes each
        let capped = to_c_line(long);
        assert!(capped.as_bytes().len() <= MAX_LINE);
        assert!(std::str::from_utf8(capped.as_bytes()).is_ok());
    }

    // Writing must not crash or block. Whether the entry reaches `log show` is checked manually (KNSH-007 notes).
    #[test]
    fn writes_entries_at_every_level() {
        let log = UnifiedLog::new(c"test");
        // `Fault` is left out: it can trigger diagnostic collection on the test machine.
        for level in [Level::Debug, Level::Info, Level::Notice, Level::Error] {
            log.log(level, "knsh-platform unit test", &[Field::new("n", Value::U64(1))]);
        }
    }
}
