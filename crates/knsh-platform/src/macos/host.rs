//! The host's name and a terminal's device name, for the prompt escapes of the interactive shell (KNSH-107): bash's
//! `\h` and `\H` read `gethostname` once at start-up, `\l` the base name of `ttyname(0)`.

use std::ffi::{CStr, OsStr};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::process::SharedFd;

/// Bash's buffer for the host name (`MAXHOSTNAMELEN`, 256 bytes on macOS).
const HOST_NAME_BUFFER: usize = 256;

/// Buffer for a terminal's device path (`/dev/ttys003`); macOS's `ttyname_r` needs at most `MAXPATHLEN`.
const TERMINAL_NAME_BUFFER: usize = 1024;

/// This host's name (`gethostname`), as bash's `\H` shows it; `None` if the system gives none.
#[must_use]
pub fn host_name() -> Option<String> {
    let mut buffer = [0_u8; HOST_NAME_BUFFER];
    // SAFETY: `buffer` is valid and writable for `buffer.len()` bytes during the call.
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return None;
    }
    // The name may fill the buffer without a terminator; the last byte is then dropped, as bash bounds it.
    if let Some(last) = buffer.last_mut() {
        *last = 0;
    }
    let name = CStr::from_bytes_until_nul(&buffer).ok()?;
    let name = String::from_utf8_lossy(name.to_bytes()).into_owned();
    (!name.is_empty()).then_some(name)
}

/// The device path of terminal `fd` (`ttyname_r`), as bash's `\l` reads it; `None` when `fd` is not a terminal.
#[must_use]
pub fn terminal_name(fd: &SharedFd) -> Option<PathBuf> {
    let mut buffer = [0_u8; TERMINAL_NAME_BUFFER];
    // SAFETY: `buffer` is valid and writable for `buffer.len()` bytes during the call; `fd` is held open.
    if unsafe { libc::ttyname_r(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return None;
    }
    let name = CStr::from_bytes_until_nul(&buffer).ok()?;
    Some(PathBuf::from(OsStr::from_bytes(name.to_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-107: `\h` needs the host's name; a pipe is no terminal.
    #[test]
    fn host_has_a_name_and_a_pipe_has_no_terminal_name() {
        assert!(host_name().is_some_and(|name| !name.is_empty()));
        let (read, _write) = std::io::pipe().unwrap();
        let fd = SharedFd::new(std::os::fd::OwnedFd::from(read));
        assert_eq!(terminal_name(&fd), None);
    }
}
