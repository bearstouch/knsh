//! What the shell tells its host when `cd` changes the working directory (KNSH-101; NFR-COMPAT-10).
//!
//! The interpreter does not know whether its output is a terminal or whether a session is being recorded: the host
//! does. So `cd` calls a [`DirectoryObserver`] after every change, and the host writes OSC 7 there (with [`Osc7`],
//! when the shell's output is a terminal, `specs/09-reference/defaults-and-limits.md`) and publishes `cwd.changed`
//! when the session is recorded (`specs/05-models/event.md`). A subshell's `cd` changes only the subshell, so it is
//! never reported.

use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

/// Told after `cd` changed the shell's working directory, once `PWD` and `OLDPWD` are set. Called on the thread
/// that evaluates the shell, so it must not block for long.
pub trait DirectoryObserver: Send + Sync {
    /// The working directory is now `cwd` (absolute, as `PWD` holds it: symbolic links kept unless `cd -P`).
    fn changed(&self, cwd: &Path);
}

/// A [`DirectoryObserver`] that writes OSC 7 (`ESC ] 7 ; file://host/path BEL`) to a terminal, the same sequence
/// `knsh`'s integration mode writes (KNSH-022).
pub struct Osc7 {
    /// The host name in the URL, as bytes.
    host: Vec<u8>,
    /// Where the sequence goes: the terminal.
    out: Mutex<Box<dyn Write + Send>>,
}

impl Osc7 {
    /// An observer writing OSC 7 for host `host` to `out`.
    #[must_use]
    pub fn new(host: impl Into<Vec<u8>>, out: Box<dyn Write + Send>) -> Self {
        Self {
            host: host.into(),
            out: Mutex::new(out),
        }
    }
}

impl std::fmt::Debug for Osc7 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Osc7").field("host", &self.host).finish_non_exhaustive()
    }
}

impl DirectoryObserver for Osc7 {
    fn changed(&self, cwd: &Path) {
        let sequence = osc7(&self.host, cwd.as_os_str().as_encoded_bytes());
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        // A terminal that went away is not the shell's error, as bash ignores a failed prompt write.
        let _ = out.write_all(sequence.as_bytes());
        let _ = out.flush();
    }
}

/// OSC 7 for the working directory `path` on `host`: `ESC ] 7 ; file://<host><path> BEL`, both percent-encoded so
/// no byte can end or change the URL (every byte outside `A-Z a-z 0-9 / . _ ~ -` as `%XX`).
#[must_use]
pub fn osc7(host: &[u8], path: &[u8]) -> String {
    format!("\x1b]7;file://{}{}\x07", percent_encode(host), percent_encode(path))
}

/// `bytes` with every byte outside `A-Z a-z 0-9 / . _ ~ -` written as `%XX` (upper-case hex).
fn percent_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len());
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'~' | b'-') {
            encoded.push(char::from(byte));
        } else {
            // Writing to a String cannot fail.
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // NFR-COMPAT-10: the same percent-encoded `file://host/path` URL as integration mode's marks (KNSH-022).
    #[test]
    fn osc7_percent_encodes_host_and_path() {
        assert_eq!(osc7(b"mac.local", b"/tmp/a b"), "\x1b]7;file://mac.local/tmp/a%20b\x07");
        assert_eq!(osc7(b"h", b"/x\x07\x1b\n%\xff"), "\x1b]7;file://h/x%07%1B%0A%25%FF\x07");
    }

    #[test]
    fn osc7_observer_writes_the_sequence() {
        let out = Shared::default();
        let observer = Osc7::new("mac", Box::new(out.clone()));
        observer.changed(Path::new("/Users/me/src"));
        assert_eq!(
            String::from_utf8(out.0.lock().unwrap().clone()).unwrap(),
            "\x1b]7;file://mac/Users/me/src\x07"
        );
    }
}
