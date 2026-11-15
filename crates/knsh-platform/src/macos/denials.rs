//! [`DenialLog`] on macOS: `log stream` for the denials, `sandbox-exec` for the canary (KNSH-047).
//!
//! Both tools run as the user who runs `knshd`, without admin rights (KNSH-025, C2), with an empty environment and
//! standard input and error on `/dev/null`. Only safe standard-library calls are used: `std::process` keeps each
//! child unreaped until it is waited for, so killing it can never reach a reused pid (CLAUDE.md "Concurrency").

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use knsh_core::CanonicalPath;

use crate::engine_dirs::FILE_MODE;
use crate::error::{Operation, PlatformError};
use crate::probe::SANDBOX_EXEC;
use crate::violation::{
    CanaryNonce, DenialLog, DenialStream, LOG_TOOL, MAX_ENTRY_LEN, STREAM_PREDICATE, StreamStopper, canary_profile,
};

/// The program the canary runs: it reads the denied file, which logs one denial and fails.
const CANARY_READER: &str = "/bin/cat";

/// The canary file's name in its directory.
const CANARY_FILE: &str = "sandbox-canary";

/// How long the canary process may take. It is one denied read; the bound only matters if something hangs.
const CANARY_TIMEOUT: Duration = Duration::from_secs(2);

/// How often a canary wait checks whether the process has ended.
const POLL: Duration = Duration::from_millis(10);

/// Takes a lock even if a thread panicked while holding it: the only state is a child handle.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Sandbox denials from the unified log.
#[derive(Debug, Clone)]
pub struct UnifiedLogDenials {
    /// The canary file: canonical, because Seatbelt matches resolved paths.
    canary: CanonicalPath,
}

impl UnifiedLogDenials {
    /// A source whose canary file lives in `dir`, a private engine directory (the run directory).
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::Canonicalise`] if `dir` cannot be resolved, or
    /// [`PlatformError::NotCanonical`] if the resolved path is not usable.
    pub fn new(dir: &std::path::Path) -> Result<Self, PlatformError> {
        let dir =
            std::fs::canonicalize(dir).map_err(|error| PlatformError::from_io(Operation::Canonicalise, &error))?;
        let canary = CanonicalPath::new(dir.join(CANARY_FILE)).map_err(PlatformError::NotCanonical)?;
        Ok(Self { canary })
    }

    /// Creates the canary file owner-only if it is missing. Its content is irrelevant: only the denied read is.
    fn ensure_canary_file(&self) -> Result<(), PlatformError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(FILE_MODE)
            .open(self.canary.as_path())
            .map_err(|error| PlatformError::from_io(Operation::SandboxLog, &error))?;
        // A denied access to a missing path is not logged (KNSH-025); give the file a byte so `cat` really reads.
        if file
            .metadata()
            .map_err(|error| PlatformError::from_io(Operation::SandboxLog, &error))?
            .len()
            == 0
        {
            file.write_all(b"k")
                .map_err(|error| PlatformError::from_io(Operation::SandboxLog, &error))?;
        }
        Ok(())
    }
}

impl DenialLog for UnifiedLogDenials {
    fn open(&self) -> Result<Box<dyn DenialStream>, PlatformError> {
        let mut child = Command::new(LOG_TOOL)
            .args(["stream", "--style", "ndjson", "--predicate", STREAM_PREDICATE])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| PlatformError::from_io(Operation::SandboxLog, &error))?;
        let Some(stdout) = child.stdout.take() else {
            reap(&mut child);
            return Err(PlatformError::Os {
                operation: Operation::SandboxLog,
                errno: libc::EPIPE,
            });
        };
        Ok(Box::new(LogStream {
            reader: BufReader::new(stdout),
            child: Arc::new(Mutex::new(child)),
        }))
    }

    fn trigger_canary(&self, nonce: &CanaryNonce) -> Result<(), PlatformError> {
        self.ensure_canary_file()?;
        let profile = canary_profile(&self.canary, nonce);
        let profile = OsStr::from_bytes(&profile);
        let mut child = Command::new(SANDBOX_EXEC)
            .arg("-p")
            .arg(profile)
            .arg(CANARY_READER)
            .arg(self.canary.as_path())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| PlatformError::from_io(Operation::SandboxLog, &error))?;
        // The read is denied, so `cat` fails; how it exits does not matter, only that it ends.
        let deadline = Instant::now() + CANARY_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() < deadline => thread::sleep(POLL),
                Ok(None) => {
                    reap(&mut child);
                    return Err(PlatformError::Os {
                        operation: Operation::SandboxLog,
                        errno: libc::ETIMEDOUT,
                    });
                }
                Err(error) => {
                    reap(&mut child);
                    return Err(PlatformError::from_io(Operation::Wait, &error));
                }
            }
        }
    }
}

/// Kills a child that is still running and reaps it. Best effort: both only fail if it already ended.
fn reap(child: &mut Child) {
    if matches!(child.try_wait(), Ok(None)) {
        let _ = child.kill();
    }
    let _ = child.wait();
}

/// One running `log stream`.
struct LogStream {
    reader: BufReader<ChildStdout>,
    /// Shared with the stoppers; never locked while reading, so a stop is never blocked by a read.
    child: Arc<Mutex<Child>>,
}

impl DenialStream for LogStream {
    fn next_entry(&mut self) -> Result<Option<Vec<u8>>, PlatformError> {
        read_entry(&mut self.reader)
    }

    fn stopper(&self) -> Box<dyn StreamStopper> {
        Box::new(Stopper {
            child: Arc::clone(&self.child),
        })
    }
}

impl Drop for LogStream {
    /// The tool never outlives its stream: `log stream` would otherwise run until it next wrote a line.
    fn drop(&mut self) {
        reap(&mut lock(&self.child));
    }
}

/// Ends a [`LogStream`] by killing its tool: the reader then sees the end of its output.
struct Stopper {
    child: Arc<Mutex<Child>>,
}

impl StreamStopper for Stopper {
    fn stop(&self) {
        let mut child = lock(&self.child);
        // Still unreaped (the stream reaps it on drop), so the pid cannot have been reused.
        if matches!(child.try_wait(), Ok(None)) {
            let _ = child.kill();
        }
    }
}

/// Reads one line, without its newline. A line longer than [`MAX_ENTRY_LEN`] is consumed to its end and returned
/// empty, so memory stays bounded whatever the tool writes. `Ok(None)` at the end of the output.
fn read_entry(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, PlatformError> {
    let mut line = Vec::new();
    // Once set, `line` stays empty: the rest of the overlong line is consumed without being kept.
    let mut too_long = false;
    loop {
        let buffer = reader
            .fill_buf()
            .map_err(|error| PlatformError::from_io(Operation::SandboxLog, &error))?;
        if buffer.is_empty() {
            // End of output: a last line without a newline still counts.
            return Ok((!line.is_empty() || too_long).then_some(line));
        }
        let (chunk, found) = match buffer.iter().position(|&byte| byte == b'\n') {
            Some(end) => (&buffer[..end], Some(end + 1)),
            None => (buffer, None),
        };
        if !too_long {
            if line.len() + chunk.len() > MAX_ENTRY_LEN {
                too_long = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        let consumed = found.unwrap_or(buffer.len());
        reader.consume(consumed);
        if found.is_some() {
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn reads_lines_and_skips_overlong_ones() {
        let mut input = b"first\n".to_vec();
        input.extend(vec![b'x'; MAX_ENTRY_LEN + 1]);
        input.extend_from_slice(b"\nlast");
        let mut reader = BufReader::with_capacity(7, Cursor::new(input));
        assert_eq!(read_entry(&mut reader).unwrap(), Some(b"first".to_vec()));
        assert_eq!(read_entry(&mut reader).unwrap(), Some(Vec::new()));
        assert_eq!(read_entry(&mut reader).unwrap(), Some(b"last".to_vec()));
        assert_eq!(read_entry(&mut reader).unwrap(), None);
    }

    #[test]
    fn exact_limit_is_kept() {
        let mut input = vec![b'y'; MAX_ENTRY_LEN];
        input.push(b'\n');
        let mut reader = BufReader::new(Cursor::new(input));
        assert_eq!(
            read_entry(&mut reader).unwrap().map(|line| line.len()),
            Some(MAX_ENTRY_LEN)
        );
    }
}
