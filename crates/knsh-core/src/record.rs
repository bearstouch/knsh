//! The execution record model (`specs/05-models/execution-record.md`, KNSH-016).
//!
//! An [`ExecutionRecord`] is what the record store keeps for one command line. Its text fields are
//! [`Redacted`] or already-typed values ([`CanonicalPath`], IDs, timestamps), so no constructor here takes a raw
//! secret-bearing `String` (FR-REC-11) and nothing in a record prints its command by accident (NFR-PRIV-02).
//!
//! The fields every record has (the human telemetry set of FR-REC-09: `command`, `cwd`, times and `exit_code`) are
//! plain members; the fields only agent records carry are grouped in [`RecordDetails`], so the store can drop them
//! as one unit for human sessions. `sandbox_violations` is filled by the violation reader (KNSH-047). Fields that
//! later phases fill (`argv`, `decision`, `children`,
//! `files_changed`, `network`, …) have columns in the store's schema but no member here yet: they are always empty
//! in phase 1.

use std::fmt;
use std::str::FromStr;

use crate::error::CoreError;
use crate::id::{CheckpointId, RecordId, SessionId};
use crate::path::CanonicalPath;
use crate::redacted::Redacted;
use crate::session::Actor;
use crate::time::Timestamp;
use crate::violation::SandboxViolation;

/// One of a command's two recorded output streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

impl OutputStream {
    /// Both streams, in a fixed order.
    pub const ALL: [Self; 2] = [Self::Stdout, Self::Stderr];

    /// The wire and storage form: `stdout` or `stderr`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

impl fmt::Display for OutputStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OutputStream {
    type Err = CoreError;

    /// Parses `stdout` or `stderr` exactly.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidOutputStream`] for anything else.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stdout" => Ok(Self::Stdout),
            "stderr" => Ok(Self::Stderr),
            _ => Err(CoreError::InvalidOutputStream),
        }
    }
}

/// The fields of an execution record that only agent records carry.
///
/// A human telemetry record keeps none of them (FR-REC-09): the store replaces them with
/// [`RecordDetails::default`] before writing, whatever the caller supplied.
#[derive(Debug, Clone, Default)]
pub struct RecordDetails {
    /// The original line when a rewrite was applied (FR-REC-04), already redacted.
    pub rewritten_from: Option<Redacted<String>>,
    /// Exit code of each command in the last pipeline.
    pub pipestatus: Vec<i32>,
    /// The signal that ended the line, such as `SIGKILL`.
    pub signal: Option<String>,
    /// Sandbox profile name and a hash of the compiled profile.
    pub sandbox_profile: Option<String>,
    /// Names of the secrets injected into the line, never their values (FR-REC-11).
    pub secrets_injected: Vec<String>,
    /// The checkpoint holding the line's pre-images.
    pub checkpoint_id: Option<CheckpointId>,
    /// Denials the system reported for the line, best effort (FR-SBX-08, KNSH-047). Late ones are appended after
    /// the record is written.
    pub sandbox_violations: Vec<SandboxViolation>,
}

impl RecordDetails {
    /// Whether no field is set, as for every human record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let Self {
            rewritten_from,
            pipestatus,
            signal,
            sandbox_profile,
            secrets_injected,
            checkpoint_id,
            sandbox_violations,
        } = self;
        rewritten_from.is_none()
            && pipestatus.is_empty()
            && signal.is_none()
            && sandbox_profile.is_none()
            && secrets_injected.is_empty()
            && checkpoint_id.is_none()
            && sandbox_violations.is_empty()
    }
}

/// One execution record.
///
/// # Invariants
///
/// - `command` is the line actually executed, with secrets redacted before it got here (FR-REC-04, FR-REC-05).
/// - `exit_code` is `None` when the line was denied or is still running.
#[derive(Debug, Clone)]
pub struct ExecutionRecord {
    /// Primary key; orders records by creation time.
    pub record_id: RecordId,
    /// The owning session.
    pub session_id: SessionId,
    /// Who ran the line. Decides which fields are kept (FR-REC-09).
    pub actor: Actor,
    /// The line, redacted.
    pub command: Redacted<String>,
    /// Working directory at start.
    pub cwd: CanonicalPath,
    /// When the line started.
    pub started_at: Timestamp,
    /// When the line ended, if it has.
    pub ended_at: Option<Timestamp>,
    /// The line's exit code; `None` when denied or still running.
    pub exit_code: Option<i32>,
    /// Agent-only fields; always empty for a human record once stored.
    pub details: RecordDetails,
}

/// What the store kept of one recorded output stream (FR-REC-06).
///
/// When the output was larger than the cap, its head and tail are kept and the middle is dropped: the stored bytes
/// are `head ++ tail`, `skipped` bytes were dropped between them, and they were dropped at offset `skipped_at` of
/// the stored bytes (the length of the head).
///
/// # Invariants
///
/// `stored + skipped == original` and `skipped_at <= stored`; `skipped == 0` implies `skipped_at == stored`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutputInfo {
    /// Bytes kept, the range `records.output` can read.
    pub stored: u64,
    /// Bytes the command wrote.
    pub original: u64,
    /// Bytes dropped between head and tail.
    pub skipped: u64,
    /// Offset in the stored bytes where the dropped bytes were.
    pub skipped_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_stream_round_trips_its_wire_form() {
        for stream in OutputStream::ALL {
            assert_eq!(stream.as_str().parse::<OutputStream>(), Ok(stream));
            assert_eq!(stream.to_string(), stream.as_str());
        }
        for bad in ["", "STDOUT", "stdin", "stdout "] {
            assert_eq!(
                bad.parse::<OutputStream>(),
                Err(CoreError::InvalidOutputStream),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn default_details_are_empty() {
        assert!(RecordDetails::default().is_empty());
        let details = RecordDetails {
            pipestatus: vec![0],
            ..RecordDetails::default()
        };
        assert!(!details.is_empty());
    }

    // NFR-PRIV-02: a record's derived Debug never shows the command.
    #[test]
    fn record_debug_never_prints_the_command() {
        let record = ExecutionRecord {
            record_id: RecordId::from_ulid(crate::Ulid::from_u128(1)),
            session_id: SessionId::from_ulid(crate::Ulid::from_u128(2)),
            actor: Actor::Human,
            command: Redacted::new(String::from("curl -H 'token: hunter2'")),
            cwd: CanonicalPath::new("/tmp").unwrap(),
            started_at: Timestamp::UNIX_EPOCH,
            ended_at: None,
            exit_code: None,
            details: RecordDetails {
                rewritten_from: Some(Redacted::new(String::from("hunter2"))),
                ..RecordDetails::default()
            },
        };
        let printed = format!("{record:?}");
        assert!(!printed.contains("hunter2"), "{printed}");
    }
}
