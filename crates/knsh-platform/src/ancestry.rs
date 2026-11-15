//! Who a peer process is, and which processes it descends from (KNSH-048).
//!
//! `agent.sock` binds a connection that carries no valid session token to an agent session by asking whether the
//! peer descends from an envelope `knshd` started (FR-AGT-23). The peer is named by the kernel's **audit token** for
//! the connection (`getsockopt(LOCAL_PEERTOKEN)`, read through [`PeerCredentials`](crate::PeerCredentials)), and
//! the peer is named by a [`ProcessIdentity`]: its pid together with its pid version. A pid alone is never enough:
//! once a process exits its pid can be reused by an unrelated one, which would then inherit the dead process's place
//! in an envelope.
//!
//! The pid version is not a stable name for a *process*, though: the kernel gives a process a new pid version on
//! every `exec` as well as on every pid reuse (observed on macOS 26, KNSH-048). An envelope's root starts through
//! `knsh-exec`, which execs at least twice, so a root named by its pid version would stop matching as soon as it
//! started. Envelope roots and every ancestor on the walk are therefore named by a [`ProcessKey`]: the pid with the
//! kernel's 64-bit unique id, which survives `exec` and is never reused while the system runs. A [`ProcessIdentity`]
//! (from an audit token, or read by the supervisor while it holds the unreaped child) is turned into a key with
//! [`ProcessTree::resolve`], which checks the version against the live process in the same read.
//!
//! The walk itself is not here: [`ProcessTree`] answers one step at a time (the current identity of a pid, the key of
//! an identity, the parent of one key), so the matching logic in `knshd` is pure and tested against a fake tree.

use std::fmt;

use crate::error::PlatformError;

/// One process image: its pid and the pid version the kernel gave it, as an audit token names it. Two processes that
/// reuse the same pid have different versions, and so does one process before and after an `exec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessIdentity {
    pid: i32,
    version: i32,
}

impl ProcessIdentity {
    /// The process `pid` at pid version `version`.
    #[must_use]
    pub const fn new(pid: i32, version: i32) -> Self {
        Self { pid, version }
    }

    /// The pid. Meaningless without [`ProcessIdentity::version`]: never signal or match on it alone.
    #[must_use]
    pub const fn pid(self) -> i32 {
        self.pid
    }

    /// The pid version.
    #[must_use]
    pub const fn version(self) -> i32 {
        self.version
    }
}

/// One process for the life of the system, across `exec`: its pid and the kernel's unique id for it (`p_uniqueid`),
/// which is never reused while the system runs. Only a [`ProcessTree`] makes one, from a live process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessKey {
    pid: i32,
    unique_id: u64,
}

impl ProcessKey {
    /// The process `pid` with unique id `unique_id`. For [`ProcessTree`] backends and fakes.
    #[must_use]
    pub const fn new(pid: i32, unique_id: u64) -> Self {
        Self { pid, unique_id }
    }

    /// The pid. Meaningless without [`ProcessKey::unique_id`]: never signal or match on it alone.
    #[must_use]
    pub const fn pid(self) -> i32 {
        self.pid
    }

    /// The unique id.
    #[must_use]
    pub const fn unique_id(self) -> u64 {
        self.unique_id
    }
}

impl fmt::Display for ProcessIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.pid, self.version)
    }
}

/// The kernel's audit token for the process at the other end of a connection, as it was when the peer connected
/// (`audit_token_t`, eight 32-bit words). Only the fields `knshd` uses are exposed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuditToken([u32; 8]);

impl AuditToken {
    /// Word holding the effective uid (`audit_token_to_euid`).
    const EUID: usize = 1;
    /// Word holding the pid (`audit_token_to_pid`).
    const PID: usize = 5;
    /// Word holding the pid version (`audit_token_to_pidversion`).
    const PID_VERSION: usize = 7;

    /// The token from its eight raw words, as the kernel writes them.
    #[must_use]
    pub const fn from_raw(words: [u32; 8]) -> Self {
        Self(words)
    }

    /// A token naming `process`, run by `euid`, for fakes and tests. The other words are zero.
    #[must_use]
    pub const fn for_process(process: ProcessIdentity, euid: u32) -> Self {
        let mut words = [0; 8];
        words[Self::EUID] = euid;
        words[Self::PID] = process.pid.cast_unsigned();
        words[Self::PID_VERSION] = process.version.cast_unsigned();
        Self(words)
    }

    /// The peer's effective uid when it connected.
    #[must_use]
    pub const fn euid(self) -> u32 {
        self.0[Self::EUID]
    }

    /// The peer process: pid and pid version. Matching on this, never on the pid alone, is what makes a reused pid
    /// harmless.
    #[must_use]
    pub const fn process(self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.0[Self::PID].cast_signed(),
            version: self.0[Self::PID_VERSION].cast_signed(),
        }
    }
}

impl fmt::Debug for AuditToken {
    /// Only the fields that are used; the rest (audit session, user and group ids) never reach a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditToken")
            .field("process", &self.process())
            .field("euid", &self.euid())
            .finish()
    }
}

/// The process table, one step at a time. Object safe: hold it as `Arc<dyn ProcessTree>`.
///
/// Every answer is about a process that is alive at the moment of the call; a process that has exited (or whose pid
/// now belongs to another process) is an error, never a stale answer.
pub trait ProcessTree: Send + Sync {
    /// The identity of the live process `pid`. The supervisor reads it for an envelope's root while it still holds
    /// the unreaped child, so the pid cannot have been reused yet.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::ProcessInfo`](crate::Operation::ProcessInfo): `ESRCH` if no such
    /// process exists, or another `errno` if the kernel refuses to say.
    fn identity(&self, pid: i32) -> Result<ProcessIdentity, PlatformError>;

    /// The key of the live process `process` names: its pid at exactly that pid version. Version and unique id come
    /// from one read, so the key is of the very process image the identity named.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::ProcessInfo`](crate::Operation::ProcessInfo): `ESRCH` if no process
    /// has that pid at that version any more (it exited, its pid was reused, or it has exec'd since).
    fn resolve(&self, process: ProcessIdentity) -> Result<ProcessKey, PlatformError>;

    /// The parent of `child`, or `None` for a process with no parent to follow (`launchd`, the kernel).
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::ProcessInfo`](crate::Operation::ProcessInfo): `ESRCH` if `child` is no
    /// longer alive, or if its parent changed while it was being read. Callers treat every error as "not a
    /// descendant".
    fn parent(&self, child: ProcessKey) -> Result<Option<ProcessKey>, PlatformError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_token_exposes_pid_version_and_euid() {
        let mut words = [0u32; 8];
        words[1] = 501;
        words[5] = 4242;
        words[7] = 17;
        let token = AuditToken::from_raw(words);
        assert_eq!(token.process(), ProcessIdentity::new(4242, 17));
        assert_eq!(token.euid(), 501);
        assert_eq!(AuditToken::for_process(ProcessIdentity::new(4242, 17), 501), token);
    }

    // PID reuse: the same pid at another version is another process.
    #[test]
    fn identities_with_the_same_pid_differ_by_version() {
        assert_ne!(ProcessIdentity::new(10, 1), ProcessIdentity::new(10, 2));
        assert_eq!(ProcessIdentity::new(10, 2).to_string(), "10.2");
    }

    #[test]
    fn debug_shows_only_the_used_fields() {
        let rendered = format!("{:?}", AuditToken::from_raw([9, 501, 9, 9, 9, 42, 9, 3]));
        assert_eq!(
            rendered,
            "AuditToken { process: ProcessIdentity { pid: 42, version: 3 }, euid: 501 }"
        );
    }
}
