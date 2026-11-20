//! The Endpoint Security descendant client: every exec inside an envelope, offered to `knshd` for a decision
//! (FR-AGT-13, decision 3, KNSH-094).
//!
//! On macOS 27 and later, `es_new_descendants_client` creates an Endpoint Security client scoped to a process
//! subtree, needing neither root nor privacy approval, but needing Apple's Endpoint Security entitlement. `knshd`
//! creates one per envelope ([`DescendantClients::watch`]) before it starts the envelope, and every exec the client
//! sees is handed to an [`ExecHandler`], whose [`ExecVerdict`] the backend sends back to the kernel before the
//! message's deadline. Deciding is `knshd`'s job; this module only carries the events and the answers.
//!
//! | Trait | Effect | macOS backend | Fake ([`testing`](crate::testing)) |
//! | --- | --- | --- | --- |
//! | [`DescendantClients`] | Check that a client can be created; create one per envelope | `SystemDescendantClients` (unavailable until verified) | `ScriptedDescendantClients` |
//!
//! # Failing closed
//!
//! A backend that cannot hand an event to its handler, or cannot read an event's fields, answers
//! [`ExecVerdict::Deny`]. A handler that answers late is the handler's failure, never an allow: `knshd`'s handler
//! answers by the deadline whatever its decision is doing.
//!
//! # Still open (`specs/09-reference/decisions.md`, still open 1 and 2)
//!
//! Whether Apple grants the entitlement, which events the client can authorise beyond exec, and what happens to
//! pending and later operations if `knshd` exits are verified on macOS 27 before they are relied on. Until then the
//! macOS backend reports itself unavailable, so `hello` keeps `sandbox: "seatbelt"` and envelopes alone confine
//! direct execution.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use crate::clock::Monotonic;
use crate::error::PlatformError;

/// The first macOS major version with the descendant client (decision 3). Below it the client is never tried.
pub const ENDPOINT_SECURITY_MIN_MAJOR: u32 = 27;

/// One exec inside a watched subtree, waiting for an answer. Holds what the kernel reported, unchecked: the handler
/// validates every field and denies what it cannot read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecEvent {
    /// The process that is calling `exec` (its pid survives the exec).
    pub pid: i32,
    /// Its process group. The envelope's leader is the one process whose `pid` equals its `group` when the envelope
    /// starts.
    pub group: i32,
    /// The executable about to run, as the kernel resolved it (symbolic links followed).
    pub executable: PathBuf,
    /// The new program's arguments, `argv[0]` included. `argv[0]` is chosen by the caller and never trusted.
    pub argv: Vec<OsString>,
    /// The working directory of the calling process, if the kernel reported one.
    pub cwd: Option<PathBuf>,
    /// The `PATH` in the new program's environment, if it has one: where names in the program's arguments resolve.
    pub path: Option<OsString>,
    /// When the answer must have reached the kernel, on the monotonic clock the backend was built with. A later
    /// answer is not waited for (the kernel's own deadline handling applies).
    pub deadline: Monotonic,
}

/// The answer to one [`ExecEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecVerdict {
    /// The exec goes ahead.
    Allow,
    /// The exec fails in the calling process (`EPERM`).
    Deny,
}

/// Decides the execs of one watched subtree. Called on the backend's own thread or queue; must answer before
/// [`ExecEvent::deadline`].
pub trait ExecHandler: Send + Sync {
    /// The verdict for `event`. Total: every failure is [`ExecVerdict::Deny`].
    fn exec(&self, event: ExecEvent) -> ExecVerdict;
}

/// A live descendant client. Dropping it deletes the client; no event reaches its handler afterwards.
pub trait DescendantClient: Send {}

/// Creates descendant clients. Object safe: hold it as `Arc<dyn DescendantClients>`.
pub trait DescendantClients: Send + Sync {
    /// Creates and deletes one client with no subscriptions, to show that clients can be created here (the capability
    /// probe, KNSH-094). Never decides anything.
    ///
    /// # Errors
    ///
    /// [`PlatformError::EndpointSecurityUnavailable`] when no client can be created (no entitlement, an older macOS,
    /// a backend not built yet), or another [`PlatformError`] for a call that failed.
    fn check(&self) -> Result<(), PlatformError>;

    /// Creates a client over the subtree `knshd` starts next, subscribed to authorisation of exec, sending every
    /// event to `handler`. The caller starts the envelope only after this returns, so no exec in it is missed.
    ///
    /// # Errors
    ///
    /// As [`check`](Self::check): no client was created, and the caller must not start the envelope as if one were.
    fn watch(&self, handler: Arc<dyn ExecHandler>) -> Result<Box<dyn DescendantClient>, PlatformError>;
}
