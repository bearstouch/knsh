//! The macOS descendant client backend (KNSH-094): not bound yet, so it reports itself unavailable.
//!
//! `es_new_descendants_client` exists only on macOS 27 and later and only for a binary signed with Apple's Endpoint
//! Security entitlement, which has been applied for but not granted (decision 3, still open 1). Its exact
//! signature, which events it can authorise and what happens when `knshd` exits (still open 2) are verified on
//! macOS 27 before any code relies on them. Binding a guessed signature would put an unverified foreign call on the
//! decision path, so until then [`SystemDescendantClients`] creates no client: the probe keeps `sandbox:
//! "seatbelt"`, and envelopes alone confine direct execution (FR-AGT-31), with no error shown to the agent.
//!
//! What the binding must do once it exists, against the [`DescendantClients`] contract:
//!
//! - `check`: create a client with no subscriptions and delete it; any result but success is unavailable.
//! - `watch`: create the client before the envelope starts, subscribe to `ES_EVENT_TYPE_AUTH_EXEC`, and for each
//!   message build an [`ExecEvent`](crate::ExecEvent) (pid, process group, executable path, argument strings, working
//!   directory, `PATH` from the environment, deadline converted to the monotonic clock), call the handler on a
//!   queue of its own and respond with its verdict; any field that cannot be read is answered deny. Dropping the
//!   returned client deletes it.

use std::sync::Arc;

use crate::endpoint_security::{DescendantClient, DescendantClients, ExecHandler};
use crate::error::PlatformError;

/// The real backend. Today it never creates a client (module documentation).
#[derive(Debug, Default)]
pub struct SystemDescendantClients;

impl SystemDescendantClients {
    /// The backend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl DescendantClients for SystemDescendantClients {
    fn check(&self) -> Result<(), PlatformError> {
        Err(PlatformError::EndpointSecurityUnavailable)
    }

    fn watch(&self, _handler: Arc<dyn ExecHandler>) -> Result<Box<dyn DescendantClient>, PlatformError> {
        Err(PlatformError::EndpointSecurityUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint_security::{ExecEvent, ExecVerdict};

    struct AllowAll;

    impl ExecHandler for AllowAll {
        fn exec(&self, _event: ExecEvent) -> ExecVerdict {
            ExecVerdict::Allow
        }
    }

    // KNSH-094: until the binding is verified on macOS 27 with the entitlement, no client is ever created, so the
    // capability is never claimed.
    #[test]
    fn reports_unavailable_until_bound() {
        let clients = SystemDescendantClients::new();
        assert_eq!(clients.check(), Err(PlatformError::EndpointSecurityUnavailable));
        assert!(matches!(
            clients.watch(Arc::new(AllowAll)),
            Err(PlatformError::EndpointSecurityUnavailable)
        ));
    }
}
