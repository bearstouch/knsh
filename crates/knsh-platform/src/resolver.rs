//! Name resolution for the network proxy (KNSH-060, FR-NET-07).
//!
//! The proxy resolves every name itself, checks each address the resolver returns, and connects to an address it
//! checked, never resolving the name again. Commands never resolve names: the system resolver is denied inside every
//! sandbox profile (FR-NET-08). Behind this trait so the proxy's address checks are tested with a fake resolver
//! ([`crate::testing::FakeResolver`]) that answers what the test says, including answers that point at internal
//! addresses.

use std::net::IpAddr;

use crate::error::PlatformError;

/// The most addresses one resolution returns; the rest are ignored. Far above what real names have.
pub const MAX_ADDRESSES: usize = 32;

/// Resolves host names to addresses. Object safe: hold it as `Arc<dyn Resolver>`.
pub trait Resolver: Send + Sync {
    /// The addresses of `name`, in the order the system prefers them, at most [`MAX_ADDRESSES`]. `name` is a
    /// normalised host name, never an IP literal. An empty list means the name has no address.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::Resolve`](crate::Operation::Resolve) if the name could not be
    /// resolved (no such name, no network, a resolver failure).
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, PlatformError>;
}
