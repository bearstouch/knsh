//! The system resolver (`getaddrinfo`), through the standard library.

use std::net::{IpAddr, ToSocketAddrs};

use crate::error::{Operation, PlatformError};
use crate::resolver::{MAX_ADDRESSES, Resolver};

/// The system resolver: `getaddrinfo` as the standard library calls it, so it follows the system's DNS
/// configuration. It runs in `knshd`, which no sandbox profile confines.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl SystemResolver {
    /// The system resolver.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Resolver for SystemResolver {
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, PlatformError> {
        // The port is a placeholder: only the addresses are used. Duplicates (one per socket type) are dropped.
        let found = (name, 0).to_socket_addrs().map_err(|error| PlatformError::Os {
            operation: Operation::Resolve,
            errno: error.raw_os_error().unwrap_or(libc::EIO),
        })?;
        let mut addresses: Vec<IpAddr> = Vec::new();
        for address in found {
            if addresses.len() == MAX_ADDRESSES {
                break;
            }
            if !addresses.contains(&address.ip()) {
                addresses.push(address.ip());
            }
        }
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `localhost` resolves from the hosts file, without the network.
    #[test]
    fn resolves_localhost_to_loopback() {
        let addresses = SystemResolver::new().resolve("localhost").unwrap();
        assert_ne!(addresses.len(), 0);
        assert!(addresses.iter().all(IpAddr::is_loopback), "{addresses:?}");
    }

    #[test]
    fn unknown_name_is_an_error() {
        let error = SystemResolver::new().resolve("knsh-test.invalid").unwrap_err();
        assert!(matches!(
            error,
            PlatformError::Os {
                operation: Operation::Resolve,
                ..
            }
        ));
    }
}
