//! The crate's error type.

use std::fmt;

/// Why the proxy could not start or issue credentials. Messages name no host, credential or path (NFR-PRIV-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    /// The loopback listener could not be bound or configured.
    Listen,
    /// The accept loop's event queue could not be created or armed.
    EventQueue,
    /// The accept thread could not be started.
    Thread,
    /// The random source failed: no token was drawn.
    Random,
    /// The credential table is full ([`crate::MAX_CREDENTIALS`]).
    TooManyCredentials,
}

impl ProxyError {
    /// A fixed name for logs.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Listen => "listen",
            Self::EventQueue => "event_queue",
            Self::Thread => "thread",
            Self::Random => "random",
            Self::TooManyCredentials => "too_many_credentials",
        }
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Listen => "the proxy could not listen on the loopback interface",
            Self::EventQueue => "the proxy's event queue failed",
            Self::Thread => "the proxy could not start a thread",
            Self::Random => "the random source failed",
            Self::TooManyCredentials => "too many live proxy credentials",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ProxyError {}
