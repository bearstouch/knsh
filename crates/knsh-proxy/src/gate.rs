//! What the proxy asks before it opens a tunnel, and where it reports what it refused.
//!
//! The proxy core authenticates the client and parses its request; whether the destination is allowed is the
//! [`ConnectionGate`]'s answer. Both protocols ask the same gate with the same [`Target`], so a SOCKS5 domain goes
//! through exactly the host rules and address checks of an HTTP CONNECT (FR-NET-05). The host rules, name resolution
//! and address checks (KNSH-060) implement this trait; until then `knshd` uses a gate that refuses every destination.
//!
//! IP literals are refused by the core before the gate is asked for a connection, unless
//! [`ConnectionGate::allows_ip_literal`] says the address is allowlisted (FR-NET-05).
//!
//! Every refusal, whatever the protocol and however early, is passed to the [`ProxyReport`] (FR-NET-09). A report
//! names the owner when the credentials were known, never the credentials themselves.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::credentials::Owner;
use crate::target::Target;

/// Why a connection was refused. Fixed names ([`Refusal::reason`]) for reports and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// No credentials were offered (HTTP without `Proxy-Authorization`, or SOCKS5 without username/password).
    MissingCredentials,
    /// The credentials were not live ones: unknown or revoked, wrong token, another scheme than Basic.
    UnknownCredentials,
    /// The request broke the protocol or a size limit; it was refused, not repaired (NFR-SEC-05, NFR-SEC-07).
    Malformed,
    /// A protocol the proxy does not serve: an HTTP method other than CONNECT (absolute-URI requests included), or
    /// SOCKS4.
    UnsupportedProtocol,
    /// A SOCKS5 command other than CONNECT: BIND or UDP ASSOCIATE (FR-NET-05).
    UnsupportedCommand,
    /// An IP-literal destination that is not allowlisted (FR-NET-05).
    IpLiteral,
    /// The host rules do not allow the destination for this command (FR-NET-02, FR-NET-03, FR-NET-04).
    HostNotAllowed,
    /// The name resolved to an address the checks refuse (FR-NET-07).
    AddressNotAllowed,
    /// The name could not be resolved.
    Unresolved,
    /// No host rules are in force, so every destination is refused (fail closed until KNSH-060).
    NoHostRules,
    /// The destination could not be reached.
    Unreachable,
    /// The destination did not answer within the connect timeout.
    Timeout,
    /// The proxy is serving its connection limit.
    Busy,
}

impl Refusal {
    /// A fixed name for reports and logs.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::MissingCredentials => "missing_credentials",
            Self::UnknownCredentials => "unknown_credentials",
            Self::Malformed => "malformed",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::UnsupportedCommand => "unsupported_command",
            Self::IpLiteral => "ip_literal",
            Self::HostNotAllowed => "host_not_allowed",
            Self::AddressNotAllowed => "address_not_allowed",
            Self::Unresolved => "unresolved",
            Self::NoHostRules => "no_host_rules",
            Self::Unreachable => "unreachable",
            Self::Timeout => "timeout",
            Self::Busy => "busy",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

/// Decides whether an authenticated command may reach a destination, and at which address (module documentation).
/// Object safe: `knshd` holds it as `Arc<dyn ConnectionGate>`.
pub trait ConnectionGate: Send + Sync {
    /// The address to connect to for `owner`'s request to reach `target`. The proxy connects to exactly this
    /// address and never resolves `target` again, so what was checked is what is reached (FR-NET-07).
    ///
    /// # Errors
    ///
    /// The [`Refusal`] if the destination is not allowed or cannot be resolved; the proxy refuses the request.
    fn check(&self, owner: &Owner, target: &Target) -> Result<SocketAddr, Refusal>;

    /// Whether the IP literal `ip` is allowlisted for `owner` (FR-NET-05). No by default: the core refuses IP
    /// literals without asking [`ConnectionGate::check`].
    fn allows_ip_literal(&self, owner: &Owner, ip: IpAddr) -> bool {
        let _ = (owner, ip);
        false
    }
}

/// A gate that refuses every destination with [`Refusal::NoHostRules`]: what `knshd` runs until host rules exist
/// (KNSH-060). With it, an envelope reaches no more than it did without a proxy: nothing outside its loopback ports.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseAll;

impl ConnectionGate for RefuseAll {
    fn check(&self, _owner: &Owner, _target: &Target) -> Result<SocketAddr, Refusal> {
        Err(Refusal::NoHostRules)
    }
}

/// How the client spoke to the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// HTTP (CONNECT, or a refused other method).
    Http,
    /// SOCKS5.
    Socks5,
    /// SOCKS4 (always refused).
    Socks4,
}

impl Protocol {
    /// A fixed name for reports and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::Socks4 => "socks4",
        }
    }
}

/// One refused connection, as reported (FR-NET-09). It never holds credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// Whose connection it was, when its credentials were live.
    pub owner: Option<Owner>,
    /// How the client spoke, once its first byte was read (not for a connection closed at the limit).
    pub protocol: Option<Protocol>,
    /// The destination, when the request got as far as naming a valid one.
    pub target: Option<Target>,
    /// Why it was refused.
    pub refusal: Refusal,
}

/// Where refusals go (module documentation). Called on the connection's thread; it must not block for long.
pub trait ProxyReport: Send + Sync {
    /// Reports one refused connection.
    fn denied(&self, denial: &Denial);
}
