//! What the proxy asks before it opens a tunnel, and where it reports what it refused.
//!
//! The proxy core authenticates the client and parses its request; whether the destination is allowed is the
//! [`ConnectionGate`]'s answer. Both protocols ask the same gate with the same [`Target`], so a SOCKS5 domain goes
//! through exactly the host rules and address checks of an HTTP CONNECT (FR-NET-05). `knshd` runs
//! [`HostRules`](crate::HostRules), which applies the host rules, resolves names and checks addresses (KNSH-060);
//! [`RefuseAll`] refuses every destination.
//!
//! IP literals are refused by the core before the gate is asked for a connection, unless
//! [`ConnectionGate::allows_ip_literal`] says the address is allowlisted (FR-NET-05). Once a tunnel is granted, its
//! first bytes must be a TLS `ClientHello` naming the host unless [`ConnectionGate::checks_server_name`] says
//! otherwise (FR-NET-06).
//!
//! Every refusal, whatever the protocol and however early, is passed to the [`ProxyReport`], and so is every
//! destination a command was let through to (FR-NET-09). A report names the owner when the credentials were known,
//! never the credentials themselves.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;

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
    /// The host is in no host rule of the session (FR-NET-02, FR-NET-03).
    HostNotAllowed,
    /// `network.mode = "none"`: no host is reachable, only the loopback ports (FR-NET-04).
    NetworkOff,
    /// An approval host that the line's classes do not open and that was not approved (FR-NET-03); the envelope
    /// never reaches one.
    ApprovalRequired,
    /// An approval host asked for by a line holding dynamic code, which never reaches one (FR-NET-11, FR-POL-21).
    DynamicCode,
    /// The line receives a secret whose `hosts` do not list the destination (FR-SEC-03, FR-NET-10).
    SecretHosts,
    /// The name resolved to an address the checks refuse (FR-NET-07).
    AddressNotAllowed,
    /// The name could not be resolved.
    Unresolved,
    /// No host rules are in force for the owner (its scope was never set or was forgotten, or the gate is
    /// [`RefuseAll`]), so every destination is refused (fail closed).
    NoHostRules,
    /// The destination could not be reached.
    Unreachable,
    /// The destination did not answer within the connect timeout.
    Timeout,
    /// The proxy is serving its connection limit.
    Busy,
    /// After the tunnel was granted, the client sent bytes that are not a well-formed TLS `ClientHello` within the
    /// size limit, or closed before one was complete; the host is not configured for non-TLS use (FR-NET-06,
    /// [`crate::tls`]).
    NotTls,
    /// The `ClientHello` names no server, or offers Encrypted Client Hello, whose clear name is not the host the
    /// client means (FR-NET-06).
    ServerNameMissing,
    /// The `ClientHello` names another server than the requested host (FR-NET-06): a tunnel opened for one host is
    /// never used to talk to another.
    ServerNameMismatch,
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
            Self::NetworkOff => "network_off",
            Self::ApprovalRequired => "approval_required",
            Self::DynamicCode => "dynamic_code",
            Self::SecretHosts => "secret_hosts",
            Self::AddressNotAllowed => "address_not_allowed",
            Self::Unresolved => "unresolved",
            Self::NoHostRules => "no_host_rules",
            Self::Unreachable => "unreachable",
            Self::Timeout => "timeout",
            Self::Busy => "busy",
            Self::NotTls => "not_tls",
            Self::ServerNameMissing => "server_name_missing",
            Self::ServerNameMismatch => "server_name_mismatch",
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
    /// The addresses to connect to for `owner`'s request to reach `target`, in the order to try them. The proxy
    /// connects to one of exactly these addresses and never resolves `target` again, so what was checked is what is
    /// reached (FR-NET-07). An empty list is refused as [`Refusal::Unresolved`].
    ///
    /// # Errors
    ///
    /// The [`Refusal`] if the destination is not allowed or cannot be resolved; the proxy refuses the request.
    fn check(&self, owner: &Owner, target: &Target) -> Result<Vec<SocketAddr>, Refusal>;

    /// Whether the IP literal `ip` is allowlisted for `owner` on `port` (FR-NET-05). No by default: the core
    /// refuses IP literals without asking [`ConnectionGate::check`].
    fn allows_ip_literal(&self, owner: &Owner, ip: IpAddr, port: NonZeroU16) -> bool {
        let _ = (owner, ip, port);
        false
    }

    /// Whether `owner`'s tunnel to `target`, already allowed by [`ConnectionGate::check`], must start with a TLS
    /// `ClientHello` naming the host (FR-NET-06, [`crate::tls`]). Yes by default (fail closed); a gate says no only
    /// for a host explicitly configured for non-TLS use, or a destination the command could reach without the
    /// proxy anyway.
    fn checks_server_name(&self, owner: &Owner, target: &Target) -> bool {
        let _ = (owner, target);
        true
    }
}

/// A gate that refuses every destination with [`Refusal::NoHostRules`]. With it, an envelope reaches no more than
/// it would without a proxy: nothing outside its loopback ports.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseAll;

impl ConnectionGate for RefuseAll {
    fn check(&self, _owner: &Owner, _target: &Target) -> Result<Vec<SocketAddr>, Refusal> {
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

/// Where refusals and contacted destinations go (module documentation). Called on the connection's thread, for an
/// authenticated connection while the proxy's connection lock is held (so a report always precedes the revocation
/// that ends its line); it must not block, and must not call back into the proxy.
pub trait ProxyReport: Send + Sync {
    /// Reports one refused connection.
    fn denied(&self, denial: &Denial);

    /// Reports that `owner`'s connection to `target` passed every check and its tunnel is opening (FR-NET-09).
    fn contacted(&self, owner: &Owner, target: &Target);
}
