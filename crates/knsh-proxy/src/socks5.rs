//! A strict, hand-written SOCKS5 handshake reader (RFC 1928) with username/password authentication (RFC 1929), and
//! the proxy's replies (FR-NET-01, FR-NET-05, decision 14).
//!
//! The proxy serves one path through SOCKS5:
//!
//! 1. The greeting must offer username/password (`0x02`); the proxy picks it, or answers "no acceptable methods"
//!    (`0xFF`) and closes. "No authentication" is never chosen, even when offered: without credentials there is no
//!    command to tie the connection to.
//! 2. The username/password exchange: the user is `knsh-<id>` and the password the token, as for HTTP.
//! 3. The request must be CONNECT. BIND and UDP ASSOCIATE (and unknown commands) are answered "command not
//!    supported" (`0x07`).
//!
//! Every field is bounded by the protocol itself (at most 255 bytes), read exactly, and checked: a wrong version,
//! a zero-length list or name, a non-zero reserved byte or an unknown address type is refused, never repaired. The
//! reader works on any [`Read`], so tests and the fuzz target feed it bytes.
//!
//! SOCKS4 and `SOCKS4a` (first byte `0x04`) are refused with a SOCKS4 "rejected" reply ([`SOCKS4_REJECTED`]).

use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use crate::target::{Host, Target};

/// The SOCKS5 version byte, the first byte of a SOCKS5 greeting.
pub const VERSION: u8 = 5;
/// The SOCKS4 version byte, the first byte of a SOCKS4 or `SOCKS4a` request.
pub const VERSION_4: u8 = 4;

/// The username/password method (RFC 1929).
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
/// The username/password sub-negotiation version.
const AUTH_VERSION: u8 = 0x01;

/// "Username/password chosen."
pub const METHOD_SELECTED: [u8; 2] = [VERSION, METHOD_USERNAME_PASSWORD];
/// "No acceptable methods": the greeting did not offer username/password.
pub const NO_ACCEPTABLE_METHODS: [u8; 2] = [VERSION, 0xff];
/// Credentials accepted.
pub const AUTH_SUCCEEDED: [u8; 2] = [AUTH_VERSION, 0x00];
/// Credentials refused; the connection is closed after it (RFC 1929).
pub const AUTH_FAILED: [u8; 2] = [AUTH_VERSION, 0x01];
/// SOCKS4 "request rejected or failed", the whole answer to a SOCKS4 client.
pub const SOCKS4_REJECTED: [u8; 8] = [0, 0x5b, 0, 0, 0, 0, 0, 0];

/// A reply code to a request (RFC 1928, section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// `0x00`: the tunnel is open.
    Succeeded,
    /// `0x01`: malformed request.
    GeneralFailure,
    /// `0x02`: refused by the rules.
    NotAllowed,
    /// `0x04`: the destination could not be reached.
    HostUnreachable,
    /// `0x06`: the destination did not answer in time.
    TtlExpired,
    /// `0x07`: BIND, UDP ASSOCIATE or an unknown command.
    CommandNotSupported,
    /// `0x08`: an unknown address type.
    AddressTypeNotSupported,
}

impl Reply {
    /// The reply's bytes. The bound address is always `0.0.0.0:0`: clients ignore it for CONNECT, and the proxy's
    /// outbound address is nobody's business.
    #[must_use]
    pub const fn bytes(self) -> [u8; 10] {
        let code = match self {
            Self::Succeeded => 0x00,
            Self::GeneralFailure => 0x01,
            Self::NotAllowed => 0x02,
            Self::HostUnreachable => 0x04,
            Self::TtlExpired => 0x06,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
        };
        [VERSION, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    }
}

/// Why a handshake step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksError {
    /// The client closed, timed out or the socket failed: nothing to answer.
    Closed,
    /// The bytes broke the protocol.
    Malformed,
    /// The request named an unknown address type, so its length is unknown: answer
    /// [`Reply::AddressTypeNotSupported`].
    AddressType,
}

impl From<io::Error> for SocksError {
    fn from(_: io::Error) -> Self {
        Self::Closed
    }
}

/// Reads exactly `N` bytes.
fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], SocksError> {
    let mut buf = [0; N];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Reads a one-byte length and that many bytes (1 to 255; zero is malformed).
fn read_field(reader: &mut impl Read) -> Result<Vec<u8>, SocksError> {
    let [len] = read_array::<1>(reader)?;
    if len == 0 {
        return Err(SocksError::Malformed);
    }
    let mut field = vec![0; usize::from(len)];
    reader.read_exact(&mut field)?;
    Ok(field)
}

/// Reads the greeting, version byte included, and says whether it offers username/password.
///
/// # Errors
///
/// [`SocksError::Malformed`] for another version or an empty method list; [`SocksError::Closed`] if the bytes stop.
pub fn read_greeting(reader: &mut impl Read) -> Result<bool, SocksError> {
    let [version] = read_array::<1>(reader)?;
    if version != VERSION {
        return Err(SocksError::Malformed);
    }
    let methods = read_field(reader)?;
    Ok(methods.contains(&METHOD_USERNAME_PASSWORD))
}

/// Username and password from the RFC 1929 sub-negotiation.
#[derive(Clone, PartialEq, Eq)]
pub struct UserPassword {
    /// The user name.
    pub user: Vec<u8>,
    /// The password.
    pub password: Vec<u8>,
}

impl std::fmt::Debug for UserPassword {
    /// Never the password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserPassword").finish_non_exhaustive()
    }
}

/// Reads the RFC 1929 username/password request.
///
/// # Errors
///
/// [`SocksError::Malformed`] for another sub-negotiation version or an empty name or password;
/// [`SocksError::Closed`] if the bytes stop.
pub fn read_user_password(reader: &mut impl Read) -> Result<UserPassword, SocksError> {
    let [version] = read_array::<1>(reader)?;
    if version != AUTH_VERSION {
        return Err(SocksError::Malformed);
    }
    let user = read_field(reader)?;
    let password = read_field(reader)?;
    Ok(UserPassword { user, password })
}

/// The command of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `0x01`: the only one served.
    Connect,
    /// `0x02`: refused (FR-NET-05).
    Bind,
    /// `0x03`: refused (FR-NET-05).
    UdpAssociate,
    /// Anything else: refused.
    Unknown(u8),
}

/// The destination of a request, as sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// `0x01`: an IPv4 address.
    V4(Ipv4Addr),
    /// `0x03`: a domain name, 1 to 255 bytes, unchecked.
    Domain(Vec<u8>),
    /// `0x04`: an IPv6 address.
    V6(Ipv6Addr),
}

/// A request, read but not yet judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The command.
    pub command: Command,
    /// The destination.
    pub address: Address,
    /// The destination port, as sent (zero included).
    pub port: u16,
}

impl Request {
    /// The destination as a [`Target`], or `None` if the port is zero or the domain is not a valid host name. A
    /// domain that spells an address (`127.0.0.1`) is an IP literal, as for CONNECT (FR-NET-05).
    #[must_use]
    pub fn target(&self) -> Option<Target> {
        let port = NonZeroU16::new(self.port)?;
        let host = match &self.address {
            Address::V4(v4) => Host::Ip(IpAddr::V4(*v4)),
            Address::V6(v6) => Host::Ip(IpAddr::V6(*v6)),
            Address::Domain(name) => Host::parse(name)?,
        };
        Some(Target { host, port })
    }
}

/// Reads a request (RFC 1928, section 4).
///
/// # Errors
///
/// [`SocksError::Malformed`] for another version or a non-zero reserved byte, [`SocksError::AddressType`] for an
/// unknown address type, [`SocksError::Closed`] if the bytes stop.
pub fn read_request(reader: &mut impl Read) -> Result<Request, SocksError> {
    let [version, command, reserved, address_type] = read_array::<4>(reader)?;
    if version != VERSION || reserved != 0 {
        return Err(SocksError::Malformed);
    }
    let command = match command {
        0x01 => Command::Connect,
        0x02 => Command::Bind,
        0x03 => Command::UdpAssociate,
        other => Command::Unknown(other),
    };
    let address = match address_type {
        0x01 => Address::V4(Ipv4Addr::from(read_array::<4>(reader)?)),
        0x03 => Address::Domain(read_field(reader)?),
        0x04 => Address::V6(Ipv6Addr::from(read_array::<16>(reader)?)),
        _ => return Err(SocksError::AddressType),
    };
    let port = u16::from_be_bytes(read_array::<2>(reader)?);
    Ok(Request { command, address, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn greeting(bytes: &[u8]) -> Result<bool, SocksError> {
        read_greeting(&mut &bytes[..])
    }

    fn request(bytes: &[u8]) -> Result<Request, SocksError> {
        read_request(&mut &bytes[..])
    }

    // FR-NET-01: only username/password is ever chosen.
    #[test]
    fn greeting_offers_username_password_or_not() {
        assert_eq!(greeting(&[5, 1, 2]), Ok(true));
        assert_eq!(greeting(&[5, 3, 0, 1, 2]), Ok(true));
        assert_eq!(greeting(&[5, 1, 0]), Ok(false));
        assert_eq!(greeting(&[5, 0]), Err(SocksError::Malformed));
        assert_eq!(greeting(&[4, 1, 2]), Err(SocksError::Malformed));
        assert_eq!(greeting(&[5, 2, 2]), Err(SocksError::Closed));
    }

    // RFC 1929: version 1, non-empty user and password.
    #[test]
    fn reads_user_password() {
        let parsed = read_user_password(&mut &b"\x01\x06knsh-1\x03tok"[..]).unwrap();
        assert_eq!(parsed.user, b"knsh-1");
        assert_eq!(parsed.password, b"tok");
        assert!(!format!("{parsed:?}").contains("tok"));
        for bad in [&b"\x05\x06knsh-1\x03tok"[..], b"\x01\x00\x03tok", b"\x01\x01a\x00"] {
            assert_eq!(read_user_password(&mut &bad[..]), Err(SocksError::Malformed), "{bad:?}");
        }
        assert_eq!(read_user_password(&mut &b"\x01\x06knsh"[..]), Err(SocksError::Closed));
    }

    // FR-NET-05: domains go through the same host parsing as CONNECT; addresses are IP literals.
    #[test]
    fn reads_requests_and_targets() {
        let domain = request(b"\x05\x01\x00\x03\x0bExample.COM\x01\xbb").unwrap();
        assert_eq!(domain.command, Command::Connect);
        let target = domain.target().unwrap();
        assert_eq!(target.to_string(), "example.com:443");
        let v4 = request(&[5, 1, 0, 1, 10, 0, 0, 1, 0, 80]).unwrap();
        assert!(v4.target().unwrap().host.is_ip());
        let mut v6 = vec![5, 1, 0, 4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0, 22]);
        assert_eq!(request(&v6).unwrap().target().unwrap().to_string(), "[::1]:22");
        // A domain spelling an address is an IP literal; a bad name or port zero has no target.
        let spelled = request(b"\x05\x01\x00\x03\x09127.0.0.1\x00\x50").unwrap();
        assert!(spelled.target().unwrap().host.is_ip());
        assert!(request(b"\x05\x01\x00\x03\x03a b\x00\x50").unwrap().target().is_none());
        assert!(
            request(b"\x05\x01\x00\x03\x05127.1\x00\x50")
                .unwrap()
                .target()
                .is_none()
        );
        assert!(request(b"\x05\x01\x00\x03\x01a\x00\x00").unwrap().target().is_none());
    }

    // FR-NET-05: BIND and UDP ASSOCIATE are read so they can be answered, never served.
    #[test]
    fn reads_bind_and_udp_associate_as_such() {
        assert_eq!(
            request(&[5, 2, 0, 1, 1, 2, 3, 4, 0, 80]).unwrap().command,
            Command::Bind
        );
        assert_eq!(
            request(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap().command,
            Command::UdpAssociate
        );
        assert_eq!(
            request(&[5, 9, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap().command,
            Command::Unknown(9)
        );
    }

    // NFR-SEC-05: malformed requests are refused, never repaired.
    #[test]
    fn refuses_malformed_requests() {
        assert_eq!(request(&[4, 1, 0, 1, 1, 2, 3, 4, 0, 80]), Err(SocksError::Malformed));
        assert_eq!(request(&[5, 1, 1, 1, 1, 2, 3, 4, 0, 80]), Err(SocksError::Malformed));
        assert_eq!(request(&[5, 1, 0, 9, 1, 2, 3, 4, 0, 80]), Err(SocksError::AddressType));
        assert_eq!(request(&[5, 1, 0, 3, 0, 0, 80]), Err(SocksError::Malformed));
        assert_eq!(request(&[5, 1, 0, 1, 1, 2]), Err(SocksError::Closed));
    }

    // RFC 1928: replies carry the code in the second byte and an IPv4 zero address.
    #[test]
    fn replies_carry_their_codes() {
        assert_eq!(Reply::Succeeded.bytes(), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Reply::NotAllowed.bytes()[1], 2);
        assert_eq!(Reply::CommandNotSupported.bytes()[1], 7);
        assert_eq!(Reply::AddressTypeNotSupported.bytes()[1], 8);
    }
}
