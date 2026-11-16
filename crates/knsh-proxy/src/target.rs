//! Connection targets: the host and port a client asks the proxy to reach (FR-NET-05).
//!
//! HTTP CONNECT and SOCKS5 name their destination differently (an authority such as `example.com:443` or
//! `[::1]:443`, or a SOCKS5 address type with raw bytes), but both end up as one [`Target`], so the same host rules
//! and address checks apply to both protocols.
//!
//! A host is a [`Host::Name`] or a [`Host::Ip`]. Anything that a resolver could read as an address is an
//! [`Host::Ip`], whatever the protocol called it: a SOCKS5 domain of `127.0.0.1` is an IP literal. Names are
//! normalised (lower case, no trailing dot) so rules compare them byte for byte. A name whose last label is a number
//! (`127.1`, `0x7f.1`) is refused outright: some resolvers read it as an address, so it would let an IP literal
//! past the "names only" rule.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

/// Longest host name: 253 characters, as DNS allows (255 octets on the wire).
pub const MAX_NAME_LEN: usize = 253;

/// Longest label of a host name, as DNS allows.
const MAX_LABEL_LEN: usize = 63;

/// The host part of a [`Target`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// A host name: 1 to [`MAX_NAME_LEN`] ASCII lower-case letters, digits, `-`, `_` and `.`, in labels of 1 to 63,
    /// with no trailing dot and a last label that is not a number.
    Name(String),
    /// An IP address literal (FR-NET-05: refused unless allowlisted).
    Ip(IpAddr),
}

impl Host {
    /// Reads a host as a client sent it, unbracketed (`example.com`, `127.0.0.1`, `::1`). `None` for anything that
    /// is neither an address nor a valid name: such a request is refused, never repaired.
    #[must_use]
    pub fn parse(text: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(text).ok()?;
        if let Ok(v4) = text.parse::<Ipv4Addr>() {
            return Some(Self::Ip(IpAddr::V4(v4)));
        }
        if let Ok(v6) = text.parse::<Ipv6Addr>() {
            return Some(Self::Ip(IpAddr::V6(v6)));
        }
        parse_name(text).map(Self::Name)
    }

    /// Whether this is an IP literal rather than a name.
    #[must_use]
    pub fn is_ip(&self) -> bool {
        matches!(self, Self::Ip(_))
    }
}

impl fmt::Display for Host {
    /// The name, or the address (IPv6 without brackets).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => f.write_str(name),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// Where a client asked to connect: a host and a non-zero port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    /// The host.
    pub host: Host,
    /// The port.
    pub port: NonZeroU16,
}

impl Target {
    /// Reads an HTTP CONNECT authority (RFC 9110, section 9.3.6): `host:port` or `[ipv6]:port`. The port is
    /// required and is 1 to 5 decimal digits naming 1 to 65535. A bare IPv6 address, user information, an empty
    /// host or a zone index (`%en0`) are refused.
    #[must_use]
    pub fn parse_authority(text: &[u8]) -> Option<Self> {
        let colon = text.iter().rposition(|&byte| byte == b':')?;
        let (host, port) = (&text[..colon], &text[colon + 1..]);
        let port = parse_port(port)?;
        let host = if let Some(inner) = host.strip_prefix(b"[").and_then(|rest| rest.strip_suffix(b"]")) {
            // Brackets hold an IPv6 address and nothing else.
            match Host::parse(inner)? {
                ip @ Host::Ip(IpAddr::V6(_)) => ip,
                Host::Ip(IpAddr::V4(_)) | Host::Name(_) => return None,
            }
        } else {
            // Unbracketed, a colon could only be part of an IPv6 address, which needs brackets here.
            if host.contains(&b':') {
                return None;
            }
            Host::parse(host)?
        };
        Some(Self { host, port })
    }
}

impl fmt::Display for Target {
    /// `host:port`, with an IPv6 address in brackets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]:{}", self.port),
            host @ (Host::Ip(IpAddr::V4(_)) | Host::Name(_)) => write!(f, "{host}:{}", self.port),
        }
    }
}

/// A decimal port of 1 to 5 digits, 1 to 65535. No sign, no spaces.
fn parse_port(text: &[u8]) -> Option<NonZeroU16> {
    if text.is_empty() || text.len() > 5 || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse::<NonZeroU16>().ok()
}

/// Normalises and checks a host name (module documentation). One trailing dot is dropped: `example.com.` and
/// `example.com` are the same host and must meet the same rules.
fn parse_name(text: &str) -> Option<String> {
    let text = text.strip_suffix('.').unwrap_or(text);
    if text.is_empty() || text.len() > MAX_NAME_LEN {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    let mut last = "";
    for label in lower.split('.') {
        let valid = !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_');
        if !valid {
            return None;
        }
        last = label;
    }
    // `127.1`, `2130706433` and `0x7f.1` are addresses to `inet_aton`: refusing them keeps "names only" honest.
    let numeric = last.bytes().all(|byte| byte.is_ascii_digit())
        || (last.starts_with("0x") && last[2..].bytes().all(|byte| byte.is_ascii_hexdigit()));
    (!numeric).then_some(lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(text: &str) -> Option<Target> {
        Target::parse_authority(text.as_bytes())
    }

    // FR-NET-05: names are normalised so rules see one spelling.
    #[test]
    fn parses_and_normalises_names() {
        let parsed = target("Example.COM.:443").unwrap();
        assert_eq!(parsed.host, Host::Name("example.com".to_owned()));
        assert_eq!(parsed.port.get(), 443);
        assert_eq!(parsed.to_string(), "example.com:443");
        assert_eq!(
            target("registry_1.npmjs.org:8080").unwrap().host,
            Host::Name("registry_1.npmjs.org".to_owned())
        );
    }

    // FR-NET-05: addresses are IP literals in either protocol's spelling.
    #[test]
    fn parses_ip_literals() {
        assert_eq!(
            target("127.0.0.1:80").unwrap().host,
            Host::Ip("127.0.0.1".parse().unwrap())
        );
        let v6 = target("[::1]:443").unwrap();
        assert_eq!(v6.host, Host::Ip("::1".parse().unwrap()));
        assert_eq!(v6.to_string(), "[::1]:443");
        assert!(Host::parse(b"10.0.0.1").unwrap().is_ip());
    }

    // NFR-SEC-05: malformed authorities are refused, never repaired.
    #[test]
    fn refuses_malformed_authorities() {
        for bad in [
            "example.com",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:+443",
            "example.com:0443x",
            "example.com:123456",
            ":443",
            "::1:443",
            "[127.0.0.1]:443",
            "[example.com]:443",
            "[fe80::1%en0]:443",
            "user@example.com:443",
            "exa mple.com:443",
            "example..com:443",
            ".example.com:443",
            "-ok.example.com:é",
            "exämple.com:443",
            "example.com/path:443",
        ] {
            assert!(target(bad).is_none(), "{bad}");
        }
        let long_label = format!("{}.com:443", "a".repeat(MAX_LABEL_LEN + 1));
        assert!(target(&long_label).is_none());
        let long_name = format!("{}.com:443", "a.".repeat(MAX_NAME_LEN / 2));
        assert!(target(&long_name).is_none());
    }

    // FR-NET-05: names a resolver would read as addresses never pass as names.
    #[test]
    fn refuses_numeric_names_that_resolvers_read_as_addresses() {
        for bad in ["127.1", "2130706433", "0x7f.1", "1.2.3", "example.0x10", "a.123"] {
            assert!(Host::parse(bad.as_bytes()).is_none(), "{bad}");
        }
        // A number in a label that is not the last one is an ordinary name.
        assert!(matches!(Host::parse(b"1.example.com"), Some(Host::Name(_))));
    }
}
