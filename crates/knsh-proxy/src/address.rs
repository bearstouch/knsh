//! Which addresses are internal: the ones a name may not point the proxy at unless allowlisted (FR-NET-07).
//!
//! The proxy resolves names itself and refuses a name if any address it resolves to is internal, so a public name
//! cannot be made to point at the machine itself or the local network (DNS rebinding), and an allowed host cannot be
//! used to reach an internal service by its address.
//!
//! # Ranges (`specs/03-functional-requirements/network-proxy.md`, "Internal addresses")
//!
//! | IPv4 | |
//! | --- | --- |
//! | `0.0.0.0/8` | "this network"; `0.0.0.0` reaches the machine itself |
//! | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | private (RFC 1918) |
//! | `100.64.0.0/10` | carrier-grade NAT (RFC 6598) |
//! | `127.0.0.0/8` | loopback |
//! | `169.254.0.0/16` | link-local, cloud metadata services among them |
//! | `192.0.0.0/24` | IETF protocol assignments |
//! | `198.18.0.0/15` | benchmarking, used by some VPNs and proxies for local routing |
//! | `224.0.0.0/4`, `240.0.0.0/4` | multicast, reserved, and the broadcast address |
//!
//! | IPv6 | |
//! | --- | --- |
//! | `::`, `::1` | unspecified, loopback |
//! | `fc00::/7` | unique local |
//! | `fe80::/10` | link-local |
//! | `fec0::/10` | site-local (deprecated, still routed by some stacks) |
//! | `ff00::/8` | multicast |
//! | `::ffff:0:0/96`, `::/96`, `64:ff9b::/96` | IPv4-mapped, IPv4-compatible and NAT64 addresses: judged by the IPv4 address they embed |
//!
//! Every other address is public. The list is deliberately wider than "private": an address a command cannot reach
//! on the public internet is one the proxy has no business connecting to on its behalf.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `ip` is internal (module documentation): loopback, link-local, private or otherwise not public.
#[must_use]
pub fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_v4(v4),
        IpAddr::V6(v6) => is_internal_v6(v6),
    }
}

/// Whether `ip` is a loopback address: `127.0.0.0/8`, `::1`, or an IPv4-mapped loopback address.
#[must_use]
pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || embedded_v4(v6).is_some_and(|v4| v4.is_loopback()),
    }
}

fn is_internal_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..128).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..20).contains(&b))
        // Multicast (224/4), reserved (240/4) and the broadcast address.
        || a >= 224
}

fn is_internal_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(ip) {
        return is_internal_v4(v4);
    }
    let first = ip.segments()[0];
    ip.is_unspecified()
        || ip.is_loopback()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || (first & 0xffc0) == 0xfec0
        || (first & 0xff00) == 0xff00
}

/// The IPv4 address an IPv6 address carries, when connecting to it reaches that IPv4 address: IPv4-mapped
/// (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`, deprecated but still accepted by some stacks) and the NAT64
/// well-known prefix (`64:ff9b::a.b.c.d`).
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    let low = Ipv4Addr::from((u32::from(segments[6]) << 16) | u32::from(segments[7]));
    match segments[..6] {
        // `::/96` includes `::` and `::1`, which embed `0.0.0.0` and `0.0.0.1`: internal either way.
        [0, 0, 0, 0, 0, 0xffff | 0] | [0x64, 0xff9b, 0, 0, 0, 0] => Some(low),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn internal(text: &str) -> bool {
        is_internal(text.parse().unwrap())
    }

    // FR-NET-07: every range of the module documentation is internal, at both ends.
    #[test]
    fn internal_ranges() {
        for address in [
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.1",
            "10.255.255.255",
            "100.64.0.0",
            "100.127.255.255",
            "127.0.0.1",
            "127.1.2.3",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "192.0.0.8",
            "198.18.0.1",
            "198.19.255.255",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
        ] {
            assert!(internal(address), "{address}");
        }
    }

    // FR-NET-07: public addresses, including the neighbours of each internal range, are not internal.
    #[test]
    fn public_addresses() {
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "9.255.255.255",
            "11.0.0.1",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.1",
            "169.253.255.255",
            "169.255.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.167.255.255",
            "192.169.0.1",
            "192.0.1.1",
            "198.17.255.255",
            "198.20.0.1",
            "223.255.255.255",
            "2606:4700::1111",
            "2001:4860:4860::8888",
            "fbff::1",
            "fe7f::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(!internal(address), "{address}");
        }
    }

    #[test]
    fn loopback_addresses() {
        for address in ["127.0.0.1", "127.9.9.9", "::1", "::ffff:127.0.0.1"] {
            assert!(is_loopback(address.parse().unwrap()), "{address}");
        }
        for address in ["10.0.0.1", "::", "0.0.0.0", "fe80::1"] {
            assert!(!is_loopback(address.parse().unwrap()), "{address}");
        }
    }
}
