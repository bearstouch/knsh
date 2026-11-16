//! Host rules: which hosts a command may reach through the proxy (KNSH-060; FR-NET-02, FR-NET-03, FR-NET-04,
//! FR-NET-11, FR-POL-21).
//!
//! [`check_host`] is the whole rule check, and a pure function of the session's network policy, who asks (an
//! envelope, or a line with its classes, whether it holds dynamic code and whether it was approved) and the host. The
//! proxy (`knsh-proxy`) asks it for every connection, and again for every address a name resolves to that the address
//! checks would otherwise refuse (FR-NET-07). Nothing here resolves names or opens sockets.
//!
//! # The rules
//!
//! 1. `network.mode = "none"`: no host at all ([`HostRefusal::NetworkOff`], FR-NET-04). The loopback ports are not
//!    hosts: the sandbox profile allows them directly, and the proxy allows them before it asks here.
//! 2. A host in `network.hosts` is open to every command of the session, the envelope included (FR-NET-02).
//! 3. A host in `network.approval_hosts` (FR-NET-03) is reached only by a line, never by the envelope (which has no
//!    classes and is never approved), and only:
//!    - not if the line holds dynamic code, even approved ([`HostRefusal::DynamicCode`], FR-NET-11, FR-POL-21);
//!    - by its classes, when every class it presents that connects lists the host under `network.class_hosts`
//!      ([`HostAccess::Class`]);
//!    - or because it was approved, or covered by a grant ([`HostAccess::Approval`]).
//!
//!    Otherwise [`HostRefusal::ApprovalRequired`].
//! 4. Any other host: [`HostRefusal::NotListed`].
//!
//! # Matching
//!
//! A host is a normalised name (ASCII lower case, no trailing dot) or an IP address in its standard text form, as
//! the proxy hands them over. A listed entry matches ([`host_matches`]):
//!
//! - a name, the same name, ignoring ASCII case and one trailing dot;
//! - `*.` followed by a name, every name strictly below it (`*.example.com` matches `a.example.com` and
//!   `a.b.example.com`, not `example.com`);
//! - an IP address, written plainly or in brackets (`10.0.0.5`, `[fd00::1]`), the same address however it is
//!   spelled. Listing an address is how a profile allowlists an IP literal (FR-NET-05) or an internal address a name
//!   resolves to (FR-NET-07).
//!
//! Any other entry (a `*` elsewhere, a port) matches nothing: the rules fail closed rather than guess.

use std::fmt;
use std::net::IpAddr;

use knsh_bash::NetworkClass;

use super::line::DecisionSource;
use super::model::{NetworkMode, NetworkPolicy};
use crate::lifecycle::Allowed;

/// What a line presents to the host rules: its network classes, whether it holds dynamic code and whether it was
/// approved (module documentation).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct LineAccess {
    /// The network classes the line presents (`LineCapabilities::classes`): none for dynamic code, or when any
    /// command that can connect has none.
    pub classes: Vec<NetworkClass>,
    /// Whether any part of the line is dynamic code: it then never reaches an approval host (FR-POL-21).
    pub dynamic: bool,
    /// Whether the line was approved (by the authority or the user), or allowed by a grant that answered the rules'
    /// ask (FR-NET-03, `specs/05-models/grant.md`).
    pub approved: bool,
}

impl LineAccess {
    /// What an allowed line presents: the classes and dynamic flag of its capabilities, and whether it was
    /// approved or granted.
    #[must_use]
    pub fn of(allowed: &Allowed) -> Self {
        let capabilities = &allowed.profile.capabilities;
        Self {
            classes: capabilities.classes.clone(),
            dynamic: capabilities.dynamic,
            approved: allowed.profile.approved || allowed.decision.source == DecisionSource::Grant,
        }
    }
}

/// Who asks to connect.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Requester {
    /// The envelope: the agent CLI itself, outside any supervised line. It has no classes and is never approved,
    /// so it reaches `network.hosts` only.
    Envelope,
    /// A supervised line.
    Line(LineAccess),
}

/// Why a host is open to the requester.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostAccess {
    /// Listed in `network.hosts`: open to every command (FR-NET-02).
    Open,
    /// An approval host the line's classes open (`network.class_hosts`, FR-NET-03).
    Class,
    /// An approval host the line reaches because it was approved or granted (FR-NET-03).
    Approval,
}

/// Why a host is refused to the requester.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostRefusal {
    /// `network.mode = "none"`: no host is reachable (FR-NET-04).
    NetworkOff,
    /// Neither in `network.hosts` nor in `network.approval_hosts`.
    NotListed,
    /// An approval host, and the requester's classes do not open it and it was not approved (FR-NET-03).
    ApprovalRequired,
    /// An approval host, and the line holds dynamic code, which never reaches one (FR-NET-11, FR-POL-21).
    DynamicCode,
}

impl HostRefusal {
    /// A fixed name for reports: `network_off`, `host_not_allowed`, `approval_required` or `dynamic_code`.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NetworkOff => "network_off",
            Self::NotListed => "host_not_allowed",
            Self::ApprovalRequired => "approval_required",
            Self::DynamicCode => "dynamic_code",
        }
    }
}

impl fmt::Display for HostRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

/// Whether `requester` may reach `host` under `network` (module documentation, "The rules"). Pure and total.
///
/// # Errors
///
/// The [`HostRefusal`] when the host is not open to the requester.
pub fn check_host(network: &NetworkPolicy, requester: &Requester, host: &str) -> Result<HostAccess, HostRefusal> {
    match network.mode {
        NetworkMode::None => return Err(HostRefusal::NetworkOff),
        NetworkMode::Allowlist => {}
    }
    if listed(&network.hosts, host) {
        return Ok(HostAccess::Open);
    }
    if !listed(&network.approval_hosts, host) {
        return Err(HostRefusal::NotListed);
    }
    let line = match requester {
        Requester::Envelope => return Err(HostRefusal::ApprovalRequired),
        Requester::Line(line) => line,
    };
    // FR-POL-21: checked before classes and approvals, so neither can lift it. The decision's capabilities already
    // drop a dynamic line's classes; this holds even if they did not.
    if line.dynamic {
        return Err(HostRefusal::DynamicCode);
    }
    // Class entries are matched like every other entry (`host_matches`), not by exact text as `ClassHosts::allows`
    // does, so a class rule opens exactly the hosts its approval entry names.
    if class_allows(network, &line.classes, host) {
        return Ok(HostAccess::Class);
    }
    if line.approved {
        return Ok(HostAccess::Approval);
    }
    Err(HostRefusal::ApprovalRequired)
}

/// Whether `host` is listed in `network.non_tls_hosts`, so the proxy lets its tunnels carry anything instead of
/// checking that they start with a TLS `ClientHello` naming the host (FR-NET-06). It says nothing about whether the
/// host may be reached: that is [`check_host`]'s answer alone. Matched like every entry ([`host_matches`]).
#[must_use]
pub fn is_non_tls_host(network: &NetworkPolicy, host: &str) -> bool {
    listed(&network.non_tls_hosts, host)
}

/// Whether a line presenting `classes` reaches `host` by class alone: it presents a class that connects, and every
/// class it presents that connects lists an entry matching `host` (the `ClassHosts` rule, with [`host_matches`]).
fn class_allows(network: &NetworkPolicy, classes: &[NetworkClass], host: &str) -> bool {
    let mut connecting = classes.iter().filter(|class| **class != NetworkClass::None).peekable();
    connecting.peek().is_some() && connecting.all(|class| listed(network.class_hosts.for_class(*class), host))
}

/// Whether any entry of `entries` matches `host`.
fn listed(entries: &[String], host: &str) -> bool {
    entries.iter().any(|entry| host_matches(entry, host))
}

/// Whether the profile entry `entry` matches `host` (module documentation, "Matching").
#[must_use]
pub fn host_matches(entry: &str, host: &str) -> bool {
    if let Some(listed) = entry_address(entry) {
        return host.parse::<IpAddr>().is_ok_and(|address| address == listed);
    }
    if host.parse::<IpAddr>().is_ok() {
        // A name entry never matches an address, however the address is spelled.
        return false;
    }
    let host = normalise(host);
    let entry = normalise(entry);
    if let Some(parent) = entry.strip_prefix("*.") {
        // Strictly below `parent`: at least one label, then `.parent`.
        return valid_name(parent)
            && host
                .strip_suffix(parent)
                .and_then(|rest| rest.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty());
    }
    valid_name(&entry) && entry == host
}

/// The address an entry lists, written plainly (`10.0.0.5`, `fd00::1`) or in brackets (`[fd00::1]`).
fn entry_address(entry: &str) -> Option<IpAddr> {
    let inner = entry
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(entry);
    inner.parse().ok()
}

/// ASCII lower case, without one trailing dot.
fn normalise(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// A name an entry may list: non-empty labels of letters, digits, `-` and `_`. A `*`, `:` or bracket left over
/// means the entry is something this matcher does not understand, and it matches nothing.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::model::ClassHosts;

    fn policy(mode: NetworkMode) -> NetworkPolicy {
        NetworkPolicy {
            mode,
            hosts: vec![
                "registry.npmjs.org".to_owned(),
                "*.pythonhosted.org".to_owned(),
                "10.0.0.5".to_owned(),
            ],
            approval_hosts: vec!["github.com".to_owned(), "upload.pypi.org".to_owned()],
            class_hosts: ClassHosts {
                fetch: vec!["github.com".to_owned()],
                publish: Vec::new(),
            },
            loopback: vec![3000],
            non_tls_hosts: vec!["*.corp.example".to_owned(), "10.0.0.5".to_owned()],
        }
    }

    fn line(classes: &[NetworkClass], dynamic: bool, approved: bool) -> Requester {
        Requester::Line(LineAccess {
            classes: classes.to_vec(),
            dynamic,
            approved,
        })
    }

    fn plain_line() -> Requester {
        line(&[], false, false)
    }

    // KNSH-060 hosts_open_to_every_command (FR-NET-02): the envelope, a plain line, a classed line, an approved line
    // and dynamic code all reach `network.hosts`.
    #[test]
    fn hosts_open_to_every_command() {
        let network = policy(NetworkMode::Allowlist);
        for requester in [
            Requester::Envelope,
            plain_line(),
            line(&[NetworkClass::Fetch], false, false),
            line(&[], false, true),
            line(&[], true, false),
        ] {
            assert_eq!(
                check_host(&network, &requester, "registry.npmjs.org"),
                Ok(HostAccess::Open),
                "{requester:?}"
            );
            assert_eq!(
                check_host(&network, &requester, "files.pythonhosted.org"),
                Ok(HostAccess::Open)
            );
        }
        assert_eq!(
            check_host(&network, &plain_line(), "example.com"),
            Err(HostRefusal::NotListed)
        );
    }

    // KNSH-060 approval_host_refused_without_class_or_approval (FR-NET-03): no class that opens it, no approval:
    // refused, to the envelope too.
    #[test]
    fn approval_host_refused_without_class_or_approval() {
        let network = policy(NetworkMode::Allowlist);
        for requester in [
            Requester::Envelope,
            plain_line(),
            // `git push` presents publish, and github.com is listed under fetch only.
            line(&[NetworkClass::Publish], false, false),
            // Both classes connect, and publish does not list it.
            line(&[NetworkClass::Fetch, NetworkClass::Publish], false, false),
            // `network:none` connects nowhere and opens nothing.
            line(&[NetworkClass::None], false, false),
        ] {
            assert_eq!(
                check_host(&network, &requester, "github.com"),
                Err(HostRefusal::ApprovalRequired),
                "{requester:?}"
            );
        }
        // A class host opens only the hosts its class lists.
        assert_eq!(
            check_host(&network, &line(&[NetworkClass::Fetch], false, false), "upload.pypi.org"),
            Err(HostRefusal::ApprovalRequired)
        );
    }

    // KNSH-060 approval_host_allowed_for_approved_line (FR-NET-03): approved (or granted) lines reach approval
    // hosts; so does a line whose classes open the host.
    #[test]
    fn approval_host_allowed_for_approved_line() {
        let network = policy(NetworkMode::Allowlist);
        assert_eq!(
            check_host(&network, &line(&[NetworkClass::Publish], false, true), "github.com"),
            Ok(HostAccess::Approval)
        );
        assert_eq!(
            check_host(&network, &line(&[], false, true), "upload.pypi.org"),
            Ok(HostAccess::Approval)
        );
        assert_eq!(
            check_host(&network, &line(&[NetworkClass::Fetch], false, false), "github.com"),
            Ok(HostAccess::Class)
        );
        assert_eq!(
            check_host(
                &network,
                &line(&[NetworkClass::None, NetworkClass::Fetch], false, false),
                "GitHub.com."
            ),
            Ok(HostAccess::Class),
            "case and a trailing dot do not matter, network:none needs no host"
        );
    }

    // KNSH-060 mode_none_refuses_all_but_loopback (FR-NET-04): no host, whatever is listed and whoever asks. (The
    // loopback ports are allowed before host rules are asked: `knsh-proxy`'s rules.)
    #[test]
    fn mode_none_refuses_every_host() {
        let network = policy(NetworkMode::None);
        for host in ["registry.npmjs.org", "github.com", "10.0.0.5", "example.com"] {
            for requester in [Requester::Envelope, line(&[NetworkClass::Fetch], false, true)] {
                assert_eq!(check_host(&network, &requester, host), Err(HostRefusal::NetworkOff));
            }
        }
    }

    // KNSH-060 dynamic_code_never_reaches_approval_hosts (FR-NET-11, FR-POL-21): approved, classed or both, a line
    // holding dynamic code never reaches an approval host; `network.hosts` stay open to it.
    #[test]
    fn dynamic_code_never_reaches_approval_hosts() {
        let network = policy(NetworkMode::Allowlist);
        for requester in [
            line(&[], true, true),
            line(&[NetworkClass::Fetch], true, false),
            line(&[NetworkClass::Fetch], true, true),
        ] {
            assert_eq!(
                check_host(&network, &requester, "github.com"),
                Err(HostRefusal::DynamicCode),
                "{requester:?}"
            );
            assert_eq!(
                check_host(&network, &requester, "registry.npmjs.org"),
                Ok(HostAccess::Open)
            );
        }
    }

    // KNSH-060: the rule check is a pure function of its inputs: the same answer every time.
    #[test]
    fn check_is_deterministic() {
        let network = policy(NetworkMode::Allowlist);
        let requester = line(&[NetworkClass::Fetch], false, false);
        let first = check_host(&network, &requester, "github.com");
        for _ in 0..3 {
            assert_eq!(check_host(&network, &requester, "github.com"), first);
        }
    }

    // FR-NET-05, FR-NET-07: addresses match listed addresses however they are spelled, and names never match them.
    #[test]
    fn matches_names_wildcards_and_addresses() {
        assert!(host_matches("Example.COM.", "example.com"));
        assert!(host_matches("*.example.com", "a.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "aexample.com"));
        assert!(!host_matches("example.com", "a.example.com"));
        assert!(host_matches("[fd00::1]", "fd00:0:0::1"));
        assert!(host_matches("10.0.0.5", "10.0.0.5"));
        assert!(!host_matches("10.0.0.5", "10.0.0.6"));
        assert!(!host_matches("example.com", "10.0.0.5"));
        // Entries this matcher does not understand match nothing (fail closed).
        for entry in ["*", "*.", "a*.example.com", "example.com:443", "*.*.com", ""] {
            assert!(!host_matches(entry, "a.example.com"), "{entry}");
            assert!(!host_matches(entry, "example.com"), "{entry}");
        }
    }

    // FR-NET-06: `network.non_tls_hosts` is matched like every host entry, and listing a host there never opens it.
    #[test]
    fn non_tls_hosts_exempt_only_listed_hosts() {
        let network = policy(NetworkMode::Allowlist);
        assert!(is_non_tls_host(&network, "git.corp.example"));
        assert!(is_non_tls_host(&network, "10.0.0.5"));
        assert!(!is_non_tls_host(&network, "corp.example"));
        assert!(!is_non_tls_host(&network, "registry.npmjs.org"));
        assert_eq!(
            check_host(&network, &Requester::Envelope, "git.corp.example"),
            Err(HostRefusal::NotListed)
        );
    }
}
