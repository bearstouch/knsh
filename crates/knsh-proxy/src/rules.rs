//! The gate `knshd` runs: host rules, name resolution and address checks (KNSH-060; FR-NET-02 to FR-NET-05,
//! FR-NET-07, FR-NET-11).
//!
//! [`HostRules`] is the [`ConnectionGate`]. It keeps one [`Scope`] per owner of live credentials (the envelope of a
//! session, or a line), which `knshd` sets when it issues the credentials and forgets when it revokes them. An owner
//! with no scope is refused ([`Refusal::NoHostRules`]): fail closed.
//!
//! # A decision ([`decide`])
//!
//! 1. **Loopback ports.** A loopback address, or the name `localhost` (or a name below it, RFC 6761), on a port of
//!    `network.loopback` is allowed whatever the mode: the sandbox profile lets the command reach that port anyway,
//!    so the proxy adds nothing by refusing it (FR-NET-04). `localhost` is never resolved: it is `127.0.0.1` and
//!    `::1`. Not for a line that receives secrets: it may reach only its secrets' hosts (FR-SEC-03), so its
//!    loopback destinations go through the host rules like any other (`knshd` also compiles its sandbox profile
//!    without loopback ports).
//! 2. **IP literals** are refused unless allowlisted: listed in a host rule the requester may use (FR-NET-05).
//! 3. **Names** go through the host rules ([`knsh_core::check_host`]): `network.hosts`, `network.approval_hosts`
//!    with the line's classes and approval, dynamic code limited to `network.hosts` (FR-NET-02, FR-NET-03,
//!    FR-NET-04, FR-NET-11).
//! 4. **Resolution.** An allowed name is resolved once, by the proxy ([`Resolver`]). If **any** address it resolves
//!    to is internal ([`crate::address`]) and not allowlisted (step 1's loopback ports, or the address listed in a
//!    host rule the requester may use), the name is refused (FR-NET-07). One bad address refuses the name, so an
//!    answer that mixes a public and an internal address cannot be used to reach the internal one.
//! 5. The checked addresses, with the port, are what the proxy connects to, in order, and nothing else: the name is
//!    never resolved again (FR-NET-07).
//!
//! # The server-name check ([`Scope::checks_server_name`])
//!
//! Every tunnel must start with a TLS `ClientHello` naming its host (FR-NET-06, [`crate::tls`]), except to a host
//! listed in `network.non_tls_hosts`, and to step 1's loopback ports, which the sandbox profile lets the command
//! reach without the proxy, so checking them adds nothing. An owner with no scope is checked (fail closed).
//!
//! The decision is a pure function of the scope, the target and the resolver's answer; [`decide`] takes the
//! resolver as a function so tests can answer anything.
//!
//! # Lock order
//!
//! [`HostRules`]'s map lock is taken alone and never held while resolving.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::{HostRefusal, NetworkPolicy, RecordId, Requester, SessionId, check_host, is_non_tls_host};
use knsh_platform::{MAX_ADDRESSES, Resolver};

use crate::address::{is_internal, is_loopback};
use crate::credentials::Owner;
use crate::gate::{ConnectionGate, Refusal};
use crate::target::{Host, Target};

/// What one owner of credentials may reach: its session's network policy, and who it is to the host rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// The session's `[network]` policy, as loaded for the session (the envelope) or for the line's decision.
    pub network: NetworkPolicy,
    /// The envelope, or a line with its classes, dynamic flag and approval.
    pub requester: Requester,
}

impl Scope {
    /// Step 1: a loopback address on a `network.loopback` port.
    fn loopback_port(&self, ip: IpAddr, port: NonZeroU16) -> bool {
        is_loopback(ip) && self.opens_loopback(port)
    }

    /// Whether `port` is one of step 1's loopback ports for this requester: never for a line narrowed to its
    /// secrets' hosts (FR-SEC-03).
    fn opens_loopback(&self, port: NonZeroU16) -> bool {
        let narrowed = matches!(&self.requester, Requester::Line(line) if !line.secret_hosts.is_empty());
        !narrowed && self.network.loopback.contains(&port.get())
    }

    /// Whether the address `ip` is listed in a host rule the requester may use (FR-NET-05, FR-NET-07).
    fn lists_address(&self, ip: IpAddr) -> bool {
        check_host(&self.network, &self.requester, &ip.to_string()).is_ok()
    }

    /// Step 2: whether the IP literal `ip` may be the destination on `port`.
    #[must_use]
    pub fn allows_ip_literal(&self, ip: IpAddr, port: NonZeroU16) -> bool {
        self.loopback_port(ip, port) || self.lists_address(ip)
    }

    /// Whether a tunnel to `target` must start with a `ClientHello` naming its host (module documentation, "The
    /// server-name check"): yes unless the target is a loopback port or listed in `network.non_tls_hosts`.
    #[must_use]
    pub fn checks_server_name(&self, target: &Target) -> bool {
        let port = target.port;
        let exempt = match &target.host {
            Host::Ip(ip) => self.loopback_port(*ip, port) || is_non_tls_host(&self.network, &ip.to_string()),
            Host::Name(name) => {
                (is_localhost(name) && self.opens_loopback(port)) || is_non_tls_host(&self.network, name)
            }
        };
        !exempt
    }

    /// Step 4: whether a name may resolve to `ip`: a public address, or an internal one allowlisted.
    fn allows_resolved(&self, ip: IpAddr, port: NonZeroU16) -> bool {
        !is_internal(ip) || self.loopback_port(ip, port) || self.lists_address(ip)
    }
}

/// The [`Refusal`] a host rule refusal is reported as.
fn refusal(refused: HostRefusal) -> Refusal {
    match refused {
        HostRefusal::NetworkOff => Refusal::NetworkOff,
        HostRefusal::NotListed => Refusal::HostNotAllowed,
        HostRefusal::ApprovalRequired => Refusal::ApprovalRequired,
        HostRefusal::DynamicCode => Refusal::DynamicCode,
        HostRefusal::SecretHosts => Refusal::SecretHosts,
    }
}

/// Whether `name` is `localhost` or below it: loopback by definition (RFC 6761), never resolved.
fn is_localhost(name: &str) -> bool {
    name == "localhost" || name.ends_with(".localhost")
}

/// The addresses the proxy connects to for `scope`'s request to reach `target`, or why not (module documentation,
/// "A decision"). `resolve` is asked at most once, and only for a name the host rules allow.
///
/// # Errors
///
/// The [`Refusal`]: [`Refusal::IpLiteral`], a host rule's refusal, [`Refusal::Unresolved`] or
/// [`Refusal::AddressNotAllowed`].
pub fn decide(
    scope: &Scope,
    target: &Target,
    resolve: impl FnOnce(&str) -> Option<Vec<IpAddr>>,
) -> Result<Vec<SocketAddr>, Refusal> {
    let port = target.port;
    let name = match &target.host {
        Host::Ip(ip) if scope.allows_ip_literal(*ip, port) => return Ok(vec![SocketAddr::new(*ip, port.get())]),
        Host::Ip(_) => return Err(Refusal::IpLiteral),
        Host::Name(name) => name,
    };
    if is_localhost(name) && scope.opens_loopback(port) {
        let loopback = [IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)];
        return Ok(loopback.map(|ip| SocketAddr::new(ip, port.get())).to_vec());
    }
    check_host(&scope.network, &scope.requester, name).map_err(refusal)?;
    let mut addresses = resolve(name).ok_or(Refusal::Unresolved)?;
    addresses.truncate(MAX_ADDRESSES);
    if addresses.is_empty() {
        return Err(Refusal::Unresolved);
    }
    // FR-NET-07: one internal address refuses the name, whatever the others are.
    if !addresses.iter().all(|ip| scope.allows_resolved(*ip, port)) {
        return Err(Refusal::AddressNotAllowed);
    }
    Ok(addresses
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port.get()))
        .collect())
}

/// The gate `knshd` runs (module documentation).
pub struct HostRules {
    scopes: Mutex<HashMap<Owner, Arc<Scope>>>,
    resolver: Arc<dyn Resolver>,
}

impl HostRules {
    /// A gate that knows no owner yet, resolving names with `resolver`.
    #[must_use]
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self {
            scopes: Mutex::new(HashMap::new()),
            resolver,
        }
    }

    /// Sets what `owner` may reach. Called when its credentials are issued, before they are handed out.
    pub fn set(&self, owner: Owner, scope: Scope) {
        self.lock().insert(owner, Arc::new(scope));
    }

    /// Forgets the scope of the line `record`. Called when its credentials are revoked.
    pub fn forget_line(&self, record: RecordId) {
        self.lock().retain(|owner, _| owner.line != Some(record));
    }

    /// Forgets every scope of `session` (its envelope's and its lines'). Called when its credentials are revoked.
    pub fn forget_session(&self, session: SessionId) {
        self.lock().retain(|owner, _| owner.session != session);
    }

    /// How many owners have a scope.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no owner has a scope.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Takes the lock even if a thread panicked while holding it: every update is a single map operation.
    fn lock(&self) -> MutexGuard<'_, HashMap<Owner, Arc<Scope>>> {
        self.scopes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The scope of `owner`, released from the lock before anything is resolved.
    fn scope(&self, owner: &Owner) -> Option<Arc<Scope>> {
        self.lock().get(owner).cloned()
    }
}

impl ConnectionGate for HostRules {
    fn check(&self, owner: &Owner, target: &Target) -> Result<Vec<SocketAddr>, Refusal> {
        let scope = self.scope(owner).ok_or(Refusal::NoHostRules)?;
        decide(&scope, target, |name| self.resolver.resolve(name).ok())
    }

    fn allows_ip_literal(&self, owner: &Owner, ip: IpAddr, port: NonZeroU16) -> bool {
        self.scope(owner).is_some_and(|scope| scope.allows_ip_literal(ip, port))
    }

    fn checks_server_name(&self, owner: &Owner, target: &Target) -> bool {
        self.scope(owner).is_none_or(|scope| scope.checks_server_name(target))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use knsh_core::{ClassHosts, LineAccess, NetworkClass, NetworkMode, Ulid};
    use knsh_platform::testing::FakeResolver;

    use super::*;

    fn network(mode: NetworkMode) -> NetworkPolicy {
        NetworkPolicy {
            mode,
            hosts: vec![
                "registry.npmjs.org".to_owned(),
                "git.corp".to_owned(),
                "10.1.2.3".to_owned(),
            ],
            approval_hosts: vec!["github.com".to_owned()],
            class_hosts: ClassHosts {
                fetch: vec!["github.com".to_owned()],
                publish: Vec::new(),
            },
            loopback: vec![3000],
            non_tls_hosts: vec!["git.corp".to_owned(), "*.plain.test".to_owned()],
        }
    }

    fn line_scope(mode: NetworkMode, classes: &[NetworkClass], dynamic: bool, approved: bool) -> Scope {
        Scope {
            network: network(mode),
            requester: Requester::Line(LineAccess {
                classes: classes.to_vec(),
                dynamic,
                approved,
                secret_hosts: Vec::new(),
            }),
        }
    }

    fn plain(mode: NetworkMode) -> Scope {
        line_scope(mode, &[], false, false)
    }

    fn target(text: &str) -> Target {
        Target::parse_authority(text.as_bytes()).unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// Answers every name with `addresses`.
    fn answering(addresses: &[&str]) -> impl FnOnce(&str) -> Option<Vec<IpAddr>> {
        let addresses: Vec<IpAddr> = addresses.iter().map(|text| ip(text)).collect();
        move |_| Some(addresses)
    }

    /// A resolver the decision must not ask.
    fn never(_: &str) -> Option<Vec<IpAddr>> {
        panic!("resolved a name it should have refused first")
    }

    // KNSH-060 refuses_ip_literal_destination (FR-NET-05): an address that is not listed is refused, public or
    // not, without resolving anything.
    #[test]
    fn refuses_ip_literal_destination() {
        let scope = plain(NetworkMode::Allowlist);
        for literal in [
            "93.184.216.34:443",
            "[2606:4700::1111]:443",
            "127.0.0.1:443",
            "169.254.169.254:80",
        ] {
            assert_eq!(
                decide(&scope, &target(literal), never),
                Err(Refusal::IpLiteral),
                "{literal}"
            );
        }
        assert!(!scope.allows_ip_literal(ip("93.184.216.34"), NonZeroU16::new(443).unwrap()));
    }

    // FR-NET-05: a listed address is allowlisted, as the destination itself.
    #[test]
    fn allowlisted_ip_literal_is_permitted() {
        let scope = plain(NetworkMode::Allowlist);
        assert_eq!(
            decide(&scope, &target("10.1.2.3:22"), never),
            Ok(vec![addr("10.1.2.3:22")])
        );
    }

    // KNSH-060 refuses_name_resolving_to_loopback (FR-NET-07): an allowed name that resolves to loopback (DNS
    // rebinding) is refused, also when only one of its addresses is loopback.
    #[test]
    fn refuses_name_resolving_to_loopback() {
        let scope = plain(NetworkMode::Allowlist);
        for answer in [
            &["127.0.0.1"][..],
            &["::1"],
            &["104.16.0.1", "127.0.0.1"],
            &["::ffff:127.0.0.1"],
        ] {
            assert_eq!(
                decide(&scope, &target("registry.npmjs.org:443"), answering(answer)),
                Err(Refusal::AddressNotAllowed),
                "{answer:?}"
            );
        }
    }

    // KNSH-060 refuses_name_resolving_to_private_and_link_local (FR-NET-07): IPv4 and IPv6 alike.
    #[test]
    fn refuses_name_resolving_to_private_and_link_local() {
        let scope = plain(NetworkMode::Allowlist);
        for answer in [
            "10.0.0.7",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "fd00::1",
            "fe80::1",
        ] {
            assert_eq!(
                decide(&scope, &target("registry.npmjs.org:443"), answering(&[answer])),
                Err(Refusal::AddressNotAllowed),
                "{answer}"
            );
        }
    }

    // KNSH-060 allowlisted_private_address_is_permitted (FR-NET-07): an internal address listed in a host rule is
    // allowlisted; another internal address of the same name is still refused.
    #[test]
    fn allowlisted_private_address_is_permitted() {
        let scope = plain(NetworkMode::Allowlist);
        assert_eq!(
            decide(&scope, &target("git.corp:443"), answering(&["10.1.2.3"])),
            Ok(vec![addr("10.1.2.3:443")])
        );
        assert_eq!(
            decide(&scope, &target("git.corp:443"), answering(&["10.1.2.3", "10.1.2.4"])),
            Err(Refusal::AddressNotAllowed)
        );
    }

    // FR-NET-07: public answers are connected to, in the resolver's order, with the requested port.
    #[test]
    fn allowed_name_gives_every_checked_address() {
        let scope = plain(NetworkMode::Allowlist);
        assert_eq!(
            decide(
                &scope,
                &target("registry.npmjs.org:443"),
                answering(&["2606:4700::6810:1", "104.16.0.1"])
            ),
            Ok(vec![addr("[2606:4700::6810:1]:443"), addr("104.16.0.1:443")])
        );
        assert_eq!(
            decide(&scope, &target("registry.npmjs.org:443"), |_| None),
            Err(Refusal::Unresolved)
        );
        assert_eq!(
            decide(&scope, &target("registry.npmjs.org:443"), answering(&[])),
            Err(Refusal::Unresolved)
        );
    }

    // FR-NET-02 to FR-NET-04, FR-NET-11: host rule refusals keep their reason, and nothing refused is resolved.
    #[test]
    fn host_rule_refusals_resolve_nothing() {
        let cases = [
            (
                plain(NetworkMode::Allowlist),
                "example.com:443",
                Refusal::HostNotAllowed,
            ),
            (
                plain(NetworkMode::Allowlist),
                "github.com:443",
                Refusal::ApprovalRequired,
            ),
            (
                line_scope(NetworkMode::Allowlist, &[], true, true),
                "github.com:443",
                Refusal::DynamicCode,
            ),
            (plain(NetworkMode::None), "registry.npmjs.org:443", Refusal::NetworkOff),
            (
                Scope {
                    network: network(NetworkMode::Allowlist),
                    requester: Requester::Envelope,
                },
                "github.com:443",
                Refusal::ApprovalRequired,
            ),
        ];
        for (scope, destination, expected) in cases {
            assert_eq!(
                decide(&scope, &target(destination), never),
                Err(expected),
                "{destination}"
            );
        }
        assert_eq!(
            decide(
                &line_scope(NetworkMode::Allowlist, &[NetworkClass::Fetch], false, false),
                &target("github.com:443"),
                answering(&["140.82.112.3"])
            ),
            Ok(vec![addr("140.82.112.3:443")])
        );
    }

    // KNSH-060 mode_none_refuses_all_but_loopback (FR-NET-04): under `none` only the loopback ports are reachable,
    // as an address or as `localhost`, which is never resolved.
    #[test]
    fn mode_none_refuses_all_but_loopback() {
        let scope = plain(NetworkMode::None);
        assert_eq!(
            decide(&scope, &target("127.0.0.1:3000"), never),
            Ok(vec![addr("127.0.0.1:3000")])
        );
        assert_eq!(
            decide(&scope, &target("[::1]:3000"), never),
            Ok(vec![addr("[::1]:3000")])
        );
        assert_eq!(
            decide(&scope, &target("localhost:3000"), never),
            Ok(vec![addr("127.0.0.1:3000"), addr("[::1]:3000")])
        );
        assert_eq!(
            decide(&scope, &target("127.0.0.1:3001"), never),
            Err(Refusal::IpLiteral)
        );
        assert_eq!(decide(&scope, &target("localhost:22"), never), Err(Refusal::NetworkOff));
        assert_eq!(
            decide(&scope, &target("registry.npmjs.org:443"), never),
            Err(Refusal::NetworkOff)
        );
        // A loopback port does not open other internal addresses.
        assert_eq!(decide(&scope, &target("10.0.0.1:3000"), never), Err(Refusal::IpLiteral));
    }

    // KNSH-092 network_narrowed_to_secret_hosts (FR-SEC-03, FR-NET-10): a line that receives a secret reaches only
    // the secret's hosts; other open hosts, allowlisted addresses and the loopback ports are refused to it.
    #[test]
    fn network_narrowed_to_secret_hosts() {
        let mut scope = plain(NetworkMode::Allowlist);
        if let Requester::Line(line) = &mut scope.requester {
            line.secret_hosts = vec![vec!["registry.npmjs.org".to_owned()]];
        }
        assert_eq!(
            decide(&scope, &target("registry.npmjs.org:443"), answering(&["104.16.0.1"])),
            Ok(vec![addr("104.16.0.1:443")])
        );
        assert_eq!(
            decide(&scope, &target("git.corp:443"), never),
            Err(Refusal::SecretHosts)
        );
        assert_eq!(decide(&scope, &target("10.1.2.3:443"), never), Err(Refusal::IpLiteral));
        assert!(!scope.allows_ip_literal(ip("10.1.2.3"), NonZeroU16::new(443).unwrap()));
        // No loopback port: `localhost` and loopback addresses go through the host rules, which do not list them.
        assert_eq!(
            decide(&scope, &target("127.0.0.1:3000"), never),
            Err(Refusal::IpLiteral)
        );
        assert_eq!(
            decide(&scope, &target("localhost:3000"), never),
            Err(Refusal::HostNotAllowed)
        );
        assert!(scope.checks_server_name(&target("localhost:3000")));
        assert_eq!(Refusal::SecretHosts.reason(), "secret_hosts");
    }

    // KNSH-060 connects_to_checked_address_without_reresolving (FR-NET-07): the gate resolves once and returns the
    // addresses it checked; a later change of answer (rebinding) does not reach this decision.
    #[test]
    fn gate_resolves_once_and_returns_the_checked_addresses() {
        let resolver = Arc::new(FakeResolver::new());
        resolver.answer("registry.npmjs.org", &[ip("104.16.0.1")]);
        let rules = HostRules::new(Arc::clone(&resolver) as Arc<dyn Resolver>);
        let owner = Owner {
            session: SessionId::from_ulid(Ulid::from_u128(1)),
            line: Some(RecordId::from_ulid(Ulid::from_u128(2))),
        };
        rules.set(owner, plain(NetworkMode::Allowlist));
        let checked = rules.check(&owner, &target("registry.npmjs.org:443"));
        resolver.answer("registry.npmjs.org", &[ip("127.0.0.1")]);
        assert_eq!(checked, Ok(vec![addr("104.16.0.1:443")]));
        assert_eq!(resolver.asked(), ["registry.npmjs.org"]);
        // The next connection resolves again and meets the rebinding.
        assert_eq!(
            rules.check(&owner, &target("registry.npmjs.org:443")),
            Err(Refusal::AddressNotAllowed)
        );
    }

    // Fail closed: an owner with no scope (never set, or forgotten with its credentials) is refused.
    #[test]
    fn owner_without_scope_is_refused() {
        let resolver = Arc::new(FakeResolver::new());
        let rules = HostRules::new(resolver);
        let session = SessionId::from_ulid(Ulid::from_u128(1));
        let envelope = Owner { session, line: None };
        let line = Owner {
            session,
            line: Some(RecordId::from_ulid(Ulid::from_u128(2))),
        };
        assert_eq!(
            rules.check(&envelope, &target("10.1.2.3:22")),
            Err(Refusal::NoHostRules)
        );
        rules.set(envelope, plain(NetworkMode::Allowlist));
        rules.set(line, plain(NetworkMode::Allowlist));
        let port = NonZeroU16::new(22).unwrap();
        assert!(rules.allows_ip_literal(&line, ip("10.1.2.3"), port));
        rules.forget_line(line.line.unwrap());
        assert!(!rules.allows_ip_literal(&line, ip("10.1.2.3"), port));
        assert!(rules.allows_ip_literal(&envelope, ip("10.1.2.3"), port));
        rules.forget_session(session);
        assert!(rules.is_empty());
        assert_eq!(
            rules.check(&envelope, &target("10.1.2.3:22")),
            Err(Refusal::NoHostRules)
        );
    }

    // FR-NET-07: the resolver is asked only after the host rules allowed the name.
    #[test]
    fn resolves_only_allowed_names() {
        let asked = Cell::new(0);
        let scope = plain(NetworkMode::Allowlist);
        let _ = decide(&scope, &target("example.com:443"), |_| {
            asked.set(asked.get() + 1);
            None
        });
        assert_eq!(asked.get(), 0);
    }

    // FR-NET-06: every tunnel is checked for a TLS server name, except to `network.non_tls_hosts` and to the
    // loopback ports (which the profile lets the command reach directly); an owner without a scope is checked.
    #[test]
    fn checks_server_name_unless_non_tls_or_loopback_port() {
        let scope = plain(NetworkMode::Allowlist);
        assert!(scope.checks_server_name(&target("registry.npmjs.org:443")));
        assert!(scope.checks_server_name(&target("github.com:443")));
        assert!(scope.checks_server_name(&target("10.1.2.3:443")));
        assert!(!scope.checks_server_name(&target("git.corp:9418")));
        assert!(!scope.checks_server_name(&target("GIT.corp.:443")));
        assert!(!scope.checks_server_name(&target("a.plain.test:80")));
        assert!(scope.checks_server_name(&target("plain.test:80")));
        assert!(!scope.checks_server_name(&target("localhost:3000")));
        assert!(!scope.checks_server_name(&target("127.0.0.1:3000")));
        assert!(!scope.checks_server_name(&target("[::1]:3000")));
        assert!(scope.checks_server_name(&target("localhost:3001")));

        let rules = HostRules::new(Arc::new(FakeResolver::new()));
        let session = SessionId::from_ulid(Ulid::from_u128(1));
        let envelope = Owner { session, line: None };
        assert!(rules.checks_server_name(&envelope, &target("git.corp:9418")));
        rules.set(envelope, plain(NetworkMode::Allowlist));
        assert!(!rules.checks_server_name(&envelope, &target("git.corp:9418")));
        assert!(rules.checks_server_name(&envelope, &target("registry.npmjs.org:443")));
    }
}
