//! Proxy credentials, host rules and reporting for envelopes and lines (KNSH-057, KNSH-059, KNSH-060; FR-AGT-03,
//! FR-NET-01 to FR-NET-05, FR-NET-07, FR-NET-09, FR-NET-11, decision 14).
//!
//! Every envelope and every supervised line reaches the network only through `knshd`'s proxy (`knsh-proxy`): their
//! sandbox profiles allow outbound TCP to the proxy's loopback port and the profile's `network.loopback` ports,
//! nothing else (`specs/03-functional-requirements/sandbox-profiles.md`). So the proxy can tie each connection to
//! one command, each envelope and each line gets credentials of its own, issued when it starts and revoked when it
//! ends, and carried in its environment as the user and password of an HTTP proxy URL (decision 14):
//!
//! ```text
//! http://knsh-<id>:<token>@127.0.0.1:<port>
//! ```
//!
//! # Who issues them
//!
//! The proxy itself, behind [`ProxyIssuer`]: it alone maps credentials to sessions and records. `knshd` starts one
//! [`LiveProxy`] at start-up. If it cannot start, `knshd` wires [`NoProxy`] instead: envelopes and lines then get
//! no proxy settings and no proxy port in their profile, so they reach nothing but their loopback ports. That fails
//! closed: nothing leaves the machine unfiltered, and nothing pretends a proxy is there.
//!
//! # What it lets through
//!
//! The proxy's gate is [`knsh_proxy::HostRules`]: each owner of credentials gets a [`Scope`] when they are issued,
//! and loses it when they are revoked. An envelope's scope is its session profile's `[network]` policy, with the
//! envelope as requester (it reaches `network.hosts` only); a line's is the profile its decision was made under,
//! with the line's classes, dynamic flag and approval ([`LineAccess`]). The gate applies the host rules, resolves
//! names itself and refuses internal addresses (`knsh-proxy`'s `rules` module). `hello` keeps reporting
//! `network_filter: none` until the TLS server-name check (FR-NET-06, KNSH-061) is in force too.
//!
//! # Reporting ([`NetworkReport`])
//!
//! Every refusal is logged (fixed fields, never a host name or a credential, NFR-PRIV-02). A refusal whose
//! credentials were live is also published as `proxy.denied` for the owner's session, naming the record for a line
//! and none for the envelope, whose connections belong to the session alone (FR-NET-09). A line's refusals and
//! contacts are also collected for its record's `network` field while the line runs, and handed to the spawner when
//! its credentials are revoked ([`ProxyIssuer::revoke_line`]); the proxy reports a connection before the revocation
//! that ends it returns, so nothing reported for a running line is missed.
//!
//! # The environment
//!
//! [`proxy_env`] gives the variables decision 14 names, and [`is_proxy_var`] the inherited ones every envelope and
//! line loses first, with or without a proxy: a caller's own proxy (and the credentials in its URL) must not reach
//! the command, a `NO_PROXY` or `ALL_PROXY` it set could send a tool around the proxy, and a line must never run with
//! its envelope's credentials, which would attribute its connections to the session instead of its record
//! ([`command_env`]).

use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::{
    EventData, LineAccess, MAX_NETWORK_ENTRIES, NetworkEntry, NetworkPolicy, NetworkResult, RecordId, Redacted,
    Requester, SessionId, merge_network, redact,
};
use knsh_platform::{Field, Level, SystemLog, Value};
use knsh_proxy::{Denial, HostRules, Owner, Proxy, ProxyReport, Scope, Target};

use crate::events::EventHub;

/// The variables that carry the proxy URL (decision 14): curl, git, pip, cargo and Node (with
/// [`NODE_USE_ENV_PROXY`]) read one of them.
const PROXY_URL_VARS: [&str; 4] = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];

/// Node ignores the proxy variables without it (KNSH-027, C9).
const NODE_USE_ENV_PROXY: &str = "NODE_USE_ENV_PROXY";

/// git otherwise waits for a `407` challenge before it sends credentials: one extra round trip per connection.
const GIT_HTTP_PROXY_AUTHMETHOD: &str = "GIT_HTTP_PROXY_AUTHMETHOD";

/// Inherited variables an envelope never keeps, besides [`PROXY_URL_VARS`]: proxy settings that would send a tool
/// elsewhere (`ALL_PROXY`, the tool-specific ones presets may set) or around the proxy (`NO_PROXY`), and the two
/// switches decision 14 sets itself.
const OTHER_PROXY_VARS: [&str; 12] = [
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    NODE_USE_ENV_PROXY,
    GIT_HTTP_PROXY_AUTHMETHOD,
    "npm_config_https_proxy",
    "npm_config_proxy",
    "NPM_CONFIG_HTTPS_PROXY",
    "NPM_CONFIG_PROXY",
    "PIP_PROXY",
    "CARGO_HTTP_PROXY",
];

/// The loopback address the proxy URL names. An address, not `localhost`: the resolver is denied in every profile
/// (FR-NET-08), and the profile's allow is for the loopback interface.
const PROXY_HOST: &str = "127.0.0.1";

/// Longest credential id or token accepted: far above what the proxy issues, low enough to keep URLs small.
const MAX_PART_LEN: usize = 128;

/// One envelope's proxy credentials: the proxy's port, and the id and token the proxy maps to the session.
///
/// Invariant: the id and token are 1 to [`MAX_PART_LEN`] ASCII letters and digits, so neither ends the URL's user
/// or password part (`:`, `@`, `/`) and no tool has to percent-decode them (decision 14).
#[derive(Clone)]
pub(crate) struct ProxyCredential {
    port: NonZeroU16,
    id: String,
    token: Redacted<String>,
}

impl ProxyCredential {
    /// Credentials for the proxy on `port`, or `None` if `id` or `token` breaks the invariant.
    pub(crate) fn new(port: NonZeroU16, id: &str, token: Redacted<String>) -> Option<Self> {
        let valid = |text: &str| {
            !text.is_empty() && text.len() <= MAX_PART_LEN && text.bytes().all(|byte| byte.is_ascii_alphanumeric())
        };
        (valid(id) && valid(token.expose())).then(|| Self {
            port,
            id: id.to_owned(),
            token,
        })
    }

    /// The proxy's loopback port: the one the envelope profile allows besides `network.loopback`.
    pub(crate) fn port(&self) -> NonZeroU16 {
        self.port
    }

    /// `http://knsh-<id>:<token>@127.0.0.1:<port>`. Redacted: it holds the token.
    pub(crate) fn url(&self) -> Redacted<String> {
        Redacted::new(format!(
            "http://knsh-{}:{}@{PROXY_HOST}:{}",
            self.id,
            self.token.expose(),
            self.port
        ))
    }
}

impl fmt::Debug for ProxyCredential {
    /// The port and id only: the token never reaches a log or a test failure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyCredential")
            .field("port", &self.port)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Why the proxy could not issue credentials. The envelope does not start (fail closed, `-32603`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProxyUnavailable;

/// Issues and revokes envelope and line credentials (module documentation, "Who issues them"). Object safe, so
/// tests can issue fixed credentials.
pub(crate) trait ProxyIssuer: Send + Sync {
    /// Credentials for the envelope of `session`, whose connections may reach what `network` opens to the envelope,
    /// or `None` when no proxy runs: the envelope then gets no proxy settings and its profile no proxy port.
    ///
    /// # Errors
    ///
    /// A proxy runs but could not issue credentials: the envelope must not start.
    fn issue(&self, session: SessionId, network: &NetworkPolicy) -> Result<Option<ProxyCredential>, ProxyUnavailable>;

    /// Credentials for the line `record` of `session`, whose connections may reach what `network` opens to a line
    /// presenting `access`, or `None` when no proxy runs.
    ///
    /// # Errors
    ///
    /// A proxy runs but could not issue credentials: the line must not start.
    fn issue_line(
        &self,
        session: SessionId,
        record: RecordId,
        network: &NetworkPolicy,
        access: LineAccess,
    ) -> Result<Option<ProxyCredential>, ProxyUnavailable>;

    /// Revokes the credentials of the line `record` and closes its connections, and returns its record's `network`
    /// field: the hosts it contacted or was refused (FR-NET-09). Called once the line has ended, whether or not
    /// [`ProxyIssuer::issue_line`] succeeded.
    fn revoke_line(&self, record: RecordId) -> Vec<NetworkEntry>;

    /// Revokes every credential issued for `session` (its envelope's and its lines'). Called once its envelope has
    /// ended, whether or not [`ProxyIssuer::issue`] succeeded, so it must accept a session it issued nothing for.
    fn revoke(&self, session: SessionId);
}

/// No proxy runs (`network_filter: none`): envelopes and lines get no proxy settings and reach only their loopback
/// ports.
pub(crate) struct NoProxy;

impl ProxyIssuer for NoProxy {
    fn issue(
        &self,
        _session: SessionId,
        _network: &NetworkPolicy,
    ) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
        Ok(None)
    }

    fn issue_line(
        &self,
        _session: SessionId,
        _record: RecordId,
        _network: &NetworkPolicy,
        _access: LineAccess,
    ) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
        Ok(None)
    }

    fn revoke_line(&self, _record: RecordId) -> Vec<NetworkEntry> {
        Vec::new()
    }

    fn revoke(&self, _session: SessionId) {}
}

/// The running proxy (`knsh-proxy`) as the [`ProxyIssuer`], with the gate and the report it was started with.
pub(crate) struct LiveProxy {
    proxy: Proxy,
    rules: Arc<HostRules>,
    report: Arc<NetworkReport>,
}

impl LiveProxy {
    /// Wraps a proxy started with `rules` as its gate and `report` as its report.
    pub(crate) fn new(proxy: Proxy, rules: Arc<HostRules>, report: Arc<NetworkReport>) -> Self {
        Self { proxy, rules, report }
    }

    /// Sets `owner`'s scope, then issues its credentials in the URL form of decision 14. The scope is set first, so
    /// no connection with the credentials meets a gate that does not know them.
    fn issue_for(&self, owner: Owner, scope: Scope) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
        self.rules.set(owner, scope);
        let issued = self.proxy.issue(owner).map_err(|_| ProxyUnavailable)?;
        // The proxy issues decimal ids and letter-and-digit tokens, so this holds; if it ever did not, the command
        // must not start without its credentials (fail closed).
        ProxyCredential::new(self.proxy.port(), issued.id(), issued.token().clone())
            .map(Some)
            .ok_or(ProxyUnavailable)
    }
}

impl ProxyIssuer for LiveProxy {
    fn issue(&self, session: SessionId, network: &NetworkPolicy) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
        let scope = Scope {
            network: network.clone(),
            requester: Requester::Envelope,
        };
        self.issue_for(Owner { session, line: None }, scope)
    }

    fn issue_line(
        &self,
        session: SessionId,
        record: RecordId,
        network: &NetworkPolicy,
        access: LineAccess,
    ) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
        // Collected from the first connection on; forgotten by `revoke_line` whatever happens next.
        self.report.track(session, record);
        let scope = Scope {
            network: network.clone(),
            requester: Requester::Line(access),
        };
        let owner = Owner {
            session,
            line: Some(record),
        };
        self.issue_for(owner, scope)
    }

    fn revoke_line(&self, record: RecordId) -> Vec<NetworkEntry> {
        // Revoking closes the line's connections, and the proxy has reported each before this returns ("Reporting"),
        // so the collected list is complete for every connection the line made while it ran.
        self.proxy.revoke_line(record);
        self.rules.forget_line(record);
        self.report.take(record)
    }

    fn revoke(&self, session: SessionId) {
        self.proxy.revoke_session(session);
        self.rules.forget_session(session);
        self.report.forget_session(session);
    }
}

/// The network entries collected for each running line: its session, and its entries so far.
type Running = HashMap<RecordId, (SessionId, Vec<NetworkEntry>)>;

/// The proxy's report (module documentation, "Reporting"): the system log, `proxy.denied` events and the lines'
/// `network` fields.
///
/// Only lines being tracked ([`NetworkReport::track`] to [`NetworkReport::take`]) collect entries, so the map holds
/// no more lines than are running, and a report that arrives after a line was taken is not kept.
pub(crate) struct NetworkReport {
    log: Arc<dyn SystemLog>,
    events: Arc<EventHub>,
    running: Mutex<Running>,
}

impl NetworkReport {
    /// Reports to `log` and publishes to `events`.
    pub(crate) fn new(log: Arc<dyn SystemLog>, events: Arc<EventHub>) -> Arc<Self> {
        Arc::new(Self {
            log,
            events,
            running: Mutex::new(HashMap::new()),
        })
    }

    /// Takes the lock even if a thread panicked while holding it: every update is one map operation.
    fn lock(&self) -> MutexGuard<'_, Running> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts collecting the line `record` of `session`.
    pub(crate) fn track(&self, session: SessionId, record: RecordId) {
        self.lock().entry(record).or_insert_with(|| (session, Vec::new()));
    }

    /// Stops collecting the line `record` and returns what was collected.
    pub(crate) fn take(&self, record: RecordId) -> Vec<NetworkEntry> {
        self.lock()
            .remove(&record)
            .map(|(_, entries)| entries)
            .unwrap_or_default()
    }

    /// Stops collecting every line of `session` (its lines are taken one by one when they end; this only guards
    /// against one that never was).
    pub(crate) fn forget_session(&self, session: SessionId) {
        self.lock().retain(|_, (owner, _)| *owner != session);
    }

    /// Adds one entry to the record of `owner`'s line, if it is being collected for that session. Envelope
    /// connections have no record (FR-NET-09).
    fn collect(&self, owner: &Owner, target: &Target, result: NetworkResult) {
        let Some(record) = owner.line else {
            return;
        };
        let entry = NetworkEntry::new(redact(&target.host.to_string()), target.port.get(), result);
        if let Some((session, entries)) = self.lock().get_mut(&record)
            && *session == owner.session
        {
            merge_network(entries, vec![entry], MAX_NETWORK_ENTRIES);
        }
    }

    /// The system log entry for a refusal: fixed fields only.
    fn log_denial(&self, denial: &Denial) {
        let mut fields = vec![Field::new("reason", Value::Static(denial.refusal.reason()))];
        if let Some(protocol) = denial.protocol {
            fields.push(Field::new("protocol", Value::Static(protocol.name())));
        }
        if let Some(owner) = denial.owner {
            fields.push(Field::new("session_id", Value::Id(owner.session.ulid())));
            if let Some(record) = owner.line {
                fields.push(Field::new("record_id", Value::Id(record.ulid())));
            }
        }
        if let Some(target) = &denial.target {
            fields.push(Field::new("port", Value::U64(u64::from(target.port.get()))));
        }
        self.log.log(Level::Notice, "proxy refused a connection", &fields);
    }
}

impl ProxyReport for NetworkReport {
    fn denied(&self, denial: &Denial) {
        self.log_denial(denial);
        // Before credentials were checked there is no session to publish to: the log entry is the report.
        let Some(owner) = denial.owner else {
            return;
        };
        let reason = denial.refusal.reason();
        let data = EventData::ProxyDenied {
            record_id: owner.line,
            protocol: denial.protocol.map(knsh_proxy::Protocol::name),
            host: denial.target.as_ref().map(|target| redact(&target.host.to_string())),
            port: denial.target.as_ref().map(|target| target.port.get()),
            reason,
        };
        // Best effort: a session that has ended (or is not this engine's) gets no event.
        let _ = self.events.publish_for_session(owner.session, data);
        if let Some(target) = &denial.target {
            self.collect(&owner, target, NetworkResult::Refused(reason.to_owned()));
        }
    }

    fn contacted(&self, owner: &Owner, target: &Target) {
        self.collect(owner, target, NetworkResult::Contacted);
    }
}

/// A command's environment: `env` without any inherited proxy setting, plus the command's own ([`proxy_env`]).
pub(crate) fn command_env(env: &[(String, String)], credential: Option<&ProxyCredential>) -> Vec<(String, String)> {
    env.iter()
        .filter(|(name, _)| !is_proxy_var(name))
        .cloned()
        .chain(proxy_env(credential))
        .collect()
}

/// Whether `name` is an inherited proxy setting the envelope loses (module documentation, "The environment").
pub(crate) fn is_proxy_var(name: &str) -> bool {
    PROXY_URL_VARS.contains(&name) || OTHER_PROXY_VARS.contains(&name)
}

/// The variables that send the envelope's traffic through the proxy with `credential` (decision 14): the four URL
/// variables, `NODE_USE_ENV_PROXY=1` and `GIT_HTTP_PROXY_AUTHMETHOD=basic`. Nothing without a credential.
pub(crate) fn proxy_env(credential: Option<&ProxyCredential>) -> Vec<(String, String)> {
    let Some(credential) = credential else {
        return Vec::new();
    };
    let url = credential.url();
    PROXY_URL_VARS
        .iter()
        .map(|name| ((*name).to_owned(), url.expose().clone()))
        .chain([
            (NODE_USE_ENV_PROXY.to_owned(), "1".to_owned()),
            (GIT_HTTP_PROXY_AUTHMETHOD.to_owned(), "basic".to_owned()),
        ])
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use knsh_core::{Delivery, EventScope};
    use knsh_platform::testing::{FakeResolver, RecordingLog};

    use super::*;
    use crate::events::Subscriber;

    /// A proxy on `port` that issues `knsh-<n>:<token>` per session, numbered from 1, and `knsh-line<n>:<token>`
    /// per line, records what each line presented and every revocation, and returns `network` when a line is
    /// revoked.
    pub(crate) struct FakeProxy {
        pub(crate) port: NonZeroU16,
        /// When set, issuing fails.
        pub(crate) broken: bool,
        pub(crate) issued: Mutex<Vec<SessionId>>,
        pub(crate) revoked: Mutex<Vec<SessionId>>,
        pub(crate) lines: Mutex<Vec<RecordId>>,
        pub(crate) accesses: Mutex<Vec<LineAccess>>,
        pub(crate) revoked_lines: Mutex<Vec<RecordId>>,
        pub(crate) network: Mutex<Vec<NetworkEntry>>,
    }

    impl FakeProxy {
        /// The token every credential of this fake carries.
        pub(crate) const TOKEN: &'static str = "s3cr3tT0ken";

        /// A working proxy on `port` that has issued and revoked nothing yet.
        pub(crate) fn new(port: u16) -> Self {
            Self {
                port: NonZeroU16::new(port).unwrap(),
                broken: false,
                issued: Mutex::new(Vec::new()),
                revoked: Mutex::new(Vec::new()),
                lines: Mutex::new(Vec::new()),
                accesses: Mutex::new(Vec::new()),
                revoked_lines: Mutex::new(Vec::new()),
                network: Mutex::new(Vec::new()),
            }
        }
    }

    impl ProxyIssuer for FakeProxy {
        fn issue(
            &self,
            session: SessionId,
            _network: &NetworkPolicy,
        ) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
            if self.broken {
                return Err(ProxyUnavailable);
            }
            let mut issued = self.issued.lock().unwrap();
            issued.push(session);
            let id = issued.len().to_string();
            Ok(ProxyCredential::new(
                self.port,
                &id,
                Redacted::new(Self::TOKEN.to_owned()),
            ))
        }

        fn issue_line(
            &self,
            _session: SessionId,
            record: RecordId,
            _network: &NetworkPolicy,
            access: LineAccess,
        ) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
            if self.broken {
                return Err(ProxyUnavailable);
            }
            self.accesses.lock().unwrap().push(access);
            let mut lines = self.lines.lock().unwrap();
            lines.push(record);
            let id = format!("line{}", lines.len());
            Ok(ProxyCredential::new(
                self.port,
                &id,
                Redacted::new(Self::TOKEN.to_owned()),
            ))
        }

        fn revoke_line(&self, record: RecordId) -> Vec<NetworkEntry> {
            self.revoked_lines.lock().unwrap().push(record);
            self.network.lock().unwrap().clone()
        }

        fn revoke(&self, session: SessionId) {
            self.revoked.lock().unwrap().push(session);
        }
    }

    /// The real proxy with the gate `knshd` runs (host rules over `resolver`), reporting to a recording log and to
    /// an event hub.
    struct Live {
        proxy: LiveProxy,
        log: Arc<RecordingLog>,
        hub: Arc<EventHub>,
    }

    fn live_with(resolver: Arc<FakeResolver>) -> Live {
        use knsh_platform::macos::{SystemClock, SystemRandom};
        use knsh_proxy::{Config, Parts};

        let log = Arc::new(RecordingLog::new());
        let hub = crate::events::tests::hub();
        let rules = Arc::new(HostRules::new(resolver));
        let report = NetworkReport::new(Arc::clone(&log) as Arc<dyn SystemLog>, Arc::clone(&hub));
        let proxy = Proxy::start(
            Config::DEFAULT,
            Parts {
                gate: Arc::clone(&rules) as Arc<dyn knsh_proxy::ConnectionGate>,
                report: Arc::clone(&report) as Arc<dyn ProxyReport>,
                random: Arc::new(SystemRandom::new()),
                clock: Arc::new(SystemClock::new()),
            },
        )
        .unwrap();
        Live {
            proxy: LiveProxy::new(proxy, rules, report),
            log,
            hub,
        }
    }

    fn live() -> (LiveProxy, Arc<RecordingLog>) {
        let live = live_with(Arc::new(FakeResolver::new()));
        (live.proxy, live.log)
    }

    /// `network.mode = "allowlist"` with `hosts` open to every command and `github.com` for approval.
    fn allowlist(hosts: &[&str]) -> NetworkPolicy {
        NetworkPolicy {
            mode: knsh_core::NetworkMode::Allowlist,
            hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
            approval_hosts: vec!["github.com".to_owned()],
            class_hosts: knsh_core::ClassHosts::default(),
            loopback: Vec::new(),
        }
    }

    /// The default `[network]`: `mode = "none"`.
    fn no_network() -> NetworkPolicy {
        NetworkPolicy {
            mode: knsh_core::NetworkMode::None,
            hosts: Vec::new(),
            approval_hosts: Vec::new(),
            class_hosts: knsh_core::ClassHosts::default(),
            loopback: Vec::new(),
        }
    }

    /// A server on loopback that accepts connections and holds them open.
    fn accepting_server() -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                held.push(stream);
            }
        });
        address
    }

    /// Sends a CONNECT for `example.com:443` with the user and password of `credential`'s URL (or none), and
    /// returns the status line.
    fn connect_status(port: NonZeroU16, credential: Option<&ProxyCredential>) -> String {
        connect_to(port, "example.com:443", credential)
    }

    /// Sends a CONNECT for `target` with the user and password of `credential`'s URL (or none), and returns the
    /// status line.
    fn connect_to(port: NonZeroU16, target: &str, credential: Option<&ProxyCredential>) -> String {
        use std::io::{BufRead, BufReader, Write};

        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port.get())).unwrap();
        let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(credential) = credential {
            let url = credential.url().expose().clone();
            let userinfo = &url["http://".len()..url.find('@').unwrap()];
            request = format!(
                "{request}Proxy-Authorization: Basic {}\r\n",
                base64(userinfo.as_bytes())
            );
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).unwrap();
        let mut status = String::new();
        BufReader::new(stream).read_line(&mut status).unwrap();
        status
    }

    /// Standard padded base64, for test requests.
    fn base64(input: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
            for i in 0..4 {
                out.push(if i <= chunk.len() {
                    char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize])
                } else {
                    '='
                });
            }
        }
        out
    }

    fn session(n: u128) -> SessionId {
        SessionId::from_ulid(knsh_core::Ulid::from_u128(n))
    }

    fn record(n: u128) -> RecordId {
        RecordId::from_ulid(knsh_core::Ulid::from_u128(n))
    }

    // FR-NET-01: the live proxy issues distinct credentials per envelope and line, on its own loopback port; they
    // authenticate until revoked, and meet the session's host rules (here `network.mode = "none"`, FR-NET-04).
    #[test]
    fn live_proxy_issues_and_revokes_envelope_and_line_credentials() {
        let (proxy, log) = live();
        let envelope = proxy.issue(session(1), &no_network()).unwrap().unwrap();
        let line = proxy
            .issue_line(session(1), record(5), &no_network(), LineAccess::default())
            .unwrap()
            .unwrap();
        assert_eq!(envelope.port(), proxy.proxy.port());
        assert_eq!(line.port(), envelope.port());
        assert_ne!(envelope.url().expose(), line.url().expose());
        let port = envelope.port();

        // Live credentials pass the 407 and meet the gate, which refuses (403); none get the challenge.
        assert!(connect_status(port, Some(&line)).starts_with("HTTP/1.1 403 "));
        assert!(connect_status(port, None).starts_with("HTTP/1.1 407 "));
        proxy.revoke_line(record(5));
        assert!(connect_status(port, Some(&line)).starts_with("HTTP/1.1 407 "));
        assert!(connect_status(port, Some(&envelope)).starts_with("HTTP/1.1 403 "));
        proxy.revoke(session(1));
        assert!(connect_status(port, Some(&envelope)).starts_with("HTTP/1.1 407 "));

        // Every refusal is logged with its reason; the gate's names the line, and no entry names the host.
        let started = std::time::Instant::now();
        while log.entries().len() < 5 && started.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let entries = format!("{:?}", log.entries());
        assert!(entries.contains("network_off"), "{entries}");
        assert!(entries.contains("missing_credentials"), "{entries}");
        assert!(entries.contains("unknown_credentials"), "{entries}");
        assert!(entries.contains(&record(5).ulid().to_string()), "{entries}");
        assert!(!entries.contains("example.com"), "{entries}");
    }

    // FR-NET-01: a line never keeps its envelope's (or a caller's) proxy settings; it gets its own.
    #[test]
    fn command_env_replaces_inherited_proxy_settings() {
        let line = ProxyCredential::new(NonZeroU16::new(9).unwrap(), "2", Redacted::new("lineTok".to_owned())).unwrap();
        let inherited = vec![
            ("PATH".to_owned(), "/usr/bin".to_owned()),
            ("HTTPS_PROXY".to_owned(), "http://knsh-1:envTok@127.0.0.1:9".to_owned()),
            ("NO_PROXY".to_owned(), "*".to_owned()),
            ("ALL_PROXY".to_owned(), "socks5://elsewhere".to_owned()),
        ];
        let env = command_env(&inherited, Some(&line));
        assert!(env.contains(&("PATH".to_owned(), "/usr/bin".to_owned())));
        assert!(env.contains(&("HTTPS_PROXY".to_owned(), "http://knsh-2:lineTok@127.0.0.1:9".to_owned())));
        assert!(
            !env.iter()
                .any(|(name, value)| name == "NO_PROXY" || name == "ALL_PROXY" || value.contains("envTok"))
        );
        assert_eq!(env.iter().filter(|(name, _)| name == "HTTPS_PROXY").count(), 1);
        // Without a proxy: no proxy settings at all.
        let bare = command_env(&inherited, None);
        assert_eq!(bare, [("PATH".to_owned(), "/usr/bin".to_owned())]);
    }

    // Decision 14: the URL carries the id and token as user and password, on the loopback address and the port.
    #[test]
    fn credential_url_names_id_token_and_port() {
        let credential = ProxyCredential::new(
            NonZeroU16::new(41_000).unwrap(),
            "7",
            Redacted::new("abc123".to_owned()),
        )
        .unwrap();
        assert_eq!(credential.url().expose(), "http://knsh-7:abc123@127.0.0.1:41000");
        assert_eq!(credential.port().get(), 41_000);
        // The token never shows in debug output.
        assert!(!format!("{credential:?}").contains("abc123"));
    }

    // Decision 14: anything but letters and digits could end the URL's user or password part, or need decoding.
    #[test]
    fn credential_refuses_parts_that_would_break_the_url() {
        let port = NonZeroU16::new(1).unwrap();
        for (id, token) in [
            ("", "t"),
            ("i", ""),
            ("a@b", "t"),
            ("i", "x:y"),
            ("i", "p/q"),
            ("i", "é"),
        ] {
            assert!(
                ProxyCredential::new(port, id, Redacted::new(token.to_owned())).is_none(),
                "{id} {token}"
            );
        }
        assert!(ProxyCredential::new(port, &"a".repeat(MAX_PART_LEN + 1), Redacted::new("t".to_owned())).is_none());
    }

    // Decision 14: the four URL variables, Node's switch and git's Basic scheme; nothing without a proxy.
    #[test]
    fn proxy_env_sets_url_variables_and_switches() {
        let credential =
            ProxyCredential::new(NonZeroU16::new(9).unwrap(), "1", Redacted::new("tok".to_owned())).unwrap();
        let env = proxy_env(Some(&credential));
        let url = "http://knsh-1:tok@127.0.0.1:9";
        for name in PROXY_URL_VARS {
            assert!(env.contains(&(name.to_owned(), url.to_owned())), "{name}");
        }
        assert!(env.contains(&("NODE_USE_ENV_PROXY".to_owned(), "1".to_owned())));
        assert!(env.contains(&("GIT_HTTP_PROXY_AUTHMETHOD".to_owned(), "basic".to_owned())));
        assert!(
            env.iter().all(|(name, _)| is_proxy_var(name)),
            "every variable set is one stripped first"
        );
        assert_eq!(proxy_env(None), []);
        assert!(
            NoProxy
                .issue(SessionId::from_ulid(knsh_core::Ulid::from_u128(1)), &no_network())
                .unwrap()
                .is_none()
        );
    }

    /// One `proxy.denied` as published: `(record_id, protocol, host, port, reason)`.
    type Published = (Option<RecordId>, Option<String>, Option<String>, Option<u16>, String);

    /// The `proxy.denied` events `subscriber` received so far.
    fn proxy_denied(subscriber: &Subscriber) -> Vec<Published> {
        subscriber
            .take(1_000)
            .into_iter()
            .filter_map(|(_, delivery)| match delivery {
                Delivery::Event(event) => match &event.data {
                    EventData::ProxyDenied {
                        record_id,
                        protocol,
                        host,
                        port,
                        reason,
                    } => Some((
                        *record_id,
                        protocol.map(str::to_owned),
                        host.as_ref().map(|host| host.expose().clone()),
                        *port,
                        (*reason).to_owned(),
                    )),
                    _ => None,
                },
                Delivery::Lost(_) => None,
            })
            .collect()
    }

    // KNSH-060 emits_proxy_denied_with_reason (FR-NET-09): a refusal of a line's connection is published as
    // `proxy.denied` for its session, with the record, protocol, host, port and reason. A refusal before
    // credentials are known has no session, so it is only logged.
    #[test]
    fn emits_proxy_denied_with_reason() {
        let running = live_with(Arc::new(FakeResolver::new()));
        crate::events::tests::start(&running.hub, 1);
        let subscriber = Subscriber::new();
        subscriber
            .subscribe(&running.hub, EventScope::Session(session(1)), None)
            .unwrap();
        let line = running
            .proxy
            .issue_line(session(1), record(5), &allowlist(&[]), LineAccess::default())
            .unwrap()
            .unwrap();
        let port = line.port();
        assert!(connect_to(port, "github.com:443", Some(&line)).starts_with("HTTP/1.1 403 "));
        assert!(connect_to(port, "example.com:8443", Some(&line)).starts_with("HTTP/1.1 403 "));
        assert!(connect_to(port, "example.com:443", None).starts_with("HTTP/1.1 407 "));
        let _ = running.proxy.revoke_line(record(5));
        let denied = proxy_denied(&subscriber);
        assert_eq!(
            denied,
            [
                (
                    Some(record(5)),
                    Some("http".to_owned()),
                    Some("github.com".to_owned()),
                    Some(443),
                    "approval_required".to_owned()
                ),
                (
                    Some(record(5)),
                    Some("http".to_owned()),
                    Some("example.com".to_owned()),
                    Some(8443),
                    "host_not_allowed".to_owned()
                ),
            ]
        );
    }

    // KNSH-060 record_lists_contacted_and_refused_hosts (FR-NET-09): a line's record gets every host it contacted
    // and every host it was refused, repeats counted, and nothing of another line or of the envelope.
    #[test]
    fn record_lists_contacted_and_refused_hosts() {
        let server = accepting_server();
        let resolver = Arc::new(FakeResolver::new());
        resolver.answer("registry.test", &[server.ip()]);
        let running = live_with(Arc::clone(&resolver));
        // The test server is on loopback: listing its address allowlists it (FR-NET-07).
        let network = allowlist(&["registry.test", "127.0.0.1"]);
        let line = running
            .proxy
            .issue_line(session(1), record(5), &network, LineAccess::default())
            .unwrap()
            .unwrap();
        let other = running
            .proxy
            .issue_line(session(1), record(6), &network, LineAccess::default())
            .unwrap()
            .unwrap();
        let envelope = running.proxy.issue(session(1), &network).unwrap().unwrap();
        let port = line.port();
        let contacted = format!("registry.test:{}", server.port());
        assert!(connect_to(port, &contacted, Some(&line)).starts_with("HTTP/1.1 200 "));
        assert!(connect_to(port, "github.com:443", Some(&line)).starts_with("HTTP/1.1 403 "));
        assert!(connect_to(port, "github.com:443", Some(&line)).starts_with("HTTP/1.1 403 "));
        assert!(connect_to(port, "elsewhere.test:443", Some(&other)).starts_with("HTTP/1.1 403 "));
        assert!(connect_to(port, "envelope.test:443", Some(&envelope)).starts_with("HTTP/1.1 403 "));

        let network = running.proxy.revoke_line(record(5));
        let shown: Vec<(String, u16, Option<String>, u32)> = network
            .iter()
            .map(|entry| {
                (
                    entry.host.expose().clone(),
                    entry.port,
                    entry.result.reason().map(str::to_owned),
                    entry.count,
                )
            })
            .collect();
        assert_eq!(
            shown,
            [
                ("registry.test".to_owned(), server.port(), None, 1),
                ("github.com".to_owned(), 443, Some("approval_required".to_owned()), 2),
            ]
        );
        assert_eq!(network[0].result, NetworkResult::Contacted);
        // Taken once: a second revocation finds nothing.
        assert!(running.proxy.revoke_line(record(5)).is_empty());
        assert_eq!(running.proxy.revoke_line(record(6)).len(), 1);
    }

    // KNSH-060 envelope_connection_attributed_to_session (FR-NET-09): the envelope's own refused connection is
    // published for the session with no record, and lands in no line's record.
    #[test]
    fn envelope_connection_attributed_to_session() {
        let running = live_with(Arc::new(FakeResolver::new()));
        crate::events::tests::start(&running.hub, 1);
        let subscriber = Subscriber::new();
        subscriber
            .subscribe(&running.hub, EventScope::Session(session(1)), None)
            .unwrap();
        let envelope = running.proxy.issue(session(1), &allowlist(&[])).unwrap().unwrap();
        let _line = running
            .proxy
            .issue_line(session(1), record(5), &allowlist(&[]), LineAccess::default())
            .unwrap()
            .unwrap();
        // The envelope never reaches an approval host: it has no classes and is never approved (FR-NET-03).
        assert!(connect_to(envelope.port(), "github.com:443", Some(&envelope)).starts_with("HTTP/1.1 403 "));
        assert!(running.proxy.revoke_line(record(5)).is_empty());
        running.proxy.revoke(session(1));
        assert_eq!(
            proxy_denied(&subscriber),
            [(
                None,
                Some("http".to_owned()),
                Some("github.com".to_owned()),
                Some(443),
                "approval_required".to_owned()
            )]
        );
    }
}
