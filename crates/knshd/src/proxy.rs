//! Proxy credentials for envelopes and lines (KNSH-057, KNSH-059; FR-AGT-03, FR-NET-01, decision 14).
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
//! Until host rules, name resolution and address checks exist (KNSH-060), the proxy's gate is
//! [`knsh_proxy::RefuseAll`]: every destination is refused, and reported. Envelopes and lines therefore reach no
//! more than they did without a proxy, while credentials, the `407` challenge and both protocols are exercised end
//! to end. `hello` keeps reporting `network_filter: none` until the rules are in force.
//!
//! # The environment
//!
//! [`proxy_env`] gives the variables decision 14 names, and [`is_proxy_var`] the inherited ones every envelope and
//! line loses first, with or without a proxy: a caller's own proxy (and the credentials in its URL) must not reach
//! the command, a `NO_PROXY` or `ALL_PROXY` it set could send a tool around the proxy, and a line must never run with
//! its envelope's credentials, which would attribute its connections to the session instead of its record
//! ([`command_env`]).

use std::fmt;
use std::num::NonZeroU16;
use std::sync::Arc;

use knsh_core::{RecordId, Redacted, SessionId};
use knsh_platform::{Field, Level, SystemLog, Value};
use knsh_proxy::{Denial, Owner, Proxy, ProxyReport};

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
    /// Credentials for the envelope of `session`, or `None` when no proxy runs: the envelope then gets no proxy
    /// settings and its profile no proxy port.
    ///
    /// # Errors
    ///
    /// A proxy runs but could not issue credentials: the envelope must not start.
    fn issue(&self, session: SessionId) -> Result<Option<ProxyCredential>, ProxyUnavailable>;

    /// Credentials for the line `record` of `session`, or `None` when no proxy runs.
    ///
    /// # Errors
    ///
    /// A proxy runs but could not issue credentials: the line must not start.
    fn issue_line(&self, session: SessionId, record: RecordId) -> Result<Option<ProxyCredential>, ProxyUnavailable>;

    /// Revokes the credentials of the line `record` and closes its connections. Called once the line has ended,
    /// whether or not [`ProxyIssuer::issue_line`] succeeded.
    fn revoke_line(&self, record: RecordId);

    /// Revokes every credential issued for `session` (its envelope's and its lines'). Called once its envelope has
    /// ended, whether or not [`ProxyIssuer::issue`] succeeded, so it must accept a session it issued nothing for.
    fn revoke(&self, session: SessionId);
}

/// No proxy runs (`network_filter: none`): envelopes and lines get no proxy settings and reach only their loopback
/// ports.
pub(crate) struct NoProxy;

impl ProxyIssuer for NoProxy {
    fn issue(&self, _session: SessionId) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
        Ok(None)
    }

    fn issue_line(&self, _session: SessionId, _record: RecordId) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
        Ok(None)
    }

    fn revoke_line(&self, _record: RecordId) {}

    fn revoke(&self, _session: SessionId) {}
}

/// The running proxy (`knsh-proxy`) as the [`ProxyIssuer`].
pub(crate) struct LiveProxy {
    proxy: Proxy,
}

impl LiveProxy {
    /// Wraps a started proxy.
    pub(crate) fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }

    /// Issues credentials for `owner` in the URL form of decision 14.
    fn issue_for(&self, owner: Owner) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
        let issued = self.proxy.issue(owner).map_err(|_| ProxyUnavailable)?;
        // The proxy issues decimal ids and letter-and-digit tokens, so this holds; if it ever did not, the command
        // must not start without its credentials (fail closed).
        ProxyCredential::new(self.proxy.port(), issued.id(), issued.token().clone())
            .map(Some)
            .ok_or(ProxyUnavailable)
    }
}

impl ProxyIssuer for LiveProxy {
    fn issue(&self, session: SessionId) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
        self.issue_for(Owner { session, line: None })
    }

    fn issue_line(&self, session: SessionId, record: RecordId) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
        self.issue_for(Owner {
            session,
            line: Some(record),
        })
    }

    fn revoke_line(&self, record: RecordId) {
        self.proxy.revoke_line(record);
    }

    fn revoke(&self, session: SessionId) {
        self.proxy.revoke_session(session);
    }
}

/// Reports the proxy's refusals to the system log: session, record, protocol, port and reason, never a credential
/// or a host name (NFR-PRIV-02). `proxy.denied` events and the record's `network` field arrive with KNSH-060.
pub(crate) struct LoggedDenials {
    log: Arc<dyn SystemLog>,
}

impl LoggedDenials {
    /// Reports to `log`.
    pub(crate) fn new(log: Arc<dyn SystemLog>) -> Self {
        Self { log }
    }
}

impl ProxyReport for LoggedDenials {
    fn denied(&self, denial: &Denial) {
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

    use super::*;

    /// A proxy on `port` that issues `knsh-<n>:<token>` per session, numbered from 1, and `knsh-line<n>:<token>`
    /// per line, and records revocations.
    pub(crate) struct FakeProxy {
        pub(crate) port: NonZeroU16,
        /// When set, issuing fails.
        pub(crate) broken: bool,
        pub(crate) issued: Mutex<Vec<SessionId>>,
        pub(crate) revoked: Mutex<Vec<SessionId>>,
        pub(crate) lines: Mutex<Vec<RecordId>>,
        pub(crate) revoked_lines: Mutex<Vec<RecordId>>,
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
                revoked_lines: Mutex::new(Vec::new()),
            }
        }
    }

    impl ProxyIssuer for FakeProxy {
        fn issue(&self, session: SessionId) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
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
        ) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
            if self.broken {
                return Err(ProxyUnavailable);
            }
            let mut lines = self.lines.lock().unwrap();
            lines.push(record);
            let id = format!("line{}", lines.len());
            Ok(ProxyCredential::new(
                self.port,
                &id,
                Redacted::new(Self::TOKEN.to_owned()),
            ))
        }

        fn revoke_line(&self, record: RecordId) {
            self.revoked_lines.lock().unwrap().push(record);
        }

        fn revoke(&self, session: SessionId) {
            self.revoked.lock().unwrap().push(session);
        }
    }

    /// The real proxy with the gate `knshd` runs, reporting to a recording log.
    fn live() -> (LiveProxy, Arc<knsh_platform::testing::RecordingLog>) {
        use knsh_platform::macos::{SystemClock, SystemRandom};
        use knsh_proxy::{Config, Parts, RefuseAll};

        let log = Arc::new(knsh_platform::testing::RecordingLog::new());
        let proxy = Proxy::start(
            Config::DEFAULT,
            Parts {
                gate: Arc::new(RefuseAll),
                report: Arc::new(LoggedDenials::new(Arc::clone(&log) as Arc<dyn SystemLog>)),
                random: Arc::new(SystemRandom::new()),
                clock: Arc::new(SystemClock::new()),
            },
        )
        .unwrap();
        (LiveProxy::new(proxy), log)
    }

    /// Sends a CONNECT for `example.com:443` with the user and password of `credential`'s URL (or none), and
    /// returns the status line.
    fn connect_status(port: NonZeroU16, credential: Option<&ProxyCredential>) -> String {
        use std::io::{BufRead, BufReader, Write};

        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port.get())).unwrap();
        let mut request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n".to_owned();
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
    // authenticate until revoked, and every destination is refused while no host rules exist (KNSH-060).
    #[test]
    fn live_proxy_issues_and_revokes_envelope_and_line_credentials() {
        let (proxy, log) = live();
        let envelope = proxy.issue(session(1)).unwrap().unwrap();
        let line = proxy.issue_line(session(1), record(5)).unwrap().unwrap();
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
        assert!(entries.contains("no_host_rules"), "{entries}");
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
                .issue(SessionId::from_ulid(knsh_core::Ulid::from_u128(1)))
                .unwrap()
                .is_none()
        );
    }
}
