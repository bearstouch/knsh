//! Proxy credentials for envelopes (KNSH-057; FR-AGT-03, FR-NET-01, decision 14).
//!
//! Every envelope reaches the network only through `knshd`'s proxy: its sandbox profile allows outbound TCP to the
//! proxy's loopback port and the profile's `network.loopback` ports, nothing else
//! (`specs/03-functional-requirements/sandbox-profiles.md`). So the proxy can tie each connection to one session,
//! the envelope gets credentials of its own, issued when its session opens and revoked when it ends, and carried in
//! its environment as the user and password of an HTTP proxy URL (decision 14):
//!
//! ```text
//! http://knsh-<id>:<token>@127.0.0.1:<port>
//! ```
//!
//! # Who issues them
//!
//! The proxy itself (KNSH-059), behind [`EnvelopeProxy`]: it alone maps credentials to sessions. Until it exists
//! `knshd` wires [`NoProxy`] (the capability probe reports `network_filter: none`): the envelope then gets no proxy
//! settings and no proxy port in its profile, so it reaches nothing but its loopback ports. That fails closed:
//! nothing leaves the machine unfiltered, and nothing pretends a proxy is there.
//!
//! # The environment
//!
//! [`proxy_env`] gives the variables decision 14 names, and [`is_proxy_var`] the inherited ones every envelope
//! loses first, with or without a proxy: a caller's own proxy (and the credentials in its URL) must not reach the
//! envelope, and a `NO_PROXY` or `ALL_PROXY` it set could send a tool around the envelope's proxy.

use std::fmt;
use std::num::NonZeroU16;

use knsh_core::{Redacted, SessionId};

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
// Read by `ProxyCredential::new`, which only tests call until the proxy issues credentials (KNSH-059).
#[cfg_attr(not(test), allow(dead_code))]
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
    // The proxy (KNSH-059) is its first caller outside tests.
    #[cfg_attr(not(test), allow(dead_code))]
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

/// Issues and revokes envelope credentials (module documentation, "Who issues them"). Object safe, so tests can
/// issue fixed credentials.
pub(crate) trait EnvelopeProxy: Send + Sync {
    /// Credentials for the envelope of `session`, or `None` when no proxy runs: the envelope then gets no proxy
    /// settings and its profile no proxy port.
    ///
    /// # Errors
    ///
    /// A proxy runs but could not issue credentials: the envelope must not start.
    fn issue(&self, session: SessionId) -> Result<Option<ProxyCredential>, ProxyUnavailable>;

    /// Revokes every credential issued for `session`. Called once its envelope has ended, whether or not
    /// [`EnvelopeProxy::issue`] succeeded, so it must accept a session it issued nothing for.
    fn revoke(&self, session: SessionId);
}

/// No proxy runs (`network_filter: none`): envelopes get no proxy settings and reach only their loopback ports.
pub(crate) struct NoProxy;

impl EnvelopeProxy for NoProxy {
    fn issue(&self, _session: SessionId) -> Result<Option<ProxyCredential>, ProxyUnavailable> {
        Ok(None)
    }

    fn revoke(&self, _session: SessionId) {}
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

    /// A proxy on `port` that issues `knsh-<n>:<token>` per session, numbered from 1, and records revocations.
    pub(crate) struct FakeProxy {
        pub(crate) port: NonZeroU16,
        /// When set, [`EnvelopeProxy::issue`] fails.
        pub(crate) broken: bool,
        pub(crate) issued: Mutex<Vec<SessionId>>,
        pub(crate) revoked: Mutex<Vec<SessionId>>,
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
            }
        }
    }

    impl EnvelopeProxy for FakeProxy {
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

        fn revoke(&self, session: SessionId) {
            self.revoked.lock().unwrap().push(session);
        }
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
