//! The method catalogue: the single declaration of every client-callable method (KNSH-014).
//!
//! Each [`MethodSpec`] says on which [`Endpoint`]s the method exists, whether this build implements it
//! ([`Availability`]), which backend it needs ([`Backend`]) and whether it is deprecated ([`Deprecation`]).
//! `knshd` generates both its per-endpoint dispatch tables and the `methods` list of `hello` from
//! [`Catalogue::available`], so the two can never disagree (`specs/06-api/handshake.md`: "A method or capability is
//! available only if `hello` lists it").
//!
//! The entries follow the method tables of `specs/06-api/agent-socket.md`, `user-socket.md` and
//! `control-service.md`. Engine notifications (`decision.requested`, `command.output`, ...) are sent, never called,
//! so they are not here. The control service's `session.*` verbs are not named by the spec yet and are added with it.

use std::fmt;

use crate::capability::{Backend, Capabilities};
use crate::method::MethodName;

/// An endpoint a method can be called on (`specs/02-architecture/endpoints.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Endpoint {
    /// `user.sock`: user processes outside envelopes.
    User,
    /// `agent.sock`: processes inside envelopes, scoped to their own session.
    Agent,
    /// The XPC control service: the trusted authority only.
    Control,
}

impl Endpoint {
    /// Every endpoint.
    pub const ALL: [Self; 3] = [Self::User, Self::Agent, Self::Control];

    /// A fixed name, for logs and tests.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Agent => "agent",
            Self::Control => "control",
        }
    }
}

/// The set of endpoints a method exists on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoints {
    user: bool,
    agent: bool,
    control: bool,
}

impl Endpoints {
    /// `user.sock` only.
    pub const USER: Self = Self::new(true, false, false);
    /// `agent.sock` only.
    pub const AGENT: Self = Self::new(false, true, false);
    /// The control service only.
    pub const CONTROL: Self = Self::new(false, false, true);
    /// `user.sock` and `agent.sock`.
    pub const SOCKETS: Self = Self::new(true, true, false);
    /// `user.sock` and the control service.
    pub const USER_CONTROL: Self = Self::new(true, false, true);
    /// Every endpoint.
    pub const ALL: Self = Self::new(true, true, true);

    /// A set from one flag per endpoint.
    #[must_use]
    pub const fn new(user: bool, agent: bool, control: bool) -> Self {
        Self { user, agent, control }
    }

    /// Whether `endpoint` is in the set.
    #[must_use]
    pub const fn contains(self, endpoint: Endpoint) -> bool {
        match endpoint {
            Endpoint::User => self.user,
            Endpoint::Agent => self.agent,
            Endpoint::Control => self.control,
        }
    }

    const fn is_empty(self) -> bool {
        !(self.user || self.agent || self.control)
    }
}

/// Whether this build implements a method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Availability {
    /// Implemented: served and listed wherever its endpoint and backend allow.
    Available,
    /// Specified but not implemented in this build: never listed or served, answered `-32601`.
    Planned,
}

/// An engine release, `major.minor`. Patch releases do not count for deprecation windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Release {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
}

impl Release {
    /// A release from its parts.
    #[must_use]
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// Reads the `major.minor` prefix of a `major.minor.patch` version such as `CARGO_PKG_VERSION`.
    #[must_use]
    pub fn parse(version: &str) -> Option<Self> {
        let mut parts = version.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        Some(Self { major, minor })
    }

    /// The release of this engine build. The workspace version is always `major.minor.patch` (a unit test checks).
    #[must_use]
    pub fn current() -> Self {
        // The fallback is unreachable (see the test `current_release_parses`); 0.0 is the most conservative
        // answer, since it keeps every deprecated method inside its window.
        Self::parse(env!("CARGO_PKG_VERSION")).unwrap_or(Self::new(0, 0))
    }
}

impl fmt::Display for Release {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Minor releases a deprecated method keeps working after the release that deprecated it
/// (`specs/06-api/handshake.md#rules`).
pub const DEPRECATION_WINDOW: u32 = 2;

/// A method marked deprecated in `hello`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Deprecation {
    /// The release that first marked the method deprecated.
    pub since: Release,
}

impl Deprecation {
    /// The first release that may drop the method: [`DEPRECATION_WINDOW`] minor releases after
    /// [`Deprecation::since`] keep it working, so with `since = 0.3`, releases 0.3, 0.4 and 0.5 serve it and 0.6 may
    /// remove it. A new major release may remove it too.
    #[must_use]
    pub const fn earliest_removal(self) -> Release {
        Release::new(self.since.major, self.since.minor + DEPRECATION_WINDOW + 1)
    }

    /// Whether `release` must still serve the method.
    #[must_use]
    pub fn must_serve_in(self, release: Release) -> bool {
        release >= self.since && release < self.earliest_removal()
    }
}

/// One method of the catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MethodSpec {
    /// The method name. Valid per [`MethodName`]; [`Catalogue::validate`] checks it.
    pub name: &'static str,
    /// Where the method can be called.
    pub endpoints: Endpoints,
    /// Whether this build implements it.
    pub availability: Availability,
    /// The backend it needs, if any. Without it the method is not listed and is answered `-32005`.
    pub requires: Option<Backend>,
    /// Set once the method is deprecated.
    pub deprecated: Option<Deprecation>,
}

impl MethodSpec {
    /// A method specified but not yet implemented, with no backend requirement and not deprecated.
    const fn planned(name: &'static str, endpoints: Endpoints) -> Self {
        Self {
            name,
            endpoints,
            availability: Availability::Planned,
            requires: None,
            deprecated: None,
        }
    }

    /// The same method, implemented.
    const fn available(self) -> Self {
        Self {
            availability: Availability::Available,
            ..self
        }
    }

    /// The same method, needing `backend`.
    const fn requires(self, backend: Backend) -> Self {
        Self {
            requires: Some(backend),
            ..self
        }
    }
}

/// What the catalogue says about a method name on one endpoint, given the probed capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// Listed and served.
    Available(&'a MethodSpec),
    /// Exists, but not on this endpoint (`-32003`).
    NotOnEndpoint,
    /// On this endpoint and implemented, but its backend is `none` here (`-32005`).
    Unavailable(Backend),
    /// Specified but not implemented in this build (`-32601`).
    Planned,
    /// Not a method (`-32601`).
    Unknown,
}

/// Why a catalogue is inconsistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogueError {
    /// The name does not follow the method-name grammar.
    InvalidName(&'static str),
    /// The name appears twice.
    Duplicate(&'static str),
    /// The method is on no endpoint.
    NoEndpoint(&'static str),
    /// `hello` is missing, not on every endpoint, not available, or depends on a backend: no client could start.
    Hello,
    /// A deprecated method is not served while its deprecation window is still open, or is deprecated in a release
    /// after this one.
    DeprecationWindow(&'static str),
}

impl fmt::Display for CatalogueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(name) => write!(f, "invalid method name {name:?}"),
            Self::Duplicate(name) => write!(f, "method {name:?} declared twice"),
            Self::NoEndpoint(name) => write!(f, "method {name:?} is on no endpoint"),
            Self::Hello => f.write_str("hello must be available on every endpoint with no backend requirement"),
            Self::DeprecationWindow(name) => write!(f, "deprecated method {name:?} must still be served"),
        }
    }
}

impl std::error::Error for CatalogueError {}

/// A list of methods, with the queries `knshd` builds its tables and `hello` from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Catalogue {
    methods: &'static [MethodSpec],
}

/// Every method in the specification. Phase 1 implements `hello`, `records.query` and `records.output` (KNSH-016),
/// `records.forget` (KNSH-017), and `events.subscribe` and `events.unsubscribe` (KNSH-018); the rest arrive with their
/// stories.
const ENGINE_METHODS: &[MethodSpec] = &[
    // Handshake (specs/06-api/handshake.md).
    MethodSpec::planned("hello", Endpoints::ALL).available(),
    // agent.sock (specs/06-api/agent-socket.md). Running a line needs the sandbox: without it agent sessions refuse
    // to start (specs/05-models/capabilities.md).
    MethodSpec::planned("exec.run", Endpoints::AGENT).requires(Backend::Sandbox),
    MethodSpec::planned("exec.start", Endpoints::AGENT).requires(Backend::Sandbox),
    MethodSpec::planned("exec.wait", Endpoints::AGENT),
    MethodSpec::planned("exec.kill", Endpoints::AGENT),
    MethodSpec::planned("session.info", Endpoints::AGENT),
    // Shared by agent.sock (own session) and user.sock (all sessions); the read and checkpoint methods are on the
    // control service too.
    MethodSpec::planned("policy.check", Endpoints::SOCKETS),
    MethodSpec::planned("records.query", Endpoints::ALL).available(),
    MethodSpec::planned("records.output", Endpoints::ALL).available(),
    // Events (KNSH-018): agent.sock sees its own session, user.sock and the control service every session.
    MethodSpec::planned("events.subscribe", Endpoints::ALL).available(),
    MethodSpec::planned("events.unsubscribe", Endpoints::ALL).available(),
    MethodSpec::planned("checkpoint.list", Endpoints::ALL),
    MethodSpec::planned("checkpoint.diff", Endpoints::ALL),
    MethodSpec::planned("checkpoint.undo", Endpoints::ALL),
    MethodSpec::planned("checkpoint.redo", Endpoints::ALL),
    // user.sock (specs/06-api/user-socket.md).
    MethodSpec::planned("checkpoint.restore", Endpoints::USER_CONTROL),
    MethodSpec::planned("session.start_agent", Endpoints::USER),
    MethodSpec::planned("session.list", Endpoints::USER),
    MethodSpec::planned("session.end", Endpoints::USER),
    MethodSpec::planned("approval.list", Endpoints::USER),
    MethodSpec::planned("approval.approve", Endpoints::USER),
    MethodSpec::planned("approval.deny", Endpoints::USER),
    MethodSpec::planned("policy.edit", Endpoints::USER),
    MethodSpec::planned("profile.use", Endpoints::USER),
    MethodSpec::planned("policy.grant", Endpoints::USER_CONTROL),
    // Deleting records is for the user only: an agent can never erase its own trail (KNSH-017).
    MethodSpec::planned("records.forget", Endpoints::USER).available(),
    // Control service (specs/06-api/control-service.md).
    MethodSpec::planned("authority.register", Endpoints::CONTROL),
    MethodSpec::planned("decision.respond", Endpoints::CONTROL),
    MethodSpec::planned("policy.set", Endpoints::CONTROL),
    MethodSpec::planned("policy.get", Endpoints::CONTROL),
    MethodSpec::planned("policy.grants", Endpoints::CONTROL),
    MethodSpec::planned("policy.revoke", Endpoints::CONTROL),
    MethodSpec::planned("secrets.provide", Endpoints::CONTROL).requires(Backend::Secrets),
    MethodSpec::planned("secrets.revoke", Endpoints::CONTROL).requires(Backend::Secrets),
    MethodSpec::planned("recording.set", Endpoints::CONTROL),
];

impl Catalogue {
    /// The engine's catalogue.
    pub const ENGINE: Self = Self::new(ENGINE_METHODS);

    /// A catalogue over `methods`. Only the engine's and tests' catalogues exist; check them with
    /// [`Catalogue::validate`].
    #[must_use]
    pub const fn new(methods: &'static [MethodSpec]) -> Self {
        Self { methods }
    }

    /// Every entry, in declaration order.
    #[must_use]
    pub const fn methods(&self) -> &'static [MethodSpec] {
        self.methods
    }

    /// The entry named `name`, on any endpoint.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&'static MethodSpec> {
        self.methods.iter().find(|spec| spec.name == name)
    }

    /// What a call to `name` on `endpoint` meets, given `capabilities`. The checks run in a fixed order: a method
    /// on another endpoint is `NotOnEndpoint` even if it is planned, so an agent learns only that it may not call
    /// it, never more.
    #[must_use]
    pub fn lookup(&self, endpoint: Endpoint, name: &str, capabilities: &Capabilities) -> Lookup<'static> {
        let Some(spec) = self.find(name) else {
            return Lookup::Unknown;
        };
        if !spec.endpoints.contains(endpoint) {
            return Lookup::NotOnEndpoint;
        }
        match (spec.availability, spec.requires) {
            (Availability::Planned, _) => Lookup::Planned,
            (Availability::Available, Some(backend)) if !capabilities.has(backend) => Lookup::Unavailable(backend),
            (Availability::Available, _) => Lookup::Available(spec),
        }
    }

    /// The methods callable on `endpoint` on this machine, in declaration order: on the endpoint, implemented, and
    /// with their backend present. This is the one query both the dispatch tables and `hello`'s `methods` list are
    /// built from.
    pub fn available<'c>(
        &self,
        endpoint: Endpoint,
        capabilities: &'c Capabilities,
    ) -> impl Iterator<Item = &'static MethodSpec> + 'c {
        let catalogue = *self;
        self.methods.iter().filter(move |spec| {
            matches!(
                catalogue.lookup(endpoint, spec.name, capabilities),
                Lookup::Available(_)
            )
        })
    }

    /// Checks the catalogue against `release`: valid unique names, every method on some endpoint, `hello`
    /// everywhere, and every deprecated method still served within its window.
    ///
    /// # Errors
    ///
    /// The first [`CatalogueError`] found.
    pub fn validate(&self, release: Release) -> Result<(), CatalogueError> {
        for (index, spec) in self.methods.iter().enumerate() {
            if MethodName::new(spec.name).is_err() {
                return Err(CatalogueError::InvalidName(spec.name));
            }
            if self.methods[..index].iter().any(|earlier| earlier.name == spec.name) {
                return Err(CatalogueError::Duplicate(spec.name));
            }
            if spec.endpoints.is_empty() {
                return Err(CatalogueError::NoEndpoint(spec.name));
            }
            if let Some(deprecation) = spec.deprecated {
                let deprecated_later = deprecation.since > release;
                let dropped_early = deprecation.must_serve_in(release) && spec.availability != Availability::Available;
                if deprecated_later || dropped_early {
                    return Err(CatalogueError::DeprecationWindow(spec.name));
                }
            }
        }
        match self.find(crate::method::HELLO) {
            Some(hello)
                if hello.endpoints == Endpoints::ALL
                    && hello.availability == Availability::Available
                    && hello.requires.is_none() =>
            {
                Ok(())
            }
            Some(_) | None => Err(CatalogueError::Hello),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::capability::{FileEvents, NetworkFilter, Sandbox, Secrets};

    fn capabilities(sandbox: Sandbox) -> Capabilities {
        Capabilities {
            sandbox,
            network_filter: NetworkFilter::None,
            file_events: FileEvents::None,
            secrets: Secrets::None,
            checkpoints: BTreeMap::new(),
        }
    }

    fn names(catalogue: Catalogue, endpoint: Endpoint, caps: &Capabilities) -> Vec<&'static str> {
        catalogue.available(endpoint, caps).map(|spec| spec.name).collect()
    }

    #[test]
    fn engine_catalogue_is_valid() {
        Catalogue::ENGINE.validate(Release::current()).unwrap();
    }

    #[test]
    fn current_release_parses() {
        assert!(Release::parse(env!("CARGO_PKG_VERSION")).is_some());
        assert_eq!(Release::parse("1.22.3"), Some(Release::new(1, 22)));
        assert_eq!(Release::parse("1"), None);
        assert_eq!(Release::parse("a.b.c"), None);
    }

    // Every method named in the endpoint method tables of specs/06-api is declared, on the right endpoints.
    #[test]
    fn engine_catalogue_declares_spec_methods_on_their_endpoints() {
        let on = |name: &str| Catalogue::ENGINE.find(name).unwrap().endpoints;
        assert_eq!(on("hello"), Endpoints::ALL);
        assert_eq!(on("exec.run"), Endpoints::AGENT);
        assert_eq!(on("session.info"), Endpoints::AGENT);
        assert_eq!(on("session.start_agent"), Endpoints::USER);
        assert_eq!(on("approval.approve"), Endpoints::USER);
        assert_eq!(on("records.query"), Endpoints::ALL);
        assert_eq!(on("checkpoint.restore"), Endpoints::USER_CONTROL);
        assert_eq!(on("authority.register"), Endpoints::CONTROL);
        assert!(
            !on("exec.run").contains(Endpoint::User),
            "agents' run is never on user.sock"
        );
        assert!(
            !on("checkpoint.restore").contains(Endpoint::Agent),
            "no restore or force on agent.sock"
        );
    }

    /// The method names in the first column of the `| Method | Purpose |` table of a spec page, without wildcards
    /// (`checkpoint.*`).
    fn spec_methods(page: &str) -> Vec<&str> {
        page.lines()
            .skip_while(|line| !line.starts_with("| Method |"))
            .skip(2)
            .take_while(|line| line.starts_with('|'))
            .filter_map(|line| line.split('|').nth(1))
            .flat_map(|cell| cell.split('`').skip(1).step_by(2))
            // Socket names (`user.sock`) fit the method grammar but appear only in prose rows. A method's verb is the
            // part after the last dot, so a verb of `sock` marks a socket name.
            .filter(|name| MethodName::new(name).is_ok() && name.rsplit('.').next() != Some("sock"))
            .collect()
    }

    // Every method the endpoint pages of specs/06-api name is declared on that endpoint.
    #[test]
    fn catalogue_matches_spec_method_tables() {
        let pages = [
            (Endpoint::Agent, include_str!("../../../specs/06-api/agent-socket.md")),
            (Endpoint::User, include_str!("../../../specs/06-api/user-socket.md")),
            (
                Endpoint::Control,
                include_str!("../../../specs/06-api/control-service.md"),
            ),
        ];
        for (endpoint, page) in pages {
            let names = spec_methods(page);
            assert!(names.len() >= 5, "{}: table not found", endpoint.name());
            for name in names {
                let spec = Catalogue::ENGINE
                    .find(name)
                    .unwrap_or_else(|| panic!("{name} is not in the catalogue"));
                assert!(spec.endpoints.contains(endpoint), "{name} on {}", endpoint.name());
            }
        }
    }

    // Phase 1 implements the handshake, the record reads (KNSH-016), on user.sock only `records.forget` (KNSH-017),
    // and the event subscriptions (KNSH-018): no method is claimed before it exists.
    #[test]
    fn phase1_lists_hello_record_and_event_methods_only() {
        let caps = capabilities(Sandbox::Seatbelt);
        for endpoint in Endpoint::ALL {
            let expected: &[&str] = match endpoint {
                Endpoint::User => &[
                    "hello",
                    "records.query",
                    "records.output",
                    "events.subscribe",
                    "events.unsubscribe",
                    "records.forget",
                ],
                Endpoint::Agent | Endpoint::Control => &[
                    "hello",
                    "records.query",
                    "records.output",
                    "events.subscribe",
                    "events.unsubscribe",
                ],
            };
            assert_eq!(
                names(Catalogue::ENGINE, endpoint, &caps),
                expected,
                "{}",
                endpoint.name()
            );
        }
        assert_eq!(
            Catalogue::ENGINE.lookup(Endpoint::Agent, "records.forget", &caps),
            Lookup::NotOnEndpoint,
            "an agent can never erase records"
        );
    }

    const TEST_METHODS: &[MethodSpec] = &[
        MethodSpec::planned("hello", Endpoints::ALL).available(),
        MethodSpec::planned("exec.run", Endpoints::AGENT)
            .available()
            .requires(Backend::Sandbox),
        MethodSpec::planned("records.query", Endpoints::SOCKETS).available(),
        MethodSpec::planned("session.start_agent", Endpoints::USER).available(),
        MethodSpec::planned("records.output", Endpoints::SOCKETS),
    ];

    #[test]
    fn lookup_orders_endpoint_then_availability_then_backend() {
        let catalogue = Catalogue::new(TEST_METHODS);
        catalogue.validate(Release::current()).unwrap();
        let none = capabilities(Sandbox::None);
        let seatbelt = capabilities(Sandbox::Seatbelt);
        assert_eq!(
            catalogue.lookup(Endpoint::User, "exec.run", &seatbelt),
            Lookup::NotOnEndpoint
        );
        assert_eq!(
            catalogue.lookup(Endpoint::Agent, "exec.run", &none),
            Lookup::Unavailable(Backend::Sandbox)
        );
        assert!(matches!(
            catalogue.lookup(Endpoint::Agent, "exec.run", &seatbelt),
            Lookup::Available(spec) if spec.name == "exec.run"
        ));
        assert_eq!(
            catalogue.lookup(Endpoint::User, "records.output", &seatbelt),
            Lookup::Planned
        );
        assert_eq!(catalogue.lookup(Endpoint::User, "no.such", &seatbelt), Lookup::Unknown);
        assert_eq!(
            catalogue.lookup(Endpoint::Agent, "session.start_agent", &seatbelt),
            Lookup::NotOnEndpoint
        );
    }

    // A method whose backend is missing is not listed (honest capabilities, NFR-SEC-10).
    #[test]
    fn available_drops_methods_without_their_backend() {
        let catalogue = Catalogue::new(TEST_METHODS);
        assert_eq!(
            names(catalogue, Endpoint::Agent, &capabilities(Sandbox::Seatbelt)),
            ["hello", "exec.run", "records.query"]
        );
        assert_eq!(
            names(catalogue, Endpoint::Agent, &capabilities(Sandbox::None)),
            ["hello", "records.query"]
        );
        assert_eq!(
            names(catalogue, Endpoint::User, &capabilities(Sandbox::None)),
            ["hello", "records.query", "session.start_agent"]
        );
    }

    #[test]
    fn deprecation_window_is_two_minor_releases() {
        let deprecation = Deprecation {
            since: Release::new(0, 3),
        };
        assert_eq!(deprecation.earliest_removal(), Release::new(0, 6));
        assert!(!deprecation.must_serve_in(Release::new(0, 2)));
        for minor in 3..=5 {
            assert!(deprecation.must_serve_in(Release::new(0, minor)), "0.{minor}");
        }
        assert!(!deprecation.must_serve_in(Release::new(0, 6)));
        assert!(!deprecation.must_serve_in(Release::new(1, 0)));
    }

    // KNSH-014: a deprecated method keeps working for two minor releases; the catalogue refuses to drop it sooner.
    #[test]
    fn validate_refuses_dropping_a_deprecated_method_inside_its_window() {
        const DROPPED: &[MethodSpec] = &[
            MethodSpec::planned("hello", Endpoints::ALL).available(),
            MethodSpec {
                deprecated: Some(Deprecation {
                    since: Release::new(0, 3),
                }),
                ..MethodSpec::planned("records.old", Endpoints::USER)
            },
        ];
        let catalogue = Catalogue::new(DROPPED);
        assert_eq!(
            catalogue.validate(Release::new(0, 5)),
            Err(CatalogueError::DeprecationWindow("records.old"))
        );
        assert_eq!(catalogue.validate(Release::new(0, 6)), Ok(()));
        // Deprecated in a release that does not exist yet.
        assert_eq!(
            catalogue.validate(Release::new(0, 2)),
            Err(CatalogueError::DeprecationWindow("records.old"))
        );
    }

    #[test]
    fn validate_refuses_inconsistent_catalogues() {
        const BAD_NAME: &[MethodSpec] = &[
            MethodSpec::planned("hello", Endpoints::ALL).available(),
            MethodSpec::planned("Exec.run", Endpoints::AGENT),
        ];
        const DUPLICATE: &[MethodSpec] = &[
            MethodSpec::planned("hello", Endpoints::ALL).available(),
            MethodSpec::planned("exec.run", Endpoints::AGENT),
            MethodSpec::planned("exec.run", Endpoints::USER),
        ];
        const NOWHERE: &[MethodSpec] = &[
            MethodSpec::planned("hello", Endpoints::ALL).available(),
            MethodSpec::planned("exec.run", Endpoints::new(false, false, false)),
        ];
        const NO_HELLO: &[MethodSpec] = &[MethodSpec::planned("exec.run", Endpoints::AGENT)];
        const PARTIAL_HELLO: &[MethodSpec] = &[MethodSpec::planned("hello", Endpoints::USER).available()];
        const PLANNED_HELLO: &[MethodSpec] = &[MethodSpec::planned("hello", Endpoints::ALL)];
        let release = Release::current();
        let check = |methods| Catalogue::new(methods).validate(release);
        assert_eq!(check(BAD_NAME), Err(CatalogueError::InvalidName("Exec.run")));
        assert_eq!(check(DUPLICATE), Err(CatalogueError::Duplicate("exec.run")));
        assert_eq!(check(NOWHERE), Err(CatalogueError::NoEndpoint("exec.run")));
        assert_eq!(check(NO_HELLO), Err(CatalogueError::Hello));
        assert_eq!(check(PARTIAL_HELLO), Err(CatalogueError::Hello));
        assert_eq!(check(PLANNED_HELLO), Err(CatalogueError::Hello));
    }
}
