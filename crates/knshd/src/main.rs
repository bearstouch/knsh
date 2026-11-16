//! Per-user daemon and supervisor.
//!
//! Endpoints, the supervisor, the event bus and the wiring between services.
//!
//! # Boundaries
//!
//! Thin: logic lives in the library crates. The supervisor is the only process that starts agent commands, always
//! through `knsh-exec`.
//!
//! # Specification
//!
//! - `specs/02-architecture/process-model.md`
//! - `specs/02-architecture/endpoints.md`
//! - `specs/02-architecture/system-overview.md`
//! - `specs/09-reference/file-locations.md`, NFR-PRIV-04, NFR-SEC-08 (engine directories, KNSH-011)
//! - NFR-REL-03, `specs/04-non-functional-requirements/security.md` "squats its endpoints" (launchd agent, KNSH-012)
//! - `specs/06-api/README.md`, `specs/06-api/wire-format.md`, NFR-SEC-07 (connection server and dispatcher, KNSH-013)
//! - `specs/06-api/handshake.md`, `specs/05-models/capabilities.md`, NFR-SEC-10, NFR-REL-08 (`hello`, method
//!   catalogue and capability probe, KNSH-014; the sandbox probe through `knsh-exec`, FR-AGT-06, KNSH-046)
//! - `specs/06-api/user-socket.md#records`, FR-REC-02, FR-REC-08, NFR-REL-05 (record store, `records.query` and
//!   `records.output`, KNSH-016)
//! - FR-REC-07, FR-REC-10, NFR-PRIV-03 (record retention and `records.forget`, KNSH-017)
//! - `specs/05-models/event.md`, FR-EVT-01 to FR-EVT-04, FR-EVT-07, `specs/06-api/user-socket.md#events` (event bus,
//!   `events.subscribe` and `events.unsubscribe`, KNSH-018)
//! - `specs/06-api/user-socket.md#human-sessions`, FR-SES-21, FR-SES-24, FR-SES-25, FR-REC-09, NFR-PRIV-05 (human
//!   sessions, telemetry and `session.info`, KNSH-021)
//! - `specs/06-api/agent-socket.md#policycheck`, FR-POL-70 (`policy.check` dry runs, KNSH-043)
//! - FR-SBX-07 (compiled profile files named by hash, collected when unused, KNSH-045)
//! - FR-SBX-06, FR-SBX-08, decision 9 (sandbox violation reader, KNSH-047)
//! - FR-AGT-23, FR-SES-02, NFR-SEC-02, `specs/06-api/agent-socket.md` (`agent.sock`: session tokens, the envelope
//!   registry and the audit-token fallback, KNSH-048)
//! - FR-LC-01, FR-LC-14, FR-LC-16, FR-OUT-04, `specs/06-api/agent-socket.md#execrun`, `specs/06-api/wire-format.md`
//!   (receiving `exec.run` from `knsh -c` with its stdio passed as descriptors, KNSH-049)
//!
//! On start it prepares the engine directories (KNSH-011) and takes its sockets from launchd ([`endpoints`],
//! KNSH-012). It then serves them ([`server`], KNSH-013): a kqueue accept loop hands each connection to its own
//! thread, which reads frames ([`connection`]) and dispatches JSON-RPC methods through per-endpoint tables
//! ([`dispatch`]), generated from the method catalogue and the capabilities probed once at start ([`probe`],
//! [`hello`], KNSH-014). It opens the record store in the engine data directory and answers `records.query` and
//! `records.output` from it ([`records`], KNSH-016), and `records.forget` on `user.sock`; the store applies record
//! retention on its own thread, at start and hourly (KNSH-017). The event bus ([`events`], KNSH-018) numbers and
//! buffers each session's events and serves `events.subscribe` and `events.unsubscribe`; a subscribed connection
//! gets a second thread that writes its events as notifications. The session registry ([`sessions`], KNSH-021) holds
//! recorded human sessions, each bound to the `knsh` connection that started it and ended when it closes; their
//! telemetry becomes records and events, and a recording session keeps `knshd` alive. `policy.check` ([`policy`],
//! KNSH-043) answers what a profile would decide for a line, reading profiles and binaries but writing, publishing and
//! running nothing. Compiled sandbox profiles are written to private files named by their hash ([`profiles`],
//! KNSH-045), and the ones an earlier run left behind are removed at start. The sandbox violation reader
//! ([`violations`], KNSH-047) streams the system's sandbox denials, publishes them as `sandbox.violation` and
//! attaches them to the records their tags name; `hello` reports whether it is live. `agent.sock` is served too
//! ([`agents`], KNSH-048): each connection is bound at `hello` to one agent session, by its session token or, without
//! one, by the caller's audit token and the envelope it descends from, and every later call acts for that session
//! only. Descriptors passed with a request (`SCM_RIGHTS`) reach that request's call, and only `exec.run` takes them
//! ([`exec`], KNSH-049): it checks the forwarded line and hands it, without the shims in `PATH`, to the supervisor,
//! which later stories provide. It exits after ten idle minutes ([`lifetime`]) or when launchd stops it, finishing
//! in-flight requests and committing pending writes first. A session can be paused or taken over by a human
//! ([`holds`], KNSH-054): its new lines are held with `-32007`, and a pause stops its envelope's and running lines'
//! process groups.
//! The supervisor arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

// Platform-neutral, but only the macOS server uses them until the Linux backend exists.
// Owned by the session registry, so built where it is.
#[cfg(target_os = "macos")]
mod agents;
// Reading a line's output (KNSH-053): platform-neutral, used by the macOS spawner.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod capture;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod connection;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod dispatch;
#[cfg(target_os = "macos")]
mod endpoints;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod events;
// Reads the session binding, so built where the session registry is. Served with the supervisor (KNSH-051).
#[cfg(target_os = "macos")]
mod exec;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod hello;
// Pause, resume and human control (KNSH-054): owned by the session registry.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod holds;
// Lines started with exec.start (KNSH-053), built with `exec`.
#[cfg(target_os = "macos")]
mod jobs;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod lifetime;
// Reads the session registry, so built where it is.
#[cfg(target_os = "macos")]
mod policy;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod probe;
// Hashes with CommonCrypto, so built on macOS: the start-up sweep and each supervised line's profile (KNSH-051).
#[cfg(target_os = "macos")]
mod profiles;
// The lifecycle orchestrator (KNSH-050), served with `exec.run` (KNSH-051).
// Envelope and line proxy credentials (KNSH-057, KNSH-059), used by `start_agent` and the spawner.
#[cfg(target_os = "macos")]
mod proxy;
#[cfg(target_os = "macos")]
mod supervisor;
// The spawner behind the orchestrator (KNSH-051): lines through `knsh-exec`, process groups, timeouts.
#[cfg(target_os = "macos")]
mod spawn;
#[cfg(target_os = "macos")]
mod start_agent;
// The record store is built on macOS only until the Linux SQLite backend exists.
#[cfg(target_os = "macos")]
mod records;
#[cfg(target_os = "macos")]
mod server;
// Writes records, so built where the record store is.
#[cfg(target_os = "macos")]
mod sessions;
// The reader is platform-neutral; its record sink is built where the record store is.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod violations;

use std::fmt;
use std::process::ExitCode;

use knsh_platform::PlatformError;

/// Why `knshd` could not start. Messages never name a path (`PlatformError` messages carry no input), so they are
/// safe to print and log.
#[derive(Debug)]
enum StartError {
    /// `HOME` is not set.
    NoHome,
    /// `HOME` is not a usable home directory (relative, `/`, or with `.` or `..`).
    BadHome(PlatformError),
    /// The engine directories cannot be made private and excluded (NFR-PRIV-04).
    EngineDirs(PlatformError),
    /// launchd provided no socket: `knshd` was not started through its launch agent.
    NoLaunchdSockets(PlatformError),
    /// The method catalogue and the implemented handlers disagree (a build defect).
    Dispatch(dispatch::BuildError),
    /// The connection server failed to start, failed while serving, or could not commit pending writes on exit.
    #[cfg(target_os = "macos")]
    Serve(server::ServeError),
    /// This platform has no backend yet.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Unsupported,
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHome => f.write_str("HOME is not set"),
            Self::BadHome(error) => write!(f, "unusable HOME: {error}"),
            Self::EngineDirs(error) => write!(f, "cannot prepare engine directories: {error}"),
            Self::NoLaunchdSockets(error) => write!(
                f,
                "no sockets from launchd ({error}); knshd only runs from its launch agent, see 'knsh daemon install'"
            ),
            Self::Dispatch(error) => write!(f, "cannot build dispatch tables: {error}"),
            #[cfg(target_os = "macos")]
            Self::Serve(error) => write!(f, "{error}"),
            Self::Unsupported => f.write_str("this platform is not supported yet"),
        }
    }
}

impl StartError {
    /// A fixed name for the failure, for the system log (which accepts only static text).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn kind(&self) -> &'static str {
        match self {
            Self::NoHome => "no_home",
            Self::BadHome(_) => "bad_home",
            Self::EngineDirs(_) => "engine_dirs",
            Self::NoLaunchdSockets(_) => "no_launchd_sockets",
            Self::Dispatch(_) => "dispatch",
            #[cfg(target_os = "macos")]
            Self::Serve(error) => error.kind(),
            Self::Unsupported => "unsupported",
        }
    }
}

/// Entry point. Exits with status 1 and the reason on stderr if `knshd` cannot start: without private engine
/// directories (NFR-PRIV-04) or without launchd's sockets (KNSH-012) it must not run at all.
fn main() -> ExitCode {
    match start() {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            // Under launchd stderr is discarded; the reason is also in the system log (see `start`).
            eprintln!("knshd: {reason}");
            ExitCode::FAILURE
        }
    }
}

/// Everything `knshd` does: prepare its directories, take its sockets from launchd, then serve until idle or
/// stopped. Returns `Ok` on an orderly exit, which launchd does not count as a crash: the next connection starts
/// `knshd` again.
#[cfg(target_os = "macos")]
fn start() -> Result<(), StartError> {
    use std::path::Path;
    use std::sync::Arc;

    use knsh_platform::macos::{
        LaunchdSockets, RealFs, SystemClock, SystemPeerCredentials, SystemProcessTree, SystemRandom, UnifiedLog,
        effective_uid,
    };
    use knsh_platform::{EnginePaths, Field, Level, SystemLog, Value, ensure_engine_dirs};

    use crate::events::EventHub;
    use crate::policy::{PolicyCheck, ProfileLoader};
    use crate::records::Records;
    use crate::server::{Config, Exit, Server, Services};
    use crate::sessions::Sessions;
    use crate::violations::{Reader, ReaderStatus};

    let log: Arc<dyn SystemLog> = Arc::new(UnifiedLog::new(c"daemon"));
    let uid = effective_uid();
    let fail = |error: StartError| {
        log.log(
            Level::Error,
            "knshd failed",
            &[Field::new("reason", Value::Static(error.kind()))],
        );
        error
    };

    let prepare = || {
        // `HOME` rather than the password database: the launch agent sets it, and tests point it at an isolated home.
        let home = std::env::var_os("HOME").ok_or(StartError::NoHome)?;
        let paths = EnginePaths::for_home(Path::new(&home)).map_err(StartError::BadHome)?;
        ensure_engine_dirs(&RealFs::new(), &paths, uid).map_err(StartError::EngineDirs)?;
        sweep_profiles(&paths, uid, log.as_ref());
        // Never a fallback bind: without launchd's sockets, knshd does not run (KNSH-012).
        let listeners = endpoints::activate(&LaunchdSockets::new()).map_err(StartError::NoLaunchdSockets)?;
        let clock = Arc::new(SystemClock::new());
        let store = open_store(&paths, uid, &clock, log.as_ref());
        let records = Records::new(store.clone());
        // The event bus with the specified limits (10,000 events per session).
        let random = Arc::new(SystemRandom::new());
        let events = EventHub::new(knsh_core::EventBus::default(), clock.clone(), random.clone());
        // The live sessions: recorded human sessions (KNSH-021); agent sessions arrive with `knsh agent` (KNSH-056).
        // Sandbox denials the system reports, attributed by tag to sessions and records (KNSH-047). Best effort:
        // a reader that cannot start is reported as `sandbox_violations: none` and never blocks anything.
        let reader = start_violation_reader(&paths, clock.clone(), random.clone(), &log, store.clone(), &events);
        // `agent.sock` callers without a token are matched to their envelope through the process table (KNSH-048).
        let processes = Arc::new(SystemProcessTree::new());
        let sessions = Sessions::new(
            store.clone(),
            Arc::clone(&events),
            clock.clone(),
            random.clone(),
            processes,
        );
        // Dry runs read profiles and binaries through the real filesystem. `TMPDIR` is set by launchd for the agent;
        // without it `${TMPDIR}` is the system's `/tmp`.
        let tmpdir = std::env::var_os("TMPDIR").map_or_else(|| "/tmp".into(), std::path::PathBuf::from);
        let profiles = ProfileLoader::new(
            Arc::new(RealFs::new()),
            paths.policies_dir(),
            paths.home().to_path_buf(),
            tmpdir,
        );
        let policy = PolicyCheck::new(Arc::clone(&sessions), profiles.clone());
        let mut handlers = records.handlers();
        handlers.extend(events.handlers());
        handlers.extend(sessions.handlers());
        handlers.extend(policy.handlers());
        // `exec.run` (KNSH-051), listed only when the sandbox probe passes; without `knsh-exec` nothing can run.
        let supervision = Supervision {
            paths: &paths,
            uid,
            log: &log,
            sessions: &sessions,
            profiles,
            events: &events,
            store,
            clock: clock.clone(),
            random,
        };
        handlers.extend(supervision.handlers());
        // Probed once, before serving: every hello of this process reports the same result, and a restarted knshd
        // probes again (KNSH-014).
        let probed = probe_this_machine(&paths, clock.clone(), Arc::clone(&log));
        let violation_status = reader.as_ref().map_or_else(ReaderStatus::stopped, Reader::status);
        let services = Services {
            dispatcher: hello::dispatcher_with_violations(probed, handlers, violation_status, Arc::clone(&sessions))
                .map_err(StartError::Dispatch)?,
            credentials: Arc::new(SystemPeerCredentials::new()),
            log: Arc::clone(&log),
            own_uid: uid,
            clock,
            // A recording session keeps knshd alive, as does any open connection. Records are committed as they are
            // written; on exit knshd waits for queued store jobs.
            activity: sessions,
            pending: Arc::new(records),
        };
        let server = Server::new(listeners, services, Config::DEFAULT).map_err(StartError::Serve)?;
        server.stop_on_termination_signals().map_err(StartError::Serve)?;
        Ok((server, reader))
    };
    let (server, mut reader) = prepare().map_err(fail)?;

    log.log(Level::Notice, "knshd started", &[]);
    let exit = server.run().map_err(|error| fail(StartError::Serve(error)));
    // The `log stream` child must not outlive knshd; pending violations are released to the store first.
    if let Some(reader) = reader.as_mut() {
        reader.stop();
    }
    let exit = exit?;
    let reason = match exit {
        Exit::Idle => "idle",
        Exit::Stopped => "stopped",
    };
    log.log(
        Level::Notice,
        "knshd exiting",
        &[Field::new("reason", Value::Static(reason))],
    );
    Ok(())
}

/// Runs the capability probe on this machine (KNSH-014). The sandbox check runs the `knsh-exec` installed next to
/// this binary, the same one agent lines will use, and keeps its files in the private run directory (KNSH-046).
#[cfg(target_os = "macos")]
fn probe_this_machine(
    paths: &knsh_platform::EnginePaths,
    clock: std::sync::Arc<knsh_platform::macos::SystemClock>,
    log: std::sync::Arc<dyn knsh_platform::SystemLog>,
) -> probe::Probed {
    use std::sync::Arc;

    use knsh_platform::macos::{RealFs, SystemProbes, SystemProcesses, SystemRandom};

    use crate::probe::{PROBE_TIMEOUT, Probes, SandboxProbe};

    probe::probe(&Probes {
        processes: Arc::new(SystemProcesses::new()),
        system: Arc::new(SystemProbes::new()),
        clock,
        log,
        timeout: PROBE_TIMEOUT,
        sandbox: SandboxProbe {
            trampoline: std::env::current_exe()
                .ok()
                .and_then(|exe| SandboxProbe::trampoline_beside(&exe)),
            dir: paths.run_dir(),
            fs: Arc::new(RealFs::new()),
            random: Arc::new(SystemRandom::new()),
        },
    })
}

/// Starts the sandbox violation reader (KNSH-047): `log stream` as this user, its canary file in the private run
/// directory, violations published to `events` and attached to records in `store`. `None`, logged, if it cannot
/// start; `hello` then reports `sandbox_violations: none`.
#[cfg(target_os = "macos")]
fn start_violation_reader(
    paths: &knsh_platform::EnginePaths,
    clock: std::sync::Arc<knsh_platform::macos::SystemClock>,
    random: std::sync::Arc<knsh_platform::macos::SystemRandom>,
    log: &std::sync::Arc<dyn knsh_platform::SystemLog>,
    store: Option<knsh_store::RecordStore>,
    events: &std::sync::Arc<events::EventHub>,
) -> Option<violations::Reader> {
    use std::sync::Arc;

    use knsh_platform::macos::UnifiedLogDenials;

    let unavailable = || log.log(knsh_platform::Level::Error, "sandbox violation reader unavailable", &[]);
    let Ok(source) = UnifiedLogDenials::new(&paths.run_dir()) else {
        unavailable();
        return None;
    };
    let effects = violations::Effects {
        source: Arc::new(source),
        clock,
        random,
        log: Arc::clone(log),
    };
    let sink = violations::RecordViolations::new(store, Arc::clone(events), Arc::clone(log));
    let reader = violations::Reader::start(effects, sink, violations::Config::DEFAULT).ok();
    if reader.is_none() {
        unavailable();
    }
    reader
}

/// The record store. One that cannot be opened (newer schema, foreign or unsafe file) is reported and left
/// untouched; knshd still serves, so a human session is never blocked by it, and the record methods answer -32603.
/// Retention uses the defaults (30 days or 2 GB); per-profile periods arrive with profile loading.
#[cfg(target_os = "macos")]
fn open_store(
    paths: &knsh_platform::EnginePaths,
    uid: u32,
    clock: &std::sync::Arc<knsh_platform::macos::SystemClock>,
    log: &dyn knsh_platform::SystemLog,
) -> Option<knsh_store::RecordStore> {
    use knsh_platform::{Field, Level, Value};
    use knsh_store::{DATABASE_FILE, RecordStore, StoreConfig};

    let opened = RecordStore::open(
        &knsh_platform::macos::RealFs::new(),
        &paths.data_dir().join(DATABASE_FILE),
        uid,
        clock.clone(),
        StoreConfig::default(),
    );
    match opened {
        Ok(store) => Some(store),
        Err(error) => {
            log.log(
                Level::Error,
                "record store unavailable",
                &[Field::new("reason", Value::Static(error.kind()))],
            );
            None
        }
    }
}

/// What the lifecycle orchestrator and its spawner are built from (KNSH-050, KNSH-051).
#[cfg(target_os = "macos")]
struct Supervision<'a> {
    paths: &'a knsh_platform::EnginePaths,
    uid: u32,
    log: &'a std::sync::Arc<dyn knsh_platform::SystemLog>,
    sessions: &'a std::sync::Arc<sessions::Sessions>,
    profiles: policy::ProfileLoader,
    events: &'a std::sync::Arc<events::EventHub>,
    store: Option<knsh_store::RecordStore>,
    clock: std::sync::Arc<knsh_platform::macos::SystemClock>,
    random: std::sync::Arc<knsh_platform::macos::SystemRandom>,
}

/// Starts the network proxy (KNSH-059) on a loopback port with the host rules, the system resolver and address
/// checks as its gate (KNSH-060), reporting refusals to the system log and as `proxy.denied` on `events`. One that
/// cannot start is logged, and envelopes and lines then get no proxy settings and no proxy port
/// ([`proxy::NoProxy`]): they reach only their loopback ports (fail closed).
#[cfg(target_os = "macos")]
fn start_proxy(
    clock: std::sync::Arc<knsh_platform::macos::SystemClock>,
    random: std::sync::Arc<knsh_platform::macos::SystemRandom>,
    log: &std::sync::Arc<dyn knsh_platform::SystemLog>,
    events: &std::sync::Arc<events::EventHub>,
) -> std::sync::Arc<dyn proxy::ProxyIssuer> {
    use std::sync::Arc;

    use knsh_platform::macos::SystemResolver;
    use knsh_platform::{Field, Level, Value};
    use knsh_proxy::{Config, HostRules, Parts, Proxy};

    let rules = Arc::new(HostRules::new(Arc::new(SystemResolver::new())));
    let report = proxy::NetworkReport::new(Arc::clone(log), Arc::clone(events));
    let started = Proxy::start(
        Config::DEFAULT,
        Parts {
            gate: Arc::clone(&rules) as Arc<dyn knsh_proxy::ConnectionGate>,
            report: Arc::clone(&report) as Arc<dyn knsh_proxy::ProxyReport>,
            random,
            clock,
        },
    );
    match started {
        Ok(running) => Arc::new(proxy::LiveProxy::new(running, rules, report)),
        Err(error) => {
            log.log(
                Level::Error,
                "network proxy unavailable",
                &[Field::new("reason", Value::Static(error.kind()))],
            );
            Arc::new(proxy::NoProxy)
        }
    }
}

#[cfg(target_os = "macos")]
impl Supervision<'_> {
    /// The `exec.run` handler: the orchestrator over the real spawner, the `knsh-exec` installed next to this binary
    /// (the one the sandbox probe checked). No hooks, authority or local approvals are wired yet (KNSH-062,
    /// KNSH-069, KNSH-066): every line policy asks about waits and is denied at the timeout. When `knsh-exec` or a
    /// canonical home cannot be found it is logged, and every call is `-32005` ([`exec::unserved_handlers`]).
    fn exec_run_handlers(self, proxy: std::sync::Arc<dyn proxy::ProxyIssuer>) -> dispatch::Handlers {
        use std::sync::Arc;

        use knsh_core::{CanonicalPath, NoAuthority, NoHooks};
        use knsh_platform::macos::{RealFs, SystemProcesses, sha256};

        use crate::probe::SandboxProbe;
        use crate::spawn::{Limits, TrampolineSpawner};
        use crate::supervisor::{DenyAtTimeout, Lifecycle, Parts};

        let trampoline = std::env::current_exe()
            .ok()
            .and_then(|exe| SandboxProbe::trampoline_beside(&exe));
        let home = std::fs::canonicalize(self.paths.home())
            .ok()
            .and_then(|home| CanonicalPath::new(home).ok());
        let (Some(trampoline), Some(home)) = (trampoline, home) else {
            self.log.log(
                knsh_platform::Level::Error,
                "supervisor unavailable: exec.run not served",
                &[],
            );
            return exec::unserved_handlers();
        };
        let files = profiles::ProfileFiles::new(Arc::new(RealFs::new()), self.paths.profiles_dir(), self.uid, sha256);
        let spawner = TrampolineSpawner {
            processes: Arc::new(SystemProcesses::new()),
            clock: self.clock.clone(),
            files,
            log: Arc::clone(self.log),
            trampoline,
            home,
            limits: Limits::DEFAULT,
            proxy,
        };
        let lifecycle = Lifecycle::new(Parts {
            sessions: Arc::clone(self.sessions),
            profiles: self.profiles,
            events: Arc::clone(self.events),
            store: self.store,
            clock: self.clock,
            random: self.random,
            hooks: Arc::new(NoHooks),
            authority: Arc::new(NoAuthority),
            approvals: Arc::new(DenyAtTimeout::default()),
            spawner: Arc::new(spawner),
            // Secret redaction arrives with KNSH-091; the hook is already on the capture path.
            redaction: Arc::new(knsh_core::NoOutputRedaction),
        });
        exec::ExecRun::new(lifecycle, self.paths.shim_dir()).handlers()
    }
}

#[cfg(target_os = "macos")]
impl Supervision<'_> {
    /// `session.start_agent` (KNSH-056) and `exec.*` (KNSH-050 to KNSH-053), over the same paths, sessions,
    /// profiles and clock.
    fn handlers(self) -> dispatch::Handlers {
        // One proxy issues every envelope's and line's credentials (KNSH-059).
        let proxy = start_proxy(self.clock.clone(), self.random.clone(), self.log, self.events);
        let mut handlers = self.start_agent_handlers(&proxy);
        handlers.extend(self.exec_run_handlers(proxy));
        handlers
    }

    /// The `session.start_agent` handler (KNSH-056), launching envelopes through the `knsh-exec` beside `knshd`
    /// with the `knsh` beside it as their `SHELL`. Without either binary or a canonical home it is logged, and every
    /// call is `-32005` for the sandbox ([`start_agent::unserved_handlers`]).
    fn start_agent_handlers(&self, proxy: &std::sync::Arc<dyn proxy::ProxyIssuer>) -> dispatch::Handlers {
        use std::sync::Arc;

        use knsh_core::CanonicalPath;
        use knsh_platform::macos::{RealFs, SystemProcesses, sha256};

        use crate::probe::SandboxProbe;
        use crate::start_agent::{AgentStarter, TrampolineLauncher};

        let exe = std::env::current_exe().ok();
        let trampoline = exe.as_deref().and_then(SandboxProbe::trampoline_beside);
        let canonical = |path: &std::path::Path| {
            std::fs::canonicalize(path)
                .ok()
                .and_then(|path| CanonicalPath::new(path).ok())
        };
        let knsh = exe
            .as_deref()
            .and_then(std::path::Path::parent)
            .and_then(|dir| canonical(&dir.join("knsh")));
        let home = canonical(self.paths.home());
        let (Some(trampoline), Some(knsh), Some(home)) = (trampoline, knsh, home) else {
            self.log.log(
                knsh_platform::Level::Error,
                "envelope launcher unavailable: session.start_agent not served",
                &[],
            );
            return start_agent::unserved_handlers();
        };
        let launcher = TrampolineLauncher {
            processes: Arc::new(SystemProcesses::new()),
            files: profiles::ProfileFiles::new(Arc::new(RealFs::new()), self.paths.profiles_dir(), self.uid, sha256),
            trampoline,
            home,
            knsh: knsh.clone(),
        };
        AgentStarter::new(
            Arc::clone(self.sessions),
            self.profiles.clone(),
            Arc::new(launcher),
            Arc::clone(proxy),
            self.clock.clone(),
            self.paths.shim_dir(),
            knsh.into_path_buf(),
        )
        .handlers()
    }
}

/// Removes the compiled profile files an earlier run left behind: no line runs yet, so none is in use (FR-SBX-07). A
/// failed sweep only leaves files behind and never blocks a human session, so it is logged, not fatal.
#[cfg(target_os = "macos")]
fn sweep_profiles(paths: &knsh_platform::EnginePaths, uid: u32, log: &dyn knsh_platform::SystemLog) {
    use std::sync::Arc;

    use knsh_platform::macos::{RealFs, sha256};

    let files = profiles::ProfileFiles::new(Arc::new(RealFs::new()), paths.profiles_dir(), uid, sha256);
    if files.sweep().is_err() {
        log.log(knsh_platform::Level::Error, "stale sandbox profiles not removed", &[]);
    }
}

/// Everything `knshd` does. Only macOS has a backend so far (Linux later).
#[cfg(not(target_os = "macos"))]
fn start() -> Result<(), StartError> {
    Err(StartError::Unsupported)
}
