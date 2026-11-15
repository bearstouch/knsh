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
//! only. It exits after ten idle minutes ([`lifetime`]) or when launchd stops it, finishing in-flight
//! requests and committing pending writes first.
//! The supervisor arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

// Platform-neutral, but only the macOS server uses them until the Linux backend exists.
// Owned by the session registry, so built where it is.
#[cfg(target_os = "macos")]
mod agents;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod connection;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod dispatch;
#[cfg(target_os = "macos")]
mod endpoints;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod events;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod hello;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod lifetime;
// Reads the session registry, so built where it is.
#[cfg(target_os = "macos")]
mod policy;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod probe;
// Hashes with CommonCrypto, so built on macOS. Only the start-up sweep uses it until the supervisor (KNSH-050)
// writes a profile for each envelope and line.
#[cfg(target_os = "macos")]
#[cfg_attr(not(test), allow(dead_code))]
mod profiles;
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

    use knsh_store::{DATABASE_FILE, RecordStore, StoreConfig};

    use crate::events::EventHub;
    use crate::policy::PolicyCheck;
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
        // A store that cannot be opened (newer schema, foreign or unsafe file) is reported and left untouched; knshd
        // still serves, so a human session is never blocked by it, and the record methods answer -32603.
        // Retention uses the defaults (30 days or 2 GB); per-profile periods arrive with profile loading.
        let store = match RecordStore::open(
            &RealFs::new(),
            &paths.data_dir().join(DATABASE_FILE),
            uid,
            clock.clone(),
            StoreConfig::default(),
        ) {
            Ok(store) => Some(store),
            Err(error) => {
                log.log(
                    Level::Error,
                    "record store unavailable",
                    &[Field::new("reason", Value::Static(error.kind()))],
                );
                None
            }
        };
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
        let sessions = Sessions::new(store, Arc::clone(&events), clock.clone(), random, processes);
        // Dry runs read profiles and binaries through the real filesystem. `TMPDIR` is set by launchd for the agent;
        // without it `${TMPDIR}` is the system's `/tmp`.
        let tmpdir = std::env::var_os("TMPDIR").map_or_else(|| "/tmp".into(), std::path::PathBuf::from);
        let policy = PolicyCheck::new(
            Arc::clone(&sessions),
            Arc::new(RealFs::new()),
            paths.policies_dir(),
            paths.home().to_path_buf(),
            tmpdir,
        );
        let mut handlers = records.handlers();
        handlers.extend(events.handlers());
        handlers.extend(sessions.handlers());
        handlers.extend(policy.handlers());
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
