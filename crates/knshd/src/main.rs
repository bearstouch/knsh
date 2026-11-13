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
//!   catalogue and capability probe, KNSH-014)
//! - `specs/06-api/user-socket.md#records`, FR-REC-02, FR-REC-08, NFR-REL-05 (record store, `records.query` and
//!   `records.output`, KNSH-016)
//! - FR-REC-07, FR-REC-10, NFR-PRIV-03 (record retention and `records.forget`, KNSH-017)
//!
//! On start it prepares the engine directories (KNSH-011) and takes its sockets from launchd ([`endpoints`],
//! KNSH-012). It then serves them ([`server`], KNSH-013): a kqueue accept loop hands each connection to its own
//! thread, which reads frames ([`connection`]) and dispatches JSON-RPC methods through per-endpoint tables
//! ([`dispatch`]), generated from the method catalogue and the capabilities probed once at start ([`probe`],
//! [`hello`], KNSH-014). It opens the record store in the engine data directory and answers `records.query` and
//! `records.output` from it ([`records`], KNSH-016), and `records.forget` on `user.sock`; the store applies record
//! retention on its own thread, at start and hourly (KNSH-017). It exits after ten idle minutes ([`lifetime`]) or when launchd
//! stops it, finishing in-flight requests and committing pending writes first. The supervisor arrives in later
//! stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

// Platform-neutral, but only the macOS server uses them until the Linux backend exists.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod connection;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod dispatch;
#[cfg(target_os = "macos")]
mod endpoints;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod hello;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod lifetime;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod probe;
// The record store is built on macOS only until the Linux SQLite backend exists.
#[cfg(target_os = "macos")]
mod records;
#[cfg(target_os = "macos")]
mod server;

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
        LaunchdSockets, RealFs, SystemClock, SystemPeerCredentials, SystemProbes, SystemProcesses, UnifiedLog,
        effective_uid,
    };
    use knsh_platform::{EnginePaths, Field, Level, SystemLog, Value, ensure_engine_dirs};

    use knsh_store::{DATABASE_FILE, RecordStore, StoreConfig};

    use crate::lifetime::NoSessions;
    use crate::probe::{PROBE_TIMEOUT, Probes, probe};
    use crate::records::Records;
    use crate::server::{Config, Exit, Server, Services};

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
        let records = Records::new(store);
        // Probed once, before serving: every hello of this process reports the same result, and a restarted knshd
        // probes again (KNSH-014).
        let probed = probe(&Probes {
            processes: Arc::new(SystemProcesses::new()),
            system: Arc::new(SystemProbes::new()),
            clock: clock.clone(),
            log: Arc::clone(&log),
            timeout: PROBE_TIMEOUT,
        });
        let services = Services {
            dispatcher: hello::phase1_dispatcher(probed, records.handlers()).map_err(StartError::Dispatch)?,
            credentials: Arc::new(SystemPeerCredentials::new()),
            log: Arc::clone(&log),
            own_uid: uid,
            clock,
            // Until the session registry (KNSH-015) is wired in, only open connections keep knshd alive. Records are
            // committed as they are written; on exit knshd waits for queued store jobs.
            activity: Arc::new(NoSessions),
            pending: Arc::new(records),
        };
        let server = Server::new(listeners, services, Config::DEFAULT).map_err(StartError::Serve)?;
        server.stop_on_termination_signals().map_err(StartError::Serve)?;
        Ok(server)
    };
    let server = prepare().map_err(fail)?;

    log.log(Level::Notice, "knshd started", &[]);
    let exit = server.run().map_err(|error| fail(StartError::Serve(error)))?;
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

/// Everything `knshd` does. Only macOS has a backend so far (Linux later).
#[cfg(not(target_os = "macos"))]
fn start() -> Result<(), StartError> {
    Err(StartError::Unsupported)
}
