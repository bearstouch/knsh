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
//!
//! Skeleton created by KNSH-001. On start it prepares the engine directories (KNSH-011), takes its sockets from
//! launchd and serves them ([`endpoints`], KNSH-012). The dispatcher, idle exit and supervisor arrive in later
//! stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
mod endpoints;

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
    /// Every accept loop ended, so nothing is served any more.
    Stopped,
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
            Self::Stopped => f.write_str("every endpoint stopped accepting connections"),
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
            Self::Stopped => "stopped",
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

/// Everything `knshd` does: prepare its directories, take its sockets from launchd, then serve until killed.
#[cfg(target_os = "macos")]
fn start() -> Result<(), StartError> {
    use std::path::Path;
    use std::sync::Arc;

    use knsh_platform::macos::{LaunchdSockets, RealFs, SystemPeerCredentials, UnifiedLog, effective_uid};
    use knsh_platform::{EnginePaths, Field, Level, SystemLog, Value, ensure_engine_dirs};

    let log: Arc<dyn SystemLog> = Arc::new(UnifiedLog::new(c"daemon"));
    let uid = effective_uid();

    let prepare = || {
        // `HOME` rather than the password database: the launch agent sets it, and tests point it at an isolated home.
        let home = std::env::var_os("HOME").ok_or(StartError::NoHome)?;
        let paths = EnginePaths::for_home(Path::new(&home)).map_err(StartError::BadHome)?;
        ensure_engine_dirs(&RealFs::new(), &paths, uid).map_err(StartError::EngineDirs)?;
        // Never a fallback bind: without launchd's sockets, knshd does not run (KNSH-012).
        endpoints::activate(&LaunchdSockets::new()).map_err(StartError::NoLaunchdSockets)
    };
    let listeners = match prepare() {
        Ok(listeners) => listeners,
        Err(error) => {
            log.log(
                Level::Error,
                "knshd failed to start",
                &[Field::new("reason", Value::Static(error.kind()))],
            );
            return Err(error);
        }
    };

    log.log(Level::Notice, "knshd started", &[]);
    let context = Arc::new(endpoints::Context {
        credentials: Arc::new(SystemPeerCredentials::new()),
        log,
        own_uid: uid,
    });
    endpoints::serve(listeners, &context);
    Err(StartError::Stopped)
}

/// Everything `knshd` does. Only macOS has a backend so far (Linux later).
#[cfg(not(target_os = "macos"))]
fn start() -> Result<(), StartError> {
    Err(StartError::Unsupported)
}
