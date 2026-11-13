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
//!
//! Skeleton created by KNSH-001. So far it only prepares the engine directories on start (KNSH-011); endpoints and
//! the supervisor arrive in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

use std::process::ExitCode;

/// Entry point: prepares the engine directories, then exits. Fails (exit status 1, reason on stderr) if they cannot
/// be made private and excluded, because nothing may be recorded into a directory that is not (NFR-PRIV-04).
fn main() -> ExitCode {
    match start() {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            // The reason never names a path (`PlatformError` messages carry no input), so it is safe to print.
            eprintln!("knshd: {reason}");
            ExitCode::FAILURE
        }
    }
}

/// Everything `knshd` does on start, so far only preparing its directories.
#[cfg(target_os = "macos")]
fn start() -> Result<(), String> {
    use std::path::Path;

    use knsh_platform::macos::{RealFs, effective_uid};
    use knsh_platform::{EnginePaths, ensure_engine_dirs};

    // `HOME` rather than the password database, so tests and launchd can point the daemon at an isolated home.
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let paths = EnginePaths::for_home(Path::new(&home)).map_err(|error| format!("unusable HOME: {error}"))?;
    ensure_engine_dirs(&RealFs::new(), &paths, effective_uid())
        .map_err(|error| format!("cannot prepare engine directories: {error}"))
}

/// Everything `knshd` does on start. Only macOS has a backend so far (Linux later).
#[cfg(not(target_os = "macos"))]
fn start() -> Result<(), String> {
    Err("this platform is not supported yet".to_owned())
}
