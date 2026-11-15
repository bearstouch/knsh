//! Sandbox trampoline.
//!
//! `knshd` never applies a sandbox between `fork` and `exec` inside its own multithreaded process. Instead it spawns
//! this small single-threaded program, which sets up the process and then becomes Apple's `sandbox-exec`, which
//! applies the profile and runs the interpreter (decision 1):
//!
//! ```text
//! knsh-exec [--keep-fd <n>]... --profile <absolute path> --interpreter <absolute path> --line <line>
//!   => execve /usr/bin/sandbox-exec -f <profile> <interpreter> -c -- <line>
//! ```
//!
//! In order, before the exec:
//!
//! 1. The arguments are read strictly ([`args`]); anything malformed exits with [`exit::USAGE`].
//! 2. The profile must be a regular file of this user that nobody else can write ([`profile`]), else
//!    [`exit::PROFILE`].
//! 3. The process leads its own process group (`setpgid(0, 0)`).
//! 4. Every descriptor except stdio and those named with `--keep-fd` gets `FD_CLOEXEC` ([`descriptors`]).
//! 5. `SIGPIPE`, which the Rust runtime ignores, is reset to its default action.
//! 6. The process must have exactly one thread.
//! 7. `execve` of `/usr/bin/sandbox-exec` by absolute path, with the environment as received.
//!
//! A failure in 3 to 6 exits with [`exit::SETUP`], and a failed `execve` with [`exit::EXEC`]. Every failure prints
//! one line to stderr (never an argument's value) and exits without running anything: there is no fallback to
//! running the command unsandboxed. If `sandbox-exec` itself cannot apply the profile it exits non-zero before the
//! interpreter starts (65 for an unreadable or invalid profile, 71 if the interpreter cannot be executed); the
//! supervisor treats every such exit as a deny.
//!
//! # Boundaries
//!
//! Standard library only, single-threaded, no workspace or third-party dependencies (NFR-SUP-01). One of only two
//! crates allowed to use `unsafe`: system calls are hand-written `extern` declarations in [`sys`].
//! Every `unsafe` block needs a `// SAFETY:` comment and every `unsafe fn` a `# Safety` doc section.
//! macOS only for now: elsewhere it refuses every invocation (Landlock and seccomp arrive with KNSH-113).
//!
//! # Specification
//!
//! - `specs/02-architecture/process-model.md#knsh-exec`, `specs/02-architecture/enforcement-model.md`
//! - `specs/04-non-functional-requirements/supply-chain.md` (NFR-SUP-01), decision 1
//! - FR-LC-13, FR-LC-14 (the line and its interpreter), KNSH-046

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]

mod args;
mod descriptors;
// Outside macOS only usage errors and `Unsupported` are ever built; the other failures belong to the macOS path.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod exit;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod profile;
#[cfg(target_os = "macos")]
mod sys;

use std::io::Write as _;
use std::process::ExitCode;

use exit::Failure;

/// Entry point. Returns only on failure: on success the process has become `sandbox-exec`.
fn main() -> ExitCode {
    let failure = run(std::env::args_os().skip(1));
    // `writeln!` rather than `eprintln!`, which panics if stderr is closed; the exit code alone still tells the
    // supervisor what happened.
    let _ = writeln!(std::io::stderr(), "knsh-exec: {failure}");
    ExitCode::from(failure.code())
}

/// Everything before the exec (crate documentation). Returns the reason the line was not run.
#[cfg(target_os = "macos")]
fn run(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Failure {
    let invocation = match args::parse(arguments) {
        Ok(invocation) => invocation,
        Err(error) => return Failure::Usage(error),
    };
    if let Err(error) = profile::check(&invocation.profile, sys::effective_uid()) {
        return Failure::Profile(error);
    }
    if let Err(failure) = prepare(&invocation.keep) {
        return failure;
    }
    // Allocated before the thread check, so nothing runs between the check and the exec but the exec itself.
    let argv = args::exec_argv(invocation);
    let env = environment();
    // The process must be single-threaded when it becomes sandbox-exec. Nothing here starts a thread, so this
    // holds by construction; the check makes it observable (the integration tests rely on it) and fails closed if
    // the runtime ever starts one.
    match sys::thread_count() {
        Ok(1) => {}
        Ok(count) => return Failure::Setup(exit::Setup::Threads(count)),
        Err(error) => return Failure::Setup(exit::Setup::Os("thread count", error)),
    }
    Failure::Exec(sys::exec(std::path::Path::new(args::SANDBOX_EXEC), argv, env))
}

/// The environment as received, as `KEY=value` entries for `execve`. Passed on unchanged: the supervisor builds
/// the line's environment, and the trampoline adds nothing of its own.
#[cfg(target_os = "macos")]
fn environment() -> Vec<std::ffi::OsString> {
    std::env::vars_os()
        .map(|(key, value)| {
            let mut entry = key;
            entry.push("=");
            entry.push(value);
            entry
        })
        .collect()
}

/// Steps 3 to 5: process group, descriptors, `SIGPIPE`.
#[cfg(target_os = "macos")]
fn prepare(keep: &[i32]) -> Result<(), Failure> {
    sys::lead_own_process_group().map_err(os_failure("setpgid"))?;
    let open = sys::open_descriptors().map_err(os_failure("descriptor list"))?;
    let plan = descriptors::plan(&open, keep).map_err(|error| match error {
        // A listed descriptor that is not open is malformed input (exit 64); closed stdio is the environment's
        // fault, not the caller's (exit 71).
        descriptors::PlanError::KeptNotOpen(_) => Failure::Descriptors(error),
        descriptors::PlanError::StdioClosed(_) => Failure::Setup(exit::Setup::Descriptors(error)),
    })?;
    for &fd in &plan.inherit {
        sys::set_close_on_exec(fd, false).map_err(os_failure("fcntl"))?;
    }
    for &fd in &plan.close_on_exec {
        sys::set_close_on_exec(fd, true).map_err(os_failure("fcntl"))?;
    }
    sys::default_sigpipe().map_err(os_failure("signal"))
}

/// Maps the error of the system call named `call` to a setup failure.
#[cfg(target_os = "macos")]
fn os_failure(call: &'static str) -> impl Fn(std::io::Error) -> Failure {
    move |error| Failure::Setup(exit::Setup::Os(call, error))
}

/// Not macOS: no sandbox backend exists yet, so nothing ever runs (fail closed).
#[cfg(not(target_os = "macos"))]
fn run(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Failure {
    match args::parse(arguments) {
        Ok(_) => Failure::Unsupported,
        Err(error) => Failure::Usage(error),
    }
}
