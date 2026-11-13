//! Capability probes: real checks that a backend works on this machine, each bounded in time (KNSH-014).
//!
//! A probe never guesses from a version number. The sandbox probe runs `sandbox-exec` with a trivial profile and
//! needs a clean exit; [`SystemProbe`] reads the OS version and starts and stops an `FSEvents` stream. Every probe has
//! a deadline on the injected [`Clock`]: one that hangs is abandoned and reported as failed, so `knshd` reports the
//! backend as `none` (NFR-SEC-10, NFR-REL-08) instead of never answering `hello`.
//!
//! Deciding what a failure means for the capability report is `knshd`'s job; this module only says whether each
//! check passed.

use std::fmt;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use crate::clock::Clock;
use crate::error::PlatformError;
use crate::process::{ExitStatus, ProcessGroupId, Processes, Signal, SpawnRequest};

/// The Seatbelt front end that `knsh-exec` applies profiles with.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The command run under the trivial profile.
pub const TRUE_PROGRAM: &str = "/usr/bin/true";

/// The smallest valid Seatbelt profile. Allowing everything isolates the question "does Seatbelt work at all" from
/// any rule of ours.
pub const TRIVIAL_PROFILE: &str = "(version 1)(allow default)";

/// How often a probe checks whether its work has finished.
const POLL: Duration = Duration::from_millis(5);

/// System facts the capability probe reads directly from the OS. Object safe: hold it as `Arc<dyn SystemProbe>`.
pub trait SystemProbe: Send + Sync {
    /// The OS major version, for example 15 for macOS 15.1.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::SystemInfo`](crate::Operation::SystemInfo) if the version cannot be
    /// read or parsed.
    fn os_major_version(&self) -> Result<u32, PlatformError>;

    /// Creates, starts, stops and releases one file-event stream, to show that file events work here.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::FileEvents`](crate::Operation::FileEvents) if any step fails.
    fn check_file_events(&self) -> Result<(), PlatformError>;
}

/// Why a probe did not pass. Holds no input, so it can be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFailure {
    /// A platform call failed.
    Platform(PlatformError),
    /// The probe ran but its command did not exit cleanly.
    Exited(ExitStatus),
    /// The probe did not finish before its deadline.
    TimedOut,
    /// The probe's worker thread could not be started or ended without an answer (it panicked).
    NoAnswer,
}

impl ProbeFailure {
    /// A fixed name for the system log.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Platform(_) => "platform",
            Self::Exited(_) => "exited",
            Self::TimedOut => "timed_out",
            Self::NoAnswer => "no_answer",
        }
    }
}

impl fmt::Display for ProbeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(f, "probe failed: {error}"),
            Self::Exited(status) => write!(f, "probe command ended with {status:?}"),
            Self::TimedOut => f.write_str("probe timed out"),
            Self::NoAnswer => f.write_str("probe gave no answer"),
        }
    }
}

impl std::error::Error for ProbeFailure {}

/// The request the sandbox probe spawns: `sandbox-exec -p <trivial profile> /usr/bin/true`, with an empty
/// environment and null standard descriptors.
#[must_use]
pub fn sandbox_probe_request() -> SpawnRequest {
    SpawnRequest::new(SANDBOX_EXEC)
        .arg("-p")
        .arg(TRIVIAL_PROFILE)
        .arg(TRUE_PROGRAM)
}

/// Checks that Seatbelt works: runs [`sandbox_probe_request`] and requires exit status 0 within `timeout`.
///
/// On timeout the process group is killed and reaped (for at most another `timeout`), so a hung probe does not
/// outlive the check.
///
/// # Errors
///
/// [`ProbeFailure::Platform`] if the spawn or a wait fails, [`ProbeFailure::Exited`] for any other exit,
/// [`ProbeFailure::TimedOut`] if it did not finish in time.
pub fn check_sandbox(processes: &dyn Processes, clock: &dyn Clock, timeout: Duration) -> Result<(), ProbeFailure> {
    let group = processes
        .spawn(&sandbox_probe_request())
        .map_err(ProbeFailure::Platform)?;
    match wait_until(processes, clock, group, timeout) {
        Ok(Some(ExitStatus::Exited(0))) => Ok(()),
        Ok(Some(status)) => Err(ProbeFailure::Exited(status)),
        Ok(None) => {
            // Still running at the deadline: stop the whole group, then reap it so its id is not left to be reused.
            // Both are best effort: the probe has already failed, and a group that cannot be reaped in time is left
            // to the kernel rather than blocking start-up.
            let _ = processes.signal(group, Signal::Kill);
            let _ = wait_until(processes, clock, group, timeout);
            Err(ProbeFailure::TimedOut)
        }
        Err(error) => {
            // Waiting failed with the child possibly still running: stop it the same way, so a failed probe never
            // leaves a process group behind.
            let _ = processes.signal(group, Signal::Kill);
            let _ = wait_until(processes, clock, group, timeout);
            Err(ProbeFailure::Platform(error))
        }
    }
}

/// Polls `group` until it exits (`Some`) or `timeout` passes on `clock` (`None`).
fn wait_until(
    processes: &dyn Processes,
    clock: &dyn Clock,
    group: ProcessGroupId,
    timeout: Duration,
) -> Result<Option<ExitStatus>, PlatformError> {
    let start = clock.monotonic();
    loop {
        if let Some(status) = processes.try_wait(group)? {
            return Ok(Some(status));
        }
        if clock.monotonic().saturating_duration_since(start) >= timeout {
            return Ok(None);
        }
        clock.sleep(POLL);
    }
}

/// Runs `probe` on its own thread and waits for its answer until `timeout` passes on `clock`.
///
/// A probe that does not answer in time is abandoned: its thread is detached and keeps running until the call it is
/// stuck in returns, but nothing waits for it. That is the only way to bound a foreign call that cannot be
/// interrupted (`FSEventStreamStart`, `sysctl`).
///
/// # Errors
///
/// [`ProbeFailure::TimedOut`] if no answer arrives in time; [`ProbeFailure::NoAnswer`] if the thread cannot be
/// started or ends without answering.
pub fn run_bounded<T, F>(clock: &dyn Clock, timeout: Duration, probe: F) -> Result<T, ProbeFailure>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    // Capacity 1: an abandoned probe that answers late still completes its send and ends, instead of blocking.
    let (sender, receiver) = mpsc::sync_channel(1);
    // The deadline starts before the probe can run: read after the spawn, a probe that is quick to move the clock
    // (or a slow thread start) would push the deadline back.
    let start = clock.monotonic();
    thread::Builder::new()
        .name("knsh-probe".to_owned())
        .spawn(move || {
            // The receiver is gone if the probe was abandoned; the late answer is simply dropped.
            let _ = sender.send(probe());
        })
        .map_err(|_| ProbeFailure::NoAnswer)?;
    loop {
        match receiver.recv_timeout(POLL) {
            Ok(answer) => return Ok(answer),
            Err(RecvTimeoutError::Disconnected) => return Err(ProbeFailure::NoAnswer),
            Err(RecvTimeoutError::Timeout) => {}
        }
        if clock.monotonic().saturating_duration_since(start) >= timeout {
            return Err(ProbeFailure::TimedOut);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use knsh_core::Timestamp;

    use super::*;
    use crate::testing::{FakeClock, Script, ScriptedProcesses};

    const TIMEOUT: Duration = Duration::from_secs(2);

    fn clock() -> Arc<FakeClock> {
        Arc::new(FakeClock::new(Timestamp::UNIX_EPOCH))
    }

    #[test]
    fn sandbox_probe_passes_on_clean_exit() {
        let processes = ScriptedProcesses::new();
        processes.expect(SANDBOX_EXEC, Script::Exits(0));
        assert_eq!(check_sandbox(&processes, &*clock(), TIMEOUT), Ok(()));
        let spawned = processes.spawned();
        assert_eq!(spawned[0].args, ["-p", TRIVIAL_PROFILE, TRUE_PROGRAM]);
        assert!(spawned[0].env.is_empty(), "the engine's environment is never passed on");
    }

    // KNSH-014: any failure is a failed probe (fake process runner).
    #[test]
    fn failed_probe_reports_failure() {
        let processes = ScriptedProcesses::new();
        processes.expect(SANDBOX_EXEC, Script::Exits(65));
        assert_eq!(
            check_sandbox(&processes, &*clock(), TIMEOUT),
            Err(ProbeFailure::Exited(ExitStatus::Exited(65)))
        );
        processes.expect(SANDBOX_EXEC, Script::FailsToSpawn(libc::ENOENT));
        assert!(matches!(
            check_sandbox(&processes, &*clock(), TIMEOUT),
            Err(ProbeFailure::Platform(_))
        ));
    }

    // KNSH-014: a hanging sandbox-exec is killed at the deadline (fake clock: no real waiting).
    #[test]
    fn hanging_sandbox_probe_times_out_and_is_killed() {
        let processes = ScriptedProcesses::new();
        processes.expect(SANDBOX_EXEC, Script::RunsUntilSignalled);
        let clock = clock();
        let start = clock.monotonic();
        assert_eq!(check_sandbox(&processes, &*clock, TIMEOUT), Err(ProbeFailure::TimedOut));
        assert!(clock.monotonic().saturating_duration_since(start) >= TIMEOUT);
        assert_eq!(processes.signals().len(), 1);
        assert_eq!(processes.signals()[0].1, Signal::Kill);
        // Reaped: the group is forgotten, so it can never be signalled again.
        assert_eq!(
            processes.signal(processes.signals()[0].0, Signal::Kill),
            Err(PlatformError::UnknownProcessGroup)
        );
    }

    #[test]
    fn bounded_probe_returns_its_answer() {
        let clock = clock();
        assert_eq!(run_bounded(&*clock, TIMEOUT, || 42), Ok(42));
    }

    // KNSH-014: a probe stuck in a call is abandoned at the deadline. The probe moves the fake clock past the
    // deadline and then blocks until the test releases it.
    #[test]
    fn hanging_bounded_probe_times_out() {
        let clock = clock();
        let (release, blocked) = mpsc::channel::<()>();
        let probe_clock = Arc::clone(&clock);
        let result = run_bounded(&*clock, TIMEOUT, move || {
            probe_clock.advance(TIMEOUT * 2);
            let _ = blocked.recv();
            1
        });
        assert_eq!(result, Err(ProbeFailure::TimedOut));
        drop(release);
    }

    #[test]
    fn panicking_probe_gives_no_answer() {
        let result = run_bounded(&*clock(), TIMEOUT, || -> u32 { panic!("probe bug") });
        assert_eq!(result, Err(ProbeFailure::NoAnswer));
    }
}
