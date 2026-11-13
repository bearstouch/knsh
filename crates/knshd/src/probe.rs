//! The capability probe v1 (KNSH-014, `specs/05-models/capabilities.md`).
//!
//! [`probe`] runs once when `knshd` starts, before it serves anything. Its result is kept for the lifetime of the
//! process and shared by every `hello` and by the dispatch tables; a new `knshd` (launchd starts one on the next
//! connection after an idle exit) probes again. So the report always matches what this process found.
//!
//! v1 probes:
//!
//! | Capability | Check | Phase 1 |
//! | --- | --- | --- |
//! | `sandbox` | `sandbox-exec` runs `/usr/bin/true` under a trivial profile and exits 0 | Reported, unused |
//! | `file_events` | An `FSEvents` stream is created, started and stopped | Reported |
//! | `platform` | The OS major version from `sysctl` | `macos-<major>-<arch>` |
//! | `network_filter`, `secrets` | No backend exists yet | Always `none` |
//! | `checkpoints` | No root is configured yet | Always `{}` |
//!
//! Every check is real, bounded by [`PROBE_TIMEOUT`], and any failure (an error, a bad exit, a timeout) reports the
//! backend as `none` (NFR-SEC-10, NFR-REL-08). Failures are logged with fixed reasons only.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use knsh_platform::probe::{check_sandbox, run_bounded};
use knsh_platform::{Clock, Field, Level, PlatformError, ProbeFailure, Processes, SystemLog, SystemProbe, Value};
use knsh_proto::{Capabilities, FileEvents, NetworkFilter, Platform, Sandbox, Secrets};

/// How long each check may take. A working check takes milliseconds; the bound only matters when something hangs.
/// The checks run one after another, and a hung `sandbox-exec` gets one more bound to be reaped after it is killed,
/// so the worst case delays start-up by four times this.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The effects the probe uses.
pub(crate) struct Probes {
    /// Runs `sandbox-exec`.
    pub(crate) processes: Arc<dyn Processes>,
    /// OS version and file events.
    pub(crate) system: Arc<dyn SystemProbe>,
    /// Deadlines.
    pub(crate) clock: Arc<dyn Clock>,
    /// Where failures are reported.
    pub(crate) log: Arc<dyn SystemLog>,
    /// The bound on each check.
    pub(crate) timeout: Duration,
}

/// What the probe found, fixed for the lifetime of this `knshd`.
#[derive(Debug, Clone)]
pub(crate) struct Probed {
    /// The `platform` string.
    pub(crate) platform: Platform,
    /// The backends.
    pub(crate) capabilities: Arc<Capabilities>,
}

/// Runs every v1 check and builds the report.
pub(crate) fn probe(probes: &Probes) -> Probed {
    let sandbox = match check_sandbox(probes.processes.as_ref(), probes.clock.as_ref(), probes.timeout) {
        Ok(()) => Sandbox::Seatbelt,
        Err(failure) => {
            log_failure(probes, "sandbox", failure);
            Sandbox::None
        }
    };

    let file_events = match bounded_check(probes, "file_events", |system| system.check_file_events()) {
        Some(()) => FileEvents::FsEvents,
        None => FileEvents::None,
    };
    let major = bounded_check(probes, "platform", |system| system.os_major_version());

    let capabilities = Capabilities {
        sandbox,
        // No feature is claimed before it exists: the proxy arrives in phase 3, secrets and checkpoints later.
        network_filter: NetworkFilter::None,
        file_events,
        secrets: Secrets::None,
        checkpoints: BTreeMap::new(),
    };
    probes.log.log(
        Level::Notice,
        "capabilities probed",
        &[
            Field::new("sandbox", Value::Static(capabilities.sandbox.as_str())),
            Field::new("file_events", Value::Static(capabilities.file_events.as_str())),
            Field::new("os_major", Value::U64(major.map_or(0, u64::from))),
        ],
    );
    Probed {
        platform: Platform::this_build(major),
        capabilities: Arc::new(capabilities),
    }
}

/// Runs one [`SystemProbe`] check on its own thread, bounded by [`Probes::timeout`]. Any failure, whether the call
/// returned an error or never answered, is logged under `backend` and gives `None`, so the caller reports `none`.
fn bounded_check<T: Send + 'static>(
    probes: &Probes,
    backend: &'static str,
    check: impl FnOnce(&dyn SystemProbe) -> Result<T, PlatformError> + Send + 'static,
) -> Option<T> {
    let system = Arc::clone(&probes.system);
    let answer = run_bounded(probes.clock.as_ref(), probes.timeout, move || check(system.as_ref()));
    match answer.and_then(|result| result.map_err(ProbeFailure::Platform)) {
        Ok(value) => Some(value),
        Err(failure) => {
            log_failure(probes, backend, failure);
            None
        }
    }
}

/// Logs a failed check with fixed reasons only: the backend, the failure kind and, for a platform call, its errno.
fn log_failure(probes: &Probes, backend: &'static str, failure: ProbeFailure) {
    let mut fields = vec![
        Field::new("backend", Value::Static(backend)),
        Field::new("reason", Value::Static(failure.kind())),
    ];
    if let ProbeFailure::Platform(error) = failure
        && let Some(errno) = error.errno()
    {
        fields.push(Field::new("errno", Value::Errno(errno)));
    }
    probes.log.log(Level::Error, "capability probe failed", &fields);
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::mpsc;

    use knsh_core::Timestamp;
    use knsh_platform::probe::SANDBOX_EXEC;
    use knsh_platform::testing::{FakeClock, FakeSystemProbe, RecordingLog, Script, ScriptedProcesses};

    use super::*;

    /// A test machine: scripted processes, a fake system probe, a fake clock and a recording log.
    pub(crate) struct Machine {
        pub(crate) processes: Arc<ScriptedProcesses>,
        pub(crate) system: Arc<dyn SystemProbe>,
        pub(crate) clock: Arc<FakeClock>,
        pub(crate) log: Arc<RecordingLog>,
    }

    impl Machine {
        pub(crate) fn new(sandbox: Script, system: Arc<dyn SystemProbe>) -> Self {
            let processes = Arc::new(ScriptedProcesses::new());
            processes.expect(SANDBOX_EXEC, sandbox);
            Self {
                processes,
                system,
                clock: Arc::new(FakeClock::new(Timestamp::UNIX_EPOCH)),
                log: Arc::new(RecordingLog::new()),
            }
        }

        /// Every check passes, on OS major version 15.
        pub(crate) fn working() -> Self {
            Self::new(Script::Exits(0), Arc::new(FakeSystemProbe::working(15)))
        }

        /// Every check fails.
        pub(crate) fn failing() -> Self {
            Self::new(Script::Exits(1), Arc::new(FakeSystemProbe::failing()))
        }

        pub(crate) fn probes(&self) -> Probes {
            Probes {
                processes: self.processes.clone(),
                system: Arc::clone(&self.system),
                clock: self.clock.clone(),
                log: self.log.clone(),
                timeout: PROBE_TIMEOUT,
            }
        }
    }

    #[test]
    fn working_machine_reports_its_backends() {
        let machine = Machine::working();
        let probed = probe(&machine.probes());
        assert_eq!(probed.capabilities.sandbox, Sandbox::Seatbelt);
        assert_eq!(probed.capabilities.file_events, FileEvents::FsEvents);
        assert_eq!(probed.platform.major(), Some(15));
        assert_eq!(machine.processes.remaining_scripts(), 0, "sandbox-exec really ran");
    }

    // KNSH-014: phase 1 claims no feature before it exists, whatever the machine offers.
    #[test]
    fn phase1_reports_unbuilt_backends_as_none() {
        let probed = probe(&Machine::working().probes());
        assert_eq!(probed.capabilities.network_filter, NetworkFilter::None);
        assert_eq!(probed.capabilities.secrets, Secrets::None);
        assert!(probed.capabilities.checkpoints.is_empty());
    }

    // KNSH-014, NFR-SEC-10: any failure reports `none` (fake process runner), and is logged without content.
    #[test]
    fn failed_probe_reports_none() {
        let machine = Machine::failing();
        let probed = probe(&machine.probes());
        assert_eq!(probed.capabilities.sandbox, Sandbox::None);
        assert_eq!(probed.capabilities.file_events, FileEvents::None);
        assert_eq!(probed.platform.major(), None);
        assert_eq!(
            probed.platform,
            Platform::this_build(None),
            "an unreadable version is `unknown`, never guessed"
        );
        let failures = machine
            .log
            .entries()
            .into_iter()
            .filter(|entry| entry.message == "capability probe failed")
            .count();
        assert_eq!(failures, 3);

        // A sandbox-exec that cannot even be started is a failure too.
        let machine = Machine::new(Script::FailsToSpawn(2), Arc::new(FakeSystemProbe::working(15)));
        assert_eq!(probe(&machine.probes()).capabilities.sandbox, Sandbox::None);
    }

    /// A system probe stuck in its calls: it moves the fake clock past every deadline, then blocks until released.
    struct HangingSystem {
        clock: Arc<FakeClock>,
        blocked: std::sync::Mutex<mpsc::Receiver<()>>,
    }

    impl HangingSystem {
        fn hang(&self) {
            self.clock.advance(PROBE_TIMEOUT * 2);
            let _ = self.blocked.lock().unwrap().recv();
        }
    }

    impl SystemProbe for HangingSystem {
        fn os_major_version(&self) -> Result<u32, PlatformError> {
            self.hang();
            Ok(15)
        }

        fn check_file_events(&self) -> Result<(), PlatformError> {
            self.hang();
            Ok(())
        }
    }

    // KNSH-014: probing is bounded; a hanging probe reports `none` (fake clock: no real waiting for sandbox-exec).
    #[test]
    fn hanging_probe_times_out_as_none() {
        let clock = Arc::new(FakeClock::new(Timestamp::UNIX_EPOCH));
        let (release, blocked) = mpsc::channel();
        let system = Arc::new(HangingSystem {
            clock: Arc::clone(&clock),
            blocked: std::sync::Mutex::new(blocked),
        });
        let mut machine = Machine::new(Script::RunsUntilSignalled, system);
        machine.clock = clock;
        let probed = probe(&machine.probes());
        assert_eq!(probed.capabilities.sandbox, Sandbox::None);
        assert_eq!(probed.capabilities.file_events, FileEvents::None);
        assert_eq!(probed.platform.major(), None);
        // The hung sandbox-exec was killed, not left running.
        assert_eq!(machine.processes.signals().len(), 1);
        drop(release);
    }
}
