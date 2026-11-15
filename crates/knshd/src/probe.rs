//! The capability probe (KNSH-014; sandbox backend KNSH-046; `specs/05-models/capabilities.md`).
//!
//! [`probe`] runs once when `knshd` starts, before it serves anything. Its result is kept for the lifetime of the
//! process and shared by every `hello` and by the dispatch tables; a new `knshd` (launchd starts one on the next
//! connection after an idle exit) probes again. So the report always matches what this process found.
//!
//! | Capability | Check |
//! | --- | --- |
//! | `sandbox` | `knsh-exec` applies a deny-write profile and a line's write is observed to fail ([`check_sandbox`]) |
//! | `file_events` | An `FSEvents` stream is created, started and stopped |
//! | `platform` | The OS major version from `sysctl` |
//! | `network_filter`, `secrets` | No backend exists yet: always `none` |
//! | `checkpoints` | No root is configured yet: always `{}` |
//!
//! Every check is real, bounded by [`PROBE_TIMEOUT`], and any failure (an error, a bad exit, a timeout) reports the
//! backend as `none` (NFR-SEC-10, NFR-REL-08). Failures are logged with fixed reasons only.
//!
//! `sandbox: "seatbelt"` is reported exactly when the trampoline agent lines will use can apply and enforce a
//! profile on this machine; with `none`, every method that needs the sandbox is unlisted and answered `-32005`
//! naming `sandbox`, so agent sessions refuse to start (FR-AGT-06).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use knsh_platform::engine_dirs::FILE_MODE;
use knsh_platform::probe::{run_bounded, run_to_exit};
use knsh_platform::{
    Clock, ExitStatus, Field, Fs, Level, PlatformError, ProbeFailure, Processes, Random, SpawnRequest, SystemLog,
    SystemProbe, Value,
};
use knsh_proto::{Capabilities, FileEvents, NetworkFilter, Platform, Sandbox, SandboxViolations, Secrets};

/// How long each check may take. A working check takes milliseconds; the bound only matters when something hangs.
/// The checks run one after another, and a hung `knsh-exec` gets one more bound to be reaped after it is killed,
/// so the worst case delays start-up by four times this.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The probe's profile: everything allowed except writing files. Constant text, no path in it: the probe asks only
/// whether Seatbelt enforces a deny at all, with no rule of the compiler involved.
pub(crate) const PROBE_PROFILE: &str = "(version 1)(allow default)(deny file-write*)";

/// The interpreter of the probe line, which every macOS has.
pub(crate) const PROBE_INTERPRETER: &str = "/bin/sh";

/// The variable naming the file the probe line tries to create. Passed in the environment, so the path never needs
/// shell quoting.
pub(crate) const PROBE_TARGET_VAR: &str = "KNSH_PROBE_TARGET";

/// The exit that means "the write was attempted and failed". Distinct from the trampoline's own codes (64, 66, 69,
/// 71), `sandbox-exec`'s (65, 71) and the shell's (1, 2, 126, 127), so a run that never reached the write cannot
/// pass.
pub(crate) const PROBE_DENIED_EXIT: i32 = 42;

/// The probe line: with no target named it fails (so a lost environment cannot look like a denial); a write that
/// succeeds exits 1; only a failed write exits [`PROBE_DENIED_EXIT`].
pub(crate) const PROBE_LINE: &str =
    r#"[ -n "$KNSH_PROBE_TARGET" ] || exit 1; if echo knsh > "$KNSH_PROBE_TARGET"; then exit 1; fi; exit 42"#;

/// The file name of `knsh-exec`, installed next to `knshd`.
pub(crate) const TRAMPOLINE: &str = "knsh-exec";

/// The effects the probe uses.
pub(crate) struct Probes {
    /// Runs `knsh-exec`.
    pub(crate) processes: Arc<dyn Processes>,
    /// OS version and file events.
    pub(crate) system: Arc<dyn SystemProbe>,
    /// Deadlines.
    pub(crate) clock: Arc<dyn Clock>,
    /// Where failures are reported.
    pub(crate) log: Arc<dyn SystemLog>,
    /// The bound on each check.
    pub(crate) timeout: Duration,
    /// What the sandbox check needs besides processes.
    pub(crate) sandbox: SandboxProbe,
}

/// The sandbox check's own inputs.
pub(crate) struct SandboxProbe {
    /// The `knsh-exec` binary, or `None` if `knshd` cannot name its own executable (then `sandbox: none`).
    pub(crate) trampoline: Option<PathBuf>,
    /// A private engine directory (`0700`, this user's) for the probe's profile and its target file.
    pub(crate) dir: PathBuf,
    /// Writes the profile, makes the control write and looks for the target afterwards.
    pub(crate) fs: Arc<dyn Fs>,
    /// Makes the probe's file names unique, so a file left by an earlier run is never reused.
    pub(crate) random: Arc<dyn Random>,
}

impl SandboxProbe {
    /// The trampoline next to `executable` (`knshd`'s own path), if that path is absolute and has a parent.
    pub(crate) fn trampoline_beside(executable: &Path) -> Option<PathBuf> {
        // A relative path would be resolved against whatever directory knshd runs in, which is not where it lives.
        if !executable.is_absolute() {
            return None;
        }
        executable.parent().map(|dir| dir.join(TRAMPOLINE))
    }
}

/// What the probe found, fixed for the lifetime of this `knshd`.
#[derive(Debug, Clone)]
pub(crate) struct Probed {
    /// The `platform` string.
    pub(crate) platform: Platform,
    /// The backends.
    pub(crate) capabilities: Arc<Capabilities>,
}

/// Runs every check and builds the report.
pub(crate) fn probe(probes: &Probes) -> Probed {
    let sandbox = match check_sandbox(probes) {
        Ok(()) => Sandbox::Seatbelt,
        Err(failure) => {
            log_sandbox_failure(probes, failure);
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
        // No feature is claimed before it exists: the proxy arrives later in phase 3, secrets and checkpoints later.
        network_filter: NetworkFilter::None,
        file_events,
        secrets: Secrets::None,
        checkpoints: BTreeMap::new(),
        // Not probed: the violation reader reports its own state at each `hello` (KNSH-047, `violations.rs`).
        sandbox_violations: SandboxViolations::None,
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

/// Logs a failed sandbox check with fixed reasons only: the failure kind, the errno of a failed platform call and
/// the exit code of a run that ended wrongly (which tells a trampoline refusal from a write that went through).
fn log_sandbox_failure(probes: &Probes, failure: SandboxFailure) {
    let mut fields = vec![
        Field::new("backend", Value::Static("sandbox")),
        Field::new("reason", Value::Static(failure.kind())),
    ];
    if let Some(errno) = failure.errno() {
        fields.push(Field::new("errno", Value::Errno(errno)));
    }
    if let SandboxFailure::Exited(ExitStatus::Exited(code)) = failure {
        fields.push(Field::new("exit", Value::U64(u64::try_from(code).unwrap_or(0))));
    }
    probes.log.log(Level::Error, "capability probe failed", &fields);
}

/// Why the sandbox check did not pass. Holds no path or output, so it can be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SandboxFailure {
    /// `knshd` cannot name its own executable, so it cannot find `knsh-exec`.
    NoTrampoline,
    /// Preparing the probe failed: a random name, writing the profile, or the control write (the target location is
    /// not writable without the sandbox, so a failed write under it would prove nothing).
    Setup(PlatformError),
    /// `knsh-exec` could not be started, waited for, or did not finish in time.
    Run(ProbeFailure),
    /// It ended with anything but [`PROBE_DENIED_EXIT`]: the trampoline or `sandbox-exec` refused, or the write
    /// succeeded.
    Exited(ExitStatus),
    /// It reported a denial but the target file exists: the write was not really denied.
    WriteSucceeded,
}

impl SandboxFailure {
    /// A fixed name for the system log.
    pub(crate) const fn kind(self) -> &'static str {
        match self {
            Self::NoTrampoline => "no_trampoline",
            Self::Setup(_) => "setup",
            Self::Run(failure) => failure.kind(),
            Self::Exited(_) => "exited",
            Self::WriteSucceeded => "write_succeeded",
        }
    }

    /// The `errno` of a failed platform call, if that is what failed.
    pub(crate) fn errno(self) -> Option<i32> {
        match self {
            Self::Setup(error) | Self::Run(ProbeFailure::Platform(error)) => error.errno(),
            Self::NoTrampoline
            | Self::Run(ProbeFailure::Exited(_) | ProbeFailure::TimedOut | ProbeFailure::NoAnswer)
            | Self::Exited(_)
            | Self::WriteSucceeded => None,
        }
    }
}

/// The sandbox check (KNSH-046): `knsh-exec` runs [`PROBE_LINE`] under [`PROBE_PROFILE`], and passes only if the
/// line exits [`PROBE_DENIED_EXIT`] and the file it tried to create does not exist.
///
/// 1. Write the profile to `probe-<random>.sb` in [`SandboxProbe::dir`] (new file, `0600`).
/// 2. Control: create and remove `probe-<random>.target` there without a sandbox, so the location is known to be
///    writable and the target known to be absent.
/// 3. Run `knsh-exec --profile <file> --interpreter /bin/sh --line <PROBE_LINE>`, bounded by the timeout, with only
///    [`PROBE_TARGET_VAR`] in its environment.
/// 4. Require the denied exit, then require the target to be absent.
///
/// Both files are removed afterwards, whatever happened (best effort).
///
/// # Errors
///
/// A [`SandboxFailure`] for the first step that did not go as expected.
pub(crate) fn check_sandbox(probes: &Probes) -> Result<(), SandboxFailure> {
    let sandbox = &probes.sandbox;
    let trampoline = sandbox.trampoline.as_deref().ok_or(SandboxFailure::NoTrampoline)?;
    let token = sandbox.random.next_u64().map_err(SandboxFailure::Setup)?;
    let stem = format!("probe-{token:016x}");
    let profile = sandbox.dir.join(format!("{stem}.sb"));
    let target = sandbox.dir.join(format!("{stem}.target"));

    let result = run_sandbox_check(probes, trampoline, &profile, &target);
    // Best effort: the names are random, so a file that cannot be removed now is never read again.
    for path in [&profile, &target] {
        let _ = sandbox.fs.remove_file(path);
    }
    result
}

/// Steps 1 to 4 of [`check_sandbox`].
fn run_sandbox_check(probes: &Probes, trampoline: &Path, profile: &Path, target: &Path) -> Result<(), SandboxFailure> {
    let fs = probes.sandbox.fs.as_ref();
    // `create_new` refuses anything already there (including a symlink), so the profile is exactly what was written.
    fs.create_new(profile, FILE_MODE).map_err(SandboxFailure::Setup)?;
    fs.write(profile, PROBE_PROFILE.as_bytes(), FILE_MODE)
        .map_err(SandboxFailure::Setup)?;
    fs.create_new(target, FILE_MODE).map_err(SandboxFailure::Setup)?;
    fs.remove_file(target).map_err(SandboxFailure::Setup)?;

    let request = SpawnRequest::new(trampoline)
        .arg("--profile")
        .arg(profile)
        .arg("--interpreter")
        .arg(PROBE_INTERPRETER)
        .arg("--line")
        .arg(PROBE_LINE)
        .env(PROBE_TARGET_VAR, target);
    let status = run_to_exit(
        probes.processes.as_ref(),
        probes.clock.as_ref(),
        &request,
        probes.timeout,
    )
    .map_err(SandboxFailure::Run)?;
    if status != ExitStatus::Exited(PROBE_DENIED_EXIT) {
        return Err(SandboxFailure::Exited(status));
    }
    // The exit says "denied"; the filesystem must agree. Any answer but "not found" fails the probe.
    match fs.metadata(target) {
        Err(error) if error.is_not_found() => Ok(()),
        Err(error) => Err(SandboxFailure::Setup(error)),
        Ok(_) => Err(SandboxFailure::WriteSucceeded),
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
    use knsh_platform::testing::{
        FakeClock, FakeSystemProbe, MemFs, RecordingLog, Script, ScriptedProcesses, SeededRandom,
    };
    use knsh_platform::{Operation, ProcessGroupId, Signal};

    use super::*;

    /// Where the fake `knsh-exec` lives.
    pub(crate) const TRAMPOLINE_PATH: &str = "/knsh/bin/knsh-exec";
    /// The fake private directory for the probe's files.
    const DIR: &str = "/knsh/run";

    /// Scripted processes that, on spawn, can create the file the probe line targets, as a real unsandboxed write
    /// would; and that record the profile file's contents and mode as they were when `knsh-exec` started.
    pub(crate) struct Trampoline {
        pub(crate) scripted: ScriptedProcesses,
        fs: Arc<MemFs>,
        writes: bool,
        seen_profile: std::sync::Mutex<Option<(Vec<u8>, u32)>>,
    }

    impl Processes for Trampoline {
        fn spawn(&self, request: &SpawnRequest) -> Result<ProcessGroupId, PlatformError> {
            let profile = request.args.get(1).map(PathBuf::from);
            if let Some(profile) = profile
                && let Some(contents) = self.fs.contents(&profile)
            {
                let mode = self.fs.metadata(&profile)?.mode;
                *self.seen_profile.lock().unwrap() = Some((contents, mode));
            }
            if self.writes
                && let Some((_, target)) = request.env.iter().find(|(key, _)| key == PROBE_TARGET_VAR)
            {
                self.fs.write(Path::new(target), b"knsh\n", 0o644)?;
            }
            self.scripted.spawn(request)
        }

        fn signal(&self, group: ProcessGroupId, signal: Signal) -> Result<(), PlatformError> {
            self.scripted.signal(group, signal)
        }

        fn wait(&self, group: ProcessGroupId) -> Result<ExitStatus, PlatformError> {
            self.scripted.wait(group)
        }

        fn exited(&self, group: ProcessGroupId) -> Result<bool, PlatformError> {
            self.scripted.exited(group)
        }

        fn try_wait(&self, group: ProcessGroupId) -> Result<Option<ExitStatus>, PlatformError> {
            self.scripted.try_wait(group)
        }
    }

    /// A test machine: a scripted `knsh-exec`, an in-memory filesystem, a fake system probe, a fake clock and a
    /// recording log.
    pub(crate) struct Machine {
        pub(crate) processes: Arc<Trampoline>,
        pub(crate) fs: Arc<MemFs>,
        pub(crate) system: Arc<dyn SystemProbe>,
        pub(crate) clock: Arc<FakeClock>,
        pub(crate) log: Arc<RecordingLog>,
        pub(crate) trampoline: Option<PathBuf>,
    }

    impl Machine {
        /// `knsh-exec` follows `script`; with `writes`, the line's write really lands (no sandbox in effect).
        pub(crate) fn with(script: Script, writes: bool, system: Arc<dyn SystemProbe>) -> Self {
            let fs = Arc::new(MemFs::new());
            fs.add_dir_all(Path::new(DIR)).unwrap();
            let scripted = ScriptedProcesses::new();
            scripted.expect(TRAMPOLINE_PATH, script);
            Self {
                processes: Arc::new(Trampoline {
                    scripted,
                    fs: Arc::clone(&fs),
                    writes,
                    seen_profile: std::sync::Mutex::new(None),
                }),
                fs,
                system,
                clock: Arc::new(FakeClock::new(Timestamp::UNIX_EPOCH)),
                log: Arc::new(RecordingLog::new()),
                trampoline: Some(PathBuf::from(TRAMPOLINE_PATH)),
            }
        }

        pub(crate) fn new(sandbox: Script, system: Arc<dyn SystemProbe>) -> Self {
            Self::with(sandbox, false, system)
        }

        /// Every check passes, on OS major version 15: the trampoline reports the write denied and nothing was
        /// written.
        pub(crate) fn working() -> Self {
            Self::new(Script::Exits(PROBE_DENIED_EXIT), Arc::new(FakeSystemProbe::working(15)))
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
                sandbox: SandboxProbe {
                    trampoline: self.trampoline.clone(),
                    dir: PathBuf::from(DIR),
                    fs: self.fs.clone(),
                    random: Arc::new(SeededRandom::new(7)),
                },
            }
        }

        fn sandbox(&self) -> Sandbox {
            probe(&self.probes()).capabilities.sandbox
        }

        /// The `reason` of every logged probe failure.
        fn failure_reasons(&self) -> Vec<String> {
            self.log
                .entries()
                .into_iter()
                .filter(|entry| entry.message == "capability probe failed")
                .map(|entry| format!("{:?}", entry.fields))
                .collect()
        }

        /// Nothing but the probe directory itself is left.
        fn assert_clean(&self) {
            let left: Vec<PathBuf> = self.fs.paths().into_iter().filter(|p| p.starts_with(DIR)).collect();
            assert_eq!(left, [PathBuf::from(DIR)], "the probe removes its files");
        }
    }

    #[test]
    fn working_machine_reports_its_backends() {
        let machine = Machine::working();
        let probed = probe(&machine.probes());
        assert_eq!(probed.capabilities.sandbox, Sandbox::Seatbelt);
        assert_eq!(probed.capabilities.file_events, FileEvents::FsEvents);
        assert_eq!(probed.platform.major(), Some(15));
        assert_eq!(
            machine.processes.scripted.remaining_scripts(),
            0,
            "knsh-exec really ran"
        );
    }

    // KNSH-046: `seatbelt` only when knsh-exec applied the deny profile and the line's write was observed to fail.
    #[test]
    fn probe_reports_seatbelt_when_denial_observed() {
        let machine = Machine::working();
        assert_eq!(machine.sandbox(), Sandbox::Seatbelt);

        // It ran the trampoline with the probe's profile file, interpreter and line, and nothing else.
        let spawned = machine.processes.scripted.spawned();
        assert_eq!(spawned.len(), 1);
        let request = &spawned[0];
        assert_eq!(request.program, Path::new(TRAMPOLINE_PATH));
        let profile = PathBuf::from(&request.args[1]);
        assert_eq!(
            request.args,
            [
                "--profile".into(),
                profile.clone().into_os_string(),
                "--interpreter".into(),
                PROBE_INTERPRETER.into(),
                "--line".into(),
                PROBE_LINE.into(),
            ]
        );
        assert!(profile.starts_with(DIR) && profile.extension() == Some("sb".as_ref()));
        assert_eq!(
            request.env.len(),
            1,
            "only the target: the engine's environment is never passed on"
        );
        assert_eq!(request.env[0].0, PROBE_TARGET_VAR);
        let target = PathBuf::from(&request.env[0].1);
        assert!(target.starts_with(DIR));

        // The profile file held exactly the deny profile, owner-only, while knsh-exec ran.
        let seen = machine.processes.seen_profile.lock().unwrap().clone();
        assert_eq!(seen, Some((PROBE_PROFILE.as_bytes().to_vec(), FILE_MODE)));
        machine.assert_clean();
    }

    // KNSH-046: a write that succeeds means nothing was enforced, whatever the exit code says.
    #[test]
    fn probe_reports_none_when_write_succeeds() {
        // The honest case: the line saw its write succeed and exited 1.
        let machine = Machine::with(Script::Exits(1), true, Arc::new(FakeSystemProbe::working(15)));
        assert_eq!(machine.sandbox(), Sandbox::None);
        assert!(machine.failure_reasons()[0].contains("exited"));
        machine.assert_clean();

        // The exit claims a denial but the file is there: the filesystem wins.
        let machine = Machine::with(
            Script::Exits(PROBE_DENIED_EXIT),
            true,
            Arc::new(FakeSystemProbe::working(15)),
        );
        assert_eq!(machine.sandbox(), Sandbox::None);
        assert!(machine.failure_reasons()[0].contains("write_succeeded"));
        machine.assert_clean();
    }

    // KNSH-046, NFR-SEC-10: any error in the probe reports `none`, and is logged without content.
    #[test]
    fn probe_reports_none_on_error() {
        let system = || -> Arc<dyn SystemProbe> { Arc::new(FakeSystemProbe::working(15)) };

        // knshd cannot find knsh-exec.
        let mut machine = Machine::working();
        machine.trampoline = None;
        assert_eq!(machine.sandbox(), Sandbox::None);
        assert!(machine.failure_reasons()[0].contains("no_trampoline"));

        // knsh-exec cannot be started.
        let machine = Machine::new(Script::FailsToSpawn(2), system());
        assert_eq!(machine.sandbox(), Sandbox::None);
        machine.assert_clean();

        // The trampoline or sandbox-exec refused (usage, profile, sandbox-exec missing, profile not applied), or the
        // line was killed.
        for code in [64, 65, 66, 69, 71, 126, 127, 0] {
            let machine = Machine::new(Script::Exits(code), system());
            assert_eq!(machine.sandbox(), Sandbox::None, "exit {code}");
            machine.assert_clean();
        }

        // The profile cannot be written, or the control write fails (a failed write under the sandbox would then
        // prove nothing).
        for (operation, errno) in [
            (Operation::Write, 28),
            (Operation::Write, 13),
            (Operation::RemoveFile, 1),
        ] {
            let machine = Machine::working();
            machine.fs.inject_fault(operation, errno);
            assert_eq!(machine.sandbox(), Sandbox::None, "{operation:?}");
            assert!(machine.failure_reasons()[0].contains("setup"));
            assert_eq!(machine.processes.scripted.spawned().len(), 0, "nothing ran");
        }

        // The target cannot be checked afterwards.
        let machine = Machine::working();
        machine.fs.inject_fault(Operation::Metadata, 13);
        assert_eq!(machine.sandbox(), Sandbox::None);
    }

    // KNSH-046: the knsh-exec integration test runs this probe's profile and line against the real Seatbelt; it
    // keeps its own copy (knsh-exec depends on nothing), so the copy must not drift.
    #[test]
    fn real_trampoline_test_uses_the_probe_constants() {
        let test = include_str!("../../knsh-exec/tests/trampoline.rs");
        assert!(test.contains(PROBE_PROFILE));
        assert!(test.contains(PROBE_LINE));
        assert!(test.contains(&format!("Some({PROBE_DENIED_EXIT})")));
    }

    #[test]
    fn finds_the_trampoline_next_to_knshd() {
        assert_eq!(
            SandboxProbe::trampoline_beside(Path::new("/opt/knsh/bin/knshd")),
            Some(PathBuf::from("/opt/knsh/bin/knsh-exec"))
        );
        assert_eq!(SandboxProbe::trampoline_beside(Path::new("knshd")), None);
        assert_eq!(SandboxProbe::trampoline_beside(Path::new("/")), None);
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
        assert_eq!(machine.failure_reasons().len(), 3);
        for entry in machine.failure_reasons() {
            assert!(!entry.contains(DIR), "no path is logged: {entry}");
        }
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

    // KNSH-014: probing is bounded; a hanging probe reports `none` (fake clock: no real waiting for knsh-exec).
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
        // The hung knsh-exec was killed, not left running, and its files removed.
        assert_eq!(machine.processes.scripted.signals().len(), 1);
        machine.assert_clean();
        drop(release);
    }
}
