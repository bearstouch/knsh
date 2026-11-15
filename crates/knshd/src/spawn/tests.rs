//! The spawner against a fake `knsh-exec` on a fake clock, and against the real one on this machine (KNSH-051).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use knsh_core::{LookupError, PathContext, PolicyFs, ProfileName, ProfileSource, Timestamp, Ulid, load_profile_text};
use knsh_platform::engine_dirs::DIR_MODE;
use knsh_platform::testing::{DEFAULT_UID, FakeClock, MemFs, RecordingLog};
use knsh_platform::{EnginePaths, Fs, Monotonic, Operation};

use super::*;

const HOME: &str = "/Users/u";
const PROJECT: &str = "/Users/u/app";
/// Where the fake `knsh-exec` lives.
const TRAMPOLINE: &str = "/knsh/bin/knsh-exec";

/// Every path is already canonical.
struct Canonical;

impl PolicyFs for Canonical {
    fn canonicalise(&self, path: &Path) -> Result<CanonicalPath, LookupError> {
        CanonicalPath::new(path).map_err(|_| LookupError::Failed)
    }
}

struct NoParents;

impl ProfileSource for NoParents {
    fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        Err(LookupError::NotFound)
    }
}

/// The profile `web`, with `extra` appended to its text.
fn profile(extra: &str) -> Profile {
    let context = PathContext {
        home: PathBuf::from(HOME),
        tmpdir: PathBuf::from("/private/tmp"),
        start_dir: PathBuf::from(PROJECT),
    };
    let text = format!("name = \"web\"\n{extra}");
    load_profile_text(text.as_bytes(), &NoParents, &context, &Canonical).unwrap()
}

/// How the fake trampoline's line behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    /// Exits with this code this long after the spawn.
    ExitsAfter(Duration, i32),
    /// Ends at the first `SIGTERM` or `SIGKILL`.
    StopsOnTerm,
    /// Ignores `SIGTERM`; only `SIGKILL` ends it.
    IgnoresTerm,
    /// `knsh-exec` fails before `sandbox-exec`: writes this code to its status descriptor and exits with it.
    FailsSetup(u8),
}

#[derive(Debug, Default)]
struct FakeState {
    spawned: Vec<SpawnRequest>,
    /// Each signal with the fake time since the spawn it was sent at.
    signals: Vec<(Duration, Signal)>,
    started_at: Option<Monotonic>,
    ended: Option<ExitStatus>,
    reaped: bool,
    /// The status descriptor's number in the spawn request.
    status_fd: Option<i32>,
    /// Whether the compiled profile file existed, with these bytes, when `knsh-exec` started.
    profile_seen: Option<Vec<u8>>,
}

/// A fake `knsh-exec` group on a fake clock: one spawn per test.
struct FakeTrampoline {
    clock: Arc<FakeClock>,
    fs: Arc<MemFs>,
    behaviour: Behaviour,
    state: Mutex<FakeState>,
    /// What the line writes to its stdout and stderr as it starts, then closes them.
    writes: Option<(&'static [u8], &'static [u8])>,
}

const GROUP: i32 = 4242;

impl FakeTrampoline {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap()
    }

    fn elapsed(&self, state: &FakeState) -> Duration {
        self.clock
            .monotonic()
            .saturating_duration_since(state.started_at.unwrap())
    }

    /// Ends the line by itself once its time has come.
    fn advance(&self, state: &mut FakeState) {
        if state.ended.is_none()
            && let Behaviour::ExitsAfter(after, code) = self.behaviour
            && self.elapsed(state) >= after
        {
            state.ended = Some(ExitStatus::Exited(code));
        }
    }

    fn held(state: &FakeState, group: ProcessGroupId) -> Result<(), PlatformError> {
        if group.as_raw() != GROUP || state.reaped || state.started_at.is_none() {
            return Err(PlatformError::UnknownProcessGroup);
        }
        Ok(())
    }
}

impl Processes for FakeTrampoline {
    fn spawn(&self, request: &SpawnRequest) -> Result<ProcessGroupId, PlatformError> {
        let mut state = self.state();
        assert!(state.started_at.is_none(), "one spawn per test");
        let profile = request
            .args
            .iter()
            .position(|arg| arg == "--profile")
            .map(|at| PathBuf::from(&request.args[at + 1]));
        state.profile_seen = profile.and_then(|path| self.fs.contents(&path));
        if let Behaviour::FailsSetup(code) = self.behaviour {
            let mut status = std::fs::File::from(request.inherit[0].try_clone_owned().unwrap());
            status.write_all(&[code]).unwrap();
            state.ended = Some(ExitStatus::Exited(i32::from(code)));
        }
        // Kept without the status pipe's write end: holding it would keep the spawner's read from ever ending, as
        // a real child that exited no longer holds it. Its number is kept for assertions.
        let mut kept = request.clone();
        if let (Some((stdout, stderr)), Stdio::Passed(fds)) = (self.writes, &request.stdio) {
            std::fs::File::from(fds[1].try_clone_owned().unwrap())
                .write_all(stdout)
                .unwrap();
            std::fs::File::from(fds[2].try_clone_owned().unwrap())
                .write_all(stderr)
                .unwrap();
            // Like a child that exited: it no longer holds the output pipes, so the readers see end of file.
            kept.stdio = Stdio::Null;
        }
        state.status_fd = kept.inherit.first().map(AsRawFd::as_raw_fd);
        kept.inherit.clear();
        state.spawned.push(kept);
        state.started_at = Some(self.clock.monotonic());
        Ok(ProcessGroupId::from_raw(GROUP))
    }

    fn signal(&self, group: ProcessGroupId, signal: Signal) -> Result<(), PlatformError> {
        let mut state = self.state();
        Self::held(&state, group)?;
        let at = self.elapsed(&state);
        state.signals.push((at, signal));
        let ends = matches!(
            (signal, self.behaviour),
            (Signal::Kill, _) | (Signal::Terminate, Behaviour::StopsOnTerm | Behaviour::ExitsAfter(..))
        );
        if state.ended.is_none() && ends {
            state.ended = Some(ExitStatus::Signalled(signal.number()));
        }
        Ok(())
    }

    fn exited(&self, group: ProcessGroupId) -> Result<bool, PlatformError> {
        let mut state = self.state();
        Self::held(&state, group)?;
        self.advance(&mut state);
        Ok(state.ended.is_some())
    }

    fn wait(&self, group: ProcessGroupId) -> Result<ExitStatus, PlatformError> {
        let mut state = self.state();
        Self::held(&state, group)?;
        self.advance(&mut state);
        let status = state.ended.ok_or(PlatformError::NotScripted)?;
        state.reaped = true;
        Ok(status)
    }

    fn try_wait(&self, group: ProcessGroupId) -> Result<Option<ExitStatus>, PlatformError> {
        let ended = self.exited(group)?;
        if ended { self.wait(group).map(Some) } else { Ok(None) }
    }
}

/// Counts the events and when they came, on the fake clock.
#[derive(Default)]
struct Seen {
    events: Mutex<Vec<(&'static str, Duration)>>,
    clock: Option<Arc<FakeClock>>,
}

impl Seen {
    fn at(&self, name: &'static str) {
        let now = self
            .clock
            .as_ref()
            .map_or(Duration::ZERO, |clock| clock.monotonic().elapsed_since_origin());
        self.events.lock().unwrap().push((name, now));
    }

    fn names(&self) -> Vec<&'static str> {
        self.events.lock().unwrap().iter().map(|(name, _)| *name).collect()
    }
}

impl LineEvents for Seen {
    fn started(&self) {
        self.at("started");
    }

    fn long_running(&self) {
        self.at("long_running");
    }
}

/// A spawner over a fake trampoline and an in-memory profiles directory.
struct Fixture {
    clock: Arc<FakeClock>,
    fs: Arc<MemFs>,
    processes: Arc<FakeTrampoline>,
    log: Arc<RecordingLog>,
    spawner: TrampolineSpawner,
}

fn profiles_dir() -> PathBuf {
    EnginePaths::for_home(Path::new(HOME)).unwrap().profiles_dir()
}

fn fixture(behaviour: Behaviour) -> Fixture {
    fixture_writing(behaviour, None)
}

/// [`fixture`] whose line writes `writes` to its stdout and stderr as it starts.
fn fixture_writing(behaviour: Behaviour, writes: Option<(&'static [u8], &'static [u8])>) -> Fixture {
    let clock = Arc::new(FakeClock::new(
        Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
    ));
    let fs = Arc::new(MemFs::new());
    fs.add_dir_all(&profiles_dir()).unwrap();
    fs.set_mode(&profiles_dir(), DIR_MODE).unwrap();
    let processes = Arc::new(FakeTrampoline {
        clock: Arc::clone(&clock),
        fs: Arc::clone(&fs),
        behaviour,
        state: Mutex::new(FakeState::default()),
        writes,
    });
    let log = Arc::new(RecordingLog::new());
    let spawner = TrampolineSpawner {
        processes: processes.clone(),
        clock: clock.clone(),
        files: ProfileFiles::new(fs.clone(), profiles_dir(), DEFAULT_UID, |bytes| {
            let mut digest = [0u8; 32];
            digest[..8].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
            digest
        }),
        log: log.clone(),
        trampoline: PathBuf::from(TRAMPOLINE),
        home: CanonicalPath::new(HOME).unwrap(),
        limits: Limits::DEFAULT,
    };
    Fixture {
        clock,
        fs,
        processes,
        log,
        spawner,
    }
}

/// One line's inputs, owned, so a test can change any of them before running it.
struct Line {
    profile: Profile,
    executed: String,
    binaries: Vec<CanonicalPath>,
    interpreter: Interpreter,
    args: Vec<String>,
    env: Vec<(String, String)>,
    cwd: CanonicalPath,
    timeout: Option<Duration>,
    control: LineControl,
    capture: Option<CapturePlan>,
}

impl Line {
    fn new(interpreter: Interpreter) -> Self {
        Self {
            profile: profile(""),
            executed: "/usr/bin/git status".to_owned(),
            binaries: vec![CanonicalPath::new("/usr/bin/git").unwrap()],
            interpreter,
            args: Vec::new(),
            env: vec![("HOME".to_owned(), HOME.to_owned())],
            cwd: CanonicalPath::new(PROJECT).unwrap(),
            timeout: None,
            control: LineControl::default(),
            capture: None,
        }
    }

    fn to_run(&self, stdio: Option<LineStdio>) -> LineToRun<'_> {
        LineToRun {
            record_id: RecordId::from_ulid(Ulid::from_u128(7)),
            session_id: SessionId::from_ulid(Ulid::from_u128(3)),
            profile: &self.profile,
            executed: &self.executed,
            binaries: &self.binaries,
            interpreter: self.interpreter,
            args: &self.args,
            env: &self.env,
            cwd: &self.cwd,
            stdio,
            timeout: self.timeout,
            capture: self.capture.clone(),
            control: &self.control,
        }
    }
}

impl Fixture {
    fn run(&self, line: &Line) -> (SpawnReport, Seen) {
        let seen = Seen {
            clock: Some(Arc::clone(&self.clock)),
            ..Seen::default()
        };
        let report = self.spawner.run(line.to_run(None), &seen);
        (report, seen)
    }

    fn request(&self) -> SpawnRequest {
        self.processes.state().spawned[0].clone()
    }

    fn signals(&self) -> Vec<(Duration, Signal)> {
        self.processes.state().signals.clone()
    }
}

/// The value after `option` in `request`'s arguments.
fn option<'a>(request: &'a SpawnRequest, name: &str) -> Option<&'a OsString> {
    let at = request.args.iter().position(|arg| arg == name)?;
    request.args.get(at + 1)
}

fn exits(code: i32) -> Behaviour {
    Behaviour::ExitsAfter(Duration::from_millis(5), code)
}

fn ran(report: &SpawnReport) -> Ran {
    *report.outcome.as_ref().unwrap()
}

// FR-LC-14: `sh` runs `/bin/sh`, `zsh` runs `/bin/zsh`, whatever the profile's bash is.
#[test]
fn selects_bin_sh_for_sh_request() {
    for (interpreter, expected) in [(Interpreter::Sh, "/bin/sh"), (Interpreter::Zsh, "/bin/zsh")] {
        let fixture = fixture(exits(0));
        let mut line = Line::new(interpreter);
        line.profile = profile("[exec]\nbash = \"/opt/homebrew/bin/bash\"\n");
        let (report, _) = fixture.run(&line);
        assert_eq!(ran(&report).status, LineStatus::Exited(0));
        let request = fixture.request();
        assert_eq!(option(&request, "--interpreter").unwrap(), expected);
    }
}

// FR-LC-14, NFR-COMPAT-04: `bash` and `knsh -c` run the profile's bash: `/bin/bash` by default, another if named.
#[test]
fn selects_profile_bash_for_knsh_c() {
    for (extra, expected) in [
        ("", "/bin/bash"),
        ("[exec]\nbash = \"/opt/homebrew/bin/bash\"\n", "/opt/homebrew/bin/bash"),
    ] {
        for interpreter in [Interpreter::Knsh, Interpreter::Bash] {
            let fixture = fixture(exits(0));
            let mut line = Line::new(interpreter);
            line.profile = profile(extra);
            fixture.run(&line);
            let request = fixture.request();
            assert_eq!(option(&request, "--interpreter").unwrap(), expected, "{interpreter:?}");
        }
    }
}

// FR-LC-13, FR-LC-16: the child is `knsh-exec` with the compiled profile file, the re-serialised line and its
// operands, in the line's directory, with exactly the environment `knshd` received: the shim directory and the
// session token were removed on receipt (KNSH-049) and nothing is added back.
#[test]
fn strips_shim_directory_from_child_path() {
    let shims = EnginePaths::for_home(Path::new(HOME)).unwrap().shim_dir();
    let received = vec![
        ("HOME".to_owned(), HOME.to_owned()),
        ("PATH".to_owned(), format!("{}:/usr/bin:/bin", shims.display())),
        (knsh_proto::SESSION_TOKEN_VAR.to_owned(), "secret".to_owned()),
        // Read by the dynamic linker of the unsandboxed `knsh-exec`: never passed on.
        ("DYLD_INSERT_LIBRARIES".to_owned(), format!("{PROJECT}/inject.dylib")),
        ("LANG".to_owned(), "C".to_owned()),
    ];
    let fixture = fixture(exits(3));
    let mut line = Line::new(Interpreter::Bash);
    line.env = crate::exec::supervised_env(received, &shims);
    line.args = vec!["name".to_owned(), "one".to_owned()];
    let (report, _) = fixture.run(&line);
    assert_eq!(ran(&report).status, LineStatus::Exited(3));

    let request = fixture.request();
    assert_eq!(request.program, Path::new(TRAMPOLINE));
    let env: Vec<(String, String)> = request
        .env
        .iter()
        .map(|(name, value)| (name.to_str().unwrap().to_owned(), value.to_str().unwrap().to_owned()))
        .collect();
    assert_eq!(
        env,
        [
            ("HOME".to_owned(), HOME.to_owned()),
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ("LANG".to_owned(), "C".to_owned()),
        ]
    );
    assert_eq!(request.cwd.as_deref(), Some(Path::new(PROJECT)));
    let status_fd = fixture.processes.state().status_fd.unwrap().to_string();
    let profile_file = option(&request, "--profile").unwrap().clone();
    assert_eq!(
        request.args,
        [
            "--status-fd",
            status_fd.as_str(),
            "--profile",
            profile_file.to_str().unwrap(),
            "--interpreter",
            "/bin/bash",
            "--line",
            "/usr/bin/git status",
            "--arg",
            "name",
            "--arg",
            "one",
        ]
        .map(OsString::from)
    );
    // FR-SBX-07: the profile file was written before the spawn, holds this line's profile (tagged with its record,
    // exec allowed for the binary it resolved to), is named in the record, and is removed once the line has ended.
    let seen = String::from_utf8(fixture.processes.state().profile_seen.clone().unwrap()).unwrap();
    assert!(
        seen.contains("knsh:00000000000000000000000003:00000000000000000000000007:"),
        "{seen}"
    );
    assert!(seen.contains(r#"(literal "/usr/bin/git")"#), "{seen}");
    assert_eq!(
        report.sandbox_profile.as_deref().unwrap().split('@').next(),
        Some("web")
    );
    assert!(fixture.fs.contents(Path::new(&profile_file)).is_none());
}

// FR-LC-40: at `timeout_s` the group gets SIGTERM, then SIGKILL after the grace period if it is still there; it is
// killed once more before the leader is reaped, so no member survives. Never a signal after the reap.
#[test]
fn kills_process_group_on_timeout_with_32008() {
    let second = Duration::from_secs(1);
    let fixture = fixture(Behaviour::IgnoresTerm);
    let mut line = Line::new(Interpreter::Bash);
    line.timeout = Some(second);
    let (report, _) = fixture.run(&line);
    let outcome = ran(&report);
    assert!(outcome.timed_out);
    assert_eq!(outcome.status, LineStatus::Signalled(9));
    let signals = fixture.signals();
    let kinds: Vec<Signal> = signals.iter().map(|(_, signal)| *signal).collect();
    assert_eq!(kinds, [Signal::Terminate, Signal::Kill, Signal::Kill]);
    // On time, within one poll.
    assert!(
        signals[0].0 >= second && signals[0].0 < second + POLL_MAX,
        "{signals:?}"
    );
    let grace = signals[1].0.checked_sub(signals[0].0).unwrap();
    assert!(grace >= Limits::DEFAULT.kill_grace && grace < Limits::DEFAULT.kill_grace + POLL_MAX);
    assert!(fixture.processes.state().reaped);

    // A line that stops at SIGTERM: no wait for the grace period, and its group is still killed before the reap.
    let fixture = self::fixture(Behaviour::StopsOnTerm);
    let (report, _) = fixture.run(&line);
    assert_eq!(
        ran(&report),
        Ran {
            status: LineStatus::Signalled(15),
            timed_out: true
        }
    );
    let kinds: Vec<Signal> = fixture.signals().iter().map(|(_, signal)| *signal).collect();
    assert_eq!(kinds, [Signal::Terminate, Signal::Kill]);

    // Ending before the timeout: no signal at all.
    let fixture = self::fixture(exits(0));
    let (report, _) = fixture.run(&line);
    assert!(!ran(&report).timed_out);
    assert_eq!(fixture.signals(), []);
}

// `exec.kill` stops the whole group as a timeout does (SIGTERM, SIGKILL after the grace, a last group kill before the
// reap), but is not a timeout: the line ends by its signal and is not answered -32008.
#[test]
fn kill_terminates_whole_process_group() {
    let fixture = fixture(Behaviour::IgnoresTerm);
    let line = Line::new(Interpreter::Bash);
    assert!(line.control.request_kill(), "still running");
    let (report, _) = fixture.run(&line);
    assert_eq!(
        ran(&report),
        Ran {
            status: LineStatus::Signalled(9),
            timed_out: false
        }
    );
    let kinds: Vec<Signal> = fixture.signals().iter().map(|(_, signal)| *signal).collect();
    assert_eq!(kinds, [Signal::Terminate, Signal::Kill, Signal::Kill]);
    let signals = fixture.signals();
    assert!(signals[0].0 < POLL_MAX, "at once: {signals:?}");
    assert!(fixture.processes.state().reaped);
}

/// A capture plan keeping `cap` bytes, publishing nothing.
fn capture_plan(cap: usize) -> CapturePlan {
    CapturePlan {
        redaction: Arc::new(knsh_core::NoOutputRedaction),
        cap,
        sink: None,
    }
}

// KNSH-053: a captured line runs with stdin on /dev/null and stdout and stderr on pipes, and the report carries
// what it wrote, capped (FR-REC-06).
#[test]
fn captured_line_reports_its_output() {
    let fixture = fixture_writing(exits(0), Some((b"0123456789", b"oops\n")));
    let mut line = Line::new(Interpreter::Bash);
    line.capture = Some(capture_plan(4));
    let (report, _) = fixture.run(&line);
    assert_eq!(ran(&report).status, LineStatus::Exited(0));
    let output = report.output.unwrap();
    assert_eq!(output.stdout.output.data().expose(), b"0189");
    assert_eq!(output.stdout.output.info().original, 10);
    assert_eq!(output.stderr.output.data().expose(), b"oos\n", "head and tail");
    assert_eq!(output.stderr.lines, 1);
    // Without a plan, nothing is captured.
    let fixture = self::fixture(exits(0));
    let (report, _) = fixture.run(&Line::new(Interpreter::Bash));
    assert!(report.output.is_none());
}

// KNSH-053, FR-OUT-04: `knsh -c` in a session that records output: the line's output is teed, so the caller's
// descriptors receive exactly what it wrote while the capture keeps a copy; stdin stays the caller's.
#[test]
fn tees_passed_output_when_recording() {
    let fixture = fixture_writing(exits(0), Some((b"to the caller\n", b"err\n")));
    let mut line = Line::new(Interpreter::Knsh);
    line.capture = Some(capture_plan(1 << 20));
    let (mut out_read, out_write) = std::io::pipe().unwrap();
    let (mut err_read, err_write) = std::io::pipe().unwrap();
    let (stdin_read, _stdin_write) = std::io::pipe().unwrap();
    let stdio = LineStdio {
        stdin: stdin_read.into(),
        stdout: out_write.into(),
        stderr: err_write.into(),
    };
    let report = fixture.spawner.run(line.to_run(Some(stdio)), &Seen::default());
    assert_eq!(ran(&report).status, LineStatus::Exited(0));
    let output = report.output.unwrap();
    assert_eq!(output.stdout.output.data().expose(), b"to the caller\n");
    // Every copy of the caller's write ends is closed once the readers are done with them.
    let mut seen = Vec::new();
    out_read.read_to_end(&mut seen).unwrap();
    assert_eq!(seen, b"to the caller\n");
    let mut seen = Vec::new();
    err_read.read_to_end(&mut seen).unwrap();
    assert_eq!(seen, b"err\n");
    match &fixture.request().stdio {
        Stdio::Null => {}
        other => panic!("the fake drops what it wrote to: {other:?}"),
    }
}

// FR-LC-17: `command.started` once spawned; `command.long_running` exactly once after 30 s, never for a short line.
#[test]
fn emits_long_running_once_after_threshold() {
    let fixture = fixture(Behaviour::ExitsAfter(Duration::from_secs(95), 0));
    let (report, seen) = fixture.run(&Line::new(Interpreter::Bash));
    assert_eq!(ran(&report).status, LineStatus::Exited(0));
    assert_eq!(seen.names(), ["started", "long_running"]);
    let events = seen.events.lock().unwrap().clone();
    let threshold = Limits::DEFAULT.long_running;
    assert!(
        events[1].1 >= threshold && events[1].1 < threshold + POLL_MAX,
        "{events:?}"
    );

    let fixture = self::fixture(Behaviour::ExitsAfter(Duration::from_secs(29), 0));
    let (_, seen) = fixture.run(&Line::new(Interpreter::Bash));
    assert_eq!(seen.names(), ["started"]);
}

// NFR-REL-08: if `knsh-exec` cannot apply the profile, the line never ran: the spawn is a failure, never the line's
// exit code, and it is logged. A profile file that cannot be written starts nothing at all.
#[test]
fn refuses_to_run_when_profile_application_fails() {
    let fixture = fixture(Behaviour::FailsSetup(66));
    let (report, seen) = fixture.run(&Line::new(Interpreter::Bash));
    assert_eq!(report.outcome, Err(SpawnFailure::Trampoline(66)));
    assert!(report.sandbox_profile.is_some());
    // It was spawned, so `command.started` went out; the record then says it did not run (no exit code).
    assert_eq!(seen.names(), ["started"]);
    let entries = fixture.log.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].message, "agent line not run");

    let fixture = self::fixture(exits(0));
    fixture.fs.inject_fault(Operation::Rename, 28);
    let (report, seen) = fixture.run(&Line::new(Interpreter::Bash));
    assert_eq!(report.outcome, Err(SpawnFailure::ProfileFile));
    assert_eq!(fixture.processes.state().spawned, []);
    assert_eq!(seen.names(), [""; 0]);

    // A line that exits 66 itself is just that.
    let fixture = self::fixture(exits(66));
    let (report, _) = fixture.run(&Line::new(Interpreter::Bash));
    assert_eq!(ran(&report).status, LineStatus::Exited(66));
}

// `knsh-exec` refuses an empty `--line` with a usage error it cannot report on the status pipe; an empty line is
// run as `:`, which, like `bash -c ''`, runs nothing and exits 0.
#[test]
fn runs_an_empty_line_as_a_no_op() {
    let fixture = fixture(exits(0));
    let mut line = Line::new(Interpreter::Bash);
    line.executed = String::new();
    let (report, _) = fixture.run(&line);
    assert_eq!(ran(&report).status, LineStatus::Exited(0));
    assert_eq!(option(&fixture.request(), "--line").unwrap(), ":");
}

// NFR-REL-08: the status pipe is read to a byte or end of file; a read that fails reports the line as not run.
#[test]
fn status_read_failure_is_not_a_run() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(5))
        }
    }
    assert_eq!(read_status(&mut &[][..]), Ok(None));
    assert_eq!(read_status(&mut &[71u8][..]), Ok(Some(71)));
    assert!(matches!(
        read_status(&mut Failing),
        Err(PlatformError::Os {
            operation: Operation::Wait,
            errno: 5
        })
    ));
}

// FR-LC-13: the caller's three descriptors are the child's stdio.
#[test]
fn passes_the_callers_descriptors() {
    let fixture = fixture(exits(0));
    let line = Line::new(Interpreter::Sh);
    let (_read, write) = std::io::pipe().unwrap();
    let write = std::os::fd::OwnedFd::from(write);
    let raw = write.as_raw_fd();
    let stdio = LineStdio {
        stdin: write.try_clone().unwrap(),
        stdout: write,
        stderr: std::fs::File::open("/dev/null").unwrap().into(),
    };
    let report = fixture.spawner.run(line.to_run(Some(stdio)), &Seen::default());
    assert!(report.outcome.is_ok());
    match &fixture.request().stdio {
        Stdio::Passed(fds) => assert_eq!(fds[1].as_raw_fd(), raw),
        other => panic!("{other:?}"),
    }
}

// FR-LC-15: the line's profile allows exec only of what the line resolved to, besides trusted and system folders.
#[test]
fn resolved_binaries_are_the_lines_programs() {
    let fixture = fixture(exits(0));
    let mut line = Line::new(Interpreter::Bash);
    line.binaries = vec![CanonicalPath::new("/Users/u/app/bin/tool").unwrap()];
    fixture.run(&line);
    let seen = String::from_utf8(fixture.processes.state().profile_seen.clone().unwrap()).unwrap();
    assert!(seen.contains(r#"(literal "/Users/u/app/bin/tool")"#), "{seen}");
    assert!(!seen.contains(r#"(literal "/usr/bin/git")"#), "{seen}");
}

#[test]
fn signal_status_outside_the_shell_range_is_refused() {
    assert_eq!(line_status(ExitStatus::Exited(0)), Some(LineStatus::Exited(0)));
    assert_eq!(line_status(ExitStatus::Exited(256)), None);
    assert_eq!(line_status(ExitStatus::Signalled(9)), Some(LineStatus::Signalled(9)));
    assert_eq!(line_status(ExitStatus::Signalled(0)), None);
}

/// Against the real `knsh-exec` and `sandbox-exec` on this machine.
mod platform {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    use knsh_platform::macos::{RealFs, SystemClock, SystemProcesses, effective_uid, sha256};

    use super::*;

    /// The `knsh-exec` built beside this test binary (`target/<profile>/knsh-exec`), or `None` when only this crate
    /// was built.
    fn trampoline() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let path = exe.parent()?.parent()?.join("knsh-exec");
        path.is_file().then_some(path)
    }

    /// A private, canonical temporary directory, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("knshd-spawn-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(std::fs::canonicalize(&dir).unwrap())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The real spawner, its profiles in `scratch/profiles`.
    fn spawner(scratch: &Scratch, trampoline: PathBuf) -> TrampolineSpawner {
        let profiles = scratch.0.join("profiles");
        std::fs::create_dir(&profiles).unwrap();
        std::fs::set_permissions(&profiles, std::fs::Permissions::from_mode(0o700)).unwrap();
        let home = std::fs::canonicalize(std::env::var_os("HOME").unwrap()).unwrap();
        TrampolineSpawner {
            processes: Arc::new(SystemProcesses::new()),
            clock: Arc::new(SystemClock::new()),
            files: ProfileFiles::new(Arc::new(RealFs::new()), profiles, effective_uid(), sha256),
            log: Arc::new(RecordingLog::new()),
            trampoline,
            home: CanonicalPath::new(home).unwrap(),
            limits: Limits::DEFAULT,
        }
    }

    /// A profile writing only to `scratch/work`, its default read and exec rules otherwise.
    fn scratch_profile(scratch: &Scratch) -> Profile {
        let work = scratch.0.join("work");
        std::fs::create_dir(&work).unwrap();
        let context = PathContext {
            home: PathBuf::from(HOME),
            tmpdir: PathBuf::from("/private/tmp"),
            start_dir: work.clone(),
        };
        let text = format!("name = \"it\"\n[fs]\nwrite = [\"{}\"]\n", work.display());
        load_profile_text(text.as_bytes(), &NoParents, &context, &Canonical).unwrap()
    }

    /// Runs `executed` under `profile`, its stdout to a pipe; returns the report and what it printed.
    fn run(
        spawner: &TrampolineSpawner,
        profile: &Profile,
        executed: &str,
        timeout: Option<Duration>,
    ) -> (SpawnReport, String) {
        let (mut read, write) = std::io::pipe().unwrap();
        let null = || std::os::fd::OwnedFd::from(std::fs::File::open("/dev/null").unwrap());
        let stdio = LineStdio {
            stdin: null(),
            stdout: write.into(),
            stderr: null(),
        };
        let cwd = CanonicalPath::new(std::fs::canonicalize("/tmp").unwrap()).unwrap();
        let line = LineToRun {
            record_id: RecordId::from_ulid(Ulid::from_u128(7)),
            session_id: SessionId::from_ulid(Ulid::from_u128(3)),
            profile,
            executed,
            binaries: &[],
            interpreter: Interpreter::Bash,
            args: &[],
            env: &[("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
            cwd: &cwd,
            stdio: Some(stdio),
            timeout,
            capture: None,
            control: &LineControl::default(),
        };
        let report = spawner.run(line, &Seen::default());
        let mut out = String::new();
        read.read_to_string(&mut out).unwrap();
        (report, out)
    }

    /// Runs `executed` with its output captured (no passed stdio), as `exec.run` from an agent does.
    fn run_captured(
        spawner: &TrampolineSpawner,
        profile: &Profile,
        executed: &str,
        control: &LineControl,
    ) -> SpawnReport {
        let cwd = CanonicalPath::new(std::fs::canonicalize("/tmp").unwrap()).unwrap();
        let line = LineToRun {
            record_id: RecordId::from_ulid(Ulid::from_u128(7)),
            session_id: SessionId::from_ulid(Ulid::from_u128(3)),
            profile,
            executed,
            binaries: &[],
            interpreter: Interpreter::Bash,
            args: &[],
            env: &[("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
            cwd: &cwd,
            stdio: None,
            timeout: None,
            capture: Some(super::capture_plan(knsh_core::DEFAULT_OUTPUT_CAP)),
            control,
        };
        spawner.run(line, &Seen::default())
    }

    macro_rules! require_trampoline {
        () => {
            match trampoline() {
                Some(path) => path,
                None => {
                    eprintln!("knsh-exec is not built beside this test: run `cargo test --workspace`; skipped");
                    return;
                }
            }
        };
    }

    // FR-LC-40: `sleep 100` with `timeout_s = 1` is killed, and no process of its group survives.
    #[test]
    fn sleep_is_killed_at_its_timeout_with_its_whole_group() {
        let trampoline = require_trampoline!();
        let scratch = Scratch::new("timeout");
        let spawner = spawner(&scratch, trampoline);
        let profile = scratch_profile(&scratch);
        // A marker no other process has, so survivors can be looked for by their arguments.
        let marker = format!("100.{}", std::process::id());
        let started = std::time::Instant::now();
        let (report, _) = run(
            &spawner,
            &profile,
            &format!("/bin/sleep {marker} & /bin/sleep {marker}; wait"),
            Some(Duration::from_secs(1)),
        );
        let outcome = ran(&report);
        assert!(outcome.timed_out, "{report:?}");
        assert!(matches!(outcome.status, LineStatus::Signalled(_)), "{outcome:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
        let survivors = Command::new("/usr/bin/pgrep")
            .args(["-f", &format!("sleep {marker}")])
            .output()
            .unwrap();
        assert_eq!(
            survivors.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&survivors.stdout)
        );
    }

    // FR-LC-15, FR-SBX-04: a binary placed in an untrusted folder after classification (so not in the line's
    // resolved binaries) cannot be executed under the line's profile, while a trusted one can.
    #[test]
    fn swapped_binary_in_untrusted_folder_fails_to_exec() {
        let trampoline = require_trampoline!();
        let scratch = Scratch::new("swap");
        let spawner = spawner(&scratch, trampoline);
        let profile = scratch_profile(&scratch);
        let untrusted = scratch.0.join("untrusted");
        std::fs::create_dir(&untrusted).unwrap();
        let tool = untrusted.join("tool");
        std::fs::copy("/usr/bin/true", &tool).unwrap();
        // Control: outside the sandbox the copy runs.
        assert!(Command::new(&tool).status().unwrap().success());
        let (report, out) = run(
            &spawner,
            &profile,
            &format!("/usr/bin/true; echo trusted=$?; {}; echo swapped=$?", tool.display()),
            None,
        );
        assert_eq!(ran(&report).status, LineStatus::Exited(0), "{report:?}");
        assert_eq!(out, "trusted=0\nswapped=126\n");
        assert!(report.sandbox_profile.unwrap().starts_with("it@"));
    }

    // NFR-REL-08: a trampoline that cannot be started never runs the line; the spawn is reported as not run.
    #[test]
    fn missing_trampoline_reports_not_run() {
        let scratch = Scratch::new("notrun");
        let spawner = spawner(&scratch, PathBuf::from("/nonexistent/knsh-exec"));
        let profile = scratch_profile(&scratch);
        let (report, out) = run(&spawner, &profile, "echo ran", None);
        assert!(matches!(report.outcome, Err(SpawnFailure::Start(_))), "{report:?}");
        assert_eq!(out, "");
    }

    // KNSH-053: a real line under `knsh-exec`: stdout and stderr captured apart, stdin is /dev/null.
    #[test]
    fn captures_stdout_and_stderr_of_a_real_line() {
        let trampoline = require_trampoline!();
        let scratch = Scratch::new("capture");
        let spawner = spawner(&scratch, trampoline);
        let profile = scratch_profile(&scratch);
        let report = run_captured(
            &spawner,
            &profile,
            "echo out; echo err >&2; /bin/cat; exit 3",
            &LineControl::default(),
        );
        assert_eq!(ran(&report).status, LineStatus::Exited(3), "{report:?}");
        let output = report.output.unwrap();
        assert_eq!(output.stdout.output.data().expose(), b"out\n");
        assert_eq!(output.stderr.output.data().expose(), b"err\n");
    }

    // exec.kill: a real group (`sleep & sleep; wait`) is stopped as a whole, and nothing of it survives.
    #[test]
    fn kill_stops_a_real_group() {
        let trampoline = require_trampoline!();
        let scratch = Scratch::new("kill");
        let spawner = Arc::new(spawner(&scratch, trampoline));
        let profile = scratch_profile(&scratch);
        let marker = format!("101.{}", std::process::id());
        let control = Arc::new(LineControl::default());
        let killer = {
            let control = Arc::clone(&control);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(500));
                control.request_kill()
            })
        };
        let started = std::time::Instant::now();
        let report = run_captured(
            &spawner,
            &profile,
            &format!("/bin/sleep {marker} & /bin/sleep {marker}; wait"),
            &control,
        );
        assert!(killer.join().unwrap(), "it was running");
        let outcome = ran(&report);
        assert!(!outcome.timed_out);
        assert!(matches!(outcome.status, LineStatus::Signalled(_)), "{outcome:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
        let survivors = Command::new("/usr/bin/pgrep")
            .args(["-f", &format!("sleep {marker}")])
            .output()
            .unwrap();
        assert_eq!(survivors.status.code(), Some(1));
    }
}
