//! Forwarding a recorded human session's telemetry to `knshd` (KNSH-021, FR-SES-21, FR-SES-24, FR-REC-09,
//! NFR-REL-02).
//!
//! # Shape
//!
//! The hosted shell's hooks write lines into a pipe; `knsh`'s forwarder thread decodes them and hands them to a
//! [`ChannelSink`], which stamps each line on receipt and queues it, never waiting. A worker thread
//! ([`RecordingHandle`]) takes them off the queue and drives the [`Recorder`], the only part that talks to `knshd`
//! (through a [`Connector`] and the [`DaemonLink`] it returns). So the shell never waits for `knshd`: a slow or
//! absent daemon only fills the queue, whose overflow is dropped (NFR-REL-02).
//!
//! # What is sent
//!
//! On the first line delivery, after the shell has started, the recorder connects to `user.sock` and starts a human
//! session (`session.start_human`). Connecting only then keeps the connection's descriptor out of the shell, whose
//! spawn might otherwise race with it. Then, for each command line:
//!
//! - when the prompt comes back, `telemetry.command` with `command`, `cwd`, `started_at`, `ended_at` and `exit_code`
//!   only (FR-REC-09);
//! - `telemetry.cwd` when the working directory is not the one last seen (at the start of a line or when it ends);
//! - `telemetry.idle` once the prompt has waited [`IDLE_AFTER`] without a new command line, and again only after the
//!   next one (FR-SES-24). The prompt counts as shown when the session starts and after each command line.
//!
//! The session ends when the link is dropped (the connection closes): `knshd` publishes `session.ended`.
//!
//! # Failures
//!
//! Every failure is silent (NFR-REL-02). A call that fails drops the link, and the telemetry with it; a new session is
//! tried at the next command line, at most once per [`RECONNECT_INTERVAL`]. A line that cannot be represented (a
//! command over [`MAX_TELEMETRY_COMMAND_LEN`] bytes, a working directory that is not absolute and resolved) is not
//! recorded. Bytes that are not UTF-8 are sent as U+FFFD.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use knsh_core::{CanonicalPath, Timestamp};
use knsh_platform::{Clock, Monotonic};
use knsh_proto::{MAX_TELEMETRY_COMMAND_LEN, MAX_TELEMETRY_CWD_LEN, TelemetryCommandParams};

use super::host::{Flow, TelemetrySink};
use super::telemetry::TelemetryLine;

/// How long a prompt waits for input before `session.idle` (FR-SES-24, `specs/09-reference/defaults-and-limits.md`).
pub const IDLE_AFTER: Duration = Duration::from_secs(5);

/// The least time between two attempts to reach `knshd` after a failure.
pub const RECONNECT_INTERVAL: Duration = Duration::from_secs(30);

/// Lines queued between the forwarder and the worker. Beyond it, lines are dropped rather than waited for.
const QUEUE_LEN: usize = 1024;

/// A link to `knshd` failed. Never shown to the user: the telemetry is dropped (NFR-REL-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkError;

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("knshd unreachable")
    }
}

impl std::error::Error for LinkError {}

/// A human session in `knshd`. Dropping it closes the connection, which ends the session (`session.ended`).
pub trait DaemonLink: Send {
    /// `telemetry.command`: one finished command line.
    ///
    /// # Errors
    ///
    /// [`LinkError`] if the call failed; the link is then dropped.
    fn command(&mut self, command: &TelemetryCommandParams) -> Result<(), LinkError>;

    /// `telemetry.cwd`: the working directory changed.
    ///
    /// # Errors
    ///
    /// As [`DaemonLink::command`].
    fn cwd_changed(&mut self, cwd: &CanonicalPath) -> Result<(), LinkError>;

    /// `telemetry.idle`: the prompt has waited [`IDLE_AFTER`].
    ///
    /// # Errors
    ///
    /// As [`DaemonLink::command`].
    fn idle(&mut self) -> Result<(), LinkError>;
}

/// Opens [`DaemonLink`]s: connects to `user.sock` and starts a human session.
pub trait Connector: Send {
    /// Connects and starts a session.
    ///
    /// # Errors
    ///
    /// [`LinkError`] if `knshd` cannot be reached or refuses the session.
    fn connect(&mut self) -> Result<Box<dyn DaemonLink>, LinkError>;
}

/// The command line now running.
#[derive(Debug)]
struct Running {
    command: Vec<u8>,
    cwd: Vec<u8>,
    started_at: Timestamp,
}

/// The telemetry state machine of one recorded session. Single-threaded; the [`RecordingHandle`] worker owns it.
pub struct Recorder<C: Connector> {
    connector: C,
    clock: Arc<dyn Clock>,
    link: Option<Box<dyn DaemonLink>>,
    /// When `knshd` was last tried and could not be reached; `None` once it has been.
    failed_at: Option<Monotonic>,
    /// Whether the first connection has been tried: before that, nothing may connect (see the module docs).
    started: bool,
    running: Option<Running>,
    /// The working directory last seen.
    cwd: Option<Vec<u8>>,
    /// When `session.idle` is due; `None` while a command runs or once it was sent for this prompt.
    idle_due: Option<Monotonic>,
}

impl<C: Connector> Recorder<C> {
    /// A recorder that will connect with `connector`. `cwd` is the shell's starting directory, if known: a change
    /// from it is reported. Nothing connects before [`Recorder::start`].
    pub fn new(connector: C, clock: Arc<dyn Clock>, cwd: Option<Vec<u8>>) -> Self {
        Self {
            connector,
            clock,
            link: None,
            failed_at: None,
            started: false,
            running: None,
            cwd,
            idle_due: None,
        }
    }

    /// The shell has started: connect and start the session, and wait for the first prompt to go idle.
    pub fn start(&mut self) {
        if self.started {
            return;
        }
        self.started = true;
        self.arm_idle();
        self.ensure_link();
    }

    /// Handles one telemetry line received at `at`.
    pub fn line(&mut self, line: TelemetryLine, at: Timestamp) {
        match line {
            TelemetryLine::CommandStarted { cwd, command } => {
                self.idle_due = None;
                self.observe_cwd(&cwd);
                self.running = Some(Running {
                    command,
                    cwd,
                    started_at: at,
                });
            }
            TelemetryLine::CommandFinished { exit_code, cwd } => {
                if let Some(running) = self.running.take()
                    && let Some(params) = command_params(&running, at, exit_code)
                {
                    self.send(|link| link.command(&params));
                }
                self.observe_cwd(&cwd);
                self.arm_idle();
            }
        }
    }

    /// When [`Recorder::tick`] must next run, on the clock's monotonic time.
    #[must_use]
    pub const fn deadline(&self) -> Option<Monotonic> {
        self.idle_due
    }

    /// Sends `session.idle` if the prompt has waited long enough. Only once per prompt (FR-SES-24).
    pub fn tick(&mut self) {
        if let Some(due) = self.idle_due
            && self.clock.monotonic() >= due
        {
            self.idle_due = None;
            // Only to a session that exists: idle alone never reconnects.
            if self.link.is_some() {
                self.send(|link| link.idle());
            }
        }
    }

    /// Whether a session is open in `knshd` now.
    #[must_use]
    pub fn is_linked(&self) -> bool {
        self.link.is_some()
    }

    /// Ends the session, if any, by dropping the link.
    pub fn finish(&mut self) {
        self.link = None;
    }

    fn arm_idle(&mut self) {
        self.idle_due = self.clock.monotonic().checked_add(IDLE_AFTER);
    }

    /// Reports `cwd` if it differs from the directory last seen, then remembers it. A directory that is not
    /// canonical cannot be reported and is not remembered either, so it never causes a change of its own.
    fn observe_cwd(&mut self, cwd: &[u8]) {
        if self.cwd.as_deref() == Some(cwd) {
            return;
        }
        let Some(path) = canonical(cwd) else {
            return;
        };
        if self.cwd.replace(cwd.to_vec()).is_some() {
            self.send(|link| link.cwd_changed(&path));
        }
    }

    /// Runs `call` on the link, connecting first if allowed. A failure drops the link.
    fn send(&mut self, call: impl FnOnce(&mut dyn DaemonLink) -> Result<(), LinkError>) {
        self.ensure_link();
        let Some(link) = self.link.as_mut() else {
            return;
        };
        if call(link.as_mut()).is_err() {
            self.link = None;
            self.failed_at = Some(self.clock.monotonic());
        }
    }

    /// Connects unless linked, not started yet, or a recent attempt failed ([`RECONNECT_INTERVAL`]).
    fn ensure_link(&mut self) {
        if self.link.is_some() || !self.started {
            return;
        }
        let now = self.clock.monotonic();
        if let Some(failed_at) = self.failed_at
            && now.saturating_duration_since(failed_at) < RECONNECT_INTERVAL
        {
            return;
        }
        match self.connector.connect() {
            Ok(link) => {
                self.link = Some(link);
                self.failed_at = None;
            }
            Err(LinkError) => self.failed_at = Some(now),
        }
    }
}

/// The `telemetry.command` parameters of a finished line, or `None` if it cannot be recorded.
fn command_params(running: &Running, ended_at: Timestamp, exit_code: u8) -> Option<TelemetryCommandParams> {
    if running.command.len() > MAX_TELEMETRY_COMMAND_LEN {
        return None;
    }
    let command = String::from_utf8_lossy(&running.command).into_owned();
    if command.len() > MAX_TELEMETRY_COMMAND_LEN {
        // U+FFFD takes three bytes where one invalid byte stood.
        return None;
    }
    Some(TelemetryCommandParams {
        command,
        cwd: canonical(&running.cwd)?,
        started_at: running.started_at,
        // The stamps come from the wall clock, which may step back between the two lines.
        ended_at: ended_at.max(running.started_at),
        exit_code,
    })
}

/// `$PWD` as a canonical path, or `None` if it is not absolute and free of `.`, `..` and `//`.
fn canonical(cwd: &[u8]) -> Option<CanonicalPath> {
    // `knshd` refuses a longer one with `-32602`, which would drop the link and end the session for one bad line.
    let text = String::from_utf8_lossy(cwd);
    if text.len() > MAX_TELEMETRY_CWD_LEN {
        return None;
    }
    CanonicalPath::new(text.into_owned()).ok()
}

/// What the forwarder hands the worker.
enum Message {
    /// The shell has started (the forwarder runs).
    Start,
    /// A line and when it was received.
    Line(TelemetryLine, Timestamp),
    /// The shell has exited: send what is queued, then end the session.
    Stop,
}

/// The [`TelemetrySink`] of a recorded session: stamps each line on receipt and queues it for the worker without
/// waiting. A full queue drops the line (NFR-REL-02).
pub struct ChannelSink {
    sender: SyncSender<Message>,
    clock: Arc<dyn Clock>,
}

impl TelemetrySink for ChannelSink {
    fn started(&mut self) {
        let _ = self.sender.try_send(Message::Start);
    }

    fn deliver(&mut self, line: TelemetryLine) -> Flow {
        let Ok(at) = self.clock.now() else {
            return Flow::Continue;
        };
        match self.sender.try_send(Message::Line(line, at)) {
            Ok(()) | Err(TrySendError::Full(_)) => Flow::Continue,
            // The worker is gone: nothing will ever be sent again.
            Err(TrySendError::Disconnected(_)) => Flow::Stop,
        }
    }
}

/// The worker thread of a recorded session and the queue into it.
pub struct RecordingHandle {
    sender: SyncSender<Message>,
    clock: Arc<dyn Clock>,
    stopping: Arc<AtomicBool>,
    worker: JoinHandle<()>,
}

impl RecordingHandle {
    /// Starts the worker thread, which owns `recorder`.
    ///
    /// # Errors
    ///
    /// The [`std::io::Error`] of a thread that could not be started. The caller then runs the shell unrecorded.
    pub fn spawn<C: Connector + 'static>(recorder: Recorder<C>) -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_LEN);
        let clock = Arc::clone(&recorder.clock);
        let stopping = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stopping);
        let worker = thread::Builder::new()
            .name("knsh-telemetry".to_owned())
            .spawn(move || work(recorder, &receiver, &flag))?;
        Ok(Self {
            sender,
            clock,
            stopping,
            worker,
        })
    }

    /// The sink for the forwarder.
    #[must_use]
    pub fn sink(&self) -> Box<dyn TelemetrySink> {
        Box::new(ChannelSink {
            sender: self.sender.clone(),
            clock: Arc::clone(&self.clock),
        })
    }

    /// The shell has exited: lets the worker send what is queued and end the session, waiting at most `bound`.
    /// A worker still busy then is left behind; the connection closes when `knsh` exits, which ends the session too.
    pub fn finish(self, bound: Duration) {
        self.stopping.store(true, Ordering::Release);
        // Wakes a worker waiting for a line. If the queue is full the worker is busy and sees the flag after the
        // message in hand.
        let _ = self.sender.try_send(Message::Stop);
        drop(self.sender);
        let deadline = Instant::now() + bound;
        while !self.worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if self.worker.is_finished() {
            let _ = self.worker.join();
        }
    }
}

/// Starts recording a human session if `recording` is on, and returns its handle; `None` when it is off or the worker
/// cannot start, and the shell then runs unrecorded. With recording off `connector` is never built, so `knshd` is
/// never contacted and never started (FR-SES-23).
pub fn start_recording<C: Connector + 'static>(
    recording: bool,
    connector: impl FnOnce() -> C,
    clock: Arc<dyn Clock>,
    cwd: Option<Vec<u8>>,
) -> Option<RecordingHandle> {
    if !recording {
        return None;
    }
    RecordingHandle::spawn(Recorder::new(connector(), clock, cwd)).ok()
}

/// The worker loop: feeds the recorder until stopped, waking for the idle deadline.
fn work<C: Connector>(mut recorder: Recorder<C>, receiver: &Receiver<Message>, stopping: &AtomicBool) {
    loop {
        let message = match recorder.deadline() {
            Some(due) => {
                let wait = due.saturating_duration_since(recorder.clock.monotonic());
                receiver.recv_timeout(wait)
            }
            None => receiver.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match message {
            Ok(Message::Start) => recorder.start(),
            Ok(Message::Line(line, at)) => recorder.line(line, at),
            Err(RecvTimeoutError::Timeout) => recorder.tick(),
            Ok(Message::Stop) | Err(RecvTimeoutError::Disconnected) => break,
        }
        if stopping.load(Ordering::Acquire) {
            break;
        }
    }
    // Lines still queued when the shell exited are the last command lines: send them before ending the session.
    while let Ok(message) = receiver.try_recv() {
        match message {
            Message::Line(line, at) => recorder.line(line, at),
            Message::Start | Message::Stop => {}
        }
    }
    recorder.finish();
}

/// The [`Connector`] of a real session: `user.sock` at `socket`.
pub struct UserSocketConnector {
    socket: std::path::PathBuf,
}

impl UserSocketConnector {
    /// How long the handshake and `session.start_human` may take: `knshd` may be starting on demand (its capability
    /// probe alone may take 2 s). Only the worker waits; the shell never does.
    const START_TIMEOUT: Duration = Duration::from_secs(5);
    /// How long each telemetry call may take once the session runs.
    const CALL_TIMEOUT: Duration = Duration::from_secs(1);

    /// Connects to the `user.sock` at `socket`.
    #[must_use]
    pub const fn new(socket: std::path::PathBuf) -> Self {
        Self { socket }
    }
}

impl Connector for UserSocketConnector {
    fn connect(&mut self) -> Result<Box<dyn DaemonLink>, LinkError> {
        use std::os::unix::net::UnixStream;

        use knsh_json::FromJson;
        use knsh_proto::{SessionStartHumanParams, SessionStartHumanResult};

        use crate::cli::client::Client;

        let stream = UnixStream::connect(&self.socket).map_err(|_| LinkError)?;
        let timeouts = |stream: &UnixStream, timeout: Duration| {
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))
        };
        timeouts(&stream, Self::START_TIMEOUT).map_err(|_| LinkError)?;
        let reader = stream.try_clone().map_err(|_| LinkError)?;
        let mut client = Client::new(reader, stream.try_clone().map_err(|_| LinkError)?);
        client.hello().map_err(|_| LinkError)?;
        let params = params_object(&SessionStartHumanParams)?;
        let result = client
            .call("session.start_human", Some(params))
            .map_err(|_| LinkError)?;
        let started = SessionStartHumanResult::from_json(&result).map_err(|_| LinkError)?;
        if !started.recording {
            return Err(LinkError);
        }
        timeouts(&stream, Self::CALL_TIMEOUT).map_err(|_| LinkError)?;
        Ok(Box::new(UserSocketLink { client }))
    }
}

/// A params object for a call.
fn params_object(params: &impl knsh_json::ToJson) -> Result<knsh_json::Object, LinkError> {
    match params.to_json() {
        Ok(knsh_json::Value::Object(object)) => Ok(object),
        Ok(_) | Err(_) => Err(LinkError),
    }
}

/// A human session over a `user.sock` connection.
struct UserSocketLink {
    client: crate::cli::client::Client<std::os::unix::net::UnixStream, std::os::unix::net::UnixStream>,
}

impl UserSocketLink {
    fn call(&mut self, method: &str, params: &impl knsh_json::ToJson) -> Result<(), LinkError> {
        let params = params_object(params)?;
        self.client
            .call(method, Some(params))
            .map(|_| ())
            .map_err(|_| LinkError)
    }
}

impl DaemonLink for UserSocketLink {
    fn command(&mut self, command: &TelemetryCommandParams) -> Result<(), LinkError> {
        self.call("telemetry.command", command)
    }

    fn cwd_changed(&mut self, cwd: &CanonicalPath) -> Result<(), LinkError> {
        self.call("telemetry.cwd", &knsh_proto::TelemetryCwdParams { cwd: cwd.clone() })
    }

    fn idle(&mut self) -> Result<(), LinkError> {
        self.call("telemetry.idle", &knsh_proto::TelemetryIdleParams)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use knsh_platform::testing::FakeClock;

    use super::*;

    /// A [`Connector`] and links that record every call, for tests. Shared state, so a test can look while the worker
    /// owns the connector.
    #[derive(Debug, Default, Clone)]
    struct FakeDaemon {
        state: Arc<Mutex<FakeState>>,
    }

    /// What a [`FakeDaemon`] saw.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    struct FakeState {
        /// Connection attempts, successful or not.
        connects: usize,
        /// Sessions ended (links dropped).
        ended: usize,
        /// Calls in order: `command <cmd>`, `cwd <path>`, `idle`.
        calls: Vec<String>,
        /// The commands received, in order.
        commands: Vec<TelemetryCommandParams>,
        /// Whether `knshd` is reachable: connections and calls fail while `false`.
        down: bool,
    }

    impl FakeDaemon {
        /// A reachable fake daemon.
        #[must_use]
        fn new() -> Self {
            Self::default()
        }

        /// A copy of what it saw so far.
        #[must_use]
        fn state(&self) -> FakeState {
            self.lock().clone()
        }

        /// Makes it unreachable (`true`) or reachable again.
        fn set_down(&self, down: bool) {
            self.lock().down = down;
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    impl Connector for FakeDaemon {
        fn connect(&mut self) -> Result<Box<dyn DaemonLink>, LinkError> {
            let mut state = self.lock();
            state.connects += 1;
            if state.down {
                return Err(LinkError);
            }
            Ok(Box::new(FakeLink { daemon: self.clone() }))
        }
    }

    /// A link of a [`FakeDaemon`].
    struct FakeLink {
        daemon: FakeDaemon,
    }

    impl FakeLink {
        fn record(&self, call: String, command: Option<&TelemetryCommandParams>) -> Result<(), LinkError> {
            let mut state = self.daemon.lock();
            if state.down {
                return Err(LinkError);
            }
            state.calls.push(call);
            state.commands.extend(command.cloned());
            Ok(())
        }
    }

    impl DaemonLink for FakeLink {
        fn command(&mut self, command: &TelemetryCommandParams) -> Result<(), LinkError> {
            self.record(format!("command {}", command.command), Some(command))
        }

        fn cwd_changed(&mut self, cwd: &CanonicalPath) -> Result<(), LinkError> {
            self.record(format!("cwd {}", cwd.as_path().display()), None)
        }

        fn idle(&mut self) -> Result<(), LinkError> {
            self.record("idle".to_owned(), None)
        }
    }

    impl Drop for FakeLink {
        fn drop(&mut self) {
            self.daemon.lock().ended += 1;
        }
    }

    fn clock() -> Arc<FakeClock> {
        Arc::new(FakeClock::new(
            Timestamp::from_unix_micros(1_800_000_000_000_000).expect("time"),
        ))
    }

    fn started(cwd: &str, command: &str) -> TelemetryLine {
        TelemetryLine::CommandStarted {
            cwd: cwd.as_bytes().to_vec(),
            command: command.as_bytes().to_vec(),
        }
    }

    fn finished(exit_code: u8, cwd: &str) -> TelemetryLine {
        TelemetryLine::CommandFinished {
            exit_code,
            cwd: cwd.as_bytes().to_vec(),
        }
    }

    fn recorder(daemon: &FakeDaemon, clock: &Arc<FakeClock>) -> Recorder<FakeDaemon> {
        let mut recorder = Recorder::new(daemon.clone(), clock.clone(), Some(b"/home".to_vec()));
        recorder.start();
        recorder
    }

    /// Feeds `line` stamped with the clock's current time.
    fn feed(recorder: &mut Recorder<FakeDaemon>, clock: &FakeClock, line: TelemetryLine) {
        recorder.line(line, clock.now().expect("now"));
    }

    // KNSH-021 (FR-REC-09): each typed line becomes one record with command, cwd, times and exit code only; a `cd`
    // is reported as `cwd.changed` after its own record.
    #[test]
    fn record_contains_only_telemetry_fields() {
        let (daemon, clock) = (FakeDaemon::new(), clock());
        let mut recorder = recorder(&daemon, &clock);
        feed(&mut recorder, &clock, started("/home", "cd /tmp"));
        clock.advance(Duration::from_millis(1500));
        feed(&mut recorder, &clock, finished(0, "/tmp"));
        feed(&mut recorder, &clock, started("/tmp", "false"));
        feed(&mut recorder, &clock, finished(1, "/tmp"));
        let state = daemon.state();
        assert_eq!(state.connects, 1);
        assert_eq!(state.calls, ["command cd /tmp", "cwd /tmp", "command false"]);
        // The params type has exactly these five fields; the values are the line's own.
        let TelemetryCommandParams {
            command,
            cwd,
            started_at,
            ended_at,
            exit_code,
        } = &state.commands[0];
        assert_eq!(command, "cd /tmp");
        assert_eq!(cwd.as_path(), std::path::Path::new("/home"));
        assert_eq!(ended_at.as_unix_micros() - started_at.as_unix_micros(), 1_500_000);
        assert_eq!(*exit_code, 0);
        assert_eq!(state.commands[1].exit_code, 1);
    }

    // KNSH-021 (FR-SES-24), fake clock: `session.idle` once the prompt has waited 5 s, never twice for one prompt,
    // and again only after a new command line.
    #[test]
    fn idle_emitted_once_after_5_seconds() {
        let (daemon, clock) = (FakeDaemon::new(), clock());
        let mut recorder = recorder(&daemon, &clock);
        let idles = |daemon: &FakeDaemon| daemon.state().calls.iter().filter(|c| *c == "idle").count();

        clock.advance(Duration::from_millis(4_999));
        recorder.tick();
        assert_eq!(idles(&daemon), 0, "not yet 5 s");
        clock.advance(Duration::from_millis(1));
        recorder.tick();
        assert_eq!(idles(&daemon), 1);
        clock.advance(IDLE_AFTER * 10);
        recorder.tick();
        assert_eq!(idles(&daemon), 1, "once per prompt");
        assert_eq!(recorder.deadline(), None);

        // A command that runs for a long time is not an idle prompt.
        feed(&mut recorder, &clock, started("/home", "sleep 60"));
        clock.advance(IDLE_AFTER * 2);
        recorder.tick();
        assert_eq!(idles(&daemon), 1);
        feed(&mut recorder, &clock, finished(0, "/home"));
        clock.advance(IDLE_AFTER);
        recorder.tick();
        assert_eq!(idles(&daemon), 2, "again after a new command");
    }

    // KNSH-021 (NFR-REL-02): an unreachable daemon drops telemetry; lines never wait, reconnects are rate-limited,
    // and recording resumes in a new session once it is back.
    #[test]
    fn unreachable_daemon_drops_telemetry_without_blocking() {
        let (daemon, clock) = (FakeDaemon::new(), clock());
        daemon.set_down(true);
        let mut recorder = recorder(&daemon, &clock);
        assert!(!recorder.is_linked());
        for _ in 0..5 {
            feed(&mut recorder, &clock, started("/home", "ls"));
            feed(&mut recorder, &clock, finished(0, "/home"));
        }
        assert_eq!(daemon.state().connects, 1, "no retry before the interval");
        assert_eq!(daemon.state().calls, Vec::<String>::new());

        daemon.set_down(false);
        clock.advance(RECONNECT_INTERVAL);
        feed(&mut recorder, &clock, started("/home", "pwd"));
        feed(&mut recorder, &clock, finished(0, "/home"));
        assert_eq!(daemon.state().calls, ["command pwd"]);

        // It goes away mid-session: the call fails, the link is dropped, and the next lines are dropped too.
        daemon.set_down(true);
        feed(&mut recorder, &clock, started("/home", "lost"));
        feed(&mut recorder, &clock, finished(0, "/home"));
        assert!(!recorder.is_linked());
        assert_eq!(daemon.state().ended, 1);
        assert_eq!(daemon.state().calls, ["command pwd"]);
    }

    // The worker never makes the forwarder wait: with a daemon whose calls block, the sink still returns at once and
    // drops what does not fit.
    #[test]
    fn sink_never_waits_for_the_worker() {
        struct Stuck;
        impl Connector for Stuck {
            fn connect(&mut self) -> Result<Box<dyn DaemonLink>, LinkError> {
                thread::sleep(Duration::from_secs(60));
                Err(LinkError)
            }
        }
        let clock = clock();
        let handle = RecordingHandle::spawn(Recorder::new(Stuck, clock.clone(), None)).expect("spawn");
        let mut sink = handle.sink();
        sink.started();
        let begun = Instant::now();
        for _ in 0..(QUEUE_LEN * 3) {
            assert_eq!(sink.deliver(started("/", "x")), Flow::Continue);
        }
        assert!(begun.elapsed() < Duration::from_secs(2), "{:?}", begun.elapsed());
        let begun = Instant::now();
        handle.finish(Duration::from_millis(100));
        assert!(begun.elapsed() < Duration::from_secs(2));
    }

    // Lines delivered before the shell exits are all sent before the session ends.
    #[test]
    fn finish_sends_queued_lines_then_ends_the_session() {
        let daemon = FakeDaemon::new();
        let handle =
            RecordingHandle::spawn(Recorder::new(daemon.clone(), clock(), Some(b"/".to_vec()))).expect("spawn");
        let mut sink = handle.sink();
        // Nothing connects before the shell has started.
        sink.deliver(started("/", "early"));
        thread::sleep(Duration::from_millis(50));
        assert_eq!(daemon.state().connects, 0);
        sink.started();
        for n in 0..3 {
            sink.deliver(started("/", &format!("cmd{n}")));
            sink.deliver(finished(0, "/"));
        }
        handle.finish(Duration::from_secs(5));
        let state = daemon.state();
        assert_eq!(state.connects, 1);
        assert_eq!(state.calls, ["command cmd0", "command cmd1", "command cmd2"]);
        assert_eq!(state.ended, 1);
    }

    // KNSH-021 (FR-SES-23), fake connector counting attempts: with recording off nothing is started and no
    // connection is ever tried; with it on, exactly one once the shell has started.
    #[test]
    fn recording_off_never_connects() {
        let daemon = FakeDaemon::new();
        let handle = start_recording(false, || daemon.clone(), clock(), None);
        assert!(handle.is_none());
        assert_eq!(daemon.state().connects, 0);

        let handle = start_recording(true, || daemon.clone(), clock(), None).expect("recording on");
        handle.sink().started();
        handle.finish(Duration::from_secs(5));
        assert_eq!(daemon.state().connects, 1);
        assert_eq!(daemon.state().ended, 1);
    }

    // Lines that cannot be represented are not recorded; nothing else is affected.
    #[test]
    fn unrepresentable_lines_are_skipped() {
        let (daemon, clock) = (FakeDaemon::new(), clock());
        let mut recorder = recorder(&daemon, &clock);
        feed(&mut recorder, &clock, started("relative", "ls"));
        feed(&mut recorder, &clock, finished(0, "/home"));
        let long = "x".repeat(MAX_TELEMETRY_COMMAND_LEN + 1);
        feed(&mut recorder, &clock, started("/home", &long));
        feed(&mut recorder, &clock, finished(0, "/home"));
        // A directory knshd would refuse is not sent, so the session is not lost over it.
        let deep = format!("/{}", "d".repeat(MAX_TELEMETRY_CWD_LEN));
        feed(&mut recorder, &clock, started(&deep, "ls"));
        feed(&mut recorder, &clock, finished(0, "/home"));
        assert!(recorder.is_linked());
        recorder.line(
            TelemetryLine::CommandStarted {
                cwd: b"/home".to_vec(),
                command: b"echo \xff".to_vec(),
            },
            clock.now().expect("now"),
        );
        feed(&mut recorder, &clock, finished(0, "/home"));
        assert_eq!(daemon.state().calls, ["command echo \u{fffd}"]);
    }
}
