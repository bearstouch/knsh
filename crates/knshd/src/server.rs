//! The connection server: a kqueue accept loop, one bounded worker thread per connection, idle exit and orderly
//! shutdown (KNSH-013).
//!
//! # Threads
//!
//! - **The accept loop** ([`Server::run`]) is one thread blocked in [`Kqueue::wait`]. It wakes when a listener has a
//!   connection, when a connection closes, when [`StopHandle::stop`] or `SIGTERM` asks it to stop, or when the idle
//!   clock is due. Nothing it does blocks on a client.
//! - **One worker thread per connection** runs [`connection::serve`]. A slow or stuck client (or handler) holds only
//!   its own thread, so it cannot block anyone else. At most [`Config::max_connections`] are open; excess connections
//!   are accepted and closed at once, so the backlog never fills with clients that wait forever.
//!
//! # Lock order
//!
//! There is one lock, [`Shared::registry`] (the open connections). It is never held while calling a handler, the
//! system log or the event queue.
//!
//! # Lifetime
//!
//! `knshd` exits when [`IdleTimer`] expires: no connection is open and [`Activity`] reports no envelope or recording
//! session for [`Config::idle_limit`] on the injected clock. On exit, or on a stop request, the loop stops accepting,
//! lets in-flight requests finish within [`Config::shutdown_grace`], closes every connection, and commits
//! [`PendingWrites`] before returning.
//!
//! # Privacy
//!
//! The system log only accepts static messages and typed values ([`knsh_platform::Value`]), and nothing here logs a
//! message, a method name or a parameter: only endpoint names, counts, `errno` values and fixed reasons.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use knsh_platform::macos::{Kqueue, Token};
use knsh_platform::{Clock, Field, Level, Monotonic, PeerCredentials, PlatformError, SystemLog, Value};

use crate::connection::{self, Closed};
use crate::dispatch::{Dispatcher, Endpoint};
use crate::endpoints::{Listeners, Refusal, admit};
use crate::lifetime::{Activity, CommitFailed, IDLE_LIMIT, Idle, IdleTimer, PendingWrites};

/// Token of the wake-up a closing connection sends, so the idle clock sees the last connection go at once.
const CONNECTION_CLOSED: Token = usize::MAX;
/// Token of a stop request: [`StopHandle::stop`] or a termination signal.
const STOP: Token = usize::MAX - 1;

/// Pause after an accept error that is not about one connection (for example `EMFILE`), so a persistent failure
/// does not spin a core: the listener stays readable and would fire again at once.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Logged in place of an `errno` when a failure carries none. `knshd` may not depend on `libc` (NFR-SUP-02), and 0
/// is never a real `errno`, so it reads unambiguously as "unknown".
const UNKNOWN_ERRNO: i32 = 0;

/// Limits and timings of the server.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Config {
    /// Most connections served at once, over both endpoints. Further connections are closed on accept.
    pub(crate) max_connections: usize,
    /// Idle time before exit (`specs/02-architecture/process-model.md`: 10 minutes).
    pub(crate) idle_limit: Duration,
    /// Longest the accept loop sleeps before it looks at the idle clock and the sessions again.
    pub(crate) tick: Duration,
    /// How long a new connection may take to send its first message. A client that connects and says nothing
    /// would otherwise hold a connection slot forever.
    pub(crate) handshake_timeout: Duration,
    /// How long one write to a client may block. A client that stops reading is disconnected instead of holding
    /// its worker thread forever.
    pub(crate) write_timeout: Duration,
    /// How long shutdown waits for in-flight requests before it closes their connections anyway.
    pub(crate) shutdown_grace: Duration,
}

impl Config {
    /// The production configuration.
    pub(crate) const DEFAULT: Self = Self {
        max_connections: 64,
        idle_limit: IDLE_LIMIT,
        tick: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(10),
        write_timeout: Duration::from_secs(30),
        shutdown_grace: Duration::from_secs(5),
    };
}

/// The effects and services the server needs, shared by every thread.
pub(crate) struct Services {
    /// The per-endpoint dispatch tables.
    pub(crate) dispatcher: Dispatcher,
    /// Who is at the other end of each connection.
    pub(crate) credentials: Arc<dyn PeerCredentials>,
    /// Where refusals and failures are reported. Never receives message content.
    pub(crate) log: Arc<dyn SystemLog>,
    /// The user `knshd` runs as.
    pub(crate) own_uid: u32,
    /// The clock the idle timer reads.
    pub(crate) clock: Arc<dyn Clock>,
    /// Sessions that keep `knshd` alive.
    pub(crate) activity: Arc<dyn Activity>,
    /// Writes committed before exit.
    pub(crate) pending: Arc<dyn PendingWrites>,
}

/// Why [`Server::run`] returned normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exit {
    /// Idle for the whole idle limit.
    Idle,
    /// Asked to stop ([`StopHandle::stop`], `SIGTERM` or `SIGINT`).
    Stopped,
}

/// Why the server could not serve. Carries no input, so it can be printed and logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServeError {
    /// The event queue could not be created, registered with or waited on.
    EventQueue(PlatformError),
    /// A listener could not be switched to non-blocking mode; holds the `errno`.
    Listener(i32),
    /// Pending writes could not be committed before exit.
    Commit(CommitFailed),
}

impl ServeError {
    /// A fixed name for the system log.
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::EventQueue(_) => "event_queue",
            Self::Listener(_) => "listener",
            Self::Commit(_) => "commit",
        }
    }
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventQueue(error) => write!(f, "event queue failed: {error}"),
            Self::Listener(errno) => write!(f, "cannot configure a listener (errno {errno})"),
            Self::Commit(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ServeError {}

/// State shared between the accept loop and the connection threads.
struct Shared {
    services: Services,
    config: Config,
    queue: Kqueue,
    /// The open connections, by id: a second handle to each stream, so shutdown can close them.
    registry: Mutex<Registry>,
    /// Signalled whenever the registry becomes empty.
    drained: Condvar,
}

#[derive(Default)]
struct Registry {
    next_id: u64,
    open: BTreeMap<u64, UnixStream>,
}

impl Shared {
    fn registry(&self) -> MutexGuard<'_, Registry> {
        // Every update under this lock is a single map operation that a panic cannot leave half done.
        self.registry.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn open_connections(&self) -> usize {
        self.registry().open.len()
    }

    fn log(&self, level: Level, message: &'static str, fields: &[Field]) {
        self.services.log.log(level, message, fields);
    }
}

/// Removes its connection from the registry when the connection thread ends, however it ends (a panicking handler
/// included), and wakes the accept loop so the idle clock sees it.
struct Registration {
    id: u64,
    shared: Arc<Shared>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut registry = self.shared.registry();
        registry.open.remove(&self.id);
        if registry.open.is_empty() {
            self.shared.drained.notify_all();
        }
        drop(registry);
        // Best effort: the loop also looks again at its next tick.
        let _ = self.shared.queue.wake(CONNECTION_CLOSED);
    }
}

/// Asks a running [`Server`] to stop, from any thread.
#[derive(Clone)]
pub(crate) struct StopHandle {
    shared: Arc<Shared>,
}

impl StopHandle {
    /// Asks the server to stop accepting, finish in-flight requests and return [`Exit::Stopped`].
    ///
    /// # Errors
    ///
    /// [`PlatformError`] if the accept loop cannot be woken.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn stop(&self) -> Result<(), PlatformError> {
        self.shared.queue.wake(STOP)
    }
}

/// The connection server over launchd's listeners.
pub(crate) struct Server {
    shared: Arc<Shared>,
    /// Indexed by token.
    listeners: Vec<(Endpoint, UnixListener)>,
    /// When the server was created: the idle clock counts from here, as if `knshd` had just been busy.
    created: Monotonic,
}

impl Server {
    /// Prepares to serve `listeners`: each becomes non-blocking (the accept loop drains the backlog until
    /// `EWOULDBLOCK`) and is registered with a new event queue.
    ///
    /// # Errors
    ///
    /// [`ServeError::EventQueue`] or [`ServeError::Listener`] if the queue or a listener cannot be set up.
    pub(crate) fn new(listeners: Listeners, services: Services, config: Config) -> Result<Self, ServeError> {
        let queue = Kqueue::new().map_err(ServeError::EventQueue)?;
        let listeners: Vec<_> = listeners
            .user
            .into_iter()
            .map(|l| (Endpoint::User, l))
            .chain(listeners.agent.into_iter().map(|l| (Endpoint::Agent, l)))
            .collect();
        for (token, (_, listener)) in listeners.iter().enumerate() {
            listener
                .set_nonblocking(true)
                .map_err(|error| ServeError::Listener(errno(&error)))?;
            queue
                .watch_readable(listener.as_fd(), token)
                .map_err(ServeError::EventQueue)?;
        }
        queue.watch_wakeup(CONNECTION_CLOSED).map_err(ServeError::EventQueue)?;
        queue.watch_wakeup(STOP).map_err(ServeError::EventQueue)?;
        let created = services.clock.monotonic();
        let shared = Arc::new(Shared {
            services,
            config,
            queue,
            registry: Mutex::new(Registry::default()),
            drained: Condvar::new(),
        });
        Ok(Self {
            shared,
            listeners,
            created,
        })
    }

    /// Makes `SIGTERM` (launchd stopping the job) and `SIGINT` stop the server in order instead of killing it.
    ///
    /// # Errors
    ///
    /// [`ServeError::EventQueue`] if the signals cannot be watched.
    pub(crate) fn stop_on_termination_signals(&self) -> Result<(), ServeError> {
        self.shared
            .queue
            .watch_termination(STOP)
            .map_err(ServeError::EventQueue)
    }

    /// A handle that stops this server from another thread.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn stop_handle(&self) -> StopHandle {
        StopHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Serves until idle or stopped, then shuts down in order: stop accepting, let in-flight requests finish within
    /// the grace period, close every connection, commit pending writes.
    ///
    /// # Errors
    ///
    /// [`ServeError::EventQueue`] if waiting fails (the shutdown still runs), or [`ServeError::Commit`] if pending
    /// writes cannot be committed.
    pub(crate) fn run(self) -> Result<Exit, ServeError> {
        let exit = self.accept_until_exit();
        // From here nothing is accepted. launchd keeps the listening sockets, so a client that connects now waits in
        // the backlog and launchd starts a new `knshd` for it.
        self.drain();
        self.shared.services.pending.commit().map_err(ServeError::Commit)?;
        exit
    }

    fn accept_until_exit(&self) -> Result<Exit, ServeError> {
        let services = &self.shared.services;
        let config = &self.shared.config;
        let mut timer = IdleTimer::new(config.idle_limit, self.created);
        let mut events = Vec::new();
        // Whether a connection arrived or closed since the last look. A short connection can open and close between
        // two looks at the registry; it must still reset the idle clock (the ten minutes count from its end).
        let mut connection_activity = false;
        loop {
            let busy = connection_activity || self.shared.open_connections() > 0 || services.activity.keeps_alive();
            connection_activity = false;
            let (timeout, expired) = match timer.observe(services.clock.monotonic(), busy) {
                Idle::Busy => (config.tick, false),
                Idle::Remaining(remaining) => (remaining.min(config.tick), false),
                // One last non-blocking look: a client that connected just now is served rather than left to
                // launchd.
                Idle::Expired => (Duration::ZERO, true),
            };
            self.shared
                .queue
                .wait(timeout, &mut events)
                .map_err(ServeError::EventQueue)?;
            if expired && events.is_empty() {
                return Ok(Exit::Idle);
            }
            for &token in &events {
                match token {
                    STOP => return Ok(Exit::Stopped),
                    // The loop looks at the registry again on its next pass.
                    CONNECTION_CLOSED => connection_activity = true,
                    index => {
                        self.accept_all(index);
                        connection_activity = true;
                    }
                }
            }
        }
    }

    /// Accepts every waiting connection on listener `index`.
    fn accept_all(&self, index: usize) {
        let Some((endpoint, listener)) = self.listeners.get(index) else {
            return;
        };
        loop {
            match listener.accept() {
                Ok((stream, _)) => self.take(*endpoint, stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                // The peer gave up before the accept, or a signal interrupted it: nothing is wrong with the listener.
                Err(error) if is_per_connection(&error) => {}
                Err(error) => {
                    self.shared.log(
                        Level::Error,
                        "accept failed",
                        &[Field::new("errno", Value::Errno(errno(&error)))],
                    );
                    thread::sleep(ACCEPT_BACKOFF);
                    return;
                }
            }
        }
    }

    /// Admits an accepted connection and starts its thread, or closes it.
    fn take(&self, endpoint: Endpoint, stream: UnixStream) {
        // An accepted socket inherits the listener's non-blocking flag on macOS; workers read in blocking mode.
        if stream.set_nonblocking(false).is_err() {
            return;
        }
        match endpoint {
            Endpoint::User => {
                if let Err(refusal) = admit(
                    self.shared.services.credentials.as_ref(),
                    self.shared.services.own_uid,
                    &stream,
                ) {
                    self.log_refusal(refusal);
                    return;
                }
            }
            // Closed unserved until phase 2 (KNSH-048): with no session matching yet, refusing is the fail-closed
            // answer for agents.
            Endpoint::Agent => return,
        }
        let Some(registration) = self.register(&stream) else {
            self.shared.log(
                Level::Error,
                "refused connection: limit reached",
                &[
                    Field::new("endpoint", Value::Static(endpoint.name())),
                    Field::new("limit", Value::U64(self.shared.config.max_connections as u64)),
                ],
            );
            return;
        };
        let config = &self.shared.config;
        // Without its timeouts a connection could hold a slot forever: close it instead. Returning drops the stream
        // and the registration, which frees the slot.
        if stream.set_read_timeout(Some(config.handshake_timeout)).is_err()
            || stream.set_write_timeout(Some(config.write_timeout)).is_err()
        {
            return;
        }
        let shared = Arc::clone(&self.shared);
        let spawned = thread::Builder::new()
            .name("knshd-connection".to_owned())
            .spawn(move || serve_one(&shared, endpoint, &stream, registration));
        if let Err(error) = spawned {
            // The closure, with the stream and the registration, was dropped: the connection is closed and removed.
            self.shared.log(
                Level::Error,
                "cannot start connection thread",
                &[Field::new("errno", Value::Errno(errno(&error)))],
            );
        }
    }

    /// Adds the connection to the registry, or returns `None` at the connection limit.
    fn register(&self, stream: &UnixStream) -> Option<Registration> {
        let handle = stream.try_clone().ok()?;
        let mut registry = self.shared.registry();
        if registry.open.len() >= self.shared.config.max_connections {
            return None;
        }
        let id = registry.next_id;
        registry.next_id += 1;
        registry.open.insert(id, handle);
        Some(Registration {
            id,
            shared: Arc::clone(&self.shared),
        })
    }

    fn log_refusal(&self, refusal: Refusal) {
        match refusal {
            Refusal::OtherUser { peer_uid } => self.shared.log(
                Level::Error,
                "refused user.sock connection from another user",
                &[Field::new("peer_uid", Value::U64(u64::from(peer_uid)))],
            ),
            Refusal::UnknownPeer(error) => self.shared.log(
                Level::Error,
                "refused user.sock connection with unknown peer",
                &[Field::new(
                    "errno",
                    Value::Errno(error.errno().unwrap_or(UNKNOWN_ERRNO)),
                )],
            ),
        }
    }

    /// Ends every connection: stops reading from each (a worker finishes the request it is handling, writes the
    /// answer, then reads end of file), waits up to the grace period for the workers to finish, then closes whatever
    /// is left.
    fn drain(&self) {
        let shared = &self.shared;
        let deadline = Instant::now() + shared.config.shutdown_grace;
        let mut registry = shared.registry();
        for stream in registry.open.values() {
            let _ = stream.shutdown(Shutdown::Read);
        }
        while !registry.open.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            registry = shared
                .drained
                .wait_timeout(registry, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let stuck = registry.open.len();
        for stream in registry.open.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        drop(registry);
        if stuck > 0 {
            shared.log(
                Level::Error,
                "requests still running after shutdown grace",
                &[Field::new("connections", Value::U64(stuck as u64))],
            );
        }
    }
}

/// The read side of a connection that must complete `hello` before a deadline counted from the accept, however
/// slowly its bytes arrive: before each read the socket's read timeout is cut to the time left, so a client that
/// trickles one byte at a time cannot hold its slot past the deadline (`specs/09-reference/defaults-and-limits.md`).
struct HandshakeReader<'a> {
    stream: &'a UnixStream,
    /// `None` once `hello` has succeeded.
    deadline: Cell<Option<Instant>>,
}

impl Read for &HandshakeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(deadline) = self.deadline.get() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.stream.set_read_timeout(Some(left))?;
        }
        let mut stream = self.stream;
        stream.read(buf)
    }
}

/// A connection thread: serves the connection, then logs why it ended if that was abnormal.
fn serve_one(shared: &Shared, endpoint: Endpoint, stream: &UnixStream, registration: Registration) {
    let reader = HandshakeReader {
        stream,
        deadline: Cell::new(Some(Instant::now() + shared.config.handshake_timeout)),
    };
    // Lift the handshake deadline once `hello` succeeds: a greeted client (an observer, a subscriber) may stay quiet
    // as long as it likes. If lifting the socket timeout fails the connection is still served, only with it left on.
    let mut lift_timeout = || {
        reader.deadline.set(None);
        let _ = stream.set_read_timeout(None);
    };
    let closed = connection::serve(
        &reader,
        stream,
        endpoint,
        &shared.services.dispatcher,
        &mut lift_timeout,
    );
    match closed {
        Closed::Peer => {}
        Closed::Frame(_) | Closed::Handshake | Closed::Parse | Closed::Write(_) => shared.log(
            Level::Info,
            "connection closed",
            &[
                Field::new("endpoint", Value::Static(endpoint.name())),
                Field::new("reason", Value::Static(closed.kind())),
            ],
        ),
    }
    // Close before deregistering, so a drain that sees the registry empty knows every connection is already closed.
    let _ = stream.shutdown(Shutdown::Both);
    drop(registration);
}

/// Whether an accept error concerns one connection only, so the loop simply moves on.
fn is_per_connection(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
    )
}

fn errno(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(UNKNOWN_ERRNO)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread::JoinHandle;

    use knsh_core::Timestamp;
    use knsh_json::{Frame, FrameReader};
    use knsh_platform::testing::{FakeClock, FixedPeerCredentials, RecordingLog};
    use knsh_proto::{ErrorCode, Message, Request, decode};

    use super::*;
    use crate::dispatch::tests::ok_handler;
    use crate::dispatch::{HELLO, Table};

    const OWN_UID: u32 = 501;
    /// Generous bound for anything that should happen "at once" on a loaded test machine.
    const PROMPTLY: Duration = Duration::from_secs(5);

    /// Sessions that keep `knshd` alive while the flag is set.
    #[derive(Default)]
    struct FlagActivity(AtomicBool);

    impl Activity for FlagActivity {
        fn keeps_alive(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// An ordered journal of what happened, shared by handlers and the pending-writes fake.
    #[derive(Default)]
    struct Journal(Mutex<Vec<&'static str>>);

    impl Journal {
        fn push(&self, entry: &'static str) {
            self.0.lock().unwrap().push(entry);
        }

        fn entries(&self) -> Vec<&'static str> {
            self.0.lock().unwrap().clone()
        }
    }

    impl PendingWrites for Journal {
        fn commit(&self) -> Result<(), CommitFailed> {
            self.push("commit");
            Ok(())
        }
    }

    /// A temporary socket directory, removed on drop. Short: socket paths are limited to 103 bytes.
    struct SocketDir(PathBuf);

    impl SocketDir {
        fn new(tag: &str) -> Self {
            let path = PathBuf::from("/tmp").join(format!("knshd-s{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for SocketDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A running server on temporary sockets, with every effect faked except the sockets themselves.
    struct TestServer {
        dir: SocketDir,
        clock: Arc<FakeClock>,
        log: Arc<RecordingLog>,
        activity: Arc<FlagActivity>,
        journal: Arc<Journal>,
        stop: StopHandle,
        thread: Option<JoinHandle<Result<Exit, ServeError>>>,
    }

    fn test_config() -> Config {
        Config {
            max_connections: 4,
            idle_limit: IDLE_LIMIT,
            tick: Duration::from_millis(10),
            handshake_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            shutdown_grace: Duration::from_secs(5),
        }
    }

    impl TestServer {
        fn start(tag: &str, config: Config, user_table: Table, peer_uid: u32) -> Self {
            let dir = SocketDir::new(tag);
            let listeners = Listeners {
                user: vec![UnixListener::bind(dir.0.join("u")).unwrap()],
                agent: vec![UnixListener::bind(dir.0.join("a")).unwrap()],
            };
            let clock = Arc::new(FakeClock::new(
                Timestamp::from_unix_micros(1_700_000_000_000_000).unwrap(),
            ));
            let log = Arc::new(RecordingLog::new());
            let activity = Arc::new(FlagActivity::default());
            let journal = Arc::new(Journal::default());
            let services = Services {
                dispatcher: Dispatcher::new(user_table, Table::new().with(HELLO, ok_handler())),
                credentials: Arc::new(FixedPeerCredentials::uid(peer_uid)),
                log: log.clone(),
                own_uid: OWN_UID,
                clock: clock.clone(),
                activity: activity.clone(),
                pending: journal.clone(),
            };
            let server = Server::new(listeners, services, config).unwrap();
            let stop = server.stop_handle();
            let thread = Some(thread::spawn(move || server.run()));
            Self {
                dir,
                clock,
                log,
                activity,
                journal,
                stop,
                thread,
            }
        }

        fn simple(tag: &str) -> Self {
            Self::start(tag, test_config(), Table::new().with(HELLO, ok_handler()), OWN_UID)
        }

        fn connect(&self, socket: &str) -> UnixStream {
            let stream = UnixStream::connect(self.dir.0.join(socket)).unwrap();
            stream.set_read_timeout(Some(PROMPTLY)).unwrap();
            stream
        }

        /// Connects to user.sock and completes the handshake.
        fn greeted(&self) -> UnixStream {
            let mut stream = self.connect("u");
            call(&mut stream, 1, HELLO);
            assert!(matches!(read_message(&stream), Some(Message::Success(_))));
            stream
        }

        fn finished(&self) -> bool {
            self.thread.as_ref().is_none_or(JoinHandle::is_finished)
        }

        /// Waits for `run` to return.
        fn join(&mut self) -> Result<Exit, ServeError> {
            let thread = self.thread.take().unwrap();
            let deadline = Instant::now() + PROMPTLY;
            while !thread.is_finished() {
                assert!(Instant::now() < deadline, "server did not exit");
                thread::sleep(Duration::from_millis(5));
            }
            thread.join().unwrap()
        }

        /// Lets the accept loop run a few ticks.
        fn settle() {
            thread::sleep(Duration::from_millis(100));
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            if self.thread.is_some() {
                let _ = self.stop.stop();
                let _ = self.thread.take().map(JoinHandle::join);
            }
        }
    }

    fn call(stream: &mut UnixStream, id: u32, method: &str) {
        let text = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{"secret":"hunter2"}}}}"#);
        send_raw(stream, text.as_bytes());
    }

    fn send_raw(stream: &mut UnixStream, payload: &[u8]) {
        let mut frame = u32::try_from(payload.len() + 5).unwrap().to_be_bytes().to_vec();
        frame.push(0x01);
        frame.extend_from_slice(&[0; 4]);
        frame.extend_from_slice(payload);
        stream.write_all(&frame).unwrap();
    }

    /// The next message, or `None` when the server closed the connection.
    fn read_message(stream: &UnixStream) -> Option<Message> {
        match FrameReader::new(stream).read_frame() {
            Ok(Some(Frame::Json(payload))) => Some(decode(&payload).unwrap()),
            Ok(None) => None,
            other => panic!("unexpected read: {other:?}"),
        }
    }

    /// Whether the server closed the connection (end of file, or reset).
    fn is_closed(stream: &mut UnixStream) -> bool {
        let mut buf = [0u8; 1];
        match stream.read(&mut buf) {
            Ok(0) => true,
            Ok(_) => false,
            Err(error) => error.kind() == io::ErrorKind::ConnectionReset,
        }
    }

    /// A user table with `hello` and `test.block`, which waits until the returned sender is used (or dropped).
    fn blocking_table(
        journal_slot: &Arc<Mutex<Option<Arc<Journal>>>>,
    ) -> (Table, mpsc::Sender<()>, mpsc::Receiver<()>) {
        let (release, released) = mpsc::channel::<()>();
        let (entered_tx, entered) = mpsc::channel::<()>();
        let released = Mutex::new(released);
        let entered_tx = Mutex::new(entered_tx);
        let slot = Arc::clone(journal_slot);
        let table = Table::new().with(HELLO, ok_handler()).with(
            "test.block",
            Arc::new(move |_: &Request| {
                let _ = entered_tx.lock().unwrap().send(());
                let _ = released.lock().unwrap().recv();
                if let Some(journal) = slot.lock().unwrap().as_ref() {
                    journal.push("handler finished");
                }
                Ok(knsh_json::Value::from(true))
            }),
        );
        (table, release, entered)
    }

    // KNSH-013: user.sock is served end to end: hello first, then dispatch.
    #[test]
    fn serves_hello_over_user_sock() {
        let server = TestServer::simple("hello");
        let mut stream = server.greeted();
        call(&mut stream, 2, "no.such");
        let Some(Message::Error(error)) = read_message(&stream) else {
            panic!("expected an error")
        };
        assert_eq!(error.error.code, ErrorCode::MethodNotFound);
    }

    // KNSH-013: resource bound. With the limit reached, a further connection is closed at once; once a slot frees,
    // connections are served again.
    #[test]
    fn connection_limit_refuses_excess() {
        let config = Config {
            max_connections: 2,
            ..test_config()
        };
        let server = TestServer::start("limit", config, Table::new().with(HELLO, ok_handler()), OWN_UID);
        let first = server.greeted();
        let _second = server.greeted();

        let mut excess = server.connect("u");
        assert!(is_closed(&mut excess), "excess connection must be closed");
        assert!(
            server
                .log
                .entries()
                .iter()
                .any(|entry| entry.message == "refused connection: limit reached")
        );

        drop(first);
        let deadline = Instant::now() + PROMPTLY;
        loop {
            let mut stream = server.connect("u");
            call(&mut stream, 1, HELLO);
            if matches!(read_message(&stream), Some(Message::Success(_))) {
                break;
            }
            assert!(Instant::now() < deadline, "freed slot was never reused");
            thread::sleep(Duration::from_millis(10));
        }
    }

    // KNSH-013: isolation. A client stuck mid-frame and a client whose request is stuck in its handler do not stop
    // another client from being served.
    #[test]
    fn stuck_client_does_not_block_others() {
        let slot = Arc::new(Mutex::new(None));
        let (table, release, entered) = blocking_table(&slot);
        let server = TestServer::start("stuck", test_config(), table, OWN_UID);

        // Stuck mid-frame: a length prefix and nothing more.
        let mut half = server.connect("u");
        half.write_all(&[0, 0]).unwrap();
        // Stuck in a handler.
        let mut blocked = server.greeted();
        call(&mut blocked, 2, "test.block");
        entered.recv_timeout(PROMPTLY).unwrap();

        let started = Instant::now();
        let mut other = server.greeted();
        call(&mut other, 2, "no.such");
        assert!(matches!(read_message(&other), Some(Message::Error(_))));
        assert!(started.elapsed() < PROMPTLY);

        release.send(()).unwrap();
        assert!(matches!(read_message(&blocked), Some(Message::Success(_))));
    }

    // A client that connects and never says hello is disconnected after the handshake timeout, freeing its slot.
    #[test]
    fn silent_client_is_closed_after_handshake_timeout() {
        let config = Config {
            handshake_timeout: Duration::from_millis(100),
            ..test_config()
        };
        let server = TestServer::start("silent", config, Table::new().with(HELLO, ok_handler()), OWN_UID);
        let mut silent = server.connect("u");
        let started = Instant::now();
        assert!(is_closed(&mut silent));
        assert!(started.elapsed() < PROMPTLY);
        // A greeted client is not subject to it.
        let greeted = server.greeted();
        thread::sleep(Duration::from_millis(300));
        let mut greeted = greeted;
        call(&mut greeted, 2, HELLO);
        assert!(matches!(read_message(&greeted), Some(Message::Success(_))));
    }

    // The handshake timeout counts from the accept, not per read: a client that trickles bytes slower than the
    // timeout but faster than each read's timeout is still closed (defaults-and-limits "First message timeout").
    #[test]
    fn trickling_client_is_closed_at_the_handshake_deadline() {
        let config = Config {
            handshake_timeout: Duration::from_millis(300),
            ..test_config()
        };
        let server = TestServer::start("trickle", config, Table::new().with(HELLO, ok_handler()), OWN_UID);
        let mut trickle = server.connect("u");
        // A frame header announcing a 59-byte payload, then payload bytes one every 100 ms for over a second: each
        // read finishes well within the timeout, the whole frame never does.
        let mut bytes = vec![0u8, 0, 0, 64, 1, 0, 0, 0, 0];
        bytes.extend_from_slice(&[b' '; 12]);
        let mut closed_by_server = false;
        for byte in bytes {
            if trickle.write_all(&[byte]).is_err() {
                closed_by_server = true;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        if !closed_by_server {
            // Right after the last byte: closed already, or the server is still waiting for more.
            trickle.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            closed_by_server = is_closed(&mut trickle);
        }
        assert!(closed_by_server, "trickling client outlived the handshake deadline");
    }

    // KNSH-012, process model "One process per user": the peer check still guards user.sock.
    #[test]
    fn refused_peer_is_closed_and_logged() {
        let server = TestServer::start(
            "peer",
            test_config(),
            Table::new().with(HELLO, ok_handler()),
            OWN_UID + 1,
        );
        let mut stream = server.connect("u");
        assert!(is_closed(&mut stream));
        let entries = server.log.entries();
        assert!(
            entries
                .iter()
                .any(|entry| entry.message == "refused user.sock connection from another user")
        );
    }

    // agent.sock connections are closed unserved until phase 2 (KNSH-048): agents fail closed.
    #[test]
    fn agent_sock_connections_are_closed_unserved() {
        let server = TestServer::simple("agent");
        let mut stream = server.connect("a");
        assert!(is_closed(&mut stream));
    }

    // KNSH-013: with no sessions and no connections, the server exits after 10 idle minutes of the injected clock,
    // committing pending writes first.
    #[test]
    fn server_exits_after_10_idle_minutes() {
        let mut server = TestServer::simple("idle");
        server
            .clock
            .advance(IDLE_LIMIT.checked_sub(Duration::from_secs(1)).unwrap());
        TestServer::settle();
        assert!(!server.finished(), "exited before the idle limit");
        server.clock.advance(Duration::from_secs(1));
        assert_eq!(server.join(), Ok(Exit::Idle));
        assert_eq!(server.journal.entries(), vec!["commit"]);
    }

    // KNSH-013: an active recording session (or envelope) keeps knshd alive; the idle minutes count from its end.
    #[test]
    fn active_recording_session_prevents_exit() {
        let mut server = TestServer::simple("session");
        server.activity.0.store(true, Ordering::SeqCst);
        TestServer::settle();
        server.clock.advance(IDLE_LIMIT * 3);
        TestServer::settle();
        assert!(!server.finished(), "exited with a recording session");

        server.activity.0.store(false, Ordering::SeqCst);
        TestServer::settle();
        server
            .clock
            .advance(IDLE_LIMIT.checked_sub(Duration::from_secs(1)).unwrap());
        TestServer::settle();
        assert!(!server.finished(), "idle minutes must count from the session's end");
        server.clock.advance(Duration::from_secs(1));
        assert_eq!(server.join(), Ok(Exit::Idle));
    }

    // KNSH-013: an open connection keeps knshd alive too.
    #[test]
    fn open_connection_prevents_exit() {
        let mut server = TestServer::simple("conn");
        let stream = server.greeted();
        server.clock.advance(IDLE_LIMIT * 2);
        TestServer::settle();
        assert!(!server.finished(), "exited with an open connection");

        drop(stream);
        TestServer::settle();
        server.clock.advance(IDLE_LIMIT);
        assert_eq!(server.join(), Ok(Exit::Idle));
    }

    // KNSH-013: a connection that opens and closes between two looks of the accept loop still resets the idle
    // clock; the ten minutes count from its end.
    #[test]
    fn short_connection_resets_the_idle_timer() {
        let mut server = TestServer::simple("short");
        server
            .clock
            .advance(IDLE_LIMIT.checked_sub(Duration::from_secs(1)).unwrap());
        TestServer::settle();
        drop(server.greeted());
        TestServer::settle();
        server.clock.advance(Duration::from_secs(2));
        TestServer::settle();
        assert!(!server.finished(), "exited right after serving a connection");
        server.clock.advance(IDLE_LIMIT);
        assert_eq!(server.join(), Ok(Exit::Idle));
    }

    // KNSH-013: data safety. On stop, the in-flight request finishes and is answered, then pending writes are
    // committed, then run returns. A greeted but quiet connection is closed.
    #[test]
    fn pending_writes_committed_before_exit() {
        let slot = Arc::new(Mutex::new(None));
        let (table, release, entered) = blocking_table(&slot);
        let mut server = TestServer::start("pending", test_config(), table, OWN_UID);
        *slot.lock().unwrap() = Some(Arc::clone(&server.journal));

        let mut busy = server.greeted();
        call(&mut busy, 2, "test.block");
        entered.recv_timeout(PROMPTLY).unwrap();
        let mut quiet = server.greeted();

        server.stop.stop().unwrap();
        TestServer::settle();
        assert!(!server.finished(), "must wait for the in-flight request");
        // No new connection is served once stopping has begun.
        assert!(UnixStream::connect(server.dir.0.join("u")).is_ok_and(|mut s| {
            s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
            let mut buf = [0u8; 1];
            !matches!(s.read(&mut buf), Ok(n) if n > 0)
        }));

        release.send(()).unwrap();
        assert!(
            matches!(read_message(&busy), Some(Message::Success(_))),
            "in-flight answer lost"
        );
        assert_eq!(server.join(), Ok(Exit::Stopped));
        assert_eq!(server.journal.entries(), vec!["handler finished", "commit"]);
        assert!(is_closed(&mut quiet));
    }

    // KNSH-013: shutdown is bounded. A request that never finishes does not hold knshd past the grace period.
    #[test]
    fn shutdown_is_bounded_by_the_grace_period() {
        let slot = Arc::new(Mutex::new(None));
        let (table, release, entered) = blocking_table(&slot);
        let config = Config {
            shutdown_grace: Duration::from_millis(200),
            ..test_config()
        };
        let mut server = TestServer::start("grace", config, table, OWN_UID);
        let mut busy = server.greeted();
        call(&mut busy, 2, "test.block");
        entered.recv_timeout(PROMPTLY).unwrap();

        let started = Instant::now();
        server.stop.stop().unwrap();
        assert_eq!(server.join(), Ok(Exit::Stopped));
        assert!(started.elapsed() < PROMPTLY);
        assert_eq!(server.journal.entries(), vec!["commit"]);
        assert!(
            server
                .log
                .entries()
                .iter()
                .any(|entry| entry.message == "requests still running after shutdown grace")
        );
        drop(release);
    }

    // KNSH-013, NFR-PRIV-02: no message content reaches the system log, whatever the client sends.
    #[test]
    fn no_message_content_in_system_log() {
        let mut server = TestServer::simple("privacy");
        let mut stream = server.greeted();
        call(&mut stream, 2, "secret.method");
        let _ = read_message(&stream);
        send_raw(&mut stream, br#"{"hunter2":"#);
        let _ = read_message(&stream);
        let mut other = server.connect("u");
        call(&mut other, 1, "records.query");
        let _ = read_message(&other);
        server.stop.stop().unwrap();
        server.join().unwrap();

        let entries = server.log.entries();
        assert!(!entries.is_empty(), "closes are logged");
        let rendered = format!("{entries:?}");
        for content in ["hunter2", "secret", "records.query"] {
            assert!(!rendered.contains(content), "{content} leaked into {rendered}");
        }
    }

    #[test]
    fn accept_errors_about_one_connection_do_not_stop_the_loop() {
        assert!(is_per_connection(&io::Error::from(io::ErrorKind::ConnectionAborted)));
        assert!(is_per_connection(&io::Error::from(io::ErrorKind::Interrupted)));
        assert!(!is_per_connection(&io::Error::from(io::ErrorKind::OutOfMemory)));
    }
}
