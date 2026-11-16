//! `agent.sock` over real sockets, real audit tokens and the real process table (KNSH-048 integration tests).
//!
//! A [`Server`] serves temporary sockets with the dispatcher `knshd` builds, reading peers with
//! [`SystemPeerCredentials`] and matching them with [`SystemProcessTree`]. The envelope registry is the only fake
//! part: the test registers whichever process it wants as an envelope's root.
//!
//! The child process of [`child_bound_by_audit_token`] is this test binary run again, filtered to
//! [`agent_child`], which connects and says `hello` without a token when `KNSH_TEST_AGENT_SOCKET` is set (and does
//! nothing otherwise).

use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use knsh_core::Timestamp;
use knsh_json::{Frame, FrameReader, FrameWriter, Value};
use knsh_platform::ProcessTree;
use knsh_platform::macos::{SystemPeerCredentials, SystemProcessTree, effective_uid};
use knsh_platform::testing::{FakeClock, RecordingLog};
use knsh_proto::{ErrorCode, Message, decode};

use crate::endpoints::Listeners;
use crate::server::{Config, Exit, ServeError, Server, Services, StopHandle};
use crate::sessions::tests::{Fixture, fixture_on};

/// The environment variable that turns [`agent_child`] into a client of this socket.
const SOCKET_VARIABLE: &str = "KNSH_TEST_AGENT_SOCKET";
/// Marks the child's answer on its standard output.
const ANSWER: &str = "KNSH-ANSWER ";

/// A running server on temporary sockets.
struct Running {
    dir: PathBuf,
    fixture: Fixture,
    stop: StopHandle,
    thread: Option<JoinHandle<Result<Exit, ServeError>>>,
}

impl Running {
    fn start(tag: &str) -> Self {
        // Short: socket paths are limited to 103 bytes.
        let dir = PathBuf::from("/tmp").join(format!("knshd-a{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let fixture = fixture_on(Some(Arc::new(SystemProcessTree::new())));
        let dispatcher = super::endpoint_tests::dispatcher(&fixture);
        let services = Services {
            dispatcher: Arc::new(dispatcher),
            credentials: Arc::new(SystemPeerCredentials::new()),
            log: Arc::new(RecordingLog::new()),
            own_uid: effective_uid(),
            clock: Arc::new(FakeClock::new(
                Timestamp::from_unix_micros(1_700_000_000_000_000).unwrap(),
            )),
            activity: Arc::clone(&fixture.sessions) as _,
            pending: Arc::new(crate::records::Records::new(Some(fixture.store.clone()))),
        };
        let listeners = Listeners {
            user: vec![UnixListener::bind(dir.join("u")).unwrap()],
            agent: vec![UnixListener::bind(dir.join("a")).unwrap()],
        };
        let server = Server::new(listeners, services, Config::DEFAULT).unwrap();
        let stop = server.stop_handle();
        let thread = Some(std::thread::spawn(move || server.run()));
        Self {
            dir,
            fixture,
            stop,
            thread,
        }
    }

    fn agent_socket(&self) -> PathBuf {
        self.dir.join("a")
    }

    /// Opens an agent session whose envelope's root is `root`.
    fn open_envelope(&self, root: knsh_platform::ProcessIdentity) -> knsh_core::SessionId {
        super::endpoint_tests::open_agent(&self.fixture, Some(root)).session_id
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.stop.stop();
        let _ = self.thread.take().map(JoinHandle::join);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Says `hello` without a token on `socket` and returns the answer, or `None` if the server closed without one.
/// With `check_close`, reads once more after the answer and reports whether the server then closed the connection.
fn hello_without_token(socket: &Path, check_close: bool) -> (Option<Message>, bool) {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let text = br#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{"client":"t","client_version":"1","protocols":[1],"binary_frames":false}}"#;
    let mut writer = FrameWriter::new(&mut stream);
    writer.write_json(&knsh_json::parse(text, 4096).unwrap()).unwrap();
    writer.flush().unwrap();
    let mut reader = FrameReader::new(&stream);
    let answer = match reader.read_frame() {
        Ok(Some(Frame::Json(payload))) => Some(decode(&payload).unwrap()),
        _ => None,
    };
    let closed = check_close && matches!(reader.read_frame(), Ok(None) | Err(_));
    (answer, closed)
}

/// The child half of [`child_bound_by_audit_token`]: connects as a process inside the envelope and prints the
/// answer to its `hello`. Does nothing when run as a normal test.
#[test]
fn agent_child() {
    let Some(socket) = std::env::var_os(SOCKET_VARIABLE) else {
        return;
    };
    let (answer, _) = hello_without_token(Path::new(&socket), false);
    let line = match answer {
        Some(Message::Success(success)) => knsh_json::write(&success.result).unwrap(),
        Some(Message::Error(error)) => format!("error {}", error.error.code.code()),
        Some(_) | None => "closed".to_owned(),
    };
    let mut stdout = std::io::stdout().lock();
    // On a line of its own: the test harness may have written to the same line already.
    writeln!(stdout, "\n{ANSWER}{line}").unwrap();
}

// KNSH-048 integration (FR-AGT-23): a child process spawned under a registered envelope connects without a token
// and is bound to the envelope's session by its audit token. The envelope's root is this test process; the child is
// this binary run again.
#[test]
fn child_bound_by_audit_token() {
    let server = Running::start("child");
    let own = SystemProcessTree::new()
        .identity(std::process::id().cast_signed())
        .unwrap();
    let session_id = server.open_envelope(own);
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "agents::platform_tests::agent_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(SOCKET_VARIABLE, server.agent_socket())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success(), "child failed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let answer = stdout
        .lines()
        .find_map(|line| line.split_once(ANSWER).map(|(_, answer)| answer))
        .unwrap_or_else(|| panic!("no answer from the child: {stdout}"));
    let result = knsh_json::parse(answer.as_bytes(), 1 << 20).unwrap();
    assert_eq!(
        result
            .as_object()
            .and_then(|r| r.get("session_id"))
            .and_then(Value::as_str),
        Some(session_id.to_string().as_str()),
        "{answer}"
    );
}

// KNSH-048 integration (FR-AGT-23): a process outside every envelope is refused with -32009 and its connection is
// closed. The only envelope is rooted at another process (a `sleep` this test started), which this process does not
// descend from.
#[test]
fn process_outside_every_envelope_is_refused() {
    let server = Running::start("out");
    let mut sleeper = Command::new("/bin/sleep")
        .arg("30")
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let root = SystemProcessTree::new().identity(sleeper.id().cast_signed());
    let refused = root.map(|root| {
        server.open_envelope(root);
        hello_without_token(&server.agent_socket(), true)
    });
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    let (answer, closed) = refused.unwrap();
    match answer {
        Some(Message::Error(error)) => assert_eq!(error.error.code, ErrorCode::InvalidSessionToken),
        other => panic!("expected -32009, got {other:?}"),
    }
    assert!(closed, "the connection is closed after the refusal");
}
