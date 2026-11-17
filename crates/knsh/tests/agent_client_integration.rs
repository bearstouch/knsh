//! End-to-end checks of the agent client (KNSH-049) through the real `knsh` binary and a test envelope's supervisor:
//! a Unix socket at the engine's `agent.sock` path that answers `hello` and `exec.run`, receiving the caller's stdio
//! as descriptors (`SCM_RIGHTS`) and running each allowed line with `/bin/bash -c` on exactly those descriptors, as
//! the real supervisor will (KNSH-050, KNSH-051). `knshd`'s own side of `exec.run` is tested in `knshd`.
//!
//! The stand-in denies any line containing `DENY` (`-32001`), and holds the first `exec.run` of a line containing
//! `HOLD` (`-32007`). Every test uses a short temporary `HOME` under `/tmp` (a socket path must fit in 104 bytes),
//! never the user's real one.

#![cfg(all(test, target_os = "macos"))]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::cell::RefCell;
use std::fs;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use knsh_json::{Frame, FrameReader, FrameWriter, FromJson, Object, ToJson, Value};
use knsh_platform::macos::{RealFs, effective_uid, recv_with_descriptors};
use knsh_platform::{EnginePaths, ensure_engine_dirs};
use knsh_proto::{
    Denial, ErrorCode, ErrorResponse, ExecRunParams, ExecRunResult, ExecStdio, Interpreter, LineStatus, Message,
    RpcError, SESSION_TOKEN_VAR, SuccessResponse, decode,
};

const SESSION: &str = "01JCZ0000000000000000000CD";

/// A short temporary home, removed when dropped.
struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(format!("/private/tmp/knshac-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("home");
        let home = Self(dir);
        ensure_engine_dirs(&RealFs::new(), &home.paths(), effective_uid()).expect("engine dirs");
        home
    }

    fn paths(&self) -> EnginePaths {
        EnginePaths::for_home(&self.0).expect("paths")
    }

    /// `program` with `args`, an empty environment but for `HOME`, `PATH` and `extra`, in the home directory.
    fn run(&self, program: &Path, args: &[&str], path: &str, extra: &[(&str, &str)]) -> Output {
        let mut command = Command::new(program);
        command
            .args(args)
            .env_clear()
            .env("HOME", &self.0)
            .env("PATH", path)
            .current_dir(&self.0)
            .stdin(Stdio::null());
        for (name, value) in extra {
            command.env(name, value);
        }
        command.output().expect("run")
    }

    fn knsh(&self, args: &[&str]) -> Output {
        self.run(Path::new(env!("CARGO_BIN_EXE_knsh")), args, "/usr/bin:/bin", &[])
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// What the stand-in supervisor saw.
#[derive(Default)]
struct Seen {
    /// The session token of each `hello`.
    tokens: Vec<Option<String>>,
    /// Each `exec.run` with the number of descriptors that came with it.
    lines: Vec<(ExecRunParams, usize)>,
}

/// The test envelope's supervisor, serving `agent.sock` under `home` until the test ends or [`Supervisor::kill`].
struct Supervisor {
    seen: Arc<Mutex<Seen>>,
    /// Set to stop accepting, as when `knshd` dies.
    stopped: Arc<AtomicBool>,
    accepting: thread::JoinHandle<()>,
}

impl Supervisor {
    fn start(home: &Home) -> Self {
        // A stale socket file from a supervisor that died is replaced, as launchd's restart does.
        let _ = fs::remove_file(home.paths().agent_socket());
        let listener = UnixListener::bind(home.paths().agent_socket()).expect("bind agent.sock");
        // Polled, so that `kill` can close the listening socket.
        listener.set_nonblocking(true).expect("non-blocking listener");
        let seen = Arc::new(Mutex::new(Seen::default()));
        let shared = Arc::clone(&seen);
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let shims = home.paths().shim_dir();
        let accepting = thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking stream");
                        let seen = Arc::clone(&shared);
                        let shims = shims.clone();
                        thread::spawn(move || serve(&stream, &seen, &shims));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
            // The listener closes here; the socket file stays behind, as after a crash.
        });
        Self {
            seen,
            stopped,
            accepting,
        }
    }

    /// Stops the supervisor as a crash would: nothing listens on `agent.sock` any more, but its file remains.
    fn kill(self) {
        self.stopped.store(true, Ordering::Relaxed);
        self.accepting.join().expect("accept loop");
    }

    fn lines(&self) -> Vec<(ExecRunParams, usize)> {
        self.seen.lock().unwrap().lines.clone()
    }

    fn tokens(&self) -> Vec<Option<String>> {
        self.seen.lock().unwrap().tokens.clone()
    }
}

/// Reads through `recvmsg`, keeping the descriptors that arrive.
struct DescriptorReader<'a> {
    stream: &'a UnixStream,
    received: Rc<RefCell<Vec<OwnedFd>>>,
}

impl Read for DescriptorReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        recv_with_descriptors(self.stream, buf, &mut self.received.borrow_mut())
    }
}

fn serve(stream: &UnixStream, seen: &Mutex<Seen>, shims: &Path) {
    let received = Rc::new(RefCell::new(Vec::new()));
    let mut reader = FrameReader::new(DescriptorReader {
        stream,
        received: Rc::clone(&received),
    });
    let mut writer = FrameWriter::new(stream.try_clone().unwrap());
    let mut held = false;
    while let Ok(Some(Frame::Json(payload))) = reader.read_frame() {
        let descriptors = received.take();
        let Ok(Message::Request(request)) = decode(&payload) else {
            return;
        };
        let params = request.params.clone().map_or(Value::Null, Value::Object);
        let answer = match request.method.as_str() {
            "hello" => {
                let token = params
                    .as_object()
                    .and_then(|params| params.get("session_token"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                seen.lock().unwrap().tokens.push(token);
                Ok(Value::Object(
                    Object::new()
                        .with("protocol", 1)
                        .unwrap()
                        .with("session_id", SESSION)
                        .unwrap(),
                ))
            }
            "exec.run" => {
                let params = ExecRunParams::from_json(&params).expect("exec.run params");
                seen.lock().unwrap().lines.push((params.clone(), descriptors.len()));
                if params.command.contains("HOLD") && !held {
                    held = true;
                    let state = Object::new().with("state", "paused").unwrap();
                    Err(RpcError::new(ErrorCode::SessionHeld).with_data(Value::Object(state)))
                } else if params.command.contains("DENY") {
                    let denial = Denial {
                        rule_id: Some("exec.deny[0]".to_owned()),
                        reason: Some("the test profile denies this".to_owned()),
                        source: Some("rule".to_owned()),
                    };
                    Err(denial.to_error().unwrap())
                } else {
                    Ok(run_line(&params, descriptors, shims).to_json().unwrap())
                }
            }
            _ => Err(RpcError::new(ErrorCode::MethodNotFound)),
        };
        let message = match answer {
            Ok(result) => Message::Success(SuccessResponse { id: request.id, result }),
            Err(error) => Message::Error(ErrorResponse {
                id: Some(request.id),
                error,
            }),
        };
        writer.write_json(&message.to_value().unwrap()).unwrap();
        writer.flush().unwrap();
    }
}

/// Runs an allowed line as the supervisor will: `/bin/bash -c line args…` in its directory, with its environment
/// minus the shim directory in `PATH` (FR-LC-16: without that, `sh` inside the line would be the shim again and
/// forward itself forever), attached to the caller's own descriptors. The supervisor's copies are closed once the
/// line is started.
fn run_line(params: &ExecRunParams, descriptors: Vec<OwnedFd>, shims: &Path) -> ExecRunResult {
    assert_eq!(params.stdio, ExecStdio::Passed);
    let mut descriptors = descriptors.into_iter();
    let (stdin, stdout, stderr) = (
        descriptors.next().unwrap(),
        descriptors.next().unwrap(),
        descriptors.next().unwrap(),
    );
    let mut child = Command::new("/bin/bash")
        .arg("-c")
        .arg(&params.command)
        .args(&params.args)
        .env_clear()
        .envs(params.env.iter().map(|(name, value)| {
            if name == "PATH" {
                let kept: Vec<&str> = value.split(':').filter(|entry| Path::new(entry) != shims).collect();
                (name.clone(), kept.join(":"))
            } else {
                (name.clone(), value.clone())
            }
        }))
        .current_dir(params.cwd.as_path())
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap();
    let status = child.wait().unwrap();
    let status = match (status.code(), std::os::unix::process::ExitStatusExt::signal(&status)) {
        (Some(code), _) => LineStatus::Exited(u8::try_from(code).unwrap()),
        (None, Some(signal)) => LineStatus::Signalled(u8::try_from(signal).unwrap()),
        (None, None) => panic!("no status"),
    };
    ExecRunResult {
        record_id: None,
        status,
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// KNSH-049 integration: `knsh -c 'echo hi | tr a-z A-Z'` in a test envelope writes `HI` to the caller's own stdout
// pipe: the supervisor ran it on the passed descriptor, and nothing came back through the API.
#[test]
fn output_reaches_the_callers_own_pipe() {
    let home = Home::new();
    let supervisor = Supervisor::start(&home);
    let output = home.knsh(&["-c", "echo hi | tr a-z A-Z; echo oops >&2"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "HI\n");
    assert_eq!(text(&output.stderr), "oops\n");
    let lines = supervisor.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].1, 3, "stdin, stdout and stderr were passed");
    assert_eq!(lines[0].0.interpreter, Interpreter::Knsh);
}

// KNSH-049 integration, FR-AGT-10: `knsh -c 'exit 3'` exits 3; the line, its operands, the directory and the
// environment arrive unchanged, and the session token goes in `hello`.
#[test]
fn exits_with_the_lines_code_and_forwards_everything() {
    let home = Home::new();
    let supervisor = Supervisor::start(&home);
    let output = home.run(
        Path::new(env!("CARGO_BIN_EXE_knsh")),
        &["-c", "printf '%s|' \"$0\" \"$1\"; exit 3", "name", "one two"],
        "/usr/bin:/bin",
        &[(SESSION_TOKEN_VAR, "abc123"), ("CUSTOM", "value with spaces")],
    );
    assert_eq!(output.status.code(), Some(3), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "name|one two|");
    assert_eq!(supervisor.tokens(), [Some("abc123".to_owned())]);
    let (params, _) = supervisor.lines().remove(0);
    assert_eq!(params.args, ["name", "one two"]);
    assert_eq!(params.cwd.as_path(), fs::canonicalize(&home.0).unwrap());
    assert!(
        params
            .env
            .contains(&("CUSTOM".to_owned(), "value with spaces".to_owned()))
    );
    assert!(
        params
            .env
            .contains(&(SESSION_TOKEN_VAR.to_owned(), "abc123".to_owned()))
    );
}

// FR-LC-31: a denied line exits 126 with the reason and rule ID on stderr, and does not run.
#[test]
fn denied_line_exits_126_with_the_reason() {
    let home = Home::new();
    let _supervisor = Supervisor::start(&home);
    let marker = home.0.join("marker");
    let output = home.knsh(&["-c", &format!("touch {} # DENY", marker.display())]);
    assert_eq!(output.status.code(), Some(126));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("denied: the test profile denies this"), "{stderr}");
    assert!(stderr.contains("exec.deny[0]"), "{stderr}");
    assert_eq!(output.stdout, b"");
    assert!(!marker.exists());
}

// NFR-COMPAT-09: a line killed by a signal exits 128 + n.
#[test]
fn signalled_line_exits_128_plus_n() {
    let home = Home::new();
    let _supervisor = Supervisor::start(&home);
    let output = home.knsh(&["-c", "kill -TERM $$"]);
    assert_eq!(output.status.code(), Some(143), "{}", text(&output.stderr));
}

// NFR-REL-01: with no supervisor listening, nothing runs, the reason is on stderr, and knsh exits 126.
#[test]
fn unreachable_supervisor_runs_nothing() {
    let home = Home::new();
    let marker = home.0.join("marker");
    let output = home.knsh(&["-c", &format!("touch {}", marker.display())]);
    assert_eq!(output.status.code(), Some(126));
    assert!(
        text(&output.stderr).contains("supervisor is unavailable"),
        "{}",
        text(&output.stderr)
    );
    assert!(!marker.exists(), "the line must never run locally");
}

// KNSH-074 integration test (NFR-REL-01, NFR-REL-03): the supervisor dies during an agent session. The next
// `knsh -c` runs nothing and exits 126 saying why; once the supervisor is back (launchd's restart), the next line runs
// normally. The client keeps no state between lines, so nothing has to be reset.
#[test]
fn killed_supervisor_runs_nothing_until_restarted() {
    let home = Home::new();
    let supervisor = Supervisor::start(&home);
    let output = home.knsh(&["-c", "echo before"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "before\n");

    supervisor.kill();
    let marker = home.0.join("marker");
    let output = home.knsh(&["-c", &format!("touch {}", marker.display())]);
    assert_eq!(output.status.code(), Some(126));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("supervisor is unavailable"), "{stderr}");
    assert!(stderr.contains("did not run"), "{stderr}");
    assert_eq!(output.stdout, b"");
    assert!(!marker.exists(), "the line must never run locally");

    let restarted = Supervisor::start(&home);
    let output = home.knsh(&["-c", &format!("touch {} && echo after", marker.display())]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "after\n");
    assert!(marker.exists());
    assert_eq!(restarted.lines().len(), 1);
}

// KNSH-054: a held line waits and then runs, without failing.
#[test]
fn held_line_waits_then_runs() {
    let home = Home::new();
    let supervisor = Supervisor::start(&home);
    let output = home.knsh(&["-c", "echo resumed # HOLD"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "resumed\n");
    assert!(text(&output.stderr).contains("held"), "{}", text(&output.stderr));
    assert_eq!(supervisor.lines().len(), 2);
}

// KNSH-049 shims, FR-LC-14, FR-AGT-31: `bash -c`, `sh -c` and `zsh -c` found through PATH are forwarded with the
// interpreter recorded; `/bin/bash` by absolute path is not intercepted.
#[test]
fn shims_forward_by_name_and_absolute_paths_are_not_intercepted() {
    let home = Home::new();
    let supervisor = Supervisor::start(&home);
    let shims = home.paths().shim_dir();
    knsh::agent::shims::install(&shims, Path::new(env!("CARGO_BIN_EXE_knsh"))).unwrap();
    let path = format!("{}:/usr/bin:/bin", shims.display());
    let script = "bash -c 'echo from-bash'; sh -c 'echo from-sh'; zsh -c 'echo from-zsh'; /bin/bash -c 'echo direct'";
    let output = home.run(Path::new("/bin/sh"), &["-c", script], &path, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "from-bash\nfrom-sh\nfrom-zsh\ndirect\n");
    let interpreters: Vec<(Interpreter, String)> = supervisor
        .lines()
        .into_iter()
        .map(|(params, _)| (params.interpreter, params.command))
        .collect();
    assert_eq!(
        interpreters,
        [
            (Interpreter::Bash, "echo from-bash".to_owned()),
            (Interpreter::Sh, "echo from-sh".to_owned()),
            (Interpreter::Zsh, "echo from-zsh".to_owned()),
        ],
        "only the three shims were forwarded"
    );
    // A shim's non -c form is the equivalent line, under its own interpreter.
    let output = home.run(&shims.join("sh"), &["script.sh", "a b"], &path, &[]);
    assert_eq!(
        output.status.code(),
        Some(127),
        "bash cannot find the script: {}",
        text(&output.stderr)
    );
    let (params, _) = supervisor.lines().pop().unwrap();
    assert_eq!(params.interpreter, Interpreter::Sh);
    assert_eq!(params.command, "sh 'script.sh' 'a b'");
}

// KNSH-057, FR-AGT-20: inside an envelope (its session token set) `knsh -i` hosts no human shell: it is forwarded to
// the supervisor as an agent line reading the same stdin, so commands typed into the envelope's terminal are the
// agent's and are decided like any other line.
#[test]
fn interactive_knsh_in_an_envelope_is_an_agent_line() {
    let home = Home::new();
    let supervisor = Supervisor::start(&home);
    let output = home.run(
        Path::new(env!("CARGO_BIN_EXE_knsh")),
        &["-i"],
        "/usr/bin:/bin",
        &[(SESSION_TOKEN_VAR, "abc123")],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(supervisor.tokens(), [Some("abc123".to_owned())]);
    let lines = supervisor.lines();
    assert_eq!(lines.len(), 1, "forwarded, not run locally");
    assert_eq!(lines[0].1, 3, "with the terminal's stdin, stdout and stderr");
}
