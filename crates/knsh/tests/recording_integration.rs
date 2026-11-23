//! End-to-end checks of human recording (KNSH-021, FR-SES-21, FR-SES-23, FR-SES-24, FR-SES-25, FR-REC-09,
//! NFR-REL-02) through the real `knsh` binary, the real `/bin/zsh` and `/bin/bash`, and a stand-in for `knshd`: a
//! Unix socket at the engine's `user.sock` path that speaks the framed JSON-RPC protocol and records every call.
//! `knshd`'s side of these methods (records written, events published, session ended on close) is tested in
//! `knshd`'s `sessions` module.
//!
//! Every test uses a short temporary `HOME` under `/tmp` (a socket path must fit in 104 bytes), never the user's
//! real one, and feeds the interactive shell its command lines on standard input, which runs the hooks just as typing
//! does.

#![cfg(all(test, target_os = "macos"))]
#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use knsh_json::{Frame, FrameReader, FrameWriter, Object, Value};
use knsh_platform::macos::{RealFs, effective_uid};
use knsh_platform::{EnginePaths, ensure_engine_dirs};
use knsh_proto::{Message, SuccessResponse, decode};

/// A short temporary home, removed when dropped.
struct Home(PathBuf);

impl Home {
    fn new(recording: Option<bool>) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(format!("/private/tmp/knshrec-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("home");
        let home = Self(dir);
        ensure_engine_dirs(&RealFs::new(), &home.paths(), effective_uid()).expect("engine dirs");
        if let Some(on) = recording {
            home.write_config(&format!("[recording]\nhuman = {on}\n"));
        }
        home
    }

    /// Writes `text` as the user's `config.toml`.
    fn write_config(&self, text: &str) {
        let paths = self.paths();
        fs::create_dir_all(paths.config_dir()).expect("config dir");
        fs::write(paths.config_file(), text).expect("config");
    }

    fn paths(&self) -> EnginePaths {
        EnginePaths::for_home(&self.0).expect("paths")
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One call the stand-in daemon received.
#[derive(Debug, Clone)]
struct Received {
    connection: usize,
    method: String,
    params: Object,
}

/// What the stand-in daemon saw.
#[derive(Debug, Default)]
struct Seen {
    calls: Vec<Received>,
    connections: usize,
    /// Connections whose peer closed them: each ends its session in the real `knshd`.
    closed: usize,
}

/// A stand-in for `knshd` on `user.sock`.
struct FakeDaemon {
    seen: Arc<Mutex<Seen>>,
    socket: PathBuf,
}

impl FakeDaemon {
    /// Listens at the home's `user.sock`. After `stop_after` `telemetry.command` calls the daemon "crashes": it
    /// closes the connection without answering and stops listening.
    fn start(home: &Home, stop_after: Option<usize>) -> Self {
        let socket = home.paths().user_socket();
        let listener = UnixListener::bind(&socket).expect("bind user.sock");
        let seen = Arc::new(Mutex::new(Seen::default()));
        let shared = Arc::clone(&seen);
        let path = socket.clone();
        thread::spawn(move || {
            for (connection, stream) in listener.incoming().enumerate() {
                let Ok(stream) = stream else { return };
                shared.lock().expect("seen").connections += 1;
                let seen = Arc::clone(&shared);
                let crashed = serve(&stream, connection, &seen, stop_after);
                if crashed {
                    // Gone: nothing listens any more, so a reconnect fails like a stopped daemon.
                    let _ = fs::remove_file(&path);
                    return;
                }
            }
        });
        Self { seen, socket }
    }

    fn methods(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("seen")
            .calls
            .iter()
            .map(|call| call.method.clone())
            .collect()
    }

    /// Connections accepted so far.
    fn connections(&self) -> usize {
        self.seen.lock().expect("seen").connections
    }

    fn calls(&self, method: &str) -> Vec<Received> {
        let seen = self.seen.lock().expect("seen");
        seen.calls
            .iter()
            .filter(|call| call.method == method)
            .cloned()
            .collect()
    }

    /// Waits until `done` holds, for up to five seconds.
    fn wait_for(&self, done: impl Fn(&Seen) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if done(&self.seen.lock().expect("seen")) {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }
}

impl Drop for FakeDaemon {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
    }
}

/// Serves one connection until the peer closes it; `true` if the daemon "crashed" instead.
fn serve(stream: &UnixStream, connection: usize, seen: &Mutex<Seen>, stop_after: Option<usize>) -> bool {
    let mut reader = FrameReader::new(stream);
    let mut writer = FrameWriter::new(stream);
    let mut commands = 0;
    loop {
        let Ok(Some(Frame::Json(payload))) = reader.read_frame() else {
            seen.lock().expect("seen").closed += 1;
            return false;
        };
        let Ok(Message::Request(request)) = decode(&payload) else {
            panic!("not a request: {}", String::from_utf8_lossy(&payload));
        };
        let method = request.method.as_str().to_owned();
        seen.lock().expect("seen").calls.push(Received {
            connection,
            method: method.clone(),
            params: request.params.clone().unwrap_or_default(),
        });
        if method == "telemetry.command" {
            commands += 1;
            if stop_after.is_some_and(|limit| commands > limit) {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return true;
            }
        }
        let result = match method.as_str() {
            "hello" => r#"{"protocol":1}"#,
            "session.start_human" => r#"{"session_id":"01JD0000000000000000000000","recording":true}"#,
            "telemetry.command" => r#"{"record_id":"01JD0000000000000000000001"}"#,
            "telemetry.idle" => r#"{"emitted":true}"#,
            _ => "{}",
        };
        let result = knsh_json::parse(result.as_bytes(), 4096).expect("result");
        let answer = Message::Success(SuccessResponse { id: request.id, result });
        if writer.write_json(&answer.to_value().expect("answer")).is_err() || writer.flush().is_err() {
            return false;
        }
    }
}

/// `knsh -i` with `home` as `HOME`, hosting `shell` (`None`: zsh), in a minimal environment plus `extra`.
fn knsh(home: &Home, shell: Option<&str>, extra: &[(&str, &str)]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_knsh"));
    command
        .arg("-i")
        .env_clear()
        .env("HOME", &home.0)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("TERM", "dumb")
        .env("BASH_SILENCE_DEPRECATION_WARNING", "1")
        .current_dir(&home.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(shell) = shell {
        command.env("SHELL", shell);
    }
    for (name, value) in extra {
        command.env(name, value);
    }
    command
}

fn run(mut command: Command, script: &str) -> Output {
    let mut child = command.spawn().expect("spawn knsh");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(script.as_bytes())
        .expect("script");
    child.wait_with_output().expect("wait")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn field<'a>(call: &'a Received, name: &str) -> &'a Value {
    call.params
        .get(name)
        .unwrap_or_else(|| panic!("{name} missing in {call:?}"))
}

const SHELLS: [Option<&str>; 2] = [None, Some("/bin/bash")];

// KNSH-021 integration test: with recording on, three typed commands become exactly three records with only the
// telemetry fields, a `cd` becomes `cwd.changed`, the shell sees KNSH_RECORDING=1, and the session ends (the
// connection closes) when the shell exits.
#[test]
fn three_typed_commands_become_three_records() {
    for shell in SHELLS {
        let home = Home::new(Some(true));
        let daemon = FakeDaemon::start(&home, None);
        // `exit` starts a line too, but its prompt never returns, so it is not a finished command.
        let output = run(
            knsh(&home, shell, &[]),
            "echo one\ncd /\necho \"rec=$KNSH_RECORDING\"\nexit 0\n",
        );
        assert_eq!(output.status.code(), Some(0), "{shell:?}: {}", text(&output.stderr));
        assert!(
            text(&output.stdout).contains("rec=1"),
            "{shell:?}: {}",
            text(&output.stdout)
        );
        assert!(
            daemon.wait_for(|seen| seen.closed == 1),
            "{shell:?}: session never ended"
        );

        let commands = daemon.calls("telemetry.command");
        let typed: Vec<&str> = commands
            .iter()
            .map(|call| field(call, "command").as_str().expect("command"))
            .collect();
        assert_eq!(typed, ["echo one", "cd /", "echo \"rec=$KNSH_RECORDING\""], "{shell:?}");
        for call in &commands {
            // FR-REC-09: these five fields and nothing else.
            let mut keys: Vec<&str> = call.params.iter().map(|(key, _)| key).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                ["command", "cwd", "ended_at", "exit_code", "started_at"],
                "{shell:?}"
            );
            assert_eq!(call.connection, 0, "one session");
        }
        assert_eq!(
            field(&commands[1], "cwd").as_str(),
            Some(home.0.to_str().expect("utf-8"))
        );
        assert_eq!(field(&commands[2], "cwd").as_str(), Some("/"));
        let methods = daemon.methods();
        assert_eq!(methods[..2], ["hello", "session.start_human"], "{shell:?}");
        let cwds = daemon.calls("telemetry.cwd");
        assert_eq!(cwds.len(), 1, "{shell:?}: {methods:?}");
        assert_eq!(field(&cwds[0], "cwd").as_str(), Some("/"));
        assert_eq!(daemon.connections(), 1);
    }
}

// FR-SES-27 integration test: `knsh --native` records typed commands like the hosted shells (the same three records,
// `cd` as `cwd.changed`, `KNSH_RECORDING=1` for the commands), and the session ends when the shell exits. A session
// with recording off never connects and never has the variable, even when inherited (FR-SES-23, FR-SES-25).
#[test]
fn native_session_records_typed_commands() {
    let home = Home::new(Some(true));
    let daemon = FakeDaemon::start(&home, None);
    let mut command = knsh(&home, None, &[]);
    command.arg("--native");
    let output = run(command, "echo one\ncd /\necho \"rec=$KNSH_RECORDING\"\nexit 0\n");
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains("rec=1"), "{}", text(&output.stdout));
    assert!(daemon.wait_for(|seen| seen.closed == 1), "session never ended");

    let commands = daemon.calls("telemetry.command");
    let typed: Vec<&str> = commands
        .iter()
        .map(|call| field(call, "command").as_str().expect("command"))
        .collect();
    assert_eq!(typed, ["echo one", "cd /", "echo \"rec=$KNSH_RECORDING\""]);
    assert_eq!(field(&commands[2], "cwd").as_str(), Some("/"));
    assert_eq!(daemon.calls("telemetry.cwd").len(), 1);
    assert_eq!(daemon.connections(), 1);
}

#[test]
fn native_session_with_recording_off_never_connects() {
    let home = Home::new(Some(false));
    let daemon = FakeDaemon::start(&home, None);
    let mut command = knsh(&home, None, &[("KNSH_RECORDING", "1")]);
    command.arg("--native");
    let output = run(command, "echo \"rec=[$KNSH_RECORDING]\"\nexit 0\n");
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains("rec=[]"), "{}", text(&output.stdout));
    assert_eq!(daemon.connections(), 0);
}

// KNSH-021 integration test (NFR-REL-02): `knshd` stops mid-session; the shell keeps working, its exit status is
// unchanged, and nothing is printed about it.
#[test]
fn shell_keeps_working_when_knshd_stops() {
    for shell in SHELLS {
        let home = Home::new(Some(true));
        let daemon = FakeDaemon::start(&home, Some(1));
        let started = Instant::now();
        let output = run(knsh(&home, shell, &[]), "echo a\necho b\necho c\necho d\nexit 3\n");
        assert_eq!(output.status.code(), Some(3), "{shell:?}: {}", text(&output.stderr));
        assert_eq!(
            text(&output.stdout)
                .lines()
                .filter(|l| l.len() == 1)
                .collect::<Vec<_>>(),
            ["a", "b", "c", "d"]
        );
        assert!(
            !text(&output.stderr).contains("knsh"),
            "{shell:?}: {}",
            text(&output.stderr)
        );
        assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
        // The first line was recorded; the daemon died on the second.
        assert_eq!(
            field(&daemon.calls("telemetry.command")[0], "command").as_str(),
            Some("echo a")
        );
    }
}

// NFR-REL-02: recording on but no `knshd` at all: the shell runs normally and says nothing.
#[test]
fn shell_runs_normally_without_knshd() {
    for shell in SHELLS {
        let home = Home::new(Some(true));
        let output = run(knsh(&home, shell, &[]), "echo \"rec=$KNSH_RECORDING\"\nexit 5\n");
        assert_eq!(output.status.code(), Some(5), "{shell:?}: {}", text(&output.stderr));
        assert!(text(&output.stdout).contains("rec=1"));
        assert!(
            !text(&output.stderr).contains("knsh"),
            "{shell:?}: {}",
            text(&output.stderr)
        );
    }
}

// KNSH-021 (FR-SES-23, FR-SES-25): recording off by default, or turned off explicitly: `knsh` never connects, and
// the shell does not have KNSH_RECORDING even when `knsh` inherited it.
#[test]
fn recording_off_never_connects_and_clears_the_indicator() {
    for (shell, setting) in [(None, None), (Some("/bin/bash"), None), (None, Some(false))] {
        let home = Home::new(setting);
        let daemon = FakeDaemon::start(&home, None);
        let output = run(
            knsh(&home, shell, &[("KNSH_RECORDING", "1")]),
            "echo \"rec=${KNSH_RECORDING-unset}\"\nexit 0\n",
        );
        assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
        assert!(text(&output.stdout).contains("rec=unset"), "{}", text(&output.stdout));
        thread::sleep(Duration::from_millis(100));
        assert_eq!(daemon.connections(), 0, "{shell:?} {setting:?}");
    }
}

// FR-SES-04: an unclear setting keeps recording off and says so once; the shell still starts.
#[test]
fn malformed_setting_keeps_recording_off() {
    let home = Home::new(None);
    home.write_config("[recording]\nhuman = \"yes\"\n");
    let daemon = FakeDaemon::start(&home, None);
    let output = run(knsh(&home, None, &[]), "exit 0\n");
    assert_eq!(output.status.code(), Some(0));
    assert!(
        text(&output.stderr).contains("recording is off"),
        "{}",
        text(&output.stderr)
    );
    assert_eq!(daemon.connections(), 0);
}

/// Starts `knsh` and writes each step's line to it in turn, after pausing for the step's duration.
fn run_slowly(mut command: Command, steps: &[(Duration, &str)]) -> Output {
    let mut child = command.spawn().expect("spawn knsh");
    let mut stdin = child.stdin.take().expect("stdin");
    for (pause, line) in steps {
        thread::sleep(*pause);
        stdin.write_all(line.as_bytes()).expect("line");
        stdin.flush().expect("flush");
    }
    drop(stdin);
    child.wait_with_output().expect("wait")
}

// KNSH-021 (FR-SES-24): a prompt that waits 5 s for input sends `telemetry.idle` once, and again only after a new
// command; a prompt answered quickly sends none.
#[test]
fn idle_prompt_is_reported_once_per_prompt() {
    let home = Home::new(Some(true));
    let daemon = FakeDaemon::start(&home, None);
    let wait = Duration::from_millis(6_500);
    let output = run_slowly(
        knsh(&home, None, &[]),
        &[
            (Duration::ZERO, "echo first\n"),
            (wait, "echo second\n"),
            (Duration::from_millis(200), "echo third\n"),
            (wait, "exit 0\n"),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(daemon.wait_for(|seen| seen.closed == 1));
    let methods: Vec<String> = daemon
        .methods()
        .into_iter()
        .filter(|method| method == "telemetry.idle" || method == "telemetry.command")
        .collect();
    assert_eq!(
        methods,
        [
            "telemetry.command",
            "telemetry.idle",
            "telemetry.command",
            "telemetry.command",
            "telemetry.idle",
        ]
    );
}
