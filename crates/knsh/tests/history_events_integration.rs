//! End-to-end checks of `knsh history` and `knsh events` (KNSH-023) through the real `knsh` binary and a stand-in for
//! `knshd`: a Unix socket at the engine's `user.sock` path that answers `hello`, `records.query` and
//! `events.subscribe` from a script. `knshd`'s side of these methods is tested in `knshd` and `knsh-store`.
//!
//! Every test uses a short temporary `HOME` under `/tmp` (a socket path must fit in 104 bytes), never the user's real
//! one.

#![cfg(all(test, target_os = "macos"))]
#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use knsh_json::{Frame, FrameReader, FrameWriter, Value};
use knsh_platform::macos::{RealFs, effective_uid};
use knsh_platform::{EnginePaths, ensure_engine_dirs};
use knsh_proto::{Message, SuccessResponse, decode};

const SESSION: &str = "01JCZ0000000000000000000CD";

/// A short temporary home, removed when dropped.
struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(format!("/private/tmp/knshhe-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("home");
        let home = Self(dir);
        ensure_engine_dirs(&RealFs::new(), &home.paths(), effective_uid()).expect("engine dirs");
        home
    }

    fn paths(&self) -> EnginePaths {
        EnginePaths::for_home(&self.0).expect("paths")
    }

    fn knsh(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_knsh"))
            .args(args)
            .env_clear()
            .env("HOME", &self.0)
            .output()
            .expect("run knsh")
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A stand-in `knshd` serving one connection: answers `hello`, then each other call with the next scripted result.
/// After answering `events.subscribe` it sends `events` as notifications and closes the connection. Returns the
/// requests it received (method and params as JSON text).
fn fake_daemon(home: &Home, results: Vec<&'static str>, events: Vec<String>) -> Arc<Mutex<Vec<String>>> {
    let listener = UnixListener::bind(home.paths().user_socket()).expect("bind user.sock");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let shared = Arc::clone(&seen);
    thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else { return };
        serve(&stream, results, &events, &shared);
    });
    seen
}

fn serve(stream: &UnixStream, results: Vec<&str>, events: &[String], seen: &Mutex<Vec<String>>) {
    let mut reader = FrameReader::new(stream);
    let mut writer = FrameWriter::new(stream);
    let mut results = results.into_iter();
    while let Ok(Some(Frame::Json(payload))) = reader.read_frame() {
        let Ok(Message::Request(request)) = decode(&payload) else {
            panic!("not a request: {}", String::from_utf8_lossy(&payload));
        };
        let method = request.method.as_str().to_owned();
        let params = request.params.clone().unwrap_or_default();
        seen.lock().expect("seen").push(format!(
            "{method} {}",
            knsh_json::write(&Value::Object(params)).expect("params")
        ));
        let result = if method == "hello" {
            r#"{"protocol":1}"#
        } else {
            results.next().expect("a scripted result")
        };
        let result = knsh_json::parse(result.as_bytes(), 1 << 16).expect("result");
        let answer = Message::Success(SuccessResponse { id: request.id, result });
        writer.write_json(&answer.to_value().expect("answer")).expect("answer");
        writer.flush().expect("flush");
        if method == "events.subscribe" {
            for event in events {
                writer
                    .write_json(&knsh_json::parse(event.as_bytes(), 1 << 16).expect("event"))
                    .expect("event");
            }
            writer.flush().expect("flush");
            // `knshd` going away ends the stream.
            return;
        }
    }
}

// KNSH-023: `knsh history` reads every page and prints newest first; the hostile command is escaped.
#[test]
fn history_prints_newest_first_and_escapes_commands() {
    let home = Home::new();
    let seen = fake_daemon(
        &home,
        vec![
            r#"{"records":[{"record_id":"01JCZ0000000000000000000A1","session_id":"01JCZ0000000000000000000CD",
                "actor":{"kind":"human"},"command":"first","cwd":"/","started_at":"2026-11-12T18:00:00.000000Z",
                "ended_at":null,"exit_code":null,"stdout":null,"stderr":null}],"next_cursor":"01JCZ0000000000000000000A1"}"#,
            r#"{"records":[{"record_id":"01JCZ0000000000000000000A2","session_id":"01JCZ0000000000000000000CD",
                "actor":{"kind":"human"},"command":"printf '\u001b[2J'\u009b","cwd":"/",
                "started_at":"2026-11-12T18:01:00.000000Z","ended_at":"2026-11-12T18:01:01.000000Z","exit_code":0,
                "stdout":null,"stderr":null}],"next_cursor":null}"#,
        ],
        Vec::new(),
    );
    let output = home.knsh(&["history", "--session", SESSION, "--since", "2026-11-12"]);
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout,
        format!(
            "2026-11-12T18:01:00.000000Z  {SESSION}  human  exit 0  printf '\\e[2J'\\u{{9b}}\n\
             2026-11-12T18:00:00.000000Z  {SESSION}  human  -  first\n"
        )
    );
    let seen = seen.lock().expect("seen").clone();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(
        seen[1],
        format!(r#"records.query {{"session_id":"{SESSION}","since":"2026-11-12T00:00:00.000000Z","limit":1000}}"#)
    );
    assert!(
        seen[2].contains(r#""cursor":"01JCZ0000000000000000000A1""#),
        "{}",
        seen[2]
    );
}

// KNSH-023: `knsh events --json` prints one event per line as they arrive; `knshd` closing the stream exits with 1.
#[test]
fn events_json_streams_one_event_per_line() {
    let home = Home::new();
    let event = |seq: u32| {
        format!(
            r#"{{"jsonrpc":"2.0","method":"session.idle","params":{{"event":"session.idle",
                "id":"01JCZ00000000000000000E{seq:03}","seq":{seq},"ts":"2026-11-12T18:02:11.204913Z",
                "session_id":"{SESSION}","actor":{{"kind":"human"}},"data":{{}},"subscription_id":1}}}}"#
        )
    };
    let seen = fake_daemon(
        &home,
        vec![r#"{"subscription_id":1,"oldest_seq":1,"latest_seq":4,"gap":false}"#],
        vec![event(3), event(4)],
    );
    let output = home.knsh(&["events", "--session", SESSION, "--since", "2", "--json"]);
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("knshd closed the connection"), "{stderr}");
    let lines: Vec<&str> = stdout.split_terminator('\n').collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    for (line, seq) in lines.iter().zip([3, 4]) {
        let value = knsh_json::parse(line.as_bytes(), 1 << 16).expect("one JSON value per line");
        assert_eq!(value.as_object().and_then(|o| o.get("seq")), Some(&Value::from(seq)));
    }
    assert_eq!(
        seen.lock().expect("seen")[1],
        format!(r#"events.subscribe {{"session_id":"{SESSION}","since_seq":2}}"#)
    );
}

// KNSH-023: without `knshd`, both commands fail with 1 and a clear message, and print nothing on stdout.
#[test]
fn history_and_events_without_knshd_fail_with_1() {
    let home = Home::new();
    for args in [&["history"][..], &["events", "--json"]] {
        let output = home.knsh(args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(stderr.contains("cannot reach knshd"), "{args:?}: {stderr}");
        assert_eq!(output.stdout, b"", "{args:?}");
    }
}

// KNSH-023: malformed values are usage errors (exit 2) and nothing is sent.
#[test]
fn history_and_events_usage_errors_exit_2() {
    let home = Home::new();
    for args in [
        &["history", "--limit", "0"][..],
        &["history", "--since", "yesterday"],
        &["history", "--session", "abc"],
        &["events", "--since", "3"],
        &["events", "--session", SESSION, "--since", "x"],
    ] {
        let output = home.knsh(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(output.stdout, b"", "{args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("--"), "{args:?}");
    }
}
