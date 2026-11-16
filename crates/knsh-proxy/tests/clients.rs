//! Real clients through the proxy (KNSH-059; FR-NET-01, decision 14; the client matrix of KNSH-027).
//!
//! Each test runs the system's tool with a clean environment against a proxy whose test gate routes the name
//! `allowed.test` to a local HTTP server, so nothing leaves the machine. A tool that is not installed skips its test
//! with a note rather than failing. The matrix's other clients (npm, pip, cargo, Node) need real hosts and TLS,
//! which arrive with host rules (KNSH-060) and the server-name check (KNSH-061).

#![cfg(target_os = "macos")]
// The whole file is test code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use knsh_core::{RecordId, SessionId, Ulid};
use knsh_platform::macos::{SystemClock, SystemRandom};
use knsh_proxy::{
    Config, ConnectionGate, Denial, Host, Owner, Parts, Proxy, ProxyReport, Refusal, Target, USER_PREFIX,
};

const BODY: &str = "hello through knsh";

/// Routes `allowed.test` to the local server and records who asked.
struct Gate {
    server: SocketAddr,
    checked: Mutex<Vec<Owner>>,
}

impl ConnectionGate for Gate {
    fn check(&self, owner: &Owner, target: &Target) -> Result<Vec<SocketAddr>, Refusal> {
        self.checked.lock().unwrap().push(*owner);
        match &target.host {
            Host::Name(name) if name == "allowed.test" => Ok(vec![self.server]),
            Host::Name(_) | Host::Ip(_) => Err(Refusal::HostNotAllowed),
        }
    }
}

#[derive(Default)]
struct Recorder(Mutex<Vec<Denial>>);

impl ProxyReport for Recorder {
    fn denied(&self, denial: &Denial) {
        self.0.lock().unwrap().push(denial.clone());
    }

    fn contacted(&self, _owner: &Owner, _target: &Target) {}
}

/// A local HTTP server: every connection gets a fixed `200` after its first read.
fn http_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            std::thread::spawn(move || {
                let mut buf = [0; 4096];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                    BODY.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    address
}

struct Fixture {
    proxy: Proxy,
    gate: Arc<Gate>,
    report: Arc<Recorder>,
    owner: Owner,
    user: String,
    token: String,
}

fn fixture() -> Fixture {
    let gate = Arc::new(Gate {
        server: http_server(),
        checked: Mutex::new(Vec::new()),
    });
    let report = Arc::new(Recorder::default());
    let proxy = Proxy::start(
        Config::DEFAULT,
        Parts {
            gate: Arc::clone(&gate) as Arc<dyn ConnectionGate>,
            report: Arc::clone(&report) as Arc<dyn ProxyReport>,
            random: Arc::new(SystemRandom::new()),
            clock: Arc::new(SystemClock::new()),
        },
    )
    .unwrap();
    let owner = Owner {
        session: SessionId::from_ulid(Ulid::from_u128(1)),
        line: Some(RecordId::from_ulid(Ulid::from_u128(2))),
    };
    let issued = proxy.issue(owner).unwrap();
    let user = format!("{USER_PREFIX}{}", issued.id());
    let token = issued.token().expose().clone();
    Fixture {
        proxy,
        gate,
        report,
        owner,
        user,
        token,
    }
}

impl Fixture {
    /// `<scheme>://knsh-<id>:<token>@127.0.0.1:<port>`, as decision 14 puts it in the environment.
    fn url(&self, scheme: &str) -> String {
        format!(
            "{scheme}://{}:{}@127.0.0.1:{}",
            self.user,
            self.token,
            self.proxy.port()
        )
    }
}

/// `tool` if it is installed, or `None` with a note.
fn tool(path: &str) -> Option<&str> {
    if Path::new(path).exists() {
        Some(path)
    } else {
        eprintln!("skipped: {path} is not installed");
        None
    }
}

/// Runs `command` with a clean environment and an empty home, killed after 30 s.
fn run(mut command: Command, home: &Path) -> Output {
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

fn home() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("knsh-proxy-clients-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// FR-NET-01, decision 14: curl tunnels through CONNECT with the URL's credentials.
#[test]
fn curl_through_http_connect() {
    let Some(curl) = tool("/usr/bin/curl") else { return };
    let fixture = fixture();
    let mut command = Command::new(curl);
    command
        .args(["-sS", "--max-time", "20", "--proxytunnel", "-x"])
        .arg(fixture.url("http"))
        .arg("http://allowed.test/");
    let output = run(command, &home());
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout), BODY);
    assert_eq!(*fixture.gate.checked.lock().unwrap(), [fixture.owner]);
}

// FR-NET-01: without credentials curl gets the 407 challenge and nothing else.
#[test]
fn curl_without_credentials_gets_407() {
    let Some(curl) = tool("/usr/bin/curl") else { return };
    let fixture = fixture();
    let mut command = Command::new(curl);
    command
        .args([
            "-sS",
            "--max-time",
            "20",
            "--proxytunnel",
            "-w",
            "%{http_connect}",
            "-x",
        ])
        .arg(format!("http://127.0.0.1:{}", fixture.proxy.port()))
        .arg("http://allowed.test/");
    let output = run(command, &home());
    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "407");
    assert!(fixture.gate.checked.lock().unwrap().is_empty());
    assert_eq!(fixture.report.0.lock().unwrap()[0].refusal, Refusal::MissingCredentials);
}

// FR-NET-01: curl over SOCKS5 with RFC 1929 credentials, the name resolved by the proxy (socks5h).
#[test]
fn curl_through_socks5() {
    let Some(curl) = tool("/usr/bin/curl") else { return };
    let fixture = fixture();
    let mut command = Command::new(curl);
    command
        .args(["-sS", "--max-time", "20", "-x"])
        .arg(fixture.url("socks5h"))
        .arg("http://allowed.test/");
    let output = run(command, &home());
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout), BODY);
    assert_eq!(*fixture.gate.checked.lock().unwrap(), [fixture.owner]);
}

// KNSH-027, C9: git sends proxy credentials only after a 407 with a Basic challenge; with it, its CONNECT reaches
// the gate as the command's. (The local server does not speak TLS, so git then fails: only the CONNECT is checked.)
#[test]
fn git_authenticates_after_the_challenge() {
    let Some(git) = tool("/usr/bin/git") else { return };
    let fixture = fixture();
    let home = home();
    let mut command = Command::new(git);
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-c")
        .arg(format!("http.proxy={}", fixture.url("http")))
        .args(["ls-remote", "https://allowed.test/repo.git"]);
    let output = run(command, &home);
    // The xcode-select stub prints this when no developer tools are installed.
    if String::from_utf8_lossy(&output.stderr).contains("xcode-select") {
        eprintln!("skipped: git needs the command line tools");
        return;
    }
    assert!(
        fixture.gate.checked.lock().unwrap().contains(&fixture.owner),
        "git's CONNECT never authenticated: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let refusals = fixture.report.0.lock().unwrap().clone();
    assert!(
        refusals
            .iter()
            .all(|denial| denial.refusal == Refusal::MissingCredentials),
        "{refusals:?}"
    );
}
