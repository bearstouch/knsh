//! Real clients through the proxy (KNSH-059, KNSH-061; FR-NET-01, FR-NET-06, decision 14; the client matrix of
//! KNSH-027, claim C10).
//!
//! Each test runs the system's tool with a clean environment against a proxy whose test gate routes the name
//! `allowed.test` to a local HTTP server (exempt from the server-name check, like a host in
//! `network.non_tls_hosts`) and `tls.test` to a local server that records the first bytes it receives (checked), so
//! nothing leaves the machine. The recording server speaks no TLS, so a TLS client fails after its `ClientHello`: what
//! is checked is that the hello it sent named the requested host and passed the proxy, or that a forged one never
//! reached the destination. A tool that is not installed skips its test with a note rather than failing.

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
use knsh_proxy::tls::{self, HelloState, ServerName};
use knsh_proxy::{
    Config, ConnectionGate, Denial, Host, Owner, Parts, Proxy, ProxyReport, Refusal, Target, USER_PREFIX,
};

const BODY: &str = "hello through knsh";

/// Routes `allowed.test` to the HTTP server and `tls.test` to the recording server, and records who asked. Only
/// `allowed.test` is exempt from the server-name check.
struct Gate {
    server: SocketAddr,
    recorder: SocketAddr,
    checked: Mutex<Vec<Owner>>,
}

impl ConnectionGate for Gate {
    fn check(&self, owner: &Owner, target: &Target) -> Result<Vec<SocketAddr>, Refusal> {
        self.checked.lock().unwrap().push(*owner);
        match &target.host {
            Host::Name(name) if name == "allowed.test" => Ok(vec![self.server]),
            Host::Name(name) if name == "tls.test" => Ok(vec![self.recorder]),
            Host::Name(_) | Host::Ip(_) => Err(Refusal::HostNotAllowed),
        }
    }

    fn checks_server_name(&self, _owner: &Owner, target: &Target) -> bool {
        target.host != Host::Name("allowed.test".to_owned())
    }
}

/// What the recording server received: the first bytes of each connection, up to a complete `ClientHello`.
type Received = Arc<Mutex<Vec<Vec<u8>>>>;

/// A local server that reads each connection's first bytes until they form a `ClientHello` (or are refused, or 10 s
/// pass), records them, and closes without answering.
fn recording_server() -> (SocketAddr, Received) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let received: Received = Arc::default();
    let sink = Arc::clone(&received);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let sink = Arc::clone(&sink);
            std::thread::spawn(move || {
                stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut data = Vec::new();
                let mut buf = [0; 4096];
                while tls::read_client_hello(&data) == HelloState::Incomplete {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => data.extend_from_slice(&buf[..read]),
                    }
                }
                sink.lock().unwrap().push(data);
            });
        }
    });
    (address, received)
}

#[derive(Default)]
struct Recorder(Mutex<Vec<Denial>>, Mutex<Vec<Target>>);

impl ProxyReport for Recorder {
    fn denied(&self, denial: &Denial) {
        self.0.lock().unwrap().push(denial.clone());
    }

    fn contacted(&self, _owner: &Owner, target: &Target) {
        self.1.lock().unwrap().push(target.clone());
    }
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
    received: Received,
    owner: Owner,
    user: String,
    token: String,
}

fn fixture() -> Fixture {
    let (recorder, received) = recording_server();
    let gate = Arc::new(Gate {
        server: http_server(),
        recorder,
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
        received,
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
fn run(command: Command, home: &Path) -> Output {
    run_with_path(command, home, "/usr/bin:/bin")
}

/// [`run`] with another `PATH`.
fn run_with_path(mut command: Command, home: &Path, path: &str) -> Output {
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", path)
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

impl Fixture {
    /// The server names of the `ClientHello` messages that reached the destination, waiting up to 10 s for at least one.
    fn names_received(&self) -> Vec<HelloState> {
        let started = Instant::now();
        while self.received.lock().unwrap().is_empty() && started.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        self.received
            .lock()
            .unwrap()
            .iter()
            .map(|data| tls::read_client_hello(data))
            .collect()
    }

    /// Asserts that `tool`'s TLS connection to `tls.test` named it, passed the proxy's check and was reported as a
    /// contact, with no refusal but the `407` challenge.
    fn assert_named_tls_test(&self, tool: &str, output: &Output) {
        let names = self.names_received();
        assert!(
            !names.is_empty(),
            "{tool}'s ClientHello never reached the destination: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for name in &names {
            assert_eq!(
                *name,
                HelloState::Complete(ServerName::Name("tls.test".to_owned())),
                "{tool}"
            );
        }
        let refusals = self.report.0.lock().unwrap().clone();
        assert!(
            refusals
                .iter()
                .all(|denial| denial.refusal == Refusal::MissingCredentials),
            "{tool}: {refusals:?}"
        );
        assert!(
            self.report
                .1
                .lock()
                .unwrap()
                .iter()
                .all(|target| target.to_string() == "tls.test:443"),
            "{tool}"
        );
    }
}

// KNSH-061 (FR-NET-06, C10): curl's ClientHello names the requested host and passes the check.
#[test]
fn curl_https_names_the_requested_host() {
    let Some(curl) = tool("/usr/bin/curl") else { return };
    let fixture = fixture();
    let mut command = Command::new(curl);
    command
        .args(["-sS", "--max-time", "20", "-x"])
        .arg(fixture.url("http"))
        .arg("https://tls.test/");
    let output = run(command, &home());
    assert!(!output.status.success(), "the recording server speaks no TLS");
    fixture.assert_named_tls_test("curl", &output);
}

// KNSH-061 forged SNI (FR-NET-06, C10 negative control): `--connect-to` makes curl send `CONNECT tls.test:443` and
// a ClientHello naming `example.test`; the proxy refuses it and the destination receives nothing.
#[test]
fn curl_forged_server_name_is_refused() {
    let Some(curl) = tool("/usr/bin/curl") else { return };
    let fixture = fixture();
    let mut command = Command::new(curl);
    command
        .args([
            "-sS",
            "--max-time",
            "20",
            "--connect-to",
            "example.test:443:tls.test:443",
            "-x",
        ])
        .arg(fixture.url("http"))
        .arg("https://example.test/");
    let output = run(command, &home());
    assert!(!output.status.success());
    let started = Instant::now();
    while fixture.report.0.lock().unwrap().is_empty() && started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    let refusals = fixture.report.0.lock().unwrap().clone();
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert_eq!(refusals[0].refusal, Refusal::ServerNameMismatch);
    assert_eq!(
        refusals[0].target.as_ref().map(ToString::to_string).as_deref(),
        Some("tls.test:443")
    );
    // The recording server may have recorded an empty read at most: no byte of the forged hello reached it.
    assert!(
        fixture.received.lock().unwrap().iter().all(Vec::is_empty),
        "the forged hello reached the destination"
    );
    assert!(
        fixture.report.1.lock().unwrap().is_empty(),
        "a refused tunnel is never a contact"
    );
}

// KNSH-061 (FR-NET-06, C10): git's ClientHello (after the `407` challenge) names the requested host.
#[test]
fn git_https_names_the_requested_host() {
    let Some(git) = tool("/usr/bin/git") else { return };
    let fixture = fixture();
    let home = home();
    let mut command = Command::new(git);
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-c")
        .arg(format!("http.proxy={}", fixture.url("http")))
        .args(["ls-remote", "https://tls.test/repo.git"]);
    let output = run(command, &home);
    if String::from_utf8_lossy(&output.stderr).contains("xcode-select") {
        eprintln!("skipped: git needs the command line tools");
        return;
    }
    assert!(!output.status.success(), "the recording server speaks no TLS");
    fixture.assert_named_tls_test("git", &output);
}

// KNSH-061 (FR-NET-06, C10): npm's ClientHello names the requested host.
#[test]
fn npm_https_names_the_requested_host() {
    let Some(bin) = ["/opt/homebrew/bin", "/usr/local/bin"]
        .into_iter()
        .find(|dir| Path::new(dir).join("npm").exists() && Path::new(dir).join("node").exists())
    else {
        eprintln!("skipped: npm is not installed in /opt/homebrew/bin or /usr/local/bin");
        return;
    };
    let fixture = fixture();
    let mut command = Command::new(Path::new(bin).join("npm"));
    command
        .args(["view", "left-pad", "version", "--registry", "https://tls.test/"])
        .args(["--fetch-retries", "0", "--fetch-timeout", "10000", "--cache"])
        .arg(home().join("npm-cache"))
        .arg("--https-proxy")
        .arg(fixture.url("http"));
    let output = run_with_path(command, &home(), &format!("{bin}:/usr/bin:/bin"));
    assert!(!output.status.success(), "the recording server speaks no TLS");
    fixture.assert_named_tls_test("npm", &output);
}
