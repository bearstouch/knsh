//! The proxy over real loopback sockets: a test gate routes names to local echo servers, and a recorder keeps what
//! was reported.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use knsh_core::{RecordId, SessionId, Ulid};
use knsh_platform::macos::{SystemClock, SystemRandom};

use super::*;
use crate::credentials::USER_PREFIX;

/// Routes names to addresses; allowlists IP literals; records every question.
#[derive(Default)]
struct TestGate {
    routes: HashMap<String, Vec<SocketAddr>>,
    allowed_ips: Vec<IpAddr>,
    checked: Mutex<Vec<(Owner, Target)>>,
}

impl ConnectionGate for TestGate {
    fn check(&self, owner: &Owner, target: &Target) -> Result<Vec<SocketAddr>, Refusal> {
        self.checked.lock().unwrap().push((*owner, target.clone()));
        match &target.host {
            Host::Name(name) => self.routes.get(name).cloned().ok_or(Refusal::HostNotAllowed),
            Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, target.port.get())]),
        }
    }

    fn allows_ip_literal(&self, _owner: &Owner, ip: IpAddr, _port: NonZeroU16) -> bool {
        self.allowed_ips.contains(&ip)
    }
}

#[derive(Default)]
struct Recorder(Mutex<Vec<Denial>>, Mutex<Vec<(Owner, Target)>>);

impl ProxyReport for Recorder {
    fn denied(&self, denial: &Denial) {
        self.0.lock().unwrap().push(denial.clone());
    }

    fn contacted(&self, owner: &Owner, target: &Target) {
        self.1.lock().unwrap().push((*owner, target.clone()));
    }
}

impl Recorder {
    /// The refusals reported so far, waiting briefly for the connection thread to report.
    fn refusals(&self, at_least: usize) -> Vec<Denial> {
        let started = Instant::now();
        while self.0.lock().unwrap().len() < at_least && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.0.lock().unwrap().clone()
    }
}

/// An echo server on loopback: every connection gets back what it sends, until it closes.
fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            std::thread::spawn(move || {
                let mut buf = [0; 4096];
                while let Ok(read) = stream.read(&mut buf) {
                    if read == 0 || stream.write_all(&buf[..read]).is_err() {
                        break;
                    }
                }
                let _ = stream.shutdown(Shutdown::Write);
            });
        }
    });
    address
}

/// A loopback address where nothing listens: connecting is refused at once.
fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// A server on loopback that accepts connections and never reads, writes or closes them.
fn silent_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            held.push(stream);
        }
    });
    address
}

struct Fixture {
    proxy: Proxy,
    gate: Arc<TestGate>,
    report: Arc<Recorder>,
    echo: SocketAddr,
}

const SHORT: Duration = Duration::from_secs(5);

fn fixture_with(config: Config) -> Fixture {
    let echo = echo_server();
    let mut gate = TestGate::default();
    gate.routes.insert("allowed.test".to_owned(), vec![echo]);
    gate.routes.insert("silent.test".to_owned(), vec![silent_server()]);
    // The first address refuses connections; the second, also checked, answers.
    gate.routes
        .insert("fallback.test".to_owned(), vec![closed_port(), echo]);
    gate.allowed_ips.push("127.0.0.1".parse().unwrap());
    let gate = Arc::new(gate);
    let report = Arc::new(Recorder::default());
    let proxy = Proxy::start(
        config,
        Parts {
            gate: Arc::clone(&gate) as Arc<dyn ConnectionGate>,
            report: Arc::clone(&report) as Arc<dyn ProxyReport>,
            random: Arc::new(SystemRandom::new()),
            clock: Arc::new(SystemClock::new()),
        },
    )
    .unwrap();
    Fixture {
        proxy,
        gate,
        report,
        echo,
    }
}

fn fixture() -> Fixture {
    fixture_with(Config {
        handshake_timeout: SHORT,
        connect_timeout: SHORT,
        ..Config::DEFAULT
    })
}

fn session(n: u128) -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(n))
}

fn record(n: u128) -> RecordId {
    RecordId::from_ulid(Ulid::from_u128(n))
}

fn line_owner() -> Owner {
    Owner {
        session: session(1),
        line: Some(record(10)),
    }
}

/// `knsh-<id>` and the token.
fn login(issued: &Issued) -> (String, String) {
    (format!("{USER_PREFIX}{}", issued.id()), issued.token().expose().clone())
}

/// `Basic base64(user:password)`, encoded here independently of the crate's decoder.
fn basic(user: &str, password: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("{user}:{password}").into_bytes();
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let bytes = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    format!("Basic {out}")
}

fn open(proxy: &Proxy) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", proxy.port().get())).unwrap();
    stream.set_read_timeout(Some(SHORT)).unwrap();
    stream
}

/// Reads a response head (up to its empty line).
fn response_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8(head).unwrap()
}

/// Sends `CONNECT target` with optional credentials and returns the stream and the response head.
fn connect(proxy: &Proxy, target: &str, authorization: Option<&str>) -> (TcpStream, String) {
    let mut stream = open(proxy);
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(authorization) = authorization {
        let _ = write!(request, "Proxy-Authorization: {authorization}\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let head = response_head(&mut stream);
    (stream, head)
}

/// Whether the peer closed: end of stream or an error, and no data.
fn closed(stream: &mut TcpStream) -> bool {
    let mut buf = [0; 16];
    matches!(stream.read(&mut buf), Ok(0) | Err(_))
}

fn echoes(stream: &mut TcpStream, data: &[u8]) -> bool {
    stream.write_all(data).unwrap();
    let mut back = vec![0; data.len()];
    stream.read_exact(&mut back).is_ok() && back == data
}

// FR-NET-01: the proxy listens on loopback.
#[test]
fn listens_on_loopback() {
    let fixture = fixture();
    let stream = open(&fixture.proxy);
    assert_eq!(
        stream.peer_addr().unwrap(),
        SocketAddr::from(([127, 0, 0, 1], fixture.proxy.port().get()))
    );
}

// FR-NET-01: CONNECT with live credentials opens a byte-for-byte tunnel; bytes sent right after the head are kept.
#[test]
fn tunnels_connect_byte_for_byte() {
    let fixture = fixture();
    let (user, token) = login(&fixture.proxy.issue(line_owner()).unwrap());
    let mut stream = open(&fixture.proxy);
    let request = format!(
        "CONNECT allowed.test:443 HTTP/1.1\r\nProxy-Authorization: {}\r\n\r\n\x16\x03\n\rearly",
        basic(&user, &token)
    );
    stream.write_all(request.as_bytes()).unwrap();
    let head = response_head(&mut stream);
    assert_eq!(head, "HTTP/1.1 200 Connection established\r\n\r\n");
    let mut early = [0; 9];
    stream.read_exact(&mut early).unwrap();
    assert_eq!(&early, b"\x16\x03\n\rearly");
    let all: Vec<u8> = (0..=255).collect();
    assert!(echoes(&mut stream, &all));
    assert_eq!(fixture.report.refusals(0), []);
}

// FR-NET-01: credentials map each connection to its command and session; the gate sees that owner.
#[test]
fn maps_credentials_to_command_and_session() {
    let fixture = fixture();
    let envelope = Owner {
        session: session(2),
        line: None,
    };
    for owner in [line_owner(), envelope] {
        let (user, token) = login(&fixture.proxy.issue(owner).unwrap());
        let (_stream, head) = connect(&fixture.proxy, "Allowed.Test.:443", Some(&basic(&user, &token)));
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    }
    let checked = fixture.gate.checked.lock().unwrap().clone();
    let owners: Vec<Owner> = checked.iter().map(|(owner, _)| *owner).collect();
    assert_eq!(owners, [line_owner(), envelope]);
    // The gate sees the normalised name.
    assert_eq!(checked[0].1.to_string(), "allowed.test:443");
}

// FR-NET-01, decision 14: missing or unknown credentials get 407 with the Basic challenge, and are reported.
#[test]
fn refuses_unknown_credentials_with_407() {
    let fixture = fixture();
    let (user, token) = login(&fixture.proxy.issue(line_owner()).unwrap());
    let unknown = [
        None,
        Some(basic(&user, "WRONGtoken")),
        Some(basic("knsh-999", &token)),
        Some(basic("someone", &token)),
        Some(format!("Bearer {token}")),
        Some("Basic !!!!".to_owned()),
    ];
    for authorization in &unknown {
        let (mut stream, head) = connect(&fixture.proxy, "allowed.test:443", authorization.as_deref());
        assert!(head.starts_with("HTTP/1.1 407 "), "{head}");
        assert!(
            head.contains("\r\nProxy-Authenticate: Basic realm=\"knsh\"\r\n"),
            "{head}"
        );
        assert!(closed(&mut stream));
    }
    let refusals = fixture.report.refusals(unknown.len());
    assert_eq!(refusals[0].refusal, Refusal::MissingCredentials);
    for denial in &refusals[1..] {
        assert_eq!(denial.refusal, Refusal::UnknownCredentials);
        assert_eq!(denial.owner, None);
        assert_eq!(denial.protocol, Some(Protocol::Http));
    }
    assert!(
        fixture.gate.checked.lock().unwrap().is_empty(),
        "no destination was checked"
    );
}

// FR-NET-01: a line's credentials stop working when it ends, and its open tunnels close; the envelope's stay.
#[test]
fn revokes_credentials_when_line_ends() {
    let fixture = fixture();
    let line = basic_for(&fixture.proxy, line_owner());
    let envelope = basic_for(
        &fixture.proxy,
        Owner {
            session: session(1),
            line: None,
        },
    );
    let (mut open_tunnel, head) = connect(&fixture.proxy, "allowed.test:443", Some(&line));
    assert!(head.starts_with("HTTP/1.1 200 "));
    assert!(echoes(&mut open_tunnel, b"before"));

    fixture.proxy.revoke_line(record(10));
    assert!(closed(&mut open_tunnel), "the line's tunnel is closed at once");
    let (_stream, head) = connect(&fixture.proxy, "allowed.test:443", Some(&line));
    assert!(head.starts_with("HTTP/1.1 407 "), "{head}");
    let (mut still, head) = connect(&fixture.proxy, "allowed.test:443", Some(&envelope));
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert!(echoes(&mut still, b"envelope"));

    // The session's end takes the envelope's credentials and tunnels too.
    fixture.proxy.revoke_session(session(1));
    assert!(closed(&mut still));
    let (_stream, head) = connect(&fixture.proxy, "allowed.test:443", Some(&envelope));
    assert!(head.starts_with("HTTP/1.1 407 "), "{head}");
    assert_eq!(fixture.proxy.live_credentials(), 0);
}

fn basic_for(proxy: &Proxy, owner: Owner) -> String {
    let (user, token) = login(&proxy.issue(owner).unwrap());
    basic(&user, &token)
}

// NFR-SEC-05, NFR-SEC-07: malformed and oversized requests are refused, never repaired, before any destination is
// checked.
#[test]
fn rejects_malformed_connect_without_recovery() {
    let fixture = fixture();
    let auth = basic_for(&fixture.proxy, line_owner());
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (b"CONNECT allowed.test:443 HTTP/1.1\n\n".to_vec(), "HTTP/1.1 400 "),
        (
            format!("CONNECT allowed.test:443 HTTP/1.1\r\nProxy-Authorization: {auth}\r\n folded\r\n\r\n").into_bytes(),
            "HTTP/1.1 400 ",
        ),
        (
            format!("CONNECT allowed.test HTTP/1.1\r\nProxy-Authorization: {auth}\r\n\r\n").into_bytes(),
            "HTTP/1.1 400 ",
        ),
        (
            format!(
                "CONNECT allowed.test:443 HTTP/1.1\r\nProxy-Authorization: {auth}\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .into_bytes(),
            "HTTP/1.1 400 ",
        ),
        (
            format!("CONNECT {}:443 HTTP/1.1\r\n\r\n", "a".repeat(http::MAX_REQUEST_LINE)).into_bytes(),
            "HTTP/1.1 431 ",
        ),
    ];
    for (request, expected) in &cases {
        let mut stream = open(&fixture.proxy);
        stream.write_all(request).unwrap();
        let head = response_head(&mut stream);
        assert!(
            head.starts_with(expected),
            "{head} for {:?}",
            String::from_utf8_lossy(request)
        );
    }
    let refusals = fixture.report.refusals(cases.len());
    assert!(refusals.iter().all(|denial| denial.refusal == Refusal::Malformed));
    assert!(fixture.gate.checked.lock().unwrap().is_empty());
}

// Plain-HTTP absolute-URI requests and other methods are refused, not forwarded.
#[test]
fn refuses_methods_other_than_connect() {
    let fixture = fixture();
    let auth = basic_for(&fixture.proxy, line_owner());
    let mut stream = open(&fixture.proxy);
    let request =
        format!("GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\nProxy-Authorization: {auth}\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let head = response_head(&mut stream);
    assert!(
        head.starts_with("HTTP/1.1 405 ") && head.contains("Allow: CONNECT"),
        "{head}"
    );
    let refusals = fixture.report.refusals(1);
    assert_eq!(refusals[0].refusal, Refusal::UnsupportedProtocol);
    assert_eq!(refusals[0].owner, Some(line_owner()));
}

// FR-NET-05: an IP literal is refused unless allowlisted, without asking the gate for an address.
#[test]
fn refuses_ip_literal_target() {
    let fixture = fixture();
    let auth = basic_for(&fixture.proxy, line_owner());
    for target in ["10.1.2.3:443", "[::1]:443"] {
        let (_stream, head) = connect(&fixture.proxy, target, Some(&auth));
        assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
    }
    assert!(fixture.gate.checked.lock().unwrap().is_empty());
    // SOCKS5 takes the same path: an IPv4 address and a domain spelling one.
    let socks_auth = login(&fixture.proxy.issue(line_owner()).unwrap());
    for request in [
        vec![5, 1, 0, 1, 10, 1, 2, 3, 1, 187],
        b"\x05\x01\x00\x03\x0810.1.2.3\x01\xbb".to_vec(),
    ] {
        let mut stream = socks5_authenticated(&fixture.proxy, &socks_auth);
        stream.write_all(&request).unwrap();
        assert_eq!(socks5_reply(&mut stream)[1], 0x02, "connection not allowed by ruleset");
    }
    let refusals = fixture.report.refusals(4);
    assert!(refusals.iter().all(|denial| denial.refusal == Refusal::IpLiteral));
    assert_eq!(refusals[3].protocol, Some(Protocol::Socks5));
    assert!(fixture.gate.checked.lock().unwrap().is_empty());
    // An allowlisted address goes through.
    let target = format!("127.0.0.1:{}", fixture.echo.port());
    let (mut stream, head) = connect(&fixture.proxy, &target, Some(&auth));
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert!(echoes(&mut stream, b"allowlisted"));
}

// FR-NET-09: a gate refusal is answered 403 and reported with owner and destination; an unreachable one is 502.
#[test]
fn reports_gate_refusals_and_unreachable_destinations() {
    let fixture = fixture();
    let auth = basic_for(&fixture.proxy, line_owner());
    let (_stream, head) = connect(&fixture.proxy, "denied.test:443", Some(&auth));
    assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
    // A port nothing listens on.
    let closed_port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let (_stream, head) = connect(&fixture.proxy, &format!("127.0.0.1:{closed_port}"), Some(&auth));
    assert!(head.starts_with("HTTP/1.1 502 "), "{head}");
    let refusals = fixture.report.refusals(2);
    assert_eq!(refusals[0].refusal, Refusal::HostNotAllowed);
    assert_eq!(refusals[0].owner, Some(line_owner()));
    assert_eq!(refusals[0].target.as_ref().unwrap().to_string(), "denied.test:443");
    assert_eq!(refusals[1].refusal, Refusal::Unreachable);
}

/// Greets with username/password, authenticates, and returns the stream ready for a request.
fn socks5_authenticated(proxy: &Proxy, (user, token): &(String, String)) -> TcpStream {
    let mut stream = open(proxy);
    stream.write_all(&[5, 2, 0, 2]).unwrap();
    let mut chosen = [0; 2];
    stream.read_exact(&mut chosen).unwrap();
    assert_eq!(chosen, [5, 2]);
    let mut auth = vec![1, u8::try_from(user.len()).unwrap()];
    auth.extend_from_slice(user.as_bytes());
    auth.push(u8::try_from(token.len()).unwrap());
    auth.extend_from_slice(token.as_bytes());
    stream.write_all(&auth).unwrap();
    let mut status = [0; 2];
    stream.read_exact(&mut status).unwrap();
    assert_eq!(status, [1, 0]);
    stream
}

fn socks5_reply(stream: &mut TcpStream) -> [u8; 10] {
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).unwrap();
    reply
}

// FR-NET-01: SOCKS5 with RFC 1929 credentials maps to the command and opens a tunnel.
#[test]
fn accepts_socks5_with_valid_credentials() {
    let fixture = fixture();
    let credentials = login(&fixture.proxy.issue(line_owner()).unwrap());
    let mut stream = socks5_authenticated(&fixture.proxy, &credentials);
    stream.write_all(b"\x05\x01\x00\x03\x0cALLOWED.test\x01\xbb").unwrap();
    assert_eq!(socks5_reply(&mut stream), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert!(echoes(&mut stream, b"\x00socks\xff"));
    let checked = fixture.gate.checked.lock().unwrap().clone();
    assert_eq!(checked.len(), 1);
    assert_eq!(checked[0].0, line_owner());
    assert_eq!(checked[0].1.to_string(), "allowed.test:443");
}

// FR-NET-01: a greeting without username/password is refused with "no acceptable methods"; bad credentials fail.
#[test]
fn refuses_no_auth_method() {
    let fixture = fixture();
    let mut stream = open(&fixture.proxy);
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut answer = [0; 2];
    stream.read_exact(&mut answer).unwrap();
    assert_eq!(answer, [5, 0xff]);
    assert!(closed(&mut stream));

    let (user, _) = login(&fixture.proxy.issue(line_owner()).unwrap());
    let mut stream = open(&fixture.proxy);
    let mut request = vec![5, 1, 2, 1, u8::try_from(user.len()).unwrap()];
    request.extend_from_slice(user.as_bytes());
    request.extend_from_slice(&[5, b'w', b'r', b'o', b'n', b'g']);
    stream.write_all(&request).unwrap();
    let mut answers = [0; 4];
    stream.read_exact(&mut answers).unwrap();
    assert_eq!(answers, [5, 2, 1, 1]);
    assert!(closed(&mut stream));
    let refusals = fixture.report.refusals(2);
    assert_eq!(refusals[0].refusal, Refusal::MissingCredentials);
    assert_eq!(refusals[1].refusal, Refusal::UnknownCredentials);
}

// FR-NET-05: BIND and UDP ASSOCIATE are refused with "command not supported"; SOCKS4 is rejected.
#[test]
fn refuses_udp_associate_and_bind() {
    let fixture = fixture();
    let credentials = login(&fixture.proxy.issue(line_owner()).unwrap());
    for command in [2, 3] {
        let mut stream = socks5_authenticated(&fixture.proxy, &credentials);
        stream.write_all(&[5, command, 0, 1, 127, 0, 0, 1, 0, 80]).unwrap();
        assert_eq!(socks5_reply(&mut stream)[1], 0x07);
        assert!(closed(&mut stream));
    }
    let mut socks4 = open(&fixture.proxy);
    socks4.write_all(b"\x04\x01\x01\xbb\x7f\x00\x00\x01knsh\x00").unwrap();
    let mut answer = [0; 8];
    socks4.read_exact(&mut answer).unwrap();
    assert_eq!(answer[1], 0x5b);
    let refusals = fixture.report.refusals(3);
    assert_eq!(refusals[0].refusal, Refusal::UnsupportedCommand);
    assert_eq!(refusals[1].refusal, Refusal::UnsupportedCommand);
    assert_eq!(refusals[2].refusal, Refusal::UnsupportedProtocol);
    assert_eq!(refusals[2].protocol, Some(Protocol::Socks4));
    assert!(fixture.gate.checked.lock().unwrap().is_empty());
}

// A client that never finishes its handshake is cut off at the handshake timeout.
#[test]
fn closes_slow_handshakes() {
    let fixture = fixture_with(Config {
        handshake_timeout: Duration::from_millis(200),
        ..Config::DEFAULT
    });
    let started = Instant::now();
    let mut stream = open(&fixture.proxy);
    stream.write_all(b"CONNECT allowed.test:443 HTTP/1.1\r\n").unwrap();
    assert!(closed(&mut stream));
    assert!(started.elapsed() < Duration::from_secs(4));
}

// Connections beyond the limit are closed on accept and reported.
#[test]
fn refuses_connections_beyond_the_limit() {
    let fixture = fixture_with(Config {
        handshake_timeout: SHORT,
        max_connections: 1,
        ..Config::DEFAULT
    });
    let _first = open(&fixture.proxy);
    let started = Instant::now();
    while fixture.proxy.live_connections() < 1 && started.elapsed() < SHORT {
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut second = open(&fixture.proxy);
    assert!(closed(&mut second));
    assert_eq!(fixture.report.refusals(1)[0].refusal, Refusal::Busy);
}

// The idle timeout closes a tunnel through the proxy.
#[test]
fn closes_idle_tunnels() {
    let fixture = fixture_with(Config {
        handshake_timeout: SHORT,
        idle_timeout: Duration::from_millis(200),
        ..Config::DEFAULT
    });
    let auth = basic_for(&fixture.proxy, line_owner());
    let (mut stream, head) = connect(&fixture.proxy, "allowed.test:443", Some(&auth));
    assert!(head.starts_with("HTTP/1.1 200 "));
    let started = Instant::now();
    assert!(closed(&mut stream));
    assert!(started.elapsed() >= Duration::from_millis(150));
}

// Stopping the proxy closes its tunnels.
#[test]
fn drop_closes_connections() {
    let fixture = fixture();
    let auth = basic_for(&fixture.proxy, line_owner());
    let (mut stream, head) = connect(&fixture.proxy, "allowed.test:443", Some(&auth));
    assert!(head.starts_with("HTTP/1.1 200 "));
    drop(fixture.proxy);
    assert!(closed(&mut stream));
}

// FR-NET-01: revocation closes the destination side too, so a tunnel to a destination that never closes does not
// keep its connection (and thread) until the idle timeout.
#[test]
fn revocation_closes_tunnels_to_silent_destinations() {
    let fixture = fixture();
    let auth = basic_for(&fixture.proxy, line_owner());
    let (mut stream, head) = connect(&fixture.proxy, "silent.test:443", Some(&auth));
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert_eq!(fixture.proxy.live_connections(), 1);
    fixture.proxy.revoke_line(record(10));
    assert!(closed(&mut stream));
    let started = Instant::now();
    while fixture.proxy.live_connections() > 0 && started.elapsed() < SHORT {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        fixture.proxy.live_connections(),
        0,
        "the tunnel ended with its credentials"
    );
}

// KNSH-060 connects_to_checked_address_without_reresolving (FR-NET-07): the proxy connects only to the addresses
// the gate checked, in order (here the first refuses and the second answers), and reports the contact once.
#[test]
fn connects_only_to_checked_addresses_in_order() {
    let fixture = fixture();
    let (user, token) = login(&fixture.proxy.issue(line_owner()).unwrap());
    let (mut stream, head) = connect(&fixture.proxy, "fallback.test:443", Some(&basic(&user, &token)));
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert!(echoes(&mut stream, b"through the second address"));
    assert_eq!(
        fixture.gate.checked.lock().unwrap().len(),
        1,
        "one decision, no second lookup"
    );
    let contacted = fixture.report.1.lock().unwrap().clone();
    assert_eq!(
        contacted,
        [(line_owner(), Target::parse_authority(b"fallback.test:443").unwrap())]
    );
}

// FR-NET-09: a contact is reported before the revocation that ends its line returns, and a refused request is
// never reported as contacted.
#[test]
fn reports_contacts_before_revocation_returns() {
    let fixture = fixture();
    let (user, token) = login(&fixture.proxy.issue(line_owner()).unwrap());
    let (_tunnel, head) = connect(&fixture.proxy, "allowed.test:443", Some(&basic(&user, &token)));
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    let (_refused, head) = connect(&fixture.proxy, "refused.test:443", Some(&basic(&user, &token)));
    assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
    // Reported before the client got its answer: no wait is needed (a command that exits on its `403` is revoked at
    // once, and its record must still list the refusal).
    assert_eq!(
        fixture.report.0.lock().unwrap().len(),
        1,
        "refusal reported before the 403"
    );
    fixture.proxy.revoke_line(line_owner().line.unwrap());
    let contacted = fixture.report.1.lock().unwrap().clone();
    assert_eq!(contacted.len(), 1);
    assert_eq!(contacted[0].1.to_string(), "allowed.test:443");
    let refusals = fixture.report.refusals(1);
    assert_eq!(refusals[0].refusal, Refusal::HostNotAllowed);
    assert_eq!(refusals[0].owner, Some(line_owner()));
}
