//! The proxy server: one loopback listener for HTTP CONNECT and SOCKS5, per-command credentials, and tunnels
//! (FR-NET-01, FR-NET-05, FR-NET-06, FR-NET-13).
//!
//! # Threads
//!
//! One accept thread waits on a kqueue (`knsh_platform::macos::Kqueue`) for the listener and for a wake-up that
//! stops it. Each accepted connection gets its own thread, which reads the handshake, decides, and then relays
//! ([`crate::relay`]). At most [`Config::max_connections`] connections are served at once; more are closed on
//! accept and reported as [`Refusal::Busy`].
//!
//! # A connection
//!
//! 1. **Protocol.** The first byte tells them apart: `0x05` is SOCKS5, `0x04` SOCKS4 (refused), anything else HTTP.
//! 2. **Handshake.** Read under a deadline of [`Config::handshake_timeout`] for the whole handshake, not per read, so
//!    a client that trickles bytes cannot hold a thread. Malformed requests are refused, never repaired.
//! 3. **Credentials.** Missing or unknown credentials are refused: `407` with `Proxy-Authenticate: Basic realm="knsh"`
//!    (git sends credentials only after it), or the SOCKS5 refusals. Live credentials give the [`Owner`].
//! 4. **Destination.** An IP literal is refused unless the gate allowlists it; otherwise the [`ConnectionGate`] gives
//!    the exact addresses to connect to, or a refusal. Both protocols take this one path.
//! 5. **Connect.** The proxy connects to those addresses in order, the first that answers winning, all within
//!    [`Config::connect_timeout`], and never to any other: the name is not resolved again (FR-NET-07).
//! 6. **Server name** (FR-NET-06). Unless the gate says the destination is exempt
//!    ([`ConnectionGate::checks_server_name`]: a host configured for non-TLS use, a loopback port), the proxy
//!    answers success, then reads the client's first bytes, under a fresh [`Config::handshake_timeout`] and at most
//!    [`tls::MAX_HELLO_BYTES`], and parses them as a TLS `ClientHello` ([`crate::tls`]). The tunnel opens only if
//!    the hello names the requested host. Otherwise nothing has reached the destination: the refusal is reported
//!    and the connection closed (success was already answered, since a TLS client sends its hello only after it).
//! 7. **Tunnel.** The proxy reports the contact, answers success if it has not yet, forwards the bytes the client
//!    sent so far (the `ClientHello`, or anything sent after its request), and relays byte for byte under the idle
//!    and total timeouts.
//!
//! Every refusal and every contact is reported to the [`ProxyReport`] (FR-NET-09). The proxy opens a connection only
//! for a client's request that passed every check, and sends nothing of its own on it (FR-NET-13).
//!
//! # Reports and revocation
//!
//! The report of an authenticated connection (a refusal after its credentials were checked, or its contact) is made
//! under the `live` lock, the lock revocation takes. So everything reported for a line's connections that were not
//! yet revoked is reported before [`Proxy::revoke_line`] returns, and `knshd` can collect the line's `network` field
//! right after revoking. A refusal is reported before the client is answered, so a command that exits on its refusal
//! cannot have its credentials revoked before the report. A connection revoked while its destination was being
//! checked may still report its refusal afterwards; its tunnel never opens.
//!
//! # Revocation
//!
//! Revoking a line's or a session's credentials also shuts down the connections they opened, so a process that
//! outlives its line keeps no tunnel. A connection is registered when accepted and gets its owner when its
//! credentials are checked; both happen under the `live` lock, as does revocation, so no connection can be
//! authenticated with credentials that are being revoked and escape the shutdown. The destination socket is
//! recorded (again under the lock) before the tunnel opens and is shut down with the client's; a connection revoked
//! before that point never opens its tunnel.
//!
//! # Lock order
//!
//! `live`, then the credential table's lock; `live`, then whatever the [`ProxyReport`] locks. Neither is held across
//! I/O, except `shutdown(2)` calls, which do not block.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroU16;
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use knsh_core::{RecordId, SessionId};
use knsh_platform::macos::Kqueue;
use knsh_platform::{Clock, Monotonic, Random};

use crate::credentials::{Credentials, Issued, Owner};
use crate::error::ProxyError;
use crate::gate::{ConnectionGate, Denial, Protocol, ProxyReport, Refusal};
use crate::http::{self, Authorization, HeadState, HttpError, MAX_HEAD, Response};
use crate::relay::{Timeouts, relay};
use crate::socks5::{self, Command, Reply, SocksError};
use crate::target::{Host, Target};
use crate::tls::{self, HelloState};

/// The kqueue token of the listener.
const LISTENER: usize = 1;
/// The kqueue token of the stop wake-up.
const STOP: usize = 2;
/// Longest wait of the accept loop between checks of the stop flag (the wake-up normally ends it first).
const ACCEPT_WAIT: Duration = Duration::from_secs(60);
/// Bytes read per call while reading an HTTP head.
const READ_CHUNK: usize = 4096;

/// The proxy's limits (`specs/09-reference/defaults-and-limits.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// The whole handshake, from accept to the decision.
    pub handshake_timeout: Duration,
    /// Connecting to the destination.
    pub connect_timeout: Duration,
    /// A tunnel with no byte in either direction for this long is closed.
    pub idle_timeout: Duration,
    /// A tunnel is closed this long after it opened.
    pub total_timeout: Duration,
    /// Connections served at once.
    pub max_connections: usize,
}

impl Config {
    /// The specified defaults.
    pub const DEFAULT: Self = Self {
        handshake_timeout: Duration::from_secs(10),
        connect_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(300),
        total_timeout: Duration::from_hours(4),
        max_connections: 512,
    };
}

/// What the proxy is built from: its effects and its decisions.
pub struct Parts {
    /// Decides destinations.
    pub gate: Arc<dyn ConnectionGate>,
    /// Receives refusals.
    pub report: Arc<dyn ProxyReport>,
    /// Draws tokens. A secure source in production.
    pub random: Arc<dyn Random>,
    /// Measures the timeouts.
    pub clock: Arc<dyn Clock>,
}

/// One live connection: its owner once authenticated, and handles to shut it down.
struct LiveConnection {
    owner: Option<Owner>,
    stream: TcpStream,
    /// The destination socket, once the tunnel is about to open: shut down with the client's, so a revoked tunnel
    /// does not hold its destination (and its thread) until the idle timeout.
    upstream: Option<TcpStream>,
    /// Set by a revocation: no destination may be attached afterwards.
    revoked: bool,
}

impl LiveConnection {
    /// Shuts down the client socket and the destination socket, if any, both ways.
    fn shut_down(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
        if let Some(upstream) = &self.upstream {
            let _ = upstream.shutdown(Shutdown::Both);
        }
    }
}

/// The live connections.
struct Live {
    next_id: u64,
    connections: HashMap<u64, LiveConnection>,
}

/// What the accept thread and every connection thread share.
struct Shared {
    config: Config,
    credentials: Credentials,
    gate: Arc<dyn ConnectionGate>,
    report: Arc<dyn ProxyReport>,
    clock: Arc<dyn Clock>,
    stopping: AtomicBool,
    live: Mutex<Live>,
}

/// The running proxy (module documentation). Dropping it stops accepting and closes every connection.
pub struct Proxy {
    shared: Arc<Shared>,
    port: NonZeroU16,
    queue: Arc<Kqueue>,
    accept: Option<JoinHandle<()>>,
}

impl Proxy {
    /// Listens on an ephemeral port of `127.0.0.1`, and nothing else, and starts serving.
    ///
    /// # Errors
    ///
    /// [`ProxyError::Listen`], [`ProxyError::EventQueue`] or [`ProxyError::Thread`] if it cannot start; nothing is
    /// left running.
    pub fn start(config: Config, parts: Parts) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| ProxyError::Listen)?;
        listener.set_nonblocking(true).map_err(|_| ProxyError::Listen)?;
        let port = listener
            .local_addr()
            .ok()
            .and_then(|address| NonZeroU16::new(address.port()))
            .ok_or(ProxyError::Listen)?;
        let queue = Arc::new(Kqueue::new().map_err(|_| ProxyError::EventQueue)?);
        queue
            .watch_readable(listener.as_fd(), LISTENER)
            .and_then(|()| queue.watch_wakeup(STOP))
            .map_err(|_| ProxyError::EventQueue)?;
        let shared = Arc::new(Shared {
            config,
            credentials: Credentials::new(parts.random),
            gate: parts.gate,
            report: parts.report,
            clock: parts.clock,
            stopping: AtomicBool::new(false),
            live: Mutex::new(Live {
                next_id: 0,
                connections: HashMap::new(),
            }),
        });
        let accept = {
            let shared = Arc::clone(&shared);
            let queue = Arc::clone(&queue);
            std::thread::Builder::new()
                .name("knsh-proxy-accept".to_owned())
                .spawn(move || accept_loop(&shared, &queue, &listener))
                .map_err(|_| ProxyError::Thread)?
        };
        Ok(Self {
            shared,
            port,
            queue,
            accept: Some(accept),
        })
    }

    /// The loopback port it listens on: the one every profile allows (FR-NET-01).
    #[must_use]
    pub fn port(&self) -> NonZeroU16 {
        self.port
    }

    /// Issues new credentials for `owner`: a line (with its record) or an envelope (without).
    ///
    /// # Errors
    ///
    /// As [`Credentials::issue`]: the command must not start.
    pub fn issue(&self, owner: Owner) -> Result<Issued, ProxyError> {
        self.shared.credentials.issue(owner)
    }

    /// Revokes the credentials of the line `record` and closes the connections they opened.
    pub fn revoke_line(&self, record: RecordId) {
        self.shared.revoke(
            |owner| owner.line == Some(record),
            |credentials| credentials.revoke_line(record),
        );
    }

    /// Revokes every credential of `session` (envelope and lines) and closes the connections they opened.
    pub fn revoke_session(&self, session: SessionId) {
        self.shared.revoke(
            |owner| owner.session == session,
            |credentials| credentials.revoke_session(session),
        );
    }

    /// How many credentials are live.
    #[must_use]
    pub fn live_credentials(&self) -> usize {
        self.shared.credentials.live()
    }

    /// How many connections are open, authenticated or not.
    #[must_use]
    pub fn live_connections(&self) -> usize {
        self.shared.lock_live().connections.len()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        // If the wake-up cannot be sent, the loop still sees the flag within `ACCEPT_WAIT`.
        let _ = self.queue.wake(STOP);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        for connection in self.shared.lock_live().connections.values_mut() {
            connection.revoked = true;
            connection.shut_down();
        }
    }
}

impl Shared {
    /// Takes the lock even if a thread panicked while holding it: every update is a single map operation.
    fn lock_live(&self) -> MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Revokes credentials and shuts down the connections whose owner matches, under the `live` lock (module
    /// documentation, "Revocation").
    fn revoke(&self, matches: impl Fn(&Owner) -> bool, revoke: impl FnOnce(&Credentials)) {
        let mut live = self.lock_live();
        revoke(&self.credentials);
        for connection in live.connections.values_mut() {
            if connection.owner.as_ref().is_some_and(&matches) {
                connection.revoked = true;
                connection.shut_down();
            }
        }
    }

    /// Registers an accepted connection, or `None` at the connection limit.
    fn register(&self, stream: &TcpStream) -> Option<u64> {
        let mut live = self.lock_live();
        if live.connections.len() >= self.config.max_connections {
            return None;
        }
        let stream = stream.try_clone().ok()?;
        let id = live.next_id;
        live.next_id = live.next_id.wrapping_add(1);
        live.connections.insert(
            id,
            LiveConnection {
                owner: None,
                stream,
                upstream: None,
                revoked: false,
            },
        );
        Some(id)
    }

    /// Records the destination socket of connection `id`, so a revocation shuts it down too, and reports the
    /// contact under the same lock ("Reports and revocation"). `false` if the connection was revoked meanwhile (or
    /// the socket cannot be kept): the tunnel must not open, and nothing is reported as contacted.
    fn attach_upstream(&self, id: u64, owner: &Owner, target: &Target, upstream: &TcpStream) -> bool {
        let mut live = self.lock_live();
        let Some(connection) = live.connections.get_mut(&id) else {
            return false;
        };
        if connection.revoked {
            return false;
        }
        match upstream.try_clone() {
            Ok(clone) => {
                connection.upstream = Some(clone);
                self.report.contacted(owner, target);
                true
            }
            Err(_) => false,
        }
    }

    /// Whether connection `id` was revoked (or is gone): its client socket was shut down by the revocation, so a
    /// read that failed on it is not the client's doing.
    fn revoked(&self, id: u64) -> bool {
        self.lock_live()
            .connections
            .get(&id)
            .is_none_or(|connection| connection.revoked)
    }

    /// Forgets a connection that has ended.
    fn unregister(&self, id: u64) {
        self.lock_live().connections.remove(&id);
    }

    /// The owner of `user` and `password`, recorded on connection `id`; `None` if they are not live credentials.
    fn authenticate(&self, id: u64, user: &[u8], password: &[u8]) -> Option<Owner> {
        let mut live = self.lock_live();
        let owner = self.credentials.authenticate(user, password)?;
        live.connections.get_mut(&id)?.owner = Some(owner);
        Some(owner)
    }

    /// Reports a refusal. One that names an owner is reported under the `live` lock, so it is ordered before any
    /// revocation of the owner's credentials ("Reports and revocation").
    fn deny(&self, owner: Option<Owner>, protocol: Option<Protocol>, target: Option<&Target>, refusal: Refusal) {
        let _live = owner.is_some().then(|| self.lock_live());
        self.report.denied(&Denial {
            owner,
            protocol,
            target: target.cloned(),
            refusal,
        });
    }

    /// Step 4: the addresses to connect to, or why not. IP literals are refused here unless allowlisted, for both
    /// protocols, before the gate is asked for an address (FR-NET-05).
    fn decide(&self, owner: &Owner, target: &Target) -> Result<Vec<SocketAddr>, Refusal> {
        if let Host::Ip(ip) = target.host
            && !self.gate.allows_ip_literal(owner, ip, target.port)
        {
            return Err(Refusal::IpLiteral);
        }
        self.gate.check(owner, target)
    }

    /// Steps 4 and 5's connect: the upstream socket for `owner`'s request to reach `target`, or why not.
    fn open_upstream(&self, owner: &Owner, target: &Target) -> Result<TcpStream, Refusal> {
        self.decide(owner, target).and_then(|address| self.connect(address))
    }

    /// Step 5's connect: to the gate's addresses in order, and to nothing else, until one answers, all within
    /// [`Config::connect_timeout`]. The refusal is the last attempt's; no address at all is [`Refusal::Unresolved`].
    fn connect(&self, addresses: Vec<SocketAddr>) -> Result<TcpStream, Refusal> {
        let deadline = Instant::now() + self.config.connect_timeout;
        let mut refusal = Refusal::Unresolved;
        for address in addresses {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Refusal::Timeout);
            }
            match TcpStream::connect_timeout(&address, left) {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    refusal = match error.kind() {
                        ErrorKind::TimedOut | ErrorKind::WouldBlock => Refusal::Timeout,
                        _ => Refusal::Unreachable,
                    };
                }
            }
        }
        Err(refusal)
    }

    /// The tunnel's limits.
    fn timeouts(&self) -> Timeouts {
        Timeouts {
            idle: self.config.idle_timeout,
            total: self.config.total_timeout,
        }
    }
}

/// The accept thread: waits on the kqueue, accepts every waiting connection, and starts a thread for each.
fn accept_loop(shared: &Arc<Shared>, queue: &Kqueue, listener: &TcpListener) {
    let mut events = Vec::new();
    while !shared.stopping.load(Ordering::SeqCst) {
        if queue.wait(ACCEPT_WAIT, &mut events).is_err() {
            // `kevent` fails only for a broken queue: stop accepting (fail closed), and let `Drop` clean up.
            return;
        }
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        if !events.contains(&LISTENER) {
            continue;
        }
        loop {
            match listener.accept() {
                Ok((stream, _)) => start_connection(shared, stream),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                // `WouldBlock`: the backlog is drained. Anything else (`EMFILE`, `ECONNABORTED`): try again at the
                // next event rather than spin.
                Err(_) => break,
            }
        }
    }
}

/// Registers `stream` and serves it on its own thread, or closes it at the connection limit.
fn start_connection(shared: &Arc<Shared>, stream: TcpStream) {
    let Some(id) = shared.register(&stream) else {
        shared.deny(None, None, None, Refusal::Busy);
        return;
    };
    let worker = Arc::clone(shared);
    let spawned = std::thread::Builder::new()
        .name("knsh-proxy-conn".to_owned())
        .spawn(move || {
            serve(&worker, id, &stream);
            worker.unregister(id);
        });
    if spawned.is_err() {
        // The closure (and with it the stream) is dropped: the client sees the connection close.
        shared.unregister(id);
        shared.deny(None, None, None, Refusal::Busy);
    }
}

/// A reader over the client socket that enforces one deadline for the whole handshake.
struct Handshake<'a> {
    stream: &'a TcpStream,
    clock: &'a dyn Clock,
    deadline: Monotonic,
}

impl Read for Handshake<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.deadline.saturating_duration_since(self.clock.monotonic());
        if left.is_zero() {
            return Err(ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        let mut stream = self.stream;
        stream.read(buf)
    }
}

/// Steps 1 to 5 for one connection.
fn serve(shared: &Shared, id: u64, stream: &TcpStream) {
    // Accepted sockets inherit the listener's non-blocking flag on macOS.
    if stream.set_nonblocking(false).is_err()
        || stream.set_write_timeout(Some(shared.config.handshake_timeout)).is_err()
    {
        return;
    }
    let deadline = shared
        .clock
        .monotonic()
        .checked_add(shared.config.handshake_timeout)
        .unwrap_or_else(|| shared.clock.monotonic());
    let mut reader = Handshake {
        stream,
        clock: shared.clock.as_ref(),
        deadline,
    };
    let mut first = [0; 1];
    if reader.read_exact(&mut first).is_err() {
        return;
    }
    match first[0] {
        socks5::VERSION => serve_socks5(shared, id, stream, &mut reader),
        socks5::VERSION_4 => {
            let _ = (&*stream).write_all(&socks5::SOCKS4_REJECTED);
            shared.deny(None, Some(Protocol::Socks4), None, Refusal::UnsupportedProtocol);
        }
        byte => serve_http(shared, id, stream, &mut reader, byte),
    }
}

/// An HTTP refusal: the response, and the report.
fn refuse_http(shared: &Shared, stream: &TcpStream, owner: Option<Owner>, target: Option<&Target>, refusal: Refusal) {
    let response = match refusal {
        Refusal::MissingCredentials | Refusal::UnknownCredentials => Response::ProxyAuthenticationRequired,
        Refusal::Malformed | Refusal::UnsupportedCommand => Response::BadRequest,
        Refusal::UnsupportedProtocol => Response::MethodNotAllowed,
        // The server-name refusals come after success was answered and only close the connection
        // (`check_client_hello`); they are listed for completeness.
        Refusal::IpLiteral
        | Refusal::HostNotAllowed
        | Refusal::NetworkOff
        | Refusal::ApprovalRequired
        | Refusal::DynamicCode
        | Refusal::SecretHosts
        | Refusal::AddressNotAllowed
        | Refusal::NoHostRules
        | Refusal::NotTls
        | Refusal::ServerNameMissing
        | Refusal::ServerNameMismatch => Response::Forbidden,
        Refusal::Unresolved | Refusal::Unreachable => Response::BadGateway,
        Refusal::Timeout => Response::GatewayTimeout,
        Refusal::Busy => Response::ServiceUnavailable,
    };
    // Reported before the client can see the answer: a command that exits on its `403` and has its credentials
    // revoked must find the refusal already reported ("Reports and revocation").
    shared.deny(owner, Some(Protocol::Http), target, refusal);
    let _ = (&*stream).write_all(response.bytes());
}

/// An HTTP head over its size limit: `431` rather than [`refuse_http`]'s `400`, reported as malformed.
fn refuse_head_too_large(shared: &Shared, stream: &TcpStream) {
    let _ = (&*stream).write_all(Response::HeadersTooLarge.bytes());
    shared.deny(None, Some(Protocol::Http), None, Refusal::Malformed);
}

/// Reads an HTTP head into `buf` (which holds the first byte already) and returns its length, or `None` after a
/// size refusal (`431`) or when the client went away.
fn read_head(shared: &Shared, stream: &TcpStream, reader: &mut Handshake<'_>, buf: &mut Vec<u8>) -> Option<usize> {
    let mut chunk = [0; READ_CHUNK];
    loop {
        match http::head_state(buf) {
            HeadState::Complete(len) => return Some(len),
            HeadState::TooLarge => {
                refuse_head_too_large(shared, stream);
                return None;
            }
            HeadState::Malformed => {
                refuse_http(shared, stream, None, None, Refusal::Malformed);
                return None;
            }
            HeadState::Incomplete => {}
        }
        // Never more than the head limit, so `buf` stays bounded whatever the client sends.
        let room = MAX_HEAD.saturating_sub(buf.len()).clamp(1, READ_CHUNK);
        match reader.read(&mut chunk[..room]) {
            Ok(0) | Err(_) => return None,
            Ok(read) => buf.extend_from_slice(&chunk[..read]),
        }
    }
}

/// An HTTP connection: steps 2 to 5 for CONNECT.
fn serve_http(shared: &Shared, id: u64, stream: &TcpStream, reader: &mut Handshake<'_>, first: u8) {
    let mut buf = Vec::with_capacity(READ_CHUNK);
    buf.push(first);
    let Some(head_len) = read_head(shared, stream, reader, &mut buf) else {
        return;
    };
    let request = match http::parse_head(&buf[..head_len]) {
        Ok(request) => request,
        Err(HttpError::TooLarge) => return refuse_head_too_large(shared, stream),
        Err(HttpError::Malformed) => return refuse_http(shared, stream, None, None, Refusal::Malformed),
    };
    let owner = match &request.authorization {
        Authorization::Missing => return refuse_http(shared, stream, None, None, Refusal::MissingCredentials),
        Authorization::Unusable => return refuse_http(shared, stream, None, None, Refusal::UnknownCredentials),
        Authorization::Basic { user, password } => match shared.authenticate(id, user, password) {
            Some(owner) => owner,
            None => return refuse_http(shared, stream, None, None, Refusal::UnknownCredentials),
        },
    };
    if !request.is_connect() {
        // Absolute-URI requests (plain HTTP) included: not served yet, so refused rather than forwarded unchecked.
        return refuse_http(shared, stream, Some(owner), None, Refusal::UnsupportedProtocol);
    }
    let Some(target) = Target::parse_authority(request.target) else {
        return refuse_http(shared, stream, Some(owner), None, Refusal::Malformed);
    };
    let upstream = match shared.open_upstream(&owner, &target) {
        Ok(upstream) => upstream,
        Err(refusal) => return refuse_http(shared, stream, Some(owner), Some(&target), refusal),
    };
    // Bytes the client sent after its head (a ClientHello sent without waiting) belong to the tunnel, and are the
    // start of what the server-name check reads.
    let pending = buf.split_off(head_len);
    let opening = Opening {
        id,
        protocol: Protocol::Http,
        owner,
        target: &target,
        success: Response::Established.bytes(),
    };
    open_tunnel(shared, stream, &opening, &upstream, pending);
}

/// A SOCKS5 refusal: the reply, and the report.
fn refuse_socks5(shared: &Shared, stream: &TcpStream, owner: Owner, target: Option<&Target>, refusal: Refusal) {
    let reply = match refusal {
        Refusal::UnsupportedCommand => Reply::CommandNotSupported,
        Refusal::IpLiteral
        | Refusal::HostNotAllowed
        | Refusal::NetworkOff
        | Refusal::ApprovalRequired
        | Refusal::DynamicCode
        | Refusal::SecretHosts
        | Refusal::AddressNotAllowed
        | Refusal::NoHostRules
        | Refusal::NotTls
        | Refusal::ServerNameMissing
        | Refusal::ServerNameMismatch => Reply::NotAllowed,
        Refusal::Unresolved | Refusal::Unreachable => Reply::HostUnreachable,
        Refusal::Timeout => Reply::TtlExpired,
        Refusal::MissingCredentials
        | Refusal::UnknownCredentials
        | Refusal::Malformed
        | Refusal::UnsupportedProtocol
        | Refusal::Busy => Reply::GeneralFailure,
    };
    // Reported before the client can see the reply ("Reports and revocation").
    shared.deny(Some(owner), Some(Protocol::Socks5), target, refusal);
    let _ = (&*stream).write_all(&reply.bytes());
}

/// A SOCKS5 connection: steps 2 to 5 (`socks5` module documentation).
fn serve_socks5(shared: &Shared, id: u64, stream: &TcpStream, reader: &mut Handshake<'_>) {
    let mut writer = stream;
    let deny = |owner, refusal| shared.deny(owner, Some(Protocol::Socks5), None, refusal);
    // A refusal before the request is judged: `answer` is best effort (the client may be gone), the report is not,
    // and comes first ("Reports and revocation").
    let refuse = |answer: &[u8], owner, refusal| {
        deny(owner, refusal);
        let _ = (&*stream).write_all(answer);
    };
    let offered = match socks5::read_greeting(&mut [socks5::VERSION].as_slice().chain(&mut *reader)) {
        Ok(offered) => offered,
        Err(SocksError::Closed) => return,
        Err(SocksError::Malformed | SocksError::AddressType) => return deny(None, Refusal::Malformed),
    };
    if !offered {
        return refuse(&socks5::NO_ACCEPTABLE_METHODS, None, Refusal::MissingCredentials);
    }
    if writer.write_all(&socks5::METHOD_SELECTED).is_err() {
        return;
    }
    let credentials = match socks5::read_user_password(reader) {
        Ok(credentials) => credentials,
        Err(SocksError::Closed) => return,
        Err(SocksError::Malformed | SocksError::AddressType) => {
            return refuse(&socks5::AUTH_FAILED, None, Refusal::Malformed);
        }
    };
    let Some(owner) = shared.authenticate(id, &credentials.user, &credentials.password) else {
        return refuse(&socks5::AUTH_FAILED, None, Refusal::UnknownCredentials);
    };
    if writer.write_all(&socks5::AUTH_SUCCEEDED).is_err() {
        return;
    }
    let request = match socks5::read_request(reader) {
        Ok(request) => request,
        Err(SocksError::Closed) => return,
        Err(SocksError::AddressType) => {
            return refuse(&Reply::AddressTypeNotSupported.bytes(), Some(owner), Refusal::Malformed);
        }
        Err(SocksError::Malformed) => return refuse_socks5(shared, stream, owner, None, Refusal::Malformed),
    };
    let target = request.target();
    match request.command {
        Command::Connect => {}
        Command::Bind | Command::UdpAssociate | Command::Unknown(_) => {
            return refuse_socks5(shared, stream, owner, target.as_ref(), Refusal::UnsupportedCommand);
        }
    }
    let Some(target) = target else {
        return refuse_socks5(shared, stream, owner, None, Refusal::Malformed);
    };
    let upstream = match shared.open_upstream(&owner, &target) {
        Ok(upstream) => upstream,
        Err(refusal) => return refuse_socks5(shared, stream, owner, Some(&target), refusal),
    };
    let success = Reply::Succeeded.bytes();
    let opening = Opening {
        id,
        protocol: Protocol::Socks5,
        owner,
        target: &target,
        success: &success,
    };
    // The SOCKS5 reader takes exact lengths, so nothing the client sent after its request is buffered.
    open_tunnel(shared, stream, &opening, &upstream, Vec::new());
}

/// A connection whose destination passed the gate and is connected: what steps 6 and 7 need to know.
struct Opening<'a> {
    id: u64,
    protocol: Protocol,
    owner: Owner,
    target: &'a Target,
    /// The protocol's success answer: `200 Connection established`, or the SOCKS5 success reply.
    success: &'a [u8],
}

/// Steps 6 and 7: checks the server name unless the gate exempts the destination, then reports the contact, answers
/// success, forwards `pending` (the client's bytes read so far) and relays.
fn open_tunnel(shared: &Shared, stream: &TcpStream, opening: &Opening<'_>, upstream: &TcpStream, pending: Vec<u8>) {
    let pending = if shared.gate.checks_server_name(&opening.owner, opening.target) {
        // A TLS client sends its ClientHello only once it has the success answer, so the answer must come first.
        // Nothing reaches the destination until the hello is checked.
        if (&*stream).write_all(opening.success).is_err() {
            return;
        }
        let Some(hello) = check_client_hello(shared, stream, opening, pending) else {
            return;
        };
        // Revoked while the hello was read: the client socket is already shut down.
        if !shared.attach_upstream(opening.id, &opening.owner, opening.target, upstream) {
            return;
        }
        hello
    } else {
        // Exempt: no hello to wait for, so attach first and answer success only if the connection is still live.
        // Revoked while the destination was checked or connected: the client socket is already shut down.
        if !shared.attach_upstream(opening.id, &opening.owner, opening.target, upstream)
            || (&*stream).write_all(opening.success).is_err()
        {
            return;
        }
        pending
    };
    if (&*upstream).write_all(&pending).is_err() {
        return;
    }
    tunnel(shared, stream, upstream);
}

/// Step 6 (FR-NET-06): reads the client's first bytes, starting with `pending`, until they form a complete
/// `ClientHello` or are refused, and checks its server name against the requested host. Returns every byte read, to
/// be forwarded, or `None` once the connection is refused (reported, then shut down) or the client went away.
fn check_client_hello(shared: &Shared, stream: &TcpStream, opening: &Opening<'_>, mut buf: Vec<u8>) -> Option<Vec<u8>> {
    // A fresh deadline: resolving and connecting may have used most of the request's.
    let deadline = shared
        .clock
        .monotonic()
        .checked_add(shared.config.handshake_timeout)
        .unwrap_or_else(|| shared.clock.monotonic());
    let mut reader = Handshake {
        stream,
        clock: shared.clock.as_ref(),
        deadline,
    };
    let mut chunk = [0; READ_CHUNK];
    let refusal = loop {
        match tls::read_client_hello(&buf) {
            HelloState::Complete(name) => match tls::check_server_name(&opening.target.host, &name) {
                Ok(()) => return Some(buf),
                Err(refusal) => break refusal,
            },
            HelloState::Refused(_) => break Refusal::NotTls,
            HelloState::Incomplete => {}
        }
        // `read_client_hello` refuses at `MAX_HELLO_BYTES`, so `buf` never grows past it and `room` is at least 1
        // here; the lower clamp only guards against a zero-length read, which would look like the client closing.
        let room = tls::MAX_HELLO_BYTES.saturating_sub(buf.len()).clamp(1, READ_CHUNK);
        match reader.read(&mut chunk[..room]) {
            Ok(read) if read > 0 => buf.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                break Refusal::Timeout;
            }
            // Closed (or reset) before the hello was complete: a client that sent nothing just gave up; one that
            // sent part of a hello is refused as not TLS.
            Ok(_) | Err(_) if buf.is_empty() => return None,
            Ok(_) | Err(_) => break Refusal::NotTls,
        }
    };
    // A revocation shuts the client socket down, which ends the read: that is not the client's refusal.
    if !shared.revoked(opening.id) {
        shared.deny(
            Some(opening.owner),
            Some(opening.protocol),
            Some(opening.target),
            refusal,
        );
    }
    let _ = stream.shutdown(Shutdown::Both);
    None
}

/// Step 5's relay, once success has been answered.
fn tunnel(shared: &Shared, stream: &TcpStream, upstream: &TcpStream) {
    // The handshake's timeouts give way to the relay's own.
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
    relay(stream, upstream, shared.timeouts(), &shared.clock);
}

#[cfg(test)]
mod tests;
