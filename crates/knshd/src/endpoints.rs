//! The endpoints `knshd` serves, received from launchd (KNSH-012).
//!
//! launchd creates `user.sock` and `agent.sock` and starts `knshd` on first contact
//! (`specs/02-architecture/process-model.md`). `knshd` only ever serves those sockets: [`activate`] takes them from
//! launchd and fails if there are none, and nothing here can bind a socket, so `knshd` never claims an endpoint name
//! itself.
//!
//! Each connection on `user.sock` is admitted only if its peer runs as the same user as `knshd` ([`admit`]): one
//! process per user, never serving another macOS user. The socket is already owner-only; the check is the second
//! layer, and it fails closed when the kernel cannot say who the peer is.
//!
//! Phase 1 placeholder: an admitted connection is closed straight away, because the dispatcher arrives with
//! KNSH-013. `agent.sock` is activated (so launchd's sockets are both accounted for) but every connection on it is
//! closed unserved until phase 2 (KNSH-048); refusing is the fail-closed answer for agents.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use knsh_platform::launchd::{AGENT_SOCKET_NAME, USER_SOCKET_NAME};
use knsh_platform::{Field, Level, PeerCredentials, PlatformError, SocketActivation, SystemLog, Value};

/// Pause after an accept error that is not about one connection (for example `EMFILE`), so a persistent failure
/// does not spin a core.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Logged in place of an `errno` when a failure carries none. `knshd` may not depend on `libc` (NFR-SUP-02), and 0
/// is never a real `errno`, so it reads unambiguously as "unknown".
const UNKNOWN_ERRNO: i32 = 0;

/// The listening sockets launchd created for `knshd`.
#[derive(Debug)]
pub(crate) struct Listeners {
    /// `user.sock`: user processes outside envelopes.
    pub(crate) user: Vec<UnixListener>,
    /// `agent.sock`: processes inside envelopes (served from phase 2).
    pub(crate) agent: Vec<UnixListener>,
}

/// Takes both endpoints from launchd. There is no fallback: if launchd provides no socket for either, `knshd` must
/// not run, because binding its own would let it (or an impostor started the same way) serve a name launchd does
/// not own.
///
/// # Errors
///
/// The [`PlatformError`] of the first endpoint launchd could not provide: `ESRCH` when `knshd` was not started by
/// launchd, `ENOENT` when the job declares no such socket.
pub(crate) fn activate(activation: &dyn SocketActivation) -> Result<Listeners, PlatformError> {
    Ok(Listeners {
        user: activation.listeners(USER_SOCKET_NAME)?,
        agent: activation.listeners(AGENT_SOCKET_NAME)?,
    })
}

/// Why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The peer runs as another user.
    OtherUser {
        /// The peer's effective uid.
        peer_uid: u32,
    },
    /// The kernel could not report the peer's credentials, so who it is cannot be known.
    UnknownPeer(PlatformError),
}

/// Admits a connection only if its peer runs as `own_uid`, the user `knshd` runs as. Fails closed: unknown
/// credentials refuse the connection.
///
/// # Errors
///
/// The [`Refusal`] when the peer is another user or cannot be identified.
pub(crate) fn admit(credentials: &dyn PeerCredentials, own_uid: u32, stream: &UnixStream) -> Result<(), Refusal> {
    match credentials.peer_uid(stream) {
        Ok(peer_uid) if peer_uid == own_uid => Ok(()),
        Ok(peer_uid) => Err(Refusal::OtherUser { peer_uid }),
        Err(error) => Err(Refusal::UnknownPeer(error)),
    }
}

/// Effects the accept loops need, shared by every endpoint thread.
pub(crate) struct Context {
    /// Who is at the other end of each connection.
    pub(crate) credentials: Arc<dyn PeerCredentials>,
    /// Where refusals are reported. Never receives message content.
    pub(crate) log: Arc<dyn SystemLog>,
    /// The user `knshd` runs as.
    pub(crate) own_uid: u32,
}

/// Serves every listener on its own thread until all of them stop. Accept loops only stop on a broken listener, so
/// returning at all is unexpected and the caller treats it as a failure.
pub(crate) fn serve(listeners: Listeners, context: &Arc<Context>) {
    let mut threads = Vec::new();
    for listener in listeners.user {
        let context = Arc::clone(context);
        threads.push(thread::spawn(move || accept_loop(&listener, &context, handle_user)));
    }
    for listener in listeners.agent {
        let context = Arc::clone(context);
        threads.push(thread::spawn(move || accept_loop(&listener, &context, handle_agent)));
    }
    for thread in threads {
        // A panicking accept loop is already reported by the panic hook; the others keep serving until they end.
        let _ = thread.join();
    }
}

/// Accepts connections on `listener` forever, passing each to `handle`.
fn accept_loop(listener: &UnixListener, context: &Context, handle: fn(UnixStream, &Context)) {
    loop {
        match listener.accept() {
            Ok((stream, _)) => handle(stream, context),
            // The peer gave up before the accept, or a signal interrupted it: nothing is wrong with the listener.
            Err(error) if is_per_connection(&error) => {}
            Err(error) => {
                context.log.log(
                    Level::Error,
                    "accept failed",
                    &[Field::new(
                        "errno",
                        Value::Errno(error.raw_os_error().unwrap_or(UNKNOWN_ERRNO)),
                    )],
                );
                thread::sleep(ACCEPT_BACKOFF);
            }
        }
    }
}

/// Whether an accept error concerns one connection only, so the loop simply moves on.
fn is_per_connection(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
    )
}

/// A connection on `user.sock`: refused unless its peer is this user. Admitted connections are closed for now; the
/// dispatcher arrives with KNSH-013.
fn handle_user(stream: UnixStream, context: &Context) {
    match admit(context.credentials.as_ref(), context.own_uid, &stream) {
        Ok(()) => {}
        Err(Refusal::OtherUser { peer_uid }) => context.log.log(
            Level::Error,
            "refused user.sock connection from another user",
            &[Field::new("peer_uid", Value::U64(u64::from(peer_uid)))],
        ),
        Err(Refusal::UnknownPeer(error)) => context.log.log(
            Level::Error,
            "refused user.sock connection with unknown peer",
            &[Field::new(
                "errno",
                Value::Errno(error.errno().unwrap_or(UNKNOWN_ERRNO)),
            )],
        ),
    }
    drop(stream);
}

/// A connection on `agent.sock`: closed unserved until phase 2 (KNSH-048). Agents fail closed.
fn handle_agent(stream: UnixStream, _context: &Context) {
    drop(stream);
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::path::PathBuf;

    use knsh_platform::Operation;
    use knsh_platform::testing::{FakeSocketActivation, FixedPeerCredentials, RecordingLog};

    use super::*;

    const OWN_UID: u32 = 501;

    /// A temporary directory for test sockets, removed on drop. Kept short: socket paths are limited to 103 bytes.
    struct SocketDir(PathBuf);

    impl SocketDir {
        fn new(tag: &str) -> Self {
            let path = PathBuf::from("/tmp").join(format!("knshd-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn listener(&self, name: &str) -> UnixListener {
            UnixListener::bind(self.0.join(name)).unwrap()
        }
    }

    impl Drop for SocketDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // KNSH-012: without launchd's sockets `knshd` does not start, and never binds one of its own.
    #[test]
    fn refuses_to_start_without_launchd_sockets() {
        let error = activate(&FakeSocketActivation::unmanaged()).unwrap_err();
        assert!(
            matches!(
                error,
                PlatformError::Os {
                    operation: Operation::ActivateSocket,
                    ..
                }
            ),
            "{error:?}"
        );

        // Started by launchd, but only one of the two sockets is declared: still refused.
        let dir = SocketDir::new("partial");
        let activation = FakeSocketActivation::new();
        activation.provide(USER_SOCKET_NAME, vec![dir.listener("u")]);
        assert!(activate(&activation).is_err());
    }

    #[test]
    fn activates_both_endpoints_from_launchd() {
        let dir = SocketDir::new("both");
        let activation = FakeSocketActivation::new();
        activation.provide(USER_SOCKET_NAME, vec![dir.listener("u")]);
        activation.provide(AGENT_SOCKET_NAME, vec![dir.listener("a")]);
        let listeners = activate(&activation).unwrap();
        assert_eq!((listeners.user.len(), listeners.agent.len()), (1, 1));
    }

    // KNSH-012, process model "One process per user": a peer running as another user is refused.
    #[test]
    fn rejects_peer_with_different_uid() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        assert_eq!(
            admit(&FixedPeerCredentials::uid(OWN_UID + 1), OWN_UID, &stream),
            Err(Refusal::OtherUser { peer_uid: OWN_UID + 1 })
        );
        // Root is another user too: `knshd` never serves it.
        assert_eq!(
            admit(&FixedPeerCredentials::uid(0), OWN_UID, &stream),
            Err(Refusal::OtherUser { peer_uid: 0 })
        );
        assert_eq!(admit(&FixedPeerCredentials::uid(OWN_UID), OWN_UID, &stream), Ok(()));
    }

    // Fail closed: if the kernel cannot say who the peer is, the connection is refused.
    #[test]
    fn rejects_peer_with_unknown_credentials() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        assert!(matches!(
            admit(&FixedPeerCredentials::unavailable(), OWN_UID, &stream),
            Err(Refusal::UnknownPeer(_))
        ));
    }

    // A refused connection is closed and logged with the peer's uid only, never content.
    #[test]
    fn refused_connection_is_closed_and_logged() {
        let log = Arc::new(RecordingLog::new());
        let context = Context {
            credentials: Arc::new(FixedPeerCredentials::uid(OWN_UID + 1)),
            log: log.clone(),
            own_uid: OWN_UID,
        };
        let (stream, mut peer) = UnixStream::pair().unwrap();
        handle_user(stream, &context);
        let mut buf = [0u8; 1];
        assert_eq!(peer.read(&mut buf).unwrap(), 0, "connection must be closed");
        let entries = log.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "refused user.sock connection from another user");
    }

    #[test]
    fn accept_errors_about_one_connection_do_not_stop_the_loop() {
        assert!(is_per_connection(&io::Error::from(io::ErrorKind::ConnectionAborted)));
        assert!(is_per_connection(&io::Error::from(io::ErrorKind::Interrupted)));
        assert!(!is_per_connection(&io::Error::from(io::ErrorKind::OutOfMemory)));
        // A non-blocking listener would return this forever: it must take the back-off path, never spin.
        assert!(!is_per_connection(&io::Error::from(io::ErrorKind::WouldBlock)));
    }
}
