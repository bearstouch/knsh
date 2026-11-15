//! The endpoints `knshd` serves, received from launchd (KNSH-012).
//!
//! launchd creates `user.sock` and `agent.sock` and starts `knshd` on first contact
//! (`specs/02-architecture/process-model.md`). `knshd` only ever serves those sockets: [`activate`] takes them from
//! launchd and fails if there are none, and nothing here can bind a socket, so `knshd` never claims an endpoint name
//! itself.
//!
//! Each connection, on either socket, is admitted only if its peer runs as the same user as `knshd` ([`admit`]): one
//! process per user, never serving another macOS user. The socket is already owner-only; the check is the second
//! layer, and it fails closed when the kernel cannot say who the peer is.
//!
//! Serving the admitted connections is the job of [`crate::server`] (KNSH-013).

use std::os::unix::net::{UnixListener, UnixStream};

use knsh_platform::launchd::{AGENT_SOCKET_NAME, USER_SOCKET_NAME};
use knsh_platform::{PeerCredentials, PlatformError, SocketActivation};

/// The listening sockets launchd created for `knshd`.
#[derive(Debug)]
pub(crate) struct Listeners {
    /// `user.sock`: user processes outside envelopes.
    pub(crate) user: Vec<UnixListener>,
    /// `agent.sock`: processes inside envelopes, each bound to its own session at `hello` (KNSH-048).
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use knsh_platform::Operation;
    use knsh_platform::testing::{FakeSocketActivation, FixedPeerCredentials};

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
}
