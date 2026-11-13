//! Fakes for the launchd traits (KNSH-012): socket activation, peer credentials and the service manager.

use std::collections::HashMap;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::lock;
use crate::error::{Operation, PlatformError};
use crate::launchd::{PeerCredentials, ServiceManager, SocketActivation};

/// Socket activation with listeners the test provides, behaving like `launch_activate_socket`.
///
/// - [`FakeSocketActivation::unmanaged`]: the process was not started by launchd; every name fails with `ESRCH`.
/// - [`FakeSocketActivation::new`] then [`FakeSocketActivation::provide`]: a launchd job. A name with no listeners
///   fails with `ENOENT`; taking a name a second time fails with `EALREADY`.
#[derive(Debug)]
pub struct FakeSocketActivation {
    managed: bool,
    /// Listeners not yet taken, by `Sockets` entry name; `None` once taken.
    sockets: Mutex<HashMap<String, Option<Vec<UnixListener>>>>,
}

impl FakeSocketActivation {
    /// A launchd job with no sockets yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            managed: true,
            sockets: Mutex::new(HashMap::new()),
        }
    }

    /// A process launchd did not start.
    #[must_use]
    pub fn unmanaged() -> Self {
        Self {
            managed: false,
            ..Self::new()
        }
    }

    /// Makes `listeners` the sockets of the entry `name`. Tests bind them in a temporary directory.
    pub fn provide(&self, name: &str, listeners: Vec<UnixListener>) {
        lock(&self.sockets).insert(name.to_owned(), Some(listeners));
    }
}

impl Default for FakeSocketActivation {
    fn default() -> Self {
        Self::new()
    }
}

/// [`PlatformError::Os`] for [`Operation::ActivateSocket`].
fn activation_error(errno: i32) -> PlatformError {
    PlatformError::Os {
        operation: Operation::ActivateSocket,
        errno,
    }
}

impl SocketActivation for FakeSocketActivation {
    fn listeners(&self, name: &str) -> Result<Vec<UnixListener>, PlatformError> {
        if !self.managed {
            return Err(activation_error(libc::ESRCH));
        }
        match lock(&self.sockets).get_mut(name) {
            None => Err(activation_error(libc::ENOENT)),
            Some(slot) => match slot.take() {
                Some(listeners) if listeners.is_empty() => Err(activation_error(libc::ENOENT)),
                Some(listeners) => Ok(listeners),
                None => Err(activation_error(libc::EALREADY)),
            },
        }
    }
}

/// Peer credentials fixed in advance: every peer has the same uid, or the lookup fails.
#[derive(Debug, Clone, Copy)]
pub struct FixedPeerCredentials {
    uid: Option<u32>,
}

impl FixedPeerCredentials {
    /// Every peer runs as `uid`.
    #[must_use]
    pub const fn uid(uid: u32) -> Self {
        Self { uid: Some(uid) }
    }

    /// The kernel cannot report any peer (fails with `EINVAL`).
    #[must_use]
    pub const fn unavailable() -> Self {
        Self { uid: None }
    }
}

impl PeerCredentials for FixedPeerCredentials {
    fn peer_uid(&self, _stream: &UnixStream) -> Result<u32, PlatformError> {
        self.uid.ok_or(PlatformError::Os {
            operation: Operation::PeerCredentials,
            errno: libc::EINVAL,
        })
    }
}

/// One call made to a [`RecordingServiceManager`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceCall {
    /// [`ServiceManager::bootstrap`].
    Bootstrap {
        /// The user whose GUI domain was targeted.
        uid: u32,
        /// The property list loaded.
        plist: PathBuf,
    },
    /// [`ServiceManager::bootout`].
    Bootout {
        /// The user whose GUI domain was targeted.
        uid: u32,
        /// The label unloaded.
        label: String,
    },
}

#[derive(Debug, Default)]
struct ManagerState {
    calls: Vec<ServiceCall>,
    /// Labels currently loaded. A bootstrap loads the file name without `.plist`, like launchd's convention.
    loaded: Vec<String>,
    bootstrap_failure: Option<i32>,
    bootout_failure: Option<i32>,
}

/// A service manager that records calls and tracks which labels are loaded. A failed call is still recorded.
#[derive(Debug, Default)]
pub struct RecordingServiceManager {
    state: Mutex<ManagerState>,
}

impl RecordingServiceManager {
    /// No job loaded, no failures.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every call so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<ServiceCall> {
        lock(&self.state).calls.clone()
    }

    /// Makes every later bootstrap fail as if `launchctl` exited with `status`.
    pub fn fail_bootstrap(&self, status: i32) {
        lock(&self.state).bootstrap_failure = Some(status);
    }

    /// Makes every later bootout fail as if `launchctl` exited with `status`.
    pub fn fail_bootout(&self, status: i32) {
        lock(&self.state).bootout_failure = Some(status);
    }
}

impl ServiceManager for RecordingServiceManager {
    fn bootstrap(&self, uid: u32, plist: &Path) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        state.calls.push(ServiceCall::Bootstrap {
            uid,
            plist: plist.to_path_buf(),
        });
        if let Some(status) = state.bootstrap_failure {
            return Err(PlatformError::Launchctl { status: Some(status) });
        }
        let label = plist
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default();
        if state.loaded.contains(&label) {
            // launchd refuses to load a label twice (`Bootstrap failed: 5: Input/output error`).
            return Err(PlatformError::Launchctl { status: Some(5) });
        }
        state.loaded.push(label);
        Ok(())
    }

    fn bootout(&self, uid: u32, label: &str) -> Result<bool, PlatformError> {
        let mut state = lock(&self.state);
        state.calls.push(ServiceCall::Bootout {
            uid,
            label: label.to_owned(),
        });
        if let Some(status) = state.bootout_failure {
            return Err(PlatformError::Launchctl { status: Some(status) });
        }
        let before = state.loaded.len();
        state.loaded.retain(|loaded| loaded != label);
        Ok(state.loaded.len() != before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_activation_fake_behaves_like_launchd() {
        let unmanaged = FakeSocketActivation::unmanaged();
        assert_eq!(unmanaged.listeners("user").unwrap_err().errno(), Some(libc::ESRCH));

        let dir = std::env::temp_dir().join(format!("knsh-fake-activation-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let listener = UnixListener::bind(dir.join("s")).unwrap();

        let activation = FakeSocketActivation::new();
        activation.provide("user", vec![listener]);
        activation.provide("empty", Vec::new());
        assert_eq!(activation.listeners("user").unwrap().len(), 1);
        assert_eq!(activation.listeners("user").unwrap_err().errno(), Some(libc::EALREADY));
        assert_eq!(activation.listeners("agent").unwrap_err().errno(), Some(libc::ENOENT));
        assert_eq!(activation.listeners("empty").unwrap_err().errno(), Some(libc::ENOENT));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn service_manager_fake_tracks_loaded_labels() {
        let manager = RecordingServiceManager::new();
        assert_eq!(manager.bootout(501, "knsh.knshd"), Ok(false));
        manager.bootstrap(501, Path::new("/h/knsh.knshd.plist")).unwrap();
        assert_eq!(
            manager.bootstrap(501, Path::new("/h/knsh.knshd.plist")),
            Err(PlatformError::Launchctl { status: Some(5) })
        );
        assert_eq!(manager.bootout(501, "knsh.knshd"), Ok(true));
        assert_eq!(manager.calls().len(), 4);
    }
}
