//! launchd on macOS: socket activation (`launch_activate_socket`), peer credentials (`getpeereid`) and loading the
//! job (`/bin/launchctl`). KNSH-012.

use std::ffi::{CString, OsStr, c_char, c_int};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::{Operation, PlatformError};
use crate::launchd::{PeerCredentials, ServiceManager, SocketActivation};

// `<launch.h>`, in libSystem (linked by default). Not bound by the `libc` crate.
unsafe extern "C" {
    /// Returns, in a `malloc`ed array the caller frees, the descriptors launchd created for the `Sockets` entry
    /// `name` of the calling job. Returns 0 or an `errno` value: `ENOENT` (no such entry), `ESRCH` (the caller is
    /// not managed by launchd), `EALREADY` (already activated).
    fn launch_activate_socket(name: *const c_char, fds: *mut *mut c_int, count: *mut usize) -> c_int;
}

/// [`PlatformError::Os`] for [`Operation::ActivateSocket`].
fn activation_error(errno: i32) -> PlatformError {
    PlatformError::Os {
        operation: Operation::ActivateSocket,
        errno,
    }
}

/// The sockets launchd created for this process's job.
#[derive(Debug, Clone, Copy, Default)]
pub struct LaunchdSockets;

impl LaunchdSockets {
    /// launchd socket activation for the calling process.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SocketActivation for LaunchdSockets {
    fn listeners(&self, name: &str) -> Result<Vec<UnixListener>, PlatformError> {
        let c_name = CString::new(name).map_err(|_| activation_error(libc::EINVAL))?;
        let mut fds: *mut c_int = std::ptr::null_mut();
        let mut count: usize = 0;
        // SAFETY: `c_name` is NUL-terminated and outlives the call; `fds` and `count` are valid places for launchd to
        // write the array pointer and its length.
        let rc = unsafe { launch_activate_socket(c_name.as_ptr(), &raw mut fds, &raw mut count) };
        if rc != 0 {
            return Err(activation_error(rc));
        }
        let mut listeners = Vec::with_capacity(count);
        for index in 0..count {
            // SAFETY: on success `fds` points to `count` descriptors; `index < count`.
            let raw = unsafe { *fds.add(index) };
            // SAFETY: launchd hands each descriptor to this process exactly once (a second activation fails with
            // `EALREADY`), so taking ownership here cannot double-close it.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            listeners.push(UnixListener::from(fd));
        }
        // SAFETY: launchd allocated the array with `malloc` and the caller must free it; it is not used after this.
        // `free(NULL)` is a no-op if launchd returned no array.
        unsafe { libc::free(fds.cast()) };
        // Close-on-exec, so no child of `knshd` (agent commands run below it) ever inherits an endpoint. Done after
        // every descriptor is owned, so an error here still closes them all.
        // Blocking, too: `knshd` accepts in a plain loop per listener, and a non-blocking listener would make that
        // loop spin on `EWOULDBLOCK` (launchd does not document the descriptor flags it hands over).
        for listener in &listeners {
            set_cloexec(listener.as_raw_fd())?;
            listener
                .set_nonblocking(false)
                .map_err(|error| PlatformError::from_io(Operation::ActivateSocket, &error))?;
        }
        if listeners.is_empty() {
            return Err(activation_error(libc::ENOENT));
        }
        Ok(listeners)
    }
}

/// Sets `FD_CLOEXEC` on `fd`.
fn set_cloexec(fd: c_int) -> Result<(), PlatformError> {
    // SAFETY: `fd` is an open descriptor owned by the caller for the duration of the call; `F_GETFD` and `F_SETFD`
    // touch no memory of ours.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    // SAFETY: as above.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(PlatformError::from_io(
            Operation::ActivateSocket,
            &io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// Peer credentials from the kernel (`getpeereid`): the effective uid the peer had when it connected.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemPeerCredentials;

impl SystemPeerCredentials {
    /// The kernel's record of each connection's peer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl PeerCredentials for SystemPeerCredentials {
    fn peer_uid(&self, stream: &UnixStream) -> Result<u32, PlatformError> {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: the descriptor is open for the lifetime of `stream`; `uid` and `gid` are valid places to write.
        let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &raw mut uid, &raw mut gid) };
        if rc == 0 {
            Ok(uid)
        } else {
            Err(PlatformError::from_io(
                Operation::PeerCredentials,
                &io::Error::last_os_error(),
            ))
        }
    }
}

/// `launchctl` exit status meaning the job is not loaded (`Boot-out failed: 3: No such process`, macOS 14 to 26).
const NOT_LOADED: i32 = libc::ESRCH;

/// `launchctl` status for the same case on some releases (`Could not find specified service`).
const NOT_FOUND: i32 = 113;

/// `launchctl`, by absolute path so a `PATH` entry cannot substitute another program.
#[derive(Debug, Clone, Copy, Default)]
pub struct Launchctl;

impl Launchctl {
    /// The system `launchctl`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Runs `/bin/launchctl` with `args`, discarding its output: it names paths and labels, and the exit status is
    /// what callers act on.
    fn run(args: &[&OsStr]) -> Result<(), PlatformError> {
        let status = Command::new("/bin/launchctl")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| PlatformError::from_io(Operation::Spawn, &error))?;
        if status.success() {
            Ok(())
        } else {
            Err(PlatformError::Launchctl { status: status.code() })
        }
    }
}

impl ServiceManager for Launchctl {
    fn bootstrap(&self, uid: u32, plist: &Path) -> Result<(), PlatformError> {
        let domain = format!("gui/{uid}");
        Self::run(&["bootstrap".as_ref(), domain.as_ref(), plist.as_os_str()])
    }

    fn bootout(&self, uid: u32, label: &str) -> Result<bool, PlatformError> {
        let target = format!("gui/{uid}/{label}");
        match Self::run(&["bootout".as_ref(), target.as_ref()]) {
            Ok(()) => Ok(true),
            Err(PlatformError::Launchctl {
                status: Some(NOT_LOADED | NOT_FOUND),
            }) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-012: a process launchd did not start gets no sockets (`ESRCH`), so `knshd` cannot run outside launchd.
    #[test]
    fn activation_outside_launchd_fails() {
        let error = LaunchdSockets::new().listeners("user").unwrap_err();
        assert!(
            matches!(
                error,
                PlatformError::Os {
                    operation: Operation::ActivateSocket,
                    errno: libc::ESRCH | libc::ENOENT,
                }
            ),
            "{error:?}"
        );
        assert_eq!(
            LaunchdSockets::new().listeners("a\0b").unwrap_err().errno(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn peer_credentials_report_own_uid_for_a_socket_pair() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(
            SystemPeerCredentials::new().peer_uid(&a).unwrap(),
            super::super::effective_uid()
        );
    }

    // Not loaded is not an error: uninstall and reinstall both start with a bootout. Ignored by default: it runs the
    // real `launchctl` against the user's GUI domain, which CI runners and SSH sessions may not have (a missing
    // domain exits with another status).
    #[test]
    #[ignore = "runs /bin/launchctl against the user's GUI domain; run with --ignored"]
    fn bootout_of_unknown_label_reports_not_loaded() {
        let uid = super::super::effective_uid();
        let label = format!("knsh.test.absent.{}", std::process::id());
        assert_eq!(Launchctl::new().bootout(uid, &label), Ok(false));
    }
}
