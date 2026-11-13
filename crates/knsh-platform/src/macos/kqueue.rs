//! An event queue over `kqueue(2)`: readable listeners, cross-thread wake-ups and termination signals (KNSH-013).
//!
//! `knshd` has no async runtime (CLAUDE.md "Dependencies"): its accept loop is one thread blocked in [`Kqueue::wait`]
//! that wakes when a listener has a connection, when another thread calls [`Kqueue::wake`] (a connection closed), when
//! launchd asks it to stop (`SIGTERM`), or when the timeout passes (the idle clock is due).
//!
//! Each registration carries a caller-chosen [`Token`]; [`Kqueue::wait`] reports tokens, never raw descriptors, so the
//! caller cannot confuse a listener with a wake-up.

use std::ffi::c_int;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::Duration;

use crate::error::{Operation, PlatformError};

/// Identifies a registration in [`Kqueue::wait`] results. Chosen by the caller; distinct registrations should use
/// distinct tokens.
pub type Token = usize;

/// Most events read by one [`Kqueue::wait`]. More pending events are returned by the next call.
const MAX_EVENTS: usize = 16;

/// The signals [`Kqueue::watch_termination`] turns into events: `SIGTERM` (launchd stopping the job) and `SIGINT`
/// (Ctrl-C when run by hand).
const TERMINATION_SIGNALS: [c_int; 2] = [libc::SIGTERM, libc::SIGINT];

/// [`PlatformError::Os`] for `operation` from the current `errno`.
fn last_error(operation: Operation) -> PlatformError {
    PlatformError::from_io(operation, &io::Error::last_os_error())
}

/// A kernel event queue. `Send + Sync`: `kevent` may be called from any thread, so one thread can wait while others
/// [`wake`](Self::wake) it.
#[derive(Debug)]
pub struct Kqueue {
    fd: OwnedFd,
}

impl Kqueue {
    /// A new, empty queue. A kqueue is never inherited by a child process (`kqueue(2)`), so no agent command can see
    /// it.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] ([`Operation::EventQueue`]) if the kernel cannot create one (`EMFILE`, `ENOMEM`).
    pub fn new() -> Result<Self, PlatformError> {
        // SAFETY: `kqueue` takes no arguments and returns a new descriptor or -1.
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(last_error(Operation::EventQueue));
        }
        // SAFETY: `raw` is a fresh descriptor that nothing else owns.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
        })
    }

    /// Reports `token` whenever `fd` is readable: for a listening socket, when a connection is waiting to be accepted.
    /// Level-triggered: the event repeats until the backlog is drained.
    ///
    /// The registration ends when `fd` is closed. The caller keeps `fd` open while it waits.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] ([`Operation::EventQueue`]) if the registration fails (`EBADF` for a closed descriptor).
    pub fn watch_readable(&self, fd: BorrowedFd<'_>, token: Token) -> Result<(), PlatformError> {
        let ident = usize::try_from(fd.as_raw_fd()).map_err(|_| PlatformError::Os {
            operation: Operation::EventQueue,
            errno: libc::EBADF,
        })?;
        self.change(change(ident, libc::EVFILT_READ, libc::EV_ADD, 0, token))
    }

    /// Registers a wake-up that [`wake`](Self::wake) triggers from any thread. Edge-triggered: one wake reports
    /// `token` once, and several wakes before a [`wait`](Self::wait) are reported once.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] ([`Operation::EventQueue`]) if the registration fails.
    pub fn watch_wakeup(&self, token: Token) -> Result<(), PlatformError> {
        self.change(change(
            token,
            libc::EVFILT_USER,
            libc::EV_ADD | libc::EV_CLEAR,
            0,
            token,
        ))
    }

    /// Makes a [`wait`](Self::wait) report the wake-up `token`, which [`watch_wakeup`](Self::watch_wakeup) registered.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] ([`Operation::EventQueue`]) if `token` was never registered (`ENOENT`).
    pub fn wake(&self, token: Token) -> Result<(), PlatformError> {
        self.change(change(token, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER, token))
    }

    /// Turns `SIGTERM` and `SIGINT` into `token` events instead of terminating the process, so the caller can shut
    /// down in order (finish in-flight requests, commit pending writes).
    ///
    /// The signals get a handler that does nothing, with `SA_RESTART` so no other thread sees `EINTR` from them. A
    /// handler, unlike `SIG_IGN` or a blocked mask, is reset by `exec`: processes this one starts still terminate on
    /// `SIGTERM`. The signal is registered with the queue before the handler is installed, so none is ever lost.
    ///
    /// Process-wide: call it once, from the process that owns the queue.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::EventQueue`] if the registration fails, or [`Operation::WatchSignal`]
    /// if the handler cannot be installed.
    pub fn watch_termination(&self, token: Token) -> Result<(), PlatformError> {
        for signal in TERMINATION_SIGNALS {
            let ident = usize::try_from(signal).map_err(|_| PlatformError::Os {
                operation: Operation::WatchSignal,
                errno: libc::EINVAL,
            })?;
            self.change(change(ident, libc::EVFILT_SIGNAL, libc::EV_ADD, 0, token))?;
            install_noop_handler(signal)?;
        }
        Ok(())
    }

    /// Waits until at least one registration fires or `timeout` passes, then appends the fired tokens to `events`
    /// (after clearing it). An empty `events` means the timeout passed or a signal interrupted the wait.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] ([`Operation::EventQueue`]) if `kevent` fails for a reason other than `EINTR`.
    pub fn wait(&self, timeout: Duration, events: &mut Vec<Token>) -> Result<(), PlatformError> {
        events.clear();
        let timeout = libc::timespec {
            // Saturate: a timeout past `time_t::MAX` seconds is "forever" in practice.
            tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
            tv_nsec: libc::c_long::from(timeout.subsec_nanos()),
        };
        let mut fired = [empty_event(); MAX_EVENTS];
        let capacity = c_int::try_from(MAX_EVENTS).unwrap_or(c_int::MAX);
        // SAFETY: no changes are passed; `fired` has room for `capacity` events and `timeout` is a valid timespec,
        // all of which outlive the call.
        let count = unsafe {
            libc::kevent(
                self.fd.as_raw_fd(),
                std::ptr::null(),
                0,
                fired.as_mut_ptr(),
                capacity,
                &raw const timeout,
            )
        };
        let Ok(count) = usize::try_from(count) else {
            let error = io::Error::last_os_error();
            // A signal (ours included: SIGTERM is handled) interrupted the wait; the signal event, if any, is reported
            // by the next wait.
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(PlatformError::from_io(Operation::EventQueue, &error));
        };
        // The token travels in `udata` as an address-sized integer; it is never dereferenced.
        events.extend(fired.iter().take(count).map(|event| event.udata.addr()));
        Ok(())
    }

    /// Applies one change to the queue.
    fn change(&self, change: libc::kevent) -> Result<(), PlatformError> {
        // SAFETY: `change` is one valid event, no event list is read back and the timeout is null (do not wait).
        let rc = unsafe {
            libc::kevent(
                self.fd.as_raw_fd(),
                &raw const change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if rc < 0 {
            return Err(last_error(Operation::EventQueue));
        }
        Ok(())
    }
}

/// A change record for `kevent`, carrying `token` in `udata`.
fn change(ident: usize, filter: i16, flags: u16, filter_flags: u32, token: Token) -> libc::kevent {
    libc::kevent {
        ident,
        filter,
        flags,
        fflags: filter_flags,
        data: 0,
        udata: std::ptr::without_provenance_mut(token),
    }
}

/// An all-zero event, to fill the output buffer.
const fn empty_event() -> libc::kevent {
    libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

/// The handler for watched termination signals. It does nothing: the queue reports the signal.
extern "C" fn noop_handler(_signal: c_int) {}

/// Installs [`noop_handler`] for `signal` with `SA_RESTART`.
fn install_noop_handler(signal: c_int) -> Result<(), PlatformError> {
    // SAFETY: an all-zero `sigaction` is a valid starting value (empty mask, no flags); every field used is set below.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = noop_handler as extern "C" fn(c_int) as libc::sighandler_t;
    action.sa_flags = libc::SA_RESTART;
    // SAFETY: `action` is fully initialised, the old action is not requested, and the handler is async-signal-safe
    // (it does nothing).
    let rc = unsafe { libc::sigaction(signal, &raw const action, std::ptr::null_mut()) };
    if rc < 0 {
        return Err(last_error(Operation::WatchSignal));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::Arc;
    use std::time::Instant;

    use super::*;

    const LISTENER: Token = 1;
    const WAKE: Token = 2;

    #[test]
    fn wait_times_out_with_no_events() {
        let queue = Kqueue::new().unwrap();
        let mut events = vec![99];
        let started = Instant::now();
        queue.wait(Duration::from_millis(20), &mut events).unwrap();
        assert_eq!(events, Vec::<Token>::new());
        assert!(started.elapsed() >= Duration::from_millis(15));
    }

    // The accept loop wakes when a connection is waiting, and the event repeats until it is accepted.
    #[test]
    fn reports_listener_with_pending_connection() {
        let dir = std::env::temp_dir().join(format!("knsh-kq-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let queue = Kqueue::new().unwrap();
        queue.watch_readable(listener.as_fd(), LISTENER).unwrap();

        let mut events = Vec::new();
        queue.wait(Duration::ZERO, &mut events).unwrap();
        assert_eq!(events, Vec::<Token>::new());

        let _client = UnixStream::connect(&path).unwrap();
        queue.wait(Duration::from_secs(5), &mut events).unwrap();
        assert_eq!(events, vec![LISTENER]);
        queue.wait(Duration::ZERO, &mut events).unwrap();
        assert_eq!(events, vec![LISTENER], "level-triggered until accepted");

        let _accepted = listener.accept().unwrap();
        queue.wait(Duration::ZERO, &mut events).unwrap();
        assert_eq!(events, Vec::<Token>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Another thread can wake the waiter; several wakes coalesce into one event.
    #[test]
    fn wake_from_another_thread() {
        let queue = Arc::new(Kqueue::new().unwrap());
        queue.watch_wakeup(WAKE).unwrap();
        let waker = Arc::clone(&queue);
        let thread = std::thread::spawn(move || {
            waker.wake(WAKE).unwrap();
            waker.wake(WAKE).unwrap();
        });
        thread.join().unwrap();
        let mut events = Vec::new();
        queue.wait(Duration::from_secs(5), &mut events).unwrap();
        assert_eq!(events, vec![WAKE]);
        queue.wait(Duration::ZERO, &mut events).unwrap();
        assert_eq!(events, Vec::<Token>::new());
    }

    // launchd's SIGTERM becomes an event instead of killing the process, so shutdown can be orderly.
    #[test]
    fn termination_signal_becomes_an_event() {
        const TERM: Token = 3;
        let queue = Kqueue::new().unwrap();
        queue.watch_termination(TERM).unwrap();
        let status = std::process::Command::new("/bin/kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        let mut events = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while events.is_empty() && Instant::now() < deadline {
            queue.wait(Duration::from_secs(1), &mut events).unwrap();
        }
        assert_eq!(events, vec![TERM]);
    }

    #[test]
    fn waking_an_unregistered_token_fails() {
        let queue = Kqueue::new().unwrap();
        assert!(matches!(
            queue.wake(WAKE),
            Err(PlatformError::Os {
                operation: Operation::EventQueue,
                ..
            })
        ));
    }
}
