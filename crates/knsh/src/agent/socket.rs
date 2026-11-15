//! The real `agent.sock` connection of `knsh -c` (KNSH-049): a Unix socket that passes this process's stdin, stdout
//! and stderr with `exec.run` (`SCM_RIGHTS`, through `knsh-platform`, so `knsh` itself stays free of `unsafe`).

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use knsh_json::{Object, Value};
use knsh_platform::macos::send_with_descriptors;

use super::forward::AgentSocket;
use crate::cli::client::{Client, ClientError};

/// How long `knshd` may take to answer `hello`, including being started on demand by launchd.
const HELLO_TIMEOUT: Duration = Duration::from_secs(60);

/// How long writing the request may block. Reading the answer has no limit: a supervised line may run for hours, and
/// the agent CLI's own tool timeout (which kills `knsh`) is what bounds it.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Where a missing standard stream is taken from, so the line sees a stream rather than a closed descriptor.
const DEV_NULL: &str = "/dev/null";

/// `EBADF` on macOS: the descriptor is not open. Spelled out because `knsh` does not depend on `libc`.
const EBADF: i32 = 9;

/// A connection to `agent.sock` at a path, opened by [`AgentSocket::open`].
pub struct UnixAgentSocket {
    path: PathBuf,
    /// The streams the line gets, taken before anything else is opened (see [`Stdio`] for why).
    stdio: Stdio,
    connection: Option<(Client<UnixStream, UnixStream>, UnixStream)>,
}

impl UnixAgentSocket {
    /// A socket for `agent.sock` at `path`, not yet connected, that will pass this process's stdin, stdout and
    /// stderr. Call it before opening any other descriptor.
    ///
    /// # Errors
    ///
    /// The error of duplicating a standard stream, or of opening `/dev/null` for one that is closed.
    pub fn new(path: PathBuf) -> io::Result<Self> {
        Ok(Self {
            path,
            stdio: Stdio::of_this_process()?,
            connection: None,
        })
    }
}

impl AgentSocket for UnixAgentSocket {
    fn open(&mut self, session_token: Option<&str>) -> Result<(), ClientError> {
        // Connecting is all `knsh` does to reach `knshd`; launchd may start it for this socket (KNSH-023).
        let stream = UnixStream::connect(&self.path).map_err(ClientError::Connect)?;
        stream.set_read_timeout(Some(HELLO_TIMEOUT)).map_err(ClientError::Io)?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT)).map_err(ClientError::Io)?;
        let reader = stream.try_clone().map_err(ClientError::Io)?;
        let writer = stream.try_clone().map_err(ClientError::Io)?;
        let mut client = Client::new(reader, writer);
        client.hello_with_token(session_token)?;
        // Lifted while `knshd` has just answered: the line's answer comes when the line ends.
        stream.set_read_timeout(None).map_err(ClientError::Io)?;
        self.connection = Some((client, stream));
        Ok(())
    }

    fn exec_run(&mut self, params: &Value) -> Result<Value, ClientError> {
        let (client, stream) = self.connection.as_mut().ok_or(ClientError::Closed)?;
        let Value::Object(params) = params else {
            return Err(ClientError::Protocol);
        };
        let descriptors = self.stdio.borrowed();
        let stream: &UnixStream = stream;
        client.call_sending("exec.run", Some(Object::clone(params)), &mut |frame| {
            send_with_descriptors(stream, frame, &descriptors)
        })
    }
}

/// This process's stdin, stdout and stderr, as the line receives them: duplicates, which share the open files (and
/// so the terminal or pipes) with the originals. A stream that is closed is replaced by `/dev/null`, as if the caller
/// had redirected it there.
///
/// Taken before the connection is made: were descriptor 0 closed, the socket could otherwise land on it and be
/// passed to the line as its stdin, giving the line this connection to `knshd`. Shared with `knsh agent` (KNSH-056),
/// which passes the same three streams to the agent CLI.
pub(crate) struct Stdio {
    streams: [OwnedFd; 3],
}

impl Stdio {
    /// Duplicates of this process's stdin, stdout and stderr (`/dev/null` for a closed one).
    pub(crate) fn of_this_process() -> io::Result<Self> {
        Ok(Self {
            streams: [
                stream(io::stdin().as_fd(), false)?,
                stream(io::stdout().as_fd(), true)?,
                stream(io::stderr().as_fd(), true)?,
            ],
        })
    }

    /// The three streams, in order, for sending.
    pub(crate) fn borrowed(&self) -> [BorrowedFd<'_>; 3] {
        self.streams.each_ref().map(AsFd::as_fd)
    }
}

/// A duplicate of `fd` if it is open; otherwise `/dev/null`, for writing when `write` is set.
fn stream(fd: BorrowedFd<'_>, write: bool) -> io::Result<OwnedFd> {
    match fd.try_clone_to_owned() {
        Ok(copy) => Ok(copy),
        // Closed: duplicating it is how that shows, without `fcntl`.
        Err(error) if error.raw_os_error() == Some(EBADF) => {
            let null: File = OpenOptions::new().read(!write).write(write).open(DEV_NULL)?;
            Ok(OwnedFd::from(null))
        }
        Err(error) => Err(error),
    }
}
