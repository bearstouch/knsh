//! The supervision channel over a Unix socket pair (KNSH-108): the interpreter's client ([`SocketLink`]) and the
//! supervisor's reading and writing of frames ([`RequestReader`], [`write_frame`]).
//!
//! Requests travel from the interpreter with the command's descriptors attached to the first byte of their frame
//! ([`super::send_with_descriptors_up_to`]); the reader collects every descriptor that arrives in one queue and gives
//! each request as many as its table names, in order. Descriptors ride on the first byte of their own frame, so they
//! never arrive after the bytes of a later frame: the queue is always in step. A request whose descriptors are
//! missing, or extra descriptors left over, breaks the channel (closing what arrived).
//!
//! The client has one reader thread that hands each reply to the request waiting for it (by id), so the interpreter's
//! threads can wait for their commands side by side. When the channel fails, every waiting request and every later
//! one fails, and the spawner denies them ([`crate::supervision`]).

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, PoisonError};

use super::descriptors::{MAX_COMMAND_DESCRIPTORS, recv_with_descriptors_up_to, send_with_descriptors_up_to};
use crate::process::ExitStatus;
use crate::supervision::{
    Reply, Request, StartAnswer, Submission, SupervisionError, SupervisorLink, encode_frame, frame_len,
};

/// Takes ownership of descriptor `fd`, which `knshd` passed the native interpreter as its end of the channel
/// (`knsh --native-line <fd> …`), as a Unix stream, marked close-on-exec.
///
/// # Errors
///
/// `EBADF` if `fd` is below 3 or not open, `ENOTSOCK` if it is not a socket: the interpreter then has no supervisor
/// and denies every command (FR-LC-57). Nothing is taken over on failure.
pub fn inherited_stream(fd: RawFd) -> std::io::Result<UnixStream> {
    if fd < 3 {
        return Err(std::io::Error::from_raw_os_error(libc::EBADF));
    }
    // SAFETY: an all-zero `stat` is a valid value for `fstat` to fill.
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fstat` only reads the descriptor number and writes `status`, which outlives the call.
    if unsafe { libc::fstat(fd, &raw mut status) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSOCK));
    }
    // SAFETY: `fcntl(F_SETFD)` takes an open descriptor (checked above) and a plain flag.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is open and a socket (checked above), and the caller hands it over: this process received it from
    // `knshd` for this purpose only, and nothing else in it owns or closes the number.
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

/// Most descriptors received and not yet given to a request: a few requests' tables. More breaks the channel, so a
/// sender cannot make the supervisor hold descriptors without bound.
const MAX_QUEUED_DESCRIPTORS: usize = 4 * MAX_COMMAND_DESCRIPTORS;

/// Writes `payload` as one frame on `stream`, with `descriptors` attached to its first byte.
///
/// # Errors
///
/// The frame is too large, or the socket failed ([`SupervisionError::from_io`]).
pub fn write_frame(
    stream: &UnixStream,
    payload: &[u8],
    descriptors: &[BorrowedFd<'_>],
) -> Result<(), SupervisionError> {
    let frame = encode_frame(payload)?;
    if descriptors.is_empty() {
        let mut writer = stream;
        return writer
            .write_all(&frame)
            .map_err(|error| SupervisionError::from_io(&error));
    }
    send_with_descriptors_up_to(stream, &frame, descriptors, MAX_COMMAND_DESCRIPTORS)
        .map_err(|error| SupervisionError::from_io(&error))
}

/// The supervisor's reader of requests on its end of a native-mode line's channel.
#[derive(Debug)]
pub struct RequestReader {
    stream: UnixStream,
    /// Bytes read and not yet part of a request.
    buffered: Vec<u8>,
    /// Descriptors received and not yet given to a request, in arrival order.
    descriptors: VecDeque<OwnedFd>,
}

impl RequestReader {
    /// A reader of `stream`, which must not be read by anything else.
    #[must_use]
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            buffered: Vec::new(),
            descriptors: VecDeque::new(),
        }
    }

    /// The next request with its descriptors, or `None` once the interpreter closed its end between two requests.
    ///
    /// # Errors
    ///
    /// [`SupervisionError::Malformed`] for a frame over the limit, a request that does not decode, or descriptors
    /// that do not match its table (more than [`MAX_COMMAND_DESCRIPTORS`] in one read, more than a few requests'
    /// worth queued, too few, or left over at the end);
    /// [`SupervisionError::Closed`] for an end inside a frame; the socket's error otherwise. The channel is unusable
    /// afterwards: every descriptor received is closed when the reader is dropped.
    pub fn next_request(&mut self) -> Result<Option<(Request, Vec<OwnedFd>)>, SupervisionError> {
        let Some(header) = self.fill(4)? else {
            if self.descriptors.is_empty() {
                return Ok(None);
            }
            return Err(SupervisionError::Malformed);
        };
        let mut length = [0u8; 4];
        length.copy_from_slice(&header);
        let len = frame_len(length)?;
        self.buffered.drain(..4);
        let Some(payload) = self.fill(len)? else {
            return Err(SupervisionError::Closed);
        };
        let request = Request::decode(&payload)?;
        self.buffered.drain(..len);
        let wanted = request.descriptor_count();
        if self.descriptors.len() < wanted {
            return Err(SupervisionError::Malformed);
        }
        let descriptors = self.descriptors.drain(..wanted).collect();
        Ok(Some((request, descriptors)))
    }

    /// Reads until `len` bytes are buffered and returns a copy of them; `None` at end of stream before any byte of
    /// them (an end inside them is [`SupervisionError::Closed`]).
    fn fill(&mut self, len: usize) -> Result<Option<Vec<u8>>, SupervisionError> {
        let mut chunk = vec![0u8; 64 * 1024];
        while self.buffered.len() < len {
            let mut arrived = Vec::new();
            let read = recv_with_descriptors_up_to(&self.stream, &mut chunk, &mut arrived, MAX_COMMAND_DESCRIPTORS)
                .map_err(|error| match error.kind() {
                    std::io::ErrorKind::InvalidData => SupervisionError::Malformed,
                    _ => SupervisionError::from_io(&error),
                })?;
            self.descriptors.extend(arrived);
            // One read carries at most one message's descriptors, but may also take the first bytes (and so the
            // descriptors) of the frames after the one being read: a few requests' worth may queue, never more.
            if self.descriptors.len() > MAX_QUEUED_DESCRIPTORS {
                return Err(SupervisionError::Malformed);
            }
            if read == 0 {
                if self.buffered.is_empty() {
                    return Ok(None);
                }
                return Err(SupervisionError::Closed);
            }
            self.buffered.extend_from_slice(&chunk[..read]);
        }
        Ok(Some(self.buffered[..len].to_vec()))
    }
}

/// Replies waiting to be delivered, by request id.
type Pending = HashMap<u64, Sender<Result<Reply, SupervisionError>>>;

/// State shared by the link and its reader thread.
#[derive(Debug, Default)]
struct Shared {
    pending: Mutex<Pending>,
    /// Set once the reader saw the channel fail or close: nothing is sent any more.
    broken: AtomicBool,
}

impl Shared {
    /// Fails every waiting request and every later one.
    fn break_all(&self, error: SupervisionError) {
        self.broken.store(true, Ordering::SeqCst);
        let pending = std::mem::take(&mut *self.pending.lock().unwrap_or_else(PoisonError::into_inner));
        for (_, waiter) in pending {
            let _ = waiter.send(Err(error));
        }
    }
}

/// The interpreter's [`SupervisorLink`] over its end of the socket pair `knshd` passed it (module documentation).
#[derive(Debug)]
pub struct SocketLink {
    /// Writes requests; one at a time, so frames never interleave.
    writer: Mutex<UnixStream>,
    shared: Arc<Shared>,
    next_id: AtomicU64,
}

impl SocketLink {
    /// A link over `stream`, with its reader thread started.
    ///
    /// # Errors
    ///
    /// The stream cannot be duplicated for the reader, or the thread cannot start.
    pub fn new(stream: UnixStream) -> std::io::Result<Self> {
        let reading = stream.try_clone()?;
        let shared = Arc::new(Shared::default());
        let for_reader = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("knsh-supervision".to_owned())
            .spawn(move || read_replies(reading, &for_reader))?;
        Ok(Self {
            writer: Mutex::new(stream),
            shared,
            next_id: AtomicU64::new(1),
        })
    }

    /// Sends `request` with `descriptors` and waits for its reply.
    fn call(&self, request: &Request, descriptors: &[BorrowedFd<'_>]) -> Result<Reply, SupervisionError> {
        let id = match request {
            Request::Start { id, .. } | Request::Wait { id, .. } => *id,
        };
        let payload = request.encode()?;
        let (sender, receiver) = mpsc::channel();
        {
            let mut pending = self.shared.pending.lock().unwrap_or_else(PoisonError::into_inner);
            // Checked under the lock `break_all` takes, so a request is either failed by it or sees the flag.
            if self.shared.broken.load(Ordering::SeqCst) {
                return Err(SupervisionError::Closed);
            }
            pending.insert(id, sender);
        }
        let sent = {
            let writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
            write_frame(&writer, &payload, descriptors)
        };
        if let Err(error) = sent {
            self.shared.break_all(error);
        }
        let reply = receiver.recv().map_err(|_| SupervisionError::Closed)??;
        if reply.id() == id {
            Ok(reply)
        } else {
            Err(SupervisionError::Malformed)
        }
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }
}

impl Drop for SocketLink {
    fn drop(&mut self) {
        // Ends the reader thread: it sees end of stream once the supervisor closes too, or an error now.
        let writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writer.shutdown(std::net::Shutdown::Both);
    }
}

/// The reader thread: delivers each reply to its request until the channel ends, then fails what still waits.
fn read_replies(mut stream: UnixStream, shared: &Shared) {
    let error = loop {
        let mut header = [0u8; 4];
        if let Err(error) = stream.read_exact(&mut header) {
            break SupervisionError::from_io(&error);
        }
        let len = match frame_len(header) {
            Ok(len) => len,
            Err(error) => break error,
        };
        let mut payload = vec![0u8; len];
        if let Err(error) = stream.read_exact(&mut payload) {
            break SupervisionError::from_io(&error);
        }
        let reply = match Reply::decode(&payload) {
            Ok(reply) => reply,
            Err(error) => break error,
        };
        let waiter = shared
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&reply.id());
        // A reply to nothing asked is not one this protocol sends.
        let Some(waiter) = waiter else {
            break SupervisionError::Malformed;
        };
        let _ = waiter.send(Ok(reply));
    };
    shared.break_all(error);
}

impl SupervisorLink for SocketLink {
    fn start(&self, submission: &Submission, descriptors: &[BorrowedFd<'_>]) -> Result<StartAnswer, SupervisionError> {
        let request = Request::Start {
            id: self.next_id(),
            submission: submission.clone(),
        };
        match self.call(&request, descriptors)? {
            Reply::Running { child, pid, .. } => Ok(StartAnswer::Running { child, pid }),
            Reply::Denied { reason, .. } => Ok(StartAnswer::Denied(reason)),
            Reply::NotFound { .. } => Ok(StartAnswer::NotFound),
            Reply::NotExecutable { .. } | Reply::Failed { .. } => Ok(StartAnswer::NotExecutable),
            Reply::Exited { .. } => Err(SupervisionError::Malformed),
        }
    }

    fn wait(&self, child: u64) -> Result<ExitStatus, SupervisionError> {
        let request = Request::Wait {
            id: self.next_id(),
            child,
        };
        match self.call(&request, &[])? {
            Reply::Exited { status, .. } => Ok(status),
            Reply::Failed { .. } => Err(SupervisionError::Malformed),
            Reply::Running { .. } | Reply::Denied { .. } | Reply::NotFound { .. } | Reply::NotExecutable { .. } => {
                Err(SupervisionError::Malformed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;
    use std::path::PathBuf;
    use std::thread;

    use super::*;

    fn submission(descriptors: Vec<i32>) -> Submission {
        Submission {
            program: PathBuf::from("/bin/echo"),
            argv0: "echo".into(),
            args: vec!["hi".into()],
            env: Vec::new(),
            cwd: PathBuf::from("/"),
            umask: None,
            descriptors,
        }
    }

    // KNSH-108: requests reach the supervisor with their descriptors, in order, and replies reach the request waiting
    // for them, also when two are pending at once.
    #[test]
    fn link_and_reader_carry_requests_descriptors_and_replies() {
        let (client, server) = UnixStream::pair().unwrap();
        let link = Arc::new(SocketLink::new(client).unwrap());
        let supervisor = thread::spawn(move || {
            let writer = server.try_clone().unwrap();
            let mut reader = RequestReader::new(server);
            let mut seen = Vec::new();
            while let Some((request, descriptors)) = reader.next_request().unwrap() {
                let reply = match &request {
                    Request::Start { id, .. } => Reply::Running {
                        id: *id,
                        child: 40 + *id,
                        pid: 1000,
                    },
                    Request::Wait { id, child } => Reply::Exited {
                        id: *id,
                        status: ExitStatus::Exited(i32::try_from(*child).unwrap()),
                    },
                };
                seen.push((request, descriptors.len()));
                write_frame(&writer, &reply.encode().unwrap(), &[]).unwrap();
            }
            seen
        });
        let null = std::fs::File::open("/dev/null").unwrap();
        let fds = [null.as_fd(), null.as_fd(), null.as_fd()];
        let answer = link.start(&submission(vec![0, 1, 5]), &fds).unwrap();
        let StartAnswer::Running { child, pid } = answer else {
            panic!("{answer:?}")
        };
        assert_eq!(pid, 1000);
        let waits: Vec<_> = (0..2)
            .map(|_| {
                let link = Arc::clone(&link);
                thread::spawn(move || link.wait(child).unwrap())
            })
            .collect();
        for wait in waits {
            assert_eq!(wait.join().unwrap(), ExitStatus::Exited(i32::try_from(child).unwrap()));
        }
        drop(link);
        let seen = supervisor.join().unwrap();
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0].1, 3);
        assert_eq!(seen[1].1, 0);
    }

    // FR-LC-57: once the supervisor's end is gone, every request fails, the waiting one included.
    #[test]
    fn closed_channel_fails_every_request() {
        let (client, server) = UnixStream::pair().unwrap();
        let link = SocketLink::new(client).unwrap();
        drop(server);
        assert!(link.start(&submission(Vec::new()), &[]).is_err());
        assert!(link.wait(1).is_err());
        assert!(link.start(&submission(Vec::new()), &[]).is_err());
    }

    // Untrusted input: a request naming more descriptors than arrived breaks the channel.
    #[test]
    fn reader_refuses_missing_descriptors() {
        let (client, server) = UnixStream::pair().unwrap();
        let request = Request::Start {
            id: 1,
            submission: submission(vec![0, 1]),
        };
        let null = std::fs::File::open("/dev/null").unwrap();
        write_frame(&client, &request.encode().unwrap(), &[null.as_fd()]).unwrap();
        let mut reader = RequestReader::new(server);
        assert_eq!(reader.next_request().unwrap_err(), SupervisionError::Malformed);
    }

    // Untrusted input: a frame longer than the limit is refused before it is read.
    #[test]
    fn reader_refuses_oversized_frames() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&u32::MAX.to_be_bytes()).unwrap();
        let mut reader = RequestReader::new(server);
        assert_eq!(reader.next_request().unwrap_err(), SupervisionError::Malformed);
        let (client, server) = UnixStream::pair().unwrap();
        drop(client);
        assert!(RequestReader::new(server).next_request().unwrap().is_none());
    }
}
