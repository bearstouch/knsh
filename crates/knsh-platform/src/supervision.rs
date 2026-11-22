//! The supervision channel of a native-mode line (KNSH-108, FR-LC-52 to FR-LC-57,
//! `specs/03-functional-requirements/command-lifecycle.md#native-mode-knsh-108`).
//!
//! A native-mode line runs in `knsh`'s own interpreter, sandboxed so that it can execute nothing. Before each external
//! command it would start, the interpreter sends the command to the supervisor over a socket pair `knshd` created for
//! the line; the supervisor decides it with the phase 2 pipeline and, if it is allowed, starts it through `knsh-exec`
//! and later reports how it ended. This module holds both halves of what crosses that channel:
//!
//! - the messages ([`Request`], [`Reply`]) and their encoding: one JSON object per frame, behind a 4-byte big-endian
//!   length of at most [`MAX_FRAME`] bytes ([`encode_frame`], [`frame_len`]). Every byte string (program, arguments,
//!   environment, working directory) is base64, so a path or value that is not UTF-8 crosses unchanged. A start
//!   request carries the command's whole descriptor table: the numbers in the message, the descriptors themselves
//!   attached to the frame (`SCM_RIGHTS`, one per number, in order);
//! - [`SupervisedSpawner`], the interpreter's [`CommandSpawner`] over a [`SupervisorLink`]: the real link is the
//!   macOS socket client (`macos::SocketLink`), tests use [`crate::testing::FakeSupervisor`].
//!
//! # Fail closed (FR-LC-57, NFR-REL-01)
//!
//! A denied command is reported on the command's own standard error (`knsh: <name>: <reason>`, after its
//! redirections) and refused with [`CommandOutcome::Denied`], which the interpreter turns into status 126.
//! When the link fails (closed, broken, an answer that is not one), the spawner marks itself broken and denies that
//! command and every later one the same way, without asking again: nothing runs without the supervisor.
//!
//! # Not available to a native-mode line
//!
//! Job control: every command joins the line's process group (FR-LC-56), so [`ChildOptions`] are not sent and
//! [`CommandSpawner::signal_job`] knows no group. A command's stops are not reported; only its end is.

use std::collections::HashSet;
use std::ffi::OsString;
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use knsh_json::{Object, Value, base64_decode, base64_encode};

use crate::command::{ChildDescriptor, CommandOutcome, CommandRequest, CommandSpawner, StandardStream, Started};
use crate::error::{Operation, PlatformError};
use crate::process::{ChildEvent, ChildHandle, ChildOptions, ExitStatus, MAX_PLACED_FD, ProcessGroupId, Signal};

/// The largest frame either side sends or accepts, in bytes after the length: the API's frame limit
/// ([`knsh_json::MAX_PAYLOAD`], 1 MiB).
pub const MAX_FRAME: usize = knsh_json::MAX_PAYLOAD;

/// Most descriptors one command's table may hold (`specs/09-reference/defaults-and-limits.md`).
pub const MAX_COMMAND_DESCRIPTORS: usize = 64;

/// Most arguments after `argv[0]` one command may have: what `knsh-exec` accepts (`--arg`, at most 4096).
pub const MAX_COMMAND_ARGS: usize = 4096;

/// Most environment entries one command may have.
pub const MAX_COMMAND_ENV: usize = 4096;

/// Why the channel failed. The interpreter's spawner treats every one as "the supervisor is unreachable".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisionError {
    /// The other end closed the channel.
    Closed,
    /// Reading or writing the socket failed with this `errno`.
    Io(i32),
    /// A message, or its frame, is not one this protocol sends: malformed JSON, an unknown field value, a length
    /// over [`MAX_FRAME`], descriptors that do not match the table, a limit exceeded.
    Malformed,
}

impl std::fmt::Display for SupervisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => f.write_str("the supervision channel is closed"),
            Self::Io(errno) => write!(f, "the supervision channel failed (errno {errno})"),
            Self::Malformed => f.write_str("a malformed message on the supervision channel"),
        }
    }
}

impl std::error::Error for SupervisionError {}

impl SupervisionError {
    /// The error of an I/O failure: [`SupervisionError::Closed`] for a broken pipe or reset, its `errno` otherwise.
    #[must_use]
    pub fn from_io(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::NotConnected => Self::Closed,
            _ => Self::Io(error.raw_os_error().unwrap_or(libc::EIO)),
        }
    }
}

/// One external command the interpreter asks the supervisor to decide and start: what [`CommandRequest`] holds,
/// with the descriptor table as numbers (the descriptors travel beside the message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    /// The program the interpreter resolved: absolute, not canonicalised.
    pub program: PathBuf,
    /// `argv[0]` as written.
    pub argv0: OsString,
    /// The arguments after `argv[0]`.
    pub args: Vec<OsString>,
    /// The complete environment.
    pub env: Vec<(OsString, OsString)>,
    /// The working directory, absolute.
    pub cwd: PathBuf,
    /// The file mode creation mask, or `None` for the supervisor's default.
    pub umask: Option<u32>,
    /// The descriptor numbers of the command's table, strictly increasing, each 0 to [`MAX_PLACED_FD`]; the
    /// descriptors themselves are attached to the frame in this order.
    pub descriptors: Vec<i32>,
}

/// A message from the interpreter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Decide `submission` and, if allowed, start it. Answered [`Reply::Running`], [`Reply::Denied`],
    /// [`Reply::NotFound`], [`Reply::NotExecutable`] or [`Reply::Failed`].
    Start {
        /// The request's number, echoed by its reply. Unique among the requests still unanswered.
        id: u64,
        /// The command.
        submission: Submission,
    },
    /// Wait for a started command to end. Answered [`Reply::Exited`] or [`Reply::Failed`].
    Wait {
        /// The request's number.
        id: u64,
        /// The command, as [`Reply::Running`] named it.
        child: u64,
    },
}

/// A message from the supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// The command was allowed and started.
    Running {
        /// The request answered.
        id: u64,
        /// The command's number for [`Request::Wait`], never reused on this channel.
        child: u64,
        /// Its process id, for display only (`$!`).
        pid: i32,
    },
    /// The command was denied and never started (FR-LC-55).
    Denied {
        /// The request answered.
        id: u64,
        /// Why, already redacted: printed on the command's standard error.
        reason: String,
    },
    /// The program does not exist (bash's 127).
    NotFound {
        /// The request answered.
        id: u64,
    },
    /// The program cannot be executed (bash's 126).
    NotExecutable {
        /// The request answered.
        id: u64,
    },
    /// The command ended.
    Exited {
        /// The request answered.
        id: u64,
        /// How.
        status: ExitStatus,
    },
    /// The supervisor could not do what was asked (a start that failed after the decision, an unknown child): the
    /// interpreter treats it as a refusal (a start) or an error (a wait).
    Failed {
        /// The request answered.
        id: u64,
    },
}

impl Reply {
    /// The request this answers.
    #[must_use]
    pub const fn id(&self) -> u64 {
        match self {
            Self::Running { id, .. }
            | Self::Denied { id, .. }
            | Self::NotFound { id }
            | Self::NotExecutable { id }
            | Self::Exited { id, .. }
            | Self::Failed { id } => *id,
        }
    }
}

/// `payload` behind its 4-byte big-endian length.
///
/// # Errors
///
/// [`SupervisionError::Malformed`] if `payload` is longer than [`MAX_FRAME`].
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, SupervisionError> {
    if payload.len() > MAX_FRAME {
        return Err(SupervisionError::Malformed);
    }
    let len = u32::try_from(payload.len()).map_err(|_| SupervisionError::Malformed)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// The payload length a frame header declares, checked against [`MAX_FRAME`] before anything is allocated.
///
/// # Errors
///
/// [`SupervisionError::Malformed`] for a length over [`MAX_FRAME`].
pub fn frame_len(header: [u8; 4]) -> Result<usize, SupervisionError> {
    let len = usize::try_from(u32::from_be_bytes(header)).map_err(|_| SupervisionError::Malformed)?;
    if len > MAX_FRAME {
        return Err(SupervisionError::Malformed);
    }
    Ok(len)
}

fn bytes_value(bytes: &[u8]) -> Value {
    Value::from(base64_encode(bytes))
}

fn object_value(object: Object) -> Value {
    Value::Object(object)
}

fn int(value: i64) -> Result<Value, SupervisionError> {
    Value::int(value).map_err(|_| SupervisionError::Malformed)
}

fn id_value(id: u64) -> Result<Value, SupervisionError> {
    int(i64::try_from(id).map_err(|_| SupervisionError::Malformed)?)
}

/// Builds an object from `(key, value)` pairs; keys are this module's constants, never repeated.
fn object(fields: Vec<(&str, Value)>) -> Result<Object, SupervisionError> {
    let mut object = Object::new();
    for (key, value) in fields {
        object.insert(key, value).map_err(|_| SupervisionError::Malformed)?;
    }
    Ok(object)
}

fn to_text(value: &Value) -> Result<Vec<u8>, SupervisionError> {
    knsh_json::write(value)
        .map(String::into_bytes)
        .map_err(|_| SupervisionError::Malformed)
}

impl Request {
    /// The number of descriptors attached to this request's frame.
    #[must_use]
    pub fn descriptor_count(&self) -> usize {
        match self {
            Self::Start { submission, .. } => submission.descriptors.len(),
            Self::Wait { .. } => 0,
        }
    }

    /// The request's payload (without the frame length).
    ///
    /// # Errors
    ///
    /// [`SupervisionError::Malformed`] for a request this protocol cannot carry: an id above 2^53, more than
    /// [`MAX_COMMAND_DESCRIPTORS`] descriptors, numbers out of order or range, more than [`MAX_COMMAND_ARGS`]
    /// arguments or [`MAX_COMMAND_ENV`] environment entries.
    pub fn encode(&self) -> Result<Vec<u8>, SupervisionError> {
        let value = match self {
            Self::Start { id, submission } => {
                check_submission(submission)?;
                let args = submission.args.iter().map(|arg| bytes_value(arg.as_bytes())).collect();
                let env = submission
                    .env
                    .iter()
                    .map(|(name, value)| {
                        Value::Array(vec![bytes_value(name.as_bytes()), bytes_value(value.as_bytes())])
                    })
                    .collect();
                let descriptors = submission
                    .descriptors
                    .iter()
                    .map(|&number| int(i64::from(number)))
                    .collect::<Result<Vec<_>, _>>()?;
                let umask = match submission.umask {
                    Some(mask) => int(i64::from(mask))?,
                    None => Value::Null,
                };
                object_value(object(vec![
                    ("op", Value::from("start")),
                    ("id", id_value(*id)?),
                    ("program", bytes_value(submission.program.as_os_str().as_bytes())),
                    ("argv0", bytes_value(submission.argv0.as_bytes())),
                    ("args", Value::Array(args)),
                    ("env", Value::Array(env)),
                    ("cwd", bytes_value(submission.cwd.as_os_str().as_bytes())),
                    ("umask", umask),
                    ("descriptors", Value::Array(descriptors)),
                ])?)
            }
            Self::Wait { id, child } => object_value(object(vec![
                ("op", Value::from("wait")),
                ("id", id_value(*id)?),
                ("child", id_value(*child)?),
            ])?),
        };
        to_text(&value)
    }

    /// Reads a request's payload. The input is untrusted (the interpreter runs the agent's script): anything but a
    /// complete, well-formed request within the limits is refused, never repaired.
    ///
    /// # Errors
    ///
    /// [`SupervisionError::Malformed`].
    pub fn decode(payload: &[u8]) -> Result<Self, SupervisionError> {
        let value = knsh_json::parse(payload, MAX_FRAME).map_err(|_| SupervisionError::Malformed)?;
        let Value::Object(object) = value else {
            return Err(SupervisionError::Malformed);
        };
        let id = unsigned(field(&object, "id")?)?;
        match text(field(&object, "op")?)? {
            "start" => {
                only_keys(
                    &object,
                    &[
                        "op",
                        "id",
                        "program",
                        "argv0",
                        "args",
                        "env",
                        "cwd",
                        "umask",
                        "descriptors",
                    ],
                )?;
                let args = array(field(&object, "args")?)?
                    .iter()
                    .map(|arg| bytes(arg).map(OsString::from_vec))
                    .collect::<Result<Vec<_>, _>>()?;
                let env = array(field(&object, "env")?)?
                    .iter()
                    .map(|entry| match array(entry)? {
                        [name, value] => Ok((OsString::from_vec(bytes(name)?), OsString::from_vec(bytes(value)?))),
                        _ => Err(SupervisionError::Malformed),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let umask = match field(&object, "umask")? {
                    Value::Null => None,
                    mask => Some(u32::try_from(unsigned(mask)?).map_err(|_| SupervisionError::Malformed)?),
                };
                let descriptors = array(field(&object, "descriptors")?)?
                    .iter()
                    .map(|number| i32::try_from(unsigned(number)?).map_err(|_| SupervisionError::Malformed))
                    .collect::<Result<Vec<_>, _>>()?;
                let submission = Submission {
                    program: PathBuf::from(OsString::from_vec(bytes(field(&object, "program")?)?)),
                    argv0: OsString::from_vec(bytes(field(&object, "argv0")?)?),
                    args,
                    env,
                    cwd: PathBuf::from(OsString::from_vec(bytes(field(&object, "cwd")?)?)),
                    umask,
                    descriptors,
                };
                check_submission(&submission)?;
                Ok(Self::Start { id, submission })
            }
            "wait" => {
                only_keys(&object, &["op", "id", "child"])?;
                let child = unsigned(field(&object, "child")?)?;
                Ok(Self::Wait { id, child })
            }
            _ => Err(SupervisionError::Malformed),
        }
    }
}

impl Reply {
    /// The reply's payload (without the frame length).
    ///
    /// # Errors
    ///
    /// [`SupervisionError::Malformed`] for an id or child number above 2^53.
    pub fn encode(&self) -> Result<Vec<u8>, SupervisionError> {
        let id = ("id", id_value(self.id())?);
        let fields = match self {
            Self::Running { child, pid, .. } => vec![
                id,
                ("result", Value::from("running")),
                ("child", id_value(*child)?),
                ("pid", int(i64::from(*pid))?),
            ],
            Self::Denied { reason, .. } => vec![
                id,
                ("result", Value::from("denied")),
                ("reason", Value::from(reason.as_str())),
            ],
            Self::NotFound { .. } => vec![id, ("result", Value::from("not_found"))],
            Self::NotExecutable { .. } => vec![id, ("result", Value::from("not_executable"))],
            Self::Exited {
                status: ExitStatus::Exited(code),
                ..
            } => vec![id, ("result", Value::from("exited")), ("code", int(i64::from(*code))?)],
            Self::Exited {
                status: ExitStatus::Signalled(signal),
                ..
            } => vec![
                id,
                ("result", Value::from("signalled")),
                ("signal", int(i64::from(*signal))?),
            ],
            Self::Failed { .. } => vec![id, ("result", Value::from("failed"))],
        };
        to_text(&object_value(object(fields)?))
    }

    /// Reads a reply's payload.
    ///
    /// # Errors
    ///
    /// [`SupervisionError::Malformed`] for anything but a complete, well-formed reply.
    pub fn decode(payload: &[u8]) -> Result<Self, SupervisionError> {
        let value = knsh_json::parse(payload, MAX_FRAME).map_err(|_| SupervisionError::Malformed)?;
        let Value::Object(object) = value else {
            return Err(SupervisionError::Malformed);
        };
        let id = unsigned(field(&object, "id")?)?;
        let small = |key: &str| -> Result<i32, SupervisionError> {
            let value = field(&object, key)?.as_i64().ok_or(SupervisionError::Malformed)?;
            i32::try_from(value).map_err(|_| SupervisionError::Malformed)
        };
        match text(field(&object, "result")?)? {
            "running" => Ok(Self::Running {
                id,
                child: unsigned(field(&object, "child")?)?,
                pid: small("pid")?,
            }),
            "denied" => Ok(Self::Denied {
                id,
                reason: text(field(&object, "reason")?)?.to_owned(),
            }),
            "not_found" => Ok(Self::NotFound { id }),
            "not_executable" => Ok(Self::NotExecutable { id }),
            "exited" => Ok(Self::Exited {
                id,
                status: ExitStatus::Exited(small("code")?),
            }),
            "signalled" => Ok(Self::Exited {
                id,
                status: ExitStatus::Signalled(small("signal")?),
            }),
            "failed" => Ok(Self::Failed { id }),
            _ => Err(SupervisionError::Malformed),
        }
    }
}

/// The protocol's limits on one submission (module documentation).
fn check_submission(submission: &Submission) -> Result<(), SupervisionError> {
    let ordered = submission.descriptors.windows(2).all(|pair| pair[0] < pair[1]);
    let in_range = submission
        .descriptors
        .iter()
        .all(|number| (0..=MAX_PLACED_FD).contains(number));
    if submission.descriptors.len() > MAX_COMMAND_DESCRIPTORS
        || !ordered
        || !in_range
        || submission.args.len() > MAX_COMMAND_ARGS
        || submission.env.len() > MAX_COMMAND_ENV
        || !submission.program.is_absolute()
        || !submission.cwd.is_absolute()
    {
        return Err(SupervisionError::Malformed);
    }
    Ok(())
}

fn field<'a>(object: &'a Object, key: &str) -> Result<&'a Value, SupervisionError> {
    object.get(key).ok_or(SupervisionError::Malformed)
}

/// Refuses keys this protocol never sends: the channel is private to one build of `knsh` and `knshd`, so there is no
/// additive evolution to allow for.
fn only_keys(object: &Object, keys: &[&str]) -> Result<(), SupervisionError> {
    if object.iter().all(|(key, _)| keys.contains(&key)) {
        Ok(())
    } else {
        Err(SupervisionError::Malformed)
    }
}

fn text(value: &Value) -> Result<&str, SupervisionError> {
    value.as_str().ok_or(SupervisionError::Malformed)
}

fn bytes(value: &Value) -> Result<Vec<u8>, SupervisionError> {
    base64_decode(text(value)?).map_err(|_| SupervisionError::Malformed)
}

fn array(value: &Value) -> Result<&[Value], SupervisionError> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(SupervisionError::Malformed),
    }
}

fn unsigned(value: &Value) -> Result<u64, SupervisionError> {
    value
        .as_i64()
        .and_then(|number| u64::try_from(number).ok())
        .ok_or(SupervisionError::Malformed)
}

/// What the supervisor answered a [`Request::Start`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartAnswer {
    /// Allowed and started: wait for it with [`SupervisorLink::wait`].
    Running {
        /// Its number on the channel.
        child: u64,
        /// Its process id, for display only.
        pid: i32,
    },
    /// Denied, with the reason to print.
    Denied(String),
    /// The program does not exist (127).
    NotFound,
    /// The program cannot be executed, or the supervisor could not start it (126).
    NotExecutable,
}

/// The interpreter's end of the supervision channel: sends one request and waits for its reply. Called from every
/// thread of the interpreter (pipeline stages, substitutions), concurrently.
pub trait SupervisorLink: Send + Sync {
    /// Sends `submission` with `descriptors` (one per number of its table, in order) and waits for the answer.
    ///
    /// # Errors
    ///
    /// The channel failed: the spawner denies this command and every later one.
    fn start(&self, submission: &Submission, descriptors: &[BorrowedFd<'_>]) -> Result<StartAnswer, SupervisionError>;

    /// Waits for the command the supervisor numbered `child` to end.
    ///
    /// # Errors
    ///
    /// The channel failed, or the supervisor could not wait for it.
    fn wait(&self, child: u64) -> Result<ExitStatus, SupervisionError>;
}

/// Reason printed for a command denied because the supervisor cannot be reached (FR-LC-57).
pub const UNREACHABLE: &str = "the supervisor is unreachable, so the command was denied (fail closed)";
/// Reason printed for a command whose descriptor table is larger than the channel carries.
const TOO_MANY_DESCRIPTORS: &str = "the command holds too many open descriptors to be submitted, so it was denied";
/// Reason printed for a command the channel cannot carry (too many arguments or environment entries).
const NOT_SUBMITTABLE: &str = "the command cannot be submitted to the supervisor, so it was denied";

/// The [`CommandSpawner`] of a native-mode line's interpreter: every command is decided and started by the
/// supervisor over `link` (module documentation).
pub struct SupervisedSpawner {
    link: Arc<dyn SupervisorLink>,
    /// The process's standard output and error, for a denial reported on a standard stream: real `stdout` and
    /// `stderr` in `knsh`, buffers in tests.
    standard: Mutex<(Box<dyn Write + Send>, Box<dyn Write + Send>)>,
    /// Set once the link failed: every later command is denied without asking (FR-LC-57).
    broken: AtomicBool,
    /// The commands started and not yet waited for to their end, by their channel number.
    running: Mutex<HashSet<u64>>,
}

impl std::fmt::Debug for SupervisedSpawner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupervisedSpawner")
            .field("broken", &self.broken.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl SupervisedSpawner {
    /// A spawner asking `link` for every command, reporting denials on a standard stream to `stdout` or `stderr`.
    #[must_use]
    pub fn new(link: Arc<dyn SupervisorLink>, stdout: Box<dyn Write + Send>, stderr: Box<dyn Write + Send>) -> Self {
        Self {
            link,
            standard: Mutex::new((stdout, stderr)),
            broken: AtomicBool::new(false),
            running: Mutex::new(HashSet::new()),
        }
    }

    /// Whether the link failed, so that every command is now denied.
    #[must_use]
    pub fn is_broken(&self) -> bool {
        self.broken.load(Ordering::SeqCst)
    }

    /// Writes `knsh: <name>: <reason>` on descriptor 2 of `request`'s table, as bash writes the error of a command it
    /// cannot execute after the command's redirections. Best effort: a closed or failing stream loses the message,
    /// never the denial.
    fn report(&self, request: &CommandRequest, reason: &str) {
        let mut message = b"knsh: ".to_vec();
        message.extend_from_slice(request.argv0.as_bytes());
        message.extend_from_slice(b": ");
        message.extend_from_slice(reason.as_bytes());
        message.push(b'\n');
        let Some((_, descriptor)) = request.descriptors.iter().find(|(number, _)| *number == 2) else {
            return;
        };
        match descriptor {
            ChildDescriptor::Standard(StandardStream::Input) => {}
            ChildDescriptor::Standard(StandardStream::Output) => {
                let mut standard = self.standard.lock().unwrap_or_else(PoisonError::into_inner);
                let _ = standard.0.write_all(&message);
                let _ = standard.0.flush();
            }
            ChildDescriptor::Standard(StandardStream::Error) => {
                let mut standard = self.standard.lock().unwrap_or_else(PoisonError::into_inner);
                let _ = standard.1.write_all(&message);
                let _ = standard.1.flush();
            }
            ChildDescriptor::Open(fd) => {
                if let Ok(owned) = fd.try_clone_owned() {
                    let _ = std::fs::File::from(owned).write_all(&message);
                }
            }
        }
    }

    /// Denies `request` with `reason`: reported, then refused (status 126, FR-LC-55).
    fn deny(&self, request: &CommandRequest, reason: &str) -> Started {
        self.report(request, reason);
        Started::Refused(CommandOutcome::Denied)
    }
}

/// `request` as a submission: its table's numbers, which [`CommandRequest`] keeps in increasing order.
fn submission(request: &CommandRequest) -> Submission {
    Submission {
        program: request.program.clone(),
        argv0: request.argv0.clone(),
        args: request.args.clone(),
        env: request.env.clone(),
        cwd: request.cwd.clone(),
        umask: request.umask,
        descriptors: request.descriptors.iter().map(|(number, _)| *number).collect(),
    }
}

/// The process's own descriptor for a standard stream.
#[allow(unsafe_code)]
fn standard_fd(stream: StandardStream) -> BorrowedFd<'static> {
    // SAFETY: descriptors 0, 1 and 2 of the interpreter's process stay open for its whole life: `knsh-exec` refuses
    // to start it with any of them closed, and the interpreter's redirections act on its own descriptor table, never
    // on the process's. Borrowing them only lends them to `sendmsg`, which duplicates them for the peer.
    unsafe { BorrowedFd::borrow_raw(stream.number()) }
}

impl CommandSpawner for SupervisedSpawner {
    /// Asks the supervisor (module documentation). `options` are not sent: every command joins the line's process
    /// group.
    fn start(&self, request: &CommandRequest, _options: &ChildOptions) -> Result<Started, PlatformError> {
        if self.is_broken() {
            return Ok(self.deny(request, UNREACHABLE));
        }
        if request.descriptors.len() > MAX_COMMAND_DESCRIPTORS {
            return Ok(self.deny(request, TOO_MANY_DESCRIPTORS));
        }
        let submission = submission(request);
        if check_submission(&submission).is_err() {
            return Ok(self.deny(request, NOT_SUBMITTABLE));
        }
        let descriptors: Vec<BorrowedFd<'_>> = request
            .descriptors
            .iter()
            .map(|(_, descriptor)| match descriptor {
                ChildDescriptor::Standard(stream) => standard_fd(*stream),
                ChildDescriptor::Open(fd) => fd.as_fd(),
            })
            .collect();
        match self.link.start(&submission, &descriptors) {
            Ok(StartAnswer::Running { child, pid }) => {
                self.running
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(child);
                Ok(Started::Running(ChildHandle::new(pid, child, None)))
            }
            Ok(StartAnswer::Denied(reason)) => Ok(self.deny(request, &reason)),
            Ok(StartAnswer::NotFound) => Ok(Started::Refused(CommandOutcome::NotFound)),
            Ok(StartAnswer::NotExecutable) => Ok(Started::Refused(CommandOutcome::NotExecutable)),
            Err(_) => {
                self.broken.store(true, Ordering::SeqCst);
                Ok(self.deny(request, UNREACHABLE))
            }
        }
    }

    fn wait(&self, child: ChildHandle) -> Result<ChildEvent, PlatformError> {
        let number = child.generation();
        if !self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&number)
        {
            return Err(PlatformError::UnknownProcessGroup);
        }
        let status = self.link.wait(number).map_err(|error| {
            if matches!(error, SupervisionError::Closed | SupervisionError::Io(_)) {
                self.broken.store(true, Ordering::SeqCst);
            }
            PlatformError::Os {
                operation: Operation::Wait,
                errno: match error {
                    SupervisionError::Io(errno) => errno,
                    SupervisionError::Closed | SupervisionError::Malformed => libc::EPIPE,
                },
            }
        })?;
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&number);
        Ok(ChildEvent::Exited(status))
    }

    /// No job of a native-mode line has a group of its own (module documentation).
    fn signal_job(&self, _group: ProcessGroupId, _signal: Signal) -> Result<(), PlatformError> {
        Err(PlatformError::UnknownProcessGroup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Submission {
        Submission {
            program: PathBuf::from("/usr/bin/git"),
            argv0: "git".into(),
            args: vec!["push".into(), OsString::from_vec(vec![0xff, b'x'])],
            env: vec![("PATH".into(), "/usr/bin".into()), ("EMPTY".into(), OsString::new())],
            cwd: PathBuf::from("/work"),
            umask: Some(0o022),
            descriptors: vec![0, 1, 2, 7],
        }
    }

    // KNSH-108: a start request crosses unchanged, bytes that are not UTF-8 included; so does every reply.
    #[test]
    fn requests_and_replies_round_trip() {
        let start = Request::Start {
            id: 3,
            submission: sample(),
        };
        assert_eq!(Request::decode(&start.encode().unwrap()), Ok(start.clone()));
        assert_eq!(start.descriptor_count(), 4);
        let wait = Request::Wait { id: 4, child: 9 };
        assert_eq!(Request::decode(&wait.encode().unwrap()), Ok(wait));
        for reply in [
            Reply::Running {
                id: 1,
                child: 2,
                pid: 77,
            },
            Reply::Denied {
                id: 1,
                reason: "exec.deny[0]".into(),
            },
            Reply::NotFound { id: 1 },
            Reply::NotExecutable { id: 1 },
            Reply::Exited {
                id: 1,
                status: ExitStatus::Exited(3),
            },
            Reply::Exited {
                id: 1,
                status: ExitStatus::Signalled(9),
            },
            Reply::Failed { id: 1 },
        ] {
            assert_eq!(Reply::decode(&reply.encode().unwrap()), Ok(reply));
        }
    }

    // Untrusted input: unknown keys, descriptors out of order or range, relative paths and oversized frames are
    // refused, never repaired.
    #[test]
    fn refuses_malformed_requests() {
        let mut bad = sample();
        bad.descriptors = vec![1, 0];
        assert!(
            Request::Start {
                id: 1,
                submission: bad.clone()
            }
            .encode()
            .is_err()
        );
        bad.descriptors = vec![0, 256];
        assert!(Request::Start { id: 1, submission: bad }.encode().is_err());
        let mut relative = sample();
        relative.program = PathBuf::from("git");
        assert!(
            Request::Start {
                id: 1,
                submission: relative
            }
            .encode()
            .is_err()
        );
        for payload in [
            &b"{"[..],
            br#"{"op":"wait","id":1,"child":2,"extra":true}"#,
            br#"{"op":"run","id":1}"#,
            br#"{"op":"wait","id":-1,"child":2}"#,
            br"[]",
        ] {
            assert_eq!(
                Request::decode(payload),
                Err(SupervisionError::Malformed),
                "{payload:?}"
            );
        }
        assert_eq!(frame_len(u32::MAX.to_be_bytes()), Err(SupervisionError::Malformed));
        assert_eq!(frame_len(16u32.to_be_bytes()), Ok(16));
        let frame = encode_frame(b"abc").unwrap();
        assert_eq!(frame, [0, 0, 0, 3, b'a', b'b', b'c']);
    }
}
