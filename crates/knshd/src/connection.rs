//! One client connection: frames in, JSON-RPC dispatch, frames out (KNSH-013).
//!
//! The rules, from `specs/06-api/README.md`, `specs/06-api/wire-format.md` and the KNSH-013 acceptance criteria:
//!
//! - **Handshake first.** Until `hello` succeeds, any other request is answered `-32600` and the connection is closed.
//!   A failed `hello` closes it too. Notifications and responses are never answered, not even then (README.md
//!   "Envelope"); they only close the connection.
//! - **Framing violations close the connection** without an answer: an oversized frame is refused by the frame
//!   reader before anything is allocated for it (NFR-SEC-07, KNSH-004), and after any fatal frame error nothing more
//!   is read.
//! - **Malformed JSON is answered `-32700` and closes the connection.** The peer is sending something the strict
//!   profile forbids, and the engine never tries to recover from malformed input.
//! - Other envelope faults (`-32600`, `-32601`, `-32602`) are answered and the connection stays open.
//! - **`-32009` closes the connection** (KNSH-048). On `agent.sock` it means the caller has no live session: its
//!   `hello` matched no token or envelope, or the session it was bound to has ended. Nothing more can be done on
//!   the connection, so it is answered and closed rather than left open for a caller with no rights.
//! - Notifications and responses from the client are ignored: no client notification exists yet, and `knshd` sends
//!   no requests that a client could answer.
//! - **Byte transport.** A successful `hello` with `binary_frames: false` switches the connection to base64 inside
//!   JSON for raw bytes (KNSH-014); every later handler sees the choice in [`Call::bytes`].
//! - **Binary streams.** A handler that returns raw bytes ([`Answer::bytes`]) names the stream [`Call::stream`] in
//!   its result; the bytes follow the JSON answer in binary chunks, closed by an end-of-stream frame, before the next
//!   message is read. If the result itself cannot be written, the `-32603` that replaces it opens no stream.
//! - **Descriptors** (KNSH-049). Descriptors passed with `SCM_RIGHTS` arrive with the bytes of the frame they were
//!   sent with; the frame reader reads exactly one frame at a time, so whatever the [`Inbox`] holds once a frame is
//!   read came with that frame. They go to that frame's call ([`Call::descriptors`]) and nowhere else: a request
//!   other than `exec.run` that carries any is refused (`-32602`), a message that is not a request has them closed,
//!   and whatever a handler leaves is closed when the call ends.
//! - **Event notifications** (KNSH-018). Once the connection holds a subscription, a second thread, the *pump*,
//!   writes its events as notifications while the first keeps reading requests. Both write through one lock on the
//!   writer, and the reading thread holds it from dispatching a request until its answer is written, so the answer
//!   to `events.subscribe` always precedes that subscription's events, and nothing of a subscription is written
//!   after the answer to `events.unsubscribe`. An event too large for a frame is announced as lost instead
//!   (`events.lost`), never dropped silently. When the connection ends, every subscription ends with it.
//!
//! The loop works on any blocking [`Read`] and [`Write`], so tests drive it over a socket pair. It never logs:
//! [`Closed`] says why the connection ended, without any content.

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;

#[cfg(test)]
use knsh_core::StillWaiting;
use knsh_core::{Caller, Delivery, Lost, SubscriptionId};
use knsh_json::{Frame, FrameReader, FrameWriter, JsonError, StreamId};
use knsh_platform::AuditToken;
use knsh_proto::{
    ByteTransport, ErrorCode, ErrorResponse, HelloParams, Message, OutputData, ProtoError, Rejection, Request,
    RequestId, RpcError, SuccessResponse, decode, event_notification, event_notification_with_bytes, lost_notification,
};

use crate::dispatch::{Answer, Call, Dispatcher, Endpoint, HELLO, Passed, Reply};
use crate::events::Subscriber;
use crate::sessions::SessionBinding;

/// Deliveries the pump writes per turn of the writer lock, so a busy subscription never starves the answers to
/// requests for long.
const PUMP_BATCH: usize = 64;

/// Why a connection ended. Holds no message content, so it can be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Closed {
    /// The client closed the connection between messages (or `knshd` stopped reading it during shutdown).
    Peer,
    /// A framing violation, an oversized frame or a transport error while reading (including a read timeout).
    Frame(JsonError),
    /// The first message was not a successful `hello`.
    Handshake,
    /// A message was not strict-profile JSON; `-32700` was sent.
    Parse,
    /// After `hello`, a call was answered `-32009`: the connection's session ended (KNSH-048).
    Unbound,
    /// Writing an answer or an event notification failed.
    Write(JsonError),
    /// The thread that writes event notifications could not be started; the connection's subscriptions were ended.
    Thread,
}

impl Closed {
    /// A fixed name for the system log.
    pub(crate) const fn kind(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Frame(_) => "frame",
            Self::Handshake => "handshake",
            Self::Parse => "parse",
            Self::Unbound => "unbound",
            Self::Write(_) => "write",
            Self::Thread => "thread",
        }
    }
}

/// Where a connection's passed descriptors collect while its bytes are read (KNSH-049).
pub(crate) trait Inbox {
    /// Every descriptor that arrived since the last call, in arrival order.
    fn take(&self) -> Vec<OwnedFd>;
}

/// A transport that cannot carry descriptors (an in-memory buffer in tests): never any.
#[cfg(test)]
pub(crate) struct NoDescriptors;

#[cfg(test)]
impl Inbox for NoDescriptors {
    fn take(&self) -> Vec<OwnedFd> {
        Vec::new()
    }
}

/// What to do after one message.
#[derive(Debug, PartialEq)]
struct Step {
    /// The answer to send, if any.
    reply: Option<Message>,
    /// Raw bytes to send after the answer, on this stream.
    stream: Option<(StreamId, Vec<u8>)>,
    /// Whether the connection is closed after the answer.
    close: bool,
}

impl Step {
    const fn reply(message: Message) -> Self {
        Self {
            reply: Some(message),
            stream: None,
            close: false,
        }
    }

    const fn reply_and_close(message: Message) -> Self {
        Self {
            reply: Some(message),
            stream: None,
            close: true,
        }
    }

    const NOTHING: Self = Self {
        reply: None,
        stream: None,
        close: false,
    };

    const CLOSE: Self = Self {
        reply: None,
        stream: None,
        close: true,
    };
}

/// The protocol state of one connection.
struct Session<'a> {
    endpoint: Endpoint,
    dispatcher: &'a Dispatcher,
    /// The connection's event subscriptions.
    subscriber: &'a Subscriber,
    /// The human session bound to the connection, if any (KNSH-021).
    binding: &'a SessionBinding,
    /// Whether the client is still connected, for calls that wait on a decision (FR-LC-41).
    caller: &'a dyn Caller,
    /// Whether `hello` has succeeded.
    greeted: bool,
    /// How raw bytes reach this client: binary frames until a `hello` opts out.
    bytes: ByteTransport,
    /// [`bytes`](Self::bytes) as the event pump reads it: a later `hello` may change it while the pump runs. Set
    /// before that `hello` is answered, under the writer lock, so every notification after the answer follows it.
    pump_bytes: &'a AtomicBool,
    /// Whether a call was answered `-32009`: the connection is closed after that answer.
    unbound: bool,
    /// The stream ID the next call may open. Every stream is ended before the next message is read, so IDs never
    /// collide; they still advance so that a client never sees an ID reused back to back.
    next_stream: StreamId,
}

impl Session<'_> {
    /// Handles one JSON frame payload and the descriptors that came with it. Descriptors not handed to a call are
    /// closed when this returns.
    fn handle(&mut self, payload: &[u8], descriptors: &Passed) -> Step {
        match decode(payload) {
            Ok(message) if self.greeted => self.handle_message(message, descriptors),
            Ok(message) => self.handle_first(message, descriptors),
            Err(rejection) => self.handle_rejection(&rejection),
        }
    }

    /// Before `hello`: only a `hello` request is accepted.
    fn handle_first(&mut self, message: Message, descriptors: &Passed) -> Step {
        match message {
            Message::Request(request) if request.method.as_str() == HELLO => {
                // A `hello` with descriptors is refused by the dispatcher (`-32602`), which fails the handshake.
                match self.call(&request, descriptors) {
                    // `hello` returns no raw bytes, so only the result is sent.
                    Ok(answer) => {
                        self.greeted = true;
                        self.settle_bytes(&request);
                        Step::reply(success(request.id, answer.result))
                    }
                    // A failed handshake (for example no common protocol, KNSH-014) ends the connection.
                    Err(error) => Step::reply_and_close(failure(Some(request.id), error)),
                }
            }
            Message::Request(request) => {
                Step::reply_and_close(failure(Some(request.id), RpcError::new(ErrorCode::InvalidRequest)))
            }
            // Never answered, even out of order (README.md "Envelope"), but the handshake rule still closes.
            Message::Notification(_) | Message::Success(_) | Message::Error(_) => Step::CLOSE,
        }
    }

    /// After `hello`: requests are dispatched; client notifications and responses are ignored (and any descriptors
    /// they carried are closed).
    fn handle_message(&mut self, message: Message, descriptors: &Passed) -> Step {
        match message {
            Message::Request(request) => self.dispatch(request, descriptors),
            Message::Notification(_) | Message::Success(_) | Message::Error(_) => Step::NOTHING,
        }
    }

    fn dispatch(&mut self, request: Request, descriptors: &Passed) -> Step {
        match self.call(&request, descriptors) {
            Ok(Answer { result, bytes }) => {
                // A repeated `hello` echoes its own `binary_frames` choice, so the connection must follow it too;
                // otherwise the client would be told one transport and sent the other.
                if request.method.as_str() == HELLO {
                    self.settle_bytes(&request);
                }
                let stream = bytes.map(|bytes| (self.take_stream(), bytes));
                Step {
                    stream,
                    ..Step::reply(success(request.id, result))
                }
            }
            // The caller has no live session any more: nothing else can succeed on this connection.
            Err(error) if error.code == ErrorCode::InvalidSessionToken => {
                self.unbound = true;
                Step::reply_and_close(failure(Some(request.id), error))
            }
            Err(error) => Step::reply(failure(Some(request.id), error)),
        }
    }

    /// Uses up the stream ID the last call was offered, and moves on to the next (skipping 0, which is reserved
    /// for JSON messages).
    fn take_stream(&mut self) -> StreamId {
        let taken = self.next_stream;
        self.next_stream = StreamId::new(taken.get().wrapping_add(1)).unwrap_or(FIRST_STREAM);
        taken
    }

    /// Adopts the byte transport of a `hello` that succeeded. The handler accepted these params, so they parse; the
    /// default (binary frames) only applies to hand-built test handlers that accept anything.
    fn settle_bytes(&mut self, request: &Request) {
        self.bytes = request
            .params::<HelloParams>()
            .map(|params| params.bytes)
            .unwrap_or_default();
        self.pump_bytes.store(self.bytes.uses_binary_frames(), Ordering::SeqCst);
    }

    fn call(&self, request: &Request, descriptors: &Passed) -> Reply {
        self.dispatcher.call(&Call {
            endpoint: self.endpoint,
            bytes: self.bytes,
            stream: self.next_stream,
            request,
            subscriber: self.subscriber,
            binding: self.binding,
            descriptors,
            caller: self.caller,
        })
    }

    /// A message `decode` refused.
    fn handle_rejection(&self, rejection: &Rejection) -> Step {
        if matches!(rejection.error(), ProtoError::Parse(_)) {
            // Strict profile: answered, then no more input is read from this peer.
            return Step::reply_and_close(failure(None, RpcError::new(ErrorCode::ParseError)));
        }
        match rejection.response() {
            Some(response) if self.greeted => Step::reply(Message::Error(response)),
            // Before the handshake every refused request is "not hello": -32600, whatever else is wrong with it.
            Some(response) => Step::reply_and_close(failure(response.id, RpcError::new(ErrorCode::InvalidRequest))),
            // A notification or response: never answered.
            None if self.greeted => Step::NOTHING,
            None => Step::CLOSE,
        }
    }
}

/// The first stream ID of a connection.
const FIRST_STREAM: StreamId = match StreamId::new(1) {
    Some(id) => id,
    None => unreachable!(),
};

fn success(id: RequestId, result: knsh_json::Value) -> Message {
    Message::Success(SuccessResponse { id, result })
}

fn failure(id: Option<RequestId>, error: RpcError) -> Message {
    Message::Error(ErrorResponse { id, error })
}

/// [`serve_with_descriptors`] over a transport that carries no descriptors (an in-memory buffer in tests).
#[cfg(test)]
pub(crate) fn serve<R: Read, W: Write + Send>(
    reader: R,
    writer: W,
    endpoint: Endpoint,
    peer: Option<AuditToken>,
    dispatcher: &Dispatcher,
    on_greeted: &mut dyn FnMut(),
    shutdown: &(dyn Fn() + Sync),
) -> Closed {
    serve_with_descriptors(
        reader,
        &NoDescriptors,
        &StillWaiting,
        writer,
        endpoint,
        peer,
        dispatcher,
        on_greeted,
        shutdown,
    )
}

/// Serves one connection until it ends, and says why it ended.
///
/// `peer` is the peer's audit token (`None` when the kernel could not report it): `hello` on `agent.sock` uses it to
/// match a caller without a session token to its envelope (KNSH-048), and `session.start_agent` on `user.sock` to
/// find the session a nested `knsh agent` runs inside (KNSH-056).
///
/// `on_greeted` runs once, right after `hello` succeeds and before its answer is written; the server uses it to lift
/// the handshake read timeout. `shutdown` closes the underlying connection in both directions: the pump calls it when
/// a notification cannot be written, so that the reading thread, blocked in a read, ends too.
///
/// `inbox` holds the descriptors received with the bytes `reader` returned: those collected while a frame is read go
/// to that frame's call (module documentation, "Descriptors"). `caller` says whether the client is still connected
/// while a call is being handled ([`Call::caller`]).
#[allow(clippy::too_many_arguments)]
pub(crate) fn serve_with_descriptors<R: Read, W: Write + Send>(
    reader: R,
    inbox: &dyn Inbox,
    caller: &dyn Caller,
    writer: W,
    endpoint: Endpoint,
    peer: Option<AuditToken>,
    dispatcher: &Dispatcher,
    on_greeted: &mut dyn FnMut(),
    shutdown: &(dyn Fn() + Sync),
) -> Closed {
    let mut reader = FrameReader::new(reader);
    let writer = Mutex::new(FrameWriter::new(writer));
    let subscriber = Subscriber::new();
    let binding = SessionBinding::for_peer(peer);
    let pump_bytes = AtomicBool::new(true);
    let mut session = Session {
        endpoint,
        dispatcher,
        subscriber: &subscriber,
        binding: &binding,
        caller,
        greeted: false,
        bytes: ByteTransport::BinaryFrames,
        pump_bytes: &pump_bytes,
        unbound: false,
        next_stream: FIRST_STREAM,
    };
    thread::scope(|scope| {
        let mut pump = None;
        let closed = loop {
            let frame = reader.read_frame();
            // Whatever arrived while this frame was read belongs to it; on any other outcome it is closed here.
            let descriptors = Passed::new(inbox.take());
            let payload = match frame {
                Ok(Some(Frame::Json(payload))) => payload,
                Ok(None) => break Closed::Peer,
                // No method opens a binary stream yet, so the reader refuses every chunk as an unknown stream before
                // it gets here. Should one arrive anyway, the stream is not ours to read: close.
                Ok(Some(Frame::Chunk { .. } | Frame::End { .. })) => {
                    break Closed::Frame(JsonError::Frame(knsh_json::FrameReason::UnknownStream));
                }
                Err(error) => break Closed::Frame(error),
            };
            // Held from dispatch until the answer is written: the pump cannot slip a notification in between, so a
            // subscription's events never precede the answer that names it, and none follow its unsubscribe.
            let mut out = lock(&writer);
            let was_greeted = session.greeted;
            let step = session.handle(&payload, &descriptors);
            // Closed before the answer is written: by then the call has taken what it needed.
            drop(descriptors);
            // Free the payload (up to 1 MB) before a handler's answer is written, so a connection holds one at a time.
            drop(payload);
            if session.greeted && !was_greeted {
                on_greeted();
            }
            if let Some(reply) = step.reply
                && let Err(error) = write(&mut out, &reply, step.stream.as_ref())
            {
                break Closed::Write(error);
            }
            drop(out);
            if step.close {
                // Once greeted, only malformed JSON and a lost session close the connection; before that, every close
                // is the handshake rule (including malformed JSON as the first message, and a refused agent hello).
                break if session.unbound {
                    Closed::Unbound
                } else if session.greeted {
                    Closed::Parse
                } else {
                    Closed::Handshake
                };
            }
            // The first subscription starts the pump; connections that never subscribe never get one.
            if pump.is_none() && subscriber.is_subscribed() {
                let (writer, subscriber, bytes) = (&writer, &subscriber, &pump_bytes);
                let spawned = thread::Builder::new()
                    .name("knshd-events".to_owned())
                    .spawn_scoped(scope, move || pump_events(writer, subscriber, bytes, shutdown));
                match spawned {
                    Ok(handle) => pump = Some(handle),
                    // Subscriptions that nothing would ever deliver must not be left looking alive.
                    Err(_) => break Closed::Thread,
                }
            }
        };
        // Every subscription ends with the connection; the pump wakes, sees the close and returns. A human session
        // bound to the connection ends too (`session.ended`, KNSH-021): `knsh` went away, whether it exited or not.
        subscriber.close();
        binding.release();
        let Some(pump) = pump else {
            return closed;
        };
        // The pump may be blocked writing to a peer that stopped reading: closing the connection unblocks it.
        shutdown();
        match (closed, pump.join()) {
            // The pump failed first and closed the connection under the reader: that failure is the reason.
            (Closed::Peer | Closed::Frame(_), Ok(Err(error))) => Closed::Write(error),
            (closed, _) => closed,
        }
    })
}

/// Takes the writer even if the other thread panicked while holding it: the frame writer has no state that a panic
/// between two frames could corrupt, and a half-written frame only makes the peer close.
fn lock<W>(writer: &Mutex<FrameWriter<W>>) -> MutexGuard<'_, FrameWriter<W>> {
    writer.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The pump: waits for its connection's subscriptions to have something, then writes one batch of notifications
/// under the writer lock, until the connection closes. On a write error it closes the connection and returns it.
///
/// Events that carry raw bytes (`command.output`, KNSH-053) are followed by their bytes as one binary stream, or
/// carry them as base64 when the client opted out of binary frames (`binary`, which the latest `hello` set). Every
/// stream is opened, sent and ended under one hold of the writer lock, so no two streams are ever open at once and
/// the pump may reuse [`FIRST_STREAM`] for each.
fn pump_events<W: Write>(
    writer: &Mutex<FrameWriter<W>>,
    subscriber: &Subscriber,
    binary: &AtomicBool,
    shutdown: &(dyn Fn() + Sync),
) -> Result<(), JsonError> {
    while subscriber.signal().wait() {
        let mut out = lock(writer);
        // Read under the writer lock: a `hello` answered before this batch has already set it.
        let bytes = if binary.load(Ordering::SeqCst) {
            ByteTransport::BinaryFrames
        } else {
            ByteTransport::Base64
        };
        // Taken under the writer lock, so an unsubscribe answered before this cannot have its events written after.
        let batch = subscriber.take(PUMP_BATCH);
        let written = batch
            .iter()
            .try_for_each(|(id, delivery)| write_delivery(&mut out, *id, delivery, bytes))
            .and_then(|()| out.flush());
        if let Err(error) = written {
            drop(out);
            shutdown();
            return Err(error);
        }
    }
    Ok(())
}

/// Writes one delivery as a notification. An event that cannot be sent as one frame (too large) is announced as a
/// lost range of exactly that event instead, so the subscriber knows to read it from the record store (FR-EVT-04).
fn write_delivery<W: Write>(
    writer: &mut FrameWriter<W>,
    subscription: SubscriptionId,
    delivery: &Delivery,
    bytes: ByteTransport,
) -> Result<(), JsonError> {
    let lost = match delivery {
        Delivery::Event(event) => {
            // The raw bytes to send after the notification, when they go in a binary stream.
            let (notification, stream) = match (event.data.bytes(), bytes) {
                (None, _) => (event_notification(subscription, event), None),
                (Some(raw), ByteTransport::BinaryFrames) => (
                    event_notification_with_bytes(subscription, event, OutputData::Stream(FIRST_STREAM)),
                    Some(raw.expose().as_slice()),
                ),
                (Some(raw), ByteTransport::Base64) => (
                    event_notification_with_bytes(subscription, event, OutputData::Base64(raw.expose())),
                    None,
                ),
            };
            if let Some(value) = notification_value(notification) {
                match writer.write_json(&value) {
                    // Nothing was written; the writer is still usable for the replacement.
                    Err(JsonError::TooDeep | JsonError::FrameTooLarge { .. }) => {}
                    Ok(()) => {
                        // The notification declared exactly these bytes on the stream; the end frame closes it.
                        if let Some(raw) = stream {
                            writer.write_chunk(FIRST_STREAM, raw)?;
                            writer.write_end(FIRST_STREAM)?;
                        }
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
            Lost {
                session_id: event.session_id,
                from_seq: event.seq,
                to_seq: event.seq,
            }
        }
        Delivery::Lost(lost) => *lost,
    };
    let value = notification_value(lost_notification(subscription, &lost)).ok_or(JsonError::TooDeep)?;
    writer.write_json(&value)
}

/// A built notification as a JSON value, or `None` if it could not be built.
fn notification_value(notification: Result<knsh_proto::Notification, ProtoError>) -> Option<knsh_json::Value> {
    notification
        .and_then(|notification| Message::Notification(notification).to_value())
        .ok()
}

/// Writes one message, then `stream`'s bytes if the message went out as it was, and flushes. A result that cannot
/// be written as strict JSON (too deep, too large) is replaced by `-32603` for the same request, so the client is
/// never left waiting; the stream it announced is then not sent, since the client never learned of it.
fn write<W: Write>(
    writer: &mut FrameWriter<W>,
    message: &Message,
    stream: Option<&(StreamId, Vec<u8>)>,
) -> Result<(), JsonError> {
    let written = match message.to_value() {
        Ok(value) => writer.write_json(&value),
        // The result cannot even be built as a JSON value: treat it like one too deep to write.
        Err(_) => Err(JsonError::TooDeep),
    };
    match written {
        Ok(()) => {
            if let Some((id, bytes)) = stream {
                // The result declared exactly `bytes.len()` bytes on `id`; the end frame closes the stream.
                writer.write_chunk(*id, bytes)?;
                writer.write_end(*id)?;
            }
        }
        // Nothing was written; the writer is still usable for the fallback.
        Err(JsonError::TooDeep | JsonError::FrameTooLarge { .. }) => {
            let fallback = internal_error(message).to_value().map_err(|_| JsonError::TooDeep)?;
            writer.write_json(&fallback)?;
        }
        Err(error) => return Err(error),
    }
    writer.flush()
}

/// The `-32603` answer that replaces `message` when it cannot be sent.
fn internal_error(message: &Message) -> Message {
    let id = match message {
        Message::Success(success) => Some(success.id.clone()),
        Message::Error(error) => error.id.clone(),
        Message::Request(_) | Message::Notification(_) => None,
    };
    failure(id, RpcError::new(ErrorCode::InternalError))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use knsh_json::{FrameWriter, Value};

    use super::*;
    use crate::dispatch::tests::ok_handler;
    use crate::dispatch::{Endpoint, Table};

    fn dispatcher() -> Dispatcher {
        Dispatcher::from_tables(
            Table::new()
                .with(HELLO, ok_handler())
                .with("records.query", ok_handler()),
            Table::new().with(HELLO, ok_handler()).with("exec.run", ok_handler()),
        )
    }

    /// Frames each JSON text as one frame.
    fn frames(texts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for text in texts {
            out.extend_from_slice(&u32::try_from(text.len() + 5).unwrap().to_be_bytes());
            out.push(0x01);
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(text);
        }
        out
    }

    /// Runs a `user.sock` connection over `input` with the test tables and returns why it closed and every answer.
    fn run(input: &[u8]) -> (Closed, Vec<Message>) {
        run_with(&dispatcher(), input)
    }

    /// Runs a `user.sock` connection over `input` with `dispatcher` and returns why it closed and every answer,
    /// decoded.
    fn run_with(dispatcher: &Dispatcher, input: &[u8]) -> (Closed, Vec<Message>) {
        let mut output = Vec::new();
        let closed = serve(
            Cursor::new(input),
            &mut output,
            Endpoint::User,
            None,
            dispatcher,
            &mut || {},
            &|| {},
        );
        let mut reader = FrameReader::new(output.as_slice());
        let mut answers = Vec::new();
        while let Some(Frame::Json(payload)) = reader.read_frame().unwrap() {
            answers.push(decode(&payload).unwrap());
        }
        (closed, answers)
    }

    fn error_code(message: &Message) -> (Option<RequestId>, ErrorCode) {
        match message {
            Message::Error(response) => (response.id.clone(), response.error.code),
            other => panic!("not an error response: {other:?}"),
        }
    }

    const HELLO_REQ: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"hello"}"#;

    // KNSH-013: handshake order. A request other than hello first gets -32600 and the connection closes; nothing
    // after it is served.
    #[test]
    fn first_message_must_be_hello() {
        let (closed, answers) = run(&frames(&[
            br#"{"jsonrpc":"2.0","id":7,"method":"records.query"}"#,
            HELLO_REQ,
        ]));
        assert_eq!(closed, Closed::Handshake);
        assert_eq!(answers.len(), 1);
        assert_eq!(
            error_code(&answers[0]),
            (Some(RequestId::from(7u32)), ErrorCode::InvalidRequest)
        );
    }

    // Before the handshake every refused request is -32600, even one that would otherwise be -32601.
    #[test]
    fn invalid_first_message_gets_minus_32600() {
        for text in [
            br#"{"jsonrpc":"2.0","id":2,"method":"BAD"}"#.as_slice(),
            br#"{"jsonrpc":"1.0","id":2,"method":"hello"}"#,
            br"[]",
        ] {
            let (closed, answers) = run(&frames(&[text]));
            assert_eq!(closed, Closed::Handshake);
            assert_eq!(answers.len(), 1);
            assert_eq!(error_code(&answers[0]).1, ErrorCode::InvalidRequest);
        }
    }

    // A notification first is never answered (JSON-RPC), but the connection still closes.
    #[test]
    fn notification_first_closes_without_answer() {
        let (closed, answers) = run(&frames(&[br#"{"jsonrpc":"2.0","method":"hello"}"#, HELLO_REQ]));
        assert_eq!(closed, Closed::Handshake);
        assert_eq!(answers, Vec::<Message>::new());
    }

    #[test]
    fn failed_hello_closes_the_connection() {
        let dispatcher = Dispatcher::from_tables(Table::new(), Table::new());
        let mut output = Vec::new();
        let closed = serve(
            Cursor::new(frames(&[HELLO_REQ, HELLO_REQ])),
            &mut output,
            Endpoint::User,
            None,
            &dispatcher,
            &mut || {},
            &|| {},
        );
        assert_eq!(closed, Closed::Handshake);
    }

    // After hello, methods are dispatched per endpoint: unknown is -32601, another endpoint's is -32003, and the
    // connection stays open for both.
    #[test]
    fn dispatches_after_hello() {
        let (closed, answers) = run(&frames(&[
            HELLO_REQ,
            br#"{"jsonrpc":"2.0","id":2,"method":"records.query"}"#,
            br#"{"jsonrpc":"2.0","id":3,"method":"exec.run"}"#,
            br#"{"jsonrpc":"2.0","id":4,"method":"no.such"}"#,
            br#"{"jsonrpc":"2.0","method":"records.query"}"#,
            br#"{"jsonrpc":"2.0","id":5,"method":"records.query","params":[1]}"#,
        ]));
        assert_eq!(closed, Closed::Peer);
        assert_eq!(answers.len(), 5, "the notification is not answered");
        assert!(matches!(&answers[0], Message::Success(s) if s.id == RequestId::from(1u32)));
        assert!(matches!(&answers[1], Message::Success(s) if s.result == Value::from(true)));
        assert_eq!(error_code(&answers[2]).1, ErrorCode::NotAllowed);
        assert_eq!(error_code(&answers[3]).1, ErrorCode::MethodNotFound);
        assert_eq!(error_code(&answers[4]).1, ErrorCode::InvalidParams);
    }

    // KNSH-013: strict profile. Malformed JSON is answered -32700 (id null) and nothing after it is read.
    #[test]
    fn malformed_json_closes_connection_with_minus_32700() {
        for bad in [
            br#"{"jsonrpc":"2.0","id":2,"method":"#.as_slice(),
            br#"{"a":1,"a":2}"#,
            b"\xff",
        ] {
            let (closed, answers) = run(&frames(&[HELLO_REQ, bad, HELLO_REQ]));
            assert_eq!(closed, Closed::Parse);
            assert_eq!(answers.len(), 2, "nothing after the bad message is served");
            assert_eq!(error_code(&answers[1]), (None, ErrorCode::ParseError));
        }
        // Before the handshake too.
        let (closed, answers) = run(&frames(&[b"{"]));
        assert_eq!(closed, Closed::Handshake);
        assert_eq!(error_code(&answers[0]), (None, ErrorCode::ParseError));
    }

    // KNSH-013, NFR-SEC-07: an oversized frame closes the connection, unanswered, before its payload is read.
    #[test]
    fn oversized_frame_closes_connection_unanswered() {
        let mut input = frames(&[HELLO_REQ]);
        input.extend_from_slice(&u32::MAX.to_be_bytes());
        let (closed, answers) = run(&input);
        assert!(
            matches!(closed, Closed::Frame(JsonError::FrameTooLarge { .. })),
            "{closed:?}"
        );
        assert_eq!(answers.len(), 1, "only hello is answered");
    }

    // A binary chunk on a stream nobody opened is a framing violation.
    #[test]
    fn unopened_stream_closes_connection() {
        let mut wire = FrameWriter::new(frames(&[HELLO_REQ]));
        wire.write_chunk(knsh_json::StreamId::new(1).unwrap(), b"x").unwrap();
        let (closed, answers) = run(&wire.into_inner());
        assert!(matches!(closed, Closed::Frame(_)), "{closed:?}");
        assert_eq!(answers.len(), 1);
    }

    /// Runs a connection against the phase-1 dispatcher of a working test machine.
    fn run_phase1(input: &[u8]) -> (Closed, Vec<Message>) {
        let dispatcher = crate::hello::phase1_dispatcher(
            crate::probe::probe(&crate::probe::tests::Machine::working().probes()),
            crate::hello::tests::handlers(),
        )
        .unwrap();
        run_with(&dispatcher, input)
    }

    // KNSH-014: no protocol in common fails `hello` and closes the connection; nothing after it is served.
    #[test]
    fn unsupported_protocol_list_is_refused() {
        let (closed, answers) = run_phase1(
            &frames(&[
                br#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{"client":"c","client_version":"1","protocols":[2]}}"#,
                br#"{"jsonrpc":"2.0","id":2,"method":"hello","params":{"client":"c","client_version":"1","protocols":[1]}}"#,
            ]),
        );
        assert_eq!(closed, Closed::Handshake);
        assert_eq!(answers.len(), 1);
        assert_eq!(
            error_code(&answers[0]),
            (Some(RequestId::from(1u32)), ErrorCode::CapabilityUnavailable)
        );
    }

    // KNSH-014: after `hello` with `binary_frames: false`, handlers see the base64 transport and inline raw bytes as
    // base64 JSON strings; without the opt-out they keep binary frames.
    #[test]
    fn binary_opt_out_switches_to_base64() {
        let bytes_handler: crate::dispatch::Handler =
            std::sync::Arc::new(|call: &Call<'_>| Ok(call.bytes.inline(b"knsh").unwrap_or(Value::Null).into()));
        let dispatcher = Dispatcher::from_tables(
            Table::new()
                .with(HELLO, ok_handler())
                .with("records.output", bytes_handler),
            Table::new(),
        );
        // The result of `records.output` after `hello`.
        let output_of = |hello: &[u8]| {
            let (_, answers) = run_with(
                &dispatcher,
                &frames(&[hello, br#"{"jsonrpc":"2.0","id":2,"method":"records.output"}"#]),
            );
            match answers.last() {
                Some(Message::Success(success)) => success.result.clone(),
                other => panic!("records.output was not answered with a result: {other:?}"),
            }
        };
        let opted_out = output_of(
            br#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{"client":"c","client_version":"1","protocols":[1],"binary_frames":false}}"#,
        );
        assert_eq!(opted_out, Value::from("a25zaA=="));
        let default = output_of(
            br#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{"client":"c","client_version":"1","protocols":[1]}}"#,
        );
        assert_eq!(default, Value::Null, "bytes go in binary frames by default");

        // A repeated `hello` that opts out switches the transport it reports, so the two never disagree.
        let (_, answers) = run_with(
            &dispatcher,
            &frames(&[
                br#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{"client":"c","client_version":"1","protocols":[1]}}"#,
                br#"{"jsonrpc":"2.0","id":2,"method":"hello","params":{"client":"c","client_version":"1","protocols":[1],"binary_frames":false}}"#,
                br#"{"jsonrpc":"2.0","id":3,"method":"records.output"}"#,
            ]),
        );
        match answers.last() {
            Some(Message::Success(success)) => assert_eq!(success.result, Value::from("a25zaA==")),
            other => panic!("records.output was not answered with a result: {other:?}"),
        }
    }

    #[test]
    fn on_greeted_runs_once_after_hello() {
        let mut calls = 0;
        let mut output = Vec::new();
        serve(
            Cursor::new(frames(&[HELLO_REQ, HELLO_REQ])),
            &mut output,
            Endpoint::User,
            None,
            &dispatcher(),
            &mut || calls += 1,
            &|| {},
        );
        assert_eq!(calls, 1);
    }

    // A result the strict writer refuses is replaced by -32603 for the same id: the client is never left waiting.
    #[test]
    fn unwritable_result_becomes_internal_error() {
        let mut deep = Value::from(true);
        for _ in 0..40 {
            deep = Value::from(vec![deep]);
        }
        let deep = std::sync::Arc::new(deep);
        let dispatcher = Dispatcher::from_tables(
            Table::new().with(
                HELLO,
                std::sync::Arc::new(move |_: &Call<'_>| Ok((*deep).clone().into())),
            ),
            Table::new(),
        );
        let mut output = Vec::new();
        serve(
            Cursor::new(frames(&[HELLO_REQ])),
            &mut output,
            Endpoint::User,
            None,
            &dispatcher,
            &mut || {},
            &|| {},
        );
        let mut reader = FrameReader::new(output.as_slice());
        let Some(Frame::Json(payload)) = reader.read_frame().unwrap() else {
            panic!("no answer")
        };
        assert_eq!(
            error_code(&decode(&payload).unwrap()),
            (Some(RequestId::from(1u32)), ErrorCode::InternalError)
        );
    }

    /// A `user.sock` connection served on its own thread over a socket pair, with `hello` and the event methods of
    /// `hub`. Returns the client end and the server thread, which answers why the connection closed.
    fn served(
        hub: &std::sync::Arc<crate::events::EventHub>,
    ) -> (std::os::unix::net::UnixStream, std::thread::JoinHandle<Closed>) {
        let mut user = Table::new().with(HELLO, ok_handler());
        for (name, handler) in hub.handlers() {
            user = user.with(name, handler);
        }
        let dispatcher = Dispatcher::from_tables(user, Table::new());
        let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let thread = std::thread::spawn(move || {
            let stream = &server;
            serve(stream, stream, Endpoint::User, None, &dispatcher, &mut || {}, &|| {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            })
        });
        (client, thread)
    }

    fn send(client: &std::os::unix::net::UnixStream, text: &str) {
        let mut client = client;
        client.write_all(&frames(&[text.as_bytes()])).unwrap();
    }

    fn next(reader: &mut FrameReader<&std::os::unix::net::UnixStream>) -> Message {
        match reader.read_frame().unwrap() {
            Some(Frame::Json(payload)) => decode(&payload).unwrap(),
            other => panic!("expected a JSON message, got {other:?}"),
        }
    }

    /// The `(method, seq)` of an event notification.
    fn notified(message: &Message) -> (String, u64) {
        let Message::Notification(notification) = message else {
            panic!("expected a notification, got {message:?}")
        };
        let params = notification.params.as_ref().unwrap();
        let seq = params
            .get("seq")
            .or_else(|| params.get("from_seq"))
            .and_then(Value::as_i64)
            .unwrap();
        (notification.method.as_str().to_owned(), u64::try_from(seq).unwrap())
    }

    fn result(message: &Message) -> Value {
        match message {
            Message::Success(success) => success.result.clone(),
            other => panic!("expected a result, got {other:?}"),
        }
    }

    // KNSH-018: the answer names the subscription first, then the events follow as notifications in seq order: the
    // replay after since_seq, then live events, with no duplicate and no gap even while events are being published.
    #[test]
    fn subscribe_streams_events_in_seq_order() {
        use crate::events::tests::{agent, hub, sid, start};
        use knsh_core::EventData;

        let hub = hub();
        start(&hub, 1);
        for _ in 0..9 {
            hub.publish(sid(1), &agent(), EventData::SessionIdle).unwrap();
        }
        let (client, server) = served(&hub);
        let mut reader = FrameReader::new(&client);
        send(&client, std::str::from_utf8(HELLO_REQ).unwrap());
        assert!(matches!(next(&mut reader), Message::Success(_)));

        // Publish concurrently with the subscribe: whatever interleaving happens, the stream must be gapless.
        let publisher = {
            let hub = std::sync::Arc::clone(&hub);
            std::thread::spawn(move || {
                for _ in 0..200 {
                    hub.publish(sid(1), &agent(), EventData::SessionIdle).unwrap();
                }
            })
        };
        send(
            &client,
            &format!(
                r#"{{"jsonrpc":"2.0","id":2,"method":"events.subscribe","params":{{"session_id":"{}","since_seq":4}}}}"#,
                sid(1)
            ),
        );
        let answer = result(&next(&mut reader));
        assert_eq!(
            answer.as_object().unwrap().get("subscription_id"),
            Some(&Value::from(1u32))
        );
        assert_eq!(answer.as_object().unwrap().get("gap"), Some(&Value::from(false)));
        publisher.join().unwrap();
        let seqs: Vec<u64> = (5..=210).map(|_| notified(&next(&mut reader)).1).collect();
        assert_eq!(seqs, (5..=210).collect::<Vec<_>>());

        drop(reader);
        drop(client);
        assert_eq!(server.join().unwrap(), Closed::Peer);
    }

    // KNSH-018: after the unsubscribe answer nothing more of that subscription is sent.
    #[test]
    fn unsubscribe_stops_delivery() {
        use crate::events::tests::{agent, hub, sid, start};
        use knsh_core::EventData;

        let hub = hub();
        start(&hub, 1);
        let (client, server) = served(&hub);
        let mut reader = FrameReader::new(&client);
        send(&client, std::str::from_utf8(HELLO_REQ).unwrap());
        next(&mut reader);
        send(&client, r#"{"jsonrpc":"2.0","id":2,"method":"events.subscribe"}"#);
        result(&next(&mut reader));
        hub.publish(sid(1), &agent(), EventData::SessionIdle).unwrap();
        assert_eq!(notified(&next(&mut reader)), ("session.idle".to_owned(), 2));

        send(
            &client,
            r#"{"jsonrpc":"2.0","id":3,"method":"events.unsubscribe","params":{"subscription_id":1}}"#,
        );
        assert!(matches!(next(&mut reader), Message::Success(s) if s.id == RequestId::from(3u32)));
        hub.publish(sid(1), &agent(), EventData::SessionIdle).unwrap();
        // The next message is the answer to this request, not an event.
        send(&client, r#"{"jsonrpc":"2.0","id":4,"method":"hello"}"#);
        assert!(matches!(next(&mut reader), Message::Success(s) if s.id == RequestId::from(4u32)));
        assert_eq!(hub.subscription_count(), 0);

        drop(reader);
        drop(client);
        assert_eq!(server.join().unwrap(), Closed::Peer);
    }

    // KNSH-018 resource cleanup: closing the connection ends every subscription it made, and the pump thread with it.
    #[test]
    fn disconnect_ends_subscriptions() {
        use crate::events::tests::{hub, start};

        let hub = hub();
        start(&hub, 1);
        let (client, server) = served(&hub);
        let mut reader = FrameReader::new(&client);
        send(&client, std::str::from_utf8(HELLO_REQ).unwrap());
        next(&mut reader);
        for id in 2..5 {
            send(
                &client,
                &format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"events.subscribe"}}"#),
            );
            result(&next(&mut reader));
        }
        assert_eq!(hub.subscription_count(), 3);
        drop(reader);
        drop(client);
        assert_eq!(
            server.join().unwrap(),
            Closed::Peer,
            "the server thread, pump included, finished"
        );
        assert_eq!(hub.subscription_count(), 0);
    }

    /// Writes to a socket until `fail` is set, then fails every write, like a peer whose socket broke.
    struct BreakableWriter<'a> {
        stream: &'a std::os::unix::net::UnixStream,
        fail: &'a std::sync::atomic::AtomicBool,
    }

    impl Write for BreakableWriter<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            let mut stream = self.stream;
            stream.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // KNSH-018 resource cleanup: when a notification cannot be written, the pump closes the connection, the reading
    // thread (blocked in a read) ends too, the connection reports the write failure and its subscriptions end.
    #[test]
    fn pump_write_failure_closes_the_connection() {
        use crate::events::tests::{agent, hub, sid, start};
        use knsh_core::EventData;

        let hub = hub();
        start(&hub, 1);
        let mut user = Table::new().with(HELLO, ok_handler());
        for (name, handler) in hub.handlers() {
            user = user.with(name, handler);
        }
        let dispatcher = Dispatcher::from_tables(user, Table::new());
        let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let fail = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = {
            let fail = std::sync::Arc::clone(&fail);
            std::thread::spawn(move || {
                let stream = &server;
                let writer = BreakableWriter { stream, fail: &fail };
                serve(stream, writer, Endpoint::User, None, &dispatcher, &mut || {}, &|| {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                })
            })
        };
        let mut reader = FrameReader::new(&client);
        send(&client, std::str::from_utf8(HELLO_REQ).unwrap());
        next(&mut reader);
        send(&client, r#"{"jsonrpc":"2.0","id":2,"method":"events.subscribe"}"#);
        result(&next(&mut reader));
        assert_eq!(hub.subscription_count(), 1);

        // The client keeps its end open and sends nothing: only the pump's failure can end the connection.
        fail.store(true, std::sync::atomic::Ordering::SeqCst);
        hub.publish(sid(1), &agent(), EventData::SessionIdle).unwrap();
        assert!(matches!(thread.join().unwrap(), Closed::Write(_)));
        assert_eq!(hub.subscription_count(), 0);
        drop(reader);
        drop(client);
    }

    // FR-EVT-04: an event too large for one frame is announced as lost, never dropped silently, and later events
    // still arrive.
    #[test]
    fn oversized_event_is_reported_lost() {
        use crate::events::tests::{agent, hub, sid, start};
        use knsh_core::{CanonicalPath, EventData, RecordId, Redacted, Timestamp, Ulid};

        let hub = hub();
        start(&hub, 1);
        let (client, server) = served(&hub);
        let mut reader = FrameReader::new(&client);
        send(&client, std::str::from_utf8(HELLO_REQ).unwrap());
        next(&mut reader);
        send(&client, r#"{"jsonrpc":"2.0","id":2,"method":"events.subscribe"}"#);
        result(&next(&mut reader));
        let at = Timestamp::from_unix_micros(0).unwrap();
        hub.publish(
            sid(1),
            &agent(),
            EventData::CommandFinished {
                record_id: RecordId::from_ulid(Ulid::from_u128(1)),
                command: Redacted::new("x".repeat(knsh_json::MAX_PAYLOAD)),
                cwd: CanonicalPath::new("/tmp").unwrap(),
                started_at: at,
                ended_at: at,
                exit_code: Some(0),
            },
        )
        .unwrap();
        hub.publish(sid(1), &agent(), EventData::SessionIdle).unwrap();
        assert_eq!(notified(&next(&mut reader)), ("events.lost".to_owned(), 2));
        assert_eq!(notified(&next(&mut reader)), ("session.idle".to_owned(), 3));

        drop(reader);
        drop(client);
        assert_eq!(server.join().unwrap(), Closed::Peer);
    }

    // FR-LC-18, KNSH-053: a `command.output` chunk follows its notification as one binary stream (exactly the declared
    // bytes, then the end frame); a client that opted out of binary frames gets it as base64 inside the notification.
    #[test]
    fn command_output_is_sent_as_a_binary_stream() {
        use crate::events::tests::{agent, hub, sid, start};
        use knsh_core::{EventData, OutputStream, RecordId, Redacted, Ulid};

        let chunk = || EventData::CommandOutput {
            record_id: RecordId::from_ulid(Ulid::from_u128(1)),
            stream: OutputStream::Stdout,
            offset: 0,
            bytes: Redacted::new(b"\x00raw \xff bytes\n".to_vec()),
        };
        for (hello, binary) in [
            (std::str::from_utf8(HELLO_REQ).unwrap(), true),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{"client":"c","client_version":"1","protocols":[1],"binary_frames":false}}"#,
                false,
            ),
        ] {
            let hub = hub();
            start(&hub, 1);
            let (client, server) = served(&hub);
            let mut reader = FrameReader::new(&client);
            send(&client, hello);
            next(&mut reader);
            send(&client, r#"{"jsonrpc":"2.0","id":2,"method":"events.subscribe"}"#);
            result(&next(&mut reader));
            hub.publish(sid(1), &agent(), chunk()).unwrap();
            hub.publish(sid(1), &agent(), EventData::SessionIdle).unwrap();

            let notification = next(&mut reader);
            assert_eq!(notified(&notification), ("command.output".to_owned(), 2));
            let Message::Notification(notification) = notification else {
                unreachable!()
            };
            let data = notification
                .params
                .as_ref()
                .and_then(|params| params.get("data"))
                .and_then(Value::as_object)
                .unwrap();
            assert_eq!(data.get("size").and_then(Value::as_str), Some("13"));
            if binary {
                let stream = data.get("data").and_then(Value::as_object).unwrap();
                let id = u32::try_from(stream.get("stream_id").and_then(Value::as_i64).unwrap()).unwrap();
                // A client opens the stream the notification announced, with its declared size.
                reader.open_stream(StreamId::new(id).unwrap(), Some(13)).unwrap();
                match reader.read_frame().unwrap() {
                    Some(Frame::Chunk { stream, data }) => {
                        assert_eq!(stream.get(), id);
                        assert_eq!(data, b"\x00raw \xff bytes\n");
                    }
                    other => panic!("expected the chunk, got {other:?}"),
                }
                assert!(matches!(reader.read_frame().unwrap(), Some(Frame::End { .. })));
            } else {
                assert_eq!(
                    data.get("data_base64").and_then(Value::as_str),
                    Some(knsh_json::base64_encode(b"\x00raw \xff bytes\n").as_str())
                );
            }
            // The stream ended: later events follow normally.
            assert_eq!(notified(&next(&mut reader)), ("session.idle".to_owned(), 3));
            drop(reader);
            drop(client);
            assert_eq!(server.join().unwrap(), Closed::Peer);
        }
    }
}
