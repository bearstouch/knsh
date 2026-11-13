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
//! - Notifications and responses from the client are ignored: no client notification exists yet, and `knshd` sends
//!   no requests that a client could answer.
//!
//! The loop works on any blocking [`Read`] and [`Write`], so tests drive it over a socket pair. It never logs:
//! [`Closed`] says why the connection ended, without any content.

use std::io::{Read, Write};

use knsh_json::{Frame, FrameReader, FrameWriter, JsonError};
use knsh_proto::{
    ErrorCode, ErrorResponse, Message, ProtoError, Rejection, Request, RequestId, RpcError, SuccessResponse, decode,
};

use crate::dispatch::{Dispatcher, Endpoint, HELLO};

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
    /// Writing an answer failed.
    Write(JsonError),
}

impl Closed {
    /// A fixed name for the system log.
    pub(crate) const fn kind(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Frame(_) => "frame",
            Self::Handshake => "handshake",
            Self::Parse => "parse",
            Self::Write(_) => "write",
        }
    }
}

/// What to do after one message.
#[derive(Debug, PartialEq)]
struct Step {
    /// The answer to send, if any.
    reply: Option<Message>,
    /// Whether the connection is closed after the answer.
    close: bool,
}

impl Step {
    const fn reply(message: Message) -> Self {
        Self {
            reply: Some(message),
            close: false,
        }
    }

    const fn reply_and_close(message: Message) -> Self {
        Self {
            reply: Some(message),
            close: true,
        }
    }

    const NOTHING: Self = Self {
        reply: None,
        close: false,
    };

    const CLOSE: Self = Self {
        reply: None,
        close: true,
    };
}

/// The protocol state of one connection.
struct Session<'a> {
    endpoint: Endpoint,
    dispatcher: &'a Dispatcher,
    /// Whether `hello` has succeeded.
    greeted: bool,
}

impl Session<'_> {
    /// Handles one JSON frame payload.
    fn handle(&mut self, payload: &[u8]) -> Step {
        match decode(payload) {
            Ok(message) if self.greeted => self.handle_message(message),
            Ok(message) => self.handle_first(message),
            Err(rejection) => self.handle_rejection(&rejection),
        }
    }

    /// Before `hello`: only a `hello` request is accepted.
    fn handle_first(&mut self, message: Message) -> Step {
        match message {
            Message::Request(request) if request.method.as_str() == HELLO => {
                match self.dispatcher.call(self.endpoint, &request) {
                    Ok(result) => {
                        self.greeted = true;
                        Step::reply(success(request.id, result))
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

    /// After `hello`: requests are dispatched; client notifications and responses are ignored.
    fn handle_message(&self, message: Message) -> Step {
        match message {
            Message::Request(request) => Step::reply(self.dispatch(request)),
            Message::Notification(_) | Message::Success(_) | Message::Error(_) => Step::NOTHING,
        }
    }

    fn dispatch(&self, request: Request) -> Message {
        match self.dispatcher.call(self.endpoint, &request) {
            Ok(result) => success(request.id, result),
            Err(error) => failure(Some(request.id), error),
        }
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

fn success(id: RequestId, result: knsh_json::Value) -> Message {
    Message::Success(SuccessResponse { id, result })
}

fn failure(id: Option<RequestId>, error: RpcError) -> Message {
    Message::Error(ErrorResponse { id, error })
}

/// Serves one connection until it ends, and says why it ended.
///
/// `on_greeted` runs once, right after `hello` succeeds and before its answer is written; the server uses it to lift
/// the handshake read timeout.
pub(crate) fn serve<R: Read, W: Write>(
    reader: R,
    writer: W,
    endpoint: Endpoint,
    dispatcher: &Dispatcher,
    on_greeted: &mut dyn FnMut(),
) -> Closed {
    let mut reader = FrameReader::new(reader);
    let mut writer = FrameWriter::new(writer);
    let mut session = Session {
        endpoint,
        dispatcher,
        greeted: false,
    };
    loop {
        let payload = match reader.read_frame() {
            Ok(Some(Frame::Json(payload))) => payload,
            Ok(None) => return Closed::Peer,
            // No method opens a binary stream yet, so the reader refuses every chunk as an unknown stream before it
            // gets here. Should one arrive anyway, the stream is not ours to read: close.
            Ok(Some(Frame::Chunk { .. } | Frame::End { .. })) => {
                return Closed::Frame(JsonError::Frame(knsh_json::FrameReason::UnknownStream));
            }
            Err(error) => return Closed::Frame(error),
        };
        let was_greeted = session.greeted;
        let step = session.handle(&payload);
        // Free the payload (up to 1 MB) before a handler's answer is written, so a connection holds one at a time.
        drop(payload);
        if session.greeted && !was_greeted {
            on_greeted();
        }
        if let Some(reply) = step.reply
            && let Err(error) = write(&mut writer, &reply)
        {
            return Closed::Write(error);
        }
        if step.close {
            // Once greeted, only malformed JSON closes the connection; before that, every close is the handshake
            // rule (including malformed JSON as the first message).
            return if session.greeted {
                Closed::Parse
            } else {
                Closed::Handshake
            };
        }
    }
}

/// Writes one message and flushes it. A result that cannot be written as strict JSON (too deep, too large) is
/// replaced by `-32603` for the same request, so the client is never left waiting.
fn write<W: Write>(writer: &mut FrameWriter<W>, message: &Message) -> Result<(), JsonError> {
    let written = match message.to_value() {
        Ok(value) => writer.write_json(&value),
        // The result cannot even be built as a JSON value: treat it like one too deep to write.
        Err(_) => Err(JsonError::TooDeep),
    };
    match written {
        Ok(()) => {}
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
        Dispatcher::new(
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

    /// Runs a connection over `input` and returns why it closed and every answer, decoded.
    fn run(input: &[u8]) -> (Closed, Vec<Message>) {
        let mut output = Vec::new();
        let closed = serve(
            Cursor::new(input),
            &mut output,
            Endpoint::User,
            &dispatcher(),
            &mut || {},
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
        let dispatcher = Dispatcher::new(Table::new(), Table::new());
        let mut output = Vec::new();
        let closed = serve(
            Cursor::new(frames(&[HELLO_REQ, HELLO_REQ])),
            &mut output,
            Endpoint::User,
            &dispatcher,
            &mut || {},
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

    #[test]
    fn on_greeted_runs_once_after_hello() {
        let mut calls = 0;
        let mut output = Vec::new();
        serve(
            Cursor::new(frames(&[HELLO_REQ, HELLO_REQ])),
            &mut output,
            Endpoint::User,
            &dispatcher(),
            &mut || calls += 1,
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
        let dispatcher = Dispatcher::new(
            Table::new().with(HELLO, std::sync::Arc::new(move |_: &Request| Ok((*deep).clone()))),
            Table::new(),
        );
        let mut output = Vec::new();
        serve(
            Cursor::new(frames(&[HELLO_REQ])),
            &mut output,
            Endpoint::User,
            &dispatcher,
            &mut || {},
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
}
