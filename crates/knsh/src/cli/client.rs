//! A small blocking JSON-RPC client for `user.sock` (`specs/06-api/README.md`, `specs/06-api/handshake.md`).
//!
//! One request at a time: [`Client::hello`] first, then [`Client::call`] for each method. The answer to a call is the
//! response with the same `id`; notifications that arrive in between are skipped. Every frame is read through
//! `knsh-json`'s frame codec and every message through `knsh-proto`, with the same strict rules as `knshd`, so a
//! malformed answer is reported, never guessed at.
//!
//! Introduced with `knsh forget` (KNSH-017); `knsh history` and `knsh events` (KNSH-023) build on it.

use std::fmt;
use std::io::{self, Read, Write};

use knsh_json::{Frame, FrameReader, FrameWriter, JsonError, Object, ToJson, Value};
use knsh_proto::{Message, MethodName, ProtoError, Request, RequestId, RpcError, SUPPORTED_PROTOCOLS, decode};

/// The name this client gives in `hello`.
pub const CLIENT_NAME: &str = "knsh";

/// Why a call failed.
#[derive(Debug)]
pub enum ClientError {
    /// `knshd`'s socket could not be reached (not installed, or launchd refused to start it).
    Connect(io::Error),
    /// Reading or writing the connection failed, including a read timeout.
    Io(io::Error),
    /// `knshd` closed the connection before answering.
    Closed,
    /// The answer was not a valid frame or message, or answered another request.
    Protocol,
    /// `knshd` answered with an error.
    Rpc(RpcError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(error) => write!(
                f,
                "cannot reach knshd ({error}); is it installed? see 'knsh daemon install'"
            ),
            Self::Io(error) => write!(f, "connection to knshd failed: {error}"),
            Self::Closed => f.write_str("knshd closed the connection before answering"),
            Self::Protocol => f.write_str("knshd sent an answer this client cannot read"),
            Self::Rpc(error) => write!(f, "{}", error.code),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(error) | Self::Io(error) => Some(error),
            Self::Closed | Self::Protocol | Self::Rpc(_) => None,
        }
    }
}

impl From<JsonError> for ClientError {
    /// A framing failure: an I/O error underneath, or bytes that break the frame rules.
    fn from(error: JsonError) -> Self {
        match error {
            JsonError::Io(kind) => Self::Io(io::Error::from(kind)),
            _ => Self::Protocol,
        }
    }
}

impl From<ProtoError> for ClientError {
    fn from(_: ProtoError) -> Self {
        Self::Protocol
    }
}

/// A connection to an engine endpoint.
pub struct Client<R: Read, W: Write> {
    reader: FrameReader<R>,
    writer: FrameWriter<W>,
    next_id: u32,
}

impl<R: Read, W: Write> Client<R, W> {
    /// A client over the two halves of a connection.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: FrameReader::new(reader),
            writer: FrameWriter::new(writer),
            next_id: 1,
        }
    }

    /// The handshake: names this client and its protocol versions. Must be the first call on a connection.
    ///
    /// # Errors
    ///
    /// Any [`ClientError`]; [`ClientError::Rpc`] with `-32005` if `knshd` speaks none of this client's protocols.
    pub fn hello(&mut self) -> Result<Value, ClientError> {
        let params = Object::new()
            .with("client", CLIENT_NAME)?
            .with("client_version", env!("CARGO_PKG_VERSION"))?
            .with("protocols", SUPPORTED_PROTOCOLS.to_vec().to_json()?)?;
        self.call("hello", Some(params))
    }

    /// Calls `method` and waits for its answer.
    ///
    /// # Errors
    ///
    /// [`ClientError::Rpc`] when `knshd` answers with an error; [`ClientError::Io`], [`ClientError::Closed`] or
    /// [`ClientError::Protocol`] when no valid answer arrives.
    pub fn call(&mut self, method: &str, params: Option<Object>) -> Result<Value, ClientError> {
        let id = RequestId::from(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        let request = Message::Request(Request {
            id: id.clone(),
            method: MethodName::new(method)?,
            params,
        });
        self.writer.write_json(&request.to_value()?)?;
        self.writer.flush()?;
        loop {
            let Some(frame) = self.reader.read_frame()? else {
                return Err(ClientError::Closed);
            };
            // This client opens no binary stream, so only JSON frames can be valid here.
            let Frame::Json(payload) = frame else {
                return Err(ClientError::Protocol);
            };
            match decode(&payload).map_err(|_| ClientError::Protocol)? {
                Message::Success(success) if success.id == id => return Ok(success.result),
                Message::Error(failure) if failure.id.as_ref() == Some(&id) => {
                    return Err(ClientError::Rpc(failure.error));
                }
                // Engine notifications (events) may interleave with answers; they are not ours to handle here.
                Message::Notification(_) => {}
                Message::Request(_) | Message::Success(_) | Message::Error(_) => return Err(ClientError::Protocol),
            }
        }
    }
}

/// Connects to `user.sock` at `path` and runs the handshake.
///
/// # Errors
///
/// [`ClientError::Connect`] if the socket cannot be reached; any error of [`Client::hello`].
#[cfg(unix)]
pub fn connect_user(
    path: &std::path::Path,
) -> Result<Client<std::os::unix::net::UnixStream, std::os::unix::net::UnixStream>, ClientError> {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    // `knshd` may need a moment to start on demand; a large `forget` may take a while. Bounded either way, so a stuck
    // daemon never hangs the shell.
    const READ_TIMEOUT: Duration = Duration::from_secs(300);
    const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

    let stream = UnixStream::connect(path).map_err(ClientError::Connect)?;
    stream.set_read_timeout(Some(READ_TIMEOUT)).map_err(ClientError::Io)?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT)).map_err(ClientError::Io)?;
    let writer = stream.try_clone().map_err(ClientError::Io)?;
    let mut client = Client::new(stream, writer);
    client.hello()?;
    Ok(client)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Cursor;

    use knsh_proto::ErrorCode;

    use super::*;

    /// Frames each JSON text as one frame: what `knshd` would send.
    pub(crate) fn frames(texts: &[&str]) -> Vec<u8> {
        let mut wire = FrameWriter::new(Vec::new());
        for text in texts {
            wire.write_json(&knsh_json::parse(text.as_bytes(), 1 << 16).unwrap())
                .unwrap();
        }
        wire.into_inner()
    }

    /// The JSON texts of every frame in `wire`: what the client sent.
    pub(crate) fn sent(wire: &[u8]) -> Vec<String> {
        let mut reader = FrameReader::new(wire);
        let mut texts = Vec::new();
        while let Some(Frame::Json(payload)) = reader.read_frame().unwrap() {
            texts.push(String::from_utf8(payload).unwrap());
        }
        texts
    }

    pub(crate) const HELLO_OK: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"protocol":1}}"#;

    #[test]
    fn calls_are_matched_to_their_answers() {
        let answers = frames(&[
            HELLO_OK,
            r#"{"jsonrpc":"2.0","method":"event.something","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"deleted":1}}"#,
        ]);
        let mut written = Vec::new();
        let mut client = Client::new(Cursor::new(answers), &mut written);
        client.hello().unwrap();
        let result = client.call("records.forget", Some(Object::new())).unwrap();
        assert_eq!(
            result.as_object().unwrap().get("deleted").and_then(Value::as_i64),
            Some(1)
        );
        let texts = sent(&written);
        assert!(texts[0].contains(r#""method":"hello""#), "{}", texts[0]);
        assert!(texts[0].contains(r#""client":"knsh""#), "{}", texts[0]);
        assert!(texts[1].contains(r#""id":2"#), "{}", texts[1]);
    }

    #[test]
    fn errors_and_bad_answers_are_reported() {
        let answers = frames(&[
            HELLO_OK,
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32003,"message":"Caller not allowed on this endpoint or session"}}"#,
        ]);
        let mut client = Client::new(Cursor::new(answers), Vec::new());
        client.hello().unwrap();
        match client.call("records.forget", None) {
            Err(ClientError::Rpc(error)) => assert_eq!(error.code, ErrorCode::NotAllowed),
            other => panic!("{other:?}"),
        }
        // The connection ended without an answer.
        assert!(matches!(client.call("records.forget", None), Err(ClientError::Closed)));

        // An answer to another request is not taken as ours.
        let answers = frames(&[r#"{"jsonrpc":"2.0","id":9,"result":{}}"#]);
        let mut client = Client::new(Cursor::new(answers), Vec::new());
        assert!(matches!(client.hello(), Err(ClientError::Protocol)));
    }
}
