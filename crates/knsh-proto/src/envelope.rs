//! The JSON-RPC 2.0 envelope: requests, notifications, success and error responses, read and written strictly
//! (`specs/06-api/README.md#envelope`).
//!
//! [`decode`] turns one frame payload into a [`Message`] or a [`Rejection`]. A rejection carries the
//! [`ProtoError`] (and so the code) plus what is needed to answer it: the caller's `id` when it could be read, and
//! whether answering is allowed at all, since JSON-RPC forbids replying to notifications and responses.

use knsh_json::{Fields, FromJson, JsonError, Kind, MAX_PAYLOAD, Object, Value};

use crate::error::{EnvelopeFault, ProtoError};
use crate::error_code::ErrorCode;
use crate::method::MethodName;

/// Longest accepted string `id`, in bytes. The engine echoes the `id` in its answer, so an unbounded one would let a
/// caller make every answer as large as its request.
pub const MAX_ID_LEN: usize = 128;

/// The value of `jsonrpc` in every message.
const VERSION: &str = "2.0";

/// The only members an envelope may have. Extensions belong inside `params`, `result` or `data`.
const MEMBERS: [&str; 6] = ["jsonrpc", "id", "method", "params", "result", "error"];

/// A request `id`: an integer within ±2^53 or a short string, echoed unchanged in the response.
///
/// # Invariants
///
/// An integer is within ±2^53 and was written without a fraction or exponent (`1.0` is not an id: echoing it back as
/// `1` would not match what the caller sent). A string is at most [`MAX_ID_LEN`] bytes. `null` is never an id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(IdRepr);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum IdRepr {
    Int(i64),
    String(String),
}

impl RequestId {
    /// An integer id.
    ///
    /// # Errors
    ///
    /// [`ProtoError::InvalidRequest`] ([`EnvelopeFault::InvalidId`]) outside ±2^53.
    pub fn int(value: i64) -> Result<Self, ProtoError> {
        // `Value::int` holds the ±2^53 rule, so the check lives in one place.
        Value::int(value)
            .map(|_| Self(IdRepr::Int(value)))
            .map_err(|_| invalid(EnvelopeFault::InvalidId))
    }

    /// A string id.
    ///
    /// # Errors
    ///
    /// [`ProtoError::InvalidRequest`] ([`EnvelopeFault::InvalidId`]) if longer than [`MAX_ID_LEN`] bytes.
    pub fn string(value: impl Into<String>) -> Result<Self, ProtoError> {
        let value = value.into();
        if value.len() <= MAX_ID_LEN {
            Ok(Self(IdRepr::String(value)))
        } else {
            Err(invalid(EnvelopeFault::InvalidId))
        }
    }

    /// The integer, if this is an integer id.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match &self.0 {
            IdRepr::Int(value) => Some(*value),
            IdRepr::String(_) => None,
        }
    }

    /// The string, if this is a string id.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match &self.0 {
            IdRepr::Int(_) => None,
            IdRepr::String(value) => Some(value),
        }
    }

    /// Reads an id member's value; `None` if it breaks the invariants (including `null`, which callers handle first).
    fn read(value: &Value) -> Option<Self> {
        match value {
            // A decimal such as `1.0` is refused even when it is an exact integer (see the type's invariants).
            Value::Number(number) if number.as_decimal_text().is_none() => {
                number.as_i64().map(|i| Self(IdRepr::Int(i)))
            }
            Value::String(text) => Self::string(text.as_str()).ok(),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => None,
        }
    }

    fn to_value(&self) -> Result<Value, ProtoError> {
        match &self.0 {
            IdRepr::Int(value) => Value::int(*value).map_err(ProtoError::Encode),
            IdRepr::String(value) => Ok(Value::from(value.as_str())),
        }
    }
}

impl From<u32> for RequestId {
    /// Any `u32` is within ±2^53, so a client's request counter needs no error handling.
    fn from(value: u32) -> Self {
        Self(IdRepr::Int(i64::from(value)))
    }
}

/// A call that expects an answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// Echoed in the response.
    pub id: RequestId,
    /// The method to call.
    pub method: MethodName,
    /// Named parameters; `None` when the member is absent.
    pub params: Option<Object>,
}

impl Request {
    /// Reads `params` as the method's parameter type. Absent `params` reads as an empty object, so a method whose
    /// parameters are all optional accepts both.
    ///
    /// # Errors
    ///
    /// [`ProtoError::InvalidParams`] (`-32602`) with the conversion error when `params` does not fit `T`.
    pub fn params<T: FromJson>(&self) -> Result<T, ProtoError> {
        read_params(self.params.as_ref())
    }
}

/// A call that expects no answer (no `id`), such as the engine's `command.output` events.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    /// The method to call.
    pub method: MethodName,
    /// Named parameters; `None` when the member is absent.
    pub params: Option<Object>,
}

impl Notification {
    /// Reads `params` as the method's parameter type; see [`Request::params`].
    ///
    /// # Errors
    ///
    /// [`ProtoError::InvalidParams`] (`-32602`) when `params` does not fit `T`.
    pub fn params<T: FromJson>(&self) -> Result<T, ProtoError> {
        read_params(self.params.as_ref())
    }
}

/// The answer to a request that succeeded.
#[derive(Debug, Clone, PartialEq)]
pub struct SuccessResponse {
    /// The request's `id`.
    pub id: RequestId,
    /// The method's result.
    pub result: Value,
}

/// The `error` member of an error response.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcError {
    /// What went wrong.
    pub code: ErrorCode,
    /// Human-readable text. Engine-built errors use [`ErrorCode::meaning`], never text from the request.
    pub message: String,
    /// Details; for engine codes, an object with the fields of [`ErrorCode::data_fields`].
    pub data: Option<Value>,
}

impl RpcError {
    /// An error with the code's fixed meaning as its message and no `data`.
    #[must_use]
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            message: code.meaning().to_owned(),
            data: None,
        }
    }

    /// The same error with `data` attached.
    #[must_use]
    pub fn with_data(self, data: Value) -> Self {
        Self {
            data: Some(data),
            ..self
        }
    }
}

impl From<&ProtoError> for RpcError {
    /// The answer to a protocol error. No `data`: the details (offsets, field names) help only an attacker probing the
    /// parser, and the code alone tells an honest client what to fix.
    fn from(error: &ProtoError) -> Self {
        Self::new(error.code())
    }
}

/// The answer to a request that failed.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorResponse {
    /// The request's `id`, or `None` (`"id": null`) when it could not be read.
    pub id: Option<RequestId>,
    /// The error.
    pub error: RpcError,
}

/// One JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A call that expects an answer.
    Request(Request),
    /// A call that expects no answer.
    Notification(Notification),
    /// A successful answer.
    Success(SuccessResponse),
    /// A failed answer.
    Error(ErrorResponse),
}

impl Message {
    /// Reads a message from an already-parsed value.
    ///
    /// # Errors
    ///
    /// A [`Rejection`] when `value` is not a valid envelope (`-32600`), names a malformed method (`-32601`) or sends
    /// positional `params` (`-32602`).
    pub fn from_value(value: &Value) -> Result<Self, Rejection> {
        // Without an object there is no `id` to read, so these are answered with `id: null`.
        let object = match value {
            Value::Object(object) => object,
            Value::Array(_) => return Err(Rejection::answered(None, invalid(EnvelopeFault::Batch))),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                return Err(Rejection::answered(None, invalid(EnvelopeFault::NotAnObject)));
            }
        };
        let has = |key| object.contains_key(key);
        // A message without `method` but with `result` or `error` is meant as a response. Responses are never
        // answered, even when malformed (an unreadable `id` included): answering one could start an error ping-pong
        // between two peers. Decided before the id is read so that no rejection below can be answered by mistake.
        let response_shaped = !has("method") && (has("result") || has("error"));
        // The id is read next so that every later rejection of a request can be answered with the caller's id.
        let id = IdMember::read(object.get("id")).map_err(|error| Rejection {
            error,
            id: None,
            answer: !response_shaped,
        })?;
        let reject = |error| Rejection {
            error,
            id: id.id().cloned(),
            answer: !response_shaped,
        };

        if object.get("jsonrpc").and_then(Value::as_str) != Some(VERSION) {
            return Err(reject(invalid(EnvelopeFault::WrongVersion)));
        }
        // A closed member set: an unknown member may be a misspelt `params` or `id`, and guessing would mean repairing.
        if object.iter().any(|(key, _)| !MEMBERS.contains(&key)) {
            return Err(reject(invalid(EnvelopeFault::UnknownMember)));
        }
        // Exactly one of `method`, `result` and `error` decides the kind; `params` belongs to calls only.
        match (object.get("method"), has("result"), has("error"), has("params")) {
            (Some(method), false, false, _) => read_call(object, method, id),
            (None, true, false, false) => read_success(object, id),
            (None, false, true, false) => read_error(object, id),
            _ => Err(reject(invalid(EnvelopeFault::Ambiguous))),
        }
    }

    /// The message as a JSON value.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Encode`] if a part cannot be built as strict JSON.
    pub fn to_value(&self) -> Result<Value, ProtoError> {
        let mut object = Object::new();
        insert(&mut object, "jsonrpc", Value::from(VERSION))?;
        match self {
            Self::Request(request) => {
                insert(&mut object, "id", request.id.to_value()?)?;
                insert_call(&mut object, &request.method, request.params.as_ref())?;
            }
            Self::Notification(notification) => {
                insert_call(&mut object, &notification.method, notification.params.as_ref())?;
            }
            Self::Success(success) => {
                insert(&mut object, "id", success.id.to_value()?)?;
                insert(&mut object, "result", success.result.clone())?;
            }
            Self::Error(response) => {
                let id = match &response.id {
                    Some(id) => id.to_value()?,
                    None => Value::Null,
                };
                insert(&mut object, "id", id)?;
                insert(&mut object, "error", error_value(&response.error)?)?;
            }
        }
        Ok(Value::Object(object))
    }
}

/// Reads one frame payload as a message.
///
/// # Errors
///
/// A [`Rejection`] with [`ProtoError::Parse`] (`-32700`) when the payload is not strict-profile JSON, or any rejection
/// of [`Message::from_value`].
pub fn decode(payload: &[u8]) -> Result<Message, Rejection> {
    // Frames already cap the payload; passing the same limit makes `decode` safe on input from any other source.
    let value =
        knsh_json::parse(payload, MAX_PAYLOAD).map_err(|error| Rejection::answered(None, ProtoError::Parse(error)))?;
    Message::from_value(&value)
}

/// Writes a message as strict-profile JSON text, ready for a frame.
///
/// # Errors
///
/// [`ProtoError::Encode`] if the message cannot be written as strict JSON (for example `result` nested deeper than
/// the profile allows).
pub fn encode(message: &Message) -> Result<String, ProtoError> {
    knsh_json::write(&message.to_value()?).map_err(ProtoError::Encode)
}

/// A message that could not be read, with what is needed to answer it.
#[derive(Debug, Clone, PartialEq)]
pub struct Rejection {
    error: ProtoError,
    id: Option<RequestId>,
    /// False for notifications and responses: JSON-RPC forbids answering them, even with an error.
    answer: bool,
}

impl Rejection {
    /// A rejection that is answered, with `id` or `null`.
    const fn answered(id: Option<RequestId>, error: ProtoError) -> Self {
        Self {
            error,
            id,
            answer: true,
        }
    }

    /// A rejection that must not be answered.
    const fn silent(id: Option<RequestId>, error: ProtoError) -> Self {
        Self {
            error,
            id,
            answer: false,
        }
    }

    /// Why the message was refused.
    #[must_use]
    pub const fn error(&self) -> &ProtoError {
        &self.error
    }

    /// The message's `id`, if it could be read.
    #[must_use]
    pub const fn id(&self) -> Option<&RequestId> {
        self.id.as_ref()
    }

    /// The error response to send, or `None` when the message was a notification or a response, which are never
    /// answered (`specs/06-api/README.md#envelope`).
    #[must_use]
    pub fn response(&self) -> Option<ErrorResponse> {
        self.answer.then(|| ErrorResponse {
            id: self.id.clone(),
            error: RpcError::from(&self.error),
        })
    }
}

/// The `id` member as found: absent, `null`, or a valid id.
enum IdMember {
    Absent,
    Null,
    Id(RequestId),
}

impl IdMember {
    /// Reads the member. An invalid id cannot be echoed, so a request carrying one is answered with `id: null`; the
    /// caller decides whether to answer at all.
    fn read(member: Option<&Value>) -> Result<Self, ProtoError> {
        match member {
            None => Ok(Self::Absent),
            Some(Value::Null) => Ok(Self::Null),
            Some(value) => RequestId::read(value)
                .map(Self::Id)
                .ok_or(invalid(EnvelopeFault::InvalidId)),
        }
    }

    const fn id(&self) -> Option<&RequestId> {
        match self {
            Self::Id(id) => Some(id),
            Self::Absent | Self::Null => None,
        }
    }
}

/// Reads a request or notification.
///
/// Envelope faults are always answered: JSON-RPC answers an invalid request even when it might have been meant as a
/// notification. An unknown method or bad params is answered only for a request, never for a notification.
fn read_call(object: &Object, method: &Value, id: IdMember) -> Result<Message, Rejection> {
    let id = match id {
        IdMember::Id(id) => Some(id),
        IdMember::Absent => None,
        // A request `id` is never `null` (README.md#envelope): it could not be told apart from an unreadable one.
        IdMember::Null => return Err(Rejection::answered(None, invalid(EnvelopeFault::InvalidId))),
    };
    let fault = |fault| Rejection::answered(id.clone(), invalid(fault));
    let call_error = |error| match &id {
        Some(id) => Rejection::answered(Some(id.clone()), error),
        None => Rejection::silent(None, error),
    };

    let Some(method) = method.as_str() else {
        return Err(fault(EnvelopeFault::MethodNotString));
    };
    // `params` must be structured (JSON-RPC 2.0 section 4.2). An array is structured but positional, which no engine
    // method takes: that is a params error for the method (checked after the method), not an envelope error. The
    // shape is classified before the method so that envelope faults (-32600) take precedence over -32601 and -32602.
    let params = match object.get("params") {
        None => Params::Absent,
        Some(Value::Object(params)) => Params::Named(params),
        Some(Value::Array(_)) => Params::Positional,
        Some(Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)) => {
            return Err(fault(EnvelopeFault::ParamsNotStructured));
        }
    };
    let method = MethodName::new(method).map_err(call_error)?;
    let params = match params {
        Params::Absent => None,
        Params::Named(params) => Some(params.clone()),
        Params::Positional => {
            let error = JsonError::WrongType {
                field: Some("params"),
                expected: Kind::Object,
            };
            return Err(call_error(ProtoError::InvalidParams(error)));
        }
    };
    Ok(match id {
        Some(id) => Message::Request(Request { id, method, params }),
        None => Message::Notification(Notification { method, params }),
    })
}

/// The shape of a call's `params` member.
enum Params<'a> {
    Absent,
    Named(&'a Object),
    Positional,
}

/// Reads a success response. Responses are never answered, so every rejection here is silent.
fn read_success(object: &Object, id: IdMember) -> Result<Message, Rejection> {
    // A success answers a request whose `id` was read, so `id: null` cannot be one.
    let id = response_id(id)?.ok_or_else(|| Rejection::silent(None, invalid(EnvelopeFault::InvalidId)))?;
    // The kind match in `Message::from_value` guarantees `result`; the default only keeps this free of panics.
    let result = object.get("result").cloned().unwrap_or(Value::Null);
    Ok(Message::Success(SuccessResponse { id, result }))
}

/// Reads an error response. `id: null` is allowed here: it answers a request whose id could not be read.
fn read_error(object: &Object, id: IdMember) -> Result<Message, Rejection> {
    let id = response_id(id)?;
    let reject = |fault| Rejection::silent(id.clone(), invalid(fault));
    // As in `read_success`, `error` is guaranteed present; a `null` default would be refused as malformed anyway.
    let member = object.get("error").unwrap_or(&Value::Null);
    let (code, message, data) = read_error_object(member).map_err(|_| reject(EnvelopeFault::InvalidErrorObject))?;
    // The code set is closed (see `ErrorCode`): a client must never act on a code it does not know.
    let code = ErrorCode::from_code(code).ok_or_else(|| reject(EnvelopeFault::UnknownErrorCode))?;
    Ok(Message::Error(ErrorResponse {
        id,
        error: RpcError { code, message, data },
    }))
}

/// The id of a response: a response must carry the `id` member, though it may be `null`.
fn response_id(id: IdMember) -> Result<Option<RequestId>, Rejection> {
    match id {
        IdMember::Id(id) => Ok(Some(id)),
        IdMember::Null => Ok(None),
        IdMember::Absent => Err(Rejection::silent(None, invalid(EnvelopeFault::MissingId))),
    }
}

/// Reads the members of an `error` object, which is closed: an unknown member is refused like a malformed one.
fn read_error_object(value: &Value) -> Result<(i64, String, Option<Value>), JsonError> {
    let mut fields = Fields::new(value)?;
    let code = fields.required("code")?;
    let message = fields.required("message")?;
    let data = fields.optional("data")?;
    fields.finish_closed()?;
    Ok((code, message, data))
}

/// Reads `params` as `T`, an absent member reading as an empty object.
fn read_params<T: FromJson>(params: Option<&Object>) -> Result<T, ProtoError> {
    let value = Value::Object(params.cloned().unwrap_or_default());
    T::from_json(&value).map_err(ProtoError::InvalidParams)
}

/// Adds `method` and, when present, `params`.
fn insert_call(object: &mut Object, method: &MethodName, params: Option<&Object>) -> Result<(), ProtoError> {
    insert(object, "method", Value::from(method.as_str()))?;
    if let Some(params) = params {
        insert(object, "params", Value::Object(params.clone()))?;
    }
    Ok(())
}

/// The `error` member: `code`, `message` and, when present, `data`.
fn error_value(error: &RpcError) -> Result<Value, ProtoError> {
    let mut object = Object::new();
    insert(
        &mut object,
        "code",
        Value::int(i64::from(error.code.code())).map_err(ProtoError::Encode)?,
    )?;
    insert(&mut object, "message", Value::from(error.message.as_str()))?;
    if let Some(data) = &error.data {
        insert(&mut object, "data", data.clone())?;
    }
    Ok(Value::Object(object))
}

/// Adds one member to an outgoing object; any failure is an encoding error (`-32603`).
fn insert(object: &mut Object, key: &'static str, value: Value) -> Result<(), ProtoError> {
    object.insert(key, value).map_err(ProtoError::Encode)
}

/// Shorthand for the `-32600` error with `fault`.
const fn invalid(fault: EnvelopeFault) -> ProtoError {
    ProtoError::InvalidRequest(fault)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_str(text: &str) -> Result<Message, Rejection> {
        decode(text.as_bytes())
    }

    fn rejection(text: &str) -> Rejection {
        decode_str(text).unwrap_err()
    }

    fn answer(text: &str) -> String {
        let response = rejection(text).response().expect("an answer");
        encode(&Message::Error(response)).unwrap()
    }

    fn method(name: &str) -> MethodName {
        MethodName::new(name).unwrap()
    }

    fn object(json: &str) -> Object {
        match knsh_json::parse(json.as_bytes(), 1024).unwrap() {
            Value::Object(object) => object,
            other => panic!("not an object: {other:?}"),
        }
    }

    #[test]
    fn parse_error_maps_to_minus_32700() {
        // Strict profile (wire-format.md "Strict JSON profile"): every violation is a parse error, answered with
        // `id: null` because nothing in the message can be trusted, and the connection stays usable.
        let deep = format!("{}{}", "[".repeat(33), "]".repeat(33));
        let violations: [&[u8]; 9] = [
            br#"{"jsonrpc":"2.0","id":1,"method":"exec.run","method":"exec.kill"}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"exec.run",}"#,
            br#"{"jsonrpc":"2.0","id":9007199254740993,"method":"exec.run"}"#,
            br#"{"jsonrpc":"2.0","id":"\ud800","method":"exec.run"}"#,
            b"{\"jsonrpc\":\"2.0\",\"id\":\"\xff\",\"method\":\"exec.run\"}",
            br#"{"jsonrpc":"2.0","id":1,"method":"exec.run"} {}"#,
            b"// comment",
            b"",
            deep.as_bytes(),
        ];
        for payload in violations {
            let rejection = decode(payload).unwrap_err();
            assert!(matches!(rejection.error(), ProtoError::Parse(_)), "{payload:?}");
            assert_eq!(rejection.error().code(), ErrorCode::ParseError);
            let response = rejection.response().unwrap();
            assert_eq!(
                encode(&Message::Error(response)).unwrap(),
                r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#
            );
        }
        let oversized = vec![b' '; MAX_PAYLOAD + 1];
        assert!(matches!(decode(&oversized).unwrap_err().error(), ProtoError::Parse(_)));
    }

    #[test]
    fn rejects_wrong_jsonrpc_version() {
        for version in [r#""1.0""#, r#""2""#, r#""2.0 ""#, "2.0", "null", r#"["2.0"]"#] {
            let text = format!(r#"{{"jsonrpc":{version},"id":5,"method":"exec.run"}}"#);
            let rejection = rejection(&text);
            assert_eq!(
                rejection.error(),
                &ProtoError::InvalidRequest(EnvelopeFault::WrongVersion)
            );
            assert_eq!(
                rejection.id(),
                Some(&RequestId::from(5)),
                "the id is echoed when it can be read"
            );
            assert_eq!(
                answer(&text),
                r#"{"jsonrpc":"2.0","id":5,"error":{"code":-32600,"message":"Invalid Request"}}"#
            );
        }
        let missing = rejection(r#"{"id":"a","method":"exec.run"}"#);
        assert_eq!(
            missing.error(),
            &ProtoError::InvalidRequest(EnvelopeFault::WrongVersion)
        );
        // A wrong version on a response is refused too, but never answered.
        let response = rejection(r#"{"jsonrpc":"1.0","id":1,"result":true}"#);
        assert_eq!(
            response.error(),
            &ProtoError::InvalidRequest(EnvelopeFault::WrongVersion)
        );
        assert_eq!(response.response(), None);
    }

    #[test]
    fn round_trips_request_response_notification() {
        let params = object(r#"{"command":"npm test","timeout_s":30,"env":{"CI":"1"}}"#);
        let messages = [
            Message::Request(Request {
                id: RequestId::from(7),
                method: method("exec.run"),
                params: Some(params.clone()),
            }),
            Message::Request(Request {
                id: RequestId::string("req-1").unwrap(),
                method: method("hello"),
                params: None,
            }),
            Message::Notification(Notification {
                method: method("command.output"),
                params: Some(params),
            }),
            Message::Notification(Notification {
                method: method("decision.cancelled"),
                params: None,
            }),
            Message::Success(SuccessResponse {
                id: RequestId::int(-(1 << 53)).unwrap(),
                result: Value::from(object(r#"{"record_id":"01J","exit_code":0}"#)),
            }),
            Message::Success(SuccessResponse {
                id: RequestId::from(1),
                result: Value::Null,
            }),
            Message::Error(ErrorResponse {
                id: Some(RequestId::from(3)),
                error: RpcError::new(ErrorCode::Denied).with_data(Value::from(object(
                    r#"{"rule_id":"r1","reason":"no","source":"policy"}"#,
                ))),
            }),
            Message::Error(ErrorResponse {
                id: None,
                error: RpcError::new(ErrorCode::ParseError),
            }),
        ];
        for message in messages {
            let text = encode(&message).unwrap();
            assert_eq!(decode_str(&text), Ok(message.clone()), "{text}");
            assert_eq!(encode(&decode_str(&text).unwrap()).unwrap(), text, "stable encoding");
        }
        // The exact wire form of each kind.
        let request = Message::Request(Request {
            id: RequestId::from(1),
            method: method("exec.run"),
            params: Some(object(r#"{"command":"ls"}"#)),
        });
        assert_eq!(
            encode(&request).unwrap(),
            r#"{"jsonrpc":"2.0","id":1,"method":"exec.run","params":{"command":"ls"}}"#
        );
        let notification = Message::Notification(Notification {
            method: method("command.output"),
            params: None,
        });
        assert_eq!(
            encode(&notification).unwrap(),
            r#"{"jsonrpc":"2.0","method":"command.output"}"#
        );
    }

    #[test]
    fn reads_spec_examples() {
        // specs/06-api/handshake.md and agent-socket.md.
        let hello = decode_str(
            r#"{"jsonrpc": "2.0", "id": 1, "method": "hello",
                "params": {"client": "my-agent", "client_version": "0.4.0", "protocols": [1], "session_token": "t"}}"#,
        )
        .unwrap();
        let Message::Request(hello) = hello else {
            panic!("not a request")
        };
        assert_eq!((hello.id.as_i64(), hello.method.as_str()), (Some(1), "hello"));
        let result = decode_str(r#"{"jsonrpc": "2.0", "id": 7, "result": {"record_id": "01J", "exit_code": 0}}"#);
        assert!(matches!(result, Ok(Message::Success(_))));
    }

    #[test]
    fn unknown_or_malformed_method_maps_to_minus_32601() {
        for name in ["exec", "Exec.run", "rpc.discover", "exec.run.now", ""] {
            let text = format!(r#"{{"jsonrpc":"2.0","id":"x","method":"{name}"}}"#);
            assert_eq!(rejection(&text).error(), &ProtoError::MethodNotFound, "{name}");
            assert_eq!(
                answer(&text),
                r#"{"jsonrpc":"2.0","id":"x","error":{"code":-32601,"message":"Method not found"}}"#
            );
        }
        // JSON-RPC never answers a notification, not even an unknown one.
        let notification = rejection(r#"{"jsonrpc":"2.0","method":"no_such"}"#);
        assert_eq!(notification.error(), &ProtoError::MethodNotFound);
        assert_eq!(notification.response(), None);
    }

    #[test]
    fn invalid_params_map_to_minus_32602() {
        let text = r#"{"jsonrpc":"2.0","id":2,"method":"exec.run","params":["ls"]}"#;
        assert!(matches!(rejection(text).error(), ProtoError::InvalidParams(_)));
        assert_eq!(
            answer(text),
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Invalid params"}}"#
        );
        assert_eq!(
            rejection(r#"{"jsonrpc":"2.0","method":"exec.run","params":[]}"#).response(),
            None
        );

        // Typed reading: a field of the wrong type or a missing one is -32602, named by our code, not the input.
        let Ok(Message::Request(request)) =
            decode_str(r#"{"jsonrpc":"2.0","id":2,"method":"exec.run","params":{"n":"1"}}"#)
        else {
            panic!("not a request")
        };
        let error = request.params::<NParams>().unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidParams);
        assert_eq!(
            error,
            ProtoError::InvalidParams(JsonError::WrongType {
                field: Some("n"),
                expected: Kind::Integer
            })
        );
        let Ok(Message::Request(request)) = decode_str(r#"{"jsonrpc":"2.0","id":2,"method":"exec.run"}"#) else {
            panic!("not a request")
        };
        assert_eq!(
            request.params::<NParams>(),
            Err(ProtoError::InvalidParams(JsonError::MissingField("n")))
        );
        assert_eq!(
            request.params::<Value>(),
            Ok(Value::Object(Object::new())),
            "absent params read as {{}}"
        );
    }

    #[derive(Debug, PartialEq)]
    struct NParams {
        n: u32,
    }

    impl FromJson for NParams {
        fn from_json(value: &Value) -> Result<Self, JsonError> {
            let mut fields = Fields::new(value)?;
            let params = Self {
                n: fields.required("n")?,
            };
            fields.finish()?;
            Ok(params)
        }
    }

    #[test]
    fn rejects_invalid_envelopes_as_minus_32600() {
        let long_id = format!(
            r#"{{"jsonrpc":"2.0","id":"{}","method":"exec.run"}}"#,
            "a".repeat(MAX_ID_LEN + 1)
        );
        let cases: [(&str, EnvelopeFault, Option<RequestId>); 16] = [
            (
                r#"[{"jsonrpc":"2.0","id":1,"method":"exec.run"}]"#,
                EnvelopeFault::Batch,
                None,
            ),
            ("[]", EnvelopeFault::Batch, None),
            (r#""exec.run""#, EnvelopeFault::NotAnObject, None),
            ("null", EnvelopeFault::NotAnObject, None),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"exec.run","extra":1}"#,
                EnvelopeFault::UnknownMember,
                Some(1.into()),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1.0,"method":"exec.run"}"#,
                EnvelopeFault::InvalidId,
                None,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1.5,"method":"exec.run"}"#,
                EnvelopeFault::InvalidId,
                None,
            ),
            (
                r#"{"jsonrpc":"2.0","id":true,"method":"exec.run"}"#,
                EnvelopeFault::InvalidId,
                None,
            ),
            (
                r#"{"jsonrpc":"2.0","id":[1],"method":"exec.run"}"#,
                EnvelopeFault::InvalidId,
                None,
            ),
            (
                r#"{"jsonrpc":"2.0","id":null,"method":"exec.run"}"#,
                EnvelopeFault::InvalidId,
                None,
            ),
            (&long_id, EnvelopeFault::InvalidId, None),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":1}"#,
                EnvelopeFault::MethodNotString,
                Some(1.into()),
            ),
            (
                r#"{"jsonrpc":"2.0","method":"exec.run","params":"x"}"#,
                EnvelopeFault::ParamsNotStructured,
                None,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"exec.run","params":null}"#,
                EnvelopeFault::ParamsNotStructured,
                Some(1.into()),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"exec.run","result":1}"#,
                EnvelopeFault::Ambiguous,
                Some(1.into()),
            ),
            (r#"{"jsonrpc":"2.0","id":1}"#, EnvelopeFault::Ambiguous, Some(1.into())),
        ];
        for (text, fault, id) in cases {
            let rejection = rejection(text);
            assert_eq!(rejection.error(), &ProtoError::InvalidRequest(fault), "{text}");
            assert_eq!(rejection.error().code(), ErrorCode::InvalidRequest);
            let response = rejection.response().expect("invalid requests are always answered");
            assert_eq!(response.id, id, "{text}");
            assert_eq!(response.error, RpcError::new(ErrorCode::InvalidRequest));
        }
        let at_limit = format!(
            r#"{{"jsonrpc":"2.0","id":"{}","method":"exec.run"}}"#,
            "a".repeat(MAX_ID_LEN)
        );
        assert!(decode_str(&at_limit).is_ok());
    }

    #[test]
    fn responses_are_read_strictly_and_never_answered() {
        let cases: [(&str, ProtoError); 13] = [
            (r#"{"jsonrpc":"2.0","result":1}"#, invalid(EnvelopeFault::MissingId)),
            // An unreadable id on a response is refused but still never answered (no ping-pong).
            (
                r#"{"jsonrpc":"2.0","id":true,"result":1}"#,
                invalid(EnvelopeFault::InvalidId),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1.5,"error":{"code":-32603,"message":"m"}}"#,
                invalid(EnvelopeFault::InvalidId),
            ),
            (
                r#"{"jsonrpc":"1.0","id":[1],"result":1}"#,
                invalid(EnvelopeFault::InvalidId),
            ),
            (
                r#"{"jsonrpc":"1.0","id":1,"result":true}"#,
                invalid(EnvelopeFault::WrongVersion),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"result":1,"error":{"code":-32603,"message":"m"}}"#,
                invalid(EnvelopeFault::Ambiguous),
            ),
            (
                r#"{"jsonrpc":"2.0","id":null,"result":1}"#,
                invalid(EnvelopeFault::InvalidId),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"result":1,"params":{}}"#,
                invalid(EnvelopeFault::Ambiguous),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"error":"denied"}"#,
                invalid(EnvelopeFault::InvalidErrorObject),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001}}"#,
                invalid(EnvelopeFault::InvalidErrorObject),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001.5,"message":"m"}}"#,
                invalid(EnvelopeFault::InvalidErrorObject),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"m","extra":1}}"#,
                invalid(EnvelopeFault::InvalidErrorObject),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"m"}}"#,
                invalid(EnvelopeFault::UnknownErrorCode),
            ),
        ];
        for (text, error) in cases {
            let rejection = rejection(text);
            assert_eq!(rejection.error(), &error, "{text}");
            assert_eq!(rejection.response(), None, "{text}");
        }
        let Ok(Message::Error(response)) = decode_str(
            r#"{"jsonrpc":"2.0","id":4,"error":{"code":-32011,"message":"Request cancelled","data":{"request_id":"r"}}}"#,
        ) else {
            panic!("not an error response")
        };
        assert_eq!(
            (response.id, response.error.code),
            (Some(RequestId::from(4)), ErrorCode::Cancelled)
        );
    }

    #[test]
    fn protocol_errors_never_echo_input() {
        // The answer is fixed text per code: nothing the caller sent (other than its id) is reflected back.
        let text = r#"{"jsonrpc":"2.0","id":1,"method":"evil.<script>","params":{"x":"secret"}}"#;
        let reply = answer(text);
        assert!(!reply.contains("evil") && !reply.contains("secret"), "{reply}");
    }

    #[test]
    fn request_ids_respect_the_strict_profile() {
        assert_eq!(RequestId::int(1 << 53).map(|id| id.as_i64()), Ok(Some(1 << 53)));
        assert_eq!(RequestId::int((1 << 53) + 1), Err(invalid(EnvelopeFault::InvalidId)));
        assert_eq!(
            RequestId::string("a".repeat(MAX_ID_LEN + 1)),
            Err(invalid(EnvelopeFault::InvalidId))
        );
        assert_eq!(RequestId::string("abc").unwrap().as_str(), Some("abc"));
        assert_eq!(RequestId::from(u32::MAX).as_i64(), Some(i64::from(u32::MAX)));
    }

    #[test]
    fn encode_refuses_output_outside_the_strict_profile() {
        // Everything the engine sends conforms to the profile (wire-format.md): too-deep results fail to encode.
        let mut deep = Value::Null;
        for _ in 0..knsh_json::MAX_DEPTH {
            deep = Value::Array(vec![deep]);
        }
        let message = Message::Success(SuccessResponse {
            id: RequestId::from(1),
            result: deep,
        });
        assert_eq!(encode(&message).unwrap_err().code(), ErrorCode::InternalError);
    }
}
