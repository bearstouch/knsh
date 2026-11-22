//! `events.subscribe` and `events.unsubscribe`: parameters, results and the notifications that carry events
//! (`specs/06-api/user-socket.md#events`, `specs/05-models/event.md`, KNSH-018).
//!
//! Events reach a subscriber as JSON-RPC notifications whose `method` is the event name (for example
//! `session.started`) and whose `params` are the event envelope plus the `subscription_id` it was delivered for.
//! Events a subscriber will never receive, because it fell behind its queue (FR-EVT-04), are announced by one
//! [`EVENTS_LOST`] notification per session and range.
//!
//! `seq` values are JSON integers: they count events of one session and stay far below 2^53.
//!
//! Engine events (`authority.connected`, `authority.disconnected`, KNSH-068) use the same envelope with
//! `session_id` and `actor` set to `null` and `seq` counted in the engine's own sequence
//! ([`engine_event_notification`]); their lost ranges are announced with `session_id: null`
//! ([`engine_lost_notification`]).

use knsh_core::{
    Actor, EngineEvent, EngineEventData, EngineLost, Event, EventData, Lost, Proposal, SessionId, Subscribed,
    SubscriptionId,
};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::envelope::Notification;
use crate::error::ProtoError;
use crate::method::MethodName;
use crate::records::{OUTPUT_CONTENT_TYPE, OutputData};

/// The notification announcing events a subscription will never receive.
pub const EVENTS_LOST: &str = "events.lost";

/// The parameters of `events.subscribe`.
///
/// `since_seq` needs `session_id`: sequence numbers count one session's events, so without a session they mean
/// nothing (`-32602`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventsSubscribeParams {
    /// Only this session's events; every session the endpoint may see when absent.
    pub session_id: Option<SessionId>,
    /// Resume after this `seq`: buffered events after it are delivered first. Live events only when absent.
    pub since_seq: Option<u64>,
}

impl FromJson for EventsSubscribeParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let session_id = fields
            .optional::<String>("session_id")?
            .map(|text| text.parse().map_err(|_| out_of_range("session_id")))
            .transpose()?;
        let since_seq = fields.optional::<u64>("since_seq")?;
        fields.finish()?;
        if since_seq.is_some() && session_id.is_none() {
            return Err(JsonError::MissingField("session_id"));
        }
        Ok(Self { session_id, since_seq })
    }
}

impl ToJson for EventsSubscribeParams {
    /// Absent fields are left out.
    fn to_json(&self) -> Result<Value, JsonError> {
        let mut object = Object::new();
        if let Some(session_id) = self.session_id {
            object.insert("session_id", Value::from(session_id.to_string()))?;
        }
        if let Some(since_seq) = self.since_seq {
            object.insert("since_seq", since_seq.to_json()?)?;
        }
        Ok(Value::Object(object))
    }
}

/// The result of `events.subscribe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventsSubscribeResult {
    /// Names the subscription in its notifications and in `events.unsubscribe`.
    pub subscription_id: SubscriptionId,
    /// With `session_id`: the oldest `seq` still buffered (how far back a resume reaches). `null` otherwise.
    pub oldest_seq: Option<u64>,
    /// With `session_id`: the newest `seq` published so far. `null` otherwise.
    pub latest_seq: Option<u64>,
    /// Whether `since_seq` was older than the buffer: delivery starts at `oldest_seq`, and the events in between
    /// must be read from the record store.
    pub gap: bool,
}

impl From<Subscribed> for EventsSubscribeResult {
    fn from(subscribed: Subscribed) -> Self {
        Self {
            subscription_id: subscribed.id,
            oldest_seq: subscribed.oldest_seq,
            latest_seq: subscribed.latest_seq,
            gap: subscribed.gap,
        }
    }
}

impl ToJson for EventsSubscribeResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new()
                .with("subscription_id", self.subscription_id.get().to_json()?)?
                .with("oldest_seq", self.oldest_seq.to_json()?)?
                .with("latest_seq", self.latest_seq.to_json()?)?
                .with("gap", self.gap)?,
        ))
    }
}

impl FromJson for EventsSubscribeResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let subscription_id = SubscriptionId::new(fields.required("subscription_id")?);
        let oldest_seq = fields.optional("oldest_seq")?;
        let latest_seq = fields.optional("latest_seq")?;
        let gap = fields.required("gap")?;
        fields.finish()?;
        Ok(Self {
            subscription_id,
            oldest_seq,
            latest_seq,
            gap,
        })
    }
}

/// The parameters of `events.unsubscribe`. The result is an empty object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventsUnsubscribeParams {
    /// A subscription made on the same connection.
    pub subscription_id: SubscriptionId,
}

impl FromJson for EventsUnsubscribeParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let subscription_id = SubscriptionId::new(fields.required("subscription_id")?);
        fields.finish()?;
        Ok(Self { subscription_id })
    }
}

impl ToJson for EventsUnsubscribeParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new().with("subscription_id", self.subscription_id.get().to_json()?)?,
        ))
    }
}

/// The event envelope of `specs/05-models/event.md` as a JSON object: `event`, `id`, `seq`, `ts`, `session_id`,
/// `actor` and `data`.
///
/// # Errors
///
/// [`JsonError`] if a value cannot be written (a `seq` beyond ±2^53, which a real session never reaches).
pub fn event_envelope(event: &Event) -> Result<Object, JsonError> {
    envelope_with(event, data(&event.data)?)
}

/// The `command.proposed` event as a hook reads it on stdin (`specs/05-models/hook.md#input`, FR-HOOK-02): the
/// envelope's `event`, `session_id`, `actor` and `data`, without `id`, `seq` or `ts`, since it is not a delivery from
/// the event bus. The payload is written by the same code as the published event's, so the two cannot drift apart;
/// every text in it was redacted before the proposal was made (FR-SEC-11).
///
/// # Errors
///
/// [`JsonError`] if the object cannot be written, which a valid proposal always can.
pub fn hook_input(proposal: &Proposal<'_>) -> Result<Vec<u8>, JsonError> {
    let payload = EventData::CommandProposed {
        command: proposal.command.clone(),
        cwd: proposal.cwd.clone(),
        rewritten_from: proposal.rewritten_from.cloned(),
    };
    let object = Object::new()
        .with("event", payload.name())?
        .with("session_id", proposal.session_id.to_string())?
        .with("actor", actor(proposal.actor)?)?
        .with("data", data(&payload)?)?;
    knsh_json::write(&Value::Object(object)).map(String::into_bytes)
}

/// The envelope of `event` with `data` as its `data` member.
fn envelope_with(event: &Event, data: Object) -> Result<Object, JsonError> {
    Object::new()
        .with("event", event.name())?
        .with("id", event.id.to_string())?
        .with("seq", event.seq.to_json()?)?
        .with("ts", event.ts.to_string())?
        .with("session_id", event.session_id.to_string())?
        .with("actor", actor(&event.actor)?)?
        .with("data", data)
}

/// The notification delivering `event` to `subscription`: `method` is the event name, `params` the envelope plus
/// `subscription_id`.
///
/// # Errors
///
/// [`ProtoError::Encode`] if the envelope cannot be built.
pub fn event_notification(subscription: SubscriptionId, event: &Event) -> Result<Notification, ProtoError> {
    let params = event_envelope(event)
        .and_then(|envelope| envelope.with("subscription_id", subscription.get().to_json()?))
        .map_err(ProtoError::Encode)?;
    Ok(Notification {
        method: MethodName::new(event.name())?,
        params: Some(params),
    })
}

/// The notification delivering an event that carries raw bytes (`command.output`, KNSH-053): the envelope of
/// [`event_notification`] whose `data` also names the bytes, as `data.data` (`stream_id`, `size`, `content_type`)
/// when they follow in a binary stream, or as `data.data_base64` for a client that opted out of binary frames
/// (`specs/06-api/wire-format.md`). The caller sends the stream's chunk and end frame right after it.
///
/// # Errors
///
/// [`ProtoError::Encode`] if the envelope cannot be built, or if `event` carries no bytes.
pub fn event_notification_with_bytes(
    subscription: SubscriptionId,
    event: &Event,
    bytes: OutputData<'_>,
) -> Result<Notification, ProtoError> {
    let params = (|| {
        let size = event
            .data
            .bytes()
            .ok_or(JsonError::MissingField("bytes"))?
            .expose()
            .len();
        let size = crate::records::bytes(u64::try_from(size).unwrap_or(u64::MAX));
        let mut data = data(&event.data)?;
        match bytes {
            OutputData::Stream(id) => data.insert(
                "data",
                Value::Object(
                    Object::new()
                        .with("stream_id", id.get())?
                        .with("size", size)?
                        .with("content_type", OUTPUT_CONTENT_TYPE)?,
                ),
            )?,
            OutputData::Base64(raw) => data.insert("data_base64", Value::from(knsh_json::base64_encode(raw)))?,
        }
        envelope_with(event, data)?.with("subscription_id", subscription.get().to_json()?)
    })()
    .map_err(ProtoError::Encode)?;
    Ok(Notification {
        method: MethodName::new(event.name())?,
        params: Some(params),
    })
}

/// The [`EVENTS_LOST`] notification: `{subscription_id, session_id, from_seq, to_seq}`, every `seq` from `from_seq`
/// to `to_seq` inclusive will never be delivered on this subscription (FR-EVT-04).
///
/// # Errors
///
/// [`ProtoError::Encode`] if the parameters cannot be built.
pub fn lost_notification(subscription: SubscriptionId, lost: &Lost) -> Result<Notification, ProtoError> {
    let params = (|| {
        Object::new()
            .with("subscription_id", subscription.get().to_json()?)?
            .with("session_id", lost.session_id.to_string())?
            .with("from_seq", lost.from_seq.to_json()?)?
            .with("to_seq", lost.to_seq.to_json()?)
    })()
    .map_err(ProtoError::Encode)?;
    Ok(Notification {
        method: MethodName::new(EVENTS_LOST)?,
        params: Some(params),
    })
}

/// The notification delivering an engine event (KNSH-068) to `subscription`: the event envelope with
/// `session_id: null`, `actor: null` and an empty `data` object, plus `subscription_id`.
///
/// # Errors
///
/// [`ProtoError::Encode`] if the envelope cannot be built.
pub fn engine_event_notification(
    subscription: SubscriptionId,
    event: &EngineEvent,
) -> Result<Notification, ProtoError> {
    let params = (|| {
        Object::new()
            .with("event", event.name())?
            .with("id", event.id.to_string())?
            .with("seq", event.seq.to_json()?)?
            .with("ts", event.ts.to_string())?
            .with("session_id", Value::Null)?
            .with("actor", Value::Null)?
            .with("data", engine_data(&event.data)?)?
            .with("subscription_id", subscription.get().to_json()?)
    })()
    .map_err(ProtoError::Encode)?;
    Ok(Notification {
        method: MethodName::new(event.name())?,
        params: Some(params),
    })
}

/// The `data` member of an engine event: `{}` for the authority's arrival and departure, `{profile, expires_at}` for
/// `policy.updated` (KNSH-071).
fn engine_data(data: &EngineEventData) -> Result<Object, JsonError> {
    match data {
        EngineEventData::AuthorityConnected | EngineEventData::AuthorityDisconnected => Ok(Object::new()),
        EngineEventData::PolicyUpdated { profile, expires_at } => Object::new()
            .with("profile", profile.as_str())?
            .with("expires_at", expires_at.to_string()),
    }
}

/// The [`EVENTS_LOST`] notification for engine events: `{subscription_id, session_id: null, from_seq, to_seq}`.
///
/// # Errors
///
/// [`ProtoError::Encode`] if the parameters cannot be built.
pub fn engine_lost_notification(subscription: SubscriptionId, lost: &EngineLost) -> Result<Notification, ProtoError> {
    let params = (|| {
        Object::new()
            .with("subscription_id", subscription.get().to_json()?)?
            .with("session_id", Value::Null)?
            .with("from_seq", lost.from_seq.to_json()?)?
            .with("to_seq", lost.to_seq.to_json()?)
    })()
    .map_err(ProtoError::Encode)?;
    Ok(Notification {
        method: MethodName::new(EVENTS_LOST)?,
        params: Some(params),
    })
}

/// `{kind, agent_id?}`, as in records. Shared with `approval.list` (KNSH-066).
pub(crate) fn actor(actor: &Actor) -> Result<Object, JsonError> {
    let object = Object::new().with("kind", actor.kind().as_str())?;
    match actor.agent_id() {
        Some(agent_id) => object.with("agent_id", agent_id.as_str()),
        None => Ok(object),
    }
}

/// The `data` member of each phase 1 event (`specs/05-models/event.md#phase-1-payloads`).
#[allow(
    clippy::too_many_lines,
    reason = "one flat arm per event variant, each mirroring its payload in the spec"
)]
fn data(data: &EventData) -> Result<Object, JsonError> {
    match data {
        EventData::SessionStarted {
            profile,
            envelope,
            recording,
            parent_session_id,
        } => Object::new()
            .with("profile", profile.as_str())?
            .with("envelope", *envelope)?
            .with("recording", *recording)?
            .with(
                "parent_session_id",
                parent_session_id.map(|id| id.to_string()).to_json()?,
            ),
        EventData::SessionEnded | EventData::SessionIdle => Ok(Object::new()),
        EventData::SessionStateChanged { from, to } => {
            Object::new().with("from", from.as_str())?.with("to", to.as_str())
        }
        EventData::CommandFinished {
            record_id,
            command,
            cwd,
            started_at,
            ended_at,
            exit_code,
            parent_record_id,
        } => Object::new()
            .with("record_id", record_id.to_string())?
            // Redacted before it was published (FR-EVT-07); this is where it is emitted.
            .with("command", command.expose().as_str())?
            .with("cwd", path(cwd))?
            .with("started_at", started_at.to_string())?
            .with("ended_at", ended_at.to_string())?
            .with("exit_code", exit_code.to_json()?)?
            .with("parent_record_id", parent_record_id.map(|id| id.to_string()).to_json()?),
        EventData::CwdChanged { cwd } => Object::new().with("cwd", path(cwd)),
        // The violation's own object (`specs/05-models/event.md#phase-2-payloads`, KNSH-047).
        EventData::SandboxViolation(violation) => violation.to_object(),
        // KNSH-050 (`specs/05-models/event.md#phase-2-payloads`). Every text was redacted before it was published.
        EventData::CommandProposed {
            command,
            cwd,
            rewritten_from,
        } => Object::new()
            .with("command", command.expose().as_str())?
            .with("cwd", path(cwd))?
            .with("rewritten_from", redacted(rewritten_from.as_ref()).to_json()?),
        EventData::CommandDenied {
            record_id,
            command,
            cwd,
            source,
            rule_id,
            reason,
            parent_record_id,
        } => Object::new()
            .with("record_id", record_id.map(|id| id.to_string()).to_json()?)?
            .with("command", command.expose().as_str())?
            .with("cwd", path(cwd))?
            .with("source", source.code())?
            .with("rule_id", redacted(rule_id.as_ref()).to_json()?)?
            .with("reason", redacted(reason.as_ref()).to_json()?)?
            .with("parent_record_id", parent_record_id.map(|id| id.to_string()).to_json()?),
        // KNSH-055; `command` was redacted before it was published.
        EventData::CommandDeniedRepeatedly { command, cwd, until } => Object::new()
            .with("command", command.expose().as_str())?
            .with("cwd", path(cwd))?
            .with("until", until.to_string()),
        EventData::ProxyDenied {
            record_id,
            protocol,
            host,
            port,
            reason,
        } => proxy_denied(*record_id, *protocol, host.as_ref(), *port, reason),
        EventData::DecisionCancelled { request_id, reason } => Object::new()
            .with("request_id", request_id.map(|id| id.to_string()).to_json()?)?
            .with("reason", reason.as_str()),
        // KNSH-051; `command` was redacted before it was published. `command.started` also links a native-mode
        // line's command to its line (KNSH-108).
        EventData::CommandStarted {
            record_id,
            command,
            cwd,
            started_at,
            parent_record_id,
        } => Object::new()
            .with("record_id", record_id.to_string())?
            .with("command", command.expose().as_str())?
            .with("cwd", path(cwd))?
            .with("started_at", started_at.to_string())?
            .with("parent_record_id", parent_record_id.map(|id| id.to_string()).to_json()?),
        EventData::CommandLongRunning {
            record_id,
            command,
            cwd,
            started_at,
        } => Object::new()
            .with("record_id", record_id.to_string())?
            .with("command", command.expose().as_str())?
            .with("cwd", path(cwd))?
            .with("started_at", started_at.to_string()),
        // KNSH-092 (FR-SEC-06): the secret's name and the line, never the value; `command` was redacted before it was
        // published.
        EventData::SecretInjected {
            record_id,
            name,
            command,
        } => Object::new()
            .with("record_id", record_id.to_string())?
            .with("name", name.as_str())?
            .with("command", command.expose().as_str()),
        // KNSH-053: the chunk's place; its bytes are added by `event_notification_with_bytes`, never inline here.
        EventData::CommandOutput {
            record_id,
            stream,
            offset,
            bytes,
        } => Object::new()
            .with("record_id", record_id.to_string())?
            .with("stream", stream.as_str())?
            .with("offset", crate::records::bytes(*offset))?
            .with(
                "size",
                crate::records::bytes(u64::try_from(bytes.expose().len()).unwrap_or(u64::MAX)),
            ),
        // KNSH-065 (FR-POL-42): a profile name is `[A-Za-z0-9._-]`, so it needs no redaction.
        EventData::PolicyInvalid { profile } => Object::new().with("profile", profile.as_str()),
        // KNSH-080 (FR-EVT-08): paths are shown like `cwd`, with U+FFFD for bytes that are not UTF-8.
        EventData::FileChanged { root, path: changed } => {
            Object::new().with("root", path(root))?.with("path", path(changed))
        }
        // KNSH-081 (FR-CKP-06): paths are shown like `cwd`; `omitted` counts the paths the event does not list.
        EventData::AgentEdit { root, paths, omitted } => {
            let listed = paths.iter().map(|changed| Value::String(path(changed))).collect();
            Object::new()
                .with("root", path(root))?
                .with("paths", Value::Array(listed))?
                .with("omitted", *omitted)
        }
        // KNSH-080 (FR-CKP-04, NFR-REL-04).
        EventData::CheckpointUncertain {
            root,
            record_id,
            reason,
        } => Object::new()
            .with("root", path(root))?
            .with("record_id", record_id.map(|id| id.to_string()).to_json()?)?
            .with("reason", reason.as_str()),
        // KNSH-082 (FR-CKP-11): roots are shown like `cwd`; `files_changed` is a count, like `exec.run`'s.
        EventData::CheckpointCreated {
            checkpoint_id,
            attribution,
            record_ids,
            roots,
            files_changed,
            uncertain,
        } => {
            let records = record_ids.iter().map(|id| Value::String(id.to_string())).collect();
            let roots = roots.iter().map(|root| Value::String(path(root))).collect();
            Object::new()
                .with("checkpoint_id", checkpoint_id.to_string())?
                .with("attribution", attribution.as_str())?
                .with("record_ids", Value::Array(records))?
                .with("roots", Value::Array(roots))?
                .with("files_changed", files_changed.to_json()?)?
                .with("uncertain", *uncertain)
        }
        // KNSH-084 (FR-CKP-25): shaped like `checkpoint.created`, with the operation and how many paths came back.
        EventData::CheckpointRestored {
            checkpoint_id,
            operation,
            record_ids,
            roots,
            files_restored,
            forced,
        } => {
            let records = record_ids.iter().map(|id| Value::String(id.to_string())).collect();
            let roots = roots.iter().map(|root| Value::String(path(root))).collect();
            Object::new()
                .with("checkpoint_id", checkpoint_id.to_string())?
                .with("operation", operation.as_str())?
                .with("record_ids", Value::Array(records))?
                .with("roots", Value::Array(roots))?
                .with("files_restored", files_restored.to_json()?)?
                .with("forced", *forced)
        }
    }
}

/// The `proxy.denied` payload (KNSH-060, FR-NET-09): `record_id` is null for the envelope's own connections, which
/// belong to the session alone; `host` was redacted before it was published.
fn proxy_denied(
    record_id: Option<knsh_core::RecordId>,
    protocol: Option<&str>,
    host: Option<&knsh_core::Redacted<String>>,
    port: Option<u16>,
    reason: &str,
) -> Result<Object, JsonError> {
    Object::new()
        .with("record_id", record_id.map(|id| id.to_string()).to_json()?)?
        .with("protocol", protocol.map(str::to_owned).to_json()?)?
        .with("host", redacted(host).to_json()?)?
        .with("port", port.to_json()?)?
        .with("reason", reason)
}

/// An optional text that was redacted before it was published, as it is emitted.
fn redacted(text: Option<&knsh_core::Redacted<String>>) -> Option<String> {
    text.map(|text| text.expose().clone())
}

/// A path need not be UTF-8; JSON strings must be. Bytes that are not valid UTF-8 show as U+FFFD, as in records.
fn path(path: &knsh_core::CanonicalPath) -> String {
    path.as_path().to_string_lossy().into_owned()
}

/// The error for a field whose value has the right JSON type but is not valid.
const fn out_of_range(field: &'static str) -> JsonError {
    JsonError::OutOfRange { field: Some(field) }
}

#[cfg(test)]
mod tests {
    use knsh_core::{AgentId, CanonicalPath, EventId, ProfileName, RecordId, Redacted, SessionState, Timestamp, Ulid};

    use super::*;
    use crate::envelope::{Message, encode};

    fn sid(n: u128) -> SessionId {
        SessionId::from_ulid(Ulid::from_u128(n))
    }

    fn params(text: &str) -> Result<EventsSubscribeParams, JsonError> {
        EventsSubscribeParams::from_json(&knsh_json::parse(text.as_bytes(), 4096).unwrap())
    }

    fn event(data: EventData, actor: Actor) -> Event {
        Event {
            id: EventId::from_ulid(Ulid::from_u128(7)),
            seq: 4182,
            ts: Timestamp::from_unix_micros(1_700_000_000_123_456).unwrap(),
            session_id: sid(1),
            actor,
            data,
        }
    }

    fn written(notification: Notification) -> String {
        encode(&Message::Notification(notification)).unwrap()
    }

    #[test]
    fn subscribe_params_are_strict() {
        assert_eq!(
            params("{}").unwrap(),
            EventsSubscribeParams {
                session_id: None,
                since_seq: None
            }
        );
        let id = sid(1).to_string();
        let both = params(&format!(r#"{{"session_id":"{id}","since_seq":0}}"#)).unwrap();
        assert_eq!(both.session_id, Some(sid(1)));
        assert_eq!(both.since_seq, Some(0));
        assert_eq!(
            params(r#"{"since_seq":3}"#),
            Err(JsonError::MissingField("session_id")),
            "since_seq means nothing without a session"
        );
        assert!(params(r#"{"session_id":"nope"}"#).is_err());
        assert!(params(&format!(r#"{{"session_id":"{id}","since_seq":-1}}"#)).is_err());
        assert!(params(&format!(r#"{{"session_id":"{id}","since_seq":1.5}}"#)).is_err());
        // Round trip.
        let back = EventsSubscribeParams::from_json(&both.to_json().unwrap()).unwrap();
        assert_eq!(back, both);
    }

    #[test]
    fn subscribe_result_round_trips() {
        let result = EventsSubscribeResult {
            subscription_id: SubscriptionId::new(3),
            oldest_seq: Some(6),
            latest_seq: Some(10),
            gap: true,
        };
        let text = knsh_json::write(&result.to_json().unwrap()).unwrap();
        assert_eq!(
            text,
            r#"{"subscription_id":3,"oldest_seq":6,"latest_seq":10,"gap":true}"#
        );
        assert_eq!(
            EventsSubscribeResult::from_json(&result.to_json().unwrap()).unwrap(),
            result
        );
    }

    #[test]
    fn unsubscribe_params_require_an_id() {
        let read = |text: &str| EventsUnsubscribeParams::from_json(&knsh_json::parse(text.as_bytes(), 4096).unwrap());
        assert_eq!(
            read(r#"{"subscription_id":4}"#).unwrap().subscription_id,
            SubscriptionId::new(4)
        );
        assert!(read("{}").is_err());
        assert!(read(r#"{"subscription_id":"4"}"#).is_err());
    }

    // specs/05-models/event.md: the envelope fields, with the event name as the notification method.
    #[test]
    fn event_notification_carries_the_envelope() {
        let actor = Actor::Agent(AgentId::new("claude-code").unwrap());
        let text = written(
            event_notification(
                SubscriptionId::new(2),
                &event(
                    EventData::SessionStateChanged {
                        from: SessionState::Active,
                        to: SessionState::Paused,
                    },
                    actor,
                ),
            )
            .unwrap(),
        );
        let id = EventId::from_ulid(Ulid::from_u128(7));
        let session = sid(1);
        assert_eq!(
            text,
            format!(
                r#"{{"jsonrpc":"2.0","method":"session.state_changed","params":{{"event":"session.state_changed","id":"{id}","seq":4182,"ts":"2023-11-14T22:13:20.123456Z","session_id":"{session}","actor":{{"kind":"agent","agent_id":"claude-code"}},"data":{{"from":"active","to":"paused"}},"subscription_id":2}}}}"#
            )
        );
    }

    // FR-EVT-07: the redacted command is what is emitted; the human actor has no agent_id.
    #[test]
    fn command_finished_and_cwd_payloads() {
        let at = Timestamp::from_unix_micros(0).unwrap();
        let record = RecordId::from_ulid(Ulid::from_u128(9));
        let finished = written(
            event_notification(
                SubscriptionId::new(1),
                &event(
                    EventData::CommandFinished {
                        record_id: record,
                        command: Redacted::new("curl -H 'Authorization: «redacted»'".to_owned()),
                        cwd: CanonicalPath::new("/Users/me/app").unwrap(),
                        started_at: at,
                        ended_at: at,
                        exit_code: None,
                        parent_record_id: None,
                    },
                    Actor::Human,
                ),
            )
            .unwrap(),
        );
        assert!(finished.contains(r#""actor":{"kind":"human"}"#), "{finished}");
        assert!(
            finished.contains(&format!(
                r#""data":{{"record_id":"{record}","command":"curl -H 'Authorization: «redacted»'","cwd":"/Users/me/app","started_at":"1970-01-01T00:00:00.000000Z","ended_at":"1970-01-01T00:00:00.000000Z","exit_code":null,"parent_record_id":null}}"#
            )),
            "{finished}"
        );
        let cwd = written(
            event_notification(
                SubscriptionId::new(1),
                &event(
                    EventData::CwdChanged {
                        cwd: CanonicalPath::new("/tmp").unwrap(),
                    },
                    Actor::Human,
                ),
            )
            .unwrap(),
        );
        assert!(
            cwd.contains(r#""method":"cwd.changed""#) && cwd.contains(r#""data":{"cwd":"/tmp"}"#),
            "{cwd}"
        );
        let started = written(
            event_notification(
                SubscriptionId::new(1),
                &event(
                    EventData::SessionStarted {
                        profile: ProfileName::new("default").unwrap(),
                        envelope: false,
                        recording: true,
                        parent_session_id: None,
                    },
                    Actor::Human,
                ),
            )
            .unwrap(),
        );
        assert!(
            started
                .contains(r#""data":{"profile":"default","envelope":false,"recording":true,"parent_session_id":null}"#),
            "{started}"
        );
    }

    // FR-HOOK-02 (KNSH-062): a hook reads the `command.proposed` payload, with the session and actor, on stdin.
    #[test]
    fn hook_input_is_the_proposed_event() {
        let actor = Actor::Agent(AgentId::new("claude-code").unwrap());
        let command = Redacted::new("rm -rf \"build\"".to_owned());
        let from = Redacted::new("rm -rf /".to_owned());
        let cwd = CanonicalPath::new("/Users/me/app").unwrap();
        let line = "rm -rf build";
        let classification = knsh_bash::classify(
            &knsh_bash::parse_line(line),
            line,
            &NoResolver,
            &knsh_bash::Interpreters::defaults(),
        );
        let proposal = Proposal {
            session_id: SessionId::from_ulid(Ulid::from_u128(1)),
            actor: &actor,
            command: &command,
            cwd: &cwd,
            rewritten_from: Some(&from),
            classification: &classification,
            redactor: &knsh_core::Redactor::default(),
        };
        let text = String::from_utf8(hook_input(&proposal).unwrap()).unwrap();
        assert_eq!(
            text,
            format!(
                r#"{{"event":"command.proposed","session_id":"{}","actor":{{"kind":"agent","agent_id":"claude-code"}},"data":{{"command":"rm -rf \"build\"","cwd":"/Users/me/app","rewritten_from":"rm -rf /"}}}}"#,
                SessionId::from_ulid(Ulid::from_u128(1))
            )
        );
    }

    /// Resolves nothing: the hook input does not depend on the classification.
    struct NoResolver;

    impl knsh_bash::Resolver for NoResolver {
        fn resolve(&self, _name: &str, _lookup: knsh_bash::Lookup) -> knsh_bash::Program {
            knsh_bash::Program::NotFound
        }

        fn source_file(&self, _path: &str) -> knsh_bash::SourceFile {
            knsh_bash::SourceFile::Unresolved
        }
    }

    // KNSH-050 (FR-LC-07, FR-LC-32, FR-LC-41): the lifecycle payloads of `specs/05-models/event.md`.
    #[test]
    fn lifecycle_payloads() {
        let agent = || Actor::Agent(AgentId::new("claude-code").unwrap());
        let cwd = || CanonicalPath::new("/Users/me/app").unwrap();
        let data =
            |data: EventData| written(event_notification(SubscriptionId::new(1), &event(data, agent())).unwrap());
        let proposed = data(EventData::CommandProposed {
            command: Redacted::new("git status".to_owned()),
            cwd: cwd(),
            rewritten_from: Some(Redacted::new("git push --force".to_owned())),
        });
        assert!(proposed.contains(r#""method":"command.proposed""#), "{proposed}");
        assert!(
            proposed.contains(
                r#""data":{"command":"git status","cwd":"/Users/me/app","rewritten_from":"git push --force"}"#
            ),
            "{proposed}"
        );
        let record = RecordId::from_ulid(Ulid::from_u128(9));
        let denied = data(EventData::CommandDenied {
            record_id: Some(record),
            command: Redacted::new("rm -rf build".to_owned()),
            cwd: cwd(),
            source: knsh_core::DecisionSource::Rule,
            rule_id: Some(Redacted::new("exec.deny[0]".to_owned())),
            reason: None,
            parent_record_id: None,
        });
        assert!(
            denied.contains(&format!(
                r#""data":{{"record_id":"{record}","command":"rm -rf build","cwd":"/Users/me/app","source":"rule","rule_id":"exec.deny[0]","reason":null,"parent_record_id":null}}"#
            )),
            "{denied}"
        );
        // KNSH-055 (FR-HOOK-21).
        let until = Timestamp::from_unix_micros(1_700_000_600_000_000).unwrap();
        let repeated = data(EventData::CommandDeniedRepeatedly {
            command: Redacted::new("rm -rf build".to_owned()),
            cwd: cwd(),
            until,
        });
        assert!(
            repeated.contains(r#""method":"command.denied_repeatedly""#),
            "{repeated}"
        );
        assert!(
            repeated.contains(&format!(
                r#""data":{{"command":"rm -rf build","cwd":"/Users/me/app","until":"{until}"}}"#
            )),
            "{repeated}"
        );
        let cancelled = data(EventData::DecisionCancelled {
            request_id: None,
            reason: knsh_core::CancelReason::CallerGone,
        });
        assert!(
            cancelled.contains(r#""data":{"request_id":null,"reason":"caller_gone"}"#),
            "{cancelled}"
        );
        // KNSH-065 (FR-POL-42): the profile whose file failed its signature check.
        let invalid = data(EventData::PolicyInvalid {
            profile: knsh_core::ProfileName::new("web-app").unwrap(),
        });
        assert!(invalid.contains(r#""event":"policy.invalid""#), "{invalid}");
        assert!(invalid.contains(r#""data":{"profile":"web-app"}"#), "{invalid}");
        // KNSH-051 (FR-LC-17): `command.started` and `command.long_running` share one shape; `command.started` also
        // names the line record of a native-mode line's command (KNSH-108, FR-LC-54).
        let started_at = Timestamp::from_unix_micros(1_700_000_000_000_000).unwrap();
        let line = RecordId::from_ulid(Ulid::from_u128(0x0108));
        for (event, name, parent) in [
            (
                EventData::CommandStarted {
                    record_id: record,
                    command: Redacted::new("npm test".to_owned()),
                    cwd: cwd(),
                    started_at,
                    parent_record_id: Some(line),
                },
                "command.started",
                format!(r#","parent_record_id":"{line}""#),
            ),
            (
                EventData::CommandLongRunning {
                    record_id: record,
                    command: Redacted::new("npm test".to_owned()),
                    cwd: cwd(),
                    started_at,
                },
                "command.long_running",
                String::new(),
            ),
        ] {
            let text = data(event);
            assert!(text.contains(&format!(r#""method":"{name}""#)), "{text}");
            assert!(
                text.contains(&format!(
                    r#""data":{{"record_id":"{record}","command":"npm test","cwd":"/Users/me/app","started_at":"{started_at}"{parent}}}"#
                )),
                "{text}"
            );
        }
    }

    // KNSH-080 (FR-EVT-08, FR-CKP-04, NFR-REL-04): `file.changed` and `checkpoint.uncertain`.
    #[test]
    fn checkpoint_payloads() {
        let agent = || Actor::Agent(AgentId::new("claude-code").unwrap());
        let cwd = || CanonicalPath::new("/Users/me/app").unwrap();
        let data =
            |data: EventData| written(event_notification(SubscriptionId::new(1), &event(data, agent())).unwrap());
        let record = RecordId::from_ulid(Ulid::from_u128(9));
        let changed = data(EventData::FileChanged {
            root: cwd(),
            path: knsh_core::CanonicalPath::new("/Users/me/app/src/main.rs").unwrap(),
        });
        assert!(changed.contains(r#""event":"file.changed""#), "{changed}");
        assert!(
            changed.contains(r#""data":{"root":"/Users/me/app","path":"/Users/me/app/src/main.rs"}"#),
            "{changed}"
        );
        let uncertain = data(EventData::CheckpointUncertain {
            root: cwd(),
            record_id: Some(record),
            reason: knsh_core::UncertainReason::EventsDropped,
        });
        assert!(uncertain.contains(r#""event":"checkpoint.uncertain""#), "{uncertain}");
        assert!(
            uncertain.contains(&format!(
                r#""data":{{"root":"/Users/me/app","record_id":"{record}","reason":"events_dropped"}}"#
            )),
            "{uncertain}"
        );
        let gap = data(EventData::CheckpointUncertain {
            root: cwd(),
            record_id: None,
            reason: knsh_core::UncertainReason::RestartGap,
        });
        assert!(
            gap.contains(r#""data":{"root":"/Users/me/app","record_id":null,"reason":"restart_gap"}"#),
            "{gap}"
        );
    }

    // KNSH-081 (FR-CKP-06): `agent.edit` lists its root, its paths and how many more it does not list.
    #[test]
    fn agent_edit_payload() {
        let agent = || Actor::Agent(AgentId::new("claude-code").unwrap());
        let edit = written(
            event_notification(
                SubscriptionId::new(1),
                &event(
                    EventData::AgentEdit {
                        root: CanonicalPath::new("/Users/me/app").unwrap(),
                        paths: vec![
                            CanonicalPath::new("/Users/me/app/README").unwrap(),
                            CanonicalPath::new("/Users/me/app/src/main.rs").unwrap(),
                        ],
                        omitted: 3,
                    },
                    agent(),
                ),
            )
            .unwrap(),
        );
        assert!(edit.contains(r#""event":"agent.edit""#), "{edit}");
        assert!(
            edit.contains(
                r#""data":{"root":"/Users/me/app","paths":["/Users/me/app/README","/Users/me/app/src/main.rs"],"omitted":3}"#
            ),
            "{edit}"
        );
    }

    // KNSH-082 (FR-CKP-11): `checkpoint.created` names the checkpoint, its attribution, lines, roots and size.
    #[test]
    fn checkpoint_created_payload() {
        let record = RecordId::from_ulid(Ulid::from_u128(5));
        let checkpoint = knsh_core::CheckpointId::from_ulid(Ulid::from_u128(6));
        let created = written(
            event_notification(
                SubscriptionId::new(1),
                &event(
                    EventData::CheckpointCreated {
                        checkpoint_id: checkpoint,
                        attribution: knsh_core::Attribution::Command,
                        record_ids: vec![record],
                        roots: vec![CanonicalPath::new("/Users/me/app").unwrap()],
                        files_changed: 2,
                        uncertain: false,
                    },
                    Actor::Agent(AgentId::new("claude-code").unwrap()),
                ),
            )
            .unwrap(),
        );
        assert!(created.contains(r#""event":"checkpoint.created""#), "{created}");
        assert!(
            created.contains(&format!(
                r#""data":{{"checkpoint_id":"{checkpoint}","attribution":"command","record_ids":["{record}"],"roots":["/Users/me/app"],"files_changed":2,"uncertain":false}}"#
            )),
            "{created}"
        );
    }

    // KNSH-084 (FR-CKP-25): `checkpoint.restored` names the change, the operation and how many paths came back.
    #[test]
    fn checkpoint_restored_payload() {
        let checkpoint = knsh_core::CheckpointId::from_ulid(Ulid::from_u128(7));
        let record = RecordId::from_ulid(Ulid::from_u128(8));
        let restored = written(
            event_notification(
                SubscriptionId::new(1),
                &event(
                    EventData::CheckpointRestored {
                        checkpoint_id: checkpoint,
                        operation: knsh_core::RestoreOperation::Undo,
                        record_ids: vec![record],
                        roots: vec![CanonicalPath::new("/Users/me/app").unwrap()],
                        files_restored: 3,
                        forced: false,
                    },
                    Actor::Agent(AgentId::new("claude-code").unwrap()),
                ),
            )
            .unwrap(),
        );
        assert!(restored.contains(r#""event":"checkpoint.restored""#), "{restored}");
        assert!(
            restored.contains(&format!(
                r#""data":{{"checkpoint_id":"{checkpoint}","operation":"undo","record_ids":["{record}"],"roots":["/Users/me/app"],"files_restored":3,"forced":false}}"#
            )),
            "{restored}"
        );
    }

    // KNSH-060 (FR-NET-09): `proxy.denied` names the record for a line's refusal and none for the envelope's.
    #[test]
    fn proxy_denied_payload() {
        let record = RecordId::from_ulid(Ulid::from_u128(5));
        let agent = || Actor::Agent(AgentId::new("claude-code").unwrap());
        let data =
            |data: EventData| written(event_notification(SubscriptionId::new(1), &event(data, agent())).unwrap());
        let proxy_denied = data(EventData::ProxyDenied {
            record_id: Some(record),
            protocol: Some("socks5"),
            host: Some(Redacted::new("github.com".to_owned())),
            port: Some(443),
            reason: "approval_required",
        });
        assert!(proxy_denied.contains(r#""method":"proxy.denied""#), "{proxy_denied}");
        assert!(
            proxy_denied.contains(&format!(
                r#""data":{{"record_id":"{record}","protocol":"socks5","host":"github.com","port":443,"reason":"approval_required"}}"#
            )),
            "{proxy_denied}"
        );
        let envelope_denied = data(EventData::ProxyDenied {
            record_id: None,
            protocol: None,
            host: None,
            port: None,
            reason: "malformed",
        });
        assert!(
            envelope_denied
                .contains(r#""data":{"record_id":null,"protocol":null,"host":null,"port":null,"reason":"malformed"}"#),
            "{envelope_denied}"
        );
    }

    // KNSH-047 (FR-SBX-08): `sandbox.violation` carries the violation's own object.
    #[test]
    fn sandbox_violation_payload() {
        let session = sid(1);
        let record: RecordId = RecordId::from_ulid(Ulid::from_u128(2));
        let tag: knsh_core::DenialTag = format!("knsh:{session}:{record}:fixed.engine").parse().unwrap();
        let violation = knsh_core::SandboxViolation {
            at: Timestamp::UNIX_EPOCH,
            report: knsh_core::DenialReport {
                tag,
                process: Redacted::new(String::from("cat")),
                pid: 71_295,
                operation: String::from("file-read-data"),
                argument: Some(Redacted::new(String::from("/private/etc/hosts"))),
                count: 9,
            },
        };
        let text = written(
            event_notification(
                SubscriptionId::new(1),
                &event(EventData::SandboxViolation(Box::new(violation)), Actor::Human),
            )
            .unwrap(),
        );
        assert!(text.contains(r#""method":"sandbox.violation""#), "{text}");
        assert!(
            text.contains(&format!(
                r#""data":{{"session_id":"{session}","record_id":"{record}","rule":"fixed.engine","operation":"file-read-data","argument":"/private/etc/hosts","process":"cat","pid":71295,"count":9,"at":"1970-01-01T00:00:00.000000Z"}}"#
            )),
            "{text}"
        );
    }

    #[test]
    fn lost_notification_names_the_range() {
        let text = written(
            lost_notification(
                SubscriptionId::new(5),
                &Lost {
                    session_id: sid(1),
                    from_seq: 2,
                    to_seq: 16,
                },
            )
            .unwrap(),
        );
        let session = sid(1);
        assert_eq!(
            text,
            format!(
                r#"{{"jsonrpc":"2.0","method":"events.lost","params":{{"subscription_id":5,"session_id":"{session}","from_seq":2,"to_seq":16}}}}"#
            )
        );
    }

    // FR-AUTH-02, KNSH-068: engine events have no session and no actor, and their lost ranges name no session.
    #[test]
    fn engine_events_have_null_session_and_actor() {
        use knsh_core::{EventId, Timestamp, Ulid};

        let event = EngineEvent {
            id: EventId::from_ulid(Ulid::from_u128(9)),
            seq: 3,
            ts: Timestamp::from_unix_micros(0).unwrap(),
            data: EngineEventData::AuthorityConnected,
        };
        let id = event.id;
        assert_eq!(
            written(engine_event_notification(SubscriptionId::new(2), &event).unwrap()),
            format!(
                r#"{{"jsonrpc":"2.0","method":"authority.connected","params":{{"event":"authority.connected","id":"{id}","seq":3,"ts":"1970-01-01T00:00:00.000000Z","session_id":null,"actor":null,"data":{{}},"subscription_id":2}}}}"#
            )
        );
        assert_eq!(
            written(engine_lost_notification(SubscriptionId::new(2), &EngineLost { from_seq: 1, to_seq: 4 }).unwrap()),
            r#"{"jsonrpc":"2.0","method":"events.lost","params":{"subscription_id":2,"session_id":null,"from_seq":1,"to_seq":4}}"#
        );

        // FR-POL-53 (KNSH-071): `policy.updated` names the pushed profile and when it expires.
        let updated = EngineEvent {
            data: EngineEventData::PolicyUpdated {
                profile: knsh_core::ProfileName::new("web-app").unwrap(),
                expires_at: Timestamp::from_unix_micros(60_000_000).unwrap(),
            },
            ..event
        };
        assert!(
            written(engine_event_notification(SubscriptionId::new(2), &updated).unwrap())
                .contains(r#""event":"policy.updated","id":"#)
        );
        assert!(
            written(engine_event_notification(SubscriptionId::new(2), &updated).unwrap())
                .contains(r#""data":{"profile":"web-app","expires_at":"1970-01-01T00:01:00.000000Z"}"#)
        );
    }

    // FR-LC-18, KNSH-053: `command.output` names its record, stream, offset and size; the bytes are announced as a
    // binary stream, or inlined as base64 for a client without binary frames, never as JSON text.
    #[test]
    fn command_output_announces_its_bytes() {
        let output = event(
            EventData::CommandOutput {
                record_id: RecordId::from_ulid(Ulid::from_u128(9)),
                stream: knsh_core::OutputStream::Stderr,
                offset: 8192,
                bytes: Redacted::new(b"oops\n".to_vec()),
            },
            Actor::Agent(AgentId::new("claude-code").unwrap()),
        );
        let subscription = SubscriptionId::new(3);
        let stream = knsh_json::StreamId::new(7).unwrap();
        let framed = written(event_notification_with_bytes(subscription, &output, OutputData::Stream(stream)).unwrap());
        assert!(framed.contains(r#""method":"command.output""#), "{framed}");
        assert!(
            framed.contains(
                r#""data":{"record_id":"00000000000000000000000009","stream":"stderr","offset":"8192","size":"5","data":{"stream_id":7,"size":"5","content_type":"application/octet-stream"}}"#
            ),
            "{framed}"
        );
        assert!(!framed.contains("oops"), "{framed}");
        let inline =
            written(event_notification_with_bytes(subscription, &output, OutputData::Base64(b"oops\n")).unwrap());
        assert!(inline.contains(r#""data_base64":"b29wcwo=""#), "{inline}");
        // An event without bytes cannot be sent this way.
        let ended = event(EventData::SessionEnded, Actor::Human);
        assert!(event_notification_with_bytes(subscription, &ended, OutputData::Stream(stream)).is_err());
    }
}
