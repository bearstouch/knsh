//! `events.subscribe` and `events.unsubscribe`: parameters, results and the notifications that carry events
//! (`specs/06-api/user-socket.md#events`, `specs/05-models/event.md`, KNSH-018).
//!
//! Events reach a subscriber as JSON-RPC notifications whose `method` is the event name (for example
//! `session.started`) and whose `params` are the event envelope plus the `subscription_id` it was delivered for.
//! Events a subscriber will never receive, because it fell behind its queue (FR-EVT-04), are announced by one
//! [`EVENTS_LOST`] notification per session and range.
//!
//! `seq` values are JSON integers: they count events of one session and stay far below 2^53.

use knsh_core::{Actor, Event, EventData, Lost, SessionId, Subscribed, SubscriptionId};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::envelope::Notification;
use crate::error::ProtoError;
use crate::method::MethodName;

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
    Object::new()
        .with("event", event.name())?
        .with("id", event.id.to_string())?
        .with("seq", event.seq.to_json()?)?
        .with("ts", event.ts.to_string())?
        .with("session_id", event.session_id.to_string())?
        .with("actor", actor(&event.actor)?)?
        .with("data", data(&event.data)?)
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

/// `{kind, agent_id?}`, as in records.
fn actor(actor: &Actor) -> Result<Object, JsonError> {
    let object = Object::new().with("kind", actor.kind().as_str())?;
    match actor.agent_id() {
        Some(agent_id) => object.with("agent_id", agent_id.as_str()),
        None => Ok(object),
    }
}

/// The `data` member of each phase 1 event (`specs/05-models/event.md#phase-1-payloads`).
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
        } => Object::new()
            .with("record_id", record_id.to_string())?
            // Redacted before it was published (FR-EVT-07); this is where it is emitted.
            .with("command", command.expose().as_str())?
            .with("cwd", path(cwd))?
            .with("started_at", started_at.to_string())?
            .with("ended_at", ended_at.to_string())?
            .with("exit_code", exit_code.to_json()?),
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
        } => Object::new()
            .with("record_id", record_id.map(|id| id.to_string()).to_json()?)?
            .with("command", command.expose().as_str())?
            .with("cwd", path(cwd))?
            .with("source", source.code())?
            .with("rule_id", redacted(rule_id.as_ref()).to_json()?)?
            .with("reason", redacted(reason.as_ref()).to_json()?),
        EventData::DecisionCancelled { request_id, reason } => Object::new()
            .with("request_id", request_id.map(|id| id.to_string()).to_json()?)?
            .with("reason", reason.as_str()),
    }
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
                    },
                    Actor::Human,
                ),
            )
            .unwrap(),
        );
        assert!(finished.contains(r#""actor":{"kind":"human"}"#), "{finished}");
        assert!(
            finished.contains(&format!(
                r#""data":{{"record_id":"{record}","command":"curl -H 'Authorization: «redacted»'","cwd":"/Users/me/app","started_at":"1970-01-01T00:00:00.000000Z","ended_at":"1970-01-01T00:00:00.000000Z","exit_code":null}}"#
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
        });
        assert!(
            denied.contains(&format!(
                r#""data":{{"record_id":"{record}","command":"rm -rf build","cwd":"/Users/me/app","source":"rule","rule_id":"exec.deny[0]","reason":null}}"#
            )),
            "{denied}"
        );
        let cancelled = data(EventData::DecisionCancelled {
            request_id: None,
            reason: knsh_core::CancelReason::CallerGone,
        });
        assert!(
            cancelled.contains(r#""data":{"request_id":null,"reason":"caller_gone"}"#),
            "{cancelled}"
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
}
