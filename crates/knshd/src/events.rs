//! The event bus as `knshd` runs it, and `events.subscribe` / `events.unsubscribe` (KNSH-018).
//!
//! [`EventHub`] wraps the pure [`EventBus`] of `knsh-core` in a lock, gives each event its ID and time from the
//! injected clock and random source, and wakes the connections whose subscriptions received it. Each connection has
//! one [`Subscriber`]: the subscriptions it made and the [`Signal`] its notification pump waits on
//! (`connection.rs`). Publishing only appends to bounded queues and raises signals; it never waits for a subscriber
//! or for any I/O (FR-EVT-04).
//!
//! # Scope
//!
//! - `user.sock`: [`EventScope::All`], or one session with `session_id` (FR-EVT-01).
//! - `agent.sock`: only the session the connection was bound to at `hello` (KNSH-048). Without `session_id` the
//!   subscription is that session's; naming any other session is `-32003`. A connection whose session has ended is
//!   refused with `-32009`.
//!
//! # Lock order
//!
//! A connection's writer, then its [`Subscriber`] (`owned`), then the hub (`state`), then a [`Signal`]. Publishing
//! takes only the hub lock and then signals. No lock is held across I/O except the writer, which belongs to one
//! connection.
//!
//! # Errors
//!
//! Malformed parameters, a `since_seq` without a session or newer than the session's latest event, an unknown
//! subscription and a connection already holding [`MAX_SUBSCRIPTIONS_PER_CONNECTION`] subscriptions are `-32602`. A
//! session without buffered events (never started, or ended long ago) is `-32006` with `data.session_id`.
//!
//! Specification: `specs/06-api/user-socket.md#events`, `specs/05-models/event.md`,
//! `specs/03-functional-requirements/events.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use knsh_core::{
    Actor, CoreError, Delivery, EngineEventData, EventBus, EventData, EventId, EventScope, Session, SessionId,
    SessionState, StateChanged, Subscribed, SubscriptionId, Ulid,
};
use knsh_json::{Object, ToJson, Value};
use knsh_platform::{Clock, PlatformError, Random};
use knsh_proto::{ErrorCode, EventsSubscribeParams, EventsSubscribeResult, EventsUnsubscribeParams, RpcError};

use crate::dispatch::{Answer, Call, Endpoint, Handler, Handlers, Reply};

/// The most subscriptions one connection may hold at once. Each can queue up to 10,000 events, so the bound keeps
/// one client from pinning an unbounded amount of memory.
pub(crate) const MAX_SUBSCRIPTIONS_PER_CONNECTION: usize = 16;

/// Takes the lock even if a thread panicked while holding it: every update under these locks is a single map or
/// queue operation that a panic cannot leave half done.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A wake-up flag one notification pump waits on.
#[derive(Debug, Default)]
pub(crate) struct Signal {
    state: Mutex<SignalState>,
    changed: Condvar,
}

/// What a [`Signal`] has to say, under its lock.
#[derive(Debug, Default)]
struct SignalState {
    /// Something may be waiting to be taken.
    pending: bool,
    /// The connection is ending: the pump stops.
    closed: bool,
}

impl Signal {
    /// Says that something may be waiting.
    fn notify(&self) {
        lock(&self.state).pending = true;
        self.changed.notify_all();
    }

    /// Stops the pump.
    fn close(&self) {
        lock(&self.state).closed = true;
        self.changed.notify_all();
    }

    /// Waits until something may be waiting (`true`, and the flag is cleared) or the signal is closed (`false`).
    pub(crate) fn wait(&self) -> bool {
        let mut state = lock(&self.state);
        loop {
            if state.closed {
                return false;
            }
            if state.pending {
                state.pending = false;
                return true;
            }
            state = self.changed.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// Why an event could not be published. Carries no event content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishError {
    /// The bus refused the event (unknown or ended session, wrong actor, duplicate start).
    Bus(CoreError),
    /// The clock or the random source failed, so the event has no ID or time.
    Platform(PlatformError),
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bus(error) => write!(f, "event refused: {error}"),
            Self::Platform(error) => write!(f, "cannot stamp event: {error}"),
        }
    }
}

impl std::error::Error for PublishError {}

/// The hub's state, under one lock.
struct HubState {
    /// Numbering, buffers and per-subscription queues.
    bus: EventBus,
    /// The pump to wake for each subscription.
    signals: BTreeMap<SubscriptionId, Arc<Signal>>,
}

impl HubState {
    /// Wakes the pump of every subscription in `delivered_to`.
    fn wake(&self, delivered_to: &[SubscriptionId]) {
        for subscription in delivered_to {
            if let Some(signal) = self.signals.get(subscription) {
                signal.notify();
            }
        }
    }
}

/// The engine's event bus: one per `knshd`, shared by publishers and every connection.
pub(crate) struct EventHub {
    state: Mutex<HubState>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
}

impl EventHub {
    /// A hub over `bus`, stamping events from `clock` and `random`.
    pub(crate) fn new(bus: EventBus, clock: Arc<dyn Clock>, random: Arc<dyn Random>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(HubState {
                bus,
                signals: BTreeMap::new(),
            }),
            clock,
            random,
        })
    }

    /// Publishes one event of `session_id` and wakes every subscription that received it. Never waits for a
    /// subscriber (FR-EVT-04). The payload's text is already redacted: [`EventData`] accepts nothing else
    /// (FR-EVT-07).
    ///
    /// # Errors
    ///
    /// [`PublishError`] if the event cannot be stamped or the bus refuses it; nothing is delivered then.
    pub(crate) fn publish(&self, session_id: SessionId, actor: &Actor, data: EventData) -> Result<u64, PublishError> {
        let mut state = lock(&self.state);
        // Stamped under the lock, so stamps follow `seq` order unless the wall clock itself steps back.
        let (id, ts) = self.stamp()?;
        let published = state
            .bus
            .publish(session_id, actor, data, id, ts)
            .map_err(PublishError::Bus)?;
        state.wake(&published.delivered_to);
        Ok(published.event.seq)
    }

    /// Publishes one engine event (`authority.connected`, `authority.disconnected`, KNSH-068) to every subscription
    /// to all sessions, and wakes them. Never waits for a subscriber (FR-EVT-04).
    ///
    /// # Errors
    ///
    /// [`PublishError::Platform`] if the event cannot be stamped; nothing is delivered then.
    pub(crate) fn publish_engine(&self, data: EngineEventData) -> Result<u64, PublishError> {
        let mut state = lock(&self.state);
        let (id, ts) = self.stamp()?;
        let published = state.bus.publish_engine(data, id, ts);
        state.wake(&published.delivered_to);
        Ok(published.event.seq)
    }

    /// A new event's ID and time, from the injected clock and random source.
    fn stamp(&self) -> Result<(EventId, knsh_core::Timestamp), PublishError> {
        let ts = self.clock.now().map_err(PublishError::Platform)?;
        let mut random = [0; 10];
        self.random.fill(&mut random).map_err(PublishError::Platform)?;
        let id = Ulid::new(ts.as_unix_millis(), random)
            .map(EventId::from_ulid)
            .map_err(PublishError::Bus)?;
        Ok((id, ts))
    }

    /// Publishes `data` for `session_id` as its own actor, if the session is live. For publishers that know only
    /// the session, such as the sandbox violation reader (KNSH-047), which learns it from a denial's tag.
    ///
    /// # Errors
    ///
    /// As [`EventHub::publish`]; [`PublishError::Bus`] with [`CoreError::SessionNotFoundOrEnded`] if the session
    /// never started or has ended.
    pub(crate) fn publish_for_session(&self, session_id: SessionId, data: EventData) -> Result<u64, PublishError> {
        // Read under the same lock `publish` takes, then released: the actor of a live session never changes
        // (FR-SES-01), so it is still right when the event is numbered.
        let actor = lock(&self.state)
            .bus
            .session_actor(session_id)
            .cloned()
            .ok_or(PublishError::Bus(CoreError::SessionNotFoundOrEnded))?;
        self.publish(session_id, &actor, data)
    }

    /// Publishes `session.started` for a session just created in the registry.
    ///
    /// # Errors
    ///
    /// As [`EventHub::publish`].
    pub(crate) fn session_started(&self, session: &Session) -> Result<u64, PublishError> {
        self.publish(session.session_id(), session.actor(), EventData::started(session))
    }

    /// Publishes `session.state_changed` for a registry transition (FR-SES-14) and, when the session reached
    /// `ended`, `session.ended` right after it.
    ///
    /// # Errors
    ///
    /// As [`EventHub::publish`]; `session.ended` is not published if `session.state_changed` failed.
    pub(crate) fn state_changed(&self, change: &StateChanged) -> Result<u64, PublishError> {
        let seq = self.publish(change.session_id, &change.actor, EventData::state_changed(change))?;
        match change.to {
            SessionState::Ended => self.publish(change.session_id, &change.actor, EventData::SessionEnded),
            SessionState::Active | SessionState::Paused | SessionState::HumanControl => Ok(seq),
        }
    }

    /// The number of live subscriptions, over every connection.
    #[cfg(test)]
    pub(crate) fn subscription_count(&self) -> usize {
        lock(&self.state).bus.subscription_count()
    }

    /// The `events.subscribe` and `events.unsubscribe` handlers.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let subscribe = Arc::clone(self);
        let subscribe: Handler = Arc::new(move |call: &Call<'_>| subscribe.subscribe(call));
        let unsubscribe: Handler = Arc::new(|call: &Call<'_>| Self::unsubscribe(call));
        [("events.subscribe", subscribe), ("events.unsubscribe", unsubscribe)]
            .into_iter()
            .collect()
    }

    /// `events.subscribe`: registers a subscription for the calling connection and answers its ID. The buffered
    /// events after `since_seq` are queued in the same step, so they reach the client right after this answer.
    fn subscribe(self: &Arc<Self>, call: &Call<'_>) -> Reply {
        let params: EventsSubscribeParams = call.request.params().map_err(|error| RpcError::from(&error))?;
        let scope = scope_of(call, params.session_id)?;
        let subscribed = call
            .subscriber
            .subscribe(self, scope, params.since_seq)
            .map_err(|error| subscribe_error(error, params.session_id))?;
        let result = EventsSubscribeResult::from(subscribed)
            .to_json()
            .map_err(|_| RpcError::new(ErrorCode::InternalError))?;
        Ok(Answer::from(result))
    }

    /// `events.unsubscribe`: ends one of the calling connection's subscriptions. Nothing more is sent for it after
    /// this answer. The connection's [`Subscriber`] knows the hub, so no hub is needed here.
    fn unsubscribe(call: &Call<'_>) -> Reply {
        // agent.sock: only while the connection's session is live. Its subscriptions are its own either way.
        if call.endpoint == Endpoint::Agent {
            call.binding.agent_session()?;
        }
        let params: EventsUnsubscribeParams = call.request.params().map_err(|error| RpcError::from(&error))?;
        // Only the connection's own subscriptions: an ID made elsewhere is as unknown as one never made.
        if !call.subscriber.unsubscribe(params.subscription_id) {
            return Err(RpcError::new(ErrorCode::InvalidParams));
        }
        Ok(Answer::from(Value::Object(Object::new())))
    }

    /// Registers a subscription and the signal that wakes its pump. Wakes the pump at once if replayed events are
    /// already waiting.
    fn register(
        &self,
        scope: EventScope,
        since_seq: Option<u64>,
        signal: &Arc<Signal>,
    ) -> Result<Subscribed, CoreError> {
        let mut state = lock(&self.state);
        let subscribed = state.bus.subscribe(scope, since_seq)?;
        state.signals.insert(subscribed.id, Arc::clone(signal));
        if state.bus.has_pending(subscribed.id) {
            signal.notify();
        }
        Ok(subscribed)
    }

    /// Ends subscriptions; queued events are dropped.
    fn remove(&self, ids: impl IntoIterator<Item = SubscriptionId>) {
        let mut state = lock(&self.state);
        for id in ids {
            state.bus.unsubscribe(id);
            state.signals.remove(&id);
        }
    }

    /// Takes up to `max` deliveries across `ids`, each subscription in turn, keeping each one's order.
    fn take(&self, ids: &BTreeSet<SubscriptionId>, max: usize) -> Vec<(SubscriptionId, Delivery)> {
        let mut state = lock(&self.state);
        let mut taken = Vec::new();
        for &id in ids {
            let left = max.saturating_sub(taken.len());
            if left == 0 {
                // More is waiting than this batch takes: look again without waiting for a new signal.
                if let Some(signal) = state.signals.get(&id) {
                    signal.notify();
                }
                break;
            }
            if let Some(deliveries) = state.bus.take(id, left) {
                taken.extend(deliveries.into_iter().map(|delivery| (id, delivery)));
            }
            if state.bus.has_pending(id)
                && let Some(signal) = state.signals.get(&id)
            {
                signal.notify();
            }
        }
        taken
    }
}

/// The events a caller may see: every session (or the one it names) on `user.sock`; on `agent.sock` only the session
/// the connection was bound to, whether or not it is named (KNSH-048).
fn scope_of(call: &Call<'_>, asked: Option<SessionId>) -> Result<EventScope, RpcError> {
    match call.endpoint {
        // The authority sees every session, as the user does (`specs/06-api/control-service.md`).
        Endpoint::User | Endpoint::Control => Ok(asked.map_or(EventScope::All, EventScope::Session)),
        Endpoint::Agent => {
            let own = call.binding.agent_session()?;
            match asked {
                Some(other) if other != own => Err(RpcError::new(ErrorCode::NotAllowed)),
                Some(_) | None => Ok(EventScope::Session(own)),
            }
        }
    }
}

/// Why a subscription was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubscribeError {
    /// The bus refused it.
    Bus(CoreError),
    /// The connection already holds [`MAX_SUBSCRIPTIONS_PER_CONNECTION`] subscriptions.
    TooMany,
    /// The connection is closing.
    Closed,
}

/// The JSON-RPC error for a refused subscription. `session_id` is the requested scope, named in `-32006`'s data.
fn subscribe_error(error: SubscribeError, session_id: Option<SessionId>) -> RpcError {
    match error {
        SubscribeError::Bus(CoreError::SessionNotFoundOrEnded) => {
            let error = RpcError::new(ErrorCode::SessionNotFound);
            match session_id.map(|id| Object::new().with("session_id", id.to_string())) {
                Some(Ok(data)) => error.with_data(Value::Object(data)),
                // A one-key object with a fixed key cannot fail to build; without data the code still says enough.
                Some(Err(_)) | None => error,
            }
        }
        SubscribeError::Bus(CoreError::InvalidSinceSeq) | SubscribeError::TooMany => {
            RpcError::new(ErrorCode::InvalidParams)
        }
        // `EventBus::subscribe` returns none of these; listed one by one (no catch-all, CLAUDE.md) so that a new
        // `CoreError` variant forces a decision here. A connection that is going away is the engine's problem too.
        SubscribeError::Bus(
            CoreError::UlidLength(_)
            | CoreError::UlidInvalidChar(_)
            | CoreError::UlidOverflow
            | CoreError::UlidTimeOutOfRange
            | CoreError::PathEmpty
            | CoreError::PathRelative
            | CoreError::PathDotComponent
            | CoreError::PathEmptyComponent
            | CoreError::PathNul
            | CoreError::TimestampOutOfRange
            | CoreError::InvalidTimestamp
            | CoreError::InvalidOutputStream
            | CoreError::InvalidDecision
            | CoreError::InvalidAgentId
            | CoreError::InvalidProfileName
            | CoreError::InvalidSecretName
            | CoreError::HumanRecording
            | CoreError::HumanProfile
            | CoreError::AgentIdRequired
            | CoreError::AgentIdForHuman
            | CoreError::EnvelopeForHuman
            | CoreError::InvalidTransition { .. }
            | CoreError::SessionExists
            | CoreError::ParentNotFoundOrEnded
            | CoreError::ProfileNotStricter
            | CoreError::HumanChildOfAgent
            | CoreError::EventActorMismatch
            | CoreError::InvalidGrantRule
            | CoreError::GrantExpired
            | CoreError::GrantExists
            | CoreError::GrantNotFound
            | CoreError::TooManyGrants
            | CoreError::InvalidDenialTag
            | CoreError::InvalidViolation
            | CoreError::InvalidArgv
            | CoreError::InvalidNetwork
            | CoreError::InvalidUnprotected
            | CoreError::InvalidFilesChanged,
        )
        | SubscribeError::Closed => RpcError::new(ErrorCode::InternalError),
    }
}

/// What one connection subscribed to.
#[derive(Default)]
struct Owned {
    /// The hub the subscriptions live in, from the first one on.
    hub: Option<Arc<EventHub>>,
    /// The live subscriptions, each also registered in the hub.
    ids: BTreeSet<SubscriptionId>,
    /// Set by [`Subscriber::close`]: no new subscription is accepted.
    closed: bool,
}

/// One connection's subscriptions and the signal its notification pump waits on.
///
/// Closing the connection must end all of them: [`Subscriber::close`] does, and `Drop` calls it again as a backstop.
#[derive(Default)]
pub(crate) struct Subscriber {
    signal: Arc<Signal>,
    owned: Mutex<Owned>,
}

impl Subscriber {
    /// A subscriber with no subscriptions.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Subscribes this connection on `hub`.
    pub(crate) fn subscribe(
        &self,
        hub: &Arc<EventHub>,
        scope: EventScope,
        since_seq: Option<u64>,
    ) -> Result<Subscribed, SubscribeError> {
        let mut owned = lock(&self.owned);
        if owned.closed {
            return Err(SubscribeError::Closed);
        }
        if owned.ids.len() >= MAX_SUBSCRIPTIONS_PER_CONNECTION {
            return Err(SubscribeError::TooMany);
        }
        let subscribed = hub
            .register(scope, since_seq, &self.signal)
            .map_err(SubscribeError::Bus)?;
        owned.ids.insert(subscribed.id);
        owned.hub.get_or_insert_with(|| Arc::clone(hub));
        Ok(subscribed)
    }

    /// Ends one of this connection's subscriptions. Returns `false` if it is not one of them.
    fn unsubscribe(&self, id: SubscriptionId) -> bool {
        let mut owned = lock(&self.owned);
        if !owned.ids.remove(&id) {
            return false;
        }
        if let Some(hub) = &owned.hub {
            hub.remove([id]);
        }
        true
    }

    /// Whether this connection holds a subscription, so it needs a notification pump.
    pub(crate) fn is_subscribed(&self) -> bool {
        !lock(&self.owned).ids.is_empty()
    }

    /// The signal the pump waits on.
    pub(crate) fn signal(&self) -> &Signal {
        &self.signal
    }

    /// Takes up to `max` deliveries across this connection's subscriptions.
    pub(crate) fn take(&self, max: usize) -> Vec<(SubscriptionId, Delivery)> {
        let owned = lock(&self.owned);
        match &owned.hub {
            Some(hub) => hub.take(&owned.ids, max),
            None => Vec::new(),
        }
    }

    /// Ends every subscription and stops the pump. Idempotent.
    pub(crate) fn close(&self) {
        let mut owned = lock(&self.owned);
        owned.closed = true;
        let ids = std::mem::take(&mut owned.ids);
        if let Some(hub) = &owned.hub {
            hub.remove(ids);
        }
        drop(owned);
        self.signal.close();
    }
}

impl Drop for Subscriber {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use knsh_core::{AgentId, BusLimits, ProfileName, SessionSpec, Timestamp, Transition};
    use knsh_json::Value;
    use knsh_platform::testing::{FakeClock, SeededRandom};
    use knsh_proto::{ByteTransport, MethodName, Request, RequestId};

    use super::*;

    /// A hub with a fake clock and seeded random source.
    pub(crate) fn hub() -> Arc<EventHub> {
        hub_with(BusLimits::default())
    }

    pub(crate) fn hub_with(limits: BusLimits) -> Arc<EventHub> {
        EventHub::new(
            EventBus::new(limits),
            Arc::new(FakeClock::new(
                Timestamp::from_unix_micros(1_700_000_000_000_000).unwrap(),
            )),
            Arc::new(SeededRandom::new(7)),
        )
    }

    pub(crate) fn sid(n: u128) -> SessionId {
        SessionId::from_ulid(Ulid::from_u128(n))
    }

    pub(crate) fn agent() -> Actor {
        Actor::Agent(AgentId::new("claude-code").unwrap())
    }

    /// Publishes `session.started` for session `n`.
    pub(crate) fn start(hub: &EventHub, n: u128) {
        hub.publish(
            sid(n),
            &agent(),
            EventData::SessionStarted {
                profile: ProfileName::new("default").unwrap(),
                envelope: true,
                recording: true,
                parent_session_id: None,
            },
        )
        .unwrap();
    }

    fn call(
        hub: &Arc<EventHub>,
        subscriber: &Subscriber,
        endpoint: Endpoint,
        method: &'static str,
        params: &str,
    ) -> Reply {
        let params = knsh_json::parse(params.as_bytes(), 4096).unwrap();
        let request = Request {
            id: RequestId::from(1u32),
            method: MethodName::new(method).unwrap(),
            params: params.as_object().cloned(),
        };
        hub.handlers()[method](&Call {
            endpoint,
            bytes: ByteTransport::BinaryFrames,
            stream: knsh_json::StreamId::new(1).unwrap(),
            request: &request,
            subscriber,
            binding: crate::dispatch::tests::binding(),
            descriptors: crate::dispatch::tests::no_descriptors(),
            caller: &knsh_core::StillWaiting,
            control: None,
        })
    }

    fn seqs(deliveries: &[(SubscriptionId, Delivery)]) -> Vec<u64> {
        deliveries
            .iter()
            .map(|(_, delivery)| match delivery {
                Delivery::Event(event) => event.seq,
                other => panic!("unexpected delivery {other:?}"),
            })
            .collect()
    }

    #[test]
    fn subscribe_answers_and_queues_the_resume() {
        let hub = hub();
        start(&hub, 1);
        for _ in 0..4 {
            hub.publish(sid(1), &agent(), EventData::SessionIdle).unwrap();
        }
        let subscriber = Subscriber::new();
        let answer = call(
            &hub,
            &subscriber,
            Endpoint::User,
            "events.subscribe",
            &format!(r#"{{"session_id":"{}","since_seq":2}}"#, sid(1)),
        )
        .unwrap();
        let text = knsh_json::write(&answer.result).unwrap();
        assert_eq!(
            text,
            r#"{"subscription_id":1,"oldest_seq":1,"latest_seq":5,"gap":false}"#
        );
        assert!(subscriber.signal().wait(), "replayed events wake the pump");
        assert_eq!(seqs(&subscriber.take(100)), vec![3, 4, 5]);
    }

    // -32006 for a session with no events, -32602 for a since_seq beyond the latest, -32003 on agent.sock.
    #[test]
    fn subscribe_errors() {
        let hub = hub();
        start(&hub, 1);
        let subscriber = Subscriber::new();
        let unknown = call(
            &hub,
            &subscriber,
            Endpoint::User,
            "events.subscribe",
            &format!(r#"{{"session_id":"{}"}}"#, sid(9)),
        )
        .unwrap_err();
        assert_eq!(unknown.code, ErrorCode::SessionNotFound);
        assert_eq!(
            unknown.data,
            Some(Value::Object(
                Object::new().with("session_id", sid(9).to_string()).unwrap()
            ))
        );
        let future = call(
            &hub,
            &subscriber,
            Endpoint::User,
            "events.subscribe",
            &format!(r#"{{"session_id":"{}","since_seq":5}}"#, sid(1)),
        )
        .unwrap_err();
        assert_eq!(future.code, ErrorCode::InvalidParams);
        let no_session = call(
            &hub,
            &subscriber,
            Endpoint::User,
            "events.subscribe",
            r#"{"since_seq":0}"#,
        )
        .unwrap_err();
        assert_eq!(no_session.code, ErrorCode::InvalidParams);
        for method in ["events.subscribe", "events.unsubscribe"] {
            let agent = call(&hub, &subscriber, Endpoint::Agent, method, r#"{"subscription_id":1}"#).unwrap_err();
            assert_eq!(agent.code, ErrorCode::NotAllowed, "{method}");
        }
        assert!(!subscriber.is_subscribed());
    }

    #[test]
    fn subscriptions_per_connection_are_bounded() {
        let hub = hub();
        let subscriber = Subscriber::new();
        for _ in 0..MAX_SUBSCRIPTIONS_PER_CONNECTION {
            call(&hub, &subscriber, Endpoint::User, "events.subscribe", "{}").unwrap();
        }
        let refused = call(&hub, &subscriber, Endpoint::User, "events.subscribe", "{}").unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidParams);
    }

    // Another connection's subscription is not this connection's to end.
    #[test]
    fn unsubscribe_only_ends_own_subscriptions() {
        let hub = hub();
        start(&hub, 1);
        let mine = Subscriber::new();
        let theirs = Subscriber::new();
        call(&hub, &theirs, Endpoint::User, "events.subscribe", "{}").unwrap();
        let refused = call(
            &hub,
            &mine,
            Endpoint::User,
            "events.unsubscribe",
            r#"{"subscription_id":1}"#,
        )
        .unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidParams);
        hub.publish(sid(1), &agent(), EventData::SessionIdle).unwrap();
        assert_eq!(seqs(&theirs.take(10)), vec![2], "still delivered");

        let answer = call(
            &hub,
            &theirs,
            Endpoint::User,
            "events.unsubscribe",
            r#"{"subscription_id":1}"#,
        )
        .unwrap();
        assert_eq!(answer.result, Value::Object(Object::new()));
        hub.publish(sid(1), &agent(), EventData::SessionIdle).unwrap();
        assert!(theirs.take(10).is_empty(), "nothing after unsubscribe");
    }

    // Resource cleanup: closing ends every subscription in the hub and stops the pump.
    #[test]
    fn close_ends_subscriptions() {
        let hub = hub();
        start(&hub, 1);
        let subscriber = Subscriber::new();
        call(&hub, &subscriber, Endpoint::User, "events.subscribe", "{}").unwrap();
        call(&hub, &subscriber, Endpoint::User, "events.subscribe", "{}").unwrap();
        assert_eq!(lock(&hub.state).bus.subscription_count(), 2);
        subscriber.close();
        assert_eq!(lock(&hub.state).bus.subscription_count(), 0);
        assert!(lock(&hub.state).signals.is_empty());
        assert!(!subscriber.signal().wait(), "the pump stops");
        let refused = call(&hub, &subscriber, Endpoint::User, "events.subscribe", "{}").unwrap_err();
        assert_eq!(refused.code, ErrorCode::InternalError);

        // Dropping without close does the same.
        let dropped = Subscriber::new();
        call(&hub, &dropped, Endpoint::User, "events.subscribe", "{}").unwrap();
        drop(dropped);
        assert_eq!(lock(&hub.state).bus.subscription_count(), 0);
    }

    // FR-SES-14: registry transitions become session.state_changed, and ending also publishes session.ended.
    #[test]
    fn registry_changes_become_events() {
        let hub = hub();
        let subscriber = Subscriber::new();
        call(&hub, &subscriber, Endpoint::User, "events.subscribe", "{}").unwrap();
        let mut registry = knsh_core::SessionRegistry::new();
        let session = registry
            .create(SessionSpec {
                session_id: sid(1),
                actor: agent(),
                profile: ProfileName::new("default").unwrap(),
                envelope: true,
                recording: None,
                parent_session_id: None,
            })
            .unwrap();
        hub.session_started(session).unwrap();
        hub.state_changed(&registry.transition(sid(1), Transition::Pause).unwrap())
            .unwrap();
        let ended_seq = hub
            .state_changed(&registry.transition(sid(1), Transition::End).unwrap())
            .unwrap();
        assert_eq!(ended_seq, 4);
        let names: Vec<_> = subscriber
            .take(10)
            .into_iter()
            .map(|(_, delivery)| match delivery {
                Delivery::Event(event) => (event.name(), event.seq),
                other => panic!("unexpected delivery {other:?}"),
            })
            .collect();
        assert_eq!(
            names,
            [
                ("session.started", 1),
                ("session.state_changed", 2),
                ("session.state_changed", 3),
                ("session.ended", 4)
            ]
        );
        assert_eq!(
            hub.publish(sid(1), &agent(), EventData::SessionIdle),
            Err(PublishError::Bus(CoreError::SessionNotFoundOrEnded))
        );
    }

    // A batch never takes more than asked, and leaves the signal raised when more is waiting.
    #[test]
    fn take_is_batched_and_rewakes() {
        let hub = hub();
        start(&hub, 1);
        let subscriber = Subscriber::new();
        call(&hub, &subscriber, Endpoint::User, "events.subscribe", "{}").unwrap();
        for _ in 0..5 {
            hub.publish(sid(1), &agent(), EventData::SessionIdle).unwrap();
        }
        assert!(subscriber.signal().wait());
        assert_eq!(seqs(&subscriber.take(3)), vec![2, 3, 4]);
        assert!(subscriber.signal().wait(), "the rest is still signalled");
        assert_eq!(seqs(&subscriber.take(3)), vec![5, 6]);
    }
}
