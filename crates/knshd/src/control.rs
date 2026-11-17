//! The control service's JSON-RPC side (KNSH-067, `specs/06-api/control-service.md`).
//!
//! The XPC transport (`knsh_platform::macos::XpcControlService`) verifies every message's sender before this module
//! sees it (FR-AUTH-12 – FR-AUTH-14). What arrives here is one verified message's JSON at a time, and it is served
//! exactly like a socket connection: the same strict profile, the same handshake rule and the same dispatch tables,
//! on [`Endpoint::Control`] ([`MessageConnection`]). Only the method catalogue differs per endpoint.
//!
//! # Ordering and locks
//!
//! Each connection's [`MessageConnection`] sits behind one lock, the counterpart of a socket's writer lock: a call
//! holds it from dispatch until its answer is sent, and the event pump holds it while it sends a batch. So the answer
//! to `events.subscribe` precedes that subscription's events, and nothing of a subscription is sent after the answer
//! to `events.unsubscribe`, as on the sockets. Lock order: [`ControlEndpoint`]'s connection map, then a connection's
//! lock, never the other way; neither is held while waiting for the pump to end.
//!
//! # Privacy
//!
//! Nothing here logs a message, a method name or a parameter: only fixed reasons and counts.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};

use knsh_platform::{
    AfterMessage, ConnectionId, ControlHandler, ControlPeer, Field, Level, PeerRejection, SystemLog, Value,
};
use knsh_proto::ByteTransport;

use crate::authority::Registration;
use crate::connection::{MessageConnection, Outgoing, delivery_message};
use crate::decisions::AuthorityLink;
use crate::dispatch::{Dispatcher, Endpoint};
use crate::lifetime::Activity;

/// Deliveries the pump sends per hold of a connection's lock, so a busy subscription never starves its answers.
const PUMP_BATCH: usize = 64;

/// Serves verified control connections through the shared dispatcher.
pub(crate) struct ControlEndpoint {
    dispatcher: Arc<Dispatcher>,
    log: Arc<dyn SystemLog>,
    /// Told when a connection ends, so the authority's place frees up (KNSH-068, FR-AUTH-01).
    registration: Arc<Registration>,
    connections: Mutex<BTreeMap<ConnectionId, Arc<Connection>>>,
}

/// One open control connection.
struct Connection {
    /// The protocol state; also the lock that orders answers and event notifications (module docs).
    state: Mutex<MessageConnection>,
    /// Sends event notifications to the peer.
    peer: Arc<dyn ControlPeer>,
    /// The event pump, started by the connection's first subscription.
    pump: Mutex<Option<JoinHandle<()>>>,
}

impl ControlEndpoint {
    /// An endpoint dispatching through `dispatcher`, logging refusals to `log`, and telling `registration` when a
    /// connection ends.
    pub(crate) fn new(
        dispatcher: Arc<Dispatcher>,
        log: Arc<dyn SystemLog>,
        registration: Arc<Registration>,
    ) -> Arc<Self> {
        Arc::new(Self {
            dispatcher,
            log,
            registration,
            connections: Mutex::new(BTreeMap::new()),
        })
    }

    fn connection(&self, id: ConnectionId) -> Option<Arc<Connection>> {
        lock(&self.connections).get(&id).cloned()
    }

    /// Starts `connection`'s event pump if it has a subscription and no pump yet.
    ///
    /// # Errors
    ///
    /// `Err` if the thread could not start; the connection must then close, so subscriptions that nothing would
    /// deliver never look alive.
    fn start_pump(&self, connection: &Arc<Connection>, subscribed: bool) -> Result<(), ()> {
        let mut pump = lock(&connection.pump);
        if !subscribed || pump.is_some() {
            return Ok(());
        }
        let pumping = Arc::clone(connection);
        let spawned = thread::Builder::new()
            .name("knshd-control-events".to_owned())
            .spawn(move || pump_events(&pumping));
        let Ok(handle) = spawned else {
            self.log.log(Level::Error, "control event pump not started", &[]);
            return Err(());
        };
        *pump = Some(handle);
        Ok(())
    }
}

impl ControlHandler for ControlEndpoint {
    fn opened(&self, connection: ConnectionId, peer: Arc<dyn ControlPeer>) {
        let state = MessageConnection::new(Endpoint::Control, connection, Arc::clone(&self.dispatcher));
        let opened = Arc::new(Connection {
            state: Mutex::new(state),
            peer,
            pump: Mutex::new(None),
        });
        lock(&self.connections).insert(connection, opened);
        self.log.log(Level::Notice, "control connection opened", &[]);
    }

    fn message(&self, connection: ConnectionId, json: &[u8], reply: &dyn ControlPeer) -> AfterMessage {
        let Some(open) = self.connection(connection) else {
            // Never opened, or already closed: nothing may be served on it.
            return AfterMessage::Close;
        };
        let mut state = lock(&open.state);
        let out = state.handle(json);
        // Sent before the lock is released: the pump cannot slip a notification in ahead of this answer.
        let sent = out
            .json
            .as_deref()
            .is_none_or(|answer| reply.send(answer, out.bytes.as_deref()).is_ok());
        let subscribed = state.subscriber().is_subscribed();
        drop(state);
        if !sent || out.close || self.start_pump(&open, subscribed).is_err() {
            return AfterMessage::Close;
        }
        AfterMessage::KeepOpen
    }

    fn closed(&self, connection: ConnectionId) {
        let Some(closed) = lock(&self.connections).remove(&connection) else {
            return;
        };
        // The authority's connection ending frees its place and publishes `authority.disconnected` (FR-AUTH-02).
        self.registration.disconnected(connection);
        // Every subscription ends with the connection; the pump wakes, sees the close and returns.
        lock(&closed.state).close();
        let pump = lock(&closed.pump).take();
        if let Some(pump) = pump {
            // The pump only sends (never blocks on the peer), so it ends promptly once its subscriber is closed.
            let _ = pump.join();
        }
        self.log.log(Level::Notice, "control connection closed", &[]);
    }

    fn refused(&self, reason: PeerRejection) {
        self.log.log(
            Level::Error,
            "control peer refused",
            &[Field::new("reason", Value::Static(reason.kind()))],
        );
    }
}

/// Notifications to the authority (`decision.requested`, `decision.cancelled`; KNSH-069), sent under the connection's
/// lock like an answer or an event, so they never interleave with one.
impl AuthorityLink for ControlEndpoint {
    fn notify(&self, connection: ConnectionId, json: &[u8]) -> Result<(), ()> {
        let open = self.connection(connection).ok_or(())?;
        let _state = lock(&open.state);
        open.peer.send(json, None).map_err(|_| ())
    }
}

/// An open control connection keeps `knshd` alive, like an open socket connection (KNSH-013).
impl Activity for ControlEndpoint {
    fn keeps_alive(&self) -> bool {
        !lock(&self.connections).is_empty()
    }
}

/// The pump: waits for the connection's subscriptions to have something, then sends one batch of notifications
/// under the connection's lock, until the connection closes or a send fails.
fn pump_events(connection: &Connection) {
    let (subscriber, binary) = {
        let state = lock(&connection.state);
        (Arc::clone(state.subscriber()), Arc::clone(state.pump_bytes()))
    };
    while subscriber.signal().wait() {
        let _state = lock(&connection.state);
        // Read under the lock: a `hello` answered before this batch has already set it.
        let bytes = if binary.load(Ordering::SeqCst) {
            ByteTransport::BinaryFrames
        } else {
            ByteTransport::Base64
        };
        // Taken under the lock, so an unsubscribe answered before this cannot have its events sent after.
        for (subscription, delivery) in subscriber.take(PUMP_BATCH) {
            let Some(Outgoing {
                json: Some(json),
                bytes,
                ..
            }) = delivery_message(subscription, &delivery, bytes)
            else {
                continue;
            };
            if connection.peer.send(&json, bytes.as_deref()).is_err() {
                // Nothing more can be delivered: end the subscriptions now (fail closed) rather than leave them
                // looking alive. `closed` ends them again and joins this thread.
                subscriber.close();
                return;
            }
        }
    }
}

/// Takes a lock even if another thread panicked while holding it: every update under these locks is one step.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use knsh_json::{Value as Json, parse};
    use knsh_platform::PlatformError;
    use knsh_platform::testing::RecordingLog;

    use super::*;
    use crate::dispatch::tests::ok_handler;
    use crate::dispatch::{HELLO, Table};

    /// Collects what is sent to it.
    #[derive(Default)]
    struct Collect(Mutex<Vec<Vec<u8>>>);

    impl ControlPeer for Collect {
        fn send(&self, json: &[u8], _: Option<&[u8]>) -> Result<(), PlatformError> {
            lock(&self.0).push(json.to_vec());
            Ok(())
        }
    }

    impl Collect {
        fn taken(&self) -> Vec<Json> {
            std::mem::take(&mut *lock(&self.0))
                .iter()
                .map(|bytes| parse(bytes, knsh_json::MAX_PAYLOAD).unwrap())
                .collect()
        }
    }

    /// An endpoint whose control table serves `hello` and `records.query`.
    fn endpoint() -> (Arc<ControlEndpoint>, Arc<RecordingLog>) {
        let dispatcher = Dispatcher::from_tables(Table::new(), Table::new())
            .serving(Endpoint::Control, HELLO, ok_handler())
            .serving(Endpoint::Control, "records.query", ok_handler());
        let log = Arc::new(RecordingLog::new());
        let registration = Registration::new(crate::events::tests::hub(), log.clone());
        (
            ControlEndpoint::new(Arc::new(dispatcher), log.clone(), registration),
            log,
        )
    }

    fn open(endpoint: &ControlEndpoint, id: u64) -> ConnectionId {
        let id = ConnectionId(id);
        endpoint.opened(id, Arc::new(Collect::default()));
        id
    }

    fn field<'a>(answer: &'a Json, key: &str) -> Option<&'a Json> {
        answer.as_object()?.get(key)
    }

    fn error_code(answer: &Json) -> Option<i64> {
        field(field(answer, "error")?, "code")?.as_i64()
    }

    // AC "the same strict JSON profile and schema apply": the control service answers through the same session
    // rules as the sockets, on its own dispatch table.
    #[test]
    fn serves_json_rpc_after_hello() {
        let (endpoint, _) = endpoint();
        let id = open(&endpoint, 1);
        let reply = Collect::default();
        let hello = br#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{}}"#;
        assert_eq!(endpoint.message(id, hello, &reply), AfterMessage::KeepOpen);
        let query = br#"{"jsonrpc":"2.0","id":2,"method":"records.query","params":{}}"#;
        assert_eq!(endpoint.message(id, query, &reply), AfterMessage::KeepOpen);
        let answers = reply.taken();
        assert_eq!(answers.len(), 2);
        assert!(
            answers.iter().all(|answer| field(answer, "result").is_some()),
            "{answers:?}"
        );
        // A method the control service does not serve is refused, never routed elsewhere.
        let other = br#"{"jsonrpc":"2.0","id":3,"method":"approval.list","params":{}}"#;
        assert_eq!(endpoint.message(id, other, &reply), AfterMessage::KeepOpen);
        assert_eq!(error_code(&reply.taken()[0]), Some(-32003));
        assert!(endpoint.keeps_alive());
        endpoint.closed(id);
        assert!(!endpoint.keeps_alive());
    }

    // `specs/06-api/wire-format.md`: anything but `hello` first is `-32600` and closes; malformed JSON is `-32700` and
    // closes, never recovered from.
    #[test]
    fn closes_on_handshake_violation_and_malformed_json() {
        let (endpoint, _) = endpoint();
        let reply = Collect::default();
        let first = open(&endpoint, 1);
        let query = br#"{"jsonrpc":"2.0","id":2,"method":"records.query","params":{}}"#;
        assert_eq!(endpoint.message(first, query, &reply), AfterMessage::Close);
        assert_eq!(error_code(&reply.taken()[0]), Some(-32600));

        let second = open(&endpoint, 2);
        let duplicate_keys = br#"{"jsonrpc":"2.0","id":1,"id":2,"method":"hello","params":{}}"#;
        assert_eq!(endpoint.message(second, duplicate_keys, &reply), AfterMessage::Close);
        assert_eq!(error_code(&reply.taken()[0]), Some(-32700));
    }

    // A message for a connection that was never opened (or already closed) is not served.
    #[test]
    fn refuses_messages_on_unknown_connections() {
        let (endpoint, _) = endpoint();
        let reply = Collect::default();
        let hello = br#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{}}"#;
        assert_eq!(endpoint.message(ConnectionId(9), hello, &reply), AfterMessage::Close);
        let id = open(&endpoint, 1);
        endpoint.closed(id);
        assert_eq!(endpoint.message(id, hello, &reply), AfterMessage::Close);
        assert_eq!(reply.taken(), Vec::<Json>::new());
    }

    // FR-AUTH-01, FR-AUTH-02 (KNSH-068): `authority.register` reaches the registration with the connection it came on,
    // a second connection is refused with `-32003`, and the authority's connection closing frees its place.
    #[test]
    fn registration_follows_the_authority_connection() {
        let log = Arc::new(RecordingLog::new());
        let registration = Registration::new(crate::events::tests::hub(), log.clone());
        let mut dispatcher =
            Dispatcher::from_tables(Table::new(), Table::new()).serving(Endpoint::Control, HELLO, ok_handler());
        for (name, handler) in registration.handlers() {
            dispatcher = dispatcher.serving(Endpoint::Control, name, handler);
        }
        let endpoint = ControlEndpoint::new(Arc::new(dispatcher), log, Arc::clone(&registration));
        let reply = Collect::default();
        let hello = br#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{}}"#;
        let register = br#"{"jsonrpc":"2.0","id":2,"method":"authority.register","params":{}}"#;

        let first = open(&endpoint, 1);
        let second = open(&endpoint, 2);
        for id in [first, second] {
            assert_eq!(endpoint.message(id, hello, &reply), AfterMessage::KeepOpen);
        }
        assert_eq!(endpoint.message(first, register, &reply), AfterMessage::KeepOpen);
        assert_eq!(endpoint.message(second, register, &reply), AfterMessage::KeepOpen);
        let answers = reply.taken();
        assert!(field(&answers[2], "result").is_some(), "{answers:?}");
        assert_eq!(error_code(&answers[3]), Some(-32003));

        endpoint.closed(first);
        assert!(!registration.is_registered());
        assert_eq!(endpoint.message(second, register, &reply), AfterMessage::KeepOpen);
        assert!(field(&reply.taken()[0], "result").is_some());
        assert!(registration.is_registered());
    }

    // KNSH-069: notifications reach the named connection's peer; an unknown connection is an error.
    #[test]
    fn notifies_the_named_connection() {
        let (endpoint, _) = endpoint();
        let peer = Arc::new(Collect::default());
        endpoint.opened(ConnectionId(1), peer.clone());
        let json = br#"{"jsonrpc":"2.0","method":"decision.cancelled","params":{}}"#;
        assert!(endpoint.notify(ConnectionId(1), json).is_ok());
        assert_eq!(peer.taken().len(), 1);
        assert!(endpoint.notify(ConnectionId(2), json).is_err());
    }

    // FR-AUTH-24 (KNSH-069): a request made with no authority is sent to the connection that registers, through the
    // control service, after the answer to its `authority.register` (queuing from inside that call cannot deadlock
    // on the connection's lock).
    #[test]
    fn sends_pending_requests_after_registering() {
        use std::time::{Duration, Instant};

        use knsh_platform::testing::{FakeClock, SeededRandom};

        use crate::decisions::{AuthorityLink, Decisions};

        let log = Arc::new(RecordingLog::new());
        let registration = Registration::new(crate::events::tests::hub(), log.clone());
        let clock = Arc::new(FakeClock::new(
            knsh_core::Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
        ));
        let decisions = Decisions::with_default_timeout(
            clock,
            Arc::new(SeededRandom::new(1)),
            log.clone(),
            crate::grants::GrantStore::new(),
        );
        registration.watch(decisions.clone());
        let mut dispatcher =
            Dispatcher::from_tables(Table::new(), Table::new()).serving(Endpoint::Control, HELLO, ok_handler());
        for (name, handler) in registration.handlers().into_iter().chain(decisions.handlers()) {
            dispatcher = dispatcher.serving(Endpoint::Control, name, handler);
        }
        let endpoint = ControlEndpoint::new(Arc::new(dispatcher), log, Arc::clone(&registration));
        let link: Arc<dyn AuthorityLink> = endpoint.clone();
        decisions.attach(Arc::downgrade(&link)).unwrap();

        let asking = crate::decisions::tests::ask(&decisions, "git push", Arc::new(knsh_core::StillWaiting));
        let peer = Arc::new(Collect::default());
        let id = ConnectionId(1);
        endpoint.opened(id, peer.clone());
        let hello = br#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{}}"#;
        let register = br#"{"jsonrpc":"2.0","id":2,"method":"authority.register","params":{}}"#;
        // Answers go to `reply`, as XPC replies; notifications to the connection's peer.
        assert_eq!(endpoint.message(id, hello, peer.as_ref()), AfterMessage::KeepOpen);
        assert_eq!(endpoint.message(id, register, peer.as_ref()), AfterMessage::KeepOpen);
        let started = Instant::now();
        while lock(&peer.0).len() < 3 {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the request was not sent again"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let sent = peer.taken();
        assert!(field(&sent[1], "result").is_some(), "{sent:?}");
        assert_eq!(
            field(&sent[2], "method").and_then(Json::as_str),
            Some("decision.requested")
        );
        let request_id = field(field(&sent[2], "params").unwrap(), "request_id")
            .and_then(Json::as_str)
            .unwrap()
            .to_owned();
        let deny = format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"decision.respond","params":{{"request_id":"{request_id}","verdict":"deny"}}}}"#
        );
        assert_eq!(
            endpoint.message(id, deny.as_bytes(), peer.as_ref()),
            AfterMessage::KeepOpen
        );
        assert_eq!(asking.join().unwrap().reply, knsh_core::AskReply::Deny { reason: None });
        assert_eq!(
            field(field(&peer.taken()[0], "result").unwrap(), "applied"),
            Some(&Json::Bool(true))
        );
    }

    // Refusals are logged with a fixed reason only.
    #[test]
    fn logs_refused_peers_without_content() {
        let (endpoint, log) = endpoint();
        endpoint.refused(PeerRejection::NoTrustedAuthority);
        let entries = log.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "control peer refused");
    }
}
