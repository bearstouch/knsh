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

use crate::connection::{MessageConnection, Outgoing, delivery_message};
use crate::dispatch::{Dispatcher, Endpoint};
use crate::lifetime::Activity;

/// Deliveries the pump sends per hold of a connection's lock, so a busy subscription never starves its answers.
const PUMP_BATCH: usize = 64;

/// Serves verified control connections through the shared dispatcher.
pub(crate) struct ControlEndpoint {
    dispatcher: Arc<Dispatcher>,
    log: Arc<dyn SystemLog>,
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
    /// An endpoint dispatching through `dispatcher`, logging refusals to `log`.
    pub(crate) fn new(dispatcher: Arc<Dispatcher>, log: Arc<dyn SystemLog>) -> Arc<Self> {
        Arc::new(Self {
            dispatcher,
            log,
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
        let state = MessageConnection::new(Endpoint::Control, Arc::clone(&self.dispatcher));
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
        (ControlEndpoint::new(Arc::new(dispatcher), log.clone()), log)
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
