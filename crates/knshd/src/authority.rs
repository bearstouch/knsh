//! The authority: trusting one (`authority.trust` on `user.sock`) and registering as the one (`authority.register` on
//! the control service). KNSH-068; FR-AUTH-01, FR-AUTH-02, FR-AUTH-10, FR-AUTH-11.
//!
//! # Trust ([`AuthorityTrust`])
//!
//! `knsh authority trust --team-id <id> --identifier <bundle-id> --min-version <v>` sends `authority.trust`:
//!
//! 1. **Validate.** The params are parsed by the trust record's own types, so a malformed team ID, identifier or
//!    version is `-32602` before anything else happens, and never reaches the prompt (FR-AUTH-10).
//! 2. **Read.** The current record is read from the Keychain. A record that exists but cannot be read, or does not
//!    decode, is tampering or a locked keychain (decision 11): `-32603`, no prompt, nothing written.
//! 3. **Unchanged.** Exactly the record already trusted: nothing is asked or written (`changed: false`).
//! 4. **Authenticate.** `knshd` shows the Touch ID or password prompt itself (NFR-SEC-04), naming the authority:
//!    `trust the authority app: <identifier> (team <team>, version <v> or later)`, or, when one is already trusted,
//!    `replace the trusted authority app: <old> with <new>`. Replacing needs the prompt exactly like a first trust.
//!    Any outcome but success is `-32001` with `source: "user"`; nothing is written.
//! 5. **Store.** A first record is created, a different one replaces the old value in place (the item keeps its
//!    access list). A failed write is `-32603` and the previous record stays in force.
//! 6. **Apply.** The control service switches to the new record at once ([`AuthorityTrust::when_trusted`]): every
//!    connection verified under the old record is closed, so a registered authority disconnects.
//!
//! Trusts are serialised: the lock order is only [`AuthorityTrust`]'s `saving`, held across the prompt so two trusts
//! cannot interleave their read and write.
//!
//! # Registration ([`Registration`])
//!
//! Every control connection was verified by the transport before any of its messages arrived here (FR-AUTH-12 –
//! FR-AUTH-14). The first one to call `authority.register` becomes the authority and `authority.connected` is
//! published; calling it again on the same connection changes nothing. Any other connection is refused with
//! `-32003` until the authority's connection ends, which publishes `authority.disconnected` (FR-AUTH-01,
//! FR-AUTH-02). Both are engine events: no session, no actor, delivered to every subscription to all sessions.
//!
//! The authority's first message (`hello`) is sent before it can verify `knshd`'s reply (FR-AUTH-15), so it carries
//! nothing sensitive, and neither does `authority.register`.
//!
//! # Privacy
//!
//! Nothing here logs a team, identifier or version: only fixed messages.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use knsh_core::{EngineEventData, TrustedAuthority};
use knsh_platform::{ConnectionId, Level, NotAuthenticated, PromptReason, SystemLog, TrustStore, UserPresence};
use knsh_proto::{
    AuthorityRegisterParams, AuthorityRegisterResult, AuthorityTrustParams, AuthorityTrustResult, Denial, ErrorCode,
    RpcError,
};

use crate::dispatch::{Call, Endpoint, Handler, Handlers, Reply, answer, params};
use crate::events::EventHub;

/// The method that trusts an authority.
const AUTHORITY_TRUST: &str = "authority.trust";
/// The method an authority registers with.
const AUTHORITY_REGISTER: &str = "authority.register";

/// How long the prompt waits for the user. Shorter than the CLI's read timeout (300 s), so the CLI always gets the
/// answer.
pub(crate) const TRUST_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// What the engine does once a new record is stored: switch the control service to it. Called with the record now
/// trusted.
pub(crate) type OnTrusted = Arc<dyn Fn(&TrustedAuthority) + Send + Sync>;

/// Takes a lock even if another thread panicked while holding it: every update under these locks is one step.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The `authority.trust` service. One per `knshd`.
pub(crate) struct AuthorityTrust {
    /// Where the trust record is kept: the Keychain item only `knshd` can read (FR-AUTH-11).
    store: Arc<dyn TrustStore>,
    /// The Touch ID or password prompt, shown by `knshd` itself.
    presence: Arc<dyn UserPresence>,
    log: Arc<dyn SystemLog>,
    /// Applies a new record to the control service; set once the service exists.
    on_trusted: Mutex<Option<OnTrusted>>,
    /// Serialises trusts (module documentation).
    saving: Mutex<()>,
}

impl AuthorityTrust {
    /// The service over `store`, prompting through `presence`.
    pub(crate) fn new(
        store: Arc<dyn TrustStore>,
        presence: Arc<dyn UserPresence>,
        log: Arc<dyn SystemLog>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            presence,
            log,
            on_trusted: Mutex::new(None),
            saving: Mutex::new(()),
        })
    }

    /// The record trusted now, read at start for the control service's gate. A record that cannot be read is logged
    /// and nothing is trusted: every control connection is then refused (fail closed, decision 11).
    pub(crate) fn current(&self) -> Option<TrustedAuthority> {
        self.store.read().unwrap_or_else(|_| {
            self.log.log(
                Level::Error,
                "authority trust record unreadable: no authority is trusted",
                &[],
            );
            None
        })
    }

    /// Calls `apply` with every record stored from now on (step 6).
    pub(crate) fn when_trusted(&self, apply: OnTrusted) {
        *lock(&self.on_trusted) = Some(apply);
    }

    /// The handler.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let service = Arc::clone(self);
        let trust: Handler = Arc::new(move |call: &Call<'_>| service.trust(call));
        [(AUTHORITY_TRUST, trust)].into_iter().collect()
    }

    /// `authority.trust` (module documentation, steps 1 to 6).
    fn trust(&self, call: &Call<'_>) -> Reply {
        user_only(call)?;
        // Step 1: a malformed part is `-32602` here, before the prompt.
        let AuthorityTrustParams { authority } = params(call)?;
        let _saving = lock(&self.saving);

        // Step 2: never prompt for, or write over, a record that cannot be read.
        let current = self.store.read().map_err(|_| {
            self.log.log(
                Level::Error,
                "authority trust refused: the trust record cannot be read",
                &[],
            );
            RpcError::new(ErrorCode::InternalError)
        })?;
        if current.as_ref() == Some(&authority) {
            return answer(&AuthorityTrustResult {
                authority,
                changed: false,
                replaced: false,
            });
        }

        // Step 4: the prompt names exactly what will be trusted, and what it replaces.
        let reason = match &current {
            None => PromptReason::change("trust the authority app", &authority.describe()),
            Some(old) => PromptReason::change(
                "replace the trusted authority app",
                &format!("{} with {}", old.describe(), authority.describe()),
            ),
        };
        let proof = self
            .presence
            .authenticate(&reason, TRUST_PROMPT_TIMEOUT)
            .map_err(|refusal| {
                self.log
                    .log(Level::Notice, "authority trust refused: not authenticated", &[]);
                not_authenticated(refusal)
            })?;

        // Step 5: create the first record, or replace the one read above in place.
        let replaced = current.is_some();
        let stored = if replaced {
            self.store.replace(&authority, proof)
        } else {
            self.store.create(&authority, proof)
        };
        stored.map_err(|_| {
            self.log.log(
                Level::Error,
                "authority trust failed: the trust record could not be written",
                &[],
            );
            RpcError::new(ErrorCode::InternalError)
        })?;
        self.log.log(Level::Notice, "authority trusted", &[]);

        // Step 6.
        let apply = lock(&self.on_trusted).clone();
        if let Some(apply) = apply {
            apply(&authority);
        }
        answer(&AuthorityTrustResult {
            authority,
            changed: true,
            replaced,
        })
    }
}

/// `-32003` unless the call came on `user.sock`. The catalogue lists the method only there; this is the second lock
/// on the door: only the user chooses who decides for their agents.
fn user_only(call: &Call<'_>) -> Result<(), RpcError> {
    match call.endpoint {
        Endpoint::User => Ok(()),
        Endpoint::Agent | Endpoint::Control => Err(RpcError::new(ErrorCode::NotAllowed)),
    }
}

/// `-32001` from the user: the prompt did not succeed, so nothing was trusted (decision 12).
fn not_authenticated(refusal: NotAuthenticated) -> RpcError {
    Denial {
        rule_id: None,
        reason: Some(refusal.to_string()),
        source: Some(String::from("user")),
    }
    .to_error()
    .unwrap_or_else(|_| RpcError::new(ErrorCode::Denied))
}

/// The single registered authority (FR-AUTH-01). One per `knshd`.
pub(crate) struct Registration {
    /// The authority's connection, if one registered. Lock order: this, then the event hub.
    current: Mutex<Option<ConnectionId>>,
    events: Arc<EventHub>,
    log: Arc<dyn SystemLog>,
}

impl Registration {
    /// No authority registered yet.
    pub(crate) fn new(events: Arc<EventHub>, log: Arc<dyn SystemLog>) -> Arc<Self> {
        Arc::new(Self {
            current: Mutex::new(None),
            events,
            log,
        })
    }

    /// The handler.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let registration = Arc::clone(self);
        let register: Handler = Arc::new(move |call: &Call<'_>| registration.register(call));
        [(AUTHORITY_REGISTER, register)].into_iter().collect()
    }

    /// `authority.register`: the calling control connection becomes the authority, unless another one is.
    fn register(&self, call: &Call<'_>) -> Reply {
        // Only a verified control connection can be the authority; the catalogue lists the method nowhere else.
        let connection = match (call.endpoint, call.control) {
            (Endpoint::Control, Some(connection)) => connection,
            (Endpoint::User | Endpoint::Agent | Endpoint::Control, _) => {
                return Err(RpcError::new(ErrorCode::NotAllowed));
            }
        };
        let AuthorityRegisterParams = params(call)?;
        let mut current = lock(&self.current);
        match *current {
            // Already the authority: nothing changes, and no second `authority.connected`.
            Some(registered) if registered == connection => {}
            // FR-AUTH-01: one authority at a time.
            Some(_) => {
                self.log.log(
                    Level::Notice,
                    "authority registration refused: another authority is registered",
                    &[],
                );
                return Err(RpcError::new(ErrorCode::NotAllowed));
            }
            None => {
                *current = Some(connection);
                self.log.log(Level::Notice, "authority registered", &[]);
                // Published under the lock, so connected and disconnected events always alternate.
                self.publish(EngineEventData::AuthorityConnected);
            }
        }
        answer(&AuthorityRegisterResult)
    }

    /// The control connection `connection` ended. If it was the authority's, the authority is gone: another
    /// connection may now register, and `authority.disconnected` is published (FR-AUTH-02).
    pub(crate) fn disconnected(&self, connection: ConnectionId) {
        let mut current = lock(&self.current);
        if *current == Some(connection) {
            *current = None;
            self.log.log(Level::Notice, "authority disconnected", &[]);
            self.publish(EngineEventData::AuthorityDisconnected);
        }
    }

    /// Whether an authority is registered now.
    #[cfg(test)]
    pub(crate) fn is_registered(&self) -> bool {
        lock(&self.current).is_some()
    }

    /// Publishes `data`; a failure (no clock or random source) is logged, and registration itself is unaffected.
    fn publish(&self, data: EngineEventData) {
        if self.events.publish_engine(data).is_err() {
            self.log.log(Level::Error, "authority event not published", &[]);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
