//! The secrets broker: Keychain secrets and authority-supplied secrets (KNSH-089; FR-SEC-01, FR-SEC-07;
//! `specs/05-models/secret.md`, `specs/06-api/control-service.md#secretsprovide`).
//!
//! # Sources
//!
//! A secret is looked up by name in two places, in this order:
//!
//! 1. **Provided by the authority** with `secrets.provide`: held in this process's memory only, in a [`SecretValue`]
//!    zeroed on drop, until its time is up or `secrets.revoke` removes it. Never written to the state store or any
//!    file, so it is lost when `knshd` exits (FR-SEC-07). A provided secret takes the place of a Keychain item of the
//!    same name while it lives: the authority's short-lived token is preferred over a stored one.
//! 2. **The Keychain**, service `knsh`, through [`SecretStore`]: read at each lookup and never cached here.
//!
//! [`SecretBroker::lookup`] answers with the value or a typed [`Unavailable`]; [`SecretBroker::resolve`] takes every
//! secret a line needs, or none. A line that needs a secret it cannot have is denied, never run without it: the
//! injection path (KNSH-092) runs lines only with what `resolve` returned.
//!
//! # Expiry
//!
//! A provided secret expires at the earlier of two deadlines: its wall-clock `expires_at` (reported to the
//! authority) and the same duration on the monotonic clock, so moving the system clock back never extends it. A wall
//! clock that cannot be read counts as expired (fail closed). Expired secrets are dropped at every access and by a
//! watcher every [`PURGE_PERIOD`], so a value does not stay in memory long after its time.
//!
//! # Privacy
//!
//! No method returns a value to any client: `secrets.provide` answers with the name and expiry, `secrets.revoke` with
//! whether one was removed. Nothing here logs a name or a value.
//!
//! # Locks
//!
//! One lock, over the provided secrets. It is never held while reading the Keychain.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use knsh_core::{SecretName, Timestamp};
use knsh_platform::{Clock, Monotonic, PlatformError, SecretStore, SecretValue};
use knsh_proto::{
    ErrorCode, RpcError, SecretsProvideParams, SecretsProvideResult, SecretsRevokeParams, SecretsRevokeResult,
};

use crate::dispatch::{Call, Handler, Handlers, Reply, answer, params};
use crate::supervise::control_only;

/// Most secrets the authority may have provided at once. Another name past this is `-32602`; replacing a live one
/// is always accepted (`specs/09-reference/defaults-and-limits.md`).
pub(crate) const MAX_PROVIDED_SECRETS: usize = 256;

/// How often the watcher drops expired secrets from memory. Lookups refuse an expired secret whatever the period.
pub(crate) const PURGE_PERIOD: Duration = Duration::from_secs(1);

/// Why a secret could not be had. Either way the line that needs it is denied (fail closed).
#[cfg_attr(not(test), allow(dead_code, reason = "used by secret injection, KNSH-092"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// No provided secret is live under the name and the Keychain has no such item.
    NotFound,
    /// The Keychain has the item but it cannot be read (decision 11: not readable by `knshd`, a locked keychain,
    /// tampering), or its value was refused.
    AccessDenied,
}

/// A secret a line needs that it cannot have: what its denial names (KNSH-092).
#[cfg_attr(not(test), allow(dead_code, reason = "used by secret injection, KNSH-092"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Missing {
    /// The secret.
    pub(crate) name: SecretName,
    /// Why.
    pub(crate) reason: Unavailable,
}

/// One secret the authority provided.
struct Provided {
    value: SecretValue,
    /// Reported to the authority.
    expires_at: Timestamp,
    /// The same deadline on the monotonic clock.
    deadline: Monotonic,
}

impl Provided {
    /// Whether it is past either deadline, or the wall clock is unknown.
    fn expired(&self, now: Option<Timestamp>, monotonic: Monotonic) -> bool {
        now.is_none_or(|now| now >= self.expires_at) || monotonic >= self.deadline
    }
}

/// The secrets broker (module documentation).
pub(crate) struct SecretBroker {
    keychain: Arc<dyn SecretStore>,
    clock: Arc<dyn Clock>,
    /// Memory only (FR-SEC-07).
    provided: Mutex<BTreeMap<SecretName, Provided>>,
}

impl SecretBroker {
    /// A broker reading persistent secrets from `keychain`, timing provided ones with `clock`.
    pub(crate) fn new(keychain: Arc<dyn SecretStore>, clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            keychain,
            clock,
            provided: Mutex::new(BTreeMap::new()),
        })
    }

    /// The provided secrets with every expired one dropped (and its buffer zeroed).
    fn live(&self) -> MutexGuard<'_, BTreeMap<SecretName, Provided>> {
        let now = self.clock.now().ok();
        let monotonic = self.clock.monotonic();
        let mut provided = self.provided.lock().unwrap_or_else(PoisonError::into_inner);
        provided.retain(|_, secret| !secret.expired(now, monotonic));
        provided
    }

    /// Holds `value` under `name` for `duration_s` seconds, in place of any provided secret of that name. Returns
    /// when it expires and whether one was replaced.
    ///
    /// # Errors
    ///
    /// `-32603` when the wall clock cannot be read or the deadline overflows; `-32602` when
    /// [`MAX_PROVIDED_SECRETS`] other names are already held. Nothing is stored then.
    pub(crate) fn provide(
        &self,
        name: SecretName,
        value: SecretValue,
        duration_s: u64,
    ) -> Result<(Timestamp, bool), RpcError> {
        let now = self.clock.now().map_err(|_| RpcError::new(ErrorCode::InternalError))?;
        let duration = Duration::from_secs(duration_s);
        let expires_at = u64::try_from(duration.as_micros())
            .ok()
            .and_then(|micros| now.as_unix_micros().checked_add(micros))
            .and_then(|micros| Timestamp::from_unix_micros(micros).ok())
            .ok_or_else(|| RpcError::new(ErrorCode::InternalError))?;
        let deadline = self
            .clock
            .monotonic()
            .checked_add(duration)
            .ok_or_else(|| RpcError::new(ErrorCode::InternalError))?;
        let mut provided = self.live();
        let replaced = provided.contains_key(&name);
        if !replaced && provided.len() >= MAX_PROVIDED_SECRETS {
            return Err(RpcError::new(ErrorCode::InvalidParams));
        }
        provided.insert(
            name,
            Provided {
                value,
                expires_at,
                deadline,
            },
        );
        Ok((expires_at, replaced))
    }

    /// Removes the provided secret `name` at once (FR-SEC-07). Returns whether a live one was removed. Keychain
    /// items are never touched.
    pub(crate) fn revoke(&self, name: &SecretName) -> bool {
        // The removed value is dropped, and zeroed, before the lock is released.
        self.live().remove(name).is_some()
    }

    /// The value of `name`: a live provided secret, else the Keychain item (module documentation, "Sources").
    ///
    /// # Errors
    ///
    /// [`Unavailable`] when neither source has it; the caller must deny the line that needs it.
    #[cfg_attr(not(test), allow(dead_code, reason = "used by secret injection, KNSH-092"))]
    pub(crate) fn lookup(&self, name: &SecretName) -> Result<SecretValue, Unavailable> {
        if let Some(provided) = self.live().get(name) {
            return Ok(provided.value.duplicate());
        }
        // The lock is released: a slow or blocked Keychain never holds up `secrets.provide` or `secrets.revoke`.
        self.keychain.read(name).map_err(|error| {
            if matches!(error, PlatformError::SecretNotFound) {
                Unavailable::NotFound
            } else {
                // Every other failure, whatever it is, means no value: fail closed.
                Unavailable::AccessDenied
            }
        })
    }

    /// Every secret in `names`, or the first one that cannot be had: a line runs with all the secrets it needs or
    /// is denied, never run with some missing.
    ///
    /// # Errors
    ///
    /// [`Missing`] naming the first secret that is unavailable, and why.
    #[cfg_attr(not(test), allow(dead_code, reason = "used by secret injection, KNSH-092"))]
    pub(crate) fn resolve(&self, names: &[SecretName]) -> Result<Vec<(SecretName, SecretValue)>, Missing> {
        names
            .iter()
            .map(|name| {
                self.lookup(name)
                    .map(|value| (name.clone(), value))
                    .map_err(|reason| Missing {
                        name: name.clone(),
                        reason,
                    })
            })
            .collect()
    }

    /// Drops every expired provided secret now.
    pub(crate) fn purge_expired(&self) {
        drop(self.live());
    }

    /// Starts the watcher thread, dropping expired secrets every `period` for as long as the broker lives.
    ///
    /// # Errors
    ///
    /// The thread could not be started. Expired secrets are still refused; they are dropped at the next access.
    pub(crate) fn watch(self: &Arc<Self>, period: Duration) -> std::io::Result<()> {
        // Weak: the thread must not keep the broker alive on its own.
        let broker = Arc::downgrade(self);
        thread::Builder::new()
            .name(String::from("knshd-secret-expiry"))
            .spawn(move || {
                loop {
                    thread::sleep(period);
                    let Some(broker) = broker.upgrade() else {
                        return;
                    };
                    broker.purge_expired();
                }
            })
            .map(drop)
    }

    /// `secrets.provide` and `secrets.revoke`, on the control service only.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let provide = Arc::clone(self);
        let revoke = Arc::clone(self);
        let provide: Handler = Arc::new(move |call: &Call<'_>| {
            control_only(call)?;
            provide.provide_call(call)
        });
        let revoke: Handler = Arc::new(move |call: &Call<'_>| {
            control_only(call)?;
            revoke.revoke_call(call)
        });
        [("secrets.provide", provide), ("secrets.revoke", revoke)]
            .into_iter()
            .collect()
    }

    /// `secrets.provide`: answers with the name and expiry, never the value.
    fn provide_call(&self, call: &Call<'_>) -> Reply {
        let SecretsProvideParams {
            name,
            value,
            duration_s,
        } = params(call)?;
        // The parsed string's buffer moves into the zeroed type without a copy.
        let value = SecretValue::from_string(value.into_inner());
        let (expires_at, replaced) = self.provide(name.clone(), value, duration_s)?;
        answer(&SecretsProvideResult {
            name,
            expires_at,
            replaced,
        })
    }

    /// `secrets.revoke`.
    fn revoke_call(&self, call: &Call<'_>) -> Reply {
        let SecretsRevokeParams { name } = params(call)?;
        answer(&SecretsRevokeResult {
            revoked: self.revoke(&name),
        })
    }
}

#[cfg(test)]
mod tests;
