//! Descendant clients whose events the test delivers (KNSH-094).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::endpoint_security::{DescendantClient, DescendantClients, ExecEvent, ExecHandler, ExecVerdict};
use crate::error::PlatformError;

/// Descendant clients without a kernel: `check` and `watch` answer as set, each watched handler is kept, and the test
/// delivers exec events to it with [`deliver`](Self::deliver) as the backend would. Counts checks and live clients.
#[derive(Default)]
pub struct ScriptedDescendantClients {
    state: Mutex<State>,
    checks: AtomicUsize,
    /// Shared with each client, which decrements it when dropped.
    live: Arc<AtomicUsize>,
}

#[derive(Default)]
struct State {
    /// The error `check` and `watch` fail with, if any.
    failure: Option<PlatformError>,
    /// Every handler ever watched, in order, and whether its client is still live.
    handlers: Vec<(Arc<dyn ExecHandler>, Arc<AtomicUsize>)>,
}

/// A fake client: dropping it marks it deleted.
struct ScriptedClient {
    live: Arc<AtomicUsize>,
    /// 1 while this client lives; shared with the fake's entry for its handler.
    own: Arc<AtomicUsize>,
}

impl DescendantClient for ScriptedClient {}

impl Drop for ScriptedClient {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
        self.own.store(0, Ordering::SeqCst);
    }
}

impl ScriptedDescendantClients {
    /// Clients that can be created.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Clients that cannot be created: `check` and `watch` fail with `error`.
    #[must_use]
    pub fn failing(error: PlatformError) -> Self {
        let clients = Self::default();
        clients.state().failure = Some(error);
        clients
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many times `check` was called.
    #[must_use]
    pub fn checks(&self) -> usize {
        self.checks.load(Ordering::SeqCst)
    }

    /// How many clients were ever watched.
    #[must_use]
    pub fn watched(&self) -> usize {
        self.state().handlers.len()
    }

    /// How many clients are live (created and not yet dropped).
    #[must_use]
    pub fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    /// Delivers `event` to the handler of the `client`-th watch, as the backend would, and returns its verdict. A
    /// client that was dropped receives nothing: [`ExecVerdict::Deny`], as for an event no handler can take.
    ///
    /// # Panics
    ///
    /// If no `client`-th watch exists (a test mistake).
    #[must_use]
    pub fn deliver(&self, client: usize, event: ExecEvent) -> ExecVerdict {
        let (handler, own) = {
            let state = self.state();
            let (handler, own) = &state.handlers[client];
            (Arc::clone(handler), Arc::clone(own))
        };
        // The lock is released first: the handler may take as long as it likes, and may call back into the fake.
        if own.load(Ordering::SeqCst) == 0 {
            return ExecVerdict::Deny;
        }
        handler.exec(event)
    }
}

impl DescendantClients for ScriptedDescendantClients {
    fn check(&self) -> Result<(), PlatformError> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        self.state().failure.map_or(Ok(()), Err)
    }

    fn watch(&self, handler: Arc<dyn ExecHandler>) -> Result<Box<dyn DescendantClient>, PlatformError> {
        let mut state = self.state();
        if let Some(error) = state.failure {
            return Err(error);
        }
        let own = Arc::new(AtomicUsize::new(1));
        state.handlers.push((handler, Arc::clone(&own)));
        self.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(ScriptedClient {
            live: Arc::clone(&self.live),
            own,
        }))
    }
}
