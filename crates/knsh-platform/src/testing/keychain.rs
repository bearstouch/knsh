//! An in-memory signing key store (KNSH-065).

use std::sync::Mutex;

use super::lock;
use crate::error::{Operation, PlatformError};
use crate::signing::{SIGNING_KEY_LEN, SigningKey, SigningKeyStore};

#[derive(Debug, Default)]
struct State {
    key: Option<[u8; SIGNING_KEY_LEN]>,
    /// `OSStatus` every read fails with, as a tampered or locked keychain would (decision 11).
    read_failure: Option<i32>,
    /// `OSStatus` every create fails with.
    create_failure: Option<i32>,
    reads: usize,
    creates: usize,
}

/// A [`SigningKeyStore`] in memory: empty or holding a key, with injected read and create failures, counting calls.
/// Never touches the real Keychain.
#[derive(Debug, Default)]
pub struct MemKeyStore {
    state: Mutex<State>,
}

impl MemKeyStore {
    /// An empty store: no key yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store already holding `key`.
    #[must_use]
    pub fn with_key(key: [u8; SIGNING_KEY_LEN]) -> Self {
        let store = Self::new();
        lock(&store.state).key = Some(key);
        store
    }

    /// Makes every later read fail with `status` (for example `-25293`, what an item overwritten by another program
    /// reads as).
    pub fn fail_reads(&self, status: i32) {
        lock(&self.state).read_failure = Some(status);
    }

    /// Lets reads succeed again.
    pub fn allow_reads(&self) {
        lock(&self.state).read_failure = None;
    }

    /// Makes every later create fail with `status` (for example `-25299`, an item that already exists).
    pub fn fail_creates(&self, status: i32) {
        lock(&self.state).create_failure = Some(status);
    }

    /// Reads so far.
    #[must_use]
    pub fn reads(&self) -> usize {
        lock(&self.state).reads
    }

    /// Successful creates so far.
    #[must_use]
    pub fn creates(&self) -> usize {
        lock(&self.state).creates
    }
}

impl SigningKeyStore for MemKeyStore {
    fn read(&self) -> Result<Option<SigningKey>, PlatformError> {
        let mut state = lock(&self.state);
        state.reads += 1;
        if let Some(status) = state.read_failure {
            return Err(PlatformError::Keychain {
                operation: Operation::KeychainRead,
                status,
            });
        }
        Ok(state.key.map(SigningKey::from_bytes))
    }

    fn create(&self, key: &SigningKey) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        let duplicate = state.key.is_some().then_some(-25299);
        if let Some(status) = state.create_failure.or(duplicate) {
            return Err(PlatformError::Keychain {
                operation: Operation::KeychainAdd,
                status,
            });
        }
        state.key = Some(*key.bytes());
        state.creates += 1;
        Ok(())
    }
}
